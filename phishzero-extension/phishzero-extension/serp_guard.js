/**
 * PhishEye SERP Guard (Search Engine Result Annotations & Ad-Shield)
 * Injects real-time PhishEye safety badges (Safe / Caution / Danger) next to
 * Google, Bing, DuckDuckGo, Yahoo, and Brave search results before the user clicks.
 */
(() => {
  "use strict";
  if (window.__peSerpGuard) return;
  window.__peSerpGuard = true;

  const hasContext = () => {
    try {
      return !!(typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.id);
    } catch (_) {
      return false;
    }
  };

  // Search engine hostnames to skip when annotating external result links
  const INTERNAL_HOSTS = /(^|\.)(google\.[a-z.]+|bing\.com|microsoft\.com\/bing|duckduckgo\.com|yahoo\.com|search\.yahoo\.com|search\.brave\.com|gstatic\.com|googleusercontent\.com)$/i;

  const processedAnchors = new WeakSet();
  let scanTimer = null;

  function injectStyles() {
    if (document.getElementById("pe-serp-styles")) return;
    const style = document.createElement("style");
    style.id = "pe-serp-styles";
    style.textContent = `
      .pe-serp-badge {
        position: relative;
        display: inline-flex;
        align-items: center;
        gap: 4px;
        margin-left: 8px;
        padding: 2px 7px;
        font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
        font-size: 11px;
        font-weight: 800;
        line-height: 1.3;
        border-radius: 999px;
        border: 1.5px solid currentColor;
        vertical-align: middle;
        cursor: help;
        user-select: none;
        text-decoration: none !important;
        box-shadow: 1px 2px 0 rgba(0, 0, 0, 0.14);
        transition: transform 0.15s ease, box-shadow 0.15s ease;
        z-index: 20;
      }
      .pe-serp-badge:hover {
        transform: translateY(-1px);
        box-shadow: 2px 3px 0 rgba(0, 0, 0, 0.22);
        z-index: 99999;
      }
      .pe-serp-badge[data-state="safe"] {
        background: #dcfce7;
        color: #15803d;
        border-color: #16a34a;
      }
      .pe-serp-badge[data-state="warn"] {
        background: #fef3c7;
        color: #b45309;
        border-color: #d97706;
      }
      .pe-serp-badge[data-state="danger"] {
        background: #fee2e2;
        color: #b91c1c;
        border-color: #dc2626;
        animation: pe-serp-pulse 1.8s infinite;
      }
      @keyframes pe-serp-pulse {
        0%, 100% { box-shadow: 0 0 0 0 rgba(220, 38, 38, 0.45); }
        50% { box-shadow: 0 0 0 5px rgba(220, 38, 38, 0); }
      }
      .pe-serp-tooltip {
        visibility: hidden;
        opacity: 0;
        position: absolute;
        bottom: calc(100% + 8px);
        left: 0;
        width: 265px;
        padding: 10px 12px;
        background: #fffef7;
        color: #20251e;
        border: 2px solid #20251e;
        border-radius: 10px;
        box-shadow: 4px 5px 0 #20251e;
        font-size: 11.5px;
        font-weight: 600;
        line-height: 1.45;
        text-align: left;
        pointer-events: none;
        transition: opacity 0.15s ease, visibility 0.15s ease;
        z-index: 100000;
        white-space: normal;
      }
      .pe-serp-badge:hover .pe-serp-tooltip {
        visibility: visible;
        opacity: 1;
      }
      .pe-serp-tt-head {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding-bottom: 5px;
        margin-bottom: 5px;
        border-bottom: 1.5px dashed rgba(32, 37, 30, 0.25);
        font-weight: 900;
        font-size: 12px;
      }
      .pe-serp-tt-brand span {
        color: #ed3651;
      }
      .pe-serp-tt-host {
        font-size: 10.5px;
        font-weight: 800;
        color: #5a6654;
        margin-bottom: 4px;
        word-break: break-all;
      }
      .pe-serp-tt-reason {
        font-size: 11px;
        color: #20251e;
      }
    `;
    (document.head || document.documentElement).appendChild(style);
  }

  function unwrapSearchRedirect(rawHref) {
    if (!rawHref) return "";
    try {
      const u = new URL(rawHref, window.location.origin);
      // Google /url?q=... or /aclk?adurl=...
      if (
        (u.hostname.includes("google.") || u.hostname.includes("googleadservices.com")) &&
        (u.pathname === "/url" || u.pathname.startsWith("/pagead/") || u.pathname === "/aclk")
      ) {
        const target =
          u.searchParams.get("adurl") ||
          u.searchParams.get("q") ||
          u.searchParams.get("url") ||
          u.searchParams.get("dest");
        if (target && /^https?:\/\//i.test(target)) return target;
      }
      // Bing /ck/a?...&u=a1aHR0cHM...
      if (u.hostname.includes("bing.com") && u.pathname.startsWith("/ck/a")) {
        const uParam = u.searchParams.get("u");
        if (uParam && uParam.startsWith("a1")) {
          const b64 = uParam.slice(2).replace(/-/g, "+").replace(/_/g, "/");
          const decoded = atob(b64);
          if (/^https?:\/\//i.test(decoded)) return decoded;
        }
      }
      // Yahoo /RU=https%3A...
      if (u.hostname.includes("yahoo.com") && rawHref.includes("/RU=")) {
        const m = rawHref.match(/\/RU=([^/]+)\//);
        if (m && m[1]) {
          const dec = decodeURIComponent(m[1]);
          if (/^https?:\/\//i.test(dec)) return dec;
        }
      }
      return u.href;
    } catch (_) {
      return rawHref;
    }
  }

  function collectResultAnchors() {
    const results = [];
    const seenEls = new Set();

    // Primary result title links across Google, Bing, DuckDuckGo, Yahoo, Brave
    const candidates = document.querySelectorAll(
      [
        "a:has(h3)",                                // Google organic & ad result titles
        "#search .g h3",                            // Google fallback
        "[data-text-ad] a[href^='http']",           // Google sponsored ads
        "#b_results .b_algo h2 a[href]",            // Bing organic results
        "#b_results .b_ad h2 a[href]",              // Bing sponsored ads
        "a[data-testid='result-title-a']",          // DuckDuckGo results
        "#web ol.searchCenterMiddle h3 a[href]",    // Yahoo results
        "#results .snippet a.heading-serpresult"    // Brave search results
      ].join(", ")
    );

    for (const node of candidates) {
      const anchor = node.tagName === "A" ? node : node.closest("a[href]");
      if (!anchor || seenEls.has(anchor) || processedAnchors.has(anchor)) continue;
      seenEls.add(anchor);

      const targetUrl = unwrapSearchRedirect(anchor.href);
      if (!targetUrl || !/^https?:\/\//i.test(targetUrl)) continue;

      let host = "";
      try {
        host = new URL(targetUrl).hostname.toLowerCase().replace(/^www\./, "");
      } catch (_) {
        continue;
      }
      if (!host || INTERNAL_HOSTS.test(host)) continue;

      // Find the heading element inside the anchor (if present) for clean badge placement
      const heading = anchor.querySelector("h3, h2") || anchor;
      const isAd = Boolean(
        anchor.closest("[data-text-ad], .uEierd, .b_ad, [data-testid='ad-result']")
      );

      results.push({
        anchor,
        heading,
        url: targetUrl,
        host,
        titleText: (heading.textContent || "").trim().slice(0, 140),
        isAd
      });
    }

    return results;
  }

  function escapeHtml(s) {
    const d = document.createElement("div");
    d.textContent = String(s || "");
    return d.innerHTML;
  }

  function renderSerpBadge(item, scan) {
    if (!item || !item.heading) return;
    if (
      item.heading.querySelector(".pe-serp-badge") ||
      item.heading.nextElementSibling?.classList?.contains("pe-serp-badge")
    ) {
      return;
    }

    const score = typeof scan?.riskScore === "number" ? Number(scan.riskScore.toFixed(1)) : 0.1;
    const rawBadge = scan?.statusBadge || "SAFE";
    const isDanger = rawBadge === "PHISHING_DETECTED" || rawBadge === "SUSPICIOUS" || score >= 60;
    const isWarn = !isDanger && (rawBadge === "MODERATE" || score >= 30);

    const state = isDanger ? "danger" : isWarn ? "warn" : "safe";
    const icon = isDanger ? "🛑" : isWarn ? "⚠️" : "✓";
    const labelText = isDanger
      ? `DANGER · ${score}%`
      : isWarn
      ? `CAUTION · ${score}%`
      : "SAFE";
    const verdictTitle = isDanger
      ? "PhishEye: Phishing Risk"
      : isWarn
      ? "PhishEye: Caution / Unverified"
      : "PhishEye: Verified Safe";
    const primaryReason =
      Array.isArray(scan?.reasons) && scan.reasons.length > 0
        ? scan.reasons[0]
        : isDanger
        ? "Flagged by PhishEye 54-feature XGBoost model"
        : "No phishing indicators found";

    const badge = document.createElement("span");
    badge.className = "pe-serp-badge";
    badge.setAttribute("data-state", state);
    badge.innerHTML = `
      <span>${icon}</span>
      <span>${escapeHtml(labelText)}</span>
      <span class="pe-serp-tooltip" role="tooltip">
        <div class="pe-serp-tt-head">
          <span class="pe-serp-tt-brand"><span>PH</span>ish <span>EYE</span></span>
          <span>${escapeHtml(verdictTitle)}</span>
        </div>
        <div class="pe-serp-tt-host">${escapeHtml(item.host)}${item.isAd ? " · Sponsored Ad" : ""}</div>
        <div class="pe-serp-tt-reason">${escapeHtml(primaryReason)}</div>
      </span>
    `;

    // Prevent clicking the badge from opening the link if the user is just inspecting it
    badge.addEventListener("click", (e) => {
      e.stopPropagation();
    });

    item.heading.appendChild(badge);
  }

  function scanSearchResults() {
    if (!hasContext()) return;
    chrome.storage.local.get(["phisheye_protection"], (st) => {
      if (chrome.runtime.lastError || (st && st.phisheye_protection === false)) return;

      const items = collectResultAnchors();
      if (items.length === 0) return;

      injectStyles();
      items.forEach((it) => processedAnchors.add(it.anchor));

      const uniqueUrls = Array.from(new Set(items.map((it) => it.url))).slice(0, 35);
      chrome.runtime.sendMessage(
        {
          type: "BATCH_CHECK_URLS",
          urls: uniqueUrls
        },
        (response) => {
          if (chrome.runtime.lastError || !response || !response.results) return;
          for (const item of items) {
            const res = response.results[item.url];
            if (res) {
              renderSerpBadge(item, res);
            }
          }
        }
      );
    });
  }

  function scheduleScan() {
    if (scanTimer) clearTimeout(scanTimer);
    scanTimer = setTimeout(scanSearchResults, 220);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", scheduleScan, { once: true });
  } else {
    scheduleScan();
  }

  const observer = new MutationObserver(() => scheduleScan());
  if (document.documentElement) {
    observer.observe(document.documentElement, { childList: true, subtree: true });
  }
})();
