


(function () {
  let rightClickBlocked = false;

  window.addEventListener(
    "contextmenu",
    (e) => {
      if (e.defaultPrevented) {
        rightClickBlocked = true;
      }
    },
    true
  );

  function isRightClickDisabled() {
    if (rightClickBlocked) return true;
    if (
      document.body &&
      (document.body.getAttribute("oncontextmenu")?.includes("false") ||
        typeof document.body.oncontextmenu === "function")
    ) {
      return true;
    }
    if (
      document.documentElement &&
      (document.documentElement.getAttribute("oncontextmenu")?.includes("false") ||
        typeof document.documentElement.oncontextmenu === "function")
    ) {
      return true;
    }
    return false;
  }

  const MULTI_PART_TLDS = new Set([
    "co.in", "ac.in", "gov.in", "org.in", "net.in", "edu.in", "res.in",
    "co.uk", "org.uk", "ac.uk", "com.au", "co.jp", "co.nz", "com.br", "com.sg"
  ]);

  function getApexDomain(host) {
    if (!host) return "";
    const clean = host.toLowerCase().trim().replace(/^\.+|\.+$/g, "");
    const parts = clean.split(".");
    if (parts.length <= 2) return clean;
    const lastTwo = parts.slice(-2).join(".");
    if (MULTI_PART_TLDS.has(lastTwo) && parts.length >= 3) {
      return parts.slice(-3).join(".");
    }
    return lastTwo;
  }

  const KNOWN_OAUTH_PROVIDERS = new Set([
    "accounts.google.com",
    "login.microsoftonline.com",
    "github.com",
    "appleid.apple.com",
    "auth0.com",
    "clerk.com",
    "okta.com"
  ]);

  function inspectFormsAndCredentials() {
    const forms = Array.from(document.querySelectorAll("form"));
    const currentHost = (window.location.hostname || "").toLowerCase();
    const currentApex = getApexDomain(currentHost);

    let hasExtForm = false;
    let crossOriginFormDetected = false;
    const formDestinations = [];
    const credentialTypes = new Set();

    // Check all inputs on page for sensitive credentials
    const allInputs = Array.from(document.querySelectorAll("input, textarea"));
    for (const inp of allInputs) {
      const type = (inp.getAttribute("type") || inp.type || "").toLowerCase();
      const name = (inp.name || inp.id || "").toLowerCase();
      const auto = (inp.getAttribute("autocomplete") || "").toLowerCase();

      if (type === "password" || name.includes("password") || name.includes("pwd") || auto.includes("password")) {
        credentialTypes.add("password");
      } else if (name.includes("card") || name.includes("cvv") || name.includes("cc-") || auto.includes("cc-")) {
        credentialTypes.add("credit_card");
      } else if (name.includes("otp") || name.includes("pin") || name.includes("totp") || name.includes("2fa")) {
        credentialTypes.add("otp_2fa");
      } else if (name.includes("seed") || name.includes("mnemonic") || name.includes("recovery")) {
        credentialTypes.add("seed_phrase");
      }
    }

    for (const form of forms) {
      const rawAction = form.getAttribute("action");
      if (
        !rawAction ||
        rawAction.trim() === "" ||
        rawAction.startsWith("#") ||
        rawAction.startsWith("javascript:")
      ) {
        continue;
      }
      try {
        const actionUrl = new URL(rawAction, window.location.href);
        const actionHost = (actionUrl.hostname || "").toLowerCase();
        const actionApex = getApexDomain(actionHost);

        if ((actionUrl.protocol === "http:" || actionUrl.protocol === "https:") && currentHost) {
          if (actionHost !== currentHost) {
            hasExtForm = true;
          }
          // If action apex domain differs from page apex domain
          if (actionApex && currentApex && actionApex !== currentApex) {
            const isKnownOAuth = Array.from(KNOWN_OAUTH_PROVIDERS).some(
              (p) => actionHost === p || actionHost.endsWith("." + p)
            );
            if (!isKnownOAuth) {
              crossOriginFormDetected = true;
              if (!formDestinations.includes(actionHost)) {
                formDestinations.push(actionHost);
              }
            }
          }
        }
      } catch (_) {}
    }

    return {
      has_external_form: hasExtForm,
      cross_origin_form_detected: crossOriginFormDetected,
      form_destinations: formDestinations.slice(0, 4),
      has_credential_inputs: credentialTypes.size > 0,
      credential_types: Array.from(credentialTypes)
    };
  }

  function hasExternalFormAction() {
    return inspectFormsAndCredentials().has_external_form;
  }

  function collectDomSignals() {
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    const hiddenInputs = document.querySelectorAll('input[type="hidden"]');
    const iframes = document.querySelectorAll("iframe");

    let faviconUrl = "";
    try {
      const iconLink = document.querySelector(
        'link[rel="icon"], link[rel="shortcut icon"], link[rel*="icon"]'
      );
      if (iconLink && iconLink.href) {
        faviconUrl = iconLink.href;
      } else if (window.location.origin && window.location.origin.startsWith("http")) {
        faviconUrl = window.location.origin + "/favicon.ico";
      }
    } catch (_) {}

    const logoUrls = [];
    const logoHints = [];
    try {
      const imgs = Array.from(document.querySelectorAll("img[src]"));
      for (const img of imgs) {
        const src = (img.currentSrc || img.src || "").trim();
        if (!src || src.startsWith("data:")) continue;
        const meta = `${img.id || ""} ${img.className || ""} ${img.alt || ""} ${img.title || ""} ${src}`.toLowerCase();
        const rect = typeof img.getBoundingClientRect === "function" ? img.getBoundingClientRect() : null;
        const nearTop = rect ? rect.top >= -50 && rect.top <= 360 && rect.width >= 20 && rect.height >= 14 : false;
        if (/logo|brand|header|nav|auth|signin|login|icon|badge/.test(meta) || nearTop) {
          if (!logoUrls.includes(src)) {
            logoUrls.push(src);
          }
          if (img.alt || img.title) {
            logoHints.push(String(img.alt || img.title).slice(0, 80));
          }
          if (logoUrls.length >= 4) break;
        }
      }
    } catch (_) {}

    const exfilWebhooks = [];
    const popunderIndicators = [];
    let suspiciousDownloadCount = 0;
    const scamIntentHits = [];
    let pageTextSample = "";

    try {
      // 1) Inspect scripts & forms for Telegram Bot / Discord Webhook / Form exfiltration & Pop-under networks
      const scriptHtml = Array.from(document.querySelectorAll("script, form"))
        .slice(0, 60)
        .map((el) => `${el.src || ""} ${el.action || ""} ${(el.textContent || "").slice(0, 1500)}`)
        .join(" ")
        .toLowerCase();

      const exfilPatterns = [
        { pat: "api.telegram.org/bot", label: "Telegram Bot API credential exfiltration" },
        { pat: "discord.com/api/webhooks", label: "Discord Webhook credential exfiltration" },
        { pat: "discordapp.com/api/webhooks", label: "Discord Webhook credential exfiltration" },
        { pat: "formsubmit.co/", label: "Anonymous FormSubmit credential forwarder" },
        { pat: "getform.io/f/", label: "Anonymous Getform credential forwarder" },
        { pat: "web3forms.com/api", label: "Anonymous Web3Forms credential forwarder" }
      ];
      for (const item of exfilPatterns) {
        if (scriptHtml.includes(item.pat)) {
          exfilWebhooks.push(item.label);
        }
      }

      const adwareNetworks = [
        "popads.net", "propellerads", "adsterra", "exoclick.com",
        "clickadu.com", "hilltopads", "onclickads", "acscdn.com", " histats.com"
      ];
      for (const net of adwareNetworks) {
        if (scriptHtml.includes(net)) {
          popunderIndicators.push(`Adware/pop-under script (${net.trim()})`);
          break;
        }
      }

      // 2) Count direct APK / EXE / Torrent / Payload download links
      const links = Array.from(document.querySelectorAll("a[href]")).slice(0, 200);
      for (const a of links) {
        const href = (a.getAttribute("href") || "").toLowerCase().split("?")[0];
        if (
          /\.(apk|exe|msi|scr|bat|cmd|ps1|vbs|dmg|iso|torrent)$/.test(href) ||
          href.startsWith("magnet:?")
        ) {
          suspiciousDownloadCount++;
        }
      }

      // 3) Extract visible text sample & scan for high-confidence scam/phishing/lure intent phrases
      const metaDesc =
        (document.querySelector('meta[name="description"]')?.getAttribute("content") || "") + " ";
      const rawBodyText = (document.body ? document.body.innerText || "" : "")
        .replace(/\s+/g, " ")
        .trim();
      pageTextSample = (metaDesc + rawBodyText).slice(0, 600);
      const textLower = (metaDesc + rawBodyText.slice(0, 3000)).toLowerCase();

      const intentPatterns = [
        { kw: "account has been suspended", label: "Urgent account suspension coercion" },
        { kw: "verify your identity immediately", label: "Urgent identity verification coercion" },
        { kw: "unusual sign-in activity", label: "Fake unusual sign-in alert" },
        { kw: "pan card will be blocked", label: "Banking/KYC suspension scam lure" },
        { kw: "enter your seed phrase", label: "Crypto wallet seed-phrase drainer" },
        { kw: "enter your 12-word", label: "Crypto wallet recovery-phrase drainer" },
        { kw: "recovery phrase to continue", label: "Crypto wallet recovery-phrase drainer" },
        { kw: "connect wallet to claim", label: "Crypto airdrop drainer lure" },
        { kw: "mod apk", label: "Unauthorized Mod APK distribution lure" },
        { kw: "unlocked premium apk", label: "Unauthorized Mod APK distribution lure" },
        { kw: "windows defender alert", label: "Fake Tech Support / Defender scam alert" },
        { kw: "call microsoft support", label: "Fake Tech Support phone scam" }
      ];
      for (const item of intentPatterns) {
        if (textLower.includes(item.kw) && !scamIntentHits.includes(item.label)) {
          scamIntentHits.push(item.label);
        }
      }
    } catch (_) {}

    const formMeta = inspectFormsAndCredentials();

    return {
      url: window.location.href,
      hostname: window.location.hostname || "local-test-page",
      title: document.title || "",
      favicon_url: faviconUrl,
      logo_urls: logoUrls,
      logo_hints: logoHints.slice(0, 4),
      has_password_field: passwordInputs.length > 0 || formMeta.credential_types.includes("password"),
      password_field_count: passwordInputs.length,
      hidden_input_count: hiddenInputs.length,
      iframe_count: iframes.length,
      external_form_action: formMeta.has_external_form,
      cross_origin_form_detected: formMeta.cross_origin_form_detected,
      form_action_destinations: formMeta.form_destinations,
      has_credential_inputs: formMeta.has_credential_inputs,
      credential_input_types: formMeta.credential_types,
      right_click_disabled: isRightClickDisabled(),
      exfil_webhooks: exfilWebhooks,
      popunder_scripts: popunderIndicators,
      suspicious_download_links: suspiciousDownloadCount,
      scam_intent_hits: scamIntentHits,
      page_text_sample: pageTextSample,
      timestamp: new Date().toISOString()
    };
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  function freezePageRedirects() {
    try {
      // 1) Immediately stop ongoing document/meta/script loading
      window.stop();
    } catch (_) {}

    try {
      // 2) Strip any <meta http-equiv="refresh"> tags
      document.querySelectorAll('meta[http-equiv="refresh" i]').forEach((m) => m.remove());
    } catch (_) {}

    try {
      // 3) Neutralize all underlying page iframes so they cannot trigger top-level redirects or pop-unders
      document.querySelectorAll("iframe").forEach((ifr) => {
        if (ifr.closest("#phishzero-overlay")) return;
        if (!ifr.hasAttribute("data-pz-saved-src") && ifr.src) {
          ifr.setAttribute("data-pz-saved-src", ifr.src);
        }
        ifr.src = "about:blank";
      });
    } catch (_) {}

    try {
      // 4) Block Chromium Navigation API redirects in the isolated world as well
      if (typeof navigation !== "undefined" && navigation && !window.__pzNavGuardAttached) {
        window.__pzNavGuardAttached = true;
        navigation.addEventListener("navigate", (e) => {
          if (
            document.getElementById("phishzero-overlay") &&
            !document.documentElement.hasAttribute("data-pz-allow-nav") &&
            e.cancelable
          ) {
            e.preventDefault();
          }
        });
      }
    } catch (_) {}

    try {
      // 5) Inject Main-World Redirect, Timer & Pop-Under Killer
      const s = document.createElement("script");
      s.textContent = `(function(){
        try {
          if (window.__pzMainFreezeActive) return;
          window.__pzMainFreezeActive = true;
          const isLocked = () => Boolean(document.getElementById("phishzero-overlay")) && !document.documentElement.hasAttribute("data-pz-allow-nav");

          // Clear all existing setTimeout / setInterval redirect timers
          const maxId = window.setTimeout(function(){}, 0);
          for (let i = 1; i <= maxId; i++) {
            window.clearTimeout(i);
            window.clearInterval(i);
          }

          // Block new page timers while overlay is active
          const origSetTimeout = window.setTimeout;
          const origSetInterval = window.setInterval;
          window.setTimeout = function(fn, d) {
            if (isLocked()) return 0;
            return origSetTimeout.apply(this, arguments);
          };
          window.setInterval = function(fn, d) {
            if (isLocked()) return 0;
            return origSetInterval.apply(this, arguments);
          };

          // Block window.open pop-under tabs & programmatic <a target="_blank">.click() / form.submit() redirects
          const origOpen = window.open;
          window.open = function() {
            if (isLocked()) return null;
            return origOpen.apply(this, arguments);
          };
          const origAnchorClick = HTMLAnchorElement.prototype.click;
          HTMLAnchorElement.prototype.click = function() {
            if (isLocked() && (!this.closest || !this.closest("#phishzero-overlay"))) return;
            return origAnchorClick.apply(this, arguments);
          };
          const origFormSubmit = HTMLFormElement.prototype.submit;
          HTMLFormElement.prototype.submit = function() {
            if (isLocked() && (!this.closest || !this.closest("#phishzero-overlay"))) return;
            return origFormSubmit.apply(this, arguments);
          };

          // Prevent page capture-phase click/pointer hijacks when user interacts with #phishzero-overlay
          ["click", "mousedown", "mouseup", "pointerdown", "pointerup", "touchstart", "auxclick", "contextmenu"].forEach(function(evt) {
            window.addEventListener(evt, function(e) {
              if (!isLocked()) return;
              if (e.target && e.target.closest && !e.target.closest("#phishzero-overlay")) {
                e.stopImmediatePropagation();
                e.preventDefault();
              }
            }, true);
          });

          // Block Chromium Navigation API redirects (location.href / location.replace / meta refresh)
          if (typeof navigation !== "undefined" && navigation && navigation.addEventListener) {
            navigation.addEventListener("navigate", function(e) {
              if (isLocked() && e.cancelable) {
                e.preventDefault();
              }
            });
          }

          // Watch and strip dynamically injected <meta http-equiv="refresh"> or adware iframes
          new MutationObserver(function(muts) {
            if (!isLocked()) return;
            for (const m of muts) {
              for (const n of m.addedNodes) {
                if (!n || n.nodeType !== 1) continue;
                if (n.id === "phishzero-overlay" || (n.closest && n.closest("#phishzero-overlay"))) continue;
                if (n.tagName === "META" && /refresh/i.test(n.getAttribute("http-equiv") || "")) {
                  n.remove();
                } else if (n.tagName === "IFRAME") {
                  n.src = "about:blank";
                }
              }
            }
          }).observe(document.documentElement, { childList: true, subtree: true });
        } catch (_) {}
      })();`;
      (document.head || document.documentElement).appendChild(s);
      s.remove();
    } catch (_) {}
  }

  function unfreezePageRedirects() {
    try {
      document.documentElement.setAttribute("data-pz-allow-nav", "1");
      document.querySelectorAll("iframe[data-pz-saved-src]").forEach((ifr) => {
        ifr.src = ifr.getAttribute("data-pz-saved-src");
        ifr.removeAttribute("data-pz-saved-src");
      });
    } catch (_) {}
  }

  function injectWarningOverlay(scanResult, domData) {
    if (document.getElementById("phishzero-overlay")) {
      return;
    }

    document.documentElement.removeAttribute("data-pz-allow-nav");
    document.documentElement.setAttribute("data-pz-block-popunders", "1");
    freezePageRedirects();

    const overlay = document.createElement("div");
    overlay.id = "phishzero-overlay";

    const hostnameDisplay = escapeHtml(
      domData.hostname || window.location.hostname || "local-test-page"
    );
    const confidenceVal = Math.max(0, Math.min(100, Number(scanResult.confidence || 98.5)));
    const confidenceDisplay = confidenceVal.toFixed(1);

    const reasons =
      Array.isArray(scanResult.reasons) && scanResult.reasons.length > 0
        ? scanResult.reasons
        : ["Deceptive credential harvesting form target detected in DOM."];

    const reasonsHtml = reasons
      .map(
        (reason) => `
        <li class="pz-reason-item">
          <span class="pz-reason-marker">⚠️</span>
          <span>${escapeHtml(reason)}</span>
        </li>`
      )
      .join("");

    const isZeroDayPrediction =
      scanResult.is_zero_day === true &&
      scanResult.detection_method === "ML_XGBOOST_ZERO_DAY";

    const layerLabel = escapeHtml(scanResult.layer || "XGBoost & Zero-Day Shield");
    const pwdSummary = domData.has_password_field
      ? `Password input detected (${domData.password_field_count} field${domData.password_field_count > 1 ? "s" : ""})${domData.external_form_action ? " submitting to an external host" : ""}.`
      : "Sensitive input fields and page structure analyzed.";
    const urlSignalSummary = reasons[0] ? escapeHtml(reasons[0]) : "Suspicious look-alike domain or URL structure.";

    overlay.innerHTML = `
      <style>
        #phishzero-overlay {
          --paper: rgba(255, 254, 247, 0.95);
          --paper-solid: #fffef7;
          --ink: #20251e;
          --muted: #5a6654;
          --panel: rgba(246, 246, 239, 0.9);
          --safe: #168b49;
          --warn: #996011;
          --danger: #b93e33;
          --overlay-bg: rgba(244, 241, 231, 0.56);
          --body-bg: #e4e1d6;
          --eye-paper: #fffef4;
          --brand-accent: #ed3651;
          --sandbox-bg: #dcecdf;
          --sandbox-color: #1f3d29;
          --sandbox-border: #2a5238;
          --border-subtle: rgba(32, 37, 30, 0.18);
          --shadow-card: 0 22px 54px rgba(18, 25, 20, 0.24), 0 4px 14px rgba(18, 25, 20, 0.1), 5px 6px 0 #20251e;

          position: fixed;
          inset: 0;
          width: 100vw;
          height: 100vh;
          z-index: 2147483647;
          background: var(--overlay-bg);
          backdrop-filter: blur(6px);
          -webkit-backdrop-filter: blur(6px);
          font-family: 'Segoe UI', system-ui, -apple-system, 'Trebuchet MS', Arial, sans-serif;
          color: var(--ink);
          margin: 0;
          padding: 0;
          box-sizing: border-box;
          user-select: none;
          overflow: hidden;
          transition: background 0.35s ease;
        }

        #phishzero-overlay[data-theme="dark"] {
          --paper: rgba(34, 44, 39, 0.95);
          --paper-solid: #222c27;
          --ink: #f6f3e8;
          --muted: #bbc9b8;
          --panel: rgba(43, 55, 47, 0.92);
          --safe: #15803d;
          --warn: #996011;
          --danger: #b93e33;
          --overlay-bg: rgba(12, 23, 28, 0.72);
          --body-bg: #0c1520;
          --eye-paper: #252e29;
          --brand-accent: #ff8292;
          --sandbox-bg: #2d4739;
          --sandbox-color: #e0f7e5;
          --sandbox-border: #8eb695;
          --border-subtle: rgba(246, 243, 232, 0.2);
          --shadow-card: 0 24px 58px rgba(0, 0, 0, 0.5), 0 4px 16px rgba(0, 0, 0, 0.3), 5px 6px 0 #090f0b;
        }

        #phishzero-overlay * {
          box-sizing: border-box;
          margin: 0;
          padding: 0;
        }

        #pz-sea {
          position: absolute;
          inset: 0;
          width: 100%;
          height: 100%;
          pointer-events: none;
          z-index: 1;
        }

        .pz-background-eye {
          position: absolute;
          right: clamp(18px, 4vw, 38px);
          top: clamp(14px, 3vw, 26px);
          width: clamp(95px, 13vw, 170px);
          color: var(--ink);
          opacity: 0.72;
          pointer-events: none;
          z-index: 2;
        }

        .pz-stage {
          position: absolute;
          inset: 0;
          display: grid;
          place-items: center;
          overflow-y: auto;
          padding: 32px 18px;
          z-index: 10;
        }

        .pz-card {
          width: min(94vw, 485px);
          margin: auto;
          padding: 22px 24px;
          background: var(--paper);
          backdrop-filter: blur(12px);
          -webkit-backdrop-filter: blur(12px);
          color: var(--ink);
          border: 2px solid var(--ink);
          border-radius: 18px 13px 20px 14px;
          box-shadow: var(--shadow-card);
          display: flex;
          flex-direction: column;
          gap: 15px;
          text-align: left;
          transition: background 0.3s ease, color 0.3s ease, box-shadow 0.3s ease;
        }

        .pz-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 12px;
          padding-bottom: 14px;
          border-bottom: 1.5px solid var(--border-subtle);
        }

        .pz-brand {
          display: flex;
          align-items: center;
          gap: 10px;
        }

        .pz-brand-eye {
          width: 46px;
          flex-shrink: 0;
        }

        .pz-brand-name {
          font-size: 27px;
          letter-spacing: -1.2px;
          font-weight: 900;
          line-height: 1;
        }

        .pz-brand-name span {
          color: var(--brand-accent);
        }

        .pz-theme-btn {
          cursor: pointer;
          font-family: inherit;
          font-size: 11.5px;
          font-weight: 800;
          padding: 7px 14px;
          background: var(--panel);
          color: var(--ink);
          border: 1.5px solid var(--ink);
          border-radius: 999px;
          box-shadow: 2px 2px 0 var(--ink);
          transition: transform 0.15s ease, box-shadow 0.15s ease;
        }

        .pz-theme-btn:hover {
          transform: translateY(-1px);
          box-shadow: 3px 3px 0 var(--ink);
        }

        .pz-host-bar {
          display: flex;
          justify-content: space-between;
          align-items: center;
          gap: 12px;
          padding: 12px 15px;
          border: 1.5px solid var(--ink);
          border-radius: 10px;
          box-shadow: 2px 3px 0 var(--ink);
          background: var(--paper-solid);
        }

        .pz-host-label {
          font-size: 10px;
          font-weight: 800;
          letter-spacing: 0.08em;
          color: var(--muted);
          text-transform: uppercase;
        }

        .pz-host-value {
          font-size: 13px;
          font-weight: 800;
          color: var(--ink);
          word-break: break-all;
          text-align: right;
        }

        .pz-score-card {
          position: relative;
          overflow: hidden;
          text-align: center;
          padding: 22px 18px 18px;
          background: var(--danger);
          color: #ffffff;
          border: 2.5px solid var(--ink);
          box-shadow: 3px 4px 0 var(--ink);
          border-radius: 36% 6% 35% 6% / 6% 32% 6% 32%;
          transition: background 0.4s ease;
        }

        #phishzero-overlay[data-theme="dark"] .pz-score-card {
          border-color: #ecf0df;
          box-shadow: 3px 4px 0 #ecf0df;
        }

        #pz-mini {
          position: absolute;
          inset: 0;
          width: 100%;
          height: 100%;
          pointer-events: none;
        }

        .pz-score-content {
          position: relative;
          z-index: 1;
        }

        .pz-badge-pill {
          display: inline-block;
          border: 2px solid #ffffff;
          border-radius: 6px;
          padding: 7px 14px;
          font-size: 14px;
          font-weight: 900;
          transform: rotate(-1deg);
          box-shadow: 2px 3px rgba(0, 0, 0, 0.26);
          letter-spacing: 0.04em;
          background: rgba(0, 0, 0, 0.16);
        }

        .pz-score-ring {
          width: 136px;
          height: 136px;
          margin: 16px auto 13px;
          border: 2px dashed rgba(255, 255, 255, 0.55);
          border-radius: 50%;
          padding: 9px;
          display: flex;
          align-items: center;
          justify-content: center;
        }

        .pz-score-inner {
          width: 100%;
          height: 100%;
          border: 7px solid #ffffff;
          border-radius: 49% 51% 48% 52%;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          background: rgba(0, 0, 0, 0.22);
        }

        .pz-score-num {
          font-size: 30px;
          font-weight: 900;
          font-style: italic;
          line-height: 1;
          text-shadow: 2px 2px rgba(0, 0, 0, 0.35);
        }

        .pz-score-label {
          font-size: 8.5px;
          font-weight: 800;
          letter-spacing: 0.06em;
          background: #20251e;
          color: #ffffff;
          padding: 3px 7px;
          border-radius: 4px;
          margin-top: 5px;
        }

        .pz-score-sub {
          border-top: 1px dashed rgba(255, 255, 255, 0.55);
          padding-top: 11px;
          font-size: 12px;
          font-weight: 700;
          line-height: 1.5;
        }

        .pz-report {
          border: 1.5px solid var(--ink);
          border-radius: 11px;
          box-shadow: 2px 3px 0 var(--ink);
          background: var(--panel);
          overflow: hidden;
        }

        .pz-report > summary {
          padding: 13px 15px;
          font-size: 13.5px;
          font-weight: 900;
          cursor: pointer;
          display: flex;
          align-items: center;
          justify-content: space-between;
        }

        .pz-report-intro {
          padding: 0 15px 11px;
          color: var(--muted);
          font-size: 11.5px;
          line-height: 1.6;
        }

        .pz-subsection {
          margin: 0 12px 9px;
          border: 1px solid var(--border-subtle);
          border-left: 4px solid var(--danger);
          border-radius: 8px;
          background: var(--paper-solid);
        }

        .pz-subsection summary {
          padding: 10px 12px;
          font-size: 12px;
          font-weight: 800;
          line-height: 1.5;
          cursor: pointer;
        }

        .pz-subsection small {
          display: block;
          color: var(--muted);
          font-size: 10.5px;
          font-weight: 500;
          margin-top: 2px;
        }

        .pz-detail-body {
          padding: 0 12px 11px;
          font-size: 11.5px;
          line-height: 1.65;
          color: var(--ink);
        }

        .pz-reasons-list {
          list-style: none;
          display: flex;
          flex-direction: column;
          gap: 7px;
          padding: 4px 12px 12px;
        }

        .pz-reason-item {
          display: flex;
          align-items: flex-start;
          gap: 8px;
          font-size: 12px;
          font-weight: 700;
          padding: 8px 10px;
          border: 1px solid var(--border-subtle);
          border-radius: 8px;
          background: var(--paper-solid);
          line-height: 1.45;
        }

        .pz-reason-marker {
          font-size: 12.5px;
          flex-shrink: 0;
          margin-top: 1px;
        }

        .pz-evidence {
          border: 1.5px solid var(--ink);
          border-radius: 10px;
          box-shadow: 2px 3px 0 var(--ink);
          padding: 12px 14px;
          font-size: 12px;
          line-height: 1.55;
          font-weight: 700;
          background: var(--paper-solid);
        }

        .pz-actions {
          display: grid;
          gap: 10px;
          margin-top: 2px;
        }

        .pz-action-btn {
          width: 100%;
          padding: 13px 14px;
          border: 2px solid var(--ink);
          border-radius: 10px;
          font-family: inherit;
          font-size: 13px;
          font-weight: 800;
          cursor: pointer;
          text-align: center;
          transition: transform 0.14s ease, box-shadow 0.14s ease, background 0.15s ease;
        }

        .pz-action-btn:hover {
          transform: translateY(-1px);
        }

        .pz-btn-back {
          background: var(--ink);
          color: var(--paper-solid);
          box-shadow: 2px 3px 0 rgba(0, 0, 0, 0.22);
        }

        .pz-btn-sandbox {
          background: var(--sandbox-bg);
          color: var(--sandbox-color);
          border-color: var(--sandbox-border);
        }

        .pz-btn-continue {
          background: transparent;
          color: var(--muted);
          border: 1.5px dashed var(--muted);
          font-size: 12px;
          padding: 11px 14px;
        }

        .pz-btn-continue:hover {
          color: var(--danger);
          border-color: var(--danger);
        }

        .pz-confirm {
          padding: 13px 14px;
          border: 1.5px dashed #a66d19;
          border-radius: 10px;
          background: #fff0d8;
          color: #493210;
        }

        #phishzero-overlay[data-theme="dark"] .pz-confirm {
          background: #44351e;
          color: #fff4df;
        }

        .pz-confirm p {
          font-size: 11.5px;
          line-height: 1.55;
          margin-bottom: 10px;
        }

        .pz-confirm-row {
          display: flex;
          gap: 9px;
        }

        .pz-btn-report-link {
          background: none;
          border: none;
          color: var(--muted);
          font-family: inherit;
          font-size: 11.5px;
          font-weight: 700;
          text-decoration: underline;
          cursor: pointer;
          padding: 4px;
          text-align: center;
        }

        .pz-btn-report-link:hover {
          color: var(--danger);
        }

        .pz-btn-report-link.reported {
          color: var(--safe);
          pointer-events: none;
        }

        .pz-sandbox-box {
          padding: 8px 0;
        }

        .pz-sandbox-box iframe {
          width: 100%;
          height: 250px;
          border: 2px solid var(--ink);
          border-radius: 10px;
          background: #ffffff;
        }

        @media (max-width: 600px) {
          .pz-background-eye {
            top: 10px;
            right: 10px;
            opacity: 0.4;
          }
          .pz-stage {
            padding: 20px 12px;
          }
          .pz-card {
            padding: 18px 16px;
          }
        }
      </style>

      <canvas id="pz-sea" aria-hidden="true"></canvas>
      <div class="pz-background-eye" id="pz-big-eye" aria-hidden="true"></div>

      <div class="pz-stage" id="pz-stage">
        <section class="pz-card" role="alertdialog" aria-labelledby="pz-heading">
          <header class="pz-header">
            <div class="pz-brand">
              <div class="pz-brand-eye" id="pz-small-eye" aria-hidden="true"></div>
              <h1 class="pz-brand-name" id="pz-heading"><span>PH</span>ish <span>EYE</span></h1>
            </div>
            <button type="button" class="pz-theme-btn" id="pz-theme-toggle">Theme ☀️</button>
          </header>

          <div class="pz-host-bar">
            <span class="pz-host-label">CURRENT SITE:</span>
            <span class="pz-host-value">${hostnameDisplay}</span>
          </div>

          <div class="pz-score-card">
            <canvas id="pz-mini" aria-hidden="true"></canvas>
            <div class="pz-score-content">
              <div class="pz-badge-pill">⚠️ PHISHING THREAT DETECTED</div>
              <div class="pz-score-ring">
                <div class="pz-score-inner">
                  <span class="pz-score-num">${confidenceDisplay}%</span>
                  <span class="pz-score-label">DANGER SCORE</span>
                </div>
              </div>
              <div class="pz-score-sub">Multiple strong phishing indicators were found on this page (${layerLabel}).</div>
            </div>
          </div>

          <details class="pz-report">
            <summary><span>Why is this flagged?</span><span style="font-size:11px;opacity:0.7;">View signals ▾</span></summary>
            <p class="pz-report-intro">Click any section below to inspect the signals detected on this site.</p>
            <details class="pz-subsection">
              <summary>01 · URL &amp; domain signals<small>${urlSignalSummary}</small></summary>
              <div class="pz-detail-body">
                <ul class="pz-reasons-list" style="padding:4px 0 0;">
                  ${reasonsHtml}
                </ul>
              </div>
            </details>
            <details class="pz-subsection">
              <summary>02 · Passwords &amp; forms<small>${escapeHtml(pwdSummary)}</small></summary>
              <div class="pz-detail-body">
                <p>Phishing pages often imitate trusted sign-in screens while sending credentials to an untrusted destination.</p>
              </div>
            </details>
            <details class="pz-subsection">
              <summary>03 · AI &amp; Threat Intelligence<small>Flagged by ${layerLabel} (${confidenceDisplay}% risk score).</small></summary>
              <div class="pz-detail-body">
                <p>Combined URL heuristics, DOM structure inspection, and XGBoost machine-learning risk scoring.</p>
              </div>
            </details>
          </details>

          <div class="pz-evidence">⚠️ Primary signal: ${urlSignalSummary}</div>

          <div class="pz-actions">
            <button type="button" class="pz-action-btn pz-btn-back" id="pz-btn-back">
              ← Go back (recommended)
            </button>

            <button type="button" class="pz-action-btn pz-btn-sandbox" id="pz-btn-sandbox">
              ◇ Run virtually in sandbox (Screenshot)
            </button>
            <div id="pz-sandbox-box" class="pz-sandbox-box" style="display:none;"></div>

            <button type="button" class="pz-action-btn pz-btn-continue" id="pz-btn-continue">
              Continue to site anyway →
            </button>

            <div class="pz-confirm" id="pz-confirmation" style="display:none;">
              <p>Continuing could expose you to a deceptive site designed to harvest passwords or personal data. Do you want to continue?</p>
              <div class="pz-confirm-row">
                <button type="button" class="pz-action-btn pz-btn-back" id="pz-cancel-continue" style="padding:9px 10px;font-size:11.5px;">Stay here</button>
                <button type="button" class="pz-action-btn pz-btn-continue" id="pz-confirm-continue" style="padding:9px 10px;font-size:11.5px;">Confirm — continue anyway</button>
              </div>
            </div>

            <button type="button" class="pz-btn-report-link" id="pz-btn-report">
              🚨 Report Site to Threat DB
            </button>
          </div>
        </section>
      </div>
    `;

    (document.body || document.documentElement).appendChild(overlay);

    {
      const toast = document.createElement("div");
      toast.id = "pz-ml-toast";
      toast.setAttribute("role", "alert");
      const toastLabel = isZeroDayPrediction
        ? `XGBoost ML estimate: ${confidenceDisplay}% risk. Results may not be 100% accurate.`
        : `Estimated risk: ${confidenceDisplay}% · Flagged by ${escapeHtml(scanResult.layer || "PhishEye AI Shield")}`;
      toast.innerHTML = `
        <div style="display:flex;align-items:center;gap:10px;padding:11px 14px 9px;">
          <span style="font-size:18px;flex-shrink:0;">🔮</span>
          <div style="flex:1;min-width:0;">
            <div style="font-size:11.5px;font-weight:900;letter-spacing:0.03em;text-transform:uppercase;">AI ML Alert Notice</div>
            <div style="font-size:10.5px;font-weight:500;opacity:0.9;line-height:1.4;margin-top:2px;">${toastLabel}</div>
          </div>
          <button type="button" id="pz-ml-toast-close" aria-label="Dismiss" style="background:rgba(255,255,255,0.18);border:1.5px solid rgba(255,255,255,0.3);color:inherit;border-radius:50%;width:24px;height:24px;font-size:12px;font-weight:700;display:flex;align-items:center;justify-content:center;cursor:pointer;flex-shrink:0;padding:0;font-family:inherit;">&#x2715;</button>
        </div>
        <div style="height:3px;background:rgba(255,255,255,0.2);width:100%;"><div id="pz-ml-toast-bar" style="height:100%;width:100%;background:rgba(255,255,255,0.75);transition:none;border-radius:0 2px 2px 0;"></div></div>
      `;
      toast.style.cssText = "position:fixed;top:18px;right:18px;z-index:200;width:min(320px,calc(100vw - 36px));background:linear-gradient(135deg,#7f1d1d,#b91c1c);color:#fff1f2;border:1px solid rgba(255,255,255,0.25);border-radius:12px;box-shadow:0 10px 28px rgba(0,0,0,0.35);transform:translateY(-16px);opacity:0;transition:transform 0.32s cubic-bezier(0.22,1,0.36,1),opacity 0.28s;pointer-events:none;overflow:hidden;font-family:'Trebuchet MS',Arial,sans-serif;";
      overlay.appendChild(toast);
      requestAnimationFrame(() => {
        toast.style.transform = "translateY(0)";
        toast.style.opacity = "1";
        toast.style.pointerEvents = "auto";
        const bar = document.getElementById("pz-ml-toast-bar");
        if (bar) {
          setTimeout(() => {
            bar.style.transition = "width 4s linear";
            bar.style.width = "0%";
          }, 40);
        }
      });
      const dismissToast = () => {
        toast.style.transform = "translateY(-16px)";
        toast.style.opacity = "0";
        toast.style.pointerEvents = "none";
        setTimeout(() => { if (toast.parentNode) toast.parentNode.removeChild(toast); }, 320);
      };
      const closeBtn = document.getElementById("pz-ml-toast-close");
      if (closeBtn) closeBtn.addEventListener("click", dismissToast);
      setTimeout(dismissToast, 4000);
    }

    const themeBtn = document.getElementById("pz-theme-toggle");
    const reportBtn = document.getElementById("pz-btn-report");
    const backBtn = document.getElementById("pz-btn-back");
    const sandboxBtn = document.getElementById("pz-btn-sandbox");
    const sandboxBox = document.getElementById("pz-sandbox-box");
    const continueBtn = document.getElementById("pz-btn-continue");
    const confirmBox = document.getElementById("pz-confirmation");
    const cancelContinueBtn = document.getElementById("pz-cancel-continue");
    const confirmContinueBtn = document.getElementById("pz-confirm-continue");

    function setOverlayTheme(theme) {
      const mode = theme === "dark" ? "dark" : "light";
      overlay.setAttribute("data-theme", mode);
      if (themeBtn) {
        themeBtn.textContent = mode === "dark" ? "Theme 🌙" : "Theme ☀️";
      }
    }

    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get(["phisheye_theme"], (stored) => {
        if (stored && stored.phisheye_theme) {
          setOverlayTheme(stored.phisheye_theme);
        }
      });
    }

    if (themeBtn) {
      themeBtn.addEventListener("click", () => {
        const nextTheme =
          overlay.getAttribute("data-theme") === "dark" ? "light" : "dark";
        setOverlayTheme(nextTheme);
        if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
          chrome.storage.local.set({ phisheye_theme: nextTheme });
        }
      });
    }

    if (backBtn) {
      backBtn.addEventListener("click", () => {
        unfreezePageRedirects();
        let safeTarget = "https://www.google.com";
        try {
          if (document.referrer) {
            const refUrl = new URL(document.referrer);
            if (refUrl.hostname && refUrl.hostname !== window.location.hostname) {
              safeTarget = document.referrer;
            }
          }
        } catch (_) {}
        window.location.replace(safeTarget);
      });
    }

    if (sandboxBtn) {
      sandboxBtn.addEventListener("click", () => {
        if (sandboxBox.style.display !== "none") {
          sandboxBox.style.display = "none";
          return;
        }
        sandboxBox.style.display = "block";
        sandboxBox.innerHTML = "<p style='text-align:center;font-size:11px;font-weight:bold;padding:12px;'>Loading sandboxed virtual preview...</p>";
        chrome.runtime.sendMessage(
          {
            type: "SANDBOX_URL",
            payload: { url: domData.url }
          },
          (res) => {
            if (res && res.status === "sandboxed" && res.safe_html_preview) {
              sandboxBox.innerHTML = "";
              const iframe = document.createElement("iframe");
              iframe.sandbox = "allow-same-origin";
              iframe.style.cssText = "width:100%;height:260px;border:2px solid var(--ink,#20251e);border-radius:6px;background:#fff;display:block;margin-top:8px;";
              iframe.srcdoc = res.safe_html_preview;
              sandboxBox.appendChild(iframe);
            } else {
              sandboxBox.textContent = ""; const _p = document.createElement("p"); _p.style.cssText = "font-size:11px;color:#b93e33;font-weight:bold;padding:10px;"; _p.textContent = res?.message || "Sandbox unavailable."; sandboxBox.appendChild(_p);
            }
          }
        );
      });
    }

    if (continueBtn && confirmBox) {
      continueBtn.addEventListener("click", () => {
        confirmBox.style.display = "block";
      });
    }

    if (cancelContinueBtn && confirmBox) {
      cancelContinueBtn.addEventListener("click", () => {
        confirmBox.style.display = "none";
      });
    }

    let cleanupAnimation = null;

    if (confirmContinueBtn) {
      confirmContinueBtn.addEventListener("click", () => {
        unfreezePageRedirects();
        if (cleanupAnimation) cleanupAnimation();
        overlay.remove();
      });
    }

    if (reportBtn) {
      reportBtn.addEventListener("click", () => {
        reportBtn.disabled = true;
        chrome.runtime.sendMessage(
          {
            type: "REPORT_URL",
            payload: {
              url: domData.url,
              reason: reasons.join("; ")
            }
          },
          (res) => {
            reportBtn.textContent = res?.message ? `✓ ${res.message}` : "✓ Added to Threat DB";
            reportBtn.classList.add("reported");
          }
        );
      });
    }

    // --- Mount Living Ocean Animation inside Overlay ---
    try {
      const rand = (a, b) => a + Math.random() * (b - a);
      const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
      const mod = (v, n) => ((v % n) + n) % n;
      const TAU = Math.PI * 2;
      let animRaf = 0, animLast = 0, animTime = 0;
      const animPointer = { x: window.innerWidth / 2, y: window.innerHeight / 2 };

      function eyeMarkup(id) {
        return `<svg class="eye-svg" viewBox="0 0 140 140" style="display:block;width:100%;overflow:visible;">`
          + `<defs><clipPath id="${id}"><path data-opening/></clipPath></defs>`
          + `<path class="eye-paper" d="M70 8 C105 5 128 32 130 67 C133 102 109 130 73 131 C36 134 10 110 9 76 C7 43 27 11 61 8Z" stroke="currentColor" stroke-width="5" fill="currentColor" fill-opacity="0.1"/>`
          + `<g clip-path="url(#${id})"><g data-pupil><rect x="43" y="49" width="54" height="45" rx="12" fill="currentColor"/></g></g>`
          + `<path data-upper fill="none" stroke="currentColor" stroke-width="6"/>`
          + `<path data-lower fill="none" stroke="currentColor" stroke-width="6"/>`
          + `<path d="M29 24 L39 18" stroke="currentColor" stroke-width="4" stroke-linecap="round"/>`
          + `</svg>`;
      }

      const bigEyeEl = document.getElementById("pz-big-eye");
      const smallEyeEl = document.getElementById("pz-small-eye");
      if (bigEyeEl) bigEyeEl.innerHTML = eyeMarkup("pz-big-clip");
      if (smallEyeEl) smallEyeEl.innerHTML = eyeMarkup("pz-small-clip");

      const eyeNodes = [].slice.call(overlay.querySelectorAll(".eye-svg")).map((svg) => ({
        svg,
        pupil: svg.querySelector("[data-pupil]"),
        opening: svg.querySelector("[data-opening]"),
        upper: svg.querySelector("[data-upper]"),
        lower: svg.querySelector("[data-lower]"),
        x: 0,
        y: 0,
        next: rand(1.4, 3),
        start: null
      }));

      function stepEyes(dt) {
        for (let ei = 0; ei < eyeNodes.length; ei++) {
          const e = eyeNodes[ei];
          const r = e.svg.getBoundingClientRect();
          const dx = animPointer.x - r.left - r.width / 2;
          const dy = animPointer.y - r.top - r.height * 0.52;
          const d = Math.hypot(dx, dy);
          const strength = Math.min(d / 180, 1);
          const smooth = 1 - Math.exp(-dt * 15);
          e.x += ((d ? (dx / d) * 19 * strength : 0) - e.x) * smooth;
          e.y += ((d ? (dy / d) * 3 * strength : 0) - e.y) * smooth;
          e.pupil.setAttribute("transform", `translate(${e.x} ${e.y})`);
          let open = 1;
          if (e.start === null && animTime >= e.next) e.start = animTime;
          if (e.start !== null) {
            const p = (animTime - e.start) / 0.16;
            if (p >= 1) {
              e.start = null;
              e.next = animTime + rand(1.8, 3.8);
            } else {
              open = Math.max(0.02, Math.abs(p * 2 - 1));
            }
          }
          const u = 72 - 11 * open, l = 72 + 14 * open;
          e.upper.setAttribute("d", `M13 ${u} Q70 ${u - 6 * open} 127 ${u}`);
          e.lower.setAttribute("d", `M14 ${l} Q70 ${l - 7 * open} 126 ${l}`);
          e.opening.setAttribute("d", `M13 ${u} Q70 ${u - 6 * open} 127 ${u} L126 ${l} Q70 ${l - 7 * open} 14 ${l}Z`);
        }
      }

      function PzShape() { this.lines = []; this.line = null; this.x = 0; this.y = 0; }
      PzShape.prototype.m = function(x, y) { this.line = []; this.lines.push(this.line); this.line.push([x, y]); this.x = x; this.y = y; return this; };
      PzShape.prototype.l = function(x, y) { for (let i = 1; i <= 6; i++) this.line.push([this.x + (x - this.x) * i / 6, this.y + (y - this.y) * i / 6]); this.x = x; this.y = y; return this; };
      PzShape.prototype.c = function(ax, ay, bx, by, x, y) {
        for (let i = 1; i <= 12; i++) {
          const t = i / 12, u = 1 - t;
          this.line.push([u * u * u * this.x + 3 * u * u * t * ax + 3 * u * t * t * bx + t * t * t * x, u * u * u * this.y + 3 * u * u * t * ay + 3 * u * t * t * by + t * t * t * y]);
        }
        this.x = x; this.y = y; return this;
      };
      PzShape.prototype.q = function(ax, ay, x, y) {
        return this.c(this.x + (ax - this.x) * 2 / 3, this.y + (ay - this.y) * 2 / 3, x + (ax - x) * 2 / 3, y + (ay - y) * 2 / 3, x, y);
      };

      const dolphShape = new PzShape().m(1.28, .02).q(1.10, -.04, .94, -.07).c(.78, -.34, .45, -.43, .04, -.36).q(-.10, -.45, -.24, -.70).q(-.36, -.77, -.38, -.33).c(-.76, -.29, -1.05, -.14, -1.29, -.015).q(-1.49, -.20, -1.64, -.28).q(-1.59, -.07, -1.43, .025).q(-1.60, .11, -1.65, .28).q(-1.43, .23, -1.27, .10).c(-.88, .16, -.49, .35, .04, .28).q(.52, .25, .91, .12).q(1.12, .19, 1.29, .12).q(1.38, .07, 1.28, .02).m(.12, .24).q(-.07, .57, -.34, .56).q(-.23, .35, -.12, .26).m(.91, .12).q(1.08, .17, 1.26, .11);
      const fshShape = new PzShape().m(1, .04).c(.50, -.49, -.18, -.45, -.67, 0).l(-1.14, -.34).q(-1.02, 0, -1.17, .34).l(-.64, .14).q(.28, .49, 1, .04).m(.02, -.30).q(-.17, -.55, -.31, -.32).m(.06, .05).q(-.18, .24, -.28, .10);

      const cloudPath = new Path2D("M-95 20 Q-120 17 -105 10 Q-120 -8 -104 -17 Q-91 -25 -82 -9 Q-90 -37 -65 -37 Q-57 -66 -30 -48 Q-8 -76 12 -51 Q40 -68 48 -40 Q73 -43 73 -18 Q94 -25 100 -5 Q120 -4 108 10 Q137 15 120 22 Q80 27 40 22 Q0 30 -37 23 Q-75 30 -95 20 M-79 -8 Q-73 -23 -59 -12 M-35 -32 Q-20 -46 -8 -29 M18 -39 Q36 -46 39 -29 M59 -13 Q72 -22 80 -7 M-62 16 Q-47 2 -35 14 M0 19 Q15 4 26 17 M66 17 Q78 8 89 18");

      function PzOcean(canvas, mini) {
        this.canvas = canvas;
        this.c = canvas.getContext("2d");
        this.mini = Boolean(mini);
        this.w = 1; this.h = 1;
        this.creatures = [];
        this.clouds = [];
        this.particles = [];
        this.resize();
        if (typeof ResizeObserver !== "undefined") {
          this.observer = new ResizeObserver(() => this.resize());
          this.observer.observe(canvas);
        }
      }

      PzOcean.prototype.surface = function(x, t) {
        if (t === undefined) t = animTime;
        return this.h * (this.mini ? 0.70 : 0.73) + Math.sin(x * 0.007 + t * 0.65) * (this.mini ? 2 : 5) + Math.sin(x * 0.014 - t * 0.35) * (this.mini ? 1 : 2);
      };

      PzOcean.prototype.resize = function() {
        const r = this.canvas.getBoundingClientRect();
        if (!r.width || !r.height) return;
        this.w = r.width; this.h = r.height;
        const dpr = Math.min(window.devicePixelRatio || 1, 2);
        this.canvas.width = Math.round(this.w * dpr);
        this.canvas.height = Math.round(this.h * dpr);
        this.c.setTransform(dpr, 0, 0, dpr, 0, 0);
        const count = this.mini ? 5 : Math.min(16, Math.max(10, Math.floor(this.w / 110)));
        this.creatures = Array.from({ length: count }, (_, i) => {
          const dolph = i < (this.mini ? 1 : 3);
          const size = this.mini ? (dolph ? 18 : rand(10, 13)) : (dolph ? rand(32, 40) : rand(18, 25));
          const height = this.mini ? (dolph ? 27 : 16) : (dolph ? rand(52, 76) : rand(24, 35));
          const depth = this.mini ? (dolph ? 35 : rand(17, 28)) : (dolph ? Math.min(rand(85, 112), this.h * 0.21) : rand(28, Math.max(32, this.h * 0.15)));
          const airDuration = dolph ? rand(1.05, 1.3) : rand(0.8, 1.05);
          const diveDuration = (depth * Math.PI * airDuration) / (4 * height);
          return {
            dolphin: dolph,
            jumper: dolph || i % 3 === 0,
            size,
            height,
            depth,
            airDuration,
            diveDuration,
            duration: airDuration + diveDuration,
            phase: rand(0, airDuration + diveDuration),
            x: rand(0, this.w),
            direction: Math.random() > 0.5 ? 1 : -1,
            speed: this.mini ? (dolph ? 80 : rand(48, 64)) : (dolph ? rand(190, 235) : rand(83, 110)),
            seed: rand(0, TAU),
            trail: 0,
            previousDepth: null,
            spine: []
          };
        });
        this.clouds = Array.from({ length: this.mini ? 2 : 3 }, (_, i) => ({
          x: (this.w * (i + 0.3)) / (this.mini ? 2 : 3),
          y: this.h * (this.mini ? 0.15 + i * 0.07 : 0.09 + i * 0.045),
          scale: this.mini ? 0.15 + i * 0.025 : 0.6 + i * 0.1,
          speed: this.mini ? 5 + i : 12 + i * 2,
          phase: i * 2.4
        }));
        this.particles = [];
      };

      PzOcean.prototype.add = function(p) {
        if (this.particles.length < (this.mini ? 75 : 240)) this.particles.push(p);
      };

      PzOcean.prototype.splash = function(x, y, entry) {
        const scale = this.mini ? 0.45 : 1;
        for (let i = 0; i < (entry ? 12 : 7); i++) {
          this.add({
            type: "drop",
            x,
            y,
            vx: rand(-110, 110) * scale,
            vy: rand(-150, -50) * scale,
            age: 0,
            life: rand(0.6, 1.1),
            scale
          });
        }
        for (let i = 0; i < 2; i++) {
          this.add({
            type: "ripple",
            x,
            y: y + i * 3,
            age: 0,
            life: 2.1 + i * 0.2,
            scale: scale * 0.85
          });
        }
      };

      PzOcean.prototype.trajectory = function(f, t) {
        if (!f.jumper) return { depth: f.depth + Math.sin(t * 0.9 + f.seed) * (this.mini ? 3 : 7), air: false };
        const q = mod(t + f.phase, f.duration);
        if (q < f.airDuration) {
          const u = q / f.airDuration;
          return { depth: -4 * f.height * u * (1 - u), air: true };
        }
        const u2 = (q - f.airDuration) / f.diveDuration;
        return { depth: f.depth * Math.sin(Math.PI * u2), air: false };
      };

      PzOcean.prototype.path = function(f, t) {
        const x = f.x + f.direction * f.speed * (t - animTime);
        return { x, y: this.surface(x, t) + this.trajectory(f, t).depth };
      };

      PzOcean.prototype.buildSpine = function(f) {
        const segments = 48, length = 3.15 * f.size, step = length / segments;
        let t = animTime + (1.4 * f.size) / f.speed;
        const pts = f.spine;
        pts.length = 0;
        for (let i = 0; i <= segments; i++) {
          const local = 1.4 - (i * 3.15) / segments;
          const base = this.path(f, t);
          const tailness = clamp((1.05 - local) / 2.7, 0, 1);
          const midsection = Math.sin(clamp((1.4 - local) / 3.15, 0, 1) * Math.PI);
          const air = this.trajectory(f, t).air;
          const stroke = Math.sin(animTime * (f.dolphin ? 8.3 : 12) + local * 2.5 + f.seed) * f.size * (f.dolphin ? 0.1 * midsection + 0.27 * tailness * tailness : 0.035 * midsection + 0.17 * tailness * tailness) * (air ? 0.4 : 1);
          base.y += stroke;
          pts.push(base);
          const before = this.path(f, t - 0.004), after = this.path(f, t + 0.004);
          const vel = Math.hypot((after.x - before.x) / 0.008, (after.y - before.y) / 0.008);
          t -= step / Math.max(vel, 1);
        }
        for (let j = 0; j < pts.length; j++) {
          const a = pts[Math.max(0, j - 1)], b = pts[Math.min(pts.length - 1, j + 1)];
          const dx = a.x - b.x, dy = a.y - b.y, n = Math.hypot(dx, dy) || 1;
          pts[j].nx = (-dy / n) * f.direction;
          pts[j].ny = (dx / n) * f.direction;
        }
      };

      PzOcean.prototype.map = function(f, x, y) {
        const index = clamp(((1.4 - x) / 3.15) * 48, 0, 48);
        const i = Math.min(47, Math.floor(index));
        const mix = index - i;
        const a = f.spine[i], b = f.spine[i + 1];
        let nx = a.nx + (b.nx - a.nx) * mix, ny = a.ny + (b.ny - a.ny) * mix;
        const norm = Math.hypot(nx, ny) || 1;
        nx /= norm; ny /= norm;
        return {
          x: a.x + (b.x - a.x) * mix + nx * y * f.size,
          y: a.y + (b.y - a.y) * mix + ny * y * f.size
        };
      };

      PzOcean.prototype.drawClouds = function(dt, dk) {
        const c = this.c;
        for (const item of this.clouds) {
          item.x += item.speed * dt;
          const margin = 140 * item.scale;
          if (item.x - margin > this.w) item.x = -margin;
          c.save();
          c.translate(item.x, item.y + Math.sin(animTime * 0.28 + item.phase) * (this.mini ? 2 : 5));
          c.scale(item.scale, item.scale);
          c.strokeStyle = this.mini || dk ? "#fffef1" : "#485041";
          const bloom = 0.5 + 0.5 * Math.sin(animTime * 0.8 + item.phase);
          c.globalAlpha = this.mini ? 0.14 + bloom * 0.35 : 0.18 + bloom * 0.15;
          c.lineWidth = this.mini ? 3 : 1.9;
          c.stroke(cloudPath);
          c.restore();
        }
      };

      PzOcean.prototype.drawSea = function(dk, ink) {
        const c = this.c;
        c.beginPath();
        c.moveTo(0, this.surface(0));
        for (let x = 0; x <= this.w + 10; x += 10) c.lineTo(x, this.surface(x));
        c.lineTo(this.w, this.h);
        c.lineTo(0, this.h);
        c.closePath();
        c.fillStyle = this.mini ? "#ffffff07" : dk ? "#b7dfca0a" : "#658c7912";
        c.fill();

        const segments = this.mini ? 1 : Math.ceil(this.w / 290);
        const span = this.w / segments;
        for (let i = 0; i < segments; i++) {
          const x = i * span;
          c.save();
          c.translate(x, this.surface(x));
          c.scale(span / 210, this.mini ? 0.55 : 1);
          c.strokeStyle = ink;
          c.globalAlpha = this.mini ? 0.45 : dk ? 0.43 : 0.35;
          c.lineWidth = 1.7;
          const flex = Math.sin(animTime * 0.7 + i) * 3;
          c.beginPath();
          c.moveTo(-6, 0);
          c.bezierCurveTo(32, -18 + flex, 54, -12, 87, -5);
          c.bezierCurveTo(126, 5, 154, 13 + flex, 182, 5);
          c.bezierCurveTo(210, -3, 211, -24, 193, -22);
          c.bezierCurveTo(180, -20, 192, -12, 200, -15);
          c.moveTo(-5, 8);
          c.bezierCurveTo(31, -4, 58, -2 + flex, 91, 6);
          c.bezierCurveTo(124, 14, 154, 22, 175, 18);
          c.moveTo(65, 7);
          c.bezierCurveTo(89, 10, 88, 30 + flex, 72, 27);
          c.bezierCurveTo(65, 25, 65, 21, 69, 20);
          c.stroke();
          c.restore();
        }
      };

      PzOcean.prototype.drawParticles = function(dt, dk, ink) {
        const c = this.c;
        for (let i = this.particles.length - 1; i >= 0; i--) {
          const p = this.particles[i];
          p.age += dt;
          if (p.age >= p.life) {
            this.particles.splice(i, 1);
            continue;
          }
          c.strokeStyle = ink;
          c.beginPath();
          if (p.type === "drop") {
            c.globalAlpha = (1 - p.age / p.life) * (this.mini ? 0.65 : dk ? 0.62 : 0.46);
            c.lineWidth = 1.2;
            p.vy += 230 * p.scale * dt;
            p.x += p.vx * dt;
            p.y += p.vy * dt;
            c.moveTo(p.x, p.y);
            c.lineTo(p.x - p.vx * 0.03, p.y - p.vy * 0.03);
          } else if (p.type === "ripple") {
            c.globalAlpha = (1 - p.age / p.life) * (this.mini ? 0.36 : dk ? 0.32 : 0.26);
            c.lineWidth = 1.0;
            c.ellipse(p.x, p.y, (8 + p.age * 45) * p.scale, (2.5 + p.age * 8.5) * p.scale, 0, 0, TAU);
          } else {
            c.globalAlpha = (1 - p.age / p.life) * (this.mini ? 0.65 : dk ? 0.62 : 0.46);
            c.lineWidth = 1.2;
            p.y -= dt * 11;
            c.arc(p.x, p.y, (1.4 + p.age * 1.5) * p.scale, 0, TAU);
          }
          c.stroke();
        }
        c.globalAlpha = 1;
      };

      PzOcean.prototype.draw = function(dt) {
        const c = this.c;
        const dk = overlay.getAttribute("data-theme") === "dark";
        const ink = this.mini || dk ? "#fffef1" : "#3d4738";
        c.clearRect(0, 0, this.w, this.h);
        c.lineCap = "round";
        c.lineJoin = "round";

        this.drawClouds(dt, dk);
        this.drawSea(dk, ink);

        for (let fi = 0; fi < this.creatures.length; fi++) {
          const f = this.creatures[fi];
          f.x += f.direction * f.speed * dt;
          const margin = f.size * 3;
          if (f.x > this.w + margin) f.x = -margin;
          if (f.x < -margin) f.x = this.w + margin;
          const pose = this.trajectory(f, animTime);
          const water = this.surface(f.x);
          if (f.previousDepth !== null) {
            if (f.previousDepth < 0 && pose.depth >= 0) this.splash(f.x, water, true);
            else if (f.previousDepth >= 0 && pose.depth < 0) this.splash(f.x, water, false);
          }
          f.previousDepth = pose.depth;
          if (pose.depth > 5) {
            f.trail = (f.trail || 0) + dt;
            if (f.trail > 0.25) {
              const tail = this.path(f, animTime - (1.3 * f.size) / f.speed);
              this.add({ type: "bubble", x: tail.x, y: tail.y, age: 0, life: 1.8, scale: this.mini ? 0.5 : 1 });
              f.trail = 0;
            }
          }
          this.buildSpine(f);

          c.save();
          c.strokeStyle = ink;
          c.fillStyle = ink;
          c.globalAlpha = this.mini ? 0.65 : dk ? 0.72 : 0.52;
          c.lineWidth = this.mini ? 1.4 : 2.1;
          c.beginPath();
          const shape = f.dolphin ? dolphShape : fshShape;
          for (let li = 0; li < shape.lines.length; li++) {
            const line = shape.lines[li];
            for (let pi = 0; pi < line.length; pi++) {
              const pt = this.map(f, line[pi][0], line[pi][1]);
              if (pi) c.lineTo(pt.x, pt.y); else c.moveTo(pt.x, pt.y);
            }
          }
          c.stroke();
          const eye = this.map(f, f.dolphin ? 0.73 : 0.55, f.dolphin ? -0.13 : -0.09);
          c.beginPath();
          c.arc(eye.x, eye.y, Math.max(0.65, f.size * 0.027), 0, TAU);
          c.fill();
          c.restore();
        }
        this.drawParticles(dt, dk, ink);
      };

      const seaC = document.getElementById("pz-sea");
      const miniC = document.getElementById("pz-mini");
      const scenes = [];
      if (seaC) scenes.push(new PzOcean(seaC, false));
      if (miniC) scenes.push(new PzOcean(miniC, true));

      const onPointer = (e) => {
        animPointer.x = e.clientX;
        animPointer.y = e.clientY;
      };
      window.addEventListener("pointermove", onPointer, { passive: true });

      function loop(ts) {
        animRaf = 0;
        const dt = animLast ? Math.min((ts - animLast) / 1000, 0.035) : 1 / 60;
        animLast = ts;
        animTime += dt;
        for (let i = 0; i < scenes.length; i++) scenes[i].draw(dt);
        stepEyes(dt);
        animRaf = requestAnimationFrame(loop);
      }
      animRaf = requestAnimationFrame(loop);

      cleanupAnimation = () => {
        if (animRaf) cancelAnimationFrame(animRaf);
        window.removeEventListener("pointermove", onPointer);
      };
    } catch (_) {}
  }

  function shouldWarn(r, d) {
    if (!r) return false;
    if (r.rawVerdict === "SAFE" || r.statusBadge === "SAFE" || r.detection_method === "TRUSTED_WHITELIST") return false;
    if (r.verdict === "Phishing" || r.rawVerdict === "PHISHING_DETECTED" || r.statusBadge === "PHISHING_DETECTED") return true;
    const conf = Number(r.confidence || r.riskScore || 0);
    return conf >= 60;
  }

  function runDomScan() {
    chrome.storage.local.get(["phisheye_protection"], (stored) => {
      if (stored && stored.phisheye_protection === false) {
        return;
      }

      const domData = collectDomSignals();

      chrome.runtime.sendMessage(
        {
          type: "ANALYZE_URL",
          payload: domData
        },
        (response) => {
          if (chrome.runtime.lastError || !response) {
            return;
          }
          if (
            response.rawVerdict === "SERVER_DOWN" ||
            response.statusBadge === "SERVER_DOWN"
          ) {
            return;
          }
          if (response.statusBadge === "MODERATE" || shouldWarn(response, domData)) {
            document.documentElement.setAttribute("data-pz-block-popunders", "1");
          }
          if (shouldWarn(response, domData)) {
            injectWarningOverlay(response, domData);
          }
        }
      );
    });
  }

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "GET_DOM_STATUS") {
      const domData = collectDomSignals();
      chrome.runtime.sendMessage(
        {
          type: "ANALYZE_URL",
          payload: domData
        },
        (scanResult) => {
          if (
            shouldWarn(scanResult, domData)
          ) {
            injectWarningOverlay(scanResult, domData);
          }
          sendResponse({ domData, scanResult });
        }
      );
      return true;
    }

    if (message.type === "DISMISS_WARNING_OVERLAY") {
      unfreezePageRedirects();
      const existing = document.getElementById("phishzero-overlay");
      if (existing) {
        existing.remove();
      }
      sendResponse({ status: "dismissed" });
      return false;
    }

    if (message.type === "SHOW_WARNING_OVERLAY") {
      const domData = collectDomSignals();
      injectWarningOverlay(
        message.payload || {
          verdict: "Phishing",
          confidence: 98.5,
          reasons: ["Manual Zero-Day warning trigger."]
        },
        domData
      );
      sendResponse({ status: "shown" });
      return false;
    }
  });

  runDomScan();

  // Lazy-load DOM observer: Catches phishing kits that render credential fields or decoy overlays 0.5-2.5s after load
  try {
    let lazyTimer = 0;
    const lazyObserver = new MutationObserver((mutations) => {
      if (document.getElementById("phishzero-overlay")) return;
      for (const m of mutations) {
        for (const n of m.addedNodes) {
          if (!n || n.nodeType !== 1) continue;
          if (
            n.tagName === "INPUT" ||
            n.tagName === "FORM" ||
            (n.querySelector && (n.querySelector('input[type="password"]') || n.querySelector("form")))
          ) {
            clearTimeout(lazyTimer);
            lazyTimer = setTimeout(() => {
              if (!document.getElementById("phishzero-overlay")) {
                runDomScan();
              }
            }, 600);
            return;
          }
        }
      }
    });
    lazyObserver.observe(document.documentElement, { childList: true, subtree: true });
    // Disconnect after 15 seconds to free up browser memory
    setTimeout(() => lazyObserver.disconnect(), 15000);
  } catch (_) {}
})();
