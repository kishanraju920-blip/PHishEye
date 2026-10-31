
importScripts("download_guard.js");

const CACHE_TTL_MS = 10 * 60 * 1000;
const DEFAULT_API_BASE = "https://phisheye-backend.onrender.com";
const SCAN_ROUTE = "/analyze";
const REPORT_ROUTE = "/report";
const FETCH_TIMEOUT_MS = 15000;

const TRUSTED_DOMAINS = [
  "amazon.in", "amazon.com", "amazon.co.uk", "amazon.de", "amazon.co.jp",
  "google.com", "google.co.in", "google.co.uk", "google.ca", "google.com.au",
  "google.co.jp", "google.de", "google.fr", "github.com", "microsoft.com",
  "paypal.com", "youtube.com", "gmail.com", "facebook.com", "instagram.com",
  "whatsapp.com", "twitter.com", "x.com", "linkedin.com", "apple.com",
  "netflix.com", "spotify.com", "reddit.com", "wikipedia.org", "stackoverflow.com",
  "dropbox.com", "zoom.us", "slack.com", "discord.com", "adobe.com",
  "figma.com", "canva.com", "stripe.com", "shopify.com", "vitap.ac.in",
  "yahoo.com", "bing.com", "outlook.com", "office.com", "live.com",
  "icloud.com", "notion.so", "medium.com", "quora.com", "twitch.tv",
  "tiktok.com", "snapchat.com", "brainly.com", "brainly.in", "chegg.com",
  "coursera.org", "udemy.com", "khanacademy.org", "grammarly.com", "byjus.com",
  "geeksforgeeks.org", "w3schools.com",
  "flipkart.com", "myntra.com", "ajio.com", "meesho.com", "nykaa.com", "snapdeal.com", "tatacliq.com", "jiomart.com", "bigbasket.com", "swiggy.com", "zomato.com", "paytm.com", "phonepe.com", "irctc.co.in", "makemytrip.com", "goibibo.com", "cleartrip.com", "hotstar.com", "jio.com", "airtel.in", "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com", "kotak.com", "ebay.com", "walmart.com", "target.com", "bestbuy.com", "aliexpress.com", "alibaba.com", "etsy.com", "booking.com", "airbnb.com", "uber.com", "ola.com", "cred.club", "zerodha.com", "naukri.com", "linkedin.com", "indeed.com", "gov.in", "nic.in", "ac.in", "edu.in", "bbc.com", "bbc.co.uk", "cnn.com", "nytimes.com", "timesofindia.com", "indiatimes.com", "ndtv.com", "thehindu.com", "hindustantimes.com", "openai.com", "chatgpt.com", "anthropic.com", "claude.ai", "gemini.google.com", "cloudflare.com", "mozilla.org", "python.org", "npmjs.com", "gitlab.com", "trello.com", "pinterest.com", "tumblr.com", "imdb.com", "amazon.ca", "amazon.com.au", "amazon.fr", "amazon.it", "amazon.es", "vit.ac.in", "telegram.org", "hotmail.com", "msn.com", "skype.com", "godaddy.com", "namecheap.com", "mailchimp.com", "salesforce.com", "oracle.com", "ibm.com", "intel.com", "nvidia.com", "amd.com", "samsung.com", "sony.com", "hp.com", "dell.com", "lenovo.com"
];

function isTrustedHost(hostname) {
  const host = (hostname || "").toLowerCase().replace(/\.$/, "");
  return TRUSTED_DOMAINS.some((d) => host === d || host.endsWith(`.${d}`));
}

function extractHostname(rawUrl) {
  if (!rawUrl) return "local-test-page";
  try {
    const parsed = new URL(rawUrl);
    return parsed.hostname || rawUrl;
  } catch (_) {
    return rawUrl;
  }
}

function isScannableUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== "string") return false;
  const lower = rawUrl.trim().toLowerCase();
  if (
    lower.startsWith("chrome://") ||
    lower.startsWith("chrome-extension://") ||
    lower.startsWith("edge://") ||
    lower.startsWith("about:") ||
    lower.startsWith("devtools://")
  ) {
    return false;
  }
  return /^https?:\/\//i.test(lower);
}

function computeStatusBadge(riskScore, isMalicious) {
  if (isMalicious || riskScore >= 60) {
    return "PHISHING_DETECTED";
  }
  if (riskScore >= 30) {
    return "MODERATE";
  }
  return "SAFE";
}

/**
 * Extracts exact threat intelligence & lexical feature reasons from the FastAPI `/analyze` response.
 */
function buildReasonsFromModel(data, domPayload, statusBadge = "SAFE") {
  const reasons = [];
  const isSafe = statusBadge === "SAFE";

  if (Array.isArray(data?.reasons) && data.reasons.length > 0) {
    data.reasons.forEach((r) => {
      if (!r || reasons.includes(r)) return;
      if (
        isSafe &&
        /flagged|suspicious|multiple hyphens|multiple subdomains|long url|high character|unencrypted|hidden tracking|password input field/i.test(
          r
        )
      ) {
        return;
      }
      reasons.push(r);
    });
  }

  const f = data?.lexical_features;
  if (isSafe) {
    if (reasons.length === 0) {
      reasons.push("Clean domain & URL lexical profile");
    }
    if (f && f.has_https === 1 && !reasons.some((r) => /https/i.test(r))) {
      reasons.push("Encrypted HTTPS connection verified");
    }
    if (!reasons.some((r) => /form|credential|authority|tranco/i.test(r))) {
      reasons.push("No deceptive credential-harvesting forms or brand spoofing detected");
    }
    return reasons;
  }

  // Exact lexical features from `features.py` (only appended for non-safe sites)
  if (f && typeof f === "object") {
    if (f.has_suspicious_words === 1) {
      const msg = "Suspicious phishing keywords detected in URL (has_suspicious_words = 1)";
      if (!reasons.includes(msg)) reasons.push(msg);
    }
    if (f.has_ip === 1) {
      const msg = "Raw IP address used instead of domain name (has_ip = 1)";
      if (!reasons.includes(msg)) reasons.push(msg);
    }
    if (f.has_https === 0) {
      const msg = "Unencrypted HTTP connection — missing HTTPS/SSL (has_https = 0)";
      if (!reasons.includes(msg)) reasons.push(msg);
    }
    if (Number(f.count_at) > 0) {
      const msg = `Credential spoofing '@' symbol present in URL (count_at = ${f.count_at})`;
      if (!reasons.includes(msg)) reasons.push(msg);
    }
    if (Number(f.count_hyphens) >= 2) {
      const msg = `Multiple hyphens in URL / domain (count_hyphens = ${f.count_hyphens})`;
      if (!reasons.includes(msg)) reasons.push(msg);
    }
    if (Number(f.count_subdomains) >= 2) {
      const msg = `Multiple subdomains detected (count_subdomains = ${f.count_subdomains}, count_dots = ${f.count_dots ?? 0})`;
      if (!reasons.includes(msg)) reasons.push(msg);
    }
    if (Number(f.url_length) >= 55) {
      const msg = `Long URL structure (url_length = ${f.url_length}, path_length = ${f.path_length ?? 0})`;
      if (!reasons.includes(msg)) reasons.push(msg);
    }
    if (Number(f.entropy) >= 4.1) {
      const msg = `High character randomness / Shannon entropy (entropy = ${f.entropy})`;
      if (!reasons.includes(msg)) reasons.push(msg);
    }
  }

  return reasons.length > 0 ? reasons : ["AI model evaluation completed"];
}

function evaluateOfflineFallback(payload) {
  const rawUrl = payload?.url || "";
  const url = rawUrl.toLowerCase();
  const hostname = payload?.hostname || extractHostname(rawUrl);
  const suspiciousKeywords = [
    "paypa1",
    "paypal",
    "phish",
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "banking",
    "wallet",
    "confirm",
    "password"
  ];
  const riskMirrorKeywords = [
    "netmirror",
    "mirror",
    "pirate",
    "torrent",
    "movierulz",
    "ibomma",
    "tamilrockers",
    "filmyzilla",
    "hdhub",
    "vegamovies",
    "123movies",
    "fmovies",
    "soap2day",
    "pikashow",
    "thoptv",
    "modapk",
    "apkmod",
    "happymod",
    "crack",
    "keygen",
    "fitgirl"
  ];
  const cautionTlds = [
    "cc", "gg", "to", "sx", "tv", "lol", "fun", "site", "online",
    "live", "xyz", "top", "click", "icu", "cyou", "sbs", "cfd", "cam", "buzz"
  ];
  const hostLower = (hostname || "").toLowerCase();
  const matchedKeywords = suspiciousKeywords.filter((kw) => hostLower.includes(kw));
  const matchedMirrorKw = riskMirrorKeywords.filter((kw) => hostLower.includes(kw));
  const tld = hostLower.includes(".") ? hostLower.split(".").pop() : "";

  const isHttpOrLocal =
    url.startsWith("file://") ||
    url.includes("localhost") ||
    url.includes("127.0.0.1") ||
    !url.startsWith("https://");

  const hyphenCount = (hostLower.match(/-/g) || []).length;
  const dotCount = (hostLower.match(/\./g) || []).length;

  const reasons = [];

  let riskScore = 3.5;

  if (matchedKeywords.length > 0) {
    riskScore += 45;
    reasons.push(
      `Suspicious phishing keywords in hostname (${matchedKeywords.slice(0, 4).join(", ")})`
    );
  }
  if (matchedMirrorKw.length > 0) {
    riskScore += 56;
    reasons.push(
      `High-risk mirror / streaming / APK lure domain pattern ('${matchedMirrorKw[0]}')`
    );
  }
  if (cautionTlds.includes(tld)) {
    riskScore += 28;
    reasons.push(`Domain uses high-abuse TLD (.${tld})`);
  }
  if (isHttpOrLocal) {
    riskScore += 20;
    reasons.push("Unencrypted HTTP or local test origin (has_https = 0)");
  }
  if (hyphenCount >= 2) {
    riskScore += 18;
    reasons.push(`Multiple hyphens in domain name (count_hyphens = ${hyphenCount})`);
  }
  if (hostLower.length >= 38) {
    riskScore += 12;
    reasons.push(`Unusually long hostname (${hostLower.length} chars)`);
  }
  if (payload?.has_password_field && isHttpOrLocal) {
    riskScore += 25;
    reasons.push(
      `Password input field (${payload.password_field_count || 1}) detected on unverified origin`
    );
  }
  if (payload?.external_form_action) {
    riskScore += 30;
    reasons.push("Form action submits credentials to an external domain");
  }
  if (payload?.right_click_disabled) {
    riskScore += 10;
    reasons.push("Context menu (right-click inspection) disabled by script");
  }
  if ((payload?.iframe_count || 0) >= 2) {
    riskScore += 16;
    reasons.push(`Page embeds ${payload.iframe_count} external/adware iframe overlays`);
  }
  if (Array.isArray(payload?.exfil_webhooks) && payload.exfil_webhooks.length > 0) {
    riskScore = Math.max(riskScore, 96.5);
    reasons.unshift(`Critical: ${payload.exfil_webhooks[0]} detected in page code`);
  }
  if (Array.isArray(payload?.scam_intent_hits) && payload.scam_intent_hits.length > 0) {
    riskScore += 42;
    reasons.unshift(`Page content analysis: ${payload.scam_intent_hits[0]}`);
  }
  if (Array.isArray(payload?.popunder_scripts) && payload.popunder_scripts.length > 0) {
    riskScore += 28;
    reasons.push(payload.popunder_scripts[0]);
  }
  if ((payload?.suspicious_download_links || 0) >= 1) {
    riskScore += 26;
    reasons.push(`Page hosts ${payload.suspicious_download_links} direct executable/APK/torrent download link(s)`);
  }

  riskScore = Math.max(1.5, Math.min(99.4, Number(riskScore.toFixed(1))));
  const statusBadge = computeStatusBadge(riskScore, riskScore >= 60);
  const isSuspicious = statusBadge === "PHISHING_DETECTED" || statusBadge === "SUSPICIOUS";

  if (statusBadge === "SAFE") {
    reasons.length = 0;
    reasons.push(`Domain ${hostname} has a clean lexical & structural profile`);
    if (!isHttpOrLocal) {
      reasons.push("Encrypted HTTPS connection verified");
    }
    reasons.push(`Normal domain structure (dots = ${dotCount}, hyphens = ${hyphenCount})`);
  }

  return {
    cacheVer: 4,
    url: rawUrl,
    hostname,
    verdict: isSuspicious ? "Phishing" : statusBadge === "MODERATE" ? "Moderate" : "Benign",
    rawVerdict: isSuspicious ? "PHISHING_DETECTED" : statusBadge === "MODERATE" ? "MODERATE" : "SAFE",
    statusBadge,
    is_malicious: isSuspicious,
    riskScore,
    confidence: riskScore,
    confidence_score: Number((riskScore / 100).toFixed(4)),
    detection_method: "OFFLINE_HEURISTIC_FALLBACK",
    layer: "Offline Fallback Engine",
    is_zero_day: true,
    mode: "Offline Fallback Engine",
    reasons,
    domMetrics: payload,
    timestamp: new Date().toISOString()
  };
}

function updateActionBadge(statusBadge, tabId) {
  let badgeText = "SAFE";
  let badgeColor = "#16A34A";

  if (statusBadge === "PHISHING_DETECTED" || statusBadge === "SUSPICIOUS") {
    badgeText = "!";
    badgeColor = "#E11D48";
  } else if (statusBadge === "MODERATE") {
    badgeText = "~";
    badgeColor = "#D97706";
  }

  const details = { text: badgeText };
  const colorDetails = { color: badgeColor };

  if (typeof tabId === "number") {
    details.tabId = tabId;
    colorDetails.tabId = tabId;
  }

  try {
    Promise.resolve(chrome.action.setBadgeText(details)).catch(() => {});
    Promise.resolve(chrome.action.setBadgeBackgroundColor(colorDetails)).catch(() => {});
  } catch (_) {}
}

async function getApiBaseUrl() {
  try {
    const stored = await chrome.storage.local.get(["phisheye_api_base"]);
    if (stored && typeof stored.phisheye_api_base === "string" && stored.phisheye_api_base.trim()) {
      const val = stored.phisheye_api_base.trim().replace(/\/+$/, "");
      if (!val.includes("ngrok") && !val.includes("localhost") && !val.includes("127.0.0.1")) {
        return val;
      }
      chrome.storage.local.set({ phisheye_api_base: DEFAULT_API_BASE });
    }
  } catch (_) {}
  return DEFAULT_API_BASE;
}

async function handleAnalyzeUrl(payload, senderTabId) {
  const targetUrl = (payload?.url || "").trim();
  const hostname = payload?.hostname || extractHostname(targetUrl);

  if (!isScannableUrl(targetUrl)) {
    return null;
  }

  // Check if protection is paused
  try {
    const protStored = await chrome.storage.local.get(["phisheye_protection"]);
    if (protStored && protStored.phisheye_protection === false) {
      return null;
    }
  } catch (_) {}

  if (isTrustedHost(hostname)) {
    const safeResult = {
      url: targetUrl,
      hostname,
      verdict: "Benign",
      rawVerdict: "SAFE",
      statusBadge: "SAFE",
      is_malicious: false,
      riskScore: 0.1,
      confidence: 0.1,
      confidence_score: 0.001,
      layer: "PhishEye Trusted Domain List",
      detection_method: "TRUSTED_WHITELIST",
      is_zero_day: false,
      mode: "PhishEye Trusted Domain List",
      reasons: ["Verified authority domain"],
      timestamp: new Date().toISOString()
    };
    const rec = { latestScan: safeResult, [targetUrl]: safeResult };
    if (typeof senderTabId === "number") rec[`tab_${senderTabId}`] = safeResult;
    await chrome.storage.local.set(rec);
    updateActionBadge("SAFE", senderTabId);
    return safeResult;
  }

  let result;
  const apiBase = await getApiBaseUrl();

  // Map content.js DOM signals to FastAPI's DOMSignals schema
  const domSignals = {
    password_inputs: Number(payload?.password_field_count || 0),
    hidden_inputs: Number(payload?.hidden_input_count || 0),
    iframe_count: Number(payload?.iframe_count || 0),
    external_form_action: Boolean(payload?.external_form_action),
    context_menu_disabled: Boolean(payload?.right_click_disabled),
    favicon_url: String(payload?.favicon_url || ""),
    logo_urls: Array.isArray(payload?.logo_urls) ? payload.logo_urls.slice(0, 4) : [],
    logo_hints: Array.isArray(payload?.logo_hints) ? payload.logo_hints.slice(0, 4) : [],
    page_title: String(payload?.title || "").slice(0, 160),
    exfil_webhooks: Array.isArray(payload?.exfil_webhooks) ? payload.exfil_webhooks.slice(0, 5) : [],
    popunder_scripts: Array.isArray(payload?.popunder_scripts) ? payload.popunder_scripts.slice(0, 5) : [],
    suspicious_download_links: Number(payload?.suspicious_download_links || 0),
    scam_intent_hits: Array.isArray(payload?.scam_intent_hits) ? payload.scam_intent_hits.slice(0, 6) : [],
    page_text_sample: String(payload?.page_text_sample || "").slice(0, 600),
    cross_origin_form_detected: Boolean(payload?.cross_origin_form_detected),
    form_action_destinations: Array.isArray(payload?.form_action_destinations) ? payload.form_action_destinations.slice(0, 4) : [],
    has_credential_inputs: Boolean(payload?.has_credential_inputs),
    credential_input_types: Array.isArray(payload?.credential_input_types) ? payload.credential_input_types.slice(0, 4) : []
  };

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    const response = await fetch(`${apiBase}${SCAN_ROUTE}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "ngrok-skip-browser-warning": "true"
      },
      body: JSON.stringify({
        url: targetUrl,
        dom_signals: domSignals
      }),
      signal: controller.signal
    });
    clearTimeout(timer);

    if (!response.ok) {
      throw new Error(`FastAPI /analyze responded with status ${response.status}`);
    }

    const data = await response.json();

    // Let the backend model's threat_score and verdict directly drive the extension
    const isMalicious =
      Boolean(data.is_malicious) ||
      data.verdict === "PHISHING_DETECTED" ||
      data.verdict === "MALICIOUS";

    let riskScore =
      typeof data.threat_score === "number"
        ? data.threat_score
        : typeof data.risk_score === "number"
        ? data.risk_score
        : 0.0;

    riskScore = Math.max(0.1, Math.min(100.0, Number(riskScore.toFixed(1))));
    const statusBadge = data.status_badge || computeStatusBadge(riskScore, isMalicious);
    const reasons = buildReasonsFromModel(data, payload, statusBadge);
    const layerName = data.layer || "Layer 2: Deep AI + DOM Shield";

    result = {
      cacheVer: 4,
      url: data.url || targetUrl,
      hostname: data.hostname || hostname,
      verdict:
        (statusBadge === "SUSPICIOUS" || statusBadge === "PHISHING_DETECTED")
          ? "Phishing"
          : statusBadge === "MODERATE"
          ? "Moderate"
          : "Benign",
      rawVerdict:
        (statusBadge === "SUSPICIOUS" || statusBadge === "PHISHING_DETECTED")
          ? "PHISHING_DETECTED"
          : statusBadge === "MODERATE"
          ? "MODERATE"
          : "SAFE",
      statusBadge,
      is_malicious: isMalicious,
      riskScore,
      confidence: riskScore,
      ml_probability: data.ml_probability ?? riskScore,
      dom_penalty: data.dom_penalty ?? 0,
      confidence_score: Number((riskScore / 100).toFixed(4)),
      layer: layerName,
      detection_method: data.detection_method || "ML_XGBOOST_ZERO_DAY",
      is_zero_day: Boolean(data.is_zero_day ?? true),
      threat_details: data.threat_details || reasons[0] || "",
      lexical_features: data.lexical_features || null,
      reports_count: data.reports_count ?? 0,
      mode: layerName,
      reasons,
      domMetrics: payload || null,
      timestamp: new Date().toISOString()
    };
  } catch (error) {
    // Offline Fallback Mode when FastAPI backend is unreachable
    result = evaluateOfflineFallback(payload);
  }

  // Persist scan result in chrome.storage.local under latestScan, URL, and tabId
  const storageRecord = {
    latestScan: result,
    [targetUrl]: result
  };
  if (typeof senderTabId === "number") {
    storageRecord[`tab_${senderTabId}`] = result;
  }

  await chrome.storage.local.set(storageRecord);
  updateActionBadge(result.statusBadge, senderTabId);

  return result;
}

async function handleSandboxUrl(payload) {
  const targetUrl = (payload?.url || "").trim();
  const apiBase = await getApiBaseUrl();
  const response = await fetch(`${apiBase}/sandbox`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "ngrok-skip-browser-warning": "true"
    },
    body: JSON.stringify({ url: targetUrl, label: payload?.label === "safe" ? "safe" : "phishing" })
  });
  if (!response.ok) {
    throw new Error(`Sandbox request failed with HTTP ${response.status}`);
  }
  return await response.json();
}

async function handleReportUrl(payload) {
  const targetUrl = (payload?.url || "").trim();
  const apiBase = await getApiBaseUrl();
  let backendMessage = null;

  try {
    const ctrl = new AbortController();
    const tmr = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
    const res = await fetch(`${apiBase}${REPORT_ROUTE}`, {
      signal: ctrl.signal,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "ngrok-skip-browser-warning": "true"
      },
      body: JSON.stringify({ url: targetUrl, label: payload?.label === "safe" ? "safe" : "phishing" })
    });
    clearTimeout(tmr);
    const data = await res.json();
    backendMessage = data.message || data.detail;
  } catch (_) {}

  const reportEntry = {
    url: targetUrl || "unknown",
    label: payload?.label === "safe" ? "safe" : "phishing",
    reason: payload?.reason || "User report",
    reportedAt: new Date().toISOString()
  };

  const stored = await chrome.storage.local.get(["reportedUrls"]);
  const reportedUrls = Array.isArray(stored.reportedUrls) ? stored.reportedUrls : [];
  reportedUrls.push(reportEntry);
  if (reportedUrls.length > 500) reportedUrls.splice(0, reportedUrls.length - 500);
  await chrome.storage.local.set({ reportedUrls });

  return {
    success: true,
    message: backendMessage || "Thanks for reporting",
    mode: "Backend + Local Threat Report Store",
    reportedCount: reportedUrls.length
  };
}

// --- Block Pop-Under & Forced New-Tab Redirects Spawned by Flagged Tabs ---
chrome.tabs.onCreated.addListener((newTab) => {
  if (!newTab || typeof newTab.openerTabId !== "number" || typeof newTab.id !== "number") {
    return;
  }
  const rawDest = (newTab.pendingUrl || newTab.url || "").toLowerCase();
  if (
    rawDest.startsWith("chrome://") ||
    rawDest.startsWith("edge://") ||
    rawDest.startsWith("https://www.google.com")
  ) {
    return;
  }

  chrome.storage.local.get([`tab_${newTab.openerTabId}`, "phisheye_protection"], (stored) => {
    if (stored && stored.phisheye_protection === false) return;
    const openerScan = stored?.[`tab_${newTab.openerTabId}`];
    if (!openerScan) return;

    const isFlaggedOpener =
      openerScan.statusBadge === "PHISHING_DETECTED" ||
      openerScan.statusBadge === "SUSPICIOUS" ||
      openerScan.statusBadge === "MODERATE" ||
      Number(openerScan.riskScore || 0) >= 30;

    if (isFlaggedOpener) {
      const destHost = extractHostname(rawDest);
      // If pop-under opens about:blank or a different domain from a flagged tab, kill it immediately
      if (!rawDest || rawDest === "about:blank" || destHost !== openerScan.hostname) {
        chrome.tabs.remove(newTab.id).catch(() => {});
        chrome.tabs.update(newTab.openerTabId, { active: true }).catch(() => {});
      }
    }
  });
});

// --- Listen to Tab Navigation (chrome.tabs.onUpdated) ---
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  const targetUrl =
    changeInfo.url || (changeInfo.status === "complete" ? tab?.url : null);

  if (!targetUrl || !isScannableUrl(targetUrl)) {
    return;
  }

  if (changeInfo.url) {
    handleAnalyzeUrl(
      {
        url: targetUrl,
        hostname: extractHostname(targetUrl)
      },
      tabId
    ).catch(() => {});
  } else if (changeInfo.status === "complete") {
    chrome.storage.local.get([targetUrl, `tab_${tabId}`], (stored) => {
      let existing = stored?.[targetUrl] || stored?.[`tab_${tabId}`];
      if (existing && (existing.cacheVer !== 4 || Date.now() - Date.parse(existing.timestamp || 0) > CACHE_TTL_MS)) existing = null;
      if (!existing) {
        handleAnalyzeUrl(
          {
            url: targetUrl,
            hostname: extractHostname(targetUrl)
          },
          tabId
        ).catch(() => {});
      } else {
        updateActionBadge(existing.statusBadge, tabId);
      }
    });
  }
});

// --- Listen to Tab Activation (chrome.tabs.onActivated) ---
chrome.tabs.onActivated.addListener((activeInfo) => {
  if (!activeInfo || typeof activeInfo.tabId !== "number") return;

  chrome.tabs.get(activeInfo.tabId, (tab) => {
    if (chrome.runtime.lastError || !tab || !isScannableUrl(tab.url)) {
      return;
    }

    chrome.storage.local.get([tab.url, `tab_${tab.id}`], (stored) => {
      let existing = stored?.[tab.url] || stored?.[`tab_${tab.id}`];
      if (existing && (existing.cacheVer !== 4 || Date.now() - Date.parse(existing.timestamp || 0) > CACHE_TTL_MS)) existing = null;
      if (existing) {
        updateActionBadge(existing.statusBadge, tab.id);
        chrome.storage.local.set({ latestScan: existing });
      } else {
        handleAnalyzeUrl(
          {
            url: tab.url,
            hostname: extractHostname(tab.url)
          },
          tab.id
        ).catch(() => {});
      }
    });
  });
});

// --- Message Listener for Content Script & Popup ---
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.type) {
    return false;
  }

  if (message.type === "ANALYZE_URL" || message.type === "SCAN_URL") {
    const tabId = message.tabId ?? sender?.tab?.id;
    handleAnalyzeUrl(message.payload, tabId)
      .then((result) => sendResponse(result))
      .catch((err) =>
        sendResponse({
          verdict: "Benign",
          statusBadge: "SAFE",
          riskScore: 0,
          confidence: 0,
          reasons: [`Scan error: ${err.message}`]
        })
      );
    return true;
  }

  if (message.type === "REPORT_URL") {
    handleReportUrl(message.payload)
      .then((res) => sendResponse(res))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (message.type === "SANDBOX_URL") {
    handleSandboxUrl(message.payload)
      .then((res) => sendResponse(res))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (message.type === "BATCH_CHECK_URLS") {
    const urls = Array.isArray(message.urls) ? message.urls.slice(0, 35) : [];
    (async () => {
      const results = {};
      const apiBase = await getApiBaseUrl();
      const stored = await chrome.storage.local.get(urls);

      await Promise.all(
        urls.map(async (rawUrl) => {
          try {
            const hostname = extractHostname(rawUrl);
            if (isTrustedHost(hostname)) {
              results[rawUrl] = {
                statusBadge: "SAFE",
                riskScore: 0.1,
                reasons: ["Verified authority domain (PhishEye Trusted List)"]
              };
              return;
            }

            const cached = stored?.[rawUrl];
            if (
              cached &&
              cached.cacheVer === 4 &&
              Date.now() - Date.parse(cached.timestamp || 0) <= CACHE_TTL_MS
            ) {
              results[rawUrl] = {
                statusBadge: cached.statusBadge || "SAFE",
                riskScore: cached.riskScore ?? 0.1,
                reasons: cached.reasons || ["Verified clean domain"]
              };
              return;
            }

            const ctrl = new AbortController();
            const timer = setTimeout(() => ctrl.abort(), 3500);
            try {
              const res = await fetch(`${apiBase}${SCAN_ROUTE}`, {
                method: "POST",
                headers: {
                  "Content-Type": "application/json",
                  "ngrok-skip-browser-warning": "true"
                },
                body: JSON.stringify({ url: rawUrl, dom_signals: {} }),
                signal: ctrl.signal
              });
              clearTimeout(timer);
              if (res.ok) {
                const data = await res.json();
                const isMal =
                  Boolean(data.is_malicious) ||
                  data.verdict === "PHISHING_DETECTED" ||
                  data.verdict === "MALICIOUS";
                const score = Math.max(
                  0.1,
                  Math.min(100, Number((data.threat_score ?? data.risk_score ?? 0.1).toFixed(1)))
                );
                const badge = data.status_badge || computeStatusBadge(score, isMal);
                const entry = {
                  cacheVer: 4,
                  statusBadge: badge,
                  riskScore: score,
                  reasons: Array.isArray(data.reasons) && data.reasons.length
                    ? data.reasons
                    : ["Evaluated by PhishEye 54-feature AI model"],
                  timestamp: new Date().toISOString()
                };
                results[rawUrl] = entry;
                chrome.storage.local.set({ [rawUrl]: entry });
                return;
              }
            } catch (_) {
              clearTimeout(timer);
            }

            const fallback = evaluateOfflineFallback({ url: rawUrl, hostname });
            results[rawUrl] = {
              statusBadge: fallback.statusBadge,
              riskScore: fallback.riskScore,
              reasons: fallback.reasons
            };
          } catch (_) {
            results[rawUrl] = { statusBadge: "SAFE", riskScore: 0.1, reasons: ["Clean URL"] };
          }
        })
      );

      sendResponse({ results });
    })();
    return true;
  }

  return false;
});