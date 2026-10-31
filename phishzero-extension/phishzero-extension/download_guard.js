/**
 * PhishEye download_guard.js  (loaded by background.js via importScripts)
 * Pauses EVERY download the moment it starts, scans it, then cancels or resumes it.
 */
const DG_TIMEOUT_MS = 14000;
const DG_RISKY_EXT = /\.(exe|msi|scr|bat|cmd|com|pif|ps1|vbs|vbe|js|jse|wsf|hta|lnk|jar|apk|dmg|pkg|iso|img|dll|reg|msix|appx)$/i;
const DG_DOUBLE = /\.(pdf|docx?|xlsx?|pptx?|txt|jpe?g|png|gif|mp3|mp4)\.(exe|scr|bat|cmd|com|js|vbs|lnk|msi|jar|hta)$/i;
const DG_RISKY_MIME = /^(application\/(x-msdownload|x-msdos-program|vnd\.microsoft\.portable-executable|x-dosexec|java-archive|vnd\.android\.package-archive|x-apple-diskimage))/i;

const dgAllowed = new Set();      // URLs the user explicitly chose to download anyway
const dgPending = new Map();      // notificationId -> url

function dgHost(u) { try { return new URL(u).hostname.toLowerCase().replace(/^www\./, ""); } catch (_) { return ""; } }

function dgLocalScore(item) {
  const url = item.finalUrl || item.url || "";
  let path = "";
  try { path = decodeURIComponent(new URL(url).pathname).toLowerCase(); } catch (_) {}
  const name = ((item.filename || "").replace(/\\/g, "/").split("/").pop() || path.split("/").pop() || "").toLowerCase();
  let score = 0; const reasons = [];
  if (DG_RISKY_EXT.test(name)) { score += 40; reasons.push("Executable / script file type"); }
  if (DG_DOUBLE.test(name)) { score += 40; reasons.push("Double extension disguises an executable as a document"); }
  if (DG_RISKY_MIME.test(item.mime || "")) { score += 30; reasons.push("Server reports executable content type"); }
  const fh = dgHost(url), ph = dgHost(item.referrer || "");
  if (fh && ph && fh !== ph) { score += 15; reasons.push("File host (" + fh + ") differs from the page (" + ph + ")"); }
  return { score, reasons };
}

async function dgDecide(item) {
  const url = item.finalUrl || item.url || "";

  // 1) Did it start from a page we've already flagged?
  if (item.referrer) {
    try {
      const st = await chrome.storage.local.get([item.referrer]);
      const prev = st && st[item.referrer];
      if (prev && prev.statusBadge === "PHISHING_DETECTED") {
        return { block: true, reasons: ["Download was started by a page flagged as phishing"] };
      }
    } catch (_) {}
  }

  // 2) Ask the backend (blacklist, double-extension, mime, ML, host mismatch ...)
  try {
    const base = await getApiBaseUrl();
    const ctl = new AbortController();
    const to = setTimeout(() => ctl.abort(), DG_TIMEOUT_MS);
    const res = await fetch(base + "/scan-download", {
      method: "POST",
      headers: { "Content-Type": "application/json", "ngrok-skip-browser-warning": "true" },
      body: JSON.stringify({ url, referrer: item.referrer || "", filename: item.filename || "", mime: item.mime || "" }),
      signal: ctl.signal
    });
    clearTimeout(to);
    if (res.ok) {
      const d = await res.json();
      return { block: !!d.block, reasons: d.reasons || [] };
    }
  } catch (_) { /* backend down -> offline rules below */ }

  // 3) Offline rules
  const local = dgLocalScore(item);
  return { block: local.score >= 50, reasons: local.reasons.concat(["(offline check - backend unreachable)"]) };
}

chrome.downloads.onCreated.addListener(async (item) => {
  try {
    const { phisheye_protection } = await chrome.storage.local.get(["phisheye_protection"]);
    if (phisheye_protection === false) return;

    const url = item.finalUrl || item.url || "";
    if (dgAllowed.has(item.url) || dgAllowed.has(url)) { dgAllowed.delete(item.url); dgAllowed.delete(url); return; }

    try { await chrome.downloads.pause(item.id); } catch (_) {}      // hold it before any bytes land
    const verdict = await dgDecide(item);

    if (verdict.block) {
      try { await chrome.downloads.cancel(item.id); } catch (_) {}
      try { await chrome.downloads.erase({ id: item.id }); } catch (_) {}
      const nid = "pe-dl-" + item.id + "-" + Date.now();
      dgPending.set(nid, item.url);
      chrome.notifications.create(nid, {
        type: "basic",
        iconUrl: "icons/icon128.png",
        title: "PhishEye blocked a download",
        message: (verdict.reasons.slice(0, 2).join(" | ") || "Suspicious file") + "\n" + dgHost(url),
        buttons: [{ title: "Download anyway" }],
        requireInteraction: true
      });
    } else {
      try { await chrome.downloads.resume(item.id); } catch (_) {}
    }
    dgLog(item, verdict);
  } catch (_) {
    try { await chrome.downloads.resume(item.id); } catch (__) {}    // never leave a download stuck
  }
});

// Keep the last 30 scan results so the user (and popup) can review them.
async function dgLog(item, verdict) {
  try {
    const { downloadLog } = await chrome.storage.local.get(["downloadLog"]);
    const log = Array.isArray(downloadLog) ? downloadLog : [];
    log.unshift({ url: (item.finalUrl || item.url || "").slice(0, 300), blocked: !!verdict.block,
                  reasons: (verdict.reasons || []).slice(0, 4), at: new Date().toISOString() });
    await chrome.storage.local.set({ downloadLog: log.slice(0, 30) });
  } catch (_) {}
}

chrome.notifications.onButtonClicked.addListener((nid) => {
  const url = dgPending.get(nid);
  if (!url) return;
  dgAllowed.add(url);
  chrome.downloads.download({ url });
  dgPending.delete(nid);
  chrome.notifications.clear(nid);
});
chrome.notifications.onClosed.addListener((nid) => dgPending.delete(nid));

// Badge "DL" when guard.js finds deceptive download buttons on the page.
chrome.runtime.onMessage.addListener((m, sender, sendResponse) => {
  if (m && m.type === "DOWNLOAD_LURES" && sender && sender.tab && typeof sender.tab.id === "number") {
    if (m.count > 0) {
      chrome.action.setBadgeText({ tabId: sender.tab.id, text: "DL!" });
      chrome.action.setBadgeBackgroundColor({ tabId: sender.tab.id, color: "#D97706" });
    }
    if (typeof sendResponse === "function") sendResponse({ ok: true });
  }
  return false;
});
