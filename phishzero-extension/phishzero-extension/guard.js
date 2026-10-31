/**
 * PhishEye guard.js  (content script, run_at: document_start)
 *  A) Hard lock: while the warning overlay is up, the page underneath cannot scroll, be clicked,
 *     be tabbed into, or remove the overlay.
 *  B) Fake-download guard: intercepts clicks on deceptive "Download / Update Flash Player" style
 *     buttons, executable links, script-fired downloads and invisible click-hijack layers.
 */
(() => {
  "use strict";
  if (window.__peGuard) return;
  window.__peGuard = true;

  const OVERLAY_ID = "phishzero-overlay";
  const hasContext = () => {
    try {
      return Boolean(typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.id);
    } catch (_) {
      return false;
    }
  };

  const idOf = (el) => {
    try {
      return el && el.nodeType === 1 && typeof el.getAttribute === "function"
        ? String(el.getAttribute("id") || "")
        : "";
    } catch (_) {
      return "";
    }
  };

  const isOurs = (el) => {
    const id = idOf(el);
    return Boolean(id) && (id === OVERLAY_ID || id === "pe-dl-modal" || id.startsWith("pz-"));
  };

  const inOurUi = (e) => {
    try {
      const path = typeof e.composedPath === "function" ? e.composedPath() : [];
      return path.some((n) => n && n.nodeType === 1 && isOurs(n));
    } catch (_) {
      return false;
    }
  };

  /* ===================== A. SCROLL / INTERACTION LOCK ===================== */
  let locked = false;
  let userDismissed = false;
  let savedOverlay = null;
  let reattach = 0;
  let keepAlive = 0;
  let timer = 0;
  const inerted = new Set();
  const savedStyle = new Map();

  function forceStyle(el, prop, val) {
    if (!el || !el.style) return;
    try {
      if (!savedStyle.has(el)) savedStyle.set(el, {});
      const s = savedStyle.get(el);
      if (!(prop in s)) s[prop] = [el.style.getPropertyValue(prop), el.style.getPropertyPriority(prop)];
      el.style.setProperty(prop, val, "important");
    } catch (_) {}
  }

  function applyLock() {
    forceStyle(document.documentElement, "overflow", "hidden");
    forceStyle(document.body, "overflow", "hidden");
    if (document.body && document.body.children) {
      for (const el of document.body.children) {
        if (!isOurs(el)) {
          forceStyle(el, "pointer-events", "none");
          forceStyle(el, "user-select", "none");
          if (!el.inert) {
            try {
              el.inert = true;
              inerted.add(el);
            } catch (_) {}
          }
        }
      }
    }
  }

  function releaseLock() {
    inerted.forEach((el) => {
      try {
        el.inert = false;
      } catch (_) {}
    });
    inerted.clear();
    savedStyle.forEach((props, el) => {
      try {
        for (const p in props) {
          const [v, pr] = props[p];
          if (v) el.style.setProperty(p, v, pr);
          else el.style.removeProperty(p);
        }
      } catch (_) {}
    });
    savedStyle.clear();
    clearInterval(keepAlive);
    keepAlive = 0;
  }

  function check() {
    timer = 0;
    const ov = document.getElementById(OVERLAY_ID);
    if (ov) {
      savedOverlay = ov;
      locked = true;
      applyLock();
      if (!keepAlive) keepAlive = setInterval(applyLock, 300);
    } else if (locked) {
      if (!userDismissed && savedOverlay && reattach < 25) {
        reattach++;
        try {
          (document.body || document.documentElement).appendChild(savedOverlay);
          applyLock();
          return;
        } catch (_) {}
      }
      locked = false;
      userDismissed = false;
      savedOverlay = null;
      releaseLock();
    }
  }

  const schedule = () => {
    if (!timer) timer = setTimeout(check, 50);
  };

  try {
    new MutationObserver(schedule).observe(document, { childList: true, subtree: true });
  } catch (_) {}

  const SCROLL_KEYS = new Set([" ", "Spacebar", "ArrowUp", "ArrowDown", "PageUp", "PageDown", "Home", "End"]);
  [
    "wheel",
    "touchmove",
    "touchstart",
    "touchend",
    "pointerdown",
    "pointerup",
    "mousedown",
    "mouseup",
    "click",
    "dblclick",
    "auxclick",
    "contextmenu",
    "submit"
  ].forEach((t) =>
    window.addEventListener(
      t,
      (e) => {
        if (locked && !inOurUi(e)) {
          e.preventDefault();
          e.stopImmediatePropagation();
        }
      },
      { capture: true, passive: false }
    )
  );
  window.addEventListener(
    "keydown",
    (e) => {
      if (locked && !inOurUi(e) && SCROLL_KEYS.has(e.key)) {
        e.preventDefault();
        e.stopImmediatePropagation();
      }
    },
    true
  );

  document.addEventListener(
    "click",
    (e) => {
      const t = e.target;
      if (t && typeof t.closest === "function" && t.closest("#pz-confirm-continue")) {
        userDismissed = true;
      }
    },
    true
  );

  if (hasContext()) {
    try {
      chrome.runtime.onMessage.addListener((m) => {
        if (m && m.type === "DISMISS_WARNING_OVERLAY") userDismissed = true;
      });
    } catch (_) {}
  }

  /* ===================== B. FAKE-DOWNLOAD GUARD ===================== */
  const BLOCK_AT = 3;
  const RISKY = /\.(exe|msi|scr|bat|cmd|com|pif|ps1|vbs|vbe|js|jse|wsf|hta|lnk|jar|apk|dmg|pkg|iso|img|dll|msix|appx)$/i;
  const DOUBLE = /\.(pdf|docx?|xlsx?|pptx?|txt|jpe?g|png|gif|mp3|mp4)\.(exe|scr|bat|cmd|com|js|vbs|lnk|msi|jar|hta)$/i;
  const LURE = /(flash|java\b|codec|player|browser|chrome|firefox|edge|driver|antivirus|security|virus|plugin|extension|update)/;
  const ACTION = /(download|install|update|upgrade|get |run |start |allow)/;
  const DLWORD = /(download|install|update|upgrade)/;
  const IP_HOST = /^\d{1,3}(\.\d{1,3}){3}$|^\[?[0-9a-f:]+\]?$/i;
  const bypass = new WeakSet();
  let pageStatus = "";

  const normHost = (h) => (h || "").toLowerCase().replace(/^www\./, "");
  if (hasContext()) {
    try {
      chrome.storage.local.get([location.href], (r) => {
        if (hasContext() && chrome.runtime.lastError) return;
        pageStatus = (r && r[location.href] && r[location.href].statusBadge) || "";
      });
      chrome.storage.onChanged.addListener((c) => {
        if (c && c[location.href] && c[location.href].newValue) {
          pageStatus = c[location.href].newValue.statusBadge || "";
        }
      });
    } catch (_) {}
  }

  function invisibleLayer(target) {
    try {
      let n = target,
        depth = 0;
      while (n && n.nodeType === 1 && depth++ < 6) {
        const cs = getComputedStyle(n);
        if ((cs.position === "fixed" || cs.position === "absolute") && parseFloat(cs.opacity) < 0.05) {
          const r = n.getBoundingClientRect();
          if (r.width >= innerWidth * 0.6 && r.height >= innerHeight * 0.6) return true;
        }
        n = n.parentElement;
      }
    } catch (_) {}
    return false;
  }

  function classify(el, e, target, deep) {
    const why = [];
    let score = 0;
    const add = (n, m) => {
      score += n;
      why.push(m);
    };

    const text = String(
      el.innerText || el.value || (el.getAttribute && el.getAttribute("aria-label")) || ""
    )
      .trim()
      .slice(0, 120)
      .toLowerCase();
    const rawHref =
      (typeof el.href === "string" ? el.href : "") ||
      (el.getAttribute && (el.getAttribute("data-href") || el.getAttribute("data-url"))) ||
      "";
    let url = null;
    try {
      if (rawHref) url = new URL(rawHref, location.href);
    } catch (_) {}
    let path = url ? url.pathname.toLowerCase() : "";
    try {
      path = decodeURIComponent(path);
    } catch (_) {}

    const hasDl = Boolean(el.hasAttribute && el.hasAttribute("download"));
    const sameHost = Boolean(url) && normHost(url.hostname) === normHost(location.hostname);
    const risky = Boolean(url) && RISKY.test(path);
    const dbl = Boolean(url) && DOUBLE.test(path);
    const lure = LURE.test(text) && ACTION.test(text);
    const noRealTarget =
      !url || /^javascript:/i.test(rawHref) || (Boolean(url.hash) && url.pathname === location.pathname);
    const scriptBtn = DLWORD.test(text) && noRealTarget;
    const downloadish = risky || dbl || hasDl || lure || scriptBtn;
    if (!downloadish) return { score: 0, why };

    if (dbl) add(3, "Double file extension disguises an executable as a document");
    else if (risky) add(2, "Link points straight to a program/script file");
    if (url && !sameHost && /^https?:$/.test(url.protocol) && (risky || hasDl)) {
      add(1, "File is hosted on a different site (" + url.hostname + ")");
    }
    if (url && url.protocol === "data:") add(2, "File is generated inside the page (data: URL)");
    if (url && IP_HOST.test(url.hostname)) add(2, "File is served from a raw IP address");
    if (lure) add(2, "Button wording imitates a fake software update/installer");
    if (scriptBtn) add(1, '"Download" button isn\'t a real file link (script-driven)');
    if (e && e.isTrusted === false && (hasDl || risky)) {
      add(3, "A script started this download without you clicking");
    }
    if (deep && invisibleLayer(target)) {
      add(3, "You clicked through an invisible overlay (click-hijacking)");
    }
    if (pageStatus === "PHISHING_DETECTED") add(3, "This page was flagged as phishing");
    else if (pageStatus === "MODERATE") add(1, "This page has a moderate risk score");
    return { score, why };
  }

  function showModal(r, el) {
    const old = document.getElementById("pe-dl-modal");
    if (old) old.remove();
    const host = document.createElement("div");
    host.id = "pe-dl-modal";
    host.style.cssText = "all:initial;position:fixed;inset:0;z-index:2147483647;";
    const root = host.attachShadow({ mode: "closed" });
    root.innerHTML =
      "<style>" +
      ".b{position:fixed;inset:0;background:rgba(12,18,14,.72);display:grid;place-items:center;font-family:Trebuchet MS,Arial,sans-serif}" +
      ".c{width:min(92vw,420px);background:#fffef7;color:#20251e;border:2px solid #20251e;border-radius:13px 8px 15px 8px;box-shadow:7px 8px #20251e;padding:18px}" +
      "h2{margin:0 0 8px;font-size:17px;color:#b93e33}p{margin:0 0 8px;font-size:13px}" +
      "ul{margin:0 0 14px;padding-left:18px;font-size:12.5px;line-height:1.5}" +
      ".r{display:flex;gap:8px}button{flex:1;padding:10px;font:inherit;font-weight:700;font-size:13px;border:2px solid #20251e;border-radius:8px;background:#fff;color:#20251e;cursor:pointer}" +
      "button.ok{background:#168b49;color:#fff}" +
      '</style><div class="b"><div class="c"><h2>&#9888; Suspicious download blocked</h2>' +
      "<p>PhishEye stopped this click because:</p><ul></ul>" +
      '<div class="r"><button class="ok" id="x">Cancel (recommended)</button><button id="y">Download anyway</button></div></div></div>';
    const ul = root.querySelector("ul");
    r.why.slice(0, 5).forEach((w) => {
      const li = document.createElement("li");
      li.textContent = w;
      ul.appendChild(li);
    });
    root.getElementById("x").addEventListener("click", () => host.remove());
    root.getElementById("y").addEventListener("click", () => {
      bypass.add(el);
      host.remove();
      el.click();
    });
    document.documentElement.appendChild(host);
  }

  function onClick(e) {
    if (inOurUi(e)) return;
    const t = e.target instanceof Element ? e.target : null;
    if (!t) return;
    const el =
      t.closest(
        "a[href],a[download],button,[role='button'],input[type='submit'],input[type='button'],[onclick]"
      ) || t;
    if (bypass.has(el)) {
      bypass.delete(el);
      return;
    }
    if (hasContext()) {
      try {
        chrome.storage.local.get(["phisheye_protection"], () => {
          if (hasContext()) void chrome.runtime.lastError;
        });
      } catch (_) {}
    }
    const r = classify(el, e, t, true);
    if (r.score >= BLOCK_AT) {
      e.preventDefault();
      e.stopImmediatePropagation();
      showModal(r, el);
    }
  }
  document.addEventListener("click", onClick, true);

  let scanTimer = 0,
    lastCount = -1;
  function scanPage() {
    scanTimer = 0;
    if (!document.body || !hasContext()) return;
    let n = 0;
    const els = document.querySelectorAll("a[href],a[download],button,[role='button']");
    for (let i = 0; i < Math.min(els.length, 300); i++) {
      if (classify(els[i], { isTrusted: true }, els[i], false).score >= BLOCK_AT) n++;
    }
    if (n !== lastCount) {
      lastCount = n;
      try {
        chrome.runtime.sendMessage(
          { type: "DOWNLOAD_LURES", count: n, url: location.href },
          () => {
            if (hasContext()) void chrome.runtime.lastError;
          }
        );
      } catch (_) {}
    }
  }
  const queueScan = () => {
    if (!scanTimer) scanTimer = setTimeout(scanPage, 1500);
  };
  document.addEventListener("DOMContentLoaded", queueScan);
  try {
    new MutationObserver(queueScan).observe(document, { childList: true, subtree: true });
  } catch (_) {}
})();
