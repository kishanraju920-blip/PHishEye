/**
 * PhishEye Main-World Page Shield (Runs at document_start in MAIN world)
 * 1) While #phishzero-overlay is open: mutes 100% of website interaction listeners, timers,
 *    window.open, <a target="_blank">.click(), form.submit(), and navigation redirects.
 * 2) Even before scan completes or after user clicks "Continue anyway" on risky/mirror sites:
 *    blocks invisible full-screen click-hijack layers, window.open pop-unders, and forced
 *    cross-origin redirects when clicking the page.
 */
(() => {
  "use strict";

  if (window.__phisheyeMainShieldInstalled) return;
  window.__phisheyeMainShieldInstalled = true;

  const ALLOWED_OAUTH_HOSTS = [
    "accounts.google.com",
    "login.microsoftonline.com",
    "github.com",
    "appleid.apple.com",
    "auth0.com",
    "clerk.com"
  ];

  const isOverlayOpen = () =>
    Boolean(document.getElementById("phishzero-overlay")) &&
    !document.documentElement.hasAttribute("data-pz-allow-nav");

  const isPopunderGuardActive = () =>
    isOverlayOpen() ||
    Boolean(
      document.documentElement &&
        document.documentElement.hasAttribute("data-pz-block-popunders")
    );

  // Check if an element is an invisible full-screen click-hijack overlay used by mirror/adware sites
  function isClickHijackOverlay(el) {
    try {
      let node = el;
      let depth = 0;
      while (node && node.nodeType === 1 && depth++ < 6) {
        if (node.id === "phishzero-overlay" || (node.closest && node.closest("#phishzero-overlay"))) {
          return false;
        }
        const cs = window.getComputedStyle(node);
        const pos = cs.position;
        const opacity = parseFloat(cs.opacity);
        const zIndex = parseInt(cs.zIndex, 10) || 0;
        const rect = node.getBoundingClientRect();
        const coversScreen =
          rect.width >= window.innerWidth * 0.65 && rect.height >= window.innerHeight * 0.65;

        if ((pos === "fixed" || pos === "absolute") && coversScreen) {
          if (
            opacity < 0.12 ||
            cs.backgroundColor === "rgba(0, 0, 0, 0)" ||
            cs.backgroundColor === "transparent" ||
            zIndex > 9999
          ) {
            // Make sure it's not the main page wrapper containing lots of visible text
            const textLen = (node.innerText || "").trim().length;
            if (textLen < 40 || node.tagName === "A" || node.tagName === "IFRAME") {
              return true;
            }
          }
        }
        node = node.parentElement;
      }
    } catch (_) {}
    return false;
  }

  // Track whether the user genuinely clicked a visible same-intent link
  let lastLegitClickedHost = "";
  let lastLegitClickTime = 0;

  const INTERACTION_EVENTS = new Set([
    "click",
    "mousedown",
    "mouseup",
    "pointerdown",
    "pointerup",
    "touchstart",
    "touchend",
    "auxclick",
    "dblclick",
    "contextmenu",
    "keydown",
    "keyup"
  ]);

  const origAddEventListener = EventTarget.prototype.addEventListener;
  const listenerMap = new WeakMap();

  // 1) Wrap EventTarget.prototype.addEventListener in MAIN world at document_start
  EventTarget.prototype.addEventListener = function (type, listener, options) {
    const evtType = String(type || "").toLowerCase();
    if (typeof listener === "function" && INTERACTION_EVENTS.has(evtType)) {
      let wrapped = listenerMap.get(listener);
      if (!wrapped) {
        wrapped = function (event) {
          // If warning overlay is open, completely mute ALL website interaction listeners
          if (isOverlayOpen()) {
            try {
              event.preventDefault();
              event.stopImmediatePropagation();
            } catch (_) {}
            return;
          }
          // If pop-under guard is active and listener is attached to window/document/body
          // to hijack arbitrary page clicks, block it if target is a hijack overlay
          if (isPopunderGuardActive() && event && event.target && isClickHijackOverlay(event.target)) {
            try {
              event.preventDefault();
              event.stopImmediatePropagation();
            } catch (_) {}
            return;
          }
          return listener.apply(this, arguments);
        };
        listenerMap.set(listener, wrapped);
      }
      return origAddEventListener.call(this, type, wrapped, options);
    }
    return origAddEventListener.apply(this, arguments);
  };

  // 2) #1 Capture-phase listener on window & document (runs BEFORE any page listener)
  const firstCaptureGuard = (e) => {
    if (isOverlayOpen()) {
      const inOverlay =
        e.target &&
        typeof e.target.closest === "function" &&
        Boolean(e.target.closest("#phishzero-overlay"));
      if (!inOverlay) {
        try {
          e.preventDefault();
          e.stopImmediatePropagation();
        } catch (_) {}
        return;
      }
      // Even when clicking inside #phishzero-overlay, wipe inline handlers on window/document/body
      try {
        window.onclick = null;
        window.onmousedown = null;
        window.onmouseup = null;
        window.onpointerdown = null;
        document.onclick = null;
        document.onmousedown = null;
        document.onmouseup = null;
        document.onpointerdown = null;
        if (document.body) {
          document.body.onclick = null;
          document.body.onmousedown = null;
          document.body.onmouseup = null;
          document.body.onpointerdown = null;
        }
      } catch (_) {}
      return;
    }

    // Track legitimate visible link clicks vs invisible click-hijack overlays
    if (e.target && e.target.nodeType === 1) {
      if (isPopunderGuardActive() && isClickHijackOverlay(e.target)) {
        try {
          e.preventDefault();
          e.stopImmediatePropagation();
          e.target.style.setProperty("pointer-events", "none", "important");
          e.target.style.setProperty("display", "none", "important");
        } catch (_) {}
        return;
      }

      const anchor = typeof e.target.closest === "function" ? e.target.closest("a[href]") : null;
      if (anchor && anchor.href && !isClickHijackOverlay(anchor)) {
        try {
          const u = new URL(anchor.href, location.href);
          const rect = anchor.getBoundingClientRect();
          const hasTextOrImg =
            (anchor.innerText || "").trim().length > 0 || Boolean(anchor.querySelector("img, svg"));
          if (rect.width > 5 && rect.height > 5 && rect.width < window.innerWidth * 0.8 && hasTextOrImg) {
            if (isPopunderGuardActive() && anchor.target === "_blank" && u.hostname !== location.hostname) {
              // Prevent cross-origin target="_blank" pop-under links on flagged sites
              e.preventDefault();
              e.stopImmediatePropagation();
              return;
            }
            lastLegitClickedHost = u.hostname;
            lastLegitClickTime = Date.now();
          }
        } catch (_) {}
      }
    }
  };

  for (const evt of INTERACTION_EVENTS) {
    origAddEventListener.call(window, evt, firstCaptureGuard, true);
    origAddEventListener.call(document, evt, firstCaptureGuard, true);
  }

  // 3) Block window.open() pop-unders and forced new tabs
  const origWindowOpen = window.open;
  window.open = function (url) {
    if (isOverlayOpen() || isPopunderGuardActive()) {
      return null;
    }
    try {
      if (url) {
        const dest = new URL(String(url), location.href);
        const isOAuth = ALLOWED_OAUTH_HOSTS.some(
          (h) => dest.hostname === h || dest.hostname.endsWith("." + h)
        );
        // Block cross-origin window.open if user didn't click a link to that host
        if (
          dest.hostname !== location.hostname &&
          !isOAuth &&
          (dest.hostname !== lastLegitClickedHost || Date.now() - lastLegitClickTime > 1500)
        ) {
          return null;
        }
      }
    } catch (_) {}
    return origWindowOpen.apply(this, arguments);
  };

  // 4) Block programmatic <a target="_blank">.click() and cross-origin script clicks
  const origAnchorClick = HTMLAnchorElement.prototype.click;
  HTMLAnchorElement.prototype.click = function () {
    if (isOverlayOpen()) return;
    if (isPopunderGuardActive()) {
      try {
        const dest = new URL(this.href || "", location.href);
        if (this.target === "_blank" || dest.hostname !== location.hostname) {
          return;
        }
      } catch (_) {
        return;
      }
    }
    return origAnchorClick.apply(this, arguments);
  };

  const origFormSubmit = HTMLFormElement.prototype.submit;
  HTMLFormElement.prototype.submit = function () {
    if (isOverlayOpen()) return;
    if (isPopunderGuardActive()) {
      try {
        const dest = new URL(this.action || "", location.href);
        if (this.target === "_blank" || (dest.hostname && dest.hostname !== location.hostname)) {
          return;
        }
      } catch (_) {}
    }
    return origFormSubmit.apply(this, arguments);
  };

  // 5) Guard setTimeout & setInterval while overlay is open
  const origSetTimeout = window.setTimeout;
  const origSetInterval = window.setInterval;

  window.setTimeout = function (fn, delay, ...args) {
    if (typeof fn === "function") {
      const wrappedTimer = function () {
        if (isOverlayOpen()) return;
        return fn.apply(this, arguments);
      };
      return origSetTimeout.call(window, wrappedTimer, delay, ...args);
    }
    if (isOverlayOpen()) return 0;
    return origSetTimeout.apply(window, arguments);
  };

  window.setInterval = function (fn, delay, ...args) {
    if (typeof fn === "function") {
      const wrappedInterval = function () {
        if (isOverlayOpen()) return;
        return fn.apply(this, arguments);
      };
      return origSetInterval.call(window, wrappedInterval, delay, ...args);
    }
    if (isOverlayOpen()) return 0;
    return origSetInterval.apply(window, arguments);
  };

  // 6) Chromium Navigation API Lock — blocks ALL redirects while #phishzero-overlay is open,
  //    and blocks forced cross-origin redirects when clicking on a flagged/mirror page
  if (typeof navigation !== "undefined" && navigation && navigation.addEventListener) {
    navigation.addEventListener("navigate", (e) => {
      if (!e.cancelable) return;
      if (isOverlayOpen()) {
        e.preventDefault();
        return;
      }
      if (isPopunderGuardActive() && e.destination && e.destination.url) {
        try {
          const destUrl = new URL(e.destination.url);
          const isOAuth = ALLOWED_OAUTH_HOSTS.some(
            (h) => destUrl.hostname === h || destUrl.hostname.endsWith("." + h)
          );
          if (destUrl.hostname && destUrl.hostname !== location.hostname && !isOAuth) {
            e.preventDefault();
          }
        } catch (_) {}
      }
    });
  }
})();
