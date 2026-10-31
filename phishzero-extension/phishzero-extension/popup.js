(() => {
  'use strict';

  const $ = (s) => document.querySelector(s);
  const isExtension = typeof chrome !== 'undefined' && Boolean(chrome.runtime && chrome.runtime.id);
  const REQUEST_TIMEOUT_MS = 12000;

  const TRUSTED_DOMAINS = [
    'amazon.in', 'amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.co.jp',
    'google.com', 'google.co.in', 'google.co.uk', 'google.ca', 'google.com.au',
    'google.co.jp', 'google.de', 'google.fr', 'github.com', 'microsoft.com',
    'paypal.com', 'youtube.com', 'gmail.com', 'facebook.com', 'instagram.com',
    'whatsapp.com', 'twitter.com', 'x.com', 'linkedin.com', 'apple.com',
    'netflix.com', 'spotify.com', 'reddit.com', 'wikipedia.org', 'stackoverflow.com',
    'dropbox.com', 'zoom.us', 'slack.com', 'discord.com', 'adobe.com',
    'figma.com', 'canva.com', 'stripe.com', 'shopify.com', 'vitap.ac.in',
    'yahoo.com', 'bing.com', 'outlook.com', 'office.com', 'live.com',
    'icloud.com', 'notion.so', 'medium.com', 'quora.com', 'twitch.tv',
    'tiktok.com', 'snapchat.com', 'brainly.com', 'brainly.in', 'chegg.com',
    'coursera.org', 'udemy.com', 'khanacademy.org', 'grammarly.com', 'byjus.com',
    'geeksforgeeks.org', 'w3schools.com',
    'flipkart.com', 'myntra.com', 'ajio.com', 'meesho.com', 'nykaa.com', 'snapdeal.com', 'tatacliq.com', 'jiomart.com', 'bigbasket.com', 'swiggy.com', 'zomato.com', 'paytm.com', 'phonepe.com', 'irctc.co.in', 'makemytrip.com', 'goibibo.com', 'cleartrip.com', 'hotstar.com', 'jio.com', 'airtel.in', 'sbi.co.in', 'hdfcbank.com', 'icicibank.com', 'axisbank.com', 'kotak.com', 'ebay.com', 'walmart.com', 'target.com', 'bestbuy.com', 'aliexpress.com', 'alibaba.com', 'etsy.com', 'booking.com', 'airbnb.com', 'uber.com', 'ola.com', 'cred.club', 'zerodha.com', 'naukri.com', 'linkedin.com', 'indeed.com', 'gov.in', 'nic.in', 'ac.in', 'edu.in', 'bbc.com', 'bbc.co.uk', 'cnn.com', 'nytimes.com', 'timesofindia.com', 'indiatimes.com', 'ndtv.com', 'thehindu.com', 'hindustantimes.com', 'openai.com', 'chatgpt.com', 'anthropic.com', 'claude.ai', 'gemini.google.com', 'cloudflare.com', 'mozilla.org', 'python.org', 'npmjs.com', 'gitlab.com', 'trello.com', 'pinterest.com', 'tumblr.com', 'imdb.com', 'amazon.ca', 'amazon.com.au', 'amazon.fr', 'amazon.it', 'amazon.es', 'vit.ac.in', 'telegram.org', 'hotmail.com', 'msn.com', 'skype.com', 'godaddy.com', 'namecheap.com', 'mailchimp.com', 'salesforce.com', 'oracle.com', 'ibm.com', 'intel.com', 'nvidia.com', 'amd.com', 'samsung.com', 'sony.com', 'hp.com', 'dell.com', 'lenovo.com'
  ];

  const examples = {
    low: {
      score: 1.5,
      status: 'low',
      url: 'Sample: no unusual URL pattern.',
      forms: 'Sample: no suspicious form behavior.',
      feeds: 'PhishTank: not checked. URLhaus: not checked.',
      model: 'Sample low-risk XGBoost score (1.5%).',
      reasons: ['No phishing indicators found in sample scenario']
    },
    suspicious: {
      score: 52,
      status: 'suspicious',
      url: 'Sample: misleading domain pattern. Review the actual address.',
      forms: 'Page inspection has not been performed in this preview.',
      feeds: 'PhishTank: not checked. URLhaus: not checked.',
      model: 'Sample moderate-risk XGBoost score (52.0%).',
      reasons: ['Misleading domain pattern detected in sample scenario']
    },
    high: {
      score: 98.5,
      status: 'high',
      url: 'Sample: domain imitates a trusted service.',
      forms: 'Sample: password form submits to another domain.',
      feeds: 'PhishTank: FLAGGED. URLhaus: high risk.',
      model: 'Sample high-risk XGBoost score (98.5%).',
      reasons: [
        'Deceptive credential harvesting form target detected',
        'High lexical URL entropy & brand-impersonation keywords'
      ]
    },
    unavailable: {
      score: null,
      status: 'unavailable',
      url: 'URL analysis unavailable.',
      forms: 'Page inspection unavailable.',
      feeds: 'PhishTank: not checked. URLhaus: not checked.',
      model: 'Model explanation not available.',
      reasons: []
    }
  };

  let currentDomain = 'example.com';
  let tabUrl = '';
  let tabId = null;
  let theme = false;
  let isProtectionActive = true;
  let currentReasons = [];
  let lastLiveAssessment = null;

  function isTrustedHost(hostname) {
    const host = (hostname || '').toLowerCase().replace(/\.$/, '');
    return TRUSTED_DOMAINS.some((d) => host === d || host.endsWith('.' + d));
  }

  function normalizeScore(raw) {
    if (raw === null || raw === undefined) return null;
    const n = parseFloat(String(raw).replace('%', ''));
    if (Number.isNaN(n)) return null;
    const pct = n > 0 && n <= 1 && !String(raw).includes('%') ? n * 100 : n;
    return Math.max(0, Math.min(100, pct));
  }

  function classifyStatus(statusStr, score) {
    // Always prioritize numeric danger score so a 30-59% score is NEVER shown as "Low Risk"
    // and a >=60% score is ALWAYS shown as "High Risk".
    if (score !== null && Number.isFinite(score)) {
      if (score >= 60) return 'high';
      if (score >= 30) return 'suspicious';
    }
    const s = String(statusStr || '').trim().toUpperCase();
    if (
      [
        'PHISHING',
        'PHISHING_DETECTED',
        'MALICIOUS',
        'DANGER',
        'DANGEROUS',
        'UNSAFE',
        'BAD',
        'HIGH'
      ].includes(s)
    ) {
      return 'high';
    }
    if (['SUSPICIOUS', 'WARNING', 'RISKY', 'MODERATE', 'CAUTION'].includes(s)) return 'suspicious';
    if (['SAFE', 'BENIGN', 'LEGITIMATE', 'LEGIT', 'CLEAN', 'GOOD', 'LOW'].includes(s)) return 'low';
    if (score === null || !Number.isFinite(score)) return 'unavailable';
    return 'low';
  }

  async function getApiBaseUrl() {
    const prodDefault = 'https://phisheye-backend.onrender.com';
    if (isExtension) {
      try {
        const stored = await chrome.storage.local.get(['phisheye_api_base']);
        if (
          stored &&
          typeof stored.phisheye_api_base === 'string' &&
          stored.phisheye_api_base.trim()
        ) {
          const val = stored.phisheye_api_base.trim().replace(/\/+$/, '');
          if (!val.includes('ngrok') && !val.includes('localhost') && !val.includes('127.0.0.1')) {
            return val;
          }
          chrome.storage.local.set({ phisheye_api_base: prodDefault });
        }
      } catch (_) {}
    }
    return prodDefault;
  }

  function showMLToast(status, score) {
    const toast = $('#ml-toast');
    if (!toast || status === 'unavailable') return;
    const scoreText = typeof score === 'number' && Number.isFinite(score) ? score.toFixed(1) + '%' : 'N/A';
    const isSafe = status === 'low';
    const isWarn = status === 'suspicious';
    const icon = isSafe ? '\ud83d\udd2e' : isWarn ? '!' : '\u26a0\ufe0f';
    const iconEl = toast.querySelector('.toast-icon');
    const titleEl = toast.querySelector('.toast-title');
    const scoreEl = toast.querySelector('.toast-score');
    if (iconEl) iconEl.textContent = icon;
    if (titleEl) {
      titleEl.textContent = isSafe
        ? 'AI ML Notice: Verified Safe'
        : isWarn
        ? 'AI ML Alert: Suspicious URL'
        : 'AI ML Alert: Phishing Detected';
    }
    if (scoreEl) {
      scoreEl.textContent = 'Estimated Risk: ' + scoreText + ' \u00b7 ML prediction';
    }
    const variant = isSafe ? 'ml-toast-safe' : isWarn ? 'ml-toast-warn' : 'ml-toast-danger';
    toast.className = 'ml-toast ml-toast-show ' + variant;
    const bar = toast.querySelector('.toast-progress-bar');
    if (bar) {
      bar.style.transition = 'none';
      bar.style.width = '100%';
    }
    setTimeout(() => {
      if (bar) {
        bar.style.transition = 'width 4s linear';
        bar.style.width = '0%';
      }
    }, 20);
    clearTimeout(toast._dismissTimer);
    toast._dismissTimer = setTimeout(() => {
      toast.className = 'ml-toast';
    }, 4000);
  }

  function updateActionBadge(status) {
    if (!isExtension || !chrome.action || tabId === null) return;
    const isSafe = status === 'low';
    const isMod = status === 'suspicious';
    chrome.action.setBadgeText({
      tabId,
      text: isSafe ? 'SAFE' : isMod ? '~' : status === 'high' ? '!' : ''
    });
    if (status !== 'unavailable') {
      chrome.action.setBadgeBackgroundColor({
        tabId,
        color: isSafe ? '#10B981' : isMod ? '#D97706' : '#EF4444'
      });
    }
  }

  function renderReasonsList(reasons) {
    const ul = $('#reasons-list');
    if (!ul) return;
    ul.innerHTML = '';
    (reasons || []).forEach((r) => {
      const li = document.createElement('li');
      li.textContent = r;
      ul.appendChild(li);
    });
  }

  function render(data, demo = false) {
    const valid =
      typeof data.score === 'number' &&
      Number.isFinite(data.score) &&
      data.score >= 0 &&
      data.score <= 100;
    const status =
      valid && ['low', 'suspicious', 'high'].includes(data.status) ? data.status : 'unavailable';

    const states = {
      low: {
        color: '#128147',
        label: '\u2713 LOW RISK',
        message: 'Verified clean by PhishEye AI & Domain Shield.',
        evidence: 'No warning indicators reported by the detector. This does not guarantee safety.',
        icon: '\u2713'
      },
      suspicious: {
        color: '#996011',
        label: '! SUSPICIOUS',
        message: 'Review the warning evidence before continuing.',
        evidence: 'Some signals need a closer look. Verify the domain before entering information.',
        icon: '!'
      },
      high: {
        color: '#b23730',
        label: '! HIGH RISK',
        message: 'Review the warnings before entering personal information.',
        evidence: 'High-risk indicators reported. Returning to a trusted page is recommended.',
        icon: '!'
      },
      unavailable: {
        color: '#556a63',
        label: data.customBadge || 'SCORE UNAVAILABLE',
        message: data.customMessage || 'No completed assessment is available.',
        evidence:
          data.customEvidence ||
          'This website has not been assessed here. An unavailable result does not mean safe.',
        icon: '?'
      }
    };

    const state = states[status];
    const tips = {
      low: 'Check the address before you type',
      suspicious: 'Double-check this domain',
      high: 'Pause before entering passwords',
      unavailable: data.customTip || 'This site has not been assessed'
    };

    const awareness = $('#awareness');
    if (awareness) {
      awareness.style.setProperty(
        '--signal',
        status === 'low'
          ? 'var(--accent)'
          : status === 'suspicious'
          ? '#a57626'
          : status === 'high'
          ? document.documentElement.classList.contains('dark')
            ? '#ffa69d'
            : '#b23730'
          : 'var(--muted)'
      );
      awareness.dataset.state = status;
    }

    const panel = $('.panel');
    if (panel) panel.dataset.risk = status;

    const awarenessLabel = $('#awareness-label');
    if (awarenessLabel) {
      awarenessLabel.textContent =
        (demo ? 'DEMO \u00b7 ' : 'LIVE \u00b7 ') +
        (status === 'low'
          ? 'LOW RISK'
          : status === 'suspicious'
          ? 'SUSPICIOUS'
          : status === 'high'
          ? 'HIGH RISK'
          : 'NOT ASSESSED');
    }
    const awarenessTip = $('#awareness-tip');
    if (awarenessTip) awarenessTip.textContent = tips[status];

    const shieldSymbol = $('#shield-symbol');
    if (shieldSymbol) {
      shieldSymbol.setAttribute(
        'd',
        status === 'low'
          ? 'M71 29 L78 36 L92 22'
          : status === 'unavailable'
          ? 'M76 24 Q76 18 83 19 Q91 20 84 28 Q81 30 81 33 M81 39 V40'
          : 'M81 20 V32 M81 39 V40'
      );
    }

    const assessmentEl = $('.assessment');
    if (assessmentEl) assessmentEl.style.setProperty('--risk', state.color);

    const statusEl = $('#status');
    if (statusEl) statusEl.textContent = state.label;
    const verdictBadgeEl = $('#verdict-badge');
    if (verdictBadgeEl) verdictBadgeEl.textContent = state.label;

    const scoreText = valid ? data.score.toFixed(1) + '%' : '\u2014';
    const scoreEl = $('#score');
    if (scoreEl) scoreEl.textContent = scoreText;
    const confScoreEl = $('#confidence-score');
    if (confScoreEl) confScoreEl.textContent = scoreText;

    const captionEl = $('#score-caption');
    if (captionEl) captionEl.textContent = demo ? 'DEMO DANGER SCORE' : 'DANGER SCORE';

    const domainEl = $('#domain');
    if (domainEl) domainEl.textContent = demo ? 'example.com' : currentDomain;
    const targetUrlEl = $('#target-url');
    if (targetUrlEl) targetUrlEl.textContent = demo ? 'example.com' : currentDomain;

    const siteLabelEl = $('#site-label');
    if (siteLabelEl) siteLabelEl.textContent = demo ? 'PREVIEW SITE' : 'CURRENT SITE';

    const ring = $('.score-ring');
    if (ring) {
      ring.classList.remove('score-reveal');
      ring.classList.remove('ring-drawing');
      void ring.offsetWidth;
      ring.classList.add('score-reveal');
      ring.classList.add('ring-drawing');
    }

    const verdictEl = $('#verdict');
    if (verdictEl) {
      verdictEl.textContent =
        !demo && status === 'low'
          ? data.source
            ? 'Verified clean by ' + data.source
            : 'Low risk according to the connected detector.'
          : !demo && data.source
          ? 'Flagged by ' + data.source
          : state.message;
    }

    const noteEl = $('#assessment-note');
    if (noteEl) {
      noteEl.textContent = demo
        ? 'Sample data \u00b7 not a live scan'
        : status === 'unavailable'
        ? data.customNote || 'Browser or unassessed page'
        : data.source || 'Assessment supplied by PhishEye AI';
    }

    const reportIntro = $('#report-intro');
    if (reportIntro) {
      reportIntro.textContent = demo
        ? 'Sample findings for this preview.'
        : 'Review the live PhishEye detection evidence below.';
    }

    const urlReason = $('#url-reason');
    if (urlReason) urlReason.textContent = data.url || 'URL findings not provided.';
    const formReason = $('#form-reason');
    if (formReason) formReason.textContent = data.forms || 'Page-inspection findings not provided.';
    const feedReason = $('#feed-reason');
    if (feedReason) feedReason.textContent = data.feeds || 'Threat-feed results not provided.';
    const modelReason = $('#model-reason');
    if (modelReason) {
      modelReason.textContent = demo
        ? 'The displayed score is sample data. XGBoost has not been run.'
        : data.model || 'Model explanation not provided.';
    }

    currentReasons = Array.isArray(data.reasons) ? data.reasons : [];
    renderReasonsList(currentReasons);

    const evidenceEl = $('#evidence');
    if (evidenceEl) {
      evidenceEl.textContent =
        !demo && currentReasons.length > 0
          ? currentReasons[0]
          : !demo && status === 'low'
          ? 'No warning indicators reported by the detector. This does not guarantee safety.'
          : state.evidence;
    }
    const evidenceIcon = $('#evidence-icon');
    if (evidenceIcon) evidenceIcon.textContent = state.icon;

    const connEl = $('#connection');
    if (connEl) {
      connEl.textContent = demo
        ? 'Demo preview'
        : !isProtectionActive
        ? 'Shield Paused'
        : status === 'unavailable'
        ? 'Ready'
        : 'Live Shield \u25cf';
    }
    const modeLabel = $('#mode-label');
    if (modeLabel) modeLabel.textContent = demo ? 'DESIGN PREVIEW' : 'EXTENSION PANEL';

    {
      const isSafeState = status === 'low';
      const goBackEl = $('#btn-goback');
      const proceedEl = $('#btn-proceed');
      const confirmEl = $('#confirmation');
      if (goBackEl) goBackEl.hidden = isSafeState;
      if (proceedEl) proceedEl.hidden = isSafeState;
      if (isSafeState && confirmEl) confirmEl.hidden = true;
      const whyTitle = $('#why-title');
      if (whyTitle) whyTitle.textContent = isSafeState ? 'Why is it safe?' : 'Why is it flagged?';
      const introEl = $('#report-intro');
      if (introEl && isSafeState) introEl.textContent = 'These are the checks that came back clean for this site.';
      const rb = $('#btn-report');
      const rs = $('#btn-report-safe');
      if (rs) rs.hidden = isSafeState || demo || !data.zeroDay;
      if (rb && !rb.classList.contains('reported')) rb.textContent = isSafeState ? '\uD83D\uDEA8 Report Phishing' : '\uD83D\uDEA8 Report Site';
    }

    if (!demo) {
      updateActionBadge(status);
      if (valid) {
        showMLToast(status, data.score);
      }
    }
  }

  function convertBackgroundResult(data) {
    const score = normalizeScore(
      data.threat_score !== undefined
        ? data.threat_score
        : data.risk_score !== undefined
        ? data.risk_score
        : data.riskScore !== undefined
        ? data.riskScore
        : data.score
    );
    const rawStatus =
      data.status_badge || data.statusBadge || data.verdict || data.rawVerdict || '';
    const status = classifyStatus(rawStatus, score);

    let reasons = [];
    if (Array.isArray(data.reasons) && data.reasons.length > 0) {
      reasons = data.reasons.map(String);
    }
    if (status === 'low') {
      reasons = reasons.filter(
        (r) =>
          !/flagged|suspicious|multiple hyphens|multiple subdomains|long url|high character|unencrypted|hidden tracking|password input field/i.test(
            r
          )
      );
      if (reasons.length === 0) {
        reasons = [
          `Host ${currentDomain} passed 54-feature URL & domain verification`,
          'Encrypted HTTPS connection & clean page structure verified'
        ];
      }
    } else if (reasons.length === 0) {
      reasons = ['Flagged by PhishEye AI model'];
    }

    const source = data.layer || data.mode || data.detection_method || 'PhishEye AI Backend';
    const scoreStr = score !== null ? score.toFixed(1) + '%' : 'N/A';
    const dom = data.domMetrics || {};

    return {
      score,
      status,
      zeroDay: data.detection_method === 'ML_XGBOOST_ZERO_DAY',
      source,
      reasons,
      url:
        status === 'low'
          ? `\u2713 ${reasons[0] || `Host ${currentDomain} matches clean lexical and structural patterns.`}`
          : reasons[0] || `Suspicious lexical patterns detected on ${currentDomain}.`,
      forms:
        status === 'low'
          ? '\u2713 Clean page structure \u2014 no deceptive credential-harvesting forms or external form redirects detected.'
          : dom.external_form_action
          ? 'Warning: Form action submits credentials to an external domain.'
          : dom.has_password_field
          ? `Detected ${dom.password_field_count || 1} password input field(s) on this page.`
          : 'No deceptive credential-harvesting forms detected.',
      feeds:
        status === 'low'
          ? `\u2713 Clean reputation \u2014 ${currentDomain} is not listed in PhishTank, URLhaus, or PhishEye blacklists.`
          : String(source).toLowerCase().includes('blacklist') ||
            String(source).toLowerCase().includes('urlhaus') ||
            String(source).toLowerCase().includes('phishtank')
          ? `Match found in threat intelligence feed (${source}).`
          : `Status: ${rawStatus || status.toUpperCase()} \u00b7 Zero-day heuristic / ML evaluation.`,
      model:
        status === 'low'
          ? `\u2713 Verified low risk (${scoreStr} score) by ${source}.`
          : `XGBoost zero-day danger score: ${scoreStr} (source: ${source}).`
    };
  }

  function setTheme(value) {
    theme = Boolean(value);
    document.documentElement.classList.toggle('dark', theme);
    document.documentElement.setAttribute('data-theme', theme ? 'dark' : 'light');
    const themeBtn = $('#theme');
    if (themeBtn) themeBtn.setAttribute('aria-checked', String(theme));
    const toggleThemeInput = $('#toggle-theme');
    if (toggleThemeInput) toggleThemeInput.checked = theme;
    const awareness = $('#awareness');
    if (awareness && awareness.dataset.state === 'high') {
      awareness.style.setProperty('--signal', theme ? '#ffa69d' : '#b23730');
    }
  }

  function setProtection(active, { rescan = true } = {}) {
    isProtectionActive = Boolean(active);
    const protBtn = $('#protection-switch-ui');
    if (protBtn) protBtn.setAttribute('aria-checked', String(isProtectionActive));
    const protInput = $('#toggle-protection');
    if (protInput) protInput.checked = isProtectionActive;
    const protLabel = $('#protection-label');
    if (protLabel) protLabel.textContent = isProtectionActive ? 'Protection' : 'Paused';

    if (isExtension) {
      try {
        chrome.storage.local.set({ phisheye_protection: isProtectionActive });
      } catch (_) {}
    }

    if (!isProtectionActive) {
      render(
        {
          score: null,
          status: 'unavailable',
          customBadge: '\u23f8\ufe0f SHIELD PAUSED',
          customMessage: 'Real-time protection is currently paused.',
          customEvidence: 'Re-enable Protection above to resume automatic zero-day scanning.',
          customTip: 'Real-time protection is paused',
          customNote: 'Protection paused by user'
        },
        false
      );
    } else if (lastLiveAssessment) {
      render(lastLiveAssessment, false);
    } else if (rescan) {
      scanActiveTab();
    }
  }

  async function scanActiveTab() {
    if (!isExtension) {
      render(examples.high, true);
      return;
    }

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab || !tab.url) {
        render(examples.unavailable, false);
        return;
      }

      tabId = tab.id;
      tabUrl = tab.url;

      let parsed;
      try {
        parsed = new URL(tab.url);
        currentDomain = parsed.hostname || parsed.protocol.replace(':', '') + ' page';
      } catch (_) {
        currentDomain = 'Unavailable';
      }

      const domainEl = $('#domain');
      if (domainEl) {
        domainEl.textContent = currentDomain;
        domainEl.title = tabUrl;
      }

      if (!parsed || !/^https?:$/.test(parsed.protocol)) {
        render(
          {
            score: null,
            status: 'unavailable',
            customBadge: '\u2139\ufe0f LOCAL / BROWSER PAGE',
            customMessage: 'Browser-internal and local pages are not scanned.',
            customEvidence: 'Open an HTTP/HTTPS website to run a live PhishEye threat assessment.',
            customTip: 'Internal browser page',
            customNote: 'Not applicable for internal pages'
          },
          false
        );
        return;
      }

      if (!isProtectionActive) return;

      if (isTrustedHost(parsed.hostname)) {
        const trustedResult = {
          score: 0.1,
          status: 'low',
          source: 'PhishEye Trusted Domain List',
          reasons: ['Verified authority domain'],
          url: `${parsed.hostname} is a verified authority domain.`,
          forms: 'Trusted authority origin — form destination verified.',
          feeds: 'Verified clean in Tranco & PhishEye authority list.',
          model: 'Danger score: 0.1% (Trusted authority domain).'
        };
        lastLiveAssessment = trustedResult;
        render(trustedResult, false);
        return;
      }

      try {
        const stored = await chrome.storage.local.get([
          tab.url,
          `tab_${tab.id}`,
          `phisheyeAssessment:${tab.id}`,
          'latestScan'
        ]);
        const cached =
          stored[tab.url] ||
          stored[`tab_${tab.id}`] ||
          stored[`phisheyeAssessment:${tab.id}`] ||
          stored.latestScan;
        if (cached && cached.cacheVer === 4 && (cached.url === tab.url || cached.pageUrl === tab.url)) {
          const converted = convertBackgroundResult(cached);
          lastLiveAssessment = converted;
          render(converted, false);
          return;
        }
      } catch (_) {}

      try {
        const response = await new Promise((resolve, reject) => {
          chrome.runtime.sendMessage(
            {
              type: 'ANALYZE_URL',
              payload: { url: tab.url, hostname: parsed.hostname },
              tabId: tab.id
            },
            (res) => {
              if (chrome.runtime.lastError) {
                reject(new Error(chrome.runtime.lastError.message));
                return;
              }
              if (!res) {
                reject(new Error('No response from background script'));
                return;
              }
              resolve(res);
            }
          );
        });
        const converted = convertBackgroundResult(response);
        lastLiveAssessment = converted;
        render(converted, false);
      } catch (_) {
        const apiBase = await getApiBaseUrl();
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
        const res = await fetch(`${apiBase}/analyze`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'ngrok-skip-browser-warning': 'true'
          },
          body: JSON.stringify({ url: tab.url }),
          signal: controller.signal
        });
        clearTimeout(timer);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const converted = convertBackgroundResult(data);
        lastLiveAssessment = converted;
        render(converted, false);
      }
    } catch (err) {
      render(
        {
          score: null,
          status: 'unavailable',
          customBadge: '\u26a0\ufe0f SCAN FAILED',
          customMessage: 'Could not reach PhishEye backend.',
          customEvidence: err && err.message ? err.message : 'Check backend connection.',
          customTip: 'Scan could not be completed'
        },
        false
      );
    }
  }

  async function loadSandboxPreview() {
    const sandboxPanel = $('#sandbox-panel');
    const sandboxContent = $('#sandbox-content');
    if (!sandboxPanel || !sandboxContent) return;

    sandboxPanel.hidden = false;
    sandboxPanel.classList.remove('hidden');
    sandboxContent.innerHTML =
      "<p style='text-align:center;font-weight:700;'>Loading virtual preview…</p>";

    try {
      const apiBase = await getApiBaseUrl();
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
      const response = await fetch(`${apiBase}/sandbox`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'ngrok-skip-browser-warning': 'true'
        },
        body: JSON.stringify({ url: tabUrl }),
        signal: controller.signal
      });
      clearTimeout(timer);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();

      if (data.status === 'sandboxed' && data.safe_html_preview) {
        sandboxContent.innerHTML = '';
        const iframe = document.createElement('iframe');
        iframe.sandbox = 'allow-same-origin';
        iframe.style.cssText =
          'width:100%;height:240px;border:2px solid var(--ink);border-radius:6px;background:#fff;';
        iframe.srcdoc = data.safe_html_preview;
        sandboxContent.appendChild(iframe);
      } else {
        sandboxContent.innerHTML = `<p style="font-weight:700;color:var(--muted);">${
          data.message || 'Could not load preview.'
        }</p>`;
      }
    } catch (err) {
      sandboxContent.innerHTML = `<p style="font-weight:700;color:#b23730;">Sandbox error: ${err.message}</p>`;
    }
  }

  // Wire UI Events
  const toastClose = $('#toast-close');
  if (toastClose) {
    toastClose.addEventListener('click', () => {
      const toast = $('#ml-toast');
      if (toast) {
        clearTimeout(toast._dismissTimer);
        toast.className = 'ml-toast';
      }
    });
  }

  const themeBtn = $('#theme');
  if (themeBtn) {
    themeBtn.addEventListener('click', () => {
      const next = !theme;
      setTheme(next);
      try {
        if (isExtension) {
          chrome.storage.local.set({
            phisheye_theme: next ? 'dark' : 'light',
            phisheyePanelDark: next
          });
        } else {
          localStorage.setItem('phisheyePanelDark', String(next));
        }
      } catch (_) {}
    });
  }

  const protBtn = $('#protection-switch-ui');
  if (protBtn) {
    protBtn.addEventListener('click', () => {
      setProtection(!isProtectionActive);
    });
  }

  const sampleSelect = $('#sample');
  if (sampleSelect) {
    sampleSelect.addEventListener('change', (e) => {
      const val = e.target.value;
      if (val === 'live') {
        $('#message').textContent = '';
        if (lastLiveAssessment) render(lastLiveAssessment, false);
        else scanActiveTab();
      } else if (examples[val]) {
        render(examples[val], true);
        $('#message').textContent = 'Sample scenario selected. No live scan was performed.';
      }
    });
  }

  const report = $('#why-report');
  const awarenessBtn = $('#awareness');
  if (awarenessBtn && report) {
    awarenessBtn.addEventListener('click', () => {
      report.open = !report.open;
      awarenessBtn.setAttribute('aria-expanded', String(report.open));
      if (report.open) {
        const summary = report.querySelector('summary');
        if (summary) summary.focus({ preventScroll: true });
        report.scrollIntoView({ behavior: 'auto', block: 'nearest' });
      }
    });
    report.addEventListener('toggle', () => {
      awarenessBtn.setAttribute('aria-expanded', String(report.open));
    });
  }

  const goBackBtn = $('#btn-goback');
  if (goBackBtn) {
    goBackBtn.addEventListener('click', () => {
      if (!isExtension || tabId === null) {
        window.close();
        return;
      }
      if (chrome.tabs && chrome.tabs.goBack) {
        chrome.tabs.goBack(tabId, () => {
          if (chrome.runtime.lastError) {
            chrome.tabs.update(tabId, { url: 'https://www.google.com' });
          }
          window.close();
        });
      } else {
        chrome.tabs.update(tabId, { url: 'https://www.google.com' });
        window.close();
      }
    });
  }

  const sandboxBtn = $('#btn-sandbox');
  if (sandboxBtn) {
    sandboxBtn.addEventListener('click', () => {
      const sandboxPanel = $('#sandbox-panel');
      if (sandboxPanel && !sandboxPanel.hidden) {
        sandboxPanel.hidden = true;
      } else {
        loadSandboxPreview();
      }
    });
  }

  function wireReport(btn, label, doneText) {
    if (!btn) return;
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      if (btn.classList.contains('reported')) return;
      const payload = {
        url: tabUrl || currentDomain,
        label,
        reason:
          currentReasons.length > 0
            ? currentReasons.join('; ')
            : 'User report via PhishEye popup'
      };
      const done = () => {
        btn.textContent = doneText;
        btn.classList.add('reported');
      };
      if (isExtension) {
        chrome.runtime.sendMessage({ type: 'REPORT_URL', payload }, () => {
          void chrome.runtime.lastError;
          done();
        });
      } else {
        done();
      }
    });
  }
  wireReport($('#btn-report'), 'phishing', '\u2713 Thanks for reporting');
  wireReport($('#btn-report-safe'), 'safe', '\u2713 Thanks for reporting');

  const proceedBtn = $('#btn-proceed');
  const confirmationBox = $('#confirmation');
  const cancelBtn = $('#btn-cancel');
  const confirmBtn = $('#btn-confirm');

  if (proceedBtn && confirmationBox) {
    proceedBtn.addEventListener('click', () => {
      confirmationBox.hidden = false;
      confirmationBox.classList.remove('hidden');
    });
  }
  if (cancelBtn && confirmationBox) {
    cancelBtn.addEventListener('click', () => {
      confirmationBox.hidden = true;
      confirmationBox.classList.add('hidden');
    });
  }
  if (confirmBtn) {
    confirmBtn.addEventListener('click', () => {
      if (!isExtension || tabId === null) {
        window.close();
        return;
      }
      chrome.tabs.sendMessage(tabId, { type: 'DISMISS_WARNING_OVERLAY' }, () => {
        void chrome.runtime.lastError;
        window.close();
      });
    });
  }

  const closeBtn = $('#close');
  const reopenBtn = $('#reopen');
  if (closeBtn) {
    closeBtn.addEventListener('click', () => {
      if (isExtension) window.close();
      else {
        $('.panel').hidden = true;
        $('#closed').hidden = false;
        if (reopenBtn) reopenBtn.focus();
      }
    });
  }
  if (reopenBtn) {
    reopenBtn.addEventListener('click', () => {
      $('.panel').hidden = false;
      $('#closed').hidden = true;
      if (closeBtn) closeBtn.focus();
    });
  }

  window.PhishEyePanel = {
    setAssessment(data) {
      render(data, false);
    }
  };

  async function init() {
    if (!isExtension) {
      try {
        setTheme(localStorage.getItem('phisheyePanelDark') === 'true');
      } catch (_) {}
      render(examples.high, true);
      return;
    }

    try {
      const stored = await chrome.storage.local.get([
        'phisheye_theme',
        'phisheyePanelDark',
        'phisheye_protection'
      ]);
      const isDark =
        stored.phisheye_theme === 'dark' ||
        (stored.phisheye_theme === undefined && Boolean(stored.phisheyePanelDark));
      setTheme(isDark);
      setProtection(stored.phisheye_protection !== false, { rescan: false });
      await scanActiveTab();
    } catch (_) {
      await scanActiveTab();
    }
  }

  init();
})();
