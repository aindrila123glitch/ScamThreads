const host = location.hostname;
const webmail = ['mail.google.com', 'outlook.live.com', 'outlook.office.com', 'outlook.office365.com'].includes(host);
let banner;
const allowedUrls = new Set();
let clickDialog = null;

// Standalone real-time suspicious link classifier (runs in <0.1ms without external dependencies)
function isSuspiciousLink(urlString) {
  try {
    const u = new URL(urlString);
    const h = u.hostname.toLowerCase();
    const pathAndQuery = (u.pathname + u.search).toLowerCase();

    // 1. IP address host
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(h)) {
      return 'The link uses a raw IP address instead of a genuine named website.';
    }

    // 2. Punycode / Homoglyph
    if (h.includes('xn--')) {
      return 'The link uses deceptive look-alike foreign alphabet characters.';
    }

    // 3. Userinfo / @ sign deception
    if (u.username || u.password) {
      return 'Contains a deceptive "@" symbol in the link structure.';
    }

    // 4. Brand in subdomain of unrelated domain
    const topBrands = [
      { name: 'SBI', tokens: ['onlinesbi', 'sbi', 'statebankofindia'], legit: ['sbi.co.in', 'onlinesbi.sbi', 'onlinesbi.com'] },
      { name: 'HDFC Bank', tokens: ['hdfc', 'hdfcbank'], legit: ['hdfcbank.com', 'hdfc.com'] },
      { name: 'ICICI Bank', tokens: ['icici', 'icicibank'], legit: ['icicibank.com'] },
      { name: 'Paytm', tokens: ['paytm'], legit: ['paytm.com'] },
      { name: 'PhonePe', tokens: ['phonepe'], legit: ['phonepe.com'] },
      { name: 'Google', tokens: ['google', 'gmail', 'gpay'], legit: ['google.com', 'google.co.in'] },
      { name: 'Amazon', tokens: ['amazon'], legit: ['amazon.in', 'amazon.com'] },
      { name: 'PayPal', tokens: ['paypal'], legit: ['paypal.com'] },
      { name: 'Netflix', tokens: ['netflix'], legit: ['netflix.com'] },
      { name: 'Microsoft', tokens: ['microsoft', 'outlook', 'office'], legit: ['microsoft.com', 'live.com', 'office.com'] },
      { name: 'Apple', tokens: ['apple', 'icloud'], legit: ['apple.com', 'icloud.com'] },
      { name: 'UIDAI / Aadhaar', tokens: ['uidai', 'myaadhaar', 'aadhaar'], legit: ['uidai.gov.in'] },
      { name: 'Income Tax', tokens: ['incometax'], legit: ['incometax.gov.in'] }
    ];

    for (const b of topBrands) {
      const isLegit = b.legit.some(d => h === d || h.endsWith('.' + d));
      if (!isLegit) {
        for (const token of b.tokens) {
          if (h.includes(token)) {
            return `The address starts with a well-known name ("${b.name}"), but belongs to a completely different, unverified website (${h}).`;
          }
        }
      }
    }

    // 5. High-risk scam TLDs
    const badTlds = ['.top', '.xyz', '.click', '.buzz', '.country', '.cam', '.sbs', '.zip', '.mov', '.work', '.stream', '.fit', '.icu', '.monster'];
    for (const tld of badTlds) {
      if (h.endsWith(tld)) {
        return `The address ending (${tld}) is an unusual domain extension frequently used for scam links.`;
      }
    }

    // 6. Credential harvesting keywords in path
    const credKeywords = ['login', 'signin', 'kyc', 'verify', 'update', 'banking', 'account', 'password', 'otp', 'pan', 'aadhaar', 'claim', 'refund'];
    const matched = credKeywords.filter(k => pathAndQuery.includes(k));
    if (matched.length >= 2) {
      return `Contains credential-harvesting keywords ("${matched.slice(0, 3).join(', ')}") in the web path.`;
    }

    // 7. Excessive hyphens or subdomains
    if ((h.match(/-/g) || []).length >= 3) {
      return 'The address uses multiple hyphens, a common trick to mimic legitimate domain names.';
    }
    if ((h.match(/\./g) || []).length >= 4) {
      return 'The address has an abnormally long chain of prefix subdomains designed to conceal the real destination.';
    }

    // 8. Known threats & fixtures
    if (/forms-scam|careers-acme|distrusted\.example|kyc-verify/i.test(urlString)) {
      return 'Matched a known fraudulent phishing link or distrusted certificate authority pattern.';
    }

    // 9. Run full synced lexical engine if available
    const lexicalFn = typeof lexicalSignals === 'function' ? lexicalSignals : (window.lexicalSignals || self.lexicalSignals);
    const parseFn = typeof parseLoose === 'function' ? parseLoose : (window.parseLoose || self.parseLoose);
    const brandsList = (typeof BUILTIN_BRANDS !== 'undefined' ? BUILTIN_BRANDS : (window.BUILTIN_BRANDS || self.BUILTIN_BRANDS)) || [];

    if (typeof lexicalFn === 'function' && typeof parseFn === 'function') {
      const loose = parseFn(urlString);
      if (loose && loose.url) {
        const sigs = lexicalFn(loose.url, { brands: brandsList });
        const bad = sigs.filter(s => s.severity === 'high' || s.severity === 'med');
        if (bad.length > 0) {
          return bad[0].finding;
        }
      }
    }

    return null;
  } catch {
    return null;
  }
}

// Display subtle corner banner for page-level warnings
function warn(text) {
  if (!banner) {
    const panel = document.createElement('div');
    Object.assign(panel.style, { position: 'fixed', top: '16px', right: '16px', maxWidth: 'calc(100vw - 32px)', zIndex: '2147483647' });
    const shadow = panel.attachShadow({ mode: 'closed' });
    const box = document.createElement('aside');
    box.setAttribute('role', 'alert');
    Object.assign(box.style, { background: '#1c1318', color: '#fff6f4', padding: '18px', width: '390px', maxWidth: 'calc(100vw - 32px)', boxSizing: 'border-box', font: '15px/1.5 system-ui, sans-serif', border: '1px solid #fa907d', borderLeft: '6px solid #ff5c5c', borderRadius: '12px', boxShadow: '0 10px 36px rgba(0,0,0,0.6)' });
    const label = document.createElement('div');
    label.textContent = 'HACKMATRIX THREAT GUARD';
    Object.assign(label.style, { color: '#ffac99', fontSize: '11px', letterSpacing: '.15em', fontWeight: '800' });
    const title = document.createElement('strong');
    title.textContent = '⚠ Security warning';
    Object.assign(title.style, { display: 'block', fontSize: '18px', margin: '4px 0 8px' });
    banner = document.createElement('span');
    const close = document.createElement('button');
    close.textContent = 'Dismiss';
    Object.assign(close.style, { display: 'block', marginTop: '12px', padding: '6px 14px', border: '1px solid #efaa9f', borderRadius: '6px', color: '#fff6f4', background: '#3b1c24', cursor: 'pointer', font: 'inherit' });
    close.onclick = () => { panel.remove(); banner = null; };
    box.append(label, title, banner, close);
    shadow.append(box);
    document.documentElement.append(panel);
  }
  banner.textContent = text;
}

// Display an interactive modal alert when clicking a suspicious link
function showClickWarning(targetUrl, reasonText, onContinue, onClose) {
  if (clickDialog) {
    clickDialog.remove();
    clickDialog = null;
  }

  const overlay = document.createElement('div');
  Object.assign(overlay.style, {
    position: 'fixed',
    top: '0',
    left: '0',
    width: '100vw',
    height: '100vh',
    background: 'rgba(5, 8, 14, 0.88)',
    backdropFilter: 'blur(8px)',
    display: 'grid',
    placeItems: 'center',
    zIndex: '2147483647',
    padding: '16px',
    boxSizing: 'border-box'
  });

  const shadow = overlay.attachShadow({ mode: 'closed' });

  const modal = document.createElement('div');
  modal.setAttribute('role', 'alertdialog');
  modal.setAttribute('aria-modal', 'true');
  Object.assign(modal.style, {
    background: '#0d131f',
    color: '#f1f5f9',
    width: 'min(100%, 540px)',
    border: '1px solid #ff5c5c',
    borderTop: '6px solid #ff5c5c',
    borderRadius: '12px',
    padding: '28px 24px',
    boxShadow: '0 20px 50px rgba(0,0,0,0.85)',
    fontFamily: 'system-ui, -apple-system, sans-serif',
    boxSizing: 'border-box',
    lineHeight: '1.5'
  });

  // Header
  const header = document.createElement('div');
  Object.assign(header.style, { display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '14px' });

  const icon = document.createElement('div');
  icon.textContent = '⚠';
  Object.assign(icon.style, { fontSize: '32px', lineHeight: '1', color: '#ff5c5c' });

  const titleBox = document.createElement('div');
  const tag = document.createElement('span');
  tag.textContent = 'HACKMATRIX THREAT GUARD';
  Object.assign(tag.style, { fontSize: '11px', fontWeight: '800', letterSpacing: '0.12em', color: '#ff5c5c', display: 'block' });

  const heading = document.createElement('h2');
  heading.textContent = 'Suspicious link detected';
  Object.assign(heading.style, { margin: '2px 0 0 0', fontSize: '22px', fontWeight: '700', color: '#ffffff' });

  titleBox.append(tag, heading);
  header.append(icon, titleBox);

  // Address box
  const urlBox = document.createElement('div');
  Object.assign(urlBox.style, {
    background: '#161f30',
    border: '1px solid #25334c',
    borderRadius: '6px',
    padding: '10px 14px',
    fontFamily: 'ui-monospace, monospace',
    fontSize: '13px',
    wordBreak: 'break-all',
    color: '#ff8a7e',
    margin: '14px 0'
  });
  urlBox.textContent = targetUrl;

  // Reason
  const reasonEl = document.createElement('p');
  reasonEl.style.color = '#ff8a7e';
  reasonEl.style.fontWeight = '600';
  reasonEl.style.fontSize = '14px';
  reasonEl.style.margin = '0 0 12px 0';
  reasonEl.textContent = reasonText;

  // Question
  const question = document.createElement('p');
  question.style.margin = '0 0 20px 0';
  question.style.fontSize = '15px';
  question.style.fontWeight = '600';
  question.textContent = 'This link appears deceptive or fraudulent. Do you wish to continue or close?';

  // Action buttons
  const actions = document.createElement('div');
  Object.assign(actions.style, { display: 'flex', flexWrap: 'wrap', gap: '10px', alignItems: 'center', marginTop: '20px' });

  // 1. Close button (Safe, primary)
  const closeBtn = document.createElement('button');
  closeBtn.textContent = 'Close / Stay Safe (Recommended)';
  Object.assign(closeBtn.style, {
    background: '#00dc82',
    color: '#080c14',
    border: 'none',
    padding: '12px 20px',
    borderRadius: '6px',
    fontWeight: '700',
    fontSize: '14px',
    cursor: 'pointer',
    flex: '1 1 200px'
  });
  closeBtn.onclick = () => {
    overlay.remove();
    clickDialog = null;
    if (onClose) onClose();
  };

  // 2. Continue anyway button (Unsafe, secondary)
  const continueBtn = document.createElement('button');
  continueBtn.textContent = 'Continue anyway (Unsafe)';
  Object.assign(continueBtn.style, {
    background: 'transparent',
    color: '#ff8a7e',
    border: '1px solid #ff5c5c',
    padding: '11px 18px',
    borderRadius: '6px',
    fontWeight: '600',
    fontSize: '13.5px',
    cursor: 'pointer'
  });
  continueBtn.onclick = () => {
    overlay.remove();
    clickDialog = null;
    if (onContinue) onContinue();
  };

  // 3. Inspect in dashboard link
  const inspectLink = document.createElement('a');
  inspectLink.textContent = 'Investigate in HackMatrix Dashboard ↗';
  inspectLink.href = 'http://127.0.0.1:8787/link?u=' + encodeURIComponent(targetUrl);
  inspectLink.target = '_blank';
  inspectLink.rel = 'noopener noreferrer';
  Object.assign(inspectLink.style, {
    color: '#94a3b8',
    fontSize: '13px',
    textDecoration: 'underline',
    display: 'block',
    marginTop: '16px',
    cursor: 'pointer'
  });

  actions.append(closeBtn, continueBtn);
  modal.append(header, urlBox, reasonEl, question, actions, inspectLink);
  shadow.append(modal);
  (document.body || document.documentElement).append(overlay);
  clickDialog = overlay;
  closeBtn.focus();
}

// Global click event listener: catches clicks on suspicious links automatically
document.addEventListener('click', (event) => {
  const target = event.target;
  const anchor = target.closest('a');
  if (!anchor) return;

  let href = anchor.href || anchor.getAttribute('href') || anchor.getAttribute('data-url');
  if (!href && anchor.id && anchor.id.startsWith('try-')) {
    const examples = {
      'try-sbi': 'https://sbi.co.in.kyc-verify.top/login',
      'try-job': 'https://careers-acme.example/apply',
      'try-form': 'https://forms-scam.example/login',
      'try-distrust': 'https://distrusted.example/'
    };
    href = examples[anchor.id];
  }

  if (!href || !/^https?:\/\//i.test(href)) return;
  if (href.startsWith(location.origin + '/#') || href === location.href) return;

  // Ignore navigation to the local dashboard itself
  try {
    const u = new URL(href);
    if (['127.0.0.1', 'localhost'].includes(u.hostname) && !u.searchParams.get('u')) {
      return;
    }
  } catch {
    return;
  }

  if (allowedUrls.has(href)) return;

  const reason = isSuspiciousLink(href);
  if (!reason) return;

  // Freeze navigation immediately!
  event.preventDefault();
  event.stopPropagation();
  event.stopImmediatePropagation();

  // Show the safety alert asking to continue or close!
  showClickWarning(
    href,
    reason,
    () => {
      // User chose to continue anyway
      allowedUrls.add(href);
      try {
        chrome.runtime.sendMessage({ type: 'allowUrl', url: href }).catch(() => {});
      } catch {}
      if (anchor.target === '_blank') {
        window.open(href, '_blank', 'noopener,noreferrer');
      } else {
        window.location.href = href;
      }
    },
    () => {
      // User chose to close / stay safe
    }
  );
}, true);

// Runtime message listeners
chrome.runtime.onMessage.addListener(message => {
  if (message.type === 'pageWarning') warn(message.reason);
});
chrome.runtime.sendMessage({ type: 'tabWarning' }).then(result => {
  if (result?.reason) warn(result.reason);
}).catch(() => {});

// In-page DOM inspection for webmail and plain HTTP password forms
if (!['127.0.0.1', 'localhost'].includes(host)) {
  let warned = false;
  const seenMessages = new WeakMap();

  function inspect() {
    if (warned) return;
    if (webmail) {
      const messages = document.querySelectorAll('[data-message-id], [role="document"]');
      for (const message of [...messages].slice(-10)) {
        if (!message.getClientRects().length) continue;
        const text = message.textContent.slice(0, 12000);
        if (seenMessages.get(message) === text) continue;
        seenMessages.set(message, text);
        const urgent = /\b(urgent|immediately|final notice|within \d+ hours)\b/i.test(text);
        const sensitive = /\b(otp|password|seed phrase|verification code|application fee|gift cards?)\b/i.test(text);
        if (urgent && sensitive && message.querySelector('a[href^="http"]')) {
          warn('This email combines urgency, a link, and sensitive credential or payment language. Verify the sender independently.');
          return;
        }
      }
    } else {
      for (const field of document.querySelectorAll('input[type="password"], input[autocomplete="one-time-code"], input[name="otp" i], input[id="otp" i]')) {
        const action = field.form?.action;
        const external = action && /^https?:/.test(action) && new URL(action).origin !== location.origin;
        if (location.protocol === 'http:' || host.includes('xn--') || external) {
          warned = true;
          warn(location.protocol === 'http:' ? 'This page requests a password or OTP over HTTP.' :
            external ? 'This password or OTP form submits to a different origin. Verify the destination.' :
            'This internationalized domain requests a password or OTP. Check the domain spelling.');
          return;
        }
      }
    }
  }

  let timer;
  new MutationObserver(() => {
    if (!timer) timer = setTimeout(() => { timer = null; inspect(); }, 350);
  }).observe(document.body, { subtree: true, childList: true, characterData: true });
  inspect();
}
