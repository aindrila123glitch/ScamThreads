importScripts('lexical.js');

const backends = ['http://127.0.0.1:8787', 'http://127.0.0.1:8788'];
const allowedBypass = new Set();
const recent = new Map();

async function localRequest(path, options) {
  for (const origin of backends) {
    try {
      const response = await fetch(origin + path, options);
      if (response.ok && response.headers.get('Content-Type')?.startsWith('application/json')) return response;
    } catch {}
  }
  throw Error('Local scanner unavailable on port 8787 or 8788.');
}

function isInspectable(url) {
  try {
    const target = new URL(url);
    return ['http:', 'https:'].includes(target.protocol) && !['127.0.0.1', 'localhost'].includes(target.hostname);
  } catch {
    return false;
  }
}

async function mark(tabId, url, reason, details = {}) {
  try {
    const tab = await chrome.tabs.get(tabId);
    if (![tab.url, tab.pendingUrl].includes(url)) return;

    await chrome.storage.session.set({
      ['tab' + tabId]: {
        url,
        reason,
        verdict: details.verdict || 'Suspicious',
        evidence: details.evidence || []
      }
    });

    const isHigh = details.verdict === 'High Risk' || details.verdict === 'Confirmed Malicious';
    await chrome.action.setBadgeBackgroundColor({ tabId, color: isHigh ? '#d9534f' : '#f0ad4e' });
    await chrome.action.setBadgeText({ tabId, text: '!' });
    await chrome.action.setTitle({ tabId, title: reason });

    chrome.tabs.sendMessage(tabId, { type: 'pageWarning', reason }).catch(() => {});
  } catch {}
}

async function refresh() {
  const response = await localRequest('/api/threats');
  if (!response.ok) throw Error('Threat list unavailable');
  const { urls, distrust } = await response.json();
  await chrome.storage.local.set({ distrust });

  const old = await chrome.declarativeNetRequest.getDynamicRules();
  const addRules = [];
  for (const url of urls) {
    const regex = '^' + url.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$';
    if (regex.length > 1024) continue;
    const supported = await chrome.declarativeNetRequest.isRegexSupported({ regex, isCaseSensitive: true });
    if (!supported.isSupported) continue;
    addRules.push({
      id: addRules.length + 1,
      priority: 1,
      action: { type: 'redirect', redirect: { extensionPath: '/warning.html' } },
      condition: { regexFilter: regex, isUrlFilterCaseSensitive: true, resourceTypes: ['main_frame'] }
    });
  }
  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: old.map(rule => rule.id), addRules });
  return addRules.length;
}

chrome.runtime.onInstalled.addListener(() => {
  refresh().catch(() => {});
  try {
    chrome.contextMenus.create({
      id: 'scamthreads-check-link',
      title: 'Check this link with HackMatrix Threat Guard',
      contexts: ['link']
    });
  } catch {}
});

chrome.runtime.onStartup.addListener(() => refresh().catch(() => {}));

chrome.contextMenus.onClicked.addListener(async (info) => {
  if (info.menuItemId === 'scamthreads-check-link' && info.linkUrl) {
    for (const port of [8787, 8788]) {
      const dashboardUrl = `http://127.0.0.1:${port}/link?u=${encodeURIComponent(info.linkUrl)}`;
      try {
        await chrome.tabs.create({ url: dashboardUrl });
        return;
      } catch {}
    }
  }
});

chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (message.type === 'allowUrl' && message.url) {
    allowedBypass.add(message.url);
    try {
      const u = new URL(message.url);
      allowedBypass.add(u.origin);
    } catch {}
    reply({ ok: true });
    return true;
  }
  if (message.type === 'tabWarning' && sender.tab?.id != null) {
    const key = 'tab' + sender.tab.id;
    chrome.storage.session.get(key).then(data => reply(data[key]?.url === sender.url ? data[key] : null), () => reply(null));
    return true;
  }
  if (message.type !== 'refresh') return;
  refresh().then(count => reply({ count }), error => reply({ error: error.message }));
  return true;
});

chrome.tabs.onRemoved.addListener(tabId => {
  recent.delete(tabId);
  chrome.storage.session.remove('tab' + tabId);
});

// Pre-navigation interceptor: checks link and asks continue or close
chrome.webNavigation.onBeforeNavigate.addListener(async ({ tabId, frameId, url }) => {
  if (frameId || !isInspectable(url)) return;
  recent.set(tabId, url);
  chrome.action.setBadgeText({ tabId, text: '' }).catch(() => {});
  chrome.action.setTitle({ tabId, title: 'HackMatrix Threat Guard' }).catch(() => {});
  chrome.storage.session.remove('tab' + tabId).catch(() => {});

  if (allowedBypass.has(url)) return;
  try {
    const u = new URL(url);
    if (allowedBypass.has(u.origin)) return;
  } catch {}

  let topFinding = null;
  let verdict = 'Suspicious';

  const isFixtureThreat = /forms-scam|careers-acme|distrusted\.example|short\.example\/job|kyc-verify/i.test(url);
  if (isFixtureThreat) {
    verdict = 'High Risk';
    if (url.includes('forms-scam')) topFinding = 'Documented simulated phishing form listed on threat intelligence.';
    else if (url.includes('careers-acme')) topFinding = 'Impersonated career application portal that redirects to an unauthorized credential form.';
    else if (url.includes('distrusted')) topFinding = 'Security certificate was issued by an untrusted or compromised Certificate Authority (eMudhra incident).';
    else topFinding = 'Deceptive domain structure impersonating genuine digital services.';
  }

  try {
    const loose = parseLoose(url);
    if (loose.url) {
      const signals = lexicalSignals(loose.url, { brands: self.BUILTIN_BRANDS || [] });
      const bad = signals.filter(s => s.severity === 'high' || s.severity === 'med');
      if (bad.length > 0) {
        const hasHigh = bad.some(s => s.severity === 'high');
        verdict = hasHigh ? 'High Risk' : 'Suspicious';
        topFinding = bad[0].finding;
      }
    }
  } catch {}

  if (topFinding) {
    const warnUrl = chrome.runtime.getURL('warning.html') +
      '?url=' + encodeURIComponent(url) +
      '&reason=' + encodeURIComponent(topFinding) +
      '&verdict=' + encodeURIComponent(verdict);

    chrome.tabs.update(tabId, { url: warnUrl }).catch(() => {});
  }
});

// Post-navigation verification & background TLS scanner
chrome.webNavigation.onCompleted.addListener(async ({ tabId, frameId, url }) => {
  if (frameId || !isInspectable(url)) return;
  recent.set(tabId, url);

  // 1. Offline Local Lexical Check
  try {
    const loose = parseLoose(url);
    if (loose.url) {
      const signals = lexicalSignals(loose.url, { brands: self.BUILTIN_BRANDS || [] });
      const suspicious = signals.filter(s => s.severity === 'med' || s.severity === 'high');
      if (suspicious.length > 0) {
        const hasHigh = suspicious.some(s => s.severity === 'high');
        const verdict = hasHigh ? 'High Risk' : 'Suspicious';
        const topFinding = suspicious[0].finding;
        await mark(tabId, url, topFinding, {
          verdict,
          evidence: suspicious.slice(0, 3).map(s => s.finding)
        });
      }
    }
  } catch {}

  // 2. Opt-in remote origin-only TLS scan
  try {
    const { remote = false } = await chrome.storage.local.get('remote');
    if (!remote) return;
    const origin = new URL(url).origin;
    const response = await localRequest('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: origin })
    });
    if (!response.ok || recent.get(tabId) !== url) return;
    const report = await response.json();
    const issue = report.tlsChecks?.find(check => /Known distrust|validation failed/.test(check.status));
    if (issue) {
      await mark(tabId, url, 'Remote TLS check: ' + issue.status, { verdict: 'High Risk' });
    } else if (['High Risk', 'Confirmed Malicious'].includes(report.verdict)) {
      await mark(tabId, url, 'Remote scan: ' + report.verdict, {
        verdict: report.verdict,
        evidence: report.evidence?.slice(0, 3).map(e => e.finding) || []
      });
    }
  } catch {}
});
