const statusEl = document.querySelector('#status');
const verdictBadge = document.querySelector('#verdict-badge');
const evidenceList = document.querySelector('#evidence-list');
const toggle = document.querySelector('#remote');
let currentTabUrl = '';

async function findDashboardUrl(param = '') {
  for (const port of [8787, 8788]) {
    const origin = 'http://127.0.0.1:' + port;
    try {
      const response = await fetch(origin + '/api/threats', { signal: AbortSignal.timeout(1200) });
      if (response.ok && Array.isArray((await response.json()).urls)) {
        return origin + '/' + param;
      }
    } catch {}
  }
  return null;
}

document.querySelector('#dashboard').onclick = async event => {
  event.preventDefault();
  const target = await findDashboardUrl();
  if (target) {
    await chrome.tabs.create({ url: target });
  } else {
    statusEl.textContent = 'Dashboard unavailable. Start local server on port 8787 or 8788.';
    document.querySelector('#card').dataset.alert = 'true';
  }
};

document.querySelector('#deep-investigate').onclick = async () => {
  if (!currentTabUrl) return;
  const target = await findDashboardUrl('#url=' + encodeURIComponent(currentTabUrl));
  if (target) {
    await chrome.tabs.create({ url: target });
  } else {
    statusEl.textContent = 'Start the local dashboard server (port 8787 or 8788) to run investigations.';
    document.querySelector('#card').dataset.alert = 'true';
  }
};

(async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentTabUrl = tab?.url || '';
  const key = 'tab' + tab?.id;
  const [stored, settings] = await Promise.all([chrome.storage.session.get(key), chrome.storage.local.get('remote')]);
  const alertData = stored[key];

  if (alertData) {
    verdictBadge.textContent = alertData.verdict || 'Suspicious';
    verdictBadge.style.color = (alertData.verdict === 'High Risk' || alertData.verdict === 'Confirmed Malicious') ? '#f27474' : '#f8bb86';
    statusEl.textContent = alertData.reason || 'Indicators identified.';
    document.querySelector('#card').dataset.alert = 'true';

    evidenceList.replaceChildren();
    for (const item of (alertData.evidence || []).slice(0, 3)) {
      const li = document.createElement('li');
      li.textContent = item;
      evidenceList.append(li);
    }
  } else {
    verdictBadge.textContent = 'No Threat Detected';
    verdictBadge.style.color = '#69ebbd';
    statusEl.textContent = 'No active phishing or certificate alert for this tab.';
    document.querySelector('#card').dataset.alert = 'false';
  }

  toggle.checked = settings.remote === true;
})();

toggle.onchange = () => chrome.storage.local.set({ remote: toggle.checked });

document.querySelector('#refresh').onclick = async () => {
  try {
    const result = await chrome.runtime.sendMessage({ type: 'refresh' });
    statusEl.textContent = result.error ?? result.count + ' local rules loaded.';
    document.querySelector('#card').dataset.alert = Boolean(result.error);
  } catch (error) {
    statusEl.textContent = error.message;
  }
};
