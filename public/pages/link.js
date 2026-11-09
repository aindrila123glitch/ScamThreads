import { api, renderResult, saveRecentResult, showDashboardLinkModal } from '../shared.js';

const form = document.getElementById('link-form');
const urlInput = document.getElementById('url-input');
const submitBtn = document.getElementById('submit-btn');
const statusArea = document.getElementById('status-area');
const resultContainer = document.getElementById('result-container');

// Quick example links metadata
const examples = {
  'try-sbi': {
    url: 'https://sbi.co.in.kyc-verify.top/login',
    reason: 'Brand name "SBI" used in subdomain of unrelated domain (kyc-verify.top). High-risk suspicious domain extension (.top).'
  },
  'try-job': {
    url: 'https://careers-acme.example/apply',
    reason: 'Impersonated career application portal that redirects to an unauthorized external credential form.'
  },
  'try-form': {
    url: 'https://forms-scam.example/login',
    reason: 'Known fraudulent credential-harvesting phishing form listed on public threat intelligence.'
  },
  'try-distrust': {
    url: 'https://distrusted.example/',
    reason: 'Uses a compromised or untrusted Certificate Authority intermediate key (eMudhra incident).'
  }
};

for (const [id, info] of Object.entries(examples)) {
  const el = document.getElementById(id);
  if (el) {
    el.addEventListener('click', (e) => {
      e.preventDefault();
      urlInput.value = info.url;
      // Automatically trigger the warning modal asking continue or close!
      showDashboardLinkModal(info.url, info.reason, () => {
        executeScan(info.url);
      });
    });
  }
}

// Prefill from query string (?u=... or ?url=...)
const params = new URLSearchParams(window.location.search);
const prefilled = params.get('u') || params.get('url');
if (prefilled) {
  urlInput.value = prefilled;
  executeScan(prefilled);
}

function showLoading(msg) {
  statusArea.style.display = 'flex';
  statusArea.className = 'status-banner';
  statusArea.replaceChildren();

  const spinner = document.createElement('div');
  spinner.className = 'spinner';
  const text = document.createElement('span');
  text.textContent = msg;

  statusArea.append(spinner, text);
}

function showError(err) {
  statusArea.style.display = 'block';
  statusArea.className = 'error-banner';
  statusArea.replaceChildren();

  const p = document.createElement('p');
  p.style.margin = '0';
  p.textContent = err.message || String(err);
  statusArea.append(p);
}

function hideStatus() {
  statusArea.style.display = 'none';
  statusArea.replaceChildren();
}

async function executeScan(rawUrl) {
  if (!rawUrl) return;

  submitBtn.disabled = true;
  resultContainer.replaceChildren();
  showLoading('Checking where this link leads… this can take up to 15 seconds.');

  try {
    const data = await api('scan', { url: rawUrl, deep: true });
    hideStatus();

    saveRecentResult({
      type: 'link',
      title: rawUrl,
      verdict: data.verdict,
      result: data
    });

    // Render evidence report
    renderResult(data, resultContainer);

    // If suspicious or high risk, automatically pop up the safety alert!
    if (data.verdict === 'High Risk' || data.verdict === 'Confirmed Malicious' || data.verdict === 'Suspicious') {
      showDashboardLinkModal(rawUrl, data.explanation);
    }
  } catch (err) {
    showError(err);
  } finally {
    submitBtn.disabled = false;
  }
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  const rawUrl = urlInput.value.trim();
  if (rawUrl) {
    executeScan(rawUrl);
  }
});
