const params = new URLSearchParams(window.location.search);
const targetUrl = params.get('url') || '';
const reason = params.get('reason') || 'Deceptive address or unverified security certificate';

const urlEl = document.getElementById('target-url');
const reasonEl = document.getElementById('warning-reason');
const closeBtn = document.getElementById('btn-close');
const continueBtn = document.getElementById('btn-continue');
const inspectLink = document.getElementById('btn-inspect');

if (urlEl) urlEl.textContent = targetUrl || 'Unknown destination address';
if (reasonEl) reasonEl.textContent = reason;

if (inspectLink && targetUrl) {
  inspectLink.href = 'http://127.0.0.1:8787/link?u=' + encodeURIComponent(targetUrl);
}

// 1. Close tab or Go back (Safe)
closeBtn.onclick = () => {
  if (window.history.length > 1) {
    window.history.back();
  } else {
    window.close();
  }
};

// 2. Continue to website anyway (Unsafe)
continueBtn.onclick = () => {
  if (!targetUrl) return;
  try {
    chrome.runtime.sendMessage({ type: 'allowUrl', url: targetUrl }, () => {
      window.location.replace(targetUrl);
    });
  } catch {
    window.location.replace(targetUrl);
  }
};
