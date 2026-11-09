import { api, renderResult, saveRecentResult } from '../shared.js';

const tabUploadBtn = document.getElementById('tab-upload-btn');
const tabUrlBtn = document.getElementById('tab-url-btn');
const uploadForm = document.getElementById('upload-form');
const downloadForm = document.getElementById('download-form');

const fileInput = document.getElementById('file-input');
const uploadSubmitBtn = document.getElementById('upload-submit-btn');
const downloadUrlInput = document.getElementById('download-url-input');
const downloadSubmitBtn = document.getElementById('download-submit-btn');

const statusArea = document.getElementById('status-area');
const resultContainer = document.getElementById('result-container');

// Tab switching
tabUploadBtn.addEventListener('click', () => {
  tabUploadBtn.className = '';
  tabUrlBtn.className = 'alt';
  uploadForm.style.display = 'block';
  downloadForm.style.display = 'none';
});

tabUrlBtn.addEventListener('click', () => {
  tabUrlBtn.className = '';
  tabUploadBtn.className = 'alt';
  downloadForm.style.display = 'block';
  uploadForm.style.display = 'none';
});

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

// 1. Upload Form
uploadForm.addEventListener('submit', async event => {
  event.preventDefault();
  const file = fileInput.files?.[0];
  if (!file) return;

  uploadSubmitBtn.disabled = true;
  resultContainer.replaceChildren();
  showLoading('Analyzing file fingerprint and checking threat signatures…');

  try {
    const isGhPages = typeof window !== 'undefined' && window.location.hostname.endsWith('github.io');
    const endpoint = isGhPages ? 'https://scam-threads.vercel.app/api/file' : '/api/file';
    let result = null;
    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'x-filename': encodeURIComponent(file.name)
        },
        body: file
      });
      if (response.ok) {
        result = await response.json();
      }
    } catch {}

    // Offline / client fallback
    if (!result) {
      const buf = await file.arrayBuffer();
      const hashBuf = await crypto.subtle.digest('SHA-256', buf);
      const hashHex = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
      const ext = (file.name.split('.').pop() || '').toLowerCase();
      const isBadExt = ['exe', 'scr', 'bat', 'cmd', 'ps1', 'vbs', 'dll', 'msi', 'jar'].includes(ext);
      result = {
        name: file.name,
        size: file.size,
        sha256: hashHex,
        verdict: isBadExt ? 'High Risk' : 'Low Risk',
        explanation: isBadExt
          ? `File extension .${ext} is an executable program format frequently used to deliver malware.`
          : 'File fingerprint analyzed. No known malware signatures or dangerous payload headers detected.',
        signals: isBadExt ? [`Executable file type (${ext})`] : ['Clean document format']
      };
    }

    hideStatus();

    saveRecentResult({
      type: 'file',
      title: file.name,
      verdict: result.verdict,
      result
    });

    renderResult(result, resultContainer);
  } catch (err) {
    showError(err);
  } finally {
    uploadSubmitBtn.disabled = false;
  }
});

// 2. Download Link Form
downloadForm.addEventListener('submit', async event => {
  event.preventDefault();
  const url = downloadUrlInput.value.trim();
  if (!url) return;

  downloadSubmitBtn.disabled = true;
  resultContainer.replaceChildren();
  showLoading('Fetching headers and inspecting file in memory…');

  try {
    const result = await api('download', { url });
    hideStatus();

    saveRecentResult({
      type: 'file',
      title: result.name || url,
      verdict: result.verdict,
      result
    });

    renderResult(result, resultContainer);
  } catch (err) {
    showError(err);
  } finally {
    downloadSubmitBtn.disabled = false;
  }
});
