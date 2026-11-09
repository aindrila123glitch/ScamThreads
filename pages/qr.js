import { saveRecentResult } from '../shared.js';

const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('qr-file-input');
const resultBox = document.getElementById('qr-result-box');

dropZone.addEventListener('click', () => fileInput.click());

dropZone.addEventListener('dragover', event => {
  event.preventDefault();
  dropZone.style.borderColor = 'var(--thread)';
});

dropZone.addEventListener('dragleave', () => {
  dropZone.style.borderColor = 'var(--muted)';
});

dropZone.addEventListener('drop', event => {
  event.preventDefault();
  dropZone.style.borderColor = 'var(--muted)';
  const file = event.dataTransfer?.files?.[0];
  if (file) handleImageFile(file);
});

fileInput.addEventListener('change', () => {
  const file = fileInput.files?.[0];
  if (file) handleImageFile(file);
});

function handleImageFile(file) {
  resultBox.style.display = 'block';
  resultBox.className = 'status-banner';
  resultBox.replaceChildren();

  const spinner = document.createElement('div');
  spinner.className = 'spinner';
  const text = document.createElement('span');
  text.textContent = 'Decoding QR image in browser memory…';
  resultBox.append(spinner, text);

  const reader = new FileReader();
  reader.onload = e => {
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = img.width;
      canvas.height = img.height;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0);
      const imgData = ctx.getImageData(0, 0, img.width, img.height);

      if (typeof jsQR !== 'undefined') {
        const code = jsQR(imgData.data, img.width, img.height);
        if (code && code.data) {
          renderDecodedQr(code.data);
        } else {
          showError('No QR code could be detected in this image. Try zooming in or cropping the QR code.');
        }
      } else {
        showError('QR decoder library is unavailable.');
      }
    };
    img.src = e.target.result;
  };
  reader.readAsDataURL(file);
}

function showError(msg) {
  resultBox.className = 'error-banner';
  resultBox.replaceChildren();
  const p = document.createElement('p');
  p.style.margin = '0';
  p.textContent = msg;
  resultBox.append(p);
}

function renderDecodedQr(raw) {
  resultBox.className = 'card-box';
  resultBox.replaceChildren();

  const h2 = document.createElement('h2');
  h2.textContent = 'Decoded QR Content';
  resultBox.append(h2);

  const decodedPre = document.createElement('pre');
  decodedPre.style.cssText = 'background:var(--chalk); padding:14px; border:1px solid var(--rule); border-radius:4px; font-size:1rem; margin-bottom:18px; overflow-wrap:anywhere; font-family:inherit;';
  decodedPre.textContent = raw;
  resultBox.append(decodedPre);

  // Check if UPI payment QR
  if (raw.startsWith('upi://pay')) {
    saveRecentResult({
      type: 'qr',
      title: 'UPI Payment QR',
      verdict: 'Suspicious',
      result: { raw, type: 'UPI Payment' }
    });

    const upiBox = document.createElement('div');
    upiBox.className = 'verdict high';

    const vTitle = document.createElement('div');
    vTitle.className = 'v';
    vTitle.textContent = 'Warning: Money transfer QR';
    upiBox.append(vTitle);

    const warnP = document.createElement('p');
    warnP.style.cssText = 'font-weight:700; margin:6px 0 14px 0; color:var(--high); font-size:1.05rem;';
    warnP.textContent = 'Scanning this QR code or entering your UPI PIN will DEDUCT money from your account. You NEVER need to enter a UPI PIN or scan a QR code to receive money or refunds.';
    upiBox.append(warnP);

    try {
      const upiUrl = new URL(raw);
      const pa = upiUrl.searchParams.get('pa') || 'Not specified';
      const pn = upiUrl.searchParams.get('pn') || 'Not specified';
      const am = upiUrl.searchParams.get('am');

      const detailsUl = document.createElement('ul');
      detailsUl.className = 'why';
      const li1 = document.createElement('li'); li1.textContent = 'Payee Name (who gets paid): ' + pn;
      const li2 = document.createElement('li'); li2.textContent = 'Payee UPI ID: ' + pa;
      detailsUl.append(li1, li2);
      if (am) {
        const li3 = document.createElement('li'); li3.textContent = 'Amount to be deducted: ₹' + am;
        detailsUl.append(li3);
      }
      upiBox.append(detailsUl);
    } catch {}

    resultBox.append(upiBox);
  } else if (/^https?:\/\//i.test(raw)) {
    saveRecentResult({
      type: 'qr',
      title: raw,
      verdict: 'Inconclusive',
      result: { raw, type: 'URL' }
    });

    const btn = document.createElement('a');
    btn.className = 'btn';
    btn.href = '/link?u=' + encodeURIComponent(raw);
    btn.textContent = 'Check this link →';
    resultBox.append(btn);
  } else {
    saveRecentResult({
      type: 'qr',
      title: 'QR Text',
      verdict: 'Inconclusive',
      result: { raw }
    });

    const p = document.createElement('p');
    p.style.color = 'var(--muted)';
    p.textContent = 'This QR code contains plain text. No website address was detected.';
    resultBox.append(p);
  }
}
