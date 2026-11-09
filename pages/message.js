import { api, renderResult, saveRecentResult, translateFinding } from '../shared.js';

const form = document.getElementById('message-form');
const messageInput = document.getElementById('message-input');
const urlInput = document.getElementById('msg-url-input');
const submitBtn = document.getElementById('submit-btn');
const statusArea = document.getElementById('status-area');
const resultContainer = document.getElementById('result-container');

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

function renderMessageLanes(data, container) {
  const rep = data.messageReport;
  if (!rep) return;

  const section = document.createElement('section');
  section.className = 'block';

  const h2 = document.createElement('h2');
  h2.textContent = 'Message analysis breakdown';
  section.append(h2);

  const grid = document.createElement('div');
  grid.style.cssText = 'display:grid; grid-template-columns:repeat(auto-fit, minmax(280px, 1fr)); gap:16px; margin-top:12px;';

  // Lane A: Pressure tactics
  const cardA = document.createElement('div');
  cardA.style.cssText = 'background:var(--surface); border:1px solid var(--rule); border-left:6px solid var(--warn); padding:16px; border-radius:4px;';
  const hA = document.createElement('h3');
  hA.style.cssText = 'margin:0 0 10px 0; color:var(--warn);';
  hA.textContent = 'Pressure tactics we noticed';
  cardA.append(hA);

  const langList = rep.language || [];
  if (langList.length === 0) {
    const p = document.createElement('p');
    p.style.cssText = 'font-size:0.95rem; color:var(--muted); margin:0;';
    p.textContent = 'No artificial panic language or urgency pressure words were found.';
    cardA.append(p);
  } else {
    const ulA = document.createElement('ul');
    ulA.style.cssText = 'margin:0; padding-left:1.2rem; font-size:0.95rem;';
    for (const item of langList) {
      const li = document.createElement('li');
      li.style.marginBottom = '6px';
      li.textContent = translateFinding(item.finding || item);
      ulA.append(li);
    }
    cardA.append(ulA);
  }

  // Lane B: Hard evidence
  const cardB = document.createElement('div');
  cardB.style.cssText = 'background:var(--surface); border:1px solid var(--rule); border-left:6px solid var(--thread); padding:16px; border-radius:4px;';
  const hB = document.createElement('h3');
  hB.style.cssText = 'margin:0 0 10px 0; color:var(--thread);';
  hB.textContent = 'Hard evidence we verified';
  cardB.append(hB);

  const ext = rep.extracted || {};
  const extItems = [];
  if (ext.urls?.length) extItems.push(`Links found: ${ext.urls.join(', ')}`);
  if (ext.phones?.length) extItems.push(`Phone numbers extracted: ${ext.phones.join(', ')}`);
  if (ext.upis?.length) extItems.push(`UPI payment addresses: ${ext.upis.join(', ')}`);
  if (ext.ifscs?.length) extItems.push(`Bank IFSC codes: ${ext.ifscs.join(', ')}`);
  if (ext.crypto?.length) extItems.push(`Cryptocurrency addresses: ${ext.crypto.join(', ')}`);

  const techList = rep.technical || [];
  for (const t of techList) {
    extItems.push(translateFinding(t.finding || t));
  }

  if (extItems.length === 0) {
    const p = document.createElement('p');
    p.style.cssText = 'font-size:0.95rem; color:var(--muted); margin:0;';
    p.textContent = 'No external payment addresses, bank codes, or links were found in the text.';
    cardB.append(p);
  } else {
    const ulB = document.createElement('ul');
    ulB.style.cssText = 'margin:0; padding-left:1.2rem; font-size:0.95rem;';
    for (const item of extItems) {
      const li = document.createElement('li');
      li.style.marginBottom = '6px';
      li.textContent = item;
      ulB.append(li);
    }
    cardB.append(ulB);
  }

  grid.append(cardA, cardB);
  section.append(grid);
  container.prepend(section);
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  const text = messageInput.value.trim();
  const url = urlInput.value.trim();
  if (!text && !url) return;

  submitBtn.disabled = true;
  resultContainer.replaceChildren();
  showLoading('Analyzing language patterns and extracting indicators…');

  try {
    const data = await api('scan', { message: text, url: url || undefined, deep: true });
    hideStatus();

    saveRecentResult({
      type: 'message',
      title: text.slice(0, 45) + (text.length > 45 ? '…' : ''),
      verdict: data.verdict,
      result: data
    });

    renderResult(data, resultContainer);
    renderMessageLanes(data, resultContainer);
  } catch (err) {
    showError(err);
  } finally {
    submitBtn.disabled = false;
  }
});
