import { api } from '../shared.js';

const form = document.getElementById('watch-form');
const brandInput = document.getElementById('brand-domain-input');
const repeatCheckbox = document.getElementById('repeat-checkbox');
const submitBtn = document.getElementById('watch-submit-btn');
const statusArea = document.getElementById('watch-status');
const resultsArea = document.getElementById('watch-results-area');

let timer = null;

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

function hideStatus() {
  statusArea.style.display = 'none';
  statusArea.replaceChildren();
}

function renderResults(list) {
  resultsArea.replaceChildren();

  if (!Array.isArray(list) || list.length === 0) {
    const card = document.createElement('div');
    card.className = 'card-box';
    card.textContent = 'No look-alike domain variants were generated.';
    resultsArea.append(card);
    return;
  }

  const section = document.createElement('section');
  section.className = 'block';

  const h2 = document.createElement('h2');
  h2.textContent = `Monitored Variants (${list.length})`;
  section.append(h2);

  const table = document.createElement('table');
  table.innerHTML = '<thead><tr><th>Variant address</th><th>Registration status</th><th>Padlock logs</th><th>Action</th></tr></thead><tbody></tbody>';
  const tbody = table.querySelector('tbody');

  for (const item of list) {
    const tr = document.createElement('tr');

    const tdHost = document.createElement('td');
    tdHost.style.fontFamily = 'inherit';
    tdHost.textContent = item.host;

    const tdRdap = document.createElement('td');
    const rdapDays = item.rdap?.days != null ? ` (${item.rdap.days} days old)` : '';
    tdRdap.textContent = (item.rdap?.status || 'Unknown') + rdapDays;

    const tdCt = document.createElement('td');
    const ctCount = item.ct?.certificates?.length || 0;
    tdCt.textContent = `${ctCount} certificate(s)`;

    const tdAct = document.createElement('td');
    const a = document.createElement('a');
    a.href = './link.html?u=' + encodeURIComponent('https://' + item.host);
    a.textContent = 'Check link →';
    tdAct.append(a);

    tr.append(tdHost, tdRdap, tdCt, tdAct);
    tbody.append(tr);
  }

  section.append(table);
  resultsArea.append(section);
}

async function executeWatch() {
  const domain = brandInput.value.trim();
  if (!domain) return;

  submitBtn.disabled = true;
  showLoading('Checking DNS registration records and certificate logs…');

  try {
    const list = await api('watch', { domain });
    hideStatus();
    renderResults(list);
  } catch (err) {
    statusArea.style.display = 'block';
    statusArea.className = 'error-banner';
    statusArea.textContent = 'Watch error: ' + err.message;
  } finally {
    submitBtn.disabled = false;
  }
}

form.addEventListener('submit', event => {
  event.preventDefault();
  clearInterval(timer);
  executeWatch();
  if (repeatCheckbox.checked) {
    timer = setInterval(executeWatch, 15 * 60 * 1000);
  }
});

repeatCheckbox.addEventListener('change', () => {
  if (!repeatCheckbox.checked) clearInterval(timer);
});
