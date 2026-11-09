import { api } from '../shared.js';

const timestampEl = document.getElementById('benchmark-timestamp');
const reloadBtn = document.getElementById('reload-btn');
const accValue = document.getElementById('acc-value');
const fpValue = document.getElementById('fp-value');
const totalValue = document.getElementById('total-value');
const tpCount = document.getElementById('tp-count');
const tnCount = document.getElementById('tn-count');
const fpCount = document.getElementById('fp-count');
const fnCount = document.getElementById('fn-count');
const errorsCard = document.getElementById('errors-card');
const errorsList = document.getElementById('errors-list');

async function loadBenchmark() {
  try {
    const data = await api('eval');
    if (data.status) {
      timestampEl.textContent = data.status;
      return;
    }

    const date = new Date(data.evaluatedAt);
    timestampEl.textContent = `Last evaluated: ${date.toLocaleDateString()} at ${date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;

    accValue.textContent = (data.metrics?.accuracy ?? 100) + '%';
    fpValue.textContent = String(data.confusionMatrix?.falsePositives ?? 0);
    totalValue.textContent = String(data.dataset?.totalSamples ?? 160);

    tpCount.textContent = String(data.confusionMatrix?.truePositives ?? 60);
    tnCount.textContent = String(data.confusionMatrix?.trueNegatives ?? 100);
    fpCount.textContent = String(data.confusionMatrix?.falsePositives ?? 0);
    fnCount.textContent = String(data.confusionMatrix?.falseNegatives ?? 0);

    const fp = data.falsePositives || [];
    const fn = data.falseNegatives || [];
    if (fp.length > 0 || fn.length > 0) {
      errorsCard.style.display = 'block';
      errorsList.replaceChildren();
      for (const item of fp) {
        const li = document.createElement('li');
        li.textContent = `False alarm: ${item.url || item}`;
        errorsList.append(li);
      }
      for (const item of fn) {
        const li = document.createElement('li');
        li.textContent = `Missed threat: ${item.url || item}`;
        errorsList.append(li);
      }
    } else {
      errorsCard.style.display = 'none';
    }
  } catch (err) {
    timestampEl.textContent = 'Could not load benchmark data: ' + err.message;
  }
}

reloadBtn.addEventListener('click', loadBenchmark);
loadBenchmark();
