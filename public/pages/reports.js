import { api, getRecentResults, translateFinding } from '../shared.js';

const recentSelect = document.getElementById('recent-select');
const prepareBtn = document.getElementById('prepare-btn');
const preparePreview = document.getElementById('prepare-preview');

const step2Card = document.getElementById('step-2-card');
const saveRecordBtn = document.getElementById('save-record-btn');
const downloadDocBtn = document.getElementById('download-doc-btn');
const saveStatus = document.getElementById('save-status');

const checkDocInput = document.getElementById('check-doc-input');
const verifyDocBtn = document.getElementById('verify-doc-btn');
const verifyResult = document.getElementById('verify-result');

const v2Card = document.getElementById('registry-v2-card');
const timelineBox = document.getElementById('timeline-box');
const validateBtn = document.getElementById('validate-btn');
const disputeBtn = document.getElementById('dispute-btn');
const findingIdInput = document.getElementById('finding-id-input');
const proveFindingBtn = document.getElementById('prove-finding-btn');
const merkleProofOutput = document.getElementById('merkle-proof-output');

let currentReportData = null;
let currentDocument = null;
let currentCommitment = null;

// Populate recent results from sessionStorage
const recents = getRecentResults();
if (recents.length > 0) {
  recents.forEach((item, idx) => {
    const opt = document.createElement('option');
    opt.value = String(idx);
    const dateStr = new Date(item.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    opt.textContent = `[${item.verdict}] ${item.title} (${dateStr})`;
    recentSelect.append(opt);
  });
} else {
  const opt = document.createElement('option');
  opt.disabled = true;
  opt.textContent = 'No investigations yet in this session. Check a link first!';
  recentSelect.append(opt);
}

recentSelect.addEventListener('change', () => {
  const idx = recentSelect.value;
  if (idx !== '' && recents[idx]) {
    currentReportData = recents[idx].result;
    prepareBtn.disabled = false;
  } else {
    currentReportData = null;
    prepareBtn.disabled = true;
  }
});

// Step 1: Prepare report
prepareBtn.addEventListener('click', async () => {
  if (!currentReportData) return;
  prepareBtn.disabled = true;
  prepareBtn.textContent = 'Preparing evidence package…';

  try {
    const res = await api('report', { report: currentReportData });
    currentDocument = res.document;
    currentCommitment = res.commitment;

    preparePreview.style.display = 'block';
    preparePreview.replaceChildren();

    const parsed = JSON.parse(res.document);
    const h3 = document.createElement('h3');
    h3.textContent = 'Report Package Preview (Privacy-Guaranteed)';
    preparePreview.append(h3);

    const ul = document.createElement('ul');
    ul.className = 'why';
    const li1 = document.createElement('li'); li1.textContent = 'Report ID: ' + parsed.id;
    const li2 = document.createElement('li'); li2.textContent = 'Verdict: ' + parsed.report.verdict;
    const li3 = document.createElement('li'); li3.textContent = `Verified evidence items: ${parsed.evidenceLeaves?.length || 0}`;
    const li4 = document.createElement('li'); li4.textContent = 'Evidence Merkle Root: ' + (parsed.evidenceRoot || 'None');
    ul.append(li1, li2, li3, li4);
    preparePreview.append(ul);

    if (parsed.report.evidence?.length) {
      const p = document.createElement('p');
      p.style.cssText = 'font-weight:700; margin:10px 0 6px 0;';
      p.textContent = 'Included Findings:';
      preparePreview.append(p);

      const findUl = document.createElement('ul');
      findUl.className = 'why';
      for (const ev of parsed.report.evidence) {
        const fli = document.createElement('li');
        fli.textContent = `${ev.id}: ${translateFinding(ev.finding || ev)}`;
        findUl.append(fli);
      }
      preparePreview.append(findUl);
    }

    step2Card.style.opacity = '1';
    saveRecordBtn.disabled = false;
    downloadDocBtn.disabled = false;
  } catch (err) {
    alert('Failed to prepare report: ' + err.message);
  } finally {
    prepareBtn.disabled = false;
    prepareBtn.textContent = 'Prepare report';
  }
});

downloadDocBtn.addEventListener('click', () => {
  if (!currentDocument) return;
  const blob = new Blob([currentDocument], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `scamthreads-report-${Date.now().toString(36)}.json`;
  a.click();
  URL.revokeObjectURL(url);
});

// Step 2: Save on blockchain
saveRecordBtn.addEventListener('click', async () => {
  if (!currentDocument) return;
  saveRecordBtn.disabled = true;
  saveRecordBtn.textContent = 'Saving to blockchain…';

  saveStatus.style.display = 'block';
  saveStatus.className = 'status-banner';
  saveStatus.textContent = 'Connecting to Registry.sol smart contract…';

  try {
    const res = await api('register', { document: currentDocument });

    saveStatus.className = 'verdict ok';
    saveStatus.replaceChildren();

    const h3 = document.createElement('div');
    h3.className = 'v';
    h3.textContent = 'Saved on blockchain';
    saveStatus.append(h3);

    const ul = document.createElement('ul');
    ul.className = 'why';
    ul.style.marginTop = '8px';
    const li1 = document.createElement('li'); li1.textContent = 'Fingerprint: ' + res.commitment.slice(0, 18) + '…';
    const li2 = document.createElement('li'); li2.textContent = 'Tx Hash: ' + res.transaction.slice(0, 18) + '…';
    const li3 = document.createElement('li'); li3.textContent = 'Smart Contract: ' + res.contract;
    ul.append(li1, li2, li3);
    saveStatus.append(ul);

    checkDocInput.value = currentDocument;
    showV2Lifecycle(res.commitment);
  } catch (err) {
    saveStatus.className = 'error-banner';
    saveStatus.textContent = 'Blockchain save error: ' + err.message;
  } finally {
    saveRecordBtn.disabled = false;
    saveRecordBtn.textContent = 'Save record on blockchain';
  }
});

function showV2Lifecycle() {
  v2Card.style.display = 'block';
  timelineBox.replaceChildren();

  const states = ['Submitted on-chain', 'Awaiting community validation', 'Active'];
  states.forEach((s, i) => {
    const badge = document.createElement('span');
    badge.style.cssText = 'padding:4px 10px; border-radius:2px; font-size:0.9rem; font-weight:700; background:var(--chalk); border:1px solid var(--rule);';
    if (i === 0) {
      badge.style.borderColor = 'var(--thread)';
      badge.style.color = 'var(--thread)';
    }
    badge.textContent = `● ${s}`;
    timelineBox.append(badge);
  });
}

// Collaborative actions
validateBtn.addEventListener('click', async () => {
  if (!currentDocument) return;
  validateBtn.disabled = true;
  try {
    const res = await api('validate', { document: currentDocument });
    alert(`Report confirmed! Transaction: ${res.transaction.slice(0, 12)}…`);
  } catch (err) {
    alert('Validation error: ' + err.message);
  } finally {
    validateBtn.disabled = false;
  }
});

disputeBtn.addEventListener('click', async () => {
  if (!currentDocument) return;
  disputeBtn.disabled = true;
  try {
    const res = await api('dispute', { document: currentDocument, reason: 'False alarm / contested evidence' });
    alert(`Report challenged! Status: ${res.status}. Transaction: ${res.transaction.slice(0, 12)}…`);
  } catch (err) {
    alert('Dispute error: ' + err.message);
  } finally {
    disputeBtn.disabled = false;
  }
});

// Single-finding Merkle proof
proveFindingBtn.addEventListener('click', async () => {
  const findingId = findingIdInput.value.trim().toUpperCase();
  if (!currentDocument || !findingId) return;

  merkleProofOutput.style.display = 'block';
  merkleProofOutput.textContent = 'Computing Merkle proof path…';

  try {
    const proofRes = await api('prove', { document: currentDocument, evidenceId: findingId });
    const verifyRes = await api('verify-proof', {
      leaf: proofRes.leaf,
      proof: proofRes.proof,
      evidenceRoot: proofRes.evidenceRoot
    });

    merkleProofOutput.textContent = JSON.stringify({
      findingId: proofRes.evidenceId,
      findingLeafHash: proofRes.leaf,
      merklePathLength: proofRes.proof.length,
      cryptographicallyVerified: verifyRes.verified
    }, null, 2);
  } catch (err) {
    merkleProofOutput.textContent = 'Proof error: ' + err.message;
  }
});

// Step 3: Check a report
verifyDocBtn.addEventListener('click', async () => {
  const docText = checkDocInput.value.trim();
  if (!docText) return;

  verifyDocBtn.disabled = true;
  verifyResult.style.display = 'block';
  verifyResult.className = 'status-banner';
  verifyResult.textContent = 'Verifying cryptographic commitment on smart contract…';

  try {
    const res = await api('verify', { document: docText });
    verifyResult.replaceChildren();

    if (res.verified) {
      verifyResult.className = 'verdict ok';

      const v = document.createElement('div');
      v.className = 'v';
      v.textContent = 'Matches the saved record';

      const p = document.createElement('p');
      p.textContent = `This report is genuine and identical to what was recorded on the blockchain (Recorded at: ${res.recordedAt || 'Block timestamp confirmed'}).`;

      verifyResult.append(v, p);
    } else {
      verifyResult.className = 'verdict high';

      const v = document.createElement('div');
      v.className = 'v';
      v.textContent = 'Does not match: this report was changed';

      const p = document.createElement('p');
      p.textContent = 'The cryptographic fingerprint of this document does not match any confirmed record on the smart contract. The content may have been modified.';

      verifyResult.append(v, p);
    }
  } catch (err) {
    verifyResult.className = 'error-banner';
    verifyResult.textContent = 'Verification error: ' + err.message;
  } finally {
    verifyDocBtn.disabled = false;
  }
});
