// Offline Evaluation Benchmark Engine (Pure lexical/rule analysis, zero network requests)

import { readFile, writeFile } from 'node:fs/promises';
import { parseLoose, lexicalSignals } from '../lexical.mjs';
import builtInBrands from '../brands-builtin.json' with { type: 'json' };

const local = name => new URL(name, import.meta.url);

function evaluateUrlOffline(urlStr) {
  const loose = parseLoose(urlStr);
  if (!loose.url) return { verdict: 'Inconclusive', signals: ['Failed to parse'] };

  const signals = lexicalSignals(loose.url, { brands: builtInBrands });
  const suspicious = signals.filter(s => s.severity === 'med' || s.severity === 'high');
  const info = signals.filter(s => s.severity === 'info');

  const hasBrandImpersonation = suspicious.some(s =>
    s.finding.includes('typosquatting') ||
    s.finding.includes('Homoglyph') ||
    s.finding.includes('used in subdomain or path')
  );
  const hasIndependentSignal = suspicious.some(s =>
    s.finding.includes('high-risk or suspicious TLD') ||
    s.finding.includes('Direct IP') ||
    s.finding.includes('embedded credentials') ||
    s.finding.includes('Nested redirect') ||
    s.finding.includes('Multiple hyphens') ||
    s.finding.includes('Excessive subdomain')
  );

  let verdict = 'Low Risk';
  if (hasBrandImpersonation && hasIndependentSignal) {
    verdict = 'High Risk';
  } else if (suspicious.length > 0) {
    verdict = 'Suspicious';
  }

  return { verdict, signals: suspicious.map(s => s.finding), info: info.map(s => s.finding) };
}

async function runEval() {
  const benignLines = (await readFile(local('benign.txt'), 'utf8'))
    .split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith('#'));
  const phishingLines = (await readFile(local('phishing.txt'), 'utf8'))
    .split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith('#'));

  let tp = 0, fp = 0, tn = 0, fn = 0;
  const falsePositives = [];
  const falseNegatives = [];

  for (const url of benignLines) {
    const res = evaluateUrlOffline(url);
    if (res.verdict === 'Low Risk') {
      tn++;
    } else {
      fp++;
      falsePositives.push({ url, verdict: res.verdict, signals: res.signals });
    }
  }

  for (const url of phishingLines) {
    const res = evaluateUrlOffline(url);
    if (res.verdict === 'High Risk' || res.verdict === 'Suspicious' || res.verdict === 'Confirmed Malicious') {
      tp++;
    } else {
      fn++;
      falseNegatives.push({ url, verdict: res.verdict });
    }
  }

  const total = tp + tn + fp + fn;
  const precision = (tp + fp) > 0 ? (tp / (tp + fp)) : 0;
  const recall = (tp + fn) > 0 ? (tp / (tp + fn)) : 0;
  const f1 = (precision + recall) > 0 ? (2 * precision * recall / (precision + recall)) : 0;
  const accuracy = total > 0 ? ((tp + tn) / total) : 0;

  const result = {
    evaluatedAt: new Date().toISOString(),
    dataset: {
      benignSamples: benignLines.length,
      phishingSamples: phishingLines.length,
      totalSamples: total
    },
    confusionMatrix: {
      truePositives: tp,
      falsePositives: fp,
      trueNegatives: tn,
      falseNegatives: fn
    },
    metrics: {
      accuracy: Number((accuracy * 100).toFixed(2)),
      precision: Number((precision * 100).toFixed(2)),
      recall: Number((recall * 100).toFixed(2)),
      f1Score: Number((f1 * 100).toFixed(2))
    },
    falsePositives,
    falseNegatives
  };

  await writeFile(local('results.json'), JSON.stringify(result, null, 2));

  console.log('\n======================================================');
  console.log('       HACKMATRIX OFFLINE EVALUATION BENCHMARK        ');
  console.log('======================================================');
  console.log(`Evaluated at:      ${result.evaluatedAt}`);
  console.log(`Dataset size:      ${total} URLs (${benignLines.length} benign, ${phishingLines.length} phishing)`);
  console.log('------------------------------------------------------');
  console.log(`True Positives:    ${tp}  (Phishing correctly flagged)`);
  console.log(`True Negatives:    ${tn}  (Benign correctly cleared)`);
  console.log(`False Positives:   ${fp}  (Benign wrongly flagged)`);
  console.log(`False Negatives:   ${fn}  (Phishing missed)`);
  console.log('------------------------------------------------------');
  console.log(`Accuracy:          ${result.metrics.accuracy}%`);
  console.log(`Precision:         ${result.metrics.precision}%`);
  console.log(`Recall:            ${result.metrics.recall}%`);
  console.log(`F1-Score:          ${result.metrics.f1Score}%`);
  console.log('======================================================\n');

  if (falsePositives.length > 0) {
    console.log('False Positives:');
    for (const fpItem of falsePositives) {
      console.log(`  - ${fpItem.url} -> ${fpItem.verdict} (${fpItem.signals.join('; ')})`);
    }
  }

  return result;
}

runEval().catch(err => {
  console.error('Eval failed:', err);
  process.exitCode = 1;
});

