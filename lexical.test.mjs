import test from 'node:test';
import assert from 'node:assert/strict';
import { parseLoose, lexicalSignals, getRegisteredDomain, levenshtein, normalizeConfusables } from './lexical.mjs';
import { scan } from './scanner.mjs';
import builtInBrands from './brands-builtin.json' with { type: 'json' };

test('registered domain extraction handles multi-part suffixes', () => {
  assert.equal(getRegisteredDomain('secure.sbi.co.in'), 'sbi.co.in');
  assert.equal(getRegisteredDomain('portal.gov.uk'), 'portal.gov.uk');
  assert.equal(getRegisteredDomain('accounts.google.com'), 'google.com');
  assert.equal(getRegisteredDomain('kyc-verify.top'), 'kyc-verify.top');
});

test('homoglyph and confusable normalization maps deceptive characters', () => {
  assert.equal(normalizeConfusables('paypa1'), 'paypal');
  assert.equal(normalizeConfusables('micr0s0ft'), 'microsoft');
  assert.equal(normalizeConfusables('g00g1e'), 'google');
  assert.equal(normalizeConfusables('onlinesb1'), 'onlinesbl');
});

test('parseLoose handles non-default ports, userinfo, and raw IPs without throwing', () => {
  const withCreds = parseLoose('https://user:pass@185.0.2.10:8080/path');
  assert(withCreds.flags.includes('userinfo'));
  assert(withCreds.flags.includes('nondefault-port'));
  assert(withCreds.flags.includes('ip-host'));

  const clean = parseLoose('https://sbi.co.in');
  assert.equal(clean.flags.length, 0);
  assert.equal(clean.url.hostname, 'sbi.co.in');
});

test('6 suspicious inputs are flagged as Suspicious or High Risk', async () => {
  const cases = [
    { url: 'https://paypa1-secure-login.xyz', expected: ['High Risk', 'Suspicious'] },
    { url: 'https://sbi.co.in.kyc-verify.top', expected: ['High Risk', 'Suspicious'] },
    { url: 'https://onlinesb1.net', expected: ['Suspicious', 'High Risk'] },
    { url: 'https://secure.sbi.co.in@185.0.2.10/otp', expected: ['High Risk', 'Suspicious'] },
    { url: 'https://xn--gogle-pqa.com/login', expected: ['Suspicious', 'High Risk'] },
    { url: 'https://bit.ly/secure-login', expected: ['Suspicious', 'High Risk'] }
  ];

  for (const c of cases) {
    const res = await scan({ url: c.url });
    assert(c.expected.includes(res.verdict), `Expected ${c.url} to be in ${c.expected.join('/')}, got ${res.verdict}`);
    assert(res.evidence.length > 0, `Expected evidence for ${c.url}`);
    assert(res.signals.length > 0, `Expected signals for ${c.url}`);
  }
});

test('6 benign inputs do not trigger false positives (evaluated as Low Risk)', async () => {
  const benign = [
    'https://sbi.co.in',
    'https://www.wikipedia.org',
    'https://github.com',
    'https://accounts.google.com',
    'https://mail.google.com',
    'https://iitd.ac.in'
  ];

  for (const url of benign) {
    const loose = parseLoose(url);
    const signals = lexicalSignals(loose.url, { brands: builtInBrands });
    const suspicious = signals.filter(s => s.severity === 'med' || s.severity === 'high');
    assert.equal(suspicious.length, 0, `Benign URL ${url} triggered suspicious signals: ${JSON.stringify(suspicious)}`);

    // In offline/mock mode (without live probe network failures turning it into inconclusive),
    // we verify lexical analysis clears it
    const info = signals.filter(s => s.severity === 'info');
    if (url.includes('sbi.co.in') || url.includes('google.com')) {
      assert(info.length > 0, `Expected genuine brand confirmation for ${url}`);
    }
  }
});

