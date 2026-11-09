import test from 'node:test';
import assert from 'node:assert/strict';
import { auditHeadersAndHtml, scan } from './scanner.mjs';

test('coverage meter tracks 12 core checks and calculates done/total ratio', async () => {
  const res = await scan({ url: 'https://careers-acme.example/apply' });
  assert.equal(typeof res.coverage, 'object');
  assert.equal(res.coverage.total, 12);
  assert(res.coverage.done >= 6);
  assert(Array.isArray(res.checks));
  assert.equal(res.checks.length, 12);
});

test('auditHeadersAndHtml flags missing clickjacking defense, MIME sniffing and referrer policy', () => {
  const headers = {
    'server': 'Apache/2.4.41',
    'x-powered-by': 'PHP/7.4.3'
  };
  const findings = auditHeadersAndHtml(headers, '<html></html>', new URL('https://example.com/'));

  assert(findings.some(f => f.issue === 'Missing Clickjacking Defense'));
  assert(findings.some(f => f.issue === 'Missing MIME Sniffing Protection'));
  assert(findings.some(f => f.issue === 'Missing Referrer-Policy'));
  assert(findings.some(f => f.issue === 'Server Version Disclosure'));

  // Each finding must have required 6-property shape
  for (const f of findings) {
    assert(f.issue && f.evidence && f.impact && f.severity && f.fix && f.limitation);
  }
});

test('auditHeadersAndHtml detects vulnerable cookie attributes', () => {
  const headers = {
    'content-security-policy': "default-src 'self'",
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'permissions-policy': 'camera=()',
    'set-cookie': ['sessionid=xyz123; Path=/']
  };
  const findings = auditHeadersAndHtml(headers, '<html></html>', new URL('https://example.com/'));

  assert(findings.some(f => f.issue === 'Insecure Cookie'));
  assert(findings.some(f => f.issue === 'Vulnerable Cookie'));
  assert(findings.some(f => f.issue === 'Missing SameSite Cookie Protection'));
});

test('auditHeadersAndHtml flags overly permissive CORS and mixed content', () => {
  const headers = {
    'access-control-allow-origin': '*',
    'access-control-allow-credentials': 'true',
    'strict-transport-security': 'max-age=31536000'
  };
  const html = '<script src="http://cdn.example/tracker.js"></script>';
  const findings = auditHeadersAndHtml(headers, html, new URL('https://example.com/'));

  assert(findings.some(f => f.issue === 'Overly Permissive CORS Configuration' && f.severity === 'High'));
  assert(findings.some(f => f.issue === 'Mixed Active Content In HTTPS Page' && f.severity === 'Med'));
});

