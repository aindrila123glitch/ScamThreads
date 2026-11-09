import https from 'node:https';
import http from 'node:http';
import dns from 'node:dns/promises';
import net from 'node:net';
import crypto from 'node:crypto';
import {fixtures} from './fixtures.mjs';
import {brandMatches,fingerprints,infrastructure,inspectForms} from './intelligence.mjs';
import builtInBrands from './brands-builtin.json' with { type: 'json' };
import {parseLoose, lexicalSignals} from './lexical.mjs';
import {downloadSignals} from './filerules.mjs';
import {analyzeMessage} from './messages.mjs';

const SCT_OID = Buffer.from([0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x04, 0x02]);

export function matchDistrust(chain, list) {
  for (const {fingerprint} of chain) {
    const key=fingerprint.replaceAll(':','').toUpperCase();
    if (Object.hasOwn(list,key)) return list[key];
  }
  return null;
}

export function publicIPv4(ip) {
  if (net.isIP(ip) !== 4) return false;
  const [a,b,c] = ip.split('.').map(Number);
  return !(a === 0 || a === 10 || a === 127 || a >= 224 ||
    a === 100 && b >= 64 && b <= 127 || a === 169 && b === 254 ||
    a === 172 && b >= 16 && b <= 31 || a === 192 && [0,168].includes(b) ||
    a === 192 && b === 88 && c === 99 || a === 198 && [18,19,51].includes(b) ||
    a === 203 && b === 0 && c === 113);
}

export function normalize(input) {
  const value = String(input ?? '').trim();
  if (!value || value.length > 2048) throw Error('Enter a URL or domain up to 2048 characters.');
  const url = new URL(/^[\w+.-]+:\/\//.test(value) ? value : 'https://' + value);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.port)
    throw Error('Use a public HTTP(S) URL on its default port, without credentials.');
  url.hash = '';
  return url;
}

export function auditHeadersAndHtml(headers = {}, html = '', url = null) {
  const security = [];
  const secure = url?.protocol === 'https:';

  // 1. HSTS
  if (secure && !headers['strict-transport-security']) {
    security.push({
      issue: 'Missing HSTS',
      evidence: 'Strict-Transport-Security response header absent',
      impact: 'Users may be downgraded to unencrypted HTTP via SSL stripping attacks',
      severity: 'Low',
      fix: 'Configure HSTS after verifying HTTPS coverage.',
      limitation: 'Evaluates HTTP response headers only'
    });
  }

  // 2. CSP
  if (!headers['content-security-policy']) {
    security.push({
      issue: 'Missing CSP',
      evidence: 'Content-Security-Policy response header absent',
      impact: 'Absence of CSP significantly increases risk of Cross-Site Scripting (XSS) exploitation',
      severity: 'Low',
      fix: 'Deploy a tested Content Security Policy.',
      limitation: 'Evaluates HTTP response headers only'
    });
  }

  // 3. Clickjacking Defense
  const xfo = headers['x-frame-options'];
  const csp = headers['content-security-policy'] || '';
  if (!xfo && !csp.includes('frame-ancestors')) {
    security.push({
      issue: 'Missing Clickjacking Defense',
      evidence: 'Neither X-Frame-Options nor CSP frame-ancestors header present',
      impact: 'Website can be embedded in an invisible malicious iframe for UI redressing and clickjacking',
      severity: 'Med',
      fix: 'Add X-Frame-Options: DENY or Content-Security-Policy: frame-ancestors none',
      limitation: 'Evaluates HTTP response headers only'
    });
  }

  // 4. X-Content-Type-Options
  if ((headers['x-content-type-options'] || '').toLowerCase() !== 'nosniff') {
    security.push({
      issue: 'Missing MIME Sniffing Protection',
      evidence: 'X-Content-Type-Options: nosniff header absent',
      impact: 'Browser may interpret non-executable MIME types as executable scripts, facilitating XSS',
      severity: 'Low',
      fix: 'Add X-Content-Type-Options: nosniff',
      limitation: 'Evaluates HTTP response headers only'
    });
  }

  // 5. Referrer-Policy
  if (!headers['referrer-policy']) {
    security.push({
      issue: 'Missing Referrer-Policy',
      evidence: 'Referrer-Policy response header absent',
      impact: 'Sensitive URL path or query parameters may leak to third-party referrers upon navigation',
      severity: 'Low',
      fix: 'Configure Referrer-Policy: strict-origin-when-cross-origin',
      limitation: 'Evaluates HTTP response headers only'
    });
  }

  // 6. Permissions-Policy
  if (!headers['permissions-policy']) {
    security.push({
      issue: 'Missing Permissions-Policy',
      evidence: 'Permissions-Policy response header absent',
      impact: 'Page does not restrict browser hardware features like camera, microphone, or geolocation',
      severity: 'Low',
      fix: 'Deploy Permissions-Policy restricting unused browser APIs',
      limitation: 'Evaluates HTTP response headers only'
    });
  }

  // 7. Version disclosure
  for (const h of ['server', 'x-powered-by']) {
    const val = headers[h];
    if (val && /\d+\.\d+/.test(val)) {
      security.push({
        issue: 'Server Version Disclosure',
        evidence: `Header "${h}" discloses software version (${val})`,
        impact: 'Exposes exact software versions to attackers for targeted vulnerability scanning',
        severity: 'Low',
        fix: 'Remove or sanitize server banner headers',
        limitation: 'Passive header inspection only'
      });
    }
  }

  // 8. Set-Cookie flags
  const rawCookies = headers['set-cookie'];
  const cookies = Array.isArray(rawCookies) ? rawCookies : rawCookies ? [rawCookies] : [];
  for (const cookie of cookies) {
    const cookieName = cookie.split('=')[0]?.trim() || 'cookie';
    if (!/;\s*Secure/i.test(cookie) && secure) {
      security.push({
        issue: 'Insecure Cookie',
        evidence: `Cookie "${cookieName}" lacks Secure directive`,
        impact: 'Cookie may be transmitted over unencrypted HTTP connections',
        severity: 'Med',
        fix: 'Add Secure flag to all authentication cookies',
        limitation: 'Static response analysis'
      });
    }
    if (!/;\s*HttpOnly/i.test(cookie)) {
      security.push({
        issue: 'Vulnerable Cookie',
        evidence: `Cookie "${cookieName}" lacks HttpOnly directive`,
        impact: 'Cookie can be read by malicious client-side JavaScript in XSS attacks',
        severity: 'Med',
        fix: 'Add HttpOnly flag to sensitive session cookies',
        limitation: 'Static response analysis'
      });
    }
    if (!/;\s*SameSite=(?:Strict|Lax)/i.test(cookie)) {
      security.push({
        issue: 'Missing SameSite Cookie Protection',
        evidence: `Cookie "${cookieName}" lacks SameSite directive`,
        impact: 'Cookie may be sent in cross-site requests, increasing CSRF vulnerability',
        severity: 'Low',
        fix: 'Set SameSite=Lax or SameSite=Strict',
        limitation: 'Static response analysis'
      });
    }
  }

  // 9. Wildcard CORS with credentials
  if (headers['access-control-allow-origin'] === '*' && headers['access-control-allow-credentials'] === 'true') {
    security.push({
      issue: 'Overly Permissive CORS Configuration',
      evidence: 'Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true',
      impact: 'Arbitrary external websites can read authenticated user data',
      severity: 'High',
      fix: 'Do not use wildcard origin with credentials; whitelist specific trusted origins',
      limitation: 'Evaluates returned headers only'
    });
  }

  // 10. Mixed active content
  if (secure && html) {
    if (/<(?:script|link|iframe)\b[^>]*\b(?:src|href)\s*=\s*["']http:\/\//i.test(html)) {
      security.push({
        issue: 'Mixed Active Content In HTTPS Page',
        evidence: 'Insecure HTTP script/stylesheet resource referenced on HTTPS page',
        impact: 'Insecure script loads compromise entire HTTPS origin security',
        severity: 'Med',
        fix: 'Update all active resource references to HTTPS',
        limitation: 'Scanned in first 64 KiB of HTML'
      });
    }
  }

  return security;
}

async function probe(url, distrust) {
  const host = url.hostname;
  if (host === 'localhost' || host.endsWith('.localhost') || !host.includes('.')) throw Error('Public IPv4 targets only.');
  let timer;
  const addresses = await Promise.race([dns.lookup(host,{all:true}), new Promise((_,reject)=>{
    timer=setTimeout(()=>reject(Error('DNS timeout')),3000);
  })]).finally(()=>clearTimeout(timer));
  if (addresses.some(({address})=>net.isIP(address)===4 && !publicIPv4(address))) throw Error('Non-public destination blocked.');
  const address=addresses.find(entry=>publicIPv4(entry.address))?.address;
  if (!address) throw Error('No public IPv4 destination.');
  const secure=url.protocol==='https:';
  return new Promise((resolve,reject)=>{
    let tls = secure ? 'Inconclusive' : 'HTTP without TLS';
    let certificate = [];
    let certFacts = null;
    const request=(secure?https:http).request(url,{
      agent:false, family:4,
      lookup:(_host, options, done)=> options.all ? done(null,[{address,family:4}]) : done(null,address,4)
    },response=>{
      if (secure) {
        let cert=response.socket.getPeerCertificate(true);
        const seen=new Set();
        while(cert?.fingerprint256 && !seen.has(cert.fingerprint256)){
          seen.add(cert.fingerprint256);
          certificate.push({fingerprint:cert.fingerprint256, subject:cert.subject?.CN, expires:cert.valid_to, raw: cert.raw});
          cert=cert.issuerCertificate;
        }
        const match=matchDistrust(certificate,distrust);
        tls=match ? 'Known distrust match: '+match : 'Valid under scanner trust store';

        // Deep X.509 certificate inspection
        if (certificate.length > 0 && certificate[0].raw) {
          try {
            const x509 = new crypto.X509Certificate(certificate[0].raw);
            const keyDetails = x509.publicKey?.asymmetricKeyDetails || {};
            const keyType = x509.publicKey?.asymmetricKeyType || 'unknown';
            const keySize = keyDetails.modulusLength || keyDetails.namedCurve || 0;
            const from = Date.parse(x509.validFrom);
            const to = Date.parse(x509.validTo);
            const lifetimeDays = Number.isFinite(from) && Number.isFinite(to) ? Math.round((to - from) / 86400000) : null;
            const ageDays = Number.isFinite(from) ? Math.floor((Date.now() - from) / 86400000) : null;
            const hasEmbeddedSCT = certificate[0].raw.includes(SCT_OID);
            certFacts = {
              subject: x509.subject,
              issuer: x509.issuer,
              validFrom: x509.validFrom,
              validTo: x509.validTo,
              lifetimeDays,
              ageDays,
              keyType,
              keySize,
              signatureAlgorithm: x509.signatureAlgorithm || 'unknown',
              hasEmbeddedSCT
            };
          } catch {}
        }
      }
      const {headers,statusCode}=response;
      let html='';
      const chunks=[];
      response.on('error',reject);
      response.on('data',chunk=>{
        chunks.push(chunk);
        html+=chunk.toString();
        if(html.length>=65536){ resolve({headers,statusCode,tls,certificate,certFacts,address,html:html.slice(0,65536),bytes:null}); response.destroy(); }
      });
      response.on('end',()=>resolve({headers,statusCode,tls,certificate,certFacts,address,html,bytes:Buffer.concat(chunks)}));
    });
    const deadline=setTimeout(()=>request.destroy(Error('HTTP timeout')),4500);
    request.on('close',()=>clearTimeout(deadline));
    request.on('error',reject);
    request.end();
  });
}

function messageFindings(message) {
  return [
    [/\b(urgent|immediately|final notice|within \d+ hours)\b/i,'Urgency language'],
    [/\b(otp|password|seed phrase|verification code)\b/i,'Mentions sensitive credentials'],
    [/\b(application fee|processing fee|gift card|wire transfer)\b/i,'Unusual payment language']
  ].filter(([pattern])=>pattern.test(message)).map(([,label])=>label);
}

export async function scan({url, message='', distrust={}, known=new Set(),brands=[], deep=false}) {
  message=String(message).slice(0,12000);
  const mergedBrands=[...builtInBrands, ...(Array.isArray(brands) ? brands : [])];
  const msgAnalysis = message.trim() ? analyzeMessage(message, { brands: mergedBrands }) : null;
  const extracted = (msgAnalysis?.extracted?.urls?.length ? msgAnalysis.extracted.urls : [...new Set(message.match(/https?:\/\/[^\s<>"']+/gi)??[])]).slice(0, 12);
  const payment = msgAnalysis?.extracted?.upis?.[0]?.toLowerCase() ??
    message.match(/\b(?:UPI|payment ID)\s*[:=]\s*([\w.-]+@[\w.-]+)/i)?.[1]?.toLowerCase() ?? null;
  const target=url || extracted[0];
  if(!target && !message.trim()) throw Error('Provide a URL or message.');

  const redirects=[], signals=[], limits=[], tlsChecks=[];
  let security = [];
  let observed={},network={},brandEvidence=[],certFacts=null;

  if (msgAnalysis?.technicalFindings) {
    for (const tf of msgAnalysis.technicalFindings) signals.push(tf.finding);
  }

  // Track checks for Evidence-Coverage Meter
  const checks = [
    { id: 'url-parsing', name: 'URL normalization and parsing', status: 'skipped' },
    { id: 'lexical-rules', name: 'Lexical phishing and typosquat analysis', status: 'skipped' },
    { id: 'threat-feed', name: 'Known threat feed lookup', status: 'skipped' },
    { id: 'redirect-analysis', name: 'Redirect chain following', status: 'skipped' },
    { id: 'tls-validation', name: 'TLS connection validation', status: 'skipped' },
    { id: 'certificate-analysis', name: 'Certificate trust and CT verification', status: 'skipped' },
    { id: 'security-headers', name: 'HTTP security headers and cookie audit', status: 'skipped' },
    { id: 'form-analysis', name: 'Form target and credential destination inspection', status: 'skipped' },
    { id: 'brand-fingerprints', name: 'Brand visual and structure fingerprints', status: 'skipped' },
    { id: 'domain-rdap', name: 'RDAP registration age', status: 'skipped' },
    { id: 'network-asn', name: 'BGP network and ASN lookup', status: 'skipped' },
    { id: 'download-check', name: 'Payload download inspection', status: 'skipped' }
  ];
  const updateCheck = (id, status, reason = null) => {
    const c = checks.find(item => item.id === id);
    if (c) { c.status = status; if (reason) c.reason = reason; }
  };

  const loose = target ? parseLoose(target) : null;
  const initial = loose?.url?.href ?? null;
  if (loose?.url) {
    updateCheck('url-parsing', 'done');
  } else if (target) {
    updateCheck('url-parsing', 'failed', 'Invalid URL format');
  }

  const demo = initial && Object.hasOwn(fixtures,initial) ? fixtures[initial] : null;

  const lexicalResults = loose?.url ? lexicalSignals(loose.url, { brands: mergedBrands }) : [];
  if (loose?.url) updateCheck('lexical-rules', 'done');

  const suspiciousLexical = lexicalResults.filter(s => s.severity === 'med' || s.severity === 'high');
  const infoLexical = lexicalResults.filter(s => s.severity === 'info');
  for (const s of suspiciousLexical) {
    signals.push(s.finding);
  }

  let confirmed = initial ? known.has(initial) : false;
  if(confirmed) signals.push('Exact match in configured URLhaus feed');
  if (known.size > 0 || demo) {
    updateCheck('threat-feed', 'done');
  } else {
    updateCheck('threat-feed', 'skipped', 'No live threat feed loaded');
  }

  let tls='Not checked', certificates=[];

  let current = null;
  let skipFetch = false;

  if (loose?.flags.includes('userinfo')) {
    skipFetch = true;
    limits.push('Not fetched: URL contains credentials.');
  } else if (loose?.flags.includes('nondefault-port')) {
    skipFetch = true;
    limits.push('Not fetched: URL uses a non-default port.');
  } else if (loose?.flags.includes('ip-host')) {
    if (!publicIPv4(loose.url.hostname)) {
      skipFetch = true;
      limits.push('Non-public destination blocked.');
    } else {
      skipFetch = true;
      limits.push('Not fetched: Direct IP destination.');
    }
  }

  if(demo){
    signals.push(...demo.signals);
    confirmed ||= Boolean(demo.confirmed);
    tls=demo.tls;
    updateCheck('redirect-analysis', 'done');
    updateCheck('tls-validation', 'done');
    updateCheck('certificate-analysis', 'done');
    updateCheck('security-headers', 'done');
    updateCheck('form-analysis', 'done');
    updateCheck('download-check', 'done');
    if (initial==='https://distrusted.example/') {
      const fingerprint='A1'.repeat(32);
      certificates=[{fingerprint,subject:'Synthetic demo intermediate',expires:'Fixture'}];
      const advisory=matchDistrust(certificates,{[fingerprint]:'Local synthetic advisory DEMO-001'});
      tls='Known distrust match: '+advisory;
      tlsChecks.push({url:initial,status:tls,certificates});
    }
    current=new URL(demo.destination??initial);
    if(current.href!==initial) redirects.push(current.href);
  } else if(target && !skipFetch && loose?.url){
    try {
      current = normalize(target);
      for(let hop=0;hop<4;hop++){
        if(current.hostname.includes('xn--')) signals.push('Internationalized hostname in Punycode');
        if(known.has(current.href)){
          confirmed=true;
          signals.push('Exact match in configured URLhaus feed');
          limits.push('Fetching stopped at a known malicious URL.');
          break;
        }
        const result=await probe(current,distrust);
        tls=result.tls;
        certificates=result.certificate;
        certFacts=result.certFacts;
        tlsChecks.push({url:current.href,status:tls,certificates,certFacts});
        signals.push(...downloadSignals(result.headers, current.href));
        updateCheck('download-check', 'done');
        updateCheck('redirect-analysis', 'done');
        updateCheck('tls-validation', 'done');

        // Check TLS certificate depth facts
        if (certFacts) {
          updateCheck('certificate-analysis', 'done');
          if ((certFacts.keyType === 'rsa' && certFacts.keySize < 2048) || (certFacts.keyType === 'ec' && typeof certFacts.keySize === 'number' && certFacts.keySize < 256)) {
            signals.push('Inadequate public key cryptographic strength (< 2048-bit RSA / < 256-bit EC)');
          }
          if (certFacts.lifetimeDays != null && certFacts.lifetimeDays > 398) {
            signals.push(`Certificate lifetime (${certFacts.lifetimeDays} days) exceeds 398-day baseline limit`);
          }
          if (certFacts.ageDays != null && certFacts.ageDays <= 7 && suspiciousLexical.length > 0) {
            signals.push('Certificate was issued recently (within last 7 days) on a lookalike or suspicious domain');
          }
          if (!certFacts.hasEmbeddedSCT) {
            signals.push('No embedded Certificate Transparency timestamps in leaf certificate');
          }
        }

        if(result.statusCode>=300 && result.statusCode<400 && result.headers.location){
          if(hop===3){limits.push('Redirect limit reached.');break;}
          const next=normalize(new URL(result.headers.location,current).href);
          if(next.hostname!==current.hostname) signals.push('Cross-domain redirect');
          redirects.push(next.href);
          current=next;
          continue;
        }

        if(/<input\b[^>]*\btype\s*=\s*["']?password\b/i.test(result.html))
          signals.push('Password input in fetched HTML');
        signals.push(...inspectForms(result.html,current));
        updateCheck('form-analysis', 'done');

        // Full security header and cookie audit
        security = auditHeadersAndHtml(result.headers, result.html, current);
        updateCheck('security-headers', 'done');

        if(deep){
          updateCheck('brand-fingerprints', 'done');
          const iconTask=(async()=>{
            const tag=[...result.html.matchAll(/<link\b[^>]*>/gi)].map(match=>match[0])
              .find(value=>/\brel\s*=\s*["']?(?:shortcut\s+)?icon\b/i.test(value));
            const href=tag?.match(/\bhref\s*=\s*["']([^"']+)/i)?.[1]??'/favicon.ico';
            try{
              const iconURL=normalize(new URL(href,current).href);
              if(iconURL.origin!==current.origin)return null;
              const icon=await probe(iconURL,distrust);
              return icon.statusCode===200&&/^image\//i.test(icon.headers['content-type']??'')?icon.bytes:null;
            }catch{return null;}
          })();
          const [icon,details]=await Promise.all([iconTask,infrastructure(current.hostname,result.address)]);
          observed=fingerprints(result.html,icon);
          network=details;
          brandEvidence=brandMatches(current.hostname,observed,mergedBrands);
          if(!icon)limits.push('Same-origin favicon bytes unavailable.');
          if(network.days!=null) {
            updateCheck('domain-rdap', 'done');
          } else {
            updateCheck('domain-rdap', 'failed', 'Domain registration age unavailable');
            limits.push('Domain registration age unavailable.');
          }
          if (network.asn) {
            updateCheck('network-asn', 'done');
          } else {
            updateCheck('network-asn', 'failed', 'BGP ASN unavailable');
          }
        }
        break;
      }
    }catch(error){
      const certError=/CERT|SELF_SIGNED|ISSUER|LEAF_SIGNATURE/.test(error.code??'');
      tls=certError ? 'Certificate validation failed: '+error.code : 'Inconclusive';
      certificates=[];
      tlsChecks.push({url:current?.href ?? initial,status:tls,certificates});
      limits.push(String(error.message));
      updateCheck('tls-validation', certError ? 'failed' : 'skipped', error.message);
    }
  } else if (skipFetch && loose?.url) {
    current = loose.url;
    updateCheck('redirect-analysis', 'skipped', 'Network fetch skipped due to URL flags');
    updateCheck('tls-validation', 'skipped', 'Network fetch skipped');
  } else {
    limits.push('No URL submitted or extracted.');
  }

  if(!demo && !known.size) limits.push('No live threat feed loaded.');
  const messageSignals = msgAnalysis ? msgAnalysis.languageFindings.map(f => f.finding) : messageFindings(message);
  const suspiciousLanguage = messageSignals.length > 0;
  if(msgAnalysis?.hasInjection || /ignore (?:all |the )?(?:previous|prior) instructions|say (?:this|it) is safe/i.test(message)) {
    if (!messageSignals.includes('Instruction-like text isolated from the verdict engine')) {
      messageSignals.push('Instruction-like text isolated from the verdict engine');
    }
  }

  const distinct=[...new Set(signals)];
  const externalForm=distinct.some(s=>s.startsWith('Password or OTP form targets'));
  const hasBrandImpersonation = distinct.some(s =>
    s.includes('typosquatting') ||
    s.includes('Homoglyph') ||
    s.includes('used in subdomain or path') ||
    s.includes('Lookalike employer domain')
  );
  const hasIndependentSignal =
    distinct.some(s => s.includes('credential form') || s.includes('Password input')) ||
    (network.days != null && network.days <= 30) ||
    distinct.some(s => s.includes('high-risk or suspicious TLD')) ||
    distinct.includes('Cross-domain redirect') ||
    distinct.some(s => s.includes('Direct IP') || s.includes('embedded credentials')) ||
    externalForm;

  const high=(hasBrandImpersonation && hasIndependentSignal) ||
    (externalForm && (brandEvidence.length>0 || distinct.includes('Internationalized hostname in Punycode'))) ||
    (brandEvidence.length>0 && network.days!=null && network.days<=30) ||
    ['Internationalized hostname in Punycode','Cross-domain redirect','Password input in fetched HTML'].every(s=>distinct.includes(s));
  const trustIssue=/Expired|validation failed|Known distrust/.test(tls);

  const nonPublicBlocked = limits.some(l => l.includes('Non-public destination blocked'));
  const verdict = nonPublicBlocked ? 'Inconclusive' :
    confirmed ? 'Confirmed Malicious' : high ? 'High Risk' :
    distinct.length || suspiciousLanguage || trustIssue || brandEvidence.length ? 'Suspicious' :
    !initial || limits.length ? 'Inconclusive' : 'Low Risk';

  const lexicalFindingsMap = new Map(suspiciousLexical.map(s => [s.finding, s.source]));
  const evidence=[
    ...distinct.map(finding=>({
      finding,
      source:demo?'Bundled demo dataset':
        finding.includes('URLhaus')?'Configured URLhaus feed':
        finding.includes('Certificate') || finding.includes('cryptographic') ? 'TLS inspection' :
        lexicalFindingsMap.has(finding)?lexicalFindingsMap.get(finding):
        'Passive URL/HTTP scan'
    })),
    ...infoLexical.map(s=>({finding:s.finding, source:s.source})),
    ...brandEvidence,
    ...(network.days!=null?[{finding:'Registration age: '+network.days+' days',source:'RDAP'}]:[]),
    ...(trustIssue?[{finding:tls,source:demo?'Bundled demo dataset':'Remote TLS check'}]:[]),
    ...messageSignals.map(finding=>({finding,source:'Local message rules',lane:'language'}))
  ].map((item,index)=>({...item,id:'E'+(index+1)}));

  // Evidence coverage calculation
  const doneCount = checks.filter(c => c.status === 'done').length;
  const coverage = { done: doneCount, total: checks.length };

  for (const c of checks) {
    if (c.status !== 'done' && c.reason) {
      if (!limits.includes(c.reason)) limits.push(`${c.name}: ${c.reason}`);
    }
  }

  return {
    time:new Date().toISOString(),initial,destination:current?.href??null,redirects,tls,certificates,certFacts,tlsChecks,security,
    signals:distinct,messageSignals,extracted,payment,verdict,evidence,limits,observed,network,demo:Boolean(demo),
    checks,coverage,
    messageReport: msgAnalysis ? { extracted: msgAnalysis.extracted, language: msgAnalysis.languageFindings, technical: msgAnalysis.technicalFindings } : null,
    action:verdict==='Low Risk'?'Verify the sender independently before sharing sensitive information.':
      'Pause before entering credentials or paying. Verify the request using an official contact.'
  };
}
