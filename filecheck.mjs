import https from 'node:https';
import http from 'node:http';
import dns from 'node:dns/promises';
import net from 'node:net';
import { normalize, publicIPv4 } from './scanner.mjs';
import { analyzeFile } from './filerules.mjs';

export async function fetchFile(inputUrl, maxBytes = 10 * 1024 * 1024) {
  let current = normalize(inputUrl);
  let redirects = 0;

  while (redirects < 4) {
    const host = current.hostname;
    if (host === 'localhost' || host.endsWith('.localhost') || !host.includes('.')) {
      throw Error('Public IPv4 targets only.');
    }

    let timer;
    const addresses = await Promise.race([
      dns.lookup(host, { all: true }),
      new Promise((_, reject) => { timer = setTimeout(() => reject(Error('DNS timeout')), 3000); })
    ]).finally(() => clearTimeout(timer));

    if (addresses.some(({ address }) => net.isIP(address) === 4 && !publicIPv4(address))) {
      throw Error('Non-public destination blocked.');
    }

    const address = addresses.find(entry => publicIPv4(entry.address))?.address;
    if (!address) throw Error('No public IPv4 destination.');

    const secure = current.protocol === 'https:';

    const result = await new Promise((resolve, reject) => {
      const chunks = [];
      let total = 0;
      let truncated = false;

      const req = (secure ? https : http).request(current, {
        agent: false,
        family: 4,
        lookup: (_h, opts, done) => opts.all ? done(null, [{ address, family: 4 }]) : done(null, address, 4)
      }, res => {
        const { statusCode, headers } = res;

        if (statusCode >= 300 && statusCode < 400 && headers.location) {
          res.destroy();
          return resolve({ redirect: new URL(headers.location, current).href });
        }

        if (statusCode !== 200) {
          res.destroy();
          return reject(Error(`Download failed with HTTP ${statusCode}`));
        }

        res.on('data', chunk => {
          total += chunk.length;
          if (total <= maxBytes) {
            chunks.push(chunk);
          } else {
            truncated = true;
            res.destroy();
            resolve({ bytes: Buffer.concat(chunks), headers, truncated, size: total });
          }
        });

        res.on('end', () => {
          resolve({ bytes: Buffer.concat(chunks), headers, truncated, size: total });
        });

        res.on('error', reject);
      });

      const deadline = setTimeout(() => req.destroy(Error('Download timeout')), 15000);
      req.on('close', () => clearTimeout(deadline));
      req.on('error', reject);
      req.end();
    });

    if (result.redirect) {
      redirects++;
      if (redirects >= 4) throw Error('Redirect limit exceeded during file download.');
      current = normalize(result.redirect);
      continue;
    }

    // Derive filename
    let name = '';
    const cd = result.headers['content-disposition'] || '';
    const match = /filename\*?=['"]?(?:UTF-8'')?([^'";\r\n]+)['"]?/i.exec(cd);
    if (match) name = match[1];
    else {
      name = current.pathname.split('/').filter(Boolean).pop() || 'downloaded-file';
    }

    return {
      bytes: result.bytes,
      name,
      truncated: result.truncated,
      size: result.size,
      headers: result.headers,
      finalUrl: current.href
    };
  }

  throw Error('Download failed to complete.');
}

export async function lookupHash(sha256, env = process.env) {
  if (!sha256) return { source: 'Cloud lookup', status: 'unavailable' };

  // VirusTotal API v3
  if (env.VT_API_KEY) {
    try {
      const res = await fetch(`https://www.virustotal.com/api/v3/files/${sha256}`, {
        headers: { 'x-apikey': env.VT_API_KEY },
        signal: AbortSignal.timeout(6000)
      });
      if (res.status === 200) {
        const body = await res.json();
        const stats = body?.data?.attributes?.last_analysis_stats || {};
        const malicious = Number(stats.malicious || 0);
        return {
          source: 'VirusTotal threat intelligence',
          status: 'completed',
          completedLookup: true,
          maliciousEngines: malicious,
          totalEngines: Object.values(stats).reduce((a, b) => a + Number(b), 0)
        };
      }
      if (res.status === 404) {
        return { source: 'VirusTotal threat intelligence', status: 'not_found', completedLookup: true, maliciousEngines: 0 };
      }
    } catch {}
  }

  // MalwareBazaar API
  if (env.ABUSECH_KEY) {
    try {
      const res = await fetch('https://mb-api.abuse.ch/api/v1/', {
        method: 'POST',
        headers: {
          'Auth-Key': env.ABUSECH_KEY,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({ query: 'get_info', hash: sha256 }),
        signal: AbortSignal.timeout(6000)
      });
      if (res.status === 200) {
        const body = await res.json();
        if (body.query_status === 'ok') {
          return {
            source: 'MalwareBazaar threat intelligence',
            status: 'completed',
            completedLookup: true,
            malwareBazaar: 'found',
            signature: body.data?.[0]?.signature || 'Malware'
          };
        }
        if (body.query_status === 'hash_not_found') {
          return { source: 'MalwareBazaar threat intelligence', status: 'not_found', completedLookup: true, malwareBazaar: 'none' };
        }
      }
    } catch {}
  }

  return { source: 'Cloud lookup', status: 'unavailable', completedLookup: false };
}

export async function inspectFile({ bytes, name, truncated = false, size = null }, known = new Set(), env = process.env) {
  let remote = null;
  const limits = [];
  const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes || []);
  const sha256 = (await import('node:crypto')).createHash('sha256').update(buf).digest('hex');

  if (truncated) {
    limits.push('Hash lookup skipped for truncated download.');
  } else {
    remote = await lookupHash(sha256, env);
  }

  const result = analyzeFile({
    bytes: buf,
    name,
    size: size ?? buf.length,
    truncated,
    known,
    remote
  });

  if (limits.length) {
    result.limits.push(...limits);
  }

  return result;
}

