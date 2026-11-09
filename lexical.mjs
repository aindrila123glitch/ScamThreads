// Pure lexical phishing and URL parsing rules (zero I/O, zero network dependencies)

const MULTI_SUFFIXES = new Set([
  'co.in', 'gov.in', 'ac.in', 'org.in', 'net.in', 'res.in', 'edu.in', 'mil.in',
  'co.uk', 'gov.uk', 'ac.uk', 'org.uk', 'ltd.uk', 'me.uk',
  'com.au', 'gov.au', 'edu.au', 'org.au', 'net.au',
  'co.nz', 'co.za', 'com.br', 'co.jp', 'com.sg', 'com.my', 'com.hk'
]);

const SUSPICIOUS_TLDS = new Set([
  'top', 'xyz', 'fit', 'work', 'click', 'buzz', 'club', 'surf', 'country',
  'stream', 'gq', 'cf', 'ml', 'ga', 'tk', 'icu', 'monster', 'rest', 'cam',
  'sbs', 'zip', 'mov', 'loan', 'racing', 'download', 'accountant', 'faith', 'live'
]);

const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'cutt.ly', 'rb.gy', 'ow.ly',
  'shorturl.at', 'rebrand.ly', 'goo.gl', 'tiny.cc', 'bc.vc'
]);

const HOMOGLYPH_MAP = {
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '8': 'b',
  'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y', 'і': 'i', 'ѕ': 's', 'ј': 'j',
  'ο': 'o', 'α': 'a', 'ν': 'v', 'ι': 'i', 'κ': 'k', 'ρ': 'p'
};

export function getRegisteredDomain(host) {
  if (!host || typeof host !== 'string') return '';
  const lower = host.toLowerCase().trim();
  const parts = lower.split('.');
  if (parts.length <= 2) return lower;
  const lastTwo = parts.slice(-2).join('.');
  if (MULTI_SUFFIXES.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

export function parseLoose(input) {
  const raw = String(input ?? '').trim();
  const flags = [];
  if (!raw) return { url: null, flags: ['empty'] };

  let candidate = raw;
  if (!/^[\w+.-]+:\/\//i.test(candidate)) {
    candidate = 'https://' + candidate;
  }

  let parsed;
  try {
    parsed = new URL(candidate);
  } catch {
    // If native URL parsing failed, try stripping unescaped characters
    try {
      parsed = new URL(encodeURI(candidate));
    } catch {
      return { url: null, flags: ['invalid-url'] };
    }
  }

  const host = parsed.hostname.toLowerCase();

  // Flags check
  if (parsed.username || parsed.password || candidate.includes('@')) {
    flags.push('userinfo');
  }
  if (parsed.port && !(parsed.protocol === 'http:' && parsed.port === '80') && !(parsed.protocol === 'https:' && parsed.port === '443')) {
    flags.push('nondefault-port');
  }
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host.startsWith('[') || /^0x[0-9a-f]+$/i.test(host)) {
    flags.push('ip-host');
  }
  if (/^\d+$/.test(host) || /^0[0-7]+$/.test(host) || /^0x[0-9a-f]+$/i.test(host)) {
    flags.push('numeric-host');
  }
  if (host.includes('xn--')) {
    flags.push('punycode');
  }
  if (/[^\x00-\x7F]/.test(raw) || /[^\x00-\x7F]/.test(host)) {
    flags.push('non-ascii');
  }

  return { url: parsed, flags };
}

export function levenshtein(a, b) {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  const row = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let prev = i - 1;
    row[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const temp = row[j];
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      row[j] = Math.min(row[j] + 1, row[j - 1] + 1, prev + cost);
      prev = temp;
    }
  }
  return row[b.length];
}

export function normalizeConfusables(str) {
  let out = '';
  const lower = str.toLowerCase();
  for (let i = 0; i < lower.length; i++) {
    if (lower.slice(i, i + 2) === 'rn') {
      out += 'm';
      i++;
      continue;
    }
    if (lower.slice(i, i + 2) === 'vv') {
      out += 'w';
      i++;
      continue;
    }
    const ch = lower[i];
    out += HOMOGLYPH_MAP[ch] ?? ch;
  }
  return out;
}

export function lexicalSignals(parsedUrl, { brands = [] } = {}) {
  if (!parsedUrl) return [];
  const signals = [];
  const host = parsedUrl.hostname.toLowerCase();
  const registered = getRegisteredDomain(host);
  const labels = host.split('.');
  const tld = labels[labels.length - 1];

  // Check if host belongs to a known brand's real domain
  let matchedGenuineBrand = null;
  for (const b of brands) {
    if (b.domains?.some(d => host === d.toLowerCase() || host.endsWith('.' + d.toLowerCase()))) {
      matchedGenuineBrand = b;
      signals.push({
        finding: `Matches genuine domain of ${b.name}`,
        severity: 'info',
        source: 'Lexical rules'
      });
      break;
    }
  }

  // TLD check
  if (SUSPICIOUS_TLDS.has(tld)) {
    signals.push({
      finding: `Domain uses high-risk or suspicious TLD (.${tld})`,
      severity: 'med',
      source: 'Lexical rules'
    });
  }

  // Subdomain nesting (5+ labels)
  if (labels.length >= 5) {
    signals.push({
      finding: `Excessive subdomain nesting (${labels.length} domain labels)`,
      severity: 'med',
      source: 'Lexical rules'
    });
  }

  // Multiple hyphens in domain/subdomains
  const hyphenCount = (host.match(/-/g) || []).length;
  if (hyphenCount >= 2) {
    signals.push({
      finding: `Multiple hyphens in hostname (${hyphenCount} hyphens)`,
      severity: 'med',
      source: 'Lexical rules'
    });
  }

  // URL shorteners
  if (SHORTENERS.has(host) || SHORTENERS.has(registered)) {
    signals.push({
      finding: `Known URL shortening service (${host})`,
      severity: 'med',
      source: 'Lexical rules'
    });
  }

  // IP address host
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host.startsWith('[')) {
    signals.push({
      finding: `Direct IP address used as website host`,
      severity: 'med',
      source: 'Lexical rules'
    });
  }

  // Userinfo / @ in authority
  if (parsedUrl.username || parsedUrl.password) {
    signals.push({
      finding: `URL authority contains embedded credentials or '@' sign`,
      severity: 'high',
      source: 'Lexical rules'
    });
  }

  // Punycode
  if (host.includes('xn--')) {
    signals.push({
      finding: `Internationalized domain name in Punycode (${host})`,
      severity: 'med',
      source: 'Lexical rules'
    });
  }

  // Nested redirect parameter
  const search = parsedUrl.search.toLowerCase();
  if (/[?&](url|redirect|dest|destination|next|target|r|link|uri)=https?%3A%2F%2F|[?&](url|redirect|dest|destination|next|target|r|link|uri)=https?:\/\//i.test(search)) {
    signals.push({
      finding: `Nested redirect parameter detected in URL query`,
      severity: 'med',
      source: 'Lexical rules'
    });
  }

  // Suspicious keywords in path or query
  const pathAndQuery = (parsedUrl.pathname + parsedUrl.search).toLowerCase();
  const keywordMatches = ['kyc', 'otp', 'signin', 'login', 'banking', 'verification', 'verify', 'password', 'wallet', 'update-account']
    .filter(kw => new RegExp(`[\\/._?&=-]${kw}[\\/._?&=-]|${kw}$`, 'i').test(pathAndQuery));
  if (keywordMatches.length >= 2) {
    signals.push({
      finding: `Multiple credential or urgency keywords in URL path (${keywordMatches.join(', ')})`,
      severity: 'med',
      source: 'Lexical rules'
    });
  }

  // Search engine check to avoid false positives on search queries
  const SEARCH_ENGINES = new Set(['google.com', 'google.co.in', 'bing.com', 'duckduckgo.com', 'yahoo.com', 'search.yahoo.com', 'yandex.com', 'baidu.com']);
  const isSearchEngine = SEARCH_ENGINES.has(registered);

  // Long URL
  if ((!isSearchEngine && parsedUrl.href.length > 200) || parsedUrl.pathname.length > 120) {
    signals.push({
      finding: `Abnormally long URL structure (${parsedUrl.href.length} characters)`,
      severity: 'med',
      source: 'Lexical rules'
    });
  }

  // Heavy percent encoding
  const percentCount = (parsedUrl.pathname.match(/%[0-9a-f]{2}/gi) || []).length;
  if (percentCount >= 4) {
    signals.push({
      finding: `Heavy percent-encoding in URL path (${percentCount} occurrences)`,
      severity: 'med',
      source: 'Lexical rules'
    });
  }

  // Brand token analysis (only if not already confirmed genuine for this exact brand)
  const registeredName = registered.split('.')[0];
  const subdomains = host.slice(0, Math.max(0, host.length - registered.length - 1));

  for (const b of brands) {
    if (matchedGenuineBrand?.name === b.name) continue;

    for (const token of b.tokens || []) {
      const normToken = token.toLowerCase();

      // 1. Brand name in subdomain or path of an unrelated registered domain
      // Note: Search engine search queries (e.g. google.com/search?q=brand) are not brand impersonation
      const inSubdomain = subdomains.includes(normToken);
      const inPath = parsedUrl.pathname.toLowerCase().includes(normToken);
      const inQuery = !isSearchEngine && parsedUrl.search.toLowerCase().includes(normToken);

      if (inSubdomain || inPath || inQuery) {
        signals.push({
          finding: `Brand name "${b.name}" used in subdomain or path of an unrelated domain (${registered})`,
          severity: 'high',
          source: 'Lexical rules'
        });
        break;
      }

      // 2. Homoglyph or confusable normalization
      const normRegistered = normalizeConfusables(registeredName);
      if (normRegistered !== registeredName && normRegistered.includes(normToken)) {
        signals.push({
          finding: `Homoglyph or confusable character imitation of brand "${b.name}" in domain`,
          severity: 'high',
          source: 'Lexical rules'
        });
        break;
      }

      // 3. Typosquatting distance check on registered domain name tokens
      // Tokenize registeredName by hyphens and numbers
      const domainTokens = registeredName.split(/[-_0-9]+/).filter(t => t.length >= 3);
      let isTypo = false;
      for (const dt of domainTokens) {
        if (dt === normToken) continue;
        const dist = levenshtein(dt, normToken);
        if (normToken.length >= 5 && normToken.length <= 7 && dist === 1) isTypo = true;
        else if (normToken.length >= 8 && dist >= 1 && dist <= 2) isTypo = true;
        if (isTypo) {
          signals.push({
            finding: `Possible typosquatting imitation of brand "${b.name}" (${dt} ~ ${normToken})`,
            severity: 'high',
            source: 'Lexical rules'
          });
          break;
        }
      }
      if (isTypo) break;
    }
  }

  return signals;
}

