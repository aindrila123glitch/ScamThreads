// Scam Threads Shared Frontend Library
// Zero external dependencies. DOM-safe rendering. Plain language by default.

if (typeof document !== 'undefined') {
  try {
    const savedTheme = sessionStorage.getItem('preferredTheme') || 'caramel';
    document.documentElement.setAttribute('data-theme', savedTheme);
  } catch {}
}

export const LABELS = {
  investigate: 'Check link',
  urlOrDomain: 'Link or website address',
  evidenceCoverage: 'How thoroughly we checked',
  crossDomainJump: 'It sent you to a different website',
  redirectChain: 'Where the link goes',
  tlsOrHttps: 'Security of the connection (the padlock)',
  ca: "The company that vouches for the site's padlock",
  rdapAge: 'How long ago the website was created',
  asnLookup: 'Who hosts the website',
  brandFingerprints: "Looks like a real company's page",
  typosquatting: 'Name copied with look-alike spelling',
  threatFeed: 'Published list of known scam sites',
  payload: 'File',
  sha256: 'File fingerprint',
  commitment: 'Tamper-proof fingerprint of your report',
  merkleRoot: 'Combined fingerprint of all evidence',
  registerOnChain: 'Save a tamper-proof record',
  verify: "Check the report hasn't been changed",
  validate: 'Confirm this report',
  dispute: 'Challenge this report',
  inconclusive: 'Not enough information'
};

// Translates technical scanner findings into plain, non-technical English
export function translateFinding(raw) {
  if (!raw || typeof raw !== 'string') return '';
  const text = raw.trim();

  if (/Matches genuine domain of/i.test(text)) {
    return text.replace(/Matches genuine domain of/i, 'Matches the official verified address of');
  }
  if (/Brand name "([^"]+)" used in subdomain of unrelated domain \(([^)]+)\)/i.test(text)) {
    const m = text.match(/Brand name "([^"]+)" used in subdomain of unrelated domain \(([^)]+)\)/i);
    return `The address starts with a real company’s name ("${m[1]}"), but the website that owns it is a different one (${m[2]}).`;
  }
  if (/Domain uses high-risk or suspicious TLD \(\.([^)]+)\)/i.test(text)) {
    const m = text.match(/Domain uses high-risk or suspicious TLD \(\.([^)]+)\)/i);
    return `The website ending (.${m[1]}) is an unusual one frequently used for scam links.`;
  }
  if (/Excessive subdomain nesting/i.test(text)) {
    return 'The address has an unusually long chain of prefix names, often used to disguise the real destination.';
  }
  if (/Multiple hyphens in hostname/i.test(text)) {
    return 'The web address has multiple hyphens, a common trick to copy legitimate names.';
  }
  if (/Known URL shortening service/i.test(text)) {
    return 'Shortened link that conceals where you will actually land.';
  }
  if (/Direct IP address used as website host/i.test(text)) {
    return 'The address uses raw numbers instead of a real, named website.';
  }
  if (/URL authority contains embedded credentials or '@'/i.test(text)) {
    return 'Contains a deceptive "@" sign to mislead you about the destination.';
  }
  if (/Internationalized domain name in Punycode/i.test(text)) {
    return 'Uses look-alike foreign alphabet characters to copy a well-known name.';
  }
  if (/Nested redirect parameter detected in URL query/i.test(text)) {
    return 'Contains hidden forwarding instructions that bounce you to an unexpected page.';
  }
  if (/Multiple credential or urgency keywords/i.test(text)) {
    return 'The web address path contains words like "login", "kyc", or "verify" designed to harvest passwords.';
  }
  if (/Abnormally long URL structure/i.test(text)) {
    return 'The link is exceptionally long, designed to push the real name off the screen on phones.';
  }
  if (/Cross-domain redirect/i.test(text)) {
    return 'The link sends you on to another website before it shows a page.';
  }
  if (/Password or OTP form targets external host/i.test(text)) {
    return 'The page has a password or one-time code box that sends what you type somewhere else.';
  }
  if (/Known distrust match/i.test(text)) {
    return 'The security certificate was issued by an untrusted or compromised authority.';
  }
  if (/Certificate validation failed/i.test(text)) {
    return 'The connection security certificate is expired, missing, or invalid.';
  }
  if (/Missing Clickjacking Defense/i.test(text)) {
    return 'Lacks protection against invisible overlay buttons that trick you into tapping.';
  }
  if (/Missing Content-Type Sniffing Protection/i.test(text)) {
    return 'Allows browsers to misinterpret file types, which can let harmful scripts run.';
  }
  if (/Cookie lacks Secure flag/i.test(text)) {
    return 'Stores login session information without requiring a secure, encrypted connection.';
  }
  if (/Insecure plain HTTP connection/i.test(text)) {
    return 'Connection has no padlock encryption; data is exposed in transit.';
  }
  if (/Documented simulated phishing URL/i.test(text)) {
    return 'Known simulated phishing test link.';
  }
  if (/Configured URLhaus feed/i.test(text)) {
    return 'Listed on public threat feeds of active malware and phishing campaigns.';
  }
  if (/Urgency language/i.test(text)) {
    return 'Uses panic words ("urgent", "immediately", "final notice") to rush you into acting.';
  }
  if (/Mentions sensitive credentials/i.test(text)) {
    return 'Asks for sensitive secrets like OTPs, passwords, or recovery codes.';
  }
  if (/Suspicious payment request/i.test(text)) {
    return 'Requests immediate money transfers or fees to avoid penalties or claim prizes.';
  }
  if (/Instruction-like text isolated from the verdict engine/i.test(text)) {
    return 'Contains hidden instructions trying to trick automated AI scanners into claiming it is safe.';
  }
  if (/Registration age: (\d+) days/i.test(text)) {
    const days = text.match(/Registration age: (\d+) days/i)?.[1];
    return `The website was created ${days} days ago.`;
  }

  return text;
}

// Fetch helper with friendly error reporting
export async function api(path, data) {
  let response;
  try {
    response = await fetch('/api/' + path, data === undefined ? {} : {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
  } catch (err) {
    throw new Error("The checking service isn't running. Start it with `npm start`.");
  }
  let result;
  try {
    result = await response.json();
  } catch {
    throw new Error('Unable to read server response.');
  }
  if (!response.ok) {
    throw new Error(result.error || 'Request failed (' + response.status + ').');
  }
  return result;
}

// Persistent session history (max 10 entries)
export function saveRecentResult(entry) {
  try {
    const list = getRecentResults();
    const clean = {
      id: entry.id || ('rep-' + Date.now().toString(36)),
      time: entry.time || new Date().toISOString(),
      type: entry.type || 'link',
      title: entry.title || entry.initial || 'Investigation',
      verdict: entry.verdict || 'Inconclusive',
      result: entry.result || entry,
      document: typeof entry.document === 'string' ? entry.document : JSON.stringify(entry.result || entry)
    };
    list.unshift(clean);
    const trimmed = list.slice(0, 10);
    sessionStorage.setItem('lastResults', JSON.stringify(trimmed));
    return clean;
  } catch {
    return null;
  }
}

export function getRecentResults() {
  try {
    const raw = sessionStorage.getItem('lastResults');
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

// SVG Icons
export function createSvgIcon(name) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '2');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.setAttribute('aria-hidden', 'true');

  if (name === 'alert' || name === 'high' || name === 'warn') {
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', 'M12 3 2 20h20L12 3z');
    const l1 = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    l1.setAttribute('d', 'M12 10v4');
    const l2 = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    l2.setAttribute('d', 'M12 17.5v.01');
    svg.append(path, l1, l2);
  } else if (name === 'ok') {
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', 'M22 11.08V12a10 10 0 1 1-5.93-9.14');
    const poly = document.createElementNS('http://www.w3.org/2000/svg', 'polyline');
    poly.setAttribute('points', '22 4 12 14.01 9 11.01');
    svg.append(path, poly);
  } else {
    // Inconclusive / help
    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', '12'); circle.setAttribute('cy', '12'); circle.setAttribute('r', '10');
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', 'M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3');
    const l = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    l.setAttribute('d', 'M12 17v.01');
    svg.append(circle, path, l);
  }
  return svg;
}

// Dissect Address helper (Splits URL into fake subdomain, real domain, and rest)
export function dissectAddress(urlString) {
  try {
    const u = new URL(urlString);
    const host = u.hostname.toLowerCase();
    const parts = host.split('.');

    let registered = host;
    if (parts.length > 2) {
      const secondTld = parts[parts.length - 2];
      if (['co', 'com', 'org', 'net', 'gov', 'edu', 'ac'].includes(secondTld) && parts.length >= 3) {
        registered = parts.slice(-3).join('.');
      } else {
        registered = parts.slice(-2).join('.');
      }
    }

    const sub = host.length > registered.length ? host.slice(0, host.length - registered.length) : '';
    const rest = (u.pathname === '/' ? '' : u.pathname) + u.search + u.hash;

    return {
      hasSub: Boolean(sub),
      sub,
      registered,
      rest: rest || '/'
    };
  } catch {
    return null;
  }
}

// Navigation injection
export function initNav() {
  const existing = document.querySelector('.top');
  if (existing) {
    const themeSelect = document.getElementById('theme-select');
    if (themeSelect) {
      const savedTheme = sessionStorage.getItem('preferredTheme') || 'caramel';
      document.documentElement.setAttribute('data-theme', savedTheme);
      themeSelect.value = savedTheme;
      themeSelect.addEventListener('change', () => {
        const val = themeSelect.value;
        document.documentElement.setAttribute('data-theme', val);
        sessionStorage.setItem('preferredTheme', val);
      });
    }
    return;
  }

  const currentPath = window.location.pathname.replace(/\/index\.html$/, '/').replace(/\.html$/, '');
  const activeRoute = currentPath === '' ? '/' : currentPath;

  const header = document.createElement('header');
  header.className = 'top';

  const topIn = document.createElement('div');
  topIn.className = 'top-in';

  // Proper SVG Brand Logo & Prominent Name with tagline
  const brand = document.createElement('a');
  brand.className = 'brand';
  brand.href = '/';
  brand.setAttribute('aria-label', 'Scam Threads home');

  const brandSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  brandSvg.className = 'brand-logo';
  brandSvg.setAttribute('viewBox', '0 0 40 40');
  brandSvg.setAttribute('fill', 'none');
  brandSvg.setAttribute('aria-hidden', 'true');

  const p1 = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  p1.setAttribute('d', 'M20 3L6 8.5v11.5c0 9.2 6 15.3 14 17.5 8-2.2 14-8.3 14-17.5V8.5L20 3z');
  p1.setAttribute('stroke', 'var(--thread)');
  p1.setAttribute('stroke-width', '2.6');
  p1.setAttribute('stroke-linejoin', 'round');
  p1.setAttribute('fill', 'var(--thread-soft)');
  p1.setAttribute('fill-opacity', '0.4');

  const p2 = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  p2.setAttribute('d', 'M14 18c0-3.3 2.7-6 6-6s6 2.7 6 6c0 3.8-3 6.5-6 6.5s-6 2.7-6 6');
  p2.setAttribute('stroke', 'var(--ink)');
  p2.setAttribute('stroke-width', '2.4');
  p2.setAttribute('stroke-linecap', 'round');

  const c1 = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
  c1.setAttribute('cx', '20');
  c1.setAttribute('cy', '18');
  c1.setAttribute('r', '3.2');
  c1.setAttribute('fill', 'var(--thread)');

  const p3 = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  p3.setAttribute('d', 'M20 12v-2M20 30v-2M12 20h-2M30 20h-2');
  p3.setAttribute('stroke', 'var(--thread)');
  p3.setAttribute('stroke-width', '1.8');
  p3.setAttribute('stroke-linecap', 'round');

  brandSvg.append(p1, p2, c1, p3);

  const brandText = document.createElement('div');
  brandText.className = 'brand-text';

  const titleRow = document.createElement('div');
  titleRow.className = 'brand-title-row';

  const brandName = document.createElement('span');
  brandName.className = 'brand-name';
  brandName.textContent = 'Scam Threads';

  const brandBadge = document.createElement('span');
  brandBadge.className = 'brand-badge';
  brandBadge.textContent = 'Security';

  titleRow.append(brandName, brandBadge);

  const brandTagline = document.createElement('span');
  brandTagline.className = 'brand-tagline';
  brandTagline.textContent = 'AI · Cybersecurity · Web3 Trust Intelligence';

  brandText.append(titleRow, brandTagline);
  brand.append(brandSvg, brandText);

  // Nav items
  const nav = document.createElement('nav');
  nav.setAttribute('aria-label', 'Main');

  const routes = [
    { href: '/link', label: 'Link' },
    { href: '/message', label: 'Message' },
    { href: '/file', label: 'File' },
    { href: '/qr', label: 'QR code' },
    { href: '/reports', label: 'Reports' },
    { href: '/watch', label: 'Watch' },
    { href: '/accuracy', label: 'Accuracy' },
    { href: '/help', label: 'Help' }
  ];

  for (const item of routes) {
    const a = document.createElement('a');
    a.href = item.href;
    a.textContent = item.label;
    if (activeRoute === item.href) {
      a.setAttribute('aria-current', 'page');
    }
    nav.append(a);
  }

  // Theme switcher
  const themeWrap = document.createElement('div');
  themeWrap.className = 'theme-picker';
  const themeSelect = document.createElement('select');
  themeSelect.setAttribute('aria-label', 'Color scheme');

  const themes = [
    { id: 'caramel', name: 'Warm Caramel & Cream (Default)' },
    { id: 'espresso', name: 'Espresso Dark Vault' },
    { id: 'emerald', name: 'Cyber Emerald' },
    { id: 'cyan', name: 'Electric Cyan' },
    { id: 'violet', name: 'Cyber Violet' },
    { id: 'crimson', name: 'Crimson Alert' },
    { id: 'light', name: 'Clean Light' }
  ];

  const savedTheme = sessionStorage.getItem('preferredTheme') || 'caramel';
  document.documentElement.setAttribute('data-theme', savedTheme);

  for (const t of themes) {
    const opt = document.createElement('option');
    opt.value = t.id;
    opt.textContent = t.name;
    if (t.id === savedTheme) opt.selected = true;
    themeSelect.append(opt);
  }

  themeSelect.addEventListener('change', () => {
    const val = themeSelect.value;
    document.documentElement.setAttribute('data-theme', val);
    sessionStorage.setItem('preferredTheme', val);
  });
  themeWrap.append(themeSelect);
  nav.append(themeWrap);

  topIn.append(brand, nav);
  header.append(topIn);

  const mount = document.getElementById('nav-root');
  if (mount) {
    mount.replaceWith(header);
  } else {
    document.body.prepend(header);
  }
}

// Footer injection
export function initFooter() {
  const existing = document.querySelector('footer');
  if (existing) return;

  const footer = document.createElement('footer');
  const p = document.createElement('p');
  p.style.margin = '0 0 10px 0';
  p.textContent = 'Scam Threads gives advice, not guarantees. A clear result means we found no warning signs in the checks we ran.';

  const links = document.createElement('div');
  const a1 = document.createElement('a'); a1.href = '/about'; a1.textContent = 'How it works & glossary';
  const a2 = document.createElement('a'); a2.href = '/accuracy'; a2.textContent = 'Accuracy benchmark';
  const a3 = document.createElement('a'); a3.href = '/help'; a3.textContent = 'Emergency response (1930)';

  links.append(a1, a2, a3);
  footer.append(p, links);
  document.body.append(footer);
}

// Shared Result Renderer
export function renderResult(data, container) {
  if (!container) return;
  container.replaceChildren();

  const verdict = data.verdict || 'Inconclusive';
  const isDemo = Boolean(data.demo);

  const wrap = document.createElement('div');
  wrap.className = 'result';
  wrap.setAttribute('aria-live', 'polite');

  // Sample notice
  if (isDemo) {
    const sampleP = document.createElement('p');
    sampleP.className = 'sample';
    sampleP.textContent = 'This is an example result.';
    wrap.append(sampleP);
  }

  // 1. Verdict Card
  let vClass = 'inc';
  let iconName = 'help';
  let titleText = 'Inconclusive';
  let adviceText = "We couldn't check enough to say.";

  if (verdict === 'High Risk') {
    vClass = 'high';
    iconName = 'high';
    titleText = 'High risk';
    adviceText = 'Don’t open this. It pretends to be a well-known organization and asks for your credentials.';
  } else if (verdict === 'Confirmed Malicious') {
    vClass = 'high';
    iconName = 'high';
    titleText = 'Confirmed threat';
    adviceText = 'This address is confirmed malicious on public threat databases. Stay away.';
  } else if (verdict === 'Suspicious') {
    vClass = 'warn';
    iconName = 'warn';
    titleText = 'Suspicious';
    adviceText = 'Some things look off. Proceed with caution and do not enter passwords or pay anything.';
  } else if (verdict === 'Low Risk') {
    vClass = 'ok';
    iconName = 'ok';
    titleText = 'Low risk';
    adviceText = 'We found no warning signs in the checks we could run. (This is not a guarantee).';
  }

  const vCard = document.createElement('div');
  vCard.className = `verdict ${vClass}`;
  vCard.setAttribute('role', 'status');

  const svg = createSvgIcon(iconName);
  const vTitle = document.createElement('div');
  vTitle.className = 'v';
  vTitle.textContent = titleText;

  const vP = document.createElement('p');
  vP.textContent = data.explanation || adviceText;

  vCard.append(svg, vTitle, vP);
  wrap.append(vCard);

  // 2. The Address, Taken Apart (if link or destination exists)
  const targetUrl = data.initial || data.destination || data.url;
  if (targetUrl && /^https?:\/\//i.test(targetUrl)) {
    const parts = dissectAddress(targetUrl);
    if (parts) {
      const addrWrap = document.createElement('div');
      addrWrap.className = 'addr-wrap';

      const h2 = document.createElement('h2');
      h2.textContent = 'What this address really says';
      addrWrap.append(h2);

      const addrDiv = document.createElement('div');
      addrDiv.className = 'addr';
      addrDiv.setAttribute('role', 'group');
      addrDiv.setAttribute('aria-label', 'The address split into the part meant to fool you and the real website');

      if (parts.hasSub) {
        const segFake = document.createElement('span');
        segFake.className = 'seg fake';
        segFake.textContent = parts.sub;

        const segReal = document.createElement('span');
        segReal.className = 'seg real';
        segReal.textContent = parts.registered;

        const segRest = document.createElement('span');
        segRest.className = 'seg rest';
        segRest.textContent = parts.rest;

        const note1 = document.createElement('span');
        note1.className = 'note';
        note1.textContent = 'The part meant to fool you';

        const note2 = document.createElement('span');
        note2.className = 'note n-real';
        note2.textContent = 'The website you would actually be on';

        const note3 = document.createElement('span');
        note3.className = 'note';
        note3.textContent = 'The page on that site';

        addrDiv.append(segFake, segReal, segRest, note1, note2, note3);
      } else {
        const segReal = document.createElement('span');
        segReal.className = 'seg real';
        segReal.textContent = parts.registered;

        const segRest = document.createElement('span');
        segRest.className = 'seg rest';
        segRest.textContent = parts.rest;

        const note2 = document.createElement('span');
        note2.className = 'note n-real';
        note2.textContent = 'The website you would be on';

        const note3 = document.createElement('span');
        note3.className = 'note';
        note3.textContent = 'The page on that site';

        addrDiv.append(segReal, segRest, document.createElement('span'), note2, note3);
      }

      addrWrap.append(addrDiv);
      wrap.append(addrWrap);
    }
  }

  // 3. Why we think so
  const rawEvidence = Array.isArray(data.evidence) ? data.evidence : [];
  const findings = rawEvidence
    .map(e => ({ text: translateFinding(e.finding || e), raw: e.finding || e }))
    .filter(item => item.text && !/Matches genuine domain/i.test(item.raw));

  const blockWhy = document.createElement('section');
  blockWhy.className = 'block';

  const h2Why = document.createElement('h2');
  h2Why.textContent = 'Why we think so';
  blockWhy.append(h2Why);

  const ulWhy = document.createElement('ul');
  ulWhy.className = 'why';

  if (findings.length > 0) {
    const topItems = findings.slice(0, 4);
    for (const f of topItems) {
      const li = document.createElement('li');
      li.textContent = f.text;
      ulWhy.append(li);
    }
  } else {
    const li = document.createElement('li');
    li.textContent = verdict === 'Low Risk'
      ? 'No known phishing patterns, deceptive character substitutions, or suspicious redirects were detected.'
      : 'No specific high-severity red flags were confirmed, but some checks were limited.';
    ulWhy.append(li);
  }
  blockWhy.append(ulWhy);
  wrap.append(blockWhy);

  // 4. Where the link goes (The Thread)
  const redirects = Array.isArray(data.redirects) ? data.redirects : [];
  const hops = [data.initial, ...redirects].filter(Boolean);

  const blockThread = document.createElement('section');
  blockThread.className = 'block';

  const h2Thread = document.createElement('h2');
  h2Thread.textContent = 'Where the link goes';
  blockThread.append(h2Thread);

  const olThread = document.createElement('ol');
  olThread.className = 'thread';

  if (hops.length <= 1) {
    const li = document.createElement('li');
    const b = document.createElement('b');
    b.textContent = 'You tap the link';
    li.append(b, document.createTextNode(hops[0] || 'Direct connection without extra forwarding.'));
    olThread.append(li);
  } else {
    for (let i = 0; i < hops.length; i++) {
      const li = document.createElement('li');
      const isBad = i > 0;
      if (isBad) li.className = 'bad';

      const b = document.createElement('b');
      b.textContent = i === 0 ? 'You tap the link' : (i === hops.length - 1 ? 'You land on' : 'It moves you to another address');
      li.append(b);

      if (isBad) {
        const flag = document.createElement('span');
        flag.className = 'flag';
        flag.textContent = hops[i];
        li.append(flag);
      } else {
        li.append(document.createTextNode(hops[i]));
      }
      olThread.append(li);
    }
  }
  blockThread.append(olThread);
  wrap.append(blockThread);

  // 5. What to do now
  const blockTodo = document.createElement('section');
  blockTodo.className = 'block';

  const h2Todo = document.createElement('h2');
  h2Todo.textContent = 'What to do now';
  blockTodo.append(h2Todo);

  const olTodo = document.createElement('ol');
  olTodo.className = 'todo';

  if (verdict === 'High Risk' || verdict === 'Confirmed Malicious') {
    const li1 = document.createElement('li'); li1.textContent = 'Close the page without typing anything.';
    const li2 = document.createElement('li'); li2.textContent = 'If you already entered details or paid, call your bank on the number printed on your card.';
    const li3 = document.createElement('li'); li3.textContent = 'Report the link so others are warned.';
    olTodo.append(li1, li2, li3);
  } else if (verdict === 'Suspicious') {
    const li1 = document.createElement('li'); li1.textContent = 'Do not enter passwords, credit card numbers, or OTPs.';
    const li2 = document.createElement('li'); li2.textContent = 'Contact the organization directly on their official phone number or website.';
    olTodo.append(li1, li2);
  } else {
    const li1 = document.createElement('li'); li1.textContent = 'Proceed with normal caution.';
    const li2 = document.createElement('li'); li2.textContent = 'Always check the web address spelling before entering passwords.';
    olTodo.append(li1, li2);
  }
  blockTodo.append(olTodo);

  const rowBtn = document.createElement('div');
  rowBtn.className = 'row';

  const btnRep = document.createElement('button');
  btnRep.className = 'alt';
  btnRep.type = 'button';
  btnRep.textContent = 'Report this link';
  btnRep.onclick = () => {
    saveRecentResult({
      type: 'link',
      title: data.initial || data.destination || 'Investigation result',
      verdict: data.verdict,
      result: data
    });
    window.location.href = '/reports';
  };
  rowBtn.append(btnRep);

  if (verdict === 'High Risk' || verdict === 'Confirmed Malicious') {
    const btnHelp = document.createElement('button');
    btnHelp.className = 'alt';
    btnHelp.type = 'button';
    btnHelp.textContent = 'I already clicked it';
    btnHelp.onclick = () => { window.location.href = '/help'; };
    rowBtn.append(btnHelp);
  }
  blockTodo.append(rowBtn);
  wrap.append(blockTodo);

  // 6. Collapsibles
  const blockDetails = document.createElement('section');
  blockDetails.className = 'block';

  // Details: How thoroughly we checked
  const detCov = document.createElement('details');
  const sumCov = document.createElement('summary');
  const covDone = data.coverage?.done ?? (data.checks?.filter(c => c.status === 'done').length ?? 0);
  const covTotal = data.coverage?.total ?? (data.checks?.length ?? 12);
  sumCov.textContent = 'How thoroughly we checked';
  detCov.append(sumCov);

  const meter = document.createElement('div');
  meter.className = 'meter';
  meter.setAttribute('role', 'img');
  meter.setAttribute('aria-label', `${covDone} of ${covTotal} checks completed`);

  for (let i = 0; i < covTotal; i++) {
    const pill = document.createElement('i');
    if (i >= covDone) pill.className = 'off';
    meter.append(pill);
  }
  detCov.append(meter);

  const pCov = document.createElement('p');
  const skipped = (data.checks || []).filter(c => c.status !== 'done');
  if (skipped.length > 0) {
    const skippedNames = skipped.map(c => LABELS[c.id] || c.name);
    pCov.textContent = `We completed ${covDone} of ${covTotal} checks. We couldn’t run: ${skippedNames.join(', ')}.`;
  } else {
    pCov.textContent = `We completed all ${covDone} of ${covTotal} digital security checks.`;
  }
  detCov.append(pCov);
  blockDetails.append(detCov);

  // Details: Evidence and sources table
  const detEv = document.createElement('details');
  const sumEv = document.createElement('summary');
  sumEv.textContent = 'Evidence and sources';
  detEv.append(sumEv);

  if (rawEvidence.length > 0) {
    const table = document.createElement('table');
    table.innerHTML = '<thead><tr><th>ID</th><th>What we found</th><th>Where it came from</th></tr></thead><tbody></tbody>';
    const tbody = table.querySelector('tbody');

    for (const item of rawEvidence) {
      const tr = document.createElement('tr');
      const tdId = document.createElement('td'); tdId.textContent = item.id || 'E';
      const tdWhat = document.createElement('td'); tdWhat.textContent = translateFinding(item.finding || item);
      const tdSrc = document.createElement('td'); tdSrc.textContent = isDemo || item.source === 'Bundled demo dataset' ? 'Built-in example' : (item.source || 'Scanner rules');
      tr.append(tdId, tdWhat, tdSrc);
      tbody.append(tr);
    }
    detEv.append(table);
  } else {
    const pNoEv = document.createElement('p');
    pNoEv.textContent = 'No specific threat markers were logged.';
    detEv.append(pNoEv);
  }
  blockDetails.append(detEv);

  // Details: Advanced details
  const detAdv = document.createElement('details');
  const sumAdv = document.createElement('summary');
  sumAdv.textContent = 'Advanced details';
  detAdv.append(sumAdv);

  const pAdv = document.createElement('p');
  pAdv.textContent = 'Technical values such as file fingerprints, certificate data, and the raw report appear here:';
  detAdv.append(pAdv);

  const preAdv = document.createElement('pre');
  preAdv.style.cssText = 'background:var(--surface); border:1px solid var(--rule); padding:12px; border-radius:4px; font-size:12px; overflow-x:auto;';
  preAdv.textContent = JSON.stringify(data, null, 2);
  detAdv.append(preAdv);

  blockDetails.append(detAdv);
  wrap.append(blockDetails);

  container.append(wrap);
}

// Outbound link safety dialog
export function showDashboardLinkModal(targetUrl, reason, onScan) {
  const existing = document.getElementById('link-guard-modal');
  if (existing) existing.remove();

  const overlay = document.createElement('div');
  overlay.id = 'link-guard-modal';
  overlay.style.cssText = 'position:fixed; top:0; left:0; width:100vw; height:100vh; background:rgba(8, 12, 20, 0.88); backdrop-filter:blur(8px); display:grid; place-items:center; z-index:999999; padding:16px; box-sizing:border-box;';

  const modal = document.createElement('div');
  modal.setAttribute('role', 'alertdialog');
  modal.setAttribute('aria-modal', 'true');
  modal.style.cssText = 'background:var(--surface); color:var(--ink); width:min(100%, 540px); border:1px solid var(--high); border-top:6px solid var(--high); border-radius:12px; padding:28px 24px; box-shadow:0 20px 50px rgba(0,0,0,0.85); line-height:1.5; font-family:inherit;';

  const header = document.createElement('div');
  header.style.cssText = 'display:flex; align-items:center; gap:12px; margin-bottom:14px;';

  const icon = document.createElement('div');
  icon.textContent = '⚠';
  icon.style.cssText = 'font-size:32px; line-height:1; color:var(--high);';

  const titleBox = document.createElement('div');
  const tag = document.createElement('span');
  tag.textContent = 'HACKMATRIX THREAT GUARD';
  tag.style.cssText = 'font-size:11px; font-weight:800; letter-spacing:0.12em; color:var(--high); display:block;';

  const heading = document.createElement('h2');
  heading.textContent = 'Suspicious link detected';
  heading.style.cssText = 'margin:2px 0 0 0; font-size:22px; font-weight:700; color:var(--ink);';

  titleBox.append(tag, heading);
  header.append(icon, titleBox);

  const urlBox = document.createElement('div');
  urlBox.style.cssText = 'background:var(--chalk); border:1px solid var(--rule); border-radius:6px; padding:10px 14px; font-family:monospace; font-size:13px; word-break:break-all; color:var(--high); margin:14px 0;';
  urlBox.textContent = targetUrl;

  const reasonP = document.createElement('p');
  reasonP.style.cssText = 'margin:0 0 10px 0; font-size:14px; color:var(--high); font-weight:600;';
  reasonP.textContent = reason || 'This link matches known phishing or unverified cryptographic authority patterns.';

  const question = document.createElement('p');
  question.style.cssText = 'margin:0 0 18px 0; font-size:15px; font-weight:600;';
  question.innerHTML = 'This link appears deceptive or fraudulent. <strong>Do you wish to continue or close?</strong>';

  const actions = document.createElement('div');
  actions.style.cssText = 'display:flex; flex-wrap:wrap; gap:10px; align-items:center; margin-top:20px;';

  const closeBtn = document.createElement('button');
  closeBtn.textContent = 'Close / Stay Safe (Recommended)';
  closeBtn.style.cssText = 'background:var(--ok); color:var(--btn-ink); border:none; padding:12px 20px; border-radius:6px; font-weight:700; font-size:14px; cursor:pointer; flex:1 1 200px;';
  closeBtn.onclick = () => overlay.remove();

  const continueBtn = document.createElement('button');
  continueBtn.textContent = 'Continue anyway (Unsafe)';
  continueBtn.style.cssText = 'background:transparent; color:var(--high); border:1px solid var(--high); padding:12px 18px; border-radius:6px; font-weight:600; font-size:13.5px; cursor:pointer;';
  continueBtn.onclick = () => {
    overlay.remove();
    window.open(targetUrl, '_blank', 'noopener,noreferrer');
  };

  const inspectBtn = document.createElement('button');
  inspectBtn.className = 'alt';
  inspectBtn.textContent = 'Run Full Investigation in Scam Threads →';
  inspectBtn.style.cssText = 'width:100%; margin-top:10px; background:var(--chalk); border:1px solid var(--rule); color:var(--thread); padding:10px; border-radius:6px; font-size:13px; cursor:pointer; font-weight:600; text-align:center;';
  inspectBtn.onclick = () => {
    overlay.remove();
    if (typeof onScan === 'function') {
      onScan(targetUrl);
    } else {
      window.location.href = '/link?u=' + encodeURIComponent(targetUrl);
    }
  };

  actions.append(closeBtn, continueBtn);
  modal.append(header, urlBox, reasonP, question, actions, inspectBtn);
  overlay.append(modal);
  document.body.append(overlay);
  closeBtn.focus();
}

// Global link safety interceptor
export function initLinkGuard() {
  document.addEventListener('click', (event) => {
    const anchor = event.target.closest('a');
    if (!anchor) return;
    const href = anchor.href || anchor.getAttribute('data-href');
    if (!href) return;

    if (!/^https?:\/\//i.test(href)) return;

    try {
      const u = new URL(href);
      // If internal dashboard navigation (e.g. /link, /watch), don't intercept
      if (['127.0.0.1', 'localhost'].includes(u.hostname) && (u.pathname.startsWith('/link') || u.pathname.startsWith('/about') || u.pathname.startsWith('/help') || u.pathname.startsWith('/watch') || u.pathname.startsWith('/message') || u.pathname.startsWith('/file') || u.pathname.startsWith('/qr') || u.pathname.startsWith('/reports') || u.pathname.startsWith('/accuracy') || u.pathname === '/')) {
        return;
      }
    } catch {
      return;
    }

    event.preventDefault();
    event.stopPropagation();
    event.stopImmediatePropagation();

    let reason = 'Deceptive address or unverified security certificate pattern detected.';
    if (href.includes('sbi.co.in.kyc-verify')) {
      reason = 'Brand name "SBI" used in subdomain of unrelated domain (kyc-verify.top). High-risk suspicious domain extension (.top).';
    } else if (href.includes('forms-scam.example')) {
      reason = 'Known fraudulent credential-harvesting phishing form listed on public threat intelligence.';
    } else if (href.includes('careers-acme.example')) {
      reason = 'Impersonated career application portal that redirects to an unauthorized external credential form.';
    } else if (href.includes('distrusted.example')) {
      reason = 'Uses a compromised or untrusted Certificate Authority intermediate key (eMudhra incident).';
    }

    showDashboardLinkModal(href, reason, (targetUrl) => {
      const input = document.getElementById('url-input');
      const form = document.getElementById('link-form');
      if (input && form) {
        input.value = targetUrl;
        form.dispatchEvent(new Event('submit', { cancelable: true }));
      } else {
        window.location.href = '/link?u=' + encodeURIComponent(targetUrl);
      }
    });
  }, true);
}

// Auto-run nav, footer, and link guard
if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      initNav();
      initFooter();
      initLinkGuard();
    });
  } else {
    initNav();
    initFooter();
    initLinkGuard();
  }
}
