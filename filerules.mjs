// Pure file heuristics, magic bytes, EICAR detection, and file verdicts (zero network dependencies)
import { createHash } from 'node:crypto';

// Assemble standard EICAR string at runtime to prevent local antivirus quarantining this repository
export const EICAR_STRING = ['X5O!P%', '@AP[4\\PZX54(P^)7CC)7}', '$EICAR-STANDARD-ANTIVIRUS', '-TEST-FILE!$H+H*'].join('');

const EXEC_EXTENSIONS = new Set([
  'exe', 'dll', 'scr', 'msi', 'bat', 'cmd', 'com', 'ps1', 'vbs', 'js',
  'jse', 'wsf', 'hta', 'jar', 'apk', 'lnk', 'iso', 'reg', 'cpl', 'msix'
]);

const DOC_IMAGE_EXTENSIONS = new Set([
  'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'jpg', 'jpeg', 'png', 'gif', 'bmp', 'txt', 'csv'
]);

export function magic(buf) {
  if (!buf || buf.length < 2) return { type: 'unknown', label: 'Empty or insufficient bytes' };

  // Windows PE (MZ)
  if (buf[0] === 0x4D && buf[1] === 0x5A) {
    return { type: 'exe', label: 'Windows Portable Executable (PE/MZ)' };
  }
  // Linux ELF (\x7FELF)
  if (buf.length >= 4 && buf[0] === 0x7F && buf[1] === 0x45 && buf[2] === 0x4C && buf[3] === 0x46) {
    return { type: 'exe', label: 'Linux/Unix Executable (ELF)' };
  }
  // Mach-O
  if (buf.length >= 4) {
    if ((buf[0] === 0xFE && buf[1] === 0xED && buf[2] === 0xFA && (buf[3] === 0xCE || buf[3] === 0xCF)) ||
        (buf[0] === 0xCF && buf[1] === 0xFA && buf[2] === 0xED && buf[3] === 0xFE) ||
        (buf[0] === 0xCA && buf[1] === 0xFE && buf[2] === 0xBA && buf[3] === 0xBE)) {
      return { type: 'exe', label: 'macOS Mach-O Executable / Universal Binary' };
    }
  }
  // ZIP (PK\x03\x04)
  if (buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x4B && buf[2] === 0x03 && buf[3] === 0x04) {
    return { type: 'archive', label: 'ZIP Archive' };
  }
  // PDF (%PDF-)
  if (buf.length >= 5 && buf.subarray(0, 5).toString('latin1') === '%PDF-') {
    return { type: 'document', label: 'PDF Document' };
  }
  // OLE2 (Compound Document: \xD0\xCF\x11\xE0)
  if (buf.length >= 4 && buf[0] === 0xD0 && buf[1] === 0xCF && buf[2] === 0x11 && buf[3] === 0xE0) {
    return { type: 'ole', label: 'Microsoft Compound File (OLE2)' };
  }
  // RAR (Rar!\x1a\x07)
  if (buf.length >= 6 && buf.subarray(0, 4).toString('latin1') === 'Rar!') {
    return { type: 'archive', label: 'RAR Archive' };
  }
  // 7z (7z\xBC\xAF\x27\x1C)
  if (buf.length >= 6 && buf[0] === 0x37 && buf[1] === 0x7A && buf[2] === 0xBC && buf[3] === 0xAF && buf[4] === 0x27 && buf[5] === 0x1C) {
    return { type: 'archive', label: '7-Zip Archive' };
  }
  // Windows LNK Shortcut (4C 00 00 00)
  if (buf.length >= 20 && buf[0] === 0x4C && buf[1] === 0x00 && buf[2] === 0x00 && buf[3] === 0x00 && buf[4] === 0x01 && buf[5] === 0x14 && buf[6] === 0x02) {
    return { type: 'script', label: 'Windows Shortcut (LNK)' };
  }
  // PNG (\x89PNG\r\n\x1a\n)
  if (buf.length >= 8 && buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4E && buf[3] === 0x47) {
    return { type: 'image', label: 'PNG Image' };
  }
  // JPEG (\xFF\xD8\xFF)
  if (buf.length >= 3 && buf[0] === 0xFF && buf[1] === 0xD8 && buf[2] === 0xFF) {
    return { type: 'image', label: 'JPEG Image' };
  }
  // GIF (GIF87a / GIF89a)
  if (buf.length >= 6 && (buf.subarray(0, 6).toString('latin1') === 'GIF87a' || buf.subarray(0, 6).toString('latin1') === 'GIF89a')) {
    return { type: 'image', label: 'GIF Image' };
  }
  // Shebang (#!...)
  if (buf.length >= 2 && buf[0] === 0x23 && buf[1] === 0x21) {
    return { type: 'script', label: 'Script with Shebang (#!' };
  }

  // Text vs binary heuristic
  let printable = 0;
  const sampleLen = Math.min(buf.length, 512);
  for (let i = 0; i < sampleLen; i++) {
    const b = buf[i];
    if (b === 9 || b === 10 || b === 13 || (b >= 32 && b <= 126)) printable++;
  }
  if (printable / sampleLen > 0.85) {
    return { type: 'text', label: 'Plain text / script source' };
  }

  return { type: 'unknown', label: 'Unrecognized binary format' };
}

export function entropy(buf) {
  if (!buf || buf.length === 0) return 0;
  const sample = buf.subarray(0, 1024 * 1024);
  const freq = new Uint32Array(256);
  for (let i = 0; i < sample.length; i++) {
    freq[sample[i]]++;
  }
  let ent = 0;
  const len = sample.length;
  for (let i = 0; i < 256; i++) {
    if (freq[i] > 0) {
      const p = freq[i] / len;
      ent -= p * Math.log2(p);
    }
  }
  return Number(ent.toFixed(3));
}

export function nameSignals(filename) {
  const name = String(filename ?? '').trim();
  const signals = [];
  if (!name) return signals;

  // Right-to-left override character
  if (/[\u202A-\u202E\u2066-\u2069]/.test(name)) {
    signals.push({
      finding: 'Filename uses Right-to-Left Override (RTLO) deceptive characters',
      severity: 'high',
      source: 'Filename analysis'
    });
  }

  // Long run of spaces before extension (e.g. "invoice      .exe")
  if (/\s{5,}\.[a-z0-9]+$/i.test(name)) {
    signals.push({
      finding: 'Deceptive whitespace padding before filename extension',
      severity: 'high',
      source: 'Filename analysis'
    });
  }

  // Double extension (e.g. invoice.pdf.exe)
  const parts = name.split('.').filter(Boolean);
  if (parts.length >= 3) {
    const penultimate = parts[parts.length - 2].toLowerCase();
    const finalExt = parts[parts.length - 1].toLowerCase();
    if (DOC_IMAGE_EXTENSIONS.has(penultimate) && EXEC_EXTENSIONS.has(finalExt)) {
      signals.push({
        finding: `Double extension spoofing detected (${penultimate}.${finalExt})`,
        severity: 'high',
        source: 'Filename analysis'
      });
    }
  }

  // Executable / script extension
  const ext = parts[parts.length - 1]?.toLowerCase();
  if (EXEC_EXTENSIONS.has(ext)) {
    signals.push({
      finding: `Executable or script extension (.${ext})`,
      severity: 'med',
      source: 'Filename analysis'
    });
  }

  return signals;
}

export function peSignals(buf) {
  const signals = [];
  if (!buf || buf.length < 512 || buf[0] !== 0x4D || buf[1] !== 0x5A) return signals;

  const sample = buf.subarray(0, 1024 * 1024).toString('latin1');

  // UPX Section markers
  if (sample.includes('UPX0') || sample.includes('UPX1') || sample.includes('UPX!')) {
    signals.push({
      finding: 'UPX packer section markers detected in PE binary',
      severity: 'med',
      source: 'PE static analysis'
    });
  }

  // Process injection APIs
  const apis = ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'SetWindowsHookEx', 'QueueUserAPC', 'NtMapViewOfSection'];
  const matchedApis = apis.filter(api => sample.includes(api));
  if (matchedApis.length >= 3) {
    signals.push({
      finding: `Multiple process injection Win32 API references detected (${matchedApis.join(', ')})`,
      severity: 'med',
      source: 'PE static analysis'
    });
  }

  return signals;
}

export function scriptSignals(buf) {
  const signals = [];
  if (!buf || buf.length === 0) return signals;

  const text = buf.subarray(0, 200 * 1024).toString('latin1');
  const patterns = [
    [/FromBase64String/i, 'FromBase64String decoding'],
    [/-(?:EncodedCommand|e|enc)\b/i, 'PowerShell encoded command execution'],
    [/\b(?:Invoke-Expression|iex)\b/i, 'Invoke-Expression (IEX) dynamic execution'],
    [/\b(?:DownloadString|DownloadFile)\b/i, 'Remote payload download call'],
    [/WScript\.Shell/i, 'WScript.Shell object creation'],
    [/powershell.*-(?:windowstyle\s+hidden|w\s+hidden)/i, 'Hidden-window PowerShell execution'],
    [/\beval\s*\(/i, 'Dynamic eval() script execution'],
    [/(?:String\.fromCharCode\s*\([^)]*\)){3,}/i, 'Obfuscated fromCharCode sequence'],
    [/cmd\.exe\s+\/c/i, 'Child command prompt invocation'],
    [/certutil.*-decode/i, 'CertUtil payload decoding']
  ];

  let patternHits = 0;
  const hitLabels = [];
  for (const [re, label] of patterns) {
    if (re.test(text)) {
      patternHits++;
      hitLabels.push(label);
    }
  }

  if (patternHits >= 4) {
    signals.push({
      finding: `Multiple aggressive script downloader/obfuscation patterns (${hitLabels.slice(0, 4).join(', ')})`,
      severity: 'high',
      source: 'Script static analysis'
    });
  } else if (patternHits >= 2) {
    signals.push({
      finding: `Suspicious script automation patterns (${hitLabels.slice(0, 3).join(', ')})`,
      severity: 'med',
      source: 'Script static analysis'
    });
  }

  return signals;
}

export function downloadSignals(headers = {}, urlStr = '') {
  const cd = headers['content-disposition'] || '';
  const ct = (headers['content-type'] || '').toLowerCase();
  let filename = '';
  const cdMatch = /filename\*?=['"]?(?:UTF-8'')?([^'";\r\n]+)['"]?/i.exec(cd);
  if (cdMatch) filename = cdMatch[1];
  else {
    try {
      filename = new URL(urlStr).pathname.split('/').filter(Boolean).pop() ?? '';
    } catch {}
  }

  const ext = filename.split('.').pop()?.toLowerCase() ?? '';
  const execMimes = [
    'application/x-msdownload', 'application/x-dosexec',
    'application/vnd.microsoft.portable-executable',
    'application/x-msi', 'application/java-archive',
    'application/vnd.android.package-archive'
  ];

  if (EXEC_EXTENSIONS.has(ext) || execMimes.some(m => ct.includes(m))) {
    return ['Link delivers an executable or script download'];
  }
  return [];
}

export function analyzeFile({ bytes, name = '', size = null, truncated = false, known = new Set(), remote = null } = {}) {
  const limits = [];
  const findings = [];
  const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes || []);
  const actualSize = size ?? buf.length;
  const sha256 = createHash('sha256').update(buf).digest('hex');

  // EICAR check
  let isEicar = false;
  if (buf.length <= 128 && buf.toString('latin1').includes(EICAR_STRING)) {
    isEicar = true;
    findings.push({
      finding: 'Matches standard EICAR anti-malware test signature',
      severity: 'high',
      source: 'Signature match'
    });
  }

  // Local signature list
  let isKnownMalware = false;
  if (known && known.has(sha256)) {
    isKnownMalware = true;
    findings.push({
      finding: `SHA-256 matched local malware hash signature list (${sha256.slice(0, 16)}…)`,
      severity: 'high',
      source: 'Signature match'
    });
  }

  // Magic & type
  const detected = magic(buf);
  const ent = entropy(buf);

  if (detected.type === 'exe' && ent >= 7.2) {
    findings.push({
      finding: `High Shannon entropy (${ent}/8.0) indicating packed or compressed executable`,
      severity: 'info',
      source: 'File static analysis'
    });
  }

  // Name signals
  const nameRes = nameSignals(name);
  findings.push(...nameRes);

  // Mismatch: claims doc/image but byte header is an executable
  const ext = name.split('.').pop()?.toLowerCase();
  if (DOC_IMAGE_EXTENSIONS.has(ext) && detected.type === 'exe') {
    findings.push({
      finding: `Filename claims document/image extension (.${ext}) but file header is an executable (${detected.label})`,
      severity: 'high',
      source: 'File static analysis'
    });
  }

  // PE & script signals
  if (detected.type === 'exe') {
    findings.push(...peSignals(buf));
  }
  if (detected.type === 'script' || detected.type === 'text' || EXEC_EXTENSIONS.has(ext)) {
    findings.push(...scriptSignals(buf));
  }

  // Remote cloud lookups
  let remoteConfirmed = false;
  let remoteSuspicious = false;
  if (remote) {
    if (remote.source) {
      if (remote.status === 'unavailable') {
        limits.push('Cloud hash intelligence service unavailable or unconfigured.');
      } else if (remote.maliciousEngines != null) {
        if (remote.maliciousEngines >= 5) {
          remoteConfirmed = true;
          findings.push({
            finding: `VirusTotal multi-engine consensus: ${remote.maliciousEngines} engines flagged as malicious`,
            severity: 'high',
            source: 'VirusTotal threat intelligence'
          });
        } else if (remote.maliciousEngines >= 1) {
          remoteSuspicious = true;
          findings.push({
            finding: `VirusTotal multi-engine alert: ${remote.maliciousEngines} engine(s) flagged as suspicious`,
            severity: 'med',
            source: 'VirusTotal threat intelligence'
          });
        }
      } else if (remote.malwareBazaar === 'found') {
        remoteConfirmed = true;
        findings.push({
          finding: `MalwareBazaar database positive match: signature "${remote.signature || 'Malware'}"`,
          severity: 'high',
          source: 'MalwareBazaar threat intelligence'
        });
      }
    }
  }

  if (truncated) {
    limits.push('File download capped at maximum buffer size; static analysis performed on truncated bytes.');
  }

  // Verdict calculation
  const highCount = findings.filter(f => f.severity === 'high').length;
  const medCount = findings.filter(f => f.severity === 'med').length;

  let verdict = 'Low Risk';
  if (isEicar || isKnownMalware || remoteConfirmed) {
    verdict = 'Confirmed Malicious';
  } else if (highCount >= 1 || medCount >= 3) {
    verdict = 'High Risk';
  } else if (medCount >= 1 || remoteSuspicious) {
    verdict = 'Suspicious';
  } else if (truncated || (['exe', 'script', 'archive', 'ole', 'unknown'].includes(detected.type) && !remote?.completedLookup)) {
    verdict = 'Inconclusive';
  }

  const evidence = findings.map((item, index) => ({
    ...item,
    id: 'F' + (index + 1)
  }));

  const action = verdict === 'Confirmed Malicious' || verdict === 'High Risk'
    ? 'Delete or quarantine this file immediately. Do not execute or permit scripts to run.'
    : verdict === 'Suspicious'
    ? 'Exercise caution. Verify file source and compute signatures before opening.'
    : verdict === 'Inconclusive'
    ? 'File analysis inconclusive. Inspect hash in an isolated sandbox.'
    : 'No malicious indicators detected within the available static file heuristics.';

  return {
    sha256,
    name,
    size: actualSize,
    type: detected.type,
    label: detected.label,
    entropy: ent,
    truncated,
    verdict,
    evidence,
    limits,
    action
  };
}

