// Smarter Multilingual Message Analyser & Indicator Extractor (English, Hindi, Bengali, Hinglish)

import builtInBrands from './brands-builtin.json' with { type: 'json' };

const INJECTION_REGEX = /(?:ignore|disregard) (?:all |the )?(?:previous|prior) instructions|say (?:this|it) is (?:safe|low risk)|override (?:security|system)/i;

const EXTRACTION_PATTERNS = {
  url: /https?:\/\/[^\s<>"']+|www\.[^\s<>"']+\.[a-z]{2,}/gi,
  email: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi,
  phone: /(?:\+91[\s-]?)?[6-9]\d{9}\b|\+[1-9]\d{1,14}\b/g,
  upi: /[a-zA-Z0-9._-]+@(okhdfcbank|okaxis|okicici|oksbi|paytm|ybl|ibl|axl|upi|apl|fbl|idfcbank|postbank|jupiteraxis|airtel)\b|[a-zA-Z0-9._-]+@[a-zA-Z]{3,}\b/gi,
  ifsc: /\b[A-Z]{4}0[A-Z0-9]{6}\b/g,
  crypto: /\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{38,59}|0x[a-fA-F0-9]{40})\b/g,
  amount: /(?:₹|Rs\.?|INR|\$|USD|EUR)\s*[\d,]+(?:\.\d{2})?|\b[\d,]+\s*(?:rupees|inr|dollars)\b/gi
};

const LANGUAGE_RULES = [
  // English
  [/\b(?:urgent|urgently|immediately|final notice|within \d+ hours?|action required|account suspension|24 hours? left)\b/i, 'Urgency language'],
  [/\b(?:otp|one-time password|password|pin|cvv|seed phrase|verification code|security code)\b/i, 'Mentions sensitive credentials'],
  [/\b(?:application fee|processing fee|courier charge|refundable deposit|wire transfer|gift card)\b/i, 'Unusual payment language'],
  [/\b(?:congratulations|you have won|lottery|cashback|prize money|claim bonus|reward points)\b/i, 'Prize, reward, or cashback lure'],
  [/\b(?:kyc update|pan card update|account blocked|electricity power cut|sim deactivation|eb bill)\b/i, 'Fake account block or utility disconnection threat'],
  [/\b(?:anydesk|teamviewer|rustdesk|quicksupport|screen share|zoho assist)\b/i, 'Requests installation of remote-access software'],
  [/\b(?:do not tell anyone|confidential|do not call bank|keep secret)\b/i, 'Secrecy and isolation manipulation'],
  [/\b(?:contact on telegram|whatsapp us on|dm on telegram)\b/i, 'Off-platform contact redirection'],

  // Hindi (Devanagari)
  [/तुरंत|जल्दी|अंतिम अवसर|समय समाप्त|चेतावनी/u, 'Hindi: Urgency or final notice warning'],
  [/ओटीपी|पासवर्ड|पिन|सीवीवी|कोड/u, 'Hindi: Requests sensitive authentication credentials'],
  [/केवाईसी|अकाउंट ब्लॉक|बिजली कटेगी|सिम बंद|पैन कार्ड/u, 'Hindi: Threat of account suspension or KYC deactivation'],
  [/लॉटरी|इनाम|कैशबैक|रुपये जीतें|मुफ्त/u, 'Hindi: Lottery or prize reward lure'],

  // Bengali
  [/জরুরী|অবিলম্বে|শেষ সুযোগ/u, 'Bengali: Urgency or final chance alert'],
  [/ওটিপি|পাসওয়ার্ড|পিন|কেওয়াইসি|অ্যাকাউন্ট বন্ধ/u, 'Bengali: Credential request or account freeze warning'],
  [/লটারি|পুরস্কার|টাকা জিতেছেন/u, 'Bengali: Lottery or monetary lure'],

  // Hinglish
  [/\b(?:kyc band|account band|otp batao|turant call|bijli cut|sim block|paise jeete|inaam mila|jaldi karo)\b/i, 'Hinglish: Urgency, KYC block, or OTP demand']
];

export function extractIndicators(text) {
  const input = String(text ?? '');
  const rawUrls = input.match(EXTRACTION_PATTERNS.url) ?? [];
  const cleanedUrls = rawUrls.map(u => u.replace(/[.,;:!?)'"]+$/, ''));
  const indicators = {
    urls: [...new Set(cleanedUrls)].slice(0, 10),
    emails: [...new Set(input.match(EXTRACTION_PATTERNS.email) ?? [])].slice(0, 10),
    phones: [...new Set(input.match(EXTRACTION_PATTERNS.phone) ?? [])].slice(0, 10),
    upis: [...new Set(input.match(EXTRACTION_PATTERNS.upi) ?? [])].slice(0, 10),
    ifscs: [...new Set(input.match(EXTRACTION_PATTERNS.ifsc) ?? [])].slice(0, 5),
    cryptoWallets: [...new Set(input.match(EXTRACTION_PATTERNS.crypto) ?? [])].slice(0, 5),
    amounts: [...new Set(input.match(EXTRACTION_PATTERNS.amount) ?? [])].slice(0, 5)
  };
  return indicators;
}

export function analyzeMessage(text, { brands = builtInBrands } = {}) {
  const raw = String(text ?? '').slice(0, 12000);
  const languageFindings = [];
  const technicalFindings = [];
  const limits = [];

  // Prompt Injection Detection
  let hasInjection = false;
  if (INJECTION_REGEX.test(raw)) {
    hasInjection = true;
    languageFindings.push({
      finding: 'Instruction-like text isolated from the verdict engine',
      severity: 'info',
      lane: 'language'
    });
  }

  // Language heuristics (suspicion only, never proof)
  for (const [re, label] of LANGUAGE_RULES) {
    if (re.test(raw)) {
      languageFindings.push({
        finding: label,
        severity: 'med',
        lane: 'language'
      });
    }
  }

  // Extraction
  const extracted = extractIndicators(raw);

  // Claimed Brand vs Destination Technical Mismatches
  const lower = raw.toLowerCase();
  for (const b of brands) {
    const claimsBrand = (b.tokens || []).some(t => new RegExp(`\\b${t}\\b`, 'i').test(lower)) ||
      lower.includes(b.name.toLowerCase());

    if (claimsBrand) {
      // Check extracted URLs
      for (const u of extracted.urls) {
        try {
          const parsed = new URL(/^[\w+.-]+:\/\//i.test(u) ? u : 'https://' + u);
          const host = parsed.hostname.toLowerCase();
          const isGenuine = (b.domains || []).some(d => host === d.toLowerCase() || host.endsWith('.' + d.toLowerCase()));
          if (!isGenuine) {
            technicalFindings.push({
              finding: `Message claims to be from "${b.name}", but contains link to unrelated host: ${host}`,
              severity: 'high',
              lane: 'technical'
            });
          }
        } catch {}
      }

      // Check extracted UPI handles
      for (const upi of extracted.upis) {
        const isOfficialOrg = (b.domains || []).some(d => upi.includes(d.split('.')[0]));
        if (!isOfficialOrg && (upi.includes('@ok') || upi.includes('@paytm') || upi.includes('@ybl'))) {
          technicalFindings.push({
            finding: `Message claims organisation "${b.name}" but requests payment to third-party or personal UPI handle (${upi})`,
            severity: 'high',
            lane: 'technical'
          });
        }
      }
    }
  }

  // Verdict calculation for message analysis
  // Language lane only => at most Suspicious
  // Technical lane signals => High Risk
  let verdict = 'Low Risk';
  if (technicalFindings.some(f => f.severity === 'high')) {
    verdict = 'High Risk';
  } else if (technicalFindings.length > 0 || languageFindings.some(f => f.severity === 'med')) {
    verdict = 'Suspicious';
  }

  return {
    verdict,
    hasInjection,
    extracted,
    languageFindings,
    technicalFindings,
    limits
  };
}
