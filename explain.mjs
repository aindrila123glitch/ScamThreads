// Deterministic Evidence-Grounded AI Explainer Fallback (Works zero-dependency without Ollama)

export function deterministicExplanation(result) {
  if (!result || !Array.isArray(result.evidence) || result.evidence.length === 0) {
    return 'No significant malicious indicators identified within available checks. [E1]';
  }

  const lines = [];

  for (const item of result.evidence) {
    const id = item.id;
    const f = (item.finding || '').toLowerCase();

    if (f.includes('matches genuine domain')) {
      lines.push(`Domain verified as authentic genuine asset of claimed organisation. [${id}]`);
    } else if (f.includes('exact match in configured urlhaus') || f.includes('known threat')) {
      lines.push(`Destination exactly matches active threat intelligence feed of confirmed malicious hosts. [${id}]`);
    } else if (f.includes('homoglyph')) {
      lines.push(`Domain employs deceptive homoglyph or lookalike characters to spoof legitimate brand identity. [${id}]`);
    } else if (f.includes('typosquatting')) {
      lines.push(`Hostname is a crafted typosquat variation of an established brand. [${id}]`);
    } else if (f.includes('used in subdomain or path')) {
      lines.push(`Legitimate brand name is embedded in subdomain or path of an unrelated third-party domain. [${id}]`);
    } else if (f.includes('punycode')) {
      lines.push(`Internationalized Punycode encoding detected, commonly abused for deceptive character spoofing. [${id}]`);
    } else if (f.includes('high-risk or suspicious tld')) {
      lines.push(`Website is registered under a high-risk top-level domain frequently associated with abuse. [${id}]`);
    } else if (f.includes('cross-domain redirect')) {
      lines.push(`Initial destination silently redirects visitors to an unexpected foreign domain. [${id}]`);
    } else if (f.includes('password or otp form targets a different hostname') || f.includes('password input in fetched html')) {
      lines.push(`Login authentication form transmits submitted credentials to an external destination host. [${id}]`);
    } else if (f.includes('known distrust match')) {
      lines.push(`TLS certificate chain is linked to an untrusted or compromised Certificate Authority advisory. [${id}]`);
    } else if (f.includes('expired certificate') || f.includes('validation failed')) {
      lines.push(`TLS certificate has expired or failed cryptographic chain verification. [${id}]`);
    } else if (f.includes('urgency language') || f.includes('urgency manipulation')) {
      lines.push(`Communication utilizes artificial urgency pressure to provoke hasty compliance. [${id}]`);
    } else if (f.includes('mentions sensitive credentials') || f.includes('requests sensitive credentials')) {
      lines.push(`Communication solicits secret authentication credentials, OTPs, or passwords. [${id}]`);
    } else if (f.includes('unusual payment') || f.includes('unusual or advance payment')) {
      lines.push(`Message demands irregular or advance fee transfer through unconventional payment channels. [${id}]`);
    } else if (f.includes('prize') || f.includes('lottery') || f.includes('cashback')) {
      lines.push(`Social engineering lure offering unverified lottery rewards, cash prizes, or cashback. [${id}]`);
    } else if (f.includes('fake account block') || f.includes('kyc')) {
      lines.push(`Coercive manipulation threatening impending account suspension or utility disconnection. [${id}]`);
    } else if (f.includes('remote-access software')) {
      lines.push(`Instructions solicit installation of remote screen-control tools to compromise victim device. [${id}]`);
    } else if (f.includes('isolated from the verdict engine')) {
      lines.push(`Adversarial prompt-injection instructions detected in input text and quarantined from decision logic. [${id}]`);
    } else if (f.includes('claims to be from') && f.includes('unrelated host')) {
      lines.push(`Discrepancy detected between claimed sender organisation and embedded link destination. [${id}]`);
    } else {
      // Clean fallback: capitalize first letter, strip trailing period, attach ID
      const cleaned = item.finding.trim().replace(/\.+$/, '');
      lines.push(`${cleaned}. [${id}]`);
    }
  }

  return lines.join('\n');
}

