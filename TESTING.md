# HackMatrix — Testing Report & Evaluation Benchmark

This report documents the verification results across the complete HackMatrix testing suite, including unit tests, integration tests, smart contract tests, and offline benchmark evaluations against 160 real-world benign and phishing samples.

```
Total Automated Tests: 46
Passing:               46
Failing:               0
Suites:                7 test suites (lexical, filerules, filecheck, messages, merkle, registry, scanner)
Duration:              ~5.8 seconds
```

---

## 1. Documented Suspicious Test Cases (Observed Results)

| # | Submitted Target | Observed Verdict | Key Technical Evidence | Source |
|---|---|---|---|---|
| **1** | `https://paypa1-secure-login.xyz` | **High Risk** | `Homoglyph or confusable character imitation of brand "PayPal" in domain`<br>`Domain uses high-risk or suspicious TLD (.xyz)`<br>`Multiple credential or urgency keywords in URL path` | Lexical rules |
| **2** | `https://sbi.co.in.kyc-verify.top` | **High Risk** | `Brand name "SBI" used in subdomain or path of an unrelated domain (kyc-verify.top)`<br>`Domain uses high-risk or suspicious TLD (.top)` | Lexical rules |
| **3** | `https://onlinesb1.net` | **Suspicious** | `Possible typosquatting imitation of brand "SBI" (onlinesb1 ~ onlinesbi)` | Lexical rules |
| **4** | `https://secure.sbi.co.in@185.0.2.10/otp` | **High Risk** | `URL authority contains embedded credentials or '@' sign`<br>`Direct IP address used as website host`<br>`Brand name "SBI" embedded in credential authority` | Lexical rules |
| **5** | `https://xn--gogle-pqa.com/login` | **Suspicious** | `Internationalized domain name in Punycode (xn--gogle-pqa.com)` | Lexical rules |
| **6** | `https://bit.ly/secure-login` | **Suspicious** | `Known URL shortening service (bit.ly)`<br>`Multiple credential keywords in URL path` | Lexical rules |

---

## 2. Documented Benign Test Cases (False-Positive Control)

The platform implements strict brand whitelisting and registered domain parsing to ensure legitimate websites are cleared without false alerts.

| # | Submitted Target | Observed Verdict | Observations & Whitelist Match |
|---|---|---|---|
| **1** | `https://sbi.co.in` | **Low Risk** | `[E1] Matches genuine domain of SBI` — No suspicious indicators |
| **2** | `https://www.wikipedia.org` | **Low Risk** | Clean registered domain (`wikipedia.org`) — Zero malicious findings |
| **3** | `https://github.com` | **Low Risk** | Clean registered domain (`github.com`) — Zero malicious findings |
| **4** | `https://accounts.google.com` | **Low Risk** | `[E1] Matches genuine domain of Google` — Genuine subdomain cleared |
| **5** | `https://mail.google.com` | **Low Risk** | `[E1] Matches genuine domain of Google` — Genuine service cleared |
| **6** | `https://iitd.ac.in` | **Low Risk** | Legitimate educational portal with multi-part TLD (`.ac.in`) cleared |

---

## 3. Offline Evaluation Benchmark Results (`eval/results.json`)

To evaluate detection efficacy without making live network requests, HackMatrix provides an offline evaluation harness (`npm run eval`) testing 100 well-known benign domains and 60 real-world phishing and lookalike samples:

```
======================================================
       HACKMATRIX OFFLINE EVALUATION BENCHMARK        
======================================================
Evaluated at:      2026-11-08T07:48:06.250Z
Dataset size:      160 URLs (100 benign, 60 phishing)
------------------------------------------------------
True Positives:    60  (Phishing correctly flagged)
True Negatives:    100  (Benign correctly cleared)
False Positives:   0   (Benign wrongly flagged)
False Negatives:   0   (Phishing missed)
------------------------------------------------------
Accuracy:          100.00%
Precision:         100.00%
Recall:            100.00%
F1-Score:          100.00%
======================================================
```

---

## 4. Malicious File Payload & Antivirus Inspection Tests

| Test Scenario | Input Data | Observed Verdict | Key Finding |
|---|---|---|---|
| **Standard EICAR String** | Assembly-assembled test string | **Confirmed Malicious** | Matches standard EICAR anti-malware test signature |
| **Disguised Executable** | PE/MZ header named `invoice.pdf` | **High Risk** | Filename claims document extension (.pdf) but file header is an executable |
| **Double Extension Spoof** | Script named `invoice.pdf.exe` | **High Risk** | Double extension spoofing detected (pdf.exe) |
| **Known Malware Hash** | SHA-256 matched in local list | **Confirmed Malicious** | SHA-256 matched local malware hash signature list |
| **Downloader Script** | Script with Base64 + IEX + DownloadString | **High Risk** | Multiple aggressive script downloader/obfuscation patterns |
| **Clean Document** | Plain text `readme.txt` | **Low Risk** | Plain text / script source |
| **Clean Image** | PNG image header `photo.png` | **Low Risk** | PNG Image |

---

## 5. Web3 Registry v2 & Smart Contract Verification Tests

Tested on in-process Ganache EVM provider (`registry.test.mjs`):
1. **Report Anchoring**: Anchored SHA-256 commitment, Merkle evidence root, and threat category on-chain.
2. **Community Validation**: Signer 1 and Signer 2 submitted validations; contract status transitioned from `Submitted` (0) to `Validated` (1).
3. **Sybil / Duplicate Prevention**: Attempting second validation from same address reverted with `Already acted`.
4. **Dispute Registration**: Signer 3 submitted dispute with reason hash; dispute counter incremented.
5. **Report Revision**: Original reporter successfully superseded old report with updated commitment; old report marked `Superseded` (3) linking `supersededBy`. Non-owner revision attempts rejected.
6. **Merkle Proof Verification**: Tested proofs for individual findings; tampered leaves or modified siblings reliably rejected.

