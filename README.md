# ⚡ PEER'S PHISH DETECTOR ⚡
### Lexical URL Phishing Analysis & Heuristic Risk Scorer
**Sqrock IT Solution | Alpha 2 Cybersecurity Internship — Day 03 Practical Project**  
**Author:** Md Peer Siddiqui  
**Repository:** [https://github.com/MdPeerSiddiqui/Peers-Phish-Detector](https://github.com/MdPeerSiddiqui/Peers-Phish-Detector)

---

```
  _____  ______ ______ _____  _  _____ 
 |  __ \|  ____|  ____|  __ \(_)/ ____|
 | |__) | |__  | |__  | |__) |_| (___  
 |  ___/|  __| |  __| |  _  /   \___ \ 
 | |    | |____| |____| | \ \   ____) |
 |_|    |_| |_|_|___/_| |_| |_____/ \___|\__\___|\___|\__\___/|_|   
 ⚡ PEER'S PHISH DETECTOR v1.0 — URL Anatomy & Heuristic Scorer ⚡
```

---

## 📌 1. Project Overview

During social engineering and spear phishing campaigns, attackers craft deceptive Uniform Resource Locators (URLs) to trick victims into surrendering sensitive credentials, financial data, or authorization tokens.

**PEER'S Phish Detector** is a specialized, lightweight cybersecurity audit utility developed in Python. It statically dissects the anatomy of any given URL across **8 transparent heuristic indicators**, calculates an itemized risk score (0 to 100), and assigns the URL to an explicitly defined risk tier.

> **Important Distinction:**  
> This tool conducts **lexical URL inspection** (identifying patterns, character substitutions, subdomain manipulation, protocol usage, and sensitive keywords inside the URL string itself). It operates safely without fetching the target web page, protecting the security analyst from executing drive-by malware or alerting an active threat actor.

---

## 🔬 2. The 8 Balanced Heuristic Scoring Rules

Unlike opaque "black-box" scanners, **PEER'S Phish Detector** itemizes every point awarded. Points are balanced heuristic weights chosen to reflect empirical phishing attack patterns:

| # | Heuristic Factor | Max Pts | Technical Indicator & Detection Logic |
|---|------------------|---------|--------------------------------------|
| **1** | **Unencrypted Protocol** | **+20** | Flags unencrypted `http://` connections. Legitimate modern banking and authentication portals universally mandate TLS encryption (`https://`). |
| **2** | **Raw IP Hostname** | **+35** | Identifies raw IPv4 addresses used as hostnames (e.g. `http://192.168.1.100/login`). Attackers frequently use raw IPs to bypass DNS registration records and domain reputation filters. |
| **3** | **Subdomain Abuse** | **+25** | Detects excessive label nesting (>3 domain labels) and identifies trusted brand names (e.g. `paypal`, `google`) placed in subdomain prefixes on an unrelated registered domain. |
| **4** | **Sensitive Action Keywords** | **+25** | Scans for high-urgency authentication tokens (`login`, `verify`, `account`, `banking`, `update`). Evaluates hostname presence (+20 pts) separately from path/query presence (+10 pts) to prevent over-penalizing legitimate sites like `github.com/login`. |
| **5** | **Brand Typosquatting** | **+30** | Employs visual lookalike normalization (homoglyphs) detecting substitutions like `paypa1` (digit `1` for letter `l`) or `g00gle` (digit `0` for letter `o`), plus brand lures inside URL paths on untrusted hosts (+15 pts). |
| **6** | **Suspicious TLD Extension** | **+15** | Flags high-abuse, disposable Top-Level Domains frequently utilized by automated phishing kits (e.g., `.xyz`, `.top`, `.tk`, `.ml`, `.cf`, `.gq`, `.buzz`, `.fit`). |
| **7** | **URL Shortener Masking** | **+25** | Detects redirection services (`bit.ly`, `tinyurl.com`, `t.co`, `is.gd`, `ow.ly`) that conceal the true destination hostname and infrastructure from the victim. |
| **8** | **Character Density & Length** | **+15** | Analyzes excessive hostname hyphenation (≥3 hyphens) and anomalous string length (>75 chars or hostname >40 chars), typical of auto-generated phishing kits. |

*Total score is mathematically capped at **100 points**.*

---

## 🎯 3. Defined Risk Tiers & Terminology

To maintain scientific integrity and prevent false assurance, the tool adheres to transparent threshold definitions:

| Risk Score | Assigned Tier | Meaning & User Guidance |
| :---: | :---: | :--- |
| **0 – 19** | **Low Risk** | **No suspicious lexical indicators detected.** *(Note: Does not prove or guarantee that a website is benign, as zero-day phishing pages can reside on fresh, clean domains).* |
| **20 – 49** | **Medium Risk** | **Caution advised.** Elevated risk signals detected (e.g., plain unencrypted HTTP or shortened destination URL). |
| **50 – 74** | **High Risk** | **High probability of phishing.** Multiple high-severity risk signals identified (e.g., raw IP, brand typosquatting, or high-abuse TLDs with banking keywords). |
| **75 – 100** | **Critical Risk** | **Immediate threat indicator pattern detected.** Severe composite phishing signature (e.g., unencrypted raw IP impersonating financial brands with sensitive query parameters). |

---

## 📊 4. 10-URL Empirical Benchmark Results

The tool includes a built-in empirical benchmark suite (`--test`) evaluating 10 representative URL test cases ranging from legitimate baselines to sophisticated composite phishing lures:

| # | Target URL | Expected Tier | Actual Score | Actual Tier | Result | Key Heuristics Triggered |
|:-:|:---|:---:|:---:|:---:|:---:|:---|
| **1** | `https://example.com` | Low Risk | **0 / 100** | **Low Risk** | `MATCH` | Zero indicators triggered (RFC 2606 baseline). |
| **2** | `http://example.com` | Medium Risk | **20 / 100** | **Medium Risk** | `MATCH` | Unencrypted HTTP protocol (+20 pts). |
| **3** | `http://192.168.1.100/login` | High Risk | **65 / 100** | **High Risk** | `MATCH` | Raw IP (+35), HTTP (+20), Path login keyword (+10). |
| **4** | `https://paypal.com.account-verify.security-update.evil.com/login` | High Risk | **60 / 100** | **High Risk** | `MATCH` | Subdomain abuse (+25), Host/path keywords (+25), Length (+10). |
| **5** | `https://paypa1-security.com/signin` | High Risk | **55 / 100** | **High Risk** | `MATCH` | Brand typosquatting 'paypa1' (+30), Host/path keywords (+25). |
| **6** | `https://bit.ly/secure-login-39x` | Medium Risk | **35 / 100** | **Medium Risk** | `MATCH` | URL shortener masking (+25), Path action keywords (+10). |
| **7** | `http://banking-portal-update.xyz/verify` | High Risk | **60 / 100** | **High Risk** | `MATCH` | HTTP (+20), Sensitive keywords (+25), High-abuse TLD `.xyz` (+15). |
| **8** | `https://login-verify-account-update-billing-auth-portal.com` | High Risk | **35 / 100** | **Medium Risk** | `DIVERGENT` | 6 hyphens (+10), Hostname length >40 (+10), Host keywords (+20). |
| **9** | `https://github.com/login` | Low Risk | **10 / 100** | **Low Risk** | `MATCH` | Login keyword in path only (+10). Legitimate site protected from false positive. |
| **10** | `http://192.168.1.50/paypal-update/account.php?verify=token` | Critical Risk | **80 / 100** | **Critical Risk** | `MATCH` | Raw IP (+35), HTTP (+20), Brand in path (+15), Query keywords (+10). |

### 💡 The "HTTPS Phishing Paradox" (Explaining Test Case #8 Divergence)
In test case #8, a security analyst intuitively flags the URL as *High Risk* due to aggressive credential keyword stuffing. However, the static lexical scorer awarded **35/100 (Medium Risk)** because the URL uses a valid TLS certificate (`https://`) and a standard `.com` top-level domain.

**Cybersecurity Insight:** According to the Anti-Phishing Working Group (APWG), over 80% of active phishing websites now utilize valid, free SSL/TLS certificates (e.g., Let's Encrypt). This divergence provides an essential lesson: **a green padlock icon or HTTPS scheme does not mean a website is safe.** It only guarantees the connection is encrypted, not that the recipient is trustworthy.

---

## 🚀 5. Installation & Execution Guide

### Prerequisites
- Python 3.8 or higher
- Terminal access (Linux/Kali, macOS, or Windows)

### Option A: Linux / Kali Linux
```bash
# 1. Clone the repository
git clone https://github.com/MdPeerSiddiqui/Peers-Phish-Detector.git
cd Peers-Phish-Detector

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the interactive scanner
python3 phish_detector.py

# 5. Run the 10-URL benchmark test suite
python3 phish_detector.py --test

# 6. Run automated unit tests
python3 -m unittest tests/test_phish_detector.py
```

### Option B: Windows (PowerShell / Command Prompt)
```powershell
# 1. Clone the repository
git clone https://github.com/MdPeerSiddiqui/Peers-Phish-Detector.git
cd Peers-Phish-Detector

# 2. Create and activate virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run interactive scan
python phish_detector.py

# 5. Run benchmark suite
python phish_detector.py --test

# 6. Run automated unit tests
python -m unittest tests/test_phish_detector.py
```

---

## 💻 6. Usage Examples & Output Previews

### Single URL Scan (Terminal Preview)
```
┌──────────────────────────────────────────────────────────────────────────────┐
│                     URL HEURISTIC AUDIT REPORT CARD                          │
└──────────────────────────────────────────────────────────────────────────────┘
 TARGET URL : https://paypa1-security.com/signin
 HOSTNAME   : paypa1-security.com
 RISK SCORE : [███████████░░░░░░░░░] 55 / 100
 RISK LEVEL : HIGH RISK
 VERDICT    : Significant phishing indicators detected in URL pattern.

TRIGGERED RISK INDICATORS (2 DETECTED):
  [!] Sensitive Action Keywords (+25 pts)
      --> Sensitive credential keyword(s) in hostname: security (+20 pts). Action keyword(s) in URL path/query: signin (+10 pts).
  [!] Brand Typosquatting (+30 pts)
      --> Brand lookalike / typosquatting detected targeting 'paypal' (+30 pts).
────────────────────────────────────────────────────────────────────────────────
```

---

## 📁 7. Repository Architecture

```
Peers-Phish-Detector/
├── .gitignore                      # Git exclusion rules
├── LICENSE                         # Open-source MIT license
├── README.md                       # Comprehensive project documentation
├── requirements.txt                # Python package dependencies
├── test_urls.json                  # Curated 10-URL empirical benchmark dataset
├── phish_detector.py               # Core analysis tool & CLI orchestrator
├── tests/
│   └── test_phish_detector.py      # Automated 16-point unit test suite
├── reports/
│   ├── test_results.json           # Machine-readable benchmark audit output
│   └── test_results.txt            # Plaintext benchmark audit log
└── screenshots/                    # Execution evidence captures
```

---

## 🛡️ 8. Scope, Ethics & Limitations

- **Educational & Defensive Scope:** This project was developed strictly for authorized educational training within the Sqrock IT Solution Cybersecurity Internship.
- **URL Lexical Analysis vs DOM Inspection:** This tool analyzes static URL strings. It does not inspect the HTML Document Object Model (DOM), CSS styling, JavaScript payloads, or server-side `<form action="...">` redirection endpoints.
- **Defense-in-Depth Recommendation:** In an enterprise Security Operations Center (SOC), heuristic URL scoring should be paired with dynamic sandboxing, SSL certificate age inspection, and live threat intelligence feeds (e.g., Google Safe Browsing, PhishTank, VirusTotal).

---

## 👨‍💻 Author & Internship Details

- **Intern Name:** Md Peer Siddiqui
- **Company:** Sqrock IT Solution
- **Track:** Alpha 2 Cybersecurity Internship (Social Engineering Attack Simulations Using Python)
- **Day:** Day 03 — Phishing Page Anatomy & Detection
- **License:** MIT License
