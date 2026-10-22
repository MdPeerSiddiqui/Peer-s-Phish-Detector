# ⚡ PEER'S PHISH DETECTOR ⚡
### Real-World Lexical URL Threat Analyzer, Heuristic Scorer & Graphical User Interface (GUI)
**Sqrock IT Solution | Alpha 2 Cybersecurity Internship — Day 03 Practical Project**  
**Author:** Md Peer Siddiqui  
**Repository:** [https://github.com/MdPeerSiddiqui/Peer-s-Phish-Detector](https://github.com/MdPeerSiddiqui/Peer-s-Phish-Detector)

---

```text
  _____  ______ ______ _____  _  _____ 
 |  __ \|  ____|  ____|  __ \(_)/ ____|
 | |__) | |__  | |__  | |__) |_| (___  
 |  ___/|  __| |  __| |  _  /   \___ \ 
 | |    | |____| |____| | \ \   ____) |
 |_|    |_| |_|_|___/_| |_| |_____/ \___|\__\___|\___|\__\___/|_|   
 ⚡ PEER'S PHISH DETECTOR v2.0 — Real-World Engine & Graphical UI ⚡
```

---

## 📌 1. Project Overview

During social engineering and spear phishing campaigns, attackers engineer deceptive Uniform Resource Locators (URLs) to trick victims into surrendering sensitive credentials, financial data, or session cookies.

**PEER'S Phish Detector** is a full-featured, real-world cybersecurity audit utility featuring both a **modern Graphical User Interface (GUI)** and a **scriptable Command-Line Interface (CLI)**. It statically dissects the anatomy of **any given URL** across **8 transparent heuristic indicators**, executes safe non-intrusive DNS resolution, calculates an itemized risk score (0 to 100), and assigns the URL to an explicitly defined risk tier.

> **Defensive Safety Architecture:**  
> This tool conducts **lexical URL inspection** (identifying deceptive patterns, character substitutions, subdomain nesting, protocol weaknesses, and sensitive keywords inside the URL string itself) combined with non-intrusive DNS socket queries. It never executes remote HTML, CSS, JavaScript, or downloads payloads, protecting the security analyst from drive-by malware or alerting an active threat actor.

---

## 🖥️ 2. Graphical User Interface (GUI) Features

Running `python phish_detector.py` or `python gui.py` immediately launches a desktop application built with a modern dark cybersecurity theme:

- **Target URL Inspection Bar:** Analyze any live or suspicious URL, paste from clipboard with one click, or clear the buffer.
- **10-Sample Benchmark Preset Menu:** Instantly load legitimate domains, raw IP portals, PayPal subdomain spoofs, homoglyph typosquats, and disposable TLD lures.
- **Dynamic Heuristic Risk Gauge:** Real-time visual progress meter with color-coded risk badge (Emerald, Amber, Coral, Crimson).
- **URL Anatomical Dissection Card:** Deconstructs Protocol/TLS encryption status, Hostname, Subdomain labels, Path/Query parameters, and Live Resolved IP address (or NXDOMAIN warning for dead/taken-down domains).
- **Detailed Threat Breakdown Table:** Itemized findings table showing each triggered factor, points awarded, and technical rationale.
- **Action Toolbar:**
  - `📋 Copy Audit Summary`: Copies full audit breakdown to clipboard.
  - `💾 Export JSON Report`: Saves machine-readable JSON security report.
  - `📄 Generate Official PDF Report`: Compiles an executive 3-page PDF lab report.
  - `🧪 Run 10-URL Benchmark`: Executes the built-in empirical test suite inside an interactive modal.
  - `ℹ️ About & Methodology`: In-app reference of heuristic weights and false assurance safeguards.

---

## 🔬 3. The 8 Balanced Heuristic Scoring Rules

Unlike opaque "black-box" scanners, **PEER'S Phish Detector** itemizes every point awarded. Points are balanced heuristic weights chosen to reflect empirical phishing attack patterns:

| # | Heuristic Factor | Max Pts | Technical Indicator & Detection Logic |
|---|------------------|---------|--------------------------------------|
| **1** | **Unencrypted Protocol** | **+20** | Flags unencrypted `http://` connections. Legitimate modern banking and authentication portals universally mandate TLS encryption (`https://`). |
| **2** | **Raw IP Hostname** | **+35** | Identifies raw IPv4 addresses used as hostnames (e.g. `http://192.168.1.100/login`). Attackers frequently use raw IPs to bypass DNS registration records and domain reputation filters. |
| **3** | **Subdomain Abuse** | **+25** | Detects excessive label nesting (>3 domain labels) and identifies trusted brand names (e.g. `paypal`, `google`) placed in subdomain prefixes on an unrelated registered domain. |
| **4** | **Sensitive Action Keywords** | **+25** | Scans for high-urgency authentication tokens (`login`, `verify`, `account`, `banking`, `update`). Evaluates hostname presence (+20 pts) separately from path/query presence (+10 pts) to prevent over-penalizing legitimate sites like `github.com/login`. |
| **5** | **Brand Typosquatting** | **+30** | Employs visual lookalike normalization (homoglyphs) detecting substitutions like `paypa1` (digit `1` for letter `l`) or `g00gle` (digit `0` for letter `o`), plus brand lures inside URL paths on untrusted hosts (+15 pts). |
| **6** | **Suspicious TLD Extension** | **+15** | Flags high-abuse, disposable Top-Level Domains frequently utilized by automated phishing kits (e.g., `.xyz`, `.top`, `.tk`, `.ml`, `.cf`, `.gq`, `.buzz`, `.fit`, `.rest`, `.icu`). |
| **7** | **URL Shortener Masking** | **+25** | Detects redirection services (`bit.ly`, `tinyurl.com`, `t.co`, `is.gd`, `ow.ly`, `rebrand.ly`, `cutt.ly`) that conceal the true destination hostname and infrastructure from the victim. |
| **8** | **Character Density & Length** | **+15** | Analyzes excessive hostname hyphenation (≥3 hyphens) and anomalous string length (>75 chars or hostname >40 chars), typical of auto-generated phishing kits. |

*Total score is mathematically capped at **100 points**.*

---

## 🎯 4. Defined Risk Tiers & Terminology

To maintain scientific integrity and prevent false assurance, the tool adheres to transparent threshold definitions:

| Risk Score | Assigned Tier | Meaning & User Guidance |
| :---: | :---: | :--- |
| **0 – 19** | **Low Risk** | **No suspicious lexical indicators detected.** *(Note: Does not prove or guarantee that a website is benign, as zero-day phishing pages can reside on fresh, clean domains).* |
| **20 – 49** | **Medium Risk** | **Caution advised.** Elevated risk signals detected (e.g., plain unencrypted HTTP or shortened destination URL). |
| **50 – 74** | **High Risk** | **High probability of phishing.** Multiple high-severity risk signals identified (e.g., raw IP, brand typosquatting, or high-abuse TLDs with banking keywords). |
| **75 – 100** | **Critical Risk** | **Immediate threat indicator pattern detected.** Severe composite phishing signature (e.g., unencrypted raw IP impersonating financial brands with sensitive query parameters). |

---

## 📊 5. 10-URL Empirical Benchmark Results

The tool includes a built-in empirical benchmark suite (`--test`) evaluating 10 representative URL test cases:

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

**Cybersecurity Insight:** According to the Anti-Phishing Working Group (APWG), over 83% of active phishing websites now utilize valid, free SSL/TLS certificates (e.g., Let's Encrypt). This divergence demonstrates that **a green padlock icon or HTTPS scheme does not mean a website is safe.** It only guarantees the connection is encrypted, not that the recipient is trustworthy.

---

## 🚀 6. Installation & Execution Guide

### Option A: Linux / Kali Linux (GUI & CLI)
```bash
# 1. Clone the repository
git clone https://github.com/MdPeerSiddiqui/Peer-s-Phish-Detector.git
cd Peer-s-Phish-Detector

# 2. Ensure Tkinter is installed on Kali / Debian (for Graphical UI)
sudo apt update && sudo apt install -y python3-tk

# 3. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Launch the Graphical User Interface (GUI)
python3 phish_detector.py
# (Or directly run: python3 gui.py)

# 6. Run via CLI (interactive mode or direct URL scan)
python3 phish_detector.py --cli
python3 phish_detector.py https://paypa1-security-verification.xyz/login

# 7. Run the 10-URL benchmark test suite
python3 phish_detector.py --test

# 8. Run automated unit tests
python3 -m unittest tests/test_phish_detector.py
```

### Option B: Windows (PowerShell / Command Prompt)
```powershell
# 1. Clone the repository
git clone https://github.com/MdPeerSiddiqui/Peer-s-Phish-Detector.git
cd Peer-s-Phish-Detector

# 2. Create and activate virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Launch Graphical User Interface (GUI)
python phish_detector.py

# 5. Run via CLI
python phish_detector.py --cli
python phish_detector.py https://google.com

# 6. Run benchmark suite
python phish_detector.py --test

# 7. Run automated unit tests
python -m unittest tests/test_phish_detector.py
```

---

## 💻 7. CLI Output Previews

### Direct Single URL Scan
```text
----------------------------------------------------------------------------------
[TARGET URL] : https://paypa1-security-verification.xyz/login
[HOSTNAME]   : paypa1-security-verification.xyz
[RESOLVED IP]: NXDOMAIN (Domain Unregistered or Suspended)
[RISK SCORE] : 70/100  |  Tier: High Risk
[VERDICT]    : Significant phishing indicators detected in URL pattern.
----------------------------------------------------------------------------------
Heuristic Breakdown (3 rules triggered):
  [01] Sensitive Action Keywords    : +25 pts
       └── Sensitive credential keyword(s) in hostname: verification, security (+20 pts). Action keyword(s) in URL path/query: login (+10 pts).
  [02] Brand Typosquatting          : +30 pts
       └── Brand lookalike / typosquatting detected targeting 'paypal' (+30 pts).
  [03] Suspicious TLD Extension     : +15 pts
       └── High-abuse top-level domain extension detected (.xyz) (+15 pts).
==================================================================================
```

---

## 📁 8. Repository Architecture

```text
Peer-s-Phish-Detector/
├── .gitignore                      # Git exclusion rules
├── LICENSE                         # Open-source MIT license
├── README.md                       # Comprehensive documentation & benchmarks
├── requirements.txt                # Python package dependencies
├── test_urls.json                  # Curated 10-URL empirical benchmark dataset
├── phish_detector.py               # Core analysis tool & CLI / GUI auto-launcher
├── gui.py                          # Modern dark-themed Graphical User Interface
├── tests/
│   └── test_phish_detector.py      # Automated 16-point unit test suite
├── reports/
│   ├── Day03_Phishing_Detection_Report_Sqrock_MdPeerSiddiqui.pdf  # Executive audit report
│   ├── test_results.json           # Machine-readable benchmark audit output
│   └── test_results.txt            # Plaintext benchmark audit log
├── scripts/
│   └── generate_day03_pdf.py       # Script that builds the executive PDF report
└── screenshots/                    # Execution evidence captures
```

---

## 🛡️ 9. Scope, Ethics & Limitations

- **Educational & Defensive Scope:** This project was developed strictly for authorized educational training within the Sqrock IT Solution Cybersecurity Internship.
- **URL Lexical Analysis vs DOM Inspection:** This tool analyzes static URL strings and conducts safe DNS queries. It does not inspect the HTML Document Object Model (DOM), CSS styling, JavaScript payloads, or server-side `<form action="...">` redirection endpoints.
- **Defense-in-Depth Recommendation:** In an enterprise Security Operations Center (SOC), heuristic URL scoring should be paired with dynamic sandboxing, SSL certificate age inspection, and live threat intelligence feeds (e.g., Google Safe Browsing, PhishTank, VirusTotal).

---

## 👨‍💻 Author & Internship Details

- **Intern Name:** Md Peer Siddiqui
- **Company:** Sqrock IT Solution
- **Track:** Alpha 2 Cybersecurity Internship (Social Engineering Attack Simulations Using Python)
- **Day:** Day 03 — Phishing Page Anatomy & Detection
- **License:** MIT License
