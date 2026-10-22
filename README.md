# 🐾 PEER'S PHISH DETECTOR 🎀
### Pink Claymorphism Edition &bull; Real-World Lexical URL Threat Analyzer & Heuristic Scorer

<p align="center">
  <img src="https://img.shields.io/badge/Release-v1.0%20Official-f43f5e?style=for-the-badge&logo=heart&logoColor=white" alt="Release" />
  <img src="https://img.shields.io/badge/Theme-Pink%20Claymorphism-ec4899?style=for-the-badge" alt="Theme" />
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/Framework-Flask%20%7C%20REST%20API-000000?style=for-the-badge&logo=flask&logoColor=white" alt="Flask" />
  <img src="https://img.shields.io/badge/Track-Sqrock%20Cybersecurity-0284c7?style=for-the-badge" alt="Sqrock" />
  <img src="https://img.shields.io/badge/License-MIT-10b981?style=for-the-badge" alt="License" />
</p>

---

## 📌 1. Executive Summary

During spear-phishing and social engineering operations, adversaries engineer deceptive Uniform Resource Locators (URLs) to hijack sessions, impersonate financial institutions, and harvest credentials.

**PEER'S Phish Detector (v1.0 Official Release)** combines enterprise-grade lexical threat analysis with a **Cute Pink Claymorphism Web Dashboard** (Hello Kitty inspired aesthetic) and an interactive **CLI utility**. It statically dissects the anatomical components of **any target URL** across **8 balanced heuristic threat vectors**, performs safe non-intrusive DNS resolution, calculates an itemized risk score (0 to 100), and classifies threats into standardized operational risk tiers.

> **Defensive Architecture:**  
> The engine performs pure **lexical string dissection** and non-intrusive socket-level DNS queries without executing remote web page content, JavaScript, or downloading payloads. This eliminates drive-by malware execution risks and prevents alerting active threat actors during security investigations.

---

## 🎀 2. Pink Claymorphism Web Dashboard Features

Running `python app.py` or `python phish_detector.py` immediately spins up a local web application and opens a pastel pink 3D claymorphism dashboard in your default browser:

- **Target URL Inspection Bar:** Analyze any arbitrary public or internal URL, paste from clipboard with a single click, or clear the buffer.
- **Preset Test Samples:** Rapidly evaluate known RFC baselines, unencrypted portals, raw IP servers, PayPal brand typosquats, and disposable `.xyz` domains.
- **Dynamic 3D Radial Risk Gauge:** Real-time animated circular progress ring with a cute kitty bow visualizing the 0–100 risk score with sweet pastel transitions (Mint Green, Warm Apricot, Strawberry Coral, Berry Crimson).
- **URL Anatomical Dissection:** Isolates Scheme encryption status, Hostname, Subdomain nesting, Path & Query parameters, and Live Resolved IP address (with NXDOMAIN detection for inactive or suspended infrastructure).
- **Triggered Threat Indicators:** Itemized security cards detailing the specific heuristic factor, point penalty, and forensic rationale.
- **Interactive 10-URL Benchmark Modal:** Run and review empirical benchmark test results directly from the web interface.
- **One-Click Executive PDF Export:** Compile and download the official 3-page executive audit report formatted for SOC leadership.

---

## 🔬 3. The 8 Balanced Heuristic Scoring Rules

Unlike opaque "black-box" scanners, **PEER'S Phish Detector** itemizes every point awarded. Points are balanced heuristic weights chosen to reflect empirical phishing attack patterns:

| # | Heuristic Factor | Max Pts | Technical Detection Logic & Security Relevance |
|---|---|:---:|---|
| **1** | **Unencrypted Protocol** | **+20** | Flags unencrypted `http://` schemes. Legitimate modern banking and authentication portals universally mandate TLS encryption (`https://`). |
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

| Risk Score | Assigned Tier | Operational Definition & User Guidance |
|:---:|:---:|---|
| **0 – 19** | **Low Risk** | **No suspicious lexical indicators detected.** *(Note: Does not prove that a website is benign, as zero-day phishing pages can reside on fresh, clean domains).* |
| **20 – 49** | **Medium Risk** | **Caution advised.** Elevated risk signals detected (e.g., plain unencrypted HTTP or shortened destination URL). |
| **50 – 74** | **High Risk** | **High probability of phishing.** Multiple high-severity risk signals identified (e.g., raw IP, brand typosquatting, or high-abuse TLDs with banking keywords). |
| **75 – 100** | **Critical Risk** | **Immediate threat signature detected.** Severe composite phishing lure (e.g., unencrypted raw IP impersonating financial brands with sensitive query parameters). |

---

## 📊 5. 10-URL Empirical Benchmark Results

The tool includes a built-in empirical benchmark suite (`--test`) evaluating 10 representative URL test cases:

| # | Target URL | Expected Tier | Actual Score | Actual Tier | Status | Key Heuristics Triggered |
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

**Cybersecurity Insight:** According to the Anti-Phishing Working Group (APWG), over 83% of active phishing websites now deploy valid, free SSL/TLS certificates (e.g., Let's Encrypt). This divergence demonstrates that **a green padlock icon or HTTPS scheme does not mean a website is safe.** It only guarantees the connection is encrypted, not that the recipient is trustworthy.

---

## 🚀 6. Installation & Execution Guide

### Option A: Linux / Kali Linux
```bash
# 1. Clone the repository
git clone https://github.com/MdPeerSiddiqui/Peer-s-Phish-Detector.git
cd Peer-s-Phish-Detector

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Launch the Web SOC Dashboard (opens browser automatically)
python3 app.py
# (Or: python3 phish_detector.py)

# 5. Optional: Run via Command Line (CLI)
python3 phish_detector.py --cli
python3 phish_detector.py https://google.com
python3 phish_detector.py https://paypa1-security-verification.xyz/login

# 6. Run the 10-URL benchmark & unit tests
python3 phish_detector.py --test
python3 -m unittest tests/test_phish_detector.py
```

### Option B: Windows (PowerShell)
```powershell
# 1. Clone the repository
git clone https://github.com/MdPeerSiddiqui/Peer-s-Phish-Detector.git
cd Peer-s-Phish-Detector

# 2. Create and activate virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Launch the Web SOC Dashboard
python app.py

# 5. Run via CLI
python phish_detector.py --cli
python phish_detector.py https://google.com

# 6. Run benchmark suite
python phish_detector.py --test

# 7. Run automated unit tests
python -m unittest tests/test_phish_detector.py
```

---

## 📁 7. Repository Architecture

```text
Peer-s-Phish-Detector/
├── .gitignore                      # Git exclusion rules
├── LICENSE                         # Open-source MIT license
├── README.md                       # Comprehensive documentation & benchmarks
├── requirements.txt                # Python package dependencies
├── test_urls.json                  # Curated 10-URL empirical benchmark dataset
├── app.py                          # Modern Flask Web SOC Dashboard & REST API
├── phish_detector.py               # Core analysis tool & CLI / Web auto-launcher
├── gui.py                          # Desktop Tkinter GUI interface
├── templates/
│   └── index.html                  # Self-contained dark-mode Web Dashboard
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

## 🛡️ 8. Scope, Ethics & Limitations

- **Educational & Defensive Scope:** This project was developed strictly for authorized educational training within the Sqrock IT Solution Cybersecurity Internship.
- **URL Lexical Analysis vs DOM Inspection:** This tool analyzes static URL strings and conducts safe socket-level DNS queries. It does not inspect the HTML Document Object Model (DOM), CSS styling, JavaScript payloads, or server-side `<form action="...">` redirection endpoints.
- **Defense-in-Depth Recommendation:** In an enterprise Security Operations Center (SOC), heuristic URL scoring should be paired with dynamic sandboxing, SSL certificate age inspection, and live threat intelligence feeds (e.g., Google Safe Browsing, PhishTank, VirusTotal).

---

## 👨‍💻 Author & Internship Details

- **Intern Name:** Md Peer Siddiqui
- **Company:** Sqrock IT Solution
- **Track:** Alpha 2 Cybersecurity Internship (Social Engineering Attack Simulations Using Python)
- **Day:** Day 03 — Phishing Page Anatomy & Detection
- **License:** MIT License
