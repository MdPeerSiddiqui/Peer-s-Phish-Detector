#!/usr/bin/env python3
r"""
================================================================================
  _____  ______ ______ _____  _  _____ 
 |  __ \|  ____|  ____|  __ \(_)/ ____|
 | |__) | |__  | |__  | |__) |_| (___  
 |  ___/|  __| |  __| |  _  /   \___ \ 
 | |    | |____| |____| | \ \   ____) |
 |_|    |______|______|_|  \_\ |_____/ 
  _____  _     _     _       _____       _            _             
 |  __ \| |   (_)   | |     |  __ \     | |          | |            
 | |__) | |__  _ ___| |__   | |  | | ___| |_ ___  ___| |_ ___  _ __ 
 |  ___/| '_ \| / __| '_ \  | |  | |/ _ \ __/ _ \/ __| __/ _ \| '__|
 | |    | | | | \__ \ | | | | |__| |  __/ ||  __/ (__| || (_) | |   
 |_|    |_| |_|_|___/_| |_| |_____/ \___|\__\___|\___|\__\___/|_|   
                                                                     
  ⚡ PEER'S PHISH DETECTOR — Lexical URL Risk Scoring Engine ⚡
  Developed under Sqrock IT Solution — Alpha 2 Cybersecurity Internship (Day 03)
================================================================================
"""

import argparse
import ipaddress
import json
import os
import re
import socket
import sys
from datetime import datetime
from urllib.parse import urlparse
from typing import Tuple, List, Dict

# Cross-platform color styling with graceful fallback
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    C_CYAN = Fore.CYAN
    C_GREEN = Fore.GREEN
    C_YELLOW = Fore.YELLOW
    C_RED = Fore.RED
    C_MAGENTA = Fore.MAGENTA
    C_WHITE = Fore.WHITE
    C_BRIGHT = Style.BRIGHT
    C_DIM = Style.DIM
    C_RESET = Style.RESET_ALL
except ImportError:
    C_CYAN = "\033[36m"
    C_GREEN = "\033[32m"
    C_YELLOW = "\033[33m"
    C_RED = "\033[31m"
    C_MAGENTA = "\033[35m"
    C_WHITE = "\033[37m"
    C_BRIGHT = "\033[1m"
    C_DIM = "\033[2m"
    C_RESET = "\033[0m"

# Ensure UTF-8 printing in Windows terminal
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass

BANNER = rf"""{C_CYAN}{C_BRIGHT}
  _____  ______ ______ _____  _  _____ 
 |  __ \|  ____|  ____|  __ \(_)/ ____|
 | |__) | |__  | |__  | |__) |_| (___  
 |  ___/|  __| |  __| |  _  /   \___ \ 
 | |    | |____| |____| | \ \   ____) |
 |_|    |______|______|_|  \_\ |_____/ 
  _____  _     _     _       _____       _            _             
 |  __ \| |   (_)   | |     |  __ \     | |          | |            
 | |__) | |__  _ ___| |__   | |  | | ___| |_ ___  ___| |_ ___  _ __ 
 |  ___/| '_ \| / __| '_ \  | |  | |/ _ \ __/ _ \/ __| __/ _ \| '__|
 | |    | | | | \__ \ | | | | |__| |  __/ ||  __/ (__| || (_) | |   
 |_|    |_| |_|_|___/_| |_| |_____/ \___|\__\___|\___|\__\___/|_|   
{C_RESET}
{C_YELLOW}{C_BRIGHT} ⚡ PEER'S PHISH DETECTOR v1.0 — URL Anatomy & Heuristic Scorer ⚡{C_RESET}
{C_WHITE}{C_DIM} [★] Developed for Sqrock IT Solution | Alpha 2 Cybersecurity Track (Day 03){C_RESET}
{C_CYAN}{"=" * 82}{C_RESET}
"""

# =============================================================================
# HEURISTIC CONFIGURATION & DICTIONARIES (EXPANDED REAL-WORLD THREAT FEED)
# =============================================================================

# Common sensitive action keywords targeted in phishing campaigns
SENSITIVE_KEYWORDS = [
    "login", "verify", "verification", "account", "banking", "security", "update",
    "signin", "wallet", "kyc", "password", "authenticate", "auth", "portal",
    "billing", "confirm", "confirmation", "support", "secure", "recover", "recovery",
    "suspend", "suspended", "validate", "unlock", "renew", "reactivate", "invoice"
]

# High-profile brands frequently targeted by brand lookalikes & phishing lures
TARGET_BRANDS = [
    # Financial & Payment
    "paypal", "chase", "wellsfargo", "bankofamerica", "citibank", "barclays", "hsbc",
    "stripe", "shopify", "venmo", "zelle",
    # Tech & Cloud Ecosystems
    "google", "microsoft", "apple", "amazon", "netflix", "dropbox", "adobe", "steam",
    "yahoo", "office365", "outlook",
    # Crypto & Web3
    "binance", "coinbase", "metamask", "kraken",
    # Social Media & Messaging
    "facebook", "instagram", "linkedin", "twitter", "whatsapp", "telegram", "discord", "tiktok"
]

# Top-level domains statistically overrepresented in disposable phishing campaigns
SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".tk", ".ml", ".cf", ".gq", ".ga", ".buzz", ".club",
    ".work", ".icu", ".cam", ".fit", ".rest", ".online", ".men", ".loan",
    ".live", ".shop", ".cyou", ".sbs", ".cfd", ".vip", ".monster", ".tokyo",
    ".racing", ".download", ".accountant", ".bid", ".date", ".faith", ".party",
    ".review", ".stream", ".trade", ".win"
]

# Popular URL shorteners that mask the true destination host
KNOWN_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
    "ow.ly", "rebrand.ly", "cutt.ly", "adf.ly", "bit.do", "mcaf.ee",
    "su.pr", "qr.ae", "shorturl.at", "shorte.st"
]


def resolve_dns(hostname: str, timeout: float = 2.0) -> dict:
    """
    Safely resolves a domain to IP addresses via standard socket lookup.
    Operates without fetching remote HTTP content, keeping the analyst secure.
    """
    if not hostname:
        return {"status": "empty", "ips": [], "error": "No hostname provided"}

    host_clean = hostname.split(":")[0].strip()

    # Check if already raw IP
    try:
        ipaddress.ip_address(host_clean)
        return {"status": "raw_ip", "ips": [host_clean], "is_ip": True, "error": None}
    except ValueError:
        pass

    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            addr_info = socket.getaddrinfo(host_clean, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            ips = list(dict.fromkeys(info[4][0] for info in addr_info))
            return {"status": "resolved", "ips": ips, "is_ip": False, "error": None}
        finally:
            socket.setdefaulttimeout(old_timeout)
    except socket.gaierror as e:
        return {"status": "nxdomain", "ips": [], "is_ip": False, "error": f"NXDOMAIN ({e.strerror})"}
    except Exception as e:
        return {"status": "error", "ips": [], "is_ip": False, "error": str(e)}


# =============================================================================
# HEURISTIC INSPECTION FUNCTIONS
# =============================================================================

def check_protocol(parsed_url) -> tuple[int, str]:
    """
    Check 1: Evaluates protocol scheme.
    Plain unencrypted HTTP exposes credentials in transit and is heavily used
    in disposable attack kits lacking SSL certificates.
    """
    if parsed_url.scheme.lower() == "http":
        return 20, "Unencrypted HTTP protocol in use (+20 pts). Lacks TLS certificate."
    return 0, ""


def check_ip_address(hostname: str) -> tuple[int, str]:
    """
    Check 2: Detects if the host is a raw IP address instead of a domain name.
    Phishing operators frequently use raw IPs to bypass domain registration audits.
    """
    if not hostname:
        return 0, ""
    clean_host = hostname.split(":")[0]  # remove port if present
    try:
        ipaddress.ip_address(clean_host)
        return 35, f"Raw IP address used as hostname ({clean_host}) (+35 pts). Bypasses domain identity records."
    except ValueError:
        return 0, ""


def check_subdomain_abuse(hostname: str) -> tuple[int, str]:
    """
    Check 3: Analyzes subdomain depth and nested brand deception.
    e.g., 'paypal.com.account-verify.security-update.evil.com'
    """
    if not hostname:
        return 0, ""
    
    parts = hostname.split(".")
    # If using raw IP, skip subdomain check
    try:
        ipaddress.ip_address(hostname.split(":")[0])
        return 0, ""
    except ValueError:
        pass

    score = 0
    reasons = []

    # Deep label nesting (excessive dots)
    if len(parts) > 3:
        score += 20
        reasons.append(f"Excessive subdomain depth ({len(parts)} labels) (+20 pts).")

    # Brand in subdomain but not main second-level domain (SLD)
    if len(parts) >= 3:
        subdomain_part = ".".join(parts[:-2]).lower()
        main_domain = ".".join(parts[-2:]).lower()
        for brand in TARGET_BRANDS:
            if brand in subdomain_part and brand not in main_domain:
                score += 15
                reasons.append(f"Target brand '{brand}' spoofed inside subdomain prefix (+15 pts).")
                break

    capped_score = min(score, 25)
    return capped_score, " ".join(reasons)


def check_sensitive_keywords(parsed_url) -> tuple[int, str]:
    """
    Check 4: Searches for high-risk action keywords (login, verify, billing, etc.).
    Keywords in the hostname carry significantly higher risk than in the path.
    """
    hostname = (parsed_url.hostname or "").lower()
    path_and_query = f"{parsed_url.path} {parsed_url.query}".lower()

    found_in_host = [kw for kw in SENSITIVE_KEYWORDS if kw in hostname]
    found_in_path = [kw for kw in SENSITIVE_KEYWORDS if kw in path_and_query and kw not in found_in_host]

    score = 0
    reasons = []

    if found_in_host:
        score += 20
        reasons.append(f"Sensitive credential keyword(s) in hostname: {', '.join(found_in_host[:2])} (+20 pts).")
    
    if found_in_path:
        # Lower weight for path to avoid over-penalizing legitimate login URLs (e.g. github.com/login)
        score += 10
        reasons.append(f"Action keyword(s) in URL path/query: {', '.join(found_in_path[:2])} (+10 pts).")

    capped_score = min(score, 25)
    return capped_score, " ".join(reasons)


def check_brand_typosquatting(parsed_url) -> tuple[int, str]:
    """
    Check 5: Detects visual character substitutions (homoglyphs/typosquatting)
    and brand impersonation in paths of non-brand hosts.
    e.g., 'paypa1' (1 for l), 'g00gle' (0 for o), or raw IP hosting '/paypal-login'.
    """
    hostname = (parsed_url.hostname or "").lower()
    path_and_query = f"{parsed_url.path} {parsed_url.query}".lower()
    
    if not hostname:
        return 0, ""

    # Common substitution mappings
    de_obfuscated = (
        hostname.replace("0", "o")
                .replace("1", "l")
                .replace("vv", "w")
                .replace("rn", "m")
    )

    for brand in TARGET_BRANDS:
        # 1. Homoglyph / Typosquat in hostname
        if brand in de_obfuscated and brand not in hostname:
            return 30, f"Brand lookalike / typosquatting detected targeting '{brand}' (+30 pts)."
        
        # 2. Brand present in path on raw IP or unrelated host
        if brand in path_and_query and brand not in hostname:
            # Check if host is raw IP or unrelated host
            try:
                ipaddress.ip_address(hostname)
                is_ip = True
            except ValueError:
                is_ip = False
            
            if is_ip or not hostname.endswith(f".{brand}.com"):
                return 15, f"Brand name '{brand}' targeted inside URL path on untrusted host (+15 pts)."
            
    return 0, ""


def check_suspicious_tld(hostname: str) -> tuple[int, str]:
    """
    Check 6: Checks against disposable, high-abuse Top-Level Domains.
    """
    if not hostname:
        return 0, ""

    host_lower = hostname.lower()
    for tld in SUSPICIOUS_TLDS:
        if host_lower.endswith(tld):
            return 15, f"High-abuse top-level domain extension detected ({tld}) (+15 pts)."

    return 0, ""


def check_url_shortener(hostname: str) -> tuple[int, str]:
    """
    Check 7: Detects known URL shorteners concealing destination host.
    """
    if not hostname:
        return 0, ""

    host_lower = hostname.lower()
    for shortener in KNOWN_SHORTENERS:
        if host_lower == shortener or host_lower.endswith(f".{shortener}"):
            return 25, f"Known URL shortener service ({shortener}) (+25 pts). Destination host concealed."

    return 0, ""


def check_character_density(parsed_url, raw_url: str) -> tuple[int, str]:
    """
    Check 8: Evaluates hyphen density and excessive URL string length.
    """
    hostname = parsed_url.hostname or ""
    hyphen_count = hostname.count("-")
    score = 0
    reasons = []

    if hyphen_count >= 3:
        score += 10
        reasons.append(f"Abnormally high hyphen density in hostname ({hyphen_count} hyphens) (+10 pts).")

    if len(raw_url) > 75:
        score += 10
        reasons.append(f"Excessive URL character length ({len(raw_url)} characters) (+10 pts).")
    elif len(hostname) > 40:
        score += 10
        reasons.append(f"Excessive hostname label length ({len(hostname)} characters) (+10 pts).")

    capped_score = min(score, 15)
    return capped_score, " ".join(reasons)


# =============================================================================
# MASTER SCORING ORCHESTRATOR
# =============================================================================

def classify_risk(final_score: int) -> tuple[str, str]:
    """
    Classify risk tier based on transparent heuristic score boundaries.
    """
    if final_score >= 75:
        return "Critical Risk", "Multiple high-confidence deceptive indicators detected."
    elif final_score >= 50:
        return "High Risk", "Significant phishing indicators detected in URL pattern."
    elif final_score >= 20:
        return "Medium Risk", "Caution: Minor or procedural indicators detected (e.g. HTTP or shortened URL)."
    else:
        return "Low Risk", "No suspicious indicators detected in URL pattern. (Note: does not guarantee safety)."


def score_url(url: str) -> dict:
    """
    Evaluate a URL against all 8 heuristic factors and calculate total risk score.
    Returns a dictionary containing breakdown, score, and defined risk tier.
    """
    url_stripped = url.strip()
    # Normalize scheme if omitted
    if not re.match(r"^[a-zA-Z]+://", url_stripped):
        parsed = urlparse("http://" + url_stripped)
        url_normalized = "http://" + url_stripped
    else:
        parsed = urlparse(url_stripped)
        url_normalized = url_stripped

    hostname = parsed.hostname or ""

    factors = []
    total_score = 0

    # 1. Protocol Check
    pts, reason = check_protocol(parsed)
    if pts > 0:
        total_score += pts
        factors.append({"factor": "Unencrypted Protocol", "points": pts, "reason": reason})

    # 2. Raw IP Check
    pts, reason = check_ip_address(hostname)
    if pts > 0:
        total_score += pts
        factors.append({"factor": "Raw IP Hostname", "points": pts, "reason": reason})

    # 3. Subdomain Abuse
    pts, reason = check_subdomain_abuse(hostname)
    if pts > 0:
        total_score += pts
        factors.append({"factor": "Subdomain Abuse", "points": pts, "reason": reason})

    # 4. Sensitive Keywords
    pts, reason = check_sensitive_keywords(parsed)
    if pts > 0:
        total_score += pts
        factors.append({"factor": "Sensitive Action Keywords", "points": pts, "reason": reason})

    # 5. Brand Typosquatting
    pts, reason = check_brand_typosquatting(parsed)
    if pts > 0:
        total_score += pts
        factors.append({"factor": "Brand Typosquatting", "points": pts, "reason": reason})

    # 6. High-Risk TLD
    pts, reason = check_suspicious_tld(hostname)
    if pts > 0:
        total_score += pts
        factors.append({"factor": "Suspicious TLD Extension", "points": pts, "reason": reason})

    # 7. URL Shortener
    pts, reason = check_url_shortener(hostname)
    if pts > 0:
        total_score += pts
        factors.append({"factor": "URL Shortener Masking", "points": pts, "reason": reason})

    # 8. Character Density
    pts, reason = check_character_density(parsed, url_normalized)
    if pts > 0:
        total_score += pts
        factors.append({"factor": "Character Density & Length", "points": pts, "reason": reason})

    # Cap score at 100
    final_score = min(total_score, 100)

    # Risk Tier Classification (Explicit threshold definition)
    risk_level, verdict = classify_risk(final_score)

    return {
        "url": url_stripped,
        "hostname": hostname,
        "score": final_score,
        "risk_level": risk_level,
        "risk_tier": risk_level,
        "verdict": verdict,
        "indicators_triggered": len(factors),
        "breakdown": factors
    }


def display_audit_card(result: dict):
    """Render a clean, formatted risk report card to the terminal."""
    score = result["score"]
    level = result["risk_level"]

    if level == "Critical Risk":
        color_lvl = f"{C_RED}{C_BRIGHT}{level}{C_RESET}"
    elif level == "High Risk":
        color_lvl = f"{C_YELLOW}{C_BRIGHT}{level}{C_RESET}"
    elif level == "Medium Risk":
        color_lvl = f"{C_CYAN}{C_BRIGHT}{level}{C_RESET}"
    else:
        color_lvl = f"{C_GREEN}{C_BRIGHT}{level}{C_RESET}"

    print(f"\n{C_CYAN}{'-' * 82}{C_RESET}")
    print(f"{C_WHITE}{C_BRIGHT}[TARGET URL]{C_RESET} : {result['url']}")
    print(f"{C_WHITE}[HOSTNAME]  {C_RESET} : {result['hostname'] or 'N/A'}")
    
    # Show DNS info if available
    dns_info = result.get("dns_info")
    if dns_info:
        if dns_info["status"] == "resolved":
            print(f"{C_WHITE}[RESOLVED IP]{C_RESET}: {C_GREEN}{', '.join(dns_info['ips'][:3])}{C_RESET} {C_DIM}(Live DNS Lookup){C_RESET}")
        elif dns_info["status"] == "raw_ip":
            print(f"{C_WHITE}[RESOLVED IP]{C_RESET}: {C_RED}{dns_info['ips'][0]}{C_RESET} {C_DIM}(Direct IP Host){C_RESET}")
        elif dns_info["status"] == "nxdomain":
            print(f"{C_WHITE}[RESOLVED IP]{C_RESET}: {C_YELLOW}NXDOMAIN{C_RESET} {C_DIM}(Domain Unregistered or Suspended){C_RESET}")

    print(f"{C_WHITE}[RISK SCORE]{C_RESET} : {C_BRIGHT}{score}/100{C_RESET}  |  Tier: {color_lvl}")
    print(f"{C_WHITE}[VERDICT]   {C_RESET} : {C_DIM}{result['verdict']}{C_RESET}")
    print(f"{C_CYAN}{'-' * 82}{C_RESET}")

    if result["breakdown"]:
        print(f"{C_YELLOW}{C_BRIGHT}Heuristic Breakdown ({result['indicators_triggered']} rules triggered):{C_RESET}")
        for idx, item in enumerate(result["breakdown"], 1):
            print(f"  {C_WHITE}[{idx:02d}]{C_RESET} {C_CYAN}{item['factor']:<28}{C_RESET} : {C_YELLOW}+{item['points']:02d} pts{C_RESET}")
            print(f"       └── {C_DIM}{item['reason']}{C_RESET}")
    else:
        print(f"{C_GREEN}  [✔] Clean lexical structure. No known phishing indicators flagged.{C_RESET}")
    print(f"{C_CYAN}{'=' * 82}{C_RESET}")


def run_benchmark(benchmark_file="test_urls.json", output_dir="reports"):
    """
    Run the 10-URL benchmark test suite and evaluate expected vs actual results.
    Exports structured test_results.json and test_results.txt.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(script_dir, benchmark_file)

    if not os.path.exists(file_path):
        print(f"{C_RED}[!] Error: Benchmark file '{benchmark_file}' not found.{C_RESET}")
        return

    with open(file_path, "r", encoding="utf-8") as f:
        cases = json.load(f)

    print(f"\n{C_YELLOW}{C_BRIGHT}[*] EXECUTING 10-URL BENCHMARK TEST SUITE...{C_RESET}")
    print(f"{C_WHITE}{C_DIM}Comparing heuristic output against documented expectations.{C_RESET}\n")

    benchmark_results = []
    matches = 0

    header = f"{'#':<3} | {'Target URL':<42} | {'Actual Score':<12} | {'Actual Tier':<14} | {'Match'}"
    print(header)
    print("-" * 85)

    for item in cases:
        res = score_url(item["url"])
        is_match = (res["risk_level"].lower() == item["expected_risk"].lower())
        if is_match:
            matches += 1
            match_str = f"{C_GREEN}MATCH{C_RESET}"
        else:
            match_str = f"{C_YELLOW}DIVERGENT{C_RESET}"

        item_result = {
            "id": item["id"],
            "url": item["url"],
            "description": item["description"],
            "expected_risk": item["expected_risk"],
            "actual_score": res["score"],
            "actual_risk": res["risk_level"],
            "indicators_triggered": res["indicators_triggered"],
            "is_match": is_match,
            "breakdown": res["breakdown"]
        }
        benchmark_results.append(item_result)

        display_url = (item["url"][:39] + "...") if len(item["url"]) > 42 else item["url"]
        print(f"{item['id']:<3} | {display_url:<42} | {res['score']:>3}/100     | {res['risk_level']:<14} | {match_str}")

    print("-" * 85)
    print(f"{C_GREEN}[✔] Benchmark Complete: {matches}/{len(cases)} test cases aligned with expected risk tiers.{C_RESET}")

    # Export deliverables to reports/
    out_dir_path = os.path.join(script_dir, output_dir)
    os.makedirs(out_dir_path, exist_ok=True)

    json_path = os.path.join(out_dir_path, "test_results.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(benchmark_results, f, indent=4)
    print(f"{C_WHITE}[★] Structured Benchmark JSON Saved : {C_GREEN}{json_path}{C_RESET}")

    txt_path = os.path.join(out_dir_path, "test_results.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("PEER'S PHISH DETECTOR — 10-URL BENCHMARK RESULTS\n")
        f.write("=" * 80 + "\n")
        for r in benchmark_results:
            f.write(f"ID #{r['id']} | {r['url']}\n")
            f.write(f"Description: {r['description']}\n")
            f.write(f"Expected: {r['expected_risk']} | Actual: {r['actual_risk']} ({r['actual_score']}/100)\n")
            f.write(f"Indicators Triggered: {r['indicators_triggered']}\n")
            for b in r['breakdown']:
                f.write(f"  - {b['factor']} (+{b['points']} pts): {b['reason']}\n")
            f.write("-" * 80 + "\n")
    print(f"{C_WHITE}[★] Plaintext Audit Log Saved       : {C_GREEN}{txt_path}{C_RESET}")


def run_interactive_cli():
    """Interactive command-line loop allowing analysts to scan multiple URLs."""
    print(f"{C_CYAN}  Interactive CLI Shell Ready. Type 'test' for benchmark, 'exit' or 'q' to quit.{C_RESET}\n")
    while True:
        try:
            print(f"{C_YELLOW}[?] Enter any URL to evaluate for phishing indicators:{C_RESET}")
            user_input = input(f"{C_CYAN}    └── URL > {C_RESET}").strip()
            if not user_input:
                continue
            if user_input.lower() in ("exit", "quit", "q"):
                print(f"{C_GREEN}[*] Exiting PEER'S Phish Detector. Stay safe!{C_RESET}")
                break
            if user_input.lower() == "test":
                run_benchmark()
                continue

            result = score_url(user_input)
            if result.get("hostname"):
                dns_info = resolve_dns(result["hostname"])
                result["dns_info"] = dns_info
            display_audit_card(result)
        except (KeyboardInterrupt, EOFError):
            print(f"\n{C_RED}[!] Session closed.{C_RESET}")
            break


def main():
    parser = argparse.ArgumentParser(
        description="PEER'S Phish Detector — URL Anatomy & Heuristic Threat Scorer"
    )
    parser.add_argument(
        "url",
        nargs="?",
        default=None,
        help="Single URL to inspect (e.g. 'https://paypa1-security.com')",
    )
    parser.add_argument(
        "--cli",
        action="store_true",
        help="Force command-line interface (CLI) mode instead of graphical UI",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run the automated 10-URL benchmark test suite",
    )
    parser.add_argument(
        "--no-dns",
        action="store_true",
        help="Skip live DNS resolution",
    )

    args = parser.parse_args()

    # 1. Benchmark suite
    if args.test:
        print(BANNER)
        run_benchmark()
        return

    # 2. Direct URL argument in CLI
    if args.url:
        print(BANNER)
        result = score_url(args.url)
        if not args.no_dns and result.get("hostname"):
            dns_info = resolve_dns(result["hostname"])
            result["dns_info"] = dns_info
        display_audit_card(result)
        return

    # 3. Explicit CLI mode requested
    if args.cli:
        print(BANNER)
        run_interactive_cli()
        return

    # 4. Default: Launch Graphical User Interface (GUI)
    try:
        from app import launch_web_server
        launch_web_server()
    except Exception as e:
        # Fall back to CLI if headless or display is unavailable
        print(BANNER)
        print(f"{C_YELLOW}[i] Notice: Graphical environment unavailable ({e}).{C_RESET}")
        print(f"{C_CYAN}[i] Seamlessly falling back to interactive CLI mode...{C_RESET}\n")
        run_interactive_cli()


if __name__ == "__main__":
    main()
