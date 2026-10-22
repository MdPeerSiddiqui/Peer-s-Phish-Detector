"""
=============================================================================
PEER'S PHISH DETECTOR — AUTOMATED UNIT TEST SUITE
Sqrock IT Solution | Alpha 2 Cybersecurity Internship (Day 03)
Author: Md Peer Siddiqui
=============================================================================
"""

import unittest
from urllib.parse import urlparse
import sys
import os

# Add parent directory to path so phish_detector can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from phish_detector import (
    check_protocol,
    check_ip_address,
    check_subdomain_abuse,
    check_sensitive_keywords,
    check_brand_typosquatting,
    check_suspicious_tld,
    check_url_shortener,
    check_character_density,
    classify_risk,
    score_url,
)


class TestPhishDetectorHeuristics(unittest.TestCase):
    """Unit tests for the 8 heuristic scoring rules."""

    def test_check_protocol_http(self):
        parsed = urlparse("http://example.com")
        pts, reason = check_protocol(parsed)
        self.assertEqual(pts, 20)
        self.assertIn("Unencrypted HTTP", reason)

    def test_check_protocol_https(self):
        parsed = urlparse("https://example.com")
        pts, reason = check_protocol(parsed)
        self.assertEqual(pts, 0)
        self.assertEqual(reason, "")

    def test_check_ip_address_ipv4(self):
        pts, reason = check_ip_address("192.168.1.1")
        self.assertEqual(pts, 35)
        self.assertIn("Raw IP address used as hostname", reason)

    def test_check_ip_address_domain(self):
        pts, reason = check_ip_address("example.com")
        self.assertEqual(pts, 0)
        self.assertEqual(reason, "")

    def test_check_subdomain_abuse_deep_nesting(self):
        pts, reason = check_subdomain_abuse("a.b.c.d.example.com")
        self.assertGreaterEqual(pts, 20)
        self.assertIn("Excessive subdomain depth", reason)

    def test_check_subdomain_abuse_brand_spoof(self):
        pts, reason = check_subdomain_abuse("paypal.com.verify.attacker.com")
        self.assertEqual(pts, 25)  # 20 + 15 capped at 25
        self.assertIn("Target brand 'paypal' spoofed", reason)

    def test_check_sensitive_keywords_host_and_path(self):
        parsed = urlparse("https://verify-portal.com/login")
        pts, reason = check_sensitive_keywords(parsed)
        self.assertEqual(pts, 25)  # 20 (host) + 10 (path) capped at 25
        self.assertIn("hostname", reason)
        self.assertIn("path", reason)

    def test_check_sensitive_keywords_legitimate_path_only(self):
        parsed = urlparse("https://github.com/login")
        pts, reason = check_sensitive_keywords(parsed)
        self.assertEqual(pts, 10)  # path only
        self.assertIn("Action keyword(s) in URL path/query", reason)

    def test_check_brand_typosquatting_homoglyph(self):
        parsed = urlparse("https://paypa1-security.com")
        pts, reason = check_brand_typosquatting(parsed)
        self.assertEqual(pts, 30)
        self.assertIn("Brand lookalike / typosquatting detected targeting 'paypal'", reason)

    def test_check_brand_in_path_on_ip(self):
        parsed = urlparse("http://192.168.1.50/paypal-update/account.php")
        pts, reason = check_brand_typosquatting(parsed)
        self.assertEqual(pts, 15)
        self.assertIn("Brand name 'paypal' targeted inside URL path", reason)

    def test_check_suspicious_tld(self):
        pts, reason = check_suspicious_tld("suspicious-site.xyz")
        self.assertEqual(pts, 15)
        self.assertIn("High-abuse top-level domain", reason)

    def test_check_legitimate_tld(self):
        pts, reason = check_suspicious_tld("company.org")
        self.assertEqual(pts, 0)
        self.assertEqual(reason, "")

    def test_check_url_shortener(self):
        pts, reason = check_url_shortener("bit.ly")
        self.assertEqual(pts, 25)
        self.assertIn("Known URL shortener", reason)

    def test_check_character_density_hyphens(self):
        raw = "https://login-verify-account-update.com"
        parsed = urlparse(raw)
        pts, reason = check_character_density(parsed, raw)
        self.assertGreaterEqual(pts, 10)
        self.assertIn("hyphen density", reason)

    def test_risk_classification_tiers(self):
        tier_crit, _ = classify_risk(85)
        tier_high, _ = classify_risk(60)
        tier_med, _ = classify_risk(35)
        tier_low, _ = classify_risk(10)
        
        self.assertEqual(tier_crit, "Critical Risk")
        self.assertEqual(tier_high, "High Risk")
        self.assertEqual(tier_med, "Medium Risk")
        self.assertEqual(tier_low, "Low Risk")

    def test_score_capping_at_100(self):
        # A URL triggering almost everything
        url = "http://192.168.1.100/paypal-login-verify-account-update-billing.xyz"
        result = score_url(url)
        self.assertLessEqual(result["score"], 100)
        self.assertGreaterEqual(result["score"], 75)
        self.assertEqual(result["risk_tier"], "Critical Risk")


if __name__ == "__main__":
    unittest.main()
