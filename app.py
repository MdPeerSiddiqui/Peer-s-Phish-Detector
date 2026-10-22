"""
=============================================================================
PEER'S PHISH DETECTOR — WEB SOC APPLICATION & RESTful API
Sqrock IT Solution | Alpha 2 Cybersecurity Internship (Day 03)
Author: Md Peer Siddiqui
Repository: https://github.com/MdPeerSiddiqui/Peer-s-Phish-Detector
=============================================================================
"""

import os
import sys
import json
import threading
import webbrowser
from flask import Flask, request, jsonify, render_template, send_file

# Add current folder to sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from phish_detector import score_url, resolve_dns
from scripts.generate_day03_pdf import create_day03_report

app = Flask(__name__, template_folder="templates")


@app.route("/")
def index():
    """Serve the modern dark-themed web dashboard."""
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Inspect any arbitrary URL against the 8 balanced heuristic rules."""
    data = request.get_json(silent=True) or {}
    target_url = data.get("url", "").strip()
    include_dns = data.get("dns", True)

    if not target_url:
        return jsonify({"error": "No URL provided"}), 400

    result = score_url(target_url)

    if include_dns and result.get("hostname"):
        dns_info = resolve_dns(result["hostname"], timeout=2.0)
        result["dns_info"] = dns_info
    else:
        result["dns_info"] = None

    return jsonify(result)


@app.route("/api/benchmark", methods=["GET"])
def api_benchmark():
    """Execute the 10-URL empirical benchmark suite and return comparison data."""
    bench_file = os.path.join(CURRENT_DIR, "test_urls.json")
    if not os.path.exists(bench_file):
        return jsonify({"error": "test_urls.json not found"}), 404

    with open(bench_file, "r", encoding="utf-8") as f:
        cases = json.load(f)

    benchmark_results = []
    for item in cases:
        res = score_url(item["url"])
        is_match = (res["risk_level"].lower() == item["expected_risk"].lower())
        benchmark_results.append({
            "id": item["id"],
            "url": item["url"],
            "description": item["description"],
            "expected_risk": item["expected_risk"],
            "actual_score": res["score"],
            "actual_risk": res["risk_level"],
            "is_match": is_match,
            "breakdown": res["breakdown"]
        })

    return jsonify(benchmark_results)


@app.route("/api/export-pdf", methods=["GET"])
def api_export_pdf():
    """Compile and download the official 3-page executive cybersecurity lab report."""
    pdf_path = os.path.join(CURRENT_DIR, "reports", "Day03_Phishing_Detection_Report_Sqrock_MdPeerSiddiqui.pdf")
    
    # Generate fresh if not existing
    if not os.path.exists(pdf_path):
        create_day03_report(pdf_path)

    return send_file(
        pdf_path,
        as_attachment=True,
        download_name="Day03_Phishing_Detection_Report_Sqrock_MdPeerSiddiqui.pdf",
        mimetype="application/pdf"
    )


def open_browser(port):
    """Wait briefly for the server to bind, then open the browser automatically."""
    import time
    time.sleep(0.8)
    try:
        webbrowser.open_new_tab(f"http://127.0.0.1:{port}")
    except Exception:
        pass


def launch_web_server(port=5000):
    """Launch the Web SOC application and open the browser."""
    print("\n" + "=" * 70)
    print("  ⚡ PEER'S PHISH DETECTOR — WEB APPLICATION & HEURISTIC ENGINE ⚡")
    print("  Sqrock IT Solution | Alpha 2 Cybersecurity Internship (Day 03)")
    print(f"  --> Local Web Dashboard: http://127.0.0.1:{port}")
    print("=" * 70 + "\n")

    threading.Thread(target=open_browser, args=(port,), daemon=True).start()
    app.run(host="127.0.0.1", port=port, debug=False)


if __name__ == "__main__":
    launch_web_server()
