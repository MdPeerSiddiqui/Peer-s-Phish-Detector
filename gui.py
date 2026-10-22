"""
=============================================================================
PEER'S PHISH DETECTOR — MODERN GRAPHICAL USER INTERFACE (GUI)
Sqrock IT Solution | Alpha 2 Cybersecurity Internship (Day 03)
Author: Md Peer Siddiqui
Repository: https://github.com/MdPeerSiddiqui/Peer-s-Phish-Detector
=============================================================================
"""

import sys
import os
import json
import threading
from urllib.parse import urlparse
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# Add current folder to sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from phish_detector import (
    score_url,
    resolve_dns,
    classify_risk,
    TARGET_BRANDS,
    SUSPICIOUS_TLDS,
    KNOWN_SHORTENERS,
    SENSITIVE_KEYWORDS
)

# Optional PDF generator import
try:
    from scripts.generate_day03_pdf import create_day03_report
    PDF_AVAILABLE = True
except Exception:
    PDF_AVAILABLE = False


# Theme Color Constants (Modern Cyber Dark Palette)
THEME = {
    "bg_main": "#0b0f19",
    "bg_card": "#141e33",
    "bg_input": "#1e293b",
    "border": "#27354f",
    "text_light": "#f8fafc",
    "text_muted": "#94a3b8",
    "accent_cyan": "#00d2ff",
    "accent_blue": "#3b82f6",
    "low_risk": "#10b981",       # Emerald
    "med_risk": "#f59e0b",       # Amber
    "high_risk": "#ef4444",      # Coral Red
    "crit_risk": "#dc2626",      # Crimson
}

PRESET_SAMPLES = [
    ("Select a preset sample URL...", ""),
    ("1. Legitimate HTTPS Baseline", "https://example.com"),
    ("2. Unencrypted HTTP Connection", "http://example.com"),
    ("3. Raw IPv4 Login Portal", "http://192.168.1.100/login"),
    ("4. Deep Subdomain Brand Spoof", "https://paypal.com.account-verify.security-update.evil.com/login"),
    ("5. Homoglyph Typosquat (paypa1)", "https://paypa1-security.com/signin"),
    ("6. URL Shortener Mask (bit.ly)", "https://bit.ly/secure-login-39x"),
    ("7. Disposable TLD (.xyz) + Banking", "http://banking-portal-update.xyz/verify"),
    ("8. Hyphen & Keyword Stuffing", "https://login-verify-account-update-billing-auth-portal.com"),
    ("9. Legitimate Path on Trusted Host", "https://github.com/login"),
    ("10. Multi-Vector Composite Threat", "http://192.168.1.50/paypal-update/account.php?verify=token"),
]


class PhishDetectorGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("⚡ PEER'S Phish Detector v2.0 — URL Anatomy & Heuristic Threat Scorer")
        self.root.geometry("1060x820")
        self.root.minsize(920, 720)
        self.root.configure(bg=THEME["bg_main"])

        # State Variables
        self.current_result = None
        self.var_url = tk.StringVar()
        self.var_dns = tk.BooleanVar(value=True)
        self.var_preset = tk.StringVar(value=PRESET_SAMPLES[0][0])
        self.var_status = tk.StringVar(value="Ready. Enter any URL to begin lexical heuristic inspection.")

        self._configure_styles()
        self._build_ui()

    def _configure_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        # Global Frame Styling
        style.configure("TFrame", background=THEME["bg_main"])
        style.configure("Card.TFrame", background=THEME["bg_card"], relief="solid", borderwidth=1)

        # Label Styling
        style.configure("TLabel", background=THEME["bg_main"], foreground=THEME["text_light"], font=("Helvetica", 9))
        style.configure("Card.TLabel", background=THEME["bg_card"], foreground=THEME["text_light"], font=("Helvetica", 9))
        style.configure("Muted.TLabel", background=THEME["bg_card"], foreground=THEME["text_muted"], font=("Helvetica", 8))
        style.configure("Header.TLabel", background=THEME["bg_main"], foreground=THEME["accent_cyan"], font=("Helvetica", 16, "bold"))
        style.configure("SubHeader.TLabel", background=THEME["bg_main"], foreground=THEME["text_muted"], font=("Helvetica", 9))

        # Checkbutton
        style.configure("TCheckbutton", background=THEME["bg_main"], foreground=THEME["text_light"], font=("Helvetica", 9))

        # Treeview (Findings Table)
        style.configure("Treeview",
                        background=THEME["bg_input"],
                        foreground=THEME["text_light"],
                        fieldbackground=THEME["bg_input"],
                        font=("Helvetica", 9),
                        rowheight=26)
        style.configure("Treeview.Heading",
                        background=THEME["border"],
                        foreground=THEME["text_light"],
                        font=("Helvetica", 9, "bold"))
        style.map("Treeview.Heading", background=[("active", THEME["accent_blue"])])

    def _build_ui(self):
        # Master Container with Padding
        master = tk.Frame(self.root, bg=THEME["bg_main"], padx=18, pady=14)
        master.pack(fill=tk.BOTH, expand=True)

        # ---------------- 1. Top Header Banner ----------------
        header_frame = tk.Frame(master, bg=THEME["bg_main"])
        header_frame.pack(fill=tk.X, pady=(0, 10))

        title_lbl = tk.Label(
            header_frame,
            text="⚡ PEER'S PHISH DETECTOR",
            font=("Helvetica", 17, "bold"),
            fg=THEME["accent_cyan"],
            bg=THEME["bg_main"]
        )
        title_lbl.pack(anchor="w")

        sub_lbl = tk.Label(
            header_frame,
            text="Lexical URL Anatomy Dissection & Heuristic Risk Scorer | Sqrock IT Solution (Day 03)",
            font=("Helvetica", 9),
            fg=THEME["text_muted"],
            bg=THEME["bg_main"]
        )
        sub_lbl.pack(anchor="w")

        # ---------------- 2. URL Input Card ----------------
        input_card = tk.LabelFrame(
            master,
            text=" 🌐 Target URL Inspection Bar ",
            font=("Helvetica", 10, "bold"),
            fg=THEME["accent_cyan"],
            bg=THEME["bg_card"],
            bd=1,
            relief="solid",
            padx=12,
            pady=10
        )
        input_card.pack(fill=tk.X, pady=(0, 10))

        # Input Row
        row1 = tk.Frame(input_card, bg=THEME["bg_card"])
        row1.pack(fill=tk.X, pady=(0, 6))

        self.url_entry = tk.Entry(
            row1,
            textvariable=self.var_url,
            font=("Courier", 11),
            bg=THEME["bg_input"],
            fg="#ffffff",
            insertbackground="#ffffff",
            bd=1,
            relief="solid"
        )
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=5, padx=(0, 8))
        self.url_entry.bind("<Return>", lambda e: self.on_analyze())
        self.url_entry.focus()

        btn_analyze = tk.Button(
            row1,
            text="🔍 ANALYZE URL",
            font=("Helvetica", 10, "bold"),
            bg=THEME["accent_cyan"],
            fg="#0b0f19",
            activebackground=THEME["accent_blue"],
            activeforeground="#ffffff",
            cursor="hand2",
            bd=0,
            padx=16,
            pady=5,
            command=self.on_analyze
        )
        btn_analyze.pack(side=tk.LEFT, padx=(0, 5))

        btn_paste = tk.Button(
            row1,
            text="📋 Paste",
            font=("Helvetica", 9),
            bg=THEME["border"],
            fg=THEME["text_light"],
            activebackground=THEME["accent_blue"],
            cursor="hand2",
            bd=0,
            padx=10,
            pady=5,
            command=self.on_paste
        )
        btn_paste.pack(side=tk.LEFT, padx=(0, 5))

        btn_clear = tk.Button(
            row1,
            text="🧹 Clear",
            font=("Helvetica", 9),
            bg=THEME["border"],
            fg=THEME["text_light"],
            activebackground=THEME["high_risk"],
            cursor="hand2",
            bd=0,
            padx=10,
            pady=5,
            command=self.on_clear
        )
        btn_clear.pack(side=tk.LEFT)

        # Control Row (Presets & Options)
        row2 = tk.Frame(input_card, bg=THEME["bg_card"])
        row2.pack(fill=tk.X)

        lbl_preset = tk.Label(row2, text="Or load benchmark sample:", font=("Helvetica", 8), fg=THEME["text_muted"], bg=THEME["bg_card"])
        lbl_preset.pack(side=tk.LEFT, padx=(0, 6))

        preset_names = [p[0] for p in PRESET_SAMPLES]
        self.preset_combo = ttk.Combobox(row2, textvariable=self.var_preset, values=preset_names, state="readonly", width=38)
        self.preset_combo.pack(side=tk.LEFT, padx=(0, 15))
        self.preset_combo.bind("<<ComboboxSelected>>", self.on_select_preset)

        chk_dns = tk.Checkbutton(
            row2,
            text="Enable Safe Live DNS & IP Resolution",
            variable=self.var_dns,
            font=("Helvetica", 8),
            fg=THEME["text_light"],
            bg=THEME["bg_card"],
            activebackground=THEME["bg_card"],
            selectcolor=THEME["bg_input"]
        )
        chk_dns.pack(side=tk.LEFT)

        # ---------------- 3. Middle Section: Results & Gauge ----------------
        mid_frame = tk.Frame(master, bg=THEME["bg_main"])
        mid_frame.pack(fill=tk.X, pady=(0, 10))

        # Left Column: Risk Gauge & Badge
        left_card = tk.LabelFrame(
            mid_frame,
            text=" 📊 Heuristic Risk Gauge ",
            font=("Helvetica", 9, "bold"),
            fg=THEME["accent_cyan"],
            bg=THEME["bg_card"],
            bd=1,
            relief="solid",
            padx=12,
            pady=8
        )
        left_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 6))

        gauge_top = tk.Frame(left_card, bg=THEME["bg_card"])
        gauge_top.pack(fill=tk.X, pady=(2, 4))

        self.score_lbl = tk.Label(
            gauge_top,
            text="-- / 100",
            font=("Helvetica", 24, "bold"),
            fg=THEME["text_muted"],
            bg=THEME["bg_card"]
        )
        self.score_lbl.pack(side=tk.LEFT, padx=(0, 12))

        self.tier_badge = tk.Label(
            gauge_top,
            text="STANDBY",
            font=("Helvetica", 10, "bold"),
            fg="#ffffff",
            bg=THEME["border"],
            padx=10,
            pady=3,
            bd=0
        )
        self.tier_badge.pack(side=tk.LEFT)

        # Visual Progress Canvas (0 - 100 Meter)
        self.canvas_gauge = tk.Canvas(left_card, height=18, bg=THEME["bg_input"], bd=0, highlightthickness=0)
        self.canvas_gauge.pack(fill=tk.X, pady=6)
        self._draw_gauge(0, THEME["border"])

        self.verdict_lbl = tk.Label(
            left_card,
            text="Enter a URL above to perform automated heuristic security triage.",
            font=("Helvetica", 8, "italic"),
            fg=THEME["text_muted"],
            bg=THEME["bg_card"],
            wraplength=480,
            justify="left"
        )
        self.verdict_lbl.pack(anchor="w", pady=(2, 0))

        # Right Column: URL Anatomical Dissection Card
        right_card = tk.LabelFrame(
            mid_frame,
            text=" 🔬 URL Anatomical Dissection ",
            font=("Helvetica", 9, "bold"),
            fg=THEME["accent_cyan"],
            bg=THEME["bg_card"],
            bd=1,
            relief="solid",
            padx=12,
            pady=8
        )
        right_card.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(6, 0))

        self.anatomy_grid = tk.Frame(right_card, bg=THEME["bg_card"])
        self.anatomy_grid.pack(fill=tk.BOTH, expand=True)

        self.anatomy_labels = {}
        fields = [
            ("Protocol / TLS:", "scheme", 0),
            ("Hostname:", "hostname", 1),
            ("Subdomain Label:", "subdomain", 2),
            ("Path & Query:", "path_query", 3),
            ("Resolved IP (DNS):", "dns_ip", 4),
        ]
        for title, key, r in fields:
            lbl_title = tk.Label(self.anatomy_grid, text=title, font=("Helvetica", 8, "bold"), fg=THEME["text_muted"], bg=THEME["bg_card"])
            lbl_title.grid(row=r, column=0, sticky="w", pady=1)
            lbl_val = tk.Label(self.anatomy_grid, text="--", font=("Courier", 8), fg=THEME["text_light"], bg=THEME["bg_card"], anchor="w")
            lbl_val.grid(row=r, column=1, sticky="w", padx=8, pady=1)
            self.anatomy_labels[key] = lbl_val

        # ---------------- 4. Bottom Section: Triggered Indicators Table ----------------
        table_card = tk.LabelFrame(
            master,
            text=" 🚨 Triggered Threat Indicators & Security Audit Rationale ",
            font=("Helvetica", 9, "bold"),
            fg=THEME["accent_cyan"],
            bg=THEME["bg_card"],
            bd=1,
            relief="solid",
            padx=10,
            pady=8
        )
        table_card.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        columns = ("factor", "points", "reason")
        self.tree = ttk.Treeview(table_card, columns=columns, show="headings", selectmode="browse")
        self.tree.heading("factor", text="Heuristic Risk Factor")
        self.tree.heading("points", text="Points")
        self.tree.heading("reason", text="Technical Detection Logic & Security Rationale")

        self.tree.column("factor", width=180, anchor="w")
        self.tree.column("points", width=65, anchor="center")
        self.tree.column("reason", width=730, anchor="w")

        scrollbar = ttk.Scrollbar(table_card, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # ---------------- 5. Action Toolbar ----------------
        toolbar = tk.Frame(master, bg=THEME["bg_main"])
        toolbar.pack(fill=tk.X, pady=(0, 6))

        btn_copy = tk.Button(
            toolbar,
            text="📋 Copy Audit Summary",
            font=("Helvetica", 9),
            bg=THEME["border"],
            fg=THEME["text_light"],
            activebackground=THEME["accent_blue"],
            bd=0,
            padx=12,
            pady=5,
            cursor="hand2",
            command=self.on_copy_summary
        )
        btn_copy.pack(side=tk.LEFT, padx=(0, 6))

        btn_json = tk.Button(
            toolbar,
            text="💾 Export JSON Report",
            font=("Helvetica", 9),
            bg=THEME["border"],
            fg=THEME["text_light"],
            activebackground=THEME["accent_blue"],
            bd=0,
            padx=12,
            pady=5,
            cursor="hand2",
            command=self.on_export_json
        )
        btn_json.pack(side=tk.LEFT, padx=(0, 6))

        btn_pdf = tk.Button(
            toolbar,
            text="📄 Generate Official PDF Report",
            font=("Helvetica", 9, "bold"),
            bg=THEME["accent_blue"],
            fg="#ffffff",
            activebackground=THEME["accent_cyan"],
            bd=0,
            padx=14,
            pady=5,
            cursor="hand2",
            command=self.on_generate_pdf
        )
        btn_pdf.pack(side=tk.LEFT, padx=(0, 6))

        btn_bench = tk.Button(
            toolbar,
            text="🧪 Run 10-URL Benchmark",
            font=("Helvetica", 9),
            bg=THEME["border"],
            fg=THEME["text_light"],
            activebackground=THEME["accent_blue"],
            bd=0,
            padx=12,
            pady=5,
            cursor="hand2",
            command=self.on_run_benchmark
        )
        btn_bench.pack(side=tk.LEFT, padx=(0, 6))

        btn_about = tk.Button(
            toolbar,
            text="ℹ️ About & Methodology",
            font=("Helvetica", 9),
            bg=THEME["border"],
            fg=THEME["text_light"],
            activebackground=THEME["accent_blue"],
            bd=0,
            padx=12,
            pady=5,
            cursor="hand2",
            command=self.on_about
        )
        btn_about.pack(side=tk.RIGHT)

        # ---------------- 6. Status Bar ----------------
        self.status_bar = tk.Label(
            master,
            textvariable=self.var_status,
            font=("Helvetica", 8),
            fg=THEME["text_muted"],
            bg=THEME["bg_main"],
            anchor="w"
        )
        self.status_bar.pack(fill=tk.X)

    # =========================================================================
    # UI ACTIONS & HANDLERS
    # =========================================================================

    def _draw_gauge(self, score: int, color_hex: str):
        self.canvas_gauge.delete("all")
        width = self.canvas_gauge.winfo_width()
        if width <= 1:
            width = 460
        height = 18

        # Background track
        self.canvas_gauge.create_rectangle(0, 0, width, height, fill=THEME["bg_input"], width=0)

        # Score bar
        fill_width = int((max(0, min(score, 100)) / 100.0) * width)
        if fill_width > 0:
            self.canvas_gauge.create_rectangle(0, 0, fill_width, height, fill=color_hex, width=0)

    def on_paste(self):
        try:
            clipboard_text = self.root.clipboard_get().strip()
            if clipboard_text:
                self.var_url.set(clipboard_text)
                self.var_status.set("URL pasted from clipboard.")
        except Exception:
            messagebox.showinfo("Clipboard", "Clipboard is empty or does not contain text.")

    def on_clear(self):
        self.var_url.set("")
        self.current_result = None
        self.score_lbl.configure(text="-- / 100", fg=THEME["text_muted"])
        self.tier_badge.configure(text="STANDBY", bg=THEME["border"])
        self._draw_gauge(0, THEME["border"])
        self.verdict_lbl.configure(text="Enter a URL above to perform automated heuristic security triage.")
        for key in self.anatomy_labels:
            self.anatomy_labels[key].configure(text="--", fg=THEME["text_light"])
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.var_status.set("Reset to standby.")

    def on_select_preset(self, event=None):
        chosen = self.var_preset.get()
        for name, url in PRESET_SAMPLES:
            if name == chosen and url:
                self.var_url.set(url)
                self.on_analyze()
                break

    def on_analyze(self):
        raw_url = self.var_url.get().strip()
        if not raw_url:
            messagebox.showwarning("Input Required", "Please enter or paste a URL to scan.")
            return

        self.var_status.set(f"Analyzing {raw_url}...")
        self.root.update_idletasks()

        # Run scoring
        result = score_url(raw_url)
        self.current_result = result

        # DNS Check (Optional worker thread or fast lookup)
        dns_info = None
        if self.var_dns.get() and result.get("hostname"):
            self.var_status.set(f"Resolving DNS for {result['hostname']}...")
            self.root.update_idletasks()
            dns_info = resolve_dns(result["hostname"], timeout=2.0)
            result["dns_info"] = dns_info

        self._render_results(result, dns_info)

    def _render_results(self, result: dict, dns_info: dict = None):
        score = result["score"]
        tier = result["risk_level"]
        verdict = result["verdict"]

        # Color-coded tier styling
        if tier == "Critical Risk":
            color = THEME["crit_risk"]
        elif tier == "High Risk":
            color = THEME["high_risk"]
        elif tier == "Medium Risk":
            color = THEME["med_risk"]
        else:
            color = THEME["low_risk"]

        self.score_lbl.configure(text=f"{score} / 100", fg=color)
        self.tier_badge.configure(text=tier.upper(), bg=color)
        self._draw_gauge(score, color)
        self.verdict_lbl.configure(text=verdict)

        # Update Anatomy Card
        parsed = urlparse(result["url"] if "://" in result["url"] else "http://" + result["url"])
        scheme_txt = f"{parsed.scheme.upper()} ({'TLS Encrypted' if parsed.scheme == 'https' else 'Plain Unencrypted'})"
        self.anatomy_labels["scheme"].configure(text=scheme_txt, fg=THEME["low_risk"] if parsed.scheme == 'https' else THEME["med_risk"])
        self.anatomy_labels["hostname"].configure(text=result["hostname"] or "N/A")

        # Subdomain splitting
        host_parts = (result["hostname"] or "").split(".")
        if len(host_parts) > 2:
            subdomain_txt = ".".join(host_parts[:-2])
        else:
            subdomain_txt = "(None)"
        self.anatomy_labels["subdomain"].configure(text=subdomain_txt)

        path_q = f"{parsed.path or '/'} {parsed.query or ''}".strip()
        self.anatomy_labels["path_query"].configure(text=path_q[:45] + ("..." if len(path_q) > 45 else ""))

        # DNS resolution text
        if dns_info:
            if dns_info["status"] == "resolved":
                ip_str = ", ".join(dns_info["ips"][:2])
                self.anatomy_labels["dns_ip"].configure(text=f"{ip_str} (Live Resolving)", fg=THEME["low_risk"])
            elif dns_info["status"] == "raw_ip":
                self.anatomy_labels["dns_ip"].configure(text=f"{dns_info['ips'][0]} (Raw IP Host)", fg=THEME["high_risk"])
            elif dns_info["status"] == "nxdomain":
                self.anatomy_labels["dns_ip"].configure(text="NXDOMAIN (Unregistered / Taken Down)", fg=THEME["med_risk"])
            else:
                self.anatomy_labels["dns_ip"].configure(text=f"Lookup failed ({dns_info.get('error', 'timeout')})", fg=THEME["text_muted"])
        else:
            self.anatomy_labels["dns_ip"].configure(text="DNS Lookup Disabled / Skipped", fg=THEME["text_muted"])

        # Populate Indicators Table
        for row in self.tree.get_children():
            self.tree.delete(row)

        breakdown = result.get("breakdown", [])
        if not breakdown:
            self.tree.insert("", tk.END, values=("Clean Lexical Baseline", "+0 pts", "No suspicious lexical patterns or phishing indicators detected."))
        else:
            for item in breakdown:
                self.tree.insert("", tk.END, values=(item["factor"], f"+{item['points']} pts", item["reason"]))

        self.var_status.set(f"Audit Complete: Scored {score}/100 ({tier}) with {len(breakdown)} indicator(s) flagged.")

    def on_copy_summary(self):
        if not self.current_result:
            messagebox.showinfo("Copy Summary", "Please analyze a URL first.")
            return

        res = self.current_result
        lines = [
            "==================================================",
            "⚡ PEER'S PHISH DETECTOR — URL AUDIT SUMMARY",
            "==================================================",
            f"Target URL   : {res['url']}",
            f"Hostname     : {res['hostname']}",
            f"Risk Score   : {res['score']} / 100",
            f"Risk Tier    : {res['risk_level']}",
            f"Verdict      : {res['verdict']}",
            f"Indicators   : {res['indicators_triggered']} triggered",
            "--------------------------------------------------",
            "Breakdown of Factors:"
        ]
        if not res["breakdown"]:
            lines.append("  - (None: Clean baseline URL)")
        else:
            for item in res["breakdown"]:
                lines.append(f"  * {item['factor']} (+{item['points']} pts): {item['reason']}")
        lines.append("==================================================")
        summary_text = "\n".join(lines)

        self.root.clipboard_clear()
        self.root.clipboard_append(summary_text)
        messagebox.showinfo("Clipboard", "Audit summary successfully copied to clipboard!")

    def on_export_json(self):
        if not self.current_result:
            messagebox.showinfo("Export JSON", "Please analyze a URL first.")
            return

        default_name = "url_audit_report.json"
        save_path = filedialog.asksaveasfilename(
            initialdir=os.path.join(CURRENT_DIR, "reports"),
            initialfile=default_name,
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        if not save_path:
            return

        try:
            with open(save_path, "w", encoding="utf-8") as f:
                json.dump(self.current_result, f, indent=4)
            messagebox.showinfo("Export Success", f"Audit report saved successfully to:\n{save_path}")
        except Exception as e:
            messagebox.showerror("Export Failed", f"Failed to save JSON: {e}")

    def on_generate_pdf(self):
        if not PDF_AVAILABLE:
            messagebox.showerror("ReportLab Required", "PDF generator script not found or ReportLab package is missing.")
            return

        try:
            out_path = create_day03_report()
            messagebox.showinfo(
                "PDF Generated Successfully",
                f"Official Day 03 Cybersecurity Internship Report compiled at:\n\n{out_path}"
            )
        except Exception as e:
            messagebox.showerror("PDF Generation Error", f"An error occurred while compiling PDF: {e}")

    def on_run_benchmark(self):
        """Run the 10-URL benchmark in a popup dialog."""
        bench_path = os.path.join(CURRENT_DIR, "test_urls.json")
        if not os.path.exists(bench_path):
            messagebox.showerror("Benchmark Missing", f"Could not find test dataset at:\n{bench_path}")
            return

        with open(bench_path, "r", encoding="utf-8") as f:
            test_cases = json.load(f)

        win = tk.Toplevel(self.root)
        win.title("🧪 PEER'S Phish Detector — 10-URL Empirical Benchmark Suite")
        win.geometry("900x520")
        win.configure(bg=THEME["bg_main"])

        lbl = tk.Label(win, text="10-URL EMPIRICAL BENCHMARK AUDIT RESULTS", font=("Helvetica", 12, "bold"), fg=THEME["accent_cyan"], bg=THEME["bg_main"])
        lbl.pack(pady=10)

        cols = ("id", "url", "score", "actual", "expected", "match")
        b_tree = ttk.Treeview(win, columns=cols, show="headings", height=12)
        b_tree.heading("id", text="#")
        b_tree.heading("url", text="Evaluated URL")
        b_tree.heading("score", text="Score")
        b_tree.heading("actual", text="Actual Tier")
        b_tree.heading("expected", text="Expected Tier")
        b_tree.heading("match", text="Status")

        b_tree.column("id", width=35, anchor="center")
        b_tree.column("url", width=420, anchor="w")
        b_tree.column("score", width=65, anchor="center")
        b_tree.column("actual", width=110, anchor="center")
        b_tree.column("expected", width=110, anchor="center")
        b_tree.column("match", width=90, anchor="center")

        b_tree.pack(fill=tk.BOTH, expand=True, padx=12, pady=6)

        matches = 0
        for item in test_cases:
            res = score_url(item["url"])
            is_match = (res["risk_level"].lower() == item["expected_risk"].lower())
            if is_match:
                matches += 1
            status = "MATCH" if is_match else "DIVERGENT"
            b_tree.insert("", tk.END, values=(item["id"], item["url"], f"{res['score']}/100", res["risk_level"], item["expected_risk"], status))

        summary_lbl = tk.Label(
            win,
            text=f"Benchmark Outcome: {matches}/{len(test_cases)} tests aligned. Note: Divergence in #8 demonstrates the 'HTTPS Phishing Paradox'.",
            font=("Helvetica", 9),
            fg=THEME["low_risk"] if matches >= 8 else THEME["med_risk"],
            bg=THEME["bg_main"]
        )
        summary_lbl.pack(pady=8)

    def on_about(self):
        about_text = (
            "⚡ PEER'S PHISH DETECTOR v2.0\n"
            "Sqrock IT Solution | Alpha 2 Cybersecurity Track (Day 03)\n"
            "Author: Md Peer Siddiqui\n\n"
            "8 BALANCED HEURISTIC RULES:\n"
            "1. Unencrypted HTTP Protocol (+20 pts)\n"
            "2. Raw IP Hostname Detection (+35 pts)\n"
            "3. Subdomain Nesting & Brand Spoofing (+25 pts)\n"
            "4. Sensitive Credential Action Keywords (+25 pts)\n"
            "5. Brand Homoglyphs & Typosquatting (+30 pts)\n"
            "6. High-Abuse Disposable TLD Scrutiny (+15 pts)\n"
            "7. URL Shortener Redirection Masking (+25 pts)\n"
            "8. Hostname Hyphen Density & Length (+15 pts)\n\n"
            "TRANSPARENT RISK TIERS:\n"
            "• Low Risk (0–19): No suspicious lexical indicators detected.\n"
            "• Medium Risk (20–49): Procedural signals detected; caution advised.\n"
            "• High Risk (50–74): Significant phishing indicators detected.\n"
            "• Critical Risk (75–100): Composite high-severity threat signature.\n\n"
            "NOTE: Designed for safe lexical URL triage. Does not initiate dangerous "
            "remote page code execution. Total score capped at 100 points."
        )
        messagebox.showinfo("About PEER'S Phish Detector", about_text)


def launch_gui():
    """Main GUI launcher with window lifecycle handling."""
    root = tk.Tk()
    app = PhishDetectorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    launch_gui()
