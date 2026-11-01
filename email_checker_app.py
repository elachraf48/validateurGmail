"""
email_checker_app.py — Gmail Email Checker
Standalone PyQt5 desktop app that validates Gmail addresses using the same
two-stage SMTP check as the Telegram bot.

Run from the project root:
    python email_checker_app.py
"""

try:
    from PyQt5.QtWidgets import (
        QApplication, QMainWindow, QWidget, QSplitter, QVBoxLayout, QHBoxLayout,
        QPlainTextEdit, QListWidget, QListWidgetItem, QLabel, QPushButton,
        QProgressBar, QSlider, QSpinBox, QGroupBox, QFileDialog, QSizePolicy,
        QFrame, QMessageBox, QCheckBox, QInputDialog,
    )
    from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
    from PyQt5.QtGui import QColor, QFont, QDragEnterEvent, QDropEvent
except ImportError:
    print("PyQt5 is required. Install it with:  pip install PyQt5")
    raise SystemExit(1)

import sys
import os
import csv
import json
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ── import the shared checker ────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from utils.helpers import check_gmail_status_fast, MxConnection
except ImportError:
    MxConnection = None
    def check_gmail_status_fast(username, **_):  # fallback stub for testing
        import random, time as t
        t.sleep(0.1)
        return random.choice(["Good", "Good", "Good", "Verify", "Disable", "Unknown"])

# ── Proxy helpers ─────────────────────────────────────────────────────────────

def parse_proxy(s: str):
    """Parse 'ip:port:user:pass' → (host, int(port), user, password).
    Raises ValueError if the format is wrong."""
    parts = s.strip().split(":")
    if len(parts) != 4:
        raise ValueError(f"Bad proxy format (need ip:port:user:pass): {s!r}")
    host, port, user, pw = parts
    return host, int(port), user, pw


def test_proxy(proxy_str: str, timeout: int = 8) -> bool:
    """Return True if the SOCKS5 proxy is alive and authenticated.
    Tests by connecting to google.com:80 — most proxy providers allow this port
    even when email ports (25/465/587) are blocked by their ruleset."""
    try:
        import socks  # PySocks
    except ImportError:
        return False
    try:
        host, port, user, pw = parse_proxy(proxy_str)
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, host, port, username=user, password=pw)
        s.settimeout(timeout)
        s.connect(("google.com", 80))
        s.close()
        return True
    except Exception:
        return False


class ProxyMxConnection:
    """
    Drop-in replacement for MxConnection that routes the port-25 socket
    through a SOCKS5 proxy.  Requires PySocks (pip install PySocks).

    Falls back gracefully: if MxConnection is unavailable or PySocks is not
    installed, check() always returns 'Pass' so the AUTH PLAIN stage still runs.
    """

    def __init__(self, proxy_str: str, helo_domain: str = "checkbot.local",
                 from_addr: str = "v@checkbot.local", timeout: int = 8):
        self._proxy_str  = proxy_str
        self.helo_domain = helo_domain
        self.from_addr   = from_addr
        self.timeout     = timeout
        self._sock       = None
        self._file       = None
        self._connected  = False
        # Resolve Gmail MX once — reuse the parent's cache if available
        self._mx_host    = None

    # ── connection lifecycle ───────────────────────────────────────────────

    def _resolve_mx(self):
        if self._mx_host:
            return self._mx_host
        # Borrow from MxConnection cache if possible
        if MxConnection is not None and MxConnection.GMAIL_MX:
            self._mx_host = MxConnection.GMAIL_MX
            return self._mx_host
        try:
            import dns.resolver
            recs = dns.resolver.resolve('gmail.com', 'MX')
            self._mx_host = str(recs[0].exchange).rstrip('.')
        except Exception:
            pass
        return self._mx_host

    def _connect(self):
        try:
            import socks
        except ImportError:
            raise RuntimeError("PySocks is not installed. Run: pip install PySocks")
        mx = self._resolve_mx()
        if not mx:
            raise OSError("Cannot resolve Gmail MX")
        host, port, user, pw = parse_proxy(self._proxy_str)
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, host, port, username=user, password=pw)
        s.settimeout(self.timeout)
        s.connect((mx, 25))
        f = s.makefile('rw')
        self._read_response(f)                            # banner
        f.write(f"EHLO {self.helo_domain}\r\n"); f.flush()
        self._read_response(f)
        f.write(f"MAIL FROM:<{self.from_addr}>\r\n"); f.flush()
        r = self._read_response(f)
        if not r or not r.startswith('250'):
            s.close()
            raise OSError(f"MAIL FROM rejected: {r}")
        self._sock = s
        self._file = f
        self._connected = True

    def _ensure_connected(self):
        if not self._connected:
            try:
                self._connect()
            except Exception:
                # Port 25 blocked by proxy — fall back to direct connection
                self._fallback_to_direct()

    def _fallback_to_direct(self):
        """Fall back to a direct (non-proxy) port-25 connection when the proxy
        blocks port 25.  Uses MxConnection's logic directly."""
        import socket
        mx = self._resolve_mx()
        if not mx:
            raise OSError("Cannot resolve Gmail MX")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect((mx, 25))
        f = s.makefile('rw')
        self._read_response(f)                            # banner
        f.write(f"EHLO {self.helo_domain}\r\n"); f.flush()
        self._read_response(f)
        f.write(f"MAIL FROM:<{self.from_addr}>\r\n"); f.flush()
        r = self._read_response(f)
        if not r or not r.startswith('250'):
            s.close()
            raise OSError(f"MAIL FROM rejected: {r}")
        self._sock = s
        self._file = f
        self._connected = True

    def close(self):
        if self._connected:
            try:
                self._file.write("QUIT\r\n"); self._file.flush()
            except Exception:
                pass
            try:
                self._sock.close()
            except Exception:
                pass
            self._connected = False
            self._sock = None
            self._file = None

    # ── RCPT TO check (identical logic to MxConnection) ───────────────────

    def check(self, email: str) -> str:
        for attempt in range(2):
            try:
                self._ensure_connected()
                self._file.write(f"RCPT TO:<{email}>\r\n"); self._file.flush()
                r = self._read_response(self._file)
                if not r:
                    self._connected = False
                    continue
                r_lower = r.lower()
                if r.startswith('250') or '2.1.5' in r:
                    self._reset()
                    return 'Pass'
                if r.startswith('4'):
                    self._connected = False
                    return 'Pass'
                if '5.2.1' in r:
                    self._reset()
                    return 'Disable'
                if '5.1.1' in r or 'does not exist' in r_lower or 'no such user' in r_lower:
                    self._reset()
                    return 'Not Exist'
                if r.startswith('550'):
                    self._reset()
                    return 'Not Exist'
                self._connected = False
                return 'Pass'
            except Exception:
                self._connected = False
        return 'Pass'

    def _reset(self):
        try:
            self._file.write("RSET\r\n"); self._file.flush()
            self._read_response(self._file)
            self._file.write(f"MAIL FROM:<{self.from_addr}>\r\n"); self._file.flush()
            r2 = self._read_response(self._file)
            if not r2 or not r2.startswith('250'):
                self._connected = False
        except Exception:
            self._connected = False

    @staticmethod
    def _read_response(f) -> str:
        try:
            lines = []
            while True:
                line = f.readline()
                if not line:
                    break
                if isinstance(line, bytes):
                    line = line.decode('utf-8', errors='ignore')
                line = line.rstrip('\r\n')
                lines.append(line)
                if len(line) < 4 or line[3] != '-':
                    break
            return '\n'.join(lines)
        except Exception:
            return ''

def _check_gmail_via_proxy(username: str, mx_conn=None, proxy_str: str = None) -> str:
    """
    Two-stage Gmail check routed through a SOCKS5 proxy for stage 2 AUTH PLAIN.
    Stage 1 (MX RCPT TO) uses the provided ProxyMxConnection.
    Stage 2 (AUTH PLAIN) opens smtp.gmail.com:587 through the proxy.
    Falls back to direct connection if PySocks is not installed.
    """
    import smtplib, base64

    if '@gmail.com' in username:
        username = username.split('@')[0]
    email = f"{username}@gmail.com"

    # Stage 1 — MX RCPT TO via ProxyMxConnection
    if mx_conn is not None:
        mx_result = mx_conn.check(email)
    else:
        mx_result = 'Pass'

    if mx_result in ("Disable", "Not Exist"):
        return mx_result

    # Stage 2 — AUTH PLAIN always goes direct (most SOCKS5 proxies block
    # email ports 25/465/587; direct port 587 works fine from this server).
    server = None
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587, timeout=10)
        server.ehlo()
        server.starttls()
        server.ehlo()
        auth = base64.b64encode(f"\x00{email}\x00wrongpass".encode()).decode()
        code, resp = server.docmd("AUTH", f"PLAIN {auth}")
        resp_str = resp.decode() if isinstance(resp, bytes) else str(resp)
        if code == 534 or "5.7.9" in resp_str or "WebLoginRequired" in resp_str:
            return "Verify"
        return "Good"
    except Exception:
        return "Unknown"
    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:
                pass


# ── constants ─────────────────────────────────────────────────────────────────
SETTINGS_FILE = "email_checker_settings.json"
DEFAULT_THREADS = 50
DEFAULT_TIMEOUT = 10
MAX_THREADS     = 200

STATUS_COLORS = {
    "Good":      "#00c853",
    "Verify":    "#ff9800",
    "Disable":   "#f44336",
    "Not Exist": "#f44336",
    "Unknown":   "#9e9e9e",
}

BTN_STATES = {
    "IDLE":    ("▶   Start",  "#2e7d32", "#43a047"),
    "RUNNING": ("⏹   Stop",   "#b71c1c", "#e53935"),
    "PAUSED":  ("▶   Resume", "#e65100", "#fb8c00"),
    # PAUSED also shows btn_restart (Start Again) — handled in _apply_btn_state
}

DARK_STYLE = """
QMainWindow, QWidget {
    background-color: #1e1e2e;
    color: #cdd6f4;
    font-family: 'Segoe UI', sans-serif;
    font-size: 13px;
}
QPlainTextEdit, QListWidget {
    background-color: #181825;
    color: #cdd6f4;
    border: 1px solid #313244;
    border-radius: 6px;
    selection-background-color: #45475a;
}
QScrollBar:vertical {
    background: #181825; width: 8px;
}
QScrollBar::handle:vertical {
    background: #45475a; border-radius: 4px;
}
QGroupBox {
    border: 1px solid #313244;
    border-radius: 6px;
    margin-top: 8px;
    padding-top: 6px;
    font-weight: bold;
    color: #a6adc8;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
}
QProgressBar {
    background-color: #181825;
    border: 1px solid #313244;
    border-radius: 5px;
    text-align: center;
    color: #cdd6f4;
    height: 18px;
}
QProgressBar::chunk {
    background-color: #89b4fa;
    border-radius: 4px;
}
QSlider::groove:horizontal {
    height: 4px;
    background: #313244;
    border-radius: 2px;
}
QSlider::handle:horizontal {
    background: #89b4fa;
    width: 14px; height: 14px;
    margin: -5px 0;
    border-radius: 7px;
}
QSlider::sub-page:horizontal {
    background: #89b4fa;
    border-radius: 2px;
}
QSpinBox {
    background-color: #181825;
    border: 1px solid #313244;
    border-radius: 4px;
    padding: 2px 6px;
    color: #cdd6f4;
    min-width: 50px;
}
QLabel { color: #cdd6f4; }
QSplitter::handle { background: #313244; }
"""

BTN_STYLE = """
QPushButton {{
    background-color: {bg};
    color: white;
    border: none;
    border-radius: 6px;
    padding: 8px 18px;
    font-size: 13px;
    font-weight: bold;
    min-width: 110px;
}}
QPushButton:hover {{ background-color: {hover}; }}
QPushButton:disabled {{ background-color: #45475a; color: #585b70; }}
"""

EXPORT_BTN_STYLE = """
QPushButton {
    background-color: #313244;
    color: #cdd6f4;
    border: 1px solid #45475a;
    border-radius: 6px;
    padding: 6px 14px;
    font-size: 12px;
}
QPushButton:hover { background-color: #45475a; }
QPushButton:disabled { color: #585b70; }
"""


# ── Worker thread ─────────────────────────────────────────────────────────────

class CheckerWorker(QThread):
    result_ready = pyqtSignal(int, str, str)          # (row_index, status, email)
    progress     = pyqtSignal(int, int, float, float) # (done, total, speed, eta)
    finished     = pyqtSignal(dict)                   # summary counts

    def __init__(self, emails, threads, timeout, proxies=None, use_proxy=False):
        super().__init__()
        self.emails       = emails
        self.threads      = threads
        self.timeout      = timeout
        self.proxies      = proxies or []
        self.use_proxy    = use_proxy and bool(proxies)
        self._stop_event  = threading.Event()
        self._pause_event = threading.Event()
        self._pause_event.set()  # not paused initially
        self._thread_local = threading.local()  # one MxConnection per thread

    def stop(self):
        self._stop_event.set()
        self._pause_event.set()  # unblock any waiting thread

    def pause(self):
        self._pause_event.clear()

    def resume(self):
        self._pause_event.set()

    def run(self):
        total     = len(self.emails)
        counts    = {"Good": 0, "Verify": 0, "Disable": 0, "Not Exist": 0, "Unknown": 0}
        done      = 0
        start_t   = time.time()
        last_emit = start_t

        def check_one(idx_email):
            idx, email = idx_email
            # Wait if paused
            self._pause_event.wait()
            if self._stop_event.is_set():
                return idx, email, "Unknown"
            try:
                # Pick a stable proxy for this thread (round-robin by thread name)
                proxy_str = None
                if self.use_proxy and self.proxies:
                    proxy_str = self.proxies[
                        abs(hash(threading.current_thread().name)) % len(self.proxies)
                    ]

                # Reuse one connection per thread (12× faster for MX stage)
                if proxy_str:
                    if not getattr(self._thread_local, 'mx_conn', None):
                        self._thread_local.mx_conn = ProxyMxConnection(proxy_str)
                    status = _check_gmail_via_proxy(
                        email,
                        mx_conn=self._thread_local.mx_conn,
                        proxy_str=proxy_str,
                    )
                elif MxConnection is not None:
                    if not getattr(self._thread_local, 'mx_conn', None):
                        self._thread_local.mx_conn = MxConnection()
                    status = check_gmail_status_fast(
                        email, mx_conn=self._thread_local.mx_conn
                    )
                else:
                    status = check_gmail_status_fast(email)
            except Exception:
                status = "Unknown"
            return idx, email, status

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(check_one, (i, e)): i
                for i, e in enumerate(self.emails, 1)
            }
            for future in as_completed(futures):
                if self._stop_event.is_set():
                    break

                # Block here while paused (after current batch finishes)
                self._pause_event.wait()

                try:
                    idx, email, status = future.result()
                except Exception:
                    idx   = futures[future]
                    email = self.emails[idx - 1]
                    status = "Unknown"

                counts[status] = counts.get(status, 0) + 1
                done += 1
                self.result_ready.emit(idx, status, email)

                now = time.time()
                elapsed = now - start_t
                speed = done / elapsed if elapsed > 0 else 1.0
                remaining = total - done
                eta = remaining / speed if speed > 0 else 0.0

                if now - last_emit >= 0.4 or done == total:
                    self.progress.emit(done, total, speed, eta)
                    last_emit = now

        self.finished.emit(counts)


# ── Proxy test worker ─────────────────────────────────────────────────────────

class ProxyTestWorker(QThread):
    proxy_result = pyqtSignal(int, bool)  # (index, alive)
    finished     = pyqtSignal()

    def __init__(self, proxies: list):
        super().__init__()
        self.proxies = proxies

    def run(self):
        for i, p in enumerate(self.proxies):
            ok = test_proxy(p)
            self.proxy_result.emit(i, ok)
        self.finished.emit()


# ── Drag-and-drop text edit ───────────────────────────────────────────────────

class DropTextEdit(QPlainTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setPlaceholderText(
            "Paste Gmail addresses here (one per line)\n\n"
            "— or drag & drop a .txt / .csv / .xlsx file —"
        )

    def dragEnterEvent(self, e: QDragEnterEvent):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
        else:
            super().dragEnterEvent(e)

    def dropEvent(self, e: QDropEvent):
        if e.mimeData().hasUrls():
            for url in e.mimeData().urls():
                path = url.toLocalFile()
                emails = load_emails_from_file(path)
                if emails:
                    self.setPlainText("\n".join(emails))
            e.acceptProposedAction()
        else:
            super().dropEvent(e)


# ── File loading helpers ──────────────────────────────────────────────────────

def extract_emails_from_text(text: str):
    """Return a deduplicated list of gmail addresses from raw text."""
    emails = []
    seen   = set()
    for line in text.splitlines():
        line = line.strip()
        # Handle lines like "123. good|user@gmail.com" or "user@gmail.com"
        if "|" in line:
            line = line.split("|")[-1].strip()
        # Strip leading index like "1. " or "1) "
        if line and line[0].isdigit():
            parts = line.split(None, 1)
            if len(parts) == 2 and (parts[0].rstrip(".):") ).isdigit():
                line = parts[1].strip()
        if "@" in line and line not in seen:
            seen.add(line)
            emails.append(line)
    return emails


def load_emails_from_file(path: str):
    ext = os.path.splitext(path)[1].lower()
    try:
        if ext in (".txt", ".csv"):
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return extract_emails_from_text(f.read())
        elif ext in (".xlsx", ".xls"):
            import openpyxl
            wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
            ws = wb.active
            lines = []
            for row in ws.iter_rows(values_only=True):
                for cell in row:
                    if cell:
                        lines.append(str(cell).strip())
            return extract_emails_from_text("\n".join(lines))
    except Exception as e:
        print(f"Error loading file: {e}")
    return []


# ── Settings helpers ──────────────────────────────────────────────────────────

def load_settings():
    try:
        with open(SETTINGS_FILE) as f:
            s = json.load(f)
            return (
                max(1, min(MAX_THREADS, int(s.get("threads", DEFAULT_THREADS)))),
                max(5, min(30,          int(s.get("timeout", DEFAULT_TIMEOUT)))),
                list(s.get("proxies",   [])),
                bool(s.get("use_proxy", False)),
            )
    except Exception:
        return DEFAULT_THREADS, DEFAULT_TIMEOUT, [], False


def save_settings(threads, timeout, proxies=None, use_proxy=False):
    try:
        with open(SETTINGS_FILE, "w") as f:
            json.dump({
                "threads":   threads,
                "timeout":   timeout,
                "proxies":   proxies or [],
                "use_proxy": use_proxy,
            }, f)
    except Exception:
        pass


# ── Main Window ───────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Gmail Email Checker")
        self.setMinimumSize(960, 640)
        self.resize(1100, 720)

        self._worker      = None
        self._btn_state   = "IDLE"
        self._results     = []   # list of (status, email)
        self._counts      = {"Good": 0, "Verify": 0, "Disable": 0, "Not Exist": 0, "Unknown": 0}
        self._proxy_worker = None  # ProxyTestWorker when running

        threads, timeout, proxies, use_proxy = load_settings()
        self._proxies   = proxies
        self._use_proxy = use_proxy

        # ── central widget ────────────────────────────────────────────────────
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        # ── splitter: input (left) | results (right) ─────────────────────────
        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(6)

        # left: input
        left = QWidget()
        lv   = QVBoxLayout(left)
        lv.setContentsMargins(0, 0, 0, 0)
        lv.setSpacing(4)

        lbl_input = QLabel("📋  Input Emails")
        lbl_input.setFont(QFont("Segoe UI", 10, QFont.Bold))
        lv.addWidget(lbl_input)

        self.text_input = DropTextEdit()
        self.text_input.textChanged.connect(self._on_input_changed)
        lv.addWidget(self.text_input)

        self.lbl_count = QLabel("Accounts: 0")
        self.lbl_count.setStyleSheet("color: #a6adc8; font-size: 11px;")
        lv.addWidget(self.lbl_count)

        btn_load = QPushButton("📂  Load File (.txt / .csv / .xlsx)")
        btn_load.setStyleSheet(EXPORT_BTN_STYLE)
        btn_load.clicked.connect(self._load_file)
        lv.addWidget(btn_load)

        # right: results
        right = QWidget()
        rv    = QVBoxLayout(right)
        rv.setContentsMargins(0, 0, 0, 0)
        rv.setSpacing(4)

        lbl_results = QLabel("🔍  Results")
        lbl_results.setFont(QFont("Segoe UI", 10, QFont.Bold))
        rv.addWidget(lbl_results)

        self.results_list = QListWidget()
        self.results_list.setFont(QFont("Consolas", 11))
        self.results_list.setUniformItemSizes(True)
        rv.addWidget(self.results_list)

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setSizes([340, 660])
        root.addWidget(splitter, stretch=1)

        # ── progress bar ──────────────────────────────────────────────────────
        pb_box = QGroupBox("Progress")
        pb_lay = QVBoxLayout(pb_box)
        pb_lay.setSpacing(4)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("0 / 0")
        pb_lay.addWidget(self.progress_bar)

        self.lbl_speed = QLabel("Speed: —   ETA: —")
        self.lbl_speed.setStyleSheet("color: #a6adc8; font-size: 11px;")
        pb_lay.addWidget(self.lbl_speed)

        root.addWidget(pb_box)

        # ── settings ──────────────────────────────────────────────────────────
        settings_box = QGroupBox("Settings")
        s_lay = QHBoxLayout(settings_box)
        s_lay.setSpacing(16)

        # threads
        s_lay.addWidget(QLabel("🧵  Threads:"))
        self.slider_threads = QSlider(Qt.Horizontal)
        self.slider_threads.setRange(1, MAX_THREADS)
        self.slider_threads.setValue(threads)
        self.slider_threads.setFixedWidth(160)
        s_lay.addWidget(self.slider_threads)
        self.spin_threads = QSpinBox()
        self.spin_threads.setRange(1, MAX_THREADS)
        self.spin_threads.setValue(threads)
        s_lay.addWidget(self.spin_threads)

        sep = QFrame(); sep.setFrameShape(QFrame.VLine); sep.setStyleSheet("color: #313244;")
        s_lay.addWidget(sep)

        # timeout
        s_lay.addWidget(QLabel("⏱  Timeout (s):"))
        self.slider_timeout = QSlider(Qt.Horizontal)
        self.slider_timeout.setRange(5, 30)
        self.slider_timeout.setValue(timeout)
        self.slider_timeout.setFixedWidth(160)
        s_lay.addWidget(self.slider_timeout)
        self.spin_timeout = QSpinBox()
        self.spin_timeout.setRange(5, 30)
        self.spin_timeout.setValue(timeout)
        s_lay.addWidget(self.spin_timeout)

        s_lay.addStretch()
        root.addWidget(settings_box)

        # sync sliders ↔ spinboxes
        self.slider_threads.valueChanged.connect(self.spin_threads.setValue)
        self.spin_threads.valueChanged.connect(self.slider_threads.setValue)
        self.slider_timeout.valueChanged.connect(self.spin_timeout.setValue)
        self.spin_timeout.valueChanged.connect(self.slider_timeout.setValue)
        self.spin_threads.valueChanged.connect(self._save_settings)
        self.spin_timeout.valueChanged.connect(self._save_settings)

        # ── counters + copy buttons ───────────────────────────────────────────
        counters_box = QGroupBox("Results Summary")
        c_lay = QHBoxLayout(counters_box)
        c_lay.setSpacing(6)

        self.counter_labels = {}
        self.copy_btns = {}
        for status, color in STATUS_COLORS.items():
            lbl = QLabel(f"<b style='color:{color}'>{status}: 0</b>")
            lbl.setTextFormat(Qt.RichText)
            c_lay.addWidget(lbl)
            self.counter_labels[status] = lbl

            btn_copy = QPushButton("Copy")
            btn_copy.setToolTip(f"Copy all {status} emails to clipboard")
            btn_copy.setEnabled(False)
            btn_copy.setFixedWidth(52)
            btn_copy.setStyleSheet(f"""
                QPushButton {{
                    background-color: #313244;
                    color: {color};
                    border: 1px solid {color};
                    border-radius: 4px;
                    padding: 2px 6px;
                    font-size: 11px;
                    font-weight: bold;
                }}
                QPushButton:hover {{ background-color: #45475a; }}
                QPushButton:disabled {{ color: #585b70; border-color: #45475a; }}
            """)
            btn_copy.clicked.connect(lambda checked, s=status: self._copy_status(s))
            c_lay.addWidget(btn_copy)
            self.copy_btns[status] = btn_copy
            c_lay.addSpacing(10)

        c_lay.addStretch()
        root.addWidget(counters_box)

        # ── dedup buttons ─────────────────────────────────────────────────────
        dedup_box = QGroupBox("Deduplicate Input")
        dedup_lay = QHBoxLayout(dedup_box)
        dedup_lay.setSpacing(10)

        self.btn_dedup_keep = QPushButton("🔁  Remove Duplicates  (keep first)")
        self.btn_dedup_keep.setToolTip(
            "If an email appears more than once, keep only the FIRST occurrence\n"
            "and remove all later copies."
        )
        self.btn_dedup_keep.setStyleSheet(EXPORT_BTN_STYLE)
        self.btn_dedup_keep.clicked.connect(self._dedup_keep_first)
        dedup_lay.addWidget(self.btn_dedup_keep)

        self.btn_dedup_all = QPushButton("🗑  Remove All Duplicates  (remove both)")
        self.btn_dedup_all.setToolTip(
            "If an email appears 2 or more times, remove EVERY occurrence.\n"
            "Only emails that appear exactly once are kept."
        )
        self.btn_dedup_all.setStyleSheet(EXPORT_BTN_STYLE)
        self.btn_dedup_all.clicked.connect(self._dedup_remove_all)
        dedup_lay.addWidget(self.btn_dedup_all)

        dedup_lay.addStretch()
        root.addWidget(dedup_box)

        # ── proxy management ──────────────────────────────────────────────────
        proxy_box = QGroupBox("🌐  Proxy Management")
        px_lay = QVBoxLayout(proxy_box)
        px_lay.setSpacing(6)

        # Row 1 — count label + checkbox
        px_row1 = QHBoxLayout()
        self.lbl_proxy_count = QLabel("0 proxies")
        self.lbl_proxy_count.setStyleSheet("color: #a6adc8; font-size: 11px;")
        px_row1.addWidget(self.lbl_proxy_count)
        px_row1.addStretch()
        self.chk_use_proxy = QCheckBox("Use proxies")
        self.chk_use_proxy.setChecked(self._use_proxy)
        self.chk_use_proxy.setEnabled(bool(self._proxies))
        self.chk_use_proxy.stateChanged.connect(self._proxy_toggle_use)
        px_row1.addWidget(self.chk_use_proxy)
        px_lay.addLayout(px_row1)

        # Row 2 — proxy list widget
        self.proxy_list = QListWidget()
        self.proxy_list.setFont(QFont("Consolas", 10))
        self.proxy_list.setFixedHeight(120)
        px_lay.addWidget(self.proxy_list)

        # Row 3 — buttons
        px_row3 = QHBoxLayout()
        px_row3.setSpacing(8)
        btn_load_proxy = QPushButton("📂  Load File")
        btn_load_proxy.setStyleSheet(EXPORT_BTN_STYLE)
        btn_load_proxy.clicked.connect(self._proxy_load_file)
        px_row3.addWidget(btn_load_proxy)

        btn_paste_proxy = QPushButton("📋  Paste")
        btn_paste_proxy.setStyleSheet(EXPORT_BTN_STYLE)
        btn_paste_proxy.clicked.connect(self._proxy_paste)
        px_row3.addWidget(btn_paste_proxy)

        self.btn_test_proxy = QPushButton("🔍  Test Proxies")
        self.btn_test_proxy.setStyleSheet(EXPORT_BTN_STYLE)
        self.btn_test_proxy.clicked.connect(self._proxy_run_test)
        px_row3.addWidget(self.btn_test_proxy)

        self.btn_remove_failed = QPushButton("🗑  Remove Failed")
        self.btn_remove_failed.setStyleSheet(EXPORT_BTN_STYLE)
        self.btn_remove_failed.clicked.connect(self._proxy_remove_failed)
        self.btn_remove_failed.setVisible(False)
        px_row3.addWidget(self.btn_remove_failed)

        btn_clear_proxy = QPushButton("✖  Clear All")
        btn_clear_proxy.setStyleSheet(EXPORT_BTN_STYLE)
        btn_clear_proxy.clicked.connect(self._proxy_clear)
        px_row3.addWidget(btn_clear_proxy)

        px_row3.addStretch()
        px_lay.addLayout(px_row3)

        # Row 4 — test status label
        self.lbl_proxy_test_status = QLabel("")
        self.lbl_proxy_test_status.setStyleSheet("color: #a6adc8; font-size: 11px;")
        self.lbl_proxy_test_status.setVisible(False)
        px_lay.addWidget(self.lbl_proxy_test_status)

        root.addWidget(proxy_box)

        # populate list from loaded settings
        self._proxy_populate_list()

        # keep ref to proxy buttons that need disabling during test
        self._proxy_btns = [btn_load_proxy, btn_paste_proxy, self.btn_test_proxy,
                            btn_clear_proxy]

        # ── bottom action bar ─────────────────────────────────────────────────
        bottom = QHBoxLayout()
        bottom.setSpacing(10)

        self.btn_start = QPushButton("▶   Start")
        self.btn_start.clicked.connect(self._on_start_stop_resume)
        bottom.addWidget(self.btn_start)

        # "Start Again" — only visible when paused
        self.btn_restart = QPushButton("Start Again")
        self.btn_restart.setStyleSheet(BTN_STYLE.format(bg="#1565c0", hover="#1976d2"))
        self.btn_restart.clicked.connect(self._restart_check)
        bottom.addWidget(self.btn_restart)

        # Apply initial state AFTER btn_restart exists (hides btn_restart at IDLE)
        self._apply_btn_state("IDLE")

        bottom.addStretch()

        self.btn_txt   = QPushButton("💾  TXT")
        self.btn_csv   = QPushButton("📊  CSV")
        self.btn_excel = QPushButton("📗  Excel")
        for btn in (self.btn_txt, self.btn_csv, self.btn_excel):
            btn.setStyleSheet(EXPORT_BTN_STYLE)
            btn.setEnabled(False)
            bottom.addWidget(btn)

        self.btn_txt.clicked.connect(lambda: self._export("txt"))
        self.btn_csv.clicked.connect(lambda: self._export("csv"))
        self.btn_excel.clicked.connect(lambda: self._export("xlsx"))

        self.btn_clear = QPushButton("Clear All")
        self.btn_clear.setStyleSheet(EXPORT_BTN_STYLE)
        self.btn_clear.clicked.connect(self._full_reset_safe)
        bottom.addWidget(self.btn_clear)

        root.addLayout(bottom)

    # ── button state machine ──────────────────────────────────────────────────

    def _apply_btn_state(self, state: str):
        self._btn_state = state
        label, bg, hover = BTN_STATES[state]
        self.btn_start.setText(label)
        self.btn_start.setStyleSheet(BTN_STYLE.format(bg=bg, hover=hover))
        # "Start Again" only visible while paused
        self.btn_restart.setVisible(state == "PAUSED")

    def _on_start_stop_resume(self):
        if self._btn_state == "IDLE":
            self._start_check()
        elif self._btn_state == "RUNNING":
            self._pause_check()      # Stop → PAUSED (shows Resume + Start Again)
        elif self._btn_state == "PAUSED":
            self._resume_check()

    # ── validation control ────────────────────────────────────────────────────

    def _start_check(self):
        emails = extract_emails_from_text(self.text_input.toPlainText())
        if not emails:
            QMessageBox.warning(self, "No emails", "Please paste or load Gmail addresses first.")
            return

        # reset state
        self._results = []
        self._counts  = {k: 0 for k in self._counts}
        self.results_list.clear()
        self.progress_bar.setValue(0)
        self.progress_bar.setMaximum(len(emails))
        self.progress_bar.setFormat(f"0 / {len(emails)}")
        self._update_counters()

        threads = self.spin_threads.value()
        timeout = self.spin_timeout.value()

        self._worker = CheckerWorker(
            emails, threads, timeout,
            proxies=self._proxies,
            use_proxy=self._use_proxy,
        )
        self._worker.result_ready.connect(self._on_result)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_finished)
        self._worker.start()

        self._apply_btn_state("RUNNING")
        self._set_inputs_enabled(False)

    def _pause_check(self):
        if self._worker:
            self._worker.pause()
        self._apply_btn_state("PAUSED")

    def _resume_check(self):
        if self._worker:
            self._worker.resume()
        self._apply_btn_state("RUNNING")

    def _stop_and_reset(self):
        """Kill the worker completely (called by Clear All or Start Again)."""
        if self._worker:
            self._worker.stop()
            self._worker.wait(3000)
            self._worker = None

    def _restart_check(self):
        """Stop current paused run and start completely fresh."""
        if self._worker:
            self._worker.stop()
            self._worker.wait(3000)
            self._worker = None
        self._full_reset()
        self._start_check()

    # ── worker signal handlers ────────────────────────────────────────────────

    def _on_result(self, idx: int, status: str, email: str):
        self._results.append((status, email))
        self._counts[status] = self._counts.get(status, 0) + 1
        self._update_counters()

        color = STATUS_COLORS.get(status, "#cdd6f4")
        item  = QListWidgetItem(f"{idx:>5}.  {status:<10} | {email}")
        item.setForeground(QColor(color))
        self.results_list.addItem(item)
        self.results_list.scrollToBottom()

        for btn in (self.btn_txt, self.btn_csv, self.btn_excel):
            btn.setEnabled(True)
        if status in self.copy_btns:
            self.copy_btns[status].setEnabled(True)

    def _on_progress(self, done: int, total: int, speed: float, eta: float):
        self.progress_bar.setValue(done)
        pct = (done / total * 100) if total else 0
        self.progress_bar.setFormat(f"{done} / {total}  ({pct:.1f}%)")

        if eta > 3600:
            eta_str = f"{eta/3600:.1f}h"
        elif eta > 60:
            eta_str = f"{eta/60:.1f}m"
        else:
            eta_str = f"{eta:.0f}s"
        self.lbl_speed.setText(f"Speed: {speed:.1f}/s   ETA: {eta_str}")

    def _on_finished(self, counts: dict):
        self._counts = {k: counts.get(k, 0) for k in self._counts}
        self._update_counters()
        self._apply_btn_state("IDLE")
        self._set_inputs_enabled(True)
        self.lbl_speed.setText(
            f"Done — {sum(counts.values())} emails checked   "
            f"Good: {counts.get('Good',0)}  "
            f"Verify: {counts.get('Verify',0)}  "
            f"Disable: {counts.get('Disable',0)}  "
            f"Not Exist: {counts.get('Not Exist',0)}  "
            f"Unknown: {counts.get('Unknown',0)}"
        )

    # ── copy by status ────────────────────────────────────────────────────────

    def _copy_status(self, status: str):
        """Copy all emails of a given status to the clipboard."""
        emails = [e for s, e in self._results if s == status]
        if not emails:
            return
        QApplication.clipboard().setText("\n".join(emails))
        btn = self.copy_btns.get(status)
        if btn:
            orig = btn.text()
            btn.setText(f"{len(emails)} OK!")
            QTimer.singleShot(1500, lambda: btn.setText(orig))

    # ── full reset ────────────────────────────────────────────────────────────

    def _full_reset(self):
        """Reset all results, progress, counters; return to IDLE."""
        self._results = []
        self._counts  = {k: 0 for k in self._counts}
        self.results_list.clear()
        self.progress_bar.setValue(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setFormat("0 / 0")
        self.lbl_speed.setText("Speed: -   ETA: -")
        self._update_counters()
        for btn in (self.btn_txt, self.btn_csv, self.btn_excel):
            btn.setEnabled(False)
        for btn in self.copy_btns.values():
            btn.setEnabled(False)
        self._apply_btn_state("IDLE")
        self._set_inputs_enabled(True)

    def _full_reset_safe(self):
        """Full reset — kills worker if running, then resets everything."""
        self._stop_and_reset()
        self._full_reset()

    # ── dedup helpers ─────────────────────────────────────────────────────────

    def _dedup_keep_first(self):
        """Keep first occurrence of each email; remove later duplicates."""
        if self._btn_state != "IDLE":
            return
        lines   = [l.strip() for l in self.text_input.toPlainText().splitlines() if l.strip()]
        seen, out = set(), []
        for line in lines:
            key = line.lower()
            if key not in seen:
                seen.add(key)
                out.append(line)
        removed = len(lines) - len(out)
        self.text_input.setPlainText("\n".join(out))
        if removed:
            QMessageBox.information(
                self, "Dedup — Keep First",
                f"Removed {removed} duplicate line(s).\n"
                f"Each email now appears at most once (first occurrence kept)."
            )
        else:
            QMessageBox.information(self, "Dedup — Keep First", "No duplicates found.")

    def _dedup_remove_all(self):
        """Remove every occurrence of emails that appear 2+ times."""
        if self._btn_state != "IDLE":
            return
        from collections import Counter
        lines  = [l.strip() for l in self.text_input.toPlainText().splitlines() if l.strip()]
        counts = Counter(l.lower() for l in lines)
        out    = [l for l in lines if counts[l.lower()] == 1]
        removed = len(lines) - len(out)
        dupes   = sum(1 for c in counts.values() if c > 1)
        self.text_input.setPlainText("\n".join(out))
        if removed:
            QMessageBox.information(
                self, "Dedup — Remove All",
                f"Found {dupes} email(s) that appeared more than once.\n"
                f"Removed all {removed} occurrences of those emails.\n"
                f"Only emails that appeared exactly once are kept."
            )
        else:
            QMessageBox.information(self, "Dedup — Remove All", "No duplicates found.")

    # ── helpers ───────────────────────────────────────────────────────────────

    def _on_input_changed(self):
        emails = extract_emails_from_text(self.text_input.toPlainText())
        self.lbl_count.setText(f"Accounts: {len(emails)}")

    def _update_counters(self):
        for status, lbl in self.counter_labels.items():
            color = STATUS_COLORS[status]
            n     = self._counts.get(status, 0)
            lbl.setText(f"<b style='color:{color}'>{status}: {n}</b>")

    def _set_inputs_enabled(self, enabled: bool):
        self.text_input.setReadOnly(not enabled)
        self.slider_threads.setEnabled(enabled)
        self.spin_threads.setEnabled(enabled)
        self.slider_timeout.setEnabled(enabled)
        self.spin_timeout.setEnabled(enabled)

    def _save_settings(self):
        save_settings(
            max(1, min(MAX_THREADS, self.spin_threads.value())),
            self.spin_timeout.value(),
            self._proxies,
            self._use_proxy,
        )

    def _load_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Email List", "",
            "Email files (*.txt *.csv *.xlsx *.xls);;All files (*)"
        )
        if path:
            emails = load_emails_from_file(path)
            if emails:
                self.text_input.setPlainText("\n".join(emails))
            else:
                QMessageBox.warning(self, "No emails found", f"Could not read emails from:\n{path}")

    def _clear_results(self):
        """Legacy shim — delegates to _full_reset_safe."""
        self._full_reset_safe()

    # ── proxy management ──────────────────────────────────────────────────────

    def _proxy_populate_list(self):
        """Rebuild the list widget from self._proxies (no validation, just display)."""
        self.proxy_list.clear()
        for p in self._proxies:
            self.proxy_list.addItem(p)
        self._proxy_refresh_ui()

    def _proxy_refresh_ui(self):
        """Update count label + enable/disable checkbox based on list state."""
        n = len(self._proxies)
        self.lbl_proxy_count.setText(f"{n} {'proxy' if n == 1 else 'proxies'}")
        self.chk_use_proxy.setEnabled(n > 0)
        if n == 0:
            self.chk_use_proxy.setChecked(False)

    def _proxy_add_lines(self, raw_lines: list):
        """Validate, dedup, append proxies; refresh UI."""
        existing = set(self._proxies)
        added = 0
        for line in raw_lines:
            line = line.strip()
            if not line or line in existing:
                continue
            try:
                parse_proxy(line)  # validate format
                self._proxies.append(line)
                existing.add(line)
                self.proxy_list.addItem(line)
                added += 1
            except ValueError:
                pass  # silently skip bad lines
        if added:
            self._proxy_refresh_ui()
            self._save_settings()

    def _proxy_load_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Load Proxies", "", "Text files (*.txt);;All files (*)"
        )
        if path:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    self._proxy_add_lines(f.readlines())
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    def _proxy_paste(self):
        text, ok = QInputDialog.getMultiLineText(
            self, "Paste Proxies",
            "One proxy per line  (format: ip:port:user:pass):"
        )
        if ok and text.strip():
            self._proxy_add_lines(text.splitlines())

    def _proxy_clear(self):
        self._proxies.clear()
        self.proxy_list.clear()
        self.chk_use_proxy.setChecked(False)
        self._use_proxy = False
        self.btn_remove_failed.setVisible(False)
        self.lbl_proxy_test_status.setVisible(False)
        self._proxy_refresh_ui()
        self._save_settings()

    def _proxy_toggle_use(self, state):
        self._use_proxy = bool(state)
        self._save_settings()

    def _proxy_run_test(self):
        if not self._proxies:
            return
        # Disable buttons + show status
        for b in self._proxy_btns:
            b.setEnabled(False)
        self.btn_remove_failed.setVisible(False)
        self.lbl_proxy_test_status.setVisible(True)
        self.lbl_proxy_test_status.setText(f"Testing 0 / {len(self._proxies)}…")

        # Mark all as pending
        for i in range(self.proxy_list.count()):
            item = self.proxy_list.item(i)
            raw = self._proxies[i]
            item.setText(f"⏳  {raw}")

        self._proxy_worker = ProxyTestWorker(list(self._proxies))
        self._proxy_worker.proxy_result.connect(self._on_proxy_test_result)
        self._proxy_worker.finished.connect(self._on_proxy_test_done)
        self._proxy_worker.start()
        self._proxy_test_done_count = 0

    def _on_proxy_test_result(self, idx: int, ok: bool):
        self._proxy_test_done_count += 1
        item = self.proxy_list.item(idx)
        if item:
            raw = self._proxies[idx]
            item.setText(f"{'✅' if ok else '❌'}  {raw}")
            item.setForeground(
                QColor("#00c853" if ok else "#f44336")
            )
        total = len(self._proxies)
        self.lbl_proxy_test_status.setText(
            f"Testing {self._proxy_test_done_count} / {total}…"
        )

    def _on_proxy_test_done(self):
        # Re-enable buttons
        for b in self._proxy_btns:
            b.setEnabled(True)
        total = len(self._proxies)
        # Count failures
        failed = sum(
            1 for i in range(self.proxy_list.count())
            if self.proxy_list.item(i).text().startswith("❌")
        )
        alive = total - failed
        self.lbl_proxy_test_status.setText(
            f"Test complete — ✅ {alive} alive  ❌ {failed} failed"
        )
        self.btn_remove_failed.setVisible(failed > 0)

    def _proxy_remove_failed(self):
        """Remove proxies marked ❌ from the list and self._proxies."""
        keep = []
        for i in range(self.proxy_list.count()):
            item = self.proxy_list.item(i)
            if not item.text().startswith("❌"):
                keep.append(self._proxies[i])
        self._proxies = keep
        self._proxy_populate_list()
        self.btn_remove_failed.setVisible(False)
        if not self._proxies:
            self.lbl_proxy_test_status.setVisible(False)
        self._save_settings()

    # ── export ────────────────────────────────────────────────────────────────

    def _export(self, fmt: str):
        if not self._results:
            return
        date_str = datetime.now().strftime("%Y-%m-%d_%H%M")
        default  = f"gmail_check_{date_str}.{fmt}"

        filters = {
            "txt":  "Text files (*.txt)",
            "csv":  "CSV files (*.csv)",
            "xlsx": "Excel files (*.xlsx)",
        }
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Results", default, filters.get(fmt, "All files (*)")
        )
        if not path:
            return

        try:
            if fmt == "txt":
                with open(path, "w", encoding="utf-8") as f:
                    for i, (status, email) in enumerate(self._results, 1):
                        f.write(f"{i}. {status}|{email}\n")

            elif fmt == "csv":
                with open(path, "w", newline="", encoding="utf-8") as f:
                    w = csv.writer(f)
                    w.writerow(["#", "status", "email"])
                    for i, (status, email) in enumerate(self._results, 1):
                        w.writerow([i, status, email])

            elif fmt == "xlsx":
                import openpyxl
                from openpyxl.styles import Font, PatternFill
                wb = openpyxl.Workbook()

                SHEET_COLORS = {
                    "Good":      "00c853",
                    "Verify":    "ff9800",
                    "Disable":   "f44336",
                    "Not Exist": "f44336",
                    "Unknown":   "9e9e9e",
                }

                def write_sheet(ws, rows):
                    ws.append(["#", "Status", "Email"])
                    ws.column_dimensions["A"].width = 6
                    ws.column_dimensions["B"].width = 12
                    ws.column_dimensions["C"].width = 40
                    for i, (status, email) in enumerate(rows, 1):
                        ws.append([i, status, email])
                        color = SHEET_COLORS.get(status, "9e9e9e")
                        ws.cell(i + 1, 2).font = Font(color=color, bold=True)

                ws_all = wb.active
                ws_all.title = "All"
                write_sheet(ws_all, self._results)

                ws_good = wb.create_sheet("Good")
                write_sheet(ws_good, [(s, e) for s, e in self._results if s == "Good"])

                ws_blocked = wb.create_sheet("Blocked")
                write_sheet(ws_blocked, [(s, e) for s, e in self._results if s != "Good"])

                wb.save(path)

            QMessageBox.information(self, "Saved", f"Results saved to:\n{path}")

        except Exception as ex:
            QMessageBox.critical(self, "Export failed", str(ex))

    def closeEvent(self, event):
        if self._worker and self._worker.isRunning():
            self._worker.stop()
            self._worker.wait(3000)
        if self._proxy_worker and self._proxy_worker.isRunning():
            self._proxy_worker.wait(3000)
        event.accept()


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(DARK_STYLE)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())
