#!/usr/bin/env python3
import sys
import os
import time
import keyring
import logging
from pathlib import Path
from urllib3.exceptions import InsecureRequestWarning
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import multiprocessing
from multiprocessing import Queue
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QLabel, QLineEdit, QTextEdit, QPushButton, QFileDialog, QCheckBox,
    QGroupBox, QFormLayout, QProgressBar, QMessageBox, QListWidget,
    QListWidgetItem, QSplitter, QFrame, QComboBox, QMenu, QDialog, QDialogButtonBox, QStatusBar
)
from PyQt6.QtCore import Qt, QSettings, QTimer
from PyQt6.QtGui import QFont, QColor, QIcon, QPixmap  # ✅ Added QIcon and QPixmap
import os  # ✅ Ensured for file checks

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ==============================
# WORKER PROCESS (SCAN LOGIC) - From original script
# ==============================
def worker_process(base_url, api_key, dry_run, targets_file, profile_id, start_scan, log_queue, finished_queue):
    import http.client as http_client
    http_client.HTTPConnection.debuglevel = 1
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True

    class ProcessHTTPLogger:
        def write(self, message):
            if message.strip():
                log_queue.put(("HTTP_RAW", message.strip()))
        def flush(self):
            pass

    http_logger = ProcessHTTPLogger()
    logging.getLogger().handlers = []
    handler = logging.StreamHandler(http_logger)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('[HTTP] %(message)s')
    handler.setFormatter(formatter)
    logging.getLogger().addHandler(handler)
    logging.getLogger("requests.packages.urllib3").addHandler(handler)

    # Normalize base_url to ensure /api/v1
    parsed = urlparse(base_url)
    if not parsed.path.startswith('/api/v1'):
        base_url = urljoin(base_url.rstrip('/') + '/', 'api/v1')
    else:
        base_url = f"{parsed.scheme}://{parsed.netloc}/api/v1"

    session = requests.Session()
    retry_strategy = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    def add_target(address):
        data = {"address": address, "description": "Added via GUI", "type": "default", "criticality": 10}
        try:
            # Internal retry for target addition
            for attempt in range(3):
                response = session.post(f"{base_url}/targets", json=data, headers={'X-Auth': api_key, 'Content-Type': 'application/json'}, verify=False)
                if response.status_code == 201:
                    return response.json().get('target_id')
                elif response.status_code == 429: # Too many requests
                    log_queue.put(("WARNING", f"Rate limited adding {address}, retrying in {2**attempt}s..."))
                    time.sleep(2**attempt)
                else:
                    break # Other error, don't retry
            log_queue.put(("ERROR", f"Failed to add {address}: {response.status_code} - {response.text}"))
            return None
        except Exception as e:
            log_queue.put(("ERROR", f"Network error {address}: {str(e)}"))
            return None

    def start_scan_func(target_id, profile_id):
        data = {
            "profile_id": profile_id,
            "incremental": False,
            "schedule": {"disable": False, "start_date": None, "time_sensitive": False},
            "user_authorized_to_scan": "yes",
            "target_id": target_id
        }
        try:
            response = session.post(f"{base_url}/scans", json=data, headers={'X-Auth': api_key, 'Content-Type': 'application/json'}, verify=False)
            if response.status_code in [200, 201]:
                scan_id = response.headers.get("Location", "").split("/")[-1]
                log_queue.put(("INFO", f"Scan started for {target_id} (Scan ID: {scan_id})"))
                return scan_id
            else:
                log_queue.put(("ERROR", f"Failed scan {target_id} (Code: {response.status_code}): {response.text}"))
                return None
        except Exception as e:
            log_queue.put(("ERROR", f"Network error scan {target_id}: {str(e)}"))
            return None

    def read_targets(filepath):
        targets = []
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if url and not url.startswith('#'):
                    targets.append(url)
        return targets

    # Main processing loop
    targets = read_targets(targets_file)
    log_queue.put(("INFO", f"Processing {len(targets)} targets..."))

    for url in targets:
        log_queue.put(("INFO", f"Processing target: {url}"))
        if dry_run:
            log_queue.put(("INFO", f"[DRY-RUN] Would add target: {url}"))
            if start_scan:
                log_queue.put(("INFO", f"[DRY-RUN] Would start scan with profile {profile_id}"))
        else:
            target_id = add_target(url)
            if target_id and start_scan:
                scan_id = start_scan_func(target_id, profile_id)
                if scan_id:
                    log_queue.put(("INFO", f"Successfully started scan for {url} (ID: {scan_id})"))
                else:
                    log_queue.put(("ERROR", f"Failed to start scan for {url}"))
            elif not target_id:
                log_queue.put(("ERROR", f"Failed to add target: {url}"))
        time.sleep(0.5)

    finished_queue.put("FINISHED")


# ==============================
# WORKER PROCESS (CLEAN LOGIC) - From bulk cleaner script
# ==============================
def clean_worker_process(base_url, api_key, log_queue, finished_queue, delete_targets=True, delete_scans=True):
    """
    Worker process to perform full cleanup.
    """
    from urllib.parse import urljoin, urlparse
    def normalize_acunetix_url(base_url):
        parsed = urlparse(base_url)
        if not parsed.path.startswith('/api/v1'):
            return urljoin(base_url.rstrip('/') + '/', 'api/v1')
        else:
            return f"{parsed.scheme}://{parsed.netloc}/api/v1"

    base_url = normalize_acunetix_url(base_url)
    headers = {'X-Auth': api_key, 'Content-Type': 'application/json'}
    session = requests.Session()
    retry_strategy = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    total_deleted = 0
    batch_size = 100
    iteration = 0

    log_queue.put(("INFO", f"Starting full cleanup process... (Delete targets: {delete_targets}, Delete scans: {delete_scans})"))
    log_queue.put(("INFO", f"Fetching targets in batches of {batch_size} and deleting them iteratively."))
    log_queue.put(("INFO", f"Base URL used: {base_url}"))

    try:
        while True:
            iteration += 1
            log_queue.put(("INFO", f"--- Iteration {iteration} ---"))

            # Fetch a batch of targets with pagination (l=limit)
            targets_url = f"{base_url}/targets?l={batch_size}"
            try:
                response = session.get(targets_url, headers=headers, verify=False)
                if response.status_code != 200:
                    log_queue.put(("ERROR", f"❌ Failed to fetch targets batch (HTTP {response.status_code}): {response.text}"))
                    break

                data = response.json()
                targets = data.get('targets', [])

                if not targets:
                    log_queue.put(("INFO", "No more targets found."))
                    break # Stop loop if no targets found

                target_ids_to_delete = [t.get('target_id') for t in targets if t.get('target_id')]
                log_queue.put(("INFO", f"Fetched {len(target_ids_to_delete)} targets for deletion in this iteration."))

            except requests.exceptions.RequestException as e:
                log_queue.put(("ERROR", f"❌ Request error fetching targets: {e}"))
                break
            except ValueError as e:
                log_queue.put(("ERROR", f"❌ JSON decode error fetching targets: {e}"))
                break

            # Abort scans and delete targets from this batch in parallel
            deleted_in_batch = 0
            max_workers = 10  # Adjust based on your Acunetix server capacity

            def delete_single_target(target_id):
                try:
                    # Abort scans for the target
                    if delete_scans:
                        scans_response = session.get(f"{base_url}/scans?target_id={target_id}", headers=headers, verify=False)
                        if scans_response.status_code == 200:
                            scans = scans_response.json().get('scans', [])
                            for scan in scans:
                                status = scan.get('status', '')
                                scan_id = scan.get('scan_id')
                                if status in ['processing', 'queued']:
                                    session.post(f"{base_url}/scans/{scan_id}/abort", headers=headers, verify=False)
                                    log_queue.put(("INFO", f"  - Aborted scan {scan_id} for target {target_id}"))

                    # Delete the target
                    if delete_targets:
                        del_response = session.delete(f"{base_url}/targets/{target_id}", headers=headers, verify=False)
                        if del_response.status_code == 204:
                            return target_id, True
                        else:
                            log_queue.put(("ERROR", f"  - Failed to delete target {target_id} (Code: {del_response.status_code})"))
                            return target_id, False
                    else:
                        # If not deleting targets, mark as processed
                        return target_id, True
                except requests.exceptions.RequestException as e:
                    log_queue.put(("ERROR", f"  - Error deleting target {target_id}: {e}"))
                    return target_id, False
                except Exception as e:
                    log_queue.put(("ERROR", f"  - Unexpected error for target {target_id}: {e}"))
                    return target_id, False

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Create a dictionary mapping future to target ID
                future_to_target_id = {executor.submit(delete_single_target, tid): tid for tid in target_ids_to_delete}
                for future in as_completed(future_to_target_id):
                    target_id, success = future.result()
                    if success:
                        if delete_targets:
                            deleted_in_batch += 1
                            total_deleted += 1
                        log_queue.put(("INFO", f"  - Processed target {target_id}"))
                    else:
                        # If deletion failed, error message is already sent in delete_single_target
                        pass

            log_queue.put(("INFO", f"Completed iteration {iteration}, processed {deleted_in_batch} targets. Total processed: {total_deleted}"))
            # Small pause to avoid overloading the API
            time.sleep(0.5)

    except Exception as e:
        log_queue.put(("ERROR", f"❌ Unexpected error during cleanup: {e}"))

    log_queue.put(("WARNING", "--- Cleanup Finished ---"))
    log_queue.put(("WARNING", f"Total targets processed: {total_deleted}"))
    finished_queue.put("FINISHED")


# ==============================
# CONFIRMATION DIALOG FOR CLEAN ALL (with options)
# ==============================
class CleanAllConfirmationDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("⚠️ Confirm Full Cleanup")
        self.setModal(True)
        layout = QVBoxLayout()

        warning = QLabel(
            "<b>This will perform a cleanup operation on your Acunetix instance.</b><br><br>"
            "Select what you want to delete:<br>"
        )
        warning.setWordWrap(True)
        layout.addWidget(warning)

        self.delete_targets_cb = QCheckBox("Delete all targets")
        self.delete_targets_cb.setChecked(True) # Checked by default
        self.delete_scans_cb = QCheckBox("Cancel and delete all scans")
        self.delete_scans_cb.setChecked(True) # Checked by default
        layout.addWidget(self.delete_targets_cb)
        layout.addWidget(self.delete_scans_cb)

        layout.addWidget(QLabel("To confirm, type <b>yes</b> below:"))
        self.input_line = QLineEdit()
        self.input_line.setPlaceholderText("Type 'yes' to confirm")
        layout.addWidget(self.input_line)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.setLayout(layout)

    def get_input(self):
        return self.input_line.text().strip()
    
    def get_delete_targets(self):
        return self.delete_targets_cb.isChecked()
    
    def get_delete_scans(self):
        return self.delete_scans_cb.isChecked()


# ==============================
# GUI - Updated with new features + logo
# ==============================
class AcunetixGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Acunetix Automation")
        self.resize(1100, 750)
        self.settings = QSettings("AcunetixAutomation", "GUI")
        self.worker_process = None
        self.clean_process = None # New process for cleanup
        self.log_queue = None
        self.finished_queue = None
        self.scan_timer = None
        self.clean_timer = None # New timer for cleanup
        self.current_targets = []
        self.worker_temp_file = None
        # State indicators for timerEvent
        self.is_cleaning = False
        self.is_scanning = False

        # Widgets
        self.url_input = QLineEdit()
        self.api_input = QLineEdit()
        self.api_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.show_api_btn = QPushButton("👁️")
        self.show_api_btn.setFixedWidth(40)
        self.targets_input = QLineEdit()
        self.targets_btn = QPushButton("Browse...")
        self.profile_combo = QComboBox()
        self.dry_run_cb = QCheckBox("Dry-run mode")
        self.test_btn = QPushButton(" Test Connection ")
        self.clean_all_btn = QPushButton("🧹 Clean All Scans & Targets") # Button added
        self.start_btn = QPushButton(" ▶️ Start Scans ")
        self.cancel_btn = QPushButton(" ⏹️ Cancel ")
        self.targets_list = QListWidget()
        # Search field for target list
        self.targets_filter = QLineEdit()
        self.targets_filter.setPlaceholderText("Filter targets...")
        self.log_text = QTextEdit()
        self.progress = QProgressBar()  # ✅ Progress bar
        self.progress_label = QLabel("Status: Idle")  # ✅ Status label
        self.progress.setStyleSheet("QProgressBar {"
                                    "border: 2px solid #FFA500;"
                                    "border-radius: 5px;"
                                    "text-align: center;"
                                    "color: #333;"
                                    "background-color: #f0f0f0;"
                                    "}"
                                    "QProgressBar::chunk {"
                                    "background-color: #FFA500;"  # ✅ Orange like logo
                                    "width: 20px;"
                                    "}")  # ✅ Orange progress chunk
        self.progress.setFormat("Progress: %p%")  # ✅ Show % value
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar) # Add status bar

        self.init_ui()
        self.load_settings()

    def init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)

        # === LOGO ===
        logo_path = "assets/logo.ico"  # ✅ Path to .ico file (preferred for Windows icons)
        logo_label = QLabel()
        
        if os.path.exists(logo_path):
            # Load icon for application (window)
            self.setWindowIcon(QIcon(logo_path))
            
            # Load logo as pixmap for display in interface
            pixmap = QPixmap(logo_path)
            # Resize for harmonious display (max 120x120)
            pixmap = pixmap.scaled(100, 100, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
            logo_label.setPixmap(pixmap)
            logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            main_layout.addWidget(logo_label)
            main_layout.addSpacing(10)  # Spacing between logo and config
        else:
            # Warning message if logo is missing
            self.log_message(f"⚠️ Logo not found: {logo_path}. Using placeholder.", "WARNING")
            logo_label = QLabel("🔒⚙️🔍")
            logo_label.setFont(QFont("Segoe UI", 24))
            logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            main_layout.addWidget(logo_label)
            main_layout.addSpacing(10)

        # === Main Tab ===
        main_layout_v = QVBoxLayout()
        config_group = QGroupBox("Acunetix Configuration")
        config_layout = QVBoxLayout()
        config_layout.addWidget(QLabel("Acunetix URL:"))
        config_layout.addWidget(self.url_input)
        config_layout.addWidget(QLabel("API Key:"))
        api_layout = QHBoxLayout()
        api_layout.addWidget(self.api_input)
        api_layout.addWidget(self.show_api_btn)
        config_layout.addLayout(api_layout)
        config_layout.addWidget(QLabel("Targets File:"))
        targets_layout = QHBoxLayout()
        targets_layout.addWidget(self.targets_input)
        targets_layout.addWidget(self.targets_btn)
        config_layout.addLayout(targets_layout)
        config_layout.addWidget(QLabel("Scan Profile:"))
        config_layout.addWidget(self.profile_combo)
        config_group.setLayout(config_layout)
        config_group.setFixedHeight(250)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.dry_run_cb)
        self.remove_selected_btn = QPushButton("🗑️ Remove Selected (local)")
        button_layout.addWidget(self.remove_selected_btn)
        button_layout.addStretch()
        button_layout.addWidget(self.test_btn)
        button_layout.addWidget(self.clean_all_btn) # Button added here
        button_layout.addWidget(self.start_btn)
        button_layout.addWidget(self.cancel_btn)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        left_panel = QWidget()
        left_layout = QVBoxLayout()
        left_layout.addWidget(QLabel("Targets to Scan:"))
        left_layout.addWidget(self.targets_filter) # Filter field
        left_layout.addWidget(self.targets_list)
        left_panel.setLayout(left_layout)
        left_panel.setFixedWidth(400)
        self.targets_list.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)

        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Consolas", 9))
        splitter.addWidget(left_panel)
        splitter.addWidget(self.log_text)
        splitter.setSizes([400, 700])

        # === LAYOUT ORDER: MAIN STRUCTURE ===
        main_layout_v.addWidget(config_group)
        main_layout_v.addLayout(button_layout)
        main_layout_v.addWidget(splitter)  # ✅ Splitter takes ALL remaining space above the progress bar

        # === PROGRESS BAR LAYOUT (fixed at bottom, above status bar) ===
        progress_layout = QHBoxLayout()
        progress_layout.addWidget(self.progress_label)
        progress_layout.addWidget(self.progress)
        progress_layout.setStretch(1, 1)  # ✅ Progress bar expands to fill space
        progress_layout.setContentsMargins(10, 5, 10, 5)  # Padding

        # Add progress layout to main layout — it will appear just above status bar
        main_layout_v.addLayout(progress_layout)

        # Final layout
        main_layout.addLayout(main_layout_v)

        # === Signals ===
        self.show_api_btn.clicked.connect(self.toggle_api_visibility)
        self.targets_btn.clicked.connect(self.browse_targets)
        self.targets_filter.textChanged.connect(self.filter_targets) # Signal for filter
        self.remove_selected_btn.clicked.connect(self.remove_selected_targets)
        self.test_btn.clicked.connect(self.test_connection)
        self.clean_all_btn.clicked.connect(self.clean_all_targets) # Added signal
        self.start_btn.clicked.connect(self.start_scans)
        self.cancel_btn.clicked.connect(self.cancel_scans)

        self.cancel_btn.setEnabled(False)
        self.log_text.verticalScrollBar().setValue(self.log_text.verticalScrollBar().maximum())
        self.profile_combo.addItem("Test connection first...", "")

    def toggle_api_visibility(self):
        if self.api_input.echoMode() == QLineEdit.EchoMode.Password:
            self.api_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.show_api_btn.setText("🙈")
        else:
            self.api_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.show_api_btn.setText("👁️")

    def browse_targets(self):
        file, _ = QFileDialog.getOpenFileName(self, "Targets File", "", "Text Files (*.txt)")
        if file:
            self.targets_input.setText(file)
            self.load_targets_preview(file)

    def load_targets_preview(self, filepath):
        self.targets_list.clear()
        self.current_targets = []
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    url = line.strip()
                    if url and not url.startswith('#'):
                        self.current_targets.append(url)
                        item = QListWidgetItem("⏳ " + url)
                        item.setForeground(QColor("#FFA500"))
                        self.targets_list.addItem(item)
            self.status_bar.showMessage(f"Loaded {len(self.current_targets)} targets from {os.path.basename(filepath)}")
        except Exception as e:
            self.log_message(f"Error loading targets: {e}", "ERROR")

    def filter_targets(self, text):
        """Filter list items based on entered text."""
        for i in range(self.targets_list.count()):
            item = self.targets_list.item(i)
            item.setHidden(text.lower() not in item.text().lower())

    def remove_selected_targets(self):
        selected_items = self.targets_list.selectedItems()
        if not selected_items:
            return
        urls_to_remove = set()
        for item in selected_items:
            text = item.text().replace("⏳ ", "").replace("✅ ", "").replace("❌ ", "")
            urls_to_remove.add(text)
        self.current_targets = [url for url in self.current_targets if url not in urls_to_remove]
        for item in selected_items:
            self.targets_list.takeItem(self.targets_list.row(item))
        self.log_message(f"Removed {len(selected_items)} target(s) (local only).", "INFO")
        self.status_bar.showMessage(f"Removed {len(selected_items)} targets, {len(self.current_targets)} remaining.")

    def log_message(self, message, level="INFO"):
        color = {"ERROR": "#ff6b6b", "WARNING": "#ffd166", "INFO": "#a0e7a0", "HTTP_RAW": "#888888"}.get(level, "#e0e0e0")
        formatted = f'<span style="color:{color};">[{level}] {message}</span>'
        self.log_text.append(formatted)
        was_at_bottom = self.log_text.verticalScrollBar().value() == self.log_text.verticalScrollBar().maximum()
        if was_at_bottom:
            self.log_text.verticalScrollBar().setValue(self.log_text.verticalScrollBar().maximum())

    def normalize_acunetix_url(self, base_url):
        parsed = urlparse(base_url)
        if not parsed.path.startswith('/api/v1'):
            return urljoin(base_url.rstrip('/') + '/', 'api/v1')
        else:
            return f"{parsed.scheme}://{parsed.netloc}/api/v1"

    def test_connection(self):
        self.test_btn.setEnabled(False)
        self.log_message("Testing connection...", "INFO")
        base_url = self.normalize_acunetix_url(self.url_input.text())
        headers = {'X-Auth': self.api_input.text(), 'Content-Type': 'application/json'}
        try:
            response = requests.get(f"{base_url}/targets", headers=headers, verify=False)
            if response.status_code == 200:
                self.log_message("✅ Connection successful!", "INFO")
                self.fetch_scan_profiles(base_url, headers)
            elif response.status_code == 401:
                self.log_message("❌ Invalid API key.", "ERROR")
            elif response.status_code == 403:
                self.log_message("❌ API key lacks permissions.", "ERROR")
            elif response.status_code == 404:
                self.log_message("❌ API endpoint not found – check URL.", "ERROR")
            else:
                self.log_message(f"❌ Connection failed (Code: {response.status_code}).", "ERROR")
                self.profile_combo.clear()
                self.profile_combo.addItem("Connection failed", "")
        except Exception as e:
            self.log_message(f"❌ Connection error: {e}", "ERROR")
            self.profile_combo.clear()
            self.profile_combo.addItem("Connection error", "")
        finally:
            QTimer.singleShot(100, lambda: self.test_btn.setEnabled(True))

    def fetch_scan_profiles(self, base_url, headers):
        try:
            response = requests.get(f"{base_url}/scanning_profiles", headers=headers, verify=False)
            if response.status_code == 200:
                data = response.json()
                profiles = data.get("scanning_profiles", [])
                self.profile_combo.clear()
                if not profiles:
                    self.profile_combo.addItem("No profiles found", "")
                    return
                profiles.sort(key=lambda x: x.get("sort_order", 0))
                for p in profiles:
                    name = p.get("name", "Unnamed")
                    pid = p.get("profile_id", "")
                    self.profile_combo.addItem(name, pid)
                self.log_message(f"✅ Loaded {len(profiles)} scan profiles.", "INFO")
            else:
                self.profile_combo.clear()
                self.profile_combo.addItem("Failed to load profiles", "")
        except Exception as e:
            self.log_message(f"⚠️ Error loading profiles: {e}", "WARNING")
            self.profile_combo.clear()
            self.profile_combo.addItem("Error loading profiles", "")

    def start_scans(self):
        if self.is_cleaning: # Prevent starting scan during cleanup
            self.log_message("Cannot start scans while a cleanup is in progress.", "ERROR")
            return
        if not self.current_targets:
            QMessageBox.warning(self, "Error", "No targets to scan.")
            return

        import tempfile
        temp_targets_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        temp_targets_file.write('\n'.join(self.current_targets))
        temp_targets_file.close()
        self.worker_temp_file = temp_targets_file.name

        keyring.set_password("acunetix_automation", "api_key", self.api_input.text())
        self.settings.setValue("url", self.url_input.text())

        self.log_queue = Queue()
        self.finished_queue = Queue()

        self.worker_process = multiprocessing.Process(
            target=worker_process,
            args=(
                self.url_input.text(),
                self.api_input.text(),
                self.dry_run_cb.isChecked(),
                self.worker_temp_file,
                self.profile_combo.currentData(),
                True,
                self.log_queue,
                self.finished_queue
            )
        )
        self.worker_process.start()
        self.is_scanning = True # Indicate scan is in progress

        self.start_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.clean_all_btn.setEnabled(False) # Disable cleanup during scan
        self.test_btn.setEnabled(False) # Disable test during scan
        self.progress_label.setText("Status: Scanning...")
        self.progress.setValue(0)
        self.scan_timer = self.startTimer(100)

    def timerEvent(self, event):
        # Handle messages for scan process
        if self.is_scanning:
            while not self.log_queue.empty():
                try:
                    level, message = self.log_queue.get_nowait()
                    self.log_message(message, level)
                except:
                    break
            if not self.finished_queue.empty():
                try:
                    self.finished_queue.get_nowait()
                    self.on_scan_finished()
                except:
                    pass
        # Handle messages for cleanup process
        elif self.is_cleaning:
            cleaning_progress_updated = False
            while not self.log_queue.empty():
                try:
                    level, message = self.log_queue.get_nowait()
                    self.log_message(message, level)
                    # Update cleanup progress
                    if "Completed iteration" in message and level == "INFO":
                        cleaning_progress_updated = True
                except:
                    break # Exit loop if queue is empty or error

            # Update progress bar *after* processing messages
            if cleaning_progress_updated:
                current_val = self.progress.value()
                if current_val < 99:
                    self.progress.setValue(current_val + 1)

            if not self.finished_queue.empty():
                try:
                    self.finished_queue.get_nowait()
                    self.on_clean_finished() # Call cleanup finish function
                except:
                    pass

    def cancel_scans(self):
        if self.worker_process and self.worker_process.is_alive():
            self.worker_process.terminate()
            self.worker_process.join(timeout=1)
            if self.worker_process.is_alive():
                self.worker_process.kill()
            self.log_message("Scans cancelled by user.", "WARNING")
        self.on_scan_finished() # Reset state

    def on_scan_finished(self):
        self.log_message("✅ All scans are finished.", "INFO")
        self.cleanup_process()

    def cleanup_process(self):
        if self.scan_timer:
            self.killTimer(self.scan_timer)
            self.scan_timer = None
        if self.worker_process:
            self.worker_process = None
        self.is_scanning = False # Reset indicator
        self.start_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.clean_all_btn.setEnabled(True) # Re-enable cleanup
        self.test_btn.setEnabled(True) # Re-enable test
        self.progress_label.setText("Status: Idle")
        if hasattr(self, 'worker_temp_file') and self.worker_temp_file:
            try:
                os.unlink(self.worker_temp_file)
            except:
                pass
            self.worker_temp_file = None

    def load_settings(self):
        self.url_input.setText(self.settings.value("url", "https://localhost:3443"))
        saved_api = keyring.get_password("acunetix_automation", "api_key")
        if saved_api:
            self.api_input.setText(saved_api)

    def closeEvent(self, event):
        if self.worker_process and self.worker_process.is_alive():
            self.cancel_scans()
        if self.clean_process and self.clean_process.is_alive(): # Stop cleanup process
            self.log_message("Terminating cleanup process...", "WARNING")
            self.clean_process.terminate()
            self.clean_process.join(timeout=2)
            if self.clean_process.is_alive():
                self.clean_process.kill()
            self.on_clean_finished() # Reset state
        event.accept()

    # ==============================
    # NEW: CLEAN ALL TARGETS (BULK) with options
    # ==============================

    def clean_all_targets(self):
        if self.is_scanning: # Prevent cleanup during scan
            self.log_message("Cannot start cleanup while scans are in progress.", "ERROR")
            return
        dialog = CleanAllConfirmationDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            if dialog.get_input().lower() == "yes":
                delete_targets = dialog.get_delete_targets()
                delete_scans = dialog.get_delete_scans()
                if not (delete_targets or delete_scans): # Verify at least one option is selected
                    QMessageBox.warning(self, "Cancelled", "You must select at least one option to delete.")
                    return
                self.initiate_bulk_cleanup_process(delete_targets, delete_scans)
            else:
                QMessageBox.warning(self, "Cancelled", "You must type 'yes' to confirm.")
        else:
            self.log_message("Clean all cancelled by user.", "INFO")

    def initiate_bulk_cleanup_process(self, delete_targets=True, delete_scans=True):
        # Disable buttons to avoid conflicts
        self.clean_all_btn.setEnabled(False)
        self.test_btn.setEnabled(False)
        self.start_btn.setEnabled(False) # Disable scan button too

        # Save settings
        keyring.set_password("acunetix_automation", "api_key", self.api_input.text())
        self.settings.setValue("url", self.url_input.text())

        # Initialize queues for cleanup process
        self.log_queue = Queue()
        self.finished_queue = Queue()

        # Launch cleanup process
        self.clean_process = multiprocessing.Process(
            target=clean_worker_process,
            args=(
                self.url_input.text(),
                self.api_input.text(),
                self.log_queue,
                self.finished_queue,
                delete_targets,
                delete_scans
            )
        )
        self.clean_process.start()
        self.is_cleaning = True # Indicate cleanup is in progress

        # Reset progress bar and label
        self.progress.setValue(0)
        self.progress_label.setText("Status: Cleaning...")

        # Start timer to read cleanup process logs
        self.clean_timer = self.startTimer(100)


    def on_clean_finished(self):
        self.log_message("--- Bulk cleanup process finished ---", "WARNING")
        self.cleanup_clean_process()

    def cleanup_clean_process(self):
        if self.clean_timer:
            self.killTimer(self.clean_timer)
            self.clean_timer = None
        if self.clean_process:
            # Wait for process to finish
            self.clean_process.join()
            self.clean_process = None
        self.is_cleaning = False # Reset indicator
        # Re-enable buttons
        self.clean_all_btn.setEnabled(True)
        self.test_btn.setEnabled(True)
        self.start_btn.setEnabled(True) # Re-enable scan button
        # Reset progress bar and label
        self.progress.setValue(0)
        self.progress_label.setText("Status: Idle")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = AcunetixGUI()
    window.show()
    sys.exit(app.exec())