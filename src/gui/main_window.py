import json
import os
import re
import subprocess
import webbrowser
from datetime import datetime
from pathlib import Path
from shutil import which
from urllib.parse import urlparse

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QBrush, QCloseEvent, QColor
from PySide6.QtWidgets import (
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QProgressBar,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from src.core import scoring
from src.core.models import ScanResult
from src.core.payload_loader import load_payload_cases
from src.core.report_writer import write_html_report, write_json_report, write_markdown_report, write_reports
from src.core.scanner import ScannerThread
from src.core.scoring import security_score
from src.data.owasp_llm_top10 import OWASP_LLM_TOP10
from src.gui.widgets import ReadOnlyTextEdit


DISCLAIMER = "Use this tool only on systems you own or have explicit permission to test."

DEFAULT_SETTINGS: dict[str, object] = {
    "timeout_seconds": 30,
    "delay_between_tests_seconds": 2,
    "max_crawl_pages": 12,
    "enable_browser_scan": True,
}

# Row background tints by canonical category verdict.
STATUS_COLORS = {
    scoring.PASS: "#d1e7dd",   # green
    scoring.FAIL: "#f8d7da",   # red
    scoring.MIXED: "#ffe0b2",  # orange
    scoring.ERROR: "#ffe0b2",  # orange (could not evaluate)
}


class MainWindow(QMainWindow):
    def __init__(self, base_dir: Path) -> None:
        super().__init__()
        self.base_dir = base_dir
        self.payload_cases = load_payload_cases(base_dir)
        self.results: list[ScanResult] = []
        self.scanner_thread: ScannerThread | None = None
        self.settings = self._load_settings()

        self._spinner_index = 0
        self._spinner_timer = QTimer(self)
        self._spinner_timer.setInterval(120)
        self._spinner_timer.timeout.connect(self._tick_spinner)

        self.setWindowTitle("OWASP LLM Top 10 Payload Tester")
        self._build_ui()
        self._connect_signals()
        self._refresh_report_list()
        self.category_list.setCurrentRow(0)

    def _build_ui(self) -> None:
        root = QWidget()
        root_layout = QVBoxLayout(root)

        disclaimer = QLabel(DISCLAIMER)
        disclaimer.setObjectName("disclaimer")
        disclaimer.setWordWrap(True)
        root_layout.addWidget(disclaimer)

        splitter = QSplitter(Qt.Horizontal)
        root_layout.addWidget(splitter, stretch=1)

        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_panel.setMinimumWidth(280)

        self.category_list = QListWidget()
        for category in OWASP_LLM_TOP10:
            item = QListWidgetItem(f"{category['id']}: {category['name']}", self.category_list)
            item.setData(Qt.UserRole, f"{category['id']}: {category['name']}")
            item.setCheckState(Qt.Unchecked)
        left_layout.addWidget(QLabel("OWASP tests"))
        left_layout.addWidget(self.category_list, stretch=3)

        self.report_list = QListWidget()
        self.report_list.setAlternatingRowColors(True)
        self.report_title = QLabel("Saved reports")
        self.report_title.setObjectName("reportTitle")
        left_layout.addWidget(self.report_title)
        left_layout.addWidget(self.report_list, stretch=2)
        splitter.addWidget(left_panel)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        splitter.addWidget(right)
        splitter.setStretchFactor(1, 1)

        input_frame = QFrame()
        input_frame.setFrameShape(QFrame.StyledPanel)
        input_layout = QFormLayout(input_frame)

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("http://127.0.0.1:8000/")
        self.website_status_label = QLabel("Website status: Not checked")
        self.website_status_label.setObjectName("websiteStatus")
        self.security_score_label = QLabel("Security score: Not scanned")
        self.security_score_label.setObjectName("securityScore")

        button_row = QHBoxLayout()
        self.start_button = QPushButton("Start Test")
        self.start_button.setObjectName("startButton")
        # Lock the width so the animated "Running" spinner can't resize the
        # button and shift the Stop button left/right while it ticks.
        start_width = self.start_button.fontMetrics().horizontalAdvance("Running        |") + 36
        self.start_button.setFixedWidth(start_width)
        self.stop_button = QPushButton("Stop Test")
        self.stop_button.setObjectName("stopButton")
        self.stop_button.setEnabled(False)
        button_row.addWidget(self.start_button)
        button_row.addWidget(self.stop_button)
        button_row.addStretch(1)

        input_layout.addRow("Target website URL", self.url_input)
        input_layout.addRow("Website check", self.website_status_label)
        input_layout.addRow("OWASP score", self.security_score_label)
        input_layout.addRow("", button_row)
        right_layout.addWidget(input_frame)

        main_splitter = QSplitter(Qt.Vertical)
        right_layout.addWidget(main_splitter, stretch=1)

        detail = QWidget()
        detail_layout = QFormLayout(detail)
        self.selected_category = QLabel()
        self.payload_path = QLineEdit()
        self.payload_path.setReadOnly(True)
        self.payload_preview = ReadOnlyTextEdit("Payload preview")
        self.response_preview = ReadOnlyTextEdit("HTTP response preview")
        self.result_label = QLabel("Not run")
        self.reason_label = QLabel("")
        self.reason_label.setWordWrap(True)

        detail_layout.addRow("Selected OWASP category", self.selected_category)
        detail_layout.addRow("Payload file path", self.payload_path)
        detail_layout.addRow("Payload preview", self.payload_preview)
        detail_layout.addRow("HTTP response preview", self.response_preview)
        detail_layout.addRow("Result", self.result_label)
        detail_layout.addRow("Reason", self.reason_label)
        main_splitter.addWidget(detail)

        bottom = QWidget()
        bottom_layout = QVBoxLayout(bottom)
        self.logs = QTextEdit()
        self.logs.setReadOnly(True)
        self.logs.setAcceptRichText(False)
        self.progress = QProgressBar()
        self.progress.setRange(0, len(self.payload_cases))
        self.export_button = QPushButton("Export report")
        self.export_button.setEnabled(False)
        bottom_layout.addWidget(QLabel("Live logs"))
        bottom_layout.addWidget(self.logs, stretch=1)
        bottom_layout.addWidget(self.progress)
        bottom_layout.addWidget(self.export_button, alignment=Qt.AlignRight)
        main_splitter.addWidget(bottom)
        main_splitter.setStretchFactor(0, 2)
        main_splitter.setStretchFactor(1, 1)

        self.setCentralWidget(root)
        self.setStyleSheet(
            """
            QLabel#disclaimer {
                background: #fff3cd;
                color: #4d3900;
                border: 1px solid #e0c36f;
                border-radius: 6px;
                padding: 10px;
                font-weight: 600;
            }
            QLabel#websiteStatus {
                color: #495057;
                font-weight: 600;
            }
            QLabel#securityScore {
                color: #495057;
                font-weight: 700;
            }
            QLabel#reportTitle {
                margin-top: 8px;
                font-weight: 700;
            }
            QPushButton {
                padding: 6px 12px;
            }
            QPushButton#startButton, QPushButton#startButton:disabled {
                background: #198754;
                color: #ffffff;
                font-weight: 600;
                border: none;
                border-radius: 4px;
                text-align: left;
                padding-left: 14px;
                padding-right: 14px;
            }
            QPushButton#stopButton {
                background: #dc3545;
                color: #ffffff;
                font-weight: 600;
                border: none;
                border-radius: 4px;
            }
            QPushButton#stopButton:disabled {
                background: #e9a3ab;
                color: #fdecee;
            }
            QTextEdit, QLineEdit, QListWidget {
                font-size: 13px;
            }
            """
        )

    def _connect_signals(self) -> None:
        self.category_list.currentRowChanged.connect(self._show_category)
        self.report_list.itemClicked.connect(self._open_selected_report)
        self.report_list.itemDoubleClicked.connect(self._open_selected_report)
        self.start_button.clicked.connect(self._start_scan)
        self.stop_button.clicked.connect(self._stop_scan)
        self.export_button.clicked.connect(self._export_reports)

    def _show_category(self, row: int) -> None:
        category = OWASP_LLM_TOP10[row] if 0 <= row < len(OWASP_LLM_TOP10) else None
        if not category:
            return
        case = next((item for item in self.payload_cases if item.category_id == category["id"]), None)
        if not case:
            return
        self.selected_category.setText(f"{case.category_id}: {case.category_name}")
        self.payload_path.setText(case.payload_path)
        self.payload_preview.setPlainText(case.payload_text)

        result = self._latest_result_for_category(case.category_id)
        if result:
            self.response_preview.setPlainText(result.response_preview)
            self.result_label.setText(f"{result.result} - {result.payload_name}")
            self.reason_label.setText(result.reason)
            self.payload_preview.setPlainText(result.payload_text)
        else:
            self.response_preview.clear()
            self.result_label.setText("Not run")
            self.reason_label.clear()

    def _start_scan(self) -> None:
        target_url = self.url_input.text().strip()
        if not self._validate_inputs(target_url):
            return

        confirmed = QMessageBox.question(
            self,
            "Confirm authorization",
            "I confirm I own or have permission to test this target.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if confirmed != QMessageBox.Yes:
            self._append_log("Scan cancelled before authorization confirmation.")
            return

        selected_category_ids = self._selected_category_ids()
        if selected_category_ids:
            self._append_log(
                f"Selected categories: {', '.join(selected_category_ids)}."
            )
        else:
            self._append_log("No categories selected. Running all OWASP LLM Top 10 tests.")

        self.results = []
        self._reset_safety_checklist()
        self.progress.setValue(0)
        self.export_button.setEnabled(False)
        self.logs.clear()
        self.website_status_label.setText("Website status: Checking...")
        self.website_status_label.setStyleSheet("color: #6c757d;")
        self.security_score_label.setText("Security score: Running...")
        self.security_score_label.setStyleSheet("color: #6c757d; font-weight: 700;")
        self._set_running(True)

        self.scanner_thread = ScannerThread(
            base_dir=self.base_dir,
            target_url=target_url,
            timeout_seconds=int(self.settings.get("timeout_seconds", 30)),
            delay_seconds=int(self.settings.get("delay_between_tests_seconds", 2)),
            max_crawl_pages=int(self.settings.get("max_crawl_pages", 12)),
            enable_browser_scan=bool(self.settings.get("enable_browser_scan", True)),
            selected_category_ids=selected_category_ids,
        )
        self.scanner_thread.log.connect(self._append_log)
        self.scanner_thread.website_status.connect(self._update_website_status)
        self.scanner_thread.progress.connect(self._update_progress)
        self.scanner_thread.result.connect(self._record_result)
        self.scanner_thread.finished_with_results.connect(self._scan_finished)
        self.scanner_thread.failed.connect(self._scan_failed)
        self.scanner_thread.start()
        self._append_log("Scan started.")

    def _selected_category_ids(self) -> list[str]:
        selected: list[str] = []
        for row in range(self.category_list.count()):
            item = self.category_list.item(row)
            if item.checkState() == Qt.Checked and 0 <= row < len(OWASP_LLM_TOP10):
                selected.append(OWASP_LLM_TOP10[row]["id"])
        return selected

    def _stop_scan(self) -> None:
        if not self.scanner_thread:
            return
        self.stop_button.setEnabled(False)
        self._stop_spinner()
        self.scanner_thread.stop()
        self.website_status_label.setText("Website status: Stopping...")
        self.security_score_label.setText("Security score: Stopping...")
        self._append_log("Stop requested. Finishing the current step and halting...")

    def closeEvent(self, event: QCloseEvent) -> None:
        thread = self.scanner_thread
        if thread is not None and thread.isRunning():
            thread.stop()
            # Give the cooperative stop a moment to unwind the current step.
            thread.wait(5000)
        super().closeEvent(event)

    def _record_result(self, result: ScanResult) -> None:
        self.results.append(result)
        self._append_log(f"{result.category_id} / {result.payload_name} completed: {result.result} - {result.reason}")
        row = self._row_for_category(result.category_id)
        if row is not None:
            self._apply_category_color(row, result.category_id)
            self.category_list.setCurrentRow(row)
        self._update_security_score()

    def _update_progress(self, current: int, total: int) -> None:
        self.progress.setRange(0, total)
        self.progress.setValue(current)

    def _scan_finished(self, results: list[ScanResult]) -> None:
        self.results = results
        self._set_running(False)
        self.export_button.setEnabled(bool(self.results))
        if self.results:
            json_path, md_path = write_reports(self.base_dir, self.results)
            self._append_log(f"Reports saved: {json_path.name}, {md_path.name}")
            html_path = self._save_latest_html_report()
            self._append_log(f"HTML report saved in app reports: {html_path.name}")
            download_path = self._auto_download_html_report()
            self._append_log(f"HTML report automatically saved: {download_path}")
            self._refresh_report_list(html_path)
            self._update_security_score(final=True)
            QMessageBox.information(
                self,
                "Report downloaded",
                f"The scan is complete and the HTML report was saved automatically:\n{download_path}\n\nIt was also saved in the app report list:\n{html_path}",
            )
        self._append_log("Scan finished.")
        self.scanner_thread = None

    def _scan_failed(self, message: str) -> None:
        self._set_running(False)
        QMessageBox.critical(self, "Scanner error", message)
        self._append_log(f"Scanner error: {message}")
        self.scanner_thread = None

    def _export_reports(self) -> None:
        if not self.results:
            QMessageBox.information(self, "No results", "Run a scan before exporting a report.")
            return

        default_path = self.base_dir / "reports" / "owasp_llm_report.html"
        file_path, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Save report",
            str(default_path),
            "HTML report (*.html);;Markdown report (*.md);;JSON report (*.json)",
        )
        if not file_path:
            return

        output_path = Path(file_path)
        if selected_filter.startswith("JSON") or output_path.suffix.lower() == ".json":
            output_path = output_path if output_path.suffix.lower() == ".json" else output_path.with_suffix(".json")
            write_json_report(output_path, self.results)
        elif selected_filter.startswith("Markdown") or output_path.suffix.lower() == ".md":
            output_path = output_path if output_path.suffix.lower() == ".md" else output_path.with_suffix(".md")
            write_markdown_report(output_path, self.results)
        else:
            output_path = output_path if output_path.suffix.lower() == ".html" else output_path.with_suffix(".html")
            write_html_report(output_path, self.results)

        sidebar_copy = self._save_report_copy(output_path)
        self._refresh_report_list(sidebar_copy)
        QMessageBox.information(self, "Report saved", f"Saved:\n{output_path}")
        self._append_log(f"Report saved: {output_path}")
        self._append_log(f"Report added to sidebar: {sidebar_copy}")

    def _reports_dir(self) -> Path:
        reports_dir = self.base_dir / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        return reports_dir

    def _refresh_report_list(self, selected_path: Path | None = None) -> None:
        self.report_list.clear()
        reports = sorted(
            (
                path
                for path in self._reports_dir().iterdir()
                if path.is_file() and path.suffix.lower() == ".html"
            ),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        for path in reports:
            item = QListWidgetItem(path.name, self.report_list)
            item.setData(Qt.UserRole, str(path))

        title = "Saved reports"
        if self.report_list.count():
            title = f"Saved reports ({self.report_list.count()})"
        self.report_title.setText(title)

        if selected_path is None:
            return

        selected_value = str(selected_path)
        for row in range(self.report_list.count()):
            item = self.report_list.item(row)
            if item.data(Qt.UserRole) == selected_value:
                self.report_list.setCurrentRow(row)
                break

    def _save_report_copy(self, output_path: Path) -> Path:
        suffix = output_path.suffix.lower()
        if output_path.parent == self._reports_dir():
            return output_path
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = self._reports_dir() / f"exported_{self._safe_site_name()}_{timestamp}{suffix or '.html'}"
        if suffix == ".json":
            write_json_report(report_path, self.results)
        elif suffix == ".md":
            write_markdown_report(report_path, self.results)
        else:
            write_html_report(report_path, self.results)
        return report_path

    def _save_latest_html_report(self) -> Path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = self._reports_dir() / f"report_{timestamp}.html"
        write_html_report(report_path, self.results)
        return report_path

    def _open_selected_report(self, item: QListWidgetItem) -> None:
        report_path = Path(item.data(Qt.UserRole))
        if not report_path.exists():
            QMessageBox.warning(self, "Missing report", f"Could not find:\n{report_path}")
            self._refresh_report_list()
            return
        opened_with = self._open_report_in_browser(report_path)
        if not opened_with:
            QMessageBox.warning(
                self,
                "Open failed",
                "Could not open the report in a browser. Please check your browser configuration.",
            )

    def _open_report_in_browser(self, report_path: Path) -> str | None:
        report_url = report_path.resolve().as_uri()

        if webbrowser.open_new_tab(report_url):
            self._append_log(f"Opened report in browser: default browser - {report_path}")
            return "default browser"

        for browser in self._browser_candidates():
            browser_path = which(browser)
            if browser_path is None:
                continue
            try:
                subprocess.Popen([browser_path, report_url])
                self._append_log(f"Opened report in browser: {browser} - {report_path}")
                return browser
            except OSError:
                continue
        return None

    def _browser_candidates(self) -> list[str]:
        browsers: list[str] = []

        configured = os.environ.get("BROWSER", "")
        for entry in configured.split(os.pathsep):
            candidate = entry.strip()
            if candidate and candidate not in browsers:
                browsers.append(candidate)

        browsers.extend([
            "brave-browser",
            "brave",
            "google-chrome",
            "google-chrome-stable",
            "microsoft-edge",
            "microsoft-edge-stable",
            "chromium",
            "chromium-browser",
            "firefox",
            "floorp",
            "opera",
            "vivaldi",
        ])
        return browsers

    def _set_running(self, running: bool) -> None:
        self.start_button.setEnabled(not running)
        self.stop_button.setEnabled(running)
        self.url_input.setEnabled(not running)
        if running:
            self._start_spinner()
        else:
            self._stop_spinner()

    _SPINNER_FRAMES = "|/-\\"

    def _running_label(self, frame: str) -> str:
        # Fixed leading spacing keeps "Running" anchored on the left and the
        # spinner glyph parked on the right half of the (fixed-width) button.
        return f"Running        {frame}"

    def _start_spinner(self) -> None:
        self._spinner_index = 0
        self.start_button.setText(self._running_label(self._SPINNER_FRAMES[0]))
        self._spinner_timer.start()

    def _stop_spinner(self) -> None:
        self._spinner_timer.stop()
        self.start_button.setText("Start Test")

    def _tick_spinner(self) -> None:
        frame = self._SPINNER_FRAMES[self._spinner_index % len(self._SPINNER_FRAMES)]
        self._spinner_index += 1
        self.start_button.setText(self._running_label(frame))

    def _validate_inputs(self, target_url: str) -> bool:
        parsed = urlparse(target_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            QMessageBox.warning(self, "Invalid URL", "Enter a valid http:// or https:// website URL.")
            return False
        return True

    def _append_log(self, message: str) -> None:
        self.logs.append(message)

    def _update_website_status(self, message: str, ok: bool) -> None:
        state = "OK" if ok else "Not reachable"
        color = "#198754" if ok else "#dc3545"
        self.website_status_label.setText(f"Website status: {state}")
        self.website_status_label.setStyleSheet(f"color: {color}; font-weight: 600;")
        if not ok:
            QMessageBox.warning(self, "Website check failed", message)

    def _reset_safety_checklist(self) -> None:
        # Reset the result text suffix and color; preserve the user's category selection.
        for row in range(self.category_list.count()):
            item = self.category_list.item(row)
            item.setText(item.data(Qt.UserRole))
            item.setBackground(QBrush())

    def _row_for_category(self, category_id: str) -> int | None:
        for row, category in enumerate(OWASP_LLM_TOP10):
            if category["id"] == category_id:
                return row
        return None

    def _latest_result_for_category(self, category_id: str) -> ScanResult | None:
        matches = [result for result in self.results if result.category_id == category_id]
        return matches[-1] if matches else None

    def _category_status_for(self, category_id: str) -> str | None:
        """Canonical verdict for a category, or None if it has no results yet."""
        statuses = [result.result for result in self.results if result.category_id == category_id]
        return scoring.category_status(statuses) if statuses else None

    def _apply_category_color(self, row: int, category_id: str) -> None:
        item = self.category_list.item(row)
        status = self._category_status_for(category_id)
        color = STATUS_COLORS.get(status) if status else None
        item.setBackground(QBrush(QColor(color)) if color else QBrush())

    def _auto_download_html_report(self) -> Path:
        downloads_dir = Path.home() / "Downloads"
        if not downloads_dir.exists():
            downloads_dir = self.base_dir / "reports"
        downloads_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = downloads_dir / f"owasp_llm_report_{self._safe_site_name()}_{timestamp}.html"
        write_html_report(path, self.results)
        return path

    def _safe_site_name(self) -> str:
        parsed = urlparse(self.url_input.text().strip())
        source = parsed.netloc or parsed.path or "website"
        source = source.lower().removeprefix("www.")
        safe = re.sub(r"[^a-z0-9]+", "_", source).strip("_")
        return safe or "website"

    def _update_security_score(self, final: bool = False) -> None:
        total_categories = len(OWASP_LLM_TOP10)
        scanned_statuses = [
            status
            for category in OWASP_LLM_TOP10
            if (status := self._category_status_for(category["id"])) is not None
        ]
        scanned = len(scanned_statuses)
        score = security_score(scanned_statuses)

        if score.total > 0 and score.errors == score.total:
            self.security_score_label.setText("Security score: Not evaluated (no AI bot/chat endpoint found)")
            self.security_score_label.setStyleSheet("color: #6c757d; font-weight: 700;")
            return

        score_text = (
            f"Security score: {score.display} "
            f"(FAIL {score.failed}, MIXED {score.mixed}, ERROR {score.errors})"
        )
        if not final and scanned < total_categories:
            score_text += f" - scanned {scanned}/{total_categories}"
        if score.total > 0 and score.passed == score.total:
            color = "#198754"  # all passed
        elif score.failed > 0:
            color = "#dc3545"  # at least one outright failure
        elif score.mixed > 0:
            color = "#b7791f"  # needs manual review
        else:
            color = "#6c757d"  # nothing conclusive yet
        self.security_score_label.setText(score_text)
        self.security_score_label.setStyleSheet(f"color: {color}; font-weight: 700;")

    def _load_settings(self) -> dict[str, object]:
        settings = dict(DEFAULT_SETTINGS)
        settings_path = self.base_dir / "config" / "settings.json"
        try:
            loaded = json.loads(settings_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return settings
        if isinstance(loaded, dict):
            settings.update(loaded)
        return settings
