import json
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from PySide6.QtCore import Qt
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

from src.core.models import ScanResult
from src.core.payload_loader import load_payload_cases
from src.core.report_writer import write_html_report, write_json_report, write_markdown_report, write_reports
from src.core.scanner import ScannerThread
from src.data.owasp_llm_top10 import OWASP_LLM_TOP10
from src.gui.widgets import ReadOnlyTextEdit


DISCLAIMER = "Use this tool only on systems you own or have explicit permission to test."


class MainWindow(QMainWindow):
    def __init__(self, base_dir: Path) -> None:
        super().__init__()
        self.base_dir = base_dir
        self.payload_cases = load_payload_cases(base_dir)
        self.results: list[ScanResult] = []
        self.scanner_thread: ScannerThread | None = None
        self.settings = self._load_settings()

        self.setWindowTitle("OWASP LLM Top 10 Payload Tester")
        self._build_ui()
        self._connect_signals()
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

        self.category_list = QListWidget()
        self.category_list.setMinimumWidth(280)
        for category in OWASP_LLM_TOP10:
            item = QListWidgetItem(f"{category['id']}: {category['name']}", self.category_list)
            item.setData(Qt.UserRole, f"{category['id']}: {category['name']}")
            item.setCheckState(Qt.Unchecked)
        splitter.addWidget(self.category_list)

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
        button_row.addWidget(self.start_button)
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
            QPushButton {
                padding: 6px 12px;
            }
            QTextEdit, QLineEdit, QListWidget {
                font-size: 13px;
            }
            """
        )

    def _connect_signals(self) -> None:
        self.category_list.currentRowChanged.connect(self._show_category)
        self.start_button.clicked.connect(self._start_scan)
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
        )
        self.scanner_thread.log.connect(self._append_log)
        self.scanner_thread.website_status.connect(self._update_website_status)
        self.scanner_thread.progress.connect(self._update_progress)
        self.scanner_thread.result.connect(self._record_result)
        self.scanner_thread.finished_with_results.connect(self._scan_finished)
        self.scanner_thread.failed.connect(self._scan_failed)
        self.scanner_thread.start()
        self._append_log("Scan started.")

    def _record_result(self, result: ScanResult) -> None:
        self.results.append(result)
        self._append_log(f"{result.category_id} / {result.payload_name} completed: {result.result} - {result.reason}")
        row = self._row_for_category(result.category_id)
        if row is not None:
            item = self.category_list.item(row)
            base_text = item.data(Qt.UserRole)
            category_result = self._category_result(result.category_id)
            item.setText(f"{base_text} - {category_result}")
            item.setCheckState(Qt.Checked if category_result == "PASS" else Qt.Unchecked)
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
            download_path = self._auto_download_html_report()
            self._append_log(f"HTML report automatically saved: {download_path}")
            self._update_security_score(final=True)
            QMessageBox.information(
                self,
                "Report downloaded",
                f"The scan is complete and the HTML report was saved automatically:\n{download_path}",
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

        QMessageBox.information(self, "Report saved", f"Saved:\n{output_path}")
        self._append_log(f"Report saved: {output_path}")

    def _set_running(self, running: bool) -> None:
        self.start_button.setEnabled(not running)
        self.url_input.setEnabled(not running)

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
        for row in range(self.category_list.count()):
            item = self.category_list.item(row)
            item.setText(item.data(Qt.UserRole))
            item.setCheckState(Qt.Unchecked)

    def _row_for_category(self, category_id: str) -> int | None:
        for row, category in enumerate(OWASP_LLM_TOP10):
            if category["id"] == category_id:
                return row
        return None

    def _latest_result_for_category(self, category_id: str) -> ScanResult | None:
        matches = [result for result in self.results if result.category_id == category_id]
        return matches[-1] if matches else None

    def _category_result(self, category_id: str) -> str:
        matches = [result.result for result in self.results if result.category_id == category_id]
        if not matches:
            return "Not run"
        if "FAIL" in matches:
            return "FAIL"
        if "WARNING" in matches:
            return "WARNING"
        if "ERROR" in matches:
            return "ERROR"
        if all(result == "PASS" for result in matches):
            return "PASS"
        return matches[-1]

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
        category_ids = [category["id"] for category in OWASP_LLM_TOP10]
        category_results = [self._category_result(category_id) for category_id in category_ids]
        total = len(category_ids)
        passed = sum(1 for result in category_results if result == "PASS")
        failed = sum(1 for result in category_results if result == "FAIL")
        warnings = sum(1 for result in category_results if result == "WARNING")
        errors = sum(1 for result in category_results if result == "ERROR")
        scanned = sum(1 for result in category_results if result != "Not run")
        if scanned == total and errors == total:
            self.security_score_label.setText("Security score: Not evaluated (no AI bot/chat endpoint found)")
            self.security_score_label.setStyleSheet("color: #6c757d; font-weight: 700;")
            return
        score_text = (
            f"Security score: {passed}/{total} secure "
            f"(FAIL {failed}, WARNING {warnings}, ERROR {errors})"
        )
        if not final and scanned < total:
            score_text += f" - scanned {scanned}/{total}"
        color = "#198754" if passed == total else "#b7791f" if failed == 0 else "#dc3545"
        self.security_score_label.setText(score_text)
        self.security_score_label.setStyleSheet(f"color: {color}; font-weight: 700;")

    def _load_settings(self) -> dict[str, object]:
        settings_path = self.base_dir / "config" / "settings.json"
        try:
            return json.loads(settings_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {
                "timeout_seconds": 30,
                "delay_between_tests_seconds": 2,
                "max_crawl_pages": 12,
                "enable_browser_scan": True,
            }
