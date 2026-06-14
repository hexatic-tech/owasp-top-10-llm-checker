from pathlib import Path
import sys

from PySide6.QtWidgets import QApplication

from src.core.payload_loader import ensure_payload_files
from src.gui.main_window import MainWindow


BASE_DIR = Path(__file__).resolve().parent


def main() -> int:
    ensure_payload_files(BASE_DIR)
    (BASE_DIR / "reports").mkdir(exist_ok=True)

    app = QApplication(sys.argv)
    app.setApplicationName("OWASP LLM Top 10 Payload Tester")
    window = MainWindow(BASE_DIR)
    window.resize(1180, 780)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
