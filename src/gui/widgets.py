from PySide6.QtWidgets import QTextEdit


class ReadOnlyTextEdit(QTextEdit):
    def __init__(self, placeholder: str = "") -> None:
        super().__init__()
        self.setReadOnly(True)
        self.setPlaceholderText(placeholder)
        self.setAcceptRichText(False)
