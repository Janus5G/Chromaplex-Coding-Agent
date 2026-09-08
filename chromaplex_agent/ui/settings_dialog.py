from __future__ import annotations

from PySide6.QtCore import QSettings
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
)

from ..config import APP_NAME, APP_ORG, DEFAULT_CAFFEINE_MODEL, DEFAULT_OPENAI_MODEL, DEFAULT_TIMEOUT
from ..credentials import CredentialStore


class ApiSettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("API settings")
        self.resize(520, 320)
        self._settings = QSettings(APP_ORG, APP_NAME)
        layout = QVBoxLayout(self)
        form = QFormLayout()

        self.provider = QComboBox()
        self.provider.addItems(["openai", "caffeine"])
        self.provider.setCurrentText(self._settings.value("provider", "openai"))
        form.addRow("Provider:", self.provider)

        self.openai_model = QComboBox()
        self.openai_model.setEditable(True)
        self.openai_model.addItems(["gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"])
        self.openai_model.setCurrentText(self._settings.value("openai_model", DEFAULT_OPENAI_MODEL))
        form.addRow("OpenAI model:", self.openai_model)

        self.caffeine_model = QLineEdit(self._settings.value("caffeine_model", DEFAULT_CAFFEINE_MODEL))
        form.addRow("Caffeine model:", self.caffeine_model)

        self.openai_key = QLineEdit()
        self.openai_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.openai_key.setPlaceholderText("Stored securely or supplied via OPENAI_API_KEY")
        form.addRow("OpenAI API key:", self.openai_key)

        self.caffeine_key = QLineEdit()
        self.caffeine_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.caffeine_key.setPlaceholderText("Stored securely or supplied via CAFFEINE_API_KEY")
        form.addRow("Caffeine API key:", self.caffeine_key)

        self.timeout = QLineEdit(str(self._settings.value("timeout", DEFAULT_TIMEOUT)))
        form.addRow("Timeout (seconds):", self.timeout)

        self.online_reputation = QCheckBox("Enable hash-only online reputation lookup")
        self.online_reputation.setChecked(str(self._settings.value("online_reputation", "false")).lower() in {"1", "true", "yes"})
        form.addRow("Secure Compile Gate:", self.online_reputation)

        self.virustotal_key = QLineEdit()
        self.virustotal_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.virustotal_key.setPlaceholderText("Optional; requires an appropriate VirusTotal API license/key")
        form.addRow("VirusTotal API key:", self.virustotal_key)
        layout.addLayout(form)

        note = QLabel(
            "API keys are stored with Linux Secret Service when secret-tool is available. "
            "They are never written to project files or QSettings. Online reputation is hash-only; files are never uploaded automatically."
        )
        note.setWordWrap(True)
        layout.addWidget(note)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def save(self) -> tuple[bool, str]:
        self._settings.setValue("provider", self.provider.currentText())
        self._settings.setValue("openai_model", self.openai_model.currentText().strip() or DEFAULT_OPENAI_MODEL)
        self._settings.setValue("caffeine_model", self.caffeine_model.text().strip() or DEFAULT_CAFFEINE_MODEL)
        try:
            timeout = max(5, min(int(self.timeout.text()), 600))
        except ValueError:
            timeout = DEFAULT_TIMEOUT
        self._settings.setValue("timeout", timeout)
        self._settings.setValue("online_reputation", self.online_reputation.isChecked())
        failures: list[str] = []
        if self.openai_key.text().strip() and not CredentialStore.set("openai", self.openai_key.text().strip()):
            failures.append("OpenAI key was not persisted (secret-tool unavailable or failed). It can still be supplied via OPENAI_API_KEY.")
        if self.caffeine_key.text().strip() and not CredentialStore.set("caffeine", self.caffeine_key.text().strip()):
            failures.append("Caffeine key was not persisted (secret-tool unavailable or failed). It can still be supplied via CAFFEINE_API_KEY.")
        if self.virustotal_key.text().strip() and not CredentialStore.set("virustotal", self.virustotal_key.text().strip()):
            failures.append("VirusTotal key was not persisted (secret-tool unavailable or failed). It can still be supplied via VIRUSTOTAL_API_KEY.")
        return not failures, "\n".join(failures)
