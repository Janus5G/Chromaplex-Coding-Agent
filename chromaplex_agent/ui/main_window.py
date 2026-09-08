from __future__ import annotations

import html
import json
import os
import tempfile
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QSettings, QThread, Qt, QUrl
from PySide6.QtGui import QAction, QDesktopServices, QKeySequence
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSplitter,
    QStatusBar,
    QTabWidget,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

try:
    from PySide6.QtWebEngineWidgets import QWebEngineView
except Exception:
    QWebEngineView = None

from ..ai_client import AIAgent
from ..config import APP_NAME, APP_ORG, DEFAULT_CAFFEINE_MODEL, DEFAULT_OPENAI_MODEL, DEFAULT_TIMEOUT, DISPLAY_NAME, ONLINE_SIMULATOR_URL
from ..credentials import CredentialStore
from ..capabilities import CAPABILITY_FILENAME, CapabilityManifest, ensure_manifest_file
from ..editor import CodeEditor, CodeHighlighter
from ..modes import MODES, default_filename
from ..targets import TARGETS, get_target, targets_for_mode
from ..project import Workspace, parse_project_json
from ..integrity import write_file_sidecar
from ..malware_scan import ClamAVScanner, VirusTotalHashReputation
from ..secure_compile import SecureCompileError, SecureCompilePolicy, preflight_sources, secure_build_chromaplex, secure_build_c, secure_build_csharp, secure_build_wasm, secure_build_embedded_project
from ..security import SafetyLevel, scan_files
from ..runtimes.chromaplex import compile_cpl, run_cpa, run_cpl
from ..runtimes.host import run_project
from ..workers import GenerateWorker
from .settings_dialog import ApiSettingsDialog


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(DISPLAY_NAME)
        self.resize(1380, 860)
        self.settings = QSettings(APP_ORG, APP_NAME)
        self.workspace = Workspace()
        self.worker = None
        self.thread = None
        self._loading_editor = False
        self.history: list[dict] = []
        self.preview_temp: Path | None = None
        self._build_ui()
        self._update_targets()
        self._update_languages()

    def _build_ui(self):
        file_menu = self.menuBar().addMenu("&File")
        open_action = QAction("Open file…", self, shortcut=QKeySequence.StandardKey.Open)
        open_action.triggered.connect(self.open_file)
        file_menu.addAction(open_action)
        save_action = QAction("Save current file…", self, shortcut=QKeySequence.StandardKey.Save)
        save_action.triggered.connect(self.save_current_file)
        file_menu.addAction(save_action)
        save_project_action = QAction("Save project folder…", self)
        save_project_action.triggered.connect(self.save_project_folder)
        file_menu.addAction(save_project_action)
        export_action = QAction("Export project ZIP…", self)
        export_action.triggered.connect(self.export_zip)
        file_menu.addAction(export_action)
        file_menu.addSeparator()
        quit_action = QAction("Quit", self, shortcut=QKeySequence.StandardKey.Quit)
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

        settings_menu = self.menuBar().addMenu("&Settings")
        api_action = QAction("API settings…", self)
        api_action.triggered.connect(self.open_api_settings)
        settings_menu.addAction(api_action)

        help_menu = self.menuBar().addMenu("&Help")
        sim_action = QAction("Open ChromaPlex 3D simulator", self)
        sim_action.triggered.connect(lambda: QDesktopServices.openUrl(QUrl(ONLINE_SIMULATOR_URL)))
        help_menu.addAction(sim_action)

        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status.showMessage("Ready")

        tabs = QTabWidget()
        self.setCentralWidget(tabs)
        studio = QWidget()
        tabs.addTab(studio, "Studio")
        history_tab = QWidget()
        tabs.addTab(history_tab, "History")

        root = QVBoxLayout(studio)
        controls = QGroupBox("Generate")
        controls_layout = QVBoxLayout(controls)
        row = QHBoxLayout()
        row.addWidget(QLabel("Mode:"))
        self.mode = QComboBox()
        self.mode.addItems([MODES[key].name for key in ("linux", "windows", "web", "chromaplex")])
        saved_mode = self.settings.value("mode", "chromaplex")
        self.mode.setCurrentText(MODES.get(saved_mode, MODES["chromaplex"]).name)
        self.mode.currentTextChanged.connect(self._mode_changed)
        row.addWidget(self.mode)
        row.addWidget(QLabel("Language:"))
        self.language = QComboBox()
        self.language.currentTextChanged.connect(self._update_action_state)
        row.addWidget(self.language)
        row.addWidget(QLabel("Target:"))
        self.target = QComboBox()
        self.target.currentTextChanged.connect(self._target_changed)
        row.addWidget(self.target)
        row.addStretch()
        self.generate_button = QPushButton("Generate")
        self.generate_button.clicked.connect(self.generate)
        row.addWidget(self.generate_button)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel_generation)
        row.addWidget(self.cancel_button)
        controls_layout.addLayout(row)
        self.prompt = QTextEdit()
        self.prompt.setPlaceholderText("Describe the program you want to create…")
        self.prompt.setMaximumHeight(110)
        controls_layout.addWidget(self.prompt)
        root.addWidget(controls)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        root.addWidget(splitter, 1)

        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.addWidget(QLabel("Project files"))
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.currentItemChanged.connect(self._file_selected)
        left_layout.addWidget(self.tree, 1)
        splitter.addWidget(left)

        center = QWidget()
        center_layout = QVBoxLayout(center)
        center_layout.setContentsMargins(0, 0, 0, 0)
        toolbar = QHBoxLayout()
        self.filename_label = QLabel("No file")
        toolbar.addWidget(self.filename_label)
        toolbar.addStretch()
        self.save_button = QPushButton("Save file")
        self.save_button.clicked.connect(self.save_current_file)
        toolbar.addWidget(self.save_button)
        self.seal_button = QPushButton("Secure review + SHA-256 seal")
        self.seal_button.clicked.connect(self.security_review_and_seal)
        toolbar.addWidget(self.seal_button)
        self.run_button = QPushButton("Run")
        self.run_button.clicked.connect(self.run_current)
        toolbar.addWidget(self.run_button)
        self.compile_button = QPushButton("Compile")
        self.compile_button.clicked.connect(self.compile_current)
        toolbar.addWidget(self.compile_button)
        self.binary_button = QPushButton("Build binary/bundle")
        self.binary_button.clicked.connect(self.build_binary_current)
        toolbar.addWidget(self.binary_button)
        self.preview_button = QPushButton("Preview")
        self.preview_button.clicked.connect(self.preview_current)
        toolbar.addWidget(self.preview_button)
        center_layout.addLayout(toolbar)
        self.editor = CodeEditor()
        self.highlighter = CodeHighlighter(self.editor.document())
        self.editor.edited.connect(self._editor_changed)
        center_layout.addWidget(self.editor, 1)
        splitter.addWidget(center)

        right = QTabWidget()
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        right.addTab(self.output, "Output")
        if QWebEngineView:
            self.web_view = QWebEngineView()
            try:
                from PySide6.QtWebEngineCore import QWebEngineSettings
                settings = self.web_view.settings()
                settings.setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessRemoteUrls, False)
                settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptCanAccessClipboard, False)
                settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptCanOpenWindows, False)
            except Exception:
                pass
            right.addTab(self.web_view, "Preview")
        else:
            self.web_view = None
            note = QTextEdit()
            note.setReadOnly(True)
            note.setPlainText("Qt WebEngine is not installed. Preview will open in the default browser.")
            right.addTab(note, "Preview")
        self.right_tabs = right
        splitter.addWidget(right)
        splitter.setSizes([230, 760, 390])

        history_layout = QVBoxLayout(history_tab)
        self.history_list = QListWidget()
        self.history_list.itemDoubleClicked.connect(self.show_history)
        history_layout.addWidget(self.history_list)
        self._update_action_state()

    def current_mode_key(self) -> str:
        name = self.mode.currentText()
        for key, config in MODES.items():
            if config.name == name:
                return key
        return "chromaplex"

    def _mode_changed(self):
        key = self.current_mode_key()
        self.settings.setValue("mode", key)
        self._update_targets()
        self._update_languages()

    def current_target_key(self) -> str:
        if not hasattr(self, "target"):
            return targets_for_mode(self.current_mode_key())[0].key
        name = self.target.currentText()
        for profile in targets_for_mode(self.current_mode_key()):
            if profile.name == name:
                return profile.key
        return targets_for_mode(self.current_mode_key())[0].key

    def _update_targets(self):
        mode = self.current_mode_key()
        profiles = targets_for_mode(mode)
        saved = str(self.settings.value(f"target/{mode}", profiles[0].key))
        self.target.blockSignals(True)
        self.target.clear()
        self.target.addItems([p.name for p in profiles])
        chosen = TARGETS.get(saved, profiles[0])
        if chosen.key not in {p.key for p in profiles}:
            chosen = profiles[0]
        self.target.setCurrentText(chosen.name)
        self.target.setToolTip(chosen.notes)
        self.target.blockSignals(False)

    def _target_changed(self):
        if not hasattr(self, "target") or not self.target.currentText():
            return
        key = self.current_target_key()
        self.settings.setValue(f"target/{self.current_mode_key()}", key)
        self.target.setToolTip(get_target(key).notes)
        if self.workspace.files:
            files = dict(self.workspace.files)
            ensure_manifest_file(files, key)
            main = self.workspace.main_file
            description = self.workspace.description
            self.status.showMessage("Target changed — capability manifest updated; review and SHA-256 seal required")
            self._load_workspace(files, main, description, key)
        self._update_action_state()

    def _update_languages(self):
        config = MODES[self.current_mode_key()]
        self.language.blockSignals(True)
        self.language.clear()
        self.language.addItems(list(config.languages))
        self.language.setCurrentText(config.default_language)
        self.language.blockSignals(False)
        self.highlighter.set_language(self.language.currentText())
        self._update_action_state()

    def _update_action_state(self):
        language = self.language.currentText() if hasattr(self, "language") else ""
        mode = self.current_mode_key() if hasattr(self, "mode") else "chromaplex"
        has_file = bool(self.workspace.selected_file)
        chroma = mode == "chromaplex" and language in {"CPL", "CPA"}
        self.save_button.setEnabled(has_file)
        self.seal_button.setEnabled(has_file)
        self.run_button.setEnabled(has_file and (MODES[mode].execution_capable or chroma))
        native_build = (mode == "linux" and language == "C") or (mode == "windows" and language == "C#") or (mode == "web" and language == "WebAssembly (WAT)")
        self.compile_button.setEnabled(has_file and (chroma or native_build))
        self.binary_button.setEnabled(has_file and (chroma or native_build))
        self.preview_button.setEnabled(has_file and mode == "web")
        if hasattr(self, "highlighter"):
            self.highlighter.set_language(language)

    def _load_workspace(self, files: dict[str, str], main: str, description: str = "", target: str | None = None):
        self.workspace.load(files, main, description, target or self.current_target_key())
        self.tree.clear()
        items: dict[str, QTreeWidgetItem] = {}
        for name in sorted(self.workspace.files):
            parts = name.split("/")
            parent = self.tree.invisibleRootItem()
            prefix = ""
            for i, part in enumerate(parts):
                prefix = f"{prefix}/{part}".strip("/")
                if prefix not in items:
                    item = QTreeWidgetItem([part])
                    item.setData(0, Qt.ItemDataRole.UserRole, prefix if i == len(parts) - 1 else "")
                    parent.addChild(item)
                    items[prefix] = item
                parent = items[prefix]
        self.tree.expandAll()
        target = items.get(self.workspace.main_file)
        if target:
            self.tree.setCurrentItem(target)
        elif self.workspace.files:
            self._show_file(next(iter(self.workspace.files)))
        self._update_action_state()

    def _show_file(self, filename: str):
        if filename not in self.workspace.files:
            return
        self._persist_editor()
        self.workspace.selected_file = filename
        self._loading_editor = True
        self.editor.setPlainText(self.workspace.files[filename])
        self._loading_editor = False
        self.filename_label.setText(filename)
        self.highlighter.set_language(self.language.currentText())
        self._update_action_state()

    def _file_selected(self, current, previous):
        if not current:
            return
        filename = current.data(0, Qt.ItemDataRole.UserRole)
        if filename:
            self._show_file(filename)

    def _persist_editor(self):
        if self._loading_editor or not self.workspace.selected_file:
            return
        self.workspace.set_content(self.workspace.selected_file, self.editor.toPlainText())

    def _editor_changed(self):
        if not self._loading_editor:
            self._persist_editor()
            if self.workspace.selected_file:
                self.filename_label.setText(self.workspace.selected_file + " *")
                self.status.showMessage("Edited — SHA-256 seal invalidated; review and seal again before execution/export")

    def _compile_policy(self, *, reviewed: bool = False) -> SecureCompilePolicy:
        enabled = str(self.settings.value("online_reputation", "false")).lower() in {"1", "true", "yes"}
        return SecureCompilePolicy(
            malware_scan_required=True,
            online_reputation_enabled=enabled,
            online_reputation_required=False,
            allow_reviewed_source=reviewed,
        )

    def _reputation_provider(self):
        if not self._compile_policy().online_reputation_enabled:
            return None
        key = CredentialStore.get("virustotal") or ""
        return VirusTotalHashReputation(key) if key else None

    def _compiler_preflight(self, *, reviewed: bool = True):
        language = self.language.currentText()
        if "Projekt" in language:
            language = ""
        caps = CapabilityManifest.from_json(self.workspace.files[CAPABILITY_FILENAME])
        return preflight_sources(
            self.workspace.files,
            language=language,
            target=self.current_target_key(),
            capability_manifest=caps,
            scanner=ClamAVScanner(timeout=int(self.settings.value("timeout", DEFAULT_TIMEOUT))),
            policy=self._compile_policy(reviewed=reviewed),
        )

    def security_review_and_seal(self):
        self._persist_editor()
        if not self.workspace.files:
            return
        report = scan_files(self.workspace.files)
        if report.level == SafetyLevel.BLOCKED:
            QMessageBox.critical(
                self,
                "Execution blocked",
                "The security review found blocked high-risk behaviour. The project cannot be SHA-256 sealed for execution.\n\n" + report.summary,
            )
            self.status.showMessage("BLOCKED by security review")
            return
        reviewed = False
        if report.level == SafetyLevel.REVIEW:
            answer = QMessageBox.warning(
                self,
                "Manual security review required",
                report.summary + "\n\nIf this behaviour is intentional and you have reviewed the code, scan and seal this exact version?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )
            if answer != QMessageBox.StandardButton.Yes:
                self.status.showMessage("Security review not approved")
                return
            reviewed = True
        try:
            caps = CapabilityManifest.from_json(self.workspace.files[CAPABILITY_FILENAME])
            language = self.language.currentText()
            if "Projekt" in language:
                language = ""
            gate = preflight_sources(
                self.workspace.files,
                language=language,
                target=self.current_target_key(),
                capability_manifest=caps,
                scanner=ClamAVScanner(timeout=int(self.settings.value("timeout", DEFAULT_TIMEOUT))),
                policy=self._compile_policy(reviewed=reviewed),
            )
        except Exception as exc:
            QMessageBox.critical(self, "Secure Compile Gate", str(exc))
            self.status.showMessage("BLOCKED by Secure Compile Gate")
            return
        manifest = self.workspace.seal()
        self.status.showMessage(f"Secure SHA-256 seal: {len(manifest.files)} file(s)")
        QMessageBox.information(
            self,
            "Secure source sealed",
            f"Static analysis: {gate.static.level.value}\nMalware scan: {gate.malware.engine} / {gate.malware.state.value}\nFiles sealed: {len(manifest.files)}\n\nAny edit invalidates this approval before Run/Compile/Build/Preview/Export.",
        )

    def _require_verified_integrity(self) -> bool:
        try:
            self.workspace.require_verified_seal()
            return True
        except Exception as exc:
            QMessageBox.warning(
                self,
                "SHA-256 verification required",
                str(exc) + "\n\nRun Security review + SHA-256 seal first.",
            )
            self.status.showMessage("Blocked: SHA-256 verification required")
            return False

    def open_api_settings(self):
        dialog = ApiSettingsDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            ok, message = dialog.save()
            if not ok and message:
                QMessageBox.warning(self, "Credential storage", message)

    def _make_agent(self) -> AIAgent | None:
        provider = self.settings.value("provider", "openai")
        key = CredentialStore.get(provider)
        if not key:
            QMessageBox.warning(self, "Missing API key", f"Configure a {provider} API key in Settings → API settings.")
            return None
        if provider == "openai":
            model = self.settings.value("openai_model", DEFAULT_OPENAI_MODEL)
        else:
            model = self.settings.value("caffeine_model", DEFAULT_CAFFEINE_MODEL)
        try:
            timeout = int(self.settings.value("timeout", DEFAULT_TIMEOUT))
        except ValueError:
            timeout = DEFAULT_TIMEOUT
        return AIAgent(provider, key, model, timeout)

    def generate(self):
        prompt = self.prompt.toPlainText().strip()
        if not prompt:
            QMessageBox.information(self, "Prompt", "Enter a description first.")
            return
        agent = self._make_agent()
        if not agent:
            return
        mode = self.current_mode_key()
        language = self.language.currentText()
        self.generate_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.status.showMessage("Generating…")
        self.thread = QThread(self)
        self.worker = GenerateWorker(agent, prompt, mode, language, self.current_target_key())
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.status.connect(self.status.showMessage)
        self.worker.finished.connect(self._generation_finished)
        self.worker.error.connect(self._generation_error)
        self.worker.finished.connect(self.thread.quit)
        self.worker.error.connect(self.thread.quit)
        self.thread.finished.connect(self._thread_finished)
        self.thread.start()

    def cancel_generation(self):
        if self.worker:
            self.worker.cancel()
            self.status.showMessage("Cancelling…")
            self.cancel_button.setEnabled(False)

    def _thread_finished(self):
        if self.worker:
            self.worker.deleteLater()
        if self.thread:
            self.thread.deleteLater()
        self.worker = None
        self.thread = None
        self.generate_button.setEnabled(True)
        self.cancel_button.setEnabled(False)

    def _generation_error(self, message: str):
        self.status.showMessage("Generation failed")
        self.output.setPlainText("ERROR:\n" + message)

    def _generation_finished(self, response):
        mode = self.current_mode_key()
        language = self.language.currentText()
        try:
            if "Projekt" in language:
                files, main, description = parse_project_json(response.text)
            else:
                main = default_filename(mode, language)
                files, description = {main: response.text}, ""
            self._load_workspace(files, main, description, self.current_target_key())
            self.output.setPlainText(f"Generated {len(files)} file(s) with {response.provider}/{response.model}.")
            self.status.showMessage("Generation complete")
            entry = {
                "time": datetime.now().isoformat(timespec="seconds"),
                "mode": mode,
                "language": language,
                "target": self.current_target_key(),
                "prompt": self.prompt.toPlainText().strip(),
                "files": dict(files),
                "main": main,
            }
            self.history.append(entry)
            item = QListWidgetItem(f"{entry['time']}  {MODES[mode].name}/{language}: {entry['prompt'][:60]}")
            item.setData(Qt.ItemDataRole.UserRole, len(self.history) - 1)
            self.history_list.addItem(item)
        except Exception as exc:
            self.output.setPlainText("Generated response could not be loaded:\n" + str(exc) + "\n\nRAW:\n" + response.text)
            self.status.showMessage("Invalid generated project")

    def save_current_file(self):
        self._persist_editor()
        name = self.workspace.selected_file
        if not name:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save file", Path(name).name)
        if path:
            saved = Path(path)
            saved.write_text(self.workspace.files[name], encoding="utf-8")
            write_file_sidecar(saved)
            self.workspace.dirty.discard(name)
            self.filename_label.setText(name)

    def save_project_folder(self):
        self._persist_editor()
        if not self.workspace.files:
            return
        if not self._require_verified_integrity():
            return
        directory = QFileDialog.getExistingDirectory(self, "Choose project folder")
        if directory:
            target = self.workspace.write_to(Path(directory))
            self.workspace.write_integrity_files(target)
            self.workspace.dirty.clear()
            self.status.showMessage(f"Verified project saved to {directory}")

    def export_zip(self):
        self._persist_editor()
        if not self.workspace.files:
            return
        if not self._require_verified_integrity():
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export project ZIP", "chromaplex-project.zip", "ZIP (*.zip)")
        if path:
            if not path.lower().endswith(".zip"):
                path += ".zip"
            self.workspace.export_zip(Path(path))
            self.status.showMessage(f"Exported {path}")

    def open_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open source file")
        if path:
            source = Path(path).read_text(encoding="utf-8")
            self._load_workspace({Path(path).name: source}, Path(path).name, target=self.current_target_key())

    def _effective_runtime_language(self) -> str:
        language = self.language.currentText()
        if "Projekt" not in language:
            return language
        filename = self.workspace.main_file or self.workspace.selected_file
        lower = filename.lower()
        mode = self.current_mode_key()
        if mode == "linux":
            if lower.endswith(".sh"):
                return "Bash"
            if lower.endswith(".py"):
                return "Python (Linux)"
            if lower.endswith(".c"):
                return "C"
            if Path(filename).name.lower() in {"makefile", "gnumakefile"} or lower.endswith(".mk"):
                return "Makefile"
        if mode == "windows":
            if lower.endswith(".ps1"):
                return "PowerShell"
            if lower.endswith((".bat", ".cmd")):
                return "Batch"
            if lower.endswith(".cs"):
                return "C#"
            if lower.endswith(".py"):
                return "Python (Windows)"
        raise RuntimeError(f"Could not infer a runnable language from project main file: {filename}")

    def run_current(self):
        self._persist_editor()
        if not self.workspace.selected_file:
            return
        mode = self.current_mode_key()
        language = self._effective_runtime_language() if mode != "chromaplex" else self.language.currentText()
        if not self._require_verified_integrity():
            return
        try:
            self._compiler_preflight(reviewed=True)
            if mode == "chromaplex":
                source = self.workspace.files[self.workspace.selected_file]
                result = run_cpl(source) if language == "CPL" else run_cpa(source)
                self.output.setPlainText(
                    f"Dialect: {result.dialect}\n\n=== OUTPUT ===\n{result.output}\n\n=== CPA ===\n{result.assembly}"
                )
            else:
                directory = self.workspace.runtime_dir()
                result = run_project(directory, self.workspace.main_file or self.workspace.selected_file, language, int(self.settings.value("timeout", DEFAULT_TIMEOUT)), reviewed=True, target=self.current_target_key())
                self.output.setPlainText(result.text)
            self.right_tabs.setCurrentIndex(0)
        except Exception as exc:
            self.output.setPlainText("RUN ERROR:\n" + str(exc))
            self.right_tabs.setCurrentIndex(0)

    def compile_current(self):
        self._persist_editor()
        if not self.workspace.selected_file or not self._require_verified_integrity():
            return
        mode = self.current_mode_key()
        language = self.language.currentText()
        source = self.workspace.files[self.workspace.selected_file]
        try:
            gate = self._compiler_preflight(reviewed=True)
            if mode == "chromaplex":
                if language == "CPL":
                    assembly, dialect = compile_cpl(source)
                    self.output.setPlainText(f"Secure Compile Gate: {gate.malware.state.value} ({gate.malware.engine})\nMemory safety: {gate.memory.level.value}\nDialect: {dialect}\n\n{assembly}")
                else:
                    result = run_cpa(source)
                    self.output.setPlainText(f"Secure Compile Gate: {gate.malware.state.value} ({gate.malware.engine})\nMemory safety: {gate.memory.level.value}\nCPA validated with {result.dialect}.\n\n{source}")
            else:
                self.output.setPlainText(f"Pre-compile gates passed.\nStatic: {gate.static.level.value}\nMemory safety: {gate.memory.level.value}\nMalware scan: {gate.malware.state.value}\n\nUse Build binary/bundle to compile in quarantine and validate the output structure.")
            self.right_tabs.setCurrentIndex(0)
        except Exception as exc:
            self.output.setPlainText("COMPILE ERROR:\n" + str(exc))

    def build_binary_current(self):
        self._persist_editor()
        if not self.workspace.selected_file or not self._require_verified_integrity():
            return
        mode = self.current_mode_key()
        language = self.language.currentText()
        if mode == "chromaplex":
            suggested, filter_text = "program.bin", "Binary (*.bin)"
        elif mode == "linux" and language == "C":
            target_profile = get_target(self.current_target_key())
            if target_profile.is_embedded:
                suggested, filter_text = "firmware.bin", "Embedded firmware (*.bin)"
            elif target_profile.is_raspberry_pi:
                suggested, filter_text = "program-arm", "ARM ELF executable (*)"
            else:
                suggested, filter_text = "program", "ELF executable (*)"
        elif mode == "windows" and language == "C#":
            suggested, filter_text = "program.exe", "Windows executable (*.exe)"
        elif mode == "web" and language == "WebAssembly (WAT)":
            suggested, filter_text = "module.wasm", "WebAssembly (*.wasm)"
        else:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Secure build output", suggested, filter_text)
        if not path:
            return
        try:
            source = self.workspace.files[self.workspace.selected_file]
            scanner = ClamAVScanner(timeout=int(self.settings.value("timeout", DEFAULT_TIMEOUT)))
            policy = self._compile_policy(reviewed=True)
            if mode == "chromaplex":
                result = secure_build_chromaplex(source, language, Path(path), scanner=scanner, reputation_provider=self._reputation_provider(), policy=policy)
            else:
                caps = CapabilityManifest.from_json(self.workspace.files[CAPABILITY_FILENAME])
                if mode == "linux":
                    target_profile = get_target(self.current_target_key())
                    if target_profile.is_embedded:
                        project_dir = self.workspace.runtime_dir()
                        result = secure_build_embedded_project(project_dir, Path(path), scanner=scanner, reputation_provider=self._reputation_provider(), policy=policy, capability_manifest=caps, timeout=int(self.settings.value("timeout", DEFAULT_TIMEOUT)))
                    else:
                        result = secure_build_c(source, Path(path), scanner=scanner, reputation_provider=self._reputation_provider(), policy=policy, capability_manifest=caps, timeout=int(self.settings.value("timeout", DEFAULT_TIMEOUT)))
                elif mode == "windows":
                    result = secure_build_csharp(source, Path(path), scanner=scanner, reputation_provider=self._reputation_provider(), policy=policy, capability_manifest=caps, timeout=int(self.settings.value("timeout", DEFAULT_TIMEOUT)))
                else:
                    result = secure_build_wasm(source, Path(path), scanner=scanner, reputation_provider=self._reputation_provider(), policy=policy, capability_manifest=caps, timeout=int(self.settings.value("timeout", DEFAULT_TIMEOUT)))
            self.output.setPlainText(
                "SECURE BUILD APPROVED\n"
                f"Built: {result.output_path}\n"
                f"SHA-256: {result.binary_sha256}\n"
                f"Memory safety: {result.source_gate.memory.level.value}\n"
                f"Binary format: {result.binary_validation.format}\n"
                f"Entropy: {result.binary_validation.entropy:.3f} bits/byte\n"
                f"Packed: {result.binary_validation.packed}\n"
                f"Malware scan: {result.binary_scan.engine} / {result.binary_scan.state.value}\n"
                f"Online reputation: {result.reputation.provider} / {result.reputation.state.value}\n"
                f"Security manifest: {result.security_manifest_path}\n"
                f"SHA sidecar: {result.sha256_path}\n"
                + ("\n=== CPA ===\n" + result.assembly if result.assembly else "")
            )
        except Exception as exc:
            self.output.setPlainText("SECURE BUILD BLOCKED:\n" + str(exc))

    def preview_current(self):
        self._persist_editor()
        if self.current_mode_key() != "web" or not self.workspace.selected_file:
            return
        if not self._require_verified_integrity():
            return
        language = self.language.currentText()
        directory = self.workspace.runtime_dir()
        target: Path | None = None
        if language == "HTML/CSS":
            target = directory / (self.workspace.main_file or self.workspace.selected_file)
        elif language == "JavaScript":
            js_name = self.workspace.selected_file
            target = directory / "__preview__.html"
            target.write_text(
                "<!doctype html><meta charset='utf-8'><title>Preview</title><body><div id='app'></div><script src='" + html.escape(js_name) + "'></script></body>",
                encoding="utf-8",
            )
        else:
            html_files = [directory / name for name in self.workspace.files if name.lower().endswith((".html", ".htm"))]
            if html_files:
                target = html_files[0]
        if not target or not target.exists():
            QMessageBox.information(self, "Preview", "No static HTML preview is available for this project. Flask/React may require their own runtime/build step.")
            return
        url = QUrl.fromLocalFile(str(target.resolve()))
        if self.web_view:
            self.web_view.setUrl(url)
            self.right_tabs.setCurrentWidget(self.web_view)
        else:
            QDesktopServices.openUrl(url)

    def show_history(self, item):
        index = item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(index, int) or not 0 <= index < len(self.history):
            return
        entry = self.history[index]
        text = json.dumps({k: v for k, v in entry.items() if k != "files"}, ensure_ascii=False, indent=2)
        QMessageBox.information(self, "History", text)

    def closeEvent(self, event):
        self._persist_editor()
        self.workspace.cleanup_runtime_dir()
        if self.thread and self.thread.isRunning():
            QMessageBox.information(self, "Generation in progress", "Cancel the active generation before closing.")
            event.ignore()
            return
        event.accept()
