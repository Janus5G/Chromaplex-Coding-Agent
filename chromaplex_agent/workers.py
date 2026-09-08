from __future__ import annotations

from PySide6.QtCore import QObject, Signal, Slot

from .ai_client import AIAgent


class GenerateWorker(QObject):
    finished = Signal(object)
    error = Signal(str)
    status = Signal(str)

    def __init__(self, agent: AIAgent, prompt: str, mode: str, language: str, target: str | None = None):
        super().__init__()
        self.agent = agent
        self.prompt = prompt
        self.mode = mode
        self.language = language
        self.target = target
        self.cancelled = False

    @Slot()
    def run(self):
        try:
            if self.cancelled:
                self.error.emit("Generation cancelled")
                return
            self.status.emit("Generating code…")
            response = self.agent.generate(self.prompt, self.mode, self.language, self.target)
            if self.cancelled:
                self.error.emit("Generation cancelled")
                return
            self.finished.emit(response)
        except Exception as exc:
            self.error.emit(str(exc))

    @Slot()
    def cancel(self):
        self.cancelled = True
