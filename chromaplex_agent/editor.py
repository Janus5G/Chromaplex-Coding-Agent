"""Editable code widget derived from the supplied Refract Studio editor design."""
from __future__ import annotations

import re

from PySide6.QtCore import QRect, QSize, Qt, Signal
from PySide6.QtGui import (
    QColor,
    QFontDatabase,
    QPainter,
    QSyntaxHighlighter,
    QTextCharFormat,
    QTextFormat,
)
from PySide6.QtWidgets import QPlainTextEdit, QTextEdit, QWidget


class LineNumberArea(QWidget):
    def __init__(self, editor: "CodeEditor"):
        super().__init__(editor)
        self.editor = editor

    def sizeHint(self):
        return QSize(self.editor.line_number_area_width(), 0)

    def paintEvent(self, event):
        self.editor.line_number_area_paint_event(event)


class CodeEditor(QPlainTextEdit):
    edited = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.line_number_area = LineNumberArea(self)
        self.blockCountChanged.connect(self.update_line_number_area_width)
        self.updateRequest.connect(self.update_line_number_area)
        self.cursorPositionChanged.connect(self.highlight_current_line)
        self.textChanged.connect(self.edited)
        self.update_line_number_area_width(0)
        self.highlight_current_line()
        font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        font.setPointSize(11)
        self.setFont(font)
        self.setTabStopDistance(self.fontMetrics().horizontalAdvance(" ") * 4)
        self.setStyleSheet(
            "QPlainTextEdit { background:#101318; color:#e7eaf0; border:0; selection-background-color:#315a8a; }"
        )

    def line_number_area_width(self):
        digits = len(str(max(1, self.blockCount())))
        return 8 + self.fontMetrics().horizontalAdvance("9") * digits

    def update_line_number_area_width(self, _):
        self.setViewportMargins(self.line_number_area_width(), 0, 0, 0)

    def update_line_number_area(self, rect, dy):
        if dy:
            self.line_number_area.scroll(0, dy)
        else:
            self.line_number_area.update(0, rect.y(), self.line_number_area.width(), rect.height())
        if rect.contains(self.viewport().rect()):
            self.update_line_number_area_width(0)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        cr = self.contentsRect()
        self.line_number_area.setGeometry(
            QRect(cr.left(), cr.top(), self.line_number_area_width(), cr.height())
        )

    def highlight_current_line(self):
        selection = QTextEdit.ExtraSelection()
        selection.format.setBackground(QColor("#171c23"))
        selection.format.setProperty(QTextFormat.Property.FullWidthSelection, True)
        selection.cursor = self.textCursor()
        selection.cursor.clearSelection()
        self.setExtraSelections([selection])

    def line_number_area_paint_event(self, event):
        painter = QPainter(self.line_number_area)
        painter.fillRect(event.rect(), QColor("#0c0f13"))
        block = self.firstVisibleBlock()
        number = block.blockNumber()
        top = self.blockBoundingGeometry(block).translated(self.contentOffset()).top()
        bottom = top + self.blockBoundingRect(block).height()
        while block.isValid() and top <= event.rect().bottom():
            if block.isVisible() and bottom >= event.rect().top():
                painter.setPen(QColor("#6f7b8a"))
                painter.drawText(
                    0,
                    int(top),
                    self.line_number_area.width() - 4,
                    self.fontMetrics().height(),
                    Qt.AlignmentFlag.AlignRight,
                    str(number + 1),
                )
            block = block.next()
            top = bottom
            bottom = top + self.blockBoundingRect(block).height()
            number += 1


class CodeHighlighter(QSyntaxHighlighter):
    COMMON = {
        "Python": ["def", "class", "if", "else", "elif", "for", "while", "return", "import", "from", "try", "except", "with", "as", "True", "False", "None"],
        "Bash": ["if", "then", "else", "fi", "for", "do", "done", "case", "esac", "function", "in"],
        "C": ["int", "char", "float", "double", "void", "struct", "typedef", "if", "else", "for", "while", "return", "include"],
        "C#": ["class", "namespace", "using", "public", "private", "static", "void", "string", "int", "if", "else", "foreach", "return", "new"],
        "JavaScript": ["const", "let", "var", "function", "class", "if", "else", "for", "while", "return", "async", "await", "import", "export"],
        "CPL": ["var", "store", "load", "print", "streng", "tal", "potens", "konstant", "pixel", "for", "skriv_voxel", "kanal"],
        "CPA": ["LOAD", "STORE", "ADD", "SUB", "OUT", "IN", "HALT", "PACK", "UNPACK", "JMP", "CMP", "MOV", "SET_COLOR", "POSITION", "LASER_WRITE", "LASER_READ", "PRINT"],
    }

    def __init__(self, document):
        super().__init__(document)
        self.language = ""
        self._keyword = QTextCharFormat()
        self._keyword.setForeground(QColor("#c792ea"))
        self._string = QTextCharFormat()
        self._string.setForeground(QColor("#ecc48d"))
        self._comment = QTextCharFormat()
        self._comment.setForeground(QColor("#69798c"))
        self._number = QTextCharFormat()
        self._number.setForeground(QColor("#82aaff"))

    def set_language(self, language: str) -> None:
        self.language = language
        self.rehighlight()

    def highlightBlock(self, text: str) -> None:
        language = self.language
        base = language
        if language.startswith("Python"):
            base = "Python"
        if language in {"HTML/CSS", "React"}:
            base = "JavaScript"
        words = self.COMMON.get(base, [])
        for word in words:
            for match in re.finditer(r"\b" + re.escape(word) + r"\b", text, re.IGNORECASE if base in {"CPL", "CPA"} else 0):
                self.setFormat(match.start(), match.end() - match.start(), self._keyword)
        for match in re.finditer(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'', text):
            self.setFormat(match.start(), match.end() - match.start(), self._string)
        comment_patterns = [r"//.*$", r"#.*$"] if base not in {"C", "C#", "JavaScript", "CPL", "CPA"} else [r"//.*$"]
        for pattern in comment_patterns:
            for match in re.finditer(pattern, text):
                self.setFormat(match.start(), match.end() - match.start(), self._comment)
        for match in re.finditer(r"\b(?:0x[0-9a-fA-F]+|\d+(?:\.\d+)?)\b", text):
            self.setFormat(match.start(), match.end() - match.start(), self._number)
