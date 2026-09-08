"""CPL (ChromaPlex Language) til CPA assembly compiler."""

import re

class CPLCompiler:
    def __init__(self):
        self.vars = {}
        self.next_reg = 0
        self.asm_lines = []
        self.label_counter = 0

    def allocate_reg(self, name):
        if name in self.vars:
            return self.vars[name]
        if self.next_reg >= 8:
            raise RuntimeError("Ikke flere registre (max 8).")
        reg = self.next_reg
        self.next_reg += 1
        self.vars[name] = reg
        return reg

    def emit(self, line):
        self.asm_lines.append("    " + line)

    def compile(self, source: str) -> str:
        self.vars = {}
        self.next_reg = 0
        self.asm_lines = []
        self.label_counter = 0
        source = source.lstrip('\ufeff')
        lines = source.splitlines()
        for line in lines:
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            self.process_statement(line)
        self.emit("HALT")
        return "\n".join(self.asm_lines)

    def process_statement(self, line: str):
        m = re.match(r"var\s+(\w+)\s*=\s*(.+);?", line)
        if m:
            reg = self.allocate_reg(m.group(1))
            self.compile_expr(m.group(2).strip(), reg)
            return
        m = re.match(r"(\w+)\s*=\s*(.+);?", line)
        if m:
            name, expr = m.group(1), m.group(2).strip()
            if name not in self.vars:
                self.allocate_reg(name)
            self.compile_expr(expr, self.vars[name])
            return
        m = re.match(r"print\s+(.+);?", line)
        if m:
            self.compile_expr(m.group(1).strip(), 7)
            self.emit("PRINT R7")
            return
        m = re.match(r"store\s+(.+?)\s+at\s*\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)(?:\s+colour\s+(\w+))?;?", line)
        if m:
            self.compile_expr(m.group(1).strip(), 7)
            colour = m.group(5) if m.group(5) else "GREEN"
            self.emit(f"SET_COLOR {colour.upper()}")
            self.emit(f"POSITION {m.group(2)}, {m.group(3)}, {m.group(4)}")
            self.emit("LASER_WRITE R7")
            return
        m = re.match(r"load\s+(\w+)\s+from\s*\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)(?:\s+colour\s+(\w+))?;?", line)
        if m:
            reg = self.allocate_reg(m.group(1))
            colour = m.group(5) if m.group(5) else "GREEN"
            self.emit(f"SET_COLOR {colour.upper()}")
            self.emit(f"POSITION {m.group(2)}, {m.group(3)}, {m.group(4)}")
            self.emit(f"LASER_READ R{reg}")
            return
        raise SyntaxError(f"Ikke-understøttet sætning: {line}")

    def compile_expr(self, expr: str, target_reg: int):
        expr = expr.strip()
        if re.match(r"^\d+$", expr):
            self.emit(f"MOV R{target_reg}, {expr}")
            return
        if expr in self.vars:
            src = self.vars[expr]
            if src != target_reg:
                self.emit(f"MOV R{target_reg}, R{src}")
            return
        m = re.match(r"(.+)\s*\+\s*(.+)", expr)
        if m:
            self.compile_expr(m.group(1).strip(), target_reg)
            self.compile_expr(m.group(2).strip(), 6)
            self.emit(f"ADD R{target_reg}, R6")
            return
        m = re.match(r"(.+)\s*\-\s*(.+)", expr)
        if m:
            self.compile_expr(m.group(1).strip(), target_reg)
            self.compile_expr(m.group(2).strip(), 6)
            self.emit(f"SUB R{target_reg}, R6")
            return
        raise SyntaxError(f"Ikke-understøttet udtryk: {expr}")
