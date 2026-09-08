"""Brainfuck til CPA compiler - Turing-komplethedsbevis."""

_MAX_BF_SOURCE_LENGTH = 1_000_000


class BFtoCPA:
    def __init__(self):
        self.label_counter = 0
        self.cpa_lines = [
            "; === Brainfuck til CPA kompilering ===",
            "LOAD.IMM B, 0    ; ptr = 0",
            ""
        ]

    def compile(self, bf_code: str) -> str:
        if not isinstance(bf_code, str):
            raise TypeError("bf_code skal være en tekststreng")
        if len(bf_code) > _MAX_BF_SOURCE_LENGTH:
            raise ValueError("Brainfuck-kilden er for stor")
        bf_code = ''.join(c for c in bf_code if c in '><+-.,[]')
        labels = {}
        stack = []

        for i, ch in enumerate(bf_code):
            if ch == '[':
                label = f"L{self.label_counter}"
                labels[i] = label
                self.label_counter += 1
                stack.append(i)
            elif ch == ']':
                if not stack:
                    raise SyntaxError(f"Manglende '[' for ']' ved pos {i}")
                start = stack.pop()
                labels[i] = labels[start] + "_end"

        if stack:
            raise SyntaxError(f"Manglende ']' for '[' ved pos {stack[0]}")

        for i, ch in enumerate(bf_code):
            if ch == '>':
                self._emit("ADD.IMM B, B, 1    ; ptr++")
            elif ch == '<':
                self._emit("SUB.IMM B, B, 1    ; ptr--")
            elif ch == '+':
                self._emit("LOAD.C R, (B,0,0), rød")
                self._emit("ADD.IMM R, R, 1")
                self._emit("STORE.C (B,0,0), rød, R")
            elif ch == '-':
                self._emit("LOAD.C R, (B,0,0), rød")
                self._emit("SUB.IMM R, R, 1")
                self._emit("STORE.C (B,0,0), rød, R")
            elif ch == '.':
                self._emit("LOAD.C R, (B,0,0), rød")
                self._emit("OUT R")
            elif ch == ',':
                self._emit("IN R")
                self._emit("STORE.C (B,0,0), rød, R")
            elif ch == '[':
                label = labels[i]
                self._emit(f"{label}:")
                self._emit("LOAD.C R, (B,0,0), rød")
                self._emit("CMP.IMM R, 0")
                self._emit(f"JMP.IF EQ, {label}_end")
            elif ch == ']':
                start_label = labels[i].replace("_end", "")
                self._emit(f"JMP {start_label}")
                self._emit(f"{labels[i]}:")

        self._emit("")
        self._emit("HALT")
        return "\n".join(self.cpa_lines)

    def _emit(self, line):
        self.cpa_lines.append(line)


def compile_bf_to_cpa(bf_code: str) -> str:
    compiler = BFtoCPA()
    return compiler.compile(bf_code)


def main():
    import sys
    if len(sys.argv) < 2:
        print("Brug: bf2cpa <fil.bf>")
        return
    if sys.argv[1] == '--string':
        bf = sys.argv[2]
    else:
        with open(sys.argv[1]) as f:
            bf = f.read()
    try:
        print(compile_bf_to_cpa(bf))
    except SyntaxError as e:
        print(f"Fejl: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
