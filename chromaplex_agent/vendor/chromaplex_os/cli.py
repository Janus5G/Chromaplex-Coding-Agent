"""Kommandolinjegrænseflade for ChromaPlex OS."""

import argparse
import sys
from .assembler import assemble
from .compiler import CPLCompiler
from .vm import VirtualMachine
from .storage import CrystalStorage

def main():
    parser = argparse.ArgumentParser(description="ChromaPlex OS CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    asm_parser = subparsers.add_parser("assemble", help="Assemblér CPA fil til bytecode")
    asm_parser.add_argument("input", help="Input .cpa fil")
    asm_parser.add_argument("-o", "--output", help="Output binær fil", required=True)

    comp_parser = subparsers.add_parser("compile", help="Kompilér CPL fil til bytecode")
    comp_parser.add_argument("input", help="Input .cpl fil")
    comp_parser.add_argument("-o", "--output", help="Output binær fil", required=True)

    run_parser = subparsers.add_parser("run", help="Kør et program")
    run_parser.add_argument("input", help="Binær fil (.bin) eller kildekode (.cpl) med --source")
    run_parser.add_argument("--source", action="store_true", help="Input er CPL kildekode, kompilér og kør")
    run_parser.add_argument("--storage", help="Krystallagerfil (JSON) at loade/gemme", default=None)

    args = parser.parse_args()

    if args.command == "assemble":
        with open(args.input, "r") as f:
            asm_text = f.read()
        bytecode = assemble(asm_text)
        with open(args.output, "wb") as f:
            f.write(bytecode)
        print(f"Assembleret til {args.output} ({len(bytecode)} bytes)")

    elif args.command == "compile":
        with open(args.input, "r") as f:
            cpl_source = f.read()
        compiler = CPLCompiler()
        asm_text = compiler.compile(cpl_source)
        bytecode = assemble(asm_text)
        with open(args.output, "wb") as f:
            f.write(bytecode)
        print(f"Kompileret {args.input} -> {args.output} ({len(bytecode)} bytes)")

    elif args.command == "run":
        if args.source:
            with open(args.input, "r") as f:
                cpl_source = f.read()
            compiler = CPLCompiler()
            asm_text = compiler.compile(cpl_source)
            bytecode = assemble(asm_text)
        else:
            with open(args.input, "rb") as f:
                bytecode = f.read()

        storage = CrystalStorage()
        if args.storage:
            import json, os
            if os.path.exists(args.storage):
                with open(args.storage, "r") as f:
                    stored_data = json.load(f)
                for key_str, val in stored_data.items():
                    x, y, z = map(int, key_str.split(","))
                    for col_idx_str, v in val.items():
                        storage.write_voxel(x, y, z, int(col_idx_str), v)

        vm = VirtualMachine(storage)
        vm.load_program(bytecode)
        vm.run()

        print("Kørsel færdig.")
        print(storage.stats())
        print("Registre:", vm.registers)

        if args.storage:
            import json
            out = {}
            for (x,y,z), vox in storage.data.items():
                key = f"{x},{y},{z}"
                out[key] = {str(k): v for k, v in vox.items()}
            with open(args.storage, "w") as f:
                json.dump(out, f, indent=2)

if __name__ == "__main__":
    main()
