from __future__ import annotations

import json
import os
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from chromaplex_agent.binary_validation import validate_binary
from chromaplex_agent.capabilities import CAPABILITY_FILENAME, CapabilityManifest, default_manifest, load_manifest
from chromaplex_agent.hardening import format_verity, install_hardening_assets, lockdown_state
from chromaplex_agent.malware_scan import MalwareScanResult, MalwareScanState
from chromaplex_agent.memory_safety import MemorySafetyLevel, scan_memory_safety
from chromaplex_agent.project import Workspace
from chromaplex_agent.sandbox import SandboxPolicy, build_bwrap_command
from chromaplex_agent.secure_compile import SecureCompileError, SecureCompilePolicy, secure_build_c
from chromaplex_agent.security import SafetyLevel, scan_files


class CleanScanner:
    def scan_file(self, path: Path):
        return MalwareScanResult(MalwareScanState.CLEAN, "test", "clean")
    def scan_directory(self, path: Path):
        return MalwareScanResult(MalwareScanState.CLEAN, "test", "clean")


class MemorySafetyTests(unittest.TestCase):
    def test_safe_c_subset_passes(self):
        r = scan_memory_safety({"main.c": "int main(void){ int x=1; return x-1; }"}, "C")
        self.assertEqual(r.level, MemorySafetyLevel.SAFE)

    def test_raw_pointer_is_blocked(self):
        r = scan_memory_safety({"main.c": "int main(void){ int *p = 0; return 0; }"}, "C")
        self.assertEqual(r.level, MemorySafetyLevel.BLOCKED)

    def test_malloc_is_blocked(self):
        r = scan_memory_safety({"main.c": "void f(void){ malloc(10); }"}, "C")
        self.assertEqual(r.level, MemorySafetyLevel.BLOCKED)

    def test_unbounded_string_api_is_blocked(self):
        r = scan_memory_safety({"main.c": 'void f(char a[8]){ strcpy(a,"123"); }'}, "C")
        self.assertEqual(r.level, MemorySafetyLevel.BLOCKED)

    def test_csharp_unsafe_is_blocked(self):
        r = scan_memory_safety({"Program.cs": "unsafe class X { }"}, "C#")
        self.assertEqual(r.level, MemorySafetyLevel.BLOCKED)

    def test_python_ctypes_escape_is_blocked(self):
        r = scan_memory_safety({"main.py": "import ctypes"}, "Python (Linux)")
        self.assertEqual(r.level, MemorySafetyLevel.BLOCKED)


class CapabilityTests(unittest.TestCase):
    def test_workspace_always_gets_explicit_manifest(self):
        w = Workspace(); w.load({"main.py": "print(1)"}, "main.py")
        self.assertIn(CAPABILITY_FILENAME, w.files)
        CapabilityManifest.from_json(w.files[CAPABILITY_FILENAME]).validate()

    def test_system_write_is_rejected(self):
        data = default_manifest().to_dict(); data["filesystem"]["system"] = "read-write"
        with self.assertRaises(ValueError):
            CapabilityManifest.from_dict(data)

    def test_manifest_is_required_on_runtime_disk(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(RuntimeError):
                load_manifest(Path(td), required=True)

    @unittest.skipUnless(shutil.which("bwrap"), "bubblewrap not installed")
    def test_default_bwrap_has_no_network_or_home_bind(self):
        with tempfile.TemporaryDirectory() as td:
            cmd = build_bwrap_command(Path(td), ["/usr/bin/true"], SandboxPolicy(default_manifest()))
        self.assertIn("--unshare-all", cmd)
        self.assertNotIn("--share-net", cmd)
        self.assertNotIn(str(Path.home()), cmd)


class BinaryValidatorTests(unittest.TestCase):
    def _write(self, data: bytes) -> Path:
        td = tempfile.mkdtemp(prefix="binary_validator_"); self.addCleanup(lambda: shutil.rmtree(td, ignore_errors=True))
        p = Path(td) / "x.bin"; p.write_bytes(data); return p

    def test_valid_minimal_wasm(self):
        p = self._write(b"\x00asm\x01\x00\x00\x00")
        r = validate_binary(p, "WASM")
        self.assertTrue(r.valid); self.assertEqual(r.format, "WASM")

    def test_bad_wasm_section_bounds_rejected(self):
        p = self._write(b"\x00asm\x01\x00\x00\x00\x01\x7f")
        self.assertFalse(validate_binary(p, "WASM").valid)

    def test_upx_marker_blocks_binary(self):
        # Valid-ish wasm custom section carrying an UPX marker: format parser can
        # parse it, packer policy still blocks release.
        p = self._write(b"\x00asm\x01\x00\x00\x00\x00\x04UPX!")
        r = validate_binary(p, "WASM")
        self.assertTrue(r.packed); self.assertFalse(r.valid)

    def test_invalid_pe_rejected(self):
        p = self._write(b"MZ" + b"\0" * 100)
        self.assertFalse(validate_binary(p, "PE").valid)

    def test_invalid_elf_rejected(self):
        p = self._write(b"\x7fELF" + b"\0" * 20)
        self.assertFalse(validate_binary(p, "ELF").valid)


class PackerSourcePolicyTests(unittest.TestCase):
    def test_upx_command_is_blocked(self):
        r = scan_files({"build.sh": "upx program"})
        self.assertEqual(r.level, SafetyLevel.BLOCKED)


class HardeningPackTests(unittest.TestCase):
    def test_lockdown_state_parser(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "lockdown"; p.write_text("none [integrity] confidentiality\n")
            self.assertEqual(lockdown_state(p), "INTEGRITY")

    def test_assets_install_into_rootfs(self):
        with tempfile.TemporaryDirectory() as td:
            out = install_hardening_assets(Path(td))
            self.assertTrue((Path(td) / "etc/apparmor.d/chromaplex-generated").exists())
            self.assertTrue((Path(td) / "etc/default/grub.d/60-chromaplex-lockdown.cfg").exists())
            self.assertEqual(len(out), 2)

    @unittest.skipUnless(shutil.which("apparmor_parser"), "apparmor_parser not installed")
    def test_shipped_apparmor_profile_parses(self):
        profile = Path(__file__).resolve().parents[1] / "hardening/apparmor.d/chromaplex-generated"
        import subprocess
        proc = subprocess.run(["apparmor_parser", "-Q", "-T", str(profile)], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_verity_helper_records_root_hash(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); data = root / "rootfs.img"; data.write_bytes(b"rootfs")
            tool = root / "veritysetup"
            tool.write_text('#!/bin/sh\n: > "$3"\necho "Root hash: aabbccdd"\necho "Salt: 00112233"\nexit 0\n')
            os.chmod(tool, 0o755)
            manifest = format_verity(data, root / "rootfs.hash", veritysetup=str(tool))
            self.assertEqual(manifest["root_hash"], "aabbccdd")
            self.assertTrue(manifest["read_only"])


class NativeSecureBuildTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("gcc"), "gcc not installed")
    def test_safe_c_build_is_hardened_scanned_structurally_validated(self):
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "program"
            r = secure_build_c("int main(void){ int x=1; return x-1; }", output, scanner=CleanScanner(), policy=SecureCompilePolicy(), capability_manifest=default_manifest())
            self.assertTrue(output.exists())
            self.assertEqual(r.binary_validation.format, "ELF")
            self.assertTrue(r.binary_validation.valid)
            manifest = json.loads(r.security_manifest_path.read_text())
            self.assertEqual(manifest["memory_safety"], "SAFE")
            self.assertFalse(manifest["binary_validation"]["packed"])

    @unittest.skipUnless(shutil.which("gcc"), "gcc not installed")
    def test_unsafe_c_never_emits_binary(self):
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "program"
            with self.assertRaisesRegex(SecureCompileError, "MEMORY SAFETY"):
                secure_build_c("int main(void){ int *p=0; return 0; }", output, scanner=CleanScanner(), capability_manifest=default_manifest())
            self.assertFalse(output.exists())

    @unittest.skipUnless(shutil.which("gcc"), "gcc not installed")
    def test_native_build_requires_explicit_capability_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaisesRegex(SecureCompileError, "explicit capability manifest"):
                secure_build_c("int main(void){return 0;}", Path(td) / "program", scanner=CleanScanner())


if __name__ == "__main__":
    unittest.main()


class EmbeddedTargetPolicyTests(unittest.TestCase):
    def _caps(self, target="esp32", **kwargs):
        data = dict(
            target=target,
            board="esp32:esp32:esp32s3" if target == "esp32" else "arduino:avr:uno",
            network=False,
            allow_hardware=(),
            mmio_ranges=(),
        )
        data.update(kwargs)
        return CapabilityManifest(**data)

    def test_embedded_raw_pointer_is_review_not_blocked(self):
        caps = self._caps()
        r = scan_memory_safety({"main.cpp": "void f(){ int x=1; int *p=&x; (void)p; }"}, "C/C++ (Embedded)", target="esp32", capability_manifest=caps)
        self.assertEqual(r.level, MemorySafetyLevel.REVIEW)
        self.assertFalse(any(f.level == MemorySafetyLevel.BLOCKED for f in r.findings))

    def test_embedded_unbounded_copy_remains_blocked(self):
        caps = self._caps()
        r = scan_memory_safety({"main.cpp": 'void f(char *d,const char*s){ strcpy(d,s); }'}, "C/C++ (Embedded)", target="esp32", capability_manifest=caps)
        self.assertEqual(r.level, MemorySafetyLevel.BLOCKED)

    def test_declared_mmio_is_allowed_for_review(self):
        from chromaplex_agent.capabilities import MMIORange
        caps = self._caps(mmio_ranges=(MMIORange(0x60004000, 0x60004FFF, "UART_REGS"),))
        src = "void f(){ *(volatile unsigned int *)0x60004010 = 1; }"
        r = scan_memory_safety({"main.cpp": src}, "C/C++ (Embedded)", target="esp32", capability_manifest=caps)
        self.assertNotEqual(r.level, MemorySafetyLevel.BLOCKED)
        self.assertFalse(any(f.rule == "undeclared-mmio-address" for f in r.findings))

    def test_undeclared_mmio_is_blocked(self):
        caps = self._caps()
        src = "void f(){ *(volatile unsigned int *)0x60004010 = 1; }"
        r = scan_memory_safety({"main.cpp": src}, "C/C++ (Embedded)", target="esp32", capability_manifest=caps)
        self.assertEqual(r.level, MemorySafetyLevel.BLOCKED)
        self.assertTrue(any(f.rule == "undeclared-mmio-address" for f in r.findings))

    def test_declared_gpio_is_not_blocked(self):
        caps = self._caps(allow_hardware=("GPIO_2",))
        r = scan_memory_safety({"main.ino": "void setup(){ pinMode(2,OUTPUT); digitalWrite(2,HIGH); }"}, "Arduino Sketch", target="esp32", capability_manifest=caps)
        self.assertNotEqual(r.level, MemorySafetyLevel.BLOCKED)

    def test_undeclared_gpio_is_blocked(self):
        caps = self._caps()
        r = scan_memory_safety({"main.ino": "void setup(){ pinMode(2,OUTPUT); }"}, "Arduino Sketch", target="esp32", capability_manifest=caps)
        self.assertEqual(r.level, MemorySafetyLevel.BLOCKED)
        self.assertTrue(any(f.rule == "hardware-gpio-2" for f in r.findings))

    def test_wifi_requires_both_hardware_and_network_capability(self):
        src = 'void setup(){ WiFi.begin("ssid","pw"); }'
        caps = self._caps(network=False, allow_hardware=("WIFI",))
        r = scan_memory_safety({"main.cpp": src}, "C/C++ (Embedded)", target="esp32", capability_manifest=caps)
        self.assertEqual(r.level, MemorySafetyLevel.BLOCKED)
        caps2 = self._caps(network=True, allow_hardware=("WIFI",))
        r2 = scan_memory_safety({"main.cpp": src}, "C/C++ (Embedded)", target="esp32", capability_manifest=caps2)
        self.assertNotEqual(r2.level, MemorySafetyLevel.BLOCKED)

    def test_embedded_malloc_without_free_is_review_not_blocked(self):
        caps = self._caps()
        r = scan_memory_safety({"main.cpp": "void f(){ void *p=malloc(32); (void)p; }"}, "C/C++ (Embedded)", target="esp32", capability_manifest=caps)
        self.assertEqual(r.level, MemorySafetyLevel.REVIEW)
        self.assertTrue(any(f.rule == "embedded-allocation-lifetime" for f in r.findings))

    def test_raspberry_pi_keeps_strict_memory_policy(self):
        caps = CapabilityManifest(target="raspberry-pi", board="raspberry-pi-5")
        r = scan_memory_safety({"main.c": "int main(){ int *p=0; return p!=0; }"}, "C", target="raspberry-pi", capability_manifest=caps)
        self.assertEqual(r.level, MemorySafetyLevel.BLOCKED)


class UnknownReputationTests(unittest.TestCase):
    def test_unknown_reputation_is_not_blocked_when_not_required(self):
        from chromaplex_agent.malware_scan import ReputationResult, ReputationState
        import chromaplex_agent.secure_compile as secure_compile_mod
        class UnknownProvider:
            def lookup_sha256(self, sha256: str):
                return ReputationResult(ReputationState.UNKNOWN, "test-reputation", "new internal firmware hash")
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "firmware.bin"
            p.write_bytes(b"new-firmware")
            policy = SecureCompilePolicy(online_reputation_enabled=True, online_reputation_required=False)
            rep = secure_compile_mod._reputation(p, UnknownProvider(), policy)
            self.assertEqual(rep.state, ReputationState.UNKNOWN)

    def test_unknown_reputation_blocks_only_when_enterprise_policy_requires_known_clean(self):
        from chromaplex_agent.malware_scan import ReputationResult, ReputationState
        import chromaplex_agent.secure_compile as secure_compile_mod
        class UnknownProvider:
            def lookup_sha256(self, sha256: str):
                return ReputationResult(ReputationState.UNKNOWN, "test-reputation", "new internal firmware hash")
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "firmware.bin"
            p.write_bytes(b"new-firmware")
            policy = SecureCompilePolicy(online_reputation_enabled=True, online_reputation_required=True)
            with self.assertRaisesRegex(SecureCompileError, "required online reputation"):
                secure_compile_mod._reputation(p, UnknownProvider(), policy)


class RaspberryPiDeploymentProfileTests(unittest.TestCase):
    def test_generated_apparmor_reflects_capabilities(self):
        from chromaplex_agent.hardening import generate_apparmor_profile
        caps = CapabilityManifest(target="raspberry-pi", board="raspberry-pi-5", network=True, process_spawn=False)
        text = generate_apparmor_profile(Path("/opt/acme/sensor"), Path("/var/lib/acme-sensor"), caps, profile_name="acme-sensor")
        self.assertIn("profile acme-sensor /opt/acme/sensor", text)
        self.assertIn("network,", text)
        self.assertIn("/var/lib/acme-sensor/** rwk,", text)
        self.assertNotIn("/home/**", text)
        self.assertNotIn("/usr/bin/** ix", text)

    def test_generated_apparmor_process_spawn_is_explicit(self):
        from chromaplex_agent.hardening import generate_apparmor_profile
        caps = CapabilityManifest(target="raspberry-pi", board="raspberry-pi-5", process_spawn=True)
        text = generate_apparmor_profile(Path("/opt/acme/app"), Path("/var/lib/acme"), caps)
        self.assertIn("/usr/bin/** ix,", text)

    def test_apparmor_generator_rejects_non_pi_target(self):
        from chromaplex_agent.hardening import generate_apparmor_profile
        with self.assertRaises(ValueError):
            generate_apparmor_profile(Path("/opt/app"), Path("/var/lib/app"), CapabilityManifest(target="linux-desktop"))
