#!/usr/bin/env python3
"""
Test framework for comparing goblin's MachOWriter against Apple's install_name_tool.

This script tests various modifications on dylib files and compares the output
of goblin's install_name_tool implementation against Apple's official tool.

Usage:
    python test_install_name_tool.py [options] <dylib_path_or_folder>

Options:
    --goblin-tool PATH    Path to goblin's install_name_tool binary
    --max-files N         Maximum number of files to test (default: all)
    --verbose, -v         Verbose output
    --strict              Require bit-for-bit identical output (not just structural)
    --skip-fat            Skip fat/universal binaries
    --operations OPS      Comma-separated list of operations to test
                          (change_id, add_rpath, delete_rpath, change_rpath)
"""

import argparse
import hashlib
import os
import random
import shutil
import string
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Optional


def safe_copy(src: Path, dst: Path) -> None:
    """Copy a file without copying file flags (which can fail on system files)."""
    shutil.copy(src, dst)  # Copies content and permission bits only
    # Make it writable so we can modify it
    os.chmod(dst, 0o644)


class TestResult(Enum):
    PASS = auto()
    FAIL = auto()
    SKIP = auto()
    ERROR = auto()


@dataclass
class TestCase:
    name: str
    operation: str
    args: list[str]
    result: TestResult = TestResult.SKIP
    error_message: str = ""
    goblin_size: int = 0
    apple_size: int = 0
    diff_offset: Optional[int] = None


@dataclass
class FileTestResult:
    path: Path
    test_cases: list[TestCase] = field(default_factory=list)
    is_fat: bool = False
    install_name: Optional[str] = None
    rpaths: list[str] = field(default_factory=list)
    dylibs: list[str] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for tc in self.test_cases if tc.result == TestResult.PASS)

    @property
    def failed(self) -> int:
        return sum(1 for tc in self.test_cases if tc.result == TestResult.FAIL)

    @property
    def skipped(self) -> int:
        return sum(1 for tc in self.test_cases if tc.result == TestResult.SKIP)

    @property
    def errors(self) -> int:
        return sum(1 for tc in self.test_cases if tc.result == TestResult.ERROR)


def random_string(length: int = 16) -> str:
    """Generate a random string for test paths."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def random_path() -> str:
    """Generate a random dylib-like path."""
    components = [
        "@rpath",
        "@executable_path",
        "@loader_path",
        "/usr/lib",
        "/usr/local/lib",
        "/opt/homebrew/lib",
    ]
    base = random.choice(components)
    subpath = "/".join(random_string(8) for _ in range(random.randint(1, 3)))
    name = f"lib{random_string(8)}.dylib"
    return f"{base}/{subpath}/{name}"


def get_macho_info(path: Path) -> dict:
    """Get information about a Mach-O binary using otool."""
    info = {
        "install_name": None,
        "rpaths": [],
        "dylibs": [],
        "is_fat": False,
    }

    # Check if it's a fat binary
    try:
        result = subprocess.run(
            ["lipo", "-info", str(path)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if "Architectures in the fat file" in result.stdout:
            info["is_fat"] = True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Get load commands
    try:
        result = subprocess.run(
            ["otool", "-l", str(path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return info

        lines = result.stdout.split("\n")
        i = 0
        while i < len(lines):
            line = lines[i].strip()

            if line == "cmd LC_ID_DYLIB":
                # Find the name
                for j in range(i, min(i + 10, len(lines))):
                    if "name " in lines[j]:
                        name = lines[j].split("name ")[1].split(" (offset")[0].strip()
                        info["install_name"] = name
                        break

            elif line == "cmd LC_RPATH":
                for j in range(i, min(i + 10, len(lines))):
                    if "path " in lines[j]:
                        path_val = (
                            lines[j].split("path ")[1].split(" (offset")[0].strip()
                        )
                        info["rpaths"].append(path_val)
                        break

            elif line in (
                "cmd LC_LOAD_DYLIB",
                "cmd LC_LOAD_WEAK_DYLIB",
                "cmd LC_REEXPORT_DYLIB",
                "cmd LC_LAZY_LOAD_DYLIB",
            ):
                for j in range(i, min(i + 10, len(lines))):
                    if "name " in lines[j]:
                        name = lines[j].split("name ")[1].split(" (offset")[0].strip()
                        info["dylibs"].append(name)
                        break

            i += 1

    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return info


def compare_binaries(path1: Path, path2: Path, strict: bool = False) -> tuple[bool, str]:
    """
    Compare two binary files.

    If strict=True, requires bit-for-bit identical.
    If strict=False, allows some differences (timestamps, padding).
    """
    data1 = path1.read_bytes()
    data2 = path2.read_bytes()

    if data1 == data2:
        return True, "Identical"

    if strict:
        # Find first difference
        for i, (b1, b2) in enumerate(zip(data1, data2)):
            if b1 != b2:
                return False, f"First difference at offset 0x{i:x}: 0x{b1:02x} vs 0x{b2:02x}"
        if len(data1) != len(data2):
            return False, f"Size difference: {len(data1)} vs {len(data2)} bytes"
        return False, "Unknown difference"

    # Non-strict comparison: check structural equivalence
    # Parse both with otool and compare the parsed info
    info1 = get_macho_info(path1)
    info2 = get_macho_info(path2)

    differences = []

    if info1["install_name"] != info2["install_name"]:
        differences.append(
            f"install_name: {info1['install_name']} vs {info2['install_name']}"
        )

    if set(info1["rpaths"]) != set(info2["rpaths"]):
        differences.append(f"rpaths: {info1['rpaths']} vs {info2['rpaths']}")

    if set(info1["dylibs"]) != set(info2["dylibs"]):
        differences.append(f"dylibs: {info1['dylibs']} vs {info2['dylibs']}")

    if differences:
        return False, "; ".join(differences)

    # Structural match but byte differences (likely timestamps/padding)
    size_diff = abs(len(data1) - len(data2))
    return True, f"Structural match (size diff: {size_diff} bytes)"


def run_apple_tool(
    input_path: Path, output_path: Path, operation: str, args: list[str]
) -> tuple[bool, str]:
    """Run Apple's install_name_tool."""
    cmd = ["install_name_tool"]

    if operation == "change_id":
        cmd.extend(["-id", args[0]])
    elif operation == "add_rpath":
        cmd.extend(["-add_rpath", args[0]])
    elif operation == "delete_rpath":
        cmd.extend(["-delete_rpath", args[0]])
    elif operation == "change_rpath":
        cmd.extend(["-rpath", args[0], args[1]])
    else:
        return False, f"Unknown operation: {operation}"

    # Copy input to output first
    safe_copy(input_path, output_path)

    cmd.append(str(output_path))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return False, result.stderr.strip() or "Unknown error"
        return True, ""
    except subprocess.TimeoutExpired:
        return False, "Timeout"
    except FileNotFoundError:
        return False, "install_name_tool not found"


def run_goblin_tool(
    goblin_path: Path,
    input_path: Path,
    output_path: Path,
    operation: str,
    args: list[str],
) -> tuple[bool, str]:
    """Run goblin's install_name_tool."""
    cmd = [str(goblin_path)]

    if operation == "change_id":
        cmd.extend(["-id", args[0]])
    elif operation == "add_rpath":
        cmd.extend(["-add_rpath", args[0]])
    elif operation == "delete_rpath":
        cmd.extend(["-delete_rpath", args[0]])
    elif operation == "change_rpath":
        cmd.extend(["-rpath", args[0], args[1]])
    else:
        return False, f"Unknown operation: {operation}"

    # Copy input to output first (goblin tool modifies in place)
    safe_copy(input_path, output_path)

    cmd.append(str(output_path))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return False, result.stderr.strip() or "Unknown error"
        return True, ""
    except subprocess.TimeoutExpired:
        return False, "Timeout"
    except FileNotFoundError:
        return False, f"Goblin tool not found at {goblin_path}"


def test_file(
    dylib_path: Path,
    goblin_tool: Path,
    operations: list[str],
    strict: bool = False,
    verbose: bool = False,
) -> FileTestResult:
    """Test a single dylib file with various operations."""
    result = FileTestResult(path=dylib_path)

    # Get info about the file
    info = get_macho_info(dylib_path)
    result.is_fat = info["is_fat"]
    result.install_name = info["install_name"]
    result.rpaths = info["rpaths"]
    result.dylibs = info["dylibs"]

    if verbose:
        print(f"  Install name: {result.install_name}")
        print(f"  RPaths: {result.rpaths}")
        print(f"  Is fat: {result.is_fat}")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Test change_id (only for dylibs with install name)
        if "change_id" in operations and result.install_name:
            new_id = random_path()
            tc = TestCase(
                name="change_id",
                operation="change_id",
                args=[new_id],
            )

            apple_out = tmpdir / "apple_change_id.dylib"
            goblin_out = tmpdir / "goblin_change_id.dylib"

            apple_ok, apple_err = run_apple_tool(
                dylib_path, apple_out, "change_id", [new_id]
            )
            goblin_ok, goblin_err = run_goblin_tool(
                goblin_tool, dylib_path, goblin_out, "change_id", [new_id]
            )

            if not apple_ok:
                tc.result = TestResult.SKIP
                tc.error_message = f"Apple tool failed: {apple_err}"
            elif not goblin_ok:
                tc.result = TestResult.ERROR
                tc.error_message = f"Goblin tool failed: {goblin_err}"
            else:
                tc.goblin_size = goblin_out.stat().st_size
                tc.apple_size = apple_out.stat().st_size
                match, msg = compare_binaries(goblin_out, apple_out, strict)
                if match:
                    tc.result = TestResult.PASS
                else:
                    tc.result = TestResult.FAIL
                    tc.error_message = msg

            result.test_cases.append(tc)

        # Test add_rpath
        if "add_rpath" in operations:
            new_rpath = f"@executable_path/../Frameworks/{random_string(8)}"
            tc = TestCase(
                name="add_rpath",
                operation="add_rpath",
                args=[new_rpath],
            )

            apple_out = tmpdir / "apple_add_rpath.dylib"
            goblin_out = tmpdir / "goblin_add_rpath.dylib"

            apple_ok, apple_err = run_apple_tool(
                dylib_path, apple_out, "add_rpath", [new_rpath]
            )
            goblin_ok, goblin_err = run_goblin_tool(
                goblin_tool, dylib_path, goblin_out, "add_rpath", [new_rpath]
            )

            if not apple_ok:
                tc.result = TestResult.SKIP
                tc.error_message = f"Apple tool failed: {apple_err}"
            elif not goblin_ok:
                tc.result = TestResult.ERROR
                tc.error_message = f"Goblin tool failed: {goblin_err}"
            else:
                tc.goblin_size = goblin_out.stat().st_size
                tc.apple_size = apple_out.stat().st_size
                match, msg = compare_binaries(goblin_out, apple_out, strict)
                if match:
                    tc.result = TestResult.PASS
                else:
                    tc.result = TestResult.FAIL
                    tc.error_message = msg

            result.test_cases.append(tc)

        # Test delete_rpath (only if there are rpaths)
        if "delete_rpath" in operations and result.rpaths:
            rpath_to_delete = result.rpaths[0]
            tc = TestCase(
                name="delete_rpath",
                operation="delete_rpath",
                args=[rpath_to_delete],
            )

            apple_out = tmpdir / "apple_delete_rpath.dylib"
            goblin_out = tmpdir / "goblin_delete_rpath.dylib"

            apple_ok, apple_err = run_apple_tool(
                dylib_path, apple_out, "delete_rpath", [rpath_to_delete]
            )
            goblin_ok, goblin_err = run_goblin_tool(
                goblin_tool, dylib_path, goblin_out, "delete_rpath", [rpath_to_delete]
            )

            if not apple_ok:
                tc.result = TestResult.SKIP
                tc.error_message = f"Apple tool failed: {apple_err}"
            elif not goblin_ok:
                tc.result = TestResult.ERROR
                tc.error_message = f"Goblin tool failed: {goblin_err}"
            else:
                tc.goblin_size = goblin_out.stat().st_size
                tc.apple_size = apple_out.stat().st_size
                match, msg = compare_binaries(goblin_out, apple_out, strict)
                if match:
                    tc.result = TestResult.PASS
                else:
                    tc.result = TestResult.FAIL
                    tc.error_message = msg

            result.test_cases.append(tc)

        # Test change_rpath (only if there are rpaths)
        if "change_rpath" in operations and result.rpaths:
            old_rpath = result.rpaths[0]
            new_rpath = f"@loader_path/../lib/{random_string(8)}"
            tc = TestCase(
                name="change_rpath",
                operation="change_rpath",
                args=[old_rpath, new_rpath],
            )

            apple_out = tmpdir / "apple_change_rpath.dylib"
            goblin_out = tmpdir / "goblin_change_rpath.dylib"

            apple_ok, apple_err = run_apple_tool(
                dylib_path, apple_out, "change_rpath", [old_rpath, new_rpath]
            )
            goblin_ok, goblin_err = run_goblin_tool(
                goblin_tool,
                dylib_path,
                goblin_out,
                "change_rpath",
                [old_rpath, new_rpath],
            )

            if not apple_ok:
                tc.result = TestResult.SKIP
                tc.error_message = f"Apple tool failed: {apple_err}"
            elif not goblin_ok:
                tc.result = TestResult.ERROR
                tc.error_message = f"Goblin tool failed: {goblin_err}"
            else:
                tc.goblin_size = goblin_out.stat().st_size
                tc.apple_size = apple_out.stat().st_size
                match, msg = compare_binaries(goblin_out, apple_out, strict)
                if match:
                    tc.result = TestResult.PASS
                else:
                    tc.result = TestResult.FAIL
                    tc.error_message = msg

            result.test_cases.append(tc)

    return result


def find_dylibs(path: Path, max_files: Optional[int] = None) -> list[Path]:
    """Find all dylib files in a directory or return single file."""
    if path.is_file():
        # Resolve symlinks and check readability
        resolved = path.resolve()
        if resolved.exists() and os.access(resolved, os.R_OK):
            return [resolved]
        return []

    dylibs = []
    for root, dirs, files in os.walk(path):
        for f in files:
            if f.endswith(".dylib"):
                p = Path(root) / f
                # Resolve symlinks and check if file actually exists and is readable
                try:
                    resolved = p.resolve()
                    if resolved.exists() and os.access(resolved, os.R_OK):
                        dylibs.append(resolved)
                        if max_files and len(dylibs) >= max_files:
                            return dylibs
                except (OSError, IOError):
                    # Skip files that can't be resolved
                    pass

    return dylibs


def build_goblin_tool(project_root: Path) -> Optional[Path]:
    """Build the goblin install_name_tool example."""
    print("Building goblin install_name_tool...")
    result = subprocess.run(
        ["cargo", "build", "--release", "--example", "install_name_tool"],
        cwd=project_root,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"Failed to build: {result.stderr}")
        return None

    tool_path = project_root / "target" / "release" / "examples" / "install_name_tool"
    if tool_path.exists():
        return tool_path
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Test goblin MachOWriter against Apple's install_name_tool"
    )
    parser.add_argument(
        "path",
        type=Path,
        help="Path to dylib file or folder containing dylibs",
    )
    parser.add_argument(
        "--goblin-tool",
        type=Path,
        default=None,
        help="Path to goblin's install_name_tool binary",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=None,
        help="Maximum number of files to test",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Require bit-for-bit identical output",
    )
    parser.add_argument(
        "--skip-fat",
        action="store_true",
        help="Skip fat/universal binaries",
    )
    parser.add_argument(
        "--operations",
        type=str,
        default="change_id,add_rpath,delete_rpath,change_rpath",
        help="Comma-separated list of operations to test",
    )

    args = parser.parse_args()

    # Build or find the goblin tool
    goblin_tool = args.goblin_tool
    if goblin_tool is None:
        # Try to find it relative to this script
        script_dir = Path(__file__).parent
        project_root = script_dir.parent.parent
        goblin_tool = build_goblin_tool(project_root)
        if goblin_tool is None:
            print("Error: Could not build goblin install_name_tool")
            sys.exit(1)

    if not goblin_tool.exists():
        print(f"Error: Goblin tool not found at {goblin_tool}")
        sys.exit(1)

    print(f"Using goblin tool: {goblin_tool}")

    # Find dylibs to test
    dylibs = find_dylibs(args.path, args.max_files)
    if not dylibs:
        print(f"No dylib files found in {args.path}")
        sys.exit(1)

    print(f"Found {len(dylibs)} dylib(s) to test")

    operations = [op.strip() for op in args.operations.split(",")]
    print(f"Testing operations: {operations}")
    print()

    # Run tests
    total_passed = 0
    total_failed = 0
    total_skipped = 0
    total_errors = 0

    for i, dylib in enumerate(dylibs, 1):
        print(f"[{i}/{len(dylibs)}] Testing {dylib.name}...")

        result = test_file(
            dylib,
            goblin_tool,
            operations,
            strict=args.strict,
            verbose=args.verbose,
        )

        if args.skip_fat and result.is_fat:
            print(f"  SKIPPED (fat binary)")
            total_skipped += len(operations)
            continue

        for tc in result.test_cases:
            if tc.result == TestResult.PASS:
                total_passed += 1
                if args.verbose:
                    print(f"  PASS: {tc.name}")
            elif tc.result == TestResult.FAIL:
                total_failed += 1
                print(f"  FAIL: {tc.name}")
                print(f"    {tc.error_message}")
                print(f"    Goblin size: {tc.goblin_size}, Apple size: {tc.apple_size}")
            elif tc.result == TestResult.SKIP:
                total_skipped += 1
                if args.verbose:
                    print(f"  SKIP: {tc.name} - {tc.error_message}")
            elif tc.result == TestResult.ERROR:
                total_errors += 1
                print(f"  ERROR: {tc.name}")
                print(f"    {tc.error_message}")

    # Summary
    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  Passed:  {total_passed}")
    print(f"  Failed:  {total_failed}")
    print(f"  Skipped: {total_skipped}")
    print(f"  Errors:  {total_errors}")
    print()

    if total_failed > 0 or total_errors > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
