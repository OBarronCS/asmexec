#!/usr/bin/env python3
# /// script
# dependencies = [
#   "pwntools",
#   "pyelftools"
# ]
# ///

import argparse

from enum import Enum, auto
import pathlib
import random
from pathlib import Path
import shlex
import sys
import os
import os.path
import shutil
import stat
import elftools
import pwnlib
import pwnlib.tubes.process
import pwnlib.util.misc
import pwnlib.gdb
import pwnlib.context
import pwnlib.elf
from pwnlib.log import install_default_handler

import platform

import subprocess
import tempfile
from typing import Dict
from typing import List
from typing import Literal
from typing import Tuple

from asmexec.helpers import find_cached_version

QEMU_HOST = "127.0.0.1"
USER_CODE_SECTION_NAME = ".text"
ENTRY_SYMBOL_NAME = "__start"

pwnlib.context.context.log_level = "debug"
pwnlib.context.context.terminal = ["tmux", "splitw", "-h", "-l", "80%"]

# This defines the canonical names for arches used by this tool
# These names are the ones zig uses to identify architectures.
# Supported zig architectures can be obtained using the command: `zig targets`
# Tuple of (qemu name, endian, instruction_bytes_to_display)
MAPPING: dict[str, tuple[str, str, int]] = {
    "x86_64": ("qemu-x86_64", "little", 10),
    "x86": ("qemu-i386", "little", 10),
    "mips": ("qemu-mips", "big", 4),
    "mipsel": ("qemu-mipsel", "little", 4),
    "mips64": ("qemu-mips64", "big", 4),
    "mips64el": ("qemu-mips64el", "little", 4),
    "aarch64": ("qemu-aarch64", "little", 4),
    "aarch64_be": (
        "qemu-aarch64_be",
        "big",
        4,
    ),
    "arm": ("qemu-arm", "little", 4),
    "armeb": ("qemu-armeb", "big", 4),
    "thumb": ("qemu-arm", "little", 4),
    "thumbeb": ("qemu-armeb", "big", 4),
    "riscv32": ("qemu-riscv32", "little", 4),
    "riscv64": ("qemu-riscv64", "little", 4),
    "sparc": ("qemu-sparc", "little", 4),
    "sparc64": ("qemu-sparc64", "little", 4),
    "powerpc": ("qemu-ppc", "big", 4),
    "powerpcle": ("qemu-ppc", "little", 4),
    "powerpc64": ("qemu-ppc64", "big", 4),
    "powerpc64le": ("qemu-ppc64le", "little", 4),
    "loongarch64": ("qemu-loongarch64", "little", 4),
    "s390x": ("qemu-s390x", "little", 4),
}

MUSL_TARGET_NAME: dict[str, str | None] = {
    "x86_64": "linux-musl",
    "x86": "linux-musl",
    "mips": "linux-musleabi",
    "mipsel": "linux-musleabi",
    "mips64": "linux-muslabi64",
    "mips64el": "linux-muslabi64",
    "aarch64": "linux-musl",
    "aarch64_be": "linux-musl",
    "arm": "linux-musleabihf",
    "armeb": "linux-musleabihf",
    "thumb": "linux-musleabihf",
    "thumbeb": "linux-musleabihf",
    "riscv32": "linux-musl",
    "riscv64": "linux-musl",
    "sparc": None,
    "sparc64": None,
    "powerpc": "linux-musl",
    "powerpcle": "linux-musl",
    "powerpc64": "linux-musl",
    "powerpc64le": "linux-musl",
    "loongarch64": "linux-musl",
    "s390x": "linux-musl",
}

ARCHITECTURE_NAME_ALIASES: dict[str, set[str]] = {
    "x86_64": {"amd64", "x64", "x86-64"},
    "x86": {"i386", "i686"},
    "aarch64": {"arm64"},
    "arm": {"arm32"},
    "riscv32": {"rv32"},
    "riscv64": {"rv64"},
    "powerpc": {"ppc"},
    "powerpcle": {"ppcle"},
    "powerpc64": {"ppc64"},
    "powerpc64le": {"ppc64le"},
    "loongarch64": {"loong64"},
}

REVERSE_ARCH_NAME_ALIAS_MAP: dict[str, str] = {}

PWNTOOLS_NAMING_CONVERSION: dict[str, str] = {"amd64": "x86_64", "i386": "x86"}

allowed_architectures = list(MAPPING.keys())

for canonical_name, value in ARCHITECTURE_NAME_ALIASES.items():
    for alias in value:
        allowed_architectures.append(alias)
        REVERSE_ARCH_NAME_ALIAS_MAP[alias] = canonical_name

_prefix_header = f".global _start;.global __start\n.section {USER_CODE_SECTION_NAME}\n_start:;__start:\n"

INTEL_SYNTAX = ".intel_syntax noprefix"
ATT_SYNTAX = ".att_syntax prefix"


SYNTAX_TABLE: Dict[str, str] = {"intel": INTEL_SYNTAX, "att": ATT_SYNTAX}

ARCHES_WHERE_SELECT_SYNTAX = ("x86_64", "x86")

DEFAULT_SYNTAX = "intel"
VALID_SYNTAX = list(SYNTAX_TABLE.keys())

_asm_header: Dict[str, str] = {
    # `.intel_syntax noprefix` forces the use of Intel assembly syntax instead of AT&T
    "x86_64": _prefix_header + "\n",
    "x86": _prefix_header + "\n",
    # `.set noreorder` disables instruction reordering for MIPS to handle delay slots correctly
    "mips": _prefix_header + ".set noreorder\n",
    "mipsel": _prefix_header + ".set noreorder\n",
    "mips64": _prefix_header + ".set noreorder\n",
    "mips64el": _prefix_header + ".set noreorder\n",
    "aarch64": _prefix_header,
    "aarch64_be": _prefix_header,
    # `.syntax unified` enables the unified assembly syntax for ARM/Thumb
    "arm": _prefix_header + ".syntax unified\n",
    "armeb": _prefix_header + ".syntax unified\n",
    "thumb": _prefix_header + ".syntax unified\n",
    "thumbeb": _prefix_header + ".syntax unified\n",
    "riscv32": _prefix_header,
    "riscv64": _prefix_header,
    "sparc": _prefix_header,
    "sparc64": _prefix_header,
    "powerpc": _prefix_header,
    "powerpcle": _prefix_header,
    "powerpc64": _prefix_header,
    "powerpc64le": _prefix_header,
    "loongarch64": _prefix_header,
    "s390x": _prefix_header,
}


# A simplified version of gdb.attach from pwntools with our own architecture mappings
def debug(arch: str, filepath: str, gdbscript: str | None = None):
    runner = pwnlib.tubes.process.process
    which = pwnlib.util.misc.which

    exe = which(filepath)

    gdbscript = gdbscript or ""
    port = random.randint(1024, 65535)

    qemu_name, endian, instruction_size = MAPPING[arch]

    # This prints a lot of stuff, so disabling logging here temporarily
    pwnlib.context.context.log_level = "error"
    sysroot = pwnlib.qemu.ld_prefix(path=qemu_name)
    pwnlib.context.context.log_level = "debug"

    qemu_args = [qemu_name, "-g", str(port)]

    if sysroot:
        qemu_args += ["-L", sysroot]

    args = qemu_args + [filepath]

    gdbserver = runner(args, aslr=1)

    # pwnlib.context.context.gdb_binary = "gdb"

    tmp = pwnlib.gdb.attach(
        (QEMU_HOST, port), exe=exe, gdbscript=gdbscript, sysroot=sysroot
    )

    return gdbserver


def run_program(filepath: str):
    return pwnlib.tubes.process.process(filepath)


def get_zig_executable() -> str:
    """
    Get the path to the zig executable.
    Precedence: ziglang module, zig in PATH.
    """
    try:
        import ziglang  # type: ignore[import-untyped]

        return os.path.join(os.path.dirname(ziglang.__file__), "zig")
    except ImportError:
        pass

    zig_path = shutil.which("zig")
    if zig_path is None:
        raise ValueError(
            "Python module ziglang not available and zig not found in PATH"
        )

    return zig_path


def zig_compile_c_to_elf(
    arch: str,
    c_source_code: str,
    musl: bool,
) -> str:
    """
    Return path to the compiled file
    """
    zig_executable = get_zig_executable()

    if musl:
        musl_target_name = MUSL_TARGET_NAME.get(arch)
        if not musl_target_name:
            print(f"musl libc not supported for '{arch}'")
            sys.exit(1)
        target = f"{arch}-{musl_target_name}"
    else:
        target = f"{arch}-freestanding"

    cached_file_path, is_cached = find_cached_version(
        [zig_executable, "cc", "-target", "-o"], c_source_code, arch, "", None
    )

    if is_cached:
        return cached_file_path

    with tempfile.TemporaryDirectory(delete=False) as tmpdir:
        c_source_file = os.path.join(tmpdir, "input.C")
        linker_script = os.path.join(tmpdir, "link.ld")
        compiled_file = os.path.join(tmpdir, "out.elf")
        bytecode_file = os.path.join(tmpdir, "out.bytecode")

        command_to_run = [
            zig_executable,
            "cc",
            "-target",
            target,
            c_source_file,
            "-o",
            compiled_file,
        ]

        with open(c_source_file, "w") as f:
            f.write(c_source_code)

        print("Compiling the assembly with the following command:")
        print(" ".join(shlex.quote(arg) for arg in command_to_run))

        # Build the binary with Zig
        compile_process = subprocess.run(
            command_to_run,
            stdin=subprocess.DEVNULL,
            # stdout=subprocess.PIPE,
            # stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        if compile_process.returncode != 0:
            raise Exception(
                "Compilation error. See error above. If you are linked to a libc library, remember to add --libc"
            )

        print(f"Copying file to cache: {cached_file_path}")
        shutil.copy2(compiled_file, cached_file_path)

        return compiled_file


def zig_assemble_to_elf(
    arch: str,
    assembly_string: str,
    vma: int | None = None,
    syntax: str | None = None,
    includes: List[pathlib.Path] | None = None,
) -> str:
    """
    Return path to the compiled file
    """

    if syntax is None:
        syntax = DEFAULT_SYNTAX

    zig_executable = get_zig_executable()

    header = _asm_header.get(arch, None)
    if header is None:
        raise ValueError(f"Can't find asm header for target {arch}")

    if arch in ARCHES_WHERE_SELECT_SYNTAX:
        header += SYNTAX_TABLE[syntax] + "\n"

    if includes is None:
        includes = []

    includes = "".join((f'#include "{path}"\n' for path in includes))
    target = f"{arch}-freestanding"

    cached_file_path, is_cached = find_cached_version(
        [zig_executable, "cc", "-target", "-o"],
        assembly_string,
        arch,
        includes,
        vma,
        syntax,
    )

    if is_cached:
        return cached_file_path

    with tempfile.TemporaryDirectory(delete=False) as tmpdir:
        asm_file = os.path.join(tmpdir, "input.S")
        linker_script = os.path.join(tmpdir, "link.ld")
        compiled_file = os.path.join(tmpdir, "out.elf")
        bytecode_file = os.path.join(tmpdir, "out.bytecode")

        command_to_run = [
            zig_executable,
            "cc",
            "-target",
            target,
            asm_file,
            "-o",
            compiled_file,
        ]

        if vma is not None:
            linker_script_code = f"""
            SECTIONS
            {{
                . = {vma:#x};

                {USER_CODE_SECTION_NAME} : {{
                    *({USER_CODE_SECTION_NAME})
                }}
            }}

            ENTRY({ENTRY_SYMBOL_NAME})
            """

            with open(linker_script, "w") as f:
                f.write(linker_script_code)

        with open(asm_file, "w") as f:
            f.write(includes)
            f.write(header)
            f.write(assembly_string)

        if vma is not None:
            command_to_run.append(f"-Wl,-T,{linker_script}")

        print("Compiling the assembly with the following command:")
        print(" ".join(shlex.quote(arg) for arg in command_to_run))

        # Build the binary with Zig
        compile_process = subprocess.run(
            command_to_run,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        if compile_process.returncode != 0:
            raise Exception(
                "Compilation error", compile_process.stdout, compile_process.stderr
            )

        print(f"Copying file to cache: {cached_file_path}")
        shutil.copy2(compiled_file, cached_file_path)

        return compiled_file

        # # Extract bytecode
        # objcopy_process = subprocess.run(
        #     [
        #         zig_executable,
        #         "objcopy",
        #         "-O",
        #         "binary",
        #         "--only-section=.text",
        #         compiled_file,
        #         bytecode_file,
        #     ],
        #     stdin=subprocess.DEVNULL,
        #     stdout=subprocess.PIPE,
        #     stderr=subprocess.PIPE,
        #     universal_newlines=True,
        # )
        # if objcopy_process.returncode != 0:
        #     raise Exception(
        #         "Extracting bytecode error", objcopy_process.stdout, objcopy_process.stderr
        #     )

        # with open(bytecode_file, "rb") as f:
        #     return f.read()


class RunMode(Enum):
    DEBUG = auto()
    RUN = auto()


def run(
    arch: str,
    executable_file_path: str,
    mode: RunMode,
    shellcode_mode: bool,
) -> None:
    # if args.PRINT:
    #     assembly_compiled = asm(assembly_source_code)
    #     dumpit(assembly_compiled)
    #     sys.exit(0)

    gdb_script = f"""
    # set context-code-lines 30
    # record
    set nearpc-num-opcode-bytes {MAPPING[arch][2]}
    """

    if mode == RunMode.DEBUG:
        p = debug(arch, executable_file_path, gdbscript=gdb_script)
        p.interactive()
    elif mode == RunMode.RUN:
        p = run_program(executable_file_path)
        p.interactive()


def main():
    install_default_handler()

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--arch",
        "-a",
        dest="arch",
        choices=allowed_architectures,
        help="Choose architecture if providing source code",
    )
    parser.add_argument(
        "--arch-list",
        action="store_true",
        dest="arch_list",
        help=" ".join(allowed_architectures),
    )

    parser.add_argument(
        "--file",
        "-f",
        "-i",
        dest="file",
        help="Path to assembly file, C file, or ELF file.",
    )

    parser.add_argument(
        "--debug",
        "-d",
        dest="debug",
        default=False,
        action="store_true",
        help="Debug the program",
    )

    parser.add_argument(
        "--run",
        "-r",
        dest="run",
        default=False,
        action="store_true",
        help="Debug the program",
    )

    parser.add_argument(
        "--asm", dest="asm", required=False, default=None, help="Assembly code to run"
    )

    parser.add_argument(
        "--vma",
        dest="vma",
        type=lambda x: int(x, 0),
        default=None,
        required=False,
        help="Virtual address to place the code at. Otherwise uses compiler default.",
    )

    parser.add_argument(
        "--libc",
        action="store_true",
        dest="libc",
        help="Compile the source code with musl libc (statically)",
    )

    parser.add_argument("--shellcode", dest="shellcode", action="store_true")

    parser.add_argument(
        "-o",
        dest="outfile",
        default=None,
        required=False,
        help="Save compiled elf to this file",
    )

    parser.add_argument(
        "--syntax",
        dest="syntax",
        default=DEFAULT_SYNTAX,
        choices=VALID_SYNTAX,
        required=False,
        help="Syntax for x86 assembly. Intel by default",
    )

    parsed_args = parser.parse_args()

    if (
        not parsed_args.file
        and not parsed_args.asm
        and not parsed_args.outfile
        and not parsed_args.arch_list
    ):
        parser.print_help()
        sys.exit(0)

    input_architecture: str = parsed_args.arch
    input_file: str = parsed_args.file

    if parsed_args.arch_list:
        print(" ".join(allowed_architectures))
        sys.exit(0)

    if input_architecture is not None:
        if input_architecture in REVERSE_ARCH_NAME_ALIAS_MAP:
            input_architecture = REVERSE_ARCH_NAME_ALIAS_MAP[input_architecture]

    asm_source_code = ""
    c_source_code = ""

    if input_file:
        input_file = str(Path(input_file).resolve())
        if input_file.endswith(".c"):
            c_source_code = open(input_file, "r").read()
        else:
            try:
                # Check if it's an ELF file
                elf = pwnlib.elf.ELF(input_file)

                print(
                    f"Detected architecture '{elf.get_machine_arch()}' from ELF header"
                )
                if not input_architecture:
                    input_architecture = elf.get_machine_arch()

                    input_architecture = PWNTOOLS_NAMING_CONVERSION.get(
                        input_architecture, input_architecture
                    )

                compiled_object_path = input_file
            except elftools.common.exceptions.ELFError:
                asm_source_code = open(input_file, "r").read()

    if not input_architecture:
        platform_arch = platform.machine()

        if platform_arch in REVERSE_ARCH_NAME_ALIAS_MAP:
            platform_arch = REVERSE_ARCH_NAME_ALIAS_MAP[input_architecture]

        if platform_arch not in MAPPING:
            print(
                f"Could not automatically determine architecture of the system: {platform_arch}"
            )
            print("You must provide an architecture with --arch")

            sys.exit(1)
        else:
            print(f"Choosing host architecture: {platform_arch}")
            input_architecture = platform_arch

    if parsed_args.asm is not None:
        asm_source_code = parsed_args.asm
    elif not sys.stdin.isatty():
        asm_source_code = sys.stdin.read()

    if c_source_code:
        compiled_object_path = zig_compile_c_to_elf(
            input_architecture, c_source_code, parsed_args.libc
        )
    elif asm_source_code:
        compiled_object_path = zig_assemble_to_elf(
            input_architecture,
            asm_source_code,
            vma=parsed_args.vma,
            syntax=parsed_args.syntax,
        )

    outfile = parsed_args.outfile
    if outfile:
        print(f"Saving compiled program to {outfile}")
        shutil.copy(compiled_object_path, outfile)

        # Mark as executable
        f = Path(outfile)
        f.chmod(f.stat().st_mode | stat.S_IEXEC)

    if parsed_args.debug:
        mode = RunMode.DEBUG
    elif parsed_args.run:
        mode = RunMode.RUN
    elif outfile is None:
        print("Specify --debug or --run to run program")
        sys.exit(1)

    run(
        input_architecture,
        compiled_object_path,
        mode,
        parsed_args.shellcode,
    )


if __name__ == "__main__":
    main()
