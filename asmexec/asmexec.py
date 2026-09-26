#!/usr/bin/env python3
# /// script
# dependencies = [
#   "pwntools",
#   "pyelftools"
# ]
# ///

import argparse

from enum import Enum, auto
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

from asmexec.compile import (
    ARCH_INFO_MAPPING,
    ARCHITECTURE_NAME_ALIASES,
    ASSEMBLY_CALLBACKS,
    CLI_ALLOWED_ARCHITECTURES,
    DEFAULT_X64_SYNTAX,
    PWNTOOLS_NAMING_CONVERSION,
    SUPPORTED_ARCHITECTURES,
    SUPPORTED_COMPILERS_TYPE,
    VALID_X86_SYNTAXES,
    resolve_to_canonical_name,
    zig_compile_c_to_elf,
)
from asmexec.helpers import get_cache_dir

QEMU_HOST = "127.0.0.1"

pwnlib.context.context.log_level = "debug"
pwnlib.context.context.terminal = ["tmux", "splitw", "-h", "-l", "80%"]


# A simplified version of gdb.attach from pwntools with our own architecture mappings
def debug(arch: str, filepath: str, gdb_path: str = "gdb"):
    runner = pwnlib.tubes.process.process
    which = pwnlib.util.misc.which

    exe = which(filepath)

    port = random.randint(1024, 65535)

    qemu_name, endian, instruction_size = ARCH_INFO_MAPPING[arch]

    if shutil.which(qemu_name) is None:
        print(
            f"Cannot find path to {qemu_name}. Make sure qemu is installed",
            file=sys.stderr,
        )
        sys.exit(1)

    # Run this after the previous check so that gets printed to the terminal
    ensure_tmux()

    gdbscript = f"""
    # record
    if ! $_isvoid($hex2ptr)
    # set context-code-lines 30
    set nearpc-num-opcode-bytes {instruction_size}
    end
    """

    # This prints a lot of stuff, so disabling logging here temporarily
    pwnlib.context.context.log_level = "error"
    sysroot = pwnlib.qemu.ld_prefix(path=qemu_name)
    pwnlib.context.context.log_level = "debug"

    qemu_args = [qemu_name, "-g", str(port)]

    if sysroot:
        qemu_args += ["-L", sysroot]

    args = qemu_args + [filepath]

    print("Launching qemu with the following command:")
    print(" ".join(shlex.quote(arg) for arg in args))

    gdbserver = runner(args, aslr=1)

    pwnlib.context.context.gdb_binary = gdb_path

    tmp = pwnlib.gdb.attach(
        (QEMU_HOST, port), exe=exe, gdbscript=gdbscript, sysroot=sysroot
    )

    return gdbserver


def run_program(filepath: str):
    return pwnlib.tubes.process.process(filepath)


def ensure_tmux():
    """
    If we are not currently in a tmux session, open one up
    """
    if os.environ.get("TMUX"):
        # We are already inside of tmux
        return

    if not shutil.which("tmux"):
        print("tmux not found", file=sys.stderr)
        sys.exit(1)
    if not sys.stdin.isatty():
        print("Not in a tty, can't start tmux", file=sys.stderr)
        sys.exit(1)

    cmd = getattr(
        sys, "orig_argv", [sys.executable, os.path.abspath(sys.argv[0]), *sys.argv[1:]]
    )
    os.execvp("tmux", ["tmux", "new-session", "--", *cmd])


class RunMode(Enum):
    DEBUG = auto()
    RUN = auto()


def main():
    install_default_handler()

    chosen_compiler: SUPPORTED_COMPILERS_TYPE = "zig"

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--arch",
        "-a",
        dest="arch",
        choices=CLI_ALLOWED_ARCHITECTURES,
        help="Choose architecture if providing source code",
    )
    parser.add_argument(
        "--arch-list",
        action="store_true",
        dest="arch_list",
        help=" ".join(CLI_ALLOWED_ARCHITECTURES),
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
        nargs="?",
        const="gdb",
        default=False,
        help="Debug the program",
        metavar="gdb path",
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

    parser.add_argument(
        "--nasm",
        action="store_true",
        dest="nasm",
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
        default=DEFAULT_X64_SYNTAX,
        choices=VALID_X86_SYNTAXES,
        required=False,
        help="Syntax for x86 assembly. Intel by default",
    )

    parser.add_argument(
        "--cache-folder",
        dest="cache_folder",
        action="store_true",
        default=False,
        help=get_cache_dir(),
    )

    args = parser.parse_args()

    if args.cache_folder:
        print(get_cache_dir())
        sys.exit(0)

    if args.arch_list:
        for arch in SUPPORTED_ARCHITECTURES:
            aliases = ARCHITECTURE_NAME_ALIASES.get(arch, None)
            if aliases:
                print(f"{arch} ({', '.join(aliases)})")
            else:
                print(arch)
        sys.exit(0)

    if not args.file and not args.asm and not args.outfile and not args.arch_list:
        parser.print_help()
        sys.exit(1)

    if args.nasm:
        chosen_compiler = "nasm"

    input_architecture: str | None = args.arch
    input_file: str = args.file

    if input_architecture is not None:
        input_architecture = resolve_to_canonical_name(input_architecture)

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

        platform_arch = resolve_to_canonical_name(platform_arch)

        if platform_arch not in SUPPORTED_ARCHITECTURES:
            print(
                f"Could not automatically determine architecture of the system: {platform_arch}",
                file=sys.stderr,
            )
            print("You must provide an architecture with --arch", file=sys.stderr)

            sys.exit(1)
        else:
            print(f"Choosing host architecture: {platform_arch}")
            input_architecture = platform_arch

    if args.asm is not None:
        asm_source_code = args.asm
    elif not sys.stdin.isatty():
        asm_source_code = sys.stdin.read()

    if c_source_code:
        compiled_object_path = zig_compile_c_to_elf(
            input_architecture, c_source_code, args.libc
        )
    elif asm_source_code:
        assembly_function = ASSEMBLY_CALLBACKS[chosen_compiler]

        compiled_object_path = assembly_function(
            input_architecture,
            asm_source_code,
            vma=args.vma,
            syntax=args.syntax,
        )

    outfile = args.outfile
    if outfile:
        print(f"Saving compiled program to {outfile}")
        shutil.copy(compiled_object_path, outfile)

        # Mark as executable
        f = Path(outfile)
        f.chmod(f.stat().st_mode | stat.S_IEXEC)

    if args.debug:
        mode = RunMode.DEBUG
    elif args.run:
        mode = RunMode.RUN
    elif outfile is None:
        print("Specify --debug or --run to run program", file=sys.stderr)
        sys.exit(1)

    if mode == RunMode.DEBUG:
        p = debug(input_architecture, compiled_object_path, gdb_path=args.debug)
        p.interactive()
    elif mode == RunMode.RUN:
        p = run_program(compiled_object_path)
        p.interactive()


if __name__ == "__main__":
    main()
