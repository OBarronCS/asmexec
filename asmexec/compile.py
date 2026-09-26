"""
This file contains helpers for compile some input assembly/c source code
"""

# Canonical names for supported architectures
import os
import pathlib
import shlex
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Callable, Literal
import typing

from asmexec.helpers import find_cached_version

# This defines the canonical names for arches used by this tool
# These names are the same ones zig uses to identify architectures.
# Supported zig architectures can be obtained using the command: `zig targets`
SUPPORTED_ARCHITECTURES_TYPE = Literal[
    "x86_64",
    "x86",
    "mips",
    "mipsel",
    "mips64",
    "mips64el",
    "aarch64",
    "aarch64_be",
    "arm",
    "armeb",
    "thumb",
    "thumbeb",
    "riscv32",
    "riscv64",
    "sparc",
    "sparc64",
    "powerpc",
    "powerpcle",
    "powerpc64",
    "powerpc64le",
    "loongarch64",
    "s390x",
]

SUPPORTED_ARCHITECTURES: list[SUPPORTED_ARCHITECTURES_TYPE] = list(
    typing.get_args(SUPPORTED_ARCHITECTURES_TYPE)
)


# Key is the canonical name, values are the aliases
ARCHITECTURE_NAME_ALIASES: dict[SUPPORTED_ARCHITECTURES_TYPE, set[str]] = {
    "x86_64": {"amd64", "x64", "x86-64"},
    "x86": {"i386", "i686", "x32"},
    "mips": {"mips32"},
    "mipsel": {"mipsel32"},
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

REVERSE_ARCH_NAME_ALIAS_MAP: dict[str, SUPPORTED_ARCHITECTURES_TYPE] = {}

PWNTOOLS_NAMING_CONVERSION: dict[str, SUPPORTED_ARCHITECTURES_TYPE] = {
    "amd64": "x86_64",
    "i386": "x86",
}

CLI_ALLOWED_ARCHITECTURES: list[str] = list(SUPPORTED_ARCHITECTURES)

for canonical_name, value in ARCHITECTURE_NAME_ALIASES.items():
    for alias in value:
        CLI_ALLOWED_ARCHITECTURES.append(alias)
        REVERSE_ARCH_NAME_ALIAS_MAP[alias] = canonical_name


def resolve_to_canonical_name(name: str) -> SUPPORTED_ARCHITECTURES_TYPE:
    if name in REVERSE_ARCH_NAME_ALIAS_MAP:
        return REVERSE_ARCH_NAME_ALIAS_MAP[name]

    # Assume it is already a valid arch
    return name


# Tuple of (qemu name, endian, instruction_bytes_to_display)
ARCH_INFO_MAPPING: dict[SUPPORTED_ARCHITECTURES_TYPE, tuple[str, str, int]] = {
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

ZIG_MUSL_TARGET_NAME: dict[str, str | None] = {
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


INTEL_SYNTAX = ".intel_syntax noprefix"
ATT_SYNTAX = ".att_syntax prefix"
SYNTAX_TABLE: dict[str, str] = {"intel": INTEL_SYNTAX, "att": ATT_SYNTAX}
ARCHES_WHERE_SELECT_SYNTAX = ("x86_64", "x86")
DEFAULT_X64_SYNTAX = "intel"

VALID_X86_SYNTAXES = list(SYNTAX_TABLE.keys())

USER_CODE_SECTION_NAME = ".text"
ENTRY_SYMBOL_NAME = "__start"

_start_section_header = f".section {USER_CODE_SECTION_NAME};"
_prefix_header = (
    f".global {ENTRY_SYMBOL_NAME};.global _start;\n{ENTRY_SYMBOL_NAME}:;_start:\n"
)

_asm_header: dict[str, str] = {
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


EXISTING_START_SYMBOLS = ["_start:", "__start:"]


def simple_remove_comments(assembly_string: str) -> str:
    return "\n".join(
        line.split("#")[0].rstrip() for line in assembly_string.splitlines()
    )


def does_start_symbol_exist(assembly_string: str) -> bool:
    tmp = simple_remove_comments(assembly_string)
    for possible in EXISTING_START_SYMBOLS:
        return possible in tmp
    return False


### nasm relevant settings
ARCHES_SUPPORTED_BY_NASM: list[SUPPORTED_ARCHITECTURES_TYPE] = ["x86_64", "x86"]

NASM_ARCH_NAMES_TYPE = Literal["elf64", "elf32"]
NASM_ARCH_NAME_MAPPING: dict[SUPPORTED_ARCHITECTURES_TYPE, NASM_ARCH_NAMES_TYPE] = {
    "x86_64": "elf64",
    "x86": "elf32",
}

LD_ARCH_NAMES_TYPE = Literal["elf_i386", "elf_x86_64"]
LD_ARCH_NAME_MAPPING: dict[SUPPORTED_ARCHITECTURES_TYPE, LD_ARCH_NAMES_TYPE] = {
    "x86_64": "elf_x86_64",
    "x86": "elf_i386",
}


###
### Compiling with Zig
###


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


def build_zig_command(
    zig_executable: str,
    zig_target: str,
    asm_path: str,
    output_path: str,
    linker_script_path: str | None,
) -> list[str]:

    command = [
        zig_executable,
        "cc",
        "-target",
        zig_target,
        asm_path,
        "-o",
        output_path,
    ]

    if linker_script_path:
        command.append(f"-Wl,-T,{linker_script_path}")

    return command


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
        musl_target_name = ZIG_MUSL_TARGET_NAME.get(arch)
        if not musl_target_name:
            print(f"musl libc not supported for '{arch}'", file=sys.stderr)
            sys.exit(1)
        zig_target_name = f"{arch}-{musl_target_name}"
    else:
        zig_target_name = f"{arch}-freestanding"

    zig_hash_lookup = build_zig_command(
        zig_executable, zig_target_name, "INPUT_FILE", "OUTPUT_FILE", ""
    )

    cached_file_path, is_cached = find_cached_version(
        zig_hash_lookup, c_source_code, arch, "", None
    )

    if is_cached:
        return cached_file_path

    with tempfile.TemporaryDirectory(delete=False) as tmpdir:
        c_source_file = os.path.join(tmpdir, "input.C")
        # linker_script = os.path.join(tmpdir, "link.ld")
        compiled_file = os.path.join(tmpdir, "out.elf")

        zig_command = build_zig_command(
            zig_executable, zig_target_name, c_source_file, compiled_file, None
        )

        with open(c_source_file, "w") as f:
            f.write(c_source_code)

        print("Compiling the assembly with the following command:")
        print(" ".join(shlex.quote(arg) for arg in zig_command))

        # Build the binary with Zig
        compile_process = subprocess.run(
            zig_command,
            stdin=subprocess.DEVNULL,
            # stdout=subprocess.PIPE,
            # stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        if compile_process.returncode != 0:
            raise Exception(
                f"""Compilation error.
See error message above
If you are linking to libc, remember to add --libc
"""
            )

        print(f"Copying file to cache: {cached_file_path}")
        shutil.copy2(compiled_file, cached_file_path)

        return compiled_file


def zig_assemble_to_elf(
    arch: SUPPORTED_ARCHITECTURES_TYPE,
    assembly_string: str,
    vma: int | None = None,
    syntax: str | None = None,
    includes: list[pathlib.Path] | None = None,
) -> str:
    """
    Return path to the compiled file
    """

    if syntax is None:
        syntax = DEFAULT_X64_SYNTAX

    zig_executable = get_zig_executable()

    header = f"{_start_section_header}\n"
    if not does_start_symbol_exist(assembly_string):
        insert_header = _asm_header.get(arch, None)

        if insert_header is None:
            raise ValueError(f"Can't find asm header for target {arch}")

        header += insert_header

    if arch in ARCHES_WHERE_SELECT_SYNTAX:
        header += SYNTAX_TABLE[syntax] + "\n"

    if includes is None:
        includes = []

    includes = "".join((f'#include "{path}"\n' for path in includes))
    zig_target_name = f"{arch}-freestanding"

    nasm_hash_lookup_linker_file = ""
    linker_script_code = ""

    if vma is not None:
        nasm_hash_lookup_linker_file = "LINKER_FILE"

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

    zig_hash_lookup = build_zig_command(
        zig_executable,
        zig_target_name,
        "INPUT_FILE",
        "OUTPUT_FILE",
        nasm_hash_lookup_linker_file,
    )

    cached_file_path, is_cached = find_cached_version(
        zig_hash_lookup,
        header
        + assembly_string
        + linker_script_code
        + USER_CODE_SECTION_NAME
        + ENTRY_SYMBOL_NAME,
        arch,
        includes,
        vma,
        syntax,
    )

    if is_cached:
        return cached_file_path

    with tempfile.TemporaryDirectory(delete=False) as tmpdir:
        asm_file = os.path.join(tmpdir, "input.S")

        compiled_file = os.path.join(tmpdir, "out.elf")

        bytecode_file = os.path.join(tmpdir, "out.bytecode")

        linker_script = ""

        if linker_script_code:
            linker_script = os.path.join(tmpdir, "link.ld")
            with open(linker_script, "w") as f:
                f.write(linker_script_code)

        zig_command = build_zig_command(
            zig_executable, zig_target_name, asm_file, compiled_file, linker_script
        )

        with open(asm_file, "w") as f:
            f.write(includes)
            f.write(header)
            f.write(assembly_string)

        print("Compiling the assembly with the following command:")
        print(" ".join(shlex.quote(arg) for arg in zig_command))

        # Build the binary with Zig
        compile_process = subprocess.run(
            zig_command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        if compile_process.returncode != 0:
            print("Compilation failed")
            print(pathlib.Path(asm_file).read_text())
            error_message = f"""Compilation error
{compile_process.stdout}
{compile_process.stderr}
"""
            if arch in ARCHES_SUPPORTED_BY_NASM:
                error_message += "If the assembly source is written with nasm syntax, add the '--nasm' CLI flag"
            raise Exception(error_message)

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


###
### Compiling with nasm
###


def get_nasm_executable() -> str:
    path = shutil.which("nasm")
    if path is None:
        raise ValueError("nasm not found in PATH")

    return path


def build_nasm_command(
    nasm_executable: str,
    nasm_arch: NASM_ARCH_NAMES_TYPE,
    asm_file: str,
    output_path: str,
) -> list[str]:
    return [
        nasm_executable,
        "-f",
        nasm_arch,
        "-g",
        "-F",
        "dwarf",
        asm_file,
        "-o",
        output_path,
    ]


def get_linker_executable() -> str:
    path = shutil.which("ld")
    if path is None:
        raise ValueError("ld not found in PATH")

    return path


def build_linker_command(
    ld_executable: str,
    ld_arch: LD_ARCH_NAMES_TYPE,
    input_path: str,
    output_path: str,
    linker_script: str | None,
) -> list[str]:

    command = [ld_executable, "-m", ld_arch]

    if linker_script:
        command += ["-T", linker_script]

    command += [input_path, "-o", output_path]

    return command


def nasm_assemble_to_elf(
    arch: SUPPORTED_ARCHITECTURES_TYPE,
    assembly_string: str,
    vma: int | None = None,
    syntax: str | None = None,
    includes: list[pathlib.Path] | None = None,
) -> str:
    """
    nasm only understands the Intel assembly syntax

    Return path to the compiled file
    """

    if arch not in ARCHES_SUPPORTED_BY_NASM:
        print(f"Architecture not supported by nasm: {arch}", file=sys.stderr)
        sys.exit(1)

    nasm_arch_name = NASM_ARCH_NAME_MAPPING[arch]
    ld_arch_name = LD_ARCH_NAME_MAPPING[arch]

    if syntax is None:
        syntax = DEFAULT_X64_SYNTAX

    ## If user has not defined a start symbol, inject it to the start
    ## for convenience

    header = ""

    section_text_string = f"section {USER_CODE_SECTION_NAME}"

    if section_text_string not in assembly_string:
        header += f"{section_text_string}\n"

    if not does_start_symbol_exist(assembly_string):
        header += "global _start;\nglobal __start:\n_start:\n__start:\n"

    ### Prepare how we will use `nasm` and `ld`
    nasm_executable = get_nasm_executable()

    # Linker
    ld_executable = get_linker_executable()

    nasm_hash_lookup_linker_file = ""
    linker_script_code = ""

    if vma is not None:
        nasm_hash_lookup_linker_file = "LINKER_FILE"
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

    nasm_hash_lookup = build_nasm_command(
        nasm_executable, nasm_arch_name, "INPUT_FILE", "OUTPUT_FILE"
    )
    ld_hash_lookup = build_linker_command(
        ld_executable,
        ld_arch_name,
        "INPUT_FILE",
        "OUTPUT_FILE",
        nasm_hash_lookup_linker_file,
    )

    cached_file_path, is_cached = find_cached_version(
        nasm_hash_lookup + ld_hash_lookup,
        header
        + assembly_string
        + linker_script_code
        + USER_CODE_SECTION_NAME
        + ENTRY_SYMBOL_NAME,
        arch,
        includes,
        vma,
        syntax,
    )

    if is_cached:
        return cached_file_path

    with tempfile.TemporaryDirectory(delete=False) as tmpdir:
        asm_file = os.path.join(tmpdir, "input.S")
        nasm_output = os.path.join(tmpdir, "out.o")

        command_to_run = build_nasm_command(
            nasm_executable, nasm_arch_name, asm_file, nasm_output
        )

        with open(asm_file, "w") as f:
            f.write(header)
            f.write(assembly_string)

        print("Compiling the assembly with the following command:")
        print(" ".join(shlex.quote(arg) for arg in command_to_run))

        compile_process = subprocess.run(
            command_to_run,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        if compile_process.returncode != 0:
            print("Compilation failed")
            print(pathlib.Path(asm_file).read_text())
            raise Exception(
                f"""Compilation error
{compile_process.stdout}
{compile_process.stderr}
"""
            )

        ### Now, we want to link it

        ld_output = os.path.join(tmpdir, "out.elf")

        linker_script = ""

        if linker_script_code:
            linker_script = os.path.join(tmpdir, "link.ld")
            with open(linker_script, "w") as f:
                f.write(linker_script_code)

        command_to_link = build_linker_command(
            ld_executable, ld_arch_name, nasm_output, ld_output, linker_script
        )

        print("Linking with the following command:")
        print(" ".join(shlex.quote(arg) for arg in command_to_link))

        link_process = subprocess.run(
            command_to_link,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )

        if link_process.returncode != 0:
            print("Linking failed")
            print(pathlib.Path(asm_file).read_text())
            raise Exception(
                f"""Compilation error
{link_process.stdout}
{link_process.stderr}
"""
            )

        print(f"Copying file to cache: {cached_file_path}")
        shutil.copy2(ld_output, cached_file_path)

        return ld_output


SUPPORTED_COMPILERS_TYPE = Literal["zig", "nasm"]

SUPPORTED_COMPILERS: list[SUPPORTED_COMPILERS_TYPE] = list(
    typing.get_args(SUPPORTED_COMPILERS_TYPE)
)

type AssembleFunction = Callable[
    [SUPPORTED_ARCHITECTURES_TYPE, str, int | None, str | None, Any | None], str
]

ASSEMBLY_CALLBACKS: dict[SUPPORTED_COMPILERS_TYPE, AssembleFunction] = {
    "zig": zig_assemble_to_elf,
    "nasm": nasm_assemble_to_elf,
}
