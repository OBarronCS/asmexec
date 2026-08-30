
# asmx
A small commandline tool that wraps `zig`, `qemu`, and `gdb` to quickly compile, run, and debug code across architectures. Useful for quickly running small test programs across different architectures (use a single command to run a program from source rather than remembering the arch triple you need to pass to `zig cc` and needing to open two terminals to run `qemu` and `gdb`).

Inspired by helpful functions in [`pwntools`](https://github.com/Gallopsled/pwntools) (`asm`, `gdb.attach`), and also uses some code from [`pwndbg`](https://github.com/pwndbg/pwndbg/).

## Quick start

You must be in a `tmux` session for this to work, as it opens a new pane with the debugger.

```sh
# Examples
## Compile and run inline assembly code. --debug/-d opens GDB
asmx --arch aarch64 --asm "nop;nop;nop;nop" --vma 0x9000 --debug

## Compile and run code from an assembly file
asmx --arch amd64 --file shellcode.S -d

## If you omit --arch, it defaults to the host architecture
asmx --asm "nop" -d

## Run and debug a pre-compiled ELF file
asmx -i mips32_hello_world -d

## Run (but do not debug with GDB) a pre-compiled ELF file
asmx -i riscv64_hello_world -r

## Compile a program with loongarch64 and debug it
asmx --arch loongarch64 -i hello_world.c -d
```

## Command reference

The repo provides the `asmexec` command (and the `asmx` alias).

```
asmx <options>

# Options
--arch <arch_name>
    Name of the architecture you want to compile and execute

--asm <source_code>
    A string containing the code you want to compile and run

    Example:
        --asm "nop; nop; nop"

-i, --file <filename>
    Path to file with assembly source code or a valid ELF. It will detect if it's an ELF based on the magic header bytes.
    
    If it's source code, it will compile it and execute it. The --arch flag is needed in the case.
    
    If it's an ELF file, the architecture is automatically detected, but can be overriden with --arch.

-o <filename>
    Save the compiled code to this file

--vma <address>
    Specify the virtual address to place the code at. This is optional. If omitted, it uses whatever the compiles chooses.

    Note that qemu cannot load certain architectures at low addresses. If you get an qemu error, try increasing the vma. 

    Example:
        asmx --arch rv32 --asm "nop" --vma 0x90000 GDB

--libc
    Add this flag when compiling c source code, and you want to statically link with musl.

--syntax <intel, att>
    If compiling x86 assembly code, note which syntax style you are using. This defaults to `intel` 

--arch-list
    Print supported architecture names
```

It will automatically cache the compiled files, so subsequent runs with the same input are faster.


## Install


### From GitHub

Install with `uv`
```sh
uv tool install git+https://github.com/OBarronCS/asmexec.git
```

With `pip`
```sh
# pipx
pipx install git+https://github.com/OBarronCS/asmexec.git

# If pipx is not available, pip works too
pip install git+https://github.com/OBarronCS/asmexec.git
```

### For local development

```sh
# With uv
uv tool install --editable .

# With pipx
pipx install --editable .

# Or, with pip
pip install --editable .
```

