
By default, this tool compiles using `zig cc` to compile assembly code. It uses `clang` under the hood, which uses a syntax similar to `GAS` syntax.

You can add the `--nasm` flag to use `nasm` instead.

Example:

NASM syntax:
```nasm
section .text
global _start

; comments
```

ZIG syntax:
```asm
.section .text
.global _start

# comments
```

