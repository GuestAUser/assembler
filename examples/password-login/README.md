# Password login demo

This folder contains a deliberately weak C login program meant for local reverse-engineering practice with this disassembler.

## Build

Compile it without optimization so the password checks stay obvious in assembly:

```bash
gcc -O0 -g -fno-inline -fno-builtin -no-pie -o examples/password-login/secret_login examples/password-login/secret_login.c
```

## Normal usage

```bash
./examples/password-login/secret_login
```

Try `open-sesame` to get access.

## Extracting the password with this disassembler

Disassemble only the password-check function:

```bash
cargo run -- examples/password-login/secret_login --symbol check_password --render pretty --color never
```

In the output, look for immediate byte comparisons inside `check_password`. You will see values matching these ASCII bytes:

```text
0x6f  -> o
0x70  -> p
0x65  -> e
0x6e  -> n
0x2d  -> -
0x73  -> s
0x65  -> e
0x73  -> s
0x61  -> a
0x6d  -> m
0x65  -> e
0x00  -> string terminator
```

That reconstructs the password as:

```text
open-sesame
```

## What fails here

This login is intentionally broken from a reverse-engineering perspective:

- The password is hardcoded in the program logic.
- The comparison is performed byte by byte, so the exact secret is visible in disassembly.
- The function returns as soon as a character does not match, which also leaks structure.
- There is no attempt to protect or derive the secret at runtime.

This is the kind of design failure the disassembler makes obvious immediately.
