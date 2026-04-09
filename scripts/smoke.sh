#!/usr/bin/env bash
set -euo pipefail

plain_output=$(cargo run --quiet -- --raw-hex "c3" --arch x86-64)
case "$plain_output" in
  *"target       : <raw-hex>"* ) ;;
  * )
    printf 'plain smoke check failed\n' >&2
    exit 1
    ;;
esac

pretty_output=$(cargo run --quiet -- --raw-hex "55 48 89 e5 5d c3" --arch x86-64 --render pretty --color never)
case "$pretty_output" in
  *"╭─ DISASSEMBLY"*"push"*"mov"*"ret"* ) ;;
  * )
    printf 'pretty smoke check failed\n' >&2
    exit 1
    ;;
esac

symbol_output=$(cargo run --quiet -- target/debug/assembler --symbol main)
case "$symbol_output" in
  *"symbols     : main"*"[.text::main]"* ) ;;
  * )
    printf 'symbol smoke check failed\n' >&2
    exit 1
    ;;
esac

printf 'smoke checks passed\n'
