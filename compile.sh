#!/usr/bin/env bash

echo "✨ Simple-AST compile.sh"

case $1 in

test)
    echo "💊 Runing all tests"
    cargo test
    ;;
test-debug)
    echo "💊 Runing test for debug: $2"
    RUST_LOG=debug cargo test $2 -- --nocapture
    ;;
*)
    echo "🪄  Compiling for std environment"
    cargo build
    ;;
esac
