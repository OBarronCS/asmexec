#!/bin/bash

set -euo pipefail

help() {
    echo "Usage: ./lint.sh [-f]"
    exit 1
}

FIX=0

while [[ $# -gt 0 ]]; do
    case $1 in
        -f)
            FIX=1
            shift
            ;;
        *)
            help
            ;;
    esac
done


set -o xtrace


if [[ "$FIX" == 1 ]]; then
    uv tool run ruff format asmexec/
    uv tool run ruff check --fix --output-format=full asmexec/
else
    uv tool run ruff format --check --diff asmexec/
    uv tool run ruff check --output-format=full asmexec/

fi
