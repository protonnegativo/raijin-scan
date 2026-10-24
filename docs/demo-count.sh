#!/usr/bin/env bash
# Prints the size of an output file as an agent would pay for it, for the README demo (docs/demo.tape):
#
#   docs/demo-count.sh FILE   # → "FILE: 39,802 bytes · 13,470 tokens (o200k_base)"
#
# Tokens are counted with tiktoken (o200k_base), like bench/count_tokens.py. Set PYTHON to an interpreter
# that has tiktoken installed (default: python3).
set -euo pipefail
f=${1:?usage: demo-count.sh FILE}
"${PYTHON:-python3}" - "$f" <<'PY'
import sys, tiktoken
path = sys.argv[1]
data = open(path, "rb").read()
tokens = len(tiktoken.get_encoding("o200k_base").encode(data.decode("utf-8", "replace"), disallowed_special=()))
line = f"{path}: {len(data):,} bytes · {tokens:,} tokens (o200k_base)"
print(f"\n\033[1;33m{line}\033[0m" if sys.stdout.isatty() else line)
PY
