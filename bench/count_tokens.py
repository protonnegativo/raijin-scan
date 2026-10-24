"""Counts bytes, lines and tokens of each output file.

Tokens are counted with tiktoken (o200k_base and cl100k_base) as a proxy: Claude's tokenizer is not
public. If ANTHROPIC_API_KEY is set and the `anthropic` package is installed, it also uses the
Anthropic count_tokens endpoint for an exact Claude count.

usage: python count_tokens.py label=file [label=file ...]
"""
import os
import sys

import tiktoken

ENCODINGS = {name: tiktoken.get_encoding(name) for name in ("o200k_base", "cl100k_base")}


def claude_tokens(text):
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return None
    try:
        import anthropic
    except ImportError:
        return None
    client = anthropic.Anthropic()
    r = client.messages.count_tokens(model=os.environ.get("CLAUDE_MODEL", "claude-sonnet-5-5"), messages=[{"role": "user", "content": text}])
    return r.input_tokens


rows = []
for arg in sys.argv[1:]:
    label, path = arg.split("=", 1)
    text = "".join(open(p, encoding="utf-8", errors="replace").read() for p in path.split("+"))
    row = {"label": label, "bytes": len(text.encode()), "lines": text.count("\n")}
    for name, enc in ENCODINGS.items():
        row[name] = len(enc.encode(text, disallowed_special=()))
    row["claude"] = claude_tokens(text)
    rows.append(row)

base = rows[0]["o200k_base"] or 1
print(f"| Output | Lines | Bytes | Tokens (o200k) | Tokens (cl100k) | Claude | vs. first |")
print("|---|---:|---:|---:|---:|---:|---:|")
for r in rows:
    claude = r["claude"] if r["claude"] is not None else "n/a"
    print(f"| {r['label']} | {r['lines']:,} | {r['bytes']:,} | {r['o200k_base']:,} | {r['cl100k_base']:,} | {claude} | {base / max(1, r['o200k_base']):.1f}x |")
