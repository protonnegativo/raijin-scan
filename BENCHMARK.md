# Token benchmark: nuclei vs raijin-scan

How many tokens does an AI agent spend reading the result of a scan? This benchmark runs nuclei on a local lab and counts the tokens in each output shape.

Reproduce: `bench/run.sh ~/nuclei-templates`.

## Setup

- **Lab:** 5 static sites served by `python -m http.server`, each reached as `127.0.0.1` and `localhost`, which makes 10 targets. Site 1 serves a fake `.git/config` and `.env`. Site 3 serves `openapi.json` and `swagger.json`.
- **nuclei:** v3.3.9 with nuclei-templates v10.5.1 and `-rl 30`.
- **raijin-scan:** reduces the same nuclei JSONL with `--input`, so both sides see exactly the same matches. Defaults are `--max-items 20` and `--max-bytes 8000`.
- **Tokens:** counted with tiktoken (`o200k_base` and `cl100k_base`). This is a **proxy**, because Claude's tokenizer is not public. `bench/count_tokens.py` also gives exact Claude counts if `ANTHROPIC_API_KEY` is set and the `anthropic` package is installed. The ratios are what matters, and they hold across both encodings.

## Scenario 1: broad scan, info only

`-t http/exposures/ -t http/technologies/ -t http/misconfiguration/` loads 2,852 templates. The run made 124 matches, all info:

- 100 `http-missing-security-headers`
- 20 `tech-detect`
- 2 `openapi`
- 2 `swagger-api`

| Output | Lines | Bytes | Tokens (o200k) | vs. nuclei JSONL |
|---|---:|---:|---:|---:|
| nuclei `-jsonl` | 124 | 220,578 | 72,698 | 1× |
| nuclei `-jsonl -omit-raw` | 124 | 147,779 | 44,771 | 1.6× |
| nuclei text (stdout+stderr) | 143 | 11,559 | 3,675 | 19.8× |
| **raijin-scan JSON (default)** | 1 | 922 | **298** | **244×** |
| raijin-scan `--pretty` | 59 | 1,342 | 423 | 172× |
| raijin-scan `--format table` | 5 | 314 | 64 | 1,136× |

raijin-scan returns 0 findings and 4 groups. One of them is `http-missing-security-headers`: 10 hosts, with the 10 missing headers listed in `variants`.

## Scenario 2: exposures, real findings

`-t http/exposures/configs/ -t http/technologies/tech-detect.yaml -t http/exposures/apis/` made 30 matches:

- 2 `laravel-env` (high)
- 2 `codeigniter-env` (high)
- 2 `git-config` (medium)
- 20 `tech-detect`
- 2 `openapi`
- 2 `swagger-api`

| Output | Lines | Bytes | Tokens (o200k) | vs. nuclei JSONL |
|---|---:|---:|---:|---:|
| nuclei `-jsonl` | 30 | 46,357 | 15,831 | 1× |
| nuclei `-jsonl -omit-raw` | 30 | 28,718 | 9,216 | 1.7× |
| nuclei text (stdout+stderr) | 48 | 2,606 | 938 | 16.9× |
| **raijin-scan JSON (default)** | 1 | 1,071 | **360** | **44×** |
| raijin-scan `--pretty` | 69 | 1,546 | 514 | 31× |
| raijin-scan `--format table` | 10 | 574 | 129 | 123× |

raijin-scan returns 3 findings, the two high ones first, each with its 2 hosts and the matched URL as evidence, plus 3 info groups.

## Reading the numbers

- **Against nuclei JSONL**, the structured output an agent would parse, raijin-scan uses **44× to 244× fewer tokens**. The gap grows with noise, because repeated info matches collapse into one group instead of costing tokens per host and per header.
- **Against nuclei's text output**, the gap is smaller:
  - scenario 1 is **12.3×** (3,675 → 298 tokens);
  - scenario 2 is about **2.6×** (938 → 360).

  The text output is already terse, but it is not structured. It has no dedup across hosts, no ranking and no budget, and it grows linearly with hosts × templates. It also includes nuclei's startup banner and log lines on stderr.
- **Output size stays bounded.** raijin-scan never goes above `--max-bytes`, whatever the scan size. Raw nuclei output has no upper bound.
- **Compact by default.** Pretty-printed JSON costs about 30% more tokens for the same content, so the JSON is one line unless you pass `--pretty`. This also makes `--max-bytes` exact, since the budget is measured on the compact encoding.
- **Only what the agent can't rebuild.** Default values, empty lists, a `hosts_count` equal to the hosts listed, the budget when nothing was cut, and fields derived from the `id` (the old `fingerprint` and `engine_ref`) are left out. Scenario 2 went from 501 to 360 tokens with the same content. The check is that each removed field can be rebuilt and matches the earlier output.

How the default output got here (o200k tokens, scenario 1 / scenario 2):

| Version | Scenario 1 | Scenario 2 |
|---|---:|---:|
| Pretty JSON, all fields | 482 | 710 |
| Compact JSON | 338 | 501 |
| Compact JSON, derivable fields left out | 298 | 360 |
