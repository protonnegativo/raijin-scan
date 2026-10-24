# Token benchmark: nuclei vs raijin-scan

How many tokens does an AI agent spend reading the result of a scan, and does it lose anything? This benchmark runs nuclei on a local lab, counts the tokens in each output shape, and checks that every nuclei match is in the raijin-scan output.

Reproduce: `bench/run.sh ~/nuclei-templates`.

## Setup

- **Lab:** 5 static sites served by `python -m http.server`, each reached as `127.0.0.1` and `localhost`, which makes 10 targets. Site 1 serves a fake `.git/config` and `.env`. Site 3 serves `openapi.json` and `swagger.json`.
- **nuclei:** v3.3.9 with nuclei-templates v10.5.1 and `-rl 30`. Every severity runs, as by default.
- **raijin-scan:** reduces the same nuclei JSONL with `--input`, so both sides see exactly the same matches. Defaults apply: no limit on findings, and `--max-bytes 16000`, which was not reached.
- **Tokens:** counted with tiktoken (`o200k_base`). This is a **proxy**, because Claude's tokenizer is not public. `bench/count_tokens.py` also gives exact Claude counts if `ANTHROPIC_API_KEY` is set and the `anthropic` package is installed. `cl100k_base` gives the same ratios.

## Scenario 1: broad scan, info only

`-t http/exposures/ -t http/technologies/ -t http/misconfiguration/` loads 2,852 templates. The run made 124 matches, all info:

- 100 `http-missing-security-headers` (10 headers × 10 targets)
- 20 `tech-detect`
- 2 `openapi`
- 2 `swagger-api`

| Output | Bytes | Tokens | vs. nuclei JSONL |
|---|---:|---:|---:|
| nuclei `-jsonl` | 220,578 | 72,698 | 1× |
| nuclei `-jsonl -omit-raw` | 147,779 | 44,771 | 1.6× |
| nuclei text (stdout+stderr) | 11,559 | 3,675 | 20× |
| **raijin-scan JSON (default)** | 1,356 | **434** | **168×** |
| raijin-scan `--pretty` | 1,870 | 575 | 126× |
| raijin-scan `--format table` | 422 | 101 | 720× |

## Scenario 2: exposures, real findings

`-t http/exposures/configs/ -t http/technologies/tech-detect.yaml -t http/exposures/apis/` made 30 matches:

- 2 `laravel-env` (high)
- 2 `codeigniter-env` (high)
- 2 `git-config` (medium)
- 20 `tech-detect`
- 2 `openapi`
- 2 `swagger-api`

| Output | Bytes | Tokens | vs. nuclei JSONL |
|---|---:|---:|---:|
| nuclei `-jsonl` | 46,357 | 15,831 | 1× |
| nuclei `-jsonl -omit-raw` | 28,718 | 9,216 | 1.7× |
| nuclei text (stdout+stderr) | 2,606 | 938 | 17× |
| **raijin-scan JSON (default)** | 1,309 | **430** | **37×** |
| raijin-scan `--pretty` | 1,815 | 586 | 27× |
| raijin-scan `--format table` | 467 | 154 | 103× |

In both scenarios the raijin-scan JSON includes about 35 tokens for `target`, which here is the long path of the input file.

## Nothing is lost

For each scenario, `bench/verify.py` checks every nuclei event against the raijin-scan output. An event's pair is its `template-id:matcher-name` and its `matched-at`. The pair must appear in a finding's `locations`, or in a group whose `variants` and `locations` contain it.

- Scenario 1: 124 events, **0 pairs missing**.
- Scenario 2: 30 events, **0 pairs missing**.

What the JSON leaves out stays in nuclei's JSONL, which raijin-scan saves to disk and points to in `raw`: the description, references, author, the `curl` command and timestamps. With `-omit-raw` there are no request or response bodies in either output.

## Reading the numbers

- **Against nuclei JSONL**, the structured output an agent would parse, raijin-scan uses **37× to 168× fewer tokens** for the same findings and locations. The gap grows with repetition. For example, 100 missing-header matches become one group: 10 header names plus 10 URLs.
- **Against nuclei's text output**, the gap is smaller:
  - scenario 1 is **8.5×** (3,675 → 434);
  - scenario 2 is **2.2×** (938 → 430).

  The text output is already terse, but it is one line per match. It has no dedup or ranking, and it carries nuclei's banner and log lines on stderr.
- **The output stays bounded.** On a scan too big for `--max-bytes`, raijin-scan cuts the least important data first: info locations, then info groups, then extra locations of low-ranked findings, then low-ranked findings. Every cut is counted in `omitted`, and `next` points to the raw file. Raw nuclei output has no upper bound.

## How the default output got here

o200k tokens:

| Version | Scenario 1 | Scenario 2 | Lossless? |
|---|---:|---:|---|
| Pretty JSON, all fields, 5 hosts per finding | 482 | 710 | no |
| Compact JSON | 338 | 501 | no |
| Compact, derivable fields left out | 298 | 360 | no |
| **Compact, every location** (current) | **434** | **430** | **yes** |

The first three versions listed at most 5 hosts and one evidence URL per finding, and 3 examples per info group. They also treated a second URL on the same host as a duplicate. The current version lists every location, and the extra tokens it costs go to information an agent can act on.
