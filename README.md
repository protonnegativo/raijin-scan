# ⚡ Raijin Scan

<p align="center">
  <img src="docs/banner.png" alt="Raijin banner: a storm thunderbird in braille inside a target-lock frame, the RAIJIN name and a status HUD" width="760">
</p>

**nuclei for AI agents: the same findings, a fraction of the output.**

`raijin-scan` is part of the [Raijin](https://github.com/protonnegativo/raijin) arsenal. It runs [nuclei](https://github.com/projectdiscovery/nuclei) underneath and returns the **Raijin Schema**: a small JSON with unique findings ranked by severity, the minimal evidence for each one, repeated info-level noise collapsed into groups, and a count of everything it left out.

On a local lab with 10 targets, the result an agent reads costs **31× to 215× fewer tokens** than nuclei's JSONL for the same matches, with the real findings first. See [BENCHMARK.md](BENCHMARK.md).

## Install

```bash
go install github.com/protonnegativo/raijin-scan/cmd/raijin-scan@latest
```

You also need `nuclei` on `PATH`, or pass `--nuclei <path>`.

## Usage

```bash
raijin-scan --scope scope.txt -l targets.txt -t http/exposures/ --max-items 10
raijin-scan --scope scope.txt -u https://app.example.com --severity critical,high
raijin-scan --scope scope.txt --input nuclei-results.jsonl     # reduce output you already have
raijin-scan --scope scope.txt -l targets.txt --state run.json  # mark findings that are new since last run
raijin-scan ... -- -H "Authorization: Bearer x"                # anything after -- goes to nuclei
```

`--scope` is required. One rule per line:

```
example.com
*.example.com
10.0.0.0/24
!admin.example.com
```

Targets outside the scope are dropped before nuclei runs, and results for out-of-scope hosts (for example after a redirect) are dropped from the output. Both are counted in `omitted.out_of_scope`.

## Output

```json
{
  "tool": "raijin-scan",
  "summary": "1 findings (1 medium), 1 info groups, 6 raw matches, 1 new",
  "findings": [
    {
      "id": "git-config",
      "title": "Git Configuration - Detect",
      "severity": "medium",
      "hosts": ["127.0.0.1:18080", "localhost:18080"],
      "evidence": "http://localhost:18080/.git/config",
      "new": true
    }
  ],
  "groups": [{"id": "tech-detect", "count": 2, "examples": ["127.0.0.1:18080", "localhost:18080"], "variants": ["python", "simplehttp"]}],
  "omitted": {"out_of_scope": 1}
}
```

Fields an agent can rebuild are left out to save tokens, so no information is lost:

- `hosts_count` appears only when it is larger than the hosts listed.
- `confidence` appears only when it is not `matched`.
- `omitted`, `errors` and `next` appear only when they are not empty.
- `budget` appears only when something was cut.

The nuclei template is the `id` up to the first `:`.

What the reducer does:

- **One finding per template and matcher**, across every host. The first 5 hosts are listed; `hosts_count` has the total.
- **Info-level matches become one `group` per template** (host count, 3 examples, and the matcher names in `variants`) unless you pass `--include-info`.
- **Evidence is the matched URL, the matcher and up to 3 extracted values**, cut at 300 characters. It never includes the request or response.
- **Ranking:** severity first, then the number of hosts.
- **Budget:** `--max-items` caps the findings; `--max-bytes` shrinks host examples, then groups, then the lowest-ranked findings until the JSON fits. Whatever was cut is counted in `omitted` and `budget.truncated` is set.
- **Errors** say what to try next. If nuclei is missing, the exit code is 2.

The JSON is compact (one line) by default because indentation costs about 30% more tokens; `--pretty` indents it (the example above is pretty-printed). `--format table` prints a short human view of the same result.

The banner above is **off by default**, so normal runs stay small. `--banner` prints it to **stderr** (never stdout, so the JSON is untouched), with the version taken from the binary. Colors are disabled when `NO_COLOR` is set or stderr is not a terminal.

## Flags

| Flag | Default | |
|---|---|---|
| `--scope` | (required) | scope file |
| `-u` / `-l` / `--input` | | one target (repeatable) / target file / existing nuclei JSONL |
| `-t`, `--tags`, `--severity` | | passed to nuclei |
| `--rate`, `--timeout` | | nuclei `-rl` / `-timeout` |
| `--max-items` | 20 | max findings |
| `--max-bytes` | 8000 | max JSON size |
| `--include-info` | false | info matches as findings, not groups |
| `--state` | | state file for new-since-last-run |
| `--format` | json | `json` or `table` |
| `--pretty` | false | indent the JSON |
| `--nuclei` | nuclei | path to the binary |
| `--banner` | false | print the banner to stderr |

## Development

```bash
go test ./...
go vet ./...
```

Standard library only. nuclei runs as a subprocess with `-jsonl -omit-raw`, so the binary stays small and nuclei can be updated on its own.

## Roadmap

- `next` suggestions from detected tech.
- Optional embedded nuclei SDK instead of the subprocess.
- `raijin-mcp` will expose this tool to MCP clients.

## Responsible use

Only scan what you are authorized to test.
