# ⚡ Raijin Scan

**nuclei for AI agents: the same findings, a fraction of the output.**

`raijin-scan` is part of the [Raijin](https://github.com/protonnegativo/raijin) arsenal. It runs [nuclei](https://github.com/projectdiscovery/nuclei) underneath and returns the **Raijin Schema**: a small JSON with unique findings ranked by severity, the minimal evidence for each one, repeated info-level noise collapsed into groups, and a count of everything it left out.

On the same 26 nuclei matches against 2 hosts, raw nuclei JSONL is **47,151 bytes**. The `raijin-scan` output is **2,668 bytes** (17.7× smaller), with the one real finding first.

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
  "summary": "1 unique finding(s) (1 medium), 2 info group(s), 6 raw match(es) collapsed, 1 new since last run",
  "findings": [
    {
      "id": "git-config",
      "title": "Git Configuration - Detect",
      "severity": "medium",
      "confidence": "matched",
      "hosts": ["127.0.0.1:18080", "localhost:18080"],
      "hosts_count": 2,
      "evidence": "http://localhost:18080/.git/config",
      "engine_ref": "nuclei:git-config",
      "fingerprint": "0ea655078c0f38f9",
      "new": true
    }
  ],
  "groups": [{"id": "tech-detect:python", "count": 2, "examples": ["127.0.0.1:18080", "localhost:18080"]}],
  "omitted": {"out_of_scope": 1},
  "errors": [],
  "next": [],
  "budget": {"max_items": 20, "max_bytes": 8000, "truncated": false}
}
```

What the reducer does:

- **One finding per template and matcher**, across every host. The first 5 hosts are listed; `hosts_count` has the total.
- **Info-level matches become `groups`** (count and 3 examples) unless you pass `--include-info`.
- **Evidence is the matched URL, the matcher and up to 3 extracted values**, cut at 300 characters. It never includes the request or response.
- **Ranking:** severity first, then the number of hosts.
- **Budget:** `--max-items` caps the findings; `--max-bytes` shrinks host examples, then groups, then the lowest-ranked findings until the JSON fits. Whatever was cut is counted in `omitted` and `budget.truncated` is set.
- **Errors** say what to try next. If nuclei is missing, the exit code is 2.

`--format table` prints a short human view of the same result.

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
| `--nuclei` | nuclei | path to the binary |

## Development

```bash
go test ./...
go vet ./...
```

Standard library only. nuclei runs as a subprocess with `-jsonl -omit-raw`, so the binary stays small and nuclei can be updated on its own.

## Roadmap

- Merge info groups from the same template (for example 10 `http-missing-security-headers:*` groups into one).
- `next` suggestions from detected tech.
- Optional embedded nuclei SDK instead of the subprocess.
- `raijin-mcp` will expose this tool to MCP clients.

## Responsible use

Only scan what you are authorized to test.
