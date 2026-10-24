#!/usr/bin/env bash
# Reproducible token benchmark: nuclei output vs raijin-scan output on the same local lab.
#
# usage: bench/run.sh <nuclei-templates dir> [workdir]
# needs: nuclei, python3 with tiktoken (pip install tiktoken), go
# optional: ANTHROPIC_API_KEY + pip install anthropic for exact Claude token counts
set -euo pipefail

TPL=${1:?usage: bench/run.sh <nuclei-templates dir> [workdir]}
W=${2:-$(mktemp -d)}
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$W"
echo "workdir: $W"

# Lab: 5 static sites on 127.0.0.1, each reached as 127.0.0.1 and localhost (10 targets).
lab() {
  local d=$W/lab
  rm -rf "$d"; mkdir -p "$d"/site{1..5}
  mkdir -p "$d/site1/.git" "$d/site4/.svn"
  printf '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://example.com/app.git\n' > "$d/site1/.git/config"
  printf 'APP_ENV=production\nDB_HOST=10.0.0.5\nDB_PASSWORD=Sup3rS3cret\nAPP_KEY=base64:abcd\n' > "$d/site1/.env"
  printf '<html><head><title>phpinfo()</title></head><body><h1 class="p">PHP Version 7.4.3</h1><table><tr><td class="e">System </td><td class="v">Linux</td></tr></table></body></html>' > "$d/site2/phpinfo.php"
  printf '{"openapi":"3.0.0","info":{"title":"Internal API","version":"1.0"},"paths":{"/users":{"get":{}}}}' > "$d/site3/openapi.json"
  printf '{"swagger":"2.0","info":{"title":"Internal API"},"paths":{}}' > "$d/site3/swagger.json"
  printf 'User-agent: *\nDisallow: /admin\nDisallow: /backup\n' > "$d/site4/robots.txt"
  printf '12\n\ndir\n' > "$d/site4/.svn/entries"
  for i in 1 2 3 4 5; do
    echo "<html><head><title>site$i</title></head></html>" > "$d/site$i/index.html"
    if ss -ltn | grep -q ":1808$i "; then echo "port 1808$i is busy; free it first" >&2; exit 1; fi
    (cd "$d/site$i" && python3 -m http.server "1808$i" --bind 127.0.0.1 >/dev/null 2>&1 & echo $! >> "$W/pids")
  done
  : > "$W/targets.txt"
  for i in 1 2 3 4 5; do printf 'http://127.0.0.1:1808%s\nhttp://localhost:1808%s\n' "$i" "$i" >> "$W/targets.txt"; done
  printf '127.0.0.1\nlocalhost\n' > "$W/scope.txt"
  sleep 1
}
trap '[ -f "$W/pids" ] && xargs kill < "$W/pids" 2>/dev/null || true' EXIT
lab

(cd "$HERE/.." && go build -o "$W/raijin-scan" ./cmd/raijin-scan)

scenario() {
  local name=$1; shift
  local o=$W/$name
  mkdir -p "$o"
  (cd "$TPL" && nuclei -l "$W/targets.txt" "$@" -duc -nc -rl 30 > "$o/text.txt" 2> "$o/text_stderr.txt")
  (cd "$TPL" && nuclei -l "$W/targets.txt" "$@" -duc -jsonl -silent -rl 30 > "$o/nuclei.jsonl")
  (cd "$TPL" && nuclei -l "$W/targets.txt" "$@" -duc -jsonl -silent -omit-raw -rl 30 > "$o/nuclei_omitraw.jsonl")
  # raijin-scan reduces the same JSONL nuclei produced, so both sides see the same matches.
  "$W/raijin-scan" --scope "$W/scope.txt" --input "$o/nuclei.jsonl" > "$o/raijin.json"
  "$W/raijin-scan" --scope "$W/scope.txt" --input "$o/nuclei.jsonl" --pretty > "$o/raijin_pretty.json"
  "$W/raijin-scan" --scope "$W/scope.txt" --input "$o/nuclei.jsonl" --format table > "$o/raijin_table.txt"
  echo; echo "## $name ($(wc -l < "$o/nuclei.jsonl") nuclei matches)"; echo
  python3 "$HERE/count_tokens.py" \
    "nuclei -jsonl=$o/nuclei.jsonl" \
    "nuclei -jsonl -omit-raw=$o/nuclei_omitraw.jsonl" \
    "nuclei text (stdout+stderr)=$o/text.txt+$o/text_stderr.txt" \
    "raijin-scan JSON (default)=$o/raijin.json" \
    "raijin-scan --pretty=$o/raijin_pretty.json" \
    "raijin-scan --format table=$o/raijin_table.txt"
}

scenario broad -t http/exposures/ -t http/technologies/ -t http/misconfiguration/
scenario exposures -t http/exposures/configs/ -t http/technologies/tech-detect.yaml -t http/exposures/apis/
