#!/usr/bin/env bash
# Reproducible token benchmark: nuclei output vs raijin-scan output on the same local lab.
#
# usage: bench/run.sh [workdir]
#   By default it replays the nuclei output committed in bench/fixtures (no nuclei needed).
#   LIVE=1 TPL=<nuclei-templates dir> runs nuclei on the local lab instead (TPL defaults to
#   ~/nuclei-templates); PORT0 is the first lab port (default 18081).
# needs: python3 with tiktoken (pip install tiktoken), go; nuclei for LIVE. PY picks the python.
# optional: ANTHROPIC_API_KEY + pip install anthropic for exact Claude token counts
set -euo pipefail

LIVE=${LIVE:-}
TPL=${TPL:-$HOME/nuclei-templates}
PY=${PY:-python3}
PORT0=${PORT0:-18081}
W=${1:-$(mktemp -d)}
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
    local p=$((PORT0 + i - 1))
    echo "<html><head><title>site$i</title></head></html>" > "$d/site$i/index.html"
    if ss -ltn | grep -q ":$p "; then echo "port $p is busy; free it first" >&2; exit 1; fi
    python3 -m http.server "$p" --bind 127.0.0.1 -d "$d/site$i" >/dev/null 2>&1 &
    echo $! >> "$W/pids"
  done
  : > "$W/targets.txt"
  for i in 1 2 3 4 5; do printf 'http://127.0.0.1:%s\nhttp://localhost:%s\n' $((PORT0 + i - 1)) $((PORT0 + i - 1)) >> "$W/targets.txt"; done
  printf '127.0.0.1\nlocalhost\n' > "$W/scope.txt"
  sleep 1
}
trap '[ -f "$W/pids" ] && xargs kill < "$W/pids" 2>/dev/null || true' EXIT
if [ -n "$LIVE" ]; then
  lab
  nuclei -version -duc 2>&1 | grep -i version || true
else
  printf '127.0.0.1\nlocalhost\n' > "$W/scope.txt"
fi

(cd "$HERE/.." && go build -o "$W/raijin-scan" ./cmd/raijin-scan)

scenario() {
  local name=$1; shift
  local o=$W/$name
  mkdir -p "$o"
  if [ -n "$LIVE" ]; then
    (cd "$TPL" && nuclei -l "$W/targets.txt" "$@" -duc -nc -rl "${RATE:-30}" > "$o/text.txt" 2> "$o/text_stderr.txt")
    (cd "$TPL" && nuclei -l "$W/targets.txt" "$@" -duc -jsonl -silent -rl "${RATE:-30}" > "$o/nuclei.jsonl")
    (cd "$TPL" && nuclei -l "$W/targets.txt" "$@" -duc -jsonl -silent -omit-raw -rl "${RATE:-30}" > "$o/nuclei_omitraw.jsonl")
  else
    cp "$HERE/fixtures/$name"/* "$o/"
  fi
  # raijin-scan reduces the same JSONL nuclei produced, so both sides see the same matches.
  "$W/raijin-scan" --scope "$W/scope.txt" --input "$o/nuclei.jsonl" > "$o/raijin.json"
  "$W/raijin-scan" --scope "$W/scope.txt" --input "$o/nuclei.jsonl" --pretty > "$o/raijin_pretty.json"
  "$W/raijin-scan" --scope "$W/scope.txt" --input "$o/nuclei.jsonl" --format table > "$o/raijin_table.txt"
  echo; echo "## $name ($(wc -l < "$o/nuclei.jsonl") nuclei matches)"; echo
  "$PY" "$HERE/verify.py" "$o/nuclei.jsonl" "$o/raijin.json"
  "$PY" "$HERE/count_tokens.py" \
    "nuclei -jsonl=$o/nuclei.jsonl" \
    "nuclei -jsonl -omit-raw=$o/nuclei_omitraw.jsonl" \
    "nuclei text (stdout+stderr)=$o/text.txt+$o/text_stderr.txt" \
    "raijin-scan JSON (default)=$o/raijin.json" \
    "raijin-scan --pretty=$o/raijin_pretty.json" \
    "raijin-scan --format table=$o/raijin_table.txt"
}

scenario broad -t http/exposures/ -t http/technologies/ -t http/misconfiguration/
scenario exposures -t http/exposures/configs/ -t http/technologies/tech-detect.yaml -t http/exposures/apis/
