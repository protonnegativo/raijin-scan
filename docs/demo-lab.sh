#!/usr/bin/env bash
# Local lab for the README demo (docs/demo.tape): static sites on 127.0.0.1:18181-18185, one of them with an
# exposed .git/config and .env. Nothing leaves the machine.
#
#   docs/demo-lab.sh start DIR   # create DIR with the sites, scope.txt and targets.txt, start the servers
#   docs/demo-lab.sh stop DIR    # stop the servers started by "start"
set -euo pipefail

cmd=${1:?usage: demo-lab.sh start|stop DIR}
d=${2:?usage: demo-lab.sh start|stop DIR}

if [ "$cmd" = stop ]; then
  [ -f "$d/.pids" ] && xargs -r kill < "$d/.pids" 2>/dev/null || true
  rm -f "$d/.pids"
  exit 0
fi

mkdir -p "$d"
d=$(cd "$d" && pwd)
rm -rf "$d/lab"
mkdir -p "$d"/lab/site{1..5} "$d/lab/site1/.git"
printf '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://example.com/app.git\n' > "$d/lab/site1/.git/config"
printf 'APP_ENV=production\nDB_HOST=10.0.0.5\nDB_PASSWORD=Sup3rS3cret\nAPP_KEY=base64:abcd\n' > "$d/lab/site1/.env"
: > "$d/targets.txt"
for i in 1 2 3 4 5; do
  echo "<html><head><title>site$i</title></head></html>" > "$d/lab/site$i/index.html"
  if ss -ltn | grep -q ":1818$i "; then echo "port 1818$i is busy" >&2; exit 1; fi
  (cd "$d/lab/site$i" && exec python3 -m http.server "1818$i" --bind 127.0.0.1) >/dev/null 2>&1 &
  echo $! >> "$d/.pids"
  printf 'http://127.0.0.1:1818%s\nhttp://localhost:1818%s\n' "$i" "$i" >> "$d/targets.txt"
done
printf '127.0.0.1\nlocalhost\n' > "$d/scope.txt"
sleep 1
