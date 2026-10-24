#!/usr/bin/env bash
# Turns the VHS recording of the README demo (docs/demo.tape) into docs/demo.gif, fast-forwarding the wait.
#
#   docs/demo-gif.sh IN.mp4 OUT.gif START END FACTOR [HOLD]
#
# START-END (seconds of IN.mp4) plays FACTOR times faster; everything else, typing and output, plays at real
# speed. HOLD adds seconds on the last frame (default 4). SCALE=WIDTH resizes
# the GIF. The palette is built in a separate pass, so
# memory stays low even for a wide, long recording.
set -euo pipefail
in=${1:?usage: demo-gif.sh IN.mp4 OUT.gif START END FACTOR [HOLD]}
out=${2:?}; s=${3:?}; e=${4:?}; f=${5:?}; hold=${6:-4}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
pal=$tmp/palette.png

graph="[0:v]trim=0:$s,setpts=PTS-STARTPTS[a];\
[0:v]trim=$s:$e,setpts=(PTS-STARTPTS)/$f[b];\
[0:v]trim=start=$e,setpts=PTS-STARTPTS,tpad=stop_mode=clone:stop_duration=$hold[c];\
[a][b][c]concat=n=3,fps=10${SCALE:+,scale=$SCALE:-1:flags=lanczos}"

ffmpeg -v error -y -i "$in" -filter_complex "$graph,palettegen=stats_mode=diff:max_colors=64" "$pal"
ffmpeg -v error -y -i "$in" -i "$pal" -filter_complex "$graph[v];[v][1:v]paletteuse=dither=none:diff_mode=rectangle" "$out"
echo "$out: $(du -h "$out" | cut -f1), $(ffprobe -v error -show_entries format=duration -of csv=p=0 "$out")s"
