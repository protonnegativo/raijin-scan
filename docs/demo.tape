# README demo, recorded with VHS: https://github.com/charmbracelet/vhs
#
# VHS opens a real terminal, types these commands and records the screen, so the GIF shows exactly what
# a user sees: raijin-scan on the left and plain nuclei on the right, the same scan of the same targets, both
# started at the same moment (docs/demo-tmux.conf), each ending with the size of its output in bytes and in
# tokens (docs/demo-count.sh, tiktoken o200k_base). Run it from the repository root on Linux or macOS (needs
# vhs, ttyd, ffmpeg, tmux, nuclei with its templates in ~/nuclei-templates, raijin-scan on PATH, and a python3
# with tiktoken, or point PYTHON at one):
#
#     PYTHON=/path/to/venv/bin/python vhs docs/demo.tape
#
# (as root, also set VHS_NO_SANDBOX=true). Every scan hits a local lab only (docs/demo-lab.sh: static sites on
# 127.0.0.1:18181-18185 with an exposed .git/config and .env), started and stopped off camera. Timings change
# from one recording to the next.
#
# VHS records to docs/demo.mp4 (its own GIF encoder runs out of memory at this size). docs/demo-gif.sh turns
# that into the GIF and fast-forwards the wait (the two scans) 10x. Find the time range by watching the video;
# this matched the current recording:
#
#     SCALE=1440 docs/demo-gif.sh docs/demo.mp4 docs/demo.gif 16.5 57 10 4 && rm docs/demo.mp4

Output docs/demo.mp4

Require tmux
Require nuclei
Require raijin-scan
Require python3

Set Shell "bash"
Set FontSize 17
Set Width 1760
Set Height 860
Set Padding 20
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set TypingSpeed 35ms
Set Framerate 20

# Off camera: start the local lab and open tmux with two panes in it, raijin-scan on the left.
Hide
Type "REPO=$PWD LAB=$(mktemp -d) && docs/demo-lab.sh start $LAB && export PATH=$REPO/docs:$PATH"
Enter
Sleep 3s
Type "tmux -L raijin-demo -f docs/demo-tmux.conf new-session -c $LAB \; split-window -h -c $LAB \; select-pane -t :.1 -T 'nuclei -jsonl   (what an agent reads today)' \; select-pane -t :.0 -T 'raijin-scan   (the same scan, for the agent)' \; select-pane -t :.0"
Enter
Sleep 2s
Show

# Left: raijin-scan. It runs nuclei underneath and prints one compact JSON line.
Type "raijin-scan --scope scope.txt -l targets.txt -t http/exposures/configs/ -t http/technologies/tech-detect.yaml -t http/exposures/apis/ | tee raijin.json; demo-count.sh raijin.json"
Sleep 500ms
# Right: the same templates and targets with plain nuclei, as JSONL.
Ctrl+B
Type "o"
Type "nuclei -l targets.txt -t http/exposures/configs/ -t http/technologies/tech-detect.yaml -t http/exposures/apis/ -duc -jsonl -silent | tee nuclei.jsonl; demo-count.sh nuclei.jsonl"
Sleep 1s
# Enter in both panes at once.
Ctrl+B
Type "g"
Wait+Screen@5m /(?s)o200k_base.*o200k_base/
Sleep 8s

# Off camera: close tmux and stop the lab.
Hide
Ctrl+B
Type ":kill-server"
Enter
Sleep 1s
Type "docs/demo-lab.sh stop $LAB && rm -rf $LAB"
Enter
Sleep 1s
