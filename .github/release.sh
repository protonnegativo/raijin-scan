#!/usr/bin/env bash
# Tags HEAD with the next release and creates its GitHub Release.
# Usage: .github/release.sh [patch|minor|major]   (needs GH_TOKEN and a full clone)
set -euo pipefail

bump=${1:-patch}
git fetch --tags --quiet origin || true

if [ -n "$(git tag --points-at HEAD 'v*')" ]; then
  echo "HEAD is already tagged: $(git tag --points-at HEAD 'v*')"; exit 0
fi

last=$(git tag -l 'v*' --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || true)
if [ -z "$last" ]; then
  next=v0.1.0
else
  IFS=. read -r major minor patch <<< "${last#v}"
  case "$bump" in
    major) next="v$((major + 1)).0.0" ;;
    minor) next="v$major.$((minor + 1)).0" ;;
    patch) next="v$major.$minor.$((patch + 1))" ;;
    *) echo "unknown bump: $bump" >&2; exit 1 ;;
  esac
fi

git config user.name >/dev/null || git config user.name "github-actions[bot]"
git config user.email >/dev/null || git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git tag -a "$next" -m "$next"
git push origin "$next"
gh release create "$next" --verify-tag --generate-notes --title "$next"
echo "released $next"
