## What and why

<!-- One problem per pull request. Link the issue: "Fixes #123". Big features need an issue first. -->

## How I tested it

<!-- Commands you ran and what you saw. A test that fails before and passes after is best. -->

## Checklist

- [ ] `go vet ./...`, `gofmt -l .` and `go test ./...` pass locally
- [ ] If the output changed: the JSON schema is still backward compatible, or this is discussed in an issue
- [ ] If the reducer changed: the offline benchmark (`bench/run.sh`) still reports nothing missing
- [ ] Docs updated if behavior changed
- [ ] I understand every line of this change and tested it myself (AI assistance is fine, see CONTRIBUTING.md)
