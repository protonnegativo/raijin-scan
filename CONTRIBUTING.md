# Contributing to raijin-scan

Thanks for wanting to help. raijin-scan is a small Go tool, part of [Raijin](https://github.com/protonnegativo/raijin), and small, focused changes are the easiest to review.

By taking part you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md). Security problems go through [SECURITY.md](SECURITY.md), not public issues.

## Before you start

- **Bug or small fix:** open a pull request directly, with a test that fails before the change and passes after.
- **New feature, new flag, new output field or a big refactor:** open an issue first and wait for a reply. It saves you from writing something that does not fit.
- Look for an existing issue or pull request on the same thing before starting.

## Build and test

You need Go 1.22 or newer (see `go.mod`).

```bash
git clone https://github.com/protonnegativo/raijin-scan && cd raijin-scan
go build ./...
go vet ./...
test -z "$(gofmt -l .)"      # prints nothing when formatting is right
go test ./...
```

These are the same checks CI runs. Run them before you push.

To build the binary: `go build -o raijin-scan ./cmd/raijin-scan`.

The engines raijin-scan wraps (nuclei, httpx, ...) are external programs found on `PATH`. Unit tests use the recorded outputs in `testdata/`, so you do not need the engines to run `go test`.

## The benchmark

If your change touches the reducer or the output, run the offline benchmark, which replays recorded engine output:

```bash
pip install tiktoken
PY=python3 bench/run.sh
```

It prints the token counts and checks that nothing from the engine's output is missing from ours. A change that makes the output larger, or that reports a missing result, needs a reason in the pull request. If the repository has no `bench/` directory, this step does not apply.

## The JSON output is a contract

The JSON that raijin-scan prints (the Raijin Schema: `summary`, `findings`, `groups`, `omitted`, `errors`, `next`) is read by AI agents, scripts and `raijin-mcp`. Treat it as a stable API:

- Do not rename or remove a field, and do not change its type or meaning.
- Adding an optional field is fine, but discuss it in an issue first, and document it.
- Keep the output deterministic: the same input gives the same bytes, with sorted keys and stable ordering.
- Update the golden files and docs in the same pull request as any intended change, and say so in the description.

Breaking changes need a maintainer's agreement and a major version bump.

## Style

- `gofmt` is the formatter. Follow the style of the surrounding code, and keep the standard library first when it is enough.
- Keep the change minimal: one problem per pull request, no unrelated cleanups or reformatting.
- Errors an agent can act on: say what happened and what to try next.

## Commits

Short, imperative subject, 72 characters or less, no trailing period. Explain the why in the body when it is not obvious.

```
Collapse identical groups across hosts
Fix timeout hint when rate is already low
```

No special prefix is required. Squash fixup commits before review.

## Pull requests

Fill in the pull request template. Say how you tested the change. Small and focused changes get reviewed faster.

## AI-assisted contributions

Contributions written or assisted with AI tools are welcome, as long as you:

- understand every line you submit and can explain it in review;
- ran and tested the change yourself, not only had a tool say it works;
- did not invent behavior, flags or API: check them in the code or in the engine's docs.

Pull requests that look unreviewed or untested by a human may be closed without a long discussion.

## License

By contributing you agree that your contribution is licensed under the [MIT License](LICENSE) of this project.
