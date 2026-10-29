# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Every result starts with `"schema_version":1`. Readers can refuse a document whose version they do not understand.
- An invalid scope file is reported as JSON on stdout (one `kind: "scope"` error per invalid line, with a hint that says what to write instead), nothing is scanned, and the exit code is 1. It used to be a one-line message on stderr.
- Release builds can set the version with `-ldflags "-X main.releaseVersion=vX.Y.Z"`.

### Changed
- Scope, the output envelope and `--state` now come from the shared `raijin-core` module. The scope matcher is stricter and fails closed: a rule that could never match (a port, a stray `*`, a space, an empty label), or a CIDR with host bits set (`10.0.0.7/24`), is now an error instead of a rule that silently matched nothing or a wider range than written. `.admin.example.com` no longer matches `*.example.com`, and bare IPv6 addresses (`2001:db8::1`) are accepted.
- The `--state` file keeps its format and is now written atomically (temporary file, then rename).
- `&`, `<` and `>` in JSON strings are written as themselves instead of `&`, `<` and `>`. It is the same JSON value (parsers read both the same way) and fewer tokens. Byte-for-byte comparisons of the output against an older version will see the difference only in documents that contain those characters.

### Fixed
- `--version` reports the release version of builds made with the GoReleaser config.
