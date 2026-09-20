# Git ignore dependency provenance

This module is copied without a pattern-engine rewrite from
[denormal/go-gitignore](https://github.com/denormal/go-gitignore/tree/ae8ad1d07817),
version `v0.0.0-20180930084346-ae8ad1d07817`, MIT license in `LICENSE`.
The upstream module archive checksum is
`h1:0nsrg//Dc7xC74H/TZ5sYR8uk4UQRNjsw8zejqH5a4Q=`.
Syncthing's `go.mod` replaces the pinned dependency with this reviewed source.
The only dependency is `github.com/danwakefield/fnmatch`
`v0.0.0-20160403171240-cbb64ac3d964`, retained in module checksums.

## Compatibility patch

- `pattern.go`: trailing `/**` requires a descendant component. Native Git
  excludes `abc/file` but does not exclude directory `abc` for `abc/**`.
- `lexer.go`, `parser.go`, `pattern.go`: consecutive stars embedded in a
  component (including spaces) use ordinary fnmatch semantics; only a whole
  `**` path component is recursive. Modern Git accepts `a**z.txt`,
  `space ** end`, and `** tail`; upstream's old grammar rejects these.
- `pattern.go`: anchored name matching passes `FNM_PATHNAME`, so `*`/`?`
  cannot consume a directory separator; recursive matching assembles whole
  components from adjacent lexer tokens, preserving spaces and embedded stars
  in `**/space name` and `**/space ** end`.
- `defn_test.go`: update the exact token/position and matcher expectations
  for those corrected semantics, preserving the complete upstream test suite.
- `go.mod` / `go.sum`: define the local replacement module and pin fnmatch.

The independent regression oracle is native `git check-ignore --no-index`
with clean Git configuration, via `TestDomuneGitOracle` in `lib/ignore` and
Domune's `tests/fixtures/gitignore/cases.json`. It also covers zero/multiple
intermediate `**`, descendants, parent exclusion, nested scopes, case and
Unicode paths. There is no dependency on a Git executable at Core runtime.

The stable go-git/v5 v5.19.2 candidate also excludes `abc` for `abc/**` in the
recorded comparison, so it does not remove the need for a compatibility patch.
These are local, unsubmitted fixes; no claim of upstream acceptance is made.

## Verification

```sh
go test ./...
```

Run from this module directory, separately from Syncthing's complete suite.
The native Git oracle and fork component commands are in Domune's
`docs/implementation/gitignore-validation.md`.
