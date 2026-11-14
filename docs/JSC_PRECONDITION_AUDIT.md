# Preserve engine prerequisites when replaying vulnerability regressions

The browser corpus removes upstream `//@` directives. These can include engine
option requests, so a clean browser replay may exercise a different configuration
from the original regression test. The documented PS5 14.10 profile has JIT off;
see the p660 source analysis in `PROBE_INDEX.md` and the follow-up discussion in
[issue #241](https://github.com/ZigZagBoi1/PS5-14.10-Research/issues/241).

`python tools/webkit_crash_corpus.py jsc-build` now additionally writes
`results/webkit/corpus/preconditions-jsc.json`. Every downloaded source reviewed
by the builder is included, even if another browser filter drops it.

Each entry retains the upstream path and commit, local source filename, original
directive text and line numbers, and SHA-256 of the decoded/re-encoded source
text. This digest identifies the builder's interpreted input, not original bytes
if decoding replaced invalid UTF-8 or normalized newlines.

Explicit `=true` requests for `useJIT`, `useBaselineJIT`, `useDFGJIT`, `useFTLJIT`,
or `useWebAssembly` receive `configuration_review_required`. Other sources remain
`unassessed`. All entries retain `vulnerability_status: unknown`.

For example, `//@ requireOptions("--useDFGJIT=true")` is preserved and flagged
even though that directive disappears from the generated browser page. An
ordinary string in a test body or a `=false` option is not such a request.

This is a narrow source audit: it does not parse JavaScript, evaluate Ruby
directive conditions, resolve defaults, infer tier entry, or prove that a test
requires a compiler vulnerability. Conditional lines and requested options need
human review. A missing flag is not proof of compatibility. Generated pages and
their existing selection rules are unchanged.

Prior-art review found upstream PR #55 (corpus replay), PR #246 (LLInt/configuration
corrections), and issue #241 (interpretation of console tests). Current master
had no per-source precondition report. This change preserves evidence needed for
that review; it does not claim a new vulnerability or a PS5 measurement.

Validation: `python3 -m unittest tools.test_webkit_crash_corpus`. Tests cover
directive retention after page generation, explicit enabled/disabled options,
body-string controls, conditional directives, hashes, and filtered-out sources.

## Suggested PR description

The JSC browser builder strips engine configuration directives, including requests
to enable JIT tiers unavailable in the documented PS5 profile. Preserve those
requests in a separate per-source audit so researchers can review a regression's
prerequisites before interpreting a clean replay.

Adds `preconditions-jsc.json` with source identity, directive locations, and
explicit option requests. Conditional directives remain unevaluated, unknown
cases remain unassessed, and no vulnerability verdict is inferred. Existing page
selection and execution are unchanged. Adds four hardware-free regression tests.
