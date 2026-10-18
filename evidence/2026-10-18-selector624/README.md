# Selector 624: bounded loader observations

2026-10-18, session-reported target context 14.10; firmware/build identity is not authenticated. Source checkout at collection: `0ccf250603b8b448045ec6405abfaf0346b88504`.

Two bounded sessions used the existing zero-argument selector-wrapper pattern from `probes/phase12_kernel_analysis/51b_accessible_syscall_deep.lua:20-25,207-212`. This pattern is historical source evidence, not a documented Sony 14.10 ABI. No other selector, memory operation, allocation experiment, fuzzing or historical probe suite ran.

| Session | UTC collection time | Observations |
|---|---|---|
| baseline | 2026-10-18 06:43:29 | Three returns `0x00000000_00000D31` (3377); script end marker received; peer EOF. |
| wrapper-followup | 2026-10-18 06:44:15 | Lua reports `Lua 5.1`; base object/metatable are tables and `__call` is a function. Recorded selector is 624 before each of three calls. Each return is a table with numeric h/l fields, decoded as the same `0xD31`. New script end marker received; peer EOF. |

Exact scripts, transmitted frames, raw responses, sender source and session metadata are preserved in the respective subdirectories. SESSION.json records script/sender/response SHA-256 and timestamps. FILE_HASHES.json records current publication-file hashes; these are not historical acquisition hashes.

## Logging correction

The follow-up reused the baseline sender, whose completion check searches for `SELECTOR624_BASELINE_END_20261018`. Consequently wrapper-followup/SESSION.json records `completion_marker_received: false`. The correct follow-up marker `SELECTOR624_WRAPPER_END_20261018` is present in wrapper-followup/response.raw. Preserve the original sender metadata; interpret that boolean as an obsolete-marker check, not absence of completion output. The received end marker shows execution reached the final print, not independent proof of every native operation or clean interpreter teardown.

## Evidence limits and next question

The six wrapper-visible returns are stable across these two short sessions. They do not identify the metric, establish native syscall dispatch/handler identity, demonstrate memory accounting, authenticate firmware, or establish a vulnerability. No firmware string was independently verified. The earlier 13.60-labeled scalar-read body remains reference material only; its object/field interpretation and acquisition authenticity remain unresolved.

The next substantive task is offline: identify writers and units of the retained 13.60 field and recover the loader's native dispatch contract from attributable existing source/binary evidence. Repeating the same baseline or trusting mutable Lua annotations cannot establish either. A controlled allocation experiment was not run.
