# Research state

Rewrite this block with `python tools/state.py set key=value`. It is the
only memory that survives a context compaction, so keep it current and
short. Volatile values (kernel base, console liveness) carry the time they
were measured; they are measurements, not truths.

<!-- STATE:BEGIN -->
- console: unknown  (run: state.py check --ip <addr>)
- kernel_base: unknown  (re-measure with .local/1331a.lua after every boot)
- kernel_base_measured: -
- last_probe: p710
- active_question: -
- next_action: Determine CSSFontFaceSet vtable RVA from WebKit 605.1.15 source; then base=VP-RVA
- open_risks: -
- notes: p710 boundary: .rodata starts at VP-0x76DB28, .text>=42.87MB (XO). p691 deltas corrected.
<!-- STATE:END -->

Session start: this block, then the last ten rows of `results/INDEX.md`,
then only the document section the active question names.
