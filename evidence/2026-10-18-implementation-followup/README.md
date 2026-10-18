# Preserved implementation follow-up package

See [the concise findings index](../../docs/research/IMPLEMENTATION_FOLLOWUP_2026-10-18.md).

Reports and selected supporting artifacts are byte-preserved copies of the
already-completed local analysis. `PUBLICATION_MANIFEST.json` records each copied
file's original local path and current SHA-256. These identify publication bytes,
not historical acquisition or execution. It excludes itself and this new index.

The manifest includes received loader-source files, runtime/source raw receipts,
serialized Lua chunks, parsed records, static disassembly windows and analysis
reports. Serialized chunks and received source must be read as data, not executed.
No console operation occurred during publication.

Earlier reports retain their original local paths, revision pins, qualifications
and corrections. Relative references within the selected packages are preserved
where their targets were included. References to other historical packages may
remain external; no omitted package is claimed to have been republished.
Original inherited OUTPUT_MANIFEST and preservation records describe their
original analysis directories, not this selected publication.

Collection sender scripts, transmitted scripts/frames, broad displacement-search
assembly exports and the archive-analysis Git database are intentionally not
republished. Their original local packages remain unchanged. The selected field
analysis includes its reviewed windows and candidate register; unreviewed
displacement hits are not implementation findings.

Raw files are protected against line-ending conversion. Some original reports
and received sources contain historical whitespace; they are not normalized to
make a new byte identity. The new findings index is checked separately for
documentation whitespace.
