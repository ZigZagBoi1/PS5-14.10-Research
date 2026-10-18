# Analysis method and evidence pointers

Inputs were opened as data only. No repository code, binary, collector or payload was executed. Existing source reports and table-comparison outputs seeded locations; this pass followed actual instructions rather than treating names as ground truth.

Decoder: Python 3.10 with existing Capstone 5.0.7, CS_ARCH_X86 / CS_MODE_64. Instruction addresses equal input file offsets. Direct relative branch/call destinations are calculated by that decoder. RIP-relative data coordinates are instruction address plus instruction length plus displacement; kernel_data.bin references are resolved by subtracting its recorded 0x1000000 mapping. Mapping authenticity remains unverified.

`SELECTED_BYTE_WINDOWS.json`: exact selected bytes, start/end-exclusive offsets and SHA-256 of those newly selected windows. These hashes establish current analysis-window identity only. Full-artifact hashes in the report are inherited, not rechecked.

`STATIC_WINDOWS.json`: instruction-window call/string observations. An assembly window can include adjacent functions or data; labels are analytical names, not recovered symbols. Some early/short exports are superseded by the expanded body exports. Filenames containing "claimed" preserve the former annotation being investigated. Files named copyin_thunk/copyout_thunk are short windows of candidate copy routines, not evidence that they are thunks.

`AIO_ENTRY_BRANCHES.json`: keyed by numeric selector; records decoded first branch and previously recorded compatibility-map destination. The next push instruction is not the end of a function or a complete branch-chain reconstruction.

`OMITTED_ENTRY_CODE.json`: selected entry code and short body heads. Numeric return constants are left uninterpreted.

`AIO663_CFG.json`: bounded traversal from 0x3b0210, within [0x3b0210,0x3b0fb0). Direct jumps/conditional fallthroughs followed; call targets not recursively traversed. Calls are assumed to return for fallthrough analysis, even where a diagnostic might not. Returns/terminal instructions stop paths. This cannot prove dynamic reachability, all indirect targets, complete function boundaries, absence of defects or acquisition authenticity.

The report identifies exact artifact offsets or structured-data keys for every new implementation conclusion. Historical logs retain their source revisions, Git blobs and inherited hashes in ../offline-candidate-triage/READ_LOG_REGISTER.json; previously recorded original artifact hash conflicts remain in the preceding comparison packages. No source evidence is overwritten here.
