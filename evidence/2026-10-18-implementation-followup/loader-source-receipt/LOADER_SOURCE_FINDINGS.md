# Present-day loader source receipt and dispatch findings

2026-10-18. New, explicitly authorized userland read-only collection from 10.0.0.96:9026. This supersedes the earlier local-source-availability gap **only for the five files received now**. Historical archive searches remain closed; their original negative findings are unchanged.

## Collection and custody

Two bounded Lua scripts read only /savedata0/syscall.lua, native.lua, uint64.lua, ropchain.lua and lua.lua through ordinary io.open/read/close. Each file was capped at 65536 bytes. No kernel selector, memory-read/write API, native call, payload, new file on target, permission change, fuzzing or allocation experiment was requested. Ordinary Lua/file I/O necessarily uses runtime resources; this is not a claim of zero transient state changes.

Sessions: 2026-10-18 06:59:20 UTC and 07:00:08 UTC (02:59:20 and 03:00:08 America/New_York). Both connected, submitted, returned the expected source-read end marker and peer EOF. Raw hex responses were retained unchanged; analyst-written decoding reconstructed exact bytes and checked declared sizes. Source copies were inspected as text, not imported or executed. The transmitted scripts and frames, sender identity/hash, timestamps, raw-response hashes and received-file hashes are preserved alongside this report and under dependencies/.

| Original target path | Received bytes | SHA-256 calculated on receipt |
|---|---:|---|
| /savedata0/syscall.lua | 3031 | 5fdd950fea422c6c4f2811b2a5f532fcece695bea8e0197e33b317320796012a |
| /savedata0/native.lua | 8273 | f8a8fc832186bddca436dc7688636424e8d032a7dda4306486d5f2346ea5e1bd |
| /savedata0/uint64.lua | 6726 | deab7ff4b666761d00e61edfae9e66c83cf6a1323d43ba176ce9e262a2501957 |
| /savedata0/ropchain.lua | 18338 | b3ac55b7145616ab9df394406f09f026da0d5ad1022a44c865a2dfb554e8cfa7 |
| /savedata0/lua.lua | 16211 | 0386a9e7c6ad8db3e2a7b21128b111d3f9a400f3508596b9d301fe8a8bf3798d |

These are **new current-file hashes**, not historical execution hashes. Custody is endpoint response -> preserved raw transcript -> decoded local file. The endpoint/runtime supplied the file contents; no independent signature, upstream revision, loaded-chunk equality, module binary hash, device identity or firmware attestation was obtained. Files could differ from code previously loaded. No upstream equivalence is asserted.

Logging limitation: dependencies/SESSION.json inherited the sender description 'three named' although its exact transmitted collect.lua names two dependencies. The raw file markers, scripts and reconstructed two-file list establish the actual scope; preserve this metadata discrepancy rather than silently rewriting the original receipt. Both scripts reuse the same source-read marker, distinguished by their separately saved session/script/response hashes and paths.

## Source-level findings

These are verified properties of the received **text**, not verified execution of its native mechanisms.

1. **Callable class identified in received source.** dependencies/ropchain.lua:593–605 constructs a callable object holding fn_addr and syscall_no. :642–655 defines __call with an explicit native-versus-coroutine branch. Both paths consume the object's syscall_no. Therefore the historical table-copy pattern has a coherent source-level selector-consumption explanation; this is stronger than merely observing a mutable Lua number. It does not establish the current loaded implementation matches this file.
2. **Two dispatch paths explain a plausible old-metadata distinction.** The native branch does not directly execute the older fcall.chain path. This is consistent with selected historical calls surviving old-chain mutations, but does not prove that branch was selected in those earlier sessions, nor that all metadata is ignored. No mutation or redirect was run. The arbitrary-function/kernel-execution interpretation remains unsupported.
3. **Return representation explained.** native.lua:209–222 wraps the native return with uint64; uint64.lua:39–67 splits numeric input into high/low fields and also accepts strings or an existing uint64-like value. This matches the observed table/h/l shape. It is source-level conversion evidence, not independent correctness proof for every native return. Small integer 3377 is exactly representable in Lua's usual numeric range, so large-integer precision is not required to display that particular value; the native producer remains independently unverified.
4. **Zero-argument calls still have marshaling behavior.** native.lua:209–222 supplies zero defaults for omitted argument positions. The fallback source has analogous defaults. 'No explicit Lua arguments' therefore does not mean the kernel necessarily receives no argument values; the actual selector ABI remains unknown. No guessed Sony prototype is supplied.
5. **The old universal Lua-filter claim is unsupported.** syscall.lua:75–89 has a platform-dependent resolve loop. The PS4 branch depends on previously discovered wrappers, while the PS5 branch constructs the requested named callable through its selected wrapper path. No universal allowlist or blanket sandbox-enforcement mechanism is recovered in this function. Kernel policy is separate and not shown by this source.
6. **Platform detection is not firmware authentication.** syscall.lua:34–72 uses module-information assumptions and a relative initialization-address condition to assign platform. This identifies a source heuristic, not a signed firmware/build identity or proof that a 14.10 kernel layout matches 13.60. No module code was collected or native wrapper disassembled here.

The code references additional game-specific offsets, helper initialization and imported functions. Recovering source-level dispatch does not authenticate those dependencies or native instruction bytes. No exploit-chain reconstruction is included in this analysis.

## Conclusions that change

- Existing readable deployed-path loader source: **now recovered**, with endpoint receipt and present-day hashes.
- Source-level selector use and native/fallback branch distinction: **supported by received source**; loaded/historical path selection remains unknown.
- Return-table conversion: **supported by received source**, consistent with latest wrapper observations.
- Native binary registration/target identity and exact loaded-code association: **partially resolved at source level only**; machine-code/module build evidence missing.
- Selector624's 14.10 metric meaning: **unchanged, unresolved**. No new calls or allocation experiment occurred. The retained 13.60 write-lock-counter interpretation cannot be transferred solely from this source.
- Historical acquisition authenticity, 14.10 sysent layout and vulnerability applicability: **unchanged, unresolved**.

## Next narrow step

Use ordinary Lua introspection, if continued live work is requested, to obtain function source-location/type metadata for the current fcall callable and report whether the native branch's controlling global is present, without invoking it or accessing arbitrary memory. This can bind source filenames/line ranges and configuration more closely to the active runtime; it still cannot prove disk-to-loaded byte equality or native machine-code identity. No syscall probing is necessary for that question.

Repository revision before/after collection remains 7e25a1174b5a3086b7e90d860d85f8ab7bad7a70 with clean status. Earlier reports, raw records and artifacts are unchanged. New source receipts and analysis are saved separately; nothing has been pushed by this collection.
