# Loaded Lua dispatch snapshots

2026-10-18, collection 07:03:33 UTC / 03:03:33 America/New_York. One bounded session. The collection script serializes three existing Lua function objects with string.dump, at most 32768 bytes per function. It does not call those functions, native_invoke, syscall callables, arbitrary-memory APIs or file APIs. No target persistence change requested. Transient Lua allocation/output occurs as part of serialization.

## Receipt

Connection established; script submitted; three complete size-delimited snapshots received; final marker and peer EOF observed. Exact collection script, transmitted frame, sender, raw response and timestamps are preserved. SESSION.json hashes the script/sender/response; LOADED_CHUNKS.json identifies reconstructed serialized bytes. The analyst decoding checks reconstructed byte counts. These are current runtime serializations, not kernel images, native code, historical execution records or signed attestations.

| Function | Bytes | SHA-256 of serialized bytes received now |
|---|---:|---|
| fcall.__call | 1754 | dc60264bc87cba571b7dd7eefa8bcda8a7f38bd17088cd50d0523e48ce349d7a |
| syscall.resolve | 981 | 7764b8f7d8b3b39325a2e1733545d60702e01e36d257d786a45c97f7fcf47edd |
| native.fcall_with_rax | 1290 | b78974c9d989e7ab7d2a227f3cead7f7550c153736e2499bc40b879f609ce44c |

The serialized files are saved as *.luac.bin and were never loaded/imported/executed by the analyst. Source extraction and runtime serialization occurred in different sessions; their relationship is assessed below, not assumed.

## What the loaded snapshots establish

PARSED_LUA_CHUNKS.json contains per-function source metadata, constants and decoded instructions; select entries by file. PC values are zero-based Lua instruction indices, not native addresses. Parsing assumes Lua-5.1-style instruction encodings and adds only the observed serialization feature described below. This is an analyst parser, not an independent trusted VM verifier.

- **fcall_call.luac.bin**: source metadata /savedata0/ropchain.lua:642–657; 97 instructions per recorded vector. Constants include native_invoke, native, fcall_with_rax, fn_addr and syscall_no, plus fallback arg_addr/chain/execute_through_coroutine references. The decoded global access/test and branch sequence is consistent with the received source's native/fallback split. This is loaded-bytecode support, stronger than metadata alone; no native branch call was made in this collection.
- **syscall_resolve.luac.bin**: /savedata0/syscall.lua:67–81; 44 instructions per vector. Constants and branches include separate ps4 wrapper lookup/error and ps5 syscall_address paths, consistent with the received source. No universal selector allowlist is recovered in this function. Native/kernel filtering remains a distinct question.
- **native_fcall_with_rax.luac.bin**: /savedata0/native.lua:209–223; 72 instructions per vector. References include native_invoke, native_cmd_handler, uint64, tonumber and lua.resolve_value, agreeing with the marshaling/return conversion structure in the received source. This is not a machine-code identity or proof that every conversion/native operation has the assumed semantics.

No exact source-to-compiled-bytecode equality test was performed: the received full source was not compiled/executed, and compilation metadata/options could affect serialization. Claim **structural agreement**, not a reproducible build match. Globals can be mutable, serialized functions do not capture all environment state, and serialization itself is runtime-provided.

## Observed format difference

All three snapshots begin with header 1b4c75615100010408040800, reporting a Lua-5.1-style header and integer/size/instruction/number widths. After each function header, the observed layout contains a counted instruction vector followed immediately by another equally counted, byte-identical vector, before constants.

A stock single-vector parser initially failed at the assumed constants boundary (unexpected tag 197). Inspection located the second vector; the adjusted parser explicitly checks its equality with the first, then parses constants, line tables, locals and upvalue names, requiring exact end-of-file consumption. Counts were 97/97, 72/72 and 44/44. No interpretation of which vector is executed, why it is duplicated, or whether it reflects a vendor/debug/serializer extension is established. No firmware identity follows from this format feature. Raw bytes are retained for independent verification.

See parse_chunks.py for the exact analysis procedure. This new, specific serialization check does not repeat prior firmware/table/hash comparisons. Do not treat an ordinary stock-Lua chunk loader as a safe or accurate way to inspect these files.

## Conclusions and remaining boundary

Current loaded Lua serialization now supports the source-level selector-consumption and two-path dispatch explanation. Earlier claims that the pipe metatable __call must itself be a C function are contradicted in these present sessions by both debug metadata and serialized Lua function data. The separately exposed native_invoke still reports C in the preceding session and was not serialized or invoked here.

Missing: native callable machine-code/module/build identity; authoritative Sony ABI; exact game/loader deployed build; any identity link to historical probe sessions; authenticated kernel firmware provenance. These snapshots do not identify selector624's 14.10 metric or authenticate sysent correspondence, and do not establish a vulnerability or kernel access.

Next offline step: inspect the recovered loader's function-registration and game-offset references as data, separating native callable setup from the loaded Lua dispatch now recovered. Use an already-retained matching module/source if one exists. No need for more baseline selector calls or arbitrary-memory extraction to repeat the current conclusion.

Repository before/after remains 7e25a1174b5a3086b7e90d860d85f8ab7bad7a70, clean. No push, original evidence modification, native execution test or kernel probing occurred.
