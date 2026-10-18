# Active loader metadata: source linkage and dispatch configuration

2026-10-18, 07:02:21 UTC / 03:02:21 America/New_York. One bounded session at 10.0.0.96:9026. No syscall callable, native dispatcher, arbitrary-memory API, payload or file operation was invoked by the collection script. Script uses ordinary Lua type/rawget/metatable/debug.getinfo operations and prints the observations. Exact transmitted script/frame, sender/script SHA-256, raw response, timestamps and response digest are retained here. End marker and peer EOF were observed.

## Observed current-session facts

All references below point to response.raw, selected by the displayed function label and INFO key:

| Item | Observed metadata | Meaning and limitation |
|---|---|---|
| fcall.__call | what=Lua; source=@/savedata0/ropchain.lua; lines 642–657; nups=0 | Active callable identifies itself as Lua, not C. Source filenames/line metadata are runtime supplied, not content authentication. |
| pipe.metatable.__call | Same source/type/line range; pipe metatable identity compares equal to fcall table | Links the examined pipe object's metatable to the class. Does not prove every callable object is unchanged or uses this class. |
| native.fcall_with_rax | what=Lua; source=@/savedata0/native.lua; lines 209–223; nups=0 | Metadata agrees with the received function's source range. No native-call execution occurred during this check. |
| native_invoke | type=function; what=C; source==[C]; line metadata -1; nups=0 | The separately exposed native callable is C according to runtime debug metadata. Its pointer, binary bytes, registration origin and module/build identity were not collected. |
| native branch condition | native_invoke is present and truthy | In the received ropchain.lua definition, the current condition would choose the native path. This is configuration evidence, not a trace demonstrating a call entered that branch or the source is byte-identical to the loaded chunk. |
| syscall.resolve | what=Lua; source=@/savedata0/syscall.lua; lines 67–81; nups=0 | Identifies the current resolver's source metadata; not a firmware identity or a kernel-policy observation. |
| runtime | Lua 5.1 | Session-reported interpreter version; does not authenticate firmware/build. |

## Conclusions changed

The old attribution of the pipe metatable __call as necessarily a C function is contradicted **for this current session**. The actual metadata distinguishes Lua class dispatch from a separately exposed C callable. A printed `function: ...` string in the old logs did not establish that distinction.

Current metadata supports the source-level explanation for a native-versus-older-chain split and why old shared-chain mutations need not affect a native-path call. Historical 45c branch selection is still not proved. No mutation, native call, binary read or execution-control test was repeated.

The source filenames and function line ranges agree with the present-day files received in ../loader-source-receipt. Equality of metadata is weaker than equality of loaded code bytes. A loaded-chunk digest was not obtained; source chunk names can be supplied at load time and globals can be replaced. Native machine-code identity and actual syscall transition remain unresolved.

## Source citation correction

The preceding LOADER_SOURCE_FINDINGS.md cited syscall.lua:75–89 for the resolve loop and :34–72 for collection/platform logic. The received file actually defines syscall.resolve at **67–81**; use that exact range. Its platform-selection and wrapper logic must be referenced within the actual functions in the received syscall.lua, rather than promoting the earlier approximate ranges to exact citations. This addendum preserves that earlier report unchanged.

The current metadata provides no information about Sony syscall 624's internal meaning, handler identity, syscall-table location/stride or kernel implementation. It cannot transfer the 13.60 write-lock-counter interpretation to 14.10. Historical acquisition and firmware authenticity remain unresolved.

## Next useful analysis

Follow the received source's native-call registration/dependency references offline and compare them with any already-retained matching game/module artifact. Do not repeat baseline calls merely to confirm stable 0xD31. A source-level explanation is now available; machine-code/build identity is the remaining independent boundary. No expanded live probe campaign follows automatically from this successful metadata check.

Repository unchanged at 7e25a1174b5a3086b7e90d860d85f8ab7bad7a70, clean. This session's new outputs are separate. No push was performed.
