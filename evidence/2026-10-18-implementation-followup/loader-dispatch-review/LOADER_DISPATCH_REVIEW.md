# Loader dispatch: focused evidence review

2026-10-18. Repository revision `7e25a1174b5a3086b7e90d860d85f8ab7bad7a70`. Offline read-only continuation of the selector-624 field analysis.

## Result

The Lua construction and observed return representation are recoverable; the actual native dispatch function is not identified in the inspected existing records. A numeric Lua selector is an annotation until the callable's implementation establishes how it is consumed. No replacement native-call model is invented.

## Recovered links

| Layer | Exact source pointer | Established / limitation |
|---|---|---|
| Transport | `tools/send_probe.py:30–32`; `tools/README.md:13` | Sender uses little-endian uint64 source length followed by Lua source. This establishes framing, not kernel dispatch. |
| Lua constructor | `probes/phase12_kernel_analysis/51b_accessible_syscall_deep.lua:20–25,207–212` | Copies entries from syscall.pipe into a table, assigns syscall_no=624, attaches the base metatable and calls the table without explicit arguments. The research constructor is not the loader's internal implementation. |
| Latest observed wrapper | `evidence/2026-10-18-selector624/wrapper-followup/baseline.lua:3–24`, `response.raw:3–17` | Base/metatable are tables; __call has Lua type function; table field is 624 before each call; returned value is a table with numeric h/l; three decoded values are 0xD31. Does not identify C versus Lua implementation, native instruction, prototype, errno, signedness, side effects or kernel handler. |
| Historical metatable | `results/46b_loader_dispatch_20261016_194751.txt:148–158` | Logs a function's printed identity and declared Lua type. A printed function address is not machine-code disassembly or an extracted C entry point. No executable-byte capture or ownership/build mapping is present here. |
| Historical stopping point | Same raw file `:160–163` | Starts pipe-object memory-reading stage and ends after its heading. Later module attribution and other stages in the current probe source are unobserved. No failure cause is assigned. |
| Mutation counterevidence | `results/45c_execution_reality_check_20261016_192713.txt:17–41,192–207`; current evidence audit and Finding 56 | Selected calls returned despite tested fn_addr/chain mutations, with restoration/completion recorded. This weakens dependency on those particular fields in those calls; it neither identifies the full dispatch nor establishes that all metadata is ignored. Log line 21's stronger interpretation is author commentary, not a recovered implementation. No mutation was repeated. |
| Claimed source attribution | `docs/USERLAND_ENTRY.md:86,94–113`; `README.md:244` | Names shahrilnet/remote_lua_loader and console paths /savedata0/main.lua, syscall.lua, misc.lua, etc. No source commit, execution-time source hash, matching native binary digest or session-bound build receipt is supplied by those citations. An upstream project name alone cannot identify deployed bytes. |

Git blob identities, as observed without rehashing original files: `docs/USERLAND_ENTRY.md` = `d5db41d5e24d0398e8b77255918484b0ceba490e`; historical 45c raw log = `0ad0bde6bff2ffbfa450bf76788a84467585b2e8`; historical 46b raw log = `6eaa1180191a0da3e76ccf458c89814b30c93ff0`. Latest session script/sender/raw SHA-256 are inherited from their SESSION.json and FILE_HASHES.json; not recomputed here.

## Concrete lead checks and limit

Read the cited repository docs, actual probe source and raw logs, existing provenance/correction audits, and latest wrapper evidence. Exact loader filenames were checked in the current repository and named sibling `F:/PS5-14.10-Research-backups`; no retained syscall.lua/main.lua/rop.lua or loader binary matching those filenames was identified. The read-only existing evidence server's `/home/marwanserver/ps5-workspace/repos` directory lists only PS5-14.10-Research and PS5-V13.60-Research, not an independently named loader checkout. No all-drive search, public fetch, target-file read, memory extraction or console interaction occurred. This is a bounded absence result, not proof that a private archive cannot exist.

The `/savedata0/` paths are **console runtime paths**, not accessible local archive paths. They were not opened. A historical traceback is evidence of a reported path/function/line, not retained source contents or proof today's matching upstream file executed.

## Unsupported interpretations to keep separate

`docs/USERLAND_ENTRY.md:90,129` calls the construction an unfiltered bypass and assigns filtering to Lua rather than the kernel. Existing observations do not recover that policy boundary. The native callable and kernel policy remain distinct unknowns.

The same document's `:133–138` claims every TCP connection spawns a fresh process and no state persists. Session address/ID variation is not enough to prove universal process creation or no persistent state. Neither this claim nor shared addresses should be used to explain selector624 changes without attributable session evidence. This report preserves the original documentation unchanged.

## What would resolve the native layer

Needed: an existing deployed loader/save-source archive containing syscall.lua and its dependencies, with its revision/current hash distinguished from historical execution identity; plus the corresponding game/module/native callable artifact or source and build identity. The critical evidence is the callable's registration and implementation path: which Lua field is read, argument marshaling/defaults, native dispatch target, and return/error conversion. Merely naming the upstream repository, reading mutable table fields or repeating 624 does not establish these.

Source can be useful before execution provenance is complete: it can explain a candidate implementation, explicitly labeled unmatched. It becomes session-specific evidence only with a defensible deployment/source/binary-to-session link. No new memory-read or function-pointer mutation experiment is proposed.

## Next useful work

Recover an already-existing loader/save archive from its actual deployment workstation/archive if supplied by a concrete lead. This focused search has exhausted its identified local leads. Continue the retained 13.60 implementation research independently; do not substitute a guessed native-dispatch story or allocation experiment for the missing loader artifact. Firmware authenticity, historical acquisition and 14.10 sysent applicability remain unresolved. No new exploitability or kernel-access claim follows.
