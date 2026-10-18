# deep_670.bin — code analysis

Input: `12288` bytes; SHA-256 `ecf646d679e85e42f524f5e475185754b63df65bf3dc1bc3430cac6f553e0123`. Contextual start RVA: `0x3b28d0`.

## Evidence and address conventions

This is static analysis of a raw little-endian x86-64 kernel memory window. It is not an executable image with symbols, sections, relocation records or type information. `+0x...` below always means a byte offset in this particular file. Add the stated kernel RVA to obtain an image RVA; add the contextual kernel base `0xffffffff8a9c0000` to obtain a contextual runtime address. Those bases come from sibling `handler_map.json` and `RE_CONTEXT.md`, rather than from a raw-file header. External calls that appear as large negative numbers in the original offset-based disassembly are relative destinations outside this window, not corrupt instructions by themselves.

Assembly evidence is in the existing `.asm` and new `.rea.asm`/`.rea.offsets.asm`; reconstructed C is in `.rea.c` and its function inventory in `.rea.functions.json`. C is decompiler pseudocode, not recovered original source. Function labels below are analytical names unless an embedded diagnostic string supports them. Instruction bytes and control flow take priority over guessed prototypes.

For name corroboration only, RIP-relative string references were also resolved against the already present sibling `kernel_text.bin` (RVA 0) and `kernel_data.bin` (RVA `0x1000000`). No target instructions were executed. Missing out-of-window code and data remain unresolved. The supplied kernel capture can contain failed reads; this analysis cannot prove those captures are authoritative firmware originals.

## Main conclusion

The entry implements AIO policy initialization/configuration. The embedded diagnostic `__aio_init` names the main handler. The rest of this 12 KiB window contains AIO debug queries, initialization, request enqueue/removal/destruction helpers, and the beginning of `aio_worker_entry2`. These are independent neighboring routines.

This file is byte-for-byte equal to `deep_669.bin[0x870:0x3870]`. To compare an offset here with that file, add `0x870`. The complete worker and some lifecycle tails are available only in 669; this file's own worker is truncated.

## Main handler: arguments and context selection

The entry reads four syscall slots at `+0x27..+0x31`:

| uap offset | Width read | Interpretation |
|---|---|---|
| `0x0` | 64 | optional pointer to 0x3c-byte configuration |
| `0x8` | 32 | configuration length; must equal0x3c only when configuration is applied |
| `0x10` | 64 | reserved argument, required zero |
| `0x18` | 32 | reserved argument, required zero |

Two external helpers inspect the process at `td+0x8`. Category classification uses the bounds `0xffff` and `0xffffff`, family mask `0xff0000`, family value `0x10000`, two global identities and a global selector (`+0x3b..+0x93`, `+0x17c..+0x20b`). Four context choices match submission handler 669. Calling the helper on the process is not evidence of a superuser check.

The reserved arguments are checked first at `+0x93..+0xcf`; either nonzero value returns 22, with a diagnostic. The handler then takes a global configuration lock (`+0x100..+0x112`).

The configuration path is entered only if all of the following hold: recognized/eligible category classification, nonnull config pointer, and `ctx+0x4a0 == 0` (`+0x117..+0x134`). Otherwise it releases that lock and calls context initialization helper `+0xb40` with default selector 1. A null pointer therefore does **not** universally imply EFAULT. A nonnull pointer and arbitrary size need not be consumed on an already-initialized or fallback path. The helper determines eventual success/16/etc.

On the configuration path, length must be **60 bytes** (`+0x1bb`), and `+0x1c1..+0x1cf` copies exactly 60 bytes through helper `+0x1640`. Copy errors are logged and returned after unlocking. The helper adds copyin instrumentation and tail-calls external code; its correctness depends on that external routine.

## Configuration layout and validation

The 60-byte structure consists of three consecutive records, each five 32-bit values (20 bytes):

```c
struct policy_group_candidate {
    uint32_t scan_or_active_limit;  // 0..128
    uint32_t age_or_reorder_limit;  // 0..128
    uint32_t split_mode;            // 0 or 1
    uint32_t issue_chunk_size;      // 1..0x1000000 if mode==1
    uint32_t other_chunk_size;      // 1..0x1000000 if mode==1
};
// policy_group_candidate groups[3];
```

Names are inferred from downstream queue/worker uses, while byte offsets and limits are direct observations. In mode 0 the two size destinations are explicitly set to zero; supplied size words are ignored. In mode 1 both sizes must be **1 through 16,777,216 inclusive**. The arithmetic comparisons at `+0x2a9..+0x2b5`, `+0x2d7..+0x2e5` and corresponding later groups implement this range using unsigned wraparound; negative 32-bit patterns do not qualify. Mode values beyond1 return 22.

For zero-based group `i`, assignments are:

| Input record offset | Context destination |
|---|---|
| `20*i +0` | `ctx+0x174+4*i` |
| `20*i +4` | `ctx+0x184+4*i` |
| `20*i +8` | `ctx+0x1a4+4*i` |
| `20*i +12` | `ctx+0x1b4+4*i` |
| `20*i +16` | `ctx+0x194+4*i` |

The first group is validated at `+0x249..+0x304` and written at `+0x304..+0x323`. The second is validated afterward at `+0x32a..+0x384` and written at `+0x384..+0x3a3`. The third follows at `+0x3aa..+0x420`.

**Observed partial-update behavior:** invalid group 1 or group 2 can return 22 after earlier valid groups have already been written. The function does not stage all 15 fields and commit them atomically as a unit. Its global lock serializes these visible writes, but there is no rollback in the validation error paths. This is a state-management finding, not proof of an exploitable condition. Context initialization remains uncompleted along those early validation paths.

After all groups are written, an optional tracing hook is invoked (`+0x427..+0x437`), the initialization selector becomes0 (`+0x43c`), and the main path either simply unlocks an already-ready context or calls `+0xb40` without overwriting the custom policy. Ordinary return is EAX; stack-guard mismatch calls failure routine at `+0x478` and UD2.

## Initialization helper at +0xb40

`ctx+0x4a0` is a three-state initialization marker:0 uninitialized, -1 initialization in progress,1 ready. A global lock and condition-variable wait loop protect it (`+0xb97..+0xc30`). Already-ready ordinary contexts produce16; the fallback/global context is a special success case (`+0xbb7..+0xbc3`). Wait errors and worker creation errors propagate. The exact lock API names are unresolved, but lock/wait/unlock call patterns are visible.

When initializing, it sets -1 (`+0xc63`), creates four queue locks, initializes several intrusive queue heads and counters, releases the initial lock, and creates two worker records at context `+0x4b0` and `+0x528` (`+0xe12..+0xe9f`). String references identify `SceAIO` and `SceFsstAIO`. It registers process suspend/resume/exit hooks once and builds a64-node pool (`+0xf21..+0x1086`). On success it sets state 1 at `+0x10af`, optionally stores the process identity and installs default policy only if the caller's selector is nonzero (`+0x10ce..+0x1140`): two first groups use mode 1, sizes 0x100000 and limits 32; third group uses mode 0, sizes 0x100000 in stored defaults, limits 32. That third default mode/size combination differs from explicit mode 0 configuration, whose size fields become zero.

## Complete function inventory in this file

| Entry | Role |
|---|---|
| `0x0` | `__aio_init` syscall handler; above. |
| `0x480` | `_get_aio_debug_submit_info`: process lookup mode 0x15; nonnull user array/count pointers, positive capacity <=process table bound; enumerates typed0x160 objects and emits 16-byte `{id,state,class,operation}` records. Copies count first; array only if total<=capacity. Object IDs combine base low16 bits and entry index in high16 bits. Errors include14 for null pointers,22 for invalid capacity,3 for absent process/table, plus helper/copyout errors. Process hold is dropped under its lock. |
| `0x7c0` | `_get_aio_debug_request_info`: similar held process lookup; capacity bound and index-high-half<128 check. Finds matching typed object and emits 24-byte details including FD, nbytes and I/O offset; count is returned separately. Exact external process authorization remains unresolved. |
| `0xb40` | Context initialize/default setup; above. |
| `0x1170` | Instrumented variable-length copyout wrapper. |
| `0x11c0` | Resolve file references for request operation 1/2, obtain optional ordering key through callback 0x80089169, place into active/overflow queues, update live counters and set queued state 1. SDK fields compare against 0x11090000 and 0x08000000 to choose file-lookup variants. Uses file capability-like constants 0x400000000000080 and 0x20000000000000d/0xe. Resolution failures are stored per entry; unexpected operation returns 22. |
| `0x15c0` | `free_queue_entry`: diagnoses leftover split context, releases file ref using atomic decrement, frees queue entry. |
| `0x1640` | Instrumented fixed0x3c-byte copyin wrapper for main configuration. |
| `0x1680` | Retry/recovery helper for selected errors5/0x60; decodes object/index IDs, validates index <=127, reacquires file, invokes external recovery-related operation and releases references. Exact recovery semantics remain unknown. |
| `0x18c0` | Cancel/remove queue entry from active/overflow intrusive list under class lock, check expected state, set state 4 and adjust counters; returns3 if not found. Includes integrity-check trap paths. |
| `0x1b70` | Ordered insertion using offset/order key plus per-class scan and age policy; maintains back-links and appends if no eligible insertion point. |
| `0x1cf0` | Type0x160 object/request destructor. Cancels queued/in-progress entries, handles split-request context ownership, releases file and saved credential references, destroys completion locks and frees arrays/object on final group release. |
| `0x21b0` | `aio_worker_entry2` begins; complex worker for read/write dispatch, queue selection and splitting, saved submitter context, result copyout and completion accounting. **Incomplete in this file**. |

## Worker boundary and limitations

The window ends at offset 0x3000 in the middle of the worker. Several control-flow destinations (for example `+0x3306`, `+0x340d`) lie outside it. The final `rex.W`/byte-like disassembly is a truncated instruction, not a meaningful independent opcode block. `deep_669.bin` includes the continuation through that worker's return/failure paths; use its offsets plus the overlap relation when inspecting shared semantics.

The raw file contains no symbol table or local strings. Names above use already-present contextual data and code references. Default FreeBSD names for error 22/14/16/3 and structures are plausible contextual interpretations, while their integer values are directly visible. Complete access-control semantics depend on external process/file/handle helpers; no privilege bypass, memory-corruption bug or runnable exploit is established. Recovering every type, out-of-window dependency and original source is impossible from this window alone.

## REA evidence ledger and decompiler reconciliation

The main pseudocode was compared with assembly after recovery. The provider reports Ghidra-specific pseudocode, unresolved computed/indirect edges and absent external bodies; generated names such as `sys_670` and `sub_003b3410` are seeds/automatic labels, while textual names such as `__aio_init` are embedded diagnostic strings. No exported symbol table exists in these raw files. Some valid tail jumps to unmapped external routines are rendered as “bad instruction data” or truncated flow in pseudocode; the source JMP in `.rea.asm` remains the appropriate evidence. True file-boundary truncation is separately identified above.

Each row maps a local entry to its retained `analyze_function` dossier ID in `.rea.dossiers.jsonl` / `.rea.evidence.json`. Function body ranges and tool limitations are retained in `.rea.functions.json`; `.rea.referenced_strings.json` records exact string-reference sites and contextual string addresses.

| File offset | REA label | Evidence ID |
|---|---|---|
| `0x0` | `sys_670` | `ev_890f4b6e7354bdfebc976f954a51f8d56fa5e32d4c3f935b4817e0d7c096d8b6` |
| `0x480` | `sub_003b2d50` | `ev_8a497eaf4907acb28469a8d43948a6fc7579b86b615409ecc9f96bcc70cb4438` |
| `0x7c0` | `sub_003b3090` | `ev_e2388affa5d31d5f1ba6a51280cd446c04078bd4b55932a22c1451d224ad3ae9` |
| `0xb40` | `sub_003b3410` | `ev_09fb36886a39ae787a7e3e79a850d8b3c9b8e1268fee81b1c9f84f76d75aa197` |
| `0x1170` | `sub_003b3a40` | `ev_8dd39206857e6e1b2e2e8dedd8c0b84ea23d2ffdd9befb2e70159c9137ad897e` |
| `0x11c0` | `sub_003b3a90` | `ev_699961f3d549250fe183c95e3c8a76c6c311f8ed972be6900aa34a4dc8c68b26` |
| `0x15c0` | `sub_003b3e90` | `ev_84a3bfb8e256918fb7e0e9b7e5420a7152fa85303ae008e2a859ef737c9155ba` |
| `0x1640` | `sub_003b3f10` | `ev_3f91f51bba7d284e379d531933c85a3f54e5c8cba319a5fefdeefcd29fde97ad` |
| `0x1680` | `sub_003b3f50` | `ev_83b7732681148924ba7b983e3c21b88b8fbbe66a6498d5a1576236fef01d1876` |
| `0x18c0` | `sub_003b4190` | `ev_5f682a18c207c4fc58082569055d3fa9e9a53b95ffc4d54b710fbb3e0ad0fc2c` |
| `0x1b70` | `sub_003b4440` | `ev_e33d17b0153a0a0972d997ce568d535b426485c1d3de2064c94d5cec17b76fac` |
| `0x1cf0` | `sub_003b45c0` | `ev_c4171eeec2fe3fcf9ae935a9751d6474adda36bba741da904ac8e260a4a63476` |
| `0x21b0` | `sub_003b4a80` | `ev_a0c2d4b84065d3522fb1a6b294370dc9d45d0e16d2d9fe441ee4ab98775cc6ec` |

## Additional recovery from the other supplied window

`deep_670.rea.overlap_recovery.c` supplies the complete worker at RVA `0x3b4a80`, using its independently observed body from `deep_669.bin` (REA evidence `ev_35f5309c076369467af9886e65f374abdaa0482c28b1385dd9e758338283e7c7`). The equality `deep_670.bin == deep_669.bin[0x870:0x3870]` was verified byte for byte. This separate file explicitly extends beyond the 670 carrier using bytes in the 669 carrier; the primary 670 decompilation continues to show its true input boundary. Body ranges and full assembly for this recovered worker are in `.rea.overlap_recovery.json`.

## Supplemental recovery audit

A final coverage pass recovered 1 additional synthetic block entries in `deep_670.rea.extra_fragments.c`. These are blocks omitted from primary function pseudocode (including disconnected dispatch arms or paths beyond unresolved transfers). They are **not additional original ABI functions**: inherited register values, the parent stack frame, exact switch edges and decompiler-imposed block boundaries remain uncertain. The full assembly remains the reference. The selected offsets are in `deep_670.rea.extra_fragments.selection.json`, with complete individual records in `.dossiers.jsonl.gz` and the canonical bundle in `.evidence.json.gz`.

| Synthetic entry offset | REA evidence ID |
|---|---|
| `0x2330` | `ev_b9984475ed6d81b46ba0f40e0ab0f757b66747d8cd3452a74e5fed2dda3dbf69` |
