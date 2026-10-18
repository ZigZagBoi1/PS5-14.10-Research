# deep_669.bin — code analysis

Input: `16384` bytes; SHA-256 `30a89c6bcbe0dc50989fa6b3ee2eba7a195b05ee8bb4c99b4cca56a0ecc160f6`. Contextual start RVA: `0x3b2060`.

## Evidence and address conventions

This is static analysis of a raw little-endian x86-64 kernel memory window. It is not an executable image with symbols, sections, relocation records or type information. `+0x...` below always means a byte offset in this particular file. Add the stated kernel RVA to obtain an image RVA; add the contextual kernel base `0xffffffff8a9c0000` to obtain a contextual runtime address. Those bases come from sibling `handler_map.json` and `RE_CONTEXT.md`, rather than from a raw-file header. External calls that appear as large negative numbers in the original offset-based disassembly are relative destinations outside this window, not corrupt instructions by themselves.

Assembly evidence is in the existing `.asm` and new `.rea.asm`/`.rea.offsets.asm`; reconstructed C is in `.rea.c` and its function inventory in `.rea.functions.json`. C is decompiler pseudocode, not recovered original source. Function labels below are analytical names unless an embedded diagnostic string supports them. Instruction bytes and control flow take priority over guessed prototypes.

For name corroboration only, RIP-relative string references were also resolved against the already present sibling `kernel_text.bin` (RVA 0) and `kernel_data.bin` (RVA `0x1000000`). No target instructions were executed. Missing out-of-window code and data remain unresolved. The supplied kernel capture can contain failed reads; this analysis cannot prove those captures are authoritative firmware originals.

## Main conclusion

The entry is an asynchronous read/write request submission interface. The diagnostic name `_aio_submit_cmd` corroborates the worker at `+0x20`; `setup_rwreqs` and `AIO req hd lock` corroborate descriptor-copy and request-group initialization. This window also contains the complete neighboring `__aio_init` handler, debugging/query interfaces, queue management, an AIO worker, and process lifecycle callbacks. It is not one 16 KiB syscall body.

The whole 12 KiB `deep_670.bin` is byte-identical to this file's interval `[0x870,0x3870)`. The shared code has the same behavior; its file offsets differ by `0x870`. In particular, this file contains more of the worker's end than 670 does.

## Submission entry and ABI

The wrapper at `+0x0..+0x1c` unpacks five syscall slots and tail-jumps to `+0x20`:

| Slot in uap | Width actually read | Meaning inferred from use |
|---|---|---|
| `+0x00` | 32 | command and flags |
| `+0x08` | 64 | user array of request descriptors |
| `+0x10` | 32 | descriptor count |
| `+0x18` | 32 | queue class/priority, accepted 1–3 |
| `+0x20` | 64 | user output pointer for generated identifiers |

The worker's effective signature is `int submit(td, cmd, user_reqs, count, class, user_ids)`. It gets a process-like pointer from `td+0x8`, and that object's handle table from `+0xc48`. The syscall return is an error code in EAX; generated identifiers go through the user-output pointer, rather than an observed write to `td_retval`.

1. `+0x74..+0xbd` and `+0x22e..+0x25d` select one of several AIO contexts using two external process/category helpers, a category bound of `0xffffff`, a category-family mask `0xff0000`, and two global identity comparisons. Context addresses include image RVAs `0x34cf320`, `0x34d0418`, `0x34cfe70`, and fallback `0x34cf8c8`. This is context selection; it is not enough to label the helper a general superuser check.
2. `+0xbd..+0xd2` requires `(cmd & 0xfff)` to be 1 or 2. Later worker behavior and embedded `aio_read`/`aio_write` diagnostics support read/write operation classes. `+0x2ef` separately tests flag `0x1000`. The visible code does not reject every other high command bit.
3. If `ctx+0x4a0 != 1`, it calls `+0x13b0` with default-initialization selector 1; nonzero status is logged and returned (`+0xd8..+0x111`).
4. `+0x11e..+0x145` accepts counts **1 through 128 inclusive**. The unsigned subtract/compare idiom rejects zero, negative 32-bit values, and values over 128. `+0x14a..+0x153` accepts queue class **1 through 3**. Invalid arguments return 22.
5. `+0x165` reserves a process-table identifier/slot through an external helper. A result of -1 maps to 35 at `+0x2bc`. Then `+0x179..+0x194` allocates `40 * count` bytes and `+0x1b3..+0x1bc` copies that many bytes from the supplied user array through a copyin-shaped routine. Failure releases the temporary allocation and reserved slot (`+0x1c9..+0x22c`). With the established count bound the descriptor allocation is 40–5120 bytes.
6. With flag `0x1000` clear, `+0x2f9..+0x34b` creates one 0x58-byte shared completion/request header containing the total count. With it set, `+0x34d..+0x3b1` creates `count` independent 0x58-byte headers. It initializes a synchronization object at header `+0x20` for each.
7. `+0x3b5..+0x569` builds a 0x30-byte AIO object, an array of `count` queue-entry pointers, a 0x30-byte saved execution context (current thread/process-related values and held credential-like reference), and one 0x58-byte queue entry per descriptor. Each queue entry points at its 0x28-byte descriptor, saved context and shared/per-item header. The AIO object records the queue class, selected AIO context, copied descriptor block and pointer array.
8. `+0x569..+0x587` publishes the object through a typed handle helper with type tag **0x160**, then releases the reservation reference. Without `0x1000`, it copies out one 32-bit identifier. With it, `+0x5a4..+0x5fa` creates `count` identifiers `base_id | (index << 16)` and copies out `4 * count` bytes. The temporary stack buffer is bounded by the earlier count check (maximum 512 payload bytes, plus alignment).
9. `+0x61b..+0x636` passes the object to `+0x1a30`, which resolves file-like handles and queues requests. On failure, `+0x65e..+0x7e7` removes the typed handle, releases held references, destroys per-header synchronization objects and frees entries, headers, copied descriptors and object storage. A successful identifier copyout occurs **before** queue setup finishes, so a later error can leave a user-visible identifier that no longer names a live object.
10. `+0x7e9..+0x82f` locks a global scheduling structure and signals one available worker handle from context offsets `+0x4b0` / `+0x528`; optional tracing calls depend on an external enable predicate. It returns 0. Stack-guard mismatch reaches the external failure routine at `+0x85c` followed by UD2.

## Structures recoverable from use

Names are provisional; offsets are relative to the corresponding object, not a complete ABI specification.

| Structure | Observed fields |
|---|---|
| User request, stride 0x28 | `+0x0` signed I/O offset, `+0x8` byte count, `+0x10` data pointer, `+0x18` optional result pointer, `+0x20` 32-bit file descriptor; tail/padding not fully typed |
| Queue entry, allocation 0x58 | `+0` operation, `+4` scheduling sequence, `+8` ordering/offset key, `+0x10` descriptor pointer, `+0x18` saved context, `+0x20` completion header, `+0x28` split-request context, `+0x30` result/error, `+0x38` state, `+0x40` referenced file object, `+0x48/+0x50` list links |
| AIO object, allocation 0x30 | `+0/+2` 16-bit group/lifetime counts, `+4` queue class, `+8` base identifier, `+0x10` completion-header storage, `+0x18` AIO context, `+0x20` copied descriptors, `+0x28` queue-entry pointer array |
| AIO context | queue heads in the first 0xc0 bytes; locks around `+0xd8`; policy limits around `+0x174..+0x1bc`; live/sequence counters around `+0x1c0/+0x1d0`; initialization state `+0x4a0`; worker records `+0x4b0/+0x528` |

## Function-by-function inventory

Ranges terminate before the next aligned entry; padding is not function behavior. The final entry is incomplete.

| Entry offset | Role and direct evidence |
|---|---|
| `0x0` | Five-slot syscall unpacking wrapper, tail-call to `0x20`. |
| `0x20` | `_aio_submit_cmd` submission worker, detailed above; normal return `0x2af`, failure tail at `0x85c`. |
| `0x870` | `__aio_init`; identical to 670 entry. Validates two reserved arguments, optionally copies 0x3c bytes of policy, writes three queue-policy groups and invokes initialization. See `deep_670.rea.analysis.md` for exact checks and partial-update behavior. |
| `0xcf0` | `_get_aio_debug_submit_info`: holds a specified process through external lookup mode 0x15; validates nonnull output pointers and positive capacity against process-table limit `+0x228`; enumerates typed 0x160 objects; emits 16-byte records `{composite_id,state,class,operation}` and total count. Copies record array only if capacity covers total; count is copied first. Drops the process hold under its lock. |
| `0x1030` | `_get_aio_debug_request_info`: similar process lookup, encoded identifier high half must be below 128; searches object and entry, then emits 24-byte request-detail records including descriptor FD, length and offset. Reports total count and copies array only when capacity suffices. Its eligibility/authorization depends partly on the external process-lookup helper. |
| `0x13b0` | AIO context initialization. State `+0x4a0`: 0 uninitialized, -1 initialization in progress, +1 ready. Uses locks/condition variable; creates two worker records, installs process suspend/resume/exit event handlers once, builds a64-entry free-list-like pool, optionally sets default limits (32 and 0x100000 sizes). Existing ready fallback context can return success; other ready contexts return 16. |
| `0x19e0` | Instrumented copyout wrapper; preserves source/destination/length then tail-calls external copyout-shaped routine. |
| `0x1a30` | Enqueue setup for copied requests. For operation 1/2 resolves descriptor FD through file-reference helpers with capability-like constants `0x400000000000080`, `0x20000000000000d/0xe`. SDK/version fields `+0x5d4/+0x5d8` choose helper variants. It records per-entry resolution errors rather than treating every bad FD as an immediate whole-call error. A file operation callback with code `0x80089169` can provide an ordering key. It inserts into bounded ordered/overflow queues, increments counters and sets state 1. Unexpected operation returns 22. |
| `0x1e30` | `free_queue_entry`: diagnoses remaining split-info, decrements referenced file's atomic refcount and invokes its final-release routine if needed, then frees entry storage. |
| `0x1eb0` | Fixed-size (0x3c) instrumented copyin wrapper used by policy initialization. |
| `0x1ef0` | Error-related request retry helper: only selected error states (5 / 0x60, and encoded 0x80020005 / 0x80020060) and nonempty ID arrays qualify. Decodes low16 object ID/high16 item index, bounds index to 127, reacquires objects/files, invokes an external recovery-related operation, and drops references. Exact recovery operation is unresolved. |
| `0x2130` | Remove/cancel one queue entry from the active or overflow list under its class lock; checks expected entry state, sets state 4, decrements queued count, adjusts accounting. Returns 3 when no matching entry/state is found. Includes linked-list integrity failure paths. |
| `0x23e0` | Ordered queue insertion helper, using descriptor ordering key, previous context key, sequence-age limit and queue scan limit; falls back to append. Maintains intrusive back-links and checks corruption. |
| `0x2560` | Typed-object destructor/request cancellation (`aior_cancel_entry` / `aioobj_free_req` diagnostics). Acts only for type 0x160; walks entries, cancels queued/in-progress work, handles split-info lifetime, releases file/credential references, destroys synchronization and frees backing arrays/object when final group references disappear. |
| `0x2a20` | `aio_worker_entry2`, large complete worker ending before `0x3cd0`; chooses queued work by class, splits requests according to policy, manages queue states and counters, saves/swaps/restores process/thread/credential-like context, dispatches read/write file callbacks, writes 16-byte result records through copyout-shaped helper, handles errors and completion wakeups, and participates in suspend/resume event registrations. See worker discussion below. |
| `0x3cd0` | Process callback: allocates a node from prebuilt global free list, stores the process pointer, pushes it onto pending-process list under scheduling lock. No free-list null test is visible here; pool invariants belong to external lifecycle context. |
| `0x3d30` | Process callback: selects process's AIO context and invokes an external operation with flag 0x80 on matching worker records. Exact suspend-phase callback association is not recoverable from this window alone. |
| `0x3e30` | Process callback: removes process from pending list, returns node to free list and signals each present context worker. |
| `0x3fc0` | Next process-context callback prologue and initial context lookup only; file ends at `0x4000` during an instruction, so later behavior is unavailable. |

## Worker behavior and confidence

The read/write interpretation is strong: `+0x32a6` onward examines request operation 1/2, reads request length/offset/buffer, checks length at most `0x7fffffff`, builds a one-element uio/iovec-like object, invokes two different file callbacks and records transferred bytes. Negative offsets have a file-type exception (`object+0x18`, subtype `+0x1d4 == 4`) with `aio_read`/`aio_write` diagnostics at `+0x35b6/+0x35cb`. The worker saves execution-related fields at `+0x31d5..+0x3225` and restores them near `+0x384f`; credential-like objects were held on submission and released by destruction. This is consistent with asynchronous I/O running on behalf of the submitting process, rather than independent proof of a privilege bypass.

Entry state values are supported by writes: 1 queued, 2 issued/in progress, 3 completed, 4 cancelled/removed. Exact public API enum names are unknown. Split requests track bytes and outstanding work with atomic updates; completion-copyout return handling should be assessed from assembly rather than assuming all user result writes succeed.

## Limitations and review findings

Observed protections include bounded count and queue class, typed handle lookup, file reference acquisition, reference-counted destruction, linked-list integrity diagnostics, locking/condition-variable operations, and stack guards. External helper names and authorization semantics are unresolved. Absence of a direct privilege predicate in the submission worker does not show that ordinary AIO requires privilege or that access checks are absent from file lookup.

No arbitrary-memory primitive, exploit, or runtime failure is established by this static window. The meaningful behavior findings are the separate publication/copyout/queue stages, per-request error recording, shared-versus-individual completion grouping, and the partially captured lifecycle tail. Runtime race-freedom, locking contracts, every error-unwind invariant and file-operation semantics require out-of-window implementations and dynamic evidence. The supplied raw bytes cannot recover the original comments, symbols, build types or complete source tree.

## REA evidence ledger and decompiler reconciliation

The main pseudocode was compared with assembly after recovery. The provider reports Ghidra-specific pseudocode, unresolved computed/indirect edges and absent external bodies; generated names such as `sys_670` and `sub_003b3410` are seeds/automatic labels, while textual names such as `__aio_init` are embedded diagnostic strings. No exported symbol table exists in these raw files. Some valid tail jumps to unmapped external routines are rendered as “bad instruction data” or truncated flow in pseudocode; the source JMP in `.rea.asm` remains the appropriate evidence. True file-boundary truncation is separately identified above.

Each row maps a local entry to its retained `analyze_function` dossier ID in `.rea.dossiers.jsonl` / `.rea.evidence.json`. Function body ranges and tool limitations are retained in `.rea.functions.json`; `.rea.referenced_strings.json` records exact string-reference sites and contextual string addresses.

| File offset | REA label | Evidence ID |
|---|---|---|
| `0x0` | `sys_669` | `ev_1fa2a9c2ed7f12ed1dc7101ca89032965da8099854d4b3b6d25d717d76d0b362` |
| `0x20` | `sub_003b2080` | `ev_579b0c99e50ec99f774c8cde87ce62f98a5d9574e866bb20b08c30f4d589aa3b` |
| `0x870` | `sys_670` | `ev_636d07ac5fda5e39904811cdeeefeb3acb964ebc68ce3119d15f1f298ee74918` |
| `0xcf0` | `sub_003b2d50` | `ev_9cc158ff8a0834c1e36c01b0f5c71c17db098e8c9b66e43bf365d0c930fb5b4a` |
| `0x1030` | `sub_003b3090` | `ev_cb996cd14eb6ae55e142fa9292b62f1571b1b2f2aeacd539a9aba778145d718e` |
| `0x13b0` | `sub_003b3410` | `ev_51d2e9401af7bee42f1552a611145b212384ab029f151898ea295e4b8eca8e53` |
| `0x19e0` | `sub_003b3a40` | `ev_6f49814be2475d18820f07347d9dfa16905bd09f1c6db25ad8de67a609471d41` |
| `0x1a30` | `sub_003b3a90` | `ev_91ae7b21faa25fca9cf3e91eea3920d2814fb95cc223f9a4a4e916de6b32edc1` |
| `0x1e30` | `sub_003b3e90` | `ev_b58cab6c08536de31eeb275844bb94ea907bc6576d6f72a1da6fdcf594f34484` |
| `0x1eb0` | `sub_003b3f10` | `ev_1aebc4bf54cbce62189e759fcc1a66738f69722cd394287159f8128970e4ea1f` |
| `0x1ef0` | `sub_003b3f50` | `ev_447ec428dd72654fcfb148c8beed9820a8078556512ae027271d8d199d2dbd3d` |
| `0x2130` | `sub_003b4190` | `ev_c87329424604f02d21296ac71f2e27d336042b53a1ca8494e3ebefb19661a13c` |
| `0x23e0` | `sub_003b4440` | `ev_7edf70aada842a4f6e12dba02b159a25a8cff5c3229d77a173341d38d8c1ceab` |
| `0x2560` | `sub_003b45c0` | `ev_b441326f3f58365712b836286be3c54475bb4be12b662e54718293629e94ac82` |
| `0x2a20` | `sub_003b4a80` | `ev_35f5309c076369467af9886e65f374abdaa0482c28b1385dd9e758338283e7c7` |
| `0x3cd0` | `sub_003b5d30` | `ev_3ef11e6c5bade0c9cd744cb7800c3f7af816a664683e72c219cda97030c093c6` |
| `0x3d30` | `sub_003b5d90` | `ev_f86bd286dcd14ea4bdd291c32867b97f885624a6c0644eed1b70fb5028f2ec22` |
| `0x3e30` | `sub_003b5e90` | `ev_5b63946abdda904c02eba6a2e9ed0ae01aae2c1dd9dc3090099c5d1d0b3c4914` |
| `0x3fc0` | `sub_003b6020` | `ev_0e48701ede19d5178b5b45ff62a783f7531c25519c34880630ec77830173b4a6` |
