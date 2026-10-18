# deep_558.bin — code analysis

## Scope and evidence

This 12,288-byte raw x86-64 window begins at syscall-558's real target, kernel RVA `0xac73c0` in the adjacent `handler_map.json`. The map gives two argument slots. File offsets are used below; add `0xac73c0` for kernel RVA. Runtime base `0xffffffff8a9c0000` comes from `RE_CONTEXT.md` and is contextual metadata.

The syscall itself is only +0x0000–0x00a7. The remainder includes high-resolution timers, HID/mouse processing and unrelated object/state helpers. Supplementary `deep_558.rea.referenced_strings.json`, resolved from the broader kernel dump, confirms timer names `hrtmtx`, `HPET1` and `hrtimer: initialize failed`, and the HID diagnostic name `hidAppMouseInitialize`. Those strings are outside this 12-KiB input; they are contextual evidence, not embedded strings recovered from it. The existing empty `dsflash_deep_558.md` contributes no evidence.

## Main handler (+0x0000–+0x00a7)

The syscall uses the usual `(thread *td, user_args *uap)` wrapper shape. It reads a 32-bit ID from argument slot 0 and a **16-bit** type/selector from argument slot 1 (`uap+8`). It reads `td+8`, then obtains a process-owned object/handle namespace from that object's `+0xc48` field. Only those load widths are proven; the original typedefs are unavailable.

At +0x0029–0x003f, the selector is ORed with `0x1000` and passed to an external lookup together with the process namespace, ID, and an address for a stack result token. The call target is file-relative `-0x72d120`, kernel RVA `0x39a2a0`.

A null lookup result returns 3 (+0x0085). A non-null result follows this exact release sequence:

1. +0x0049–0x0056 calls an external remove/detach helper with namespace, original ID, and returned token.
2. +0x005b–0x005f calls another external helper on that token, likely releasing a held namespace object or lock.
3. +0x0064–0x0071 loads the first pointer from the located object and frees/releases it through a common allocator-category helper.
4. +0x0076–0x007c frees/releases the located object itself through the same helper and allocation category.
5. +0x0081 returns zero.

The call sequence and namespace selection support a handle/named-object deletion role. There is no local name string comparison and no direct user-memory copy in this handler. Calling both releases a double-free is not warranted: their arguments are the object's first pointer and the separately allocated object address. The original allocation path and external lifetime rules are needed to validate ownership.

A canary loaded from a global at +0x000f–0x0021 is checked at +0x008a–0x0092; mismatch calls the external canary failure routine at +0x00a1 followed by `ud2`. Neither canary logic nor the error 3 identifies an authorization bypass.

### Readable reconstruction

```c
// Semantic reconstruction; helper names and object types are descriptive.
int handler558(void *td, const void *uap) {
    uint32_t id = *(const uint32_t *)uap;
    uint16_t type = *(const uint16_t *)((const char *)uap + 8);
    void *proc = *(void **)((char *)td + 8);
    void *ns = *(void **)((char *)proc + 0xc48);
    void *token;
    void **obj = lookup(ns, id, (uint32_t)type | 0x1000, &token);
    if (obj == NULL) return 3;
    detach(ns, id, token);
    release_token(token);
    free_category(obj[0], allocation_category);
    free_category(obj, allocation_category);
    return 0;
}
```

The return values of the detach/release helpers are not checked. No local `priv_check`-like call is visible; access control may reside in the process namespace lookup and selector semantics, whose bodies are not part of this input. The code directly modifies process-owned namespace state and object lifetimes. It does not visibly write a syscall result slot or copy a kernel pointer to userspace.

## Timers immediately after the handler

| Entry offset | Role and evidence |
|---|---|
| +0x00b0 | Starts/arms an initialized high-resolution timer. Accepts timer state values 1 or 2, otherwise returns 22. Adds a two-word interval to current time, inserts by deadline through +0x01a0, sets queued flag 4, and reprograms HPET when this becomes the first timer. |
| +0x01a0 | Inserts a timer in a deadline-ordered intrusive list. Compares signed high and unsigned low deadline words, updates head/tail and previous/next references, then stores the deadline. Link inconsistencies lead to diagnostic/panic-like calls and `ud2`. |
| +0x0270 | Removes/cancels a queued timer under the global mutex, updates neighbors and tail, clears queued flag 4, reprograms the next deadline if the removed timer was head, sets flag 0x10 and returns a sign-derived state from prior flags. |
| +0x04c0 | Clears timer state bits 0x18 under mutex and returns the previous 0x10 bit. |
| +0x0510 | Initializes the timer mutex (`hrtmtx`), empty list and HPET1 resource/callback. Missing HPET resource enters initialization diagnostics and a terminal failure path. |
| +0x05b0 | Timer callback/expiry service. Locks the global list, compares deadlines with current time, removes expired one-shot timers or reinserts periodic timers at next deadline, updates flags/execution count, unlocks while invoking the timer callback, then relocks and repeats. Future head deadlines rearm the hardware. Includes indirect-call target validation and linked-list integrity diagnostics. |

Timer node fields visible here: next `+0x00`, previous-link pointer `+0x08`, deadline words `+0x10/+0x18`, interval `+0x20/+0x28`, callback `+0x30`, callback argument `+0x38`, flags `+0x40`, and callback count/state `+0x44`. This interpretation is supported by multiple local routines and the supplementary timer strings. These fields belong to neighboring timer nodes, not syscall558's deleted object.

## HID/mouse subsystem functions

The mouse region uses a 16-pointer device table, an eight-slot auxiliary table, and a per-device allocation of 0x2750 bytes. Samples are held in a 65-entry ring with stride 0x98; modulo-65 arithmetic is visible in both producer paths. Many external HID parsing, lock, ID and notification helpers remain unresolved.

| Entry offset | Observed role |
|---|---|
| +0x0920 | Initializes/clears the 16-device table (0x80 bytes), eight-entry auxiliary table (0x40), shared settings (0x1c), and current timestamp. |
| +0x0970 | Finds the first free slot among 16, allocates/zeros 0x2750 bytes, associates the state at device+0x198, assigns an ID and configuration defaults, and publishes the device pointer. Returns `0x803b000a` when no slot/allocation is available. |
| +0x0be0 | Removes a device from the table via an external helper, detaches active state, frees device+0x198 and clears that pointer. |
| +0x0c40 | Interprets HID descriptor usages/fields and populates extraction descriptors for mouse axes/buttons/wheel-like values. Recognizes descriptor types 1, 9 and 12; usage values 0x30, 0x31, 0x38 and 0x238 are visible. Uses report masks and bounded descriptor counts. |
| +0x0e00, +0x0e10 | Two no-op callbacks (prologue, epilogue, return). |
| +0x0e20 | Initialization/notification wrapper identified by the supplementary `hidAppMouseInitialize` string. Checks an external subsystem state, notifies through an external helper, and emits diagnostics on failure. |
| +0x0e90 | Tests a report selector/ID against the active extraction descriptors; returns whether a matching initialized descriptor exists. |
| +0x0f40 | Incoming report processor. Validates device/data/positive length, locks state, clears the next ring sample, extracts button bits and axis/wheel values through external field readers, timestamps and marks sample state, updates notification/calibration state, invokes +0x1490 outside its lock, revalidates table membership, advances ring indices modulo 65, and moves subscriber cursors that would collide. |
| +0x1490 | Optional sample-transform callback adapter. Under lock, validates device membership/state and callback availability, copies a sample to a local 0x50-byte record, unlocks for callback execution, relocks/revalidates the device, and copies modified data back only when its callback result flag is 1. Preserves original sample timestamp. |
| +0x1710 | Device lookup wrapper over the 16-entry table; when an output pointer is supplied and index <=15, initializes its 32-bit value to zero before lookup. |
| +0x1740 | Direct lookup wrapper over the same 16-entry table. |
| +0x1760 | Adds/removes or otherwise updates an auxiliary eight-entry association by selecting one of two external table helpers based on its second argument. |
| +0x1790 | Updates shared/per-device mouse configuration; a null input returns `0x803b0001` and a nonzero second argument returns 0 without mutation. Scans the 16-device table for matching device IDs, updates state records and propagates default settings to active device state. Exact vendor setting names are unavailable. |
| +0x1a60 | Removes an ID from an auxiliary eight-slot table, then performs a second table update if the first succeeded. |
| +0x1aa0 | Installs a global callback pointer and returns zero. Actual later callback sites perform indirect-target validation. |
| +0x1ab0 | Periodic/injected-sample service. Obtains time, scans the 16 devices, builds zeroed 0x50-byte samples for selected device types, invokes +0x1490 and conditionally pushes transformed samples via +0x2250. |
| +0x1ba0 | Flush/reset helper for device type 0. If the last queued sample has nonzero button bits it invokes an external release/clear helper, then clears ring cursors at +0x100/+0x104/+0x108 and optional state at +0x190. Other device types return immediately. The +0x1be1 frame is conditional and belongs to this function. |
| +0x1c20 | Nonblocking sample read. Validates output/count arguments and count bounds, resolves the device, selects a reader/ring cursor, copies available 0x50-byte samples while applying configured value adjustments, advances cursor and reports number read. |
| +0x1e00 | Blocking/waiting counterpart to sample reading. Resolves device/reader state, sets up an auxiliary wait object, releases the lock while waiting, reacquires/revalidates, copies available samples, and cleans up auxiliary membership. |
| +0x2100 | Computes elapsed time since a global last-input timestamp and stores it through an argument. Conditional frame begins +0x2105. |
| +0x2140 | Resolves device and per-device state, rejects parameter values above 1 with `0x803b0001`, then stores a 32-bit parameter at state+0x2740; absent device/state returns `0x803b0003`. |
| +0x21a0 | Similar parameter setter, accepting unsigned values 0–8 and writing state+0x2744. |
| +0x2200 | Resolves device, requires a non-null output, writes current time and forwards to an external sample/device helper. |
| +0x2250 | Injects/publishes an already structured sample. Locks device state, fills a 0x98-byte ring entry, updates notification/calibration settings, advances modulo-65 indices and adjusts subscriber cursors. |
| +0x2540 | Writes the second argument to per-device state+0x2748. An optional flag requires the third argument to match state+0x2730 before storing; a mismatch returns success without a store. Returns `0x803b0003` for missing device/state. |
| +0x25a0 | Device-state query: resolves the device/state and optionally writes state+0x2748 through a caller output pointer, returning missing-object status otherwise. |
| +0x25f0 | Enumerates occupied device slots into a count followed by IDs, with a 16-entry ceiling. A null output returns `0x803b0001`; enumeration stops at 16 IDs. |

## Further neighbors and truncated tail

| Entry offset | Observed role |
|---|---|
| +0x2650 | Acquires an external resource, stores its handle through its argument and returns whether acquisition succeeded. |
| +0x2680 | Releases a previously stored handle if non-null and clears it. |
| +0x26b0 | Lazily acquires such a handle, submits an external operation with caller values, and releases/clears the handle on error. |
| +0x2720 | Queries handle state flags; returns success when low three state bits are clear, optionally reads data/results and rechecks state. |
| +0x2790 | Updates process/queue ownership and scheduling-related object fields under external synchronization; coordinates associated objects using several external notification helpers. |
| +0x2960, +0x2980, +0x29a0 | Tiny conditional counter helpers: when object+0x84 <=15, increment +0x9c, decrement +0x9c, or increment +0xa0 respectively. |
| +0x29c0 | Stores zero through the pointer at object+0x70. |
| +0x29e0 | Conditionally stores one through object+0x70; the initial comparison at +0x29e0 precedes its delayed frame at +0x29e9. |
| +0x2a00 | For object+0x84 <=15, decrements +0xa0 and clears the word through object+0x70 when the count reaches zero; otherwise returns immediately. Its conditional frame is +0x2a12. |
| +0x2a30 | Stores a 32-bit field at object+0x94. |
| +0x2a40 | Returns whether object+0x94 equals 1. |
| +0x2a50 | Allocates/configures a 0x4c000-byte resource through external backends, retains it in global state on success, initializes linked configuration structures, and frees resources on setup errors. |
| +0x2c40 | Constructor-like initializer with an early null/argument gate and delayed frame +0x2c58. Clears 0xc8 bytes and stores passed configuration/owner fields. |
| +0x2d40 | Maps object+0x2c8 flags to states 0,1,2: bit0x200 forces 2; otherwise state 1 when low three bits are all set. |
| +0x2d70 | Validates/configures a descriptor, then copies its fields into an object: first argument <=3 and three byte selectors each <=1, length/dimension fields <=0x2000 and >=0x140 relationships, format checks through external +0x30a0 and +0x3380, special value restrictions and flag translations. This function is truncated at file end. |

## Reliability and limitations

The dump ends in the middle of a `call rel32` at +0x2ffe; only bytes `e8 dd` are present. Targets at +0x3007, +0x3033, +0x308d and beyond are outside the mapping. The final validator's complete error exits and backend effects are therefore unavailable. Full assembly must retain these trailing bytes rather than invent the missing instruction or return.

The main handler's namespace lookup/remove/release and allocator implementations are external. The input has no symbol table, relocations or original source types. Assembly supports a process-local object-delete operation and separately supports substantial timer/mouse code, but does not prove a route from a user-controlled syscall selector into the neighboring timer/HID callbacks. Table locks, callback validation and revalidation are visible in neighbors; determining complete concurrency correctness needs their callers and external helpers.

REA/Ghidra C-like output is approximate recovered pseudocode. Delayed prologues, missing external prototypes and unmapped control-flow destinations can produce spurious function splits, `unaff_`/`extraout_` variables and incomplete returns. The assembly with byte offsets remains authoritative. No confirmed privilege bypass, information leak, arbitrary free or other exploit conclusion is established by this standalone slice.

## Decompiler review

The exported `deep_558.rea.c` was compared with the syscall entry, corrected function starts and selected timer/mouse helpers. It confirms the 16-bit selector load, namespace lookup/detach, two distinct allocation frees and 0/3 returns. Function +0x0510 is rendered with `halt_baddata()` at its successful external tail jump; assembly shows a valid callback-installation tail jump. This rendering does not indicate an intentional halt. Functions at +0x1790, +0x1ba0, +0x2100, +0x2140, +0x21a0, +0x25f0, +0x29e0, +0x2a00, +0x2c40 and +0x2d70 have checks before a delayed frame setup, and should be analyzed from those true entry offsets. The final +0x2d70 validator contains branches and a truncated call beyond the available bytes, so its complete success/error behavior cannot be recovered here.

## Supplemental recovery audit

A final coverage pass recovered 4 additional synthetic block entries in `deep_558.rea.extra_fragments.c`. These are blocks omitted from primary function pseudocode (including disconnected dispatch arms or paths beyond unresolved transfers). They are **not additional original ABI functions**: inherited register values, the parent stack frame, exact switch edges and decompiler-imposed block boundaries remain uncertain. The full assembly remains the reference. The selected offsets are in `deep_558.rea.extra_fragments.selection.json`, with complete individual records in `.dossiers.jsonl.gz` and the canonical bundle in `.evidence.json.gz`.

| Synthetic entry offset | REA evidence ID |
|---|---|
| `0xdc2` | `ev_b427a7f5434776411f947ac52c5d1acf7e432b4f61a0bb937c01082b5eb8f92d` |
| `0xdc7` | `ev_888c45f51b966ab3c75b1ef4f5d7cb3048563f1b55d24eb7f294c224fddf35d5` |
| `0xdcc` | `ev_bdd72e0b70d681b5882eedcf466511f42fb384fc578e815793c3af8c1b130ef9` |
| `0xdd1` | `ev_30fa5d82b424c0fdd024065ace51c83dbaccdf9bdca1dc9bf6a2298f316cf36e` |
