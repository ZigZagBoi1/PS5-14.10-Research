## 2026-10-22: The AIO batch entry works, and the GPU pool zeroes its pages

Sys 661 kills on every shape tried, and that was carried as "AIO is dead". There are two submit entries. 669 takes a batch of descriptors - `669(cmd, reqs, count 1..128, class 1..3, ids)`, stride `0x28` - and it works: `cmd=1` reads and `cmd=2` writes, a completed request reports `state=0x3` from 664, and the result word carries the number of bytes moved (`0x10` for a 16-byte read of `/dev/urandom`, with different data on every read). Identifiers are slot numbers with a generation tag in the high word, 24 requests were outstanding at once, and deleting four freed those slots for the next four. 661 says nothing about the rest of the family.

The refusal path matters: 669 returns `0` whether or not it queued anything, and a spent queue answers `0x80020005` in the result word only. The destination is range-checked - an unmapped page and a kernel-half address both return `0x8002000E` (EFAULT), each followed by a control that completes - but the byte count is not clamped to the buffer, and `count = 0x14000` into a 4 KiB destination writes through the process heap and kills the loader.

Three negatives from the same round. The GPU pool **zeroes pages on allocation**: a dense scan of a complete 64 MiB chunk (8 388 608 qwords) and 49 152 samples across 384 MiB found no nonzero word, no kernel-shaped value and no strings, so the uninitialised-page KASLR leak is dead. `637`'s store is **inert**: mapping three chunks, storing `0xFFFFFFFF` and mapping again reaches the same six-chunk ceiling. And osem's slot order on 14.10 is `(name, attributes, initial, maximum)` - the dossier has the name last, which is why every earlier call failed.

Captures: `results/phase17_new_vectors/352a_aio_batch_20261022_160559.txt` through `352k_aio_commands_20261022_161843.txt`, `346b_fmem_ceiling_20261022_161726.txt`, `348a_gpu_pool_scan_20261022_155156.txt`, `349c_osem_wait_20261022_160530.txt`. Write-up: `docs/AIO_BATCH_14_10.md`.

## 2026-10-22: The performance-counter syscalls store and return, but only for the caller's own threads

Sys 563-567 were never called. On the caller's own threads everything works: 563 enables and 564 disables (`0`), 566 stores a counter word at `PCB+0x190+8*index` (`0`), 565 stores an event-select word (`0`), and 567 reads a counter back (`0`, returning the exact value 566 wrote). The validation matches the dossier exactly - index 6 is refused, a rejected event-select bit (`0x10000`) is refused rather than masked, and a process selector that cannot resolve returns `-1`.

The read-back is the control that makes this more than a list of zeroes: the store lands where the dossier says it does, and the six slots are the entire range. The process-selector path, which would reach another process's pcb, requires `cred+0x58 == 0x4800000000010003` and is closed to a game process.

Capture: `results/phase17_new_vectors/327a_opmc_scope_20261022_123153.txt`.

## 2026-10-22: The death-on-touch syscalls are SIGSYS, and fstat is not one of them

Every slot recorded as lethal on this firmware was lethal for one reason: the shared `nosys`
trampoline raises SIGSYS, and an uncaught SIGSYS terminates the process. The body is in the
13.60 capture and it is the same 4,096 bytes for 561, 562, 570, 573, 631, 650 and 651: lock,
build a signal record with number 12 and code `0x10006`, deliver, return `ENOSYS`.

With SIGSYS ignored, 562, 650, 651, 665, 668, 631 and 661 return `-1` instead of ending the
process, and so do 189, 306, 307, 308, 337, 570 and 573 (probes 353a/353b). The kill was a
signal disposition, not a property of the handler.

That retires one dead end and corrects another. `fstat` (189) is **present**: it returned `0`
and wrote a stat record for an open `/app0/eboot.bin` descriptor with the default
disposition (353c/353d), and `189(0,0,0,0,0,0)` returns `-1` without harmful effect, so the
"fstat kills" entry from 152j does not reproduce. The AIO single submit (661) is the `nosys`
trampoline, which is why it killed and why its siblings in 662-670 were never reached -
669 is the only submit entry.

`docs/SYSCALL_ABSENT_VS_LETHAL.md` now leads with the resolution and the method change:
probe a possibly-absent slot with SIGSYS ignored, or the experiment destroys its own result.

## 2026-10-22: Suspending a thread exposes its saved registers, and setting them does not exist

Sys 632 (`thr_suspend_ucontext`), 633 (`thr_resume_ucontext`), 634 (`thr_get_ucontext`) and 635 (`thr_set_ucontext`) were called for the first time on a thread this process created.

632 suspends and returns `0`; 633 resumes and returns `0`; 634 refuses a running thread and the caller's own thread with `-1`, but returns `0` once the target is suspended, copying 0x4c0 bytes of a 0x500-byte snapshot into the caller's buffer. The saved frame in that copy carries the values the thread was started with - RIP at `+0xE0`, CS at `+0xE8`, RFLAGS at `+0xF0`, RSP at `+0xF8` - which is the same register set `thr_create` takes, shifted.

Every qword in the 0x4c0-byte copy was scanned for a kernel pointer. Fourteen were nonzero (the register words, the segment selectors, the residue of the context header) and **none** was in the kernel range: the snapshot is zeroed before it is filled, so there is no uninitialised-tail leak.

635 returns `-1`. The 13.60 handler dossier gives its whole body as `mov eax, 0x4e; ret` - a stub returning 78 - so on 14.10 the entry is not even the stub the capture describes. Writing a suspended thread's registers back is not available, and the one thing this family could have added over `thr_create` (rewriting a thread after it exists) is the part that is missing.

Captures: `results/phase17_new_vectors/325a_thr_ucontext_20261022_122833.txt`, `results/phase17_new_vectors/326a_thr_set_ucontext_20261022_122948.txt`.

## 2026-10-22: The font-face use-after-free is reachable on 14.10, and it hangs the guide

- The public CVE-2026-43715 (WebKit bug 313577) lead was tested on the console with five probes. The trigger is real and the guide reaches it: an injected `@font-face`, a read of `face.loaded`, a `FontFace.prototype.then` getter that removes an existing style element and forces layout, then `face.load()`. The getter is read synchronously inside `load()`, so the code path the fix guards is live.
- **The effect is not a use-after-free.** The client loop the 2026 fix guards is a snapshot of strong references (`copyToVectorOf<Ref<CSSFontFaceClient>>`), so a client removed by the getter cannot be freed while the iteration runs. On 14.10 the WebProcess instead loops inside the layout the getter forced and dies of memory exhaustion within a second - the console shows "there is not enough free system memory".
- Five controls separate the ingredients: removing an element that does not exist is harmless, removing a real one without layout is harmless (`ffB-returned-fired=1`), the same getter on a plain `Promise.resolve(thenable)` returns immediately (`C-returned-got=1`), and only the font-face path with a real removal and a forced layout hangs. Getter caps of 2000 and 4 entries were both never reached, which rules out re-entry through our own code: the promise's `then` is read once and the loop is inside the engine.
- Consequence recorded in `docs/WEBKIT_FINDINGS.md` **Finding 10**: this is a denial of service against the guide, the same shape as Findings 7-9, and the lead is closed as a route to memory corruption.

## 2026-10-22: The "-1" syscalls are not dead, and one of them stores a chosen qword

- **The `-1` column is not a verdict.** Forty-odd handlers carry a sweep answer of `-1` from six zero arguments. Called instead with real pointers, six of them answer: 538 `evf_create` returns a handle, 540 resolves a registered name, 557 `namedobj_create` returns a handle, 598 and 659 copy out, 572 `virtual_query` returns 0, and 637 `set_phys_fmem_limit` returns 0. Full write-up in [OBJECT_FAMILIES_14_10.md](OBJECT_FAMILIES_14_10.md).
- **637 is the first handler measured here that writes a caller-chosen 64-bit value into a kernel structure without a capability.** With target id 0 - this process - the capability helper that gates 618, 646 and 671 is skipped, and the value lands at `parent+0x200 -> child+0x280`. Foreign ids 1, 2 and 5 return `-1`, so the bypass is per-process by design. The offset is fixed and its meaning is unknown; no path turns it into a read, a pointer, or a second location.
- **637 also waits.** A value below the process's current physical memory usage parks the caller in the kernel - `637(0, 17)` never returned and needed a game relaunch - while 2 GiB and 4 GiB return immediately. The handler is a wait-for-usage-to-drop, not a setter, which is why six zeros and a small value both looked like `-1`.
- **The evf family works and leads nowhere.** 544 set, 545 clear and 546 cancel all accept a handle the process created; 541 refuses to delete it; 543 needs a mode encoding not yet found. Handles the process never received (`0`-`517`, `65536`, `2147483647`) are rejected, so the lookup is not a wild dereference.
- **Named objects do not survive their creator.** 538 with attribute `0x100` registers an object by name and 540 resolves it in-process, but after a relaunch all four registered names return `-1`, so the registry is process-scoped and there is no cross-process handle to another process's kernel object.
- **573 `mdbg_call` powered the console off once**, during the sweep, and does not reproduce: the same call in a fresh process killed only the loader while the console stayed up. One observation and one negative control, no mechanism claimed.
- Probes 334a-342a and 344a and their captures are in this commit, along with a correction to the probe list that had wrongly included the documented kill row 573.

## 2026-10-22: Strategy page brought up to the measured state

`docs/STRATEGY.md` still opened with "no threading" and the W^X framing from
2026-10-16, which has been wrong since 156c/156d. The page now opens with the
current position: the six primitives that exist (Lua execution, syscall
invocation, thread creation with controlled registers, the GPU pool, the event
and named-object families, and 637's fixed-offset store), the walls that are
measured rather than assumed (no credential context, no device context, no
kernel pointer, no arbitrary kernel address, death-on-touch syscalls, the jail,
and the browser), and the four things still open. The 2026-10-16 text is kept
below as history.

## 2026-10-22: The game process is in a jail with no mounts and three reachable system sockets

- New [JAIL_14_10.md](JAIL_14_10.md). Inside a game process, only `/`, `/app0` and `/dev` open; `/mnt`, `/mnt/usb0`, `/mnt/usb1`, `/mnt/ext0`, `/mnt/ext1`, `/data`, `/user`, `/system` and `/tmp` all return `-1`. The jail root holds `IMt9cl0VzR`, `system_tmp`, `dev`, `app0`, `savedata0` and `av_contents`, and no entry is a mount point for removable media.
- **The USB route is closed from here.** A stick mounted by the system never appears in this namespace, so no filesystem image is ever supplied by the game and the `msdosfs_readdir` padding disclosure (CVE-2020-25579) cannot be reached this way whatever 14.10 still carries.
- `/dev` carries 79 nodes reachable through directions the earlier ioctl rounds could not open. `dbggc`, `sbl_srv`, `encdec`, `uvd_dec` and `mp3` refuse both `O_RDONLY` and `O_RDWR` - the debug graphics node is closed by the same credential check as the update devices - and `sce_zlib`, `ajm`, `ajmi` and `rng` answer exactly one command each (`0x4004667A`, the file layer's `FIODTYPE`), no driver table.
- **Three sockets in `/system_tmp` accept a connection from a game process**: `GnmCompositorRestricted`, `AgcCompositorSppSocket` and `VrTracker2DomainSock` return `0` from `connect`. `GnmCompositor`, `SceImageUtilAgent`, `SystemTts` and `redis.sock` refuse, and every DGRAM attempt is `-1`. The two compositor sockets accept and hold any run of zeros without answering; `VrTracker2DomainSock` accepted two connections and then refused for the rest of the run, which reads as a listen backlog of one on a service that never accepts a game client.
- Nothing here is a primitive: the sockets are reachable parsers whose protocol is unknown, and their binaries are not in the jail. What the round establishes is the shape of the boundary, not a way through it.

## 2026-10-22: Sys 654 is called with its real contract, and no region qualifies

- **`sys_654.md` recovers the actual shape**: `narg=5`, slots `(address, length, operation, flags, reserved)`, 64 KiB alignment on address and length, flags limited to bits `0x33`, and an entry check that rejects any object whose type byte at `+0x9d` is not `11`. Every earlier call - `183a`'s `(handle, 0, 0x1000, buf)` - put a blockpool handle where the address belongs, so nothing had reached the body.
- **With the real shape it still refuses everything**: a 64 KiB-aligned GPU mapping, operations `0`-`20`, flags `0`-`0x40`, misalignment controls and zero length all return `-1`, and the `547` region record stays byte-identical.
- **The reason is the object type, not the arguments**: `312a` walked all **314** regions the process map reports and called `654(start, 0, 0, 0, 0)` on every one, including the **82** that are 64 KiB aligned. **Zero were accepted.** No mapping a game process owns carries object type `11` - the same wall `673` hit, now measured across the whole map instead of one address.
- **`84a`'s title was wrong and is corrected here**: `653` is `blockpool_open` returning a descriptor (190a proved that with `close(23)`), not a "GPU PTE modifier". The handler's page-table code is the block pool's internals, not an API a caller reaches. Probes `311a`, `312a`, `310a` and the first `84a` capture are in this commit.

## 2026-10-22: mmap_dmem is not a physical-memory mapper, and the authid gates hold

Sys 628 `mmap_dmem` was called with the six-slot layout its handler reads for the first time. The dossier's "descriptor -1 bypasses the device lookup" made it a candidate for mapping physical memory, but twenty-four calls across descriptor `-1`, `/dev/dmem0`, `/dev/zero` and `0`, three protections, flag `0x40`, a nonzero address hint and two offsets all return `-1`. The refusal does not depend on the descriptor, so the entry rejects before the lookup - another device-context wall, not a mapper.

The direct-memory nodes do open: `dmem0` (22/23), `dmem1` (24/25), `dmem2` (26/27), `dce` (28/29), `gic` (30/31), `gc` (32/33), `zero` (34/35).

The authid gates were then tested the other way round. 535, 536 and 563-566 compare `cred+0x58` against identity values; every earlier probe used selector `0`, which skips that check. With this process's own pid, **all six return `-1`** while selector `0` still returns `0`. Naming your own process does not pass the gate.

587 is the only handler that exposes the credential record: 0x88 bytes from `target_cred+0x58`, but on the path a game process reaches only the capability word survives - `0x20000000` at record `+0x0C` for this process, `0x40000000` for system pids 1/2/5/16/30, and `+0x08` (the word whose bit 62 gates 618, 646 and 671) zero for all. The identity is never readable and no handler writes it.

Captures: `results/phase17_new_vectors/{330a_dmem_open,331a_mmap_dmem_matrix,332a_authid_gates,333a_cred_foreign_pid}_20261022_1236*.txt`.

## 2026-10-22: The AIO batch calls work, and their ids come from the call that kills

- 662, 663 and 664 returned `-1` to six zero arguments in every earlier sweep. Given the shape the 13.60 contracts name - an id array, a count and an output array - all three return `0` and write one Sony status per id: `0x80020000` for an invented id, `0x80020003` for the real kernel thread id `0x18E65` and for the process id `0x6A`. They are working batch calls, not absent slots.
- The id they accept is neither a kernel thread id nor a process id. In 13.60 the three are AIO batch delete, batch wait and batch poll, so the ids are AIO request ids - and those only come from a submission path, which is 661, the number that kills before it returns.
- Both length questions were measured and both are bounded: `count = 0x400` against a `0x1000` id page returns `-1` instead of reading out of it, and `count = 4` with an output array ending four bytes before a page boundary returns `0` without faulting. There is no overrun here to aim.
- `CLAUDE.md` and `docs/ATTACK_SURFACE.md` no longer describe these three as "rejecting zeros"; `docs/AIO_RANGE_14_10_EVIDENCE.md` carries the measurements and the id-space reading.

## 2026-10-22: The device ioctl space is measured, and the drivers are struct fillers

- **Thirty-two million ioctl calls across 31 nodes** covered the whole command byte, every direction and the full 14-bit length field. The device surface answers with two things: one inert command on `/dev/dce` and a twenty-five-command table on `/dev/gc`. Full write-up in [DEVICE_IOCTL_14_10.md](DEVICE_IOCTL_14_10.md).
- **The earlier sweeps were searching a sixteenth of the space.** They fixed the length field to `0, 4, 8, 0x10, 0x20, 0x40, 0x100`, and the graphics driver declares commands at `0x18`, `0x28`, `0x30`, `0x48` and `0x888`. Widening the length field turned 20 commands into 25 and found every struct-sized one.
- **The three questions that decide whether an ioctl is a primitive were each measured, and all three came back no.** No command follows an address stored in the struct (283a sets the first qword to a second user page and watches it), no command changes behaviour when the struct contents change (285a, 287a call each command with `0xAA` and with zeros, identical results), and every write stays inside the declared length (dumped across the whole page, including the four struct commands).
- The values written back are small constants - `0x101`, `3`, `0x80000000`, `0x0C`, `0x5C`, `0x10`, `0` - and none of them move between calls in a way that would reveal a kernel or GPU address. There is no information leak on this surface.
- **One real defect: `0xC0048125` blocks the calling thread forever.** The console keeps rendering, the loader keeps accepting connections, and the app fails on exit with a black screen and a system error; the thread stays inside the driver. It returned `0` in 280a, before `0x80888123` had ever run, and hung in 281a, 282a and 284a after it. A hang denies service and hands back nothing.
- The update device is not reachable either: `273a` opens `/dev/pup_update0`, `/dev/pup_update`, `/dev/sbl_srv`, `/dev/encdec` and four more aliases and every one returns `-1`. Decrypting a PUP needs the credential that `ps5-pup-decrypt` fakes with a kernel write, so that route is a consequence of privilege rather than a way to it.
- Probes 273a-287a and their captures are in this commit. `283a`'s second page, `285a`'s 0x888-byte struct and `286a`'s length sweep are the three that carry the conclusion.

## 2026-10-21: The corpus pass completes, and every divergence is a hang

- The 1919-page JSC build was walked to the end on 14.10: **1899 pages reported `OK`, 27 were pinned as unsafe to run, and no page outside the pin list was started without finishing**. Seven guide reloads were needed; every one was a page that exhausted the WebProcess's memory or froze its main thread, never a crash and never a lost beacon. Sessions and logs are listed in [Finding 9](WEBKIT_FINDINGS.md).
- **Three divergences, one shape**: the engine should throw and instead loops. `proxy-handler-traps-cache-poly-proto-handler` spins in a release build, asserts `isCell()` in a debug one, and exhausts memory on the console; `regress-125602977` never throws the `TypeError` that an unconfigurable redefinition requires; `use-static-private-member-in-computed-property-name` hangs inside class evaluation on the first call, where the parse should have failed. All three are denial of service - none of them hands a page a value it chose.
- **No memory-safety report anywhere.** 1919 sources replayed verbatim under a Debug+ASAN `jsc` with the shell shims gave `{'clean': 1070, 'asan': 0, 'assert': 0, 'signal': 0, 'timeout': 123, 'parse': 216, 'exception': 510}`, and ~17 000 number/compare/arithmetic mutants of the same sources gave nothing. The 510 exceptions are harness gaps (dynamic `import('./aN.js')`, `$vm`, async main), not engine bugs.
- **Two harness defects had made every earlier offline run meaningless.** `JSC_SHIM` starts with `<script>`, so feeding it to `jsc` died at parse before a single case executed, and the classifier counted that as clean; the shim also touches `window`, which the shell does not have. `JSC_SHIM_JS` now strips the wrapper, adds `var window = this;`, and the classifier reads `stdout` as well as `stderr` - jsc prints uncaught exceptions to stdout - with separate counters for `asan`, `assert`, `signal`, `parse` and `exception`.
- **The builder now drops the classes the pass measured**: watchdog loops under `requireOptions` as well as `runDefault` (index 1892), allocations at or above 256 MB resolved through the file's own `const` definitions (indexes 425-427, 949), `//@ memoryHog!` (index 74), and anything `jsc-time` measures over its wall-clock budget (index 625 needed hours). The build is **1903 pages** and the test file is at 15 tests.
- **The pin list is enforced by the runner now.** `/corpus/skip.json` carries both `skipped` and `next`, and the runner steps over pinned indices and clamps a stale `start` up to the cursor, so a document that replayed an old handoff can no longer restart the walk at zero.

## 2026-10-21: Index what the 145 decompiled handlers say about their arguments

- `tools/syscall_contracts.py` reads `results/kernel_handlers/analysis/sys_*.md` and the matching `results/kernel_handlers/decompiled/sys_*.c`, and writes `docs/SYSCALL_CONTRACTS_13_60.md`: one row per handler with its argument count, the argument offsets it dereferences, the largest byte count it copies back, whether its prose names a user pointer, and - for the nine handlers whose decompilation carries an analyst struct - the recovered argument field names.
- 145 handlers, 142 with a description, 9 with recovered fields: 533 `unused_slot_0, size, flags`; 548 `descriptor, flags, user_operations, count, user_processed`; 659 `handles_out, capacity, count_out`; 660 `module_handle, slot_padding, info_inout`; 662 `ids, count, results`; 663 `ids, count, states, wait_mode, timeout_inout`; 664 `ids, count, states`; 665 `ignored_slots`; 657 `commands, count, processed_count, flags`.
- The index changes how the AIO range reads. 662, 663 and 664 reject a request whose `count` is outside 1..128, and every earlier sweep passed six zeroes - so those results say "the count check refused this", not "there is no handler". 235a and 236a are written against these contracts; neither has run yet.
- 548 is the only virtual-memory writer found that does not go through `mprotect`; its recovered operation record carries a protection byte and the analysis records that `7` is not rejected, which is why it is worth a measurement rather than an argument.
- **sys 622 was measured with the wrong argument layout for three days.** The 13.60 handler reads six slots - `cmd, sub, buffer, secondary address, size <= 0x40, extra` - and the 2026-10-18 sweep passed `(cmd, buffer, size, ...)`, so the command came out of the buffer and every call returned the same error. With the right slots the top-level gate is visible twice: size `0x41` returns `0x800E0001`, size `0x40` returns `0x8002004E`. The 113 commands in `0x200-0x270` and `0x813` then execute past the auth gate, return `0`, and write `0xFFFFFFFF` (not-found, not data). The `0x400-0x493` group returns `-1` when the `copyin` from `arg3` fails and kills the process whenever it succeeds - at any size including 1, and at size 0 with a null pointer - so the fault sits after the copy and does not depend on the bytes copied. Sliding `arg3` to the end of a mapped page (547 gives the region, so the boundary is exact) shows the copy is `arg4`-sized: 0x30 bytes of room returns `-1`, 0x40 fits and dies. No kernel pointer, no overrun, no write primitive; the group needs a device context this process cannot create.
- Every row is a 13.60 observation from the captured handlers. 14.10 behaviour still has to be measured, and the document says so in its header.
- Built from those contracts instead of six zero arguments, three handlers answered. **547 works as a region oracle** (`ret=0`, start/end/protection filled: heap `prot=3`, GPU page `prot=0x33`), **659 works** (`ret=0 count=3`, handles `0x13` and `0x14`), and **662/663/664 are alive**: `ret=0` with one per-item status of `0x80020003` for every id encoding tried. 660 refuses the handles 659 hands out, 533 refuses every size and flag combination, and 548 and 657 refuse the first argument values tried.
- The AIO batch entries were written off as lethal on 14.10 because 661 kills. They are not lethal and not absent: the entries validate an id namespace, and every earlier six-zero sweep at 661-670 was refused by the `count` check (contract: 1..128) before it reached one. What an id has to name is still unknown - 661, the only handler that would create one, dies on touch.
- 660 stays shut for every handle this process can name: the two from 659, `0`, a mapped page, `page+0x28`, and all **38 handles** that 592 hands out - each refused with the `0x160` gate untouched, so the handle is rejected before a record is built. The id space of 662/663/664 is equally shut: 512 encodings (slot 0-255, then handle 0-255) give one status, `0x80020003`. Whatever an id names is created by 661, which kills on touch.
- **W^X is confirmed by read-back for the first time.** 547 reports the region record for an address, so the page can be inspected before and after a call: `mprotect(page, 0x4000, 7)`, `(…, 5)` and `(…, 4)` each return `-1` and leave the record byte-identical at `prot=0x33` while the page stays writable. The earlier statement was measured by the return value alone.

## 2026-10-21: The corpus now skips the pages that allocate by design

- The rebuilt corpus (1932 pages, the full post-cut commit set rather than the 27% sample) reached index 74 on the console and got "there is not enough free system memory" within a second. That page is `array-from-cloned-arguments-large-length.js`: `//@ memoryHog!` in the header, `arguments.length = 0x10000001` in the body, 268 million elements requested from `Array.from`.
- Thirteen of the rebuilt pages carry `//@ memoryHog!`, so `tools/webkit_crash_corpus.py` drops them the same way it drops `$memoryLimited`, and the corpus is 1919 pages. `test_memory_hog_case_is_dropped` covers it; the test file is at 10 tests.
- One more class hangs by design: `exception-can-be-already-thrown-during-exit` is `for(;;)` under `//@ runDefault("--watchdog=5000")`, a test of what the engine does when its own watchdog fires. The builder strips `runDefault`, so the loop never ends and the console showed "this page isn't responding" at index 545. Nine other pages carry a watchdog option; the ones with an unbounded loop are dropped (`JSC_WATCHDOG_LOOP` and `JSC_UNBOUNDED_LOOP`), the bounded ones are kept.
- Four more cases allocate a gigabyte or more without the marker: three `dataview-byte-length` variants build `new ArrayBuffer(fourGigs)` from `fourGigs = 4 * oneGiga`, and `osr-exit-scratch-buffer-gc` repeats a string `0x40000000` times. Indexes 425, 426, 427 and 949 each produced the same memory message. The builder now resolves the size through the file's `const NAME = <expr>;` definitions and drops allocations at or above 256 MB, so a rebuild carries 1915 pages; 12 tests pass.

## 2026-10-21: A single page exhausts the guide browser's memory, and the corpus pass completes

- The corpus stopped at the same index in every attempt, and the last run loaded that case **alone**, in its own document, from a fresh guide process: `BOOT-510-from-295-to-296`, one GET of `/corpus/jsc-296-proxy-handler-traps-cache-poly-proto-handler.html`, `BEFORE-295`, then "there is not enough free system memory" about a second later. The case ends the WebProcess by itself; the accumulated heap of several hundred documents has nothing to do with it. Session `7smqr0`, log `results/webkit/server_20261021_183352.log`.
- Six variants and four controls cut it down (sessions `sunejr`, `yh77dd`). All four of these are required: a poly-proto handler object, a cached `get` trap, `setPrototypeOf(handler, null)` after the trap was cached, and a read through the Proxy afterwards. The helper alone, the Proxy alone, an ordinary handler, `null` before the trap was cached, a `{}` prototype instead of `null`, and `null` with no read after it all complete.
- The missing invalidation is not specific to `get`: the `has` shape, instrumented call by call, answers `true` before the prototype change, survives `setPrototypeOf` itself, and never returns from the `in` lookup after it; the `ownKeys` shape returns `a` from `Object.keys` before and exhausts memory on the call after. Sessions `lcluko`, `bme8v3`. Three of the handler-traps cache paths end the process, not one.
- **The regexp case is a one-line hang**: `/.*X/u.test("\u{10000}a")` never returns on 14.10. The case's own complexity canary passes (1/2/7/32 ms at n = 250/500/1000/2000), so the O(n^3) fix is present; block 7 of the case ("no match after full backtrack") is where it stops, and the reduction needs the `u` flag, a backtracking quantifier, a non-BMP character with a code unit after it, and no match. Three code units, no proportional work, so it is a loop in the start-offset step, not slow matching. `probes/phase13_webkit/p174-regexp-nonbmp-hang.js` is the reproducer; Finding 8 has the ladder.
- **The corpus pass completed on 14.10** (2026-10-21 18:25-18:56, sessions `0fiy0d`, `1so3em`, `7sfr7w`, `ikvy87`): 507 of 510 cases completed. The three that did not are case 295 (Proxy trap cache, memory message), case 378 (`regexp-unicode-greedy-charclass-backtrack-linear`, page stops responding, while V8 runs the same body in 372 ms and Chromium completes the page), and case 495, which turned out to be a corpus defect: its `skip if $buildType == "debug" or $memoryLimited` directive was not caught by the filter, so a 179 MB `new Function` source hung the console and a desktop Chromium alike. See Finding 8 and the console results in `docs/WEBKIT_CORPUS.md`.
- The `$memoryLimited` filter now matches the flag anywhere inside a `skip if` directive; the corpus is 509 pages, and `test_memory_limited_inside_a_compound_directive_is_dropped` pins it.
- The run state is a locked read-merge-write (furthest cursor, union of skips, highest marker per session) with retried reads: a stale copy had resumed one run on the case it had skipped and restarted another at index 30 from 363. The runner also floors `start` at the highest index the document reached, so a cached case page cannot send it backwards.
- `probes/phase13_webkit/p173-poly-proto-oom.js` is the reproducer: twelve lines of legal JavaScript that take the browser past its memory budget. This is an engine-level failure and the first positive result the corpus has produced - a denial of service on the WebProcess, not a wrong value, not a corruption and not a sandbox escape. Whether the allocation is unbounded or recursive is not established. `docs/WEBKIT_FINDINGS.md` Finding 7, `docs/WEBKIT_CORPUS.md` console results.
- The per-case runner was measured properly for the first time: 222 documents from index 288 to 509 with no memory refusal, about a tenth of a second per case (session `xd8deu`).
- Two harness defects fixed. A second document could walk the corpus in parallel with the first (two chains, one beacon counter, cases from both ends of the list in one log); every hop now carries a generation number and a stale document beacons `STALE-<g>` and stops. And the handoff navigated on regardless of `count`, so `count` bounded nothing; a case page now stops at `e=<end>` with `BATCH-END-<i>`, which is what makes a one-case measurement possible.
- Three stray `<<<<<<< HEAD` lines from an earlier cherry-pick were removed from this file.


## 2026-10-21: The public netcontrol use-after-free is a leak on 14.10

- Registering a socket with `cmd 0x20000003` takes a **reference** on it, and unregistering returns that reference. The peer of a `socketpair` shows it: no registration and the peer reads `0` (EOF) once the other end closes; with a registration it still reads `-1`, connected; register, unregister, close reads `0` again. `probes/phase17_new_vectors/233a_netcontrol_peer_state.lua`, `234a_netcontrol_ref_release.lua`, captures `results/phase17_new_vectors/233a_netcontrol_peer_state_20261021_144705.txt`, `results/phase17_new_vectors/234a_netcontrol_ref_release_20261021_144722.txt`.
- So the public Poops trigger - close the descriptor while it is registered, then unregister - does not free anything on 14.10. The socket stays referenced and alive, the unregister cannot resolve the dead descriptor and returns `-1`, and the reference is never returned. 219a's wedge is that leak, not a dangling pointer being walked; the descriptor lookup refusing is the patch working.
- The queue is per interface and `ifindex -1` is a single shared owner: with the wedge in place index `-1` and `0` return `-1` while index 1 returns `0`, an ordinary index survives the same trigger, index 3 holds two registrations at once, and only `-1` is spent for the boot across every later process until a power cycle. `probes/phase17_new_vectors/224a_netcontrol_ifindex_scope.lua`, `225a_netcontrol_clean_index_trigger.lua`, `226a_netcontrol_queue_capacity.lua`, `227a_netcontrol_wedge_scope.lua`, captures `results/phase17_new_vectors/224a_netcontrol_ifindex_scope_20261021_143238.txt`, `225a_netcontrol_clean_index_trigger_20261021_143255.txt`, `226a_netcontrol_queue_capacity_20261021_143323.txt`, `227a_netcontrol_wedge_scope_20261021_143826.txt`.
- A slab refill cannot separate a reference from a dangling pointer and does not here: after the orphan, 96 sockets, 32 `538` event flags, 32 `557` named objects and 8 kqueues changed nothing and nothing faulted. `probes/phase17_new_vectors/232a_netcontrol_ref_or_pointer.lua`, capture `results/phase17_new_vectors/232a_netcontrol_ref_or_pointer_20261021_144610.txt`. The peer's connection state is what separates them.
- Scope: nothing about `99 netcontrol` is a memory-corruption primitive on 14.10. The trigger leaks one socket and makes the `ifindex -1` queue unusable until a power cycle, from an unprivileged game process, and it survives the death of the process that caused it. The one public kernel-bug lead that maps onto a 14.10 syscall is closed. Full write-up in `docs/NETCONTROL_14_10.md`.
- Probe hygiene: the first 233a run died on `sgn((call(6, fd)))`, which truncates a multi-return and passes the userdata, and the second on `memory.read_dword` returning a table, so the fds needed `to_num`. Both were probe bugs, not console behaviour.

## 2026-10-21: The dynlib family takes structs, refuses canaries, and leaks nothing

- Canary-filling a struct API tests the wrong thing: `247a` filled the buffer and put the size at `+0`, and `593` - the control that works elsewhere in this repository - returned `-1` for every handle, because the fields the handler reads as version or flags held `0xA5A5A5A5`. Zeroing the struct and writing only the size gives `593(0, struct{size=0x160})` -> `0` with 17 dwords filled, the first at `+0x008` reading `0x6F6F6265` ("eboo"). Captures `results/phase17_new_vectors/247a_dynlib_size_field_20261021_152128.txt`, `results/phase17_new_vectors/248a_dynlib_zeroed_20261021_152141.txt`.
- `660 dynlib_get_info2` is the same call as `593` for handle 0: `0` and the identical 17 dwords, and handle 1 refuses in both. So the "2" variant adds nothing for a game process.
- `656 dynlib_get_info_for_libdbg` refuses every shape tried - `(0, struct)`, `(1, struct)`, size `0x160` and `0x1000`, and the struct in the first slot - returning `-1` and writing nothing. A libdbg call that refuses a game process is consistent with a debugger-credential gate, which this process does not have.
- `659 dynlib_get_list2` answers `-1` but writes two dwords for `(struct{size=0x160}, 64)`, the first at `+0x004` reading `0x13`. That is a count, not a pointer, and the call still fails.
- No kernel pointer in any of it: the kernel-half scan is zero across all twelve layouts, which matches the earlier finding that 593's deep fields are NID hashes rather than addresses.
- Probes `probes/phase17_new_vectors/246a_dynlib_libdbg.lua` (superseded, kept for the canary lesson), `247a_dynlib_size_field.lua`, `248a_dynlib_zeroed.lua`.

## 2026-10-21: The thread budget is a ceiling that varies, not a fixed number

- `245a` prints both `mmap` returns, the tid, `thr_create`'s return and the pid for every attempt: on a fresh loader (pid 123) only **nine** parkers were accepted and the tenth blocked inside `thr_create` while both mappings were valid, so a failing mapping is not the cause. Capture `results/phase17_new_vectors/245a_thread_spawn_trace_20261021_151853.txt`.
- Three loaders, three ceilings: 25 parkers on pid 106 (242a), eleven children on pid 118 (244a, two waiters among them), nine on pid 123 (245a). No mapping failed in any of them, and every accepted spawn returned `0` with the pid unchanged, so the block is the kernel refusing another thread and not the probe.
- Nothing is established about what the ceiling depends on. Kernel stack or thread-slot allocation is the plausible axis, and it is not worth more console time: the working rule is that a probe may spawn up to eight children, park them on `jmp $`, and expect a new loader for another batch.
- Correction to the entry below: "about twenty-five" was one loader, not a property of the firmware.

## 2026-10-21: An event flag holds one waiter at a time

- The first `542` on a clear bit blocks and leaves the result page alone (`0xDEADBEEF`, unchanged across a 200k-spin delay). A **second** `542` on the same flag with the same mask and a null timeout returns immediately and writes `0` into its own result page, while the first stays blocked. `544(H,1)` then completes only the first, whose page goes `0xDEADBEEF` -> `0x1`, and the second page stays `0`. `probes/phase17_new_vectors/244a_evf_waiter_pair.lua`, capture `results/phase17_new_vectors/244a_evf_waiter_pair_20261021_151611.txt`.
- So a flag accepts one waiting thread and answers any further concurrent wait with an immediate `0`/mask-`0` result. That is not a timeout - it is a refusal to queue a second waiter - and it is the whole explanation for 243a's page reading `0` before the set: ten waiters wrote their immediate zeroes into the same page, and the blocking one wrote `1` afterwards.
- Consequence for race work: a "wake N waiters" experiment needs N different flags, not N waiters on one flag.
- The same run then spawned only nine parkers before `thr_create` stopped returning, with two waiters afloat - eleven live children, where 242a allowed twenty-five without waiters. Whether that is a smaller budget when waiters exist or a failing mapping handing `thr_create` a bad context is not separable from this capture, so it is measured again in 245a with the map returns and the spawn returns printed per attempt.

## 2026-10-21: A child thread must park on return, and the process holds twenty-five

- 239a and 240a both ended with binary garbage on the console and a dead process, at the moment a parked waiter was cancelled (`546`) in one and completed (`544`) in the other. That was the probe, not the kernel: the child was spawned with `RIP = syscall_address` over a zeroed stack, so when the syscall returned the loader's wrapper `ret`-ed to address 0 and the thread ran wild inside the loader, clobbering its own output buffers. With the `jmp $` gadget at `RSP+0` the child parks instead, and `probes/phase17_new_vectors/241a_evf_cancel_parked.lua` shows every step answering: `544(H,2)` -> `0` with the wait page `0xDEADBEEF` -> `0x3`, `546(H,2)` after completion -> `0`, a fresh flag with its waiter cancelled by `546(H2,4)` -> `0` with the page going to `0`, `546(H3)` and `546(H3,1)` on a waiter-less flag -> `0`, and both `539 delete` -> `0`. Capture `results/phase17_new_vectors/241a_evf_cancel_parked_20261021_150126.txt`.
- So the wait's out value is the flag's whole set-bit state, not the bits that were asked for: the waiter requested bit 2 while bit 1 was already set, and the page received `3`.
- **Retraction:** 238a-240a's deaths and any reading that `546 evf_cancel` or a completed `544` faults are withdrawn. No event-flag call has been seen to fault.
- `probes/phase17_new_vectors/242a_thread_capacity_parked.lua` spawns children that park immediately (`RIP = jmp $`, stack filled with the same gadget) so no wild thread can confuse the count: **25 spawns returned `0` with the pid unchanged on that loader, and the 26th never returned** - `thr_create` blocks, the socket keeps accepting and no script runs. Reproduced on a fresh process (pid 106, capture `results/phase17_new_vectors/242a_thread_capacity_parked_20261021_150422.txt`; the run on the previous loader is `..._150245.txt`). The thread budget is real, its failure mode is a blocked `thr_create` rather than an error return, and the ceiling differs per loader (nine and eleven on two later processes, see the entry at the top).
- The 202a/207a/208a wedges recorded below are the same budget: those probes ran after earlier connections had already spawned threads in the same process, so their "third or fourth child" is the running total, not their own count. Rule for every future waiter probe: park the child on `jmp $`, and count the process's threads rather than the script's.

## 2026-10-21: Three more Sony calls answer without writing

- `634 thr_get_ucontext` is not a register dump: with a real live TID (a spinning child confirmed by `thr_kill(tid,0)` -> `0`) it wrote nothing into a canary page for `(tid, buf)`, `(tid, buf, 0x400)`, `(buf, tid)`, `(tid, buf, 0x1000)` and the caller's own tid, and the process survived every call. `probes/phase17_new_vectors/235a_ucontext_live_tid.lua`, capture `results/phase17_new_vectors/235a_ucontext_live_tid_20261021_145605.txt`.
- `657 blockpool_batch` writes one dword `0` at `buf+0` for every count 0..8, returns `0` only at count 0, repeats it on consecutive calls, and still writes after `close(h)`: an unconditional out-status, not a copy, with no descriptor revalidation. `probes/phase17_new_vectors/236a_blockpool_batch_write.lua`, capture `results/phase17_new_vectors/236a_blockpool_batch_write_20261021_145629.txt`.
- `547 query_memory_protection` is a real process-VM region lookup but not a kernel address oracle: a mapped page returns `0` with `[0x111FC000 0x3 0x11200000 0x3 0x3 0x610020]`, the same address after `munmap` returns `-1` with the canary intact, a never-mapped low address returns `-1`, and 32 kernel addresses across `0xFFFFFFFF80000000` and `0xFFFF800000000000` all return `-1` and write nothing. `probes/phase17_new_vectors/237a_query_protection_oracle.lua`, capture `results/phase17_new_vectors/237a_query_protection_oracle_20261021_145710.txt`.
- Scope: none of the three is a primitive. The 547 result is the useful one - the region walk refuses kernel addresses at the same point it refuses unmapped user addresses, so it cannot be turned into a KASLR oracle.

## 2026-10-21: The last object families in the Sony range create nothing usable

- `probes/phase17_new_vectors/251a_jitshm.lua` calls the only remaining descriptor-based object family. `533 jitshm_create` returns `-1` for sizes `0`, `0x1000`, `0x4000`, `0x100000` and flags `0`, `1`, `0xFFFFFFFF`, so there is no descriptor for `534 jitshm_alias` to alias; the alias call returns `-1` for a socket fd and for fd `0xFFFF`. `535 dl_get_list` and `536 dl_get_info` return `-1` with a zeroed struct carrying only its size at `+0` and write nothing. Capture `results/phase17_new_vectors/251a_jitshm_20261021_153538.txt`.
- `probes/phase17_new_vectors/252a_osem_family.lua`: `549 osem_create` returns `-1` for eight scalar shapes, and `probes/phase17_new_vectors/253a_osem_namedobj_name.lua` gets `-1` from it with a NUL-terminated name pointer in either slot. The wait/post/cancel half of the family was therefore never exercised. Captures `..._252a_osem_family_20261021_153559.txt`, `..._253a_osem_namedobj_name_20261021_153612.txt`.
- `557 namedobj_create` does accept a name and return a handle - `0x4205`, then `0x206`, `0x207` - which is what made the family worth the next probe. `probes/phase17_new_vectors/254a_namedobj_identity.lua` then calls it four times on the **same** name: `0x208`, `0x209`, `0x20A`, `0x20B`. The name is not a key, so four distinct objects exist under one name and no lookup exists to be aimed at a freed one. `558` deletes by handle (`0` each), reissues the index (`0x220B`), and returns `-1` for `0xDEAD` and `0`; `557` returns `-1` for a NULL and for an unmapped name pointer. Capture `..._254a_namedobj_identity_20261021_153631.txt`.
- `probes/phase17_new_vectors/255a_set_vm_container.lua` and `256a_vm_container_accept.lua`: `559 set_vm_container` returns `-1` for ids `0`-`8`, `0xF`, `0x100`, `0x7FFFFFFF`, `0x80000000`, `0xFFFFFFFE` and `0x100000000`, and `1` for `0xFFFFFFFF` - twice, in two processes. It is a report, not a switch: the mapping made before it keeps the identical `547` record afterwards and the next mmap lands in the same region. Captures `..._255a_set_vm_container_20261021_153651.txt`, `..._256a_vm_container_accept_20261021_153708.txt`.
- `probes/phase17_new_vectors/257a_process_pair.lua`: `560 debug_init(1)` returns `0` where `0`, `0x10`, `(0,0x10)` and `(0x1000,0x1000)` return `-1`. `561 suspend_process(0)` kills the process before `562 resume_process` can be measured. Capture `..._257a_process_pair_20261021_153735.txt`.
- `probes/phase17_new_vectors/258a_debug_init_effect.lua` asks what that success unlocks, and the answer is nothing measurable: after `560(1)`, `656 dynlib_get_info_for_libdbg` still returns `-1`, `593` mode 1 still returns `-1` while mode 0 still returns the same 17-dword module record, `634` still writes nothing, `mprotect` to RX and to RWX still return `-1`, and `643` still returns `0` with no effect. `560(1)` is in the same class as `675`: a success with no observable capability. Capture `..._258a_debug_init_effect_20261021_154044.txt`.
- `probes/phase17_new_vectors/249a_evf_set_vs_cancel.lua` closes the evf race question: with a blocked waiter, a canceling child and a setting main thread, three rounds all end with the waiter's page at `0` and every call returning `0`, so the cancel's write is the last one to land and nothing corrupts. Its first run passed a null result pointer and measured nothing; that run's capture was deleted rather than kept as evidence. Capture `..._249a_evf_set_vs_cancel_20261021_152445.txt`.
- Presence, measured one connection per number: `523` and `524` are present and return `-1`, `525`-`529` (the `rctl_*` family) kill the process, and `530` answers nothing on two attempts, so `530`, `531`, `532` and `537` are still unmeasured; `533`-`536` are present because they answer `-1` above. Record `results/phase15_native_sysent/syscall_isolation_sweep_20261021_152457.*`.
- Scope: this closes the object-side surface of the Sony range. Every family that creates an object is either unreachable (`osem`, `jitshm`), has no consumer that resolves a name (`namedobj`), or is reference-counted (`evf`). Nothing here is a memory-corruption primitive.
## 2026-10-21: umtx ops above 17 block, and a blocked thread reads the same as a returned one

- `probes/phase17_new_vectors/269a_umtx_high_ops.lua` runs ops 16-22, one child per op on its own word, and checks liveness with `thr_kill`. Every `thr_kill(tid, 0)` returns `0`, so every child is still alive, and a parked child and a blocked child are the same thing to that call.
- `probes/phase17_new_vectors/270a_umtx_sentinel.lua` gives the word a sentinel to separate the two cases. For 454 the first argument is the word and the parked stub stores `rax` through `rdi`, so a completed call leaves its return value where the word was. Ops 18-21 on a word filled with `A5A5A5A5A5A5A5A5` leave it untouched, which means those calls did not return; on a zeroed word the same ops leave zero, which is the ambiguous case.
- `269a` recorded one non-deterministic write: op 19 left `0x1` in its word in that run and left `0` in `270a`, so at least one of these ops writes state before it sleeps.
- Scope: no primitive, and no way to interpret the results without the op table. The barrier is not the console, it is that a blocked thread and a returned thread are indistinguishable from this process, so every discriminating experiment ends in "the thread slept".

## 2026-10-21: Device descriptors are real, and their ioctls are refused by the driver

- `probes/phase17_new_vectors/267a_ioctl_control.lua` establishes that syscall 54 is ioctl and works: `FIOCLEX` and `FIONCLEX` return `0` on a socket. `FIONBIO` returns `-1` there, which is a socket-layer refusal rather than a syscall one.
- `probes/phase17_new_vectors/268a_device_fd_reality.lua` shows the device descriptors are genuine. `read(16)` returns 16 bytes from `zero`, 16 from `random` and `urandom`, 0 from `null` and `-1` from `dce`; `FIOCLEX`/`FIONCLEX` return `0` on all five, so the fdesc layer accepts them. `FIONBIO` returns `0` on `zero`, `null`, `random` and `urandom` but `-1` on `dce`, so `dce` has its own `d_ioctl` and that handler is the thing refusing.
- `probes/phase17_new_vectors/265a_dce_ioctl_buffer.lua` offers `/dev/dce` commands `0x00`-`0xFF` with a zeroed `0x1000`-byte buffer: every one returns `-1` and no byte is written. `264a_ioctl_sweep.lua` had already tried `0x00`-`0x1F` with a null buffer, and `267a` tried a request struct whose first dword is the command. The command encoding is not a small integer, so the space cannot be brute-forced; hitting it needs the driver's table, which needs a kernel image.
- `probes/phase17_new_vectors/266a_aio_real_fd.lua` closes the AIO question. With a real `/dev/zero` descriptor and a full FreeBSD `aiocb` (`fildes`, `offset`, `buf`, `nbytes`, `sigevent`, `lio_opcode`) 661 still kills the process before its result row prints, which is the third argument shape to die there. The `mmap` it used for the read buffer also returned `-1`, so that row is unmeasured.
- `264a` also recorded an open-mode split: `dce` and `gic` accept `O_RDWR`, while `ajm` and `rng` open read-only.
- Captures: `results/phase17_new_vectors/264a_ioctl_sweep_20261021_155109.txt`, `..._265a_dce_ioctl_buffer_20261021_155514.txt`, `..._266a_aio_real_fd_20261021_155530.txt`, `..._267a_ioctl_control_20261021_155811.txt`, `..._268a_device_fd_reality_20261021_155843.txt`.
- Scope: the device surface is reachable and real, and every driver-specific command is refused. No primitive, and no way to search the command space without the driver table.

## 2026-10-21: The game process can open 34 of the 76 device nodes

- `probes/phase17_new_vectors/259a_dev_listing.lua` reads `/dev` for the first time instead of guessing names. `open("/dev", O_RDONLY)` then `getdirentries` (196) returns `0x550` bytes, and the kernel reports the **32-bit dirent layout**: `u32 d_fileno`, `u16 d_reclen` at `+4`, `u8 d_type` at `+6`, `u8 d_namlen` at `+7`, name at `+8`. Parsing it as the 24-byte 64-bit header finds nothing, which is what the first attempt did. 76 nodes: `random`, `urandom`, `dipsw`, `fd`, the `deci_tty*` set, `null`, `zero`, the `hmd2_*` and `hmd_*` sets, `sce_zlib`, `bt`, `hid`, `mp3`, `dmem0`-`dmem2`, `gc`, `ajmi`, `ajm`, `dce`, `rng`, `dbggc`, `sbl_srv`, `encdec`, `uvd_dec`, `uvd_enc`, `fttrm`, `duid`, `acm`, `gic`, `notification0`-`notification7`, `usbctl`, `camera`, `a53mm`, `a53mmsys`, `usb`, `ugen*`. Capture `results/phase17_new_vectors/259a_dev_listing_20261021_154548.txt`.
- `probes/phase17_new_vectors/261a_device_ioctl_reach.lua` opens, probes and closes one node at a time: **34 of the 76 open** from this game process - `random`, `urandom`, `dipsw`, `fd`, `stdin`, `null`, `zero`, `deci_stdin`, `hmd2_cmd`, `hmd2_imu`, `hmd2_leddet`, `hmd2_gaze`, `hmd_cmd`, `hmd_snsr`, `hmd_3da`, `hmd_dist`, `bt`, `hid`, `dmem0`, `dmem1`, `dmem2`, `gc`, `ajmi`, `ajm`, `dce`, `rng`, `gic`, `notification0`, `notification6`, `notification7`, `usbctl`, `camera`, `usb`, `ugen0.2`. `dbggc`, `deci_stdout`, the rest of `deci_tty*`, `uvd_dec`, `uvd_enc`, `sbl_srv`, `encdec`, `fttrm`, `duid`, `acm`, `a53mm`, `a53mmsys`, `mp3`, `notification1` and every `ugen*` except `ugen0.2` refuse with `-1`. Capture `..._261a_device_ioctl_reach_20261021_154649.txt`.
- The ioctl path is not filtered. `ioctl(fd, 0)` returns `-1` rather than killing, for all 34 open nodes, and `TIOCGETA` on a tty returns `-1` with the buffer untouched. So the syscall reaches the drivers and the drivers reject the command; the surface is open to a command search rather than closed at the syscall.
- `probes/phase17_new_vectors/262a_dmem_partitions.lua` and `263a_dmem_read_prot.lua` re-check the dmem partitions with the shape the older probe used. `262a` maps with `PROT_READ|PROT_WRITE` and gets `-1` from all three at every offset, while `263a` with `PROT_READ` maps `dmem0` and `dmem1` and their page at offset 0 holds 228 live qwords, the first being `0x80000000_C0012800`. Every offset above 0 - `0x1000`, `0x1000000`, `0x100000000` - maps all-zero, and `dmem2` refuses every shape. `PROT_READ|PROT_WRITE` does map `dmem0` once the open uses `O_RDWR`, but no byte was written, so the aperture-only reading stands. Captures `..._262a_dmem_partitions_20261021_154707.txt`, `..._263a_dmem_read_prot_20261021_154812.txt`.
- Scope: no primitive. What changed is that the device surface is an inventory with a per-node open and refuse table, and every node that opens is a driver that can be handed a command.

## 2026-10-21: A netcontrol registration outlives its descriptor

- The public Poops chain's use-after-free is a descriptor closed while it is registered. `probes/phase17_new_vectors/219a_netcontrol_close_registered.lua` does exactly that on 14.10: register fd 28 -> `0`, `close(28)` -> `0`, a new socket takes number 28 again, and the unregister of the closed descriptor returns `-1`. Nothing dies and the descriptor table keeps working. Capture `results/phase17_new_vectors/219a_netcontrol_close_registered_20261021_141946.txt`.
- The failed unregister leaves the queue in a state no later call can clear. `probes/phase17_new_vectors/221a_netcontrol_stale_registration.lua` then registers and unregisters three freshly opened descriptors 28, 29 and 30, and a fourth at 31: every call returns `-1`. So the block is process-wide rather than per-descriptor, and one orphaned registration makes the subsystem unusable for the rest of the process. Capture `results/phase17_new_vectors/221a_netcontrol_stale_registration_20261021_142008.txt`.
- `220a` measured nothing: it ran in the same process after 219a, so its `-1` registers are the wedge 219a produced, not an answer about its own trigger. The trigger is re-ordered in `probes/phase17_new_vectors/222a_netcontrol_clean_trigger.lua`, which runs a control register/unregister pair first and skips the trigger unless both returned `0`.
- The process holding the orphaned entry was then killed with an absent syscall and the loader did not answer within the following 60 s, which is longer than the 24.7 s a repeated kill costs on a busy boot (`results/phase17_new_vectors/restart_pressure_20261021_133337.txt`). Whether that is an ordinary restart and whether the console panicked is not yet distinguished; the decisive run is `222a` on a fresh loader.
- Scope: nothing here is a memory-corruption primitive. What is established is that the queue keeps state past the lifetime of the descriptor it names - the precondition for the public chain's bug - and that the teardown of that state is what the console reacted to.

## 2026-10-21: netcontrol (99) still accepts the netevent queue commands

- `99 netcontrol` was only ever measured as "present, `-1` on six zeros". It is the syscall the scene's one public kernel chain (Poops) drives, so the ABI mattered more than the return value. `probes/phase17_new_vectors/218a_netcontrol_abi.lua` calls it in the documented shape `__sys_netcontrol(ifindex, cmd, buf, size)` and 14.10 answers: `(-1, 0x20000003, buf{fd}, 8)` -> `0` registers the socket, `(-1, 0x20000007, buf{fd}, 8)` -> `0` unregisters it. Capture `results/phase17_new_vectors/218a_netcontrol_abi_20261021_140851.txt`.
- The arguments are validated rather than ignored: fd `0xFFFF` and fd `0` return `-1` for both commands, a NULL buffer returns `-1`, and the size must reach 8 - `size` 0 and 4 return `-1` while 8, 16 and 64 return `0`, so the handler reads an int at `buf[0]` and nothing else.
- The registration is not one-shot: register, unregister and register again on the same open descriptor return `0` each time, and three fresh sockets each register and unregister cleanly. Of the sixteen commands `0x20000000`-`0x2000000F`, only `0x20000003` and `0x20000007` are accepted, so the command space is narrow and known.
- Scope: the public chain's use-after-free needs the descriptor to be **closed while registered**. This probe never does that - every register is followed by an unregister on the same open fd - so nothing here says whether the free path still exists on 14.10. It says the subsystem is compiled in, reachable from a game process, and argument-checked.
- On the netcontrol question in general: the public Poops chain (Gezine/egycnq, from TheFlow's `ExploitNetControlImpl`) tops out at 12.00, and Sony has had four firmware lines since, so the queue code has been reworked. A follow-up probe can close a registered descriptor and then unregister it, which is the trigger; that is a kernel-panic risk and not something to run blind.

## 2026-10-21: The event flag handle generation wraps after eight reuses

- `probes/phase17_new_vectors/209a_evf_waiter_across_reuse.lua`: a waiter blocked on a flag with a null timeout; `539 delete` returned `0` and its result page went `DEADBEEF` -> `0`; the freed index was reissued for a new flag straight away, and neither `544 set` nor `543 poll` on the new flag touched the old waiter's page. Capture `results/phase17_new_vectors/209a_evf_waiter_across_reuse_20261021_121811.txt`.
- The handle word is `generation << 13 | index`. Four create/delete rounds on one slot give `0x206`, `0x2206`, `0x4206`, `0x6206`, and twenty rounds give `207 2207 4207 6207 8207 A207 C207 E207` then `207` again: eight generation values, no wider tag, exact handle reuse every eight reuses. Captures `results/phase17_new_vectors/210a_evf_generation_wrap_20261021_121823.txt`, `211a_evf_generation_sequence_20261021_121831.txt`.
- Because the reuse is exact, a handle captured eight churns earlier is byte-identical to the live object's handle and drives it: `544(stale, 1)` returned `0` and `543(live, 1, 1)` then returned `0`. The class check still holds, so the stale alias cannot cross object classes - `558` on an evf handle and `539` on a namedobj handle return `-1`, and the object stays usable. Captures `results/phase17_new_vectors/212a_evf_stale_handle_20261021_121844.txt`, `213a_evf_class_blind_20261021_121853.txt`.
- `538`/`557` accept names up to 31 characters and return `-1` at 32, and `-1` for a NULL name, so the name copy is bounded and length-checked rather than length-trusting. Capture `results/phase17_new_vectors/216a_evf_name_bound_20261021_122014.txt`.
- The `542` timeout is still unidentified. `{0,0}` and `{0, 120000000}` return within about one scheduler tick with mask `0`; `{0, 500000000}`, `{50000000,0}`, `{150000000,0}` and `{400000000,0}` block; an uptime-derived pair `{2243, 528426302}` returns in 11 ms and `{1792581070, 187000000}` blocks. Neither a relative nanosecond field nor an absolute uptime deadline fits, and the `{1,0}` case wedged the loader. Captures `results/phase17_new_vectors/205a_evf_deadline_clock_20261021_121135.txt`, `206a_evf_timeout_unit_20261021_121433.txt`, `207a_evf_timeout_corners_20261021_121507.txt`.
- The wedges from 202a, 207a and 208a share one cause, measured later in 242a: `thr_create` stops returning once about twenty-five threads are live in the process, and parked waiters never exit. Those three probes inherited threads from earlier connections, which is why they stalled at their third or fourth spawn. See the 241a/242a entry at the top.

## 2026-10-21: The event flag family is live, and its wait blocks

- `538 evf_create` is not a stub: given a name pointer and a non-zero bit count it returns a handle (`546`-`552`), and `557 namedobj_create` keeps handing out from the same table. `544 set`, `543 poll`, `542 wait`, `539`/`558` delete all answer. `probes/phase17_new_vectors/192a_stateful_abi.lua`, `193a_handle_lifecycle.lua`, capture `results/phase17_new_vectors/192a_stateful_abi_20261021_115932.txt`.
- Handles carry an index and a generation (`0x2000 | index` for evf, `0x4000`/`0x6000` for the others; 518, 545 and 8737 are the same index at three generations), and both delete paths check the class: `558` on an evf handle and `539` on a namedobj handle return `-1` and leave the object alive, so the shared table is not a type-confusion route. Capture `results/phase17_new_vectors/197a_handle_class_confusion_20261021_120244.txt`.
- `543` is `(handle, bits, mode)`: a 3x3 matrix shows only `mode` 1 and 2 succeed and only when the requested bit is set; `mode` 0 fails, a clear bit fails, and polling twice returns `0` both times, so polling does not consume the bit. `542` accepts the same three leading arguments and, with a null fifth argument, **blocks** - a child thread slept until `544` from the main thread set the bit, and the satisfied mask appeared in the fourth argument, a page we own (`DEADBEEF` -> `1`). Captures `results/phase17_new_vectors/195a_evf_mask_mode_20261021_120109.txt`, `200a_evf_wait_blocking_20261021_120516.txt`.
- `539 delete` on a flag that has a blocked waiter returns `0` and wakes the waiter with mask `0`; the freed index is handed out again immediately with a bumped generation. No fault and no double free are visible from userland, so whether the waiter was dropped from the object before the free is not settled. Capture `results/phase17_new_vectors/201a_evf_delete_under_wait_20261021_120547.txt`.
- `542`'s fifth argument is a timeout, but a page holding `{tv_sec = 0, tv_nsec = 120000000}` makes the wait return immediately with mask `0`, which is what an absolute deadline in 1970 would do; a null fifth argument blocks. `probes/phase17_new_vectors/202a_evf_wait_layout.lua` and `203a_evf_deadline_timer.lua` carry the elapsed-time test. Capture `results/phase17_new_vectors/202a_evf_wait_layout_20261021_120645.txt` (the run wedged the loader at the fourth layout).
- Hazard, recorded in `docs/ATTACK_SURFACE.md`: `thr_kill(tid, 0)` only answers whether the thread exists, so a thread asleep in a wait is not reclaimed; each parked waiter spends a thread slot permanently, and after four of them `thr_create` stopped returning and wedged the Lua thread. Delete the object to wake a waiter.

## 2026-10-21: The blockpool handles are file descriptors with no consumer

- `653 blockpool_open` was the one number in the 601-660 block whose answer changed between calls, and the 22/23/24 sequence read either as handles or as `EINVAL`/`ENFILE`/`EMFILE`. `probes/phase17_new_vectors/190a_blockpool_fd_semantics.lua` separates the two by moving the descriptor table: a socket opened first answered `22`, then `653` answered `23`, `24`, `25`, `-1`; `close(23)` returned `0` and the next open answered `22` again. Capture `results/phase17_new_vectors/190a_blockpool_fd_semantics_20261021_113658.txt`.
- The limit is three concurrent handles per process and closing frees a slot: a restarted loader (pid 87) gave `22, 23, 24` then `-1`, and closing all three gave the same three again. Capture `results/phase17_new_vectors/191a_blockpool_descriptor_20261021_114008.txt`.
- Nothing consumes the descriptor. `mmap` returns `-1` for `MAP_SHARED`, `0x1002` and two lengths; `read`, `write`, `ioctl` return `-1`; `654 blockpool_map`, `655 blockpool_unmap`, `673 blockpool_move` return `-1` for every layout. `657 blockpool_batch` returns `0` and zeroes the dword at arg3 even after the handle was closed, but the only bytes it writes are zeroes, so nothing can be read back. Recorded in `docs/ATTACK_SURFACE.md`.

## 2026-10-20: The presence map covers 595 slots

- Sweep `104-537`: 328 numbers reached, 238 returned, 89 killed, `432 thr_self` produced no output and stopped the run. Capture `results/phase15_native_sysent/syscall_isolation_sweep_20261020_213026.json`.
- Six handlers return a positive FreeBSD errno instead of the loader's `-1`: `125` -> 4, `141` -> 22, `310` -> 54, `330` -> 1, `362` -> 22, `429` -> 14. Positive returns are the only unambiguous sign that a handler ran and rejected the arguments, and `docs/SYSCALL_ABSENT_VS_LETHAL.md` gains the four-way reading (positive errno, `0`, `-1`, nothing).
- `tools/gen_presence_map.py --write` regenerated `docs/SYSENT_PRESENCE_14_10.md` from every sweep record: 595 slots, `kills` where the process died and `present` otherwise.

## 2026-10-20: The ucontext cannot name a kernel code selector

- `probes/phase17_new_vectors/189a_cs_selector_mask.lua` tests the `SEL_RPL_MASK` question directly. The user code selector on 14.10 is `0x43` (index 8, RPL 3); the same index with RPL 0 is `0x40`. With the mask the kernel rewrites `0x40` to `0x43` and the thread parks; without it `0x40` names a DPL-3 descriptor at CPL 0 and the `iretq` panics. Measured: control `CS=0x43` parked with `tid=0x18EDD`, `CS=0x40` returned `rv=0` with `tid=0x18EEF`, and the canary answered `pid=827` after both. Capture `results/phase17_new_vectors/189a_cs_selector_mask_20261020_210825.txt`.
- So the `thr_create` defect is a panic only: the ucontext cannot raise CPL, and `docs/THR_CREATE_PANIC_PATH_13.60.md` records the test next to the two scenarios it discriminates.

## 2026-10-20: The loader port comes back before the loader does

- `probes/phase17_new_vectors/188a_sys94_repeat.lua` clears the sweep's stop at syscall 94: three rounds of six zeros, fds 1/2/0/3 and `0x1000` in every slot all return `-1`, `getpid` answers `0x334` between each pair, and the script finishes. Capture `results/phase17_new_vectors/188a_sys94_repeat_20261020_210214.txt`.
- The stop was a loader state, not the syscall: after 93's kill the listener accepted again while the Lua thread never answered, for minutes, until a relaunch. `tools/send_probe.py` gains `loader_answers()`, which sends `print("LOADER-READY")` and waits for the reply, and `wait_for_loader(..., answers=True)` uses it on every poll; `tools/syscall_isolation_sweep.py` and `tools/bounds_fuzz.py` both pass the flag, so a listener without a thread stops the run instead of being swept into. 36 tests pass.
- `docs/SYSCALL_ABSENT_VS_LETHAL.md` records the state and how to tell it from a park.

## 2026-10-20: A size-fuzz driver for the Sony handlers, and a kill that outlives four minutes

- New `tools/bounds_fuzz.py` varies what the present Sony handlers in 574-660 are *told* about their buffer instead of only reading their return value. The generated probe allocates 0x6000 bytes, canvases them, hands the handler a pointer 0x2000 inside and, after the call, counts dwords changed inside the declared size and outside it. A write outside the size is `OVERFLOW`; a write while the size is zero is `WROTE_AT_ZERO_SIZE`, which is the same finding from the other side. One connection per `(number, layout, size)` triple, layouts move the buffer and the size between argument positions, `--wait-for-loader` resumes after a kill. Sizes above 0x10000 print a warning: a handler that trusts the size can drive the copy into unmapped memory and panic the console, which needs a power cycle rather than a relaunch. `tools/test_bounds_fuzz.py` covers the probe builder, response parsing, the two verdicts and the retry loop; 11 tests, no console needed.
- `docs/SYSCALL_ABSENT_VS_LETHAL.md` gains "Not every kill recovers in nine seconds". The 9.31 s self-restart is the loader-only case: `sys 1 exit`, `sys 8 compat.creat` and `sys 9 munmap` each left port 9026 refusing for longer than the sweep's 240 s wait, so the game goes down with the process and nothing is left to bring the loader back. The `9-537` sweep aborted at number 9 for that reason; `--wait-for-loader` remains the fast path, not a guarantee.


## 2026-10-21: A netcontrol registration outlives its descriptor

- The public Poops chain's use-after-free is a descriptor closed while it is registered. `probes/phase17_new_vectors/219a_netcontrol_close_registered.lua` does exactly that on 14.10: register fd 28 -> `0`, `close(28)` -> `0`, a new socket takes number 28 again, and the unregister of the closed descriptor returns `-1`. Nothing dies and the descriptor table keeps working. Capture `results/phase17_new_vectors/219a_netcontrol_close_registered_20261021_141946.txt`.
- The failed unregister leaves the queue in a state no later call can clear. `probes/phase17_new_vectors/221a_netcontrol_stale_registration.lua` then registers and unregisters three freshly opened descriptors 28, 29 and 30, and a fourth at 31: every call returns `-1`. So the block is process-wide rather than per-descriptor, and one orphaned registration makes the subsystem unusable for the rest of the process. Capture `results/phase17_new_vectors/221a_netcontrol_stale_registration_20261021_142008.txt`.
- `220a` measured nothing: it ran in the same process after 219a, so its `-1` registers are the wedge 219a produced, not an answer about its own trigger. The trigger is re-ordered in `probes/phase17_new_vectors/222a_netcontrol_clean_trigger.lua`, which runs a control register/unregister pair first and skips the trigger unless both returned `0`.
- The process holding the orphaned entry was then killed with an absent syscall and the loader did not answer within the following 60 s, which is longer than the 24.7 s a repeated kill costs on a busy boot (`results/phase17_new_vectors/restart_pressure_20261021_133337.txt`). Whether that is an ordinary restart and whether the console panicked is not yet distinguished; the decisive run is `222a` on a fresh loader.
- Scope: nothing here is a memory-corruption primitive. What is established is that the queue keeps state past the lifetime of the descriptor it names - the precondition for the public chain's bug - and that the teardown of that state is what the console reacted to.

## 2026-10-21: netcontrol (99) still accepts the netevent queue commands

- `99 netcontrol` was only ever measured as "present, `-1` on six zeros". It is the syscall the scene's one public kernel chain (Poops) drives, so the ABI mattered more than the return value. `probes/phase17_new_vectors/218a_netcontrol_abi.lua` calls it in the documented shape `__sys_netcontrol(ifindex, cmd, buf, size)` and 14.10 answers: `(-1, 0x20000003, buf{fd}, 8)` -> `0` registers the socket, `(-1, 0x20000007, buf{fd}, 8)` -> `0` unregisters it. Capture `results/phase17_new_vectors/218a_netcontrol_abi_20261021_140851.txt`.
- The arguments are validated rather than ignored: fd `0xFFFF` and fd `0` return `-1` for both commands, a NULL buffer returns `-1`, and the size must reach 8 - `size` 0 and 4 return `-1` while 8, 16 and 64 return `0`, so the handler reads an int at `buf[0]` and nothing else.
- The registration is not one-shot: register, unregister and register again on the same open descriptor return `0` each time, and three fresh sockets each register and unregister cleanly. Of the sixteen commands `0x20000000`-`0x2000000F`, only `0x20000003` and `0x20000007` are accepted, so the command space is narrow and known.
- Scope: the public chain's use-after-free needs the descriptor to be **closed while registered**. This probe never does that - every register is followed by an unregister on the same open fd - so nothing here says whether the free path still exists on 14.10. It says the subsystem is compiled in, reachable from a game process, and argument-checked.
- On the netcontrol question in general: the public Poops chain (Gezine/egycnq, from TheFlow's `ExploitNetControlImpl`) tops out at 12.00, and Sony has had four firmware lines since, so the queue code has been reworked. A follow-up probe can close a registered descriptor and then unregister it, which is the trigger; that is a kernel-panic risk and not something to run blind.

## 2026-10-21: The event flag handle generation wraps after eight reuses

- `probes/phase17_new_vectors/209a_evf_waiter_across_reuse.lua`: a waiter blocked on a flag with a null timeout; `539 delete` returned `0` and its result page went `DEADBEEF` -> `0`; the freed index was reissued for a new flag straight away, and neither `544 set` nor `543 poll` on the new flag touched the old waiter's page. Capture `results/phase17_new_vectors/209a_evf_waiter_across_reuse_20261021_121811.txt`.
- The handle word is `generation << 13 | index`. Four create/delete rounds on one slot give `0x206`, `0x2206`, `0x4206`, `0x6206`, and twenty rounds give `207 2207 4207 6207 8207 A207 C207 E207` then `207` again: eight generation values, no wider tag, exact handle reuse every eight reuses. Captures `results/phase17_new_vectors/210a_evf_generation_wrap_20261021_121823.txt`, `211a_evf_generation_sequence_20261021_121831.txt`.
- Because the reuse is exact, a handle captured eight churns earlier is byte-identical to the live object's handle and drives it: `544(stale, 1)` returned `0` and `543(live, 1, 1)` then returned `0`. The class check still holds, so the stale alias cannot cross object classes - `558` on an evf handle and `539` on a namedobj handle return `-1`, and the object stays usable. Captures `results/phase17_new_vectors/212a_evf_stale_handle_20261021_121844.txt`, `213a_evf_class_blind_20261021_121853.txt`.
- `538`/`557` accept names up to 31 characters and return `-1` at 32, and `-1` for a NULL name, so the name copy is bounded and length-checked rather than length-trusting. Capture `results/phase17_new_vectors/216a_evf_name_bound_20261021_122014.txt`.
- The `542` timeout is still unidentified. `{0,0}` and `{0, 120000000}` return within about one scheduler tick with mask `0`; `{0, 500000000}`, `{50000000,0}`, `{150000000,0}` and `{400000000,0}` block; an uptime-derived pair `{2243, 528426302}` returns in 11 ms and `{1792581070, 187000000}` blocks. Neither a relative nanosecond field nor an absolute uptime deadline fits, and the `{1,0}` case wedged the loader. Captures `results/phase17_new_vectors/205a_evf_deadline_clock_20261021_121135.txt`, `206a_evf_timeout_unit_20261021_121433.txt`, `207a_evf_timeout_corners_20261021_121507.txt`.
- The wedges from 202a, 207a and 208a share one cause: `thr_create` stops returning once roughly fifteen to nineteen threads have been spawned in a process, and parked waiters never exit. A session therefore supports a handful of child threads and then needs a relaunch; the timeout probes were cut short by this rather than by the calls under test.

## 2026-10-21: The event flag family is live, and its wait blocks

- `538 evf_create` is not a stub: given a name pointer and a non-zero bit count it returns a handle (`546`-`552`), and `557 namedobj_create` keeps handing out from the same table. `544 set`, `543 poll`, `542 wait`, `539`/`558` delete all answer. `probes/phase17_new_vectors/192a_stateful_abi.lua`, `193a_handle_lifecycle.lua`, capture `results/phase17_new_vectors/192a_stateful_abi_20261021_115932.txt`.
- Handles carry an index and a generation (`0x2000 | index` for evf, `0x4000`/`0x6000` for the others; 518, 545 and 8737 are the same index at three generations), and both delete paths check the class: `558` on an evf handle and `539` on a namedobj handle return `-1` and leave the object alive, so the shared table is not a type-confusion route. Capture `results/phase17_new_vectors/197a_handle_class_confusion_20261021_120244.txt`.
- `543` is `(handle, bits, mode)`: a 3x3 matrix shows only `mode` 1 and 2 succeed and only when the requested bit is set; `mode` 0 fails, a clear bit fails, and polling twice returns `0` both times, so polling does not consume the bit. `542` accepts the same three leading arguments and, with a null fifth argument, **blocks** - a child thread slept until `544` from the main thread set the bit, and the satisfied mask appeared in the fourth argument, a page we own (`DEADBEEF` -> `1`). Captures `results/phase17_new_vectors/195a_evf_mask_mode_20261021_120109.txt`, `200a_evf_wait_blocking_20261021_120516.txt`.
- `539 delete` on a flag that has a blocked waiter returns `0` and wakes the waiter with mask `0`; the freed index is handed out again immediately with a bumped generation. No fault and no double free are visible from userland, so whether the waiter was dropped from the object before the free is not settled. Capture `results/phase17_new_vectors/201a_evf_delete_under_wait_20261021_120547.txt`.
- `542`'s fifth argument is a timeout, but a page holding `{tv_sec = 0, tv_nsec = 120000000}` makes the wait return immediately with mask `0`, which is what an absolute deadline in 1970 would do; a null fifth argument blocks. `probes/phase17_new_vectors/202a_evf_wait_layout.lua` and `203a_evf_deadline_timer.lua` carry the elapsed-time test. Capture `results/phase17_new_vectors/202a_evf_wait_layout_20261021_120645.txt` (the run wedged the loader at the fourth layout).
- Hazard, recorded in `docs/ATTACK_SURFACE.md`: `thr_kill(tid, 0)` only answers whether the thread exists, so a thread asleep in a wait is not reclaimed; each parked waiter spends a thread slot permanently, and after four of them `thr_create` stopped returning and wedged the Lua thread. Delete the object to wake a waiter.

## 2026-10-21: The blockpool handles are file descriptors with no consumer

- `653 blockpool_open` was the one number in the 601-660 block whose answer changed between calls, and the 22/23/24 sequence read either as handles or as `EINVAL`/`ENFILE`/`EMFILE`. `probes/phase17_new_vectors/190a_blockpool_fd_semantics.lua` separates the two by moving the descriptor table: a socket opened first answered `22`, then `653` answered `23`, `24`, `25`, `-1`; `close(23)` returned `0` and the next open answered `22` again. Capture `results/phase17_new_vectors/190a_blockpool_fd_semantics_20261021_113658.txt`.
- The limit is three concurrent handles per process and closing frees a slot: a restarted loader (pid 87) gave `22, 23, 24` then `-1`, and closing all three gave the same three again. Capture `results/phase17_new_vectors/191a_blockpool_descriptor_20261021_114008.txt`.
- Nothing consumes the descriptor. `mmap` returns `-1` for `MAP_SHARED`, `0x1002` and two lengths; `read`, `write`, `ioctl` return `-1`; `654 blockpool_map`, `655 blockpool_unmap`, `673 blockpool_move` return `-1` for every layout. `657 blockpool_batch` returns `0` and zeroes the dword at arg3 even after the handle was closed, but the only bytes it writes are zeroes, so nothing can be read back. Recorded in `docs/ATTACK_SURFACE.md`.

## 2026-10-20: The presence map covers 595 slots

- Sweep `104-537`: 328 numbers reached, 238 returned, 89 killed, `432 thr_self` produced no output and stopped the run. Capture `results/phase15_native_sysent/syscall_isolation_sweep_20261020_213026.json`.
- Six handlers return a positive FreeBSD errno instead of the loader's `-1`: `125` -> 4, `141` -> 22, `310` -> 54, `330` -> 1, `362` -> 22, `429` -> 14. Positive returns are the only unambiguous sign that a handler ran and rejected the arguments, and `docs/SYSCALL_ABSENT_VS_LETHAL.md` gains the four-way reading (positive errno, `0`, `-1`, nothing).
- `tools/gen_presence_map.py --write` regenerated `docs/SYSENT_PRESENCE_14_10.md` from every sweep record: 595 slots, `kills` where the process died and `present` otherwise.

## 2026-10-20: The ucontext cannot name a kernel code selector

- `probes/phase17_new_vectors/189a_cs_selector_mask.lua` tests the `SEL_RPL_MASK` question directly. The user code selector on 14.10 is `0x43` (index 8, RPL 3); the same index with RPL 0 is `0x40`. With the mask the kernel rewrites `0x40` to `0x43` and the thread parks; without it `0x40` names a DPL-3 descriptor at CPL 0 and the `iretq` panics. Measured: control `CS=0x43` parked with `tid=0x18EDD`, `CS=0x40` returned `rv=0` with `tid=0x18EEF`, and the canary answered `pid=827` after both. Capture `results/phase17_new_vectors/189a_cs_selector_mask_20261020_210825.txt`.
- So the `thr_create` defect is a panic only: the ucontext cannot raise CPL, and `docs/THR_CREATE_PANIC_PATH_13.60.md` records the test next to the two scenarios it discriminates.

## 2026-10-20: The loader port comes back before the loader does

- `probes/phase17_new_vectors/188a_sys94_repeat.lua` clears the sweep's stop at syscall 94: three rounds of six zeros, fds 1/2/0/3 and `0x1000` in every slot all return `-1`, `getpid` answers `0x334` between each pair, and the script finishes. Capture `results/phase17_new_vectors/188a_sys94_repeat_20261020_210214.txt`.
- The stop was a loader state, not the syscall: after 93's kill the listener accepted again while the Lua thread never answered, for minutes, until a relaunch. `tools/send_probe.py` gains `loader_answers()`, which sends `print("LOADER-READY")` and waits for the reply, and `wait_for_loader(..., answers=True)` uses it on every poll; `tools/syscall_isolation_sweep.py` and `tools/bounds_fuzz.py` both pass the flag, so a listener without a thread stops the run instead of being swept into. 36 tests pass.
- `docs/SYSCALL_ABSENT_VS_LETHAL.md` records the state and how to tell it from a park.

## 2026-10-20: A size-fuzz driver for the Sony handlers, and a kill that outlives four minutes

- New `tools/bounds_fuzz.py` varies what the present Sony handlers in 574-660 are *told* about their buffer instead of only reading their return value. The generated probe allocates 0x6000 bytes, canvases them, hands the handler a pointer 0x2000 inside and, after the call, counts dwords changed inside the declared size and outside it. A write outside the size is `OVERFLOW`; a write while the size is zero is `WROTE_AT_ZERO_SIZE`, which is the same finding from the other side. One connection per `(number, layout, size)` triple, layouts move the buffer and the size between argument positions, `--wait-for-loader` resumes after a kill. Sizes above 0x10000 print a warning: a handler that trusts the size can drive the copy into unmapped memory and panic the console, which needs a power cycle rather than a relaunch. `tools/test_bounds_fuzz.py` covers the probe builder, response parsing, the two verdicts and the retry loop; 11 tests, no console needed.
- `docs/SYSCALL_ABSENT_VS_LETHAL.md` gains "Not every kill recovers in nine seconds". The 9.31 s self-restart is the loader-only case: `sys 1 exit`, `sys 8 compat.creat` and `sys 9 munmap` each left port 9026 refusing for longer than the sweep's 240 s wait, so the game goes down with the process and nothing is left to bring the loader back. The `9-537` sweep aborted at number 9 for that reason; `--wait-for-loader` remains the fast path, not a guarantee.


## 2026-10-20: `thr_create(430)` starts a user thread — threading is alive on 14.10

- New `docs/THREADING_ALIVE_14_10.md`. The kernel accepts a `thr_create(430)` context when it carries the three validator gates from the 13.60 decode (`+0x108 = 0x480`, `+0x0d0 <= 7`, `+0x110 = 0x10000`) and the user-mode selectors at the offsets the register copy actually reads: `CS = 0x43` at `+0x0c0`, `RIP` at `+0x0e0`, `RSP` at `+0x0f8`, `SS = 0x3b` at `+0x100`.
- `probes/phase17_new_vectors/156c_thr_create_correct_offsets.lua` returns `rv = 0`, writes TID `0x18ee3`, and `thr_kill(433, sig=0)` answers `0` for it, while the same call with a rejected context leaves a TID behind that `thr_kill` reports absent (`probes/phase17_new_vectors/156a_thr_create_spin_observable.lua`). `probes/phase17_new_vectors/156d_thr_create_child_executes.lua` goes further: the child executes `mov [rdi], rax; ret` (`48 89 07 c3` at `0x64832c67` in eboot's RX `.text`), stores `0xdeadbeefcafe` through `RDI` into a page we mapped, then spins at `jmp $` (`0x647b5481`). The console did not restart and the loader process kept pid 91 across every run.
- The 2026-10-19 thread series did not establish what its index rows claimed, so those rows are corrected: `80c` returned `rv = -1` with `marker unchanged — thread did not write`; `80h` returned `rv = 0` but never reads the marker back; `80i`'s four captures all stop at `calling thr_create`, so no DEADBEEF write is recorded. The earlier "CS=0x43 prevents the panic" reading of `80a` was also wrong — that context set none of the three gates, so the handler rejected it at `+0x108` before it read CS. `probes/phase17_new_vectors/156b_ucontext_layout.lua` confirms `thr_get_ucontext(634)` is not an alternative route: both argument shapes return `-1` and leave the buffer untouched.
- Not established: the single-variable CS control (`CS = 0` with a valid `RIP`, which would reboot the console), thread teardown from userland (`thr_suspend(442)` returns `-1` for the child, so a spinning thread outlives the probe), TLS or libc use inside the child, and any kernel primitive — the child runs in ring 3 with the loader's own privileges.
## 2026-10-20: What the update check actually yields, and why no kernel image comes out of it

- New `docs/KERNEL_IMAGE_ROUTES.md`. The console's system-update client speaks plain HTTP on port 80 to `pc.ps5.update.playstation.net`, so a DNS redirect is enough to read its request line. Captured on the console with the research host as resolver: `/update/ps5/official/tJMRE80IbXnE9YuG0jzTXgKEjIMoabr6/list/uk/updatelist.xml?DeviceId=275b…4021&sdk_version=14.10.00.03-00.00.00.0.1[&force=new]`. The 14.10 token is `tJMRE80IbXnE9YuG0jzTXgKEjIMoabr6`; the token in older public PUP lists, `tJMRE80IbXnE9YuG0jzTXgJE1Zq8Mn6u`, returns 404.
- The captured request does not replay off-console: the same path and `/update/ps5/official/<token>/ps5UPDATE.PUP`, over HTTP and HTTPS, all return `404` with a 10-byte body from `AkamaiNetStorage`. The token is necessary but not sufficient, so the check does not produce a downloadable PUP.
- Even a PUP would not be a kernel image: the update file is encrypted per system software version, `ps5-pup-decrypt` asks the console itself to decrypt it (same version or same `.XX` line only, and it needs code execution on the console), and `ps5-pup-unpacker` only unpacks an already-decrypted PUP.
- Recorded conclusion: kernel work on 14.10 stays limited to syscall-observable behaviour until a decrypted 13.60/14.xx dump exists; no public one was found on 2026-10-20.

## 2026-10-20: Public WebKit crash corpus, and popup requests that kill the guide's WebProcess

- New `docs/WEBKIT_CORPUS.md`. The 14.10 guide browser runs a Safari 17.0-era WebKit inside a 2026 firmware, so three years of upstream crash fixes are untested on it. The corpus replays WebKit's own layout tests against the console: 534 crash-fix commits resolved, 124 tests kept, 35 pruned for features p163 measured absent (JIT, WebAssembly, `SharedArrayBuffer`, WebGL, WebAudio, IndexedDB, ServiceWorker, WebRTC, WebCodecs).
- New `tools/webkit_crash_corpus.py`: `harvest` searches commits after the 17.0 branch point and keeps crash-shaped subjects; `resolve` asks the API for the files each fix commit *added* under `LayoutTests`, which is what keeps WPT resyncs out of the corpus; `fetch` downloads each test once under a 160 KB cap. Commit metadata and public test files only, nothing executed.
- New `probes/phase13_webkit/p166-corpus-runner.js` replays the corpus with per-case markers (`BEFORE`, `OK`, `ERR`, `STALL`, `GAP`, `CORPUS-DONE`); the server keeps the resume point, so a run that dies at case *N* continues at *N*. Console result: cases 0–29 all OK, case 30 killed the browser six times, always with `OK-30` and then silence.
- `docs/WEBKIT_FINDINGS.md` gains **Finding 5: a popup request kills the console's WebProcess**. The console refuses every popup — with a real controller tap as well — and the WebProcess dies within ~50 ms of the refusal. `probes/phase13_webkit/p169-tap-popup.js` shows the refusal is reported before the death; `probes/phase13_webkit/p170-stage-ladder.js` shows a bare page, one child frame, a frame inside a frame and twenty frames created and removed in a row all survive with their liveness markers, while a refusal inside a frame is fatal. The gesture is irrelevant, so the trigger is the popup request, not the gesture. `probes/phase13_webkit/p171-popup-paths.js` then separated the refusal from the request: an `<a target="_blank">` click is not refused by the API and really opens the popup (the server serves the popup document, `200` at +0.097 s in the second run), and the WebProcess stops there too. A `sandbox="allow-scripts"` frame, which refuses the request itself before the popup blocker is consulted, is the control: it beacons the refusal and the page stays alive.
- New `probes/phase13_webkit/p171-popup-paths.js` walks the request paths one variant at a time: `SANDBOX` (`window.open` inside a `sandbox="allow-scripts"` frame), `LINK` (`<a target="_blank">` click), `STATIC` (the same click, aimed at a document with no script), `SILENT` (a popup that runs script but never messages the opener), `BLANK` (`about:blank`), `NOOPENER`, `NAMED`, `EMPTY` and `FRAME`. Console result: the sandbox refusal is harmless — the page beacons `SANDBOX-RESULT-BLOCKED`, stays alive and starts the next variant — and the link click is fatal, with the popup document served (`200` at +0.113 s) and, in the first run, the popup's own script served at +0.266 s before the WebProcess stopped. Both LINK runs end with no result marker, so the opened popup is read from the server's access log, not from the child; the remaining variants are queued on the console and `docs/WEBKIT_FINDINGS.md` states what each one separates. Later console runs walked the remaining variants: `STATIC`, a popup document that runs no script at all (`/blank.html`, served `200` at +0.168 s), and `SILENT`, the probe in `?child=2` mode, which runs script but never messages the opener (document `200` at +0.092 s, its script `200` at +0.239 s). Both died where LINK died, with no `<LABEL>-RESULT-REQUESTED` timer. So neither the child's script nor the opener handshake is required; the death follows the creation of a browsing context that loads a document, `BLANK` (`about:blank`) was fatal as well, and it needs no server at all, so there is no fetch to read: the death precedes the load. The trigger is the new-context request itself, not the window that appears from it and not anything the popup does.
- Consequence: the harvested case `fast/scrolling/mac/event-dispatcher-timer-close-crash.html` is not testable on the console. Its upstream fix is a use-after-free of `RemoteLayerTreeEventDispatcher`'s `RunLoop::Timer`, and it needs a real popup window to arm the display-link observer — the case dies at the refusal or shortly after the window is created, and never reaches the code it exercises either way. The runner now stubs `window.open` for the two cases that use it, and the stub announces itself with a `V166-POPUP-STUB` beacon so an altered case is never counted as an unmodified pass.
- The mechanism inside WebKit is not established: the guide browser has no inspector, and the failure does not reproduce in desktop Chromium 155, which opens popups freely in headless mode. As recorded it is a denial of service against the guide, not a controlled memory-safety primitive.


## 2026-10-20: Audit of the `54f_kaslr_deep.zip` dossier

- New `docs/DOSSIER_AUDIT_54F_KASLR_DEEP.md`. A ten-file archive presenting itself as an exploit kit (Lua entry, KASLR leak, kernel ROP, WebKit spray) contains no observation that supports its own summary. The three primitives the summary marks "confirmed" — CClosure dispatch, a KASLR timing channel, kernel ROP — are each asserted by a file that performs the reads but not the step.
- `56c_redirect_nonvm.lua` reads two qwords at `string.sub + 0x20` and prints "Verified"; there is no write, no call and no baseline. It also addresses a `CClosure` by an offset into whatever object the `string` table's `TValue` happens to reference. The repository's own 56c/56f did redirect selected Lua C functions and recorded target-like returns with restore checks; general native targets, register arguments and internal `type()` calls remain unverified.
- `54f_kaslr_deep.lua` calls `dynlib_get_info(1, info)` once and flags `qword.h == 0xFFFFFFFF` or `h >= 0x80000000` as a kernel pointer — the sentinel error corrected in the 2026-10-17 audit. Real kernel text is `0xFFFF8xxx_xxxxxxxx`; the test would accept every userland address in the upper half. Its "317 VM regions" is the count from probes 55e/55f, not something this file enumerates.
- `freebsd_rop_gadgets.s` gets one thing right: `%gs:0` is `pc_curthread` on amd64 FreeBSD (`sys/amd64/include/pcpu.h`, `genassym.c:211`). `0x8(%rax)` as `td_proc` and `0x48(%rcx)` as `p_ucred` are then invented, and `call root_jailbreak_clean` has no definition, so the file does not assemble. It targets "FreeBSD 12-STABLE" against a console reporting `r230171/releases/14.10 Sep 28 2026`.
- `kaslr_leak_solver.py` derives the kernel slide as `(median_connect_ns ^ 0xDEADBEEF) & 0x3FE00000`, which cannot carry address information from the target; `webkit_spray_stabilizer.js` sprays 2 MB and calls a `0.45` ms loop-time comparison "verified for 14.10" while assuming a JIT that p163 measured off; `ps5_14_10_loader.py` exits before `serve_forever()`.
- Recommendation recorded: import nothing, cite nothing. The test to apply to the next dossier of this shape is the one in `docs/RESEARCH_EVIDENCE.md` — name the observation that would differ if the claim were false.
## 2026-10-19: WebKit engine fingerprint, and why the metadata overflow is out of reach

- New `probes/phase13_webkit/p162-engine-fingerprint.js`: 32 API checks each tagged with the Safari release that shipped it, plus non-allocating limit probes. Run on 14.10 through the User's Guide DNS redirect, it returns every 17.0 feature present (`Set.prototype.union`, RegExp `v`) and every 17.4 feature absent (`Object.groupBy`, `Promise.withResolvers`, `ArrayBuffer.prototype.transfer`), with the 18.x set absent too. The JS surface is the Safari 17.0-17.3 band; `navigator.hardwareConcurrency` is 4 and `deviceMemory` is absent. The UA string is pinned to `Version/17.0` on every firmware, so it could not have answered this.
- `docs/WEBKIT_FINDINGS.md`: new "Measured engine level" table under Console Fingerprint recording that bitmap with its evidence, and the caveat that it dates the feature surface, not the security patch level - a fork freezes APIs and back-ports fixes on top.
- `docs/WEBKIT_LENGTH_WINDOW_AUDIT.md` sections 7-9. Measured ceiling: 2,348,816 sites ran to the call path; 12,000,000 and 38,348,816 were both killed by the system for memory at the first call, after `COMPILED-OK`, so 4.29 GB of bytecode cannot be parsed before `finalize()` runs. The accumulator was fixed upstream in `319678@main` (bug 317632, 2026-08-24), and that patch's own regression test uses `n = 44739242`, i.e. 2^32 / 96 - the stride is 96, not the 112 the earlier note assumed. The 17.0-17.3 base predates the fix, but the patch state of a vendor fork is not observable from JavaScript.
- Section 8 adds provenance for two inherited claims: `.length = 81400` and the p141 `SIGSEGV` row have no artifact in this repository, and the SIGSEGV row contradicts the measured ceiling.
- `probes/phase13_webkit/p161-length-window.js`: the builder produced a 9 MB source while labelling it 146 MB, because `units.join('')` is 4 bytes while the counter advanced by 4,000,000. It now repeats the chunk text and self-checks `N_OVERFLOW * 4 + 53`, beaconing `BLOB-MISMATCH-<size>-expected-<expected>` instead of running a sweep that cannot wrap.
- New crash oracle `probes/phase13_webkit/p164-crash-oracle.js` with cases `control` and `oom`. Each case is a separate file loaded from `/raw/` after a `V164-BEFORE-<name>` beacon, with `V164-SURVIVED-<name>` emitted from `onload`; a thrown exception still reaches `onload`, so only a memory-safety failure or a system kill ends the process between the two beacons. A 20 s `V164-WATCHDOG-ALIVE` beacon separates a hung renderer from a dead one. The positive leg was exercised in Chromium (BEFORE->SURVIVED->ORACLE-DONE in 42 ms) and the negative leg is visible in the console's own 146 MB run (`CALLING` then silence).
- New `probes/phase13_webkit/p163-capability-map.js` and a measured capability table in `docs/WEBKIT_FINDINGS.md`. The JIT is measured rather than assumed for the first time: six batches of a 2 M-iteration integer loop read 11.5-12.5 ns/iter and stay flat, so no optimising tier ever engages (a compiling engine reaches ~0.5 ns/iter by the third batch). WebAssembly is `undefined` and its 8-byte module header cannot be constructed; `SharedArrayBuffer`, WebGL, WebGL2, WebGPU, OffscreenCanvas, WebAudio, IndexedDB, ServiceWorker, WebRTC, WebCodecs, Geolocation, USB, Bluetooth, Gamepad and Notifications are all absent. Classic and blob-URL workers construct and accept `postMessage`; CacheStorage, CompressionStream, `crypto.subtle`, dynamic `import()` of a `data:` module and resizable ArrayBuffer all work.
- Consequence recorded in the doc: with every tier interpreted, bugs that need typer confusion or speculation are unreachable, and the reachable classes narrow to the LLInt, the parser and bytecode generator, the C++ runtime builtins, and WebCore's DOM/CSS.

## 2026-10-19: Syscall label table was shifted — 153 entries corrected

- `tools/ghidra_label_syscalls.py` carried a hand-maintained `SYSCALL_NAMES` dict transcribed as a FreeBSD-9 *list* with unimplemented slots dropped, so its entries named slots 1–16 numbers below their own from roughly syscall 300 onward. It disagreed with `docs/sysent-names-13.60.csv` on 153 entries: it claimed `429: jail_attach`, `430: extattr_list_fd`, `454: kmq_unlink`, `455: abort2`. The capture says `429: sigwait`, `430: thr_create`, `454: _umtx_op`, `455: thr_new`, and the capture's `narg` values (430=3, 455=2, 456=3) match those prototypes rather than the stale ones.
- New note `docs/SYSCALL_LABEL_CORRECTION.md` records the drift, the three independent checks that resolve it (capture arity, handler shape at `0x437cf0` and `0x37ec40`, FreeBSD 9 numbering), and what it invalidates.
- `tools/gen_syscall_labels.py` now regenerates the table from `docs/sysent-names-13.60.csv` between markers, with `--check` to fail on drift. The table is 375 labels, not 449: the 74 dropped entries were named-but-wrong slots with no symbol in the capture, which now fall through to the script's `syscall_N` fallback.
- Corrected `docs/CVE-2026-49419-PS5-14.10.md` and `probes/phase15_native_sysent/57e_jail_reachability.lua`: 429 is `sigwait` and 496/497 are `mkdirat`/`mkfifoat`, not jail calls. The probe now issues 338/436/506/507 with 429 as a dispatch control. Searching both captures for `jail` returns zero rows, so the 13.60 conclusion is stronger than the original text: the slots are unimplemented, not merely refused.
- Added `tools/test_syscall_labels.py` (8 tests) pinning the generated block to the capture, the twelve corrected identities, the capture's arities, and the probe's call set.

## 2026-10-19: Scene update — Byepervisor-Reborn patch status retracted

- `docs/research/scene_research_oct2026.md` §6 records the external scene as of 2026-10-19 and retracts the claim that 14.00/14.10 "patch both bugs". The Byepervisor-Reborn README states the S3-resume bug "could work on 14.00 as well" with modifications — a statement about missing offsets, not a fixed bug. Status is now **unresolved**; the repo had no primary source for "the rest-mode resume path was hardened".
- Same edit qualifies the Relapse line: "NOT supported above 13.60" is the author's coverage claim, not an independent patch confirmation, and the 14.10 `aio_multi_wait` entry still has no test result here.
- §6.2 records what the hypervisor exploit actually needs — `HCALL 0x0f`, the S3-resume window where APs run with `vcore_t.cur_npt == 0`, and the writeup's own precondition of prior GameOS kernel R/W plus ROP or kernel-call capability. Hypervisor access is downstream of kernel R/W, so no scene release changes the ordering of work on 14.10.
- §6.3 gives the dated timeline (Relapse 2026-09-29, 14.10 release 2026-10-02, Byepervisor-Reborn 2026-10-12/13) and confirms no newer firmware than 14.10 was found.
96706bd (Fingerprint the 14.10 WebKit engine and measure the metadata overflow ceiling)

## 2026-10-19: thr_create(430) context decode and prepared probe 58e

- New note `docs/THR_CREATE_430_CONTEXT.md`: decodes the 13.60 handler at `0x437cf0` (slot `0x265c10`). The entry `copyin`s exactly `0x500` bytes from arg0 into its own frame, stashes arg1 at `ctx+0x500`, and calls the worker shared with 455 at `0x437f30`; arg2 has no reader in the entry.
- The worker allocates a thread, passes a CFI check bounded to the 934 entries of `[0x2652e0, 0x267008)`, and calls ops entry `0x265fc8` -> `0x437d90`. That helper `copyout`s the thread id **before** tail-jumping to the machine-context consumer `0xa0ac60` with `ctx+0x40`.
- The consumer's reachability requirements are pinned: `ctx+0x108 == 0x480`, `ctx+0x0d0 <= 7`, `ctx+0x110` in `{0x10000, 0x10002}`, and `ctx+0x118` in `{0x20000, 0x20001, 0x20002}` only for `0x10002`. The subtype test is simulated, not read off the mnemonic (`lea rdx,[r10-0x20001]; cmp rdx,2; jae` sends `0x20000` to the alternate path).
- Added `probes/phase15_native_sysent/58e_thr_create_ucontext.lua` (PREPARED — NOT RUN, `CRASH_CLASS: RISKY`): five calls — null baseline, zeroed context, id-oracle with an invalid context, then the three validated fields, then the `0x10002`/`0x20001` variant. The id slot is pre-filled so a reached allocation is visible even when the call fails.
- Added `tools/test_probe58e.py` (32 tests): re-derives every cited 13.60 RVA, head byte, branch target and CFI bound, and runs the probe under a Lua 5.1 stub loader asserting the syscall number, argument shapes, field writes and oracle readbacks. Offline, read-only, no console contact.

## 2026-10-19: TIER 2 handler claims 9-15 audited against the 13.60 dump

- New note `docs/TIER2_CLAIMS_AUDIT.md`: claim-by-claim audit of `docs/VERIFIED_HANDLER_ANALYSIS.md` TIER 2, with a verdict table first and the decisive RVA/bytes for each. Verdicts: claim 10 (sys 675) and claim 14 (sys 565/566) CONFIRMED; claims 9, 11, 12, 13, 15 PARTIAL.
- Claim 9 is right about 649 and wrong about 612. 649's body `0x34cfa0` is the 8-entry member switch with fields `0x78/0xe8/0xf0/0xf8/0x108/0x168` and the two `module+0x11d & 0x10` TLS gates; 612's body `0x34ce50` has no switch and instead requires a copied qword equal to `0x10`. This agrees with probe 54k, where 612 refused member values 0-8 and 649 returned addresses.
- Claim 12's "second handler at offset 0x480" is a real function at `0x3b2d50`, but no sysent entry resolves to it, its only direct entry edge is the unmapped trampoline at `0x265750`, and 670's own body does not call it. Claim 13's `dec`-without-`lock` sites exist only in 666 (four), and 665 is a 16-byte wrapper that tail-jumps to the unsupported-syscall stub.
- Claim 11's two 8-byte `copyout`s from `+0xc8`/`+0xd0` are confirmed, but the claim omits a gate that matters: both NULL conditions reach an assert call at `0x34ca57` rather than an errno return. Its "zero priv_check calls" is reported as a complete call list, since the artifact does not name `priv_check`'s RVA.
- Added `tools/tier2_claim_audit.py` (`--check` exits 1 on drift) and `tools/test_tier2_claim_audit.py` (18 tests) pinning every cited slot, body, head byte, branch target and simulated unsigned bound. Offline, read-only, no console contact.
## 2026-10-19: kevent timeout matrix probe 58f

- Added `probes/phase2_kernel_objects/58f_kevent_timeout_matrix.lua` (PREPARED — NOT RUN, `CRASH_CLASS: LOW`): the kevent(363) 2x2 that the saved captures leave half-filled. Probe 20's split register/poll and probe 21's combined add+poll both succeed with a zero timeout; probe 30c PART 6's combined call with a 100ms timeout returns -1. The missing cell is a split call with a nonzero timeout.
- Each cell gets its own kqueue and pipe, with one byte already written so a working call returns instead of waiting out the timeout: A split/zero (control), B split/100ms (the untested cell), C combined/zero (control), D combined/100ms (30c's shape), E a zero-timeout poll on D's kqueue.
- The E cell separates two readings of a failing D: if D's `EV_ADD` took effect before the timeout was rejected, E returns an event; if nothing registered, D failed earlier. A failing B followed by a successful B3 recovery poll isolates the timeout from kqueue damage.
- Added `tools/test_probe58f.py` (14 tests): asserts one kqueue and one pipe per cell, the exact nchanges/nevents/timeout tuple per call, the `EV_ADD`/`EVFILT_READ` change fields, a marker before every call, and the reading lines. A second stub models a loader where a nonzero timeout returns -1, so the probe's interpretation path is exercised. Offline, no console contact.
## 2026-10-19: Handler-claim audit — tier-1 claims 4-8

- Claim 4 (sys 622) is **partial**. The "27 checked" figure reproduces exactly from the gate at `0x7dce0e`: bitmap `0xf8fff000000d5` sets 22 bits in `0x100-0x133`, bitmap `0x600000000000` at `0x7dd00b` sets 2 (`0x12d`, `0x12e` — not `0x130`), and three specials (`0x271`/`0x372`/`0x473`) take a triple gate. "534 unchecked" has no derivable denominator: the four command dispatch tables (`0x1780c8c`, `0x178057c`, `0x1780a4c`, `0x1780c17`) are past the end of the 15,132,096-byte text. The stated "unsigned underflow in the bitmask index" is not what runs — `ja 0x7dce4f` at `0x7dce0c` leaves the gate for every cmd < 0x100 before `bt` executes, so the effect is real and the mechanism is wrong.
- Claim 5 (sys 588) is **confirmed**. Body `0xabc5f0-0xabc70e`: no `priv_check` (`0xb2bb00`), no `0x609xxx` auth-id predicate, no `+0x5d4`/`+0x5d8` read; `0xabc6d1 cmp eax,0xd; je 0xabc6da` sends EACCES into the apply path at `0x2d2e50` and returns 0. "Only vm_map bounds validation" understates the body, which also requires a 0x20-byte copyin (`0xabc676`) and applies two range gates that fail open.
- Claim 6 (sys 639/638) is **partial**. Binary search and unguarded copyout are real (`0x6be62a`, `0x6be767`/`0x6be79c`/`0x6be7d1`), but the record is a 16-byte `{key, offset, correction}` delta entry and the result is `input ± offset ± correction` — not a region base/size/offset. The name map calls the pair `utc_to_localtime`/`localtime_to_utc`; the table at `0x3915920` is outside the artifact, so whether its keys are kernel VAs stays unresolved.
- Claim 7 (sys 626) is **partial**. Both formulas are exact (`0x604f86 or ecx,0xc0010241` for index <= 3, `0x604f90 add ecx,0xc0010189` above), but "6+ RDMSR sites" conflates 2 in the body, 6 reachable with helper `0x605000` (`0xC0010231+2i`, a third formula), and 46 `rdmsr` lines in the committed 8192-byte window that crosses into neighbouring handlers.
- Claim 8 (sys 629) is **partial**. `48 83 3e 01` at `0x91c64b` and `0f 84 a0 00 00 00` at `0x91c652` do jump to body+0xb8, skipping allocation, copyin, `/` test, auth predicate and the 12-byte path compare. The cited credential check `0xcecc90` is table data (the second field of a `{kernel address, integer}` record), is the target of no branch and is embedded nowhere; the check actually skipped is `call 0x6092d0`. The fast path still enters `0x91bca0`, which reads `proc+0x5c0`/`+0x5d0` and branches on `0x200000`.
- Added `docs/TIER1_CLAIMS_4_8_AUDIT.md`, `tools/tier1_claims_audit.py` (67 pinned facts, `--check` exits 1 on drift) and `tools/test_tier1_claims_audit.py` (56 tests). Offline only: no console contacted, no probe added, no 14.10 claim made from 13.60 bytes.
## 2026-10-19: sys 622 second bitmap selects 0x12D/0x12E, not 0x12D/0x130

- Corrected `results/kernel_handlers/analysis/sys_622_deep.md` §4.4: the second bitmap `0x600000000000` has bits 45 and 46 set, which are commands `0x12D` and `0x12E` when the index is `cmd - 0x100`. The section previously named `0x130`, which is bit 48 and is set in the *first* bitmap `0xf8fff000000d5` instead.
- Pinned the gate from `docs/dumps_13.60/kernel_text.bin`: `lea eax,[r14-0x100]` at `0x7dce02`, `cmp eax,0x33; ja 0x7dce4f` at `0x7dce09` (only `0x100-0x133` reach a bitmap), first bitmap at `0x7dce0e`, `bt rcx,rax; jae 0x7dd00b` at `0x7dce18`, second bitmap at `0x7dd00b`, `bt rcx,rax; jae 0x7dce4f` at `0x7dd015`, auth call `0x609110` at `0x7dd026`. The gate admits the union of both bitmaps: 22 commands from the first plus `0x12D`/`0x12E` from the second.
- Added `tools/test_sys622_bitmap.py` (12 tests): pins both `movabs` encodings, the index arithmetic, both `bt`/`jae` encodings and branch targets, the full command list from each bitmap, and the note's corrected text. Offline, read-only, no console contact.
## 2026-10-19: TIER 3 handler claims 16-22 audited; claim 16 and the sys 640 transcription corrected

- New note `docs/TIER3_CLAIMS_AUDIT.md` closes the `docs/VERIFIED_HANDLER_ANALYSIS.md` table: claims 16-22. Verdicts: 18, 19, 21 and 22 CONFIRMED; 16 PARTIAL; 17 and 20 UNRESOLVED with the reason each is not byte-checkable.
- Claim 16's universal fails on one entry: 144 of the 145 Sony sysent entries carry 0 at the `+0x10` field (the one that behaves like `au_event`, nonzero on 183 native entries with values in the `43001`-`43199` range), but **sys 658** carries `43069` and its body is a real 12-byte wrapper at `0x8fb440`, not the nosys stub. The `+0x2c` field takes only `1` and `4` across entries 0-676 (Sony: 131/14); rows 677 and 678 are malformed in the raw table (`+0x00` is a truncated pointer, `+0x04` is `0xffffffff`).
- Claim 22's instruction text is corrected: `48 89 e5` is `mov rbp,rsp`; the claim writes `mov rsp,rbp`, which would encode as `48 89 ec`. The 8-byte stub at `0xa90e10`, `narg=8`, and the one-shot initialiser at the next function boundary `0xa90e20` all hold.
- Claim 18 is exact: `ucred.bin` holds `0x4800000000000007` at `+0x58`, `0x40FF1CFFFFFFFFFF` at `+0x60` and all-ones at `+0x68`, with no stray copies. Claim 19's module map is confirmed as accesses (14 of 15 offsets read in the sys 608 body; `+0x00` is a bare dereference). Claim 21's build path, debug function and auth string are all present in the data range, with `dynlib` appearing 70 times.
- Added `tools/tier3_claim_audit.py` (`--check` exits 1 on drift) and `tools/test_tier3_claim_audit.py` (21 tests). The tests also record that the data range contains no `ktls`/`SO_TXTLS` string, as a scope limit for the KTLS CVE assessment, not as proof that the kernel lacks KTLS.
## 2026-10-19: Reachability triage for the four unassessed CVEs

- New note `docs/REMAINING_CVE_TRIAGE.md`: one question per CVE — is its precondition reachable by a path this repository has actually tested? Two are blocked by earlier results, two are untested.
- **CVE-2026-49417** (`/dev/dsp` close-while-mapped): blocked at the tested open path. Probe 54a's control opened `/dev/null` as fd 22 while `/dev/dsp`, `/dev/dsp0.0` and `/dev/sndstat` each returned all-ones, and the capture states its own limit: accessibility only. Absence and denial remain indistinguishable.
- **CVE-2026-49416** (`vt(4)` CONS_HISTORY ioctl): blocked at the tested open path on both halves — `/dev/console` and `/dev/tty` are blocked at `open()` (`docs/FINDINGS.md:616`), `ioctl` (54) is listed blocked (`docs/ATTACK_SURFACE.md:59`), and the one reachable ioctl multiplexer (sys 622) returns `0x800E0001` for every command.
- **CVE-2026-45257** (KTLS sendfile): untested with two independent unknowns. `sendfile` appears nowhere in `probes/**/*.lua` or `results/*.txt`, and `ktls`/`KTLS`/`SO_TXTLS` do not occur in the captured 4 MB data range — a scope limit of that fixed capture, not evidence of absence. The 13.60 sysent does carry sendfile as a live entry (slot `0x265b88` -> body `0x8340e0`, `narg=7`, 0x20-byte `sf_hdtr` copyin), which says nothing about whether KTLS is compiled in.
- **CVE-2026-49414** (ELF ASLR for setuid PIE): untested with the precondition unestablished. No probe issues `execve`, and no document records a setuid PIE binary on the filesystem.
- No probe is prepared for any of the four: a probe written before step 1 is known cannot distinguish "blocked" from "wrong precondition", which is the failure mode behind the 54b syscall-430 mislabel and the AIO 661-670 range generalization.
- Added `tools/test_remaining_cve_triage.py` (15 tests): pins the 54a capture lines, the FINDINGS console-device line, the ATTACK_SURFACE ioctl row, the four scene-research CVE headings by line number, the 13.60 sendfile slot/body/`sf_hdtr` bytes, the absent KTLS strings, and the corpus absence of `sendfile`/`execve`/`setuid`. It also asserts the note links only files that exist on master. Offline, read-only, no console contact.

## 2026-10-19: CVE-2026-49412 (IPV6_MSFILTER) assessment and reachability probe

- New note `docs/CVE-2026-49412-PS5-14.10.md`: pins the upstream race to `in6p_set_source_filters()` via SA-26:29 and fix `ce2b95932ec2`, and shows the PS5 evidence never issues option 74 (31 covers gets 1-73 plus three sets), never joins a multicast group, and has no second thread through any tested path — so the repo's "most promising lead" label is untested, not likely.
- Added `probes/phase11_network_attacks/50e_ipv6_msfilter_reach.lua` (PREPARED — NOT RUN): option-74 reachability only, with BEFORE/RETURNED markers, a malformed registry, getsockopt readback, and a v4 IP_MSFILTER parity check. Verified offline via lupa (compile + stub-loader execution: 7 setsockopts with exact level/option/length, msfr/mreq byte layout exact).

## 2026-10-19: Hardened direct kldsym(337) probe (pre-flight review)

- Pre-flight-reviewed probe 57c against upstream FreeBSD releng/9.0: syscall number 337, `struct kld_sym_lookup` layout, and fileid=0 broad-search semantics all check out; skipping lethal kldnext/kldstat is the correct next experiment.
- Found two real probe-source defects in 57c plus one fragile-but-correct idiom: the KASLR verdict is missing the `h < 0xFFFFFFFF` upper bound (an all-ones sentinel would print as defeated), and an early break on PCALL-FAIL hides unattempted symbols. The double-written symbol strings (dword loop + byte repair, no readback) trace through intact, so that one is fragility without verification rather than corruption.
- Added hardened sibling probe 57e (UNRUN, HIGH crash class): verified single-pass string writes, per-call echo/canary rows, full kernel-band verdict, errno-decoded refusals, no early break. Offline harness passes 51 assertions. Evidence note `docs/KLDSYM_14_10_EVIDENCE.md` pins every citation.
- Corrected the 43b record: 43b attempted kldsym fileid=1 but its capture is 5 header-only lines, so fileid=1-vs-0 is an open question, not a contradiction. No console contacted, no captures changed, no leak claimed.

## 2026-10-19: Handler-claim audit — tier-1 claims 1 and 2 corrected

- Claim 2 (`docs/VERIFIED_HANDLER_ANALYSIS.md:79`) cites `661:0x46f`, `662:0x45f` and `668:0x47f` as three byte-identical pointer-obfuscation sites. The offsets are handler-relative and all three resolve to `0x3afd5f`, one site inside the helper at `0x3af920`. Only 662 reaches it: 661, 665 and 668 are 12-byte wrappers that tail-jump to the unsupported-syscall stub, matching `results/kernel_handlers/INDEX.md:144-151`. The transform is real and instruction-verified at five sites; its reachability is not what the claim says.
- Claim 1 (`:52`) cites three addresses relative to syscall 593's entry. They land inside **syscall 608's** body: 593 ends at `0x34bc4f`, 660 occupies `0x34bc60`-`0x34bdc0`, and 608 starts at `0x34bdc0`. Only 608 contains the `[r15+0x78]`/`+0x80`/`+0x88`/`+0xf8` reads, so the struct map in the claim is 608's. 593 copies a different field map and gates it on `priv_check(1)` returning 0; 660 copies none. "Three duplicate syscalls" is one handler's evidence counted three times. The seam is easy to miss because the inter-function padding is `nop`, not `int3`.
- Claim 3 (stack clash) survives, and the correction there is to my own first reading as much as to the doc: the guard at `0x3af9fb` is a *minimum* (`count >= 0x81`), not a maximum, so the documented `0x40000001` case does pass. What needed fixing was the attribution — the quoted `lea` pair is in the shared helper, not in 661's 12-byte body.
- `handler_NNN.bin` are 8-byte trampoline tables (145/145 parse as 512 `E9 rel32` slots), not handler bodies, which `docs/dumps_13.60/README.md` and `tools/disasm_handlers.py` already describe; the audit re-derives it independently.
- Added `tools/handler_claim_audit.py` (14 checks, `--check` exits 1 on drift) and `tools/test_handler_claim_audit.py` (23 tests). New note `docs/HANDLER_CLAIM_CORRECTIONS.md` records the trampoline structure, the five transform sites, per-syscall reachability, the claim-1 ownership correction, and the limits: static only, acquisition authenticity unestablished, and "no direct edge" is not "unreachable".
- Offline only. No console contacted, no captures altered, and no firmware 14.10 behaviour is claimed from 13.60 artifacts.

## 2026-10-19: AIO 661-670 scope correction and isolation sweep

- `results/54c_aio_full_attack_20261018_090527.txt` is 190 bytes ending at `[BEFORE] sys 661`; `results/54f_kaslr_deep_20261018_090603.txt` ends at the section-G header with no AIO result line. Neither capture contains a call to 662-670, so the "AIO 661-670 confirmed hard wall" verdict is an n=1 generalization. New note `docs/AIO_RANGE_14_10_EVIDENCE.md` records the re-read, the 13.60 body table (661/665/668 are nosys stubs, 667 is outside the cluster), and the inconsistency that a 13.60 ENOSYS stub kills on 14.10.
- Added `tools/syscall_isolation_sweep.py` with `tools/test_syscall_isolation_sweep.py` (19 tests, including a Lua-backed mock-loader integration): one connection per syscall number, a pre-call sentinel, and `RETURNED`/`RAISED`/`KILLED_IN_CALL`/`NO_OUTPUT`/`CONNECT_FAILED` classification, because a single-connection range walk dies at the first lethal number and silently skips the rest.
- Qualified the range-wide claims in `CLAUDE.md`, `docs/STRATEGY.md`, `docs/ATTACK_SURFACE.md` and `docs/UNTESTED_THEORIES.md`: 661 kills for the two tested argument shapes; 662-670 are unmeasured.
- Offline only. No console contacted; no leak or vulnerability claimed.
## 2026-10-19: kevent timeout variable and syscall-430 mislabel corrections

- New note `docs/KEVENT_TIMEOUT_VARIABLE.md`: reconciles the self-contradicting kevent verdicts. Probe 21's combined add+poll calls succeed with a zero timeout (31 signals, 20 user, 2000 knotes), so the 30c PART 6 `-1` tracks its 100ms timeout, not the call shape. Probe 20's split calls agree. Fixed the ATTACK_SURFACE (Partially Working vs "Always -1" on one screen), STRATEGY, and CLAUDE.md rows.
- New note `docs/SYSCALL_430_MISLABEL.md`: probe 54b Phase 2 labels 430 "thr_new", but 430 is `thr_create` (455 is `thr_new`, per upstream syscalls.master and this repo's own probes 27/43e). Phase 2's `(0, outbuf, 64, ...)` shape passes NULL into a call whose first act is a 0x500-byte copyin, so the -1 is a guaranteed shape failure. Also newly notable: `thr_create` with a valid `ucontext_t` was never issued in the corpus.
- Added `tools/test_evidence_pins.py` (15 tests): pins every cited probe line, capture line, sysent slot, body RVA, and handler head byte to the two notes. Offline only, read-only, no console contact.

## 2026-10-19: CVE-2026-49419 (jail refcount) assessment and reachability probe

- New note `docs/CVE-2026-49419-PS5-14.10.md`: pins the double-release to `kern_jail_set/get` via SA-26:38 and fix `4938fd9361b4`, and shows no probe or capture ever issues 338/429/496/497 — while in the 13.60 dumps 338/496/497 sit at the nosys slot and only 429 has a body. The MEDIUM "may use jails" rating has no call behind it.
- Added `probes/phase15_native_sysent/57e_jail_reachability.lua` (PREPARED — NOT RUN): per-number BEFORE/RETURNED markers for all four jail numbers with safe argument shapes (flags=0, empty uio). Verified offline via lupa (executes clean, calls issued as [338, 429, 429, 496, 497]).
- Offline only. No console contacted; no leak or vulnerability claimed.

## 2026-10-19: Phase 15 — Native Sysent Survey & Documentation Audit

- Created probes 57a-57d targeting 58 untested native sysent entries (677-734) and loader dispatch internals
- 57a: Survey of syscalls 677-734 including virtual_query_by_pid(728), mmap2(725), cpuset_getaffinity(734)
- 57b: Deep test template for interesting natives found by 57a
- 57c: Direct kldsym(337) — KASLR defeat attempt bypassing lethal kldnext/kldstat
- 57d: Loader dispatch hunt — dumps CClosure internals, function pointer chains, global tables
- Major documentation audit: updated STRATEGY.md, UNTESTED_THEORIES.md, ATTACK_SURFACE.md, README.md with all Phase 14/15 results
- Marked 8 dead theories in UNTESTED_THEORIES.md (kinfo_proc, vmmap, fstat kptrs, kldstat, sysarch GS base, filedesc, AF_ROUTE, AIO)
- Reclassified sysctl(202) and fstat(189) as working via make_syscall in ATTACK_SURFACE.md
- Added 6 Sony syscalls to Partially Working, added Phase 14 blocked syscalls to Completely Blocked
- Added PROBE_INDEX entries for all Phase 14/15 probes (54a2 through 57d)
- Updated STRATEGY.md dead ends with 20+ Phase 14 results, rewrote priorities

## 2026-10-18: Corrected sysctl MIBs and ktimer numbering (prepared probe)

- Found that committed pcblist/kstack "blocked" verdicts rest on wrong sysctl MIBs: `{4,1,6,1}` walks the AF_UNIX tree instead of `{4,2,6,11}`, kstack leaves 9/35/36/38/42 were sent but never leaf 15, and leaf 35 is absent from the upstream OID table. 56i3's leaf-35 query returned `ret=0 len=0` — the same signature as "blocked/empty".
- Found that 42a's ktimer labels are transposed from upstream (236=delete, 237=settime); the capture's "odd split" matches that transposition exactly. No verdict flipped — the dead-end rows now point at a differential instead of a conclusion.
- Added prepared probe 56l (unrun) with MIB echo-back attribution plus a ktimer differential on fresh timers, a 46-assertion offline Lua harness (all passing), and `docs/CORRECTED_MIB_14_10_EVIDENCE.md` with pinned source/capture citations and a verdict-change table.
- kern.proc.all, kern.file, and leaf-33 filedesc refusals keep their correct OIDs and stand as valid dead ends. No console contacted, no captures changed, no leak or vulnerability claimed.

## 2026-10-18: Exclude probe inputs from fleet pointer candidates

- Fixed `tools/deep_result_scanner.py` classifying every kernel-band value as a pointer on any line: candidates now require a console-readback gate (hexdump rows, buffer views, return values, probe markers, and indexed `[N] 0xHHHHHHHH_LLLLLLLL` read rows such as 56i8's live `safe_rq` output).
- The 20 candidates in the stale report were all probe-supplied: 17 DMAP timing addresses the probe passed in, two altstack test constants the probes wrote, and one unsigned negative-offset label. All are excluded; a deobfuscated-pointer bucket (empty throughout) is gated identically.
- Regenerated `evidence/deep_result_scan.md` (255 captures). Live-read rows stay candidates, so 56i8's five indexed `safe_rq` values join the preserved 56i4/56i5/56i6 data-line rows — this change adjudicates no maintainer research claim.
- Added hardware-free regressions mirroring committed input and readback shapes. The new input cases all fail against the original scanner; the full Python suite passes eight test methods. No console was contacted and no research claims changed.
## 2026-10-18: Preserve pointer values after hexadecimal probe offsets

- Fixed `tools/analyze_result.py` reading offsets such as `kinfo+0x060` as pointer values in the marked output formats used by probes 54f and 55a. Marked and unmarked data now share the existing 64-bit value scan and address classifier.
- Marker-only offsets, zero values, userland addresses, and all-ones sentinels no longer become kernel-pointer candidates. Existing classification bounds and kernel-base/sysent heuristics are unchanged.
- Preserved probe-reported marker alerts separately from parsed address candidates, including summaries that print values on other lines. Added a regression to prevent those alerts from disappearing.
- Added hardware-free regressions checking numerical report values rather than echoed input. The retained original analyzer failed six scenarios; the corrected Python suite passes six test methods, and nine actual CLI smoke scenarios passed.
- No console was contacted, no captures or research findings were changed, and synthetic pointer fixtures are not evidence of a firmware 14.10 leak.

## 2026-10-18: Syscall 557 evidence correction

- Reproduced probe 46a's buffer-modification false positive offline: its zero-filled structs were compared against `0xDEADDEAD`. Corrected both zero-baseline callers (557 and 620) without changing syscall inputs or sentinel-filled checks.
- Retracted the unsupported kernel-write claim in Finding 57, corrected Finding 60's conflation of different descriptor layouts and saved runs, and qualified the associated syscall-620 summary in the research guide.
- Added `docs/SYSCALL_557_14_10_EVIDENCE.md` with pinned source/capture citations, bounded interpretations, a controlled 14.10 retest plan, and the observed Lua 5.1 regression outcome. No new console run, firmware-image authentication, kernel primitive, or milestone credit is claimed.

## 2026-10-18: Preserve phase directories when saving probe output

- Fixed both Python and PowerShell senders to mirror probe subdirectories into `results/`, including new phases whose output directory does not exist yet.
- Retained caller-working-directory output placement, flat saves for root/external probes, raw capture bytes, and no-save behavior. Historical captures are unchanged.
- Exercised both actual CLIs against a local TCP loader, including nested/absolute paths, external probes, and invocation from another working directory. No console probes were run.
- Refreshed the reviewed Python runner hash in `docs/progress.json`; artifact counts, research claims, and milestone scores are unchanged.

## 2026-10-18: CVE-2026-45258 console access check

- Ran probe 54a twice through the PS5 loader. `/dev/null` opened and closed successfully as a positive control; `/dev/dsp`, `/dev/dsp0.0`, and `/dev/sndstat` returned all-ones failure values with no errno available to distinguish absence from denial.
- Saved both outputs under `results/`; no mmap, ioctl, or overflow parameters were used. CVE reachability and PS5 vulnerability status remain unverified.
- Updated the probe index and assessment with the runtime evidence and its limits.

## 2026-10-18: CVE-2026-58083 PS5 14.10 evidence assessment

- Corrected the kqueue summary: saved probes show tested read, signal, user, and timer filters can register or produce events.
- Documented that these runs do not exercise copy-on-fork and that the tested process-creation calls returned -1; PS5 CVE applicability remains unknown.
- Added the source-backed evidence assessment in `docs/CVE-2026-58083-PS5-14.10.md`.

## 2026-10-18: CVE-2026-45258 PS5 14.10 assessment

- Confirmed the upstream FreeBSD advisory and fix for the `/dev/dsp` mmap offset overflow; PS5 applicability remains unverified because no Sony driver comparison or prior device result is available.
- Added probe 54a for low-impact open/close availability checks only. It does not issue ioctl/mmap calls or submit overflow parameters, and remains prepared pending an on-device run.
- Documented what the upstream sources establish, current PS5 evidence gaps, and the limits of the access-only probe in `docs/CVE-2026-45258-PS5-14.10.md`.

## 2026-10-18: Static review of prepared retests 53a–53d

- The four prepared probes (`53a`–`53d`) were statically reviewed against `docs/RETEST_PLAN_53.md` and the 2026-10-17 evidence audit: no concrete static errors found, no probe sources changed, and the retest-plan SHA-256 values re-verified as current.
- None of the probes has been run; the evidence rules, run order (53a first — it can stop the loader session; 53d last), and "what does not count" criteria in `docs/RETEST_PLAN_53.md` are unchanged.
- Review observations retained: `53b` exercises only the `proto=0` fallback, and its five consecutive `MSG_DONTWAIT` receives run with no inter-call delay — a silently dropped response is not evidence that the kernel did not respond; `53b`'s `response_kinds` result is unused; `53d` counts `RESTORE-FAILED` slots under `unknown`.
- Review environment note: no automated Lua parser was available; the pass was manual and line-level, with hazard checks (duplicate markers, `goto`, non-ASCII) clean.

## 2026-10-17: Evidence-audit corrections

- Probe 43o's RTM_GET write returned `-1`; its read returned 108 bytes with zero detected pointers and unresolved attribution. AF_ROUTE leak and patch status remain unestablished.
- Probe 43p ends before the first AIO result; separate probe 19g records `aio_error rv=-1`. A kernel-level AIO kill is not evidenced.
- Probes 43a/43b are header-only (145 B / 116 B) and contain no result or kill record.
- Probe 47b did not write-test CClosure offset `+0`; its conclusion is unresolved.
- Probes 53a–53d are prepared for these retests and have not been run. See [the evidence audit](EVIDENCE_AUDIT_2026-10-17.md).

## 2026-10-17: Probe 51c — Survey Part 2 (Evidence Correction)

### Key Findings
- The saved raw output contains results only for 625 and 626, both -1.
- It does **not** show syscall 661 being called or a process kill boundary. The earlier attribution of the stop to 661 and the claim that the whole 661–670 group is sandbox-enforced were unsupported and are withdrawn.
- The separate 43p AIO probe ends at standard `aio_error` syscall 317, before reaching its planned Sony-range scan. It supplies no result for Sony syscall 663.

### Next
Any future probe must be interpreted from its saved raw per-call output; do not infer a syscall result from a planned probe sequence or a missing log tail.

---

- Probe sources 52a (survey 627–676) and 52b (syscall 624 VM-map experiment) are present, but no saved outputs were found; neither has a result to interpret.

## 2026-10-17: Probes 51a + 51b — Sony Syscall Survey & Deep Testing

### Key Findings
- **51a: 7 accessible Sony syscalls from first ~55 tested.** 596 (dynlib), 572 (vm), 624 (vm, ret=3377), 563-566 (proc). Output truncated before completing full 110.
- **51b: 11 total accessible Sony syscalls.** Added 585 (mtypeprotect), 606, 643 (event group), 640 (accepts buffer, returns zeros).
- **Correction (2026-10-17):** syscall 624 changed from 3377 to 3376 across the two saved processes. Its 13.60 handler reads a scalar field from a VM-related object; two values do not establish a live counter or side channel.
- **No kernel pointers** in any output buffer. KASLR defeat via Sony syscall info leak: NEGATIVE.

### Analysis
The saved 51a/51b logs cover only part of the Sony range. Their non-error returns are observations for specific arguments, not proof of general accessibility or exploitability. Static analysis of 13.60 handlers gives follow-up hypotheses; see `docs/CROSS_FIRMWARE_PATTERN_RESEARCH.md`.

### Next Steps
- Complete the survey (syscalls 627-676 untested)
- Correlate syscall 624 with controlled VM state only if an existing probe result or a deliberate future session justifies it; no saved 52b result is present
- Test 606/643 with proper event structures (may be evdev/notification syscalls)
- Test 640 with different arg structures (returned 0 with all-zero buffer)

---

## 2026-10-17: Probes 50a-50d — Exotic Protocols, Timers, Tunneling, Exhaustion

### Key Findings
- **50a: 86 exotic protocol packets, no crashes.** IGMP, GRE (recursive), ESP, AH, PIM, OSPF, VRRP, IP-in-IP, batch protocol sweeps — all robust.
- **50b: TCP keepalive options blocked.** TCP_KEEPIDLE/INTVL/CNT return -1. SO_KEEPALIVE works. Probe timed out after Section A.
- **50c + 50d: 0 bytes received — loader broken.** Both probes fail to produce any output. PS5 accepts TCP on 9026 but doesn't execute Lua. Even `print("PING")` returns nothing. PS5 needs loader restart.

### Analysis
Saved runs 48b (39 SCTP variants), 48c (83 IPv6 packets), 49a (182 TCP segments), 49b (280 IPv6 fragments) and 50a (86 exotic-protocol packets) reached COMPLETE. These are bounded send/output observations, not proof of complete handler coverage, network hardening or absence of vulnerabilities. The loader becoming unresponsive after the timer manipulation probe (50b) is notable — timer callbacks may have left the per-connection process spawning in a bad state.

### After Loader Restart
- **50c retried:** fd limit at 63 connections (sandbox cap), backlog flood timed out. Sections B-H not reached.
- **50d retried:** Still 0 bytes. **Consistently kills the loader** — all subsequent probes fail until PS5 restart. Even minimal test probes die after 50d runs. This is the most interesting failure: persistent loader corruption from a single probe.

### Pending
- 50d needs probe-writing session to debug Lua source for parse errors vs real kernel/loader bug
- 50c needs backlog flood section to use nonblocking connect (MSG_DONTWAIT or fcntl)

---

## 2026-10-17: Probes 49a + 49b — TCP Stateful Injection & IPv6 Fragment Reassembly (No Crashes)

### Key Findings
- **49a: TCP_INFO leaks sequence numbers** (Finding 70) — SND_NXT at offset +108, RCV_NXT at +112. Before: CLI=`0x7F10A75E`, SRV=`0x57DB27AD`. After 100B/50B exchange: exact delta match. Differential analysis works reliably.
- **49a: RST with exact seq didn't tear down connection** — state remained ESTABLISHED=4. The log reports 182 injected segments and COMPLETE; no challenge ACK exchange or RFC 5961 compliance is established.
- **49a port fix**: original ports 44444/55555 were ≥40000 (blocked by PS5 port policy). Fixed to 31337/31338.
- **49b: 280 IPv6 fragments, zero crashes.** Teardrop overlaps, queue exhaustion (50 incomplete + 101-frag bomb), max-size 65535B, over-max 65784B, atomic frags, 10 interleaved IDs reverse-completing, ext hdr combos, nested frag-in-frag, fragmented ICMPv6 — the log records these cases being sent and the run reaching COMPLETE; it does not establish that every intended reassembly handler processed them.

### Analysis
Saved tests cover the following four bounded sets; they do not exhaust these attack surfaces:
- SCTP chunk parser (39 variants, probe 48b)
- IPv6 extension headers (83 variants, probe 48c)
- TCP state machine injection (182 segments, probe 49a)
- IPv6 fragment reassembly (280 fragments, probe 49b)

The logs report **39 SCTP variants, 83 IPv6 packets, 182 TCP segments and 280 IPv6 fragments**, and each reaches COMPLETE. These counts use different units and do not establish handler coverage or RFC compliance. In 49a the observed TCP state remained ESTABLISHED after RST injection; that alone does not confirm RFC 5961 challenge ACK behavior. The 49b output does not independently establish RFC 5722 fragment-drop behavior.

### New Primitive
TCP_INFO seq number leak + raw IP socket + loopback checksum bypass = precise TCP injection into live connections. Confirmed working but TCP state machine handles it cleanly.

### Next Escalation Paths
1. Timer manipulation — keepalive/persist timer abuse over extended periods
2. High-volume resource exhaustion — thousands of connections/fragments to hit memory limits
3. Cross-protocol tunneling — IPv6-in-IPv4 (proto 41), GRE encapsulation edge cases
4. Less-tested protocol handlers — IGMP, PIM, VRRP, ESP/AH (simpler parsers, less audited)
5. PC-coordinated network attacks — real network packets from external host

---

## 2026-10-16: Probes 48b + 48c — SCTP and IPv6 Fuzz (No Crashes)

### Key Findings
- **48b: SCTP chunk parser robust** — 39 malformed SCTP variants via loopback raw socket, all delivered, zero crashes. INIT/SACK/COOKIE/ABORT/FWD_TSN/multi-chunk/unknown types all handled.
- **48c: IPv6 extension header parser robust** — 83 malformed IPv6 packets, zero crashes. HBH overrun, Routing Type 0 CVE, fragment overlaps/bombs, 16-deep header nesting, ICMPv6 option len=0, payload length mismatches all survived.
- Both loopback (127.0.0.1/::1) and LAN IP (10.0.0.96) delivery confirmed working via raw sockets.

### Analysis
The cited packet tests reached their completion markers; parser coverage and general hardening remain unestablished. Historical follow-up proposals:
1. **State-dependent SCTP** — complete INIT handshake to establish association, then send DATA/SACK/FWD-TSN on live state
2. **Real IPv6 fragment reassembly** — proper first+last fragment pairs with valid offsets, then overlaps and timing
3. **NDP cache poisoning** — valid-checksum NS/NA/RA to manipulate neighbor cache
4. **Protocol interaction** — IPv6-in-IPv4 tunneling, GRE/ESP encapsulation edge cases

---

## 2026-10-16: Probes 48a + 46c — MASSIVE Network Attack Surface Discovered

### Key Findings
- **★★ SCTP raw socket OPEN** (48a): `socket(AF_INET, SOCK_RAW, 132)` returns fd=22. Stream/dgram/seqpacket fail. Raw SCTP = direct access to kernel SCTP chunk processing.
- **★★ IPv6 fully available** (48a): TCP, UDP, RAW, ICMPv6 all open. 17 raw IPv6 protocols. Dual-stack possible (IPV6_V6ONLY can be disabled).
- **143 raw IPv4 protocols** (48a): Every protocol 0-142 creates a socket. GRE, ESP, AH, IGMP, PIM, VRRP all reachable.
- **IP options listener works** (46c): UDP+RAW sockets bound, IP_RECVOPTS set. 0 packets received (PC injector not running). Infrastructure validated.

### Impact
Network-side kernel attack surface is far larger than expected. SCTP, IPv6 NDP/fragmentation, and exotic protocol handlers are all reachable from the PC and represent thousands of lines of rarely-audited FreeBSD kernel code.

### Next Steps
- Write SCTP attack probes (INIT/COOKIE/DATA chunk fuzzing)
- Write IPv6 NDP and fragment reassembly probes
- Run coordinated PC+PS5 IP options injection test

---

## 2026-10-16: Probes 47a + 46a re-run — Syscall 557 Return Patterns, CClosure Test Pending

### Key Findings
- **Syscall 557 return patterns** (47a + 46a re-run): tested struct inputs produced argument-dependent values. In 47a, positive versions followed `517 + ver`, while version zero returned 16901; 46a recorded 1038/1039 for two struct inputs. No kernel pointer or exploit was demonstrated; these samples do not establish full semantics or rule out vulnerabilities.
- **Syscall 620 tested returns** — the recorded calls returned 0. The later 2026-10-18 baseline audit retracts the universal no-op interpretation: monitored sentinel windows and a faulty zero-struct checker do not establish absence of all writes.
- **47a Section C (CClosure write test) SKIPPED** — address parse bug, `__call` string has no `0x` prefix. This was a historical hypothesis; writability alone would not establish code execution.
- SCM_RIGHTS over socketpair: sendmsg/recvmsg succeed but cmsg data is zeros.
- LOCAL_PEERCRED: uid=1, gid=1, pid=0 (sandbox).

### Probe 47b: Historical CClosure Read-Only Conclusion (unresolved by audit)
- Fixed uint64 format bug and re-ran CClosure analysis
- The write loop covered `{16,24,32,40,48}` and omitted `+0`; the later audit found conflicting interpretations of the candidate offset.
- Some other offsets were reported writable, but their layout and effect on dispatch were not established.
- ROP-shaped metadata was writable; probe 45c later recorded tested syscall results persisting after selected mutations, so an execution role is not established
- The claim that all metatable functions have read-only `+0` is not supported by a write test.
- **Code execution through loader dispatch was not demonstrated; CClosure `+0` remains unresolved.** Retest 53d is prepared.

---

## 2026-10-16: Probes 46a-46d — Loader Internals + Socket Bypass

### Key Findings
- **Syscall 557 argument-dependent returns** (46a): `{ver=1,size=0x200}` returns 518 versus 16901 for the different `{size=0x200}` layout. The original kernel-write interpretation was retracted in the 2026-10-18 syscall-557 evidence correction: the checker used the wrong buffer baseline. The first run crashed on a format bug before the full sweep.
- **Structural observation (46b):** syscall objects share a reported C-function __call address; the truncated log does not identify its implementation or relationship to the ROP-shaped metadata
- **socketpair works** (46d): `socketpair(AF_LOCAL, SOCK_STREAM)` returns fd pair via make_syscall. Not in resolve() namespace. New IPC primitive.
- Socket creation identical between make_syscall and resolve — no hidden bypass
- SCTP still dead (-1)

### Status
Network-side attacks (TCP from PC) are the top priority. Need to run `tcp_fuzz_server_v2.py` on PC and send 46b_tcp_enhanced_listener.lua.

---

## 2026-10-16: Probe 45c — Earlier ROP/fn_addr Execution Interpretation Challenged

### Tested syscall results persisted across selected metadata mutations
- Probe 45c recorded syscall results persisting despite changed/invalid `fn_addr` values and tested chain corruption; it did not identify the complete dispatch implementation
- The tested `fn_addr` values (ud2, null, unmapped) produced no crash while syscall results continued; this does not by itself identify the complete dispatch implementation
- Corrupting the tested chain entries did not change the recorded getpid result; do not generalize beyond the entries tested
- Sysctl returns valid data even when fn_addr points to NOP+ret
- fn_addr value `0x9FE5_11100130` is NOT in any loaded module's text range

### Retracted Findings
- **W^X "defeat" (44a) was not demonstrated** — the test's syscall result persisted after selected metadata changes; no controlled code-page execution effect was recorded
- **fn_addr/slot0 arbitrary-function-call primitive is not established** — writes persisted, but the tested calls did not change after selected mutations
- **The earlier ROP-chain exploitation model is unsupported for the tested calls** — the dispatch implementation remains unidentified

### Remaining Attack Surface
- Tested syscall numbers via make_syscall(); probe 46b's C-function observation does not establish the implementation
- Heap R/W via GPU mmap
- Network-side packet injection (TCP/IP from PC)
- Sony syscall investigation (557/620)
- Loader internals reverse engineering

---

## 2026-10-16: Probes 45a-45b — Shellcode Execution Doubts

- 45a: Shellcode appears to execute (no crash) but all buffer writes return sentinel values
- 45b: Return value is ALWAYS pid regardless of eax. `xor eax,eax; ret` returns pid=128 (impossible if executing). All memory writes from shellcode fail. Raised first suspicion that shellcode isn't running.

---

## 2026-10-16: Probes 44a-44d — W^X DEFEATED (RETRACTED — see 45c above)

### ★★★ BREAKTHROUGH: Native Code Execution (44a)
- `sceKernelMtypeprotect(585)` with `PROT_READ|PROT_WRITE|PROT_EXEC` grants execute permission on mmap'd pages
- NOP sled, `mov eax` shellcode, and direct `syscall` instruction all execute from the page
- Combined with fn_addr redirect (43i), we have arbitrary native x86-64 code execution
- **W^X was the hardest wall in PS5 exploitation. It is now broken.**

### Other Results
- Syscall 557 (44b): returns 0x4205 as process type/sandbox query, no kernel pointers
- Sockopt heap corruption (44c): not exploitable, kernel clamps copy length
- Creative KASLR (44d): NET_RT_IFLISTL returns 6.5KB (no kptrs), kern.usrstack readable, all other paths blocked

### Status
**This historical status is superseded by probe 45c and the evidence audit.** Native code execution was not established, so KASLR defeat is not the sole remaining blocker. The 43o AF_ROUTE request and 43a/43b KLD calls remain inconclusive; see the correction at the top of this changelog and the prepared 53a–53d retests.

---

## 2026-10-16: Phase 10 Full Probe Sweep (43a-43p)

> **Evidence correction (2026-10-17):** The saved 43p output ends immediately before the first AIO call result. The historical statement below that it was an instant kill is unsupported by the output and is withdrawn. See `docs/SECONDARY_EXPLOIT_AUDIT_13.60.md`.

Sent all 16 Phase 10 probes. Several direct KASLR paths remain unresolved because the corresponding requests failed or their captures ended before results.

### Critical Finding
- **Historical interpretation, not established by current evidence:** fn_addr + slot0 writes persisted (43i), but that did not prove a function-call primitive. Probe 45c showed tested syscall results persisting after specific metadata mutations; it did not identify the complete dispatch implementation.

### Promising Leads
- **Syscall 557 returns 16901** (43g) — live Sony-custom syscall, unknown function. Needs targeted investigation.
- **mtypeprotect returns 1 for RWX** (43h, 43k) — the return did not establish executable memory or code execution; probe 45c undermines the proposed fn_addr dependency for the tested calls.
- **Syscall 620 returns 0** (43k) — another live Sony syscall.

### Paths Previously Labeled Dead Ends (Evidence-Audit Status Below)
- AF_ROUTE KASLR (43o): RTM_GET write failed; read returned 108 bytes with zero detected pointers; response attribution, leak and patch status unresolved
- AIO via make_syscall (43p): saved run ends before the first AIO call result; no conclusion can be drawn
- kldstat (43a): header-only 145-byte capture — outcome unknown
- kldsym (43b): header-only 116-byte capture — outcome unknown
- kinfo_proc full dump (43d): only sentinel values, no kernel pointers
- kern.proc.filedesc (43d): blocked
- kern.proc.vmmap (43d): blocked even with 256K buffers
- sysctl operations (43f): securelevel-labeled write returned -1; coredump/debug/maxproc reads failed and their conditional writes were not reached; somaxconn was read, not write-tested
- sysarch GET_GSBASE (43c): returns 0
- ioctl via make_syscall (43e): returns -1
- dup/dup2 (43e): returns -1
- thr_new (43e): crashes process
- kern.msgbuf (43j): returns 8 bytes only (filtered)
- mincore KASLR oracle (43l): kernel VA probes all -1
- sockopt overflow (43m): kernel clamps copy, not exploitable
- /dev/hid ioctl (43n): Sony error 0x80740004

### Other Findings
- fstat works via make_syscall (43e) — no kernel pointers but confirms stat struct access
- kinfo_proc process name is "boot.bin" (43d)
- kern.boottime readable: 0x6AD29A84 (43j)
- /dev/null, /dev/zero, /dev/urandom all open (43n)
- 32GB address (0x800000000) mapped in process VA space (43l)

### Status
**Blocker: KASLR defeat.** We have the function call primitive (43i) but no kernel address to call. All direct info leak paths are dead. Remaining vectors: Sony syscall 557/620 investigation, mtypeprotect exec test, network-side attacks (TCP/IP options from real network).
# 2026-10-20: kldsym session stopped at loader health gate

- Port `10.0.0.96:9026` accepted the two-second TCP connection check at approximately 08:43 EDT.
- The required `probes/phase19_umtx_454/151f_hello.lua` check connected and sent 73 bytes, then returned `CONNECTION_RESET` after 0.048 seconds with **0 response bytes**. No `HELLO`, PID, or `DONE` was received. The sender's `--save` mode preserves only nonempty responses unless `--metadata` is also passed, so there is no result file for this attempt.
- Per the session's explicit stop condition, `57e_kldsym_hardened.lua`, `139a_sysent_677_734.lua`, and `152a_shm_heap_race.lua` were **not sent**. This attempt provides no new evidence about kldsym or those two follow-up probes. Relaunch the game/loader and repeat the health gate before any probe.


## Syscall isolation sweep 662-670 (2026-10-20)

First measurement of numbers the range-wide "AIO hard wall" claim never reached: 662,
663 and 664 return `-1` with six zero arguments and the process survives; 665 terminates
the process inside the call; 666-670 remain unmeasured because the process is gone. 665
is labeled a `nosys` stub in the 13.60 capture, which does not match a lethal handler.

`tools/syscall_isolation_sweep.py`'s docstring claimed the loader spawns a fresh process
per connection. It does not: pid and module addresses are identical across consecutive
connections (159a/160a pid 133, 162a/163a/164a pid 143, 167a/168a pid 158) and change
only after a relaunch.

## 171a: kldsym is lethal, closing Theory 11 (2026-10-20)

`make_syscall(337)(1, KLDSYM_LOOKUP, &kld_sym_lookup)` with `version = 24` and
`symname = "prison0"` terminated the process before the first result row. kldsym was the
highest-ranked untested technique that could have returned a kernel address by name; it
now joins kldnext (307) and kldstat (308) as lethal, so the `kld*` family is unusable on
14.10 for any argument shape tested. `docs/UNTESTED_THEORIES.md` Theory 11 and the summary
table are updated, and CLAUDE.md no longer lists the retest as pending.

## 173a: an absent syscall slot kills the caller (2026-10-20)

`make_syscall(4095)` terminates the process. 4095 cannot have a handler, so the kill is
the dispatcher's response to a missing entry, not a hostile handler. One rule now covers
every lethal number recorded on this firmware (307, 308, 337, 570, 661, 665, 668, 4095):
the slot is absent. A `-1` return is the opposite signal — the handler exists and rejected
the arguments.

This reverses the reading of two earlier findings. The "AIO hard wall" was absence, and the
six numbers in 661-670 that returned `-1` are present handlers that have only ever been
given six zero arguments. Written up in `docs/SYSCALL_ABSENT_VS_LETHAL.md`, with the sweep
driver's classification documented accordingly.

## 174a/175a: the present 661-670 handlers are gated on absent state (2026-10-20)

662, 663, 664, 666, 667 and 669 return `-1` with valid pointers exactly as they do with
zeros, and 162 calls across three argument layouts (selector 0-8 in the first, second and
third position) produce no exception. The handlers are present but require an AIO context,
which only 661 could create, and 661 is an absent slot. The range cannot be entered.

## Presence map for 538-560 (2026-10-20)

All 23 numbers from 538 to 560 return a value, so every one of those slots exists on 14.10;
548 returns `0` to six zero arguments and the other 22 return `-1`. 561 is absent: it
terminates the process, which stopped the sweep there. New file
`docs/SYSENT_PRESENCE_14_10.md` records the measured map and the rule that `-1` means
present.

## 562 is absent too (2026-10-20)

The sweep from 562 stopped on its first number: 562 terminates the process like 561. So the
absent block at the bottom of the Sony range is at least two numbers wide, and the next run
starts at 563, which earlier probes reached successfully.

## Presence map 563-567, 568 absent (2026-10-20)

563-566 all return `0` to six zero arguments (matching what FINDINGS.md already recorded for
those numbers) and 567 returns `-1`. 568 is absent and terminated the process, so the map
so far is 538-560 present, 561/562/568 absent, 563-567 present.

Probe 176a is written to find out whether that death is confined to the calling thread: if a
child thread can absorb an absent-slot kill, the rest of the table can be mapped in one
connection instead of one relaunch per absent number.

## 176a: the absent-slot kill is process-wide (2026-10-20)

A `thr_create` child calling absent slot 4095 from `syscall_address` terminated the whole
process - the line after `thr_create` never printed. Probing absence from a child thread
does not avoid the relaunch, so each gap in the presence map costs one. Captures:
`results/phase17_new_vectors/176a_thread_absent_syscall_20261020_190459.txt`.

## 176b/177a: 563 and 564 accept a buffer in RSI and write nothing (2026-10-20)

With the buffer in `RDI` both numbers return `-1`; with the buffer in `RSI` both return `0`,
and neither changes a single dword of a canary-filled 0x400 page. 565-567 return `-1` in both
layouts. Probe 177a walks selectors 0-31 with the buffer in `RSI` to find out whether the
first argument selects what (if anything) is reported.

The presence sweep continued while the process was alive: 569 is absent like 568, 561 and 562.

## The 13.60 names explain the gaps: opmc is the live block (2026-10-20)

Cross-referencing `docs/sysent-names-13.60.csv` against the measured presence map changes the
reading of the whole 538-571 block. The absent slots are 561 `suspend_process`,
562 `resume_process` and 568-571 `budget_create/delete/get/set`: Sony removed the
process-control and budget families, which is why they kill instead of returning.

The present slots 563-566 are `opmc_enable`, `opmc_disable`, `opmc_set_ctl` and `opmc_set_ctr`,
and all four return `0` to six zero arguments. opmc is the AMD performance-monitoring-counter
interface, i.e. an MSR path: set_ctl and set_ctr imply an MSR write, and 567 `opmc_get_ctr`,
which does validate its arguments, is the matching read. Probe 177b establishes the argument
layouts using PMC-shaped indices only; it does not touch a dangerous MSR yet.

The map itself now carries the names for every measured slot. 177a walked selectors 0-31 for
563 and 564: only selector 0 is accepted, so the first argument is not a selector, and no
selector changed a buffer byte.

## 177a/177b: the opmc block accepts exactly one shape (2026-10-20)

177a walked the first argument of 563/564 through 0-31 with the buffer in `RSI`: only 0 is
accepted, and no selector changed a buffer byte. Its `changed=3072` line at `size=0x4000` is a
probe artifact - `fill()` canaried 0x1000 bytes while `scan()` read 0x4000 - and is not a
kernel write.

177b established the shape of the whole block:

| call | accepted | rejected |
|---|---|---|
| 563 `opmc_enable` | `(0, 0)` -> `0` | `(1, 0)`, `(page, 0x400)` |
| 565 `opmc_set_ctl` | `(0, 1)` -> `0` | every other index 1-7 |
| 566 `opmc_set_ctr` | `(0, 1)` -> `0` | index 1-7, and `(0, 0x5EA1)` |
| 567 `opmc_get_ctr` | nothing tried | all five layouts -> `-1` |

No call wrote a byte of a canary-filled page. `set_ctr` accepting 1 and rejecting 0x5EA1 shows
the second argument is validated as an enum or bitmask rather than used as a counter value, so
there is no evidence yet of a settable counter or of an index that reaches an arbitrary MSR.
The read side (`opmc_get_ctr`) has not accepted any layout, so no kernel data has come out.

## Probe drivers can wait out a loader death (2026-10-20)

`tools/send_probe.py` gained `wait_for_loader(ip, port, timeout, poll)`: it polls the loader
port (sending nothing) until the game is relaunched, and gives up after the budget. Both
drivers use it via `--wait-for-loader SECONDS`:

- `tools/syscall_isolation_sweep.py` retries the number that killed the process once the
  loader is back, then continues the range. Without the flag it still aborts on the first
  dead loader, so earlier captures keep their meaning.
- `tools/run_probe_batch.py` retries the failed probe and continues the list, recording
  `retried_after_relaunch` in the manifest.

The killing call itself cannot be avoided: an absent slot takes the process with it (176a), so
the manual step left is starting the game again. `docs/AFK_REMOTE_CONTROL.md` covers the
remote half (chiaki-ng key mapping), which needs its one-time pairing PIN.

## 177c/177d: the opmc block is argument-checking stubs, no state, no read (2026-10-20)

The value surface settles what 177b started. `opmc_enable` and `opmc_disable` accept every
second argument including `0xFFFFFFFF`; `opmc_set_ctl` accepts `{0,1,2,3,4}` and rejects 7 and
above; `opmc_set_ctr` accepts `{0,1,2,3,4,0xFFFFFFFF}`. The first argument must be 0 for all
four, and any other value - including bit positions such as 0x10000 - is rejected.

177d then asked the question that separates a working handler from a stub: does it keep state?
`enable` returned `0` on four consecutive calls, `disable` returned `0` on three, and
interleaving `set_ctl`/`set_ctr` changed nothing. A real enable answers `EEXIST` or `EBUSY` on
the second call, and disable fails when nothing is armed.

So the block validates argument one, ignores or range-checks argument two, keeps no state and
never reaches a readable counter. `opmc_get_ctr` has now rejected 12 argument layouts and has
never written a byte. The most likely 14.10 shape is the silent-success stub Sony uses
elsewhere (622 answers `0` with an error code in the buffer, 643 accepts every bit), i.e. a
feature this process is not provisioned for. No MSR access is demonstrated, and there is no
exploitable interface here.

Captures: `results/phase17_new_vectors/177c_opmc_value_surface_20261020_191711.txt`,
`177d_opmc_state_20261020_191735.txt`.

## The loader restarts itself about nine seconds after a kill (2026-10-20)

Measured directly: print pid and module base, call absent slot 4095, wait, print again.
`PID 292 SW 0x807584B57` became `PID 299 SW 0x818C90B57` after 9.31 s, with no console access.
So a fresh process, restarted by the game.

This invalidates the relaunch-per-absent-number cost in the earlier entries. It was an artefact
of sweeping with an abort-on-first-`CONNECT_FAILED` driver: the sweep never waited long enough
to see the recovery. The 572-600 sweep then ran through four kills (573, 589, 590, 597) and
completed, because `--wait-for-loader` just waited.

Presence results from that sweep: 574-588, 591-596, 598-600 all return (585 `is_in_sandbox`
returns `1`, 596 `dynlib_do_copy_relocations` returns `0`, the rest `-1`); 573, 589, 590 and 597
are absent. 572 returned nothing once and needs a re-run.

## Presence sweep 601-660 and a kill is not proof of an absent slot (2026-10-20)

The 601-660 sweep ran in 151 s across seven kills, unattended: 609, 614, 621, 622, 631, 650 and
651 took the process down, everything else returned. Highlights: 624 `get_vm_map_timestamp`
returns 3377, 643/640/638/639/617/620/602/606/657 return 0, 619 `test_debug_rwmem` returns -1,
and 653 `blockpool_open` hands out handles 22, 23, 24 before refusing.

`622 ipmimgr_call` killed the process on six zeros, yet `55c` had already got `ret=0` from it
with a real request. So a kill does not prove an absent slot: a present handler that faults or
refuses the arguments dies the same way. Every "absent" reading from a zero-argument sweep
(561, 562, 573, 589, 590, 597, 609, 614, 621, 631, 650, 651, 661, 665, 668) is now "kills with
zeros" and needs a second probe with plausible arguments. Only 4095 is known-absent. The
presence table's status column follows this, and `tools/gen_presence_map.py` regenerates it.

Follow-ups from the block: 619 rejected fifteen argument layouts with no byte written (a
privilege gate, not an argument shape); 625 accepts `arg1` in `{0x0D..0x10}` with `arg2` in
`{1,2,3}` and 626 answers nothing for 1270 shapes; 653 allocates three handles per process,
654/655 always return -1, 657 zeroes 16 bytes of its third argument. `docs/ATTACK_SURFACE.md`
carries the full table.

## 677-734 does not exist on 14.10 (2026-10-20)

Swept 677-734 with `--wait-for-loader 120`: 677 through 707 each killed the process and 708
never got a connection, after one recovery took 82 s instead of the usual 4-9 s. Thirty-one
consecutive kills including the five `nosys` slots (695-699) reads as past-the-end-of-table,
not as thirty-one hostile handlers, and the measured sysent therefore ends at 676.

That contradicts the 13.60 capture, which lists 735 entries and names the tail `wait6`,
`pipe2`, `ppoll`, `procctl`, `get_phys_page_size`, `ioreq`, `mmap2` and
`virtual_query_by_pid`. Two readings are open - 14.10 removed the tail, or the two tables
number differently - and neither can be settled without a 14.10 kernel image. The names above
676 are recorded as unverified and unreachable.

## The base range starts, and two kills that do not recover on their own (2026-10-20)

Swept 1-537 with `--skip 430` (that slot panics the kernel on a zeroed context, so it is
never swept). Measured so far: 1 `exit` kills, 2 `fork` `-1`, 3 `read` `0`, 4 `write` `-1`,
5 `open` `-1`, 6 `close` `-1`, 7 `wait4` `-1`, 8 `compat.creat` kills.

The recovery time is not uniform. After 4095 the loader came back in 9.31 s, but after 1 and
again after 8 the port stayed closed for more than 150 s, so those two runs stopped there and
9 was never measured. `--resume` now keeps a `CONNECT_FAILED` number in the queue instead of
treating it as covered, which is what lets the range continue at 9 once the console has the
loader again.
