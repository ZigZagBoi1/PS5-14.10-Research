# Changelog — PS5 14.10 Kernel Research

## 2026-10-20: `thr_create(430)` starts a user thread — threading is alive on 14.10

- New `docs/THREADING_ALIVE_14_10.md`. The kernel accepts a `thr_create(430)` context when it carries the three validator gates from the 13.60 decode (`+0x108 = 0x480`, `+0x0d0 <= 7`, `+0x110 = 0x10000`) and the user-mode selectors at the offsets the register copy actually reads: `CS = 0x43` at `+0x0c0`, `RIP` at `+0x0e0`, `RSP` at `+0x0f8`, `SS = 0x3b` at `+0x100`.
- `probes/phase17_new_vectors/156c_thr_create_correct_offsets.lua` returns `rv = 0`, writes TID `0x18ee3`, and `thr_kill(433, sig=0)` answers `0` for it, while the same call with a rejected context leaves a TID behind that `thr_kill` reports absent (`probes/phase17_new_vectors/156a_thr_create_spin_observable.lua`). `probes/phase17_new_vectors/156d_thr_create_child_executes.lua` goes further: the child executes `mov [rdi], rax; ret` (`48 89 07 c3` at `0x64832c67` in eboot's RX `.text`), stores `0xdeadbeefcafe` through `RDI` into a page we mapped, then spins at `jmp $` (`0x647b5481`). The console did not restart and the loader process kept pid 91 across every run.
- The 2026-10-19 thread series did not establish what its index rows claimed, so those rows are corrected: `80c` returned `rv = -1` with `marker unchanged — thread did not write`; `80h` returned `rv = 0` but never reads the marker back; `80i`'s four captures all stop at `calling thr_create`, so no DEADBEEF write is recorded. The earlier "CS=0x43 prevents the panic" reading of `80a` was also wrong — that context set none of the three gates, so the handler rejected it at `+0x108` before it read CS. `probes/phase17_new_vectors/156b_ucontext_layout.lua` confirms `thr_get_ucontext(634)` is not an alternative route: both argument shapes return `-1` and leave the buffer untouched.
- `probes/phase17_new_vectors/157a_syscall_loop_thread.lua` keeps a child thread inside the kernel. The loader exposes its own entry: `syscall.syscall_address` is `gettimeofday_import + 7`, so `syscall_address - 7` is the libkernel `mov rax, 116; mov r10, rcx; syscall; ret` wrapper. Starting the child there with a stack of repeated return addresses keeps it calling `gettimeofday` in a loop — the `timeval` advanced 21 ms while the main thread ran, `thr_kill(tid, 0)` answered `0`, and syscall 624 stayed flat because `gettimeofday` does no VM work. A 1 MB scan for `0f 05 c3` found no `syscall` instruction in eboot, so any other syscall entry has to come from libkernel.
- Thread teardown is now measured: `thr_kill(tid, 9)` ends the whole process rather than the thread, so it is only usable as a script's last statement, and a child left looping inside the kernel stops the loader from accepting connections until the game is relaunched. User-mode spinners did not.
- `probes/phase17_new_vectors/158a_thread_rop_syscall.lua` and 158b/158c test whether the child can choose its own syscall number. 158a's control stores `0x1234` from the context's `RAX` through `mov [rdi], rax; ret`, so context registers do reach the child. Through `syscall.syscall_address` the observed call is always `gettimeofday`: `RAX = 116` fills a timeval, and `RAX = 432` (`thr_self`) wrote the same timeval seconds into its buffer instead of a TID. The loader's own `make_syscall(20)` returns a real pid through that address, so the contradiction is unresolved; the umtx race cannot be armed until it is.
- Hazards recorded: reading libkernel `.text` to locate the `syscall` instruction kills the process (execute-only, no pcall survives); a `timeval` layout in `nanosleep` sets `tv_sec = 0x0727C00000000000` and parks the Lua thread forever, which the loader masks by continuing to accept TCP — a 6-second `PING` returning zero bytes detects it.
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


## 159a - the child picks its own syscall number (2026-10-20)

The 158 series reported that a child thread's syscall number was ignored and every call
became `gettimeofday`. That was a probe bug: 158a-158c started the child at
`syscall_address - 7`, which is the `mov rax, 116` prologue, so `RAX` was overwritten
before the `syscall`. Entering at `syscall_address` itself, a thread with `RAX = 432`
(`thr_self`) wrote its own thread id (`0x18E41`) into its argument buffer, matching the
tid `thr_create` returned. Child threads can issue any syscall with full argument
control — the prerequisite for the umtx race.

Files: `probes/phase17_new_vectors/159a_syscall_path_control.lua`,
`results/phase17_new_vectors/159a_syscall_path_control_20261020_180533.*`,
`docs/THREADING_ALIVE_14_10.md`.

## 160a - _umtx_op from a child thread (2026-10-20)

With the entry point fixed, a child thread issued `_umtx_op` (454) with `op` in `RSI`
and `val` in `RDX`, and its return value was captured by parking it on a two-slot stack
`[mov [rdi],rax; ret][jmp $]` so the syscall result is written back to the uaddr the
probe already owns. All three rows (WAKE 3, WAKE_PRIVATE 11, WAIT_UINT 9) returned 0
and overwrote the `0x1111` sentinel in their slot, so the write-back path is sound.
The thread, not the process, now owns a live syscall primitive.

Files: `probes/phase17_new_vectors/160a_thread_umtx_return.lua`,
`results/phase17_new_vectors/160a_thread_umtx_return_20261020_180702.*`.

## 161a - _umtx_op op codes from child threads (2026-10-20)

28 threads, one per op code 0-27, each issuing `_umtx_op(454)` with `obj` = its own
return slot, `op` in `RSI`, `val = 0`, and two valid user pages in `RCX`/`R8`. The
return value comes back through the `mov [rdi],rax; ret` stack trick from 160a.

| ops | observed |
|---|---|
| 0, 1, 4 | `-1` (qword `0xFFFFFFFFFFFFFFFF`) |
| 2, 3 | `0` |
| 5 | `0x80001111` (Sony-shaped error, not a plain errno) |
| 6-17 | no store — the thread never returned from the syscall |
| 18 | probe stalled; process stopped answering |

Rows 6-17 are the interesting ones: the handler blocked inside the kernel, so the store
gadget never ran. Those threads are alive and unreaped — `thr_kill(tid, 0)` reports them
as existing, and they cost a thread slot each.

The stall at op 18 is not an op-18 behaviour claim. It coincides with the 19th live
thread in the process (18 here plus leftovers from 159a/160a): `thr_create` stops
returning once the per-process thread budget is exhausted, which also explains 158c's
silent stall after two `thr_create` calls. Treat parked threads as a finite resource:
a session gets roughly twenty, and the count is per process, so a relaunch resets it.

Files: `probes/phase17_new_vectors/161a_umtx_op_enumeration.lua`,
`results/phase17_new_vectors/161a_umtx_op_enumeration_20261020_181142.*`.

## 162a-164a - _umtx_op mutex semantics and the timeout pointer (2026-10-20)

`_umtx_op(454)` op 4 and op 5 are live mutex operations, driven from the main thread
with a user word as `obj`:

- unlocked (zero) word: ret `0`, and the handler writes the calling thread id
  (`0x18D9F`) into the word;
- word already holding an owner: ret `-1`;
- `obj = NULL`: ret `-1`;
- `obj` unaligned: ret `0` and the owner is written at the odd address
  (`word` reads `0x018D9F00`), so there is no alignment check.
- ops 0, 1 return `-1` for every argument tried, including a valid zeroed word, so
  they are not LOCK/UNLOCK on this kernel.

163a handed op 4/5 a NULL, an unmapped (`0x1000`) and a kernel-shaped
(`0xFFFFF000_00000000`) `uaddr2`; all returned `0` and none faulted. The lock was
uncontended, so the timeout path never ran — that result says nothing about the
timeout parser.

164a forced contention: the main thread locked a word, then a child asked for the same
word with `uaddr2` at the kernel-shaped address (and, separately, at `0x1000`). The
child blocked and never returned; the slot stayed at its sentinel, and the word changed
to `0xFFFFFFFFFFFFFFFF` (the contended marker). No panic, no EFAULT. The wait path
therefore refuses the timeout without copying it in, or defers the copy — either way the
bad pointer is not dereferenced at lock time.

Note: op codes here are the probe's numbering, still unconfirmed against the kernel's
table.

## 165a - block then wake (2026-10-20)

Three ops that blocked in 161a were each given one thread on its own zeroed word, then
the main thread called op 3 (the only code that returns 0 on a free word) with
`val = 1` on that same word.

| op | word after the child ran | after op 3 |
|---|---|---|
| 6 | `0xFFFFFFFFFFFFFFFF` (contended marker) | unchanged, child still blocked |
| 9 | `0` (untouched) | unchanged, child still blocked |
| 12 | `0` (untouched) | unchanged, child still blocked |

Op 6 marks the word before sleeping, which is mutex-contention shaped; ops 9 and 12
sleep without touching `obj` at all, so they wait on something reached another way
(pointer arguments, not the word). Op 3 does not release any of the three, so either it
is not the wake for these classes or the wake requires the owner encoding the handler
itself wrote.

Canary stayed alive throughout (pid 148); three threads were spent, leaving the process
with three kernel-blocked threads that only a relaunch clears.

## 166a - pointer arguments of the sleeping ops (2026-10-20)

Ops 9 and 12 were each given a kernel-shaped (`0xFFFFF000_00000000`) and a NULL pointer
in `RCX`, and a kernel-shaped pointer in `R8`, one thread per variant.

All six threads slept. No variant returned, no thread faulted, the process survived
(pid 153). The only side effect anywhere was op 12 with `R8 = kernel range` setting the
contended marker (`0xFFFFFFFFFFFFFFFF`) in the word, which means it reached the mutex
path with an otherwise unused pointer.

So the sleep for these ops happens before any dereference of `RCX`/`R8`, or those
registers are not the parameters the handler reads. The probe cannot separate those two
readings, and the op numbering is still the probe's assumption rather than the kernel's
table.

## 167a - no unlock found (2026-10-20)

A word locked by the main thread (op 5, owner `0x18CC3`) was handed to ops 1, 0 and 2
from child threads. All three slept and never returned:

| op | word after the child slept |
|---|---|
| 1 | unchanged, child blocked |
| 0 | `0xFFFFFFFFFFFFFFFF` (contended marker) |
| 2 | untouched, child blocked |

Op 0 marks the word contended, the same shape op 6 produced in 165a. Ops 1 and 2 sleep
on an owned word but do not touch it.

None of the three releases the mutex, so the reverse operation is still unlocated. That
matters operationally: every contention experiment consumes a word permanently, because
nothing available so far clears an owner. Combined with 162a (ops 0 and 1 return -1 on an
*unowned* word) the mutex surface reads as "op 5 locks, several ops sleep on contention,
and the matching release is not in the codes we can call from a thread".

Repeating this with `val` set to the owner tid is the obvious next variant, since a
handler that compares the caller against `val` before releasing would reject our `val=0`
and sleep.

## 168a - the mutex never releases (2026-10-20)

Ops 1, 2 and 6 were given a word owned by the main thread (`0x18CC3`) with the owner
value itself in `RDX`. All three slept again; op 6 set the contended marker, ops 1 and 2
left the word untouched. Passing the owner does not change the outcome, so the release
is not among the codes reachable this way, and the contention avenue closes: every lock
we take is permanent for the life of the process.

## A correction to a long-standing assumption

The loader process id was `158` in 167a and again in 168a, with a relaunch of the game
between earlier sessions but three separate TCP connections inside this one. The process
is therefore *not* recreated per connection. Threads parked in the kernel survive across
probes, the per-process thread budget is shared by everything sent over 9026, and only a
game relaunch clears either. Any earlier result that attributed a fault to "the fresh
process" needs re-reading with that in mind.

## Sweep 666-668 (2026-10-20)

666 and 667 return `-1` with six zero arguments; 668 kills the process. Together with the
first sweep the pattern is: every number the 13.60 capture labels a `nosys` stub (665 and
668) is lethal on 14.10, and every non-stub number in 661-670 measured so far returns
`-1` and survives. 669-670 remain unmeasured.

## The 661-670 range measured (2026-10-20)

Every number in 661-670 has now been called in its own connection. 662, 663, 664, 666,
667 and 669 return `-1` with six zero arguments; 670 returns `0`; 661, 665 and 668 kill the
process.

The lethal numbers are 661 (AIO submit) and the two slots the 13.60 capture labels `nosys`
stubs (665, 668). 668 kills with a valid writable page in `RDI`/`RSI` as well as with
zeros, so the stub is lethal for at least two argument shapes. The earlier range-wide
"hard wall" claim generalized from 661 and is contradicted by seven measured survivals.

Files: `results/phase15_native_sysent/syscall_isolation_sweep_20261020_1833*.txt`,
`probes/phase17_new_vectors/169a_sys_668_argument_shape.lua`,
`results/phase17_new_vectors/169a_sys_668_argument_shape_20261020_183349.*`.

## 170a: sys 670 has no observable side effect (2026-10-20)

670 returns `0` to six zero arguments and 675-style reset was a plausible reason, but
`mprotect(RWX)`, `fork`, sys 587 and sys 629 all return exactly what they returned before
the call. The range is closed: 661, 665 and 668 kill, the rest return without changing the
tested walls.
