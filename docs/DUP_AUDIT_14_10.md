# Duplicate audit: local docs vs upstream origin/master

Static, offline audit of `C:/PS5contrib/docs/**/*.md` against the upstream tree pinned at **`c7f3b000`**
(2026-11-05 04:51 +0100), read from `C:/tmp/wt-run`. No console, no network, no probes. Written 2026-11-05.

One correction to the brief: `origin/master` in that clone currently points at `ab3379c6` (2026-11-04 23:25),
which is 23 docs and 1,560 lines *behind* `c7f3b000`. The first pass of this audit ran against `ab3379c6`; it
was redone against `c7f3b000`, which is what the tables below report. The difference was material: `c7f3b000`
already contains `FONTFACE_MEMBER_MAP_14_10.md` and the `SYS_591/608/656` dynlib decodes, so a verdict taken
at `ab3379c6` would have called three local docs new when they are not.

## 0. Method

1. Local inventory: `Get-ChildItem docs -Recurse -Filter *.md` -> **134** `.md` files (126 at top level, 7 under
   `research/`, 1 under `dumps_13.60/`), excluding this file. Two of them (`SOCKET_IOCTL_14_10.md`,
   `UPSTREAM_STATE_2026_11_05.md`) were written by other sessions *while this audit ran*; they are in the
   table, marked as late arrivals, and the 132-file figure is the snapshot at 10:28 UTC.
2. Upstream inventory: `git -C C:/tmp/wt-run ls-tree -r --name-only c7f3b000 docs` -> **227** `.md` files at
   the pinned commit (218 at `ab3379c6`). Blobs were exported once with
   `git archive --format=zip -o .local/tmp/up_c7.zip c7f3b000 -- 'docs/*.md'` and unpacked to `.local/tmp/up7/`,
   so every comparison reads the same bytes `git show c7f3b000:docs/FILE.md` would print, without 200+ shell
   round trips.
3. Common names (79): normalise both sides (CRLF -> LF, rstrip every line, collapse blank runs, drop leading and
   trailing blanks), sha256 the normalised text, then set-difference the non-empty lines. `difflib` was used only
   for files under 4,000 lines; `ALL_PROBES.md` and `ALL_RESULTS.md` (73k lines each) were compared as line sets.
4. Verdicts:
   - **IDENTICAL** - same normalised sha256.
   - **SUPERSET-LOCAL** - every upstream non-empty line is present locally, plus more. **None exist.**
   - **SUBSET-LOCAL** - local is upstream minus lines.
   - **DIVERGENT** - each side holds non-empty lines the other does not.
   - **NET-NEW** - no upstream file of that name.
5. Local-only docs (55) were additionally screened for *semantic* duplication: `grep` of upstream for the eight
   required topics, plus a token-coverage pass (how many of a local doc's probe IDs and RVA literals also occur
   anywhere upstream). Section 4 reports the result.

## 1. Counts

| bucket | count |
|---|---:|
| local `.md` files | 134 (132 at the 10:28 snapshot) |
| name present on both sides | 79 |
| - IDENTICAL | 44 (39 byte-identical, 5 EOL/whitespace only) |
| - DIVERGENT | 32 |
| - SUBSET-LOCAL | 3 |
| - SUPERSET-LOCAL | 0 |
| local-only (NET-NEW) | 55 (53 at the snapshot, plus both late arrivals) |
| upstream-only (no local file) | 148 (59 of them under `docs/2026-10-25/`, `docs/agent-work/`, `docs/research/`) |

The shape of the tree matters more than the counts: **the local docs and upstream are two different branches of
the same work, not a stale copy.** Local holds probes 894a-1222a (the 2026-11-04/05 phase-17 runs) that upstream
does not have; upstream holds the 2026-10-25 dossier, `DEAD_ENDS.md`, `JAIL_14_10.md`, `AIO_BATCH_14_10.md`,
`SYS601_1360_DISPATCH_AUDIT_2026-10-22.md`, the 10-28 'Lua surface exhausted' rewrite and the 11-05 dynlib and
fault-oracle decodes that local does not have. 32 of the 79 shared files have drifted in both directions.

## 2. Table

`upstream counterpart` is the same relative path unless marked otherwise.

| local file | upstream counterpart | verdict | note |
|---|---|---|---|
| `AFK_REMOTE_CONTROL.md` | `AFK_REMOTE_CONTROL.md` | IDENTICAL | EOL/whitespace only (3,093 vs 3,126 B) |
| `AIO_RANGE_14_10_EVIDENCE.md` | `AIO_RANGE_14_10_EVIDENCE.md` | DIVERGENT | two-way drift: local holds the 10-27 882a last-item-storm failure and the spinner-fault diagnosis, upstream holds the 10-24 663 'validates like the others' decode (L1904 / U2213, +210 / -443) |
| `ALL_PROBES.md` | `ALL_PROBES.md` | DIVERGENT | index bookkeeping only: local 'Total probes: 230', upstream '2682 across 52 phase directories' (73,753 vs 73,755 lines, +2 / -3) |
| `ALL_RESULTS.md` | `ALL_RESULTS.md` | DIVERGENT | index bookkeeping only: local '247 result files', upstream '3005' (+2 / -3) |
| `ANALYSIS_thr_create_panic_2026-10-19.md` | `ANALYSIS_thr_create_panic_2026-10-19.md` | IDENTICAL | byte-identical |
| `ATTACK_SURFACE.md` | `ATTACK_SURFACE.md` | DIVERGENT | local is the 2026-10-18 table (249 lines); upstream is 740 lines with the 10-21 Sony sweep. Direct row contradictions on 455, 482 and 661 (section 3) |
| `BROWSER_ENTRY_INFRA_2026-10-19.md` | `BROWSER_ENTRY_INFRA_2026-10-19.md` | IDENTICAL | byte-identical |
| `CHANGELOG.md` | `CHANGELOG.md` | DIVERGENT | local head is 2026-11-05 (arg-4 retraction, 663 mode-0 guard); upstream head is 2026-11-04 (Lua syntax gate) and carries 10-29 CSSFontFace entries local never had (+612 / -48) |
| `CORRECTED_MIB_14_10_EVIDENCE.md` | `CORRECTED_MIB_14_10_EVIDENCE.md` | IDENTICAL | byte-identical |
| `CRASH_EVENT_2026-10-19.md` | `CRASH_EVENT_2026-10-19.md` | IDENTICAL | byte-identical |
| `CROSS_FIRMWARE_PATTERN_RESEARCH.md` | `CROSS_FIRMWARE_PATTERN_RESEARCH.md` | IDENTICAL | byte-identical |
| `CVE-2026-45258-PS5-14.10.md` | `CVE-2026-45258-PS5-14.10.md` | IDENTICAL | byte-identical |
| `CVE-2026-49412-PS5-14.10.md` | `CVE-2026-49412-PS5-14.10.md` | DIVERGENT | local: option 74 never issued, applicability unresolved; upstream (10-22): handler reachable with a valid source-list copyin from a second thread |
| `CVE-2026-49418-PS5-14.10.md` | `CVE-2026-49418-PS5-14.10.md` | DIVERGENT | local: 'msync was never tested', strongest applicability; upstream: a saved 58a capture reaches the pre-call marker and stops, and 10-25 records the door closed |
| `CVE-2026-49419-PS5-14.10.md` | `CVE-2026-49419-PS5-14.10.md` | IDENTICAL | byte-identical |
| `CVE-2026-49422-PS5-14.10.md` | `CVE-2026-49422-PS5-14.10.md` | IDENTICAL | byte-identical |
| `CVE-2026-49424-PS5-14.10.md` | `CVE-2026-49424-PS5-14.10.md` | IDENTICAL | byte-identical |
| `CVE-2026-49427-PS5-14.10.md` | `CVE-2026-49427-PS5-14.10.md` | IDENTICAL | byte-identical |
| `CVE-2026-58083-PS5-14.10.md` | `CVE-2026-58083-PS5-14.10.md` | IDENTICAL | byte-identical |
| `CVE-2026-58090-PS5-14.10.md` | `CVE-2026-58090-PS5-14.10.md` | IDENTICAL | byte-identical |
| `CVE-2026-58093-PS5-14.10.md` | `CVE-2026-58093-PS5-14.10.md` | IDENTICAL | byte-identical |
| `CVE-2026-7270-ASSESSMENT.md` | `CVE-2026-7270-ASSESSMENT.md` | IDENTICAL | byte-identical |
| `EVIDENCE_AUDIT_2026-10-17.md` | `EVIDENCE_AUDIT_2026-10-17.md` | IDENTICAL | byte-identical |
| `EXPLOIT_SURFACE_ANALYSIS_13.60.md` | `EXPLOIT_SURFACE_ANALYSIS_13.60.md` | SUBSET-LOCAL | missing upstream's 2-line historical-draft banner that withdraws the SCM_RIGHTS claim |
| `FINDINGS.md` | `FINDINGS.md` | DIVERGENT | local is the pre-correction text (Finding 2 and the gadget line); upstream carries the 10-23 threading correction and the eboot-readability correction (+307 / -423) |
| `GHIDRA_REFERENCE_VALIDATION_2026-10-18.md` | `GHIDRA_REFERENCE_VALIDATION_2026-10-18.md` | IDENTICAL | byte-identical |
| `GIC_COMMAND_14_10.md` | `GIC_COMMAND_14_10.md` | IDENTICAL | EOL/whitespace only (5,891 vs 6,016 B) |
| `GOLD_VECTORS_2026-10-19.md` | `GOLD_VECTORS_2026-10-19.md` | DIVERGENT | local: 58a 'written, NEVER RUN'; upstream: 'RUN AND REFUSED - door closed' plus the thr_suspend signature correction |
| `HANDLER_CLAIM_CORRECTIONS.md` | `HANDLER_CLAIM_CORRECTIONS.md` | DIVERGENT | opposite reading of the same guard: local 'Claim 3 holds, and the guard is a lower bound'; upstream 'Claim 3 does not hold: the guard is an upper bound of 128' |
| `HANDLE_NAMESPACE_14_10.md` | `HANDLE_NAMESPACE_14_10.md` | DIVERGENT | different measurements under one name: local 88a/88b return-value vs out-pointer, upstream 96b-96f generation wrap period (3 bits, wraps after 8) |
| `INDEPENDENT_EVIDENCE_AUDIT_2026-10-17.md` | `INDEPENDENT_EVIDENCE_AUDIT_2026-10-17.md` | IDENTICAL | byte-identical |
| `IPV6_ANCILLARY_14_10.md` | `IPV6_ANCILLARY_14_10.md` | DIVERGENT | local: 'IPV6_MSFILTER is not implemented at all (50e)'; upstream: it works with amd64 sockaddr_storage alignment (50f) |
| `KERNEL_DUMP_ANALYSIS.md` | `KERNEL_DUMP_ANALYSIS.md` | IDENTICAL | byte-identical |
| `KEVENT_TIMEOUT_VARIABLE.md` | `KEVENT_TIMEOUT_VARIABLE.md` | DIVERGENT | local leaves split + non-zero timeout untested and blames the timeout; upstream 58f ran the full 2x2 matrix and every cell worked at 100 ms |
| `KLDSYM_14_10_EVIDENCE.md` | `KLDSYM_14_10_EVIDENCE.md` | IDENTICAL | byte-identical |
| `KQUEUE_PROC_14_10.md` | `KQUEUE_PROC_14_10.md` | IDENTICAL | EOL/whitespace only (4,849 vs 4,947 B) |
| `MLFS_14_10.md` | `MLFS_14_10.md` | IDENTICAL | EOL/whitespace only (4,015 vs 4,094 B) |
| `PANIC_ORACLE.md` | `PANIC_ORACLE.md` | IDENTICAL | byte-identical |
| `PROBE_INDEX.md` | `PROBE_INDEX.md` | DIVERGENT | local index predates the 10-19 session and keeps 271a-273a PREPARED rows upstream deleted; upstream adds the LIVE_TEST_SESSION pointer (+99 / -68) |
| `PROGRESS_AUDIT.md` | `PROGRESS_AUDIT.md` | DIVERGENT | local scores 25/100 at snapshot 24c888b0, upstream 63/100 at 353cdc6 with 1838 Lua probes inventoried (+52 / -101) |
| `REMAINING_CVE_TRIAGE.md` | `REMAINING_CVE_TRIAGE.md` | DIVERGENT | local: 'sendfile has never been issued'; upstream: 58d issued two sendfile shapes, both -1, so KTLS availability is the first unknown |
| `RESEARCH_EVIDENCE.md` | `RESEARCH_EVIDENCE.md` | DIVERGENT | local describes supersession in prose; upstream adds strict-JSON ledger rules (duplicate members, NaN/Infinity rejection) |
| `RESEARCH_PAPER.md` | `RESEARCH_PAPER.md` | DIVERGENT | local keeps four pre-correction statements, incl. 'kevent(363) - always returns -1'; upstream has the timeout-dependent wording and a non-absolute dead-end table |
| `RETEST_PLAN_53.md` | `RETEST_PLAN_53.md` | SUBSET-LOCAL | missing upstream's 2026-10-20 update recording that 53b has now run |
| `RWX_ORACLE_14_10.md` | `RWX_ORACLE_14_10.md` | DIVERGENT | local calls itself 'the first direct test'; upstream credits 237b's read-back method and only the execution half as new |
| `SECONDARY_EXPLOIT_AUDIT_13.60.md` | `SECONDARY_EXPLOIT_AUDIT_13.60.md` | IDENTICAL | byte-identical |
| `STRATEGY.md` | `STRATEGY.md` | DIVERGENT | local is the 2026-10-18 position ('we have userland code execution ... the goal is kernel R/W'); upstream is 2026-10-28 'Lua surface exhausted, WebKit only path' |
| `SYSCALL_430_MISLABEL.md` | `SYSCALL_430_MISLABEL.md` | IDENTICAL | byte-identical |
| `SYSCALL_557_14_10_EVIDENCE.md` | `SYSCALL_557_14_10_EVIDENCE.md` | IDENTICAL | byte-identical |
| `SYSCALL_ABSENT_VS_LETHAL.md` | `SYSCALL_ABSENT_VS_LETHAL.md` | DIVERGENT | local stops before the 10-22 SIGSYS resolution and the shared nosys-trampoline identity; upstream is 335 lines, local 244 (-142) |
| `SYSCALL_CONTRACTS_13_60.md` | `SYSCALL_CONTRACTS_13_60.md` | DIVERGENT | local leaves '-' placeholders where upstream fills decoded contracts for 591, 604, 636 and 656 |
| `SYSCALL_LABEL_CORRECTION.md` | `SYSCALL_LABEL_CORRECTION.md` | IDENTICAL | byte-identical |
| `SYSCALL_NAME_MAP_13.60.md` | `SYSCALL_NAME_MAP_13.60.md` | IDENTICAL | byte-identical |
| `SYSCALL_SHAPE_SWEEP_14_10.md` | `SYSCALL_SHAPE_SWEEP_14_10.md` | IDENTICAL | EOL/whitespace only (3,614 vs 3,697 B) |
| `SYSENT_PRESENCE_14_10.md` | `SYSENT_PRESENCE_14_10.md` | DIVERGENT | local keeps the summary only (230 lines); upstream carries the full 1-708 row table plus the 10-21 offline thunk resolution (-514) |
| `THREADING_ALIVE_14_10.md` | `THREADING_ALIVE_14_10.md` | DIVERGENT | local adds the 10-25 712c-720a native-child syscall work; upstream carries the 10-21 GP register layout (91u) and the 10-23 selector-sanitisation series (448a-452a) |
| `THR_CREATE_430_CONTEXT.md` | `THR_CREATE_430_CONTEXT.md` | IDENTICAL | byte-identical |
| `THR_CREATE_PANIC_PATH_13.60.md` | `THR_CREATE_PANIC_PATH_13.60.md` | SUBSET-LOCAL | missing the 22-line 189a section (CS=0x40 executes, so the missing-mask reading does not hold for 14.10) |
| `TIER1_CLAIMS_4_8_AUDIT.md` | `TIER1_CLAIMS_4_8_AUDIT.md` | IDENTICAL | byte-identical |
| `TIER2_CLAIMS_AUDIT.md` | `TIER2_CLAIMS_AUDIT.md` | IDENTICAL | byte-identical |
| `TIER3_CLAIMS_AUDIT.md` | `TIER3_CLAIMS_AUDIT.md` | IDENTICAL | byte-identical |
| `UMTX_454_EVIDENCE.md` | `UMTX_454_EVIDENCE.md` | DIVERGENT | local maps the 14.10 op space and records the op-19 loader wedge (501d); upstream records the UMTX_OP_SHM stub series (151a-152k) |
| `UNTESTED_THEORIES.md` | `UNTESTED_THEORIES.md` | DIVERGENT | local keeps the 10-18 scope banner and 17 generic theories; upstream is the 10-28 ranking with WebKit Canvas as Theory 0 |
| `USERLAND_ENTRY.md` | `USERLAND_ENTRY.md` | DIVERGENT | upstream updates the install path (n0llptr repo move, inject.iet, 'remote lua loader' notification); local keeps the older wording |
| `VERIFIED_HANDLER_ANALYSIS.md` | `VERIFIED_HANDLER_ANALYSIS.md` | DIVERGENT | claim 3 is 'CONFIRMED DEFINITIVE' locally and 'REFUTED' upstream, both from the same ja 0x3afa33 |
| `WEBKIT_BATTERY_1410_2026-10-19.md` | `WEBKIT_BATTERY_1410_2026-10-19.md` | IDENTICAL | byte-identical |
| `WEBKIT_CORPUS.md` | `WEBKIT_CORPUS.md` | DIVERGENT | local counts 518 built pages; upstream counts 509 and adds the 10-21 pass logs (-153) |
| `WEBKIT_FINDINGS.md` | `WEBKIT_FINDINGS.md` | DIVERGENT | local is the pastawithpesto-derived text; upstream adds the 10-19 false-positive correction for the .length=81400 claim (+449 / -414) |
| `WEBKIT_LENGTH_WINDOW_AUDIT.md` | `WEBKIT_LENGTH_WINDOW_AUDIT.md` | DIVERGENT | local adds section 7 (14.10 site sweep) and pins WebKit 97df94ead0; upstream marks the premise superseded in line 2 |
| `WEBKIT_STAGE1_1410_LIVE_TEST_2026-10-19.md` | `WEBKIT_STAGE1_1410_LIVE_TEST_2026-10-19.md` | IDENTICAL | byte-identical |
| `dumps_13.60/README.md` | `dumps_13.60/README.md` | IDENTICAL | byte-identical |
| `research/IMPLEMENTATION_FOLLOWUP_2026-10-18.md` | `research/IMPLEMENTATION_FOLLOWUP_2026-10-18.md` | IDENTICAL | byte-identical |
| `research/gpu_dma_research.md` | `research/gpu_dma_research.md` | IDENTICAL | byte-identical |
| `research/kernel_re_guide.md` | `research/kernel_re_guide.md` | IDENTICAL | byte-identical |
| `research/loader_internals_analysis.md` | `research/loader_internals_analysis.md` | IDENTICAL | byte-identical |
| `research/race_condition_analysis.md` | `research/race_condition_analysis.md` | IDENTICAL | byte-identical |
| `research/relapse_variant_analysis.md` | `research/relapse_variant_analysis.md` | IDENTICAL | byte-identical |
| `research/scene_research_oct2026.md` | `research/scene_research_oct2026.md` | IDENTICAL | byte-identical |
| `AIO_DEBUG_726_727_13_60.md` | - | NET-NEW | 13.60 sysent 726/727 (get_aio_debug_submit_info / request_info) hand raw kernel pointers to userland; both are absent from the 677-entry table 14.10 dispatches, so this is static only. probes: none (static, 13.60 bytes) |
| `AIO_INFLIGHT_14_10.md` | `AIO_BATCH_14_10.md (partial)` | NET-NEW | aio submit is real on 14.10 and delete refuses in-flight entries; corrects the earlier 'bookkeeping only' reading. probes: 894a, 943a, 954a-959a |
| `AIO_MODE0_GUARD_14_10.md` | `AIO_RANGE_14_10_EVIDENCE.md` | NET-NEW | 663 refuses mode 0 with count>1 before the id list is copied in (EINVAL, not EFAULT); the Bagagwa/Relapse aio_multi_wait shape is patched. probes: 1219a, 1219b, 1221a |
| `ARG4_TRAMPOLINE_14_10.md` | `THREADING_ALIVE_14_10.md` | NET-NEW | libkernel+0x3B0 is a syscall stub whose +7 byte is mov r10, rcx, so libkernel+0x3B7 delivers argument 4; first mtypeprotect(379) sweep. probes: 1216b, 1217a, 1218a, 1219a, 1219b, 1220a, 1211a, 1213c |
| `CAPABILITY_CONTEXT_14_10.md` | `OFFLINE_HANDLER_DECODE_2026-10-23.md` | NET-NEW | sys 636 timezone loader, 638 lookup, 643 unconditional write to proc+0xa34, 675 reset: none is a primitive. probes: 1209a, 1210a, 100c |
| `CFI_CENSUS_13_60.md` | `THR_CREATE_430_CONTEXT.md` | NET-NEW | function-pointer whitelist census: 934 stubs in [0x2652E0, 0x267008), 11,602 residual indirect calls not in the range. static: none (13.60 capstone) |
| `COPYIN_DEST_PROVENANCE_14_10.md` | - | NET-NEW | destination (rsi) of every direct copyin call audited; no site takes a destination from user memory. static: none (563 RVAs cited) |
| `COPYIN_LENGTH_SCREEN_14_10.md` | - | NET-NEW | the twelve stack-destination copyin sites are all length-bounded; companion to the provenance audit. static: none |
| `COPYOUT_CLASS_CLOSED.md` | - | NET-NEW | the three copy-out audits close the class; the helper body is in the corpus after all, which corrects both earlier audits. static: none |
| `COPYOUT_INLINE_MOVE_AUDIT.md` | - | NET-NEW | inline kernel-to-user moves that bypass the helper (string ops, stac regions): 0 provable leaks in the class. static: none (Chinese text) |
| `COPYOUT_LENGTH_AUDIT_14_10.md` | - | NET-NEW | 21 kernel-to-user copy sites with a dynamic length, all clamped; no site hands userland more bytes than it wrote. static: none (754f, 781d cited as corpus) |
| `COPYOUT_PARTIAL_STACK_AUDIT.md` | - | NET-NEW | the '62 handlers' figure does not reproduce; partial-initialisation stack copies enumerated. static: none |
| `COPYOUT_TABLE_INDEX_AUDIT.md` | - | NET-NEW | out-of-bounds table reads copied to userland: none reachable from a 14.10 syscall. static: 513u (reachability pointer) |
| `COPY_SITE_DYNAMIC_LENGTH_TRIAGE.md` | - | NET-NEW | depth-4 triage of dynamic-length copy sites: the four read in full are disciplined. static: none |
| `CREATIVE_ROUTES_14_10.md` | - | NET-NEW | ten routes to kernel R/W, incl. copy helpers rejecting kernel addresses and 634/632 leaking the other frame object. static design: 1175a, 1179a, 1187a, 1188a, 179a |
| `CREATIVE_ROUTES_II_14_10.md` | - | NET-NEW | ten more mechanisms reasoned from the dump, incl. the mtypeprotect/547 proposal later corrected by ROUTE_379_547_14_10.md. static: 016x |
| `DESCRIPTOR_RACES_14_10.md` | - | NET-NEW | three descriptor-teardown races run with real thr_create children against live fds: all clean. probes: 938d, 955a, 970a-c, 971a, 971b, 972a |
| `DEVFS_GAP_ANALYSIS_14_10.md` | - | NET-NEW | /dev coverage matrix: which node got a full encoding sweep, which returned buffers were scanned for a copy_out, what is untested. probes: 1038a, 1067a, 1070a-1077a + 31 already-cited ids |
| `DEVFS_NAMESPACE_14_10.md` | - | NET-NEW | the enumerated /dev namespace: 78 entries from one getdirentries(196) call, replacing hand-guessed node names. probes: 1038a, 1150a, 1151a, 1152a, 376a, 380a |
| `DEVICE_MUX_622_14_10.md` | - | NET-NEW | 622 uap read as a struct rather than six arguments; gate map below 0x134 and dispatch described. probes: 1039a, 1040a, 1072a, 1074a, 1079a, 1152a, 55c |
| `DYNLIB_608_649_14_10.md` | - | NET-NEW | 608 get_info_ex hands out no kernel addresses; 649 agrees field for field; 597 still kills; the privilege-mask oracle works. probes: 1193b, 1198a, 1199a, 1199b |
| `ERRNO_CHANNEL_14_10.md` | - | NET-NEW | the loader return value is not rax; get_error_string is the working error channel, and devfs ioctls re-measured with it. probes: 1200a-e, 1165a, 1076a, 288a, 598a |
| `EXEC_ONLY_LIBKERNEL_14_10.md` | `FINDINGS.md + 2026-10-25/10_GADGET_CATALOG.md` | NET-NEW | libkernel text is execute-only on 14.10; eboot is RX-readable and full of AVX/ymm0 stores. probes: 1183a, 1183b, 1184a-1187a, 1173a |
| `FD_LIFECYCLE_14_10.md` | - | NET-NEW | descriptor lifetime against a blocked read: three shapes, all clean; 938a-c are void. probes: 938a, 938b, 938d |
| `FD_TABLE_14_10.md` | - | NET-NEW | the descriptor table is readable on 14.10 and holds no privileged channel. probes: 975c, 975d, 975e, 976a, 978a |
| `FONTFACE_MEMBER_MAP_14_10.md` | `FONTFACE_MEMBER_MAP_14_10.md` | DIVERGENT | upstream (written 2026-11-05) runs the same experiment further: it adds a re-entry section and withdraws the local 'the engine's allocation came from elsewhere' reading (L149 / U217, +3 / -52) |
| `FREEBSD_CVE_TRIAGE_14_10.md` | - | NET-NEW | which FreeBSD 11.x-13.x local privesc bugs have a precondition an unprivileged 14.10 process can create. probes: 105a, 151a, 152k, 455a, 936a-c, 941a |
| `GPU_VM_OPS_14_10.md` | - | NET-NEW | six GPU/VM syscalls tested; 547 record layout decoded; 653 is one unambiguous contradiction. probes: 93a, 98a, 99a, 942a, 942b, 114a, 949b, 949c |
| `HANDLER_SHAPE_HUNT_14_10.md` | `SYS601_1360_DISPATCH_AUDIT_2026-10-22.md (partial)` | NET-NEW | static hunt: SMAP is on (kills pointer injection), one 601 command drains the mdbg log, attach takes a raw struct proc*. static: 1179a |
| `INTERPROC_COPYOUT_SOURCES.md` | - | NET-NEW | interprocedural audit of the 301 resolved 13.60 bodies: 174 distinct helper sites, none with a user-supplied source pointer. static: none |
| `LOADER_CRASH_REPORT_FORMAT_14_10.md` | - | NET-NEW | what the loader emits when it faults (signal.lua pivot handler) and why 1173a died. probes: 1173a |
| `LOADER_WEDGE_COMMANDS_14_10.md` | - | NET-NEW | 637's middle range and 601 command 0x08 block forever inside the kernel; detection pair + probing rule. probes: 1162a, 1170a, 1172a, 1194e, 1197a, 1199a, 1199b, 339a |
| `MAGIC_GATE_CENSUS_13_60.md` | `SYS605_1360_STATIC_AND_1410_GATE_2026-10-22.md` | NET-NEW | census of constant gates in the 13.60 text; top 25, incl. 605's five-word service whitelist at 0xa36b00. static: 724a, 741a, 741e, 751b |
| `MDBG_601_COMMAND_MAP_14_10.md` | `SYS601_1360_DISPATCH_AUDIT_2026-10-22.md` | NET-NEW | all 0x28 601 command slots measured; none writes 0x28 bytes to arg2 or any bytes to arg3; closed as a R/W route. probes: 1170a-1181a, 1195a |
| `MEMCPY_PROVENANCE.md` | - | NET-NEW | 3,418 call sites of the unchecked memcpy at RVA 0x2590b0 classified, zero unclassified. static: none (5,004 RVAs cited) |
| `MICROARCH_FEASIBILITY_14_10.md` | - | NET-NEW | Zenbleed and the other microarchitectural hypotheses scored for feasibility from the Lua loader. probes: 1071a-1074a, 1161a, 1164a, 327a, 796d, 872a, 883b |
| `PRIVILEGE_MASK_14_10.md` | - | NET-NEW | privilege mask reader at 0x8b4ebb00 and writer via 597; a userland oracle through the 608 record. probes: 356a, 1199a, 1199b |
| `PROC_LOCK_WEDGE_637_14_10.md` | - | NET-NEW | 637(pid=0, value=17) never returns; reproduces the 2026-10-22 silent hang first hit by 339a. probes: 1162a, 339a, 340a-345a, 887a, 888a |
| `ROUTE_379_547_14_10.md` | `SYSCALL_MISLABEL_AUDIT_2026-10-19.md` | NET-NEW | 379 mtypeprotect body 0xabbd80 narg 4 cannot read proc+0xc81; 547 query_memory_protection body 0xaba540; corrects CREATIVE_ROUTES_II in two places. probes: 1204a, 1205a, 1206a |
| `SACRIFICIAL_THREAD_14_10.md` | - | NET-NEW | parking a child thread so a hostile 601 command costs a thread instead of a relaunch. probes: 1170a, 1172a, 1175a, 1176a, 1176b |
| `SIGRETURN_FRAME_LAYOUT_14_10.md` | - | NET-NEW | the 14.10 trapframe layout; setcontext(422) writes every slot except CS and sigreturn(417) has no frame write, so CPL cannot move. retires 1166a, static |
| `SOCKET_IOCTL_14_10.md` | - | NET-NEW (late arrival) | socket ioctl does reach the socket layer: 54 resolves the fd (EACCES 13, not ENOTTY 25), SIOC* requests are denied and legacy 0x89xx falls through to ENOTTY; closes upstream open row O10. probes: 1222a |
| `SONY_BRANCH_ORACLE_SWEEP_14_10.md` | - | NET-NEW | the 30-bit error oracle applied to 600-609: shape-dependent vs shape-independent error codes. probes: 1208a, 1208b |
| `SONY_DEBUG_SYSCALLS_13_60.md` | - | NET-NEW | 619 and 635 are hard ENOSYS; 620 free_stack is real and unmaps the caller's stack; 634 is gated and copyout's 0x4c0 bytes. static: 1195a |
| `SONY_SERVICE_RPC_14_10.md` | `SYS605_1360_STATIC_AND_1410_GATE_2026-10-22.md` | NET-NEW | 605 reaches Sony's service RPC dispatcher and its error codes return intact. probes: 1207a |
| `SYS601_SECOND_STAGE_14_10.md` | `SYS601_1360_DISPATCH_AUDIT_2026-10-22.md` | NET-NEW | 601's dispatcher has one entry and one branch reaches a second stage, gated by a thread flag with its own setter inside 601. probes: 1170a, 1192a-1194e |
| `SYSCALL_557_14_10_RECLASSIFIED.md` | - | NET-NEW | 557 is a named-object creator: arg1 is a name pointer and the return value is a handle, not a version dispatch. probes: 557a, 557b, 557c |
| `SYSCALL_ARG4_R10_14_10.md` | - | NET-NEW (RETRACTED in place) | the document's own header retracts its central claim: argument 4 always reached the kernel; kept as the record of the measurement that exposed the mistake. probes: 1183b, 1186a, 1211a-1221a |
| `SYSV_IPC_14_10.md` | - | NET-NEW | SysV IPC and the 641/642/646 statistics handlers all return -1 on 14.10. probes: 936a, 936b, 936c, 937a |
| `TZ_TABLE_638_14_10.md` | `TIER1_CLAIMS_4_8_AUDIT.md` | NET-NEW (semantic duplicate, see 4) | 638 is utc_to_localtime over a 258-record table; the 'kernel pointer' is a 1968 epoch key and the 16-byte output is arithmetic. probes: 1027a, 1029a, 1160a-1164a |
| `UAP_OVERREAD_SCAN_14_10.md` | - | NET-NEW | three handlers read past the narg*8 argument block; zero exploitable value, class closed. static: none |
| `UPSTREAM_STATE_2026_11_05.md` | - | NET-NEW (late arrival, meta) | a line-cited inventory of what the upstream tree believes (CLOSED / OPEN / contradictions), written by a parallel session; it cites upstream at `ab3379c6`, one commit behind the `c7f3b000` used here |
| `USER_ACCESS_FAMILY_AUDIT.md` | - | NET-NEW | the 17-entry user-access helper family classified; closes route 3 of CREATIVE_ROUTES. static: none |
| `VIRTUAL_QUERY_ALL_674_14_10.md` | - | NET-NEW | 674 needs a magic word nobody had passed; 317 regions with 72-byte records follow. probes: 1170a, 1181a, 1196a, 1196b, 353a, 354x |
| `YMM0_CLOBBER_14_10.md` | - | NET-NEW | the ymm0 clobber hypothesis measured and negative. probes: 1186a-1191a |
| `_hunt601_notes.md` | - | NET-NEW (scratch) | working notes for 601 with copyin/copyinstr/copyout site lists; the file itself says 'delete before final'. static: none |

## 3. Contradictions

Only pairs where the two sides assert incompatible things about the same object are listed here. Where local is simply
older but not contradicted (procedural drift, index counts, added sections on both sides), the row is in the table and
not here.

### 3.1 The stack-clash guard reads in opposite directions (same bytes, same tree)

`VERIFIED_HANDLER_ANALYSIS.md` (both sides, claim 3, sys 661/662):

- local: `### 3. Stack Clash via Integer Overflow - sys 661/662 [CONFIRMED DEFINITIVE]`
- local: 'the guard at 0x3af9fb-0x3afa07 (lea eax,[r15-0x81]; cmp eax,0xffffff7f; ja) is a minimum check - it
  accepts count >= 0x81 and rejects the wrap-around half'
- upstream: `### 3. Stack Clash via Integer Overflow - sys 661/662 [REFUTED - see correction below]`
- upstream: 'the bounds check does *not* allow counts above 0x80. At 0x3afa07 the ja 0x3afa33 jumps to the
  buffer-setup path; the fall-through at 0x3afa09 sets r15d = 0x16 (EINVAL) and exits.'

`HANDLER_CLAIM_CORRECTIONS.md` section 5 is the same disagreement with different headings: local
'Claim 3 holds, and the guard is a lower bound' with the instruction annotated `; reject`; upstream
'Claim 3 does not hold: the guard is an upper bound of 128' with the same instruction annotated
`; take the WORK path`.

Both readings cannot be right, and the local tree already contains the measurement that settles it:
`ARG4_TRAMPOLINE_14_10.md` (probe 1221a, 2026-11-05) reports `2 | 1 | 0x80020003 for both entries` and
`0x80 | 1 | works`. A count of 0x80 that reaches the multi-item loop is only possible if the guard rejects
counts *above* 0x80. The local 11-05 measurement agrees with upstream and contradicts the local
VERIFIED_HANDLER/HANDLER_CLAIM text it sits next to.

### 3.2 Threading: 'completely blocked' vs 'works'

- local `FINDINGS.md`: `## Finding 2: Threading Completely Blocked`; 'All threading primitives return -1:'
- upstream `FINDINGS.md`: `## Finding 2: Threading Partially Available (CORRECTED 2026-10-23)`;
  '~~Original claim: all threading blocked, eliminates race classes entirely.~~ **Superseded.**'
- local `ATTACK_SURFACE.md`: '| thr_new | 455 | Blocked |'
- upstream `ATTACK_SURFACE.md`: '| thr_new | 455 | ~~Blocked via resolve()~~ **WORKS** via make_syscall -
  455(param, 0x38) starts child thread with start_func(arg) (probes 383a, 56l) ... **Key primitive for AIO race.** |'
- local `THREADING_ALIVE_14_10.md`: 'thr_suspend(442) returned -1 for it, so there is no userland way yet to stop it.'
- upstream `THREADING_ALIVE_14_10.md`: 'thr_suspend(442) returned -1 for it, and thr_kill(tid, 9) ends the whole
  process rather than the one thread, so a thread can only be removed by ending the session.'

### 3.3 'First time r10 has been under control' vs work already recorded upstream

- local `ARG4_TRAMPOLINE_14_10.md` (NET-NEW file): 'delivers **argument 4** to any syscall. That is the first time
  in this project that r10 has been under control.'
- upstream `THREADING_ALIVE_14_10.md` (2026-10-21, probe 91u): '| +0x060 | **R10** | **arg4** (NOT rcx - Sony
  skips rcx, places R10 here) |' and 'Probe 91u scanned R10 across offsets +0x048..+0x0B8 with a setsockopt(5 args)
  child; only +0x060 produced the correct result (IPV6_UNICAST_HOPS changed 42 to 77).'
- upstream, same file, 159a: 'The number in RAX reaches the kernel unchanged; argument registers behave the same way'

The delivery paths differ (a `thr_create` child context upstream, `native.fcall_with_rax` on a libkernel stub
locally) and the local stub offset +0x3B0/+0x3B7 is new, but the capability claim is not. The reason the local
claim looks true is that the local copy of `THREADING_ALIVE_14_10.md` is the SUBSET side: it is missing the
GP-register-layout section that upstream added on 10-21.

### 3.4 AIO: three positions, one of them upstream-internal

- local `ATTACK_SURFACE.md`: 'Sony AIO 661 (event_create) | 661 | SIGSYS under the default disposition; returns -1
  with SIG_IGN installed (54c, 711a), so the slot is absent.'
- upstream `ATTACK_SURFACE.md`: '| Sony AIO 661 (event_create) | 661 | **LETHAL** - instantly kills process (54c, 54f) |'
- upstream `AIO_BATCH_14_10.md`: '661 (`aio_submit`) kills the process on every argument shape tried ... It was the
  wrong conclusion from the right measurement. 661 is one entry in the family. 669 is another ... and 662/664/666
  drive a request to completion, and the bytes really move.'
- upstream `STRATEGY.md` (2026-10-28): 'AIO 662 is **dead on 14.10** - the boot tunable that gates the submit path
  never opens, the delete never drops its table lock, and the subsystem dispatches no I/O.'
- local `AIO_INFLIGHT_14_10.md`: 'This note corrects the earlier reading that the aio family is bookkeeping only:
  submission works, reads are queued on real descriptors' (probes 894a, 943a, 954a-959a).

So local is *stale* against upstream ATTACK_SURFACE on 661, and *ahead of* upstream STRATEGY on 662/669, while
agreeing with upstream AIO_BATCH. Upstream is inconsistent with itself here; the local AIO_INFLIGHT result should
not be discarded when folding.

### 3.5 msync and 58a: 'never tested' vs 'run and refused'

- local `CVE-2026-49418-PS5-14.10.md`: '**Result:** PS5 applicability is the strongest of any unassessed CVE in this
  repository.' / '### Critical observation: msync was never tested'
- upstream same file: '**Result (corrected 2026-10-20):** Upstream CVE confirmed, PS5 applicability unresolved. A
  saved 14.10 run of probe 58a exists. It mapped and wrote 16 pages, then stopped after BEFORE msync(MS_SYNC)
  without recording a return value.'
- local `GOLD_VECTORS_2026-10-19.md`: '**Status:** Probe 58a written, NEVER RUN.' / '**If msync returns 0:** ... Next
  step is the double-invalidate trigger (probe 58b, not yet written).'
- upstream same file: '**Status (updated 2026-10-25, cobrajet302gt bench): RUN AND REFUSED - door closed.** ... 58b
  ran - no effect, contents intact.'

### 3.6 kevent

- local: '# kevent: the -1 tracks the timeout, not the call shape' / 'The only failing call is the only call with a
  nonzero timeout. That makes the timeout the prime suspect and leaves one cell of the 2x2 untested: split with a
  nonzero timeout.'
- upstream: '# kevent: 100 ms timeout works in the corrected matrix' / 'All four cells returned the expected read
  event. The earlier 30c rv=-1 cannot [stand]'
- local `RESEARCH_PAPER.md`: '| kqueue kevent | fd allocates but kevent always returns -1 |'
- upstream `RESEARCH_PAPER.md`: '| kqueue kevent | Not a general dead end: zero-timeout registration/polling worked in
  probes 20/21; combined add+poll returned -1 with a 100ms timeout in 30c. Cause unresolved |'

### 3.7 IPV6_MSFILTER

- local `IPV6_ANCILLARY_14_10.md`: 'IPV6_MSFILTER is not implemented at all (50e). The line is closed unless the [..]'
- upstream: 'IPV6_MSFILTER is a **separate** option that works when the request has the amd64 sockaddr_storage
  alignment: 50f records successful INCLUDE/EXCLUDE requests with the 152-byte __msfilterreq'
- local `CVE-2026-49412-PS5-14.10.md`: '**Result:** PS5 applicability is unresolved.' / 'No saved result issues
  option 74, joins an IPv6 multicast group, demonstrates the lock-drop window ...'
- upstream same file: '**Result:** The IPV6_MSFILTER handler is reachable from the 14.10 game process with a valid
  source-list copyin, including from a second thread.'

### 3.8 sendfile (KTLS CVE row)

- local `REMAINING_CVE_TRIAGE.md`: '1. **`sendfile` has never been issued.** A search of `probes/**/*.lua` and
  `results/*.txt` finds no `sendfile` occurrence.'
- upstream: '1. **Two basic `sendfile` shapes were issued on 14.10.** The 58d live capture records `-1` for flags
  `0` and `SF_NOCACHE`.'

### 3.9 Current position and self-reported progress

- local `STRATEGY.md`: 'We have **userland code execution** via a Lua 5.1 loader on TCP port 9026. The goal is
  **kernel R/W** to enable hypervisor bypass (Byepervisor).'
- upstream `STRATEGY.md`: '**STATUS (2026-10-28):** The Lua loader kernel attack surface is **exhausted**. ...
  **The only remaining kernel path is WebKit Canvas UAF (CVE-2026-43720).**'
- local `PROGRESS_AUDIT.md`: '**25/100 (~25%) on the rubric below.**' with 'Inventoried **169 Lua probe files** and
  **168 text result files**.'
- upstream: '**63/100 (~63%) on the rubric below.**' with 'Inventoried **1838 Lua probe files**, **26 JS probe
  files** and **2029 text result files** across 32 phases.'
- upstream, same file, banner: '**Superseded score.** This audit's 63/100 predates the 2026-11-01 re-score in
  docs/progress.json (65/100 ...). The evidence gates and method below are retained; the current score is the
  progress meter's.'

The local inventory figure is contradicted by the local tree itself, which carries phase-17 probes numbered past
1221 (e.g. `AIO_MODE0_GUARD_14_10.md` cites 1221a). The 169/168 count is a snapshot, not a measurement of the
checkout.

### 3.10 Two ATTACK_SURFACE rows that decide work

- local: '| shm_open | 482 | Crashes loader |'
- upstream: '| shm_open | 482 | **WORKS** via make_syscall - SHM_ANON, named objects, O_CREAT|O_RDWR, ftruncate,
  mmap(MAP_SHARED) (391a-391d). shm_open2(571) is nosys. |'
- local: '| Sony sys 639/638 | 639 | Not memory region: the pair is localtime_to_utc/utc_to_localtime over a
  258-record timezone table at a fixed RVA ...'
- upstream: '| Sony sys 639/638 (memory region) | 639 | ret=-1 for all address ranges (probe 54f, 2026-10-18) |'

Here local is the *better* text on 638 (upstream's row is the stale one, corrected inside upstream's own
`TIER1_CLAIMS_4_8_AUDIT.md` Claim 6). Divergence direction has to be judged per row, not per file.

### 3.11 Other divergent pairs, nature of the divergence only

| pair | nature |
|---|---|
| `CHANGELOG.md` | local head is 2026-11-05 (socket ioctl), upstream head is 2026-11-04 (fault-code oracle: kernel base readable per boot); upstream holds 10-29 and 11-04 entries local never had, local holds 11-05 entries upstream never had (+624 / -84). Merge, then resync. |
| `AIO_RANGE_14_10_EVIDENCE.md` | two-way: local has 882a (10-27), upstream has the 663 decode (10-24). Both keep. |
| `THREADING_ALIVE_14_10.md` | two-way: local has 712c-720a (10-25), upstream has 91u and 448a-452a. Both keep. |
| `UMTX_454_EVIDENCE.md` | two-way: local op map + op-19 wedge, upstream SHM stub series. Both keep. |
| `HANDLE_NAMESPACE_14_10.md` | same title, different experiments (88a/88b vs 96b-96f). Upstream is the newer set. |
| `WEBKIT_LENGTH_WINDOW_AUDIT.md` | both call the 81400 claim a false positive; local adds the 14.10 site sweep and the WebKit commit pin. Local is ahead. |
| `SYSCALL_ABSENT_VS_LETHAL.md` | local has the 10-25 sigaction-shield correction, upstream has the 10-22 SIGSYS resolution and the shared-nosys identity. Merge. |
| `RWX_ORACLE_14_10.md` | local claims the first direct test; upstream credits 237b's read-back. No factual conflict, attribution only. |
| `SYSCALL_CONTRACTS_13_60.md` | local leaves placeholder rows where upstream filled contracts (591, 604, 636, 656). |
| `SYSENT_PRESENCE_14_10.md` | local keeps the summary, upstream the full 1-708 table and the 10-21 thunk resolution. |
| `RESEARCH_PAPER.md`, `UNTESTED_THEORIES.md`, `STRATEGY.md` | absolute dead-end language locally, scoped language upstream. |
| `USERLAND_ENTRY.md` | install-procedure drift (repo move, inject.iet, notification text). No conflict. |
| `RESEARCH_EVIDENCE.md` | ledger rules added upstream. |
| `PROBE_INDEX.md`, `ALL_PROBES.md`, `ALL_RESULTS.md` | index bookkeeping only. |
| `WEBKIT_CORPUS.md`, `WEBKIT_FINDINGS.md` | upstream carries the 10-19 false-positive correction; local count differs (518 vs 509). |
| `THR_CREATE_PANIC_PATH_13.60.md` | local is missing the 189a section, so it ends before its own thesis is refuted for 14.10. |
| `CVE-2026-49418`, `GOLD_VECTORS`, `REMAINING_CVE_TRIAGE`, `CVE-2026-49412` | covered in 3.5, 3.7, 3.8; all four are cases where the local tree asserts a *gap* that upstream has already closed. |

## 4. Semantic duplicates under a different name

Required topics checked by grepping upstream for the distinctive terms (`r10`, `argument 4`, `mode 0`,
`mtypeprotect`, `379`, `gadget`, `census`, `libkernel`, `0x3b0`, `copyin`, `copyout`, `capabilit`, `bit 62`,
`638`, `utc_to_localtime`, `eboot`).

| topic | local doc(s) | upstream doc that already covers it | what is already upstream | what is actually new locally |
|---|---|---|---|---|
| argument-4 / r10 delivery | `ARG4_TRAMPOLINE_14_10.md`, `SYSCALL_ARG4_R10_14_10.md` (retracted) | `THREADING_ALIVE_14_10.md` (91u, 157a, 159a) + `CHANGELOG.md` | R10 at ctx+0x060 is arg4; libkernel wrapper is `mov rax,116; mov r10,rcx; syscall; ret`; a child can pick its own syscall number and arguments | exact stub offset libkernel+0x3B0 / +0x3B7; the 1218a differential; the conclusion that 663's EINVAL is a guard rather than a missing r10 |
| aio mode/count guard | `AIO_MODE0_GUARD_14_10.md`, `AIO_INFLIGHT_14_10.md` | `AIO_RANGE_14_10_EVIDENCE.md` (static decode), `AIO_BATCH_14_10.md` | 663 body: `1 <= count <= 0x80`, `mode >= 3` EINVAL; 669 works and 662/664/666 drive requests | measured `mode==0 && count>1` EINVAL that fires *before* the id list is copied in (1219a/1219b/1221a), and the resulting 'the public bug is patched' verdict |
| mtypeprotect / 379 | `ARG4_TRAMPOLINE_14_10.md` section 3, `ROUTE_379_547_14_10.md` | `SYSCALL_MISLABEL_AUDIT_2026-10-19.md`, `FINDINGS.md` (Finding 44, 50) | 585 is `is_in_sandbox`; the real mtypeprotect is 379; 379 was never called via make_syscall | body RVA 0xabbd80 narg 4, the `[proc+0xc81]` misreading and its correction, 547 body 0xaba540, the measured errno map for prot 0x00-0x10 |
| eboot gadget census | `EXEC_ONLY_LIBKERNEL_14_10.md`, `YMM0_CLOBBER_14_10.md` | `2026-10-25/10_GADGET_CATALOG.md`, `FINDINGS.md`, `DEAD_ENDS.md` | eboot .text is RX-readable; 4.6 MB scanned; rax=0/1/6/7/8 gadgets catalogued at eboot+0x471 etc. | libkernel is XO while eboot is readable (1183a/1183b), the AVX/ymm0-store census, and the negative ymm0-clobber result (1187a-1191a) |
| libkernel stub offsets | `ARG4_TRAMPOLINE_14_10.md` | `THREADING_ALIVE_14_10.md` (wrapper named, no offset) | the wrapper shape and that `syscall_address - 7` re-enters `mov rax,116` | the offsets themselves (+0x3B0 stub, +0x3B7 entry) and that it delivers r10 from rcx |
| copyin / copyout audits | `COPYOUT_LENGTH_AUDIT_14_10.md`, `COPYIN_DEST_PROVENANCE_14_10.md`, `MEMCPY_PROVENANCE.md`, `INTERPROC_COPYOUT_SOURCES.md`, `COPYOUT_INLINE_MOVE_AUDIT.md`, `USER_ACCESS_FAMILY_AUDIT.md` | `OFFLINE_HANDLER_DECODE_2026-10-23.md`, `TIER1_CLAIMS_4_8_AUDIT.md`, `AIO_RANGE_14_10_EVIDENCE.md` | per-handler copyout reachability, the 0x2591d0/0x259280 helper RVAs, depth-4/5 notes | whole-image censuses: 3,418 memcpy sites, 432 copyin sites, 174 distinct helper sites from 301 bodies, 21 dynamic-length copyouts, the 17-entry user-access helper family |
| capability bits | `CAPABILITY_CONTEXT_14_10.md`, `PRIVILEGE_MASK_14_10.md` | `ATTACK_SURFACE.md`, `OFFLINE_HANDLER_DECODE_2026-10-23.md`, `SYS605_1360_STATIC_AND_1410_GATE_2026-10-22.md` | credential bit 62 gates 671 selectors and 636; 636's `copyin(count*16)` timezone path | 643 writes proc+0xa34 unconditionally, 675 resets globals, mask reader 0x8b4ebb00 and the 608-record oracle |
| timezone syscall 638 | `TZ_TABLE_638_14_10.md` | `TIER1_CLAIMS_4_8_AUDIT.md` Claim 6 (byte-identical in both trees), `ATTACK_SURFACE.md` row 638, `SYSENT_PRESENCE_14_10.md` | 638 = `utc_to_localtime`, record is {key, offset, correction} 16-byte stride, binary search, unguarded copyout, 'not memory-region data' | the live measurement (1027a: 16-byte deterministic pair, 258 records, index rule), the 1968 epoch-key reading, and the 'kernel pointer' refutation at the value level rather than the shape level |

Additional semantic duplicates found by the same screen, outside the required eight:

| topic | local doc | upstream doc | overlap |
|---|---|---|---|
| CFI whitelist census | `CFI_CENSUS_13_60.md` | `THR_CREATE_430_CONTEXT.md` lines 114-118 (byte-identical in both trees), `UMTX_OPS_13_60.md` line 36 | the `sub rax,rcx; ror rax,3; cmp rax,0x3a5` idiom and the 934-entry `[0x2652e0,0x267008)` bound are already written down; only the 11,602-residual count is new |
| 601 dispatch | `MDBG_601_COMMAND_MAP_14_10.md`, `SYS601_SECOND_STAGE_14_10.md`, `HANDLER_SHAPE_HUNT_14_10.md` | `SYS601_1360_DISPATCH_AUDIT_2026-10-22.md` | the 40-entry signed relative jump table at RVA 0x1a51160 for commands 0x00-0x27 is already upstream, including the 0x05/0x06/0x0c/0x10/0x12 corrections; local adds the measured 0x28-slot sweep and the thread-flag second stage |
| 605 service whitelist | `MAGIC_GATE_CENSUS_13_60.md` section A, `SONY_SERVICE_RPC_14_10.md` | `SYS605_1360_STATIC_AND_1410_GATE_2026-10-22.md` | same handler 0xa36b00, same five IDs (0x19810000, 0x3cc80700, 0x78026400, 0x78028300, 0x78028a00); local adds the 1207a live RPC round trip |
| 557 reclassification | `SYSCALL_557_14_10_RECLASSIFIED.md` | `SYSCALL_557_14_10_EVIDENCE.md` (identical), `PRIVATE_NAMEDOBJ_POINTER_AUDIT_2026-10-21.md` | the named-object reading and the handle return |
| dynlib 608 / 591 / 656 | `DYNLIB_608_649_14_10.md` | `SYS_608_DYNLIB_GET_INFO_EX_13_60.md`, `SYS_591_DYNLIB_DLSYM_BLOCKLIST_13_60.md`, `SYS_656_DYNLIB_GET_INFO_FOR_LIBDBG_13_60.md` (all written 2026-11-05 at `c7f3b000`) | the 608 contract decode, the 591 blocklist, the 656 gate chain, and the live 1198a/1198b/1300a confirmations; local adds 649 agreement and the 597 kill |
| loader fault channel | `LOADER_CRASH_REPORT_FORMAT_14_10.md` | `LOADER_FAULT_CHANNEL_14_10.md` | the `signal.lua` SIGILL/SIGBUS/SIGSEGV report path and its wire format; upstream is measured and publishable, local is a private note |
| descriptor table | `FD_TABLE_14_10.md` | `DEVICE_DESCRIPTORS_14_10.md` | the loader process's fd table read with fcntl/getsockname/getpeername and the 'do not read fd 18/20/21' warning |
| fault / branch oracles | `SONY_BRANCH_ORACLE_SWEEP_14_10.md` | `FAULT_CODE_ORACLE_14_10.md` | the #PF error-word oracle that recovers the kernel base per boot; the local 1208a instrument is the error-string oracle, a different and weaker instrument |

## 5. What to do with each class

### 5.1 Fold these local docs into an existing upstream doc (do not add a new file)

1. `ARG4_TRAMPOLINE_14_10.md` -> `THREADING_ALIVE_14_10.md`: merge the +0x3B0/+0x3B7 offsets and the 1218a
   differential into the GP-register-layout section, and drop the 'first time in this project' sentence.
2. `AIO_MODE0_GUARD_14_10.md` -> `AIO_RANGE_14_10_EVIDENCE.md` section on 663.
3. `TZ_TABLE_638_14_10.md` -> `TIER1_CLAIMS_4_8_AUDIT.md` Claim 6 as the measured half.
4. `CFI_CENSUS_13_60.md` -> `THR_CREATE_430_CONTEXT.md` (extend the 934-entry bound to the residual population).
5. `CAPABILITY_CONTEXT_14_10.md` -> `OFFLINE_HANDLER_DECODE_2026-10-23.md` (636/638) plus two `ATTACK_SURFACE.md` rows.
6. `ROUTE_379_547_14_10.md` -> `SYSCALL_MISLABEL_AUDIT_2026-10-19.md`, replacing 'UNTESTED' with the body read.
7. `EXEC_ONLY_LIBKERNEL_14_10.md` and `YMM0_CLOBBER_14_10.md` -> `FINDINGS.md` + `2026-10-25/10_GADGET_CATALOG.md`.
8. `MDBG_601_COMMAND_MAP_14_10.md` and `SYS601_SECOND_STAGE_14_10.md` -> `SYS601_1360_DISPATCH_AUDIT_2026-10-22.md`.
9. `SONY_SERVICE_RPC_14_10.md` and `MAGIC_GATE_CENSUS_13_60.md` section A -> `SYS605_1360_STATIC_AND_1410_GATE_2026-10-22.md`.
10. `AIO_INFLIGHT_14_10.md` -> `AIO_BATCH_14_10.md` (and it should override the 'dispatches no I/O' sentence in
    `STRATEGY.md`, which the upstream tree cannot support alongside its own AIO_BATCH note).
11. `COPYIN_LENGTH_SCREEN_14_10.md` -> `COPYOUT_CLASS_CLOSED.md`; keep the three whole-image censuses
    (`MEMCPY_PROVENANCE`, `INTERPROC_COPYOUT_SOURCES`, `COPYIN_DEST_PROVENANCE`) as standalone files.
12. `DYNLIB_608_649_14_10.md` -> `SYS_608_DYNLIB_GET_INFO_EX_13_60.md` (the 649 agreement and the 597 kill are the only
    parts not already there).
13. `LOADER_CRASH_REPORT_FORMAT_14_10.md` -> `LOADER_FAULT_CHANNEL_14_10.md`, which is the measured version of the
    same channel; `FD_TABLE_14_10.md` -> `DEVICE_DESCRIPTORS_14_10.md` for the same reason.

### 5.2 Resync (same name, upstream is the corrected text) - merge local-only sections first where noted

`FINDINGS.md`, `ATTACK_SURFACE.md`, `STRATEGY.md`, `VERIFIED_HANDLER_ANALYSIS.md`, `HANDLER_CLAIM_CORRECTIONS.md`,
`KEVENT_TIMEOUT_VARIABLE.md`, `IPV6_ANCILLARY_14_10.md`, `GOLD_VECTORS_2026-10-19.md`, `CVE-2026-49412-PS5-14.10.md`,
`CVE-2026-49418-PS5-14.10.md`, `REMAINING_CVE_TRIAGE.md`, `RESEARCH_PAPER.md`, `PROGRESS_AUDIT.md`,
`SYSCALL_ABSENT_VS_LETHAL.md`, `SYSENT_PRESENCE_14_10.md`, `SYSCALL_CONTRACTS_13_60.md`, `RWX_ORACLE_14_10.md`,
`WEBKIT_CORPUS.md`, `WEBKIT_FINDINGS.md`, `USERLAND_ENTRY.md`, `RESEARCH_EVIDENCE.md`, `PROBE_INDEX.md`,
`THR_CREATE_PANIC_PATH_13.60.md`, `RETEST_PLAN_53.md`, `EXPLOIT_SURFACE_ANALYSIS_13.60.md`.

Merge-then-resync (local holds a section upstream lacks): `CHANGELOG.md` (2026-11-05 entries), `AIO_RANGE_14_10_EVIDENCE.md`
(882a), `THREADING_ALIVE_14_10.md` (712c-720a), `WEBKIT_LENGTH_WINDOW_AUDIT.md` (section 7),
`SYSCALL_ABSENT_VS_LETHAL.md` (10-25 shield correction), `UMTX_454_EVIDENCE.md` (op-19 wedge),
`HANDLE_NAMESPACE_14_10.md` (88a/88b).

### 5.3 Genuinely new (no upstream counterpart, keep as new upstream docs)

The strongest, in order of what they change for the next session:

1. `SYSCALL_ARG4_R10_14_10.md` + `ARG4_TRAMPOLINE_14_10.md` - the retraction and its replacement: the 663 EINVAL
   was never a missing r10. This is the document that stops a whole line of work.
2. `AIO_MODE0_GUARD_14_10.md` - the aio multi-wait bug is patched on 14.10 by an extra guard that 13.60 does not have.
3. `SYS601_SECOND_STAGE_14_10.md` + `MDBG_601_COMMAND_MAP_14_10.md` - 601 measured across all 0x28 commands, closed.
4. `ROUTE_379_547_14_10.md` - the only body-level read of mtypeprotect and query_memory_protection.
5. `DEVFS_NAMESPACE_14_10.md` + `DEVFS_GAP_ANALYSIS_14_10.md` - the actual /dev namespace and what was never swept.
6. `ERRNO_CHANNEL_14_10.md` - the loader's return value is not rax; every earlier 'ret=-1' reading needs re-checking.
7. `VIRTUAL_QUERY_ALL_674_14_10.md` - 674 needs a magic word; 317 regions.
8. `TZ_TABLE_638_14_10.md` - measured half only (see 5.1.3).
9. `INTERPROC_COPYOUT_SOURCES.md`, `MEMCPY_PROVENANCE.md`, `COPYIN_DEST_PROVENANCE_14_10.md`, `COPYOUT_LENGTH_AUDIT_14_10.md`,
   `COPYOUT_INLINE_MOVE_AUDIT.md`, `USER_ACCESS_FAMILY_AUDIT.md`, `UAP_OVERREAD_SCAN_14_10.md` - the copy-class
   censuses that let the team stop re-auditing.
10. `PROC_LOCK_WEDGE_637_14_10.md`, `LOADER_WEDGE_COMMANDS_14_10.md`, `SACRIFICIAL_THREAD_14_10.md` - the two
    wedges and how to survive them without a relaunch.
11. `SIGRETURN_FRAME_LAYOUT_14_10.md` - CPL cannot move through 417/422.
12. `DYNLIB_608_649_14_10.md`, `PRIVILEGE_MASK_14_10.md` - the sanitiser and the mask oracle.
13. `FREEBSD_CVE_TRIAGE_14_10.md`, `MICROARCH_FEASIBILITY_14_10.md` - the two ranked feasibility tables.
14. `DEVICE_MUX_622_14_10.md`, `GPU_VM_OPS_14_10.md`, `SYSV_IPC_14_10.md`, `FD_TABLE_14_10.md`, `FD_LIFECYCLE_14_10.md`,
    `DESCRIPTOR_RACES_14_10.md`, `SONY_BRANCH_ORACLE_SWEEP_14_10.md`, `SONY_DEBUG_SYSCALLS_13_60.md`,
    `AIO_DEBUG_726_727_13_60.md`, `HANDLE_NAMESPACE_14_10.md` - narrow, complete negative results.

## 6. Net-new catalogue (two-line summaries, all 55)

Line 1 is the claim, line 2 is what it rests on and where it stops. Probe IDs are the ones cited in the file.

1. `AIO_DEBUG_726_727_13_60.md` - 13.60 syscalls 726/727 return raw kernel pointers to userland. Static only: both
   are absent from the 677-entry table 14.10 dispatches through.
2. `AIO_INFLIGHT_14_10.md` - aio submission is real and delete refuses in-flight entries. Probes 894a, 943a,
   954a-959a; corrects the 'bookkeeping only' reading.
3. `AIO_MODE0_GUARD_14_10.md` - 663 refuses mode 0 with count>1 before the id list is touched. Probes 1219a,
   1219b, 1221a; the guard is not in the 13.60 body.
4. `ARG4_TRAMPOLINE_14_10.md` - libkernel+0x3B7 delivers r10 (argument 4) for any syscall. Probes 1216b, 1217a,
   1218a, 1219a, 1219b, 1220a; also the first 379 sweep.
5. `CAPABILITY_CONTEXT_14_10.md` - 636/638/643/675 mapped and none is a primitive. Probes 1209a, 1210a; 643
   writes proc+0xa34 with no observable effect.
6. `CFI_CENSUS_13_60.md` - the whitelist covers 934 stubs and 11,602 indirect calls sit outside it. Static capstone
   over the 13.60 text; the idiom is already documented in `THR_CREATE_430_CONTEXT.md`.
7. `COPYIN_DEST_PROVENANCE_14_10.md` - the destination of every direct copyin call is audited. Static, 563 RVAs;
   no site takes a destination from user memory.
8. `COPYIN_LENGTH_SCREEN_14_10.md` - the twelve stack-destination copyin sites are all bounded. Static; removes the
   remaining 'unbounded stack copyin' candidate.
9. `COPYOUT_CLASS_CLOSED.md` - the copy-out class is closed and the helper body is in the corpus. Static; corrects
   both earlier audits that said the body was missing.
10. `COPYOUT_INLINE_MOVE_AUDIT.md` - inline kernel-to-user moves that bypass the helper carry zero provable leaks.
    Static, Chinese text; complements the helper-based audits.
11. `COPYOUT_LENGTH_AUDIT_14_10.md` - all 21 dynamic-length copyouts are clamped. Static; each site has a named
    clamp, so no 'length from userland' site remains.
12. `COPYOUT_PARTIAL_STACK_AUDIT.md` - the '62 handlers' figure does not reproduce. Static; enumerates the real
    partial-initialisation copies.
13. `COPYOUT_TABLE_INDEX_AUDIT.md` - out-of-bounds table reads copied out are not reachable on 14.10. Static plus
    the 513u reachability check.
14. `COPY_SITE_DYNAMIC_LENGTH_TRIAGE.md` - depth-4 triage of dynamic-length copy sites finds four candidates, all
    disciplined. Static; documents the three method traps that cost earlier runs.
15. `CREATIVE_ROUTES_14_10.md` - ten routes to kernel R/W, all reasoned from bytes. No console run; the copy
    helpers reject kernel addresses, which inverts the usual design rule.
16. `CREATIVE_ROUTES_II_14_10.md` - ten more mechanisms, including the mtypeprotect/547 proposal. Static; its two
    379/547 claims are corrected by `ROUTE_379_547_14_10.md`.
17. `DESCRIPTOR_RACES_14_10.md` - three descriptor-teardown races with real children, all clean. Probes 938d,
    955a, 970a-c, 971a, 971b, 972a; first use of thr_create against live fds.
18. `DEVFS_GAP_ANALYSIS_14_10.md` - the /dev coverage matrix: what was swept, what was not, what was never
    scanned for a copy_out. 45 probe IDs, 31 of them already upstream; the matrix itself is new.
19. `DEVFS_NAMESPACE_14_10.md` - the enumerated /dev namespace, 78 entries from one getdirentries(196). Probes
    1038a, 1150a-1152a, 376a, 380a; replaces every hand-guessed node list.
20. `DEVICE_MUX_622_14_10.md` - 622's uap is a struct, not six arguments. Probes 1039a, 1040a, 1072a, 1074a, 1079a,
    1152a; gate map below 0x134.
21. `DYNLIB_608_649_14_10.md` - 608 hands out no kernel addresses and 649 agrees with it. Probes 1193b, 1198a,
    1199a, 1199b; 597 still kills.
22. `ERRNO_CHANNEL_14_10.md` - the loader return value is not rax. Probes 1200a-e, 1165a, 1076a, 288a, 598a;
    re-measures the devfs ioctls through the working channel.
23. `EXEC_ONLY_LIBKERNEL_14_10.md` - libkernel is XO and eboot is RX-readable. Probes 1183a, 1183b, 1184a-1187a;
    explains why every libkernel gadget plan failed.
24. `FD_LIFECYCLE_14_10.md` - descriptor lifetime against a blocked read is clean. Probes 938a, 938b, 938d; 938a-c
    are declared void.
25. `FD_TABLE_14_10.md` - the fd table is readable and holds no privileged channel. Probes 975c, 975d, 975e, 976a.
26. `FONTFACE_MEMBER_MAP_14_10.md` - **no longer net-new**: `c7f3b000` carries the same experiment and goes further.
    See section 2; the local half is the earlier of the two readings.
27. `FREEBSD_CVE_TRIAGE_14_10.md` - which FreeBSD 11.x-13.x privesc bugs an unprivileged process can precondition.
    Probes 105a, 151a, 152k, 455a, 936a-c, 941a; every row graded.
28. `GPU_VM_OPS_14_10.md` - six GPU/VM syscalls and the 547 record layout. Probes 93a, 98a, 99a, 942a, 942b, 114a,
    949b, 949c; 653 is the one contradiction.
29. `HANDLER_SHAPE_HUNT_14_10.md` - SMAP is on, and one 601 command drains the mdbg log. Static, 1179a; attach
    takes a raw struct proc*, but the pointer-injection class is dead.
30. `INTERPROC_COPYOUT_SOURCES.md` - 174 distinct helper sites reached from 301 bodies, none with a user-supplied
    source. Static, interprocedural; closes the 'copyout from user value' route.
31. `LOADER_CRASH_REPORT_FORMAT_14_10.md` - what the loader emits when it faults. Probe 1173a; local-only format
    note derived from `signal.lua`.
32. `LOADER_WEDGE_COMMANDS_14_10.md` - two commands block the kernel forever. Probes 1162a, 1170a, 1172a, 1194e,
    1197a, 1199a, 1199b, 339a; includes the detection pair.
33. `MAGIC_GATE_CENSUS_13_60.md` - the constant-gate census, top 25. Static, 724a, 741a, 741e, 751b; 605's five-word
    whitelist is its calibration case.
34. `MDBG_601_COMMAND_MAP_14_10.md` - all 0x28 601 commands measured and the route closed. Probes 1170a-1181a,
    1195a; no command writes arg3.
35. `MEMCPY_PROVENANCE.md` - 3,418 call sites of the unchecked memcpy at 0x2590b0 classified with zero unclassified.
    Static, 5,004 RVAs; the largest single audit in the tree.
36. `MICROARCH_FEASIBILITY_14_10.md` - Zenbleed and the rest scored for feasibility from the loader. Probes 1071a-
    1074a, 1161a, 1164a, 327a, 796d, 872a, 883b; paper analysis plus offline bytes.
37. `PRIVILEGE_MASK_14_10.md` - mask reader at 0x8b4ebb00, writer via 597. Probes 356a, 1199a, 1199b; the 608
    record is the userland oracle.
38. `PROC_LOCK_WEDGE_637_14_10.md` - 637(pid=0, value=17) never returns. Probes 1162a, 339a, 340a-345a, 887a,
    888a; reproduces the 10-22 hang.
39. `ROUTE_379_547_14_10.md` - the body-level read of mtypeprotect and query_memory_protection. Probes 1204a-1206a;
    379 cannot read proc+0xc81, which retires the route CREATIVE_ROUTES_II proposed.
40. `SACRIFICIAL_THREAD_14_10.md` - park a child thread so a hostile 601 command costs a thread, not a relaunch.
    Probes 1170a, 1172a, 1175a, 1176a, 1176b.
41. `SIGRETURN_FRAME_LAYOUT_14_10.md` - setcontext writes every trapframe slot except CS, and sigreturn has no frame
    write. Static, retires 1166a before it ran; CPL cannot move.
42. `SONY_BRANCH_ORACLE_SWEEP_14_10.md` - the 30-bit error oracle applied to 600-609. Probes 1208a, 1208b;
    separates argument-gated from absent.
43. `SONY_DEBUG_SYSCALLS_13_60.md` - 619/635 hard ENOSYS, 620 free_stack real, 634 gated 0x4c0 copyout. Static,
    1195a; the debug range is smaller than the name suggests.
44. `SONY_SERVICE_RPC_14_10.md` - 605 reaches the service RPC dispatcher and error codes survive. Probe 1207a;
    the channel, not the command, is the finding.
45. `SYS601_SECOND_STAGE_14_10.md` - one thread-flag branch reaches 601's second stage. Probes 1170a, 1192a-1194e;
    the setter for that flag is inside 601.
46. `SYSCALL_557_14_10_RECLASSIFIED.md` - 557 is a named-object creator, not a version dispatcher. Probes 557a-c;
    arg1 is a name pointer and the return is a handle.
47. `SYSCALL_ARG4_R10_14_10.md` - retracted in place: argument 4 always reached the kernel. Probes 1183b, 1186a,
    1211a-1221a; kept because the retraction is the evidence.
48. `SYSV_IPC_14_10.md` - SysV IPC and the 641/642/646 statistics handlers all return -1. Probes 936a-c, 937a.
49. `TZ_TABLE_638_14_10.md` - 638 is utc_to_localtime and the 'kernel pointer' is a 1968 epoch key. Probes 1027a,
    1029a, 1160a-1164a; semantic duplicate of TIER1 Claim 6, measured half is new.
50. `UAP_OVERREAD_SCAN_14_10.md` - three handlers read past narg*8 and none is exploitable. Static; class closed.
51. `USER_ACCESS_FAMILY_AUDIT.md` - the 17-entry user-access helper family, classified. Static; closes route 3 of
    CREATIVE_ROUTES.
52. `VIRTUAL_QUERY_ALL_674_14_10.md` - 674 needs a magic word and returns 317 regions. Probes 1170a, 1181a, 1196a,
    1196b, 353a, 354x; the argument layout is confirmed by the measurement.
53. `YMM0_CLOBBER_14_10.md` - the ymm0 clobber hypothesis is negative. Probes 1186a-1191a; supersedes the
    'open, not refuted' rows.
54. `_hunt601_notes.md` - scratch notes for 601 with copyin/copyinstr/copyout site lists. Static; the file says
    'delete before final' and should not be published as is.
55. `SOCKET_IOCTL_14_10.md` - ioctl(54) does resolve a socket descriptor and is refused one layer up. Probe 1222a;
    closes upstream open row O10, and corrects the repo's own '54 never resolves the descriptor' note.
56. `UPSTREAM_STATE_2026_11_05.md` - a line-cited inventory of what upstream closes, leaves open and contradicts.
    Meta-document written by a parallel session at `ab3379c6`; it is one commit behind the tree audited here.

## 7. Limits of this audit

- Static and documentary only. No console, no network, no `tools/send_probe.py`; nothing here re-measures a probe.
- Verdicts are textual. A doc can be DIVERGENT because one side added a section; the table says which.
- Line-set difference ignores ordering, so a pure reshuffle scores as IDENTICAL and a moved paragraph scores as
  a delete plus an insert. Both are reported with counts so the drift is visible.
- The semantic-duplicate screen is recall-oriented: it greps the eight required terms and scores token coverage.
  A duplicate that shares no vocabulary would be missed; none of the 55 survived the manual pass that way.
- The checkout is being written to by other sessions while this audit runs. Two docs appeared mid-run and the
  local `CHANGELOG.md`/`PROBE_INDEX.md` line counts moved between passes; the numbers here are the c7f3b000
  pass, taken between 10:35 and 10:47 UTC.
- Upstream is pinned at `c7f3b000`, not at `origin/master`. If either moves, every DIVERGENT verdict for the 35
  drifted files must be recomputed, not assumed.
