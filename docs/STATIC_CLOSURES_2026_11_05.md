# Static closures, 2026-11-05 (second pass): deref census, blockpool installer, R1

Three routes were closed offline in this pass, and four rows that the plan documents still
listed as open were found to be closed already by earlier work. No console time was spent on
any of it except where noted.

## 1. Direct-deref census, call-aware: zero bodies

`docs/INTERPROC_COPYOUT_SOURCES.md` closed the class with a heuristic that dropped taint at
every `call`. That heuristic was the stated justification for re-opening the question (plan
rows P1 and P8), so it was re-run with the stronger model in
`.local/deref_callee_saved.py`:

- seed `rsi = uap` at body entry (the syscall argument block);
- `mov reg,[rsi+disp]` marks `reg` as a user-controlled value;
- taint survives `call` for callee-saved registers only (`rbx, rbp, r12-r15`);
- `[rbp+disp]` stack spills are tracked through the body;
- flag any memory operand whose base or index register holds a user-controlled value.

**Result: 0 bodies** dereference a uap-derived value. The closure holds under the model it was
accused of missing, and P1 (CR2 tracer) and P8 (body x slot fault sweep) lose their stated
justification. P8 in particular was a panic machine: a raw kernel-mode deref of a bad user
pointer reaches `trap_fatal`, and `thr_create` children do not change CPL.

## 2. Blockpool installer hypothesis: refuted

Plan item #1 proposed that the blockpool path builds a `vm_object` and then hands it to the
same map-insert helper mmap uses, which would make a 0xb-type mapping reachable. Decoded
0x9a6c00-0x9a7d10 and 0x9a7f00-0x9a9560 (`.local/dis_bp.py`, `.local/dis_bp2.py`):

- 68 distinct call targets in the region;
- **zero** calls to `0xab9f60`, the insert wrapper that mmap's body (0xAB83C0) reaches at
  0xAB8A30;
- **zero** calls to `0x2d2e50`, mmap's apply helper (called at 0xAB8A93);
- the only mmap-shared helper reached is `0x6FD6B0`, at seven sites (0x9A6F72, 0x9A7211,
  0x9A7F21, 0x9A8564, 0x9A8A84, 0x9A8F5A, 0x9A954D), which is a generic lookup, not an insert;
- indirect calls in the region: 0x9A724F, 0x9A8446, 0x9A89C7, 0x9A8EAD.

Blockpool does construct a type-0xb object (`0x9a77d0 call 0x8ae21ac0`, RVA 0x461ac0), but
it never reaches a map-insert path. The hypothesis is false and the 0xb route stays shut.

## 3. R1 is dead twice over

R1 was the top-ranked route in `docs/ROUTES_III_14_10.md`: map something as type 0xb, then
use 547 to read its PTEs and get physical addresses. `docs/ROUTE_379_547_14_10.md` measured
it on 2026-11-04 (probes 1204a/1205a/1206a), and the measurement kills it independently of the
blockpool question:

- 547 body `0xaba540`: the PTE path needs `cmp byte [r13+0xc81],0` non-zero **and**
  `cmp dword [r13+0x5d8],0x6000000` at or above; the non-PTE path needs
  `[r13+0x5d4] > 0xfffffff`.
- `547(va=0x310DD0000, out)` returned out+0x00 = 0x0000000310DC4000 (vma start),
  out+0x08 = 0x0000000310DD4000 (end), out+0x10 = 0x0061002000000003 (low dword 3 = RW).
  That is the non-PTE branch, so **`proc+0xc81 == 0` at runtime**.
- `proc+0xc81` has exactly one writer image-wide: RVA `0x38f7bf mov byte [rax+0xc81],cl`,
  inside process creation, guarded by a selector test on r12d. A running process cannot set it.
- 547 enforces its bound: a kernel VA returns EINVAL 22, not a PTE.
- 379 body `0xabbd80` genuinely lacks the va bound (kernel VA returns EACCES 13, not EINVAL),
  but `vm_map_protect` only searches the calling process's vmspace, so no foreign PTE is
  touched. An id sweep 0x00-0xFF changed nothing: only 0x0A (EACCES) and 0x15 (EINVAL) differ
  from the rest, and id >= 0x100 returns EINVAL.

Since 547 never takes the PTE branch, no type-0xb mapping would have produced physical
addresses even if blockpool had installed one. R1 is closed by measurement, not by argument.

## 4. Plan and upstream rows that were already closed

Read before spending effort on them:

- **17 OBJECT-sourced copyout candidates** (plan item #3) — tested upstream on 2026-10-28:
  `.local/tmp/up/docs/DEAD_ENDS.md:182`, "Live testing of the accessible ones yielded zero
  kernel pointers — all outputs are either blocked or sanitized on 14.10." See also
  `.local/tmp/up/docs/EXPLOITATION_STATUS.md:112` and `.local/tmp/up/docs/STRATEGY.md:144-145`.
- **CVE-2026-49412, IPV6_MSFILTER** — measured clean: `docs/FREEBSD_CVE_TRIAGE_14_10.md:56`,
  173 accepted / 1875 rejected across 2048 parent leave/rejoin cycles, no UAF (probe 50w).
- **CVE-2026-45251, poll+close** — `docs/CHILD_SYSCALLS_AND_POLL_CLOSE_14_10.md` (probe 1234a):
  60 raced closes, 60/60 children created, process alive, no corruption. The same doc records
  the child-lifetime lesson: a child whose return address is `jmp $` never exits, and 60 of
  them starved the loader until a later probe read zero bytes.
- **604 `dl_get_metadata` and 656** — closed per the CHANGELOG entry "604, 656 and 560 close".
- **Socket-level SIOC\*** (upstream O10) — closed locally: `docs/SOCKET_IOCTL_14_10.md`,
  probe 1222a, SIOC\* returns EACCES, legacy codes ENOTTY, zero leaks in 37 requests.
- **601 read-back, YMM residue, double-fetch** — already recorded as closed in
  `docs/READ_IDEA_ATLAS_14_10.md`'s status-corrections section.

## Scripts

`.local/deref_callee_saved.py`, `.local/dis_bp.py`, `.local/dis_bp2.py`.
