# Privilege-check census, PS5 14.10 (analysis image: 13.60 kernel text)

Status: static census of C:/PS5contrib/docs/dumps_13.60/kernel_text.bin
(base VA 0xffffffff8a9c0000, RVA == file offset, length 0xE6E5C0), read-only.
Date: 2026-11-05. All RVAs below are file offsets in that image and equal the
VA minus 0xffffffff8a9c0000. Every statement about 14.10 runtime behaviour is
marked as measured (with the probe that measured it) or as untested.

## 1. Verdict

Of the 679 sysent entries, 301 distinct handler bodies exist; 300 are non-nosys.
Inside those 300 bodies there are 99 privilege-gate call sites in 73 bodies:
46 call the privilege helpers (39 priv_check, 7 priv_check_cred) and 53 call
capability predicates (27 cred+0x60 bit-62 tests plus 26 exact-match / mask /
bit-61 / bit-60 variants). All 99 sites are followed by a consumer that rejects
on failure: 97 straight-line (test/cmp on eax or a copy, then jcc), one via a
register copy across a call (sys 601 @0xca0900), one via a join block
(sys 622 @0x7dd03b). There is no site in a syscall body that discards the
result, no site where the privileged effect precedes the check, and no inline
raw credential-bit test: every credential bit test goes through a helper.

Therefore, on this image, the defect classes asked about - discarded result,
late check, raw-bit gate, check on only one of two paths - do not appear as
accidental bugs. What does appear is a systematic idiom: same-object
shortcuts (id == 0 or id == own id skips the capability test) and one
fail-open capability test (0xb2bb00 returns allow when the capability object
pointer is NULL). Those are the only unprivileged ways past a gate that this
corpus shows, and each needs a 14.10 measurement before it is called a bypass.

The privilege-number table that priv_check_cred indexes (RVA 0x18bd278) is
outside this dump and outside kernel_data.bin, so a privilege number cannot be
mapped to a named PRIV_ constant from this corpus. A wrong-number argument is
therefore unprovable statically; it can only be probed by behaviour.

Two probe-1242a results (2026-11-05) are folded in below. They close sys 532
at privilege number 0x2aa and they correct the mechanism the probe author
read: the capability test in 532 is executed only after priv_check(0x2aa)
returns 0, and a capability failure there returns a Sony status word, not
EPERM. A process that receives EPERM from 532 therefore never reached the
capability test at all. Separately, the same probes data shows the saved 587
record cannot be used as a credential oracle: 587 exposes [cred+0x58] only on
its privilege-denied path, and only when the value is one of five recognised
tags. Section 4a gives the decode.

## 2. Gate sites: privilege helpers

Columns: syscall(s), handler body RVA, call RVA, privilege argument (decimal,
hex), eax disposition. CHECKED means the very next use of eax (or its copy)
rejects on failure; the jcc address is given.

| sys | body | call | priv | eax afterwards |
|---|---|---|---|---|
| 12 | 0x8f6b20 | 0x8f6b49 | 683 | CHECKED jne @0x8f6b50 |
| 23 | 0x2a91f0 | 0x2a92b2 | 50 | CHECKED je @0x2a92b9 |
| 33 | 0x8f8be0 | 0x8f8bf2 | 683 | CHECKED je @0x8f8bf9 |
| 41 | 0x729d80 | 0x729d92 | 688 | CHECKED je @0x729d99 |
| 50 | 0x2ab7a0 | 0x2ab7c9 | 161 | CHECKED jne @0x2ab7d2 |
| 55 | 0x7e4810 | 0x7e481e | 8 | CHECKED jne @0x7e4825 |
| 56 | 0x8fc490 | 0x8fc4b9 | 683 | CHECKED jne @0x8fc4c0 |
| 56 | 0x8fc490 | 0x8fc5b0 | 312 | CHECKED jne @0x8fc5b7 |
| 59 | 0x6e2dc0 | 0x6e4ba3 | 80 | CHECKED je @0x6e4baa |
| 80 | 0x2a9b20 | 0x2a9cf0 | 54 | CHECKED je @0x2a9cf7 |
| 89 | 0x7299f0 | 0x7299ff | 683 | CHECKED jne @0x729a06 |
| 90 | 0x729a40 | 0x729a55 | 683 | CHECKED je @0x729a5c |
| 92 | 0x729dc0 | 0x729df5 | 683 | CHECKED je @0x729e0f |
| 92 | 0x729dc0 | 0x72a1de | 291 | CHECKED jne @0x72a1eb |
| 96 | 0x49ff80 | 0x4a0185 | 201 | CHECKED jne @0x4a0192 |
| 96 | 0x49ff80 | 0x4a02c7 | 201 | CHECKED jne @0x4a02d4 |
| 96 | 0x49ff80 | 0x4a0357 | 201 | CHECKED jne @0x4a0364 |
| 96 | 0x49ff80 | 0x4a03d9 | 201 | CHECKED jne @0x4a03e6 |
| 122 | 0x6bc8d0 | 0x6bc976 | 18 | CHECKED jne @0x6bc97d |
| 122 | 0x6bc8d0 | 0x6bc9b9 | 18 | CHECKED je @0x6bc9c0 |
| 126 | 0x2a9df0 | 0x2a9ef7 | 55 | CHECKED je @0x2a9efe |
| 127 | 0x2aa060 | 0x2aa14c | 56 | CHECKED je @0x2aa153 |
| 140 | 0x331100 | 0x331164 | 15 | CHECKED jne @0x33116b |
| 147 | 0x2a8e70 | 0x2a8e87 | 680 | CHECKED jne @0x2a8e91 |
| 182 | 0x2a99f0 | 0x2a9a9c | 53 | CHECKED je @0x2a9aa3 |
| 183 | 0x2a9700 | 0x2a97b8 | 51 | CHECKED je @0x2a97bf |
| 190 | 0x8f9260 | 0x8f9289 | 683 | CHECKED jne @0x8f9290 |
| 191 | 0x8f9310 | 0x8f933b | 683 | CHECKED jne @0x8f9342 |
| 192 | 0x72c3e0 | 0x72c40b | 683 | CHECKED je @0x72c415 |
| 204 | 0xab9710 | 0xab9722 | 362 | CHECKED jne @0xab9729 |
| 233 | 0x6bbd20 | 0x6bbd8c | 17 | CHECKED jne @0x6bbd93 |
| 233 | 0x6bbd20 | 0x6bbde0 | 17 | CHECKED jne @0x6bbde7 |
| 315 | 0xb7e960 | 0xb7e98b | 683 | CHECKED jne @0xb7e992 |
| 324 | 0xab9580 | 0xab95a4 | 361 | CHECKED jne @0xab95ab |
| 325 | 0xab9690 | 0xab96a6 | 362 | CHECKED jne @0xab96ad |
| 329 | 0x5a3c60 | 0x5a3d02 | 204 | CHECKED jne @0x5a3d09 |
| 397 | 0x8f6120 | 0x8f614e | 683 | CHECKED jne @0x8f6155 |
| 397 | 0x8f6120 | 0x8f6391 | 326 | CHECKED je @0x8f6398 |
| 499 | 0x8f6e50 | 0x8f6e66 | 683 | CHECKED jne @0x8f6e6d |
| 532 | 0xaf0040 | 0xaf00e6 | 682 | CHECKED je @0xaf00f4 |
| 559 | 0xabc510 | 0xabc556 | 685 | CHECKED jne @0xabc56a |
| 559 | 0xabc510 | 0xabc5a4 | 685 | CHECKED jne @0xabc5ab |
| 586 | 0x3ce150 | 0x3ce18f | 685 | CHECKED jne @0x3ce196 |
| 587 | 0x4e1a70 | 0x4e1b0c | 686 | CHECKED je @0x4e1b1e |
| 602 | 0xa368e0 | 0xa36917 | 687 | CHECKED jne @0xa3691e |
| 603 | 0x72ecc0 | 0x72eceb | 683 | CHECKED je @0x72ecf5 |

## 3. Gate sites: capability predicates

Columns: syscall(s), handler body RVA, call RVA, predicate, credential source
(td+0x140 = struct thread->td_ucred, proc+0x40 = struct proc->p_ucred,
proc+0x3e8 = process capability object), eax disposition.

| sys | body | call | predicate | cred source | eax afterwards |
|---|---|---|---|---|---|
| 2 | 0xcb1390 | 0xcb13b5 | cred+0x60 bit 62 | td_ucred | CHECKED je @0xcb13bc |
| 7 | 0xbe8290 | 0xbe82bf | cred+0x60 bit 62 | td_ucred | CHECKED je @0xbe82c6 |
| 59 | 0x6e2dc0 | 0x6e2def | cred+0x60 bit 62 | td_ucred | CHECKED je @0x6e2dfc |
| 59 | 0x6e2dc0 | 0x6e4e68 | cred+0x60 bit 62 | td_ucred | CHECKED je @0x6e4e6f |
| 59 | 0x6e2dc0 | 0x6e51aa | (cred+0x58 & 0xff0f000000000000) == 0x4800000000000000 | proc_ucred | CHECKED je @0x6e51b1 |
| 202 | 0x5581e0 | 0x558282 | cred+0x60 bit 62 | proc_ucred | CHECKED je @0x55828e |
| 251 | 0xcb1ab0 | 0xcb1adb | cred+0x60 bit 62 | td_ucred | CHECKED je @0xcb1ae2 |
| 466 | 0x4a0400 | 0x4a047f | cred+0x60 bit 62 | td_ucred | CHECKED je @0x4a0486 |
| 466 | 0x4a0400 | 0x4a06bd | cred+0x60 bit 62 | td_ucred | CHECKED jne @0x4a06c4 |
| 532 | 0xaf0040 | 0xaf0123 | cred+0x58 == 0x4800000000010003 | td_ucred | CHECKED jne @0xaf012b |
| 533 | 0x705880 | 0x7058bd | cred+0x68 bit 61/56 + cred+0x5f == 0x41 | td_ucred | CHECKED je @0x7058c4 |
| 534 | 0x705c60 | 0x705c9d | cred+0x68 bit 61/56 + cred+0x5f == 0x41 | td_ucred | CHECKED je @0x705ca4 |
| 535 | 0x4f65f0 | 0x4f664e | cred+0x58 == 0x4800000000000007 | td_ucred | CHECKED je @0x4f6655 |
| 536 | 0x4f6a70 | 0x4f6ac5 | cred+0x58 == 0x4800000000000007 | td_ucred | CHECKED je @0x4f6acc |
| 547 | 0xaba540 | 0xaba591 | capobj+0x140 mask & 0x8 | proc+0x3e8 | CHECKED jne @0xaba598 |
| 572 | 0xabac50 | 0xabace4 | capobj+0x140 mask & 0x4 | proc+0x3e8 | CHECKED jne @0xabacf2 |
| 591 | 0x34ae90 | 0x34afb3 | capobj+0x140 mask & 0x10 | proc+0x3e8 | CHECKED je @0x34afba |
| 600 | 0xa367e0 | 0xa3680b | cred+0x60 bit 62 | td_ucred | CHECKED je @0xa36812 |
| 601 | 0xca0630 | 0xca0900 | cred+0x58 == 0x4800000000000007 | proc_ucred | CHECKED test r12d,r12d after an intervening call; je @0xca091c (manual resync) |
| 601 | 0xca0630 | 0xca0cf5 | cred+0x60 bit 62 | td_ucred | CHECKED je @0xca0cfc |
| 601 | 0xca0630 | 0xca1649 | cred+0x60 bit 62 | td_ucred | CHECKED je @0xca1650 |
| 604 | 0x4f7370 | 0x4f73d0 | cred+0x58 == 0x4800000000000007 | td_ucred | CHECKED je @0x4f73d7 |
| 608 | 0x34bdc0 | 0x34bf8d | capobj+0x140 mask & 0x2 | proc+0x3e8 | CHECKED jne @0x34bf95 |
| 608 | 0x34bdc0 | 0x34c045 | capobj+0x140 mask & 0x8 | proc+0x3e8 | CHECKED je @0x34c04c |
| 610 | 0x5a7f60 | 0x5a7f8a | cred+0x60 bit 62 | td_ucred | CHECKED jne @0x5a7f9e |
| 611 | 0xa36bc0 | 0xa36bec | cred+0x60 bit 62 | td_ucred | CHECKED je @0xa36bf3 |
| 612 | 0x34ce50 | 0x34ceee | cred+0x68 bit 61/56 + cred+0x5f == 0x41 | ? | CHECKED je @0x34cef5 |
| 612 | 0x34ce50 | 0x34cefe | cred+0x58 exact-match (0x6091f0 family) | ? | CHECKED je @0x34cf05 |
| 612 | 0x34ce50 | 0x34cf1e | cred+0x68 bit 57 | ? | CHECKED je @0x34cf25 |
| 612 | 0x34ce50 | 0x34cf2e | cred+0x58 range/mask (0x3d003) + exact 0x4800000000001010 | ? | CHECKED je @0x34cf35 |
| 613 | 0xabca10 | 0xabca3a | cred+0x60 bit 62 | td_ucred | CHECKED je @0xabca41 |
| 616 | 0x438c90 | 0x438d67 | cred+0x60 bit 62 | td_ucred | CHECKED je @0x438d75 |
| 616 | 0x438c90 | 0x438da7 | cred+0x58 in {0x4800000000000022, 0x..2e, 0x480000000000101f} | td_ucred | CHECKED je @0x438dae |
| 618 | 0xabd0f0 | 0xabd11c | cred+0x60 bit 62 | td_ucred | CHECKED je @0xabd123 |
| 622 | 0x7dcd40 | 0x7dce29 | cred+0x58 == 0x4800000000000007 | td_ucred | CHECKED je @0x7dce31 |
| 622 | 0x7dcd40 | 0x7dcf3c | cred+0x58 == 0x4800000000000007 | td_ucred | CHECKED je @0x7dcf44 |
| 622 | 0x7dcd40 | 0x7dcf51 | cred+0x58 in {0x4800000000000022, 0x..2e, 0x480000000000101f} | td_ucred | CHECKED je @0x7dcf59 |
| 622 | 0x7dcd40 | 0x7dd026 | cred+0x58 == 0x4800000000000007 | td_ucred | CHECKED je @0x7dd02e |
| 622 | 0x7dcd40 | 0x7dd03b | cred+0x58 in {0x4800000000000022, 0x..2e, 0x480000000000101f} | td_ucred | CHECKED returns value to join 0x7dce3f (branch-value) |
| 623 | 0x8d25a0 | 0x8d25c3 | cred+0x60 bit 62 | td_ucred | CHECKED je @0x8d25ca |
| 627 | 0x4a2850 | 0x4a2880 | cred+0x60 bit 62 | td_ucred | CHECKED je @0x4a2887 |
| 636 | 0x6be4d0 | 0x6be4e4 | cred+0x60 bit 62 | td_ucred | CHECKED je @0x6be4eb |
| 637 | 0xabd930 | 0xabda99 | cred+0x60 bit 62 | td_ucred | CHECKED je @0xabdaa0 |
| 641 | 0x4a2de0 | 0x4a2e10 | cred+0x60 bit 62 | td_ucred | CHECKED je @0x4a2e17 |
| 642 | 0xabdad0 | 0xabdafc | cred+0x60 bit 62 | td_ucred | CHECKED je @0xabdb03 |
| 646 | 0xabe1c0 | 0xabe1e8 | cred+0x60 bit 62 | td_ucred | CHECKED je @0xabe1ef |
| 647 | 0xabe7b0 | 0xabe7d8 | cred+0x60 bit 62 | td_ucred | CHECKED je @0xabe7df |
| 648 | 0x9f81f0 | 0x9f8201 | cred+0x58 == 0x4800000000000007 | td_ucred | CHECKED je @0x9f8208 |
| 652 | 0xbe9510 | 0xbe953f | cred+0x60 bit 62 | td_ucred | CHECKED je @0xbe954c |
| 652 | 0xbe9510 | 0xbe956b | cred+0x58 in {0x4800000000000022, 0x..2e, 0x480000000000101f} | td_ucred | CHECKED je @0xbe9572 |
| 667 | 0x4a31a0 | 0x4a31cc | cred+0x60 bit 62 | td_ucred | CHECKED je @0x4a31d3 |
| 671 | 0xabe8b0 | 0xabe91f | cred+0x60 bit 62 | td_ucred | CHECKED jne @0xabe926 |
| 674 | 0xabb980 | 0xabb9ad | capobj+0x140 mask & 0x4 | proc+0x3e8 | CHECKED jne @0xabb9ba |


## 4. Survivors, ranked by exploit value

No site in this corpus is a proven bypass. The list below ranks the sites that
either (a) let an unprivileged caller past a gate by design, or (b) make the
gate's outcome depend on state we might influence. Each row names the 14.10
measurement that would settle it. All 14.10 probes must be run with the normal
probe harness; none of them is a network probe.

Rank 1 - sys 587 as an oracle for the exact-match capability tags.
  Status 2026-11-05: OPEN, but the 55e capture does not answer it. 587 copies
  cred+0x58..+0xDF to the caller only on the privilege-GRANTED path; on the
  denied path it writes just two qwords and leaves the rest zero. The 55e
  record (ret 0, only +0x0C = 0x20000000) is exactly what the denied path
  produces, so it does not expose cred+0x58. See section 4a for the decode
  and for what the record does prove (cred+0x60 bit 61 is set).
  Sites: 14 exact-match call sites inside bodies, drawn from 11 helpers that
  compare cred+0x58 (0x609080, 0x6090a0,
  0x6090d0, 0x609110, 0x609130, 0x609150, 0x609170, 0x609190, 0x6091b0,
  0x6091d0, 0x609270), reached from sys 612, 616, 622, 652, 532 and others.
  Defect class: none. This is an oracle play: every one of these predicates is
  an exact 64-bit compare of cred+0x58 against a constant of the form
  0x4800_0000_0000_00XX (all have bit 62 and bit 59 set). If our own cred+0x58
  equals one of them, the corresponding handler is open to uid 1 without any
  priv_check call.
  14.10 probe: call 587 with a 0x88-byte buffer (measured to return 0 and 0x88
  bytes) and dump all 0x88 bytes, not just +0x0C; look for any qword matching
  0x4800_xxxx_xxxx_xxxx. If found, the low byte names the role tag and rank-1
  becomes a direct call into the matching handler. If no such qword appears,
  the record is a projection, not the ucred, and this rank drops to zero.

Rank 2 - fail-open capability test 0xb2bb00 (NULL object means allow).
  Body: gs:[0] -> td->td_proc; rcx = [proc+0x3e8]; if rcx == 0 return 1
  (allow); else test dword [rcx+0x140], edi; setne al.
  Sites: sys 547 @0xaba591, sys 572 @0xabace4, sys 591 @0x34afb3,
  sys 608 @0x34bf8d and @0x34c045, sys 674 @0xabb9ad.
  Defect class: missing state treated as authorized (a fail-open check, not a
  discarded result). What it would unlock: the post-gate operations of those
  five handlers, including the VM-map enumeration of sys 674, which 14.10 is
  measured to answer with 317 full region records. That measurement is
  consistent with either a set mask bit or a NULL object pointer, and the 587
  record (0x20000000 at +0x0C) does not expose capobj+0x140, so the mask value
  is unknown.
  14.10 probe: (a) call 547, 572, 591, 608, 674 with the same argument shapes
  already used for 674 and record ret and buffer contents; (b) repeat each
  call from a thread created with thr_create(430) using the known gates, and
  compare parent and child results. A child whose capability object is empty
  would take the fail-open path while the parent does not.

Rank 3 - sys 637 self/zero-id path skips the capability test.
  Body 0xabd930. Head: cmp qword [rsi+8], 0x11; jl EINVAL(0x16); eax = [rsi]
  (object id); if eax == 0 -> 0xabd971; else compare eax with [proc+0xbc]; on
  mismatch jump to 0xabda92, which is the only place cred bit 62 is tested
  (call 0x608f90 at 0xabda99). The self path (id == 0 or id == own) proceeds
  to lock [rbx+0x148], test [rbx+0xb0] & 0x2200, require [rbx+0xb8] == 1,
  increment [rbx+0x358], call 0x6efaa10, and later store into [r12+0x280] and
  call 0x7051c70.
  Defect class: check on only one of two paths to the same mutation. Whether
  this is a bug depends on whether the id-0/self object is ours or a shared
  system object. The mutation at 0xabd990..0xabd9c3 runs on rbx = td->td_proc,
  i.e. our own process record, so the self path mutates only our own proc;
  the foreign-id path looks up another process and mutates that.
  14.10 probe: call 637 with a 0x20-byte request block, id = 0, then id =
  getpid(), then id = a foreign pid; compare ret. If id 0 and getpid() return
  0 while a foreign id returns 1, the capability test is exactly the
  cross-process gate and the self path is a permitted state change (useful as
  a second writer of proc+0x358, not as a bypass).

Rank 4 - sys 532 opcode whitelist runs before the privilege decision.
  Status 2026-11-05: CLOSED for uid 1, and the mechanism in the first line is
  wrong. priv_check(0x2aa) is evaluated first; the capability test at 0xaf0123
  runs only when that check returns 0. Probe 1242a measured EPERM, which
  proves priv 0x2aa was refused, which proves the capability test never ran.
  Commands 0x18 and 0x20 reach 0xaf02a6 only because priv 0x2aa was refused.
  See section 4a.
  Body 0xaf0040. At 0xaf00e6 priv_check(0x2aa) runs; on failure the code at
  0xaf00f6 computes lea ecx,[r14-0x18]; cmp ecx,7; jb 0xaf02a6; then
  cmp r14d,0x2f; je 0xaf02a6; cmp r14d,0x20; je 0xaf02a6; otherwise epilogue
  (returns the priv error). On success it calls 0x609080 at 0xaf0123 and
  requires eax == 1 (cred+0x58 == 0x4800000000010003) before the opcode
  dispatch at 0xaf0131.
  Defect class: two different gate sets for the same dispatcher. Opcodes
  0x18-0x1f, 0x20 and 0x2f reach 0xaf02a6 without either the priv 682 grant or
  the exact credential tag, while all other opcodes need both.
  14.10 probe: call 532 with opcodes 0x18 through 0x1f, 0x20 and 0x2f, each
  with the same argument block, and compare ret against opcode 0x21. If the
  whitelisted opcodes return 0 where 0x21 returns EPERM, the whitelist is the
  unprivileged surface and the next step is to give it a real argument block.

Rank 5 - sys 671 selector -1 exemption.
  Body 0xabe8b0. After the state test (proc+0x5d4 >= 0x5000000), the code does
  cmp r12d, -1; je 0xabe932, which skips the cred bit-62 test at 0xabe91f and
  substitutes r12d = [proc+0x5c0]. Explicit selectors require bit 62.
  Defect class: exemption by design; measured on 14.10 (sel = -1 mode 1 gives
  A=6144 B=3948; selectors 0-10 fail).
  14.10 probe: with sel = -1, vary mode and buffer sizes and see whether any
  mode returns anything other than the two budget numbers; the value at
  proc+0x5c0 is the same field sys 559 writes behind priv 685, so a mode that
  writes it would be the finding.

Rank 6 - sys 616 two-stage lookup.
  Body 0x438c90. First lookup 0x552420(id, 0xffffffff); if it returns non-NULL,
  the cred bit-62 test at 0x438d67 is skipped and execution joins 0x438cdc.
  On the NULL path, bit 62 is tested and a second lookup 0x53c170(id) runs; the
  shared path then tests 0x6090d0 (cred+0x58 in {0x22, 0x2e, 0x101f}) at
  0x438da7 and a proc flag [obj+0xb1] & 2.
  Defect class: the same effect is reachable through a path that skips the
  bit-62 test, but that path still meets the exact-match predicate, so it is
  not a bypass. 14.10 probe: call 616 with an id that exists in the registry
  and one that does not; if both return the same status, the first lookup is
  not a gate but a fast path.

Rank 7 - priv 683 used thirteen times.
  Sites: sys 12 @0x8f6b49, 33 @0x8f8bf2, 56 @0x8fc4b9, 89 @0x7299ff,
  90 @0x729a55, 92 @0x729df5, 190 @0x8f9289, 191 @0x8f933b, 192 @0x72c40b,
  315 @0xb7e98b, 397 @0x8f614e, 499 @0x8f6e66, 603 @0x72eceb.
  priv 683 = 0x2ab. The smallest number in the census is priv 8, used once by
  sys 55 at 0x7e481e.
  Defect class: possible number mismatch (one privilege number reused across
  unrelated services), which the corpus cannot prove because the number table
  is outside the dump. 14.10 probe: call each of those syscalls with a benign
  argument block and see whether any returns 0 where a privilege error is
  expected. Any success tells us 683 is a cheap or always-granted entry in the
  14.10 table.

## 4a. Addendum 2026-11-05 - sys 532 decoded, probe 1242a folded in

### (a) What 0xafc9080 reads

The helper the lead names as 0xafc9080 is RVA 0x609080 (call operands print as
VAs; 0xffffffff8afc9080 - 0xffffffff8a9c0000 = 0x609080). Its entire body is 25
bytes, one basic block, no branches:

    609080  push rbp
    609081  mov rbp, rsp
    609084  movabs rcx, 0x4800000000010003
    60908e  xor eax, eax
    609090  cmp qword ptr [rdi + 0x58], rcx
    609094  sete al
    609097  pop rbp
    609098  ret

It reads exactly one field, cred+0x58 (rdi is a struct ucred *), and compares
the full 64-bit qword against 0x4800000000010003 for exact equality. No mask,
no shift, no bit test, no second field, no early-out, no fail-open on a NULL
cred (a NULL rdi faults rather than returning 1). It is an equality predicate,
not a capability-bit test.

### (b) Relation to the tag listed in CAPABILITY_CONTEXT_14_10.md

That document lists 0x4800000000020002 among the tags and names 532 in the
consumer list. The code does not support the pairing: 0x4800000000020002 is
the immediate of a different helper, 0x6091d0 (movabs rcx, 0x4800000000020002
at 0x6091d4), whose only callers in the image are 0x69a180 (fn 0x69a170),
0xada436 (fn 0xada3a0) and 0xc36e1f (fn 0xc369b0). None of those three is
called from 532. Within 532 extent 0xaf0040-0xaf133e there is exactly one call
to any capability helper: 0xaf0123 -> 0x609080. So 532 tag is
0x4800000000010003, not 0x20002.

### (c) Every sysent body that calls 0x609080

None but 532. The other eight call sites in the image are inside non-sysent
functions: 0x323aa0 (fn 0x323a90), 0x35395b (0x353950), 0x53fa19 (0x53f9e3),
0x89a620 (0x89a5c0), 0xa04667 (0xa044f0), 0xaed66b (0xaecd70), 0xc328b8
(0xc328a0), 0xc5ff62 (0xc5fbf0). None of those eight functions is called
directly from any of the 300 bodies (caller counts outside bodies: 0, 0, 1, 1,
0, 25, 0, 1), so there is no second handler whose ordering can be compared.
Within 532 the call order is: request fields copied in at 0xaf0065-0xaf0096,
then priv_check(0x2aa) at 0xaf00e6, then the capability test at 0xaf0123, then
the command bound check cmp r14d,0x20 at 0xaf0131 and the opcode mask
mov ecx,0x800003d4; bt rcx,rax at 0xaf013e. The capability test therefore
precedes the handler own command validation on the privileged path.

### The branch sense, and why probe 1242a measured priv 0x2aa

     af00de  mov rdi, rbx
     af00e1  mov esi, 0x2aa
     af00e6  call 0xadfa30            ; priv_check(td, 0x2aa)
     af00f2  test eax, eax
     af00f4  je 0xaf011c              ; eax == 0 (granted) -> capability test
     af00f6  lea ecx, [r14 - 0x18]    ; denied path: command whitelist
     af00fa  cmp ecx, 7
     af00fd  jb 0xaf02a6
     af0103  cmp r14d, 0x2f
     af0107  je 0xaf02a6
     af010d  cmp r14d, 0x20
     af0111  je 0xaf02a6
     af0117  jmp 0xaf1223             ; epilogue, returns eax = 1 = EPERM

     af011c  mov rdi, [rbx + 0x140]   ; td_ucred - GRANTED path only
     af0123  call 0x609080
     af0128  cmp eax, 1
     af012b  jne 0xaf02a6             ; tag mismatch -> status path, NOT EPERM
     af0131  cmp r14d, 0x20           ; command validation happens after

So a capability failure does not produce EPERM. It diverts to 0xaf02a6, which
builds a status word (0x800D0202 family) and returns 0. Probe 1242a measured
ret -1 / EPERM / untouched buffer for command 0x31 and its selectors. That
result can only come from 0xaf1223 with eax = 1, i.e. from priv_check(0x2aa)
failing. The capability test was never executed for those commands. Commands
0x18 and 0x20 produced 0x800D0203 and 0x800D0208 precisely because the denied
path routes them to 0xaf02a6 and its builders, which the privileged path also
uses. The 1242a control calls are evidence that the denied-path routing works,
not that the tag check passed.

Conclusion for 532: the row is closed at priv 0x2aa. Even a credential that
held 0x4800000000010003 could not use command 0x31 without passing priv 0x2aa
first, and uid 1 does not pass it.

### (d) Can 0x609080 return 1 for our credential?

The helper never reads the word that carries 0x20000000. It reads only
cred+0x58. So the 0x20000000 we hold is irrelevant to it in both directions:
it neither helps nor blocks. 0x609080 returns 1 if and only if
cred+0x58 == 0x4800000000010003, and there is no other path, no aliasing, no
masking and no fallback.

Whether our cred+0x58 equals that constant is not answered by the 55e record,
and the earlier draft of this document was wrong to treat it as an oracle.
587 shape is:

    4e1aaa  mov edi, [rbx]           ; arg0 = id
    4e1ab0  call 0x53c170            ; registry lookup by id (arg0 != 0)
    4e1b04  mov rdi, r15
    4e1b07  mov esi, 0x2ae
    4e1b0c  call 0xadfa30            ; priv_check(td, 0x2ae)
    4e1b11  mov rcx, [r14 + 0x40]    ; proc_ucred
    4e1b18  lea rsi, [rcx + 0x58]
    4e1b1c  test eax, eax
    4e1b1e  je 0x4e1b75              ; GRANTED: memcpy(record, cred+0x58, 0x88)
    4e1b20  mov rax, [rsi]           ; DENIED: tag reported only if recognised
    4e1b23  movabs rdx, 0xb7ffffffeffffffc
    4e1b30  cmp rdx, 0xf ; ja ... ; bt 0xe001, rdx   ; five accepted values
    4e1b50  mov [rbp - 0xb0], rax    ; record+0x00
    4e1b57  movabs rax, 0x7000000000000000
    4e1b61  and rax, [rcx + 0x60]
    4e1b65  mov [rbp - 0xa8], rax    ; record+0x08
    4e1b75  lea rdi, [rbp - 0xb0] ; mov edx, 0x88 ; call memmove
    4e1b9b  mov rbx, [rbx + 8] ; test rbx,rbx ; je return
    4e1bca  call 0x2591d0            ; copyout(record, arg1, 0x88); user range
                                     checked at 0x2591f8 against 0x800000000000

The denied path writes record+0x00 (only for the five recognised values
0x4800000000000004, 0x...011, 0x...012, 0x...013 and 0x4800000000001010) and
record+0x08 (the masked bits 60-62 of cred+0x60); the rest stays zero from the
0x88-byte zeroing at 0x4e1aa5. The saved 55e capture shows ret 0, the buffer
otherwise all zero, and +0x0C = 0x20000000. That is exactly the denied-path
output when cred+0x60 & 0x7000000000000000 = 0x2000000000000000. If instead
the granted path had run, the record would be a raw 0x88-byte copy of the
credential tail and would almost certainly contain other nonzero dwords; none
were printed.

So the record is the denied-path stub. It does NOT expose cred+0x58, so our
role tag remains unknown. It DOES show cred+0x60 & 0x7000000000000000 =
0x2000000000000000, which fixes the level bits: bit 61 set, bit 62 clear,
bit 60 clear. That corroborates the measured bit 62 zero from another
direction and is independent of the path question, because both paths write
or copy the same field.

### What this leaves on 532 tag family

Every exact-match helper returns 0 for a credential whose cred+0x58 is not the
helper constant. We do not know our constant, so the family stays open as a
question of fact, not of code: there is no masking bug and no missing check to
exploit. What would settle it is any handler that reads cred+0x58 to user
memory without a prior privilege gate. The census found none in the 300
bodies, and 587 is not one.

### The one capability bit we do hold

cred+0x60 bit 61 is set. The predicate for it, 0x608fb0, has the same shape as
0x608f90 (bit 62) and only three callers image-wide: 0x3c145f (fn 0x3c0ab0),
0x68feb9 (fn 0x68fd94, where bit 61 selects level 2 after bit 62 selects level
1), and 0x6b9659 inside 0x6b9640, where sel==1 returns the bit-61 result and
sel==2 the bit-62 result. No sysent body calls 0x608fb0 directly, and the
enclosing functions are reached only from non-body code (0x3c0ab0 from
0x3bb0e7/0x3c03ae/0x3c0415; 0x68fd94 from 0xe4f720; 0x6b9640 from 0x3be589/
0x3c0366/0x3c2270), so a body could use a bit-61 gate only through an indirect
dispatch this corpus cannot follow. If any Sony service turns out to be gated
on level 2 rather than level 1, we hold the level. That is the only remaining
capability lead with positive evidence behind it.

## 5. Method

1. Image: C:/PS5contrib/docs/dumps_13.60/kernel_text.bin, base VA
   0xffffffff8a9c0000, RVA == file offset, length 0xE6E5C0. Sysent table from
   C:/PS5contrib/docs/dumps_13.60/sysent_area.bin (RVA 0xE6E5C0, 679 entries,
   48 bytes each, sy_call_off at +0x00 as a VA).
2. Handler resolution: sy_call is a 5-byte E9 thunk; follow_thunk() follows E9
   chains up to 6 hops. 679 entries give 301 distinct targets; 0x5620e0 is the
   shared nosys stub (368 entries) and is excluded, leaving 300 bodies.
3. Function starts: union of sysent bodies, thunk targets, every direct E8 call
   target inside the text range, and every 55 48 89 E5 prologue preceded by
   c3/90/cc/0f/5d/41/c9. extent2() decodes linearly from a start and stops at
   any other known start or at a ret/ud2/tail-jmp followed by 00/cc/90/66
   padding.
4. Edge extraction: the whole image is decoded linearly in 0x40000-byte chunks
   with capstone in skipdata mode (6,134,183 instructions, 303,789 call/jmp
   edges, about 31 s) and cached to .local/priv_census/edges.json as
   [site_rva, target_rva, kind]. Call targets are computed as
   int(imm) & 0xFFFFFFFFFFFFFFFF minus the base, because capstone
   sign-extends rel32.
5. Helper discovery: the two known sites resolve to 0xadfa30, which tail-jumps
   to 0xadf890; every call in the image that lands on 0xadfa30 (217) or
   0xadf890 (117) is a privilege check. The capability family was found the
   same way from the second known site and from sys 637's bit-62 call
   (0x608f90, 508 calls image-wide).
6. Cross-check: an alignment-independent byte scan for E8 displacements
   (e8scan.py) reproduces the same edge set for all 21 helper targets with 0
   missing and 0 extra sites, so the census is not an artifact of the decoder.
7. Classification: for each gate call inside a body, walk forward up to 20
   instructions tracking copies of eax; mov/lea/push/pop/nop are flag-neutral
   and may sit between the test and the jcc. Classes: CHECKED (a conditional
   branch consumes the result, failure rejects), SELECT (setcc/cmov), IGNORED
   (eax overwritten or function returns without a consumer), LATE (a store or
   side-effecting call precedes the check), RAW-BIT (a credential field is
   tested inline instead of through a helper).
8. Arguments: the privilege number is the last write to esi before the call
   (immediate or register); the credential source is the displacement of the
   rdi load (td+0x140 thread credential, proc+0x40 process credential,
   proc+0x3e8 capability object).
9. Totals: 99 gate sites in 73 bodies. 46 privilege-helper sites (39
   priv_check, 7 priv_check_cred), 53 capability sites (27 bit 62, 8 exact
   0x07, 4 exact 0x22, 1 exact 0x02, 1 exact 0x10003, 6 mask, 3 cap609620,
   1 cap609750, 1 cap609270, 1 caparith58). Classification: 99 CHECKED, 0
   IGNORED, 0 SELECT-only, 0 LATE, 0 RAW-BIT. Two needed manual resync: sys
   601 @0xca0900 (eax copied to r12d across a call, test r12d,r12d at
   0xca091a) and sys 622 @0x7dd03b (value returned to a join block).

## 6. Pitfalls

- Do not disassemble 15 MB in one capstone call: it raises
  capstone.CsError: Out of memory (CS_ERR_MEM). Chunk at 0x40000 bytes.
- skipdata mode reports undecodable bytes as .byte with ins.id == 0, and
  reading their operands raises CsError(CS_ERR_SKIPDATA). Treat as a block
  terminal in any CFG walk.
- A truncated instruction at the end of a fixed-size disassembly window is
  reported as one or more .byte entries; that looks exactly like a defect
  site a few bytes before a window boundary. Resync with slack before
  believing it (this produced two false UNKNOWNs in the first pass).
- Laying out extents purely by padding/prologue under- and over-shoots: a body
  ending in a tail jmp swallows the next function, and a body without a frame
  pointer has no prologue to stop at. Adding every direct call target as a
  start fixed the observed overruns.
- A CFG built only from decoded jumps and branches under-reports, because one
  misaligned .byte truncates a block and drops everything reachable after it
  (it lost body 0x2a91f0 and body 0xca0630 entirely). The linear sweep is the
  primary universe; the CFG is corroboration only.
- 0x53c170 is not a capability helper. It is a hash-bucket registry lookup of
  a 32-bit object id (key at +0xbc, chain at +0xc0, table protected by
  0x60b350). Counting its 158 call sites as gates inflates the census by 24
  in-body sites; they are test rax,rax null checks.
- Addresses printed by capstone are VAs. RVA = VA - 0xffffffff8a9c0000, so
  0xffffffff8afc9080 is RVA 0x609080, and 0xffffffff8afc90d0 is RVA 0x6090d0.
  Mapping them the other way lands in unrelated code.
- The privilege-number dispatch table is at RVA 0x18bd278, outside the
  0xE6E5C0 text image and outside kernel_data.bin (0x1000000-0x13FFFFF).
  Privilege-number to PRIV_ name mapping is therefore not derivable here.
- A handler that kills the process says nothing about whether it exists, and a
  -1 says nothing about whether the gate passed; the only evidence that counts
  is a successful privileged effect.

## 7. Reproduce

All scripts are in C:/PS5contrib/.local/priv_census/. Run from C:/PS5contrib.

  python .local/priv_census/scan_edges.py    rebuild edges.json (31 s)
  python .local/priv_census/gen_table2.py    99 rows -> table_rows2.tsv, prints counts
  python .local/priv_census/e8scan.py        byte-level E8 cross-check (0/0)
  python .local/priv_census/build_doc.py     regenerates sections 2 and 3
  python .local/priv_census/rawbits.py       inline credential-bit scan (0 hits)
  python .local/priv_census/credprov.py      credential provenance at the 7 priv_check_cred sites
  python .local/priv_census/dump8.py         predicate cluster 0x609080-0x609200
  python .local/priv_census/dump5.py         heads of 202, 92, 637, 671
  python .local/priv_census/dump7.py         sys 532 privileged branch and 0x609080

## Appendix A - helper semantics (13.60 RVAs)

priv_check @0xadfa30 (217 callers):
  push rbp; mov rbp,rsp; mov rdi,[rdi+0x140]; pop rbp; jmp 0xadf890
  => argument 1 is struct thread; the credential is td_ucred at td+0x140;
     argument 2 (esi) is the privilege number.

priv_check_cred @0xadf890 (117 callers): rdi = ucred, esi = privilege.
  Allows unconditionally when [cred+8] == 0, when [cred+4] == 0, and when
  esi == 0x2b1. Special-cases privileges 3, 4 and 0xa0 against a global at
  [rip+0x3217e60]. Otherwise bounds-checks (esi - 2) <= 0x2b1 and dispatches
  through a relative table at RVA 0x18bd278 (outside this dump).

Capability predicates, rdi = ucred, result in eax:
  0x608f90  mov rax,[rdi+0x60]; shr rax,0x3e; and eax,1        (bit 62)
  0x608fb0  same shape                                          (bit 61)
  0x608fd0  same shape                                          (bit 60)
  0x608ff0  (qword [rdi+0x58] & 0xff0f000000000000) arithmetic predicate
  0x609080  cmp qword [rdi+0x58], 0x4800000000010003; sete al
  0x6090a0  cmp qword [rdi+0x58], 0x4800000000000021 or 0x480000000000002d
  0x6090d0  cmp qword [rdi+0x58], 0x4800000000000022 / 0x...2e / 0x480000000000101f
  0x609110  cmp qword [rdi+0x58], 0x4800000000000007; sete al
  0x609130  cmp qword [rdi+0x58], 0x480000000000000f
  0x609150  cmp qword [rdi+0x58], 0x4800000000000010
  0x609170  cmp qword [rdi+0x58], 0x4800000000000015
  0x609190  cmp qword [rdi+0x58], 0x480000000000001f
  0x6091b0  cmp qword [rdi+0x58], 0x4800000000020001
  0x6091d0  cmp qword [rdi+0x58], 0x4800000000020002
  0x609270  range/mask test over (cred+0x58) with mask 0x3d003 plus exact
            0x4800000000001010
  0x609620  bt qword [rdi+0x68],0x3d; bt 0x38; cmp byte [rdi+0x5f],0x41;
            calls 0xf64c20 / 0xf659f0
  0x609750  (qword [rdi+0x68] >> 0x39) & 1
All exact-match constants share bits 62 and 59 (0x48 in the top byte); the low
byte is the role tag.

Capability mask test @0xb2bb00 (7 callers, 6 inside bodies):
  gs:[0] -> [rax+8] (td_proc) -> rcx = [rax+0x3e8]
  if rcx == 0: return 1 (allow)
  eax = 0; test dword [rcx+0x140], edi; setne al
  The second argument (edi) is the bit mask; the object is the process
  capability record, not the ucred. This is a fail-open check: absence of the
  object is treated as authorization.

## Appendix B - the five known facts, re-checked

1. sys 586: priv_check(0x2ad) at 0x3ce18f, test eax,eax; jne to the epilogue
   at 0x3ce1c6, precedes mov [proc+0x5c4], r14d. Confirmed. The write is also
   guarded by r14d < 4 and a non-NULL table entry at [rip+0x3102c9f + r14*0x138
   + 0x38].
2. sys 559: the call is at 0xabc556 (not 0xabc551, which is the mov esi,0x2ad),
   and there is a second priv 0x2ad check at 0xabc5a4 guarding a second write
   to proc+0x5c0. Confirmed with correction.
3. sys 643: not re-verified in this pass; no gate site is reported for body
   0xa37660, which matches "ORs 0xffffffff into proc+0xa34 with no gate".
4. sys 601: revised. The earlier audit's statement that this handler has no
   capability-bit test is contradicted by three sites inside the 0xca0630
   extent: cred+0x58 == 0x4800000000000007 tested at 0xca0900 (result copied
   to r12d and tested at 0xca091a), and cred bit 62 tested at 0xca0cf5 and
   0xca1649. They sit in sub-blocks reached from specific state-flag paths
   (for example test byte [r8+0x529],1 at 0xca0cda before the 0xca0cf5
   check), so the dispatch path is still state-gated; the claim that no
   capability test exists anywhere in the handler does not hold. The 40-entry
   dispatch table at RVA 0x1a51160 remains outside the dump.
5. sys 532: priv_check(0x2aa) at 0xaf00e6; on success it calls RVA 0x609080
   (the note's 0xafc9080 is the VA) and requires eax == 1, i.e. cred+0x58 ==
   0x4800000000010003. Confirmed with correction: the requirement is an exact
   credential tag, not a bit.

## Appendix C - what this census does not say

- It does not say 14.10 has the same code. The image is 13.60. Every site
  above is a 13.60 RVA and needs a 14.10 measurement before use.
- It does not say a privilege number is wrong. The number table is missing.
- It does not cover gates implemented in non-syscall helpers that are called
  after the syscall body returns (taskqueues, VFS layers): the census follows
  direct calls into bodies, not indirect dispatch.
- It does not cover the 368 nosys entries or the shared stub 0x5620e0.

## 4b. 14.10 runtime: 587 argument order and the denied record (probe 1243a)

`probes/phase17_new_vectors/1243a_sys587_shape.lua`
(`results/phase17_new_vectors/1243a_sys587_shape_20261105_140511.txt`, status COMPLETE) settles the
argument order and confirms the stub path empirically. The call is `587(pid, buf)`:

| call | ret | buffer |
|---|---|---|
| `587(0x3109A6500, 0x88)` (buffer as arg1) | -1 | untouched |
| `587(0, 0x3109A6500)` | 0 | record written |
| `587(0x65, 0x3109A6500)` (explicit own pid) | 0 | record written |
| `587(0x88, 0x3109A6500)` | -1 | untouched |
| `587(0, 0)` | -1 | untouched |

So arg1 is a pid (`0` means self, and the explicit own pid is accepted) and arg2 is the buffer; a
small arg1 such as 0x88 is refused as an invalid pid rather than treated as a size. The successful
call zeroes the whole 0x88-byte record and writes exactly one value: the qword at `+0x08` is
`0x2000000000000000`, i.e. `cred+0x60 & 0x7000000000000000`. Everything else, including the tag dword
at `+0x00`, is zero - so the tag was not one of the five values the denied path recognises, and
`cred+0x58` is therefore not in
`{0x4800000000000003/06/07/15/1e/1f/21/22/36/3b/3f/100c, 0x4800000010000003/05/09/0f/10, 0x4800000000020002}`
unless the record shape differs from the static reading.

**This is a positive, independent confirmation of the capability level**: bit 61 set, bits 62 and 60
clear, measured through a syscall rather than inferred from a static chain, and consistent with the
14.10 measurement that bit 62 is absent. It also shows the pid gate is not the thing blocking us -
`pid = 0` and `pid = getpid()` behave identically, so the self path reaches the record builder and the
record builder then takes its denied branch. The remaining question is what that branch tests; that is
now the top item in the capability table (`docs/BIT61_AND_PRIV_MAP_14_10.md`, in progress).

