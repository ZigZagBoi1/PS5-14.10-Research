# Capability tag map of 14.10 (build 13.60 image)

Date: 2026-11-05.  Image: docs/dumps_13.60/kernel_text.bin, base 0xffffffff8a9c0000,
file offset == RVA.  Script: .local/tag_table.py.  Probes: 1249a (607), 1247a (628).

## 1. The mechanism

Every "capability" gate in this image is one of two shapes, and both read the same
two fields of the credential ([proc+0x140]):

**(a) exact 64-bit tag compare on cred+0x58.**  The canonical body is 25 bytes:

    609080 push rbp / mov rbp,rsp
    609084 movabs rcx,<TAG>
    60908e xor eax,eax
    609090 cmp qword [rdi+0x58],rcx
    609094 sete al
    609097 pop rbp / ret

It returns **1 when the credential carries that exact tag** and 0 otherwise.  Each
tag gets its own helper; the helpers are packed one after another in
0x609020..0x609530 and 0x609720..0x609A00, so a tag is a 10-byte immediate away
from the next one.

**(b) bitfield tests on cred+0x60 and cred+0x6f/cred+0x82.**
0x608f90 / 0x608fb0 / 0x608fd0 are one-liners returning bit 62 / 61 / 60 of
cred+0x60, which is the privilege *level* (0, 1, 2).  0x609560 / 0x6095a0 / 0x609540
test one bit of cred+0x6f and, if set, one bit of cred+0x82 - a jail-style double
test, returning 1 only when the first bit is set and the second is not.

Probe 587 already proved we hold level 2: its denied record carried
qword +0x08 = 0x2000000000000000 = cred+0x60 & 0x7000000000000000, i.e. bit 61.

## 2. Method

1. Byte-scan the whole image for the movabs form of 48 B8..BF followed by an imm64
   whose high 24 bits are 0x480000 (the Sony tag space is
   0x4800_0000_0000_0000 .. 0x4800_0000_00FF_FFFF), keeping only sites with a
   cmp qword [reg+disp],reg within +-0x20 bytes.
2. Walk back to the enclosing 55 48 89 e5 prologue to name the helper.
3. Find every e8 rel32 in the image whose target is that prologue.
4. Attribute each call site to a syscall by bisecting the sorted list of sysent body
   starts (body = the thunk's e9 target, from docs/dumps_13.60/sysent_index.json).

Two caveats measured earlier still apply: a call site can be inside a *helper*
that is itself called by a body (so the syscall attribution is one level shallow),
and the branch sense at each site (does it want 1 or 0) is NOT modelled here - it
has to be read per site.

## 3. The table

| helper RVA | tag it compares cred+0x58 against | call sites | syscalls reached |
|---|---|---|---|
| 0x-1 | 0x4800000000010003 | 0 | (none) |
| 0x4E1A70 | 0x4800000000001010 | 0 | (none) |
| 0x609020 | 0x4800000000010003 | 0 | (none) |
| 0x609040 | 0x4800000000000006 | 64 | 31, 392, 408, 454, 532, 535, 536, 603, 604, 610, 622, 626, 630, 648, 670, 673 |
| 0x609060 | 0x4800000000000036 | 24 | 408, 603 |
| 0x609080 | 0x4800000000010003 | 9 | 31, 363, 408, 488, 532, 552, 558, 648, 649 |
| 0x6090A0 | 0x4800000000000021 | 17 | 534, 586, 610, 626, 648 |
| 0x6090D0 | 0x4800000000000022, 0x480000000000002E, 0x480000000000101F | 36 | 31, 50, 55, 363, 392, 454, 586, 603, 610, 616, 622, 626, 648, 652 |
| 0x609110 | 0x4800000000000007 | 66 | 6, 59, 165, 346, 408, 417, 454, 487, 488, 532, 535, 536, 552, 558, 586, 601, 603, 604, 622, 648, 673, 676 |
| 0x609130 | 0x480000000000000F | 0 | (none) |
| 0x609150 | 0x4800000000000010 | 0 | (none) |
| 0x609170 | 0x4800000000000015 | 5 | 165, 630 |
| 0x609190 | 0x480000000000001F | 3 | 346, 532, 558 |
| 0x6091B0 | 0x4800000000020001 | 0 | (none) |
| 0x6091D0 | 0x4800000000020002 | 3 | 552, 558, 626 |
| 0x6091F0 | 0x480000000000100E | 9 | 408, 417, 488, 612, 626, 640 |
| 0x609230 | 0x4800000010000009 | 2 | 408, 612 |
| 0x609250 | 0x4800000010000005 | 1 | 552 |
| 0x609270 | 0x4800000000001010 | 4 | 552, 558, 612, 649 |
| 0x6092B0 | 0x4800000010000003 | 2 | 232 |
| 0x6092D0 | 0x4800000000001010 | 18 | 59, 454, 455, 466, 482, 483, 488, 532, 586, 594, 628, 629, 630 |
| 0x609310 | 0x480000001000000F | 2 | 532 |
| 0x609340 | 0x4800000010000010 | 2 | 455, 466 |
| 0x609360 | 0x480000000000001E | 9 | 610 |
| 0x609380 | 0x4800000000000003 | 2 | 534, 558 |
| 0x6093A0 | 0x480000000000003B | 2 | 140, 626 |
| 0x6093C0 | 0x480000000000003F | 1 | 140 |
| 0x6093E0 | 0x480000000000100C | 1 | 488 |
| 0x609400 | 0x480000000000100F | 5 | 165, 417, 534, 648 |
| 0x609420 | 0x4800000000001012 | 3 | 488, 670 |
| 0x609440 | 0x4800000000001013 | 3 | 488, 670 |
| 0x609460 | 0x4800000000001016 | 5 | 165, 417, 534, 648 |
| 0x609480 | 0x480000000000101A | 9 | 603, 639 |
| 0x6094A0 | 0x480000000000101B | 9 | 603, 639 |
| 0x6094C0 | 0x480000000000101C | 3 | 603 |
| 0x6094E0 | 0x4800000000001021 | 2 | 639 |
| 0x609500 | 0x4800000000001030 | 3 | 552, 558, 626 |
| 0x609520 | 0x4800000000000019 | 1 | 604 |
| 0x609720 | 0x4800000000000009 | 9 | 534, 673 |
| 0x609780 | 0x480000000000100D, 0x4800000000010000, 0x4800000000010001 | 2 | 50, 363 |
| 0x609850 | 0x4800000000000026 | 1 | 626 |
| 0x609C00 | 0x4800000000000007, 0x4800000000000010 | 1 | 607 |
| 0x609D19 | 0x480000000000100D, 0x480000000000100E, 0x480000000000101F, 0x4800000010000000 | 0 | (none) |

## 4. Calibration: what our own tag is not

628 (mmap_dmem) calls helper 0x6092D0 at 0xABD5EB and then

    abd5f1 test eax,eax ; abd5f3 jne 0xabd60e   (0xabd60e sets r13d=1 -> EPERM)

so 628 continues **only when the helper returns 0**.  0x6092D0 returns 1 when

    cred+0x58 == 0x4800000000001010
  or
    cred+0x58 - 0x4800000000100004 in {0, 13, 14, 15}

(the body does movabs rdx,0xb7ffffffeffffffc ; add rdx,rcx ; cmp rdx,0xf ; ja,
then bt 0xe001,rdx).

Probes 1226a and the 1247a-front measured 628 returning EINVAL 22 and EBUSY 16,
never EPERM 1, and the three capability helpers run before any argument check.
Therefore

**our cred+0x58 is NOT one of {0x4800000000001010, 0x4800000000100004,
0x4800000000100011, 0x4800000000100012, 0x4800000000100013}.**

That single measured fact filters every tag-gated call in the table:

- 607 (tag 0x4800000000000010, helper 0x609C00) - our tag is not it, so the
  sanitizer inside 607 will zero the 0x88-byte block.  1249a measures which of the
  three outcomes actually happens (EPERM, EINVAL from the vnode-type gate, or rv 0
  with an all-zero block, which is what 587 did on its denied path).
- 717 / 532 / 649 (tag 0x4800000000010003, helpers 0x609020 and 0x609080) - not
  ours, so 532 would have failed its capability test even if priv 0x2aa had been
  granted.  This closes 532 twice over.
- 612/649/558/552 (tag 0x4800000000001010, helper 0x609270) - not ours.

Conversely, a helper whose site wants 1 for a tag we *do* hold would be open, but
we do not know the value of our tag, so the table alone cannot prove reachability.
The cheap way to learn it: find a syscall whose tag gate produces a distinguishable
error on both branches, or one that copies cred content out (587 does, but behind
priv 0x2ae).

## 5. What this changes

- The "Sony call cluster" is not uniformly privileged: 16 of the 34 helpers are
  called from two or more syscalls and the tag space is per-feature, not per-vendor.
  A syscall being tagged does not mean it is refused - 628's tag check is a *deny*
  list, not an allow list.
- 607's first gate is not a capability at all: cmp dword [vnode+0x1d4],1 is a
  vnode-type test, so the error we get back (22 vs 1) already tells us whether the
  path resolved to the right object type before any credential question is asked.
- Anything whose only gate is a tag we lack is now statically dead and must not be
  probed.  That is the whole value of the table: fewer wedges, fewer relaunches.

## 6. Reproduce

    python .local/tag_table.py        # regenerates the table above
    python .local/tag_census.py       # same, with per-call-site detail
