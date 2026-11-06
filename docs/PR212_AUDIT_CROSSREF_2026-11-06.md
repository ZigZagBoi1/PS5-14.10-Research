# PR #212 audit crossref — config collapse law (2026-11-06)

Source: cobrajet302gt, post-merge audit of kabangast's PR #212
(ZigZagBoi1/PS5-14.10-Research), graded [S]=drop re-verified, [M]=device
rows, [I]=model. Law filed upstream: cobrajet302gt/PS5-14.10-Jailbreak-Research
issue #8 addendum (config collapse law + zero-reclaim audit law).

## What settles it

`USE_ISO_MALLOC PRIVATE OFF` (OptionsPlayStation.cmake:211, WK-1400 drop) +
`USE_SYSTEM_MALLOC` defaulting OFF (WebKitFeatures.cmake:94) ⇒
`WTF_MAKE_ISO_ALLOCATED` rewrites to `WTF_MAKE_FAST_ALLOCATED`
(IsoMalloc.h:31→:35). **Every per-class IsoHeap/TZone declaration in the
port compiles away.** There is no per-type zone for CanvasRenderingContext2D
(or anything else) to hide in. Terminology: libpas replaces bmalloc
wholesale (USE(PAS_ALLOCATOR), no port line); TZone is the ISO_MALLOC knob.

## Cross-type reclaim is now canonical, matching our 14.22 corpus

Three attributed rows kill "backing stores never share" on this line:
1. [M] our P682v2: AB(192) reclaim of freed CSSFontFace, engine-write
   readback, buffer index 34, 80 ms window;
2. [M] AB(768)→freed CRC2D 768B chunk, NULL-vtable dispatch crash
   (issue #181, comment 6680151380);
3. [M] TFujiwara: v904 AB(768) landing on the ctx slot, 14.22 (issue #216).

P571v14's zero-reclaim (1100+ ABs) is the lost race against
getContext('2d') intermediates (state stack, path, font cache) — not
evidence of zones. Our 14.22 results (v900 A-OK, v904 AB(768) wins the
slot, v909 zero-ea at free, v912 carrier kill, zero-at-free) needed no
IsoHeap assumption anywhere; the fork-model's static-dead-end reading is
closed. Our tree's CLAUDE.md carries no IsoHeap-DEAD sentence (rebase
already aligned us).

## The item-4 shortcut for our v911 sweep

kabangast's leak pair {+0x58 = clients-table cell, +0x68 = wrapper's
DefaultWeakPtrImpl} (both −0x10-tail fork model) admits the cycle-closure
discriminator (comment 6684384814): W = masked(+0x68 value); accept
F ∈ {*(W+0x20), *(W+0x30)} iff masked(F+0x68) equals the stored impl. The
accepted F is the reclaimed slot's VA = carrier self-address modulo the
allocator's chunk header — **self-certifying by construction**.

Consequence for us: a valid pair read on 14.22 (p563-family with the scan
bug fixed — done-before-examine retracted, untested corrected form) plus
the discriminator yields our own process VA **without any forged-read
landing**. That converts v911's 3072-target metralleta into a directed
ladder at a known VA (a handful of cycles). Prereq: pair oracle on 14.22
is the open question; if it works, v913 = pair-read + discriminator +
directed forge at the derived VA.

## Kernel line (banked, no dispute)

70e–72c double-STATUS retraction numbering (662 aio_multi_delete, 669
submit) matches the board's relapse desk map (0x296 / 0x29D); PR #213's
zone-isolation closure points the same way.

Grade discipline for anything transposed to 14.22: the config lines are
[S] on 14.10 drop only; the 14.22 WebProcess is the same port lineage but
Sony diffs are unknown — treat allocator stance as [M×S] (device-observed
cross-type reclaim) rather than [S].
