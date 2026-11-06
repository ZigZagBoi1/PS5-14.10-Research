# Draft issue for pastawithpesto/PS5-14.10-Jailbreak-Research

> Copy-paste ready. Post under their repo's issues (or Discussions if they prefer).
> Context for the author: this console moved to 14.22; we independently confirmed
> the chain (p553-equivalent) and are stuck on the crash-oracle first-hit step.

---

**Title:** V650-V655 crash oracle — what region did your first HIT land in, and which forge offsets?

Hi — we're running an independent 14.x console (now on 14.22) and reproduced your chain up
to and including full bidirectional alias R/W (p553-level: 12 Canvas2D APIs, save/restore,
getTransform through the alias — all confirmed on 14.22; UA still 605.1.15/Version 17.0).
We also confirmed on 14.22 that the FontFaceSet::load() UAF no longer crashes inside load()
(your "DoS-only" verdict is consistent with our measurements — trigger runs clean, no 192B
reclaim, no iterateClients crash).

We're stuck exactly one step behind you: the forged `m_stateStack` crash oracle (V650).
We've run ~1400 forged-read targets across two forge styles with zero survivors:

- v650-style forge: `m_stateStack.m_buffer` at AB+112 (LE pair), m_capacity=1 @+120,
  m_size=1 @+124, everything else zero. Regions swept: your ZigZag intel regions
  (SceLibcHeap 0x310000000±16M, eboot 0x60388000±16M, libc 0xCA700000±8M,
  libkernel 0x819B40000±8M), the 14.10 WebProcess heap 0x100000000±256M, wide
  1G-32G @512MB, stack guesses. All crashed at the same point (the lineWidth read).
- all-words forge (every 8-byte word of the reclaiming AB = target pointer,
  offset-invariant): SceLibcHeap ±16M @256KB and 3G-4G @4MB (1024 targets), zero hits.

Additional measured facts on 14.22 that may differ from your console:

1. An ArrayBuffer(768) spray placed BEFORE the canvas spray takes the freed 768B ctx slot
   (canvas spray loses; v904: crash at the read with fill-poisoned internals).
2. The synchronously freed (getter-trigger) ctx chunk is ZEROED at free — reading through
   the stale wrapper crashes before any reclaim (v909: 6/6 crashes at the first read with
   nothing reclaimed). On your console, did the freed ctx chunk keep its bytes, or did you
   observe the same zeroing?
3. With the canvas-reclaim alias, stateStack grow/realloc, lineDash and getTransform all
   work through the alias — the chain infrastructure is intact.

Questions (any subset helps):

1. In your V650-V655 confirmed runs, what address REGION did the first HIT land in
   (even just "inside 0x3xxxxxxxx" or "near the eboot base")? We understand exact addresses
   are boot-ASLR specific — the region/band is what we need.
2. Did your forge write m_stateStack at AB offset +112 (your v650 comment), and did that
   offset still work on your 14.10 build? If you re-derived it from the WK-1400 source, is
   the CanvasRenderingContext2D m_stateStack offset on your tree +112?
3. When the inner 2d ctx is freed by the outer bitmaprenderer call, does the freed chunk
   keep its old bytes on your build, or is it zeroed before reclaim?
4. Any chance you can publish the v650-v655 beacon logs (the results/ dir here has only
   session10 and v480) — even redacted, the TGT/HIT sequences would let us cross-check
   our sweep against your mapped regions.

We're happy to share our full probe set (v900-v910 + p553 runs on 14.22) and raw beacon
logs if useful. Repo: ZigZagBoi1/PS5-14.10-Research (results/phase13_webkit/,
docs/WEBKIT_CROSSREF_2026-11-03.md).

Thanks — great work on the chain.
