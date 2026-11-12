# copyin-then-sleep census: only the aio family qualifies, and the tooling has a caveat

Static, 2026-11-05. The goal was to find a handler that copyin's a user struct, **sleeps**, and then
uses the copy - the shape that produced the public aio bug - outside the aio family, which is closed.

## Method

* 301 distinct handler bodies from `sysent_index.json` (thunk -> body via the 5-byte `e9` at the
  `sy_call` VA).
* copyin identified as `call` with immediate target RVA **0x259280**; sleep identified as `call` to
  **0xBF1770** (`msleep`; 663 calls it with the `0x100000` priority flag and two pushed zeros).
* Linear sweep per body with capstone, operands resolved with `detail=True`.

Note on capstone: when the image is disassembled at file offsets, a `call rel32` operand `.imm` is
already an **RVA**, not a VA. Subtracting the kernel base from it produces negative nonsense; that bug
cost one census pass.

## Result at face value

85 of 301 bodies contain a copyin. 8 contain an msleep. **6 bodies contain both**:

| body | syscalls | order |
|---|---|---|
| 0x3AF900 | 662 aio_multi_delete | copyin then msleep |
| 0x3AF8E0 / 0x3AF8F0 | 668 / 661 | share the aio cluster |
| 0x3B01F0 | 663 aio_multi_wait | copyin then msleep |
| 0x3B0FB0 | 664 aio_multi_poll | copyin then msleep |
| 0x3B1680 | 666 aio_multi_cancel | copyin then msleep |
| 0x3B2060 | 669 aio_submit_cmd | copyin then msleep |
| 0x705C60 | 534 jitshm_alias | msleep **before** copyin |
| 0xA37660 | (mapped to 643 by the table) | see caveat |

## The caveat, stated plainly

Handler bodies are **not contiguous**. The first pass bounded each body by the next body start, which
swallows unrelated functions: the 643 candidate's msleep at 0xA38D8C belongs to a different function
(its prologue and `[rdi+0x298]` context do not match the copyin function that starts at 0xA37E60),
and every aio body's range ran to 0x3B6BA8, so their candidate lists are each other's.

A second pass tried to bound a body at a `ret` followed by padding or a new prologue; that heuristic
failed to terminate on this image (every body reported the same end, 0x3B6BA8), so it is not usable
as written. The honest state is:

* **confirmed**: the aio family (662/663/664/666/669) does copyin-then-sleep, which is why it slept
  on the I/O and why its waiter records are interesting - and it is closed by the mode-0 guard and
  the submit tunable;
* **not established**: whether any non-aio handler does the same. The 534 and 643 rows are artefacts
  of the extent heuristic, not candidates;
* **needed**: a real function-extent pass (follow the `ret` graph, or use the `push rbp; mov rbp,rsp`
  prologue scan with an overlap-tolerant walk) before this census can be trusted.

## Why it still matters

If the census is ever finished and a non-aio handler shows copyin -> sleep -> use of a copied pointer
field, that is a stale-pointer TOCTOU reachable with a two-thread gate of the kind the corpus already
runs (socketpair gate, suspend/resume now that 632/633 are proven). Until then, there is no evidence
that such a handler exists in the 301 bodies.
