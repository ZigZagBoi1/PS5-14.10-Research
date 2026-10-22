# Private AIO duplicate-delete candidate — 2026-10-21

The console test ran once on 14.10 at 2026-10-21 08:52:56 EDT after a successful loader ping. The raw capture is `results/phase17_new_vectors/96a_aio_duplicate_delete_20261021_085256.txt`, with a JSON run record alongside it. Keep its source and capture on `staging` until publication is chosen.

## Observed result

The invalid-fd request published ID `0x4205` and reached state `3`. Batch deletion of `[id, id]` returned overall success with per-entry results `0x00000000, 0x80020003`. A subsequent poll returned `0x80020003` for the same ID. A post-probe ping succeeded with the same PID (`140`), so the loader survived. This supports ordinary sequential removal. It produced **no kernel pointer or kernel read/write primitive**. Do not repeat this input expecting a different outcome without a new lifecycle hypothesis.

## Why this call

The saved 14.10 `95b` capture shows a completed AIO read and successful single-ID deletion. The `95c` capture shows that an invalid-fd request still publishes an ID, reaches completed state, deletes successfully, and returns `0x80020003` on a later poll. Those observations establish that the batch-delete entry point is reachable with a completed object.

The 13.60 handler review in `results/kernel_handlers/analysis/sys_662.md` identifies a per-ID validation/lookup, a later reacquisition, and a free/removal path inside the count-bounded loop. That makes a duplicate ID in **one** batch a specific lifecycle question: does the second iteration reject the handle after the first removal, or touch stale state? The 13.60 code is a guide to choosing an input, not proof of the 14.10 implementation or a vulnerability.

## Exact test and interpretation

`96a` initializes AIO if needed, submits one invalid-fd request, waits up to 20 bounded polls for completed state, then calls syscall 662 once with `[id, id]` and a two-entry result buffer. It records markers immediately before and after that call and polls the ID once afterward. There is no race, spray, arbitrary address, or memory write in the probe.

- If the first result is success and the second is an invalid-ID error, that supports ordinary sequential removal.
- If the process or console stops at the duplicate-delete marker, record the stop and recover the console before any further test. A crash alone is **not** evidence of a UAF or kernel R/W.
- If both entries report success, repeat only after independently checking output-buffer integrity and object lifetime. Two success words alone do not prove double-free.
- A kernel pointer claim requires raw bytes, stable provenance within a boot, and expected relocation across boots. A read/write claim requires a separate bounded read/write demonstration. `96a` does neither by itself.

The broader 57a native-syscall survey, direct kldsym, and GPU msync probes all stopped at unsafe boundaries. This single-call, bounded lifecycle test avoids chaining more unknown entry points before the first result is understood.

## Offline check

The bundled Python runtime ran `tools/check_lua_syntax.py`: all 350 Lua 5.1 probes compiled, zero failures. This checks syntax only; it does not validate live ABI, race behavior, or safety.
