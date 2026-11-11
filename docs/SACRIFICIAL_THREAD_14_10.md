# The sacrificial thread: a parking syscall no longer costs a relaunch

Local-only note: built on `.local/loader_payload/thread.lua`, which is deliberately not published.

## What was blocking

Three 601 commands are hostile in ways a sweep cannot afford:

| command | effect | cost |
|---|---|---|
| 0x08 | parks forever inside the kernel | loader stuck, relaunch |
| 0x0C | parks forever | loader stuck, relaunch |
| 0x27 | faults the process | loader dead, relaunch |
| 0x03, 0x04 | take a raw `struct proc*`, SMAP #PF | console panic |

1170a and 1172a each stopped at the first parker, so 601 was being measured one relaunch per
blocker. That is the wrong price for a 48-command space.

## The primitive

The loader already ships it, and says not to use it:

`.local/loader_payload/thread.lua:104-279` — `run_lua_code_in_new_thread(lua_code, opt)` with
`opt = {args, async, client_fd, close_socket_after_finished}`. It builds a **fresh `lua_State`**
(`luaL_newstate` + `luaL_openlibs` + `luaL_loadstring` of a runner that re-requires every module and
re-installs `print`) and runs it on a `Thrd_create` thread whose entry is a longjmp into a ROP chain
(`thread:run`, `:64-84`).

Two details make it usable from a probe:

* `opt.client_fd` — the runner's `print` writes to both stdout and that fd (`:191-198`), so the child
  talks straight back down the probe socket. The current probe's fd is `memory.read_qword(signal.fd_addr)`
  (the loader's own signal module stores it). Measured: **fd 21**.
* `opt.async = true` — `Thrd_create` returns immediately, so the main thread keeps running.

Its own comment (`:111-113`) warns of "a chance to crash the game process because of unfixed race
condition in native primitives". That warning is real and has a shape — see the 1176a failure below.

## Measured

**1175a** (2026-11-04 16:05): a print-only child worked — `[1] spawn ok`, then `T1 state alive`,
`THREAD-ALIVE 1..4`, `THREAD-DONE` interleaved with `MAIN-1..6`. A second child then called
**601 0x0C**, printed `T2 pipe_ok=true`, and never printed again: **it parked** — while the main thread
went on to `MAIN2-1..8`, `[Z] alive` and `=== DONE ===`. The park cost one thread instead of the loader.

**1176a** (16:06) — first attempt at a threaded sweep, and it killed the process on the first child
(0x09) with **no crash blob** at all. That child had done 1024 `memory.write_dword` + 1024
`memory.read_dword` calls inside the new state. Native primitives are exactly what the module's warning
names. **Rule: the child does one syscall and one print. All buffer allocation, filling and reading
stays on the main thread.**

**1176b** (16:07) — restructured that way, mixed results:

* The mechanism held: children reported `T09 rv=0`, `T0A rv=-1`, `T0B rv=0` … and when 0x0C came
  round, its `T0C` line never appeared while `[B0C]` did: **the park was absorbed by the thread and the
  sweep continued in the same process.** That is the whole point.
* Truth table so far (real output, not the changed counter): only **0x0E** (two zero dwords) and
  **0x1A** (one zero dword) write anything at all; 0x09/0x0B/0x0D/0x13/0x14/0x19 return 0 and write
  nothing; 0x0A/0x0F/0x10/0x11/0x12/0x15/0x16/0x17/0x18 return -1 and write nothing.
* Then it died at **0x1B** — again with no crash blob, again on a child. So 0x1B is either a child-side
  fault or another process killer; it needs its own single-command run.
* Probe bug found and fixed: the "changed" counter compared against `324508639`, which is not
  `0xA5A5A5A5` (`2785017861`), so it printed `changed=1024` for an untouched buffer. The `dw=` column
  was the real evidence. **Never trust a derived counter without a control column beside it.**

## Consequences

* A parking command is now cheap and a full 601 sweep is one run per *process killer*, not per blocker.
* A child-side fault is still fatal to the whole process (a fault in any thread kills it, and the pivot
  handler may not report), so children must stay trivial.
* This is also the generic answer to "how do I run something that may hang": the loader's own thread
  API, not a hand-built `thr_create(430)` chain.
