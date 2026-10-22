# What the "-1" syscalls actually do (probes 334a-342a, 2026-10-22)

`docs/SYSENT_PRESENCE_14_10.md` marks about forty handlers as *present* with a
sweep answer of `-1`. That column comes from one connection per syscall with six
zero arguments (`tools/syscall_isolation_sweep.py`). A `-1` from six zeros says
the handler rejected that call. It does not say the handler is dead, and three
of the handlers in this range had already proved the point: 622, 532 and 654 all
returned `-1` to a zero sweep and all answered once they were called with the
argument shape their handler reads.

This round called the same population with real pointers.

## Method

Six shapes per syscall, one connection, nothing else in flight:

| tag | arguments |
|---|---|
| `000000` | `(0, 0, 0, 0, 0, 0)` |
| `P00000` | a zeroed 4 KiB page in slot 0 |
| `0P0000` | the page in slot 1 |
| `00P000` | the page in slot 2 |
| `PP1P00` | pages in slots 0, 1 and 3, `0x100` in slot 2 |
| `P1P100` | page in slots 0 and 2, `0x100` in slots 1 and 3 |

The page is zeroed once per syscall. A marker line is printed before each
number, so a call that kills the process is attributable. Probes
`probes/phase17_new_vectors/334a_obj_family_shapes.lua` and
`probes/phase17_new_vectors/335a_info_family_shapes.lua`.

## Result

Three handlers changed their answer. Everything else in the population returned
`-1` to all six shapes.

| syscall | name | six zeros | real pointer |
|---|---|---|---|
| 538 | `evf_create` | `-1` | `16901`, then `518`, `519`, ... |
| 540 | registry lookup | `-1` | a handle for a registered name |
| 557 | `namedobj_create` | `-1` | `519`-`524` |
| 598 | `dynlib_get_proc_param` | `-1` | `0` with `0x60` written at `+0` |
| 659 | `dynlib_get_list2` | `-1` | `0` with `3` at `+0` and `0x14` at `+8` |
| 637 | `set_phys_fmem_limit` | `-1` | `0` for a large value, **blocks** for a small one |
| 572 | `virtual_query` | `-1` | `0` |

`sys 538` and `sys 557` allocate a kernel object, reserve a handle in
`process+0xc48` and publish it to `td+0x408`, so the handle exists and the rest
of the family has something to act on. That is not the same as the family being
usable, and the following probes measured what it does.

## The evf family does not validate very much, but nothing follows from it

`336a` created objects and drove the family with the returned handle:

```
544 set(handle, 0x1)   = 0
545 clear(handle, 0x0) = 0
546 cancel(handle)     = 0
543 poll(handle, ...)  = -1
541 delete(handle)     = -1
```

`544`, `545` and `546` accept the handle and return success. `541` refuses to
delete a handle the same process created - its dossier describes a handle-role
predicate before the removal, and that predicate fails here - so objects created
this way cannot be destroyed by their creator. `543` refused both mode values
tried; its dossier gives it the same mode validation as the blocking `542`, so
the mode encoding is still unknown and the call was not pursued: `542`
`evf_wait` blocks the caller until the pattern matches, and a blocked main
thread wedges the loader.

`338a` walked the handle space with `544`, `545` and `546`:

| handle | `set` | `clear` | `cancel` |
|---|---|---|---|
| `0`-`517`, `65536`, `2147483647` | `-1` | `-1` | `-1` |
| `518`-`521` (created by the earlier probe in the same process) | `0` | `0` | `0` |
| `522` (created by this probe) | `0` | `0` | `0` |
| `16901` (first creation in the process) | `0` | `0` | `0` |

A value the caller never received is rejected, so the lookup is not a wild
handle dereference. The first `evf_create` in a fresh process returns `16901`
rather than a low number; the same value appears in three separate processes
(`336a`, `338a`, `341a`), and `544` accepts it, so it is a handle and not a
status. It is not established why the first one lands in that range.

## Named objects do not outlive their process

`538` with attribute `0x100` registers the object by name in a shared registry,
and `540` then resolves that name and returns a fresh handle - measured
in-process, with an unregistered name returning `-1` as the control (`341a`).
A registration is supposed to hold its own reference, so the object should
survive the process that made it. It does not: after a relaunch, all four names
registered by `341a` return `-1` from `540` (`342a`), exactly like the absent
control. The registry is therefore scoped to the process, and there is no
cross-process handle to another process's kernel object.

## 637 `set_phys_fmem_limit` stores a chosen qword, and waits

`335a` answered `0` for `637(0, page)` - id zero, value equal to the page
address. `339a` then swept the value with id zero:

```
637(0, 0x10)   = -1
637(0, 0x11)   = never returned          <- the thread stayed in the kernel
```

A single-value retest confirmed a wedge: the follow-up `PING` received zero
bytes and only a game relaunch cleared it. `340a` used values above any
plausible current usage:

```
637(0, 0x7FFFFFFF)             = 0
637(0, 0xFFFFFFFF)             = 0
637(1, 0xFFFFFFFF)             = -1
637(2, 0xFFFFFFFF)             = -1
637(5, 0xFFFFFFFF)             = -1
```

Read against `results/kernel_handlers/analysis/sys_637.md`, the shape is a
**wait for usage to drop**: any value below the process's current physical
memory usage parks the caller until the accounting falls under it, and a value
above it returns immediately. That explains both halves of the measurement -
`17` never returns, 4 GiB returns `0` - and it means the earlier `-1` said
nothing about the handler.

The handler's body is the part worth keeping. With the target id zero, or equal
to the current parent's id at `+0xbc`, the capability helper `0x8afc8f90`
that gates 618, 646 and 671 is **not called**; a foreign id is required to pass
it, and foreign ids return `-1` here. The body then loads the parent's child
pointer at `+0x200` and stores the caller-supplied 64-bit value at
**`child+0x280`** under `child+0x278`.

```
id = 0  ->  parent = current process        (capability helper skipped)
            parent+0x148 lock
            child = parent+0x200
            child+0x278 lock
            [child+0x280] = supplied u64
```


### What the store does to the GPU pool is not established

`344a` and `345a` both used the documented GPU mapping shape -
`mmap(0, size, 0x33, 0x1002, 0xFFFFFFFF, 0)` - and they disagree in a way that
matters.

| run | before any write | after `637(0, 0x10000000)` |
|---|---|---|
| `344a` | 8, 64 and 256 MiB map; 1024 MiB refused | 8 MiB maps; 256 MiB refused |
| `345a` (same process, later) | 64 MiB maps; 256 MiB refused | 256 MiB still refused, and still refused after raising to 4 GiB and 8 GiB |

The `344a` row looks like the write taking effect. It is not, or not proven: by
the time `344a` wrote the limit it had already mapped 8 + 64 + 256 MiB, and
`345a` shows a 256 MiB mapping failing in the same process even with the stored
value at 4 GiB. The plain reading is that this process's GPU-visible pool is
finite and `344a` had spent it - so the refusal follows the *consumption*, not
the write.

What that leaves: the store lands (it returns 0), the destination is fixed, and
no run has yet shown the value changing an outcome. `346a` is the A/B that
settles it - allocate 64 MiB chunks until one fails, raise the value, then try
again on a fresh process - and it has not run.

That is a fully caller-chosen 64-bit value written into a kernel structure by
an unprivileged process, at a fixed offset in a fixed object. It is not an
arbitrary-address write and the meaning of `child+0x280` is unknown; the
analysis calls it a limit or parameter, with unknown units. No path was found
that turns it into a read, a pointer, or a second location.

## 573 `mdbg_call` and one console power-off

`334a` included 573 in its number list, which was a mistake: the presence map
already records 573 as a kill row. Its dossier identifies it as the shared
`nosys` trampoline (`jmp 0x5620e0`) that builds SIGSYS and returns `ENOSYS`;
it takes no pointer and copies nothing.

During `334a` the call killed the process **and the console powered off**. The
are recorded because it happened, and because it does not reproduce on its own:

| run | state before the call | outcome |
|---|---|---|
| `334a` | seven kernel objects created, 35 syscalls already swept | process died, console powered off |
| `337a` | fresh process, `573(0,0,0,0,0,0)` only | process died, console stayed up |

`337a` printed `[BEFORE]` and never printed `[AFTER]`, and a PING afterwards was
refused, so the process died and the console did not. One observation and one
negative control are not a mechanism; what they establish is that the power-off
is not a property of the call alone.

## What this round changes

- The `-1` column in `docs/SYSENT_PRESENCE_14_10.md` is not a verdict. Six of
  the forty-odd rows answer when called with a real pointer, and one of them
  writes a chosen value into a kernel object.
- The object families (evf, namedobj, the registry) exist and work, but they are
  synchronisation objects: patterns, wait queues, a refcount. Nothing measured
  here reads memory, writes to an address, or hands back a kernel pointer.
- The one store that does exist is `637`'s. It lands, it returns 0, and it is
  bounded to a single field of the caller's own process object, with the
  capability bypass being per-process by design rather than a defect. Whether
  the value changes anything observable is not established: the one run that
  looked like an effect is explained by the pool already being consumed.
