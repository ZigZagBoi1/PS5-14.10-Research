# SysV IPC and the 641/642/646 statistics handlers on 14.10

Measured 2026-10-29 on firmware 14.10 (`192.168.1.121:9026`, Lua loader).
Syscall numbers come from the 13.60 capture, `docs/sysent-names-13.60.csv`:

```
220 compat7.__semctl   221 semget   222 semop   223 (unnamed)
224 compat7.msgctl     225 msgget   226 msgsnd  227 msgrcv
228 shmat              229 compat7.shmctl  230 shmdt  231 shmget
510 __semctl           511 msgctl   512 shmctl
```

## Isolation sweep

`tools/syscall_isolation_sweep.py --range 208-265` (one connection per number,
six zero arguments, `results/phase15_native_sysent/syscall_isolation_sweep_20261029_233635.txt`):

| result | numbers |
|---|---|
| killed in call | 221, 222, 225, 226, 227, 228, 230, 231, 250, 254, 255, 256 |
| returned -1 | 208-219, 220, 223, 224, 229, 232, 233, 235-249, 251, 252, 257-265 |
| returned 0 | 234, 253 |

Every native SysV entry killed; the three compat entries that answered (220, 229)
and the unnamed 223/224 returned -1. An unimplemented slot does not kill: 219
(`lkmnosys`) returned -1, so a kill means the entry is populated.

## Targeted shapes

Three probes with real arguments, each on a fresh process
(`results/phase17_new_vectors/936a_*`, `936b_*`, `936c_*`):

| probe | call | flags | result |
|---|---|---|---|
| 936a | `semget(IPC_PRIVATE, 1, 0x380)` | `IPC_CREAT\|0600` | killed |
| 936b | `msgget(IPC_PRIVATE, 0x380)` | `IPC_CREAT\|0600` | killed |
| 936c | `msgget(0x1234, 0)` | pure lookup, no create | killed |

So the fault is not in the creation path and not in argument validation: a
lookup that cannot allocate anything dies the same way as a create. Six zeros,
a private key with create, and a foreign key without create are three different
shapes and all three kill the process, while unimplemented neighbours return -1.

## Verdict

The SysV block is unreachable on 14.10. It is not "missing" (712-734 style
kill differently and the compat entries answer), and it is not gated on
arguments: the handler is entered and faults before returning, for every shape
that can be sent from this loader. No object can be created, so there is no
`semctl`/`msgctl`/`shmctl` lifetime to attack and nothing for `sem_undo`,
`msgrcv` or `shmdt` to act on.

## 641 / 642 / 646

`docs/ATTACK_SURFACE.md` lists `641 get_cpu_usage_proc`,
`642 get_map_statistics` and `646 get_kernel_mem_statistics` as `-1`, while the
decompiled 13.60 bodies cannot return -1 - so the recorded -1 looked like a
shape problem rather than a gate. Probe 937a
(`results/phase17_new_vectors/937a_stats_handlers_641_642_646_20261029_233919.txt`)
sent `(buf, 0x400)`, `(buf, 0x400, 0)`, `(0, buf, 0x400)` to 642 and 646 and
`(pid, 0)` / `(pid, buf)` to 641, with a zeroed 0x400 scratch buffer:

- every call returned `-1`,
- every buffer stayed all-zero,
- the process survived all six calls.

A gate that rejects before the body explains this, and the 13.60 bodies only
prove the gate sits somewhere they do not show. Without a way to satisfy
`thread+0x140` these three stay closed.
