# ptrace(26) presence on PS5 firmware 14.10

**Finding: PRESENT and reachable [M].** Native `ptrace` (syscall 26) is not absent on
14.10: the handler answered a call with `-1` and the calling process survived
(canary=OK). This corrects `docs/FREEBSD_CVE_TRIAGE_14_10.md` §3, which listed
ptrace as "**UNKNOWN** - worth one presence call" and stated "native 26 was never
swept (only `compat.ptrace` is known to be `nosys`)".

## Evidence [M]

Probe `probes/phase20_bsd_deep/392f_bsd_last_batch.lua` ran on the retail 14.10
console on 2026-10-23. Its `[E] misc` section calls:

```lua
mk(26)(uint64(0), uint64(0), uint64(0), uint64(0))  -- PT_TRACE_ME, zero args
```

Capture `results/phase20_bsd_deep/392f_bsd_last_batch_20261023_184540.txt`:

```
[E] misc
  ptrace: -1
  ...
canary=OK
=== 392f COMPLETE ===
```

The call returned `-1` and the process completed with its canary intact — no kill,
no panic.

## Interpretation (per docs/SYSCALL_ABSENT_VS_LETHAL.md)

That document's rule is decisive: **RETURNED with `-1` means the slot exists and
rejected these arguments**; KILLED_IN_CALL means an absent slot. An absent FreeBSD
stub would return `ENOSYS` or terminate the caller, not return a value. Since slot 26
returned `-1` with the caller alive, `ptrace` is a **present handler** on 14.10.

The 13.60 static table agrees: `docs/sysent-names-13.60.csv` entry `26,ptrace,0x2660e0` [S].

## Scope of this finding

This is a **presence** result only. It establishes that syscall 26 has a reachable
handler and is therefore on the live attack surface. It does **not** establish:

- which ptrace requests are accepted (only `PT_TRACE_ME` with zero args was tried);
- that a traceable child can be created (fork/rfork are blocked; threads share the
  address space, so the usual `PTRACE_TRACEME` followed by exec pattern has no
  execve path on 14.10);
- any privilege escalation or kernel read/write primitive.

`CT_TRACE_ME` is the request that makes the *caller* traceable by its parent; with no
fork/execve path on 14.10, the classic ptrace privesc precondition is not reachable
from the game process even though the handler is present. Whether any other request
(`PTRACE_PEEKTEXT/POKETEXT`, attach to an existing pid) is accepted remains untested
and would require a console run.

## Ledger

Recorded in `results/INDEX.md` at grade **M** with capture `392f` attached.

## References

- [`probes/phase20_bsd_deep/392f_bsd_last_batch.lua`](../probes/phase20_bsd_deep/392f_bsd_last_batch.lua)
- [`results/phase20_bsd_deep/392f_bsd_last_batch_20261023_184540.txt`](../results/phase20_bsd_deep/392f_bsd_last_batch_20261023_184540.txt)
- [`docs/SYSCALL_ABSENT_VS_LETHAL.md`](SYSCALL_ABSENT_VS_LETHAL.md)
- [`docs/sysent-names-13.60.csv`](sysent-names-13.60.csv)
- [`docs/FREEBSD_CVE_TRIAGE_14_10.md`](FREEBSD_CVE_TRIAGE_14_10.md) §3
