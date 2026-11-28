# execve(59) reachability on PS5 14.10

**Finding: syscall 59 is PRESENT and reachable [M] — it was issued in three saved
captures, all predating `docs/FREEBSD_CVE_TRIAGE_14_10.md` (2026-11-04).** This
corrects that document's `UNKNOWN` / "no probe has ever issued 59" claim (both the
§2.5 CVE-2026-7270 row and S7). The reachability question S7 asked is answered:
execve's slot exists and rejects bad paths without killing the caller.

**But the deeper question is still open:** none of these calls proves the ELF loader
*runs*. Every attempt used a nonexistent/NULL path and returned -1; a live exec path
would return ENOENT for those (also -1 at the loader, which does not surface errno),
so -1 cannot be split between "handler ran, file not found" and "stub returned
ENOSYS". The S7 probe on a real binary (`/app0/eboot.bin` with a legal argv) was
never run.

## Evidence [M]

| Capture | Date | Call | Result |
|---------|------|------|--------|
| `results/phase22_cve_hunt/184a_new_cve_reachability_20261022_122318.txt` | 2026-10-22 | `59("/nonexistent", argv, envp)` and `59("/bin/sh", ...)` via SROP | both `-1`; `pid_post=82`, `=== DONE ===` (caller alive) |
| `results/phase34_shm_race/93d5_rack_tcp_probe_20261105_090502.txt` | 2026-11-05 | `execve(NULL, NULL, NULL)` | `ret=-1 ok=true`, `alive=true`, COMPLETE |
| `results/phase34_shm_race/93d8_mmap_noread_20261105_091044.txt` | 2026-11-05 | `execve(59)` (plus fork variants) | `ret=-1 ok=true` |

The 184a probe source (`probes/phase22_cve_hunt/184a_new_cve_reachability.lua`,
Section D) builds the path in GPU memory and invokes syscall 59 through the child
thread's ROP chain (`srop(59, ga(0x600), ga(0x700), ga(0x710))`) with a minimal
argv/envp. The calls returned and the probe completed with the pid unchanged.

## Interpretation (per docs/SYSCALL_ABSENT_VS_LETHAL.md)

- **`-1` with a live caller = present handler.** An absent slot terminates the
  caller (e.g. the 4095 past-the-end probe), and a stub returns `ENOSYS`. Syscall 59
  returned `-1` with the caller alive and the probe reaching its `COMPLETE` marker,
  so the execve slot exists on 14.10 and is reachable from the game process. This
  also answers the `CVE-2026-7270-ASSESSMENT.md` note that "the 13.60 syscall table
  lists execve as syscall 59; that does not prove the 14.10 dispatch mapping or
  that a particular loader can invoke it" — a loader invoked syscall 59 on 14.10.
- **The S7 reachability deliverable is met**: "a kill means the slot is absent"
  did not happen; the slot answered.

## Scope — what is NOT established

- **No real-binary exec.** S7's decisive follow-up `59("/app0/eboot.bin", argv, envp)`
  (ENOEXEC/EACCES = ELF loader ran) was never issued. No capture writes an execve
  call with a real path and a legal argv.
- **ENOENT vs ENOSYS is unresolved.** The loader prints only the raw return word
  (`-1`), not errno. For `/nonexistent` both a live handler (ENOENT) and a stub
  (ENOSYS) present as -1, so the -1 results cannot by themselves prove the exec
  code path ran.
- **CVE-2026-7270 is still untested.** No oversized/shebang argument was submitted;
  the primitive remains scoped only by reachability, not reproduced. The
  `CVE-2026-7270-ASSESSMENT.md` conclusion (no vulnerable-path test) stands.
- **CVE-2026-49414 (setuid PIE ASLR) precondition** (a setuid exec) is still
  unestablished; no setuid binary path was exercised.

## Ledger

Recorded in `results/INDEX.md` at grade **M**, with the 184a capture attached. The
three captures already had `?`-grade seed rows; this row supersedes them for the
execve-reachability question.

## References

- [`probes/phase22_cve_hunt/184a_new_cve_reachability.lua`](../probes/phase22_cve_hunt/184a_new_cve_reachability.lua) — Section D
- [`results/phase22_cve_hunt/184a_new_cve_reachability_20261022_122318.txt`](../results/phase22_cve_hunt/184a_new_cve_reachability_20261022_122318.txt)
- [`results/phase34_shm_race/93d5_rack_tcp_probe_20261105_090502.txt`](../results/phase34_shm_race/93d5_rack_tcp_probe_20261105_090502.txt)
- [`results/phase34_shm_race/93d8_mmap_noread_20261105_091044.txt`](../results/phase34_shm_race/93d8_mmap_noread_20261105_091044.txt)
- [`docs/CVE-2026-7270-ASSESSMENT.md`](CVE-2026-7270-ASSESSMENT.md)
- [`docs/FREEBSD_CVE_TRIAGE_14_10.md`](FREEBSD_CVE_TRIAGE_14_10.md) §2.5 / S7
- [`docs/SYSCALL_ABSENT_VS_LETHAL.md`](SYSCALL_ABSENT_VS_LETHAL.md)
