# The umtx corpus called syscall 557 — `_umtx_op` is 454, and its SHM/robust-lists argument layouts were never exercised

**Status:** evidence correction + prepared probe, offline. This note re-reads committed probe sources and saved captures, records no new console output, and claims no vulnerability. It corrects which syscall the phase-1/2 "umtx" probes actually called, records the only two saved executions of the real `_umtx_op(454)` on 14.10, and lists the umtx paths that no saved capture has ever exercised. A reachability probe (110a) is prepared but not run.

## 1. Exact records cited

| Record | Path | Key lines |
|---|---|---|
| Probe 04 resolve block | `probes/phase1_identity_layout/04_kernel_surface.lua` | `:11` `sc_umtx_op = 557` |
| Probe 04 umtx test loop | `probes/phase1_identity_layout/04_kernel_surface.lua` | `:40-:48` `pcall(function() return syscall.sc_umtx_op(scratch, op, 0, 0, 0, 0) end)`; `OK` printed when `pcall` succeeded, return value not checked |
| Probe 10 resolve block | `probes/phase2_kernel_objects/10_umtx_stress.lua` | `:14-:15` `sc_umtx_op = 557` |
| Probe 10 SHM counters | `probes/phase2_kernel_objects/10_umtx_stress.lua` | `:82-:94` create counted `rv >= 0`; `:97-:112` lookup/alive/destroy counted `pcall` success only, return value not checked |
| Probe 11 resolve block | `probes/phase2_kernel_objects/11_umtx_race.lua` | `:14` `sc_umtx_op = 557` |
| Probe 12 resolve block | `probes/phase2_kernel_objects/12_nwake_robust.lua` | `:14` `sc_umtx_op = 557` |
| Probe 13 resolve block | `probes/phase2_kernel_objects/13_nwake_oracle.lua` | `:16` `sc_umtx_op = 557` |
| Probe 82a binding | `probes/phase17_new_vectors/82a_umtx_exploit_vectors.lua` | `:79-:94` `resolve({ sc_umtx_op = 557 })` primary, `make_syscall(454)` only if resolve fails |
| 13.60 capture labels | `docs/sysent-names-13.60.csv` | `:456` `454,_umtx_op,0x265600`; `:559` `557,namedobj_create,0x265da8` |
| 56i umtx source (never reached) | `probes/phase14_final_push/56i_unconventional_kaslr.lua` | `:241` `make_syscall(454)`; `:280` op 25; `:299` op 22 |
| 56i capture (7 lines, ends in section B binary dump) | `results/phase14_final_push/56i_unconventional_kaslr_20261018_115126.txt` | no umtx output lines |
| 56i2 umtx source | `probes/phase14_final_push/56i2_kaslr_auxv_stack.lua` | `:302` `make_syscall(454)`; `:315` op 5; `:343` op 21 |
| 56i2 capture | `results/phase14_final_push/56i2_kaslr_auxv_stack_20261018_115541.txt` | `[F] UMTX probe`, `MUTEX_TRYLOCK ret=0`, mutex word `+0x00: 0x00000000_00018DBB` after the call, `NWAKE_PRIVATE ret=0` |
| 557 live behavior (capture) | `results/47a_dispatch_deep_20261016_195632.txt` | `:64-:65` `ver=0 → ret=16901`, `ver=1 → ret=518`; through `:319` `ver=255 → ret=772` |

## 2. What the phase-1/2 probes actually called

Every umtx-labelled probe in phases 1-2 (04, 10, 11, 12, 13) and the prepared phase-17 probe 82a bind `sc_umtx_op` to **syscall 557**. The 13.60 sysent capture labels 557 as `namedobj_create` and 454 as `_umtx_op`; open PR #39 additionally verified the 454 identity three ways (capture arity `narg=6`, handler shape at `0x37ec40` with a jump table bounded at `0x1b` over the 27 umtx ops, and FreeBSD 9 `syscalls.master` numbering). The live 47a sweep shows 557 returning sequential object-id-like values (`517+ver` for `ver=1..255`), which is creation-syscall behavior, not umtx-op dispatch.

Two probe-10 observations are inconsistent with FreeBSD `_umtx_op` semantics and consistent with calling a different syscall:

- `STRESS 2: oversized robust: ACCEPTED(!)` — FreeBSD 11 `__umtx_op_robust_lists` returns `EINVAL` for any `val > 24` (`kern_umtx.c`, releng/11.0, `__umtx_op_robust_lists`); a 4096-byte registration cannot succeed on `_umtx_op`.
- `STRESS 1: destroy 2: OK; lookup after dd: OK(!)` — FreeBSD 11 `umtx_shm` destroy on an unregistered key returns `ESRCH` (`umtx_shm_find_reg` → `ESRCH`), and lookup likewise; "OK" for both is not `_umtx_op` behavior.

The captured phase-1/2 "umtx OK" lines therefore characterize syscall 557 calls that did not throw, and (for probe 10's create counter) returned non-negative values. They carry no information about `_umtx_op`.

## 3. The only saved executions of 454 on 14.10

Probe 56i2's section `[F]` is the only saved capture where syscall 454 was issued. Two calls succeeded:

- `MUTEX_TRYLOCK ret=0` — the probe passes op 5 (`UMTX_OP_MUTEX_LOCK`) with a zeroed object. FreeBSD `_umtx_op` mutex-lock writes the owner TID into the first word; the capture records the previously zeroed word as `0x00000000_00018DBB` after the call. `0x18DBB` is TID-shaped (the thr_create probes record TIDs in the `0x18A19..0x18A1C` family), which is consistent with `_umtx_op` semantics. The probe labels the section `MUTEX_TRYLOCK` but passes op 5.
- `NWAKE_PRIVATE ret=0` — op 21 with count 1.

So 454 is reachable from the Lua loader and behaves like `_umtx_op`. Probe 56i's source contains the SHM (op 25) and `MUTEX_WAKE2` (op 22) sections, but its capture is 7 lines and ends inside section `[B]`; those calls never executed.

## 4. What no saved capture has exercised on 454

- `UMTX_OP_SHM` (25) — create/lookup/alive/destroy were never issued against 454 with a correct argument shape. FreeBSD 11 `__umtx_op_shm` reads the key address from `uaddr1` (4th positional argument) and the flag word from `val` (3rd argument): `_umtx_op(obj_ignored, UMTX_OP_SHM, flags, key, NULL)`. The phase-2 shape (`key` in the `obj` position, `uaddr1 = 0`) would return `EFAULT` even on the correct syscall.
- `UMTX_OP_ROBUST_LISTS` (26) — same layout gap: FreeBSD 11 `__umtx_op_robust_lists` copies the 24-byte `struct umtx_robust_lists_params` from `uaddr1` with size `val`. The phase-2/82a shape (`params` in `obj`, `uaddr1 = 0`) cannot reach the registration path.
- The op matrix (0-26) beyond ops 5 and 21, including the RW-lock ops and PI-mutex ops that allocate `umtx_pi` objects.

Consequences:

- Probe 10's analysis line "SHM double-destroy + lookup after = OK → exact CVE-2024-43102 pattern" describes calls to 557 and is void for umtx. The CVE-2024-43102 reachability question on 14.10 is **open, not answered**. The advisory (FreeBSD-SA-24:08.umtx) affected FreeBSD 14.0/14.1; whether the PS5's FreeBSD 9-lineage kernel at r230171 carries the vulnerable `umtx_shm` refcount path is unknown. UMTX_OP_SHM is also interesting independent of that CVE: each create/destroy pair exercises `umtx_shm_reg` allocation, an shm-backed fd, and registry refcounting.
- Probe 82a (prepared, never run) would have tested the wrong syscall: `resolve({sc_umtx_op = 557})` succeeds (phase-2 probes called it), so the `make_syscall(454)` fallback would never fire. This change also repairs 82a's binding and its SHM/ROBUST_LISTS layouts.

## 5. Prepared probe

`probes/phase19_umtx_454/110a_umtx_shm_reachability.lua` (CRASH_CLASS: LOW) issues the missing calls against `make_syscall(454)` with FreeBSD 11 argument layouts:

- [A] benign wake ops (`UMTX_OP_WAKE` 3, `UMTX_OP_NWAKE_PRIVATE` 21) as a dispatch control
- [B] mutex lock(5)/unlock(6) round trips with owner-word readback, `UMTX_OP_MUTEX_WAKE2` (22), plus a same-shape op-5 call against syscall 557 as a negative control for the phase-2 interpretation
- [C] `UMTX_OP_SHM` (25) with the key in `uaddr1`: single create→lookup→alive→destroy→destroy→lookup cycle, 50-round create/destroy churn, and 10 create-without-destroy (fd leak) rounds. `UMTX_SHM_ALIVE` is called twice — once on the plain heap key (control) and once on a `ftruncate`+`mmap` of the returned shm fd before and after DESTROY, since FreeBSD 11's `umtx_shm_alive` checks the vm object backing the supplied address (`OBJ_UMTXDEAD`), not the key registration
- [D] `UMTX_OP_ROBUST_LISTS` (26) with the 24-byte params struct in `uaddr1`: correct-size registration, oversized (32, expect `EINVAL` per FreeBSD 11), and zero-size
- [E] final canary

Every call is wrapped in `pcall`, all arguments are `uint64()` values, and every return value is printed. No claim is made about what the run will return.

## 6. Limits

- The 13.60 labels come from a fixed-range capture; acquisition authenticity and 14.10 identity are unchanged open questions from the evidence ledger. The live 56i2 result is the strongest 14.10-side signal and is two calls deep.
- `0x18DBB` is TID-shaped by comparison with the thr_create TID family; the capture does not print the caller's TID, so the identification is inferential.
- No 14.10 kernel image is available, so Sony-side modifications to `kern_umtx.c` (including umtxshm) are unverifiable from this repository.
- The FreeBSD 11.0 argument-layout citations describe upstream FreeBSD; the PS5 kernel may differ, which is itself something probe 110a's return values will help distinguish.

## 7. UMTX_OP_SHM is a stub on 14.10 (probes 151a–152k, 2026-10-20)

Probes 151a–152k exercised `_umtx_op(454)` with op 25 (UMTX_OP_SHM) using `make_syscall(454)` and the FreeBSD-style argument layout (`obj=key_addr, op=25, val=sub_op`). The results establish that the SHM sub-operations are **non-functional stubs**:

| Observation | Probe | Detail |
|---|---|---|
| All sub-ops return 0 for valid addresses | 151a, 152b–152k | create(1), destroy(4), alive(8) all return 0 for any mapped userland address |
| Invalid addresses return -1 | 152k | `create(addr=0)` and `create(addr=0xDEAD)` return -1 — address validation IS happening |
| Invalid sub-ops also return 0 | 152k | sub-op 0 and sub-op 16 both return 0 — the handler ignores the sub-op value |
| Zero VM operations | 152k | sys 624 counter shows delta=0 for any number of SHM creates/destroys; mmap (control) shows delta=+5 |
| alive() returns 0 for never-created keys | 152h, 152i | A key at a separate address that was never passed to create still returns alive=0 |
| No fd allocation | 152j | fstat-based scan crashed (189 kills process), but zero VM ops implies no shm_map call |
| No slab reclaim observable | 152f, 152g | 500 SHM spray creates produced zero kernel pointers and no alive() behavior changes |

**Conclusion:** The PS5 14.10 kernel's `__umtx_op_shm` handler validates the address (returns EFAULT/-1 for unmapped addresses) but does not perform SHM registration, vm_object allocation, or fd mapping. The sub-op field is ignored. This means:

- **CVE-2024-43102 is NOT exploitable on this firmware** — the vulnerable `umtx_shm_create_reg`/`umtx_shm_unref_reg` race path is not reachable because the SHM subsystem is stubbed out
- The earlier "100% dangling references" claim (152b) was based on alive() returning 0, which it does unconditionally for valid addresses — not a state indicator
- The "double-destroy returns 0 on both" observation is the stub returning success for any valid address, not a double-free

The stub behavior is consistent with Sony removing the SHM shared-memory subsystem from their FreeBSD fork while keeping the UMTX_OP_SHM dispatch entry. Other UMTX ops (WAIT=5, NWAKE_PRIVATE=21, MUTEX_LOCK=5) are functional (56i2, 152k section G timeout confirms WAIT blocks correctly).
