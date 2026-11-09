# Direct kldsym(337) pre-flight review and hardened probe (firmware 14.10, offline)

Probe 57c stages a new direct `kldsym(337)` attempt on 14.10 (the earlier
43b capture is header-only, so no direct attempt has yet produced
evidence). This note records what checks out against upstream FreeBSD
releng/9.0, what 57c gets wrong, and what the hardened sibling probe 57e
changes. No console was contacted; nothing here asserts 14.10 kernel
behavior.

## A. What 57c gets right (verified against upstream)

- Number: upstream `sys/kern/syscalls.master` assigns 337 to
  `kldsym(int fileid, int cmd, void *data)`. The 57c call shape
  `(fileid, KLDSYM_LOOKUP=1, &lookup)` matches that prototype. (The
  repo's 13.60 artifacts corroborate nothing here: `sysent_index.json`
  has no 337 entry and `ps5_13.60_sysent.json` has no `kld` keys.)
- Layout: upstream `sys/sys/linker.h` defines `struct kld_sym_lookup`
  as `int version; char *symname; u_long symvalue; size_t symsize`,
  which on amd64 is exactly 57c's `+0x00/+0x08/+0x10/+0x18` with
  `version = 0x20 = sizeof(struct kld_sym_lookup)`. The handler checks
  `lookup.version != sizeof(lookup) || cmd != KLDSYM_LOOKUP` and
  returns EINVAL otherwise, so 57c's constants satisfy the gate.
- fileid=0 semantics: upstream `sys/kern/kern_linker.c` `sys_kldsym`
  treats `fileid == 0` as "search every loaded module", not "kernel
  only". 57c's comment ("fileid=0 means the kernel itself") is
  imprecise but the direction is right: fileid=0 is the broad search
  and fileid=1 is the narrow one. Note the handler also copies the
  input struct in with `copyin` before validating, so a malformed
  userland string can still produce EFAULT/EINVAL-shaped refusals that
  say nothing about the KASLR question.
- Design: skipping lethal `kldnext(307)`/`kldstat(308)` (probes
  56k4/56k5) and calling 337 directly is the correct next experiment.

## B. What 57c gets wrong (probe-source defects, not kernel facts)

1. Symbol strings are written twice with no verification
   (`57c:78-91`): a dword loop, then a `write_byte` repair loop whose
   failure path just `break`s. Tracing the dwords shows the name bytes
   do land intact even without the repair pass (each iteration's
   character byte sits at offset `i-1` and the next iteration
   overwrites the trailing zeros), so there is no corruption bug here —
   but no readback verifies the final bytes either, so a capture still
   cannot distinguish "symbol absent" from "name mangled in memory".
2. The verdict checks only `h >= 0xFFFF8000` (`57c:125`) without the
   `h < 0xFFFFFFFF` upper bound the repo's own kernel-band rule
   requires. A `0xFFFFFFFF_xxxxxxxx` sentinel with ret=0 would print
   `KASLR DEFEATED`.
3. The `break` on PCALL-FAIL (`57c:110-114`) aborts the remaining
   symbols, so a partial kill hides which names were never attempted.

## C. What 57e changes

Hardened sibling probe `probes/phase15_native_sysent/57e_kldsym_hardened.lua`
(UNRUN, HIGH crash class — 337 may share the 307/308 fate):

- Single `write_byte` string path with byte-by-byte readback; any
  mismatch skips the call and counts it as unverified in the summary.
- A canary echo row per call (fileid, cmd, version, first name bytes)
  so every refusal is attributable to its inputs.
- The full kernel-band check on `ret=0` values; out-of-band values
  print as sentinel suspects, never as defeats.
- Refusals decoded through the upstream errno table (EPERM=1,
  ENOENT=2, EFAULT=14, EINVAL=22, ENOSYS=78) instead of bare numbers.
- No early break: fileid=0 runs all six symbols, then fileid=1 runs
  all six, then a SUMMARY row (resolved/refused/unverified).

The symbol set is shared with 57c/43b so captures stay comparable, and
the fileid=0-then-1 order runs the broad search first.

## D. The 43b record, corrected

The 57c header says kldsym "was NEVER directly tested". The precise
record: probe 43b called `kldsym(337)` with fileid=1 first
(`probes/phase10_untested_theories/43b_kldsym_resolve.lua:104-106`),
but its capture is 5 header-only lines ending at the lookup header
(`results/43b_kldsym_resolve_20261016_180719.txt:1-5`) — no call
result, no kill record. So fileid=1-vs-0 on 14.10 is an open question,
not a 57c-vs-43b contradiction: 43b attempted it and produced no
evidence either way.

## E. Offline verification

- `tools/test_probe57e.lua`: 51-assertion offline harness mirroring the
  56l convention (loadfile sandbox, byte store, syscall shim, output
  assertions). Handlers cover lookup-succeeds, errno refusals
  (ENOENT/EINVAL/EPERM/unmapped), all-ones sentinel rejection,
  pcall-failure, and unverified-string paths. All passing.
- Invocation-shape assertions pin 12 calls (6 symbols x 2 fileids),
  3 args each, cmd=1, size field 0x20.
- No console contacted, no captures changed, no leak claimed.

## F. Deliberately out of scope

- Running 57c or 57e (needs the loader on hardware).
- Asserting 14.10's linker honors fileid=0 the way upstream does.
- The 13.60 sysent name map is not cited for any 14.10 claim.
