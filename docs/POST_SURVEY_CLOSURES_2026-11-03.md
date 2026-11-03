# Five lanes closed by measurement, 2026-11-03

Status: measured, firmware 14.10. Each section records what was called, what came back,
and whether the result changes anything already in the repository.

## 1. The opmc store pair has six slots, and the index is checked

`566(tid, idx, value)` stores and `567(tid, idx, out)` reads back, per thread. This is
already documented from probe 327a (`docs/CHANGELOG.md`, 2026-10-22): six slots at
`PCB+0x190+8*idx`, and a process-wide selector path gated on
`cred+0x58 == 0x4800000000010003`.

`983a` asked the question 327a did not: is `idx` bounded? Slots 0…5 return the value
that was written. Index 6, 7 and every out-of-range value tried — 8, 9, `0x10`, `0x40`,
`0x100`, `0x1000`, `0x7FFFFFFF`, `0xFFFFFFFF` — leave the destination holding
`0xEEEEEEEEEEEEF000` instead of the stored value, i.e. a status word. A foreign tid and
tid 0 behave the same way. **There is no out-of-bounds store.**

`983b` added the value's shape: what is returned is the stored value with its **low
byte cleared** (`0xDEADBEEFCAFEBABE` comes back `0xDEADBEEFCAFEB800`, while `0xFF`,
`0x01`, `0x100` and `0xFFFFFFFF` survive), the six slots are independent, and
`567` refuses a NULL destination and a kernel address. So the primitive is six
56-bit fields in the caller's own PCB, not a general kernel write.

## 2. Syscall 605 has one reachable, inert entry

`docs/ATTACK_SURFACE.md` lists `605 workaround8849 → -1`, from a single call. Sweeping
argument shapes on the one ID that works shows otherwise, and then shows it does
nothing:

- `605(0x19810000, …)` returns `0` for every shape tried — out pointer, size, and four
  different argument orders — and writes **nothing** into a page prefilled
  `0xDEADBEEF`;
- the neighbouring IDs `0x1980FFF8`…`0x1980FFFF` and `0x19810001`…`0x19810010` all
  return `-1`.

So the whitelist admits exactly one entry and that entry is a no-op status query. The
`ATTACK_SURFACE` row is corrected accordingly in this change.

## 3. `547` does not see the kernel map

`547(start, end, out)` answers `0` for our own heap and for GPU mappings and `-1` for
every kernel candidate tried — `0xFFFFFFFF80000000`, `…8A000000`, `…8A9C0000`,
`…8B000000`, `…8C000000`, `…8E000000`, `0xFFFF800000000000` — leaving the output page
untouched. `639` and `638` behave the same. It walks the caller's `vm_map`, and the
kernel map is not part of it, which is the same conclusion 237a reached by a different
call (`docs/ATTACK_SURFACE.md`). Recorded here so the lane is not reopened on the
theory that a protection query can distinguish mapped kernel pages.

## 4. `641`, `642`, `646`: gated, not argument-dependent

The method note in `docs/CHANGELOG.md` says a handler whose body cannot return `-1`
must be treated as gated rather than as broken when a call does. All three return `-1`
for every shape tried:

- `641`: struct pointer, three flat arguments, two flat arguments, and the caller's own
  pointer;
- `642`: the struct form and four flat arguments;
- `646`: one and two arguments.

Output buffers are untouched and the process survives each call. Probes `972a`
(two captures) and `972b`.

## 5. SysV IPC is lethal at first touch, even with legal arguments

The isolation sweep already showed 221, 222, 225, 226, 227, 228, 230 and 231 killing
on zero arguments, with 219 (`lkmnosys`) returning `-1` as the control that makes those
kills meaningful. The remaining question was whether the kills were bad-argument
faults.

`973a` called `221 semget(IPC_PRIVATE, 1, 0666)` — a legal Semget with `IPC_CREAT`
absent — and the process died at the call. On this console kernel the range 220…231 is
present but lethal, and there is no argument shape to find.

## Related

- [DEVICE_DESCRIPTORS_14_10.md](DEVICE_DESCRIPTORS_14_10.md) — the descriptor table,
  which closed the device `ioctl`/`mmap` lane at the same time.
- [LOADER_FAULT_CHANNEL_14_10.md](LOADER_FAULT_CHANNEL_14_10.md) — how a fault now
  reports itself, which is what makes a "the process died" result decodable.
