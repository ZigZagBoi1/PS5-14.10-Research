# Socket-level ioctl on 14.10: the dispatch exists, the permission gate does not open

Measured 2026-11-05 (probe 1222a, pid 80). This closes upstream open row O10
(`docs/2026-10-25/README.md:73`, "our ioctl sweep tested /dev nodes but NOT socket-level ioctls")
and reconciles it with this repository's older note that syscall 54 "never resolves the descriptor".

## 1. ioctl does reach the socket layer

`socket(AF_INET, SOCK_DGRAM, 0)` (syscall 97) returns fd 22. `ioctl(fd, FIONBIO, &one)` through
syscall 54 returns **EACCES 13**, not ENOTTY 25. So the descriptor resolves, the socket's ioctl
handler is entered, and something above it refuses. The old "54 never resolves the descriptor"
reading came from device nodes, where ENOTTY is the correct answer for an unknown request.

## 2. The request code decides EACCES versus ENOTTY

| request family | example | errno |
|---|---|---|
| FreeBSD `SIOC*` (size-carrying, `0xC02xxxxx`) | `SIOCGIFCONF` 0xC0206911, 0x8920 group | **13 EACCES** |
| small-numbered legacy ioctls | 0x8912, 0x8913, 0x8940-0x894F | 25 ENOTTY |
| `FIONBIO` | 0x8004667E | 13 EACCES |

A recognised request is denied with EACCES; an unrecognised one falls through to ENOTTY. That is a
permission gate on the network ioctl path for this process, consistent with the credential context
recorded in `docs/CAPABILITY_CONTEXT_14_10.md` (no capability bits, `proc+0xc81 == 0`), and it is
not something a different request code is going to get around without privilege.

## 3. No kernel pointers

Every request ran with a 0x100-byte zeroed ifreq-shaped buffer and the buffer was rescanned
afterwards for qwords in the supervisor range (`>= 0xFFFF800000000000`): **0 across 37 requests.**
Nothing was written for the denied requests, and nothing leaked through the accepted ones.

## 4. Sony socket extensions, first contact

These entries had never been called in this corpus (the name map gives 102 `netgetsockinfo`,
113 `socketex`, 114 `socketclose`, 125 `netgetiflist`, 141 `kqueueex`):

| call | result |
|---|---|
| `102(fd, buf, 0x100)` | rv = 1, buffer untouched |
| `102(buf, 0x100)` | -1, EBADF 9 |
| `125(fd, buf, 0x100)` | -1, EFAULT 14 |
| `125(buf, 0x100)` | rv = 4, buffer untouched |

`102` clearly keys on the descriptor in argument 1 (EBADF when it is a buffer address), and `125`
does not. Neither copies anything into a zeroed buffer at those shapes, and neither produced a
supervisor-range value. The probe then hit a Lua bug of its own (a memory handle passed where a
number was expected), so 113 and 141 were not reached; that is a probe defect, not a kernel result.

## 5. Status

| question | answer |
|---|---|
| does syscall 54 resolve socket descriptors | **yes** |
| can this process issue `SIOC*` on a socket | **no — EACCES**, request recognised, permission refused |
| did any socket ioctl leak a kernel pointer | **no, 0/37** |
| Sony net extensions | reachable, no output at the shapes tried; 113/141 untested |
