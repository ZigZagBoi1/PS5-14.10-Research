# Descriptor-teardown races on 14.10: three shapes, all clean

Real threads (`thr_create(430)` + `thr_exit(431)`) against live descriptors were
never raced on 14.10 before these probes. Each shape below ran with the child inside
the kernel operation and the parent closing the descriptor underneath it. None
faulted, and the process survived every round.

| probe | child operation | parent action | rounds | result |
|---|---|---|---|---|
| `970a` | `setsockopt(fd, 41, 46, pktinfo, 0x14)` | `close(fd)` right after spawn | 12 | clean |
| `970c` | five children, same call | `close(fd)` 2 ms later | 12 x 5 | clean |
| `971a` | `recvmsg(fd, msg, 0)` with `SCM_RIGHTS` queued | `close(fd)` 2 ms later | 10 | child won every round (`ret=4`), no overlap |
| `971b` | `recvmsg(fd, msg, 0)` blocking, nothing queued | `close(fd)` 2 ms later | 10 | child returned `0` every round, clean |
| `938d` | blocked `read()` on a socketpair | `close(peer)` / `close(self)` | - | `EOF` / stays blocked, no UAF |

The IPv6 option path is the one that matters for the Relapse-era primitive: output
options hang off the inpcb (`inp_outputopts`) and are freed with it, so a
`setsockopt` inside that teardown would be the interesting case. It did not occur in
60 overlaps.

## Harness facts established while running these

- **A gadget must be validated at its entry address, not by its surroundings.**
  `972a` prints eight bytes either side of each candidate. `58 C3` at eboot `+0x992`
  sits inside `mov eax,[rdi+0x58]`, but entering at `+0x992` executes `pop rax; ret`,
  which is what the chains use. `48 89 06 C3` at `+0x1A0BA9` and `48 89 07 C3` at
  `+0x92C67` are likewise valid entry points.
- **A child's syscall return can be recorded through `RSI`** when `RDI` must carry
  the descriptor: `mov [rsi],rax; ret`, with `RSI` pointing at the message header.
  Storing through `RDI` would write to the fd number itself.
- **Re-entering the call stub by repeating it in the chain is unsafe.** The stub's
  registers are clobbered by the call, so a second `fn` in the same chain has
  garbage arguments and takes the process with it (`970b`).
- **A blocking call in the parent wedges the single-threaded loader** and costs a
  game relaunch (`955a`: a blocking `write()` of 32 KB into a peer whose reads had
  not completed). Parent-side calls must be short or use `MSG_DONTWAIT`.
