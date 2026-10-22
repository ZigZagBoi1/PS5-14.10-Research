# The system sockets a game process can reach (14.10)

`/system_tmp` is one of the few directories inside the game's jail
([JAIL_14_10.md](JAIL_14_10.md)), and it holds seven UNIX domain sockets owned by
system services. Probes 296a and later connected to them from an unprivileged game
process. This page records what happens when a game talks to them, what the
compositor's protocol looks like, and where the limits are.

## Which sockets answer

| socket | connect from a game process |
|---|---|
| `GnmCompositorRestricted` | accepted (until it was killed by traffic, see below) |
| `VrTracker2DomainSock` | accepted |
| `AgcCompositorSppSocket` | accepted (until killed) |
| `GnmCompositor` | refused |
| `SceImageUtilAgent` | refused |
| `SystemTts` (mode `0xC1F8`, the others are `0xC1FF`) | refused |
| `redis.sock` | refused |

The four refusals are permission, not state: they refuse on a freshly booted
console and keep refusing. The three that accept are the surface this page is
about.

Every send needs `SIGPIPE` ignored **and** blocked first, or the write terminates
the game process (probe 361a). `sigaction(13, &{SIG_IGN}, 0)` is syscall **416**;
`sigprocmask` is **340** and the `SIGPIPE` bit is `0x1000`.

## What the daemons do with input

* **VrTracker2DomainSock** accepts, reads whatever is sent, closes the connection
  without a reply, and stays listening. Nine different message shapes (364a) all
  ended the same way. It is not a crash and it is not a parser conversation.
* **GnmCompositorRestricted** answers. Every connection gets exactly one reply and
  then the socket is closed by the daemon (372a: a second send on the same socket
  fails).
* **A killed compositor does not come back.** After 361b sent 8 KiB to
  `GnmCompositorRestricted` and to `AgcCompositorSppSocket`, both stopped
  listening for the rest of the boot: the node files remain with mode `0xC1FF`,
  and `connect` returns `ECONNREFUSED` because nothing is listening on the inode.
  The display went black at the same time, because these two services are the
  compositing path (`362a`, `362b`, and the user's report). That is a denial of
  service reachable from an unprivileged game process; it is **not** evidence of
  memory corruption - we have an external symptom and no crash address, no
  controlled value and no reclaim.

## The compositor protocol

Each request is one message. The first two dwords are read; everything after them
in the 0x30-byte message is ignored by every command tried (370a varied dwords 2
to 11 with value 1, 371a grew the message to 0x100 bytes, and no reply moved).

```
request:   u32 size          total bytes of the message (0x30 is the minimum)
           u32 command       0 .. 6 are recognised, 7 and above are 0x80FF
           ...               ignored by commands 0-6

reply:     u32 type          always 1
           u32 flags         0x8000, 0x8100 or 0x80FF
           u32 payload_len   bytes that follow the 16-byte header
           u32 status        sony error, e.g. 0x80D40009
           payload           payload_len bytes
```

Messages shorter than 0x30 get no reply at all; 0x30 is the shortest that does
(368a: 0x20 silent, 0x30 answered).

| command | reply | payload |
|---|---|---|
| 0 | 1024 + 3920 = **4944 bytes**, `00000001 00008000 00001340 80D40009` | `0x1340` bytes, all zero except `+0x2C = 0x000000FF` |
| 1 | 16 bytes, `00000001 00008100 00000000 00000000` | none, **no error word** |
| 2, 3, 4, 5 | 16 bytes, `00000001 00008100 00000000 80D40009` | none |
| 6 | 32 bytes, `00000001 00008100 00000010 80D40009` | 16 zero bytes |
| 7 and above | 16 bytes, `00000001 000080FF 00000000 00000000` | none |

The 4944-byte reply to command 0 was only visible once the read buffer was larger
than 0x400 (373a); the earlier reads had been truncating it.

Command 1 is the only one that answers without setting `0x80D40009`, and it does
not open a session: the daemon closes the connection after it (372a).

## What the surface is not

* **No kernel access.** The commands that would carry data all answer
  `0x80D40009`, whatever is in the header. Nothing in this protocol reached a
  pointer, a length that was copied from us, or a handle we supplied.
* **No protocol oracle.** The reply is not a function of the message contents
  except for its size and its command word, so there is no field to fuzz toward a
  different answer from outside.
* **The client is not in this process, and the libraries cannot be read.** The
  eboot text region (0x494000 bytes) contains no reference to any of these socket
  names (374a), so the game we run does not talk to the compositor. The system
  libraries that would are laid out as text `p=0x4`, `.rodata` `p=0x1` and
  writable data `p=0x3` (375a), and **only `p=0x3`/`p=0x5` can be read**: a 0x100
  read at `libSceNpGameIntent.sprx` `0x4E8000` (`p=0x1`) terminates the process on
  first touch (377a), while the same read at eboot's `p=0x5` text returns `/lib`.
  The socket name therefore cannot be located, and the client's code cannot be
  disassembled, so the rest of the protocol is not recoverable from a game
  process.

## Reproduction

```bash
# what each socket does with a connection and an 8 KiB write
python tools/send_probe.py probes/phase17_new_vectors/361b_socket_consumption.lua

# the reply, and the fact that it is one per connection
python tools/send_probe.py probes/phase17_new_vectors/365a_compositor_reply.lua
python tools/send_probe.py probes/phase17_new_vectors/372a_compositor_session.lua

# the command and size map
python tools/send_probe.py probes/phase17_new_vectors/369a_compositor_header.lua
python tools/send_probe.py probes/phase17_new_vectors/373a_compositor_fullread.lua
```

Probes 361a-377a, captures in `results/phase17_new_vectors/`.
