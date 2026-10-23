# The gic command: a firmware round-trip, not a kernel window

Status: measured on 14.10 on 2026-10-23, and cross-read against the 13.60 text
dump. Captures under `results/phase17_new_vectors/470*`-`475*`; the handler
disassembly is reproducible with `docs/dumps_13.60/kernel_text.bin`.

## What the command is

`/dev/gic` owns exactly one driver ioctl in the whole 32-bit encoding space
(471b): `0xC0104701` = `_IOWR('G', 1, 0x10)`, 16 bytes in and out. The three
other returns (`0x20006601`, `0x20006602`, `0x4004667A`) are framework commands
that answer on every device node; the dce node's `0x80088209` changes nothing at
all (470a: 0 flips in 50k calls, every fd property identical across seven content
steps).

## The 16-byte argument (472a, corrected by 475b/475c)

| bytes | meaning |
|---|---|
| `+0x0` | q0, a 64-bit address |
| `+0x8` | q1, a 32-bit value |
| `+0xC` | status, written by the handler |

Earlier probes read `+0x4` as a "class word". It is not: it is bits 32-63 of q0,
because the field at `+0x0` is a `u64`. Our own page `0x31115C020` reports `3`,
the game text `0x1f830000` reports `0`, `0x1d02c8000` reports `1` — every row of
the old table follows from the pointer's high half and none of it is a
classification. The command is not a classifier.

The status field is written by the handler and takes two values: `0`, or
`0x816800FF` when the kernel's copy of the 0x470-byte buffer fails.

## What the handler does (13.60 text 0xab80e0)

`0xC0104701` appears once in the dump, as an immediate at `0xab811d` inside this
function:

```
0ab80ed  sub  rsp, 0x488                  ; 0x470-byte stack buffer
0ab8145  call bzero(buf, 0x470)
0ab816c  mov  rdi, q0
0ab816f  lea  rsi, [rbp-0x4a0]            ; buf
0ab8176  call 0x259280                    ; copyin(q0 -> buf, 0x470)
0ab8184  jne  fail -> status 0x816800FF
0ab8191  mov  word [buf], 1               ; version low half
0ab81b6  call memcpy(buf+4, src, 10)      ; title id, 10 bytes
0ab81c8  call 0x566bd0(flag<<16, q1, buf) ; firmware request
0ab81fa  call 0x2591d0                    ; copyout(buf -> q0, 0x470)
0ab8208  status = result ? 0x816800FF : 0
0ab8212  mov  [data+0xc], status
```

The privilege test at `0xab810b` reads bit 62 of a credential word reached
through the thread pointer and turns it into the high half of the request's
first field (`flag<<16`); a game process sends the same request with zero there.

`0x259280` and `0x2591d0` are the kernel's ordinary fault-handled user copies:
both validate `addr + len <= 0x800000000000`, mask the address to 47 bits, set a
recovery address at `gs:[0x20]+0x108`, and bracket the `rep movs` with
`stac`/`clac`. A bad address returns `0xE`, not a fault. That is the whole of
the address validation for this command.

### The firmware request (0x566bd0 -> 0x563fd0)

```
0x563fd0(ctx, flags, arg1, buf):
    bounce = malloc(0x4000)
    memcpy(bounce, buf, 0x470)            ; our data, with the header patched in
    request = { type = 2, flags, arg1,
                in  = bus_addr(bounce),
                out = bus_addr(bounce) + 0x470 }
    if (0x5a4610(ctx, &request) == 0 && request.status == 0)
        memcpy(buf, bounce + 0x470, 0x470)
```

So the command ships 0x470 bytes of caller data plus the running title id to a
firmware service and copies the 0x470-byte answer back. `0x563eb0` opens the
service by name, `0x563ee0` closes it, and a mutex around the whole call makes
it serial.

## What the answer contains (475c, 475d, 475e)

The write is a fixed 0x470 bytes at q0 — measured over an 0x4000-byte fill at
eleven different q1 values and seven different third dwords, always first `+0x0`
and last `+0x46F`, about 1130 of 1136 bytes changed (the remainder are device
bytes that happen to match the fill). The head is stable:

| offset | bytes |
|---|---|
| `+0x00` | `02 00 01 00` (a `u32` 0x00010002; the handler only writes the low `u16`) |
| `+0x04` | `43 55 53 41 32 37 33 39 30 00` = `"CUSA27390\0"`, the running title |
| `+0x10` .. `+0x46F` | different on every call, no visible structure |

The unchanged bytes are not an echo of the input: the answer replaced a page
filled with `C0FFEE00`, and the same call on a page filled with `11112222`
produced a different tail again. The tail is whatever the service returns; it is
not caller-controlled and it carried no kernel-range qword in the first 0x400
bytes of any sample (475d section E).

## The "lethal address", corrected

473e/473f fed the map's eboot record — `0xf0000000`, prot `0x3` — as q0 and the
game died, taking its loader with it; TCP to the console timed out rather than
refusing for about a minute before resetting.

475f and 475g show what that address is. It reads as zeros, a userland
`write_dword` there stores and reads back (`CAFEBABF`), and writing the identical
zeros back changes nothing. It is ordinary writable user memory holding the
game's zero-filled image data, not a kernel pointer and not a device window. The
command's copy would put 0x470 bytes of service output into it — that is the
probe overwriting the running game's own data, and the game dies of the damage.
The earlier reading of the call as a handler fault is withdrawn.

The remaining unknown is why the process teardown also stalls the console's TCP
service for about a minute; that is the crash reporter, not this handler.

## Open questions

- Does the service keep any state between calls? The answer differs per call and
  the mutex serialises, but nothing distinguishes a fresh nonce from cached data.
- Is the answer an encrypted or authenticated form of the request? The title id
  comes back in plaintext at `+0x4` while the rest does not, which fits a
  signature or MAC over the record rather than an echo.
- What does the service make of the caller's 0x470 bytes? The handler patches
  only 14 of them, so all but the header reach it as the game wrote them.
