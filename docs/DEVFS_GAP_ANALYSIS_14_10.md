# DEVFS gap analysis, PS5 firmware 14.10

Scope: the /dev attack surface as seen from the unprivileged game process (uid=1, euid=1, gid=1).
Sources: existing probes and captures only. No console was available when this was written, so nothing here is a new measurement; every MEASURED cell names the probe and the capture that establishes it.
Ground truth for the node set: docs/DEVFS_NAMESPACE_14_10.md (78 entries, one getdirentries(196) call, capture results/phase17_new_vectors/1070a_devfs_enum_20261104_095131.txt).

Capture shorthand used below: ID/NNNN means results/phase17_new_vectors/ID_NNNN.txt unless a phase is given. Section 7 lists every path in full.

## 1. Node table

Columns: open = open() succeeds from this process (and which modes were tried); read = read(3) attempted; write = write(4) attempted on a suitably opened fd; ioctl = which part of the 32-bit command space was walked; mmap = mmap(477) on the devfs fd; poll/kq = poll(209) or kevent(363, kqueue 362) on the devfs fd; close-then-use = fd closed then its fd number reused or a mapping/registration left live; two-fd = a second open of the same node, both fds live.

ioctl coverage codes:
- FS = full 32-bit space, 2 949 120 calls (5 directions x 10 lengths x 65536). Probes 275a/471a/471b/476a.
- G24 = 4 directions x 6 lengths x 256 groups x 256 numbers = 1 572 864 calls. Probe 288a.
- B81 = group 0x81 complete over lengths 0x000-0x7FF. Probes 280a/284a (+281a/282a/283a/285a/287a for the writes).
- 26 = the 26 fixed codes of probe 1075a.
- BLK = 8 group blocks, probe 299a (a sketch, not a sweep).
- G0 = numbers 0x00-0xFF only, probe 386a (cannot see any command that carries a type byte).
- 5E = five encrypt-service codes 0xC0104401, 0xC0184402..05, probe 360a.
- none = never called.

| node | open | read | write | ioctl | mmap | poll/kq | close-then-use | two-fd |
|---|---|---|---|---|---|---|---|---|
| null | MEASURED, fd 22 (1071a/100515) | MEASURED rv=0 (1071a) | MEASURED rv=64 (1038a/181643) | 26 (1075a) | UNTESTED | UNTESTED | UNTESTED | UNTESTED |
| zero | MEASURED fd 22 | MEASURED 256 B (1038a/181643); 1024 B in 1071a | MEASURED rv=64 | 26 | UNTESTED | UNTESTED | UNTESTED | UNTESTED |
| random | MEASURED fd 22 | MEASURED 256 B, 32 words touched | not attempted (fd was O_RDONLY, 1038a prints rdonly) | 26 | UNTESTED | UNTESTED | UNTESTED | UNTESTED |
| urandom | MEASURED fd 22 (symlink, target unmeasured) | MEASURED 256 B | not attempted (rdonly) | 26 | UNTESTED | UNTESTED | UNTESTED | UNTESTED |
| dipsw | MEASURED fd 22 | MEASURED rv=-1 (1071a) | UNTESTED | none | UNTESTED | UNTESTED | UNTESTED | UNTESTED |
| rng | MEASURED fd 22 | MEASURED rv=-1 | not attempted (rdonly) | BLK (299a) + 26 (1075a did not include rng) -> BLK only, found only 0x4004667A | UNTESTED | UNTESTED | UNTESTED | UNTESTED |
| sce_zlib | MEASURED fd 22, O_RDWR reported -1 by 298a; 360a lists it as opening O_RDWR (contradiction, see 8) | MEASURED rv=-1 | UNTESTED (fd read-only in every capture) | 26 + BLK | UNTESTED | UNTESTED | UNTESTED | UNTESTED |
| uvd_enc | MEASURED fd 22, and O_RDWR per 360a | MEASURED rv=-1 | UNTESTED | none (279a never reached it, no other sweep included it) | UNTESTED | UNTESTED | UNTESTED | UNTESTED |
| dmem0 | MEASURED fd 22 | MEASURED rv=-1 | UNTESTED (read-only fd) | FS (471a) -> 3 framework codes only | MEASURED, maps and returns live data at offset 0 (600a/204707) | UNTESTED | UNTESTED (600a unmaps before close) | UNTESTED |
| dmem1 | MEASURED fd 22 | MEASURED rv=-1 | UNTESTED | FS (476a/150014) -> 3 framework + 0x4008800A; 0x80108017 panics (478n_cmd17) | UNTESTED | UNTESTED | UNTESTED | UNTESTED |
| dmem2 | MEASURED fd 22 | MEASURED rv=-1 | UNTESTED | 26 (1075a) + 0x4008800A analysed (477a) | UNTESTED | UNTESTED | UNTESTED | UNTESTED |
| gc | MEASURED fd 22, O_RDWR | MEASURED rv=-1 | MEASURED rv=-1 (1038a/182309) | B81: 25 commands, table below | MEASURED, maps, page reads all-ones (600a) | UNTESTED | UNTESTED | UNTESTED (only dce was cross-checked with fd2) |
| dce | MEASURED fd 22 | MEASURED rv=-1 | MEASURED rv=-1 | FS (275a) -> 0x80088209 only, inert (470a) | MEASURED, mmap fails rv=-1 (600a) | MEASURED: poll(POLLIN, timeout 0) once in 470a | UNTESTED | MEASURED: fd2 cross-check in 470a |
| ajm | MEASURED fd 22 | MEASURED rv=-1 | not attempted (rdonly) | FS (476a) -> 3 framework only | UNTESTED | UNTESTED | UNTESTED | UNTESTED |
| ajmi | MEASURED fd 22 | MEASURED rv=-1 | not attempted (rdonly) | 26 + BLK (299a) -> FIONBIO only | UNTESTED | UNTESTED | UNTESTED | UNTESTED |
| gic | MEASURED fd 22 | MEASURED rv=-1 | MEASURED rv=-1 | FS (471b) -> 0xC0104701, fully analysed (docs/GIC_COMMAND_14_10.md) | UNTESTED | UNTESTED | UNTESTED | UNTESTED |
| usb | MEASURED fd 22 (288a, fallback open) | UNTESTED | UNTESTED, and O_RDWR fails (292a) so no write-capable fd has ever been obtained | G24 (288a) -> 5 hits, all framework FIO* codes | UNTESTED | UNTESTED | UNTESTED | UNTESTED |
| usbctl | MEASURED fd 22 (288a); O_RDWR -1 (292a) | MEASURED rv=-1 (1038a/182309) | not attempted (rdonly) | G24 (288a) -> 6 hits incl 0x40045594, 0x200055C9, 0x200055CA; 292a repeated them | UNTESTED | UNTESTED | UNTESTED | UNTESTED |
| ugen0.2 | MEASURED fd 22 (288a); O_RDWR -1 (292a); 360a lists it as O_RDWR (contradiction) | UNTESTED | UNTESTED. No probe in the repo writes to a ugen node (grep of probes/ for ugen + write: zero hits) | G24 + 292a + 293a argument matrix -> 19 driver commands, list below | UNTESTED | UNTESTED | UNTESTED | UNTESTED |
| ugen0.1, ugen1.1, ugen2.1 | UNTESTED, never opened by any probe | UNTESTED | UNTESTED | none | UNTESTED | UNTESTED | UNTESTED | UNTESTED |
| ugen2.2 | MEASURED open in 360a (list [B]) but the name is not in the 78-entry devfs listing | UNTESTED | UNTESTED | none | UNTESTED | UNTESTED | UNTESTED | UNTESTED |
| camera | MEASURED fd 22 (O_RDONLY) and fd 27 (O_RDWR) (298a) | MEASURED rv=-1 | MEASURED rv=-1 | dir x type x number matrix in 1076a (capture), the 768-command version only in 1077a's header (no capture), G24 in 288a, 26 codes in 1075a. Answer is EINVAL 22 for every code. | UNTESTED | UNTESTED | UNTESTED | UNTESTED |
| hid | MEASURED fd 22 | MEASURED rv=0 | MEASURED rv=-1 | 5E (360a) -> 0x803B0004; 43n sweep -> 0x80740004 for every code; G24 planned in 288a but never reached (capture truncated) | UNTESTED | UNTESTED | UNTESTED | UNTESTED |
| bt | MEASURED fd 22 | MEASURED rv=0 | MEASURED rv=-1 | none (279a and 288a both died before reaching it) | UNTESTED | UNTESTED | UNTESTED | UNTESTED |
| notification0 | MEASURED fd 22 | MEASURED rv=-1 | MEASURED rv=len for len 64..16384, rv=-1 at 65536+ (1067a/093517) | 26 (1075a) | UNTESTED | UNTESTED | UNTESTED | UNTESTED |
| notification6, notification7 | MEASURED open (360a list [B]); never opened before that | UNTESTED | UNTESTED | 5E via 360a open loop only (no per-node ioctl printed) | UNTESTED | UNTESTED | UNTESTED | UNTESTED |
| hmd_cmd, hmd_snsr, hmd_3da, hmd_dist | MEASURED fd 22, O_RDWR per 360a | MEASURED rv=-1 (1071a) | UNTESTED | 5E -> 0x81110103; G0 (386a) -> nothing | UNTESTED | UNTESTED | UNTESTED | UNTESTED |
| hmd2_cmd, hmd2_imu, hmd2_track, hmd2_leddet, hmd2_gen_data, hmd2_gaze | MEASURED fd 22 | MEASURED rv=-1 (1071a) | UNTESTED | 5E -> 0x8A721003; G0 (386a) -> nothing | UNTESTED | UNTESTED | UNTESTED | UNTESTED |
| deci_stdin | MEASURED open; read blocks forever even with O_NONBLOCK (loader had to be abandoned) | MEASURED only as a hang | UNTESTED | none | UNTESTED | UNTESTED | UNTESTED | UNTESTED |
| deci_stdout, deci_stderr, deci_tty2..14, deci_ttya0/b0/c0 | UNTESTED individually (only the family is listed) | UNTESTED (family: blocks) | UNTESTED | none | UNTESTED | UNTESTED | UNTESTED | UNTESTED |
| stdin, stdout, stderr (type 10, symlinks) | these are the loader own fds 0/1/2 | n/a | n/a | MEASURED only as the ioctl control: stdout + TIOCGWINSZ 0x40087468 -> -1, nothing filled (1076a CTL) | n/a | n/a | n/a | n/a |
| fd (ino 334, DT_DIR) | UNTESTED. Never opened, never listed through | UNTESTED | UNTESTED | none | UNTESTED | UNTESTED | UNTESTED | UNTESTED |
| mem, kmem, physmem, memctl, msr, cpuctl, pci, pcib0, smb0, iic0, spi0, gpio, bpf, audit, kaudit, klog, console, ctty, ttyv0, ttyu0, uart, ada0, da0, cd0, nvme0, mmcsd0, md0, tap0, tun0, dmass, sceKernel, scevfs, scezlib, notification1 | open() = -1 (1073a); listed-yet-refusing: ctty (ino 69), notification1 (ino 145) | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| a53mm, a53mmsys, dbggc, fttrm, duid, mp3, sbl_srv, encdec, uvd_dec, acm, lvd3 | open() = -1 with a per-node errno (1150a/1151a) | n/a | n/a | 298a and 292a confirm all-modes refusal for dbggc/sbl_srv/encdec/uvd_dec/mp3 | n/a | n/a | n/a | n/a |
| hmd2_image, hmd2_slam_trace | open() = -1, Sony 0x8A721003 (1150a/1151a) | n/a | n/a | n/a | n/a | n/a | n/a | n/a |

Count: 40 nodes open from this process (null zero random urandom dipsw rng sce_zlib uvd_enc dmem0 dmem1 dmem2 gc dce ajm ajmi gic usb usbctl ugen0.2 camera hid bt notification0 notification6 notification7 hmd_cmd hmd_snsr hmd_3da hmd_dist hmd2_cmd hmd2_imu hmd2_track hmd2_leddet hmd2_gen_data hmd2_gaze plus the deci family, ugen2.2 and the three std streams). 22 further names refuse open with a documented errno. The remainder are aliases or never tested.

### 1.1 The two command tables that had no document

/dev/gc, 25 commands, all type 0x81, all rv=0, writes measured byte-exactly in 281a/282a and reproduced in 284a/285a/287a:

| cmd | write effect |
|---|---|
| 0x40048135 | [0]=0x00000101 |
| 0x4004813A | [0]=1 |
| 0x40088137 | two zero dwords |
| 0x8004813C | no write |
| 0xC0048113 | [0]=3 |
| 0xC0048114, 0xC0048116, 0xC0048117 | no write |
| 0xC0048115, 0xC004811F, 0xC004812E, 0xC0108120 | [0]=0 |
| 0xC004811D | (hit in 279a, no write recorded) |
| 0xC0048125 | hangs the calling thread forever; the console keeps rendering, the loader accepts connections, the app fails on exit (280a returned 0 for it before 0x80888123 ran; hung in 281a, 282a, 284a) |
| 0xC0088101, 0xC0088111 | no write |
| 0xC008811B | [0]=0x80000000, [4]=0x0C |
| 0xC0088133 | [4]=0x5C |
| 0xC010810B | 0x10 at +0, +4, +8, +C |
| 0xC0108139 | zeros at +0, +8, +C |

Negative results on the same table: NULL argument -> -1 for every command (282a); no command follows a pointer in the struct (283a, buffer[0] = second page, page unchanged for all 18); 0xAA versus zeros does not change behaviour (285a/287a); every write stays inside the declared length (whole-page dumps).

/dev/ugen0.2, 19 driver commands found by 288a and confirmed by 292a/293a (24 including framework):

- _IOR-class, size 8, need a readable 8-byte argument, write nothing: 0x80045506, 0x80045565, 0x80045571, 0x80045572, 0x80045576, 0x80045577, 0x80045578, 0x8004557A, 0x8004557B, 0x8004557C (this one also needs valid content: -1 even for a zeroed page), 0x8004557D, 0x80045580, 0x80045588, 0x80045589.
- _IOW-class, size 4: 0x40045564, 0x40045575 zero the first dword; 0x40045587 writes 0x64; 0x4004558B writes 0x8000; 0x40045592 writes 1.
- Argument matrix (293a) columns NULL, unmapped pointer, zeroed page, 0xAA page: NULL and unmapped give -1 for every command (fault handling is present), zeroed and 0xAA give 0.
- /dev/usbctl carries three of the same family: 0x40045594, 0x200055C9, 0x200055CA. /dev/usb carries only framework codes.

## 2. Question 1: who got a full encoding sweep, and what the sweep varied

| probe | nodes | directions | lengths | group/number | argument page | pointer | NULL tried | output inspected |
|---|---|---|---|---|---|---|---|---|
| 275a | dce | 5: 0, 0x20000000, 0x40000000, 0x80000000, 0xC0000000 | 10: 0,4,8,0x10,0x18,0x20,0x40,0x100,0x1000 | 0..0xFFFF | zeroed 0x1000 | same every call | no | return value only |
| 471a | dmem0 | same | same | same | zeroed | same | no | return value only |
| 471b | gic | same | same | same | zeroed | same | no | return value only |
| 476a | ajm, dmem1 (encdec, uvd_dec, physhm0 refused) | same | same | same | zeroed | same | no | return value; hit rows only |
| 288a | usb, usbctl, ugen0.2, camera (hid, bt, hmd_cmd, notification0 never reached) | 4 | 6: 0,4,8,0x10,0x30,0x100 | 256x256 | painted 0xAA | same | no | return value; hits printed, page never compared |
| 279a | gc only (9 others never reached) | 4 | 5: 4,8,0x10,0x20,0x100 | 256x256 | zeroed | same | no | return value |
| 280a/284a | gc | all | 0x000..0x7FF | group 0x81 | zeroed then filled | same | no | return value |
| 281a/282a/287a | gc | the 25 | declared | group 0x81 | 0xAA, zeros, structs | same | yes (282a) | whole page dumped after every call |
| 292a/293a | ugen0.2, usbctl, usb | the found ones | declared | the found ones | 0x40 page, 4 shapes | NULL, unmapped, zeroed, 0xAA | yes | 0x40-byte dump after every call |
| 1076a (1077a unrun) | camera | 3 | size 8 then 0x10/0x20/0x40/0x100 | type 0-63, number 0-3 | painted per dword 0xA0000000+i | same | no | first two dwords compared per call |
| 1075a | 15 nodes | the 26 codes | in the literal | in the literal | painted 0xCDCDCDCD | same | no | first qword of buf0 |
| 386a | gc + 6 hmd nodes | 4 | 5 | number 0x00-0xFF only | zeroed | same | no | page checked (nothing wrote it) |
| 360a | 77 names | 3 (0xC0/0xC0/0xC0) | 0x10/0x18 in the literal | type 0x44, numbers 1-5 | painted | same | no | non-zero word count |
| 299a | sce_zlib, ajm, ajmi, rng, camera | 4 | 5 | 8 fixed blocks | zeroed | same | no | return value |

Full 32-bit space: 4 nodes (dce, dmem0, gic, ajm) and dmem1 up to the truncation point. Group 0x81 complete over the whole length field: gc. 24 of 32 bits: usb, usbctl, ugen0.2. Everything else on the table never left group 0 or was only sketched. Never swept at all, despite open() succeeding: dipsw, uvd_enc, notification0 (26 codes only), notification6, notification7, bt, hid (43n codes and 5E only), ajm (FS but only framework answered, so its own table is unsearched in practice), all 10 hmd nodes, the 19 deci nodes, ugen0.1/ugen1.1/ugen2.1, fd.

What the sweeps varied:
- The 32-bit command word: yes, in 275a/471a/471b/476a/288a/279a. Not in 386a (numbers only), 386a-style probes cannot see a command whose type byte is non-zero, which is every command this repo has ever found (0x81 gc, 0x88 dce, 0x80 dmem, 0x47 gic, 0x55 usb, 0x44 encrypt).
- The length field: yes in the FS sweeps (10 lengths) and in 284a (0x000-0x7FF); only 6 lengths in 288a; one length per command in 282a.
- The argument pointer: essentially no. Every sweep passes one fixed pointer. NULL was tried only in 282a (gc) and 293a (ugen), an unmapped pointer only in 293a. No sweep has tried an argument pointer that is kernel-range, or one that straddles a page boundary, or one whose low bits are unaligned.
- The buffer contents: zeroed in 275a/471a/471b/476a/279a/284a/299a, painted 0xAA in 288a/281a/292a, painted per dword in 1076a, sentinel dwords in 1075a. Content ladders (0, 1, 2, 0x1000, 0xFFFFFFFF, self, 0x7FFFFFFF) were done only in 470a (dce) and 293a (ugen). So for every node except dce and ugen, a command that only writes when its input is valid was invisible.
- The access mode of the fd: half the nodes only accept O_RDONLY. A driver that checks FWRITE returns EBADF before dispatch, so a write-direction command is invisible on a read-only fd. 299a/476a/279a ran on read-only fds for ajm/ajmi/sce_zlib/rng and found only FIONBIO. No probe has ever tried O_WRONLY on any node.

## 3. Question 2: was any returned buffer scanned for a copy_out

| node | scan performed | result |
|---|---|---|
| gic | 475c-475e: 0x470 bytes compared and searched for supervisor-range qwords, over a 0x4000 fill | 1131 of 1136 bytes change; head 0x00010002 + CUSA27390; status 0 or 0x816800FF; no kernel-range qword in the first 0x400. The copy is a fault-handled user copy (47-bit mask, addr+len <= 0x800000000000, recovery via gs:[0x20]+0x108, stac/clac), so the handler cannot reach kernel memory. |
| gc | 281a/282a/284a dumped the whole page after each of the 25 commands | only small constants (0x101, 1, 3, 0x80000000, 0x0C, 0x5C, 0x10, 0); no value above 32 bits; no command wrote outside its declared length |
| ugen0.2 | 292a/293a dumped 0x40 bytes after each of 19 commands | constants 0x64, 0x8000, 1; two commands zero the first dword; the 14 _IOR commands leave the 0xAA page untouched |
| camera | 1076a compared the first two dwords after every command of its matrix (the 768-command walk is 1077a, which has no capture) | every _IOR/_IOWR leaves the buffer byte-identical; every _IOW zeroes the first 8 bytes. No copy_out at all. |
| dmem1 | 477a inspected the 8-byte answer to 0x4008800A | constant 0x0000000150000000 (a 40-bit value in the GPU window, not a canonical pointer); dmem2 answers zeros; dmem0 answers -1 |
| everything else | no | the hit predicate in 275a/471a/471b/476a/279a/288a/299a was the return value; the page was never compared before and after, so a copy_out that also returned an error would be invisible |

So: one node (gic) has a real supervisor-range scan, three nodes (gc, ugen, camera) have byte-level diffs, and the rest of the corpus only ever measured return values. No sweep has ever used "count of changed bytes > 0" as its hit predicate, and no scan has ever flagged a value in the supervisor range outside gic.

## 4. Question 3: untested pairs ranked by driver-bug likelihood

| rank | untested pair | why a Sony driver plausibly breaks there | cost | what a hit looks like |
|---|---|---|---|---|
| 1 | full-space ioctl on the 20 open nodes that never saw their own type byte: hmd2_cmd, hmd_cmd, hmd_snsr, hmd_3da, hmd_dist, hmd2_imu, hmd2_track, hmd2_leddet, hmd2_gen_data, hmd2_gaze, uvd_enc, dipsw, bt, notification0, notification6, notification7, ajmi, sce_zlib, rng, ugen0.1/ugen1.1/ugen2.1 | every command this repo has found carries a non-zero type byte, and these nodes were only ever swept at group 0 (386a) or with 5-26 fixed codes (360a, 1075a). hmd2_cmd and hmd_cmd are literally named command nodes and a single fixed code (0x8A721003, 0x81110103) comes back from the hmd family, which proves a live dispatcher with a validity check. | 2.95M calls per node, hours; chunk and resume | a command that returns 0 and changes the page, or a different status word per command (a real dispatcher), or a panic (a handler that trusts its input) |
| 2 | kevent/poll registration on a devfs fd, then close (knote UAF) | zero coverage: a grep of every probe for a devfs path and a kevent call finds only the old 06_bug_hunt.lua, which registers a bare kqueue. kqueue(362)/kevent(363) work with a zero timeout (KEVENT_TIMEOUT_VARIABLE.md), EVFILT_PROC register/close is clean, but no devfs node has ever been a knote subject, and devfs d_kqfilter plus close is a classic use-after-free shape | one probe, seconds | panic on close or on the next kevent; ev.data/ev.udata holding a supervisor-range qword; a knote that fires after the fd number is reused |
| 3 | mmap a devfs fd then close, then read the mapping (mapping surviving a driver free) | 600a proves /dev/gc and /dev/dmem0 map (gc reads all-ones, dmem0 returns live GPU status data at +0), and it unmaps before close, so the close path has never been exercised while a mapping is live | one probe, seconds | post-close read returning different non-sentinel data (the page was freed and reused); a fault at a still-mapped address; a write to the mapping that changes device state |
| 4 | second open of the same node, two fds live, interleaved commands (two fds sharing driver state) | only dce was ever cross-checked with fd2 (470a, inert). /dev/gc has a command that wedges the calling thread forever (0xC0048125) which implies global state without a per-open copy; a second fd is the cheapest way to turn that hang into a double-free or a lock-order bug. gic's 0xC0104701 does a firmware round trip and would be re-entered by a second fd. | one probe, seconds | a second open that returns a distinct errno (single-open driver); fdA and fdB disagreeing on the same command; close(fdB) while a command runs on fdA causing a panic |
| 5 | write() on nodes that open write-capable but were never written: deci_stdout, deci_stderr, deci_tty2..14, deci_ttya0/b0/c0, ctty, dipsw, all 10 hmd nodes, dmem0/1/2, uvd_enc, sce_zlib, notification0 (large and crafted payloads), and the O_WRONLY gate on usb/usbctl/ugen0.2 (never tried anywhere) | write is the one operation with a length and a payload the driver must bound. notification0 already accepts 16384 bytes with rv=len and nothing observable, and the 16384-to-65536 boundary is untested (1067a). ugen write is the USB bulk transfer path, the one kernel parser that eats attacker bytes without a code-execution prerequisite. | one probe, seconds | rv != requested length (truncated copy or an internal length bug); rv == len but a later observable side effect; a driver-domain errno that depends on the payload; a panic |
| 6 | ioctl on a node after mmap, ftruncate, fsync, poll alone, double close | each is a cheap negative. ftruncate(480) on a devfs fd has never been called. poll with a zero timeout on a non-pollable node may wedge the loader (only dce was polled). ioctl-after-mmap's remaining angle is whether the driver DMAs into the mapping (283a killed the argument-as-pointer theory for gc). | one probe, seconds | any return other than ENODEV/EINVAL/-1; a page change inside the mapping; a hang from a poll that never fires |

Mapping to the six classes the request named: poll/kqfilter plus close is rank 2; mmap then close is rank 3; write() to nodes never written is rank 5; ioctl after mmap, ftruncate and double close are rank 6; second open is rank 4. Rank 1 is added because it is the largest untested block of the ioctl surface and the only one where a real dispatcher is already proven to exist.

## 5. Question 4: exact shapes for the top five

Syscall numbers used throughout: open 5, close 6, read 3, write 4, ioctl 54, fcntl 92, fstat 189, getdirentries 196, poll 209, mmap 477, munmap 73, ftruncate 480, kqueue 362, kevent 363, thr_create 430.

### 5.1 Rank 1, the unswept nodes

open(5)("/dev/hmd2_cmd", 4 = O_RDONLY|O_NONBLOCK, 0); if -1, retry flags 2 and 1.
arg = memory.alloc(0x1000) painted 0xAAAAAAAA per dword; page2 = a second 0x1000 page, also 0xAA.
for dir in {0, 0x20000000, 0x40000000, 0x80000000, 0xC0000000} x for len in {0,4,8,0x10,0x18,0x20,0x40,0x100,0x1000} x for type 0..0xFF x for num 0..0xFF: cmd = dir + len*0x10000 + type*0x100 + num; rv = ioctl(54)(fd, cmd, arg).
Per call, cheap test: rv != -1, or any dword of the page differs from 0xAAAAAAAA (compare with memory.read_dword, never tonumber on a sentinel qword).
On a hit: print cmd, rv, the first 8 dwords, the changed-dword count, then re-run the same cmd with (a) a zeroed page, (b) a NULL pointer, (c) page2's address in dword 0, (d) type/num swapped. Then close and reopen before the next hit, so state cannot carry.
Report per node: total calls, hit list with the four-shape result, and an explicit [B] total= line. 279a, 476a and 288a all lost results to a truncated capture; a resume marker plus an incremental hit print is mandatory.
Real primitive: rv == 0 with changed bytes outside the declared len; a canonical user-range pointer appearing in the output (0x0000_1000_0000_0000 to 0x0000_7FFF_FFFF_FFFF); the same cmd returning different data on the second call (a state read, i.e. leaked kernel memory); a second fd changing the answer; or the console/loader dying (a handler that trusts its input).
Just another status word: rv in the known set {-1, 22, 0x8002004E, 0x800E0001, 0x8A721003, 0x81110103, 0x803B0004, 0x80740004, 0x816800FF} with a byte-identical page.

### 5.2 Rank 2, knote UAF

kq = kqueue(362)(); fd = open("/dev/camera", 2); ev = {ident=fd, filter=EVFILT_READ(-1), flags=EV_ADD(1), fflags=0, data=0, udata=0x4141414141414141}; kevent(363)(kq, ev, 1, 0, 0, {0,0}) -> expect rv=0.
close(6)(fd); then kevent(363)(kq, 0, 0, out, 8, {0,0}) three times; then a second open to reuse the fd number; then kevent again; then close(kq).
Variants: EVFILT_VNODE with NOTE_REVOKE on /dev/gc and /dev/dmem0; 2000 register/delete cycles as in 771b; and the same from a thr_create(430) child while the parent closes.
Always pass a {0,0} timeout; a NULL timespec inside kevent blocks and wedges the single-threaded loader.
Real primitive: panic or console death on close or on the following kevent; out.data or out.udata holding a supervisor-range qword; the knote firing for an ident that is now a different file.
Status word: rv=0 on register, 0 events on poll, clean close, nothing reused.

### 5.3 Rank 3, mmap then close

fd = open("/dev/gc", 2); p = mmap(477)(0, 0x1000, 3, 1, fd, 0); if p == -1, try flags 0x1001/0x1002 as 977a did.
Snapshot 16 qwords with read_dword pairs into a local array. close(6)(fd). Snapshot the same 16 qwords again and diff dword-wise.
Then: write one dword into the mapping and read it back; call munmap(73); and the reverse order (close first, then mmap) to see the failure mode. Repeat for /dev/dmem0, which returns live data at +0.
Real primitive: the post-close snapshot differs in a non-sentinel way (the backing page was freed and reused, i.e. a read of whatever now lives there); a fault on an address that is still mapped; a write that is visible in device state.
Status word: identical snapshots and a clean munmap. Record it as a negative for that node and stop.

### 5.4 Rank 4, two fds on one node

fdA = open("/dev/gc", 2); fdB = open("/dev/gc", 2). If the second open fails, print errno via get_error_string() and stop: a single-open driver is itself the finding.
Baseline: 0xC008811B on fdA ([0]=0x80000000, [4]=0x0C), then the same on fdB, then on fdA again. Any difference between fdA and fdB is per-open state; any difference between the two fdA calls is global state.
Then the hang command: child = thr_create(430) running 0xC0048125 on fdA. Parent sleeps 2 s, calls 0xC008811B on fdB, then close(6)(fdB), then open("/dev/gc") again, then checks whether the new fd answers. Put this section last: 0xC0048125 never returns and the child thread is lost.
Same shape on /dev/gic with 0xC0104701 (arg = {addr, arg, status}) and on /dev/camera with any _IOW code.
Real primitive: fdA and fdB disagreeing; the driver refusing the second open with its own errno; a panic or a stall on close(fdB) while a command is in flight on fdA; the re-opened fd answering differently.
Status word: identical answers on both fds and a clean close.

### 5.5 Rank 5, write on write-capable nodes

Gate first, since nobody has ever tried it: for n in {usb, usbctl, ugen0.2, ajm, ajmi, rng, sce_zlib, dmem0, dmem1, dmem2, uvd_enc, dipsw, hmd_cmd, hmd2_cmd, bt, the deci family}: rv = open(5)(n, 1 = O_WRONLY, 0); print rv and, only if rv == -1, get_error_string().
Where W is obtainable: buf = 0x1000 painted 0xAA. for len in {0, 1, 8, 0x10, 0x100, 0x1000, 0x4000}: rv = write(4)(fd, buf, len); print rv, then poll(209)({POLLIN, 0}, 1, 0), then whether a second write returns the same.
Crafted payloads, notification0 only: len 16384, 16385, 20000, 32768, 65535, 65536 (1067a stops at 16384 and resumes at 65536 with -1). Then len 16384 with every qword 0x41414141, then with the address of a live mapping in dword 0, then with a 0x10 header of 0xFF.
Real primitive: rv != len (a truncated copy or an internal length check); rv == len with a later observable side effect (a read on the same node changes, a second write's rv changes, the console dies); an rv that is a driver-domain errno which changes with the payload (proves the bytes were parsed).
Status word: rv == len with nothing observable, or a uniform -1.

## 6. Free negatives, same run
- ftruncate(480) at 0 and 0x1000 on every open node. Never called on a devfs fd.
- fsync(95)/fdatasync on a devfs fd; fcntl(92) F_SETFL O_ASYNC (FIOASYNC already returns 0 on some fds); F_GETPATH.
- poll(209) with {0,0} timeout on each node (timeout 0 only; a negative timeout on a non-pollable node wedges the loader).
- close(6) twice on one fd (EBADF versus panic).
- open the same node with O_EXCL, and open /dev/fd/22 and /dev/fd/0 to learn what the fd directory node does.

## 7. Capture index

| probe | capture | establishes |
|---|---|---|
| 1070a | results/phase17_new_vectors/1070a_devfs_enum_20261104_095131.txt | the 78-entry namespace, record layout, inode/type per node |
| 1071a | results/phase17_new_vectors/1071a_devfs_full_read_20261104_100515.txt | open and read of 37 nodes, sentinel scan, 0 supervisor qwords |
| 1073a | results/phase17_new_vectors/1073a_hidden_node_open_20261104_101148.txt | 55 raw-memory and bus names fail to open; notification1/ctty listed but refuse |
| 1075a | results/phase17_new_vectors/1075a_device_ioctl_20261104_101328.txt | 15 nodes x 26 codes, camera returns 22 |
| 1076a | results/phase17_new_vectors/1076a_camera_ioctl_20261104_101408.txt | camera type-step matrix, _IOW zeroes 8 bytes |
| 1077a | no capture exists anywhere in results/ | the probe was written to walk dir x type 0-63 x number 0-3 (768 commands) and its header claims the direction bits alone select the behaviour, but there is no capture to back that claim |
| 1150a | results/phase17_new_vectors/1150a_devfs_errno_20261104_120627.txt | errno per refusing node |
| 1151a | results/phase17_new_vectors/1151a_devfs_open_modes_20261104_120816.txt | four open modes on the refusing nodes |
| 279a | results/phase17_new_vectors/279a_node_ioc_sweep_20261022_100333.txt | gc command discovery, truncated |
| 280a/281a/282a/283a/284a/285a/286a/287a | results/phase17_new_vectors/280a_gc_command_table_20261022_100852.txt and siblings | the 25-command gc table, its writes, the hang, the pointer and content negatives |
| 288a | results/phase17_new_vectors/288a_node_ioctl_groups_20261022_104212.txt | usb/usbctl/ugen0.2 command tables, camera saturation, truncated before hid |
| 292a | results/phase17_new_vectors/292a_ugen_commands_20261022_111332.txt | ugen page dumps, first look at the writes |
| 293a | results/phase17_new_vectors/293a_ugen_argument_shapes_20261022_111458.txt | NULL/unmapped/zeroed/0xAA matrix, fault handling present |
| 298a | results/phase17_new_vectors/298a_dbggc_sweep_20261022_112208.txt | two-mode open matrix, camera and rng and ajm modes |
| 299a | results/phase17_new_vectors/299a_node_ioc_sweep_20261022_113426.txt | block sweep of 5 nodes, FIONBIO only, truncated in camera |
| 360a | results/phase17_new_vectors/360a_encrypt_ioctl_matrix_20261022_175029.txt | 77-name open loop, 5-code matrix, four distinct driver status words |
| 470a | results/phase17_new_vectors/470a_dce_command_footprint_20261023_141013.txt | dce inert over 50k calls, fd2 cross-check, poll |
| 471a/471b | results/phase17_new_vectors/471a_dmem0_encoding_20261023_141216.txt, 471b_gic_encoding_20261023_141321.txt | full-space results for dmem0 and gic |
| 472a..475g | results/phase17_new_vectors/* | gic command shape, copy_out analysis, supervisor scan |
| 476a | results/phase17_new_vectors/476a_unswept_node_sweep_20261023_150014.txt | ajm and dmem1 full space; both captures truncated |
| 477a/478n/481a/482c/482g | results/phase17_new_vectors/477a_dmem1_read_command_20261023_150520.txt, 478n_cmd17_20261023_152714.txt, 481a_dmem_arg_matrix_20261023_160540.txt, 482c_mmap_window_hint_20261023_161114.txt, 482g_window_exact_placement_20261023_161809.txt | dmem1 read command, the panic command, argument matrix, mmap window |
| 600a | results/phase17_new_vectors/600a_gc_mmio_dump_20261024_204707.txt | mmap on gc, dce, dmem0 fds |
| 1038a | results/phase17_new_vectors/1038a_device_read_write_20261103_181643.txt and _182309.txt | the only write() coverage |
| 1067a | results/phase17_new_vectors/1067a_notification_write_len_20261104_093517.txt | notification0 write length ladder |

## 8. Contradictions, stale claims and traps
- ioctl 54 is not blocked. 1076a's control call reaches the tty layer and returns -1 with a clear error. docs/ATTACK_SURFACE.md:60 and docs/UNTESTED_THEORIES.md:72 still say blocked and DEAD.
- docs/CHANGELOG.md:1192 links docs/DEVICE_IOCTL_14_10.md, which does not exist. The 32-million-call campaign that produced the gc table has no document; this file carries its results in 1.1. No document anywhere records the ugen0.2 or usbctl command tables.
- The CHANGELOG summary of that campaign (one inert command on dce plus a twenty-five-command table on gc) understates the surface: 288a found 19 live driver commands on ugen0.2 and 3 on usbctl in the same week, and 360a found four distinct driver status words across 11 nodes.
- camera is rv=22 for every command, so any hit test of the form rv != -1 saturates on camera and reports millions of hits. 288a's camera block and 476a run 1 both did exactly that.
- open() mode results disagree between captures: 360a lists ugen0.2 and sce_zlib as opening O_RDWR; 292a and 298a report O_RDWR = -1 for ugen0.2 and sce_zlib. One of the two used different flags or a stale fd. Any new probe must print the flags it used and the rv per mode rather than a single merged fd.
- ugen2.2 appears in 360a's open list but is not among the 78 listed entries, and notification6/notification7 open even though DEVFS_NAMESPACE_14_10.md records them as never opened. The listing is not the whole namespace (same conclusion as 1073a's counterexample).
- 1038a prints rdonly for random, urandom, rng, usbctl, ajm, ajmi: those are EBADF on a read-only fd, not driver refusals. They must not be recorded as measured negatives for write.
- Sentinel qword 0xCDCDCDCDCDCDCDCD read through tonumber rounds above 2^53 and fabricates a changed dword. Compare with memory.read_dword.
- The loader normalises every failed syscall to -1; errno is only meaningful after rv == -1, via get_error_string().
- Probe 476b (the refuse-value shape) still has no capture; the claim that a refusal can arrive as a table {h=-1,l=-1} is untested. A new hit test must check both halves.
- A blocking read on a deci tty wedges the loader permanently; any probe that touches the tty group must issue the read from a thr_create child, and every blocking-capable call needs a zero timeout.

- Two conclusions in circulation rest on probe headers rather than captures: 1077a's 768-command camera walk has no capture file, and 476b (refuse-value shape) was never run. Treat both as claims, not measurements.

## 9. What this changes
The corpus measures the return-value surface, not the memory surface. Almost every sweep answered one question (is rv == -1) and the three places where the page was actually diffed (gic, gc, ugen) are the three places that produced usable information. Widening the command space further has lower expected value than keeping the command space fixed and changing the measurement: a changed-byte count per call, a content ladder per hit, the argument-pointer matrix, the access mode of the fd, and the operations that are not ioctl at all.
## Measured the same day: 1165a, the USB copy-out question (2026-11-04 15:29)

The gap analysis ranked "scan the bytes that come back, not the return value" as its first untested pair.
Probe `probes/phase17_new_vectors/1165a_usb_ioctl_copyout_contents.lua` ran it on the 22 commands 288a found
(capture `results/phase17_new_vectors/1165a_usb_ioctl_copyout_contents_20261104_152913.txt`, COMPLETE, 27 calls,
alive pid 80, no panic). The sentinel was 0xA5A5A5A5 dwords and the fill was proved by read-back before any call.

**The open() contradiction in section 4 is resolved: O_RDONLY works, O_RDWR does not.** Both `/dev/ugen0.2` and
`/dev/usbctl` opened read-only and returned **fd 22**. 292a/298a's `O_RDWR = -1` is a write-permission answer, not
a missing device; 360a's "O_RDWR opens" row is the wrong one.

**The 14 `_IOR-8` commands copy out nothing.** Every one returned 0 and left all 0x400 sentinel bytes untouched.
288a's "19 live driver commands on ugen0.2" were return-value artefacts: a handler that ignores its argument and
returns 0 is indistinguishable from a handler that copied 8 bytes of zeros into a zeroed page, and that is exactly
what 288a's predicate could not see. Four commands answer with errno instead of a status: 0x80045565 EPERM,
0x8004557C ENXIO, 0x80045588 / 0x80045589 EINVAL, 0x4004558B EINVAL.

**Five commands do write a dword back, and the encoding lies about the direction.** With the whole buffer at 0xA5:

| command | result | value stored at +0 |
|---|---|---|
| 0x40045564 | 0 | 0x00000000 |
| 0x40045575 | 0 | 0x00000000 |
| 0x40045587 | 0 | 0x00000064 |
| 0x40045592 | 0 | 0x00000001 |
| 0x40045594 (usbctl) | 0 | 0x00000000 |

The stored value is the kernel's, not an echo of the input (the input was 0xA5, and 0x64 also appears when the
argument pointer is moved to +0x80). So `_IOW('U', ...)` does not mean "input only" on this driver: at least these
four entry points return a scalar in their first dword. Scalar values are not pointers - 27 calls produced zero
0xFFFF8xxx-shaped qwords - so the USB stack is not a leak channel.

Consequences for the rest of this document: finding #1 is reduced from "two undocumented command tables" to
"four scalar getters", finding #4's copy-out question is answered **for the USB nodes only** (the camera, gic and gc
rows are still whatever the earlier sweeps say), and the twenty-node full-space sweep it proposed as pair (1) is now
lower value: the one node family with real copy-out candidates answers with scalars.

## 11. The cdevsw tables are not in the dumps (2026-11-04)

The obvious way to convert "unknown driver internals" into "known handlers" is to enumerate `cdevsw`:
each entry holds `d_name` and the eight method pointers, so a data-dump scan would hand us the real
`d_ioctl` body for `dmem0`, `ajm*`, `dce*`, `/dev/gc`, `usbctl`, `ugen*` - the nodes we can actually open -
and let us read the command gates instead of guessing them (the 674 lesson: a blind command sweep misses
any command that checks a magic field).

**It does not work. Measured three ways against `docs/dumps_13.60/`:**

1. **No name-pointer references.** `cdevsw.d_name` is a `const char *`. Taking every ASCII string in
   `kernel_data.bin` that starts with a device prefix (`dmem`, `ajm`, `dce`, `gc`, `usb`, `acm`, `ugen`,
   `mp3`, `sbl`, `encdec`, `lvd`, `fttrm`, `duid`, `dbggc`, `a53` - **1,295 strings**) and searching the
   whole 4 MB data dump for a little-endian qword equal to any of their VAs finds **0 references**.
2. **No cdevsw-shaped structs.** Generic scan: for every 8-aligned offset, take the qword as a candidate
   `d_name`, require it to point at a 1-28 character `[a-z][a-z0-9_./-]*` string inside the data dump, and
   require at least 4 of the next 7 qwords to point into kernel text. **0 candidates.**
3. **The data dump has almost no pointers at all.** Only **2 qwords out of 524,287** land in the text
   range (`0.0004%`), and both are the same 40-byte blob at `0xffffffff8bab7df0` and `0xffffffff8bbfe460`
   holding `0xffffffff8b3b2b47`; that address is mid-instruction in an AVX routine and the surrounding
   bytes are high-bit obfuscated text, so both are coincidences, not tables.

So `kernel_data.bin` is a **strings/rodata** capture, not the `.data` section: the CDev tables, the
`make_dev` chains and every driver method vector live in memory that was never dumped.

**What the 2,113 rip-relative references to device-name strings actually are.** Scanning all of kernel
text for `[rip+disp]` operands whose target is one of those strings yields 2,113 hits, but they resolve
overwhelmingly to log prefixes: `dce-otg` 126, `dce-ft` 74, `dce-dpp` 44, `ajm` 83, `acm` 29 - format
strings passed to a print helper, not names passed to `make_dev` (which would be a single reference per
node). The one non-log hit is `0x27cdab lea r8,[rip+...]` -> the literal `dce_otg_ioctl_setmode_st`,
i.e. an assertion tag naming an ioctl entry point that the dump cannot resolve further.

**Consequence for the plan.** Driver entry points are not reachable from static data. Any further work on
`dmem0`/`ajm`/`dce`/`gc` has to be behavioural, and the highest-value behavioural shape is no longer
"more command numbers" (2.9 M ioctls already landmarks the space) but **magic-gated commands**: the 674
result shows a handler whose entire body is unreachable until one struct field equals `0x40000000`. A
sweep that varies one dword across each command, at a small fixed argv, is the only way to find those
without the handler bodies.
