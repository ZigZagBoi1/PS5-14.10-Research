# PS5 V13.60 Final Kernel Dumper

Dumps all remaining kernel data from a jailbroken V13.60 PS5.

## What It Grabs

| Region | Size | What |
|--------|------|------|
| `data_gap.bin` | ~3.2 MB | Kernel .data between .text end and previous dump start |
| `data_extended.bin` | 4 MB | Continuation past previous kernel_data.bin |
| `handler_full_NNN.bin` | 16 KB each | Full 16KB dump of each Sony syscall handler (was 4KB) |
| `proc_match_N.bin` | 8 KB each | Kernel proc structures found via PID scan |

## Prerequisites

1. PS5 on firmware **13.60**
2. **Relapse** jailbreak applied (kernel R/W)
3. **Byepervisor** applied (HV bypass)
4. **elfldr** running on PS5 (port 9021)
5. **PS5 Payload Dev SDK** installed on your laptop

## Build

```bash
export PS5SDK=/path/to/ps5-payload-dev/sdk
cd tools/v1360-dumper
make
```

This produces `ps5-final-dumper.elf`.

## Install & Run

### Step 1: Start the receiver on your laptop

```bash
cd /path/to/PS5-14.10-Research
python3 tools/v1360-dumper/receiver.py --output-dir docs/dumps_13.60
```

It will print "Waiting for PS5 connection..." and listen on port 8888.

### Step 2: Send the payload to the PS5

Open a second terminal:

```bash
# Make sure your PS5 is jailbroken (Relapse + Byepervisor)
# elfldr should be running on port 9021

nc 10.0.0.30 9021 < tools/v1360-dumper/ps5-final-dumper.elf
```

Or if you have the elfldr sender tool:

```bash
elfldr-send 10.0.0.30 tools/v1360-dumper/ps5-final-dumper.elf
```

### Step 3: Watch the receiver

The receiver prints progress for each region as it arrives. Total transfer
is ~10-12 MB and takes about 3-5 minutes (100ms delay between 16KB chunks).

When you see `[DONE] All regions received.`, everything is saved.

### Step 4: Commit the dumps

```bash
cd /path/to/PS5-14.10-Research
git add docs/dumps_13.60/
git commit -m "Add final V13.60 kernel dumps — data gap, extended data, full handlers, proc structs"
git push
```

## If the PS5 IP or laptop IP changed

Edit `main.c` line 15-16:

```c
#define RECEIVER_IP   "10.0.0.231"   // your laptop IP
#define RECEIVER_PORT 8888
```

Rebuild with `make clean && make`.

## Troubleshooting

- **Connection refused on 9021**: Relapse + Byepervisor not applied, or elfldr not running. Re-jailbreak from the browser.
- **Connection refused on 8888**: Receiver not running. Start it first.
- **Payload crashes PS5**: The 100ms delay between reads is conservative. If it still crashes, increase `READ_DELAY_US` in main.c to 200000 (200ms).
- **Zero-filled chunks in failmap**: Some kernel pages may be unmapped. Check the failmap — a few zeros at region boundaries is normal.
