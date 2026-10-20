# Userland Entry — PS5 14.10

How we get code execution on firmware 14.10.

## The Game

**Hamidashi Creative** (はみだしクリエイティブ) by Madosoft — a Japanese visual novel running on the **Artemis engine**. The Artemis engine embeds a Lua interpreter, which is the key to everything.

Available as a free demo on the Japanese PSN store.

### How We Know It's Hamidashi Creative

The `/savedata0/offsets.lua` file contains gadget tables for 14 supported Artemis-engine games. Each game has different ROP gadget offsets in its eboot. Our observed stack pivot (`pop rsp; ret`) is at eboot+0x9A2 — an exact match for the `hamidashi_creative` entry and no other game:

```lua
hamidashi_creative = {
    gadgets = {
        ["pop rsp; ret"] = 0x9a2,   -- <-- matches our observed pivot
        ["pop rax; ret"] = 0x992,
        ["pop r8; ret"]  = 0x991,
        ["ret"]          = 0x42,
        ...
    }
}
```

### Supported Games

All are Japanese visual novels using the Artemis engine with embedded Lua:

| Game | eboot ID | Notes |
|------|----------|-------|
| RaspberryCube | 0xbb0 | |
| Aibeya | 0xb90 | |
| Aikagi2 | 0x170 | Family [F] |
| **HamidashiCreative** | **0x420** | **Our target** |
| AikagiKimiIsshoniPack | 0x5d0 | |
| C | 0x280 | |
| WinterGuest | 0x600 | |
| IxSHETell | 0xd80 | |
| NoraPrincess | 0x660 | CUSA13303 |
| JinkiResurrection | 0xb10 | CUSA25179 |
| FuyuKiss | 0x410 | |
| NoraPrincess2 | 0x2e0 | CUSA13586 |
| SnowDrop | 0x070 | CUSA14324 |
| Mikagami | 0x560 | CUSA11481 |

Game identification works by checking the last nibble of `luaB_auxwrap` in the eboot. A CRC32 tiebreaker on the first 0xFF bytes of libc resolves clashes between games with identical eboots.

## The Save File Chain

```
PS5 (play game, create save)
  → USB (export save — note your hex Account ID from the save folder)
    → Jailbroken PS4 (activate profile with MATCHING Account ID via Apollo)
      → Import save under matched profile, decrypt with Apollo
        → USB (move decrypted save to PC)
          → PC (embed Lua loader into save data)
        → USB (move modified save back)
      → Jailbroken PS4 (re-encrypt save under matched profile)
    → USB (export encrypted save)
  → PS5 (import save, load game)
    → Artemis engine loads Lua from save
      → TCP listener on port 9026
```

### Step by Step

1. Download the game on PS5 via a Japanese PSN account
2. Play for ~5 minutes to generate a save file
3. Copy the save from PS5 to USB
4. Move the USB to a jailbroken PS4
5. Import the save into the PS4, decrypt it
6. Move the decrypted save to PC via USB
7. In the decrypted save folder, delete everything except `sce_sys/`, then copy the payload files into that folder
8. Move the modified save back to the PS4
9. Re-encrypt the save on the jailbroken PS4
10. Export the encrypted save to USB
11. Move the USB back to the PS5 and import the save
12. Load the game — black screen, then the notification `remote lua loader` / `running on <ip>` / `listening on <ip>:9026`

The game stays on a black screen while the loader runs. The Lua loader listens on TCP 9026 and accepts probe scripts.

## The Loader

Based on [n0llptr/remote_lua_loader](https://github.com/n0llptr/remote_lua_loader) — the repository moved from `shahrilnet/remote_lua_loader`, and the old URL redirects.

The loader provides:
- **`memory.*` API** — read/write arbitrary process memory (`read_byte`, `read_dword`, `read_qword`, `write_*`, `alloc`)
- **`syscall.*` API** — invoke syscalls via `syscall.resolve()` (filtered) or `make_syscall(N)` (unfiltered)
- **ROP chain** — 0x300-byte structure with function target (`fn_addr`), 6 argument slots, and stack pivot
- **TCP protocol** — 8-byte little-endian length prefix + raw Lua source

### Key Loader Files (in /savedata0/)

| File | Purpose |
|------|---------|
| `inject.iet` | Artemis IET script that runs `e:include("/savedata0/main.lua")`; this is what starts the loader |
| `main.lua` | Entry point, TCP listener, `remote_lua_loader` function |
| `syscall.lua` | Syscall resolve/dispatch, `make_syscall` constructor |
| `kernel.lua` | Kernel R/W primitives (IPv6 pktopts overlap technique) |
| `offsets.lua` | Per-game gadget tables, game identification |
| `kernel_offset.lua` | Kernel symbol offsets per firmware (1.00–10.01) |
| `misc.lua` | Utilities, coroutine wrapper |
| `memory.lua` | Memory read/write API |
| `rop.lua` | ROP chain builder |
| `native.lua` | Native command table and dispatch entries |
| `uint64.lua` | 64-bit integer class (Lua 5.1 has no integer type) |
| `bit32.lua` | Bitwise operations library for Lua 5.1 |
| `struct.lua` | Binary struct packing (lua-struct) |
| `hash.lua` | Checksum helpers |
| `globals.lua` | Page size constants (`0x4000` PS5, `0x1000` physical) |
| `gpu.lua` | GPU access helpers |
| `thread.lua` | Thread class |
| `signal.lua` | Signal handler registration |
| `lua.lua` | Lua class helpers |
| `kernel_patches_ps4.lua` | PS4 kernel patch set |
| `elfldr.elf`, `ps5-elfldr.elf` | ELF payload loaders for PS4 and PS5 |
| `ps5-kexp.bin` | PS5 kernel exploit blob |
| `saveg.dat` | The game's original save data |

Copy every file in the payload directory, not just the Lua sources: `main.lua` requires the helpers above, and the two loaders are what the kernel-side probes reach for once a connection is accepted.

### Stack Trace

```
/savedata0/misc.lua:92: in function 'run_with_coroutine'
/savedata0/main.lua:85: in function 'run_lua_code'
/savedata0/main.lua:216: in function 'remote_lua_loader'
/savedata0/main.lua:315: in function 'run_loader'
```

## Kernel Offsets

Kernel symbol offsets are from [@hammer-83](https://github.com/hammer-83)'s [ps5-jar-loader](https://github.com/hammer-83/ps5-jar-loader) project.

**Current coverage:** firmware 1.00 through 10.01 only.

**We do NOT have offsets for firmware 14.10.** Once we defeat KASLR, we'll need to discover them. The existing `kernel.lua` has the IPv6 pktopts overlap technique for kernel R/W, but it needs valid kernel base + symbol offsets to work.

## Sandbox Context

The game process runs in a **PS4-compatibility sandbox** (backwards compatibility mode). This may differ from the native PS5 app sandbox:
- Some syscalls might be more permissive (PS4 compat layer)
- Some kernel surfaces might be restricted differently
- The `make_syscall()` bypass works because the sandbox filter is in the Lua `syscall.resolve()` function, not in the kernel

## Per-Connection ASLR

Every TCP connection to port 9026 spawns a **fresh process** with a completely new address space. This means:
- All addresses must be re-derived every run
- No state persists between connections
- Module bases change (use `dynlib_get_info` syscall 593 to leak them)
- Heap layout changes (use GPU mmap anchor + relative offsets)
- The `0x9FE5` prefix in `fn_addr` is constant across sessions (reduced ASLR entropy)

## Setup Guide

### What You Need

- PS5 on **firmware 14.10** (will NOT work on other firmware versions)
- USB drive (FAT32 or exFAT)
- Jailbroken PS4 (for save file encryption/decryption)
- Japanese PSN account (for downloading the game)
- PC on the same LAN as the PS5 (for sending probes)
- Python 3.6+ (for `send_probe.py`) or PowerShell (for `send_probe.ps1`)

### Step 1: Get the Game

1. Create a Japanese PSN account if you don't have one (set region to Japan during signup)
2. Log into the Japanese PSN store on your PS5
3. Search for **Hamidashi Creative** (はみだしクリエイティブ) — download the free demo
4. Any of the other Artemis-engine games in the supported list above will also work, but Hamidashi Creative is the one this research was built on

### Step 2: Create a Save File

1. Launch the game
2. Play through enough to trigger an auto-save or manual save (~5 minutes)
3. You now have a save file on the PS5

### Step 3: Match the PSN Account ID (CRITICAL)

The PS5 ties save files to your **PSN Account ID** — a 16-character hex identifier (e.g. `abcdef0123456789`). If the account ID on the PS4 doesn't match the one on your PS5's Japanese PSN account, the PS5 will reject the save on import.

**How to find your Account ID:**
1. On the PS5, back up any save from the Japanese account to USB
2. On a PC, look at the exported save folder structure — one of the directory names is the hex Account ID
3. Alternatively, open the `PARAM.SFO` file from any exported save and look for the `ACCOUNT_ID` field

**How to set the same ID on the PS4:**
1. On your jailbroken PS4, install [Apollo Save Tool](https://github.com/bucanero/apollo-ps4)
2. Use Apollo to **offline activate** a user profile with your Japanese PSN Account ID
3. This creates a PS4 user with the matching account ID so saves transfer cleanly
4. All save file operations (decrypt, modify, re-encrypt) must happen under this matched profile

Without this step, the PS5 will see the save as coming from a different account and refuse to import it.

### Step 4: Prepare the Payload

1. Copy the save from PS5 to USB (`Settings → Saved Data → USB Drive`)
2. Move the USB to your **jailbroken PS4**
3. Import the save into the PS4 (under the Apollo-activated profile with matching Account ID)
4. Decrypt the save using Apollo Save Tool or similar
5. Move the decrypted save to your PC via USB
6. Embed the Lua loader into the save data (the loader files go in the save's data — `main.lua`, `syscall.lua`, `kernel.lua`, `offsets.lua`, `kernel_offset.lua`, `misc.lua`, `memory.lua`, `rop.lua`)
7. The base loader is from [shahrilnet/remote_lua_loader](https://github.com/shahrilnet/remote_lua_loader)

### Step 5: Re-encrypt and Load

1. Move the modified save back to the PS4
2. Re-encrypt the save using Apollo Save Tool (under the matched profile)
3. Export the encrypted save to USB
4. Move the USB to the PS5
5. Import the save (`Settings → Saved Data → USB Drive`)
6. Launch Hamidashi Creative
7. The screen goes black, then the notification appears: **"remote lua loader"**, `running on <ip>`, `listening on <your-ps5-ip>:9026`

### Step 5: Send Probes

Your PS5 is now listening for Lua scripts on TCP 9026. From your PC on the same LAN:

```bash
# Python (recommended)
PYTHONIOENCODING=utf-8 python tools/send_probe.py --save probes/phase10_untested_theories/43o_afroute_kaslr.lua

# Custom IP/port (if different from default 10.0.0.96:9026)
python tools/send_probe.py --ip <ps5-ip> --port 9026 --save probes/phase10_untested_theories/43o_afroute_kaslr.lua

# PowerShell (no Python required)
.\tools\send_probe.ps1 probes\phase10_untested_theories\43o_afroute_kaslr.lua -Save
```

Results are saved to `results/<phase>/<probe_name>_<timestamp>.txt`.

### TCP Protocol

The loader uses a simple protocol:
1. Connect to `<ps5-ip>:9026` via TCP
2. Send an **8-byte little-endian uint64** containing the Lua source length
3. Send the raw Lua source (UTF-8)
4. Read the response (probe output via `print()` statements)
5. Connection closes when the probe finishes

Each connection spawns a fresh process, so there's no state between probes. The 30-second socket timeout is per-read, not total — long probes should print progress to keep the connection alive.

### Troubleshooting

| Problem | Fix |
|---------|-----|
| Can't connect to port 9026 | Make sure the game is running and the loader notification appeared. PS5 and PC must be on the same LAN. |
| Connection resets immediately | The loader process crashed on the previous probe. Relaunch the game. |
| Timeout with no output | The capture may have stopped because of a process exit, Lua error, connection loss, or capture timeout. A timeout alone does not identify the cause. Check the last `BEFORE` marker and corroborate with console-side evidence. |
| The "remote lua loader" notification doesn't appear | Save file wasn't modified correctly, or encryption failed. Re-do the save prep steps. |
| PS5 won't import the save | **Account ID mismatch.** The PS4 profile must have the same PSN Account ID as the PS5 Japanese account. Use Apollo to offline-activate with the correct hex ID. |
| Save imports but game crashes on load | Save data corruption during modify or re-encrypt. Start fresh from a clean save. |
| Wrong game / different gadget offsets | The offsets.lua auto-detects the game via eboot fingerprint. Check that your game is in the supported list. |
