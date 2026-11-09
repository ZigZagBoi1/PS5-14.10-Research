# AFK Remote Control Setup (chiaki-ng → PS5)

Goal: full control of the PS5 from this PC (see screen + press controls) so the loader-restart workflow never requires being at the console again.

## Why chiaki-ng
- Streams the PS5 screen to this PC with full input (gamepad or keyboard-mapped buttons)
- Can wake the PS5 from rest mode over the network
- Official PS Remote Play (already installed, v9.5.0.08040) is the fallback, but it requires a real gamepad and cannot map keys — chiaki-ng is the AFK-automation client.

## One-time console step (~5 minutes at the TV, unavoidable once)
Remote Play pairing requires being at the console exactly once. After that, everything is remote.

1. **Relaunch Hamidashi Creative** — press PS button, close the game if running, reopen it. Wait for the black screen + "lua loader is loaded" notification (port 9026 back up).
2. **Turn OFF auto-updates (CRITICAL — protects fw 14.10):** Settings → System → System Software → System Software Update and Settings → turn OFF "Download update files automatically" AND "Install update files automatically".
3. **Enable wake-from-network:** Settings → System → Power Saving → Features Available in Rest Mode → "Enable Turning On PS5 from Network" = ON, and "Keep Connected to the Internet" = ON.
4. **Get the pairing PIN:** Settings → System → Remote Play → Link Device → 8-digit code.
5. On the PC: launch chiaki-ng → log in to your PSN account when prompted (your credentials, entered by you) → Register this PS5 → enter the PIN from step 4.
6. chiaki-ng Settings → Controller/Key mapping → enable keyboard bindings (defaults work; adjust to taste). Optionally set the console for direct connection to 10.0.0.96.

## After setup — the AFK loop
- **Loader dies during a probe** - usually nothing needs doing: a kill takes the process and the game restarts it about nine seconds later (pid 292 -> 299 after an absent-slot call, nothing touched on the console). The relaunch below is only for the case where the port stays refused for more than a minute:
  1. Watchdog flags it (or a probe returns 0 bytes / port 9026 refuses).
  2. Open chiaki-ng → connect to PS5.
  3. PS button → close game → reopen Hamidashi Creative → wait for "lua loader is loaded".
  4. Resume the probe queue - or let it resume itself: both drivers take
     `--wait-for-loader SECONDS`, which polls port 9026 (sending nothing) until the game is
     back and then retries the probe that died, so the relaunch is the only manual step and it
     can happen minutes later.
- The screen stays visible from the PC the whole time — no TV, no couch trips.
- chiaki-ng ships a CLI (cli/ folder in its repo) — if it exposes session launch programmatically, the relaunch itself can be keystroke-scripted later.

## Install (PC)
Preferred: portable zip from https://github.com/chiaki-ng/chiaki-ng/releases (v1.10.0 or newer, "portable" Windows asset), extracted to a local folder — no admin needed. Fallback: winget install --id=StreetPea.chiaki-ng -e (may require permission approval).
