# Unattended PS5 console control on stock 14.10 (Remote Play keyboard lane)

**Date:** 2026-10-19 · **Console:** 14.10, stock, no jailbreak · **Host:** Arch/CachyOS KDE Plasma 6 (Wayland)

## Why

The repo's swarm and probe loop need someone to physically press buttons: wake the console,
reopen the guide app, reload the page between probes, dismiss OOM dialogs. Our rig now runs the
whole browser-oracle loop with **zero human presses**: the same Remote Play surface the
`controlling.md` docs describe, driven from scripts instead of hands.

Remote Play is a **stock Sony server** — this needs no jailbreak and no firmware-specific bug.
It is a pre-existing supported surface, so it survives every firmware update.

## Architecture

```
script ──> ps5_key <key>
             │ 1. KWin DBus script: activate chiaki window (by PID)
             │ 2. uinput one-shot keyboard device: tap <key>
             ▼
        chiaki-ng (QT_QPA_PLATFORM=xcb)  ── Remote Play ──▶  PS5
             ▲                                                  │
             │ stream frames (import -window → vision/diff)    │ guide app loads lab page
             └──────────────────────────────────────────────────┘ via DNS-redirect (beacon log)
```

Verdicts come from the page's beacons, not from screenshots: screenshots are the fallback.
A deterministic click oracle (`input_probe.html`, served by the lab DNS kit) proved the loop
end-to-end: a huge auto-focused link + Cross produced `GET /document/en/ps5/PROBE_HIT` on the
server — a scripted keypress navigated the PS5 browser.

## chiaki-ng keyboard defaults (from `gui/src/settings.cpp`, `GetControllerMappingForDecoding`)

| key | button | key | button |
|---|---|---|---|
| Return | Cross | C | Triangle |
| Escape | PS | arrows | D-pad |
| Space | Options | T | touchpad press |

**Both feature flags must be added to `~/.config/Chiaki/Chiaki.conf` or keys are silently
dropped:** `keyboard_enabled=true` (and `mouse_touch_enabled=true` for pointer/touchpad).
Defaults are off; nothing in the docs says so.

## Host-side gotchas (each cost real time)

- **XTEST fake input is dead on Plasma 6 XWayland.** `xdotool key/type` reports success, the
  focused window receives nothing (verified with a canary window that logs real KeyPress
  events). KWin 6.5+ scripting has no `sendInputEvent`. Working injector: **uinput**
  (`UI_DEV_CREATE` + `UI_SET_KEYBIT` for all 256 codes, `uinput_user_dev` packed `HHHHI`,
  open `/dev/uinput` unbuffered, sleep ~1 s after create or libinput drops early events).
- **Force X11 mode** (`QT_QPA_PLATFORM=xcb`): Wayland-native windows can be neither focused
  nor injected from scripts here.
- **Focus by PID, never by caption** — the stream window title changes mid-session. KWin
  DBus: `loadScript` → `"/Scripting/Script$ID" org.kde.kwin.Script.run` (note the *no-slash*
  path format). The script sets `keepAbove` + `requestActivate` + `workspace.activeWindow` +
  `raiseWindow`; `requestActivate` alone is not enough under Plasma 6.
- **In the guide-app WebView, Cross = click at the touchpad pointer position, NOT activation
  of the DOM-focused element.** `.focus()` + Cross hits BODY. Deterministic trick: make the
  target link huge (`display:block`, 92% width) so the resting pointer (~screen center)
  already overlaps it. The touchpad pointer moves only via mouse **drag** (click alone = zero
  delta), gain ≈0.25x and nonlinear — resize the target instead of parking the pointer.
- **Guide WebView JS goes fully idle when unattended** (timers stop, last frame stays
  rendered). A 10 s heartbeat beacon distinguishes idle from dead; Triangle (key `C`) reloads
  the page. `ps5_watchdog` automates exactly that escalation, plus relaunching the headless
  stream if chiaki itself dies (a fresh stream also wakes a sleeping console via PSN).
- chiaki-ng AppImage: PSN login's embedded Chromium dies against Arch system NSS — extract,
  delete bundled `libnss3/libnssutil3/libsmime3`, run `AppRun` (see PR #36 infra notes).
- A dropped Remote Play lease (`Remote is already in use`) needs ~90 s before relaunch.

## Artifacts (`tools/console_control/`)

| file | role |
|---|---|
| `kbd.py` | one-shot uinput keyboard tap (the injector; args = X11 keysym names) |
| `kwin_focus_window_by_pid.js` | KWin scripting template, replace `CHIAKIPID` |
| `ps5_key` | focus + inject wrapper — `ps5_key return` = Cross lands on console |
| `ps5_watchdog` | 5-min loop: stale beacons → Triangle → PS-overlay dance → relaunch stream |

## Measured results on our 14.10 console (2026-10-19)

- Cross dismissed a system error dialog (frame diff 182573 AE vs 925 AE noise floor).
- Triangle reloaded the guide page (`INPUT-PROBE-LOAD` beacon 6 s after the key).
- Cross on the huge auto-focused link → `GET /document/en/ps5/PROBE_HIT` (20:21:34) —
  scripted navigation proven.
- Watchdog keeps the canary-battery heartbeat alive unattended overnight-to-date.

## Integration with the probe loop

The lab server auto-chains the guide page: empty case manifest → canary battery (heartbeat);
non-empty → fuzz-case runner (one case per page load, `/nextcase` counter, 45 s reload).
Dropping a candidate `.js` into `fuzzcases/` + manifest gets a console verdict with its own
BEFORE/SURVIVED-style beacons **within ~45 s, no human at the TV** — same semantics as the new
p164 crash oracle, driven entirely by the queue.
