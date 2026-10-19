# 14.10 Guide Browser — Exact Entry Infrastructure + Fuzz-Case Runner

Companion to `WEBKIT_STAGE1_1410_LIVE_TEST_2026-10-19.md` (PR #32) and
`WEBKIT_BATTERY_1410_2026-10-19.md` (PR #33). This doc captures the
**operational details** needed to reproduce the DNS-redirect browser entry on
14.10, because the generic "point DNS at a server" recipe from the
`guides.playstation.com` era no longer works on 14.10.

All facts below were observed live on a retail 14.10 console (wired, firmware
`14.10.00.00`) against a LAN host running dnsmasq + a self-signed HTTPS server.

## 1. Exact domains (the part that broke the old recipe)

On 14.10 the User's Guide app does **not** touch `guides.playstation.com`
(that domain is stale — hijacking it produces nothing). Observed query order:

| Order | Domain | Role |
|-------|--------|------|
| 1 | `envelope*.np.dl.playstation.net` | envelope/config fetch (leave un-hijacked) |
| 2 | `manuals.playstation.net` | guide content (`/document/<lang>/ps5/...`) |
| 3 | `ps5.np.playstation.net` | guide app **shell** — this is the one that hosts the WebView |

**Hijack `ps5.np.playstation.net` and `manuals.playstation.net` (A record → your host).**
Serving the shell domain is what gets you arbitrary JS execution.

## 2. TLS / cert flow

- Self-signed cert is accepted after an on-screen warning. Include SANs for
  **both** domains (plus `*.np.playstation.net` wildcard helps).
- Warning presents **Yes / No / Display Certificate** — Yes proceeds to the page.
- No certificate pinning observed on this path.

## 3. App caching behavior (where people lose hours)

- The guide app caches DNS **and** page content aggressively. A page refresh
  (Circle → X, not Triangle) often re-serves the cached page with **zero new
  requests** hitting your server.
- Reliable reload: fully close the guide app and reopen; if DNS changed,
  **Restart System** (not rest mode) is the dependable reset.
- PS5 keeps **separate DNS settings per wired/Wi-Fi profile** — set it on the
  profile actually in use.
- If IPv6 is on and automatic, router-advertised IPv6 DNS can bypass the manual
  IPv4 DNS entirely. Turn IPv6 off while experimenting.

## 4. Server-side path quirk

The shell requests assets under a nested prefix, e.g.
`GET /document/en/ps5/src/firmware.js`. A server that only serves `/src/...`
404s every JS module and the page renders black. Strip the
`/document/<lang>/ps5/` prefix (or mirror the tree) before resolving files.

## 5. Verified UA string

```
Mozilla/5.0 (PlayStation; PlayStation 5/14.10) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15
```

## 6. Fuzz-case runner (new artifact, `tools/browser_runner/fuzz.html`)

A page that fetches `fuzzcases/manifest.json` (array of `.js` filenames),
`eval()`s each case sequentially, and beacons `start` / `survived` / `threw`
per case plus `FUZZ-RUNNER-DONE`. Served as the default guide path whenever the
manifest is non-empty, so **one guide-open = one batch of crash cases tested on
real 14.10 hardware**, results in the server log.

**Offer:** this console can act as a crash oracle for the repo. Drop any
candidate JS case (fuzz output, hand-written repro, a variant of p142-style
grooming) into a PR/issue and it can be run on-device the same day — survives /
throws / hangs / reboots is exactly the signal fuzzers cannot get off-host.

## 7. Implications for off-host JSC fuzzing (learned the hard way)

- Per `WEBKIT_FINDINGS.md`, the 14.10 engine runs with **JIT disabled
  (LLInt only)**. A JIT-centric Fuzzilli profile mostly explores code that
  never executes on-console — run with JIT-off/no-jit settings or filter
  candidates accordingly.
- Source match is a **late-2023 WebKit branch** (Safari 17.0-era). Crashes
  found on 2026-era trunk frequently involve APIs/semantics that do not exist
  on-console (our first Fuzzilli find — growable-ArrayBuffer options — is
  exactly this class). Era-correct trees or on-console filtering are mandatory;
  trunk-only crash counts are vanity metrics for this target.
