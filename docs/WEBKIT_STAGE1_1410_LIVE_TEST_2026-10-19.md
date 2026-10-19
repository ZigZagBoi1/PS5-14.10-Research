# Live test: Relapse WebKit stage-1 on FW 14.10 — scope-leak bug is DEAD

**Date:** 2026-10-19
**Console:** retail PS5, FW **14.10** (`PlayStation 5/14.10`), US
**Tested by:** cobrajet302gt + Hermes agent, self-hosted DNS/HTTPS kit
**Verdict:** the JSC scope-leak primitive that opens Relapse's browser stage **no longer fires on 14.10**. Stage-1 is dead at its very first step, deterministically (54/54 attempts). This is offset-independent — the failing check is pure JavaScript semantics.

## Method (reproducible, free)

1. Home LAN box (192.168.50.169) running dnsmasq + a catch-all HTTPS server with a self-signed cert.
2. PS5 wired, **manual DNS → our box** (note: PS5 keeps *separate* DNS per wired/Wi-Fi profile; also disable Automatic IPv6 or the router's IPv6 DNS wins).
3. **Key finding: on 14.10 the User's Guide app loads `ps5.np.playstation.net` (app shell) and `manuals.playstation.net` (content). NOT `guides.playstation.com`** — community instructions naming the old domain are stale for 14.10.
4. Guide app is a WebKit web app: it shows a **Yes/No certificate warning** (Yes = proceed), then executes arbitrary unsigned JS from our server.
5. Relapse exploit page served with `offsets/14.10.js` = verbatim copy of `offsets/13.60.js`; page instrumented so every `writeLog`/error also `fetch`-beacons to the server (progress survives even if the view dies).

## Raw beacon log (server-side, verbatim excerpts)

```
[+] Agent: Mozilla/5.0 (PlayStation; PlayStation 5/14.10) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15
[+] Firmware: 14.10
[*] Starting WebKit exploit
[*] Attempt: 1
[*] Retry: setup failed: Error: Scope not leaked. attempt 2
... (identical for every attempt) ...
[*] Attempt: 53
[*] Retry: setup failed: Error: Scope not leaked. attempt 54
```

- 54/54 attempts failed at the same step. No crashes, no variance, no progress past the leak.
- 14.10 WebKit user-agent: **AppleWebKit/605.1.15, Version/17.0**.

## Why this is decisive, not an offsets artifact

`leakScopeObject()` (webkit.js ~L209-229) is pure JS: `super.foo` through a `Proxy` get-trap that returns the receiver. The very next line is:

```js
if (leakedScope === undefined || leakedScope === null)
  throw new Error("Scope not leaked.");
```

No firmware offsets participate in this check (the only nearby offset use, `CANARY_OFFSET` writes into a typed array, cannot throw). On 13.60-era WebKit the call returns the leaked scope object; on 14.10 it returns `undefined` every time. The engine behavior itself changed → the bug (or the code path that exposed it) is gone.

## Consequences

1. **The free browser door on 14.10 requires a NEW WebKit bug.** Relapse's chain cannot be revived by offset-fixing alone; the entry primitive is dead.
2. Kernel stage (aio race) and hypervisor status are moot from the browser side until someone finds a fresh 14.10 WebKit primitive.
3. The guide app is confirmed to run **arbitrary unsigned JS** on 14.10 (cert warning → Yes). It remains the best attack surface to point a *new* WebKit exploit at — no save-game chain needed.
4. Sony ships WebKit "Version/17.0" on 14.10; if 13.60 reports the same string, Sony patches WebKit **without bumping the advertised version** — worth recording for fingerprinting.

## Open questions for the repo

- What WebKit UA string does 13.60 report from the same guide app? (If also 17.0, version string is useless for triage.)
- Does the `super`/Proxy leak still fire on 14.00? (14.00 keeps the hypervisor bug per Sonic_Iso; if the leak survives there, 14.00 testkits get a browser path.)
- Anyone with the 14.10 `libSceWebKit2` (PUP-decrypted on a 14.10 JB rig) diff the `super` property-lookup path vs 13.60?

## Kit notes (for reproduction)

- Hijack list that matters on 14.10: `ps5.np.playstation.net`, `manuals.playstation.net` (+ cert SANs for both).
- Guide app aggressively caches DNS + page: after DNS changes, **Restart System** (not rest mode) and fully close/reopen the guide.
- Serve exploit at any path (catch-all 200 for HTML; strip the `/document/en/ps5/` prefix when serving `/src/`, `/offsets/`, `/payloads/`).
- Beacon pattern: `window.beacon = m => new Image().src = "/beacon?m=" + encodeURIComponent(m)` + `window.onerror` beacon — cheap, survives renderer death, gives server-side step traces.
