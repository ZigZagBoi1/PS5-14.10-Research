# PS5 Firmware 14.10 — Public Jailbreak / Exploit Research Status Report

**Compiled:** October 16, 2026
**Scope:** Publicly available information only. Every claim is cited inline. Anything unverified, rumored, or not found is explicitly flagged. No information was fabricated.

---

## TL;DR

As of today (Oct 16, 2026), the highest fully jailbroken PS5 firmware is **13.60** (v26.05-13.60.00, released July 24, 2026), via the **Relapse** exploit chain (userland + kernel, released Sept 29, 2026). Firmware **14.00** (Sept 16, 2026) patched the Relapse kernel bug (`aio_multi_wait` UaF). Firmware **14.10** (Oct 1, 2026) additionally patched the **hypervisor bug** (per Sonic_Iso) and has **no public userland or kernel exploit**. Private 14.x-era kernel exploits are rumored/modeled to exist among scene researchers (Sonic-Iso, SaudiDos, Jordy), but nothing has shipped publicly. The scene's model in 2026: report bugs to Sony via HackerOne for bounties, publish after Sony patches — meaning 14.10 owners are effectively waiting for a future firmware to retroactively unlock their console. Sony is enforcing the split (PSN access requires 14.10 as of ~Oct 13–15, 2026; GTA 6 reportedly requires 14.10).

---

## 1. Firmware Landscape and Exact Timeline

Firmware versions and release dates per the PS5 firmware history tracker (https://xtremeps3.com/ps5-firmware-history/):

| Firmware | Full version string | Release date |
|---|---|---|
| 10.01 | — | Sept 21, 2024 |
| 12.00 | — | Sept 17, 2025 |
| 12.02 | — | Oct 2, 2025 |
| 12.40 | — | Dec 4, 2025 |
| 12.70 | — | Feb 12, 2026 |
| **13.60** | v26.05-13.60.00 | **July 24, 2026** |
| 14.00 beta | — | Aug 6, 2026 |
| **14.00** | v26.06-14.00.00 | **Sept 16–17, 2026** |
| **14.10** | v26.06-14.10.00 | **Oct 1, 2026** |

Both 14.00 and 14.10 shipped with vague release notes citing "security fixes" (https://www.playstationlifestyle.net/ — PS5 14.10 update coverage; https://www.pushsquare.com/ — 14.10 update coverage). A community post reacting to 14.10's patch notes noted they added no visible user-facing features ("The patch was 1.2 GB and added no visible features" — https://vocal.media/gamers/sony-locked-the-ps5-hackers-found-a-key-players-are-stuck-in-the-middle).

---

## 2. Which Firmware Ranges Are Publicly Exploitable Today?

### 2.1 Userland (entry-point) exploits — public

| Exploit | Entry vector | Firmware range | Status / notes |
|---|---|---|---|
| **Relapse webkit stage** | Browser WebKit (JSC info leaks + structured-clone pool mismatch → typedarray corruption) | **7.00–13.60** | Current flagship userland stage of the Relapse chain (https://github.com/ntfargo/Relapse-Exploit) |
| **slopkit** | Browser WebKit | 9.00–12.00 | Jordy's webkit jailbreak project; publicly hosted at jordyidk.github.io/slopkit/ (https://github.com/jordyidk/slopkit). Per PS4 dev wiki, the WebKit bug used for PS5 13.60 exploitation is *"Enhance JSC MarkedVector's interface to more closely match Vector's"* (https://www.psdevwiki.com/ps4/WebKit_Bugs) |
| **BD-JB** (TheFloW) | Blu-ray Disc Java | ≤ 7.61 | The classic offline userland entry; predates 2026 (https://github.com/TheOfficialFloW/BD-JB) |
| **BD-JB5 + bdj_unpatch** (Gezine) | Blu-ray Disc Java | BD-JB5 "supported up to 13.42" per repo; `bdj_unpatch` for 13.60+ requires an **already-jailbroken** console to unpatch BD-J | https://github.com/Gezine/BD-JB5 , https://github.com/Gezine/bdj_unpatch |
| **Y2JB** (Gezine) | YouTube app (v1.6 supports up to 12.70) | ≤ 12.70 | Recently extended with Relapse-chain support (Modded Warfare video, Oct 5, 2026: "Y2JB gets relapse support" — https://www.youtube.com/watch?v=YiAD8XolzOM) |
| **Yarpe / YarP2JB** (Helloyunho, matem6) | Userland leak exploit + port | Offsets for 9.00–12.70; ~45-minute leak runtime | https://github.com/Helloyunho/yarpe , https://github.com/matem6/YarP2JB |
| **ntfusion WebKit type-confusion PoC** (ntfargo) | Browser WebKit | "PS5 6.00 or superior" per test host; **status on 14.x unknown** | New bug released as PoC in late July 2026 because ntfargo is busy with private projects; community is testing which firmware it still triggers on via zecoxao.github.io/ntfusion (source: ONE Jailbreak news roundup, July 25, 2026 — https://onejailbreak.com/it/blog/notizie-sul-jailbreak-ps5-13-60/ ; PoC gist: https://gist.github.com/ntfargo/892977e9366c736759cb49665c3cafd9) |
| **CSSFontFace** (ntfargo) | Browser WebKit UAF | PS4: 6.00–11.02 (exploitable). **PS5: only 1.xx–8.60** (ASLR makes it unusable on newer PS5 FW); bug unpatched but not exploitable on latest PS5 firmware | https://github.com/ntfargo/CSSFontFace-Exploit ; technical write-up: https://linearfox.com/blog/cssfontface-uaf-playstation |
| **Mast1c0re** | PS2-emulator save/game exploit | ≤ 7.60 | Older, still-cited code-execution primitive (pre-2026 release) |

### 2.2 Kernel exploits — public

| Exploit | Bug | Firmware range | Status / notes |
|---|---|---|---|
| **Relapse kernel stage** (Jordy kernel bug, Sonic_Iso kernel implementation) | Decrement-by-one **UaF in `aio_multi_wait`** + info leak in `get_aio_debug_request_info`, chained with `osem_delete`/`osem_open`/`osem_close` → kernel ROP execution | **~FW 5.00–13.60** (dev wiki lists lower bound with "?", upper bound 13.60) | **Patched in 14.00.** Credits: Jordy discovered the bugs and made a write-up (2026-09-06: https://pastebin.com/hrRgDXLL); released implementation chained with slopkit on 2026-09-16; Sonic_Iso released the standalone Relapse implementation ~Sept 29, 2026. Source: PS5 dev wiki Vulnerabilities page (https://www.psdevwiki.com/ps5/Vulnerabilities) |
| **UMTX** | Kernel race in umtx syscalls | 1.xx–5.50 | Patched in FW 8.00 (https://github.com/PS5Dev/PS5-UMTX-Jailbreak) |
| **IPV6 kernel exploit** | IPv6 network-stack bug | 3.00–4.51 | Patched in 6.xx (community documentation) |
| **Lapse** | Kernel exploit | ≤ 10.01 | Earlier 2025-era release |
| **P2JB** (Gezine/Luac0re, implementation by cheburek3000) | Kernel exploit | Up to 12.70 | Requires the Star Wars Racer Revenge game disc ("Patience To Jailbreak" — released May 2, 2026) |
| **Gezine's private zero-day kernel exploit** | Undisclosed | Confirmed still working on 13.60 | **PRIVATE — never released.** 13.60 did *not* patch it (Gezine publicly debunked the rumor and said what 13.60 patched was non-critical, likely userland: https://onejailbreak.com/it/blog/notizie-sul-jailbreak-ps5-13-60/ ; https://www.reddit.com/r/PS5_Jailbreak/comments/1v5vnfp/gezines_exploit_is_not_patched_at_1360/). **Status on 14.00/14.10: not publicly known** |

### 2.3 Hypervisor exploits — public

| Exploit | Bug | Firmware range | Status / notes |
|---|---|---|---|
| **Original Byepervisor** (TheFloW, 2023) | HV break for early firmware | 1.xx/2.xx only | HV loaded in a separate region starting FW 3.00 killed this approach — "Starting in 3.00, the hypervisor is loaded in a separate region independently of the kernel - And thus these exploits do not work" (Hardwear.io talk PDF: https://hardwear.io/wp-content/uploads/2026/03/Byepervisor__Breaking_PS5_Hypervisor_Security.pdf) |
| **Byepervisor-Reborn** (PS5Dev, released ~Oct 12–13, 2026) | S3-resume `khv_startup_mp` AP-launch path (hypercall 0x0f) | **6.xx–13.60** (full support listed for 13.60/13.20/13.00; 13.00 untested per repo) | Public implementation of the S3-resume HV bug. Requires an existing kernel exploit + elfldr to reach the hypervisor. Defeats XOM protection, enabling kernel dump/patch. Ships no HEN patches itself. Devs state the bug "could work on 14.00 with modifications" — **unverified publicly**. Repo: https://github.com/PS5Dev/Byepervisor-Reborn ; coverage: https://onejailbreak.com/blog/byepervisor-reborn-ps5-hypervisor-exploit-up-to-13-60/ |
| **S3-resume HV bug — technical write-up** | Full writeup published by soniciso1 | Bug described across 6.xx–13.60; **14.10 patched it** | https://github.com/soniciso1/ps5-hv-writeups/blob/main/s3-resume-startup_mp-ap-launch.md |
| **TheFlow's private HV exploit** (PS5 Linux) | Undisclosed | Older firmwares (Linux previously capped at 7.61) | **PRIVATE / RETIRED.** Jordy reported it to Sony via HackerOne on Sept 15, 2026 against TheFlow's wishes; TheFlow then quit the scene (https://kotaku.com/popular-playstation-hacker-calling-it-quits-due-to-ai-using-slop-kiddies-reporting-important-bug-to-sony-2000735105) |

### 2.4 Range summary (public, as of Oct 16, 2026)

- **Userland + kernel + hypervisor (full):** FW **6.xx – 13.60** (Relapse chain + Byepervisor-Reborn).
- **Userland + kernel only:** FW **7.00 – 13.60** (Relapse chain); older firmware covered by UMTX/IPV6-era chains.
- **FW 14.00:** **No public exploit.** Kernel bug patched; hypervisor bug believed to survive 14.00 ("could work on 14.00 with modifications" — Byepervisor-Reborn devs), but there is **no public 14.00 kernel exploit** to reach it, so this is moot for now.
- **FW 14.10:** **No public exploit of any layer.** Hypervisor bug patched per Sonic_Iso.
- **BootROM/silicon level:** Level 0 BootROM keys leaked publicly on the final hours of Dec 31, 2025 — unpatchable, affects every PS5 revision (~95.3M consoles sold as of June 30, 2026). This is a long-term enabler (deep analysis, eventual custom firmware), but **no public exploit chain built on it has shipped** as of today. Sources: https://www.tomshardware.com/video-games/playstation/playstation-5-rom-keys-leaked-jailbreaking-could-be-made-easier-with-bootrom-codes , https://www.kitguru.net/gaming/matthew-wilson/bootrom-keys-for-ps5-leak-enabling-custom-firmware-emulation-and-piracy/ , https://psn.gg/news/ps5-bootrom-keys-unpatchable-explainer , https://tech-insider.org/ps5-bootrom-leak-unpatchable-hardware-flaw-2026/ , https://respawn.outlookindia.com/gaming/gaming-originals/why-the-ps5-rom-leak-could-be-a-turning-point-for-console-security

---

## 3. Status of Firmware 14.00 and 14.10

### 14.00 (Sept 16–17, 2026)

- **What it patched:** The Relapse kernel bug (`aio_multi_wait` decrement UaF + `get_aio_debug_request_info` info leak). Evidence: Relapse's stated range ends at 13.60 (https://github.com/ntfargo/Relapse-Exploit); the PS5 dev wiki lists the bug as "FW ?5.00?-13.60" (https://www.psdevwiki.com/ps5/Vulnerabilities); press coverage states "Firmware 14.00, released in mid-September 2026, sits outside the stated range, and reporting says that release closes the hole used here" (https://cybersecuritynews.com/ps5-relapse-exploit/).
- **What survived:** The hypervisor (S3-resume startup_mp) bug. Modded Warfare's Oct 5, 2026 video was titled "PS5 Jailbreak News: 14.10 Update, HV bug lives..." (https://www.reddit.com/r/PS5_Jailbreak/comments/1wxe51n/modded_warfare_ps5_jailbreak_news_1410_update_hv/), and Byepervisor-Reborn's devs say the HV bug could work on 14.00 with modifications.
- **Sentiment on 14.00 owners:** "They patched kernel but scene gods have already said they have a kernel exploit for 14" (https://www.reddit.com/r/PS5_Jailbreak/comments/1x05bmm/how_it_feels_being_on_140_rn/).

### 14.10 (Oct 1, 2026)

- **What it patched:** The **hypervisor bug**, per Sonic_Iso's confirmation ~Oct 3–4, 2026 (discussed in Reddit threads 1wy8m5v and 1wyb7gu). Note there was an initial contradictory claim from Jordy that the HV bug survived 14.10 (https://www.reddit.com/r/PS5_Jailbreak/comments/1wvn1zt/) — this was superseded ~2 days later by Sonic_Iso's confirmation that the hypervisor *is* patched. Sonic_Iso advised users to **stay on 13.60 and not update**. A cached post from Sonic_Iso's X account (posted ~Oct 15, before he left X) restates this: "PS5 14.10 and newer may will get the new userland and kernel exploit in the future, but not the hypervisor."
- **What has NOT appeared (as of Oct 16, 2026):** No public userland exploit, no public kernel exploit, no public hypervisor exploit, no offsets, no kernel dump for 14.00 or 14.10. Community consensus when 14.10 shipped: "A new Userland & kernel exploit would need to be found as entry points" (https://www.reddit.com/r/PS5_Jailbreak/comments/1wvl9aw/1410_is_out/). Press coverage likewise reports no public exploit for 14.x (https://www.wccftech.com/ — Byepervisor/Relapse coverage; https://www.reddit.com/r/PS5_Jailbreak/).
- **A claimed-but-unverified video:** "NEW PS5 14.00/14.10 USERLAND & KERNEL BUG WORKING + KSTUFF NEXT GEN SOON?!" by TheeEvolutionYT (Oct 7, 2026, ~47K views — https://www.youtube.com/watch?v=MkfPFMzc0vE). This is a small channel making an extraordinary claim ("userland & kernel bug working" on 14.x) with no accompanying public exploit, offset files, or repo. **Treat as unverified clickbait-style coverage of the private-exploit rumors until actual code appears.**
- **PSN enforcement (the "why it matters"):**
  - Around Oct 13, 2026, Sony began blocking all firmware below 14.10 from PSN — including 14.00 (https://www.notebookcheck.net/Sony-blocks-PS5-console-jailbreak-from-PSN-requiring-firmware-14-10.1424308.0.html ; https://www.reddit.com/r/ps5homebrew/comments/1x5nj12/software_version_1400_can_no_longer_connect_to/ — "It's not a 'full lockout'. You still have full functionality of your PS5. You just can't use Sony's network.").
  - A jailbroken PS5 was reportedly **banned** from PSN after its user took it online (reported ~Oct 9, 2026: https://www.facebook.com/mineclubs/videos/a-user-has-reportedly-been-banned-from-psn-after-taking-a-jailbroken-ps5-online-/1460873219340389/).
- **GTA 6 pressure:** GTA VI is reported to require PS5 system software 14.10.00.00 or newer, based on PlayStation Store backend data (PlayStation Game Size on X) — not officially confirmed by Rockstar or Sony (https://videocardz.com/newz/gta-vi-reportedly-requires-ps5-firmware-14-10-leaving-current-jailbreak-users-behind ; https://www.tweaktown.com/news/113907/gta-vi-will-reportedly-require-ps5-firmware-14-10-or-newer-to-block-jailbroken-consoles/index.html ; https://www.notebookcheck.net/GTA-6-blocks-PS5-jailbreak-and-piracy-on-release-date-requiring-14-10-00-firmware.1414828.0.html). This creates a direct fork-in-the-road for 13.60 jailbreak users when the game launches.
- **Testkit escape hatch:** A video titled "PS5 14.10 Downgrading To Jailbreak 13.60 (Testkit)" was posted ~Oct 12, 2026 (https://www.youtube.com/watch?v=t6VNF1K2448) — downgrades via testkit/devkit units are possible; retail consoles cannot downgrade.

---

## 4. Public Research Material Available for 14.1x Work

What the public actually has to work with today — and what it doesn't:

### 4.1 What exists publicly

1. **Relapse per-firmware offset files (7.00–13.60).** The `offsets/` folder in ntfargo/Relapse-Exploit contains one JS offsets file per firmware, including `13.60.js` with a full syscall map, kernel struct offsets (allproc, rootvnode, ucred, proc, aio group/idTable), and the KASLR mode string ("rtmsg2"). This is the freshest public baseline of kernel internals immediately preceding 14.00 — the starting point for diffing 14.x. (https://github.com/ntfargo/Relapse-Exploit/tree/main/offsets)
2. **PS5 13.60 live kernel memory dump (new — Oct 13, 2026).** `terrafirma2021/ps5-13.60-kernel-dump` — "Live RAM reconstruction from a PS5 running firmware 13.60, captured on 13 October 2026." Contents: `kernel-13.60-live.bin.gz` (decompressed: 103,546,880 bytes, SHA-256 `c3f745e25dc25ee7afef89eb418b295b6334bbefe8aa17e6886483c35d78cddd`) + a JSON with capture layout/addresses/hashes/missing pages. Layout: kernel text at `0xffffffff9e3f0000` (13,369,344 bytes, load as raw x86-64 in Ghidra) and kernel data at `0xffffffff9f0b0000` (90,177,536 bytes), with 688 unmapped pages zeroed. Explicitly **not** an ELF or bootable image, and not a complete decrypted firmware. Useful for symbol/type reconstruction and offset verification. (https://github.com/terrafirma2021/ps5-13.60-kernel-dump)
3. **slopkit — reusable WebKit exploit framework.** Jordy's webkit jailbreak project for 9.00–12.00, publicly hosted (jordyidk.github.io/slopkit/), with a commit chain containing the Relapse kernel implementation (https://github.com/jordyidk/slopkit/tree/f749b4b3f1910f8bc809de34d06e1479b29560ae). Provides the structural template (info-leak → typedarray corruption → loader) any future 14.x userland exploit would follow.
4. **Jordy's `aio_multi_wait` technical write-up (Sept 6, 2026).** Full public analysis of the Relapse kernel bug family: https://pastebin.com/hrRgDXLL (linked from the PS5 dev wiki Vulnerabilities page). Includes how the decrement UaF chains with `osem_*` syscalls into kernel ROP.
5. **PS5 dev wiki Vulnerabilities & WebKit Bugs pages.** Living documentation of every known PS5 vulnerability with credits and dates — the canonical "state of the art" reference (https://www.psdevwiki.com/ps5/Vulnerabilities , https://www.psdevwiki.com/ps4/WebKit_Bugs — the PS4 wiki hosts the PS5-relevant WebKit bug entries, e.g. the JSC MarkedVector bug used in the 13.60 chain).
6. **S3-resume `khv_startup_mp` HV write-up.** soniciso1/ps5-hv-writeups documents the full hypervisor bug (hypercall 0x0f, AP launch on S3 resume) that Byepervisor-Reborn implements (https://github.com/soniciso1/ps5-hv-writeups/blob/main/s3-resume-startup_mp-ap-launch.md).
7. **Byepervisor-Reborn offset tables (13.00/13.20/13.60).** `include/offsets/` in the repo provides hypervisor-side offsets for the top three firmwares — again a 13.60 baseline for future diffing (https://github.com/PS5Dev/Byepervisor-Reborn).
8. **ntfusion — brand-new WebKit type-confusion PoC (July 2026).** ntfargo published a fresh WebKit type-confusion bug affecting PS5 (6.00+) and PS4 (10.00+), deliberately unpatched-unknown territory, as a PoC for others to develop. The community is actively testing it against the newest firmware to find where Sony finally kills it (host: https://zecoxao.github.io/ntfusion ; PoC: https://gist.github.com/ntfargo/892977e9366c736759cb49665c3cafd9 ; source: https://onejailbreak.com/it/blog/notizie-sul-jailbreak-ps5-13-60/). **This is currently the most plausible public seed for a future 14.x userland entry — but its status on 14.10 is not publicly confirmed.**
9. **Leaked BootROM (Level 0) keys (Dec 31, 2025).** Hardware-level, unpatchable cryptographic material affecting every PS5 sold. Enables deep system analysis and is the presumed foundation of any eventual custom firmware, but no public tooling has shipped that turns it into a jailbreak on current firmware. (https://www.tomshardware.com/video-games/playstation/playstation-5-rom-keys-leaked-jailbreaking-could-be-made-easier-with-bootrom-codes ; https://psn.gg/news/ps5-bootrom-keys-unpatchable-explainer ; https://www.kitguru.net/gaming/matthew-wilson/bootrom-keys-for-ps5-leak-enabling-custom-firmware-emulation-and-piracy/)

### 4.2 What does NOT exist publicly for 14.1x (verified absence as of Oct 16, 2026)

- ❌ No public **userland** exploit for 14.00 or 14.10.
- ❌ No public **kernel** exploit for 14.00 or 14.10.
- ❌ No public **hypervisor** exploit for 14.10 (bug patched); 14.00 status "probably works, needs modifications" but unverified and unreachable without a 14.00 kernel exploit anyway.
- ❌ No public **offset files** for 14.00/14.10 (Relapse offsets stop at 13.60.js).
- ❌ No public **kernel dump** for 14.00/14.10 (the public dump is 13.60 only).
- ❌ No public **HEN/homebrew layer** for 14.x (kstuff-ng, etaHEN etc. target ≤13.60).
- ❓ **Unconfirmed:** whether the PS5's browser/YouTube-app userland entry vectors still function at all on 14.10 (Sony has progressively restricted browser access in recent firmware; Modded Warfare's Oct 5 video discussed WebKit entry status ambiguously). No public source confirms a working entry point on 14.x — which is itself the finding.

### 4.3 What exists privately (rumors and named claims — unverified)

- **Sonic-Iso:** publicly stated (before leaving X) that "there are already **multiple kernel exploits for fw14.00**" in private hands, and that "PS5 14.10 and newer may will get the new userland and kernel exploit in the future, but not the hypervisor" (Reddit threads: https://www.reddit.com/r/PS5_Jailbreak/comments/1wre6d0/ and https://www.reddit.com/r/PS5_Jailbreak/comments/1x7e3em/sonic_iso_no_longer_on_x/ — note: direct Reddit fetches were blocked; quotes are from search snippets).
- **SaudiDos & Jordy:** "According to the latest updates from SaudiDos & Jordy, there might be a private exploit working on newer firmware versions" (https://www.reddit.com/r/PS5_Jailbreak/comments/1ww3waq/some_hope_for_ps5_1410/). **Who SaudiDos is and any further details were not found in public sources.**
- **Gezine:** has a private zero-day kernel exploit confirmed unpatched at 13.60; its 14.x status is unknown publicly.
- **TheeEvolutionYT's video claim** (14.00/14.10 "userland & kernel bug working") — unverified, no artifact published.

---

## 5. 2026 Scene News — Chronology

| Date | Event | Source |
|---|---|---|
| Dec 31, 2025 | PS5 Level 0 **BootROM keys** leak publicly (unpatchable, all ~95M consoles) | https://www.tomshardware.com/video-games/playstation/playstation-5-rom-keys-leaked-jailbreaking-could-be-made-easier-with-bootrom-codes ; https://psn.gg/news/ps5-bootrom-keys-unpatchable-explainer |
| Jan 2026 | BootROM leak coverage; reports of 60–80M affected consoles | https://respawn.outlookindia.com/gaming/gaming-originals/why-the-ps5-rom-leak-could-be-a-turning-point-for-console-security |
| Feb 12, 2026 | FW 12.70 released | https://xtremeps3.com/ps5-firmware-history/ |
| ~Feb 2026 | **P2JB** kernel exploit released (up to 12.70; needs Star Wars Racer Revenge disc) | https://www.youtube.com/watch?v=dZKHOCeyyLI |
| Spring 2026 | Y2JB v1.6 userland exploit (YouTube app, ≤12.70); Yarpe + YarP2JB leak-based userland (9.00–12.70) released | https://github.com/Gezine/Y2JB ; https://github.com/matem6/YarP2JB |
| ~Aug 2026 | **"Celsius"** kernel exploit **leaked** for PS4 13.04 / PS5 12.70; public analysis reportedly stalled ("no real progress on the Celsius kernel bug yet" — ONE Jailbreak, July 25, 2026) | https://www.youtube.com/watch?v=-OlBkDy-Qj0 ; https://www.youtube.com/watch?v=Be5q0Yb7ikQ ; https://onejailbreak.com/it/blog/notizie-sul-jailbreak-ps5-13-60/ |
| July 24, 2026 | FW 13.60 released; rumor that Gezine's private zero-day was patched is **debunked by Gezine** (13.60 patched something non-critical, probably userland); Kstuff 1.09 confirmed running on 13.60 (private exploit alive) | https://onejailbreak.com/it/blog/notizie-sul-jailbreak-ps5-13-60/ |
| July 25, 2026 | ntfargo releases **ntfusion** WebKit type-confusion PoC for community testing on latest firmware | https://onejailbreak.com/it/blog/notizie-sul-jailbreak-ps5-13-60/ |
| Sept 6, 2026 | Jordy publishes `aio_multi_wait` write-up | https://pastebin.com/hrRgDXLL (via https://www.psdevwiki.com/ps5/Vulnerabilities) |
| Sept 15, 2026 | **HackerOne drama:** Jordy reports TheFlow's private PS5 hypervisor exploit to Sony despite TheFlow's request to hold disclosure (he wanted to wait until after GTA 6 launched, to preserve Linux access for players). Jordy said he agreed at first but reported after another person independently found the bug, fearing they'd cash the bounty instead | https://kotaku.com/popular-playstation-hacker-calling-it-quits-due-to-ai-using-slop-kiddies-reporting-important-bug-to-sony-2000735105 ; https://www.dexerto.com/gaming/playstation-pays-user-50000-bounty-for-reporting-critical-exploit-3419001/ |
| Sept 16–17, 2026 | FW **14.00** released; Jordy releases kernel implementation chained with slopkit webkit exploit (per dev wiki credit) | https://xtremeps3.com/ps5-firmware-history/ ; https://www.psdevwiki.com/ps5/Vulnerabilities |
| Sept 29, 2026 | **Relapse** published publicly — full chain for PS5 7.00–13.60 (first firmware jailbreak coverage since UMTX in 2022) | https://github.com/ntfargo/Relapse-Exploit ; https://kotaku.com/ps5-jailbreak-2000738283 ; https://arstechnica.com/gaming/2026/09/ps5-jailbreaks-just-got-a-lot-more-useful/ |
| Oct 1, 2026 | FW **14.10** released ("security fixes") | https://xtremeps3.com/ps5-firmware-history/ ; https://www.pushsquare.com/ |
| ~Oct 3–4, 2026 | Sonic_Iso confirms the **hypervisor bug is patched in 14.10**; tells everyone to stay on 13.60. (Supersedes Jordy's earlier claim that the HV bug survived 14.10) | Reddit threads 1wy8m5v / 1wyb7gu / 1wvn1zt (accessed via search snippets) |
| Oct 5, 2026 | Modded Warfare: "PS5 Jailbreak News: 14.10 Update, HV bug lives, Y2JB Relapse, Proton, Homebrew, Emulators & More" — also covers **Proton coming to PS5** and Xbox emulators arriving | https://www.reddit.com/r/PS5_Jailbreak/comments/1wxe51n/modded_warfare_ps5_jailbreak_news_1410_update_hv/ ; https://www.youtube.com/watch?v=YiAD8XolzOM |
| Oct 7, 2026 | TheeEvolutionYT posts "NEW PS5 14.00/14.10 USERLAND & KERNEL BUG WORKING + KSTUFF NEXT GEN SOON?!" (unverified claim) | https://www.youtube.com/watch?v=MkfPFMzc0vE |
| ~Oct 9, 2026 | A jailbroken PS5 user reportedly **banned** from PSN after going online | https://www.facebook.com/mineclubs/videos/a-user-has-reportedly-been-banned-from-psn-after-taking-a-jailbroken-ps5-online-/1460873219340389/ |
| Oct 12, 2026 | "PS5 14.10 Downgrading To Jailbreak 13.60 (**Testkit**)" video — devkit/testkit downgrade path demonstrated | https://www.youtube.com/watch?v=t6VNF1K2448 |
| ~Oct 12, 2026 | **kstuff-ng v1.13 beta** by Echo Stretch — FPKG layer working on 13.60 | https://github.com/EchoStretch (kstuff-ng) — community reporting |
| Oct 12–13, 2026 | **Byepervisor-Reborn** released — public HV exploit for 6.xx–13.60 | https://github.com/PS5Dev/Byepervisor-Reborn ; https://onejailbreak.com/blog/byepervisor-reborn-ps5-hypervisor-exploit-up-to-13-60/ |
| Oct 13, 2026 | **Playden** launcher released — run Steam library Windows games on a jailbroken PS5 without booting Linux (QR sign-in, downloads Windows versions) | https://onejailbreak.com/blog/play-steam-library-games-on-jailbroken-ps5/ |
| Oct 13, 2026 | **PS5 13.60 live kernel dump** published (capture dated Oct 13, 2026) | https://github.com/terrafirma2021/ps5-13.60-kernel-dump |
| Oct 13–15, 2026 | **Sony blocks PSN for all firmware below 14.10** (including 14.00) | https://www.notebookcheck.net/Sony-blocks-PS5-console-jailbreak-from-PSN-requiring-firmware-14-10.1424308.0.html ; https://www.reddit.com/r/ps5homebrew/comments/1x5nj12/software_version_1400_can_no_longer_connect_to/ |
| Oct 14, 2026 | **Overdrive Store** (homebrew storefront distributing commercial games) shuts down; a C&D letter from Sony legal is claimed by one X account but **no public letter/Sony statement exists** | https://onejailbreak.com/blog/overdrive-ps5-store-closes/ |
| Oct 14, 2026 | Sony pays Jordy (**2tonejordy** on HackerOne) the **maximum $50,000 bounty** for a "critical" vulnerability — the specific bug is not publicly identified. Jordy: "I can at least buy GTA 6 with this I think." Per Dexerto, only one other researcher received the max payout in the last 3 years | https://www.dexerto.com/gaming/playstation-pays-user-50000-bounty-for-reporting-critical-exploit-3419001/ ; https://x.com/couldbeautism/status/2110222993960194422 |
| Oct 15, 2026 | **Ubuntu boots to desktop on PS5 13.60** (Relapse + Byepervisor-Reborn). Sonic_Iso releases `1360linux.elf` for testing via Discord; install guide published. First time Linux runs on firmware beyond 7.61. Sonic credits TheFlow's groundwork | https://onejailbreak.com/blog/ubuntu-boots-on-jailbroken-ps5-firmware-13-60/ ; https://rmuxnet.gitlab.io/ps5-linux-guide/guide/getting-started ; https://x.com/Sonic_Iso/status/2110726595736445246 |
| Oct 15–16, 2026 | **Sonic-Iso leaves X** (Reddit: "Sonic iso no longer on X"); his profile https://x.com/Sonic_Iso now returns 404. A cached post from ~24h earlier still discussed 14.10 userland/kernel exploit prospects | https://www.reddit.com/r/PS5_Jailbreak/comments/1x7e3em/sonic_iso_no_longer_on_x/ |

**Scene meta-notes:**
- The 2026 scene model is now **bounty-driven responsible disclosure with delayed publication**: find bug → report to Sony via HackerOne (bounties up to $50K) → publish the exploit only after Sony patches it, retroactively unlocking the firmware range. Relapse, the HV bug, and presumably future 14.x exploits all follow this cadence.
- PSX-HAX remains active but its front page is mostly FPKG dump lists (https://www.psxhax.com/). Wololo's PS5 status page has not been updated since 2025 and is explicitly stale (https://wololo.net/ps5/).
- **Conference material:** No 2026 conference talk covering the current 14.x-era research was found. The public conference record is older: TheFloW's original "Byepervisor: Breaking PS5 Hypervisor Security" Hardwear.io talk (covering only 1.xx/2.xx HV breaks — https://hardwear.io/wp-content/uploads/2026/03/Byepervisor__Breaking_PS5_Hypervisor_Security.pdf) and SpecterDev's "Next-Gen Exploitation: Exploring the PS5 Security Landscape" (https://www.slideshare.net/slideshow/next-gen-exploitation-exploring-the-ps5-security-landscape-pdf/269866512). A "PS5 BootROM Leak: 95M Consoles Unpatched" article (https://tech-insider.org/ps5-bootrom-leak-unpatchable-hardware-flaw-2026/) notes the boot ROM comparison to the Xbox One "Bliss" voltage-fault-injection exploit presented at RE//verse 2026, but that talk concerns Xbox, not PS5.

---

## 6. Post-Exploit Toolchain (as of Oct 16, 2026)

The working stack a 13.60 user runs after the Relapse + Byepervisor-Reborn chain:

1. **Loaders / injection**
   - `ps5-payload-elfldr` — ELF loader listening on **TCP port 9021**, injects via ptrace into SceRedisServer, survives rest mode (https://github.com/ps5-payload-dev/elfldr).
   - WebKit autoloaders that run the chain automatically on browser load: itsPLK/ps5-webkit-autoloader (7.00–13.60 — https://github.com/itsPLK/ps5-webkit-autoloader), X-F1REBALL-X/PS5-WebKit-Autoloader (https://github.com/X-F1REBALL-X/PS5-WebKit-Autoloader), CielWhat/ps5-webkit-autoloader-13x (Relapse port — https://github.com/CielWhat/ps5-webkit-autoloader-13x).
   - The Relapse page itself binds R2 to load kstuff + ShadowMountPlus + etaHEN in sequence.
2. **SDK / dev tooling**
   - `ps5-payload-dev/sdk` — homebrew SDK for building PS5 ELFs (https://github.com/ps5-payload-dev/sdk).
   - `ps5-payload-websrv` — web server payload (https://github.com/ps5-payload-dev/websrv).
3. **Homebrew enablement layers (HEN)**
   - **kstuff-ng** (Echo Stretch) — next-gen kstuff providing FPKG support on 13.60; v1.13 beta released ~Oct 12, 2026 (community reporting via Modded Warfare / r/PS5_Jailbreak).
   - **Kstuff-lite v1.07+** and Kstuff 1.09 confirmed running on 13.60 (https://onejailbreak.com/it/blog/notizie-sul-jailbreak-ps5-13-60/).
   - **etaHEN** — official supports ≤8.20 (https://github.com/etaHEN/etaHen); an unofficial etaHEN 2.5B port circulates for 13.60.
4. **Game dumping / mounting**
   - **ShadowMountPlus** — mounted in the Relapse flow; used with FPKG/dump workflows.
   - **Arc Sama's co-processor A53 + Kraken compression method** for loading game dumps — approaching non-APR beta testing as of late July 2026 (https://onejailbreak.com/it/blog/notizie-sul-jailbreak-ps5-13-60/).
5. **PC-side / network payloads**
   - `ps5-payload-websrv` (above); **Payload Manager v0.5.0** (https://github.com/itsPLK/ps5-payload-manager); **CheatRunner v0.16** (https://github.com/notmaj0r/CheatRunner).
6. **Linux (the big 2026 unlock)**
   - PS5 Linux previously capped at **7.61** because everything above needed a hypervisor escape. With Relapse + Byepervisor-Reborn, **Ubuntu now boots to desktop on 13.60**; Sonic_Iso's `1360linux.elf` is in testing, more firmwares to follow (https://onejailbreak.com/blog/ubuntu-boots-on-jailbroken-ps5-firmware-13-60/).
   - Install guide: https://rmuxnet.gitlab.io/ps5-linux-guide/guide/getting-started
   - PS5 Linux Manager web panel (boot params / vram.txt editing) exists; dual-boot in development (onejailbreak roundup, July 2026).
   - Historical context: TheFloW's early PS5 Linux work included a Slim demo running GTA 5 with ray tracing (https://onejailbreak.com/blog/ps5-steam-machine-linux-gta-5-ray-tracing/).
7. **Windows-games-without-Linux**
   - **Playden** (Oct 13, 2026): sign in with Steam QR, browse your library, download the Windows versions, launch them natively on the jailbroken PS5 — no Linux boot required (https://onejailbreak.com/blog/play-steam-library-games-on-jailbroken-ps5/).
8. **Emulation / streaming on 13.60**
   - Proton coming to PS5; Xbox emulators arriving (Modded Warfare, Oct 5 — https://www.youtube.com/watch?v=YiAD8XolzOM). PS5 emulation projects (Sharp EMU reaching Demon's Souls menus; Kite PS5) progress quickly — though these run on PC, not on console.
   - PSBox streams Xbox Cloud Gaming to a jailbroken PS5 (https://onejailbreak.com/blog/xbox-cloud-gaming-now-works-on-jailbroken-ps5/).
   - AnyPad PS5 lets jailbroken consoles use other Bluetooth pads (https://onejailbreak.com/blog/anypad-ps5-adds-bluetooth-pads-on-jailbreak/).
9. **Storefront**
   - **Overdrive Store** — homebrew storefront that browsed/downloaded commercial games — shut down Oct 14, 2026; claimed (unverified) Sony C&D (https://onejailbreak.com/blog/overdrive-ps5-store-closes/).

---

## 7. Verification Notes, Uncertainties, and Not-Found Items

- **Reddit access:** Direct fetches of www.reddit.com pages (including `.json`, old.reddit, np.reddit) returned HTTP 403 throughout this research. All Reddit-thread quotes above come from search-engine snippets of those threads and should be treated accordingly.
- **The $50K bounty's target bug is not publicly identified.** Dexerto explicitly notes the HackerOne dispute "does not establish which vulnerability earned Jordy the newly publicized $50,000 reward" (https://www.dexerto.com/gaming/playstation-pays-user-50000-bounty-for-reporting-critical-exploit-3419001/).
- **Hypervisor bug on 14.00:** plausible-but-unverified. Byepervisor-Reborn's devs say it "could work on 14.00 with modifications"; nobody has publicly demonstrated it on 14.00, and no public 14.00 kernel exploit exists to reach the HV layer anyway.
- **WebKit/browser entry point on 14.10:** **not confirmed either way** in public sources. No public WebKit exploit claims to work on 14.x. The ntfusion PoC (PS5 6.00+) is being tested on latest firmware but no public result pins down its 14.10 status. Modded Warfare's Oct 5 video discussed the topic ambiguously ("WebKit not working offline" wording).
- **Sonic-Iso leaving X:** reported by r/PS5_Jailbreak ~Oct 15–16 ("Sonic iso no longer on X" — https://www.reddit.com/r/PS5_Jailbreak/comments/1x7e3em/sonic_iso_no_longer_on_x/); his profile https://x.com/Sonic_Iso returns 404 as of today, consistent with deletion. A cached search snippet of a post made ~24h before deletion exists. Timing relative to the Ubuntu/Linux release is unclear. **Flagged as partially verified.**
- **SaudiDos:** a scene name appearing only in the "Some hope for PS5 14.10" thread (https://www.reddit.com/r/PS5_Jailbreak/comments/1ww3waq/some_hope_for_ps5_1410/). Identity, credibility, and any further detail were **not found** in public sources.
- **"Celsius" kernel bug/exploit:** referenced in Modded Warfare's Aug 2026 news video ("New Celsius Kernel Bug, 27K Bug Bounty" — https://www.youtube.com/watch?v=-OlBkDy-Qj0) and a follow-up ("'Celsius' kernel exploit leaked for PS4 and PS5" — https://www.youtube.com/watch?v=Be5q0Yb7ikQ), with ONE Jailbreak reporting analysis stalled as of July 2026. Full technical details of what Celsius is (and its exact affected range) were **not found** in public sources.
- **BootROM key leak exploitability:** all coverage describes leaked keys as an enabler, not a working jailbreak. No public exploit chain built on the keys has shipped as of Oct 16, 2026 (https://www.kitguru.net/gaming/matthew-wilson/bootrom-keys-for-ps5-leak-enabling-custom-firmware-emulation-and-piracy/ ; https://tech-insider.org/ps5-bootrom-leak-unpatchable-hardware-flaw-2026/).
- **GTA 6 firmware requirement:** sourced from PlayStation Store backend data via "PlayStation Game Size" on X; **neither Rockstar nor Sony has confirmed it** (https://www.tweaktown.com/news/113907/gta-vi-will-reportedly-require-ps5-firmware-14-10-or-newer-to-block-jailbroken-consoles/index.html). GTA 6's launch date itself was not verified in this research.
- **Overdrive Store closure / C&D letter:** the letter is claimed by a single X account; no public document or Sony statement exists (https://onejailbreak.com/blog/overdrive-ps5-store-closes/).
- **Wololo's PS5 status page** is stale (not updated since 2025) — not used as evidence here.

---

## BOTTOM LINE

**Exploitable firmware ranges as of Oct 16, 2026:**

| Layer | Publicly exploitable range |
|---|---|
| Userland (browser/YouTube/BD-J entry) | 1.xx – **13.60** (Relapse webkit stage 7.00–13.60; Y2JB ≤12.70; BD-JB5 ≤13.42; older chains cover the rest) |
| Kernel | ~5.00 – **13.60** (Relapse kernel stage; UMTX-era chains cover ≤5.50; P2JB ≤12.70; Lapse ≤10.01) |
| Hypervisor | 6.xx – **13.60** (Byepervisor-Reborn; bug reported as possibly functional on 14.00, unverified) |
| **14.00** | **Nothing public.** Kernel bug patched; HV bug likely survives but is unreachable without a (nonexistent) public 14.00 kernel exploit. Private kernel exploits for 14.00 are claimed to exist (Sonic-Iso). |
| **14.10** | **Nothing public at any layer.** HV bug patched. No public userland entry, no kernel exploit, no offsets, no dump. Private userland+kernel work "may" surface for 14.10+ "in the future" (Sonic-Iso's last public statement before leaving X). |
| Silicon | Level 0 BootROM keys (all consoles) leaked Dec 31, 2025 — unpatchable, long-term enabler, no public chain built on it yet |

**Where 14.10 sits:** It is the *safest* firmware for Sony and the *worst* for the scene — released Oct 1, 2026, it closed the last known public hole (the S3-resume hypervisor bug) on top of 14.00 already closing the `aio_multi_wait` kernel bug. It is enforced by PSN (everything below 14.10 was blocked from PSN around Oct 13–15, 2026) and, reportedly, by GTA 6 (14.10 required to run, unconfirmed). Owners of 14.10 consoles currently have **zero public jailbreak options** and cannot downgrade (except testkit units).

**The gap that must be closed:** a **new userland entry point + a new kernel exploit for 14.10**, with fresh offsets. Concretely:
1. **Userland:** the most plausible public seed is ntfargo's unreleased-in-full ntfusion WebKit type-confusion PoC (PS5 6.00+) — if it still triggers on 14.10, it provides the entry; unconfirmed publicly. Alternatively the private userland+kernel work hinted at by Sonic-Iso/Jordy/SaudiDos could land publicly once Sony patches (following the 2026 bounty-then-publish cadence).
2. **Kernel:** nothing public exists for 14.1x; researchers claim private 14.00-era kernel exploits already exist, but the community-visible path is the same retroactive-publish model — meaning 14.10 likely becomes exploitable only *after* Sony ships a future firmware (14.20+) that patches the next reported bug.
3. **Offsets/dump material:** Relapse's 13.60.js offsets and the fresh Oct 13, 2026 **13.60 kernel dump** are the public baselines for diffing against 14.x internals once someone gains any 14.x read access.

Until a public userland bug on 14.10 is confirmed and a kernel bug is published, **13.60 is the ceiling for jailbroken PS5s**, and every day more consoles drift to 14.10 via PSN enforcement.
