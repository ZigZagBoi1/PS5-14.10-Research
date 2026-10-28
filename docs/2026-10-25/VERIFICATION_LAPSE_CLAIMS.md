# Verification: Lapse/Prolapse Claims in Agent Documents

**Date:** 2026-10-25
**Method:** WebFetch of cited sources, cross-referenced against claims in `11_LAPSE_PROLAPSE_IDENTIFICATION.md` and `FREEBSD_EXPLOIT_TECHNIQUES.md`

---

## Sources Actually Fetched and Verified

| Source | URL | Status |
|--------|-----|--------|
| Gistre Blog — Lapse writeup | `blog.gistre.epita.fr/posts/marco.chan-witzel-2026-07-13-lapse-the-aio-kernel-exploit-behind-the-ps5-jailbreak/` | **Fetched.** Blog exists, covers aio_multi_delete |
| LAVX.hu — Prolapse news | `news.lavx.hu/article/ps5-kernel-exploit-prolapse-works-on-firmware-14-10-...` | **Fetched.** Confirms Prolapse targets 14.00/14.10, fixed in 14.20 |
| OneJailbreak — Prolapse announcement | `onejailbreak.com/blog/prolapse-kernel-exploit-targets-ps5-14-00-and-14-10/` | Not fetched (cited in docs, not verified) |
| PSDevWiki — Vulnerabilities | `psdevwiki.com/ps5/Vulnerabilities` | Not fetched |

---

## Claim-by-Claim Verification

### Claim 1: "The author of Lapse is abc"

**Source says:** The Gistre blog post does not name the Lapse author as "abc." It describes the exploit and its technical approach but the author of the *exploit* (not the blog post) is not explicitly named "abc" anywhere in the fetched content.

**Verdict: UNVERIFIED.** The blog post author is Marco Chan-Witzel (the student who wrote the analysis). The original Lapse exploit author is described elsewhere as "anonymous." The name "abc" may come from community sources not fetched, but our documents present it as established fact.

---

### Claim 2: "Lapse has 4 stages"

**Source says:** The Gistre blog describes **5 stages**, not 4. The document `FREEBSD_EXPLOIT_TECHNIQUES.md` says "Four stages" (line 30) and numbers them 1-4.

**What the blog actually describes (5 stages):**
1. Double-free via aio_multi_delete race
2. Kernel address leak via reclaim + aliased object
3. Second double-free for R/W setup
4. Arbitrary kernel R/W
5. Privilege escalation (ucred modification)

**Verdict: INCORRECT.** `FREEBSD_EXPLOIT_TECHNIQUES.md` merged stages 4+5 into one. The corrected `11_LAPSE_PROLAPSE_IDENTIFICATION.md` references the blog and says "5 stages" which is consistent, but `FREEBSD_EXPLOIT_TECHNIQUES.md` says 4. Note: `09_EXPLOIT_CHAIN.md` correctly says 5 stages.

---

### Claim 3: "Uses socket operations with SO_LINGER to delay socket close, creating timing windows"

**Source says:** The Gistre blog mentions "some socket options" and "specific socket options" — it does NOT specifically name `SO_LINGER`. The blog describes using socket options for heap spray/reclaim, not for timing windows.

**Verdict: EMBELLISHED.** `SO_LINGER` is a reasonable inference (it's a classic FreeBSD exploitation technique for controlling socket close timing), but it is NOT sourced from the Gistre blog. Our document presents it as if directly quoted from the writeup. The blog's actual language is vague: "some socket options."

---

### Claim 4: "The aliased sockets are treated as an event flag object"

**Source says:** The blog mentions reclaiming the freed slot with some kind of kernel object to create an aliased pair. It uses the phrase "event flag object" in a general sense. The blog does NOT say `evf_create(538)` or name any specific syscall.

**Verdict: PARTIALLY CONFIRMED.** The general idea (reclaim with event flag → aliased object → kptr leak) is in the blog. The specific syscall number and calling convention are inferences, not sourced.

---

### Claim 5: "0x58-byte queue entries landing in the 0x80/128-byte zone"

**Source says:** The Gistre blog does NOT mention specific object sizes (0x58, 0x30), UMA zone sizes (0x80, 128-byte, 64-byte), or zone addresses.

**Verdict: UNSOURCED from the blog.** These sizes come from our 13.60 decompile analysis (`docs/AIO_13_60_ANALYSIS.md`), not from the Lapse writeup. The document presents them in the Lapse section as if they came from the blog.

**Correction:** The sizes ARE reasonable based on our independent 13.60 analysis. They should be attributed to our decompile, not to the Lapse writeup.

---

### Claim 6: "Prolapse patched in 14.20 via generation-ID revalidation"

**Source says:** The LAVX.hu article confirms Prolapse is patched in 14.20, saying "Sony fixed it in firmware 14.20, released October 21. Coixao confirmed the update closed the flaw." It does NOT describe the fix as "generation-ID revalidation."

**Verdict: HALF CONFIRMED.** The 14.20 fix is confirmed. The "generation-ID revalidation" mechanism is our inference based on what would logically close a TOCTOU race after a lock-drop window. It may well be correct, but it's not sourced from any external document.

---

### Claim 7: "Jose Coixao (notnotzecoxao) disclosed Prolapse"

**Source says:** The LAVX.hu article: "security researcher Jose Coixao disclosed it on social media."

**Verdict: CONFIRMED.** The Prolapse researcher is correctly identified.

---

### Claim 8: "Relapse by ntfargo, PS5 7.00-13.60"

**Source says:** Web search confirmed Relapse exists on GitHub by ntfargo for PS5. The firmware range 7.00-13.60 is stated in community sources.

**Verdict: CONFIRMED** (author and existence). Firmware range plausible but specific bounds not independently verified against the GitHub repo.

---

### Claim 9: "Relapse uses aio_multi_wait (663) race for UAF"

**Source says:** Not verified from the Relapse source code. The document states this without a source citation.

**Verdict: UNVERIFIED.** Our document may be conflating Relapse's mechanism with a different AIO syscall. Relapse may use the same 662 race or a different AIO entry point. No source provided.

---

### Claim 10: "Gezine also teased a 14.10 kernel exploit"

**Source says:** The LAVX.hu article mentions: "A separate 14.10 kernel exploit from researcher Gezine was teased but not released."

**Verdict: CONFIRMED.** There are potentially two independent 14.10 kernel exploits — Prolapse (Coixao) and an unnamed one (Gezine).

---

## Summary of Corrections Needed

| Document | Issue | Severity |
|----------|-------|----------|
| `FREEBSD_EXPLOIT_TECHNIQUES.md` | Claims 4 stages, blog says 5 | MODERATE |
| `FREEBSD_EXPLOIT_TECHNIQUES.md` | Names `SO_LINGER` as if sourced from blog | MODERATE |
| `FREEBSD_EXPLOIT_TECHNIQUES.md` | UMA zone sizes presented in Lapse section as if from blog | LOW (sizes are from our decompile, just misattributed) |
| `11_LAPSE_PROLAPSE_IDENTIFICATION.md` | Author "abc" unverified | LOW |
| `11_LAPSE_PROLAPSE_IDENTIFICATION.md` | SO_LINGER + evf spray presented as specific blog claims | MODERATE |
| Both documents | "generation-ID revalidation" as 14.20 fix mechanism is inference | LOW |
| `FREEBSD_EXPLOIT_TECHNIQUES.md` | Relapse "663 race" claim unsourced | LOW |
| `EXPLOIT_CHAIN_DESIGN.md` | References Lapse's "SO_LINGER" and "evf" as proven techniques | MODERATE — they're reasonable inferences, not established facts |

## What IS Confirmed

1. The bug is `aio_multi_delete` TOCTOU double-free — confirmed by blog + our probe 65l
2. Prolapse targets PS5 14.00/14.10 — confirmed by LAVX.hu
3. Patched in 14.20 — confirmed by LAVX.hu + Coixao
4. The exploit uses socket options + event flags for spray/reclaim — confirmed in general terms by blog
5. The exploit achieves KASLR defeat through aliased object fields — confirmed by blog
6. FreeBSD UMA has no double-free detection — confirmed by FreeBSD documentation
7. The Lapse chain produces arbitrary kernel R/W — confirmed by blog

## Impact on Strategy

**LOW.** The embellishments are in the specific details (which syscall, which option, which size), not in the general approach. The blog confirms the general strategy:

1. Double-free via 662 race ✓
2. Reclaim with socket/evf objects ✓ (specific options unknown)
3. Read kernel pointers through aliased object ✓ (specific readback path unknown)
4. Second double-free for R/W ✓
5. Modify ucred for privesc ✓

The strategic direction is correct. The specific implementation details (SO_LINGER, evf_create(538), 128-byte zone) are reasonable inferences that need live probing to confirm on 14.10, which is exactly what the priority probe queue (69a-69e) targets.
