# OSINT deep-dive: WebKit 616.1.27 delta + PS5 14.x scene (2026-11-19)

Compiled by research agent; full source index at the end. Key items for the bench:

## Headlines
1. 616.1.27 = Safari 17.0 (2023-09-18). PS5 14.00/14.10 = 616.1.27.211.1 (Sony suffix; UA Version/17.0).
   FW 13.00-13.60 ran 7624.1.16.11.4 (Safari 26.4-era) — 14.00 was a BRANCH REGRESSION backwards,
   which killed the Relapse/SlopKit/Prolapse-era chains and opened a 3-year post-17.0 CVE window.
2. linearfox CSSFontFace writeup (ntfargo/ufm42): SAME bug family as our chain; on PS5 the
   post-callback path performs a BUILD-SPECIFIC VTABLE CHECK (lea rax, const; cmp [rdi], rax;
   jnz -> SIGTRAP). Counterfeit vptr = instant death with everything else perfect. They had no
   leak (ASLR unsolved past 8.60); WE HAVE the leak (BASE/VP per load) — the check only passes
   with the REAL vptr. Directly explains p693 v31/v32 yield deaths. Test: vtr=1 (real vtable).
3. Own-repo Finding 14 (p553): CVE-2026-43720 (Canvas getContext reentrancy UAF) unpatched on
   14.10, stable bidirectional R/W via 6 transform float64 + 7 numeric props. Blocker: info
   leak (DAZ zeroes float64-encoded pointers). SYNTHESIS: p693 leak (oracle u32 + walk + BASE)
   closes the p553 blocker -> full ARW without winning the client-yield dispatch.
4. CVE-2023-42916 (OOB read -> disclosure, Safari 17.1.2, TAG, ITW): sibling 42917 cleared in
   WK1400 audit, 42916 NOT verified — candidate alternate leak; triage via crashscan2.
5. 14.20 closed 43720 (Sony backports into the 616.1.27.211.1 line) — re-verify per firmware.
6. Kernel tier-1 (post-userland): CVE-2026-7270 (execve memmove OOB write, public exploit),
   CVE-2026-45251 (poll/select UAF, pdfork sandbox check), sys532 OOB read (verify on 14.10).
7. COOP validated as the only route on XO .text (our own WEBPROCESS_XO_TEXT_14_10.md is cited
   by the public lineage); Synacktiv PS4 textarea-vptr pattern = the ARW-era dispatch hijack.

## Key sources
- linearfox writeup: https://linearfox.com/blog/cssfontface-uaf-playstation
- Relapse: https://github.com/ntfargo/Relapse-Exploit + giovannirapa explainer
- Prolapse: https://github.com/1nk1/PS5-Prolapse (zecoxao 14.x teaser; 14.20 closed)
- Apple/WebKitGTK advisory map 17.0->27.x (see agent report for full table)
- Synacktiv PS4: https://www.synacktiv.com/.../eu-20-Meffre-This-Is-For-The-Pwners...
- COOP (Schuster et al. S&P2015) + our COOP_ANALYSIS.md / FontFace dual-vtable map
