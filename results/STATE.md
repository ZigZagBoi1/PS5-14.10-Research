# Research state

Rewrite this block with `python tools/state.py set key=value`. It is the
only memory that survives a context compaction, so keep it current and
short. Volatile values (kernel base, console liveness) carry the time they
were measured; they are measurements, not truths.

<!-- STATE:BEGIN -->
- console: 10.0.0.96 PS5 browser ACTIVE, autonomous control via pynput WORKING (2026-11-14 09:02 UTC)
- kernel_text: 0xFFFFFFFFD5000000 (measured 2026-11-10, probe 1199b, slide +0x55000000)
- kernel_data: 0xFFFFFFFFD5CE0000 (TEXT + 0xCE0000, SDK v0.45)
- allproc: 0xFFFFFFFFD85B9EA0
- security_flags: 0xFFFFFFFFD6A84064
- rootvnode: 0xFFFFFFFFD8E3B510
- last_probe: p691-run2
- active_question: HARD BLOCKER: FontFace backing()=null gates ALL JS property getters. face.style ALWAYS returns 'normal'. The style-read mechanism for arbitrary memory read is DEAD. L1/L2 leaked but VP walk chain impossible without a read primitive. Canvas2D alias is same-type R/W only (no info leak). Need: (1) restore backing() by reclaiming the WeakPtrImpl, (2) find alternate read primitive, (3) new WebKit bug. 14 Canvas2D probes + 5 FontFace probes exhausted.
- race_assessment: ALL DEAD: PKTINFO=embedded struct, SNDBUF=mbuf logical overflow, close+setsockopt=fget blocks, 16 CVEs blocked. See docs/KERNEL_RACE_OFFLINE_ASSESSMENT_2026-11-10.md
- cve_assessment: 16 FreeBSD kernel CVEs (2019-2026) checked; ALL blocked on 14.10 (feature removal, missing prereqs, zone isolation, existing locks). See docs/CVE_KERNEL_RW_ASSESSMENT_2026-11-10.md
- cve_2020_7457: SA-20:20 patch adds INP_WLOCK only around ip6_pcbopts (2292 path). PKTINFO already locked in ip6_ctloutput. Sony blocked 2292 entirely. 91d/92c tested PKTINFO race to 11K+ calls = clean.
- next_action: AUTONOMOUS LOOP: (1) search for new WebKit read primitives, (2) build WeakPtrImpl reclaim probe, (3) test on PS5 via autonomous browser control. Game process blocked by PSN sign-out - browser is the only available attack surface.
- queued_probes: p635k-slim(active index), p635l-slim(in probes/), 1407a, 1408a, 1409a
- notes: all kernel addresses valid this boot only; if rebooted re-measure with fault oracle first
- ipv6_options: 2292PKTOPTIONS(6)=BLOCKED, PKTINFO(46)=OK, TCLASS(61)=OK, RTHDR(51)=partial, DSTOPTS/HOPOPTS=BLOCKED
- phase34_results: 56 captures examined 2026-11-10; 0 anomalies across all SHM/socket/VM/mmap races
- repo_overhaul: Phases 0-4 COMPLETE 2026-11-11: CLAUDE.md slim, PRs resolved, search index, capability graph, autonomous runner (54 tasks, 3 validated)
- chiaki_mcp: validated 2026-11-12, PostMessage automation working, Enter+2 refresh sequence confirmed
<!-- STATE:END -->

Session start: this block, then the last ten rows of `results/INDEX.md`,
then only the document section the active question names.
