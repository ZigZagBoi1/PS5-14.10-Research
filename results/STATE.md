# Research state

Rewrite this block with `python tools/state.py set key=value`. It is the
only memory that survives a context compaction, so keep it current and
short. Volatile values (kernel base, console liveness) carry the time they
were measured; they are measurements, not truths.

<!-- STATE:BEGIN -->
- console: 10.0.0.96 PS5 browser active via User Guide, chiaki-ng automation working (2026-11-12 00:44 UTC)
- kernel_text: 0xFFFFFFFFD5000000 (measured 2026-11-10, probe 1199b, slide +0x55000000)
- kernel_data: 0xFFFFFFFFD5CE0000 (TEXT + 0xCE0000, SDK v0.45)
- allproc: 0xFFFFFFFFD85B9EA0
- security_flags: 0xFFFFFFFFD6A84064
- rootvnode: 0xFFFFFFFFD8E3B510
- last_probe: p694 (CVE-2023-42950 heap UAF, all clean)
- active_question: kernel R/W — WebKit sole path; p692 UAF needs correct free trigger (getContext reentry not fonts.delete)
- race_assessment: ALL DEAD: PKTINFO=embedded struct, SNDBUF=mbuf logical overflow, close+setsockopt=fget blocks, 16 CVEs blocked. See docs/KERNEL_RACE_OFFLINE_ASSESSMENT_2026-11-10.md
- cve_assessment: 16 FreeBSD kernel CVEs (2019-2026) checked; ALL blocked on 14.10 (feature removal, missing prereqs, zone isolation, existing locks). See docs/CVE_KERNEL_RW_ASSESSMENT_2026-11-10.md
- cve_2020_7457: SA-20:20 patch adds INP_WLOCK only around ip6_pcbopts (2292 path). PKTINFO already locked in ip6_ctloutput. Sony blocked 2292 entirely. 91d/92c tested PKTINFO race to 11K+ calls = clean.
- next_action: 1) Redesign p692 UAF free mechanism using Canvas2D getContext reentry. 2) Test p800 TransformStream. 3) Queued Lua probes 1407a-1409a need game process relaunch.
- queued_probes: 1407a (ktimer TAI leak), 1408a (sysvsem OOB), 1409a (kevent leak), p800 (TransformStream typeconf)
- notes: all kernel addresses valid this boot only; if rebooted re-measure with fault oracle first
- ipv6_options: 2292PKTOPTIONS(6)=BLOCKED, PKTINFO(46)=OK, TCLASS(61)=OK, RTHDR(51)=partial, DSTOPTS/HOPOPTS=BLOCKED
- phase34_results: 56 captures examined 2026-11-10; 0 anomalies across all SHM/socket/VM/mmap races
- repo_overhaul: Phases 0-4 COMPLETE 2026-11-11: CLAUDE.md slim, PRs resolved, search index, capability graph, autonomous runner (54 tasks, 3 validated)
<!-- STATE:END -->

Session start: this block, then the last ten rows of `results/INDEX.md`,
then only the document section the active question names.
