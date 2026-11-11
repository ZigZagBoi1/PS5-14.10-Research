# Research state

Rewrite this block with `python tools/state.py set key=value`. It is the
only memory that survives a context compaction, so keep it current and
short. Volatile values (kernel base, console liveness) carry the time they
were measured; they are measurements, not truths.

<!-- STATE:BEGIN -->
- console: 192.168.1.121:9026 (a probe death kills the game; only the user can relaunch)
- kernel_base: 0xFFFFFFFF90C00000
- kernel_base_measured: 2026-11-10 20:36 UTC after console reboot, image 0xFFFFFFFF90C00000-0xFFFFFFFF97000000 (100MB, 4MB grid: 25 present slots), one isolated present sample at 0xFFFFFFFF80400000, probes 1331a capture results/1331a_20261110_203553.txt
- last_probe: 1553a
- active_question: browser lane: what replaces the blocked info-leak step now that Canvas UAF gives a write primitive without a heap address
- next_action: REBOOT console (1569a wedged it in /dev/dce 0x80288208). Driver ioctl space PARKED by decision after 2 of 2 handler-reaching words killed the console. Kernel lane closed at the 17 OBJECT-copyout sites (docs/KPTR_HUNT_OBJECT_COPYOUT_AUDIT_2026-11-05.md: all 7 unique sites closed). Next line: browser/WebKit.
- open_risks: CONSOLE-FATAL: /dev/dce ioctl 0x80208217 (group 0x82, function 0x17) blocks the calling thread forever and wedges the whole console -- needs a reboot, not a loader relaunch (1566a, 2026-11-10). Same class: /dev/gc 0xC0048125. Any unknown driver ioctl command word must be treated as console-fatal until measured otherwise: never send one from the loader thread, and never send one at all without the operator's explicit go-ahead.
- notes: probe rule: never dereference a range after a 548 op without a 547 check first - 1534c's read after op 1 faulted and killed the game, which is exactly the pattern Review1534c flagged as D3 elsewhere in the same probe
- upstream_note: origin/master carries its own STATE block for a different bench (console 10.0.0.96:9026, kernel_text 0xFFFFFFFFD5000000, allproc 0xFFFFFFFFD85B9EA0, rootvnode 0xFFFFFFFFD8E3B510); kept in git history, not merged into this block (689f2fff)
<!-- STATE:END -->

Session start: this block, then the last ten rows of `results/INDEX.md`,
then only the document section the active question names.
