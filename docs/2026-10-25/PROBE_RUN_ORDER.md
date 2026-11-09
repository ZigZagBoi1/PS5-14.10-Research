# Probe 69-Series Run Order (2026-10-25)

**42 probes ready.** Run in dependency order — each tier's results inform the next.

## Tier 1: LOW RISK — Measurements & Reconnaissance (run first)

These are safe (CRASH_CLASS: LOW) and provide critical sizing/capability data.

| # | Probe | What it answers | Why it matters |
|---|-------|----------------|----------------|
| 1 | `69l_evf_object_size` | Do evf/namedobj objects match R's 64B zone? | Determines if cross-subsystem spray is geometrically possible |
| 2 | `69t1_666_667_semantics` | What do 666/667 return beyond status dwords? | Might expose R+0x00/R+0x08 without cross-spray |
| 3 | `69n_663_mode_sweep` | Does mode parameter unlock wider readback? | Same-subsystem R readback if mode changes output format |
| 4 | `69m_read_gadget_scan` | Which eboot gadgets read memory (mov rax,[rdi];ret)? | Required for any kernel pointer chase post-spray |
| 5 | `69k_dlsym_deep_sweep` | Does dynlib_dlsym(591) resolve kernel symbols? | Potential KASLR defeat without heap manipulation |
| 6 | `69j_sioc_ioctl_kaslr` | Do socket SIOC* ioctls leak kernel pointers? | Untested KASLR surface (device ioctls were tested, socket-level weren't) |
| 7 | `69q5_recvmsg_errqueue` | Do untested recvmsg options leak kernel data? | IP_RECVERR, IPV6_RECVERR, IP_RECVTOS never tested |
| 8 | `69q1_624_doublefree_oracle` | Does 624 VM counter detect the double-free? | Confirms kernel state change from the race |

## Tier 2: MODERATE RISK — Spray Feasibility (run second)

CRASH_CLASS: MODERATE to HIGH. These test whether spray reclaims the freed R slot.

| # | Probe | What it answers |
|---|-------|----------------|
| 9 | `69p_file_refcount_uaf` | Does double-SUCCESS double-decrement the file refcount? (the Lapse path) |
| 10 | `69d_r_reclaim_kaslr` | Can evf/namedobj/setsockopt spray reclaim R → read kernel ptrs? (200 objects) |
| 11 | `69f_evf_spray_readback` | Dedicated evf spray → read via 543/542 |
| 12 | `69h_highvol_spray` | 4096+ object spray to drain UMA per-CPU cache |
| 13 | `69h2_evf_namedobj_volume_spray` | High-volume evf+namedobj variant |
| 14 | `69q2_controlled_spray` | IP_OPTIONS (40B) controlled-data spray into R's 64B bucket |
| 15 | `69u_socketpair_zone_spray` | Socketpair + IP_OPTIONS combined spray |
| 16 | `69v_sendmsg_cmsg_spray` | sendmsg cmsg-based spray |

## Tier 3: HIGH RISK — Race Variants (run third)

These trigger the actual double-free race. Process may crash.

| # | Probe | What it answers |
|---|-------|----------------|
| 17 | `69g_submit_during_delete` | 3-thread race: delete + submit + re-delete = real UAF? |
| 18 | `69i_aio_cmd2_class23` | cmd=2 (write) and class=2/3 race differences |
| 19 | `69s3_aio_class23_race` | Class 2/3 double-free variant |
| 20 | `69r2_aio_highvol_race` | High-volume race (more iterations, bigger batch) |

## Tier 4: FULL CHAIN — Combined Exploits (run last)

Only after Tier 1-3 results confirm the spray works.

| # | Probe | What it does |
|---|-------|-------------|
| 21 | `69r1_full_chain_poc` | Double-free → spray → readback → KASLR in one probe |
| 22 | `69s1_full_chain_kaslr` | Full chain with decompile-guided R+0x00/R+0x08 targeting |
| 23 | `69s2_controlled_kwrite` | Controlled kernel write via UAF |
| 24 | `69t2_heap_feng_shui` | Heap layout manipulation for spray reliability |

## Supporting Probes (run as needed)

| Probe | Purpose |
|-------|---------|
| `69a_aio_overlap_hexdump` | Hexdump AIO output buffers for overlap artifacts |
| `69a2_aio_class_lifecycle` | AIO class 1/2/3 lifecycle comparison |
| `69b_poll_close_race` | CVE-2026-45251 poll+close race (200 iters) |
| `69b2_signal_crash_oracle` | Signal-based crash detection for UAF |
| `69c_aio_class_lifecycle` | AIO class lifecycle (variant) |
| `69c2_dlsym_real_handles` | dlsym with real module handles |
| `69e_solinger_spray_readback` | SO_LINGER spray (inline, won't cross-spray, tests pattern) |
| `69o_poll_close_race` | High-volume poll+close (5000 iters) |
| `69p2_aio_readback_after_uaf` | AIO readback after confirmed UAF |
| `69p3_namedobj_reclaim` | Namedobj-specific R reclaim |
| `69p4_pipe_spray_reclaim` | Pipe buffer spray for R reclaim |
| `69p5_socket_zone_size` | Socket object zone sizing |
| `69p6_submit_during_delete` | Submit-during-delete variant |
| `69q3_pipe_buffer_spray` | Pipe buffer spray variant |
| `69q4_read_gadget_scan` | Read gadget scan variant |
| `69r3_highvol_evf_spray` | High-volume evf-only spray |
| `69r4_kqueue_knote_spray` | Kqueue knote as spray object |
| `69h_zone_size_map` | Zone size mapping |

## Key Decision Points

After **Tier 1**:
- If 69l shows evf ≠ 64B → cross-spray with evf is dead, focus on IP_OPTIONS or same-subsystem
- If 69t1/69n show new readback paths → skip cross-spray entirely
- If 69k resolves kernel symbols → KASLR solved without heap exploitation

After **Tier 2**:
- If 69p shows file refcount UAF → we have the Lapse path (file UAF → kernel R/W)
- If 69h shows spray lands in R's zone → KASLR via R+0x00/R+0x08 readback
- If all spray fails → focus on same-subsystem 663/666/667 readback

After **Tier 3**:
- If 69g produces observable UAF → proceed to full chain
- If class 2/3 has wider TOCTOU → use different class for production exploit

## Run Command

```powershell
.\tools\send_probe.ps1 probes\phase16_kwrite\<name>.lua -Save
```
