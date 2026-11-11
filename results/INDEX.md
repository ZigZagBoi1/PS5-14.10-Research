# Run ledger

One line per console run. Append with `python tools/state.py row ...`; never edit
history. Search it before writing a probe: `grep -n 622 results/INDEX.md`.

A row without a capture path is not evidence. Grade `V` means the probe died or
never reached the handler: it is not a dead end and must not be cited as one.
Grade `?` marks a capture that has been indexed but not yet read and graded.

| date (UTC) | probe | claim | result | grade | capture |
|---|---|---|---|---|---|
| 2026-10-15 18:41 | 01 | - | - | ? | results/phase1_identity_layout/01_identity_20261015_184155.txt |
| 2026-10-15 18:42 | 01 | - | - | ? | results/phase1_identity_layout/01_identity_20261015_184244.txt |
| 2026-10-15 18:43 | 02 | - | - | ? | results/phase1_identity_layout/02_syscall_sweep_20261015_184327.txt |
| 2026-10-15 18:48 | 02 | - | - | ? | results/phase1_identity_layout/02_syscall_sweep_20261015_184857.txt |
| 2026-10-15 18:49 | 02 | - | - | ? | results/phase1_identity_layout/02_syscall_sweep_20261015_184940.txt |
| 2026-10-15 18:50 | 02 | - | - | ? | results/phase1_identity_layout/02_syscall_sweep_20261015_185021.txt |
| 2026-10-15 18:50 | 03 | - | - | ? | results/phase1_identity_layout/03_vmmap_layout_20261015_185027.txt |
| 2026-10-15 18:50 | 04 | - | - | ? | results/phase1_identity_layout/04_kernel_surface_20261015_185036.txt |
| 2026-10-15 18:51 | 04 | - | - | ? | results/phase1_identity_layout/04_kernel_surface_20261015_185134.txt |
| 2026-10-15 18:51 | 04 | - | - | ? | results/phase1_identity_layout/04_kernel_surface_20261015_185153.txt |
| 2026-10-15 18:52 | 04 | - | - | ? | results/phase1_identity_layout/04_kernel_surface_20261015_185213.txt |
| 2026-10-15 18:52 | 05 | - | - | ? | results/phase1_identity_layout/05_file_recon_20261015_185219.txt |
| 2026-10-15 18:52 | 06 | - | - | ? | results/phase1_identity_layout/06_bug_hunt_20261015_185224.txt |
| 2026-10-15 18:53 | 07 | - | - | ? | results/phase1_identity_layout/07_ipv6_leak_20261015_185335.txt |
| 2026-10-15 18:54 | 08 | - | - | ? | results/phase1_identity_layout/08_read_offsets_20261015_185427.txt |
| 2026-10-15 18:56 | 09 | - | - | ? | results/phase2_kernel_objects/09_ipv6_stress_20261015_185645.txt |
| 2026-10-15 19:00 | 10 | - | - | ? | results/phase2_kernel_objects/10_umtx_stress_20261015_190047.txt |
| 2026-10-15 19:03 | 11 | - | - | ? | results/phase2_kernel_objects/11_umtx_race_20261015_190341.txt |
| 2026-10-15 19:04 | 11 | - | - | ? | results/phase2_kernel_objects/11_umtx_race_20261015_190437.txt |
| 2026-10-15 19:04 | 11 | - | - | ? | results/phase2_kernel_objects/11_umtx_race_20261015_190449.txt |
| 2026-10-15 19:05 | 11 | - | - | ? | results/phase2_kernel_objects/11_race2_20261015_190539.txt |
| 2026-10-15 19:07 | 12 | - | - | ? | results/phase2_kernel_objects/12_nwake_robust_20261015_190720.txt |
| 2026-10-15 19:08 | 13 | - | - | ? | results/phase2_kernel_objects/13_nwake_oracle_20261015_190841.txt |
| 2026-10-15 19:16 | 14 | - | - | ? | results/phase2_kernel_objects/14_device_ioctl_20261015_191602.txt |
| 2026-10-15 19:17 | 15 | - | - | ? | results/phase2_kernel_objects/15_dmem_deep_20261015_191724.txt |
| 2026-10-15 19:20 | 17 | - | - | ? | results/phase2_kernel_objects/17_dmem_kptr_20261015_192017.txt |
| 2026-10-15 19:22 | 18 | - | - | ? | results/phase2_kernel_objects/18_dmem_phys_20261015_192222.txt |
| 2026-10-15 19:27 | 19 | - | - | ? | results/phase2_kernel_objects/19_aio_stress_20261015_192707.txt |
| 2026-10-15 19:28 | 19b | - | - | ? | results/phase2_kernel_objects/19b_aio_safe_20261015_192814.txt |
| 2026-10-15 19:29 | 19c | - | - | ? | results/phase2_kernel_objects/19c_aio_pipes_20261015_192919.txt |
| 2026-10-15 19:30 | 19d | - | - | ? | results/phase2_kernel_objects/19d_aio_minimal_20261015_193005.txt |
| 2026-10-15 19:30 | 19e | - | - | ? | results/phase2_kernel_objects/19e_aio_nocrash_20261015_193047.txt |
| 2026-10-15 19:31 | 19f | - | - | ? | results/phase2_kernel_objects/19f_aio_read_only_20261015_193137.txt |
| 2026-10-15 19:33 | 19g | - | - | ? | results/phase2_kernel_objects/19g_aio_debug_20261015_193320.txt |
| 2026-10-15 19:35 | 20 | - | - | ? | results/phase2_kernel_objects/20_kqueue_stress_20261015_193513.txt |
| 2026-10-15 19:36 | 21 | - | - | ? | results/phase2_kernel_objects/21_kqueue_deep_20261015_193631.txt |
| 2026-10-15 19:36 | 21 | - | - | ? | results/phase2_kernel_objects/21_kqueue_deep_20261015_193640.txt |
| 2026-10-15 19:38 | 22 | - | - | ? | results/phase3_signals_codexec/22_signal_stress_20261015_193830.txt |
| 2026-10-15 19:39 | 23 | - | - | ? | results/phase3_signals_codexec/23_sigalt_exploit_20261015_193944.txt |
| 2026-10-15 19:42 | 24 | - | - | ? | results/phase3_signals_codexec/24_sigalt_kwrite_20261015_194200.txt |
| 2026-10-15 19:46 | 25 | - | - | ? | results/phase3_signals_codexec/25_sigalt_safe_20261015_194601.txt |
| 2026-10-15 19:47 | 25b | - | - | ? | results/phase3_signals_codexec/25b_sigalt_ign_20261015_194744.txt |
| 2026-10-15 19:48 | 25c | - | - | ? | results/phase3_signals_codexec/25c_sigprocmask_20261015_194850.txt |
| 2026-10-15 19:50 | 26 | - | - | ? | results/phase3_signals_codexec/26_gadget_scan_20261015_195024.txt |
| 2026-10-15 19:51 | 26b | - | - | ? | results/phase3_signals_codexec/26b_ret_gadget_20261015_195125.txt |
| 2026-10-15 19:52 | 26c | - | - | ? | results/phase3_signals_codexec/26c_wxor_gadget_20261015_195234.txt |
| 2026-10-15 19:53 | 26d | - | - | ? | results/phase3_signals_codexec/26d_find_ret_20261015_195332.txt |
| 2026-10-15 19:55 | 26e | - | - | ? | results/phase3_signals_codexec/26e_code_read_20261015_195541.txt |
| 2026-10-15 19:57 | 26f | - | - | ? | results/phase3_signals_codexec/26f_kstack_crash_20261015_195707.txt |
| 2026-10-15 19:59 | 27 | - | - | ? | results/phase4_ipc_network/27_thread_and_fd_20261015_195948.txt |
| 2026-10-15 20:01 | 28 | - | - | ? | results/phase4_ipc_network/28_ipv6_scmrights_20261015_200134.txt |
| 2026-10-15 20:03 | 29 | - | - | ? | results/phase4_ipc_network/29_rthdr_mmap_20261015_200310.txt |
| 2026-10-15 20:04 | 30 | - | - | ? | results/phase4_ipc_network/30_mmap_fcntl_deep_20261015_200421.txt |
| 2026-10-15 20:10 | 30b | - | - | ? | results/phase4_ipc_network/30b_fcntl_scm_20261015_201028.txt |
| 2026-10-15 20:20 | 31 | - | - | ? | results/phase4_ipc_network/31_sockopt_fuzz_20261015_202000.txt |
| 2026-10-15 20:25 | 31b | - | - | ? | results/phase4_ipc_network/31b_tcpinfo_dump_20261015_202500.txt |
| 2026-10-15 20:30 | 31c | - | - | ? | results/phase4_ipc_network/31c_ps5opts_fuzz_20261015_203000.txt |
| 2026-10-15 20:45 | 32c | - | - | ? | results/phase5_buffer_io/32c_safe_stress_20261015_204500.txt |
| 2026-10-15 21:00 | 33f | - | - | ? | results/phase5_buffer_io/33f_dontwait_20261015_210000.txt |
| 2026-10-15 22:55 | 40 | - | - | ? | results/phase7_heap_exploitation/40_gpu_dmem_boundary_20261015_225541.txt |
| 2026-10-15 22:56 | 40 | - | - | ? | results/phase7_heap_exploitation/40_gpu_dmem_boundary_20261015_225641.txt |
| 2026-10-15 22:58 | 41 | - | - | ? | results/phase7_heap_exploitation/41_mmap_gpu_boundary_20261015_225812.txt |
| 2026-10-15 22:59 | 41b | - | - | ? | results/phase7_heap_exploitation/41b_mmap_gpu_boundary_20261015_225905.txt |
| 2026-10-15 22:59 | 41c | - | - | ? | results/phase7_heap_exploitation/41c_safe_adjacent_20261015_225952.txt |
| 2026-10-15 23:01 | 41d | - | - | ? | results/phase7_heap_exploitation/41d_heap_dump_20261015_230106.txt |
| 2026-10-15 23:02 | 41e | - | - | ? | results/phase7_heap_exploitation/41e_write_test_20261015_230228.txt |
| 2026-10-15 23:04 | 41f | - | - | ? | results/phase7_heap_exploitation/41f_heap_objects_20261015_230401.txt |
| 2026-10-15 23:04 | 41g | - | - | ? | results/phase7_heap_exploitation/41g_heap_objects_lite_20261015_230439.txt |
| 2026-10-15 23:06 | 41h | - | - | ? | results/phase7_heap_exploitation/41h_refcount_corrupt_20261015_230621.txt |
| 2026-10-15 23:08 | 41i | - | - | ? | results/phase7_heap_exploitation/41i_object_id_20261015_230841.txt |
| 2026-10-15 23:10 | 41j | - | - | ? | results/phase7_heap_exploitation/41j_uaf_spray_20261015_231032.txt |
| 2026-10-15 23:11 | 41k | - | - | ? | results/phase7_heap_exploitation/41k_uaf_wide_20261015_231128.txt |
| 2026-10-15 23:15 | 41l | - | - | ? | results/phase7_heap_exploitation/41l_vtable_dump_20261015_231544.txt |
| 2026-10-15 23:17 | 41m | - | - | ? | results/phase7_heap_exploitation/41m_type_desc_dump_20261015_231728.txt |
| 2026-10-15 23:18 | 41n | - | - | ? | results/phase7_heap_exploitation/41n_obj_vtable_20261015_231851.txt |
| 2026-10-15 23:20 | 41m | - | - | ? | results/phase7_heap_exploitation/41m_vtable_probe_20261015_232000.txt |
| 2026-10-15 23:21 | 41o | - | - | ? | results/phase7_heap_exploitation/41o_vtable_redirect_20261015_232102.txt |
| 2026-10-15 23:22 | 41p | - | - | ? | results/phase7_heap_exploitation/41p_gc_vtable_20261015_232246.txt |
| 2026-10-15 23:24 | 41o | - | - | ? | results/phase7_heap_exploitation/41o_heap_infoleak_20261015_232436.txt |
| 2026-10-15 23:25 | 41n | - | - | ? | results/phase7_heap_exploitation/41n_header_chase_20261015_232532.txt |
| 2026-10-15 23:27 | 41o | - | - | ? | results/phase7_heap_exploitation/41o_header_chase2_20261015_232741.txt |
| 2026-10-15 23:27 | 41p | - | - | ? | results/phase7_heap_exploitation/41p_libkernel_gadgets_20261015_232718.txt |
| 2026-10-15 23:28 | 41p | - | - | ? | results/phase7_heap_exploitation/41p_libkernel_gadgets_20261015_232807.txt |
| 2026-10-15 23:29 | 41q | - | - | ? | results/phase7_heap_exploitation/41q_segment_readability_20261015_232935.txt |
| 2026-10-15 23:30 | 41r | - | - | ? | results/phase7_heap_exploitation/41r_eboot_gadgets_20261015_233051.txt |
| 2026-10-15 23:31 | 41p | - | - | ? | results/phase7_heap_exploitation/41p_downward_scan_20261015_233152.txt |
| 2026-10-15 23:33 | 41q | - | - | ? | results/phase7_heap_exploitation/41q_anchor_scan_20261015_233343.txt |
| 2026-10-15 23:34 | 36 | - | - | ? | results/phase6_raw_packets/36_bind_port_sweep_20261015_233451.txt |
| 2026-10-15 23:34 | 41s | - | - | ? | results/phase7_heap_exploitation/41s_eboot_deep_scan_20261015_233451.txt |
| 2026-10-15 23:35 | 37 | - | - | ? | results/phase6_raw_packets/37_ip_options_20261015_233523.txt |
| 2026-10-15 23:35 | 39 | - | - | ? | results/phase6_raw_packets/39_frag_reass_20261015_233506.txt |
| 2026-10-15 23:35 | 41t | - | - | ? | results/phase7_heap_exploitation/41t_eboot_scan_tail_20261015_233542.txt |
| 2026-10-15 23:36 | 38 | - | - | ? | results/phase6_raw_packets/38_untested_syscalls_20261015_233617.txt |
| 2026-10-15 23:36 | 41u | - | - | ? | results/phase7_heap_exploitation/41u_find_syscall_ret_20261015_233642.txt |
| 2026-10-15 23:38 | 42a | - | - | ? | results/phase8_live_network/42a_ktimer_deep_20261015_233834.txt |
| 2026-10-15 23:39 | 41v | - | - | ? | results/phase7_heap_exploitation/41v_got_dump_20261015_233933.txt |
| 2026-10-15 23:39 | 42b | - | - | ? | results/phase8_live_network/42b_memfd_msync_20261015_233903.txt |
| 2026-10-15 23:43 | 41w | - | - | ? | results/phase7_heap_exploitation/41w_kernel_rw_20261015_234305.txt |
| 2026-10-15 23:47 | 40 | - | - | ? | results/phase8_live_network/40_tcp_connectback_20261015_234749.txt |
| 2026-10-15 23:52 | 41z | - | - | ? | results/phase7_heap_exploitation/41z_chain_hijack_20261015_235238.txt |
| 2026-10-16 00:00 | 40 | - | - | ? | results/phase8_live_network/40_tcp_connectback_20261016_000025.txt |
| 2026-10-16 06:55 | 42b | - | - | ? | results/phase9_kaslr_defeat/42b_kaslr_defeat_20261016_065521.txt |
| 2026-10-16 06:57 | 42c | - | - | ? | results/phase9_kaslr_defeat/42c_kaslr_deep_20261016_065713.txt |
| 2026-10-16 06:59 | 42d | - | - | ? | results/phase9_kaslr_defeat/42d_dmem_kaslr_20261016_065912.txt |
| 2026-10-16 07:00 | 42e | - | - | ? | results/phase9_kaslr_defeat/42e_sysctl_enum_20261016_070045.txt |
| 2026-10-16 07:02 | 42f | - | - | ? | results/phase9_kaslr_defeat/42f_ps5_syscall_scan_20261016_070223.txt |
| 2026-10-16 07:03 | 42f | - | - | ? | results/42f_kernel_phys_scan_20261016_070313.txt |
| 2026-10-16 07:04 | 42f2 | - | - | ? | results/42f2_fast_phys_scan_20261016_070400.txt |
| 2026-10-16 07:04 | 42g | - | - | ? | results/phase9_kaslr_defeat/42g_fnaddr_dump_20261016_070424.txt |
| 2026-10-16 07:05 | 42g | - | - | ? | results/42g_rop_kptr_leak_20261016_070509.txt |
| 2026-10-16 07:05 | 42h | - | - | ? | results/phase9_kaslr_defeat/42h_code_dump_20261016_070529.txt |
| 2026-10-16 07:06 | 42g3 | - | - | ? | results/42g3_high_phys_only_20261016_070632.txt |
| 2026-10-16 07:07 | 42g4 | - | - | ? | results/42g4_minimal_high_20261016_070704.txt |
| 2026-10-16 07:07 | 42i | - | - | ? | results/phase9_kaslr_defeat/42i_vmquery_20261016_070711.txt |
| 2026-10-16 07:08 | 42h | - | - | ? | results/42h_rop_exploit_20261016_070824.txt |
| 2026-10-16 07:09 | 42h2 | - | - | ? | results/42h2_rop_exploit2_20261016_070945.txt |
| 2026-10-16 07:10 | 42j | - | - | ? | results/phase9_kaslr_defeat/42j_thread_ptrace_20261016_071002.txt |
| 2026-10-16 07:11 | 42i | - | - | ? | results/42i_chain_analysis_20261016_071113.txt |
| 2026-10-16 18:06 | 43o | - | - | ? | results/43o_afroute_kaslr_20261016_180647.txt |
| 2026-10-16 18:06 | 43p | - | - | ? | results/43p_aio_bypass_20261016_180656.txt |
| 2026-10-16 18:07 | 43b | - | - | ? | results/43b_kldsym_resolve_20261016_180719.txt |
| 2026-10-16 18:07 | 43c | - | - | ? | results/43c_sysarch_gsbase_20261016_180744.txt |
| 2026-10-16 18:07 | 43d | - | - | ? | results/43d_kinfo_proc_full_20261016_180723.txt |
| 2026-10-16 18:07 | 43e | - | - | ? | results/43e_blocked_syscall_bypass_20261016_180750.txt |
| 2026-10-16 18:07 | 43i | - | - | ? | results/43i_fn_redirect_20261016_180730.txt |
| 2026-10-16 18:08 | 43g | - | - | ? | results/43g_sony_syscall_sweep_20261016_180802.txt |
| 2026-10-16 18:08 | 43h | - | - | ? | results/43h_mtypeprotect_wxbypass_20261016_180808.txt |
| 2026-10-16 18:08 | 43j | - | - | ? | results/43j_msgbuf_full_read_20261016_180815.txt |
| 2026-10-16 18:08 | 43k | - | - | ? | results/43k_cpuusage_deep_20261016_180826.txt |
| 2026-10-16 18:08 | 43l | - | - | ? | results/43l_mincore_kaslr_20261016_180845.txt |
| 2026-10-16 18:08 | 43m | - | - | ? | results/43m_sockopt_overflow_20261016_180851.txt |
| 2026-10-16 18:08 | 43n | - | - | ? | results/43n_hid_ioctl_20261016_180856.txt |
| 2026-10-16 18:25 | 44a | - | - | ? | results/44a_mtypeprotect_exec_20261016_182522.txt |
| 2026-10-16 18:25 | 44b | - | - | ? | results/44b_sony557_deep_20261016_182531.txt |
| 2026-10-16 18:25 | 44c | - | - | ? | results/44c_sockopt_heap_corrupt_20261016_182537.txt |
| 2026-10-16 18:25 | 44d | - | - | ? | results/44d_kaslr_creative_20261016_182544.txt |
| 2026-10-16 18:56 | 45a | - | - | ? | results/45a_native_exec_kaslr_20261016_185642.txt |
| 2026-10-16 19:13 | 45b | - | - | ? | results/45b_shellcode_write_diag_20261016_191357.txt |
| 2026-10-16 19:26 | 45c | - | - | ? | results/45c_execution_reality_check_20261016_192602.txt |
| 2026-10-16 19:47 | 46a | - | - | ? | results/46a_sony_syscall_deep_20261016_194741.txt |
| 2026-10-16 19:47 | 46b | - | - | ? | results/46b_loader_dispatch_20261016_194751.txt |
| 2026-10-16 19:48 | 46d | - | - | ? | results/46d_socket_bypass_20261016_194839.txt |
| 2026-10-16 19:56 | 47a | - | - | ? | results/47a_dispatch_deep_20261016_195632.txt |
| 2026-10-16 20:04 | 47b | - | - | ? | results/47b_cclosure_hijack_20261016_200432.txt |
| 2026-10-16 20:04 | 47b | - | - | ? | results/47b_cclosure_hijack_20261016_200459.txt |
| 2026-10-16 20:11 | 48a | - | - | ? | results/48a_sctp_ipv6_icmp_20261016_201145.txt |
| 2026-10-16 20:13 | 46c | - | - | ? | results/46c_ip_options_listener_20261016_201355.txt |
| 2026-10-16 20:58 | 49a | - | - | ? | results/49a_tcp_inject_loopback_20261016_205847.txt |
| 2026-10-16 21:29 | 50b | - | - | ? | results/50b_timer_manipulation_20261016_212925.txt |
| 2026-10-16 21:36 | 50c | - | - | ? | results/50c_resource_exhaustion_20261016_213603.txt |
| 2026-10-16 21:48 | 51a | - | - | ? | results/51a_sony_syscall_survey_20261016_214814.txt |
| 2026-10-16 21:48 | 51b | - | - | ? | results/51b_accessible_syscall_deep_20261016_214832.txt |
| 2026-10-16 21:58 | 51c | - | - | ? | results/51c_sony_survey_part2_20261016_215838.txt |
| 2026-10-16 22:08 | 51a | - | - | ? | results/51a_sony_syscall_survey_20261016_220811.txt |
| 2026-10-16 23:04 | 51b | - | - | ? | results/51b_dynlib_cluster_fuzz_20261016_230416.txt |
| 2026-10-18 03:22 | 54a | - | - | ? | results/54a_dsp_access_check_20261018_032250.txt |
| 2026-10-18 03:22 | 54a | - | - | ? | results/54a_dsp_access_check_20261018_032254.txt |
| 2026-10-18 08:32 | 01 | - | - | ? | results/01_identity_20261018_083215.txt |
| 2026-10-18 08:34 | 54i | - | - | ? | results/54i_sys567_pmc_read_20261018_083439.txt |
| 2026-10-18 08:36 | 54j | - | - | ? | results/54j_sys572_vm_deep_20261018_083604.txt |
| 2026-10-18 08:36 | 54j | - | - | ? | results/54j_sys624_oracle_20261018_083648.txt |
| 2026-10-18 09:05 | 54c | - | - | ? | results/54c_aio_full_attack_20261018_090527.txt |
| 2026-10-18 09:12 | 53b | - | - | ? | results/53b_afroute_retest_20261018_091237.txt |
| 2026-10-18 09:12 | 53b | - | - | ? | results/53b_afroute_retest_20261018_091257.txt |
| 2026-10-18 09:12 | 53b | - | - | ? | results/phase13_53batch/53b_afroute_retest_20261018_091257.txt |
| 2026-10-18 09:12 | 54e | - | - | ? | results/54e_device_fuzz_20261018_091240.txt |
| 2026-10-18 09:12 | 54e | - | - | ? | results/54e_device_fuzz_20261018_091259.txt |
| 2026-10-18 09:13 | 53d | - | - | ? | results/53d_cclosure_retest_20261018_091303.txt |
| 2026-10-18 09:13 | 53d | - | - | ? | results/phase13_53batch/53d_cclosure_retest_20261018_091303.txt |
| 2026-10-18 09:13 | 54a2 | - | - | ? | results/54a2_rdmsr_precise_20261018_091308.txt |
| 2026-10-18 09:13 | 54i | - | - | ? | results/54i_sys572_buffer_exam_20261018_091303.txt |
| 2026-10-18 09:18 | 54l | - | - | ? | results/54l_rwx_verify_20261018_091853.txt |
| 2026-10-18 09:18 | 54l | - | - | ? | results/phase14_final_push/54l_rwx_verify_20261018_091853.txt |
| 2026-10-18 09:20 | 54m | - | - | ? | results/54m_cclosure_redirect_20261018_092047.txt |
| 2026-10-18 09:20 | 54m | - | - | ? | results/phase14_final_push/54m_cclosure_redirect_20261018_092047.txt |
| 2026-10-18 09:24 | 54n | - | - | ? | results/54n_cclosure_real_cfunc_20261018_092406.txt |
| 2026-10-18 09:24 | 54n | - | - | ? | results/phase14_final_push/54n_cclosure_real_cfunc_20261018_092406.txt |
| 2026-10-18 09:27 | 54o | - | - | ? | results/54o_cfunc_redirect_controlled_20261018_092721.txt |
| 2026-10-18 09:27 | 54o | - | - | ? | results/phase14_final_push/54o_cfunc_redirect_controlled_20261018_092721.txt |
| 2026-10-18 09:30 | 54p | - | - | ? | results/54p_redirect_minimal_20261018_093008.txt |
| 2026-10-18 09:38 | 54p | - | - | ? | results/phase14_final_push/54p_redirect_minimal_20261018_093839.txt |
| 2026-10-18 09:39 | 01 | - | - | ? | results/phase1_identity_layout/01_identity_20261018_093937.txt |
| 2026-10-18 09:40 | 01 | - | - | ? | results/phase1_identity_layout/01_identity_20261018_094011.txt |
| 2026-10-18 09:40 | 01 | - | - | ? | results/phase1_identity_layout/01_identity_20261018_094017.txt |
| 2026-10-18 09:40 | 54p | - | - | ? | results/phase14_final_push/54p_redirect_minimal_20261018_094036.txt |
| 2026-10-18 09:41 | 01 | - | - | ? | results/phase1_identity_layout/01_identity_20261018_094103.txt |
| 2026-10-18 09:41 | 01 | - | - | ? | results/phase1_identity_layout/01_identity_20261018_094147.txt |
| 2026-10-18 09:42 | 01 | - | - | ? | results/phase1_identity_layout/01_identity_20261018_094249.txt |
| 2026-10-18 09:42 | 54p | - | - | ? | results/phase14_final_push/54p_redirect_minimal_20261018_094206.txt |
| 2026-10-18 09:43 | 01 | - | - | ? | results/phase1_identity_layout/01_identity_20261018_094355.txt |
| 2026-10-18 09:43 | 54p | - | - | ? | results/phase14_final_push/54p_redirect_minimal_20261018_094326.txt |
| 2026-10-18 09:45 | 54q | - | - | ? | results/phase14_final_push/54q_cfunc_redirect_return1_20261018_094551.txt |
| 2026-10-18 09:48 | 55b | - | - | ? | results/phase14_final_push/55b_batch_vm_ops_20261018_094849.txt |
| 2026-10-18 10:09 | 55f | - | - | ? | results/phase14_final_push/55f_674_deep_dump_20261018_100958.txt |
| 2026-10-18 10:34 | 52b | - | - | ? | results/phase13_52batch/52b_624_oracle_20261018_103451.txt |
| 2026-10-18 10:34 | 54r | - | - | ? | results/phase14_final_push/54r_cfunc_code_bytes_20261018_103421.txt |
| 2026-10-18 10:40 | 56a | - | - | ? | results/phase14_final_push/56a_controlled_redirect_20261018_104052.txt |
| 2026-10-18 10:41 | 56a | - | - | ? | results/phase14_final_push/56a_controlled_redirect_20261018_104142.txt |
| 2026-10-18 10:47 | 56a | - | - | ? | results/phase14_final_push/56a_controlled_redirect_20261018_104741.txt |
| 2026-10-18 11:01 | 56b | - | - | ? | results/phase14_final_push/56b_redirect_minimal_20261018_110114.txt |
| 2026-10-18 11:10 | 56b | - | - | ? | results/phase14_final_push/56b_redirect_minimal_20261018_111030.txt |
| 2026-10-18 11:16 | 56c | - | - | ? | results/phase14_final_push/56c_redirect_nonvm_20261018_111606.txt |
| 2026-10-18 11:16 | 56c | - | - | ? | results/phase14_final_push/56c_redirect_nonvm_20261018_111610.txt |
| 2026-10-18 11:21 | 56d | - | - | ? | results/phase14_final_push/56d_gadget_redirect_20261018_112132.txt |
| 2026-10-18 11:21 | 56d | - | - | ? | results/phase14_final_push/56d_gadget_redirect_20261018_112134.txt |
| 2026-10-18 11:22 | 56d | - | - | ? | results/phase14_final_push/56d_gadget_redirect_20261018_112241.txt |
| 2026-10-18 11:25 | 56e | - | - | ? | results/phase14_final_push/56e_clean_gadget_20261018_112542.txt |
| 2026-10-18 11:28 | 56f | - | - | ? | results/phase14_final_push/56f_controlled_return_20261018_112849.txt |
| 2026-10-18 11:34 | 56g | - | - | ? | results/phase14_final_push/56g_syscall_gadget_20261018_113423.txt |
| 2026-10-18 11:34 | 56g | - | - | ? | results/phase14_final_push/56g_syscall_gadget_20261018_113437.txt |
| 2026-10-18 11:45 | 56h | - | - | ? | results/phase14_final_push/56h_kldstat_kaslr_20261018_114516.txt |
| 2026-10-18 11:47 | 56h2 | - | - | ? | results/phase14_final_push/56h2_kldsym_kaslr_20261018_114736.txt |
| 2026-10-18 11:51 | 56i | - | - | ? | results/phase14_final_push/56i_unconventional_kaslr_20261018_115126.txt |
| 2026-10-18 11:55 | 56i2 | - | - | ? | results/phase14_final_push/56i2_kaslr_auxv_stack_20261018_115541.txt |
| 2026-10-18 11:58 | 56i3 | - | - | ? | results/phase14_final_push/56i3_kaslr_deep_scan_20261018_115832.txt |
| 2026-10-18 12:01 | 56i4 | - | - | ? | results/phase14_final_push/56i4_vm_region_dump_20261018_120109.txt |
| 2026-10-18 12:05 | 56i5 | - | - | ? | results/phase14_final_push/56i5_kptr_investigate_20261018_120505.txt |
| 2026-10-18 12:10 | 56i6 | - | - | ? | results/phase14_final_push/56i6_kaslr_pivot_20261018_121034.txt |
| 2026-10-18 12:13 | 56i7 | - | - | ? | results/phase14_final_push/56i7_kptr_validate_20261018_121302.txt |
| 2026-10-18 12:16 | 56i8 | - | - | ? | results/phase14_final_push/56i8_eboot_data_kptr_20261018_121608.txt |
| 2026-10-18 12:19 | 56i9 | - | - | ? | results/phase14_final_push/56i9_kaslr_bruteforce_20261018_121926.txt |
| 2026-10-18 12:21 | 56j | - | - | ? | results/phase14_final_push/56j_timing_kaslr_20261018_122158.txt |
| 2026-10-18 12:36 | 56k | - | - | ? | results/phase14_final_push/56k_kaslr_bruteforce_20261018_123645.txt |
| 2026-10-18 13:09 | 56k2 | - | - | ? | results/phase14_final_push/56k2_signal_oracle_20261018_130912.txt |
| 2026-10-18 13:10 | 56k2 | - | - | ? | results/phase14_final_push/56k2_signal_oracle_20261018_131048.txt |
| 2026-10-18 13:17 | 56k2 | - | - | ? | results/phase14_final_push/56k2_signal_oracle_20261018_131756.txt |
| 2026-10-18 13:22 | 56k2 | - | - | ? | results/phase14_final_push/56k2_signal_oracle_20261018_132218.txt |
| 2026-10-18 13:29 | 56k3 | - | - | ? | results/phase14_final_push/56k3_external_oracle_20261018_132915.txt |
| 2026-10-18 13:32 | 56k4 | - | - | ? | results/phase14_final_push/56k4_kldstat_kaslr_20261018_133209.txt |
| 2026-10-18 13:35 | 56k5 | - | - | ? | results/phase14_final_push/56k5_modsys_kaslr_20261018_133508.txt |
| 2026-10-19 08:48 | 58e | - | - | ? | results/phase16_thr_create_crash/58e_thr_create_reachability_20261019_084825.txt |
| 2026-10-19 08:48 | 58e | - | - | ? | results/phase16_thr_create_crash/58e_thr_create_ucontext_20261019_084859.txt |
| 2026-10-19 08:56 | 76c | - | - | ? | results/phase16_thr_create_crash/76c_thr_create_safe_longjmp_20261019_085609.txt |
| 2026-10-19 08:56 | 76c | - | - | ? | results/phase16_thr_create_crash/76c_thr_create_safe_longjmp_20261019_085651.txt |
| 2026-10-19 09:03 | 76d | - | - | ? | results/phase16_thr_create_crash/76d_thr_create_exit_only_20261019_090357.txt |
| 2026-10-19 09:04 | 76d | - | - | ? | results/phase16_thr_create_crash/76d_thr_create_exit_only_20261019_090422.txt |
| 2026-10-19 09:06 | 76d | - | - | ? | results/phase16_thr_create_crash/76d_thr_create_exit_only_20261019_090657.txt |
| 2026-10-19 09:12 | 76e | - | - | ? | results/phase16_thr_create_crash/76e_thr_create_exit_wait_20261019_091202.txt |
| 2026-10-19 18:46 | 79a | - | - | ? | results/phase17_seg_hypothesis/79a_getmcontext_layout_20261019_184618.txt |
| 2026-10-19 18:46 | 79a | - | - | ? | results/phase17_seg_hypothesis/79a_getmcontext_layout_20261019_184646.txt |
| 2026-10-19 18:47 | 113a | - | - | ? | results/phase17_new_vectors/113a_untested_handler_trio_20261019_184749.txt |
| 2026-10-19 18:48 | 110a | - | - | ? | results/phase19_umtx_454/110a_umtx_shm_reachability_20261019_184821.txt |
| 2026-10-19 18:48 | 113a | - | - | ? | results/phase17_new_vectors/113a_untested_handler_trio_sectionB_20261019_184806.txt |
| 2026-10-19 18:48 | 113a | - | - | ? | results/phase17_new_vectors/113a_untested_handler_trio_sectionC_20261019_184808.txt |
| 2026-10-19 18:48 | 113a | - | - | ? | results/phase17_new_vectors/113a_untested_handler_trio_sectionD_20261019_184810.txt |
| 2026-10-19 18:48 | 87a | - | - | ? | results/phase17_new_vectors/87a_sys532_gpu_dispatch_nopriv_20261019_184839.txt |
| 2026-10-19 18:48 | 87a | - | - | ? | results/phase17_new_vectors/87a_sys532_gpu_dispatch_nopriv_sectionB_20261019_184850.txt |
| 2026-10-19 18:48 | 87a | - | - | ? | results/phase17_new_vectors/87a_sys532_gpu_dispatch_nopriv_sectionC_20261019_184851.txt |
| 2026-10-19 18:49 | 100a | - | - | ? | results/phase17_new_vectors/100a_kernel_table_modlist_20261019_184946.txt |
| 2026-10-19 18:49 | 101a | - | - | ? | results/phase17_new_vectors/101a_sys628_mmap_variant_20261019_184947.txt |
| 2026-10-19 18:49 | 104a | - | - | ? | results/phase17_new_vectors/104a_dispatch_internals_20261019_184947.txt |
| 2026-10-19 18:49 | 56l | - | - | ? | results/phase14_final_push/56l_corrected_mib_probe_20261019_184914.txt |
| 2026-10-19 18:49 | 57d | - | - | ? | results/phase15_native_sysent/57d_loader_dispatch_hunt_20261019_184916.txt |
| 2026-10-19 18:49 | 57e | - | - | ? | results/phase15_native_sysent/57e_jail_reachability_20261019_184919.txt |
| 2026-10-19 18:49 | 57e | - | - | ? | results/phase15_native_sysent/57e_jail_reachability_20261019_184945.txt |
| 2026-10-19 18:49 | 59a | - | - | ? | results/phase15_native_sysent/59a_linux_abi_detection_20261019_184946.txt |
| 2026-10-19 18:50 | 107a | - | - | ? | results/phase17_new_vectors/107a_syscall_addr_finder_20261019_185036.txt |
| 2026-10-19 18:51 | 109a | - | - | ? | results/phase17_new_vectors/109a_kernel_infoleak_sweep_20261019_185105.txt |
| 2026-10-19 18:51 | 118a | - | - | ? | results/phase17_new_vectors/118a_eboot_syscall_scanner_20261019_185114.txt |
| 2026-10-19 18:51 | 119a | - | - | ? | results/phase17_new_vectors/119a_evfilt_proc_leak_20261019_185117.txt |
| 2026-10-19 18:52 | 119a | - | - | ? | results/phase17_new_vectors/119a_evfilt_proc_leak_20261019_185223.txt |
| 2026-10-19 18:52 | 121a | - | - | ? | results/phase17_new_vectors/121a_procctl_comprehensive_20261019_185226.txt |
| 2026-10-19 18:53 | 100a | - | - | ? | results/phase17_new_vectors/100a_kernel_table_modlist_sectionB_20261019_185355.txt |
| 2026-10-19 18:53 | 100a | - | - | ? | results/phase17_new_vectors/100a_kernel_table_modlist_sectionC_20261019_185356.txt |
| 2026-10-19 18:53 | 100a | - | - | ? | results/phase17_new_vectors/100a_kernel_table_modlist_sectionD_20261019_185356.txt |
| 2026-10-19 18:53 | 119a | - | - | ? | results/phase17_new_vectors/119a_evfilt_proc_leak_no_self_signal_20261019_185317.txt |
| 2026-10-19 18:53 | 121a | - | - | ? | results/phase17_new_vectors/121a_procctl_comprehensive_20261019_185317.txt |
| 2026-10-19 18:53 | 79d | - | - | ? | results/phase17_new_vectors/79d_shm_sem_mqueuee_20261019_185320.txt |
| 2026-10-19 18:53 | 87a | - | - | ? | results/phase17_new_vectors/87a_sys532_gpu_dispatch_nopriv_sectionD_20261019_185338.txt |
| 2026-10-19 18:53 | 91a | - | - | ? | results/phase17_new_vectors/91a_sys630_mount_enum_20261019_185318.txt |
| 2026-10-19 18:53 | 91a | - | - | ? | results/phase17_new_vectors/91a_sys630_mount_enum_sectionB_20261019_185357.txt |
| 2026-10-19 18:53 | 91a | - | - | ? | results/phase17_new_vectors/91a_sys630_mount_enum_sectionC_20261019_185358.txt |
| 2026-10-19 18:53 | 91a | - | - | ? | results/phase17_new_vectors/91a_sys630_mount_enum_sectionD_20261019_185359.txt |
| 2026-10-19 18:53 | 94a | - | - | ? | results/phase17_new_vectors/94a_pmu_counter_read_20261019_185318.txt |
| 2026-10-19 18:54 | 101a | - | - | ? | results/phase17_new_vectors/101a_sys628_mmap_variant_sectionB_20261019_185404.txt |
| 2026-10-19 18:54 | 101a | - | - | ? | results/phase17_new_vectors/101a_sys628_mmap_variant_sectionC_20261019_185405.txt |
| 2026-10-19 18:54 | 101a | - | - | ? | results/phase17_new_vectors/101a_sys628_mmap_variant_sectionD_20261019_185405.txt |
| 2026-10-19 18:54 | 50e | - | - | ? | results/phase11_network_attacks/50e_ipv6_msfilter_reach_20261019_185428.txt |
| 2026-10-19 18:54 | 50e | - | - | ? | results/phase11_network_attacks/50e_ipv6_msfilter_reach_20261019_185451.txt |
| 2026-10-19 18:54 | 58a | - | - | ? | results/phase15_native_sysent/58a_msync_reachability_20261019_185431.txt |
| 2026-10-19 18:54 | 58d | - | - | ? | results/phase15_native_sysent/58d_shm_sendfile_reachability_20261019_185429.txt |
| 2026-10-19 18:54 | 58f | - | - | ? | results/phase2_kernel_objects/58f_kevent_timeout_matrix_20261019_185428.txt |
| 2026-10-19 18:54 | 94a | - | - | ? | results/phase17_new_vectors/94a_pmu_counter_read_sectionB_20261019_185403.txt |
| 2026-10-19 18:54 | 94a | - | - | ? | results/phase17_new_vectors/94a_pmu_counter_read_sectionC_20261019_185403.txt |
| 2026-10-19 18:55 | 110a | - | - | ? | results/phase17_new_vectors/110a_vm_page_manipulation_20261019_185544.txt |
| 2026-10-19 18:55 | 120a | - | - | ? | results/phase17_new_vectors/120a_pdfork_capsicum_20261019_185541.txt |
| 2026-10-19 18:55 | 58f | - | - | ? | results/phase2_kernel_objects/58f_kevent_timeout_matrix_20261019_185526.txt |
| 2026-10-19 18:55 | 58f | - | - | ? | results/phase2_kernel_objects/58f_kevent_timeout_matrix_20261019_185532.txt |
| 2026-10-19 19:43 | 110a | - | - | ? | results/phase17_new_vectors/110a_vm_page_manipulation_20261019_194310.txt |
| 2026-10-19 19:43 | 110a | - | - | ? | results/phase17_new_vectors/110a_vm_page_manipulation_sectionD4_20261019_194349.txt |
| 2026-10-19 19:43 | 110a | - | - | ? | results/phase17_new_vectors/110a_vm_page_manipulation_sectionE1_20261019_194354.txt |
| 2026-10-19 19:43 | 110a | - | - | ? | results/phase17_new_vectors/110a_vm_page_manipulation_sectionE2_20261019_194358.txt |
| 2026-10-19 19:44 | 108a | - | - | ? | results/phase17_new_vectors/108a_scm_rights_fd_lifecycle_20261019_194427.txt |
| 2026-10-19 19:45 | 108a | - | - | ? | results/phase17_new_vectors/108a_scm_rights_fd_lifecycle_20261019_194507.txt |
| 2026-10-19 19:46 | 108a | - | - | ? | results/phase17_new_vectors/108a_scm_rights_fd_lifecycle_20261019_194610.txt |
| 2026-10-19 19:46 | 32e | - | - | ? | results/phase5_buffer_io/32e_ping_20261019_194621.txt |
| 2026-10-19 19:47 | 108a | - | - | ? | results/phase17_new_vectors/108a_scm_rights_fd_lifecycle_20261019_194758.txt |
| 2026-10-19 19:47 | 32e | - | - | ? | results/phase5_buffer_io/32e_ping_20261019_194756.txt |
| 2026-10-19 19:48 | 111a | - | - | ? | results/phase17_new_vectors/111a_heap_feng_shui_20261019_194806.txt |
| 2026-10-19 19:48 | 111a | - | - | ? | results/phase17_new_vectors/111a_heap_feng_shui_sectionB_20261019_194822.txt |
| 2026-10-19 19:48 | 32e | - | - | ? | results/phase5_buffer_io/32e_ping_20261019_194857.txt |
| 2026-10-19 19:48 | 57c | - | - | ? | results/phase15_native_sysent/57c_kldsym_direct_20261019_194850.txt |
| 2026-10-19 19:49 | 112a | - | - | ? | results/phase17_new_vectors/112a_sys605_gpu_rw_flag_or_20261019_194911.txt |
| 2026-10-19 19:49 | 112a | - | - | ? | results/phase17_new_vectors/112a_sys605_gpu_rw_flag_or_sectionB_20261019_194917.txt |
| 2026-10-19 19:49 | 112a | - | - | ? | results/phase17_new_vectors/112a_sys605_gpu_rw_flag_or_sectionC_20261019_194921.txt |
| 2026-10-19 19:49 | 112a | - | - | ? | results/phase17_new_vectors/112a_sys605_gpu_rw_flag_or_sectionD_20261019_194924.txt |
| 2026-10-19 19:49 | 112a | - | - | ? | results/phase17_new_vectors/112a_sys605_gpu_rw_flag_or_sectionE_20261019_194926.txt |
| 2026-10-19 19:49 | 59b | - | - | ? | results/phase15_native_sysent/59b_thr_family_survey_20261019_194932.txt |
| 2026-10-19 19:49 | 79a | - | - | ? | results/phase17_new_vectors/79a_devdsp_pipe2_procctl_20261019_194903.txt |
| 2026-10-19 19:49 | 86a | - | - | ? | results/phase17_new_vectors/86a_aio_real_handlers_20261019_194953.txt |
| 2026-10-19 19:50 | 83a | - | - | ? | results/phase17_new_vectors/83a_sys601_deep_retest_20261019_195006.txt |
| 2026-10-19 19:50 | 83a | - | - | ? | results/phase17_new_vectors/83a_sys601_deep_retest_sectionB_20261019_195019.txt |
| 2026-10-19 19:50 | 83a | - | - | ? | results/phase17_new_vectors/83a_sys601_deep_retest_sectionC_20261019_195022.txt |
| 2026-10-19 19:50 | 83a | - | - | ? | results/phase17_new_vectors/83a_sys601_deep_retest_sectionD_20261019_195026.txt |
| 2026-10-19 19:50 | 84a | - | - | ? | results/phase17_new_vectors/84a_sys653_gpu_pte_nopriv_20261019_195033.txt |
| 2026-10-19 19:50 | 84a | - | - | ? | results/phase17_new_vectors/84a_sys653_gpu_pte_nopriv_sectionC_20261019_195040.txt |
| 2026-10-19 19:50 | 86a | - | - | ? | results/phase17_new_vectors/86a_aio_real_handlers_sectionB_20261019_195000.txt |
| 2026-10-19 19:50 | 86a | - | - | ? | results/phase17_new_vectors/86a_aio_real_handlers_sectionC_20261019_195003.txt |
| 2026-10-19 19:50 | 95a | - | - | ? | results/phase17_new_vectors/95a_aio_subsystem_20261019_195054.txt |
| 2026-10-19 19:51 | 32e | - | - | ? | results/phase5_buffer_io/32e_ping_20261019_195148.txt |
| 2026-10-19 19:51 | 57a | - | - | ? | results/phase15_native_sysent/57a_native_survey_677_734_20261019_195140.txt |
| 2026-10-19 19:51 | 95a | - | - | ? | results/phase17_new_vectors/95a_aio_subsystem_sectionB_20261019_195100.txt |
| 2026-10-19 19:51 | 95a | - | - | ? | results/phase17_new_vectors/95a_aio_subsystem_sectionC_20261019_195103.txt |
| 2026-10-19 19:51 | 95a | - | - | ? | results/phase17_new_vectors/95a_aio_subsystem_sectionD_20261019_195106.txt |
| 2026-10-19 19:54 | 32e | - | - | ? | results/phase5_buffer_io/32e_ping_20261019_195438.txt |
| 2026-10-19 19:54 | 95a | - | - | ? | results/phase17_new_vectors/95a_aio_subsystem_sectionD_20261019_195443.txt |
| 2026-10-19 19:54 | 95b | - | - | ? | results/phase17_new_vectors/95b_aio_one_byte_completion_20261019_195448.txt |
| 2026-10-19 19:55 | 117a | - | - | ? | results/phase17_new_vectors/117a_gadget_redirect_clean_20261019_195553.txt |
| 2026-10-19 19:55 | 95c | - | - | ? | results/phase17_new_vectors/95c_aio_invalid_fd_lifecycle_20261019_195516.txt |
| 2026-10-19 19:59 | 117a | - | - | ? | results/phase17_new_vectors/117a_gadget_redirect_clean_20261019_195949.txt |
| 2026-10-19 19:59 | 120a | - | - | ? | results/phase17_new_vectors/120a_pdfork_capsicum_20261019_195932.txt |
| 2026-10-19 19:59 | 121a | - | - | ? | results/phase17_new_vectors/121a_procctl_comprehensive_20261019_195926.txt |
| 2026-10-19 20:00 | 118a | - | - | ? | results/phase17_new_vectors/118a_eboot_syscall_scanner_20261019_200023.txt |
| 2026-10-19 20:00 | 119a | - | - | ? | results/phase17_new_vectors/119a_evfilt_proc_leak_20261019_200000.txt |
| 2026-10-19 20:01 | 122a | - | - | ? | results/phase17_new_vectors/122a_syscall_finder_targeted_20261019_200151.txt |
| 2026-10-19 20:03 | 122b | - | - | ? | results/phase17_new_vectors/122b_syscall_scan_chunk2_20261019_200353.txt |
| 2026-10-19 20:14 | 123a | - | - | ? | results/phase17_new_vectors/123a_stack_probe_chain_20261019_201421.txt |
| 2026-10-19 20:16 | 123c | - | - | ? | results/phase17_new_vectors/123c_stack_capture_safe_20261019_201649.txt |
| 2026-10-19 20:18 | 123d | - | - | ? | results/phase17_new_vectors/123d_gadget_effects_20261019_201812.txt |
| 2026-10-19 20:40 | 123e | - | - | ? | results/phase17_new_vectors/123e_single_gadget_tests_20261019_204044.txt |
| 2026-10-19 20:42 | 123f | - | - | ? | results/phase17_new_vectors/123f_gadget_survival_v2_20261019_204209.txt |
| 2026-10-19 20:43 | 123g | - | - | ? | results/phase17_new_vectors/123g_compound_gadget_scan_20261019_204339.txt |
| 2026-10-19 20:44 | 123h | - | - | ? | results/phase17_new_vectors/123h_compound_scan_safe_20261019_204448.txt |
| 2026-10-19 20:45 | 123i | - | - | ? | results/phase17_new_vectors/123i_fast_compound_scan_20261019_204548.txt |
| 2026-10-19 20:49 | 123j | - | - | ? | results/phase17_new_vectors/123j_micro_compound_scan_20261019_204954.txt |
| 2026-10-19 20:52 | 123k | - | - | ? | results/phase17_new_vectors/123k_aligned_compound_only_20261019_205258.txt |
| 2026-10-19 20:54 | 123l | - | - | ? | results/phase17_new_vectors/123l_upper_eboot_scan_20261019_205452.txt |
| 2026-10-19 20:56 | 123m | - | - | ? | results/phase17_new_vectors/123m_stack_pivot_scan_20261019_205605.txt |
| 2026-10-19 20:57 | 123n | - | - | ? | results/phase17_new_vectors/123n_compound_test_20261019_205746.txt |
| 2026-10-19 20:58 | 123n | - | - | ? | results/phase17_new_vectors/123n_compound_test_20261019_205802.txt |
| 2026-10-19 20:59 | 123o | - | - | ? | results/phase17_new_vectors/123o_xor_ret_context_20261019_205920.txt |
| 2026-10-19 21:08 | 108a | - | - | ? | results/phase17_new_vectors/108a_scm_rights_fd_lifecycle_20261019_210852.txt |
| 2026-10-19 21:22 | 108b | - | - | ? | results/phase17_new_vectors/108b_mini_test_20261019_212218.txt |
| 2026-10-19 21:34 | 108b | - | - | ? | results/phase17_new_vectors/108b_mini_test_20261019_213428.txt |
| 2026-10-19 21:50 | 80a | - | - | ? | results/phase17_new_vectors/80a_thr_create_cs43_threading_20261019_215051.txt |
| 2026-10-19 21:51 | 80a | - | - | ? | results/phase17_new_vectors/80a_thr_create_cs43_threading_20261019_215106.txt |
| 2026-10-19 21:51 | 80a | - | - | ? | results/phase17_new_vectors/80a_thr_create_cs43_threading_20261019_215140.txt |
| 2026-10-19 21:51 | 80a | - | - | ? | results/phase17_new_vectors/80a_thr_create_cs43_threading_20261019_215154.txt |
| 2026-10-19 21:52 | 80a | - | - | ? | results/phase17_new_vectors/80a_thr_create_cs43_threading_20261019_215205.txt |
| 2026-10-19 21:55 | 80b | - | - | ? | results/phase17_new_vectors/80b_thread_rop_chain_20261019_215520.txt |
| 2026-10-19 21:58 | 80b | - | - | ? | results/phase17_new_vectors/80b_thread_rop_chain_20261019_215840.txt |
| 2026-10-19 22:00 | 80c | - | - | ? | results/phase17_new_vectors/80c_thread_register_exec_20261019_220059.txt |
| 2026-10-19 22:02 | 80c | - | - | ? | results/phase17_new_vectors/80c_thread_register_exec_20261019_220250.txt |
| 2026-10-19 22:04 | 80d | - | - | ? | results/phase17_new_vectors/80d_thread_diag_20261019_220426.txt |
| 2026-10-19 22:07 | 80e | - | - | ? | results/phase17_new_vectors/80e_cs_sweep_20261019_220708.txt |
| 2026-10-19 22:12 | 80f | - | - | ? | results/phase17_new_vectors/80f_get_current_cs_20261019_221206.txt |
| 2026-10-19 22:13 | 80g | - | - | ? | results/phase17_new_vectors/80g_thread_correct_offsets_20261019_221341.txt |
| 2026-10-19 22:15 | 80h | - | - | ? | results/phase17_new_vectors/80h_thread_write_test_20261019_221511.txt |
| 2026-10-19 22:15 | 80i | - | - | ? | results/phase17_new_vectors/80i_thread_write_final_20261019_221559.txt |
| 2026-10-19 22:16 | 80i | - | - | ? | results/phase17_new_vectors/80i_thread_write_final_20261019_221625.txt |
| 2026-10-19 22:17 | 80i | - | - | ? | results/phase17_new_vectors/80i_thread_write_final_20261019_221714.txt |
| 2026-10-19 22:17 | 80i | - | - | ? | results/phase17_new_vectors/80i_thread_write_final_20261019_221733.txt |
| 2026-10-19 22:20 | 80j | - | - | ? | results/phase17_new_vectors/80j_two_stage_20261019_222020.txt |
| 2026-10-19 22:22 | 80j | - | - | ? | results/phase17_new_vectors/80j_two_stage_20261019_222255.txt |
| 2026-10-19 22:23 | 80j | - | - | ? | results/phase17_new_vectors/80j_two_stage_20261019_222346.txt |
| 2026-10-19 22:25 | 80j | - | - | ? | results/phase17_new_vectors/80j_two_stage_20261019_222512.txt |
| 2026-10-19 22:28 | 80j | - | - | ? | results/phase17_new_vectors/80j_two_stage_20261019_222818.txt |
| 2026-10-19 22:28 | 80j | - | - | ? | results/phase17_new_vectors/80j_two_stage_20261019_222842.txt |
| 2026-10-19 22:31 | 80j | - | - | ? | results/phase17_new_vectors/80j_two_stage_20261019_223100.txt |
| 2026-10-19 22:33 | 80k | - | - | ? | results/phase17_new_vectors/80k_rop_chain_20261019_223328.txt |
| 2026-10-19 22:33 | 80k | - | - | ? | results/phase17_new_vectors/80k_rop_chain_20261019_223354.txt |
| 2026-10-19 22:40 | 80k | - | - | ? | results/phase17_new_vectors/80k_rop_chain_20261019_224016.txt |
| 2026-10-19 22:40 | 80l | - | - | ? | results/phase17_new_vectors/80l_gadget_scan_20261019_224044.txt |
| 2026-10-19 22:41 | 80m | - | - | ? | results/phase17_new_vectors/80m_toctou_race_20261019_224154.txt |
| 2026-10-19 22:43 | 80n | - | - | ? | results/phase17_new_vectors/80n_infinite_thread_20261019_224321.txt |
| 2026-10-19 22:47 | 80n | - | - | ? | results/phase17_new_vectors/80n_infinite_thread_20261019_224728.txt |
| 2026-10-19 22:48 | 80m | - | - | ? | results/phase17_new_vectors/80m_toctou_race_20261019_224845.txt |
| 2026-10-19 22:48 | 80n | - | - | ? | results/phase17_new_vectors/80n_infinite_thread_20261019_224822.txt |
| 2026-10-19 22:54 | 80o | - | - | ? | results/phase17_new_vectors/80o_socket_race_20261019_225401.txt |
| 2026-10-19 22:55 | 80p | - | - | ? | results/phase17_new_vectors/80p_umtx_shm_20261019_225551.txt |
| 2026-10-19 23:07 | 80q | - | - | ? | results/phase17_new_vectors/80q_umtx_race_20261019_230755.txt |
| 2026-10-19 23:09 | 80r | - | - | ? | results/phase17_new_vectors/80r_umtx_wait_race_20261019_230958.txt |
| 2026-10-19 23:12 | 80r | - | - | ? | results/phase17_new_vectors/80r_umtx_wait_race_20261019_231233.txt |
| 2026-10-19 23:14 | 100a | - | - | ? | results/autonomous/100a_kernel_table_modlist_20261019_231428.txt |
| 2026-10-19 23:14 | 80r | - | - | ? | results/phase17_new_vectors/80r_umtx_wait_race_20261019_231457.txt |
| 2026-10-19 23:16 | 102a | - | - | ? | results/autonomous/102a_chicken_combined_chain_20261019_231621.txt |
| 2026-10-19 23:22 | 100a | - | - | ? | results/autonomous/100a_kernel_table_modlist_20261019_232205.txt |
| 2026-10-19 23:24 | 100a | - | - | ? | results/autonomous/100a_kernel_table_modlist_20261019_232421.txt |
| 2026-10-19 23:24 | 101a | - | - | ? | results/autonomous/101a_sys628_mmap_variant_20261019_232441.txt |
| 2026-10-19 23:25 | 102a | - | - | ? | results/autonomous/102a_chicken_combined_chain_20261019_232500.txt |
| 2026-10-19 23:25 | 103a | - | - | ? | results/autonomous/103a_sys588_rwx_cclosure_exec_20261019_232519.txt |
| 2026-10-19 23:27 | 104a | - | - | ? | results/autonomous/104a_dispatch_internals_20261019_232741.txt |
| 2026-10-19 23:28 | 105a | - | - | ? | results/autonomous/105a_evfilt_proc_kptr_leak_20261019_232800.txt |
| 2026-10-19 23:28 | 106a | - | - | ? | results/autonomous/106a_sigreturn_srop_20261019_232820.txt |
| 2026-10-19 23:28 | 107a | - | - | ? | results/autonomous/107a_syscall_addr_finder_20261019_232839.txt |
| 2026-10-19 23:30 | 108a | - | - | ? | results/autonomous/108a_scm_rights_fd_lifecycle_20261019_233040.txt |
| 2026-10-19 23:30 | 108b | - | - | ? | results/autonomous/108b_mini_test_20261019_233059.txt |
| 2026-10-19 23:34 | 80v | - | - | ? | results/phase17_new_vectors/80v_minimal_dispatch_20261019_233453.txt |
| 2026-10-19 23:35 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261019_233503.txt |
| 2026-10-19 23:36 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261019_233608.txt |
| 2026-10-19 23:38 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261019_233822.txt |
| 2026-10-19 23:40 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261019_234026.txt |
| 2026-10-19 23:42 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261019_234253.txt |
| 2026-10-19 23:45 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261019_234519.txt |
| 2026-10-19 23:45 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261019_234552.txt |
| 2026-10-19 23:46 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261019_234658.txt |
| 2026-10-19 23:48 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261019_234803.txt |
| 2026-10-19 23:48 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261019_234853.txt |
| 2026-10-19 23:51 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261019_235115.txt |
| 2026-10-19 23:54 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261019_235417.txt |
| 2026-10-20 00:21 | 81a | - | - | ? | results/phase17_new_vectors/81a_env_enumerate_20261020_002153.txt |
| 2026-10-20 00:26 | 82b | - | - | ? | results/phase17_new_vectors/82b_kernel_rw_init_20261020_002639.txt |
| 2026-10-20 00:28 | 83b | - | - | ? | results/phase17_new_vectors/83b_pivot_data_dump_20261020_002834.txt |
| 2026-10-20 00:30 | 83d | - | - | ? | results/phase17_new_vectors/83d_fcall_bytecode_dump_20261020_003000.txt |
| 2026-10-20 00:32 | 83f | - | - | ? | results/phase17_new_vectors/83f_safe_prereqs_20261020_003244.txt |
| 2026-10-20 00:34 | 84a | - | - | ? | results/phase17_new_vectors/84a_manual_pivot_init_20261020_003437.txt |
| 2026-10-20 00:36 | 84c | - | - | ? | results/phase17_new_vectors/84c_resolve_test_20261020_003658.txt |
| 2026-10-20 00:39 | 84e | - | - | ? | results/phase17_new_vectors/84e_minimal_syscall_20261020_003917.txt |
| 2026-10-20 00:41 | 84g | - | - | ? | results/phase17_new_vectors/84g_syscall_interface_20261020_004154.txt |
| 2026-10-20 00:43 | 84i | - | - | ? | results/phase17_new_vectors/84i_uint64_args_20261020_004358.txt |
| 2026-10-20 00:44 | 84j | - | - | ? | results/phase17_new_vectors/84j_socket_uint64_20261020_004411.txt |
| 2026-10-20 00:46 | 84k | - | - | ? | results/phase17_new_vectors/84k_setsockopt_test_20261020_004626.txt |
| 2026-10-20 00:46 | 84l | - | - | ? | results/phase17_new_vectors/84l_sockopt_scan_20261020_004652.txt |
| 2026-10-20 00:48 | 85c | - | - | ? | results/phase17_new_vectors/85c_getsockopt_safe_20261020_004842.txt |
| 2026-10-20 00:50 | 85e | - | - | ? | results/phase17_new_vectors/85e_step_by_step_20261020_005006.txt |
| 2026-10-20 00:53 | 85g | - | - | ? | results/phase17_new_vectors/85g_kptr_safe_20261020_005321.txt |
| 2026-10-20 00:58 | 85i | - | - | ? | results/phase17_new_vectors/85i_kevent_v2_20261020_005807.txt |
| 2026-10-20 01:02 | 86a | - | - | ? | results/phase17_new_vectors/86a_native_read_test_20261020_010207.txt |
| 2026-10-20 01:04 | 86c | - | - | ? | results/phase17_new_vectors/86c_kernel_wire_20261020_010440.txt |
| 2026-10-20 01:09 | 86e | - | - | ? | results/phase17_new_vectors/86e_upvalue_safe_20261020_010945.txt |
| 2026-10-20 01:16 | 86g | - | - | ? | results/phase17_new_vectors/86g_minimal_rw_20261020_011649.txt |
| 2026-10-20 01:19 | 87a | - | - | ? | results/phase17_new_vectors/87a_fd_table_scan_20261020_011945.txt |
| 2026-10-20 01:23 | 87c | - | - | ? | results/phase17_new_vectors/87c_ipv6_strings_20261020_012307.txt |
| 2026-10-20 01:25 | 87e | - | - | ? | results/phase17_new_vectors/87e_fsbase_safe_20261020_012533.txt |
| 2026-10-20 01:30 | 87g | - | - | ? | results/phase17_new_vectors/87g_data_quick_20261020_013048.txt |
| 2026-10-20 01:38 | 88b | - | - | ? | results/phase17_new_vectors/88b_storage_only_20261020_013857.txt |
| 2026-10-20 01:44 | 88d | - | - | ? | results/phase17_new_vectors/88d_safe_pipe_dump_20261020_014405.txt |
| 2026-10-20 01:46 | 88f | - | - | ? | results/phase17_new_vectors/88f_eboot_data_scan_20261020_014637.txt |
| 2026-10-20 01:50 | 88h | - | - | ? | results/phase17_new_vectors/88h_kptr_chunks_20261020_015035.txt |
| 2026-10-20 02:35 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_023548.txt |
| 2026-10-20 02:35 | 80x | - | - | ? | results/phase17_new_vectors/80x_cclosure_pointer_minimal_20261020_023553.txt |
| 2026-10-20 02:36 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_023625.txt |
| 2026-10-20 02:36 | 80z | - | - | ? | results/phase17_new_vectors/80z_native_fcall_closure_20261020_023616.txt |
| 2026-10-20 02:37 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_023745.txt |
| 2026-10-20 02:37 | 80za | - | - | ? | results/phase17_new_vectors/80za_native_fcall_classify_20261020_023749.txt |
| 2026-10-20 02:38 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_023820.txt |
| 2026-10-20 02:38 | 80y | - | - | ? | results/phase17_new_vectors/80y_sys728_isolated_20261020_023811.txt |
| 2026-10-20 02:40 | 109b | - | - | ? | results/phase17_new_vectors/109b_fstat_kqueue_isolated_20261020_024019.txt |
| 2026-10-20 02:40 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_024017.txt |
| 2026-10-20 02:40 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_024055.txt |
| 2026-10-20 02:41 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_024104.txt |
| 2026-10-20 02:42 | 109c | - | - | ? | results/phase17_new_vectors/109c_fstat_only_no_close_20261020_024225.txt |
| 2026-10-20 02:42 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_024221.txt |
| 2026-10-20 02:42 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_024233.txt |
| 2026-10-20 02:43 | 109d | - | - | ? | results/phase17_new_vectors/109d_fstat_fd0_control_20261020_024359.txt |
| 2026-10-20 02:43 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_024324.txt |
| 2026-10-20 02:43 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_024355.txt |
| 2026-10-20 02:44 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_024405.txt |
| 2026-10-20 02:44 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_024431.txt |
| 2026-10-20 02:44 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_024452.txt |
| 2026-10-20 02:45 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_024511.txt |
| 2026-10-20 02:45 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_024559.txt |
| 2026-10-20 02:46 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_024629.txt |
| 2026-10-20 02:49 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_024938.txt |
| 2026-10-20 02:50 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_025028.txt |
| 2026-10-20 02:51 | 109c | - | - | ? | results/phase17_new_vectors/109c_fstat_only_no_close_20261020_025129.txt |
| 2026-10-20 02:51 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_025120.txt |
| 2026-10-20 02:51 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_025133.txt |
| 2026-10-20 02:52 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_025224.txt |
| 2026-10-20 02:53 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_025313.txt |
| 2026-10-20 02:53 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_025328.txt |
| 2026-10-20 02:53 | 85h | - | - | ? | results/phase17_new_vectors/85h_kevent_leak_20261020_025323.txt |
| 2026-10-20 02:54 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_025412.txt |
| 2026-10-20 02:54 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_025444.txt |
| 2026-10-20 02:54 | 85j | - | - | ? | results/phase17_new_vectors/85j_kevent_socketpair_20261020_025408.txt |
| 2026-10-20 02:55 | 109e | - | - | ? | results/phase17_new_vectors/109e_local_peercred_20261020_025504.txt |
| 2026-10-20 02:55 | 109e | - | - | ? | results/phase17_new_vectors/109e_local_peercred_20261020_025512.txt |
| 2026-10-20 02:55 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_025515.txt |
| 2026-10-20 02:56 | 109f | - | - | ? | results/phase17_new_vectors/109f_unix_sockaddr_20261020_025628.txt |
| 2026-10-20 02:56 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_025612.txt |
| 2026-10-20 02:56 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_025631.txt |
| 2026-10-20 02:57 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_025743.txt |
| 2026-10-20 02:58 | 108c | - | - | ? | results/phase17_new_vectors/108c_scm_rights_cmsg_isolated_20261020_025803.txt |
| 2026-10-20 02:58 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_025806.txt |
| 2026-10-20 02:59 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_025913.txt |
| 2026-10-20 03:00 | 109g | - | - | ? | results/phase17_new_vectors/109g_getsockopt_isolated_20261020_030002.txt |
| 2026-10-20 03:00 | 109h | - | - | ? | results/phase17_new_vectors/109h_kevent_filters_isolated_20261020_030055.txt |
| 2026-10-20 03:00 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_030005.txt |
| 2026-10-20 03:00 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_030044.txt |
| 2026-10-20 03:00 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_030059.txt |
| 2026-10-20 03:02 | 53e | - | - | ? | results/phase17_new_vectors/53e_kldsym_single_20261020_030243.txt |
| 2026-10-20 03:02 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_030214.txt |
| 2026-10-20 03:02 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_030248.txt |
| 2026-10-20 03:03 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_030325.txt |
| 2026-10-20 03:03 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_030358.txt |
| 2026-10-20 03:04 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_030444.txt |
| 2026-10-20 03:05 | 109i | - | - | ? | results/phase17_new_vectors/109i_fstat_fd_classes_20261020_030517.txt |
| 2026-10-20 03:05 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_030522.txt |
| 2026-10-20 03:06 | 59c | - | - | ? | results/phase17_new_vectors/59c_thr_get_ucontext_self_20261020_030643.txt |
| 2026-10-20 03:06 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_030619.txt |
| 2026-10-20 03:06 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_030647.txt |
| 2026-10-20 03:08 | 53b | - | - | ? | results/phase13_53batch/53b_afroute_retest_20261020_030812.txt |
| 2026-10-20 03:08 | 53b | - | - | ? | results/phase13_53batch/53b_afroute_retest_20261020_030848.txt |
| 2026-10-20 03:08 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_030828.txt |
| 2026-10-20 03:09 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_030910.txt |
| 2026-10-20 03:10 | 53g | - | - | ? | results/phase17_new_vectors/53g_afroute_single_valid_20261020_031032.txt |
| 2026-10-20 03:10 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_031020.txt |
| 2026-10-20 03:10 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_031037.txt |
| 2026-10-20 03:11 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_031146.txt |
| 2026-10-20 03:12 | 110b | - | - | ? | results/phase17_new_vectors/110b_standard_copyout_20261020_031208.txt |
| 2026-10-20 03:12 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261020_031212.txt |
| 2026-10-20 03:46 | 89d | - | - | ? | results/phase17_new_vectors/89d_native_introspect_20261020_034651.txt |
| 2026-10-20 03:47 | 125a | - | - | ? | results/phase17_new_vectors/125a_ipv6_krw_init_20261020_034735.txt |
| 2026-10-20 03:47 | 125b | - | - | ? | results/phase17_new_vectors/125b_read_kernel_lua_20261020_034758.txt |
| 2026-10-20 03:48 | 125c | - | - | ? | results/phase17_new_vectors/125c_native_exec_bootstrap_20261020_034841.txt |
| 2026-10-20 03:52 | 125d | - | - | ? | results/phase17_new_vectors/125d_fcall_safe_20261020_035259.txt |
| 2026-10-20 03:53 | 125e | - | - | ? | results/phase17_new_vectors/125e_fcall_getpid_real_20261020_035331.txt |
| 2026-10-20 03:58 | 125f | - | - | ? | results/phase17_new_vectors/125f_read_native_source_20261020_035856.txt |
| 2026-10-20 03:59 | 125g | - | - | ? | results/phase17_new_vectors/125g_addrofs_and_fcall_20261020_035930.txt |
| 2026-10-20 03:59 | 125g | - | - | ? | results/phase17_new_vectors/125g_addrofs_and_fcall_20261020_035940.txt |
| 2026-10-20 04:00 | 125h | - | - | ? | results/phase17_new_vectors/125h_read_main_20261020_040014.txt |
| 2026-10-20 04:00 | 125i | - | - | ? | results/phase17_new_vectors/125i_read_all_sources_20261020_040030.txt |
| 2026-10-20 04:03 | 125j | - | - | ? | results/phase17_new_vectors/125j_fcall_via_wrapper_20261020_040329.txt |
| 2026-10-20 04:04 | 125k | - | - | ? | results/phase17_new_vectors/125k_read_misc_and_bypass_20261020_040418.txt |
| 2026-10-20 04:06 | 125l | - | - | ? | results/phase17_new_vectors/125l_ropchain_syscall_20261020_040609.txt |
| 2026-10-20 04:07 | 125m | - | - | ? | results/phase17_new_vectors/125m_heap_kptr_scan_20261020_040708.txt |
| 2026-10-20 04:10 | 126a | - | - | ? | results/phase17_new_vectors/126a_thr_create_ropchain_20261020_041031.txt |
| 2026-10-20 04:10 | 126b | - | - | ? | results/phase17_new_vectors/126b_read_ropchain_source_20261020_041048.txt |
| 2026-10-20 04:11 | 126c | - | - | ? | results/phase17_new_vectors/126c_thr_create_fixed_20261020_041143.txt |
| 2026-10-20 04:12 | 126d | - | - | ? | results/phase17_new_vectors/126d_live_thread_20261020_041252.txt |
| 2026-10-20 04:14 | 126e | - | - | ? | results/phase17_new_vectors/126e_thr_correct_offsets_20261020_041430.txt |
| 2026-10-20 04:15 | 126f | - | - | ? | results/phase17_new_vectors/126f_thr_mclen_20261020_041526.txt |
| 2026-10-20 04:17 | 126g | - | - | ? | results/phase17_new_vectors/126g_thrd_create_20261020_041700.txt |
| 2026-10-20 04:18 | 126h | - | - | ? | results/phase17_new_vectors/126h_thread_exec_20261020_041814.txt |
| 2026-10-20 04:21 | 127a | - | - | ? | results/phase17_new_vectors/127a_thread_rop_20261020_042125.txt |
| 2026-10-20 04:58 | 129a | - | - | ? | results/phase17_new_vectors/129a_smart_pivot_scan_20261020_045854.txt |
| 2026-10-20 06:41 | 129b | - | - | ? | results/phase17_new_vectors/129b_native_test_20261020_064157.txt |
| 2026-10-20 06:45 | 145a | - | - | ? | results/phase17_new_vectors/145a_kaslr_spray_oracle_20261020_064552.txt |
| 2026-10-20 06:56 | 147a | - | - | ? | results/phase17_new_vectors/147a_safe_ipv6_race_20261020_065601.txt |
| 2026-10-20 06:58 | 148a | - | - | ? | results/phase17_new_vectors/148a_threaded_sockopt_race_20261020_065817.txt |
| 2026-10-20 07:51 | 150a | - | - | ? | results/phase17_new_vectors/150a_dump_kernel_lua_20261020_075120.txt |
| 2026-10-20 08:45 | 153a | - | - | ? | results/phase19_umtx_454/153a_shm_threaded_race_20261020_084524.txt |
| 2026-10-20 08:46 | 139a | - | - | ? | results/phase17_new_vectors/139a_sysent_677_734_20261020_084616.txt |
| 2026-10-20 09:17 | 56i | - | - | ? | results/phase14_cclosure_redirect/56i_native_register_20261020_091741.txt |
| 2026-10-20 09:20 | 56k | - | - | ? | results/phase14_cclosure_redirect/56k_kernel_read_20261020_092058.txt |
| 2026-10-20 09:21 | 56k | - | - | ? | results/phase14_cclosure_redirect/56k_kernel_read_20261020_092112.txt |
| 2026-10-20 09:32 | 56l | - | - | ? | results/phase14_cclosure_redirect/56l_umtx_shm_deep_20261020_093254.txt |
| 2026-10-20 10:06 | 56i5b | - | - | ? | results/phase14_final_push/56i5b_ro_candidate_fingerprint_20261020_100603.txt |
| 2026-10-20 10:15 | 56s | - | - | ? | results/phase14_cclosure_redirect/56s_thr_errno_20261020_101531.txt |
| 2026-10-20 10:16 | 32e | - | - | ? | results/phase5_buffer_io/32e_ping_20261020_101631.txt |
| 2026-10-20 10:16 | 56i5 | - | - | ? | results/phase14_final_push/56i5_kptr_investigate_20261020_101653.txt |
| 2026-10-20 10:16 | 56i5b | - | - | ? | results/phase14_final_push/56i5b_ro_candidate_fingerprint_20261020_101635.txt |
| 2026-10-20 10:17 | 32e | - | - | ? | results/phase5_buffer_io/32e_ping_20261020_101751.txt |
| 2026-10-20 10:17 | 56i5b | - | - | ? | results/phase14_final_push/56i5b_ro_candidate_fingerprint_20261020_101756.txt |
| 2026-10-20 10:19 | 100a | - | - | ? | results/phase17_new_vectors/100a_kernel_table_modlist_sectionC_20261020_101957.txt |
| 2026-10-20 10:22 | 152b | - | - | ? | results/phase19_umtx_454/152b_shm_heap_safe_20261020_102211.txt |
| 2026-10-20 10:23 | 152c | - | - | ? | results/phase19_umtx_454/152c_shm_threaded_uaf_20261020_102320.txt |
| 2026-10-20 10:27 | 152d | - | - | ? | results/phase19_umtx_454/152d_shm_race_clean_20261020_102752.txt |
| 2026-10-20 10:34 | 152e | - | - | ? | results/phase19_umtx_454/152e_shm_race_fcall_20261020_103437.txt |
| 2026-10-20 10:35 | 152f | - | - | ? | results/phase19_umtx_454/152f_shm_slab_reclaim_20261020_103556.txt |
| 2026-10-20 10:36 | 152f | - | - | ? | results/phase19_umtx_454/152f_shm_slab_reclaim_20261020_103613.txt |
| 2026-10-20 10:37 | 152g | - | - | ? | results/phase19_umtx_454/152g_shm_same_type_reclaim_20261020_103742.txt |
| 2026-10-20 10:39 | 152h | - | - | ? | results/phase19_umtx_454/152h_shm_thread_pressure_20261020_103935.txt |
| 2026-10-20 10:41 | 152i | - | - | ? | results/phase19_umtx_454/152i_shm_key_semantics_20261020_104133.txt |
| 2026-10-20 10:51 | 153b | - | - | ? | results/phase19_umtx_454/153b_umtx_safe_sweep_20261020_105149.txt |
| 2026-10-20 14:48 | hello | - | - | ? | results/hello_probe_20261020_144853.txt |
| 2026-10-20 15:17 | 92a | - | - | ? | results/92a_run_b_20261020_151718.txt |
| 2026-10-20 15:17 | 92a | - | - | ? | results/92a_run_c_20261020_151753.txt |
| 2026-10-20 15:17 | 92a | - | - | ? | results/phase17_new_vectors/92a_pmu_hardware_exploit_20261020_151702.txt |
| 2026-10-20 15:18 | 94a | - | - | ? | results/94a_run_b_20261020_151814.txt |
| 2026-10-20 15:18 | 94a | - | - | ? | results/94a_run_c_20261020_151821.txt |
| 2026-10-20 15:18 | 94a | - | - | ? | results/phase17_new_vectors/94a_pmu_counter_read_20261020_151807.txt |
| 2026-10-20 15:20 | 95a | - | - | ? | results/phase17_new_vectors/95a_pmu_cross_connection_stability_20261020_152023.txt |
| 2026-10-20 15:20 | 95a | - | - | ? | results/phase17_new_vectors/95a_pmu_cross_connection_stability_20261020_152024.txt |
| 2026-10-20 15:20 | 95a | - | - | ? | results/phase17_new_vectors/95a_pmu_cross_connection_stability_20261020_152025.txt |
| 2026-10-20 15:20 | 95a | - | - | ? | results/phase17_new_vectors/95a_pmu_cross_connection_stability_20261020_152024_mtxoo0bx/95a_pmu_cross_connection_stability_20261020_152024.txt |
| 2026-10-20 15:20 | 95a | - | - | ? | results/phase17_new_vectors/95a_pmu_cross_connection_stability_20261020_152025_l7tojqy1/95a_pmu_cross_connection_stability_20261020_152025.txt |
| 2026-10-20 15:25 | 87a | - | - | ? | results/phase17_new_vectors/87a_sys532_gpu_dispatch_nopriv_20261020_152539.txt |
| 2026-10-20 15:25 | 87a | - | - | ? | results/phase17_new_vectors/87a_sys532_gpu_dispatch_nopriv_20261020_152557.txt |
| 2026-10-20 15:26 | 83a | - | - | ? | results/phase17_new_vectors/83a_sys601_deep_retest_20261020_152638.txt |
| 2026-10-20 15:26 | 83a | - | - | ? | results/phase17_new_vectors/83a_sys601_deep_retest_20261020_152658.txt |
| 2026-10-20 15:26 | 98a | - | - | ? | results/98a_B_20261020_152620.txt |
| 2026-10-20 15:26 | 98a | - | - | ? | results/phase17_new_vectors/98a_gpu_pte_wxbypass_20261020_152606.txt |
| 2026-10-20 15:27 | 84a | - | - | ? | results/phase17_new_vectors/84a_sys653_gpu_pte_nopriv_20261020_152707.txt |
| 2026-10-20 15:27 | 88a | - | - | ? | results/phase17_new_vectors/88a_handle_namespace_confusion_20261020_152742.txt |
| 2026-10-20 15:27 | 89a | - | - | ? | results/phase17_new_vectors/89a_sys625_msr_controller_20261020_152757.txt |
| 2026-10-20 15:27 | 99a | - | - | ? | results/99a_B_20261020_152730.txt |
| 2026-10-20 15:27 | 99a | - | - | ? | results/phase17_new_vectors/99a_hw_write_vm_selfmod_20261020_152717.txt |
| 2026-10-20 15:28 | 85a | - | - | ? | results/phase17_new_vectors/85a_dispatch_retaddr_global_20261020_152809.txt |
| 2026-10-20 15:28 | 93a | - | - | ? | results/phase17_new_vectors/93a_gpu_vm_range_ops_20261020_152816.txt |
| 2026-10-20 15:28 | 93a | - | - | ? | results/phase17_new_vectors/93a_gpu_vm_range_ops_20261020_152838.txt |
| 2026-10-20 15:30 | 93a | - | - | ? | results/phase17_new_vectors/93a_gpu_vm_range_ops_20261020_153016.txt |
| 2026-10-20 16:34 | 80a | - | - | ? | results/phase17_new_vectors/80a_thr_create_cs43_threading_20261020_163406.txt |
| 2026-10-20 16:38 | 156a | - | - | ? | results/phase17_new_vectors/156a_thr_create_spin_observable_20261020_163827.txt |
| 2026-10-20 16:39 | 156b | - | - | ? | results/phase17_new_vectors/156b_ucontext_layout_20261020_163929.txt |
| 2026-10-20 16:42 | 80e | - | - | ? | results/phase17_new_vectors/80e_thr_create_child_executes_20261020_164252.txt |
| 2026-10-20 16:44 | 156d | - | - | ? | results/phase17_new_vectors/156d_thr_create_child_executes_20261020_164412.txt |
| 2026-10-20 16:44 | 89a | - | - | ? | results/89a_B_20261020_164441.txt |
| 2026-10-20 16:44 | 92a | - | - | ? | results/92a_D_20261020_164446.txt |
| 2026-10-20 16:44 | 93a | - | - | ? | results/93a_A_20261020_164434.txt |
| 2026-10-20 16:44 | 96a | - | - | ? | results/96a_A_20261020_164436.txt |
| 2026-10-20 16:45 | 89a | - | - | ? | results/89a_sys625_msr_controller_B_20261020_164517.txt |
| 2026-10-20 17:11 | 157a | - | - | ? | results/phase17_new_vectors/157a_syscall_loop_thread_20261020_171137.txt |
| 2026-10-20 17:13 | 157a | - | - | ? | results/phase17_new_vectors/157a_syscall_loop_thread_20261020_171313.txt |
| 2026-10-20 17:15 | 157a | - | - | ? | results/phase17_new_vectors/157a_syscall_loop_thread_20261020_171551.txt |
| 2026-10-20 17:17 | 157a | - | - | ? | results/phase17_new_vectors/157a_syscall_loop_thread_20261020_171737.txt |
| 2026-10-20 17:18 | 157b | - | - | ? | results/phase17_new_vectors/157b_memory_readback_shape_20261020_171837.txt |
| 2026-10-20 17:19 | 89a | - | - | ? | results/89a_sys625_msr_controller_B_20261020_171912.txt |
| 2026-10-20 17:19 | 92a | - | - | ? | results/92a_pmu_hardware_exploit_D_20261020_171914.txt |
| 2026-10-20 17:19 | 96a | - | - | ? | results/96a_handle_namespace_uaf_B_20261020_171916.txt |
| 2026-10-20 17:19 | 98a | - | - | ? | results/98a_gpu_pte_wxbypass_C_20261020_171918.txt |
| 2026-10-20 17:21 | 157a | - | - | ? | results/phase17_new_vectors/157a_syscall_loop_thread_20261020_172142.txt |
| 2026-10-20 17:22 | 157a | - | - | ? | results/phase17_new_vectors/157a_syscall_loop_thread_20261020_172245.txt |
| 2026-10-20 17:23 | 160a | - | - | ? | results/160a_kaslr_fingerprint_boot1_20261020_172345.txt |
| 2026-10-20 17:24 | 160a | - | - | ? | results/160a_kaslr_fingerprint_boot1_20261020_172423.txt |
| 2026-10-20 17:28 | 160a | - | - | ? | results/160a_kaslr_fingerprint_boot1_20261020_172811.txt |
| 2026-10-20 17:32 | 160a | - | - | ? | results/160a_kaslr_fingerprint_boot1_20261020_173247.txt |
| 2026-10-20 17:33 | pmu | - | - | ? | results/pmu_diag_20261020_173358.txt |
| 2026-10-20 17:34 | 160a | - | - | ? | results/160a_boot1_20261020_173454.txt |
| 2026-10-20 17:39 | 161a | - | - | ? | results/161a_boot1_20261020_173947.txt |
| 2026-10-20 17:42 | 158a | - | - | ? | results/phase17_new_vectors/158a_thread_rop_syscall_20261020_174216.txt |
| 2026-10-20 17:44 | 161a | - | - | ? | results/161a_boot2_20261020_174434.txt |
| 2026-10-20 17:46 | 158a | - | - | ? | results/phase17_new_vectors/158a_thread_rop_syscall_20261020_174615.txt |
| 2026-10-20 17:53 | 158a | - | - | ? | results/phase17_new_vectors/158a_thread_rop_syscall_20261020_175327.txt |
| 2026-10-20 17:55 | 158a | - | - | ? | results/phase17_new_vectors/158a_thread_rop_syscall_20261020_175502.txt |
| 2026-10-20 17:56 | 158b | - | - | ? | results/phase17_new_vectors/158b_thread_syscall_args_20261020_175611.txt |
| 2026-10-20 17:58 | 161a | - | - | ? | results/161a_boot3_20261020_175830.txt |
| 2026-10-20 17:59 | 158c | - | - | ? | results/phase17_new_vectors/158c_thread_syscall_number_20261020_175955.txt |
| 2026-10-20 18:05 | 159a | - | - | ? | results/phase17_new_vectors/159a_syscall_path_control_20261020_180533.txt |
| 2026-10-20 18:05 | 162a | - | - | ? | results/162a_leak_hunt_20261020_180523.txt |
| 2026-10-20 18:07 | 160a | - | - | ? | results/phase17_new_vectors/160a_thread_umtx_return_20261020_180702.txt |
| 2026-10-20 18:09 | 161a | - | - | ? | results/phase17_new_vectors/161a_umtx_op_enumeration_20261020_180927.txt |
| 2026-10-20 18:11 | 161a | - | - | ? | results/phase17_new_vectors/161a_umtx_op_enumeration_20261020_181142.txt |
| 2026-10-20 18:12 | 164a | - | - | ? | results/164a_165a_sysctl_summary_20261020_181240.txt |
| 2026-10-20 18:14 | 162a | - | - | ? | results/phase17_new_vectors/162a_umtx_arg_validation_20261020_181434.txt |
| 2026-10-20 18:14 | 163a | - | - | ? | results/phase17_new_vectors/163a_umtx_timeout_pointer_20261020_181458.txt |
| 2026-10-20 18:15 | 164a | - | - | ? | results/phase17_new_vectors/164a_umtx_contended_timeout_20261020_181521.txt |
| 2026-10-20 18:15 | 164a | - | - | ? | results/phase17_new_vectors/164a_umtx_contended_timeout_20261020_181543.txt |
| 2026-10-20 18:17 | 165a | - | - | ? | results/phase17_new_vectors/165a_umtx_block_wake_20261020_181724.txt |
| 2026-10-20 18:17 | 165a | - | - | ? | results/phase17_new_vectors/165a_umtx_block_wake_20261020_181736.txt |
| 2026-10-20 18:18 | 165a | - | - | ? | results/phase17_new_vectors/165a_umtx_block_wake_20261020_181810.txt |
| 2026-10-20 18:20 | 166a | - | - | ? | results/phase17_new_vectors/166a_umtx_pointer_args_20261020_182031.txt |
| 2026-10-20 18:23 | 167a | - | - | ? | results/phase17_new_vectors/167a_umtx_unlock_candidate_20261020_182310.txt |
| 2026-10-20 18:23 | 168a | - | - | ? | results/phase17_new_vectors/168a_umtx_unlock_val_20261020_182344.txt |
| 2026-10-20 18:28 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261020_182830.txt |
| 2026-10-20 18:31 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261020_183119.txt |
| 2026-10-20 18:33 | 169a | - | - | ? | results/phase17_new_vectors/169a_sys_668_argument_shape_20261020_183349.txt |
| 2026-10-20 18:33 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261020_183322.txt |
| 2026-10-20 18:37 | 170a | - | - | ? | results/phase17_new_vectors/170a_sys_670_side_effects_20261020_183724.txt |
| 2026-10-20 18:38 | 171a | - | - | ? | results/phase17_new_vectors/171a_kldsym_lookup_20261020_183815.txt |
| 2026-10-20 18:42 | 172a | - | - | ? | results/phase17_new_vectors/172a_sysctlbyname_20261020_184210.txt |
| 2026-10-20 18:44 | 173a | - | - | ? | results/phase17_new_vectors/173a_unimplemented_syscall_slot_20261020_184436.txt |
| 2026-10-20 18:52 | 174a | - | - | ? | results/phase17_new_vectors/174a_present_aio_handlers_20261020_185216.txt |
| 2026-10-20 18:52 | 175a | - | - | ? | results/phase17_new_vectors/175a_aio_layout_sweep_20261020_185233.txt |
| 2026-10-20 18:52 | 175a | - | - | ? | results/phase17_new_vectors/175a_aio_layout_sweep_20261020_185250.txt |
| 2026-10-20 18:53 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261020_185359.txt |
| 2026-10-20 18:54 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261020_185415.txt |
| 2026-10-20 19:00 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261020_190003.txt |
| 2026-10-20 19:02 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261020_190202.txt |
| 2026-10-20 19:04 | 176a | - | - | ? | results/phase17_new_vectors/176a_thread_absent_syscall_20261020_190459.txt |
| 2026-10-20 19:06 | 176b | - | - | ? | results/phase17_new_vectors/176b_563_buffer_writes_20261020_190630.txt |
| 2026-10-20 19:06 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261020_190649.txt |
| 2026-10-20 19:09 | 177a | - | - | ? | results/phase17_new_vectors/177a_563_564_selector_20261020_190922.txt |
| 2026-10-20 19:09 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261020_190943.txt |
| 2026-10-20 19:12 | 177b | - | - | ? | results/phase17_new_vectors/177b_opmc_establish_20261020_191252.txt |
| 2026-10-20 19:17 | 177c | - | - | ? | results/phase17_new_vectors/177c_opmc_value_surface_20261020_191711.txt |
| 2026-10-20 19:17 | 177d | - | - | ? | results/phase17_new_vectors/177d_opmc_state_20261020_191735.txt |
| 2026-10-20 19:38 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261020_193825.txt |
| 2026-10-20 19:41 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261020_194148.txt |
| 2026-10-20 19:42 | 179a | - | - | ? | results/phase17_new_vectors/179a_debug_rwmem_args_20261020_194237.txt |
| 2026-10-20 19:42 | 179a | - | - | ? | results/phase17_new_vectors/179a_debug_rwmem_args_20261020_194248.txt |
| 2026-10-20 19:42 | 179a | - | - | ? | results/phase17_new_vectors/179a_debug_rwmem_args_20261020_194254.txt |
| 2026-10-20 19:43 | 179a | - | - | ? | results/phase17_new_vectors/179a_debug_rwmem_args_20261020_194308.txt |
| 2026-10-20 19:43 | 180a | - | - | ? | results/phase17_new_vectors/180a_opmc_hw_20261020_194332.txt |
| 2026-10-20 19:43 | 181a | - | - | ? | results/phase17_new_vectors/181a_opmc_set_hw_surface_20261020_194345.txt |
| 2026-10-20 19:43 | 182a | - | - | ? | results/phase17_new_vectors/182a_opmc_get_hw_surface_20261020_194358.txt |
| 2026-10-20 19:44 | 182a | - | - | ? | results/phase17_new_vectors/182a_opmc_get_hw_surface_20261020_194411.txt |
| 2026-10-20 19:44 | 182a | - | - | ? | results/phase17_new_vectors/182a_opmc_get_hw_surface_20261020_194421.txt |
| 2026-10-20 19:44 | 183a | - | - | ? | results/phase17_new_vectors/183a_blockpool_20261020_194445.txt |
| 2026-10-20 19:45 | 184a | - | - | ? | results/phase17_new_vectors/184a_blockpool_batch_20261020_194508.txt |
| 2026-10-20 19:46 | 185a | - | - | ? | results/phase17_new_vectors/185a_telemetry_buffers_20261020_194653.txt |
| 2026-10-20 19:47 | 186a | - | - | ? | results/phase17_new_vectors/186a_count_and_aio_structs_20261020_194723.txt |
| 2026-10-20 20:02 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261020_200248.txt |
| 2026-10-20 20:03 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261020_200319.txt |
| 2026-10-20 20:07 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261020_200753.txt |
| 2026-10-20 20:14 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261020_201435.txt |
| 2026-10-20 20:35 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261020_203523.txt |
| 2026-10-20 20:50 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261020_205040.txt |
| 2026-10-20 20:54 | 187a | - | - | ? | results/phase17_new_vectors/187a_sys94_wedge_20261020_205430.txt |
| 2026-10-20 20:56 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261020_205641.txt |
| 2026-10-20 20:56 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261020_205654.txt |
| 2026-10-20 21:02 | 188a | - | - | ? | results/phase17_new_vectors/188a_sys94_repeat_20261020_210214.txt |
| 2026-10-20 21:02 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261020_210224.txt |
| 2026-10-20 21:06 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261020_210647.txt |
| 2026-10-20 21:08 | 189a | - | - | ? | results/phase17_new_vectors/189a_cs_selector_mask_20261020_210825.txt |
| 2026-10-20 21:30 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261020_213026.txt |
| 2026-10-20 22:34 | bounds | - | - | ? | results/phase17_new_vectors/bounds_fuzz_20261020_223442.txt |
| 2026-10-20 22:46 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261020_224601.txt |
| 2026-10-20 23:02 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261020_230242.txt |
| 2026-10-21 08:51 | 32e | - | - | ? | results/phase5_buffer_io/32e_ping_20261021_085148.txt |
| 2026-10-21 08:52 | 32e | - | - | ? | results/phase5_buffer_io/32e_ping_20261021_085222.txt |
| 2026-10-21 08:52 | 32e | - | - | ? | results/phase5_buffer_io/32e_ping_20261021_085252.txt |
| 2026-10-21 08:52 | 96a | - | - | ? | results/phase17_new_vectors/96a_aio_duplicate_delete_20261021_085256.txt |
| 2026-10-21 08:53 | 32e | - | - | ? | results/phase5_buffer_io/32e_ping_20261021_085302.txt |
| 2026-10-21 09:00 | 32e | - | - | ? | results/phase5_buffer_io/32e_ping_20261021_090036.txt |
| 2026-10-21 09:01 | 32e | - | - | ? | results/phase5_buffer_io/32e_ping_20261021_090111.txt |
| 2026-10-21 09:02 | 32e | - | - | ? | results/phase5_buffer_io/32e_ping_20261021_090242.txt |
| 2026-10-21 09:11 | 32e | - | - | ? | results/phase5_buffer_io/32e_ping_20261021_091132.txt |
| 2026-10-21 09:12 | 110b | - | - | ? | results/phase19_umtx_454/110b_pi_mutex_baseline_20261021_091207.txt |
| 2026-10-21 09:12 | 110c | - | - | ? | results/phase20_pup_device/110c_pup_device_access_20261021_091203.txt |
| 2026-10-21 11:36 | 190a | - | - | ? | results/phase17_new_vectors/190a_blockpool_fd_semantics_20261021_113658.txt |
| 2026-10-21 11:37 | 191a | - | - | ? | results/phase17_new_vectors/191a_blockpool_descriptor_20261021_113741.txt |
| 2026-10-21 11:40 | 191a | - | - | ? | results/phase17_new_vectors/191a_blockpool_descriptor_20261021_114008.txt |
| 2026-10-21 11:59 | 192a | - | - | ? | results/phase17_new_vectors/192a_stateful_abi_20261021_115932.txt |
| 2026-10-21 12:00 | 193a | - | - | ? | results/phase17_new_vectors/193a_handle_lifecycle_20261021_120012.txt |
| 2026-10-21 12:00 | 194a | - | - | ? | results/phase17_new_vectors/194a_evf_argument_order_20261021_120042.txt |
| 2026-10-21 12:01 | 195a | - | - | ? | results/phase17_new_vectors/195a_evf_mask_mode_20261021_120109.txt |
| 2026-10-21 12:02 | 197a | - | - | ? | results/phase17_new_vectors/197a_handle_class_confusion_20261021_120244.txt |
| 2026-10-21 12:03 | 198a | - | - | ? | results/phase17_new_vectors/198a_query_memory_record_20261021_120317.txt |
| 2026-10-21 12:04 | 199a | - | - | ? | results/phase17_new_vectors/199a_rwmem_statistics_20261021_120407.txt |
| 2026-10-21 12:04 | 199a | - | - | ? | results/phase17_new_vectors/199a_rwmem_statistics_20261021_120421.txt |
| 2026-10-21 12:05 | 200a | - | - | ? | results/phase17_new_vectors/200a_evf_wait_blocking_20261021_120516.txt |
| 2026-10-21 12:05 | 201a | - | - | ? | results/phase17_new_vectors/201a_evf_delete_under_wait_20261021_120547.txt |
| 2026-10-21 12:06 | 202a | - | - | ? | results/phase17_new_vectors/202a_evf_wait_layout_20261021_120645.txt |
| 2026-10-21 12:10 | 203a | - | - | ? | results/phase17_new_vectors/203a_evf_deadline_timer_20261021_121034.txt |
| 2026-10-21 12:10 | 203a | - | - | ? | results/phase17_new_vectors/203a_evf_deadline_timer_20261021_121044.txt |
| 2026-10-21 12:11 | 204a | - | - | ? | results/phase17_new_vectors/204a_evf_clock_20261021_121111.txt |
| 2026-10-21 12:11 | 205a | - | - | ? | results/phase17_new_vectors/205a_evf_deadline_clock_20261021_121124.txt |
| 2026-10-21 12:11 | 205a | - | - | ? | results/phase17_new_vectors/205a_evf_deadline_clock_20261021_121135.txt |
| 2026-10-21 12:14 | 206a | - | - | ? | results/phase17_new_vectors/206a_evf_timeout_unit_20261021_121433.txt |
| 2026-10-21 12:15 | 207a | - | - | ? | results/phase17_new_vectors/207a_evf_timeout_corners_20261021_121507.txt |
| 2026-10-21 12:18 | 209a | - | - | ? | results/phase17_new_vectors/209a_evf_waiter_across_reuse_20261021_121811.txt |
| 2026-10-21 12:18 | 210a | - | - | ? | results/phase17_new_vectors/210a_evf_generation_wrap_20261021_121823.txt |
| 2026-10-21 12:18 | 211a | - | - | ? | results/phase17_new_vectors/211a_evf_generation_sequence_20261021_121831.txt |
| 2026-10-21 12:18 | 212a | - | - | ? | results/phase17_new_vectors/212a_evf_stale_handle_20261021_121844.txt |
| 2026-10-21 12:18 | 213a | - | - | ? | results/phase17_new_vectors/213a_evf_class_blind_20261021_121853.txt |
| 2026-10-21 12:20 | 216a | - | - | ? | results/phase17_new_vectors/216a_evf_name_bound_20261021_122014.txt |
| 2026-10-21 12:44 | 83b | - | - | ? | results/phase22_threaded_races/83b_sys601_threaded_auth_20261021_124459.txt |
| 2026-10-21 12:47 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261021_124747.txt |
| 2026-10-21 12:57 | 83b | - | - | ? | results/phase22_threaded_races/83b_sys601_threaded_auth_20261021_125711.txt |
| 2026-10-21 13:10 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261021_131039.txt |
| 2026-10-21 13:11 | 85b | - | - | ? | results/phase22_threaded_races/85b_dispatch_retaddr_threaded_20261021_131139.txt |
| 2026-10-21 13:18 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261021_131806.txt |
| 2026-10-21 13:26 | 89a | - | - | ? | results/phase22_threaded_races/89a_cve2019_5607_fd_race_20261021_132658.txt |
| 2026-10-21 13:33 | restart | - | - | ? | results/phase17_new_vectors/restart_pressure_20261021_133337.txt |
| 2026-10-21 13:33 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261021_133356.txt |
| 2026-10-21 13:35 | 83b | - | - | ? | results/83b_race_v2_20261021_133536.txt |
| 2026-10-21 13:38 | 83b | - | - | ? | results/83b_race_v3_20261021_133814.txt |
| 2026-10-21 14:08 | 218a | - | - | ? | results/phase17_new_vectors/218a_netcontrol_abi_20261021_140851.txt |
| 2026-10-21 14:13 | 160a | - | - | ? | results/phase19_umtx_454/160a_umtx_op_matrix_fixed_20261021_141350.txt |
| 2026-10-21 14:16 | 160a2 | - | - | ? | results/phase19_umtx_454/160a2_umtx_lock_ops_20261021_141649.txt |
| 2026-10-21 14:19 | 219a | - | - | ? | results/phase17_new_vectors/219a_netcontrol_close_registered_20261021_141946.txt |
| 2026-10-21 14:19 | 220a | - | - | ? | results/phase17_new_vectors/220a_netcontrol_trigger_20261021_141952.txt |
| 2026-10-21 14:20 | 221a | - | - | ? | results/phase17_new_vectors/221a_netcontrol_stale_registration_20261021_142008.txt |
| 2026-10-21 14:26 | 160b | - | - | ? | results/phase22_threaded_races/160b_umtx_pi_race_20261021_142640.txt |
| 2026-10-21 14:31 | 222a | - | - | ? | results/phase17_new_vectors/222a_netcontrol_clean_trigger_20261021_143149.txt |
| 2026-10-21 14:32 | 224a | - | - | ? | results/phase17_new_vectors/224a_netcontrol_ifindex_scope_20261021_143238.txt |
| 2026-10-21 14:32 | 225a | - | - | ? | results/phase17_new_vectors/225a_netcontrol_clean_index_trigger_20261021_143255.txt |
| 2026-10-21 14:33 | 226a | - | - | ? | results/phase17_new_vectors/226a_netcontrol_queue_capacity_20261021_143323.txt |
| 2026-10-21 14:35 | 228a | - | - | ? | results/phase17_new_vectors/228a_netcontrol_orphan_timing_20261021_143507.txt |
| 2026-10-21 14:38 | 227a | - | - | ? | results/phase17_new_vectors/227a_netcontrol_wedge_scope_20261021_143826.txt |
| 2026-10-21 14:39 | 229a | - | - | ? | results/phase17_new_vectors/229a_netcontrol_orphan_type_20261021_143937.txt |
| 2026-10-21 14:40 | 230a | - | - | ? | results/phase17_new_vectors/230a_netcontrol_index_orphan_20261021_144041.txt |
| 2026-10-21 14:41 | 231a | - | - | ? | results/phase17_new_vectors/231a_netcontrol_socket_poison_20261021_144127.txt |
| 2026-10-21 14:46 | 232a | - | - | ? | results/phase17_new_vectors/232a_netcontrol_ref_or_pointer_20261021_144610.txt |
| 2026-10-21 14:47 | 233a | - | - | ? | results/phase17_new_vectors/233a_netcontrol_peer_state_20261021_144705.txt |
| 2026-10-21 14:47 | 234a | - | - | ? | results/phase17_new_vectors/234a_netcontrol_ref_release_20261021_144722.txt |
| 2026-10-21 14:56 | 235a | - | - | ? | results/phase17_new_vectors/235a_ucontext_live_tid_20261021_145605.txt |
| 2026-10-21 14:56 | 236a | - | - | ? | results/phase17_new_vectors/236a_blockpool_batch_write_20261021_145629.txt |
| 2026-10-21 14:57 | 121b | - | - | ? | results/phase21_kernel_leak/121b_sys657_dispatch_gate_20261021_145755.txt |
| 2026-10-21 14:57 | 237a | - | - | ? | results/phase17_new_vectors/237a_query_protection_oracle_20261021_145710.txt |
| 2026-10-21 14:57 | 238a | - | - | ? | results/phase17_new_vectors/238a_evf_cancel_20261021_145759.txt |
| 2026-10-21 14:57 | 32e | - | - | ? | results/phase5_buffer_io/32e_ping_20261021_145735.txt |
| 2026-10-21 14:58 | 121c | - | - | ? | results/phase21_kernel_leak/121c_sys657_one_gpu_command_20261021_145826.txt |
| 2026-10-21 14:58 | 121d | - | - | ? | results/phase21_kernel_leak/121d_sys654_one_gpu_range_20261021_145849.txt |
| 2026-10-21 14:58 | 32e | - | - | ? | results/phase5_buffer_io/32e_ping_20261021_145836.txt |
| 2026-10-21 14:59 | 121a | - | - | ? | results/phase21_kernel_leak/121a_sys642_count_gate_20261021_145900.txt |
| 2026-10-21 14:59 | 239a | - | - | ? | results/phase17_new_vectors/239a_evf_cancel_scope_20261021_145930.txt |
| 2026-10-21 15:00 | 240a | - | - | ? | results/phase17_new_vectors/240a_evf_cancel_after_completion_20261021_150026.txt |
| 2026-10-21 15:01 | 241a | - | - | ? | results/phase17_new_vectors/241a_evf_cancel_parked_20261021_150126.txt |
| 2026-10-21 15:02 | 242a | - | - | ? | results/phase17_new_vectors/242a_thread_capacity_parked_20261021_150245.txt |
| 2026-10-21 15:02 | 32e | - | - | ? | results/phase5_buffer_io/32e_ping_20261021_150256.txt |
| 2026-10-21 15:03 | 121e | - | - | ? | results/phase21_kernel_leak/121e_msync65_baseline_20261021_150300.txt |
| 2026-10-21 15:04 | 121f | - | - | ? | results/phase21_kernel_leak/121f_dmem_msync_baseline_20261021_150442.txt |
| 2026-10-21 15:04 | 242a | - | - | ? | results/phase17_new_vectors/242a_thread_capacity_parked_20261021_150422.txt |
| 2026-10-21 15:04 | 32e | - | - | ? | results/phase5_buffer_io/32e_ping_20261021_150439.txt |
| 2026-10-21 15:05 | 121g | - | - | ? | results/phase21_kernel_leak/121g_dmem_msync_invalidate_20261021_150504.txt |
| 2026-10-21 15:05 | 121h | - | - | ? | results/phase21_kernel_leak/121h_dmem_invalidate_cleanup_20261021_150517.txt |
| 2026-10-21 15:10 | 122a | - | - | ? | results/phase21_kernel_leak/122a_gc_mmap_pointer_slice_20261021_151058.txt |
| 2026-10-21 15:10 | 32e | - | - | ? | results/phase5_buffer_io/32e_ping_20261021_151056.txt |
| 2026-10-21 15:11 | 122b | - | - | ? | results/phase21_kernel_leak/122b_dmem12_pointer_slices_20261021_151130.txt |
| 2026-10-21 15:11 | 243a | - | - | ? | results/phase17_new_vectors/243a_thread_slot_reclaim_20261021_151141.txt |
| 2026-10-21 15:11 | 32e | - | - | ? | results/phase5_buffer_io/32e_ping_20261021_151143.txt |
| 2026-10-21 15:15 | 32e | - | - | ? | results/phase5_buffer_io/32e_ping_20261021_151521.txt |
| 2026-10-21 15:16 | 123a | - | - | ? | results/phase21_kernel_leak/123a_sys547_region_record_20261021_151631.txt |
| 2026-10-21 15:16 | 244a | - | - | ? | results/phase17_new_vectors/244a_evf_waiter_pair_20261021_151611.txt |
| 2026-10-21 15:18 | 245a | - | - | ? | results/phase17_new_vectors/245a_thread_spawn_trace_20261021_151853.txt |
| 2026-10-21 15:20 | 246a | - | - | ? | results/phase17_new_vectors/246a_dynlib_libdbg_20261021_152056.txt |
| 2026-10-21 15:21 | 247a | - | - | ? | results/phase17_new_vectors/247a_dynlib_size_field_20261021_152128.txt |
| 2026-10-21 15:21 | 248a | - | - | ? | results/phase17_new_vectors/248a_dynlib_zeroed_20261021_152141.txt |
| 2026-10-21 15:24 | 249a | - | - | ? | results/phase17_new_vectors/249a_evf_set_vs_cancel_20261021_152445.txt |
| 2026-10-21 15:24 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261021_152457.txt |
| 2026-10-21 15:36 | 253a | - | - | ? | results/phase17_new_vectors/253a_osem_namedobj_name_20261021_153612.txt |
| 2026-10-21 15:37 | 256a | - | - | ? | results/phase17_new_vectors/256a_vm_container_accept_20261021_153708.txt |
| 2026-10-21 15:40 | 258a | - | - | ? | results/phase17_new_vectors/258a_debug_init_effect_20261021_154044.txt |
| 2026-10-21 15:45 | 259a | - | - | ? | results/phase17_new_vectors/259a_dev_listing_20261021_154548.txt |
| 2026-10-21 15:46 | 260a | - | - | ? | results/phase17_new_vectors/260a_open_return_shape_20261021_154621.txt |
| 2026-10-21 15:46 | 261a | - | - | ? | results/phase17_new_vectors/261a_device_ioctl_reach_20261021_154649.txt |
| 2026-10-21 15:48 | 263a | - | - | ? | results/phase17_new_vectors/263a_dmem_read_prot_20261021_154812.txt |
| 2026-10-21 15:51 | 264a | - | - | ? | results/phase17_new_vectors/264a_ioctl_sweep_20261021_155109.txt |
| 2026-10-21 15:55 | 265a | - | - | ? | results/phase17_new_vectors/265a_dce_ioctl_buffer_20261021_155514.txt |
| 2026-10-21 15:58 | 267a | - | - | ? | results/phase17_new_vectors/267a_ioctl_control_20261021_155811.txt |
| 2026-10-21 15:58 | 268a | - | - | ? | results/phase17_new_vectors/268a_device_fd_reality_20261021_155843.txt |
| 2026-10-21 16:02 | 270a | - | - | ? | results/phase17_new_vectors/270a_umtx_sentinel_20261021_160225.txt |
| 2026-10-21 16:08 | 160b | - | - | ? | results/phase22_threaded_races/160b_umtx_pi_race_20261021_160844.txt |
| 2026-10-21 16:10 | 160c | - | - | ? | results/phase22_threaded_races/160c_umtx_pi_race_4t_20261021_161035.txt |
| 2026-10-21 16:11 | 160d | - | - | ? | results/phase22_threaded_races/160d_umtx_rwlock_race_20261021_161148.txt |
| 2026-10-21 16:13 | 160d | - | - | ? | results/phase22_threaded_races/160d_umtx_rwlock_race_20261021_161313.txt |
| 2026-10-21 16:15 | 160e | - | - | ? | results/phase22_threaded_races/160e_umtx_pi_corrupt_20261021_161522.txt |
| 2026-10-21 16:29 | 89b | - | - | ? | results/phase22_threaded_races/89b_cve2019_5607_gate_20261021_162936.txt |
| 2026-10-21 16:31 | 89b | - | - | ? | results/phase22_threaded_races/89b_cve2019_5607_gate_20261021_163120.txt |
| 2026-10-21 16:34 | 89a | - | - | ? | results/phase22_threaded_races/89a_cve2019_5607_fd_race_20261021_163417.txt |
| 2026-10-21 16:39 | 89a | - | - | ? | results/phase22_threaded_races/89a_cve2019_5607_fd_race_20261021_163959.txt |
| 2026-10-21 16:51 | 89a | - | - | ? | results/phase22_threaded_races/89a_cve2019_5607_fd_race_20261021_165106.txt |
| 2026-10-21 16:54 | 89a | - | - | ? | results/phase22_threaded_races/89a_cve2019_5607_fd_race_20261021_165439.txt |
| 2026-10-21 17:21 | 90a | - | - | ? | results/phase22_threaded_races/90a_fd_close_sendmsg_race_20261021_172135.txt |
| 2026-10-21 17:23 | 90a | - | - | ? | results/phase22_threaded_races/90a_fd_close_sendmsg_race_20261021_172322.txt |
| 2026-10-21 17:40 | 91a | - | - | ? | results/phase22_threaded_races/91a_ipv6_setsockopt_race_20261021_174047.txt |
| 2026-10-21 17:47 | 91b | - | - | ? | results/phase22_threaded_races/91b_ipv6_race_regtest_20261021_174752.txt |
| 2026-10-21 17:49 | 91b | - | - | ? | results/phase22_threaded_races/91b_ipv6_race_regtest_20261021_174955.txt |
| 2026-10-21 17:54 | 91c | - | - | ? | results/phase22_threaded_races/91c_eboot_gadget_scan_20261021_175428.txt |
| 2026-10-21 17:56 | 91d | - | - | ? | results/phase22_threaded_races/91d_ipv6_race_full_20261021_175603.txt |
| 2026-10-21 17:58 | 91e | - | - | ? | results/phase22_threaded_races/91e_ipv6_race_heavy_20261021_175812.txt |
| 2026-10-21 17:59 | 91f | - | - | ? | results/phase22_threaded_races/91f_ipv6_race_overlap_20261021_175935.txt |
| 2026-10-21 18:01 | 91g | - | - | ? | results/phase22_threaded_races/91g_child_verify_20261021_180110.txt |
| 2026-10-21 18:05 | 91h | - | - | ? | results/phase22_threaded_races/91h_child_regdump_20261021_180539.txt |
| 2026-10-21 18:08 | 91i | - | - | ? | results/phase22_threaded_races/91i_child_setsockopt_first_20261021_180854.txt |
| 2026-10-21 18:12 | 91j | - | - | ? | results/phase22_threaded_races/91j_child_mmap_r10_20261021_181213.txt |
| 2026-10-21 18:16 | 91k | - | - | ? | results/phase22_threaded_races/91k_r10_hunt_20261021_181656.txt |
| 2026-10-21 18:22 | 91k | - | - | ? | results/phase22_threaded_races/91k_r10_hunt_20261021_182238.txt |
| 2026-10-21 18:27 | 91k | - | - | ? | results/phase22_threaded_races/91k_r10_hunt_20261021_182730.txt |
| 2026-10-21 18:29 | 91k | - | - | ? | results/phase22_threaded_races/91k_r10_hunt_20261021_182911.txt |
| 2026-10-21 18:30 | 91k | - | - | ? | results/phase22_threaded_races/91k_r10_hunt_20261021_183033.txt |
| 2026-10-21 18:33 | 91k | - | - | ? | results/phase22_threaded_races/91k_r10_hunt_20261021_183308.txt |
| 2026-10-21 18:37 | 91l | - | - | ? | results/phase22_threaded_races/91l_r10_gadget_scan_20261021_183714.txt |
| 2026-10-21 18:41 | 91m | - | - | ? | results/phase22_threaded_races/91m_mov_r10_rcx_scan_20261021_184141.txt |
| 2026-10-21 18:43 | 91m | - | - | ? | results/phase22_threaded_races/91m_mov_r10_rcx_scan_20261021_184301.txt |
| 2026-10-21 18:49 | 91m | - | - | ? | results/phase22_threaded_races/91m_mov_r10_rcx_scan_20261021_184959.txt |
| 2026-10-21 18:52 | 91n | - | - | ? | results/phase22_threaded_races/91n_r10_offset_socketpair_20261021_185227.txt |
| 2026-10-21 18:57 | 91o | - | - | ? | results/phase22_threaded_races/91o_r10_setsockopt_safe_20261021_185705.txt |
| 2026-10-21 19:00 | 91g | - | - | ? | results/phase22_threaded_races/91g_child_verify_20261021_190032.txt |
| 2026-10-21 19:08 | 91p | - | - | ? | results/phase22_threaded_races/91p_r10_offset_hops_20261021_190841.txt |
| 2026-10-21 19:14 | 91q | - | - | ? | results/phase22_threaded_races/91q_r10_nowrite_20261021_191444.txt |
| 2026-10-21 19:18 | 91r | - | - | ? | results/phase22_threaded_races/91r_r10_zeromalloc_20261021_191825.txt |
| 2026-10-21 19:22 | 91s | - | - | ? | results/phase22_threaded_races/91s_thr_control_20261021_192241.txt |
| 2026-10-21 19:25 | 91t | - | - | ? | results/phase22_threaded_races/91t_mmap_nanosleep_20261021_192543.txt |
| 2026-10-21 19:27 | 91u | - | - | ? | results/phase22_threaded_races/91u_r10_final_20261021_192734.txt |
| 2026-10-21 19:47 | 92b | - | - | ? | results/phase22_threaded_races/92b_2292_gate_check_20261021_194730.txt |
| 2026-10-21 19:49 | 92c | - | - | ? | results/phase22_threaded_races/92c_pktinfo_close_race_20261021_194935.txt |
| 2026-10-21 19:52 | 92e | - | - | ? | results/phase22_threaded_races/92e_pktinfo_race_fixed_20261021_195255.txt |
| 2026-10-21 20:24 | 93a | - | - | ? | results/phase22_threaded_races/93a_socket_close_race_20261021_202408.txt |
| 2026-10-21 20:26 | 93b | - | - | ? | results/phase22_threaded_races/93b_scmrights_close_diag_20261021_202631.txt |
| 2026-10-21 20:29 | 94a | - | - | ? | results/phase22_threaded_races/94a_sys601_vm_fingerprint_20261021_202923.txt |
| 2026-10-21 20:39 | 94b | - | - | ? | results/phase22_threaded_races/94b_kqueue_close_race_20261021_203942.txt |
| 2026-10-21 20:47 | 95a | - | - | ? | results/phase22_threaded_races/95a_umtx_pi_race_20261021_204746.txt |
| 2026-10-21 20:59 | 95a | - | - | ? | results/phase22_threaded_races/95a_umtx_pi_race_20261021_205923.txt |
| 2026-10-21 21:01 | 95a | - | - | ? | results/phase22_threaded_races/95a_umtx_pi_race_20261021_210143.txt |
| 2026-10-21 21:03 | 235a | - | - | ? | results/phase17_new_vectors/235a_recovered_contracts_20261021_210325.txt |
| 2026-10-21 21:04 | 237a | - | - | ? | results/phase17_new_vectors/237a_aio_ids_and_protection_20261021_210420.txt |
| 2026-10-21 21:04 | 237a | - | - | ? | results/phase17_new_vectors/237a_aio_ids_and_protection_20261021_210446.txt |
| 2026-10-21 21:05 | 237a | - | - | ? | results/phase17_new_vectors/237a_aio_ids_and_protection_20261021_210525.txt |
| 2026-10-21 21:05 | 237a | - | - | ? | results/phase17_new_vectors/237a_aio_ids_and_protection_20261021_210533.txt |
| 2026-10-21 21:06 | 237b | - | - | ? | results/phase17_new_vectors/237b_mprotect_oracle_20261021_210611.txt |
| 2026-10-21 21:06 | 237b | - | - | ? | results/phase17_new_vectors/237b_mprotect_oracle_20261021_210622.txt |
| 2026-10-21 21:07 | 95b | - | - | ? | results/phase22_threaded_races/95b_umtx_pi_race_only_20261021_210703.txt |
| 2026-10-21 21:08 | 236a | - | - | ? | results/phase17_new_vectors/236a_batch_vm_548_20261021_210850.txt |
| 2026-10-21 21:08 | 237b | - | - | ? | results/phase17_new_vectors/237b_mprotect_oracle_20261021_210838.txt |
| 2026-10-21 21:11 | 238a | - | - | ? | results/phase17_new_vectors/238a_548_657_first_arg_20261021_211117.txt |
| 2026-10-21 21:11 | 239a | - | - | ? | results/phase17_new_vectors/239a_aio_id_slots_20261021_211151.txt |
| 2026-10-21 21:12 | 240a | - | - | ? | results/phase17_new_vectors/240a_660_module_handles_20261021_211236.txt |
| 2026-10-21 21:16 | 96a | - | - | ? | results/phase22_threaded_races/96a_robust_lists_20261021_211623.txt |
| 2026-10-21 21:18 | 242a | - | - | ? | results/phase17_new_vectors/242a_sys622_commands_20261021_211852.txt |
| 2026-10-21 21:20 | 243a | - | - | ? | results/phase17_new_vectors/243a_sys622_arg3_20261021_212019.txt |
| 2026-10-21 21:21 | 124a | - | - | ? | results/phase21_kernel_leak/124a_gpu_mmap_msync_invalidate_20261021_212103.txt |
| 2026-10-21 21:21 | 97a | - | - | ? | results/phase22_threaded_races/97a_exit_umtx_race_20261021_212158.txt |
| 2026-10-21 21:22 | 106a | - | - | ? | results/phase17_new_vectors/106a_sigreturn_srop_20261021_212215.txt |
| 2026-10-21 21:22 | 244a | - | - | ? | results/phase17_new_vectors/244a_sys622_400_size_20261021_212220.txt |
| 2026-10-21 21:22 | 80a | - | - | ? | results/phase17_new_vectors/80a_thr_create_cs43_threading_20261021_212214.txt |
| 2026-10-21 21:22 | 82a | - | - | ? | results/phase17_new_vectors/82a_umtx_exploit_vectors_20261021_212217.txt |
| 2026-10-21 21:23 | 80a | - | - | ? | results/phase17_new_vectors/80a_thr_create_cs43_threading_20261021_212300.txt |
| 2026-10-21 21:23 | 80a | - | - | ? | results/phase17_new_vectors/80a_thr_create_cs43_threading_20261021_212358.txt |
| 2026-10-21 21:24 | 245a | - | - | ? | results/phase17_new_vectors/245a_sys622_400_size1_20261021_212411.txt |
| 2026-10-21 21:24 | 80a | - | - | ? | results/phase17_new_vectors/80a_thr_create_cs43_threading_20261021_212436.txt |
| 2026-10-21 21:25 | 246a | - | - | ? | results/phase17_new_vectors/246a_sys622_copy_size_20261021_212514.txt |
| 2026-10-21 21:25 | 247a | - | - | ? | results/phase17_new_vectors/247a_sys622_copy_size_20261021_212549.txt |
| 2026-10-21 21:25 | 80a | - | - | ? | results/phase17_new_vectors/80a_thr_create_cs43_threading_20261021_212556.txt |
| 2026-10-21 21:27 | 125a | - | - | ? | results/phase21_kernel_leak/125a_thread_kevent_kptr_20261021_212757.txt |
| 2026-10-21 21:32 | 126a | - | - | ? | results/phase21_kernel_leak/126a_multi_vector_blitz_20261021_213200.txt |
| 2026-10-21 21:34 | 127a | - | - | ? | results/phase21_kernel_leak/127a_socketpair_exploit_20261021_213405.txt |
| 2026-10-21 21:36 | 97b | - | - | ? | results/phase22_threaded_races/97b_exit_umtx_isolate_20261021_213615.txt |
| 2026-10-21 21:37 | 128a | - | - | ? | results/phase21_kernel_leak/128a_getcontext_srop_20261021_213742.txt |
| 2026-10-21 21:37 | 97b | - | - | ? | results/phase22_threaded_races/97b_exit_umtx_isolate_20261021_213738.txt |
| 2026-10-21 21:42 | 98a | - | - | ? | results/phase22_threaded_races/98a_rwlock_race_20261021_214206.txt |
| 2026-10-21 21:44 | 128b | - | - | ? | results/phase21_kernel_leak/128b_srop_correct_offsets_20261021_214423.txt |
| 2026-10-21 22:01 | 99a | - | - | ? | results/phase22_threaded_races/99a_umtx_deep_ops_20261021_220114.txt |
| 2026-10-21 22:02 | 128c | - | - | ? | results/phase21_kernel_leak/128c_srop_clean_return_20261021_220254.txt |
| 2026-10-21 22:06 | 99b | - | - | ? | results/phase22_threaded_races/99b_umtx_sem_cvwait_20261021_220621.txt |
| 2026-10-21 22:08 | 128d | - | - | ? | results/phase21_kernel_leak/128d_srop_rax_control_20261021_220849.txt |
| 2026-10-21 22:12 | 99c | - | - | ? | results/phase22_threaded_races/99c_pi_exit_race_20261021_221247.txt |
| 2026-10-21 22:16 | 99d | - | - | ? | results/phase22_threaded_races/99d_pi_leak_measure_20261021_221636.txt |
| 2026-10-21 22:17 | 130a | - | - | ? | results/phase21_kernel_leak/130a_srop_kldstat_kaslr_20261021_221730.txt |
| 2026-10-21 22:20 | 130b | - | - | ? | results/phase21_kernel_leak/130b_srop_syscall_triage_20261021_222023.txt |
| 2026-10-21 22:22 | 130c | - | - | ? | results/phase21_kernel_leak/130c_srop_sysctl_kptr_20261021_222220.txt |
| 2026-10-21 22:22 | 99e | - | - | ? | results/phase22_threaded_races/99e_pi_contend_orphan_20261021_222229.txt |
| 2026-10-21 22:24 | 130d | - | - | ? | results/phase21_kernel_leak/130d_srop_open_read_umtx_20261021_222452.txt |
| 2026-10-21 22:25 | 99e | - | - | ? | results/phase22_threaded_races/99e_pi_contend_orphan_20261021_222511.txt |
| 2026-10-21 22:31 | 131c | - | - | ? | results/phase21_kernel_leak/131c_srop_minimal_read_20261021_223153.txt |
| 2026-10-21 22:31 | 99f | - | - | ? | results/phase22_threaded_races/99f_pi_toctou_race_20261021_223107.txt |
| 2026-10-21 22:35 | 132a | - | - | ? | results/phase21_kernel_leak/132a_srop_dipsw_dmem_20261021_223550.txt |
| 2026-10-21 22:37 | 132b | - | - | ? | results/phase21_kernel_leak/132b_srop_wxe_bypass_20261021_223747.txt |
| 2026-10-21 22:38 | 100a | - | - | ? | results/phase22_threaded_races/100a_evf_race_20261021_223837.txt |
| 2026-10-21 22:39 | 132c | - | - | ? | results/phase21_kernel_leak/132c_srop_dipsw_write_20261021_223951.txt |
| 2026-10-21 22:43 | 133a | - | - | ? | results/phase21_kernel_leak/133a_srop_thr_create_cs_fix_20261021_224308.txt |
| 2026-10-21 22:45 | 133b | - | - | ? | results/phase21_kernel_leak/133b_srop_thr_create_clone_20261021_224502.txt |
| 2026-10-21 22:48 | 134a | - | - | ? | results/phase21_kernel_leak/134a_srop_thread_verify_20261021_224815.txt |
| 2026-10-21 22:51 | 135a | - | - | ? | results/phase21_kernel_leak/135a_srop_race_umtx_20261021_225112.txt |
| 2026-10-21 22:55 | 135b | - | - | ? | results/phase21_kernel_leak/135b_srop_kernel_syscalls_20261021_225531.txt |
| 2026-10-21 22:57 | 135c | - | - | ? | results/phase21_kernel_leak/135c_srop_kevent_sysctl_20261021_225726.txt |
| 2026-10-21 23:00 | 136a | - | - | ? | results/phase21_kernel_leak/136a_srop_auxv_stack_20261021_230032.txt |
| 2026-10-21 23:11 | 137a | - | - | ? | results/phase21_kernel_leak/137a_srop_contract_scan_20261021_231111.txt |
| 2026-10-21 23:13 | 137b | - | - | ? | results/phase21_kernel_leak/137b_srop_evf_race_547deep_20261021_231352.txt |
| 2026-10-21 23:17 | 137c | - | - | ? | results/phase21_kernel_leak/137c_srop_pmc_sockopt_msgbuf_20261021_231727.txt |
| 2026-10-21 23:19 | 137d | - | - | ? | results/phase21_kernel_leak/137d_srop_deci_devs_20261021_231945.txt |
| 2026-10-21 23:34 | 137f | - | - | ? | results/phase21_kernel_leak/137f_srop_devlist_rdev_20261021_233420.txt |
| 2026-10-21 23:35 | 137e | - | - | ? | results/phase21_kernel_leak/137e_srop_deci_write_20261021_233555.txt |
| 2026-10-21 23:41 | 138b | - | - | ? | results/phase21_kernel_leak/138b_srop_sbl_srv_20261021_234118.txt |
| 2026-10-21 23:42 | 138c | - | - | ? | results/phase21_kernel_leak/138c_srop_devs_batch_20261021_234209.txt |
| 2026-10-21 23:45 | 138d | - | - | ? | results/phase21_kernel_leak/138d_srop_kptr_deep_20261021_234501.txt |
| 2026-10-21 23:48 | 138e | - | - | ? | results/phase21_kernel_leak/138e_srop_kldstat_fsstat_20261021_234804.txt |
| 2026-10-21 23:50 | 138f | - | - | ? | results/phase21_kernel_leak/138f_srop_residue_modfind_20261021_235053.txt |
| 2026-10-21 23:53 | 138g | - | - | ? | results/phase21_kernel_leak/138g_srop_fsstat_proc_gc_20261021_235348.txt |
| 2026-10-21 23:58 | 138h | - | - | ? | results/phase21_kernel_leak/138h_srop_safe_vectors_20261021_235805.txt |
| 2026-10-22 00:03 | 139a | - | - | ? | results/phase21_kernel_leak/139a_srop_deci_cmd_mmap_oracle_20261022_000303.txt |
| 2026-10-22 00:05 | 139b | - | - | ? | results/phase21_kernel_leak/139b_srop_mmap_oracle_20261022_000511.txt |
| 2026-10-22 00:10 | 139c | - | - | ? | results/phase21_kernel_leak/139c_srop_dipsw_rng_notif_20261022_001016.txt |
| 2026-10-22 00:13 | 140a | - | - | ? | results/phase21_kernel_leak/140a_srop_auxv_kevent_fpu_20261022_001318.txt |
| 2026-10-22 00:17 | 140b | - | - | ? | results/phase21_kernel_leak/140b_srop_sysctl_toctou_20261022_001716.txt |
| 2026-10-22 00:19 | 140c | - | - | ? | results/phase21_kernel_leak/140c_srop_fcntl_shm_kstack_20261022_001923.txt |
| 2026-10-22 00:21 | 140d | - | - | ? | results/phase21_kernel_leak/140d_srop_mbuf_residue_20261022_002147.txt |
| 2026-10-22 00:25 | 141a | - | - | ? | results/phase21_kernel_leak/141a_srop_umtx_pi_race_20261022_002547.txt |
| 2026-10-22 00:29 | 141b | - | - | ? | results/phase21_kernel_leak/141b_srop_pi_ops_20261022_002922.txt |
| 2026-10-22 00:47 | 142a | - | - | ? | results/phase21_kernel_leak/142a_srop_shm_fd_pi_race_20261022_004724.txt |
| 2026-10-22 00:58 | 142b | - | - | ? | results/phase21_kernel_leak/142b_thr_pi_lock_shm_mmap_20261022_005835.txt |
| 2026-10-22 01:05 | 142c | - | - | ? | results/phase21_kernel_leak/142c_thr_getctx_pi_lock_20261022_010508.txt |
| 2026-10-22 01:09 | 142d | - | - | ? | results/phase21_kernel_leak/142d_thr_getctx_correct_offsets_20261022_010951.txt |
| 2026-10-22 01:16 | 142e | - | - | ? | results/phase21_kernel_leak/142e_thr_lock_pi_clean_20261022_011628.txt |
| 2026-10-22 01:20 | 142f | - | - | ? | results/phase21_kernel_leak/142f_thr_blocking_pi_20261022_012048.txt |
| 2026-10-22 01:25 | 142g | - | - | ? | results/phase21_kernel_leak/142g_gadget_scan_rop_thr_20261022_012535.txt |
| 2026-10-22 01:29 | 142h | - | - | ? | results/phase21_kernel_leak/142h_rop_wait_thr_20261022_012914.txt |
| 2026-10-22 01:32 | 142i | - | - | ? | results/phase21_kernel_leak/142i_full_rop_wait_20261022_013254.txt |
| 2026-10-22 01:36 | 142j | - | - | ? | results/phase21_kernel_leak/142j_80a_rop_wait_20261022_013639.txt |
| 2026-10-22 01:52 | 142l | - | - | ? | results/phase21_kernel_leak/142l_metadata_shift_20261022_015224.txt |
| 2026-10-22 01:57 | 142m | - | - | ? | results/phase21_kernel_leak/142m_thread_sideeffect_20261022_015708.txt |
| 2026-10-22 02:07 | 142n | - | - | ? | results/phase21_kernel_leak/142n_gadgets_pipe_20261022_020700.txt |
| 2026-10-22 02:10 | 142o | - | - | ? | results/phase21_kernel_leak/142o_verify_pipe_20261022_021004.txt |
| 2026-10-22 02:14 | 142p | - | - | ? | results/phase21_kernel_leak/142p_socket_thread_io_20261022_021423.txt |
| 2026-10-22 02:21 | 142q | - | - | ? | results/phase21_kernel_leak/142q_robust_cmsg_20261022_022120.txt |
| 2026-10-22 02:27 | 142s | - | - | ? | results/phase21_kernel_leak/142s_lean_shm_open_20261022_022739.txt |
| 2026-10-22 02:35 | 142u | - | - | ? | results/phase21_kernel_leak/142u_kevent_minimal_20261022_023508.txt |
| 2026-10-22 02:38 | 142v | - | - | ? | results/phase21_kernel_leak/142v_dev_enum_ioctl_20261022_023820.txt |
| 2026-10-22 02:41 | 142w | - | - | ? | results/phase21_kernel_leak/142w_kevent363_deci_notif_20261022_024139.txt |
| 2026-10-22 02:46 | 142x2 | - | - | ? | results/phase21_kernel_leak/142x2_safe_devs_fstat_20261022_024622.txt |
| 2026-10-22 02:46 | 142x2 | - | - | ? | results/phase21_kernel_leak/142x2_safe_devs_fstat_20261022_024632.txt |
| 2026-10-22 02:50 | 142y | - | - | ? | results/phase21_kernel_leak/142y_umtx_pi_race_20261022_025019.txt |
| 2026-10-22 02:57 | 142z3 | - | - | ? | results/phase21_kernel_leak/142z3_mctx_minimal_20261022_025747.txt |
| 2026-10-22 03:00 | 143a | - | - | ? | results/phase21_kernel_leak/143a_gc_dce_ioctl_fuzz_20261022_030035.txt |
| 2026-10-22 03:03 | 143b | - | - | ? | results/phase21_kernel_leak/143b_procfs_sockopt_umtx_20261022_030302.txt |
| 2026-10-22 03:04 | 143c | - | - | ? | results/phase21_kernel_leak/143c_ip_options_dump_20261022_030449.txt |
| 2026-10-22 03:14 | 143d | - | - | ? | results/phase21_kernel_leak/143d_sys670_deep_probe_20261022_031404.txt |
| 2026-10-22 03:15 | 143e | - | - | ? | results/phase21_kernel_leak/143e_sys670_make_syscall_20261022_031519.txt |
| 2026-10-22 03:16 | 143f | - | - | ? | results/phase21_kernel_leak/143f_sys670_fresh_20261022_031647.txt |
| 2026-10-22 03:19 | 143g | - | - | ? | results/phase21_kernel_leak/143g_fd_fstat_kevent_race_20261022_031906.txt |
| 2026-10-22 03:21 | 143h | - | - | ? | results/phase21_kernel_leak/143h_fd18_read_full_20261022_032114.txt |
| 2026-10-22 03:22 | 143i | - | - | ? | results/phase21_kernel_leak/143i_read_loader_modules_20261022_032253.txt |
| 2026-10-22 03:24 | 143j | - | - | ? | results/phase21_kernel_leak/143j_globals_offsets_20261022_032453.txt |
| 2026-10-22 03:28 | 143k | - | - | ? | results/phase21_kernel_leak/143k_native_invoke_koffsets_20261022_032821.txt |
| 2026-10-22 03:30 | 143l | - | - | ? | results/phase21_kernel_leak/143l_io_read_koffsets_20261022_033004.txt |
| 2026-10-22 03:33 | 144a | - | - | ? | results/phase21_kernel_leak/144a_koffsets_msync_native_20261022_033305.txt |
| 2026-10-22 03:42 | 58b | - | - | ? | results/phase15_native_sysent/58b_msync_anon_vs_device_20261022_034238.txt |
| 2026-10-22 03:44 | 143m | - | - | ? | results/phase21_kernel_leak/143m_read_gpu_ropchain_signal_20261022_034452.txt |
| 2026-10-22 03:46 | 143n | - | - | ? | results/phase21_kernel_leak/143n_native_invoke_focused_20261022_034654.txt |
| 2026-10-22 03:49 | 143o | - | - | ? | results/phase21_kernel_leak/143o_fcall_kaslr_hunt_20261022_034936.txt |
| 2026-10-22 03:51 | 143p | - | - | ? | results/phase21_kernel_leak/143p_ipv6_pktopts_errno_20261022_035124.txt |
| 2026-10-22 03:57 | 143q | - | - | ? | results/phase21_kernel_leak/143q_ipv6_pipe_kptr_leak_20261022_035728.txt |
| 2026-10-22 03:58 | 143r | - | - | ? | results/phase21_kernel_leak/143r_read_kernel_lua_full_20261022_035852.txt |
| 2026-10-22 04:00 | 143s | - | - | ? | results/phase21_kernel_leak/143s_pktopts_overlap_v2_20261022_040048.txt |
| 2026-10-22 04:06 | 143u | - | - | ? | results/phase21_kernel_leak/143u_pktopts_minimal_20261022_040619.txt |
| 2026-10-22 04:15 | 143v | - | - | ? | results/phase21_kernel_leak/143v_sidt_sgdt_kaslr_20261022_041512.txt |
| 2026-10-22 04:16 | 143w | - | - | ? | results/phase21_kernel_leak/143w_sidt_scan_only_20261022_041643.txt |
| 2026-10-22 04:18 | 143x | - | - | ? | results/phase21_kernel_leak/143x_sidt_small_scan_20261022_041812.txt |
| 2026-10-22 04:20 | 143y | - | - | ? | results/phase21_kernel_leak/143y_sidt_tiny_20261022_042020.txt |
| 2026-10-22 04:27 | 143z | - | - | ? | results/phase21_kernel_leak/143z_sidt_execute_20261022_042724.txt |
| 2026-10-22 04:32 | 143z | - | - | ? | results/phase21_kernel_leak/143z_sidt_execute_20261022_043203.txt |
| 2026-10-22 04:36 | 144a | - | - | ? | results/phase21_kernel_leak/144a_sidt_diagnostic_20261022_043638.txt |
| 2026-10-22 04:40 | 58a | - | - | ? | results/phase15_native_sysent/58a_msync_reachability_20261022_044042.txt |
| 2026-10-22 04:42 | 58b | - | - | ? | results/phase15_native_sysent/58b_msync_device_pager_20261022_044239.txt |
| 2026-10-22 04:58 | 58e | - | - | ? | results/phase15_native_sysent/58e_msync_minimal_20261022_045849.txt |
| 2026-10-22 04:59 | 58f | - | - | ? | results/phase15_native_sysent/58f_msync_dmem_20261022_045922.txt |
| 2026-10-22 05:00 | 143q | - | - | ? | results/phase21_kernel_leak/143q_pcblist_pktopts_kaslr_20261022_050000.txt |
| 2026-10-22 05:03 | hello | - | - | ? | results/hello_20261022_050346.txt |
| 2026-10-22 05:04 | 144f | - | - | ? | results/phase21_kernel_leak/144f_thread_rop_validate_20261022_050418.txt |
| 2026-10-22 05:04 | 145a | - | - | ? | results/phase22_cve_hunt/145a_tcp_rack_reachability_20261022_050401.txt |
| 2026-10-22 05:04 | sidt | - | - | ? | results/sidt_v4_20261022_050435.txt |
| 2026-10-22 05:04 | thread | - | - | ? | results/thread_test_20261022_050418.txt |
| 2026-10-22 05:05 | 145b | - | - | ? | results/phase22_cve_hunt/145b_posixshm_semctl_kevent_20261022_050555.txt |
| 2026-10-22 05:07 | 145c | - | - | ? | results/phase22_cve_hunt/145c_shm_deep_kevent_20261022_050719.txt |
| 2026-10-22 05:07 | sidt | - | - | ? | results/sidt_v5_20261022_050719.txt |
| 2026-10-22 05:09 | 146a | - | - | ? | results/phase22_cve_hunt/146a_umtx_pi_mutex_race_20261022_050947.txt |
| 2026-10-22 05:10 | hello | - | - | ? | results/hello_20261022_051056.txt |
| 2026-10-22 05:11 | 144g | - | - | ? | results/phase21_kernel_leak/144g_sidt_delayed_20261022_051112.txt |
| 2026-10-22 05:11 | sidt | - | - | ? | results/sidt_v6_20261022_051112.txt |
| 2026-10-22 05:12 | 146b | - | - | ? | results/phase22_cve_hunt/146b_umtx_robust_multirace_20261022_051249.txt |
| 2026-10-22 05:18 | 146d | - | - | ? | results/phase22_cve_hunt/146d_orphan_simple_20261022_051848.txt |
| 2026-10-22 05:26 | 145b | - | - | ? | results/phase21_kernel_leak/145b_pi_mutex_ops_20261022_052628.txt |
| 2026-10-22 05:28 | 145c | - | - | ? | results/phase21_kernel_leak/145c_pi_double_unlock_uaf_20261022_052839.txt |
| 2026-10-22 05:29 | 146e | - | - | ? | results/phase22_cve_hunt/146e_orphan_timeout_20261022_052900.txt |
| 2026-10-22 05:30 | 146f | - | - | ? | results/phase22_cve_hunt/146f_pi_chain_stress_20261022_053030.txt |
| 2026-10-22 05:32 | 146a | - | - | ? | results/phase21_kernel_leak/146a_rdtsc_prefetch_kaslr_20261022_053244.txt |
| 2026-10-22 05:34 | 146b | - | - | ? | results/phase21_kernel_leak/146b_gadget_scan_fast_20261022_053425.txt |
| 2026-10-22 05:34 | 146g2 | - | - | ? | results/phase22_cve_hunt/146g2_contested_isolated_20261022_053434.txt |
| 2026-10-22 05:35 | 146g3 | - | - | ? | results/phase22_cve_hunt/146g3_race_isolate_20261022_053543.txt |
| 2026-10-22 05:36 | 146c | - | - | ? | results/phase21_kernel_leak/146c_gadget_context_test_20261022_053622.txt |
| 2026-10-22 05:36 | 146g4 | - | - | ? | results/phase22_cve_hunt/146g4_race_faketid_20261022_053652.txt |
| 2026-10-22 05:38 | 147a | - | - | ? | results/phase21_kernel_leak/147a_sysent_679_734_srop_20261022_053846.txt |
| 2026-10-22 05:39 | 147a | - | - | ? | results/phase22_cve_hunt/147a_shm_race_kaslr_20261022_053954.txt |
| 2026-10-22 05:40 | 147a | - | - | ? | results/phase22_cve_hunt/147a_shm_race_kaslr_20261022_054004.txt |
| 2026-10-22 05:40 | 147b | - | - | ? | results/phase21_kernel_leak/147b_sysent_thread_isolated_20261022_054022.txt |
| 2026-10-22 05:44 | 148a | - | - | ? | results/phase22_cve_hunt/148a_posixshm_largepage_20261022_054441.txt |
| 2026-10-22 05:49 | 149a | - | - | ? | results/phase22_cve_hunt/149a_socketpair_pipe_scmrights_20261022_054919.txt |
| 2026-10-22 05:51 | 149b | - | - | ? | results/phase22_cve_hunt/149b_scmrights_fix_pipe_io_20261022_055150.txt |
| 2026-10-22 05:55 | 150a | - | - | ? | results/phase22_cve_hunt/150a_sendfile_pipe_drain_20261022_055507.txt |
| 2026-10-22 06:04 | 151b | - | - | ? | results/phase22_cve_hunt/151b_unix_uaf_peek_20261022_060402.txt |
| 2026-10-22 06:05 | 151c | - | - | ? | results/phase22_cve_hunt/151c_scmrights_close_race_20261022_060555.txt |
| 2026-10-22 06:08 | 151d | - | - | ? | results/phase22_cve_hunt/151d_fd_leak_verify_20261022_060807.txt |
| 2026-10-22 06:15 | 151e | - | - | ? | results/phase22_cve_hunt/151e_fd_leak_exploit_20261022_061533.txt |
| 2026-10-22 06:17 | 151e | - | - | ? | results/phase22_cve_hunt/151e_fd_leak_exploit_20261022_061701.txt |
| 2026-10-22 09:13 | 152a | - | - | ? | results/phase22_cve_hunt/152a_kaslr_timing_oracle_20261022_091335.txt |
| 2026-10-22 09:13 | 152c | - | - | ? | results/phase22_cve_hunt/152c_kernel_read_via_pipe_20261022_091326.txt |
| 2026-10-22 09:14 | 153a | - | - | ? | results/phase22_cve_hunt/153a_cve45251_poll_close_uaf_20261022_091441.txt |
| 2026-10-22 09:21 | 153b | - | - | ? | results/phase22_cve_hunt/153b_poll_close_uaf_v2_20261022_092117.txt |
| 2026-10-22 09:23 | 154a | - | - | ? | results/phase22_cve_hunt/154a_cve49427_sendfile_shm_uaf_20261022_092325.txt |
| 2026-10-22 09:27 | 155a | - | - | ? | results/phase22_cve_hunt/155a_eboot_syscall_search_20261022_092706.txt |
| 2026-10-22 09:29 | 155b | - | - | ? | results/phase22_cve_hunt/155b_syscall_offsets_20261022_092949.txt |
| 2026-10-22 09:30 | 155c | - | - | ? | results/phase22_cve_hunt/155c_syscall_context_20261022_093024.txt |
| 2026-10-22 09:30 | 272a | - | - | ? | results/phase17_new_vectors/272a_thr_create_recipe_20261022_093002.txt |
| 2026-10-22 09:35 | 156a | - | - | ? | results/phase22_cve_hunt/156a_shm_residue_kaslr_20261022_093529.txt |
| 2026-10-22 09:40 | 157a | - | - | ? | results/phase22_cve_hunt/157a_sendfile_socket_shm_20261022_094000.txt |
| 2026-10-22 09:42 | 158a | - | - | ? | results/phase22_cve_hunt/158a_kaslr_deep_sysctl_unix_20261022_094254.txt |
| 2026-10-22 09:46 | 159a | - | - | ? | results/phase22_cve_hunt/159a_signal_race_scmrights_20261022_094625.txt |
| 2026-10-22 09:46 | 274a | - | - | ? | results/phase17_new_vectors/274a_dce_ioctl_sweep_20261022_094658.txt |
| 2026-10-22 09:48 | 275a | - | - | ? | results/phase17_new_vectors/275a_dce_ioctl_encoding_20261022_094845.txt |
| 2026-10-22 09:56 | 276a | - | - | ? | results/phase17_new_vectors/276a_dce_command_ownership_20261022_095620.txt |
| 2026-10-22 09:57 | 277a | - | - | ? | results/phase17_new_vectors/277a_dce_command_shape_20261022_095718.txt |
| 2026-10-22 09:59 | 277a | - | - | ? | results/phase17_new_vectors/277a_dce_command_shape_20261022_095959.txt |
| 2026-10-22 10:02 | 278a | - | - | ? | results/phase17_new_vectors/278a_node_ioctl_sweep_20261022_100205.txt |
| 2026-10-22 10:03 | 279a | - | - | ? | results/phase17_new_vectors/279a_node_ioc_sweep_20261022_100333.txt |
| 2026-10-22 10:07 | 160b | - | - | ? | results/phase22_cve_hunt/160b_signal_minimal_20261022_100716.txt |
| 2026-10-22 10:08 | 280a | - | - | ? | results/phase17_new_vectors/280a_gc_command_table_20261022_100852.txt |
| 2026-10-22 10:08 | 58a | - | - | ? | results/phase15_native_sysent/58a_msync_reachability_20261022_100842.txt |
| 2026-10-22 10:10 | 161a | - | - | ? | results/phase22_cve_hunt/161a_dmem0_msync_invalidate_20261022_101002.txt |
| 2026-10-22 10:10 | 281a | - | - | ? | results/phase17_new_vectors/281a_gc_command_writes_20261022_101056.txt |
| 2026-10-22 10:11 | 162a | - | - | ? | results/phase22_cve_hunt/162a_sysent_679_734_20261022_101117.txt |
| 2026-10-22 10:14 | 163a | - | - | ? | results/phase22_cve_hunt/163a_kaslr_timing_sidechannel_20261022_101417.txt |
| 2026-10-22 10:15 | 282a | - | - | ? | results/phase17_new_vectors/282a_gc_table_tail_20261022_101510.txt |
| 2026-10-22 10:17 | 283a | - | - | ? | results/phase17_new_vectors/283a_gc_pointer_contents_20261022_101729.txt |
| 2026-10-22 10:19 | 284a | - | - | ? | results/phase17_new_vectors/284a_gc_full_length_field_20261022_101936.txt |
| 2026-10-22 10:22 | 285a | - | - | ? | results/phase17_new_vectors/285a_gc_big_command_20261022_102228.txt |
| 2026-10-22 10:25 | 165b | - | - | ? | results/phase22_cve_hunt/165b_rtsock_overflow_20261022_102555.txt |
| 2026-10-22 10:27 | 166a | - | - | ? | results/phase22_cve_hunt/166a_rtsock_deep_analysis_20261022_102733.txt |
| 2026-10-22 10:27 | 286a | - | - | ? | results/phase17_new_vectors/286a_gc_sweep_remainder_20261022_102717.txt |
| 2026-10-22 10:29 | 287a | - | - | ? | results/phase17_new_vectors/287a_gc_struct_commands_20261022_102913.txt |
| 2026-10-22 10:33 | 167a | - | - | ? | results/phase22_cve_hunt/167a_rtsock_residue_kaslr_20261022_103356.txt |
| 2026-10-22 10:37 | 168a | - | - | ? | results/phase22_cve_hunt/168a_kaslr_multiplex_20261022_103710.txt |
| 2026-10-22 10:40 | 169a | - | - | ? | results/phase22_cve_hunt/169a_kaslr_stat_timing_20261022_104016.txt |
| 2026-10-22 10:42 | 288a | - | - | ? | results/phase17_new_vectors/288a_node_ioctl_groups_20261022_104212.txt |
| 2026-10-22 10:44 | 170a | - | - | ? | results/phase22_cve_hunt/170a_native_api_explore_20261022_104412.txt |
| 2026-10-22 10:51 | 171a | - | - | ? | results/phase22_cve_hunt/171a_ropchain_kaslr_timing_20261022_105116.txt |
| 2026-10-22 10:56 | 172a | - | - | ? | results/phase22_cve_hunt/172a_kaslr_timing_verify_20261022_105606.txt |
| 2026-10-22 11:07 | 289a | - | - | ? | results/phase17_new_vectors/289a_msdosfs_dirent_pad_20261022_110700.txt |
| 2026-10-22 11:07 | 290a | - | - | ? | results/phase17_new_vectors/290a_fs_roots_20261022_110740.txt |
| 2026-10-22 11:13 | 292a | - | - | ? | results/phase17_new_vectors/292a_ugen_commands_20261022_111332.txt |
| 2026-10-22 11:14 | 293a | - | - | ? | results/phase17_new_vectors/293a_ugen_argument_shapes_20261022_111458.txt |
| 2026-10-22 11:16 | 294a | - | - | ? | results/phase17_new_vectors/294a_jail_layout_20261022_111606.txt |
| 2026-10-22 11:16 | 295a | - | - | ? | results/phase17_new_vectors/295a_jail_inventory_20261022_111637.txt |
| 2026-10-22 11:17 | 173a | - | - | ? | results/phase22_cve_hunt/173a_physhm_copyin_leak_20261022_111718.txt |
| 2026-10-22 11:17 | 296a | - | - | ? | results/phase17_new_vectors/296a_system_sockets_20261022_111702.txt |
| 2026-10-22 11:19 | 297a | - | - | ? | results/phase17_new_vectors/297a_socket_framing_20261022_111933.txt |
| 2026-10-22 11:22 | 174a | - | - | ? | results/phase22_cve_hunt/174a_physhm_srop_copyin_20261022_112232.txt |
| 2026-10-22 11:22 | 298a | - | - | ? | results/phase17_new_vectors/298a_dbggc_sweep_20261022_112208.txt |
| 2026-10-22 11:24 | 175a | - | - | ? | results/phase22_cve_hunt/175a_physhm_sendfile_mprotect_20261022_112425.txt |
| 2026-10-22 11:29 | 176a | - | - | ? | results/phase22_cve_hunt/176a_physhm_mprotect_read_20261022_112953.txt |
| 2026-10-22 11:34 | 177a | - | - | ? | results/phase22_cve_hunt/177a_physhm_copyin_after_mprotect_20261022_113417.txt |
| 2026-10-22 11:34 | 299a | - | - | ? | results/phase17_new_vectors/299a_node_ioc_sweep_20261022_113426.txt |
| 2026-10-22 11:53 | 300a | - | - | ? | results/phase17_new_vectors/300a_camera_commands_20261022_115356.txt |
| 2026-10-22 11:54 | 301a | - | - | ? | results/phase17_new_vectors/301a_thread_state_calls_20261022_115421.txt |
| 2026-10-22 11:54 | 302a | - | - | ? | results/phase17_new_vectors/302a_thread_state_ids_20261022_115439.txt |
| 2026-10-22 11:55 | 303a | - | - | ? | results/phase17_new_vectors/303a_thread_state_bounds_20261022_115509.txt |
| 2026-10-22 11:55 | 303a | - | - | ? | results/phase17_new_vectors/303a_thread_state_bounds_20261022_115517.txt |
| 2026-10-22 11:56 | 304a | - | - | ? | results/phase17_new_vectors/304a_camera_ret_meaning_20261022_115641.txt |
| 2026-10-22 12:04 | 305a | - | - | ? | results/phase17_new_vectors/305a_sys622_unauth_20261022_120414.txt |
| 2026-10-22 12:04 | 306a | - | - | ? | results/phase17_new_vectors/306a_sys622_device_index_20261022_120435.txt |
| 2026-10-22 12:05 | 307a | - | - | ? | results/phase17_new_vectors/307a_sys532_argument_map_20261022_120556.txt |
| 2026-10-22 12:05 | 87a | - | - | ? | results/phase17_new_vectors/87a_sys532_gpu_dispatch_nopriv_20261022_120531.txt |
| 2026-10-22 12:06 | 308a | - | - | ? | results/phase17_new_vectors/308a_sys532_handle_forge_20261022_120629.txt |
| 2026-10-22 12:06 | 308a | - | - | ? | results/phase17_new_vectors/308a_sys532_handle_forge_20261022_120652.txt |
| 2026-10-22 12:07 | 309a | - | - | ? | results/phase17_new_vectors/309a_sys532_handless_commands_20261022_120715.txt |
| 2026-10-22 12:08 | 58a | - | - | ? | results/phase15_native_sysent/58a_msync_reachability_20261022_120837.txt |
| 2026-10-22 12:09 | 179a | - | - | ? | results/phase22_cve_hunt/179a_ipv6_msfilter_reachability_20261022_120903.txt |
| 2026-10-22 12:09 | 355a | - | - | ? | results/phase17_new_vectors/355a_fstat_kptr_scan_20261022_120934.txt |
| 2026-10-22 12:10 | 180a | - | - | ? | results/phase22_cve_hunt/180a_msync_physhm_madvise_20261022_121047.txt |
| 2026-10-22 12:10 | 310a | - | - | ? | results/phase17_new_vectors/310a_sys653_value_map_20261022_121050.txt |
| 2026-10-22 12:10 | 84a | - | - | ? | results/phase17_new_vectors/84a_sys653_gpu_pte_nopriv_20261022_121037.txt |
| 2026-10-22 12:11 | 178a | - | - | ? | results/phase22_cve_hunt/178a_physhm_copyin_minimal_20261022_121115.txt |
| 2026-10-22 12:11 | 311a | - | - | ? | results/phase17_new_vectors/311a_sys654_range_op_20261022_121159.txt |
| 2026-10-22 12:12 | 181a | - | - | ? | results/phase22_cve_hunt/181a_ip4_msfilter_reachability_20261022_121240.txt |
| 2026-10-22 12:12 | 312a | - | - | ? | results/phase17_new_vectors/312a_sys654_region_scan_20261022_121245.txt |
| 2026-10-22 12:15 | 313a | - | - | ? | results/phase17_new_vectors/313a_physhm_open_20261022_121511.txt |
| 2026-10-22 12:15 | 314a | - | - | ? | results/phase17_new_vectors/314a_physhm_open_sweep_20261022_121523.txt |
| 2026-10-22 12:15 | 315a | - | - | ? | results/phase17_new_vectors/315a_physhm_map_20261022_121540.txt |
| 2026-10-22 12:16 | 182a | - | - | ? | results/phase22_cve_hunt/182a_mcast_msfilter_confirm_20261022_121620.txt |
| 2026-10-22 12:17 | 316a | - | - | ? | results/phase17_new_vectors/316a_physhm_read_20261022_121701.txt |
| 2026-10-22 12:18 | 183a | - | - | ? | results/phase22_cve_hunt/183a_msfilter_struct_shape_20261022_121832.txt |
| 2026-10-22 12:18 | 318a | - | - | ? | results/phase17_new_vectors/318a_physhm_access_20261022_121828.txt |
| 2026-10-22 12:19 | 319a | - | - | ? | results/phase17_new_vectors/319a_physhm_fd_ops_20261022_121950.txt |
| 2026-10-22 12:20 | 320a | - | - | ? | results/phase17_new_vectors/320a_physhm_prot_20261022_122005.txt |
| 2026-10-22 12:20 | 320a | - | - | ? | results/phase17_new_vectors/320a_physhm_prot_20261022_122014.txt |
| 2026-10-22 12:21 | 321a | - | - | ? | results/phase17_new_vectors/321a_physhm_ptr_20261022_122101.txt |
| 2026-10-22 12:23 | 184a | - | - | ? | results/phase22_cve_hunt/184a_new_cve_reachability_20261022_122318.txt |
| 2026-10-22 12:23 | 322a | - | - | ? | results/phase17_new_vectors/322a_sys601_commands_20261022_122315.txt |
| 2026-10-22 12:23 | 323a | - | - | ? | results/phase17_new_vectors/323a_sys601_sweep_20261022_122329.txt |
| 2026-10-22 12:24 | 324a | - | - | ? | results/phase17_new_vectors/324a_sys601_sweep2_20261022_122438.txt |
| 2026-10-22 12:27 | 325a | - | - | ? | results/phase17_new_vectors/325a_thr_ucontext_20261022_122754.txt |
| 2026-10-22 12:28 | 325a | - | - | ? | results/phase17_new_vectors/325a_thr_ucontext_20261022_122833.txt |
| 2026-10-22 12:29 | 185a | - | - | ? | results/phase22_cve_hunt/185a_umtx_mutex_race_20261022_122906.txt |
| 2026-10-22 12:29 | 326a | - | - | ? | results/phase17_new_vectors/326a_thr_set_ucontext_20261022_122915.txt |
| 2026-10-22 12:29 | 326a | - | - | ? | results/phase17_new_vectors/326a_thr_set_ucontext_20261022_122928.txt |
| 2026-10-22 12:29 | 326a | - | - | ? | results/phase17_new_vectors/326a_thr_set_ucontext_20261022_122948.txt |
| 2026-10-22 12:31 | 327a | - | - | ? | results/phase17_new_vectors/327a_opmc_scope_20261022_123153.txt |
| 2026-10-22 12:36 | 330a | - | - | ? | results/phase17_new_vectors/330a_dmem_open_20261022_123604.txt |
| 2026-10-22 12:36 | 330a | - | - | ? | results/phase17_new_vectors/330a_dmem_open_20261022_123616.txt |
| 2026-10-22 12:36 | 331a | - | - | ? | results/phase17_new_vectors/331a_mmap_dmem_matrix_20261022_123630.txt |
| 2026-10-22 12:36 | 332a | - | - | ? | results/phase17_new_vectors/332a_authid_gates_20261022_123643.txt |
| 2026-10-22 12:36 | 333a | - | - | ? | results/phase17_new_vectors/333a_cred_foreign_pid_20261022_123655.txt |
| 2026-10-22 12:44 | 337a | - | - | ? | results/phase17_new_vectors/337a_mdbg_minimal_20261022_124437.txt |
| 2026-10-22 12:45 | 335a | - | - | ? | results/phase17_new_vectors/335a_info_family_shapes_20261022_124546.txt |
| 2026-10-22 12:45 | 336a | - | - | ? | results/phase17_new_vectors/336a_evf_handle_20261022_124514.txt |
| 2026-10-22 12:45 | 338a | - | - | ? | results/phase17_new_vectors/338a_evf_handle_space_20261022_124527.txt |
| 2026-10-22 12:53 | 341a | - | - | ? | results/phase17_new_vectors/341a_named_objects_create_20261022_125357.txt |
| 2026-10-22 12:57 | 343a | - | - | ? | results/phase17_new_vectors/343a_fmem_limit_effect_20261022_125753.txt |
| 2026-10-22 12:58 | 344a | - | - | ? | results/phase17_new_vectors/344a_fmem_limit_gpu_20261022_125834.txt |
| 2026-10-22 13:02 | 345a | - | - | ? | results/phase17_new_vectors/345a_fmem_raise_20261022_130203.txt |
| 2026-10-22 13:04 | 347a | - | - | ? | results/phase17_new_vectors/347a_handle_family_confusion_20261022_130431.txt |
| 2026-10-22 14:21 | test | - | - | ? | results/phase22_cve_hunt/test_alive_20261022_142136.txt |
| 2026-10-22 14:22 | 185d | - | - | ? | results/phase22_cve_hunt/185d_child_getpid_20261022_142230.txt |
| 2026-10-22 14:23 | 185e | - | - | ? | results/phase22_cve_hunt/185e_child_getpid_v2_20261022_142354.txt |
| 2026-10-22 14:25 | 185f | - | - | ? | results/phase22_cve_hunt/185f_child_getpid_v3_20261022_142554.txt |
| 2026-10-22 14:27 | 185g | - | - | ? | results/phase22_cve_hunt/185g_find_gadgets_20261022_142714.txt |
| 2026-10-22 14:28 | 185h | - | - | ? | results/phase22_cve_hunt/185h_child_getpid_final_20261022_142845.txt |
| 2026-10-22 14:46 | 186c | - | - | ? | results/phase22_cve_hunt/186c_socket_poll_close_20261022_144643.txt |
| 2026-10-22 14:46 | test | - | - | ? | results/phase22_cve_hunt/test_alive_20261022_144602.txt |
| 2026-10-22 14:51 | 102b | - | - | ? | results/phase22_threaded_races/102b_netcontrol_route_trigger_20261022_145139.txt |
| 2026-10-22 14:51 | 222a | - | - | ? | results/phase17_new_vectors/222a_netcontrol_clean_trigger_20261022_145135.txt |
| 2026-10-22 14:52 | 102b | - | - | ? | results/phase22_threaded_races/102b_netcontrol_route_trigger_20261022_145201.txt |
| 2026-10-22 14:54 | 102b | - | - | ? | results/phase22_threaded_races/102b_netcontrol_route_trigger_20261022_145410.txt |
| 2026-10-22 14:58 | 102b | - | - | ? | results/phase22_threaded_races/102b_netcontrol_route_trigger_20261022_145859.txt |
| 2026-10-22 15:04 | 102c | - | - | ? | results/phase22_threaded_races/102c_netcontrol_trigger_v2_20261022_150401.txt |
| 2026-10-22 15:04 | 102c | - | - | ? | results/phase22_threaded_races/102c_netcontrol_trigger_v2_20261022_150454.txt |
| 2026-10-22 15:04 | 102d | - | - | ? | results/phase22_threaded_races/102d_netcontrol_ifindex_scan_20261022_150434.txt |
| 2026-10-22 15:05 | 101a | - | - | ? | results/phase22_threaded_races/101a_double_close_race_20261022_150548.txt |
| 2026-10-22 15:08 | 103a | - | - | ? | results/phase22_threaded_races/103a_sys601_race_20261022_150857.txt |
| 2026-10-22 15:11 | 104a | - | - | ? | results/phase22_threaded_races/104a_child_blocked_syscalls_20261022_151110.txt |
| 2026-10-22 15:13 | 104a | - | - | ? | results/phase22_threaded_races/104a_child_blocked_syscalls_20261022_151307.txt |
| 2026-10-22 15:14 | 104b | - | - | ? | results/phase22_threaded_races/104b_fcntl_pipe_explore_20261022_151447.txt |
| 2026-10-22 15:16 | 105a | - | - | ? | results/phase22_threaded_races/105a_pipe_close_race_20261022_151655.txt |
| 2026-10-22 15:20 | 106a | - | - | ? | results/phase22_threaded_races/106a_mmap_exec_verify_20261022_152015.txt |
| 2026-10-22 15:23 | 107a | - | - | ? | results/phase22_threaded_races/107a_mprotect_ghost_exec_20261022_152317.txt |
| 2026-10-22 15:24 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261022_152411.txt |
| 2026-10-22 15:27 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261022_152712.txt |
| 2026-10-22 15:29 | 108a | - | - | ? | results/phase22_threaded_races/108a_cclosure_gadget_chain_20261022_152955.txt |
| 2026-10-22 15:30 | 108a | - | - | ? | results/phase22_threaded_races/108a_cclosure_gadget_chain_20261022_153037.txt |
| 2026-10-22 15:35 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261022_153527.txt |
| 2026-10-22 15:40 | 348a | - | - | ? | results/phase17_new_vectors/348a_gpu_pool_scan_20261022_154009.txt |
| 2026-10-22 15:47 | 108b | - | - | ? | results/phase22_threaded_races/108b_cclosure_arb_read_20261022_154743.txt |
| 2026-10-22 15:50 | 109a | - | - | ? | results/phase22_threaded_races/109a_register_leak_scan_20261022_155002.txt |
| 2026-10-22 15:51 | 348a | - | - | ? | results/phase17_new_vectors/348a_gpu_pool_scan_20261022_155156.txt |
| 2026-10-22 15:52 | 349a | - | - | ? | results/phase17_new_vectors/349a_osem_family_20261022_155250.txt |
| 2026-10-22 15:53 | 110a | - | - | ? | results/phase22_threaded_races/110a_fstat_child_thread_20261022_155348.txt |
| 2026-10-22 15:57 | 111a | - | - | ? | results/phase22_threaded_races/111a_kldstat_child_thread_20261022_155714.txt |
| 2026-10-22 15:57 | 349b | - | - | ? | results/phase17_new_vectors/349b_osem_order_20261022_155726.txt |
| 2026-10-22 16:01 | 112a | - | - | ? | results/phase22_threaded_races/112a_child_syscall_survey_20261022_160114.txt |
| 2026-10-22 16:04 | 113a | - | - | ? | results/phase22_threaded_races/113a_fd_scan_dirents_mincore_20261022_160430.txt |
| 2026-10-22 16:05 | 349c | - | - | ? | results/phase17_new_vectors/349c_osem_wait_20261022_160530.txt |
| 2026-10-22 16:05 | 350a | - | - | ? | results/phase17_new_vectors/350a_blockpool_batch_20261022_160542.txt |
| 2026-10-22 16:05 | 352a | - | - | ? | results/phase17_new_vectors/352a_aio_batch_20261022_160559.txt |
| 2026-10-22 16:06 | 352b | - | - | ? | results/phase17_new_vectors/352b_aio_data_20261022_160628.txt |
| 2026-10-22 16:07 | 114a | - | - | ? | results/phase22_threaded_races/114a_sony_fd_probe_20261022_160714.txt |
| 2026-10-22 16:07 | 352c | - | - | ? | results/phase17_new_vectors/352c_aio_bisect_20261022_160738.txt |
| 2026-10-22 16:08 | 115a | - | - | ? | results/phase22_threaded_races/115a_fd9_mmap_deep_20261022_160843.txt |
| 2026-10-22 16:08 | 352d | - | - | ? | results/phase17_new_vectors/352d_aio_edges_20261022_160838.txt |
| 2026-10-22 16:08 | 352e | - | - | ? | results/phase17_new_vectors/352e_aio_results_20261022_160848.txt |
| 2026-10-22 16:09 | 352f | - | - | ? | results/phase17_new_vectors/352f_aio_repeat_20261022_160902.txt |
| 2026-10-22 16:10 | 116a | - | - | ? | results/phase22_threaded_races/116a_gpu_register_map_20261022_161035.txt |
| 2026-10-22 16:12 | 352h | - | - | ? | results/phase17_new_vectors/352h_aio_slots_20261022_161248.txt |
| 2026-10-22 16:14 | 346a | - | - | ? | results/phase17_new_vectors/346a_fmem_headroom_20261022_161448.txt |
| 2026-10-22 16:15 | 117a | - | - | ? | results/phase22_threaded_races/117a_all_chr_mmap_20261022_161545.txt |
| 2026-10-22 16:15 | 352j | - | - | ? | results/phase17_new_vectors/352j_aio_hostile_20261022_161504.txt |
| 2026-10-22 16:18 | 349d | - | - | ? | results/phase17_new_vectors/349d_osem_timeout_ptr_20261022_161833.txt |
| 2026-10-22 16:18 | 352k | - | - | ? | results/phase17_new_vectors/352k_aio_commands_20261022_161843.txt |
| 2026-10-22 16:19 | 118a | - | - | ? | results/phase22_threaded_races/118a_read_gadget_scan_20261022_161950.txt |
| 2026-10-22 16:22 | 118b | - | - | ? | results/phase22_threaded_races/118b_fast_gadget_scan_20261022_162245.txt |
| 2026-10-22 16:24 | 118c | - | - | ? | results/phase22_threaded_races/118c_rsi_read_test_20261022_162458.txt |
| 2026-10-22 16:24 | 352l | - | - | ? | results/phase17_new_vectors/352l_aio_write_source_20261022_162420.txt |
| 2026-10-22 16:24 | 352m | - | - | ? | results/phase17_new_vectors/352m_aio_write_file_20261022_162444.txt |
| 2026-10-22 16:27 | 352n | - | - | ? | results/phase17_new_vectors/352n_aio_write_socket_20261022_162740.txt |
| 2026-10-22 16:28 | 118d | - | - | ? | results/phase22_threaded_races/118d_rdi_offset_read_20261022_162805.txt |
| 2026-10-22 16:30 | 352n | - | - | ? | results/phase17_new_vectors/352n_aio_write_socket_20261022_163000.txt |
| 2026-10-22 16:30 | 352o | - | - | ? | results/phase17_new_vectors/352o_aio_targets_20261022_163033.txt |
| 2026-10-22 16:31 | 119a | - | - | ? | results/phase22_threaded_races/119a_rax_arb_read_20261022_163115.txt |
| 2026-10-22 16:31 | 352p | - | - | ? | results/phase17_new_vectors/352p_aio_generation_20261022_163108.txt |
| 2026-10-22 16:38 | 119b | - | - | ? | results/phase22_threaded_races/119b_data_segment_scan_20261022_163854.txt |
| 2026-10-22 16:39 | 353d | - | - | ? | results/phase17_new_vectors/353d_fstat_kldstat_20261022_163923.txt |
| 2026-10-22 16:42 | 119c | - | - | ? | results/phase22_threaded_races/119c_real_data_scan_20261022_164221.txt |
| 2026-10-22 16:42 | 354a | - | - | ? | results/phase17_new_vectors/354a_unexplained_kills_20261022_164235.txt |
| 2026-10-22 16:44 | 119d | - | - | ? | results/phase22_threaded_races/119d_kptr_verify_20261022_164455.txt |
| 2026-10-22 16:44 | 354b | - | - | ? | results/phase17_new_vectors/354b_range_under_sigign_20261022_164419.txt |
| 2026-10-22 16:49 | 354b | - | - | ? | results/phase17_new_vectors/354b_range_under_sigign_20261022_164915.txt |
| 2026-10-22 16:49 | 354c | - | - | ? | results/phase17_new_vectors/354c_bisect_451_20261022_164947.txt |
| 2026-10-22 16:52 | 119e | - | - | ? | results/phase22_threaded_races/119e_pipe_and_modules_20261022_165247.txt |
| 2026-10-22 16:54 | 119f | - | - | ? | results/phase22_threaded_races/119f_safe_pipe_read_20261022_165405.txt |
| 2026-10-22 16:54 | 354d | - | - | ? | results/phase17_new_vectors/354d_range_456_20261022_165436.txt |
| 2026-10-22 16:55 | 119g | - | - | ? | results/phase22_threaded_races/119g_modules_eboot_rest_20261022_165526.txt |
| 2026-10-22 16:56 | 354e | - | - | ? | results/phase17_new_vectors/354e_bisect_501_20261022_165614.txt |
| 2026-10-22 16:56 | 354e | - | - | ? | results/phase17_new_vectors/354e_bisect_501_20261022_165626.txt |
| 2026-10-22 16:56 | 354f | - | - | ? | results/phase17_new_vectors/354f_range_523_20261022_165635.txt |
| 2026-10-22 16:57 | 354g | - | - | ? | results/phase17_new_vectors/354g_range_623_20261022_165716.txt |
| 2026-10-22 16:57 | 355a | - | - | ? | results/phase17_new_vectors/355a_aio_class_20261022_165716.txt |
| 2026-10-22 16:57 | 355b | - | - | ? | results/phase17_new_vectors/355b_blockpool_fd_20261022_165750.txt |
| 2026-10-22 16:58 | 120a | - | - | ? | results/phase22_threaded_races/120a_umtx_op_survey_20261022_165819.txt |
| 2026-10-22 16:58 | 355c | - | - | ? | results/phase17_new_vectors/355c_sys622_data_20261022_165803.txt |
| 2026-10-22 17:03 | 120b | - | - | ? | results/phase22_threaded_races/120b_umtx_safe_survey_20261022_170336.txt |
| 2026-10-22 17:07 | 120c | - | - | ? | results/phase22_threaded_races/120c_umtx_rest_20261022_170701.txt |
| 2026-10-22 17:10 | 120d | - | - | ? | results/phase22_threaded_races/120d_mutex_rw_pi_20261022_171030.txt |
| 2026-10-22 17:15 | 120e | - | - | ? | results/phase22_threaded_races/120e_lock_cycles_20261022_171549.txt |
| 2026-10-22 17:19 | 120e | - | - | ? | results/phase22_threaded_races/120e_lock_cycles_20261022_171912.txt |
| 2026-10-22 17:24 | 121a | - | - | ? | results/phase22_threaded_races/121a_pi_mutex_race_20261022_172411.txt |
| 2026-10-22 17:25 | 121b | - | - | ? | results/phase22_threaded_races/121b_native_pi_race_20261022_172529.txt |
| 2026-10-22 17:39 | 356a | - | - | ? | results/phase17_new_vectors/356a_chicken_retest_20261022_173936.txt |
| 2026-10-22 17:39 | 356a | - | - | ? | results/phase17_new_vectors/356a_chicken_retest_20261022_173941.txt |
| 2026-10-22 17:41 | 357a | - | - | ? | results/phase17_new_vectors/357a_sys622_device_index_20261022_174133.txt |
| 2026-10-22 17:42 | 358a | - | - | ? | results/phase17_new_vectors/358a_gc_read_20261022_174215.txt |
| 2026-10-22 17:43 | 359a | - | - | ? | results/phase17_new_vectors/359a_dirent_inodes_20261022_174331.txt |
| 2026-10-22 17:49 | 122a2 | - | - | ? | results/phase22_threaded_races/122a2_physhm_safe_20261022_174953.txt |
| 2026-10-22 17:50 | 360a | - | - | ? | results/phase17_new_vectors/360a_encrypt_ioctl_matrix_20261022_175029.txt |
| 2026-10-22 17:53 | 361a | - | - | ? | results/phase17_new_vectors/361a_socket_consumption_20261022_175317.txt |
| 2026-10-22 17:53 | 361b | - | - | ? | results/phase17_new_vectors/361b_socket_consumption_20261022_175357.txt |
| 2026-10-22 17:54 | 361b | - | - | ? | results/phase17_new_vectors/361b_socket_consumption_20261022_175438.txt |
| 2026-10-22 17:54 | 362a | - | - | ? | results/phase17_new_vectors/362a_compositor_reply_20261022_175455.txt |
| 2026-10-22 17:55 | 362b | - | - | ? | results/phase17_new_vectors/362b_socket_state_20261022_175509.txt |
| 2026-10-22 17:56 | 362b | - | - | ? | results/phase17_new_vectors/362b_socket_state_20261022_175632.txt |
| 2026-10-22 17:56 | 362b | - | - | ? | results/phase17_new_vectors/362b_socket_state_20261022_175637.txt |
| 2026-10-22 17:56 | 363a | - | - | ? | results/phase17_new_vectors/363a_vrtracker_ladder_20261022_175645.txt |
| 2026-10-22 17:57 | 362b | - | - | ? | results/phase17_new_vectors/362b_socket_state_20261022_175716.txt |
| 2026-10-22 17:57 | 364a | - | - | ? | results/phase17_new_vectors/364a_vrtracker_shapes_20261022_175750.txt |
| 2026-10-22 18:01 | 365a | - | - | ? | results/phase17_new_vectors/365a_compositor_reply_20261022_180150.txt |
| 2026-10-22 18:02 | 366a | - | - | ? | results/phase17_new_vectors/366a_compositor_words_20261022_180217.txt |
| 2026-10-22 18:02 | 367a | - | - | ? | results/phase17_new_vectors/367a_compositor_size_20261022_180240.txt |
| 2026-10-22 18:03 | 368a | - | - | ? | results/phase17_new_vectors/368a_compositor_opcodes_20261022_180326.txt |
| 2026-10-22 18:03 | 369a | - | - | ? | results/phase17_new_vectors/369a_compositor_header_20261022_180356.txt |
| 2026-10-22 18:04 | 370a | - | - | ? | results/phase17_new_vectors/370a_compositor_args_20261022_180431.txt |
| 2026-10-22 18:04 | 371a | - | - | ? | results/phase17_new_vectors/371a_compositor_sizes_20261022_180456.txt |
| 2026-10-22 18:06 | 372a | - | - | ? | results/phase17_new_vectors/372a_compositor_session_20261022_180626.txt |
| 2026-10-22 18:06 | 373a | - | - | ? | results/phase17_new_vectors/373a_compositor_fullread_20261022_180644.txt |
| 2026-10-22 18:08 | 374a | - | - | ? | results/phase17_new_vectors/374a_eboot_socket_strings_20261022_180807.txt |
| 2026-10-22 18:08 | 375a | - | - | ? | results/phase17_new_vectors/375a_region_names_20261022_180822.txt |
| 2026-10-22 18:10 | 376a | - | - | ? | results/phase17_new_vectors/376a_module_strings_20261022_181048.txt |
| 2026-10-22 18:14 | 362b | - | - | ? | results/phase17_new_vectors/362b_socket_state_20261022_181426.txt |
| 2026-10-22 18:14 | 378a | - | - | ? | results/phase17_new_vectors/378a_jail_artifacts_20261022_181438.txt |
| 2026-10-22 18:14 | 379a | - | - | ? | results/phase17_new_vectors/379a_socket_targets_20261022_181453.txt |
| 2026-10-22 18:19 | 122a3 | - | - | ? | results/phase22_threaded_races/122a3_physhm_prot_test_20261022_181919.txt |
| 2026-10-22 18:20 | 122a4 | - | - | ? | results/phase22_threaded_races/122a4_physhm_offset_args_20261022_182057.txt |
| 2026-10-22 18:22 | 382a | - | - | ? | results/phase17_new_vectors/382a_gpu_refs_20261022_182200.txt |
| 2026-10-22 18:23 | 382a | - | - | ? | results/phase17_new_vectors/382a_gpu_refs_20261022_182322.txt |
| 2026-10-22 18:23 | 382a | - | - | ? | results/phase17_new_vectors/382a_gpu_refs_20261022_182354.txt |
| 2026-10-22 18:26 | 383a | - | - | ? | results/phase17_new_vectors/383a_thr_new_20261022_182600.txt |
| 2026-10-22 18:26 | 383a | - | - | ? | results/phase17_new_vectors/383a_thr_new_20261022_182615.txt |
| 2026-10-22 18:26 | 383a | - | - | ? | results/phase17_new_vectors/383a_thr_new_20261022_182639.txt |
| 2026-10-22 18:27 | 383a | - | - | ? | results/phase17_new_vectors/383a_thr_new_20261022_182718.txt |
| 2026-10-22 18:36 | 50e | - | - | ? | results/phase11_network_attacks/50e_ipv6_msfilter_reach_20261022_183623.txt |
| 2026-10-22 18:37 | 50f | - | - | ? | results/phase11_network_attacks/50f_ipv6_msfilter_aligned_20261022_183727.txt |
| 2026-10-22 18:40 | 50g | - | - | ? | results/phase11_network_attacks/50g_ipv6_msfilter_source_sizes_20261022_184026.txt |
| 2026-10-22 18:41 | 50h | - | - | ? | results/phase11_network_attacks/50h_ipv6_msfilter_child_control_20261022_184128.txt |
| 2026-10-22 18:44 | 50h | - | - | ? | results/phase11_network_attacks/50h_ipv6_msfilter_child_control_20261022_184413.txt |
| 2026-10-22 18:45 | 50i | - | - | ? | results/phase11_network_attacks/50i_ipv6_msfilter_leave_overlap_20261022_184502.txt |
| 2026-10-22 18:46 | 50j | - | - | ? | results/phase11_network_attacks/50j_ipv6_msfilter_gated_overlap_20261022_184602.txt |
| 2026-10-22 18:46 | 50k | - | - | ? | results/phase11_network_attacks/50k_ipv6_msfilter_pipe_gated_20261022_184659.txt |
| 2026-10-22 18:47 | 50k | - | - | ? | results/phase11_network_attacks/50k_ipv6_msfilter_pipe_gated_20261022_184723.txt |
| 2026-10-22 18:50 | 50l | - | - | ? | results/phase11_network_attacks/50l_ipv6_msfilter_dual_child_20261022_185015.txt |
| 2026-10-22 18:50 | 50m | - | - | ? | results/phase11_network_attacks/50m_ipv6_msfilter_shared_gate_20261022_185043.txt |
| 2026-10-22 18:51 | 50n | - | - | ? | results/phase11_network_attacks/50n_cpuset_affinity_read_20261022_185119.txt |
| 2026-10-22 18:53 | 50o | - | - | ? | results/phase11_network_attacks/50o_ipv6_msfilter_sustained_race_20261022_185346.txt |
| 2026-10-22 19:14 | 124a | - | - | ? | results/phase22_threaded_races/124a_sys588_wxbypass_verify_20261022_191455.txt |
| 2026-10-22 19:24 | 122b2 | - | - | ? | results/phase22_threaded_races/122b2_sys630_safe_20261022_192408.txt |
| 2026-10-22 19:24 | 58a | - | - | ? | results/phase15_native_sysent/58a_msync_reachability_20261022_192449.txt |
| 2026-10-22 19:26 | 58b | - | - | ? | results/phase15_native_sysent/58b_msync_devpager_20261022_192601.txt |
| 2026-10-22 19:26 | 58b | - | - | ? | results/phase15_native_sysent/58b_msync_devpager_20261022_192645.txt |
| 2026-10-22 19:34 | 126a | - | - | ? | results/phase22_threaded_races/126a_fstat_devices_aio_ids_20261022_193437.txt |
| 2026-10-22 19:45 | 50e3 | - | - | ? | results/phase23_cve_reachability/50e3_msfilter_discriminate_20261022_194524.txt |
| 2026-10-22 19:49 | 50o | - | - | ? | results/phase11_network_attacks/50o_ipv6_msfilter_sustained_race_20261022_194955.txt |
| 2026-10-22 19:50 | 50p | - | - | ? | results/phase11_network_attacks/50p_ipv6_msfilter_long_race_20261022_195014.txt |
| 2026-10-22 19:51 | 50g | - | - | ? | results/phase23_cve_reachability/50g_665_668_sigsys_20261022_195155.txt |
| 2026-10-22 19:52 | 126a | - | - | ? | results/phase22_threaded_races/126a_fstat_devices_aio_ids_20261022_195202.txt |
| 2026-10-22 19:53 | 50q | - | - | ? | results/phase11_network_attacks/50q_ipv6_msfilter_return_census_20261022_195332.txt |
| 2026-10-22 19:53 | 50r | - | - | ? | results/phase11_network_attacks/50r_ipv6_msfilter_repeat_control_20261022_195346.txt |
| 2026-10-22 19:54 | 50s | - | - | ? | results/phase11_network_attacks/50s_ipv6_msfilter_rejoin_control_20261022_195400.txt |
| 2026-10-22 19:54 | 50t | - | - | ? | results/phase11_network_attacks/50t_ipv6_msfilter_child_repeat_control_20261022_195411.txt |
| 2026-10-22 19:54 | 50u | - | - | ? | results/phase11_network_attacks/50u_ipv6_msfilter_rcx_restore_control_20261022_195435.txt |
| 2026-10-22 19:55 | 50v | - | - | ? | results/phase11_network_attacks/50v_ipv6_msfilter_full_register_restore_20261022_195505.txt |
| 2026-10-22 19:55 | 50w | - | - | ? | results/phase11_network_attacks/50w_ipv6_msfilter_valid_call_race_20261022_195515.txt |
| 2026-10-22 19:56 | 50x | - | - | ? | results/phase11_network_attacks/50x_ipv6_msfilter_long_no_parent_20261022_195650.txt |
| 2026-10-22 20:00 | 127a | - | - | ? | results/phase24_thread_rop/127a_child_rop_syscall_20261022_200011.txt |
| 2026-10-22 20:02 | 127b | - | - | ? | results/phase24_thread_rop/127b_gadget_deep_scan_20261022_200200.txt |
| 2026-10-22 20:04 | 127c | - | - | ? | results/phase24_thread_rop/127c_fast_gadget_find_20261022_200412.txt |
| 2026-10-22 20:06 | 127d | - | - | ? | results/phase24_thread_rop/127d_rop_chain_dump_20261022_200624.txt |
| 2026-10-22 20:06 | 277g | - | - | ? | results/phase17_new_vectors/277g_netcontrol_dead_clear_slot_test_20261022_200623.txt |
| 2026-10-22 20:09 | 83a | - | - | ? | results/phase17_new_vectors/83a_sys601_deep_retest_20261022_200903.txt |
| 2026-10-22 20:11 | 127e | - | - | ? | results/phase24_thread_rop/127e_syscall_hunt_20261022_201124.txt |
| 2026-10-22 20:12 | 83c | - | - | ? | results/phase17_new_vectors/83c_sys601_arg2_copyout_20261022_201232.txt |
| 2026-10-22 20:14 | 112b | - | - | ? | results/phase17_new_vectors/112b_sys605_whitelist_gate_20261022_201455.txt |
| 2026-10-22 20:14 | 127f | - | - | ? | results/phase24_thread_rop/127f_syscall_module_scan_20261022_201443.txt |
| 2026-10-22 20:22 | 127g | - | - | ? | results/phase24_thread_rop/127g_syscall_path_and_rop_loop_20261022_202224.txt |
| 2026-10-22 20:31 | 127h | - | - | ? | results/phase24_thread_rop/127h_thread_rop_fixed_20261022_203129.txt |
| 2026-10-22 20:31 | 127h | - | - | ? | results/phase24_thread_rop/127h_thread_rop_fixed_20261022_203154.txt |
| 2026-10-22 20:34 | 127i | - | - | ? | results/phase24_thread_rop/127i_thread_156d_clone_20261022_203409.txt |
| 2026-10-22 20:35 | 127j | - | - | ? | results/phase24_thread_rop/127j_rop_write_loop_20261022_203519.txt |
| 2026-10-22 20:42 | 127k | - | - | ? | results/phase24_thread_rop/127k_umtx_race_20261022_204201.txt |
| 2026-10-22 20:53 | 127l | - | - | ? | results/phase24_thread_rop/127l_umtx_race_trylock_20261022_205337.txt |
| 2026-10-22 20:55 | 127m | - | - | ? | results/phase24_thread_rop/127m_pi_dangling_race_20261022_205511.txt |
| 2026-10-22 20:57 | 386a | - | - | ? | results/phase17_new_vectors/386a_gc_hmd_ioctl_sweep_20261022_205749.txt |
| 2026-10-22 20:59 | 387a | - | - | ? | results/phase17_new_vectors/387a_eboot_ioctl_constants_20261022_205931.txt |
| 2026-10-22 21:01 | 127n | - | - | ? | results/phase24_thread_rop/127n_pi_alloc_measure_20261022_210149.txt |
| 2026-10-22 21:04 | 385a | - | - | ? | results/phase17_new_vectors/385a_prx_readability_20261022_210429.txt |
| 2026-10-22 21:05 | 388a | - | - | ? | results/phase17_new_vectors/388a_self_header_20261022_210502.txt |
| 2026-10-22 21:05 | 389a | - | - | ? | results/phase17_new_vectors/389a_elf_segments_20261022_210526.txt |
| 2026-10-22 21:06 | 390a | - | - | ? | results/phase17_new_vectors/390a_self_plaintext_20261022_210605.txt |
| 2026-10-22 21:12 | 391a | - | - | ? | results/phase17_new_vectors/391a_sys622_arg1_pointer_20261022_211208.txt |
| 2026-10-22 21:18 | 128a | - | - | ? | results/phase25_sys625_msr/128a_sys625_survey_20261022_211851.txt |
| 2026-10-22 21:20 | 128b | - | - | ? | results/phase25_sys625_msr/128b_umtx_syscall_race_20261022_212008.txt |
| 2026-10-22 21:20 | 392a | - | - | ? | results/phase17_new_vectors/392a_thread_syscall_storm_20261022_212003.txt |
| 2026-10-22 21:23 | 393a | - | - | ? | results/phase17_new_vectors/393a_storm_bisect_20261022_212351.txt |
| 2026-10-22 21:24 | 128c | - | - | ? | results/phase25_sys625_msr/128c_mmap_munmap_race_20261022_212422.txt |
| 2026-10-22 21:28 | 128d | - | - | ? | results/phase25_sys625_msr/128d_cv_socket_race_20261022_212815.txt |
| 2026-10-22 21:28 | 394a | - | - | ? | results/phase17_new_vectors/394a_machine_health_20261022_212804.txt |
| 2026-10-22 21:30 | 395a | - | - | ? | results/phase17_new_vectors/395a_storm_small_20261022_213029.txt |
| 2026-10-22 21:51 | 128f | - | - | ? | results/phase25_sys625_msr/128f_sa_identity_20261022_215129.txt |
| 2026-10-22 21:53 | 128e | - | - | ? | results/phase25_sys625_msr/128e_socket_race_minimal_20261022_215314.txt |
| 2026-10-22 21:53 | 396a | - | - | ? | results/phase17_new_vectors/396a_read_ladder_20261022_215302.txt |
| 2026-10-22 21:57 | 397a | - | - | ? | results/phase17_new_vectors/397a_thread_idle_20261022_215708.txt |
| 2026-10-22 22:12 | 394a | - | - | ? | results/phase17_new_vectors/394a_machine_health_20261022_221236.txt |
| 2026-10-22 22:13 | 398a | - | - | ? | results/phase17_new_vectors/398a_thread_park_isolation_20261022_221326.txt |
| 2026-10-22 22:28 | 128g | - | - | ? | results/phase25_sys625_msr/128g_controlled_fd_race_20261022_222810.txt |
| 2026-10-22 22:30 | 399a | - | - | ? | results/phase17_new_vectors/399a_thread_park_no_kill_20261022_223003.txt |
| 2026-10-22 22:30 | 400a | - | - | ? | results/phase17_new_vectors/400a_thread_storm_small_20261022_223035.txt |
| 2026-10-22 22:36 | 275a | - | - | ? | results/phase17_new_vectors/275a_sysent_tail_realargs_20261022_223604.txt |
| 2026-10-22 22:36 | 401a | - | - | ? | results/phase17_new_vectors/401a_thread_one_syscall_20261022_223624.txt |
| 2026-10-22 22:37 | 402a | - | - | ? | results/phase17_new_vectors/402a_syscall_gadget_scan_20261022_223728.txt |
| 2026-10-22 22:38 | 403a | - | - | ? | results/phase17_new_vectors/403a_pop_rax_scan_20261022_223816.txt |
| 2026-10-22 22:38 | 404a | - | - | ? | results/phase17_new_vectors/404a_thread_syscall_chain_20261022_223835.txt |
| 2026-10-22 22:39 | 275c | - | - | ? | results/phase17_new_vectors/275c_sysent_tail_realargs2_20261022_223925.txt |
| 2026-10-22 22:41 | 275d | - | - | ? | results/phase17_new_vectors/275d_sysent_child_bypass_20261022_224149.txt |
| 2026-10-22 22:44 | 404a | - | - | ? | results/phase17_new_vectors/404a_thread_syscall_chain_20261022_224403.txt |
| 2026-10-22 22:45 | 405a | - | - | ? | results/phase17_new_vectors/405a_gadget_verify_20261022_224535.txt |
| 2026-10-22 22:49 | 406a | - | - | ? | results/phase17_new_vectors/406a_thread_syscall_chain_fixed_20261022_224913.txt |
| 2026-10-22 22:53 | 407a | - | - | ? | results/phase17_new_vectors/407a_chain_layout_fixed_20261022_225307.txt |
| 2026-10-22 22:53 | 408a | - | - | ? | results/phase17_new_vectors/408a_chain_writes_20261022_225356.txt |
| 2026-10-22 22:54 | 408a | - | - | ? | results/phase17_new_vectors/408a_chain_writes_20261022_225424.txt |
| 2026-10-22 22:55 | 408a | - | - | ? | results/phase17_new_vectors/408a_chain_writes_20261022_225531.txt |
| 2026-10-22 22:55 | 408a | - | - | ? | results/phase17_new_vectors/408a_chain_writes_20261022_225543.txt |
| 2026-10-22 22:56 | 409a | - | - | ? | results/phase17_new_vectors/409a_chain_arg_gadgets_20261022_225607.txt |
| 2026-10-22 23:03 | 411a | - | - | ? | results/phase17_new_vectors/411a_aio_race_20261022_230339.txt |
| 2026-10-22 23:04 | 412a | - | - | ? | results/phase17_new_vectors/412a_aio_race_long_20261022_230453.txt |
| 2026-10-22 23:06 | 413a | - | - | ? | results/phase17_new_vectors/413a_chain_control_long_20261022_230604.txt |
| 2026-10-22 23:07 | 413c | - | - | ? | results/phase17_new_vectors/413c_chain_bigstack_400_20261022_230726.txt |
| 2026-10-22 23:07 | 413d | - | - | ? | results/phase17_new_vectors/413d_chain_bigstack_1200_20261022_230732.txt |
| 2026-10-22 23:08 | 414a | - | - | ? | results/phase17_new_vectors/414a_aio_race_bigstack_20261022_230803.txt |
| 2026-10-22 23:11 | 415a | - | - | ? | results/phase17_new_vectors/415a_aio_two_children_20261022_231101.txt |
| 2026-10-22 23:11 | 416a | - | - | ? | results/phase17_new_vectors/416a_aio_delete_race_20261022_231115.txt |
| 2026-10-22 23:12 | 417a | - | - | ? | results/phase17_new_vectors/417a_chain_exit_20261022_231248.txt |
| 2026-10-22 23:15 | 418a | - | - | ? | results/phase17_new_vectors/418a_exit_many_children_20261022_231502.txt |
| 2026-10-22 23:15 | 419a | - | - | ? | results/phase17_new_vectors/419a_fstat_close_race_20261022_231527.txt |
| 2026-10-22 23:16 | 420a | - | - | ? | results/phase17_new_vectors/420a_aio_three_children_20261022_231625.txt |
| 2026-10-22 23:17 | 421a | - | - | ? | results/phase17_new_vectors/421a_kevent_close_race_20261022_231753.txt |
| 2026-10-22 23:18 | 422a | - | - | ? | results/phase17_new_vectors/422a_fd_reuse_race_20261022_231850.txt |
| 2026-10-22 23:19 | 422b | - | - | ? | results/phase17_new_vectors/422b_fd_reuse_race_fixed_20261022_231924.txt |
| 2026-10-22 23:21 | 423a | - | - | ? | results/phase17_new_vectors/423a_mprotect_prot_sweep_20261022_232141.txt |
| 2026-10-22 23:22 | 424a | - | - | ? | results/phase17_new_vectors/424a_mmap_exec_20261022_232204.txt |
| 2026-10-22 23:24 | 424b | - | - | ? | results/phase17_new_vectors/424b_mmap_rwx_20261022_232408.txt |
| 2026-10-22 23:25 | 424c | - | - | ? | results/phase17_new_vectors/424c_mmap_gpu_prot_20261022_232512.txt |
| 2026-10-22 23:25 | 425a | - | - | ? | results/phase17_new_vectors/425a_dup2_race_20261022_232538.txt |
| 2026-10-22 23:26 | 426a | - | - | ? | results/phase17_new_vectors/426a_dlsym_jit_20261022_232608.txt |
| 2026-10-22 23:26 | 427a | - | - | ? | results/phase17_new_vectors/427a_dlsym_calling_convention_20261022_232628.txt |
| 2026-10-22 23:26 | 428a | - | - | ? | results/phase17_new_vectors/428a_sys532_full_sweep_20261022_232648.txt |
| 2026-10-22 23:49 | 430a | - | - | ? | results/phase17_new_vectors/430a_sys532_copyout_20261022_234902.txt |
| 2026-10-22 23:55 | 431a | - | - | ? | results/phase17_new_vectors/431a_sys532_handle_search_20261022_235520.txt |
| 2026-10-22 23:56 | 432a | - | - | ? | results/phase17_new_vectors/432a_sys532_handle_search2_20261022_235606.txt |
| 2026-10-22 23:56 | 432a | - | - | ? | results/phase17_new_vectors/432a_sys532_handle_search2_20261022_235623.txt |
| 2026-10-22 23:57 | 433a | - | - | ? | results/phase17_new_vectors/433a_sys532_handle_map_20261022_235749.txt |
| 2026-10-22 23:59 | 433a | - | - | ? | results/phase17_new_vectors/433a_sys532_handle_map_20261022_235907.txt |
| 2026-10-23 00:12 | 434a | - | - | ? | results/phase17_new_vectors/434a_compositor_census_20261023_001201.txt |
| 2026-10-23 00:13 | 434a | - | - | ? | results/phase17_new_vectors/434a_compositor_census_20261023_001328.txt |
| 2026-10-23 00:16 | 436a | - | - | ? | results/phase17_new_vectors/436a_handle_reuse_20261023_001654.txt |
| 2026-10-23 00:19 | 437a | - | - | ? | results/phase17_new_vectors/437a_slot_reuse_20261023_001934.txt |
| 2026-10-23 00:20 | 438a | - | - | ? | results/phase17_new_vectors/438a_slot_prediction_20261023_002050.txt |
| 2026-10-23 00:21 | 439a | - | - | ? | results/phase17_new_vectors/439a_osem_lifetime_20261023_002111.txt |
| 2026-10-23 00:21 | 440a | - | - | ? | results/phase17_new_vectors/440a_osem_double_release_20261023_002132.txt |
| 2026-10-23 00:21 | 441a | - | - | ? | results/phase17_new_vectors/441a_compositor_size_diff_20261023_002155.txt |
| 2026-10-23 00:22 | 441b | - | - | ? | results/phase17_new_vectors/441b_socket_recheck_20261023_002210.txt |
| 2026-10-23 00:25 | 441b | - | - | ? | results/phase17_new_vectors/441b_socket_recheck_20261023_002523.txt |
| 2026-10-23 00:25 | 442a | - | - | ? | results/phase17_new_vectors/442a_evf_lifetime_20261023_002538.txt |
| 2026-10-23 00:26 | 443a | - | - | ? | results/phase17_new_vectors/443a_named_leak_20261023_002601.txt |
| 2026-10-23 00:26 | 444a | - | - | ? | results/phase17_new_vectors/444a_evf_delete_20261023_002615.txt |
| 2026-10-23 00:27 | 445a | - | - | ? | results/phase17_new_vectors/445a_name_truncation_20261023_002720.txt |
| 2026-10-23 00:29 | 441b | - | - | ? | results/phase17_new_vectors/441b_socket_recheck_20261023_002937.txt |
| 2026-10-23 00:29 | 446a | - | - | ? | results/phase17_new_vectors/446a_outbuf_sweep_20261023_002959.txt |
| 2026-10-23 00:36 | 441b | - | - | ? | results/phase17_new_vectors/441b_socket_recheck_20261023_003623.txt |
| 2026-10-23 00:37 | 447a | - | - | ? | results/phase17_new_vectors/447a_debug_rwmem_20261023_003742.txt |
| 2026-10-23 00:39 | 441b | - | - | ? | results/phase17_new_vectors/441b_socket_recheck_20261023_003941.txt |
| 2026-10-23 06:29 | 160f | - | - | ? | results/phase22_threaded_races/160f_pi_exit_cascade_20261023_062904.txt |
| 2026-10-23 06:46 | 160i | - | - | ? | results/phase22_threaded_races/160i_pi_ownership_fraud_20261023_064652.txt |
| 2026-10-23 07:10 | 353a | - | - | ? | results/phase17_new_vectors/353a_aio_async_detect_20261023_071045.txt |
| 2026-10-23 07:13 | 353b | - | - | ? | results/phase17_new_vectors/353b_aio_fd_close_race_20261023_071305.txt |
| 2026-10-23 07:41 | 353c | - | - | ? | results/phase17_new_vectors/353c_aio_cancel_race_20261023_074144.txt |
| 2026-10-23 07:43 | 353d | - | - | ? | results/phase17_new_vectors/353d_aio_unmap_race_20261023_074303.txt |
| 2026-10-23 07:44 | 353d | - | - | ? | results/phase17_new_vectors/353d_aio_unmap_race_20261023_074456.txt |
| 2026-10-23 07:47 | 353d2 | - | - | ? | results/phase17_new_vectors/353d2_aio_unmap_clean_20261023_074717.txt |
| 2026-10-23 07:48 | 353e | - | - | ? | results/phase17_new_vectors/353e_aio_gen_collision_20261023_074822.txt |
| 2026-10-23 07:59 | 56d | - | - | ? | results/phase13_53batch/56d_cclosure_gadget_redirect_20261023_075937.txt |
| 2026-10-23 07:59 | 56d | - | - | ? | results/phase13_53batch/56d_cclosure_gadget_redirect_20261023_075950.txt |
| 2026-10-23 09:27 | 56d2 | - | - | ? | results/phase13_53batch/56d2_cclosure_gadget_safe_20261023_092733.txt |
| 2026-10-23 09:33 | 56d3 | - | - | ? | results/phase13_53batch/56d3_cclosure_retcount_20261023_093302.txt |
| 2026-10-23 09:34 | 56d3 | - | - | ? | results/phase13_53batch/56d3_cclosure_retcount_20261023_093451.txt |
| 2026-10-23 09:36 | 56d3 | - | - | ? | results/phase13_53batch/56d3_cclosure_retcount_20261023_093625.txt |
| 2026-10-23 09:37 | 56d3 | - | - | ? | results/phase13_53batch/56d3_cclosure_retcount_20261023_093736.txt |
| 2026-10-23 09:40 | 56d4 | - | - | ? | results/phase13_53batch/56d4_find_ret1_gadget_20261023_094040.txt |
| 2026-10-23 09:45 | 56d6 | - | - | ? | results/phase13_53batch/56d6_wide_gadget_scan_20261023_094541.txt |
| 2026-10-23 09:46 | 56d7 | - | - | ? | results/phase13_53batch/56d7_rax678_stack_leak_20261023_094622.txt |
| 2026-10-23 10:07 | 56g | - | - | ? | results/phase13_53batch/56g_libkernel_symbol_scan_20261023_100744.txt |
| 2026-10-23 10:08 | 56g2 | - | - | ? | results/phase13_53batch/56g2_module_list_20261023_100809.txt |
| 2026-10-23 10:11 | 56h | - | - | ? | results/phase13_53batch/56h_rdtsc_gadget_20261023_101119.txt |
| 2026-10-23 10:12 | 56h2 | - | - | ? | results/phase13_53batch/56h2_timing_kaslr_20261023_101231.txt |
| 2026-10-23 10:14 | 56i | - | - | ? | results/phase13_53batch/56i_thread_timer_kaslr_20261023_101400.txt |
| 2026-10-23 10:19 | 56j | - | - | ? | results/phase13_53batch/56j_untested_530_531_537_20261023_101932.txt |
| 2026-10-23 10:20 | 56k | - | - | ? | results/phase13_53batch/56k_mprotect_kernel_anomaly_20261023_102031.txt |
| 2026-10-23 10:22 | 243a | - | - | ? | results/phase17_new_vectors/243a_thread_slot_reclaim_20261023_102230.txt |
| 2026-10-23 10:32 | 56l | - | - | ? | results/phase13_53batch/56l_thr_new_real_20261023_103230.txt |
| 2026-10-23 10:32 | 56l | - | - | ? | results/phase13_53batch/56l_thr_new_real_20261023_103255.txt |
| 2026-10-23 10:33 | 56l | - | - | ? | results/phase13_53batch/56l_thr_new_real_20261023_103350.txt |
| 2026-10-23 10:43 | 448a | - | - | ? | results/phase17_new_vectors/448a_thr_create_kernel_selector_20261023_104315.txt |
| 2026-10-23 10:43 | 449a | - | - | ? | results/phase17_new_vectors/449a_priv_gadget_scan_20261023_104352.txt |
| 2026-10-23 10:44 | 450a | - | - | ? | results/phase17_new_vectors/450a_priv_gadget_scan2_20261023_104412.txt |
| 2026-10-23 10:44 | 451a | - | - | ? | results/phase17_new_vectors/451a_priv_gadget_context_20261023_104434.txt |
| 2026-10-23 10:45 | 452a | - | - | ? | results/phase17_new_vectors/452a_ring_test_in_20261023_104514.txt |
| 2026-10-23 10:46 | 453a | - | - | ? | results/phase17_new_vectors/453a_iopl_copy_20261023_104628.txt |
| 2026-10-23 10:46 | 56l | - | - | ? | results/phase13_53batch/56l_thr_new_real_20261023_104627.txt |
| 2026-10-23 10:48 | 454a | - | - | ? | results/phase17_new_vectors/454a_stack_init_branch_20261023_104857.txt |
| 2026-10-23 10:49 | 454a | - | - | ? | results/phase17_new_vectors/454a_stack_init_branch_20261023_104906.txt |
| 2026-10-23 10:49 | 454a | - | - | ? | results/phase17_new_vectors/454a_stack_init_branch_20261023_104917.txt |
| 2026-10-23 10:49 | 454a | - | - | ? | results/phase17_new_vectors/454a_stack_init_branch_20261023_104931.txt |
| 2026-10-23 10:49 | 454a | - | - | ? | results/phase17_new_vectors/454a_stack_init_branch_20261023_104951.txt |
| 2026-10-23 10:50 | 454a | - | - | ? | results/phase17_new_vectors/454a_stack_init_branch_20261023_105003.txt |
| 2026-10-23 10:50 | 454a | - | - | ? | results/phase17_new_vectors/454a_stack_init_branch_20261023_105024.txt |
| 2026-10-23 10:50 | 454a | - | - | ? | results/phase17_new_vectors/454a_stack_init_branch_20261023_105037.txt |
| 2026-10-23 10:53 | 56l | - | - | ? | results/phase13_53batch/56l_thr_new_real_20261023_105339.txt |
| 2026-10-23 10:56 | 56l | - | - | ? | results/phase13_53batch/56l_thr_new_real_20261023_105601.txt |
| 2026-10-23 10:58 | 56m | - | - | ? | results/phase13_53batch/56m_ioctl_overcopy_scan_20261023_105857.txt |
| 2026-10-23 11:01 | 455a | - | - | ? | results/phase17_new_vectors/455a_msync_invalidate_20261023_110152.txt |
| 2026-10-23 11:02 | 455b | - | - | ? | results/phase17_new_vectors/455b_msync_flags_20261023_110216.txt |
| 2026-10-23 11:03 | 455c | - | - | ? | results/phase17_new_vectors/455c_msync_device_flags_20261023_110354.txt |
| 2026-10-23 11:04 | 455d | - | - | ? | results/phase17_new_vectors/455d_msync_vnode_20261023_110421.txt |
| 2026-10-23 11:05 | 56o | - | - | ? | results/phase13_53batch/56o_unix_creds_signal_frame_20261023_110512.txt |
| 2026-10-23 11:06 | 56o | - | - | ? | results/phase13_53batch/56o_unix_creds_signal_frame_20261023_110625.txt |
| 2026-10-23 11:09 | 56p | - | - | ? | results/phase13_53batch/56p_getrusage_timestamp_procctl_20261023_110958.txt |
| 2026-10-23 11:12 | 456a | - | - | ? | results/phase17_new_vectors/456a_loopback_scan_20261023_111210.txt |
| 2026-10-23 11:14 | 56p | - | - | ? | results/phase13_53batch/56p_getrusage_timestamp_procctl_20261023_111455.txt |
| 2026-10-23 11:17 | 56q | - | - | ? | results/phase13_53batch/56q_kevent_scm_rights_sendfile_20261023_111737.txt |
| 2026-10-23 11:33 | 457a | - | - | ? | results/phase17_new_vectors/457a_ioctl_structured_20261023_113337.txt |
| 2026-10-23 11:34 | 458a | - | - | ? | results/phase17_new_vectors/458a_ioctl_echo_and_sweep_20261023_113427.txt |
| 2026-10-23 11:35 | 459a | - | - | ? | results/phase17_new_vectors/459a_ioctl_encoding_20261023_113531.txt |
| 2026-10-23 11:40 | 460a | - | - | ? | results/phase17_new_vectors/460a_aio_wait_20261023_114004.txt |
| 2026-10-23 11:42 | 461a | - | - | ? | results/phase17_new_vectors/461a_aio_wait_race_20261023_114228.txt |
| 2026-10-23 11:42 | sa | - | - | ? | results/sa_probe_20261023_114216.txt |
| 2026-10-23 11:43 | 461a | - | - | ? | results/phase17_new_vectors/461a_aio_wait_race_20261023_114335.txt |
| 2026-10-23 11:47 | 461a | - | - | ? | results/phase17_new_vectors/461a_aio_wait_race_20261023_114713.txt |
| 2026-10-23 11:49 | 462a | - | - | ? | results/phase17_new_vectors/462a_aio_wait_thread_20261023_114941.txt |
| 2026-10-23 11:50 | 463a | - | - | ? | results/phase17_new_vectors/463a_aio_wait_sleep_20261023_115000.txt |
| 2026-10-23 11:50 | 464a | - | - | ? | results/phase17_new_vectors/464a_aio_delete_under_wait_20261023_115018.txt |
| 2026-10-23 11:50 | 465a | - | - | ? | results/phase17_new_vectors/465a_aio_complete_then_delete_20261023_115041.txt |
| 2026-10-23 11:50 | 465a | - | - | ? | results/phase17_new_vectors/465a_aio_complete_then_delete_20261023_115053.txt |
| 2026-10-23 11:51 | 465a | - | - | ? | results/phase17_new_vectors/465a_aio_complete_then_delete_20261023_115101.txt |
| 2026-10-23 11:51 | 466a | - | - | ? | results/phase17_new_vectors/466a_aio_waiter_return_20261023_115123.txt |
| 2026-10-23 11:51 | 466a | - | - | ? | results/phase17_new_vectors/466a_aio_waiter_return_20261023_115133.txt |
| 2026-10-23 11:52 | 467a | - | - | ? | results/phase17_new_vectors/467a_aio_wait_lock_20261023_115224.txt |
| 2026-10-23 11:52 | 468a | - | - | ? | results/phase17_new_vectors/468a_aio_lone_completion_20261023_115245.txt |
| 2026-10-23 11:53 | 469a | - | - | ? | results/phase17_new_vectors/469a_aio_poll_completes_20261023_115304.txt |
| 2026-10-23 12:13 | 56r | - | - | ? | results/phase13_53batch/56r_sigframe_kptr_scan_20261023_121340.txt |
| 2026-10-23 12:13 | 56s | - | - | ? | results/phase13_53batch/56s_eboot_syscall_scan_20261023_121306.txt |
| 2026-10-23 12:14 | 56s | - | - | ? | results/phase13_53batch/56s_eboot_syscall_scan_20261023_121428.txt |
| 2026-10-23 12:26 | 66a | - | - | ? | results/phase15_jailbreak/66a_sound_mmap_krw_20261023_122632.txt |
| 2026-10-23 12:30 | 67a | - | - | ? | results/phase15_jailbreak/67a_msync_devpager_uaf_20261023_123028.txt |
| 2026-10-23 12:32 | 271a | - | - | ? | results/phase17_new_vectors/271a_ioctl_catalog_matrix_20261023_123200.txt |
| 2026-10-23 12:33 | 271b | - | - | ? | results/phase17_new_vectors/271b_camera_ioctl_deep_20261023_123353.txt |
| 2026-10-23 12:35 | 271c | - | - | ? | results/phase17_new_vectors/271c_ioctl_group_discovery_20261023_123543.txt |
| 2026-10-23 12:37 | 271d | - | - | ? | results/phase17_new_vectors/271d_ioctl_3dir_sweep_20261023_123708.txt |
| 2026-10-23 12:40 | 271e | - | - | ? | results/phase17_new_vectors/271e_gc_cmd_sweep_20261023_124018.txt |
| 2026-10-23 12:41 | 271e | - | - | ? | results/phase17_new_vectors/271e_gc_cmd_sweep_20261023_124121.txt |
| 2026-10-23 12:49 | 271f | - | - | ? | results/phase17_new_vectors/271f_untested_devices_ioctl_20261023_124953.txt |
| 2026-10-23 13:51 | 271g | - | - | ? | results/phase17_new_vectors/271g_child_thread_rop_kqueue_race_20261023_135157.txt |
| 2026-10-23 13:54 | 271g | - | - | ? | results/phase17_new_vectors/271g_child_thread_rop_kqueue_race_20261023_135410.txt |
| 2026-10-23 13:55 | 111a | - | - | ? | results/phase20_event_leak/111a_sys662_event_records_20261023_135525.txt |
| 2026-10-23 13:55 | 111b | - | - | ? | results/phase20_event_leak/111b_event_arg_order_20261023_135552.txt |
| 2026-10-23 13:56 | 111b | - | - | ? | results/phase20_event_leak/111b_event_arg_order_20261023_135642.txt |
| 2026-10-23 13:57 | 112a | - | - | ? | results/phase17_new_vectors/112a_sys605_gpu_rw_flag_or_20261023_135724.txt |
| 2026-10-23 13:57 | 112c | - | - | ? | results/phase20_event_leak/112c_credential_bit_oracle_20261023_135758.txt |
| 2026-10-23 14:00 | 271h | - | - | ? | results/phase17_new_vectors/271h_kqueue_race_data_20261023_140045.txt |
| 2026-10-23 14:02 | 113a | - | - | ? | results/phase20_event_leak/113a_sys588_exec_after_flip_20261023_140225.txt |
| 2026-10-23 14:03 | 113b | - | - | ? | results/phase20_event_leak/113b_thread_control_20261023_140331.txt |
| 2026-10-23 14:03 | 271i | - | - | ? | results/phase17_new_vectors/271i_kqueue_diag_timer_race_20261023_140319.txt |
| 2026-10-23 14:10 | 470a | - | - | ? | results/phase17_new_vectors/470a_dce_command_footprint_20261023_141013.txt |
| 2026-10-23 14:12 | 471a | - | - | ? | results/phase17_new_vectors/471a_dmem0_encoding_20261023_141216.txt |
| 2026-10-23 14:13 | 272a | - | - | ? | results/phase17_new_vectors/272a_multiarg_gadget_scan_20261023_141312.txt |
| 2026-10-23 14:13 | 272a | - | - | ? | results/phase17_new_vectors/272a_multiarg_gadget_scan_20261023_141340.txt |
| 2026-10-23 14:13 | 471b | - | - | ? | results/phase17_new_vectors/471b_gic_encoding_20261023_141321.txt |
| 2026-10-23 14:15 | 272a | - | - | ? | results/phase17_new_vectors/272a_multiarg_gadget_scan_20261023_141512.txt |
| 2026-10-23 14:15 | 472a | - | - | ? | results/phase17_new_vectors/472a_gic_command_shape_20261023_141510.txt |
| 2026-10-23 14:17 | 473a | - | - | ? | results/phase17_new_vectors/473a_gic_oracle_20261023_141731.txt |
| 2026-10-23 14:20 | 473a | - | - | ? | results/phase17_new_vectors/473a_gic_oracle_20261023_142044.txt |
| 2026-10-23 14:21 | 473b | - | - | ? | results/phase17_new_vectors/473b_first_regions_20261023_142116.txt |
| 2026-10-23 14:23 | 473c | - | - | ? | results/phase17_new_vectors/473c_gic_rx_address_20261023_142317.txt |
| 2026-10-23 14:23 | 473d | - | - | ? | results/phase17_new_vectors/473d_gic_libsce_rx_20261023_142347.txt |
| 2026-10-23 14:24 | 473e | - | - | ? | results/phase17_new_vectors/473e_gic_index_walk_20261023_142424.txt |
| 2026-10-23 14:31 | 473f | - | - | ? | results/phase17_new_vectors/473f_gic_eboot_address_20261023_143107.txt |
| 2026-10-23 14:33 | 384a | - | - | ? | results/phase17_new_vectors/384a_child_multiarg_sysctl_20261023_143352.txt |
| 2026-10-23 14:36 | 474a | - | - | ? | results/phase17_new_vectors/474a_gic_address_boundary_20261023_143637.txt |
| 2026-10-23 14:37 | 384a | - | - | ? | results/phase17_new_vectors/384a_child_multiarg_sysctl_20261023_143704.txt |
| 2026-10-23 14:37 | 475a | - | - | ? | results/phase17_new_vectors/475a_gic_write_target_20261023_143702.txt |
| 2026-10-23 14:37 | 475b | - | - | ? | results/phase17_new_vectors/475b_gic_write_target_fixed_20261023_143733.txt |
| 2026-10-23 14:38 | 475c | - | - | ? | results/phase17_new_vectors/475c_gic_payload_shape_20261023_143847.txt |
| 2026-10-23 14:39 | 475d | - | - | ? | results/phase17_new_vectors/475d_gic_write_extent_20261023_143919.txt |
| 2026-10-23 14:40 | 384b | - | - | ? | results/phase17_new_vectors/384b_child_write_minimal_20261023_144048.txt |
| 2026-10-23 14:40 | 475e | - | - | ? | results/phase17_new_vectors/475e_gic_write_length_20261023_144026.txt |
| 2026-10-23 14:42 | 384b | - | - | ? | results/phase17_new_vectors/384b_child_write_minimal_20261023_144252.txt |
| 2026-10-23 14:44 | 384b | - | - | ? | results/phase17_new_vectors/384b_child_write_minimal_20261023_144456.txt |
| 2026-10-23 14:45 | 475f | - | - | ? | results/phase17_new_vectors/475f_eboot_writable_check_20261023_144514.txt |
| 2026-10-23 14:45 | 475g | - | - | ? | results/phase17_new_vectors/475g_eboot_window_storage_20261023_144547.txt |
| 2026-10-23 14:46 | 384b | - | - | ? | results/phase17_new_vectors/384b_child_write_minimal_20261023_144629.txt |
| 2026-10-23 14:48 | 384b | - | - | ? | results/phase17_new_vectors/384b_child_write_minimal_20261023_144828.txt |
| 2026-10-23 14:52 | 386a | - | - | ? | results/phase17_new_vectors/386a_r8_r9_gadget_scan_20261023_145217.txt |
| 2026-10-23 14:54 | 385a | - | - | ? | results/phase17_new_vectors/385a_concurrent_child_races_20261023_145412.txt |
| 2026-10-23 14:55 | 476a | - | - | ? | results/phase17_new_vectors/476a_unswept_node_sweep_20261023_145542.txt |
| 2026-10-23 15:00 | 476a | - | - | ? | results/phase17_new_vectors/476a_unswept_node_sweep_20261023_150014.txt |
| 2026-10-23 15:05 | 477a | - | - | ? | results/phase17_new_vectors/477a_dmem1_read_command_20261023_150520.txt |
| 2026-10-23 15:06 | 477b | - | - | ? | results/phase17_new_vectors/477b_dmem1_write_group_20261023_150640.txt |
| 2026-10-23 15:12 | 478a | - | - | ? | results/phase17_new_vectors/478a_dmem1_arg_layout_20261023_151221.txt |
| 2026-10-23 15:13 | 478b | - | - | ? | results/phase17_new_vectors/478b_dmem1_zero_field_20261023_151329.txt |
| 2026-10-23 15:13 | 478c | - | - | ? | results/phase17_new_vectors/478c_dmem1_prefix_only_20261023_151355.txt |
| 2026-10-23 15:14 | 387b | - | - | ? | results/phase17_new_vectors/387b_ioctl_group_sweep_full_20261023_151435.txt |
| 2026-10-23 15:14 | 478d | - | - | ? | results/phase17_new_vectors/478d_dmem1_enabler_bisect_20261023_151417.txt |
| 2026-10-23 15:15 | 478e | - | - | ? | results/phase17_new_vectors/478e_dmem1_replay_477ab_20261023_151503.txt |
| 2026-10-23 15:16 | 477b | - | - | ? | results/phase17_new_vectors/477b_dmem1_write_group_20261023_151601.txt |
| 2026-10-23 15:17 | 387c | - | - | ? | results/phase17_new_vectors/387c_ioctl_fast_discovery_20261023_151722.txt |
| 2026-10-23 15:18 | 478f | - | - | ? | results/phase17_new_vectors/478f_dmem1_rate_20261023_151855.txt |
| 2026-10-23 15:18 | 478h | - | - | ? | results/phase17_new_vectors/478h_dmem1_delay_20261023_151842.txt |
| 2026-10-23 15:19 | 478g | - | - | ? | results/phase17_new_vectors/478g_dmem1_hidden_state_20261023_151922.txt |
| 2026-10-23 15:20 | 477b | - | - | ? | results/phase17_new_vectors/477b_dmem1_write_group_20261023_152010.txt |
| 2026-10-23 15:24 | 478i | - | - | ? | results/phase17_new_vectors/478i_dmem1_ladder_20261023_152432.txt |
| 2026-10-23 15:25 | 478j | - | - | ? | results/phase17_new_vectors/478j_dmem1_rung11_20261023_152519.txt |
| 2026-10-23 15:25 | 478k | - | - | ? | results/phase17_new_vectors/478k_rung00_20261023_152536.txt |
| 2026-10-23 15:25 | 478k | - | - | ? | results/phase17_new_vectors/478k_rung01_20261023_152536.txt |
| 2026-10-23 15:25 | 478k | - | - | ? | results/phase17_new_vectors/478k_rung02_20261023_152536.txt |
| 2026-10-23 15:25 | 478k | - | - | ? | results/phase17_new_vectors/478k_rung03_20261023_152536.txt |
| 2026-10-23 15:25 | 478k | - | - | ? | results/phase17_new_vectors/478k_rung04_20261023_152535.txt |
| 2026-10-23 15:25 | 478k | - | - | ? | results/phase17_new_vectors/478k_rung05_20261023_152535.txt |
| 2026-10-23 15:25 | 478k | - | - | ? | results/phase17_new_vectors/478k_rung06_20261023_152535.txt |
| 2026-10-23 15:25 | 478k | - | - | ? | results/phase17_new_vectors/478k_rung07_20261023_152535.txt |
| 2026-10-23 15:25 | 478k | - | - | ? | results/phase17_new_vectors/478k_rung08_20261023_152534.txt |
| 2026-10-23 15:25 | 478k | - | - | ? | results/phase17_new_vectors/478k_rung09_20261023_152534.txt |
| 2026-10-23 15:25 | 478k | - | - | ? | results/phase17_new_vectors/478k_rung0a_20261023_152534.txt |
| 2026-10-23 15:25 | 478k | - | - | ? | results/phase17_new_vectors/478k_rung0b_20261023_152534.txt |
| 2026-10-23 15:25 | 478k | - | - | ? | results/phase17_new_vectors/478k_rung0c_20261023_152534.txt |
| 2026-10-23 15:25 | 478k | - | - | ? | results/phase17_new_vectors/478k_rung0d_20261023_152533.txt |
| 2026-10-23 15:25 | 478k | - | - | ? | results/phase17_new_vectors/478k_rung0e_20261023_152533.txt |
| 2026-10-23 15:25 | 478k | - | - | ? | results/phase17_new_vectors/478k_rung0f_20261023_152533.txt |
| 2026-10-23 15:25 | 478k | - | - | ? | results/phase17_new_vectors/478k_rung10_20261023_152532.txt |
| 2026-10-23 15:26 | 478m | - | - | ? | results/phase17_new_vectors/478m_dmem1_exact13_20261023_152614.txt |
| 2026-10-23 15:26 | 478n | - | - | ? | results/phase17_new_vectors/478n_cmd00_20261023_152640.txt |
| 2026-10-23 15:26 | 478n | - | - | ? | results/phase17_new_vectors/478n_cmd01_20261023_152641.txt |
| 2026-10-23 15:26 | 478n | - | - | ? | results/phase17_new_vectors/478n_cmd02_20261023_152641.txt |
| 2026-10-23 15:26 | 478n | - | - | ? | results/phase17_new_vectors/478n_cmd03_20261023_152641.txt |
| 2026-10-23 15:26 | 478n | - | - | ? | results/phase17_new_vectors/478n_cmd04_20261023_152641.txt |
| 2026-10-23 15:26 | 478n | - | - | ? | results/phase17_new_vectors/478n_cmd05_20261023_152641.txt |
| 2026-10-23 15:26 | 478n | - | - | ? | results/phase17_new_vectors/478n_cmd06_20261023_152642.txt |
| 2026-10-23 15:26 | 478n | - | - | ? | results/phase17_new_vectors/478n_cmd07_20261023_152642.txt |
| 2026-10-23 15:26 | 478n | - | - | ? | results/phase17_new_vectors/478n_cmd08_20261023_152642.txt |
| 2026-10-23 15:26 | 478n | - | - | ? | results/phase17_new_vectors/478n_cmd09_20261023_152642.txt |
| 2026-10-23 15:26 | 478n | - | - | ? | results/phase17_new_vectors/478n_cmd0a_20261023_152642.txt |
| 2026-10-23 15:26 | 478n | - | - | ? | results/phase17_new_vectors/478n_cmd0b_20261023_152642.txt |
| 2026-10-23 15:26 | 478n | - | - | ? | results/phase17_new_vectors/478n_cmd0c_20261023_152643.txt |
| 2026-10-23 15:26 | 478n | - | - | ? | results/phase17_new_vectors/478n_cmd0d_20261023_152643.txt |
| 2026-10-23 15:26 | 478n | - | - | ? | results/phase17_new_vectors/478n_cmd0e_20261023_152643.txt |
| 2026-10-23 15:26 | 478n | - | - | ? | results/phase17_new_vectors/478n_cmd0f_20261023_152643.txt |
| 2026-10-23 15:26 | 478n | - | - | ? | results/phase17_new_vectors/478n_cmd10_20261023_152643.txt |
| 2026-10-23 15:26 | 478n | - | - | ? | results/phase17_new_vectors/478n_cmd11_20261023_152643.txt |
| 2026-10-23 15:26 | 478n | - | - | ? | results/phase17_new_vectors/478n_cmd12_20261023_152644.txt |
| 2026-10-23 15:26 | 478n | - | - | ? | results/phase17_new_vectors/478n_cmd13_20261023_152644.txt |
| 2026-10-23 15:26 | 478n | - | - | ? | results/phase17_new_vectors/478n_cmd14_20261023_152644.txt |
| 2026-10-23 15:26 | 478n | - | - | ? | results/phase17_new_vectors/478n_cmd15_20261023_152644.txt |
| 2026-10-23 15:26 | 478n | - | - | ? | results/phase17_new_vectors/478n_cmd16_20261023_152644.txt |
| 2026-10-23 15:27 | 478n | - | - | ? | results/phase17_new_vectors/478n_cmd17_20261023_152714.txt |
| 2026-10-23 15:32 | 479a | - | - | ? | results/phase17_new_vectors/479a_sweep_tool_smoke_20261023_153246.txt |
| 2026-10-23 15:32 | 479a | - | - | ? | results/phase17_new_vectors/479a_sweep_tool_smoke_20261023_153251.txt |
| 2026-10-23 15:35 | 480a | - | - | ? | results/phase17_new_vectors/480a_dmem2_block_20261023_153548.txt |
| 2026-10-23 15:38 | 478p | - | - | ? | results/phase17_new_vectors/478p_dmem1_cmd17_padded_20261023_153833.txt |
| 2026-10-23 15:38 | 480b | - | - | ? | results/phase17_new_vectors/480b_dmem2_open_only_20261023_153812.txt |
| 2026-10-23 15:40 | 478p | - | - | ? | results/phase17_new_vectors/478p_dmem1_cmd17_padded_20261023_154002.txt |
| 2026-10-23 15:43 | 480c | - | - | ? | results/phase17_new_vectors/480c_dmem1_cmd17_readonly_20261023_154324.txt |
| 2026-10-23 15:45 | 67c | - | - | ? | results/phase15_jailbreak/67c_msync_isolate_20261023_154556.txt |
| 2026-10-23 15:52 | 480c | - | - | ? | results/phase17_new_vectors/480c_dmem1_cmd17_readonly_20261023_155258.txt |
| 2026-10-23 16:01 | 480d | - | - | ? | results/phase17_new_vectors/480d_dmem0_cmd17_20261023_160146.txt |
| 2026-10-23 16:05 | 481a | - | - | ? | results/phase17_new_vectors/481a_dmem_arg_matrix_20261023_160540.txt |
| 2026-10-23 16:06 | 482a | - | - | ? | results/phase17_new_vectors/482a_dmem_window_lookup_20261023_160622.txt |
| 2026-10-23 16:10 | 482b | - | - | ? | results/phase17_new_vectors/482b_window_mapping_20261023_161040.txt |
| 2026-10-23 16:11 | 482c | - | - | ? | results/phase17_new_vectors/482c_mmap_window_hint_20261023_161114.txt |
| 2026-10-23 16:11 | 482d | - | - | ? | results/phase17_new_vectors/482d_dmem_window_call_20261023_161134.txt |
| 2026-10-23 16:11 | 482d | - | - | ? | results/phase17_new_vectors/482d_dmem_window_call_20261023_161143.txt |
| 2026-10-23 16:11 | 482d | - | - | ? | results/phase17_new_vectors/482d_dmem_window_call_20261023_161157.txt |
| 2026-10-23 16:12 | 482d | - | - | ? | results/phase17_new_vectors/482d_dmem_window_call_20261023_161208.txt |
| 2026-10-23 16:13 | 482e | - | - | ? | results/phase17_new_vectors/482e_dmem_map_ops_20261023_161336.txt |
| 2026-10-23 16:15 | 482f | - | - | ? | results/phase17_new_vectors/482f_window_mapped_vs_unmapped_20261023_161543.txt |
| 2026-10-23 16:18 | 388b | - | - | ? | results/phase18_bsd_native/388b_ksem_deep_exploration_20261023_161839.txt |
| 2026-10-23 16:18 | 482g | - | - | ? | results/phase17_new_vectors/482g_window_exact_placement_20261023_161809.txt |
| 2026-10-23 16:21 | 388c | - | - | ? | results/phase18_bsd_native/388c_ksem_corrected_20261023_162122.txt |
| 2026-10-23 16:22 | 388d | - | - | ? | results/phase18_bsd_native/388d_ksem_minimal_20261023_162241.txt |
| 2026-10-23 16:26 | 389a | - | - | ? | results/phase18_bsd_native/389a_ksem_race_20261023_162610.txt |
| 2026-10-23 16:29 | 389b | - | - | ? | results/phase18_bsd_native/389b_bsd_batch2_20261023_162908.txt |
| 2026-10-23 16:29 | 483a | - | - | ? | results/phase17_new_vectors/483a_camera_sweep_20261023_162959.txt |
| 2026-10-23 16:30 | 483b | - | - | ? | results/phase17_new_vectors/483b_camera_block_bisect_20261023_163057.txt |
| 2026-10-23 16:32 | 389c | - | - | ? | results/phase18_bsd_native/389c_bsd_batch2_safe_20261023_163210.txt |
| 2026-10-23 16:33 | 389d | - | - | ? | results/phase18_bsd_native/389d_bsd_batch2_no125_20261023_163315.txt |
| 2026-10-23 16:34 | 389e | - | - | ? | results/phase18_bsd_native/389e_sc102_and_more_20261023_163436.txt |
| 2026-10-23 16:38 | 389f | - | - | ? | results/phase18_bsd_native/389f_bsd_safe_sweep_20261023_163808.txt |
| 2026-10-23 16:51 | 483a | - | - | ? | results/phase17_new_vectors/483a_camera_sweep_20261023_165123.txt |
| 2026-10-23 17:19 | 389g | - | - | ? | results/phase18_bsd_native/389g_targeted_bsd_20261023_171948.txt |
| 2026-10-23 17:22 | 389h | - | - | ? | results/phase18_bsd_native/389h_safe_targeted_20261023_172209.txt |
| 2026-10-23 17:23 | 389i | - | - | ? | results/phase18_bsd_native/389i_modfind_mlock_20261023_172335.txt |
| 2026-10-23 17:29 | 390a | - | - | ? | results/phase18_bsd_native/390a_kaslr_gadget_scan_20261023_172945.txt |
| 2026-10-23 17:32 | 390b | - | - | ? | results/phase18_bsd_native/390b_kaslr_fast_scan_20261023_173258.txt |
| 2026-10-23 17:35 | 390c | - | - | ? | results/phase18_bsd_native/390c_gadget_context_20261023_173530.txt |
| 2026-10-23 17:40 | 390d | - | - | ? | results/phase18_bsd_native/390d_prefetch_survive_20261023_174000.txt |
| 2026-10-23 17:47 | 390e | - | - | ? | results/phase18_bsd_native/390e_rdtsc_functions_20261023_174700.txt |
| 2026-10-23 17:47 | 483c | - | - | ? | results/phase17_new_vectors/483c_camera_sweep_resume_20261023_174757.txt |
| 2026-10-23 18:13 | 391b | - | - | ? | results/phase19_posixshm/391b_sendfile_uaf_trigger_20261023_181317.txt |
| 2026-10-23 18:19 | 391c | - | - | ? | results/phase19_posixshm/391c_shm_trunc_uaf_20261023_181935.txt |
| 2026-10-23 18:23 | 391d | - | - | ? | results/phase19_posixshm/391d_sendfile_child_drain_20261023_182316.txt |
| 2026-10-23 18:34 | 392b | - | - | ? | results/phase20_bsd_deep/392b_bsd_data_returners_20261023_183440.txt |
| 2026-10-23 18:39 | 392c | - | - | ? | results/phase20_bsd_deep/392c_bsd_remaining_20261023_183931.txt |
| 2026-10-23 18:41 | 392d | - | - | ? | results/phase20_bsd_deep/392d_bsd_safe_20261023_184111.txt |
| 2026-10-23 18:41 | 67b | - | - | ? | results/phase15_jailbreak/67b_poll_fd_uaf_20261023_184143.txt |
| 2026-10-23 18:43 | 392e | - | - | ? | results/phase20_bsd_deep/392e_bsd_noscan_20261023_184356.txt |
| 2026-10-23 18:45 | 392f | - | - | ? | results/phase20_bsd_deep/392f_bsd_last_batch_20261023_184540.txt |
| 2026-10-23 19:16 | 485a | - | - | ? | results/phase17_new_vectors/485a_camera_death_bisect_20261023_191648.txt |
| 2026-10-23 19:17 | 484a | - | - | ? | results/phase17_new_vectors/484a_localhost_scan_20261023_191732.txt |
| 2026-10-23 19:34 | 484b | - | - | ? | results/phase17_new_vectors/484b_localhost_nonblock_20261023_193418.txt |
| 2026-10-23 19:49 | 393a | - | - | ? | results/phase21_next_vectors/393a_dl_get_metadata_20261023_194926.txt |
| 2026-10-23 19:51 | 393b | - | - | ? | results/phase21_next_vectors/393b_sysctl_toctou_20261023_195133.txt |
| 2026-10-23 19:59 | 393c | - | - | ? | results/phase21_next_vectors/393c_sysctl_toctou_safe_20261023_195906.txt |
| 2026-10-23 20:04 | 393d | - | - | ? | results/phase21_next_vectors/393d_sysctl_toctou_dword_20261023_200412.txt |
| 2026-10-23 20:05 | 393e | - | - | ? | results/phase21_next_vectors/393e_chain_debug_20261023_200535.txt |
| 2026-10-23 20:07 | 393f | - | - | ? | results/phase21_next_vectors/393f_minimal_chain_20261023_200755.txt |
| 2026-10-23 20:11 | 393g | - | - | ? | results/phase21_next_vectors/393g_race_fixed_20261023_201127.txt |
| 2026-10-23 20:14 | 393h | - | - | ? | results/phase21_next_vectors/393h_race_rsp_fix_20261023_201423.txt |
| 2026-10-23 20:19 | 394a | - | - | ? | results/phase21_next_vectors/394a_loop_gadget_scan_20261023_201928.txt |
| 2026-10-23 20:22 | 394b | - | - | ? | results/phase21_next_vectors/394b_loop_gadget_fast_20261023_202245.txt |
| 2026-10-23 20:26 | 394c | - | - | ? | results/phase21_next_vectors/394c_gadget_wide_20261023_202620.txt |
| 2026-10-23 20:29 | 395a | - | - | ? | results/phase21_next_vectors/395a_pop_rsp_loop_20261023_202931.txt |
| 2026-10-23 20:33 | 395a | - | - | ? | results/phase21_next_vectors/395a_pop_rsp_loop_20261023_203357.txt |
| 2026-10-23 20:39 | 395b | - | - | ? | results/phase21_next_vectors/395b_loop_syscall_20261023_203917.txt |
| 2026-10-23 20:41 | 395b | - | - | ? | results/phase21_next_vectors/395b_loop_syscall_20261023_204132.txt |
| 2026-10-23 21:04 | 395c | - | - | ? | results/phase21_next_vectors/395c_loop_getpid_20261023_210424.txt |
| 2026-10-23 21:05 | 395d | - | - | ? | results/phase21_next_vectors/395d_loop_close_err_20261023_210509.txt |
| 2026-10-23 21:12 | 395d | - | - | ? | results/phase21_next_vectors/395d_loop_close_err_20261023_211225.txt |
| 2026-10-23 21:18 | 395e | - | - | ? | results/phase21_next_vectors/395e_errno_diagnostic_20261023_211808.txt |
| 2026-10-23 21:19 | 395e | - | - | ? | results/phase21_next_vectors/395e_errno_diagnostic_20261023_211937.txt |
| 2026-10-23 21:21 | 395f | - | - | ? | results/phase21_next_vectors/395f_multi_close_noloop_20261023_212109.txt |
| 2026-10-23 21:22 | 395f | - | - | ? | results/phase21_next_vectors/395f_multi_close_noloop_20261023_212234.txt |
| 2026-10-23 21:26 | 395g | - | - | ? | results/phase21_next_vectors/395g_loop_errfix_20261023_212617.txt |
| 2026-10-23 21:28 | 396a | - | - | ? | results/phase21_next_vectors/396a_ipv6_setsockopt_race_20261023_212824.txt |
| 2026-10-23 21:29 | 396b | - | - | ? | results/phase21_next_vectors/396b_ipv6_optscan_20261023_212914.txt |
| 2026-10-23 21:30 | 396c | - | - | ? | results/phase21_next_vectors/396c_ipv6_verify_20261023_213004.txt |
| 2026-10-23 21:31 | 396d | - | - | ? | results/phase21_next_vectors/396d_setsockopt_args_20261023_213116.txt |
| 2026-10-23 21:31 | 396e | - | - | ? | results/phase21_next_vectors/396e_native_sockopt_20261023_213158.txt |
| 2026-10-23 21:38 | 396f | - | - | ? | results/phase21_next_vectors/396f_pop_r8_verify_20261023_213839.txt |
| 2026-10-23 21:41 | 396g | - | - | ? | results/phase21_next_vectors/396g_sockopt_diag_20261023_214112.txt |
| 2026-10-23 21:45 | 396h | - | - | ? | results/phase21_next_vectors/396h_fd_verify_20261023_214543.txt |
| 2026-10-23 21:46 | 65d | - | - | ? | results/phase16_kwrite/65d_aio_multi_delete_race_20261023_214636.txt |
| 2026-10-23 21:48 | 65e | - | - | ? | results/phase16_kwrite/65e_aio_race_pending_20261023_214831.txt |
| 2026-10-23 21:50 | 396i | - | - | ? | results/phase21_next_vectors/396i_minimal_sockopt_20261023_215059.txt |
| 2026-10-23 21:52 | 65f | - | - | ? | results/phase16_kwrite/65f_aio_race_v3_20261023_215237.txt |
| 2026-10-23 21:54 | 65g | - | - | ? | results/phase16_kwrite/65g_aio_race_clean_20261023_215403.txt |
| 2026-10-23 21:55 | 65g | - | - | ? | results/phase16_kwrite/65g_aio_race_clean_20261023_215555.txt |
| 2026-10-23 21:57 | 65h | - | - | ? | results/phase16_kwrite/65h_aio_race_poll_20261023_215737.txt |
| 2026-10-23 21:59 | 65i | - | - | ? | results/phase16_kwrite/65i_aio_race_2child_20261023_215920.txt |
| 2026-10-23 22:01 | 397a | - | - | ? | results/phase21_next_vectors/397a_aio_untested_20261023_220157.txt |
| 2026-10-23 22:01 | 65j | - | - | ? | results/phase16_kwrite/65j_aio_race_nosysarch_20261023_220145.txt |
| 2026-10-23 22:04 | 397b | - | - | ? | results/phase21_next_vectors/397b_munmap_madvise_20261023_220440.txt |
| 2026-10-23 22:04 | 65k | - | - | ? | results/phase16_kwrite/65k_aio_race_multi_20261023_220403.txt |
| 2026-10-23 22:06 | 397c | - | - | ? | results/phase21_next_vectors/397c_munmap_safe_20261023_220600.txt |
| 2026-10-23 22:06 | 65l | - | - | ? | results/phase16_kwrite/65l_aio_race_fixed_20261023_220628.txt |
| 2026-10-23 22:07 | 397d | - | - | ? | results/phase21_next_vectors/397d_remap_madvise_20261023_220714.txt |
| 2026-10-23 22:11 | 397e | - | - | ? | results/phase21_next_vectors/397e_sockopt_close_race_20261023_221158.txt |
| 2026-10-23 22:14 | 398a | - | - | ? | results/phase21_next_vectors/398a_shm_truncate_race_20261023_221448.txt |
| 2026-10-23 22:15 | 65m | - | - | ? | results/phase16_kwrite/65m_aio_uaf_read_20261023_221528.txt |
| 2026-10-23 22:16 | 398b | - | - | ? | results/phase21_next_vectors/398b_sysctl_munmap_race_20261023_221632.txt |
| 2026-10-23 22:18 | 398c | - | - | ? | results/phase21_next_vectors/398c_sysctl_race_simple_20261023_221800.txt |
| 2026-10-23 22:20 | 398d | - | - | ? | results/phase21_next_vectors/398d_recv_munmap_race_20261023_222009.txt |
| 2026-10-23 22:20 | 65n | - | - | ? | results/phase16_kwrite/65n_aio_object_size_20261023_222029.txt |
| 2026-10-23 22:23 | 398e | - | - | ? | results/phase21_next_vectors/398e_kevent_munmap_race_20261023_222320.txt |
| 2026-10-23 22:23 | 65o | - | - | ? | results/phase16_kwrite/65o_concurrent_spray_20261023_222356.txt |
| 2026-10-23 22:26 | 65p | - | - | ? | results/phase16_kwrite/65p_aio_self_overlap_20261023_222656.txt |
| 2026-10-23 22:28 | 398f | - | - | ? | results/phase21_next_vectors/398f_mprotect_copyout_20261023_222836.txt |
| 2026-10-23 22:29 | 65q | - | - | ? | results/phase16_kwrite/65q_overlap_exploit_20261023_222916.txt |
| 2026-10-23 22:30 | 398f2 | - | - | ? | results/phase21_next_vectors/398f2_mprotect_copyout_20261023_223005.txt |
| 2026-10-23 22:34 | 65r | - | - | ? | results/phase16_kwrite/65r_fd_refcount_20261023_223423.txt |
| 2026-10-23 22:36 | 399a | - | - | ? | results/phase21_next_vectors/399a_sys636_timezone_20261023_223625.txt |
| 2026-10-23 22:36 | 399b | - | - | ? | results/phase21_next_vectors/399b_devnode_read_20261023_223631.txt |
| 2026-10-23 22:39 | 399c | - | - | ? | results/phase21_next_vectors/399c_gpu_write_20261023_223907.txt |
| 2026-10-23 22:39 | 399c | - | - | ? | results/phase21_next_vectors/399c_gpu_write_20261023_223915.txt |
| 2026-10-23 22:40 | 399d | - | - | ? | results/phase21_next_vectors/399d_gpu_mmio_scan_20261023_224056.txt |
| 2026-10-23 22:42 | 399e | - | - | ? | results/phase21_next_vectors/399e_gc_mmap_repro_20261023_224213.txt |
| 2026-10-23 22:44 | 399f | - | - | ? | results/phase21_next_vectors/399f_eboot_kernel_refs_20261023_224444.txt |
| 2026-10-23 22:47 | 65s | - | - | ? | results/phase16_kwrite/65s_aio_overlap_reclaim_20261023_224749.txt |
| 2026-10-23 22:50 | 65s | - | - | ? | results/phase16_kwrite/65s_aio_overlap_reclaim_20261023_225002.txt |
| 2026-10-23 22:54 | 65t | - | - | ? | results/phase16_kwrite/65t_aio_bigbatch_overlap_20261023_225417.txt |
| 2026-10-23 22:56 | 400a | - | - | ? | results/phase21_next_vectors/400a_kptr_rescan_20261023_225600.txt |
| 2026-10-23 22:57 | 65u | - | - | ? | results/phase16_kwrite/65u_aio_mainthread_race_20261023_225722.txt |
| 2026-10-23 22:59 | 400b | - | - | ? | results/phase21_next_vectors/400b_copyin_toctou_20261023_225952.txt |
| 2026-10-23 23:01 | 400c | - | - | ? | results/phase21_next_vectors/400c_vmmap_sysctl_20261023_230120.txt |
| 2026-10-23 23:02 | 400d | - | - | ? | results/phase21_next_vectors/400d_sysctl_sub32_20261023_230233.txt |
| 2026-10-23 23:05 | 400e | - | - | ? | results/phase21_next_vectors/400e_kaslr_stability_20261023_230514.txt |
| 2026-10-23 23:05 | 400e | - | - | ? | results/phase21_next_vectors/400e_kaslr_stability_20261023_230518.txt |
| 2026-10-23 23:14 | 65v | - | - | ? | results/phase16_kwrite/65v_cross_subsystem_overlap_20261023_231444.txt |
| 2026-10-23 23:17 | 66a | - | - | ? | results/phase16_kwrite/66a_dlsym_real_handles_20261023_231740.txt |
| 2026-10-23 23:18 | 66b | - | - | ? | results/phase16_kwrite/66b_dynlib_info2_kptr_20261023_231820.txt |
| 2026-10-23 23:19 | 66c | - | - | ? | results/phase16_kwrite/66c_aio_crosstype_spray_20261023_231943.txt |
| 2026-10-23 23:21 | 66d | - | - | ? | results/phase16_kwrite/66d_aio_overlap_detect_20261023_232132.txt |
| 2026-10-23 23:23 | 484d | - | - | ? | results/phase17_new_vectors/484d_connect_truth_20261023_232338.txt |
| 2026-10-23 23:23 | 484d | - | - | ? | results/phase17_new_vectors/484d_connect_truth_20261023_232346.txt |
| 2026-10-23 23:23 | 484d | - | - | ? | results/phase17_new_vectors/484d_connect_truth_20261023_232351.txt |
| 2026-10-23 23:27 | 65w | - | - | ? | results/phase16_kwrite/65w_fixed_cross_spray_20261023_232747.txt |
| 2026-10-23 23:27 | 66e | - | - | ? | results/phase16_kwrite/66e_aio_evf_overlap_20261023_232738.txt |
| 2026-10-23 23:33 | 66f | - | - | ? | results/phase16_kwrite/66f_massive_spray_20261023_233354.txt |
| 2026-10-23 23:36 | 66g | - | - | ? | results/phase16_kwrite/66g_669_count_limit_20261023_233607.txt |
| 2026-10-23 23:51 | 67a | - | - | ? | results/phase16_kwrite/67a_aio_readback_663_666_667_20261023_235139.txt |
| 2026-10-23 23:52 | 67a | - | - | ? | results/phase16_kwrite/67a_aio_readback_663_666_667_20261023_235254.txt |
| 2026-10-23 23:55 | 67b | - | - | ? | results/phase16_kwrite/67b_cpupin_samecache_20261023_235515.txt |
| 2026-10-24 00:03 | 67b | - | - | ? | results/phase16_kwrite/67b_poll_aio_overlap_kaslr_20261024_000315.txt |
| 2026-10-24 00:03 | 67b | - | - | ? | results/phase16_kwrite/67b_poll_aio_overlap_kaslr_20261024_000350.txt |
| 2026-10-24 00:07 | 67c | - | - | ? | results/phase16_kwrite/67c_overlap_oracle_20261024_000729.txt |
| 2026-10-24 00:12 | 67c | - | - | ? | results/phase16_kwrite/67c_overlap_oracle_20261024_001237.txt |
| 2026-10-24 00:15 | 65l | - | - | ? | results/phase16_kwrite/65l_aio_race_fixed_20261024_001504.txt |
| 2026-10-24 00:15 | 67d | - | - | ? | results/phase16_kwrite/67d_overlap_readback_20261024_001504.txt |
| 2026-10-24 00:15 | 67d | - | - | ? | results/phase16_kwrite/67d_overlap_readback_20261024_001534.txt |
| 2026-10-24 00:17 | 67d | - | - | ? | results/phase16_kwrite/67d_overlap_readback_20261024_001712.txt |
| 2026-10-24 00:20 | 67d | - | - | ? | results/phase16_kwrite/67d_synced_race_20261024_002050.txt |
| 2026-10-24 00:22 | 67e | - | - | ? | results/phase16_kwrite/67e_forced_reclaim_20261024_002242.txt |
| 2026-10-24 00:23 | 67e | - | - | ? | results/phase16_kwrite/67e_main_child_race_20261024_002327.txt |
| 2026-10-24 00:31 | 67f | - | - | ? | results/phase16_kwrite/67f_crosszone_namedobj_20261024_003154.txt |
| 2026-10-24 01:46 | 67h | - | - | ? | results/phase16_kwrite/67h_cross_cpu_delete_20261024_014630.txt |
| 2026-10-24 01:47 | 67h | - | - | ? | results/phase16_kwrite/67h_cross_cpu_delete_20261024_014732.txt |
| 2026-10-24 01:48 | 65l | - | - | ? | results/phase16_kwrite/65l_aio_race_fixed_20261024_014840.txt |
| 2026-10-24 01:49 | 67f | - | - | ? | results/phase16_kwrite/67f_fresh_race_20261024_014938.txt |
| 2026-10-24 01:53 | 67g | - | - | ? | results/phase16_kwrite/67g_highthroughput_race_20261024_015309.txt |
| 2026-10-24 01:54 | 65l | - | - | ? | results/phase16_kwrite/65l_aio_race_fixed_20261024_015417.txt |
| 2026-10-24 01:56 | 67h | - | - | ? | results/phase16_kwrite/67h_race_oracle_exploit_20261024_015638.txt |
| 2026-10-24 01:58 | 67i2 | - | - | ? | results/phase16_kwrite/67i2_gated_race_simple_20261024_015835.txt |
| 2026-10-24 02:00 | 67j | - | - | ? | results/phase16_kwrite/67j_gated_cross_cpu_20261024_020031.txt |
| 2026-10-24 02:03 | 67j | - | - | ? | results/phase16_kwrite/67j_gated_cross_cpu_20261024_020317.txt |
| 2026-10-24 02:03 | 67j | - | - | ? | results/phase16_kwrite/67j_gated_cross_cpu_20261024_020341.txt |
| 2026-10-24 02:09 | 67k | - | - | ? | results/phase16_kwrite/67k_combined_20261024_020945.txt |
| 2026-10-24 02:22 | 67l | - | - | ? | results/phase16_kwrite/67l_overlap_detect_20261024_022243.txt |
| 2026-10-24 02:32 | 67m | - | - | ? | results/phase16_kwrite/67m_663_characterize_20261024_023236.txt |
| 2026-10-24 11:08 | 486a | - | - | ? | results/phase17_new_vectors/486a_aio662_gate_20261024_110855.txt |
| 2026-10-24 11:11 | 486b | - | - | ? | results/phase17_new_vectors/486b_aio_create_probe_20261024_111120.txt |
| 2026-10-24 11:12 | 486c | - | - | ? | results/phase17_new_vectors/486c_661_zero_20261024_111223.txt |
| 2026-10-24 11:13 | 486e | - | - | ? | results/phase17_new_vectors/486e_aio662_live_slots_20261024_111353.txt |
| 2026-10-24 11:14 | 486f | - | - | ? | results/phase17_new_vectors/486f_aio668_zero_20261024_111414.txt |
| 2026-10-24 11:15 | 486h | - | - | ? | results/phase17_new_vectors/486h_aio662_context_scan_20261024_111558.txt |
| 2026-10-24 11:16 | 486j | - | - | ? | results/phase17_new_vectors/486j_aio668_default_20261024_111623.txt |
| 2026-10-24 11:19 | 486k | - | - | ? | results/phase17_new_vectors/486k_aio662_slot_sweep_20261024_111954.txt |
| 2026-10-24 11:20 | 487a | - | - | ? | results/phase17_new_vectors/487a_661_page_0_0_20261024_112058.txt |
| 2026-10-24 11:24 | 487a | - | - | ? | results/phase17_new_vectors/487a_aio_count0_20261024_112413.txt |
| 2026-10-24 11:24 | 487b | - | - | ? | results/phase17_new_vectors/487b_aio_nodes_20261024_112457.txt |
| 2026-10-24 11:27 | 488a | - | - | ? | results/phase17_new_vectors/488a_aio_create_delete_20261024_112740.txt |
| 2026-10-24 11:27 | 488b | - | - | ? | results/phase17_new_vectors/488b_aio_create_matrix_20261024_112758.txt |
| 2026-10-24 11:28 | 488c | - | - | ? | results/phase17_new_vectors/488c_aio_create_out_20261024_112813.txt |
| 2026-10-24 11:28 | 488d | - | - | ? | results/phase17_new_vectors/488d_aio_delete_live_20261024_112833.txt |
| 2026-10-24 11:29 | 488e | - | - | ? | results/phase17_new_vectors/488e_aio_mode_matrix_20261024_112906.txt |
| 2026-10-24 11:29 | 488f | - | - | ? | results/phase17_new_vectors/488f_aio_request_state_20261024_112924.txt |
| 2026-10-24 11:29 | 489a | - | - | ? | results/phase17_new_vectors/489a_aio_delete_outrec_20261024_112959.txt |
| 2026-10-24 11:32 | 489b | - | - | ? | results/phase17_new_vectors/489b_aio_poll_cancel_20261024_113256.txt |
| 2026-10-24 11:33 | 489c | - | - | ? | results/phase17_new_vectors/489c_aio_dup_delete_20261024_113350.txt |
| 2026-10-24 11:34 | 490a | - | - | ? | results/phase17_new_vectors/490a_native_surface_20261024_113421.txt |
| 2026-10-24 11:34 | 490b | - | - | ? | results/phase17_new_vectors/490b_loader_threads_20261024_113447.txt |
| 2026-10-24 11:34 | 490c | - | - | ? | results/phase17_new_vectors/490c_thread_lua_source_20261024_113455.txt |
| 2026-10-24 11:35 | 491a | - | - | ? | results/phase17_new_vectors/491a_lua_thread_syscall_20261024_113522.txt |
| 2026-10-24 11:36 | 491b | - | - | ? | results/phase17_new_vectors/491b_aio_delete_leak_20261024_113617.txt |
| 2026-10-24 11:36 | 492a | - | - | ? | results/phase17_new_vectors/492a_loader_tables_20261024_113633.txt |
| 2026-10-24 11:37 | 492b | - | - | ? | results/phase17_new_vectors/492b_aio_poll_write_20261024_113714.txt |
| 2026-10-24 11:37 | 492b | - | - | ? | results/phase17_new_vectors/492b_aio_poll_write_20261024_113721.txt |
| 2026-10-24 11:37 | 492c | - | - | ? | results/phase17_new_vectors/492c_aio_poll_writer_20261024_113733.txt |
| 2026-10-24 11:37 | 492d | - | - | ? | results/phase17_new_vectors/492d_aio_poll_ptr_check_20261024_113751.txt |
| 2026-10-24 11:38 | 493a | - | - | ? | results/phase17_new_vectors/493a_eboot_syscall_scan_20261024_113818.txt |
| 2026-10-24 11:40 | 493b | - | - | ? | results/phase17_new_vectors/493b_syscall_scan_bounded_20261024_114015.txt |
| 2026-10-24 11:44 | 494a | - | - | ? | results/phase17_new_vectors/494a_run_lua_in_thread_20261024_114406.txt |
| 2026-10-24 11:44 | 494b | - | - | ? | results/phase17_new_vectors/494b_thread_runner_source_20261024_114423.txt |
| 2026-10-24 11:44 | 494c | - | - | ? | results/phase17_new_vectors/494c_thread_body_test_20261024_114437.txt |
| 2026-10-24 11:44 | 494d | - | - | ? | results/phase17_new_vectors/494d_thread_662_20261024_114457.txt |
| 2026-10-24 11:45 | 494d | - | - | ? | results/phase17_new_vectors/494d_thread_662_20261024_114506.txt |
| 2026-10-24 11:45 | 494d | - | - | ? | results/phase17_new_vectors/494d_thread_662_20261024_114521.txt |
| 2026-10-24 11:45 | 495a | - | - | ? | results/phase17_new_vectors/495a_thread_memory_20261024_114537.txt |
| 2026-10-24 11:46 | 495b | - | - | ? | results/phase17_new_vectors/495b_aio_race_20261024_114600.txt |
| 2026-10-24 11:47 | 495c | - | - | ? | results/phase17_new_vectors/495c_aio_race_first_20261024_114703.txt |
| 2026-10-24 11:47 | 496a | - | - | ? | results/phase17_new_vectors/496a_aio_id_reuse_20261024_114738.txt |
| 2026-10-24 11:48 | 496b | - | - | ? | results/phase17_new_vectors/496b_aio_pileup_20261024_114822.txt |
| 2026-10-24 11:49 | 496c | - | - | ? | results/phase17_new_vectors/496c_threads_control_20261024_114919.txt |
| 2026-10-24 11:49 | 496d | - | - | ? | results/phase17_new_vectors/496d_threads_limit_20261024_114954.txt |
| 2026-10-24 11:54 | 497a | - | - | ? | results/phase17_new_vectors/497a_aio_wait_semantics_20261024_115449.txt |
| 2026-10-24 11:57 | 497b | - | - | ? | results/phase17_new_vectors/497b_aio_delete_vs_poll_20261024_115740.txt |
| 2026-10-24 11:58 | 497c | - | - | ? | results/phase17_new_vectors/497c_poll_only_control_20261024_115821.txt |
| 2026-10-24 11:59 | 497e | - | - | ? | results/phase17_new_vectors/497e_aio_dense_race_20261024_115907.txt |
| 2026-10-24 11:59 | 497f | - | - | ? | results/phase17_new_vectors/497f_aio_race_matrix_20261024_115922.txt |
| 2026-10-24 12:00 | 498a | - | - | ? | results/phase17_new_vectors/498a_aio_double_pass_20261024_120059.txt |
| 2026-10-24 12:01 | 498b | - | - | ? | results/phase17_new_vectors/498b_aio_slot_recycle_20261024_120131.txt |
| 2026-10-24 12:01 | 498b | - | - | ? | results/phase17_new_vectors/498b_aio_slot_recycle_20261024_120147.txt |
| 2026-10-24 12:02 | 498c | - | - | ? | results/phase17_new_vectors/498c_aio_create_vs_delete_20261024_120251.txt |
| 2026-10-24 12:06 | 498c | - | - | ? | results/phase17_new_vectors/498c_aio_create_vs_delete_20261024_120607.txt |
| 2026-10-24 12:07 | 498a | - | - | ? | results/phase17_new_vectors/498a_aio_double_pass_20261024_120734.txt |
| 2026-10-24 12:07 | 498d | - | - | ? | results/phase17_new_vectors/498d_aio_post_race_health_20261024_120740.txt |
| 2026-10-24 12:09 | 497f | - | - | ? | results/phase17_new_vectors/497f_aio_race_matrix_20261024_120925.txt |
| 2026-10-24 12:09 | 497f | - | - | ? | results/phase17_new_vectors/497f_aio_race_matrix_20261024_120926.txt |
| 2026-10-24 12:09 | 498e | - | - | ? | results/phase17_new_vectors/498e_aio_post_race_health2_20261024_120911.txt |
| 2026-10-24 12:12 | 499a | - | - | ? | results/phase17_new_vectors/499a_aio_alias_after_race_20261024_121248.txt |
| 2026-10-24 12:13 | 499b | - | - | ? | results/phase17_new_vectors/499b_aio_allocator_churn_20261024_121326.txt |
| 2026-10-24 12:13 | 499b | - | - | ? | results/phase17_new_vectors/499b_aio_allocator_churn_20261024_121340.txt |
| 2026-10-24 12:13 | 499b | - | - | ? | results/phase17_new_vectors/499b_aio_allocator_churn_20261024_121341.txt |
| 2026-10-24 12:13 | 499b | - | - | ? | results/phase17_new_vectors/499b_aio_allocator_churn_20261024_121342.txt |
| 2026-10-24 12:13 | 499b | - | - | ? | results/phase17_new_vectors/499b_aio_allocator_churn_20261024_121344.txt |
| 2026-10-24 12:14 | 499c | - | - | ? | results/phase17_new_vectors/499c_aio_cross_cpu_alias_20261024_121420.txt |
| 2026-10-24 12:14 | 499c | - | - | ? | results/phase17_new_vectors/499c_aio_cross_cpu_alias_20261024_121421.txt |
| 2026-10-24 12:15 | 499d | - | - | ? | results/phase17_new_vectors/499d_aio_recycle_instrumented_20261024_121533.txt |
| 2026-10-24 12:20 | 500a | - | - | ? | results/phase17_new_vectors/500a_aio_descriptor_layout_20261024_122021.txt |
| 2026-10-24 12:20 | 500b | - | - | ? | results/phase17_new_vectors/500b_aio_submit_gate_20261024_122051.txt |
| 2026-10-24 12:23 | 501a | - | - | ? | results/phase17_new_vectors/501a_struct_pointer_follow_20261024_122357.txt |
| 2026-10-24 12:24 | 501b | - | - | ? | results/phase17_new_vectors/501b_sys572_follow_20261024_122450.txt |
| 2026-10-24 12:25 | 501c | - | - | ? | results/phase17_new_vectors/501c_sys572_output_20261024_122504.txt |
| 2026-10-24 12:28 | 501d | - | - | ? | results/phase17_new_vectors/501d_umtx_op_map_20261024_122827.txt |
| 2026-10-24 12:32 | 502a | - | - | ? | results/phase17_new_vectors/502a_aio_slot_swap_race_20261024_123226.txt |
| 2026-10-24 12:33 | 502b | - | - | ? | results/phase17_new_vectors/502b_aio_slot_swap_control_20261024_123316.txt |
| 2026-10-24 12:33 | 502c | - | - | ? | results/phase17_new_vectors/502c_aio_create_vs_delete_20261024_123357.txt |
| 2026-10-24 12:34 | 502c | - | - | ? | results/phase17_new_vectors/502c_aio_create_vs_delete_20261024_123415.txt |
| 2026-10-24 12:34 | 502d | - | - | ? | results/phase17_new_vectors/502d_aio_steal_slot_20261024_123448.txt |
| 2026-10-24 12:35 | 502e | - | - | ? | results/phase17_new_vectors/502e_aio_object_cap_20261024_123514.txt |
| 2026-10-24 12:35 | 502f | - | - | ? | results/phase17_new_vectors/502f_aio_poll_then_delete_scale_20261024_123547.txt |
| 2026-10-24 12:36 | 502h | - | - | ? | results/phase17_new_vectors/502h_aio_one_slot_churn_20261024_123632.txt |
| 2026-10-24 12:37 | 502i | - | - | ? | results/phase17_new_vectors/502i_aio_slot_churn_polled_20261024_123710.txt |
| 2026-10-24 12:38 | 502j | - | - | ? | results/phase17_new_vectors/502j_aio_seed_swap_20261024_123813.txt |
| 2026-10-24 12:41 | 503a | - | - | ? | results/phase17_new_vectors/503a_aio_out_record_20261024_124145.txt |
| 2026-10-24 12:41 | 503a | - | - | ? | results/phase17_new_vectors/503a_aio_out_record_20261024_124159.txt |
| 2026-10-24 12:42 | 503a | - | - | ? | results/phase17_new_vectors/503a_aio_out_record_20261024_124223.txt |
| 2026-10-24 12:42 | 503a | - | - | ? | results/phase17_new_vectors/503a_aio_out_record_20261024_124230.txt |
| 2026-10-24 13:03 | 504a | - | - | ? | results/phase17_new_vectors/504a_aio_shared_ctx_20261024_130318.txt |
| 2026-10-24 13:03 | 504a | - | - | ? | results/phase17_new_vectors/504a_aio_shared_ctx_20261024_130324.txt |
| 2026-10-24 13:05 | 504b | - | - | ? | results/phase17_new_vectors/504b_aio_reclaim_ctx_20261024_130530.txt |
| 2026-10-24 13:05 | 504c | - | - | ? | results/phase17_new_vectors/504c_aio_decrement_probe_20261024_130551.txt |
| 2026-10-24 13:08 | 505a | - | - | ? | results/phase17_new_vectors/505a_aio_slot_capacity_20261024_130857.txt |
| 2026-10-24 13:09 | 506a | - | - | ? | results/phase17_new_vectors/506a_thread_wall_20261024_130924.txt |
| 2026-10-24 13:09 | 506b | - | - | ? | results/phase17_new_vectors/506b_helper_speed_sleep_20261024_130944.txt |
| 2026-10-24 13:09 | 506b | - | - | ? | results/phase17_new_vectors/506b_helper_speed_sleep_20261024_130950.txt |
| 2026-10-24 13:10 | 506c | - | - | ? | results/phase17_new_vectors/506c_helper_startup_20261024_131013.txt |
| 2026-10-24 13:10 | 507a | - | - | ? | results/phase17_new_vectors/507a_aio_fill_zone_20261024_131058.txt |
| 2026-10-24 13:12 | 508a | - | - | ? | results/phase17_new_vectors/508a_aio_filler_health_20261024_131243.txt |
| 2026-10-24 13:28 | 509a | - | - | ? | results/phase17_new_vectors/509a_thread_syscall_concurrency_20261024_132809.txt |
| 2026-10-24 13:28 | 509b | - | - | ? | results/phase17_new_vectors/509b_thread_syscall_concurrency_20261024_132841.txt |
| 2026-10-24 13:30 | 510a | - | - | ? | results/phase17_new_vectors/510a_child_rop_syscall_20261024_133036.txt |
| 2026-10-24 13:32 | 510b | - | - | ? | results/phase17_new_vectors/510b_gadget_survey_20261024_133236.txt |
| 2026-10-24 13:32 | 510c | - | - | ? | results/phase17_new_vectors/510c_loader_chain_gadgets_20261024_133254.txt |
| 2026-10-24 13:33 | 510d | - | - | ? | results/phase17_new_vectors/510d_fcall_stub_pointer_20261024_133331.txt |
| 2026-10-24 13:34 | 510e | - | - | ? | results/phase17_new_vectors/510e_chain_walk_20261024_133410.txt |
| 2026-10-24 13:37 | 511a | - | - | ? | results/phase17_new_vectors/511a_identity_and_native_20261024_133748.txt |
| 2026-10-24 13:39 | 512a | - | - | ? | results/phase17_new_vectors/512a_dlsym_handles_20261024_133938.txt |
| 2026-10-24 13:40 | 513a | - | - | ? | results/phase17_new_vectors/513a_dlsym_argument_shapes_20261024_134011.txt |
| 2026-10-24 13:40 | 514a | - | - | ? | results/phase17_new_vectors/514a_chain_ring_scan_20261024_134050.txt |
| 2026-10-24 13:41 | 514b | - | - | ? | results/phase17_new_vectors/514b_fcall_stub_bytes_20261024_134115.txt |
| 2026-10-24 13:41 | 515a | - | - | ? | results/phase17_new_vectors/515a_heap_protection_20261024_134158.txt |
| 2026-10-24 13:42 | 516a | - | - | ? | results/phase17_new_vectors/516a_exec_regions_20261024_134240.txt |
| 2026-10-24 13:43 | 517a | - | - | ? | results/phase17_new_vectors/517a_libc_syscall_scan_20261024_134346.txt |
| 2026-10-24 13:44 | 518a | - | - | ? | results/phase17_new_vectors/518a_libc_syscall_stub_20261024_134454.txt |
| 2026-10-24 13:46 | 520a | - | - | ? | results/phase17_new_vectors/520a_libkernel_syscall_entry_20261024_134621.txt |
| 2026-10-24 13:46 | 520a | - | - | ? | results/phase17_new_vectors/520a_libkernel_syscall_entry_20261024_134631.txt |
| 2026-10-24 13:47 | 520a | - | - | ? | results/phase17_new_vectors/520a_libkernel_syscall_entry_20261024_134702.txt |
| 2026-10-24 13:50 | 521a | - | - | ? | results/phase17_new_vectors/521a_corrected_mib_leaks_20261024_135059.txt |
| 2026-10-24 13:53 | 58b | - | - | ? | results/phase15_native_sysent/58b_msync_device_pager_20261024_135357.txt |
| 2026-10-24 13:58 | 523a | - | - | ? | results/phase17_new_vectors/523a_aio_delete_race_threads_20261024_135839.txt |
| 2026-10-24 14:00 | 523b | - | - | ? | results/phase17_new_vectors/523b_aio_delete_storm_20261024_140023.txt |
| 2026-10-24 14:01 | 523c | - | - | ? | results/phase17_new_vectors/523c_aio_delete_race_fixed_20261024_140141.txt |
| 2026-10-24 14:08 | 523c | - | - | ? | results/phase17_new_vectors/523c_aio_delete_race_fixed_20261024_140856.txt |
| 2026-10-24 14:09 | 523c | - | - | ? | results/phase17_new_vectors/523c_aio_delete_race_fixed_20261024_140951.txt |
| 2026-10-24 14:17 | 524b | - | - | ? | results/phase17_new_vectors/524b_aio_double_free_allocator_20261024_141727.txt |
| 2026-10-24 14:17 | 524b | - | - | ? | results/phase17_new_vectors/524b_aio_double_free_allocator_20261024_141737.txt |
| 2026-10-24 14:20 | 525a | - | - | ? | results/phase17_new_vectors/525a_aio_delete_create_swap_20261024_142013.txt |
| 2026-10-24 14:21 | 525a | - | - | ? | results/phase17_new_vectors/525a_aio_delete_create_swap_20261024_142104.txt |
| 2026-10-24 14:21 | 525b | - | - | ? | results/phase17_new_vectors/525b_aio_fill_freed_slots_20261024_142127.txt |
| 2026-10-24 14:50 | 528a | - | - | ? | results/phase17_new_vectors/528a_aio_multi_delete_20261024_145057.txt |
| 2026-10-24 14:51 | 528a | - | - | ? | results/phase17_new_vectors/528a_aio_multi_delete_20261024_145105.txt |
| 2026-10-24 14:51 | 528a | - | - | ? | results/phase17_new_vectors/528a_aio_multi_delete_20261024_145110.txt |
| 2026-10-24 14:51 | 528a | - | - | ? | results/phase17_new_vectors/528a_aio_multi_delete_20261024_145123.txt |
| 2026-10-24 14:54 | 529a | - | - | ? | results/phase17_new_vectors/529a_devctrl_leak_sweep_20261024_145447.txt |
| 2026-10-24 14:58 | 529a | - | - | ? | results/phase17_new_vectors/529a_devctrl_leak_sweep_20261024_145846.txt |
| 2026-10-24 15:04 | 529a | - | - | ? | results/phase17_new_vectors/529a_devctrl_leak_sweep_20261024_150424.txt |
| 2026-10-24 15:05 | 530a | - | - | ? | results/phase17_new_vectors/530a_aio_count_bounds_20261024_150511.txt |
| 2026-10-24 15:09 | 531a | - | - | ? | results/phase17_new_vectors/531a_aio_count_short_buffer_20261024_150904.txt |
| 2026-10-24 15:12 | 532a | - | - | ? | results/phase17_new_vectors/532a_aio_block_threshold_20261024_151231.txt |
| 2026-10-24 15:16 | 534a | - | - | ? | results/phase17_new_vectors/534a_aio_block_ids_20261024_151654.txt |
| 2026-10-24 15:17 | 535a | - | - | ? | results/phase17_new_vectors/535a_aio_short_copyin_20261024_151745.txt |
| 2026-10-24 15:18 | 536a | - | - | ? | results/phase17_new_vectors/536a_sys625_msr_20261024_151858.txt |
| 2026-10-24 15:19 | 537a | - | - | ? | results/phase17_new_vectors/537a_sys625_write_read_20261024_151945.txt |
| 2026-10-24 15:20 | 538a | - | - | ? | results/phase17_new_vectors/538a_sys625_msr_map_20261024_152011.txt |
| 2026-10-24 15:20 | 539a | - | - | ? | results/phase17_new_vectors/539a_sys625_domain_paths_20261024_152030.txt |
| 2026-10-24 15:20 | 540a | - | - | ? | results/phase17_new_vectors/540a_sys625_index_map_20261024_152048.txt |
| 2026-10-24 15:21 | 541a | - | - | ? | results/phase17_new_vectors/541a_umtx_op_matrix_20261024_152151.txt |
| 2026-10-24 15:22 | 541a | - | - | ? | results/phase17_new_vectors/541a_umtx_op_matrix_20261024_152200.txt |
| 2026-10-24 15:22 | 542a | - | - | ? | results/phase17_new_vectors/542a_umtx_pi_lock_20261024_152258.txt |
| 2026-10-24 15:24 | 543a | - | - | ? | results/phase17_new_vectors/543a_umtx_contested_bit_20261024_152411.txt |
| 2026-10-24 15:24 | 543b | - | - | ? | results/phase17_new_vectors/543b_umtx_contested_owner_20261024_152451.txt |
| 2026-10-24 15:29 | 544a | - | - | ? | results/phase17_new_vectors/544a_umtx_pi_owner_exit_20261024_152907.txt |
| 2026-10-24 15:30 | 545a | - | - | ? | results/phase17_new_vectors/545a_umtx_dead_owner_wake_20261024_153015.txt |
| 2026-10-24 15:30 | 546a | - | - | ? | results/phase17_new_vectors/546a_aio_shared_ctx_dangling_20261024_153049.txt |
| 2026-10-24 15:31 | 547a | - | - | ? | results/phase17_new_vectors/547a_aio_get_data_20261024_153148.txt |
| 2026-10-24 15:33 | 548a | - | - | ? | results/phase17_new_vectors/548a_eboot_pop_gadgets_20261024_153311.txt |
| 2026-10-24 16:11 | 549a | - | - | ? | results/phase17_new_vectors/549a_chain_arg4_plumbing_20261024_161110.txt |
| 2026-10-24 16:13 | 549a | - | - | ? | results/phase17_new_vectors/549a_chain_arg4_plumbing_20261024_161340.txt |
| 2026-10-24 16:14 | 551a | - | - | ? | results/phase17_new_vectors/551a_chain_arg4_ret_20261024_161417.txt |
| 2026-10-24 16:14 | 552a | - | - | ? | results/phase17_new_vectors/552a_chain_arg4_674_20261024_161459.txt |
| 2026-10-24 16:15 | 553a | - | - | ? | results/phase17_new_vectors/553a_chain_arg4_mmap_20261024_161528.txt |
| 2026-10-24 16:16 | 554a | - | - | ? | results/phase17_new_vectors/554a_libc_pop_r10_20261024_161605.txt |
| 2026-10-24 16:16 | 554a | - | - | ? | results/phase17_new_vectors/554a_libc_pop_r10_20261024_161635.txt |
| 2026-10-24 16:21 | 556a | - | - | ? | results/phase17_new_vectors/556a_aio_double_free_followup_20261024_162100.txt |
| 2026-10-24 16:23 | 557a | - | - | ? | results/phase17_new_vectors/557a_aio_block_last_item_race_20261024_162310.txt |
| 2026-10-24 16:23 | 558a | - | - | ? | results/phase17_new_vectors/558a_pi_mutex_contention_20261024_162337.txt |
| 2026-10-24 16:24 | 559a | - | - | ? | results/phase17_new_vectors/559a_ctx_gpr_args_20261024_162438.txt |
| 2026-10-24 16:29 | 559a | - | - | ? | results/phase17_new_vectors/559a_ctx_gpr_args_20261024_162921.txt |
| 2026-10-24 16:30 | 559a | - | - | ? | results/phase17_new_vectors/559a_ctx_gpr_args_20261024_163013.txt |
| 2026-10-24 16:32 | 559b | - | - | ? | results/phase17_new_vectors/559b_ctx_arg4_sysctl_20261024_163201.txt |
| 2026-10-24 16:33 | 561a | - | - | ? | results/phase17_new_vectors/561a_aio_generation_wrap_20261024_163338.txt |
| 2026-10-24 16:37 | 562a | - | - | ? | results/phase17_new_vectors/562a_aio_wake_burst_race_20261024_163725.txt |
| 2026-10-24 16:40 | 562a | - | - | ? | results/phase17_new_vectors/562a_aio_wake_burst_race_20261024_164054.txt |
| 2026-10-24 16:41 | 562a | - | - | ? | results/phase17_new_vectors/562a_aio_wake_burst_race_20261024_164142.txt |
| 2026-10-24 16:41 | 562a | - | - | ? | results/phase17_new_vectors/562a_aio_wake_burst_race_20261024_164156.txt |
| 2026-10-24 16:41 | 563a | - | - | ? | results/phase17_new_vectors/563a_cpu_count_20261024_164111.txt |
| 2026-10-24 16:42 | 562a | - | - | ? | results/phase17_new_vectors/562a_aio_wake_burst_race_20261024_164223.txt |
| 2026-10-24 16:46 | 564a | - | - | ? | results/phase17_new_vectors/564a_pi_real_flag_20261024_164627.txt |
| 2026-10-24 16:46 | 565a | - | - | ? | results/phase17_new_vectors/565a_pi_waiter_handoff_20261024_164655.txt |
| 2026-10-24 16:47 | 567a | - | - | ? | results/phase17_new_vectors/567a_robust_owner_exit_20261024_164752.txt |
| 2026-10-24 16:49 | 569a | - | - | ? | results/phase17_new_vectors/569a_pi_dead_owner_churn_20261024_164918.txt |
| 2026-10-24 16:49 | 569a | - | - | ? | results/phase17_new_vectors/569a_pi_dead_owner_churn_20261024_164926.txt |
| 2026-10-24 16:49 | 569a | - | - | ? | results/phase17_new_vectors/569a_pi_dead_owner_churn_20261024_164955.txt |
| 2026-10-24 16:50 | 570a | - | - | ? | results/phase17_new_vectors/570a_child_liveness_20261024_165029.txt |
| 2026-10-24 16:54 | 571a | - | - | ? | results/phase17_new_vectors/571a_pi_handoff_20261024_165451.txt |
| 2026-10-24 16:57 | 572a | - | - | ? | results/phase17_new_vectors/572a_cclosure_exec_page_20261024_165728.txt |
| 2026-10-24 16:57 | 572b | - | - | ? | results/phase17_new_vectors/572b_closure_addr_20261024_165737.txt |
| 2026-10-24 16:58 | 572a | - | - | ? | results/phase17_new_vectors/572a_cclosure_exec_page_20261024_165817.txt |
| 2026-10-24 18:08 | 563a | - | - | ? | results/phase17_new_vectors/563a_leak_survey_532_20261024_180849.txt |
| 2026-10-24 18:09 | 563a | - | - | ? | results/phase17_new_vectors/563a_leak_survey_532_20261024_180913.txt |
| 2026-10-24 18:10 | 563b | - | - | ? | results/phase17_new_vectors/563b_leak_survey_562_20261024_181042.txt |
| 2026-10-24 18:11 | 563b | - | - | ? | results/phase17_new_vectors/563b_leak_survey_563_20261024_181119.txt |
| 2026-10-24 18:12 | 563d | - | - | ? | results/phase17_new_vectors/563d_leak_survey_569_20261024_181211.txt |
| 2026-10-24 18:13 | 563e | - | - | ? | results/phase17_new_vectors/563e_leak_survey_570_20261024_181301.txt |
| 2026-10-24 18:15 | 564a | - | - | ? | results/phase17_new_vectors/564a_leak_survey_20261024_181520.txt |
| 2026-10-24 18:15 | 564b | - | - | ? | results/phase17_new_vectors/564b_leak_survey_20261024_181524.txt |
| 2026-10-24 18:15 | 564c | - | - | ? | results/phase17_new_vectors/564c_leak_survey_20261024_181530.txt |
| 2026-10-24 18:15 | 564d | - | - | ? | results/phase17_new_vectors/564d_leak_survey_20261024_181536.txt |
| 2026-10-24 18:15 | 564e | - | - | ? | results/phase17_new_vectors/564e_leak_survey_20261024_181540.txt |
| 2026-10-24 18:15 | 565a | - | - | ? | results/phase17_new_vectors/565a_survey_hits_20261024_181556.txt |
| 2026-10-24 18:16 | 565b | - | - | ? | results/phase17_new_vectors/565b_sys639_write_20261024_181621.txt |
| 2026-10-24 18:17 | 566a | - | - | ? | results/phase17_new_vectors/566a_aio_read_runs_20261024_181750.txt |
| 2026-10-24 18:18 | 567a | - | - | ? | results/phase17_new_vectors/567a_mdbg_sweep_20261024_181858.txt |
| 2026-10-24 18:20 | 566b | - | - | ? | results/phase17_new_vectors/566b_aio_read_baseline_20261024_182016.txt |
| 2026-10-24 18:20 | 566c | - | - | ? | results/phase17_new_vectors/566c_aio_pending_delete_20261024_182041.txt |
| 2026-10-24 18:20 | 566c | - | - | ? | results/phase17_new_vectors/566c_aio_pending_delete_20261024_182054.txt |
| 2026-10-24 18:23 | 566c | - | - | ? | results/phase17_new_vectors/566c_aio_pending_delete_20261024_182355.txt |
| 2026-10-24 18:24 | 566d | - | - | ? | results/phase17_new_vectors/566d_alloc_shapes_20261024_182429.txt |
| 2026-10-24 18:24 | 566e | - | - | ? | results/phase17_new_vectors/566e_init_line_20261024_182443.txt |
| 2026-10-24 18:25 | 566f | - | - | ? | results/phase17_new_vectors/566f_aio_pending_delete_20261024_182512.txt |
| 2026-10-24 18:27 | 566g | - | - | ? | results/phase17_new_vectors/566g_aio_delete_record_20261024_182745.txt |
| 2026-10-24 19:00 | 566g | - | - | ? | results/phase17_new_vectors/566g_aio_delete_record_20261024_190010.txt |
| 2026-10-24 19:00 | 568a | - | - | ? | results/phase17_new_vectors/568a_aio_alias_cycles_20261024_190019.txt |
| 2026-10-24 19:02 | 568a | - | - | ? | results/phase17_new_vectors/568a_aio_alias_cycles_20261024_190209.txt |
| 2026-10-24 19:02 | 568a | - | - | ? | results/phase17_new_vectors/568a_aio_alias_cycles_20261024_190247.txt |
| 2026-10-24 19:03 | 569a | - | - | ? | results/phase17_new_vectors/569a_aio_stale_slot_20261024_190337.txt |
| 2026-10-24 19:04 | 570a | - | - | ? | results/phase17_new_vectors/570a_aio_block_size_20261024_190448.txt |
| 2026-10-24 19:08 | 571a | - | - | ? | results/phase17_new_vectors/571a_aio_block_isolate_20261024_190839.txt |
| 2026-10-24 19:09 | 574a | - | - | ? | results/phase17_new_vectors/574a_aio_poll_bisect_20261024_190924.txt |
| 2026-10-24 19:10 | 572a | - | - | ? | results/phase17_new_vectors/572a_aio_workitem_dup_20261024_191008.txt |
| 2026-10-24 19:10 | 572a | - | - | ? | results/phase17_new_vectors/572a_aio_workitem_dup_20261024_191021.txt |
| 2026-10-24 19:10 | 572a | - | - | ? | results/phase17_new_vectors/572a_aio_workitem_dup_20261024_191031.txt |
| 2026-10-24 19:19 | 576a | - | - | ? | results/phase17_new_vectors/576a_aio_block_stages_20261024_191930.txt |
| 2026-10-24 19:20 | 577a | - | - | ? | results/phase17_new_vectors/577a_aio_completion_storm_20261024_192017.txt |
| 2026-10-24 19:25 | 577a | - | - | ? | results/phase17_new_vectors/577a_aio_completion_storm_20261024_192541.txt |
| 2026-10-24 19:26 | 574a | - | - | ? | results/phase17_new_vectors/574a_aio_poll_bisect_20261024_192627.txt |
| 2026-10-24 19:26 | 578a | - | - | ? | results/phase17_new_vectors/578a_aio_early_completion_20261024_192600.txt |
| 2026-10-24 19:26 | 579a | - | - | ? | results/phase17_new_vectors/579a_sys649_member_types_20261024_192651.txt |
| 2026-10-24 19:29 | 579b | - | - | ? | results/phase17_new_vectors/579b_sys649_all_handles_20261024_192940.txt |
| 2026-10-24 20:25 | 586a | - | - | ? | results/phase17_new_vectors/586a_blockpool_map_20261024_202526.txt |
| 2026-10-24 20:26 | 587a | - | - | ? | results/phase17_new_vectors/587a_blockpool_batch_alloc_20261024_202648.txt |
| 2026-10-24 20:26 | 587a | - | - | ? | results/phase17_new_vectors/587a_blockpool_batch_alloc_20261024_202654.txt |
| 2026-10-24 20:27 | 588a | - | - | ? | results/phase17_new_vectors/588a_blockpool_open_flags_20261024_202716.txt |
| 2026-10-24 20:27 | 589a | - | - | ? | results/phase17_new_vectors/589a_blockpool_offset_probe_20261024_202744.txt |
| 2026-10-24 20:28 | 590a | - | - | ? | results/phase17_new_vectors/590a_umtx_robust_lists_20261024_202808.txt |
| 2026-10-24 20:29 | 591a | - | - | ? | results/phase17_new_vectors/591a_chicken_gate_retest_20261024_202903.txt |
| 2026-10-24 20:40 | 592a | - | - | ? | results/phase17_new_vectors/592a_loadprx_probe_20261024_204027.txt |
| 2026-10-24 20:40 | 593a | - | - | ? | results/phase17_new_vectors/593a_blockpool_id_devctx_20261024_204044.txt |
| 2026-10-24 20:41 | 594a | - | - | ? | results/phase17_new_vectors/594a_devctl_after_blockpool_20261024_204104.txt |
| 2026-10-24 20:43 | 595a | - | - | ? | results/phase17_new_vectors/595a_devctx_before_after_20261024_204309.txt |
| 2026-10-24 20:43 | 596a | - | - | ? | results/phase17_new_vectors/596a_devctl_arg1_pointer_20261024_204337.txt |
| 2026-10-24 20:44 | 597a | - | - | ? | results/phase17_new_vectors/597a_device_enum_20261024_204428.txt |
| 2026-10-24 20:46 | 598a | - | - | ? | results/phase17_new_vectors/598a_ioctl_raw_sweep_20261024_204606.txt |
| 2026-10-24 20:46 | 599a | - | - | ? | results/phase17_new_vectors/599a_dmem_phys_window_20261024_204639.txt |
| 2026-10-24 20:47 | 600a | - | - | ? | results/phase17_new_vectors/600a_gc_mmio_dump_20261024_204707.txt |
| 2026-10-24 20:50 | 601a | - | - | ? | results/phase17_new_vectors/601a_device_id_unlock_20261024_205001.txt |
| 2026-10-24 20:54 | 602a | - | - | ? | results/phase17_new_vectors/602a_aio_race_spray_20261024_205452.txt |
| 2026-10-24 20:56 | 603a | - | - | ? | results/phase17_new_vectors/603a_aio_pending_wait_20261024_205602.txt |
| 2026-10-24 20:56 | 604a | - | - | ? | results/phase17_new_vectors/604a_aio_delete_pending_20261024_205621.txt |
| 2026-10-24 20:56 | 605a | - | - | ? | results/phase17_new_vectors/605a_aio_pending_orderings_20261024_205650.txt |
| 2026-10-24 20:57 | 606a | - | - | ? | results/phase17_new_vectors/606a_aio_aiocb_layout_20261024_205717.txt |
| 2026-10-24 20:58 | 607a | - | - | ? | results/phase17_new_vectors/607a_aio_worker_reclaim_20261024_205811.txt |
| 2026-10-24 21:00 | 608a | - | - | ? | results/phase17_new_vectors/608a_aio_wedge_bisect_20261024_210016.txt |
| 2026-10-24 21:00 | ping | - | - | ? | results/ping_20261024_210011.txt |
| 2026-10-24 21:01 | 609a | - | - | ? | results/phase17_new_vectors/609a_aio_slot_leak_20261024_210101.txt |
| 2026-10-24 21:03 | 610a | - | - | ? | results/phase17_new_vectors/610a_aio_race_threshold_20261024_210325.txt |
| 2026-10-24 21:11 | 611a | - | - | ? | results/phase17_new_vectors/611a_aio_cycle_leak_20261024_211125.txt |
| 2026-10-24 21:14 | 612a | - | - | ? | results/phase17_new_vectors/612a_aio_leak_localize_20261024_211432.txt |
| 2026-10-24 21:14 | 613a | - | - | ? | results/phase17_new_vectors/613a_aio_file_cycles_20261024_211455.txt |
| 2026-10-24 21:15 | 614a | - | - | ? | results/phase17_new_vectors/614a_child_libkernel_call_20261024_211546.txt |
| 2026-10-24 21:17 | 614a | - | - | ? | results/phase17_new_vectors/614a_child_libkernel_call_20261024_211726.txt |
| 2026-10-24 21:17 | 615a | - | - | ? | results/phase17_new_vectors/615a_regions_debug_20261024_211741.txt |
| 2026-10-24 21:17 | 615b | - | - | ? | results/phase17_new_vectors/615b_region_names_20261024_211756.txt |
| 2026-10-24 21:18 | 614a | - | - | ? | results/phase17_new_vectors/614a_child_libkernel_call_20261024_211826.txt |
| 2026-10-24 21:19 | 616a | - | - | ? | results/phase17_new_vectors/616a_child_libkernel_call_20261024_211915.txt |
| 2026-10-24 21:19 | 617a | - | - | ? | results/phase17_new_vectors/617a_pltscan_20261024_211939.txt |
| 2026-10-24 21:21 | 616a | - | - | ? | results/phase17_new_vectors/616a_child_libkernel_call_20261024_212150.txt |
| 2026-10-24 21:21 | 618a | - | - | ? | results/phase17_new_vectors/618a_libc_head_20261024_212122.txt |
| 2026-10-24 21:21 | 618a | - | - | ? | results/phase17_new_vectors/618a_libc_head_20261024_212133.txt |
| 2026-10-24 21:22 | 619a | - | - | ? | results/phase17_new_vectors/619a_child_marker_20261024_212223.txt |
| 2026-10-24 21:22 | 619a | - | - | ? | results/phase17_new_vectors/619a_child_marker_20261024_212255.txt |
| 2026-10-24 21:24 | 616a | - | - | ? | results/phase17_new_vectors/616a_child_libkernel_call_20261024_212423.txt |
| 2026-10-24 21:25 | 620a | - | - | ? | results/phase17_new_vectors/620a_libkernel_stub_main_20261024_212500.txt |
| 2026-10-24 21:25 | 621a | - | - | ? | results/phase17_new_vectors/621a_fcall_stub_20261024_212525.txt |
| 2026-10-24 21:26 | 622a | - | - | ? | results/phase17_new_vectors/622a_syscall_gadget_scan_20261024_212646.txt |
| 2026-10-24 21:27 | 615a | - | - | ? | results/phase17_new_vectors/615a_regions_debug_20261024_212728.txt |
| 2026-10-24 21:27 | 623a | - | - | ? | results/phase17_new_vectors/623a_syscall_context_20261024_212719.txt |
| 2026-10-24 21:27 | 624a | - | - | ? | results/phase17_new_vectors/624a_prot5_diag_20261024_212746.txt |
| 2026-10-24 21:28 | 625a | - | - | ? | results/phase17_new_vectors/625a_two_thread_syscalls_20261024_212854.txt |
| 2026-10-24 21:29 | 625a | - | - | ? | results/phase17_new_vectors/625a_two_thread_syscalls_20261024_212910.txt |
| 2026-10-24 21:31 | 626a | - | - | ? | results/phase17_new_vectors/626a_kqueue_close_race_20261024_213153.txt |
| 2026-10-24 21:32 | 627a | - | - | ? | results/phase17_new_vectors/627a_mdbg_read_shapes_20261024_213235.txt |
| 2026-10-24 21:33 | 628a | - | - | ? | results/phase17_new_vectors/628a_signal_globals_20261024_213314.txt |
| 2026-10-24 21:33 | 629a | - | - | ? | results/phase17_new_vectors/629a_loader_tables_20261024_213328.txt |
| 2026-10-24 21:33 | 630a | - | - | ? | results/phase17_new_vectors/630a_kernel_read_api_20261024_213357.txt |
| 2026-10-24 21:34 | 631a | - | - | ? | results/phase17_new_vectors/631a_loader_threads_20261024_213429.txt |
| 2026-10-24 21:34 | 631a | - | - | ? | results/phase17_new_vectors/631a_loader_threads_20261024_213437.txt |
| 2026-10-24 21:34 | 631a | - | - | ? | results/phase17_new_vectors/631a_loader_threads_20261024_213448.txt |
| 2026-10-24 21:35 | 632a | - | - | ? | results/phase17_new_vectors/632a_aio_race_threads_20261024_213552.txt |
| 2026-10-24 21:39 | 628a | - | - | ? | results/phase17_new_vectors/628a_signal_globals_20261024_213959.txt |
| 2026-10-24 21:40 | 632a | - | - | ? | results/phase17_new_vectors/632a_aio_race_threads_20261024_214004.txt |
| 2026-10-24 21:40 | 632a | - | - | ? | results/phase17_new_vectors/632a_aio_race_threads_20261024_214016.txt |
| 2026-10-24 21:41 | 633a | - | - | ? | results/phase17_new_vectors/633a_aio_race_barrier_20261024_214109.txt |
| 2026-10-24 21:42 | 633a | - | - | ? | results/phase17_new_vectors/633a_aio_race_barrier_20261024_214227.txt |
| 2026-10-24 21:43 | 634a | - | - | ? | results/phase17_new_vectors/634a_umtx_barrier_20261024_214354.txt |
| 2026-10-24 21:43 | 634a | - | - | ? | results/phase17_new_vectors/634a_umtx_barrier_20261024_214358.txt |
| 2026-10-24 21:44 | 628a | - | - | ? | results/phase17_new_vectors/628a_signal_globals_20261024_214458.txt |
| 2026-10-24 21:44 | 633b | - | - | ? | results/phase17_new_vectors/633b_aio_race_barrier2_20261024_214420.txt |
| 2026-10-24 21:45 | 633c | - | - | ? | results/phase17_new_vectors/633c_aio_race_barrier3_20261024_214506.txt |
| 2026-10-24 21:45 | 635a | - | - | ? | results/phase17_new_vectors/635a_aio_race_health_20261024_214536.txt |
| 2026-10-24 21:47 | 633d | - | - | ? | results/phase17_new_vectors/633d_aio_race32_20261024_214712.txt |
| 2026-10-24 21:49 | 628a | - | - | ? | results/phase17_new_vectors/628a_signal_globals_20261024_214919.txt |
| 2026-10-24 21:49 | 633f | - | - | ? | results/phase17_new_vectors/633f_k0_20261024_214917.txt |
| 2026-10-24 21:49 | 633f | - | - | ? | results/phase17_new_vectors/633f_k1_20261024_214918.txt |
| 2026-10-24 21:49 | 633f | - | - | ? | results/phase17_new_vectors/633f_k2_20261024_214919.txt |
| 2026-10-24 21:49 | 636a | - | - | ? | results/phase17_new_vectors/636a_aio_delete_semantics_20261024_214950.txt |
| 2026-10-24 21:50 | 636a | - | - | ? | results/phase17_new_vectors/636a_aio_delete_semantics_20261024_215001.txt |
| 2026-10-24 21:50 | 639a | - | - | ? | results/phase17_new_vectors/639a_aio_health_baseline_20261024_215030.txt |
| 2026-10-24 21:51 | 639a | - | - | ? | results/phase17_new_vectors/639a_aio_health_baseline_20261024_215111.txt |
| 2026-10-24 21:51 | 639a | - | - | ? | results/phase17_new_vectors/639a_aio_health_baseline_20261024_215123.txt |
| 2026-10-24 21:51 | 640a | - | - | ? | results/phase17_new_vectors/640a_aio_race_four_20261024_215157.txt |
| 2026-10-24 21:52 | 641a | - | - | ? | results/phase17_new_vectors/641a_aio_race_lastitem_20261024_215235.txt |
| 2026-10-24 21:53 | 642a | - | - | ? | results/phase17_new_vectors/642a_aio_race_count1_20261024_215308.txt |
| 2026-10-24 21:53 | 642a | - | - | ? | results/phase17_new_vectors/642a_aio_race_count1_20261024_215316.txt |
| 2026-10-24 21:54 | 639a | - | - | ? | results/phase17_new_vectors/639a_aio_health_baseline_20261024_215422.txt |
| 2026-10-24 21:55 | 643a | - | - | ? | results/phase17_new_vectors/643a_aio_delete_vs_create_20261024_215501.txt |
| 2026-10-24 21:55 | 644a | - | - | ? | results/phase17_new_vectors/644a_aio_parent_create_vs_child_delete_20261024_215520.txt |
| 2026-10-24 21:55 | 645a | - | - | ? | results/phase17_new_vectors/645a_aio_wait_vs_delete_20261024_215554.txt |
| 2026-10-24 21:56 | 645a | - | - | ? | results/phase17_new_vectors/645a_aio_wait_vs_delete_20261024_215600.txt |
| 2026-10-24 21:56 | 646a | - | - | ? | results/phase17_new_vectors/646a_aio_wait_pending_20261024_215620.txt |
| 2026-10-24 21:56 | 647a | - | - | ? | results/phase17_new_vectors/647a_umtx_mutex_race_20261024_215650.txt |
| 2026-10-24 21:57 | 648a | - | - | ? | results/phase17_new_vectors/648a_umtx_pi_mutex_20261024_215734.txt |
| 2026-10-24 22:00 | 649a | - | - | ? | results/phase17_new_vectors/649a_umtx_pi_kill_waiter_20261024_220014.txt |
| 2026-10-24 22:02 | 650a | - | - | ? | results/phase17_new_vectors/650a_umtx_pi_kill_waiter2_20261024_220255.txt |
| 2026-10-24 22:09 | 651a | - | - | ? | results/phase17_new_vectors/651a_pi_waiter_kill_tid_20261024_220907.txt |
| 2026-10-24 22:12 | 654a | - | - | ? | results/phase17_new_vectors/654a_pi_signal_interrupt_20261024_221251.txt |
| 2026-10-24 22:13 | 654a | - | - | ? | results/phase17_new_vectors/654a_pi_signal_interrupt_20261024_221300.txt |
| 2026-10-24 22:13 | 654a | - | - | ? | results/phase17_new_vectors/654a_pi_signal_interrupt_20261024_221308.txt |
| 2026-10-24 22:13 | 654a | - | - | ? | results/phase17_new_vectors/654a_pi_signal_interrupt_20261024_221350.txt |
| 2026-10-24 22:16 | 655a | - | - | ? | results/phase17_new_vectors/655a_umtx_word_semantics_20261024_221612.txt |
| 2026-10-24 22:20 | 656a | - | - | ? | results/phase17_new_vectors/656a_zero_returners_dump_20261024_222023.txt |
| 2026-10-24 22:22 | 657a | - | - | ? | results/phase17_new_vectors/657a_thr_ucontext_20261024_222227.txt |
| 2026-10-24 22:25 | 658a | - | - | ? | results/phase17_new_vectors/658a_scm_rights_basic_20261024_222512.txt |
| 2026-10-24 22:27 | 659a | - | - | ? | results/phase17_new_vectors/659a_sendmsg_variants_20261024_222721.txt |
| 2026-10-24 22:28 | 660a | - | - | ? | results/phase17_new_vectors/660a_scm_rights_layout_20261024_222802.txt |
| 2026-10-24 22:28 | 661a | - | - | ? | results/phase17_new_vectors/661a_scm_peek_20261024_222828.txt |
| 2026-10-24 22:29 | 662a | - | - | ? | results/phase17_new_vectors/662a_fd_refcount_leak_20261024_222935.txt |
| 2026-10-24 22:32 | 523a | - | - | ? | results/phase23_cve_2026/523a_undecoded_syscalls_20261024_223218.txt |
| 2026-10-24 22:38 | 666a | - | - | ? | results/phase17_new_vectors/666a_aio_swap_storm_20261024_223813.txt |
| 2026-10-24 22:39 | 667a | - | - | ? | results/phase17_new_vectors/667a_aio_swap_storm2_20261024_223919.txt |
| 2026-10-24 22:39 | 667b | - | - | ? | results/phase17_new_vectors/667b_aioburst_control_20261024_223910.txt |
| 2026-10-24 22:40 | 668a | - | - | ? | results/phase17_new_vectors/668a_aio_race_burst_20261024_224012.txt |
| 2026-10-24 22:41 | 668b | - | - | ? | results/phase17_new_vectors/668b_burst_control32_20261024_224153.txt |
| 2026-10-24 22:43 | 669b | - | - | ? | results/phase17_new_vectors/669b_burst_shapes_20261024_224321.txt |
| 2026-10-24 22:47 | 671b | - | - | ? | results/phase17_new_vectors/671b_nonblock_burst_control_20261024_224758.txt |
| 2026-10-24 22:48 | 671a | - | - | ? | results/phase17_new_vectors/671a_aio_race_burst32_20261024_224803.txt |
| 2026-10-24 22:48 | 672a | - | - | ? | results/phase17_new_vectors/672a_aio_race_statuses_20261024_224815.txt |
| 2026-10-24 22:50 | 673a | - | - | ? | results/phase17_new_vectors/673a_aio_alias_detect_20261024_225040.txt |
| 2026-10-24 22:50 | 674a | - | - | ? | results/phase17_new_vectors/674a_aio_alias_detect2_20261024_225057.txt |
| 2026-10-24 22:53 | 675a | - | - | ? | results/phase17_new_vectors/675a_mdbg_ret0_dump_20261024_225357.txt |
| 2026-10-24 22:55 | 676a | - | - | ? | results/phase17_new_vectors/676a_mdbg_arg_layouts_20261024_225537.txt |
| 2026-10-24 22:57 | 677a | - | - | ? | results/phase17_new_vectors/677a_umtx_op_table_20261024_225744.txt |
| 2026-10-24 23:01 | 678a | - | - | ? | results/phase17_new_vectors/678a_umtx_op_table2_20261024_230103.txt |
| 2026-10-24 23:05 | 679a | - | - | ? | results/phase17_new_vectors/679a_umtx_ops_13_27_20261024_230531.txt |
| 2026-10-24 23:06 | 680a | - | - | ? | results/phase17_new_vectors/680a_dmem_map_prot_20261024_230658.txt |
| 2026-10-24 23:07 | 681a | - | - | ? | results/phase17_new_vectors/681a_dmem_regs_20261024_230758.txt |
| 2026-10-24 23:08 | 682a | - | - | ? | results/phase17_new_vectors/682a_aio_effect_oracle_20261024_230848.txt |
| 2026-10-24 23:08 | 682a | - | - | ? | results/phase17_new_vectors/682a_aio_effect_oracle_20261024_230859.txt |
| 2026-10-24 23:09 | 682a | - | - | ? | results/phase17_new_vectors/682a_aio_effect_oracle_20261024_230928.txt |
| 2026-10-24 23:09 | 683a | - | - | ? | results/phase17_new_vectors/683a_aio_race_churn_20261024_230953.txt |
| 2026-10-24 23:12 | 684a | - | - | ? | results/phase17_new_vectors/684a_dmem_writeback_20261024_231224.txt |
| 2026-10-24 23:12 | 685a | - | - | ? | results/phase17_new_vectors/685a_dmem_change_test_20261024_231240.txt |
| 2026-10-24 23:12 | 685a | - | - | ? | results/phase17_new_vectors/685a_dmem_change_test_20261024_231250.txt |
| 2026-10-24 23:13 | 686a | - | - | ? | results/phase17_new_vectors/686a_dmem_offsets_20261024_231305.txt |
| 2026-10-24 23:14 | 687a | - | - | ? | results/phase17_new_vectors/687a_sys670_shape_20261024_231449.txt |
| 2026-10-24 23:15 | 688a | - | - | ? | results/phase17_new_vectors/688a_dmem_gpu_va_20261024_231510.txt |
| 2026-10-24 23:16 | 689a | - | - | ? | results/phase17_new_vectors/689a_dmem_live_check_20261024_231653.txt |
| 2026-10-24 23:16 | 690a | - | - | ? | results/phase17_new_vectors/690a_dmem_persist_20261024_231653.txt |
| 2026-10-24 23:17 | 691a | - | - | ? | results/phase17_new_vectors/691a_dmem_large_window_20261024_231711.txt |
| 2026-10-24 23:17 | 692a | - | - | ? | results/phase17_new_vectors/692a_dmem_recon_20261024_231735.txt |
| 2026-10-24 23:18 | 693a | - | - | ? | results/phase17_new_vectors/693a_dmem_maps_sysmem_20261024_231803.txt |
| 2026-10-24 23:18 | 694a | - | - | ? | results/phase17_new_vectors/694a_dmem_region_name_20261024_231835.txt |
| 2026-10-24 23:18 | 695a | - | - | ? | results/phase17_new_vectors/695a_dmem_sysmem_probe_20261024_231853.txt |
| 2026-10-24 23:19 | 696a | - | - | ? | results/phase17_new_vectors/696a_dmem_dump_pages_20261024_231904.txt |
| 2026-10-24 23:19 | 697a | - | - | ? | results/phase17_new_vectors/697a_dmem_offset_model_20261024_231928.txt |
| 2026-10-24 23:20 | 698a | - | - | ? | results/phase17_new_vectors/698a_sys563_566_20261024_232013.txt |
| 2026-10-24 23:20 | 699a | - | - | ? | results/phase17_new_vectors/699a_sysctl_walk_20261024_232039.txt |
| 2026-10-24 23:22 | 700a | - | - | ? | results/phase17_new_vectors/700a_sysctl_read_20261024_232226.txt |
| 2026-10-24 23:23 | 701a | - | - | ? | results/phase17_new_vectors/701a_chicken_unlock_20261024_232326.txt |
| 2026-10-24 23:23 | 701a | - | - | ? | results/phase17_new_vectors/701a_chicken_unlock_20261024_232339.txt |
| 2026-10-24 23:23 | 701a | - | - | ? | results/phase17_new_vectors/701a_chicken_unlock_20261024_232347.txt |
| 2026-10-24 23:24 | 702a | - | - | ? | results/phase17_new_vectors/702a_sysctl_machdep_20261024_232421.txt |
| 2026-10-24 23:26 | 703a | - | - | ? | results/phase17_new_vectors/703a_dmem_sweep_20261024_232654.txt |
| 2026-10-24 23:27 | 704a | - | - | ? | results/phase17_new_vectors/704a_gc_mmio_20261024_232730.txt |
| 2026-10-24 23:27 | 705a | - | - | ? | results/phase17_new_vectors/705a_kinfo_kernel_threads_20261024_232751.txt |
| 2026-10-24 23:27 | ping | - | - | ? | results/ping_20261024_232707.txt |
| 2026-10-25 07:25 | 528a | - | - | ? | results/phase27_phys_memory/528a_map_direct_memory_20261025_072556.txt |
| 2026-10-25 07:25 | 529a | - | - | ? | results/phase27_phys_memory/529a_libkernel_wrapper_survey_20261025_072542.txt |
| 2026-10-25 07:26 | 527a | - | - | ? | results/phase23_cve_2026/527a_ghost_handle_refcount_20261025_072635.txt |
| 2026-10-25 07:31 | 528a | - | - | ? | results/phase27_phys_memory/528a_map_direct_memory_20261025_073147.txt |
| 2026-10-25 09:13 | 706a | - | - | ? | results/phase17_new_vectors/706a_sys619_slot_20261025_091322.txt |
| 2026-10-25 09:13 | 706a | - | - | ? | results/phase17_new_vectors/706a_sys619_slot_20261025_091336.txt |
| 2026-10-25 09:17 | 528c | - | - | ? | results/phase27_phys_memory/528c_map_srop_20261025_091721.txt |
| 2026-10-25 09:17 | 528c | - | - | ? | results/phase27_phys_memory/528c_map_srop_20261025_091758.txt |
| 2026-10-25 09:18 | 528c | - | - | ? | results/phase27_phys_memory/528c_map_srop_20261025_091851.txt |
| 2026-10-25 09:20 | 707a | - | - | ? | results/phase17_new_vectors/707a_aio_alias_after_race_20261025_092024.txt |
| 2026-10-25 09:20 | 707a | - | - | ? | results/phase17_new_vectors/707a_aio_alias_after_race_20261025_092034.txt |
| 2026-10-25 09:22 | 528d | - | - | ? | results/phase27_phys_memory/528d_child_srop_diag_20261025_092237.txt |
| 2026-10-25 09:23 | 528c | - | - | ? | results/phase27_phys_memory/528c_map_srop_20261025_092310.txt |
| 2026-10-25 09:23 | 708a | - | - | ? | results/phase17_new_vectors/708a_sys589_dlopen_20261025_092301.txt |
| 2026-10-25 09:26 | 528d | - | - | ? | results/phase27_phys_memory/528d_child_srop_diag_20261025_092612.txt |
| 2026-10-25 09:28 | 528e | - | - | ? | results/phase27_phys_memory/528e_srop_wrapper_diag_20261025_092826.txt |
| 2026-10-25 09:30 | 528f | - | - | ? | results/phase27_phys_memory/528f_mainthread_mapdm_20261025_093022.txt |
| 2026-10-25 09:31 | 528f | - | - | ? | results/phase27_phys_memory/528f_mainthread_mapdm_20261025_093141.txt |
| 2026-10-25 09:33 | 528f2 | - | - | ? | results/phase27_phys_memory/528f2_mainthread_mapdm_20261025_093306.txt |
| 2026-10-25 09:34 | 528g | - | - | ? | results/phase27_phys_memory/528g_mapdm_inline_epi_20261025_093452.txt |
| 2026-10-25 09:37 | 528g | - | - | ? | results/phase27_phys_memory/528g_mapdm_inline_epi_20261025_093716.txt |
| 2026-10-25 09:37 | 528g | - | - | ? | results/phase27_phys_memory/528g_mapdm_inline_epi_20261025_093747.txt |
| 2026-10-25 09:39 | 528h | - | - | ? | results/phase27_phys_memory/528h_mapdm_debug_20261025_093940.txt |
| 2026-10-25 09:39 | 708b | - | - | ? | results/phase17_new_vectors/708b_broad_shield_20261025_093920.txt |
| 2026-10-25 09:39 | 709a | - | - | ? | results/phase17_new_vectors/709a_wide_queries_20261025_093905.txt |
| 2026-10-25 09:42 | 528i | - | - | ? | results/phase27_phys_memory/528i_raw_map_syscalls_20261025_094222.txt |
| 2026-10-25 09:43 | 710a | - | - | ? | results/phase17_new_vectors/710a_shield_verify_20261025_094335.txt |
| 2026-10-25 09:43 | 711a | - | - | ? | results/phase17_new_vectors/711a_lethal_under_shield_20261025_094352.txt |
| 2026-10-25 09:44 | 528j | - | - | ? | results/phase27_phys_memory/528j_raw_map_errno_20261025_094403.txt |
| 2026-10-25 09:44 | 711b | - | - | ? | results/phase17_new_vectors/711b_full_presence_20261025_094438.txt |
| 2026-10-25 09:45 | 528k | - | - | ? | results/phase27_phys_memory/528k_map_errno_capture_20261025_094531.txt |
| 2026-10-25 09:46 | 528l | - | - | ? | results/phase27_phys_memory/528l_mmap_dmem_verify_20261025_094634.txt |
| 2026-10-25 09:47 | 528m | - | - | ? | results/phase27_phys_memory/528m_phys_kernel_scan_20261025_094732.txt |
| 2026-10-25 09:47 | 712a | - | - | ? | results/phase17_new_vectors/712a_native_syscall_child_20261025_094752.txt |
| 2026-10-25 09:49 | 528n | - | - | ? | results/phase27_phys_memory/528n_phys_wide_scan_20261025_094900.txt |
| 2026-10-25 09:49 | 712b | - | - | ? | results/phase17_new_vectors/712b_fcall_stub_contents_20261025_094949.txt |
| 2026-10-25 09:51 | 712c | - | - | ? | results/phase17_new_vectors/712c_child_on_fn_addr_20261025_095117.txt |
| 2026-10-25 09:54 | 712c | - | - | ? | results/phase17_new_vectors/712c_child_on_fn_addr_20261025_095448.txt |
| 2026-10-25 09:55 | 712c | - | - | ? | results/phase17_new_vectors/712c_child_on_fn_addr_20261025_095514.txt |
| 2026-10-25 09:55 | 712c | - | - | ? | results/phase17_new_vectors/712c_child_on_fn_addr_20261025_095529.txt |
| 2026-10-25 09:55 | 712c | - | - | ? | results/phase17_new_vectors/712c_child_on_fn_addr_20261025_095537.txt |
| 2026-10-25 09:56 | 713a | - | - | ? | results/phase17_new_vectors/713a_native_aio_race_20261025_095627.txt |
| 2026-10-25 09:57 | 714b | - | - | ? | results/phase17_new_vectors/714b_gadget_list_20261025_095753.txt |
| 2026-10-25 09:58 | 714a | - | - | ? | results/phase17_new_vectors/714a_native_delete_hammer_20261025_095852.txt |
| 2026-10-25 09:59 | 715a | - | - | ? | results/phase17_new_vectors/715a_aio_alias_matrix_20261025_095938.txt |
| 2026-10-25 10:00 | 716a | - | - | ? | results/phase17_new_vectors/716a_poll_state_control_20261025_100038.txt |
| 2026-10-25 10:02 | 717a | - | - | ? | results/phase17_new_vectors/717a_aio_long_hammer_20261025_100226.txt |
| 2026-10-25 10:04 | 718a | - | - | ? | results/phase17_new_vectors/718a_aio_timed_pair_20261025_100449.txt |
| 2026-10-25 10:06 | 718a | - | - | ? | results/phase17_new_vectors/718a_aio_timed_pair_20261025_100607.txt |
| 2026-10-25 10:07 | 712c | - | - | ? | results/phase17_new_vectors/712c_child_on_fn_addr_20261025_100726.txt |
| 2026-10-25 10:07 | 719a | - | - | ? | results/phase17_new_vectors/719a_aio_umtx_gate_20261025_100720.txt |
| 2026-10-25 10:07 | 719b | - | - | ? | results/phase17_new_vectors/719b_umtx_child_gate_test_20261025_100751.txt |
| 2026-10-25 10:08 | 719a | - | - | ? | results/phase17_new_vectors/719a_aio_umtx_gate_20261025_100828.txt |
| 2026-10-25 10:09 | 719a | - | - | ? | results/phase17_new_vectors/719a_aio_umtx_gate_20261025_100908.txt |
| 2026-10-25 10:10 | 720a | - | - | ? | results/phase17_new_vectors/720a_aio_race_allocator_20261025_101020.txt |
| 2026-10-25 10:11 | 720a | - | - | ? | results/phase17_new_vectors/720a_aio_race_allocator_20261025_101155.txt |
| 2026-10-25 10:14 | 721a | - | - | ? | results/phase17_new_vectors/721a_poll_vs_delete_20261025_101403.txt |
| 2026-10-25 10:17 | 722a | - | - | ? | results/phase17_new_vectors/722a_aio_wide_window_20261025_101719.txt |
| 2026-10-25 10:18 | 723a | - | - | ? | results/phase17_new_vectors/723a_aio_alias_after_race_20261025_101857.txt |
| 2026-10-25 10:19 | 724a | - | - | ? | results/phase17_new_vectors/724a_cpl_probe_scan_20261025_101945.txt |
| 2026-10-25 10:20 | 724b | - | - | ? | results/phase17_new_vectors/724b_priv_gadget_scan_20261025_102014.txt |
| 2026-10-25 10:21 | 724c | - | - | ? | results/phase17_new_vectors/724c_seg_readback_scan_20261025_102100.txt |
| 2026-10-25 10:21 | 724d | - | - | ? | results/phase17_new_vectors/724d_exact_gadgets_20261025_102128.txt |
| 2026-10-25 10:22 | 725a | - | - | ? | results/phase17_new_vectors/725a_cpl_in_test_20261025_102201.txt |
| 2026-10-25 10:22 | 726a | - | - | ? | results/phase17_new_vectors/726a_cpl_control_20261025_102227.txt |
| 2026-10-25 10:30 | 727b | - | - | ? | results/phase17_new_vectors/727b_aio_block_serial_control_20261025_103003.txt |
| 2026-10-25 10:30 | 727c | - | - | ? | results/phase17_new_vectors/727c_aio_block_2child_race_20261025_103022.txt |
| 2026-10-25 10:31 | 727d | - | - | ? | results/phase17_new_vectors/727d_aio_block_disjoint_20261025_103156.txt |
| 2026-10-25 10:32 | 727a | - | - | ? | results/phase17_new_vectors/727a_aio_block_pathB_race_20261025_103243.txt |
| 2026-10-25 10:32 | 727c | - | - | ? | results/phase17_new_vectors/727c_aio_block_2child_race_20261025_103202.txt |
| 2026-10-25 10:36 | 728a | - | - | ? | results/phase17_new_vectors/728a_aio_pathB_alias_20261025_103635.txt |
| 2026-10-25 10:37 | 728a | - | - | ? | results/phase17_new_vectors/728a_aio_pathB_alias_20261025_103708.txt |
| 2026-10-25 10:41 | 729a | - | - | ? | results/phase17_new_vectors/729a_child_syscall_probe_20261025_104128.txt |
| 2026-10-25 10:42 | 729b | - | - | ? | results/phase17_new_vectors/729b_chain_compare_20261025_104235.txt |
| 2026-10-25 10:44 | 729b | - | - | ? | results/phase17_new_vectors/729b_chain_compare_20261025_104410.txt |
| 2026-10-25 10:48 | 730a | - | - | ? | results/phase17_new_vectors/730a_child_561_20261025_104851.txt |
| 2026-10-25 10:58 | 731a | - | - | ? | results/phase17_new_vectors/731a_aio_wait_delete_uaf_20261025_105801.txt |
| 2026-10-25 11:01 | 733a | - | - | ? | results/phase17_new_vectors/733a_sendmsg_pointer_leak_20261025_110120.txt |
| 2026-10-25 11:06 | 734a | - | - | ? | results/phase17_new_vectors/734a_sendmsg_isolation_20261025_110644.txt |
| 2026-10-25 11:07 | 735a | - | - | ? | results/phase17_new_vectors/735a_alloc_bisect_20261025_110746.txt |
| 2026-10-25 11:08 | 736a | - | - | ? | results/phase17_new_vectors/736a_sys28_zeros_20261025_110828.txt |
| 2026-10-25 11:08 | 737a | - | - | ? | results/phase17_new_vectors/737a_recvmsg_valid_20261025_110858.txt |
| 2026-10-25 11:09 | 738a | - | - | ? | results/phase17_new_vectors/738a_stmt_bisect_20261025_110943.txt |
| 2026-10-25 11:10 | 739a | - | - | ? | results/phase17_new_vectors/739a_shield_scope_20261025_111018.txt |
| 2026-10-25 11:11 | 740a | - | - | ? | results/phase17_new_vectors/740a_mmap_under_shield_20261025_111106.txt |
| 2026-10-25 11:11 | 741a | - | - | ? | results/phase17_new_vectors/741a_sendmsg_mmap_20261025_111125.txt |
| 2026-10-25 11:12 | 742a | - | - | ? | results/phase17_new_vectors/742a_sockaddr_control_20261025_111200.txt |
| 2026-10-25 11:12 | 743a | - | - | ? | results/phase17_new_vectors/743a_aio_delete_pending_20261025_111240.txt |
| 2026-10-25 11:14 | 744a | - | - | ? | results/phase17_new_vectors/744a_aio_descriptor_ptrs_20261025_111410.txt |
| 2026-10-25 11:20 | 744b | - | - | ? | results/phase17_new_vectors/744b_aio_ptr_validation_20261025_112008.txt |
| 2026-10-25 11:21 | 745a | - | - | ? | results/phase17_new_vectors/745a_aio_res_kernel_va_20261025_112127.txt |
| 2026-10-25 11:21 | 746a | - | - | ? | results/phase17_new_vectors/746a_sys667_20261025_112159.txt |
| 2026-10-25 11:23 | 747a | - | - | ? | results/phase17_new_vectors/747a_aio_file_and_op_20261025_112339.txt |
| 2026-10-25 11:25 | 748a | - | - | ? | results/phase17_new_vectors/748a_aio_file_op_matrix_20261025_112549.txt |
| 2026-10-25 11:28 | 752a | - | - | ? | results/phase17_new_vectors/752a_aio_socket_op_kernel_src_20261025_112848.txt |
| 2026-10-25 11:29 | 753a | - | - | ? | results/phase17_new_vectors/753a_aio_mode_direction_20261025_112919.txt |
| 2026-10-25 11:30 | 750a | - | - | ? | results/phase17_new_vectors/750a_aio_kernel_buffer_20261025_113000.txt |
| 2026-10-25 11:30 | 754a | - | - | ? | results/phase17_new_vectors/754a_aio_timing_kernel_buf_20261025_113037.txt |
| 2026-10-25 11:32 | 528s | - | - | ? | results/phase27_phys_memory/528s_ultralight_scan_20261025_113216.txt |
| 2026-10-25 11:33 | 528t | - | - | ? | results/phase27_phys_memory/528t_dmem_range_test_20261025_113323.txt |
| 2026-10-25 11:34 | 528u | - | - | ? | results/phase27_phys_memory/528u_gc_mmap_scan_20261025_113421.txt |
| 2026-10-25 11:35 | 528v | - | - | ? | results/phase27_phys_memory/528v_dmem0_header_deep_20261025_113513.txt |
| 2026-10-25 11:35 | 755a | - | - | ? | results/phase17_new_vectors/755a_aio_first_kernel_buf_20261025_113510.txt |
| 2026-10-25 11:36 | 756a | - | - | ? | results/phase17_new_vectors/756a_aio_buf_addr_matrix_20261025_113600.txt |
| 2026-10-25 11:38 | 757a | - | - | ? | results/phase17_new_vectors/757a_spin_gadget_scan_20261025_113807.txt |
| 2026-10-25 11:40 | 757b | - | - | ? | results/phase17_new_vectors/757b_spin_scan_chunked_20261025_114041.txt |
| 2026-10-25 11:41 | 758a | - | - | ? | results/phase17_new_vectors/758a_read_wake_children_20261025_114140.txt |
| 2026-10-25 11:42 | 759a | - | - | ? | results/phase17_new_vectors/759a_aio_race_wake_release_20261025_114228.txt |
| 2026-10-25 11:43 | 760a | - | - | ? | results/phase17_new_vectors/760a_aio_race_polled_20261025_114325.txt |
| 2026-10-25 11:44 | 761a | - | - | ? | results/phase17_new_vectors/761a_aio_distinct_id_race_20261025_114421.txt |
| 2026-10-25 11:45 | 762a | - | - | ? | results/phase17_new_vectors/762a_dynlib_copyout_leak_20261025_114511.txt |
| 2026-10-25 11:45 | 762b | - | - | ? | results/phase17_new_vectors/762b_sys608_struct_dump_20261025_114531.txt |
| 2026-10-25 11:45 | 762b | - | - | ? | results/phase17_new_vectors/762b_sys608_struct_dump_20261025_114536.txt |
| 2026-10-25 11:46 | 763a | - | - | ? | results/phase17_new_vectors/763a_mdbg_valid_pointers_20261025_114641.txt |
| 2026-10-25 11:48 | 760b | - | - | ? | results/phase17_new_vectors/760b_aio_race_eight_20261025_114828.txt |
| 2026-10-25 11:52 | 764a | - | - | ? | results/phase17_new_vectors/764a_aio_pathA_race_20261025_115216.txt |
| 2026-10-25 11:55 | 528w | - | - | ? | results/phase27_phys_memory/528w_gpu_cmdbuf_decode_20261025_115528.txt |
| 2026-10-25 11:55 | 765a | - | - | ? | results/phase17_new_vectors/765a_aio_pathA_contended_20261025_115544.txt |
| 2026-10-25 11:56 | 766a | - | - | ? | results/phase17_new_vectors/766a_aio_cancel_effect_20261025_115613.txt |
| 2026-10-25 11:57 | 528y | - | - | ? | results/phase27_phys_memory/528y_gc_ioctl_sweep_20261025_115747.txt |
| 2026-10-25 11:57 | 767a | - | - | ? | results/phase17_new_vectors/767a_iopl_context_20261025_115719.txt |
| 2026-10-25 11:58 | 528z | - | - | ? | results/phase27_phys_memory/528z_gnm_submit_hunt_20261025_115843.txt |
| 2026-10-25 12:01 | 767b | - | - | ? | results/phase17_new_vectors/767b_iopl_ctx_20261025_120146.txt |
| 2026-10-25 12:02 | 768a | - | - | ? | results/phase17_new_vectors/768a_flag_gadget_scan_20261025_120241.txt |
| 2026-10-25 12:03 | 530a | - | - | ? | results/phase27_phys_memory/530a_gpu_submit_test_20261025_120323.txt |
| 2026-10-25 12:03 | 530a | - | - | ? | results/phase27_phys_memory/530a_gpu_submit_test_20261025_120353.txt |
| 2026-10-25 12:03 | 769a | - | - | ? | results/phase17_new_vectors/769a_ctx_rflags_probe_20261025_120335.txt |
| 2026-10-25 12:04 | 769a | - | - | ? | results/phase17_new_vectors/769a_ctx_rflags_probe_20261025_120418.txt |
| 2026-10-25 12:04 | 769b | - | - | ? | results/phase17_new_vectors/769b_ctx_iopl_probe_20261025_120429.txt |
| 2026-10-25 12:05 | 530b | - | - | ? | results/phase27_phys_memory/530b_gpu_submit_debug_20261025_120527.txt |
| 2026-10-25 12:05 | 770a | - | - | ? | results/phase17_new_vectors/770a_popfq_iret_iopl_20261025_120501.txt |
| 2026-10-25 12:06 | 530c | - | - | ? | results/phase27_phys_memory/530c_gnm_submit_direct_20261025_120633.txt |
| 2026-10-25 12:07 | 530d | - | - | ? | results/phase27_phys_memory/530d_eboot_gnm_got_20261025_120718.txt |
| 2026-10-25 12:07 | 770b | - | - | ? | results/phase17_new_vectors/770b_iret_control_20261025_120732.txt |
| 2026-10-25 12:08 | 530e | - | - | ? | results/phase27_phys_memory/530e_gpu_ring_vmmap_20261025_120814.txt |
| 2026-10-25 12:08 | 771a | - | - | ? | results/phase17_new_vectors/771a_kqueue_signal_basic_20261025_120807.txt |
| 2026-10-25 12:09 | 530f | - | - | ? | results/phase27_phys_memory/530f_gnm_nid_call_20261025_120917.txt |
| 2026-10-25 12:09 | 771b | - | - | ? | results/phase17_new_vectors/771b_signal_knote_churn_20261025_120901.txt |
| 2026-10-25 12:10 | 530g | - | - | ? | results/phase27_phys_memory/530g_gnm_safe_call_20261025_121006.txt |
| 2026-10-25 12:11 | 773a | - | - | ? | results/phase17_new_vectors/773a_signal_knote_native_race_20261025_121108.txt |
| 2026-10-25 12:12 | 774a | - | - | ? | results/phase17_new_vectors/774a_timer_knote_churn_20261025_121229.txt |
| 2026-10-25 12:13 | 530h | - | - | ? | results/phase27_phys_memory/530h_ring_inject_20261025_121340.txt |
| 2026-10-25 12:13 | 775a | - | - | ? | results/phase17_new_vectors/775a_aio_close_inflight_20261025_121339.txt |
| 2026-10-25 12:13 | 775a | - | - | ? | results/phase17_new_vectors/775a_aio_close_inflight_20261025_121349.txt |
| 2026-10-25 12:13 | 775a | - | - | ? | results/phase17_new_vectors/775a_aio_close_inflight_20261025_121359.txt |
| 2026-10-25 12:14 | 530i | - | - | ? | results/phase27_phys_memory/530i_eboot_submit_hunt_20261025_121451.txt |
| 2026-10-25 12:15 | 777a | - | - | ? | results/phase17_new_vectors/777a_aio_unwedge_20261025_121523.txt |
| 2026-10-25 12:15 | 777b | - | - | ? | results/phase17_new_vectors/777b_aio_cancel_then_delete_20261025_121533.txt |
| 2026-10-25 12:16 | 530j | - | - | ? | results/phase27_phys_memory/530j_got_hunt_20261025_121604.txt |
| 2026-10-25 12:16 | 530k | - | - | ? | results/phase27_phys_memory/530k_got_clean_20261025_121659.txt |
| 2026-10-25 12:17 | 530l | - | - | ? | results/phase27_phys_memory/530l_minimal_got_20261025_121746.txt |
| 2026-10-25 12:18 | 530m | - | - | ? | results/phase27_phys_memory/530m_fast_got_20261025_121829.txt |
| 2026-10-25 12:19 | 530n | - | - | ? | results/phase27_phys_memory/530n_debug_output_20261025_121903.txt |
| 2026-10-25 12:20 | 530o | - | - | ? | results/phase27_phys_memory/530o_gc_info_ioctls_20261025_122039.txt |
| 2026-10-25 12:21 | 530p | - | - | ? | results/phase27_phys_memory/530p_ioctl_deep_20261025_122130.txt |
| 2026-10-25 12:22 | 530q | - | - | ? | results/phase27_phys_memory/530q_ioctl_probe_20261025_122255.txt |
| 2026-10-25 12:24 | 775a | - | - | ? | results/phase17_new_vectors/775a_aio_close_inflight_20261025_122410.txt |
| 2026-10-25 12:24 | 776a | - | - | ? | results/phase17_new_vectors/776a_aio_cancel_inflight_20261025_122415.txt |
| 2026-10-25 12:24 | 778a | - | - | ? | results/phase17_new_vectors/778a_device_enum_20261025_122452.txt |
| 2026-10-25 12:25 | 778a | - | - | ? | results/phase17_new_vectors/778a_device_enum_20261025_122537.txt |
| 2026-10-25 12:31 | 531a | - | - | ? | results/phase27_phys_memory/531a_mapdm_rop_20261025_123134.txt |
| 2026-10-25 12:31 | 778b | - | - | ? | results/phase17_new_vectors/778b_device_open_20261025_123159.txt |
| 2026-10-25 12:32 | 531b | - | - | ? | results/phase27_phys_memory/531b_mapdm_read_20261025_123226.txt |
| 2026-10-25 12:32 | 779a | - | - | ? | results/phase17_new_vectors/779a_sony_low_sweep_20261025_123206.txt |
| 2026-10-25 12:33 | 531c | - | - | ? | results/phase27_phys_memory/531c_mapdm_hint_20261025_123318.txt |
| 2026-10-25 12:34 | 531d | - | - | ? | results/phase27_phys_memory/531d_mapdm_minimal_20261025_123401.txt |
| 2026-10-25 12:34 | 531e | - | - | ? | results/phase27_phys_memory/531e_raw_map_20261025_123456.txt |
| 2026-10-25 12:34 | 780a | - | - | ? | results/phase17_new_vectors/780a_sys557_object_20261025_123423.txt |
| 2026-10-25 12:34 | 781a | - | - | ? | results/phase17_new_vectors/781a_sys557_relation_20261025_123453.txt |
| 2026-10-25 12:35 | 531f | - | - | ? | results/phase27_phys_memory/531f_phys_scan_20261025_123544.txt |
| 2026-10-25 12:37 | 531g | - | - | ? | results/phase27_phys_memory/531g_rop_mapdm_20261025_123731.txt |
| 2026-10-25 12:37 | 782a | - | - | ? | results/phase17_new_vectors/782a_sys557_558_pair_20261025_123709.txt |
| 2026-10-25 12:37 | 782a | - | - | ? | results/phase17_new_vectors/782a_sys557_558_pair_20261025_123727.txt |
| 2026-10-25 12:38 | 783a | - | - | ? | results/phase17_new_vectors/783a_sys558_destroy_20261025_123800.txt |
| 2026-10-25 12:39 | 531i | - | - | ? | results/phase27_phys_memory/531i_gadget_lite_20261025_123930.txt |
| 2026-10-25 12:40 | 531j | - | - | ? | results/phase27_phys_memory/531j_find_syscall_20261025_124039.txt |
| 2026-10-25 12:45 | 531k | - | - | ? | results/phase27_phys_memory/531k_srop_mapdm_20261025_124506.txt |
| 2026-10-25 12:45 | 784a | - | - | ? | results/phase17_new_vectors/784a_sys557_payload_20261025_124555.txt |
| 2026-10-25 12:46 | 785a | - | - | ? | results/phase17_new_vectors/785a_sys558_double_20261025_124605.txt |
| 2026-10-25 12:46 | 786a | - | - | ? | results/phase17_new_vectors/786a_sys557_capacity_20261025_124623.txt |
| 2026-10-25 12:47 | 531l | - | - | ? | results/phase27_phys_memory/531l_tcb_mapdm_20261025_124711.txt |
| 2026-10-25 12:47 | 787a | - | - | ? | results/phase17_new_vectors/787a_sys557_payload_fields_20261025_124723.txt |
| 2026-10-25 12:47 | 787b | - | - | ? | results/phase17_new_vectors/787b_sys557_page_check_20261025_124736.txt |
| 2026-10-25 12:47 | 788a | - | - | ? | results/phase17_new_vectors/788a_sys557_payload_writeback_20261025_124748.txt |
| 2026-10-25 12:48 | 789a | - | - | ? | results/phase17_new_vectors/789a_sys557_free_running_job_20261025_124802.txt |
| 2026-10-25 12:48 | 790a | - | - | ? | results/phase17_new_vectors/790a_sys558_double_destroy_20261025_124859.txt |
| 2026-10-25 12:49 | 791a | - | - | ? | results/phase17_new_vectors/791a_sys557_flags_20261025_124939.txt |
| 2026-10-25 12:49 | 792a | - | - | ? | results/phase17_new_vectors/792a_aio_op_matrix_20261025_124953.txt |
| 2026-10-25 12:50 | 531m | - | - | ? | results/phase27_phys_memory/531m_thr_test_20261025_125031.txt |
| 2026-10-25 12:51 | 531n | - | - | ? | results/phase27_phys_memory/531n_thr_diag_20261025_125138.txt |
| 2026-10-25 12:52 | 531o | - | - | ? | results/phase27_phys_memory/531o_thr_heap_20261025_125214.txt |
| 2026-10-25 12:54 | 531p | - | - | ? | results/phase27_phys_memory/531p_thr_nosig_20261025_125402.txt |
| 2026-10-25 12:54 | 531q | - | - | ? | results/phase27_phys_memory/531q_sig_test_20261025_125439.txt |
| 2026-10-25 12:54 | 793a | - | - | ? | results/phase17_new_vectors/793a_sys557_stale_id_20261025_125435.txt |
| 2026-10-25 12:54 | 793a | - | - | ? | results/phase17_new_vectors/793a_sys557_stale_id_20261025_125443.txt |
| 2026-10-25 12:54 | 793a | - | - | ? | results/phase17_new_vectors/793a_sys557_stale_id_20261025_125454.txt |
| 2026-10-25 12:54 | 793a | - | - | ? | results/phase17_new_vectors/793a_sys557_stale_id_20261025_125459.txt |
| 2026-10-25 12:56 | 531r | - | - | ? | results/phase27_phys_memory/531r_rop_mapdm_20261025_125607.txt |
| 2026-10-25 13:03 | 531u | - | - | ? | results/phase27_phys_memory/531u_incremental_20261025_130355.txt |
| 2026-10-25 13:04 | 531v | - | - | ? | results/phase27_phys_memory/531v_chain_s1_20261025_130441.txt |
| 2026-10-25 13:05 | 531w | - | - | ? | results/phase27_phys_memory/531w_chain_s2_20261025_130511.txt |
| 2026-10-25 13:06 | 531x | - | - | ? | results/phase27_phys_memory/531x_mapdm_full_20261025_130611.txt |
| 2026-10-25 13:11 | 531z | - | - | ? | results/phase27_phys_memory/531z_mapdm_fixed_20261025_131102.txt |
| 2026-10-25 14:25 | 778a | - | - | ? | results/phase17_new_vectors/778a_relapse_preconditions_20261025_142516.txt |
| 2026-10-25 14:30 | 778b | - | - | ? | results/phase17_new_vectors/778b_multiwait_timeout_20261025_143050.txt |
| 2026-10-25 14:32 | 779a | - | - | ? | results/phase17_new_vectors/779a_multiwait_completed_20261025_143223.txt |
| 2026-10-25 14:32 | 780a | - | - | ? | results/phase17_new_vectors/780a_multiwait_shapes_20261025_143247.txt |
| 2026-10-25 14:35 | 781a | - | - | ? | results/phase17_new_vectors/781a_single_wait_cycle_20261025_143533.txt |
| 2026-10-25 14:38 | 782a | - | - | ? | results/phase17_new_vectors/782a_waiter_reclaim_20261025_143850.txt |
| 2026-10-25 15:37 | 784a | - | - | ? | results/phase17_new_vectors/784a_aio_buffer_ptr_20261025_153719.txt |
| 2026-10-25 15:38 | 785a | - | - | ? | results/phase17_new_vectors/785a_signal_watchdog_20261025_153802.txt |
| 2026-10-25 15:38 | 786a | - | - | ? | results/phase17_new_vectors/786a_real_handler_watchdog_20261025_153828.txt |
| 2026-10-25 15:39 | 786b | - | - | ? | results/phase17_new_vectors/786b_real_handler_watchdog_20261025_153912.txt |
| 2026-10-25 15:39 | 786b | - | - | ? | results/phase17_new_vectors/786b_real_handler_watchdog_20261025_153926.txt |
| 2026-10-25 15:39 | 787a | - | - | ? | results/phase17_new_vectors/787a_watchdog_blocking_wait_20261025_153952.txt |
| 2026-10-25 15:40 | 788a | - | - | ? | results/phase17_new_vectors/788a_interrupted_wait_aftermath_20261025_154053.txt |
| 2026-10-25 15:45 | 70a | - | - | ? | results/phase16_kwrite/70a_generation_wraparound_20261025_154511.txt |
| 2026-10-25 15:47 | 69a | - | - | ? | results/phase16_kwrite/69a_aio_overlap_hexdump_20261025_154737.txt |
| 2026-10-25 15:48 | 69d | - | - | ? | results/phase16_kwrite/69d_r_reclaim_kaslr_20261025_154808.txt |
| 2026-10-25 15:56 | 790a | - | - | ? | results/phase17_new_vectors/790a_helper_completion_20261025_155621.txt |
| 2026-10-25 15:57 | 790a | - | - | ? | results/phase17_new_vectors/790a_helper_completion_20261025_155703.txt |
| 2026-10-25 16:03 | 69l | - | - | ? | results/phase16_kwrite/69l_evf_object_size_20261025_160330.txt |
| 2026-10-25 16:04 | 69m | - | - | ? | results/phase16_kwrite/69m_read_gadget_scan_20261025_160405.txt |
| 2026-10-25 16:06 | 69n | - | - | ? | results/phase16_kwrite/69n_663_mode_sweep_20261025_160649.txt |
| 2026-10-25 16:06 | 69t1 | - | - | ? | results/phase16_kwrite/69t1_666_667_semantics_20261025_160641.txt |
| 2026-10-25 16:07 | 69j | - | - | ? | results/phase16_kwrite/69j_sioc_ioctl_kaslr_20261025_160700.txt |
| 2026-10-25 16:07 | 69k | - | - | ? | results/phase16_kwrite/69k_dlsym_deep_sweep_20261025_160708.txt |
| 2026-10-25 16:07 | 69q1 | - | - | ? | results/phase16_kwrite/69q1_624_doublefree_oracle_20261025_160715.txt |
| 2026-10-25 16:26 | 70a | - | - | ? | results/phase16_kwrite/70a_small_alloc_sizing_20261025_162637.txt |
| 2026-10-25 16:26 | 70b | - | - | ? | results/phase16_kwrite/70b_aio_self_reclaim_kaslr_20261025_162649.txt |
| 2026-10-25 16:27 | 70b | - | - | ? | results/phase16_kwrite/70b_aio_self_reclaim_kaslr_20261025_162701.txt |
| 2026-10-25 16:28 | 70c | - | - | ? | results/phase16_kwrite/70c_refcount_underflow_20261025_162848.txt |
| 2026-10-25 16:28 | 70d | - | - | ? | results/phase16_kwrite/70d_666_field_mapping_20261025_162835.txt |
| 2026-10-25 16:30 | 70e | - | - | ? | results/phase16_kwrite/70e_race_refcount_impact_20261025_163013.txt |
| 2026-10-25 16:39 | 70e | - | - | ? | results/phase16_kwrite/70e_race_refcount_impact_20261025_163942.txt |
| 2026-10-25 16:50 | 71a | - | - | ? | results/phase16_kwrite/71a_aio_id_reuse_3thread_20261025_165001.txt |
| 2026-10-25 16:54 | 71b | - | - | ? | results/phase16_kwrite/71b_3thread_uaf_mainc_20261025_165409.txt |
| 2026-10-25 16:56 | 71c | - | - | ? | results/phase16_kwrite/71c_3thread_fixed_timing_20261025_165604.txt |
| 2026-10-25 17:00 | 71d | - | - | ? | results/phase16_kwrite/71d_3thread_lean_20261025_170045.txt |
| 2026-10-25 17:02 | 71e | - | - | ? | results/phase16_kwrite/71e_665_668_real_args_20261025_170230.txt |
| 2026-10-25 17:19 | 532a | - | - | ? | results/phase27_phys_memory/532a_r8_survive_20261025_171949.txt |
| 2026-10-25 17:19 | 532b | - | - | ? | results/phase27_phys_memory/532b_mapdm_aligned_20261025_171957.txt |
| 2026-10-25 17:20 | 532c | - | - | ? | results/phase27_phys_memory/532c_child_dmem_mmap_20261025_172047.txt |
| 2026-10-25 17:21 | 532d | - | - | ? | results/phase27_phys_memory/532d_dmem_oob_map_20261025_172139.txt |
| 2026-10-25 17:22 | 532e | - | - | ? | results/phase27_phys_memory/532e_dmem_range_scan_20261025_172239.txt |
| 2026-10-25 17:23 | 532f | - | - | ? | results/phase27_phys_memory/532f_gc_mmap_range_20261025_172327.txt |
| 2026-10-25 17:24 | 532g | - | - | ? | results/phase27_phys_memory/532g_gc_mmio_read_20261025_172411.txt |
| 2026-10-25 17:25 | 532h | - | - | ? | results/phase27_phys_memory/532h_mapdm_disasm_20261025_172525.txt |
| 2026-10-25 17:26 | 532i | - | - | ? | results/phase27_phys_memory/532i_mapdm_mainthread_20261025_172639.txt |
| 2026-10-25 17:27 | 532j | - | - | ? | results/phase27_phys_memory/532j_libkernel_got_20261025_172720.txt |
| 2026-10-25 17:27 | 532k | - | - | ? | results/phase27_phys_memory/532k_libkernel_relro_20261025_172754.txt |
| 2026-10-25 17:28 | 71f | - | - | ? | results/phase16_kwrite/71f_665_662shape_20261025_172836.txt |
| 2026-10-25 17:35 | 532m | - | - | ? | results/phase27_phys_memory/532m_lk_gadget_test_20261025_173550.txt |
| 2026-10-25 17:38 | 532n | - | - | ? | results/phase27_phys_memory/532n_batch_map_child_20261025_173836.txt |
| 2026-10-25 17:38 | 71f2 | - | - | ? | results/phase16_kwrite/71f2_668_first_20261025_173819.txt |
| 2026-10-25 17:44 | 532q | - | - | ? | results/phase27_phys_memory/532q_mmap_dmem_v2_20261025_174401.txt |
| 2026-10-25 17:44 | 532r | - | - | ? | results/phase27_phys_memory/532r_mmap_dmem_rw_20261025_174459.txt |
| 2026-10-25 17:45 | 532s | - | - | ? | results/phase27_phys_memory/532s_alloc_sysram_20261025_174533.txt |
| 2026-10-25 17:46 | 532t | - | - | ? | results/phase27_phys_memory/532t_mmap_dmem_unowned_20261025_174623.txt |
| 2026-10-25 17:47 | 532u | - | - | ? | results/phase27_phys_memory/532u_alloc_range_map_20261025_174711.txt |
| 2026-10-25 17:49 | 533a | - | - | ? | results/phase27_phys_memory/533a_fd_close_race_20261025_174926.txt |
| 2026-10-25 17:50 | 533b | - | - | ? | results/phase27_phys_memory/533b_aio_dmem_overrun_20261025_175044.txt |
| 2026-10-25 17:52 | 533c | - | - | ? | results/phase27_phys_memory/533c_pager_extend_20261025_175203.txt |
| 2026-10-25 17:53 | 533d | - | - | ? | results/phase27_phys_memory/533d_aio_phys_probe_20261025_175303.txt |
| 2026-10-25 17:56 | 533e | - | - | ? | results/phase27_phys_memory/533e_pager_boundary_20261025_175638.txt |
| 2026-10-25 17:57 | 533f | - | - | ? | results/phase27_phys_memory/533f_boundary_v2_20261025_175728.txt |
| 2026-10-25 17:58 | 533g | - | - | ? | results/phase27_phys_memory/533g_read_past_pool_20261025_175812.txt |
| 2026-10-25 17:58 | 533h | - | - | ? | results/phase27_phys_memory/533h_read_sysram_20261025_175850.txt |
| 2026-10-25 17:59 | 533i | - | - | ? | results/phase27_phys_memory/533i_read_sysram_v2_20261025_175954.txt |
| 2026-10-25 18:00 | 533j | - | - | ? | results/phase27_phys_memory/533j_direct_read_ext_20261025_180046.txt |
| 2026-10-25 18:02 | 534a | - | - | ? | results/phase27_phys_memory/534a_fd_close_race_20261025_180248.txt |
| 2026-10-25 18:04 | 534b | - | - | ? | results/phase27_phys_memory/534b_fd_race_fix_20261025_180415.txt |
| 2026-10-25 18:05 | 534c | - | - | ? | results/phase27_phys_memory/534c_fd_race_v3_20261025_180549.txt |
| 2026-10-25 18:07 | 534d | - | - | ? | results/phase27_phys_memory/534d_race_parallel_20261025_180716.txt |
| 2026-10-25 18:09 | 534e | - | - | ? | results/phase27_phys_memory/534e_race_small_20261025_180905.txt |
| 2026-10-25 18:12 | 534e | - | - | ? | results/phase27_phys_memory/534e_race_small_20261025_181205.txt |
| 2026-10-25 18:13 | 534f | - | - | ? | results/phase27_phys_memory/534f_race_500_20261025_181321.txt |
| 2026-10-25 18:19 | 71h | - | - | ? | results/phase16_kwrite/71h_663_behavior_20261025_181957.txt |
| 2026-10-25 18:20 | 71g | - | - | ? | results/phase16_kwrite/71g_child_669_test_20261025_182022.txt |
| 2026-10-25 18:23 | 527b | - | - | ? | results/phase23_cve_2026/527b_ghost_refcount_v2_20261025_182352.txt |
| 2026-10-25 18:29 | 72a | - | - | ? | results/phase16_kwrite/72a_663_662_race_20261025_182929.txt |
| 2026-10-25 18:35 | 72b | - | - | ? | results/phase16_kwrite/72b_663_662_race_v2_20261025_183507.txt |
| 2026-10-25 18:49 | 527c | - | - | ? | results/phase23_cve_2026/527c_ghost_real_fill_20261025_184954.txt |
| 2026-10-25 18:54 | 527d | - | - | ? | results/phase23_cve_2026/527d_ghost_stream_20261025_185447.txt |
| 2026-10-25 19:12 | 72c | - | - | ? | results/phase16_kwrite/72c_663_662_gate_20261025_191219.txt |
| 2026-10-25 19:22 | 69l | - | - | ? | results/phase16_kwrite/69l_evf_object_size_20261025_192201.txt |
| 2026-10-25 19:23 | 69m | - | - | ? | results/phase16_kwrite/69m_read_gadget_scan_20261025_192313.txt |
| 2026-10-25 19:28 | 540a | - | - | ? | results/phase29_aio_race/540a_aio_delete_race_20261025_192851.txt |
| 2026-10-25 19:28 | 69d | - | - | ? | results/phase16_kwrite/69d_kaslr_spray_20261025_192848.txt |
| 2026-10-25 19:28 | 72d | - | - | ? | results/phase16_kwrite/72d_663_qword_output_20261025_192827.txt |
| 2026-10-25 19:29 | 69i | - | - | ? | results/phase16_kwrite/69i_aio_cmd2_class_20261025_192959.txt |
| 2026-10-25 19:29 | 69j | - | - | ? | results/phase16_kwrite/69j_socket_ioctl_kaslr_20261025_192918.txt |
| 2026-10-25 19:29 | 69k | - | - | ? | results/phase16_kwrite/69k_dlsym_sweep_20261025_192927.txt |
| 2026-10-25 19:29 | 69n | - | - | ? | results/phase16_kwrite/69n_663_mode_sweep_20261025_192936.txt |
| 2026-10-25 19:30 | 540b | - | - | ? | results/phase29_aio_race/540b_aio_race_stagger_20261025_193038.txt |
| 2026-10-25 19:35 | 540c | - | - | ? | results/phase29_aio_race/540c_aio_race_verify_20261025_193500.txt |
| 2026-10-25 19:36 | 73a | - | - | ? | results/phase16_kwrite/73a_timing_gadgets_20261025_193630.txt |
| 2026-10-25 19:37 | 73b | - | - | ? | results/phase16_kwrite/73b_module_data_kptr_scan_20261025_193758.txt |
| 2026-10-25 19:40 | 534f | - | - | ? | results/phase27_phys_memory/534f_race_500_20261025_194022.txt |
| 2026-10-25 19:41 | 73c | - | - | ? | results/phase16_kwrite/73c_kptr_verify_20261025_194117.txt |
| 2026-10-25 19:52 | 541a | - | - | ? | results/phase29_aio_race/541a_aio_cancel_race_20261025_195246.txt |
| 2026-10-25 19:55 | 541b | - | - | ? | results/phase29_aio_race/541b_cancel_inflight_20261025_195552.txt |
| 2026-10-25 19:58 | 74a | - | - | ? | results/phase16_kwrite/74a_ipoptions_proper_20261025_195838.txt |
| 2026-10-25 19:58 | 74b | - | - | ? | results/phase16_kwrite/74b_669_ids_overcopy_20261025_195815.txt |
| 2026-10-25 19:59 | 74c | - | - | ? | results/phase16_kwrite/74c_eboot_got_scan_20261025_195908.txt |
| 2026-10-25 20:00 | 541c | - | - | ? | results/phase29_aio_race/541c_cancel_write_trigger_20261025_200051.txt |
| 2026-10-25 20:00 | 74a | - | - | ? | results/phase16_kwrite/74a_ipoptions_proper_20261025_200005.txt |
| 2026-10-25 20:01 | 74d | - | - | ? | results/phase16_kwrite/74d_socket_buffer_spray_20261025_200117.txt |
| 2026-10-25 20:01 | 74d | - | - | ? | results/phase16_kwrite/74d_socket_buffer_spray_20261025_200140.txt |
| 2026-10-25 20:02 | 74c | - | - | ? | results/phase16_kwrite/74c_got_plt_scan_20261025_200256.txt |
| 2026-10-25 20:02 | 74d | - | - | ? | results/phase16_kwrite/74d_669_ids_overcopy_20261025_200257.txt |
| 2026-10-25 20:04 | 74b | - | - | ? | results/phase16_kwrite/74b_eboot_got_kptr_20261025_200415.txt |
| 2026-10-25 20:06 | 74c | - | - | ? | results/phase16_kwrite/74c_669_ids_overcopy_20261025_200633.txt |
| 2026-10-25 20:06 | 74e | - | - | ? | results/phase16_kwrite/74e_module_kptr_verify_20261025_200649.txt |
| 2026-10-25 20:07 | 74e | - | - | ? | results/phase16_kwrite/74e_module_kptr_verify_20261025_200701.txt |
| 2026-10-25 20:07 | 74e | - | - | ? | results/phase16_kwrite/74e_verify_module_kptrs_20261025_200742.txt |
| 2026-10-25 20:08 | 541d | - | - | ? | results/phase29_aio_race/541d_wait_race_20261025_200804.txt |
| 2026-10-25 20:12 | 75a | - | - | ? | results/phase16_kwrite/75a_dynlib_v2_kaslr_20261025_201209.txt |
| 2026-10-25 20:14 | 541d | - | - | ? | results/phase29_aio_race/541d_wait_race_20261025_201427.txt |
| 2026-10-25 20:17 | 75b | - | - | ? | results/phase16_kwrite/75b_572_598_659_deep_20261025_201714.txt |
| 2026-10-25 20:18 | 75c | - | - | ? | results/phase16_kwrite/75c_572_deep_dump_20261025_201834.txt |
| 2026-10-25 21:11 | 544a | - | - | ? | results/phase30_mapdirect_loader/544a_fcall_stub_layout_20261025_211156.txt |
| 2026-10-25 21:15 | 544b | - | - | ? | results/phase30_mapdirect_loader/544b_mapdm_7arg_20261025_211538.txt |
| 2026-10-25 21:16 | 544c | - | - | ? | results/phase30_mapdirect_loader/544c_mapdm_diag_20261025_211640.txt |
| 2026-10-25 21:20 | 544d | - | - | ? | results/phase30_mapdirect_loader/544d_alloc_diag_20261025_212017.txt |
| 2026-10-25 21:21 | 544e | - | - | ? | results/phase30_mapdirect_loader/544e_mapdm_real_20261025_212109.txt |
| 2026-10-25 21:22 | 544f | - | - | ? | results/phase30_mapdirect_loader/544f_mapdm_mainthread_20261025_212224.txt |
| 2026-10-25 21:25 | 76a | - | - | ? | results/phase16_kwrite/76a_ipv6_rthdr_64b_roundtrip_20261025_212543.txt |
| 2026-10-25 21:26 | 80w | - | - | ? | results/phase17_new_vectors/80w_loader_health_20261025_212603.txt |
| 2026-10-25 21:28 | 76a | - | - | ? | results/phase16_kwrite/76a_ipv6_rthdr_64b_roundtrip_20261025_212858.txt |
| 2026-10-25 21:28 | ps5 | - | - | ? | results/ps5_probe_ping_codex_20261025_212853.txt |
| 2026-10-25 21:29 | 544g | - | - | ? | results/phase30_mapdirect_loader/544g_mapdm_stub_patch_20261025_212942.txt |
| 2026-10-25 21:29 | 76b | - | - | ? | results/phase16_kwrite/76b_ipv6_rthdr_pattern_readback_20261025_212943.txt |
| 2026-10-25 21:30 | 544h | - | - | ? | results/phase30_mapdirect_loader/544h_mapdm_readbuf_20261025_213046.txt |
| 2026-10-25 21:30 | 76c | - | - | ? | results/phase16_kwrite/76c_ipv6_rthdr_volume_20261025_213024.txt |
| 2026-10-25 21:31 | 544i | - | - | ? | results/phase30_mapdirect_loader/544i_mapdm_minimal_20261025_213146.txt |
| 2026-10-25 21:34 | 544j | - | - | ? | results/phase30_mapdirect_loader/544j_mapdm_isolated_20261025_213432.txt |
| 2026-10-25 21:35 | 544k | - | - | ? | results/phase30_mapdirect_loader/544k_mapdm_nativeread_20261025_213528.txt |
| 2026-10-25 21:36 | 544l | - | - | ? | results/phase30_mapdirect_loader/544l_mapdm_pureprint_20261025_213631.txt |
| 2026-10-25 21:37 | 544m | - | - | ? | results/phase30_mapdirect_loader/544m_mapdm_fixedaddr_20261025_213720.txt |
| 2026-10-25 21:38 | 544n | - | - | ? | results/phase30_mapdirect_loader/544n_mapdm_noread_20261025_213802.txt |
| 2026-10-25 21:38 | 544o | - | - | ? | results/phase30_mapdirect_loader/544o_mapdm_directaccess_20261025_213845.txt |
| 2026-10-25 21:39 | 544p | - | - | ? | results/phase30_mapdirect_loader/544p_mapdm_flags_20261025_213941.txt |
| 2026-10-25 21:40 | 544q | - | - | ? | results/phase30_mapdirect_loader/544q_mapdm_fcalltable_20261025_214043.txt |
| 2026-10-25 21:43 | 544r | - | - | ? | results/phase30_mapdirect_loader/544r_mapdm_writeonly_20261025_214336.txt |
| 2026-10-25 21:43 | 544r | - | - | ? | results/phase30_mapdirect_loader/544r_mapdm_writeonly_20261025_214353.txt |
| 2026-10-25 21:44 | 544r | - | - | ? | results/phase30_mapdirect_loader/544r_mapdm_writeonly_20261025_214407.txt |
| 2026-10-25 21:44 | 544r | - | - | ? | results/phase30_mapdirect_loader/544r_mapdm_writeonly_20261025_214418.txt |
| 2026-10-25 21:45 | 544s | - | - | ? | results/phase30_mapdirect_loader/544s_mapdm_syscall_after_20261025_214520.txt |
| 2026-10-25 21:47 | 544t | - | - | ? | results/phase30_mapdirect_loader/544t_mapdm_apollo_flags_20261025_214720.txt |
| 2026-10-25 21:47 | 544t | - | - | ? | results/phase30_mapdirect_loader/544t_mapdm_apollo_flags_20261025_214736.txt |
| 2026-10-25 21:48 | 544t | - | - | ? | results/phase30_mapdirect_loader/544t_mapdm_apollo_flags_20261025_214823.txt |
| 2026-10-25 21:50 | 544v | - | - | ? | results/phase30_mapdirect_loader/544v_mapdm_survive_20261025_215031.txt |
| 2026-10-25 21:50 | 544v | - | - | ? | results/phase30_mapdirect_loader/544v_mapdm_survive_20261025_215044.txt |
| 2026-10-25 21:50 | 544v | - | - | ? | results/phase30_mapdirect_loader/544v_mapdm_survive_20261025_215056.txt |
| 2026-10-25 21:51 | 544v | - | - | ? | results/phase30_mapdirect_loader/544v_mapdm_survive_20261025_215104.txt |
| 2026-10-25 21:51 | 544v | - | - | ? | results/phase30_mapdirect_loader/544v_mapdm_survive_20261025_215117.txt |
| 2026-10-25 21:51 | 544w | - | - | ? | results/phase30_mapdirect_loader/544w_mapdm_atomic_20261025_215157.txt |
| 2026-10-25 21:52 | 544w | - | - | ? | results/phase30_mapdirect_loader/544w_mapdm_atomic_20261025_215210.txt |
| 2026-10-25 21:52 | 544w | - | - | ? | results/phase30_mapdirect_loader/544w_mapdm_atomic_20261025_215217.txt |
| 2026-10-25 21:56 | 545b | - | - | ? | results/phase30_mapdirect_loader/545b_mapdm_fixedaddr_20261025_215619.txt |
| 2026-10-25 21:57 | 545b | - | - | ? | results/phase30_mapdirect_loader/545b_mapdm_fixedaddr_20261025_215728.txt |
| 2026-10-25 21:57 | 545b | - | - | ? | results/phase30_mapdirect_loader/545b_mapdm_fixedaddr_20261025_215746.txt |
| 2026-10-25 21:57 | 545b | - | - | ? | results/phase30_mapdirect_loader/545b_mapdm_fixedaddr_20261025_215758.txt |
| 2026-10-25 21:58 | 545b | - | - | ? | results/phase30_mapdirect_loader/545b_mapdm_fixedaddr_20261025_215815.txt |
| 2026-10-25 21:58 | 545b | - | - | ? | results/phase30_mapdirect_loader/545b_mapdm_fixedaddr_20261025_215827.txt |
| 2026-10-25 22:00 | 545c | - | - | ? | results/phase30_mapdirect_loader/545c_mapdm_failfirst_20261025_220000.txt |
| 2026-10-25 22:01 | 545c | - | - | ? | results/phase30_mapdirect_loader/545c_mapdm_failfirst_20261025_220120.txt |
| 2026-10-25 22:08 | 545c | - | - | ? | results/phase30_mapdirect_loader/545c_mapdm_failfirst_20261025_220845.txt |
| 2026-10-25 22:17 | 545c | - | - | ? | results/phase30_mapdirect_loader/545c_mapdm_failfirst_20261025_221731.txt |
| 2026-10-25 22:17 | 545c | - | - | ? | results/phase30_mapdirect_loader/545c_mapdm_failfirst_20261025_221741.txt |
| 2026-10-25 22:18 | 545c | - | - | ? | results/phase30_mapdirect_loader/545c_mapdm_failfirst_20261025_221800.txt |
| 2026-10-25 22:18 | 545c | - | - | ? | results/phase30_mapdirect_loader/545c_mapdm_failfirst_20261025_221852.txt |
| 2026-10-25 22:19 | 545c | - | - | ? | results/phase30_mapdirect_loader/545c_mapdm_failfirst_20261025_221911.txt |
| 2026-10-25 22:19 | 545c | - | - | ? | results/phase30_mapdirect_loader/545c_mapdm_failfirst_20261025_221922.txt |
| 2026-10-25 22:20 | 545d | - | - | ? | results/phase30_mapdirect_loader/545d_mapdm_premmap_20261025_222023.txt |
| 2026-10-25 22:20 | 545d | - | - | ? | results/phase30_mapdirect_loader/545d_mapdm_premmap_20261025_222034.txt |
| 2026-10-25 22:21 | 545e | - | - | ? | results/phase30_mapdirect_loader/545e_mapdm_direct_20261025_222130.txt |
| 2026-10-25 22:22 | 545f | - | - | ? | results/phase30_mapdirect_loader/545f_mapdm_mapfixed_20261025_222259.txt |
| 2026-10-25 22:24 | 545g | - | - | ? | results/phase30_mapdirect_loader/545g_mapdm_native_after_20261025_222432.txt |
| 2026-10-25 22:26 | 545h | - | - | ? | results/phase30_mapdirect_loader/545h_mmap_dmem_raw_20261025_222648.txt |
| 2026-10-26 | p550 | - | - | ? | results/phase13_webkit/p550_canvas_uaf_transform_leak_20261026.txt |
| 2026-10-26 | p551 | - | - | ? | results/phase13_webkit/p551_canvas_uaf_variants_20261026.txt |
| 2026-10-26 | p552 | - | - | ? | results/phase13_webkit/p552_canvas_uaf_desync_exploit_20261026.txt |
| 2026-10-26 | p553 | - | - | ? | results/phase13_webkit/p553_canvas_uaf_write_confirm_20261026.txt |
| 2026-10-26 | p554 | - | - | ? | results/phase13_webkit/p554_canvas_crosstype_offsetmap_20261026.txt |
| 2026-10-26 | p554b | - | - | ? | results/phase13_webkit/p554b_crosstype_lean_20261026.txt |
| 2026-10-26 | p554c | - | - | ? | results/phase13_webkit/p554c_crosstype_safe_20261026.txt |
| 2026-10-26 | p554d | - | - | ? | results/phase13_webkit/p554d_sametype_deep_20261026.txt |
| 2026-10-26 | p556 | - | - | ? | results/phase13_webkit/p556_rab_offset_race_20261026.txt |
| 2026-10-26 09:12 | 546b | - | - | ? | results/phase30_mapdirect_loader/546b_mapdm_diag_20261026_091216.txt |
| 2026-10-26 09:15 | 546c | - | - | ? | results/phase30_mapdirect_loader/546c_mapdm_solo_20261026_091546.txt |
| 2026-10-26 09:47 | 791a | - | - | ? | results/phase17_new_vectors/791a_aio_lastitem_race_20261026_094704.txt |
| 2026-10-26 09:48 | 791b | - | - | ? | results/phase17_new_vectors/791b_aio_block_delete_status_20261026_094833.txt |
| 2026-10-26 09:49 | 791c | - | - | ? | results/phase17_new_vectors/791c_aio_lastitem_array_race_20261026_094916.txt |
| 2026-10-26 09:50 | 791c | - | - | ? | results/phase17_new_vectors/791c_aio_lastitem_array_race_20261026_095036.txt |
| 2026-10-26 09:51 | 791c | - | - | ? | results/phase17_new_vectors/791c_aio_lastitem_array_race_20261026_095121.txt |
| 2026-10-26 09:52 | 791c | - | - | ? | results/phase17_new_vectors/791c_aio_lastitem_array_race_20261026_095204.txt |
| 2026-10-26 09:53 | 791d | - | - | ? | results/phase17_new_vectors/791d_aio_socket_barrier_race_20261026_095312.txt |
| 2026-10-26 09:54 | 791e | - | - | ? | results/phase17_new_vectors/791e_aio_alias_burst_20261026_095422.txt |
| 2026-10-26 09:57 | 791f | - | - | ? | results/phase17_new_vectors/791f_aio_repeat_doubles_20261026_095703.txt |
| 2026-10-26 10:01 | 792b | - | - | ? | results/phase17_new_vectors/792b_child_create_ctx_20261026_100124.txt |
| 2026-10-26 10:02 | 792c | - | - | ? | results/phase17_new_vectors/792c_child_postrace_alloc_20261026_100208.txt |
| 2026-10-26 10:03 | 792d | - | - | ? | results/phase17_new_vectors/792d_child_alloc_alias_20261026_100304.txt |
| 2026-10-26 10:33 | 793a | - | - | ? | results/phase17_new_vectors/793a_mdbg_named_commands_20261026_103335.txt |
| 2026-10-26 10:36 | 793b | - | - | ? | results/phase17_new_vectors/793b_mdbg_arg_layout_20261026_103634.txt |
| 2026-10-26 10:37 | 794a | - | - | ? | results/phase17_new_vectors/794a_mdbg_cmd0_selector_20261026_103726.txt |
| 2026-10-26 10:47 | 795a | - | - | ? | results/phase17_new_vectors/795a_aio_alloc_during_free_20261026_104728.txt |
| 2026-10-26 10:47 | 795a | - | - | ? | results/phase17_new_vectors/795a_aio_alloc_during_free_20261026_104746.txt |
| 2026-10-26 10:48 | 795a | - | - | ? | results/phase17_new_vectors/795a_aio_alloc_during_free_20261026_104815.txt |
| 2026-10-26 10:49 | 795a | - | - | ? | results/phase17_new_vectors/795a_aio_alloc_during_free_20261026_104900.txt |
| 2026-10-26 10:57 | 796a | - | - | ? | results/phase17_new_vectors/796a_sys626_msr_read_20261026_105730.txt |
| 2026-10-26 10:58 | 796b | - | - | ? | results/phase17_new_vectors/796b_sys626_source_20261026_105806.txt |
| 2026-10-26 10:59 | 796c | - | - | ? | results/phase17_new_vectors/796c_sys626_values_20261026_105912.txt |
| 2026-10-26 10:59 | 796d | - | - | ? | results/phase17_new_vectors/796d_sys626_cmd6_shape_20261026_105940.txt |
| 2026-10-26 11:02 | 797a | - | - | ? | results/phase17_new_vectors/797a_sys625_commands_20261026_110222.txt |
| 2026-10-26 11:07 | 798a | - | - | ? | results/phase17_new_vectors/798a_vmmcall_bytes_20261026_110731.txt |
| 2026-10-26 11:07 | 798a | - | - | ? | results/phase17_new_vectors/798a_vmmcall_bytes_20261026_110735.txt |
| 2026-10-26 11:07 | 798a | - | - | ? | results/phase17_new_vectors/798a_vmmcall_bytes_20261026_110742.txt |
| 2026-10-26 11:08 | 798a | - | - | ? | results/phase17_new_vectors/798a_vmmcall_bytes_20261026_110838.txt |
| 2026-10-26 11:09 | 799a | - | - | ? | results/phase17_new_vectors/799a_named_object_lifecycle_20261026_110933.txt |
| 2026-10-26 11:09 | 799a | - | - | ? | results/phase17_new_vectors/799a_named_object_lifecycle_20261026_110940.txt |
| 2026-10-26 11:10 | 800a | - | - | ? | results/phase17_new_vectors/800a_fd_double_release_20261026_111002.txt |
| 2026-10-26 11:10 | 801a | - | - | ? | results/phase17_new_vectors/801a_oversized_copyout_20261026_111053.txt |
| 2026-10-26 11:11 | 801a | - | - | ? | results/phase17_new_vectors/801a_oversized_copyout_20261026_111134.txt |
| 2026-10-26 11:13 | 802a | - | - | ? | results/phase17_new_vectors/802a_dmem0_bounds_20261026_111344.txt |
| 2026-10-26 11:51 | 803b | - | - | ? | results/phase17_new_vectors/803b_wx_bypass_548_20261026_115135.txt |
| 2026-10-26 11:51 | 803b | - | - | ? | results/phase17_new_vectors/803b_wx_bypass_548_20261026_115157.txt |
| 2026-10-26 11:52 | 803c | - | - | ? | results/phase17_new_vectors/803c_mmap_548_protect_20261026_115225.txt |
| 2026-10-26 11:53 | 803e | - | - | ? | results/phase17_new_vectors/803e_548_maxprot_matrix_20261026_115339.txt |
| 2026-10-26 11:54 | 803f | - | - | ? | results/phase17_new_vectors/803f_548_op3_payload_20261026_115424.txt |
| 2026-10-26 11:55 | 803g | - | - | ? | results/phase17_new_vectors/803g_548_text_pages_20261026_115523.txt |
| 2026-10-26 11:55 | 803h | - | - | ? | results/phase17_new_vectors/803h_mmap_prot_matrix_20261026_115541.txt |
| 2026-10-26 11:56 | 803i | - | - | ? | results/phase17_new_vectors/803i_file_mmap_exec_20261026_115603.txt |
| 2026-10-26 11:58 | 804a | - | - | ? | results/phase17_new_vectors/804a_named_object_lifecycle_20261026_115819.txt |
| 2026-10-26 11:59 | 804b | - | - | ? | results/phase17_new_vectors/804b_548_op3_prot_20261026_115903.txt |
| 2026-10-26 12:01 | 805a | - | - | ? | results/phase17_new_vectors/805a_net_pcblist_sweep_20261026_120122.txt |
| 2026-10-26 12:01 | 806a | - | - | ? | results/phase17_new_vectors/806a_dmem_foreign_phys_20261026_120148.txt |
| 2026-10-26 12:02 | 806b | - | - | ? | results/phase17_new_vectors/806b_dmem_phys_read_20261026_120207.txt |
| 2026-10-26 12:02 | 806c | - | - | ? | results/phase17_new_vectors/806c_dmem_alias_scan_20261026_120228.txt |
| 2026-10-26 12:03 | 806d | - | - | ? | results/phase17_new_vectors/806d_dmem_fine_scan_20261026_120302.txt |
| 2026-10-26 12:03 | 807a | - | - | ? | results/phase17_new_vectors/807a_phys_kernel_find_20261026_120336.txt |
| 2026-10-26 12:04 | 808a | - | - | ? | results/phase17_new_vectors/808a_phys_low_dump_20261026_120410.txt |
| 2026-10-26 12:05 | 808c | - | - | ? | results/phase17_new_vectors/808c_phys_scan_upper_20261026_120539.txt |
| 2026-10-26 12:06 | 808d | - | - | ? | results/phase17_new_vectors/808d_elf_hunt_20261026_120634.txt |
| 2026-10-26 12:08 | 809a | - | - | ? | results/phase17_new_vectors/809a_phys_persistence_20261026_120840.txt |
| 2026-10-26 12:09 | 810a | - | - | ? | results/phase17_new_vectors/810a_sys558_cross_delete_20261026_120945.txt |
| 2026-10-26 12:10 | 810b | - | - | ? | results/phase17_new_vectors/810b_plant_markers_20261026_121009.txt |
| 2026-10-26 12:11 | 810c | - | - | ? | results/phase17_new_vectors/810c_verify_markers_20261026_121110.txt |
| 2026-10-26 12:11 | 810d | - | - | ? | results/phase17_new_vectors/810d_scan_2g_4g_20261026_121138.txt |
| 2026-10-26 12:15 | 811a | - | - | ? | results/phase17_new_vectors/811a_aio_slot_exhaustion_20261026_121528.txt |
| 2026-10-26 12:17 | 812a | - | - | ? | results/phase17_new_vectors/812a_cross_family_ids_20261026_121734.txt |
| 2026-10-26 12:19 | 812b | - | - | ? | results/phase17_new_vectors/812b_cross_family_ids_20261026_121932.txt |
| 2026-10-26 12:19 | 812c | - | - | ? | results/phase17_new_vectors/812c_osem_id_type_20261026_121954.txt |
| 2026-10-26 12:26 | 814a | - | - | ? | results/phase17_new_vectors/814a_getcontext_dump_20261026_122643.txt |
| 2026-10-26 12:26 | 814a | - | - | ? | results/phase17_new_vectors/814a_getcontext_dump_20261026_122659.txt |
| 2026-10-26 12:28 | 814b | - | - | ? | results/phase17_new_vectors/814b_sigreturn_roundtrip_20261026_122800.txt |
| 2026-10-26 12:31 | 815a | - | - | ? | results/phase17_new_vectors/815a_eboot_gadget_scan_20261026_123115.txt |
| 2026-10-26 12:34 | 815b | - | - | ? | results/phase17_new_vectors/815b_gadget_scan_regions_20261026_123432.txt |
| 2026-10-26 12:37 | 815b | - | - | ? | results/phase17_new_vectors/815b_gadget_scan_regions_20261026_123716.txt |
| 2026-10-26 12:37 | 815b | - | - | ? | results/phase17_new_vectors/815b_gadget_scan_regions_20261026_123740.txt |
| 2026-10-26 12:37 | 815c | - | - | ? | results/phase17_new_vectors/815c_exec_regions_20261026_123706.txt |
| 2026-10-26 12:38 | 816a | - | - | ? | results/phase17_new_vectors/816a_rflags_iopl_20261026_123814.txt |
| 2026-10-26 12:42 | 816b | - | - | ? | results/phase17_new_vectors/816b_frame_control_20261026_124248.txt |
| 2026-10-26 12:44 | 816c | - | - | ? | results/phase17_new_vectors/816c_frame_readback_20261026_124415.txt |
| 2026-10-26 14:05 | 547b | - | - | ? | results/phase30_mapdirect_loader/547b_phys_scan_20261026_140531.txt |
| 2026-10-26 14:06 | 547c | - | - | ? | results/phase30_mapdirect_loader/547c_large_phys_map_20261026_140657.txt |
| 2026-10-26 14:07 | 547d | - | - | ? | results/phase30_mapdirect_loader/547d_dense_scan_20261026_140739.txt |
| 2026-10-26 14:10 | 547e | - | - | ? | results/phase30_mapdirect_loader/547e_pool_rest_20261026_141054.txt |
| 2026-10-26 14:15 | 547g | - | - | ? | results/phase30_mapdirect_loader/547g_high_phys_scan_20261026_141513.txt |
| 2026-10-26 17:05 | 817a | - | - | ? | results/phase17_new_vectors/817a_aio_window_16_20261026_170533.txt |
| 2026-10-26 17:11 | 817b | - | - | ? | results/phase17_new_vectors/817b_aio_shared_barrier_20261026_171132.txt |
| 2026-10-26 17:18 | 818a | - | - | ? | results/phase17_new_vectors/818a_aio_orphan_thread_20261026_171823.txt |
| 2026-10-26 18:42 | 819a | - | - | ? | results/phase17_new_vectors/819a_devctrl_cmd0_shape_20261026_184259.txt |
| 2026-10-26 18:43 | 819a | - | - | ? | results/phase17_new_vectors/819a_devctrl_cmd0_shape_20261026_184322.txt |
| 2026-10-26 18:50 | ping | - | - | ? | results/ping_20261026_185034.txt |
| 2026-10-26 18:57 | 820a | - | - | ? | results/phase17_new_vectors/820a_sys639_region_record_20261026_185757.txt |
| 2026-10-26 18:58 | 820a | - | - | ? | results/phase17_new_vectors/820a_sys639_region_record_20261026_185813.txt |
| 2026-10-26 19:06 | 821a | - | - | ? | results/phase17_new_vectors/821a_kernel_va_mapping_20261026_190642.txt |
| 2026-10-26 19:07 | 821b | - | - | ? | results/phase17_new_vectors/821b_mprotect_probe_20261026_190704.txt |
| 2026-10-26 19:14 | 821b | - | - | ? | results/phase17_new_vectors/821b_mprotect_probe_20261026_191436.txt |
| 2026-10-26 19:14 | 821b | - | - | ? | results/phase17_new_vectors/821b_mprotect_probe_20261026_191443.txt |
| 2026-10-26 19:15 | 822a | - | - | ? | results/phase17_new_vectors/822a_batch548_kernel_va_20261026_191532.txt |
| 2026-10-26 19:15 | 822b | - | - | ? | results/phase17_new_vectors/822b_batch548_layout_20261026_191555.txt |
| 2026-10-26 19:27 | 825a | - | - | ? | results/phase17_new_vectors/825a_osem_name_uaf_20261026_192754.txt |
| 2026-10-26 19:28 | 826a | - | - | ? | results/phase17_new_vectors/826a_osem_refcount_20261026_192827.txt |
| 2026-10-26 19:28 | 827a | - | - | ? | results/phase17_new_vectors/827a_osem_dangling_open_20261026_192855.txt |
| 2026-10-26 19:31 | 828a | - | - | ? | results/phase17_new_vectors/828a_osem_counter_oracle_20261026_193100.txt |
| 2026-10-26 19:32 | 829a | - | - | ? | results/phase17_new_vectors/829a_osem_chunk_reuse_20261026_193202.txt |
| 2026-10-26 19:32 | 830a | - | - | ? | results/phase17_new_vectors/830a_osem_limit_fingerprint_20261026_193232.txt |
| 2026-10-26 19:33 | 831a | - | - | ? | results/phase17_new_vectors/831a_osem_stale_alias_20261026_193352.txt |
| 2026-10-26 19:36 | 832a | - | - | ? | results/phase17_new_vectors/832a_mdbg_length_arg_20261026_193611.txt |
| 2026-10-26 19:36 | 833a | - | - | ? | results/phase17_new_vectors/833a_mdbg_uio_20261026_193634.txt |
| 2026-10-26 19:36 | 833a | - | - | ? | results/phase17_new_vectors/833a_mdbg_uio_20261026_193642.txt |
| 2026-10-26 19:36 | 833a | - | - | ? | results/phase17_new_vectors/833a_mdbg_uio_20261026_193652.txt |
| 2026-10-26 19:38 | 835a | - | - | ? | results/phase17_new_vectors/835a_sys548_prot_ops_20261026_193822.txt |
| 2026-10-26 19:38 | 835a | - | - | ? | results/phase17_new_vectors/835a_sys548_prot_ops_20261026_193831.txt |
| 2026-10-26 19:39 | 836a | - | - | ? | results/phase17_new_vectors/836a_sys548_map_address_20261026_193919.txt |
| 2026-10-26 19:40 | 837a | - | - | ? | results/phase17_new_vectors/837a_sys548_exec_page_20261026_194014.txt |
| 2026-10-26 19:40 | 838a | - | - | ? | results/phase17_new_vectors/838a_sys548_op_isolated_20261026_194034.txt |
| 2026-10-26 19:42 | 839a | - | - | ? | results/phase17_new_vectors/839a_syscall_frame_stale_20261026_194241.txt |
| 2026-10-26 19:45 | 840a | - | - | ? | results/phase17_new_vectors/840a_bind_sockaddr_chunk_20261026_194518.txt |
| 2026-10-26 19:47 | 840b | - | - | ? | results/phase17_new_vectors/840b_osem_destroy_while_waiting_20261026_194729.txt |
| 2026-10-26 19:47 | 840b | - | - | ? | results/phase17_new_vectors/840b_osem_destroy_while_waiting_20261026_194743.txt |
| 2026-10-26 19:48 | 840b | - | - | ? | results/phase17_new_vectors/840b_osem_destroy_while_waiting_20261026_194803.txt |
| 2026-10-26 19:48 | 840b | - | - | ? | results/phase17_new_vectors/840b_osem_destroy_while_waiting_20261026_194818.txt |
| 2026-10-26 19:48 | 841a | - | - | ? | results/phase17_new_vectors/841a_osem_wait_blocks_20261026_194857.txt |
| 2026-10-26 19:49 | 841a | - | - | ? | results/phase17_new_vectors/841a_osem_wait_blocks_20261026_194907.txt |
| 2026-10-26 19:51 | 841a | - | - | ? | results/phase17_new_vectors/841a_osem_wait_blocks_20261026_195131.txt |
| 2026-10-26 19:51 | 842a | - | - | ? | results/phase17_new_vectors/842a_osem_destroy_with_waiter_20261026_195147.txt |
| 2026-10-26 19:53 | 843a | - | - | ? | results/phase17_new_vectors/843a_osem_stale_write_reclaim_20261026_195329.txt |
| 2026-10-26 19:53 | 843b | - | - | ? | results/phase17_new_vectors/843b_osem_reclaim_window_20261026_195347.txt |
| 2026-10-26 19:54 | 844a | - | - | ? | results/phase17_new_vectors/844a_osem_create_after_waiter_destroy_20261026_195410.txt |
| 2026-10-26 19:54 | 845a | - | - | ? | results/phase17_new_vectors/845a_osem_stale_unlock_landing_20261026_195432.txt |
| 2026-10-26 19:56 | 846a | - | - | ? | results/phase17_new_vectors/846a_osem_destroy_race_noqueue_20261026_195655.txt |
| 2026-10-26 20:00 | 847a | - | - | ? | results/phase17_new_vectors/847a_aio_pathb_alias_20261026_200036.txt |
| 2026-10-26 20:03 | 848a | - | - | ? | results/phase17_new_vectors/848a_excess_copyout_hunt_20261026_200319.txt |
| 2026-10-26 20:06 | 849a | - | - | ? | results/phase17_new_vectors/849a_context_record_dump_20261026_200651.txt |
| 2026-10-26 20:07 | 850a | - | - | ? | results/phase17_new_vectors/850a_sys548_handle_map_20261026_200732.txt |
| 2026-10-26 20:08 | 851a | - | - | ? | results/phase17_new_vectors/851a_sys548_object_handle_20261026_200809.txt |
| 2026-10-26 20:08 | 852a | - | - | ? | results/phase17_new_vectors/852a_sys548_open_handle_20261026_200821.txt |
| 2026-10-26 20:08 | 853a | - | - | ? | results/phase17_new_vectors/853a_region_list_full_20261026_200852.txt |
| 2026-10-26 20:39 | 552a | - | - | ? | results/phase30_mapdirect_loader/552a_mapdm_srop_20261026_203954.txt |
| 2026-10-26 20:39 | 854a | - | - | ? | results/phase17_new_vectors/854a_sys558_osem_free_20261026_203900.txt |
| 2026-10-26 20:39 | 854b | - | - | ? | results/phase17_new_vectors/854b_sys558_presence_20261026_203911.txt |
| 2026-10-26 20:40 | 855a | - | - | ? | results/phase17_new_vectors/855a_sys557_create_20261026_204024.txt |
| 2026-10-26 20:43 | 552b | - | - | ? | results/phase30_mapdirect_loader/552b_child_srop_test_20261026_204337.txt |
| 2026-10-26 20:43 | 856a | - | - | ? | results/phase17_new_vectors/856a_sys532_commands_20261026_204326.txt |
| 2026-10-26 20:43 | 856a | - | - | ? | results/phase17_new_vectors/856a_sys532_commands_20261026_204332.txt |
| 2026-10-26 20:44 | 856b | - | - | ? | results/phase17_new_vectors/856b_sys532_status_map_20261026_204401.txt |
| 2026-10-26 20:44 | 857a | - | - | ? | results/phase17_new_vectors/857a_sys532_arg_matrix_20261026_204449.txt |
| 2026-10-26 20:46 | 858a | - | - | ? | results/phase17_new_vectors/858a_sys532_struct_20261026_204646.txt |
| 2026-10-26 20:47 | 859a | - | - | ? | results/phase17_new_vectors/859a_sys532_ids_20261026_204727.txt |
| 2026-10-26 20:48 | 552b | - | - | ? | results/phase30_mapdirect_loader/552b_child_srop_test_20261026_204853.txt |
| 2026-10-26 20:48 | 860a | - | - | ? | results/phase17_new_vectors/860a_sys532_size_20261026_204819.txt |
| 2026-10-26 20:48 | 861a | - | - | ? | results/phase17_new_vectors/861a_sys532_side_effects_20261026_204855.txt |
| 2026-10-26 20:50 | 552c | - | - | ? | results/phase30_mapdirect_loader/552c_mapdm_srop_fixed_20261026_205032.txt |
| 2026-10-26 20:51 | 862a | - | - | ? | results/phase17_new_vectors/862a_sys533_jitshm_20261026_205153.txt |
| 2026-10-26 20:52 | 862b | - | - | ? | results/phase17_new_vectors/862b_sys533_slots_20261026_205237.txt |
| 2026-10-26 20:53 | 863a | - | - | ? | results/phase17_new_vectors/863a_sys605_to_548_20261026_205320.txt |
| 2026-10-26 20:55 | 552d | - | - | ? | results/phase30_mapdirect_loader/552d_srop_alloc_test_20261026_205546.txt |
| 2026-10-26 20:57 | 552e | - | - | ? | results/phase30_mapdirect_loader/552e_mapdm_fcall_test_20261026_205738.txt |
| 2026-10-26 20:59 | 552f | - | - | ? | results/phase30_mapdirect_loader/552f_find_mapdm_20261026_205948.txt |
| 2026-10-26 21:00 | 552f | - | - | ? | results/phase30_mapdirect_loader/552f_find_mapdm_20261026_210019.txt |
| 2026-10-26 21:02 | 552g | - | - | ? | results/phase30_mapdirect_loader/552g_dmem_mmap_phys_20261026_210226.txt |
| 2026-10-26 21:03 | 552h | - | - | ? | results/phase30_mapdirect_loader/552h_phys_scan_kernel_20261026_210352.txt |
| 2026-10-26 21:06 | 552i | - | - | ? | results/phase30_mapdirect_loader/552i_phys_exec_and_structures_20261026_210636.txt |
| 2026-10-26 21:08 | 552j | - | - | ? | results/phase30_mapdirect_loader/552j_eboot_imports_20261026_210848.txt |
| 2026-10-26 21:10 | 552k | - | - | ? | results/phase30_mapdirect_loader/552k_got_scan_20261026_211021.txt |
| 2026-10-26 21:11 | 552l | - | - | ? | results/phase30_mapdirect_loader/552l_data_got_scan_20261026_211123.txt |
| 2026-10-26 21:12 | 552m | - | - | ? | results/phase30_mapdirect_loader/552m_test_unknown_funcs_20261026_211251.txt |
| 2026-10-26 21:14 | 552n | - | - | ? | results/phase30_mapdirect_loader/552n_fast_pid_scan_20261026_211438.txt |
| 2026-10-26 21:23 | 552o | - | - | ? | results/phase30_mapdirect_loader/552o_fast_kptr_pid_scan_20261026_212312.txt |
| 2026-10-26 21:26 | 553a | - | - | ? | results/phase30_mapdirect_loader/553a_test_lk_funcs_safe_20261026_212605.txt |
| 2026-10-26 21:26 | 553a | - | - | ? | results/phase30_mapdirect_loader/553a_test_lk_funcs_safe_20261026_212646.txt |
| 2026-10-26 21:27 | 553a | - | - | ? | results/phase30_mapdirect_loader/553a_test_lk_funcs_safe_20261026_212749.txt |
| 2026-10-26 21:29 | 553b | - | - | ? | results/phase30_mapdirect_loader/553b_test_lk_remaining_20261026_212923.txt |
| 2026-10-26 21:32 | 553c | - | - | ? | results/phase30_mapdirect_loader/553c_investigate_funcs_20261026_213209.txt |
| 2026-10-26 21:34 | 553d | - | - | ? | results/phase30_mapdirect_loader/553d_deep_funcs_20261026_213401.txt |
| 2026-10-26 21:35 | 553e | - | - | ? | results/phase30_mapdirect_loader/553e_release_mmap_test_20261026_213529.txt |
| 2026-10-26 22:26 | 864a | - | - | ? | results/phase17_new_vectors/864a_sys532_matrix_20261026_222612.txt |
| 2026-10-26 22:26 | 864b | - | - | ? | results/phase17_new_vectors/864b_sys532_value_20261026_222636.txt |
| 2026-10-26 22:27 | 865a | - | - | ? | results/phase17_new_vectors/865a_sys548_fd_handles_20261026_222702.txt |
| 2026-10-26 22:29 | 866a | - | - | ? | results/phase17_new_vectors/866a_aio_wait_delete_20261026_222901.txt |
| 2026-10-26 22:29 | 866a | - | - | ? | results/phase17_new_vectors/866a_aio_wait_delete_20261026_222944.txt |
| 2026-10-26 22:38 | 867a | - | - | ? | results/phase17_new_vectors/867a_sys558_double_close_20261026_223852.txt |
| 2026-10-26 22:40 | 868a | - | - | ? | results/phase17_new_vectors/868a_sys538_stored_pointer_20261026_224036.txt |
| 2026-10-26 22:41 | 869a | - | - | ? | results/phase17_new_vectors/869a_semaphore_name_duplicate_20261026_224121.txt |
| 2026-10-26 22:51 | 870a | - | - | ? | results/phase17_new_vectors/870a_priority_syscalls_20261026_225109.txt |
| 2026-10-26 22:56 | 871a | - | - | ? | results/phase17_new_vectors/871a_aio_count_boundary_20261026_225600.txt |
| 2026-10-26 22:56 | 872a | - | - | ? | results/phase17_new_vectors/872a_aio_spin_harness_20261026_225658.txt |
| 2026-10-26 22:57 | 872a | - | - | ? | results/phase17_new_vectors/872a_aio_spin_harness_20261026_225720.txt |
| 2026-10-26 22:57 | 872a | - | - | ? | results/phase17_new_vectors/872a_aio_spin_harness_20261026_225759.txt |
| 2026-10-26 22:59 | 872a | - | - | ? | results/phase17_new_vectors/872a_aio_spin_harness_20261026_225948.txt |
| 2026-10-26 23:06 | 872a | - | - | ? | results/phase17_new_vectors/872a_aio_spin_harness_20261026_230616.txt |
| 2026-10-26 23:08 | 873a | - | - | ? | results/phase17_new_vectors/873a_aio_state_writers_20261026_230817.txt |
| 2026-10-26 23:08 | 873a | - | - | ? | results/phase17_new_vectors/873a_aio_state_writers_20261026_230840.txt |
| 2026-10-26 23:09 | 873b | - | - | ? | results/phase17_new_vectors/873b_aio_state_gate_20261026_230902.txt |
| 2026-10-26 23:09 | 874a | - | - | ? | results/phase17_new_vectors/874a_aio_complete_vs_delete_20261026_230925.txt |
| 2026-10-26 23:09 | 874b | - | - | ? | results/phase17_new_vectors/874b_pipe_pending_20261026_230940.txt |
| 2026-10-26 23:17 | 874a | - | - | ? | results/phase17_new_vectors/874a_aio_complete_vs_delete_20261026_231741.txt |
| 2026-10-26 23:18 | 874a | - | - | ? | results/phase17_new_vectors/874a_aio_complete_vs_delete_20261026_231831.txt |
| 2026-10-26 23:18 | 874a | - | - | ? | results/phase17_new_vectors/874a_aio_complete_vs_delete_20261026_231842.txt |
| 2026-10-26 23:18 | 874a | - | - | ? | results/phase17_new_vectors/874a_aio_complete_vs_delete_20261026_231854.txt |
| 2026-10-26 23:19 | 875a | - | - | ? | results/phase17_new_vectors/875a_aio_wait_completion_20261026_231912.txt |
| 2026-10-26 23:19 | 876a | - | - | ? | results/phase17_new_vectors/876a_aio_wait_loop_20261026_231929.txt |
| 2026-10-26 23:20 | 877a | - | - | ? | results/phase17_new_vectors/877a_aio_wait_repeat_20261026_232022.txt |
| 2026-10-26 23:23 | 878a | - | - | ? | results/phase17_new_vectors/878a_gate_matrix_child_20261026_232316.txt |
| 2026-10-26 23:25 | 879a | - | - | ? | results/phase17_new_vectors/879a_aio_pending_delete_race_20261026_232517.txt |
| 2026-10-26 23:25 | 880a | - | - | ? | results/phase17_new_vectors/880a_aio_completion_window_20261026_232548.txt |
| 2026-10-26 23:26 | 880b | - | - | ? | results/phase17_new_vectors/880b_aio_slot_swap_20261026_232615.txt |
| 2026-10-26 23:26 | 880b | - | - | ? | results/phase17_new_vectors/880b_aio_slot_swap_20261026_232628.txt |
| 2026-10-26 23:26 | 880b | - | - | ? | results/phase17_new_vectors/880b_aio_slot_swap_20261026_232643.txt |
| 2026-10-26 23:28 | 881a | - | - | ? | results/phase17_new_vectors/881a_aio_waiter_deletes_20261026_232852.txt |
| 2026-10-26 23:58 | 881a | - | - | ? | results/phase17_new_vectors/881a_aio_waiter_deletes_20261026_235854.txt |
| 2026-10-27 | p555 | - | - | ? | results/phase13_webkit/p555_reentrancy_timing_20261027.txt |
| 2026-10-27 | p557 | - | - | ? | results/phase13_webkit/p557_ssv_desync_test_20261027.txt |
| 2026-10-27 | p558 | - | - | ? | results/phase13_webkit/p558_rab_escalation_20261027.txt |
| 2026-10-27 | p559 | - | - | ? | results/phase13_webkit/p559_rab_oob_values_20261027.txt |
| 2026-10-27 | p560 | - | - | ? | results/phase13_webkit/p560_sort_oob_write_20261027.txt |
| 2026-10-27 00:03 | 882a | - | - | ? | results/phase17_new_vectors/882a_aio_last_item_storm_20261027_000320.txt |
| 2026-10-27 00:05 | 882a | - | - | ? | results/phase17_new_vectors/882a_aio_last_item_storm_20261027_000506.txt |
| 2026-10-27 00:06 | 883a | - | - | ? | results/phase17_new_vectors/883a_aio_storm_loop_fixed_20261027_000641.txt |
| 2026-10-27 00:08 | 883a | - | - | ? | results/phase17_new_vectors/883a_aio_storm_loop_fixed_20261027_000802.txt |
| 2026-10-27 00:09 | 883a | - | - | ? | results/phase17_new_vectors/883a_aio_storm_loop_fixed_20261027_000906.txt |
| 2026-10-27 00:09 | 883a | - | - | ? | results/phase17_new_vectors/883a_aio_storm_loop_fixed_20261027_000952.txt |
| 2026-10-27 00:12 | 884a | - | - | ? | results/phase17_new_vectors/884a_aio_k_deletes_20261027_001222.txt |
| 2026-10-27 00:16 | 885a | - | - | ? | results/phase17_new_vectors/885a_aio_loop_debug_20261027_001626.txt |
| 2026-10-27 05:35 | 555a | - | - | ? | results/phase32_aio_race/555a_aio_recon_20261027_053544.txt |
| 2026-10-27 05:40 | 555b | - | - | ? | results/phase32_aio_race/555b_spray_and_lifecycle_20261027_054000.txt |
| 2026-10-27 13:36 | 555c | - | - | ? | results/phase32_aio_race/555c_double_delete_race_20261027_133613.txt |
| 2026-10-27 13:38 | 555c | - | - | ? | results/phase32_aio_race/555c_double_delete_race_20261027_133838.txt |
| 2026-10-27 13:41 | 886a | - | - | ? | results/phase17_new_vectors/886a_suspend_process_20261027_134127.txt |
| 2026-10-27 13:47 | 555c | - | - | ? | results/phase32_aio_race/555c_double_delete_race_20261027_134757.txt |
| 2026-10-27 13:49 | 555d | - | - | ? | results/phase32_aio_race/555d_race_diag_20261027_134941.txt |
| 2026-10-27 13:54 | 555d | - | - | ? | results/phase32_aio_race/555d_race_diag_20261027_135424.txt |
| 2026-10-27 13:57 | 555e | - | - | ? | results/phase32_aio_race/555e_barrier_test_20261027_135729.txt |
| 2026-10-27 13:59 | 555f | - | - | ? | results/phase32_aio_race/555f_yield_race_20261027_135944.txt |
| 2026-10-27 14:03 | 555g | - | - | ? | results/phase32_aio_race/555g_umtx_race_20261027_140311.txt |
| 2026-10-27 14:06 | 555h | - | - | ? | results/phase32_aio_race/555h_dual_child_race_20261027_140636.txt |
| 2026-10-27 14:10 | 555i | - | - | ? | results/phase32_aio_race/555i_barrier_race_20261027_141026.txt |
| 2026-10-27 14:14 | 555j | - | - | ? | results/phase32_aio_race/555j_pipe_barrier_race_20261027_141401.txt |
| 2026-10-27 14:16 | 555k | - | - | ? | results/phase32_aio_race/555k_shared_barrier_race_20261027_141635.txt |
| 2026-10-27 14:19 | 555l | - | - | ? | results/phase32_aio_race/555l_reverse_order_race_20261027_141916.txt |
| 2026-10-27 14:21 | 555m | - | - | ? | results/phase32_aio_race/555m_single_delete_race_20261027_142143.txt |
| 2026-10-27 14:51 | 556a | - | - | ? | results/phase32_aio_race/556a_knote_spray_race_20261027_145138.txt |
| 2026-10-27 14:53 | 556b | - | - | ? | results/phase32_aio_race/556b_wait_knote_race_20261027_145302.txt |
| 2026-10-27 15:03 | 557a | - | - | ? | results/phase32_aio_race/557a_wait_victim_spray_20261027_150350.txt |
| 2026-10-27 15:07 | 557b | - | - | ? | results/phase32_aio_race/557b_wait_no_race_diag_20261027_150745.txt |
| 2026-10-27 15:10 | 557c | - | - | ? | results/phase32_aio_race/557c_aio_capacity_diag_20261027_151031.txt |
| 2026-10-27 15:12 | 557d | - | - | ? | results/phase32_aio_race/557d_aio_fd_compare_20261027_151247.txt |
| 2026-10-27 15:42 | 887a | - | - | ? | results/phase17_new_vectors/887a_sys637_self_gate_20261027_154234.txt |
| 2026-10-27 15:43 | 888a | - | - | ? | results/phase17_new_vectors/888a_sys637_cross_target_20261027_154328.txt |
| 2026-10-27 15:43 | 889a | - | - | ? | results/phase17_new_vectors/889a_mmap_arena_control_20261027_154349.txt |
| 2026-10-27 15:44 | 890a | - | - | ? | results/phase17_new_vectors/890a_mmap_capacity_20261027_154417.txt |
| 2026-10-27 15:59 | 891a | - | - | ? | results/phase17_new_vectors/891a_gate_free_branches_20261027_155950.txt |
| 2026-10-27 16:01 | 892a | - | - | ? | results/phase17_new_vectors/892a_sys619_sweep_20261027_160132.txt |
| 2026-10-27 16:04 | 893a | - | - | ? | results/phase17_new_vectors/893a_sys616_name_read_20261027_160401.txt |
| 2026-10-27 16:22 | 894a | - | - | ? | results/phase17_new_vectors/894a_aio_poll_delete_twice_20261027_162214.txt |
| 2026-10-27 16:24 | 895a | - | - | ? | results/phase17_new_vectors/895a_aio_delete_race_threads_20261027_162413.txt |
| 2026-10-27 16:28 | 896a | - | - | ? | results/phase17_new_vectors/896a_aio_delete_race_clean_20261027_162858.txt |
| 2026-10-27 16:32 | 555a | - | - | ? | results/phase32_aio_race/555a_aio_recon_20261027_163221.txt |
| 2026-10-27 16:36 | 559a | - | - | ? | results/phase32_aio_race/559a_spray_vehicle_hunt_20261027_163651.txt |
| 2026-10-27 16:36 | 898a | - | - | ? | results/phase17_new_vectors/898a_aio_stage_bisect_20261027_163638.txt |
| 2026-10-27 16:44 | 901a | - | - | ? | results/phase17_new_vectors/901a_aio_scope_asymmetry_20261027_164457.txt |
| 2026-10-27 16:45 | 901a | - | - | ? | results/phase17_new_vectors/901a_aio_scope_asymmetry_20261027_164525.txt |
| 2026-10-27 16:51 | 559c | - | - | ? | results/phase32_aio_race/559c_spray_simple_20261027_165106.txt |
| 2026-10-27 16:52 | 559e | - | - | ? | results/phase32_aio_race/559e_spray_stress_20261027_165237.txt |
| 2026-10-27 16:55 | 560a | - | - | ? | results/phase32_aio_race/560a_kqueue_close_race_20261027_165505.txt |
| 2026-10-27 16:57 | 561a | - | - | ? | results/phase32_aio_race/561a_mapdm_outofpool_20261027_165713.txt |
| 2026-10-27 16:57 | 561a | - | - | ? | results/phase32_aio_race/561a_mapdm_outofpool_20261027_165746.txt |
| 2026-10-27 16:58 | 561b | - | - | ? | results/phase32_aio_race/561b_mapdm_accept_only_20261027_165851.txt |
| 2026-10-27 17:01 | 561c | - | - | ? | results/phase32_aio_race/561c_child_phys_read_20261027_170131.txt |
| 2026-10-27 17:03 | 561d | - | - | ? | results/phase32_aio_race/561d_find_syscall_gadget_20261027_170345.txt |
| 2026-10-27 17:10 | 561e | - | - | ? | results/phase32_aio_race/561e_child_nosyscall_read_20261027_171055.txt |
| 2026-10-27 17:13 | 562a | - | - | ? | results/phase32_aio_race/562a_phys_read_single_20261027_171305.txt |
| 2026-10-27 17:13 | 902a | - | - | ? | results/phase17_new_vectors/902a_aio_child_delete_only_20261027_171312.txt |
| 2026-10-27 17:13 | 902a | - | - | ? | results/phase17_new_vectors/902a_aio_child_delete_only_20261027_171324.txt |
| 2026-10-27 17:14 | 902a | - | - | ? | results/phase17_new_vectors/902a_aio_child_delete_only_20261027_171456.txt |
| 2026-10-27 17:17 | 562b | - | - | ? | results/phase32_aio_race/562b_phys_read_robust_20261027_171718.txt |
| 2026-10-27 17:21 | 562c | - | - | ? | results/phase32_aio_race/562c_isolate_binary_20261027_172122.txt |
| 2026-10-27 17:23 | 562d | - | - | ? | results/phase32_aio_race/562d_child_spinloop_20261027_172303.txt |
| 2026-10-27 17:25 | 562e | - | - | ? | results/phase32_aio_race/562e_phys_read_dup2_20261027_172529.txt |
| 2026-10-27 17:29 | 562f | - | - | ? | results/phase32_aio_race/562f_dup2_test_20261027_172915.txt |
| 2026-10-27 17:35 | 562g | - | - | ? | results/phase32_aio_race/562g_direct_write_phys_20261027_173531.txt |
| 2026-10-27 17:37 | 902b | - | - | ? | results/phase17_new_vectors/902b_aio_child_control_20261027_173745.txt |
| 2026-10-27 17:40 | 562h | - | - | ? | results/phase32_aio_race/562h_phys_read_384b_pattern_20261027_174047.txt |
| 2026-10-27 17:42 | 562i | - | - | ? | results/phase32_aio_race/562i_diagnose_crash_20261027_174203.txt |
| 2026-10-27 17:44 | 562j | - | - | ? | results/phase32_aio_race/562j_mainthread_phys_read_20261027_174416.txt |
| 2026-10-27 17:44 | 903a | - | - | ? | results/phase17_new_vectors/903a_alloc_type_20261027_174449.txt |
| 2026-10-27 17:45 | 903b | - | - | ? | results/phase17_new_vectors/903b_child_instrumented_20261027_174540.txt |
| 2026-10-27 17:46 | 562k | - | - | ? | results/phase32_aio_race/562k_socketpair_phys_20261027_174643.txt |
| 2026-10-27 18:00 | 904a | - | - | ? | results/phase17_new_vectors/904a_spawn_minimal_20261027_180059.txt |
| 2026-10-27 18:01 | 904b | - | - | ? | results/phase17_new_vectors/904b_child_delete_minimal_20261027_180120.txt |
| 2026-10-27 18:01 | 904b | - | - | ? | results/phase17_new_vectors/904b_child_delete_minimal_20261027_180129.txt |
| 2026-10-27 18:02 | 905a | - | - | ? | results/phase17_new_vectors/905a_aio_double_delete_race_20261027_180233.txt |
| 2026-10-27 18:04 | 562m | - | - | ? | results/phase32_aio_race/562m_stdout_inject_20261027_180417.txt |
| 2026-10-27 18:08 | 906a | - | - | ? | results/phase17_new_vectors/906a_aio_double_delete_sentinel_20261027_180859.txt |
| 2026-10-27 18:10 | 562n | - | - | ? | results/phase32_aio_race/562n_dual_child_20261027_181054.txt |
| 2026-10-27 18:13 | 562o | - | - | ? | results/phase32_aio_race/562o_direct_read_20261027_181339.txt |
| 2026-10-27 18:15 | 562p | - | - | ? | results/phase32_aio_race/562p_kernel_copyin_20261027_181536.txt |
| 2026-10-27 18:16 | 562q | - | - | ? | results/phase32_aio_race/562q_copyin_diag_20261027_181649.txt |
| 2026-10-27 18:21 | 562r | - | - | ? | results/phase32_aio_race/562r_survival_test_20261027_182159.txt |
| 2026-10-27 18:22 | 907a | - | - | ? | results/phase17_new_vectors/907a_thread_exhaustion_20261027_182220.txt |
| 2026-10-27 18:29 | 562s | - | - | ? | results/phase32_aio_race/562s_chain_then_mapdm_20261027_182932.txt |
| 2026-10-27 18:36 | 562t | - | - | ? | results/phase32_aio_race/562t_baseline_child_20261027_183603.txt |
| 2026-10-27 18:36 | 908a | - | - | ? | results/phase17_new_vectors/908a_child_no_stub_20261027_183640.txt |
| 2026-10-27 18:37 | 562u | - | - | ? | results/phase32_aio_race/562u_heap_stack_child_20261027_183742.txt |
| 2026-10-27 18:38 | 562v | - | - | ? | results/phase32_aio_race/562v_heap_mapdm_read_20261027_183833.txt |
| 2026-10-27 18:40 | 562w | - | - | ? | results/phase32_aio_race/562w_prebuilt_mapdm_20261027_184050.txt |
| 2026-10-27 18:42 | 562x | - | - | ? | results/phase32_aio_race/562x_mapdm_noop_child_20261027_184257.txt |
| 2026-10-27 18:43 | 910a | - | - | ? | results/phase17_new_vectors/910a_child_self_exit_20261027_184306.txt |
| 2026-10-27 18:43 | 911a | - | - | ? | results/phase17_new_vectors/911a_aio_race_exiting_children_20261027_184323.txt |
| 2026-10-27 18:44 | 562y | - | - | ? | results/phase32_aio_race/562y_dmem0_pread_20261027_184431.txt |
| 2026-10-27 18:45 | 912a | - | - | ? | results/phase17_new_vectors/912a_aio_delete_storm_20261027_184548.txt |
| 2026-10-27 18:46 | 913a | - | - | ? | results/phase17_new_vectors/913a_sync_gadget_scan_20261027_184607.txt |
| 2026-10-27 18:46 | 913b | - | - | ? | results/phase17_new_vectors/913b_selfloop_scan_20261027_184626.txt |
| 2026-10-27 18:47 | 562z | - | - | ? | results/phase32_aio_race/562z_dmem0_mmap_20261027_184729.txt |
| 2026-10-27 18:47 | 914a | - | - | ? | results/phase17_new_vectors/914a_aio_storm_128_20261027_184724.txt |
| 2026-10-27 18:48 | 563a | - | - | ? | results/phase32_aio_race/563a_kernel_elf_scan_20261027_184847.txt |
| 2026-10-27 18:50 | 563b | - | - | ? | results/phase32_aio_race/563b_dmem0_heatmap_20261027_185023.txt |
| 2026-10-27 18:53 | 563c | - | - | ? | results/phase32_aio_race/563c_devmem_and_finescan_20261027_185338.txt |
| 2026-10-27 18:56 | 563d | - | - | ? | results/phase32_aio_race/563d_ultramin_mapdm_20261027_185613.txt |
| 2026-10-27 19:07 | 563e | - | - | ? | results/phase32_aio_race/563e_selfmod_rop_20261027_190735.txt |
| 2026-10-27 19:13 | 915a | - | - | ? | results/phase17_new_vectors/915a_aio_waiter_delete_20261027_191334.txt |
| 2026-10-27 19:14 | 916a | - | - | ? | results/phase17_new_vectors/916a_aio_completion_race_20261027_191426.txt |
| 2026-10-27 19:22 | 563f | - | - | ? | results/phase32_aio_race/563f_selfmod_fastread_20261027_192231.txt |
| 2026-10-27 19:46 | 918a | - | - | ? | results/phase17_new_vectors/918a_sys663_signature_20261027_194624.txt |
| 2026-10-27 19:46 | 917a | - | - | ? | results/phase17_new_vectors/917a_aio_capture_wait_ret_20261027_194605.txt |
| 2026-10-27 19:48 | 919a | - | - | ? | results/phase17_new_vectors/919a_sys663_returns_20261027_194818.txt |
| 2026-10-27 19:48 | 919a | - | - | ? | results/phase17_new_vectors/919a_sys663_returns_20261027_194824.txt |
| 2026-10-27 19:50 | 563g | - | - | ? | results/phase32_aio_race/563g_copyin_bypass_20261027_195025.txt |
| 2026-10-27 19:50 | 920a | - | - | ? | results/phase17_new_vectors/920a_aio_delete_mismatch_20261027_195014.txt |
| 2026-10-27 19:51 | 563h | - | - | ? | results/phase32_aio_race/563h_dmem_high_flags_20261027_195135.txt |
| 2026-10-27 19:52 | 563i | - | - | ? | results/phase32_aio_race/563i_dmem_read_seek_20261027_195259.txt |
| 2026-10-27 19:57 | 922a | - | - | ? | results/phase17_new_vectors/922a_aio_delete_overcount_20261027_195748.txt |
| 2026-10-27 19:57 | 921a | - | - | ? | results/phase17_new_vectors/921a_aio_delete_count_sweep_20261027_195732.txt |
| 2026-10-27 19:58 | 923a | - | - | ? | results/phase17_new_vectors/923a_aio_forged_id_20261027_195800.txt |
| 2026-10-27 19:58 | 925a | - | - | ? | results/phase17_new_vectors/925a_aio_stale_gen_terminal_20261027_195828.txt |
| 2026-10-27 19:58 | 924a | - | - | ? | results/phase17_new_vectors/924a_aio_stale_gen_20261027_195817.txt |
| 2026-10-27 20:01 | 563j | - | - | ? | results/phase32_aio_race/563j_mapdm_phys0_trace_test_20261027_200109.txt |
| 2026-10-27 20:05 | 563k | - | - | ? | results/phase32_aio_race/563k_mapdm_flag_sweep_20261027_200543.txt |
| 2026-10-27 20:19 | 564a | - | - | ? | results/phase32_aio_race/564a_ipv6_2292pktoptions_test_20261027_201950.txt |
| 2026-10-27 20:37 | 926a | - | - | ? | results/phase17_new_vectors/926a_aio_kernel_buf_20261027_203748.txt |
| 2026-10-27 20:38 | 927a | - | - | ? | results/phase17_new_vectors/927a_aio_kernel_buf_prefilled_20261027_203800.txt |
| 2026-10-27 22:08 | 77a | - | - | ? | results/phase16_kwrite/77a_prolapse_spray_test_20261027_220838.txt |
| 2026-10-27 22:11 | 77b | - | - | ? | results/phase16_kwrite/77b_prolapse_race_spray_20261027_221100.txt |
| 2026-10-27 22:17 | 77c | - | - | ? | results/phase16_kwrite/77c_prolapse_drain_spray_20261027_221708.txt |
| 2026-10-27 22:18 | 77d | - | - | ? | results/phase16_kwrite/77d_prolapse_race_then_spray_20261027_221841.txt |
| 2026-10-27 22:20 | 77e | - | - | ? | results/phase16_kwrite/77e_prolapse_same_type_reclaim_20261027_222015.txt |
| 2026-10-27 22:20 | 77e | - | - | ? | results/phase16_kwrite/77e_prolapse_same_type_reclaim_20261027_222038.txt |
| 2026-10-27 22:21 | 77e | - | - | ? | results/phase16_kwrite/77e_prolapse_same_type_reclaim_20261027_222147.txt |
| 2026-10-27 22:24 | 77e | - | - | ? | results/phase16_kwrite/77e_prolapse_same_type_reclaim_20261027_222425.txt |
| 2026-10-27 22:34 | 77f | - | - | ? | results/phase16_kwrite/77f_prolapse_full_chain_20261027_223403.txt |
| 2026-10-27 22:36 | 65l | - | - | ? | results/phase16_kwrite/65l_aio_race_fixed_20261027_223615.txt |
| 2026-10-28 | p561 | - | - | ? | results/phase13_webkit/p561_transfer_sort_uaf_20261028.txt |
| 2026-10-28 | p562 | - | - | ? | results/phase13_webkit/p562_double_detach_uaf_20261028.txt |
| 2026-10-28 | p563 | - | - | ? | results/phase13_webkit/p563_canvas_crosstype_reclaim_20261028.txt |
| 2026-10-28 | p564 | - | - | ? | results/phase13_webkit/p564_canvas_force_reclaim_20261028.txt |
| 2026-10-28 | p565 | - | - | ? | results/phase13_webkit/p565_canvas_offset128_20261028.txt |
| 2026-10-28 | p566 | - | - | ? | results/phase13_webkit/p566_canvas_full_reclaim_20261028.txt |
| 2026-10-28 | v700b | - | - | ? | results/phase13_webkit/v700b_string_crosstype_768_20261028.txt |
| 2026-10-28 | v700c | - | - | ? | results/phase13_webkit/v700c_string_payload_dead_20261028.txt |
| 2026-10-28 | v701 | - | - | ? | results/phase13_webkit/v701_sametype_state_grow_20261028.txt |
| 2026-10-28 | v702 | - | - | ? | results/phase13_webkit/v702_gc_free_variant_a_20261028.txt |
| 2026-10-28 | v703 | - | - | ? | results/phase13_webkit/v703_gc_free_variant_b_20261028.txt |
| 2026-10-28 | v704 | - | - | ? | results/phase13_webkit/v704_ab768_direct_reclaim_20261028.txt |
| 2026-10-28 | v705 | - | - | ? | results/phase13_webkit/v705_property_survival_scan_20261028.txt |
| 2026-10-28 | v706 | - | - | ? | results/phase13_webkit/v706_factory_method_scan_20261028.txt |
| 2026-10-28 | v707 | - | - | ? | results/phase13_webkit/v707_ab_fill_pattern_20261028.txt |
| 2026-10-28 | v707b | - | - | ? | results/phase13_webkit/v707b_ab_fill_variant_b_20261028.txt |
| 2026-10-28 | v707c | - | - | ? | results/phase13_webkit/v707c_ab_fill_variant_c_20261028.txt |
| 2026-10-28 08:07 | 570a | - | - | ? | results/phase17_new_vectors/570a_dlsym_info2_test_20261028_080738.txt |
| 2026-10-28 08:16 | 571a | - | - | ? | results/phase17_new_vectors/571a_sys599_656_test_20261028_081628.txt |
| 2026-10-28 08:18 | 572a | - | - | ? | results/phase17_new_vectors/572a_vm_info_reshape_20261028_081812.txt |
| 2026-10-28 09:04 | 69g | - | - | ? | results/phase32_aio_race/69g_submit_during_delete_20261028_090414.txt |
| 2026-10-28 09:14 | 69h | - | - | ? | results/phase32_aio_race/69h_native_submit_delete_race_20261028_091447.txt |
| 2026-10-28 09:24 | 69i | - | - | ? | results/phase32_aio_race/69i_barrier_race_20261028_092454.txt |
| 2026-10-28 09:57 | 74a | - | - | ? | results/phase16_kwrite/74a_ipv6_exthdr_spray_20261028_095721.txt |
| 2026-10-28 10:07 | 65l | - | - | ? | results/phase16_kwrite/65l_aio_race_fixed_20261028_100717.txt |
| 2026-10-28 10:07 | 70a | - | - | ? | results/phase32_aio_race/70a_662_feature_path_20261028_100743.txt |
| 2026-10-28 10:07 | 74a | - | - | ? | results/phase16_kwrite/74a_ipv6_exthdr_spray_20261028_100726.txt |
| 2026-10-28 10:08 | 70b | - | - | ? | results/phase32_aio_race/70b_fixed_barrier_race_20261028_100854.txt |
| 2026-10-28 10:08 | spray | - | - | ? | results/spray_survey_20261028_100849.txt |
| 2026-10-28 10:09 | 77f | - | - | ? | results/phase16_kwrite/77f_prolapse_full_chain_20261028_100937.txt |
| 2026-10-28 10:11 | overlap | - | - | ? | results/overlap_detect_20261028_101112.txt |
| 2026-10-28 10:12 | overlap | - | - | ? | results/overlap_663_20261028_101221.txt |
| 2026-10-28 10:13 | pending | - | - | ? | results/pending_overlap_20261028_101326.txt |
| 2026-10-28 10:15 | zone128 | - | - | ? | results/zone128_spray_20261028_101510.txt |
| 2026-10-28 10:18 | ipsec | - | - | ? | results/ipsec_spray_20261028_101836.txt |
| 2026-10-28 10:21 | same | - | - | ? | results/same_type_overlap_20261028_102115.txt |
| 2026-10-28 10:24 | race | - | - | ? | results/race_overlap2_20261028_102429.txt |
| 2026-10-28 10:28 | race | - | - | ? | results/race_reclaim_20261028_102804.txt |
| 2026-10-28 10:32 | 71 | - | - | ? | results/phase33_umtx_exploit/71_robust_lists_20261028_103205.txt |
| 2026-10-28 11:06 | 68b | - | - | ? | results/phase16_kwrite/68b_aio_spray_pipes_20261028_110601.txt |
| 2026-10-28 11:11 | 75a | - | - | ? | results/phase16_kwrite/75a_coixao_spray_oracle_20261028_111124.txt |
| 2026-10-28 11:16 | 77f | - | - | ? | results/phase16_kwrite/77f_prolapse_full_chain_20261028_111636.txt |
| 2026-10-28 11:19 | 75b | - | - | ? | results/phase16_kwrite/75b_ipv6_spray_size_sweep_20261028_111954.txt |
| 2026-10-28 11:33 | 75c | - | - | ? | results/phase16_kwrite/75c_zone128_spray_oracle_20261028_113341.txt |
| 2026-10-28 11:42 | 75d | - | - | ? | results/phase16_kwrite/75d_zone128_spray_cpupin_20261028_114234.txt |
| 2026-10-28 11:52 | 75e | - | - | ? | results/phase16_kwrite/75e_zone128_more_frees_20261028_115212.txt |
| 2026-10-28 12:07 | overlap | - | - | ? | results/phase16_kwrite/overlap_detect2_20261028_120720.txt |
| 2026-10-28 19:06 | 58d | - | - | ? | results/phase15_native_sysent/58d_shm_sendfile_reachability_20261028_190649.txt |
| 2026-10-28 19:07 | 50e | - | - | ? | results/phase11_network_attacks/50e_ipv6_msfilter_reach_20261028_190701.txt |
| 2026-10-28 19:07 | 50e | - | - | ? | results/phase11_network_attacks/50e_ipv6_msfilter_reach_20261028_190737.txt |
| 2026-10-28 19:08 | 108a | - | - | ? | results/phase17_new_vectors/108a_scm_rights_fd_lifecycle_20261028_190816.txt |
| 2026-10-28 19:11 | 105a | - | - | ? | results/phase17_new_vectors/105a_evfilt_proc_kptr_leak_20261028_191128.txt |
| 2026-10-28 19:11 | canary | - | - | ? | results/canary_20261028_191120.txt |
| 2026-10-28 19:12 | 78d | - | - | ? | results/phase16_thr_create_crash/78d_kevent_evfilt_proc_20261028_191208.txt |
| 2026-10-28 19:14 | 931a | - | - | ? | results/phase17_new_vectors/931a_kevent_proc_repeat_20261028_191409.txt |
| 2026-10-28 19:15 | 931a | - | - | ? | results/phase17_new_vectors/931a_kevent_proc_repeat_20261028_191514.txt |
| 2026-10-28 19:15 | 931a | - | - | ? | results/phase17_new_vectors/931a_kevent_proc_repeat_20261028_191545.txt |
| 2026-10-28 19:16 | 932a | - | - | ? | results/phase17_new_vectors/932a_shm_object_lifecycle_20261028_191635.txt |
| 2026-10-28 19:16 | 932a | - | - | ? | results/phase17_new_vectors/932a_shm_object_lifecycle_20261028_191643.txt |
| 2026-10-28 19:17 | 932b | - | - | ? | results/phase17_new_vectors/932b_shm_object_lifecycle_20261028_191723.txt |
| 2026-10-28 19:17 | 933a | - | - | ? | results/phase17_new_vectors/933a_shm_refcount_20261028_191756.txt |
| 2026-10-28 19:18 | 105a | - | - | ? | results/phase17_new_vectors/105a_evfilt_proc_kptr_leak_20261028_191810.txt |
| 2026-10-28 19:18 | 109a | - | - | ? | results/phase17_new_vectors/109a_kernel_infoleak_sweep_20261028_191850.txt |
| 2026-10-28 19:18 | 930a | - | - | ? | results/phase17_new_vectors/930a_path_access_20261028_191858.txt |
| 2026-10-28 19:18 | 931a | - | - | ? | results/phase17_new_vectors/931a_kevent_proc_repeat_20261028_191818.txt |
| 2026-10-28 19:18 | 931a | - | - | ? | results/phase17_new_vectors/931a_kevent_proc_repeat_20261028_191832.txt |
| 2026-10-28 19:19 | 928a | - | - | ? | results/phase17_new_vectors/928a_exec_page_oracle_20261028_191940.txt |
| 2026-10-28 19:21 | 928b | - | - | ? | results/phase17_new_vectors/928b_exec_page_oracle_20261028_192117.txt |
| 2026-10-28 19:23 | 928c | - | - | ? | results/phase17_new_vectors/928c_exec_page_control_20261028_192304.txt |
| 2026-10-28 19:24 | 934a | - | - | ? | results/phase17_new_vectors/934a_shm_rx_page_20261028_192458.txt |
| 2026-10-28 19:26 | 88a | - | - | ? | results/phase17_new_vectors/88a_handle_namespace_confusion_20261028_192603.txt |
| 2026-10-28 19:26 | 88b | - | - | ? | results/phase17_new_vectors/88b_handle_typing_20261028_192633.txt |
| 2026-10-28 19:27 | 88c | - | - | ? | results/phase17_new_vectors/88c_ef_shapes_20261028_192735.txt |
| 2026-10-28 19:34 | 557a | - | - | ? | results/phase17_new_vectors/557a_what_creates_20261028_193403.txt |
| 2026-10-28 19:34 | 557b | - | - | ? | results/phase17_new_vectors/557b_name_lifetime_20261028_193442.txt |
| 2026-10-28 19:35 | 557c | - | - | ? | results/phase17_new_vectors/557c_stale_name_kernel_20261028_193539.txt |
| 2026-10-28 19:37 | 557d | - | - | ? | results/phase17_new_vectors/557d_name_length_20261028_193749.txt |
| 2026-10-28 19:39 | 50f | - | - | ? | results/phase11_network_attacks/50f_ipv6_cmsg_20261028_193913.txt |
| 2026-10-28 19:39 | 50g | - | - | ? | results/phase11_network_attacks/50g_ipv6_cmsg_sizes_20261028_193956.txt |
| 2026-10-28 19:40 | 50h | - | - | ? | results/phase11_network_attacks/50h_ipv6_cmsg_bound_20261028_194041.txt |
| 2026-10-28 19:41 | 954d | - | - | ? | results/phase11_network_attacks/954d_ipv6_sendmsg_plain_20261028_194127.txt |
| 2026-10-28 19:41 | 50i | - | - | ? | results/phase11_network_attacks/50i_ipv6_sendmsg_plain_20261028_194127.txt |
| 2026-10-28 19:42 | 954e | - | - | ? | results/phase11_network_attacks/954e_ipv6_opt_map_20261028_194207.txt |
| 2026-10-28 19:42 | 50j | - | - | ? | results/phase11_network_attacks/50j_ipv6_opt_map_20261028_194207.txt |
| 2026-10-28 19:43 | 50k | - | - | ? | results/phase11_network_attacks/50k_ipv6_cmsg_validate_20261028_194333.txt |
| 2026-10-28 19:44 | 954g | - | - | ? | results/phase11_network_attacks/954g_ipv6_cmsg_correct_20261028_194441.txt |
| 2026-10-28 19:44 | 50l | - | - | ? | results/phase11_network_attacks/50l_ipv6_cmsg_correct_20261028_194441.txt |
| 2026-10-28 19:45 | 954h | - | - | ? | results/phase11_network_attacks/954h_ipv6_2292_cmsg_20261028_194513.txt |
| 2026-10-28 19:45 | 954i | - | - | ? | results/phase11_network_attacks/954i_ipv6_sticky_2292_20261028_194547.txt |
| 2026-10-28 19:45 | 50m | - | - | ? | results/phase11_network_attacks/50m_ipv6_2292_cmsg_20261028_194513.txt |
| 2026-10-28 19:45 | 50n | - | - | ? | results/phase11_network_attacks/50n_ipv6_sticky_2292_20261028_194547.txt |
| 2026-10-28 19:48 | 96b | - | - | ? | results/phase17_new_vectors/96b_handle_generation_wrap_20261028_194828.txt |
| 2026-10-28 19:49 | 96c | - | - | ? | results/phase17_new_vectors/96c_handle_cross_family_aba_20261028_194929.txt |
| 2026-10-28 19:49 | 96c | - | - | ? | results/phase17_new_vectors/96c_handle_cross_family_aba_20261028_194951.txt |
| 2026-10-28 19:50 | 96d | - | - | ? | results/phase17_new_vectors/96d_handle_allocator_order_20261028_195024.txt |
| 2026-10-28 19:51 | 96e | - | - | ? | results/phase17_new_vectors/96e_handle_cross_family_use_20261028_195107.txt |
| 2026-10-28 19:51 | 96f | - | - | ? | results/phase17_new_vectors/96f_aio_delete_semantics_20261028_195140.txt |
| 2026-10-28 19:56 | 935a | - | - | ? | results/phase17_new_vectors/935a_poison_diff_sweep_20261028_195603.txt |
| 2026-10-28 19:56 | 935a | - | - | ? | results/phase17_new_vectors/935a_poison_diff_sweep_20261028_195634.txt |
| 2026-10-28 20:05 | 936a | - | - | ? | results/phase17_new_vectors/936a_bit62_gate_oracle_20261028_200511.txt |
| 2026-10-28 20:06 | 937a | - | - | ? | results/phase17_new_vectors/937a_gadget_scan_wide_20261028_200631.txt |
| 2026-10-28 20:07 | 937b | - | - | ? | results/phase17_new_vectors/937b_aio_delete_recreate_race_20261028_200755.txt |
| 2026-10-28 20:08 | 937c | - | - | ? | results/phase17_new_vectors/937c_aio_three_actor_race_20261028_200847.txt |
| 2026-10-28 20:09 | 937c | - | - | ? | results/phase17_new_vectors/937c_aio_three_actor_race_20261028_200923.txt |
| 2026-10-28 20:11 | 938a | - | - | ? | results/phase17_new_vectors/938a_sys629_integer_branch_20261028_201120.txt |
| 2026-10-28 20:43 | 98a | - | - | ? | results/phase17_new_vectors/98a_gpu_pte_wxbypass_20261028_204352.txt |
| 2026-10-28 20:44 | 98b | - | - | ? | results/phase17_new_vectors/98b_secB_20261028_204403.txt |
| 2026-10-28 20:45 | 939a | - | - | ? | results/phase17_new_vectors/939a_file_backed_exec_20261028_204533.txt |
| 2026-10-28 20:47 | 939b | - | - | ? | results/phase17_new_vectors/939b_file_fd_mapping_20261028_204747.txt |
| 2026-10-28 20:48 | 939c | - | - | ? | results/phase17_new_vectors/939c_file_maxprot_oracle_20261028_204810.txt |
| 2026-10-28 20:48 | 939d | - | - | ? | results/phase17_new_vectors/939d_file_exec_20261028_204844.txt |
| 2026-10-28 20:49 | 939e | - | - | ? | results/phase17_new_vectors/939e_entry_prot_oracle_20261028_204919.txt |
| 2026-10-28 20:50 | 940a | - | - | ? | results/phase17_new_vectors/940a_exec_backing_file_20261028_205023.txt |
| 2026-10-28 20:51 | 941a | - | - | ? | results/phase17_new_vectors/941a_umtx_pi_ops_20261028_205120.txt |
| 2026-10-28 20:51 | 941a | - | - | ? | results/phase17_new_vectors/941a_umtx_pi_ops_20261028_205128.txt |
| 2026-10-28 20:52 | 114a | - | - | ? | results/phase17_new_vectors/114a_gpu_mmap_alias_race_20261028_205250.txt |
| 2026-10-28 20:52 | 93a | - | - | ? | results/phase17_new_vectors/93a_gpu_vm_range_ops_20261028_205225.txt |
| 2026-10-28 20:52 | 99a | - | - | ? | results/phase17_new_vectors/99a_hw_write_vm_selfmod_20261028_205232.txt |
| 2026-10-28 20:52 | 99b | - | - | ? | results/phase17_new_vectors/99b_secB_20261028_205244.txt |
| 2026-10-28 20:53 | 114a | - | - | ? | results/phase17_new_vectors/114a_gpu_mmap_alias_race_20261028_205304.txt |
| 2026-10-28 20:53 | 114a | - | - | ? | results/phase17_new_vectors/114a_gpu_mmap_alias_race_20261028_205313.txt |
| 2026-10-28 20:53 | 114b | - | - | ? | results/phase17_new_vectors/114b_secB_20261028_205338.txt |
| 2026-10-28 21:14 | 93c | - | - | ? | results/phase23_newvuln/93c_lockf_spray_128b_20261028_211446.txt |
| 2026-10-28 21:14 | 93d | - | - | ? | results/phase23_newvuln/93d_dynlib_info2_leak_20261028_211439.txt |
| 2026-10-28 21:16 | 93a | - | - | ? | results/phase23_newvuln/93a_sndbuf_race_20261028_211607.txt |
| 2026-10-28 21:18 | 93a2 | - | - | ? | results/phase23_newvuln/93a2_sndbuf_race_prefill_20261028_211825.txt |
| 2026-10-28 21:21 | 93a3 | - | - | ? | results/phase23_newvuln/93a3_sndbuf_race_verify_20261028_212138.txt |
| 2026-10-28 21:26 | 93a4 | - | - | ? | results/phase23_newvuln/93a4_sndbuf_simple_20261028_212618.txt |
| 2026-10-28 21:28 | 93a5 | - | - | ? | results/phase23_newvuln/93a5_minimal_20261028_212835.txt |
| 2026-10-28 21:29 | 93a4 | - | - | ? | results/phase23_newvuln/93a4_sndbuf_simple_20261028_212912.txt |
| 2026-10-28 21:37 | 942a | - | - | ? | results/phase17_new_vectors/942a_sys620_attr_oracle_20261028_213746.txt |
| 2026-10-28 21:37 | 943a | - | - | ? | results/phase17_new_vectors/943a_uninit_copyout_sweep_20261028_213753.txt |
| 2026-10-28 21:38 | 943a | - | - | ? | results/phase17_new_vectors/943a_uninit_copyout_sweep_20261028_213802.txt |
| 2026-10-28 21:38 | 944a | - | - | ? | results/phase17_new_vectors/944a_extattr_surface_20261028_213845.txt |
| 2026-10-28 21:39 | 944a | - | - | ? | results/phase17_new_vectors/944a_extattr_surface_20261028_213908.txt |
| 2026-10-28 21:43 | 945a | - | - | ? | results/phase17_new_vectors/945a_extattr_list_isolate_20261028_214351.txt |
| 2026-10-28 21:48 | 947a | - | - | ? | results/phase17_new_vectors/947a_mlfs_surface_20261028_214831.txt |
| 2026-10-28 21:48 | 947b | - | - | ? | results/phase17_new_vectors/947b_mlfs_inode_lifetime_20261028_214857.txt |
| 2026-10-28 21:50 | 948a | - | - | ? | results/phase17_new_vectors/948a_aio_file_fd_20261028_215023.txt |
| 2026-10-28 21:54 | 949a | - | - | ? | results/phase17_new_vectors/949a_mlfs_lookup_race_20261028_215408.txt |
| 2026-10-28 22:00 | 93a8 | - | - | ? | results/phase23_newvuln/93a8_sndbuf_noinit_20261028_220001.txt |
| 2026-10-28 22:06 | 93a9 | - | - | ? | results/phase23_newvuln/93a9_sndbuf_final_20261028_220648.txt |
| 2026-10-28 22:07 | 93b | - | - | ? | results/phase23_newvuln/93b_mmap_munmap_race_20261028_220710.txt |
| 2026-10-28 22:09 | 93c | - | - | ? | results/phase23_newvuln/93c_sndbuf_race_concurrent_20261028_220907.txt |
| 2026-10-28 22:10 | 93c2 | - | - | ? | results/phase23_newvuln/93c2_sndbuf_race_20261028_221028.txt |
| 2026-10-28 22:12 | 93c3 | - | - | ? | results/phase23_newvuln/93c3_sndbuf_race_20261028_221259.txt |
| 2026-10-28 22:14 | 93c4 | - | - | ? | results/phase23_newvuln/93c4_sndbuf_race_20261028_221405.txt |
| 2026-10-28 22:14 | 93c5 | - | - | ? | results/phase23_newvuln/93c5_sndbuf_measure_20261028_221459.txt |
| 2026-10-28 22:16 | 74d | - | - | ? | results/phase16_kwrite/74d_evf_spray_test_20261028_221645.txt |
| 2026-10-28 22:17 | 77f | - | - | ? | results/phase16_kwrite/77f_prolapse_full_chain_20261028_221736.txt |
| 2026-10-28 22:19 | 77g | - | - | ? | results/phase16_kwrite/77g_prolapse_evf_cross_20261028_221925.txt |
| 2026-10-28 22:22 | 79c | - | - | ? | results/phase17_new_vectors/79c_ktimer_signal_reentrancy_20261028_222245.txt |
| 2026-10-28 22:23 | 79c | - | - | ? | results/phase17_new_vectors/79c_ktimer_signal_reentrancy_20261028_222305.txt |
| 2026-10-28 22:25 | 79d | - | - | ? | results/phase23_newvuln/79d_ktimer_lifecycle_20261028_222508.txt |
| 2026-10-28 22:27 | 94a | - | - | ? | results/phase23_newvuln/94a_spray_vehicle_hunt_20261028_222734.txt |
| 2026-10-28 22:30 | 94b | - | - | ? | results/phase23_newvuln/94b_aio_overlap_detect_20261028_223014.txt |
| 2026-10-28 22:31 | 94c | - | - | ? | results/phase23_newvuln/94c_aio_overlap_v2_20261028_223150.txt |
| 2026-10-28 22:33 | 94c | - | - | ? | results/phase23_newvuln/94c_aio_overlap_v2_20261028_223313.txt |
| 2026-10-28 22:34 | 94c | - | - | ? | results/phase23_newvuln/94c_aio_overlap_v2_20261028_223427.txt |
| 2026-10-28 22:36 | 94d | - | - | ? | results/phase23_newvuln/94d_aio_status_debug_20261028_223628.txt |
| 2026-10-29 | v674 | - | - | ? | results/phase13_webkit/v674_canvas_api_info_leak_20261029.txt |
| 2026-10-29 | v674b | - | - | ? | results/phase13_webkit/v674b_apng_decoder_overread_20261029.txt |
| 2026-10-29 | v675 | - | - | ? | results/phase13_webkit/v675_same_type_alias_baseline_20261029.txt |
| 2026-10-29 | v676 | - | - | ? | results/phase13_webkit/v676_ab_spray_miss_20261029.txt |
| 2026-10-29 | v677 | - | - | ? | results/phase13_webkit/v677_gc_pressure_free_20261029.txt |
| 2026-10-29 | v677b | - | - | ? | results/phase13_webkit/v677b_gc_pressure_variant_b_20261029.txt |
| 2026-10-29 | v677c | - | - | ? | results/phase13_webkit/v677c_gc_pressure_variant_c_20261029.txt |
| 2026-10-29 | v677d | - | - | ? | results/phase13_webkit/v677d_gc_pressure_variant_d_20261029.txt |
| 2026-10-29 | v678 | - | - | ? | results/phase13_webkit/v678_staged_alloc_gc_20261029.txt |
| 2026-10-29 | v679 | - | - | ? | results/phase13_webkit/v679_aslr_spray_probabilistic_20261029.txt |
| 2026-10-29 | v679b | - | - | ? | results/phase13_webkit/v679b_aslr_spray_1gb_20261029.txt |
| 2026-10-29 | v680 | - | - | ? | results/phase13_webkit/v680_address_space_mapper_20261029.txt |
| 2026-10-29 | v681 | - | - | ? | results/phase13_webkit/v681_aslr_zero_spray_20261029.txt |
| 2026-10-29 | v682 | - | - | ? | results/phase13_webkit/v682_aslr_low_range_20261029.txt |
| 2026-10-29 | v683 | - | - | ? | results/phase13_webkit/v683_oob_state_stack_20261029.txt |
| 2026-10-29 | v684 | - | - | ? | results/phase13_webkit/v684_weakref_ab_scan_20261029.txt |
| 2026-10-29 | v685 | - | - | ? | results/phase13_webkit/v685_opaque_root_gc_dead_20261029.txt |
| 2026-10-29 | v707e | - | - | ? | results/phase13_webkit/v707e_ab_fill_variant_e_20261029.txt |
| 2026-10-29 | v707f | - | - | ? | results/phase13_webkit/v707f_ab_fill_variant_f_20261029.txt |
| 2026-10-29 | v707g | - | - | ? | results/phase13_webkit/v707g_ab_fill_variant_g_20261029.txt |
| 2026-10-29 | v707h | - | - | ? | results/phase13_webkit/v707h_ab_fill_variant_h_20261029.txt |
| 2026-10-29 20:04 | 93a | - | - | ? | results/phase17_new_vectors/93a_gpu_vm_range_ops_20261029_200455.txt |
| 2026-10-29 20:06 | 93a | - | - | ? | results/phase17_new_vectors/93a_gpu_vm_range_ops_20261029_200646.txt |
| 2026-10-29 20:06 | 98a | - | - | ? | results/phase17_new_vectors/98a_gpu_pte_wxbypass_20261029_200657.txt |
| 2026-10-29 20:07 | 949b | - | - | ? | results/phase17_new_vectors/949b_sys653_selector_20261029_200736.txt |
| 2026-10-29 20:07 | 98a | - | - | ? | results/phase17_new_vectors/98a_secB_20261029_200717.txt |
| 2026-10-29 20:08 | 949c | - | - | ? | results/phase17_new_vectors/949c_sys653_narg_20261029_200806.txt |
| 2026-10-29 20:08 | 98a | - | - | ? | results/phase17_new_vectors/98a_secB_20261029_200824.txt |
| 2026-10-29 20:09 | 99a | - | - | ? | results/phase17_new_vectors/99a_hw_write_vm_selfmod_20261029_200912.txt |
| 2026-10-29 20:09 | 99a | - | - | ? | results/phase17_new_vectors/99a_secB_20261029_200923.txt |
| 2026-10-29 20:10 | 114a | - | - | ? | results/phase17_new_vectors/114a_gpu_mmap_alias_race_20261029_201025.txt |
| 2026-10-29 20:10 | 114a | - | - | ? | results/phase17_new_vectors/114a_secC_20261029_201034.txt |
| 2026-10-29 20:14 | 951a | - | - | ? | results/phase17_new_vectors/951a_mapfixed_over_exec_20261029_201443.txt |
| 2026-10-29 20:16 | 952a | - | - | ? | results/phase17_new_vectors/952a_mapfixed_exec_spawn_20261029_201621.txt |
| 2026-10-29 20:16 | 952a | - | - | ? | results/phase17_new_vectors/952a_mapfixed_exec_spawn_20261029_201641.txt |
| 2026-10-29 20:16 | 952a | - | - | ? | results/phase17_new_vectors/952a_mapfixed_exec_spawn_20261029_201605.txt |
| 2026-10-29 20:18 | 953a | - | - | ? | results/phase17_new_vectors/953a_mapfixed_mprotect_x_20261029_201850.txt |
| 2026-10-29 20:18 | canary953 | - | - | ? | results/canary953_20261029_201822.txt |
| 2026-10-29 20:19 | 953a | - | - | ? | results/phase17_new_vectors/953a_mapfixed_mprotect_x_20261029_201910.txt |
| 2026-10-29 23:29 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261029_232929.txt |
| 2026-10-29 23:32 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261029_233221.txt |
| 2026-10-29 23:36 | syscall | - | - | ? | results/phase15_native_sysent/syscall_isolation_sweep_20261029_233635.txt |
| 2026-10-29 23:37 | 936a | - | - | ? | results/phase17_new_vectors/936a_sysv_ipc_reach_20261029_233737.txt |
| 2026-10-29 23:38 | 936b | - | - | ? | results/phase17_new_vectors/936b_sysv_creators_ordered_20261029_233818.txt |
| 2026-10-29 23:38 | 936c | - | - | ? | results/phase17_new_vectors/936c_sysv_lookup_only_20261029_233847.txt |
| 2026-10-29 23:39 | 937a | - | - | ? | results/phase17_new_vectors/937a_stats_handlers_641_642_646_20261029_233919.txt |
| 2026-10-29 23:45 | 938b | - | - | ? | results/phase17_new_vectors/938b_close_vs_blocked_read_exit_20261029_234521.txt |
| 2026-10-29 23:46 | 938c | - | - | ? | results/phase17_new_vectors/938c_close_vs_blocked_read_rsi_20261029_234628.txt |
| 2026-10-29 23:47 | 939a | - | - | ? | results/939a_gadget_bytes_20261029_234714.txt |
| 2026-10-29 23:47 | 939a | - | - | ? | results/939a_gadget_bytes_20261029_234726.txt |
| 2026-10-29 23:49 | 938d | - | - | ? | results/phase17_new_vectors/938d_fd_race_fixed_base_20261029_234956.txt |
| 2026-10-29 23:49 | 939b | - | - | ? | results/939b_dynlib_base_20261029_234904.txt |
| 2026-10-29 23:49 | 939c | - | - | ? | results/939c_gadget_check_20261029_234923.txt |
| 2026-10-29 23:50 | 938d | - | - | ? | results/phase17_new_vectors/938d_fd_race_fixed_base_20261029_235006.txt |
| 2026-10-29 23:50 | 938d | - | - | ? | results/phase17_new_vectors/938d_fd_race_fixed_base_20261029_235021.txt |
| 2026-10-29 23:50 | 938d | - | - | ? | results/phase17_new_vectors/938d_fd_race_fixed_base_20261029_235042.txt |
| 2026-10-30 10:40 | 954a | - | - | ? | results/phase17_new_vectors/954a_aio_inflight_oracle_20261030_104037.txt |
| 2026-10-30 10:41 | 955a | - | - | ? | results/phase17_new_vectors/955a_aio_inflight_delete_race_20261030_104154.txt |
| 2026-10-30 10:51 | 956a | - | - | ? | results/phase17_new_vectors/956a_aio_lock_probe_20261030_105108.txt |
| 2026-10-30 10:51 | 957a | - | - | ? | results/phase17_new_vectors/957a_aio_slot_reuse_race_20261030_105153.txt |
| 2026-10-30 10:53 | 958a | - | - | ? | results/phase17_new_vectors/958a_aio_double_delete_hunt_20261030_105321.txt |
| 2026-10-30 10:53 | 958a | - | - | ? | results/phase17_new_vectors/958a_aio_double_delete_hunt_20261030_105341.txt |
| 2026-10-30 10:54 | 959a | - | - | ? | results/phase17_new_vectors/959a_aio_state_map_20261030_105401.txt |
| 2026-10-30 11:22 | 970a | - | - | ? | results/phase17_new_vectors/970a_setsockopt_close_race_20261030_112215.txt |
| 2026-10-30 11:22 | 970b | - | - | ? | results/phase17_new_vectors/970b_setsockopt_loop_close_20261030_112249.txt |
| 2026-10-30 11:25 | 970c | - | - | ? | results/phase17_new_vectors/970c_setsockopt_children_close_20261030_112546.txt |
| 2026-10-30 11:26 | 971a | - | - | ? | results/phase17_new_vectors/971a_scmrights_close_race_20261030_112622.txt |
| 2026-10-30 11:32 | 972a | - | - | ? | results/phase17_new_vectors/972a_gadget_validate_20261030_113223.txt |
| 2026-10-30 11:33 | 971b | - | - | ? | results/phase17_new_vectors/971b_blocked_recvmsg_close_20261030_113304.txt |
| 2026-11-03 | p588d | - | - | ? | results/phase13_webkit/p588d_v6_definitive_null_test_20261103.txt |
| 2026-11-03 | p588d | - | - | ? | results/phase13_webkit/p588d_v7_trigger_sweep_20261103.txt |
| 2026-11-03 | p588d | - | - | ? | results/phase13_webkit/p588d_v8b_engine_write_map_20261103.txt |
| 2026-11-03 | p589 | - | - | ? | results/phase13_webkit/p589_alpha_fontfaceset_trigger_20261103.txt |
| 2026-11-03 | p590 | - | - | ? | results/phase13_webkit/p590_two_uaf_test_20261103.txt |
| 2026-11-03 11:08 | p588 | - | - | ? | results/phase12_kernel_analysis/p588-constant-drain-lk-lc_20261103_110854.txt |
| 2026-11-03 11:12 | p588 | - | - | ? | results/phase12_kernel_analysis/p588-constant-drain-lk-lc_20261103_111208.txt |
| 2026-11-03 11:16 | 972a | - | - | ? | results/phase17_new_vectors/972a_sys_641_642_646_20261103_111605.txt |
| 2026-11-03 11:16 | 972a | - | - | ? | results/phase17_new_vectors/972a_sys_641_642_646_20261103_111616.txt |
| 2026-11-03 11:16 | 972b | - | - | ? | results/phase17_new_vectors/972b_sys_641_642_646_shapes_20261103_111636.txt |
| 2026-11-03 11:17 | p589 | - | - | ? | results/phase12_kernel_analysis/p589-find-libkernel-drain_20261103_111730.txt |
| 2026-11-03 11:17 | 973a | - | - | ? | results/phase17_new_vectors/973a_sysv_ipc_reach_20261103_111703.txt |
| 2026-11-03 11:18 | p589 | - | - | ? | results/phase12_kernel_analysis/p589-find-libkernel-drain_20261103_111814.txt |
| 2026-11-03 11:22 | 974a | - | - | ? | results/phase17_new_vectors/974a_aio_many_inflight_20261103_112243.txt |
| 2026-11-03 11:23 | 974b | - | - | ? | results/phase17_new_vectors/974b_aio_pair_complete_delete_20261103_112307.txt |
| 2026-11-03 11:25 | p590 | - | - | ? | results/phase12_kernel_analysis/p590-lk-code-offset-drain_20261103_112532.txt |
| 2026-11-03 11:25 | 975a | - | - | ? | results/phase17_new_vectors/975a_aio_fd_oracle_20261103_112532.txt |
| 2026-11-03 11:25 | 975b | - | - | ? | results/phase17_new_vectors/975b_aio_special_fds_20261103_112556.txt |
| 2026-11-03 11:26 | 975c | - | - | ? | results/phase17_new_vectors/975c_fcntl_fd_map_20261103_112621.txt |
| 2026-11-03 11:26 | 975d | - | - | ? | results/phase17_new_vectors/975d_fd_identify_20261103_112648.txt |
| 2026-11-03 11:27 | 975e | - | - | ? | results/phase17_new_vectors/975e_fd_peername_20261103_112723.txt |
| 2026-11-03 11:27 | 975d | - | - | ? | results/phase17_new_vectors/975d_fd_identify_20261103_112700.txt |
| 2026-11-03 11:28 | 976a | - | - | ? | results/phase17_new_vectors/976a_ioctl_real_fds_20261103_112812.txt |
| 2026-11-03 11:29 | 977a | - | - | ? | results/phase17_new_vectors/977a_device_fd_mmap_20261103_112901.txt |
| 2026-11-03 11:29 | 977b | - | - | ? | results/phase17_new_vectors/977b_fd18_content_20261103_112918.txt |
| 2026-11-03 11:30 | 978a | - | - | ? | results/phase17_new_vectors/978a_dev_nodes_20261103_113020.txt |
| 2026-11-03 11:40 | p591 | - | - | ? | results/phase12_kernel_analysis/p591-lk-remaining-drain_20261103_114040.txt |
| 2026-11-03 11:43 | p591 | - | - | ? | results/phase12_kernel_analysis/p591-lk-remaining-drain_20261103_114347.txt |
| 2026-11-03 11:46 | p591b | - | - | ? | results/phase12_kernel_analysis/p591b-child-thread-minimal_20261103_114658.txt |
| 2026-11-03 11:50 | p591b | - | - | ? | results/phase12_kernel_analysis/p591b-child-thread-minimal_20261103_115041.txt |
| 2026-11-03 11:55 | p591c | - | - | ? | results/phase12_kernel_analysis/p591c-thr-exit-only_20261103_115532.txt |
| 2026-11-03 11:57 | p591c | - | - | ? | results/phase12_kernel_analysis/p591c-thr-exit-only_20261103_115748.txt |
| 2026-11-03 11:58 | p591c | - | - | ? | results/phase12_kernel_analysis/p591c-thr-exit-only_20261103_115834.txt |
| 2026-11-03 12:02 | p591c | - | - | ? | results/phase12_kernel_analysis/p591c-thr-exit-only_20261103_120201.txt |
| 2026-11-03 12:04 | p591 | - | - | ? | results/phase12_kernel_analysis/p591-lk-remaining-drain_20261103_120459.txt |
| 2026-11-03 12:29 | p591 | - | - | ? | results/phase12_kernel_analysis/p591-lk-remaining-drain_20261103_122942.txt |
| 2026-11-03 12:33 | p591 | - | - | ? | results/phase12_kernel_analysis/p591-lk-remaining-drain_20261103_123306.txt |
| 2026-11-03 12:34 | p591 | - | - | ? | results/phase12_kernel_analysis/p591-lk-remaining-drain_20261103_123423.txt |
| 2026-11-03 12:35 | p591d | - | - | ? | results/phase12_kernel_analysis/p591d-native-multiarg_20261103_123533.txt |
| 2026-11-03 12:38 | p591 | - | - | ? | results/phase12_kernel_analysis/p591-lk-remaining-drain_20261103_123839.txt |
| 2026-11-03 12:44 | p591 | - | - | ? | results/phase12_kernel_analysis/p591-lk-remaining-drain_20261103_124431.txt |
| 2026-11-03 13:36 | p588 | - | - | ? | results/phase13_webkit/p588-route-d-discriminator_20261103_133624.txt |
| 2026-11-03 13:38 | p588b | - | - | ? | results/phase13_webkit/p588b-route-d-null-table_20261103_133856.txt |
| 2026-11-03 13:48 | p588c | - | - | ? | results/phase13_webkit/p588c-second-walk-diag_20261103_134800.txt |
| 2026-11-03 14:57 | 979a | - | - | ? | results/phase17_new_vectors/979a_aio_direction_oracle_20261103_145752.txt |
| 2026-11-03 14:58 | 980a | - | - | ? | results/phase17_new_vectors/980a_copyin_kernel_addr_20261103_145828.txt |
| 2026-11-03 15:02 | 981a | - | - | ? | results/phase11_network_attacks/981a_ipv6_pktoptions_connected_20261103_150254.txt |
| 2026-11-03 15:03 | 982a | - | - | ? | results/phase11_network_attacks/982a_ipv6_msfilter_aligned_20261103_150323.txt |
| 2026-11-03 15:06 | 983a | - | - | ? | results/phase17_new_vectors/983a_opmc_index_bounds_20261103_150605.txt |
| 2026-11-03 15:06 | 983b | - | - | ? | results/phase17_new_vectors/983b_opmc_value_mask_20261103_150650.txt |
| 2026-11-03 15:08 | 984a | - | - | ? | results/phase17_new_vectors/984a_sys605_arg2_20261103_150821.txt |
| 2026-11-03 15:11 | 985a | - | - | ? | results/phase17_new_vectors/985a_device_fd_io_20261103_151106.txt |
| 2026-11-03 15:26 | 986a | - | - | ? | results/phase17_new_vectors/986a_vm_prot_kernel_probe_20261103_152645.txt |
| 2026-11-03 15:26 | 986a | - | - | ? | results/phase17_new_vectors/986a_vm_prot_kernel_probe_20261103_152618.txt |
| 2026-11-03 15:26 | 986a | - | - | ? | results/phase17_new_vectors/986a_vm_prot_kernel_probe_20261103_152633.txt |
| 2026-11-03 15:31 | 987a | - | - | ? | results/phase17_new_vectors/987a_loader_source_extract_20261103_153117.txt |
| 2026-11-03 15:31 | 987a | - | - | ? | results/phase17_new_vectors/987a_loader_source_extract_20261103_153105.txt |
| 2026-11-03 15:32 | 988a | - | - | ? | results/phase17_new_vectors/988a_fault_channel_20261103_153229.txt |
| 2026-11-03 15:38 | 989a | - | - | ? | results/phase17_new_vectors/989a_shared_maxprot_20261103_153858.txt |
| 2026-11-03 15:39 | 989b | - | - | ? | results/phase17_new_vectors/989b_shared_maxprot_fixed_20261103_153943.txt |
| 2026-11-03 15:42 | 990a | - | - | ? | results/phase17_new_vectors/990a_crash_attribution_20261103_154231.txt |
| 2026-11-03 15:51 | 991a | - | - | ? | results/phase17_new_vectors/991a_siginfo_page_20261103_155109.txt |
| 2026-11-03 15:51 | 991a | - | - | ? | results/phase17_new_vectors/991a_siginfo_page_20261103_155123.txt |
| 2026-11-03 16:28 | 992a | - | - | ? | results/phase17_new_vectors/992a_loader_globals_20261103_162806.txt |
| 2026-11-03 16:28 | 993a | - | - | ? | results/phase17_new_vectors/993a_siginfo_dump_20261103_162852.txt |
| 2026-11-03 16:29 | 993b | - | - | ? | results/phase17_new_vectors/993b_chain_selftest_20261103_162932.txt |
| 2026-11-03 16:31 | 993c | - | - | ? | results/phase17_new_vectors/993c_frame_dump_20261103_163122.txt |
| 2026-11-03 16:32 | 994a | - | - | ? | results/phase17_new_vectors/994a_handler_registers_20261103_163210.txt |
| 2026-11-03 16:32 | 995a | - | - | ? | results/phase17_new_vectors/995a_fault_class_dump_20261103_163237.txt |
| 2026-11-03 16:33 | 995a | - | - | ? | results/phase17_new_vectors/995a_fault_class_dump_20261103_163314.txt |
| 2026-11-03 16:34 | 995a | - | - | ? | results/phase17_new_vectors/995a_fault_class_dump_20261103_163437.txt |
| 2026-11-03 16:37 | 996a | - | - | ? | results/phase17_new_vectors/996a_fault_code_oracle_20261103_163711.txt |
| 2026-11-03 16:38 | 997a | - | - | ? | results/phase17_new_vectors/997a_child_fault_survival_20261103_163808.txt |
| 2026-11-03 16:40 | 998a | - | - | ? | results/phase17_new_vectors/998a_fault_scan_loop_20261103_164018.txt |
| 2026-11-03 16:41 | 999a | - | - | ? | results/phase17_new_vectors/999a_handler_exit_test_20261103_164158.txt |
| 2026-11-03 16:42 | 999a | - | - | ? | results/phase17_new_vectors/999a_handler_exit_test_20261103_164227.txt |
| 2026-11-03 16:45 | 999a | - | - | ? | results/phase17_new_vectors/999a_handler_exit_test_20261103_164532.txt |
| 2026-11-03 16:46 | 1000a | - | - | ? | results/phase17_new_vectors/1000a_fault_scan_20261103_164605.txt |
| 2026-11-03 16:46 | 1000a | - | - | ? | results/phase17_new_vectors/1000a_fault_scan_20261103_164641.txt |
| 2026-11-03 16:48 | 1001a | - | - | ? | results/phase17_new_vectors/1001a_kernel_map_sweep_20261103_164811.txt |
| 2026-11-03 16:50 | 1002a | - | - | ? | results/phase17_new_vectors/1002a_kernel_base_edges_20261103_165031.txt |
| 2026-11-03 16:51 | 1003a | - | - | ? | results/phase17_new_vectors/1003a_kva_layout_20261103_165133.txt |
| 2026-11-03 16:52 | 1003b | - | - | ? | results/phase17_new_vectors/1003b_below_kernel_20261103_165225.txt |
| 2026-11-03 16:56 | 1001a | - | - | ? | results/phase17_new_vectors/1001a_kernel_map_sweep_20261103_165604.txt |
| 2026-11-03 16:57 | 1004a | - | - | ? | results/phase17_new_vectors/1004a_kernel_half_sweep_20261103_165726.txt |
| 2026-11-03 17:00 | 1005a | - | - | ? | results/phase17_new_vectors/1005a_postboot_edges_20261103_170022.txt |
| 2026-11-03 17:00 | 1006a | - | - | ? | results/phase17_new_vectors/1006a_kernel_read_probe_20261103_170042.txt |
| 2026-11-03 17:01 | 1006a | - | - | ? | results/phase17_new_vectors/1006a_kernel_read_probe_20261103_170148.txt |
| 2026-11-03 17:10 | 1008a | - | - | ? | results/phase17_new_vectors/1008a_cpl_test_20261103_171024.txt |
| 2026-11-03 17:11 | 1008a | - | - | ? | results/phase17_new_vectors/1008a_cpl_test_20261103_171134.txt |
| 2026-11-03 17:13 | 1009a | - | - | ? | results/phase17_new_vectors/1009a_sigsys_catch_20261103_171331.txt |
| 2026-11-03 17:14 | 1010a | - | - | ? | results/phase17_new_vectors/1010a_sigsys_error_20261103_171414.txt |
| 2026-11-03 17:15 | 1011a | - | - | ? | results/phase17_new_vectors/1011a_sigsys_real_20261103_171507.txt |
| 2026-11-03 17:27 | 1015a | - | - | ? | results/phase17_new_vectors/1015a_ipv6_pktoptions_leak_20261103_172725.txt |
| 2026-11-03 17:27 | 1019a | - | - | ? | results/phase17_new_vectors/1019a_pktopts_other_options_20261103_172738.txt |
| 2026-11-03 17:28 | 1018a | - | - | ? | results/phase17_new_vectors/1018a_kernel_pid_kinfo_20261103_172849.txt |
| 2026-11-03 17:28 | 1019a | - | - | ? | results/phase17_new_vectors/1019a_pktopts_other_options_20261103_172802.txt |
| 2026-11-03 17:28 | 1019a | - | - | ? | results/phase17_new_vectors/1019a_pktopts_other_options_20261103_172834.txt |
| 2026-11-03 17:30 | 1021a | - | - | ? | results/phase17_new_vectors/1021a_fstat_and_neighbours_20261103_173016.txt |
| 2026-11-03 17:30 | 1021a | - | - | ? | results/phase17_new_vectors/1021a_fstat_and_neighbours_20261103_173029.txt |
| 2026-11-03 17:31 | 1022a | - | - | ? | results/phase17_new_vectors/1022a_map_fixed_kernel_half_20261103_173132.txt |
| 2026-11-03 17:32 | 1023a | - | - | ? | results/phase17_new_vectors/1023a_fstat_fd_table_20261103_173205.txt |
| 2026-11-03 17:32 | 1024a | - | - | ? | results/phase17_new_vectors/1024a_fstat_full_scan_20261103_173240.txt |
| 2026-11-03 17:34 | 1018a | - | - | ? | results/phase17_new_vectors/1018a_kernel_pid_kinfo_20261103_173401.txt |
| 2026-11-03 17:34 | 1018a | - | - | ? | results/phase17_new_vectors/1018a_kernel_pid_kinfo_20261103_173419.txt |
| 2026-11-03 17:34 | 1019a | - | - | ? | results/phase17_new_vectors/1019a_pktopts_other_options_20261103_173401.txt |
| 2026-11-03 17:35 | 1015a | - | - | ? | results/phase17_new_vectors/1015a_ipv6_pktoptions_leak_20261103_173501.txt |
| 2026-11-03 17:39 | 1025a | - | - | ? | results/phase17_new_vectors/1025a_sony_copyout_sweep_20261103_173959.txt |
| 2026-11-03 17:42 | 1025a | - | - | ? | results/phase17_new_vectors/1025a_sony_copyout_sweep_20261103_174207.txt |
| 2026-11-03 17:42 | 1026a | - | - | ? | results/phase17_new_vectors/1026a_638_write_probe_20261103_174249.txt |
| 2026-11-03 17:43 | 1026a | - | - | ? | results/phase17_new_vectors/1026a_638_write_probe_20261103_174317.txt |
| 2026-11-03 17:43 | 1027a | - | - | ? | results/phase17_new_vectors/1027a_638_struct_20261103_174353.txt |
| 2026-11-03 17:46 | 1028a | - | - | ? | results/phase17_new_vectors/1028a_638_pointer_presence_20261103_174618.txt |
| 2026-11-03 17:47 | 1029a | - | - | ? | results/phase17_new_vectors/1029a_638_neighbourhood_20261103_174711.txt |
| 2026-11-03 17:52 | 1030a | - | - | ? | results/phase17_new_vectors/1030a_dynlib_dlopen_20261103_175203.txt |
| 2026-11-03 17:52 | 1031a | - | - | ? | results/phase17_new_vectors/1031a_dlopen_shapes_20261103_175251.txt |
| 2026-11-03 17:53 | 1032a | - | - | ? | results/phase17_new_vectors/1032a_loadprx_growth_20261103_175312.txt |
| 2026-11-03 17:55 | 1033a | - | - | ? | results/phase17_new_vectors/1033a_stats_enum_leak_20261103_175530.txt |
| 2026-11-03 17:56 | 1034a | - | - | ? | results/phase17_new_vectors/1034a_physhm_arg1_20261103_175646.txt |
| 2026-11-03 18:12 | 1037a | - | - | ? | results/phase17_new_vectors/1037a_dl_get_info_20261103_181242.txt |
| 2026-11-03 18:16 | 1038a | - | - | ? | results/phase17_new_vectors/1038a_device_read_write_20261103_181643.txt |
| 2026-11-03 18:23 | 1038a | - | - | ? | results/phase17_new_vectors/1038a_device_read_write_20261103_182309.txt |
| 2026-11-03 18:24 | 1039a | - | - | ? | results/phase17_new_vectors/1039a_622_shape_sweep_20261103_182423.txt |
| 2026-11-03 18:34 | 1041a | - | - | ? | results/phase17_new_vectors/1041a_lua_thread_test_20261103_183453.txt |
| 2026-11-03 18:35 | 1041a | - | - | ? | results/phase17_new_vectors/1041a_lua_thread_test_20261103_183508.txt |
| 2026-11-03 18:37 | 1042a | - | - | ? | results/phase17_new_vectors/1042a_aio_lua_race_20261103_183724.txt |
| 2026-11-03 18:37 | 1042a | - | - | ? | results/phase17_new_vectors/1042a_aio_lua_race_20261103_183752.txt |
| 2026-11-03 18:49 | 1042b | - | - | ? | results/phase17_new_vectors/1042b_aio_lua_thread_single_20261103_184954.txt |
| 2026-11-03 18:50 | 1042c | - | - | ? | results/phase17_new_vectors/1042c_aio_lua_race_gated_20261103_185030.txt |
| 2026-11-03 18:53 | 1042d | - | - | ? | results/phase17_new_vectors/1042d_aio_race_parent_child_20261103_185323.txt |
| 2026-11-03 18:55 | 1042e | - | - | ? | results/phase17_new_vectors/1042e_getpid_control_20261103_185541.txt |
| 2026-11-03 19:00 | 1043a | - | - | ? | results/phase17_new_vectors/1043a_native_chain_concurrency_20261103_190058.txt |
| 2026-11-03 19:21 | 1043a | - | - | ? | results/phase17_new_vectors/1043a_native_chain_concurrency_20261103_192147.txt |
| 2026-11-03 19:23 | 1043a | - | - | ? | results/phase17_new_vectors/1043a_native_chain_concurrency_20261103_192323.txt |
| 2026-11-03 19:24 | 1043b | - | - | ? | results/phase17_new_vectors/1043b_aio_native_race_20261103_192406.txt |
| 2026-11-03 19:25 | 1044a | - | - | ? | results/phase17_new_vectors/1044a_aio_double_free_detector_20261103_192556.txt |
| 2026-11-03 19:27 | 1045a | - | - | ? | results/phase17_new_vectors/1045a_child_fault_containment_20261103_192726.txt |
| 2026-11-03 19:29 | 1046a | - | - | ? | results/phase17_new_vectors/1046a_aio_shape_matrix_20261103_192912.txt |
| 2026-11-03 19:29 | 1047a | - | - | ? | results/phase17_new_vectors/1047a_aio_double_free_polled_20261103_192946.txt |
| 2026-11-03 19:30 | 1048a | - | - | ? | results/phase17_new_vectors/1048a_aio_poll_timing_20261103_193033.txt |
| 2026-11-03 19:32 | 1049a | - | - | ? | results/phase17_new_vectors/1049a_aio_invalidation_probe_20261103_193227.txt |
| 2026-11-03 19:33 | 1050a | - | - | ? | results/phase17_new_vectors/1050a_aio_double_free_v2_20261103_193333.txt |
| 2026-11-03 19:34 | 1051a | - | - | ? | results/phase17_new_vectors/1051a_aio_three_way_delete_race_20261103_193436.txt |
| 2026-11-03 19:35 | 1052a | - | - | ? | results/phase17_new_vectors/1052a_aio_poll_delete_race_20261103_193514.txt |
| 2026-11-03 19:35 | 1052b | - | - | ? | results/phase17_new_vectors/1052b_aio_poll_delete_aligned_20261103_193529.txt |
| 2026-11-03 19:47 | 1040a | - | - | ? | results/phase17_new_vectors/1040a_622_cmd302_ptr_20261103_194722.txt |
| 2026-11-03 19:54 | 1053a | - | - | ? | results/phase17_new_vectors/1053a_622_cmd302_len40_20261103_195401.txt |
| 2026-11-03 20:03 | 1054a | - | - | ? | results/phase17_new_vectors/1054a_622_cmd302_ptrs_20261103_200354.txt |
| 2026-11-03 20:11 | 1056a | - | - | ? | results/phase17_new_vectors/1056a_kernel_read_sweep_20261103_201104.txt |
| 2026-11-03 20:11 | 1057a | - | - | ? | results/phase17_new_vectors/1057a_fault_frame_dump_20261103_201152.txt |
| 2026-11-03 20:14 | 1001a | - | - | ? | results/phase17_new_vectors/1001a_kernel_map_sweep_20261103_201400.txt |
| 2026-11-03 20:19 | 1001a | - | - | ? | results/phase17_new_vectors/1001a_kernel_map_sweep_20261103_201929.txt |
| 2026-11-03 20:20 | 1058a | - | - | ? | results/phase17_new_vectors/1058a_image_4k_read_sweep_20261103_202034.txt |
| 2026-11-03 20:23 | 1058a | - | - | ? | results/phase17_new_vectors/1058a_image_4k_read_sweep_20261103_202351.txt |
| 2026-11-03 20:34 | 1001a | - | - | ? | results/phase17_new_vectors/1001a_kernel_map_sweep_20261103_203453.txt |
| 2026-11-03 20:35 | 1058a | - | - | ? | results/phase17_new_vectors/1058a_image_4k_read_sweep_20261103_203517.txt |
| 2026-11-03 20:38 | 1001a | - | - | ? | results/phase17_new_vectors/1001a_kernel_map_sweep_20261103_203810.txt |
| 2026-11-03 21:01 | 1058a | - | - | ? | results/phase17_new_vectors/1058a_image_4k_read_sweep_20261103_210113.txt |
| 2026-11-03 21:06 | 1001a | - | - | ? | results/phase17_new_vectors/1001a_kernel_map_sweep_20261103_210601.txt |
| 2026-11-03 21:06 | 1058a | - | - | ? | results/phase17_new_vectors/1058a_image_4k_read_sweep_20261103_210616.txt |
| 2026-11-03 21:09 | 1001a | - | - | ? | results/phase17_new_vectors/1001a_kernel_map_sweep_20261103_210911.txt |
| 2026-11-03 21:13 | 1058a | - | - | ? | results/phase17_new_vectors/1058a_image_4k_read_sweep_20261103_211325.txt |
| 2026-11-03 21:18 | 1059a | - | - | ? | results/phase17_new_vectors/1059a_sweep_step_debug_20261103_211808.txt |
| 2026-11-03 21:23 | 1058a | - | - | ? | results/phase17_new_vectors/1058a_image_4k_read_sweep_20261103_212310.txt |
| 2026-11-03 21:25 | 1058a | - | - | ? | results/phase17_new_vectors/1058a_image_4k_read_sweep_20261103_212500.txt |
| 2026-11-03 21:25 | 1058a | - | - | ? | results/phase17_new_vectors/1058a_image_4k_read_sweep_20261103_212523.txt |
| 2026-11-03 21:47 | 1058a | - | - | ? | results/phase17_new_vectors/1058a_image_4k_read_sweep_20261103_214712.txt |
| 2026-11-03 22:35 | 1061a | - | - | ? | results/phase17_new_vectors/1061a_pktinfo_free_reuse_20261103_223540.txt |
| 2026-11-03 22:35 | 1061a | - | - | ? | results/phase17_new_vectors/1061a_pktinfo_free_reuse_20261103_223554.txt |
| 2026-11-03 22:36 | 1061a | - | - | ? | results/phase17_new_vectors/1061a_pktinfo_free_reuse_20261103_223629.txt |
| 2026-11-03 22:36 | 1061a | - | - | ? | results/phase17_new_vectors/1061a_pktinfo_free_reuse_20261103_223641.txt |
| 2026-11-03 22:36 | 1061a | - | - | ? | results/phase17_new_vectors/1061a_pktinfo_free_reuse_20261103_223659.txt |
| 2026-11-03 22:37 | 1061a | - | - | ? | results/phase17_new_vectors/1061a_pktinfo_free_reuse_20261103_223706.txt |
| 2026-11-03 22:37 | 1061a | - | - | ? | results/phase17_new_vectors/1061a_pktinfo_free_reuse_20261103_223716.txt |
| 2026-11-03 22:37 | 1061a | - | - | ? | results/phase17_new_vectors/1061a_pktinfo_free_reuse_20261103_223731.txt |
| 2026-11-03 23:15 | 1062a | - | - | ? | results/phase17_new_vectors/1062a_sys615_stack_leak_20261103_231500.txt |
| 2026-11-03 23:20 | 1063a | - | - | ? | results/phase17_new_vectors/1063a_kern_file_direct_20261103_232000.txt |
| 2026-11-03 23:21 | 1063a | - | - | ? | results/phase17_new_vectors/1063a_kern_file_direct_20261103_232100.txt |
| 2026-11-03 23:30 | 56l | - | - | ? | results/phase14_final_push/56l_corrected_mib_probe_20261103_233000.txt |
| 2026-11-03 23:35 | 1065a | - | - | ? | results/phase17_new_vectors/1065a_umtx_op_matrix_20261103_233500.txt |
| 2026-11-03 23:37 | 1065a | - | - | ? | results/phase17_new_vectors/1065a_umtx_op_matrix_20261103_233720.txt |
| 2026-11-03 23:59 | 1065a | - | - | ? | results/phase17_new_vectors/1065a_umtx_op_matrix_20261103_235900.txt |
| 2026-11-04 00:15 | 1066a | - | - | ? | results/phase17_new_vectors/1066a_sys613_copyout_20261104_001500.txt |
| 2026-11-04 02:37 | p598v7 | - | - | ? | results/phase13_webkit/p598v7-layout-probe_20261104_023708.txt |
| 2026-11-04 03:39 | p598v8 | - | - | ? | results/phase13_webkit/p598v8-zero-seed_20261104_033947.txt |
| 2026-11-04 04:01 | p599v1v2 | - | - | ? | results/phase13_webkit/p599v1v2-gc-destructor_20261104_040100.txt |
| 2026-11-04 05:00 | p599v4 | - | - | ? | results/phase13_webkit/p599v4-gc-destructor-forge_20261104_050000.txt |
| 2026-11-04 05:15 | p599v4f | - | - | ? | results/phase13_webkit/p599v4f-two-phase-uaf_20261104_051500.txt |
| 2026-11-04 05:44 | p599v4i | - | - | ? | results/phase13_webkit/p599v4i-null-spray-test_20261104_054400.txt |
| 2026-11-04 06:23 | p600 | - | - | ? | results/phase13_webkit/p600-butterfly-gigacage_20261104_062300.txt |
| 2026-11-04 06:36 | p601 | - | - | ? | results/phase13_webkit/p601-dataview-overflow-wasm_20261104_063643.txt |
| 2026-11-04 06:42 | p602 | - | - | ? | results/phase13_webkit/p602-jit-flattendict_20261104_064226.txt |
| 2026-11-04 06:44 | p602b | - | - | ? | results/phase13_webkit/p602b-aggressive-flatten_20261104_064444.txt |
| 2026-11-04 07:04 | p604 | - | - | ? | results/phase13_webkit/p604-dfg-nan-confusion_20261104_070408.txt |
| 2026-11-04 07:10 | p605 | - | - | ? | results/phase13_webkit/p605-dfg-type-confusion_20261104_071039.txt |
| 2026-11-04 07:29 | p606 | - | - | ? | results/phase13_webkit/p606-cve-2024-23222-race_20261104_072900.txt |
| 2026-11-04 07:38 | p607 | - | - | ? | results/phase13_webkit/p607-dfg-race-fine_20261104_073800.txt |
| 2026-11-04 08:23 | p608h | - | - | ? | results/phase13_webkit/p608h_fine_iteration_20261104_082316.txt |
| 2026-11-04 08:26 | p608i | - | - | ? | results/phase13_webkit/p608i_ultra_fine_20261104_082631.txt |
| 2026-11-04 08:28 | p608j | - | - | ? | results/phase13_webkit/p608j_single_iteration_20261104_082857.txt |
| 2026-11-04 08:30 | p608k | - | - | ? | results/phase13_webkit/p608k_gc_force_20261104_083056.txt |
| 2026-11-04 08:32 | p608l | - | - | ? | results/phase13_webkit/p608l_gc_timing_20261104_083243.txt |
| 2026-11-04 08:34 | p608m | - | - | ? | results/phase13_webkit/p608m_accum_threshold_20261104_083458.txt |
| 2026-11-04 08:39 | p608n | - | - | ? | results/phase13_webkit/p608n_burst_vs_count_20261104_083956.txt |
| 2026-11-04 08:42 | p608o | - | - | ? | results/phase13_webkit/p608o_single_function_20261104_084251.txt |
| 2026-11-04 08:52 | p608p | - | - | ? | results/phase13_webkit/p608p_no_dfg_20261104_085200.txt |
| 2026-11-04 08:52 | p608q | - | - | ? | results/phase13_webkit/p608q_no_dfg_fine_20261104_085200.txt |
| 2026-11-04 08:55 | p608r | - | - | ? | results/phase13_webkit/p608r_resizable_vs_normal_20261104_085500.txt |
| 2026-11-04 09:04 | p608s | - | - | ? | results/phase13_webkit/p608s_corruption_detect_20261104_090400.txt |
| 2026-11-04 09:34 | 1068a | - | - | ? | results/phase17_new_vectors/1068a_sys587_foreign_pid_20261104_093419.txt |
| 2026-11-04 09:35 | 1067a | - | - | ? | results/phase17_new_vectors/1067a_notification_write_len_20261104_093504.txt |
| 2026-11-04 09:35 | 1067a | - | - | ? | results/phase17_new_vectors/1067a_notification_write_len_20261104_093517.txt |
| 2026-11-04 09:37 | 1040a | - | - | ? | results/phase17_new_vectors/1040a_622_cmd302_ptr_20261104_093743.txt |
| 2026-11-04 09:44 | 1004a | - | - | ? | results/phase17_new_vectors/1004a_kernel_half_sweep_20261104_094441.txt |
| 2026-11-04 09:47 | p609 | - | - | ? | results/phase13_webkit/p609_webp_vuln_test_20261104_094700.txt |
| 2026-11-04 09:47 | 1005a | - | - | ? | results/phase17_new_vectors/1005a_postboot_edges_20261104_094712.txt |
| 2026-11-04 09:49 | 1070a | - | - | ? | results/phase17_new_vectors/1070a_devfs_enum_20261104_094917.txt |
| 2026-11-04 09:50 | 1070a | - | - | ? | results/phase17_new_vectors/1070a_devfs_enum_20261104_095013.txt |
| 2026-11-04 09:51 | 1070a | - | - | ? | results/phase17_new_vectors/1070a_devfs_enum_20261104_095112.txt |
| 2026-11-04 09:51 | 1070a | - | - | ? | results/phase17_new_vectors/1070a_devfs_enum_20261104_095131.txt |
| 2026-11-04 09:52 | 1071a | - | - | ? | results/phase17_new_vectors/1071a_devfs_full_read_20261104_095227.txt |
| 2026-11-04 09:59 | p609b | - | - | ? | results/phase13_webkit/p609b_webp_oom_discriminate_20261104_095945.txt |
| 2026-11-04 10:05 | 1071a | - | - | ? | results/phase17_new_vectors/1071a_devfs_full_read_20261104_100515.txt |
| 2026-11-04 10:05 | 1072a | - | - | ? | results/phase17_new_vectors/1072a_622_cmd302_kaddr_20261104_100535.txt |
| 2026-11-04 10:09 | 1074a | - | - | ? | results/phase17_new_vectors/1074a_622_shape_sweep_full_20261104_100958.txt |
| 2026-11-04 10:11 | 1073a | - | - | ? | results/phase17_new_vectors/1073a_hidden_node_open_20261104_101148.txt |
| 2026-11-04 10:13 | 1075a | - | - | ? | results/phase17_new_vectors/1075a_device_ioctl_20261104_101328.txt |
| 2026-11-04 10:14 | p610 | - | - | ? | results/phase13_webkit/p610_png_heap_read_20261104_101400.txt |
| 2026-11-04 10:14 | 1076a | - | - | ? | results/phase17_new_vectors/1076a_camera_ioctl_20261104_101408.txt |
| 2026-11-04 10:22 | 1074a | - | - | ? | results/phase17_new_vectors/1074a_622_shape_sweep_full_20261104_102213.txt |
| 2026-11-04 10:29 | 1074a | - | - | ? | results/phase17_new_vectors/1074a_622_shape_sweep_full_20261104_102934.txt |
| 2026-11-04 10:29 | 1074a | - | - | ? | results/phase17_new_vectors/1074a_622_shape_sweep_full_20261104_102943.txt |
| 2026-11-04 10:35 | p611 | - | - | ? | results/phase13_webkit/p611_svg_filter_overread_20261104_103510.txt |
| 2026-11-04 10:39 | 1074a | - | - | ? | results/phase17_new_vectors/1074a_622_shape_sweep_full_20261104_103948.txt |
| 2026-11-04 10:44 | 1078a | - | - | ? | results/phase17_new_vectors/1078a_622_arm_handle_20261104_104443.txt |
| 2026-11-04 10:48 | 622 | - | - | ? | results/622_arm_cmd_20261104_104819.txt |
| 2026-11-04 10:48 | 622 | - | - | ? | results/622_arm_cmd_20261104_104828.txt |
| 2026-11-04 10:51 | 622 | - | - | ? | results/622_arm_cmd_20261104_105122.txt |
| 2026-11-04 10:51 | 622 | - | - | ? | results/622_arm_cmd_20261104_105123.txt |
| 2026-11-04 10:51 | 622 | - | - | ? | results/622_arm_cmd_20261104_105124.txt |
| 2026-11-04 10:51 | 622 | - | - | ? | results/622_arm_cmd_20261104_105125.txt |
| 2026-11-04 10:51 | 622 | - | - | ? | results/622_arm_cmd_20261104_105130.txt |
| 2026-11-04 10:51 | 622 | - | - | ? | results/622_arm_cmd_20261104_105131.txt |
| 2026-11-04 10:51 | 622 | - | - | ? | results/622_arm_cmd_20261104_105134.txt |
| 2026-11-04 10:51 | 622 | - | - | ? | results/622_arm_cmd_20261104_105135.txt |
| 2026-11-04 10:51 | 622 | - | - | ? | results/622_arm_cmd_20261104_105136.txt |
| 2026-11-04 10:51 | 622 | - | - | ? | results/622_arm_cmd_20261104_105153.txt |
| 2026-11-04 10:51 | 622 | - | - | ? | results/622_arm_cmd_20261104_105154.txt |
| 2026-11-04 10:51 | 622 | - | - | ? | results/622_arm_cmd_20261104_105155.txt |
| 2026-11-04 10:51 | 622 | - | - | ? | results/622_arm_cmd_20261104_105156.txt |
| 2026-11-04 10:51 | 622 | - | - | ? | results/622_arm_cmd_20261104_105157.txt |
| 2026-11-04 10:51 | 622 | - | - | ? | results/622_arm_cmd_20261104_105158.txt |
| 2026-11-04 10:52 | 622 | - | - | ? | results/622_arm_cmd_20261104_105208.txt |
| 2026-11-04 10:52 | 622 | - | - | ? | results/622_arm_cmd_20261104_105259.txt |
| 2026-11-04 10:53 | 622 | - | - | ? | results/622_arm_cmd_20261104_105300.txt |
| 2026-11-04 10:53 | 622 | - | - | ? | results/622_arm_cmd_20261104_105301.txt |
| 2026-11-04 10:53 | 622 | - | - | ? | results/622_arm_cmd_20261104_105310.txt |
| 2026-11-04 10:54 | 622 | - | - | ? | results/622_arm_cmd_20261104_105425.txt |
| 2026-11-04 10:55 | 622 | - | - | ? | results/622_arm_cmd_20261104_105528.txt |
| 2026-11-04 10:55 | 622 | - | - | ? | results/622_arm_cmd_20261104_105529.txt |
| 2026-11-04 10:55 | 622 | - | - | ? | results/622_arm_cmd_20261104_105531.txt |
| 2026-11-04 10:55 | 622 | - | - | ? | results/622_arm_cmd_20261104_105532.txt |
| 2026-11-04 10:55 | 622 | - | - | ? | results/622_arm_cmd_20261104_105533.txt |
| 2026-11-04 10:55 | 622 | - | - | ? | results/622_arm_cmd_20261104_105534.txt |
| 2026-11-04 10:55 | 622 | - | - | ? | results/622_arm_cmd_20261104_105535.txt |
| 2026-11-04 10:55 | 622 | - | - | ? | results/622_arm_cmd_20261104_105537.txt |
| 2026-11-04 10:55 | 622 | - | - | ? | results/622_arm_cmd_20261104_105538.txt |
| 2026-11-04 10:55 | 622 | - | - | ? | results/622_arm_cmd_20261104_105539.txt |
| 2026-11-04 10:55 | 622 | - | - | ? | results/622_arm_cmd_20261104_105540.txt |
| 2026-11-04 10:55 | 622 | - | - | ? | results/622_arm_cmd_20261104_105541.txt |
| 2026-11-04 10:55 | 622 | - | - | ? | results/622_arm_cmd_20261104_105542.txt |
| 2026-11-04 10:55 | 622 | - | - | ? | results/622_arm_cmd_20261104_105543.txt |
| 2026-11-04 10:55 | 622 | - | - | ? | results/622_arm_cmd_20261104_105551.txt |
| 2026-11-04 10:56 | 622 | - | - | ? | results/622_arm_cmd_20261104_105615.txt |
| 2026-11-04 10:56 | 622 | - | - | ? | results/622_arm_cmd_20261104_105616.txt |
| 2026-11-04 10:56 | 622 | - | - | ? | results/622_arm_cmd_20261104_105617.txt |
| 2026-11-04 10:56 | 622 | - | - | ? | results/622_arm_cmd_20261104_105618.txt |
| 2026-11-04 10:56 | 622 | - | - | ? | results/622_arm_cmd_20261104_105619.txt |
| 2026-11-04 10:56 | 622 | - | - | ? | results/622_arm_cmd_20261104_105628.txt |
| 2026-11-04 11:32 | p612 | - | - | ? | results/phase13_webkit/p612_t_determinism_20261104_113237.txt |
| 2026-11-04 12:06 | 1150a | - | - | ? | results/phase17_new_vectors/1150a_devfs_errno_20261104_120627.txt |
| 2026-11-04 12:07 | 1151a | - | - | ? | results/phase17_new_vectors/1151a_devfs_open_modes_20261104_120724.txt |
| 2026-11-04 12:08 | 1151a | - | - | ? | results/phase17_new_vectors/1151a_devfs_open_modes_20261104_120816.txt |
| 2026-11-04 12:08 | 1152a | - | - | ? | results/phase17_new_vectors/1152a_622_271_errno_20261104_120858.txt |
| 2026-11-04 13:11 | 1160a | - | - | ? | results/phase17_new_vectors/1160a_638_table_walk_20261104_131147.txt |
| 2026-11-04 13:12 | 1160a | - | - | ? | results/phase17_new_vectors/1160a_638_table_walk_20261104_131222.txt |
| 2026-11-04 13:13 | 1160a | - | - | ? | results/phase17_new_vectors/1160a_638_table_walk_20261104_131318.txt |
| 2026-11-04 13:14 | 1161a | - | - | ? | results/phase17_new_vectors/1161a_638_table_dump_20261104_131423.txt |
| 2026-11-04 13:18 | 1162a | - | - | ? | results/phase17_new_vectors/1162a_636_637_gate_639_abi_20261104_131810.txt |
| 2026-11-04 14:52 | 1163a | - | - | ? | results/phase17_new_vectors/1163a_639_five_slots_20261104_145220.txt |
| 2026-11-04 15:01 | 1164a | - | - | ? | results/phase17_new_vectors/1164a_638_tail_and_policy_20261104_150148.txt |
| 2026-11-04 15:29 | 1165a | - | - | ? | results/phase17_new_vectors/1165a_usb_ioctl_copyout_contents_20261104_152913.txt |
| 2026-11-04 15:32 | 56l | - | - | ? | results/phase14_final_push/56l_corrected_mib_probe_20261104_153236.txt |
| 2026-11-04 15:34 | 1166a | - | - | ? | results/phase17_new_vectors/1166a_417_selector_control_20261104_153445.txt |
| 2026-11-04 15:48 | 1170a | - | - | ? | results/phase17_new_vectors/1170a_mdbg_log_drain_20261104_154828.txt |
| 2026-11-04 15:53 | 601 | - | - | ? | results/601_cmd_20261104_155349.txt |
| 2026-11-04 15:53 | 601 | - | - | ? | results/601_cmd_20261104_155350.txt |
| 2026-11-04 15:53 | 601 | - | - | ? | results/601_cmd_20261104_155351.txt |
| 2026-11-04 15:53 | 601 | - | - | ? | results/601_cmd_20261104_155352.txt |
| 2026-11-04 15:53 | 601 | - | - | ? | results/601_cmd_20261104_155353.txt |
| 2026-11-04 15:54 | 601 | - | - | ? | results/601_cmd_20261104_155402.txt |
| 2026-11-04 15:56 | 1172a | - | - | ? | results/phase17_new_vectors/1172a_mdbg_mid_sweep_20261104_155634.txt |
| 2026-11-04 16:00 | 1173a | - | - | ? | results/phase17_new_vectors/1173a_libc_gadget_scan_20261104_160017.txt |
| 2026-11-04 16:04 | 1173a | - | - | ? | results/phase17_new_vectors/1173a_libc_gadget_scan_20261104_160427.txt |
| 2026-11-04 16:05 | 1175a | - | - | ? | results/phase17_new_vectors/1175a_loader_thread_api_20261104_160547.txt |
| 2026-11-04 16:06 | 1176a | - | - | ? | results/phase17_new_vectors/1176a_mdbg_threaded_sweep_20261104_160636.txt |
| 2026-11-04 16:06 | 1176a | - | - | ? | results/phase17_new_vectors/1176a_mdbg_threaded_sweep_20261104_160655.txt |
| 2026-11-04 16:07 | 1176b | - | - | ? | results/phase17_new_vectors/1176b_mdbg_threaded_sweep_20261104_160745.txt |
| 2026-11-04 16:08 | 1177a | - | - | ? | results/phase17_new_vectors/1177a_mdbg_sweep_high_20261104_160845.txt |
| 2026-11-04 16:09 | 1178a | - | - | ? | results/phase17_new_vectors/1178a_mdbg_drain_repeat_20261104_160925.txt |
| 2026-11-04 16:10 | 1179a | - | - | ? | results/phase17_new_vectors/1179a_mdbg_arg_shapes_20261104_161012.txt |
| 2026-11-04 16:11 | 1180a | - | - | ? | results/phase17_new_vectors/1180a_mdbg_sweep_30_4f_20261104_161101.txt |
| 2026-11-04 16:11 | 1181a | - | - | ? | results/phase17_new_vectors/1181a_mdbg_sweep_50_ff_20261104_161126.txt |
| 2026-11-04 16:12 | 1182a | - | - | ? | results/phase17_new_vectors/1182a_ymm_store_scan_20261104_161219.txt |
| 2026-11-04 16:20 | 1183a | - | - | ? | results/phase17_new_vectors/1183a_page_scan_20261104_162003.txt |
| 2026-11-04 16:23 | 1183a | - | - | ? | results/phase17_new_vectors/1183a_page_scan_20261104_162301.txt |
| 2026-11-04 16:24 | 1183b | - | - | ? | results/phase17_new_vectors/1183b_libkernel_text_locate_20261104_162413.txt |
| 2026-11-04 16:26 | 1184a | - | - | ? | results/phase17_new_vectors/1184a_eboot_ymm_scan_20261104_162647.txt |
| 2026-11-04 16:27 | 1184a | - | - | ? | results/phase17_new_vectors/1184a_eboot_ymm_scan_20261104_162729.txt |
| 2026-11-04 16:55 | 1185a | - | - | ? | results/phase17_new_vectors/1185a_gadget_window_dump_20261104_165528.txt |
| 2026-11-04 16:56 | 1186a | - | - | ? | results/phase17_new_vectors/1186a_eboot_dump_1mb_20261104_165602.txt |
| 2026-11-04 16:57 | 1187a | - | - | ? | results/phase17_new_vectors/1187a_ymm0_spill_test_20261104_165730.txt |
| 2026-11-04 17:00 | 1188a | - | - | ? | results/phase17_new_vectors/1188a_fcall_validate_20261104_170051.txt |
| 2026-11-04 17:02 | 1189a | - | - | ? | results/phase17_new_vectors/1189a_inchain_ymm_spill_20261104_170208.txt |
| 2026-11-04 17:04 | 1190a | - | - | ? | results/phase17_new_vectors/1190a_ymm_store_after_syscalls_20261104_170402.txt |
| 2026-11-04 17:05 | 1191a | - | - | ? | results/phase17_new_vectors/1191a_ymm0_poison_spill_20261104_170531.txt |
| 2026-11-04 17:27 | 1192a | - | - | ? | results/phase17_new_vectors/1192a_601_dispatcher_command_20261104_172719.txt |
| 2026-11-04 18:16 | 1193a | - | - | ? | results/phase17_new_vectors/1193a_601_errno_attach_flag_20261104_181636.txt |
| 2026-11-04 18:16 | 1193c | - | - | ? | results/phase17_new_vectors/1193c_601_cmd0_struct_vs_arg3_20261104_181632.txt |
| 2026-11-04 18:17 | 1194b | - | - | ? | results/phase17_new_vectors/1194b_601_arg2_write_leak_20261104_181707.txt |
| 2026-11-04 18:17 | 1194c | - | - | ? | results/phase17_new_vectors/1194c_601_type_gate_discriminator_20261104_181720.txt |
| 2026-11-04 18:17 | 1194d | - | - | ? | results/phase17_new_vectors/1194d_601_arg2_struct_consumers_20261104_181743.txt |
| 2026-11-04 18:18 | 1194e | - | - | ? | results/phase17_new_vectors/1194e_601_arg3_outptr_sweep_20261104_181806.txt |
| 2026-11-04 18:44 | 1195a | - | - | ? | results/phase17_new_vectors/1195a_601_attach_hunt_20261104_184447.txt |
| 2026-11-04 18:52 | 1196a | - | - | ? | results/phase17_new_vectors/1196a_virtual_query_all_magic_20261104_185203.txt |
| 2026-11-04 18:58 | 1196b | - | - | ? | results/phase17_new_vectors/1196b_sony_info_magic_sweep_20261104_185821.txt |
| 2026-11-04 18:59 | 1196c | - | - | ? | results/phase17_new_vectors/1196c_dynlib_get_info2_records_20261104_185910.txt |
| 2026-11-04 19:00 | 1197a | - | - | ? | results/phase17_new_vectors/1197a_sony_errno_census_20261104_190001.txt |
| 2026-11-04 19:49 | p553 | - | - | ? | results/phase13_webkit/p553_canvas_uaf_rw_20261104_194910.txt |
| 2026-11-04 19:54 | 1100a | - | - | ? | results/phase34_shm_race/1100a_shm_ftruncate_race_20261104_195438.txt |
| 2026-11-04 19:56 | 1100b | - | - | ? | results/phase34_shm_race/1100b_shm_race_small_20261104_195600.txt |
| 2026-11-04 20:00 | 1100b | - | - | ? | results/phase34_shm_race/1100b_shm_race_small_20261104_200010.txt |
| 2026-11-04 20:00 | 1100b | - | - | ? | results/phase34_shm_race/1100b_shm_race_small_20261104_200033.txt |
| 2026-11-04 20:01 | 1100b | - | - | ? | results/phase34_shm_race/1100b_shm_race_small_20261104_200149.txt |
| 2026-11-04 20:02 | 1100b | - | - | ? | results/phase34_shm_race/1100b_shm_race_small_20261104_200228.txt |
| 2026-11-04 20:02 | 1100b | - | - | ? | results/phase34_shm_race/1100b_shm_race_small_20261104_200258.txt |
| 2026-11-04 20:03 | 1100b | - | - | ? | results/phase34_shm_race/1100b_shm_race_small_20261104_200317.txt |
| 2026-11-04 20:05 | 1100c | - | - | ? | results/phase34_shm_race/1100c_shm_race_lua_20261104_200512.txt |
| 2026-11-04 20:08 | 1100d | - | - | ? | results/phase34_shm_race/1100d_shm_race_single_20261104_200815.txt |
| 2026-11-04 20:09 | 1101a | - | - | ? | results/phase34_shm_race/1101a_pipe2_sendfile_race_20261104_200908.txt |
| 2026-11-04 20:21 | 1102b | - | - | ? | results/phase34_shm_race/1102b_shm_race_dword2_20261104_202110.txt |
| 2026-11-04 20:28 | 1102c | - | - | ? | results/phase34_shm_race/1102c_shm_race_nodwq_20261104_202828.txt |
| 2026-11-04 20:34 | 1102d | - | - | ? | results/phase34_shm_race/1102d_shm_race_fixed_20261104_203451.txt |
| 2026-11-04 20:45 | 1104a | - | - | ? | results/phase34_shm_race/1104a_shm_truncread_test_20261104_204542.txt |
| 2026-11-04 20:47 | 1105a | - | - | ? | results/phase34_shm_race/1105a_shm_race_native_20261104_204745.txt |
| 2026-11-04 20:53 | 1106a | - | - | ? | results/phase34_shm_race/1106a_shm_race_tiny_20261104_205301.txt |
| 2026-11-04 20:56 | 1107a | - | - | ? | results/phase34_shm_race/1107a_shm_384b_pattern_20261104_205628.txt |
| 2026-11-04 20:57 | 1108a | - | - | ? | results/phase34_shm_race/1108a_shm_race_live_20261104_205725.txt |
| 2026-11-04 20:58 | 1109a | - | - | ? | results/phase34_shm_race/1109a_shm_race_10k_20261104_205842.txt |
| 2026-11-04 21:01 | 1110a | - | - | ? | results/phase34_shm_race/1110a_shm_race_wd_20261104_210120.txt |
| 2026-11-04 21:01 | 1198a | - | - | ? | results/phase17_new_vectors/1198a_dynlib_get_info_ex_records_20261104_210133.txt |
| 2026-11-04 21:02 | 1199a | - | - | ? | results/phase17_new_vectors/1199a_priv_grant_597_20261104_210201.txt |
| 2026-11-04 21:06 | 1110a | - | - | ? | results/phase34_shm_race/1110a_shm_race_wd_20261104_210618.txt |
| 2026-11-04 21:07 | 1199b | - | - | ? | results/phase17_new_vectors/1199b_597_arg_shapes_20261104_210744.txt |
| 2026-11-04 21:09 | 1111a | - | - | ? | results/phase34_shm_race/1111a_sendfile_ftrunc_race_20261104_210900.txt |
| 2026-11-04 21:18 | 1113a | - | - | ? | results/phase34_shm_race/1113a_sendfile_sanity_20261104_211850.txt |
| 2026-11-04 21:23 | 1114a | - | - | ? | results/phase34_shm_race/1114a_read_ftrunc_race_20261104_212359.txt |
| 2026-11-04 21:47 | 1200a | - | - | ? | results/phase17_new_vectors/1200a_ioctl_magic_differential_20261104_214714.txt |
| 2026-11-04 21:47 | 1200b | - | - | ? | results/phase17_new_vectors/1200b_ioctl_return_constant_20261104_214755.txt |
| 2026-11-04 21:49 | 1200c | - | - | ? | results/phase17_new_vectors/1200c_is_ioctl_real_20261104_214900.txt |
| 2026-11-04 21:50 | 1200d | - | - | ? | results/phase17_new_vectors/1200d_failure_reporting_20261104_215018.txt |
| 2026-11-04 21:51 | 1201a | - | - | ? | results/phase17_new_vectors/1201a_597_grant_errno_20261104_215119.txt |
| 2026-11-04 21:53 | 1200e | - | - | ? | results/phase17_new_vectors/1200e_devfs_ioctl_errno_20261104_215321.txt |
| 2026-11-04 21:53 | 1202a | - | - | ? | results/phase17_new_vectors/1202a_fd_taking_syscall_oracle_20261104_215350.txt |
| 2026-11-04 21:57 | 1203a | - | - | ? | results/phase17_new_vectors/1203a_localise_sweep_death_20261104_215717.txt |
| 2026-11-04 21:57 | 1203a | - | - | ? | results/phase17_new_vectors/1203a_localise_sweep_death_20261104_215754.txt |
| 2026-11-04 22:07 | 1204a | - | - | ? | results/phase17_new_vectors/1204a_547_shape_379_gate_20261104_220709.txt |
| 2026-11-04 22:07 | 1205a | - | - | ? | results/phase17_new_vectors/1205a_379_id10_sweep_20261104_220736.txt |
| 2026-11-04 22:09 | p595 | - | - | ? | results/phase13_webkit/p595-apng-overread_20261104_220908.txt |
| 2026-11-04 22:09 | 1206a | - | - | ? | results/phase17_new_vectors/1206a_379_id_space_20261104_220938.txt |
| 2026-11-04 22:13 | 1207a | - | - | ? | results/phase17_new_vectors/1207a_605_service_magic_live_20261104_221352.txt |
| 2026-11-04 22:23 | 1208a | - | - | ? | results/phase17_new_vectors/1208a_sony_range_branch_oracle_20261104_222301.txt |
| 2026-11-04 22:26 | 1208b | - | - | ? | results/phase17_new_vectors/1208b_sony_branch_oracle_part2_20261104_222609.txt |
| 2026-11-04 22:31 | 1209a | - | - | ? | results/phase17_new_vectors/1209a_636_tz_table_load_20261104_223151.txt |
| 2026-11-04 22:35 | 1210a | - | - | ? | results/phase17_new_vectors/1210a_643_a34_bit_sweep_20261104_223541.txt |
| 2026-11-04 22:35 | 1210a | - | - | ? | results/phase17_new_vectors/1210a_643_a34_bit_sweep_20261104_223550.txt |
| 2026-11-04 22:45 | 1211a | - | - | ? | results/phase17_new_vectors/1211a_aio_multi_wait_mode0_20261104_224549.txt |
| 2026-11-04 22:49 | p622 | - | - | ? | results/phase13_webkit/p622-cve-2023-41993_20261104_224917.txt |
| 2026-11-04 22:51 | 1212a | - | - | ? | results/phase17_new_vectors/1212a_r10_trampoline_20261104_225144.txt |
| 2026-11-04 22:56 | p621 | - | - | ? | results/phase13_webkit/p621-cve-2024-44308_20261104_225617.txt |
| 2026-11-04 23:07 | p620 | - | - | ? | results/phase13_webkit/p620-crash-backtrace_20261104_230750.txt |
| 2026-11-04 23:13 | 1198a | - | - | ? | results/phase17_new_vectors/1198a_dynlib_get_info_ex_records_20261104_231354.txt |
| 2026-11-04 23:18 | 1198b | - | - | ? | results/phase17_new_vectors/1198b_dynlib_get_info_ex_fixed_20261104_231800.txt |
| 2026-11-04 23:42 | 1199a | - | - | ? | results/phase17_new_vectors/1199a_fault_oracle_kaslr_20261104_234210.txt |
| 2026-11-04 23:44 | 1199b | - | - | ? | results/phase17_new_vectors/1199b_fault_oracle_upper_20261104_234410.txt |
| 2026-11-04 23:54 | 1199c | - | - | ? | results/phase17_new_vectors/1199c_fault_oracle_edges_20261104_235448.txt |
| 2026-11-05 | p629 | - | - | ? | results/phase13_webkit/p629_canvas2d_offset_map_20261105.txt |
| 2026-11-05 | p630 | - | - | ? | results/phase13_webkit/p630_textbase_leak_survey_20261105.txt |
| 2026-11-05 | p631 | - | - | ? | results/phase13_webkit/p631_webp_cve_2023_4863_20261105.txt |
| 2026-11-05 | p632 | - | - | ? | results/phase13_webkit/p632_cve_2025_43529_dfg_storebarrier_20261105.txt |
| 2026-11-05 | p633 | - | - | ? | results/phase13_webkit/p633_dom_stale_css_sidechannel_20261105.txt |
| 2026-11-05 | p634 | - | - | ? | results/phase13_webkit/p634_cve_2018_4416_structureid_20261105.txt |
| 2026-11-05 | p635 | - | - | ? | results/phase13_webkit/p635_cve_2026_43720_canvas_reentry_20261105.txt |
| 2026-11-05 | p636 | - | - | ? | results/phase13_webkit/p636_isoheap_gigacage_jit_20261105.txt |
| 2026-11-05 01:50 | 1300a | - | - | ? | results/phase34_kread_survey/1300a_kread_survey_20261105_015027.txt |
| 2026-11-05 01:55 | 1300b | - | - | ? | results/phase34_kread_survey/1300b_dlsym_real_handles_20261105_015555.txt |
| 2026-11-05 05:14 | 1400a | - | - | ? | results/phase14_kernel_read/1400a_microarch_gadget_scan_20261105_051451.txt |
| 2026-11-05 05:17 | 1400a | - | - | ? | results/phase14_kernel_read/1400a_microarch_gadget_scan_20261105_051711.txt |
| 2026-11-05 05:19 | 1400a | - | - | ? | results/phase14_kernel_read/1400a_microarch_gadget_scan_20261105_051931.txt |
| 2026-11-05 05:20 | 1400a | - | - | ? | results/phase14_kernel_read/1400a_microarch_gadget_scan_20261105_052053.txt |
| 2026-11-05 05:24 | 1400a | - | - | ? | results/phase14_kernel_read/1400a_microarch_gadget_scan_20261105_052442.txt |
| 2026-11-05 05:32 | 1400c | - | - | ? | results/phase14_kernel_read/1400c_rdtsc_ret_check_20261105_053235.txt |
| 2026-11-05 05:36 | 1401a | - | - | ? | results/phase14_kernel_read/1401a_timing_primitives_20261105_053645.txt |
| 2026-11-05 05:41 | 1402a | - | - | ? | results/phase14_kernel_read/1402a_rdtsc_child_thread_20261105_054111.txt |
| 2026-11-05 05:52 | 1403a | - | - | ? | results/phase14_kernel_read/1403a_srop_rdtsc_20261105_055253.txt |
| 2026-11-05 05:58 | 1403b | - | - | ? | results/phase14_kernel_read/1403b_child_rdtsc_20261105_055812.txt |
| 2026-11-05 06:02 | 1403c | - | - | ? | results/phase14_kernel_read/1403c_child_rdtsc_v2_20261105_060202.txt |
| 2026-11-05 06:04 | 1403c | - | - | ? | results/phase14_kernel_read/1403c_child_rdtsc_v2_20261105_060408.txt |
| 2026-11-05 06:05 | 1403c | - | - | ? | results/phase14_kernel_read/1403c_child_rdtsc_v2_20261105_060544.txt |
| 2026-11-05 06:14 | 1403d | - | - | ? | results/phase14_kernel_read/1403d_child_diag_20261105_061451.txt |
| 2026-11-05 06:16 | 1403e | - | - | ? | results/phase14_kernel_read/1403e_rdtsc_timing_20261105_061659.txt |
| 2026-11-05 06:20 | 1403f | - | - | ? | results/phase14_kernel_read/1403f_rdtsc_gadget_scan_20261105_062013.txt |
| 2026-11-05 06:22 | 1403g | - | - | ? | results/phase14_kernel_read/1403g_gadget_scan_v2_20261105_062209.txt |
| 2026-11-05 06:24 | 1403h | - | - | ? | results/phase14_kernel_read/1403h_gadget_scan_fast_20261105_062427.txt |
| 2026-11-05 06:26 | 1403h | - | - | ? | results/phase14_kernel_read/1403h_gadget_scan_fast_20261105_062628.txt |
| 2026-11-05 06:28 | 1403i | - | - | ? | results/phase14_kernel_read/1403i_text_boundary_20261105_062807.txt |
| 2026-11-05 06:29 | 1403h | - | - | ? | results/phase14_kernel_read/1403h_gadget_scan_fast_20261105_062908.txt |
| 2026-11-05 06:33 | 1403j | - | - | ? | results/phase14_kernel_read/1403j_check_gadgets_20261105_063316.txt |
| 2026-11-05 06:34 | 1403k | - | - | ? | results/phase14_kernel_read/1403k_final_scan_20261105_063445.txt |
| 2026-11-05 06:42 | 1403l | - | - | ? | results/phase14_kernel_read/1403l_loop_gadgets_20261105_064236.txt |
| 2026-11-05 06:46 | 1403m | - | - | ? | results/phase14_kernel_read/1403m_timer_thread_20261105_064635.txt |
| 2026-11-05 06:48 | 1403n | - | - | ? | results/phase14_kernel_read/1403n_read_gadgets_20261105_064837.txt |
| 2026-11-05 06:49 | 1403n | - | - | ? | results/phase14_kernel_read/1403n_read_gadgets_20261105_064911.txt |
| 2026-11-05 06:53 | 1403o | - | - | ? | results/phase14_kernel_read/1403o_rop_read_verify_20261105_065323.txt |
| 2026-11-05 06:55 | 1403o | - | - | ? | results/phase14_kernel_read/1403o_rop_read_verify_20261105_065537.txt |
| 2026-11-05 06:58 | 1403o | - | - | ? | results/phase14_kernel_read/1403o_rop_read_verify_20261105_065804.txt |
| 2026-11-05 07:01 | 1403p | - | - | ? | results/phase14_kernel_read/1403p_minimal_reader_20261105_070100.txt |
| 2026-11-05 07:02 | 1403p | - | - | ? | results/phase14_kernel_read/1403p_minimal_reader_20261105_070251.txt |
| 2026-11-05 07:04 | 1403q | - | - | ? | results/phase14_kernel_read/1403q_rop_timing_20261105_070410.txt |
| 2026-11-05 07:08 | 1403r | - | - | ? | results/phase14_kernel_read/1403r_timing_stats_20261105_070811.txt |
| 2026-11-05 07:09 | 1403r | - | - | ? | results/phase14_kernel_read/1403r_timing_stats_20261105_070936.txt |
| 2026-11-05 07:25 | 1404a | - | - | ? | results/phase14_kernel_read/1404a_aio669_count_boundary_20261105_072539.txt |
| 2026-11-05 07:33 | 1404b | - | - | ? | results/phase14_kernel_read/1404b_dev_read_survey_20261105_073324.txt |
| 2026-11-05 07:40 | 1404c | - | - | ? | results/phase14_kernel_read/1404c_dev_usb_deep_20261105_074013.txt |
| 2026-11-05 07:49 | p637 | - | - | ? | results/phase13_webkit/p637_cve_2025_31277_regexp_habt_20261105_074954.txt |
| 2026-11-05 07:58 | p638 | - | - | ? | results/phase13_webkit/p638_cve_2025_31277_escalate_20261105_075839.txt |
| 2026-11-05 08:04 | 93c6 | - | - | ? | results/phase23_newvuln/93c6_sndbuf_exploit_20261105_080421.txt |
| 2026-11-05 08:06 | p639 | - | - | ? | results/phase13_webkit/p639_habt_hole_write_discriminator_20261105_080658.txt |
| 2026-11-05 08:09 | 93c6 | - | - | ? | results/phase23_newvuln/93c6_sndbuf_exploit_20261105_080942.txt |
| 2026-11-05 08:09 | p640 | - | - | ? | results/phase13_webkit/p640_cross_realm_double_habt_20261105_080944.txt |
| 2026-11-05 08:11 | 93c6 | - | - | ? | results/phase23_newvuln/93c6_sndbuf_exploit_20261105_081149.txt |
| 2026-11-05 08:15 | 93c7 | - | - | ? | results/phase34_shm_race/93c7_pipe2_shm_race_20261105_081517.txt |
| 2026-11-05 08:18 | 93c8 | - | - | ? | results/phase34_shm_race/93c8_socket_race_deep_20261105_081802.txt |
| 2026-11-05 08:19 | 93c9 | - | - | ? | results/phase34_shm_race/93c9_poll_close_uaf_20261105_081916.txt |
| 2026-11-05 08:27 | 93d0 | - | - | ? | results/phase34_shm_race/93d0_dual_child_race_20261105_082719.txt |
| 2026-11-05 08:31 | p642 | - | - | ? | results/phase13_webkit/p642_relapse_primitives_test_20261105_083113.txt |
| 2026-11-05 08:34 | p641 | - | - | ? | results/phase13_webkit/p641_canvas2d_uaf_stale_read_20261105_083402.txt |
| 2026-11-05 08:41 | p643 | - | - | ? | results/phase13_webkit/p643_cve_2018_4233_createthis_20261105_084145.txt |
| 2026-11-05 08:43 | p644 | - | - | ? | results/phase13_webkit/p644_cve_2021_1789_enumerator_oob_20261105_084312.txt |
| 2026-11-05 08:45 | 93d1 | - | - | ? | results/phase34_shm_race/93d1_aio_heap_overflow_20261105_084526.txt |
| 2026-11-05 08:48 | p643v2 | - | - | ? | results/phase13_webkit/p643v2_cve_2018_4233_createthis_v2_20261105_084820.txt |
| 2026-11-05 08:50 | 93d2 | - | - | ? | results/phase34_shm_race/93d2_vm_race_deep_20261105_085059.txt |
| 2026-11-05 08:50 | p645 | - | - | ? | results/phase13_webkit/p645_cve_2020_9802_arithnegate_oob_20261105_085056.txt |
| 2026-11-05 08:53 | p646 | - | - | ? | results/phase13_webkit/p646_cve_2019_8623_licm_uninit_20261105_085344.txt |
| 2026-11-05 08:55 | 93d3 | - | - | ? | results/phase34_shm_race/93d3_kevent_sony_fuzz_20261105_085507.txt |
| 2026-11-05 08:56 | 93d4 | - | - | ? | results/phase34_shm_race/93d4_handle_race_20261105_085636.txt |
| 2026-11-05 09:05 | 93d5 | - | - | ? | results/phase34_shm_race/93d5_rack_tcp_probe_20261105_090502.txt |
| 2026-11-05 09:06 | 93d6 | - | - | ? | results/phase34_shm_race/93d6_dev_mmap_scan_20261105_090649.txt |
| 2026-11-05 09:07 | 1199d | - | - | ? | results/phase9_kaslr_defeat/1199d-spectre-prerequisites_20261105_090708.txt |
| 2026-11-05 09:08 | 1199e | - | - | ? | results/phase9_kaslr_defeat/1199e-spectre-gadget-fast_20261105_090851.txt |
| 2026-11-05 09:08 | 93d7 | - | - | ? | results/phase34_shm_race/93d7_dev_mmap_safe_20261105_090850.txt |
| 2026-11-05 09:10 | 93d8 | - | - | ? | results/phase34_shm_race/93d8_mmap_noread_20261105_091044.txt |
| 2026-11-05 09:12 | 1199f | - | - | ? | results/phase9_kaslr_defeat/1199f-rdtsc-context_20261105_091213.txt |
| 2026-11-05 09:15 | 93d9 | - | - | ? | results/phase34_shm_race/93d9_camera_child_read_20261105_091523.txt |
| 2026-11-05 09:20 | 1199g | - | - | ? | results/phase9_kaslr_defeat/1199g-timer-resolution_20261105_092010.txt |
| 2026-11-05 09:22 | 1199h | - | - | ? | results/phase9_kaslr_defeat/1199h-read-gadgets_20261105_092247.txt |
| 2026-11-05 09:30 | 1199i | - | - | ? | results/phase9_kaslr_defeat/1199i-counting-thread-poc_20261105_093032.txt |
| 2026-11-05 09:34 | 1199j | - | - | ? | results/phase9_kaslr_defeat/1199j-counting-thread-thr-new_20261105_093412.txt |
| 2026-11-05 09:36 | 1213a | - | - | ? | results/phase17_new_vectors/1213a_stub_harvest_r10_trampoline_20261105_093632.txt |
| 2026-11-05 09:58 | 1213c | - | - | ? | results/phase17_new_vectors/1213c_eboot_r10_census_20261105_095853.txt |
| 2026-11-05 09:59 | 1213d | - | - | ? | results/phase17_new_vectors/1213d_wide_tails_20261105_095919.txt |
| 2026-11-05 09:59 | 1214a | - | - | ? | results/phase17_new_vectors/1214a_eboot_dump_100000_20261105_095945.txt |
| 2026-11-05 09:59 | 1214b | - | - | ? | results/phase17_new_vectors/1214b_eboot_dump_200000_20261105_095951.txt |
| 2026-11-05 09:59 | 1214c | - | - | ? | results/phase17_new_vectors/1214c_eboot_dump_300000_20261105_095952.txt |
| 2026-11-05 10:01 | 1215a | - | - | ? | results/phase17_new_vectors/1215a_libc_dump_20261105_100131.txt |
| 2026-11-05 10:02 | 1215b | - | - | ? | results/phase17_new_vectors/1215b_libc_import_window_20261105_100207.txt |
| 2026-11-05 10:10 | 1216b | - | - | ? | results/phase17_new_vectors/1216b_stub_table_walk_cheap_20261105_101016.txt |
| 2026-11-05 10:10 | 1217a | - | - | ? | results/phase17_new_vectors/1217a_aio_mode0_trampoline_20261105_101040.txt |
| 2026-11-05 10:11 | 1218a | - | - | ? | results/phase17_new_vectors/1218a_trampoline_diff_test_20261105_101101.txt |
| 2026-11-05 10:11 | 1219a | - | - | ? | results/phase17_new_vectors/1219a_663_matrix_20261105_101125.txt |
| 2026-11-05 10:12 | 1219b | - | - | ? | results/phase17_new_vectors/1219b_mode0_guard_location_20261105_101203.txt |
| 2026-11-05 10:14 | 1220a | - | - | ? | results/phase17_new_vectors/1220a_379_prot_trampoline_20261105_101406.txt |
| 2026-11-05 10:24 | 1221a | - | - | ? | results/phase17_new_vectors/1221a_stock_vs_trampoline_20261105_102419.txt |
| 2026-11-05 10:38 | 1222a | - | - | ? | results/phase17_new_vectors/1222a_socket_ioctl_leak_20261105_103857.txt |
| 2026-11-05 10:47 | 1223a | - | - | ? | results/phase17_new_vectors/1223a_blockpool_handle_20261105_104739.txt |
| 2026-11-05 11:14 | 93e2 | - | - | ? | results/phase34_shm_race/93e2_poll_close_race_20261105_111424.txt |
| 2026-11-05 11:16 | 93e3 | - | - | ? | results/phase34_shm_race/93e3_poll_uaf_tighten_20261105_111627.txt |
| 2026-11-05 11:19 | 93e4 | - | - | ? | results/phase34_shm_race/93e4_kqueue_close_race_20261105_111901.txt |
| 2026-11-05 11:22 | 1223b | - | - | ? | results/phase17_new_vectors/1223b_blockpool_map_20261105_112255.txt |
| 2026-11-05 11:23 | 93e5 | - | - | ? | results/phase34_shm_race/93e5_close_dup2_race_20261105_112333.txt |
| 2026-11-05 11:23 | 1223c | - | - | ? | results/phase17_new_vectors/1223c_blockpool_va_20261105_112324.txt |
| 2026-11-05 11:24 | 1223d | - | - | ? | results/phase17_new_vectors/1223d_blockpool_fd_test_20261105_112401.txt |
| 2026-11-05 11:25 | 1224a | - | - | ? | results/phase17_new_vectors/1224a_blockpool_determinism_20261105_112545.txt |
| 2026-11-05 11:26 | 1224b | - | - | ? | results/phase17_new_vectors/1224b_blockpool_fdlimit_20261105_112602.txt |
| 2026-11-05 11:31 | 1224c | - | - | ? | results/phase17_new_vectors/1224c_blockpool_fresh_mmap_20261105_113133.txt |
| 2026-11-05 11:31 | 1225a | - | - | ? | results/phase17_new_vectors/1225a_routes_first_contact_20261105_113155.txt |
| 2026-11-05 11:34 | 1226a | - | - | ? | results/phase17_new_vectors/1226a_dmem_container_20261105_113410.txt |
| 2026-11-05 11:34 | 1227a | - | - | ? | results/phase17_new_vectors/1227a_ucontext_dynlib_leak_20261105_113433.txt |
| 2026-11-05 11:34 | 1227b | - | - | ? | results/phase17_new_vectors/1227b_thr_self_pointer_20261105_113451.txt |
| 2026-11-05 11:38 | 1228a | - | - | ? | results/phase17_new_vectors/1228a_ucontext_family_20261105_113800.txt |
| 2026-11-05 11:38 | 1228b | - | - | ? | results/phase17_new_vectors/1228b_ucontext_mmapstack_20261105_113820.txt |
| 2026-11-05 11:38 | 1228b | - | - | ? | results/phase17_new_vectors/1228b_ucontext_mmapstack_20261105_113835.txt |
| 2026-11-05 11:38 | 1228c | - | - | ? | results/phase17_new_vectors/1228c_ucontext_156c_offsets_20261105_113856.txt |
| 2026-11-05 11:43 | 1229a | - | - | ? | results/phase17_new_vectors/1229a_ucontext_layout_20261105_114304.txt |
| 2026-11-05 11:46 | 1230a | - | - | ? | results/phase17_new_vectors/1230a_blockpool_handle_type_20261105_114659.txt |
| 2026-11-05 11:51 | 1231a | - | - | ? | results/phase17_new_vectors/1231a_aio_write_source_20261105_115149.txt |
| 2026-11-05 12:11 | 1001a | - | - | ? | results/phase17_new_vectors/1001a_kernel_map_sweep_20261105_121144.txt |
| 2026-11-05 12:12 | 1231b | - | - | ? | results/phase17_new_vectors/1231b_aio_write_dontwait_20261105_121208.txt |
| 2026-11-05 12:12 | 1232a | - | - | ? | results/phase17_new_vectors/1232a_aio_kernel_read_20261105_121221.txt |
| 2026-11-05 12:13 | 1233a | - | - | ? | results/phase17_new_vectors/1233a_kernel_mem_files_20261105_121317.txt |
| 2026-11-05 12:18 | 93e8 | - | - | ? | results/phase34_shm_race/93e8_close_race_diagnostic_20261105_121818.txt |
| 2026-11-05 12:21 | 93e9 | - | - | ? | results/phase34_shm_race/93e9_close_race_delayed_20261105_122100.txt |
| 2026-11-05 12:22 | 93f | - | - | ? | results/phase34_shm_race/93f_blocking_close_race_20261105_122232.txt |
| 2026-11-05 12:24 | 94a | - | - | ? | results/phase34_shm_race/94a_shm_ftruncate_race_20261105_122406.txt |
| 2026-11-05 12:25 | 1234a | - | - | ? | results/phase17_new_vectors/1234a_poll_close_race_20261105_122552.txt |
| 2026-11-05 12:26 | 94b | - | - | ? | results/phase34_shm_race/94b_sendfile_truncate_race_20261105_122629.txt |
| 2026-11-05 12:41 | 1234b | - | - | ? | results/phase17_new_vectors/1234b_fd_reuse_read_20261105_124109.txt |
| 2026-11-05 12:45 | 1235a | - | - | ? | results/phase17_new_vectors/1235a_aio_mode3_guard_20261105_124519.txt |
| 2026-11-05 12:48 | 94c | - | - | ? | results/phase34_shm_race/94c_sendfile_behavior_20261105_124858.txt |
| 2026-11-05 12:53 | 1236a | - | - | ? | results/phase17_new_vectors/1236a_aio_mode_space_zero_ids_20261105_125350.txt |
| 2026-11-05 12:56 | 1237b | - | - | ? | results/phase17_new_vectors/1237b_suspended_in_syscall_ctx_20261105_125603.txt |
| 2026-11-05 12:57 | 1237c | - | - | ? | results/phase17_new_vectors/1237c_suspend_in_poll_20261105_125717.txt |
| 2026-11-05 13:07 | 1238a | - | - | ? | results/phase17_new_vectors/1238a_tid_space_pid_filter_20261105_130709.txt |
| 2026-11-05 13:12 | 95a | - | - | ? | results/phase34_shm_race/95a_setitimer_watchdog_20261105_131221.txt |
| 2026-11-05 13:12 | 1240a | - | - | ? | results/phase17_new_vectors/1240a_physhm_copyin_20261105_131220.txt |
| 2026-11-05 13:14 | 94d | - | - | ? | results/phase34_shm_race/94d_sendfile_tcp_race_20261105_131429.txt |
| 2026-11-05 13:19 | 96a | - | - | ? | results/phase34_shm_race/96a_gc_ioctl_close_race_20261105_131911.txt |
| 2026-11-05 13:25 | 96a | - | - | ? | results/phase34_shm_race/96a_gc_ioctl_close_race_20261105_132554.txt |
| 2026-11-05 13:27 | 97a | - | - | ? | results/phase34_shm_race/97a_shm_ftruncate_mmap_race_20261105_132700.txt |
| 2026-11-05 13:54 | 1241a | - | - | ? | results/phase17_new_vectors/1241a_sendfile_presence_20261105_135444.txt |
| 2026-11-05 13:54 | 1242a | - | - | ? | results/phase17_new_vectors/1242a_sys532_cmd31_gate_20261105_135459.txt |
| 2026-11-05 14:01 | 98a | - | - | ? | results/phase34_shm_race/98a_mmap_munmap_race_20261105_140102.txt |
| 2026-11-05 14:05 | 1243a | - | - | ? | results/phase17_new_vectors/1243a_sys587_shape_20261105_140511.txt |
| 2026-11-05 14:07 | 98a | - | - | ? | results/phase34_shm_race/98a_mmap_munmap_race_20261105_140715.txt |
| 2026-11-05 14:09 | 98b | - | - | ? | results/phase34_shm_race/98b_mmap_munmap_race_v2_20261105_140924.txt |
| 2026-11-05 14:13 | 1199k | - | - | ? | results/phase9_kaslr_defeat/1199k-single-counter-test_20261105_141334.txt |
| 2026-11-05 14:13 | 1244a | - | - | ? | results/phase17_new_vectors/1244a_aio_mode_guard_coverage_20261105_141334.txt |
| 2026-11-05 14:24 | 1199k | - | - | ? | results/phase9_kaslr_defeat/1199k-single-counter-test_20261105_142445.txt |
| 2026-11-05 14:32 | 1199k | - | - | ? | results/phase9_kaslr_defeat/1199k-single-counter-test_20261105_143249.txt |
| 2026-11-05 14:35 | 1199k | - | - | ? | results/phase9_kaslr_defeat/1199k-single-counter-test_20261105_143542.txt |
| 2026-11-05 14:40 | 1199k | - | - | ? | results/phase9_kaslr_defeat/1199k-single-counter-test_20261105_144026.txt |
| 2026-11-05 14:44 | 1199k | - | - | ? | results/phase9_kaslr_defeat/1199k-single-counter-test_20261105_144459.txt |
| 2026-11-05 14:49 | 1199k | - | - | ? | results/phase9_kaslr_defeat/1199k-single-counter-test_20261105_144943.txt |
| 2026-11-05 14:56 | 1199k | - | - | ? | results/phase9_kaslr_defeat/1199k-single-counter-test_20261105_145638.txt |
| 2026-11-05 14:59 | p570 | - | - | ? | results/phase13_webkit/p570_browser_launch_20261105_145944.txt |
| 2026-11-05 15:06 | 1199l | - | - | ? | results/phase9_kaslr_defeat/1199l-counting-timer_20261105_150604.txt |
| 2026-11-05 15:08 | 1199l | - | - | ? | results/phase9_kaslr_defeat/1199l-counting-timer_20261105_150825.txt |
| 2026-11-05 15:09 | 1199l | - | - | ? | results/phase9_kaslr_defeat/1199l-counting-timer_20261105_150946.txt |
| 2026-11-05 15:10 | 1245a | - | - | ? | results/phase17_new_vectors/1245a_uninit_copyout_dynamic_20261105_151028.txt |
| 2026-11-05 15:12 | 1199l | - | - | ? | results/phase9_kaslr_defeat/1199l-counting-timer_20261105_151235.txt |
| 2026-11-05 15:16 | 1199m | - | - | ? | results/phase9_kaslr_defeat/1199m-cache-timing_20261105_151615.txt |
| 2026-11-05 15:25 | 1245a | - | - | ? | results/phase17_new_vectors/1245a_native_exec_feasibility_20261105_152559.txt |
| 2026-11-05 15:27 | 1245b | - | - | ? | results/phase17_new_vectors/1245b_exec_rdtsc_clflush_20261105_152714.txt |
| 2026-11-05 15:29 | p572 | - | - | ? | results/p572_browser_scan_20261105_152941.txt |
| 2026-11-05 15:30 | 1199n | - | - | ? | results/phase9_kaslr_defeat/1199n-kernel-cache-footprint_20261105_153031.txt |
| 2026-11-05 15:34 | p573 | - | - | ? | results/p573_browser_launch_20261105_153403.txt |
| 2026-11-05 15:35 | 1199o | - | - | ? | results/phase9_kaslr_defeat/1199o-spectre-v1-discriminator_20261105_153500.txt |
| 2026-11-05 15:37 | p574 | - | - | ? | results/p574_sysservice_exports_20261105_153706.txt |
| 2026-11-05 15:38 | p575 | - | - | ? | results/p575_lua_api_scan_20261105_153822.txt |
| 2026-11-05 15:39 | 1199p | - | - | ? | results/phase9_kaslr_defeat/1199p-spectre-oob-range_20261105_153930.txt |
| 2026-11-05 15:39 | p576 | - | - | ? | results/p576_dlsym_browser_20261105_153926.txt |
| 2026-11-05 15:40 | p577 | - | - | ? | results/p577_raw_dlsym_20261105_154021.txt |
| 2026-11-05 15:40 | p578 | - | - | ? | results/p578_kernel_rw_check_20261105_154052.txt |
| 2026-11-05 15:41 | p579 | - | - | ? | results/p579_ipv6_exploit_20261105_154129.txt |
| 2026-11-05 15:42 | p580 | - | - | ? | results/p580_fw_offsets_20261105_154208.txt |
| 2026-11-05 15:42 | p581 | - | - | ? | results/p581_ofiles_setup_20261105_154259.txt |
| 2026-11-05 15:44 | p582 | - | - | ? | results/p582_page_walk_20261105_154401.txt |
| 2026-11-05 15:44 | 1247b | - | - | ? | results/phase17_new_vectors/1247b_dmem_physical_sweep_20261105_154409.txt |
| 2026-11-05 15:44 | 1247b | - | - | ? | results/phase17_new_vectors/1247b_dmem_physical_sweep_20261105_154430.txt |
| 2026-11-05 15:44 | 1248a | - | - | ? | results/phase17_new_vectors/1248a_exec_page_hunt_20261105_154412.txt |
| 2026-11-05 15:44 | 1249a | - | - | ? | results/phase17_new_vectors/1249a_sys607_path_oracle_20261105_154410.txt |
| 2026-11-05 15:48 | 1199q | - | - | ? | results/phase9_kaslr_defeat/1199q-spectre-fstat-fd_20261105_154802.txt |
| 2026-11-05 15:48 | p583 | - | - | ? | results/p583_kernel_lua_dump_20261105_154827.txt |
| 2026-11-05 15:49 | p584 | - | - | ? | results/p584_full_kernel_lua_20261105_154921.txt |
| 2026-11-05 15:50 | p585 | - | - | ? | results/p585_find_exploit_20261105_155031.txt |
| 2026-11-05 15:52 | p586 | - | - | ? | results/p586_launch_browser_20261105_155203.txt |
| 2026-11-05 15:54 | p587 | - | - | ? | results/p587_ipv6_race_20261105_155414.txt |
| 2026-11-05 16:56 | 1249a | - | - | ? | results/phase17_new_vectors/1249a_sys607_path_oracle_20261105_165652.txt |
| 2026-11-05 16:57 | 1250a | - | - | ? | results/phase17_new_vectors/1250a_shm_faultin_and_exec_20261105_165710.txt |
| 2026-11-05 16:57 | 1250b | - | - | ? | results/phase17_new_vectors/1250b_shm_shape_and_copyin_20261105_165752.txt |
| 2026-11-05 16:58 | 1250c | - | - | ? | results/phase17_new_vectors/1250c_shm_object_inventory_20261105_165829.txt |
| 2026-11-05 17:01 | 1251a | - | - | ? | results/phase17_new_vectors/1251a_674_calibration_20261105_170156.txt |
| 2026-11-05 17:07 | 1251a | - | - | ? | results/phase17_new_vectors/1251a_674_calibration_20261105_170708.txt |
| 2026-11-05 17:07 | 1252a | - | - | ? | results/phase17_new_vectors/1252a_exec_surface_map_20261105_170742.txt |
| 2026-11-05 21:00 | 1253a | - | - | ? | results/phase17_new_vectors/1253a_sysent_tail_sigsys_20261105_210052.txt |
| 2026-11-05 21:01 | 1254a | - | - | ? | results/phase17_new_vectors/1254a_kill_list_presence_20261105_210158.txt |
| 2026-11-05 21:03 | 1255a | - | - | ? | results/phase17_new_vectors/1255a_presence_map_538_676_20261105_210306.txt |
| 2026-11-05 21:03 | 1256a | - | - | ? | results/phase17_new_vectors/1256a_presence_map_622_676_20261105_210353.txt |
| 2026-11-05 21:34 | 1199a | - | - | ? | results/1199a_20261105_213431.txt |
| 2026-11-06 00:06 | 500a | - | - | ? | results/phase23_cve_2026/500a_poll_close_race_20261106_000628.txt |
| 2026-11-06 00:09 | 500b | - | - | ? | results/phase23_cve_2026/500b_poll_close_minimal_20261106_000923.txt |
| 2026-11-06 00:23 | 500c | - | - | ? | results/phase23_cve_2026/500c_poll_close_gated_20261106_002340.txt |
| 2026-11-06 00:27 | 500d | - | - | ? | results/phase23_cve_2026/500d_poll_close_spray_20261106_002740.txt |
| 2026-11-06 00:32 | 500e | - | - | ? | results/phase23_cve_2026/500e_poll_close_doublepoll_20261106_003229.txt |
| 2026-11-06 00:35 | 500e | - | - | ? | results/phase23_cve_2026/500e_poll_close_doublepoll_20261106_003546.txt |
| 2026-11-06 01:11 | 500f | - | - | ? | results/phase23_cve_2026/500f_kqueue_crosszone_spray_20261106_011110.txt |
| 2026-11-06 01:15 | 500g | - | - | ? | results/phase23_cve_2026/500g_sockopt_spray_sweep_20261106_011530.txt |
| 2026-11-06 01:25 | 500h | - | - | ? | results/phase23_cve_2026/500h_recvmsg_iov_spray_20261106_012529.txt |
| 2026-11-06 01:46 | 500i | - | - | ? | results/phase23_cve_2026/500i_si_mtx_offset_scan_20261106_014631.txt |
| 2026-11-06 01:57 | 500j | - | - | ? | results/phase23_cve_2026/500j_precision_retest_20261106_015755.txt |
| 2026-11-06 02:13 | 500k | - | - | ? | results/phase23_cve_2026/500k_crash_oracle_20261106_021322.txt |
| 2026-11-06 02:25 | 500l | - | - | ? | results/phase23_cve_2026/500l_page_level_spray_20261106_022538.txt |
| 2026-11-06 02:31 | 500m | - | - | ? | results/phase23_cve_2026/500m_multisize_spray_20261106_023158.txt |
| 2026-11-06 04:04 | 500n | - | - | ? | results/phase23_cve_2026/500n_same_cpu_readback_oracle_20261106_040421.txt |
| 2026-11-06 04:11 | 500n | - | - | ? | results/phase23_cve_2026/500n_same_cpu_readback_oracle_20261106_041102.txt |
| 2026-11-06 04:53 | 500o | - | - | ? | results/phase23_cve_2026/500o_safe_reclaim_oracle_20261106_045302.txt |
| 2026-11-06 14:37 | 1331a | - | - | ? | results/1331a_20261106_143746.txt |
| 2026-11-06 14:38 | 1332a | - | - | ? | results/1332a_20261106_143858.txt |
| 2026-11-06 14:40 | 1334a | - | - | ? | results/1334a_20261106_144023.txt |
| 2026-11-06 14:41 | 1334b | - | - | ? | results/1334b_20261106_144105.txt |
| 2026-11-06 14:43 | 1334c | - | - | ? | results/1334c_20261106_144345.txt |
| 2026-11-06 14:48 | 1334c | - | - | ? | results/1334c_20261106_144823.txt |
| 2026-11-06 14:50 | 1334c | - | - | ? | results/1334c_20261106_145045.txt |
| 2026-11-06 14:56 | 1335a | - | - | ? | results/1335a_20261106_145651.txt |
| 2026-11-06 14:58 | 1335a | - | - | ? | results/1335a_20261106_145830.txt |
| 2026-11-06 15:00 | 1335a | - | - | ? | results/1335a_20261106_150042.txt |
| 2026-11-06 15:01 | 1335a | - | - | ? | results/1335a_20261106_150130.txt |
| 2026-11-06 15:06 | 1336a | - | - | ? | results/1336a_20261106_150621.txt |
| 2026-11-06 15:07 | 1337a | - | - | ? | results/1337a_20261106_150723.txt |
| 2026-11-06 15:08 | 1337a | - | - | ? | results/1337a_20261106_150821.txt |
| 2026-11-06 16:15 | 1338a | - | - | ? | results/1338a_20261106_161521.txt |
| 2026-11-06 16:23 | 1338a | - | - | ? | results/1338a_20261106_162334.txt |
| 2026-11-06 16:59 | 1339a | - | - | ? | results/1339a_20261106_165911.txt |
| 2026-11-06 17:04 | 1339a | - | - | ? | results/1339a_20261106_170440.txt |
| 2026-11-06 17:05 | 1339a | - | - | ? | results/1339a_20261106_170531.txt |
| 2026-11-06 17:06 | 1339a | - | - | ? | results/1339a_20261106_170625.txt |
| 2026-11-06 17:11 | 1339b | - | - | ? | results/1339b_diag_20261106_171149.txt |
| 2026-11-06 17:13 | 1339b | - | - | ? | results/1339b_diag_20261106_171301.txt |
| 2026-11-06 17:18 | 1339c | - | - | ? | results/1339c_single_20261106_171824.txt |
| 2026-11-06 17:20 | 1339c | - | - | ? | results/1339c_single_20261106_172019.txt |
| 2026-11-06 17:24 | 1339d | - | - | ? | results/1339d_r8test_20261106_172443.txt |
| 2026-11-06 17:47 | 1339e | - | - | ? | results/1339e_r8only_20261106_174727.txt |
| 2026-11-06 17:49 | 1339g | - | - | ? | results/1339g_opt25_child_20261106_174923.txt |
| 2026-11-06 17:51 | 1339h | - | - | ? | results/1339h_gadget_search_20261106_175128.txt |
| 2026-11-06 17:53 | 1339i | - | - | ? | results/1339i_r8_across_20261106_175341.txt |
| 2026-11-06 17:56 | 1339j | - | - | ? | results/1339j_mass_race_20261106_175655.txt |
| 2026-11-06 17:58 | 1339j | - | - | ? | results/1339j_mass_race_20261106_175852.txt |
| 2026-11-06 18:06 | 1339j | - | - | ? | results/1339j_mass_race_20261106_180636.txt |
| 2026-11-06 18:19 | 1339j | - | - | ? | results/1339j_mass_race_20261106_181929.txt |
| 2026-11-06 18:22 | 1339j | - | - | ? | results/1339j_mass_race_20261106_182245.txt |
| 2026-11-06 18:27 | 1339j | - | - | ? | results/1339j_mass_race_20261106_182744.txt |
| 2026-11-06 18:41 | 1339j | - | - | ? | results/1339j_mass_race_20261106_184103.txt |
| 2026-11-06 18:50 | 1339j | - | - | ? | results/1339j_mass_race_20261106_185021.txt |
| 2026-11-06 19:44 | 1339k | - | - | ? | results/1339k_multi_child_20261106_194414.txt |
| 2026-11-06 19:47 | 1339k | - | - | ? | results/1339k_multi_child_20261106_194739.txt |
| 2026-11-06 19:48 | 1339k | - | - | ? | results/1339k_multi_child_20261106_194833.txt |
| 2026-11-06 19:52 | 1339L | - | - | ? | results/1339L_parent_use_20261106_195201.txt |
| 2026-11-06 19:54 | 1339m | - | - | ? | results/1339m_wide_race_20261106_195441.txt |
| 2026-11-06 19:55 | 1339n | - | - | ? | results/1339n_cmsg_test_20261106_195556.txt |
| 2026-11-06 19:59 | 1339m | - | - | ? | results/1339m_wide_race_20261106_195920.txt |
| 2026-11-06 20:00 | 1339m | - | - | ? | results/1339m_wide_race_20261106_200054.txt |
| 2026-11-06 20:07 | 1339p | - | - | ? | results/1339p_safe_race_20261106_200705.txt |
| 2026-11-06 20:09 | 1339p | - | - | ? | results/1339p_safe_race_20261106_200932.txt |
| 2026-11-06 20:11 | 1339p | - | - | ? | results/1339p_safe_race_20261106_201101.txt |
| 2026-11-06 20:14 | 1339p | - | - | ? | results/1339p_safe_race_20261106_201403.txt |
| 2026-11-06 20:20 | 1339q | - | - | ? | results/1339q_diag_20261106_202020.txt |
| 2026-11-06 20:20 | 1339q | - | - | ? | results/1339q_diag_20261106_202041.txt |
| 2026-11-06 20:22 | 1339r | - | - | ? | results/1339r_race_fresh_stacks_20261106_202250.txt |
| 2026-11-06 20:32 | 1339s | - | - | ? | results/1339s_r8_persist_20261106_203218.txt |
| 2026-11-06 20:35 | 1339s | - | - | ? | results/1339s_r8_persist_20261106_203507.txt |
| 2026-11-06 20:35 | 1339s | - | - | ? | results/1339s_r8_persist_20261106_203555.txt |
| 2026-11-06 20:59 | 1339t | - | - | ? | results/1339t_race_spray_20261106_205920.txt |
| 2026-11-06 21:06 | 1339u | - | - | ? | results/1339u_symmetric_diag_20261106_210659.txt |
| 2026-11-06 21:12 | 1339v | - | - | ? | results/1339v_fast_race_20261106_211253.txt |
| 2026-11-06 21:19 | 1339v | - | - | ? | results/1339v_fast_race_20261106_211930.txt |
| 2026-11-06 21:20 | 1339v | - | - | ? | results/1339v_fast_race_20261106_212041.txt |
| 2026-11-06 21:21 | 1339v | - | - | ? | results/1339v_fast_race_20261106_212102.txt |
| 2026-11-06 21:23 | 1339v | - | - | ? | results/1339v_fast_race_20261106_212336.txt |
| 2026-11-06 21:29 | 1339w | - | - | ? | results/1339w_aggressive_20261106_212945.txt |
| 2026-11-06 21:30 | 1339w | - | - | ? | results/1339w_aggressive_20261106_213039.txt |
| 2026-11-06 21:31 | 1339w | - | - | ? | results/1339w_aggressive_20261106_213146.txt |
| 2026-11-06 21:38 | 1339x | - | - | ? | results/1339x_pinned_20261106_213856.txt |
| 2026-11-06 21:40 | 1339x | - | - | ? | results/1339x_pinned_20261106_214017.txt |
| 2026-11-06 21:44 | 1339y | - | - | ? | results/1339y_exhaust_20261106_214417.txt |
| 2026-11-06 22:03 | 1339z | - | - | ? | results/1339z_scatter_20261106_220300.txt |
| 2026-11-06 22:03 | 1339z | - | - | ? | results/1339z_scatter_20261106_220332.txt |
| 2026-11-06 22:03 | 1339z | - | - | ? | results/1339z_scatter_20261106_220349.txt |
| 2026-11-06 22:04 | 1339z | - | - | ? | results/1339z_scatter_20261106_220450.txt |
| 2026-11-06 22:09 | 1339z | - | - | ? | results/1339z_scatter_20261106_220926.txt |
| 2026-11-06 22:12 | 1340a | - | - | ? | results/1340a_toctou_20261106_221226.txt |
| 2026-11-06 22:14 | 1340b | - | - | ? | results/1340b_lean_20261106_221455.txt |
| 2026-11-06 22:26 | 1340c | - | - | ? | results/1340c_pinned_spray_20261106_222630.txt |
| 2026-11-06 22:37 | 1340d | - | - | ? | results/1340d_stagger_20261106_223731.txt |
| 2026-11-06 22:43 | 1340e | - | - | ? | results/1340e_diagnostic_20261106_224319.txt |
| 2026-11-06 22:46 | 1340e | - | - | ? | results/1340e_diagnostic_20261106_224614.txt |
| 2026-11-06 23:06 | 1340f | - | - | ? | results/1340f_multiround_20261106_230627.txt |
| 2026-11-06 23:16 | 1340f | - | - | ? | results/1340f_multiround_20261106_231621.txt |
| 2026-11-06 23:19 | 1340f | - | - | ? | results/1340f_multiround_20261106_231918.txt |
| 2026-11-06 23:24 | 1340f | - | - | ? | results/1340f_multiround_20261106_232418.txt |
| 2026-11-07 17:02 | 1335a | 622 entry check is on the size field: 0x100 rejects, 0x40 dispatches; status word, not ret, is the discriminator | 0x200 arg4=0x100 -> 0x800E0001; arg4=0x40 -> 0xFFFFFFFF | M | results/1335a_20261106_150315.txt |
| 2026-11-07 17:02 | 55c_sys622_careful | void: every call passed arg4=0x100, rejected at the 622 entry check before dispatch | 0x800E0001 on all 402 reads, zero 0xFFFFFFFF, ret 0 in both shapes | V | results/phase14_final_push/55c_sys622_careful_20261018_095816.txt |
| 2026-11-07~ | 168 | - | - | ? | results/phase21/168_page_reuse_summary.txt |
| 2026-11-07~ | 526a | - | - | ? | results/phase23_cve_2026/526a_scm_rights_deep_results.txt |
| 2026-11-07~ | P3 | - | - | ? | results/phase22_dem9n101/P3_thr_create_console.txt |
| 2026-11-09 09:14 | 361b | The /system_tmp sockets | === 361b DONE === | M | results/phase17_new_vectors/361b_socket_consumption_20261022_175443.txt |
| 2026-11-09 09:14 | 377a | module .rodata (prot=0x1) is unreadable: eboot read at [A] succeeded, the first .sprx read kills past pcall | read ok=true len=256 first=2F6C6962; [B] regions: 317; died at libSceNpGameIntent.sprx 0x4E8000 prot=0x1 | M | results/phase17_new_vectors/377a_sprx_read_ladder_20261022_181129.txt |
| 2026-11-09 09:14 | 376a | void: died before any result line; capture is a header plus a fault dump | 4 lines: header, '77', fault bytes | V | results/phase17_new_vectors/376a_module_strings_20261022_180910.txt |
| 2026-11-09 09:14 | 156c | void: the capture named 156c holds probe 80d, not the thr_create/resolve test the bullet rests on | === PROBE 80d: thr_create CORRECT OFFSETS + SPIN === | V | results/phase17_new_vectors/156c_thr_create_correct_offsets_20261020_164129.txt |
| 2026-11-09 09:14 | 353a | AIO (sys 661); The whole kld* family plus sysctlbyname; Ignore SIGSYS before probing a possibly-absent slot | === 353a DONE === | M | results/phase17_new_vectors/353a_sigsys_nosys_20261022_163648.txt |
| 2026-11-09 09:14 | 30c | kqueue | [*] Received 1151 bytes total | M | results/phase4_ipc_network/30c_fcntl_bypass_20261015_201500.txt |
| 2026-11-09 09:14 | 58a | msync via syscall 226; msync(MS_INVALIDATE) CVE-2026-49418 | === PROBE 58a COMPLETE === | M | results/phase15_native_sysent/58a_msync_reachability_20261024_135342.txt |
| 2026-11-09 09:14 | 42a | void: kenv section header printed, no call result | last line '--- kenv ---' | V | results/phase8_live_network/42a_kernel_rw_20261016_001156.txt |
| 2026-11-09 09:14 | 43a | void: stopped at the syscall-308 test header, no kldstat result | last line '--- Testing kldstat as syscall 308 ---' | V | results/43a_kldstat_kaslr_20261016_180703.txt |
| 2026-11-09 09:14 | 262a | /dev/dmem0 physical memory | === PROBE 262a COMPLETE === | M | results/phase17_new_vectors/262a_dmem_partitions_20261021_154707.txt |
| 2026-11-09 09:14 | 45c | ROP chain hijack / fn_addr redirect; W^X bypass via mtypeprotect + fn_addr | === PROBE 45c COMPLETE === | M | results/45c_execution_reality_check_20261016_192713.txt |
| 2026-11-09 09:14 | 53b | AF_ROUTE KASLR (Relapse technique) | === PROBE 53b COMPLETE === | M | results/phase13_53batch/53b_afroute_retest_20261020_030901.txt |
| 2026-11-09 09:14 | 43f | sysctl operations (43f) | === PROBE 43f COMPLETE === | M | results/43f_sysctl_write_20261016_180756.txt |
| 2026-11-09 09:14 | 273a | ioctl via make_syscall | === PROBE 273a COMPLETE === | M | results/phase17_new_vectors/273a_pup_device_reach_20261022_094331.txt |
| 2026-11-09 09:14 | 383a | thr_new via make_syscall | === 383a DONE === | M | results/phase17_new_vectors/383a_thr_new_20261022_182743.txt |
| 2026-11-09 09:14 | 46a | sections A-E measured (620 struct: no kernel pointers); [F] neighbour sweep is void | 620 struct: no kernel pointers; capture ends at '[F] NEIGHBOR SWEEP 550-625' | M | results/46a_sony_syscall_deep_20261016_195704.txt |
| 2026-11-09 09:14 | 55g | dword write at +0x20 reached, then a boundary; no post-call marker | MARKER_BEFORE_DIFFERENT_WRITE then fault dump | M | results/phase14_final_push/55g_cclosure_write_diagnostic_20261018_103406.txt |
| 2026-11-09 09:14 | 48b | SCTP chunk fuzzing | === PROBE 48b COMPLETE === | M | results/48b_sctp_loopback_fuzz_20261016_202732.txt |
| 2026-11-09 09:14 | 48c | IPv6 extension header fuzzing | === PROBE 48c COMPLETE === | M | results/48c_ipv6_exthdr_fuzz_20261016_202737.txt |
| 2026-11-09 09:14 | 49a | TCP state machine injection | === PROBE 49a COMPLETE === | M | results/49a_tcp_inject_loopback_20261016_205919.txt |
| 2026-11-09 09:14 | 49b | IPv6 fragment reassembly attacks | or any unexpected behavior between fragment pairs. | M | results/49b_ipv6_frag_reassembly_20261016_205926.txt |
| 2026-11-09 09:14 | 50a | 86 exotic protocol packets, process survived | KEY: ... survived all 86 exotic protocol packets | M | results/50a_exotic_protocols_20261016_212850.txt |
| 2026-11-09 09:14 | 54i | sys 572 VM info query | === PROBE 54i COMPLETE === | M | results/phase14_final_push/54i_sys572_buffer_exam_20261018_091303.txt |
| 2026-11-09 09:14 | 54a2 | sys 626 RDMSR precise (cmd=1 + cmd=4) | === PROBE 54a2 COMPLETE === | M | results/phase14_final_push/54a2_rdmsr_precise_20261018_091308.txt |
| 2026-11-09 09:14 | 54b | void: ends mid blocked-syscall list; no 629 jail call result in this capture | ends '90 dup2 ret=-1 buf[0]=0' | V | results/54b_jail_bypass_20261018_090446.txt |
| 2026-11-09 09:14 | 54k | sys 626 RDMSR; sys 567 RDMSR read; sys 612 | === PROBE 54k COMPLETE === | M | results/54k_sys649_deep_and_rdmsr_20261018_090952.txt |
| 2026-11-09 09:14 | 54f | sections A-F measured (598/639/638/net.route/593 scans); section G is void | 593(h=507) +0x150: 0xE8ED7E9B_97C07349; capture ends at '[G] AIO event subsystem' | M | results/54f_kaslr_deep_20261018_090603.txt |
| 2026-11-09 09:14 | 55a | 643 accepts all 32 bits; mprotect(RWX) and fork still fail afterwards | fork: ret=4294967295 | M | results/phase14_final_push/55a_chicken_switches_20261018_094008.txt |
| 2026-11-09 09:14 | 54d | sys 588 DMEM page attribute modify | === PROBE 54d COMPLETE === | M | results/54d_dmem_page_flip_20261018_091257.txt |
| 2026-11-09 09:14 | 123a | void: boundary sweep ends at val=16; the qword write is not shown | val=16: ret=-1 (0xFFFFFFFF) | V | results/phase22_threaded_races/123a_sys637_kernel_write_20261022_182704.txt |
| 2026-11-09 09:14 | 122a | physhm mmap returns a VA; the first read kills past pcall | base=0x000000031111C000 then fault dump at '[C] hex dump' | M | results/phase22_threaded_races/122a_physhm_hexdump_20261022_174827.txt |
| 2026-11-09 09:14 | 50e2 | CVE-2026-49412 IPV6_MSFILTER UAF | === 50e2 COMPLETE === | M | results/phase23_cve_reachability/50e2_ipv6_msfilter_reach_20261022_194410.txt |
| 2026-11-09 09:14 | 50f | CVE-2026-45257 KTLS page-cache overwrite | === 50f COMPLETE === | M | results/phase23_cve_reachability/50f_ktls_reach_20261022_194646.txt |
| 2026-11-09 09:14 | 803d | sys 548 batch VM ops | [D] alive pid=140 | M | results/phase17_new_vectors/803d_548_op_matrix_20261026_115307.txt |
| 2026-11-09 09:14 | 241a | 622 with the documented layout: cmd 0x100 -> 0x8002004E, cmd 0x200 -> 0xFFFFFFFF status | cmd=0x200 ret=0x0 buf[0]=0xFFFFFFFF buf[4]=0xDEADBEEF | M | results/phase17_new_vectors/241a_sys622_layout_20261021_211732.txt |
| 2026-11-09 09:14 | 55d | void: cmd scan stops at 0x02, no 0x03/0x04 kill measured | 0x02: ret=-1 buf[0]=0 | V | results/phase14_final_push/55d_sys601_process_control_20261018_100435.txt |
| 2026-11-09 09:14 | 55e | sys 674 VM map kernel pointer search; sys 672 dynlinker library list; sys 676 CPU mode update; sys 673 page remap; sys 675 reset global state; sys 587 credential metadata; sys 671 resource class query | === PROBE 55e COMPLETE === | M | results/phase14_final_push/55e_vm_cred_survey_20261018_100751.txt |
| 2026-11-09 09:14 | 52a | 627-630 return PCALL-FAIL; the process dies at 631 | P1 num=631 calling now... (no return line) | M | results/phase13_52batch/52a_survey_627_676_20261018_103436.txt |
| 2026-11-09 09:14 | 125a | sys 662 AIO batch delete | === 125a COMPLETE === | M | results/phase22_threaded_races/125a_sys662_kaslr_stackclash_20261022_192348.txt |
| 2026-11-09 09:14 | 151a | void: op sweep stops at op=1; op 25 (SHM) never reached in this capture | op=1: ok=true ret=-1 | V | results/phase19_umtx_454/151a_umtx_shm_race_20261020_075419.txt |
| 2026-11-09 09:14 | 353c | fstat(189) via make_syscall; AIO batch races (cancel, unmap, gen counter) | === 353c DONE === | M | results/phase17_new_vectors/353c_absent_or_rejecting_20261022_163852.txt |
| 2026-11-09 09:14 | 334a | shape matrix: 572 answers with P00000=0*, the rest -1 | sys 572 000000=-1 P00000=0* 0P0000=-1 ... | M | results/phase17_new_vectors/334a_obj_family_shapes_20261022_124106.txt |
| 2026-11-09 09:14 | 339a | void: three lines, dies at the first 637 call | 637(0, 0x10) = -1 | V | results/phase17_new_vectors/339a_637_598_659_20261022_124747.txt |
| 2026-11-09 09:14 | 342a | Named evf/namedobj objects do not outlive their process | === 342a DONE === | M | results/phase17_new_vectors/342a_named_objects_after_relaunch_20261022_125458.txt |
| 2026-11-09 09:14 | 223a | netcontrol(99) netevent queue UAF | === PROBE 223a COMPLETE === | M | results/phase17_new_vectors/223a_netcontrol_queue_scope_20261021_143212.txt |
| 2026-11-09 09:14 | 251a | jitshm (533 jitshm_create, 534 jitshm_alias) | === PROBE 251a COMPLETE === | M | results/phase17_new_vectors/251a_jitshm_20261021_153538.txt |
| 2026-11-09 09:14 | 252a | osem (549-556) | === PROBE 252a COMPLETE === | M | results/phase17_new_vectors/252a_osem_family_20261021_153559.txt |
| 2026-11-09 09:14 | 254a | namedobj (557 namedobj_create, 558 namedobj_delete) | === PROBE 254a COMPLETE === | M | results/phase17_new_vectors/254a_namedobj_identity_20261021_153631.txt |
| 2026-11-09 09:14 | 255a | 559 set_vm_container | === PROBE 255a COMPLETE === | M | results/phase17_new_vectors/255a_set_vm_container_20261021_153651.txt |
| 2026-11-09 09:14 | 257a | 560(1)=0 opens nothing; the 561 section prints no result (the kill) | 560(16) -> -1 ... then '[B] 561 suspend_process / 562 resume_process' and stop | M | results/phase17_new_vectors/257a_process_pair_20261021_153735.txt |
| 2026-11-09 09:14 | 348a | The GPU pool zeroes pages on allocation | === 348a DONE === | M | results/phase17_new_vectors/348a_gpu_pool_scan_20261022_154151.txt |
| 2026-11-09 09:14 | 346b | sys 637's store is inert | === 346b DONE === | M | results/phase17_new_vectors/346b_fmem_ceiling_20261022_161726.txt |
| 2026-11-09 09:14 | 266a | 661 with a real /dev/zero fd kills at the call | ends at '[B] 661(aiocb)' | M | results/phase17_new_vectors/266a_aio_real_fd_20261021_155530.txt |
| 2026-11-09 09:14 | 269a | UMTX ops 18-21 (high ops) | === PROBE 269a COMPLETE === | M | results/phase17_new_vectors/269a_umtx_high_ops_20261021_160200.txt |
| 2026-11-09 09:14 | 160f | void: ends mid round 1; the 5-7 round cascade is not in this capture | R1: C=0x0, waiting... | V | results/phase22_threaded_races/160f_pi_exit_cascade_20261023_063249.txt |
| 2026-11-09 09:14 | 58d | CVE-2026-58093 TIOCSCTTY race UAF; CVE-2026-58099 kqueue fork race; CVE-2026-58090 unix socket receive UAF | === 58d COMPLETE === | M | results/phase26_cve_vectors/58d_tiocsctty_reachability_20261023_070440.txt |
| 2026-11-09 09:14 | 353b | AIO fd-close race | === 353b DONE === | M | results/phase17_new_vectors/353b_lethal_reclassify_20261022_163752.txt |
| 2026-11-09 09:14 | 410a | Object lifetimes hold at native speed | === 410a DONE === | M | results/phase17_new_vectors/410a_osem_race_20261022_225639.txt |
| 2026-11-09 09:14 | 429a | Sys 532 handle forgery | === 429a DONE === | M | results/phase17_new_vectors/429a_sys532_user_pointer_20261022_234844.txt |
| 2026-11-09 09:14 | 56e2 | NET_RT_DUMP kernel pointer search | === 56e2 COMPLETE === | M | results/phase13_53batch/56e2_rtdump_hexdump_20261023_095601.txt |
| 2026-11-09 09:14 | 56e | CVE-2026-3038 sa_len=127 routing socket overflow | === 56e COMPLETE === | M | results/phase13_53batch/56e_routing_socket_deep_20261023_095248.txt |
| 2026-11-09 09:14 | 56d5 | CClosure deep Lua stack read | === 56d5 COMPLETE === | M | results/phase13_53batch/56d5_deep_stack_read_20261023_094324.txt |
| 2026-11-09 09:14 | 56f | sys 624 side channel | === 56f COMPLETE === | M | results/phase13_53batch/56f_624_side_channel_20261023_100614.txt |
| 2026-11-09 09:14 | 56g3 | Sysctl deep scan | === 56g3 COMPLETE === | M | results/phase13_53batch/56g3_sysctl_deep_scan_20261023_100911.txt |
| 2026-11-09 09:14 | 56h | void: capture is find_thrd_create, not the timing test the bullet rests on | ends 'native.get_lua_opt type=function' | V | results/phase14_cclosure_redirect/56h_find_thrd_create_20261020_090420.txt |
| 2026-11-09 09:14 | 56m | void: op scan stops at op=1 | op= 1: ENOSYS(-1) | V | results/phase14_cclosure_redirect/56m_umtx_ops_and_thr_20261020_093600.txt |
| 2026-11-09 09:14 | 56n | Thread ucontext kernel pointer scan; getsockopt kernel pointer scan | === 56n COMPLETE === | M | results/phase13_53batch/56n_ucontext_kptr_scan_20261023_110050.txt |
| 2026-11-09 09:14 | 56o | Unix socket SCM_CREDS credential leak; sigaction struct kernel pointer scan; fstat deep scan + overcopy check; getdirentries kernel pointer scan | === PROBE 56o COMPLETE === | M | results/phase14_cclosure_redirect/56o_thr_create_minimal_20261020_094804.txt |
| 2026-11-09 09:14 | 56p | getrusage padding scan; SO_TIMESTAMP / SO_BINTIME ancillary data; procctl(544) output scan; getrlimit overcopy + kptr scan | === PROBE 56p COMPLETE === | M | results/phase14_cclosure_redirect/56p_thr_create_refine_20261020_095417.txt |
| 2026-11-09 09:14 | 56q | kevent output scan; SCM_RIGHTS fd passing WORKS; sendfile error path data leak; poll output overcopy | === PROBE 56q COMPLETE === | M | results/phase14_cclosure_redirect/56q_thr_mclen_20261020_100500.txt |
| 2026-11-09 09:14 | 56r | Signal delivery frame (sendsig) kernel stack residue | === PROBE 56r COMPLETE === | M | results/phase14_cclosure_redirect/56r_thr_diagnostic_20261020_100748.txt |
| 2026-11-09 09:14 | 271g | Eboot syscall instruction scan; Kqueue race condition (ZDI-26-784) | === 271g COMPLETE === | M | results/phase17_new_vectors/271g_child_thread_rop_kqueue_race_20261023_135621.txt |
| 2026-11-09 09:14 | 275b | Sysent 679-734 | === 275b COMPLETE === | M | results/phase17_new_vectors/275b_sysent_tail_guarded_20261022_223712.txt |
| 2026-11-09 09:14 | 56j | Syscalls 530/531/537 | === PROBE 56j COMPLETE === | M | results/phase14_cclosure_redirect/56j_native_functions_20261020_091908.txt |
| 2026-11-09 09:14 | 56k | mprotect ret=0 on kernel/unmapped addresses | === PROBE 56k COMPLETE === | M | results/phase14_cclosure_redirect/56k_kernel_read_20261020_093127.txt |
| 2026-11-09 09:14 | 387a | ioctl overcopy sweep: results through the camera node, zero bytes past declared length (partial, ends mid camera) | camera code=0x40084104 ret=22 mod=2 | M | results/phase17_new_vectors/387a_ioctl_overcopy_scan_20261023_150627.txt |
| 2026-11-09 09:14 | 391a | shm_open+ftruncate+largepage mmap succeeds; capture ends at the sendfile section | largepage mmap: 0x3112A8000 *** LARGEPAGE OK *** | M | results/phase19_posixshm/391a_shm_open_retest_20261023_180734.txt |
| 2026-11-09 09:14 | 392a | CVE-2026-49419 (jail refcount underflow); FatGid/setcred (CVE-2026-45250); CVE-2026-58094 (ZDI-26-785, FIOSSHMLPGCNF TOCTOU) | === 392a COMPLETE === | M | results/phase20_bsd_deep/392a_bsd_high_value_20261023_183045.txt |
| 2026-11-09 09:14 | 388a | BSD-native syscall range (1-530) exhausted | === 388a COMPLETE === | M | results/phase18_bsd_native/388a_bsd_top5_exploration_20261023_161540.txt |
| 2026-11-09 09:14 | 519a | Module data region "kernel pointers" are NaN-boxed Lua values | === DONE === | M | results/phase17_new_vectors/519a_libc_stub_bytes_20261024_134510.txt |
| 2026-11-09 09:14 | 525a | SysV IPC completely absent | === PROBE 525a COMPLETE === | M | results/phase23_cve_2026/525a_sysv_ipc_presence_20261105_090149.txt |
| 2026-11-09 09:14 | 524a | void: probe self-reports INCOMPLETE; capture shows 'no double delete observed', not the VM-op claim | [B] no double delete observed / === PROBE 524a INCOMPLETE === | V | results/phase17_new_vectors/524a_aio_double_delete_single_20261024_141445.txt |
| 2026-11-09 09:14 | 435a | Object handles are predictable and generation-checked | === 435a DONE === | M | results/phase17_new_vectors/435a_kernel_gauge_20261023_001637.txt |
| 2026-11-09 09:14 | 89a | CVE-2019-5607 ALL PATHS CLOSED | === PROBE 89a COMPLETE === | M | results/phase22_threaded_races/89a_cve2019_5607_fd_race_20261021_165612.txt |
| 2026-11-09 09:14 | 544a | sceKernelMapDirectMemory from main thread (544a-545g) | === PROBE 544a COMPLETE === | M | results/phase30_mapdirect_loader/544a_fcall_stub_layout_20261025_211235.txt |
| 2026-11-09 09:14 | 546a | void: child launch ends in a fault dump, no ROP result | ends '[E] thr_create launch child' plus fault bytes | V | results/phase30_mapdirect_loader/546a_mapdm_child_20261026_090208.txt |
| 2026-11-09 09:14 | 547a | dmem0 16GB physical memory scan for kernel; dmem0 as system RAM | === 547a DONE === | M | results/phase30_mapdirect_loader/547a_dmem0_low_phys_20261026_140353.txt |
| 2026-11-09 09:14 | 547f | dmem1/dmem2/gc/dce/zero for kernel physical access | === 547f DONE === | M | results/phase30_mapdirect_loader/547f_dmem12_20261026_141012.txt |
| 2026-11-09 09:14 | 548a | Sony syscall 596 (dynlib_do_copy_relocations); Sony syscall 604 (dl_get_metadata); Sony syscall 559 (set_vm_container) deep; Sony syscalls 615/613 with subcmd patterns | === 548a DONE === | M | results/phase31_sony_leak/548a_sony_leak_hunt_20261026_143900.txt |
| 2026-11-09 09:14 | 528x | /dev/gc ioctl surface for GPU DMA | === 528x DONE === | M | results/phase27_phys_memory/528x_gpu_sdma_hunt_20261025_115659.txt |
| 2026-11-09 09:14 | 65l | ★ AIO 662 double-free — THE BIGGEST DEAD END | === 65l COMPLETE === | M | results/phase16_kwrite/65l_aio_race_fixed_20261028_111549.txt |
| 2026-11-09 09:14 | 68a | AIO R-object KASLR spray | === 68a DONE === | M | results/phase16_kwrite/68a_aio_uaf_readback_20261028_105844.txt |
| 2026-11-09 09:14 | 75a | IPv6 RTHDR zone-128 spray (75a-75e) | === PROBE 75a COMPLETE === | M | results/phase16_kwrite/75a_dynlib_v2_kaslr_20261025_201254.txt |
| 2026-11-09 09:14 | 824a | osem waiter-wake race | === PROBE 824a COMPLETE === | M | results/phase17_new_vectors/824a_osem_create_20261026_192653.txt |
| 2026-11-09 09:14 | 803c | sys 548 W^X bypass attempt | [D] alive pid=140 | M | results/phase17_new_vectors/803c_mmap_548_protect_20261026_115236.txt |
| 2026-11-09 09:14 | 813a | sigreturn privilege escalation | [*] alive pid=157 | M | results/phase17_new_vectors/813a_sigreturn_gate_20261026_122338.txt |
| 2026-11-09 09:14 | 883b | thr_create child loader stub loop | [Z] alive pid=134 | M | results/phase17_new_vectors/883b_aio_padded_chain_single_20261027_001203.txt |
| 2026-11-09 09:30 | 380a | GPU mapping read kills past pcall; the store before it reported ok | [A dump-area] write ok=true then fault bytes | M | results/phase17_new_vectors/380a_gpu_mapping_write_20261022_181716.txt |
| 2026-11-09 09:30 | 381a | a store to an unmapped 0x7F0000000000 reports ok=true and the process stays alive — the write path swallows faults | [D unmapped] 0x7F0000000000 <- 0x44444444 ok=true / still alive | M | results/phase17_new_vectors/381a_gpu_write_control_20261022_181839.txt |
| 2026-11-09 09:30 | 42g2 | void: dies at the kenv step header, no kenv result | --- STEP 1: KENV (syscall 390) --- | V | results/42g2_high_phys_decode_20261016_070600.txt |
| 2026-11-09 09:30 | 152k | UMTX op 25 sub-ops answer without allocating: subop_0 ret=0, invalid op 99 ret=-1 | subop_0: ok=true ret=0x0 / invalid_op(99): ret=-1 | M | results/phase19_umtx_454/152k_shm_side_channel_20261020_104543.txt |
| 2026-11-09 09:30 | 340a | 637 accepts a caller qword for id 0 (0x7FFFFFFF and 0xFFFFFFFF return 0) and refuses 0x0 and every foreign id | 637(0, 0xFFFFFFFF)=0 / 637(0, 0x0)=-1 / 637(1..5, 0xFFFFFFFF)=-1 | M | results/phase17_new_vectors/340a_dynlib_out_637_limit_20261022_125339.txt |
| 2026-11-09 09:30 | 160i | void: rounds print uret=0 and the capture stops mid-run; no crash measured | R7: a=0x18A09 uret=0x0 m=0x0 | V | results/phase22_threaded_races/160i_pi_ownership_fraud_20261023_065002.txt |
| 2026-11-09 09:30 | 160j | PI fraud diagnostic completes: gpu kptr clean, canary OK | gpu kptr: clean / canary=OK / === 160j COMPLETE === | M | results/phase22_threaded_races/160j_pi_fraud_diag_20261023_070221.txt |
| 2026-11-09 09:30 | 160g | void: stops at the dead-owner lock step | [4] Main LOCKs mutex with dead child owner | V | results/phase22_threaded_races/160g_pi_exit_diag_20261023_063550.txt |
| 2026-11-09 09:30 | 160h | dead-owner PI rescue completes cleanly | canary=OK / === 160h COMPLETE === | M | results/phase22_threaded_races/160h_dead_owner_rescue_20261023_064240.txt |
| 2026-11-09 09:30 | 56i2 | mprotect timing on kernel addresses is flat across batches — noise, not signal | kern_FFFF 20817 20645 21869 20968 20696 20999 | M | results/phase13_53batch/56i2_timing_stability_20261023_101431.txt |
| 2026-11-09 09:30 | 546d | void: fault dump during polling, no MapDM result | [F] Polling... then fault bytes | V | results/phase30_mapdirect_loader/546d_mapdm_fixed_20261026_134339.txt |
| 2026-11-09 09:30 | 156d | child executes via marker write through make_syscall thr_create; the resolve() filter is not measured here | === PROBE 156d COMPLETE === | M | results/phase17_new_vectors/156d_thr_create_child_executes_20261025_125313.txt |
| 2026-11-09 09:44 | 1331a | fault-oracle sweep: image mapped 0xFFFFFFFFC1000000-0xFFFFFFFFC6C00000 at 4MB resolution, stub alone at 0xFFFFFFFFC0000000; slide 0xC000000 from the 2026-11-06 boot | 25/512 present: C0000000 then C1000000..C6C00000 contiguous, spawned=512 failed=0 | M | results/1331a_20261109_094441.txt |
| 2026-11-09 09:51 | 1341a | - | - | ? | results/phase35_dead_end_reruns/1341a_resolve_vs_raw_20261109_095129.txt |
| 2026-11-09 09:52 | 1341a2 | syscall.resolve() installs any name->number pair (zzz20=20 became callable) and the named thr_new(455)/thr_create(430) calls return 0 with real TIDs, identical to make_syscall; the 'resolve() filter' is only the loader's 26-name registration list, while fork(2)/rfork(251) return -1 on both paths | thr_new raw/named=0 tid 0x18F0A/0x18F0B; thr_create raw/named=0 tid 0x18F0C/0x18F0D; fork/rfork=-1; table=26 names; canary OK | M | results/phase35_dead_end_reruns/1341a2_resolve_vs_raw_fixed_20261109_095214.txt |
| 2026-11-09 09:53 | 1341b | Re-run of the uncaptured 524a surface: 645/647/648/654/655/658/660/667 all return -1 with no output written (zero kptr-shaped dwords), and 653 is the exception - 653(0) returns 22 (EINVAL) while 653(mapped, attr) returns -1, so the handler validates arg0 before the permission check | 645()=-1; 648/647/667 nothing written; 660 only echoes size; 654/655 all -1; 653(0)=22, 653(gpu,1/3/5/7/0x33)=-1; canary OK, 0.406s | M | results/phase35_dead_end_reruns/1341b_vm_ops_ordered_20261109_095307.txt |
| 2026-11-09 09:55 | 1341c | kenv(390) called from a child thread with (0, 'kernel', buf, 0x100) never returns: the capture stops right after that child was spawned, and a fresh connection gets no script execution (a PING OK probe prints nothing), so the call blocks and wedges the loader thread | spawn(20) tid=0x18F0F; spawn(390) tid=0x18F10 then IDLE_TIMEOUT 26.4s; follow-up ping_loader: 0 bytes; child RAX unobserved | M | results/phase35_dead_end_reruns/1341c_kenv_390_child_20261109_095444.txt |
| 2026-11-09 10:01 | 1341d | sys 601 cmd 0x04 terminates the whole process, not just the calling thread: the child faulted, the loader wrote its ucontext-shaped fault dump to the socket, the parent's own spawn line never printed, and 9026 then refused connections | last ASCII line is the [B] CALL banner, then 496 raw bytes starting 37 13 37 13; tail holds SS=0x3b, flags=0x480, type=0x10002, rflags=0x40e; ping afterwards CONNECTION_REFUSED | M | results/phase35_dead_end_reruns/1341d_sys601_cmd04_child_20261109_100048.txt |
| 2026-11-09 10:05 | 1331a | kernel image base unchanged across the 1341c/1341d relaunches: same 25 present samples, stub alone at 0xFFFFFFFFC0000000 then a contiguous image 0xFFFFFFFFC1000000-0xFFFFFFFFC6C00000; the 512 faulting children also re-prove that an ordinary child fault is contained by the loader handler | 25/512 present, image 0xFFFFFFFFC1000000-0xFFFFFFFFC6C00000 (last present sample C6C00000), slide 0xC000000, spawned=512 failed=0 alive pid=92 | M | results/1331a_20261109_100517.txt |
| 2026-11-09 10:06 | 1342a | sys 568 is lethal on both pointer classes: an absent arg1 kills the process just as a mapped one did, so 568 dies before it looks at its first argument | run stopped after the 'CALL 568 N' line; ping afterwards CONNECTION_REFUSED; sweep 590..676 left for the next run | M | results/phase35_dead_end_reruns/1342a_arg1_sweep_589_plus_20261109_100539.txt |
| 2026-11-09 10:10 | 1342a | - | - | ? | results/phase35_dead_end_reruns/1342a_arg1_sweep_589_plus_20261109_101034.txt |
| 2026-11-09 10:11 | 1342a | - | - | ? | results/phase35_dead_end_reruns/1342a_arg1_sweep_589_plus_20261109_101145.txt |
| 2026-11-09 10:12 | 1342a | with SIGSYS ignored the previous 'lethal' numbers are nosys slots: 568/569/589/590 plus 597/610/619/620 answer ENOSYS, so every U-pass kill at 568/569/589 was the nosys trampoline raising the signal, not a hostile handler; 568-620 also yields a full N-class map and the range's only real faulting handler is 622 | 48 calls, 568..620 minus 570/571/573/609/614/621; sigaction(12,SIG_IGN)=0; ENOSYS on 568,569,574-584,589,590,597,610,619,620; died at CALL 622 N | M | results/phase35_dead_end_reruns/1342a_arg1_sweep_589_plus_20261109_101208.txt |
| 2026-11-09 10:14 | 1342a | arg1 pointer-class sweep completes 532-676 with no kernel read anywhere: 131 of 145 numbers measured, the K pass rejects every supervisor pointer, and only eight handlers branch on arg1 (538 and 557 mint an id, 563-566 invert, 572 and 653 flip) -- 1342a run 4 ran all three phases in one connection and survived | 157 calls, COMPLETE 0.109s, alive pid=113; N 623..676 + U 568..676 + K on 11; 27 ENOSYS stubs; no K call returned data | M | results/phase35_dead_end_reruns/1342a_arg1_sweep_589_plus_20261109_101254.txt |
| 2026-11-09 10:18 | 1343b | - | - | ? | results/phase35_dead_end_reruns/1343b_outpage_scorer_20261109_101811.txt |
| 2026-11-09 10:20 | 1343a | arg2 and arg3 are dereferenced by 20 and 10 handlers respectively; holding arg1 mapped and switching arg2/arg3 between mapped and absent changes the answer for those numbers, and 557 mints a different handle for every phase (16901/519/520) | 131 numbers x 3 phases, COMPLETE 0.359s, alive pid=113; 20 differ on arg2, 10 on arg3 | M | results/phase35_dead_end_reruns/1343a_arg23_classes_20261109_101720.txt |
| 2026-11-09 10:20 | 1343b | seven syscalls write into the pages they are handed (547 region record, 592 handle list, 598 param, 638/639 time conversion, 657, 659) and none leaks a kernel pointer: every out-page holds userland addresses or small integers, and the end checkpoint was intact in all cases | 131 numbers, 7 writers, COMPLETE 34.14s, alive pid=113, no 0xFFFF8xxx value | M | results/phase35_dead_end_reruns/1343b_outpage_scorer_20261109_101855.txt |
| 2026-11-09 10:28 | 1344a | arg2 and arg3 are class-checked by the same copyin/copyout as arg1: with the boot's kernel image base in either slot, every handler that touches the pointer answers EFAULT and none returns 0 while writing, so no call in 532-676 writes through a pointer it never validated | 131 numbers; 21 change with arg2=K, 10 with arg3=K, all EFAULT/EINVAL/ESRCH, alive pid=113 | M | results/phase35_dead_end_reruns/1344a_arg23_kernel_class_20261109_102818.txt |
| 2026-11-09 10:28 | ping | - | - | ? | results/ping_loader_20261109_102815.txt |
| 2026-11-09 10:30 | 1345a | no handler in 532-676 dereferences args four to six: with args 1-3 mapped and each of arg4/5/6 switched between a mapped page and zero, only 557's object id and 624's VM-op counter move, so the fourth-to-sixth positions are scalars everywhere in the range | 131 numbers x 4 phases, 2 differences (557 id 525-528, 624 counter 3480-3483), alive pid=113 | M | results/phase35_dead_end_reruns/1345a_arg456_classes_20261109_102955.txt |
| 2026-11-09 10:46 | 1346a | sys 622 low dispatch table has a live entry at cmd 0x00 that kills with a null arg3. | died at cmd 0x00 before any post-call line; 110-byte capture | M | results/phase35_dead_end_reruns/1346a_sys622_low_commands_20261109_104306.txt |
| 2026-11-09 10:46 | 1347a | 622 cmd 0x372 is auth-gated and cmd 0x520's callee refuses; low commands 0x01-0x0F kill. | 0x372 -> ret 0 buf 0x8002004E on all 32 subs; 0x520 -> -1 on all 32; died inside 0x01..0x0F | M | results/phase35_dead_end_reruns/1347a_sys622_low_resume_20261109_104444.txt |
| 2026-11-09 10:46 | 1348a | A mapped zero page in arg3 does not rescue low cmd 0x01, so the kill is not a copyin from a bad pointer. | died at cmd 0x01; 130-byte capture | M | results/phase35_dead_end_reruns/1348a_sys622_low_page_20261109_104528.txt |
| 2026-11-09 10:54 | 1351a | 622 cmd 0x01's process kill is not a catchable fatal signal: with SIG_IGN on 5/6/7/8/12/24-26/30/31 the call still ends the process. | sigaction readback handler=1 for sig 12; killed at the first 622(0x01) call, no canary line | M | results/phase35_dead_end_reruns/1351a_sys622_kill_signal_20261109_105100.txt |
| 2026-11-09 11:00 | 1350a | - | - | ? | results/phase35_dead_end_reruns/1350a_sys622_kill_containment_20261109_110035.txt |
| 2026-11-09 11:01 | 1349a | 622 cmd 0x01 kills with a self-referential page too, so the low-command kill is not a NULL deref of the supplied struct. | died in [A] before the canary; [B] and [C] never ran | M | results/phase35_dead_end_reruns/1349a_sys622_low_deref_20261109_105753.txt |
| 2026-11-09 11:01 | 1350b | A 622 kill in a spawned Lua thread takes the whole process. | thread printed T-ENTER then the connection ended; main never printed MAIN-2 | M | results/phase35_dead_end_reruns/1350b_sys622_kill_containment_20261109_110109.txt |
| 2026-11-09 11:01 | 1352a | 532 dispatches for a game process on exactly the codes its priv_check failure path allows. | 0x1E and 0x2F rv=0 status 0; 0x20 0x800D0219 at size 0x30 and 0x800D0208 elsewhere; 0x18/0x19 0x800D0203; 0x1F -1 | M | results/phase35_dead_end_reruns/1352a_sys532_unpriv_commands_20261109_105538.txt |
| 2026-11-09 11:01 | 1353a | 532 cmd 0x2F zeroes its arg3 buffer, 0x1E returns 3 for any non-zero input, and the 0x18/0x19 lookup changes code with the first input dword. | 0x2F zeroed 12 dwords of input; 0x1E status 3 for zero-fill variants with a non-zero dword, 0 for all zeros; 0x18/0x19 in[0]!=0 -> 0x800D0204 | M | results/phase35_dead_end_reruns/1353a_sys532_low_step2_20261109_105622.txt |
| 2026-11-09 11:01 | 1354a | 532 cmd 0x2F is a caller-length zero fill whose destination is validated. | size follows arg4 (0x30/0x40/0x100 -> 12/16/64 dwords); unmapped user 0x1000 and kernel 0xFFFFFFFFC1000000 both answer 0x800D0210 | M | results/phase35_dead_end_reruns/1354a_sys532_write_dest_20261109_105712.txt |
| 2026-11-09 11:12 | 1355a | 601 cmd 0x12 returns -1 even with arg2 pointing at a mapped 0x20-byte block; the consumer sweep died at cmd 0x1B | 0x12 = -1 twice; died at 0x1B | M | results/phase35_dead_end_reruns/1355a_sys601_cmd12_shape_20261109_110324.txt |
| 2026-11-09 11:12 | 1356a | 601 cmd 0x12 answers EFAULT for a mapped, an unmapped and a null arg2 alike (arg1 nonzero gives EINVAL), and cmd 0x0C wedges the loader until relaunch | 0x12 errno=14 x3, arg1=buf errno=22; 0x0C hang; connection idle-timeout at 30s | M | results/phase35_dead_end_reruns/1356a_sys601_eno_20261109_110852.txt |
| 2026-11-09 11:21 | 1357a | 601 cmd 0x12 is live on 14.10: qword1!=0 returns ENOENT and qword1==0 returns EFAULT, exactly the 13.60 flag-clear path | 0x12 {0,1} -> -1 errno=2; {0,0} -> -1 errno=14; {0x1000,1} -> -1 errno=2; died at 0x11 | M | results/phase35_dead_end_reruns/1357a_sys601_cmd12_gate_20261109_111650.txt |
| 2026-11-09 11:23 | 1331a | kernel image base for the 2026-11-09 11:23 boot is 0xFFFFFFFFC1000000, unchanged from the 09:44 measurement after the user rebooted the console | 25/512 present: stub C0000000 alone, image C1000000-C6C00000 on the 4MB grid, next absent C7000000 | M | results/1331a_20261109_112311.txt |
| 2026-11-09 11:33 | 1359a | syscall 417 installs a caller-written trapframe verbatim: patching RIP to 0x10000 produced a SIGSEGV whose dumped frame carries RIP=0x10000, CS=0x43, SS=0x3B | signo=11, mcontext RIP=0x10000 CS=0x43 RFLAGS=0x10202 RSP=0x31111C868 SS=0x3B; loader died after the dump | M | results/phase35_dead_end_reruns/1359a_sys417_frame_ride_20261109_113019.txt |
| 2026-11-09 11:33 | 1358a | 417 accepts an unchanged frame (ret=0) and dies when only CS is set to 0x08, the ring-0 code selector | B: 417 unchanged ret=0 and caller continued; C: CS=0x08 -> no further output | M | results/phase35_dead_end_reruns/1358a_sys417_selectors_20261109_112355.txt |
| 2026-11-09 11:35 | 1360a | - | - | ? | results/phase35_dead_end_reruns/1360a_eboot_ring0_gadgets_20261109_113530.txt |
| 2026-11-09 11:39 | 1361a | - | - | ? | results/phase35_dead_end_reruns/1361a_eboot_gadgets_dword_20261109_113907.txt |
| 2026-11-09 11:39 | 1362a | - | - | ? | results/phase35_dead_end_reruns/1362a_sys547_record_shape_20261109_113946.txt |
| 2026-11-09 11:40 | 1364a | - | - | ? | results/phase35_dead_end_reruns/1364a_eboot_gadgets_range_20261109_114043.txt |
| 2026-11-09 11:41 | 1364a | - | - | ? | results/phase35_dead_end_reruns/1364a_eboot_gadgets_range_20261109_114123.txt |
| 2026-11-09 11:42 | 1364a | - | - | ? | results/phase35_dead_end_reruns/1364a_eboot_gadgets_range_20261109_114214.txt |
| 2026-11-09 11:47 | 1365a | - | - | ? | results/phase35_dead_end_reruns/1365a_chain_gadget_validate_20261109_114725.txt |
| 2026-11-09 11:59 | 1367b | the ring-0 chain runs (dump RIP = the chain's own return-frame value) but the return is structurally broken: with CS=0x08 the kernel skips its swapgs, so userland resumes with GS = the kernel per-CPU base and libkernel's post-syscall code dies at si_addr 0x16 -- pointing rax/rsi/rdi at a self-referential page changes nothing | signo=SIGBUS, si_addr=0x16, mcontext RIP=0x81B6F8B5C (= resumed stub), CS=0x43, RFLAGS=0x202, RSP=0x311374868, SS=0x3B | M | results/phase35_dead_end_reruns/1367b_ring0_safe_return_20261109_115658.txt |
| 2026-11-09 12:00 | 1367c | - | - | ? | results/phase35_dead_end_reruns/1367c_ring0_two_qword_dump_20261109_120047.txt |
| 2026-11-09 12:29 | 1366a | VOID: 1366a did not reach CPL0 -- the dump's mcontext is the pre-417 user context (mc_rax=0x1A1=417, mc_rdi=the frame buffer, mc_err=2), which 1367d proved by installing a 0x10000 landmark and getting the pre-417 context back instead | signo=10, mc_rip=live post-syscall, mc_cs=0x43, mc_err=2 | V | results/phase35_dead_end_reruns/1366a_ring0_kernel_read_20261109_115002.txt |
| 2026-11-09 12:29 | 1367d | 417 with a kernel CS faults inside the kernel and never installs the frame: a frame carrying CS=0x08 plus a 0x10000 landmark RIP produces the same pre-417 SIGBUS dump as the earlier chain probes, so no ring-0 code has ever executed on 14.10 | signo=10, mc_rip=0x83A2D4B5C (live), mc_cs=0x43, mc_err=2, mc_rax=0x1A1, no 0x10000 anywhere | M | results/phase35_dead_end_reruns/1367d_chain_reach_qword_20261109_122935.txt |
| 2026-11-09 12:30 | 1369a | - | - | ? | results/phase35_dead_end_reruns/1369a_sys669_tail_leak_20261109_123052.txt |
| 2026-11-09 12:32 | 1370a | sys 669's 16-byte destination write is deterministic per file offset (identical bytes across 8 calls at 0x1000, and 2 at 0x2000), so it is request payload, not uninitialised kernel memory -- the 4-byte over-copy in the 13.60 listing does not leak on 14.10 | offset 0x1000 -> 04936EDF 72609230 5F745831 E6C92398 eight times; offset 0x2000 -> 3E0FE1C5 ... twice; unmapped and null destination both ret=0 | D | results/phase35_dead_end_reruns/1370a_sys669_determinism_20261109_123204.txt |
| 2026-11-09 12:33 | 1371a | - | - | ? | results/phase35_dead_end_reruns/1371a_sys601_writer_sweep_20261109_123328.txt |
| 2026-11-09 12:41 | 1372a | sys 601 reaches at most a status word: 0x10 with a null arg2 writes nothing, 0x1C returns -1 with a null arg2 but kills the process when arg2 is a valid pointer, so the 0x1000-byte alloc-and-copyout block at ca0d6c is not 0x10 or 0x1C | 0x10 arg2=0 rv=-1 wrote=0; 0x1C arg2=0 rv=-1 wrote=0; 0x1C arg2=ptr -> process death, no further output | M | results/phase35_dead_end_reruns/1372a_sys601_high_commands_20261109_124039.txt |
| 2026-11-09 12:42 | 1372b | no 601 command in 0x00-0x26 writes more than a status dword into arg1: 0x1D and 0x20 return 0 with no write under both arg2 shapes, 0x1E-0x1F and 0x21-0x26 return -1, so the 0x1000-byte alloc-and-copyout block at ca0d6c is not reachable as any non-lethal command | 0x1D rv=0 0x20 rv=0 (no write, both shapes); 0x1E,0x1F,0x21-0x26 rv=-1; process survived to COMPLETE | D | results/phase35_dead_end_reruns/1372b_sys601_high_null_20261109_124221.txt |
| 2026-11-09 12:43 | 1373a | sys 601 moves no 0x1000-byte block through arg1 in any non-lethal command: the return value for 0x1C/0x10/0x1D/0x20/0x00/0x0E/0x1A/0x0D/0x13/0x14/0x19 is identical when arg1 has a 0x4000-byte run, an 8-byte tail or is unmapped, so the ca0d6c alloc-and-copyout block is not reachable in 0x00-0x26 and 601 is closed as a read surface (this also makes 1372b's direction-blind D verdict sound) | every command room=tail; only 0x00/0x0E/0x1A read arg1 (2/2/1 dwords, unmapped -> EFAULT) | M | results/phase35_dead_end_reruns/1373a_sys601_transfer_direction_20261109_124318.txt |
| 2026-11-09 12:49 | 1374a | the arg1-class sweep over 1-531 hangs inside its baseline pass; sys 95 (fsync) is the only NO_OUTPUT number below the next progress mark, so it is the candidate and 95/432/530 are now skipped | 89 bytes: pid=261, sigign=10/10, then no output for 30 s | V | results/phase35_dead_end_reruns/1374a_arg1_classes_bsd_20261109_124849.txt |
| 2026-11-09 12:57 | 1374a | second attempt with the three doc NO_OUTPUT numbers skipped hangs at syscall 93 instead, so the BSD range blocks in more than one place and cannot be swept in one thread | hung at marker Z93; 95/432/530 already skipped; loader accepts TCP and returns 0 bytes afterwards | V | results/phase35_dead_end_reruns/1374a_arg1_classes_bsd_20261109_125432.txt |
| 2026-11-09 13:01 | 1375a | - | - | ? | results/phase35_dead_end_reruns/1375a_arg1_sweep_threaded_20261109_130102.txt |
| 2026-11-09 13:03 | 1376a | arg1 = a mapped user page over 1-73: most of the BSD range is nosys (errno 78), the identity calls answer (getpid 278, getppid 54, getuid/geteuid/getegid/getgid 1), compat10.pipe returns 22, and mprotect (74) faults the caller on a mapped heap page with len 0 and prot 0 | n=2..73 measured; died inside 74 (mprotect); sigign 10/10 held | M | results/phase35_dead_end_reruns/1376a_arg1_user_sweep_20261109_130223.txt |
| 2026-11-09 13:05 | 1376b | arg1 = mapped user page over 75-340 classifies the BSD range: 212 numbers are nosys (errno 78), 123 are real handlers with specific errnos (socket EAFNOSUPPORT, ioctl ENOTTY, kill ESRCH, madvise/mincore/mlock/msync/poll/sync return 0), and sigsuspend (341) blocks by design | 265 numbers measured, stopped at n=341 (sigsuspend); loader wedged | M | results/phase35_dead_end_reruns/1376b_arg1_user_sweep_75_20261109_130404.txt |
| 2026-11-09 13:07 | 1376c | sigpending (343) copies out four zero dwords for a null sigset argument; sigtimedwait (345) blocks with a null timeout, so the wait family 346/359/363/402/429/441/522 and 417 are skipped | 342 ENOSYS, 343 rv=0 wrote 4 dwords, stopped at 345 | M | results/phase35_dead_end_reruns/1376c_arg1_user_sweep_342_20261109_130627.txt |
| 2026-11-09 13:09 | 1376d | getcontext (421) is a working 280-byte context copyout to a caller buffer and ksem_init/ksem_open (404/405) accept a real pointer and write an id; thr_exit (431) ends the loader's own thread, so the threading family is skipped | 79 numbers measured 346-430, stopped at 431 (thr_exit) | M | results/phase35_dead_end_reruns/1376d_arg1_user_sweep_346_20261109_130840.txt |
| 2026-11-09 13:25 | 1376e | 433-531 is entirely nosys: 433 is the last real handler (ESRCH) and every number above it is ENOSYS with SIGSYS ignored, so the BSD-native range has no handler past 430 | 88 numbers 433-531, 0 non-negative, all errno 78 | M | results/phase35_dead_end_reruns/1376e_arg1_user_sweep_433_20261109_132246.txt |
| 2026-11-09 13:25 | 1377a | the five BSD copy-out handlers (116/343/404/405/421) answer EFAULT for a supervisor destination, so the destination predicate holds and the range holds no kernel read | 24 live rows, 12 identical, 5 EFAULT wrote=0, 65/75 EINVAL, 78 ENOMEM | M | results/phase35_dead_end_reruns/1377a_arg1_kernel_class_bsd_20261109_132333.txt |
| 2026-11-09 13:27 | 1378a | - | - | ? | results/phase35_dead_end_reruns/1378a_sys677_sigign_20261109_132716.txt |
| 2026-11-09 13:28 | 1379a | - | - | ? | results/phase35_dead_end_reruns/1379a_dev_write_gate_20261109_132830.txt |
| 2026-11-09 13:29 | 1380a | - | - | ? | results/phase35_dead_end_reruns/1380a_dev_bt_camera_write_20261109_132901.txt |
| 2026-11-09 13:30 | 1381a | - | - | ? | results/phase35_dead_end_reruns/1381a_hmd2_cmd_sweep_20261109_133040.txt |
| 2026-11-09 13:31 | 1382a | - | - | ? | results/phase35_dead_end_reruns/1382a_hmd2_bc_ladder_20261109_133124.txt |
| 2026-11-09 13:34 | 1383a | 601's 14.10 command table is reduced and gated: 0x00 arg1 is the output buffer, 0x01 copies 16 bytes from arg1 and answers EINVAL, 0x02/0x05/0x06 are ENOSYS, 0x0A is EPERM, and 0x0C blocks the caller forever rather than killing | 0x00 a1 rv=0 writes 0x100+0; 0x01 a1 EINVAL(22) / 0/0 EFAULT(14); 0x07,0x09,0x0B rv=0; 0x0C IDLE_TIMEOUT with the connection open | M | results/phase35_dead_end_reruns/1383a_sys601_shape_matrix_20261109_133353.txt |
| 2026-11-09 14:00 | 1383b | 601's 14.10 table: 0x0D returns 0 silently, 0x0E writes two zero dwords only when arg1 is a buffer, 0x0F EPERM, 0x10 EINVAL, and 0x11 with arg2 non-null kills the process | 0x0D rv=0 all shapes; 0x0E 0/0 EFAULT(14) but a1 rv=0 wrote 2 dwords; 0x0F EPERM(1); 0x10 EINVAL(22); 0x11 0/0 EFAULT(14), a1 EINVAL(22), a2 -> CONNECTION_REFUSED after 8.8 s | M | results/phase35_dead_end_reruns/1383b_sys601_shape_matrix2_20261109_135948.txt |
| 2026-11-09 14:00 | 1384a | - | - | ? | results/phase35_dead_end_reruns/1384a_sys601_cmd01_payload_20261109_140049.txt |
| 2026-11-09 14:01 | 1384a | 601 cmd 0x01 is EINVAL for every flags word and every 16-byte struct shape tried, and its twin 0x24 is EPERM for all of them, so the 13.60 flags-word model does not reproduce on 14.10 | 32 flags x 24 struct shapes: 0x01 EINVAL(22) in every case, 0x24 EPERM(1) in every case; 0x12 with arg1=buffer arg2=0 is EINVAL(22) | M | results/phase35_dead_end_reruns/1384a_sys601_cmd01_payload_20261109_140135.txt |
| 2026-11-09 14:02 | 1387a | - | - | ? | results/phase36_realargs/1387a_bsd_realargs_leak_sweep_20261109_140206.txt |
| 2026-11-09 14:04 | 1385a | Opening every /dev node the process can open does not install the 601 attach object: 0x01-adjacent commands answer identically before, during and after | 0x00 rv=0 writes 0x100, 0x0A EPERM(1), 0x0E EFAULT(14), 0x12 EFAULT(14), 0x13 rv=0 - identical with 0, 14 and 2 descriptors open | M | results/phase35_dead_end_reruns/1385a_sys601_attach_by_open_20261109_140401.txt |
| 2026-11-09 14:06 | 1387a | The real-descriptor sweep is still blocked by process-control numbers: 1 is exit and 2 is fork, both fatal to the loader, so the sweep now skips them | run 1 died at n=1, run 2 died at n=2 after 8.8 s; skip set now includes 0,1,2 plus the 1376a-1376e union | V | results/phase36_realargs/1387a_bsd_realargs_leak_sweep_20261109_140419.txt |
| 2026-11-09 14:08 | 1388a | - | - | ? | results/phase35_dead_end_reruns/1388a_sys601_cmd12_consumer_20261109_140806.txt |
| 2026-11-09 14:09 | 1389a | 601 cmd 0x12 is not reachable on 14.10 with any identifier-shaped 0x20-byte block, and its consumer sweep finds no writer beyond the known zero-dword 0x0E/0x1A paths | 12 identifier shapes + 4 pointer shapes: rv=-1 every time (EFAULT when block+8 is zero, ENOENT otherwise); consumer sweep 0x00/0x0E/0x1A write only zero dwords | M | results/phase35_dead_end_reruns/1389a_sys601_cmd12_ids_20261109_140845.txt |
| 2026-11-09 14:10 | 1390a | The /dev read path is closed as well: only /dev/usb returns data (280 bytes of USB descriptors) and every other node answers ENOTTY or a Sony error, with fstat returning an ordinary 120-byte stat record | usb read rv=280 descriptor bytes; 17 nodes ENOTTY(19); hmd_cmd 0x81110106, hmd2_cmd 0x8a721006, camera 0x802e0010; fstat rv=0 with mode 0x000021A4-0x000021FF and no kernel qword | M | results/phase35_dead_end_reruns/1390a_dev_read_path_20261109_140949.txt |
| 2026-11-09 14:10 | 1331a | - | - | ? | results/1331a_20261109_141053.txt |
| 2026-11-09 14:12 | 1391a | No syscall in 532..676 treats an argument as a kernel pointer: a mapped supervisor page and an absent one produce identical returns, errnos and buffers everywhere | 131 numbers x 3 kernel classes: zero differences; 532(0x2F) copies only the constant status 0x800D0210 into a user out-pointer after a failed copyin | M | results/phase35_dead_end_reruns/1391a_kernel_arg_sweep_20261109_141210.txt |
| 2026-11-09 14:13 | 1392a | A user struct whose contents are kernel addresses produces no kernel-band output anywhere in 532..676, so no handler feeds a struct-embedded pointer to an unchecked kernel read | 131 numbers x 2 patterns, zero kernel-band dwords; only 557 differs (handle 16901 vs 518); 532 dispatcher writes only its status word | M | results/phase35_dead_end_reruns/1392a_struct_smuggle_20261109_141321.txt |
| 2026-11-09 14:14 | 1393a | - | - | ? | results/phase35_dead_end_reruns/1393a_sys601_cmd11_kernel_arg2_20261109_141450.txt |
| 2026-11-09 14:15 | 1394a | - | - | ? | results/phase35_dead_end_reruns/1394a_sys601_cmd11_field_deref_20261109_141535.txt |
| 2026-11-09 14:17 | 1395a | - | - | ? | results/phase35_dead_end_reruns/1395a_dev_mmap_offset_wrap_20261109_141728.txt |
| 2026-11-09 14:18 | 1395a | Device mmap is bounded by offset and the address map, but /dev/gc and /dev/dmem0/1 do map pages a game process can read, and dmem0 at offset 0 exposes the GPU register block while /dev/gc reads all-ones | dmem0/dmem1 off=0 reads 80000000C0012800 80000000 80000000 C0001200... (GPU regs), off=0x1000 zeros, >=0x10000000 refused; /dev/gc off 0 and 0x1000 map and read 0xFFFFFFFF, larger offsets EINVAL; dmem2/dce refuse all; MAP_FIXED at kernel addrs EINVAL; wrapping lengths EINVAL | M | results/phase35_dead_end_reruns/1395a_dev_mmap_offset_wrap_20261109_141742.txt |
| 2026-11-09 14:21 | 1396a | blockpool_open(653) mints live file descriptors for a game process on 14.10 -- fd 22 / 23 / 527 for flags 0 / 0x100000 / 0x400000, EMFILE for 0x500000, EINVAL outside the 0x100000\|0x400000 mask -- so every earlier '653(0) = 22 EINVAL' reading was a descriptor number misread as an errno | 653(0)=22 653(0x100000)=23 653(0x400000)=527 653(0x500000)=-1/EMFILE(24) 653(1\|0x200000\|0x1000\|0x10000000)=-1/EINVAL; fstat and mmap(0x40000,PROT_RW,SHARED,off 0) on each descriptor refuse EINVAL; 657(fd)=0 | M | results/phase36_realargs/1396a_blockpool_open_20261109_142118.txt |
| 2026-11-09 14:22 | 1397a | - | - | ? | results/phase36_realargs/1397a_blockpool_map_probe_20261109_142241.txt |
| 2026-11-09 14:23 | 1398a | - | - | ? | results/phase36_realargs/1398a_blockpool_type_hunt_20261109_142336.txt |
| 2026-11-09 14:24 | 1399a | - | - | ? | results/phase36_realargs/1399a_blockpool_device_20261109_142445.txt |
| 2026-11-09 14:36 | 1396b | dmem0/dmem1 are two descriptors on one writable backing store: a store at offset 0x1000 is visible through a second mapping and through dmem1 | store landed, both readers saw it; prot 3 at offsets 0 and 0x1000 | M | results/phase36_realargs/1396b_dev_map_writable_20261109_142603.txt |
| 2026-11-09 14:36 | 1397b | every dmem0 offset 0..0x10000000 maps with both prot 1 and prot 3; 1395a's EINVAL was an argument-shape artifact | all rungs mapped; rung 0x1000 held the 1396b marker, rest zero | M | results/phase36_realargs/1397b_dmem_offset_ladder_20261109_142645.txt |
| 2026-11-09 14:36 | 1397c | the prot=1 mapping of a dmem page faults on store, so the window is only writable with prot 3 | death on store into prot=1 map; capture tail is the loader mcontext dump | M | results/phase36_realargs/1397c_dmem_ladder_contents_20261109_142729.txt |
| 2026-11-09 14:36 | 1397d | dmem0 offsets to 4 GiB map, 8 GiB and up give EACCES, single mappings to 2 GiB succeed, and page 0 is a structured table not flat registers | 0x100000000 mapped, 0x200000000 EACCES(13); 48 records at 0x800 stride 0x14 | M | results/phase36_realargs/1397d_dmem_extent_regs_20261109_142819.txt |
| 2026-11-09 14:36 | 1397e | dmem offsets are contiguous 4 KiB rungs of one allocation and page 0 is a static header, not live metadata for the window | marker written at rung 0x2000 appeared at second mapping +0x1000; page 0 unchanged | M | results/phase36_realargs/1397e_dmem_page0_liveness_20261109_142921.txt |
| 2026-11-09 14:36 | 1397f | only 12 of the first 256 dmem pages are non-zero, and a 16 MiB-granular scan of the whole 4 GiB finds exactly one populated rung (offset 0) | pages 0x000, 0x001-0x004 our markers, 0x00F, 0x011-0x016; 1 of 256 rungs non-zero | M | results/phase36_realargs/1397f_dmem_content_map_20261109_143000.txt |
| 2026-11-09 14:36 | 1397g | the populated dmem block at 0xF000 holds BEEB03FF records plus the ASCII string 'OrbisMemory ONION', and page 0x17000 faults even inside a mapping that spans it | structure at 0xF000/0x103C0/0x11000; fault on 0x17000 read | M | results/phase36_realargs/1397g_dmem_f000_dump_20261109_143115.txt |
| 2026-11-09 14:36 | 1397h | the block-liveness probe died in its own diff loop before producing a comparison, so it carries no measurement | Lua error: attempt to index field '?' (a number value) at line 101 | V | results/phase36_realargs/1397h_dmem_block_liveness_20261109_143213.txt |
| 2026-11-09 14:36 | 1397i | the populated dmem block is byte-identical across a 1.5 s sleep, and the pages this session wrote are zero again after the process changed, so the allocation is per-process while the populated structures are kernel-initialised | 0 of 23 pages changed; markers from 1396b gone at pid 357 | M | results/phase36_realargs/1397i_dmem_block_checksum_20261109_143254.txt |
| 2026-11-09 14:36 | 1397j | page 0 of the dmem window is ordinary writable RAM: a store into its zero tail lands, survives 500 ms, and is visible through a fresh mapping while the populated records stay untouched | +0xBF0 AAAA5555/11112222 read back through a second mapping; page 16 +0xF00 BBBB6666 | M | results/phase36_realargs/1397j_dmem_page0_write_20261109_143351.txt |
| 2026-11-09 14:36 | 1397k | the dmem 0x800 record table is descriptive only: rewriting record[0].addr and remapping leaves offset 0x000 unchanged, and the table ends at record 47 | offset 0x000 still C0012800/80000000 after C0038000->C0039000 and ->0; last non-zero record 47 | M | results/phase36_realargs/1397k_dmem_record_steer_20261109_143442.txt |
| 2026-11-09 14:36 | 1397l | the records do not steer the 0xF000 window: pointing record[0] at the next physical chunk or at zero changes nothing after munmap/mmap | 0xF000 reads BEEB03FF... before, after C0039000, after 0x00000000, and after restore | M | results/phase36_realargs/1397l_dmem_steer_f000_20261109_143526.txt |
| 2026-11-09 14:42 | 1400a | 601 cmd 0x11 kills the process even with an all-zero struct, so its body dereferences a field the caller cannot supply safely: every shape tried is lethal | death after 'calling 601(0x11,0,page)' with a zeroed page; 184-byte capture | M | results/phase36_realargs/1400a_sys601_cmd11_struct_20261109_144119.txt |
| 2026-11-09 15:18 | 1401a | - | - | ? | results/phase36_realargs/1401a_sys601_cmd12_errno_20261109_151844.txt |
| 2026-11-09 15:23 | 1401a | 601 cmd 0x12 on 14.10: a null arg1 answers EFAULT, a mapped arg1 answers EINVAL, so a content-independent gate sits after the pointer check | 12(0,x)=EFAULT(14); 12(addr,x)=EINVAL(22); copyin bounds exact at addr+0x10000-0x08 | M | results/phase36_realargs/1401a_sys601_cmd12_errno_20261109_151911.txt |
| 2026-11-09 15:23 | 1402a | 601 cmd 0x12's EINVAL does not depend on any single struct qword or on arg2, so the gate reads process state rather than caller data | 60 shapes, all EINVAL(22); q1-q3 over {1..0xFFFFFFFF}; arg2 over {0,1,8,0x100,0x4000,page} | M | results/phase36_realargs/1402a_sys601_cmd12_field_gate_20261109_152003.txt |
| 2026-11-09 15:23 | 1403a | 601 errno map for 22 commands plus the discovery that 0x12(0,mapped) answers ENOENT, so EFAULT comes from the destination and EINVAL is a range rejection of arg1 | 0x12(0,out)=ENOENT(2) ch=0; 0x0A/0x0F/0x18=EPERM; 0x02/0x05/0x06/0x16/0x17=ENOSYS; 0x10/0x15=EINVAL; died at cmd 0x1C | M | results/phase36_realargs/1403a_sys601_write_dest_map_20261109_152155.txt |
| 2026-11-09 15:25 | 1404a | - | - | ? | results/phase36_realargs/1404a_sys601_cmd12_index_20261109_152525.txt |
| 2026-11-09 15:25 | 1405a | - | - | ? | results/phase36_realargs/1405a_sys601_cmd12_field_20261109_152556.txt |
| 2026-11-09 15:26 | 1406a | - | - | ? | results/phase36_realargs/1406a_sys601_cmd12_qword8_20261109_152629.txt |
| 2026-11-09 15:26 | 1407a | - | - | ? | results/phase36_realargs/1407a_sys601_cmd12_key_class_20261109_152658.txt |
| 2026-11-09 15:27 | 1408a | - | - | ? | results/phase36_realargs/1408a_sys601_producer_map_20261109_152747.txt |
| 2026-11-09 15:29 | 1409a | - | - | ? | results/phase36_realargs/1409a_637_dmem_ceiling_20261109_152907.txt |
| 2026-11-09 15:33 | 1413a | - | - | ? | results/phase36_realargs/1413a_dmem_ioctl_acl_20261109_153304.txt |
| 2026-11-09 15:35 | 1409a | 637 does not move the dmem window: 637(0,0xFFFFFFFFFFFFF000) answers EINVAL and every offset keeps its previous answer | 637=-1 errno=22; offsets unchanged | M | results/phase36_realargs/1409a_637_dmem_ceiling_20261109_152941.txt |
| 2026-11-09 15:35 | 1410a | the dmem offset space is two ACL windows, not a ceiling: 4 GiB contiguous plus a lone rung at exactly 0x1000000000 | 6 of 513 rungs map; first refusal 0x140000000 | M | results/phase36_realargs/1410a_dmem_offset_space_20261109_153054.txt |
| 2026-11-09 15:35 | 1411a | dmem mmap validates offset+length, and the 64 GiB window is granted read-only (prot 0/1 only) | off=0,len=0x140000000 -> EACCES; 64 GiB prot=3 -> EACCES | M | results/phase36_realargs/1411a_dmem_range_check_20261109_153133.txt |
| 2026-11-09 15:35 | 1412a | the 64 GiB dmem window is read-only, ~16-64 MiB wide, and reads as zeros except +0x120=2 | 1 of 256 dwords non-zero; prot 2/3/5/7/0x13 all EACCES | M | results/phase36_realargs/1412a_dmem_64g_window_20261109_153207.txt |
| 2026-11-09 15:35 | 1413a | every /dev/dmem ioctl in the 0x80 group answers EPERM and no /dev/dmem/cntN node exists | 10 commands all -1 errno=1 | M | results/phase36_realargs/1413a_dmem_ioctl_acl_20261109_153310.txt |
| 2026-11-09 15:35 | 1414a | the dmem node has no read or write path at all - pread/pwrite answer ENXIO at every offset including ones mmap refuses | rv=-1 errno=19 for 0/0x1000/0x120000000/0x1000000000 | M | results/phase36_realargs/1414a_dmem_readwrite_offsets_20261109_153451.txt |
| 2026-11-09 15:36 | 1415a | - | - | ? | results/phase36_realargs/1415a_sys601_sequence_20261109_153605.txt |
| 2026-11-09 15:43 | 1416a | - | - | ? | results/phase36_realargs/1416a_blockpool_open_20261109_154348.txt |
| 2026-11-09 15:45 | 1417a | - | - | ? | results/phase36_realargs/1417a_blockpool_descriptor_20261109_154513.txt |
| 2026-11-09 15:48 | 1418a | - | - | ? | results/phase36_realargs/1418a_sys673_remap_shape_20261109_154819.txt |
| 2026-11-09 15:51 | 1419a | - | - | ? | results/phase36_realargs/1419a_sys628_container_sweep_20261109_155132.txt |
| 2026-11-09 15:53 | 1420a | - | - | ? | results/phase36_realargs/1420a_cold_628_and_pool_fd_20261109_155321.txt |
| 2026-11-09 15:55 | 1421a | - | - | ? | results/phase36_realargs/1421a_umtx_kernel_addr_20261109_155519.txt |
| 2026-11-09 15:59 | 1422a | the 14.10 sysent ends at 676: every number 677-735 and every out-of-range value answers ENOSYS(78) with SIGSYS ignored, while 676 answers EINVAL, so 275b's 'sysent extends past 676' banner is wrong | 677-735 all -1/ENOSYS; 676 -1/EINVAL; controls 568 nosys, 596 rv=0, 557 rv=0x4205 | M | results/phase36_realargs/1422a_sysent_tail_errno_20261109_155915.txt |
| 2026-11-09 16:01 | 1423a | the only socket families a game process can create are AF_UNIX, AF_INET, AF_ROUTE and AF_INET6 - families 3-27 and 29-45 all answer EAFNOSUPPORT(47) with type 1/2/3 | 1/2/17/28 open; AF_NETGRAPH(32) and every other family -1 EAFNOSUPPORT; family numbering per FreeBSD 11 sys/socket.h (28=INET6 not NATM) | M | results/phase36_realargs/1423a_af_space_20261109_160029.txt |
| 2026-11-09 16:01 | 1424a | PF_KEY(27), bluetooth(36), ATM(30), netgraph(32), SDP(40/42) and AF_LINK(18) are all absent; a non-zero protocol does not open any of them, and AF_UNIX SOCK_SEQPACKET(5) does open | 20 family/proto pairs all -1 EAFNOSUPPORT(47); (1,5,0) fd=34 and fd=35; (1,4,0) EPROTOTYPE(41) | M | results/phase36_realargs/1424a_socket_family_matrix_20261109_160101.txt |
| 2026-11-09 16:11 | 1426a | - | - | ? | results/phase36_realargs/1426a_range_predicate_wrap_20261109_161120.txt |
| 2026-11-09 16:14 | 1426a | Address+length wraparound is rejected by the user-range predicate: every wrap shape returns EFAULT, so no read-only call can be aimed at a kernel address. | write 0xFFFFFFFFC1000000+0x3F000000 (sum 0) EFAULT; stub+0x40000000 EFAULT; sendto and kevent wrap EFAULT; getsockopt dest at kernel base EFAULT; controls copy 64 bytes | M | results/phase36_realargs/1426a_range_predicate_wrap_20261109_161403.txt |
| 2026-11-09 16:20 | 1427a | - | - | ? | results/phase36_realargs/1427a_msfilter_readback_20261109_162035.txt |
| 2026-11-09 16:21 | 1427a | - | - | ? | results/phase36_realargs/1427a_msfilter_readback_20261109_162121.txt |
| 2026-11-09 16:22 | 1427a | - | - | ? | results/phase36_realargs/1427a_msfilter_readback_20261109_162242.txt |
| 2026-11-09 16:25 | 1428a | - | - | ? | results/phase36_realargs/1428a_msfilter_readback_count_20261109_162551.txt |
| 2026-11-09 16:26 | 1428a | - | - | ? | results/phase36_realargs/1428a_msfilter_readback_count_20261109_162620.txt |
| 2026-11-09 16:26 | 1428a | - | - | ? | results/phase36_realargs/1428a_msfilter_readback_count_20261109_162635.txt |
| 2026-11-09 16:27 | 1429a | - | - | ? | results/phase36_realargs/1429a_msfilter_overread_20261109_162726.txt |
| 2026-11-09 16:39 | 1433a | - | - | ? | results/phase36_realargs/1433a_msfilter_ifindex_family_20261109_163942.txt |
| 2026-11-09 16:40 | 1432a | the getsockopt(41,74) reply tail is a kernel zero-fill, not a recycled allocation: claim=128 on a 1-source group returns zeros even after 512 KiB of tagged 16 KiB filter blocks were freed into that size bucket | B: claim=128 on a 128-src group -> 127 populated entries (tags A0@1..); C: after shrink to 1 src -> numsrc=1, headers=0, nonzero=0; D: after 32x128-src churn + leave -> headers=0, nonzero=0; E control claim=1 -> 32 changed dwords | M | results/phase36_realargs/1432a_msfilter_tail_reuse_20261109_163702.txt |
| 2026-11-09 16:40 | 1433a | IPV6_MSFILTER validates msfr_ifindex and both sockaddrs; no unchecked index and no cross-family confusion | GET/SET: only ifindex 1 returns 0, 2/3/4/0x10/0xFF/0xFFFF/0x10000/0x1000000/0x7FFFFFFF/0xFFFFFFFF all -1 with no crash; group family 28 + ss_len 28 -> 0, families 0/1/2/255 and ss_len 0/1/16/255 -> -1; source family 28 + ss_len 28 -> 0, all others -1 | M | results/phase36_realargs/1433a_msfilter_ifindex_family_20261109_163958.txt |
| 2026-11-09 16:42 | 1434a | - | - | ? | results/phase36_realargs/1434a_ip_mcast_surface_20261109_164208.txt |
| 2026-11-09 16:42 | 1434a | - | - | ? | results/phase36_realargs/1434a_ip_mcast_surface_20261109_164217.txt |
| 2026-11-09 16:46 | 1436a | - | - | ? | results/phase36_realargs/1436a_mmap_dmem_phys_sweep_20261109_164602.txt |
| 2026-11-09 16:49 | 1434a | The IPv4 multicast surface is live: ip_mreq join succeeds with an interface ADDRESS (0 or 127.0.0.1), not an index | join=0, second join EADDRINUSE(48), drop=0; IP_MSFILTER needs ifindex 3 | M | results/phase36_realargs/1434a_ip_mcast_surface_20261109_164244.txt |
| 2026-11-09 16:49 | 1435a | IPv4 IP_MSFILTER works with msfr_ifindex=3: set and get answer 0, numsrc is exact and the reply is n*128 bytes | n=1/2/8/128 -> changed 32/64/256/4096 dwords, d0=0x00000210 | M | results/phase36_realargs/1435a_ip_msfilter_ifindex_20261109_164339.txt |
| 2026-11-09 16:49 | 1436a | 628 mmap_dmem answers EBUSY for every container index 0..20 and EINVAL for 21+ | -1 errno=16 for idx 0..20, errno=22 for idx 21; no physical address maps | M | results/phase36_realargs/1436a_mmap_dmem_phys_sweep_20261109_164617.txt |
| 2026-11-09 16:49 | 1437a | Opening and mapping /dev/dmem0/dmem1 does not change the 628 refusal: EBUSY is process-container state, not the descriptor | still -1 errno=16 for all phys and idx after open+mmap | M | results/phase36_realargs/1437a_mmap_dmem_descriptor_20261109_164725.txt |
| 2026-11-09 16:49 | 1438a | dmem window writes do not survive the process: the 1397j markers are zeroed and the ONION header regenerates byte-identical | 0xBF0=0, 0x16F00=0, 0xF000=BEEB03FF 00000003 | M | results/phase36_realargs/1438a_dmem_marker_persistence_20261109_164756.txt |
| 2026-11-09 16:49 | 1439a | The IPv4 msfilter set path validates before swapping: every rejected list leaves the previous group list intact | bad family EAFNOSUPPORT(47), bad len EINVAL(22), numsrc stays 2 after all seven shapes | M | results/phase36_realargs/1439a_ip_msfilter_bad_entry_20261109_164928.txt |
| 2026-11-09 16:49 | 1439a | - | - | ? | results/phase36_realargs/1439a_ip_msfilter_bad_entry_20261109_164901.txt |
| 2026-11-09 16:49 | 1439a | - | - | ? | results/phase36_realargs/1439a_ip_msfilter_bad_entry_20261109_164912.txt |
| 2026-11-09 16:54 | 1440a | madvise is inert on device-pager pages: all nine advice codes and sub-page lengths leave every marker intact, so the CVE-2026-49418 page-removal path is not reachable through madvise either | 9/9 advice codes rv=0, 0 markers changed; whole-mapping DONTNEED intact=64 zeroed=0 | M | results/phase36_realargs/1440a_madvise_device_pager_20261109_165141.txt |
| 2026-11-09 16:54 | 1441a | the 64 GiB dmem window is 2 pages wide and enforces read-only through mprotect (EACCES for prot 2/3/5/7), while the low window accepts a post-mmap mprotect to RW; a store to the read-only page faults and the loader's SIGSEGV handler catches it without killing the process | window = 64 GiB + {0, 0x1000000}; mprotect(3/2/5/7) = EACCES; low-window control mprotect(3) = 0 with store landing | M | results/phase36_realargs/1441a_mprotect_device_window_20261109_165212.txt |
| 2026-11-09 16:54 | 1442a | the GPU MMIO aperture is not reachable through the dmem identity map: every page around 0x80000000 and 0xC0000000 reads zero, and 0x800000000 and above answer EACCES | 30 offsets mapped, nz=0 on all but the two control rungs; 3 offsets EACCES | M | results/phase36_realargs/1442a_dmem_mmio_aperture_20261109_165321.txt |
| 2026-11-09 16:54 | 1443a | with the correct mmap shape /dev/gc still exposes exactly two pages (offset 0 and 0x1000, all 0xFFFFFFFF), /dev/dce exposes none and /dev/ajm refuses open | gc 2 offsets map, 13 EINVAL; dce 0 of 15; ajm open = -1 | M | results/phase36_realargs/1443a_graphics_node_offsets_20261109_165418.txt |
| 2026-11-09 16:59 | 1444a | the 64 GiB read-only device window is at least 32 MiB of zeros with one non-zero dword (+0x120 = 2); it exposes no device state | mapped=128 of 128 samples at 256 KiB stride, 1 non-zero dword in the whole scan | M | results/phase36_realargs/1444a_high_window_scan_20261109_165553.txt |
| 2026-11-09 17:06 | 1446a | - | - | ? | results/phase36_realargs/1446a_select_fdset_bound_20261109_170651.txt |
| 2026-11-09 17:08 | 1446b | - | - | ? | results/phase36_realargs/1446b_select_fdset_guard_20261109_170830.txt |
| 2026-11-09 17:13 | 1446a | select/pselect accept nfds and leave the fd_set untouched when the bitmap is all-set (EBADF first), and select(0xFFFFFFFFFFFFFFFF,...) returns 0 rather than EINVAL | EBADF on every nfds, changed=4 dwords (timeval only); select(8) and pselect(8) both 3 | M | results/phase36_realargs/1446a_select_fdset_bound_20261109_170718.txt |
| 2026-11-09 17:13 | 1446b | V from munmap: the guard-page instrument was invalid because syscall 73 removes the whole mapping, so the bitmap page itself disappeared | EFAULT at every nfds; capture carries a raw mcontext dump | V | results/phase36_realargs/1446b_select_fdset_guard_20261109_170934.txt |
| 2026-11-09 17:13 | 1446c | V: same invalid instrument, the mapping was gone before the first measurement line | binary mcontext dump, 0x13371337 then 0x0b (SIGSEGV) | V | results/phase36_realargs/1446c_select_fdset_len_20261109_171018.txt |
| 2026-11-09 17:13 | 1446d | munmap(73) on 14.10 destroys the whole mmap region, not the requested page: after munmap(base+0x3000,0x1000) returns 0 a read at base faults | steps 1-11 all succeed, step 12 faults at base | M | results/phase36_realargs/1446d_instrument_selftest_20261109_171122.txt |
| 2026-11-09 17:13 | 1446e | select(93)/pselect(522) do NOT clamp nfds to FD_SETSIZE: the fd_set copy length is nfds/8, measured by an EFAULT that appears exactly when nfds/8 exceeds the mapped region | 64KiB region: nfds<=524288 rv=0, nfds=1048576 and 4194304 EFAULT(14); 4MiB region: nfds=8388608 rv=0 | M | results/phase36_realargs/1446e_select_fdset_span_20261109_171239.txt |
| 2026-11-09 17:13 | 1445a | AIO ids are 13-bit slot plus a 3-bit per-slot generation that increments on every reuse (slot 0x20C: gen 0 on first use, gen 1 after the delete) and concurrent submits get sequential slots, while a second 662 on the same ids returns 0x80020003 | 8 concurrent submits slots 517-524; 662 #1 all 0, 662 #2 all 0x80020003; reuse of 524 gave 0x220C | M | results/phase36_realargs/1445a_aio_id_generation_20261109_171255.txt |
| 2026-11-09 17:28 | 1451a | - | - | ? | results/phase36_realargs/1451a_sys673_object_type_20261109_172807.txt |
| 2026-11-09 17:28 | 1451a | - | - | ? | results/phase36_realargs/1451a_sys673_object_type_20261109_172818.txt |
| 2026-11-09 17:29 | 1448a | probe 1448a called syscall 166 (rtprio) instead of 165 (sysarch) and the first call killed the process, so the sysarch family was never exercised | died at 166(128,struct); 166 is rtprio in docs/sysent-names-13.60.csv | V | results/phase36_realargs/1448a_sysarch_family_20261109_171956.txt |
| 2026-11-09 17:29 | 1449a | sysarch(165) cmd 132 (GET_XFPUSTATE) takes a {addr,len} parms struct, copies at most 0x200 bytes then answers EINVAL; cms 128/129/130/131 behave and 133-140 are EINVAL | 132 len 0x40/0x200 rv=0 full write (xstate_bv 7), len 0x240+ EINVAL | M | results/phase36_realargs/1449a_sysarch_xfpustate_20261109_172134.txt |
| 2026-11-09 17:29 | 1450a | munmap(73) removes the entire vm_map_entry that contains addr, not the requested sub-range; a partial munmap of one region leaves a neighbouring region intact | [A][B][C] all 4 pages unmapped after one-page munmap; [D] second region still mapped | M | results/phase36_realargs/1450a_munmap_semantics_20261109_172529.txt |
| 2026-11-09 17:29 | 1451a | sys 673 rejects an anonymous, a /dev/zero and a /dev/dmem0 mapping with EINVAL for every 64 KiB-aligned shape, so its vm_object type-11 gate is unreachable from anything a game process can map | 6 shapes x 3 flavours, 0 accepted, all rv=-1 EINVAL(22) | M | results/phase36_realargs/1451a_sys673_object_type_20261109_172829.txt |
| 2026-11-09 17:40 | 1453a | Writes through /dev/dmem0 land and read back at three offsets (0xF000+0x20 replacing 5362724F, page0+0xBF0, page16+0xF00), and the ONION header bytes are byte-identical to the pid-357 captures | 3/3 writes land; pid=439 | M | results/phase36_realargs/1453a_dmem_persist_write_20261109_174007.txt |
| 2026-11-09 17:40 | 1454a | The 1453a signatures read back, but both runs report pid 439, so the loader did not spawn a new process and cross-process persistence is still unmeasured | 3/3 survived in the SAME pid; persistence test confounded | M | results/phase36_realargs/1454a_dmem_persist_read_20261109_174019.txt |
| 2026-11-09 17:41 | 1452a | A loader Lua thread that faults on an unmapped address takes the whole process down: the handler dumps its mcontext to the socket and the connection then dies, so loader threads are not fault containers and no race can be built on a faulting child | MAIN-1 then a 216-byte truncated mcontext dump (sig 0x13371337, signo 0x0B, fault VA 0x7FFFFF000000, error word 5 = present supervisor) then CONNECTION_REFUSED | M | results/phase36_realargs/1452a_fault_teardown_race_20261109_174104.txt |
| 2026-11-09 17:44 | 1455a | /dev/dmem0 is a per-process copy: after the loader pid changed 439 -> 446 every signature written by 1453a is gone and 0xF000+0x20 is back to the original 5362724F, so the window is not a cross-process write path | survived=0/3, pid 446 vs 439, 0xF000+0x20 back to 5362724F | M | results/phase36_realargs/1455a_dmem_persist_after_restart_20261109_174425.txt |
| 2026-11-09 17:44 | 1456a | - | - | ? | results/phase36_realargs/1456a_kernel_readable_20261109_174438.txt |
| 2026-11-09 17:45 | 1457a | - | - | ? | results/phase36_realargs/1457a_kernel_readable_thrcreate_20261109_174540.txt |
| 2026-11-09 17:49 | 1457a | the thr_create(430) harness runs the ROP chain (control stored 0x41424344) but every spawn after that chained child ends the process, so the readability targets it was built to test are unmeasured | control marker 0x41424344, died at the first kernel target (C0000000) | M | results/phase36_realargs/1457a_kernel_readable_thrcreate_20261109_174702.txt |
| 2026-11-09 17:49 | 1458a | a plain 1331a-style FETCH fault at 0xFFFFFFFFC0000000 ends the process when a chained child has already run in the same process, so the earlier containment was a property of the fault-only loop, not of faults in general | control OK 0x41424344; the 1331a repeat fetch fault produced a context dump and the process died | M | results/phase36_realargs/1458a_first_insn_data_fault_20261109_174839.txt |
| 2026-11-09 17:49 | 1459a | - | - | ? | results/phase36_realargs/1459a_fault_poison_isolation_20261109_174957.txt |
| 2026-11-09 17:52 | 1460a | 601 command 0x12 still answers EINVAL with the 13.60 magic 0xa0020102 in arg1, arg2 or neither, so the 14.10 gate sits before the magic compare and the caller-struct branch remains unreachable | 0x12 = -1 EINVAL for magic in arg1, byte-swapped, and struct-first; 0x11 also EINVAL; control 0x00 rv=0 writes 0x100 | M | results/phase36_realargs/1460a_sys601_magic_tag_20261109_175209.txt |
| 2026-11-09 17:53 | 1461a | 601 commands 0x0D-0x10 answer without writing to the caller buffer (0x0D rv=0, 0x0E EFAULT, 0x0F EPERM, 0x10 EINVAL) and 0x11 kills the process whenever arg2 is a mapped user page, so 0x11 is lethal in every shape tried | 0x0D=0, 0x0E=-1 EFAULT, 0x0F=-1 EPERM, 0x10=-1 EINVAL, 0x11 = death (sweep stopped there) | M | results/phase36_realargs/1461a_sys601_matrix_tail_20261109_175249.txt |
| 2026-11-09 17:54 | 1461a | the 601 tail sweep reaches 0x1C: 0x12 answers ENOENT where the old shape gave EINVAL, 0x13/0x14/0x19 return 0 with no write, 0x16/0x17 are ENOSYS, 0x15/0x10/0x0F keep their codes, and 0x1C kills the process | 0x12 ENOENT, 0x13=0, 0x14=0, 0x15 EINVAL, 0x16/0x17 ENOSYS, 0x18 EPERM, 0x19=0, 0x1A EFAULT, 0x1C death | M | results/phase36_realargs/1461a_sys601_matrix_tail_20261109_175346.txt |
| 2026-11-09 17:55 | 1463a | mmap is refused with EINVAL by every device node except gc, dmem0, dmem1 and zero, so the readable device surface is exactly the three already mapped plus /dev/zero | hid/bt/camera/gic/dce EINVAL at 0/0x1000/0x10000; rng and ajm EACCES on open; usb EISDIR; dmem2 EACCES on mmap; gc/dmem0/dmem1/zero map | M | results/phase36_realargs/1463a_dev_mmap_census_20261109_175504.txt |
| 2026-11-09 17:55 | 1462a | - | - | ? | results/phase36_realargs/1462a_sys601_cmd12_name_20261109_175525.txt |
| 2026-11-09 17:56 | 1464a | sys 601 has no disclosure path: 0x00 writes only the dword 0x100 at +0, and 0x0D/0x13/0x14/0x19 write nothing into a 0x200-byte buffer in either the arg1 or the arg2 shape, in all cases with rv=0 | 1 non-zero dword total across 10 calls; buffer untouched for 8 of 10 | M | results/phase36_realargs/1464a_sys601_full_dump_20261109_175609.txt |
| 2026-11-09 17:59 | 1466a | - | - | ? | results/phase36_realargs/1466a_sys673_flavours_20261109_175939.txt |
| 2026-11-09 17:59 | 1466a | - | - | ? | results/phase36_realargs/1466a_sys673_flavours_20261109_175951.txt |
| 2026-11-09 18:00 | 1465a | 653 blockpool_open is reachable: flags 0x400000 returns handle 0x324, 0x500000 then returns EMFILE(24) so the quota is one pool per process, and 0/0x100000 return 22/23 while 0x1/0xFFFFFFFF return EINVAL; 654 blockpool_map still refuses every 64 KiB-aligned address because the target entry must already be backed by a type-11 vm_object | 653(0x400000)=804; 653(0x500000)=-1 EMFILE; 654 all -1 EINVAL | M | results/phase36_realargs/1465a_blockpool_open_flags_20261109_175825.txt |
| 2026-11-09 18:01 | 1467a | - | - | ? | results/phase36_realargs/1467a_blockpool_handle_532_20261109_180133.txt |
| 2026-11-09 18:03 | 1468a | - | - | ? | results/phase36_realargs/1468a_dual_map_wx_20261109_180314.txt |
| 2026-11-09 18:04 | 1468a | dual mapping does not bypass W^X: one shm object mapped three times at distinct VAs with prot 3, 5 and 7, the stub written through the prot-3 alias is present in the page, and a thr_create child fetched from the prot-5 alias faults with err 0x15 (P=1, I/D=1) at that exact address | RIP=0x3112A4000 err=0x150E faultaddr=0x3112A4000 marker unchanged | M | results/phase36_realargs/1468a_dual_map_wx_20261109_180339.txt |
| 2026-11-09 18:04 | 1469a | the entry-scoped munmap does not free pages another mapping still owns: two MAP_SHARED aliases of one shm object share pages, unmapping one page of the first alias removes all four of its pages, the second alias keeps every page and its content through a 64-mapping spray, and MAP_FIXED over the middle of a live mapping is refused with -1 leaving the mapping intact | aliases share pages YES; B unchanged 11223344; MAP_FIXED -1 | M | results/phase36_realargs/1469a_munmap_shared_pages_20261109_180445.txt |
| 2026-11-09 18:04 | 1469a | - | - | ? | results/phase36_realargs/1469a_munmap_shared_pages_20261109_180432.txt |
| 2026-11-09 18:06 | 277a | mmap2(725) with the 477-known-good shape kills the process before the first result prints, so 725 is either absent on 14.10 or a handler that faults; the probe ran without SIGSYS ignored so the two cases cannot be separated yet | capture stops at the [A] header; CONNECTION_REFUSED after | M | results/phase17_new_vectors/277a_mmap2_realargs_20261109_180550.txt |
| 2026-11-09 18:07 | 1470a | mmap2(725) is a nosys slot on 14.10: with SIGSYS ignored the 477-known-good shape returns -1 ENOSYS(78) where the identical 477 call returns a mapping, so the 277a kill was the signal, not a handler, and the tail reclassification holds for 725 | 725 -> -1 errno=78; 477 -> 0x310B4A000 | M | results/phase36_realargs/1470a_sys725_sigign_20261109_180703.txt |
| 2026-11-09 18:08 | 1467a | 532 does not resolve the blockpool handle: 653 returns handle 698 (0x2BA) and 532 cmds 0x18/0x19/0x1A answer 0x800D0204 for in[0]=0x2BA exactly as for junk 0x125/0xFFFFFFFF, 0x800D0203 for 0, so the blockpool object is not addressable through 532 | 653=698; 532 0x18 in[0]=0x2BA -> 0x800D0204, in[0]=0 -> 0x800D0203 | M | results/phase36_realargs/1467a_blockpool_handle_532_20261109_180711.txt |
| 2026-11-09 18:08 | 1471a | 671 modes 1 and 2 are the only accepted modes and each writes one dword then fails EFAULT (0x1800 and 0xA00), modes 3..0x40 all refuse, and 642 refuses every mode 0..0x40, so neither call exposes a page-table address or a record copy-out | mode 1 +00=00001800, mode 2 +00=00000A00, both rv=-1 EFAULT; 642 all -1 | M | results/phase36_realargs/1471a_stats_mode_sweep_20261109_180742.txt |
| 2026-11-09 18:10 | 1447a | AIO classes 1/2/3 all submit and behave identically, and a stale id one generation behind a live object is rejected with 0x80020003, so 14.10 uses an equality check rather than the 13.60 gen < counter inequality | class1 id=0x4205 class2 0x6205 class3 0x8205, all poll 3 / del 0; four rounds stale-662 -> 0x80020003 | M | results/phase36_realargs/1447a_aio_stale_id_alias_20261109_180913.txt |
| 2026-11-09 18:10 | 1472a | the AIO id generation is exactly three bits and wraps after eight poll/delete/submit cycles on one slot (id 0x212 reappears identically in cycle 9), so an id kept from eight cycles ago is indistinguishable from a live one; the probe's own stale-id test is confounded because the live id equals the cycle-1 id | gen 0..7 over cycles 1-8, cycle 9 id=0x00000212 again, slot 0x212 constant; [B] first_id == live_id | M | results/phase36_realargs/1472a_aio_gen_wrap_20261109_180953.txt |
| 2026-11-09 18:10 | 1464a | 601 commands 0x00/0x0D/0x13/0x14/0x19 write nothing beyond the single size dword that 0x00 puts in arg1, for both buffer shapes, so none of them copies a structure out and none carries a kernel pointer | 0x00 -> 1 dword (0x100); 0x0D/0x13/0x14/0x19 untouched in both shapes | M | results/phase36_realargs/1464a_sys601_full_dump_20261109_181019.txt |
| 2026-11-09 18:17 | 1475a | the /dev/dmem0 and /dev/gc pagers refuse every protection carrying PROT_EXEC (EACCES) where anonymous mmap accepts prot 5, so the device path cannot produce an executable page | prot 0/1/2/3 map at 0x310CFA000; prot 4/5/6/7 -> -1 EACCES(13); gc same; alive pid=518 | M | results/phase36_realargs/1475a_dev_pager_exec_20261109_181728.txt |
| 2026-11-09 18:18 | 1473a | EVFILT_AIO is a no-op filter on 14.10: EV_ADD succeeds and returns ready for any identifier including ones that never existed, and it keeps firing after the AIO request is deleted, so it holds no reference and cannot prolong a request's lifetime | ident 0x4205 registers and fires; after 664 poll + 662 delete (state 0) it fires again; control idents 0x0FFF and 0 fire too; 8/8 stale events | M | results/phase36_realargs/1473a_evfilt_aio_lifetime_20261109_181742.txt |
| 2026-11-09 18:20 | 1473b | EVFILT_AIO does not exist on 14.10 - the change-only kevent returns -1/EPERM, so 1473a's rv=1 readings were EV_ERROR echoes and its 'permanently ready filter' conclusion is withdrawn | change-only ident 0x8205 -> -1 errno=1 EPERM; the following receive-only kevent never returned (idle timeout), so the run ends at [1] | M | results/phase36_realargs/1473b_evfilt_aio_decoded_20261109_182033.txt |
| 2026-11-09 19:27 | 1478a | the dmem cdev pager refuses offset+length wrap and ftruncate on the cdev returns 0 without moving the aperture | dmem0/dmem1 near-2^64 offsets EACCES(13), gc EINVAL(22), both-huge EINVAL; ftruncate 0 for 0x1000/0x400000000/0x1000000000/0x10000000000 with the EACCES boundary fixed at 0x120000000 | M | results/phase36_realargs/1478a_dev_mmap_wrap_ftruncate_20261109_192453.txt |
| 2026-11-09 19:27 | 1479a | sys 548 is a batch VM call that executes for a game process: arg2=flag mask, arg3=0x20-byte entries, arg4=count, opcode at entry+0x1C, arg5=processed count, and op 2 with a zero entry succeeds | count=0 rv=0 processed=0; zero entry op=2 rv=0 processed=1; ops 0/1/3/4/5 EINVAL(22); flags 0x1/0x1000/0x20000000 EINVAL, 0x0/0x10000000 rv=0; arg1 ignored | M | results/phase36_realargs/1479a_sys548_batch_contract_20261109_192503.txt |
| 2026-11-09 19:27 | 1479b | 548 entry byte sweep: +0x00/+0x01 and +0x10/+0x11 are validated fields, +0x02..+0x0F and +0x12 are inert, and +0x13=0xFF kills the caller | op=2 rv=0 processed=1 for every byte +0x02..+0x12, EINVAL at +0x00/+0x01/+0x10/+0x11, process died at +0x13 | M | results/phase36_realargs/1479b_sys548_field_map_20261109_192622.txt |
| 2026-11-09 19:53 | 1479c | - | - | ? | results/phase36_realargs/1479c_sys548_protect_foreign_20261109_195337.txt |
| 2026-11-09 19:54 | 1479d | - | - | ? | results/phase36_realargs/1479d_sys548_map_unmap_20261109_195406.txt |
| 2026-11-09 19:56 | 1479e | - | - | ? | results/phase36_realargs/1479e_sys548_prot_matrix_20261109_195619.txt |
| 2026-11-09 19:57 | 1479e | sys 548 op 2 is a working protection change on a page the process owns: the entry needs 16 KiB alignment (0x3fff mask), not 4 KiB, and 547 confirms prot 3 -> 1 | len 0x4000 -> rv=0 processed=1 547 prot=1; len 0x1000/0x2000 -> EINVAL(22); all 60 op x prot combinations with len 0x1000 -> EINVAL | M | results/phase36_realargs/1479e_sys548_prot_matrix_20261109_195636.txt |
| 2026-11-09 20:04 | 1480a | sys 548 op 2 changes protections among 0-3 but refuses every value with bit 0x4 with EACCES(13): prot 1 and 3 round-trip on a page we own (547 confirms 3->1->3), prot 5 and prot 7 are refused on both an own page and on eboot text (0x69188000-0x6961C000, prot 5) | prot1 rv=0 547 prot=1; prot3 rv=0 547 prot=3; prot5 rv=-1 EACCES(13); prot7 rv=-1 EACCES(13); eboot prot7 rv=-1 EACCES(13). NOTE the probe's own 'at prot 5: W is NOT enforced' line is a false positive - that PROTECT had been refused, so the store ran on a prot-3 page | M | results/phase36_realargs/1480a_sys548_eboot_rwx_20261109_200355.txt |
| 2026-11-09 20:05 | 1480b | sys 548 ops 0/1/3/4 return 0 with processed=1 for a 16 KiB-aligned entry on a page we own but change nothing (547 identical, marker intact), and op 0 at a 16 KiB-aligned unmapped address answers EBUSY(16) rather than EINVAL | op0/1/3/4 rv=0 processed=1, 547 unchanged; op0 at 0x0/0x10000/0x40000/0x100000/0x310000000 -> EBUSY(16); 0x1000 (unaligned) -> EINVAL(22) | M | results/phase36_realargs/1480b_sys548_low_map_20261109_200449.txt |
| 2026-11-09 20:06 | 1480c | sys 548 op 2 moves the pre-existing device mappings from prot 0x33 to 3 and they then read: the GPU windows that always killed the process on read (SceGnmTrapCode/TrapData/AgcDdid/EopFifo/ShadowRegInfo/Cwsr/Misc/ACQRB, SceGnmDriver, SceGnmDingDong, the eboot.bin anon at 0xC80000000) are readable, while .sprx prot-4 text is refused with EACCES | 56 non-user mappings found; 19 moved to prot 3; reads 0xF00000000=BF800001, 0xFE0000000=C0012800, 0xFE0200000=FFFFFFFF, 0x211CE0000=AFAFAFAF; every prot-4 .sprx text refused EACCES(13); no crash, pid 87 before and after | M | results/phase36_realargs/1480c_sys548_device_prot_20261109_200528.txt |
| 2026-11-09 20:08 | 1331a | reboot after the hard power-off moved KASLR again: stub C0000000 alone, image contiguous from CC800000 (24 present samples, last D2400000) | 2525 present, image 0xFFFFFFFFCC800000-0xFFFFFFFFD2400000+0x400000, span 0x5C00000, slide 0xCC800000 | M | results/1331a_20261109_200838.txt |
| 2026-11-09 20:17 | 1481c | the GPU regions 548 makes readable are empty: 16 MiB Cwsr and 1.9 MiB ACQRB are all zero with no protect or read failures, so no kernel pointer and no driver data is exposed there | 0 image candidates, 0 other kernel-half values, 1 string (FOrbShdr in SceGnmTrapCode), 0 read fails, 0 protect fails, pid 87 | M | results/phase36_realargs/1481c_gpu_region_content_20261109_201653.txt |
| 2026-11-09 20:17 | 1481a | the 19 device windows 548 moved to prot 3 stay readable for the process and split in 674 at the new boundary; contents are zeros except TrapCode, TrapData and SceGnmDriver, which mirrors the dmem0 page-0 register block | 19 windows, 4 kernel-shaped qwords all register pairs, 0 writes attempted | M | results/phase36_realargs/1481a_gpu_windows_scan_20261109_200632.txt |
| 2026-11-09 20:17 | 1481b | - | - | ? | results/phase36_realargs/1481b_gpu_windows_write_20261109_201732.txt |
| 2026-11-09 20:20 | 1481g | - | - | ? | results/phase36_realargs/1481g_sys548_prot_full_matrix_20261109_202017.txt |
| 2026-11-09 20:21 | 1481f | 674 enumerates the complete 336-record map: 279 readable, module text prot 4, 11 prot-0 stack guards, a 4 GB prot-0x33 GPU pool, and every device window now at prot 3 | 336 records; 279 readable; SceKernelInternalMemory 16 MiB prot 3; SceGnmDumpArea 1 MiB zeros; eboot.bin windows 0xC80000000 prot 3 / 0xC80010000 prot 0x33 | M | results/phase36_realargs/1481f_full_map_dump_20261109_201845.txt |
| 2026-11-09 20:21 | 1481e | the 0xC8000C000 device window is not an alias of executable memory: 0 of 5 offsets agree, and the executable view compared against was ld-elf, not eboot | 0/5 offsets equal; [D] skipped because no offset read zero in both; device dwords all zero | M | results/phase36_realargs/1481e_device_alias_test_20261109_201808.txt |
| 2026-11-09 20:21 | 1481g | 548 op 2 accepts exactly the protections whose low nibble is 0,1,2 or 3 and refuses every value carrying bit 2 or bit 3, so the exec refusal is a filter and not max_prot; prot 0x10/0x20/0x33 are accepted on a device page but prot 0x10 kills the process on an anonymous page | device 0xF00004000: 0x0/0x1/0x3/0x10/0x20/0x33 taken, 0x4-0xF rv=-1; anon 0x31137C000: 0x0/0x1/0x3 taken, prot 0x2 silently becomes 3, 0x4 refused, prot 0x10 killed the process | M | results/phase36_realargs/1481g_sys548_prot_full_matrix_20261109_202102.txt |
| 2026-11-09 20:33 | 1482a | - | - | ? | results/phase36_realargs/1482a_jitshm_contract_20261109_203354.txt |
| 2026-11-09 20:38 | 1483a | SceGnmDriver and dmem0 page 0 hold the same GPU register-init table, not live MMIO; no kernel data in any device window | TrapCode 2442/4096 dwords shader, DumpArea 2 dwords, InternalMemory 0/256 | M | results/phase36_realargs/1483a_driver_window_content_20261109_203533.txt |
| 2026-11-09 20:38 | 1484a | blockpool_open creates no mapping, so no type-11 vm_object exists and 673/654 stay unreachable | 653 -> handle 771, 674 diff shows only 5 SceLibcHeap growth entries; 673 and 654 all EINVAL | M | results/phase36_realargs/1484a_blockpool_mapping_20261109_203703.txt |
| 2026-11-09 20:38 | 1485a | 548 cannot lower an execute-only entry: every prot-4 .sprx text and sigtramp_alias refuses prot 1/2/3 with EACCES, so module text stays unreadable | 8 entries tried plus sigtramp prot 2 and 1, all -1 errno 13 | M | results/phase36_realargs/1485a_protect_exec_only_entry_20261109_203825.txt |
| 2026-11-09 20:39 | 1486a | 548 protects a whole 4 GB pool entry in one call; the complete pre-existing GPU pool is now readable and is empty except three allocation headers | 8 of 8 whole-entry protects rv=0 (largest 0xFE190000); 3 of 4372 sampled MiB rungs non-zero | M | results/phase36_realargs/1486a_gpu_pool_scan_20261109_203940.txt |
| 2026-11-09 20:42 | 1487a | void: the probe's own sign handler dropped the high dword and mapped 0x310B40000 became 0x10B40000, so the read hit an unrelated address | va printed 0x10B40000, 547 -1, read at the truncated address killed the loader | V | results/phase36_realargs/1487a_physhm_548_20261109_204209.txt |
| 2026-11-09 21:47 | 1487a | physhm installs no vm_map entry: 547 reports no mapping at the address 477 returned, the read faults with SIGSEGV, and 548 returns rv=0 processed=1 on the nonexistent entry so its return proves nothing | fd 22, va 0x310E1C000, 547 -1 at va, 548 prot 0 and prot 3 both rv=0 processed=1, read -> fault dump magic 0x13371337 signo 0x0B | M | results/phase36_realargs/1487a_physhm_548_20261109_214646.txt |
| 2026-11-09 21:53 | 1488b | 548's op map is resolved: op 0 is the only op that takes a descriptor (entry+0x08) and it answers EINVAL for every fd including /dev/dmem0 and /dev/gc; op 3 maps anonymous memory at the requested 16 KiB slot and returns the address in rax with the fd field ignored | op0 -1 EINVAL(22), op1 rv=0 no-op, op2 protect, op3 rv=0x311220000 processed=1 creating start=0x311220000 end=0x311224000 prot=3, op4 -1 EOPNOTSUPP(45); same for fd 22/23/24/25 and -1 | M | results/phase36_realargs/1488b_sys548_map_desc_20261109_215258.txt |
| 2026-11-09 21:55 | 1489a | 548 op 2 raises ./AOSharedState from prot 1 to prot 3 and restores it, so the only shared-flag entry in the map is read-only by policy and not by max_prot | 674: ./AOSharedState 0x310D80000 len 0x8000 prot=1 flags=0xC; op2(3) rv=0 processed=1 prot 1->3, op2(1) rv=0 prot 3->1 | M | results/phase36_realargs/1489a_ao_shared_prot_20261109_215505.txt |
| 2026-11-09 21:55 | 1489b | a store into ./AOSharedState written while 548 has it at prot 3 is still there after the protection is restored to 1, so 548 turns the read-only shared region into ordinary writable memory | baseline at prot 1 +0x100 = 08000000 08000000; after op2(3), store DEAD1234/CAFEBABE/55667788/99AABBCC reads back; after op2(1) +0x100 still DEAD1234 and +0x108 still 55667788; an earlier run read back the original pattern so the pager re-fetch is not deterministic | M | results/phase36_realargs/1489b_ao_shared_write_20261109_215541.txt |
| 2026-11-09 21:55 | 1489b | - | - | ? | results/phase36_realargs/1489b_ao_shared_write_20261109_215530.txt |
| 2026-11-09 21:57 | 1489c | ./AOSharedState is regenerated per process: the marker written at +0x100 by 1489b is gone after the relaunch and the header is byte-identical, so the region gives no cross-process channel | pid 111 (was 106), ./AOSharedState moved 0x310D80000 -> 0x310534000, +0x100 = 08000000, header 00000000 C28C0000 0000003B 00000000 | M | results/phase36_realargs/1489c_ao_state_persist_20261109_215707.txt |
| 2026-11-09 21:58 | 1490a | 548 cannot lower any executable entry to RW: all 41 prot-4 and prot-5 mappings answer EACCES(13) with the protection unchanged, so max_prot is exec-only for every module text and the W^X bypass is closed on this path too | 41 executable entries, 0 lowered; .executable/.libSceFios2.prx/.libc.prx at prot 5 and 37 .sprx texts at prot 4 all rv=-1 EACCES(13) processed=0; control op2 on an anon page rv=0 prot 3->1 | M | results/phase36_realargs/1490a_rx_to_rw_20261109_215813.txt |
| 2026-11-09 22:00 | 1491a | the dmem read-only window above the 4 GiB ACL is read-only by max_prot, not by policy: it maps only prot 1 and 548 op 2 answers EACCES(13) for prot 3, so the ACL boundary cannot be lifted | off 0x120000000 and 0x140000000 EACCES for prot 1 and 3; off 0x1000000000 prot 1 maps at 0x3106DC000 and prot 3 EACCES; op2(3) rv=-1 EACCES processed=0, 547 stays 1 | M | results/phase36_realargs/1491a_dmem_ro_window_prot_20261109_215915.txt |
| 2026-11-09 22:02 | 1494a | 560 debug_init does not install the mdbg context: 601 attach answers EINVAL/EFAULT exactly as before it, and commands 0x02/0x05/0x06 stay ENOSYS, so the 601 bitfield-setter family stays unreachable | 601(0x01) opt1 EFAULT opt2 EINVAL opt3 EFAULT opt4 EINVAL before AND after 560(1) rv=0 and after 643(0) rv=0; 0x02/0x05/0x06 ENOSYS(78); 0x00 control rv=0 writing 00000100 | M | results/phase36_realargs/1494a_debuginit_attach_20261109_220219.txt |
| 2026-11-09 22:02 | 1493a | 548 op 3 ignores the entry+0x08 flags field: a proposed MAP_FIXED at the middle of a 64 MiB entry allocated a fresh address instead, so the flags-to-map-flags reading is wrong or 0x10 is not MAP_FIXED here | op3 at MID 0x3129C8000 returned 0x3149C8000; 547 at A/MID/END all 3; markers 1111AAAA/2222BBBB/3333CCCC intact; flags=0 at an occupied address returned -1 | M | results/phase36_realargs/1493a_mapfixed_scope_20261109_220131.txt |
| 2026-11-09 22:02 | 1492a | 548 op 3 respects the same address ceiling mmap has, and without MAP_FIXED the start field is only a hint that is abandoned when the address is occupied | op3 refused all five high addresses (ENOMEM 12 at four, EINVAL 22 at 0x7FFFFFFFFFF000); op3 at an occupied anon page 0x3106E8000 returned 0x3106F0000 leaving the marker AABBCCDD intact | M | results/phase36_realargs/1492a_sys548_map_ceiling_20261109_220048.txt |
| 2026-11-09 22:05 | 1495a | - | - | ? | results/phase36_realargs/1495a_named_shared_persist_20261109_220500.txt |
| 2026-11-09 22:07 | 1496a | the 548 op-2 protection transform ((p>>1)&0xffffffc1)\|p turns a request for prot 6 into 7, but it cannot grant execution because mmap clamps max_prot: mmap(prot 7) comes back as prot 3 | mmap(prot 7) -> 0x310C04000, 547 prot 3; 548 op2 1 -> rv=0 547=1, 3 -> rv=0 547=3, 6 -> rv=-1 EACCES(13) processed=0, 547 stays 3 | M | results/phase36_realargs/1496a_sys548_prot6_exec_20261109_220652.txt |
| 2026-11-09 22:08 | 1497a | 601 cmd 0x11 is not a caller-pointer primitive: a page filled with a valid mapped user address kills exactly like a zero fill and a kernel fill, so the body dereferences the absent mdbg context ([proc+0x568] is NULL) rather than anything we supplied | page filled with 0x310C08000 qwords, marker sentinelled A5A5A5A5; 601(0x00) control rv=0 writing 00000100; 601(0x11,0,page) ended the capture with no return line | M | results/phase36_realargs/1497a_sys601_cmd11_userptr_20261109_220733.txt |
| 2026-11-09 22:08 | 1498a | - | - | ? | results/phase36_realargs/1498a_dev_entry_munmap_20261109_220807.txt |
| 2026-11-09 22:13 | 1500a | 657 does not take a struct thread pointer from userland: the [rdi+8] dereference uses the original td because arg2 is never reloaded, and the only use of arg2 is a suword32 zero-dword write in the arg3!=0 path | 657(E,1,fake_thread,0) -> rv=-1 EINVAL(22) with every fake-page canary untouched, including M[+0x1c4]=0; control 657(E,0,...) -> 0 | M | results/phase36_realargs/1500a_sys657_thread_ptr_20261109_221321.txt |
| 2026-11-09 22:15 | 1501a | the object table's generation counter is per slot and shared across families (namedobj 0x4205 slot 0x205 gen 2 freed, then the AIO request took slot 0x205 gen 3 as id 0x6205), but every family's delete and poll rejects a handle minted by another family, so the wrong-type free is closed | 557 -> 0x4205 slot 0x205 gen2; 669 -> 0x6205 slot 0x205 gen3 (SHARED); 558(0x6205) -> -1; 664 -> rv=0 state=0x2 still healthy; mirror 662 -> 0x80020010, 557 -> 0x206, 664(0x206) -> 0x80020003 | M | results/phase36_realargs/1501a_cross_family_handle_20261109_221511.txt |
| 2026-11-09 22:15 | 1501a | - | - | ? | results/phase36_realargs/1501a_cross_family_handle_20261109_221501.txt |
| 2026-11-09 22:17 | 1502a | - | - | ? | results/phase36_realargs/1502a_dmem_aperture_edge_20261109_221724.txt |
| 2026-11-09 22:18 | 1502a | the dmem aperture tops out at 0x11FFF0000 (0x11FFC000 maps at prot 1, 0x11FFF0000 and everything above answers EACCES) and the lone 0x1000000000 rung maps at prot 1 but reads all zeros, so the aperture exposes no kernel data | off 0 reads C0012800 80000000 (register table); off 0x11FFC000 maps prot 1; off 0x11FFF0000/0x120000000/0x140000000/0x200000000/0x800000000 all EACCES(13); rung 0x1000000000 maps 547=0 prot=1 reads 16 zero dwords; +0x1000..+0x7000 also map and read zero | M | results/phase36_realargs/1502a_dmem_aperture_edge_20261109_221730.txt |
| 2026-11-09 22:19 | 1503a | mincore(78) is a non-faulting residency oracle over the dmem pager: it reports 16 of 64 pages resident at phys 0 (0x0B for pages 00-0F, 0x00 for 10-3F) while an 8 MiB window at the pool base 0x100000000 is fully resident, so the 512 MiB of direct-memory pool inside the aperture can be scanned without risking a hole fault | mincore over phys 0 len 0x40000 rv=0 vec=0B x16 then 00 x48 -> 16/64 resident; over phys 0x100000000 len 0x800000 rv=0 -> 512/512 resident; phys 0 read back C0012800 80000000 80000000 C0001200 | M | results/phase36_realargs/1503a_mincore_aperture_20261109_221835.txt |
| 2026-11-09 22:19 | 1504a | the direct-memory pool is almost entirely outside the aperture: 16 MiB from 0x100000000 maps but every offset from 0x110000000 up answers EACCES, and the 1024 resident pages of that 16 MiB are all zeros with no PTE-shaped qwords, so the GPU page tables are not reachable from userland and the GPU branch needs the command processor | map 0x100000000 len 0x1000000 prot 1 -> va ok, mincore 1024/4096 resident, dense pages 0, qwords with bits32-63==1 0; 0x110000000/0x118000000/0x11F000000 -> EACCES(13) | M | results/phase36_realargs/1504a_pool_content_20261109_221927.txt |
| 2026-11-09 22:21 | 1505a | - | - | ? | results/phase36_realargs/1505a_clip_object_window_20261109_222116.txt |
| 2026-11-09 22:26 | 1506a | profil(44) is armable and returns 0, but the first readout was stale: the zeroing loop stepped 0x1000 and wrote 2 bytes, so the two non-zero bytes survived a re-zero and appeared in the scale-0 control | 2 non-zero bytes at idx 0x4D9 in every arm incl. the control; not a measurement | V | results/phase36_realargs/1506a_profil_consumer_live_20261109_222347.txt |
| 2026-11-09 22:26 | 1506b | profil(44) is LIVE on 14.10: with a clean baseline an arm at scale 1 / pr_off 0 collects 0x06A4 ticks on exactly ONE index (0x4D9), a re-zero returns 0, and pr_off 0x10000000 collects nothing, so the tick write is a fixed offset pr_base+0x9B2 | baseline 0, armed 1700 ticks at idx 0x4D9, re-zero 0, shifted-offset 0 | M | results/phase36_realargs/1506b_profil_clean_20261109_222420.txt |
| 2026-11-09 22:26 | 1507a | the profil tick store is validated or masked, not a raw kernel store: arming pr_base=0x1000 (unmapped) returned rv=0 and the process survived, as did the kernel image base and kernel data arms | rv=0 on all three arms, pid 125 alive before and after, no panic | M | results/phase36_realargs/1507a_profil_kernel_write_20261109_222649.txt |
| 2026-11-09 22:49 | 1508a | 548 op 3 DOES honour MAP_FIXED (flags bit 0x10, which has no bit in the 0xe0bffb6f batch mask): it deletes the vm_map entry covering the range and installs a fresh anonymous one, with no ownership or overlap check, including over a device window | flags 0x0 over a live entry: rv=0x31106C000 marker 11223344 intact; flags 0x10: rv=0x311065000 marker 00000000 (REPLACED); hole: mapped exactly at 0x311074000 writable; SceGnmTrapCode 0xF00000000 replaced, read 00000000 where it was 01008 0BF, no panic, pid 80 alive | M | results/phase36_realargs/1508a_sys548_map_fixed_20261109_224934.txt |
| 2026-11-09 22:50 | 1505a | a 548 op2 sub-range protect over a double-mapped POSIX shm object, and over a /dev/dmem0 mapping, returns rv=0 processed=1 and leaves every marker intact in both aliases, so a forced clip does not visibly rewrite the shared object's window (547 reports the head entry only, so the split itself is unconfirmed) | A/B markers 11110000/22220001/33330002/44440003 all intact after the clip; dmem markers B2B20001/C3C30002/D4D40003 intact; 547 returns prot 3 at both aliases before and after | M | results/phase36_realargs/1505a_clip_object_window_20261109_225006.txt |
| 2026-11-09 22:53 | 1509b | 548 op 3 does not refuse PROT_EXEC the way op 2 does, it silently STRIPS bit 0x4 and then applies write-implies-read, so an anonymous page can never be executable through this path either | op3 MAP_FIXED prot 0->547 0; 1->1 (store faults, not writable); 2->3; 3->3; 4->0; 5->1; 6->3; 7->3; every call rv=the requested address with processed=1; canary pid 80 alive | M | results/phase36_realargs/1509b_sys548_op3_exec_20261109_225307.txt |
| 2026-11-09 22:54 | 1510a | 548 op 3 MAP_FIXED maps below the mmap floor: a writable 16 KiB page lands at 0x4000, while page 0 itself is refused, so op 3 bypasses mmap's floor and overlap checks and enforces only the ceiling plus the exec strip | 0x4000/0x10000/0x100000/0x1000000 all rv=the requested address, processed=1, 547 prot=3, store/read OK; 0x0 rv=-1 processed=0; plain mmap(0x0,...,MAP_ANON\|MAP_FIXED) rv=-1; mmap(NULL) -> 0x311088000 | M | results/phase36_realargs/1510a_low_address_ladder_20261109_225354.txt |
| 2026-11-09 22:54 | 1509a | - | - | ? | results/phase36_realargs/1509a_graft_kernel_pages_20261109_225429.txt |
| 2026-11-09 22:55 | 1509a | void: the 674 record qwords were read as single dwords, so every graft target was a 32-bit-truncated address; the third run grafted at those wrong addresses (e.g. SceGnmTrapData 'at 0x4000', /AOSharedState 'at 0x10CF0000') and killed the loader | runs 1 and 2 printed 'nothing grafted -- VERDICT VOID' because name_at read dwords where it needed bytes; run 3 (unsaved) grafted at truncated addresses and the next connection was CONNECTION_REFUSED | V | results/phase36_realargs/1509a_graft_kernel_pages_20261109_225436.txt |
| 2026-11-09 22:58 | 1509a | grafting our own anonymous page over a live kernel-authored region is survivable at every target (SceGnmTrapData, /AOSharedState, the GPU pool, SceNpGlobalHeap, SceKernelInternalMemory) and nothing kernel-side writes into the replacement: 0 of 5 pages changed across three rounds of syscall driving | 5/5 grafts landed at the exact addresses (0xF00004000, 0x310920000, 0x211220000, 0x881F50000, 0x88170C000), sentinel 0xCCCCCCCC held, TOTAL changed dwords 0, canary pid 92 alive | M | results/phase36_realargs/1509a_graft_kernel_pages_20261109_225814.txt |
| 2026-11-09 22:59 | 1511a | destroying device vm_map entries does not attack object lifetime: 200 rounds of mmap(/dev/dmem0) followed by a 548 op3 MAP_FIXED replacement over the returned address all succeeded, and the descriptor still maps, reads the register table and round-trips data afterwards | 200/200 rounds rv=the requested address processed=1 bad=0; after the loop mmap -> 0x3110A0000 reads AABBCCDD, offset 0 reads C0012800, second descriptor fd23 maps and round-trips 13572468; pid 92 alive | M | results/phase36_realargs/1511a_device_entry_churn_20261109_225908.txt |
| 2026-11-09 23:03 | 1512a | 548 op 3 with MAP_FIXED SPLITS a larger vm_map entry instead of replacing it whole: a 16 MiB entry became 0x4000 head + 0x4000 carve + 0xFF8000 tail, twice, and every marker outside the carved page survived | rv=0x3110B0000 processed=1; entries after: [0x3110AC000,0x3110B0000) [0x3110B0000,0x3110B4000) [0x3110B4000,0x3120AC000); second carve at +0x800000 split again; alive pid=92 | M | results/phase36_realargs/1512a_sys548_op3_split_20261109_230244.txt |
| 2026-11-09 23:05 | 1513a | 548 op 3 clips a MAP_SHARED vnode entry cleanly: the carve page becomes anonymous, the head and tail keep prot 1, and a second mapping of the same file is completely unaffected | rv=0x3110BC000 processed=1; segments 0x10000/0x4000/0x2C000; B (second mapping, len 0x40000 prot 1) byte-identical before and after; file unmodified after munmap | M | results/phase36_realargs/1513a_sys548_op3_vnode_clip_20261109_230353.txt |
| 2026-11-09 23:05 | 1514a | 548 op 3 clip does NOT corrupt a vm_object shared by two entries: both mappings of one shm object keep propagating writes in both directions after the carve, with zero unreadable dwords | carve rv=0x3110BC000 processed=1; A->B and B->A propagation work after the carve; B sweep 0 odd dwords of 0x40000; second carve on B also clean; alive pid=92 | M | results/phase36_realargs/1514a_sys548_op3_shm_clip_20261109_230444.txt |
| 2026-11-09 23:16 | 1515a | 548 op 3 raced against a user-thread read page disappeared from the map; the death was read as unresolved, but 1517a later showed a spawned Lua thread dies on its own without any op 3 call, so this capture never tested the race | 1515a: 200-round serial control clean (0 bad reads), racing phase spawned then the connection ended at 495 bytes | V | results/phase36_realargs/1515a_sys548_op3_fault_race_20261109_230554.txt |
| 2026-11-09 23:16 | 1516a | 548 op 3 raced against a fault taken inside copyin (unmapped source returns EFAULT, so no signal is possible) still ended the process; 1517a's [C] control then showed a child-thread write loop dies with no op 3 at all, so the kernel race is untested | 1516a: control 200 rounds 0 failures; racing phase spawn=OK then the connection ended at 526 bytes; EFAULT self-validation passed | V | results/phase36_realargs/1516a_sys548_op3_kernel_fault_race_20261109_231009.txt |
| 2026-11-09 23:16 | 1517a | a spawned Lua thread making repeated write() calls takes the whole process down by itself -- [C] ran 200000 child writes with NO 548 op 3 call and the loader died at spawn+7 s -- so every Lua-thread race probe in this tree has an invalid instrument | 1517a: [A] EFAULT from an unmapped source confirmed, [B] 300 serial op3 rounds replacement_failures=0, [C] spawn=OK then connection ended at 455 bytes, pid 106 | M | results/phase36_realargs/1517a_sys548_op3_race_bisect_20261109_231611.txt |
| 2026-11-09 23:20 | 1518a | a spawned Lua thread running a syscall loop takes the whole process down even with no socket to fill and exactly one closure -- so every Lua-thread race probe in this tree is an invalid instrument; separately, write() to /dev/zero ignores its source pointer entirely, returning 4 for an unmapped buffer instead of EFAULT | 1518a: 200000 serial main-side writes OK (sum=800000); child with /dev/zero destination, one closure, spawn=OK then connection ended at 528 bytes, pid 113 | M | results/phase36_realargs/1518a_child_thread_stability_20261109_232028.txt |
| 2026-11-09 23:39 | 1522a | - | - | ? | results/phase36_realargs/1522a_mapdm_fcall_sixarg_20261109_233917.txt |
| 2026-11-09 23:39 | 1522a | - | - | ? | results/phase36_realargs/1522a_mapdm_fcall_sixarg_20261109_233942.txt |
| 2026-11-09 23:45 | 1522b | the loader exposes native.fcall/fcall_with_rax (6 register args from the main thread); libkernel+0x15020 is sceKernelMapDirectMemory by behaviour (returns Sony status 0x80020016 for a zero-length request) and +0x17EF0 AllocateDirectMemory returns rv=0 phys=0x110010000, but the first real map (len 0x4000, prot 3, flags 0) still takes SIGSEGV 0x0b | identity call rv=0x80020016; alloc rv=0 phys=0x110010000; map -> SIGSEGV rip=0x7286e4c0 err=0x4 fault=0x310b847c7 | M | results/phase36_realargs/1522b_mapdm_fcall_offsets_20261109_234027.txt |
| 2026-11-09 23:50 | 1523a | MapDirectMemory crashes with the payload's own prot/flags pair exactly as with prot 3/flags 0, so neither prot nor flags triggers it; the decoded fault RIP is eboot.bin+0x1BA4C0, inside the loader's own fcall ROP chain (near luaL_checklstring 0x1BA970 and luaL_optinteger 0x1BAD80), not in libkernel | identity rv=0x80020016; alloc rv=0 phys=0x110010000; first real map -> SIGSEGV rip=eboot+0x1BA4C0 err=0x4 fault=rsi+7 | M | results/phase36_realargs/1523a_mapdm_prot_matrix_20261109_234855.txt |
| 2026-11-09 23:50 | 1523b | - | - | ? | results/phase36_realargs/1523b_mapdm_fault_attribution_20261109_235029.txt |
| 2026-11-09 23:51 | 1523b | a real length alone breaks the MapDirectMemory call through native.fcall: map_fn(out, 0x4000, prot 0, flags 0, phys 0, align 0x4000) crashes exactly like the owned-phys shape, so the physical address is not the trigger and the fcall route to MapDirectMemory is unusable | identity len=0 -> 0x80020016; real len -> SIGSEGV, 2nd run rip=eboot+0x1AE841 err=0x4 fault=rsi+0x10 on the main stack | M | results/phase36_realargs/1523b_mapdm_fault_attribution_20261109_235053.txt |
| 2026-11-10 10:18 | 1523c | pre-filling *out with a page we already own does not save the MapDirectMemory call: a real length still faults inside the loader's fcall chain at the same Lua-string-hash instruction (fault = r15+7, rdx=8), so the destination hint is not honoured and the fcall route to MapDirectMemory is unusable | identity 0x80020016; B2 (dest hint 0x310A18000, phys 0x110010000) -> SIGSEGV in the chain, fault=0x310876B67 | M | results/phase36_realargs/1523c_mapdm_fixed_addr_20261109_235204.txt |
| 2026-11-10 10:18 | 1331a | kernel image base after the 2026-11-10 console reboot: image at 0xFFFFFFFFDDC00000-0xFFFFFFFFE3800000 (24 4MB samples, span 0x5C00000), stub alone at 0xFFFFFFFFC0000000 | 25/512 present; slide moved from 0xFFFFFFFFCC800000 | M | results/1331a_20261110_101848.txt |
| 2026-11-10 10:19 | 1524a | - | - | ? | results/phase36_realargs/1524a_sys570_budget_get_20261110_101944.txt |
| 2026-11-10 10:23 | 1525a | the MapDirectMemory SIGSEGVs are not caused by the length: with every other argument real and len=0 the call returns 0x80020016, a huge refused length returns 0, and len=0x4000/align=0x4000 returns rv=0 with the process alive -- the same shape that crashed 1523b | B len=0 prot 0x33 flags 0x400000 phys 0x110010000 -> 0x80020016; C len=0xFFFFFFFFFFFFF000 -> 0; D len=0x4000 -> 0, survived, COMPLETE | M | results/phase36_realargs/1525a_mapdm_length_discriminator_20261110_102146.txt |
| 2026-11-10 10:23 | 1526a | a MapDirectMemory call that returns rv=0 leaves the loader's Lua state corrupted -- the very next connection's script died before printing its banner, inside the same eboot Lua string-hash code as the 1523a crash, so the fcall route to MapDirectMemory is unusable and the earlier SIGSEGVs are the same corruption reached sooner | 1525a completed but the following run's 280-byte capture is only the fault record: RIP 0x1AA7DE74F, err=0x04 user-read-not-present, fault=RSI+8=0x310F02338 on the heap (RSP 0x310F14580), zero script output | M | results/phase36_realargs/1526a_mapdm_round_trip_20261110_102226.txt |
| 2026-11-10 10:26 | 1526a | - | - | ? | results/phase36_realargs/1526a_mapdm_round_trip_20261110_102643.txt |
| 2026-11-10 10:27 | 1527a | - | - | ? | results/phase36_realargs/1527a_ao_regions_dump_20261110_102757.txt |
| 2026-11-10 10:27 | t | - | - | ? | results/t_flush_20261110_102740.txt |
| 2026-11-10 10:28 | 1527a | the /AO* family is 15 entries: one AOSharedState (0x8000, prot 1, 70 non-zero dwords of colour/format tables) and 14 /AOCtx_* or /AOP_* shared buffers that are already prot 3 and entirely zero, with zero kernel-shaped qwords anywhere in the 0x180 dwords sampled from each | 15/313 records match /AO; 674 rv=0; all unlocks rv=0 processed=1; only 0x200698000 holds data; 0 kernel-shaped qwords in all 15 | M | results/phase36_realargs/1527a_ao_regions_dump_20261110_102811.txt |
| 2026-11-10 10:39 | 1528a | the native thr_new child-ROP chain works (catalog gadgets verify exactly: pop_rax 0x992, pop_rdi 0xC9DFE, pop_rsi 0xD77D, bare 0x42) and racing munmap(V,0x1000) from the child against 548 op-3 MAP_FIXED over the same address for 400 rounds produced zero placement failures, zero protection failures, zero non-zero reads before write, and no process death -- but only ONE collision landed because the child finished its 8000 munmaps inside the first few rounds, so the negative is thin | bad_place=0 bad_prot=0 nz=0/39 racy_unmapped=1 over 400 rounds; rv=V=0x3114E4000 every round; final 547 prot=3, mark round-trips, pid 108 alive | M | results/phase36_realargs/1528a_native_race_op3_munmap_20261110_103848.txt |
| 2026-11-10 10:39 | 1528b | a sustained native child-ROP munmap loop racing 548 op-3 MAP_FIXED on the same 16 KiB address for 800 rounds produced 56 observed collisions (547 reports the entry already gone) and ZERO corruption: op 3 returned the requested address on all 800 rounds, every gated read-before-write returned zeros (24/24), no non-zero page residue, process alive -- the vm_map locking serialises entry delete/insert on this path and the op-3 UAF hypothesis is closed | spawned=101 spawn_fail=0 collisions=56 bad_place=0 nz=0/24 final 547=-1 (child won the last round) pid 108 alive | M | results/phase36_realargs/1528b_native_race_waves_20261110_103928.txt |
| 2026-11-10 10:42 | 1529a | - | - | ? | results/phase36_realargs/1529a_copyin_race_op3_20261110_104244.txt |
| 2026-11-10 10:45 | 1529a | the copyin race instrument is built and its oracle is validated (3328 bytes drained from the child's write(fd,V,0x100) were all zero, so any non-zero byte would be a stale page), and the fake-TCB preamble from 384b is REQUIRED for a child whose syscall fails (without it the stub faults at %fs:0 -> FAULT=0x10); the racing phase has not produced a measurement yet because two children shared one ROP stack and ran off its end into RIP=0, which killed the game | baseline naive: child SIGSEGV RIP in libkernel FAULT=0x10 (no TLS); with sysarch(165,&tcb) baseline clean bytes=3328 nonzero=0; race run died at RIP=0 after a successful write (RAX=0x100) from stack overlap | V | results/phase36_realargs/1529a_copyin_race_op3_20261110_104407.txt |
| 2026-11-10 10:46 | 1529a | - | - | ? | results/phase36_realargs/1529a_copyin_race_op3_20261110_104611.txt |
| 2026-11-10 10:48 | 1529b | - | - | ? | results/phase36_realargs/1529b_copyin_race_shm_20261110_104839.txt |
| 2026-11-10 10:49 | 1529b | racing 100000 kernel copyin calls from V against 20000 sequential 548 op-3 MAP_FIXED replacements of V produced 25608192 bytes of copied data, all zero, with 0 placement failures and 0 rounds where V held a non-zero word -- the vm_map delete/insert is serialised against the page fault that the copyin needs, so no stale-page read is reachable | scanned=25608192 chunks_with_data=0 bad_place=0/20000 bad_prot=0/20000 pid 129 alive | M | results/phase36_realargs/1529b_copyin_race_shm_20261110_104907.txt |
| 2026-11-10 10:51 | 1530a | - | - | ? | results/phase36_realargs/1530a_shm_truncate_race_20261110_105119.txt |
| 2026-11-10 10:52 | 1530a | - | - | ? | results/phase36_realargs/1530a_shm_truncate_race_20261110_105204.txt |
| 2026-11-10 10:52 | 1530a | - | - | ? | results/phase36_realargs/1530a_shm_truncate_race_20261110_105250.txt |
| 2026-11-10 10:53 | 1530a | racing 12000 lseek+read(shmfd,V,0x1000) pairs against 3000 ftruncate-to-zero-and-regrow cycles returned 3000 samples of 0x1000 bytes with zero bytes outside {0x41,0x00}, and the positive control proved the child was really copying shm pages out -- the posixshm read path does not hand back pages the object has released | positive control true; samples=3000 foreign_bytes=0; child_tid=101357; pid 143 alive | M | results/phase36_realargs/1530a_shm_truncate_race_20261110_105303.txt |
| 2026-11-10 10:55 | 1529b | rerun with a liveness counter: the child completed all 100000 writes (shared offset exactly 25600000), so the earlier clean scan covered the whole race window rather than a dead child, and 25608192 scanned bytes still held zero non-zero bytes | shared offset 25600000 = ITERS*CHUNK exactly; scanned=25608192 chunks_with_data=0; bad_place=0/20000; pid 143 alive | M | results/phase36_realargs/1529b_copyin_race_shm_20261110_105548.txt |
| 2026-11-10 10:56 | 1530a | - | - | ? | results/phase36_realargs/1530a_shm_truncate_race_20261110_105601.txt |
| 2026-11-10 10:56 | 1530a | - | - | ? | results/phase36_realargs/1530a_shm_truncate_race_20261110_105617.txt |
| 2026-11-10 10:56 | 1530a | - | - | ? | results/phase36_realargs/1530a_shm_truncate_race_20261110_105630.txt |
| 2026-11-10 10:56 | 1530a | - | - | ? | results/phase36_realargs/1530a_shm_truncate_race_20261110_105644.txt |
| 2026-11-10 10:56 | 1530a | - | - | ? | results/phase36_realargs/1530a_shm_truncate_race_20261110_105658.txt |
| 2026-11-10 10:58 | 1530a | the 0x42 dead-child stamp invalidated the earlier clean result: with a finite chain, 2815 of 3000 samples still held our own stamp, so the child had finished by round 185 and 94 percent of the run raced nothing | stale=2815/3000, foreign_bytes=182975 all our own 0x42, first foreign at round 186 | M | results/phase36_realargs/1530a_shm_truncate_race_20261110_105801.txt |
| 2026-11-10 11:00 | 1530a | - | - | ? | results/phase36_realargs/1530a_shm_truncate_race_20261110_110027.txt |
| 2026-11-10 11:06 | 1529b | - | - | ? | results/phase36_realargs/1529b_copyin_race_shm_20261110_110611.txt |
| 2026-11-10 11:06 | 1530a | - | - | ? | results/phase36_realargs/1530a_shm_truncate_race_20261110_110657.txt |
| 2026-11-10 11:08 | 1529b | with a discriminating oracle (V filled 0x41 before its page was replaced, scan restricted to log bytes after that replacement, child completed all 100000 writes) the copyin-vs-548-op3 race produced zero 0x41 across 25608192 scanned bytes | 0x41 count 0 of 25608192; shared offset 25600000 = ITERS*CHUNK; bad_place 0/20000; processed==1 every round | M | results/phase36_realargs/1529b_copyin_race_shm_20261110_110638.txt |
| 2026-11-10 11:08 | 1530a | shm read vs ftruncate over 3000 cycles with a per-round fill byte and a dead-child stamp: 3 of 3000 samples were stale and none of the 2997 live samples carried a foreign byte | stale=3/3000, foreign_bytes=0, positive control exact on 0x1000 bytes | M | results/phase36_realargs/1530a_shm_truncate_race_20261110_110751.txt |
| 2026-11-10 11:09 | 1530a | repeat run with the chain integrity check moved after the write (first and tail qwords both verified against the expected gadgets): same result, 2 of 3000 samples stale and zero foreign bytes | chain check first/tail match; stale=2/3000; foreign_bytes=0 | M | results/phase36_realargs/1530a_shm_truncate_race_20261110_110919.txt |
| 2026-11-10 11:19 | 1529b | - | - | ? | results/phase36_realargs/1529b_copyin_race_shm_20261110_111941.txt |
| 2026-11-10 11:20 | 1529b | - | - | ? | results/phase36_realargs/1529b_copyin_race_shm_20261110_112019.txt |
| 2026-11-10 11:20 | 1529b | - | - | ? | results/phase36_realargs/1529b_copyin_race_shm_20261110_112043.txt |
| 2026-11-10 11:41 | 1529b | - | - | ? | results/phase36_realargs/1529b_copyin_race_shm_20261110_114104.txt |
| 2026-11-10 11:43 | 1529b | - | - | ? | results/phase36_realargs/1529b_copyin_race_shm_20261110_114338.txt |
| 2026-11-10 11:44 | 1530a | - | - | ? | results/phase36_realargs/1530a_shm_truncate_race_20261110_114404.txt |
| 2026-11-10 11:44 | 1530a | - | - | ? | results/phase36_realargs/1530a_shm_truncate_race_20261110_114424.txt |
| 2026-11-10 11:44 | 1530a | - | - | ? | results/phase36_realargs/1530a_shm_truncate_race_20261110_114445.txt |
| 2026-11-10 11:45 | 1529b | with the child lap-bounded and proven live by the shared offset taking 5 distinct values across the loop, 500 op-3 replacements of V's page produced no byte of the 0x41-filled page in 524288 bytes copied out | bad_place=0 bad_prot=0 dead=0 foreign=0 scanned=524288 distinct=5 pid 186 alive | M | results/phase36_realargs/1529b_copyin_race_shm_20261110_114359.txt |
| 2026-11-10 11:45 | 1530a | with the oracle buffer cleared after the truncate releases page 1 and before the regrow recreates it, 120 samples from a child proven live in all four quarters found no stale page content | samples=120 dead=0 foreign_bytes=0 quarters 30/30/30/30 pid 186 alive | M | results/phase36_realargs/1530a_shm_truncate_race_20261110_114527.txt |
| 2026-11-10 11:45 | 1530a | - | - | ? | results/phase36_realargs/1530a_shm_truncate_race_20261110_114507.txt |
| 2026-11-10 11:48 | 1531a | - | - | ? | results/phase36_realargs/1531a_mlfs_truncate_race_20261110_114828.txt |
| 2026-11-10 11:49 | 1531a | - | - | ? | results/phase36_realargs/1531a_mlfs_truncate_race_20261110_114906.txt |
| 2026-11-10 11:49 | 1531a | - | - | ? | results/phase36_realargs/1531a_mlfs_truncate_race_20261110_114954.txt |
| 2026-11-10 11:50 | 1531a | - | - | ? | results/phase36_realargs/1531a_mlfs_truncate_race_20261110_115016.txt |
| 2026-11-10 11:50 | 1531a | - | - | ? | results/phase36_realargs/1531a_mlfs_truncate_race_20261110_115027.txt |
| 2026-11-10 11:50 | 1531a | - | - | ? | results/phase36_realargs/1531a_mlfs_truncate_race_20261110_115054.txt |
| 2026-11-10 11:51 | 1531a | the same read-vs-truncate race on an MLFS file (a different pager and zone from the shm object) found no stale page bytes, with every sample gated on the main thread first proving the regrown page reads zero | samples=120 dead=0 foreign_bytes=0 gate_control_nonzero=0 skipped=0 quarters 30/30/30/30 pid 186 alive | M | results/phase36_realargs/1531a_mlfs_truncate_race_20261110_115112.txt |
| 2026-11-10 11:55 | 1529b | - | - | ? | results/phase36_realargs/1529b_copyin_race_shm_20261110_115515.txt |
| 2026-11-10 11:55 | 1530a | - | - | ? | results/phase36_realargs/1530a_shm_truncate_race_20261110_115555.txt |
| 2026-11-10 11:56 | 1530a | - | - | ? | results/phase36_realargs/1530a_shm_truncate_race_20261110_115620.txt |
| 2026-11-10 11:56 | 1530a | - | - | ? | results/phase36_realargs/1530a_shm_truncate_race_20261110_115629.txt |
| 2026-11-10 11:57 | 1529b | correction to the earlier row: the child now installs a fake TCB, the shm window is scanned every round instead of once at the end, and liveness requires the last two samples to differ -- 500 op-3 replacements still produced no byte of the released page | bad_place=0 bad_prot=0 stale_during_loop=0 scanned=524288 distinct=5 still_moving=true pid 186 alive | M | results/phase36_realargs/1529b_copyin_race_shm_20261110_115537.txt |
| 2026-11-10 11:57 | 1530a | all three ftruncate returns are now checked per cycle and the verdict requires zero dead samples; the shm read-vs-truncate race is clean | samples=120 dead=0 truncate_fail=0 foreign_bytes=0 quarters 30/30/30/30 pid 186 alive | M | results/phase36_realargs/1530a_shm_truncate_race_20261110_115645.txt |
| 2026-11-10 11:57 | 1531a | same hardening on the MLFS probe: truncate returns checked, verdict requires zero dead samples, oracle gated on the control read -- still no stale page | samples=120 dead=0 truncate_fail=0 gate_skipped=0 foreign_bytes=0 quarters 30/30/30/30 pid 186 alive | M | results/phase36_realargs/1531a_mlfs_truncate_race_20261110_115707.txt |
| 2026-11-10 12:01 | 1531a | after the review's seven findings were applied the MLFS probe proves its own preconditions: page 1 is read back and must hold the marker before every release, all three ftruncate returns are checked, only the marker byte counts in the oracle channel, and the control read gates every sample -- 120 samples still found no byte of a released page | samples=120 dead=0 truncate_fail=0 arm_fail=0 otherbad=0 gate_skipped=0 foreign_bytes=0 control_nonzero=0 pid 193 alive | M | results/phase36_realargs/1531a_mlfs_truncate_race_20261110_120137.txt |
| 2026-11-10 12:01 | 1531z | - | - | ? | results/phase36_realargs/1531z_mlfs_diag_20261110_120122.txt |
| 2026-11-10 12:01 | 1531z | - | - | ? | results/phase36_realargs/1531z_mlfs_diag_20261110_120131.txt |
| 2026-11-10 12:08 | 1531a | repeat of the hardened MLFS run reproduces the result exactly, and the per-quarter denominator is now correct (quart*CYCLES) after the review flagged it | samples=120 dead=0 truncate_fail=0 arm_fail=0 otherbad=0 foreign_bytes=0 control_nonzero=0 quarters 30/30/30/30 of 30 each pid 193 alive | M | results/phase36_realargs/1531a_mlfs_truncate_race_20261110_120847.txt |
| 2026-11-10 12:13 | StatusArray | syscall 573 mdbg_call has a native body (thunk 0x8ac26360 -> 0x8b65c830 -> 0x8b163d80); the 'nosys trampoline' verdict came from the compat CSV row 0x265760 | 513/0x266360 native body present; 0x80-byte stack status array bounded at index 8 of 32; copyout <= 0x24 bytes | S | - |
| 2026-11-10 12:32 | StrAudit | all 74 copyinstr sites are bounded; the helper charges its budget before each byte so the max write offset is len-1 and the NUL counts | 74/74 bounded; every 0x400 bound lands in a 0x408+ stack slot, an exact 0x400 alloc, a 0x400 zone item, or a 0x44000 kmem buffer | S | - |
| 2026-11-10 13:37 | 548align | 548 op 2 gates on 16 KiB alignment of start and length BEFORE dispatch, so every earlier op-2 range test that passed len=0x1000 was void; the call does reach vm_map_protect once aligned | 13.60 body 0x8b47c0b7 test esi,0x3fff / 0x8b47c0ca test edx,0x3fff -> EINVAL(22) at 0x8b47c2b8; 1479b +0x12 (len 0xFF000000, aligned) reached the call and killed | S | - |
| 2026-11-10 13:42 | 1533a | 548 op 2 is a working vm_map_protect for anonymous pages: it lowers 3->1 and 3->0, normalises WRITE to READ\|WRITE, and refuses PROT_EXEC with EACCES because the page's max_prot excludes it | prot 1 -> rv=0 processed=1 547=0x1; prot 2 -> 547=0x3; prot 0 -> 547=0x0; prot 7 -> rv=-1 13 Permission denied; misaligned start/len and prot 0x18 -> rv=-1 22; count=2 -> processed=2; device 0x33->1->0x33 all taken | M | results/phase36_realargs/1533a_sys548_16k_alignment_20261110_134214.txt |
| 2026-11-10 14:12 | 1534b | 548 op 0 reaches the descriptor path with a 16 KiB-aligned position and returns EBUSY(16) at a free fixed address for every descriptor, while dmem0 at position 0x120000000 returns the same EACCES(13) that 477 does, so the fd is consumed; misaligned position and arg2 bit 0x400 give EINVAL(22) | EBUSY(16) for zero/eboot/dmem0/gc at pos 0, EACCES(13) for dmem0 pos 0x120000000, EINVAL(22) for pos 0x1000 and arg2 0x400, processed=0 throughout | M | results/phase36_realargs/1534b_sys548_op0_descriptor_map_20261110_141234.txt |
| 2026-11-10 14:22 | 548ops | 548's five opcodes dispatch through an undumped table at 0x8e29bf54; the mmap helper 0x8b478430 maps an internal vm_map_find status to EBUSY(16) from its own table at 0x8c29bed0, and the munmap helper 0x8b478bb0 (vm_map_lock 0x8ac86480 + vm_map_delete 0x8ac89370) is reached by the body at 0x8b47c185, which neither op 1 nor op 4 reaches on 14.10 | op-to-case mapping unresolved (table undumped); op 3 returns 0 when the address is mapped and the address when it is free; op 0 the reverse | S | - |
| 2026-11-10 14:25 | 1534c | 548 op 0 returns EBUSY(16) even on a live range the caller owns and created with op 3 - a valid descriptor does not change it - and op 1 on that same range returned 0/processed=1 after which the first read of the range faulted, so op 1 removed it | op 0: EBUSY(16) for /dev/zero, eboot, dmem0, physhm, fd 0 and a bogus fd on an op-3 range; arg2 0x12/0x20/0x40 -> EINVAL(22), 674 record count unchanged (318->318); dmem0 pos 0x120000000 -> EACCES(13); op 1 -> rv=0 processed=1 then SIGSEGV reading U | M | results/phase36_realargs/1534c_sys548_op0_on_live_range_20261110_142452.txt |
| 2026-11-10 14:34 | 1535a | 548 op 2 refuses bit 0x4 on the device window exactly as it does on anonymous memory, so the mapping's max_prot excludes exec and W^X holds at the entry on the last mapping class a game process can reach | SceGnmTrapData 0xF00004000 prot 0x33 before; 0x37/0x7/0x5 all rv=-1 EACCES(13) processed=0 with 547 still reading 0x33; 0x33 re-applied rv=0 processed=1; the planted 48 89 07 EB FE wrote and read back, then was restored | M | results/phase36_realargs/1535a_gpu_window_exec_via_548_20261110_143418.txt |
| 2026-11-10 14:34 | 1534c-correction | correction to the 1534c row: op 1 returning 0 with processed=1 followed by a faulting read is NOT proof that op 1 removed the mapping - 547 was never re-read between the call and the read, and 1480b has op 1 on a 477 mapping leaving the page mapped and readable, so the removal claim is an inference with one data point and a counterexample on another mapping class | measured: op 1 rv=0 processed=1 then SIGSEGV on the first read of U; not measured: 547 of U after op 1, and whether the fault is the mapping's removal or its object being detached | I | - |
| 2026-11-10 14:41 | 601twostep | the attach-then-write composition for 601 was already measured by 1355a's consumer sweep, which called 0x01 (rv=-1) and then every command up to 0x1A before 0x1B killed the process, so a failed attach leaves no usable context on 14.10 and no probe needs to be spent on the two-step | 0x01 -1 ch=0 early in the same process; 0x07/0x09/0x0B/0x0D/0x13/0x14/0x19/0x1A all rv=0 writing nothing; capture ends at 'calling 0x1B ...' with no output after it | S | - |
| 2026-11-10 14:56 | 548cases | the five 548 op cases sit at strictly ascending addresses and the two measured ops (2=protect, 3=map) pin the order, so op 0 is the gated elevated map, op 3 the MAP_ANON map, and the remaining two cases are the deferred-protect queue (0x8b47c088) and the direct munmap (0x8b47c185) | op order 0..4 = bff3/c088/c0b0/c11e/c185; op 1 queues via 0x8b47bf1a and applies through 0x8b47c3b0 -> 0x8ac8dc10, a different validator from op 2's vm_map_protect | S | - |
| 2026-11-10 14:56 | 548race | the VM-map concurrency axis is not measurable from Lua: run_lua_code_in_new_thread is not reentrant and does not survive a syscall loop, and a helper death kills the process, so a 548 race probe cannot distinguish an anomaly from its own instrument | 496c/496d second-spawn death; 1517a/1518a loop deaths; probe abandoned unsent | D | - |
| 2026-11-10 15:00 | 1480b-correction | 1480b's op=1 line never called op 1: its entry buffer still held set_entry(A,0,0x4000,3,2), so that rung repeated op 2 on A, and the corpus therefore contains exactly one op-1 measurement (1534c's fault) and no control showing op 1 leaves a range mapped | last set_entry before the rung is op 2 on A; capture shows A at prot 3, D untouched and still holding 33334444 | I | - |
| 2026-11-10 15:05 | 1537a | 548 op 1 is munmap: on a 477 range, an op-3 range, a second fresh 477 range and a range with offset=0x1000, every call returned rv=0 processed=1 and the range then had no 547 record and no 674 record, so 1534c's post-call fault was a load from freshly unmapped memory and the offset field is ignored by op 1 | 4/4 ranges removed, 674 record counts 318->321->320, teardown found the U1 address re-mapped by the loader at 0x64KB | M | results/phase36_realargs/1537a_sys548_op1_removal_check_20261110_150521.txt |
| 2026-11-10 15:10 | 548op4 | op 4 is the queueing case 0x8b47c088 by elimination: op 0/1/2/3 are pinned to 0x8b47bff3/0x8b47c185/0x8b47c0b0/0x8b47c11e, and the deferred applier 0x8ac8dc10 rejects any entry whose protection byte has bit 1,2,3,5 or 7 set (test r12b,0xae / sete), so it cannot grant WRITE or EXEC and is not a W^X path | 0x8ac8dcd9 cmp byte [rdx+0x21],0xa / 0x8ac8dce5 test r12b,0xae / 0x8ac8dce9 sete cl / 0x8ac8dcf1 jne reject | S | - |
| 2026-11-10 15:14 | 1537b | 548 op 4 is a stub answering ENOTSUP(45) with processed=0 on both prot 3 and prot 1, op 0 is a stub answering EBUSY(16) with processed=0 even with a real dmem0 fd 23 or physhm fd 22, and op 1 splits a 256 KiB entry precisely around the middle page, so the five ops are 0=stub 1=munmap 2=mprotect 3=anon-map 4=stub | op4 rv=-1 45/processed=0 twice; op0 rv=-1 16/processed=0 twice; op1 rv=0 processed=1 leaving 0x310E54000-0x310E74000 and 0x310E78000-0x310E94000 around a removed middle page | M | results/phase36_realargs/1537b_sys548_op4_and_op0_semantics_20261110_151410.txt |
| 2026-11-10 15:21 | 601attachlen | 601 cmd 0x01's arg3 is a length in qwords, not a flags word: the 13.60 case at 0x8b6611ce keeps only arg3 in [2,15] with cmp rax,-0xe/jb on arg3-0x10 and then copyin(arg2, stack, arg3*8) into a 0x78-byte buffer; the struct must begin {1, <3\|4>} | static: 0x8b6611ea lea rax,[r12-0x10] / 0x8b6611f5 cmp rax,-0xe / 0x8b6611f9 jb; 1384a passed flags words in that slot, so its uniform EINVAL was the length gate, not a credential gate | S | - |
| 2026-11-10 15:43 | 1538b | 601 cmd 0x23 accepts {1,3,<name>} with arg3=3 and returns 0, then a second call on the same shape returns EPERM(1), so arg3 is a length and the call installs per-process state | len3 rv=0, len0 rv=-1 EINVAL(22), repeat len3 rv=-1 EPERM(1), len15 rv=-1 EPERM(1); 0x15 and 0x1F also shift with arg3 | M | results/phase36_realargs/1538b_sys601_length_owner_sweep_20261110_154233.txt |
| 2026-11-10 16:06 | td578pair | 601 has an upload/download pair on td+0x578 (malloc 0x480 + copyin, then copyout + free), and two other cases let a caller qword be stored in that same slot | static: 0x8b660e63 / 0x8b661542 store caller qwords at td+0x578..+0x590; the download at 0x8b661b2c copies 0x480 bytes from that pointer to user then frees it via 0x8b5c8df0, a zone deallocator - read plus unchecked free in one call, never probe with a forged pointer | S | - |
| 2026-11-10 16:11 | 1541a | 601 cmd 0x1B kills the process before returning even with a mapped 0x48-byte struct, a non-matching channel name and arg3=9 | CAPTURE ENDS AT '601(0x1B, buf, 9) ...'; 9026 then CONNECTION_REFUSED, so the game died - third consecutive kill for this command, now with a controlled shape | M | results/phase36_realargs/1541a_sys601_cmd1b_name_gate_20261110_161109.txt |
| 2026-11-10 16:20 | 1542a | 601 cmd 0x1B kills with a mapped 0x1000 page in arg3 as well, so arg3 being a small integer is not the cause; five independent shapes now die there | pid 221: [A] 601(0x1B, buf, 0x310ff9700) printed then the capture ends, 9026 refused; no rv | M | results/phase36_realargs/1542a_sys601_cmd1b_arg3_pointer_20261110_161943.txt |
| 2026-11-10 16:20 | 1404a-note | 1404a's 'idx=0x1B rv=-1 EINVAL' is NOT command 0x1B: the sweep passes the index in arg2 with arg1 fixed at 0x12, so that line names an index value, not a command, and must never be cited as 0x1B being safe | probes/phase36_realargs/1404a_sys601_cmd12_index.lua:89 sc601(uint64(0x12), uint64(i), uint64(OUT), ...) | S | - |
| 2026-11-10 16:23 | 1543a | 601 cmd 0x1B kills with arg3=0 as well, so no argument value tested rescues it; five distinct arg3 values (0,9,0x100,0x1000,mapped page) all die, so 0x1B is an unconditional killer on 14.10 | pid 228: [A] 601(0x1B, 0x3116031c0, 0x0) printed then the capture ends; no rv | M | results/phase36_realargs/1543a_sys601_cmd1b_arg3_zero_20261110_162129.txt |
| 2026-11-10 16:26 | 16kpages | 1450a/1446d/1469a measured with 4 KiB assumptions: mmap(0x4000) is ONE 16 KiB page, so the four addresses they call pages are all inside it and the 'munmap is entry-scoped' conclusion was never measured | kernel page size 0x4000 per 548 op 2's test esi,0x3fff gate and the munmap helper's rounding; 1469a's MAP_FIXED 'refusal' was a misaligned 0x1000 request | S | - |
| 2026-11-10 16:29 | 1544a | syscall 73 splits a sixteen-page entry precisely, exactly like 548 op 1; the 0x4000 page size is directly measured by sixteen distinct sentinels at 0x4000 stride inside one 0x40000 547 record | 73(base+0x10000,0x4000)=0; 547 after: pages 0,1,2,3,5,14,15 prot 0x3, page 4 unmapped; baseline 0 bad; child fault after the spawn line ended the connection | M | results/phase36_realargs/1544a_munmap_pte_scope_20261110_162901.txt |
| 2026-11-10 16:45 | 1503a-correction | RETRACTION of the mincore residency-oracle claim: a 0x40000 mincore writes only 16 bytes, because 0x40000/0x4000 = 16 pages of the 16 KiB kernel page size, and all 16 read 0x0B resident. The 0x00 bytes at 0x10..0x3F were never written by the kernel, so 16 of 64 is a counting artifact and the printed verdict is the opposite of the measurement. mincore reports every mapped page resident on the dmem pager and is NOT a hole-scanning oracle; the same capture's [C] arm (0x800000 -> 512 of 512) is already 16 KiB-correct and agrees | vec 0B x16 then 00 x48, i.e. 16 written bytes all 0x0B; len 0x40000 / 0x4000 = 16 | I | - |
| 2026-11-10 16:45 | 1504a-correction | CORRECTION of the pool-coverage claim: len 0x1000000 is 1024 pages of 16 KiB, so mincore wrote 1024 bytes and reported all of them resident; the 3072 'non-resident pages skipped' is 4 KiB bookkeeping. [C] therefore read base+0 .. base+0x3FF000, the first 4 MiB of a 16 MiB map, and the 'the pool is all zeros' negative describes 4 MiB, not 16. The [D] EACCES negatives are separately sound | mincore 1024/4096 resident (len/0x4000 = 1024); 3072 skipped was artifact; 4 MiB read of 16 MiB | I | - |
| 2026-11-10 16:57 | 1547a | Device frames round the offset DOWN to 0x4000, so a request that ends exactly at the dmem aperture limit maps a frame that also ends at the limit: the ACL straddle is structurally impossible, not merely unobserved | entry for len=0x1000 at dev 0x1000 is 0x3115E8000..0x3115EC000 (0x4000) with the mapped VA at +0x1000; SLIDE confirmed (A1+0 == A0+0x1000); aperture edge bisected to LIMIT=0x110010000 (not 0x120000000 or 0x140000000); [E] map off=LIMIT-0x1000 len=0x1000 accepted, entry ends at LIMIT, 547 refused at LIMIT; [E0] off=LIMIT-0x4000 len=0x4000 accepted; [E1] off=LIMIT-0x1000 len=0x4000 EACCES(13) | M | results/phase36_realargs/1547a_dmem_frame_straddle_20261110_165645.txt |
| 2026-11-10 17:13 | 548maxprot | the W^X wall is a single mask on the object's max protection: 0xffffffff8b4789be and r9d,0x3f3 clears bit 0x4 (PROT_EXEC) and 0x8 for every file/device mapping, so no requested protection with X can survive the vm_map_find that follows | static: 0x8b47857a movzx r9d, word [rbp-0x72] / 0x8b47858e and r9d,0x3f3 / 0x8b4789d5 call 0xffffffff8b47ea20; anon takes 0x8b479f60 and is measured max_prot 3 (1480a) | S | - |
| 2026-11-10 17:13 | 548maxprot-fix | address correction for row 548maxprot: the mask is at 0xffffffff8b4789be (helper 0xffffffff8b478430 + 0x58e), the maxprot load at 0xffffffff8b4789aa, the find at 0xffffffff8b4789d5, the descriptor resolve at 0xffffffff8b47896c | the earlier --result line printed offsets as if they were VAs (0x8b47858e); the helper base is 0x8b478430 so +0x58e is 0x8b4789be | S | - |
| 2026-11-10 17:35 | 1548a | 548 op 3 MAP_FIXED carves a device-backed entry correctly: eight interior splits, all accepted at the requested address, boundary checks pass, 8 anon/8 device pages, carved page reads 0 while the uncarved neighbour still reads C0012800, and the device object still maps afterwards | carves=8 accepted=8 boundary-ok=8 anon=8 device=8 absent=0; munmap rv=0, 547 clean | M | results/phase36_realargs/1548a_map_fixed_over_device_entry_20261110_173458.txt |
| 2026-11-10 17:40 | 548noretry | vm_map_protect takes the map lock exactly once and never releases it before the epilogue, so there is no unlock/relookup retry window and the protect-versus-munmap race cannot be built | 0xffffffff8ac8bdb0..0x8ac8d0fa: single call to the mutex helper 0x8b60bb20 at 0x8ac8be42 (rw arm 0x8ae86a00 at 0x8ac8be60), no backward branch to <= 0x8ac8be70 in 0x8ac8bdb0..0x8ac8d300, one ret at 0x8ac8d0fa | S | - |
| 2026-11-10 17:40 | 601ioctl2 | 601's forwarder is the debugger stop-the-world, and its download path needs a registration bit no reachable command sets, so 601 has no pointer-store-then-read body at all | allowlist 0x8b65fae0 admits exactly 0xa002830e/f/0xa0028310/0xa002c315/0xa0020102/0xa0020311/0xa0020319; body sets [proc+0x560]\|=0x4000 and walks [proc+0x10] clearing bit 0x200 per thread; download case 0x8b661032 returns rv=2 when td+0x528 lacks 0x400 and no 1538b command returned 2 | S | - |
| 2026-11-10 18:07 | voidaudit | the seven 'no complete capture' dead ends are all carried by a second capture; the only defect was a wrong attribution, not a missing measurement | kenv->1341c; kld*->353d (kldstat 0.81C/0x60/0x1C all -1, 307(0)=-1, 306(0)=-1); 601 0x03->323a (printed 0x00-0x02, died at 0x03), 0x04->324a (banner only, loop starts 0x04); 629 jail->54b phase 1; resolve()->1341a2; MapDM->546c/552a/552c/552e; VM ops->1341b not 524a (524a is an AIO probe with no VM-op section) | S | - |
| 2026-11-10 18:13 | 1549a | syscall 601 command 0x03 terminates the process on the 323a shape, now measured with a pre-printed call instead of inferred from a loop's order | pid 249: `[A] CALL 601(0x03, 310A439E0, 100)` printed then EOF, no rv; 9026 then answered CONNECTION_REFUSED | M | results/phase36_realargs/1549a_sys601_cmd03_printed_20261110_181253.txt |
| 2026-11-10 18:19 | 1199b | kernel image at 0xFFFFFFFFD5000000-0xFFFFFFFFDB1FFFFF (98MB, slide +0x55000000) on fresh 14.10 boot | TEXT=0xFFFFFFFFD5000000 DATA=0xFFFFFFFFD5CE0000 ALLPROC=0xFFFFFFFFD85B9EA0 | M | results/phase17_new_vectors/1199b_fault_oracle_upper_20261110_131841.txt |
| 2026-11-10 19:01 | 1550a | pipe(42) works: it returns fd0 in rax with fildes[] left untouched, so the DEAD_ENDS 'returns fds 0,0' row is a probe artefact | rv=22 = fd0, pair 22/23, byte round-trip in both directions; fildes[] still 0xDEADBEEF | M | results/phase36_realargs/1550a_pipe_rdx_recovery_20261110_190107.txt |
| 2026-11-10 19:01 | 1552a | 548 op 2 grants WRITE on a MAP_PRIVATE vnode entry and COW still breaks correctly - the store goes to a private copy, the page cache and other mappings are untouched | op2 1->3 rv=0 processed=1, 547=3, store landed 0x5C, V2 read 0xA7, fresh V3 read 0xA7 | M | results/phase36_realargs/1552a_cow_break_via_548_op2_20261110_190131.txt |
| 2026-11-10 19:21 | 1553a | a native child storing into page P faulted on its first store after 548 op1 unmapped P, then the loader died before any verdict printed; the fault is the correct-kernel signature but nothing was measured about a stale PTE | child RIP=0x2C152C67 (store gadget), rdi=0x31084C000 (P), RSP walked 0x16B70 bytes (about 1938 store pairs) then faulted; no [D] lines, no heartbeat, 9026 CONNECTION_REFUSED after | V | results/phase36_realargs/1553a_munmap_vs_store_race_20261110_192006.txt |
| 2026-11-10 19:24 | 1556a | a single thr_create(430) child faulting on an unmapped user VA takes the whole loader down; the parent never printed again | child RIP=0x2E856C67 (store gadget) rdi=0x200000000 (unmapped) rsp=0x3111BC000 untouched (first instruction faulted), rax=0x0011223344556677; no [A] thr_create line after, 9026 CONNECTION_REFUSED | M | results/phase36_realargs/1556a_child_fault_survivability_20261110_192412.txt |
| 2026-11-10 19:26 | 1534c-pte | after 548 op1 returns rv=0 processed=1, the very next read of the removed range faults and ends the run, so vm_map_delete has zapped the PTEs before it returns in the non-racy case | 1534c [G]: op1 on U(0x500004000) rv=0 processed=1 then immediate fault dump with no further line; 1537a is the control (four op1 calls, process survived and printed), 1556a proves a user-space fault ends the run | M | - |
| 2026-11-10 19:28 | 1557a | a native child storing continuously into a page that 548 op1 unmaps faults on its next store; no store survived the unmap, so vm_map_delete leaves no PTE a racing user store can reach | arm check P=H=MARKER, child faulted at RIP=0x1A792C67 (store gadget) rdi=0x3109A8000 (P) rsp=0x310C3D9F0 (1.2 MB into the 8 MiB fill, about 25k periods after the arm check); [A] control op1 rv=0 processed=1 547=-1 and the process lived | M | results/phase36_realargs/1557a_unmap_pte_removal_20261110_192806.txt |
| 2026-11-10 19:35 | 1555a | memory.write_qword, write_dword and write_buffer all land on a 477 anon page; but to_num() on a read-back uint64 loses low bits (0x11223344556677 read back as 0x1122334455666C), so 64-bit round-trips must be printed with %X on the raw uint64, never through tonumber | pid 284 P=0x311244000; [A] write_qword lands; [B] 4096 write_dword calls zero the page; [D] write_buffer zeroes it; [C]/[E] sentinels (0xAAAAAAAAAAAAAAAA, MARK) came back with corrupted low bits - the same corruption as 1554a's 'H reads MARKER before the child ran' | M | results/phase36_realargs/1555a_memory_write_paths_20261110_193430.txt |
| 2026-11-10 19:37 | 1554a | VOID: [B] never called prep(Pv), so fire() re-sent the entry still describing the already-unmapped control page; op1 answered rv=0 processed=1 while 547(P) still read 3, and the heartbeat probe correctly refused to call that a stale PTE | capture 1554a_unmap_vs_first_touch_fault_20261110_193651.txt: ctx=0x3104C0020 no overlap, op1 rv=0 processed=1, 547(P) after=3, h1=h2=0xDEADBEEF, VOID branch taken | V | results/phase36_realargs/1554a_unmap_vs_first_touch_fault_20261110_193651.txt |
| 2026-11-10 19:37 | 1559a | string.format('%X', <raw uint64 table>) raises 'bad argument #3 to format (number expected, got table)', so a 64-bit value must be converted with to_num before printing, and every arm check in the race probes compares through that conversion | capture 1559a_marker_precision_20261110_193629.txt: pid 298, died at line 70 in show() with that error | M | results/phase36_realargs/1559a_marker_precision_20261110_193629.txt |
| 2026-11-10 19:39 | 1554a | first-touch fault: the child's initial store into a fresh 477 page is serviced normally and the process survives; it then ran 23,445 store periods until 548 op1 unmapped the page, at which point the next store faulted with no stale PTE (same clean result as 1557a) | capture 1554a_unmap_vs_first_touch_fault_20261110_193914.txt pid 305: all staged H reads 0x0 before thr_create, H=0xDEADBEEF read immediately after spawn (so P was already writable), dump RIP=0x4DF96C67 STORE rdi=0x310C0C000 (=P) rsp=0x310E56C00 = 0x112C00 into the fill = 23,445 periods | M | results/phase36_realargs/1554a_unmap_vs_first_touch_fault_20261110_193914.txt |
| 2026-11-10 19:42 | 1562a | 548 op2 on a 16 KiB sub-range does not leak max_prot: adding EXEC to a single device page answers EACCES(13) exactly like the whole-window call, and a carved anon page still refuses 0x7, so the check is applied per entry and W^X cannot be reopened by splitting | capture 1562a_sys548_subrange_maxprot_20261110_194204.txt pid 312: [B] op2(MID,0x4000,0x33) rv=0 processed=1 547=51; [C] op2(MID,0x4000,0x37) rv=-1 processed=0 547=51; [D] op3 MAP_FIXED carved 0xF0000C000 as anon prot 3; [E] op2(CARVE,0x4000,0x7) rv=-1 processed=0 547=3; [F] restored 51 | M | results/phase36_realargs/1562a_sys548_subrange_maxprot_20261110_194204.txt |
| 2026-11-10 19:44 | 1563a | 674 writes min(map-entries, arg3) records of arg2 bytes at an attacker-chosen base with no buffer-length argument: 400/4000 both wrote 316*72=0x58E0 bytes into a 0x10000 region, and the limit truncates exactly (8 -> 0x240, 1 -> 0x48, 0 -> nothing), so the count is bounded by the map and by arg3 only, never by the caller's buffer | capture 1563a_sys674_record_bound_20261110_194414.txt pid 312: [A] rv=0 count=316 furthest=0x58DC; [B] lim 8 -> 0x23C, 1 -> 0x44, 0 -> nothing; [C] lim 4000 -> same 0x58DC; [D] void (filled 0xEEEEEEEE, span() looks for 0xA5A5A5A5) | M | results/phase36_realargs/1563a_sys674_record_bound_20261110_194414.txt |
| 2026-11-10 19:47 | 1564a | VOID by my own defect: the probe sized the 674 record buffer at 0x4000 while asking for 400 records, so the kernel wrote 316*72=22752 bytes over the Lua heap and killed the loader before any test ran -- an incidental confirmation of 1563a's no-buffer-length property | capture 1564a_sys548_map_fixed_boundary_20261110_194737.txt: prints [0] pid=312 then EOF; 9026 answers CONNECTION_REFUSED; buf was memory.alloc(0x4000), needed 0x58E0 | V | results/phase36_realargs/1564a_sys548_map_fixed_boundary_20261110_194737.txt |
| 2026-11-10 19:52 | 1564a-run | 548 op3 MAP_FIXED across a boundary between an anon page and a device entry replaces BOTH cleanly: after carving 0x8000 at 0xF00000000 spanning the SceGnmTrapData entry [0xF00004000,0xF00008000), both pages read back the 0xCAFEBABE we stored and 547 reports one record at prot 3, so the delete path clips both entries and no pager object survives the remap | capture 1564a_sys548_map_fixed_boundary_20261110_195243.txt pid 319: [A] 674 count=316 named SceGnmTrapData 0xF00004000; [C] carve at 0xF00008000 took, device neighbour read 0xF00144000; [D] mmap 0x8000 at 0xF00000000 -> rv=0xF00000000; [E] both pages 0xCAFEBABE; [F] 547 one record [0xF00000000,0xF00008000) prot 3 | M | - |
| 2026-11-10 19:54 | 1565a | 674's record copyout respects the user page write bit: pointing the buffer at a READ-ONLY executable page (eboot 'executable' segment 0x78420000, target inside it) returns rv=-1 with zero of sixteen dwords changed, so a kernel copyout cannot write into a code page and 674 is not a W^X bypass | capture 1565a_sys674_writebit_bypass_20261110_195359.txt pid 319: [A] 674 count=315, largest prot-5 range name='executable' [0x78420000,0x788B4000); [B] before C0FFFBD1 F875FB85 0F6696EB 0000441F; [C] 674(T=0x7866A000,72,1,cnt) rv=-1; [D] changed dwords=0 of 16 (errno not printed) | M | results/phase36_realargs/1565a_sys674_writebit_bypass_20261110_195359.txt |
| 2026-11-10 20:07 | vmfaulthold | the fault-time map race is closed by construction, which is why 1552a/1554a/1557a all measured clean: vm_fault_hold drops the map lock only at 0x8b0c75ab/0x8b0c7ab7 (vm_map_lookup_done), re-acquires with _sx_try_slock at 0x8b0c7e76, then gates pmap_enter behind a map->timestamp compare at 0x8b0c7e97 and, if it changed, a second full vm_map_lookup at 0x8b0c7ecc with object/pindex equality at 0x8b0c802f/0x8b0c803f; a racing vm_map_delete must take the exclusive lock, which bumps timestamp at 0x8ac864cc, so the stale entry is never used | static from .local/ktext_ins.pkl: vm_fault 0x8b0c69e0, vm_fault_hold 0x8b0c6b40 size 0x1e3f, RetryFault 0x8b0c6c18, pmap_enter 0x8b2a2760 called only at 0x8b0c6f8c (pre-drop) and 0x8b0c86f8 (behind all three gates) | S | - |
| 2026-11-10 20:11 | 1566a | /dev/dce's real ioctl words are not the 16-bit numbers the earlier sweeps fired: the 13.60 dispatcher compares the command register against thirteen 32-bit constants (group 0x82), and the first two tested on 14.10 diverge -- 0x9CE88210 returns -1 while 0x80208217 BLOCKS the calling thread forever, wedging the loader exactly like 0xC0048125 on /dev/gc | capture 1566a_dce_real_ioctl_words_20261110_201038.txt pid 319 fd=22: [A] 0x80088209 rv=0; [B] 0x9CE88210 rv=-1; [B] 0x80208217 never returned (IDLE_TIMEOUT 30s, then CONNECT_TIMEOUT) | M | results/phase36_realargs/1566a_dce_real_ioctl_words_20261110_201038.txt |
| 2026-11-10 20:47 | 1199b_fault_oracle_upper | KASLR re-verified same boot: kernel at 0xFFFFFFFFD5000000, 98MB, slide +0x55000000 | 50 mapped pages, stub at C0000000 | M | results/phase17_new_vectors/1199b_fault_oracle_upper_20261110_153847.txt |
| 2026-11-11 20:26 | 1567a | /dev/dce 0x40D08214 (IOC_OUT, 0xd0 bytes) is inert on 14.10: rv=-1 and the buffer is untouched, so the credential gate in front of it refuses a game process before any copyout | capture 1567a_dce_word_out_d0_20261110_203720.txt pid 81 fd 22: control 0x80088209 rv=0, 0x40D08214 rv=-1 buf[0]=0x0, closed | M | results/phase36_realargs/1567a_dce_word_out_d0_20261110_203720.txt |
| 2026-11-11 20:26 | 1568a | /dev/dce 0xC008820B (8-byte IN) is also inert on 14.10: rv=-1 with an untouched buffer, so the generic handler 0x8b225380 the four 0x82 words share refuses at its entry rather than entering the driver | capture 1568a_dce_word_in_8_20261110_203803.txt pid 81 fd 22: control 0x80088209 rv=0, 0xC008820B rv=-1 buf[0]=0x0 | M | results/phase36_realargs/1568a_dce_word_in_8_20261110_203727.txt |
| 2026-11-11 20:26 | 1569a | SECOND CONSOLE-FATAL word: /dev/dce 0x80288208 (group 0x82 function 0x08, 0x28 bytes) blocks the calling thread forever and the whole console dies -- every unmeasured dce word that actually reaches a handler has done this (0x80208217, now 0x80288208), while the three that returned -1 are gate or no-case paths | capture 1569a_dce_word_inout28_20261110_204058.txt (no text received): IDLE_TIMEOUT 30s after the pre-call header, ping then CONNECT_TIMEOUT, console dead before 1570a | M | results/phase36_realargs/1569a_dce_word_inout28_20261111_202545.txt |
| 2026-11-09 20:41 | p690 | - | - | ? | results/phase13_webkit/p690_walk_forge_oracle_20261109_204155.txt |
| 2026-11-09 23:54 | p691 | - | - | ? | results/phase13_webkit/p691_walk_forge_fixed_20261109_235425.txt |
| 2026-11-10 01:32 | p710 | - | - | ? | results/phase13_webkit/p710_base_discovery_20261110_013236.txt |
| 2026-11-10 04:11 | p803 | - | - | ? | results/phase14_kernel_read/p803_procfs_auxv_20261110_041157.txt |
| 2026-11-10 13:16 | 1199a | - | - | ? | results/phase17_new_vectors/1199a_fault_oracle_kaslr_20261110_131652.txt |
| 2026-11-10 13:42 | 1400a | - | - | ? | results/phase17_new_vectors/1400a_ipv6_pktopts_race_20261110_134201.txt |
| 2026-11-10 13:42 | 1400a | - | - | ? | results/phase17_new_vectors/1400a_ipv6_pktopts_race_20261110_134213.txt |
| 2026-11-10 13:44 | 1401a | - | - | ? | results/phase17_new_vectors/1401a_ipv6_child_race_20261110_134453.txt |
| 2026-11-10 13:45 | 1400a | - | - | ? | results/phase17_new_vectors/1400a_ipv6_pktopts_race_20261110_134516.txt |
| 2026-11-10 13:51 | 1401b | - | - | ? | results/phase17_new_vectors/1401b_ipv6_child_race_v2_20261110_135105.txt |
| 2026-11-10 13:52 | 1401c | - | - | ? | results/phase17_new_vectors/1401c_ipv6_child_race_v3_20261110_135249.txt |
| 2026-11-10 14:16 | 1199b | - | - | ? | results/phase17_new_vectors/1199b_fault_oracle_upper_20261110_141647.txt |
| 2026-11-10 15:38 | 1199a | - | - | ? | results/phase17_new_vectors/1199a_fault_oracle_kaslr_20261110_153801.txt |
| 2026-11-10 15:39 | 1405a | - | - | ? | results/phase17_new_vectors/1405a_race_orchestrator_20261110_153931.txt |
| 2026-11-10 16:21 | 01 | - | - | ? | results/phase1_identity_layout/01_identity_20261110_162113.txt |
| 2026-11-10 19:33 | 1554a | - | - | ? | results/phase36_realargs/1554a_unmap_vs_first_touch_fault_20261110_193300.txt |
| 2026-11-10 19:35 | 1554a | - | - | ? | results/phase36_realargs/1554a_unmap_vs_first_touch_fault_20261110_193528.txt |
| 2026-11-10 19:52 | 1564a | - | - | ? | results/phase36_realargs/1564a_sys548_map_fixed_boundary_20261110_195243.txt |
| 2026-11-10 19:53 | 1565a | - | - | ? | results/phase36_realargs/1565a_sys674_writebit_bypass_20261110_195350.txt |
| 2026-11-10 20:35 | 1331a | - | - | ? | results/1331a_20261110_203553.txt |
