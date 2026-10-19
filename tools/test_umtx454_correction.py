#!/usr/bin/env python3
"""Pins for the umtx(454) evidence correction and probe 110a/82a.

docs/UMTX_454_EVIDENCE.md claims that (a) the phase-1/2 "umtx" probes called
syscall 557, (b) the 13.60 capture labels 454 as _umtx_op and 557 as
namedobj_create, (c) 56i2's section [F] is the only saved 454 execution, and
(d) probe 110a issues the never-exercised SHM/ROBUST_LISTS calls with FreeBSD
11 argument layouts (key/params in uaddr1). These tests hold every one of those
claims to a committed line, and pin probe 82a's repaired binding and layouts.

Offline and read-only: no console is contacted.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NOTE = ROOT / "docs" / "UMTX_454_EVIDENCE.md"
CAPTURE = ROOT / "docs" / "sysent-names-13.60.csv"
ATTACK = ROOT / "docs" / "ATTACK_SURFACE.md"
INDEX = ROOT / "docs" / "PROBE_INDEX.md"
CHANGELOG = ROOT / "CHANGELOG.md"
GUIDE = ROOT / "CLAUDE.md"

PROBE_04 = ROOT / "probes" / "phase1_identity_layout" / "04_kernel_surface.lua"
PROBE_10 = ROOT / "probes" / "phase2_kernel_objects" / "10_umtx_stress.lua"
PROBE_11 = ROOT / "probes" / "phase2_kernel_objects" / "11_umtx_race.lua"
PROBE_12 = ROOT / "probes" / "phase2_kernel_objects" / "12_nwake_robust.lua"
PROBE_13 = ROOT / "probes" / "phase2_kernel_objects" / "13_nwake_oracle.lua"
PROBE_82A = ROOT / "probes" / "phase17_new_vectors" / "82a_umtx_exploit_vectors.lua"
PROBE_110A = ROOT / "probes" / "phase19_umtx_454" / "110a_umtx_shm_reachability.lua"
PROBE_56I = ROOT / "probes" / "phase14_final_push" / "56i_unconventional_kaslr.lua"
PROBE_56I2 = ROOT / "probes" / "phase14_final_push" / "56i2_kaslr_auxv_stack.lua"
RESULT_56I = ROOT / "results" / "phase14_final_push" / "56i_unconventional_kaslr_20261018_115126.txt"
RESULT_56I2 = ROOT / "results" / "phase14_final_push" / "56i2_kaslr_auxv_stack_20261018_115541.txt"


def read(path):
    # Some captures (e.g. 56i) contain binary bytes; tolerate them.
    return path.read_text(encoding="utf-8", errors="replace")


class CaptureLabelTests(unittest.TestCase):
    def test_capture_labels_454_umtx_and_557_namedobj(self):
        lines = read(CAPTURE).splitlines()
        self.assertIn("454,_umtx_op,0x265600", lines)
        self.assertIn("557,namedobj_create,0x265da8", lines)


class Phase2MislabelTests(unittest.TestCase):
    """The phase-1/2 umtx probes bound sc_umtx_op to 557; the note's §2 needs it."""

    def test_all_five_probes_bind_557(self):
        pattern = re.compile(r"sc_umtx_op\s*=\s*557,")
        for probe in (PROBE_04, PROBE_10, PROBE_11, PROBE_12, PROBE_13):
            self.assertIsNotNone(pattern.search(read(probe)),
                                f"{probe.name} no longer binds sc_umtx_op to 557")

    def test_probe_10_counts_are_not_return_checks(self):
        source = read(PROBE_10)
        # create counted rv >= 0; lookup/alive/destroy counted pcall success only
        self.assertIn("if ok1 then", source)
        self.assertIn("local rv = r1:tonumber()", source)
        self.assertIn("if rv >= 0 then", source)
        self.assertIn("if ok2 then shm_results.lookup_ok", source)
        self.assertIn("if ok4 then shm_results.destroy_ok", source)

    def test_probe_10_analysis_block_is_in_the_capture(self):
        result = ROOT / "results" / "phase2_kernel_objects" / "10_umtx_stress_20261015_190047.txt"
        text = read(result)
        self.assertIn("SHM double-destroy + lookup after = OK", text)
        self.assertIn("oversized robust: ACCEPTED(!)", text)


class Saved454ExecutionTests(unittest.TestCase):
    """56i2's [F] is the only saved 454 run; 56i never reached its umtx sections."""

    def test_56i_and_56i2_sources_call_454(self):
        self.assertIn("local sc_umtx = make_syscall(454)", read(PROBE_56I))
        self.assertIn("local sc_umtx = make_syscall(454)", read(PROBE_56I2))

    def test_56i2_source_passes_ops_5_and_21(self):
        source = read(PROBE_56I2)
        self.assertIn("sc_umtx(uint64(umtx_obj), uint64(5), uint64(0), uint64(0), uint64(0))", source)
        self.assertIn("sc_umtx(uint64(umtx_obj), uint64(21), uint64(1), uint64(0), uint64(0))", source)

    def test_56i_capture_never_reached_umtx(self):
        # read as bytes: the capture contains binary that decode would mangle
        raw = RESULT_56I.read_bytes()
        self.assertNotIn(b"umtx", raw.lower())
        self.assertNotIn(b"SHM", raw)
        # 7 newlines, ends inside section [B]'s binary dump
        self.assertEqual(raw.count(b"\n"), 7)

    def test_56i2_capture_records_the_f_section(self):
        text = read(RESULT_56I2)
        self.assertIn("[F] UMTX probe", text)
        self.assertIn("MUTEX_TRYLOCK ret=0", text)
        self.assertIn("+0x00: 0x00000000_00018DBB", text)
        self.assertIn("NWAKE_PRIVATE ret=0", text)

    def test_56i2_source_zeroes_the_object_before_the_call(self):
        source = read(PROBE_56I2)
        self.assertIn("safe_wd(umtx_obj + i, 0)", source)
        self.assertIn("safe_wd(umtx_out + i, 0)", source)


class Probe110aTests(unittest.TestCase):
    def setUp(self):
        self.source = read(PROBE_110A)

    def test_header_and_safety(self):
        self.assertIn("-- CRASH_CLASS: LOW", self.source)
        self.assertIn("-- PROBE 110a:", self.source)
        # Lua 5.1: no goto
        self.assertNotIn("goto ", self.source)
        # Bypass the resolver; never resolve by name
        self.assertNotIn("syscall.resolve", self.source)

    def test_binds_454_and_557_control_only(self):
        self.assertIn("local sc_umtx = make_syscall(454)", self.source)
        self.assertIn("local sc_557  = make_syscall(557)", self.source)
        self.assertIn("negative control only", self.source)

    def test_all_syscall_arguments_are_uint64(self):
        self.assertIn(
            "return sc_umtx(uint64(obj), uint64(op), uint64(val),\n"
            "            uint64(uaddr1 or 0), uint64(uaddr2 or 0), uint64(0))",
            self.source)

    def test_umtx_op_wraps_in_pcall(self):
        self.assertIn("local ok, rv = pcall(function()", self.source)

    def test_shm_flags_match_freebsd(self):
        self.assertIn("local SHM_CREAT   = 0x0001", self.source)
        self.assertIn("local SHM_LOOKUP  = 0x0002", self.source)
        self.assertIn("local SHM_DESTROY = 0x0004", self.source)
        self.assertIn("local SHM_ALIVE   = 0x0008", self.source)

    def test_shm_key_lives_in_uaddr1(self):
        # FreeBSD 11: umtx_shm(td, uap->uaddr1, uap->val)
        self.assertIn("return umtx_op(0, OP_SHM, flags, key, 0)", self.source)

    def test_robust_lists_params_live_in_uaddr1(self):
        # FreeBSD 11: copyin(uap->uaddr1, &rb, uap->val); val > 24 is EINVAL
        self.assertIn("umtx_op(0, OP_ROBUST_LISTS, 24, params, 0)", self.source)
        self.assertIn("umtx_op(0, OP_ROBUST_LISTS, 32, params, 0)", self.source)
        self.assertIn("umtx_op(0, OP_ROBUST_LISTS, 0, params, 0)", self.source)

    def test_covers_the_missing_calls(self):
        self.assertIn("shm(SHM_CREAT, key_a)", self.source)
        self.assertIn("shm(SHM_LOOKUP, key_a)", self.source)
        self.assertIn("shm(SHM_ALIVE, key_a)", self.source)
        self.assertIn("shm(SHM_DESTROY, key_a)", self.source)
        # double-destroy and lookup-after (the pattern probe 10 wanted)
        self.assertIn("shm(SHM_DESTROY, key_a)", read(PROBE_110A))
        self.assertIn("churn", self.source)
        self.assertIn("create-no-destroy", self.source)

    def test_alive_checks_the_shm_mapping_not_the_key(self):
        # FreeBSD 11 umtx_shm_alive tests the vm object backing the address,
        # so the probe must map the shm fd and pass that mapping.
        self.assertIn("ALIVE(8) on plain heap key (control)", self.source)
        self.assertIn("sc_ftruncate(uint64(fd0), uint64(0x4000))", self.source)
        self.assertIn("shm(SHM_ALIVE, shm_map)", self.source)
        self.assertIn("ALIVE(8) on the mapping after DESTROY", self.source)
        # mmap failure (-1 or huge uint64) must not be treated as a mapping
        self.assertIn("mnum >= 0 and mnum < 0x800000000000", self.source)

    def test_mutex_owner_readback_and_557_control(self):
        self.assertIn("OP_MUTEX_LOCK", self.source)
        self.assertIn("owner_word=", self.source)
        self.assertIn("CONTROL 557 op=5 same shape", self.source)

    def test_buffers_are_allocated_and_zeroed(self):
        self.assertIn("local word = memory.alloc(0x10)", self.source)
        self.assertIn("zero(word, 0x10)", self.source)
        self.assertIn("local params = memory.alloc(0x40)", self.source)
        self.assertIn("zero(params, 0x40)", self.source)

    def test_canaries_bookend_the_probe(self):
        self.assertIn("canary pid=", self.source)
        self.assertIn("final canary pid=", self.source)
        self.assertIn("=== PROBE 110a COMPLETE ===", self.source)


class Probe82aRepairTests(unittest.TestCase):
    def setUp(self):
        self.source = read(PROBE_82A)

    def test_binds_454_directly(self):
        self.assertIn("local sc_umtx = make_syscall(454)", self.source)
        # the 557 resolve path must be gone from executable code
        self.assertNotIn('syscall.resolve({ sc_umtx_op = 557 })', self.source)
        self.assertNotIn("use_resolve", self.source)

    def test_shm_destroy_flag_corrected(self):
        self.assertIn("local SHM_DESTROY = 4", self.source)
        self.assertNotIn("local SHM_DESTROY = 3", self.source)

    def test_shm_calls_use_uaddr1_layout(self):
        for flags in ("SHM_CREAT", "SHM_LOOKUP", "SHM_DESTROY"):
            self.assertIn(f"umtx_op(0, UMTX_OP_SHM, {flags}, shm_key, 0)", self.source)

    def test_robust_calls_use_uaddr1_layout(self):
        self.assertIn("umtx_op(0, UMTX_OP_ROBUST_LISTS, 24, buf, 0)", self.source)
        self.assertIn("umtx_op(0, UMTX_OP_ROBUST_LISTS, 4096, buf, 0)", self.source)
        self.assertIn("umtx_op(0, UMTX_OP_ROBUST_LISTS, sz, buf, 0)", self.source)
        self.assertNotIn("umtx_op(buf, UMTX_OP_ROBUST_LISTS, 24, 0, 0)", self.source)

    def test_uint64_arguments_in_helper(self):
        self.assertIn(
            "return sc_umtx(uint64(addr), uint64(op), uint64(val),",
            self.source)

    def test_header_documents_the_correction(self):
        self.assertIn("docs/UMTX_454_EVIDENCE.md", self.source)


class DocumentationTests(unittest.TestCase):
    def test_note_exists_and_pins_its_records(self):
        text = read(NOTE)
        for needle in (
            "454,_umtx_op,0x265600",
            "557,namedobj_create,0x265da8",
            "0x00000000_00018DBB",
            "MUTEX_TRYLOCK ret=0",
            "reads the key address from `uaddr1`",
            "copies the 24-byte `struct umtx_robust_lists_params` from `uaddr1`",
            "CVE-2024-43102",
            "probes/phase19_umtx_454/110a_umtx_shm_reachability.lua",
        ):
            self.assertIn(needle, text)

    def test_note_links_only_existing_files(self):
        import re
        text = read(NOTE)
        for rel in re.findall(r"`(probes/[^`]+\.lua|results/[^`]+\.txt|docs/[^`]+\.csv)`", text):
            self.assertTrue((ROOT / rel).exists(), f"dangling citation: {rel}")

    def test_attack_surface_has_umtx_row(self):
        text = read(ATTACK)
        self.assertIn("`_umtx_op` (454)", text)
        self.assertIn("UMTX_454_EVIDENCE", text)

    def test_probe_index_rows(self):
        text = read(INDEX)
        self.assertIn("actually called syscall 557 (namedobj_create)", text)
        self.assertIn("only saved execution of 454", text)
        self.assertIn("| 82a | `umtx_exploit_vectors` | PREPARED — NOT RUN |", text)
        self.assertIn("| 110a | `umtx_shm_reachability` | PREPARED — NOT RUN |", text)

    def test_changelog_entry_exists(self):
        text = read(CHANGELOG)
        self.assertIn("the umtx corpus called syscall 557", text)

    def test_claude_guide_correction_exists(self):
        text = read(GUIDE)
        self.assertIn('The "umtx" probes called syscall 557', text)


if __name__ == "__main__":
    unittest.main()
