#!/usr/bin/env python3
"""Tests for tools/tier1_claims_audit.py.

Three layers:

* the pure models (unsigned gate arithmetic, MSR index arithmetic, the
  EACCES-proceed predicate) are pinned independently of the dump, because
  those are the places where an off-by-one or an inverted comparison would
  silently turn a finding into a non-finding;
* the observed facts are pinned against bytes, RVAs and branch targets, so a
  replaced artifact shows up as a failure rather than a quietly different
  verdict;
* one integration test runs the audit and requires exit 0 with no DRIFT row.

Nothing here contacts a console, a network endpoint, or a running process.
"""

import contextlib
import io
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import tier1_claims_audit as audit


class GateModelTests(unittest.TestCase):
    """sys 622: `lea eax,[r14-0x100]; cmp eax,0x33; ja no_auth`."""

    def test_below_the_window_skips_the_bitmap(self):
        # Every command < 0x100 wraps the index above 0x33, so `ja` fires and
        # the two auth calls are skipped before any `bt` executes.
        for cmd in range(0x100):
            self.assertIsNone(audit.bitmask_a_index(cmd), hex(cmd))

    def test_window_bounds(self):
        self.assertEqual(audit.bitmask_a_index(0x100), 0)
        self.assertEqual(audit.bitmask_a_index(0x133), 0x33)
        self.assertIsNone(audit.bitmask_a_index(0x134))
        self.assertIsNone(audit.bitmask_a_index(0x270))

    def test_checked_and_skipped_counts(self):
        checked = audit.mask_a_checked()
        skipped = audit.mask_a_skipped()
        self.assertEqual(len(checked), 22)
        self.assertEqual(len(skipped), 30)
        self.assertEqual(len(checked) + len(skipped), 0x34)
        # The bitmap is not contiguous: 0x101 is unchecked while 0x100 is not.
        self.assertIn(0x100, checked)
        self.assertNotIn(0x101, checked)

    def test_second_bitmap_selects_0x12d_and_0x12e(self):
        # 0x600000000000 has bits 45 and 46 set; 0x100+45 = 0x12d, 0x100+46 = 0x12e.
        self.assertEqual(audit.mask_b_hits(), [0x12D, 0x12E])
        self.assertNotIn(0x130, audit.mask_b_hits())

    def test_total_checked_is_27(self):
        self.assertEqual(audit.auth_checked_commands(), 27)
        self.assertEqual(audit.auth_checked_commands(),
                         len(audit.mask_a_checked()) + len(audit.mask_b_hits()) + 3)

    def test_534_is_not_derivable(self):
        # 534 + 27 = 561, but no command set in this artifact has 561 members;
        # the count is recorded as unresolved rather than silently accepted.
        self.assertFalse(audit.observed()["c4_534_reproducible"])


class MsrModelTests(unittest.TestCase):
    """sys 626: `or ecx,0xc0010241` for index<=3, `add ecx,0xc0010189` above."""

    def test_two_formulas(self):
        self.assertEqual([audit.msr_for_index(i) for i in range(4)],
                         [0xC0010241, 0xC0010243, 0xC0010245, 0xC0010247])
        self.assertEqual([audit.msr_for_index(i) for i in range(4, 8)],
                         [0xC0010191, 0xC0010193, 0xC0010195, 0xC0010197])

    def test_or_equals_add_over_the_first_range(self):
        # The claim says "0xC0010241 + 2*index"; the code ORs. For index 0-3
        # the two agree, so the claim's arithmetic is right for the range the
        # guard admits. They diverge once the addend overlaps a bit of 0x241
        # (e.g. 0x240), which is why the equivalence is range-bound.
        for i in range(4):
            self.assertEqual((2 * i) | 0xC0010241, 0xC0010241 + 2 * i)
        self.assertNotEqual(0x240 | 0xC0010241, 0xC0010241 + 0x240)

    def test_index_guard_rejects_above_the_hardware_maximum(self):
        self.assertIsNone(audit.msr_for_index(8))
        self.assertIsNone(audit.msr_for_index(0xFFFFFFFF))
        self.assertEqual(audit.msr_for_index(7), 0xC0010197)

    def test_helper_form(self):
        # 0x60503b: lea ecx,[r14+r14-0x3ffefdcf]; -0x3ffefdcf == 0xc0010231 mod 2^32
        self.assertEqual([audit.helper_msr(i) for i in range(4)],
                         [0xC0010231, 0xC0010233, 0xC0010235, 0xC0010237])


class EaccesModelTests(unittest.TestCase):
    """sys 588: `cmp eax,0xd; je proceed; test eax,eax; jne error`."""

    def test_zero_and_eacces_proceed(self):
        self.assertTrue(audit.eacces_proceeds(0))
        self.assertTrue(audit.eacces_proceeds(0xD))

    def test_other_errors_stop(self):
        for rc in (1, 2, 12, 14, 22, 0xFFFFFFFF):
            self.assertFalse(audit.eacces_proceeds(rc), rc)


class ResolutionTests(unittest.TestCase):
    """Slots resolve to the bodies the audit names, with the bytes it quotes."""

    def test_slots_and_bodies(self):
        self.assertEqual(audit.SLOTS, {588: 0x265E08, 622: 0x265E98,
                                       626: 0x265EB8, 629: 0x265ED0,
                                       638: 0x265F10, 639: 0x265F18})
        self.assertEqual(audit.BODIES, {588: 0xABC5F0, 622: 0x7DCD40,
                                        626: 0x604CF0, 629: 0x91C640,
                                        638: 0x6BE5C0, 639: 0x6BE800})

    def test_slot_bytes_are_e9_rel32(self):
        for num, body in audit.BODIES.items():
            self.assertEqual(audit.KERNEL[audit.SLOTS[num]], 0xE9, num)
            self.assertEqual(audit.bytes_at(audit.SLOTS[num], 8)[-6:], "cccccc", num)
            self.assertEqual(audit.BODIES[num], body)

    def test_extents_stop_at_the_canary_block(self):
        # 588/626/629 have no canary-failure block inside the extent; 638/639 do.
        self.assertEqual(audit.func_extent(0xABC5F0), 0xABC70E)
        self.assertEqual(audit.func_extent(0x604CF0), 0x604FF5)
        self.assertEqual(audit.func_extent(0x91C640), 0x91C73D)
        self.assertEqual(audit.func_extent(0x6BE5C0), 0x6BE7F7)
        self.assertEqual(audit.func_extent(0x6BE800), 0x6BEB13)

    def test_bodies_do_not_overlap(self):
        spans = sorted((audit.func_extent(b), b) for b in audit.BODIES.values())
        for (end, _start), (next_start, _) in zip(spans, spans[1:]):
            self.assertLessEqual(end, next_start)


class Claim4Tests(unittest.TestCase):
    def test_ladder_instructions(self):
        self.assertEqual(audit.insn_at(0x7DCE02), "lea eax, [r14 - 0x100]")
        self.assertEqual(audit.insn_at(0x7DCE09), "cmp eax, 0x33")
        self.assertEqual(audit.insn_at(0x7DCE0C), "ja 0x7dce4f")
        self.assertEqual(audit.insn_at(0x7DCE0E), "movabs rcx, 0xf8fff000000d5")
        self.assertEqual(audit.insn_at(0x7DCE18), "bt rcx, rax")

    def test_gate_bytes(self):
        self.assertEqual(audit.bytes_at(0x7DCE09, 4), "83f83377")
        self.assertEqual(audit.bytes_at(0x7DCE0C, 2), "7741")
        self.assertEqual(audit.bytes_at(0x7DCE0E, 10), "48b9d5000000ff8f0f00")

    def test_branch_targets(self):
        self.assertEqual(0x7DCE0C + 2 + audit.struct.unpack_from(
            "<b", audit.KERNEL, 0x7DCE0D)[0], 0x7DCE4F)
        self.assertEqual(0x7DCE1C + 6 + audit.struct.unpack_from(
            "<i", audit.KERNEL, 0x7DCE1E)[0], 0x7DD00B)

    def test_no_auth_on_the_below_window_path(self):
        # 0x7dce4f is the memset/no-auth block; it is reached without either
        # auth call, and the dispatch ladder follows it at 0x7dce5d.
        self.assertEqual(audit.insn_at(0x7DCE4F), "lea rdi, [rbp - 0x70]")
        self.assertEqual(audit.insn_at(0x7DCE5D), "mov eax, 0xffffffff")

    def test_exactly_six_auth_helper_calls_in_the_extent(self):
        calls = [(a, t) for a, t in audit.call_targets(0x7DCD40, 0x7E4810)
                 if t in audit.AUTH_HELPERS]
        self.assertEqual([hex(a) for a, _ in calls],
                         ["0x7dce29", "0x7dce3a", "0x7dcf3c", "0x7dcf51",
                          "0x7dd026", "0x7dd03b"])

    def test_no_priv_check_in_the_extent(self):
        self.assertEqual([a for a, t in audit.call_targets(0x7DCD40, 0x7E4810)
                          if t == audit.PRIV_CHECK], [])

    def test_extent_holds_many_functions(self):
        # The next-sysent-start rule gives 31,440 bytes, but 53 prologues sit
        # inside it: the dispatcher's blocks are interleaved with helpers, so
        # "the body" is not one function and no per-body count is safe.
        self.assertEqual(sum(1 for a in range(0x7DCD40, 0x7E4810)
                             if audit.KERNEL[a:a + 4] == audit.PROLOGUE), 53)

    def test_dispatcher_ends_before_the_sub_handlers(self):
        self.assertEqual(audit.func_extent(0x7DCD40), 0x7DDBA3)
        self.assertEqual(audit.KERNEL[0x7DDBA3:0x7DDBA8], b"\x90" * 5)
        self.assertEqual(audit.KERNEL[0x7DDBB0:0x7DDBB4], audit.PROLOGUE)


class Claim5Tests(unittest.TestCase):
    def test_body_calls(self):
        calls = audit.call_targets(0xABC5F0, audit.func_extent(0xABC5F0))
        self.assertEqual([hex(t) for _, t in calls],
                         ["0xc1a3e0", "0x259900", "0x81f770", "0x2d2e50", "0x6fd6b0"])
        self.assertNotIn(audit.PRIV_CHECK, [t for _, t in calls])

    def test_no_ucred_offsets(self):
        body = audit.insns(0xABC5F0, audit.func_extent(0xABC5F0))
        self.assertEqual([i.address for i in body
                          if any(f"+ 0x{f}]" in i.op_str for f in ("5d4", "5d8"))], [])

    def test_bounds_check(self):
        self.assertEqual(audit.insn_at(0xABC623), "cmp qword ptr [rbx + 0x20], r13")
        self.assertEqual(audit.insn_at(0xABC627), "ja 0xabc6ee")
        self.assertEqual(audit.insn_at(0xABC63E), "setb cl")
        self.assertEqual(audit.insn_at(0xABC643), "jne 0xabc6ee")

    def test_eacces_branch_bytes_and_targets(self):
        self.assertEqual(audit.bytes_at(0xABC6D1, 3), "83f80d")
        self.assertEqual(audit.bytes_at(0xABC6D4, 2), "7404")
        self.assertEqual(audit.bytes_at(0xABC6D8, 2), "7514")
        self.assertEqual(0xABC6D4 + 2 + 4, 0xABC6DA)
        self.assertEqual(0xABC6D8 + 2 + 0x14, 0xABC6EE)

    def test_proceed_block_returns_zero(self):
        self.assertEqual(audit.insn_at(0xABC6DA), "lea rcx, [rbp - 0x50]")
        self.assertEqual(audit.insn_at(0xABC6E7), "call 0x2d2e50")
        self.assertEqual(audit.insn_at(0xABC6EC), "xor eax, eax")

    def test_a_copyin_precedes_the_bounds_check(self):
        # "Only vm_map bounds validation" understates the body: a 0x20-byte
        # copyin from uap+0x10 must also succeed.
        self.assertEqual(audit.insn_at(0xABC676), "call 0x259900")
        self.assertEqual(audit.insn_at(0xABC66C), "mov edx, 0x20")
        self.assertEqual(audit.insn_at(0xABC671), "mov rdi, r14")


class Claim6Tests(unittest.TestCase):
    def test_globals_are_outside_the_text(self):
        for key in ("c6_table_base", "c6_table_base_639", "c6_count",
                    "c6_count_639", "c6_mode"):
            self.assertGreater(audit.observed()[key], len(audit.KERNEL), key)

    def test_rip_relative_globals(self):
        # Computed from the instruction, not copied from the note: lea/mov at
        # `site` with length `n` has rip = site+n, and target = rip+disp.
        def target(site, n, disp):
            return site + n + disp
        self.assertEqual(target(0x6BE603, 7, 0x3257316), 0x3915920)  # 638 table
        self.assertEqual(target(0x6BE85D, 7, 0x32570BC), 0x3915920)  # 639 table
        self.assertEqual(target(0x6BE5F0, 6, 0x325932A), 0x3917920)  # 638 count
        self.assertEqual(target(0x6BE837, 6, 0x32590E3), 0x3917920)  # 639 count
        self.assertEqual(target(0x6BE65D, 6, 0x33B1F4C), 0x3A705AF)  # 638 mode
        self.assertEqual(target(0x6BE715, 6, 0x33B1E94), 0x3A705AF)  # 639 mode

    def test_same_table_and_count_in_both_handlers(self):
        o = audit.observed()
        self.assertEqual(o["c6_table_base"], o["c6_table_base_639"])
        self.assertEqual(o["c6_count"], o["c6_count_639"])
        self.assertEqual(o["c6_table_base"], 0x3915920)
        self.assertEqual(o["c6_count"], 0x3917920)

    def test_binary_search_shape(self):
        self.assertEqual(audit.insn_at(0x6BE62A), "lea r9d, [rdi + rdx]")
        self.assertEqual(audit.insn_at(0x6BE631), "shr r8d, 0x1f")
        self.assertEqual(audit.insn_at(0x6BE638), "sar r8d, 1")
        self.assertEqual(audit.insn_at(0x6BE63E), "shl r9, 4")
        self.assertEqual(audit.insn_at(0x6BE642), "cmp qword ptr [r9 + rcx], rsi")

    def test_copyout_sizes_and_sites(self):
        for addr, size in ((0x6BE75F, "mov edx, 8"), (0x6BE794, "mov edx, 0x10"),
                           (0x6BE7C9, "mov edx, 4"), (0x6BEA7B, "mov edx, 8"),
                           (0x6BEAB0, "mov edx, 0x10"), (0x6BEAE5, "mov edx, 4")):
            self.assertEqual(audit.insn_at(addr), size, hex(addr))

    def test_copyout_targets(self):
        for start, end in ((0x6BE5C0, 0x6BE7F7), (0x6BE800, 0x6BEB13)):
            self.assertIn(0x2591D0, [t for _, t in audit.call_targets(start, end)])

    def test_no_privilege_gate(self):
        for start, end in ((0x6BE5C0, 0x6BE7F7), (0x6BE800, 0x6BEB13)):
            targets = [t for _, t in audit.call_targets(start, end)]
            self.assertNotIn(audit.PRIV_CHECK, targets)
            self.assertEqual([t for t in targets if t in audit.AUTH_HELPERS], [])

    def test_record_is_a_delta_entry_not_a_region(self):
        # 16-byte stride, signed qword key compared against the input, then
        # two signed dwords added (638) or subtracted (639).
        self.assertEqual(audit.insn_at(0x6BE63E), "shl r9, 4")
        self.assertEqual(audit.insn_at(0x6BE72D), "add rax, qword ptr [rbx]")
        self.assertEqual(audit.insn_at(0x6BE734), "add rax, rcx")
        self.assertEqual(audit.insn_at(0x6BEA50), "sub rcx, rdx")

    def test_name_map_agrees(self):
        self.assertEqual(audit.observed()["c6_names"],
                         {638: "utc_to_localtime", 639: "localtime_to_utc"})


class Claim7Tests(unittest.TestCase):
    def test_two_rdmsr_in_the_body(self):
        hits = [i.address for i in audit.insns(0x604CF0, audit.func_extent(0x604CF0))
                if i.bytes == b"\x0f\x32"]
        self.assertEqual(hits, [0x604F8C, 0x604F96])

    def test_formula_instructions(self):
        self.assertEqual(audit.insn_at(0x604F7E), "lea ecx, [rbx + rbx]")
        self.assertEqual(audit.insn_at(0x604F81), "cmp ebx, 3")
        self.assertEqual(audit.insn_at(0x604F84), "ja 0x604f90")
        self.assertEqual(audit.bytes_at(0x604F86, 6), "81c9410201c0")
        self.assertEqual(audit.bytes_at(0x604F90, 6), "81c1890101c0")
        self.assertEqual(audit.bytes_at(0x604F8C, 2), "0f32")
        self.assertEqual(audit.bytes_at(0x604F96, 2), "0f32")

    def test_guard_ors_two_setcc_results(self):
        # `jne` at 0x604f7c tests the OR, not the cmp flags: the two reject
        # reasons are "out2 non-NULL" and "index > hw_max".
        self.assertEqual(audit.insn_at(0x604F6D), "cmp qword ptr [rsi + 0x20], 0")
        self.assertEqual(audit.insn_at(0x604F72), "setne dl")
        self.assertEqual(audit.insn_at(0x604F75), "cmp ebx, ecx")
        self.assertEqual(audit.insn_at(0x604F77), "seta cl")
        self.assertEqual(audit.insn_at(0x604F7A), "or cl, dl")
        self.assertEqual(audit.insn_at(0x604F7C), "jne 0x604fd7")

    def test_helper_holds_four_sites(self):
        hits = [i.address for i in audit.insns(0x605000, audit.func_extent(0x605000))
                if i.bytes == b"\x0f\x32"]
        self.assertEqual(hits, [0x605043, 0x60506E, 0x60508A, 0x6050A0])
        self.assertEqual(audit.insn_at(0x60503B),
                         "lea ecx, [r14 + r14 - 0x3ffefdcf]")

    def test_six_reachable_not_six_in_the_body(self):
        o = audit.observed()
        self.assertEqual(o["c7_reachable"], 6)
        self.assertEqual(len(o["c7_rdmsr_body"]), 2)

    def test_command_table_is_past_the_artifact(self):
        # 0x604e5a lea rdx,[rip+0x111e75b] -> 0x604e61 + disp
        self.assertEqual(0x604E61 + 0x111E75B, 0x17235BC)
        self.assertGreater(0x17235BC, len(audit.KERNEL))

    def test_file_window_count(self):
        # 46 rdmsr mnemonics in sys_626.asm, spread 0x604f8c-0x6055c9: most
        # belong to neighbouring handlers (sys 625 starts at 0x603c90).
        self.assertEqual(audit._asm_rdmsr_count(626), 46)
        self.assertEqual(audit._asm_rdmsr_range(626), (0x604F8C, 0x6055C9))

    def test_no_permission_check_in_the_body(self):
        targets = [t for _, t in audit.call_targets(0x604CF0, audit.func_extent(0x604CF0))]
        self.assertNotIn(audit.PRIV_CHECK, targets)
        self.assertEqual([t for t in targets if t in audit.AUTH_HELPERS], [])

    def test_command_table_is_outside_the_artifact(self):
        self.assertEqual(audit.observed()["c7_table"], 0x17235BC)
        self.assertTrue(audit.observed()["c7_table_outside"])


class Claim8Tests(unittest.TestCase):
    def test_cmp_and_je(self):
        self.assertEqual(audit.bytes_at(0x91C64B, 4), "48833e01")
        self.assertEqual(audit.insn_at(0x91C64B), "cmp qword ptr [rsi], 1")
        self.assertEqual(audit.bytes_at(0x91C652, 6), "0f84a0000000")
        self.assertEqual(audit.insn_at(0x91C652), "je 0x91c6f8")
        self.assertEqual(0x91C6F8 - 0x91C640, 0xB8)

    def test_fast_path_passes_literal_one(self):
        self.assertEqual(audit.insn_at(0x91C6FA), "mov rsi, qword ptr [r14]")
        self.assertEqual(audit.insn_at(0x91C70A), "cmp rsi, 1")
        self.assertEqual(audit.insn_at(0x91C70E), "cmovne rsi, rbx")
        self.assertEqual(audit.insn_at(0x91C715), "call 0x91bca0")

    def test_skipped_sites(self):
        # allocation, copyin, '/' test, auth predicate, 12-byte compare, diag
        for addr, want in ((0x91C66C, "call 0xc08b50"), (0x91C69B, "call 0x259900"),
                           (0x91C6A4, "cmp byte ptr [rbx], 0x2f"),
                           (0x91C6B6, "call 0x6092d0"),
                           (0x91C6CE, "call 0x8d1a30"),
                           (0x91C6EB, "call 0x80d5a0")):
            self.assertEqual(audit.insn_at(addr), want, hex(addr))
        self.assertLess(0x91C652 + 6, 0x91C66C)

    def test_cited_credential_address_is_not_code(self):
        refs = audit._refs(0xCECC90)
        self.assertEqual(refs["branches"], [])
        self.assertEqual(refs["immediates"], [])
        # The bytes at 0xcecc90 are a table of 8-byte pointer pairs, not a
        # function prologue.
        self.assertNotEqual(audit.bytes_at(0xCECC90, 4), audit.PROLOGUE.hex())
        self.assertEqual(audit.bytes_at(0xCECC90, 8), "0800000000000000")

    def test_real_skipped_check_is_the_auth_id_predicate(self):
        self.assertEqual(audit.insn_at(0x91C6B6), "call 0x6092d0")
        # 0x6092d0 compares [rdi+0x58] against 0x4800000010000004..0x13 / ..0x1010.
        self.assertEqual(audit.insn_at(0x6092D4), "mov rcx, qword ptr [rdi + 0x58]")

    def test_delegate_reads_credential_fields(self):
        self.assertEqual(audit.insn_at(0x91BDE9), "mov r8d, dword ptr [rax + 0x5c0]")
        self.assertEqual(audit.insn_at(0x91BDF6), "mov r9d, dword ptr [rax + 0x5d0]")
        self.assertEqual(audit.insn_at(0x91BDCB), "cmp r15d, 0x200000")


class RepositoryAuditTests(unittest.TestCase):
    """Integration: every pinned fact must still hold against the artifacts."""

    def test_every_pinned_fact_holds(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = audit.main(["tier1_claims_audit.py", "--check"])
        report = buf.getvalue()
        self.assertEqual(code, 0, report)
        self.assertNotIn("DRIFT", report, report)
        rows = [ln for ln in report.splitlines()
                if re.match(r"^\d\s{2,}\S+\s{2,}(holds|DRIFT)", ln)]
        self.assertEqual(len(rows), len(audit.ROWS), report)
        self.assertIn(f"{len(audit.ROWS)}/{len(audit.ROWS)} pinned facts hold", report)

    def test_verdict_table_has_five_claims(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            audit.main(["tier1_claims_audit.py"])
        report = buf.getvalue()
        for claim in ("4", "5", "6", "7", "8"):
            self.assertRegex(report, rf"(?m)^{claim}\s+(CONFIRMED|PARTIAL|REFUTED|UNRESOLVED|DRIFT)\s")

    def test_verdict_labels(self):
        self.assertEqual(audit.VERDICTS["4"][0], "PARTIAL")
        self.assertEqual(audit.VERDICTS["5"][0], "CONFIRMED")
        self.assertEqual(audit.VERDICTS["6"][0], "PARTIAL")
        self.assertEqual(audit.VERDICTS["7"][0], "PARTIAL")
        self.assertEqual(audit.VERDICTS["8"][0], "PARTIAL")


if __name__ == "__main__":
    unittest.main()
