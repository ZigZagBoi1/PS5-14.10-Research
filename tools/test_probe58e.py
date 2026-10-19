#!/usr/bin/env python3
"""Pins for probe 58e and docs/THR_CREATE_430_CONTEXT.md.

Two jobs:

1. Re-derive every 13.60 address the note cites from ``docs/dumps_13.60/`` and
   fail if the bytes move. The note's whole argument is byte-level, so the
   bytes are the test.
2. Execute ``probes/phase15_native_sysent/58e_thr_create_ucontext.lua`` under a
   stub loader (Lua 5.1 via ``lupa``) and assert the exact syscall number,
   argument shape, context-field writes and id-oracle readbacks.

Offline and read-only: no console is contacted and no capture is produced.
"""

import re
import struct
import unittest
from pathlib import Path

import lupa

ROOT = Path(__file__).resolve().parent.parent
DUMPS = ROOT / "docs" / "dumps_13.60"
KERNEL_TEXT = DUMPS / "kernel_text.bin"
KERNEL_DATA = DUMPS / "kernel_data.bin"
SYSENT_INDEX = DUMPS / "sysent_index.json"
PROBE = ROOT / "probes" / "phase15_native_sysent" / "58e_thr_create_ucontext.lua"
NOTE = ROOT / "docs" / "THR_CREATE_430_CONTEXT.md"

KERNEL_BASE = 0xFFFFFFFF8A9C0000
DATA_RVA = 0x1000000  # kernel_data.bin's first RVA, from kernel_dump_manifest.json

SLOT_430 = 0x265C10
SLOT_455 = 0x265C50
BODY_430 = 0x437CF0
BODY_455 = 0x437DE0
WORKER = 0x437F30
HELPER_430 = 0x437D90
HELPER_455 = 0x438280
MCTX_CONSUMER = 0xA0AC60
OPS_430 = 0x265FC8
OPS_455 = 0x265FD0
CFI_TOP = 0x267008
CFI_MAX_INDEX = 0x3A5
COPYIN = 0x259280
COPYOUT_QWORD = 0x259720


def read_text():
    return KERNEL_TEXT.read_bytes()


def read_data():
    return KERNEL_DATA.read_bytes()


def u32(blob, off):
    return struct.unpack_from("<I", blob, off)[0]


def u64(blob, off):
    return struct.unpack_from("<Q", blob, off)[0]


def rel32(blob, off):
    """Resolve a rel32 branch at ``off`` (E8/E9 or a 0F 8x jcc).

    The sysent slot RVAs are already absolute, so the same arithmetic applies
    to a trampoline and to an in-body branch.
    """
    if blob[off] in (0xE8, 0xE9):
        rel = struct.unpack_from("<i", blob, off + 1)[0]
        return (off + 5 + rel) & 0xFFFFFFFFFFFFFFFF
    if blob[off] == 0x0F and 0x80 <= blob[off + 1] <= 0x8F:
        rel = struct.unpack_from("<i", blob, off + 2)[0]
        return (off + 6 + rel) & 0xFFFFFFFFFFFFFFFF
    raise AssertionError("not a rel32 branch at " + hex(off))


def slot_target(off):
    return rel32(read_text(), off)


class ArtifactPinTests(unittest.TestCase):
    """Every address the note cites, re-derived from the committed dump."""

    @classmethod
    def setUpClass(cls):
        cls.text = read_text()
        cls.data = read_data()

    def test_slot_430_is_a_trampoline_to_the_decoded_body(self):
        self.assertEqual(self.text[SLOT_430:SLOT_430 + 8],
                         bytes.fromhex("e9db201d00cccccc"))
        self.assertEqual(slot_target(SLOT_430), BODY_430)

    def test_slot_455_is_a_trampoline_to_its_own_body(self):
        self.assertEqual(self.text[SLOT_455:SLOT_455 + 8],
                         bytes.fromhex("e98b211d00cccccc"))
        self.assertEqual(slot_target(SLOT_455), BODY_455)

    def test_body_430_head_bytes(self):
        # push rbp; mov rbp,rsp; push r15/r14/r12/rbx; sub rsp,0x520
        self.assertEqual(self.text[BODY_430:BODY_430 + 18],
                         bytes.fromhex("554889e5415741564154534881ec20050000"))

    def test_body_430_ends_before_455(self):
        # ret at 0x437d85, __stack_chk_fail path at 0x437d86, ud2 at 0x437d8b
        self.assertEqual(self.text[0x437D85], 0xC3)
        self.assertEqual(self.text[0x437D8B:0x437D8D], bytes.fromhex("0f0b"))
        self.assertEqual(slot_target(SLOT_430) + 0xF0, BODY_455)

    def test_helper_430_is_a_separate_function_inside_430s_extent(self):
        # The seam: 0x437d90 is not reachable by fallthrough from 430's entry.
        self.assertEqual(self.text[0x437D8D:0x437D90], b"\x90\x90\x90")
        self.assertEqual(self.text[HELPER_430:HELPER_430 + 6],
                         bytes.fromhex("554889e54156"))

    def test_430_reads_arg0_and_arg1_only(self):
        # mov r15,[rsi] (arg0) at 0x437d19; mov rax,[r14+8] (arg1) at 0x437d49.
        self.assertEqual(self.text[0x437D19:0x437D1C], bytes.fromhex("4c8b3e"))
        self.assertEqual(self.text[0x437D49:0x437D4D], bytes.fromhex("498b4608"))

    def test_430_copies_in_exactly_0x500_bytes(self):
        self.assertEqual(self.text[0x437D38:0x437D3D],
                         bytes.fromhex("ba00050000"))  # mov edx,0x500
        self.assertEqual(rel32(self.text, 0x437D40), COPYIN)

    def test_copyin_is_labelled_before_the_call(self):
        # The 3-arg call before the copyin passes the literal "copyin".
        lea = 0x437D25
        disp = struct.unpack_from("<i", self.text, lea + 3)[0]
        string_rva = lea + 7 + disp
        self.assertEqual(string_rva, 0x1397F3D)
        self.assertEqual(self.data[string_rva - DATA_RVA:
                                   string_rva - DATA_RVA + 7], b"copyin\x00")

    def test_copyin_primitive_copies_user_to_kernel(self):
        # 0x259280 masks the source, stac/rep movsq, clac: direction is user->kernel.
        body = self.text[COPYIN:COPYIN + 0xB0]
        self.assertIn(bytes.fromhex("0f01cb"), body)  # stac
        self.assertIn(bytes.fromhex("0f01ca"), body)  # clac
        self.assertIn(bytes.fromhex("f348a5"), body)  # rep movsq

    def test_arg1_is_stored_into_the_frame_slot_at_ctx_plus_0x500(self):
        # mov [rbp-0x40],rax at 0x437d63; ctx base is rbp-0x540, so the slot is
        # ctx+0x500 and the helper reads it back at 0x437d9a.
        self.assertEqual(self.text[0x437D63:0x437D67], bytes.fromhex("488945c0"))
        self.assertEqual(self.text[0x437D9A:0x437DA1],
                         bytes.fromhex("488bbe00050000"))  # mov rdi,[rsi+0x500]

    def test_ops_pointer_is_0x265fc8_and_calls_the_shared_worker(self):
        lea = 0x437D4D
        disp = struct.unpack_from("<i", self.text, lea + 3)[0]
        self.assertEqual(lea + 7 + disp, OPS_430)
        self.assertEqual(rel32(self.text, 0x437D67), WORKER)

    def test_455_uses_the_next_ops_entry_and_the_same_worker(self):
        lea = 0x437F01
        disp = struct.unpack_from("<i", self.text, lea + 3)[0]
        self.assertEqual(lea + 7 + disp, OPS_455)
        self.assertEqual(rel32(self.text, 0x437F19), WORKER)
        self.assertEqual(OPS_455 - OPS_430, 8)

    def test_ops_table_entries_resolve_to_the_two_helpers(self):
        self.assertEqual(self.text[OPS_430:OPS_430 + 8],
                         bytes.fromhex("e9c31d1d00cccccc"))
        self.assertEqual(slot_target(OPS_430), HELPER_430)
        self.assertEqual(self.text[OPS_455:OPS_455 + 8],
                         bytes.fromhex("e9ab221d00cccccc"))
        self.assertEqual(slot_target(OPS_455), HELPER_455)

    def test_helper_copyout_of_the_id_then_tail_call(self):
        self.assertEqual(rel32(self.text, 0x437DB0), COPYOUT_QWORD)
        self.assertEqual(rel32(self.text, 0x437DD1), MCTX_CONSUMER)

    def test_cfi_range_check_is_unsigned_and_bounds_the_ops_table(self):
        lea = 0x4380A7
        disp = struct.unpack_from("<i", self.text, lea + 3)[0]
        self.assertEqual(lea + 7 + disp, CFI_TOP)
        self.assertEqual(self.text[0x4380B1:0x4380B5], bytes.fromhex("48c1c803"))
        self.assertEqual(self.text[0x4380B5:0x4380BB], bytes.fromhex("483da5030000"))
        self.assertEqual(self.text[0x4380BB:0x4380C1], bytes.fromhex("0f87a9010000"))

        def accepted(ops):
            rax = (CFI_TOP - ops) & 0xFFFFFFFFFFFFFFFF
            rax = ((rax >> 3) | (rax << 61)) & 0xFFFFFFFFFFFFFFFF  # ror rax,3
            return rax <= CFI_MAX_INDEX  # ja rejects strictly above

        self.assertTrue(accepted(OPS_430))
        self.assertTrue(accepted(OPS_455))
        self.assertTrue(accepted(CFI_TOP))
        self.assertTrue(accepted(CFI_TOP - CFI_MAX_INDEX * 8))
        self.assertFalse(accepted(CFI_TOP - (CFI_MAX_INDEX + 1) * 8))
        self.assertFalse(accepted(0x265000))

    def test_mcontext_magic_check(self):
        self.assertEqual(self.text[0xA0AC8C:0xA0AC97],
                         bytes.fromhex("4881bec800000080040000"))
        self.assertEqual(rel32(self.text, 0xA0AC97), 0xA0AFEB)

    def test_mcontext_flags_check_is_a_maximum_of_7(self):
        self.assertEqual(self.text[0xA0AC9D:0xA0ACA4],
                         bytes.fromhex("448b9690000000"))  # mov r10d,[rsi+0x90]
        self.assertEqual(self.text[0xA0ACA4:0xA0ACA8], bytes.fromhex("4183fa07"))
        self.assertEqual(self.text[0xA0ACA8:0xA0ACAE], bytes.fromhex("0f873d030000"))

        def rejected(flags):
            return flags > 7  # ja rejects strictly above

        self.assertFalse(rejected(0))
        self.assertFalse(rejected(7))
        self.assertTrue(rejected(8))

    def test_mcontext_type_field_accepts_two_values(self):
        self.assertEqual(self.text[0xA0AE03:0xA0AE0A],
                         bytes.fromhex("488b96d0000000"))  # mov rdx,[rsi+0xd0]
        self.assertEqual(self.text[0xA0AE0A:0xA0AE11],
                         bytes.fromhex("4881fa00000100"))
        self.assertEqual(rel32(self.text, 0xA0AE11), 0xA0AE9E)
        self.assertEqual(self.text[0xA0AE17:0xA0AE1E],
                         bytes.fromhex("4881fa02000100"))
        self.assertEqual(rel32(self.text, 0xA0AE1E), 0xA0AFEB)

    def test_mcontext_subtype_field_accepts_0x20000_to_0x20002(self):
        self.assertEqual(self.text[0xA0AE24:0xA0AE2B],
                         bytes.fromhex("4c8b96d8000000"))  # mov r10,[rsi+0xd8]
        self.assertEqual(self.text[0xA0AE2B:0xA0AE32],
                         bytes.fromhex("498d92fffffdff"))  # lea rdx,[r10-0x20001]
        self.assertEqual(self.text[0xA0AE32:0xA0AE36], bytes.fromhex("4883fa02"))
        self.assertEqual(self.text[0xA0AE36:0xA0AE38], bytes.fromhex("733e"))
        self.assertEqual(self.text[0xA0AE76:0xA0AE7D],
                         bytes.fromhex("4981fa00000200"))

        def route(value):
            rdx = (value - 0x20001) & 0xFFFFFFFFFFFFFFFF
            if rdx >= 2:            # jae 0xa0ae76
                return "alt" if value == 0x20000 else "reject"
            return "main"

        self.assertEqual(route(0x20001), "main")
        self.assertEqual(route(0x20002), "main")
        self.assertEqual(route(0x20000), "alt")
        self.assertEqual(route(0x20003), "reject")
        self.assertEqual(route(0), "reject")

    def test_stack_guard_global_is_shared_with_455(self):
        for lea in (0x437D02, 0x437DF4):
            disp = struct.unpack_from("<i", self.text, lea + 3)[0]
            self.assertEqual(lea + 7 + disp, 0x391C310)

    def test_430_never_reads_the_third_uap_slot(self):
        # Only two uap loads exist in the entry: [rsi] and [r14+8].
        body = self.text[BODY_430:0x437D90]
        loads = [(0x437CF0 + m.start(), body[m.start():m.start() + 4])
                 for m in re.finditer(rb"[\x48\x49\x4c\x4d]\x8b", body)]
        self.assertEqual([addr for addr, _ in loads],
                         [0x437D11, 0x437D19, 0x437D1D, 0x437D49, 0x437D6C])
        self.assertEqual(self.text[0x437D19:0x437D1C], bytes.fromhex("4c8b3e"))
        self.assertEqual(self.text[0x437D49:0x437D4D], bytes.fromhex("498b4608"))

    def test_proc_c81_gate_selects_the_flags_3_variant(self):
        self.assertEqual(self.text[0xA0ACD6:0xA0ACDD],
                         bytes.fromhex("80ba810c000000"))  # cmp byte [rdx+0xc81],0
        self.assertEqual(rel32(self.text, 0xA0ACDD), 0xA0AD93)
        self.assertEqual(self.text[0xA0AD93:0xA0AD97], bytes.fromhex("4183fa03"))
        self.assertEqual(rel32(self.text, 0xA0AD97), 0xA0AFEB)

    def test_stack_size_check_only_exists_on_the_flags_ge_4_path(self):
        self.assertEqual(self.text[0xA0ACEB:0xA0ACEF], bytes.fromhex("4183fa04"))
        self.assertEqual(rel32(self.text, 0xA0ACEF), 0xA0AE03)
        self.assertEqual(self.text[0xA0AD02:0xA0AD09],
                         bytes.fromhex("4881c100feffff"))  # add rcx,-0x200
        self.assertEqual(self.text[0xA0AD09:0xA0AD0C], bytes.fromhex("4839ca"))
        self.assertEqual(self.text[0xA0AD0C:0xA0AD12], bytes.fromhex("0f87d9020000"))

    def test_note_cites_the_pinned_addresses(self):
        text = NOTE.read_text(encoding="utf-8")
        for token in ("0x437cf0", "0x437d90", "0x437f30", "0xa0ac60",
                      "0x265fc8", "0x265fd0", "0x265c10", "0x480",
                      "0x10000", "0x10002"):
            self.assertIn(token, text.lower(), token)


# --- stub loader -----------------------------------------------------------
#
# The probe only needs the loader surface it uses: syscall.pipe with a __call
# metatable, memory.alloc/read/write, uint64, and print. read_qword returns the
# repo's uint64-shaped table (h/l) so get_hi_lo formats deterministically.

SETUP_LUA = r"""
syscall = { pipe = { syscall_no = 0 } }
setmetatable(syscall.pipe, {
    __call = function(self, a, b, c, d, e, f)
        return __dispatch(self.syscall_no, a, b, c, d, e, f)
    end,
})
uint64 = function(x) return x end
memory = {
    alloc = function(n) return __alloc(n) end,
    read_dword = function(a) return __read_dword(a) end,
    read_qword = function(a) return __read_qword(a) end,
    write_dword = function(a, v) return __write_dword(a, v) end,
    write_qword = function(a, v) return __write_qword(a, v) end,
}
print = function(...)
    local parts = {}
    for i = 1, select('#', ...) do parts[i] = tostring(select(i, ...)) end
    __capture(table.concat(parts, '\t'))
end
"""


class MockLoader:
    """Records syscalls and models the two behaviours the probe must survive."""

    def __init__(self, runtime, succeed):
        self.runtime = runtime
        self.succeed = succeed
        self.bytes = {}
        self.calls = []
        self.allocations = []
        self.next_addr = 0x30000000

    def alloc(self, n):
        addr = self.next_addr
        self.allocations.append((addr, int(n)))
        self.next_addr += 0x1000
        return addr

    def read(self, addr, size):
        addr = int(addr)
        value = 0
        for i in range(size):
            value |= self.bytes.get(addr + i, 0) << (8 * i)
        return value

    def write(self, addr, value, size):
        addr = int(addr)
        value = int(value) & ((1 << (8 * size)) - 1)
        for i in range(size):
            self.bytes[addr + i] = (value >> (8 * i)) & 0xFF

    def dispatch(self, num, a, b, c, d, e, f):
        num, a, b, c = int(num), int(a), int(b), int(c)
        self.calls.append((num, a, b, c))
        if num != 430:
            return -1
        if a == 0:
            return -1  # copyin from NULL faults before anything else
        if self.succeed and b != 0:
            self.write(b, 0x1234, 8)  # id copyout, then success
            return 0
        return -1


def run_probe(succeed):
    captured = []
    runtime = lupa.LuaRuntime(unpack_returned_tuples=True)
    globals_ = runtime.globals()
    loader = MockLoader(runtime, succeed)

    def read_qword(addr):
        value = loader.read(addr, 8)
        return runtime.table(h=(value >> 32) & 0xFFFFFFFF, l=value & 0xFFFFFFFF)

    globals_["__capture"] = captured.append
    globals_["__alloc"] = loader.alloc
    globals_["__read_dword"] = lambda a: loader.read(a, 4)
    globals_["__read_qword"] = read_qword
    globals_["__write_dword"] = lambda a, v: loader.write(a, v, 4)
    globals_["__write_qword"] = lambda a, v: loader.write(a, v, 8)
    globals_["__dispatch"] = loader.dispatch

    runtime.execute(SETUP_LUA)
    source = PROBE.read_text(encoding="utf-8")
    runtime.execute(source)
    return loader, "\n".join(captured) + "\n"


class ProbeSourceTests(unittest.TestCase):
    def test_probe_is_marked_prepared_not_run(self):
        source = PROBE.read_text(encoding="utf-8")
        self.assertIn("PREPARED — NOT RUN", source)
        self.assertIn("CRASH_CLASS: RISKY", source)

    def test_probe_uses_lua_51_safe_constructs(self):
        source = PROBE.read_text(encoding="utf-8")
        self.assertNotIn("goto", source)
        self.assertIn("pcall(function()", source)
        self.assertIn("uint64(", source)
        self.assertIn("[BEFORE]", source)
        self.assertIn("[RETURNED]", source)

    def test_probe_never_hardcodes_an_address(self):
        source = PROBE.read_text(encoding="utf-8")
        self.assertNotIn("0x7f", source)  # no literal heap/module addresses
        self.assertIn("memory.alloc", source)


class ProbeExecutionTests(unittest.TestCase):
    def test_calls_430_five_times_with_the_documented_argument_shapes(self):
        loader, _ = run_probe(succeed=False)
        self.assertEqual(len(loader.calls), 5)
        self.assertEqual([c[0] for c in loader.calls], [430] * 5)

        self.assertEqual([(addr, size) for addr, size in loader.allocations],
                         [(0x30000000, 0x600), (0x30001000, 0x600),
                          (0x30002000, 0x600), (0x30003000, 0x10)])
        ctx_zero, ctx_ok, ctx_alt, id_slot = [a for a, _ in loader.allocations]

        self.assertEqual(loader.calls[0], (430, 0, 0, 0))
        self.assertEqual(loader.calls[1], (430, ctx_zero, 0, 0))
        self.assertEqual(loader.calls[2], (430, ctx_zero, id_slot, 0))
        self.assertEqual(loader.calls[3], (430, ctx_ok, id_slot, 0))
        self.assertEqual(loader.calls[4], (430, ctx_alt, id_slot, 0))

    def test_context_fields_are_written_at_the_validated_offsets(self):
        loader, _ = run_probe(succeed=False)
        ctx_zero, ctx_ok, ctx_alt, _ = [a for a, _ in loader.allocations]

        self.assertEqual(loader.read(ctx_ok + 0x108, 8), 0x480)
        self.assertEqual(loader.read(ctx_ok + 0x0D0, 4), 0)
        self.assertEqual(loader.read(ctx_ok + 0x110, 8), 0x10000)

        self.assertEqual(loader.read(ctx_alt + 0x108, 8), 0x480)
        self.assertEqual(loader.read(ctx_alt + 0x110, 8), 0x10002)
        self.assertEqual(loader.read(ctx_alt + 0x118, 8), 0x20001)

        # The zeroed buffer really is zero at the offsets the handler reads.
        for off in (0x108, 0xD0, 0x110, 0x118):
            self.assertEqual(loader.read(ctx_zero + off, 8), 0)

    def test_failure_run_reports_minus_one_and_keeps_the_prefill(self):
        _, output = run_probe(succeed=False)
        for tag in "ABCDE":
            self.assertIn(f"[RETURNED] {tag} ok=true rv=-1", output)
        self.assertIn("id after=0xDEADBEEF_DEADBEEF", output)
        self.assertIn("=== PROBE 58e COMPLETE ===", output)

    def test_success_run_shows_the_id_oracle_flipping(self):
        _, output = run_probe(succeed=True)
        self.assertIn("[RETURNED] A ok=true rv=-1", output)   # NULL context
        self.assertIn("[RETURNED] B ok=true rv=-1", output)   # no id pointer
        self.assertIn("[RETURNED] C ok=true rv=0", output)
        self.assertIn("id after=0x00000000_00001234", output)
        self.assertNotIn("id after=0xDEADBEEF_DEADBEEF\n\n[D]", output)

    def test_probe_prints_a_marker_before_every_call(self):
        _, output = run_probe(succeed=False)
        for tag in "ABCDE":
            self.assertIn(f"[BEFORE] {tag} 430(", output)


if __name__ == "__main__":
    unittest.main()
