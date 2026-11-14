-- CRASH_CLASS: LOW -- 560 has been called with 0/1 before (257a/258a) and 601 cmd 0x01 has been
-- swept 32x24 ways by 1384a without a kill. Commands above 0x01 are gated behind the attach result.
-- PROBE 1494a: does 560 debug_init make 601 attach reachable?
--
-- Two measurements that were never put together:
--   257a/258a: 560(1) returns 0 where every other shape returns -1, and it "opens nothing" - but
--              that verdict came from testing 656, 593 mode 1, 634, mprotect to RX and RWX and 643,
--              NOT from testing 601.
--   1384a:    601 cmd 0x01 (attach) answers EINVAL(22) for 32 flag words x 24 struct shapes, and
--              its twin 0x24 answers EPERM(1). Every other 601 command that needs the debug context
--              answers r3 ("no ctx") because the context is installed by 0xc9afc0, which only the
--              attach path calls.
-- The 601 tail family (13.60, 0x8b662058..0x8b6621ed) is nine bitfield setters that each do
-- `or byte [rax+0xd4], <bit>` and then store caller-supplied qwords into the context at offsets
-- 0x00, 0x20, 0x30, 0x50, 0x60, 0x70, 0x90 and 0xb0 plus a dword at 0xd0. Those commands are a
-- kernel write of caller-chosen 8-byte values at fixed offsets, and they are unreachable while the
-- context does not exist. So the whole family turns on whether anything can install the context.
--
-- [A] 601(0x00) control - it returns 0 and writes 0x100 when the syscall is healthy
-- [B] 601(0x01) with four shapes, before anything else
-- [C] 560(1), then 601(0x01) again with the same four shapes
-- [D] 643 with 0, then 601(0x01) again (643 ORs 0xFFFFFFFF into process+0xa34)
-- [E] 601 commands 0x02, 0x05, 0x06, 0x07, 0x09, 0x0A, 0x0B, 0x0D after [C]
-- [F] 601(0x00) again, and the final canary
--
-- -- prior art:
--   results/phase17_new_vectors/258a_* (560(1) tested against 656/593/634/mprotect/643 only)
--   results/phase17_new_vectors/1384a_601_attach_shapes_* (32 flag words x 24 struct shapes -> EINVAL)
--   results/phase36_realargs/1383a_sys601_command_map_* (the measured command table)
--   docs/MDBG_601_COMMAND_MAP_14_10.md (the 13.60 case map and the context install path)

print("=== PROBE 1494a: 560 DEBUG_INIT AND 601 ATTACH ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

local buf = memory.alloc(0x400)
local out = memory.alloc(0x400)
local sc601 = mk(601)

local function zero(p, n) for i = 0, n - 1, 4 do pcall(function() memory.write_dword(p + i, uint64(0)) end) end end

local function call601(cmd, a1, a2, a3, tag)
    local ok, rv = pcall(function()
        return N(sc601(uint64(cmd), uint64(a1 or 0), uint64(a2 or 0), uint64(a3 or 0), uint64(0), uint64(0)))
    end)
    if not ok then print(string.format("  %-34s EXC", tag)) return nil end
    local e = ""
    if rv == -1 then e = es() end
    print(string.format("  %-34s rv=%-4s %s", tag, tostring(rv), e))
    return rv
end

-- ---------------------------------------------------------------- [A] control
print("")
print("--- [A] 601(0x00) control ---")
zero(out, 0x40)
print(string.format("  out before: %08X %08X", N(memory.read_dword(out)), N(memory.read_dword(out + 4))))
local rvA = call601(0x00, out, 0, 0x100, "601(0x00) arg1=out")
print(string.format("  out after : %08X %08X", N(memory.read_dword(out)), N(memory.read_dword(out + 4))))
if rvA ~= 0 then
    print("601 is not answering as measured; stopping")
    print("=== PROBE 1494a INCOMPLETE ===")
    return
end

-- ---------------------------------------------------------------- [B] attach first
print("")
print("--- [B] 601(0x01) before debug_init ---")
zero(buf, 0x100)
local S1 = {}
S1[#S1 + 1] = call601(0x01, 0, 0, 0, "opt1 (0,0,0)")
S1[#S1 + 1] = call601(0x01, buf, 0, 0x100, "opt2 (buf,0,0x100)")
S1[#S1 + 1] = call601(0x01, 0, buf, 0x100, "opt3 (0,buf,0x100)")
S1[#S1 + 1] = call601(0x01, buf, buf, 0x100, "opt4 (buf,buf,0x100)")

-- ---------------------------------------------------------------- [C] after debug_init
print("")
print("--- [C] 560(1) then the same four ---")
local ok560, rv560 = pcall(function() return N(mk(560)(uint64(1), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))) end)
print(string.format("  560(1) rv=%s %s", ok560 and tostring(rv560) or "EXC", (ok560 and rv560 == -1) and es() or ""))
local S2 = {}
S2[#S2 + 1] = call601(0x01, 0, 0, 0, "opt1 after debug_init")
S2[#S2 + 1] = call601(0x01, buf, 0, 0x100, "opt2 after debug_init")
S2[#S2 + 1] = call601(0x01, 0, buf, 0x100, "opt3 after debug_init")
S2[#S2 + 1] = call601(0x01, buf, buf, 0x100, "opt4 after debug_init")

-- ---------------------------------------------------------------- [D] after 643
print("")
print("--- [D] 643 then attach again ---")
local ok643, rv643 = pcall(function() return N(mk(643)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))) end)
print(string.format("  643(0) rv=%s %s", ok643 and tostring(rv643) or "EXC", (ok643 and rv643 == -1) and es() or ""))
S2[#S2 + 1] = call601(0x01, buf, 0, 0x100, "opt2 after 643")
S2[#S2 + 1] = call601(0x01, 0, buf, 0x100, "opt3 after 643")

-- ---------------------------------------------------------------- [E] the dependent commands
print("")
print("--- [E] the commands that need the context ---")
local cmds = {0x02, 0x05, 0x06, 0x07, 0x09, 0x0A, 0x0B, 0x0D}
for _, c in ipairs(cmds) do
    zero(out, 0x200)
    call601(c, out, 0, 0x200, string.format("601(0x%02X) arg1=out", c))
end

-- ---------------------------------------------------------------- [F] verdict
print("")
print("--- [F] verdict ---")
local any = false
for _, v in ipairs(S1) do if v ~= nil and v ~= -1 then any = true end end
local anyAfter = false
for _, v in ipairs(S2) do if v ~= nil and v ~= -1 then anyAfter = true end end
print(string.format("  attach succeeded before debug_init: %s", tostring(any)))
print(string.format("  attach succeeded after  debug_init/643: %s", tostring(anyAfter)))
zero(out, 0x40)
call601(0x00, out, 0, 0x100, "601(0x00) final control")
local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("  final canary live: %s (pid %d)", tostring(final == PID), PID))
print("=== PROBE 1494a COMPLETE ===")
