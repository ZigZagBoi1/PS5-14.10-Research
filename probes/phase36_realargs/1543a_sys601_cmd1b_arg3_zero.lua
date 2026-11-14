-- CRASH_CLASS: HIGH -- 601 cmd 0x1B kills the connection's process on every shape tried so far. Only
-- the listener is assumed to survive: after 1542a the next connection answered on a new pid, so a
-- death costs this connection, not the console.
-- PROBE 1543a: 601 cmd 0x1B with arg3 = 0, the one axis never varied.
--
-- Context. Five captures have now died inside a call whose command word is 0x1B:
--
--   1176b  601(0x1B, mapped, 0x1000)   sweep died at 0x1B
--   1177a  601(0x1B, mapped, 0x1000)   sweep died at 0x1B (last command by design)
--   1355a  601(0x1B, mapped, 0x100)    died right after the "calling 0x1B" line
--   1541a  601(0x1B, struct, 9)        died after the call line, name field well formed
--   1542a  601(0x1B, struct, page)     died after the call line, arg3 a mapped 0x1000 page
--
-- arg2 was a mapped buffer in all five; arg1 was 0x1B in all five; arg3 was never 0. So the only
-- argument value never presented to this command is zero in the third slot, and that is exactly the
-- value a 13.60-shaped body would find easiest to accept (the ca11ce case treats arg3 as a qword
-- count and rejects anything outside [2,15] *before* its copyin, which cannot fault at all).
--
-- There is a live reason to care about the difference. If arg3 = 0 returns EINVAL and survives, then
-- 0x1B is not a trap slot: the kill depends on arg3, the 14.10 body differs from the 13.60 listing in
-- a way that changes how every argument of every 601 command is read, and the command space has to be
-- re-swept with the corrected model. If arg3 = 0 dies as well, 0x1B joins 0x03/0x04 as an
-- unconditional killer on 14.10 and the ctx+0xf0 write family is unreachable — 601 is then closed.
--
-- [B] repeats with a NULL arg2 and arg3 = 0. It is only reached if [A] survives, and it separates
-- "arg2 must be mapped" from "arg2 may be anything".
--
-- -- prior art:
--   results/phase36_realargs/1542a_sys601_cmd1b_arg3_pointer_20261110_161943.txt (arg3 = mapped page)
--   results/phase36_realargs/1541a_sys601_cmd1b_name_gate_20261110_161109.txt (arg3 = 9, struct valid)
--   results/phase35_dead_end_reruns/1355a_sys601_cmd12_shape_20261109_110324.txt (arg3 = 0x100)
--   results/phase17_new_vectors/1177a_mdbg_sweep_high_20261104_160845.txt (arg3 = 0x1000)
--   docs/MDBG_601_COMMAND_MAP_14_10.md (the 0x1B row and the nine channel literals)
--   note: 1404a's "idx=0x1B" line is an INDEX in arg2 with arg1 fixed at 0x12, not command 0x1B

print("=== PROBE 1543a: 601 cmd 0x1B, arg3 = 0 ===")
print("")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d  (a new pid here means the previous connection's process died)", PID))

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
local ok_sig = 0
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    local okc, sigrv = pcall(function() return mk(416)(uint64(s), uint64(N(sa)), uint64(0)) end)
    if okc and N(sigrv) == 0 then ok_sig = ok_sig + 1 end
end
print(string.format("[0] SIG_IGN installed on %d/10 signals", ok_sig))

local sc601 = mk(601)
local S = memory.alloc(0x100)
for i = 0, 0xFC, 4 do pcall(function() memory.write_dword(S + i, 0) end) end
local name = "Sce.Debug:Gnm"
for i = 1, #name do pcall(function() memory.write_byte(S + 0x28 + i - 1, uint64(name:byte(i))) end) end
print(string.format("[0] struct=%s name at +0x28 = %s", tostring(N(S)), name))

local function call(tag, a2, a3)
    print(string.format("  %-26s 601(0x1B, %s, %s) ...", tag, tostring(a2), tostring(a3)))
    local ok, r = pcall(function() return sc601(uint64(0x1B), a2, a3, uint64(0), uint64(0), uint64(0)) end)
    if not ok then print("       pcall raised: " .. tostring(r)) return -999, "" end
    local v = N(r)
    local e = (v == -1) and es() or ""
    print(string.format("       rv=%s %s", tostring(v), e))
    return v, e
end

print("")
print("[A] arg3 = 0, arg2 = the mapped struct. The only argument value never presented.")
local a1, a1e = call("buf, arg3=0", uint64(N(S)), uint64(0))

print("")
if a1 == -999 then
    print("[V] VOID: pcall raised, so nothing here is a kernel observation")
elseif a1 == -1 then
    print("[V] 0x1B SURVIVED with arg3=0 and answered -1: " .. tostring(a1e))
    print("    the command is NOT a trap slot; the kill is arg3-dependent, so the 14.10 body")
    print("    reads that argument differently from the 13.60 listing and 601 must be re-swept")
else
    print(string.format("[V] 0x1B SURVIVED with arg3=0 and answered %s (%s)", tostring(a1), tostring(a1e or "")))
    print("    the command is NOT a trap slot; the 13.60 '#prev' model does not apply to 14.10")
end

print("")
print("[B] arg2 = 0, arg3 = 0. Only reached if [A] survived; separates 'arg2 must be mapped'.")
local b1, b1e = call("NULL, arg3=0", uint64(0), uint64(0))
if b1 == -999 then
    print("  [B] VOID (pcall raised)")
else
    print(string.format("  [B] answered %s (%s): arg2 = NULL is %s", tostring(b1), tostring(b1e or ""),
        (b1 == -1) and "refused, not dereferenced" or "accepted"))
end

print("")
print(string.format("=== PROBE 1543a COMPLETE pid=%s ===", tostring(PID)))
