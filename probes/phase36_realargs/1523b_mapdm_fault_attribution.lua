-- CRASH_CLASS: MODERATE
-- PROBE 1523b: is the MapDirectMemory SIGSEGV the map succeeding, or the fcall chain itself?
--
-- -- prior art:
--   probes/phase36_realargs/1522b_mapdm_fcall_offsets.lua
--     results/phase36_realargs/1522b_mapdm_fcall_offsets_20261109_234027.txt
--   probes/phase36_realargs/1523a_mapdm_prot_matrix.lua
--     results/phase36_realargs/1523a_mapdm_prot_matrix_20261109_234855.txt
--     -> libkernel+0x15020 (sceKernelMapDirectMemory) returns Sony status 0x80020016 for a
--        zero-length request, and libkernel+0x17EF0 (AllocateDirectMemory) returns rv=0 with
--        phys 0x110010000. The first request with a real length takes SIGSEGV 0x0b -- with the
--        payload's own pair (len 0x4000, align 0x4000, prot 0x33, flags 0x400000) exactly as
--        with a bare prot 3 / flags 0, so prot and flags are NOT the trigger.
--     Fault records decoded (0x13371337 header, then ucontext at +0x18, RIP at +0xA0):
--        1522b: rip=0x7286E4C0 err=0x4 fault=0x310B847C7 cs=0x43
--        1523a: rip=eboot+0x1BA4C0 err=0x4 fault=rsi+7 cs=0x43
--        Both are READ faults (err W=0) at rsi+7 on a user page that is not present, and the
--        1523a RIP is in EBOOT, not libkernel -- i.e. the crash is inside the loader's own
--        fcall ROP chain, near luaL_checklstring (offsets.lua:971 = 0x1BA970) and
--        luaL_optinteger (offsets.lua:970 = 0x1BAD80).
--   .local/loader_payload/native.lua:180-230 -- the fcall chain harvests its eight arguments
--     with luaL_optinteger(lua_state, 3..10, 0) and pins lua_state from r13, with the author's
--     own comment "we assume that r13 will always point to lua state ... at least true for
--     aibeya / raspberry cube / hamidashi creative".
--
-- Three possibilities, and this probe separates them:
--   (a) the length alone breaks the chain          -> [B] (bogus phys, real length) crashes too
--   (b) a SUCCESSFUL map breaks the chain          -> [B] errors cleanly and [C] crashes
--   (c) the physical address breaks the chain      -> [B] errors, [C] with prot 0 also errors
-- [A] dumps the bytes around the 1523a fault RIP first, so the faulting instruction is named
-- even if everything after it dies. eboot text is p=0x5 (readable), so that read is safe.

print("=== PROBE 1523b: MAPDIRECTMEMORY FAULT ATTRIBUTION ===")
print("")

local function N(v)
    if type(v) == "number" then return v end
    if type(v) == "table" and v.tonumber then
        local ok, n = pcall(function() return v:tonumber() end)
        if ok and n then return n end
    end
    local ok, n = pcall(function() return tonumber(v) end)
    if ok and n then return n end
    return 0
end
local function addr_of(u)
    local n = N(u)
    if n >= 0x10000 and n < 0x8000000000 then return n end
    return nil
end
local function mk(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) % 4294967296 end
    return nil
end
local function rb(a)
    local ok, v = pcall(function() return memory.read_byte(a) end)
    if ok then return N(v) % 256 end
    return nil
end
local function wd(a, v)
    return pcall(function() memory.write_dword(a, uint64(v)) end)
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return N(v) end
    return nil
end
local function fmt(v)
    if v == nil then return "nil" end
    local n = N(v)
    if n < 0 then n = n + 2 ^ 64 end
    return string.format("0x%X", n)
end
local function sid(v)
    local n = N(v)
    if n < 0 then n = n + 2 ^ 64 end
    return n
end
local function self_pid()
    local ok, v = pcall(function() return getpid() end)
    if ok then return N(v) end
    return -1
end

local PID0 = self_pid()
print("pid=" .. tostring(PID0))

local function call6(fn, rdi, rsi, rdx, rcx, r8, r9)
    local ok, rv = pcall(function()
        return native.fcall_with_rax(uint64(fn), uint64(0), uint64(rdi), uint64(rsi),
                                     uint64(rdx), uint64(rcx), uint64(r8), uint64(r9))
    end)
    if not ok then return nil end
    return N(rv)
end

-- ============================================================
-- [A] module bases + the bytes around the 1523a fault RIP
-- ============================================================
print("")
print("[A] eboot base and the faulting region")

local eboot, lk = nil, nil
-- handle 0x2001 is libkernel even when its reported name differs; try it first
do
    local ib = memory.alloc(0x200)
    local iba = addr_of(ib)
    if iba then
        wd(iba, 0x160)
        local ok, rv = pcall(function() return mk(593)(uint64(0x2001), uint64(iba)) end)
        if ok and N(rv) == 0 then
            local lo = (rd(iba + 0x108) or 0) % 4294967296
            local hi = (rd(iba + 0x10C) or 0) % 4294967296
            if lo ~= 0 or hi ~= 0 then lk = hi * 4294967296 + lo end
        end
    end
end
for h = 0, 0x120 do
    local ib = memory.alloc(0x200)
    local iba = addr_of(ib)
    if not iba then break end
    wd(iba, 0x160)
    local ok, rv = pcall(function() return mk(593)(uint64(h), uint64(iba)) end)
    if ok and N(rv) == 0 then
        local nm = ""
        for i = 0, 47 do
            local b = rd(iba + 8 + i)
            if not b then break end
            local c = b % 256
            if c == 0 then break end
            if c >= 32 and c < 127 then nm = nm .. string.char(c) end
        end
        local lo = (rd(iba + 0x108) or 0) % 4294967296
        local hi = (rd(iba + 0x10C) or 0) % 4294967296
        if lo ~= 0 or hi ~= 0 then
            local base = hi * 4294967296 + lo
            if nm == "eboot.bin" then eboot = base end
            if (not lk) and nm:find("libkernel") then lk = base end
        end
    end
end
print("  eboot     = " .. fmt(eboot))
print("  libkernel = " .. fmt(lk))
if not eboot then
    print("  FAIL: eboot base not resolved; cannot attribute the fault RIP")
else
    local fa = eboot + 0x1BA4C0
    print("  1523a fault RIP was eboot+0x1BA4C0 = " .. fmt(fa))
    for row = -0x40, 0x40, 16 do
        local s = string.format("   %+05X ", row)
        for i = 0, 15 do
            local b = rb(fa + row + i)
            s = s .. (b and string.format("%02X ", b) or "?? ")
        end
        print(s)
    end
    print("  luaL_optinteger should be at eboot+0x1BAD80 = " .. fmt(eboot + 0x1BAD80))
    print("  luaL_checklstring should be at eboot+0x1BA970 = " .. fmt(eboot + 0x1BA970))
end

if not lk then
    print("VERDICT: no libkernel base; cannot continue")
    return
end
local alloc_fn = lk + 0x17EF0
local map_fn   = lk + 0x15020
print("  alloc_fn=" .. fmt(alloc_fn) .. "  map_fn=" .. fmt(map_fn))

-- ============================================================
-- [B] real length, bogus physical address: if this crashes, length alone is the trigger
-- ============================================================
print("")
print("[B] map_fn(out, 0x4000, prot 0, flags 0, phys 0, align 0x4000) -- bogus phys, real length")
local vo = memory.alloc(8)
local voaddr = addr_of(vo)
if not voaddr then print("  FAIL: out buffer"); return end
memory.write_qword(vo, uint64(0))
local rvB = call6(map_fn, voaddr, 0x4000, 0, 0, 0, 0x4000)
if rvB == nil then
    print("  *** fcall did not return -- the LENGTH alone breaks the chain (case a) ***")
    print("VERDICT: MapDirectMemory is unusable through native.fcall, whatever the physical address.")
    return
end
print("  rv=" .. tostring(rvB) .. " (0x" .. string.format("%X", sid(rvB)) .. ") va=" .. fmt(rq(voaddr)))

-- ============================================================
-- [C] real length, OWNED physical address, prot 0: if this crashes, a successful map is the trigger
-- ============================================================
print("")
print("[C] allocate an owned block")
local pout = memory.alloc(8)
local pouta = addr_of(pout)
if not pouta then print("  FAIL: out buffer"); return end
memory.write_qword(pout, uint64(0))
local rvA = call6(alloc_fn, 0, 0x150000000, 0x4000, 0x4000, 0, pouta)
print("  AllocateDirectMemory rv=" .. tostring(rvA) .. " phys=" .. fmt(rq(pouta)))
local phys = rq(pouta)
if rvA ~= 0 or not phys or phys < 0x1000 then
    print("  no owned block -- stopping")
    print("pid_after=" .. tostring(self_pid()) .. " (was " .. tostring(PID0) .. ")")
    return
end

print("")
print("[C2] map_fn(out, 0x4000, prot 0, flags 0, phys " .. fmt(phys) .. ", align 0x4000)")
memory.write_qword(vo, uint64(0))
local rvC = call6(map_fn, voaddr, 0x4000, 0, 0, phys, 0x4000)
if rvC == nil then
    print("  *** fcall did not return with an OWNED phys and prot 0 ***")
    print("VERDICT: the map itself breaks the chain (case b or c).")
    return
end
local vaC = rq(voaddr)
print("  rv=" .. tostring(rvC) .. " (0x" .. string.format("%X", sid(rvC)) .. ") va=" .. fmt(vaC))

if rvC == 0 and vaC and vaC > 0x10000 then
    print("")
    print("  *** MAP SUCCEEDED at " .. fmt(vaC) .. " with prot 0 ***")
    print("  first 8 dwords: " ..
        string.format("%08X %08X %08X %08X %08X %08X %08X %08X",
            rd(vaC) or 0, rd(vaC + 4) or 0, rd(vaC + 8) or 0, rd(vaC + 12) or 0,
            rd(vaC + 16) or 0, rd(vaC + 20) or 0, rd(vaC + 24) or 0, rd(vaC + 28) or 0))
    -- now with prot 3, the payload's base protection
    print("")
    print("  [C3] map the same physical block a second time with prot 3")
    local vo2 = memory.alloc(8)
    local vo2a = addr_of(vo2)
    if vo2a then
        memory.write_qword(vo2, uint64(0))
        local rvD = call6(map_fn, vo2a, 0x4000, 3, 0, phys, 0x4000)
        if rvD == nil then
            print("    *** prot 3 map did not return ***")
        else
            local vaD = rq(vo2a)
            print("    rv=" .. tostring(rvD) .. " va=" .. fmt(vaD))
            if rvD == 0 and vaD and vaD > 0x10000 then
                local before = rd(vaD)
                wd(vaD, 0x52414D33)
                print("    write 0x52414D33 -> readback " ..
                    string.format("%08X", rd(vaD) or 0) ..
                    "  (RW " .. ((rd(vaD) == 0x52414D33) and "CONFIRMED" or "not writable") .. ")")
            end
        end
    end
end

print("")
print("pid_after=" .. tostring(self_pid()) .. " (was " .. tostring(PID0) .. ")")
print("")
print("=== PROBE 1523b COMPLETE ===")
