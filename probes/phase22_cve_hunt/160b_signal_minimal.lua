-- CRASH_CLASS: LOW
-- PROBE 160b: Minimal signal delivery test
--
-- Just test: SIG_IGN, then nanosleep with timer

print("=== PROBE 160b: SIGNAL MINIMAL ===")
print("")

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
local function rd(addr) return to_num(memory.read_dword(addr)) end

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
    return sc_mmap(uint64(0), uint64(0x400000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end

-- [A] Test SIG_IGN for SIGALRM
print("--- [A] SIG_IGN ---")
local SA = gpu + 0x10000
for off = 0, 0x1F, 4 do wd(SA + off, 0) end
wq(SA, uint64(1))  -- SIG_IGN
wd(SA + 8, 0)
local rv1 = srop(416, uint64(14), ga(0x10000), uint64(0))
print("sigaction(SIGALRM,SIG_IGN)=" .. (rv1 and to_num(rv1) or -999))

-- [B] Arm timer 50ms
print("--- [B] SET TIMER ---")
local IT = gpu + 0x11000
for off = 0, 0x1F, 4 do wd(IT + off, 0) end
wq(IT + 16, uint64(0))       -- tv_sec
wq(IT + 24, uint64(50000))   -- tv_usec = 50ms
local rv2 = srop(83, uint64(0), ga(0x11000), uint64(0))
print("setitimer=" .. (rv2 and to_num(rv2) or -999))

-- [C] Sleep 200ms — with SIG_IGN, should complete fully
print("--- [C] NANOSLEEP ---")
local TS = gpu + 0x12000
wq(TS, uint64(0))
wq(TS + 8, uint64(200000000))  -- 200ms
local REM = gpu + 0x12010
wq(REM, uint64(0))
wq(REM + 8, uint64(0))

local rv3 = srop(240, ga(0x12000), ga(0x12010))
local v3 = rv3 and to_num(rv3) or -999
print("nanosleep(200ms)=" .. v3)

-- [D] Now test SIG_DFL (default = kill) — DON'T actually fire timer
-- Just query what SIG_DFL does
print("--- [D] QUERY HANDLERS ---")
local OSA = gpu + 0x10100
for _, sig in ipairs({1, 2, 3, 6, 9, 10, 11, 12, 13, 14, 15, 17, 20, 23, 28, 29, 30, 31}) do
    for off = 0, 0x1F, 4 do wd(OSA + off, 0) end
    local rv = srop(416, uint64(sig), uint64(0), ga(0x10100))
    if rv then
        local handler = memory.read_qword(OSA)
        local hh, hl = get_hi_lo(handler)
        local flags = rd(OSA + 8)
        if hl ~= 0 or hh ~= 0 then
            print("  sig=" .. sig .. " handler=0x" .. string.format("%X%08X", hh, hl) ..
                " flags=0x" .. string.format("%X", flags))
        else
            print("  sig=" .. sig .. " handler=SIG_DFL flags=0x" .. string.format("%X", flags))
        end
    else
        print("  sig=" .. sig .. " query_failed")
    end
end

-- [E] Test poll with SIG_IGN — does timer interrupt poll?
print("")
print("--- [E] POLL WITH SIG_IGN ---")
local pr = srop(42)
local prv = pr and to_num(pr) or -1
print("pipe=" .. prv)

if prv >= 0 then
    local PFD = gpu + 0x15000
    wd(PFD, prv)        -- fd
    wd(PFD + 4, 1)      -- POLLIN
    wd(PFD + 8, 0)

    -- Arm 50ms timer
    for off = 0, 0x1F, 4 do wd(IT + off, 0) end
    wq(IT + 16, uint64(0))
    wq(IT + 24, uint64(50000))
    srop(83, uint64(0), ga(0x11000), uint64(0))

    -- Poll 500ms — should either complete (SIG_IGN) or be interrupted
    local rv4 = srop(209, ga(0x15000), uint64(1), uint64(500))
    local v4 = rv4 and to_num(rv4) or -999
    local revents = rd(PFD + 8)
    print("poll(500ms,SIG_IGN)=" .. v4 .. " revents=0x" .. string.format("%X", revents))

    srop(6, uint64(prv))
    srop(6, uint64(prv + 1))
end

-- Cancel timer
for off = 0, 0x1F, 4 do wd(IT + off, 0) end
srop(83, uint64(0), ga(0x11000), uint64(0))

-- Reset handler
wq(SA, uint64(0))  -- SIG_DFL
srop(416, uint64(14), ga(0x10000), uint64(0))

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
