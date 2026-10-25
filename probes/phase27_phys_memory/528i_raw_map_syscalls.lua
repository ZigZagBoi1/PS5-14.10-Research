-- CRASH_CLASS: LOW
-- PROBE 528i: Raw syscall approach to map physical memory
--
-- MapDirectMemory wrapper (libkernel+0x15020) kills the process.
-- But the UNDERLYING SYSCALL might work if the wrapper's check is
-- a userland authid/capability gate, not a kernel one.
--
-- Candidates from 13.60 sysent CSV:
--   547: sceKernelMapDirectMemory
--   548: sceKernelMapDirectMemory2
--   549: (osem create, confirmed different)
--   628: mmap_dmem (tested, returns -1)
--
-- Also try: 477 (mmap) with MAP_FIXED + our phys addr as offset
-- and dmem0 fd. This is a long shot but mmap is the standard POSIX way.
--
-- Using main-thread SROP for full 6-arg register control.

print("=== PROBE 528i: RAW SYSCALL MAP PHYSICAL MEMORY ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function z(b, n) for o = 0, n - 4, 4 do wd(b + o, 0) end end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa_buf, uint64(0)) end)
end

-- SROP setup
local MC = 0x40
local sc_gc = mk(421)
local sc_sr = mk(417)
local sctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(sctx)) end)
local rip_val = rq(N(sctx) + MC + 0xA0)
local rh, rl = get_hi_lo(rip_val)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(sctx)) end)
    wq(N(sctx) + MC + 0xA0, sc_addr)
    wq(N(sctx) + MC + 0x38, uint64(num))
    if a1 then wq(N(sctx) + MC + 0x08, a1) end
    if a2 then wq(N(sctx) + MC + 0x10, a2) end
    if a3 then wq(N(sctx) + MC + 0x18, a3) end
    if a4 then wq(N(sctx) + MC + 0x20, a4) end
    if a5 then wq(N(sctx) + MC + 0x28, a5) end
    if a6 then wq(N(sctx) + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(sctx)) end)
    if ok then return rv end
    return nil
end

-- Allocate physical memory
local phys_out = memory.alloc(8)
wq(N(phys_out), uint64(0))

-- Use eboot base for libkernel (AllocateDirectMemory via fcall, known working)
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local lk_lo = rd(N(ib) + 0x108) or 0
local lk_hi = rd(N(ib) + 0x10C) or 0
if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
if lk_lo == 0 and lk_hi == 0 then
    for h = 0, 0x100 do
        local ib3 = memory.alloc(0x200)
        wd(N(ib3), 0x160)
        local ok3, r3 = pcall(function() return mk(593)(uint64(h), ib3) end)
        if ok3 and N(r3) == 0 then
            local name = ""
            for i = 0, 31 do
                local b = rd(N(ib3) + 8 + i)
                if b then local c = b % 256; if c == 0 then break end
                    if c >= 32 and c < 127 then name = name .. string.char(c) end
                end
            end
            if name:find("libkernel") then
                lk_lo = rd(N(ib3) + 0x108) or 0
                lk_hi = rd(N(ib3) + 0x10C) or 0
                if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
                if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
                break
            end
        end
    end
end
local lk_text = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
local alloc_fn = lk_text + uint64(0x17EF0)

print("[ALLOC]")
local ok_a, rv_a = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(N(phys_out)))
end)
if not ok_a or N(rv_a) ~= 0 then print("  FAILED"); return end
local phys_addr = rq(N(phys_out))
print("  phys=" .. fmt(phys_addr))

-- Open /dev/dmem0
local devpath = memory.alloc(0x20)
local dname = "/dev/dmem0"
for i = 1, #dname do wd(N(devpath) + i - 1, string.byte(dname, i)) end
wd(N(devpath) + #dname, 0)
local ok_o, dmem_fd = pcall(function()
    return native.fcall_with_rax(stub, 5, uint64(N(devpath)), uint64(2), uint64(0))
end)
local fd = ok_o and N(dmem_fd) or -1
print("  dmem0 fd=" .. fd)

-- ============================================================
-- [A] Syscall 547 — sceKernelMapDirectMemory
-- ============================================================
print("")
print("[A] sys 547 (MapDirectMemory kernel)")

-- The 13.60 wrapper at +0x15020 probably calls 547 with:
--   rdi = *virtOut, rsi = len, rdx = prot, r10 = flags,
--   r8 = physAddr, r9 = align
-- And the 7th arg (name) might be passed differently for syscall ABI
-- (it could be on stack, or the kernel might not use it).

local shapes = {
    -- Shape 1: wrapper-like signature (no name/7th arg for syscall)
    {"wrapper-sig", uint64(0), uint64(0x4000), uint64(3), uint64(0), phys_addr, uint64(0x4000)},
    -- Shape 2: flags=1
    {"flags=1", uint64(0), uint64(0x4000), uint64(3), uint64(1), phys_addr, uint64(0x4000)},
    -- Shape 3: flags=0x10
    {"flags=0x10", uint64(0), uint64(0x4000), uint64(3), uint64(0x10), phys_addr, uint64(0x4000)},
    -- Shape 4: with virtOut pointer
    {"&virtOut", nil, uint64(0x4000), uint64(3), uint64(0), phys_addr, uint64(0x4000)},
    -- Shape 5: mmap-like (addr, len, prot, flags, fd, offset)
    {"mmap-like", uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(fd >= 0 and fd or 0xFFFFFFFF), phys_addr},
}

-- For shape 4, use a buffer holding 0 as the virtOut pointer
local virt_buf = memory.alloc(8)

for si, shape in ipairs(shapes) do
    if not alive() then print("  DIED"); break end
    wq(N(virt_buf), uint64(0))

    local a1 = shape[2]
    if si == 4 then a1 = uint64(N(virt_buf)) end

    local rv = srop(547, a1, shape[3], shape[4], shape[5], shape[6], shape[7])
    if not alive() then
        print(string.format("  547 %s: KILLED", shape[1])); break
    end

    local rstr = "nil"
    if rv then
        local rvh, rvl = get_hi_lo(rv)
        if rvh < 0 then rvh = rvh + 0x100000000 end
        if rvl < 0 then rvl = rvl + 0x100000000 end
        rstr = fmt(rv)

        if rvh ~= 0xFFFFFFFF and (rvh ~= 0 or rvl > 0x1000) then
            print(string.format("  547 %s: rv=%s *** MAPPED! ***", shape[1], rstr))
            -- Try to read
            local v = rq(rvl)
            print("    [0]=" .. (v and fmt(v) or "FAULT"))
            break
        end
    end
    local va = rq(N(virt_buf))
    print(string.format("  547 %s: rv=%s va=%s", shape[1], rstr, fmt(va)))
end

-- ============================================================
-- [B] Syscall 548 — sceKernelMapDirectMemory2
-- ============================================================
if alive() then
    print("")
    print("[B] sys 548 (MapDirectMemory2)")

    for si, shape in ipairs(shapes) do
        if not alive() then break end
        wq(N(virt_buf), uint64(0))

        local a1 = shape[2]
        if si == 4 then a1 = uint64(N(virt_buf)) end

        local rv = srop(548, a1, shape[3], shape[4], shape[5], shape[6], shape[7])
        if not alive() then
            print(string.format("  548 %s: KILLED", shape[1])); break
        end

        local rstr = rv and fmt(rv) or "nil"
        if rv then
            local rvh, rvl = get_hi_lo(rv)
            if rvh < 0 then rvh = rvh + 0x100000000 end
            if rvl < 0 then rvl = rvl + 0x100000000 end
            if rvh ~= 0xFFFFFFFF and (rvh ~= 0 or rvl > 0x1000) then
                print(string.format("  548 %s: rv=%s *** MAPPED! ***", shape[1], rstr))
                break
            end
        end
        local va = rq(N(virt_buf))
        print(string.format("  548 %s: rv=%s va=%s", shape[1], rstr, fmt(va)))
    end
end

-- ============================================================
-- [C] Syscall 628 (mmap_dmem) via SROP
-- ============================================================
if alive() then
    print("")
    print("[C] sys 628 (mmap_dmem)")
    local shapes_628 = {
        {"fd+MAP_SHARED", uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(fd >= 0 and fd or 0xFFFFFFFF), phys_addr},
        {"fd+0x40", uint64(0), uint64(0x4000), uint64(3), uint64(0x40), uint64(fd >= 0 and fd or 0xFFFFFFFF), phys_addr},
        {"nofd+1", uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(0xFFFFFFFF), phys_addr},
        {"fd+0", uint64(0), uint64(0x4000), uint64(3), uint64(0), uint64(fd >= 0 and fd or 0xFFFFFFFF), phys_addr},
    }
    for si, shape in ipairs(shapes_628) do
        if not alive() then break end
        local rv = srop(628, shape[2], shape[3], shape[4], shape[5], shape[6], shape[7])
        if not alive() then
            print(string.format("  628 %s: KILLED", shape[1])); break
        end
        local rstr = rv and fmt(rv) or "nil"
        print(string.format("  628 %s: rv=%s", shape[1], rstr))
        if rv then
            local rvh, rvl = get_hi_lo(rv)
            if rvh < 0 then rvh = rvh + 0x100000000 end
            if rvl < 0 then rvl = rvl + 0x100000000 end
            if rvh ~= 0xFFFFFFFF and (rvh ~= 0 or rvl > 0x1000) then
                print(string.format("  *** 628 MAPPED! ***"))
                local v = rq(rvl)
                print("    [0]=" .. (v and fmt(v) or "FAULT"))
                break
            end
        end
    end
end

-- ============================================================
-- [D] mmap(477) with dmem0 fd
-- ============================================================
if alive() then
    print("")
    print("[D] mmap(477) with dmem0 fd")
    -- Standard POSIX mmap: addr, len, prot, flags, fd, offset
    -- If dmem0 is a device, mmap on it should map physical memory
    local shapes_477 = {
        {"SHARED", uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(fd >= 0 and fd or 0), phys_addr},
        {"SHARED|0x40", uint64(0), uint64(0x4000), uint64(3), uint64(0x41), uint64(fd >= 0 and fd or 0), phys_addr},
        {"PRIVATE", uint64(0), uint64(0x4000), uint64(3), uint64(2), uint64(fd >= 0 and fd or 0), phys_addr},
        {"off=0", uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(fd >= 0 and fd or 0), uint64(0)},
    }
    for si, shape in ipairs(shapes_477) do
        if not alive() then break end
        local rv = srop(477, shape[2], shape[3], shape[4], shape[5], shape[6], shape[7])
        if not alive() then
            print(string.format("  477 %s: KILLED", shape[1])); break
        end
        local rstr = rv and fmt(rv) or "nil"
        if rv then
            local rvh, rvl = get_hi_lo(rv)
            if rvh < 0 then rvh = rvh + 0x100000000 end
            if rvl < 0 then rvl = rvl + 0x100000000 end
            if rvh ~= 0xFFFFFFFF and (rvh ~= 0 or rvl > 0x1000) then
                print(string.format("  477 %s: rv=%s *** MAPPED! ***", shape[1], rstr))
                -- Try reading
                local v = rq(rvl)
                print("    [0]=" .. (v and fmt(v) or "FAULT"))
                -- Write test
                wd(rvl, 0xCAFEBABE)
                local rb = rd(rvl)
                if rb then
                    if rb < 0 then rb = rb + 0x100000000 end
                end
                print(string.format("    write test: 0x%X", rb or 0))
                break
            end
        end
        print(string.format("  477 %s: rv=%s", shape[1], rstr))
    end
end

if fd >= 0 then
    pcall(function() native.fcall_with_rax(stub, 6, uint64(fd)) end)
end

print("")
print("alive=" .. tostring(alive()))
print("=== 528i COMPLETE ===")
