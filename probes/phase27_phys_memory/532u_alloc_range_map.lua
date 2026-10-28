-- CRASH_CLASS: LOW
-- PROBE 532u: Allocate + map across the entire GPU pool
--
-- Idea: allocate many pages across the pool, then read them.
-- Some might contain GPU driver structures, page tables, or
-- data from other parts of the system.
--
-- Also: what data does the GPU pool contain near offset 0?
-- dmem0+0 was decoded as a GFX PM4 init state in 528w.
-- If we allocate starting from 0x100000000 (pool start),
-- we might get pages that have GPU command buffers or driver state.
--
-- Key test: after allocating at a specific phys addr, does the
-- content reflect what was previously there? Or is it zeroed?

print("=== PROBE 532u: ALLOC RANGE MAP ===")
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
local function q(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end
local function zero(b, n) for off = 0, n-4, 4 do wd(b+off, 0) end end
local function get_hi_lo(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return h, l
    end
    local n = to_num(v); if n < 0 then n = n + 0x100000000 end
    return 0, n
end

-- Get libkernel
local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0x2001), info) end)
local lk = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
local error_fn = lk + uint64(0x02E10)
local alloc_fn = lk + uint64(0x17EF0)
print("lk=" .. q(lk))

local function get_errno()
    local errno_val = -1
    pcall(function()
        local errno_ptr = native.fcall_with_rax(error_fn, 0)
        if errno_ptr and to_num(errno_ptr) ~= 0 then
            errno_val = rd(to_num(errno_ptr)) or -1
        end
    end)
    return errno_val
end

local sc_628 = make_syscall(628)

-- [A] Allocate specific phys ranges and check content
print("[A] Allocate at pool start (searchStart=0x100000000)")
local targets = {
    { "0x100000000", uint64("0x100000000"), uint64("0x100010000") },
    { "0x100010000", uint64("0x100010000"), uint64("0x100020000") },
    { "0x100100000", uint64("0x100100000"), uint64("0x100110000") },
    { "0x101000000", uint64("0x101000000"), uint64("0x101010000") },
    { "0x108000000", uint64("0x108000000"), uint64("0x108010000") },
    { "0x110000000", uint64("0x110000000"), uint64("0x110010000") },
}

for _, t in ipairs(targets) do
    local label, start_a, end_a = t[1], t[2], t[3]
    local phys_buf = memory.alloc(8); wq(phys_buf, uint64(0))
    local ok_a, rv_a = pcall(function()
        return native.fcall_with_rax(alloc_fn, 0,
            start_a, end_a, uint64(0x4000),
            uint64(0x4000), uint64(0), uint64(phys_buf))
    end)
    local rvn = to_num(rv_a)
    local errno_a = get_errno()
    local phys = rq(phys_buf)
    
    if rvn == 0 then
        -- Map it
        local ok_m, va = pcall(function()
            return sc_628(uint64(0), uint64(0x4000), uint64("0xFFFFFFFFFFFFFFFF"),
                uint64(3), uint64(0), phys)
        end)
        if ok_m and to_num(va) > 0 then
            -- Read first 8 dwords
            local hex = ""
            local nonzero = 0
            for i = 0, 7 do
                local v = rd(va + i * 4) or 0
                if v < 0 then v = v + 0x100000000 end
                hex = hex .. string.format("%08X ", v)
                if v ~= 0 then nonzero = nonzero + 1 end
            end
            print(string.format("  %s: phys=%s nz=%d %s", label, q(phys), nonzero, hex))
            -- Unmap
            pcall(function() make_syscall(73)(va, uint64(0x4000)) end)
        else
            print(string.format("  %s: alloc_ok phys=%s map_fail e=%d", label, q(phys), get_errno()))
        end
    else
        print(string.format("  %s: alloc_fail rv=%d e=%d", label, rvn, errno_a))
    end
end

-- [B] Allocate a large block and scan for non-zero content
print("")
print("[B] Large alloc (1MB) scan for non-zero")
local big_phys = memory.alloc(8); wq(big_phys, uint64(0))
pcall(function()
    native.fcall_with_rax(alloc_fn, 0,
        uint64("0x100000000"), uint64("0x150000000"), uint64(0x100000),
        uint64(0x4000), uint64(0), uint64(big_phys))
end)
local bp = rq(big_phys)
print("  phys=" .. q(bp))

if bp and to_num(bp) > 0 then
    local ok_m, va = pcall(function()
        return sc_628(uint64(0), uint64(0x100000), uint64("0xFFFFFFFFFFFFFFFF"),
            uint64(3), uint64(0), bp)
    end)
    if ok_m and to_num(va) > 0 then
        local nz_pages = 0
        local nz_first = nil
        for page = 0, 0xFF do
            local poff = page * 0x1000
            local v = rd(va + poff)
            if v and v ~= 0 then
                nz_pages = nz_pages + 1
                if not nz_first then
                    nz_first = poff
                    local vn = v; if vn < 0 then vn = vn + 0x100000000 end
                    print(string.format("  first non-zero at +0x%X: 0x%08X", poff, vn))
                    -- Dump first 32 bytes
                    for i = 0, 7 do
                        local bv = rd(va + poff + i * 4) or 0
                        if bv < 0 then bv = bv + 0x100000000 end
                        print(string.format("    +%02X: 0x%08X", i*4, bv))
                    end
                end
            end
        end
        print("  non-zero pages: " .. nz_pages .. " / 256")
        pcall(function() make_syscall(73)(va, uint64(0x100000)) end)
    else
        print("  map_fail e=" .. get_errno())
    end
else
    print("  alloc_fail")
end

-- [C] Check: what does GetDirectMemorySize report?
local getdms_fn = lk + uint64(0x17810)
local ok_gs, dms = pcall(function()
    return native.fcall_with_rax(getdms_fn, 0)
end)
print("")
print("[C] GetDirectMemorySize=" .. (ok_gs and q(dms) or "fail"))

print("")
print("=== 532u DONE ===")
