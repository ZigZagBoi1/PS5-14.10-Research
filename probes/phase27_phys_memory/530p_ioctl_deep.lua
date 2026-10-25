-- CRASH_CLASS: LOW
-- PROBE 530p: Deep dive on the 3 working /dev/gc ioctls
--
-- 530o found only 3 working ioctls:
--   0xC0108102 (nr=2, sz=16) = submit, rv=0
--   0xC010810B (nr=11, sz=16) = returns {16,16,16,16}
--   0xC020810C (nr=12, sz=32) = rv=0, output zeros
--
-- Plan:
-- 1. Test nr=12 with various input values to see what it does
-- 2. Test nr=11 before and after submit to see if it changes
-- 3. Try nr=2 with count=0 (flush?) and inspect output more carefully
-- 4. Expand sweep: nr=0..63 with sizes 8,16,24,32,48,64,128
-- 5. Try WRITE-only ioctls (dir=1)

print("=== PROBE 530p: IOCTL DEEP ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print(string.format("pid=%d", pid))

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa_buf, uint64(0)) end)
end

local devpath = memory.alloc(0x20)
local name = "/dev/gc"
for i = 1, #name do wd(N(devpath) + i - 1, string.byte(name, i)) end
wd(N(devpath) + #name, 0)
local gc_fd = N(native.fcall_with_rax(stub, 5, uint64(N(devpath)), uint64(2), uint64(0)))
print(string.format("gc_fd=%d", gc_fd))

local sc_ioctl = mk(54)

-- Helper: call ioctl and return rv + first N dwords
local function try_ioctl(cmd, in_buf, in_size, out_count)
    local buf = memory.alloc(math.max(in_size, 256))
    if in_buf then
        for i = 0, in_size - 1, 4 do
            wd(N(buf) + i, in_buf[i/4 + 1] or 0)
        end
    else
        for i = 0, in_size - 1, 4 do wd(N(buf) + i, 0) end
    end

    local ok, rv = pcall(function()
        return sc_ioctl(uint64(gc_fd), uint64(cmd), uint64(N(buf)))
    end)
    local ret = -999
    if ok and rv then ret = N(rv) end

    local out = {}
    for i = 0, (out_count or 4) - 1 do
        local d = rd(N(buf) + i * 4) or 0
        if d < 0 then d = d + 0x100000000 end
        table.insert(out, d)
    end
    return ret, out
end

-- ============================================================
-- [A] nr=12 (0xC020810C, sz=32): probe with various inputs
-- ============================================================
print("")
print("[A] nr=12 sz=32 input variations")

-- All zeros
local rv, out = try_ioctl(0xC020810C, nil, 32, 8)
local parts = {}
for _, d in ipairs(out) do table.insert(parts, string.format("0x%X", d)) end
print(string.format("  zeros: rv=%d out={%s}", rv, table.concat(parts, ",")))

-- With various first dwords (could be a command/subfunction selector)
for _, val in ipairs({1, 2, 3, 4, 5, 0x100, 0x1000, 0xFFFFFFFF}) do
    rv, out = try_ioctl(0xC020810C, {val}, 32, 8)
    local nz = false
    for _, d in ipairs(out) do if d ~= 0 then nz = true end end
    if nz or rv ~= 0 then
        parts = {}
        for _, d in ipairs(out) do table.insert(parts, string.format("0x%X", d)) end
        print(string.format("  [0]=%d: rv=%d out={%s}", val, rv, table.concat(parts, ",")))
    end
end

-- ============================================================
-- [B] nr=11: inspect full output (8 dwords)
-- ============================================================
print("")
print("[B] nr=11 full output")
rv, out = try_ioctl(0xC010810B, nil, 16, 8)
parts = {}
for i, d in ipairs(out) do table.insert(parts, string.format("[%d]=0x%X", i-1, d)) end
print(string.format("  rv=%d %s", rv, table.concat(parts, " ")))

-- Try with larger sizes
for _, sz in ipairs({32, 64, 128}) do
    local cmd = 3 * 0x40000000 + sz * 0x10000 + 0x810B
    rv, out = try_ioctl(cmd, nil, sz, sz/4)
    local nz_count = 0
    for _, d in ipairs(out) do if d ~= 0 then nz_count = nz_count + 1 end end
    print(string.format("  sz=%d: rv=%d non-zero=%d", sz, rv, nz_count))
    if nz_count > 0 and nz_count <= 8 then
        for i, d in ipairs(out) do
            if d ~= 0 then print(string.format("    [%d]=0x%X", i-1, d)) end
        end
    end
end

-- ============================================================
-- [C] Extended sweep: nr=0..63 with more sizes
-- ============================================================
print("")
print("[C] Extended sweep nr=0..63")

local working = {}
for nr = 0, 63 do
    for _, sz in ipairs({8, 16, 24, 32, 48, 64, 128, 256}) do
        local cmd = 3 * 0x40000000 + sz * 0x10000 + 0x8100 + nr
        rv, out = try_ioctl(cmd, nil, sz, math.min(sz/4, 8))
        if rv == 0 then
            local nz = 0
            for _, d in ipairs(out) do if d ~= 0 then nz = nz + 1 end end
            -- Only print if new (not already found at size 16)
            local key = string.format("%d_%d", nr, sz)
            if not working[key] then
                working[key] = true
                print(string.format("  nr=%d sz=%d cmd=0x%08X rv=0 nz=%d", nr, sz, cmd, nz))
                if nz > 0 and nz <= 4 then
                    for i, d in ipairs(out) do
                        if d ~= 0 then print(string.format("    [%d]=0x%X", i-1, d)) end
                    end
                end
            end
        end
    end
end

-- ============================================================
-- [D] WRITE-only ioctls (dir=1)
-- ============================================================
print("")
print("[D] Write-only ioctls type=0x81")
for nr = 0, 31 do
    local cmd = 0x40108100 + nr  -- dir=1, size=16
    rv = try_ioctl(cmd, nil, 16, 4)
    if rv == 0 then
        print(string.format("  nr=%d cmd=0x%08X rv=0", nr, cmd))
    end
end

-- ============================================================
-- [E] No-direction ioctls (dir=0)
-- ============================================================
print("")
print("[E] No-dir ioctls type=0x81")
for nr = 0, 31 do
    local cmd = 0x00008100 + nr  -- dir=0
    rv = try_ioctl(cmd, nil, 16, 4)
    if rv == 0 then
        print(string.format("  nr=%d cmd=0x%08X rv=0", nr, cmd))
    end
end

-- Cleanup
pcall(function() native.fcall_with_rax(stub, 6, uint64(gc_fd)) end)

print("")
print("=== 530p DONE ===")
