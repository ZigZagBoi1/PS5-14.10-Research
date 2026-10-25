-- CRASH_CLASS: LOW
-- PROBE 530o: Enumerate /dev/gc ioctls for GPU context info
--
-- We know: 0xC0108102 = submit (type=0x81, nr=2, size=16)
--          0xC010810B = query (returns {16,16,16,16})
--
-- AMD GPU drivers typically have ioctls for:
-- - Get info (ring size, write ptr, doorbell offset)
-- - Create context / get context handle
-- - Map GPU VA
-- - Wait for fence
--
-- Sweep type=0x81 (which worked) for nr=0..31 with various sizes.
-- Also try type=0x82, 0x83, 0x80 which are adjacent.
-- For info/query ioctls, provide a larger output buffer.

print("=== PROBE 530o: GC IOCTL ENUM ===")
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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print(string.format("pid=%d", pid))

-- Ignore signals
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa_buf, uint64(0)) end)
end

-- Open /dev/gc
local devpath = memory.alloc(0x20)
local name = "/dev/gc"
for i = 1, #name do wd(N(devpath) + i - 1, string.byte(name, i)) end
wd(N(devpath) + #name, 0)
local gc_fd = N(native.fcall_with_rax(stub, 5, uint64(N(devpath)), uint64(2), uint64(0)))
print(string.format("gc_fd=%d", gc_fd))

local sc_ioctl = mk(54)

-- ============================================================
-- [A] Sweep type=0x81, nr=0..31, size=16
-- ============================================================
print("")
print("[A] type=0x81 nr=0..31 size=16")

for nr = 0, 31 do
    local cmd = 0xC0100100 + nr + 0x8000  -- _IOWR('?', nr, 16) with type=0x81
    -- Actually build properly: dir=3(RW), size=16, type=0x81, nr
    -- ioctl encoding: dir(30:31) | size(16:29) | type(8:15) | nr(0:7)
    -- 0xC0108100 + nr
    cmd = 0xC0108100 + nr

    local buf = memory.alloc(0x40)
    for i = 0, 0x3F, 4 do wd(N(buf) + i, 0) end

    local ok, rv = pcall(function()
        return sc_ioctl(uint64(gc_fd), uint64(cmd), uint64(N(buf)))
    end)
    local ret = -999
    if ok and rv then ret = N(rv) end

    if ret == 0 then
        -- Read output
        local d0 = rd(N(buf)) or 0
        local d1 = rd(N(buf) + 4) or 0
        local d2 = rd(N(buf) + 8) or 0
        local d3 = rd(N(buf) + 12) or 0
        if d0 < 0 then d0 = d0 + 0x100000000 end
        if d1 < 0 then d1 = d1 + 0x100000000 end
        if d2 < 0 then d2 = d2 + 0x100000000 end
        if d3 < 0 then d3 = d3 + 0x100000000 end
        print(string.format("  nr=%d cmd=0x%08X rv=0 out={0x%X,0x%X,0x%X,0x%X}",
            nr, cmd, d0, d1, d2, d3))
    elseif ret ~= -1 then
        print(string.format("  nr=%d cmd=0x%08X rv=%d", nr, cmd, ret))
    end
    -- skip rv=-1 (normal rejection)
end

-- ============================================================
-- [B] Sweep type=0x81 with LARGER sizes (32, 64, 128, 256)
-- Some info ioctls need bigger buffers
-- ============================================================
print("")
print("[B] type=0x81 nr=0..15 various sizes")

for _, sz in ipairs({32, 64, 128, 256}) do
    for nr = 0, 15 do
        -- dir=3(RW) | size | type=0x81 | nr
        local cmd = 3 * 0x40000000 + sz * 0x10000 + 0x8100 + nr

        local buf = memory.alloc(sz + 16)
        for i = 0, sz - 1, 4 do wd(N(buf) + i, 0) end

        local ok, rv = pcall(function()
            return sc_ioctl(uint64(gc_fd), uint64(cmd), uint64(N(buf)))
        end)
        local ret = -999
        if ok and rv then ret = N(rv) end

        if ret == 0 then
            local d0 = rd(N(buf)) or 0
            local d1 = rd(N(buf) + 4) or 0
            if d0 < 0 then d0 = d0 + 0x100000000 end
            if d1 < 0 then d1 = d1 + 0x100000000 end
            print(string.format("  sz=%d nr=%d cmd=0x%08X rv=0 [0]=0x%X [4]=0x%X",
                sz, nr, cmd, d0, d1))
        end
    end
end

-- ============================================================
-- [C] Adjacent types: 0x80, 0x82, 0x83, 0x84
-- ============================================================
print("")
print("[C] Adjacent types")

for _, typ in ipairs({0x80, 0x82, 0x83, 0x84, 0x85, 0x86, 0x47, 0x67, 0x64, 0x53}) do
    for nr = 0, 15 do
        local cmd = 0xC0100000 + typ * 0x100 + nr  -- size=16

        local buf = memory.alloc(0x40)
        for i = 0, 0x3F, 4 do wd(N(buf) + i, 0) end

        local ok, rv = pcall(function()
            return sc_ioctl(uint64(gc_fd), uint64(cmd), uint64(N(buf)))
        end)
        local ret = -999
        if ok and rv then ret = N(rv) end

        if ret == 0 then
            local d0 = rd(N(buf)) or 0
            local d1 = rd(N(buf) + 4) or 0
            if d0 < 0 then d0 = d0 + 0x100000000 end
            if d1 < 0 then d1 = d1 + 0x100000000 end
            print(string.format("  type=0x%02X nr=%d rv=0 [0]=0x%X [4]=0x%X",
                typ, nr, d0, d1))
        end
    end
end

-- ============================================================
-- [D] Try READ-only ioctls (dir=2 instead of 3)
-- ============================================================
print("")
print("[D] Read-only ioctls type=0x81")
for nr = 0, 31 do
    local cmd = 0x80108100 + nr  -- dir=2 (read), size=16, type=0x81

    local buf = memory.alloc(0x40)
    for i = 0, 0x3F, 4 do wd(N(buf) + i, 0) end

    local ok, rv = pcall(function()
        return sc_ioctl(uint64(gc_fd), uint64(cmd), uint64(N(buf)))
    end)
    local ret = -999
    if ok and rv then ret = N(rv) end

    if ret == 0 then
        local d0 = rd(N(buf)) or 0
        local d1 = rd(N(buf) + 4) or 0
        if d0 < 0 then d0 = d0 + 0x100000000 end
        if d1 < 0 then d1 = d1 + 0x100000000 end
        print(string.format("  nr=%d cmd=0x%08X rv=0 [0]=0x%X [4]=0x%X",
            nr, cmd, d0, d1))
    end
end

-- Cleanup
pcall(function() native.fcall_with_rax(stub, 6, uint64(gc_fd)) end)

print("")
print("=== 530o DONE ===")
