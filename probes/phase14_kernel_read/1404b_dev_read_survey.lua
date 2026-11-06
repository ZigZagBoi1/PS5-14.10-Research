-- CRASH_CLASS: MODERATE
-- PROBE 1404b: read() survey on all /dev nodes
--
-- ioctl was exhausted (387a/387c). read() is a different code path.
-- Some devices may return data via read that wasn't reachable via ioctl.
-- NOTE: reading GPU/device mappings can kill past pcall (376a/380a).
-- We pcall every read and examine surviving output.

print("=== 1404b: /dev read survey ===")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) memory.write_dword(a, v) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function get_hi_lo(v)
    if type(v) == "table" and v.h then return v.h, v.l end
    return 0, N(v)
end

local sc_open = mk(5)
local sc_read = mk(3)
local sc_close = mk(6)

-- Buffer for read output: 4KB, sentinel-filled
local buf = memory.alloc(0x1000)
local buf_n = N(buf)

-- Known /dev nodes that open from game process (from device inventory probes)
local nodes = {
    "/dev/zero",
    "/dev/null",
    "/dev/rng",
    "/dev/gc",
    "/dev/dce",
    "/dev/ajm",
    "/dev/dmem0",
    "/dev/dmem1",
    "/dev/dmem2",
    "/dev/camera",
    "/dev/usb",
    "/dev/hid",
    "/dev/bt",
    "/dev/gic",
    "/dev/notification0",
    "/dev/notification1",
    "/dev/notification2",
    "/dev/notification3",
    "/dev/notification4",
    "/dev/notification5",
}

local function write_str(addr, s)
    for i = 1, #s do
        wd(addr + i - 1, string.byte(s, i))
    end
    wd(addr + #s, 0)
end

local path_buf = memory.alloc(256)
local path_n = N(path_buf)

print(string.format("testing %d nodes", #nodes))
print("")

for _, path in ipairs(nodes) do
    -- Sentinel fill
    for i = 0, 0xFC, 4 do wd(buf_n + i, 0xDEADDEAD) end

    -- Write path string
    write_str(path_n, path)

    -- Open: O_RDONLY = 0
    local fd = -1
    local ok_o, rv_o = pcall(function()
        return sc_open(uint64(path_n), uint64(0), uint64(0))
    end)
    if ok_o then fd = N(rv_o) end

    if fd < 0 then
        print(string.format("%-24s OPEN_FAIL (rv=%d)", path, fd))
    else
        -- Try read(fd, buf, 256)
        local ok_r, rv_r = pcall(function()
            return sc_read(uint64(fd), uint64(buf_n), uint64(256))
        end)
        local bytes_read = ok_r and N(rv_r) or -999

        if bytes_read == -999 then
            print(string.format("%-24s fd=%d READ_CRASH", path, fd))
        elseif bytes_read < 0 then
            print(string.format("%-24s fd=%d READ_FAIL rv=%d", path, fd, bytes_read))
        elseif bytes_read == 0 then
            print(string.format("%-24s fd=%d EOF (0 bytes)", path, fd))
        else
            -- Got data! Examine it
            local nonzero = 0
            local kptr_count = 0
            local sample = {}
            for i = 0, math.min(bytes_read - 1, 63), 4 do
                local v = rd(buf_n + i) or 0
                if v ~= 0 then nonzero = nonzero + 1 end
                local h = math.floor(v / 0x10000)
                if h >= 0xFFFF8000 then kptr_count = kptr_count + 1 end
                if #sample < 8 then
                    table.insert(sample, string.format("0x%08X", v))
                end
            end
            print(string.format("%-24s fd=%d READ %d bytes, nonzero_dw=%d kptr=%d",
                path, fd, bytes_read, nonzero, kptr_count))
            if #sample > 0 then
                print(string.format("  first dwords: %s", table.concat(sample, " ")))
            end
            -- Check for kernel pointers (full qword check)
            if kptr_count > 0 then
                print("  !! POTENTIAL KERNEL POINTERS:")
                for i = 0, math.min(bytes_read - 1, 255), 8 do
                    local lo = rd(buf_n + i) or 0
                    local hi = rd(buf_n + i + 4) or 0
                    if hi >= 0xFFFF8000 and hi ~= 0xFFFFFFFF then
                        print(string.format("    +0x%02X: 0x%X%08X", i, hi, lo))
                    end
                end
            end
        end

        -- Close
        pcall(function() sc_close(uint64(fd)) end)
    end
end

-- Also try O_RDWR on a few interesting nodes
print("")
print("=== O_RDWR attempts ===")
local rdwr_nodes = {"/dev/rng", "/dev/zero", "/dev/notification0"}
for _, path in ipairs(rdwr_nodes) do
    write_str(path_n, path)
    local fd2 = -1
    local ok2 = pcall(function() fd2 = N(sc_open(uint64(path_n), uint64(2), uint64(0))) end)
    if fd2 >= 0 then
        -- Read
        for i = 0, 0xFC, 4 do wd(buf_n + i, 0xDEADDEAD) end
        local ok_r, rv_r = pcall(function()
            return sc_read(uint64(fd2), uint64(buf_n), uint64(256))
        end)
        local br = ok_r and N(rv_r) or -999
        print(string.format("%-24s fd=%d read=%d", path, fd2, br))
        if br > 0 then
            local s = {}
            for i = 0, math.min(br-1, 31), 4 do
                table.insert(s, string.format("%08X", rd(buf_n+i) or 0))
            end
            print(string.format("  data: %s", table.concat(s, " ")))
        end
        pcall(function() sc_close(uint64(fd2)) end)
    else
        print(string.format("%-24s OPEN_FAIL", path))
    end
end

print("")
print("=== 1404b DONE ===")
