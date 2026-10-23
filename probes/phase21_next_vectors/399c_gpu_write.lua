-- CRASH_CLASS: HIGH
-- PROBE 399c: write() and mmap on /dev/gc and /dev/dce
--
-- On PS4, GPU DMA via the GNM driver was the path to kernel R/W.
-- The GPU has its own page tables and can read physical memory
-- independently of CPU ASLR. If we can submit GPU commands via
-- write() to /dev/gc, we might bypass KASLR entirely.
--
-- Also test: /dev/dce (display compositor), /dev/ajm (audio)
-- The ioctl sweep found gc has 25 data-filling commands (group 0x81)
-- but no command followed a user-supplied address. write() is untested.

print("=== PROBE 399c: GPU command write ===")

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

-- Ignore signals
local sa = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(sa) + i, 0) end
wq(sa, uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(10), sa, uint64(0)) end)

local sc_open = mk(5)
local sc_write = mk(4)
local sc_read = mk(3)
local sc_close = mk(6)
local sc_mmap = mk(477)

local buf = memory.alloc(0x1000)

-- ============================================
-- PART A: open /dev/gc in each mode
-- ============================================
print("")
print("-- A: open /dev/gc --")

local gc_path = memory.alloc(32)
for i = 0, 28, 4 do wd(N(gc_path) + i, 0) end
-- "/dev/gc" = 2F 64 65 76 2F 67 63 00
wd(N(gc_path), 0x7665642F)    -- /dev
wd(N(gc_path) + 4, 0x0063672F) -- /gc\0

local gc_modes = {
    {0, "O_RDONLY"},
    {1, "O_WRONLY"},
    {2, "O_RDWR"},
}

local gc_fd = -1
for _, m in ipairs(gc_modes) do
    local ok_o, fd_v = pcall(function()
        return sc_open(uint64(N(gc_path)), uint64(m[1]), uint64(0))
    end)
    local fd = ok_o and N(fd_v) or -1
    if fd > 10000 then fd = -1 end
    print(string.format("  gc mode=%d(%s) fd=%d", m[1], m[2], fd))
    if fd >= 0 then
        if gc_fd < 0 then gc_fd = fd
        else pcall(function() sc_close(uint64(fd)) end) end
    end
    if not alive() then print("CANARY FAIL open gc"); return end
end

-- ============================================
-- PART B: write to /dev/gc
-- ============================================
print("")
print("-- B: write /dev/gc --")

if gc_fd >= 0 then
    -- Try various write sizes
    local write_sizes = {4, 8, 16, 32, 64, 256, 0x1000}

    for _, sz in ipairs(write_sizes) do
        -- Fill buffer with pattern
        for i = 0, sz - 4, 4 do wd(N(buf) + i, 0x41414141) end

        local ok_w, rv_w = pcall(function()
            return sc_write(uint64(gc_fd), uint64(N(buf)), uint64(sz))
        end)
        local ret = ok_w and N(rv_w) or -999
        if ret > 0x7FFFFFFF then ret = -1 end

        if ret > 0 then
            print(string.format("  write sz=%X ret=%d ★ ACCEPTED", sz, ret))
        elseif ret ~= -1 then
            print(string.format("  write sz=%X ret=%d", sz, ret))
        end

        if not alive() then print("CANARY FAIL write gc sz=" .. sz); return end
    end

    -- Try write with GNM-like command header
    -- GNM packets: type3 packet = 0xC0000000 | (count-1)<<16 | opcode
    -- PM4 packet header for NOP: 0xC0001000 (type3, 1 dword, opcode 0x10)
    print("  -- PM4 shapes --")
    local pm4_cmds = {
        {0xC0001000, "NOP"},           -- type3, 1 dword, NOP opcode
        {0xC0001002, "CONTEXT_CTRL"},  -- context control
        {0xC0001010, "COND_EXEC"},     -- conditional exec
        {0xC0001040, "SET_BASE"},      -- set base
        {0xC0003068, "EVENT_WRITE"},   -- 3 dwords, event write
        {0xC0003C00, "DMA_DATA"},      -- DMA data (the interesting one)
    }

    for _, cmd in ipairs(pm4_cmds) do
        for i = 0, 0x1C, 4 do wd(N(buf) + i, 0) end
        wd(N(buf), cmd[1])       -- PM4 header
        wd(N(buf) + 4, 0)       -- payload dword 0
        wd(N(buf) + 8, 0)       -- payload dword 1
        wd(N(buf) + 12, 0)      -- payload dword 2

        local pkt_sz = 16 + ((math.floor(cmd[1] / 0x10000) % 0x4000) * 4)
        if pkt_sz > 32 then pkt_sz = 32 end

        local ok_pm, rv_pm = pcall(function()
            return sc_write(uint64(gc_fd), uint64(N(buf)), uint64(pkt_sz))
        end)
        local ret_pm = ok_pm and N(rv_pm) or -999
        if ret_pm > 0x7FFFFFFF then ret_pm = -1 end

        if ret_pm > 0 then
            print(string.format("  %s(0x%08X) sz=%d ret=%d ★ ACCEPTED",
                cmd[2], cmd[1], pkt_sz, ret_pm))
        end

        if not alive() then print("CANARY FAIL PM4 " .. cmd[2]); return end
    end

    pcall(function() sc_close(uint64(gc_fd)) end)
else
    print("  gc not open")
end
if not alive() then print("CANARY FAIL B"); return end

-- ============================================
-- PART C: /dev/dce write
-- ============================================
print("")
print("-- C: /dev/dce --")

local dce_path = memory.alloc(32)
for i = 0, 28, 4 do wd(N(dce_path) + i, 0) end
wd(N(dce_path), 0x7665642F)     -- /dev
wd(N(dce_path) + 4, 0x0065632F) -- /ce\0 → need /dce
-- Actually: "/dev/dce" = 2F 64 65 76 2F 64 63 65 00
wd(N(dce_path), 0x7665642F)     -- /dev
wd(N(dce_path) + 4, 0x6563642F) -- /dce
wd(N(dce_path) + 8, 0)

local ok_dce, dce_fd_v = pcall(function()
    return sc_open(uint64(N(dce_path)), uint64(2), uint64(0))
end)
local dce_fd = ok_dce and N(dce_fd_v) or -1
if dce_fd > 10000 then dce_fd = -1 end
print(string.format("dce fd=%d", dce_fd))

if dce_fd >= 0 then
    for i = 0, 0x3C, 4 do wd(N(buf) + i, 0) end

    local ok_dw, rv_dw = pcall(function()
        return sc_write(uint64(dce_fd), uint64(N(buf)), uint64(16))
    end)
    local dce_ret = ok_dw and N(rv_dw) or -999
    if dce_ret > 0x7FFFFFFF then dce_ret = -1 end
    print(string.format("  write(16)=%d", dce_ret))

    -- Read from dce
    for i = 0, 0xFF, 4 do wd(N(buf) + i, 0xDDDDDDDD) end
    local ok_dr, rv_dr = pcall(function()
        return sc_read(uint64(dce_fd), uint64(N(buf)), uint64(0x100))
    end)
    local dce_rret = ok_dr and N(rv_dr) or -999
    if dce_rret > 0x7FFFFFFF then dce_rret = -1 end
    print(string.format("  read(256)=%d", dce_rret))

    if dce_rret > 0 then
        local dump = "  "
        for i = 0, math.min(dce_rret, 32) - 4, 4 do
            dump = dump .. string.format("%08X ", rd(N(buf) + i) or 0)
        end
        print(dump)
    end

    pcall(function() sc_close(uint64(dce_fd)) end)
end
if not alive() then print("CANARY FAIL C"); return end

-- ============================================
-- PART D: mmap /dev/gc
-- Can we map the GPU command ring or MMIO registers?
-- ============================================
print("")
print("-- D: mmap /dev/gc --")

local ok_gc2, gc_fd2_v = pcall(function()
    return sc_open(uint64(N(gc_path)), uint64(2), uint64(0))
end)
local gc_fd2 = ok_gc2 and N(gc_fd2_v) or -1
if gc_fd2 > 10000 then gc_fd2 = -1 end

if gc_fd2 >= 0 then
    -- Try various mmap flags
    local mmap_shapes = {
        {0x3, 0x1, "SHARED,RW"},       -- MAP_SHARED=1, PROT_RW=3
        {0x1, 0x1, "SHARED,R"},        -- MAP_SHARED, PROT_READ
        {0x3, 0x2, "PRIVATE,RW"},      -- MAP_PRIVATE=2, PROT_RW
        {0x3, 0x1001, "SHARED+ANON"},  -- MAP_SHARED|MAP_ANON
    }

    for _, shape in ipairs(mmap_shapes) do
        local ok_m, rv_m = pcall(function()
            return sc_mmap(uint64(0), uint64(0x4000), uint64(shape[1]),
                uint64(shape[2]), uint64(gc_fd2), uint64(0))
        end)
        local mh, ml = 0, 0
        if ok_m and rv_m then mh, ml = get_hi_lo(rv_m) end
        local addr = ml + mh * 0x100000000

        if addr > 0 then
            print(string.format("  mmap(%s) = %X_%08X ★", shape[3], mh, ml))
            -- Try reading first dwords
            local v0 = rd(addr)
            local v1 = rd(addr + 4)
            if v0 then
                print(string.format("    [0]=%08X [1]=%08X", v0 or 0, v1 or 0))
            else
                print("    read killed — unmapped backing")
            end
            pcall(function() mk(73)(rv_m, uint64(0x4000)) end)
        else
            -- Check if addr is a negative errno
            local ret_n = ok_m and N(rv_m) or -999
            if ret_n > 0x7FFFFFFF then ret_n = ret_n - 0x100000000 end
        end

        if not alive() then print("CANARY FAIL mmap " .. shape[3]); return end
    end

    pcall(function() sc_close(uint64(gc_fd2)) end)
end

-- ============================================
-- PART E: /dev/usb dump (328 bytes from 399b)
-- ============================================
print("")
print("-- E: /dev/usb dump --")

local usb_path = memory.alloc(32)
for i = 0, 28, 4 do wd(N(usb_path) + i, 0) end
wd(N(usb_path), 0x7665642F)     -- /dev
wd(N(usb_path) + 4, 0x6273752F) -- /usb
wd(N(usb_path) + 8, 0)

local ok_usb, usb_fd_v = pcall(function()
    return sc_open(uint64(N(usb_path)), uint64(0), uint64(0))
end)
local usb_fd = ok_usb and N(usb_fd_v) or -1
if usb_fd > 10000 then usb_fd = -1 end

if usb_fd >= 0 then
    pcall(function() mk(92)(uint64(usb_fd), uint64(4), uint64(0x0004)) end)

    for i = 0, 0x3FC, 4 do wd(N(buf) + i, 0) end
    local ok_ur, rv_ur = pcall(function()
        return sc_read(uint64(usb_fd), uint64(N(buf)), uint64(0x400))
    end)
    local usb_bytes = ok_ur and N(rv_ur) or -1
    if usb_bytes > 0x7FFFFFFF then usb_bytes = -1 end
    print(string.format("usb bytes=%d", usb_bytes))

    if usb_bytes > 0 then
        -- Dump in 16-byte rows
        local rows = math.min(math.ceil(usb_bytes / 16), 24)
        for r = 0, rows - 1 do
            local off = r * 16
            local line = string.format("+%03X: ", off)
            for c = 0, 12, 4 do
                if off + c < usb_bytes then
                    line = line .. string.format("%08X ", rd(N(buf) + off + c) or 0)
                end
            end
            print(line)
        end
    end

    pcall(function() sc_close(uint64(usb_fd)) end)
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 399c COMPLETE ===")
