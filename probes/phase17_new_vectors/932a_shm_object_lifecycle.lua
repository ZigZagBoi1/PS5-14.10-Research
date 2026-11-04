-- CRASH_CLASS: MODERATE
-- PROBE 932a: POSIX shm object lifecycle (shm_open 482 is live on 14.10)
--
-- Context: probe 58d/2026-10-28 showed shm_open(482) works through
-- make_syscall: fd, ftruncate, mmap, munmap and shm_unlink all return
-- normally. SHM_LARGEPAGE is rejected, so the CVE-2026-49427/49428 shapes
-- are out of reach; plain shm is not.
--
-- shm objects are refcounted vm_objects reachable from userland with a name,
-- an fd and a mapping. This probe maps the object lifetime before anything
-- clever is attempted:
--
--   A) create, size, map, write, read back
--   B) second open of the same name -> independent fd, shared memory
--   C) unlink with the fd still open -> name gone, mapping and fd still live
--   D) name reuse after unlink -> a *new* object, old mapping unaffected
--   E) double unlink and unlink of a missing name -> error classes
--
-- No shrink-while-mapped test here: a bus fault would kill the process and
-- teach us nothing about the kernel, and it is a separate probe.

print("=== PROBE 932a: POSIX SHM OBJECT LIFECYCLE ===")
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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end
    return nil
end
local function zero(buf, n)
    for i = 0, n - 1, 4 do wd(buf + i, 0) end
end

local sc_getpid   = make_syscall(20)
local sc_close    = make_syscall(6)
local sc_munmap   = make_syscall(73)
local sc_mmap     = make_syscall(477)
local sc_ftrunc   = make_syscall(480)
local sc_shm_open = make_syscall(482)
local sc_shm_unlink = make_syscall(483)

local O_RDWR   = 0x0002
local O_CREAT  = 0x0200
local O_EXCL   = 0x0800
local PAGE     = 0x4000

local function mkname(s)
    local b = memory.alloc(64)
    zero(b, 64)
    for i = 1, #s do wd(b + (i - 1), string.byte(s, i)) end
    return b
end

local function call1(fn, label)
    label = label or "call"
    print("  [BEFORE] " .. label)
    local ok, rv = pcall(fn)
    local n = ok and to_num(rv) or -999
    print("  [AFTER ] " .. label .. " ok=" .. tostring(ok) .. " rv=" .. n)
    return ok, n
end

local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end

local ok_pg, rv_pg = pcall(function() return sc_getpid() end)
local mypid = ok_pg and to_num(rv_pg) or 0
local ma_saved = 0

local name = "/p932_" .. tostring(mypid)
local nb = mkname(name)
print("name = " .. name)
print("")

--------------------------------------------------------------------
-- A: create, size, map, write, read
--------------------------------------------------------------------
print("--- A: create / size / map / write ---")
local ok_a, fd_a = call1(function()
    return sc_shm_open(uint64(nb), uint64(O_RDWR + O_CREAT + O_EXCL), uint64(0600))
end)
if fd_a >= 0 then
    call1(function() return sc_ftrunc(uint64(fd_a), uint64(PAGE)) end, "ftruncate +16K")
    local ok_m, ma = call1(function()
        return sc_mmap(uint64(0), uint64(PAGE), uint64(0x3), uint64(0x11),
            uint64(fd_a), uint64(0))
    end)
    if ma > 0 then
        ma_saved = ma
        wq(ma, uint64(0x1122334455667788))
        print("  read back: " .. hex(rq(ma)))
    end
    print("")
end

--------------------------------------------------------------------
-- B: second open of the same name
--------------------------------------------------------------------
print("--- B: second open, shared object ---")
local fd_b = -1
if fd_a >= 0 then
    local ok_b, b = call1(function()
        return sc_shm_open(uint64(nb), uint64(O_RDWR), uint64(0600))
    end)
    fd_b = ok_b and b or -1
    if fd_b >= 0 then
        local ok_m2, mb = call1(function()
            return sc_mmap(uint64(0), uint64(PAGE), uint64(0x3), uint64(0x11),
                uint64(fd_b), uint64(0))
        end)
        if mb > 0 then
            print("  A wrote 0x1122334455667788")
            print("  B sees  " .. hex(rq(mb)))
            wq(mb, uint64(0x99AABBCCDDEEFF00))
            print("  B wrote 0x99AABBCCDDEEFF00")
            print("  A sees  " .. hex(rq(ma_saved > 0 and ma_saved or mb)))
        end
    end
    print("")
end

--------------------------------------------------------------------
-- C: unlink with the fd still open
--------------------------------------------------------------------
print("--- C: unlink while fd and mapping are live ---")
if fd_a >= 0 then
    call1(function() return sc_shm_unlink(uint64(nb)) end, "shm_unlink")
    local ok_re, re = call1(function()
        return sc_shm_open(uint64(nb), uint64(O_RDWR), uint64(0600))
    end)
    if ok_re and re >= 0 then
        print("  name still opens after unlink (unexpected) fd=" .. re)
        pcall(function() return sc_close(uint64(re)) end)
    end
    print("")
end

--------------------------------------------------------------------
-- D: name reuse creates a new object
--------------------------------------------------------------------
print("--- D: create the same name again ---")
local fd_c = -1
if fd_a >= 0 then
    local ok_c, c = call1(function()
        return sc_shm_open(uint64(nb), uint64(O_RDWR + O_CREAT), uint64(0600))
    end)
    fd_c = ok_c and c or -1
    if fd_c >= 0 then
        call1(function() return sc_ftrunc(uint64(fd_c), uint64(PAGE)) end, "ftruncate +16K")
        local ok_m3, mc = call1(function()
            return sc_mmap(uint64(0), uint64(PAGE), uint64(0x3), uint64(0x11),
                uint64(fd_c), uint64(0))
        end)
        if mc > 0 then
            print("  new object first qword: " .. hex(rq(mc)) .. " (expect 0)")
        end
    end
    print("")
end

--------------------------------------------------------------------
-- E: error classes
--------------------------------------------------------------------
print("--- E: error classes ---")
if fd_a >= 0 then
    call1(function() return sc_shm_unlink(uint64(nb)) end, "unlink the new name")
    call1(function() return sc_shm_unlink(uint64(nb)) end, "unlink again")
end
local missing = mkname("/p932_missing_" .. tostring(mypid))
call1(function() return sc_shm_unlink(uint64(missing)) end, "unlink missing name")
call1(function()
    return sc_shm_open(uint64(missing), uint64(O_RDWR), uint64(0600))
end, "open missing name")

print("")
print("--- cleanup ---")
for _, fd in ipairs({fd_a, fd_b, fd_c}) do
    if fd and fd >= 0 then pcall(function() return sc_close(uint64(fd)) end) end
end
print("closed fds")

local ok_can, canary = pcall(function() return sc_getpid() end)
print("final canary: " .. tostring(to_num(canary)))
print("")
print("=== PROBE 932a COMPLETE ===")
