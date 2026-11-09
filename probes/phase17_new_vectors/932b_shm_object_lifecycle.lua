-- CRASH_CLASS: MODERATE
-- PROBE 932b: POSIX shm object lifecycle, 58d calling convention
--
-- Context: 58d created a shm object (fd, ftruncate 0, mmap at a user address,
-- write+read fine) by passing the *name as a Lua string* and MAP_SHARED=1.
-- 932a passed a pointer plus MAP_SHARED|MAP_FIXED and every mmap/open after
-- the create failed, so the two conventions differ and only one is right.
--
--   A) create / size / map (MAP_SHARED) / write / read
--   B) second open of the same name -> independent fd, same memory
--   C) unlink with fd+mapping live -> name gone, old mapping still valid
--   D) recreate the same name -> a new object
--   E) error classes: double unlink, missing name, open after unlink

print("=== PROBE 932b: POSIX SHM OBJECT LIFECYCLE ===")
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
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end
    return nil
end
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end

local sc_getpid     = make_syscall(20)
local sc_close      = make_syscall(6)
local sc_munmap     = make_syscall(73)
local sc_mmap       = make_syscall(477)
local sc_ftrunc     = make_syscall(480)
local sc_shm_open   = make_syscall(482)
local sc_shm_unlink = make_syscall(483)

local O_RDWR  = 0x0002
local O_CREAT = 0x0200
local O_EXCL  = 0x0800
local MAP_SHARED = 0x0001
local PAGE = 0x4000

local function call1(fn, label)
    label = label or "call"
    print("  [BEFORE] " .. label)
    local ok, rv = pcall(fn)
    local n = ok and to_num(rv) or -999
    print("  [AFTER ] " .. label .. " ok=" .. tostring(ok) .. " rv=" .. n)
    return ok, n
end

local ok_pg, rv_pg = pcall(function() return sc_getpid() end)
local mypid = ok_pg and to_num(rv_pg) or 0
local name = "/p932b_" .. tostring(mypid)
print("name = " .. name)
print("")

local ma = 0
local mb = 0
local fd_a = -1
local fd_b = -1
local fd_c = -1

--------------------------------------------------------------------
-- A
--------------------------------------------------------------------
print("--- A: create / ftruncate / mmap / write ---")
local ok_a, a = call1(function()
    return sc_shm_open(name, uint64(O_RDWR + O_CREAT + O_EXCL), uint64(0x1FF))
end, "shm_open O_CREAT|O_EXCL")
fd_a = ok_a and a or -1

if fd_a >= 0 then
    call1(function() return sc_ftrunc(uint64(fd_a), uint64(PAGE)) end, "ftruncate 16K")
    local ok_m, m = call1(function()
        return sc_mmap(uint64(0), uint64(PAGE), uint64(3), uint64(MAP_SHARED),
            uint64(fd_a), uint64(0))
    end, "mmap MAP_SHARED")
    ma = ok_m and m or 0
    if ma > 0 then
        wq(ma, uint64(0x1122334455667788))
        print("  A wrote 0x1122334455667788, reads " .. hex(rq(ma)))
    end
    print("")
end

--------------------------------------------------------------------
-- B
--------------------------------------------------------------------
print("--- B: second open, shared object ---")
if fd_a >= 0 then
    local ok_b, b = call1(function()
        return sc_shm_open(name, uint64(O_RDWR), uint64(0))
    end, "shm_open O_RDWR (second)")
    fd_b = ok_b and b or -1
    if fd_b >= 0 then
        local ok_m2, m2 = call1(function()
            return sc_mmap(uint64(0), uint64(PAGE), uint64(3), uint64(MAP_SHARED),
                uint64(fd_b), uint64(0))
        end, "mmap second fd")
        mb = ok_m2 and m2 or 0
        if mb > 0 and ma > 0 then
            print("  B sees   " .. hex(rq(mb)))
            wq(mb, uint64(0x99AABBCCDDEEFF00))
            print("  B wrote 0x99AABBCCDDEEFF00")
            print("  A sees   " .. hex(rq(ma)))
        end
    end
    print("")
end

--------------------------------------------------------------------
-- C
--------------------------------------------------------------------
print("--- C: unlink with fd and mapping live ---")
if fd_a >= 0 then
    call1(function() return sc_shm_unlink(name) end, "shm_unlink")
    local ok_re, re = call1(function()
        return sc_shm_open(name, uint64(O_RDWR), uint64(0))
    end, "reopen after unlink")
    if ok_re and re >= 0 then
        print("  reopen SUCCEEDED after unlink fd=" .. re)
        pcall(function() return sc_close(uint64(re)) end)
    end
    if ma > 0 then
        print("  old mapping still reads " .. hex(rq(ma)))
    end
    print("")
end

--------------------------------------------------------------------
-- D
--------------------------------------------------------------------
print("--- D: recreate the same name ---")
if fd_a >= 0 then
    local ok_c, c = call1(function()
        return sc_shm_open(name, uint64(O_RDWR + O_CREAT), uint64(0x1FF))
    end, "shm_open O_CREAT (recreate)")
    fd_c = ok_c and c or -1
    if fd_c >= 0 then
        call1(function() return sc_ftrunc(uint64(fd_c), uint64(PAGE)) end, "ftruncate 16K")
        local ok_m3, m3 = call1(function()
            return sc_mmap(uint64(0), uint64(PAGE), uint64(3), uint64(MAP_SHARED),
                uint64(fd_c), uint64(0))
        end, "mmap recreated fd")
        if ok_m3 and m3 > 0 then
            print("  recreated first qword " .. hex(rq(m3)) .. " (0 = new object)")
        end
    end
    print("")
end

--------------------------------------------------------------------
-- E
--------------------------------------------------------------------
print("--- E: error classes ---")
if fd_c >= 0 then
    call1(function() return sc_shm_unlink(name) end, "unlink recreated name")
end
call1(function() return sc_shm_unlink(name) end, "unlink again")
local missing = "/p932b_missing_" .. tostring(mypid)
call1(function() return sc_shm_unlink(missing) end, "unlink missing name")
call1(function() return sc_shm_open(missing, uint64(O_RDWR), uint64(0)) end,
    "open missing name")

print("")
print("--- cleanup ---")
for _, fd in ipairs({fd_a, fd_b, fd_c}) do
    if fd and fd >= 0 then pcall(function() return sc_close(uint64(fd)) end) end
end
if ma > 0 then pcall(function() return sc_munmap(uint64(ma), uint64(PAGE)) end) end
if mb > 0 then pcall(function() return sc_munmap(uint64(mb), uint64(PAGE)) end) end
print("cleanup done")

local ok_can, canary = pcall(function() return sc_getpid() end)
print("final canary: " .. tostring(to_num(canary)))
print("")
print("=== PROBE 932b COMPLETE ===")
