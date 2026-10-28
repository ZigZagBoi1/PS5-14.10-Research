-- CRASH_CLASS: MODERATE
-- PROBE 933a: shm refcount — does a mapping outlive its fd and its name?
--
-- Context: 932b established the shm object lifecycle on 14.10 is correct and
-- reachable: create -> ftruncate -> mmap(MAP_SHARED) -> write/read, second
-- open shares memory, unlink removes the name while the mapping stays valid,
-- and recreating the name yields a fresh zeroed object.
--
-- That raises the refcount question the lifecycle probe cannot answer: when
-- the fd is closed after unlink, what keeps the object alive — the mapping or
-- nothing? If the kernel frees the vm_object on last fd close while the
-- mapping still points at it, the next shm allocation can hand its pages back
-- and the stale mapping becomes a userland-visible UAF (write through the old
-- mapping to corrupt the new object, or read it for an info leak).
--
--   A) one object: map, unlink, close fd, recreate, compare both mappings
--   B) eight objects in sequence: any page reuse across stale mappings
--   C) mmap beyond the object size, then read only inside the first page
--
-- All reads stay inside the mapped region, so a refcount bug shows up as
-- wrong data, not as a bus fault.

print("=== PROBE 933a: SHM REFCOUNT / MAPPING LIFETIME ===")
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
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
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
local MAP_SHARED = 0x0001
local PAGE = 0x4000

local ok_pg, rv_pg = pcall(function() return sc_getpid() end)
local mypid = ok_pg and to_num(rv_pg) or 0

local function call1(fn, label)
    label = label or "call"
    print("  [BEFORE] " .. label)
    local ok, rv = pcall(fn)
    local n = ok and to_num(rv) or -999
    print("  [AFTER ] " .. label .. " ok=" .. tostring(ok) .. " rv=" .. n)
    return ok, n
end

local function make_obj(name, size)
    local ok, fd = pcall(function()
        return to_num(sc_shm_open(name, uint64(O_RDWR + O_CREAT), uint64(0x1FF)))
    end)
    if not ok or fd < 0 then return -1, 0 end
    pcall(function() return sc_ftrunc(uint64(fd), uint64(size)) end)
    local okm, addr = pcall(function()
        return to_num(sc_mmap(uint64(0), uint64(size), uint64(3),
            uint64(MAP_SHARED), uint64(fd), uint64(0)))
    end)
    if not okm or addr <= 0 then return fd, 0 end
    return fd, addr
end

local my = tostring(mypid)

--------------------------------------------------------------------
-- A: mapping outlives fd close after unlink
--------------------------------------------------------------------
print("--- A: map -> unlink -> close fd -> recreate ---")
local n1 = "/p933a_1_" .. my
local n2 = "/p933a_2_" .. my
local fd1, ma = make_obj(n1, PAGE)
print("  object 1 fd=" .. fd1 .. " map=" .. hex(ma))
if fd1 >= 0 and ma > 0 then
    wq(ma, uint64(0xAAAA0000AAAA0001))
    print("  wrote AAAA...0001, reads " .. hex(rd(ma)))

    call1(function() return sc_shm_unlink(n1) end, "unlink object 1")
    call1(function() return sc_close(uint64(fd1)) end, "close fd 1 (mapping still live)")
    print("  after close, mapping reads " .. hex(rd(ma)))

    local fd2, mb = make_obj(n2, PAGE)
    print("  object 2 fd=" .. fd2 .. " map=" .. hex(mb))
    if fd2 >= 0 and mb > 0 then
        wq(mb, uint64(0xBBBB0000BBBB0002))
        print("  wrote BBBB...0002 into object 2")
        print("  stale object-1 mapping reads   " .. hex(rd(ma)))
        print("  (0xAAAA... = refcount held; 0xBBBB... = pages reused)")
        call1(function() return sc_shm_unlink(n2) end, "unlink object 2")
        pcall(function() return sc_close(uint64(fd2)) end)
        pcall(function() return sc_munmap(uint64(mb), uint64(PAGE)) end)
    end
    pcall(function() return sc_munmap(uint64(ma), uint64(PAGE)) end)
end
print("")

--------------------------------------------------------------------
-- B: eight stale mappings, one live object
--------------------------------------------------------------------
print("--- B: eight stale mappings ---")
local stale = {}
for i = 1, 8 do
    local nm = "/p933a_b" .. i .. "_" .. my
    local fd, addr = make_obj(nm, PAGE)
    if fd >= 0 and addr > 0 then
        wq(addr, uint64(0x1000 + i))
        pcall(function() return sc_shm_unlink(nm) end)
        pcall(function() return sc_close(uint64(fd)) end)
        table.insert(stale, { addr = addr, tag = 0x1000 + i })
        print("  stale " .. i .. " map=" .. hex(addr) .. " tag=" .. hex(uint64(0x1000 + i)))
    else
        print("  stale " .. i .. " could not be created (fd=" .. fd .. ")")
    end
end

local fd_live, live = make_obj("/p933a_live_" .. my, PAGE)
print("  live object fd=" .. fd_live .. " map=" .. hex(live))
if fd_live >= 0 and live > 0 then
    wq(live, uint64(0xCCCC0000CCCC0003))
    local hits = 0
    for i, s in ipairs(stale) do
        local v = rd(s.addr)
        if v ~= nil and v ~= 0 and v ~= s.tag then
            print("  stale " .. i .. " changed: " .. hex(uint64(v)) ..
                " (was " .. hex(uint64(s.tag)) .. ")")
            hits = hits + 1
        end
    end
    print("  stale mappings that changed: " .. hits .. " / " .. #stale)
    pcall(function() return sc_shm_unlink("/p933a_live_" .. my) end)
    pcall(function() return sc_close(uint64(fd_live)) end)
    pcall(function() return sc_munmap(uint64(live), uint64(PAGE)) end)
end
for _, s in ipairs(stale) do
    pcall(function() return sc_munmap(uint64(s.addr), uint64(PAGE)) end)
end
print("")

--------------------------------------------------------------------
-- C: mapping longer than the object
--------------------------------------------------------------------
print("--- C: map 4x the object size ---")
local n3 = "/p933a_3_" .. my
local okc, fdc = pcall(function()
    return to_num(sc_shm_open(n3, uint64(O_RDWR + O_CREAT), uint64(0x1FF)))
end)
if okc and fdc >= 0 then
    pcall(function() return sc_ftrunc(uint64(fdc), uint64(PAGE)) end)
    local okm, addr = call1(function()
        return sc_mmap(uint64(0), uint64(PAGE * 4), uint64(3), uint64(MAP_SHARED),
            uint64(fdc), uint64(0))
    end, "mmap length 64K on a 16K object")
    if okm and addr > 0 then
        print("  first page reads " .. hex(rd(addr)))
        print("  second page reads " .. hex(rd(addr + PAGE)))
        pcall(function() return sc_munmap(uint64(addr), uint64(PAGE * 4)) end)
    end
    pcall(function() return sc_shm_unlink(n3) end)
    pcall(function() return sc_close(uint64(fdc)) end)
end

print("")
local ok_can, canary = pcall(function() return sc_getpid() end)
print("final canary: " .. tostring(to_num(canary)))
print("")
print("=== PROBE 933a COMPLETE ===")
