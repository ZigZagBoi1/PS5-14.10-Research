-- CRASH_CLASS: HIGH
-- PROBE 812c: feed a real osem id to the aio syscalls.
--
-- 812b established that 549 returns the created id in eax (0x2FFE, not 0 as the
-- earlier note claimed) and that 550 refuses an aio id with -1.  So the family
-- check exists in at least one direction.  This probe takes a real osem id and
-- asks the aio syscalls to interpret it: poll (664), delete (662), wait (663),
-- and then checks whether the osem object is still intact.

print("=== PROBE 812c: A REAL OSEM ID IN THE AIO CALLS ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end
    return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function hex(v) if v==nil then return "nil" end return string.format("%08X", v) end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("[0] pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local sc_create = mk(669)
local sc_poll   = mk(664)
local sc_wait   = mk(663)
local sc_delete = mk(662)
local sc_osenew = mk(549)
local sc_osedel = mk(550)
local sc_osepost = mk(555)

local data = memory.alloc(0x100)
local out_id = memory.alloc(0x40)
local cell = memory.alloc(16)
local out = memory.alloc(0x40)
local nm = memory.alloc(0x40)
local ts = memory.alloc(32)
wd(N(ts), 0); wd(N(ts) + 4, 200000000)   -- timespec-ish 200ms

local function wname(s)
    for i = 1, #s do pcall(function() memory.write_byte(nm + i - 1, s:byte(i)) end) end
    pcall(function() memory.write_byte(nm + #s, 0) end)
end
local function osem_create(name, flags, a3, a4)
    wname(name)
    local ok, rv = pcall(function() return sc_osenew(uint64(nm), uint64(flags), uint64(a3), uint64(a4)) end)
    if not ok then return nil, "pcall" end
    return N(rv)
end
local function aio_call(sc, id, extra)
    wd(N(cell), id); wd(N(out), 0xCCCCCCCC)
    local ok, rv
    if extra then
        ok, rv = pcall(function() return sc(uint64(N(cell)), uint64(1), uint64(N(out)), uint64(extra)) end)
    else
        ok, rv = pcall(function() return sc(uint64(N(cell)), uint64(1), uint64(N(out))) end)
    end
    return ok and N(rv) or "pcall", rd(N(out))
end

print("[A] create two osem objects")
local s1, s2 = osem_create("c812c_a", 1, 0, 4), osem_create("c812c_b", 1, 0, 4)
print("    id1 = " .. hex(s1) .. "   id2 = " .. hex(s2))
if not s1 then print("    aborting"); return end

print("")
print("[B] 664 (aio poll) on osem id1")
local p1, o1 = aio_call(sc_poll, s1)
print("    664 = " .. tostring(p1) .. " out=" .. hex(o1) .. " alive=" .. tostring(alive()))

print("")
print("[C] 663 (aio wait, 4th arg = timespec) on osem id1")
local p2, o2 = aio_call(sc_wait, s1, N(ts))
print("    663 = " .. tostring(p2) .. " out=" .. hex(o2) .. " alive=" .. tostring(alive()))

print("")
print("[D] 662 (aio delete) on osem id1")
local p3, o3 = aio_call(sc_delete, s1)
print("    662 = " .. tostring(p3) .. " out=" .. hex(o3) .. " alive=" .. tostring(alive()))

print("")
print("[E] is osem id1 still usable?  post then delete with its own syscalls")
local okp, rp = pcall(function() return sc_osepost(uint64(s1), uint64(1), uint64(0)) end)
print("    555(id1, 1) = " .. (okp and tostring(N(rp)) or "pcall") .. " alive=" .. tostring(alive()))
local okd, rkd = pcall(function() return sc_osedel(uint64(s1), uint64(0), uint64(0), uint64(0)) end)
print("    550(id1) = " .. (okd and tostring(N(rkd)) or "pcall") .. " alive=" .. tostring(alive()))
local okd2, rkd2 = pcall(function() return sc_osedel(uint64(s1), uint64(0), uint64(0), uint64(0)) end)
print("    550(id1) again = " .. (okd2 and tostring(N(rkd2)) or "pcall") .. " alive=" .. tostring(alive()))

print("")
print("[F] health: aio object and a fresh osem object")
local A = nil
for i = 0, 0xFC, 4 do wd(N(data) + i, 0) end
wq(N(out_id), uint64(0))
local okc, rvc = pcall(function()
    return sc_create(uint64(1), uint64(N(data)), uint64(1), uint64(1), uint64(N(out_id)))
end)
A = okc and N(rvc) == 0 and rd(N(out_id)) or nil
print("    aio A = " .. hex(A))
local s3 = osem_create("c812c_c", 1, 0, 4)
print("    osem id3 = " .. hex(s3))
local pd, od = aio_call(sc_delete, s3)
print("    662(id3) = " .. tostring(pd) .. " out=" .. hex(od) .. " alive=" .. tostring(alive()))
if A then
    local pl, ol = aio_call(sc_poll, A)
    print("    664(A) = " .. tostring(pl) .. " out=" .. hex(ol) .. " alive=" .. tostring(alive()))
end
print("")
print("[*] alive pid=" .. N(native.fcall_with_rax(stub, 20)))
