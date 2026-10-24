-- CRASH_CLASS: LOW
-- PROBE 526b: does the aio id space reuse a freed slot?
--
-- Context: 526a raced three deleting children against 400 parent creates and
-- saw no 0x80020010, i.e. no second lookup ever saw a swapped slot. The likely
-- reason is that a new create does not take a just-freed slot (the id cursor
-- only advances), so a slot is only reused when the cursor wraps onto it.
-- This probe measures exactly that: create, poll, delete in a loop and report
-- the id sequence, repeats, and the gap between a freed id and its reappearance.

print("=== PROBE 526b: AIO ID REUSE ===")
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
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function hex(v) return string.format("%08X", (v or 0) % 4294967296) end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("[0] pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local sc_create = mk(669)
local sc_poll   = mk(664)
local sc_delete = mk(662)
local data = memory.alloc(0x100)
local out_id = memory.alloc(0x40)
local cell = memory.alloc(16)
local st = memory.alloc(16)

local function cycle()
    wq(N(out_id), uint64(0))
    local ok, rv = pcall(function()
        return sc_create(uint64(1), uint64(N(data)), uint64(1), uint64(1), uint64(N(out_id)))
    end)
    if not ok or N(rv) ~= 0 then return nil, "create" end
    local id = rd(N(out_id))
    wd(N(cell), id)
    wd(N(st), 0xCCCCCCCC)
    pcall(function() sc_poll(uint64(N(cell)), uint64(1), uint64(N(st))) end)
    local ps = rd(N(st))
    wd(N(st), 0xCCCCCCCC)
    pcall(function() sc_delete(uint64(N(cell)), uint64(1), uint64(N(st))) end)
    local ds = rd(N(st))
    return id, ps, ds
end

print("[A] create/poll/delete x 24, ids in decimal and hex")
local seen, order = {}, {}
for i = 1, 24 do
    local id, ps, ds
    local ok = pcall(function() id, ps, ds = cycle() end)
    if not ok or id == nil then print(string.format("    %d: FAILED ps=%s ds=%s", i, tostring(ps), tostring(ds))); break end
    local tag = ""
    if seen[id] then tag = " REUSE gap=" .. (i - seen[id]) end
    seen[id] = i
    order[#order + 1] = id
    print(string.format("    %d: id=%d %s ps=%s ds=%s%s", i, id, hex(id), hex(ps), hex(ds), tag))
    if not alive() then print("    DIED"); return end
end

print("")
print("[B] keep 40 alive, then delete them and watch which ids come back")
local kept = {}
for i = 1, 40 do
    wq(N(out_id), uint64(0))
    local ok, rv = pcall(function()
        return sc_create(uint64(1), uint64(N(data)), uint64(1), uint64(1), uint64(N(out_id)))
    end)
    if not ok or N(rv) ~= 0 then print("    create failed at " .. i); break end
    local id = rd(N(out_id))
    wd(N(cell), id)
    wd(N(st), 0xCCCCCCCC)
    pcall(function() sc_poll(uint64(N(cell)), uint64(1), uint64(N(st))) end)
    kept[#kept + 1] = id
end
print(string.format("    kept=%d first=%s last=%s span=%d", #kept, hex(kept[1]), hex(kept[#kept]), (kept[#kept] or 0) - (kept[1] or 0)))
for i = 1, #kept do
    wd(N(cell), kept[i])
    wd(N(st), 0xCCCCCCCC)
    pcall(function() sc_delete(uint64(N(cell)), uint64(1), uint64(N(st))) end)
end
local back = {}
for i = 1, 40 do
    local id = cycle()
    if id == nil then break end
    if kept_set == nil then kept_set = {}; for _, k in ipairs(kept) do kept_set[k] = true end end
    if kept_set[id] then back[#back + 1] = id end
end
print(string.format("    re-created ids that matched a deleted one: %d of 40", #back))
if #back > 0 then print("    first reuses: " .. hex(back[1]) .. " " .. hex(back[2] or 0)) end
print(string.format("    alive=%s", tostring(alive())))
