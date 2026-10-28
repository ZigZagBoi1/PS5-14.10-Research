-- CRASH_CLASS: MODERATE
-- PROBE 811a: what does the id generator do when every slot is occupied?
--
-- Context: an id is (slot | gen<<13); the slot field is 16 bits and the gen
-- field 3 bits (561a wrapped 0x205 through gens 0..7).  Every id seen stayed
-- inside a narrow band (0x2xx-0x6xx slots), so the generator allocates from a
-- bounded slot space.  Nobody has tested the boundary: if it wraps to a slot
-- that is still occupied, two live objects share a slot and an id can name the
-- wrong object.  This probe creates live objects until a create fails or a
-- duplicate id appears, printing every milestone.

print("=== PROBE 811a: AIO SLOT EXHAUSTION ===")
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

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("[0] pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local data   = memory.alloc(0x100)
local out_id = memory.alloc(0x40)
local poll_out = memory.alloc(0x40)
local cell   = memory.alloc(16)

local sc_create = mk(669)
local sc_poll   = mk(664)

local function create_one()
    for i = 0, 0xFC, 4 do wd(N(data) + i, 0) end
    wq(N(out_id), uint64(0))
    local ok, rv = pcall(function()
        return sc_create(uint64(1), uint64(N(data)), uint64(1), uint64(1), uint64(N(out_id)))
    end)
    if not ok then return -1, "pcall" end
    local r = N(rv)
    if r ~= 0 then return -1, r end
    local id = rd(N(out_id))
    wd(N(cell), id)
    wd(N(poll_out), 0xCCCCCCCC)
    pcall(function() sc_poll(uint64(N(cell)), uint64(1), uint64(N(poll_out))) end)
    return id, r
end

local TARGET = 8400
local seen = {}
local ids = {}
local dup = 0
local dups = {}
local fails = 0
local first_fail = -1
local minid, maxid = 0x7FFFFFFF, -1

print(string.format("[A] creating up to %d live objects", TARGET))
local t0 = os.clock()
for i = 1, TARGET do
    local id, why = create_one()
    if id == nil or id < 0 then
        fails = fails + 1
        if first_fail < 0 then first_fail = i end
        if fails > 4 then
            print(string.format("    stopping at %d (create refused, rv=%s)", i - 1, tostring(why)))
            break
        end
    else
        if seen[id] then
            dup = dup + 1
            if #dups < 12 then dups[#dups + 1] = string.format("%06X@%d/#%d", id, i, seen[id]) end
        else
            seen[id] = i
        end
        ids[#ids + 1] = id
        if id < minid then minid = id end
        if id > maxid then maxid = id end
    end
    if i % 1000 == 0 then
        print(string.format("    %d created fails=%d dup=%d last=%06X alive=%s t=%.1fs",
            #ids, fails, dup, id or 0, tostring(alive()), os.clock() - t0))
    end
    if not alive() then print("DEAD while creating"); return end
end

print(string.format("[B] created=%d fails=%d first_fail=%d dup=%d", #ids, fails, first_fail, dup))
if #ids > 0 then
    print(string.format("    id range %06X .. %06X", minid, maxid))
    print(string.format("    first=%06X second=%06X last=%06X", ids[1], ids[2] or 0, ids[#ids]))
end
if dup > 0 then
    print("    DUPLICATE IDS: " .. table.concat(dups, " "))
end

-- slot histogram over the live set
local slots = {}
for _, id in ipairs(ids) do
    local s = id % 0x2000
    slots[s] = (slots[s] or 0) + 1
end
local ns, worst, worstn = 0, 0, 0
for s, n in pairs(slots) do
    ns = ns + 1
    if n > worstn then worst, worstn = s, n end
end
print(string.format("[C] distinct slots=%d worst=%04X x%d", ns, worst, worstn))

print("[D] health: delete the oldest live id")
wd(N(cell), ids[1]); wd(N(poll_out), 0xCCCCCCCC)
local sd = memory.alloc(8)
wd(N(sd), 0xCCCCCCCC)
local sc_del = mk(662)
local ok, r = pcall(function() return sc_del(uint64(N(cell)), uint64(1), uint64(N(sd))) end)
print(string.format("    delete %06X rv=%s status=%08X alive=%s", ids[1], tostring(ok), rd(N(sd)) or 0, tostring(alive())))

print("[E] create one more and compare with the id we just freed")
local nid = create_one()
print(string.format("    new id=%06X  (freed was %06X) alive=%s", nid or 0, ids[1], tostring(alive())))
print("")
print("[*] alive pid=" .. N(native.fcall_with_rax(stub, 20)))
