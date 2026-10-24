-- CRASH_CLASS: MODERATE
-- PROBE 547a: aio_get_data (665), the debug getter
--
-- Context: 669 (aio_submit_cmd) allocates and never submits on 14.10, 662
-- deletes, 664 polls. 665 is aio_get_data and has never been called. In the
-- 14.20 note it is one of the "aio debug getters" that changed, so it reads
-- some per-request state back out.
--
-- This probe creates one completed request, polls it, then calls 665 with
-- several argument shapes against a canary page and prints everything that
-- changed.

print("=== PROBE 547a: AIO GET DATA ===")
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

local sc_create = mk(669)
local sc_poll   = mk(664)
local sc_delete = mk(662)
local sc_get    = mk(665)

local data = memory.alloc(0x100)
local out_id = memory.alloc(0x40)
local cell = memory.alloc(16)
local poll_out = memory.alloc(0x40)
local out = memory.alloc(0x400)

for i = 0, 0xFC, 4 do wd(N(data) + i, 0x41414141) end
wq(N(out_id), uint64(0))
local rv = N(sc_create(uint64(1), uint64(N(data)), uint64(1), uint64(1), uint64(N(out_id))))
local id = rd(N(out_id)) or 0
wd(N(cell), id)
wd(N(poll_out), 0xCCCCCCCC)
pcall(function() sc_poll(uint64(N(cell)), uint64(1), uint64(N(poll_out))) end)
print(string.format("[A] create ret=%d id=%08X poll=%08X", rv, id, rd(N(poll_out)) or 0))

local function dump(tag, ret)
    local line = string.format("%s ret=%d", tag, ret)
    for i = 0, 0x3C, 4 do
        local v = rd(N(out) + i)
        if v ~= 0 then line = line .. string.format(" +%02X=%08X", i, v) end
    end
    print(line)
end

local function shape(tag, a1, a2, a3, a4)
    for i = 0, 0x3FC, 4 do wd(N(out) + i, 0) end
    local ret = -999
    pcall(function() ret = N(sc_get(a1, a2, a3, a4)) end)
    dump(tag, ret)
end

shape("[B] (ids,1,out)", uint64(N(cell)), uint64(1), uint64(N(out)), uint64(0))
shape("[C] (ids,1,out,0x400)", uint64(N(cell)), uint64(1), uint64(N(out)), uint64(0x400))
shape("[D] (id,out)", uint64(id), uint64(N(out)), uint64(0), uint64(0))
shape("[E] (ids,0,out)", uint64(N(cell)), uint64(0), uint64(N(out)), uint64(0))

print("[F] deleting the id and asking again")
local st = memory.alloc(0x40)
wd(N(st), 0xCCCCCCCC)
pcall(function() sc_delete(uint64(N(cell)), uint64(1), uint64(N(st))) end)
print(string.format("    delete status=%08X", rd(N(st)) or 0))
shape("[G] (ids,1,out) after delete", uint64(N(cell)), uint64(1), uint64(N(out)), uint64(0))
str = nil
print("=== DONE ===")
