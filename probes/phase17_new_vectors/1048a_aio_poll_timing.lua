-- CRASH_CLASS: LOW
-- PROBE 1048a: what does a poll do to the entry, and how long is a completed object deletable?
-- 1046a showed create -> poll -> delete answers 0.  In 1047a the same pair, separated by the
-- time it takes to build a 1.4 MB chain, answered 0x80020003.  Measure the window and the
-- state transitions: immediate delete, delayed delete, double delete, and the id before/after
-- the poll.
print("=== PROBE 1048a: poll/delete timing and state ===")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(v) or 0
end
local function mk(n) local t = {} for k, v in pairs(syscall.pipe) do t[k] = v end t.syscall_no = n setmetatable(t, getmetatable(syscall.pipe)) return t end
local function rd(a) local o, v = pcall(function() return memory.read_dword(a) end) if o then return to_num(v) end end
local function rq(a) local o, v = pcall(function() return memory.read_qword(a) end) if o then return to_num(v) end end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function zero(a, n) pcall(function() for i = 0, n - 4, 4 do memory.write_dword(a + i, 0) end end) end
print("[0] pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
local page = to_num(select(2, pcall(function() return mk(477)(uint64(0), uint64(0x20000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)))
if page == 0 then print("[!] mmap failed"); return end
zero(page, 0x20000)
local D, OUT, ST, PO = page, page + 0x4000, page + 0x8000, page + 0xC000
local sc669, sc662, sc664 = mk(669), mk(662), mk(664)
local ts = memory.alloc(16)
local function sleep_ms(ms) wq(ts, 0); wq(ts + 8, ms * 1000000); pcall(function() mk(240)(uint64(ts), uint64(0)) end) end
local function create()
    wd(D + 0x00, 0); wd(D + 0x08, 0); wd(D + 0x10, 0); wd(D + 0x18, 0); wd(D + 0x20, -1); wd(D + 0x24, 0)
    wq(OUT, uint64(0))
    local ok, rv = pcall(function() return sc669(uint64(0x1001), uint64(D), uint64(1), uint64(1), uint64(OUT)) end)
    return ok, to_num(rv), rd(OUT) or 0
end
local function poll(id)
    wq(PO, uint64(id))
    wq(ST, uint64(0))
    local ok, rv = pcall(function() return sc664(uint64(PO), uint64(1), uint64(ST)) end)
    return ok, to_num(rv), rq(ST) or 0
end
local function del(id)
    wq(OUT, uint64(id))
    wq(ST, uint64(0))
    local ok, rv = pcall(function() return sc662(uint64(OUT), uint64(1), uint64(ST)) end)
    return ok, to_num(rv), rq(ST) or 0
end

-- A: immediate
local _, _, ida = create()
local _, _, spa = poll(ida)
local _, _, sda = del(ida)
print(string.format("[A] id=%08X poll=%08X del=%08X", ida, spa, sda))
local _, _, sda2 = del(ida)
print(string.format("[A] second del=%08X", sda2))

-- B: 200 ms late
local _, _, idb = create()
local _, _, spb = poll(idb)
sleep_ms(200)
local _, _, sdb = del(idb)
print(string.format("[B] id=%08X poll=%08X del_after_200ms=%08X", idb, spb, sdb))

-- C: 2000 ms late
local _, _, idc = create()
local _, _, spc = poll(idc)
sleep_ms(2000)
local _, _, sdc = del(idc)
print(string.format("[C] id=%08X poll=%08X del_after_2000ms=%08X", idc, spc, sdc))

-- D: no poll, delete twice
local _, _, idd = create()
local _, _, sdd = del(idd)
local _, _, sdd2 = del(idd)
print(string.format("[D] id=%08X del_no_poll=%08X del_again=%08X", idd, sdd, sdd2))

-- E: poll twice then delete
local _, _, ide = create()
local _, _, spe1 = poll(ide)
local _, _, spe2 = poll(ide)
local _, _, sde = del(ide)
print(string.format("[E] id=%08X poll1=%08X poll2=%08X del=%08X", ide, spe1, spe2, sde))

-- F: poll a batch of 4, delete each
local ids = {}
for i = 1, 4 do local _, _, id = create(); ids[i] = id end
wq(PO, uint64(ids[1])); wq(PO + 8, uint64(ids[2])); wq(PO + 16, uint64(ids[3])); wq(PO + 24, uint64(ids[4]))
wq(ST, uint64(0))
local okp, rvp = pcall(function() return sc664(uint64(PO), uint64(4), uint64(ST)) end)
local s1, s2, s3, s4 = rq(ST) or 0, rq(ST + 8) or 0, rq(ST + 16) or 0, rq(ST + 24) or 0
print(string.format("[F] batch poll ok=%s rv=%d st=%08X/%08X/%08X/%08X", tostring(okp), to_num(rvp), s1, s2, s3, s4))
for i = 1, 4 do
    local _, _, sd = del(ids[i])
    print(string.format("[F] del id=%08X st=%08X", ids[i], sd))
end
print("[Z] alive pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
