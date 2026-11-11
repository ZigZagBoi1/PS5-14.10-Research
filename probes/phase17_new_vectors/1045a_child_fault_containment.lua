-- CRASH_CLASS: HIGH
-- PROBE 1045a: is a child-thread fault survivable?
-- 1044a's child stopped writing status words after ~253 rounds while the process stayed alive.
-- If a child that faults is reaped without killing the process, every dangerous syscall becomes
-- testable from a child without losing the loader.  Phase A faults in userland (ret to 0x1000);
-- phase B does the same under the loader's signal handler.
print("=== PROBE 1045a: child fault containment ===")
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
local store   = find_pat(ebase, 0x494000, string.char(0x48, 0x89, 0x07, 0xC3))
print(string.format("[0] pid=%d eboot=%08X g=%s/%s/%s", to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20)),
    ebase, tostring(pop_rax), tostring(pop_rdi), tostring(store)))
if not (pop_rax and pop_rdi and store) then print("[!] gadget missing"); return end

local function mmap(px)
    local _, a = pcall(function() return mk(477)(uint64(0), uint64(px), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
    return to_num(a)
end
local Ctx = { MAGIC = 0x108, TYPE = 0x110, CS = 0x0C0, RIP = 0x0E0, RSP = 0x0F8, SS = 0x100,
              RDI = 0x048, RSI = 0x050, RDX = 0x058, RAX = 0x078 }
local block = mmap(0x40000)
local OUT = mmap(0x4000)
print(string.format("[A] block=%08X OUT=%08X", block, OUT))
if block == 0 or OUT == 0 then print("[!] mmap failed"); return end

local start = block + 0x4000
local function put(i, v) wq(start + 8 + i * 8, uint64(v)) end
put(0, pop_rax); put(1, 20); put(2, fn)
put(3, pop_rdi); put(4, OUT); put(5, store)
put(6, 0x1000)                    -- ret into an unmapped page: userland fault
local ctx = memory.alloc(0x500); zero(ctx, 0x500)
wq(ctx + Ctx.MAGIC, uint64(0x480)); wq(ctx + Ctx.TYPE, uint64(0x10000))
wq(ctx + Ctx.CS, uint64(0x43)); wq(ctx + Ctx.SS, uint64(0x3B))
wq(ctx + Ctx.RIP, uint64(fn)); wq(ctx + Ctx.RSP, uint64(start + 8))
wq(ctx + Ctx.RAX, uint64(20))
local tb = memory.alloc(8); wq(tb, uint64(0))
wd(OUT, 0)
local oksp, rvsp = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
print(string.format("[S] spawn ok=%s rv=%s", tostring(oksp), tostring(to_num(rvsp))))
if not oksp then print("[!] spawn failed"); return end

local ts = memory.alloc(16)
wq(ts, 0); wq(ts + 8, 300000000)
pcall(function() mk(240)(uint64(ts), uint64(0)) end)
print(string.format("[B] child marker=%d (pid was %d)", rd(OUT) or -1, to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
local ok2 = pcall(function() return mk(20)(uint64(0)) end)
print(string.format("[B] parent syscall after child fault ok=%s", tostring(ok2)))

-- phase B: same fault with a handler installed for SIGSEGV (11)
local sa = memory.alloc(0x100); zero(sa, 0x100)
local oksig = pcall(function() return mk(416)(uint64(11), uint64(0), uint64(sa)) end)
print(string.format("[C] sigaction(11,NULL,old) ok=%s", tostring(oksig)))
local block2 = mmap(0x40000)
local OUT2 = mmap(0x4000)
local start2 = block2 + 0x4000
local function put2(i, v) wq(start2 + 8 + i * 8, uint64(v)) end
put2(0, pop_rax); put2(1, 20); put2(2, fn)
put2(3, pop_rdi); put2(4, OUT2); put2(5, store)
put2(6, 0x2000)
local ctx2 = memory.alloc(0x500); zero(ctx2, 0x500)
wq(ctx2 + Ctx.MAGIC, uint64(0x480)); wq(ctx2 + Ctx.TYPE, uint64(0x10000))
wq(ctx2 + Ctx.CS, uint64(0x43)); wq(ctx2 + Ctx.SS, uint64(0x3B))
wq(ctx2 + Ctx.RIP, uint64(fn)); wq(ctx2 + Ctx.RSP, uint64(start2 + 8))
wq(ctx2 + Ctx.RAX, uint64(20))
local tb2 = memory.alloc(8); wq(tb2, uint64(0))
local oksp2, rvsp2 = pcall(function() return mk(430)(uint64(ctx2), uint64(tb2), uint64(0)) end)
print(string.format("[C] spawn2 ok=%s rv=%s", tostring(oksp2), tostring(to_num(rvsp2))))
wq(ts, 0); wq(ts + 8, 300000000)
pcall(function() mk(240)(uint64(ts), uint64(0)) end)
print(string.format("[C] child2 marker=%d", rd(OUT2) or -1))
print("[Z] alive pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
