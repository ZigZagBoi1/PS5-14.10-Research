-- P3: thr_create valid-context functional test (PR#71 recipe)
-- Question: can we spawn 2 live threads with valid ucontexts? Gate for all
-- race probes. Valid ctx per PR#71/dump: +0x108=0x480, +0x0d0<=7,
-- +0x110=0x10000, +0x118=0x20000, RIP=jmp$ gadget addr, RSP=alloced stack.
print("=== P3: thr_create valid context, live thread ===")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
syscall.resolve({ thr_create = 430, thr_self = 432, thr_exit = 431 })
-- jmp $ gadget: find in eboot? Use the loader's own gadget table if present
local rip_gadget
if gadgets and gadgets["ret"] then
    rip_gadget = gadgets["ret"]
    print("using gadgets.ret @ 0x" .. string.format("%x", to_num(rip_gadget)))
else
    print("no gadget table; aborting")
    return
end
local ctx = memory.alloc(0x600)
-- zero it
for i = 0, 0x500, 8 do memory.write_qword(ctx + i, 0) end
-- validated fields (offsets per 58e header notes)
memory.write_qword(ctx + 0x108, 0x480)
memory.write_dword(ctx + 0x0d0, 0)
memory.write_qword(ctx + 0x110, 0x10000)
memory.write_qword(ctx + 0x118, 0x20000)
-- context regs: uc_mcontext offsets unknown exactly; PR#71 parked children
-- via RSP+0 = jmp$. We place gadget at mc RIP slot — try common offsets by
-- writing a distinctive marker and letting the ID-oracle tell us (tid out).
local idbuf = memory.alloc(8)
memory.write_qword(idbuf, 0)
local ok, rv = pcall(function() return to_num(syscall.thr_create(ctx, idbuf, 0)) end)
print("thr_create rv=" .. tostring(rv) .. " tid_out=" .. tostring(to_num(memory.read_qword(idbuf))))
sleep(100, "ms")
print("still alive: pid=" .. to_num(syscall.getpid()))
print("P3_DONE")
