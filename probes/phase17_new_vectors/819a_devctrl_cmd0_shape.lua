-- CRASH_CLASS: RISKY
-- PROBE 819a: one 622 call, command 0, with a real buffer in every pointer slot
--
-- Context: probe 818a's shape sweep died on its very first shape for syscall
-- 622 - all six arguments zero - and the console powered off, which is the
-- panic path, not a process kill.
--
-- The 13.60 entry (offset 0x7dcd40) decodes as:
--   7DCD66  mov r14d,[rsi]        ; command
--   7DCD69  mov r15d,[rsi+8]      ; arg2
--   7DCD6D  mov r13,[rsi+0x18]    ; arg4 (a user pointer)
--   7DCD71  mov r12,[rsi+0x20]    ; arg5 (a length, must be <= 0x40)
--   7DCD85  cmp r12,0x40 / jbe    ; over 0x40 -> 0x800E0001
--   7DCE02  lea eax,[r14-0x100] / cmp eax,0x33 / ja   ; 0x100..0x133 -> bitmap
--   7DCED7  mov ecx,r14d                              ; otherwise: raw index
--   7DCEE1  movsxd rcx,[rdx+rcx*4] / add rcx,rdx / jmp rcx
--
-- The upper bound is checked and the lower bound is not, so commands below
-- 0x100 index the same table.  Whether the panic is the dispatch itself or a
-- handler dereferencing our NULL arg4 cannot be told from the capture, so this
-- probe sends exactly one call, command 0, with mapped memory in arg3, arg4 and
-- arg5, and prints a marker immediately before and after.
--
-- One call only: if this panics again, the console powers off and nothing else
-- in this file runs anyway.

print("=== PROBE 819a: syscall 622 command 0 with real buffers ===")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n)
    local t={}
    for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n
    setmetatable(t,getmetatable(syscall.pipe))
    return t
end
local out = memory.alloc(0x4000)
local buf = memory.alloc(0x4000)
for i=0,0x3FFC,4 do
    memory.write_dword(out+i, 0)
    memory.write_dword(buf+i, 0x41414141)
end
print(string.format("[A] pid=%d out=%X buf=%X", to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20)), to_num(out), to_num(buf)))

local sc = mk(622)
print("[B] control: 622(command=0x100, arg2=0, arg3=out, arg4=buf, arg5=4)")
local ok, rv = pcall(function() return sc(uint64(0x100), uint64(0), uint64(out), uint64(buf), uint64(4), uint64(0)) end)
if ok then
    print(string.format("[C] control ret=%d out[0]=%08X out[4]=%08X buf[0]=%08X",
        to_num(rv), to_num(memory.read_dword(out)), to_num(memory.read_dword(out+4)), to_num(memory.read_dword(buf))))
else
    print("[C] control pcall failed")
end
print("[D] calling 622(command=0, arg2=0, arg3=out, arg4=buf, arg5=4)")
ok, rv = pcall(function() return sc(uint64(0), uint64(0), uint64(out), uint64(buf), uint64(4), uint64(0)) end)
if ok then
    print(string.format("[E] cmd0 ret=%d out[0]=%08X out[4]=%08X buf[0]=%08X",
        to_num(rv), to_num(memory.read_dword(out)), to_num(memory.read_dword(out+4)), to_num(memory.read_dword(buf))))
else
    print("[E] cmd0 pcall failed")
end
print("[F] survived")
