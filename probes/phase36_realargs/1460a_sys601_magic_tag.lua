-- CRASH_CLASS: MODERATE
-- PROBE 1460a: sys 601 command 0x12 with the magic tag from the 13.60 body
--
-- Context:
--   601 has answered -1 for almost every command on 14.10.  The 13.60 body shows why the tested
--   shapes could never have worked: the branch that copies a caller struct into the process write
--   slots is preceded by a magic compare, and the caller struct is not even read until it matches.
--
--   docs/dumps_13.60/kernel_text.bin, VA 0xffffffff8b6614c0 (601 handler 0xffffffff8b660630):
--
--       8b6614c1  cmp eax, 0xa0020102          <- MAGIC in eax
--       8b6614c6  jne 0xffffffff8b661838      -> refusal path
--       8b6614d5  lea rsi, [rip + ...]        (bzero the 0x20 stack struct)
--       8b6614e1  call bzero
--       8b6614f5  call 0xffffffff8ac19280     copyin(r12 = uap[2], rbp-0xf0, 0x20)
--       8b6614ff  jne 0xffffffff8b661848      -> return the copyin code
--       8b661518  call 0xffffffff8ae86a00     mtx_lock(proc+0x148)
--       8b66151d  mov rax, [proc+0x528]
--       8b661527  test eax, 0x400             <- refuses when this bit is already set
--       8b66152c  jne 0xffffffff8b661573
--       8b66152e  or rax, 0x1000000
--       8b661534  mov [proc+0x528], rax
--       8b661542  mov [proc+0x578], qword0    <- CALLER-CHOSEN pointer
--       8b661550  mov [proc+0x580], qword1    <- CALLER-CHOSEN pointer
--       8b66155e  mov [proc+0x588], qword2
--       8b66156c  mov [proc+0x590], qword3
--
--   The caller's arg2 (uap[2], the third argument) must be the struct pointer, so the call shape is
--   601(cmd, MAGIC, struct, ...).  1355a sent 601(0x12, 0, struct) and got -1 twice because arg1
--   was 0 and the magic compare refused before the copyin.
--
--   This probe sends the magic.  It does not try to trigger the consumer: the command that sets
--   the 0x400 bit also overwrites proc+0x578 (0x8b661d84 stores 0x16, 0x8b6622c1 stores a lock
--   address), so the caller pointer cannot survive to the consumer on this body.  What is measured
--   here is whether the magic opens the branch at all: rv=0 with the struct read is a handhold into
--   601's real command table, rv=-1 keeps 601 closed.
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1355a_sys601_cmd12_shape_20261109_110324.txt (arg1=0 -> -1 twice)
--   results/phase36_realargs/1383a (601 command matrix: 0x00 writes 0x100, 0x01 EINVAL/EFAULT,
--     0x02/0x05/0x06 ENOSYS, 0x07/0x09/0x0B rv=0 no write, 0x0A EPERM, 0x0C parks)
--   docs/MDBG_601_COMMAND_MAP_14_10.md
--   docs/dumps_13.60/kernel_text.bin (the body quoted above, VA 0xffffffff8b6614c0)

print("=== PROBE 1460a: SYS 601 COMMAND 0x12 WITH THE MAGIC TAG ===")
print("")

local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end if type(v)=="table" and v.h then return v.h*4294967296+v.l end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function as_addr(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function rd(a) local ok,v=pcall(function() return memory.read_dword(uint64(a)) end) if ok then return to_num(v) end return nil end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function es() local ok,s=pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end

local PID = to_num(mk(20)())
print(string.format("[0] pid=%d", PID))

local sc601 = mk(601)
local function call601(tag, a1, a2, a3, a4)
    local ok, rv = pcall(function() return sc601(uint64(a1), uint64(a2), uint64(a3), uint64(a4), uint64(0), uint64(0)) end)
    if not ok then print(string.format("[%s] EXC %s", tag, tostring(rv))); return nil end
    local r = to_num(rv)
    if r == -1 then print(string.format("[%s] rv=-1 errno=%s", tag, es()))
    else print(string.format("[%s] rv=%d", tag, r)) end
    return r
end

local buf = memory.alloc(0x100)
local BUF = as_addr(buf)
for o = 0, 0xF8, 8 do wq(BUF + o, 0) end

-- control: command 0x00 is known to return 0 and write 0x100 into arg1
print("[A] control: 601(0x00, buf)")
call601("A", 0x00, BUF, 0, 0)
print(string.format("[A] buf[0]=%s buf[4]=%08X", tostring(rd(BUF)), rd(BUF + 4) or 0))
print("")

-- the hypothesis: the magic lives in arg1
local MAGIC = 0xa0020102
print(string.format("[B] 601(0x12, 0x%08X, struct)  <- magic in arg1", MAGIC))
for o = 0, 0xF8, 8 do wq(BUF + o, 0) end
call601("B", 0x12, MAGIC, BUF, 0x20)
print("[B] struct unchanged? " .. string.format("%08X %08X", rd(BUF) or 0, rd(BUF + 4) or 0))
print("")

print("[C] same call again (the branch sets 0x1000000, the gate bit is 0x400)")
call601("C", 0x12, MAGIC, BUF, 0x20)
print("")

print("[D] byte-swapped magic 0x020102A0, for completeness")
call601("D", 0x12, 0x020102A0, BUF, 0x20)
print("")

print("[E] magic in arg2 instead (601(0x12, struct, MAGIC))")
call601("E", 0x12, BUF, MAGIC, 0)
print("")

print("[F] 0x11 with the magic, since 0x11 killed on a zero page in 1400a")
for o = 0, 0xF8, 8 do wq(BUF + o, 0) end
call601("F1", 0x11, MAGIC, BUF, 0)
call601("F2", 0x11, MAGIC, 0, 0)
print("")

-- if some command opened, the process is still here
print(string.format("[G] alive pid=%d (was %d)", to_num(mk(20)()), PID))
print("")
print("=== PROBE 1460a COMPLETE ===")
