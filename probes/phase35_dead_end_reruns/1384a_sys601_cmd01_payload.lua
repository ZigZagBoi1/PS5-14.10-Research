-- CRASH_CLASS: MODERATE -- 601 cmd 0x01 is believed to be the attach/init call; a successful
-- attach may park the caller or install a session object. Nothing here has killed before.
-- PROBE 1384a: find the argument shape 601 cmd 0x01 accepts
--
-- Measured on 14.10 (results/phase35_dead_end_reruns/1383a_sys601_shape_matrix_20261109_133353.txt):
--   601(0x01, 0,   0)   -> -1 EFAULT(14)
--   601(0x01, B,   0)   -> -1
--   601(0x01, 0,   B)   -> -1
--   601(0x01, B,   B)   -> -1 EINVAL(22)     (B = 0x200 page painted 0xA5)
-- The 13.60 body for this command (results/kernel_handlers/asm/sys_601_deep.asm, body at
-- 0xca067f, shared with cmd 0x24 which differs only in r13 = 2 instead of 1) is:
--   movzx eax,BYTE [rbp-0x118] / mov r13b,al / inc r13d      ; r13 = 1 (cmd 0x01) or 2 (cmd 0x24)
--   copyin(arg1 -> [rbp-0xf0], 0x10)                          ; EFAULT on a null arg1
--   ... r12 = arg2 (NOT a pointer: it is a flags word) ...
--   mov rcx,[rbp-0xf0] / mov rdx,[rbp-0xe8]                   ; the two qwords of the struct
--   mov r8,r12 / shr r8,8 / bextr eax,r12d,0x206              ; bits 6-7 of arg2
--   test r12b,0x20 / jne 0xca19c3
--   ...
--   0xca1a16: mov ecx,eax / call 0xc9c9f0(r13, arg2>>8, bits 6-7)
--   0xca19c3: call 0xc9cf30(r13, arg2&1, bits 1-2, bits 3-5, arg2>>8, &[rbp-0x110])
--   a non-zero return is propagated, so EINVAL(22) is that helper refusing our flags, not a
--   refusal of the 16-byte struct.
-- On success the shared tail does `or QWORD [process+0x560],0x10000000` (0xca1ae5 block), i.e. it
-- sets an attach bit on the process. Every branch of the 601 family that answers with real data
-- (ca0a9a, ca197b, ca1b8b) needs the object at process+0x568, which this call is expected to
-- install - so a working 0x01 is the precondition for the only kernel-read-shaped site left.
--
-- Plan: sweep the flags word (arg2) over 14 values against a zeroed 16-byte struct, then sweep the
-- struct's two qwords against the flags value that got furthest. Every call prints rv + errno.
-- A return of 0 is the discovery; anything else is a data point about the predicate.
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1383a_sys601_shape_matrix_20261109_133353.txt
--   results/phase17_new_vectors/1192a_601_dispatcher_command.lua (skip list 0x03/0x04/0x08/0x0C/0x1B/0x27)
--   results/kernel_handlers/asm/sys_601_deep.asm (body 0xca067f, tail 0xca1a16/0xca19c3/0xca1ae5)
--   results/kernel_handlers/analysis/sys_601_deep.md (command map)

print("=== PROBE 1384a: 601 cmd 0x01 ARGUMENT SHAPE ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t = {} for k, v in pairs(syscall.pipe) do t[k] = v end t.syscall_no = n setmetatable(t, getmetatable(syscall.pipe)) return t end
local function es() local ok, s = pcall(function() return get_error_string() end) if ok and type(s) == "string" then return s end return "errno?" end
local function spin(n) local x = 0 for i = 1, n do x = x + i end return x end

-- syscall 0 is FreeBSD's indirect `syscall` dispatcher; calling it with zeros recurses and
-- kills the process (1384a run 1 died before its first line for exactly this reason). Never
-- call number 0.
local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local function trial(label, cmd, sptr, flags)
    local ok, rv = pcall(function()
        return mk(601)(uint64(cmd), uint64(sptr), uint64(flags), uint64(0), uint64(0), uint64(0))
    end)
    local r = ok and N(rv) or -99999
    print(string.format("  %-28s 601(0x%02X, %s, 0x%X) rv=%-8s %s", label, cmd, tostring(sptr), flags,
        tostring(r), ok and es() or "EXC"))
    return r
end

local S = memory.alloc(0x40)
local SU = N(S)

-- A: flags sweep against a zeroed struct
print("[A] flags sweep, struct = 16 zero bytes")
local FLAGS = {0, 1, 2, 3, 4, 8, 0x10, 0x20, 0x21, 0x80, 0xC0, 0x100, 0x1000, 0x10000, 0xFFFFFFFF, 0x206}
local best, bestv = 0, -99999
for i = 1, #FLAGS do
    pcall(function() memory.write_buffer(S, string.rep("\0", 0x40)) end)
    local r = trial("flags", 0x01, SU, FLAGS[i])
    if r == 0 then best = FLAGS[i] print("  *** ZERO RETURN ***") end
end

-- B: struct sweep at three flags values (0 = "none", 0x20 = the bit the body tests, 0xC0 = bits 6-7 = 3)
print("[B] struct qword sweep")
local STRUCTS = {
    {"zero",            0, 0},
    {"pid",             PID, 0},
    {"pid,pid",         PID, PID},
    {"1",               1, 0},
    {"0,1",             0, 1},
    {"0x1000",          0x1000, 0},
    {"pid,0x1000",      PID, 0x1000},
    {"all-ff",          0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
}
local FL3 = {0, 0x20, 0xC0}
for f = 1, #FL3 do
    for s = 1, #STRUCTS do
        pcall(function()
            memory.write_buffer(S, string.rep("\0", 0x40))
            memory.write_qword(S, uint64(STRUCTS[s][2]))
            memory.write_qword(S + 8, uint64(STRUCTS[s][3]))
        end)
        trial(STRUCTS[s][1], 0x01, SU, FL3[f])
    end
end

-- C: the 0x24 twin (same body, r13 = 2)
print("[C] cmd 0x24 twin at the same flags values")
for i = 1, #FLAGS do
    pcall(function() memory.write_buffer(S, string.rep("\0", 0x40)) end)
    trial("0x24 flags", 0x24, SU, FLAGS[i])
end

-- D: does anything changed in the meantime? the two commands that were gated before
print("[D] gate re-test")
local O = memory.alloc(0x200)
local OU = N(O)
pcall(function() memory.write_buffer(O, string.rep("\0", 0x200)) end)
trial("0x00 state", 0x00, OU, 0)
trial("0x0A eperm?", 0x0A, OU, 0)
trial("0x0E", 0x0E, OU, 0)
trial("0x12", 0x12, OU, 0)
local nz = 0
for j = 0, 31 do
    local ok, v = pcall(function() return N(memory.read_dword(OU + j * 4)) end)
    if ok and v ~= 0 then nz = nz + 1 end
end
print(string.format("  output page non-zero dwords = %d", nz))

print("=== PROBE 1384a COMPLETE ===")
