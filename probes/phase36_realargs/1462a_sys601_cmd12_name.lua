-- CRASH_CLASS: LOW
-- PROBE 1462a: sys 601 command 0x12 answers ENOENT -- is arg1 a name?
--
-- Context:
--   1461a swept 601 commands 0x0D-0x27 with the shape 601(cmd, 0, buf, 0x100) and recorded:
--     0x0D rv=0   0x0E EFAULT  0x0F EPERM   0x10 EINVAL
--     0x12 ENOENT 0x13 rv=0    0x14 rv=0     0x15 EINVAL
--     0x16 ENOSYS 0x17 ENOSYS  0x18 EPERM   0x19 rv=0
--     0x1A EFAULT 0x1C kills (0x1B was already known lethal)
--   none of the rv=0 commands wrote a byte into a 0x800 sentinel buffer.
--
--   0x12 is the interesting one: the same command answered EINVAL when 1355a sent
--   601(0x12, 0, struct20) and ENOENT when 1461a sent 601(0x12, 0, buf, 0x100), so the refusal
--   depends on the argument shape rather than on a fixed gate, and ENOENT is the errno a name
--   lookup produces.  If arg1 is a name, a resolvable one should change the errno or hand back a
--   handle, which would open a device-object path inside a handler that otherwise looks closed.
--
--   The 13.60 body has a magic-gated branch that copies a caller struct into proc+0x578..0x590
--   (docs/dumps_13.60/kernel_text.bin VA 0xffffffff8b6614c0) but 1460a showed the magic does not
--   open it, so this probe does not rely on that branch.
--
-- -- prior art:
--   results/phase36_realargs/1461a_sys601_matrix_tail_20261109_175346.txt (the rows above)
--   results/phase36_realargs/1460a_sys601_magic_tag_20261109_175209.txt (magic does not open 0x12)
--   results/phase35_dead_end_reruns/1355a_sys601_cmd12_shape_20261109_110324.txt (EINVAL shape)
--   results/phase36_realargs/1383a_601_command_matrix_*.txt
--   docs/MDBG_601_COMMAND_MAP_14_10.md

print("=== PROBE 1462a: SYS 601 COMMAND 0x12 AND NAMES ===")
print("")

local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end if type(v)=="table" and v.h then return v.h*4294967296+v.l end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function as_addr(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function rd(a) local ok,v=pcall(function() return memory.read_dword(uint64(a)) end) if ok then return to_num(v) end return nil end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function wb(a,v) pcall(function() memory.write_byte(uint64(a),v) end) end
local function es() local ok,s=pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end

local function str_addr(s, at)
    local a = at or as_addr(memory.alloc(#s + 1))
    for i = 1, #s do wb(a + i - 1, string.byte(s, i)) end
    wb(a + #s, 0)
    return a
end

local PID = to_num(mk(20)())
print(string.format("[0] pid=%d", PID))

local sc601 = mk(601)
local buf = memory.alloc(0x200)
local BUF = as_addr(buf)
for o = 0, 0x1F8, 8 do wq(BUF + o, 0) end

local function call(tag, cmd, a1, a2, a3)
    local ok, rv = pcall(function() return sc601(uint64(cmd), uint64(a1), uint64(a2), uint64(a3), uint64(0), uint64(0)) end)
    if not ok then print(string.format("[%s] EXC %s", tag, tostring(rv))); return end
    local r = to_num(rv)
    if r == -1 then print(string.format("[%s] rv=-1 errno=%s", tag, es()))
    else print(string.format("[%s] rv=%d  out=%08X %08X", tag, r, rd(BUF) or 0, rd(BUF + 4) or 0)) end
end

print("[A] control 601(0x00, buf)")
call("A", 0x00, BUF, 0, 0)
print("")

-- name candidates, in one buffer so only the pointer changes
local namebuf = memory.alloc(0x200)
local NB = as_addr(namebuf)
local names = { "dce", "gc", "ajm", "dmem0", "notification0", "/dev/dce", "/dev/gc", "/dev/dmem0", "0", "" }
print("[B] 601(0x12, name, buf, 0x100)")
for i = 1, #names do
    str_addr(names[i], NB)
    print(string.format("[B%d] name=%q", i, names[i]))
    call("B" .. i, 0x12, NB, BUF, 0x100)
end
print("")

print("[C] 601(0x12, N, buf, N) for small integers, to see the errno ladder")
for _, n in ipairs({ 0, 1, 2, 3, 0x10, 0x100 }) do
    print(string.format("[C] arg1=%d", n))
    call("C", 0x12, n, BUF, 0x20)
end
print("")

print("[D] 0x13 and 0x14 returned 0 with no write -- try a struct pointer in arg2")
for _, c in ipairs({ 0x13, 0x14, 0x19 }) do
    for o = 0, 0x1F8, 8 do wq(BUF + o, 0) end
    print(string.format("[D] cmd=0x%02X", c))
    call("D", c, BUF, 0x100, 0)
    print(string.format("[D] out=%08X %08X %08X %08X", rd(BUF) or 0, rd(BUF + 4) or 0, rd(BUF + 8) or 0, rd(BUF + 12) or 0))
end
print("")

print(string.format("[Z] alive pid=%d (was %d)", to_num(mk(20)()), PID))
print("")
print("=== PROBE 1462a COMPLETE ===")
