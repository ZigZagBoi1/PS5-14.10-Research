-- CRASH_CLASS: LOW -- sys 601 only; no command here has killed with arg2 null
-- PROBE 1373a: does any 601 command move 0x1000 bytes through arg1?
--
-- 1371a, 1372a and 1372b only counted dwords that changed in arg1, which catches a
-- copyout and nothing else. The block they were looking for (results/kernel_handlers/
-- asm/sys_601_deep.asm:ca0d6c) loads rdi = r15 (arg1, a user address) and rsi = the
-- fresh 0x1000-byte allocation before `call 0x259900`, which is the mirror of the
-- copyout helper 0x2591d0 (rdi = kernel source, rsi = user destination). If 0x259900
-- is the copyin direction, a hit writes nothing into arg1 and every earlier run would
-- have printed "wrote=0" for a direct hit. So the "no command does this" conclusion
-- from 1372b is not supported; this probe decides it by direction.
--
-- Method: give the command a destination with room (a 0x4000 allocation), then the
-- same command with only eight bytes of mapped memory left in a 0x1000 allocation, then
-- an unmapped page. A 0x1000-byte transfer in either direction overruns the eight-byte
-- case and faults, so its return value changes; a command that touches a single dword
-- answers identically in all three. rv2 ~= rv1 with rv3 also different is proof the
-- command moves a block through arg1 and the direction is then read off the errno
-- (EFAULT from the copy helper itself).
--
-- -- prior art:
--   results/kernel_handlers/asm/sys_601_deep.asm:ca0d6c-ca0dd9
--   results/phase35_dead_end_reruns/1371a_sys601_writer_sweep_20261109_123328.txt
--   results/phase35_dead_end_reruns/1372b_sys601_high_null_20261109_124221.txt
--   agent://ProbeReview2 (finding 2: 0x259900 is the mirror of the copyout helper)

print("=== PROBE 1373a: SYS 601 BLOCK TRANSFER DIRECTION ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function es()
    local ok, s = pcall(function() return get_error_string() end)
    if ok and type(s) == "string" then return s end
    return "?"
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok and v ~= nil then return to_num(v) end
    return nil
end
local function wd(addr, val) pcall(function() memory.write_dword(addr, val) end) end
local function U(hi, lo) return uint64(string.format("0x%X%08X", hi, lo)) end

local sc601 = make_syscall(601)
local A = memory.alloc(0x4000)   -- room for a whole 0x1000 transfer
local E = memory.alloc(0x1000)   -- only the last eight bytes usable
local A1, E1 = to_num(A), to_num(E)

local PAINT = 0xA5A5A5A5
for i = 0, 0x3FFC, 4 do wd(A + i, PAINT) end
for i = 0, 0xFFC, 4 do wd(E + i, PAINT) end

local function call1(cmd, dst)
    local ok, rv = pcall(function() return sc601(U(0, cmd), U(0, dst), U(0, 0), U(0, 0), U(0, 0), U(0, 0)) end)
    return ok and to_num(rv) or -999
end

print(string.format("[0] pid=%d A=0x%X E=0x%X Etail=0x%X",
    to_num(make_syscall(20)(U(0,0),U(0,0),U(0,0),U(0,0),U(0,0),U(0,0))), A1, E1, E1 + 0xFF8))

local order = {0x1C, 0x10, 0x1D, 0x20, 0x00, 0x0E, 0x1A, 0x0D, 0x13, 0x14, 0x19}
for i = 1, #order do
    local cmd = order[i]
    for j = 0, 0xFFC, 4 do wd(E + j, PAINT) end
    local rv_room = call1(cmd, A1)
    local rv_tail = call1(cmd, E1 + 0xFF8)
    local rv_unm  = call1(cmd, 0x1000)
    local mark = (rv_tail ~= rv_room or rv_unm ~= rv_room) and "  <-- ARG1-DEPENDENT" or ""
    print(string.format("  0x%02X room=%d tail=%d unmapped=%d errno=%s%s",
        cmd, rv_room, rv_tail, rv_unm, es(), mark))
    -- how much of E's tail page did the roomy call write back into E is not observable,
    -- so the roomy case is surveyed for completeness only
    local changed = 0
    for j = 0, 0xFFC, 4 do
        if rd(E + j) ~= PAINT then changed = changed + 1 end
    end
    if changed > 0 then print(string.format("      E changed dwords after the tail call = %d", changed)) end
end

print("=== PROBE 1373a COMPLETE ===")
