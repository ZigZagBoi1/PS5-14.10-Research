-- CRASH_CLASS: HIGH
-- PROBE 337a: mdbg_call (573) with the minimal shape only
--
-- During 334a the console powered off while 573 was being called with a pointer
-- shape; 573 is a nosys trampoline that delivers SIGSYS and returns ENOSYS, and
-- the presence sweep had previously recorded it as process-lethal with six
-- zeros. This calls it exactly once, with six zeros, and prints a marker before
-- and after so the outcome separates process death from a console power-off.
-- One call, no pointer, nothing else on the connection.

print("=== PROBE 337a: MDBG CALL MINIMAL ===")
print("[BEFORE] 573(0,0,0,0,0,0)")

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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function sgn(v)
    local l = to_num(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function lo_of(v)
    local h, l = get_hi_lo(v)
    return to_num(l), to_num(h)
end

local sc = make_syscall(573)
local Z = uint64(0)
local ok, rv = pcall(function() return sc(Z, Z, Z, Z, Z, Z) end)
if ok then
    print(string.format("[AFTER] ret = %d", sgn(lo_of(rv))))
else
    print("[AFTER] pcall failed")
end
print("=== 337a DONE ===")
