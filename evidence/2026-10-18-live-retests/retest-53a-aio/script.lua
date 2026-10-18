-- CRASH_CLASS: MODERATE
-- PROBE 53a: Repeat the 43p AIO survival matrix with a resumable start index.
-- Reopens: results/43p_aio_bypass_20261016_180656.txt is truncated at call 1;
-- results/phase2_kernel_objects/19g_aio_debug_20261015_193320.txt records aio_error rv=-1.
-- This probe records syscall returns; it cannot identify why an external capture stops.

local START_AT = 1 -- If a run stops at call N, set this to N+1 to test the remainder.

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end

local function signed32(v)
    if type(v) == "table" and v.h then
        if v.h == 0xFFFFFFFF then return v.l - 0x100000000 end
        if v.h == 0 and v.l >= 0x80000000 then return v.l - 0x100000000 end
    end
    local n = to_num(v)
    if n >= 0x80000000 and n < 0x100000000 then return n - 0x100000000 end
    return n
end

local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

local function safe_wd(addr, val)
    return pcall(function() memory.write_dword(addr, val) end)
end

local zero = uint64(0)
local timespec = memory.alloc(16)
safe_wd(timespec, 0)
safe_wd(timespec + 4, 0)
safe_wd(timespec + 8, 0)
safe_wd(timespec + 12, 0)
local iocb_out = memory.alloc(8)
safe_wd(iocb_out, 0)
safe_wd(iocb_out + 4, 0)

local matrix = {
    {num=317, name="aio_error", args=function() return {zero,zero,zero,zero,zero,zero} end},
    {num=316, name="aio_cancel", args=function() return {zero,zero,zero,zero,zero,zero} end},
    {num=314, name="aio_return", args=function() return {zero,zero,zero,zero,zero,zero} end},
    {num=315, name="aio_suspend", args=function() return {zero,zero,uint64(timespec),zero,zero,zero} end},
    {num=255, name="aio_read", args=function() return {zero,zero,zero,zero,zero,zero} end},
    {num=256, name="aio_write", args=function() return {zero,zero,zero,zero,zero,zero} end},
    {num=257, name="lio_listio", args=function() return {zero,zero,zero,zero,zero,zero} end},
    {num=359, name="aio_waitcomplete", args=function() return {uint64(iocb_out),uint64(timespec),zero,zero,zero,zero} end},
    {num=465, name="aio_fsync", args=function() return {zero,zero,zero,zero,zero,zero} end},
    {num=543, name="aio_mlock", args=function() return {zero,zero,zero,zero,zero,zero} end},
}

print("=== PROBE 53a: AIO RETEST ===")
print(string.format("matrix=%d start_at=%d", #matrix, START_AT))
if START_AT < 1 or START_AT > #matrix then
    print("ERROR: START_AT is outside the matrix")
    return
end

local returned = 0
local lua_errors = 0
for i = START_AT, #matrix do
    local item = matrix[i]
    print(string.format("[%d/%d] %s (syscall %d): BEFORE call", i, #matrix, item.name, item.num))
    local args = item.args()
    local sc = make_syscall(item.num)
    local ok, ret = pcall(function()
        return sc(args[1], args[2], args[3], args[4], args[5], args[6])
    end)
    if ok then
        local rv = signed32(ret)
        print(string.format("[%d/%d] %s: RETURNED ret=%d", i, #matrix, item.name, rv))
        returned = returned + 1
    else
        -- A Lua pcall error is not evidence that the console process was killed.
        print(string.format("[%d/%d] %s: LUA-ERROR %s", i, #matrix, item.name, tostring(ret)))
        lua_errors = lua_errors + 1
    end
end

print(string.format("AIO matrix reached end: returned=%d lua_errors=%d", returned, lua_errors))
print("Interpretation: a returned -1 is a syscall result; a missing tail remains unexplained without console-side evidence.")
if returned == (#matrix - START_AT + 1) then
    print("ALL AIO CALLS RETURNED (see per-call rets)")
else
    print("NOT ALL AIO CALLS RETURNED THROUGH THE WRAPPER; inspect per-call status and capture tail")
end
print("=== PROBE 53a COMPLETE ===")
