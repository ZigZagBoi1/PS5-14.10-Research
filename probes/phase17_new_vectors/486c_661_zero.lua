-- CRASH_CLASS: MODERATE
-- PROBE 486c: 661 (aio_submit) with a fully zero argument.
print("=== PROBE 486c: 661 zero ===")
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
local ok, rv = pcall(function() return make_syscall(661)(uint64(0), uint64(0), uint64(0)) end)
print("[1] 661(0,0,0) ok="..tostring(ok).." ret="..tostring(to_num(rv)))
print("=== PROBE 486c END ===")
