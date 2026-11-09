-- CRASH_CLASS: MODERATE
-- PROBE 486d: 661 (aio_submit) with a mapped buffer and count 1.
print("=== PROBE 486d: 661 buf ===")
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
local buf = memory.alloc(0x1000)
pcall(function() for i = 0, 0xFFF, 4 do memory.write_dword(buf + i, 0) end end)
local ok, rv = pcall(function() return make_syscall(661)(uint64(buf), uint64(1), uint64(0)) end)
print("[1] 661(buf,1,0) ok="..tostring(ok).." ret="..tostring(to_num(rv)))
print("=== PROBE 486d END ===")
