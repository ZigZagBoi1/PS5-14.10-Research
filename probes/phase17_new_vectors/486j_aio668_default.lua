-- CRASH_CLASS: HIGH
-- PROBE 486j: 668 with a mapped page but zero size and flags.
print("=== PROBE 486j: 668(page,0,0) ===")
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
local ok, rv = pcall(function() return make_syscall(668)(uint64(buf), uint64(0), uint64(0)) end)
print("[1] 668(page,0,0) ok="..tostring(ok).." ret="..tostring(to_num(rv)))
print("=== PROBE 486j END ===")
