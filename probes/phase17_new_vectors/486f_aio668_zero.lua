-- CRASH_CLASS: HIGH
-- PROBE 486f: is 668 lethal unconditionally, or only with a buffer?
--
-- 486b called 668(page, 0x100, 0x10) and the process died with no return.
-- A null argument first decides whether the kill is argument-independent:
-- if 668(0,0,0) returns anything, the kill needs a mapped pointer and the
-- create path may still be usable.

print("=== PROBE 486f: 668 with zeros ===")
print("")

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
local function sgn(v)
    local n = to_num(v)
    if n >= 0x8000000000000000 then return n - 0x10000000000000000 end
    if n >= 0x80000000 and n < 0x100000000 then return n - 0x100000000 end
    return n
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end

local sc668 = make_syscall(668)
local buf = memory.alloc(0x1000)
for i = 0, 0xFFF, 4 do wd(buf + i, 0) end

local ok, rv = pcall(function() return sc668(uint64(0), uint64(0), uint64(0)) end)
print(string.format("[1] 668(0,0,0) ok=%s ret=%d", tostring(ok), ok and sgn(rv) or -999))

local ok2, rv2 = pcall(function() return sc668(uint64(buf), uint64(0), uint64(0)) end)
print(string.format("[2] 668(page,0,0) ok=%s ret=%d", tostring(ok2), ok2 and sgn(rv2) or -999))

print("=== PROBE 486f END ===")
