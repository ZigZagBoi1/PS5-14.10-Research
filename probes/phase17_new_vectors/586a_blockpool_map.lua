-- CRASH_CLASS: MODERATE
-- PROBE 586a: blockpool_map (654) with the argument shape decoded from 13.60
--
-- 13.60 body 0xffffffff8b369560 (narg 5) reads, with rsi = uap:
--   arg1 = index, must be < [pool+0x20] and < [pool+0x28]
--   arg2 = size,  low 16 bits must be zero, must be <= [pool+0x28] - arg1
--   arg3 = type,  must be <= 0xa
--   arg4, arg5 unknown
-- Earlier probes passed the handle from 653 as arg1, which cannot pass the
-- index bound. 653's flags are masked with 0xffafffff (bits 20 and 22 only).

print("=== PROBE 586a: BLOCKPOOL MAP ===")

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
local function u64(v) return uint64(tostring(v)) end
local function hi_lo(v)
    if type(v) == "table" and v.h then return v.h, v.l end
    return 0, to_num(v)
end
local function hex64(v)
    local h, l = hi_lo(v)
    return string.format("%08X_%08X", to_num(h), to_num(l))
end

local sc_open  = make_syscall(653)
local sc_map   = make_syscall(654)
local sc_unmap = make_syscall(655)
local sc_batch = make_syscall(657)

local ok, h = pcall(function() return sc_open(u64(0)) end)
print("[A] open(flags=0) ok=" .. tostring(ok) .. " ret=" .. tostring(h))

for idx = 0, 2 do
    for t = 0, 10 do
        local r_ok, r = pcall(function() return sc_map(idx, 0x10000, t, 0, 0) end)
        print(string.format("[B] map(idx=%d,size=0x10000,type=%d) ok=%s ret=%s",
            idx, t, tostring(r_ok), r_ok and hex64(r) or tostring(r)))
    end
end

for _, size in ipairs({0x20000, 0x100000, 0x400000}) do
    local r_ok, r = pcall(function() return sc_map(0, size, 0, 0, 0) end)
    print(string.format("[C] map(0,0x%X,0,0,0) ok=%s ret=%s", size, tostring(r_ok), r_ok and hex64(r) or tostring(r)))
end

local u_ok, u = pcall(function() return sc_unmap(0, 0, 0, 0, 0) end)
print("[D] unmap(0,0,0,0,0) ok=" .. tostring(u_ok) .. " ret=" .. (u_ok and hex64(u) or tostring(u)))

local b_ok, b = pcall(function() return sc_batch(0, 0, 0, 0, 0) end)
print("[E] batch(0,0,0,0,0) ok=" .. tostring(b_ok) .. " ret=" .. (b_ok and hex64(b) or tostring(b)))

print("[F] alive")
