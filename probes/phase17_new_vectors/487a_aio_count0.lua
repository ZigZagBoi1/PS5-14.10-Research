-- CRASH_CLASS: HIGH
-- PROBE 487a: syscall 662 with count = 0 — does the body run?
--
-- Context: 486a showed 662 runs its delete body on 14.10 for count 1..0x80
-- (ret=0, every entry 0x80020003). count=0x81 returned -1. count=0 produced
-- binary bytes on the socket and then the console died, which does not look
-- like the 13.60 guard (that guard only enters the body for 1..0x80).
--
-- This probe makes exactly one call with count=0 and dumps what changed:
--   [1] return value
--   [2] first 0x40 bytes of the results buffer (did the kernel write?)
--   [3] first 0x40 bytes of the id buffer (did the kernel read/modify?)
-- Output is unbuffered and a marker precedes the call, so a cut capture still
-- says whether the call returned.

print("=== PROBE 487a: 662 count=0 ===")
io.stdout:setvbuf("no")

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
local function hex(buf, n)
    local out = {}
    for i = 0, n - 1 do
        local ok, b = pcall(function() return memory.read_byte(buf + i) end)
        if not ok then out[#out + 1] = "??"; break end
        out[#out + 1] = string.format("%02x", b)
    end
    return table.concat(out, " ")
end

local ids = memory.alloc(0x1000)
local res = memory.alloc(0x4000)
for off = 0, 0x1000 - 1, 4 do
    pcall(function() memory.write_dword(ids + off, 0x41414141) end)
end
for off = 0, 0x4000 - 1, 4 do
    pcall(function() memory.write_dword(res + off, 0x42424242) end)
end

local sc662 = make_syscall(662)

print(string.format("[0] ids=%s res=%s", tostring(ids), tostring(res)))
print("[0] calling 662(ids, 0, res) NOW")
local ok, rv = pcall(function() return sc662(uint64(ids), uint64(0), uint64(res)) end)
print(string.format("[1] returned ok=%s rv=%s", tostring(ok), tostring(rv)))
if ok then print(string.format("[1] ret=%d", to_num(rv))) end
print("[2] res  = " .. hex(res, 0x40))
print("[3] ids  = " .. hex(ids, 0x40))
print("=== PROBE 487a COMPLETE ===")
