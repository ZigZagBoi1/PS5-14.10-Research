-- CRASH_CLASS: LOW
-- PROBE 483b: find which /dev/camera command blocks
--
-- 483a swept /dev/camera and stopped printing after cmd=0x20000027, with the
-- connection idle but open: a blocking ioctl, not a panic. Every command that
-- returned 0x16 there was EINVAL (no handler), so the interesting one is the
-- first call after the last printed hit. This walks the neighbourhood one call
-- at a time, printing before each, so the last line names the blocker.
print("=== PROBE 483b: /dev/camera command blocker ===")
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
local function parts(r)
    if type(r) == "table" and r.h then return to_num(r.h), to_num(r.l) end
    local x = to_num(r)
    return math.floor(x / 4294967296), x % 4294967296
end
local function hex(v)
    local h, l = parts(v)
    if h == 0 then return string.format("%08X", l) end
    return string.format("%08X%08X", h, l)
end
local function put_str(buf, s)
    for i = 1, #s do
        pcall(function() memory.write_byte(buf + i - 1, s:byte(i)) end)
    end
    pcall(function() memory.write_byte(buf + #s, 0) end)
end

local sc_open = make_syscall(5)
local sc_ioctl = make_syscall(54)
local sc_close = make_syscall(6)

local path = memory.alloc(64)
put_str(path, "/dev/camera")
local fdh, fdl = parts(sc_open(uint64(path), uint64(2), uint64(0)))
print(string.format("[open] fd=%d", fdl))
if fdl == 0 or fdl > 0xFFFF then
    print("[open] failed, stopping")
    return
end

local page = memory.alloc(0x1000)
for i = 0, 0x3FF do pcall(function() memory.write_dword(page + i * 4, 0) end) end

local function call(cmd)
    return sc_ioctl(uint64(fdl), uint64(cmd), uint64(page))
end

local list = {}
for n = 0x18, 0x40 do list[#list + 1] = 0x20000000 + n end
list[#list + 1] = 0x00004701
list[#list + 1] = 0xC0104701

for _, cmd in ipairs(list) do
    print(string.format("[call] cmd=%s", hex(cmd)))
    local ok, r = pcall(function() return call(cmd) end)
    if ok then
        print(string.format("   ret=%s", hex(r)))
    else
        print("   pcall failed")
    end
end

print("")
print("[done] every command returned")
pcall(function() sc_close(uint64(fdl)) end)
