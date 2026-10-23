-- CRASH_CLASS: HIGH
-- PROBE 478p: attribute the panic with a flushed capture, non-zero argument
--
-- The loader's stdout is buffered, so a probe that panics loses its last
-- lines: 477b's capture ended four commands before the real killer. This probe
-- prints 8 KB of padding first, which forces the loader to flush, then prints
-- its markers, then issues 0x80108017 on /dev/dmem1 with the non-zero argument
-- {page, 0x10, 0}. A capture that ends right after "[4] calling" both names the
-- command in one connection and shows the argument did not matter.

print("=== PROBE 478p: dmem1 0x80108017, flushed attribution ===")
for i = 1, 200 do
    print(string.rep("pad ", 10) .. tostring(i))
end

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
    local h, l = 0, to_num(v)
    if type(v) == "table" and v.h then h, l = v.h, v.l end
    if h ~= 0 or l >= 0x80000000 then return -1 end
    return l
end
local function put_str(s)
    local buf = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(buf + i - 1, string.byte(s, i)) end) end
    pcall(function() memory.write_byte(buf + #s, 0) end)
    return buf
end

local page = memory.alloc(0x100)
for off = 0, 0xFC, 4 do pcall(function() memory.write_dword(page + off, 0) end) end
pcall(function() memory.write_qword(page, uint64(page)) end)
pcall(function() memory.write_dword(page + 8, 0x10) end)

print("[1] argument page=" .. tostring(page))
print(string.format("[2] arg=%08X %08X %08X %08X",
    to_num(memory.read_dword(page)), to_num(memory.read_dword(page + 4)),
    to_num(memory.read_dword(page + 8)), to_num(memory.read_dword(page + 12))))
local fd = sgn(make_syscall(5)(uint64(put_str("/dev/dmem1")), uint64(2), uint64(0)))
print("[3] open(/dev/dmem1)=" .. fd)
if fd < 0 then print("=== PROBE 478p COMPLETE (open refused) ==="); return end
print("[4] calling 0x80108017 with a non-zero argument")
local ok, r = pcall(function() return make_syscall(54)(uint64(fd), uint64(0x80108017), uint64(page)) end)
print(string.format("[5] RETURNED ret=%d", ok and sgn(r) or -999))
print("=== PROBE 478p COMPLETE ===")
