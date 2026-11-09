-- CRASH_CLASS: HIGH
-- PROBE 478o: does a non-zero argument change 0x80108017?
--
-- 478n proved the call is fatal with a zeroed page. 13.60's handler for
-- 0x80108017 loads [r14], [r14+8] and [r14+0xc] and calls a branch-free stub
-- that overwrites rdi/rsi and ends in ud2, so the argument should not matter.
-- This probe issues the same command with {page, 0x10, 0} and prints before
-- and after the call. If the process returns, the argument is live; if the
-- console dies, the argument is inert as the 13.60 stub implies.

print("=== PROBE 478o: dmem1 0x80108017 with a non-zero argument ===")
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
pcall(function() memory.write_dword(page + 12, 0) end)
print(string.format("[0] argument page=%08X q0=%08X %08X  q1=%08X %08X", page,
    to_num(memory.read_dword(page)), to_num(memory.read_dword(page + 4)),
    to_num(memory.read_dword(page + 8)), to_num(memory.read_dword(page + 12))))

local fd = sgn(make_syscall(5)(uint64(put_str("/dev/dmem1")), uint64(2), uint64(0)))
print("[1] open(/dev/dmem1)=" .. fd)
if fd < 0 then print("[1] refused"); return end

print("[2] about to call 0x80108017")
local ok, r = pcall(function() return make_syscall(54)(uint64(fd), uint64(0x80108017), uint64(page)) end)
print(string.format("[3] RETURNED ret=%d", ok and sgn(r) or -999))
pcall(function() make_syscall(6)(uint64(fd)) end)
print("")
print("=== PROBE 478o COMPLETE ===")
