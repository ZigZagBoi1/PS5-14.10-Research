-- CRASH_CLASS: LOW
-- PROBE 480b: does open(/dev/dmem2) return on its own?
--
-- 480a stopped between its header and its first marker, which cannot separate a
-- buffered stream from a blocking open. This probe opens only, prints, and ends:
-- the loader flushes on exit, so a completed capture means the open returns and
-- the block in 480a was the ioctl.

print("=== PROBE 480b: dmem2 open only ===")
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
local fd_rw = sgn(make_syscall(5)(uint64(put_str("/dev/dmem2")), uint64(2), uint64(0)))
print("[1] open(dmem2, O_RDWR)=" .. fd_rw)
local fd_ro = sgn(make_syscall(5)(uint64(put_str("/dev/dmem2")), uint64(0), uint64(0)))
print("[2] open(dmem2, O_RDONLY)=" .. fd_ro)
print("=== PROBE 480b COMPLETE ===")
