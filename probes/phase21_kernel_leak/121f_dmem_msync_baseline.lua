-- CRASH_CLASS: MODERATE
-- Read-only /dev/dmem0 mmap followed by one msync(65, flags=0).
-- No invalidation or post-invalidation access.
print("=== PROBE 121f: DMEM MSYNC BASELINE ===")

local function num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or -1
end
local function sc(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function is_fail(v)
    return type(v) == "table" and v.h == 0xFFFFFFFF and v.l == 0xFFFFFFFF
end

local getpid = sc(20)
print("pid=" .. num(getpid()))
local name = "/dev/dmem0"
local path = memory.alloc(#name + 1)
for i = 1, #name do memory.write_byte(path + i - 1, string.byte(name, i)) end
memory.write_byte(path + #name, 0)

local ok_open, fd = pcall(function() return sc(5)(path, uint64(2), uint64(0)) end)
print("open_ok=" .. tostring(ok_open) .. " fd=" .. tostring(fd))
if not ok_open or is_fail(fd) or num(fd) < 0 then
    print("STOP: dmem open failed")
    return
end

local ok_map, base = pcall(function()
    return sc(477)(uint64(0), uint64(0x4000), uint64(1),
                   uint64(1), fd, uint64(0))
end)
print("mmap_ok=" .. tostring(ok_map) .. " base=" .. tostring(base))
if not ok_map or is_fail(base) or num(base) == 0 then
    sc(6)(fd)
    print("STOP: dmem mapping unavailable")
    return
end

local ok_read, before = pcall(function() return memory.read_qword(num(base)) end)
print("before_read_ok=" .. tostring(ok_read) .. " value=" .. tostring(before))
print("[BEFORE] msync syscall 65, dmem read-only mapping, flags=0")
local ok_sync, rv = pcall(function() return sc(65)(base, uint64(0x4000), uint64(0)) end)
print("[AFTER] ok=" .. tostring(ok_sync) .. " rv=" .. tostring(rv))
print("canary_pid=" .. num(getpid()))
local ok_unmap, unmap_rv = pcall(function() return sc(73)(base, uint64(0x4000)) end)
print("unmap_ok=" .. tostring(ok_unmap) .. " rv=" .. tostring(unmap_rv))
local ok_close, close_rv = pcall(function() return sc(6)(fd) end)
print("close_ok=" .. tostring(ok_close) .. " rv=" .. tostring(close_rv))
print("=== PROBE 121f COMPLETE ===")
