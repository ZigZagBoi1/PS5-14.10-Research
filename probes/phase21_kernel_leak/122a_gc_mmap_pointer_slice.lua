-- CRASH_CLASS: HIGH
-- Inspect only the first 0x100 bytes of one read-only-access /dev/gc mapping.
-- Replays the known-working mmap layout from probe 15 without writing to it.
print("=== PROBE 122a: GC MMAP POINTER SLICE ===")

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
local function fail(v)
    return type(v) == "table" and v.h == 0xFFFFFFFF and v.l == 0xFFFFFFFF
end

local getpid = sc(20)
print("pid=" .. num(getpid()))
local path = memory.alloc(8)
local name = "/dev/gc"
for i = 1, #name do memory.write_byte(path + i - 1, string.byte(name, i)) end
memory.write_byte(path + #name, 0)
local ok_open, fd = pcall(function() return sc(5)(path, uint64(2), uint64(0)) end)
print("open_ok=" .. tostring(ok_open) .. " fd=" .. tostring(fd))
if not ok_open or fail(fd) or num(fd) < 0 then return end

local ok_map, base = pcall(function()
    return sc(477)(uint64(0), uint64(0x4000), uint64(3),
                   uint64(1), fd, uint64(0))
end)
print("mmap_ok=" .. tostring(ok_map) .. " base=" .. tostring(base))
if not ok_map or fail(base) or num(base) == 0 then
    sc(6)(fd)
    return
end

local hits = 0
for off = 0, 0xF8, 8 do
    local ok, v = pcall(function() return memory.read_qword(num(base) + off) end)
    if not ok then
        print(string.format("read_fail_off=0x%X", off))
        break
    end
    print(string.format("+0x%02X: %s", off, tostring(v)))
    if type(v) == "table" and v.h and v.h >= 0xFFFF8000 and v.h ~= 0xFFFFFFFF then
        hits = hits + 1
        print(string.format("KERNEL_SHAPED +0x%X: %s", off, tostring(v)))
    end
end
print("kernel_shaped_count=" .. hits)
print("canary_pid=" .. num(getpid()))
local ok_unmap, unmap_rv = pcall(function() return sc(73)(base, uint64(0x4000)) end)
print("unmap_ok=" .. tostring(ok_unmap) .. " rv=" .. tostring(unmap_rv))
local ok_close, close_rv = pcall(function() return sc(6)(fd) end)
print("close_ok=" .. tostring(ok_close) .. " rv=" .. tostring(close_rv))
print("=== PROBE 122a COMPLETE ===")
