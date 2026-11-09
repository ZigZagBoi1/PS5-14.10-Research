-- CRASH_CLASS: HIGH
-- Read only 0x100 bytes from offset-zero mappings of /dev/dmem1 and dmem2.
print("=== PROBE 122b: DMEM1/2 POINTER SLICES ===")

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
for dev = 1, 2 do
    local name = "/dev/dmem" .. dev
    print("[BEFORE] " .. name)
    local path = memory.alloc(#name + 1)
    for i = 1, #name do memory.write_byte(path + i - 1, string.byte(name, i)) end
    memory.write_byte(path + #name, 0)
    local ok_open, fd = pcall(function() return sc(5)(path, uint64(2), uint64(0)) end)
    print("open_ok=" .. tostring(ok_open) .. " fd=" .. tostring(fd))
    if ok_open and not fail(fd) and num(fd) >= 0 then
        local ok_map, base = pcall(function()
            return sc(477)(uint64(0), uint64(0x4000), uint64(1),
                           uint64(1), fd, uint64(0))
        end)
        print("mmap_ok=" .. tostring(ok_map) .. " base=" .. tostring(base))
        if ok_map and not fail(base) and num(base) ~= 0 then
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
            local ok_unmap, unmap_rv = pcall(function() return sc(73)(base, uint64(0x4000)) end)
            print("unmap_ok=" .. tostring(ok_unmap) .. " rv=" .. tostring(unmap_rv))
        end
        local ok_close, close_rv = pcall(function() return sc(6)(fd) end)
        print("close_ok=" .. tostring(ok_close) .. " rv=" .. tostring(close_rv))
    end
    print("canary_pid=" .. num(getpid()))
end
print("=== PROBE 122b COMPLETE ===")
