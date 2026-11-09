-- CRASH_CLASS: LOW
-- Isolated fstat copyout on a kqueue descriptor, with two input sentinels.
-- The output is raw dwords; pointer interpretation requires later validation.
print("=== PROBE 109b: FSTAT KQUEUE ISOLATED ===")

local function num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function sc(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function read32(p)
    local ok, value = pcall(function() return memory.read_dword(p) end)
    if ok then return num(value) end
    return nil
end
local function fmt32(value)
    if value == nil then return "READERR" end
    return string.format("%08X", value)
end

local ok, fd = pcall(function() return num(sc(362)()) end)
if not ok or fd < 0 then
    print("KQUEUE FAILED")
    print("=== PROBE 109b COMPLETE ===")
    return
end
print("kqueue_fd=" .. fd)

local function one_call(sysno, sentinel)
    local buf = memory.alloc(0x100)
    local fill_ok = pcall(function()
        for off = 0, 0xFC, 4 do memory.write_dword(buf + off, sentinel) end
    end)
    if not fill_ok then
        print(string.format("FILL FAILED sys=%d sentinel=%08X", sysno, sentinel))
        return
    end
    print(string.format("BEFORE sys=%d sentinel=%08X", sysno, sentinel))
    local call_ok, ret = pcall(function() return sc(sysno)(uint64(fd), uint64(buf)) end)
    print("pcall_ok=" .. tostring(call_ok))
    if not call_ok then return end
    print("ret=" .. tostring(ret))
    for off = 0, 0xFC, 16 do
        print(string.format("+%02X %s %s %s %s", off,
            fmt32(read32(buf + off)), fmt32(read32(buf + off + 4)),
            fmt32(read32(buf + off + 8)), fmt32(read32(buf + off + 12))))
    end
end

for _, sysno in ipairs({189, 551}) do
    one_call(sysno, 0xA5A5A5A5)
    one_call(sysno, 0x5A5A5A5A)
end
pcall(function() sc(6)(uint64(fd)) end)
print("=== PROBE 109b COMPLETE ===")
