-- CRASH_CLASS: MODERATE
-- Isolate native syscall 728 before the broad 57a/57b surveys.
-- The 13.60 name virtual_query_by_pid is a hypothesis on 14.10.
print("=== PROBE 80y: SYS728 ISOLATED ===")

local function num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(n)
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

local ok_pid, pid_value = pcall(function() return make_syscall(20)() end)
if not ok_pid then print("GETPID FAILED"); return end
local pid = num(pid_value)
print("pid=" .. pid)
local out = memory.alloc(0x400)
for off = 0, 0x3FC, 4 do memory.write_dword(out + off, 0) end
print("calling_728")
local ok, result = pcall(function()
    return make_syscall(728)(uint64(pid), uint64(0), uint64(out), uint64(4), uint64(0), uint64(0))
end)
print("pcall_ok=" .. tostring(ok))
if ok then print("ret=" .. tostring(result)) end
for off = 0, 0x3C, 4 do
    local value = read32(out + off)
    if value and value ~= 0 then
        print(string.format("out+0x%02X=%08X", off, value))
    end
end
print("=== PROBE 80y COMPLETE ===")
