-- CRASH_CLASS: LOW
-- Read only: determine whether the 14.10 game process is limited to one CPU.
print("=== PROBE 50n: CPUSET AFFINITY READ ===")
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
local function fmt(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return tostring(v)
end
local pid = sc(20)()
local mask = memory.alloc(128)
local function query(label, level, which, id)
    for i = 0, 124, 4 do memory.write_dword(mask + i, 0) end
    local rv = sc(487)(uint64(level), uint64(which), id,
        uint64(128), uint64(mask))
    print(label .. " ret=" .. fmt(rv) ..
        " mask0=" .. fmt(memory.read_qword(mask)) ..
        " mask1=" .. fmt(memory.read_qword(mask + 8)))
end
print("pid=" .. fmt(pid))
query("WHICH_PID", 3, 2, pid)
query("ROOT_PID", 1, 2, pid)
query("WHICH_TID_CURRENT", 3, 1, uint64(0xffffffffffffffff))
print("canary pid=" .. fmt(sc(20)()))
print("=== PROBE 50n COMPLETE ===")
