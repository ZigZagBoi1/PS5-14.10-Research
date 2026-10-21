-- CRASH_CLASS: MEDIUM
-- Single read-only call using the 13.60 sys642 ABI: (pid, capacity, records, count_out).
-- A prior 14.10 survey sent all-zero args; it did not test this layout.
-- This gate requests only the record count. It does not copy map records or
-- claim a kernel pointer from a successful count.
print("=== PROBE 121a: SYS642 COUNT GATE ===")

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

local getpid = sc(20)
local pid = num(getpid())
local count_out = memory.alloc(8)
memory.write_dword(count_out, 0x6A6A6A6A)
memory.write_dword(count_out + 4, 0)
print("pid=" .. pid .. " count_before=" .. num(memory.read_dword(count_out)))
print("[BEFORE] sys642(pid, capacity=0, records=NULL, count_out)")
local ok, rv = pcall(function()
    return sc(642)(uint64(pid), uint64(0), uint64(0), uint64(count_out))
end)
print("[AFTER] ok=" .. tostring(ok) .. " rv=" .. tostring(rv) ..
      " count_after=" .. num(memory.read_dword(count_out)))
print("canary_pid=" .. num(getpid()))
print("=== PROBE 121a COMPLETE ===")
