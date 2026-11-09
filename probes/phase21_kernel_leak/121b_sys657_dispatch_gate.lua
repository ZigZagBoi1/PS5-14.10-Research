-- CRASH_CLASS: MEDIUM
-- Isolated, zero-command sys657 dispatch check. No GPU object or page mutation.
print("=== PROBE 121b: SYS657 DISPATCH GATE ===")

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
local processed = memory.alloc(8)
memory.write_dword(processed, 0x6A6A6A6A)
memory.write_dword(processed + 4, 0)
print("pid=" .. num(getpid()) .. " processed_before=" .. num(memory.read_dword(processed)))
print("[BEFORE] sys657(commands=NULL, count=0, processed_out, flags=0)")
local ok, rv = pcall(function()
    return sc(657)(uint64(0), uint64(0), uint64(processed), uint64(0))
end)
print("[AFTER] ok=" .. tostring(ok) .. " rv=" .. tostring(rv) ..
      " processed_after=" .. num(memory.read_dword(processed)))
print("canary_pid=" .. num(getpid()))
print("=== PROBE 121b COMPLETE ===")
