-- CRASH_CLASS: LOW
-- One uncontended PI mutex round trip. No race, invalid owner, or kernel read.
print("=== PROBE 110b: PI MUTEX BASELINE ===")

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

local m = memory.alloc(0x20)
for i = 0, 0x1c, 4 do memory.write_dword(m + i, 0) end
memory.write_dword(m + 4, 4) -- UMUTEX_PRIO_INHERIT
print("pid=" .. num(sc(20)()) .. " owner_before=" .. num(memory.read_dword(m)) ..
      " flags=" .. num(memory.read_dword(m + 4)))

print("[BEFORE] lock_PI")
local ok1, r1 = pcall(function()
    return sc(454)(uint64(m), uint64(5), uint64(0), uint64(0), uint64(0))
end)
local owner = num(memory.read_dword(m))
print("[AFTER] lock_PI ok=" .. tostring(ok1) .. " rv=" .. tostring(r1) ..
      string.format(" owner=0x%08X", owner))
if not ok1 or num(r1) ~= 0 or owner == 0 then
    print("STOP: PI mutex was not acquired")
    return
end

print("[BEFORE] unlock_PI")
local ok2, r2 = pcall(function()
    return sc(454)(uint64(m), uint64(6), uint64(0), uint64(0), uint64(0))
end)
print("[AFTER] unlock_PI ok=" .. tostring(ok2) .. " rv=" .. tostring(r2) ..
      string.format(" owner=0x%08X", num(memory.read_dword(m))))
print("canary_pid=" .. num(sc(20)()))
print("=== PROBE 110b COMPLETE ===")
