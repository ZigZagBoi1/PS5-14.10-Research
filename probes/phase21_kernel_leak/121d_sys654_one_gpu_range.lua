-- CRASH_CLASS: HIGH
-- One sys654 op-0 call against a fresh scratch GPU mapping.
-- No loop, race, arbitrary kernel address, or post-command dereference.
print("=== PROBE 121d: SYS654 ONE GPU RANGE ===")

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
local function hilo(v)
    if type(v) == "table" and v.h then return v.h, v.l end
    return 0, num(v)
end

local getpid = sc(20)
print("pid=" .. num(getpid()))
local ok_map, base = pcall(function()
    return sc(477)(uint64(0), uint64(0x40000), uint64(0x33),
                   uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local hi, lo = hilo(base)
print("mmap_ok=" .. tostring(ok_map) .. " base=" .. tostring(base))
if not ok_map or (hi == 0xFFFFFFFF and lo == 0xFFFFFFFF) or num(base) == 0 then
    print("STOP: scratch mapping unavailable")
    return
end
local delta = (0x10000 - (lo % 0x10000)) % 0x10000
local aligned = base + delta
print("aligned=" .. tostring(aligned) .. " delta=" .. delta)
print("[BEFORE] sys654(addr, length=64KiB, op=0, flags=0, reserved=0)")
local ok, rv = pcall(function()
    return sc(654)(aligned, uint64(0x10000), uint64(0), uint64(0), uint64(0))
end)
print("[AFTER] ok=" .. tostring(ok) .. " rv=" .. tostring(rv))
print("canary_pid=" .. num(getpid()))
print("=== PROBE 121d COMPLETE ===")
