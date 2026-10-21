-- CRASH_CLASS: HIGH
-- One sys657 opcode-1 command against a fresh scratch GPU mapping.
-- No loop, race, arbitrary kernel address, or post-command dereference.
print("=== PROBE 121c: SYS657 ONE GPU COMMAND ===")

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
local pid = num(getpid())
print("pid=" .. pid)
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
local rec = memory.alloc(0x20)
local processed = memory.alloc(8)
for off = 0, 0x1c, 4 do memory.write_dword(rec + off, 0) end
memory.write_dword(processed, 0x6A6A6A6A)
memory.write_dword(processed + 4, 0)
memory.write_dword(rec, 1)                    -- opcode 1
memory.write_qword(rec + 8, aligned)          -- scratch address
memory.write_qword(rec + 0x10, uint64(0x10000)) -- 64 KiB
memory.write_qword(rec + 0x18, uint64(0x33))  -- original mapping flags

print("aligned=" .. tostring(aligned) .. " delta=" .. delta)
print("[BEFORE] sys657(opcode=1,count=1)")
local ok, rv = pcall(function()
    return sc(657)(uint64(rec), uint64(1), uint64(processed), uint64(0))
end)
print("[AFTER] ok=" .. tostring(ok) .. " rv=" .. tostring(rv) ..
      " processed=" .. num(memory.read_dword(processed)))
print("canary_pid=" .. num(getpid()))
print("=== PROBE 121c COMPLETE ===")
