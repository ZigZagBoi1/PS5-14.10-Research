-- CRASH_CLASS: MODERATE
-- Isolated read-only thr_get_ucontext(634) reachability on current thread.
print("=== PROBE 59c: THR_GET_UCONTEXT SELF ===")
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
local tidp = memory.alloc(8)
memory.write_dword(tidp, 0xA5A5A5A5)
local ok_t, rv_t = pcall(function() return sc(432)(uint64(tidp)) end)
local tid = num(memory.read_dword(tidp))
print("thr_self ok=" .. tostring(ok_t) .. " ret=" .. tostring(rv_t) .. " tid=" .. tid)
local ctx = memory.alloc(0x600)
for off = 0, 0x5FC, 4 do memory.write_dword(ctx + off, 0xA5A5A5A5) end
print("before thr_get_ucontext(634) single-arg context buffer")
local ok, rv = pcall(function() return sc(634)(uint64(ctx)) end)
print("call_ok=" .. tostring(ok) .. " ret=" .. tostring(rv))
local changed = 0
for off = 0, 0x5F8, 8 do
    local lo = num(memory.read_dword(ctx + off))
    local hi = num(memory.read_dword(ctx + off + 4))
    if lo ~= 0xA5A5A5A5 or hi ~= 0xA5A5A5A5 then
        changed = changed + 1
        print(string.format("+%03X=%08X_%08X", off, hi, lo))
    end
end
print("changed_qwords=" .. changed)
print("=== PROBE 59c COMPLETE ===")
