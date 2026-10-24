-- CRASH_CLASS: HIGH
-- PROBE 535a: does a create whose descriptor buffer is too short kill the process
--
-- Context: 534a finished every block-mode create cleanly (ids base+i*0x10000,
-- poll 3, delete 0), then ran one non-block create of count 0x7F whose
-- descriptor page is 0x200 bytes while copyin wants count*0x28 = 0x13C8.
-- The call returned 0 and the out id printed, then the process died before the
-- next print, ~8.9 s after the probe started.
--
-- This probe does that one call on a fresh process and then polls liveness
-- three times so a delayed effect shows up as a missing line rather than as a
-- silent end.

print("=== PROBE 535a: AIO SHORT COPYIN ===")
print("")
local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end

local sc669 = mk(669)
local SHORT = memory.alloc(0x200)
local OUT = memory.alloc(0x40)
for i = 0, 0x1FC, 4 do wd(SHORT + i, 0x42424242) end

local pid_val = N(native.fcall_with_rax(syscall.pipe.fn_addr, 20))
local function alive(tag)
    local p = N(native.fcall_with_rax(syscall.pipe.fn_addr, 20))
    print(string.format("[%s] pid=%d alive=%s", tag, p, tostring(p == pid_val)))
end

alive("A")
wd(N(OUT), 0)
local ret = -999
pcall(function()
    ret = N(sc669(uint64(1), uint64(N(SHORT)), uint64(0x7F), uint64(1), uint64(N(OUT))))
end)
print(string.format("[B] create ret=%d out=%08X", ret, rd(N(OUT)) or 0))
alive("C")

-- burn a little time the way the earlier runs did, then check again
local s = 0
for i = 1, 200000 do s = s + i end
alive("D")
for i = 1, 200000 do s = s + i end
alive("E")
print(string.format("sum=%d", s))
print("=== DONE ===")
