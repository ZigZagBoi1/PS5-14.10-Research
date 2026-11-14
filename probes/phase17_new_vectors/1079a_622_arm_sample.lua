-- CRASH_CLASS: HIGH
-- PROBE 1079a: one command from the 622 0x201-0x271 arm per connection.
--
-- Context: entering that arm kills the game on its first two commands (0x201, 0x202) with handle 0
-- and with a live evf handle (1078a). This probe takes a single command so the arm can be sampled
-- without the sweep dying before it reaches the rest. The marker line is rewritten between runs by
-- tools drive; nothing else changes.
--
-- A surviving command prints rv and the status dword; a fatal one leaves the capture ending at the
-- marker below, which is itself the result.

print("=== PROBE 1079a: 622 ARM SAMPLE ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function call(num, a1, a2, a3, a4, a5, a6)
    local sc = make_syscall(num)
    local ok, rv = pcall(function()
        return sc(uint64(a1 or 0), uint64(a2 or 0), uint64(a3 or 0),
                  uint64(a4 or 0), uint64(a5 or 0), uint64(a6 or 0))
    end)
    if not ok then return -999 end
    if type(rv) == "table" and rv.h then
        local h, l = to_num(rv.h), to_num(rv.l)
        if h >= 2147483648 then h = h - 4294967296 end
        if l >= 2147483648 then l = l - 4294967296 end
        if h == -1 and l == -1 then return -1 end
        return h * 4294967296 + l
    end
    local n = to_num(rv)
    if n >= 9223372036854775808 then n = n - 18446744073709551616 end
    return n
end

local CMD = 0x271 -- CMD_SELECT

local page = call(477, 0, 0x1000, 7, 0x1002, 0xFFFFFFFF, 0)
if page <= 0 then print("no page") return end
local i = 0
while i < 0x400 do memory.write_qword(page + i, uint64(0)); i = i + 8 end
local OUT = page + 0x100
local function outd() local o, v = pcall(function() return memory.read_dword(OUT) end)
    if o then return to_num(v) or 0 end return -1 end

-- control first, so a broken call is visible before the risky one
memory.write_dword(OUT, 0xA5A5A5A5)
local rvc = call(622, 0x300, 0, OUT, 0, 0, 0)
print(string.format("[A] control 0x300 rv=%d out=0x%08X", rvc, outd()))

memory.write_dword(OUT, 0xA5A5A5A5)
print(string.format("[B] risky 0x%03X handle=0 out=a5a5a5a5", CMD))
local rv = call(622, CMD, 0, OUT, 0, 0, 0)
print(string.format("    rv=%d out=0x%08X  (survived)", rv, outd()))

print("=== 1079a DONE ===")
