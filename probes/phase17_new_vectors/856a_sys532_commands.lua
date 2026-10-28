-- CRASH_CLASS: HIGH
-- PROBE 856a: SYS 532 COMMAND MAP
--
-- Context: 532 (narg 5, 13.60 handler 0xaf0040) reads uap[0]=command and
-- uap[8]/[0x10]/[0x18]/[0x20], gates on 0xadfa30(proc,0x2aa) and
-- 0x609080([proc+0x140]), and for cmd <= 0x20 indexes a table at
-- [rip+0x3207cec] (stride 0x28) after testing bitmask 0x800003d4.
-- The object it registers with type 0x2000 (site 0xb26dc6) is the only family
-- that 558 could destroy, so the command that reaches that site matters.
-- Prior notes suggest unprivileged callers may use 0x18-0x1F, 0x20 and 0x2F.
--
-- Each command is called with four argument shapes. Every stage prints before
-- it runs, so the last line names the killer if the process dies.

print("=== PROBE 856a: SYS 532 COMMAND MAP ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function U(a)
    a = to_num(a)
    return uint64(string.format("0x%08X%08X",
        math.floor(a / 4294967296), a % 4294967296))
end
local function hex(v)
    local n = to_num(v)
    if n < 0 then n = n + 18446744073709551616 end
    return string.format("%016X", n)
end

local sc532 = make_syscall(532)
local sc549 = make_syscall(549)

local p1 = to_num(memory.alloc(0x1000))
local p2 = to_num(memory.alloc(0x1000))
for i = 0, 0x3FF do
    memory.write_dword(p1 + i * 4, 0)
    memory.write_dword(p2 + i * 4, 0)
end

print(string.format("[0] pid=%s p1=%08X p2=%08X",
    tostring(make_syscall(20)()), p1, p2))
print("")

-- command, then the four shapes: all zero / p1 / p2 / both
local CMDS = {0x00, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x2F}

local function shape_args(s)
    if s == 1 then return U(0), U(0), U(0), U(0) end
    if s == 2 then return U(p1), U(0x100), U(0), U(0) end
    if s == 3 then return U(0), U(p1), U(0x100), U(0) end
    return U(p1), U(0x100), U(p2), U(0x100)
end

for _, cmd in ipairs(CMDS) do
    for s = 1, 4 do
        print(string.format("[T] cmd=%02X shape=%d", cmd, s))
        local a, b, c, d = shape_args(s)
        local ok, rv = pcall(function() return sc532(U(cmd), a, b, c, d) end)
        if not ok then
            print(string.format("[T] cmd=%02X shape=%d PCALL-FAIL", cmd, s))
        else
            print(string.format("[R] cmd=%02X shape=%d ret=%s p1[0]=%08X p2[0]=%08X",
                cmd, s, hex(rv), to_num((memory.read_dword(p1))), to_num((memory.read_dword(p2)))))
        end
    end
end

print("")
print("[Z] health")
local function name_page(tag)
    local p = to_num(memory.alloc(0x40))
    for i = 0, 0x3F do memory.write_byte(p + i, 0) end
    local s = "h532" .. tag
    for i = 1, #s do memory.write_byte(p + i - 1, string.byte(s, i)) end
    return p
end
local okc, id = pcall(function() return sc549(U(name_page("a")), U(1), U(0), U(0x100)) end)
local okd, rvd = pcall(function() return make_syscall(550)(U(to_num(id))) end)
print(string.format("[Z] create=%s destroy=%s alive=true",
    okc and hex(id) or "FAIL", okd and hex(rvd) or "FAIL"))
print("=== PROBE 856a COMPLETE ===")
