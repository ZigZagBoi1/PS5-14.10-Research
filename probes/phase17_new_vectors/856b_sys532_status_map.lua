-- CRASH_CLASS: HIGH
-- PROBE 856b: SYS 532 COMMAND AND STATUS MAP
--
-- Context: 856a showed 532 returns 0 for every command and instead writes a
-- status dword into the pointer passed as the third argument: cmd 0x18 wrote
-- 0x800D020F, cmd 0x20 wrote 0x800D0208, cmd 0x2F wrote 0. 856a did not clear
-- the page between calls, so writes were not attributable; this probe zeroes
-- the page before every call.
--
-- [A] sweeps commands 0x00-0xFF with (arg2=0, arg3=status page, arg4=0).
-- [B] varies arg2 and arg4 for the commands that answered in [A].
-- Every stage prints before it runs.

print("=== PROBE 856b: SYS 532 COMMAND AND STATUS MAP ===")
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

local function zero(p, n)
    for i = 0, n - 1 do memory.write_dword(p + i * 4, 0) end
end
local function call(cmd, a2, a3, a4, a5)
    zero(p1, 16)
    zero(p2, 16)
    local ok, rv = pcall(function() return sc532(U(cmd), U(a2), U(a3), U(a4), U(a5)) end)
    if not ok then return nil end
    return to_num(rv), to_num(memory.read_dword(p1)),
        to_num(memory.read_dword(p1 + 4)), to_num(memory.read_dword(p1 + 8))
end

print(string.format("[0] pid=%s", tostring(make_syscall(20)())))
print("")

-- [A] command sweep
print("[A] command sweep, arg3 = status page")
local wrote = {}
for cmd = 0x00, 0xFF do
    local rv, s0, s1, s2 = call(cmd, 0, p1, 0, 0)
    if rv == nil then
        print(string.format("[A] cmd=%02X PCALL-FAIL", cmd))
        break
    end
    if rv ~= 0 or s0 ~= 0 or s1 ~= 0 or s2 ~= 0 then
        print(string.format("[A] cmd=%02X ret=%s st=%08X %08X %08X", cmd, hex(rv), s0, s1, s2))
        wrote[#wrote + 1] = cmd
    end
end
print(string.format("[A] commands with output=%d", #wrote))
print("")

-- [B] argument sensitivity for every command that produced a status
print("[B] argument sensitivity")
local A2 = {0, 1, 2, 4, 0x100, 0x1000}
local A4 = {0, 1, 2}
for _, cmd in ipairs(wrote) do
    for _, a2 in ipairs(A2) do
        for _, a4 in ipairs(A4) do
            local rv, s0, s1 = call(cmd, a2, p1, a4, 0)
            if rv == nil then
                print(string.format("[B] cmd=%02X a2=%X a4=%X PCALL-FAIL", cmd, a2, a4))
            elseif s0 ~= 0 or s1 ~= 0 or rv ~= 0 then
                print(string.format("[B] cmd=%02X a2=%X a4=%X ret=%s st=%08X %08X",
                    cmd, a2, a4, hex(rv), s0, s1))
            end
        end
    end
end
print("")

-- [C] does the status depend on the pointer being the 3rd or a later argument?
print("[C] pointer position")
for _, cmd in ipairs(wrote) do
    local rv, s0 = call(cmd, 0, 0, p1, 0)    -- arg4 is the page
    local rv2, t0 = call(cmd, p1, 0, 0, 0)   -- arg2 is the page
    print(string.format("[C] cmd=%02X arg4-page ret=%s st=%08X | arg2-page ret=%s st=%08X",
        cmd, hex(rv or -1), s0, hex(rv2 or -1), t0))
end

print("")
local function name_page(tag)
    local p = to_num(memory.alloc(0x40))
    for i = 0, 0x3F do memory.write_byte(p + i, 0) end
    local s = "h532b" .. tag
    for i = 1, #s do memory.write_byte(p + i - 1, string.byte(s, i)) end
    return p
end
local okc, id = pcall(function() return sc549(U(name_page("a")), U(1), U(0), U(0x100)) end)
local okd, rvd = pcall(function() return make_syscall(550)(U(to_num(id))) end)
print(string.format("[Z] create=%s destroy=%s alive=true",
    okc and hex(id) or "FAIL", okd and hex(rvd) or "FAIL"))
print("=== PROBE 856b COMPLETE ===")
