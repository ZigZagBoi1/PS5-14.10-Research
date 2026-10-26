-- CRASH_CLASS: HIGH
-- PROBE 357a: does an open device make the 622 0x400 group reachable
--
-- Every 0x400 call so far died before it returned, with arg1 = 0 (243a/245a/
-- 247a/355c), and the dossier reads the death as a device lookup on arg1 that
-- finds nothing. arg1 was never anything but a small integer. This process can
-- open /dev/gc, /dev/dce and /dev/gic (298a), so the obvious untried value for
-- "which device" is the descriptor of a device that is actually open.
--
-- Each attempt is printed before the call, so the first death names the value.

print("=== PROBE 357a: SYS 622, ARG1 AS AN OPEN DESCRIPTOR ===")
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
local function sgn(v)
    local l = to_num(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local U = function(h, l) return uint64(string.format("0x%X%08X", h, l)) end
local Z = uint64(0)
local function rd(a) local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end return -1 end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function str_at(addr, s)
    for i = 1, #s do pcall(function() memory.write_byte(addr + i - 1, s:byte(i)) end) end
    pcall(function() memory.write_byte(addr + #s, 0) end)
end

local page = memory.alloc(0x1000)
for i = 0, 0xFF8, 8 do wq(page + i, 0) end
local path = memory.alloc(0x40)

local fds = {}
for _, name in ipairs({"/dev/gc", "/dev/dce", "/dev/gic"}) do
    for i = 0, 0x3F, 8 do wq(path + i, 0) end
    str_at(path, name)
    local fd = sgn(make_syscall(5)(U(0, to_num(path)), U(0, 2), Z, Z, Z, Z))
    fds[#fds + 1] = string.format("%s=%d", name, fd)
end
print("[A] open: " .. table.concat(fds, "  "))

local function attempt(which, tag)
    print(string.format("  trying arg1=%s (%s)", tostring(which), tag))
    local ok, rv = pcall(function()
        return make_syscall(622)(U(0, 0x400), U(0, which), U(0, to_num(page) + 0x800), U(0, to_num(page)), U(0, 0x40), Z)
    end)
    print(string.format("    -> %s  out0=0x%X", ok and tostring(sgn(rv)) or "EXC", rd(page + 0x800)))
end

local first = sgn(make_syscall(5))
-- resolve the fd numbers we just recorded by opening again is not needed: reuse the table
local fdvals = {}
do
    local idx = 0
    for _, name in ipairs({"/dev/gc", "/dev/dce", "/dev/gic"}) do
        idx = idx + 1
        local fdv = tonumber(fds[idx]:match("=(%-?%d+)$"))
        fdvals[#fdvals + 1] = fdv
    end
end

for i = 1, #fdvals do
    attempt(fdvals[i], "open descriptor")
end
for i = 0, 3 do
    attempt(i, "small integer control")
end

print("")
print("=== 357a DONE ===")
