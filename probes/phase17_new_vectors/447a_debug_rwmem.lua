-- CRASH_CLASS: HIGH
-- PROBE 447a: sys 619 is named test_debug_rwmem, and sys 603 rdup
--
-- Neither number has ever been called with anything but six zeros (the whole sweep, probes
-- 354d and 446a), and six zeros cannot separate "rejects the arguments" from "not
-- implemented". The 13.60 sysent name for 619 is `test_debug_rwmem`, which would be a memory
-- primitive if it is implemented at all, and 603 is `rdup`, a path-to-descriptor call.
--
-- Each shape is separate so the print before it says what was being asked.

print("=== PROBE 447a: 619 test_debug_rwmem / 603 rdup ===")

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
        return sc(uint64(a1 or 0), uint64(a2 or 0), uint64(a3 or 0), uint64(a4 or 0), uint64(a5 or 0), uint64(a6 or 0))
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
local function fmt(v)
    if v == -999 then return "EXC" end
    if v == -1 then return "-1" end
    return string.format("0x%X", v)
end

local sa = call(477, 0, 0x10, 7, 0x1002, 0xFFFFFFFF, 0)
memory.write_qword(sa, 1)
print(string.format("[A] sigaction(12, SIG_IGN) = %d", call(416, 12, sa, 0)))

local p1 = call(477, 0, 0x1000, 7, 0x1002, 0xFFFFFFFF, 0)
local p2 = call(477, 0, 0x1000, 7, 0x1002, 0xFFFFFFFF, 0)
memory.write_qword(p1, 0x1111222233334444)
memory.write_qword(p2, 0x5555666677778888)
print(string.format("[B] p1=0x%X p2=0x%X", p1, p2))
if p1 <= 0 or p2 <= 0 then print("=== 447a DONE ===") return end

local function show(tag, rv)
    print(string.format("    %-28s rv=%-10s p1=%08X p2=%08X", tag, fmt(rv),
        to_num(memory.read_dword(p1)), to_num(memory.read_dword(p2))))
end

print("[C] 619 with the argument shapes the name suggests")
show("619(0,0,0,0,0,0)", call(619, 0, 0, 0, 0, 0, 0))
show("619(p1,8,p2,8)", call(619, p1, 8, p2, 8, 0, 0))
show("619(p2,p1,8,0)", call(619, p2, p1, 8, 0, 0, 0))
show("619(1,p1,8,p2)", call(619, 1, p1, 8, p2, 0, 0))
show("619(0,p1,8,p2)", call(619, 0, p1, 8, p2, 0, 0))
show("619(p1,p2,8,0)", call(619, p1, p2, 8, 0, 0, 0))
show("619(8,p1,p2,0)", call(619, 8, p1, p2, 0, 0, 0))
show("619(p1,0x1000,0,0)", call(619, p1, 0x1000, 0, 0, 0, 0))
show("619(0,p1,0x1000,0)", call(619, 0, p1, 0x1000, 0, 0, 0))

print("")
print("[D] 603 rdup")
local nb = call(477, 0, 0x200, 7, 0x1002, 0xFFFFFFFF, 0)
local function put(off, s)
    local i = 1
    while i <= #s do memory.write_byte(nb + off + i - 1, string.byte(s, i)); i = i + 1 end
    memory.write_byte(nb + off + #s, 0)
    return nb + off
end
local pz = put(0x000, "/dev/zero")
local pdce = put(0x040, "/dev/dce")
local papp = put(0x080, "/app0/eboot.bin")
local psys = put(0x0C0, "/system/common")
show("rdup(/dev/zero)", call(603, pz, 0, 0, 0, 0, 0))
show("rdup(/dev/dce)", call(603, pdce, 0, 0, 0, 0, 0))
show("rdup(/app0/eboot.bin)", call(603, papp, 0, 0, 0, 0, 0))
show("rdup(/system/common)", call(603, psys, 0, 0, 0, 0, 0))
show("rdup(NULL)", call(603, 0, 0, 0, 0, 0, 0))
print("=== 447a DONE ===")
