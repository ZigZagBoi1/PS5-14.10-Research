-- CRASH_CLASS: MODERATE
-- PROBE 513a: why 591 fails.
--
-- 512a: 592 returns 39 handles that 593 accepts, but 591 returns -1 for every
-- one with name "sceKernelGetProcessId".  If 14.10 kept the 13.60 body, the
-- failure is one of: process dynlib object NULL (error 1), handle lookup
-- (error 3), caller-module attribution (error 3), or name resolution.  This
-- varies the argument count and the name to see whether any input changes the
-- return value at all.

print("=== PROBE 513a: 591 ARGUMENT SHAPES ===")
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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end
    return nil
end
local function hexq(v)
    if v == nil then return "nil" end
    if type(v) == "table" and v.h then return string.format("0x%08X_%08X", to_num(v.h), to_num(v.l)) end
    return string.format("0x%X", to_num(v))
end
local function strbuf(s)
    local b = memory.alloc(0x60)
    for i = 1, #s do pcall(function() memory.write_byte(b + i - 1, string.byte(s, i)) end) end
    pcall(function() memory.write_byte(b + #s, 0) end)
    return b
end

local sc591 = make_syscall(591)
local out = memory.alloc(8)

local function call(nargs, handle, namep, outp, tag)
    pcall(function() memory.write_qword(out, 0xDEADBEEF) end)
    local ok, rv = pcall(function()
        local sc = sc591
        local a1, a2, a3 = uint64(handle), uint64(namep), uint64(outp)
        local a4, a5, a6 = uint64(0), uint64(0), uint64(0)
        if nargs == 3 then return sc(a1, a2, a3) end
        if nargs == 4 then return sc(a1, a2, a3, a4) end
        return sc(a1, a2, a3, a4, a5, a6)
    end)
    print(string.format("    %-34s n=%d ret=%s out=%s", tag, nargs,
        ok and tostring(to_num(rv)) or "pcall-fail", hexq(rq(out))))
end

local names = {"sceKernelGetProcessId", "syscall", "getpid"}
local nm_bufs = {}
for i = 1, #names do nm_bufs[i] = strbuf(names[i]) end

print("[A] handles x names, 3 args")
local handles = {0, 0x2001, 2, 0x11}
for i = 1, #handles do
    for j = 1, #names do
        call(3, handles[i], nm_bufs[j], out, string.format("h=%X %s", handles[i], names[j]))
    end
end

print("[B] handle 0x2001, 4 and 6 args")
call(4, 0x2001, nm_bufs[1], out, "h=2001 name1")
call(6, 0x2001, nm_bufs[1], out, "h=2001 name1")
call(6, 0x2001, nm_bufs[2], out, "h=2001 syscall")

print("[C] NULL name / NULL out")
call(3, 0x2001, 0, out, "h=2001 name=NULL")
call(3, 0x2001, nm_bufs[1], 0, "h=2001 out=NULL")

print("[D] 592 list index 2 (h=2) with 6 args")
call(6, 2, nm_bufs[1], out, "h=2 name1")
print("=== DONE ===")
