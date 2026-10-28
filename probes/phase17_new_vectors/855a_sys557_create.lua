-- CRASH_CLASS: MODERATE
-- PROBE 855a: sys 557 creates a named object of type 0x1000|arg3; 558 with arg2=arg3 should destroy it
print("=== PROBE 855a: SYS 557 CREATE, 558 DESTROY ===")
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
local function hx(v)
    if type(v) == "table" and v.h then return string.format("%08X%08X", to_num(v.h), to_num(v.l)) end
    local n = to_num(v); if n < 0 then return string.format("-%X", -n) end
    return string.format("%X", n)
end
local function call(f, ...)
    local ok, r = pcall(f, ...); if not ok then return "ERR" end; return hx(r)
end
local sc557, sc558, sc551, sc549 = make_syscall(557), make_syscall(558), make_syscall(551), make_syscall(549)
local nb = memory.alloc(0x40)
local function setname(s)
    for off = 0, 0x3C, 4 do pcall(function() memory.write_dword(nb + off, 0) end) end
    for i = 1, #s do pcall(function() memory.write_byte(nb + i - 1, s:byte(i)) end) end
    return s
end
print(string.format("[0] pid=%d", to_num(syscall.getpid())))
setname("s557a")
local ida = to_num(sc557(uint64(nb), uint64(0x1234), uint64(0x200), uint64(0), uint64(0), uint64(0)))
print(string.format("[A] 557(name=s557a, val=0x1234, type=0x200) -> %s", hx(ida)))
if ida ~= -1 and ida ~= 0 then
    print(string.format("[B] 558(%X, 0x200) -> %s", ida, call(sc558, uint64(ida), uint64(0x200))))
    print(string.format("[C] 558 again -> %s   551(name) -> %s", call(sc558, uint64(ida), uint64(0x200)), call(sc551, uint64(nb))))
else
    print("[B] 557 refused; skipping the destroy stages")
end
setname("s557b")
local idb = to_num(sc557(uint64(nb), uint64(0x77), uint64(0x300), uint64(0), uint64(0), uint64(0)))
print(string.format("[D] second 557(name=s557b, val=0x77, type=0x300) -> %s", hx(idb)))
if idb ~= -1 and idb ~= 0 then
    print(string.format("[E] 558(%X, 0x300)=%s  558(%X, 0x200)=%s (wrong type must miss)", idb,
        call(sc558, uint64(idb), uint64(0x300)), idb, call(sc558, uint64(idb), uint64(0x200))))
end
print(string.format("[F] dup-name 557(s557a) -> %s", hx(to_num(sc557(uint64(nb), uint64(0x1), uint64(0x200), uint64(0), uint64(0), uint64(0))))))
print(string.format("[G] health osem create=%s", call(sc549, uint64(nb), uint64(0x101), uint64(1), uint64(0x100))))
print("[H] alive=true")
