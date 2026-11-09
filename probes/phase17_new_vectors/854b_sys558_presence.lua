-- CRASH_CLASS: LOW
-- PROBE 854b: is syscall 558 present on 14.10, and does 551 need the name flag?
print("=== PROBE 854b: SYS 558 PRESENCE ===")
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
local sc558, sc549, sc551, sc550, sc555 = make_syscall(558), make_syscall(549), make_syscall(551), make_syscall(550), make_syscall(555)
local nb = memory.alloc(0x60)
local function setname(s)
    for off = 0, 0x5C, 4 do pcall(function() memory.write_dword(nb + off, 0) end) end
    for i = 1, #s do pcall(function() memory.write_byte(nb + i - 1, s:byte(i)) end) end
end
print(string.format("[0] pid=%d", to_num(syscall.getpid())))
print(string.format("[A] 558(0,0)=%s  558(1,1)=%s  558(0,0x2000)=%s  558(0xFFFF,0x2000)=%s",
    call(sc558, uint64(0), uint64(0)), call(sc558, uint64(1), uint64(1)),
    call(sc558, uint64(0), uint64(0x2000)), call(sc558, uint64(0xFFFF), uint64(0x2000))))
setname("nm1")
local id = to_num(sc549(uint64(nb), uint64(0x101), uint64(1), uint64(0x100)))
print(string.format("[B] create(flags 0x101) id=%s  551(name)=%s  555(+1)=%s", hx(id), call(sc551, uint64(nb)), call(sc555, uint64(id), uint64(1))))
print(string.format("[C] 558(id,0x1120)=%s  558(id,0x120)=%s  551(name after)=%s", call(sc558, uint64(id), uint64(0x1120)), call(sc558, uint64(id), uint64(0x120)), call(sc551, uint64(nb))))
print(string.format("[D] 550(id)=%s  health create=%s", call(sc550, uint64(id)), call(sc549, uint64(nb), uint64(0x101), uint64(1), uint64(0x100))))
print("[E] alive=true")
