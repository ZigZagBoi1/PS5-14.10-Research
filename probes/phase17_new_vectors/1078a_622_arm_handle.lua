-- CRASH_CLASS: HIGH
-- PROBE 1078a: does a real object handle change the 622 0x201/0x202 arm from death to a status?
--
-- Context: the 13.60 disassembly of 622 reads its arguments as
--   r14d = uap[0x00] = command, r15d = uap[0x08] = handle, [uap+0x10] = 4-byte status out,
--   [uap+0x18], [uap+0x20] = size (must be <= 0x40).
-- The arm reached from the jump table at RVA 0x1780a4c (commands 0x201-0x271) passes the handle to
-- sub_007ddc00, which does func_0x0060ec10(handle, 0x8001, &obj). Every sweep so far sent handle 0
-- and the arm killed the game on its first command (0x201, 0x202, 0x303), which is what a NULL
-- handle dereference inside that lookup would also produce.
--
-- This probe creates one evf object (538) and passes its id, to separate "the arm needs any valid
-- object" from "the arm is unconditionally fatal". A control call with command 0x300 proves the
-- syscall path and the buffer are wired before the risky command runs.
--
-- Order matters: the control is first, the risky call second, and everything is printed before the
-- call so a death still leaves the handle and the control result in the capture.

print("=== PROBE 1078a: 622 ARM WITH A REAL HANDLE ===")
print("")

local GEN_SHIFT = 8192
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
local function slot(h) return h % GEN_SHIFT end
local function gen(h) return math.floor(h / GEN_SHIFT) end
local function tag(h) return string.format("%d(g%d/s%d)", h, gen(h), slot(h)) end
local function mkname(s)
    local p = memory.alloc(0x40)
    local j = 1
    while j <= #s do memory.write_byte(p + j - 1, s:byte(j)); j = j + 1 end
    memory.write_byte(p + #s, 0)
    return p
end

local page = call(477, 0, 0x1000, 7, 0x1002, 0xFFFFFFFF, 0)
if page <= 0 then print("no page") return end
local i = 0
while i < 0x400 do memory.write_qword(page + i, uint64(0)); i = i + 8 end
local OUT = page + 0x100          -- 4-byte status destination for 622
local function outd() local o, v = pcall(function() return memory.read_dword(OUT) end)
    if o then return to_num(v) or 0 end return -1 end

local h = call(538, mkname("omp1078a"), 0x100, 0, 0, 0, 0)
print(string.format("[A] evf handle = %s", tag(h)))
memory.write_dword(OUT, 0xA5A5A5A5)

print("[B] control: 622(0x300, handle, out, 0, 0, 0)")
local rv0 = call(622, 0x300, h, OUT, 0, 0, 0)
print(string.format("    rv=%d out=0x%08X", rv0, outd()))
memory.write_dword(OUT, 0xA5A5A5A5)

print("[C] risky: 622(0x202, handle, out, 0, 0, 0)")
local rv1 = call(622, 0x202, h, OUT, 0, 0, 0)
print(string.format("    rv=%d out=0x%08X  (survived)", rv1, outd()))

print("=== 1078a DONE ===")
