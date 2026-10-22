-- CRASH_CLASS: MODERATE (0x12 writes into the process structure if it is reached)
-- PROBE 322a: sys 601 mdbg_service - the no-auth commands, called again
--
-- sys_601_deep.md maps 40 commands. The ones with no credential check are
-- 0x00 (state query), 0x05 (0xb8-byte process info), 0x06, 0x07 bitfield,
-- 0x09 global byte, 0x0a, 0x0d (thread list), 0x10 (0x1000-byte kernel
-- allocation followed by copyout) and 0x12 (writes to proc +0x528, +0x578,
-- +0x580). 55d called this handler on 18 Oct and recorded -1 nearly everywhere,
-- before the argument-layout lessons of 622 and 532.
--
-- This calls each no-auth command with a real buffer and with scalar
-- arguments, prints the return and the first words of the buffer, and never
-- sends 0x12 more than once.

print("=== PROBE 322a: SYS 601 commands ===")

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
local function hi_lo(v)
    if type(v) == "table" and v.h then return v.h, to_num(v.l) end
    return 0, to_num(v)
end
local function sgn(v)
    local h, l = hi_lo(v)
    if (h % 4294967296) == 4294967295 and (l % 4294967296) == 4294967295 then return -1 end
    if h >= 0xFFFF8000 then return -1 end
    return l
end
local function U32(v) return uint64(v) end
local function U64(x) return uint64(string.format("0x%X", x)) end

local sc = make_syscall(601)
local page = memory.alloc(0x1000)
local function zero_page()
    for i = 0, 0xFFC, 8 do pcall(function() memory.write_qword(page + i, uint64(0xB1B2B3B4B5B6B7B8)) end) end
end
local function peek()
    local s = ""
    for i = 0, 3 do s = s .. string.format(" %08X", to_num(memory.read_dword(page + i * 4))) end
    return s
end

local function call(tag, cmd, a1, a2)
    zero_page()
    local ok, rv = pcall(function() return sc(U32(cmd), a1, a2) end)
    print(string.format("  %-22s cmd=0x%02X ret=%-12s buf:%s", tag, cmd,
        ok and tostring(sgn(rv)) or "DIED", peek()))
end

print("[A] commands that take an output buffer")
call("state query", 0x00, uint64(page), U64(0x100))
call("process info 0xb8", 0x05, uint64(page), U64(0x100))
call("process status", 0x06, uint64(page), U64(0x100))
call("thread list", 0x0d, uint64(page), U64(0x100))
call("device state", 0x13, uint64(page), U64(0x100))
call("device name", 0x14, uint64(page), U64(0x100))

print("")
print("[B] commands that take scalars")
call("bitfield", 0x07, U64(0x12345678), U64(0))
call("global byte", 0x09, U64(0), U64(0))

print("")
print("[C] the kernel allocation and copyout")
call("kernel alloc", 0x10, uint64(page), U64(0x1000))
call("kernel alloc sz", 0x10, uint64(page), U64(0x40))

print("")
print("[D] the process structure write, once")
call("proc write", 0x12, U64(0x41414141), U64(0x42424242))

print("")
print("=== PROBE 322a COMPLETE ===")
