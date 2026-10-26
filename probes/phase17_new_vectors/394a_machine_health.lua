-- CRASH_CLASS: LOW
-- PROBE 394a: is the console healthy before anything else runs
--
-- Two console-level deaths in a row (392a and 393a) happened without a phase marker
-- reaching us, so before any further thread work this checks the machine itself:
-- the loader answers, syscall 593 still returns the eboot base, thr_self returns a
-- plausible tid, and a plain GPU mmap still succeeds. Nothing here creates a thread,
-- loops a syscall, or touches a device.

print("=== PROBE 394a: MACHINE HEALTH ===")
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
    local h, l = 0, to_num(v)
    if type(v) == "table" then h = v.h or 0; l = v.l and to_num(v.l) or 0 end
    local x = h * 4294967296 + l
    if x >= 9223372036854775808 then x = x - 18446744073709551616 end
    return x
end
local function u64(x) return uint64(string.format("0x%X", x)) end

local sc_info = make_syscall(593)
local sc_self = make_syscall(432)
local sc_mmap = make_syscall(477)

print("[1] loader is running this script, so the Lua path works")

print("[2] syscall 593")
local info = memory.alloc(0x200)
pcall(function() memory.write_dword(info, 0x160) end)
local rv = -999
pcall(function() rv = sgn(sc_info(uint64(0), uint64(info), uint64(0), uint64(0), uint64(0), uint64(0))) end)
local base = to_num(memory.read_dword(info + 0x10C)) * 4294967296 + to_num(memory.read_dword(info + 0x108))
print(string.format("    593 rv=%d eboot base=0x%X", rv, base))

print("[3] syscall 432 thr_self")
local tb = memory.alloc(8)
pcall(function() memory.write_qword(tb, u64(0x1111)) end)
local rv2 = -999
pcall(function() rv2 = sgn(sc_self(uint64(tb), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))) end)
print(string.format("    432 rv=%d out=0x%X", rv2, sgn(uint64(tb))))

print("[4] GPU mmap 8 MiB")
local m = -999
pcall(function() m = sgn(sc_mmap(uint64(0), u64(0x800000), u64(3), u64(0x1002), u64(0xFFFFFFFF), u64(0))) end)
print(string.format("    477 -> 0x%X", m))

print("[5] read the first 16 bytes of eboot text")
if base > 0 then
    local ok, s = pcall(function() return memory.read_buffer(base, 16) end)
    if ok and type(s) == "string" then
        local h = ""
        for i = 1, #s do h = h .. string.format("%02X", string.byte(s, i)) end
        print("    " .. h)
    else
        print("    read failed")
    end
end

print("")
print("=== 394a DONE ===")
