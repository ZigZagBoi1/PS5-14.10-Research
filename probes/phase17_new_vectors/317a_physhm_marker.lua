-- CRASH_CLASS: HIGH
-- PROBE 317a: where exactly does the physhm mapping stop the process?
--
-- 315a and 316a both printed the mmap address and then binary, never reaching
-- their next labelled line. This walks the same path with fixed markers and a
-- pcall around every access, converting the address to uint64 first, so the
-- last marker that appears names the failing step.

print("=== PROBE 317a: physhm markers ===")

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
    if type(v) == "table" and v.h then h, l = v.h, to_num(v.l) end
    if (h % 4294967296) == 4294967295 and (l % 4294967296) == 4294967295 then return -1 end
    if h >= 0xFFFF8000 then return -1 end
    return l
end
local function U32(v) return uint64(v) end

local sc629 = make_syscall(629)
local sc_mmap = make_syscall(477)
local sc_close = make_syscall(6)

print("M1 start")
local fd = sgn(sc629(uint64(1), U32(2), U32(0), U32(0)))
print(string.format("M2 fd=%d", fd))
if fd < 0 then print("M9 no descriptor") return end

local pa = sgn(sc_mmap(uint64(0), U32(0x1000), U32(3), U32(1), U32(fd), uint64(0)))
print(string.format("M3 mmap=%d (0x%X)", pa, pa))
if pa <= 0 then print("M9 mmap refused") return end

local addr = uint64(string.format("0x%X", pa))
local ok, v = pcall(function() return memory.read_qword(addr) end)
print("M4 read ok=" .. tostring(ok) .. " type=" .. type(v))
print("M5 value=0x" .. string.format("%X", to_num(v)))

ok, v = pcall(function() return memory.read_dword(addr + uint64(8)) end)
print("M6 read2 ok=" .. tostring(ok) .. " value=0x" .. string.format("%X", to_num(v)))

ok, v = pcall(function() return memory.read_qword(addr) end)
print("M7 reread=0x" .. (ok and string.format("%X", to_num(v)) or "FAULT"))

sc_close(U32(fd))
print("M8 closed")
print("=== PROBE 317a COMPLETE ===")
