-- CRASH_CLASS: HIGH (reads a physhm mapping)
-- PROBE 321a: the physhm mapping with its full 64-bit address
--
-- 315a/316a/318a read at an address built by sgn(), which returns only the low
-- 32 bits of a value. Every mmap return was therefore truncated - 0x1100C000
-- instead of 0x31100C000 - and the reads went somewhere else entirely, which is
-- why the process died without ever reaching a labelled line.
--
-- This keeps the high half, formats every address as a full uint64, and makes
-- exactly one read before reporting. If that read returns, the mapping is real
-- and readable and the previous three probes were measuring the wrong address.

print("=== PROBE 321a: physhm with the full pointer ===")

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
local function is_err(v)
    local h, l = hi_lo(v)
    if (h % 4294967296) == 4294967295 and (l % 4294967296) == 4294967295 then return true end
    if h >= 0xFFFF8000 then return true end
    return false
end
local function full_hex(v)
    local h, l = hi_lo(v)
    return string.format("0x%X%08X", h, l)
end
local function U64(v)
    local h, l = hi_lo(v)
    return uint64(string.format("0x%X%08X", h, l))
end
local function U32(v) return uint64(v) end

local sc629 = make_syscall(629)
local sc_mmap = make_syscall(477)
local sc_close = make_syscall(6)

local fdv = sc629(uint64(1), U32(2), U32(0), U32(0))
print(string.format("M1 fd raw=%s", full_hex(fdv)))
if is_err(fdv) then print("no descriptor") return end
local fd = to_num(fdv)

local pv = sc_mmap(uint64(0), U32(0x1000), U32(3), U32(1), U32(fd), uint64(0))
print(string.format("M2 mmap raw=%s", full_hex(pv)))
if is_err(pv) then print("mmap refused") sc_close(U32(fd)) return end

local a = U64(pv)
local ok, v = pcall(function() return memory.read_qword(a) end)
print("M3 read ok=" .. tostring(ok) .. " raw=" .. (ok and full_hex(v) or "?"))
if ok then
    print("M4 second=" .. full_hex(memory.read_qword(a + uint64(8))))
end
sc_close(U32(fd))
print("M5 done")
print("=== PROBE 321a COMPLETE ===")
