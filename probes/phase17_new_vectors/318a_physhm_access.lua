-- CRASH_CLASS: HIGH (writes into a physhm mapping)
-- PROBE 318a: read then write the physhm mapping, uint64 addresses, markers
--
-- 315a read the page and printed structured data (magic 0x13371337, heap
-- pointers), then died on a second 0x200000 mmap. 316a printed the mapping
-- address and never reached its first labelled line, with a plain number as the
-- read address. This run converts every address to uint64 and prints a marker
-- after each step, so one relaunch answers: readable? writable? stable?

print("=== PROBE 318a: physhm access ===")

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
local function U64(x) return uint64(string.format("0x%X", x)) end

local sc629 = make_syscall(629)
local sc_mmap = make_syscall(477)
local sc_close = make_syscall(6)

local fd = sgn(sc629(uint64(1), U32(2), U32(0), U32(0)))
print(string.format("M1 fd=%d", fd))
if fd < 0 then return end
local pa = sgn(sc_mmap(uint64(0), U32(0x1000), U32(3), U32(1), U32(fd), uint64(0)))
print(string.format("M2 mmap=%d (0x%X)", pa, pa))
if pa <= 0 then return end

local a = U64(pa)
local ok, v = pcall(function() return memory.read_qword(a) end)
print("M3 qword0 ok=" .. tostring(ok) .. " v=0x" .. string.format("%X", to_num(v)))
ok, v = pcall(function() return memory.read_qword(a + uint64(8)) end)
print("M4 qword1 ok=" .. tostring(ok) .. " v=0x" .. string.format("%X", to_num(v)))
ok, v = pcall(function() return memory.read_qword(a + uint64(0x100)) end)
print("M5 qword32 ok=" .. tostring(ok) .. " v=0x" .. string.format("%X", to_num(v)))

local okw, err = pcall(function() memory.write_qword(a, uint64(0x1122334455667788)) end)
print("M6 write ok=" .. tostring(okw))
if okw then
    local okr, rv = pcall(function() return memory.read_qword(a) end)
    print("M7 readback ok=" .. tostring(okr) .. " v=0x" .. string.format("%X", to_num(rv)))
end
sc_close(U32(fd))
print("M8 done")
print("=== PROBE 318a COMPLETE ===")
