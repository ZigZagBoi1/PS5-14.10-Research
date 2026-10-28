-- CRASH_CLASS: LOW
-- PROBE 510e: walk the loader's ROP ring and find the real syscall transfer.
--
-- 510c/510d: the 0x300-byte chain window has only eboot gadgets, the fn slot
-- holds 0x9FE5_10AB4130 (a tagged heap pointer, not a code address), and the
-- chain ends with `pop rsp; ret` to heap 0x310AB23E0, so the chain continues in
-- a heap ring.  This walks 0x4000 bytes from the rop chain, collects every code
-- address (high 32 bits zero, above 0x10000), and prints the bytes at the two
-- interesting eboot sites.

print("=== PROBE 510e: chain ring walk ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end
    return nil
end
local function rb(a)
    local ok, v = pcall(function() return memory.read_byte(a) end)
    if ok then return to_num(v) end
    return nil
end
local function bhex(a, n)
    local s = ""
    for i = 0, n - 1 do
        local b = rb(a + i)
        s = s .. (b and string.format("%02X ", b) or "-- ")
    end
    return s
end

local sc_getpid = make_syscall(20)
local pipe_str = tostring(syscall.pipe)
local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
pcall(function() return sc_getpid() end)
if not rop_str or not fn_str then print("no chain"); print("=== DONE ==="); return end
local rop = uint64(rop_str)
local fn_slot = uint64(fn_str)

-- what the fn slot points at, tagged and untagged
local fv = rq(fn_slot)
local fh, fl = get_hi_lo(fv)
print(string.format("[0] fn value = 0x%08X_%08X", fh, fl))
print("[0] untagged bytes " .. bhex(fl, 32))
local untag = fl - (fh % 0x10000) * 4294967296
if untag ~= fl then
    print("[0] high-tag-cleared bytes " .. bhex(untag, 32))
end

print("[1] bytes at 0x5517A970: " .. bhex(0x5517A970, 24))
print("[1] bytes at 0x55185FC7: " .. bhex(0x55185FC7, 24))
print("[1] bytes at 0x552FFC18: " .. bhex(0x552FFC18, 32))

-- walk the ring
local seen, order = {}, {}
local hits = 0
for off = 0, 0x3FF8, 8 do
    local v = rq(rop + off)
    if v then
        local h, l = get_hi_lo(v)
        if h == 0 and l > 0x10000 and l < 0x800000000000 then
            hits = hits + 1
            if not seen[l] then
                seen[l] = true
                order[#order + 1] = l
            end
        end
    end
end
print(string.format("[2] walked 0x4000: %d code words, %d distinct", hits, #order))
table.sort(order)
for i = 1, #order do
    local a = order[i]
    local b0, b1, b2, b3 = rb(a), rb(a + 1), rb(a + 2), rb(a + 3)
    print(string.format("    %08X  %s %s %s %s", a,
        b0 and string.format("%02X", b0) or "--",
        b1 and string.format("%02X", b1) or "--",
        b2 and string.format("%02X", b2) or "--",
        b3 and string.format("%02X", b3) or "--"))
end
print("=== DONE ===")
