-- CRASH_CLASS: RISKY
-- PROBE 492d: is the poll out-pointer validated before the store?
-- 492c: poll writes 16 bytes to *(request+0x18) = { status 0x80020005, state 3 }.
-- A user heap page is accepted. If the store is a raw kernel store, an unmapped
-- user address faults in kernel mode; if it is copyout, the call simply reports
-- an error. 0x1000 is deliberately unmapped, so the two outcomes differ.
print("=== PROBE 492d: out-pointer validation ===")
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
local data = memory.alloc(0x2000)
local out  = memory.alloc(0x100)
local ids  = memory.alloc(0x100)
local res  = memory.alloc(0x400)
local sc669 = make_syscall(669)
local sc664 = make_syscall(664)
local function fill(buf, n, v)
  for off = 0, n - 1, 4 do pcall(function() memory.write_dword(buf + off, v) end) end
end
local function trial(label, ptr)
  fill(data, 0x2000, 0)
  fill(out, 0x100, 0)
  pcall(function() memory.write_qword(data + 0x18, ptr) end)
  local ok, rv = pcall(function() return sc669(uint64(1), uint64(data), uint64(1), uint64(1), uint64(out)) end)
  local id = to_num(memory.read_dword(out))
  print(string.format("%s create ok=%s ret=%s id=%d", label, tostring(ok), ok and tostring(to_num(rv)) or "-", id))
  if not ok or id <= 0 then return end
  pcall(function() memory.write_dword(ids, id) end)
  fill(res, 0x400, 0x77777777)
  local pok, prv = pcall(function() return sc664(uint64(ids), uint64(1), uint64(res)) end)
  print(string.format("%s poll ok=%s ret=%s res0=%#x res1=%#x", label, tostring(pok),
        pok and tostring(to_num(prv)) or "-", to_num(memory.read_dword(res)), to_num(memory.read_dword(res + 4))))
end
trial("[A] unmapped 0x1000", uint64(0x1000))
print("[A] survived")
trial("[B] unmapped 0x700000000000", uint64(0x700000000000))
print("[B] survived")
print("=== PROBE 492d COMPLETE ===")
