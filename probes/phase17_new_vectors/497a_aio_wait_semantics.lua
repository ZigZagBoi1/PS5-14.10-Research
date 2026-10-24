-- CRASH_CLASS: MODERATE
-- PROBE 497a: what does 663 (wait) do to a freshly created object?
-- 496d showed the helper tolerates exactly one live thread, so a second caller
-- cannot be another Lua state: it has to be the parent, and the thread has to be
-- inside the kernel while the parent calls. 663 is the only candidate that can
-- stay inside, but its block/timeout semantics are unknown. This measures them
-- with the parent only: created object (state 2), then polled object (state 3),
-- with and without a timeout argument.
print("=== PROBE 497a: 663 wait semantics ===")
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
local sc669, sc663, sc664 = make_syscall(669), make_syscall(663), make_syscall(664)
for off = 0, 0x2000 - 1, 4 do pcall(function() memory.write_dword(data + off, 0) end) end
local function create()
  for off = 0, 0x100 - 1, 4 do pcall(function() memory.write_dword(out + off, 0) end) end
  local ok = pcall(function() return sc669(uint64(1), uint64(data), uint64(1), uint64(1), uint64(out)) end)
  if not ok then return nil end
  return to_num(memory.read_dword(out))
end
local function call(label, fn)
  for off = 0, 0x40 - 1, 4 do pcall(function() memory.write_dword(res + off, 0x77777777) end) end
  local t0 = os.clock()
  local ok, rv = pcall(fn)
  local dt = os.clock() - t0
  print(string.format("    %-28s ok=%s ret=%s status=%#x (%0.4fs)", label, tostring(ok),
        ok and tostring(to_num(rv)) or "-", to_num(memory.read_dword(res)), dt))
  return ok and to_num(rv) or -999
end
local id = create()
print(string.format("[A] created id=%s (state 2, never polled)", tostring(id)))
if id then
  pcall(function() memory.write_dword(ids, id) end)
  call("663 no timeout (0,0)", function() return sc663(uint64(ids), uint64(1), uint64(res), uint64(0), uint64(0)) end)
  call("663 timeout=1ms", function() return sc663(uint64(ids), uint64(1), uint64(res), uint64(1), uint64(0)) end)
  call("663 timeout=200ms", function() return sc663(uint64(ids), uint64(1), uint64(res), uint64(200), uint64(0)) end)
  call("664 poll", function() return sc664(uint64(ids), uint64(1), uint64(res)) end)
  print("[B] after poll (state 3)")
  call("663 no timeout after poll", function() return sc663(uint64(ids), uint64(1), uint64(res), uint64(0), uint64(0)) end)
  call("663 timeout=200ms after poll", function() return sc663(uint64(ids), uint64(1), uint64(res), uint64(200), uint64(0)) end)
  call("662 delete", function()
    local t = make_syscall(662); return t(uint64(ids), uint64(1), uint64(res))
  end)
end
print("=== PROBE 497a COMPLETE ===")
