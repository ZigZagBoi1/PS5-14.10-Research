-- CRASH_CLASS: LOW
-- PROBE 501b: which pointer in a caller struct does sys 572 follow?
-- 501a's canary counter had a constant 128 baseline, but sys 572 layout A read 130.
-- Here every 8-byte struct slot points at its own page, so a write reveals both the
-- struct offset that was followed and the bytes written.
print("=== PROBE 501b: sys 572 pointer follow ===")
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
local NP = 128
local pages = {}
for i = 1, NP do
  pages[i] = memory.alloc(0x1000)
  for o = 0, 0xFFC, 4 do pcall(function() memory.write_dword(pages[i] + o, 0xA5A5A5A5) end) end
end
local struct = memory.alloc(0x400)
local out = memory.alloc(0x200)
local sc = make_syscall(572)
local function hex(a) return string.format("0x%X", a) end
local ok, ret = pcall(function()
  return sc(uint64(hex(to_num(struct))), uint64(0x400), uint64(hex(to_num(out))), uint64(0x100), uint64(0), uint64(0))
end)
print("before-fill ret=" .. tostring(ret))
-- now arm the struct: slot o (qword index k) -> page k+1
for o = 0, 0x3F8, 8 do
  local k = o / 8
  pcall(function() memory.write_qword(struct + o, uint64(hex(to_num(pages[k + 1])))) end)
end
local ok2, ret2 = pcall(function()
  return sc(uint64(hex(to_num(struct))), uint64(0x400), uint64(hex(to_num(out))), uint64(0x100), uint64(0), uint64(0))
end)
print("armed ret=" .. tostring(ret2))
local changed = 0
for i = 1, NP do
  for o = 0, 0xFFC, 4 do
    local v = to_num(memory.read_dword(pages[i] + o))
    if v ~= 0xA5A5A5A5 then
      changed = changed + 1
      if changed <= 24 then
        print(string.format("page %d (struct+0x%X) +0x%03X = 0x%08X", i - 1, (i - 1) * 8, o, v))
      end
    end
  end
end
print("changed dwords=" .. changed)
print("struct first qwords kept=" .. tostring(memory.read_qword(struct)) .. " out0=" .. tostring(memory.read_dword(out)))
print("=== PROBE 501b COMPLETE ===")
