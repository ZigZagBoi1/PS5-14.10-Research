-- CRASH_CLASS: LOW
-- PROBE 501c: sys 572 wrote 0x116b0000 into the third argument; dump the record
print("=== PROBE 501c: sys 572 output record ===")
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
local function hx(a) return string.format("0x%X", a) end
local sc = make_syscall(572)
local struct = memory.alloc(0x400)
local out = memory.alloc(0x400)
local function clear(p, n)
  for o = 0, n - 1, 4 do pcall(function() memory.write_dword(p + o, 0) end) end
end
local function dump(tag)
  local s, kern = {}, 0
  for o = 0, 0x3C, 4 do
    local v = to_num(memory.read_dword(out + o))
    s[#s + 1] = string.format("%02X:%08X", o, v)
  end
  for o = 0, 0x3F8, 8 do
    local q = memory.read_qword(out + o)
    local h = 0
    if type(q) == "table" then h = q.h or 0 end
    if h >= 0xFFFF8000 and not (h == 0xFFFFFFFF) then kern = kern + 1 end
  end
  print(tag .. " | " .. table.concat(s, " ") .. " | kern=" .. kern)
end
clear(struct, 0x400); clear(out, 0x400)
local r = sc(uint64(hx(to_num(struct))), uint64(0x400), uint64(hx(to_num(out))), uint64(0x400), uint64(0), uint64(0))
print("zeroed ret=" .. tostring(r)); dump("zeroed")
for v = 0, 4 do
  clear(struct, 0x400); clear(out, 0x400)
  pcall(function() memory.write_dword(struct, v) end)
  local r2 = sc(uint64(hx(to_num(struct))), uint64(0x400), uint64(hx(to_num(out))), uint64(0x400), uint64(0), uint64(0))
  print("struct[0]=" .. v .. " ret=" .. tostring(r2)); dump("s0=" .. v)
end
for v = 0, 3 do
  clear(struct, 0x400); clear(out, 0x400)
  pcall(function() memory.write_dword(struct + 0x10, v) end)
  local r3 = sc(uint64(hx(to_num(struct))), uint64(0x400), uint64(hx(to_num(out))), uint64(0x400), uint64(0), uint64(0))
  print("struct+0x10=" .. v .. " ret=" .. tostring(r3)); dump("s10=" .. v)
end
print("=== PROBE 501c COMPLETE ===")
