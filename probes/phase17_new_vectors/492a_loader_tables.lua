-- CRASH_CLASS: LOW
-- PROBE 492a: the loader's own tables
-- thread.lua calls Thrd_create through libc_addrofs, and ropchain uses a
-- gadgets table. If either already carries a syscall entry, a second thread can
-- issue 662 without hunting for code.
print("=== PROBE 492a: libc_addrofs / gadgets ===")
io.stdout:setvbuf("no")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function hexq(v)
    local hi, lo = 0, 0
    if type(v) == "table" and v.h then hi, lo = v.h, v.l else lo = to_num(v) end
    return string.format("%08X%08X", hi % 0x100000000, lo % 0x100000000)
end
local function dump(name, t)
  if type(t) ~= "table" then print(name .. " = " .. tostring(t)); return end
  local keys = {}
  for k, v in pairs(t) do keys[#keys + 1] = tostring(k) end
  table.sort(keys)
  print(name .. " (" .. #keys .. "):")
  for _, k in ipairs(keys) do
    local v = t[k]
    if type(v) == "number" or (type(v) == "table" and v.tonumber) then
      print(string.format("  %-28s %s", k, hexq(v)))
    else
      print(string.format("  %-28s (%s)", k, type(v)))
    end
  end
end
dump("libc_addrofs", libc_addrofs)
dump("gadgets", gadgets)
print("=== PROBE 492a COMPLETE ===")
