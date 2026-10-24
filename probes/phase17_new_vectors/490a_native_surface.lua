-- CRASH_CLASS: LOW
-- PROBE 490a: what the loader exposes for a second caller
-- The aio delete race needs two concurrent calls to 662. The loader gives one
-- OS thread; thr_create(430) works but the child can only run existing code.
-- Before hunting a "syscall; ret" gadget, list what the loader already offers:
-- native.* helpers, thread helpers, and the module handle list from 593.
print("=== PROBE 490a: loader native surface ===")
io.stdout:setvbuf("no")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function dump(name, t)
  if type(t) ~= "table" then print(name .. " = " .. tostring(t)); return end
  local keys = {}
  for k, v in pairs(t) do keys[#keys + 1] = tostring(k) .. ":" .. type(v) end
  table.sort(keys)
  print(name .. " (" .. #keys .. "): " .. table.concat(keys, " "))
end
dump("native", native)
dump("thread", thread)
dump("memory", memory)
dump("loadlib", loadlib)
print("syscall.pipe = " .. tostring(syscall.pipe))
print("fcall_stub  = " .. tostring(rawget(native or {}, "fcall_stub")))
print("=== PROBE 490a COMPLETE ===")
