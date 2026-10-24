-- CRASH_CLASS: LOW
-- PROBE 490c: read the loader's thread.lua
-- 490b failed inside it: "/savedata0/thread.lua:41: attempt to index local 'obj'".
-- The loader runs on the console, so its own helper source is readable with io.
print("=== PROBE 490c: thread.lua source ===")
io.stdout:setvbuf("no")
local paths = {"/savedata0/thread.lua", "/app0/thread.lua", "thread.lua", "/data/thread.lua"}
local src, used = nil, nil
for _, p in ipairs(paths) do
  local ok, f = pcall(io.open, p, "r")
  if ok and f then src = f:read("*a"); f:close(); used = p; break end
end
if not src then print("thread.lua not readable") else
  print("source: " .. used .. " (" .. #src .. " bytes)")
  local n = 0
  for line in src:gmatch("[^\n]*\n?") do
    if #line > 0 then
      n = n + 1
      if n <= 120 then print(string.format("%3d| %s", n, (line:gsub("\n$", "")))) end
    end
  end
  print("lines: " .. n)
end
print("=== PROBE 490c COMPLETE ===")
