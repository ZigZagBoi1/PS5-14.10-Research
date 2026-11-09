-- CRASH_CLASS: LOW
print("=== PROBE 125h: READ MAIN.LUA ===")
local f = io.open("/savedata0/main.lua", "r")
if f then print(f:read("*a")); f:close() end
print("=== END ===")
