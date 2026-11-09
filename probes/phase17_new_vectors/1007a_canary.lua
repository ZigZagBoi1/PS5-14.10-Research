-- CRASH_CLASS: LOW
print("CANARY pid="..tostring(to_num and "x" or "y"))
local ok,v=pcall(function() return syscall.pipe end)
print("ok="..tostring(ok))
