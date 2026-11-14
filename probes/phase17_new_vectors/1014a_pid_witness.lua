-- CRASH_CLASS: LOW
print("PID-WITNESS pid="..tostring(syscall.pipe))
local ok,v=pcall(function() return syscall.pipe end)
print("ok="..tostring(ok))
