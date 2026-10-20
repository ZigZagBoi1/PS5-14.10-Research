-- CRASH_CLASS: LOW
-- PROBE 84e: Minimal syscall test

print("=== PROBE 84e: MINIMAL ===")
print("step1")

-- Try the simplest possible syscall
local ok, ret = pcall(function()
    return syscall.getpid()
end)
print("getpid ok=" .. tostring(ok))
if ok then print("ret=" .. tostring(ret)) end
if not ok then print("err=" .. tostring(ret)) end

print("step2")
print("=== PROBE 84e COMPLETE ===")
