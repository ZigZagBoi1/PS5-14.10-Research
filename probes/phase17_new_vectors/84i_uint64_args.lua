-- CRASH_CLASS: LOW
-- PROBE 84i: Test syscall with uint64 args step by step

print("=== PROBE 84i: UINT64 ARGS ===")

-- Alive check
print("alive")
local pid = syscall.getpid()
print("pid=" .. tostring(pid))

-- Try with 1 arg
print("test1")
local ok1, ret1 = pcall(function()
    return syscall.getpid(uint64(0))
end)
print("1arg ok=" .. tostring(ok1) .. " ret=" .. tostring(ret1))

print("=== PROBE 84i COMPLETE ===")
