-- CRASH_CLASS: LOW
-- PROBE 84k: Test socket + setsockopt only

print("=== PROBE 84k ===")
print("pid=" .. tostring(syscall.getpid()))

-- Create socket
print("creating socket")
local fd = syscall.socket(uint64(28), uint64(2), uint64(17))
print("fd=" .. tostring(fd))

-- Try setsockopt
print("setsockopt")
local optbuf = memory.alloc(4)
memory.write_dword(optbuf, 1)
local ok, ret = pcall(function()
    return syscall.setsockopt(uint64(fd), uint64(41), uint64(46),
        uint64(optbuf), uint64(4))
end)
print("ok=" .. tostring(ok))
if ok then print("ret=" .. tostring(ret)) end
if not ok then print("err=" .. tostring(ret)) end

-- Close
pcall(function() syscall.close(uint64(fd)) end)
print("done")
print("=== PROBE 84k COMPLETE ===")
