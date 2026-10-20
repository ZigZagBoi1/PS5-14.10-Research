-- CRASH_CLASS: LOW
-- PROBE 84j: Socket with uint64 args, step by step

print("=== PROBE 84j ===")
print("pid=" .. tostring(syscall.getpid()))

-- Socket AF_INET6=28, SOCK_DGRAM=2, IPPROTO_UDP=17
print("calling socket")
local ok, ret = pcall(function()
    return syscall.socket(uint64(28), uint64(2), uint64(17))
end)
print("ok=" .. tostring(ok))
if ok then print("ret=" .. tostring(ret)) end
if not ok then print("err=" .. tostring(ret)) end

-- If socket worked, close it
if ok then
    local fd = ret
    if type(fd) == "table" and fd.tonumber then fd = fd:tonumber() end
    fd = tonumber(fd) or 0
    print("fd=" .. fd)
    if fd > 0 then
        pcall(function() syscall.close(uint64(fd)) end)
        print("closed")
    end
end

print("=== PROBE 84j COMPLETE ===")
