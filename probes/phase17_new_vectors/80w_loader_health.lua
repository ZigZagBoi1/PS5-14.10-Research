-- CRASH_CLASS: LOW
-- Minimal loader health check after a connection reset.
print("=== PROBE 80w: LOADER HEALTH ===")
print("lua=" .. tostring(_VERSION))
print("syscall=" .. type(syscall))
if type(syscall) == "table" and type(syscall.resolve) == "function" then
    syscall.resolve({ sc_getpid = 20 })
    local ok, pid = pcall(function() return syscall.sc_getpid():tonumber() end)
    print("getpid_ok=" .. tostring(ok))
    if ok then print("pid=" .. tostring(pid)) end
end
print("=== PROBE 80w COMPLETE ===")
