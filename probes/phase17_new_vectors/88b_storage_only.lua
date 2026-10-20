-- CRASH_CLASS: LOW
-- PROBE 88b: Check storage for saved kernel_rw state

print("=== PROBE 88b ===")

-- Check storage
print("storage type=" .. type(storage))
if type(storage) == "table" then
    -- List what functions storage has
    for k, v in pairs(storage) do
        print("storage." .. tostring(k) .. "=" .. type(v))
    end
    -- Try to get kernel_rw
    local ok1, krw = pcall(storage.get, "kernel_rw")
    print("get(kernel_rw) ok=" .. tostring(ok1) .. " val=" .. tostring(krw))
    if ok1 and krw and type(krw) == "table" then
        for k, v in pairs(krw) do
            print("  krw." .. tostring(k) .. "=" .. tostring(v))
        end
    end
    -- Try other keys
    for _, key in ipairs({"exploit", "kbase", "kernel_base", "allproc", "pipe_addr", "kslide"}) do
        local ok2, val = pcall(storage.get, key)
        if ok2 and val ~= nil then
            print("storage[" .. key .. "]=" .. tostring(val))
        end
    end
end

-- Check kernel.addr contents
print("")
print("kernel.addr count:")
local cnt = 0
if type(kernel) == "table" and type(kernel.addr) == "table" then
    for k, v in pairs(kernel.addr) do
        cnt = cnt + 1
        print("  " .. tostring(k) .. "=" .. tostring(v))
    end
end
print("count=" .. cnt)

-- Check ipv6_kernel_rw.data
print("")
if type(ipv6_kernel_rw) == "table" and type(ipv6_kernel_rw.data) == "table" then
    print("ipv6_kernel_rw.data:")
    for k, v in pairs(ipv6_kernel_rw.data) do
        print("  " .. tostring(k) .. "=" .. tostring(v))
    end
else
    print("ipv6_kernel_rw.data empty or nil")
end

print("=== PROBE 88b COMPLETE ===")
