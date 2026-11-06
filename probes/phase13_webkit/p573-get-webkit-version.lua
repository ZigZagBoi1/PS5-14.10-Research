-- p573: Attempt to get WebKit version from the game process
-- Try various sysctl and process info methods

local function try_sysctl(name)
    local ok, err = pcall(function()
        -- Try to get sysctl info
        local ret = make_syscall(202, 0, name, 0, 0, 0)
        return ret
    end)
    return ok and "OK" or "FAIL"
end

local function try_getpid()
    local ret = make_syscall(20, 0, 0, 0, 0, 0)
    return ret
end

local function try_kern_version()
    -- Try to get kernel version
    local ret = make_syscall(202, 1, "kern.version", 0, 0, 0)
    return ret
end

local function try_proc_info()
    -- Try to get process info
    local ret = make_syscall(117, 0, 0, 0, 0, 0)
    return ret
end

-- Main
local pid = try_getpid()
local version = try_kern_version()

print("PID: " .. tostring(pid))
print("KERN_VERSION: " .. tostring(version))

-- Try to enumerate sysctls
for i = 0, 100 do
    local ret = make_syscall(202, i, 0, 0, 0, 0)
    if ret ~= -1 and ret ~= 0 then
        print("SYSCTL[" .. i .. "]: " .. tostring(ret))
    end
end
