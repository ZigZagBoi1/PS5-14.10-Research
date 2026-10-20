-- CRASH_CLASS: LOW
-- PROBE 84c: Test syscall.resolve alone, then one call at a time

print("=== PROBE 84c: RESOLVE TEST ===")

-- Test 1: Just resolve, don't call
print("--- RESOLVE ---")
local fns = {"getpid", "mmap", "socket", "pipe", "close", "read", "write",
    "setsockopt", "getsockopt", "setjmp", "longjmp", "fork", "kill"}
for _, name in ipairs(fns) do
    local ok, fn = pcall(function() return syscall.resolve(name) end)
    if ok then
        print(name .. "=" .. tostring(fn) .. " type=" .. type(fn))
        if type(fn) == "function" then
            local is_lua = pcall(string.dump, fn)
            print("  lua=" .. tostring(is_lua))
        end
    else
        print(name .. " FAIL: " .. tostring(fn))
    end
end

-- Check what syscall has
print("")
print("--- SYSCALL KEYS ---")
for k, v in pairs(syscall) do
    print("SK:" .. tostring(k) .. " " .. type(v))
end

-- Check the pipe object more carefully
print("")
print("--- PIPE ---")
local p = syscall.pipe
print("pipe=" .. tostring(p))
print("pipe type=" .. type(p))

-- Read the metatable __call bytecode strings
print("")
print("--- __CALL BYTECODE ---")
local mt = getmetatable(p)
if mt and mt.__call then
    local ok, bc = pcall(string.dump, mt.__call)
    if ok then
        local strs = {}
        local i = 1
        while i <= #bc do
            local s = ""
            while i <= #bc and bc:byte(i) >= 32 and bc:byte(i) <= 126 do
                s = s .. bc:sub(i, i)
                i = i + 1
            end
            if #s >= 3 then strs[#strs+1] = s end
            i = i + 1
        end
        print("__call strings:")
        for _, s in ipairs(strs) do print("  " .. s) end
    end
end

print("=== PROBE 84c COMPLETE ===")
