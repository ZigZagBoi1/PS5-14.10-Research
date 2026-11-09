-- CRASH_CLASS: LOW
-- PROBE 84g: Understand how to call syscall objects
-- syscall.getpid() works. Check how syscall.socket is structured.

print("=== PROBE 84g: SYSCALL INTERFACE ===")

-- First just getpid to confirm we're alive
print("pid=" .. tostring(syscall.getpid()))

-- Dump syscall.socket structure
print("")
print("--- SOCKET TABLE ---")
if type(syscall.socket) == "table" then
    for k, v in pairs(syscall.socket) do
        print("S:" .. tostring(k) .. " " .. type(v) .. "=" .. tostring(v))
    end
    local mt = getmetatable(syscall.socket)
    if mt then
        print("MT:")
        for k, v in pairs(mt) do
            print("  " .. tostring(k) .. " " .. type(v))
        end
    end
end

-- Dump syscall.pipe structure
print("")
print("--- PIPE TABLE ---")
if type(syscall.pipe) == "table" then
    for k, v in pairs(syscall.pipe) do
        print("P:" .. tostring(k) .. " " .. type(v) .. "=" .. tostring(v))
    end
end

-- Dump syscall.mmap
print("")
print("--- MMAP TABLE ---")
if type(syscall.mmap) == "table" then
    for k, v in pairs(syscall.mmap) do
        print("M:" .. tostring(k) .. " " .. type(v) .. "=" .. tostring(v))
    end
end

-- Dump syscall.getpid
print("")
print("--- GETPID TABLE ---")
if type(syscall.getpid) == "table" then
    for k, v in pairs(syscall.getpid) do
        print("GP:" .. tostring(k) .. " " .. type(v) .. "=" .. tostring(v))
    end
end

-- Check syscall.init bytecode
print("")
print("--- SYSCALL.INIT ---")
if syscall.init then
    local ok, bc = pcall(string.dump, syscall.init)
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
        print("strings:")
        for _, s in ipairs(strs) do print("  " .. s) end
    end
end

-- Check syscall.resolve bytecode
print("")
print("--- SYSCALL.RESOLVE ---")
if syscall.resolve then
    local ok, bc = pcall(string.dump, syscall.resolve)
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
        print("strings:")
        for _, s in ipairs(strs) do print("  " .. s) end
    end
end

print("=== PROBE 84g COMPLETE ===")
