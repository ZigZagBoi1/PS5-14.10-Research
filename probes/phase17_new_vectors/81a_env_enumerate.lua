-- CRASH_CLASS: LOW
-- PROBE 81a: Enumerate entire Lua environment
-- Find hidden globals, native functions, tables we haven't explored

print("=== PROBE 81a: ENV ENUMERATE ===")

-- Dump all globals
print("--- GLOBALS ---")
local count = 0
for k, v in pairs(_G) do
    local t = type(v)
    local extra = ""
    if t == "table" then
        local n = 0
        for _ in pairs(v) do n = n + 1 end
        extra = " keys=" .. n
    elseif t == "function" then
        local is_lua = pcall(string.dump, v)
        extra = is_lua and " lua" or " C"
    end
    print("G:" .. tostring(k) .. " " .. t .. extra)
    count = count + 1
end
print("total_globals=" .. count)

-- Deep-dump interesting tables
local interesting = {"syscall", "memory", "native", "kernel", "debug", "os", "io", "package"}
for _, name in ipairs(interesting) do
    local tbl = _G[name]
    if type(tbl) == "table" then
        print("")
        print("--- TABLE: " .. name .. " ---")
        for k, v in pairs(tbl) do
            local t = type(v)
            local extra = ""
            if t == "function" then
                local is_lua = pcall(string.dump, v)
                extra = is_lua and " lua" or " C"
                extra = extra .. " str=" .. tostring(v)
            elseif t == "table" then
                local n = 0
                for _ in pairs(v) do n = n + 1 end
                extra = " keys=" .. n
            elseif t == "string" then
                extra = " val=" .. v:sub(1, 60)
            elseif t == "number" then
                extra = " val=" .. tostring(v)
            end
            print("  " .. tostring(k) .. " " .. t .. extra)
        end
        -- Check metatable
        local mt = getmetatable(tbl)
        if mt then
            print("  __MT:")
            for k, v in pairs(mt) do
                print("    " .. tostring(k) .. " " .. type(v) .. " " .. tostring(v))
            end
        end
    end
end

-- Check syscall.pipe metatable methods specifically
local mt = getmetatable(syscall.pipe)
if mt then
    print("")
    print("--- PIPE METATABLE ---")
    for k, v in pairs(mt) do
        print("PM:" .. tostring(k) .. " " .. type(v) .. " " .. tostring(v))
        if type(v) == "function" then
            local is_lua = pcall(string.dump, v)
            print("  lua_closure=" .. tostring(is_lua))
        end
        if type(v) == "table" then
            for k2, v2 in pairs(v) do
                print("  " .. tostring(k2) .. " " .. type(v2) .. " " .. tostring(v2))
            end
        end
    end
end

-- Check pipe_str for all fields
print("")
print("--- PIPE TOSTRING ---")
local ps = tostring(syscall.pipe)
for i = 1, #ps, 120 do
    print("P:" .. ps:sub(i, i + 119))
end

-- Check registry
print("")
print("--- REGISTRY ---")
local reg = debug and debug.getregistry and debug.getregistry()
if reg then
    local rc = 0
    for k, v in pairs(reg) do
        rc = rc + 1
        if rc <= 20 then
            print("R:" .. tostring(k) .. " " .. type(v))
        end
    end
    print("registry_keys=" .. rc)
else
    print("no debug.getregistry")
end

print("=== PROBE 81a COMPLETE ===")
