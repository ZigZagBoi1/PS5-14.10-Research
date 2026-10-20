-- CRASH_CLASS: LOW
-- PROBE 125b: Read kernel.lua source to understand bootstrap requirements
-- kernel.addr is empty — we need to know what fields it expects
-- and how initialize_kernel_rw populates them

print("=== PROBE 125b: READ KERNEL.LUA ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end

print("pid=" .. to_num(syscall.getpid()))

-- Read the source files from savedata0
-- The debug info shows paths like @/savedata0/kernel.lua
-- Try to read the file directly
local paths = {
    "/savedata0/kernel.lua",
    "/savedata0/native.lua",
    "/savedata0/ipv6_kernel_rw.lua",
}

for _, path in ipairs(paths) do
    print("")
    print("--- FILE: " .. path .. " ---")
    local ok, f = pcall(io.open, path, "r")
    if ok and f then
        local content = f:read("*a")
        f:close()
        if content then
            print("SIZE=" .. #content)
            print(content)
        else
            print("READ_FAILED")
        end
    else
        print("OPEN_FAILED: " .. tostring(f))
        -- Try loadfile to check if it exists
        local ok2, chunk = pcall(loadfile, path)
        if ok2 and chunk then
            print("loadfile succeeded (file exists, readable as Lua)")
            local di = debug.getinfo(chunk, "SLnu")
            print("  src=" .. tostring(di.source) .. " lines=" .. tostring(di.linedefined) .. "-" .. tostring(di.lastlinedefined))
        else
            print("loadfile: " .. tostring(chunk))
        end
    end
end

-- Also dump kernel.lua functions line ranges to understand structure
print("")
print("--- KERNEL MODULE FUNCTION MAP ---")
local funcs = {}
for k, v in pairs(kernel) do
    if type(v) == "function" then
        local di = debug.getinfo(v, "SLnu")
        funcs[#funcs+1] = {name=k, line=di.linedefined or 0, last=di.lastlinedefined or 0}
    end
end
table.sort(funcs, function(a,b) return a.line < b.line end)
for _, f in ipairs(funcs) do
    print(string.format("  %3d-%3d: %s", f.line, f.last, f.name))
end

-- Same for ipv6_kernel_rw
print("")
print("--- IPV6_KERNEL_RW FUNCTION MAP ---")
local funcs2 = {}
for k, v in pairs(ipv6_kernel_rw) do
    if type(v) == "function" then
        local di = debug.getinfo(v, "SLnu")
        funcs2[#funcs2+1] = {name=k, src=di.source, line=di.linedefined or 0, last=di.lastlinedefined or 0}
    end
end
table.sort(funcs2, function(a,b) return a.line < b.line end)
for _, f in ipairs(funcs2) do
    print(string.format("  %3d-%3d: %s (%s)", f.line, f.last, f.name, f.src))
end

-- Same for native
print("")
print("--- NATIVE FUNCTION MAP ---")
local funcs3 = {}
for k, v in pairs(native) do
    if type(v) == "function" then
        local di = debug.getinfo(v, "SLnu")
        funcs3[#funcs3+1] = {name=k, line=di.linedefined or 0, last=di.lastlinedefined or 0}
    end
end
table.sort(funcs3, function(a,b) return a.line < b.line end)
for _, f in ipairs(funcs3) do
    print(string.format("  %3d-%3d: %s", f.line, f.last, f.name))
end

print("=== PROBE 125b COMPLETE ===")
