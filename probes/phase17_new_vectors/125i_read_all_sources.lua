-- CRASH_CLASS: LOW
print("=== PROBE 125i: ALL SOURCES ===")
local files = {
    "/savedata0/lua.lua",
    "/savedata0/syscall.lua",
    "/savedata0/gpu.lua",
}
for _, path in ipairs(files) do
    local f = io.open(path, "r")
    if f then
        local content = f:read("*a")
        f:close()
        print("--- " .. path .. " (" .. #content .. " bytes) ---")
        print(content)
    else
        print("--- " .. path .. " MISSING ---")
    end
end
print("=== END ===")
