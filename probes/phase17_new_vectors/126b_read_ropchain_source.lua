-- CRASH_CLASS: LOW
print("=== PROBE 126b: ROPCHAIN SOURCE ===")
local f = io.open("/savedata0/ropchain.lua", "r")
if f then
    local content = f:read("*a")
    f:close()
    print("size=" .. #content)
    -- Print around line 385 where the error occurs
    local lines = {}
    for line in content:gmatch("[^\n]+") do lines[#lines+1] = line end
    print("total lines=" .. #lines)
    -- Print lines 370-400
    for i = math.max(1, 370), math.min(#lines, 420) do
        print(string.format("%d: %s", i, lines[i]))
    end
    -- Also find push_syscall_raw definition
    print("")
    print("--- push_syscall_raw ---")
    for i, line in ipairs(lines) do
        if line:find("push_syscall_raw") or line:find("push_syscall%s") then
            for j = math.max(1, i-2), math.min(#lines, i+15) do
                print(string.format("%d: %s", j, lines[j]))
            end
            print("...")
        end
    end
    -- Find constructor/new
    print("")
    print("--- new/constructor ---")
    for i, line in ipairs(lines) do
        if line:find("function.*new") or line:find("function.*ropchain") then
            for j = i, math.min(#lines, i+20) do
                print(string.format("%d: %s", j, lines[j]))
            end
            print("...")
            break
        end
    end
end
print("=== END ===")
