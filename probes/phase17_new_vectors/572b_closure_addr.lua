-- CRASH_CLASS: LOW
print("=== 572b: closure address formats ===")
local names = {"rawequal","rawget","rawset","type","tostring","select","pairs","next","pcall","error"}
for _, n in ipairs(names) do
    local f = _G[n]
    if f then
        local s = tostring(f)
        print(string.format("%-10s type=%s tostring=%q", n, type(f), s))
    end
end
print("pipe: " .. tostring(syscall.pipe))
