-- CRASH_CLASS: LOW
-- PROBE 566d: what do memory.alloc results look like here
print("=== PROBE 566d: ALLOC SHAPES ===")
local names = { "reqs", "data", "result", "ids", "states", "fds", "msg" }
local sizes = { 0x200, 0x1000, 0x200, 0x200, 0x100, 0x20, 0x20 }
for i = 1, #names do
    local v = memory.alloc(sizes[i])
    local t = type(v)
    local h, l = "?", "?"
    local ok, hv = pcall(function() return v.h end)
    if ok then h = tostring(hv) end
    local ok2, lv = pcall(function() return v.l end)
    if ok2 then l = tostring(lv) end
    print(string.format("%s size=%03X type=%s h=%s l=%s", names[i], sizes[i], t, h, l))
    local ok3, sum = pcall(function() return v + 4 end)
    print(string.format("   v+4 ok=%s", tostring(ok3)))
end
print("=== 566d DONE ===")
