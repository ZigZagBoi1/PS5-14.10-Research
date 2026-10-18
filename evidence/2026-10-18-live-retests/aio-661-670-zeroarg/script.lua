-- Bounded selector-returnability check for the reported Sony AIO range.
-- No memory API, file API, or non-AIO operation is used here.
-- Selector 663 is first because it is the stated priority; each selector is
-- invoked once with no explicit Lua arguments.

local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

local function describe(v)
    if type(v) == "table" then
        local h = v.h
        local l = v.l
        if h ~= nil or l ~= nil then
            return "table h=" .. tostring(h) .. " l=" .. tostring(l)
        end
    end
    return type(v) .. " " .. tostring(v)
end

local order = {663, 661, 662, 664, 665, 666, 667, 668, 669, 670}
print("=== BOUNDED AIO SELECTOR CHECK ===")
print("CALLS=" .. tostring(#order) .. " EXPLICIT_ARGS=0")
print("START")
for i, num in ipairs(order) do
    print(string.format("[%d/%d] syscall=%d BEFORE", i, #order, num))
    local sc = make_syscall(num)
    local ok, ret = pcall(function() return sc() end)
    if ok then
        print(string.format("[%d/%d] syscall=%d RETURN %s", i, #order, num, describe(ret)))
    else
        print(string.format("[%d/%d] syscall=%d LUA_ERROR %s", i, #order, num, tostring(ret)))
    end
end
print("COMPLETE")
print("=== BOUNDED AIO SELECTOR CHECK END ===")
