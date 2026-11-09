-- CRASH_CLASS: LOW
-- PROBE 89d: Deep introspection of native module
-- Enumerate all functions, their upvalues, and internal state.
-- Understand how native.fcall dispatches to find if we can call
-- arbitrary native functions or if it's restricted.

print("=== PROBE 89d: NATIVE INTROSPECT ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end

print("pid=" .. to_num(syscall.getpid()))

-- Enumerate native module
print("")
print("--- NATIVE KEYS ---")
local native_keys = {}
for k, v in pairs(native) do
    native_keys[#native_keys+1] = {k=k, t=type(v), v=v}
end
table.sort(native_keys, function(a,b) return a.k < b.k end)
for _, e in ipairs(native_keys) do
    local extra = ""
    if e.t == "function" then
        -- Get debug info
        local di = debug.getinfo(e.v, "SLnu")
        extra = string.format(" src=%s:%d nups=%d what=%s",
            tostring(di.source), di.linedefined or -1,
            di.nups or 0, tostring(di.what))
    elseif e.t == "number" then
        extra = " val=" .. tostring(e.v)
    elseif e.t == "string" then
        extra = " val=" .. e.v:sub(1, 60)
    elseif e.t == "table" then
        local count = 0
        for _ in pairs(e.v) do count = count + 1 end
        extra = " #=" .. count
    end
    print(string.format("  %s (%s)%s", e.k, e.t, extra))
end

-- Examine upvalues of key functions
print("")
print("--- UPVALUES ---")
local funcs_to_check = {"fcall", "invoke", "read_buffer", "write_buffer"}
for _, fname in ipairs(funcs_to_check) do
    local f = native[fname]
    if f and type(f) == "function" then
        local di = debug.getinfo(f, "SLnu")
        print(string.format("%s: what=%s nups=%d", fname, di.what, di.nups or 0))
        for i = 1, (di.nups or 0) do
            local name, val = debug.getupvalue(f, i)
            print(string.format("  up[%d] %s = %s (%s)", i, tostring(name), tostring(val), type(val)))
            if type(val) == "table" then
                local sub = {}
                for k2, v2 in pairs(val) do
                    sub[#sub+1] = tostring(k2) .. "=" .. tostring(v2)
                end
                for j, s in ipairs(sub) do
                    if j <= 10 then print("    " .. s) end
                end
            end
        end
    end
end

-- Examine kernel module
print("")
print("--- KERNEL KEYS ---")
local kkeys = {}
for k, v in pairs(kernel) do
    kkeys[#kkeys+1] = {k=k, t=type(v), v=v}
end
table.sort(kkeys, function(a,b) return a.k < b.k end)
for _, e in ipairs(kkeys) do
    local extra = ""
    if e.t == "function" then
        local di = debug.getinfo(e.v, "SLnu")
        extra = string.format(" src=%s:%d nups=%d what=%s",
            tostring(di.source), di.linedefined or -1,
            di.nups or 0, tostring(di.what))
    elseif e.t == "table" then
        local count = 0
        for _ in pairs(e.v) do count = count + 1 end
        extra = " #=" .. count
    end
    print(string.format("  %s (%s)%s", e.k, e.t, extra))
end

-- Examine kernel_offset
print("")
print("--- KERNEL_OFFSET ---")
if kernel_offset then
    for k, v in pairs(kernel_offset) do
        print(string.format("  %s = %s", tostring(k), tostring(v)))
    end
end

-- Examine ipv6_kernel_rw
print("")
print("--- IPV6_KERNEL_RW ---")
if ipv6_kernel_rw then
    for k, v in pairs(ipv6_kernel_rw) do
        print(string.format("  %s = %s (%s)", tostring(k), tostring(v), type(v)))
    end
end

-- Check what storage has
print("")
print("--- STORAGE ---")
if storage then
    for k, v in pairs(storage) do
        print(string.format("  %s = %s (%s)", tostring(k), tostring(v), type(v)))
    end
    -- Try listing stored keys
    local ok, keys = pcall(storage.list)
    if ok then
        print("stored keys: " .. tostring(keys))
        if type(keys) == "table" then
            for _, k in ipairs(keys) do print("  key: " .. tostring(k)) end
        end
    end
end

print("=== PROBE 89d COMPLETE ===")
