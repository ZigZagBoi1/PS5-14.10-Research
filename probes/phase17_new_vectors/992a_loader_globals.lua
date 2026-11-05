-- CRASH_CLASS: LOW
-- PROBE 992a: does a script uploaded to the loader see the loader's own Lua globals?
--
-- The loader runs the uploaded script inside its own Lua state, so the modules it
-- required (ropchain, signal, gadgets, offsets) may still be global. If they are, a
-- script can rebuild the signal pivot chain itself and read the kernel's siginfo,
-- which the shipped chain never copies.

print("=== PROBE 992a: LOADER GLOBALS ===")
for _, name in ipairs({"ropchain","signal","gadgets","offset","offsets","kernel","thread","native","memory","syscall","lua","uint64","bit32","struct","misc","gpu"}) do
    local ok, t = pcall(function() return _G[name] end)
    print(string.format("  %-10s type=%s", name, ok and type(t) or "ERR"))
end
local okg, g = pcall(function() return _G["gadgets"] end)
if okg and type(g) == "table" then
    local n = 0
    for k in pairs(g) do n = n + 1 end
    print(string.format("  gadgets keys=%d", n))
    for k, v in pairs(g) do
        if type(v) == "number" then print(string.format("    %s = 0x%X", k, v)) break end
    end
    local sp = g.stack_pivot
    if type(sp) == "table" then
        for i, v in ipairs(sp) do
            print(string.format("    pivot[%d] gadget=0x%X addr=0x%X base=0x%X", i, tonumber(tostring(v.gadget_addr)) or 0, tonumber(tostring(v.pivot_addr)) or 0, tonumber(tostring(v.pivot_base)) or 0))
        end
    end
end
local oks, s = pcall(function() return _G["signal"] end)
if oks and type(s) == "table" then
    for k, v in pairs(s) do print(string.format("  signal.%s = %s", k, type(v))) end
end
print("=== COMPLETE ===")
