-- CRASH_CLASS: LOW
print("=== PROBE 628a: SIGNAL GLOBALS ===")
local names={"signal","kernel","native","ropchain","gadgets","syscall","memory","uint64","register_signal_handler","map_fixed_address","map_direct_memory","get_error_string","kernel_offset","offsets","main","thread","struct"}
for _,n in ipairs(names) do
    local ok,v=pcall(function() return _G[n] end)
    print(string.format("  %s = %s (%s)",n,tostring(ok and type(v) or "err"),tostring(ok and v~=nil)))
end
local ok,keys=pcall(function() local t={} for k in pairs(_G) do t[#t+1]=tostring(k) end table.sort(t) return table.concat(t,",") end)
print("[A] globals="..tostring(ok and keys or "err"))
local ok2,v2=pcall(function() return type(signal)=="table" and (signal.register and "has register" or "no register") end)
print("[B] signal="..tostring(ok2 and v2 or "err"))
print("[Z] alive")
