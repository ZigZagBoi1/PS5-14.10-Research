
-- C1b: evf open/set/clear/cancel + refcounted delete
syscall.resolve({ evf_create = 538, evf_open = 540, evf_delete = 541,
                  evf_set = 544, evf_clear = 545, evf_cancel = 546 })
local name = memory.alloc(64)
local nm = "HermesEvf2"
for i = 1, #nm do memory.write_byte(name + i - 1, string.byte(nm, i)) end
memory.write_byte(name + #nm, 0)
local h = tonumber(syscall.evf_create(name, 0x101))
print("create h=" .. tostring(h))
if h and h > 0 then
    local ok, h2 = pcall(function() return tonumber(syscall.evf_open(name, 0x101, 0)) end)
    print("open h2=" .. tostring(ok and h2 or "EXC"))
    print("set=" .. tostring(pcall(function() syscall.evf_set(h, 0xF0F0) end)))
    print("clear=" .. tostring(pcall(function() syscall.evf_clear(h, 0xF0F0) end)))
    print("cancel=" .. tostring(pcall(function() syscall.evf_cancel(h, 0) end)))
    if h2 and h2 > 0 then
        print("delete h2=" .. tostring(pcall(function() syscall.evf_delete(h2) end)))
    end
    print("delete h=" .. tostring(pcall(function() syscall.evf_delete(h) end)))
end
print("C1B_DONE")
