
-- C1a: evf_create shape hunt (our console)
syscall.resolve({ evf_create = 538, evf_set = 544, evf_delete = 541,
                  namedobj_create = 557 })
local name = memory.alloc(64)
local nm = "HermesEvf"
for i = 1, #nm do memory.write_byte(name + i - 1, string.byte(nm, i)) end
memory.write_byte(name + #nm, 0)
local shapes = { {name, 0}, {0, 0}, {name, 1}, {name, 0x101} }
for i, sh in ipairs(shapes) do
    local ok, rv = pcall(function() return tonumber(syscall.evf_create(sh[1], sh[2])) end)
    print("evf_create shape" .. i .. " rv=" .. tostring(ok and rv or "EXC"))
    if ok and rv and rv > 0 and rv < 0x1000 then
        print("  set=" .. tostring(pcall(function() syscall.evf_set(rv, 1) end)))
        print("  delete=" .. tostring(pcall(function() syscall.evf_delete(rv) end)))
        break
    end
end
print("C1A_DONE")
