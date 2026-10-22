
-- C1c3: 32 named evfs — id-space shape
syscall.resolve({ evf_create = 538, evf_delete = 541 })
local handles = {}
local base = os.time()
for i = 1, 32 do
    local name = memory.alloc(32)
    local nm = "H" .. base .. "x" .. i
    for j = 1, #nm do memory.write_byte(name + j - 1, string.byte(nm, j)) end
    memory.write_byte(name + #nm, 0)
    local ok, h = pcall(function() return tonumber(syscall.evf_create(name, 0x101)) end)
    if ok and h and h > 0 and h < 0x10000 then handles[#handles+1] = h end
end
if #handles > 0 then
    print("evfs=" .. #handles .. " first=" .. handles[1] .. " last=" .. handles[#handles])
end
for _, h in ipairs(handles) do pcall(function() syscall.evf_delete(h) end) end
print("C1C3_DONE")
