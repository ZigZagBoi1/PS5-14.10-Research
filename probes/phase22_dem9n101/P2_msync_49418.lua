-- P2: 49418 exact sequence via GPU mmap (probe 41c pattern from community:
-- syscall 477 with flags 0x1002 = MAP_SHARED|0x1000 device-ish)
print("=== P2: gpu-mmap msync invalidate (49418 core) ===")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
syscall.resolve({
    open = 5, close = 6, mmap = 477, munmap = 73, msync = 65
})
local dmem = -1
for _, p in ipairs({"/dev/dmem0", "/dev/dmem1", "/dev/dce"}) do
    local ok, fd = pcall(function() return to_num(syscall.open(p, 2)) end)
    if ok and fd >= 0 then dmem = fd; print("using " .. p .. " fd=" .. fd); break end
end
if dmem < 0 then
    print("no device fd; trying anon-shared with 0x1002 flags")
    local ok, addr = pcall(function()
        return to_num(syscall.mmap(0, 0x40000, 3, 0x1002, -1, 0))
    end)
    print("mmap(0x1002) rv=0x" .. string.format("%x", addr))
    if addr > 0 and addr < 0x800000000000 then
        memory.write_qword(addr, 0x1122334455667788)
        for i = 0, 3 do
            local okm, ms = pcall(function() return to_num(syscall.msync(addr + i*0x10000, 0x10000, 2)) end)
            print("msync inv seg" .. i .. " rv=" .. tostring(ms))
        end
        -- fault back in
        memory.write_qword(addr, 0x9988776655443322)
        print("post: 0x" .. string.format("%x", to_num(memory.read_qword(addr))))
        pcall(function() syscall.munmap(addr, 0x40000) end)
    end
else
    -- device-backed: large multi-page mapping then invalidate halves
    local ok, addr = pcall(function()
        return to_num(syscall.mmap(0, 0x100000, 3, 1, dmem, 0))  -- 1MB
    end)
    print("device mmap 1MB rv=0x" .. string.format("%x", addr))
    if addr > 0 and addr < 0x800000000000 then
        for off = 0, 0xF0000, 0x10000 do
            memory.write_dword(addr + off, 0x5A5A0000 + off)
        end
        local ok2, ms = pcall(function()
            return to_num(syscall.msync(addr, 0x80000, 2))  -- invalidate first half
        end)
        print("msync invalidate 512K rv=" .. tostring(ms))
        -- munmap the invalidated half (free path), then re-touch (refault)
        pcall(function() syscall.munmap(addr, 0x80000) end)
        local rd = to_num(memory.read_dword(addr + 0x80000))
        print("second half alive: 0x" .. string.format("%x", rd))
    end
    pcall(function() syscall.close(dmem) end)
end
print("P2_DONE")
