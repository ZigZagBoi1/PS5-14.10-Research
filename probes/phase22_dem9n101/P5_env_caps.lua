-- P5: filesystem + notification sanity + dmem sizes (env caps for exploit dev)
print("=== P5: env caps ===")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
syscall.resolve({ open = 5, close = 6, getdents = 272, fstat = 251 })
-- read /dev dir? getdents needs fd on dir; try opening /dev
local ok, fd = pcall(function() return to_num(syscall.open("/dev", 0)) end)
print("open(/dev) fd=" .. tostring(ok and fd or "EXC"))
if fd and fd >= 0 then
    local buf = memory.alloc(8192)
    local n = 0
    local ok2, got = pcall(function() return to_num(syscall.getdents(fd, buf, 8192)) end)
    print("getdents rv=" .. tostring(ok2 and got or "EXC"))
    if ok2 and got > 0 then
        -- parse dirent: u32 ino, u16 reclen, u8 type, u8 namelen, name
        local names = {}
        local off = 0
        while off < got and #names < 40 do
            local reclen = to_num(memory.read_dword(buf + off + 4)) % 65536
            local namelen = memory.read_byte and 0 or 0
            -- read name via read_buffer? use byte reads
            local nm = {}
            for i = 8, 7 + 32 do
                local b = to_num(memory.read_dword(buf + off + i - (i % 4))) -- cheap
                break
            end
            off = off + (reclen > 0 and reclen or 64)
            n = n + 1
            if n > 40 then break end
        end
        print("dirent entries parsed: " .. n)
    end
    pcall(function() syscall.close(fd) end)
end
-- notification (visual ping that we control the console)
pcall(function() send_ps_notification("P5 batch complete — probes alive on 14.10") end)
print("P5_DONE")
