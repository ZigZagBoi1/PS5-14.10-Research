-- CRASH_CLASS: LOW
-- PROBE 290a: which paths this process can open, and whether readdir works
--
-- Context: 289a could not open /mnt, /mnt/usb0 etc. Either the volume is not
-- mounted, the path is different, or the process is inside a sandbox that does
-- not expose it. This probe opens a list of candidate paths read-only and, for
-- every directory that opens, tries the four candidate getdirentries numbers
-- and reports which one fills a buffer.

print("=== PROBE 290a: filesystem roots ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function sgn(v)
    local h, l = 0, to_num(v)
    if type(v) == "table" and v.h then h, l = v.h, v.l end
    if h % 0x100000000 == 0xFFFFFFFF and l % 0x100000000 == 0xFFFFFFFF then return -1 end
    if h == 0 and l >= 0x80000000 then return l - 0x100000000 end
    return l
end
local function put_str(s)
    local buf = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(buf + i - 1, s:byte(i)) end) end
    pcall(function() memory.write_byte(buf + #s, 0) end)
    return buf
end

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local buf = memory.alloc(0x4000)
local basep = memory.alloc(8)

local dirs = { 196, 554, 272, 344 }
local paths = {
    "/", "/mnt", "/mnt/usb0", "/mnt/usb1", "/mnt/ext0", "/mnt/ext1",
    "/app0", "/data", "/user", "/system", "/tmp", "/dev", "/dev/zero",
    "/savedata0", "/user/data", "/mnt/usb0/PS4", "/usb0", "/sandbox0",
}

for _, p in ipairs(paths) do
    local fd = sgn(sc_open(uint64(put_str(p)), uint64(0), uint64(0)))
    local ok = nil
    local n = 0
    if fd >= 0 then
        for _, num in ipairs(dirs) do
            local sc = make_syscall(num)
            for off = 0, 0x3FFC, 4 do pcall(function() memory.write_dword(buf + off, 0) end) end
            local r = sgn(sc(uint64(fd), uint64(buf), uint64(0x4000), uint64(basep)))
            if r > 0 then ok, n = num, r break end
        end
        pcall(function() sc_close(uint64(fd)) end)
    end
    print(string.format("%-16s fd=%-4d dirent=%-5s n=%d", p, fd, tostring(ok), n))
    if ok then
        local off = 0
        local shown = 0
        while off < n and shown < 10 do
            local reclen = 0
            pcall(function() reclen = to_num(memory.read_word(buf + off + 16)) end)
            local namlen = 0
            pcall(function() namlen = to_num(memory.read_word(buf + off + 20)) end)
            if reclen < 24 then break end
            local nm = ""
            for i = 0, math.min(namlen, 60) - 1 do
                local c = 0
                pcall(function() c = to_num(memory.read_byte(buf + off + 24 + i)) end)
                if c > 0 and c < 128 then nm = nm .. string.char(c) end
            end
            local pad0, pad1 = 0, 0
            pcall(function() pad0 = to_num(memory.read_byte(buf + off + 19)) end)
            pcall(function() pad1 = to_num(memory.read_word(buf + off + 22)) end)
            print(string.format("    %-24s pad0=0x%02X pad1=0x%04X", nm, pad0, pad1))
            off = off + reclen
            shown = shown + 1
        end
    end
end

print("")
print("=== PROBE 290a COMPLETE ===")
