-- CRASH_CLASS: LOW
-- PROBE 359a: do the directory entries carry anything pointer-shaped
--
-- 294a recovered the 32-bit dirent layout and every listing since printed names
-- only. d_fileno is a 32-bit inode number, and a kernel pointer's low half is
-- exactly 32 bits wide (a text pointer at 0xFFFF8xxx_8DEDE038 has
-- d_fileno 0x8DEDE038). Some pseudo-filesystems assign inode numbers from the
-- address of the object behind the node, so listing /dev and printing the
-- numbers is a cheap place to look for one.

print("=== PROBE 359a: INODE NUMBERS IN THE JAIL ===")
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
    local l = to_num(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local U = function(h, l) return uint64(string.format("0x%X%08X", h, l)) end
local Z = uint64(0)
local function rd(a) local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end return -1 end
local function rb(a) local ok, v = pcall(function() return memory.read_byte(a) end)
    if ok then return to_num(v) end return 0 end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function str_at(addr, s)
    for i = 1, #s do pcall(function() memory.write_byte(addr + i - 1, s:byte(i)) end) end
    pcall(function() memory.write_byte(addr + #s, 0) end)
end

local buf = memory.alloc(0x4000)
local path = memory.alloc(0x40)
local cookie = memory.alloc(8)

local function walk(dir)
    for i = 0, 0x3F, 8 do wq(path + i, 0) end
    str_at(path, dir)
    local fd = sgn(make_syscall(5)(U(0, to_num(path)), U(0, 0), Z, Z, Z, Z))
    print(string.format("[%s] open = %d", dir, fd))
    if fd < 3 then return end
    wq(cookie, 0)
    local off = 0
    local high = 0
    local big = {}
    for round = 1, 8 do
        local n = sgn(make_syscall(196)(U(0, fd), U(0, to_num(buf)), U(0, 0x4000), U(0, to_num(cookie)), Z, Z))
        if n <= 0 then break end
        off = 0
        while off + 8 <= n do
            local fileno = rd(buf + off)
            local reclen = rd(buf + off + 4) % 0x10000
            local namlen = math.floor((rd(buf + off + 4) % 0x100000000) / 0x1000000) % 0x100
            local name = {}
            for i = 0, namlen - 1 do
                local c = rb(buf + off + 8 + i)
                if c >= 32 and c < 127 then name[#name + 1] = string.char(c) end
            end
            if fileno >= 0x80000000 then
                high = high + 1
                if #big < 24 then
                    big[#big + 1] = string.format("%s=0x%X", table.concat(name), fileno)
                end
            end
            if reclen < 8 then break end
            off = off + reclen
        end
    end
    print(string.format("  entries with a high bit: %d", high))
    if #big > 0 then print("  " .. table.concat(big, "  ")) end
    print(string.format("  close = %d", sgn(make_syscall(6)(U(0, fd), Z, Z, Z, Z, Z))))
end

walk("/dev")
walk("/")
walk("/savedata0")

print("")
print("=== 359a DONE ===")
