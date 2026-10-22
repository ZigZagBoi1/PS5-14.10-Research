-- CRASH_CLASS: LOW
-- PROBE 295a: the full jail inventory
--
-- Context: 294a read the record format off the bytes. The records are
-- 32-bit: d_fileno at +0 (u32), d_reclen at +4 (u16), d_type at +6 (u8),
-- d_namlen at +7 (u8), d_name at +8, padded to a 4-byte boundary.
--
-- The jail root holds '.', '..', a random-looking directory name, 'system_tmp',
-- 'dev', 'app0', 'savedata0' and something starting 'av_conte'. There is no
-- /mnt, so a USB volume mounted by the system is outside this namespace.
--
-- This probe lists every directory it can open, in full, with the record
-- layout that works.

print("=== PROBE 295a: jail inventory ===")
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
local list = make_syscall(196)
local buf = memory.alloc(0x8000)
local basep = memory.alloc(8)

local function entries(path)
    local fd = sgn(sc_open(uint64(put_str(path)), uint64(0), uint64(0)))
    if fd < 0 then return nil, path end
    local out = {}
    for round = 1, 8 do
        for off = 0, 0x7FFC, 4 do pcall(function() memory.write_dword(buf + off, 0) end) end
        local r = sgn(list(uint64(fd), uint64(buf), uint64(0x8000), uint64(basep)))
        if r <= 0 then break end
        local off = 0
        local more = false
        while off + 8 <= r do
            local reclen = 0
            local typ = 0
            local namlen = 0
            pcall(function() reclen = to_num(memory.read_word(buf + off + 4)) end)
            pcall(function() typ = to_num(memory.read_byte(buf + off + 6)) end)
            pcall(function() namlen = to_num(memory.read_byte(buf + off + 7)) end)
            if reclen < 8 or off + reclen > r then break end
            local nm = ""
            for i = 0, namlen - 1 do
                local c = 0
                pcall(function() c = to_num(memory.read_byte(buf + off + 8 + i)) end)
                if c > 0 and c < 128 then nm = nm .. string.char(c) end
            end
            out[#out + 1] = { name = nm, type = typ }
            off = off + reclen
            more = true
        end
        if not more then break end
    end
    pcall(function() sc_close(uint64(fd)) end)
    return out, path
end

local TYPE = { [1] = "fifo", [2] = "chr", [4] = "dir", [6] = "blk", [8] = "reg", [10] = "lnk", [12] = "sock" }

local roots = { "/", "/app0", "/dev", "/savedata0", "/system_tmp" }
local subdirs = {}

for _, p in ipairs(roots) do
    local es = entries(p)
    print(string.format("[%s] %s", p, es and (#es .. " entries") or "cannot open"))
    if es then
        local names = {}
        for _, e in ipairs(es) do
            names[#names + 1] = string.format("%s(%s)", e.name, TYPE[e.type] or e.type)
            if e.type == 4 and e.name ~= "." and e.name ~= ".." and p ~= "/dev" then
                subdirs[#subdirs + 1] = (p == "/" and "" or p) .. "/" .. e.name
            end
        end
        print("  " .. table.concat(names, " "))
    end
end

for _, p in ipairs(subdirs) do
    local es = entries(p)
    if es then
        local names = {}
        for _, e in ipairs(es) do
            if e.name ~= "." and e.name ~= ".." then
                names[#names + 1] = string.format("%s(%s)", e.name, TYPE[e.type] or e.type)
            end
        end
        print(string.format("[%s] ", p) .. table.concat(names, " "))
    end
end

print("")
print("=== PROBE 295a COMPLETE ===")
