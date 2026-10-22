-- CRASH_CLASS: MODERATE
-- PROBE 259a: what /dev actually looks like from this process
--
-- The devfs listing has never been read on 14.10. Every device probe so far
-- guessed a name (/dev/dmem0, /dev/hid) instead of reading the directory, and
-- the interesting question is not only which nodes exist but which of them this
-- game process is allowed to open - each open device is a driver that can be
-- handed an ioctl.
--
--   A  open("/dev", O_RDONLY) and getdirentries (196) until the directory ends
--   B  for each name, open("/dev/<name>", O_RDONLY) and record the fd or the error
--   C  summary: how many nodes, how many opened
--
-- struct dirent, 64-bit FreeBSD: u64 d_ino, u64 d_off, u16 d_reclen,
-- u8 d_type, u8 d_pad0, u16 d_namlen, u16 d_pad1, char d_name[] (header 24).

print("=== PROBE 259a: the /dev listing ===")
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
local function q(v)
    if v == nil then return "nil" end
    if type(v) == "table" and v.h then return string.format("0x%08X_%08X", v.h, v.l) end
    local n = to_num(v)
    if n < 0 then n = n + 18446744073709551616 end
    return string.format("0x%X", n)
end
local function snum(v)
    local n = to_num(v)
    if n < 0 then n = n + 18446744073709551616 end
    if n >= 18446744073709551600 then return n - 18446744073709551616 end
    return n
end
local function call(num, a, b, c, d)
    local sc = make_syscall(num)
    local ok, rv = pcall(function() return sc(a or uint64(0), b or uint64(0), c or uint64(0), d or uint64(0)) end)
    if not ok then return nil end
    return rv
end
local function pid()
    local ok, v = pcall(function() return make_syscall(20)() end)
    if ok then return to_num(v) end
    return nil
end
local function rd8(addr)
    local ok, v = pcall(function() return memory.read_byte(addr) end)
    if ok and v ~= nil then return to_num(v) end
    return nil
end
local function rd32(addr)
    local ok, v = pcall(function() return memory.read_dword(addr) end)
    if ok and v ~= nil then return to_num(v) end
    return nil
end
local function rd16(addr)
    local ok, v = pcall(function() return memory.read_word(addr) end)
    if ok and v ~= nil then return to_num(v) end
    return nil
end
local function str(addr, len)
    local out = {}
    for i = 0, len - 1 do
        local b = rd8(addr + i)
        if b == nil or b == 0 then break end
        if b >= 32 and b < 127 then out[#out + 1] = string.char(b) else out[#out + 1] = "?" end
    end
    return table.concat(out)
end

local function path(p)
    local b = memory.alloc(0x100)
    pcall(function() memory.write_qword(b, 0) end)
    for i = 1, #p do
        local c = string.byte(p, i)
        pcall(function() memory.write_byte(b + i - 1, c) end)
    end
    return b
end

print("[0] pid=" .. tostring(pid()))

print("")
print("[A] getdirentries on /dev")
local dp = path("/dev")
local dfd = call(5, uint64(dp), uint64(0), uint64(0), uint64(0))
print("    open(/dev, O_RDONLY) -> " .. q(dfd) .. "  pid=" .. tostring(pid()))
local names = {}
local dfdn = snum(dfd)
if dfdn ~= nil and dfdn >= 0 and dfdn < 4096 then
    local BUF = memory.alloc(0x4000)
    local base = memory.alloc(8)
    for round = 1, 8 do
        pcall(function() memory.write_qword(base, 0) end)
        local rv = call(196, uint64(dfdn), uint64(BUF), uint64(0x4000), uint64(base))
        local n = snum(rv)
        print(string.format("    getdirentries #%d -> %s", round, q(rv)))
        if n == nil or n <= 0 then break end
        local off = 0
        if round == 1 then
            print("    entry layout from the dump: u32 ino, u16 reclen at +4, u8 type at +6,")
            print("    u8 namlen at +7, name at +8")
        end
        if false then
            local hex = {}
            for o = 0, 0x60 - 1 do
                hex[#hex + 1] = string.format("%02X", rd8(BUF + o) or 0)
                if (o + 1) % 16 == 0 then hex[#hex + 1] = "\n    " end
            end
            print("    first 0x60 bytes:")
            print("    " .. table.concat(hex))
        end
        while off + 24 <= n do
            local namlen = rd8(BUF + off + 7)
            local reclen = rd16(BUF + off + 4)
            if namlen == nil or reclen == nil or reclen < 8 then break end
            local nm = str(BUF + off + 8, namlen)
            if nm ~= "" and nm ~= "." and nm ~= ".." then names[#names + 1] = nm end
            off = off + reclen
        end
        if #names == 0 then break end
    end
end
print("    nodes seen: " .. tostring(#names))

print("")
print("[B] open each node")
local opened = 0
local rows = {}
for i = 1, #names do
    local pp = path("/dev/" .. names[i])
    local rv = call(5, uint64(pp), uint64(0), uint64(0), uint64(0))
    local n = snum(rv)
    local ok = (n ~= nil and n >= 0)
    if ok then opened = opened + 1 end
    rows[#rows + 1] = string.format("    %-24s -> %s", names[i], ok and ("fd " .. n) or "-1")
end
for i = 1, #rows do print(rows[i]) end

print("")
print("[C] summary")
print("    " .. tostring(#names) .. " nodes, " .. tostring(opened) .. " opened")
print("    pid -> " .. tostring(pid()))
print("")
print("=== PROBE 259a COMPLETE ===")
