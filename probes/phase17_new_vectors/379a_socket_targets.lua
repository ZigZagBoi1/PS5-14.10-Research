-- CRASH_CLASS: LOW
-- PROBE 379a: where the /system_tmp symlinks point, and what the boot's random dir holds
--
-- 378a found every entry in /system_tmp is a symlink, and that the jail's random
-- directory changed name between boots (IMt9cl0VzR -> fNAiGXx3yN). This probe
-- readlinks each socket to its real path - a socket in another directory is a
-- directory we can then open - and walks the new random directory.

print("=== PROBE 379a: SOCKET TARGETS ===")
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
    if ok then return to_num(v) end return 0 end
local function rb(a) local ok, v = pcall(function() return memory.read_byte(a) end)
    if ok then return to_num(v) end return 0 end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function str_at(addr, s)
    for i = 1, #s do pcall(function() memory.write_byte(addr + i - 1, s:byte(i)) end) end
    pcall(function() memory.write_byte(addr + #s, 0) end)
end

local buf = memory.alloc(0x4000)
local path = memory.alloc(0x100)
local lpath = memory.alloc(0x200)
local cookie = memory.alloc(8)

local function readlink(p)
    str_at(path, p)
    for i = 0, 0x1F8, 8 do wq(lpath + i, 0) end
    local n = sgn(make_syscall(58)(U(0, to_num(path)), U(0, to_num(lpath)), U(0, 0x200), Z, Z, Z))
    if n <= 0 then return string.format("(readlink %d)", n) end
    local s = {}
    for i = 0, n - 1 do
        local c = rb(lpath + i)
        if c >= 32 and c < 127 then s[#s + 1] = string.char(c) end
    end
    return table.concat(s)
end

print("[A] /system_tmp targets")
for _, nm in ipairs({"GnmCompositor", "GnmCompositorRestricted", "VrTracker2DomainSock",
                     "AgcCompositorSppSocket", "SceImageUtilAgent", "SystemTts", "redis.sock"}) do
    print(string.format("  %-24s -> %s", nm, readlink("/system_tmp/" .. nm)))
end

local function walk(dir)
    for i = 0, 0xFC, 8 do wq(path + i, 0) end
    str_at(path, dir)
    local fd = sgn(make_syscall(5)(U(0, to_num(path)), U(0, 0), Z, Z, Z, Z))
    if fd < 3 then print(string.format("  %s open failed", dir)) return end
    wq(cookie, 0)
    local listed = {}
    for round = 1, 4 do
        local n = sgn(make_syscall(196)(U(0, fd), U(0, to_num(buf)), U(0, 0x4000), U(0, to_num(cookie)), Z, Z))
        if n <= 0 then break end
        local off = 0
        while off + 8 <= n do
            local reclen = rd(buf + off + 4) % 0x10000
            local typ = math.floor((rd(buf + off + 4) % 0x1000000) / 0x10000) % 0x100
            local namlen = math.floor((rd(buf + off + 4) % 0x100000000) / 0x1000000) % 0x100
            local name = {}
            for i = 0, namlen - 1 do
                local c = rb(buf + off + 8 + i)
                if c >= 32 and c < 127 then name[#name + 1] = string.char(c) end
            end
            local nm = table.concat(name)
            if nm ~= "" and nm ~= "." and nm ~= ".." then
                local kind = "file"
                if typ == 4 then kind = "dir" end
                if typ == 8 then kind = "reg" end
                if typ == 12 then kind = "lnk" end
                print(string.format("  %s/%s  %s", dir, nm, kind))
                if typ == 12 then
                    print(string.format("      -> %s", readlink(dir .. "/" .. nm)))
                end
                if typ == 4 and #listed < 40 then listed[#listed + 1] = nm end
            end
            if reclen < 8 then break end
            off = off + reclen
        end
    end
    pcall(function() make_syscall(6)(U(0, fd), Z, Z, Z, Z, Z) end)
    return listed
end

print("")
print("[B] the boot's random directory")
local roots = walk("/")
if roots then
    for _, nm in ipairs(roots) do
        if nm ~= "dev" and nm ~= "app0" and nm ~= "savedata0" and nm ~= "av_contents" and nm ~= "system_tmp" then
            print(string.format("[%s]", nm))
            local kids = walk("/" .. nm)
            if kids then
                for _, k in ipairs(kids) do
                    if k ~= "common" or true then walk("/" .. nm .. "/" .. k) end
                end
            end
        end
    end
end

print("")
print("=== 379a DONE ===")
