-- CRASH_CLASS: LOW
-- PROBE 378a: what a system daemon leaves behind where we can read it
--
-- The compositors were killed twice by our traffic and the console was power
-- cycled between the two boots, so any file they wrote is still on disk. This
-- probe walks the directories a game process can reach two levels deep and prints
-- every entry with its size and modification time, looking for logs, dumps or
-- anything that was not in 295a's inventory.

print("=== PROBE 378a: JAIL ARTIFACTS ===")
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
local cookie = memory.alloc(8)
local st = memory.alloc(0x100)

local function stat_of(full)
    str_at(path, full)
    local r = sgn(make_syscall(188)(U(0, to_num(path)), U(0, to_num(st)), Z, Z, Z, Z))
    if r ~= 0 then return -1, 0, 0 end
    return 0, rd(st + 0x10), rd(st + 0x30)   -- size dword, mtime second
end

local function walk(dir, depth)
    for i = 0, 0xFC, 8 do wq(path + i, 0) end
    str_at(path, dir)
    local fd = sgn(make_syscall(5)(U(0, to_num(path)), U(0, 0), Z, Z, Z, Z))
    if fd < 3 then print(string.format("%s  open failed", dir)) return end
    wq(cookie, 0)
    local names = {}
    for round = 1, 8 do
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
            if nm ~= "" and nm ~= "." and nm ~= ".." then names[#names + 1] = {nm = nm, typ = typ} end
            if reclen < 8 then break end
            off = off + reclen
        end
    end
    pcall(function() make_syscall(6)(U(0, fd), Z, Z, Z, Z, Z) end)
    for _, e in ipairs(names) do
        local full = dir .. "/" .. e.nm
        if dir == "/" then full = "/" .. e.nm end
        local ok, size, mt = stat_of(full)
        local kind = "file"
        if e.typ == 4 then kind = "dir" end
        if e.typ == 8 then kind = "reg" end
        if e.typ == 12 then kind = "lnk" end
        print(string.format("  %s%-28s %-4s size=0x%X mtime=0x%X", string.rep("  ", 2 - depth), e.nm, kind, size, mt))
        if e.typ == 4 and depth > 0 then walk(full, depth - 1) end
    end
end

print("[/]")
walk("/", 0)
print("[/IMt9cl0VzR]")
walk("/IMt9cl0VzR", 1)
print("[/IMt9cl0VzR/common]")
walk("/IMt9cl0VzR/common", 1)
print("[/IMt9cl0VzR/sqlite]")
walk("/IMt9cl0VzR/sqlite", 1)
print("[/system_tmp]")
walk("/system_tmp", 0)

print("")
print("=== 378a DONE ===")
