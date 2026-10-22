-- CRASH_CLASS: MODERATE
-- PROBE 360a: is the encrypt service multiplexed onto any node we can open
--
-- 273a only ever tried to OPEN the seven update-ish names, and every one refused.
-- The decrypt tool's device is /dev/pup_update0 opened O_RDWR, and its ioctls are
--  0xC0104401 verify_blsheader   0xC0184402 decrypt_header
--  0xC0184403/04 verify_segment  0xC0184405 decrypt_segment
-- A cdevsw is per node, so a different node would answer ENOTTY -1 and write
-- nothing. What this probe measures is exactly that: every openable node in /dev,
-- every one of those five codes, and whether any of them writes to the argument
-- buffer. A node that answers anything other than -1, or writes a byte, is a way
-- in that opening the name alone never found.

print("=== PROBE 360a: ENCRYPT-SERVICE IOCTL MATRIX ===")
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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function str_at(addr, s)
    for i = 1, #s do pcall(function() memory.write_byte(addr + i - 1, s:byte(i)) end) end
    pcall(function() memory.write_byte(addr + #s, 0) end)
end

local buf = memory.alloc(0x2000)     -- 0x1000 result page + args struct
local path = memory.alloc(0x80)
local args = buf + 0x1000
local page = buf

local codes = {0xC0104401, 0xC0184402, 0xC0184403, 0xC0184404, 0xC0184405}

local function clear_page()
    for i = 0, 0xFF8, 8 do wq(page + i, 0) end
    for i = 0, 0x18, 8 do wq(args + i, 0) end
end

local function run_codes(tag, fd)
    local hits = 0
    for _, code in ipairs(codes) do
        clear_page()
        wq(args, U(0, to_num(page)))     -- args.buffer
        wq(args + 8, U(0, 0x100))        -- args.length
        wd(args + 0x10, 0)               -- args.type
        local r = sgn(make_syscall(54)(U(0, fd), U(0x00000000, code), U(0, to_num(args)), Z, Z, Z))
        local dirty = 0
        for i = 0, 0xFC, 4 do if rd(page + i) ~= 0 then dirty = dirty + 1 end end
        if r ~= -1 or dirty > 0 then
            hits = hits + 1
            print(string.format("    %s fd=%d ioctl 0x%08X -> %d  nonzero words=%d  arg0=0x%08X",
                tag, fd, code, r, dirty, rd(args)))
        end
    end
    return hits
end

-- [A] every name in /dev
local names = {}
do
    str_at(path, "/dev")
    local fd = sgn(make_syscall(5)(U(0, to_num(path)), U(0, 0), Z, Z, Z, Z))
    print(string.format("[A] /dev open = %d", fd))
    if fd >= 3 then
        local cookie = memory.alloc(8)
        wq(cookie, 0)
        local d = memory.alloc(0x4000)
        for round = 1, 6 do
            local n = sgn(make_syscall(196)(U(0, fd), U(0, to_num(d)), U(0, 0x4000), U(0, to_num(cookie)), Z, Z))
            if n <= 0 then break end
            local off = 0
            while off + 8 <= n do
                local packed = rd(d + off + 4)
                local reclen = packed % 0x10000
                local namlen = math.floor(packed / 0x1000000) % 0x100
                local s = {}
                for i = 0, namlen - 1 do
                    local c = rb(d + off + 8 + i)
                    if c >= 32 and c < 127 then s[#s + 1] = string.char(c) end
                end
                local name = table.concat(s)
                if name ~= "" and name ~= "." and name ~= ".." then names[#names + 1] = name end
                if reclen < 8 then break end
                off = off + reclen
            end
        end
        pcall(function() make_syscall(6)(U(0, fd), Z, Z, Z, Z, Z) end)
    end
    print(string.format("    %d names", #names))
end

-- [B] open every one, run the five codes on every descriptor that opens
local opened = {}
local hits = 0
for _, name in ipairs(names) do
    str_at(path, "/dev/" .. name)
    local fd = sgn(make_syscall(5)(U(0, to_num(path)), U(0, 2), Z, Z, Z, Z))
    if fd >= 3 then
        opened[#opened + 1] = name
        hits = hits + run_codes(name, fd)
        pcall(function() make_syscall(6)(U(0, fd), Z, Z, Z, Z, Z) end)
    end
end
print(string.format("[B] %d of %d nodes opened O_RDWR", #opened, #names))
print("    " .. table.concat(opened, " "))

-- [C] the update names again, every open flag
print("[C] update names, flag matrix")
for _, name in ipairs({"/dev/pup_update0", "/dev/pup_update", "/dev/sbl_srv", "/dev/encdec", "/dev/update", "/dev/upd"}) do
    local row = {}
    for _, flag in ipairs({0, 1, 2, 4, 6, 0x200, 0x800}) do
        str_at(path, name)
        local fd = sgn(make_syscall(5)(U(0, to_num(path)), U(0, flag), Z, Z, Z, Z))
        row[#row + 1] = string.format("f%d=%d", flag, fd)
        if fd >= 3 then hits = hits + run_codes(name, fd)
            pcall(function() make_syscall(6)(U(0, fd), Z, Z, Z, Z, Z) end) end
    end
    print("    " .. name .. "  " .. table.concat(row, " "))
end

print("")
print(string.format("=== 360a COMPLETE: %d nodes answered anything but -1 ===", hits))
