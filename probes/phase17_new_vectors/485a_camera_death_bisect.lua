-- CRASH_CLASS: HIGH
-- PROBE 485a: find the encoding that killed the game in the 483c sweep
--
-- Context: 483c died with CONNECTION_RESET at progress line
--   cmd=0x9000A7FF (dir=0x80000000 len=0x1000), hits=2
-- so the killer is inside 0x9000A800..0x9000AFFF, or was the block that had
-- just started. Progress is printed every 0x40 commands, so one run narrows
-- 4096 candidates to 64; the constants below move to the next window each run.
--
-- The two "hits" 483c printed are explained offline and are not the killer:
--   0x80088E25 -> handler 0xaafdca in 13.60, returns Sony error 0x802E0010
--   0x80048E2C -> handler 0xaafe8a, returns 0 (a byte <= 2 is accepted)

print("=== PROBE 485a: camera death bisect ===")
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
    local n = to_num(v)
    if n >= 0x8000000000000000 then return n - 0x10000000000000000 end
    if n >= 0x80000000 and n < 0x100000000 then return n - 0x100000000 end
    return n
end
local function split(v)
    if type(v) == "table" and v.h then return v.h, v.l end
    return 0, to_num(v)
end
local function put_str(s)
    local buf = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(buf + i - 1, string.byte(s, i)) end) end
    pcall(function() memory.write_byte(buf + #s, 0) end)
    return buf
end

local sc_open  = make_syscall(5)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)

local START = 0x9000A000   -- move this after each death
local STOP  = 0x9000B000   -- exclusive

local page = memory.alloc(0x2000)
for off = 0, 0x1FFC, 4 do pcall(function() memory.write_dword(page + off, 0) end) end
local arg = uint64(page)

local fd = sgn(sc_open(uint64(put_str("/dev/camera")), uint64(2), uint64(0)))
print(string.format("open=%d window=0x%08X..0x%08X", fd, START, STOP))

if fd >= 0 then
    local n = 0
    for cmd = START, STOP - 1 do
        if n % 0x40 == 0 then
            print(string.format("  [blk 0x%08X]", cmd))
        end
        local ok, r = pcall(function() return sc_ioctl(uint64(fd), uint64(cmd), arg) end)
        n = n + 1
        if not ok then
            print(string.format("  PCALL-FAIL at 0x%08X", cmd))
        else
            local h, l = split(r)
            if not ((h == 0xFFFFFFFF or h == -1) and (l == 0xFFFFFFFF or l == -1)) and l ~= 0x16 then
                print(string.format("  ret cmd=0x%08X -> 0x%X%08X", cmd, h, l))
            end
        end
    end
    print(string.format("DONE %d commands", n))
    sgn(sc_close(uint64(fd)))
end
print("=== PROBE 485a END ===")
