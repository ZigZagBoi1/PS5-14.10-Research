-- CRASH_CLASS: LOW
-- PROBE 477a: what /dev/dmem1's read command returns
--
-- Context: 476a swept the full encoding space on /dev/dmem1 and found one
-- driver command beside the three framework returns: 0x4008800A, which is
-- _IOR(0x80, 10, 8) - direction IOC_OUT, eight bytes. The sweep only recorded
-- the return value, so this probe asks the same command with a page it filled
-- itself and dumps what came back.
--
-- Three fills (00, AA, 5A), three repeats on the zero fill so a value that
-- changes per call can be told from a constant, and the same command on
-- /dev/dmem0 and /dev/dmem2 for contrast.
--
-- The probe does NOT touch the direction-IOC_IN block that killed the console
-- on 2026-10-23 (cmd range 0x80108000..0x8010BFFF on this node).

print("=== PROBE 477a: dmem1 read command ===")
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
    if h ~= 0 or l >= 0x80000000 then return -1 end
    return l
end
local function put_str(s)
    local buf = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(buf + i - 1, string.byte(s, i)) end) end
    pcall(function() memory.write_byte(buf + #s, 0) end)
    return buf
end
local function rd32(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return -1
end
local function dump(tag, addr, n)
    local parts = {}
    for i = 0, n - 1, 4 do
        parts[#parts + 1] = string.format("%08X", rd32(addr + i))
    end
    print(tag .. " " .. table.concat(parts, " "))
end

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)
local CMD = 0x4008800A

local page = memory.alloc(0x100)
local function fill(v)
    for off = 0, 0xFC, 4 do pcall(function() memory.write_dword(page + off, v) end) end
end

local nodes = { "/dev/dmem1", "/dev/dmem0", "/dev/dmem2" }
for _, node in ipairs(nodes) do
    print("[" .. node .. "]")
    local fd = sgn(sc_open(uint64(put_str(node)), uint64(2), uint64(0)))
    if fd < 0 then fd = sgn(sc_open(uint64(put_str(node)), uint64(0), uint64(0))) end
    print("    open=" .. fd)
    if fd >= 0 then
        for _, f in ipairs({ 0x00000000, 0xAAAAAAAA, 0x5A5A5A5A }) do
            fill(f)
            local ok, r = pcall(function() return sc_ioctl(uint64(fd), uint64(CMD), uint64(page)) end)
            local ret = ok and sgn(r) or -999
            print(string.format("    fill=%08X ret=%d", f, ret))
            dump("      after:", page, 0x20)
        end
        fill(0)
        for i = 1, 3 do
            local ok, r = pcall(function() return sc_ioctl(uint64(fd), uint64(CMD), uint64(page)) end)
            print(string.format("    repeat %d ret=%d", i, ok and sgn(r) or -999))
            dump("      value:", page, 0x10)
        end
        pcall(function() sc_close(uint64(fd)) end)
    end
    print("")
end

print("=== PROBE 477a COMPLETE ===")
