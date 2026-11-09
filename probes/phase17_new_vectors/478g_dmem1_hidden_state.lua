-- CRASH_CLASS: HIGH
-- PROBE 478g: does the prefix leave something in the argument page?
--
-- 477b prints only the first 16 bytes after each refused command. If one of
-- 0x80108000..0x80108012 writes a field further into the 0x100-byte page, then
-- 0x80108013 reads it and proceeds — which would explain why the prefixed call
-- dies while the same call after 478d's re-zeroing is refused.
--
-- This probe dumps the whole page after every prefix command, byte by byte, and
-- calls 0x80108013 at the end with whatever the prefix left. If the page is
-- all zeros at the end, hidden state in the page is ruled out.

print("=== PROBE 478g: dmem1 prefix page state ===")
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
local function dump(base, n)
    local out, zeros = {}, 0
    for i = 0, n - 1, 4 do
        local v = rd32(base + i)
        if v == 0 then zeros = zeros + 1 end
        if i % 32 == 0 then out[#out + 1] = string.format("\n  +%03X:", i) end
        out[#out + 1] = string.format(" %08X", v)
    end
    return table.concat(out) .. string.format("  (zero dwords %d/%d)", zeros, n / 4)
end

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)

-- isolated page: mmap so nothing else shares it
local sc_mmap = make_syscall(477)
local page = 0
do
    local r = sc_mmap(uint64(0), uint64(0x1000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    local ok, v = pcall(function() return r:tonumber() end)
    page = ok and to_num(v) or 0
end
if page == 0 then page = memory.alloc(0x100) end
for off = 0, 0xFC, 4 do pcall(function() memory.write_dword(page + off, 0) end) end
print(string.format("[0] page=0x%08X", to_num(page)))

local fd = sgn(sc_open(uint64(put_str("/dev/dmem1")), uint64(2), uint64(0)))
if fd < 0 then fd = sgn(sc_open(uint64(put_str("/dev/dmem1")), uint64(0), uint64(0))) end
print("[0] open(/dev/dmem1)=" .. fd)
if fd < 0 then print("[0] refused"); return end

for nr = 0x00, 0x12 do
    local ok, r = pcall(function() return sc_ioctl(uint64(fd), uint64(0x80108000 + nr), uint64(page)) end)
    print(string.format("[%02X] ret=%d%s", nr, ok and sgn(r) or -999, dump(page, 0x100)))
end

print("[F] prefix done, page state above; calling 0x80108013")
local ok, r = pcall(function() return sc_ioctl(uint64(fd), uint64(0x80108013), uint64(page)) end)
print(string.format("[F] ret=%s%s", tostring(ok and sgn(r) or -999), dump(page, 0x100)))

pcall(function() sc_close(uint64(fd)) end)
print("")
print("=== PROBE 478g COMPLETE ===")
