-- CRASH_CLASS: LOW
-- PROBE 387a: recover the ioctl encodings the game itself uses
--
-- Every node refused commands 0x00-0xFF in 386a, so guessing the command space
-- byte by byte is hopeless. But the game's own code passes those commands as
-- immediates, and eboot's RX segment is the one module region this process can
-- read (374a read all 0x494000 bytes of it).
--
-- This walks eboot's readable text and keeps the 32-bit words that look like a
-- BSD ioctl encoding: the top two bits are the direction (01, 10 or 11), the
-- size field is one of the sizes drivers actually use, and the group byte is
-- printable. It prints each distinct candidate with the number of times it
-- appears, so the real constants stand out by repetition.

print("=== PROBE 387a: EBOOT IOCTL CONSTANTS ===")
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
    if type(v) == "table" then h = v.h or 0; l = v.l and to_num(v.l) or 0 end
    local x = h * 4294967296 + l
    if x >= 9223372036854775808 then x = x - 18446744073709551616 end
    return x
end

-- eboot text base from 593
local info = memory.alloc(0x200)
pcall(function() memory.write_dword(info, 0x160) end)
local sc_info = make_syscall(593)
local rv = -1
pcall(function() rv = sgn(sc_info(uint64(0), uint64(info), uint64(0), uint64(0), uint64(0), uint64(0))) end)
local base_lo = to_num(memory.read_dword(info + 0x108))
local base_hi = to_num(memory.read_dword(info + 0x10C))
local text_size = to_num(memory.read_dword(info + 0x110))
local base = base_hi * 4294967296 + base_lo
print(string.format("593 rv=%d base=0x%X size=0x%X", rv, base, text_size))
if base <= 0 or text_size <= 0 or text_size > 0x1000000 then
    print("  no usable text region")
    print("=== 387a DONE ===")
    return
end

local sizes = { [4]=true, [8]=true, [0x10]=true, [0x18]=true, [0x20]=true, [0x28]=true, [0x30]=true, [0x40]=true }
local hits = {}
local chunk = 65536
local addr = base
local enda = base + text_size
local scanned = 0
while addr + 4 <= enda do
    local n = chunk
    if addr + n > enda then n = enda - addr end
    local ok, s = pcall(function() return memory.read_buffer(addr, n) end)
    if not ok or type(s) ~= "string" then break end
    local i = 1
    local top = #s - 3
    while i <= top do
        local b1, b2, b3, b4 = string.byte(s, i, i + 3)
        -- direction in the top two bits of the last byte: 01, 10, 11
        if b4 >= 0x40 then
            local sz = b3 * 256 + b2
            if sizes[sz] then
                local num = b1
                if b1 >= 0x20 and b1 < 0x7F and num ~= 0 then
                    local v = b4 * 16777216 + b3 * 65536 + b2 * 256 + b1
                    hits[v] = (hits[v] or 0) + 1
                end
            end
        end
        i = i + 4
        scanned = scanned + 1
    end
    addr = addr + n
end
print(string.format("scanned %d dwords", scanned))

local list = {}
for v, c in pairs(hits) do list[#list + 1] = { v = v, c = c } end
table.sort(list, function(a, b) if a.c ~= b.c then return a.c > b.c end return a.v < b.v end)
print(string.format("candidates=%d", #list))
for i = 1, math.min(#list, 40) do
    local e = list[i]
    print(string.format("  cmd=0x%08X count=%d dir=%d size=0x%X group='%s' num=0x%02X",
        e.v, e.c, math.floor(e.v / 1073741824),
        math.floor(e.v / 65536) % 16384,
        string.char(math.floor(e.v / 256) % 256), e.v % 256))
end

print("")
print("=== 387a DONE ===")
