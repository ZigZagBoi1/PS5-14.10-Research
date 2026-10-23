-- CRASH_CLASS: MODERATE (the expected outcome is a process death)
-- PROBE 473c: one RX address into the gic ioctl, alone
--
-- Context: 473a walked region starts through 0xC0104701 on /dev/gic and died
-- twice at the first libSceFios2.prx text page (prot=0x5) - execute-only code.
-- RW pages answered ZERO. 473b named the records. This probe does nothing but
-- that one call, so the death is attributable to a single address and a single
-- instruction path:
--   [1] read sys 674, print record 4 (the RX text page)
--   [2] print a marker, then one ioctl with q0 = that address
--   [3] if it survives, print the returned words and ret
-- A death with [2] printed and [3] absent means the kernel side of the command
-- faulted on execute-only text.

print("=== PROBE 473c: one RX address, one call ===")
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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return 0
end
local function rb(a)
    local ok, v = pcall(function() return memory.read_byte(a) end)
    if ok then return to_num(v) end
    return 0
end

-- The RX page, from the map
local sc674 = make_syscall(674)
local STRIDE, MAX = 72, 512
local buf = memory.alloc(STRIDE * MAX + 0x100)
local countp = memory.alloc(16)
for i = 0, 12, 4 do wd(countp + i, 0) end
sgn(sc674(uint64(buf), uint64(STRIDE), uint64(MAX), uint64(countp), uint64(0x40000000)))
local count = rd(countp)
if count < 0 or count > MAX then count = 0 end
print(string.format("regions: %d", count))

-- Find the first prot=0x5 region (RX text) rather than trusting an index
local target, tname
for i = 0, count - 1 do
    local rec = buf + i * STRIDE
    if rd(rec + 0x18) == 0x5 then
        local ok_s, s = pcall(function() return memory.read_qword(rec) end)
        target = ok_s and s or nil
        local nm = {}
        for k = 0, 31 do
            local c = rb(rec + 0x20 + k)
            if c == 0 then break end
            if c >= 32 and c < 127 then nm[#nm + 1] = string.char(c) end
        end
        tname = table.concat(nm)
        print(string.format("[1] target: record %d %s prot=0x5 %s", i, tostring(target), tname))
        break
    end
end
if not target then
    print("[1] no prot=0x5 region; aborting")
    return
end

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)
local fd = sgn(sc_open(uint64(put_str("/dev/gic")), uint64(2), uint64(0)))
print("[1] fd=" .. fd)
if fd < 0 then
    print("=== PROBE 473c ABORTED ===")
    return
end

local page = memory.alloc(0x1000)
for off = 0, 0xFFC, 4 do wd(page + off, 0) end
local ok_t, h, l = pcall(function() return target.h, target.l end)
if ok_t and h then
    wq(page, uint64(string.format("0x%X%08X", h % 0x100000000, l % 0x100000000)))
else
    wq(page, uint64(string.format("0x%X", to_num(target))))
end
wq(page + 8, uint64(0))

print("[2] >>> calling 0xC0104701 with q0 = " .. tostring(target))
local r = sc_ioctl(uint64(fd), uint64(0xC0104701), uint64(page))
print(string.format("[3] survived: ret=%d words=%08X %08X %08X %08X",
    sgn(r), rd(page), rd(page + 4), rd(page + 8), rd(page + 12)))

pcall(function() sc_close(uint64(fd)) end)
print("")
print("=== PROBE 473c COMPLETE ===")
