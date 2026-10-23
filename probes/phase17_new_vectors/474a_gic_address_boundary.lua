-- CRASH_CLASS: MODERATE (a death names the boundary)
-- PROBE 474a: where does the gic command start killing?
--
-- Context: 473f isolated one lethal address - 0xf0000000, the eboot record the
-- console's own VM map reports. 473c/473d proved mapped code pages at
-- 0x1f830000 and 0x1d02c8000 survive and classify, so the trigger is not
-- "executable" and not "read-only". This probe walks a fixed ladder from low
-- memory up to just below eboot, printing every address BEFORE the call, so
-- the first death names the lowest lethal address and every survivor above it
-- is still measured.
--
--   0x1000, 0x100000, 0x40000000, 0x60000000, 0x80000000,
--   0x90000000, 0xa0000000, 0xb0000000, 0xc0000000, 0xd0000000, 0xe0000000
--
-- If the whole ladder survives, the trigger is the eboot mapping itself rather
-- than the high half of the address space.

print("=== PROBE 474a: gic address boundary ===")
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
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return 0
end

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)
local sc674 = make_syscall(674)

-- A named baseline first: our own page must classify before the ladder runs.
local page = memory.alloc(0x1000)
for off = 0, 0xFFC, 4 do wd(page + off, 0) end

-- Map occupancy of each candidate, so the log says mapped vs unmapped
local STRIDE, MAX = 72, 512
local buf = memory.alloc(STRIDE * MAX + 0x100)
local countp = memory.alloc(16)
for i = 0, 12, 4 do wd(countp + i, 0) end
sgn(sc674(uint64(buf), uint64(STRIDE), uint64(MAX), uint64(countp), uint64(0x40000000)))
local count = rd(countp)
if count < 0 or count > MAX then count = 0 end
print(string.format("regions: %d", count))

local function mapped_at(addr)
    for i = 0, count - 1 do
        local rec = buf + i * STRIDE
        local ok_s, s = pcall(function() return memory.read_qword(rec) end)
        local ok_e, e = pcall(function() return memory.read_qword(rec + 8) end)
        if ok_s and ok_e and s and e then
            local ah, al = 0, addr
            local sh, sl = 0, to_num(s)
            local eh, el = 0, to_num(e)
            if type(s) == "table" and s.h then sh, sl = s.h, to_num(s.l) end
            if type(e) == "table" and e.h then eh, el = e.h, to_num(e.l) end
            local av = ah * 4294967296 + al
            local sv = sh * 4294967296 + sl
            local ev = eh * 4294967296 + el
            if av >= sv and av < ev then
                local nm = {}
                for k = 0, 23 do
                    local c = 0
                    local okc, cv = pcall(function() return memory.read_byte(rec + 0x20 + k) end)
                    if okc then c = to_num(cv) end
                    if c == 0 then break end
                    if c >= 32 and c < 127 then nm[#nm + 1] = string.char(c) end
                end
                return string.format("prot=0x%X %s", rd(rec + 0x18), table.concat(nm))
            end
        end
    end
    return "unmapped"
end

local fd = sgn(sc_open(uint64(put_str("/dev/gic")), uint64(2), uint64(0)))
print("fd=" .. fd)
if fd < 0 then
    print("=== PROBE 474a ABORTED ===")
    return
end

local ladder = {
    0x00001000, 0x00100000, 0x40000000, 0x60000000, 0x80000000,
    0x90000000, 0xA0000000, 0xB0000000, 0xC0000000, 0xD0000000, 0xE0000000,
}

for _, a in ipairs(ladder) do
    for off = 0, 0xFFC, 4 do wd(page + off, 0) end
    local hi32 = math.floor(a / 4294967296)
    local lo32 = a % 4294967296
    -- write it as a qword without arithmetic on a uint64
    local ok_w = pcall(function() memory.write_qword(page, uint64(string.format("0x%X%08X", hi32, lo32))) end)
    if not ok_w then
        -- fall back: only the low 32 bits matter to the handler
        wd(page, lo32)
        wd(page + 4, 0)
    end
    wd(page + 8, 0)
    wd(page + 12, 0)
    print(string.format(">>> 0x%08X  [%s]", a, mapped_at(a)))
    local r = sc_ioctl(uint64(fd), uint64(0xC0104701), uint64(page))
    print(string.format("    ret=%d -> %08X %08X %08X %08X", sgn(r),
        rd(page), rd(page + 4), rd(page + 8), rd(page + 12)))
end

pcall(function() sc_close(uint64(fd)) end)
print("")
print("=== PROBE 474a COMPLETE ===")
