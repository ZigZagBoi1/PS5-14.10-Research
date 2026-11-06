-- CRASH_CLASS: LOW
-- PROBE 1400b: micro-arch gadget scan — upper half (0x200000..0x4A0000)
--
-- 1400a v3 scanned 0-2MB cleanly. This scans the rest.
-- 4.6MB in one shot corrupts output (Lua VM GC pressure from ~1.2M uint64 allocs)

print("=== 1400b: upper eboot ===")

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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local eboot_g = nil
local function read_byte(offset)
    local aligned = offset - (offset % 4)
    local d = safe_rd(eboot_g + uint64(aligned))
    if not d then return nil end
    local shift = (offset % 4) * 8
    return math.floor(d / (2 ^ shift)) % 256
end

local function hex_bytes(offset, n)
    local parts = {}
    for i = 0, n - 1 do
        local b = read_byte(offset + i)
        parts[#parts + 1] = b and string.format("%02X", b) or "??"
    end
    return table.concat(parts, " ")
end

-- Get eboot
local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local text_lo = safe_rd(info + 0x108)
local text_hi = safe_rd(info + 0x10C)
if not text_lo then print("FAIL") return end
eboot_g = uint64(string.format("0x%X%08X", text_hi or 0, text_lo))
print("eboot=" .. string.format("0x%X%08X", text_hi or 0, text_lo))

local START = 0x200000
local LIMIT = 0x4A0000

local rdtsc = {}
local ofa_e = {}
local rdtscp = {}

-- Seed prev from the last 3 bytes before START
local seed_d = safe_rd(eboot_g + uint64(START - 4))
local prev = {0, 0, 0}
if seed_d then
    prev[1] = math.floor(seed_d / 256) % 256
    prev[2] = math.floor(seed_d / 65536) % 256
    prev[3] = math.floor(seed_d / 16777216) % 256
end

print("scanning 0x" .. string.format("%X", START) .. "..0x" .. string.format("%X", LIMIT))

for off = START, LIMIT - 4, 4 do
    local d = safe_rd(eboot_g + uint64(off))
    if d then
        local b0 = d % 256
        local b1 = math.floor(d / 256) % 256
        local b2 = math.floor(d / 65536) % 256
        local b3 = math.floor(d / 16777216) % 256

        if prev[3] == 0x0F and b0 == 0x31 then rdtsc[#rdtsc+1] = off - 1 end
        if b0 == 0x0F and b1 == 0x31 then rdtsc[#rdtsc+1] = off end
        if b1 == 0x0F and b2 == 0x31 then rdtsc[#rdtsc+1] = off + 1 end
        if b2 == 0x0F and b3 == 0x31 then rdtsc[#rdtsc+1] = off + 2 end

        if prev[2] == 0x0F and prev[3] == 0xAE then ofa_e[#ofa_e+1] = {off - 2, b0} end
        if prev[3] == 0x0F and b0 == 0xAE then ofa_e[#ofa_e+1] = {off - 1, b1} end
        if b0 == 0x0F and b1 == 0xAE then ofa_e[#ofa_e+1] = {off, b2} end
        if b1 == 0x0F and b2 == 0xAE then ofa_e[#ofa_e+1] = {off + 1, b3} end

        if prev[2] == 0x0F and prev[3] == 0x01 and b0 == 0xF9 then rdtscp[#rdtscp+1] = off - 2 end
        if prev[3] == 0x0F and b0 == 0x01 and b1 == 0xF9 then rdtscp[#rdtscp+1] = off - 1 end
        if b0 == 0x0F and b1 == 0x01 and b2 == 0xF9 then rdtscp[#rdtscp+1] = off end
        if b1 == 0x0F and b2 == 0x01 and b3 == 0xF9 then rdtscp[#rdtscp+1] = off + 1 end

        prev[1] = b1
        prev[2] = b2
        prev[3] = b3
    end

    if off > START and (off - START) % 0x100000 == 0 then
        print("  +" .. ((off - START) / 0x100000) .. "MB")
    end
end

print("scan done")
collectgarbage("collect")

-- Classify
local lfence = {}
local mfence = {}
local clf = {}

for _, entry in ipairs(ofa_e) do
    local off = entry[1]
    local third = entry[2]
    if third == 0xE8 then lfence[#lfence+1] = off
    elseif third == 0xF0 then mfence[#mfence+1] = off
    elseif third >= 0x38 and third <= 0x3F then
        clf[#clf+1] = {off, third}
    end
end

-- Results
print("")
print("rdtsc=" .. #rdtsc .. " rdtscp=" .. #rdtscp)
print("lfence=" .. #lfence .. " mfence=" .. #mfence)
print("clflush=" .. #clf)

-- RDTSC detail with ret search
print("")
print("--- rdtsc ---")
local best_off = nil
local best_dist = 999

for _, off in ipairs(rdtsc) do
    local ret_at = nil
    for j = 2, 20 do
        local b = read_byte(off + j)
        if b == 0xC3 then ret_at = j break end
    end
    if ret_at then
        print(string.format("  +0x%06X: %s  RET@+%d", off, hex_bytes(off, ret_at + 1), ret_at))
        if ret_at < best_dist then best_off = off best_dist = ret_at end
    else
        print(string.format("  +0x%06X: %s  no-ret", off, hex_bytes(off, 8)))
    end
end

-- CLFLUSH detail
if #clf > 0 then
    print("")
    print("--- clflush ---")
    for _, entry in ipairs(clf) do
        local off = entry[1]
        local modrm = entry[2]
        local reg = ({"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"})[modrm - 0x37]
        local ret_at = nil
        for j = 3, 12 do
            if read_byte(off + j) == 0xC3 then ret_at = j break end
        end
        local n = ret_at and (ret_at + 1) or 8
        local note = ret_at and string.format("  RET@+%d", ret_at) or "  no-ret"
        print(string.format("  +0x%06X [%s]: %s%s", off, reg or "?", hex_bytes(off, n), note))
    end
end

-- LFENCE
if #lfence > 0 then
    print("")
    print("--- lfence ---")
    for _, off in ipairs(lfence) do
        print(string.format("  +0x%06X: %s", off, hex_bytes(off, 8)))
    end
end

-- MFENCE
if #mfence > 0 then
    print("")
    print("--- mfence ---")
    for _, off in ipairs(mfence) do
        print(string.format("  +0x%06X: %s", off, hex_bytes(off, 8)))
    end
end

-- RDTSCP
if #rdtscp > 0 then
    print("")
    print("--- rdtscp ---")
    for _, off in ipairs(rdtscp) do
        local ret_at = nil
        for j = 3, 20 do
            if read_byte(off + j) == 0xC3 then ret_at = j break end
        end
        local n = ret_at and (ret_at + 1) or 8
        local note = ret_at and string.format("  RET@+%d", ret_at) or "  no-ret"
        print(string.format("  +0x%06X: %s%s", off, hex_bytes(off, n), note))
    end
end

-- Summary
print("")
print("=== BEST ===")
if best_off then
    print(string.format("rdtsc: +0x%06X ret@+%d", best_off, best_dist))
else
    print("rdtsc: NONE usable in upper half")
end

print("")
print("=== 1400b DONE ===")
