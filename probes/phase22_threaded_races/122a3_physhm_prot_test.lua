-- CRASH_CLASS: MODERATE
-- PROBE 122a3: physhm protection investigation
--
-- 122a/122a2 die on the first read from the physhm mmap.
-- The mmap returns a valid address but access kills past pcall.
-- This probe:
-- 1. Opens physhm, mmaps with various PROT flags
-- 2. Queries protection via sys 547 (query_memory_protection)
-- 3. Does NOT attempt to read/write the mapping (avoids death)
-- 4. Compares with a known-good anonymous mmap

print("=== PROBE 122a3: PHYSHM PROT TEST ===")
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
local function fmt_q(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end
local function full_addr(v)
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return uint64(string.format("0x%X%08X", h, l))
end
local function is_err(v)
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    return h >= 0xFFFF8000
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local sc629 = mk(629)
local sc_mmap = mk(477)
local sc_munmap = mk(73)
local sc_close = mk(6)
local sc547 = mk(547)

-- Helper: query protection for an address using sys 547
local function query_prot(addr)
    local out = memory.alloc(0x100)
    for i = 0, 0x3F, 4 do wd(out + i, 0) end
    local ok, rv = pcall(function()
        return sc547(addr, uint64(out), uint64(0x100))
    end)
    if not ok then return "PFAIL", nil end
    local ret = N(rv)
    if ret < 0 then return "ERR", nil end
    -- Read the output struct
    local results = {}
    for i = 0, 0x3F, 4 do
        local v = rd(out + i)
        if v ~= nil and v ~= 0 then
            if v < 0 then v = v + 0x100000000 end
            results[i] = v
        end
    end
    return ret, results
end

-- [A] Open physhm fd
print("[A] physhm_open")
local fd_raw = sc629(uint64(1), uint64(2), uint64(0), uint64(0))
if is_err(fd_raw) then print("  OPEN FAIL") return end
local fd = N(fd_raw)
print("  fd=" .. fd)

-- [B] Reference: anonymous RW mmap (known readable)
print("")
print("[B] anonymous mmap (reference)")
local anon_raw = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
if is_err(anon_raw) then
    print("  ANON MMAP FAIL")
else
    local anon_base = full_addr(anon_raw)
    print("  anon_base=" .. fmt_q(anon_raw))
    local pr, ps = query_prot(anon_base)
    print("  547 ret=" .. tostring(pr))
    if ps then
        for k, v in pairs(ps) do
            print(string.format("    +%02X: %08X", k, v))
        end
    end
    -- Verify it's readable
    local ok_rd = pcall(function() return memory.read_dword(anon_base) end)
    print("  read_ok=" .. tostring(ok_rd))
    sc_munmap(anon_base, uint64(0x4000))
end

local c = N(native.fcall_with_rax(stub, 20))
if c ~= pid then print("DIED!") return end

-- [C] physhm with PROT_READ (0x1)
print("")
print("[C] physhm mmap PROT_READ")
local m1_raw = sc_mmap(uint64(0), uint64(0x4000), uint64(1), uint64(1), uint64(fd), uint64(0))
if is_err(m1_raw) then
    print("  PROT_READ FAIL: " .. fmt_q(m1_raw))
else
    local m1 = full_addr(m1_raw)
    print("  base=" .. fmt_q(m1_raw))
    local pr, ps = query_prot(m1)
    print("  547 ret=" .. tostring(pr))
    if ps then
        for k, v in pairs(ps) do
            print(string.format("    +%02X: %08X", k, v))
        end
    end
    print("  (not reading — would crash)")
    sc_munmap(m1, uint64(0x4000))
end

c = N(native.fcall_with_rax(stub, 20))
if c ~= pid then print("ALIVE") return end

-- [D] physhm with PROT_WRITE (0x2)
print("")
print("[D] physhm mmap PROT_WRITE")
local m2_raw = sc_mmap(uint64(0), uint64(0x4000), uint64(2), uint64(1), uint64(fd), uint64(0))
if is_err(m2_raw) then
    print("  PROT_WRITE FAIL: " .. fmt_q(m2_raw))
else
    local m2 = full_addr(m2_raw)
    print("  base=" .. fmt_q(m2_raw))
    local pr, ps = query_prot(m2)
    print("  547 ret=" .. tostring(pr))
    if ps then
        for k, v in pairs(ps) do
            print(string.format("    +%02X: %08X", k, v))
        end
    end
    sc_munmap(m2, uint64(0x4000))
end

c = N(native.fcall_with_rax(stub, 20))
if c ~= pid then print("DIED!") return end

-- [E] physhm with PROT_RW (0x3)
print("")
print("[E] physhm mmap PROT_RW")
local m3_raw = sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(fd), uint64(0))
if is_err(m3_raw) then
    print("  PROT_RW FAIL: " .. fmt_q(m3_raw))
else
    local m3 = full_addr(m3_raw)
    print("  base=" .. fmt_q(m3_raw))
    local pr, ps = query_prot(m3)
    print("  547 ret=" .. tostring(pr))
    if ps then
        for k, v in pairs(ps) do
            print(string.format("    +%02X: %08X", k, v))
        end
    end
    sc_munmap(m3, uint64(0x4000))
end

c = N(native.fcall_with_rax(stub, 20))
if c ~= pid then print("DIED!") return end

-- [F] sys 674 to check the physhm region in VM map
print("")
print("[F] physhm in VM map (sys 674)")
-- Map it again for the query
local m4_raw = sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(fd), uint64(0))
if not is_err(m4_raw) then
    local m4 = full_addr(m4_raw)
    print("  mapped at " .. fmt_q(m4_raw))

    -- Use sys 674 to enumerate and find this region
    local sc674 = mk(674)
    local qbuf = memory.alloc(0x2000)
    local QBUF = N(qbuf)
    -- sys 674: (buf, buflen, ???)
    -- Try querying with the mapped address
    for i = 0, 0x47, 4 do wd(QBUF + i, 0) end
    local ok674, rv674 = pcall(function()
        return sc674(m4, uint64(QBUF), uint64(0x48))
    end)
    if ok674 then
        local r674 = N(rv674)
        if r674 < 0 then r674 = -1 end
        print("  674 ret=" .. r674)
        if r674 >= 0 then
            for i = 0, 0x44, 4 do
                local v = rd(QBUF + i)
                if v ~= nil then
                    if v < 0 then v = v + 0x100000000 end
                    if v ~= 0 then
                        print(string.format("    +%02X: %08X", i, v))
                    end
                end
            end
        end
    else
        print("  674 PFAIL")
    end
    sc_munmap(m4, uint64(0x4000))
end

-- Cleanup
sc_close(uint64(fd))

print("")
c = N(native.fcall_with_rax(stub, 20))
print(string.format("canary=%s", c == pid and "OK" or "FAIL"))
print("=== 122a3 COMPLETE ===")
