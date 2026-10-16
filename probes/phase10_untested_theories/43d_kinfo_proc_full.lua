-- CRASH_CLASS: LOW (sysctl read only)
-- PROBE 43d: Full kern.proc.pid dump — every byte of kinfo_proc
--
-- Previous probes only sampled every 8th qword (8 of ~137 qwords).
-- FreeBSD kinfo_proc (1096 bytes) contains:
--   ki_paddr (+0x00 or +0x08) — struct proc* in kernel memory
--   ki_addr  — struct user*
--   ki_tracep / ki_textvp — vnode pointers
--   ki_fd    — filedesc table pointer
--   ki_vmspace — vmspace pointer
--
-- If ANY of these leak, we have a kernel address.

print("=== PROBE 43d: FULL KINFO_PROC DUMP ===")
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

local sc_getpid = make_syscall(20)
local sc_sysctl = make_syscall(202)

local pid = 0
pcall(function() pid = to_num(sc_getpid()) end)
print("pid: " .. pid)

--------------------------------------------------------------------
-- A) Dump ALL 1096 bytes of kern.proc.pid
--------------------------------------------------------------------
print("")
print("=== A: FULL KINFO_PROC (every qword) ===")
do
    local mib = memory.alloc(16)
    safe_wd(mib, 1)       -- CTL_KERN
    safe_wd(mib + 4, 14)  -- KERN_PROC
    safe_wd(mib + 8, 1)   -- KERN_PROC_PID
    safe_wd(mib + 12, pid)

    local outbuf = memory.alloc(0x800)
    for off = 0, 0x7FC, 4 do safe_wd(outbuf + off, 0) end
    local oldlenp = memory.alloc(8)
    safe_wd(oldlenp, 0x800)

    local ok, ret = pcall(function()
        return sc_sysctl(uint64(mib), uint64(4), uint64(outbuf),
            uint64(oldlenp), uint64(0), uint64(0))
    end)
    local rv = ok and to_num(ret) or -999
    local actual_len = safe_rd(oldlenp) or 0
    print("ret=" .. rv .. " len=" .. actual_len)

    if rv == 0 and actual_len > 0 then
        -- Dump EVERY qword
        local kptrs = {}
        for off = 0, actual_len - 8, 8 do
            local q = safe_rq(outbuf + off)
            if q then
                local h, l = get_hi_lo(q)
                local tag = ""
                if h >= 0xFFFF8000 then
                    tag = " *** KPTR ***"
                    kptrs[#kptrs + 1] = {off = off, h = h, l = l}
                elseif h == 0xFFFFFFFF and l == 0 then
                    tag = " (bitmask)"
                elseif h == 0xFFFFFFFF and l == 0xFFFFFFFF then
                    tag = " (-1)"
                end
                -- Print non-zero qwords
                if h ~= 0 or l ~= 0 then
                    print(string.format("  +%03X: %08X_%08X%s", off, h, l, tag))
                end
            end
        end

        -- Also dump as raw bytes for string fields
        print("")
        print("  string fields:")
        -- ki_comm at ~+0x1B0 (process name, 20 bytes)
        -- ki_login at ~+0x1E0 (login name, 18 bytes)
        -- ki_emul at ~+0x370 (emulator name)
        local function dump_str(label, start, maxlen)
            local s = ""
            for i = 0, maxlen - 1 do
                local b = safe_rd(outbuf + start + i)
                if b and b > 31 and b < 127 then
                    s = s .. string.char(b)
                elseif b and b == 0 then
                    break
                else
                    s = s .. "."
                end
            end
            if #s > 0 then
                print(string.format("    %s (+%03X): \"%s\"", label, start, s))
            end
        end

        -- FreeBSD r230171 kinfo_proc layout (approximate):
        -- These offsets vary by version, dump a wide range
        for start = 0x100, 0x400, 0x10 do
            local has_ascii = false
            for i = 0, 15 do
                local b = safe_rd(outbuf + start + i)
                if b and b > 31 and b < 127 then
                    has_ascii = true
                    break
                end
            end
            if has_ascii then
                dump_str("str", start, 32)
            end
        end

        print("")
        print("=== KERNEL POINTER SUMMARY ===")
        print("found: " .. #kptrs)
        for _, kp in ipairs(kptrs) do
            print(string.format("  +%03X: %08X_%08X", kp.off, kp.h, kp.l))
        end
    end
end

--------------------------------------------------------------------
-- B) kern.proc.filedesc — file descriptor table dump
-- MIB: {1, 14, 14, pid} where 14 = KERN_PROC_FILEDESC
--------------------------------------------------------------------
print("")
print("=== B: KERN.PROC.FILEDESC ===")
do
    local mib = memory.alloc(16)
    safe_wd(mib, 1)       -- CTL_KERN
    safe_wd(mib + 4, 14)  -- KERN_PROC
    safe_wd(mib + 8, 14)  -- KERN_PROC_FILEDESC
    safe_wd(mib + 12, pid)

    -- Try size query first (oldp=NULL)
    local oldlenp = memory.alloc(8)
    safe_wd(oldlenp, 0)
    local ok, ret = pcall(function()
        return sc_sysctl(uint64(mib), uint64(4), uint64(0),
            uint64(oldlenp), uint64(0), uint64(0))
    end)
    local rv = ok and to_num(ret) or -999
    local needed = safe_rd(oldlenp) or 0
    print("  size query: ret=" .. rv .. " needed=" .. needed)

    if needed > 0 and needed < 0x40000 then
        local outbuf = memory.alloc(needed + 0x1000)
        for off = 0, math.min(needed + 0xFFC, 0x3FFFC), 4 do
            safe_wd(outbuf + off, 0)
        end
        safe_wd(oldlenp, needed + 0x1000)

        local ok2, ret2 = pcall(function()
            return sc_sysctl(uint64(mib), uint64(4), uint64(outbuf),
                uint64(oldlenp), uint64(0), uint64(0))
        end)
        local rv2 = ok2 and to_num(ret2) or -999
        local actual = safe_rd(oldlenp) or 0
        print("  data query: ret=" .. rv2 .. " len=" .. actual)

        if rv2 == 0 and actual > 0 then
            -- Scan for kernel pointers
            local kptrs = {}
            for off = 0, actual - 8, 8 do
                local q = safe_rq(outbuf + off)
                if q then
                    local h, l = get_hi_lo(q)
                    if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                        kptrs[#kptrs + 1] = {off = off, h = h, l = l}
                        print(string.format("  +%04X: %08X_%08X KPTR!", off, h, l))
                    end
                end
            end
            print("  kernel pointers: " .. #kptrs)
        end
    elseif rv == -999 then
        print("  syscall failed entirely")
    else
        print("  blocked or empty")
    end
end

--------------------------------------------------------------------
-- C) kern.proc.vmmap — try with LARGE buffer (128KB)
-- MIB: {1, 14, 35, pid} where 35 = KERN_PROC_VMMAP
--------------------------------------------------------------------
print("")
print("=== C: KERN.PROC.VMMAP (large buffer) ===")
do
    local mib = memory.alloc(16)
    safe_wd(mib, 1)       -- CTL_KERN
    safe_wd(mib + 4, 14)  -- KERN_PROC
    safe_wd(mib + 8, 35)  -- KERN_PROC_VMMAP
    safe_wd(mib + 12, pid)

    -- Size query first
    local oldlenp = memory.alloc(8)
    safe_wd(oldlenp, 0)
    local ok, ret = pcall(function()
        return sc_sysctl(uint64(mib), uint64(4), uint64(0),
            uint64(oldlenp), uint64(0), uint64(0))
    end)
    local rv = ok and to_num(ret) or -999
    local needed = safe_rd(oldlenp) or 0
    print("  size query: ret=" .. rv .. " needed=" .. needed)

    -- Even if size query fails, try with a big buffer
    local try_sizes = {0x10000, 0x20000, 0x40000}
    for _, sz in ipairs(try_sizes) do
        local outbuf = memory.alloc(sz)
        safe_wd(oldlenp, sz)
        local ok2, ret2 = pcall(function()
            return sc_sysctl(uint64(mib), uint64(4), uint64(outbuf),
                uint64(oldlenp), uint64(0), uint64(0))
        end)
        local rv2 = ok2 and to_num(ret2) or -999
        local actual = safe_rd(oldlenp) or 0
        print(string.format("  buf=%dK: ret=%d len=%d", sz/1024, rv2, actual))

        if rv2 == 0 and actual > 0 then
            -- Scan for kernel ptrs
            for off = 0, math.min(actual - 8, sz - 8), 8 do
                local q = safe_rq(outbuf + off)
                if q then
                    local h, l = get_hi_lo(q)
                    if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                        print(string.format("    +%04X: %08X_%08X KPTR", off, h, l))
                    end
                end
            end
            break
        end
    end
end

print("")
print("=== PROBE 43d COMPLETE ===")
