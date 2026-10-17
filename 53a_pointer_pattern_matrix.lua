-- CRASH_CLASS: LOW
-- PROBE 53a: read-only output matrix for missed kernel-pointer patterns
--
-- Context: Earlier scans treated 0xFFFFFFFF_* values as possible kernel pointers.
-- This probe fills output buffers with a canary, queries only known read-only
-- sysctl MIBs and fstat, and classifies returned qwords by high dword. It also
-- records output length and elapsed CPU time so partial-copy or timing anomalies
-- are visible without dereferencing any returned address.

print("=== PROBE 53a: POINTER PATTERN MATRIX ===")
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
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function u64(hi, lo)
    return uint64(string.format("0x%X%08X", hi, lo))
end
local function classify(hi, lo)
    if hi == nil or lo == nil then return "unreadable" end
    if hi == 0xFFFFFFFF then return "sentinel/all-ones-high" end
    if hi >= 0xFFFF8000 then return "KERNEL-RANGE-CANDIDATE" end
    if hi >= 0x80000000 then return "high-user-or-device-range" end
    return "non-pointer/scalar-or-userland"
end
local function scan(label, buf, nbytes)
    print("  " .. label .. " bytes=" .. tostring(nbytes))
    local hits = 0
    local i = 0
    while i + 8 <= nbytes do
        local lo = safe_rd(buf + i)
        local hi = safe_rd(buf + i + 4)
        if hi ~= nil and lo ~= nil and (hi >= 0xFFFF8000 or hi == 0xFFFFFFFF) then
            print(string.format("    +0x%03X %08X_%08X %s", i, hi, lo, classify(hi, lo)))
            hits = hits + 1
        end
        i = i + 8
    end
    print("    classified_high_values=" .. tostring(hits))
end

local sc_sysctl = make_syscall(202)
local sc_fstat = make_syscall(189)
local pid = to_num(make_syscall(20)())
print("pid=" .. tostring(pid))

local function query_sysctl(name, mib)
    print("--- sysctl " .. name .. " ---")
    local m = memory.alloc(32)
    local out = memory.alloc(0x800)
    local olen = memory.alloc(8)
    local j = 0
    while j < 0x800 do safe_wd(out + j, 0xDEADC0DE); j = j + 4 end
    j = 0
    while j < #mib do safe_wd(m + j * 4, mib[j + 1]); j = j + 1 end
    safe_wd(olen, 0x800)
    local t0 = os.clock()
    local ok, ret = pcall(function()
        return sc_sysctl(uint64(m), uint64(#mib), uint64(out), uint64(olen), uint64(0), uint64(0))
    end)
    local dt = os.clock() - t0
    local n = safe_rd(olen) or 0
    print("  ok=" .. tostring(ok) .. " ret=" .. tostring(to_num(ret)) ..
        " oldlen=" .. tostring(n) .. " cpu_time=" .. string.format("%.6f", dt))
    if ok and n > 0 and n <= 0x800 then scan(name, out, n) end
end

-- Read-only MIBs observed working on 14.10.
query_sysctl("kern.ostype", {1, 1})
query_sysctl("kern.osrelease", {1, 2})
query_sysctl("kern.version", {1, 4})
query_sysctl("kern.boottime", {1, 21})
query_sysctl("vm.vmtotal", {2, 4})
query_sysctl("vm.loadavg", {2, 2})
query_sysctl("kern.proc.pid", {1, 14, 1, pid})

print("--- fstat on standard descriptors ---")
local fd = 1
while fd <= 5 do
    local st = memory.alloc(0x200)
    local j = 0
    while j < 0x200 do safe_wd(st + j, 0xDEADC0DE); j = j + 4 end
    local t0 = os.clock()
    local ok, ret = pcall(function() return sc_fstat(uint64(fd), uint64(st)) end)
    local dt = os.clock() - t0
    print("  fd=" .. tostring(fd) .. " ok=" .. tostring(ok) .. " ret=" .. tostring(to_num(ret)) ..
        " cpu_time=" .. string.format("%.6f", dt))
    if ok and to_num(ret) == 0 then scan("fstat fd=" .. tostring(fd), st, 0x200) end
    fd = fd + 1
end

print("=== 53a COMPLETE ===")
