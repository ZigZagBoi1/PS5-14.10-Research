-- 14.10 Recon Probe 03: Process Memory Layout
-- Full vmmap dump + diff-ready output for comparing against 13.60
-- Looking for: new mappings, changed protections, exploitable regions

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: VMMAP LAYOUT ===")
log("fw: " .. tostring(FW_VERSION))

local pid = syscall.getpid():tonumber()
log("pid: " .. pid)

-- Use sysctlbyname if available, otherwise use sysctl with MIB
local mib = memory.alloc(16)
memory.write_dword(mib, 1)      -- CTL_KERN
memory.write_dword(mib + 4, 14) -- KERN_PROC
memory.write_dword(mib + 8, 32) -- KERN_PROC_VMMAP
memory.write_dword(mib + 12, pid)

local oldlenp = memory.alloc(8)
memory.write_dword(oldlenp, 0)
memory.write_dword(oldlenp + 4, 0)

syscall.resolve({ sc_sysctl = 202 })
local ret = syscall.sc_sysctl(mib, 4, 0, oldlenp, 0, 0)
local sz = memory.read_dword(oldlenp):tonumber()
log("vmmap size: " .. sz)

if sz == 0 then
    log("sysctl returned size 0 — may be blocked on 14.10")
    log("trying alternative: /proc/self/map")

    local f = io.open("/proc/" .. pid .. "/map", "r")
    if f then
        log("--- /proc/pid/map ---")
        for line in f:lines() do log(line) end
        f:close()
    else
        log("/proc/pid/map: not accessible")
    end

    log("=== VMMAP PROBE DONE (limited) ===")
    return table.concat(out, "\n")
end

if sz > 512000 then
    log("unexpectedly large, capping at 512K")
    sz = 512000
end

local data = memory.alloc(sz)
memory.write_dword(oldlenp, sz)
memory.write_dword(oldlenp + 4, 0)
syscall.sc_sysctl(mib, 4, data, oldlenp, 0, 0)
local actual = memory.read_dword(oldlenp):tonumber()
log("actual: " .. actual .. " bytes")

local type_names = {
    [0]="NONE", [1]="DEFAULT", [2]="VNODE", [3]="SWAP",
    [4]="DEVICE", [5]="PHYS", [6]="DEAD", [7]="SG",
    [8]="MGTDEVICE", [9]="GUARD",
}

local prot_str = function(p)
    local s = ""
    s = s .. (p % 2 >= 1 and "r" or "-")
    s = s .. (math.floor(p/2) % 2 >= 1 and "w" or "-")
    s = s .. (math.floor(p/4) % 2 >= 1 and "x" or "-")
    return s
end

log("")
log("--- memory regions ---")
log(string.format("%-36s %-4s %8s %s", "range", "prot", "size", "type"))

local offset = 0
local count = 0
local rwx_regions = {}
local exec_regions = {}
local rw_anon = {}

while offset < actual do
    local entry_sz = memory.read_dword(data + offset):tonumber()
    if entry_sz == 0 or entry_sz > 4096 then break end

    local kve_type = memory.read_dword(data + offset + 4):tonumber()
    local start_lo = memory.read_dword(data + offset + 8):tonumber()
    local start_hi = memory.read_dword(data + offset + 12):tonumber()
    local end_lo = memory.read_dword(data + offset + 16):tonumber()
    local end_hi = memory.read_dword(data + offset + 20):tonumber()
    local prot = memory.read_dword(data + offset + 56):tonumber()

    local size_bytes = (end_hi * 0x100000000 + end_lo) - (start_hi * 0x100000000 + start_lo)
    local size_kb = math.floor(size_bytes / 1024)
    local tname = type_names[kve_type] or tostring(kve_type)
    local ps = prot_str(prot)

    log(string.format("  %08x%08x-%08x%08x %s %6dK %s",
        start_hi, start_lo, end_hi, end_lo, ps, size_kb, tname))

    if prot >= 7 then
        rwx_regions[#rwx_regions+1] = string.format("%08x%08x %dK", start_hi, start_lo, size_kb)
    end
    if math.floor(prot/4) % 2 >= 1 then
        exec_regions[#exec_regions+1] = string.format("%08x%08x %dK %s", start_hi, start_lo, size_kb, tname)
    end
    if prot == 3 and kve_type == 1 then
        rw_anon[#rw_anon+1] = string.format("%08x%08x %dK", start_hi, start_lo, size_kb)
    end

    offset = offset + entry_sz
    count = count + 1
end

log("")
log("total VMAs: " .. count)

log("")
log("--- executable regions (code) ---")
for _, r in ipairs(exec_regions) do log("  " .. r) end

if #rwx_regions > 0 then
    log("")
    log("--- RWX REGIONS (potential targets!) ---")
    for _, r in ipairs(rwx_regions) do log("  " .. r) end
else
    log("")
    log("no RWX regions (W^X enforced)")
end

log("")
log("--- large rw anonymous (heap/stack candidates) ---")
for _, r in ipairs(rw_anon) do log("  " .. r) end

log("")
log("=== VMMAP PROBE DONE ===")
return table.concat(out, "\n")
