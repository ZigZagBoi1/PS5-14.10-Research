-- P4: kernel info-leak sweep — sysctl + named-object + module-info oracles
-- (KASLR hunt, big-net style: cast many cheap hooks in one probe)
print("=== P4: KASLR oracle sweep ===")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
syscall.resolve({
    sysctlbyname = 202, sysctl = 3, getpid = 20,
    sysarch = 165, clock_gettime = 232
})
-- sysctlbyname probes (name2oid style): kern.boottime, kern.vm_guest,
-- hw.model, kern.ostype, kern.osrelease, kern.version(truncated)
local names = {"kern.boottime", "hw.model", "kern.ostype", "kern.osrelease",
               "kern.vm_guest", "kern.smp.cpus", "vm.stats.vm.v_free_count"}
for _, nm in ipairs(names) do
    local ok, rv = pcall(function()
        local oid = memory.alloc(24)
        local oidlen = memory.alloc(8)
        memory.write_qword(oidlen, 24)
        local r1 = to_num(sysctl_name2oid and syscall.sysctl_name2oid(nm, oid, oidlen) or -1)
        return r1
    end)
    print("name2oid(" .. nm .. ") rv=" .. tostring(ok and rv or "EXC"))
end
-- kern.boottime via sysctlbyname direct (string out)
local ok2, boot = pcall(function()
    local buf = memory.alloc(64)
    local sz = memory.alloc(8)
    memory.write_qword(sz, 64)
    -- sysctlbyname(name, oldp, oldlenp, 0, 0): need fcall wrapper w/ 5 args
    return "skip-direct"
end)
print("direct: " .. tostring(boot))
-- dynlib / module base leak (community: dynlib_get_info 593)
syscall.resolve({ dynlib_get_info = 593 })
local ok3, dl = pcall(function()
    local buf = memory.alloc(0x400)
    local rv = to_num(syscall.dynlib_get_info(0, 1, buf))  -- main obj?
    return rv, buf
end)
print("dynlib_get_info rv=" .. tostring(ok3 and dl or "EXC"))
-- vm op counter side channel (sys 624, community: +5 per mmap, zero jitter)
syscall.resolve({ vmcount = 624 })
local ok4, c1 = pcall(function() return to_num(syscall.vmcount(0)) end)
local m = to_num(syscall.mmap(0, 4096, 3, 4098, -1, 0))
local ok5, c2 = pcall(function() return to_num(syscall.vmcount(0)) end)
print("vmcount before/after mmap: " .. tostring(ok4 and c1 or "?") .. " -> " .. tostring(ok5 and c2 or "?"))
pcall(function() syscall.munmap(m, 4096) end)
print("P4_DONE")
