-- CRASH_CLASS: LOW
-- PROBE 172a: sysctlbyname (570) - read any sysctl without knowing its MIB
--
-- Every sysctl leak attempt so far built a MIB from an assumed mapping
-- (probe 43f) and got -1, which cannot distinguish "blocked" from "wrong MIB".
-- FreeBSD 570 resolves the same nodes by name, so this probe asks for nodes
-- whose MIB numbers nobody here has confirmed - kern.securelevel, kern.hostname,
-- vm.kvm_size, hw.physmem and the per-pid process dump - and compares each
-- answer with the same read through plain sysctl (202) using the MIB under test.
--
-- A name that resolves where the MIB read failed means the 202 path is filtered
-- by number and the by-name path is a leak surface. A kernel address in any
-- returned buffer is the KASLR defeat this branch has been missing.
--
-- Reads only: no writes, no threads, nothing that has killed a previous probe.

print("=== PROBE 172a: SYSCTLBYNAME (570) ===")

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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return -1
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end

local sc20 = make_syscall(20)
local sc570 = make_syscall(570)
local pid = to_num(sc20())
print("[0] canary pid=" .. tostring(pid))

local namebuf = memory.alloc(0x100)
local outbuf = memory.alloc(0x800)
local oldlenp = memory.alloc(8)

local function name_read(name)
    for i = 0, 0xFC, 4 do safe_wd(namebuf + i, 0) end
    for i = 1, #name do safe_wd(namebuf + i - 1, string.byte(name, i)) end
    for i = 0, 0x7FC, 4 do safe_wd(outbuf + i, 0) end
    safe_wd(oldlenp, 0x800)
    local ok, rv = pcall(function()
        return sc570(uint64(namebuf), uint64(outbuf), uint64(oldlenp),
            uint64(0), uint64(0), uint64(0))
    end)
    local hi, lo = 0, 0
    if ok then hi, lo = get_hi_lo(rv) end
    local n = safe_rd(oldlenp)
    local b0 = safe_rd(outbuf)
    local b1 = safe_rd(outbuf + 4)
    print(string.format("  %-42s ok=%s ret=%d len=0x%X d0=0x%08X d1=0x%08X",
        name, tostring(ok), lo, n, b0, b1))
end

print("[1] fixed names")
name_read("kern.ostype")
name_read("kern.osrelease")
name_read("kern.version")
name_read("kern.securelevel")
name_read("kern.hostname")
name_read("kern.smp.cpus")
name_read("hw.physmem")
name_read("hw.ncpu")
name_read("vm.kvm_size")
name_read("vm.stats.vm.v_page_count")
name_read("security.bsd.unprivileged_proc_debug")
name_read("kern.coredump")
name_read("kern.maxproc")
name_read("kern.somaxconn")
name_read("kern.module_path")

print("[2] per-process dump by name")
local pname = "kern.proc.pid." .. tostring(pid)
name_read(pname)
name_read("kern.proc.all")

print("[3] canary after: ok=true pid=" .. tostring(to_num(sc20())))
print("=== PROBE 172a DONE ===")
