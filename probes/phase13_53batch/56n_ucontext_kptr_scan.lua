-- CRASH_CLASS: MODERATE
-- PROBE 56n: thread ucontext kernel pointer scan + getsockopt leak scan
--
-- Context: sys 634 thr_get_ucontext copies 0x4c0 bytes of a suspended thread's
-- saved registers. We only checked known offsets (RIP +0xE0, CS +0xE8, etc).
-- There may be kernel pointers in padding/unused areas.
-- Also: getsockopt on various options might leak kernel addresses.

print("=== PROBE 56n: UCONTEXT + SOCKOPT KPTR SCAN ===")
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

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local sc455 = mk(455)  -- thr_new
local sc433 = mk(433)  -- thr_kill
local sc632 = mk(632)  -- thr_suspend
local sc633 = mk(633)  -- thr_resume
local sc634 = mk(634)  -- thr_get_ucontext
local sc477 = mk(477)  -- mmap

-- Get eboot base for jmp$ gadget
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local tlo = rd(N(ib) + 0x108) or 0
local thi = rd(N(ib) + 0x10C) or 0
if tlo < 0 then tlo = tlo + 0x100000000 end
if thi < 0 then thi = thi + 0x100000000 end
print(string.format("eboot=0x%X%08X", thi, tlo))
local function eaddr(off)
    return uint64(string.format("0x%X%08X", thi, tlo + off))
end

-- ============ SECTION A: Spawn child with thr_new, suspend, read ucontext ============
print("")
print("--- A: spawn child, suspend, read ucontext ---")

local stack = sc477(uint64(0), uint64(0x10000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local sa = N(stack)

local tid_p = memory.alloc(8)
wq(tid_p, uint64(0))

local p = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(p) + i, 0) end
wq(p, eaddr(0x15481))                        -- start_func = jmp$ (spin)
wq(uint64(N(p) + 0x08), uint64(0x42424242))  -- arg (don't care)
wq(uint64(N(p) + 0x10), uint64(sa))          -- stack_base
wq(uint64(N(p) + 0x18), uint64(0xF000))      -- stack_size
wq(uint64(N(p) + 0x30), uint64(N(tid_p)))    -- child_tid

local ok1, r1 = pcall(function() return sc455(uint64(N(p)), uint64(0x38)) end)
print("  thr_new ret=" .. (ok1 and tostring(N(r1)) or "FAIL"))

-- Wait for child to start
local x = 0; for k = 1, 100000 do x = x + k end

local tid_lo = rd(N(tid_p)) or 0
local tid_hi = rd(N(tid_p) + 4) or 0
local tid = tid_lo  -- TID is typically small, fits in low dword
print("  child_tid=" .. tid)

if tid <= 0 then print("  no TID, abort"); return end

-- Verify child is alive
local ok2, r2 = pcall(function() return sc433(uint64(tid), uint64(0)) end)
print("  thr_kill(0)=" .. (ok2 and tostring(N(r2)) or "FAIL"))

-- Suspend child
local ok3, r3 = pcall(function() return sc632(uint64(tid)) end)
print("  suspend=" .. (ok3 and tostring(N(r3)) or "FAIL"))

x = 0; for k = 1, 50000 do x = x + k end

-- Allocate ucontext buffer, fill with sentinel
local SENTINEL = 0xBBBBBBBB
local UCX_SZ = 0x500  -- 0x4c0 + padding
local ucx = memory.alloc(UCX_SZ)
local ua = N(ucx)
for off = 0, UCX_SZ - 4, 4 do wd(ua + off, SENTINEL) end

-- Read ucontext
local ok4, r4 = pcall(function()
    return sc634(uint64(tid), uint64(ua), uint64(0x4C0))
end)
print("  thr_get_ucontext=" .. (ok4 and tostring(N(r4)) or "FAIL"))

-- Resume child (so it doesn't hold the thread budget)
pcall(function() sc633(uint64(tid)) end)

if not alive() then print("DEAD after ucontext read"); return end

-- Scan all 0x4C0 bytes for kernel pointers
print("")
print("--- A2: ucontext qword scan (0x4C0 bytes) ---")
local found_kptr = false
local modified = 0

for off = 0, 0x4BC, 4 do
    local val = rd(ua + off)
    if val ~= SENTINEL then
        modified = modified + 1
        -- Check qword for kernel pointer
        if off + 4 <= 0x4C0 then
            local hi = rd(ua + off + 4)
            if hi and hi ~= SENTINEL then
                local uh = hi
                if uh < 0 then uh = uh + 0x100000000 end
                local ul = val
                if ul < 0 then ul = ul + 0x100000000 end
                if uh >= 0xFFFF8000 and uh <= 0xFFFFFFFF then
                    found_kptr = true
                    print(string.format("  *** KPTR +0x%03X: 0x%08X%08X ***", off, uh, ul))
                end
            end
        end
    end
end

-- Print non-sentinel dwords for context
print("  modified dwords: " .. modified .. " of " .. math.floor(0x4C0 / 4))
-- Dump non-zero, non-sentinel values at interesting offsets
local interesting = {}
for off = 0, 0x4BC, 8 do
    local lo = rd(ua + off) or SENTINEL
    local hi = rd(ua + off + 4) or SENTINEL
    if lo ~= SENTINEL or hi ~= SENTINEL then
        local ulo = lo; if ulo < 0 then ulo = ulo + 0x100000000 end
        local uhi = hi; if uhi < 0 then uhi = uhi + 0x100000000 end
        if ulo ~= 0 or uhi ~= 0 then
            interesting[#interesting + 1] = string.format(
                "+0x%03X: 0x%08X%08X", off, uhi, ulo)
        end
    end
end
for i = 1, math.min(#interesting, 30) do
    print("  " .. interesting[i])
end
if #interesting > 30 then
    print("  ... (" .. #interesting .. " total non-zero qwords)")
end

-- ============ SECTION B: getsockopt scan ============
print("")
print("--- B: getsockopt kernel pointer scan ---")

if not alive() then print("DEAD"); return end

-- Create a TCP socket
local sc_socket = mk(97)
local ok5, sfd = pcall(function()
    return sc_socket(uint64(2), uint64(1), uint64(6))  -- AF_INET, SOCK_STREAM, TCP
end)
local sock = ok5 and N(sfd) or -1
print("  tcp_sock=" .. sock)

if sock >= 0 then
    local sc_getsockopt = mk(118)
    local SOBUF = 0x200

    -- SOL_SOCKET=0xFFFF options
    local sol_opts = {
        {name="SO_TYPE",      level=0xFFFF, opt=0x1008},
        {name="SO_ERROR",     level=0xFFFF, opt=0x1007},
        {name="SO_SNDBUF",    level=0xFFFF, opt=0x1001},
        {name="SO_RCVBUF",    level=0xFFFF, opt=0x1002},
        {name="SO_SNDLOWAT",  level=0xFFFF, opt=0x1003},
        {name="SO_RCVLOWAT",  level=0xFFFF, opt=0x1004},
        {name="SO_LINGER",    level=0xFFFF, opt=0x0080},
        {name="SO_ACCEPTCONN",level=0xFFFF, opt=0x0002},
        {name="SO_PEERLABEL", level=0xFFFF, opt=0x1010},
        {name="SO_LISTENQLIM",level=0xFFFF, opt=0x1011},
        {name="SO_LISTENQLEN",level=0xFFFF, opt=0x1012},
        {name="SO_LISTENINCQ",level=0xFFFF, opt=0x1013},
        {name="LOCAL_PEERCRED",level=0,     opt=0x001},
    }

    -- IPPROTO_TCP=6 options
    local tcp_opts = {
        {name="TCP_NODELAY",  level=6, opt=1},
        {name="TCP_MAXSEG",   level=6, opt=2},
        {name="TCP_INFO",     level=6, opt=32},
        {name="TCP_CONGESTION",level=6, opt=64},
        {name="TCP_CCALGOOPT",level=6, opt=65},
        {name="TCP_KEEPINIT", level=6, opt=128},
        {name="TCP_KEEPIDLE", level=6, opt=256},
        {name="TCP_KEEPINTVL",level=6, opt=512},
        {name="TCP_KEEPCNT",  level=6, opt=1024},
        {name="TCP_FUNCTION_BLK",level=6, opt=8192},
    }

    local all_opts = {}
    for _, o in ipairs(sol_opts) do all_opts[#all_opts + 1] = o end
    for _, o in ipairs(tcp_opts) do all_opts[#all_opts + 1] = o end

    local sock_kptr = false

    for _, opt in ipairs(all_opts) do
        if not alive() then print("DEAD in sockopt scan"); break end

        local buf = memory.alloc(SOBUF)
        local ba = N(buf)
        for off = 0, SOBUF - 4, 4 do wd(ba + off, SENTINEL) end

        local lenp = memory.alloc(8)
        wd(N(lenp), SOBUF)
        wd(N(lenp) + 4, 0)

        local ok6, r6 = pcall(function()
            return sc_getsockopt(uint64(sock), uint64(opt.level),
                uint64(opt.opt), uint64(ba), uint64(N(lenp)))
        end)
        local rv = ok6 and N(r6) or -999

        -- Read actual length returned
        local rlen = rd(N(lenp)) or 0

        -- Scan for kernel pointers
        local kp = false
        for off = 0, math.min(rlen, SOBUF) - 8, 4 do
            local lo = rd(ba + off) or SENTINEL
            local hi = rd(ba + off + 4) or SENTINEL
            if lo ~= SENTINEL and hi ~= SENTINEL then
                local uh = hi
                if uh < 0 then uh = uh + 0x100000000 end
                if uh >= 0xFFFF8000 and uh <= 0xFFFFFFFF then
                    kp = true
                    sock_kptr = true
                    local ul = lo; if ul < 0 then ul = ul + 0x100000000 end
                    print(string.format("  *** %s KPTR +0x%X: 0x%08X%08X ***",
                        opt.name, off, uh, ul))
                end
            end
        end

        -- Also check for overcopy past rlen
        if rv == 0 and rlen > 0 and rlen < SOBUF - 8 then
            for off = rlen, math.min(rlen + 64, SOBUF) - 4, 4 do
                local val = rd(ba + off)
                if val ~= SENTINEL then
                    print(string.format("  %s OVERCOPY at +0x%X len=%d",
                        opt.name, off, rlen))
                    break
                end
            end
        end

        if rv == 0 and rlen > 4 and not kp then
            print(string.format("  %s ret=0 len=%d (clean)", opt.name, rlen))
        elseif rv ~= 0 then
            -- silent for failures
        end
    end

    pcall(function() mk(6)(uint64(sock)) end)

    if not sock_kptr then
        print("  no kernel pointers in any sockopt")
    end
end

print("")
if found_kptr then
    print("*** KERNEL POINTERS FOUND IN UCONTEXT ***")
elseif sock_kptr then
    print("*** KERNEL POINTERS FOUND IN SOCKOPT ***")
else
    print("no kernel pointers found")
end
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 56n COMPLETE ===")
