-- CRASH_CLASS: MODERATE
-- PROBE 529a: Systematic libkernel callable function survey
--
-- DEM9N101 found 4 libkernel functions callable via fcall:
--   +0x17EF0 = sceKernelAllocateDirectMemory (works, returns phys addrs)
--   +0x17810 = sceKernelGetDirectMemorySize (returns 0x150000000)
--   +0x02E10 = __error (returns errno pointer)
--   +0x15020 = sceKernelMapDirectMemory (crashes via fcall — 7 arg)
--
-- Goal: find the 6-arg sceKernelMapDirectMemory (no name param)
-- or other mapping/query functions that work from the sandbox.
--
-- Strategy:
--   [A] Discover libkernel base + segment layout
--   [B] Scan libkernel RW regions for qwords pointing into its text
--   [C] Cross-validate known offsets
--   [D] Probe each unique function: safe call + classify return
--   [E] Deep-probe successes with mapping-style arguments

print("=== PROBE 529a: LIBKERNEL WRAPPER SURVEY ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function z(b, n) for o = 0, n - 4, 4 do wd(b + o, 0) end end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

-- Ignore SIGSYS+SIGPIPE so failing wrappers don't kill us
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

-- ============================================================
-- [A] DISCOVER LIBKERNEL SEGMENTS
-- ============================================================
print("")
print("[A] libkernel discovery")

local sc593 = mk(593)
local lk_handle = -1

-- Scan handles 0-0x100 for libkernel
for h = 0, 0x100 do
    local ib = memory.alloc(0x200)
    wd(N(ib), 0x160)
    local ok, ret = pcall(function() return sc593(uint64(h), ib) end)
    if ok and N(ret) == 0 then
        local tlo = rd(N(ib) + 0x108) or 0
        local thi = rd(N(ib) + 0x10C) or 0
        if tlo < 0 then tlo = tlo + 0x100000000 end
        if thi < 0 then thi = thi + 0x100000000 end
        if thi >= 8 and (tlo > 0 or thi > 8) then
            -- libkernel text is in high VA space (0x8_xxxxxxxx)
            local name = ""
            for i = 0, 31 do
                local b = rd(N(ib) + 8 + i)
                if b then
                    local c = b % 256
                    if c == 0 then break end
                    if c >= 32 and c < 127 then name = name .. string.char(c) end
                end
            end
            if name:find("libkernel") or name:find("libSce") then
                print(string.format("  h=0x%X text=0x%X%08X name='%s'", h, thi, tlo, name))
            end
            if name:find("libkernel") then
                lk_handle = h
            end
        end
    end
end

if lk_handle < 0 then
    -- Fallback: try known handles
    for _, h in ipairs({1, 2, 0x2001, 0x1}) do
        local ib = memory.alloc(0x200)
        wd(N(ib), 0x160)
        local ok, ret = pcall(function() return sc593(uint64(h), ib) end)
        if ok and N(ret) == 0 then
            local thi = rd(N(ib) + 0x10C) or 0
            if thi < 0 then thi = thi + 0x100000000 end
            if thi >= 8 then
                lk_handle = h
                print("  fallback handle=" .. h)
                break
            end
        end
    end
end

if lk_handle < 0 then print("FAIL: no libkernel handle"); return end

-- Read full segment info
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() sc593(uint64(lk_handle), ib) end)

-- Segment 0: text
local t_lo = rd(N(ib) + 0x108) or 0
local t_hi = rd(N(ib) + 0x10C) or 0
local t_sz = rd(N(ib) + 0x110) or 0
if t_lo < 0 then t_lo = t_lo + 0x100000000 end
if t_hi < 0 then t_hi = t_hi + 0x100000000 end
if t_sz < 0 then t_sz = t_sz + 0x100000000 end

-- Segment 1 (+0x118): likely data or relro
local d_lo = rd(N(ib) + 0x118) or 0
local d_hi = rd(N(ib) + 0x11C) or 0
local d_sz = rd(N(ib) + 0x120) or 0
if d_lo < 0 then d_lo = d_lo + 0x100000000 end
if d_hi < 0 then d_hi = d_hi + 0x100000000 end
if d_sz < 0 then d_sz = d_sz + 0x100000000 end

-- Segment 2 (+0x128): relro or bss
local r_lo = rd(N(ib) + 0x128) or 0
local r_hi = rd(N(ib) + 0x12C) or 0
local r_sz = rd(N(ib) + 0x130) or 0
if r_lo < 0 then r_lo = r_lo + 0x100000000 end
if r_hi < 0 then r_hi = r_hi + 0x100000000 end
if r_sz < 0 then r_sz = r_sz + 0x100000000 end

print(string.format("  text: 0x%X%08X sz=0x%X", t_hi, t_lo, t_sz))
print(string.format("  seg1: 0x%X%08X sz=0x%X", d_hi, d_lo, d_sz))
print(string.format("  seg2: 0x%X%08X sz=0x%X", r_hi, r_lo, r_sz))

local lk_text = uint64(string.format("0x%X%08X", t_hi, t_lo))
local lk_text_end = lk_text + uint64(t_sz)
local lk_seg1 = uint64(string.format("0x%X%08X", d_hi, d_lo))
local lk_seg2 = uint64(string.format("0x%X%08X", r_hi, r_lo))

-- Helper: check if a qword value falls in libkernel text range
local function in_lk_text(val)
    if val == nil then return false end
    local vh, vl = get_hi_lo(val)
    if vh < 0 then vh = vh + 0x100000000 end
    if vl < 0 then vl = vl + 0x100000000 end
    if vh ~= t_hi then return false end
    local off = vl - t_lo
    if off < 0 or off >= t_sz then return false end
    return true, off
end

-- ============================================================
-- [B] SCAN FOR FUNCTION POINTERS
-- ============================================================
print("")
print("[B] scanning RW regions for libkernel text pointers")

local func_offsets = {}  -- offset -> count
local scan_total = 0
local scan_hits = 0

-- Scan all readable regions after text
-- DEM9N101 layout: GOT starts at text+0x6C000, data at text+0x70000
-- We scan from seg1 start through seg1+seg2 range
local scan_regions = {}
if d_sz > 0 then
    table.insert(scan_regions, {addr = lk_seg1, size = d_sz, name = "seg1"})
end
if r_sz > 0 then
    table.insert(scan_regions, {addr = lk_seg2, size = r_sz, name = "seg2"})
end

-- Also scan the gap between text_end and seg1 (where GOT likely lives)
local gap_start = lk_text_end
local gap_end = lk_seg1
local gap_lo = N(gap_end) - N(gap_start)
if gap_lo > 0 and gap_lo < 0x200000 then
    table.insert(scan_regions, {addr = gap_start, size = gap_lo, name = "gap(text-seg1)"})
end

for _, region in ipairs(scan_regions) do
    local rstart = region.addr
    local rsize = region.size
    if rsize > 0x100000 then rsize = 0x100000 end  -- cap at 1MB
    local hits = 0
    for off = 0, rsize - 8, 8 do
        local val = rq(N(rstart) + off)
        if val then
            scan_total = scan_total + 1
            local in_text, func_off = in_lk_text(val)
            if in_text then
                scan_hits = scan_hits + 1
                hits = hits + 1
                func_offsets[func_off] = (func_offsets[func_off] or 0) + 1
            end
        end
    end
    print(string.format("  %s: %d/%d hits (%d qwords)", region.name, hits,
        math.floor(rsize / 8), math.floor(rsize / 8)))
end

-- Collect unique function offsets
local unique_funcs = {}
for off, count in pairs(func_offsets) do
    table.insert(unique_funcs, {offset = off, refs = count})
end
table.sort(unique_funcs, function(a, b) return a.offset < b.offset end)

print(string.format("\ntotal: %d text pointers, %d unique functions", scan_hits, #unique_funcs))
for i, f in ipairs(unique_funcs) do
    if i <= 50 then
        print(string.format("  +0x%05X (refs=%d)", f.offset, f.refs))
    end
end
if #unique_funcs > 50 then
    print("  ... +" .. (#unique_funcs - 50) .. " more")
end

if not alive() then print("DEAD after scan"); return end

-- ============================================================
-- [C] CROSS-VALIDATE KNOWN OFFSETS
-- ============================================================
print("")
print("[C] known offset cross-validation")

local known = {
    {off = 0x02E10, name = "__error (errno ptr)"},
    {off = 0x15020, name = "MapDirectMemory (7-arg, crashes)"},
    {off = 0x17810, name = "GetDirectMemorySize"},
    {off = 0x17EF0, name = "AllocateDirectMemory"},
}
for _, k in ipairs(known) do
    local found = func_offsets[k.off] and "FOUND" or "not in GOT"
    print(string.format("  +0x%05X %s: %s", k.off, k.name, found))
end

-- ============================================================
-- [D] PROBE EACH FUNCTION
-- ============================================================
print("")
print("[D] probing functions")

local probe_buf = memory.alloc(0x100)
local results = {}
local dead_after = nil

-- Helper: safe function call with buffer arg
local function try_call(fn_addr, nargs)
    z(probe_buf, 0x100)
    local ok, ret
    if nargs == 0 then
        ok, ret = pcall(function() return native.fcall_with_rax(fn_addr, 0) end)
    elseif nargs == 1 then
        ok, ret = pcall(function() return native.fcall_with_rax(fn_addr, 0, N(probe_buf)) end)
    elseif nargs == 2 then
        ok, ret = pcall(function() return native.fcall_with_rax(fn_addr, 0, N(probe_buf), 0x100) end)
    else
        ok, ret = pcall(function()
            return native.fcall_with_rax(fn_addr, 0, N(probe_buf), 0x100, 0, 0, 0, 0)
        end)
    end
    if not ok then return nil, "crash" end
    local rv = N(ret)
    -- Check if buffer was written
    local written = false
    for i = 0, 0xFC, 4 do
        local v = rd(N(probe_buf) + i)
        if v and v ~= 0 then written = true; break end
    end
    return rv, written and "wrote" or "clean"
end

-- First: probe known offsets to validate the method works
print("  validating with known GetDirectMemorySize (+0x17810)...")
local fn_gds = lk_text + uint64(0x17810)
local rv_gds, st_gds = try_call(fn_gds, 0)
if rv_gds then
    print(string.format("  +0x17810 ret=0x%X buf=%s", rv_gds, st_gds))
else
    print("  +0x17810 crashed (unexpected)")
end

if not alive() then print("DEAD after validation"); return end

-- Probe all unique functions with safe args
local probed = 0
local interesting = {}

for _, f in ipairs(unique_funcs) do
    if dead_after then break end
    local fn = lk_text + uint64(f.offset)

    -- Try with 0 args first (safest)
    local rv0, st0 = try_call(fn, 0)
    if not alive() then
        dead_after = f.offset
        print(string.format("  *** DEAD at +0x%05X (0-arg) ***", f.offset))
        break
    end

    -- Try with 1 arg (buffer pointer)
    local rv1, st1 = try_call(fn, 1)
    if not alive() then
        dead_after = f.offset
        print(string.format("  *** DEAD at +0x%05X (1-arg) ***", f.offset))
        break
    end

    -- Try with 2 args (buffer + size)
    local rv2, st2 = try_call(fn, 2)
    if not alive() then
        dead_after = f.offset
        print(string.format("  *** DEAD at +0x%05X (2-arg) ***", f.offset))
        break
    end

    probed = probed + 1

    -- Report non-trivial results
    local any_success = (rv0 and rv0 >= 0 and rv0 ~= 0xFFFFFFFF) or
                        (rv1 and rv1 >= 0 and rv1 ~= 0xFFFFFFFF) or
                        (rv2 and rv2 >= 0 and rv2 ~= 0xFFFFFFFF)
    local any_wrote = (st0 == "wrote") or (st1 == "wrote") or (st2 == "wrote")

    if any_success or any_wrote then
        local line = string.format("  +0x%05X: 0arg=%s/%s 1arg=%s/%s 2arg=%s/%s",
            f.offset,
            rv0 and string.format("0x%X", rv0) or "X", st0 or "X",
            rv1 and string.format("0x%X", rv1) or "X", st1 or "X",
            rv2 and string.format("0x%X", rv2) or "X", st2 or "X")
        print(line)
        table.insert(interesting, {offset = f.offset, rv0 = rv0, rv1 = rv1, rv2 = rv2,
            st0 = st0, st1 = st1, st2 = st2})
    end

    -- Periodic status
    if probed % 25 == 0 then
        print(string.format("  ... probed %d/%d, %d interesting", probed, #unique_funcs, #interesting))
    end
end

print(string.format("\nprobed %d functions, %d interesting, dead_at=%s",
    probed, #interesting, dead_after and string.format("+0x%05X", dead_after) or "none"))

if not alive() then print("DEAD before deep probe"); return end

-- ============================================================
-- [E] DEEP PROBE INTERESTING FUNCTIONS
-- ============================================================
print("")
print("[E] deep probing interesting functions")

-- For each interesting function, try with mapping-style arguments
local alloc_buf = memory.alloc(0x100)

-- First: allocate direct memory to have a valid phys addr
print("  allocating direct memory for test...")
local fn_alloc = lk_text + uint64(0x17EF0)
local phys_out = memory.alloc(8)
wq(N(phys_out), uint64(0))
local alloc_rv, alloc_st = pcall(function()
    return native.fcall_with_rax(fn_alloc, 0,
        0,               -- searchStart
        0x10000000,      -- searchEnd (256MB)
        0x4000,          -- len (16KB, one page)
        0x4000,          -- alignment
        0,               -- memoryType
        N(phys_out))     -- &physOut
end)
local phys_addr = rq(N(phys_out))
print(string.format("  AllocateDirectMemory: rv=%s phys=%s",
    alloc_rv and tostring(N(alloc_rv)) or "crash", fmt(phys_addr)))

if not alive() then print("DEAD after alloc"); return end

-- Try each interesting function with MapDirectMemory-style args
-- sceKernelMapDirectMemory(void **addr, size_t len, int prot, int flags,
--                           off_t directMemStart, size_t alignment)
-- 6 args: rdi=&addr, rsi=len, rdx=prot, rcx=flags, r8=physStart, r9=align
for _, f in ipairs(interesting) do
    -- Skip known functions
    if f.offset == 0x17EF0 or f.offset == 0x17810 or f.offset == 0x02E10 then
        -- already known
    elseif phys_addr and N(phys_addr) > 0 then
        local fn = lk_text + uint64(f.offset)
        local addr_out = memory.alloc(8)
        wq(N(addr_out), uint64(0))

        -- Pattern 1: MapDirectMemory(6-arg)
        local ok1, rv1 = pcall(function()
            return native.fcall_with_rax(fn, 0,
                N(addr_out),    -- rdi = &addr (output)
                0x4000,         -- rsi = len
                3,              -- rdx = prot (RW)
                0x10002,        -- rcx = flags (MAP_PRIVATE|MAP_ANON variant)
                N(phys_addr),   -- r8 = physStart
                0x4000)         -- r9 = alignment
        end)
        if not alive() then
            print(string.format("  +0x%05X MapDM pattern: KILLED", f.offset))
            return
        end
        local mapped_addr = rq(N(addr_out))
        if ok1 and N(rv1) == 0 and mapped_addr and N(mapped_addr) > 0 then
            print(string.format("  *** +0x%05X MapDirectMemory(6arg) SUCCESS! rv=0 addr=%s ***",
                f.offset, fmt(mapped_addr)))
        elseif ok1 then
            local rv_val = N(rv1)
            if rv_val ~= 0xFFFFFFFF and rv_val ~= 0 then
                print(string.format("  +0x%05X MapDM: rv=0x%X addr=%s", f.offset, rv_val, fmt(mapped_addr)))
            end
        end

        -- Pattern 2: QueryMemoryProtection(addr, &start, &end, &prot)
        local qbuf = memory.alloc(32); z(qbuf, 32)
        local ok2, rv2 = pcall(function()
            return native.fcall_with_rax(fn, 0,
                N(lk_text),     -- rdi = addr to query
                N(qbuf),        -- rsi = &start_out
                N(qbuf) + 8,    -- rdx = &end_out
                N(qbuf) + 16)   -- rcx = &prot_out
        end)
        if not alive() then
            print(string.format("  +0x%05X QMP pattern: KILLED", f.offset))
            return
        end
        if ok2 and N(rv2) == 0 then
            local qs = rq(N(qbuf))
            local qe = rq(N(qbuf) + 8)
            local qp = rd(N(qbuf) + 16)
            if qs and N(qs) > 0 then
                print(string.format("  *** +0x%05X QueryMemProt SUCCESS! start=%s end=%s prot=0x%X ***",
                    f.offset, fmt(qs), fmt(qe), qp or 0))
            end
        end

        -- Pattern 3: VirtualQuery(addr, flags, &info, count)
        local vbuf = memory.alloc(0x80); z(vbuf, 0x80)
        local ok3, rv3 = pcall(function()
            return native.fcall_with_rax(fn, 0,
                N(lk_text),     -- rdi = addr
                0,              -- rsi = flags
                N(vbuf),        -- rdx = &info_out
                0x80)           -- rcx = info size
        end)
        if not alive() then
            print(string.format("  +0x%05X VQ pattern: KILLED", f.offset))
            return
        end
        if ok3 and N(rv3) == 0 then
            local vq0 = rq(N(vbuf))
            local vq1 = rq(N(vbuf) + 8)
            if vq0 and N(vq0) > 0 then
                print(string.format("  *** +0x%05X VirtualQuery SUCCESS! [0]=%s [8]=%s ***",
                    f.offset, fmt(vq0), fmt(vq1)))
            end
        end
    end
end

-- ============================================================
-- [F] TARGETED: Scan ±0x2000 around MapDirectMemory (+0x15020)
-- ============================================================
print("")
print("[F] targeted scan around +0x15020 (MapDirectMemory)")

if phys_addr and N(phys_addr) > 0 then
    -- Try every 0x10-aligned offset from +0x14000 to +0x17000
    -- Looking for a 6-arg MapDirectMemory that works
    local found_map = false
    local scan_start = 0x14000
    local scan_end = 0x17000
    local tested = 0

    for test_off = scan_start, scan_end, 0x10 do
        local fn = lk_text + uint64(test_off)
        local addr_out = memory.alloc(8)
        wq(N(addr_out), uint64(0))

        local ok, rv = pcall(function()
            return native.fcall_with_rax(fn, 0,
                N(addr_out),    -- &addr
                0x4000,         -- len
                3,              -- prot RW
                0,              -- flags (try 0)
                N(phys_addr),   -- physAddr
                0x4000)         -- alignment
        end)
        if not alive() then
            print(string.format("  +0x%05X: KILLED (nearby is 7-arg variant?)", test_off))
            return
        end
        tested = tested + 1
        if ok then
            local rv_val = N(rv)
            local ma = rq(N(addr_out))
            if rv_val == 0 and ma and N(ma) > 0 then
                print(string.format("  *** +0x%05X: rv=0 addr=%s — MAPPING SUCCESS ***", test_off, fmt(ma)))
                found_map = true
                -- Verify: try reading the mapped page
                local peek = rd(N(ma))
                print(string.format("  mapped[0] = 0x%X", peek or 0xDEAD))
                break
            end
        end
    end

    if not found_map then
        print(string.format("  tested %d offsets [0x%X-0x%X], no 6-arg map found", tested, scan_start, scan_end))
    end

    -- Also try with different flags values
    print("")
    print("  retrying +0x15020 with different flags combos (6-arg, name slot empty)...")
    local flags_list = {0, 1, 2, 0x10, 0x12, 0x100, 0x1000, 0x10000, 0x10002, 0x80000}
    for _, flags in ipairs(flags_list) do
        local addr_out = memory.alloc(8)
        wq(N(addr_out), uint64(0))
        local ok, rv = pcall(function()
            return native.fcall_with_rax(lk_text + uint64(0x15020), 0,
                N(addr_out), 0x4000, 3, flags, N(phys_addr), 0x4000)
        end)
        if not alive() then
            print(string.format("  flags=0x%X: KILLED", flags))
            return
        end
        if ok then
            local rv_val = N(rv)
            local ma = rq(N(addr_out))
            if rv_val == 0 and ma and N(ma) > 0 then
                print(string.format("  *** flags=0x%X: rv=0 addr=%s SUCCESS ***", flags, fmt(ma)))
            elseif rv_val ~= 0xFFFFFFFF then
                print(string.format("  flags=0x%X: rv=0x%X addr=%s", flags, rv_val, fmt(ma)))
            end
        else
            print(string.format("  flags=0x%X: crash", flags))
        end
    end
else
    print("  skipped: no phys addr from AllocateDirectMemory")
end

-- ============================================================
-- [G] SUMMARY
-- ============================================================
print("")
print("[G] summary")
print("  libkernel text: " .. fmt(lk_text) .. " sz=0x" .. string.format("%X", t_sz))
print("  unique functions found: " .. #unique_funcs)
print("  probed: " .. probed)
print("  interesting: " .. #interesting)
for _, f in ipairs(interesting) do
    print(string.format("    +0x%05X", f.offset))
end
print("  dead_at: " .. (dead_after and string.format("+0x%05X", dead_after) or "none"))
print("canary=" .. N(native.fcall_with_rax(stub, 20)))
print("=== 529a COMPLETE ===")
