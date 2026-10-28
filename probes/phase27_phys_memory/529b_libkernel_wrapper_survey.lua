-- CRASH_CLASS: MODERATE
-- PROBE 529b: Systematic libkernel callable function survey (FIXED)
--
-- 529a BUG: scanned libSceLibcInternal (handle 0x2) instead of libkernel.
-- Handle 0x2001 is outside the 0-0x100 range, and the fallback picked 0x2 first.
--
-- FIX: try 0x2001 FIRST, then scan 0-0x4000 for "libkernel" in name.
-- NEVER read .text (XO kills past pcall). Only scan RW regions.
--
-- DEM9N101 known offsets (relative to libkernel text base):
--   +0x17EF0 = sceKernelAllocateDirectMemory (works)
--   +0x17810 = sceKernelGetDirectMemorySize (returns 0x150000000)
--   +0x02E10 = __error (errno pointer)
--   +0x15020 = sceKernelMapDirectMemory/MapNamedDirectMemory (7-arg, crashes via fcall)
--
-- Goal: find a 6-arg MapDirectMemory variant callable via fcall.

print("=== PROBE 529b: LIBKERNEL WRAPPER SURVEY (FIXED) ===")
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
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

-- ============================================================
-- [A] DISCOVER LIBKERNEL SEGMENTS
-- ============================================================
print("[A] libkernel discovery")

local sc593 = mk(593)
local lk_handle = -1

-- Helper: read module name from info struct
local function read_mod_name(ib_addr)
    local name = ""
    for i = 0, 31 do
        local b = rd(N(ib_addr) + 8 + i)
        if b then
            local c = b % 256
            if c == 0 then break end
            if c >= 32 and c < 127 then name = name .. string.char(c) end
        end
    end
    return name
end

-- Helper: check if handle has valid segments
local function try_handle(h)
    local ib = memory.alloc(0x200)
    wd(N(ib), 0x160)
    local ok, ret = pcall(function() return sc593(uint64(h), ib) end)
    if ok and N(ret) == 0 then
        local tlo = rd(N(ib) + 0x108) or 0
        local thi = rd(N(ib) + 0x10C) or 0
        if tlo < 0 then tlo = tlo + 0x100000000 end
        if thi < 0 then thi = thi + 0x100000000 end
        if tlo ~= 0 or thi ~= 0 then
            return true, read_mod_name(ib), thi, tlo
        end
    end
    return false, "", 0, 0
end

-- Step 1: try handle 0x2001 first (DEM9N101's known libkernel handle)
local found, name, _, _ = try_handle(0x2001)
if found then
    if name:find("libkernel") or name == "" then
        lk_handle = 0x2001
        print(string.format("  handle 0x2001: name='%s' — using as libkernel", name))
    else
        print(string.format("  handle 0x2001: name='%s' — NOT libkernel, continuing search", name))
    end
end

-- Step 2: try 0x1 (another common libkernel handle)
if lk_handle < 0 then
    found, name, _, _ = try_handle(0x1)
    if found and name:find("libkernel") then
        lk_handle = 0x1
        print(string.format("  handle 0x1: name='%s' — using as libkernel", name))
    end
end

-- Step 3: scan handles 0-0x100 for explicit "libkernel" in name
if lk_handle < 0 then
    print("  scanning handles 0-0x100 for libkernel...")
    for h = 0, 0x100 do
        local f2, n2, _, _ = try_handle(h)
        if f2 and n2:find("libkernel") then
            lk_handle = h
            print(string.format("  h=0x%X name='%s' — found libkernel", h, n2))
            break
        end
    end
end

-- Step 4: scan higher handles 0x2000-0x2100
if lk_handle < 0 then
    print("  scanning handles 0x2000-0x2100...")
    for h = 0x2000, 0x2100 do
        local f2, n2, _, _ = try_handle(h)
        if f2 then
            print(string.format("  h=0x%X name='%s'", h, n2))
            if n2:find("libkernel") or n2 == "" then
                lk_handle = h
                print("  using this handle")
                break
            end
        end
    end
end

-- Step 5: behavioral validation — call GetDirectMemorySize at +0x17810
-- If it returns 0x150000000, we have the right module
if lk_handle >= 0 then
    local ib_v = memory.alloc(0x200)
    wd(N(ib_v), 0x160)
    pcall(function() sc593(uint64(lk_handle), ib_v) end)
    local vt_lo = rd(N(ib_v) + 0x108) or 0
    local vt_hi = rd(N(ib_v) + 0x10C) or 0
    if vt_lo < 0 then vt_lo = vt_lo + 0x100000000 end
    if vt_hi < 0 then vt_hi = vt_hi + 0x100000000 end
    local test_fn = uint64(string.format("0x%X%08X", vt_hi, vt_lo + 0x17810))
    local ok_v, rv_v = pcall(function() return native.fcall_with_rax(test_fn, 0) end)
    if ok_v then
        local val = N(rv_v)
        local vh, vl = get_hi_lo(rv_v)
        if vh < 0 then vh = vh + 0x100000000 end
        if vl < 0 then vl = vl + 0x100000000 end
        print(string.format("  validation: GetDirectMemorySize(+0x17810)=%s", fmt(rv_v)))
        if vh == 1 and vl == 0x50000000 then
            print("  CONFIRMED: returns 0x150000000 — correct module!")
        elseif val == 0 or not alive() then
            print("  WARNING: unexpected return — may be wrong module")
        end
    else
        print("  validation call crashed — wrong module or bad offset")
        if not alive() then print("DEAD during validation"); return end
    end
end

if lk_handle < 0 then print("FAIL: no libkernel handle found"); return end
if not alive() then print("DEAD after handle search"); return end

-- Read full segment info for confirmed handle
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() sc593(uint64(lk_handle), ib) end)

local t_lo = rd(N(ib) + 0x108) or 0
local t_hi = rd(N(ib) + 0x10C) or 0
local t_sz = rd(N(ib) + 0x110) or 0
if t_lo < 0 then t_lo = t_lo + 0x100000000 end
if t_hi < 0 then t_hi = t_hi + 0x100000000 end
if t_sz < 0 then t_sz = t_sz + 0x100000000 end

local d_lo = rd(N(ib) + 0x118) or 0
local d_hi = rd(N(ib) + 0x11C) or 0
local d_sz = rd(N(ib) + 0x120) or 0
if d_lo < 0 then d_lo = d_lo + 0x100000000 end
if d_hi < 0 then d_hi = d_hi + 0x100000000 end
if d_sz < 0 then d_sz = d_sz + 0x100000000 end

local r_lo = rd(N(ib) + 0x128) or 0
local r_hi = rd(N(ib) + 0x12C) or 0
local r_sz = rd(N(ib) + 0x130) or 0
if r_lo < 0 then r_lo = r_lo + 0x100000000 end
if r_hi < 0 then r_hi = r_hi + 0x100000000 end
if r_sz < 0 then r_sz = r_sz + 0x100000000 end

print(string.format("  handle=0x%X", lk_handle))
print(string.format("  text: 0x%X%08X sz=0x%X (XO — will NOT read)", t_hi, t_lo, t_sz))
print(string.format("  seg1: 0x%X%08X sz=0x%X", d_hi, d_lo, d_sz))
print(string.format("  seg2: 0x%X%08X sz=0x%X", r_hi, r_lo, r_sz))

local lk_text = uint64(string.format("0x%X%08X", t_hi, t_lo))
local lk_seg1 = uint64(string.format("0x%X%08X", d_hi, d_lo))
local lk_seg2 = uint64(string.format("0x%X%08X", r_hi, r_lo))

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
-- [B] SCAN RW REGIONS FOR FUNCTION POINTERS
-- ============================================================
print("")
print("[B] scanning RW regions for libkernel text pointers")

local func_offsets = {}
local scan_hits = 0

local scan_regions = {}
if d_sz > 0 then
    table.insert(scan_regions, {addr = lk_seg1, size = d_sz, name = "seg1"})
end
if r_sz > 0 then
    table.insert(scan_regions, {addr = lk_seg2, size = r_sz, name = "seg2"})
end

-- Scan gap between text_end and seg1 (GOT area per DEM9N101: text+0x6C000..+0x70000)
local lk_text_end = lk_text + uint64(t_sz)
local gap_size = N(lk_seg1) - N(lk_text_end)
if gap_size > 0 and gap_size < 0x200000 then
    table.insert(scan_regions, {addr = lk_text_end, size = gap_size, name = "gap(GOT area)"})
end

for _, region in ipairs(scan_regions) do
    local rstart = region.addr
    local rsize = region.size
    if rsize > 0x100000 then rsize = 0x100000 end
    local hits = 0
    for off = 0, rsize - 8, 8 do
        local val = rq(N(rstart) + off)
        if val then
            local in_text, func_off = in_lk_text(val)
            if in_text then
                scan_hits = scan_hits + 1
                hits = hits + 1
                func_offsets[func_off] = (func_offsets[func_off] or 0) + 1
            end
        end
    end
    print(string.format("  %s: %d hits in %d qwords", region.name, hits, math.floor(rsize / 8)))
end

local unique_funcs = {}
for off, count in pairs(func_offsets) do
    table.insert(unique_funcs, {offset = off, refs = count})
end
table.sort(unique_funcs, function(a, b) return a.offset < b.offset end)

print(string.format("\ntotal: %d text pointers, %d unique functions", scan_hits, #unique_funcs))
for i, f in ipairs(unique_funcs) do
    if i <= 60 then
        print(string.format("  +0x%05X (refs=%d)", f.offset, f.refs))
    end
end
if #unique_funcs > 60 then
    print("  ... +" .. (#unique_funcs - 60) .. " more")
end

if not alive() then print("DEAD after scan"); return end

-- ============================================================
-- [C] CROSS-VALIDATE KNOWN DEM9N101 OFFSETS
-- ============================================================
print("")
print("[C] known offset cross-validation")

local known = {
    {off = 0x02E10, name = "__error (errno ptr)"},
    {off = 0x15020, name = "MapDirectMemory/MapNamed (7-arg)"},
    {off = 0x17810, name = "GetDirectMemorySize"},
    {off = 0x17EF0, name = "AllocateDirectMemory"},
}
for _, k in ipairs(known) do
    local found_str = func_offsets[k.off] and
        string.format("FOUND (refs=%d)", func_offsets[k.off]) or "not in scan"
    print(string.format("  +0x%05X %s: %s", k.off, k.name, found_str))
end

-- ============================================================
-- [D] PROBE EACH FUNCTION WITH SAFE ARGS
-- ============================================================
print("")
print("[D] probing functions (via fcall_with_rax, NO .text reads)")

local probe_buf = memory.alloc(0x100)
local dead_after = nil
local interesting = {}
local probed = 0

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
    local written = false
    for i = 0, 0xFC, 4 do
        local v = rd(N(probe_buf) + i)
        if v and v ~= 0 then written = true; break end
    end
    return rv, written and "wrote" or "clean"
end

-- Validate with known GetDirectMemorySize
print("  validating: GetDirectMemorySize (+0x17810)...")
local fn_gds = lk_text + uint64(0x17810)
local rv_gds, st_gds = try_call(fn_gds, 0)
if rv_gds then
    print(string.format("  +0x17810 ret=%s buf=%s", fmt(rv_gds ~= nil and uint64(rv_gds) or nil), st_gds))
else
    print("  +0x17810 crashed")
end
if not alive() then print("DEAD after validation"); return end

-- Validate __error
print("  validating: __error (+0x02E10)...")
local fn_err = lk_text + uint64(0x02E10)
local rv_err, st_err = try_call(fn_err, 0)
if rv_err then
    print(string.format("  +0x02E10 ret=0x%X buf=%s", rv_err, st_err))
else
    print("  +0x02E10 crashed")
end
if not alive() then print("DEAD after __error"); return end

-- Probe all discovered functions
for _, f in ipairs(unique_funcs) do
    if dead_after then break end
    local fn = lk_text + uint64(f.offset)

    local rv0, st0 = try_call(fn, 0)
    if not alive() then
        dead_after = f.offset
        print(string.format("  *** DEAD at +0x%05X (0-arg) ***", f.offset))
        break
    end

    local rv1, st1 = try_call(fn, 1)
    if not alive() then
        dead_after = f.offset
        print(string.format("  *** DEAD at +0x%05X (1-arg) ***", f.offset))
        break
    end

    local rv2, st2 = try_call(fn, 2)
    if not alive() then
        dead_after = f.offset
        print(string.format("  *** DEAD at +0x%05X (2-arg) ***", f.offset))
        break
    end

    probed = probed + 1

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

    if probed % 25 == 0 then
        print(string.format("  ... probed %d/%d, %d interesting", probed, #unique_funcs, #interesting))
    end
end

print(string.format("\nprobed %d functions, %d interesting, dead_at=%s",
    probed, #interesting, dead_after and string.format("+0x%05X", dead_after) or "none"))

if not alive() then print("DEAD before deep probe"); return end

-- ============================================================
-- [E] DEEP PROBE WITH MAPPING-STYLE ARGUMENTS
-- ============================================================
print("")
print("[E] deep probing interesting functions")

-- Allocate direct memory for a valid phys addr
print("  allocating direct memory...")
local fn_alloc = lk_text + uint64(0x17EF0)
local phys_out = memory.alloc(8)
wq(N(phys_out), uint64(0))
local ok_a, rv_a = pcall(function()
    return native.fcall_with_rax(fn_alloc, 0,
        0, 0x10000000, 0x4000, 0x4000, 0, N(phys_out))
end)
local phys_addr = rq(N(phys_out))
print(string.format("  AllocateDirectMemory: rv=%s phys=%s",
    ok_a and tostring(N(rv_a)) or "crash", fmt(phys_addr)))

if not alive() then print("DEAD after alloc"); return end

local have_phys = phys_addr and N(phys_addr) > 0

for _, f in ipairs(interesting) do
    if f.offset == 0x17EF0 or f.offset == 0x17810 or f.offset == 0x02E10 then
        -- skip known
    elseif have_phys then
        local fn = lk_text + uint64(f.offset)

        -- Pattern 1: MapDirectMemory(6-arg)
        local addr_out = memory.alloc(8)
        wq(N(addr_out), uint64(0))
        local ok1, rv1 = pcall(function()
            return native.fcall_with_rax(fn, 0,
                N(addr_out), 0x4000, 3, 0x10, N(phys_addr), 0x4000)
        end)
        if not alive() then
            print(string.format("  +0x%05X MapDM: KILLED", f.offset))
            return
        end
        if ok1 then
            local mapped = rq(N(addr_out))
            if N(rv1) == 0 and mapped and N(mapped) > 0 then
                print(string.format("  *** +0x%05X MapDirectMemory SUCCESS! rv=0 addr=%s ***",
                    f.offset, fmt(mapped)))
                local peek = rd(N(mapped))
                print(string.format("  mapped[0] = 0x%X", peek or 0xDEAD))
            end
        end

        -- Pattern 2: QueryMemoryProtection(addr, &start, &end, &prot)
        local qbuf = memory.alloc(32); z(qbuf, 32)
        local ok2, rv2 = pcall(function()
            return native.fcall_with_rax(fn, 0,
                N(lk_text), N(qbuf), N(qbuf) + 8, N(qbuf) + 16)
        end)
        if not alive() then
            print(string.format("  +0x%05X QMP: KILLED", f.offset))
            return
        end
        if ok2 and N(rv2) == 0 then
            local qs = rq(N(qbuf))
            if qs and N(qs) > 0 then
                local qe = rq(N(qbuf) + 8)
                local qp = rd(N(qbuf) + 16)
                print(string.format("  *** +0x%05X QueryMemProt! start=%s end=%s prot=0x%X ***",
                    f.offset, fmt(qs), fmt(qe), qp or 0))
            end
        end

        -- Pattern 3: VirtualQuery(addr, flags, &info, size)
        local vbuf = memory.alloc(0x80); z(vbuf, 0x80)
        local ok3, rv3 = pcall(function()
            return native.fcall_with_rax(fn, 0,
                N(lk_text), 0, N(vbuf), 0x80)
        end)
        if not alive() then
            print(string.format("  +0x%05X VQ: KILLED", f.offset))
            return
        end
        if ok3 and N(rv3) == 0 then
            local vq0 = rq(N(vbuf))
            if vq0 and N(vq0) > 0 then
                local vq1 = rq(N(vbuf) + 8)
                print(string.format("  *** +0x%05X VirtualQuery! [0]=%s [8]=%s ***",
                    f.offset, fmt(vq0), fmt(vq1)))
            end
        end
    end
end

-- ============================================================
-- [F] TARGETED SCAN AROUND +0x15020 (MapDirectMemory)
-- ============================================================
print("")
print("[F] targeted scan: +0x14000 to +0x18000 with MapDM args")

if have_phys then
    local found_map = false
    local tested = 0
    local scan_start = 0x14000
    local scan_end = 0x18000

    for test_off = scan_start, scan_end, 0x10 do
        local fn = lk_text + uint64(test_off)
        local addr_out = memory.alloc(8)
        wq(N(addr_out), uint64(0))

        -- Try with flags=0 first (simplest)
        local ok, rv = pcall(function()
            return native.fcall_with_rax(fn, 0,
                N(addr_out), 0x4000, 3, 0, N(phys_addr), 0x4000)
        end)
        if not alive() then
            print(string.format("  +0x%05X: KILLED", test_off))
            return
        end
        tested = tested + 1
        if ok then
            local rv_val = N(rv)
            local ma = rq(N(addr_out))
            if rv_val == 0 and ma and N(ma) > 0 then
                print(string.format("  *** +0x%05X: rv=0 addr=%s — MAPPING SUCCESS ***",
                    test_off, fmt(ma)))
                found_map = true
                local peek = rd(N(ma))
                print(string.format("  mapped[0] = 0x%X", peek or 0xDEAD))
                break
            end
        end

        -- Try flags=0x10 as well
        wq(N(addr_out), uint64(0))
        local ok2, rv2 = pcall(function()
            return native.fcall_with_rax(fn, 0,
                N(addr_out), 0x4000, 3, 0x10, N(phys_addr), 0x4000)
        end)
        if not alive() then
            print(string.format("  +0x%05X: KILLED (flags=0x10)", test_off))
            return
        end
        if ok2 then
            local rv_val2 = N(rv2)
            local ma2 = rq(N(addr_out))
            if rv_val2 == 0 and ma2 and N(ma2) > 0 then
                print(string.format("  *** +0x%05X: rv=0 addr=%s flags=0x10 — MAPPING SUCCESS ***",
                    test_off, fmt(ma2)))
                found_map = true
                local peek2 = rd(N(ma2))
                print(string.format("  mapped[0] = 0x%X", peek2 or 0xDEAD))
                break
            end
        end
    end

    if not found_map then
        print(string.format("  tested %d offsets [0x%X-0x%X], no 6-arg map found", tested, scan_start, scan_end))
    end

    if not alive() then return end

    -- Try +0x15020 specifically with many flag combos
    print("")
    print("  retrying +0x15020 with various flags (6-arg, 7th arg = garbage r9 or stack)...")
    local flags_list = {0, 1, 2, 0x10, 0x12, 0x100, 0x412, 0x1000, 0x10000, 0x10002, 0x80000}
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
            elseif rv_val ~= 0xFFFFFFFF and rv_val ~= 0 then
                print(string.format("  flags=0x%X: rv=%d", flags, rv_val))
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
print("  libkernel handle: " .. string.format("0x%X", lk_handle))
print("  libkernel text: " .. fmt(lk_text) .. " sz=0x" .. string.format("%X", t_sz))
print("  unique functions found: " .. #unique_funcs)
print("  probed: " .. probed)
print("  interesting: " .. #interesting)
for _, f in ipairs(interesting) do
    print(string.format("    +0x%05X", f.offset))
end
print("  dead_at: " .. (dead_after and string.format("+0x%05X", dead_after) or "none"))
print("canary=" .. N(native.fcall_with_rax(stub, 20)))
print("=== 529b COMPLETE ===")
