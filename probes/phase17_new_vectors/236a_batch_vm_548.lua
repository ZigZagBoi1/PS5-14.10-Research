-- CRASH_CLASS: MODERATE
-- PROBE 236a: sys 533 object + sys 548 batch VM operations, recovered layout
--
-- Context: the 13.60 decompile in results/kernel_handlers/decompiled/ carries a
-- recovered ABI for 548 that no probe has ever used. Earlier tests (55b) sent
-- loose integers and got -1 for every code, which reads as "blocked" but was a
-- layout mismatch. The recovered contract is:
--
--   sys_533_args { unused, size, flags }             -> publishes a descriptor
--   sys_548_args { descriptor, flags, user_operations, count, user_processed }
--   batch_vm_operation_548 { address+0x00, offset+0x08, length+0x10,
--                            protection+0x18, memory_type+0x19, operation+0x1c }
--
-- 548 copies each 0x20-byte operation from the user array, bounds `operation` to
-- 0..4, and dispatches through a five-entry table whose bytes are outside the
-- captured image. The five blocks are: mapping (0xabd540 / validated 0xab8430),
-- deferred append (normalizes protection bit 2 to imply bit 1), protection
-- update through 0x2cbdb0 with range and overflow checks, a flexible mapping
-- form (flags |= 0x1000), and an unmap-style call. The visible checks require
-- 0x4000 alignment and reject protection bit 8; RWX (7) is not rejected by the
-- visible predicate. That makes 548 the only VM writer we have found that is not
-- mprotect, and the one place a W^X answer could come from.
--
-- This probe only asks whether the call is reached and what it does to a page we
-- already own. It does not try to execute anything.

print("=== PROBE 236a: 533 OBJECT + 548 BATCH VM OPS ===")
print("")

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
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function hexval(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X_%08X", h, l)
end

local sc20 = make_syscall(20)
local sc533 = make_syscall(533)
local sc547 = make_syscall(547)
local sc548 = make_syscall(548)
local sc674 = make_syscall(674)
local sc74 = make_syscall(74)
local sc477 = make_syscall(477)

local okpid, pidv = pcall(function() return sc20() end)
print("PID: " .. to_num(pidv))

-- ============================================================
-- [A] 533: create a page-aligned memory object
-- ============================================================
print("")
print("[A] 533 { unused, size, flags }")

local descriptors = {}
for _, sz in ipairs({ 0x4000, 0x10000 }) do
    for flags = 0, 3 do
        local okA, retA = pcall(function()
            return sc533(uint64(0), uint64(sz), uint64(flags))
        end)
        local r = to_num(retA)
        print(string.format("  size=0x%X flags=%d ret=%s", sz, flags, tostring(retA)))
        if okA and r > 0 and r < 0x10000 then
            descriptors[#descriptors + 1] = { d = r, size = sz, flags = flags }
        end
    end
end
print("  descriptor-shaped returns: " .. #descriptors)

-- ============================================================
-- [B] VM region oracle (674)
-- ============================================================
local STRIDE674 = 72
local MAXREC = 512
local vmbuf = memory.alloc(STRIDE674 * MAXREC + 0x100)

local function region_of(addr)
    local okv = pcall(function()
        return sc674(uint64(vmbuf), uint64(STRIDE674), uint64(MAXREC))
    end)
    if not okv then return nil, "call-failed" end
    local lo = get_hi_lo(addr)
    for i = 0, MAXREC - 1 do
        local base = vmbuf + i * STRIDE674
        local startq = safe_rq(base)
        if startq == nil then break end
        local sh, sl = get_hi_lo(startq)
        local endq = safe_rq(base + 8)
        local eh, el = get_hi_lo(endq)
        if sh == 0 and eh == 0 and sl == 0 and el == 0 then break end
        if sh == 0 and lo >= sl and lo < el then
            return safe_rd(base + 0x18), string.format("0x%X-0x%X", sl, el)
        end
    end
    return nil, "not-found"
end

-- ============================================================
-- [C] 548: one operation per call, code 0..4, protection 7
-- ============================================================
print("")
print("[C] 548 one 0x20-byte operation, protection=7 (RWX)")

local OPS = 0x100
local ops = memory.alloc(OPS)
local processed = memory.alloc(0x40)

local function clear_ops()
    for j = 0, OPS / 4 - 1 do safe_wd(ops + j * 4, 0) end
end

local function write_op(idx, addr, length, prot, memtype, operation)
    local base = ops + idx * 0x20
    safe_wq(base + 0x00, addr)
    safe_wq(base + 0x08, 0)
    safe_wq(base + 0x10, length)
    safe_wd(base + 0x18, prot + memtype * 0x100)
    safe_wd(base + 0x1C, operation)
end

local pages = {}
local anon = sc477(uint64(0), uint64(0x10000), uint64(0x33), uint64(0xFFFFFFFF), uint64(0xFFFFFFFF), uint64(0))
pages[#pages + 1] = { "anon", get_hi_lo(anon) }
local gpu = sc477(uint64(0), uint64(0x10000), uint64(0x33), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
pages[#pages + 1] = { "gpu", get_hi_lo(gpu) }

local descs = { { d = 0, size = 0x10000, flags = 0 } }
for i = 1, math.min(#descriptors, 2) do descs[#descs + 1] = descriptors[i] end

for di = 1, #descs do
    local d = descs[di]
    for op = 0, 4 do
        -- A fresh page per operation: an unmap-style block must not poison the
        -- next measurement, and a mapping block needs an address it can own.
        local pg = sc477(uint64(0), uint64(0x10000), uint64(0x33), uint64(0xFFFFFFFF), uint64(0xFFFFFFFF), uint64(0))
        local paddr = get_hi_lo(pg)
        if paddr and paddr ~= 0 then
            local p0, r0 = region_of(paddr)
            clear_ops()
            write_op(0, paddr, 0x4000, 7, 0, op)
            safe_wd(processed, 0xAAAAAAAA)
            local okC, retC = pcall(function()
                return sc548(uint64(d.d), uint64(0), uint64(ops), uint64(1), uint64(processed))
            end)
            local p1, r1 = region_of(paddr)
            print(string.format("    d=%s op=%d page=%s ret=%s processed=0x%X prot=%s->%s (%s)",
                tostring(d.d), op, hexval(pg), tostring(retC), safe_rd(processed) or 0,
                tostring(p0), tostring(p1), tostring(r1)))
            local mret = sc74(uint64(paddr), uint64(0x4000), uint64(7))
            local okr = pcall(function() return memory.read_dword(paddr) end)
            print(string.format("      mprotect(RWX)=%s readable=%s", tostring(mret), tostring(okr)))
        end
    end
end

-- ============================================================
-- [D] 547: the finer protection oracle (0x18-byte result)
-- ============================================================
print("")
print("[D] 547 { address, out } 0x18-byte region record")
local q = memory.alloc(0x100)
for j = 0, 0x3F do safe_wd(q + j * 4, 0) end
for _, pg in ipairs(pages) do
    local pname, paddr = pg[1], pg[2]
    if paddr and paddr ~= 0 then
        for j = 0, 0x3F do safe_wd(q + j * 4, 0) end
        local okD, retD = pcall(function()
            return sc547(uint64(paddr), uint64(q))
        end)
        print(string.format("  %s ret=%s start=%s end=%s word16=0x%X word20=0x%X",
            pname, tostring(retD), hexval(safe_rq(q)), hexval(safe_rq(q + 8)),
            safe_rd(q + 0x10) or 0, safe_rd(q + 0x14) or 0))
    end
end

print("")
print("=== PROBE 236a COMPLETE ===")
