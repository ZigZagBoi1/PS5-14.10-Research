-- CRASH_CLASS: MODERATE
-- PROBE 1509b: does 548 op 3 grant PROT_EXEC on an anonymous page?
--
-- Context: 548 op 2 (protect) refuses every protection carrying bit 0x4 or 0x8
-- with EACCES(13) -- 1480a, 1481g -- and mmap clamps prot 7 back to 3 (1496a).
-- Those are two separate filters on two separate paths.
--
-- op 3 is a THIRD path: case 0x8b47c11e builds its own arguments and calls the
-- internal mapper directly (fd forced to -1, offset 0, flags = entry[+0x08] |
-- 0x1000).  Nobody has ever asked op 3 for a protection with bit 0x4 set.
-- 1481g's prot-4 refusal is evidence about op 2 only.  If op 3 hands the
-- protection straight to the internal mapper without the op-2 whitelist, an
-- anonymous RWX page exists and W^X -- this project's oldest wall -- is over.
--
-- This probe only asks and reads back 547.  It deliberately does NOT execute
-- anything: an NX fetch fault kills the caller (1459a), so the execution test
-- belongs in a follow-up once the protection readback is known.
--
-- 0x10 / 0x20 / 0x33 are skipped on purpose: 1481g measured prot 0x10 on an
-- anonymous page killing or wedging the process (results/.../1481g_*_202102.txt).
--
-- prior art: results/phase36_realargs/1508a_sys548_map_fixed_20261109_224934.txt
--            results/phase36_realargs/1481g_sys548_prot_full_matrix_20261109_202102.txt
--            results/phase36_realargs/1480a_sys548_eboot_rwx_20261109_200355.txt
--            results/phase36_realargs/1496a_sys548_prot6_exec_20261109_220652.txt

print("=== PROBE 1509b: 548 op3 PROTECTION MATRIX (anonymous) ===")
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
for _, n in ipairs({4, 20, 73, 477, 547, 548}) do mk[n] = make_syscall(n) end

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

-- 547: {start_lo, start_hi, end_lo, end_hi, prot@0x10, flags@0x14}
local rec = memory.alloc(0x40)
local function prot_of(va)
    local i
    for i = 0, 0x3C, 4 do wr(rec + i, 0) end
    local rv = call(mk[547], uint64(va), uint64(rec), uint64(0), uint64(0), uint64(0), uint64(0))
    if sgn(rv) ~= 0 then return -1, -1, -1 end
    return rd(rec + 0x10), rd(rec + 0x00) + rd(rec + 0x04) * 4294967296,
           rd(rec + 0x08) + rd(rec + 0x0C) * 4294967296
end

-- 548 op 3 entry builder
local ent = memory.alloc(0x40)
local done = memory.alloc(8)
local function map_fixed(va, len, prot)
    local i
    for i = 0, 0x3F, 4 do wr(ent + i, 0) end
    wr(ent + 0x00, va % 4294967296)
    wr(ent + 0x04, math.floor(va / 4294967296))
    wr(ent + 0x10, len % 4294967296)
    wr(ent + 0x14, math.floor(len / 4294967296))
    wr(ent + 0x18, prot)
    wr(ent + 0x1C, 3)          -- op 3 = anonymous map
    wr(done, 0xEEEEEEEE)
    local rv = call(mk[548], uint64(0), uint64(0x10), uint64(ent), uint64(1), uint64(done), uint64(0))
    return sgn(rv), rd(done)
end

-- ------------------------------------------------------------------
-- [A] reserve the window we will MAP_FIXED into, so every op 3 call
--     targets an address the process already owns
-- ------------------------------------------------------------------
print("--- [A] reserve a 0x60000 window ---")
local A = sgn(call(mk[477], uint64(0), uint64(0x60000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
if A < 0x10000 or A > 0x8000000000 then
    print(string.format("  mmap failed (rv=0x%X) -- INCOMPLETE", A))
    return
end
print(string.format("  A=0x%X len=0x60000", A))
local p, s0, e0 = prot_of(A)
print(string.format("  547(A) prot=%d start=0x%X end=0x%X", p, s0, e0))

-- ------------------------------------------------------------------
-- [B] op 3 with each protection, MAP_FIXED onto its own 16 KiB slot
-- ------------------------------------------------------------------
print("")
print("--- [B] op 3 with each protection (0x10/0x20/0x33 excluded: lethal on anon per 1481g) ---")
local order = {0, 1, 2, 3, 4, 5, 6, 7}
local exec_seen = false
for idx, prot in ipairs(order) do
    local va = A + (idx - 1) * 0x4000
    print(string.format("  [B%d] op3 prot=%d at 0x%X", idx, prot, va))
    local rv, proc = map_fixed(va, 0x4000, prot)
    print(string.format("       rv=0x%X processed=%d", rv, proc))
    local p2, s2, e2 = prot_of(va)
    print(string.format("       547 prot=%d start=0x%X end=0x%X", p2, s2, e2))
    -- calibrate the page so a report of "no write" is meaningful.
    -- A read of a page with prot 0 or an exec-only protection FAULTS and takes
    -- the loader with it (1459a), so only touch pages the readback says are 1/2/3.
    if p2 == 1 or p2 == 2 or p2 == 3 then
        wr(va, 0x5A5A0000 + prot)
        local back = rd(va)
        print(string.format("       store/read 0x%08X -> 0x%08X %s",
            0x5A5A0000 + prot, back, (back == 0x5A5A0000 + prot) and "(writable)" or "(NOT writable)"))
    else
        print(string.format("       prot=%d readback -- skipping the store/read (a read could fault)", p2))
    end
    if p2 >= 0 and math.floor(p2 / 4) % 2 == 1 then
        exec_seen = true
        print("       *** 547 REPORTS BIT 0x4 SET -- PROT_EXEC GRANTED ON AN ANON PAGE ***")
    end
end

-- ------------------------------------------------------------------
-- [C] verdict
-- ------------------------------------------------------------------
print("")
if exec_seen then
    print("VERDICT: 548 op 3 grants PROT_EXEC. W^X is over -- run the execution test next.")
else
    print("VERDICT: no protection with bit 0x4 survived the readback; op 3 filters like op 2.")
end
print("final canary pid=" .. tonumber(to_num(mk[20]())))
print("=== PROBE 1509b COMPLETE ===")
