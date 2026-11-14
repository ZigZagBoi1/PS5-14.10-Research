-- CRASH_CLASS: MODERATE
-- PROBE 1524a: syscall 570 budget_get -- the unclamped record loop
--
-- -- prior art:
--   docs/sysent-names-13.60.csv -- 570,budget_get,0x266350; the thunk at VA 0x8ac26350 is
--     "jmp 0xffffffff8af67610", so the body is 0xffffffff8af67610..0xffffffff8af67900.
--   docs/SYSENT_PRESENCE_14_10.md -- 570 has never been measured; the 532-676 sweeps skipped it
--     (578a run 3 skip list 570/571/573/609/614/621) and the 1342a arg1 sweep covered 131 of 145
--     numbers without it. probes/phase17_new_vectors/172a_sysctlbyname.lua called 570 as
--     "sysctlbyname", which the 13.60 table contradicts -- this is the first real call shape.
--   agent://CopyoutSource (2026-11-09) flagged this function: the budget_get record loop
--     writes 24-byte records into a 0x180-byte frame area bounded by the caller count AND
--     [obj+0x34]; if both are large the loop overruns the stack before the copyout runs.
--   .local/dx.py 0xffffffff8af67610 -- the body read in full for this probe.
--
-- The decoded shape (13.60):
--   rbx = uap.  uap[0] = index/type, uap[1] = user output, uap[2] = user pointer to a 4-byte count.
--   entry:  rdi = [td+0x140]; call 0x8afc8f90; if it returns 0 -> return 0x4e (ENOSYS 78).
--   copyin 4 bytes from uap[2] into [rbp-0x18c]; if count <= 0 -> return 0x16 (EINVAL 22).
--   object = 0x8ad59ee0(global, uap[0], 0x2000, &tmp) with an index gate uap[0] <= 0xffff.
--   object != NULL  -> PATH A, the loop at 0x8af67700:
--        stride 0x18, copies 24 bytes per iteration straight out of [obj+8], bounded by
--        min(caller_count, [obj+0x34]).  Destination base rbp-0x180; the stack canary is at
--        rbp-0x30, so exactly 14 records fit and record 14 corrupts the canary.  There is NO
--        clamp to 14 on this path.
--   object == NULL  -> PATH B at 0x8af677c4 requires uap[0] in {-6,-5,-4,-3,-2} and then
--        eax = min(count, 14) -- correctly clamped -- and fills from a static kernel table.
--   both paths: copyout(uap[1], rbp-0x180, count_used*0x18).
--
-- UPDATE 2026-11-09 (static, before sending): the entry gate is now decoded.
--   .local/dx.py 0xffffffff8afc8f90 ->  mov rax,[rdi+0x60]; shr rax,0x3e; and eax,1; ret
--   i.e. it returns BIT 62 of cred+0x60, and this process is known NOT to have that bit
--   (docs: 535/536/563-566 and 618/646/671 are gated on the same bit; 587 reads
--   cred+0x0C = 0x20000000 and cred+0x60 = 0). So 570 should answer ENOSYS(78) immediately.
--   This probe is therefore reduced to a confirmation sweep: one call per index, no record
--   dump, because a PATH A object is unreachable behind that gate.
--
-- This probe stays at count <= 13, one below the canary, so it cannot corrupt the stack. It
-- answers three things: whether the entry gate passes for a game process at all, whether any
-- index yields a PATH A object, and what the first thirteen free-text records contain -- if
-- [obj+0x34] overstates its array, the tail of the copyout is kernel heap we never owned.

print("=== PROBE 1524a: SYS 570 budget_get ===")
print("")

local function N(v)
    if type(v) == "number" then return v end
    if type(v) == "table" and v.tonumber then
        local ok, n = pcall(function() return v:tonumber() end)
        if ok and n then return n end
    end
    local ok, n = pcall(function() return tonumber(v) end)
    if ok and n then return n end
    return 0
end
local function addr_of(u)
    local n = N(u)
    if n >= 0x10000 and n < 0x8000000000 then return n end
    return nil
end
local function mk(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) % 4294967296 end
    return nil
end
local function wd(a, v)
    return pcall(function() memory.write_dword(a, uint64(v)) end)
end
local function fmt(v)
    if v == nil then return "nil" end
    local n = N(v)
    if n < 0 then n = n + 2 ^ 64 end
    return string.format("0x%X", n)
end
local function sid(v)
    local n = N(v)
    if n < 0 then n = n + 2 ^ 64 end
    return n
end
local function errs()
    local ok, s = pcall(function() return get_error_string() end)
    if ok and type(s) == "string" then return s end
    return "errno?"
end
local function self_pid()
    local ok, v = pcall(function() return getpid() end)
    if ok then return N(v) end
    return -1
end

local PID0 = self_pid()
print("pid=" .. tostring(PID0))
local sc = mk(570)

-- ============================================================
-- [A] does the entry gate pass?
-- ============================================================
print("")
print("[A] entry gate + argument sanity (count = 1, safely inside the frame)")
local out = memory.alloc(0x400)
local outa = addr_of(out)
local cnt = memory.alloc(0x10)
local cnta = addr_of(cnt)
if not outa or not cnta then print("  FAIL: buffers"); return end
print("  out=" .. fmt(outa) .. " count_ptr=" .. fmt(cnta))

local function one(idx, n, label)
    wd(cnta, n)
    print("  " .. label .. "  idx=" .. tostring(idx) .. " count=" .. n .. " -> calling")
    local ok, rv = pcall(function() return sc(uint64(idx), uint64(outa), uint64(cnta), uint64(0), uint64(0), uint64(0)) end)
    if not ok then
        print("     pcall raised: " .. tostring(rv))
        return nil
    end
    local r = N(rv)
    local used = rd(cnta)
    print("     rv=" .. tostring(r) .. " (0x" .. string.format("%X", sid(r)) .. ") " .. errs() ..
          "  count_field=" .. tostring(used))
    return r
end

local rv0 = one(0, 1, "[A1] idx 0")
if rv0 == nil then
    print("VERDICT: the call itself raised; nothing learned.")
    return
end

-- ============================================================
-- [B] the clamped PATH B: idx must be in {-6,-5,-4,-3,-2}
-- ============================================================
print("")
print("[B] PATH B indices (static-table copy, clamped to 14)")
for _, idx in ipairs({ -6, -5, -4, -3, -2 }) do
    one(idx, 3, "[B" .. tostring(idx + 7) .. "]")
end

-- ============================================================
-- [C] PATH A candidates: only meaningful if the bit-62 gate passed
-- ============================================================
print("")
print("[C] small indices (count = 1) -- a non-78 answer would mean the gate passed")
local hits = {}
for idx = 0, 6 do
    local r = one(idx, 1, "[C" .. idx .. "]")
    if r ~= nil and r ~= 78 then hits[#hits + 1] = idx end
end
print("  indices that did not answer ENOSYS: " .. (#hits > 0 and table.concat(hits, ",") or "none"))

if #hits == 0 then
    print("")
    print("VERDICT: sys 570 is gated on cred+0x60 bit 62, which a game process does not have.")
    print("         ENOSYS on every index; the unclamped record loop is unreachable.")
else
    print("")
    print("VERDICT: the gate PASSED for index " .. hits[1] .. " -- escalate to the record dump.")
end

print("")
print("pid_after=" .. tostring(self_pid()) .. " (was " .. tostring(PID0) .. ")")
print("")
print("=== PROBE 1524a COMPLETE ===")
