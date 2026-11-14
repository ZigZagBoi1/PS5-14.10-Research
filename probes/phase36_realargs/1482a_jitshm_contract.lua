-- CRASH_CLASS: LOW -- only calls 533/534 with scalar and descriptor arguments, plus a 548
-- control that is already known to work. No address is dereferenced by us.
-- PROBE 1482a: jitshm_create / jitshm_alias with the contract the 13.60 body actually has
--
-- 251a called 533 with four sizes and three flag values and recorded -1 for all of them, but
-- never printed errno, so the refusal was never classified. The 13.60 body at 0xffffffff8b0c5880
-- says the contract is much narrower than 251a assumed:
--
--   uap[1] = size   must be 16 KiB aligned   (test r12d, 0x3fff / jne EINVAL)
--   uap[2] = flags  must have no bit outside 0x37 (test r15d, 0xffffffc8 / jne EINVAL)
--   uap[0]          never read
--
-- so 0x4000 with flags 0 was already a legal shape, which means the -1 came from something later:
-- either the two credential predicates at entry (0x8afc95c0 / 0x8afc9620, where both failing
-- returns EPERM 1), the vm_object allocator 0x8ae1da60 (returning 0 gives ENOMEM 12), or the
-- 68 MB budget check (cmp r14, 0x4100000). Flags bit 2 is the execute request, and the body only
-- asks 0x8afc9540 / 0x8afc9560 whether it is allowed when that bit is set - which is why an
-- accepted 0x4 would be a JIT page, the one protection 548 and mprotect both refuse.
--
-- This probe walks the legal flag space with errno printed, so the refusal class is known:
-- EPERM means a credential gate, EINVAL means the shape is still wrong, ENOSYS means the slot is
-- absent on 14.10, ENOMEM means the allocator refused. Any positive return is a handle and is
-- fed straight to 534 in the same run.
--
-- -- prior art:
--   results/phase17_new_vectors/251a_jitshm_20261021_153538.txt (four sizes, three flags, no errno)
--   results/kernel_handlers/asm/sys_533.asm (thunk 0x265cf0 -> 0x8b0c5880)
--   docs/DEAD_ENDS.md (jitshm bullet)
--   results/phase36_realargs/1481g_sys548_prot_full_matrix_20261109_202017.txt (prot 4 refused)

print("=== PROBE 1482a: JITSHM CONTRACT ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

local sc533 = mk(533)
local sc534 = mk(534)

local function call6(sc, a1, a2, a3, a4, a5, a6)
    local ok, rv = pcall(function()
        return sc(uint64(a1), uint64(a2), uint64(a3), uint64(a4), uint64(a5), uint64(a6))
    end)
    if not ok then return -999 end
    return N(rv)
end

local function rep(rv)
    if rv == -999 then return "EXC" end
    return string.format("%d %s", rv, es())
end

-- [A] control: 548 op 2 is known to work from this process, so a healthy control proves the
-- following negatives are refusals and not a sick interpreter.
print("")
print("--- [A] control: 548 op 2 on the device window ---")
local ent = memory.alloc(0x40)
local cnt = memory.alloc(0x10)
local function set_entry(start, len, prot, op)
    for i = 0, 0x38 do pcall(function() memory.write_byte(ent + i, 0) end) end
    pcall(function() memory.write_qword(ent + 0x00, uint64(string.format("0x%X", start))) end)
    pcall(function() memory.write_qword(ent + 0x10, uint64(string.format("0x%X", len))) end)
    pcall(function() memory.write_dword(ent + 0x18, uint64(prot)) end)
    pcall(function() memory.write_byte(ent + 0x1C, op) end)
end
set_entry(0xF00004000, 0x4000, 3, 2)
local ctl = call6(mk(548), 0, 0, ent, 1, cnt, 0)
print(string.format("[A] 548 op2 prot 3 -> %s (expect 0)", rep(ctl)))

-- [B] the legal flag space at a legal size
print("")
print("--- [B] 533(arg1=0, size 0x4000, flags) ---")
local FLAGS = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x10, 0x20, 0x11, 0x14, 0x24, 0x34, 0x37}
local handles = {}
for _, f in ipairs(FLAGS) do
    print(string.format("  533(0, 0x4000, 0x%X) -> %s", f, rep(call6(sc533, 0, 0x4000, f, 0, 0, 0))))
end

-- [C] is arg1 the size and arg2 the flags instead?
print("")
print("--- [C] the other argument placement, and other sizes ---")
for _, f in ipairs({0x0, 0x4, 0x24}) do
    print(string.format("  533(0x4000, 0x%X, 0) -> %s", f, rep(call6(sc533, 0x4000, f, 0, 0, 0, 0))))
end
for _, sz in ipairs({0x4000, 0x10000, 0x40000, 0x400000}) do
    print(string.format("  533(0, 0x%X, 0x4) -> %s", sz, rep(call6(sc533, 0, sz, 0x4, 0, 0, 0))))
    print(string.format("  533(0, 0x%X, 0x0) -> %s", sz, rep(call6(sc533, 0, sz, 0x0, 0, 0, 0))))
end

-- [D] if any create returned a handle, try to map it
print("")
print("--- [D] 534 on whatever 533 returned ---")
local got = 0
for _, f in ipairs(FLAGS) do
    local rv = call6(sc533, 0, 0x4000, f, 0, 0, 0)
    if rv > 0 and rv < 0x100000 then
        got = got + 1
        handles[#handles + 1] = rv
        print(string.format("  533 flags 0x%X -> handle %d", f, rv))
        if got >= 4 then break end
    end
end
if got == 0 then
    print("  no handle was produced by any legal flag value")
else
    for _, h in ipairs(handles) do
        print(string.format("  534(%d, 0) -> %s", h, rep(call6(sc534, h, 0, 0, 0, 0, 0))))
        print(string.format("  534(%d, 3) -> %s", h, rep(call6(sc534, h, 3, 0, 0, 0, 0))))
    end
end

-- [E] 534 against descriptors we know exist, in case it takes a real fd rather than a handle
print("")
print("--- [E] 534 on a live socket and on 0/1/2 ---")
local sp = memory.alloc(0x10)
local spok = pcall(function() return mk(135)(uint64(1), uint64(1), uint64(0), uint64(sp), uint64(0), uint64(0)) end)
local fd0 = nil
pcall(function() fd0 = N(memory.read_dword(sp)) end)
for _, fdv in ipairs({0, 1, 2}) do
    print(string.format("  534(%d, 0) -> %s", fdv, rep(call6(sc534, fdv, 0, 0, 0, 0, 0))))
end
if spok and fd0 then
    print(string.format("  534(socket %d, 0) -> %s", fd0, rep(call6(sc534, fd0, 0, 0, 0, 0, 0))))
end

print("")
local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("final canary: pid=%d (started %d)", final, PID))
print("=== PROBE 1482a COMPLETE ===")
