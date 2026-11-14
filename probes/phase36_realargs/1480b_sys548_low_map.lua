-- CRASH_CLASS: MODERATE -- op 1 may be UNMAP and op 0 may be MAP. Every target is a page this
-- probe has just mapped and verified with 547, every call prints before it is made, and the
-- low-address MAP attempts are only ever queried with 547, never dereferenced.
-- PROBE 1480b: sys 548 ops 0, 1, 3, 4 with the 16 KiB alignment they actually require.
--
-- 1479d concluded "every op answers EINVAL for a valid entry" and that conclusion was an artefact
-- of the length: it used len=0x1000. 1479e then found the entry must be 0x4000-aligned in both
-- start and length, and 1480a used that to get op 2 working -- prot 1 and 3 round-trip and 547
-- confirms the change. So the whole op sweep in 1479d has to be redone at len=0x4000.
--
-- The one that matters is op 0. If op 0 is MAP with a caller-chosen address, then the question
-- is not "can I map somewhere" (mmap already does that) but "can I map where mmap refuses".
-- mmap refuses everything below its min address, and a user mapping at 0 is the precondition for
-- every kernel NULL-dereference exploit: the kernel faults, and the page it faults on is ours.
-- Phase [C] therefore asks 548 for pages at 0x0, 0x1000, 0x10000 and 0x40000 and reports only
-- what 547 says about them. Nothing at those addresses is ever read or written, so a refusal and
-- a silent success are both survivable.
--
-- -- prior art:
--   results/phase36_realargs/1480a_sys548_eboot_rwx_20261109_200355.txt (op 2 works at 16 KiB)
--   results/phase36_realargs/1479e_sys548_prot_matrix_20261109_195636.txt (16 KiB alignment rule)
--   results/phase36_realargs/1479d_sys548_map_unmap_20261109_195406.txt (the EINVAL sweep this redoes)
--   results/phase36_realargs/1479b_sys548_field_map_20261109_192622.txt (entry layout)
--   results/kernel_handlers/asm/sys_548.asm (PART B, RVA 0xabbe60)
--   docs/VM_LAYER_14_10.md section 6

print("=== PROBE 1480b: SYS 548 OPS 0 1 3 4 AT 16 KiB ===")

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

local sc548 = mk(548)
local sc477 = mk(477)
local sc547 = mk(547)

local ent = memory.alloc(0x40)
local rec = memory.alloc(0x20)
local cnt = memory.alloc(0x10)

local function set_entry(start, offset, len, prot, op)
    for i = 0, 0x38 do pcall(function() memory.write_byte(ent + i, 0) end) end
    pcall(function() memory.write_qword(ent + 0x00, uint64(string.format("0x%X", start))) end)
    pcall(function() memory.write_qword(ent + 0x08, uint64(string.format("0x%X", offset))) end)
    pcall(function() memory.write_qword(ent + 0x10, uint64(string.format("0x%X", len))) end)
    pcall(function() memory.write_dword(ent + 0x18, uint64(prot)) end)
    pcall(function() memory.write_byte(ent + 0x1C, op) end)
end

local function v548(tag)
    pcall(function() memory.write_dword(cnt, uint64(0xEEEEEEEE)) end)
    print(string.format("  -> %-46s", tag))
    local ok, rv = pcall(function()
        return sc548(uint64(0), uint64(0), uint64(ent), uint64(1), uint64(cnt), uint64(0))
    end)
    local r = -999
    if ok then r = N(rv) end
    local e = ""
    if r == -1 then e = es() end
    local p = N(memory.read_dword(cnt))
    print(string.format("     rv=%-5s %-24s processed=%d", tostring(r), e, p))
    return r, p
end

-- 547 never dereferences, so it is safe to ask about any address.
local function mapped(addr)
    local ok, rv = pcall(function() return sc547(uint64(addr), uint64(rec)) end)
    if not (ok and N(rv) == 0) then return false, nil, nil end
    local sl = N(memory.read_dword(rec + 0x00))
    local s  = N(memory.read_dword(rec + 0x04))
    local el = N(memory.read_dword(rec + 0x08))
    local e  = N(memory.read_dword(rec + 0x0C))
    local pr = N(memory.read_dword(rec + 0x10))
    return true, pr, sl + s * 4294967296, el + e * 4294967296
end

local function report(addr, tag)
    local ok, pr, s, e = mapped(addr)
    if not ok then
        print(string.format("     [%s] 547 -> not mapped", tag))
    else
        print(string.format("     [%s] 547 prot=%d start=%X end=%X", tag, pr, s, e))
    end
    return ok, pr
end

local function map_anon(len)
    local ok, rv = pcall(function()
        return sc477(uint64(0), uint64(len), uint64(3), uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
    end)
    if not ok then return nil end
    local v = rv
    if type(v) == "table" and v.tonumber then v = v:tonumber() end
    v = tonumber(v) or 0
    if v < 0x10000 then return nil end
    return v
end

-- ---------------------------------------------------------------- [A] prep
local A = map_anon(0x8000)
local D = map_anon(0x8000)
if not A or not D then
    print("[A] mmap failed")
    print("=== PROBE 1480b INCOMPLETE ===")
    return
end
print(string.format("[A] A=0x%X D=0x%X", A, D))
pcall(function() memory.write_dword(A, uint64(0x11112222)) end)
pcall(function() memory.write_dword(D, uint64(0x33334444)) end)
report(A, "A before")
report(D, "D before")

-- ---------------------------------------------------------------- [B] ops 0 1 3 4 on our pages
print("")
print("--- [B] ops 0, 1, 3, 4 with len 0x4000 on a page we own ---")
-- Op 2 is the known-good control: it must succeed here, or the whole sweep is meaningless.
set_entry(A, 0, 0x4000, 1, 2)
local ctl = v548("control op=2 prot=1")
report(A, "A after control")
if ctl ~= 0 then
    print("[B] the control failed; 548 is not accepting entries this run")
    print("=== PROBE 1480b INCOMPLETE ===")
    return
end
set_entry(A, 0, 0x4000, 3, 2)
v548("control op=2 prot=3 (restore)")
report(A, "A restored")

for _, op in ipairs({0, 3, 4}) do
    local rv = v548(string.format("op=%d prot=3 len=0x4000 on A", op))
    if rv == 0 then report(A, string.format("A after op=%d", op)) end
end

-- op 1 on D: if it is UNMAP the page goes away, which 547 will say.
local rv1 = v548("op=1 prot=0 len=0x4000 on D")
if rv1 == 0 then
    local still = select(1, mapped(D))
    report(D, "D after op=1")
    -- Read D only if 547 says it is still there; a read of an unmapped page is a SIGSEGV and
    -- pcall does not survive it.
    if still then print(string.format("[B] D reads %08X after op=1", N(memory.read_dword(D)))) end
else
    print("[B] op=1 refused; D untouched")
end

-- ---------------------------------------------------------------- [C] can op 0 map low?
-- mmap refuses below its min address. If op 0 is MAP and does not apply that floor, a page at 0
-- becomes possible. Nothing here is ever read or written: only 547 is asked.
print("")
print("--- [C] op 0 at addresses mmap refuses ---")
local LOWS = {0x0, 0x1000, 0x10000, 0x40000, 0x100000}
for i = 1, #LOWS do
    local a = LOWS[i]
    local ok0, pr0 = mapped(a)
    print(string.format("   [pre ] 0x%X mapped=%s prot=%s", a, tostring(ok0), tostring(pr0)))
    set_entry(a, 0, 0x4000, 3, 0)
    local rv = v548(string.format("op=0 MAP at 0x%X prot=3", a))
    if rv == 0 then
        report(a, string.format("0x%X after op=0", a))
    end
end

-- A second shape for the same question: prot 1, and the offset field set, in case the address is
-- taken from offset rather than start.
print("")
print("--- [C2] op 0 at 0x0 with the address in the offset field ---")
set_entry(0, 0x40000, 0x4000, 3, 0)
local rv2 = v548("op=0 start=0 offset=0x40000")
if rv2 == 0 then report(0x40000, "0x40000 after op=0 via offset") end

print("")
print("--- [C3] op 0 at a high address mmap will not give us ---")
set_entry(0x310000000, 0, 0x4000, 3, 0)
local rv3 = v548("op=0 MAP at 0x310000000")
if rv3 == 0 then report(0x310000000, "0x310000000 after op=0") end

print("")
local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("final canary: pid=%d (started %d)", final, PID))
print("=== PROBE 1480b COMPLETE ===")
