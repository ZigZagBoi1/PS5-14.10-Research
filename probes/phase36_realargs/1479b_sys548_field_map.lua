-- CRASH_CLASS: MODERATE -- 548 op handlers are undumped, so a variation that satisfies an op's
-- validation could make it act on the probe's own address space. Every call therefore uses
-- count=1, a 0x40-byte entry zone that is re-zeroed before each variation, and an address field
-- of 0 unless the variation is specifically the address test.
-- PROBE 1479b: map sys 548's 0x20-byte entry by single-field variation.
--
-- 1479a established the contract and that op 2 executes:
--   548(arg1, arg2=flag mask, arg3=entries, arg4=count, arg5=&processed)
--   count=0                       -> rv=0, processed=0, nothing touched
--   count=1, all-zero entry, op=0 -> rv=-1 EINVAL
--   count=1, all-zero entry, op=2 -> rv=0, processed=1     <-- op 2 accepts a null entry
--   count=1, all-zero entry, op=1/3/4/5 -> rv=-1 EINVAL
--   op=2 with addr=page len=0x1000 prot=3 written the way 1479a guessed -> EINVAL
-- So op 2 validates *something* that 1479a's guess got wrong, and the entry field offsets are
-- not yet known. The 13.60 body copies 0x20 bytes and reads the opcode at +0x1C; everything else
-- about the layout has to be measured.
--
-- Method: with op=2 fixed at +0x1C and every other byte zero (the shape that is known to return 0),
-- set exactly one byte to 0xFF at a time and record the rv. A byte the handler never reads cannot
-- change the answer; a byte it does read either still passes (0xFF may be a legal value) or flips
-- the call to EINVAL, and the set of flipping offsets is the field map. The same is then done with
-- a single 0xFFFFFFFF dword per offset, which catches fields that are only validated as ranges.
-- A final section places a page-aligned address at each candidate qword offset with len 0x1000 and
-- prot 3 at each candidate dword offset, looking for the one combination that returns 0 with
-- processed=1 — that is the "map my page" shape if one exists.
--
-- -- prior art:
--   results/phase36_realargs/1479a_sys548_batch_contract_20261109_192503.txt (contract + op 2 executes)
--   results/kernel_handlers/asm/sys_548.asm (PART B, RVA 0xabbe60; copyin 0x20 at 0xabbf86;
--       opcode at [rbp-0x7c] = entry+0x1C; cmp ecx,4; table 0x18dbf54; arg5 written at 0xabc355)
--   results/phase17_new_vectors/55b_*.lua (the old opcode-in-arg1 reading, superseded)
--   docs/ARG23_CLASSES_14_10.md:34

print("=== PROBE 1479b: SYS 548 ENTRY FIELD MAP ===")

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

local PROT_RW  = 3
local MAP_ANON = 0x1000

local page = N(sc477(uint64(0), uint64(0x4000), uint64(PROT_RW), uint64(MAP_ANON),
                     uint64(0xFFFFFFFF), uint64(0)))
print(string.format("[0] page=0x%X", page))
if page <= 0 or page == 0xFFFFFFFFFFFFFFFF then
    print("[!] mmap failed")
else
    for off = 0, 0x3000, 4 do
        pcall(function() memory.write_dword(page + off, uint64(0x22220000 + off)) end)
    end

    local ent = memory.alloc(0x40)
    local out = memory.alloc(0x20)
    local rec = memory.alloc(0x20)

    local function zero_entry()
        for i = 0, 0x38 do pcall(function() memory.write_byte(ent + i, 0) end) end
    end
    local function set_op(op) pcall(function() memory.write_byte(ent + 0x1C, op % 256) end) end

    local function call548(count, tag)
        pcall(function() memory.write_dword(out, uint64(0xEEEEEEEE)) end)
        local ok, v = pcall(function()
            return N(sc548(uint64(0), uint64(0), uint64(ent), uint64(count), uint64(out), uint64(0)))
        end)
        local oc = "?"
        local ok2, v2 = pcall(function() return N(memory.read_dword(out)) end)
        if ok2 then oc = string.format("%d", v2 % 4294967296) end
        if ok then
            print(string.format("  %-46s rv=%-4d %-22s processed=%s", tag, v,
                (v == -1) and es() or "", oc))
        else
            print(string.format("  %-46s EXC processed=%s", tag, oc))
        end
        return v
    end

    -- a 547-based liveness check so an op that touches our page is visible
    local function page_state(tag)
        pcall(function() for i = 0, 0x18, 4 do memory.write_dword(rec + i, uint64(0)) end end)
        pcall(function() memory.write_dword(rec, 0x20) end)
        local ok, v = pcall(function()
            return N(sc547(uint64(page), uint64(rec), uint64(0), uint64(0), uint64(0), uint64(0)))
        end)
        local pr = -1
        if ok and v == 0 then pr = N(memory.read_dword(rec + 0x10)) end
        local okr, val = pcall(function() return N(memory.read_dword(page)) end)
        print(string.format("  [%s] 547 rv=%d prot=%d dword0 ok=%s", tag, v, pr, tostring(okr)))
        return pr
    end

    print("")
    print("--- [A] reference: op 2 with an all-zero entry, count 1 ---")
    zero_entry(); set_op(2)
    call548(1, "all zero, op=2")
    page_state("after")

    print("")
    print("--- [B] single byte 0xFF at each offset, op=2, rest zero ---")
    local flip = {}
    for off = 0, 0x1B do
        zero_entry(); set_op(2)
        pcall(function() memory.write_byte(ent + off, 0xFF) end)
        local rv = call548(1, string.format("byte +0x%02X = 0xFF", off))
        if rv ~= 0 then flip[#flip + 1] = string.format("+0x%02X", off) end
    end
    print(string.format("  bytes that change the answer: %s",
        (#flip > 0) and table.concat(flip, " ") or "(none)"))

    print("")
    print("--- [C] single dword 0xFFFFFFFF at each offset, op=2 ---")
    local dflip = {}
    for off = 0, 0x1C, 4 do
        zero_entry(); set_op(2)
        pcall(function() memory.write_dword(ent + off, uint64(0xFFFFFFFF)) end)
        local rv = call548(1, string.format("dword +0x%02X = 0xFFFFFFFF", off))
        if rv ~= 0 then dflip[#dflip + 1] = string.format("+0x%02X", off) end
    end
    print(string.format("  dwords that change the answer: %s",
        (#dflip > 0) and table.concat(dflip, " ") or "(none)"))

    print("")
    print("--- [D] address at each candidate qword offset, len/prot zero ---")
    for _, aoff in ipairs({0x00, 0x08, 0x10, 0x18}) do
        zero_entry(); set_op(2)
        pcall(function() memory.write_qword(ent + aoff, uint64(page)) end)
        call548(1, string.format("qword +0x%02X = page", aoff))
    end

    print("")
    print("--- [E] len 0x1000 at each candidate qword offset ---")
    for _, loff in ipairs({0x00, 0x08, 0x10, 0x18}) do
        zero_entry(); set_op(2)
        pcall(function() memory.write_qword(ent + loff, uint64(0x1000)) end)
        call548(1, string.format("qword +0x%02X = 0x1000", loff))
    end

    print("")
    print("--- [F] prot 3 at each candidate dword offset ---")
    for _, poff in ipairs({0x00, 0x04, 0x08, 0x0C, 0x10, 0x14, 0x18}) do
        zero_entry(); set_op(2)
        pcall(function() memory.write_dword(ent + poff, uint64(3)) end)
        call548(1, string.format("dword +0x%02X = 3", poff))
    end

    print("")
    print("--- [G] the plausible map shapes: addr+len(+prot) combinations, op=2 ---")
    local SHAPES = {
        {0x00, 0x08, -1,  "addr+0x00 len+0x08"},
        {0x08, 0x10, -1,  "addr+0x08 len+0x10"},
        {0x00, 0x08, 0x10, "addr+0x00 len+0x08 prot+0x10"},
        {0x08, 0x10, 0x18, "addr+0x08 len+0x10 prot+0x18"},
        {0x08, 0x10, 0x14, "addr+0x08 len+0x10 prot+0x14"},
        {0x00, 0x10, 0x08, "addr+0x00 len+0x10 prot+0x08"},
    }
    for _, s in ipairs(SHAPES) do
        zero_entry(); set_op(2)
        pcall(function() memory.write_qword(ent + s[1], uint64(page)) end)
        pcall(function() memory.write_qword(ent + s[2], uint64(0x1000)) end)
        if s[3] >= 0 then pcall(function() memory.write_dword(ent + s[3], uint64(PROT_RW)) end) end
        call548(1, string.format("op=2 %s", s[4]))
    end
    page_state("after G")

    print("")
    print("--- [H] count 2 and 3 with op=2 all-zero entries ---")
    zero_entry(); set_op(2)
    call548(2, "count=2 op=2 zero")
    call548(3, "count=3 op=2 zero")
    print("    (entry stride 0x20, so entry 2 starts at ent+0x20 = the tail of the zone)")

    print("")
    print("--- [I] op field beyond 4: is the bound really 4? ---")
    for op = 5, 8 do
        zero_entry(); set_op(op)
        call548(1, string.format("op=%d", op))
    end
    page_state("final")
end

print("")
local canary = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("final canary: pid=%d", canary))
print("=== PROBE 1479b COMPLETE ===")
