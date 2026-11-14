-- CRASH_CLASS: MODERATE -- 548's op handlers are outside every dumped region, so an unknown op
-- with a non-null address field can legitimately unmap or reprotect the probe's own page. Every
-- entry therefore starts all-zero, the count starts at 1, and the address field is only filled
-- after the zero-entry shape has returned, so each escalation is a separate observable line.
-- PROBE 1479a: sys 548 is a BATCH VM call, not an opcode-in-arg1 call — measure the real contract.
--
-- Why this is unmeasured. Every earlier probe (55b, and the arg2/arg3 class sweeps) passed the
-- operation code in arg1 and read the -1/processed=0 answer as "548 refuses everything". The 13.60
-- body says otherwise. At RVA 0xabbe60:
--   0xabbe85  mov r13d, [rsi+0x18]        ; arg4 = COUNT
--   0xabbe89  test r13d, r13d / js ...     ; negative count takes the list-drain path
--   0xabbeac  test dword [rbx+0x8], ecx    ; arg2 is a FLAG MASK, tested against
--                                          ; 0xe0bffb6f + (byte[proc+0xc81] ? 0x20000000 : 0)
--   0xabbf68  mov r12, [rbx+0x10]          ; arg3 = ENTRY ARRAY
--   0xabbf7e  add r12, r14                 ; r14 = index * 0x20
--   0xabbf86  mov edx, 0x20 / call copyin  ; 0x20 bytes per entry, from arg3 + i*0x20
--   0xabbfa2  mov ecx, [rbp-0x7c]          ; dword at entry +0x1C = OPCODE
--   0xabbfd8  cmp ecx, 4 / ja fail         ; opcodes 0..4
--   0xabbfe3  lea rdx, [0x18dbf54] / movsxd rcx,[rdx+rcx*4] / jmp rcx   ; 5-way table
--   0xabc355  mov rdi, [rbx+0x20] / call 0x259790   ; arg5 = out count, written at the end
-- With arg4 = 0 the function returns 0 without touching anything, which is exactly the rv=0 that
-- 1343a recorded when arg2 happened to be a pointer whose low bits missed the flag mask. So 548
-- has never been called with a non-zero count, and the five op bodies are in `0x18dbf54`'s target
-- region, which is outside kernel_text.bin, kernel_data.bin and sysent_area.bin -- they cannot be
-- decoded statically, they have to be measured.
--
-- Why it matters. 1450a measured that munmap on 14.10 is NOT stock: it removes the whole vm_map_entry
-- containing the address instead of splitting it. A rewritten VM layer with a batch entry point that
-- parses five caller-controlled fields per element is the most direct place a wrong check could sit.
--
-- -- prior art:
--   results/kernel_handlers/asm/sys_548.asm (PART B, body at RVA 0xabbe60, copyin at 0x259280)
--   docs/ARG1_CLASSES_14_10.md:57 (548 -> 0 for every class)
--   docs/ARG23_CLASSES_14_10.md:34 (548 -> 0 when arg2 is a mapped pointer, EINVAL otherwise)
--   results/phase17_new_vectors/55b_sys548_batch_vm.lua (-1/processed=0, opcode in arg1)
--   results/phase36_realargs/1450a_munmap_semantics_20261109_172529.txt (entry-scoped munmap)

print("=== PROBE 1479a: SYS 548 BATCH VM CONTRACT ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function hex(v) v = v % 4294967296 return string.format("%08X", v) end

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
local sc73  = mk(73)

local PROT_RW  = 3
local MAP_ANON = 0x1000

-- ---------------------------------------------------------------- the page we will point at
local page = N(sc477(uint64(0), uint64(0x4000), uint64(PROT_RW), uint64(MAP_ANON),
                     uint64(0xFFFFFFFF), uint64(0)))
print(string.format("[0] mmap page=0x%X", page))
if page <= 0 or page == 0xFFFFFFFFFFFFFFFF then
    print("[!] mmap failed; nothing to test")
else
    for off = 0, 0x3000, 4 do
        pcall(function() memory.write_dword(page + off, uint64(0x11110000 + off)) end)
    end
    print("[0] page filled with 0x1111xxxx markers")

    -- a 0x40-byte zone for entries, zeroed
    local ent = memory.alloc(0x40)
    for i = 0, 0x38, 4 do pcall(function() memory.write_dword(ent + i, uint64(0)) end) end
    local out = memory.alloc(0x20)
    for i = 0, 0x18, 4 do pcall(function() memory.write_dword(out + i, uint64(0)) end) end

    local rec = memory.alloc(0x40)
    local function prot_of(addr)
        pcall(function() for i = 0, 0x38, 4 do memory.write_dword(rec + i, uint64(0)) end end)
        pcall(function() memory.write_dword(rec, 0x40) end)
        local ok, v = pcall(function()
            return N(sc547(uint64(addr), uint64(rec), uint64(0), uint64(0), uint64(0), uint64(0)))
        end)
        if not ok then return -2, 0 end
        if v ~= 0 then return v, 0 end
        return v, N(memory.read_dword(rec + 0x10))
    end

    local function page_intact(tag)
        local ok, v = pcall(function() return N(memory.read_dword(page)) end)
        local p2, pr = prot_of(page)
        print(string.format("    %s: page dword0 ok=%s val=0x%s | 547 rv=%d prot=%d",
            tag, tostring(ok), hex(ok and v or 0), p2, pr))
    end

    local function call548(arg1, flags, count, tag)
        -- every field of the entry zone is rewritten before each call so nothing carries over
        local ok, v = pcall(function()
            return N(sc548(uint64(arg1), uint64(flags), uint64(ent), uint64(count), uint64(out),
                           uint64(0)))
        end)
        local oc = -1
        local ok2, v2 = pcall(function() return N(memory.read_dword(out)) end)
        if ok2 then oc = v2 % 4294967296 end
        if ok then
            print(string.format("    %-34s rv=%d %s out=%s",
                tag, v, (v == -1) and es() or "", tostring(oc)))
        else
            print(string.format("    %-34s EXC out=%s", tag, tostring(oc)))
        end
        return v
    end

    print("")
    print("--- [A] baseline: count 0 must return 0 and do nothing ---")
    page_intact("before")
    call548(0, 0, 0, "count=0 flags=0")
    page_intact("after")

    print("")
    print("--- [B] count 1, all-zero entry (op=0, addr=0, len=0) ---")
    call548(0, 0, 1, "zero entry count=1")
    page_intact("after")

    print("")
    print("--- [C] op byte at entry+0x1C, everything else zero ---")
    for op = 1, 5 do
        pcall(function() memory.write_dword(ent + 0x1C, uint64(op)) end)
        local ok = call548(0, 0, 1, string.format("op=%d addr=0 len=0", op))
        pcall(function() memory.write_dword(ent + 0x1C, uint64(0)) end)
    end

    print("")
    print("--- [D] op 0..4 with addr=our page, len=0x1000, prot=3 ---")
    for op = 0, 4 do
        pcall(function() memory.write_dword(ent + 0x1C, uint64(op)) end)
        pcall(function() memory.write_qword(ent + 0x00, uint64(page)) end)
        pcall(function() memory.write_qword(ent + 0x08, uint64(0x1000)) end)
        pcall(function() memory.write_dword(ent + 0x10, uint64(PROT_RW)) end)
        call548(0, 0, 1, string.format("op=%d addr=page len=0x1000", op))
        page_intact("  after")
        -- clear so the next op starts clean
        for i = 0, 0x38, 4 do pcall(function() memory.write_dword(ent + i, uint64(0)) end) end
    end

    print("")
    print("--- [E] two entries at once, count=2, both zero ---")
    for i = 0, 0x38, 4 do pcall(function() memory.write_dword(ent + i, uint64(0)) end) end
    call548(0, 0, 2, "count=2 zero entries")
    page_intact("after")

    print("")
    print("--- [F] the flag mask: arg2 values with and without 0xe0bffb6f bits ---")
    for _, f in ipairs({0x0, 0x1, 0x1000, 0x20000000, 0x10000000, 0xFFFFFFFF}) do
        call548(0, f, 0, string.format("flags=0x%X count=0", f))
    end
    print("    (0xe0bffb6f is the mask when byte[proc+0xc81]==0; bit 29 + bits 30/31 are refused)")

    print("")
    print("--- [G] arg1 class, count=0 and count=1 ---")
    for _, a in ipairs({0, 1, 0x310000000, 0xFFFFFFFFC1000000}) do
        if a >= 0x100000000 then
            call548(uint64(string.format("0x%X", a)), 0, 0, string.format("arg1=0x%X count=0", a))
        else
            call548(a, 0, 0, string.format("arg1=0x%X count=0", a))
        end
    end

    print("")
    print("--- [H] canary ---")
    page_intact("final")
    pcall(function() return sc73(uint64(page), uint64(0x4000), uint64(0), uint64(0), uint64(0), uint64(0)) end)
end

print("")
local canary = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("final canary: pid=%d", canary))
print("=== PROBE 1479a COMPLETE ===")
