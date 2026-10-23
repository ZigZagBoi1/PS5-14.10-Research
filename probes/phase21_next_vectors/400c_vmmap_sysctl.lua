-- CRASH_CLASS: LOW
-- PROBE 400c: kern.proc.vmmap via sysctl — fetch and scan
--
-- 400b found kern.proc.vmmap(self) size query returns 0 (success).
-- This is the STANDARD FreeBSD sysctl path, NOT Sony's sys 674.
-- FreeBSD kinfo_vmentry contains: kve_start, kve_end, kve_offset,
-- kve_vn_fileid, kve_vn_fsid, kve_resident, kve_private_resident,
-- kve_protection, kve_ref_count, kve_shadow_count, kve_vn_type,
-- kve_vn_size, kve_status, kve_path, and potentially
-- KERNEL OBJECT POINTERS that Sony might not have scrubbed.
--
-- FreeBSD 11 kinfo_vmentry is 1160 bytes per entry.

print("=== PROBE 400c: kern.proc.vmmap sysctl ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive()
    local ok, v = pcall(function() return native.fcall_with_rax(stub, 20) end)
    return ok and N(v) == pid_val
end

local function is_kptr(hi, lo)
    if hi == nil or lo == nil then return false end
    if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF and lo ~= 0 then return true end
    if hi == 0xFFFFFFFF then
        if lo == 0 or lo >= 0xFFFFF000 then return false end
        if lo >= 0x80000000 then return true end
    end
    return false
end

local sc202 = mk(202)

-- ============================================
-- PART A: Get vmmap size
-- ============================================
print("-- A: vmmap size query --")

local mib = memory.alloc(16)
wd(N(mib), 1)         -- CTL_KERN
wd(N(mib) + 4, 14)    -- KERN_PROC
wd(N(mib) + 8, 35)    -- KERN_PROC_VMMAP
wd(N(mib) + 12, pid_val)

local olen = memory.alloc(8)
wq(olen, uint64(0))

local ok_s, rv_s = pcall(function()
    return sc202(uint64(N(mib)), uint64(4), uint64(0),
        uint64(N(olen)), uint64(0), uint64(0))
end)
local ret_s = ok_s and N(rv_s) or -1
if ret_s > 0x7FFFFFFF then ret_s = -1 end
local need = rd(N(olen)) or 0
local need_hi = rd(N(olen) + 4) or 0
local need_full = need + need_hi * 0x100000000
print(string.format("  ret=%d need=%d (hi=%d)", ret_s, need, need_hi))

if ret_s ~= 0 then
    -- Try miblen=3 instead of 4
    local ok_s2, rv_s2 = pcall(function()
        return sc202(uint64(N(mib)), uint64(3), uint64(0),
            uint64(N(olen)), uint64(0), uint64(0))
    end)
    local ret_s2 = ok_s2 and N(rv_s2) or -1
    if ret_s2 > 0x7FFFFFFF then ret_s2 = -1 end
    local need2 = rd(N(olen)) or 0
    print(string.format("  miblen=3: ret=%d need=%d", ret_s2, need2))
    if ret_s2 == 0 then
        need = need2
        ret_s = 0
    end
end
if not alive() then print("CANARY FAIL A"); return end

-- ============================================
-- PART B: Fetch vmmap data
-- ============================================
print("")
print("-- B: fetch vmmap --")

if ret_s == 0 and need > 0 and need < 0x80000 then
    local buf = memory.alloc(need + 0x1000)
    -- Fill with sentinels
    for i = 0, math.min(need + 0xFFC, 0x40000), 4 do
        wd(N(buf) + i, 0xDEADDEAD)
    end
    wq(olen, uint64(need + 0x1000))

    local ok_f, rv_f = pcall(function()
        return sc202(uint64(N(mib)), uint64(4), uint64(N(buf)),
            uint64(N(olen)), uint64(0), uint64(0))
    end)
    local ret_f = ok_f and N(rv_f) or -1
    if ret_f > 0x7FFFFFFF then ret_f = -1 end
    local got = rd(N(olen)) or 0
    print(string.format("  ret=%d got=%d bytes", ret_f, got))

    if ret_f == 0 and got > 0 then
        -- Determine record size from first entry
        -- FreeBSD kinfo_vmentry: kve_structsize at +0x00 (int32)
        local rec_size = rd(N(buf)) or 0
        print(string.format("  kve_structsize=%d (0x%X)", rec_size, rec_size))

        if rec_size > 64 and rec_size < 0x2000 then
            local num_entries = math.floor(got / rec_size)
            print(string.format("  entries=%d", num_entries))

            -- Scan each entry
            local total_kptr = 0
            local kptr_offsets = {}

            for e = 0, num_entries - 1 do
                local ebase = N(buf) + e * rec_size
                -- Verify structsize
                local esz = rd(ebase) or 0
                if esz ~= rec_size then
                    print(string.format("  entry %d: size mismatch %d vs %d", e, esz, rec_size))
                    break
                end

                -- Scan every qword-aligned position
                for off = 0, rec_size - 8, 4 do
                    local lo = rd(ebase + off)
                    local hi = rd(ebase + off + 4)
                    if lo and hi and is_kptr(hi, lo) then
                        total_kptr = total_kptr + 1
                        if total_kptr <= 30 then
                            print(string.format("    entry %d +%04X: %08X_%08X ★KPTR★",
                                e, off, hi, lo))
                        end
                        -- Track which offsets have kptrs
                        kptr_offsets[off] = (kptr_offsets[off] or 0) + 1
                    end
                end
            end

            print(string.format("  TOTAL kptr: %d across %d entries", total_kptr, num_entries))

            if total_kptr > 0 then
                print("  kptr offset frequency:")
                for off, count in pairs(kptr_offsets) do
                    print(string.format("    +%04X: %d entries", off, count))
                end
            end

            -- Dump first entry fully for structure analysis
            print("")
            print("  first entry dump:")
            for off = 0, math.min(rec_size - 4, 255), 4 do
                local v = rd(N(buf) + off)
                if v and v ~= 0 then
                    local hi_check = rd(N(buf) + off + 4)
                    local tag = ""
                    if hi_check and is_kptr(hi_check, v) then tag = " ★" end
                    print(string.format("    +%04X: %08X%s", off, v, tag))
                end
            end

            -- Print start/end addresses of first few entries
            print("")
            print("  regions (start-end prot):")
            for e = 0, math.min(num_entries - 1, 20) do
                local ebase = N(buf) + e * rec_size
                -- kve_start at +0x10, kve_end at +0x18 (FreeBSD 11)
                -- Or might be at +0x08, +0x10
                local s_lo = rd(ebase + 0x10)
                local s_hi = rd(ebase + 0x14)
                local e_lo = rd(ebase + 0x18)
                local e_hi = rd(ebase + 0x1C)
                local prot = rd(ebase + 0x38) or 0

                if s_lo and s_hi and (s_lo ~= 0 or s_hi ~= 0) then
                    print(string.format("    [%d] %X_%08X - %X_%08X prot=%X",
                        e, s_hi or 0, s_lo or 0, e_hi or 0, e_lo or 0, prot))
                end
            end

        elseif got > 0 then
            -- Unknown record format — just raw scan
            print("  unknown format, raw scan...")
            local raw_kptr = 0
            for off = 0, got - 8, 4 do
                local lo = rd(N(buf) + off)
                local hi = rd(N(buf) + off + 4)
                if lo and hi and is_kptr(hi, lo) then
                    raw_kptr = raw_kptr + 1
                    if raw_kptr <= 20 then
                        print(string.format("    +%04X: %08X_%08X ★", off, hi, lo))
                    end
                end
            end
            print(string.format("  raw kptr: %d", raw_kptr))

            -- Dump first 256 bytes
            print("  first 256 bytes:")
            for off = 0, 252, 4 do
                local v = rd(N(buf) + off)
                if v and v ~= 0 and v ~= 0xDEADDEAD then
                    print(string.format("    +%04X: %08X", off, v))
                end
            end
        end
    end
elseif ret_s == 0 and need == 0 then
    -- Size query returned 0 bytes needed — try fetching anyway
    print("  need=0, trying fetch with 64KB buffer...")
    local buf = memory.alloc(0x10000)
    for i = 0, 0xFFFC, 4 do wd(N(buf) + i, 0xDEADDEAD) end
    wq(olen, uint64(0x10000))

    local ok_f2, rv_f2 = pcall(function()
        return sc202(uint64(N(mib)), uint64(4), uint64(N(buf)),
            uint64(N(olen)), uint64(0), uint64(0))
    end)
    local ret_f2 = ok_f2 and N(rv_f2) or -1
    if ret_f2 > 0x7FFFFFFF then ret_f2 = -1 end
    local got2 = rd(N(olen)) or 0
    print(string.format("  ret=%d got=%d", ret_f2, got2))

    if ret_f2 == 0 and got2 > 0 then
        -- Scan
        local kptr2 = 0
        for off = 0, got2 - 8, 4 do
            local lo = rd(N(buf) + off)
            local hi = rd(N(buf) + off + 4)
            if lo and hi and is_kptr(hi, lo) then
                kptr2 = kptr2 + 1
                if kptr2 <= 20 then
                    print(string.format("    +%04X: %08X_%08X ★", off, hi, lo))
                end
            end
        end
        print(string.format("  kptr: %d", kptr2))
    end
else
    print("  vmmap not available (ret=" .. ret_s .. ")")
end
if not alive() then print("CANARY FAIL B"); return end

-- ============================================
-- PART C: kern.proc.groups and other info sysctls
-- ============================================
print("")
print("-- C: other kern.proc.* --")

local sub_cmds = {
    {32, "KERN_PROC_GROUPS"},
    {34, "KERN_PROC_RLIMIT"},
    {36, "KERN_PROC_SIGTRAMP"},
    {37, "KERN_PROC_CRED"},
    {38, "KERN_PROC_PATHNAME"},
    {39, "KERN_PROC_OSREL"},
    {40, "KERN_PROC_SIGFASTBLK"},
    {41, "KERN_PROC_AUXV"},
}

for _, cmd in ipairs(sub_cmds) do
    wd(N(mib) + 8, cmd[1])
    wd(N(mib) + 12, pid_val)
    wq(olen, uint64(0))

    local ok_c, rv_c = pcall(function()
        return sc202(uint64(N(mib)), uint64(4), uint64(0),
            uint64(N(olen)), uint64(0), uint64(0))
    end)
    local ret_c = ok_c and N(rv_c) or -1
    if ret_c > 0x7FFFFFFF then ret_c = -1 end
    local need_c = rd(N(olen)) or 0

    if ret_c == 0 and need_c > 0 then
        print(string.format("  %s: ★ ret=0 need=%d", cmd[2], need_c))

        -- Fetch data
        local cbuf = memory.alloc(math.min(need_c + 16, 0x4000))
        for i = 0, math.min(need_c + 12, 0x3FFC), 4 do wd(N(cbuf) + i, 0) end
        wq(olen, uint64(need_c + 16))

        local ok_cf, rv_cf = pcall(function()
            return sc202(uint64(N(mib)), uint64(4), uint64(N(cbuf)),
                uint64(N(olen)), uint64(0), uint64(0))
        end)
        local ret_cf = ok_cf and N(rv_cf) or -1
        if ret_cf > 0x7FFFFFFF then ret_cf = -1 end
        local got_cf = rd(N(olen)) or 0

        if ret_cf == 0 and got_cf > 0 then
            -- Scan for kptr
            local ckptr = 0
            for off = 0, got_cf - 8, 4 do
                local lo = rd(N(cbuf) + off)
                local hi = rd(N(cbuf) + off + 4)
                if lo and hi and is_kptr(hi, lo) then
                    ckptr = ckptr + 1
                    if ckptr <= 5 then
                        print(string.format("      +%04X: %08X_%08X ★", off, hi, lo))
                    end
                end
            end

            -- Print data (ASCII or hex)
            if got_cf <= 256 then
                local txt = ""
                local hex = ""
                for i = 0, got_cf - 1 do
                    local dw = rd(N(cbuf) + i - (i % 4)) or 0
                    local byte = math.floor(dw / (256 ^ (i % 4))) % 256
                    if byte >= 32 and byte < 127 then txt = txt .. string.char(byte)
                    else txt = txt .. "." end
                end
                if #txt > 0 then
                    print(string.format("    data(%dB): %s", got_cf, txt))
                end
            end
            if ckptr > 0 then
                print(string.format("    ★★★ %d kptr in %s ★★★", ckptr, cmd[2]))
            end
        end
    else
        -- Don't print blocked entries, too noisy
    end

    if not alive() then print("CANARY FAIL " .. cmd[2]); return end
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 400c COMPLETE ===")
