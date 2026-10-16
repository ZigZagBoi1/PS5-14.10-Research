-- CRASH_CLASS: HIGH (intentional crash tests: ud2, unmapped, null, chain corruption)
-- PROBE 45c: Execution Reality Check
--
-- 45b showed ALL return values = 128 (pid), ALL memory writes fail,
-- ALL register oracles return 128. xor eax,eax;ret returns 128, which
-- is IMPOSSIBLE if the code actually runs. Conclusion: fn_addr-redirected
-- code is NOT executing. The "W^X bypass" from 44a was a false positive.
--
-- This probe answers definitively what's happening:
--   B) Read the syscall stub to understand fn_addr's normal target
--   C) Sysctl with NOP fn_addr — does the chain do syscalls on its own?
--   D) Stub offset redirect — does moving fn_addr change behavior at all?
--   E-G) Crash tests: ud2, unmapped, null — does the chain CALL fn_addr?
--   H) ROP chain corruption — is the chain even used?
--   I-K) Chain dump + pipe string — full structural analysis
--
-- Tests ordered: non-destructive analysis first, crash tests last.

print("=== PROBE 45c: EXECUTION REALITY CHECK ===")
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
if not page then print("FATAL: mmap failed"); return end
print("code page: " .. qw_hex(page))

-- Fill with INT3
for i = 0, page_size/4 - 1 do safe_wd(page + i*4, 0xCCCCCCCC) end

-- Make RWX
pcall(function() sc_mtypeprotect(uint64(page), uint64(page_size), uint64(7)) end)
print("mtypeprotect(RWX): done")

-- fn_addr
local pipe_str = tostring(syscall.pipe)
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
if not fn_str then print("FATAL: cannot parse fn_addr"); return end
local fn_ptr = uint64(fn_str)
local fn_orig = safe_rq(fn_ptr)
if not fn_orig then print("FATAL: cannot read fn_addr"); return end
print("fn_addr ptr: " .. fn_str)
print("fn_addr original: " .. qw_hex(fn_orig))
print("ropchain: " .. (rop_str or "unknown"))

local function write_code(base, offset, bytes)
    local p = {}
    for _, b in ipairs(bytes) do p[#p+1] = b end
    while #p % 4 ~= 0 do p[#p+1] = 0xCC end
    for i = 0, #p/4 - 1 do
        local dw = p[i*4+1] + p[i*4+2]*256 + p[i*4+3]*65536 + p[i*4+4]*16777216
        safe_wd(base + offset + i*4, dw)
    end
end

local function exec_at(offset)
    safe_wq(fn_ptr, page + offset)
    local ok, ret = pcall(function() return sc_getpid() end)
    safe_wq(fn_ptr, fn_orig)
    return ok, ok and to_num(ret) or -999
end

--------------------------------------------------------------------
-- B) SYSCALL STUB ANALYSIS (SAFE - no code reads, XO kills process)
-- Just identify which module fn_addr lives in via dynlib_get_info
--------------------------------------------------------------------
print("")
print("=== B: FN_ADDR MODULE IDENTIFICATION ===")
local fn_h, fn_l = get_hi_lo(fn_orig)
print(string.format("fn_addr value: %08X_%08X", fn_h, fn_l))
local sc_info = make_syscall(593)
local info_buf = memory.alloc(0x200)
local found_module = "unknown"
for handle = 0, 40 do
    safe_wd(info_buf, 0x160)
    local ok = pcall(function() sc_info(uint64(handle), uint64(info_buf)) end)
    if ok then
        local t_lo = safe_rd(info_buf + 0x108)
        local t_hi = safe_rd(info_buf + 0x10C)
        local t_sz_lo = safe_rd(info_buf + 0x110)
        local t_sz_hi = safe_rd(info_buf + 0x114)
        if t_lo and t_hi then
            local mod_start_l = t_lo
            local mod_start_h = t_hi
            local mod_end_l = t_lo + (t_sz_lo or 0)
            local mod_end_h = t_hi + (t_sz_hi or 0)
            if fn_h == mod_start_h and fn_l >= mod_start_l and fn_l < mod_end_l then
                local name_bytes = {}
                for i = 0, 31 do
                    local b = safe_rd(info_buf + 0x18 + i)
                    if b and b > 0 and b < 128 then
                        name_bytes[#name_bytes+1] = string.char(b)
                    else
                        break
                    end
                end
                found_module = table.concat(name_bytes)
                local off = fn_l - mod_start_l
                print(string.format("  module[%d]: %s text=%08X_%08X+%08X", handle, found_module, mod_start_h, mod_start_l, t_sz_lo or 0))
                print(string.format("  fn_addr is at module+0x%X", off))
                break
            end
        end
    end
end
if found_module == "unknown" then
    print("  fn_addr does NOT match any loaded module text range")
end
print("  SKIPPING code read (XO kills past pcall)")

--------------------------------------------------------------------
-- C) SYSCTL WITH NOP FN_ADDR
-- If the chain does syscalls independently of fn_addr, sysctl will
-- still work even when fn_addr points to NOP+ret.
--------------------------------------------------------------------
print("")
print("=== C: SYSCTL WITH NOP FN_ADDR ===")

local mib = memory.alloc(16)
safe_wd(mib, 1)       -- CTL_KERN
safe_wd(mib + 4, 14)  -- KERN_PROC
safe_wd(mib + 8, 1)   -- KERN_PROC_PID
safe_wd(mib + 12, pid)

local sysctl_out = memory.alloc(0x800)
for i = 0, 511 do safe_wd(sysctl_out + i*4, 0) end
local oldlenp = memory.alloc(8)
safe_wd(oldlenp, 0x800)
safe_wd(oldlenp + 4, 0)

-- Write NOP+ret to code page
write_code(page, 0x100, {0x90, 0x90, 0x90, 0x90, 0xC3})

-- Redirect fn_addr to NOP+ret, then call sysctl
safe_wq(fn_ptr, page + 0x100)
local ok_sc, rv_sc = pcall(function()
    return sc_sysctl(uint64(mib), uint64(4), uint64(sysctl_out),
        uint64(oldlenp), uint64(0), uint64(0))
end)
safe_wq(fn_ptr, fn_orig)

local sc_rv = ok_sc and to_num(rv_sc) or -999
local after_out = safe_rd(sysctl_out) or 0
local after_len = safe_rd(oldlenp) or 0
print(string.format("sysctl(NOP fn_addr): ok=%s ret=%d", tostring(ok_sc), sc_rv))
print(string.format("  output[0]=0x%08X, len=%d", after_out, after_len))

if after_out ~= 0 or after_len ~= 0x800 then
    print("*** SYSCTL DATA RETURNED despite fn_addr=NOP! ***")
    print("*** Chain does syscall INDEPENDENTLY of fn_addr ***")
else
    print("no data — sysctl did NOT run")
    print("(fn_addr may be the syscall entry, or chain broken)")
end

-- Control: do sysctl with ORIGINAL fn_addr to verify it works at all
for i = 0, 511 do safe_wd(sysctl_out + i*4, 0) end
safe_wd(oldlenp, 0x800)
safe_wd(oldlenp + 4, 0)
local ok_ctrl, rv_ctrl = pcall(function()
    return sc_sysctl(uint64(mib), uint64(4), uint64(sysctl_out),
        uint64(oldlenp), uint64(0), uint64(0))
end)
local ctrl_rv = ok_ctrl and to_num(rv_ctrl) or -999
local ctrl_out = safe_rd(sysctl_out) or 0
local ctrl_len = safe_rd(oldlenp) or 0
print(string.format("sysctl(orig fn_addr): ok=%s ret=%d", tostring(ok_ctrl), ctrl_rv))
print(string.format("  output[0]=0x%08X, len=%d", ctrl_out, ctrl_len))

--------------------------------------------------------------------
-- D) STUB OFFSET REDIRECT
-- Redirect fn_addr to fn_orig+0 through +15. If the chain calls
-- fn_addr, misaligned offsets should change behavior or crash.
--------------------------------------------------------------------
print("")
print("=== D: STUB OFFSET REDIRECT ===")
for offset = 0, 15 do
    safe_wq(fn_ptr, fn_orig + offset)
    local ok, ret = pcall(function() return sc_getpid() end)
    safe_wq(fn_ptr, fn_orig)
    local rv = ok and to_num(ret) or -999
    local marker = ""
    if rv ~= pid then marker = " ← DIFFERENT!" end
    if not ok then marker = " ← CRASHED!" end
    print(string.format("  fn_addr+%02d: ok=%s ret=%d%s", offset, tostring(ok), rv, marker))
    if not ok then
        -- Try to restore and verify
        safe_wq(fn_ptr, fn_orig)
        local ok2 = pcall(function() return sc_getpid() end)
        print(string.format("  recovery: ok=%s", tostring(ok2)))
        break
    end
end

--------------------------------------------------------------------
-- E-G) NON-DESTRUCTIVE ANALYSIS (before crash tests)
-- Dump the chain, fn_ptr area, and pipe string while we still can
--------------------------------------------------------------------

-- E) ROP CHAIN DUMP
print("")
print("=== E: ROP CHAIN DUMP ===")
if rop_str then
    local rop_base = uint64(rop_str)
    print("ropchain base: " .. rop_str)
    local fn_h, fn_l = get_hi_lo(fn_orig)
    for i = 0, 63 do
        local q = safe_rq(rop_base + i*8)
        if q then
            local h, l = get_hi_lo(q)
            local marker = ""
            if h == fn_h and l == fn_l then marker = " ← fn_addr_value" end
            print(string.format("  [%02d] +0x%03X: %08X_%08X%s", i, i*8, h, l, marker))
        else
            print(string.format("  [%02d] +0x%03X: UNREADABLE", i, i*8))
            break
        end
    end
else
    print("ropchain address not found in pipe string")
end

-- F) FN_PTR NEIGHBORHOOD
print("")
print("=== F: FN_PTR NEIGHBORHOOD ===")
print("fn_ptr: " .. fn_str)
for i = -8, 15 do
    local addr = fn_ptr + i*8
    local q = safe_rq(addr)
    if q then
        local h, l = get_hi_lo(q)
        local marker = ""
        if i == 0 then marker = " ← fn_addr" end
        print(string.format("  %+03d: %08X_%08X%s", i*8, h, l, marker))
    end
end

-- G) PIPE STRING
print("")
print("=== G: PIPE STRING ===")
local line_count = 0
for line in pipe_str:gmatch("[^\n]+") do
    print("  " .. line)
    line_count = line_count + 1
    if line_count >= 40 then print("  [truncated]"); break end
end

--------------------------------------------------------------------
-- H) CRASH TEST: ud2 on code page
-- If this crashes, code at our page DOES execute.
-- If it returns normally, either page isn't X or chain doesn't jump.
--------------------------------------------------------------------
print("")
print("=== H: CRASH TEST — UD2 ===")
write_code(page, 0x000, {0x0F, 0x0B, 0xCC, 0xCC})  -- ud2; int3; int3
safe_wq(fn_ptr, page)
local ok_ud2, ret_ud2 = pcall(function() return sc_getpid() end)
safe_wq(fn_ptr, fn_orig)
local rv_ud2 = ok_ud2 and to_num(ret_ud2) or -999
print(string.format("ud2: ok=%s ret=%d", tostring(ok_ud2), rv_ud2))
if not ok_ud2 then
    print("*** CRASHED! fn_addr code DOES execute! ***")
    print("*** Page is executable! Problem is return value mechanism ***")
else
    print("NO CRASH — ud2 did not trigger")
end

-- I) CRASH TEST: unmapped address
print("")
print("=== I: CRASH TEST — UNMAPPED ADDR ===")
safe_wq(fn_ptr, uint64("0xDEAD0000DEAD0000"))
local ok_unmap = pcall(function() return sc_getpid() end)
safe_wq(fn_ptr, fn_orig)
print(string.format("unmapped: ok=%s", tostring(ok_unmap)))
if not ok_unmap then
    print("*** CRASHED! fn_addr IS the call target! ***")
else
    print("NO CRASH — chain does not call fn_addr (or catches all faults)")
end

-- J) CRASH TEST: null address
print("")
print("=== J: CRASH TEST — NULL ===")
safe_wq(fn_ptr, uint64(0))
local ok_null = pcall(function() return sc_getpid() end)
safe_wq(fn_ptr, fn_orig)
print(string.format("null: ok=%s", tostring(ok_null)))
if not ok_null then
    print("*** CRASHED! fn_addr IS the call target! ***")
else
    print("NO CRASH — chain survived null fn_addr")
end

--------------------------------------------------------------------
-- K) ROP CHAIN CORRUPTION TEST
-- Write garbage to the first 8 chain entries. If getpid still
-- returns pid, the chain isn't being used at all.
--------------------------------------------------------------------
print("")
print("=== K: ROP CHAIN CORRUPTION ===")
if rop_str then
    local rop_base = uint64(rop_str)
    -- Save first 16 entries
    local saved = {}
    for i = 0, 15 do saved[i] = safe_rq(rop_base + i*8) end

    -- Corrupt first 8 entries with garbage
    for i = 0, 7 do
        safe_wq(rop_base + i*8, uint64("0x4141414141414141"))
    end
    print("corrupted chain[0..7] with 0x41414141_41414141")

    local ok_corrupt, ret_corrupt = pcall(function() return sc_getpid() end)
    local rv_corrupt = ok_corrupt and to_num(ret_corrupt) or -999

    -- RESTORE IMMEDIATELY
    for i = 0, 15 do
        if saved[i] then safe_wq(rop_base + i*8, saved[i]) end
    end

    print(string.format("getpid after corruption: ok=%s ret=%d", tostring(ok_corrupt), rv_corrupt))

    if ok_corrupt and rv_corrupt == pid then
        print("*** CHAIN NOT USED! Syscall bypasses the ROP chain entirely ***")
        print("*** make_syscall() goes through a different code path ***")
    elseif not ok_corrupt then
        print("*** CRASHED! Chain IS used! ***")
        -- Verify recovery
        local ok_r = pcall(function() return sc_getpid() end)
        print(string.format("recovery: ok=%s", tostring(ok_r)))
    else
        print(string.format("different return value: %d (chain is used but partially)", rv_corrupt))
    end
else
    print("skipped — no ropchain address")
end

--------------------------------------------------------------------
-- L) EBOOT BASE (for cross-reference)
--------------------------------------------------------------------
print("")
print("=== L: EBOOT INFO ===")
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local text_lo = safe_rd(info + 0x108) or 0
local text_hi = safe_rd(info + 0x10C) or 0
local text_size_lo = safe_rd(info + 0x110) or 0
local text_size_hi = safe_rd(info + 0x114) or 0
print(string.format("eboot text base: %08X_%08X", text_hi, text_lo))
print(string.format("eboot text size: %08X_%08X", text_size_hi, text_size_lo))

-- Check if fn_addr is in eboot range
local fn_h, fn_l = get_hi_lo(fn_orig)
print(string.format("fn_addr value:   %08X_%08X", fn_h, fn_l))
if fn_h == text_hi and fn_l >= text_lo then
    local offset = fn_l - text_lo
    print(string.format("fn_addr is eboot+0x%X (in RX text)", offset))
else
    print("fn_addr is NOT in eboot text section")
end

--------------------------------------------------------------------
-- M) CLEANUP
--------------------------------------------------------------------
print("")
print("=== M: CLEANUP ===")
safe_wq(fn_ptr, fn_orig)
local ok_final = pcall(function() return to_num(sc_getpid()) end)
print(string.format("fn_addr restored, getpid ok=%s", tostring(ok_final)))

print("")
print("=== PROBE 45c COMPLETE ===")
