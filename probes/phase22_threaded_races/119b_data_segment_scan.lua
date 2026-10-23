-- CRASH_CLASS: LOW
-- PROBE 119b: Scan real data segments (not .text) for kernel pointers
--
-- 119a scanned eboot+2MB = still in .text (x86 code false positives).
-- The dynlib_get_info struct has data segment info.
-- Need to find the ACTUAL .data/.bss base and scan ONLY that.
--
-- Also: scan around pipe address (0x8xxx range), and dump the
-- full dynlib_get_info struct to understand its layout.

print("=== PROBE 119b: DATA SEGMENT SCAN ===")
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
local function is_code_false_positive(val)
    -- x86 code bytes that look like kptrs have bytes like:
    -- 48, 8B, 89, 8D, C7, C5, F6 in the byte stream
    -- Real kernel pointers would be 0xFFFF8xxx + varying low bytes
    if val==nil then return true end
    local h,l = get_hi_lo(val)
    if h<0 then h=h+0x100000000 end
    if l<0 then l=l+0x100000000 end
    -- Check: low byte of l should NOT be common x86 opcode
    local lobyte = l % 256
    -- Common x86 prefix/opcode bytes found in false positives:
    -- 0x48(REX.W), 0xFF(call/jmp), 0x00(add), 0x06, 0x53(push rbx), 0xF6(test)
    -- 0xC5(VEX), 0xA0, 0xD0
    -- Real kernel addresses have random low bytes
    -- Better heuristic: check if high word matches kernel VA structure
    -- FreeBSD kernel pointers: 0xFFFF800x where x varies
    -- The false positives had h like 0xFFFFFF08, 0xFFFFFB58, etc.
    -- Real kernel base: h should be 0xFFFF80xx with xx being KASLR offset
    if h >= 0xFFFFF000 then return true end  -- too high for kernel base
    return false
end

local stub=syscall.pipe.fn_addr
local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)

local sc_info = mk(593)

-- ============================================================
print("--- A: DUMP dynlib_get_info STRUCT (all 0x160 bytes) ---")
-- Dump for handles 0 (eboot) and 1 (libkernel)
for handle=0,3 do
    local inf=memory.alloc(0x200)
    wd(inf,0x160)
    local oki = pcall(function() sc_info(uint64(handle), inf) end)
    if not oki then break end
    local II = N(inf)

    -- Read name at +0x08 (char array)
    local name = ""
    for i=0,31 do
        local b = rd(II+8+i)
        if not b then break end
        local ch = b % 256
        if ch==0 then break end
        name = name .. string.char(ch)
    end

    -- Read all qwords for structure analysis
    local tl=rd(II+0x108) or 0; local th=rd(II+0x10C) or 0
    if th<0 then th=th+0x100000000 end
    if tl<0 then tl=tl+0x100000000 end
    if th==0 and tl==0 and handle > 1 then break end

    print(string.format("  handle %d: '%s'", handle, name))
    print(string.format("    +0x108 text_base: 0x%X%08X", th, tl))

    -- Print key offsets that might be segment info
    for _, off in ipairs({0x110, 0x118, 0x120, 0x128, 0x130, 0x138, 0x140, 0x148}) do
        local val = rq(II+off)
        if val then
            print(string.format("    +0x%03X: %s", off, fmt_ptr(val)))
        end
    end

    -- Check if +0x118 is the data base
    local dl=rd(II+0x118) or 0; local dh=rd(II+0x11C) or 0
    if dh<0 then dh=dh+0x100000000 end
    if dl<0 then dl=dl+0x100000000 end
    if (dh > 0 or dl > 0) and dh < 0xFFFF0000 then
        print(string.format("    data_base candidate (+0x118): 0x%X%08X", dh, dl))
    end

    -- Also check +0x128
    local dl2=rd(II+0x128) or 0; local dh2=rd(II+0x12C) or 0
    if dh2<0 then dh2=dh2+0x100000000 end
    if dl2<0 then dl2=dl2+0x100000000 end
    if (dh2 > 0 or dl2 > 0) and dh2 < 0xFFFF0000 then
        print(string.format("    +0x128 candidate: 0x%X%08X", dh2, dl2))
    end
end

local c = N(native.fcall_with_rax(stub,20))
if c~=pid then print("DIED!") return end

-- ============================================================
print("")
print("--- B: SCAN EBOOT DATA SEGMENT ---")
-- From previous runs: +0x110 low dword = 0x494000 (text size = 4.6MB)
-- Data should be near eboot + 0x494000
-- Re-read for this ASLR instance
local inf2=memory.alloc(0x200)
wd(inf2,0x160)
pcall(function() sc_info(uint64(0), inf2) end)
local I2 = N(inf2)
local tl=rd(I2+0x108) or 0; local th=rd(I2+0x10C) or 0
if th<0 then th=th+0x100000000 end
if tl<0 then tl=tl+0x100000000 end
local EB = N(uint64(string.format("0x%X%08X", th, tl)))

-- text_size from +0x110 low dword
local tsz = rd(I2+0x110) or 0
if tsz<0 then tsz=tsz+0x100000000 end
print(string.format("  text=0x%X, text_size=0x%X", EB, tsz))

-- Data segment should start around EB + tsz
-- But might be page-aligned (16KB pages = 0x4000)
local data_start = EB + tsz
-- Align up to 16KB
data_start = data_start + 0x3FFF
data_start = data_start - (data_start % 0x4000)
print(string.format("  data_start candidate: 0x%X", data_start))

-- Probe: is this readable?
local test_val = rq(data_start)
if test_val == nil then
    print("  not readable at data_start, trying EB+tsz directly...")
    data_start = EB + tsz
    test_val = rq(data_start)
end

if test_val then
    print(string.format("  data_start readable: %s", fmt_ptr(test_val)))

    -- Scan data segment (1.5MB per +0x120 hint = 0x180000)
    local dsz = rd(I2+0x120) or 0
    if dsz<0 then dsz=dsz+0x100000000 end
    local scan_limit = math.min(dsz > 0 and dsz or 0x100000, 0x100000) -- cap at 1MB
    print(string.format("  data_size hint: 0x%X, scanning 0x%X bytes", dsz, scan_limit))

    local kp = 0
    local real_kp = 0
    for off=0,scan_limit-8,8 do
        local val = rq(data_start + off)
        if val==nil then
            print(string.format("  unreadable at data+0x%X", off))
            break
        end
        if is_kptr(val) then
            if not is_code_false_positive(val) then
                real_kp = real_kp + 1
                print(string.format("  *** REAL KPTR data+0x%X: %s ***", off, fmt_ptr(val)))
                if real_kp >= 15 then break end
            else
                kp = kp + 1
            end
        end
    end
    print(string.format("  data: %d code-like, %d real kptrs", kp, real_kp))
else
    print("  data_start not readable")
    -- Try offsets around EB + tsz in 16KB steps
    for step=0,16 do
        local try_addr = EB + tsz + step*0x4000
        local tv = rq(try_addr)
        if tv then
            print(string.format("  readable at EB+0x%X: %s", tsz + step*0x4000, fmt_ptr(tv)))
            data_start = try_addr
            break
        end
    end
end

c = N(native.fcall_with_rax(stub,20))
if c~=pid then print("DIED!") return end

-- ============================================================
print("")
print("--- C: SCAN PIPE ADDRESS REGION ---")
-- Pipe address from 118d: 0x807280b57 (varies per ASLR)
local pipe_str = tostring(syscall.pipe)
local pipe_addr_str = pipe_str:match("address @ (0x[0-9a-fA-F]+)")
print("  pipe_addr: " .. (pipe_addr_str or "nil"))

if pipe_addr_str then
    local PA = tonumber(pipe_addr_str)
    if PA then
        -- This is a large address (0x8xxx range). Can we read it?
        local pv = rq(PA)
        if pv then
            print(string.format("  pipe[0]: %s *** READABLE! ***", fmt_ptr(pv)))
            -- Scan 2KB around pipe address
            local pkp = 0
            for off=-0x200,0x400,8 do
                local val = rq(PA + off)
                if val then
                    if is_kptr(val) and not is_code_false_positive(val) then
                        pkp = pkp + 1
                        print(string.format("    *** KPTR pipe+0x%X: %s ***", off, fmt_ptr(val)))
                    end
                end
            end
            print(string.format("  pipe region: %d real kptrs", pkp))
            -- Dump first 64 bytes of pipe object
            print("  pipe object dump:")
            for off=0,0x78,8 do
                local val = rq(PA + off)
                print(string.format("    +0x%02X: %s", off, fmt_ptr(val)))
            end
        else
            print("  pipe address not readable (0x8xxx might need uint64 addressing)")
            -- Try with uint64
            local pa_q = uint64(pipe_addr_str)
            local pv2 = rq(N(pa_q))
            if pv2 then
                print(string.format("  via uint64: %s *** READABLE! ***", fmt_ptr(pv2)))
            else
                print("  still not readable")
            end
        end
    end
end

c = N(native.fcall_with_rax(stub,20))
if c~=pid then print("DIED!") return end

-- ============================================================
print("")
print("--- D: SCAN LIBKERNEL DATA ---")
-- Get libkernel info
local inf3=memory.alloc(0x200)
wd(inf3,0x160)
pcall(function() sc_info(uint64(1), inf3) end)
local I3 = N(inf3)
local lkl=rd(I3+0x108) or 0; local lkh=rd(I3+0x10C) or 0
if lkh<0 then lkh=lkh+0x100000000 end
if lkl<0 then lkl=lkl+0x100000000 end
local lk_tsz = rd(I3+0x110) or 0
if lk_tsz<0 then lk_tsz=lk_tsz+0x100000000 end

if lkh > 0 or lkl > 0 then
    local LK = N(uint64(string.format("0x%X%08X", lkh, lkl)))
    print(string.format("  libkernel text=0x%X, tsz=0x%X", LK, lk_tsz))
    local lk_data = LK + lk_tsz
    lk_data = lk_data + 0x3FFF
    lk_data = lk_data - (lk_data % 0x4000)
    print(string.format("  libkernel data candidate: 0x%X", lk_data))

    local lkv = rq(lk_data)
    if lkv then
        print(string.format("  first qword: %s", fmt_ptr(lkv)))
        local lk_kp = 0
        for off=0,0x20000-8,8 do
            local val = rq(lk_data + off)
            if val==nil then
                print(string.format("  unreadable at lk_data+0x%X", off))
                break
            end
            if is_kptr(val) and not is_code_false_positive(val) then
                lk_kp = lk_kp + 1
                print(string.format("    *** KPTR lk_data+0x%X: %s ***", off, fmt_ptr(val)))
                if lk_kp >= 10 then break end
            end
        end
        print(string.format("  libkernel data: %d real kptrs", lk_kp))
    else
        print("  libkernel data not readable")
    end
end

-- ============================================================
print("")
local fc=N(native.fcall_with_rax(stub,20))
print(string.format("FINAL: canary=%s", fc==pid and "OK" or "FAIL"))
print("=== 119b COMPLETE ===")
