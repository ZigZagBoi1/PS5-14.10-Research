-- CRASH_CLASS: MODERATE
-- PROBE 850a: does 548 op 0 map a HANDLE-backed object into our address space?
--
-- Context: 13.60's op 0 builds {entry[0], entry[0x10], prot, arg2, -1, entry[8]}
-- and calls 0xabd540(proc, &x), which reads [0] as a handle that must be
-- < 0x4000 and [8] as a 0x4000-aligned length >= 0x4000.  Every dynlib handle
-- returned by 592 is below 0x4000 (0, 2, 0x11, 0x13, 0x14, 0x22, 0x31..0x38,
-- 0x3A, 0x3D, 0x40..0x42, 0x48, 0x4A, 0x4C, 0x4E, 0x51, 0x52, 0x7E, 0x81,
-- 0x82, 0x8D, 0x8E, 0x9F, 0xA0, 0xA2, 0x1F6, 0x1FA, 0x1FB, 0x2001, 0x20BD,
-- 0x21F4).  If op 0 maps one of those modules with the protection we ask for,
-- the XOM text becomes readable and the syscall instruction becomes findable.

print("=== PROBE 850a: 548 OP 0 HANDLE MAP ===")
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
local function hx(v)
    if type(v) == "table" and v.h then
        return string.format("%08X%08X", to_num(v.h), to_num(v.l))
    end
    local n = to_num(v)
    if n < 0 then return string.format("-%X", -n) end
    return string.format("%X", n)
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end

local sc548 = make_syscall(548)
local sc592 = make_syscall(592)

local entry = memory.alloc(0x40)
local list = memory.alloc(0x100)
local cnt = memory.alloc(8)

print(string.format("[0] pid=%d", to_num(syscall.getpid())))

-- Real handles straight from the loader's own list.
local n = 0
local ok592 = pcall(function()
    local r = sc592(uint64(list), uint64(0x100), uint64(cnt))
    return r
end)
n = safe_rd(cnt) or 0
print(string.format("[A] 592 count=%d ok=%s", n, tostring(ok592)))
local handles = {}
for i = 0, math.min(n, 0x3F) - 1 do
    local v = safe_rd(list + i * 4)
    if v ~= nil then handles[#handles + 1] = v end
end
print(string.format("[A] handles=%d first=%s", #handles, handles[1] and string.format("%X", handles[1]) or "none"))

local function call548(addr, second, len, prot, op)
    safe_wq(entry, addr)
    safe_wq(entry + 8, second)
    safe_wq(entry + 0x10, len)
    safe_wd(entry + 0x18, prot)
    safe_wd(entry + 0x1C, op)
    local ok, ret = pcall(function()
        return sc548(uint64(0), uint64(0), uint64(to_num(entry)), uint64(1), uint64(0))
    end)
    if not ok then return nil end
    return ret
end

-- Scan a mapped page for 0F 05 and for the ELF magic.
local function describe(addr)
    local b0, b1, b2, b3 = safe_rd(addr), safe_rd(addr + 4), safe_rd(addr + 8), safe_rd(addr + 12)
    print(string.format("      first: %08X %08X %08X %08X", b0 or 0, b1 or 0, b2 or 0, b3 or 0))
    local hits = 0
    local shown = 0
    for off = 0, 0x4000 - 2 do
        local ok, pair = pcall(function()
            local a = memory.read_byte(addr + off)
            local b = memory.read_byte(addr + off + 1)
            return a, b
        end)
        if ok then
            if to_num(pair) == 0x0F then
                local ok2, b = pcall(function() return memory.read_byte(addr + off + 1) end)
                if ok2 and to_num(b) == 0x05 then
                    hits = hits + 1
                    if shown < 6 then
                        print(string.format("      SYSCALL at +0x%04X", off))
                        shown = shown + 1
                    end
                end
            end
        else
            print("      read fault at +0x" .. string.format("%04X", off))
            break
        end
    end
    print(string.format("      0F05 hits=%d", hits))
end

-- A: every real handle, read-only, one page.
for i = 1, #handles do
    local h = handles[i]
    local r = call548(h, 0, 0x4000, 1, 0)
    local s = r and hx(r) or "nil"
    print(string.format("[B] handle=%X op0 prot=1 -> %s", h, s))
    if r ~= nil then
        local v = to_num(r)
        if v > 0 and v < 0x8000000000 then
            describe(v)
        end
    end
end

-- C: the two handles the repo believes are libkernel, with R/W.
for _, h in ipairs({2, 0x11, 0x2001}) do
    local r = call548(h, 0, 0x4000, 3, 0)
    print(string.format("[C] handle=%X op0 prot=3 -> %s", h, r and hx(r) or "nil"))
    if r ~= nil then
        local v = to_num(r)
        if v > 0 and v < 0x8000000000 then describe(v) end
    end
end

-- D: control, a bad handle and a bad length.
local r1 = call548(0x3FFF, 0, 0x4000, 1, 0)
local r2 = call548(2, 0, 0x2000, 1, 0)
print(string.format("[D] handle=3FFF -> %s ; handle=2 len=2000 -> %s",
    r1 and hx(r1) or "nil", r2 and hx(r2) or "nil"))

print("[Z] alive=true")
print("=== PROBE 850a COMPLETE ===")
