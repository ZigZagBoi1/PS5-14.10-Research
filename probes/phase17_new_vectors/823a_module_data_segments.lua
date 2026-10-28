-- CRASH_CLASS: MODERATE
-- PROBE 823a: is any readable (prot bit 1) region part of a system module?
--
-- 516a found every system prx text mapped prot 4 (execute-only) and libc
-- readable.  If libkernel also has a prot-3 data region, its ELF dynamic
-- section can be parsed, which would give the export list without dlsym(591)
-- - 591 refuses every handle on 14.10.  Only regions with the read bit are
-- ever dereferenced; an XO region is printed and skipped.

print("=== PROBE 823a: module regions and their protections ===")
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
local function u(v)
    if type(v) == "table" then
        return uint64(to_num(v.h or 0)) * uint64(4294967296) + uint64(to_num(v.l or 0))
    end
    return uint64(v)
end
local function safe_rd(a) local ok, v = pcall(function() return memory.read_dword(a) end) if ok then return to_num(v) end return nil end
local function safe_wd(a, v) return (pcall(function() memory.write_dword(a, v) end)) end
local function q(a, o)
    local hi, lo = safe_rd(a + o + 4), safe_rd(a + o)
    if not hi or not lo then return nil end
    return hi * 4294967296 + lo
end
local function name_at(a)
    local s = ""
    for k = 0, 30 do
        local c = safe_rd(a + k)
        if not c or c == 0 then break end
        local ch = c % 256
        if ch < 32 or ch > 126 then break end
        s = s .. string.char(ch)
    end
    return s
end

local sc674 = make_syscall(674)
local buf = memory.alloc(0x10000)
local cnt = memory.alloc(8)
safe_wd(cnt, 0)
local ret = -1
pcall(function() ret = to_num(sc674(u(buf), u(72), u(512), u(cnt), u(0x40000000), u(0))) end)
local n = safe_rd(cnt) or 0
print(string.format("[A] 674 ret=%d regions=%d", ret, n))
print("")

print("[B] regions whose name mentions a module or libkernel:")
local seen = {}
for i = 0, n - 1 do
    local r = buf + i * 72
    local start = (q(r, 4) or 0) * 4294967296 + (q(r, 0) or 0)
    local stop  = (q(r, 12) or 0) * 4294967296 + (q(r, 8) or 0)
    local prot  = q(r, 0x18) or 0
    local nm    = name_at(r + 0x20)
    if nm:find("libkernel") or nm:find("%.prx") or nm:find("libSce") then
        local key = nm .. "|" .. string.format("%d", prot)
        if not seen[key] then
            seen[key] = true
            print(string.format("[B] prot=%d %012X-%012X  %s", prot, start, stop, nm))
        end
    end
end
print("")

print("[C] first dword of every readable module region (guard: prot & 1):")
local done = {}
for i = 0, n - 1 do
    local r = buf + i * 72
    local start = (q(r, 4) or 0) * 4294967296 + (q(r, 0) or 0)
    local prot  = q(r, 0x18) or 0
    local nm    = name_at(r + 0x20)
    if (nm:find("%.prx") or nm:find("libkernel") or nm:find("libSce"))
       and (prot % 2) == 1 and not done[nm] then
        done[nm] = true
        local v = safe_rd(u(start))
        print(string.format("[C] %-28s prot=%d first=%s", nm, prot,
            v and string.format("%08X", v) or "nil"))
    end
end
print("[D] survived")
