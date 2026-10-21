-- CRASH_CLASS: LOW
-- PROBE 192a: argument shapes for the stateful handlers
--
-- Context: every handler in 532 and 538-558 came back -1 for six zero
-- arguments (sweep 20261020_193825). A -1 means the slot exists and the
-- handler rejected the call (docs/SYSCALL_ABSENT_VS_LETHAL.md); it says
-- nothing about which argument shape the handler wants. regmgr_call (532) was
-- never measured at all, the sweep stopped below it.
--
-- A create-style call that rejects six zeros is usually rejecting a null name
-- or a null out-pointer, not refusing service. So this probe walks the first
-- three arguments over the shapes a Sony create/registry call is known to use:
-- a name pointer, an attribute word, an initial count, a struct pointer.
--
-- What we want out of it: one handle that create (538/549/557) will hand back,
-- and one regmgr command that writes into a user buffer. Both are prerequisites
-- for the lifecycle probes (create, use, delete, race the delete).

print("=== PROBE 192a: stateful handler argument shapes ===")
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
local function u64(v)
    if type(v) == "number" then return uint64(string.format("0x%08X", v)) end
    return v
end
local function show(v)
    if v == nil then return "killed" end
    return tostring(v)
end
local dead = false

local function call(num, a1, a2, a3, a4, a5, a6)
    local sc = make_syscall(num)
    local ok, ret = pcall(function()
        return sc(u64(a1 or 0), u64(a2 or 0), u64(a3 or 0), u64(a4 or 0), u64(a5 or 0), u64(a6 or 0))
    end)
    if not ok then
        dead = true
        return nil, nil
    end
    return ret, to_num(ret)
end

-- Two kinds of argument need a real pointer, so the matrix uses sentinels and
-- resolves them here. NAME is a NUL-terminated string, STRUCT is a zeroed page
-- the handler may write into.
local NAME = memory.alloc(0x40)
local STRUCT = memory.alloc(0x100)
local OUT = memory.alloc(0x400)
local function put_str(addr, s)
    for i = 1, #s do
        pcall(function() memory.write_byte(addr + i - 1, u64(string.byte(s, i))) end)
    end
    pcall(function() memory.write_byte(addr + #s, u64(0)) end)
end
local function zero_page(addr, n)
    for off = 0, n - 4, 4 do
        pcall(function() memory.write_dword(addr + off, u64(0)) end)
    end
end
local function arg(v)
    if v == "NAME" then return NAME end
    if v == "STRUCT" then return STRUCT end
    if v == "OUT" then return OUT end
    return v
end

put_str(NAME, "probe_name")
zero_page(STRUCT, 0x100)
zero_page(OUT, 0x400)

local CANARY = 0xA5A5A5A5
local function fill(addr, n)
    for off = 0, n - 4, 4 do
        pcall(function() memory.write_dword(addr + off, u64(CANARY)) end)
    end
end
local function written(addr, n)
    local count, first = 0, nil
    for off = 0, n - 4, 4 do
        local ok, v = pcall(function() return memory.read_dword(addr + off) end)
        if ok and to_num(v) ~= CANARY then
            count = count + 1
            if not first then first = string.format("+0x%03X=%08X", off, to_num(v)) end
        end
    end
    return count, first
end

local _, pid = call(20)
print("[0] getpid " .. show(pid))
print("")

-- ============================================================
-- A: regmgr_call (532)
-- ============================================================
print("[A] 532 regmgr_call: service, command, buffer, size")

local function regmgr(label, a1, a2, a3, a4)
    fill(OUT, 0x100)
    local _, rv = call(532, arg(a1), arg(a2), arg(a3), arg(a4))
    if dead then
        print("    " .. label .. " -> process died")
        return
    end
    local n, first = written(OUT, 0x100)
    print(string.format("    %-34s -> rv=%s writes=%d %s",
        label, show(rv), n, first or ""))
end

regmgr("(0,0,OUT,8)", 0, 0, "OUT", 8)
regmgr("(0,8,OUT,8)", 0, 8, "OUT", 8)
regmgr("(0,9,OUT,8)", 0, 9, "OUT", 8)
regmgr("(0,10,OUT,8)", 0, 10, "OUT", 8)
regmgr("(0,0x10,OUT,8)", 0, 0x10, "OUT", 8)
regmgr("(0,0x100,OUT,8)", 0, 0x100, "OUT", 8)
regmgr("(1,8,OUT,8)", 1, 8, "OUT", 8)
regmgr("(2,8,OUT,8)", 2, 8, "OUT", 8)
regmgr("(0,0,NAME,32)", 0, 0, "NAME", 32)
regmgr("(0,8,NAME,32)", 0, 8, "NAME", 32)
regmgr("(0,0x100,NAME,32)", 0, 0x100, "NAME", 32)
print("")

-- ============================================================
-- B: create-style argument matrix
-- ============================================================
print("[B] create-style calls: first three arguments walked over name/attr/count")

local SHAPES = {
    { 0, 0, 0 }, { "NAME", 0, 0 }, { "NAME", 1, 0 }, { "NAME", 0, 1 },
    { "NAME", 1, 1 }, { "NAME", 2, 0 }, { "NAME", 3, 0 }, { "NAME", 0x100, 0 },
    { "NAME", 0x100, 1 }, { "STRUCT", 0, 0 }, { "STRUCT", 1, 0 }, { "STRUCT", 0, 1 },
    { 0, 1, 0 }, { 0, 0, 1 }, { 1, 0, 0 },
}

local handles = {}
for _, num in ipairs({ 538, 549, 557 }) do
    for _, s in ipairs(SHAPES) do
        if dead then break end
        local _, rv = call(num, s[1], s[2], s[3])
        if dead then
            print(string.format("    %d(%s) -> process died", num, tostring(s[1])))
            break
        end
        local label = string.format("%d(%s,%s,%s)", num, tostring(s[1]), tostring(s[2]), tostring(s[3]))
        if rv ~= nil and rv ~= -1 then
            print(string.format("    %-40s -> rv=%d  <-- answered", label, rv))
            if rv >= 0 and rv < 0x10000 then
                handles[#handles + 1] = { num = num, handle = rv }
            end
        end
    end
    if dead then break end
end
if #handles == 0 and not dead then
    print("    every shape answered -1")
end
print("")

-- ============================================================
-- C: if a handle exists, delete it and recreate
-- ============================================================
print("[C] handle delete/recreate")
local DEL = { [538] = 539, [549] = 550, [557] = 558 }
for _, h in ipairs(handles) do
    local del = DEL[h.num]
    if del then
        local _, dr = call(del, h.handle)
        print(string.format("    %d(handle=%d) -> %s", del, h.handle, show(dr)))
        local _, again = call(del, h.handle)
        print(string.format("    %d again      -> %s (double delete)", del, show(again)))
        local _, re = call(h.num, "NAME", 0, 0)
        print(string.format("    %d recreate   -> %s", h.num, show(re)))
    end
end
if #handles == 0 then print("    no handle to delete") end
print("")

-- ============================================================
-- D: query_memory_protection (547)
-- ============================================================
print("[D] 547 query_memory_protection on a mapped page")
local PAGE = memory.alloc(0x1000)
zero_page(PAGE, 0x1000)
local layouts = {
    { "addr,OUT", PAGE, "OUT", 0 },
    { "OUT,addr", "OUT", PAGE, 0 },
    { "addr,size,OUT", PAGE, 0x1000, "OUT" },
    { "OUT,size,addr", "OUT", 0x1000, PAGE },
    { "addr,0,OUT", PAGE, 0, "OUT" },
    { "addr,OUT,0", PAGE, "OUT", 0 },
}
for _, l in ipairs(layouts) do
    if dead then break end
    fill(OUT, 0x100)
    local _, rv = call(547, arg(l[2]), arg(l[3]), arg(l[4]))
    if dead then
        print("    " .. l[1] .. " -> process died")
        break
    end
    local n, first = written(OUT, 0x100)
    print(string.format("    %-22s -> rv=%s writes=%d %s", l[1], show(rv), n, first or ""))
end
print("")

print("=== PROBE 192a COMPLETE ===")
