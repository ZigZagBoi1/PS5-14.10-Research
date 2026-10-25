-- CRASH_CLASS: LOW
-- PROBE 544w: MapDirectMemory — atomic prints to find EXACT crash point
--
-- Every print is a single literal string.
-- NO string concatenation, NO tostring(), NO variable access after MapDM.
-- Just "print survived" markers.
-- Then SLOWLY introduce: bool access, number access, uint64 access.

print("=== 544w: ATOMIC ===")
io.stdout:setvbuf("no")

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
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end
local function q(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end

if not libkernel_base then print("FATAL"); return end
print("GO")

local alloc_fn = libkernel_base + uint64(0x17EF0)
local map_fn = libkernel_base + uint64(0x15020)

local phys_out = memory.alloc(8)
wq(phys_out, uint64(0))
pcall(function()
    native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
local phys = rq(phys_out)
if not phys then print("NO PHYS"); return end
print("P")

local virt_out = memory.alloc(8)
wq(virt_out, uint64(0))

-- ========= MapDM =========
print("M")
io.flush()
local ok_m, mrv = pcall(function()
    return native.fcall_with_rax(map_fn, 0,
        uint64(virt_out), uint64(0x4000), uint64(0x33),
        uint64(0x400000), phys, uint64(0x4000))
end)

-- Marker 1: raw literal print — no variables at all
print("A")
io.flush()

-- Marker 2: literal number
print(42)
io.flush()

-- Marker 3: literal string
print("B")
io.flush()

-- Marker 4: string.format with literal args only
print(string.format("%d", 123))
io.flush()

-- Marker 5: access a Lua LOCAL that existed BEFORE MapDM
local pre_str = "HELLO"
print(pre_str)
io.flush()

-- Marker 6: type() on ok_m (is it valid?)
local ok_m_type = type(ok_m)
print(ok_m_type)
io.flush()

-- Marker 7: the bool value itself
if ok_m then
    print("OK_TRUE")
else
    print("OK_FALSE")
end
io.flush()

-- Marker 8: type() on mrv
local mrv_type = type(mrv)
print(mrv_type)
io.flush()

-- Marker 9: if mrv is a number, print it
if mrv_type == "number" then
    print(mrv)
    io.flush()
end

-- Marker 10: if mrv is a table (uint64), try tostring
if mrv_type == "table" then
    print("MRV_TABLE")
    io.flush()
    local ok_ts, ts = pcall(tostring, mrv)
    if ok_ts then
        print(ts)
    else
        print("TS_FAIL")
    end
    io.flush()
end

-- Marker 11: to_num on mrv (pcall wrapped)
print("TONUM")
io.flush()
local ok_tn, tn = pcall(to_num, mrv)
if ok_tn then
    print(tn)
else
    print("TN_FAIL")
end
io.flush()

-- Marker 12: make_syscall getpid
print("SC")
io.flush()
local ok_sc, r_sc = pcall(function()
    local sc = make_syscall(20)
    return sc()
end)
if ok_sc then
    print(to_num(r_sc))
else
    print("SC_FAIL")
end
io.flush()

-- Marker 13: memory.alloc
print("MA")
io.flush()
local ok_ma, r_ma = pcall(memory.alloc, 8)
if ok_ma then
    print("MA_OK")
else
    print("MA_FAIL")
end
io.flush()

-- Marker 14: memory.read_dword on PRE-EXISTING buffer
print("RD")
io.flush()
local ok_rd, r_rd = pcall(memory.read_dword, phys_out)
if ok_rd then
    print("RD_OK")
else
    print("RD_FAIL")
end
io.flush()

-- Marker 15: memory.read_qword on virt_out (MapDM output)
print("RQ")
io.flush()
local ok_rq, r_rq = pcall(memory.read_qword, virt_out)
if ok_rq then
    print("RQ_OK")
    print(q(r_rq))
else
    print("RQ_FAIL")
end
io.flush()

print("DONE")
