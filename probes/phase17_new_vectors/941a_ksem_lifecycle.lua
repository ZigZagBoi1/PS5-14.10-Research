-- CRASH_CLASS: MODERATE
-- PROBE 941a: POSIX semaphore (ksem) lifecycle with the CORRECT syscall numbers.
-- 79d used post=401/wait=402/trywait=403/getvalue=406/destroy=407, which are not the ksem
-- numbers, so its section B told us only that ksem_init(404) exists and returned id 22.
-- FreeBSD 11 numbering: init=404, destroy=405, open=406, close=407, post=408, wait=409,
-- trywait=410, getvalue=412, unlink=413.
print("=== PROBE 941a: ksem lifecycle ===")
local function to_num(v)
    if type(v) == "table" and v.tonumber then local ok, n = pcall(function() return v:tonumber() end); if ok and n then return n end end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(v) or 0
end
local function mk(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function q(v)
    local h, l = 0, to_num(v)
    if type(v) == "table" and v.h then h, l = v.h, v.l end
    return string.format("0x%X%08X", h, l)
end
local sc_getpid, sc_init, sc_destroy = mk(20), mk(404), mk(405)
local sc_post, sc_trywait, sc_getval = mk(408), mk(410), mk(412)
local function call(f, a, b)
    local ok, rv = pcall(function() return f(uint64(a), uint64(b or 0)) end)
    if not ok then return "PCALL-FAIL" end
    return q(rv)
end
print("[0] canary getpid=" .. call(sc_getpid, 0))

local idbuf = memory.alloc(8)
local vb = memory.alloc(8)
local function init(val)
    memory.write_qword(idbuf, 0)
    local ok, rv = pcall(function() return sc_init(uint64(idbuf), uint64(val)) end)
    return ok, rv, memory.read_dword(idbuf) and to_num(memory.read_dword(idbuf))
end

print("--- A: value accounting on one semaphore ---")
local okA, rvA, idA = init(1)
print(string.format("[A0] ksem_init(1) rv=%s id=%s", okA and q(rvA) or "fail", tostring(idA)))
if okA then
    print("[A1] getvalue  -> " .. call(sc_getval, idA, vb) .. " val=" .. tostring(memory.read_dword(vb) and to_num(memory.read_dword(vb))))
    print("[A2] post      -> " .. call(sc_post, idA))
    print("[A3] getvalue  -> " .. call(sc_getval, idA, vb) .. " val=" .. tostring(memory.read_dword(vb) and to_num(memory.read_dword(vb))))
    print("[A4] trywait   -> " .. call(sc_trywait, idA))
    print("[A5] trywait   -> " .. call(sc_trywait, idA))
    print("[A6] trywait   -> " .. call(sc_trywait, idA))
    print("[A7] destroy   -> " .. call(sc_destroy, idA))
    print("[A8] post-after-destroy -> " .. call(sc_post, idA))
    print("[A9] getvalue-after-destroy -> " .. call(sc_getval, idA, vb))
    print("[A10] destroy-again -> " .. call(sc_destroy, idA))
end

print("--- B: id reuse and generation ---")
local ids = {}
for i = 1, 6 do
    local ok, rv, id = init(1)
    ids[i] = id
    print(string.format("[B%d] init id=%s rv=%s", i, tostring(id), ok and q(rv) or "fail"))
end
for i = 1, 6 do
    if ids[i] then print(string.format("[B%d] destroy id=%s -> %s", i, tostring(ids[i]), call(sc_destroy, ids[i]))) end
end
for i = 1, 6 do
    local ok, rv, id = init(1)
    print(string.format("[B%d] reinit id=%s", i + 6, tostring(id)))
end
print("[Z] COMPLETE")
