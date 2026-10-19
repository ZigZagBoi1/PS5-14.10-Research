-- 78a: getmcontext layout harvest (ZERO crash risk, no thread creation).
-- Purpose: dump the live mcontext via syscall 78 to learn Sony's real field
-- offsets and selector values (cs/ss/rflags) needed by 78b and re-based 77a.
print("=== PROBE 78a: GETMCONTEXT LAYOUT HARVEST ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function q(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function rq(addr)
    local ok, v = pcall(function() return memory.read_qword(addr) end)
    if ok then return q(v) end
    return "READ_FAIL"
end

syscall.resolve({ sc_getpid = 20 })
print("canary_getpid=" .. tostring(syscall.sc_getpid():tonumber()))

local buf = memory.alloc(0x600)
for off = 0, 0x5FC, 4 do pcall(function() memory.write_dword(buf + off, 0) end)
print("buf=" .. tostring(buf))

local ok_call, rv = pcall(function()
    local sc = {}
    for k, v in pairs(syscall.pipe) do sc[k] = v end
    sc.syscall_no = 78
    setmetatable(sc, getmetatable(syscall.pipe))
    return sc(uint64(buf))
end)
print("[RETURNED] 78 getmcontext ok=" .. tostring(ok_call) .. " rv=" .. tostring(rv))

if ok_call and (to_num(rv) == 0) then
    print("--- qword dump (buffer-relative) ---")
    for off = 0, 0x138, 8 do
        print(string.format("  +0x%03X = %s", off, rq(buf + off)))
    end
    print("--- candidate interpretation (from 58e/76d writes) ---")
    print("  expect: +0x108 mc_len=0x480, +0x0D0 dword gate=0, +0x110 type")
    print("  harvest: cs/ss/rflags live values from the fields above")
else
    print("getmcontext unavailable or errored; rv semantics unknown")
    print("--- dump anyway (partial writes possible) ---")
    for off = 0, 0x138, 8 do
        print(string.format("  +0x%03X = %s", off, rq(buf + off)))
    end
end

local ok2, pid2 = pcall(function() return syscall.sc_getpid():tonumber() end)
print("canary2_getpid=" .. tostring(pid2))
print("=== PROBE 78a COMPLETE ===")
