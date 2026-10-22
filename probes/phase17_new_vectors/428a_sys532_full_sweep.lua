-- CRASH_CLASS: MODERATE
-- PROBE 428a: every command of the largest Sony handler
--
-- 307a sampled fifteen commands of 532 out of a dispatch table the dossier puts at ~70,
-- and 305a found twenty of 622's commands that skip the credential bitmap by reading it as
-- a bitfield. 532's disassembly is a jump table at a recovered address, so the reachable
-- command space is finite and small; walking all 256 with a valid page finds every command
-- that answers at all. A command that returns 0 or a non-error status is a path nobody has
-- looked at, and the sub-command byte is swept for each.

print("=== PROBE 428a: SYS 532 FULL SWEEP ===")

local SIZE = 0x800

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
local function call(num, a1, a2, a3, a4, a5, a6)
    local sc = make_syscall(num)
    local ok, rv = pcall(function()
        return sc(uint64(a1 or 0), uint64(a2 or 0), uint64(a3 or 0), uint64(a4 or 0), uint64(a5 or 0), uint64(a6 or 0))
    end)
    if not ok then return -999 end
    if type(rv) == "table" and rv.h then
        local h, l = to_num(rv.h), to_num(rv.l)
        if h >= 2147483648 then h = h - 4294967296 end
        if l >= 2147483648 then l = l - 4294967296 end
        if h == -1 and l == -1 then return -1 end
        return h * 4294967296 + l
    end
    local n = to_num(rv)
    if n >= 9223372036854775808 then n = n - 18446744073709551616 end
    return n
end
local function sgn(v)
    local h, l = 0, to_num(v)
    if type(v) == "table" then h = v.h or 0; l = v.l and to_num(v.l) or 0 end
    local x = h * 4294967296 + l
    if x >= 9223372036854775808 then x = x - 18446744073709551616 end
    return x
end
local function rd32(a)
    local v = memory.read_dword(a)
    if type(v) == "table" then return to_num(v) end
    return to_num(v)
end

local page = memory.alloc(SIZE)
local k = 0
while k < SIZE do memory.write_dword(page + k, 0); k = k + 4 end

local hits = {}
local cmd = 0
while cmd < 0x100 do
    local sub = 0
    while sub < 4 do
        memory.write_dword(page, 0)
        local rv = call(532, cmd, sub, sgn(page), 0, SIZE, 0)
        if rv ~= -1 then
            hits[#hits + 1] = string.format("cmd=0x%02X sub=%d rv=%d out=0x%X", cmd, sub, rv, rd32(page))
        end
        sub = sub + 1
    end
    cmd = cmd + 1
end
print(string.format("[A] %d hits of 1024 calls", #hits))
local i = 1
while i <= #hits do
    print("[A] " .. hits[i])
    i = i + 1
end
print("=== 428a DONE ===")
