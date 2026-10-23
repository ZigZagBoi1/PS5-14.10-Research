-- CRASH_CLASS: MODERATE
-- PROBE 446a: which 600-676 handlers accept an output buffer
--
-- Most of this range was only ever called with six zeros, which cannot separate "rejected
-- the arguments" from "has nothing to say". Every handler that reports information writes
-- into a caller buffer, so this calls each one with a real out buffer and a real size and
-- prints what came back. 622 is skipped: 391a showed every argument shape kills the
-- process. SIGSYS is ignored first so the unimplemented slots answer -1 instead of killing.

print("=== PROBE 446a: OUT-BUFFER SWEEP 600-676 ===")

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
local function fmt(v)
    if v == -999 then return "EXC" end
    return string.format("%d", v)
end

local sa = call(477, 0, 0x10, 7, 0x1002, 0xFFFFFFFF, 0)
memory.write_qword(sa, 1)
print(string.format("[A] sigaction(12, SIG_IGN) = %d", call(416, 12, sa, 0)))

local out = call(477, 0, 0x1000, 7, 0x1002, 0xFFFFFFFF, 0)
local alt = call(477, 0, 0x1000, 7, 0x1002, 0xFFFFFFFF, 0)
print(string.format("[B] out=0x%X alt=0x%X", out, alt))
if out <= 0 then print("=== 446a DONE ===") return end

local function clear()
    local i = 0
    while i < 0x1000 do memory.write_qword(out + i, 0); i = i + 8 end
end

local num = 600
while num <= 676 do
    if num ~= 622 then
        clear()
        local rv = call(num, out, 0x100, alt, 0x100, 0, 0)
        local nz = 0
        local first = "0"
        local i = 0
        while i < 0x200 do
            local v = to_num(memory.read_dword(out + i))
            if v ~= 0 then
                nz = nz + 1
                if first == "0" then first = string.format("+0x%X=%08X", i, v) end
            end
            i = i + 4
        end
        if rv ~= -1 or nz > 0 then
            print(string.format("[C] %3d rv=%-11s dwords=%-3d %s", num, fmt(rv), nz, first))
        end
    end
    num = num + 1
end
print("=== 446a DONE ===")
