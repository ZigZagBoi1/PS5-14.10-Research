-- CRASH_CLASS: LOW
-- PROBE 396b: scan IPv6 setsockopt options 1-70
--
-- Find which IPV6 options are available on 14.10 for race targets.
-- Test both set (with 4-byte and 64-byte buffers) and get.
-- The interesting ones are buffer-allocating options (RTHDR, HOPOPTS, DSTOPTS)

print("=== PROBE 396b: ipv6 opt scan ===")

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
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- socket(AF_INET6=28, SOCK_DGRAM=2, 0)
local ok_s, rv_s = pcall(function()
    return mk(97)(uint64(28), uint64(2), uint64(0))
end)
local sock = ok_s and N(rv_s) or -1
print(string.format("sock=%d", sock))
if sock < 0 then print("FAIL"); return end

local buf4 = memory.alloc(8)
local buf64 = memory.alloc(128)
local lenp = memory.alloc(8)

-- setsockopt = 105, getsockopt = 118
-- IPPROTO_IPV6 = 41
local LEVEL = 41

local accept_set4 = {}
local accept_set64 = {}
local accept_get = {}

for opt = 1, 70 do
    -- Try set with 4 bytes (integer options)
    wd(N(buf4), 1)
    local ok1, rv1 = pcall(function()
        return mk(105)(uint64(sock), uint64(LEVEL), uint64(opt), buf4, uint64(4))
    end)
    local r1 = ok1 and N(rv1) or -999

    -- Try set with 64 bytes (buffer options)
    for i = 0, 60, 4 do wd(N(buf64) + i, 0) end
    local ok2, rv2 = pcall(function()
        return mk(105)(uint64(sock), uint64(LEVEL), uint64(opt), buf64, uint64(64))
    end)
    local r2 = ok2 and N(rv2) or -999

    -- Try get
    wq(lenp, uint64(128))
    for i = 0, 124, 4 do wd(N(buf64) + i, 0xCC) end
    local ok3, rv3 = pcall(function()
        return mk(118)(uint64(sock), uint64(LEVEL), uint64(opt), buf64, lenp)
    end)
    local r3 = ok3 and N(rv3) or -999
    local glen = rd(N(lenp)) or 0

    local tag = ""
    if r1 == 0 then tag = tag .. "s4 "; accept_set4[#accept_set4 + 1] = opt end
    if r2 == 0 then tag = tag .. "s64 "; accept_set64[#accept_set64 + 1] = opt end
    if r3 == 0 then tag = tag .. "g" .. glen .. " "; accept_get[#accept_get + 1] = opt end

    if tag ~= "" then
        print(string.format("  opt %2d: set4=%2d set64=%2d get=%2d glen=%d  [%s]",
            opt, r1, r2, r3, glen, tag))
    end

    if not alive() then
        print(string.format("DEAD at opt %d!", opt))
        break
    end
end

print(string.format("set4=%d set64=%d get=%d", #accept_set4, #accept_set64, #accept_get))

-- Also scan SOL_SOCKET=0xFFFF for comparison
print("")
print("-- SOL_SOCKET buffer options --")
local SOL = 0xFFFF
for _, opt in ipairs({0x1007, 0x1009, 0x100A, 0x100B, 0x100C, 0x100D, 0x1015}) do
    wd(N(buf4), 1)
    local ok1, rv1 = pcall(function()
        return mk(105)(uint64(sock), uint64(SOL), uint64(opt), buf4, uint64(4))
    end)
    wq(lenp, uint64(128))
    local ok2, rv2 = pcall(function()
        return mk(118)(uint64(sock), uint64(SOL), uint64(opt), buf64, lenp)
    end)
    local glen = rd(N(lenp)) or 0
    local r1 = ok1 and N(rv1) or -999
    local r2 = ok2 and N(rv2) or -999
    if r1 == 0 or r2 == 0 then
        print(string.format("  SOL opt 0x%04X: set=%2d get=%2d glen=%d", opt, r1, r2, glen))
    end
end

print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 396b COMPLETE ===")
