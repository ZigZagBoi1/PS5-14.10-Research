-- CRASH_CLASS: LOW
-- PROBE 521a: corrected MIBs that were never actually sent (pcblist / kstack / ovmmap)
--
-- Context: docs/CORRECTED_MIB_14_10_EVIDENCE.md section A: the committed
-- "tcp.pcblist blocked" verdict came from {4,1,6,1}, which walks the PF_LOCAL
-- tree, not PF_INET. The correct TCP pcblist leaf is {4,2,6,11}. Section B:
-- kern.proc.kstack is {1,14,15} and was never sent. Both handlers return
-- structures that carry kernel pointers if Sony kept the upstream shape.
-- This probe sends the corrected leaves and scans every output for
-- image-range qwords (0xFFFFFFFF8xxxxxxx).

print("=== PROBE 521a: CORRECTED MIB LEAK SWEEP ===")
print("")

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
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function q(v)
    local h, l = get_hi_lo(v)
    return string.format("0x%08X_%08X", h, l)
end

local sc_sysctl = make_syscall(202)
local sc_getpid = make_syscall(20)

local ok_p, pid_v = pcall(function() return sc_getpid() end)
local pid = 0
if ok_p then pid = to_num(pid_v) end
print("[0] pid=" .. pid)

local BUF = 0x20000
local buf = memory.alloc(BUF)
local mib = memory.alloc(32)
local olen = memory.alloc(8)

local function scan(tag, n)
    local hits = 0
    local first = {}
    local i = 0
    while i * 8 + 8 <= n and i < 8192 do
        local ok, v = pcall(function() return memory.read_qword(buf + i * 8) end)
        if not ok then break end
        local h, l = get_hi_lo(v)
        -- keep the exact value as a double only when it is representable
        if h >= 0xFFFF8000 then
            hits = hits + 1
            if #first < 6 then
                first[#first + 1] = string.format("%04X:%s", i * 8, q(v))
            end
        end
        i = i + 1
    end
    print(string.format("    %s: kptr-shaped qwords=%d", tag, hits))
    if #first > 0 then
        print("      first: " .. table.concat(first, " "))
    end
end

local function probe(name, words, want_pid)
    safe_wd(mib + 0, words[1])
    safe_wd(mib + 4, words[2])
    safe_wd(mib + 8, words[3])
    safe_wd(mib + 12, words[4] or 0)
    safe_wd(mib + 16, words[5] or 0)
    safe_wd(olen, BUF)
    -- poison a window so a short copyout is visible
    local j = 0
    while j < 0x100 do
        safe_wd(buf + j * 4, 0xC0DE0000 + j)
        j = j + 1
    end
    local ok, ret = pcall(function()
        return sc_sysctl(uint64(mib), uint64(#words), uint64(buf),
            uint64(olen), uint64(0), uint64(0))
    end)
    local rv = -999
    if ok then rv = to_num(ret) end
    local len = 0
    do
        local ok2, lv = pcall(function() return memory.read_qword(olen) end)
        if ok2 then
            local h, l = get_hi_lo(lv)
            len = l
            if h ~= 0 then len = -1 end
        end
    end
    print(string.format("[%s] ret=%s len=%s", name, tostring(rv), tostring(len)))
    if ok and len > 0 and len <= BUF then
        scan(name, len)
        local d0 = 0
        local ok3, v3 = pcall(function() return memory.read_dword(buf) end)
        if ok3 then d0 = to_num(v3) end
        print(string.format("    head: %08X %08X %08X %08X",
            d0,
            to_num((function() local a, b = pcall(function() return memory.read_dword(buf + 4) end); if a then return b end; return 0 end)()),
            to_num((function() local a, b = pcall(function() return memory.read_dword(buf + 8) end); if a then return b end; return 0 end)()),
            to_num((function() local a, b = pcall(function() return memory.read_dword(buf + 12) end); if a then return b end; return 0 end)())))
    end
    return rv, len
end

-- make sure the tcp table has at least one entry
local sc_socket = make_syscall(97)
local ok_s, fd = pcall(function() return sc_socket(uint64(2), uint64(1), uint64(0)) end)
print("[0] socket(AF_INET, SOCK_STREAM) fd=" .. (ok_s and to_num(fd) or -999))

print("[A] net.inet.tcp.pcblist {4,2,6,11}")
probe("A-tcp-pcblist", {4, 2, 6, 11})

print("[B] net.inet.tcp.pcblist {4,2,6,11,0}")
probe("B-tcp-pcblist5", {4, 2, 6, 11, 0})

print("[C] net.inet.udp.pcblist {4,2,17,1}")
probe("C-udp-pcblist", {4, 2, 17, 1})

print("[D] net.inet.raw.pcblist {4,2,255,1}")
probe("D-raw-pcblist", {4, 2, 255, 1})

print("[E] kern.proc.kstack {1,14,15,pid}")
probe("E-kstack", {1, 14, 15, pid})

print("[F] kern.proc.ovmmap {1,14,13,pid}")
probe("F-ovmmap", {1, 14, 13, pid})

print("[G] kern.proc.ofiledesc {1,14,14,pid}")
probe("G-ofiledesc", {1, 14, 14, pid})

print("[H] kern.proc.pid {1,14,1,pid}")
probe("H-kinfo", {1, 14, 1, pid})

print("")
print("=== PROBE 521a DONE ===")
