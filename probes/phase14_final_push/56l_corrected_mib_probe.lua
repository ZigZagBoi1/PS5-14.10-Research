-- CRASH_CLASS: LOW
-- PROBE 56l: corrected-MIB retest + ktimer differential (14.10)
--
-- Context: committed "blocked" verdicts for TCP pcblist and kernel stacks
-- rest on sysctl MIBs that are wrong under upstream FreeBSD releng/9.0:
--   - pcblist was probed as {4,1,6,1} (AF_UNIX tree), never {4,2,6,11}
--     (AF_INET, TCPCTL_PCBLIST). See 42h2 STEP 6 and STRATEGY.md.
--   - kstack was probed as leaves 9/35/36/38/42, never leaf 15
--     (KERN_PROC_KSTACK). Leaf 35 is absent from the upstream OID table;
--     56i3's leaf-35 query returned ret=0 len=0, the same signature as
--     "blocked/empty".
-- This probe sends the CORRECT leaves and echoes each MIB back from its
-- own buffer so the capture attributes the result to the right query.
-- It also runs a ktimer differential: upstream numbers 236 as
-- ktimer_delete (1 arg) and 237 as ktimer_settime (4 args), transposed
-- from 42a's labels. The probe decides from observed returns only.
--
-- Sections:
--   [B] TCP pcblist {4,2,6,11}: size query, data read, kernel-band scan
--   [C] kstack {1,14,15,pid}: size query, record parse (tid/state/tracelen)
--   [D] ktimer differential: 237-as-settime then 236-as-delete, each on a
--       fresh timer, each followed by an agreed-meaning gettime (238)
--
-- No exploit attempt. Read-only except for creating/arm/deleting its own
-- POSIX timers (same footprint as 42a).

print("=== PROBE 56l: CORRECTED MIB RETEST + KTIMER DIFFERENTIAL ===")
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
local function safe_rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(val) end
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function hexval(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000 and h < 0xFFFFFFFF
end

print("[A] Setup")
local sc_getpid = make_syscall(20)
local our_pid = 0
pcall(function() our_pid = to_num(sc_getpid()) end)
print("  PID: " .. our_pid)
local sc_sysctl = make_syscall(202)

-- Send one sysctl MIB: size query first, then a bounded data read.
-- mib_vals: array of ints. Returns ret_size, needed, ret_data, got, outbuf.
-- When the size query ends the call early, ret_data carries ret_size: a
-- successful size query with zero length IS the ret=0 len=0 EMPTY signature
-- (56i3's leaf-35 shape), while a failed size query keeps its nonzero
-- return and routes to the refused branch. The capture always shows the
-- size-query line, so both shapes stay attributed to the echoed MIB.
local function sysctl_query(mib_vals, max_bytes)
    local n = #mib_vals
    local mib = memory.alloc(32)
    for i = 1, n do safe_wd(mib + (i - 1) * 4, mib_vals[i]) end
    -- Echo the MIB back from our own buffer for capture attribution.
    local echo = {}
    for i = 1, n do echo[i] = tostring(safe_rd(mib + (i - 1) * 4) or -999) end
    print("  MIB sent: {" .. table.concat(echo, ",") .. "}")

    local oldlenp = memory.alloc(8)
    safe_wd(oldlenp, 0)
    safe_wd(oldlenp + 4, 0)
    local ok1, ret1 = pcall(function()
        return sc_sysctl(uint64(mib), uint64(n), uint64(0),
            uint64(oldlenp), uint64(0), uint64(0))
    end)
    local ret_size = ok1 and to_num(ret1) or -999
    local needed = safe_rd(oldlenp) or 0
    print("  size query ret=" .. ret_size .. " needed=" .. needed)

    if ret_size ~= 0 or needed <= 0 then
        return ret_size, needed, ret_size, 0, nil
    end
    local alloc_sz = needed
    local truncated = false
    if alloc_sz > max_bytes then alloc_sz, truncated = max_bytes, true end
    local outbuf = memory.alloc(alloc_sz)
    for i = 0, alloc_sz - 1, 4 do safe_wd(outbuf + i, 0) end
    safe_wd(oldlenp, alloc_sz)
    safe_wd(oldlenp + 4, 0)
    local ok2, ret2 = pcall(function()
        return sc_sysctl(uint64(mib), uint64(n), uint64(outbuf),
            uint64(oldlenp), uint64(0), uint64(0))
    end)
    local ret_data = ok2 and to_num(ret2) or -999
    local got = safe_rd(oldlenp) or 0
    print("  data ret=" .. ret_data .. " got=" .. got ..
        (truncated and " (capped at " .. max_bytes .. ")" or ""))
    return ret_size, needed, ret_data, got, outbuf
end

-- ============================================================
-- [B] TCP pcblist, correct leaf: {4,2,6,11}
-- Upstream: CTL_NET=4, AF_INET=2, IPPROTO_TCP=6, TCPCTL_PCBLIST=11.
-- Prior art sent {4,1,6,1} (AF_UNIX tree) and recorded "blocked".
-- ============================================================
print("")
print("[B] TCP pcblist {4,2,6,11}")
local _, b_needed, b_ret, b_got, b_buf =
    sysctl_query({ 4, 2, 6, 11 }, 0x4000)
if b_ret == 0 and b_got > 0 and b_buf ~= nil then
    local hits = 0
    for off = 0, b_got - 1, 8 do
        local val = safe_rq(b_buf + off)
        if val and is_kptr(val) then
            hits = hits + 1
            if hits <= 12 then
                print(string.format("  +0x%04X: %s KPTR!", off, hexval(val)))
            end
        end
    end
    print("  pcblist kernel-band qwords: " .. hits .. " in " .. b_got .. " bytes")
elseif b_ret == 0 and b_got == 0 then
    print("  EMPTY: ret=0 len=0 — same signature as 56i3's leaf-35 false negative;")
    print("  MIB echo above attributes this result to {4,2,6,11}.")
else
    print("  no data (refused or size query failed)")
end
print("  [B] COMPLETE")

-- ============================================================
-- [C] kernel stacks, correct leaf: {1,14,15,pid}
-- Upstream: CTL_KERN=1, KERN_PROC=14, KERN_PROC_KSTACK=15.
-- Record: struct kinfo_kstack, KINFO_KSTACK_SIZE=1096 bytes:
--   +0x00 lwpid_t tid (32-bit), +0x04 int state (0 STACKOK, 1 SWAPPED,
--   2 RUNNING), +0x08 char trace[1024] (symbol names, NOT pointers),
--   then 64 bytes of spare. The probe only reads tid/state/trace.
-- ============================================================
print("")
print("[C] kstack {1,14,15,pid}")
local state_name = { [0] = "STACKOK", [1] = "SWAPPED", [2] = "RUNNING" }
local _, c_needed, c_ret, c_got, c_buf =
    sysctl_query({ 1, 14, 15, our_pid }, 0x8000)
if c_ret == 0 and c_got > 0 and c_buf ~= nil then
    local rec_size = 1096
    local nrec = math.floor(c_got / rec_size)
    print("  records: ~" .. nrec .. " (" .. c_got .. " bytes / 1096)")
    local shown = nrec
    if shown > 8 then shown = 8 end
    for r = 0, shown - 1 do
        local base = c_buf + r * rec_size
        local tid = safe_rd(base) or -999
        local st = safe_rd(base + 4) or -999
        local tlen = 0
        while tlen < 64 do
            local b = safe_rb(base + 8 + tlen)
            if b == nil or b == 0 then break end
            tlen = tlen + 1
        end
        print("  record[" .. r .. "]: tid=" .. tid .. " state=" .. st ..
            "(" .. (state_name[st] or "?") .. ") tracelen~" .. tlen)
    end
    if nrec > shown then print("  ... (" .. (nrec - shown) .. " more records)") end
elseif c_ret == 0 and c_got == 0 then
    print("  EMPTY: ret=0 len=0 — MIB echo above attributes this to {1,14,15}.")
else
    print("  no data (refused or size query failed)")
end
print("  [C] COMPLETE")

-- ============================================================
-- [D] ktimer numbering differential.
-- Upstream releng/9.0 syscalls.master: 236=ktimer_delete (1 arg),
-- 237=ktimer_settime (4 args). 42a labels them transposed.
-- Each sub-test uses a FRESH timer and ends with gettime (238),
-- whose number and arity both sides agree on.
-- ============================================================
print("")
print("[D] ktimer numbering differential")
local sc_create = make_syscall(235)
local sc_236 = make_syscall(236)
local sc_237 = make_syscall(237)
local sc_gettime = make_syscall(238)

local sevp = memory.alloc(64)
local tidp = memory.alloc(8)
local its = memory.alloc(16)
local its2 = memory.alloc(32)
local function zero(b, n)
    for i = 0, n - 1, 8 do safe_wq(b + i, 0) end
end
local function new_timer(clk)
    zero(sevp, 64)
    safe_wq(tidp, 0xFFFFFFFF)
    local ok, rv = pcall(function() return sc_create(clk, sevp, tidp) end)
    local r = ok and to_num(rv) or -999
    local id = safe_rd(tidp) or -999
    return r, id
end
local function gettime(id)
    zero(its2, 32)
    local ok, rv = pcall(function() return sc_gettime(id, its2) end)
    local r = ok and to_num(rv) or -999
    local sec = safe_rq(its2 + 8)
    return r, sec and to_num(sec) or 0
end

-- D1: call 237 with 4 settime-shaped args (1s one-shot) on fresh timer A.
local rcA, idA = new_timer(0)
print("  D1 create: rv=" .. rcA .. " id=" .. idA)
local r237 = -999
if rcA == 0 then
    zero(its, 16)
    safe_wq(its + 8, 1) -- it_value.tv_sec = 1
    local ok, rv = pcall(function() return sc_237(idA, 0, its, its2) end)
    r237 = ok and to_num(rv) or -999
end
print("  D1 237(id,0,its,its2): rv=" .. r237)
local rgA, secA = -999, 0
if rcA == 0 then rgA, secA = gettime(idA) end
print("  D1 gettime: rv=" .. rgA .. " remaining_sec=" .. secA)
if rcA == 0 and r237 == 0 and rgA == 0 and secA > 0 then
    print("  D1 VERDICT: D1: 237=SETTIME — 4-arg call armed the timer")
    print("  (consistent with upstream 237=ktimer_settime)")
elseif rcA == 0 and r237 == 0 and rgA ~= 0 then
    print("  D1 VERDICT: D1: 237=DELETE — timer gone after the 237 call")
    print("  (consistent with 42a 237=delete)")
else
    print("  D1 VERDICT: D1: INCONCLUSIVE")
end

-- D2: call 236 with 1 delete-shaped arg on fresh timer B.
local rcB, idB = new_timer(0)
print("  D2 create: rv=" .. rcB .. " id=" .. idB)
local r236 = -999
if rcB == 0 then
    local ok, rv = pcall(function() return sc_236(idB) end)
    r236 = ok and to_num(rv) or -999
end
print("  D2 236(id): rv=" .. r236)
local rgB = -999
if rcB == 0 then rgB, _ = gettime(idB) end
print("  D2 gettime: rv=" .. rgB)
if rcB == 0 and r236 == 0 and rgB ~= 0 then
    print("  D2 VERDICT: D2: 236=DELETE — 1-arg call removed the timer")
    print("  (consistent with upstream 236=ktimer_delete)")
elseif rcB == 0 and rgB == 0 then
    print("  D2 VERDICT: D2: 236=SETTIME-4ARG — timer survives the 1-arg call")
    print("  (consistent with 42a 236=settime-needs-4-args)")
else
    print("  D2 VERDICT: D2: INCONCLUSIVE")
end
print("  [D] COMPLETE")

print("")
print("=== 56l DONE ===")
