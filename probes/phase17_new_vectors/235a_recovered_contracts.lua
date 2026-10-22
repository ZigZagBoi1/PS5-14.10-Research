-- CRASH_CLASS: MODERATE
-- PROBE 235a: run the recovered 13.60 argument contracts for 657/659/660/662-664
--
-- Context: every earlier sweep of these numbers passed six zero uint64s. The
-- 13.60 decompile in results/kernel_handlers/decompiled/ carries analyst
-- recovered ABI views, and they show those calls were malformed:
--   659  { handles_out, capacity, count_out }        capacity 0 -> error 12
--   660  { module_handle, pad, info_inout }          info_inout[0] must be 0x160
--   662  { ids, count, results }                     count must be 1..128
--   663  { ids, count, states, mode, timeout }       count 1..128, mode 0..2
--   664  { ids, count, states }                      count must be 1..128
--   657  { commands, count, processed, flags }       32-byte records, opcode 1..5
-- So "-1" on 662-664 may have been the count check, not a missing handler, and
-- 657 (batch VM operations: address, length, protection, memory_type) has never
-- been called with a real record. 657's protection update is the interesting
-- one: it is a VM path that does not go through mprotect.
--
-- Oracles: 659 -> returned handle count and handles; 660 -> module name,
-- segment address/size/protection (kernel VA check on the addresses);
-- 662-664 -> a per-item status (0x80020003 = bad id) instead of a bare -1;
-- 657 -> the protection field of the region in sys 674 before and after.

print("=== PROBE 235a: RECOVERED ARGUMENT CONTRACTS ===")
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
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X_%08X", h, l)
end
local function kernelish(val)
    local h = get_hi_lo(val)
    return h >= 0xFFFF8000
end

local sc20 = make_syscall(20)
local sc657 = make_syscall(657)
local sc659 = make_syscall(659)
local sc660 = make_syscall(660)
local sc662 = make_syscall(662)
local sc663 = make_syscall(663)
local sc664 = make_syscall(664)
local sc674 = make_syscall(674)

local okpid, pidv = pcall(function() return sc20() end)
local pid = to_num(pidv)
print("PID: " .. pid)

-- ============================================================
-- [A] 659: enumerate module handles
-- ============================================================
print("")
print("[A] 659 { handles_out, capacity, count_out }")

local CAP = 64
local hbuf = memory.alloc(CAP * 4 + 0x100)
local cbuf = memory.alloc(0x40)
for i = 0, (CAP * 4 + 0xFF) / 4 - 1 do safe_wd(hbuf + i * 4, 0) end
safe_wq(cbuf, 0)

local okA, retA = pcall(function()
    return sc659(uint64(hbuf), uint64(CAP), uint64(cbuf))
end)
print(string.format("  ret=%s count=%s", tostring(retA), hexval(safe_rq(cbuf))))
local handles = {}
if okA then
    for i = 0, 15 do
        local hv = safe_rd(hbuf + i * 4)
        if hv and hv ~= 0 then
            handles[#handles + 1] = hv
            print(string.format("  handle[%d] = 0x%X", i, hv))
        end
    end
end
print("  handles found: " .. #handles)

-- ============================================================
-- [B] 660: module info for the first handles (size gate 0x160)
-- ============================================================
print("")
print("[B] 660 { module_handle, pad, info_inout }  size gate 0x160")

for i = 1, math.min(#handles, 4) do
    local info = memory.alloc(0x200)
    for j = 0, 0x200 / 4 - 1 do safe_wd(info + j * 4, 0) end
    safe_wq(info, 0x160)
    local okB, retB = pcall(function()
        return sc660(uint64(handles[i]), uint64(0), uint64(info))
    end)
    local size = safe_rq(info)
    local name = ""
    for k = 0, 31 do
        local ch = safe_rd(info + 8 + k)
        if ch and ch >= 32 and ch < 127 then
            name = name .. string.char(ch)
        elseif ch == 0 then
            break
        end
    end
    local segcount = safe_rd(info + 8 + 256 + 4 * 24)
    print(string.format("  handle 0x%X ret=%s size=%s segcount=%s name=%q",
        handles[i], tostring(retB), hexval(size), tostring(segcount), name))
    if segcount and segcount > 0 and segcount < 8 then
        for s = 0, segcount - 1 do
            local base = info + 8 + 256 + s * 24
            local addr = safe_rq(base)
            local sz = safe_rd(base + 8)
            local prot = safe_rd(base + 12)
            print(string.format("    seg[%d] addr=%s size=0x%X prot=0x%X%s",
                s, hexval(addr), sz or 0, prot or 0,
                kernelish(addr) and "  <<< KERNEL VA" or ""))
        end
    end
end

-- ============================================================
-- [C] 662/663/664: one id, count=1
-- ============================================================
print("")
print("[C] AIO multi delete/wait/poll with count=1 (id 0)")

local ids = memory.alloc(0x40)
local states = memory.alloc(0x40)
local timeout = memory.alloc(0x40)
safe_wd(ids, 0)
for j = 0, 15 do
    safe_wd(states + j * 4, 0xDEADBEEF)
    safe_wd(timeout + j * 4, 0)
end

local okC1, retC1 = pcall(function()
    return sc662(uint64(ids), uint64(1), uint64(states))
end)
print(string.format("  662 count=1 ret=%s results[0]=0x%X", tostring(retC1), safe_rd(states) or 0))

local okC2, retC2 = pcall(function()
    return sc664(uint64(ids), uint64(1), uint64(states))
end)
print(string.format("  664 count=1 ret=%s states[0]=0x%X", tostring(retC2), safe_rd(states) or 0))

local okC3, retC3 = pcall(function()
    return sc663(uint64(ids), uint64(1), uint64(states), uint64(0), uint64(timeout))
end)
print(string.format("  663 count=1 mode=0 ret=%s states[0]=0x%X", tostring(retC3), safe_rd(states) or 0))

-- ============================================================
-- [D] 657: batch VM operations, 32-byte records
-- ============================================================
print("")
print("[D] 657 { commands, count, processed, flags } 32-byte records")

local STRIDE674 = 72
local MAXREC = 512
local vmbuf = memory.alloc(STRIDE674 * MAXREC + 0x100)

local function region_prot(addr)
    local okv, retv = pcall(function()
        return sc674(uint64(vmbuf), uint64(STRIDE674), uint64(MAXREC))
    end)
    if not okv then return nil, "call-failed" end
    local lo = get_hi_lo(addr)
    for i = 0, MAXREC - 1 do
        local base = vmbuf + i * STRIDE674
        local startq = safe_rq(base)
        if startq == nil then break end
        local sh, sl = get_hi_lo(startq)
        local endq = safe_rq(base + 8)
        local eh, el = get_hi_lo(endq)
        if sh == 0 and eh == 0 and sl == 0 and el == 0 then break end
        if sh == 0 and lo >= sl and lo < el then
            return safe_rd(base + 0x18), string.format("0x%X-0x%X", sl, el)
        end
    end
    return nil, "not-found"
end

local sc74 = make_syscall(74)
local sc477 = make_syscall(477)
local anon = sc477(uint64(0), uint64(0x4000), uint64(0x33), uint64(0xFFFFFFFF), uint64(0xFFFFFFFF), uint64(0))
local anon_lo = get_hi_lo(anon)
local gpu = sc477(uint64(0), uint64(0x4000), uint64(0x33), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local gpu_lo = get_hi_lo(gpu)
print(string.format("  anon mmap = %s   gpu mmap = %s", hexval(anon), hexval(gpu)))

local pages = { { "anon", anon_lo }, { "gpu", gpu_lo } }
for _, pg in ipairs(pages) do
    local pname, paddr = pg[1], pg[2]
    if paddr and paddr ~= 0 then
        local p0, r0 = region_prot(paddr)
        print(string.format("  [%s] before: prot=%s (%s)", pname, tostring(p0), tostring(r0)))
        for op = 1, 5 do
            local rec = memory.alloc(0x60)
            for j = 0, 0x60 / 4 - 1 do safe_wd(rec + j * 4, 0) end
            safe_wd(rec + 0x00, op)
            safe_wq(rec + 0x08, paddr)
            safe_wq(rec + 0x10, 0x4000)
            safe_wd(rec + 0x18, 7)
            safe_wd(rec + 0x1C, 0)
            local processed = memory.alloc(0x20)
            safe_wd(processed, 0xAAAAAAAA)
            local okD, retD = pcall(function()
                return sc657(uint64(rec), uint64(1), uint64(processed), uint64(0))
            end)
            local p1, r1 = region_prot(paddr)
            print(string.format("    op=%d ret=%s processed=0x%X prot=%s (%s)",
                op, tostring(retD), safe_rd(processed) or 0, tostring(p1), tostring(r1)))
        end
        local mret = sc74(uint64(paddr), uint64(0x4000), uint64(7))
        print(string.format("    mprotect(RWX) after = %s", tostring(mret)))
    end
end

print("")
print("=== PROBE 235a COMPLETE ===")
