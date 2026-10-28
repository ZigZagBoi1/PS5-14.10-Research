-- CRASH_CLASS: LOW
-- PROBE 71a: AIO ID reuse analysis — determines if 3-thread UAF is viable
--
-- 70e proved: concurrent 662 double-delete = double-STATUS, NOT double-free.
-- The D exclusive lock serializes the actual free; Thread B finds the slot
-- cleared and skips entry_dispose.
--
-- The ONLY remaining path to real UAF:
--   Thread A: delete → frees R/I/Q, clears slot, releases D excl lock
--   Thread C: submit → fills same slot with new request
--   Thread B: re-reads slot → finds Thread C's I → frees it (real UAF!)
--
-- BUT: if AIO IDs use generation checking (like EVF/namedobj handles:
-- generation << 13 | slot), Thread B's old-generation ID won't match
-- Thread C's new entry, and the attack is impossible.
--
-- This probe answers: are AIO IDs generation-checked?
-- All sections are LOW risk (just submit/poll/delete from main thread).

print("=== PROBE 71a: AIO ID REUSE ANALYSIS ===")
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

local pid = N(mk(20)())
print("pid=" .. pid)

-- Open /dev/zero
local zero_path = memory.alloc(16)
for c = 1, 9 do pcall(function() memory.write_byte(zero_path + c - 1, string.byte("/dev/zero", c)) end) end
pcall(function() memory.write_byte(zero_path + 9, 0) end)
local ok, zfd_v = pcall(function() return mk(5)(uint64(N(zero_path)), uint64(0)) end)
local zfd = N(zfd_v)
print("zero_fd=" .. zfd)

local data_buf = memory.alloc(256)
local result_buf = memory.alloc(8)

-- Helper: submit one AIO request
local function aio_submit(fd)
    local req = memory.alloc(0x28)
    wq(req + 0x00, uint64(0))
    wq(req + 0x08, uint64(16))
    wq(req + 0x10, uint64(N(data_buf)))
    wq(req + 0x18, uint64(N(result_buf)))
    wq(req + 0x20, uint64(fd))
    local ids_buf = memory.alloc(8)
    wd(ids_buf, 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(req)), uint64(1), uint64(1), uint64(N(ids_buf)))
    end)
    return rd(ids_buf) or 0
end

-- Helper: poll one AIO ID
local function aio_poll(aid)
    local ids_buf = memory.alloc(8)
    local st_buf = memory.alloc(8)
    wd(ids_buf, aid)
    wd(st_buf, 0xDEAD)
    pcall(function() mk(664)(uint64(N(ids_buf)), uint64(1), uint64(N(st_buf))) end)
    return rd(st_buf)
end

-- Helper: delete one AIO ID
local function aio_delete(aid)
    local ids_buf = memory.alloc(8)
    local st_buf = memory.alloc(8)
    wd(ids_buf, aid)
    wd(st_buf, 0xDEAD)
    pcall(function() mk(662)(uint64(N(ids_buf)), uint64(1), uint64(N(st_buf))) end)
    return rd(st_buf)
end

-- Helper: status via 666
local function aio_status(aid)
    local ids_buf = memory.alloc(8)
    local st_buf = memory.alloc(8)
    wd(ids_buf, aid)
    wd(st_buf, 0xDEAD)
    pcall(function() mk(666)(uint64(N(ids_buf)), uint64(1), uint64(N(st_buf))) end)
    return rd(st_buf)
end

print("")

-- ============================================================
-- [A] SEQUENTIAL ID REUSE: submit, poll, delete, re-submit x20
-- ============================================================
print("[A] Sequential ID reuse test (submit/poll/delete/re-submit x20)")

local seq_ids = {}
for trial = 1, 20 do
    local aid = aio_submit(zfd)
    seq_ids[#seq_ids + 1] = aid
    aio_poll(aid)
    aio_delete(aid)
end

for i, aid in ipairs(seq_ids) do
    print(string.format("  [%2d] id=0x%08X", i, aid))
end

local reuse = 0
for i = 2, #seq_ids do
    if seq_ids[i] == seq_ids[i-1] then reuse = reuse + 1 end
end
print(string.format("  consecutive_reuse=%d/19", reuse))
print("")

-- ============================================================
-- [B] BATCH ID PATTERN: submit 16, examine structure
-- ============================================================
print("[B] Batch ID pattern (submit 16, examine structure)")

local batch = {}
for i = 1, 16 do
    batch[#batch + 1] = aio_submit(zfd)
end

for i, aid in ipairs(batch) do
    -- Try different decompositions
    local low13 = aid % 8192
    local hi = math.floor(aid / 8192)
    local low8 = aid % 256
    local mid = math.floor(aid / 256) % 256
    local top = math.floor(aid / 65536)
    print(string.format("  [%2d] id=0x%08X  lo13=%d hi=%d  | byte: %02X.%02X.%04X",
        i, aid, low13, hi, low8, mid, top))
end

-- Poll and delete all
for _, aid in ipairs(batch) do aio_poll(aid) end
for _, aid in ipairs(batch) do aio_delete(aid) end
print("")

-- ============================================================
-- [C] REUSE AFTER BATCH DELETE: submit 16 new, compare to old
-- ============================================================
print("[C] Reuse after batch delete (submit 16 new)")

local batch2 = {}
for i = 1, 16 do
    batch2[#batch2 + 1] = aio_submit(zfd)
end

local slot_reuse = 0
for i = 1, math.min(#batch, #batch2) do
    local match = (batch[i] == batch2[i]) and "SAME" or "diff"
    if batch[i] == batch2[i] then slot_reuse = slot_reuse + 1 end
    print(string.format("  old=0x%08X  new=0x%08X  %s", batch[i], batch2[i], match))
end
print(string.format("  slot_reuse=%d/%d", slot_reuse, #batch))

for _, aid in ipairs(batch2) do aio_poll(aid) end
for _, aid in ipairs(batch2) do aio_delete(aid) end
print("")

-- ============================================================
-- [D] CROSS-GENERATION ACCESS: can old ID see new entry?
-- ============================================================
print("[D] Cross-generation access test")

-- Test 1: 666 (status query) with old ID
local d_id1 = aio_submit(zfd)
aio_poll(d_id1)
aio_delete(d_id1)

local d_id2 = aio_submit(zfd)
aio_poll(d_id2)

local old_st = aio_status(d_id1)
local new_st = aio_status(d_id2)
print(string.format("  666: old_id=0x%X→0x%08X  new_id=0x%X→0x%08X",
    d_id1, old_st or 0, d_id2, new_st or 0))

-- Test 2: 662 (delete) with old ID — does it affect new entry?
local d_id3 = aio_submit(zfd)
aio_poll(d_id3)
aio_delete(d_id3)

local d_id4 = aio_submit(zfd)
aio_poll(d_id4)

-- Delete with OLD id
local old_del = aio_delete(d_id3)
-- Check new id still valid
local new_check = aio_status(d_id4)
print(string.format("  662: delete(old=0x%X)=0x%08X  666(new=0x%X)=0x%08X",
    d_id3, old_del or 0, d_id4, new_check or 0))

if d_id1 == d_id2 then
    print("")
    print("  *** IDs reuse EXACTLY — no generation counter! ***")
    print("  *** 3-thread UAF attack IS VIABLE ***")
    print("  *** old ID and new ID are indistinguishable ***")
elseif (old_st ~= 0xDEAD and old_st ~= 0x80020003) then
    print("")
    print("  *** OLD ID still resolves to data (not dead)! ***")
    print("  *** Generation NOT checked on read path ***")
elseif new_check == 0x80020003 or new_check == 0xDEAD then
    print("")
    print("  *** OLD ID DELETE destroyed NEW entry! ***")
    print("  *** Cross-generation delete WORKS ***")
else
    print("")
    print("  IDs are generation-checked: old ID is dead, new entry unaffected")
    print("  3-thread UAF via slot-reuse is BLOCKED")
end

aio_delete(d_id4)
print("")

-- ============================================================
-- [E] GENERATION INCREMENT PATTERN (if applicable)
-- ============================================================
print("[E] Generation increment pattern")
print("    Submit/delete same slot 8 times, track ID changes")

local gen_ids = {}
for i = 1, 8 do
    local aid = aio_submit(zfd)
    gen_ids[#gen_ids + 1] = aid
    aio_poll(aid)
    aio_delete(aid)
end

-- Compute deltas
for i = 1, #gen_ids do
    local delta = 0
    if i > 1 then delta = gen_ids[i] - gen_ids[i-1] end
    print(string.format("  [%d] id=0x%08X  delta=%+d", i, gen_ids[i], delta))
end

-- Check if deltas are consistent
local deltas = {}
for i = 2, #gen_ids do
    deltas[#deltas + 1] = gen_ids[i] - gen_ids[i-1]
end
local all_same = true
for i = 2, #deltas do
    if deltas[i] ~= deltas[1] then all_same = false end
end
if #deltas > 0 then
    if all_same and deltas[1] == 0 then
        print("  CONCLUSION: zero delta — exact ID reuse, NO generation")
    elseif all_same and deltas[1] > 0 then
        print(string.format("  CONCLUSION: constant delta=%d — generation counter increments by %d",
            deltas[1], deltas[1]))
        print(string.format("  generation bits start at bit %d", math.floor(math.log(deltas[1]) / math.log(2))))
    else
        print("  CONCLUSION: variable deltas — complex allocation pattern")
    end
end
print("")

-- ============================================================
-- [F] MULTI-SLOT INTERLEAVE: submit 4, delete odds, re-submit
-- ============================================================
print("[F] Multi-slot interleave")
print("    Submit 4, delete #1 and #3, re-submit 2 → see which slots fill")

local f_ids = {}
for i = 1, 4 do f_ids[#f_ids + 1] = aio_submit(zfd) end
for _, aid in ipairs(f_ids) do aio_poll(aid) end

-- Delete #1 and #3
aio_delete(f_ids[1])
aio_delete(f_ids[3])
print(string.format("  original: %08X %08X %08X %08X", f_ids[1], f_ids[2], f_ids[3], f_ids[4]))
print(string.format("  deleted:  %08X (slot 1)  %08X (slot 3)", f_ids[1], f_ids[3]))

-- Submit 2 new
local f_new1 = aio_submit(zfd)
local f_new2 = aio_submit(zfd)
print(string.format("  new IDs:  %08X  %08X", f_new1, f_new2))

-- Do new IDs match deleted slots?
if f_new1 == f_ids[3] or f_new1 == f_ids[1] then
    print(string.format("  new1 matches deleted slot! (LIFO? got slot %s)",
        f_new1 == f_ids[3] and "3" or "1"))
end
if f_new2 == f_ids[1] or f_new2 == f_ids[3] then
    print(string.format("  new2 matches deleted slot! (LIFO? got slot %s)",
        f_new2 == f_ids[1] and "1" or "3"))
end

-- Check if old deleted IDs can access new entries
local f_check1 = aio_status(f_ids[1])
local f_check3 = aio_status(f_ids[3])
print(string.format("  666(old_id1=0x%X)=0x%08X", f_ids[1], f_check1 or 0))
print(string.format("  666(old_id3=0x%X)=0x%08X", f_ids[3], f_check3 or 0))

if (f_check1 ~= 0x80020003 and f_check1 ~= 0xDEAD) or
   (f_check3 ~= 0x80020003 and f_check3 ~= 0xDEAD) then
    print("  *** OLD DELETED ID SEES NEW DATA ***")
end

-- Cleanup
aio_poll(f_new1); aio_poll(f_new2)
aio_delete(f_ids[2]); aio_delete(f_ids[4])
aio_delete(f_new1); aio_delete(f_new2)
print("")

print("alive=YES")
print("=== PROBE 71a COMPLETE ===")
