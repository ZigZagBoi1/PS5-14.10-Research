-- CRASH_CLASS: LOW
-- PROBE 548a: Deep probe of Sony syscalls 596, 604, 559 for kernel pointer leaks
--
-- 596 (dynlib_do_copy_relocations): narg=0, returned 0 with no args.
--     Nobody checked side effects. Snapshot GOT/memory before/after.
-- 604 (dl_get_metadata): never successfully run (523a had syntax error).
--     Name suggests dynlib metadata — try (handle, outbuf, outlen_ptr) like 593.
-- 559 (proc+0x5c0 free query): returns -1 with 0, returns 1 with -1.
--     Test with pid, addresses, module handles to find what it really queries.

print("=== PROBE 548a: SONY LEAK HUNT ===")
print("")

-- Standard helpers
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

-- Kernel pointer check: h >= 0xFFFF8000 (but not bitmask sentinels)
local function is_kptr(h, l)
    if h >= 0xFFFF8000 then
        if h == 0xFFFFFFFF and (l == 0 or l == 0xFFFFFFFF) then return false end
        if h == 0xFFFF8000 and l == 0 then return false end
        return true
    end
    return false
end

-- Get PID
local sc_getpid = make_syscall(20)
local ok_pid, pid_v = pcall(function() return sc_getpid() end)
local pid = ok_pid and to_num(pid_v) or 0
print("pid=" .. pid)

-- Big output buffer
local buf = memory.alloc(0x2000)
local outlen = memory.alloc(16)

-- Zero a buffer region
local function zero_buf(b, sz)
    for i = 0, sz - 4, 4 do safe_wd(b + i, 0) end
end

-- Dump buffer as hex, return non-zero count
local function dump_hex(b, sz, label)
    print("  [" .. label .. "]")
    local nonzero = 0
    for off = 0, sz - 8, 8 do
        local q = safe_rq(b + off)
        if q then
            local h, l = get_hi_lo(q)
            if h < 0 then h = h + 0x100000000 end
            if l < 0 then l = l + 0x100000000 end
            if h ~= 0 or l ~= 0 then
                nonzero = nonzero + 1
                local tag = ""
                if is_kptr(h, l) then tag = " *** KERNEL PTR ***" end
                if nonzero <= 40 then
                    print(string.format("    +%03X: %08X_%08X%s", off, h, l, tag))
                end
            end
        end
    end
    if nonzero > 40 then print("    ... " .. nonzero .. " total nonzero qwords") end
    if nonzero == 0 then print("    (all zero)") end
    return nonzero
end

-- Scan buffer for kernel pointers specifically
local function scan_kptrs(b, sz)
    local found = {}
    for off = 0, sz - 8, 8 do
        local q = safe_rq(b + off)
        if q then
            local h, l = get_hi_lo(q)
            if h < 0 then h = h + 0x100000000 end
            if l < 0 then l = l + 0x100000000 end
            if is_kptr(h, l) then
                found[#found + 1] = {off = off, h = h, l = l}
            end
        end
    end
    return found
end

-- ============================================================
-- [A] sys 596 dynlib_do_copy_relocations
-- narg=0, ret=0 last time. Check side effects on GOT entries.
-- ============================================================
print("")
print("=== [A] sys 596 dynlib_do_copy_relocations ===")

-- Get libkernel base for GOT reference
local sc_info = make_syscall(593)
local info = memory.alloc(0x200)

-- Snapshot some GOT entries from libkernel before call
-- libkernel handle = 0x2001 (standard)
safe_wd(info, 0x160)
local ok_i, _ = pcall(function() return sc_info(uint64(0x2001), uint64(info)) end)
local lk_text_lo = safe_rd(info + 0x108)
local lk_text_hi = safe_rd(info + 0x10C)
local lk_data_lo = safe_rd(info + 0x128)
local lk_data_hi = safe_rd(info + 0x12C)
if lk_text_lo then
    local th = lk_text_hi or 0
    local tl = lk_text_lo or 0
    if th < 0 then th = th + 0x100000000 end
    if tl < 0 then tl = tl + 0x100000000 end
    print(string.format("  libkernel .text: 0x%08X%08X", th, tl))
end
if lk_data_lo then
    local dh = lk_data_hi or 0
    local dl = lk_data_lo or 0
    if dh < 0 then dh = dh + 0x100000000 end
    if dl < 0 then dl = dl + 0x100000000 end
    print(string.format("  libkernel .data: 0x%08X%08X", dh, dl))
end

-- Snapshot first 256 bytes of .data (contains GOT-like entries)
local lk_data = nil
if lk_data_lo and lk_data_hi then
    lk_data = uint64(string.format("0x%X%08X",
        (lk_data_hi or 0) < 0 and (lk_data_hi + 0x100000000) or (lk_data_hi or 0),
        (lk_data_lo or 0) < 0 and (lk_data_lo + 0x100000000) or (lk_data_lo or 0)))
end

local snap_before = {}
if lk_data then
    for off = 0, 248, 8 do
        local q = safe_rq(lk_data + off)
        if q then
            local h, l = get_hi_lo(q)
            snap_before[off] = {h = h, l = l}
        end
    end
    print("  Snapped 32 qwords from libkernel .data")
end

-- Also allocate a sentinel buffer and note its state
local sentinel = memory.alloc(0x100)
for i = 0, 0xFC, 4 do safe_wd(sentinel + i, 0xDEADBEEF) end

-- Call sys 596
local sc596 = make_syscall(596)
local ok596, ret596 = pcall(function() return sc596() end)
if ok596 then
    local h, l = get_hi_lo(ret596)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    print(string.format("  596(): ret=0x%08X_%08X", h, l))
else
    print("  596(): PCALL-FAIL")
end

-- Check for changes in libkernel .data
if lk_data then
    local changes = 0
    for off = 0, 248, 8 do
        local q = safe_rq(lk_data + off)
        if q and snap_before[off] then
            local h, l = get_hi_lo(q)
            local bh, bl = snap_before[off].h, snap_before[off].l
            if h ~= bh or l ~= bl then
                changes = changes + 1
                if h < 0 then h = h + 0x100000000 end
                if l < 0 then l = l + 0x100000000 end
                if bh < 0 then bh = bh + 0x100000000 end
                if bl < 0 then bl = bl + 0x100000000 end
                print(string.format("  CHANGED .data+%03X: %08X_%08X -> %08X_%08X",
                    off, bh, bl, h, l))
            end
        end
    end
    print("  .data changes: " .. changes)
end

-- Check sentinel
local sent_ok = true
for i = 0, 0xFC, 4 do
    local v = safe_rd(sentinel + i)
    if v ~= 0xDEADBEEF then
        sent_ok = false
        local vu = v or 0
        if vu < 0 then vu = vu + 0x100000000 end
        print(string.format("  SENTINEL CORRUPT at +%X: %08X", i, vu))
        break
    end
end
if sent_ok then print("  Sentinel: OK") end

-- Try calling 596 with some args even though narg=0
-- The kernel might still read td->td_retval or other thread state
print("")
print("  596 with args (may be ignored):")
for _, arg_val in ipairs({0, 1, 2, 0x2001, pid}) do
    zero_buf(buf, 0x200)
    local ok_a, ret_a = pcall(function() return sc596(uint64(arg_val)) end)
    if ok_a then
        local h, l = get_hi_lo(ret_a)
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        print(string.format("    596(%d): ret=0x%08X_%08X", arg_val, h, l))
    else
        print(string.format("    596(%d): PCALL-FAIL", arg_val))
    end
end

-- Check if 596 writes to td->td_retval[1] (second return value)
-- FreeBSD syscalls can return TWO values in rax+rdx
-- Lua make_syscall returns rax, but rdx might have a pointer
-- We can't read rdx directly, but if we put a buf addr in arg1
-- and 596 writes to it as a side effect...
zero_buf(buf, 0x200)
local ok_b, ret_b = pcall(function() return sc596(uint64(buf), uint64(0x200)) end)
if ok_b then
    local nz = dump_hex(buf, 0x200, "596(buf,0x200) output")
    local kp = scan_kptrs(buf, 0x200)
    if #kp > 0 then
        print("  !!! KERNEL POINTERS from 596:")
        for _, k in ipairs(kp) do
            print(string.format("    +%03X: %08X_%08X", k.off, k.h, k.l))
        end
    end
end

-- ============================================================
-- [B] sys 604 dl_get_metadata
-- Never successfully tested. Try like 593: (handle, outbuf, outlen)
-- ============================================================
print("")
print("=== [B] sys 604 dl_get_metadata ===")

local sc604 = make_syscall(604)

-- Known module handles from dynlib_get_info experience
local handles = {0, 1, 2, 0x11, 0x31, 0x2001, 0x9F}

for _, h_val in ipairs(handles) do
    -- Pattern 1: (handle, outbuf, outlen_ptr)
    zero_buf(buf, 0x1000)
    safe_wd(outlen, 0x1000)
    safe_wd(outlen + 4, 0)
    local ok_c, ret_c = pcall(function()
        return sc604(uint64(h_val), uint64(buf), uint64(outlen))
    end)
    if ok_c then
        local rh, rl = get_hi_lo(ret_c)
        if rh < 0 then rh = rh + 0x100000000 end
        if rl < 0 then rl = rl + 0x100000000 end
        local rv = to_num(ret_c)
        if rv == 0 then
            local written = safe_rd(outlen)
            print(string.format("  604(h=%d, buf, len): ret=0, len_out=%d", h_val, written or 0))
            dump_hex(buf, math.min((written or 0x100), 0x400), "604 handle=" .. h_val)
            local kp = scan_kptrs(buf, math.min((written or 0x200), 0x1000))
            if #kp > 0 then
                print("  !!! KERNEL POINTERS from 604:")
                for _, k in ipairs(kp) do
                    print(string.format("    +%03X: %08X_%08X", k.off, k.h, k.l))
                end
            end
        else
            print(string.format("  604(h=%d, buf, len): ret=%d", h_val, rv))
        end
    else
        print(string.format("  604(h=%d, buf, len): PCALL-FAIL", h_val))
    end

    -- Pattern 2: (handle, subcmd, outbuf, outlen_ptr) — 4 args
    zero_buf(buf, 0x1000)
    safe_wd(outlen, 0x1000)
    safe_wd(outlen + 4, 0)
    for _, sub in ipairs({0, 1, 2, 3, 4}) do
        local ok_d, ret_d = pcall(function()
            return sc604(uint64(h_val), uint64(sub), uint64(buf), uint64(outlen))
        end)
        if ok_d then
            local rv = to_num(ret_d)
            if rv == 0 then
                local written = safe_rd(outlen)
                print(string.format("  604(h=%d, sub=%d, buf, len): ret=0, len_out=%d",
                    h_val, sub, written or 0))
                dump_hex(buf, math.min((written or 0x100), 0x200),
                    string.format("604 h=%d sub=%d", h_val, sub))
                local kp = scan_kptrs(buf, math.min((written or 0x200), 0x1000))
                if #kp > 0 then
                    print("  !!! KERNEL POINTERS from 604:")
                    for _, k in ipairs(kp) do
                        print(string.format("    +%03X: %08X_%08X", k.off, k.h, k.l))
                    end
                end
            end
            -- Only print non-zero returns for first sub to avoid noise
            if rv ~= 0 and sub == 0 then
                print(string.format("  604(h=%d, sub=0..4): ret=%d", h_val, rv))
            end
        end
    end
end

-- Pattern 3: (outbuf, outlen) — maybe no handle needed
zero_buf(buf, 0x1000)
safe_wd(outlen, 0x1000)
safe_wd(outlen + 4, 0)
local ok_e, ret_e = pcall(function()
    return sc604(uint64(buf), uint64(outlen))
end)
if ok_e then
    local rv = to_num(ret_e)
    print(string.format("  604(buf, len): ret=%d", rv))
    if rv == 0 then
        local written = safe_rd(outlen)
        dump_hex(buf, math.min((written or 0x100), 0x400), "604 no-handle")
    end
end

-- Pattern 4: struct-based — first 8 bytes = handle, next 8 = cmd
local stbuf = memory.alloc(0x100)
for _, h_val in ipairs({0, 2, 0x2001}) do
    for _, cmd in ipairs({0, 1, 2, 3, 4, 8, 16}) do
        zero_buf(stbuf, 0x100)
        safe_wd(stbuf, h_val)
        safe_wd(stbuf + 4, 0)
        safe_wd(stbuf + 8, cmd)
        safe_wd(stbuf + 12, 0)
        zero_buf(buf, 0x1000)
        safe_wd(outlen, 0x1000)
        local ok_f, ret_f = pcall(function()
            return sc604(uint64(stbuf), uint64(buf), uint64(outlen))
        end)
        if ok_f and to_num(ret_f) == 0 then
            local written = safe_rd(outlen)
            print(string.format("  604(struct{h=%d,cmd=%d}, buf, len): ret=0, len=%d",
                h_val, cmd, written or 0))
            if (written or 0) > 0 then
                dump_hex(buf, math.min(written, 0x200),
                    string.format("604 struct h=%d cmd=%d", h_val, cmd))
            end
        end
    end
end

-- ============================================================
-- [C] sys 559 — test with various args
-- Returns -1 with 0, returns 1 with -1.
-- Name suggests proc+0x5c0 free query. Try addresses, pids.
-- ============================================================
print("")
print("=== [C] sys 559 deep ===")

local sc559 = make_syscall(559)

-- Single-arg sweep
local test_vals = {
    {0, "0"},
    {1, "1"},
    {-1, "-1"},
    {pid, "pid"},
    {2, "2"},
    {4, "4"},
    {8, "8"},
    {16, "16"},
    {255, "255"},
    {256, "256"},
    {0x1000, "0x1000"},
    {0x10000, "0x10000"},
    {0xFFFF, "0xFFFF"},
}

for _, tv in ipairs(test_vals) do
    local val, label = tv[1], tv[2]
    local ok_g, ret_g = pcall(function() return sc559(uint64(val)) end)
    if ok_g then
        local rv = to_num(ret_g)
        print(string.format("  559(%s): ret=%d", label, rv))
    else
        print(string.format("  559(%s): PCALL-FAIL", label))
    end
end

-- Two-arg patterns
print("")
print("  559 two-arg:")
local twoarg_tests = {
    {pid, 0, "pid,0"},
    {pid, 1, "pid,1"},
    {0, pid, "0,pid"},
    {1, 0, "1,0"},
    {1, 1, "1,1"},
}
for _, tt in ipairs(twoarg_tests) do
    local ok_h, ret_h = pcall(function() return sc559(uint64(tt[1]), uint64(tt[2])) end)
    if ok_h then
        print(string.format("    559(%s): ret=%d", tt[3], to_num(ret_h)))
    end
end

-- Three-arg with outbuf (maybe it writes something?)
print("")
print("  559 three-arg with outbuf:")
for _, arg1 in ipairs({0, 1, -1, pid}) do
    zero_buf(buf, 0x200)
    local ok_j, ret_j = pcall(function()
        return sc559(uint64(arg1), uint64(buf), uint64(0x200))
    end)
    if ok_j then
        local rv = to_num(ret_j)
        local nz = 0
        for off = 0, 0x1F8, 8 do
            local q = safe_rq(buf + off)
            if q then
                local qh, ql = get_hi_lo(q)
                if qh ~= 0 or ql ~= 0 then nz = nz + 1 end
            end
        end
        print(string.format("    559(%d, buf, 0x200): ret=%d nz_qwords=%d", arg1, rv, nz))
        if nz > 0 then
            dump_hex(buf, 0x200, string.format("559 arg1=%d", arg1))
            local kp = scan_kptrs(buf, 0x200)
            if #kp > 0 then
                print("    !!! KERNEL POINTERS from 559:")
                for _, k in ipairs(kp) do
                    print(string.format("      +%03X: %08X_%08X", k.off, k.h, k.l))
                end
            end
        end
    end
end

-- ============================================================
-- [D] Quick accessibility test for 615, 613, 637 with better args
-- These returned -1 before but maybe with different arg shapes...
-- ============================================================
print("")
print("=== [D] Re-test 615/613/637 ===")

-- 615: try with (pid, cmd, outbuf, outlen)
local sc615 = make_syscall(615)
for _, cmd in ipairs({0, 1, 2, 3, 4, 8, 16}) do
    zero_buf(buf, 0x1000)
    safe_wd(outlen, 0x1000)
    local ok_k, ret_k = pcall(function()
        return sc615(uint64(pid), uint64(cmd), uint64(buf), uint64(outlen))
    end)
    if ok_k then
        local rv = to_num(ret_k)
        if rv == 0 then
            print(string.format("  615(pid, %d, buf, len): ret=0 !!!", cmd))
            dump_hex(buf, 0x200, "615 cmd=" .. cmd)
        end
    end
end

-- 613: try with (pid, cmd, outbuf, outlen)
local sc613 = make_syscall(613)
for _, cmd in ipairs({0, 1, 2, 3, 4, 8}) do
    zero_buf(buf, 0x1000)
    safe_wd(outlen, 0x1000)
    local ok_m, ret_m = pcall(function()
        return sc613(uint64(pid), uint64(cmd), uint64(buf), uint64(outlen))
    end)
    if ok_m then
        local rv = to_num(ret_m)
        if rv == 0 then
            print(string.format("  613(pid, %d, buf, len): ret=0 !!!", cmd))
            dump_hex(buf, 0x200, "613 cmd=" .. cmd)
        end
    end
end

print("")
print("=== 548a DONE ===")
