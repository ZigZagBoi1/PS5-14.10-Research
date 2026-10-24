-- CRASH_CLASS: MODERATE
-- PROBE 524a: VM object operations and page table modifiers
--
-- The 13.60 contracts table reveals syscalls with decoded args
-- that directly manipulate VM objects and page tables:
-- 653 (narg=1): GPU/Display Page Table Attribute Modifier
-- 654 (narg=5): Validated 64 KiB VM object range operation
-- 655 (narg=3): Validated VM object range reset companion
-- 660: dynamic module info v2 (module_handle, slot_padding, info_inout)
-- 667: Enumerate process/thread records (count-only mode)
-- 645 (narg=0): zero-arg call, unknown purpose
-- 648 (narg=1, user ptr): unknown purpose
-- 658: descriptor-backed synchronization path
--
-- These are the last unexplored handlers with decoded contracts.
-- Any one of them could leak a kernel address or provide a
-- new primitive.

print("=== PROBE 524a: VM ops + page table modifiers ===")
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
local function fmt_hex(val)
    local h, l = get_hi_lo(val)
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X%08X", h, l)
end

local sc20 = make_syscall(20)
local pid = to_num(sc20())
print("pid: " .. pid)

local buf = memory.alloc(0x2000)
local outlen = memory.alloc(16)

local function zero_buf(addr, sz)
    for j = 0, sz - 1, 4 do safe_wd(addr + j, 0) end
end

local function check_buf_kptr(addr, sz)
    local found = 0
    for off = 0, sz - 8, 8 do
        local q = safe_rq(addr + off)
        if q then
            local qh, ql = get_hi_lo(q)
            local exponent = math.floor((qh % 0x80000000) / 0x100000)
            if qh >= 0xFFFF8000 and qh < 0xFFFFFFFF and exponent ~= 0x7FF then
                found = found + 1
                print(string.format("    *** KPTR +0x%X: 0x%08X_%08X ***", off, qh, ql))
            end
        end
    end
    return found
end

local function dump_nonzero(addr, sz, label)
    print("  " .. label .. ":")
    local nz = 0
    for off = 0, sz - 8, 8 do
        local q = safe_rq(addr + off)
        if q then
            local qh, ql = get_hi_lo(q)
            if qh ~= 0 or ql ~= 0 then
                nz = nz + 1
                if nz <= 30 then
                    print(string.format("    +0x%03X: 0x%08X_%08X", off, qh, ql))
                end
            end
        end
    end
    if nz > 30 then print("    ... " .. nz .. " total nonzero") end
    if nz == 0 then print("    (all zero)") end
    return nz
end

-- get GPU mmap address for VM tests
local sc_mmap = make_syscall(477)
local gpu = sc_mmap(uint64(0), uint64(4 * 0x4000), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local gpu_h, gpu_l = get_hi_lo(gpu)
print("GPU mmap: " .. fmt_hex(gpu))

-- get eboot base for module tests
local sc593 = make_syscall(593)
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
pcall(function() sc593(uint64(0), info) end)
local eboot_lo = safe_rd(info + 0x108)
local eboot_hi = safe_rd(info + 0x10C)
local eboot_text = uint64(string.format("0x%X%08X", eboot_hi or 0, eboot_lo or 0))
print("eboot text: " .. fmt_hex(eboot_text))
print("")

-- ============================================================
-- [A] sys 653: GPU/Display Page Table Attribute Modifier
-- narg=1. Try with: GPU mmap addr, heap addr, eboot addr, 0
-- ============================================================
print("[A] sys 653 — page table attribute modifier")
local sc653 = make_syscall(653)

local test_addrs = {
    {gpu, "GPU mmap"},
    {uint64(to_num(buf)), "heap buf"},
    {eboot_text, "eboot text"},
    {uint64(0), "zero"},
    {uint64(1), "one"},
    {uint64(0x4000), "16KB page size"},
}

for _, t in ipairs(test_addrs) do
    local ok, ret = pcall(function() return sc653(t[1]) end)
    local rv = ok and to_num(ret) or -999
    print(string.format("  653(%s): ret=%d%s", t[2], rv, ok and "" or " [PCALL-FAIL]"))
    if rv ~= -1 and rv ~= -999 then
        print("    *** NON-FAIL RETURN: " .. rv .. " ***")
    end
end

-- try with (addr, attr) dual arg
for _, prot in ipairs({0x1, 0x3, 0x5, 0x7, 0x33}) do
    local ok, ret = pcall(function() return sc653(gpu, uint64(prot)) end)
    local rv = ok and to_num(ret) or -999
    print(string.format("  653(gpu, 0x%X): ret=%d", prot, rv))
end
print("")

-- ============================================================
-- [B] sys 654: Validated 64 KiB VM object range operation
-- narg=5: likely (descriptor, flags, addr/offset, size, something)
-- 13.60 contract names no args but says "validated 64KiB"
-- ============================================================
print("[B] sys 654 — 64KiB VM range operation")
local sc654 = make_syscall(654)

-- pattern 1: (addr, size, prot, flags, outbuf)
zero_buf(buf, 0x200)
local patterns654 = {
    {gpu, uint64(0x10000), uint64(0x3), uint64(0), uint64(to_num(buf)), "gpu,64K,RW,0,buf"},
    {gpu, uint64(0x10000), uint64(0), uint64(0), uint64(0), "gpu,64K,0,0,0"},
    {uint64(0), uint64(0x10000), uint64(0), uint64(0), uint64(0), "0,64K,0,0,0"},
    -- as multiplexer: (cmd, addr, size, prot, outbuf)
    {uint64(0), gpu, uint64(0x10000), uint64(0x3), uint64(to_num(buf)), "cmd0,gpu,64K,RW,buf"},
    {uint64(1), gpu, uint64(0x10000), uint64(0x3), uint64(to_num(buf)), "cmd1,gpu,64K,RW,buf"},
    {uint64(2), gpu, uint64(0x10000), uint64(0x3), uint64(to_num(buf)), "cmd2,gpu,64K,RW,buf"},
    -- descriptor-based: (fd, offset, size, prot, outbuf) — try with -1 (anon)
    {uint64(0xFFFFFFFF), uint64(0), uint64(0x10000), uint64(0x3), uint64(to_num(buf)), "fd-1,0,64K,RW,buf"},
}

for _, p in ipairs(patterns654) do
    zero_buf(buf, 0x200)
    local ok, ret = pcall(function() return sc654(p[1], p[2], p[3], p[4], p[5]) end)
    local rv = ok and to_num(ret) or -999
    print(string.format("  654(%s): ret=%d%s", p[#p], rv, ok and "" or " [PCALL-FAIL]"))
    if rv == 0 then
        dump_nonzero(buf, 0x200, "output")
        check_buf_kptr(buf, 0x200)
    end
end
print("")

-- ============================================================
-- [C] sys 655: VM object range reset companion
-- narg=3: likely (addr, size, flags) or (descriptor, offset, size)
-- ============================================================
print("[C] sys 655 — VM range reset companion")
local sc655 = make_syscall(655)

local patterns655 = {
    {gpu, uint64(0x10000), uint64(0), "gpu,64K,0"},
    {gpu, uint64(0x4000), uint64(0), "gpu,16K,0"},
    {uint64(0), uint64(0x10000), uint64(0), "0,64K,0"},
    {uint64(0xFFFFFFFF), uint64(0), uint64(0x10000), "fd-1,0,64K"},
}

for _, p in ipairs(patterns655) do
    local ok, ret = pcall(function() return sc655(p[1], p[2], p[3]) end)
    local rv = ok and to_num(ret) or -999
    print(string.format("  655(%s): ret=%d%s", p[#p], rv, ok and "" or " [PCALL-FAIL]"))
end
print("")

-- ============================================================
-- [D] sys 660: dynamic module info v2
-- Args from 13.60: module_handle, slot_padding, info_inout
-- Different from 593 (v1) — might return more data
-- ============================================================
print("[D] sys 660 — dynlib info v2")
local sc660 = make_syscall(660)

for _, h in ipairs({0, 2, 17, 49, 159}) do
    -- try with info buffer pre-filled with sizes
    for _, sz in ipairs({0x160, 0x200, 0x400, 0x800}) do
        zero_buf(buf, 0x1000)
        safe_wd(buf, sz) -- version/size at +0
        local ok, ret = pcall(function() return sc660(uint64(h), uint64(0), uint64(to_num(buf))) end)
        local rv = ok and to_num(ret) or -999
        if rv == 0 then
            print(string.format("  660(h=%d, pad=0, buf[0]=0x%X): ret=0 *** SUCCESS ***", h, sz))
            local nz = dump_nonzero(buf, math.min(sz, 0x400), "660 output")
            if nz > 0 then check_buf_kptr(buf, math.min(sz, 0x400)) end
        elseif rv ~= -1 then
            print(string.format("  660(h=%d, pad=0, buf[0]=0x%X): ret=%d", h, sz, rv))
        end
    end
end

-- also try without size prefix
for _, h in ipairs({0, 2}) do
    zero_buf(buf, 0x1000)
    local ok, ret = pcall(function() return sc660(uint64(h), uint64(0), uint64(to_num(buf))) end)
    local rv = ok and to_num(ret) or -999
    print(string.format("  660(h=%d, pad=0, zerobuf): ret=%d%s", h, rv, ok and "" or " [PCALL-FAIL]"))
    if rv == 0 then
        dump_nonzero(buf, 0x400, "660 output")
        check_buf_kptr(buf, 0x800)
    end
end
print("")

-- ============================================================
-- [E] sys 667: enumerate process/thread records
-- count-only mode might need: (0, 0, outcount_ptr) or (pid, outbuf, size)
-- ============================================================
print("[E] sys 667 — process/thread enumeration")
local sc667 = make_syscall(667)

-- count-only mode: just count threads?
zero_buf(buf, 0x200)
safe_wd(outlen, 0)
safe_wd(outlen + 4, 0)

local patterns667 = {
    -- (pid, outbuf, bufsize, count_ptr)
    {uint64(pid), uint64(to_num(buf)), uint64(0x1000), uint64(to_num(outlen)), "pid,buf,4K,countptr"},
    -- count-only: (pid, 0, 0, count_ptr)
    {uint64(pid), uint64(0), uint64(0), uint64(to_num(outlen)), "pid,0,0,countptr"},
    -- (0, outbuf, size, count_ptr)
    {uint64(0), uint64(to_num(buf)), uint64(0x1000), uint64(to_num(outlen)), "0,buf,4K,countptr"},
    -- (outbuf, count, mode)
    {uint64(to_num(buf)), uint64(0x100), uint64(0), "buf,256,mode0"},
    {uint64(to_num(buf)), uint64(0x100), uint64(1), "buf,256,mode1"},
    -- simple
    {uint64(0), uint64(0), uint64(0), uint64(0), "zeros"},
}

for _, p in ipairs(patterns667) do
    zero_buf(buf, 0x200)
    safe_wd(outlen, 0)
    local ok, ret
    if #p == 5 then
        ok, ret = pcall(function() return sc667(p[1], p[2], p[3], p[4]) end)
    elseif #p == 4 then
        ok, ret = pcall(function() return sc667(p[1], p[2], p[3]) end)
    else
        ok, ret = pcall(function() return sc667(p[1], p[2], p[3], p[4]) end)
    end
    local rv = ok and to_num(ret) or -999
    print(string.format("  667(%s): ret=%d%s", p[#p], rv, ok and "" or " [PCALL-FAIL]"))
    if rv == 0 then
        local cnt = safe_rd(outlen)
        if cnt and cnt > 0 then print("    count_out=" .. cnt) end
        dump_nonzero(buf, 0x200, "667 output")
        check_buf_kptr(buf, 0x200)
    end
end
print("")

-- ============================================================
-- [F] sys 645 (narg=0) and 648 (narg=1, user ptr)
-- ============================================================
print("[F] sys 645/648")

local sc645 = make_syscall(645)
local ok645, ret645 = pcall(function() return sc645() end)
local rv645 = ok645 and to_num(ret645) or -999
print(string.format("  645(): ret=%d%s", rv645, ok645 and "" or " [PCALL-FAIL]"))
if rv645 ~= -1 and rv645 ~= -999 then
    print("    *** NON-FAIL RETURN ***")
end

-- 648: narg=1, user ptr — might be (outbuf)
local sc648 = make_syscall(648)
for _, sz in ipairs({0x40, 0x100, 0x200, 0x400}) do
    zero_buf(buf, 0x1000)
    safe_wd(buf, sz)
    local ok, ret = pcall(function() return sc648(uint64(to_num(buf))) end)
    local rv = ok and to_num(ret) or -999
    print(string.format("  648(buf[0]=0x%X): ret=%d%s", sz, rv, ok and "" or " [PCALL-FAIL]"))
    if rv == 0 then
        dump_nonzero(buf, math.min(sz + 0x40, 0x400), "648 output")
        check_buf_kptr(buf, 0x400)
    end
end
print("")

-- ============================================================
-- [G] sys 658: descriptor-backed synchronization
-- Args: descriptor, slot_padding
-- Try with various fd types
-- ============================================================
print("[G] sys 658 — descriptor synchronization")
local sc658 = make_syscall(658)

-- open a pipe/socket for testing
local sc_socket = make_syscall(97)
local sock = sc_socket(uint64(2), uint64(2), uint64(0)) -- AF_INET, SOCK_DGRAM
print("  test socket fd: " .. to_num(sock))

local test_fds = {
    {uint64(0), uint64(0), "fd0,0"},
    {uint64(to_num(sock)), uint64(0), "sock,0"},
    {uint64(0xFFFFFFFF), uint64(0), "fd-1,0"},
    -- try with slot values
    {uint64(to_num(sock)), uint64(1), "sock,slot1"},
    {uint64(to_num(sock)), uint64(0x100), "sock,slot256"},
}

for _, p in ipairs(test_fds) do
    local ok, ret = pcall(function() return sc658(p[1], p[2]) end)
    local rv = ok and to_num(ret) or -999
    print(string.format("  658(%s): ret=%d%s", p[3], rv, ok and "" or " [PCALL-FAIL]"))
end

-- close test socket
local sc_close = make_syscall(6)
pcall(function() sc_close(sock) end)
print("")

-- ============================================================
-- [H] sys 647: ORBI metadata (credential-gated)
-- narg=1. Might return SDK version info
-- ============================================================
print("[H] sys 647 — ORBI metadata query")
local sc647 = make_syscall(647)

zero_buf(buf, 0x200)
local ok647, ret647 = pcall(function() return sc647(uint64(to_num(buf))) end)
local rv647 = ok647 and to_num(ret647) or -999
print(string.format("  647(buf): ret=%d%s", rv647, ok647 and "" or " [PCALL-FAIL]"))
if rv647 == 0 then
    dump_nonzero(buf, 0x200, "647 output")
    check_buf_kptr(buf, 0x200)
end

-- try with module handle
local ok647b, ret647b = pcall(function() return sc647(uint64(0)) end)
print(string.format("  647(0): ret=%d", ok647b and to_num(ret647b) or -999))
print("")

-- ============================================================
-- [I] Sentinel check: verify process survived all calls
-- ============================================================
local pid2 = to_num(sc20())
print("pid: " .. pid2 .. (pid2 == pid and " OK" or " CHANGED"))
print("")
print("=== PROBE 524a COMPLETE ===")
