-- CRASH_CLASS: MODERATE
-- PROBE 69a: AIO class=2/3 lifecycle — every prior probe uses class=1 only
--
-- Context: All 30+ AIO probes hardcode class=1 in the 669 submit call.
-- The 669 contract accepts class 1-3. Different classes may:
--   - Allocate from different kernel zones (bypassing zone isolation)
--   - Use different completion/readback paths
--   - Free different sub-objects in 662
-- If class=2/3 shares zones with other subsystems, it unlocks cross-spray.

print("=== PROBE 69a: AIO CLASS LIFECYCLE ===")
print("")

local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local ok,v=pcall(function() return memory.read_dword(a) end) if ok then return N(v) end return nil end
local function rq(a) local ok,v=pcall(function() return memory.read_qword(a) end) if ok then return v end return nil end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function get_hi_lo(val) if type(val)=="table" and val.h then return val.h,val.l end return 0,N(val) end
local function fmt(val) if val==nil then return "nil" end local h,l=get_hi_lo(val) return string.format("0x%08X%08X",h,l) end
local function sgn(v) local l=N(v) if l>=0x80000000 then l=l-0x100000000 end return l end
local function put_str(s) local p=memory.alloc(#s+2) for i=1,#s do pcall(function() memory.write_byte(p+i-1,string.byte(s,i)) end) end pcall(function() memory.write_byte(p+#s,0) end) return p end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Ignore SIGSYS
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa)+8, 0); wq(uint64(N(sa)+16), uint64(0))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- Open /dev/zero for AIO targets
local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)
if fd_zero < 0 then print("FAILED to open /dev/zero"); return end

-- sys 624 VM-op oracle
local sc624 = mk(624)
local function vm_ops()
    local r = N(sc624(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
    return r
end

local reqs = memory.alloc(0x30)
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)
local ids_buf = memory.alloc(0x200)
local sts_buf = memory.alloc(0x200)

-- [A] CLASS=1 BASELINE (known working)
print("")
print("-- [A] CLASS=1 BASELINE --")
do
    local baseline = vm_ops()
    local ids = {}
    for i = 1, 8 do
        wq(N(reqs), uint64(0)); wq(N(reqs)+8, uint64(16))
        local bh,bl = get_hi_lo(uint64(N(data_buf)))
        wd(N(reqs)+0x10, bl); wd(N(reqs)+0x14, bh)
        local rh,rl = get_hi_lo(uint64(N(result_buf)))
        wd(N(reqs)+0x18, rl); wd(N(reqs)+0x1C, rh)
        wd(N(reqs)+0x20, fd_zero); wd(N(reqs)+0x24, 0)
        wd(N(one_id), 0)
        local ret = sgn(mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(one_id))))
        local id = rd(N(one_id)) or 0
        ids[#ids+1] = id
        print(string.format("  class1 submit #%d: ret=%d id=0x%X", i, ret, id))
    end
    local after_submit = vm_ops()
    print(string.format("  VM-ops: submit delta=%d", after_submit - baseline))

    -- Poll all
    for i = 1, #ids do
        wd(N(one_id), ids[i]); wd(N(one_st), 0xAA)
        pcall(function() mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    end
    local after_poll = vm_ops()
    print(string.format("  VM-ops: poll delta=%d", after_poll - after_submit))

    -- Delete all
    for i = 0, #ids-1 do
        wd(N(ids_buf)+i*4, ids[i+1])
        wd(N(sts_buf)+i*4, 0xCC)
    end
    local ret_del = sgn(mk(662)(uint64(N(ids_buf)), uint64(#ids), uint64(N(sts_buf))))
    local after_del = vm_ops()
    print(string.format("  delete ret=%d VM-ops: delete delta=%d", ret_del, after_del - after_poll))
    for i = 0, #ids-1 do
        local st = rd(N(sts_buf)+i*4) or 0xCC
        if st ~= 0 then print(string.format("    id=0x%X status=0x%X", ids[i+1], st)) end
    end
    print("  class1: OK")
end

if not alive() then print("DEAD after class1"); return end

-- [B] CLASS=2 LIFECYCLE
print("")
print("-- [B] CLASS=2 LIFECYCLE --")
do
    local baseline = vm_ops()
    local ids = {}
    for i = 1, 8 do
        wq(N(reqs), uint64(0)); wq(N(reqs)+8, uint64(16))
        local bh,bl = get_hi_lo(uint64(N(data_buf)))
        wd(N(reqs)+0x10, bl); wd(N(reqs)+0x14, bh)
        local rh,rl = get_hi_lo(uint64(N(result_buf)))
        wd(N(reqs)+0x18, rl); wd(N(reqs)+0x1C, rh)
        wd(N(reqs)+0x20, fd_zero); wd(N(reqs)+0x24, 0)
        wd(N(one_id), 0)
        local ret = sgn(mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(2), uint64(N(one_id))))
        local id = rd(N(one_id)) or 0
        ids[#ids+1] = id
        print(string.format("  class2 submit #%d: ret=%d id=0x%X", i, ret, id))
    end
    local after_submit = vm_ops()
    print(string.format("  VM-ops: submit delta=%d", after_submit - baseline))

    if ids[1] == 0 and ids[2] == 0 then
        print("  class2: ALL ZEROS — class 2 submit rejected")
    else
        -- Poll
        for i = 1, #ids do
            if ids[i] ~= 0 then
                wd(N(one_id), ids[i]); wd(N(one_st), 0xAA)
                pcall(function() mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
                local st = rd(N(one_st)) or 0xAA
                print(string.format("  class2 poll id=0x%X: status=0x%X", ids[i], st))
            end
        end
        local after_poll = vm_ops()
        print(string.format("  VM-ops: poll delta=%d", after_poll - after_submit))

        -- Delete
        local cnt = 0
        for i = 0, #ids-1 do
            if ids[i+1] ~= 0 then
                wd(N(ids_buf)+cnt*4, ids[i+1])
                wd(N(sts_buf)+cnt*4, 0xCC)
                cnt = cnt + 1
            end
        end
        if cnt > 0 then
            local ret_del = sgn(mk(662)(uint64(N(ids_buf)), uint64(cnt), uint64(N(sts_buf))))
            local after_del = vm_ops()
            print(string.format("  delete ret=%d VM-ops: delete delta=%d", ret_del, after_del - after_poll))
            for i = 0, cnt-1 do
                local st = rd(N(sts_buf)+i*4) or 0xCC
                if st ~= 0 then print(string.format("    id=0x%X status=0x%X", rd(N(ids_buf)+i*4) or 0, st)) end
            end
        end
    end
end

if not alive() then print("DEAD after class2"); return end

-- [C] CLASS=3 LIFECYCLE
print("")
print("-- [C] CLASS=3 LIFECYCLE --")
do
    local baseline = vm_ops()
    local ids = {}
    for i = 1, 8 do
        wq(N(reqs), uint64(0)); wq(N(reqs)+8, uint64(16))
        local bh,bl = get_hi_lo(uint64(N(data_buf)))
        wd(N(reqs)+0x10, bl); wd(N(reqs)+0x14, bh)
        local rh,rl = get_hi_lo(uint64(N(result_buf)))
        wd(N(reqs)+0x18, rl); wd(N(reqs)+0x1C, rh)
        wd(N(reqs)+0x20, fd_zero); wd(N(reqs)+0x24, 0)
        wd(N(one_id), 0)
        local ret = sgn(mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(3), uint64(N(one_id))))
        local id = rd(N(one_id)) or 0
        ids[#ids+1] = id
        print(string.format("  class3 submit #%d: ret=%d id=0x%X", i, ret, id))
    end
    local after_submit = vm_ops()
    print(string.format("  VM-ops: submit delta=%d", after_submit - baseline))

    if ids[1] == 0 and ids[2] == 0 then
        print("  class3: ALL ZEROS — class 3 submit rejected")
    else
        for i = 1, #ids do
            if ids[i] ~= 0 then
                wd(N(one_id), ids[i]); wd(N(one_st), 0xAA)
                pcall(function() mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
                local st = rd(N(one_st)) or 0xAA
                print(string.format("  class3 poll id=0x%X: status=0x%X", ids[i], st))
            end
        end
        local after_poll = vm_ops()
        print(string.format("  VM-ops: poll delta=%d", after_poll - after_submit))

        local cnt = 0
        for i = 0, #ids-1 do
            if ids[i+1] ~= 0 then
                wd(N(ids_buf)+cnt*4, ids[i+1])
                wd(N(sts_buf)+cnt*4, 0xCC)
                cnt = cnt + 1
            end
        end
        if cnt > 0 then
            local ret_del = sgn(mk(662)(uint64(N(ids_buf)), uint64(cnt), uint64(N(sts_buf))))
            local after_del = vm_ops()
            print(string.format("  delete ret=%d VM-ops: delete delta=%d", ret_del, after_del - after_poll))
            for i = 0, cnt-1 do
                local st = rd(N(sts_buf)+i*4) or 0xCC
                if st ~= 0 then print(string.format("    id=0x%X status=0x%X", rd(N(ids_buf)+i*4) or 0, st)) end
            end
        end
    end
end

if not alive() then print("DEAD after class3"); return end

-- [D] CLASS=0 AND OUT-OF-RANGE
print("")
print("-- [D] CLASS BOUNDARY (0, 4, 255) --")
for _, cls in ipairs({0, 4, 255}) do
    wq(N(reqs), uint64(0)); wq(N(reqs)+8, uint64(16))
    local bh,bl = get_hi_lo(uint64(N(data_buf)))
    wd(N(reqs)+0x10, bl); wd(N(reqs)+0x14, bh)
    local rh,rl = get_hi_lo(uint64(N(result_buf)))
    wd(N(reqs)+0x18, rl); wd(N(reqs)+0x1C, rh)
    wd(N(reqs)+0x20, fd_zero); wd(N(reqs)+0x24, 0)
    wd(N(one_id), 0)
    local ret = sgn(mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(cls), uint64(N(one_id))))
    local id = rd(N(one_id)) or 0
    print(string.format("  class=%d: ret=%d id=0x%X", cls, ret, id))
    if id ~= 0 then
        wd(N(one_id), id); wd(N(one_st), 0xCC)
        pcall(function() mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    end
    if not alive() then print("DEAD at class=" .. cls); return end
end

-- [E] AIO WRITE (cmd=2) — never tested in double-free context
print("")
print("-- [E] AIO WRITE (cmd=2) --")
do
    -- Need a writable destination: socketpair
    local sp = memory.alloc(16); wd(N(sp), 0xFFFFFFFF); wd(N(sp)+4, 0xFFFFFFFF)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp))) end)
    local rd_fd = rd(N(sp)) or -1; local wr_fd = rd(N(sp)+4) or -1
    print(string.format("  socketpair: rd=%d wr=%d", rd_fd, wr_fd))

    if wr_fd >= 0 then
        local write_data = memory.alloc(0x100)
        for i = 0, 15 do wd(N(write_data)+i*4, 0xDEAD0000 + i) end

        local baseline = vm_ops()
        wq(N(reqs), uint64(0)); wq(N(reqs)+8, uint64(64))
        local bh,bl = get_hi_lo(uint64(N(write_data)))
        wd(N(reqs)+0x10, bl); wd(N(reqs)+0x14, bh)
        local rh,rl = get_hi_lo(uint64(N(result_buf)))
        wd(N(reqs)+0x18, rl); wd(N(reqs)+0x1C, rh)
        wd(N(reqs)+0x20, wr_fd); wd(N(reqs)+0x24, 0)
        wd(N(one_id), 0)
        local ret = sgn(mk(669)(uint64(2), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(one_id))))
        local id = rd(N(one_id)) or 0
        local after = vm_ops()
        print(string.format("  cmd=2 submit: ret=%d id=0x%X VM-delta=%d", ret, id, after - baseline))

        if id ~= 0 then
            -- Poll
            wd(N(one_id), id); wd(N(one_st), 0xAA)
            pcall(function() mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
            local st = rd(N(one_st)) or 0xAA
            print(string.format("  cmd=2 poll: status=0x%X", st))

            -- Read back from socketpair read end
            local recv_buf = memory.alloc(0x100)
            local recv_ret = sgn(mk(3)(uint64(rd_fd), uint64(N(recv_buf)), uint64(64)))
            print(string.format("  read from pair: ret=%d", recv_ret))
            if recv_ret > 0 then
                local w0 = rd(N(recv_buf)) or 0
                print(string.format("  first dword: 0x%X (expect 0xDEAD0000)", w0))
            end

            -- Delete
            wd(N(one_id), id); wd(N(one_st), 0xCC)
            local del_ret = sgn(mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))))
            local del_st = rd(N(one_st)) or 0xCC
            print(string.format("  cmd=2 delete: ret=%d status=0x%X", del_ret, del_st))
        end

        pcall(function() mk(6)(uint64(rd_fd)) end)
        pcall(function() mk(6)(uint64(wr_fd)) end)
    end
end

-- [F] 663 WAIT MODE PARAMETER SWEEP
print("")
print("-- [F] 663 WAIT_MODE SWEEP --")
do
    -- Submit 4 IDs for testing different wait modes
    local test_ids = {}
    for i = 1, 4 do
        wq(N(reqs), uint64(0)); wq(N(reqs)+8, uint64(16))
        local bh,bl = get_hi_lo(uint64(N(data_buf)))
        wd(N(reqs)+0x10, bl); wd(N(reqs)+0x14, bh)
        local rh,rl = get_hi_lo(uint64(N(result_buf)))
        wd(N(reqs)+0x18, rl); wd(N(reqs)+0x1C, rh)
        wd(N(reqs)+0x20, fd_zero); wd(N(reqs)+0x24, 0)
        wd(N(one_id), 0)
        pcall(function() mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(one_id))) end)
        local id = rd(N(one_id)) or 0
        if id ~= 0 then
            poll_one(id)
            test_ids[#test_ids+1] = id
        end
    end
    print(string.format("  submitted %d IDs for wait_mode test", #test_ids))

    if #test_ids >= 1 then
        local wide_out = memory.alloc(0x200)
        for mode = 0, 7 do
            if not alive() then print("DEAD at mode=" .. mode); break end
            -- Zero the output
            for j = 0, 0x1FC, 4 do wd(N(wide_out)+j, 0xDEADDEAD) end
            wd(N(one_id), test_ids[1])
            local timeout = memory.alloc(16)
            wq(N(timeout), uint64(0)); wq(N(timeout)+8, uint64(0))
            local ret = sgn(mk(663)(uint64(N(one_id)), uint64(1), uint64(N(wide_out)),
                uint64(mode), uint64(N(timeout))))
            local w0 = rd(N(wide_out)) or 0xDEADDEAD
            local w1 = rd(N(wide_out)+4) or 0xDEADDEAD
            local w2 = rd(N(wide_out)+8) or 0xDEADDEAD
            local w3 = rd(N(wide_out)+12) or 0xDEADDEAD
            print(string.format("  mode=%d: ret=%d out=[0x%X 0x%X 0x%X 0x%X]",
                mode, ret, w0, w1, w2, w3))
            -- Check if any non-sentinel bytes beyond first dword
            local extra = 0
            for j = 4, 0x7C, 4 do
                local v = rd(N(wide_out)+j) or 0xDEADDEAD
                if v ~= 0xDEADDEAD then extra = extra + 1 end
            end
            if extra > 0 then
                print(string.format("    *** %d extra dwords modified! ***", extra))
                for j = 0, 0x7C, 4 do
                    local v = rd(N(wide_out)+j) or 0xDEADDEAD
                    if v ~= 0xDEADDEAD then
                        print(string.format("      +0x%02X: 0x%08X", j, v))
                    end
                end
            end
        end

        -- Cleanup test IDs
        for i = 0, #test_ids-1 do
            wd(N(ids_buf)+i*4, test_ids[i+1])
            wd(N(sts_buf)+i*4, 0xCC)
        end
        pcall(function() mk(662)(uint64(N(ids_buf)), uint64(#test_ids), uint64(N(sts_buf))) end)
    end
end

pcall(function() mk(6)(uint64(fd_zero)) end)
print("")
print("alive=" .. (alive() and "YES" or "NO"))
print("=== 69a DONE ===")
