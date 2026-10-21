-- CRASH_CLASS: MODERATE (bounded timeouts; 661/665 not called - they kill on zeros)
-- PROBE 276a: AIO lifecycle first contact on 14.10 (Relapse surface recheck)
--
-- Context: the Relapse kernel exploit (fw <= 13.60) raced aio_multi_wait(663)
-- freeing AIO nodes against aio_submit_cmd(669) spraying replacements; 14.00
-- reportedly killed the race but the patch location is unknown. The 14.10
-- isolation sweep shows the family present: 662/663/664/666/669 return -1 on
-- zeros, 670 aio_init returns 0. The 13.60 capture adds the real shapes:
--   670 aio_init(config_ptr, version<=0xFFFFFF, mustNULL, must0) - zeros OK
--   669 submit_cmd(cmd: low12 in {1,2}, buf_ptr, size>=0x81, type in {1,2,3}, ptr5)
--   663 multi_wait(ids_ptr, count, states_ptr, mode, timeout_ptr)
--   662 multi_delete(ids_ptr, count, ptr)
-- This probe asks only: does a submission get ACCEPTED on 14.10 (ret 0)?
-- If yes, the node lifecycle is live and the wait/submit race (276b) is
-- schedulable with the proven thr_create threading.

print("=== PROBE 276a: AIO lifecycle first contact ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function raw(v)
    if v == nil then return "nil" end
    if type(v) == "table" and v.h then return string.format("0x%08X_%08X", v.h, v.l) end
    return "0x" .. string.format("%X", to_num(v))
end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function zero(addr, n)
    for off = 0, n - 1, 8 do wq(addr + off, uint64(0)) end
end

local function call(num, label, a)
    local sc = make_syscall(num)
    local ok, rv = pcall(function()
        return sc(a[1] or uint64(0), a[2] or uint64(0), a[3] or uint64(0),
                  a[4] or uint64(0), a[5] or uint64(0), a[6] or uint64(0))
    end)
    print(string.format("    %-34s ret=%s", label, raw(rv)))
    return ok, rv
end

local pid_ok, pid = pcall(function() return make_syscall(20)():tonumber() end)
print("[0] pid=" .. tostring(pid))

print("[A] aio_init(670) zeros and light variants")
call(670, "init(0,0,0,0)", {})
call(670, "init(0, 0x3C, 0, 0)", { uint64(0), uint64(0x3C) })

-- command buffer: 0x100 zeroed (type 1/2/3 tried)
local cmdbuf = memory.alloc(0x200)
zero(cmdbuf, 0x200)
wd(cmdbuf, 1)

print("[B] aio_submit_cmd(669) accepted-cmd shapes")
call(669, "submit(cmd=1,buf,0x100,type=1,0)", { uint64(1), uint64(cmdbuf), uint64(0x100), uint64(1) })
call(669, "submit(cmd=1,buf,0x100,type=2,0)", { uint64(1), uint64(cmdbuf), uint64(0x100), uint64(2) })
call(669, "submit(cmd=2,buf,0x100,type=1,0)", { uint64(2), uint64(cmdbuf), uint64(0x100), uint64(1) })
call(669, "submit(cmd=1,buf,0x81,type=3,0)",  { uint64(1), uint64(cmdbuf), uint64(0x81), uint64(3) })
call(669, "submit(cmd=1,buf,0x80,type=1,0) expect -1", { uint64(1), uint64(cmdbuf), uint64(0x80), uint64(1) })

print("[C] aio_multi_wait(663) 1-usec bounded")
local ids = memory.alloc(0x40)
local states = memory.alloc(0x40)
local timeout = memory.alloc(0x10)
zero(ids, 0x40); zero(states, 0x40); zero(timeout, 0x10)
wd(ids, 1)
wd(timeout, 1)
call(663, "wait(ids=1,n=1,states,0,timeout1us)", { uint64(ids), uint64(1), uint64(states), uint64(0), uint64(timeout) })
call(663, "wait(ids=1,n=1,states,1,timeout1us)", { uint64(ids), uint64(1), uint64(states), uint64(1), uint64(timeout) })
print("    states[0] after: " .. tostring(rq(states) ~= nil and raw(rq(states)) or "-"))

print("[D] aio_multi_delete(662) / poll(664) / cancel(666) with matching shapes")
call(662, "delete(ids=1,n=1,0)", { uint64(ids), uint64(1), uint64(0) })
call(664, "poll(ids=1,n=1,states,0)", { uint64(ids), uint64(1), uint64(states), uint64(0) })
call(666, "cancel(ids=1,n=1,0)", { uint64(ids), uint64(1), uint64(0) })

local pid_ok2, pid2 = pcall(function() return make_syscall(20)():tonumber() end)
print("")
print("[E] canary: ok=" .. tostring(pid_ok2) .. " pid=" .. tostring(pid2))
print("=== END 276a ===")
