-- CRASH_CLASS: MODERATE
-- PROBE 352b: the AIO batch family, with the data path and the fd lifetime
--
-- 352a was the first call of 669 on this firmware and it works: one read of
-- /dev/zero completed, 664 reported state 3 and then 0x10003 (the observed
-- flag the dossier describes), 662 deleted the identifier. 661 - the single
-- submit everybody wrote the family off after - is a different entry.
--
-- Three questions the enablement does not answer:
--   [A] does the read really land in the data pointer (use /dev/urandom, whose
--       bytes are distinguishable from a zeroed buffer)?
--   [B] does cmd=2 write our bytes to the descriptor it is given?
--   [C] does the request hold the file description, or only the descriptor
--       number? Submit on a fd, close that fd, then poll: if it still
--       completes, the kernel took a reference; if it fails or changes, the
--       number is all it kept.

print("=== PROBE 352b: AIO DATA PATH AND FD LIFETIME ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function sgn(v)
    local l = to_num(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function hi_lo(v)
    local h, l = get_hi_lo(v)
    return to_num(h), to_num(l)
end
local Z = uint64(0)
local function sc(n) return make_syscall(n) end
local function wq(addr, value)
    pcall(function() memory.write_qword(addr, value) end)
end
local function wd(addr, value)
    pcall(function() memory.write_dword(addr, value) end)
end
local function rd(addr)
    local ok, v = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(v) end
    return -999
end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do
        pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end
local function open_path(path, flags)
    local ok, rv = pcall(function() return sc(5)(put_str(path), uint64(flags), Z) end)
    if not ok then return -1 end
    return sgn(rv)
end
local function close_fd(fd)
    local ok, rv = pcall(function() return sc(6)(uint64(fd), Z, Z) end)
    if not ok then return nil end
    return sgn(rv)
end

local reqs = memory.alloc(0x200)
local data = memory.alloc(0x1000)
local result = memory.alloc(0x200)
local ids = memory.alloc(0x200)
for i = 0, 0x3F do
    wq(reqs + i * 8, 0)
    wd(result + i * 4, 0)
    wd(ids + i * 4, 0)
end
for i = 0, 0x3FF do wd(data + i * 4, 0) end

local function fill_req(base, off, len, buf, res, fd)
    wq(base + 0x00, off)
    wq(base + 0x08, len)
    local bh, bl = hi_lo(uint64(buf))
    wd(base + 0x10, bl) wd(base + 0x14, bh)
    local rh, rl = hi_lo(uint64(res))
    wd(base + 0x18, rl) wd(base + 0x1C, rh)
    wd(base + 0x20, fd)
    wd(base + 0x24, 0)
end
local function submit(cmd, count, class)
    local ok, r = pcall(function()
        return sc(669)(uint64(cmd), uint64(reqs), uint64(count), uint64(class), uint64(ids))
    end)
    if not ok then return nil end
    return sgn(r)
end
local function poll(n, count)
    local states = memory.alloc(0x100)
    for i = 0, 0x3F do wd(states + i * 4, 0) end
    local ok, r = pcall(function()
        return sc(n)(uint64(ids), uint64(count), uint64(states))
    end)
    if not ok then return nil, 0 end
    return sgn(r), rd(states)
end
local function delete(count)
    local out = memory.alloc(0x100)
    for i = 0, 0x3F do wd(out + i * 4, 0) end
    local ok, r = pcall(function()
        return sc(662)(uint64(ids), uint64(count), uint64(out))
    end)
    if not ok then return nil end
    return sgn(r)
end

print("[A] read 16 bytes of /dev/urandom into our buffer")
local fdr = open_path("/dev/urandom", 0)
print(string.format("  open(/dev/urandom) = %d", fdr))
if fdr >= 0 then
    fill_req(reqs, 0, 16, data, result, fdr)
    print(string.format("  669 read = %s  id[0]=0x%X", tostring(submit(1, 1, 1)), rd(ids)))
    local okp, state = poll(664, 1)
    print(string.format("  664 poll = %s  state=0x%X", tostring(okp), state))
    local nz = 0
    for i = 0, 15 do
        if rd(data + i) ~= 0 then nz = nz + 1 end
    end
    print(string.format("  data[0..15] nonzero bytes = %d of 16", nz))
    print(string.format("  data = %08X %08X %08X %08X", rd(data), rd(data + 4), rd(data + 8), rd(data + 12)))
    print(string.format("  662 delete = %s", tostring(delete(1))))
    print(string.format("  close(/dev/urandom) = %s", tostring(close_fd(fdr))))
end

print("[B] write 16 bytes of ours to /dev/null")
local fdn = open_path("/dev/null", 2)
print(string.format("  open(/dev/null, O_RDWR) = %d", fdn))
if fdn >= 0 then
    for i = 0, 15 do wd(data + i * 4, 0xDEADBEEF) end
    fill_req(reqs, 0, 16, data, result, fdn)
    print(string.format("  669 write = %s  id[0]=0x%X", tostring(submit(2, 1, 1)), rd(ids)))
    local okp, state = poll(664, 1)
    print(string.format("  664 poll = %s  state=0x%X", tostring(okp), state))
    print(string.format("  662 delete = %s", tostring(delete(1))))
end

print("[C] the request and the descriptor number")
local fd2 = open_path("/dev/zero", 0)
print(string.format("  open(/dev/zero) = %d", fd2))
if fd2 >= 0 then
    fill_req(reqs, 0, 16, data, result, fd2)
    print(string.format("  669 read = %s  id[0]=0x%X", tostring(submit(1, 1, 1)), rd(ids)))
    print(string.format("  close(fd) = %s (while the request is outstanding)", tostring(close_fd(fd2))))
    local okp, state = poll(664, 1)
    print(string.format("  664 poll after close = %s  state=0x%X", tostring(okp), state))
    local reused = open_path("/dev/null", 0)
    print(string.format("  open(/dev/null) = %d (same number as the closed fd?)", reused))
    print(string.format("  664 poll again = %s  state=0x%X", tostring(poll(664, 1))))
    print(string.format("  662 delete = %s", tostring(delete(1))))
    if reused >= 0 then close_fd(reused) end
end

print("[D] four descriptors in one submit")
local fdx = open_path("/dev/zero", 0)
if fdx >= 0 then
    for i = 0, 3 do
        fill_req(reqs + i * 0x28, 0, 8, data + i * 0x40, result + i * 0x20, fdx)
    end
    print(string.format("  669 count=4 = %s", tostring(submit(1, 4, 1))))
    local okp, state = poll(664, 4)
    print(string.format("  664 poll 4 = %s  state[0]=0x%X state[3]=0x%X", tostring(okp),
        rd(result + 0x00), rd(result + 0x60)))
    local out = memory.alloc(0x100)
    for i = 0, 0x3F do wd(out + i * 4, 0) end
    local okd, r = pcall(function()
        return sc(662)(uint64(ids), uint64(4), uint64(out))
    end)
    print(string.format("  662 delete 4 = %s", okd and tostring(sgn(r)) or "EXC"))
    close_fd(fdx)
end

print("")
print("=== 352b DONE ===")
