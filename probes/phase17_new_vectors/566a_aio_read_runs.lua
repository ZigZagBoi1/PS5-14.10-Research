-- CRASH_CLASS: MODERATE
-- PROBE 566a: does an aio read actually run on 14.10?
--
-- Context: 489b saw poll=3 ("completed") immediately and the create never
-- touched the caller buffer, which read as "submit is gated off". An older
-- capture (352a) saw 3 followed by 0x10003, so the state machine may move.
-- This probe submits a read from /dev/urandom into a canary page and polls
-- repeatedly: if any byte of the page changes or the state alternates, the
-- read path runs; if the page stays 0xA5 and the state stays 3, it does not.

print("=== PROBE 566a: AIO READ REALLY RUNS? ===")

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
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_rd(addr)
    local ok, v = pcall(function() return to_num(memory.read_dword(addr)) end)
    if ok then return v end
    return -1
end
local function u64(hi, lo)
    return uint64(string.format("0x%08X%08X", hi, lo))
end
local function addr(q)
    if type(q) == "table" and q.h then return u64(q.h, q.l) end
    return uint64(q)
end

-- [A] open /dev/urandom
local path = to_num(memory.alloc(0x20))
safe_wd(path + 0x00, 0x7665642F)  -- "/dev"
safe_wd(path + 0x04, 0x6172752F)  -- "/ura"
safe_wd(path + 0x08, 0x6D6F646E)  -- "ndom"
safe_wd(path + 0x0C, 0x00000000)
print(string.format("[A] path page=0x%08X", path))

local sc_open = make_syscall(5)
local ok, fd = pcall(function() return sc_open(u64(0, path), u64(0, 0), u64(0, 0), u64(0, 0), u64(0, 0), u64(0, 0)) end)
print(string.format("[A] open=/dev/urandom ret=%s", ok and tostring(fd) or "PCALL-FAIL"))
local fdnum = 0
if ok then
    if type(fd) == "table" and fd.l then fdnum = fd.l else fdnum = tonumber(fd) or 0 end
end
print(string.format("[A] fd=%d", fdnum))

-- [B] buffers
local BUF = to_num(memory.alloc(0x4000))
for off = 0, 0x4000 - 4, 4 do safe_wd(BUF + off, 0xA5A5A5A5) end
local DATA = to_num(memory.alloc(0x100))
for off = 0, 0x100 - 4, 4 do safe_wd(DATA + off, 0) end
local OUT = to_num(memory.alloc(0x100))
for off = 0, 0x100 - 4, 4 do safe_wd(OUT + off, 0) end
print(string.format("[B] buf=0x%08X data=0x%08X out=0x%08X", BUF, DATA, OUT))

-- descriptor: offset 0, buf, nbytes, fd, op
safe_wd(DATA + 0x00, 0)
safe_wd(DATA + 0x04, 0)
safe_wd(DATA + 0x08, BUF)
safe_wd(DATA + 0x0C, 0)
safe_wd(DATA + 0x10, 0x4000)
safe_wd(DATA + 0x14, 0)
safe_wd(DATA + 0x18, fdnum)
safe_wd(DATA + 0x1C, 0)
safe_wd(DATA + 0x20, 1)  -- op: read
safe_wd(DATA + 0x24, 0)

-- [C] create
local sc_create = make_syscall(669)
local okc, ret = pcall(function()
    return sc_create(u64(0, 1), u64(0, DATA), u64(0, 1), u64(0, 1), u64(0, OUT), u64(0, 0))
end)
print(string.format("[C] create ret=%s id=0x%08X", okc and tostring(ret) or "PCALL-FAIL", safe_rd(OUT)))
local id = safe_rd(OUT)

-- [D] poll loop
local sc_poll = make_syscall(664)
local IDS = to_num(memory.alloc(0x10))
safe_wd(IDS, id)
safe_wd(IDS + 4, 0)
local ST = to_num(memory.alloc(0x10))
for i = 1, 10 do
    for off = 0, 0xC, 4 do safe_wd(ST + off, 0xDEADDEAD) end
    local okp, r = pcall(function()
        return sc_poll(u64(0, IDS), u64(0, 1), u64(0, ST), u64(0, 0), u64(0, 0), u64(0, 0))
    end)
    print(string.format("[D%d] poll ret=%s state=0x%08X buf=%08X %08X %08X %08X",
        i, okp and tostring(r) or "PCALL-FAIL", safe_rd(ST),
        safe_rd(BUF), safe_rd(BUF + 4), safe_rd(BUF + 8), safe_rd(BUF + 0xC)))
    local now = to_num(os.clock() * 10) % 100000
    local target = (now + 5) % 100000
    repeat until (to_num(os.clock() * 10) % 100000) >= target or target == 0
end

-- [E] delete + health
local sc_del = make_syscall(662)
local okd, rd2 = pcall(function()
    return sc_del(u64(0, IDS), u64(0, 1), u64(0, ST), u64(0, 0), u64(0, 0), u64(0, 0))
end)
print(string.format("[E] delete ret=%s status=0x%08X", okd and tostring(rd2) or "PCALL-FAIL", safe_rd(ST)))

print("=== 566a DONE ===")
