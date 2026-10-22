-- CRASH_CLASS: MODERATE
-- PROBE 236a: what blockpool_batch (657) actually writes
--
-- Context: 191a found the one call in the blockpool family that returns 0 -
-- `657(h, 0, buf)` - and it zeroed a single dword at buf+0, then did the same
-- again after the handle was closed. Everything else in the family (654 map,
-- 655 unmap, read, write) returned -1. A batch call that writes into a caller
-- page is either returning a count, returning status, or copying from the
-- device pool - and the last of those would be a leak worth having.
--
-- 191a counted changed dwords and reported the count, which cannot tell a
-- single zero from a copied structure. This probe fills every dword with a
-- distinct value, dumps every dword that changed with its new value and its
-- offset, and sweeps the second argument:
--
--   A  653(): the handle, and the page as it comes back untouched
--   B  657(h, n, buf) for n in 0..8, each on a fresh canary page
--   C  657(h, 0, buf) three times: does the same dword change every time
--   D  657(h, n, buf) again after close(h): does it still write
--
-- The values decide the reading: a zero is a count or status, a value that
-- looks like a pool offset or a physical address is a copy, and anything above
-- 0xFFFF8 in the high dword is a kernel pointer.

print("=== PROBE 236a: blockpool_batch write surface ===")
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
local function q(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

local sc_getpid = make_syscall(20)
local sc_mmap = make_syscall(477)
local sc_open = make_syscall(653)
local sc_batch = make_syscall(657)
local sc_close = make_syscall(6)

local dead = false
local function pid()
    local ok, v = pcall(function() return sc_getpid():tonumber() end)
    if ok then return v end
    dead = true
    return nil
end
print("[0] canary pid=" .. tostring(pid()))

local BUF = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
zero(BUF, 0x1000)

local PAGE = 0x400
local function pattern()
    for off = 0, PAGE - 4, 4 do wd(BUF + off, 0xAB000000 + off) end
end

local function changed()
    local out = {}
    for off = 0, PAGE - 4, 4 do
        local v = rd(BUF + off)
        if v ~= 0xAB000000 + off then
            out[#out + 1] = { off = off, val = v }
        end
    end
    return out
end

local function report(label, rv)
    local list = changed()
    print(string.format("    %-22s ret=%s changed=%d", label,
        rv == nil and "killed" or tostring(rv), #list))
    for i = 1, math.min(#list, 12) do
        print(string.format("      +0x%03X -> %s", list[i].off, q(list[i].val)))
    end
end

local function batch(label, a2)
    pattern()
    local ok, r = pcall(function()
        return sc_batch(uint64(OPEN), uint64(a2), uint64(BUF))
    end)
    local rv = nil
    if ok and r ~= nil then rv = to_num(r) end
    report(label, rv)
end

local ok, r = pcall(function() return sc_open():tonumber() end)
OPEN = ok and r or nil
print("[A] 653() -> " .. tostring(OPEN))
if OPEN == nil then
    print("    no handle; aborting")
    return
end

print("")
print("[B] 657(h, n, buf) across n")
for n = 0, 8 do
    batch(string.format("657(h,%d,buf)", n), n)
end

print("")
print("[C] 657(h, 0, buf) three times")
for i = 1, 3 do
    batch(string.format("657(h,0,buf) #%d", i), 0)
end

print("")
print("[D] after close(h)")
local okc, rc = pcall(function() return sc_close(uint64(OPEN)):tonumber() end)
print("    close -> " .. (okc and tostring(rc) or "killed"))
batch("657(h,0,buf)", 0)

print("")
print("    pid -> " .. tostring(pid()))
print("")
print("=== PROBE 236a COMPLETE ===")
