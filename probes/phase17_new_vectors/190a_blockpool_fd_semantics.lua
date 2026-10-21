-- CRASH_CLASS: LOW
-- PROBE 190a: is sys 653's return an fd number or an errno?
--
-- Context: the presence sweep called 653 with six zeros and got 22, then 23,
-- then 24, then -1 (183a repeated it). FreeBSD's 22/23/24 are EINVAL/ENFILE/
-- EMFILE, so the same numbers read either as kernel object handles allocated in
-- sequence or as errors from a descriptor table filling up. The two readings
-- predict different behaviour once the descriptor table moves: if 653 hands out
-- the lowest free fd, a socket opened beforehand pushes its answer up by one,
-- and closing that socket pulls it back down. If it is an errno, the answer does
-- not track the table at all.
--
-- Everything here is one connection; a kill ends it.

print("=== PROBE 190a: SYS 653 fd vs errno ===")
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
local function u64(v)
    return uint64(string.format("0x%08X", v))
end
local function show(v)
    if v == nil then return "killed" end
    return tostring(v)
end
local zero = u64(0)

local dead = false
local function call(num, a1, a2, a3, a4, a5, a6)
    local sc = make_syscall(num)
    local ok, ret = pcall(function()
        return sc(a1 or zero, a2 or zero, a3 or zero, a4 or zero, a5 or zero, a6 or zero)
    end)
    if not ok then
        dead = true
        return nil, nil
    end
    return ret, to_num(ret)
end

print("[0] process identity")
local _, pid0 = call(20)
print("    getpid -> " .. show(pid0))
print("")

-- A page the handlers can be pointed at, filled with a value that survives no
-- write, so any dword the kernel touches shows up in the count.
local BUF = memory.alloc(0x1000)
local CANARY = 0x5A5A5A5A
local function fill()
    for off = 0, 0xFFC, 4 do
        pcall(function() memory.write_dword(BUF + off, u64(CANARY)) end)
    end
end
local function changed()
    local n = 0
    local first = nil
    for off = 0, 0xFFC, 4 do
        local ok, v = pcall(function() return memory.read_dword(BUF + off) end)
        if ok and to_num(v) ~= CANARY then
            n = n + 1
            if not first then first = string.format("+0x%03X=%08X", off, to_num(v)) end
        end
    end
    return n, first
end
fill()
print("[0] canary page at " .. tostring(BUF) .. " filled with 0x5A5A5A5A")
print("")

print("[1] take one descriptor before 653 runs")
local sock, sfd = call(97, u64(2), u64(1), u64(0))
print("    socket(AF_INET, SOCK_STREAM) -> " .. show(sock))
if sfd == nil or sfd < 0 then
    sock, sfd = call(97, u64(2), u64(2), u64(0))
    print("    socket(AF_INET, SOCK_DGRAM)  -> " .. show(sock))
end
print("")

print("[2] 653 with zero arguments, three times, while that descriptor is held")
local h = {}
for i = 1, 3 do
    local _, v = call(653)
    print(string.format("    #%d -> %s", i, show(v)))
    if dead then break end
    h[#h + 1] = v
end
print("")

print("[3] close the socket, then ask again")
if sfd and sfd >= 0 then
    local _, cr = call(6, u64(sfd))
    print("    close(" .. sfd .. ") -> " .. show(cr))
end
local _, h4 = call(653)
print("    #4 -> " .. show(h4))
print("")

print("[4] release the first handle, then ask again")
if h[1] and h[1] >= 0 and h[1] < 0x1000 then
    local _, cr = call(6, u64(h[1]))
    print("    close(" .. h[1] .. ") -> " .. show(cr))
end
local _, h5 = call(653)
print("    #5 -> " .. show(h5))
print("")

local live = h5 or h4 or h[3] or h[1]
print("[5] neighbours with handle " .. show(live))
local function with_handle(num, name, a2, a3, a4, a5)
    fill()
    local _, v = call(num, u64(live or 0), a2, a3, a4, a5)
    local n, first = changed()
    print(string.format("    %-22s -> %-14s writes=%d %s", name, show(v), n, first or ""))
end
with_handle(654, "654(h)", zero, zero)
with_handle(654, "654(h,buf)", u64(BUF), zero)
with_handle(654, "654(h,0x1000,buf)", u64(0x1000), u64(BUF))
with_handle(654, "654(h,buf,0x1000)", u64(BUF), u64(0x1000))
with_handle(655, "655(h)", zero, zero)
with_handle(657, "657(h,buf)", u64(BUF), zero)
with_handle(657, "657(h,0,buf)", zero, u64(BUF))
with_handle(673, "673(h)", zero, zero)
print("")

print("[6] 653 argument sensitivity: does it take a pool id, a size, or a name?")
for _, a1 in ipairs({0, 1, 2, 3, 4}) do
    fill()
    local _, v = call(653, u64(a1))
    local n, first = changed()
    print(string.format("    653(%d) -> %-14s writes=%d %s", a1, show(v), n, first or ""))
    if dead then break end
end
print("")

print("[7] still alive?")
local _, pid1 = call(20)
print("    getpid -> " .. show(pid1) .. " (was " .. show(pid0) .. ")")
print("")
print("=== PROBE 190a END ===")
