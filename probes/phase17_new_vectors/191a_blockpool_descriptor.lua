-- CRASH_CLASS: MODERATE
-- PROBE 191a: what the 653 descriptor is, and whether it maps
--
-- Context: 190a proved 653 allocates file descriptors. A socket answered 22,
-- then 653 answered 23, 24, 25, then -1; close(23) returned 0 and the next 653
-- answered 22 again. So blockpool_open hands out real descriptors from the
-- process table and stops after three are open (the fourth failed while 22 was
-- free). Nothing is known yet about what the descriptor is attached to.
--
-- This probe first clears the handles 190a left open (24, 25 in the same
-- process), re-establishes the three-slot limit from a clean state, then asks
-- the descriptor to mmap, to read, to write, and to be used by 654/655/657/673.
-- The last section closes a handle and uses it anyway, because a handler that
-- does not revalidate the descriptor is the bug worth finding here.

print("=== PROBE 191a: the sys 653 descriptor ===")
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
    if type(v) == "number" then return uint64(string.format("0x%08X", v)) end
    return v
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
        return sc(u64(a1 or 0), u64(a2 or 0), u64(a3 or 0), u64(a4 or 0), u64(a5 or 0), u64(a6 or 0))
    end)
    if not ok then
        dead = true
        return nil, nil
    end
    return ret, to_num(ret)
end

local BUF = memory.alloc(0x1000)
local CANARY = 0x5A5A5A5A
local function fill()
    for off = 0, 0xFFC, 4 do
        pcall(function() memory.write_dword(BUF + off, u64(CANARY)) end)
    end
end
local function changed()
    local n, first = 0, nil
    for off = 0, 0xFFC, 4 do
        local ok, v = pcall(function() return memory.read_dword(BUF + off) end)
        if ok and to_num(v) ~= CANARY then
            n = n + 1
            if not first then first = string.format("+0x%03X=%08X", off, to_num(v)) end
        end
    end
    return n, first
end

local _, pid0 = call(20)
print("[0] getpid " .. show(pid0))
print("")

print("[1] clear whatever the previous connection left open, then drain again")
local opened = {}
for i = 1, 5 do
    local _, v = call(653)
    print(string.format("    drain #%d -> %s", i, show(v)))
    if dead then break end
    if v and v >= 0 and v < 0x100 then opened[#opened + 1] = v end
end
for _, fd in ipairs(opened) do
    local _, cr = call(6, fd)
    print(string.format("    close(%d) -> %s", fd, show(cr)))
end
print("")

print("[2] three-slot limit from a clean table")
local hs = {}
for i = 1, 5 do
    local _, v = call(653)
    print(string.format("    open #%d -> %s", i, show(v)))
    if dead then break end
    if v and v >= 0 and v < 0x100 then hs[#hs + 1] = v end
end
print("    handles: " .. table.concat(hs, ", "))
print("")

local h = hs[1]
if not h then
    print("[!] no handle, stopping")
else
    print("[3] does the descriptor take mmap? handle " .. h)
    local shapes = {
        { "mmap(h,0x4000,3,1)",   0, 0x4000, 3, 1 },
        { "mmap(h,0x4000,3,0x1002)", 0, 0x4000, 3, 0x1002 },
        { "mmap(h,0x4000,0,1)",   0, 0x4000, 0, 1 },
        { "mmap(h,0x1000,3,2)",   0, 0x1000, 3, 2 },
    }
    for _, s in ipairs(shapes) do
        local r, v = call(477, s[2], s[3], s[4], s[5], h, 0)
        print(string.format("    %-24s -> %s", s[1], show(v)))
        if dead then break end
        if v and v > 0x10000 then
            local ok, w = pcall(function() return memory.read_dword(v) end)
            print(string.format("       first dword at 0x%X: %s", v, ok and tostring(w) or "fault"))
        end
    end
    print("")

    print("[4] read/write/ioctl on the descriptor")
    fill()
    local _, rr = call(3, h, BUF, 64)
    local n, first = changed()
    print(string.format("    read(h,buf,64)   -> %-14s writes=%d %s", show(rr), n, first or ""))
    fill()
    local _, wr = call(4, h, BUF, 16)
    n, first = changed()
    print(string.format("    write(h,buf,16)  -> %-14s writes=%d %s", show(wr), n, first or ""))
    local _, ir = call(54, h, 0)
    print("    ioctl(h,0)       -> " .. show(ir))
    print("")

    print("[5] 654/655/657/673 with a live handle")
    local function with_handle(num, name, a2, a3, a4, a5)
        fill()
        local _, v = call(num, h, a2 or 0, a3 or 0, a4 or 0, a5 or 0)
        local c, first = changed()
        print(string.format("    %-26s -> %-14s writes=%d %s", name, show(v), c, first or ""))
    end
    with_handle(654, "654(h)", 0, 0)
    with_handle(654, "654(h,0,buf)", 0, BUF)
    with_handle(654, "654(h,buf,0x1000)", BUF, 0x1000)
    with_handle(654, "654(h,0x1000,buf)", 0x1000, BUF)
    with_handle(654, "654(h,0,buf,3)", 0, BUF, 3)
    with_handle(655, "655(h)", 0, 0)
    with_handle(655, "655(h,buf)", BUF, 0)
    with_handle(657, "657(h,buf)", BUF, 0)
    with_handle(657, "657(h,0,buf)", 0, BUF)
    with_handle(673, "673(h)", 0, 0)
    print("")

    print("[6] use after close: is the descriptor revalidated?")
    local _, cr = call(6, h)
    print("    close(" .. h .. ") -> " .. show(cr))
    fill()
    local _, b = call(657, h, 0, BUF)
    local c, first = changed()
    print(string.format("    657(closed h,0,buf) -> %-14s writes=%d %s", show(b), c, first or ""))
    if not dead then
        fill()
        local _, m = call(654, h, 0, BUF)
        c, first = changed()
        print(string.format("    654(closed h,0,buf) -> %-14s writes=%d %s", show(m), c, first or ""))
    end
    if not dead then
        local _, r2 = call(3, h, BUF, 64)
        print("    read(closed h)      -> " .. show(r2))
    end
end

print("")
print("[7] getpid " .. show((call(20))))
print("=== PROBE 191a END ===")
