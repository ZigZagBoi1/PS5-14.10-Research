-- CRASH_CLASS: LOW
-- PROBE 333a: sys 587 (credential record) against pids this process does not own
--
-- 332a passed our own pid and got the allowlist path: a zeroed 0x88-byte
-- record with only +0x0C = 0x20000000. The dossier says pid 0 selects the
-- current process and a nonzero pid is looked up and checked with
-- 0x2a8ca0(td,target) before the 0x2ae privilege test. This asks for a few
-- low system pids and records whether the lookup or the permission check is
-- what answers, and repeats 535/536 with pid 0.

print("=== PROBE 333a: CREDENTIAL RECORD BY PID ===")
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
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
local function lo_of(v)
    local h, l = get_hi_lo(v)
    return to_num(l), to_num(h)
end
local function call(sc, a, b, c, d)
    local ok, rv = pcall(function() return sc(a, b, c, d) end)
    if not ok then return "RAISED" end
    return tostring(sgn(lo_of(rv)))
end

local sc587 = make_syscall(587)
local BUF = memory.alloc(0x200)

local function dump(tag)
    local hits = {}
    for i = 0, 0x88 - 4, 4 do
        local v = safe_rd(BUF + i)
        if v and v ~= 0 then hits[#hits + 1] = string.format("+0x%02X=%08X", i, v) end
    end
    print(string.format("  %s record: %s", tag, #hits > 0 and table.concat(hits, " ") or "all zero"))
end

for _, pid in ipairs({ 0, 1, 2, 5, 16, 30 }) do
    for i = 0, 0x200 - 8, 8 do safe_wq(BUF + i, uint64(0)) end
    local r = call(sc587, uint64(pid), uint64(BUF), uint64(0), uint64(0))
    print(string.format("[A] 587(pid=%d) = %s", pid, r))
    if r == "0" then dump("pid=" .. pid) end
end

print("")
print("[B] dynamic-linker list with pid 0 (current process)")
local CNT = memory.alloc(8)
safe_wq(CNT, uint64(0))
print(string.format("  535(0,buf,0x80,count) = %s count=%s",
    call(make_syscall(535), uint64(0), uint64(BUF), uint64(0x80), uint64(CNT)),
    tostring(safe_rd(CNT))))
safe_wq(CNT, uint64(0))
print(string.format("  536(0,buf,0x80,count) = %s count=%s",
    call(make_syscall(536), uint64(0), uint64(BUF), uint64(0x80), uint64(CNT)),
    tostring(safe_rd(CNT))))

print("")
print("=== 333a DONE ===")
