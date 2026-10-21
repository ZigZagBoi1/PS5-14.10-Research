-- CRASH_CLASS: LOW
-- PROBE 175a: argument layout sweep on 662-669
--
-- 174a gave 662, 663, 664, 666, 667 and 669 a zeroed 0x400 page in RDI and
-- 0x400 in RSI. All six returned -1 and wrote nothing, exactly as they did with
-- six zeros, so they reject before touching the buffer.
--
-- Two explanations remain: the argument order is different, or the handlers are
-- gated on state that only exists after an AIO context is created - and the
-- number that would create one (661) is an absent slot. This probe sweeps the
-- three plausible layouts with the selector in each of the first three
-- positions. Anything other than -1 identifies the layout; a flat -1 across all
-- three supports the "no context can ever exist" reading, which closes the range
-- for good rather than for lack of trying.
--
-- Selectors 0-8 in each layout, six calls per number, all arguments validated by
-- the handler before any state is touched.

print("=== PROBE 175a: AIO LAYOUT SWEEP ===")

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
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end

local sc20 = make_syscall(20)
print("[0] canary pid=" .. tostring(to_num(sc20())))

local buf = memory.alloc(0x200)

local function clear()
    for i = 0, 0x1FC, 4 do safe_wd(buf + i, 0) end
end

local function probe(num, a, b, c)
    local sc = make_syscall(num)
    clear()
    local ok, rv = pcall(function()
        return sc(uint64(a), uint64(b), uint64(c), uint64(0), uint64(0), uint64(0))
    end)
    local hi, lo = 0, 0
    if ok then hi, lo = get_hi_lo(rv) end
    return ok, lo
end

for _, num in ipairs({662, 663, 664, 666, 667, 669}) do
    local hits = {}
    for sel = 0, 8 do
        local ok, lo
        ok, lo = probe(num, sel, 0, 0)          -- selector first
        if not ok or lo ~= 0xFFFFFFFF then hits[#hits + 1] = "A sel=" .. sel .. " ret=" .. tostring(lo) end
        ok, lo = probe(num, 0, sel, 0)          -- selector second
        if not ok or lo ~= 0xFFFFFFFF then hits[#hits + 1] = "B sel=" .. sel .. " ret=" .. tostring(lo) end
        ok, lo = probe(num, 0, 0, sel)          -- selector third
        if not ok or lo ~= 0xFFFFFFFF then hits[#hits + 1] = "C sel=" .. sel .. " ret=" .. tostring(lo) end
    end
    if #hits == 0 then
        print("[*] sys " .. num .. ": -1 in all 27 calls")
    else
        for _, h in ipairs(hits) do print("[*] sys " .. num .. ": " .. h) end
    end
end

print("[9] canary after: ok=true pid=" .. tostring(to_num(sc20())))
print("=== PROBE 175a DONE ===")
