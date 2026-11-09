-- CRASH_CLASS: MODERATE
-- PROBE 440a: can one handle be released twice?
--
-- 439a showed osem is reference counted: h1 created and registered, h2 opened by name, and
-- delete(h1) left the object fully usable through h2 while the name stopped resolving. So a
-- handle holds a reference and delete/close drop one.
--
-- The question this asks is whether the two release paths - 550 delete and 552 close - both
-- drop a reference for the *same* handle. If they do, then delete followed by close releases
-- two references on one hold, the object is freed while another handle still points at it,
-- and the slot can be reclaimed with any family (438a showed reclaim is exact and LIFO).
--
-- Three shapes, each on its own name and its own slots:
--   [A] delete(h2) then close(h2) - the double release
--   [B] close(h2) twice
--   [C] delete(h1) twice
-- After each, the surviving handle is exercised: if post/poll still work, the object is
-- alive; if they fail, the release count was wrong.

print("=== PROBE 440a: OSEM DOUBLE RELEASE ===")

local GEN_SHIFT = 8192
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
local function call(num, a1, a2, a3, a4, a5, a6)
    local sc = make_syscall(num)
    local ok, rv = pcall(function()
        return sc(uint64(a1 or 0), uint64(a2 or 0), uint64(a3 or 0), uint64(a4 or 0), uint64(a5 or 0), uint64(a6 or 0))
    end)
    if not ok then return -999 end
    if type(rv) == "table" and rv.h then
        local h, l = to_num(rv.h), to_num(rv.l)
        if h >= 2147483648 then h = h - 4294967296 end
        if l >= 2147483648 then l = l - 4294967296 end
        if h == -1 and l == -1 then return -1 end
        return h * 4294967296 + l
    end
    local n = to_num(rv)
    if n >= 9223372036854775808 then n = n - 18446744073709551616 end
    return n
end
local function slot(h) return h % GEN_SHIFT end
local function gen(h) return math.floor(h / GEN_SHIFT) end
local function tag(h) return string.format("%d(g%d/s%d)", h, gen(h), slot(h)) end

local page = call(477, 0, 0x1000, 7, 0x1002, 0xFFFFFFFF, 0)
if page <= 0 then print("no page") return end
local i = 0
while i < 0x400 do memory.write_qword(page + i, uint64(0)); i = i + 8 end

local function mkname(s)
    local p = memory.alloc(0x40)
    local j = 1
    while j <= #s do memory.write_byte(p + j - 1, s:byte(j)); j = j + 1 end
    memory.write_byte(p + #s, 0)
    return p
end

local function caseA()
    local n = mkname("omp440a1")
    local h1 = call(549, n, 0x100, 0, 4, 0, 0)
    local h2 = call(551, n, 0, 0, 0, 0, 0)
    print(string.format("[A] h1=%s h2=%s", tag(h1), tag(h2)))
    if h1 < 0 or h2 < 0 then return end
    local d = call(550, h2, 0, 0, 0, 0, 0)
    local c = call(552, h2, 0, 0, 0, 0, 0)
    local post = call(555, h1, 1, 0, 0, 0, 0)
    local poll = call(554, h1, 1, 0, 0, 0, 0)
    print(string.format("[A] delete(h2)=%d close(h2)=%d then post(h1)=%d poll(h1)=%d", d, c, post, poll))
end

local function caseB()
    local n = mkname("omp440a2")
    local h1 = call(549, n, 0x100, 0, 4, 0, 0)
    local h2 = call(551, n, 0, 0, 0, 0, 0)
    print(string.format("[B] h1=%s h2=%s", tag(h1), tag(h2)))
    if h1 < 0 or h2 < 0 then return end
    local c1 = call(552, h2, 0, 0, 0, 0, 0)
    local c2 = call(552, h2, 0, 0, 0, 0, 0)
    local post = call(555, h1, 1, 0, 0, 0, 0)
    local poll = call(554, h1, 1, 0, 0, 0, 0)
    print(string.format("[B] close=%d close again=%d then post(h1)=%d poll(h1)=%d", c1, c2, post, poll))
end

local function caseC()
    local n = mkname("omp440a3")
    local h1 = call(549, n, 0x100, 0, 4, 0, 0)
    print(string.format("[C] h1=%s", tag(h1)))
    if h1 < 0 then return end
    local d1 = call(550, h1, 0, 0, 0, 0, 0)
    local d2 = call(550, h1, 0, 0, 0, 0, 0)
    local post = call(555, h1, 1, 0, 0, 0, 0)
    print(string.format("[C] delete=%d delete again=%d then post=%d", d1, d2, post))
end

caseA()
caseB()
caseC()

-- reclaim check: after the double releases, what do fresh allocations get?
local f1 = call(538, page, 0, 0, 0, 0, 0)
local f2 = call(538, page, 0, 0, 0, 0, 0)
print(string.format("[D] fresh evf=%s and %s", tag(f1), tag(f2)))

print("=== 440a DONE ===")
