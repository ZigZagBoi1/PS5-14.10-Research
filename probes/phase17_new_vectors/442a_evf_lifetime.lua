-- CRASH_CLASS: MODERATE
-- PROBE 442a: the evf family's lifetime, the same question 439a asked of osem
--
-- osem is reference counted: delete on the creator's handle removed the name and that handle,
-- and the object stayed alive through a handle opened by name (439a). evf is the other
-- family with a registry - 341a registered names with attribute 0x100 and 540 resolved them -
-- and it has five more operations (544 set, 545 clear, 546 cancel, 543 poll, 542 wait), so it
-- is the richer target for a lifetime hole.
--
-- [A] create a named evf (538(name, 0x100)), open it by name (540), print both ids
-- [B] drive the object through the opened handle: set bits, poll, clear, cancel
-- [C] delete the creator's handle (541) and then drive the object again through the opened one
-- [D] delete the opened handle too
-- [E] does the name still resolve, and does a fresh allocation take the freed slot?

print("=== PROBE 442a: EVF LIFETIME ===")

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

local NP = mkname("omp442a")
local out = page + 0x100

local h1 = call(538, NP, 0x100, 0, 0, 0, 0)
local h2 = call(540, NP, 0, 0, 0, 0, 0)
print(string.format("[A] create=%s open-by-name=%s", tag(h1), tag(h2)))
if h1 < 0 or h2 < 0 then print("=== 442a DONE (no handle) ===") return end

print(string.format("[B] set(h2,0x5)=%d poll(h2,1,out)=%d out=0x%X clear(h2,0x1)=%d cancel(h2)=%d",
    call(544, h2, 0x5, 0, 0, 0, 0),
    call(543, h2, 1, out, 0, 0, 0), to_num(memory.read_dword(out)),
    call(545, h2, 0x1, 0, 0, 0, 0),
    call(546, h2, 0, 0, 0, 0, 0)))

local d1 = call(541, h1, 0, 0, 0, 0, 0)
print(string.format("[C] delete(creator h1)=%d", d1))
print(string.format("[C] after delete: set(h2,0x7)=%d poll(h2,1)=%d out=0x%X",
    call(544, h2, 0x7, 0, 0, 0, 0), call(543, h2, 1, out, 0, 0, 0), to_num(memory.read_dword(out))))

local d2 = call(541, h2, 0, 0, 0, 0, 0)
local d2b = call(541, h2, 0, 0, 0, 0, 0)
print(string.format("[D] delete(opened h2)=%d delete again=%d", d2, d2b))

local reopen = call(540, NP, 0, 0, 0, 0, 0)
local fresh = call(538, page, 0, 0, 0, 0, 0)
print(string.format("[E] reopen by name=%d fresh evf=%s (h1 slot %d, h2 slot %d)",
    reopen, tag(fresh), slot(h1), slot(h2)))

print("=== 442a DONE ===")
