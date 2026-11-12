-- CRASH_CLASS: HIGH
-- PROBE 557d: how long can a named object's name be?
--
-- 557(name_ptr, flags, 0, 0) creates an object in the shared handle table and
-- copies the string (557c: the caller's page can be unmapped afterwards). The
-- copy is the interesting part: a fixed-size record with a strcpy has no length
-- limit, and a length check would show up as a cutoff or a refusal.
--
-- The sweep runs from 1 byte to a whole page. Each create is paired with
-- 558(handle) so nothing accumulates. The final case has no terminator inside
-- the page at all - if the kernel uses strlen, that read runs into the next
-- page, which is the one shape that can fault in kernel context.

print("=== PROBE 557d: name length ===")

local function to_num(v)
    if type(v)=="table" then
        if v.tonumber then local n=v:tonumber() if n then return n end end
        if v.h then return v.h*4294967296+v.l end
    end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local function wb(a,v) pcall(function() memory.write_byte(a,v) end) end
local function call(f,...)
    local ok,rv=pcall(f,...)
    if not ok then return -999 end
    return to_num(rv)
end
local function mmap(px)
    local _, a = pcall(function()
        return mk(477)(uint64(0), uint64(px), uint64(3), uint64(0x1002),
            uint64(0xFFFFFFFF), uint64(0))
    end)
    local v = to_num(a)
    if v ~= 0 then zero(v, px) end
    return v
end
local function pid() return to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20)) end

print("[0] pid=" .. tostring(pid()))

local PAGE = 0x4000
local page = mmap(PAGE)
if page == 0 then print("[!] mmap failed"); return end
print(string.format("[1] page=%X", page))

local lengths = {1, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128,
                 255, 256, 257, 1023, 1024, 2047, 2048, 4095, 4096, 8191, 16383}

print("--- length sweep: fill, create, delete ---")
for i = 1, #lengths do
    local L = lengths[i]
    zero(page, PAGE)
    for k = 0, L - 1 do wb(page + k, 65 + (k % 26)) end
    wb(page + L, 0)
    local h = call(mk(557), uint64(page), uint64(0), uint64(0), uint64(0))
    local alive = pid()
    local d = -999
    if h > 0 then d = call(mk(558), uint64(h)) end
    print(string.format("  len=%-5d create=%-12d delete=%-4d alive=%d", L, h, d, alive))
    if alive == 0 then print("  [!] process gone at len=" .. L); return end
end
print("")

print("--- no terminator inside the page (strlen would run over) ---")
zero(page, PAGE)
for k = 0, PAGE - 1 do wb(page + k, 66) end
print("  page is all 'B', last byte=" .. tostring(65 + 0) .. "-ish")
local h = call(mk(557), uint64(page), uint64(0), uint64(0), uint64(0))
print("  create(no NUL) ret=" .. h .. " alive=" .. tostring(pid()))
if h > 0 then
    print("  delete ret=" .. call(mk(558), uint64(h)))
end
local h2 = call(mk(557), uint64(page), uint64(0), uint64(0), uint64(0))
print("  create again ret=" .. h2 .. " (same handle? " .. tostring(h == h2) .. ")")
print("[Z] alive=" .. tostring(pid()))
print("=== PROBE 557d COMPLETE ===")
