-- CRASH_CLASS: MODERATE
-- PROBE 1566a: /dev/dce's REAL ioctl command words, recovered statically from the
--              13.60 kernel text, tested on 14.10 for the first time.
--
-- Context: docs/DEVICE_IOCTL_14_10.md records that every earlier sweep fired
-- 16-bit command numbers (0x0000..0xFFFF) or 32-bit words built from a fixed
-- length set {0, 4, 8, 0x10, 0x20, 0x40, 0x100}. Only 0x80088209 answered. The
-- 13.60 dispatcher for /dev/dce compares the command register against thirteen
-- 32-bit constants, most of whose length fields (0x18, 0x58, 0xce8, 0x308, ...)
-- are NOT in that set, so they were never constructed, let alone sent:
--
--   0xffffffff8b05585b  mov ecx, 0x9ce88210
--   0xffffffff8b055865  mov ecx, 0x80208217
--   0xffffffff8b05586f  mov ecx, 0x80208218
--   0xffffffff8b05587d  mov ecx, 0x80288208
--   0xffffffff8b05588b  mov ecx, 0x80308217
--   0xffffffff8b055892  mov ecx, 0xc0188212
--   0xffffffff8b05589c  mov eax, 0xc0188213
--   0xffffffff8b0558aa  mov eax, 0xc0588212
--   0xffffffff8b0558b8  mov eax, 0xc0208219
--   0xffffffff8b0558cc  cmp r15, 0x40d08214
--   0xffffffff8b0558d5  mov ecx, 0x80088209
--   0xffffffff8b0558f6  mov ecx, 0x9ce88211
--   0xffffffff8b055900  mov ecx, 0xc008820b
--
-- This is a pure discovery run: send each word once with a zeroed page and
-- report rv, errno and whether the page changed. Nothing here is expected to be
-- dangerous; the one measured hazard in the ioctl space (0xC0048125 on
-- /dev/gc) blocks the thread forever and is not in this list.
--
-- prior art:
--   docs/DEVICE_IOCTL_14_10.md "The sweeps" -- 274a/275a/278a/279a/280a/284a/286a
--     all used 16-bit bases or the fixed length set; only 0x80088209 answered.
--   docs/DEVICE_IOCTL_14_10.md "/dev/dce" -- 0x80088209 copies in exactly 8
--     bytes, ignores its content, and is idempotent (277a).
--   results/... 276a separated the four file-layer commands.
--   The constants above were read from .local/ktext_ins.pkl at the VAs quoted.
--
-- Method:
--   [A] open /dev/dce, confirm the known command 0x80088209 still answers 0
--       (a positive control that this run's descriptor is good).
--   [B] each of the twelve other words with a zeroed 0x1000 page as arg, one
--       call each, printing the word and the declared length before the call.
--   [C] the same words with arg = a page filled with 0xFF, to catch commands
--       that read a flag out of the argument.
--   [D] close and report. Every call prints BEFORE it happens, so a kill is
--       attributed to the word on the previous line.

print("=== PROBE 1566a: /dev/dce real ioctl commands (13.60 table) ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(uint64(a)) end)
    if ok then return to_num(v) end
    return nil
end
local function wd(a, v) pcall(function() memory.write_dword(uint64(a), uint64(v)) end) end

local sc_open  = mk(5)
local sc_close = mk(6)
local sc_ioctl = mk(54)
local sc_getpid = mk(20)

print(string.format("[0] pid=%d", to_num(sc_getpid())))

local path = memory.alloc(0x40)
local function set_path(s)
    for i = 0, #s do
        pcall(function() memory.write_byte(uint64(path + i), string.byte(s, i + 1)) end)
    end
    pcall(function() memory.write_byte(uint64(path + #s + 1), 0) end)
end

set_path("/dev/dce")
local okO, rvO = pcall(function() return sc_open(uint64(path), uint64(2), uint64(0)) end)
local fd = okO and to_num(rvO) or -1
print(string.format("[0] open('/dev/dce', O_RDWR) fd=%d", fd))
if fd < 0 then
    set_path("/dev/dce")
    local ok2, rv2 = pcall(function() return sc_open(uint64(path), uint64(0), uint64(0)) end)
    fd = ok2 and to_num(rv2) or -1
    print(string.format("[0] fallback open(O_RDONLY) fd=%d", fd))
end
if fd < 0 then
    print("=== VOID: cannot open /dev/dce ===")
    return
end

local page = memory.alloc(0x1000)
local function zero_page()
    for o = 0, 0xFFC, 4 do wd(page + o, 0) end
end
local function ff_page()
    for o = 0, 0xFFC, 4 do wd(page + o, 0xFFFFFFFF) end
end

local function call(tag, cmd)
    zero_page()
    local ok, rv = pcall(function()
        return sc_ioctl(uint64(fd), uint64(cmd), uint64(page))
    end)
    local r = ok and to_num(rv) or -999
    local d0 = rd(page)
    print(string.format("%s cmd=0x%08X rv=%d buf[0]=0x%X", tag, cmd, r, to_num(d0 or 0)))
    return r
end

-- ---- [A] positive control ----
print("")
print("[A] positive control: the one command the corpus already knows")
call("[A]", 0x80088209)

-- ---- [B] the twelve recovered words, zeroed page ----
print("")
print("[B] zeroed 0x1000 page, one call per word")
local words = {
    0x9ce88210, 0x80208217, 0x80208218, 0x80288208, 0x80308217,
    0xc0188212, 0xc0188213, 0xc0588212, 0xc0208219, 0x40d08214,
    0x9ce88211, 0xc008820b,
}
local answered = {}
for _, w in ipairs(words) do
    local r = call("[B]", w)
    if r == 0 then answered[#answered + 1] = w end
end
print(string.format("[B] words answered with 0: %d of %d", #answered, #words))
for _, w in ipairs(answered) do
    print(string.format("[B]   answered 0x%08X", w))
end

-- ---- [C] the same words with a 0xFF argument page ----
print("")
print("[C] 0xFF page, one call per word (only the words that did not answer 0)")
for _, w in ipairs(words) do
    local seen = false
    for _, a in ipairs(answered) do if a == w then seen = true end end
    if not seen then
        ff_page()
        local ok, rv = pcall(function()
            return sc_ioctl(uint64(fd), uint64(w), uint64(page))
        end)
        local r = ok and to_num(rv) or -999
        print(string.format("[C] cmd=0x%08X rv=%d buf[0]=0x%X",
            w, r, to_num(rd(page) or 0)))
    end
end

-- ---- [D] teardown ----
print("")
print("[D] closing")
pcall(function() sc_close(uint64(fd)) end)
print(string.format("[D] closed fd=%d", fd))
print("")
print("=== PROBE 1566a COMPLETE ===")
