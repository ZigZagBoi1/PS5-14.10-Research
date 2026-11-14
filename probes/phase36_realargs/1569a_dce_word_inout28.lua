-- CRASH_CLASS: LOW
-- PROBE 1569a_dce_word_inout28: /dev/dce command 0x80288208, one word per run.
--
-- Context: docs/DEVICE_IOCTL_14_10.md lists thirteen 32-bit command words the
-- 13.60 /dev/dce dispatcher compares the command register against. Every earlier
-- sweep fired 16-bit numbers or a fixed length set and could never have built
-- these words, so the whole group is unmeasured on 14.10 except:
--
--   0x80088209  rv=0        (286a, 1566a - the only one the corpus ever sent)
--   0x9CE88210  rv=-1       (1566a)
--   0x80208217  BLOCKED     (1566a - wedged the loader, then the console)
--
-- 1566a also proved static screening cannot help: the 13.60 dispatcher maps
-- 0x80208217 to a plain EINVAL ("no case" fallthrough) yet 14.10 entered a
-- handler that never returned, so the 14.10 driver is a different build.
--
-- This probe sends exactly ONE unmeasured word, after a positive control, so a
-- block costs one run instead of one run per word in a batch.
--
-- 13.60 route for 0x80288208: 0x8b607ef0(cdev, arg), 0x28 bytes
-- Risk ranking: low: single direct handler
--
-- prior art:
--   docs/DEVICE_IOCTL_14_10.md  "The real command words, recovered from the
--     13.60 dispatcher" + "Complete 13.60 route for every /dev/dce word" +
--     "CONSOLE-FATAL commands" (the 0x80208217 row).
--   results/phase36_realargs/1566a_dce_real_ioctl_words_20261110_201038.txt
--     pid 319 fd 22: 0x80088209 rv=0, 0x9CE88210 rv=-1, 0x80208217 never
--     returned (IDLE_TIMEOUT 30s -> CONNECT_TIMEOUT).
--   docs/DEVICE_IOCTL_14_10.md "/dev/dce" - 277a: 0x80088209 copies in exactly
--     8 bytes, ignores the content, idempotent.
--
-- Method: [A] open /dev/dce O_RDWR, [B] positive control 0x80088209, [C] the one
-- word with a zeroed 0x1000 page, [D] close. Every print happens before the call
-- it describes, so a block leaves the word on the last line of the capture.

print("=== PROBE 1569a_dce_word_inout28: dce 0x80288208 ===")
print("[C] about to send 0x80288208 with a zeroed 0x1000 page")
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
local s = "/dev/dce"
for i = 0, #s do
    pcall(function() memory.write_byte(uint64(path + i), string.byte(s, i + 1)) end)
end
pcall(function() memory.write_byte(uint64(path + #s + 1), 0) end)

local okO, rvO = pcall(function() return sc_open(uint64(path), uint64(2), uint64(0)) end)
local fd = okO and to_num(rvO) or -1
print(string.format("[A] open('/dev/dce', O_RDWR) fd=%d", fd))
if fd < 0 then
    print("=== VOID: cannot open /dev/dce ===")
    return
end

local page = memory.alloc(0x1000)
for o = 0, 0xFFC, 4 do wd(page + o, 0) end

local okA, rvA = pcall(function() return sc_ioctl(uint64(fd), uint64(0x80088209), uint64(page)) end)
print(string.format("[B] control 0x80088209 rv=%s (want 0)", tostring(okA and to_num(rvA) or -999)))
if not okA or to_num(rvA) ~= 0 then
    print("=== VOID: the positive control failed; the descriptor is not what 1566a had ===")
    return
end

for o = 0, 0xFFC, 4 do wd(page + o, 0) end
print("[C] sending now")
local okC, rvC = pcall(function() return sc_ioctl(uint64(fd), uint64(0x80288208), uint64(page)) end)
print(string.format("[C] 0x80288208 rv=%s buf[0]=0x%X",
    tostring(okC and to_num(rvC) or -999), to_num(rd(page) or 0)))

print("[D] closing")
pcall(function() sc_close(uint64(fd)) end)
print("=== PROBE 1569a_dce_word_inout28 COMPLETE ===")
