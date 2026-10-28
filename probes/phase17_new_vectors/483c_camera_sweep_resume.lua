-- CRASH_CLASS: MODERATE
-- PROBE 483c: resume the /dev/camera encoding sweep past the rest-mode stop
--
-- Context: 483a covered 1 677 312 of 2 949 120 encodings before the console
-- entered rest mode at dir=0x40000000 len=0x100 cmd=0x410097FF. Its hit filter
-- was also wrong: it required BOTH halves of the return to be -1, so EINVAL
-- (high 0, low 0x16) was printed as a HIT. This probe fixes the filter and
-- resumes at the exact stopping point instead of redoing an hour of calls.
--
-- Refusals are -1 and EINVAL. Anything else (including 0) is printed.

print("=== PROBE 483c: camera sweep resume ===")
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
local function sgn(v)
    local n = to_num(v)
    if n >= 0x8000000000000000 then return n - 0x10000000000000000 end
    if n >= 0x80000000 and n < 0x100000000 then return n - 0x100000000 end
    return n
end
local function split(v)
    if type(v) == "table" and v.h then return v.h, v.l end
    return 0, to_num(v)
end
local function is_refusal(h, l)
    if (h == -1 or h == 0xFFFFFFFF or h == 0xFFFFFFFFFFFFFFFF) and
       (l == -1 or l == 0xFFFFFFFF) then return true end
    if (h == 0 or h == 0xFFFFFFFFFFFFFFFF) and l == 0x16 then return true end
    return false
end
local function put_str(s)
    local buf = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(buf + i - 1, string.byte(s, i)) end) end
    pcall(function() memory.write_byte(buf + #s, 0) end)
    return buf
end

local sc_open  = make_syscall(5)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)

local RESUME_DIR, RESUME_LEN, RESUME_CMD = 0x40000000, 0x100, 0x41009800
local dirs = { 0x00000000, 0x20000000, 0x40000000, 0x80000000, 0xC0000000 }
local lens = { 0, 4, 8, 0x10, 0x18, 0x20, 0x40, 0x100, 0x1000 }
local TOP = 0x10000

local page = memory.alloc(0x1000)
for off = 0, 0xFFC, 4 do pcall(function() memory.write_dword(page + off, 0) end) end
local arg = uint64(page)

local fd = sgn(sc_open(uint64(put_str("/dev/camera")), uint64(2), uint64(0)))
if fd < 0 then fd = sgn(sc_open(uint64(put_str("/dev/camera")), uint64(0), uint64(0))) end
print(string.format("open=%d resume=dir 0x%08X len 0x%X cmd 0x%08X", fd, RESUME_DIR, RESUME_LEN, RESUME_CMD))

if fd >= 0 then
    local total, hits, shown = 0, 0, 0
    local started = false
    for _, d in ipairs(dirs) do
        for _, len in ipairs(lens) do
            local base = d + (len * 0x10000)
            local g0 = 0
            if not started then
                if d == RESUME_DIR and len == RESUME_LEN then
                    started = true
                    g0 = RESUME_CMD - base
                    if g0 < 0 then g0 = 0 end
                else
                    g0 = nil
                end
            end
            if started and g0 then
                print(string.format("  [dir=0x%08X len=0x%X from 0x%08X]", d, len, base + g0))
                for g = g0, TOP - 1 do
                    local cmd = base + g
                    local ok, r = pcall(function() return sc_ioctl(uint64(fd), uint64(cmd), arg) end)
                    total = total + 1
                    local out = nil
                    if not ok then
                        out = "PCALL-FAIL"
                    else
                        local h, l = split(r)
                        if not is_refusal(h, l) then
                            out = string.format("0x%X%08X", h, l)
                        end
                    end
                    if out then
                        hits = hits + 1
                        if shown < 200 then
                            shown = shown + 1
                            print(string.format("  HIT cmd=0x%08X ret=%s", cmd, out))
                        end
                    end
                    if total % 0x800 == 0 then
                        print(string.format("  .. %d calls dir=0x%08X len=0x%X cmd=0x%08X hits=%d", total, d, len, cmd, hits))
                    end
                end
            end
        end
    end
    print(string.format("DONE total=%d hits=%d", total, hits))
    sgn(sc_close(uint64(fd)))
end
print("=== PROBE 483c END ===")
