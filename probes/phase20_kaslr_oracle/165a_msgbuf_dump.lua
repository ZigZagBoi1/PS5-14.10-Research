-- CRASH_CLASS: LOW
-- PROBE 165a: Dump kern.msgbuf (dmesg) looking for kernel addresses

print("=== PROBE 165a: MSGBUF DUMP ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local sc202 = make_syscall(202)
local mib = memory.alloc(16)
local oldlen_buf = memory.alloc(8)
local data_buf = memory.alloc(0x4000)

-- Read kern.msgbuf: MIB {1, 28}
memory.write_dword(mib, 1)
memory.write_dword(mib + 4, 28)
memory.write_qword(oldlen_buf, uint64(0x4000))

local ok, rv = pcall(function()
    return sc202(uint64(mib), uint64(2), uint64(data_buf), uint64(oldlen_buf), uint64(0), uint64(0))
end)

local dlen = to_num(memory.read_qword(oldlen_buf))
print("msgbuf: ret=" .. (ok and "OK" or "FAIL") .. " len=" .. dlen)
print("")

if not ok or dlen == 0 then
    print("No data")
    print("=== PROBE 165a COMPLETE ===")
    return
end

-- Dump as text, 64 bytes per line, reading dword-by-dword
local limit = math.min(dlen, 0x4000)
local line = {}
local line_count = 0
local total_chars = 0

for off = 0, limit - 4, 4 do
    local raw = memory.read_dword(data_buf + off)
    local dw = to_num(raw)
    for shift = 0, 24, 8 do
        local byte = math.floor(dw / (2^shift)) % 256
        total_chars = total_chars + 1
        if byte == 10 then
            -- newline: flush line
            local s = table.concat(line)
            if #s > 0 then
                print(s)
                line_count = line_count + 1
            end
            line = {}
        elseif byte >= 32 and byte < 127 then
            line[#line+1] = string.char(byte)
        elseif byte == 0 then
            -- null: might be end or padding
            if #line > 0 then
                line[#line+1] = "."
            end
        else
            line[#line+1] = "."
        end
    end
end

-- Flush remaining
if #line > 0 then
    print(table.concat(line))
    line_count = line_count + 1
end

print("")
print("Lines: " .. line_count .. " Chars: " .. total_chars)
print("=== PROBE 165a COMPLETE ===")
