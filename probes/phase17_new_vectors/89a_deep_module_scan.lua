-- CRASH_CLASS: LOW
-- PROBE 89a: Deep scan ALL module data sections for kernel pointers
-- Previous scans only covered 16KB of libkernel (128KB total) and 16KB of eboot.
-- This probe scans the full data section of every accessible module.

print("=== PROBE 89a: DEEP MODULE SCAN ===")

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

print("pid=" .. to_num(syscall.getpid()))

local sc_info = make_syscall(593)
local info = memory.alloc(0x200)

local total_kptr = 0
local handles = {0, 0x2001, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
                 31, 32, 33, 34, 35, 36, 37, 38}

for _, h in ipairs(handles) do
    memory.write_dword(info, 0x160)
    local ok = pcall(function() sc_info(uint64(h), uint64(info)) end)
    if not ok then
        -- skip
    else
        local data_lo = to_num(memory.read_dword(info + 0x118))
        local data_hi = to_num(memory.read_dword(info + 0x11C))
        local data_size = to_num(memory.read_dword(info + 0x120))

        if data_size > 0 and data_hi > 0 then
            local scan_size = math.min(data_size, 0x20000) -- cap at 128KB
            local mod_kptr = 0

            for off = 0, scan_size - 64, 64 do
                local addr = uint64(string.format("0x%X%08X", data_hi, data_lo + off))
                local rok, data = pcall(native.read_buffer, addr, 64)
                if not rok or not data then break end

                for i = 1, #data - 7, 8 do
                    local b1,b2,b3,b4,b5,b6,b7,b8 = data:byte(i,i+7)
                    local lo = b1+b2*256+b3*65536+b4*16777216
                    local hi = b5+b6*256+b7*65536+b8*16777216
                    -- Real kernel pointers: 0xFFFF8000-0xFFFFFFFE range
                    if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
                        -- Filter out known NID hash false positives
                        -- NID hashes have hi=0xFFFF7xxx-0xFFFFBxxx with lo=small offset
                        local dominated = (lo < 0x20000 and hi >= 0xFFFF7000 and hi <= 0xFFFFBFFF)
                        if not dominated then
                            mod_kptr = mod_kptr + 1
                            if mod_kptr <= 5 then
                                print(string.format("  KPTR h=0x%X +0x%04X: 0x%08X%08X", h, off+i-1, hi, lo))
                            end
                        end
                    end
                end
            end

            total_kptr = total_kptr + mod_kptr
            print(string.format("h=%d data=0x%X%08X sz=0x%X scanned=0x%X kptr=%d",
                h, data_hi, data_lo, data_size, scan_size, mod_kptr))
        end
    end
end

print("TOTAL_KPTR=" .. total_kptr)
print("=== PROBE 89a COMPLETE ===")
