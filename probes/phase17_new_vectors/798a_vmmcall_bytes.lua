-- CRASH_CLASS: LOW
-- PROBE 798a: hunt for the VMMCALL instruction in user-executable memory
--
-- The 13.60 kernel text holds 34 vmmcall trampolines (0xc16a19..0xc1720d), each the shape
-- `mov eax,<id>; vmmcall; ret`. On AMD SVM, VMMCALL is not a privileged instruction: the
-- hypervisor intercepts it from any CPL. So a CPL3 VMMCALL from this process would reach
-- Sony's hypervisor with our own registers.
--
-- To execute one we need the bytes 0F 01 D9 inside a mapping we may run from. sys 674 says
-- which regions are executable and which of those are readable:
--   .executable (eboot)   prot 5  read+exec
--   .libc.prx             prot 5  read+exec
--   every other system prx prot 4 exec-only, unreadable
-- This probe scans eboot and libc for 0F 01 D9 / D8 / DA / DB / DC / DD and prints hits with
-- their first bytes. Those are the only candidate call sites.

print("=== PROBE 798a: VMMCALL BYTES IN USER TEXT ===")
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
local function u64(h, l) return uint64(string.format("0x%X%08X", h, l)) end

-- sys 674 gives the region map: +0x00 start, +0x08 end, +0x18 prot, +0x20 name
local function regions()
    local sc = make_syscall(674)
    local buf = memory.alloc(512 * 72)
    local cnt = memory.alloc(8)
    safe_wd(cnt, 0)
    local ok = pcall(function()
        return sc(uint64(buf), uint64(72), uint64(512), uint64(cnt), uint64(0x40000000), uint64(0))
    end)
    if not ok then return {} end
    local n = safe_rd(cnt) or 0
    local out = {}
    for i = 0, 320 do
        local r = buf + i * 72
        local sl = safe_rd(r) or 0
        local sh = safe_rd(r + 4) or 0
        local el = safe_rd(r + 8) or 0
        local eh = safe_rd(r + 0xC) or 0
        local prot = safe_rd(r + 0x18) or 0
        if sh == 0 and sl == 0 then break end
        local s = u64(sh, sl)
        local e = u64(eh, el)
        local name = ""
        for k = 0, 31 do
            local b = safe_rd(r + 0x20 + k * 4)
            if not b then break end
            local done = false
            for c = 0, 3 do
                local ch = math.floor(b / (256 ^ c)) % 256
                if ch == 0 then done = true break end
                if ch >= 32 and ch < 127 then name = name .. string.char(ch) end
            end
            if done then break end
        end
        out[#out + 1] = { s = s, e = e, hi = sh, lo = sl, ehi = eh, elo = el, prot = prot, name = name }
    end
    return out, n
end

local regs = regions()
print("[A] regions=" .. tostring(#regs))
local targets = {}
for _, r in ipairs(regs) do
    if r.prot >= 4 then
        print(string.format("  %-28s prot=%d 0x%08X%08X-0x%08X%08X", r.name, r.prot, r.hi, r.lo, r.ehi, r.elo))
        if r.name:find("executable") or r.name:find("libc") then
            targets[#targets + 1] = r
        end
    end
end

local PATS = {
    { 0xD9, "vmmcall" }, { 0xD8, "vmrun" }, { 0xDA, "vmload" },
    { 0xDB, "vmsave" }, { 0xDC, "stgi" }, { 0xDD, "clgi" },
}

for _, r in ipairs(targets) do
    print("")
    print(string.format("[B] scanning %s [0x%08X%08X,0x%08X%08X)", r.name, r.hi, r.lo, r.ehi, r.elo))
    local finds = 0
    local addr = r.lo
    local hi = r.hi
    while hi == 0 and addr + 8 < r.elo do
        local v = safe_rd(addr)
        local v2 = safe_rd(addr + 4)
        if not v or not v2 then break end
        local b = {}
        b[1] = v % 256; b[2] = math.floor(v / 0x100) % 256
        b[3] = math.floor(v / 0x10000) % 256; b[4] = math.floor(v / 0x1000000) % 256
        b[5] = v2 % 256; b[6] = math.floor(v2 / 0x100) % 256
        b[7] = math.floor(v2 / 0x10000) % 256; b[8] = math.floor(v2 / 0x1000000) % 256
        for k = 1, 4 do
            if b[k] == 0x0F and b[k + 1] == 0x01 then
                local b2 = b[k + 2] or -1
                for _, pt in ipairs(PATS) do
                    if b2 == pt[1] then
                        print(string.format("  HIT %s at 0x%08X  next=%02X %02X %02X",
                            pt[2], addr + k - 1, b[k + 3] or 0, b[k + 4] or 0,
                            (safe_rd(addr + k + 2) or 0) % 256))
                        finds = finds + 1
                    end
                end
            end
        end
        addr = addr + 4
    end
    print(string.format("  %s hits=%d", r.name, finds))
end

print("")
print("[C] alive")
