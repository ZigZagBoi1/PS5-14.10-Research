-- CRASH_CLASS: LOW
-- PROBE N1: pfsmnt/sandbox mount-tree re-enumeration from the game process
--
-- Context (prior art):
--   probes/phase1_identity_layout/05_file_recon.lua (2026-10-15): /mnt,
--   /mnt/usb0../1 -> -1; /mnt/sandbox touched; /mnt/sandbox/pfsmnt listed
--   "0 entries" once - reachable and EMPTY. Untested since.
--   docs/JAIL_14_10.md:23 - jail contains no /mnt mount points.
--   docs/UNTESTED_THEORIES.md "Theory N" (eljcn pfsmnt confused-deputy):
--   the /mnt/sandbox tree visibility outside our own jail was the one
--   unbanked sliver. This probe re-measures in the CURRENT context where a
--   real title IS mounted (/app0 exists right now).
--
-- Method: syscall.resolve() helpers (05_file_recon pattern) for
-- open/getdents/close/read; make_syscall for fstat(189) readback and
-- vm-map(674) name scan (55e/55f shapes).

print("=== PROBE N1: pfsmnt/sandbox mount-tree re-enumeration ===")
print("")

local out = {}
local function log(s) out[#out+1] = s; print(s) end

syscall.resolve({
    sc_open = 5, sc_close = 6, sc_read = 3, sc_getdents = 272, sc_fstat = 189,
})

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
local function hexn(v) return string.format("0x%x", to_num(v)) end

local sc_fstat = make_syscall(189)
local sc_vmmap = make_syscall(674)

-- A: sys 674 VM-map region-name scan for mount-path strings
log("--- A: sys 674 region-name scan (mnt/pfs/CUSA/app0) ---")
local outbuf = memory.alloc(0x40000)
local ok674 = pcall(function() sc_vmmap(uint64(outbuf), uint64(0), uint64(0x40000)) end)
log("  674 call ok=" .. tostring(ok674))
local found = 0
local function cstr(addr, max)
    local bytes = {}
    for i = 0, (max or 40) - 1 do
        local b = safe_rd(addr + i)
        if not b or b == 0 then break end
        bytes[#bytes + 1] = string.char(b)
    end
    return table.concat(bytes)
end
if ok674 then
    for i = 0, 0x40000 - 72, 72 do
        local name = cstr(outbuf + i + 0x20, 40)
        if name:len() > 3 then
            local low = name:lower()
            if name:find("mnt", 1, true) or name:find("pfs", 1, true)
               or name:find("CUSA", 1, true) then
                log("  region name: " .. name)
                found = found + 1
                if found >= 20 then break end
            end
        end
    end
end
log("  name-hits: " .. found)
log("")

-- probe one directory: open (with and without dir flag), getdents, fstat raw
local function trydir(path)
    local fd = to_num(syscall.sc_open(path, 0x00020000))
    if fd < 0 or fd > 99 then fd = to_num(syscall.sc_open(path, 0)) end
    local line = path .. ": open=" .. fd
    if fd >= 0 and fd <= 99 then
        local buf = memory.alloc(4096)
        local okgd, n = pcall(function() return syscall.sc_getdents(fd, buf, 4096):tonumber() end)
        line = line .. " getdents=" .. (okgd and tostring(n) or "ERR")
        if okgd and n and n > 0 then
            local names = {}
            local o = 0
            while o < n do
                local reclen = safe_rd(buf + o + 8)
                if not reclen or reclen <= 0 then break end
                local nm = cstr(buf + o + 12, 64)
                names[#names + 1] = nm
                o = o + reclen
            end
            line = line .. " entries=[" .. table.concat(names, ",") .. "]"
        end
        -- fstat readback: raw 48 bytes at +0
        local sb = memory.alloc(160)
        local okfs = pcall(function() sc_fstat(uint64(fd), uint64(sb)) end)
        if okfs then
            local hx = {}
            for i = 0, 23 do
                local b = safe_rd(sb + i)
                hx[#hx + 1] = string.format("%02x", b or 0)
            end
            line = line .. " fstat[0..23]=" .. table.concat(hx, "")
        end
        syscall.sc_close(fd)
    else
        line = line .. " (open failed)"
    end
    log("  " .. line)
end

log("--- B: sandbox tree ---")
trydir("/mnt")
trydir("/mnt/sandbox")
trydir("/mnt/sandbox/pfsmnt")
trydir("/app0")
log("")
log("--- C: traversal attempts ---")
trydir("/mnt/sandbox/pfsmnt/../pfsmnt")
trydir("/app0/../mnt/sandbox")
trydir("/../mnt/sandbox")
trydir("/mnt/sandbox/../pfsmnt/../")

log("")
log("=== N1 complete ===")
