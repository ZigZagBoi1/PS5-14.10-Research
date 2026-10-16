-- CRASH_CLASS: SAFE (read-only)
-- PROBE 41i: identify the rc=4 objects
-- From 41h: rc=4 at +0, heap_ptr at +8, cross-ptr at +10, type? at +18,
--   heap_ptr at +20, flags at +28, heap_ptr at +30, list heads at +40/+48
-- Goals:
--   1. Dump ALL rc=4 objects (up to 32), compare structure
--   2. Categorize type tags, flags, list connectivity
--   3. Follow ptr at +8 into target object, dump its header
--   4. Check if target object has vtable-like first qword
--   5. Try to correlate with known syscall objects (EVF, socket, pipe, file)

print("=== PROBE 41i: OBJECT IDENTIFICATION ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function hex(n)
    if type(n) == "table" and n.h then
        return string.format("0x%08X%08X", n.h, n.l)
    end
    return string.format("0x%X", tonumber(n) or 0)
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
local function dump_qword(val)
    if type(val) == "table" and val.h then
        return string.format("%08X_%08X", val.h, val.l)
    end
    return string.format("%016X", to_num(val))
end

local sc_mmap   = make_syscall(477)
local sc_munmap = make_syscall(588)
local PAGE = 0x4000

local function do_mmap(sz)
    local ok, ret = pcall(function()
        return sc_mmap(uint64(0), uint64(sz), uint64(0x33),
            uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
    end)
    if not ok then return nil end
    local addr = to_num(ret)
    if addr == 0 or addr >= 0xFFFFFFFF00000000 then return nil end
    return addr
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function full_addr(hi, lo)
    return hi * 0x100000000 + lo
end

local base = do_mmap(PAGE)
if not base then print("mmap FAILED"); return end
print("anchor: " .. hex(base))
print("")

--------------------------------------------------------------------
-- PASS 1: Collect all rc=4 objects
--------------------------------------------------------------------
print("--- PASS 1: COLLECT rc=4 OBJECTS ---")

local objects = {}
for i = 1, 384 do
    local pg = base - i * 0x1000
    if pg <= 0 then break end
    local v = safe_rd(pg)
    if v == nil then break end
    if v ~= 0 then
        for off = 0, 0xF00, 0x40 do
            if #objects >= 32 then break end
            local a = pg + off
            local q0 = safe_rq(a)
            local q1 = safe_rq(a + 8)
            if q0 and q1 then
                local h0, l0 = get_hi_lo(q0)
                local h1, l1 = get_hi_lo(q1)
                if h0 == 0 and l0 == 4 and h1 == 3 and l1 >= 0x10000000 then
                    -- read the full object record (0x60 bytes)
                    local rec = {}
                    rec.addr = a
                    rec.fields = {}
                    for fo = 0, 0x58, 8 do
                        rec.fields[fo] = safe_rq(a + fo)
                    end
                    objects[#objects + 1] = rec
                end
            end
        end
    end
    if #objects >= 32 then break end
end
print("found: " .. #objects .. " objects")
print("")

--------------------------------------------------------------------
-- PASS 2: Extract key fields from each, find common patterns
--------------------------------------------------------------------
print("--- PASS 2: OBJECT FIELD COMPARISON ---")

local type_tags = {}
local flag_vals = {}
local first_qwords = {}

for j, obj in ipairs(objects) do
    -- field layout from 41h:
    -- +00: rc (always 4)
    -- +08: ptr -> target object
    -- +10: cross-ptr
    -- +18: type tag?
    -- +20: heap ptr
    -- +28: flags
    -- +30: heap ptr
    -- +38: zero?
    -- +40: list next
    -- +48: list prev
    -- +50: heap ptr
    -- +58: value?

    local f18 = obj.fields[0x18]
    local f28 = obj.fields[0x28]
    local f08 = obj.fields[0x08]

    local tag = 0
    if f18 then
        local th, tl = get_hi_lo(f18)
        tag = tl
    end

    local flags = 0
    if f28 then
        local fh, fl = get_hi_lo(f28)
        flags = fh * 0x100000000 + fl
    end

    type_tags[tag] = (type_tags[tag] or 0) + 1
    flag_vals[flags] = (flag_vals[flags] or 0) + 1

    -- follow ptr at +08 to target, read first qword (potential vtable)
    local tgt_first = nil
    if f08 then
        local ph, pl = get_hi_lo(f08)
        if ph == 3 and pl >= 0x10000000 then
            local tq = safe_rq(uint64(full_addr(ph, pl)))
            if tq then
                tgt_first = tq
                local th2, tl2 = get_hi_lo(tq)
                local key = string.format("%08X_%08X", th2, tl2)
                first_qwords[key] = (first_qwords[key] or 0) + 1
            end
        end
    end

    if j <= 12 then
        local parts = {}
        parts[#parts + 1] = string.format("tag=0x%X", tag)
        parts[#parts + 1] = string.format("flg=0x%X", flags)
        if tgt_first then
            parts[#parts + 1] = "tgt[0]=" .. dump_qword(tgt_first)
        end
        print(string.format("  #%02d %s: %s", j, hex(obj.addr), table.concat(parts, " ")))
    end
end
if #objects > 12 then
    print("  ... " .. (#objects - 12) .. " more")
end
print("")

--------------------------------------------------------------------
-- PASS 3: Type tag distribution
--------------------------------------------------------------------
print("--- PASS 3: TYPE TAGS ---")
for tag, cnt in pairs(type_tags) do
    print(string.format("  0x%X : %d objects", tag, cnt))
end
print("")

print("--- FLAGS ---")
for fl, cnt in pairs(flag_vals) do
    print(string.format("  0x%X : %d objects", fl, cnt))
end
print("")

print("--- TARGET [0] VALUES (vtable?) ---")
for fq, cnt in pairs(first_qwords) do
    print(string.format("  %s : %d objects", fq, cnt))
end
print("")

--------------------------------------------------------------------
-- PASS 4: Deep dump of one object + its target
--------------------------------------------------------------------
print("--- PASS 4: DEEP DUMP (object #1) ---")
if #objects >= 1 then
    local obj = objects[1]
    print("  container at " .. hex(obj.addr) .. ":")
    for fo = 0, 0x58, 8 do
        local q = obj.fields[fo]
        if q then
            print(string.format("    +%02X: %s", fo, dump_qword(q)))
        end
    end

    -- follow ptr chain
    local f08 = obj.fields[0x08]
    if f08 then
        local ph, pl = get_hi_lo(f08)
        if ph == 3 and pl >= 0x10000000 then
            local tgt = full_addr(ph, pl)
            print("  target at " .. hex(tgt) .. ":")
            for fo = 0, 0x78, 8 do
                local q = safe_rq(uint64(tgt + fo))
                if q then
                    local qh, ql = get_hi_lo(q)
                    local tag = ""
                    if qh >= 0xFFFFFF80 then tag = " KPTR!" end
                    if qh == 0 and ql >= 0x80000000 and ql < 0x90000000 then tag = " TEXT!" end
                    if qh == 3 and ql >= 0x10000000 then tag = " HEAP" end
                    print(string.format("    +%02X: %s%s", fo, dump_qword(q), tag))
                else
                    break
                end
            end
        end
    end

    -- follow the list at +40/+48
    local f40 = obj.fields[0x40]
    if f40 then
        local lh, ll = get_hi_lo(f40)
        if lh == 3 and ll >= 0x10000000 then
            local list_addr = full_addr(lh, ll)
            if list_addr ~= obj.addr + 0x40 then
                print("  list next at " .. hex(list_addr) .. ":")
                for fo = 0, 0x18, 8 do
                    local q = safe_rq(uint64(list_addr + fo))
                    if q then
                        print(string.format("    +%02X: %s", fo, dump_qword(q)))
                    end
                end
            else
                print("  list: self-referential (empty)")
            end
        end
    end
end
print("")

--------------------------------------------------------------------
-- PASS 5: Create known objects, see if new rc=4 appears
--------------------------------------------------------------------
print("--- PASS 5: OBJECT CREATION CORRELATION ---")
do
    -- count rc=4 objects before
    local before_count = #objects

    -- create EVF (known to work, returns ID)
    local sys_evf_create = make_syscall(538)
    local sys_evf_delete = make_syscall(539)
    local name_buf = memory.alloc(32)
    memory.write_byte(name_buf, 0x74) -- t
    memory.write_byte(name_buf + 1, 0x73) -- s
    memory.write_byte(name_buf + 2, 0x74) -- t
    memory.write_byte(name_buf + 3, 0)

    local evf_ids = {}
    for i = 1, 3 do
        local ok_e, ret_e = pcall(function() return sys_evf_create(name_buf, 0x11, memory.alloc(8)) end)
        if ok_e then
            local eid = to_num(ret_e)
            if eid > 0 and eid < 100000 then
                evf_ids[#evf_ids + 1] = eid
            end
        end
    end
    print("  created " .. #evf_ids .. " EVFs: " .. table.concat(evf_ids, ", "))

    -- scan for new rc=4 near our anchor
    local new_rc4 = 0
    for i = 1, 32 do
        local pg = base - i * 0x1000
        if pg <= 0 then break end
        local v = safe_rd(pg)
        if v == nil then break end
        if v ~= 0 then
            for off = 0, 0xF00, 0x40 do
                local a = pg + off
                local q0 = safe_rq(a)
                if q0 then
                    local h0, l0 = get_hi_lo(q0)
                    if h0 == 0 and l0 == 4 then
                        -- check if this is a new one (not in our list)
                        local known = false
                        for _, obj in ipairs(objects) do
                            if obj.addr == a then known = true; break end
                        end
                        if not known then
                            new_rc4 = new_rc4 + 1
                            if new_rc4 <= 4 then
                                local f18 = safe_rq(a + 0x18)
                                local tag = 0
                                if f18 then
                                    local th, tl = get_hi_lo(f18)
                                    tag = tl
                                end
                                print(string.format("  NEW rc=4 at %s tag=0x%X", hex(a), tag))
                            end
                        end
                    end
                end
            end
        end
    end
    print("  new rc=4 objects after EVF create: " .. new_rc4)

    -- cleanup EVFs
    for _, eid in ipairs(evf_ids) do
        pcall(function() sys_evf_delete(eid) end)
    end

    -- now create sockets
    local sys_socket = make_syscall(97)
    local sys_close = make_syscall(6)
    local sock_fds = {}
    for i = 1, 3 do
        local ok_s, fd = pcall(function() return sys_socket(2, 1, 0) end)
        if ok_s then
            local fdn = to_num(fd)
            if fdn > 0 then sock_fds[#sock_fds + 1] = fdn end
        end
    end
    print("  created " .. #sock_fds .. " sockets")

    -- scan again
    local new_sock_rc4 = 0
    for i = 1, 32 do
        local pg = base - i * 0x1000
        if pg <= 0 then break end
        local v = safe_rd(pg)
        if v == nil then break end
        if v ~= 0 then
            for off = 0, 0xF00, 0x40 do
                local a = pg + off
                local q0 = safe_rq(a)
                if q0 then
                    local h0, l0 = get_hi_lo(q0)
                    if h0 == 0 and l0 == 4 then
                        local known = false
                        for _, obj in ipairs(objects) do
                            if obj.addr == a then known = true; break end
                        end
                        if not known then
                            new_sock_rc4 = new_sock_rc4 + 1
                            if new_sock_rc4 <= 4 then
                                local f18 = safe_rq(a + 0x18)
                                local tag = 0
                                if f18 then
                                    local th, tl = get_hi_lo(f18)
                                    tag = tl
                                end
                                print(string.format("  NEW rc=4 at %s tag=0x%X (post-socket)", hex(a), tag))
                            end
                        end
                    end
                end
            end
        end
    end
    print("  new rc=4 after socket create: " .. new_sock_rc4)

    for _, fd in ipairs(sock_fds) do
        pcall(function() sys_close(fd) end)
    end
end

print("")
pcall(function() sc_munmap(uint64(base), uint64(PAGE)) end)
print("=== PROBE 41i COMPLETE ===")
