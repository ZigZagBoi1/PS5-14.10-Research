-- CRASH_CLASS: LOW
-- PROBE 514a: scan the loader's ROP ring for code addresses outside eboot.
--
-- 510c showed a 0x300-byte window of eboot-only gadgets ending in `pop rsp;ret`
-- to heap 0x310AB23E0, so the chain continues in a heap ring.  Somewhere in that
-- ring must be the transfer into libkernel (the syscall stub the loader uses).
-- This scans 0x4000 bytes of the chain, classifies every qword, and prints the
-- distinct code addresses that are NOT in eboot.

print("=== PROBE 514a: CHAIN RING SCAN ===")
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
    if type(val) == "table" and val.h then return to_num(val.h), to_num(val.l) end
    return 0, tonumber(val) or 0
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if not ok then return nil end
    return v
end

local sc_getpid = make_syscall(20)
local pipe_str = tostring(syscall.pipe)
local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
pcall(function() return sc_getpid() end)
if not rop_str then print("no chain"); print("=== DONE ==="); return end
local rop = uint64(rop_str)
print("[0] rop=" .. rop_str .. " fn_slot=" .. tostring(fn_str))

local EB_LO, EB_HI = 0x55000000, 0x55800000
local seen, order, out_of_eboot = {}, {}, {}
local eboot_n, other_n, tag_n, zero_n = 0, 0, 0, 0
for off = 0, 0x3FF8, 8 do
    local v = rq(rop + off)
    if v ~= nil then
        local h, l = get_hi_lo(v)
        if h == 0 and l == 0 then
            zero_n = zero_n + 1
        elseif h ~= 0 then
            tag_n = tag_n + 1
        elseif l >= EB_LO and l < EB_HI then
            eboot_n = eboot_n + 1
        else
            other_n = other_n + 1
            if not seen[l] then
                seen[l] = true
                out_of_eboot[#out_of_eboot + 1] = l
            end
        end
    end
end
print(string.format("[1] words: eboot=%d other=%d tagged=%d zero=%d distinct-other=%d",
    eboot_n, other_n, tag_n, zero_n, #out_of_eboot))
table.sort(out_of_eboot)
for i = 1, #out_of_eboot do
    local a = out_of_eboot[i]
    print(string.format("    other %08X", a))
end

-- ring continuation at rop+0x2E8 is a heap address; walk the first 0x200 qwords
-- there as well and classify.
local rs = rq(rop + 0x2E8)
if rs ~= nil then
    local h, l = get_hi_lo(rs)
    print(string.format("[2] rop+0x2E8 = 0x%08X_%08X", h, l))
    if h == 0 and l > 0x10000 then
        local o2 = {}
        local n2 = 0
        for off = 0, 0x7F8, 8 do
            local v = rq(uint64(l) + off)
            if v ~= nil then
                local hh, ll = get_hi_lo(v)
                if hh == 0 and ll > 0x10000 then
                    n2 = n2 + 1
                    o2[#o2 + 1] = string.format("%08X", ll)
                    if #o2 > 24 then break end
                end
            end
        end
        print(string.format("[2] ring words=%d", n2))
        local line = ""
        for i = 1, #o2 do
            line = line .. o2[i] .. " "
            if i % 6 == 0 then print("    " .. line); line = "" end
        end
        if #line > 0 then print("    " .. line) end
    end
end

local fv = rq(uint64(fn_str))
if fv ~= nil then
    local h, l = get_hi_lo(fv)
    print(string.format("[3] fn value = 0x%08X_%08X", h, l))
end
print("=== DONE ===")
