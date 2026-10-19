-- CRASH_CLASS: LOW
-- PROBE 54r: Read-only inspection of CClosure +0x20 targets
--
-- 54q stalled at the boundary of changing type()'s +0x20 slot. This probe
-- performs no writes and no redirects. It records the first 64 bytes at the
-- +0x20 target for several standard C functions, plus the neighboring closure
-- fields, so the targets can be classified as direct entry points or thunks.

print("=== PROBE 54r: C FUNC TARGET BYTES (READ ONLY) ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
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

local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local function hexval(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

local function parse_func_addr(fn)
    local s = tostring(fn)
    local hex = s:match("0x([0-9a-fA-F]+)")
    if not hex then hex = s:match(":%s*([0-9a-fA-F]+)%s*$") end
    if not hex then hex = s:match("([0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]+)") end
    if hex then return uint64("0x" .. hex) end
    return nil
end

local targets = {
    {"type", type},
    {"tonumber", tonumber},
    {"tostring", tostring},
    {"pcall", pcall},
    {"pairs", pairs},
    {"rawget", rawget},
    {"select", select},
}

for _, item in ipairs(targets) do
    local name, fn = item[1], item[2]
    local addr = parse_func_addr(fn)
    print("")
    print("[" .. name .. "] object=" .. hexval(addr))
    if addr then
        local cfunc = safe_rq(addr + 0x20)
        print("  +0x20 target=" .. hexval(cfunc))
        print("  +0x00 next=" .. hexval(safe_rq(addr + 0x00)))
        print("  +0x08 tag=" .. hexval(safe_rq(addr + 0x08)))
        print("  +0x10 gclist=" .. hexval(safe_rq(addr + 0x10)))
        print("  +0x18 env=" .. hexval(safe_rq(addr + 0x18)))
        print("  target bytes (little-endian dwords):")
        if cfunc then
            for off = 0, 0x3C, 4 do
                local word = safe_rd(cfunc + off)
                print(string.format("    +0x%02X: %08X", off, word or 0))
            end
        else
            print("    UNREADABLE_TARGET")
        end
    else
        print("  ADDRESS_PARSE_FAILED")
    end
end

print("")
print("No writes, redirects, or calls through modified pointers were attempted.")
print("=== PROBE 54r COMPLETE ===")
