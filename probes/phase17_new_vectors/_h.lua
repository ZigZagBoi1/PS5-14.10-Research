-- shared helpers for phase17 probes that must never touch an unmapped page:
-- region_of() consults 674 and callers only dereference a returned region.
local M = {}

function M.new()
    local H = {}
    local function to_num(v)
        if type(v) == "table" and v.tonumber then return v:tonumber() end
        return tonumber(v) or 0
    end
    H.to_num = to_num
    function H.make_syscall(num)
        local t = {}
        for k, v in pairs(syscall.pipe) do t[k] = v end
        t.syscall_no = num
        setmetatable(t, getmetatable(syscall.pipe))
        return t
    end
    function H.u(v)
        if type(v) == "table" then
            return uint64(to_num(v.h or 0)) * uint64(4294967296) + uint64(to_num(v.l or 0))
        end
        return uint64(v)
    end
    H.safe_rd = function(a) local ok, v = pcall(function() return memory.read_dword(a) end) if ok then return to_num(v) end return nil end
    H.safe_wd = function(a, v) return (pcall(function() memory.write_dword(a, v) end)) end
    local sc674 = H.make_syscall(674)
    local buf = memory.alloc(0x10000)
    local cnt = memory.alloc(8)
    H.regions = function()
        H.safe_wd(cnt, 0)
        local n = 0
        local ok = pcall(function() sc674(H.u(buf), H.u(72), H.u(512), H.u(cnt), H.u(0x40000000), H.u(0)) end)
        if not ok then return 0 end
        n = H.safe_rd(cnt) or 0
        return n
    end
    local function q(a, o)
        local hi, lo = H.safe_rd(a + o + 4), H.safe_rd(a + o)
        if not hi or not lo then return nil end
        return hi * 4294967296 + lo
    end
    H.name_at = function(a)
        local s = ""
        for k = 0, 30 do
            local c = H.safe_rd(a + k)
            if not c or c == 0 then break end
            local ch = c % 256
            if ch < 32 or ch > 126 then break end
            s = s .. string.char(ch)
        end
        return s
    end
    -- returns start, stop, prot, name for the region containing addr, or nil
    H.region_of = function(addr)
        local n = H.regions()
        for i = 0, n - 1 do
            local r = buf + i * 72
            local start = (q(r, 4) or 0) * 4294967296 + (q(r, 0) or 0)
            local stop  = (q(r, 12) or 0) * 4294967296 + (q(r, 8) or 0)
            if addr >= start and addr < stop then
                return start, stop, q(r, 0x18) or 0, H.name_at(r + 0x20)
            end
        end
        return nil
    end
    H.readable = function(addr)
        local _, _, prot = H.region_of(addr)
        return prot ~= nil and (prot % 2) == 1
    end
    return H
end

return M
