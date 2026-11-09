-- CRASH_CLASS: LOW
-- PROBE 216a: how long a name the create calls accept
--
-- Context: 192a showed 538 evf_create and 557 namedobj_create accept a name
-- pointer (NULL is rejected), and 215a showed a four character name still
-- works on a process that has created and deleted dozens of objects. If the
-- kernel copied a caller supplied name into a fixed buffer without a length
-- check, a long name would be the classic kernel overwrite. This walks the
-- length upwards and stops at the first rejection.
--
-- The earlier 214a attempt wrote n dwords instead of n characters, so every
-- length above four was four times longer than intended and the whole sweep
-- came back -1.

print("=== PROBE 216a: the create name length cutoff ===")
local ok, err = pcall(function()
    local function sc(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
    local function num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
    local function signed(v) local h,l=0,num(v) if type(v)=="table" and v.h then h,l=v.h,v.l end
        if h==0 and l>=0x80000000 then return l-0x100000000 end return l end
    local c538, c539 = sc(538), sc(539)
    local buf = memory.alloc(0x200)
    for _, n in ipairs({8, 15, 16, 17, 20, 24, 31, 32}) do
        for i = 0, 0x7F do memory.write_dword(buf + i*4, 0) end
        for i = 0, math.floor((n + 3) / 4) - 1 do memory.write_dword(buf + i*4, 0x41414141) end
        memory.write_dword(buf + (math.floor(n / 4) * 4), 0)
        local h = c538(uint64(buf), uint64(0), uint64(0))
        local hs = signed(h)
        print(string.format("    name length %-3d -> %s", n, tostring(hs)))
        if hs ~= -1 and hs > 0 then c539(uint64(hs), uint64(0), uint64(0)) end
    end
    print("")
    print("[B] NULL name for comparison")
    print("    538(NULL,0,0) -> " .. tostring(signed(c538(uint64(0), uint64(0), uint64(0)))))
end)
print("    pcall ok=" .. tostring(ok) .. " err=" .. tostring(err))
print("=== COMPLETE ===")
