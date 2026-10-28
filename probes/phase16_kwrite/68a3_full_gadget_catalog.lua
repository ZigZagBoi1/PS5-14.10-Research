-- CRASH_CLASS: LOW
-- PROBE 68a: Full eboot ROP gadget catalog for kernel R/W exploitation
-- Scans full 4.6MB eboot .text for memory R/W, register chain, arithmetic,
-- and stack pivot gadgets. Prior scans (118b, 272a, 386a) were partial or
-- narrow. Groups: [A] 22 dword patterns via hash map, [B] 3-byte xchg/push,
-- [C] 2-byte pop_rsp/jmp/call, [D] 5-byte mov [rdi+N] families,
-- [E] 4-byte non-REX offset R/W.

print("=== PROBE 68a: GADGET CATALOG ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end; return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

-- eboot base + text size via dynlib_get_info(593, handle=0)
local ib = memory.alloc(0x200); wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local tlo = rd(N(ib) + 0x108) or 0; local thi = rd(N(ib) + 0x10C) or 0
if tlo < 0 then tlo = tlo + 0x100000000 end
if thi < 0 then thi = thi + 0x100000000 end
local szlo = rd(N(ib) + 0x110) or 0
if szlo < 0 then szlo = szlo + 0x100000000 end
local tsz = szlo
if tsz == 0 then tsz = 0x494000 end
if tsz > 0x800000 then tsz = 0x800000 end
local base = thi * 0x100000000 + tlo
print(string.format("eb=0x%X%08X sz=0x%X (%.1f MB)", thi, tlo, tsz, tsz / 1048576))

-- [A] 4-byte dword patterns: LE dword value → name
local M = {}
M[0xC3078B48] = "Rd[rdi]"       -- 48 8B 07 C3: mov rax,[rdi];ret
M[0xC3068B48] = "Rd[rsi]"       -- 48 8B 06 C3: mov rax,[rsi];ret
M[0xC3008B48] = "Rd[rax]"       -- 48 8B 00 C3: mov rax,[rax];ret
M[0xC3028B48] = "Rd[rdx]"       -- 48 8B 02 C3: mov rax,[rdx];ret
M[0xC3078948] = "Wr[rdi]"       -- 48 89 07 C3: mov [rdi],rax;ret
M[0xC3068948] = "Wr[rsi]"       -- 48 89 06 C3: mov [rsi],rax;ret
M[0xC3028948] = "Wr[rdx]"       -- 48 89 02 C3: mov [rdx],rax;ret
M[0xC3388948] = "Wr[rax]=rdi"   -- 48 89 38 C3: mov [rax],rdi;ret
M[0xC3070148] = "Add[rdi]"      -- 48 01 07 C3: add [rdi],rax;ret
M[0xC3072148] = "And[rdi]"      -- 48 21 07 C3: and [rdi],rax;ret
M[0xC3C78948] = "MvRdiRax"      -- 48 89 C7 C3: mov rdi,rax;ret
M[0xC3F88948] = "MvRaxRdi"      -- 48 89 F8 C3: mov rax,rdi;ret
M[0xC3C68948] = "MvRsiRax"      -- 48 89 C6 C3: mov rsi,rax;ret
M[0xC3C28948] = "MvRdxRax"      -- 48 89 C2 C3: mov rdx,rax;ret
M[0xC3C18948] = "MvRcxRax"      -- 48 89 C1 C3: mov rcx,rax;ret
M[0xC3F78948] = "MvRdiRsi"      -- 48 89 F7 C3: mov rdi,rsi;ret
M[0xC3C78748] = "XchgRaxRdi4"   -- 48 87 C7 C3: xchg rax,rdi;ret (long)
M[0xC3F80148] = "AddRaxRdi"     -- 48 01 F8 C3: add rax,rdi;ret
M[0xC3F82948] = "SubRaxRdi"     -- 48 29 F8 C3: sub rax,rdi;ret
M[0xC3C70148] = "AddRdiRax"     -- 48 01 C7 C3: add rdi,rax;ret
M[0xC3D8F748] = "NegRax"        -- 48 F7 D8 C3: neg rax;ret
M[0xC3D0F748] = "NotRax"        -- 48 F7 D0 C3: not rax;ret

-- Results: name → {off, off, ...} (max 5)
local R = {}
local RV = {}  -- variable-offset gadgets: {name_str, offset}
local function rec(nm, off)
    if not R[nm] then R[nm] = {} end
    local l = R[nm]; if #l < 5 then l[#l + 1] = off end
end

print("scanning...")
local prev = nil
for off = 0, tsz - 4, 4 do
    local dw = rd(base + off)
    if dw then
        if dw < 0 then dw = dw + 0x100000000 end
        if prev then
            -- [A] Check 4-byte patterns at 4 unaligned positions
            local w0, w1, w2, w3 = prev,
                math.floor(prev / 256) + (dw % 256) * 16777216,
                math.floor(prev / 65536) + (dw % 65536) * 65536,
                math.floor(prev / 16777216) + (dw % 16777216) * 256
            local nm
            nm = M[w0]; if nm then rec(nm, off - 4) end
            nm = M[w1]; if nm then rec(nm, off - 3) end
            nm = M[w2]; if nm then rec(nm, off - 2) end
            nm = M[w3]; if nm then rec(nm, off - 1) end
            -- Extract 8 bytes for sub-dword patterns
            local b1 = prev % 256
            local b2 = math.floor(prev / 256) % 256
            local b3 = math.floor(prev / 65536) % 256
            local b4 = math.floor(prev / 16777216) % 256
            local b5 = dw % 256
            local b6 = math.floor(dw / 256) % 256
            local b7 = math.floor(dw / 65536) % 256
            local b8 = math.floor(dw / 16777216) % 256
            local bb = {b1, b2, b3, b4, b5, b6, b7, b8}
            for pi = 1, 4 do
                local a = off - 4 + pi - 1
                local c1, c2, c3, c4, c5 = bb[pi], bb[pi+1], bb[pi+2], bb[pi+3], bb[pi+4]
                -- [B] 3-byte gadgets
                if c1==0x50 and c2==0x5F and c3==0xC3 then rec("PshPopRdi", a) end
                if c1==0x48 and c2==0x97 and c3==0xC3 then rec("XchgRaxRdi", a) end
                if c1==0x48 and c2==0x94 and c3==0xC3 then rec("XchgRaxRsp", a) end
                if c1==0x31 and c2==0xC0 and c3==0xC3 then rec("XorEaxEax", a) end
                if c1==0x48 and c2==0x96 and c3==0xC3 then rec("XchgRaxRsi", a) end
                if c1==0x48 and c2==0x92 and c3==0xC3 then rec("XchgRaxRdx", a) end
                if c1==0x8B and c2==0x07 and c3==0xC3 then rec("Rd32[rdi]", a) end
                if c1==0x89 and c2==0x07 and c3==0xC3 then rec("Wr32[rdi]", a) end
                -- [C] 2-byte gadgets
                if c1==0xCD and c2==0x80 then rec("Int80", a) end
                if c1==0x0F and c2==0x34 then rec("Sysenter", a) end
                if c1==0x5C and c2==0xC3 then rec("PopRsp", a) end
                if c1==0xFF and c2==0xE0 then rec("JmpRax", a) end
                if c1==0xFF and c2==0xD0 then rec("CallRax", a) end
                -- [D] 5-byte REX variable: 48 {8B|89} {47|46} XX C3
                if c5 and c1==0x48 and c5==0xC3 then
                    if c2==0x8B and c3==0x47 then
                        if #RV<80 then RV[#RV+1]={string.format("Rd[rdi+0x%02X]",c4),a} end
                    elseif c2==0x89 and c3==0x47 then
                        if #RV<80 then RV[#RV+1]={string.format("Wr[rdi+0x%02X]",c4),a} end
                    elseif c2==0x8B and c3==0x46 then
                        if #RV<80 then RV[#RV+1]={string.format("Rd[rsi+0x%02X]",c4),a} end
                    elseif c2==0x89 and c3==0x46 then
                        if #RV<80 then RV[#RV+1]={string.format("Wr[rsi+0x%02X]",c4),a} end
                    end
                end
                -- [E] 4-byte non-REX variable: {8B|89} 47 XX C3
                if c1==0x8B and c2==0x47 and c4==0xC3 then
                    if #RV<80 then RV[#RV+1]={string.format("Rd32[rdi+0x%02X]",c3),a} end
                end
                if c1==0x89 and c2==0x47 and c4==0xC3 then
                    if #RV<80 then RV[#RV+1]={string.format("Wr32[rdi+0x%02X]",c3),a} end
                end
            end
        end
        prev = dw
    else
        prev = nil
    end
    if off % 0x40000 == 0 and off > 0 then
        collectgarbage("collect")
        print(string.format("  %d%%", math.floor(off / tsz * 100)))
        if not alive() then print("DEAD"); return end
    end
end

-- === REPORT ===
print("")
print("[A] FIXED GADGETS:")
local order = {
    "Rd[rdi]", "Rd[rsi]", "Rd[rax]", "Rd[rdx]", "Rd32[rdi]",
    "Wr[rdi]", "Wr[rsi]", "Wr[rdx]", "Wr[rax]=rdi", "Wr32[rdi]",
    "Add[rdi]", "And[rdi]", "AddRdiRax",
    "MvRdiRax", "MvRaxRdi", "MvRsiRax", "MvRdxRax", "MvRcxRax", "MvRdiRsi",
    "PshPopRdi", "XchgRaxRdi", "XchgRaxRdi4", "XchgRaxRsi", "XchgRaxRdx",
    "AddRaxRdi", "SubRaxRdi", "NegRax", "NotRax",
    "XorEaxEax", "XchgRaxRsp", "PopRsp",
    "JmpRax", "CallRax", "Int80", "Sysenter",
}
for _, nm in ipairs(order) do
    local l = R[nm]
    if l then
        local pp = {}
        for _, o in ipairs(l) do pp[#pp + 1] = string.format("+0x%X", o) end
        print(string.format("  %-16s %s", nm, table.concat(pp, ", ")))
    end
end
print("")
print("[B] OFFSET GADGETS (" .. #RV .. " found):")
for _, e in ipairs(RV) do
    print(string.format("  %-20s +0x%X", e[1], e[2]))
end
print("")
print("[C] MISSING:")
for _, nm in ipairs(order) do
    if not R[nm] then print(string.format("  %-16s ABSENT", nm)) end
end
-- Capability assessment
print("")
local hr = R["Rd[rdi]"] or R["Rd32[rdi]"] or #RV > 0
local hw = R["Wr[rdi]"]
local hc = R["MvRdiRax"] or R["PshPopRdi"] or R["XchgRaxRdi"]
local ha = R["AddRaxRdi"] or R["SubRaxRdi"]
print("rd=" .. (hr and "Y" or "N") .. " wr=" .. (hw and "Y" or "N") ..
      " chain=" .. (hc and "Y" or "N") .. " arith=" .. (ha and "Y" or "N"))
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 68a COMPLETE ===")
