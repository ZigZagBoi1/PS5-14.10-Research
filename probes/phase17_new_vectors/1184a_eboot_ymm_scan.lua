-- CRASH_CLASS: MODERATE  (one 1 MB read_buffer per chunk; a hole kills the process but the chunk line localises it)
-- PROBE 1184a: scan EBOOT (the game's own module) for a ymm0 store gadget, the last missing piece of H1 in
-- docs/MICROARCH_FEASIBILITY_14_10.md.
-- Why eboot and not libkernel: 1183b established that libkernel .text is EXECUTE-ONLY on 14.10 - the same page
-- that holds *libc_gettimeofday_import+7 (an address the loader calls for every syscall) faults on a 4-byte read.
-- libc is readable but has zero VEX ymm stores (1173a). eboot_base comes from luaB_auxwrap - addrof (lua.lua:269)
-- and the loader executes it, so try it here.
-- Gadget test: VEX prefix C5, second byte FD/FC/FE (vvvv=1111, L=1 => 256-bit), opcode 11/29/7F (store form),
-- modrm.mod != 11 and modrm.reg == 0 (source = ymm0). That is exactly "spill ymm0 to [r/m]".
print("=== PROBE 1184a: EBOOT ymm0-STORE SCAN ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function hexn(n) n=N(n) return string.format("0x%08X%08X", math.floor(n/4294967296), n % 4294967296) end
local base = 0
pcall(function() base = N(eboot_base) end)
print("[A] eboot_base=" .. hexn(base))
if base == 0 then print("[A] eboot_base not resolvable - stop"); print("=== 1184a DONE ==="); return end
local CHUNK = 0x100000
local NCHUNK = 0x40
local function byteat(s,i) return string.byte(s,i) end
local function scan_chunk(s, addr)
  local hits, tot, vzu = {}, 0, 0
  local pos = 1
  while true do
    local i = string.find(s, "\197", pos, true)   -- 0xC5 VEX2 prefix
    if not i then break end
    local b2 = byteat(s, i+1)
    if b2 == 0xF8 and byteat(s, i+2) == 0x77 then vzu = vzu + 1 end
    if (b2 == 0xFD or b2 == 0xFC or b2 == 0xFE) and i + 3 <= #s then
      local op = byteat(s, i+2); local m = byteat(s, i+3)
      if (op == 0x11 or op == 0x29 or op == 0x7F) and m then
        local mod = math.floor(m / 64); local reg = math.floor(m / 8) % 8
        if mod ~= 3 and reg == 0 then
          tot = tot + 1
          if #hits < 4 then hits[#hits+1] = addr + i - 1 end
        end
      end
    end
    pos = i + 1
  end
  return tot, hits, vzu
end
local grand, gvzu, holes = 0, 0, 0
for k=0,NCHUNK-1 do
  local a = base + k*CHUNK
  local o, buf = pcall(function() return memory.read_buffer(a, CHUNK) end)
  if not o or type(buf) ~= "string" or #buf ~= CHUNK then
    print(string.format("[C %02X] READ-FAIL %s (len=%s)", k, hexn(a), type(buf)=="string" and ("#"..tostring(#buf)) or "err"))
    holes = holes + 1
  else
    local tot, hits, vzu = scan_chunk(buf, a)
    grand = grand + tot; gvzu = gvzu + vzu
    local h = ""
    for i=1,#hits do h = h .. hexn(hits[i]) .. " " end
    print(string.format("[C %02X] %s ym0stores=%d vzu=%d %s", k, hexn(a), tot, vzu, h))
    if tot > 0 then print(string.format("[HIT] chunk %02X has %d candidate ymm0 stores", k, tot)) end
  end
end
print(string.format("[SUM] eboot chunks=%d ymm0_stores=%d vzeroupper=%d read_fails=%d", NCHUNK, grand, gvzu, holes))
print("[Z] alive")
print("=== 1184a DONE ===")
