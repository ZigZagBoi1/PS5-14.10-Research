# 601 working notes (scratch; delete before final)

## Entry / dispatch (STATIC)
- asm C:\PS5contrib\results\kernel_handlers\asm\sys_601_deep.asm:20-29: mov eax,[rsi]; cmp rax,0x27; ja 0xca221c; lea rcx,[0x1a51160]; mov r15,[rsi+8]; mov r12,[rsi+0x10]; movsxd rdx,[rcx+rax*4]; add rdx,rcx; jmp rdx
  => user struct {u32 cmd; pad; u64 arg2; u64 arg3} at rsi; arg2->r15, arg3->r12. Table 0x1a51160 = 40 entries, NOT in corpus.
- default return 0x4e (ENOSYS) at ca064b; epilogue ca221c stack canary _DAT_0391c310.
- Secondary tables INSIDE handler (all outside dump):
  * 0x1a51234: asm:268 (decompiled c:268) index (local_58-1)<7 -> 7 entries (cmd-local "type" 1..7)
  * 0x1a51200: asm:1355 index (r15-1)<=3 -> 4 entries
  * 0x1a51210: asm:1529 index (ebx-1)<=8 -> 9 entries, targets 0xca2058,0xca208f,0xca20b1,0xca20e9,0xca210b,0xca214f,0xca2171,0xca21ac,0xca21ed (order in table unknown)

## copyin (0x259280) 14 sites (asm line: addr size dst<-src)
41: ca06b5 0x10 -> [rbp-0xf0] <- r15 (arg2)
487: ca0e12 0x20 -> [rbp-0xf0] <- r12 (arg3)
574: ca0f93 0x18 -> [rbp-0xf0] <- r12
595: ca0ff9 0x480 -> r14 (kmalloc'd) <- r15
620: ca106d 0x18 -> [rbp-0xf0] <- r12
655: ca1104 0x48 -> [rbp-0xf0] <- r15
720: ca1227 0x8*N (r12<<3) -> [rbp-0xf0] <- r15   <-- LENGTH IS USER-CONTROLLED COUNT <<3, dst stack 0x78 buffer
882: ca14f5 0x20 -> [rbp-0xf0] <- r12
1004: ca16e9 0x18 -> [rbp-0x110] <- r15
1018: ca1733 0x40 -> rbx <- [rbp-0xf0] (kernel ptr from copyin)
1042: ca17ac 0x480 -> rbx <- r15
1702: ca2377 0x3c -> [rbp-0x74] <- r15 (sub_00ca2320)
## copyinstr (0x259900) 2 sites
464: ca0daf 0x1000 -> rbx(kmalloc 0x1000) <- r15, ecx=0
749: ca12b6 0x1000 -> r12 <- r14, rcx=[rbp-0x110]
## copyout (0x2591d0) 8 sites
284: ca0a9a 4 <- [rbp-0xf0]  (dword out)
552: ca0f31 8 <- [rbp-0xf0]  (qword out: [proc+0x560])
1100: ca18a4 8 <- [rbp-0xf0]
1146: ca197b len=min(r12,0x28) <- r15
1272: ca1b8b 0x480 <- r14
1317: ca1c50 0x70 <- r15

## 0xf0 object (KEY)
- 1398: ca1dd5 mov QWORD PTR [rax+0xf0],rbx   (rbx = ? value stored into ctx+0xf0)
- 1523: ca202d mov rax,QWORD PTR [rax+0xf0]   then jmp table 0x1a51210 -> writes user qwords to [rax+0x00/0x08/0x10/0x18], [0x20/0x28], [0x30..0x48], [0x50/0x58], [0x60/0x68], [0x70..0x88], [0x90..0xa8], [0xb0..0xc8], [0xd0] + flags [rax+0xd4]/[rax+0xd5]
  asm lines 1533-1603 (ca2058..ca21ed), source values [rbp-0xe8],[rbp-0xe0],[rbp-0xd8],[rbp-0xd0] = copied-in user struct
- 3145: ca39b4 mov rdi,[r14+0xf0] ; 3150: ca39cc mov [r14+0xf0],0  => FREE of ctx+0xf0 on teardown (0xc08df0)
- 3731/3742: ca41c0/ca41f8 cmp QWORD PTR [rsi+0xf0],0  (sub_00ca4090 slot alloc path)
## other user->kernel stores
- 1377: ca1d5c mov [rcx+0x36c],eax  (user dword -> proc+0x36c)
- 1381: ca1d73 lea rax,[rcx+rax*1+0x400] ; 1383: ca1d7d mov [r13+0x528],rax  (user dword<<32 OR'd into td flags)
- 1398 ca1dd5 ; 1485 ca1f73 mov [rax+0x188],rcx (user qword) ; 1505 ca1fdc mov [rax+0x180],rcx ; 1506 ca1fe3 [rax+0x178]
- 1627 ca224d mov [rax+0x190],rcx (user qword)
## deferred/blocking
- 887 (decompiled c:887): sub_00ca3c70 calls 0xc9d940(proc->pid,1000000,0) = tsleep 1s loop while td flag bit15 set
- 0xc9aa90 = kqueue/kevent-ish notify (6 calls)
## misc
- 0x8d1a30 = strncmp-like (name compare, 9 calls) at ca1df6..ca1ed6 comparing user name vs 8 known strings
- 0xb078d0 = boot-state helper (4 calls)
- 0xc9fa20(proc,int) = signal/permission helper

## DUMP MAPPING (verified)
- docs/dumps_13.60/kernel_text.bin = RVA 0x0..0xe6e5c0; verified byte-identical at RVA 0xca0630 (55 48 89 e5 41 57 41 56 41 55 41 54 53 48 81 ec f8 00 00 00).
- kernel_data.bin = RVA 0x1000000..0x1400000 (manifest, 0x400000); failmap all 0 => no failed chunks. sysent_area.bin RVA 0xe6d5c0 (0x10000). base 0xffffffff8a9c0000. sysent RVA 0xe6e5c0, 679 entries x 48B.
- 0x1a51160 (40-entry table) > 0x1400000 => genuinely absent from every dump. Confirmed closed.
- sysent sy_call for Sony nums = 8-byte thunk 'e9 rel32 cc cc cc' (e.g. RVA 0x265e18 -> 0xca0630 for 601). handler_NNN.bin = 4KB at the thunk.
- sysent narg: 601=3, 616=2, 618=3, 622=6, 667=2, 674=5.

## STRINGS RESOLVED from kernel_data.bin (NEW evidence)
- 0x135965f "Sce.PSM:AppName"; 0x1382c26 "Sce.PSM:SdbInfo"; 0x13251a9 "Sce.PSM:LogArea"; 0x1305161 "Sce.Debug:UserObjArray"; 0x12dc08b "Sce.Debug:Gnm"; 0x13641af "Sce.Debug:Gn2"; 0x13251b9 "Sce.Debug:Gn3"; 0x12c6e96 "Sce.Debug:Gn4"; 0x1378646 "Sce.Debug:KPNoverride"
- 0x1397f3d "copyin"; 0x134f297 "copyout"; 0x1305178 "mdbglog"; 0x12aa1cd ".../sys/kern/kern_resource.c"
- kqueue filter names: 0x136dfed "mdbg_current_incident"; 0x12e769e "process_exit"+0x1305180 "procexit_handler"; 0x13842de "process_exec"+0x12dc099 "procexec_handler"; 0x133ab8b "process_exec_end"+0x127ef0c "procexec_end_handler"; 0x13251c7 "process_fork"+0x12d1b27 "procfork_handler"; 0x132fb0b "process_suspend_phase2"+0x138d554 handler; 0x13a2f6d "process_resume_phase2"+0x127ef21 handler (registered by sub_00ca30e0 via 0x73dd40, prio 20000)
- name->slot (strncmp chain order 1..8): AppName, SdbInfo, LogArea, UserObjArray, Gnm, Gn2, Gn3, Gn4; KPNoverride => ebx=9 (slot 8 after dec); no match => EINVAL 0x16.

## 9-SLOT REGISTRY OBJECT (ctx+0xf0, kmalloc 0xd8 at ca117b)
- case bodies ca2058(4 qwords->+0x00,+0x08,+0x10,+0x18; flag d4|=2), ca208f(2 qwords->+0x60,+0x68; d4|=0x20), ca20b1(4->+0x30..+0x48; d4|=8), ca20e9(2->+0x50,+0x58; d4|=0x10), ca210b(4->+0xb0..+0xc8; d5|=1), ca214f(2->+0x20,+0x28; d4|=4), ca2171(4->+0x70..+0x88; d4|=0x40), ca21ac(4->+0x90..+0xa8; d4|=0x80), ca21ed(dword->+0xd0; d5|=2)
- values from [rbp-0xe8],[rbp-0xe0],[rbp-0xd8],[rbp-0xd0] = copied-in user struct (copyin 0x48 at ca1104)
- only refs in window: ca202d read, ca39b4 free, (ca41c0/ca41f8 are a different struct). Consumer outside dump.

## VERIFIED NEGATIVES (do not re-derive)
- ca11ea..ca1227: 'lea rax,[r12-0x10]; cmp rax,0xfffffffffffffff2; jb 0xca2215' accepts ONLY r12 in [2,15]; 15*8=0x78 == stack buffer size => NOT an overflow.
- ca16e9: copyin(user_ptr=[rbp-0x100] from struct, kbuf=[rbp-0xf0], 0x40) and ca17ac copyin(user_ptr=[rbp-0x108], kmalloc 0x480, 0x480): both dst are kernel stack/heap, src is user addr => ordinary.
- ca1dd5 [ctx+0xf0]=rbx where rbx = freshly kmalloc'd 0xd8 object (ca117b), not user data.

## sub_00ca2320 (mdbg request, 0x3c struct)
- fields: +0x08 local_74, +0x0c local_70 user ptr, +0x14 local_68 len, +0x20 local_5c, +0x24 local_58 type
- allowed types by mask 0xb8: 3,4,5,7; type 1 = append to ctx+0x58 (kmalloc 0x80000), ctx+0x50 used; 3/4/5 limit 0x10000; 7: len<=0x100 && local_74<=0xf; type 100 = copyin<=0x1000 + func_0x007b0ae0(buf,len) (parser; retval discarded, always returns 0)
- bp list ctx+0x40/0x48, entry +0x14 addr, +0x2c type, +0x10 index, [9] buffer; ctx+0x30/0xf8 count; ctx+0x9c index; ctx+0x28 mutex
- final: copyout 8B of local_40 to param_3 (0x2591d0)

## other bodies
- sub_00ca32b0: drains global log _DAT_03e0d870 in 0x4000 chunks; 0x782520(kbuf, len, user_desc{+0=ptr,+0x18=len}) = copyout-to-descriptor helper (also sys_667 @0x4a3xxx and sys_618 @0xabd2xx)
- sub_00ca2fd0/sub_00ca3060: knote posts {ident=3, filter=8/9, data=params} via 0xc9aa90
- sub_00ca4090: UserObjArray: proc+0x2b8 array of 256 ptrs indexed by byte; alloc 0x128 (0xca5a00); +0x11c=u16 id, +0xf8=ptr, +0xa0=0x2bf37e0, +0xc8=proc
- sys_667: 0x782a40(param_2[1]) -> idx [1,10000]; walks proc list 0x3589e80; 0x28-byte records with thread fields +0x5b0..+0x5c8 copied to userland (candidate kernel-pointer leak; gate unchecked)

## APPROACH DECISION
- 601 command numbers cannot be bound statically (table absent) => propose behavioral return-code fingerprint sweep: cmd 0..0x27 x 6 shapes, record ret; map equivalence classes to bodies by first-error code.

## SMAP IS ON (decisive)
- stac (0f 01 cb) 17 hits: 0x252316,0x2581b7,0x259235,0x25930d,0x2593b7,0x259428,0x2594a7,0x259517...; clac (0f 01 ca) 46 hits: 0x25231b,0x2551d8,... (copyin/copyout helpers 0x259280/0x2591d0 live here).
- => any raw deref of a user pointer in kernel mode = #PF panic. Kills the pointer-injection class; explains 601 cmd 0x03/0x04 lethality (they take struct proc * raw).

## 601 ATTACH BODY at ca12d5 (dispatch-table-only entry; zero branch refs to ca12d5)
- r14=uap[1]; call 0xc9afc0(r14). 0xc9afc0 decoded from raw bytes: push rbp; ...; lea rbx,[rdi+0x148]; mtx_lock(rdi+0x148) [0x4c6a00]; r15=[rdi+0x568]; mtx_unlock; if ctx==0 -> kmalloc(0x1f0,0x2c01960,0x102) and store new ctx at [proc+0x568].
- body: mtx_lock(r14+0x148); r13=[r14+0x568]; or QWORD [td+0x528],0x100; mtx_unlock; mtx_lock(r13+0x28); [r13+0x94]=[td+0x9c]; if [r13+0x88]==0 { [r13+0x34]=2; call 0x73ef00(r13); call 0x73e780(r13,r13+0x10,0); [r13+0x34]=1 } ; r14d=0x16; [r13+0x88]=0; cmove on [r13+0x38]==0 -> r14d=[rbp-0x120]; if r14d==0 -> ca18db.
- => td+0x528 bit 0x100 (the request-type unlock flag) is set by THIS command, on the CURRENT td, from uap[1] treated as struct proc *.

## REQUEST-TYPE VALIDATION MATRIX (sub_00ca2320)
- mask 0xb8 = types {3,4,5,7} allowed at gate; types 1,2,6,100 pass ONLY when td+0x528 bit 0x100 is set (attach first).
- pre-dispatch checks: 3,4 -> local_5c<=0x10000 (else 0x3f); 7 -> local_68<=0x100 && local_74<=0xf (else 0x16); 1 -> clamped append; 100 -> parser; **2,5,6 -> NO validation at all** then table 0x1a51234.

## other 601 command bodies seen
- ca13da: mtx_lock(uap[1]+0x148); or BYTE [td+0x529],0x8; mtx_unlock; jmp ENOSYS.
- ca15df..ca1637: mtx_lock(td+8+0x148); if r12(uap[2])==2 -> ca1ab7; if ==1 -> call 0xca2e20(uap[1]); else 0x16.
- ca163c: bit62 gate then tail-jmp 0xca2e60(uap[1],uap[2]).
