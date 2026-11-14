# BIT 61 AND PRIVILEGE MAP (14.10 research, 13.60 capture)

Image docs/dumps_13.60/kernel_text.bin, 15132096 bytes (0xE6E5C0), base VA 0xffffffff8a9c0000,
RVA == file offset. All addresses are RVA. Every instruction quoted below was re-decoded from the
image in this session and is prefixed by its RVA.

## VERDICT
1. Bit 61 is a LEVEL TAG, not a grant. All three helper callers turn it into a label (log line / trace
   level / policy level); none hands the caller an object, buffer or privilege. Bit 61 without bit 62
   gains one audit log line, a "2" in a trace record, and the level-2 arm of a policy predicate that
   three kernel paths test. It satisfies no priv_check, 587 included.
2. Syscall 587 (0x4e1a70) has ONE privilege gate: priv_check(td, 0x2ae = 686) at 0x4e1b0c; the rest
   is target selection (pid, pfind, cr_cansee/priv 60) plus a tag whitelist on the denied path. No
   argument shape reaches the full-copy path 0x4e1b75 for a uid-1 game process: the length is a
   hardcoded 0x88 and pid changes WHOSE cred is read, never WHICH branch runs.
3. 45 privilege checks carry an immediate inside the 300 non-nosys bodies: 38 priv_check @0xadfa30,
   7 priv_check_cred @0xadf890. Top numbers 688 (sys 41), 687 (602), 686 (587), 685 (559 x2, 586);
   priv 683 is reused by 13 syscalls. sys 532 -> 682 is MEASURED REFUSED (probe 1242a, EPERM).

## METHOD / TRUST
- capstone 5.0.7; every function entered at its '55 48 89 e5' prologue (0x608fb0, 0x3c0ab0, 0x68fd20,
  0x6b9640, 0x4e1a70). Windows that start mid-instruction are rejected, not patched.
- Callers: whole-image E8/E9 rel32 scan (291565 hits) filtered to sites inside a known function
  extent; data above ~0xcc0000 excluded from edges. "Inside a body" = interval test against the 300
  body extents from the E9 thunk targets of docs/dumps_13.60/sysent_index.json (679 entries, 301
  unique targets, nosys 0x5620e0); prologue proximity is not used because 0x25d360-0x270018 is a run
  of 8-byte 'E9 rel32; cc cc cc' stubs that fabricates callers for any back-scan.
- The brief's 0x68fd94 is not a function start: 0x68fd90 is mid-instruction (mov r15,[rbp-0x128]) and
  0x68fd94 is an operand byte. Real container 0x68fd20, extent 0x68fd20-0x69002a.

## TASK 1 - bit 61 / level 2

Helper 0x608fb0 (leaf): 0x608fb4 mov rax,[rdi+0x60] ; 0x608fb8 shr rax,0x3d ; 0x608fbc and eax,1 ;
0x608fc0 ret. Argument struct ucred *, result bit 61 of cr+0x60. Siblings 0x608f90 = shr 0x3e (bit 62),
0x608fd0 = shr 0x3c (bit 60). Exactly three call sites image-wide: 0x3c145f, 0x68feb9, 0x6b9659.

A) 0x3c145f in 0x3c0ab0 (642 insns, ends 0x3c1531). Pre-gates 0x3c1424 mov rdi,[rbx+0x10] ; 0x3c1428
test edi,edi ; 0x3c142a jne 0x3c14e3 ; 0x3c1436 test byte [rax+0x20],4 ; 0x3c1440 test byte
[r12+9],0x80 ; 0x3c1450 cmp qword [rax],0. Then 0x3c145a mov rdi,[r12+0x18] ; 0x3c145f call 0x608fb0 ;
0x3c1466 test eax,eax ; 0x3c1468 je 0x3c14e3.
   bit61==1: 0x3c146a lea r14,[rip+0x283ac0f] (malloc type string, target RVA 0x2bfc080) ; 0x3c1471
   mov edi,0x420 ; 0x3c1476 mov edx,2 ; 0x3c147e call 0xc08b50 (malloc) ; 0x3c149c call 0x4aee40
   (snprintf(buf,0x420,fmt,[r12+0x28])) ; 0x3c14a1 mov rcx,gs:[0] ; 0x3c14aa mov rdx,[rcx+8]
   (td_proc) ; 0x3c14ae mov esi,[rcx+0x9c] (td_tid) ; 0x3c14b6 mov edi,[rdx+0xbc] (p_pid) ; 0x3c14bf
   call 0x68f470 (log(pid,tid,buf,len)) ; 0x3c14ca call 0xc08df0 (free) ; 0x3c14cf xor edi,edi.
   Join 0x3c14e3 mov rax,[r13] ; 0x3c14f0 mov eax,edi, so both paths return 0; only the log differs.
   Object used: cred at [r12+0x18]; log args from [rcx+8], [rcx+0x9c], [rdx+0xbc].
B) 0x68feb9 in 0x68fd20 (184 insns, ends 0x69002a). 0x68fe99 mov rdi,[rax+0x140] (td_ucred of the
thread at [r14+0x28]) ; 0x68fea0 call 0x608f90 ; 0x68fea5 mov ecx,1 ; 0x68feaa test eax,eax ;
0x68feac jne 0x68fec7 (bit62 -> 1) ; 0x68feb2 mov rdi,[rax+0x140] ; 0x68feb9 call 0x608fb0 ;
0x68febe xor ecx,ecx ; 0x68fec2 setne cl ; 0x68fec5 add ecx,ecx (2) ; 0x68fec7 lea r12,[rip+0x31fe38a]
; 0x68fece mov [rbp-0xcc],ecx.
   Then lock 0x4c6a00 (0x68fedd) / 0x4c6fa0 (0x68fef3): 0x68fee2 movzx r15d,byte [rip+0x31fe376]
   (record length) ; 0x68fef8 mov rdi,[rip+0x31fe369] ; 0x68feff lea rsi,[rbp-0x118] ; 0x68ff06 mov
   edx,r15d ; 0x68ff0c call 0x9065d0 (write). Object used: the record at [rbp-0x118]; effect = one
   byte (level 0/1/2) inside a trace record.
C) 0x6b9659 in 0x6b9640 (32 insns, ends 0x6b9699), signature (edi=level, rsi=ucred*) -> bool. 0x6b9646
test edi,edi ; 0x6b9648 je 0x6b966f (level 0 -> al=1, always true) ; 0x6b964c cmp edi,2 ; 0x6b964f je
0x6b9660 (level 2 -> 0x6b9663 call 0x608f90) ; 0x6b9651 cmp ecx,1 ; 0x6b9654 jne 0x6b9673 (other level
-> panic: lea rdi,[rip+0xc5a940], lea rsi,[rip+0xccdf17], edx=0x527, call 0xc1d410) ; 0x6b9656 mov
rdi,rsi ; 0x6b9659 call 0x608fb0 ; 0x6b9668 test eax,eax ; 0x6b966a setne bl ; 0x6b968f movzx eax,bl.
   C1 0x3be589 in 0x3bd830: 1 -> 0x3be596 inc dword [rcx+0x14] (rcx=[rbx+0x40]) and 0x3be599 mov dword
      [r14],0 ; 0 -> 0x3be5c7. Object: the counter at [rbx+0x40]+0x14.
   C2 0x3c0366 in 0x3c0270: 1 -> 0x3c036f cmp dword [r13+0xc],3, 0x3c0374 mov r15d,2 ; 0 ->
      0x3c03bb mov r15d,0 ; r15d tested at 0x3c0444 cmp r15d,2 and 0x3c044e test r15d,r15d, so bit 61
      selects the level-2 arm of a 3-way branch.
   C3 0x3c2270 in 0x3c2240 (after lookup 0xa55660): 1 -> esi=[rbx+0x10], ecx=(obj+0xc != 3),
      rdx=obj+0x34, call 0x3c2100 at 0x3c2291 ; 0 -> esi=2, ecx=-1, tail jmp 0x3c2100 at 0x3c22b9.

REACHABILITY. All nine inbound sites fail the body-interval test: 0x3c145f, 0x68feb9, 0x6b9659,
0x3bb0e7, 0x3c03ae, 0x3c0415, 0x3be589, 0x3c0366, 0x3c2270. No body calls or tail-jumps to 0x608fb0,
0x3c0ab0, 0x68fd20 or 0x6b9640.
    0x608fb0 <- 0x3c145f in 0x3c0ab0 <- { 0x3bb0e7 in 0x3babb0 (extent 0x3babb0-0x3bb1e7);
                0x3c03ae + 0x3c0415 in 0x3c0270 }
              <- 0x68feb9 in 0x68fd20 <- E9 at 0x26b208 (only inbound)
              <- 0x6b9659 in 0x6b9640 <- { 0x3be589 in 0x3bd830 <- E9 0x25db40;
                0x3c0366 in 0x3c0270 <- call 0x3bac69 inside 0x3babb0;
                0x3c2270 in 0x3c2240 <- E9 0x265780 }
    0x3babb0 <- E9 at 0x25dac0 (only inbound)
Every entry passes one jmp stub in the thunk block. None of the four stubs (0x25dac0, 0x25db40,
0x265780, 0x26b208) is among the 679 sy_call values (slots point to RVAs 0x25dc28..0x265fa8,
neighbouring stubs), and the image holds no qword pointer to any stub or to any of these eight
functions: their dispatch tables live in the data segment, outside this dump. Answer (b): never
reached from a sysent body by direct call or tail jmp, only indirectly through table dispatch.

RANKING for a holder of bit 61 without bit 62:
1. 0x6b9640 - the only caller whose answer is acted on: a counter increment (C1), a three-way policy
   arm (C2), an argument choice (C3). Grants no object, but its holders are "level 2" wherever a level
   is read from object+0x18.
2. 0x3c0ab0 - emits one kernel log line (pid, tid, object string); no decision follows.
3. 0x68fd20 - stamps a trace level byte; no behavioural consequence.

## TASK 2 - syscall 587, body 0x4e1a70 (103 insns, ends 0x4e1bf5)

uap->arg0 = target pid (32-bit, 0 = self), uap->arg1 = user buffer of 0x88 bytes. 0x4e1aa5 call 0x49af30 = memset([rbp-0xb0],0,0x88); with fill byte 0 the callee takes
its bzero path (0x49af5e mov rdi,rbx, 0x49af64 call 0x258ff0).
T0 0x4e1aaa mov edi,[rbx] ; test ; 0x4e1aae je 0x4e1aee. pid==0 -> r14=[r15+8] (td_proc), 0x4e1af8
   lea rdi,[r14+0x148], 0x4e1aff call 0x4c6a00 (lock).
T1 pid!=0: 0x4e1ab0 call 0x53c170 = pfind (0x53c189 call 0xc4b350 on a global pidhash lock at [rip+0x304dcdf]; index = pid &
   [rip+0x304dc78]; bucket walk via [proc+0xc0]; compares dword [proc+0xbc]; then 0x53c1d9 call
   0x4c6a00 takes proc+0x148 and drops the proc when dword [proc+0xb8]==0) ; NULL -> 0x4e1b6e mov eax,3 (ESRCH). A found proc comes back LOCKED.
T2 0x4e1ac7 call 0x2a8ca0 = {mov rdi,[rdi+0x140]; mov rsi,[rsi+0x40]; jmp 0x2aa9f0} =
   cr_cansee(td_ucred,target_ucred): 0x2aaa04 call 0xbea6d0, 0x2aaa0d cmp dword [rip+0x17e8f1c],0,
   0x2aaa16/19 compare cr_uid, 0x2aaa22 mov esi,0x3c (priv 60), 0x2aaa29 call 0xadf890; refusal ->
   0x4e1ad0 add r14,0x148 ; 0x4e1ae2 call 0x4c6fa0 ; ret eax (=3).
T3 GATE 0x4e1b04 mov rdi,r15 (struct thread *) ; 0x4e1b07 mov esi,0x2ae (686) ; 0x4e1b0c call 0xadfa30
   (priv_check) ; 0x4e1b11 mov rcx,[r14+0x40] (p_ucred) ; 0x4e1b15 mov r15d,eax ; 0x4e1b18 lea
   rsi,[rcx+0x58] ; 0x4e1b1c test eax,eax ; 0x4e1b1e je 0x4e1b75 (GRANTED). priv_check @0xadfa30 =
   {mov rdi,[rdi+0x140]; jmp 0xadf890} = priv_check_cred(td->td_ucred,686,0). Per census: allow when
   [cred+8]==0 or [cred+4]==0 or num==0x2b1; else require (num-2)<=0x2b1 and index the table at RVA
   0x18bd278 (outside this dump, so the 686 slot is unreadable here).
T4 GRANTED 0x4e1b75 lea rdi,[rbp-0xb0] ; 0x4e1b7c mov edx,0x88 ; 0x4e1b81 call 0x2590b0 (bcopy,
   overlap-checked): copies cred+0x58..cred+0xDF verbatim.
T5 DENIED 0x4e1b20 mov rax,[rsi] (tag at cred+0x58) ; 0x4e1b23 movabs rdx,0xb7ffffffeffffffc (=
   -0x4800000000100004) ; 0x4e1b2d add rdx,rax ; 0x4e1b30 cmp rdx,0xf ; 0x4e1b34 ja ; 0x4e1b36 mov
   esi,0xe001 ; 0x4e1b3b bt rsi,rdx ; 0x4e1b3f jb 0x4e1b50 ; 0x4e1b41 movabs rdx,0x4800000000001010 ;
   0x4e1b4b cmp rax,rdx ; 0x4e1b4e jne 0x4e1b57 ; 0x4e1b50 mov [rbp-0xb0],rax ; 0x4e1b57 movabs
   rax,0x7000000000000000 ; 0x4e1b61 and rax,[rcx+0x60] ; 0x4e1b65 mov [rbp-0xa8],rax.
   Whitelist = 0x4800000000100004 + {0,13,14,15} via mask 0xe001 = {..100004, ..100011, ..100012,
   ..100013} plus 0x4800000000001010; otherwise the tag qword stays 0 and only the &
   0x7000000000000000 result returns.
T6 TAIL 0x4e1b86 add r14,0x148 ; 0x4e1b96 call 0x4c6fa0 (unlock) ; 0x4e1b9b mov rbx,[rbx+8] (arg1) ;
   0x4e1ba2 je 0x4e1bd1 (return r15d). With a buffer: 0x4e1ba4 mov rdi,gs:[0] ; 0x4e1bad lea
   rsi,[rip+0xe6d6e3] (format string outside dump) ; call 0xc1a3e0 ; 0x4e1bca call 0x2591d0
   copyout(record,arg1,0x88). Canary 0x4e1bd8 cmp rcx,[rbp-0x28].

REDACTION, not refusal: both branches return 0. Granted = raw cred+0x58..+0xDF; denied = tag (if
whitelisted) plus cr+0x60 & 0x7000000000000000, so the gate decides how much of the cred is visible.
CLASSIFICATION: privilege number 686 (0x2ae) via priv_check -> priv_check_cred, and that is the only
test separating granted from denied. Target selection (pid 0=self, pfind, cr_cansee with priv 60)
picks WHOSE cred is read and can return ESRCH/EPERM first; it cannot grant. The capability-tag
constants exist only on the denied path as a five-value whitelist (a disclosure limit, not a gate). No
process-state byte: proc+0xc81, +0x591, +0x563 never appear in 0x4e1a70-0x4e1c40 (the only
+0x591 test nearby is copyout's own guard, 0x259214 cmp byte [proc+0x591],0). No length argument:
0x88 is hardcoded in bcopy and copyout.
ARGUMENT SHAPES: none reach 0x4e1b75 for a uid-1 game process. 0x4e1b1e je is taken only when
priv_check succeeds for the CALLER's thread (rdi=r15=td, not the target's): pid is irrelevant (pid=0
and pid=getpid() run the identical gate on the identical cred; another pid only adds a cansee check
that can refuse); a thr_create(430) child is a thread of the same process with the same td_ucred, so
identical; arg1 only selects copyout vs "return r15d" (NULL arg1 -> EPERM, no record). Only a
credential satisfying priv 686 reaches the full copy - a different privilege class, not a uid change,
not a thread, not an argument. The measured game cred (55e: 0x88 bytes, +0x0C = 0x20000000, i.e.
cr+0x60 & 0x7000000000000000 = 0x2000000000000000, bit 61 only) takes the denied path.

## TASK 3 - privilege map (immediate operand at the call site)

Re-scan of all 300 non-nosys bodies ('BE imm32' back-scan whose decode lands on the helper call),
cross-checked with docs/PRIV_CHECK_CENSUS_14_10.md. 45 sites, all with a literal privilege number: 38
priv_check (0xadfa30) + 7 priv_check_cred (0xadf890, marked pcc). The census counts 46 (39+7); the
extra priv_check falls outside every body extent in this image, so it is omitted rather than guessed.
R = MEASURED REFUSED: probe 1242a returns EPERM for sys 532 -> 0x2aa.

  priv sys site         priv sys site         priv sys site
  ---- --- -----------  ---- --- -----------  ---- --- -----------
     8  55 0x7e481e     201  96 0x4a02c7     683  90 0x729a55
    15 140 0x331164     201  96 0x4a0357     683  92 0x729df5
    17 233 0x6bbd8c     201  96 0x4a03d9     683 190 0x8f9289
    17 233 0x6bbde0     204 329 0x5a3d02     683 191 0x8f933b
    18 122 0x6bc976     312  56 0x8fc5b0     683 192 0x72c40b
    18 122 0x6bc9b9     326 397 0x8f6391     683 315 0xb7e98b
    50  23 0x2a92b2pcc  361 324 0xab95a4     683 397 0x8f614e
    51 183 0x2a97b8pcc  362 204 0xab9722     683 499 0x8f6e66
    53 182 0x2a9a9cpcc  362 325 0xab96a6     683 603 0x72eceb
    54  80 0x2a9cf0pcc  680 147 0x2a8e87     685 559 0xabc556
    55 126 0x2a9ef7pcc  682 532 0xaf00e6 R   685 559 0xabc5a4
    56 127 0x2aa14cpcc  683  12 0x8f6b49     685 586 0x3ce18f
    59  80 0x6e4ba3pcc  683  33 0x8f8bf2     686 587 0x4e1b0c
   161  50 0x2ab7c9     683  56 0x8fc4b9     687 602 0xa36917
   201  96 0x4a0185     683  89 0x7299ff     688  41 0x729d92

Duplicates (syscall, number): (233,17) x2 0x6bbd8c 0x6bbde0; (122,18) x2 0x6bc976 0x6bc9b9; (96,201)
x4 0x4a0185 0x4a02c7 0x4a0357 0x4a03d9; (559,685) x2 0xabc556 0xabc5a4. Shared across syscalls: 683 ->
13 syscalls (12,33,56,89,90,92,190,191,192,315,397,499,603); 685 -> 2; 362 -> 2. All numbers are <=
0x2b1 = 689, so the (num-2)<=0x2b1 bound never trips at these sites; everything above 680 is
Sony-specific. Only 682 (refused) and 686 (587, refused for the game cred, denied path still returns
0) have measured behaviour. No number here is satisfied by bit 61; bit 61 only acts as a level tag.

## WHAT TO PROBE NEXT
1. Capture the data segment holding the priv table at RVA 0x18bd278; its 686 slot decides which cred shape can pass 587.
2. Call 587 with pid=0 and arg1=NULL: -1 means the gate runs before copyout; a 0 means r15d leaks the priv status.
3. Identify the owners of thunks 0x25dac0, 0x25db40, 0x265780 - the only entry points into the bit-61 cluster.
