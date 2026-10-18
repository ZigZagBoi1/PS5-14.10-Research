/* handler_627.bin — REA 6.7.0 / Ghidra 12.1.4, static recovered pseudocode.
 * Original SHA256 cf4ec20a234b0ab3de686b8d08015bc451e27a111f44fc360cd42fde80a92bc0.
 * Input zero = 0xffffffff8ac25ec0; actual target = 0xffffffff8ae62850.
 * Original binary is 512 adjacent JMP trampolines, not 512 implementations.
 * Part 1: analyst-reviewed semantic recovery with inferred types/field names.
 * Part 2: original REA/Ghidra primary-body decompilation.
 * Part 3: REA decompilation of each mapped trampoline in this input.
 * Calling conventions/external prototypes incomplete; not original or buildable C.
 * Actual body bytes are supplemental kernel_text.bin, not original input window.
 */

/* Reviewed semantic recovery; address-derived labels are not recovered symbols.
 * Supplemental kernel body at original runtime VA, not the 4KB input window.
 * Padding and types recover only accessed fields; no complete ABI is asserted.
 * Stack-canary checks omitted from semantic flow (failure -> 0xffffffff8b0bd6b0).
 */
/* REA root evidence: ev_f906bfc92afa8079adbb5dced3260238f4de088559ab81da5b42cbe2b0e9a70b; Ghidra 12.1.4. */
#include <stdint.h>
#include <stddef.h>
/* Root 0xffffffff8ae62850: process/thread timing snapshot, 0x28-byte records. */
struct proc627;
struct thread627 { void *lock_pointer_00; struct proc627 *proc_08;
    struct thread627 *next_10; uint8_t pad18[0x9c-0x18]; uint32_t id_9c;
    uint8_t pada0[0xed-0xa0]; uint8_t flags_ed; uint8_t padee[0x238-0xee]; uint64_t value_238; };
struct proc627 { struct proc627 *next_00; uint8_t pad08[8]; struct thread627 *threads_10;
    uint8_t pad18[0xb8-0x18]; uint32_t state_b8, id_bc;
    uint8_t padc0[0xb48-0xc0]; int32_t count_b48; };
struct td627 { uint8_t pad00[0x140]; void *credential_140; };
struct cred627 { uint8_t pad00[0x60]; uint64_t flags_60; };
struct args627 { void *user_records_00; void *user_count_08; };
struct timepair627 { int64_t seconds, remainder; };
struct record627 { uint32_t process_00, thread_04;
    struct timepair627 time_08, time_18; };
_Static_assert(sizeof(struct record627)==0x28,"observed record stride");
struct iov627 { void *base; uint64_t length; };
struct uio627 { struct iov627 *iov; uint32_t count; uint8_t pad0c[4];
    uint64_t offset,residual; uint32_t flags20,flags24; void *td; };
extern struct proc627 *global_ffffffff8df49e80;
extern void sub_ffffffff8ae62ce0(void);
extern int32_t sub_ffffffff8b142a40(void *user_address);
extern int sub_ffffffff8ac19790(void *user_address,uint32_t value);
extern void sub_ffffffff8b60b350(void *,int,int,int),sub_ffffffff8b60c300(void *,int,int);
extern void sub_ffffffff8ae86a00(void *,int,int,int),sub_ffffffff8ae86fa0(void *,int,int,int);
extern void sub_ffffffff8ae87190(void *,int,int,int),sub_ffffffff8ae87520(void *,int,int,int);
extern void sub_ffffffff8ae878b0(void *,int,void *,int);
extern void *sub_ffffffff8b5c8b50(uint64_t,void *,int);
extern void sub_ffffffff8b5c8df0(void *,void *);
extern void sub_ffffffff8ae61a20(struct thread627 *,void *out_usage);
extern int64_t sub_ffffffff8b4909c0(uint64_t);
extern int sub_ffffffff8b142520(void *,uint32_t,struct uio627 *);
int handler_627(struct td627 *td,const struct args627 *a) {
    if (!((((struct cred627 *)td->credential_140)->flags_60>>62)&1)) return 0x4e;
    sub_ffffffff8ae62ce0(); /* CPU mask synchronization; see report */
    void *list_lock=(void *)UINT64_C(0xffffffff8df49e60);
    if (!a->user_records_00) {
        uint32_t count=0;
        sub_ffffffff8b60b350(list_lock,0,0,0);
        for(struct proc627 *p=global_ffffffff8df49e80;p;p=p->next_00) {
            sub_ffffffff8ae86a00((uint8_t *)p+0x148,0,0,0);
            count+=(uint32_t)p->count_b48;
            sub_ffffffff8ae86fa0((uint8_t *)p+0x148,0,0,0);
        }
        sub_ffffffff8b60c300(list_lock,0,0);
        return sub_ffffffff8ac19790(a->user_count_08,count)?14:0;
    }
    int32_t capacity=sub_ffffffff8b142a40(a->user_count_08);
    if(capacity==-1) return 14;
    if(capacity<=0) return 22;
    struct iov627 iov={a->user_records_00,(uint64_t)(uint32_t)capacity*0x28};
    struct uio627 uio={&iov,1,{0},0,iov.length,0,0,td};
    uint32_t count=0;
    void *alloc_type=(void *)UINT64_C(0xffffffff8c488120);
    sub_ffffffff8b60b350(list_lock,0,0,0);
    for(struct proc627 *p=global_ffffffff8df49e80;p;p=p->next_00) {
        void *proc_lock=(uint8_t *)p+0x148;
    retry_process:
        sub_ffffffff8ae86a00(proc_lock,0,0,0);
        if(p->state_b8!=1) { sub_ffffffff8ae86fa0(proc_lock,0,0,0); continue; }
        int32_t allocated=p->count_b48;
        sub_ffffffff8ae86fa0(proc_lock,0,0,0);
        uint64_t bytes=(uint64_t)(int64_t)allocated*0x28;
        struct record627 *records=sub_ffffffff8b5c8b50(bytes,alloc_type,0x102);
        sub_ffffffff8ae86a00(proc_lock,0,0,0);
        if(allocated<p->count_b48) {
            sub_ffffffff8ae86fa0(proc_lock,0,0,0); sub_ffffffff8b5c8df0(records,alloc_type); goto retry_process;
        }
        sub_ffffffff8ae87190((uint8_t *)p+0x168,0,0,0);
        unsigned i=0;
        for(struct thread627 *t=p->threads_10;t;t=t->next_10,++i,++count) {
            sub_ffffffff8ae878b0(t,0,(void *)UINT64_C(0xffffffff8bc6a1cd),0x647);
            struct record627 *r=&records[i];
            r->process_00=p->id_bc; r->thread_04=t->id_9c;
            uint8_t usage[0xd0]; sub_ffffffff8ae61a20(t,usage);
            if(t->flags_ed&4) {
                r->time_08=(struct timepair627){0,0};
                int64_t v=sub_ffffffff8b4909c0(t->value_238);
                r->time_18.seconds=v/1000000; r->time_18.remainder=v%1000000;
            } else {
                /* Exact first 0x20 output bytes of usage helper, at +0 and +0x10. */
                r->time_08=*(struct timepair627 *)(usage+0);
                r->time_18=*(struct timepair627 *)(usage+0x10);
            }
            sub_ffffffff8ae87520((uint8_t *)t->lock_pointer_00+0x18,0,0,0);
        }
        sub_ffffffff8ae87520((uint8_t *)p+0x168,0,0,0);
        sub_ffffffff8ae86fa0(proc_lock,0,0,0);
        uint64_t available=bytes<uio.residual?bytes:uio.residual;
        int error=sub_ffffffff8b142520(records,(uint32_t)available,&uio);
        sub_ffffffff8b5c8df0(records,alloc_type);
        if(error) { sub_ffffffff8b60c300(list_lock,0,0); return error; }
    }
    sub_ffffffff8b60c300(list_lock,0,0);
    return sub_ffffffff8ac19790(a->user_count_08,count)?14:0;
}
/* Helper ...62ce0: lock ...8def6578; global mask ...8def6528=0;
 * increment current_td+0x5a8; ...8b077940(); for CPU IDs0..global ...8e6ce8b8,
 * test online mask ...8e6ce8e8 and build required bitmap, atomically OR current
 * CPU bit; ...8b1de5b0(8); ...8b077960(); decrement td+0x5a8 (call ...77af0
 * when previous value==0x80000001); spin until global mask==required; unlock.
 * Exact meanings of the helper names and timing units remain unverified.
 */

/* ===== PART 2: RAW REA/GHIDRA BODY handler_body_627 0xffffffff8ae62850 =====
 * Evidence: ev_f906bfc92afa8079adbb5dced3260238f4de088559ab81da5b42cbe2b0e9a70b
 * Signature: undefined handler_body_627()
 * Body: {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xffffffff8ae62850", "end": "0xffffffff8ae62939"}, {"start": "0xffffffff8ae62940", "end": "0xffffffff8ae629fd"}, {"start": "0xffffffff8ae62a00", "end": "0xffffffff8ae62a49"}, {"start": "0xffffffff8ae62a50", "end": "0xffffffff8ae62cd5"}], "total_bytes": 1144, "span_bytes": 1158, "non_contiguous": true, "contains_entry": true}
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int handler_body_627(long param_1,long *param_2)

{
  long *plVar1;
  code *pcVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  long lVar6;
  long lVar7;
  ulong uVar8;
  long *plVar9;
  long *plVar10;
  long *plVar11;
  long local_108;
  long local_100;
  long local_f8;
  long local_f0;
  long local_78;
  ulong local_70;
  long *local_68;
  undefined4 local_60;
  undefined8 local_58;
  ulong local_50;
  undefined8 local_48;
  long local_40;
  long local_38;
  
  local_38 = _DAT_ffffffff8e2dc310;
  iVar3 = func_0xffffffff8afc8f90(*(undefined8 *)(param_1 + 0x140));
  if (iVar3 == 0) {
    iVar3 = 0x4e;
  }
  else {
    sub_4a2ce0();
    if (*param_2 == 0) {
      iVar3 = 0;
      func_0xffffffff8b60b350(0xffffffff8df49e60,0,0,0);
      if (_DAT_ffffffff8df49e80 != (long *)0x0) {
        iVar3 = 0;
        plVar10 = _DAT_ffffffff8df49e80;
        do {
          func_0xffffffff8ae86a00(plVar10 + 0x29,0,0,0);
          iVar3 = iVar3 + (int)plVar10[0x169];
          func_0xffffffff8ae86fa0(plVar10 + 0x29,0,0);
          plVar10 = (long *)*plVar10;
        } while (plVar10 != (long *)0x0);
      }
      func_0xffffffff8b60c300(0xffffffff8df49e60,0,0);
      iVar5 = func_0xffffffff8ac19790(param_2[1],iVar3);
      iVar3 = 0xe;
      if (iVar5 == 0) {
        iVar3 = 0;
      }
    }
    else {
      uVar4 = func_0xffffffff8b142a40(param_2[1]);
      if (uVar4 == 0xffffffff) {
        iVar3 = 0xe;
      }
      else if ((int)uVar4 < 1) {
        iVar3 = 0x16;
      }
      else {
        local_78 = *param_2;
        iVar5 = 0;
        local_70 = (ulong)uVar4 * 0x28;
        local_68 = &local_78;
        local_60 = 1;
        local_58 = 0;
        local_48 = 0;
        local_50 = local_70;
        local_40 = param_1;
        func_0xffffffff8b60b350(0xffffffff8df49e60,0,0,0);
        if (_DAT_ffffffff8df49e80 != (long *)0x0) {
          iVar5 = 0;
          plVar10 = _DAT_ffffffff8df49e80;
          do {
            plVar1 = plVar10 + 0x29;
            while (func_0xffffffff8ae86a00(plVar1,0,0,0), (int)plVar10[0x17] == 1) {
              lVar7 = plVar10[0x169];
              func_0xffffffff8ae86fa0(plVar1,0,0);
              uVar8 = (long)(int)lVar7 * 0x28;
              lVar6 = func_0xffffffff8b5c8b50(uVar8,0xffffffff8c488120,0x102);
              func_0xffffffff8ae86a00(plVar1,0,0,0);
              if ((int)plVar10[0x169] <= (int)lVar7) {
                func_0xffffffff8ae87190(plVar10 + 0x2d,0,0);
                plVar11 = (long *)plVar10[2];
                if (plVar11 != (long *)0x0) {
                  plVar9 = (long *)(lVar6 + 0x20);
                  do {
                    func_0xffffffff8ae878b0(plVar11,0,0xffffffff8bc6a1cd,0x647);
                    *(undefined4 *)(plVar9 + -4) = *(undefined4 *)((long)plVar10 + 0xbc);
                    *(undefined4 *)((long)plVar9 + -0x1c) = *(undefined4 *)((long)plVar11 + 0x9c);
                    func_0xffffffff8ae61a20(plVar11);
                    if ((*(byte *)((long)plVar11 + 0xed) & 4) == 0) {
                      plVar9[-2] = local_100;
                      plVar9[-3] = local_108;
                      *plVar9 = local_f0;
                      plVar9[-1] = local_f8;
                    }
                    else {
                      plVar9[-3] = 0;
                      plVar9[-2] = 0;
                      lVar7 = func_0xffffffff8b4909c0(plVar11[0x47]);
                      plVar9[-1] = lVar7 / 1000000;
                      *plVar9 = lVar7 % 1000000;
                    }
                    func_0xffffffff8ae87520(*plVar11 + 0x18,0,0);
                    plVar11 = (long *)plVar11[2];
                    plVar9 = plVar9 + 5;
                    iVar5 = iVar5 + 1;
                  } while (plVar11 != (long *)0x0);
                }
                func_0xffffffff8ae87520(plVar10 + 0x2d,0,0);
                func_0xffffffff8ae86fa0(plVar1,0,0);
                if (local_50 < uVar8) {
                  uVar8 = local_50;
                }
                iVar3 = func_0xffffffff8b142520(lVar6,uVar8 & 0xffffffff,&local_68);
                func_0xffffffff8b5c8df0(lVar6);
                if (iVar3 != 0) {
                  func_0xffffffff8b60c300(0xffffffff8df49e60,0,0);
                  goto LAB_ffffffff8ae62cb3;
                }
                goto LAB_ffffffff8ae6294e;
              }
              func_0xffffffff8ae86fa0(plVar1,0,0);
              func_0xffffffff8b5c8df0(lVar6);
            }
            func_0xffffffff8ae86fa0(plVar1,0,0);
LAB_ffffffff8ae6294e:
            plVar10 = (long *)*plVar10;
          } while (plVar10 != (long *)0x0);
        }
        func_0xffffffff8b60c300(0xffffffff8df49e60,0,0);
        iVar5 = func_0xffffffff8ac19790(param_2[1],iVar5);
        iVar3 = 0xe;
        if (iVar5 == 0) {
          iVar3 = 0;
        }
      }
    }
  }
LAB_ffffffff8ae62cb3:
  if (_DAT_ffffffff8e2dc310 != local_38) {
    func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
    pcVar2 = (code *)invalidInstructionException();
    (*pcVar2)();
  }
  return iVar3;
}



/* Supplemental direct callee 0xffffffff8ae62ce0; Evidence ev_24a85f2e3ea167b97382abb39da26f2936b7d42aad9967fb328baae282ac8c7d */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_4a2ce0(void)

{
  int *piVar1;
  int iVar2;
  ulong uVar3;
  uint uVar4;
  ulong uVar5;
  long *in_GS_OFFSET;
  
  uVar5 = 0;
  func_0xffffffff8ae86a00(0xffffffff8def6578,0,0,0);
  _DAT_ffffffff8def6528 = 0;
  LOCK();
  *(int *)(*in_GS_OFFSET + 0x5a8) = *(int *)(*in_GS_OFFSET + 0x5a8) + 1;
  UNLOCK();
  func_0xffffffff8b077940();
  uVar3 = 0;
  do {
    if ((_DAT_ffffffff8e6ce8e8 >> (uVar5 & 0x3f) & 1) != 0) {
      if ((int)uVar5 == *(int *)((long)in_GS_OFFSET + 0x34)) {
        LOCK();
        _DAT_ffffffff8def6528 =
             _DAT_ffffffff8def6528 | 1L << ((ulong)*(uint *)((long)in_GS_OFFSET + 0x34) & 0x3f);
        UNLOCK();
      }
      uVar3 = uVar3 | 1L << (uVar5 & 0x3f);
    }
    uVar4 = (int)uVar5 + 1;
    uVar5 = (ulong)uVar4;
  } while (uVar4 <= _DAT_ffffffff8e6ce8b8);
  func_0xffffffff8b1de5b0(8);
  func_0xffffffff8b077960();
  LOCK();
  piVar1 = (int *)(*in_GS_OFFSET + 0x5a8);
  iVar2 = *piVar1;
  *piVar1 = *piVar1 + -1;
  UNLOCK();
  if (iVar2 == -0x7fffffff) {
    func_0xffffffff8b077af0();
  }
  do {
  } while (uVar3 != _DAT_ffffffff8def6528);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== PART 3: ALL 512 ORIGINAL TRAMPOLINES =====
 * Adjacent stubs are not subcommands. No permission checks/argument decoding in JMP-only bodies.
 * Unknown external ABI remains unknown. Ghidra halt_baddata() for unmapped tail
 * destinations is a boundary artifact, not an observed CPU halt or invalid target.
 */

/* Input +0x000, VA 0xffffffff8ac25ec0, JMP target 0xffffffff8ae62850; Evidence ev_e1b4c3263b3691353fa67c2117ee45beccbaddec70b000f5bfd63b251c314cdc */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae62850); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int handler_body_627(long param_1,long *param_2)

{
  long *plVar1;
  code *pcVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  long lVar6;
  long lVar7;
  ulong uVar8;
  long *plVar9;
  long *plVar10;
  long *plVar11;
  long lStack_108;
  long lStack_100;
  long lStack_f8;
  long lStack_f0;
  long lStack_78;
  ulong uStack_70;
  long *plStack_68;
  undefined4 uStack_60;
  undefined8 uStack_58;
  ulong uStack_50;
  undefined8 uStack_48;
  long lStack_40;
  long lStack_38;
  
  lStack_38 = _DAT_ffffffff8e2dc310;
  iVar3 = func_0xffffffff8afc8f90(*(undefined8 *)(param_1 + 0x140));
  if (iVar3 == 0) {
    iVar3 = 0x4e;
  }
  else {
    sub_4a2ce0();
    if (*param_2 == 0) {
      iVar3 = 0;
      func_0xffffffff8b60b350(0xffffffff8df49e60,0,0,0);
      if (_DAT_ffffffff8df49e80 != (long *)0x0) {
        iVar3 = 0;
        plVar10 = _DAT_ffffffff8df49e80;
        do {
          func_0xffffffff8ae86a00(plVar10 + 0x29,0,0,0);
          iVar3 = iVar3 + (int)plVar10[0x169];
          func_0xffffffff8ae86fa0(plVar10 + 0x29,0,0);
          plVar10 = (long *)*plVar10;
        } while (plVar10 != (long *)0x0);
      }
      func_0xffffffff8b60c300(0xffffffff8df49e60,0,0);
      iVar5 = func_0xffffffff8ac19790(param_2[1],iVar3);
      iVar3 = 0xe;
      if (iVar5 == 0) {
        iVar3 = 0;
      }
    }
    else {
      uVar4 = func_0xffffffff8b142a40(param_2[1]);
      if (uVar4 == 0xffffffff) {
        iVar3 = 0xe;
      }
      else if ((int)uVar4 < 1) {
        iVar3 = 0x16;
      }
      else {
        lStack_78 = *param_2;
        iVar5 = 0;
        uStack_70 = (ulong)uVar4 * 0x28;
        plStack_68 = &lStack_78;
        uStack_60 = 1;
        uStack_58 = 0;
        uStack_48 = 0;
        uStack_50 = uStack_70;
        lStack_40 = param_1;
        func_0xffffffff8b60b350(0xffffffff8df49e60,0,0,0);
        if (_DAT_ffffffff8df49e80 != (long *)0x0) {
          iVar5 = 0;
          plVar10 = _DAT_ffffffff8df49e80;
          do {
            plVar1 = plVar10 + 0x29;
            while (func_0xffffffff8ae86a00(plVar1,0,0,0), (int)plVar10[0x17] == 1) {
              lVar7 = plVar10[0x169];
              func_0xffffffff8ae86fa0(plVar1,0,0);
              uVar8 = (long)(int)lVar7 * 0x28;
              lVar6 = func_0xffffffff8b5c8b50(uVar8,0xffffffff8c488120,0x102);
              func_0xffffffff8ae86a00(plVar1,0,0,0);
              if ((int)plVar10[0x169] <= (int)lVar7) {
                func_0xffffffff8ae87190(plVar10 + 0x2d,0,0);
                plVar11 = (long *)plVar10[2];
                if (plVar11 != (long *)0x0) {
                  plVar9 = (long *)(lVar6 + 0x20);
                  do {
                    func_0xffffffff8ae878b0(plVar11,0,0xffffffff8bc6a1cd,0x647);
                    *(undefined4 *)(plVar9 + -4) = *(undefined4 *)((long)plVar10 + 0xbc);
                    *(undefined4 *)((long)plVar9 + -0x1c) = *(undefined4 *)((long)plVar11 + 0x9c);
                    func_0xffffffff8ae61a20(plVar11);
                    if ((*(byte *)((long)plVar11 + 0xed) & 4) == 0) {
                      plVar9[-2] = lStack_100;
                      plVar9[-3] = lStack_108;
                      *plVar9 = lStack_f0;
                      plVar9[-1] = lStack_f8;
                    }
                    else {
                      plVar9[-3] = 0;
                      plVar9[-2] = 0;
                      lVar7 = func_0xffffffff8b4909c0(plVar11[0x47]);
                      plVar9[-1] = lVar7 / 1000000;
                      *plVar9 = lVar7 % 1000000;
                    }
                    func_0xffffffff8ae87520(*plVar11 + 0x18,0,0);
                    plVar11 = (long *)plVar11[2];
                    plVar9 = plVar9 + 5;
                    iVar5 = iVar5 + 1;
                  } while (plVar11 != (long *)0x0);
                }
                func_0xffffffff8ae87520(plVar10 + 0x2d,0,0);
                func_0xffffffff8ae86fa0(plVar1,0,0);
                if (uStack_50 < uVar8) {
                  uVar8 = uStack_50;
                }
                iVar3 = func_0xffffffff8b142520(lVar6,uVar8 & 0xffffffff,&plStack_68);
                func_0xffffffff8b5c8df0(lVar6);
                if (iVar3 != 0) {
                  func_0xffffffff8b60c300(0xffffffff8df49e60,0,0);
                  goto LAB_ffffffff8ae62cb3;
                }
                goto LAB_ffffffff8ae6294e;
              }
              func_0xffffffff8ae86fa0(plVar1,0,0);
              func_0xffffffff8b5c8df0(lVar6);
            }
            func_0xffffffff8ae86fa0(plVar1,0,0);
LAB_ffffffff8ae6294e:
            plVar10 = (long *)*plVar10;
          } while (plVar10 != (long *)0x0);
        }
        func_0xffffffff8b60c300(0xffffffff8df49e60,0,0);
        iVar5 = func_0xffffffff8ac19790(param_2[1],iVar5);
        iVar3 = 0xe;
        if (iVar5 == 0) {
          iVar3 = 0;
        }
      }
    }
  }
LAB_ffffffff8ae62cb3:
  if (_DAT_ffffffff8e2dc310 != lStack_38) {
    func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
    pcVar2 = (code *)invalidInstructionException();
    (*pcVar2)();
  }
  return iVar3;
}



/* Input +0x008, VA 0xffffffff8ac25ec8, JMP target 0xffffffff8b47d540; Evidence ev_02828c9b04644899c4f8a28759e9839aab1318a8fa28c11bedd0880bf56b6461 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b47d540); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 handler_body_628(long param_1,ulong *param_2)

{
  uint uVar1;
  int iVar2;
  ulong uVar3;
  ulong uVar4;
  long lVar5;
  long lVar6;
  code *pcVar7;
  uint uVar8;
  ulong uVar9;
  int iVar10;
  undefined4 uVar11;
  long lVar12;
  ulong uVar13;
  ulong uVar14;
  uint uVar15;
  long *in_GS_OFFSET;
  bool bVar16;
  ulong uStack_40;
  long lStack_38;
  
  lStack_38 = _DAT_ffffffff8e2dc310;
  uVar14 = *param_2;
  uVar3 = param_2[1];
  uVar1 = (uint)param_2[4];
  uVar4 = param_2[5];
  iVar2 = (int)param_2[2];
  lVar5 = *in_GS_OFFSET;
  uVar8 = (uint)param_2[3] & 0xff;
  if (0x2ffffff < *(uint *)(*(long *)(lVar5 + 8) + 0x5d4)) {
    uVar8 = (uint)param_2[3];
  }
  uStack_40 = uVar14;
  iVar10 = func_0xffffffff8afc9560(*(undefined8 *)(param_1 + 0x140));
  uVar11 = 1;
  if (iVar10 != 0) goto LAB_ffffffff8b47d60e;
  iVar10 = func_0xffffffff8afc95a0(*(undefined8 *)(lVar5 + 0x140));
  if (iVar10 == 0) {
    iVar10 = func_0xffffffff8afc92d0(*(undefined8 *)(param_1 + 0x140));
    if (iVar10 == 0) {
      uVar11 = 0x16;
      if (((uVar14 & 0x3fff) != 0) || (uVar3 < 0x4000 || (uVar3 & 0x3fff) != 0))
      goto LAB_ffffffff8b47d60e;
      if ((iVar2 == -1) ||
         (iVar10 = func_0xffffffff8ad833e0(iVar2,*(undefined8 *)(param_1 + 8)), iVar10 != 0)) {
        uVar11 = 0x16;
        if ((((uVar8 & 0xfffffc0c) != 0) ||
            (uVar11 = 0x16, (uVar4 & 0x3fff) != 0 || (uVar1 & 0x9fdf2f) != 0)) ||
           (((uVar1 & 0x40) != 0 && ((0x4000 < uVar3 || ((uVar8 & 3) == 0))))))
        goto LAB_ffffffff8b47d60e;
        if (((uVar1 & 0x200000) == 0) ||
           (iVar10 = func_0xffffffff8b4e4300(*(undefined8 *)(lVar5 + 8)), iVar10 != 0)) {
          lVar12 = func_0xffffffff8b478320(param_1);
          uVar13 = lVar12 - 0x7f0000000;
          if (((uVar13 < 0x800000000) || (uVar8 < 0x40)) ||
             (*(char *)(*(long *)(lVar5 + 8) + 0xc81) != '\0')) {
            lVar6 = *(long *)(*(long *)(param_1 + 8) + 0x200);
            if ((uVar1 & 0x10) == 0) {
              if (uVar14 == 0) {
                uVar13 = *(ulong *)((ulong)(uVar13 < 0x800000000) * 0x10 + 0x1f8 + lVar6);
                uVar9 = uVar13;
              }
              else if ((uVar13 < 0x800000000) ||
                      (uVar13 = 0xff0000000, uVar9 = 0xff0000000,
                      0xff0000000 < uVar14 || uVar3 + uVar14 < 0x7f0000000)) {
                uVar13 = uVar14;
                uVar9 = uStack_40;
              }
              uStack_40 = uVar9;
              uVar14 = uVar13;
              if ((uVar1 & 0xff000000) == 0) {
                uVar15 = 1;
                if ((*(byte *)(lVar6 + 0x244) & 2) == 0) {
                  uVar15 = (*(uint *)(*(long *)(param_1 + 8) + 0x5d8) < 0x1500000) + 1;
                }
              }
              else if ((uVar1 & 0xff000000) == 0x1000000) {
                bVar16 = *(char *)(*(long *)(lVar5 + 8) + 0xc81) != '\0';
                uVar15 = bVar16 + 1 + (uint)bVar16;
              }
              else {
                uVar15 = (int)uVar1 >> 0x10 & 0xffffff00;
              }
              uVar11 = *(undefined4 *)(*(long *)(lVar5 + 8) + 0x5c4);
            }
            else {
              if (uVar14 == 0) {
                uVar11 = 0x16;
                goto LAB_ffffffff8b47d60e;
              }
              uVar11 = 0x16;
              if (((CARRY8(uVar14,uVar3) || uVar14 < *(ulong *)(lVar6 + 0x20)) ||
                  (*(ulong *)(lVar6 + 0x28) < uVar14 + uVar3)) ||
                 ((0x7ffffffff < uVar13 && (uVar14 >> 0x1c < 0xff && 0x7efffffff < uVar14 + uVar3)))
                 ) goto LAB_ffffffff8b47d60e;
              uVar11 = *(undefined4 *)(*(long *)(lVar5 + 8) + 0x5c4);
              uVar15 = 0;
            }
            uVar11 = func_0xffffffff8ad8b450
                               (param_1,lVar6,&uStack_40,uVar11,uVar4,uVar14,uVar3,iVar2,
                                uVar8 >> 1 & 0x141 | uVar8,uVar15,uVar1,lVar12,0);
            *(ulong *)(param_1 + 0x408) = uStack_40;
            goto LAB_ffffffff8b47d60e;
          }
        }
      }
      uVar11 = 0x16;
      goto LAB_ffffffff8b47d60e;
    }
    func_0xffffffff8ac1d410(0xffffffff8bd36c18);
  }
  uVar11 = 1;
LAB_ffffffff8b47d60e:
  if (_DAT_ffffffff8e2dc310 != lStack_38) {
    func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
    pcVar7 = (code *)invalidInstructionException();
    (*pcVar7)();
  }
  return uVar11;
}



/* Input +0x010, VA 0xffffffff8ac25ed0, JMP target 0xffffffff8b2dc640; Evidence ev_108bce5e9a01a5b532d34dd147050ef2824319b278900df4d687399deb3620c2 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2dc640); register/stack arguments unchanged. */

int handler_body_629(long param_1,long *param_2)

{
  long lVar1;
  int iVar2;
  char *pcVar3;
  char *pcVar4;
  undefined8 *in_GS_OFFSET;
  
  if (*param_2 == 1) {
    pcVar3 = (char *)0x0;
  }
  else {
    pcVar3 = (char *)func_0xffffffff8b5c8b50(0x400,0xffffffff8cf11e10,2);
    lVar1 = *param_2;
    func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd1a084,0);
    iVar2 = func_0xffffffff8ac19900(lVar1,pcVar3,0x400,0);
    if ((iVar2 != 0) || (iVar2 = 0x16, *pcVar3 != '/')) goto LAB_ffffffff8b2dc71d;
    iVar2 = func_0xffffffff8afc92d0(*(undefined8 *)(param_1 + 0x140));
    if ((iVar2 != 0) && (iVar2 = func_0xffffffff8b291a30(pcVar3,0xffffffff8c1dd494,0xc), iVar2 != 0)
       ) {
      func_0xffffffff8b1cd5a0(0xffffffff8bc64b80,param_1,pcVar3,0xffffffff8c1dd494);
      iVar2 = 2;
      goto LAB_ffffffff8b2dc71d;
    }
  }
  pcVar4 = (char *)0x1;
  if (*param_2 != 1) {
    pcVar4 = pcVar3;
  }
  iVar2 = func_0xffffffff8b2dbca0
                    (param_1,pcVar4,(int)param_2[1],(short)param_2[2],(int)param_2[3],0);
LAB_ffffffff8b2dc71d:
  func_0xffffffff8b5c8df0(pcVar3,0xffffffff8cf11e10);
  return iVar2;
}



/* Input +0x018, VA 0xffffffff8ac25ed8, JMP target 0xffffffff8b2dcc70; Evidence ev_ff3e8df1b182e02220ce0dbd4d2551c4a899fc226b91c1d004b6c1d72a265bff */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2dcc70); register/stack arguments unchanged. */

int sub_91cc70(long param_1,undefined8 *param_2)

{
  undefined8 uVar1;
  int iVar2;
  undefined8 uVar3;
  undefined8 *in_GS_OFFSET;
  
  uVar3 = func_0xffffffff8b5c8b50(0x400,0xffffffff8cf11e10,2);
  uVar1 = *param_2;
  func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd1a084,0);
  iVar2 = func_0xffffffff8ac19900(uVar1,uVar3,0x400,0);
  if (iVar2 == 0) {
    iVar2 = func_0xffffffff8afc92d0(*(undefined8 *)(param_1 + 0x140));
    if (iVar2 != 0) {
      iVar2 = func_0xffffffff8b291a30(uVar3,0xffffffff8c1dd4a1,0xc);
      if (iVar2 != 0) {
        func_0xffffffff8b1cd5a0(0xffffffff8bd49e5d,param_1,uVar3,0xffffffff8c1dd4a1);
        iVar2 = 2;
        goto LAB_ffffffff8b2dcd23;
      }
    }
    iVar2 = sub_91c740(param_1,uVar3);
  }
LAB_ffffffff8b2dcd23:
  func_0xffffffff8b5c8df0(uVar3,0xffffffff8cf11e10);
  return iVar2;
}



/* Input +0x020, VA 0xffffffff8ac25ee0, JMP target 0xffffffff8adf8e30; Evidence ev_4cc41713448684d0594ccc69bcaff9fac62572005ddca1bae0ddc764b4812047 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adf8e30); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 handler_body_632(long param_1,long *param_2)

{
  uint uVar1;
  uint uVar2;
  long *plVar3;
  long *plVar4;
  undefined8 uVar5;
  long *plVar6;
  
  if (*param_2 == (long)*(int *)(param_1 + 0x9c)) {
    return 0xb;
  }
  plVar3 = (long *)func_0xffffffff8b552420(*param_2,*(undefined4 *)(*(long *)(param_1 + 8) + 0xbc));
  if (plVar3 == (long *)0x0) {
    return 3;
  }
  func_0xffffffff8ae878b0(plVar3,0,0xffffffff8bcd1b07,0x32f);
  uVar1 = *(uint *)(plVar3 + 0x1d);
  if (((uVar1 & 0x20) == 0) && (uVar2 = *(uint *)((long)plVar3 + 0xe4), -1 < (int)uVar2)) {
    if ((uVar2 & 8) == 0 || (uVar1 & 2) == 0) {
      *(uint *)((long)plVar3 + 0xe4) = uVar2 | 0x80000800;
      if ((int)plVar3[0x80] == 4) {
        func_0xffffffff8b4c35d0(plVar3);
      }
      plVar6 = plVar3 + 1;
      do {
        if ((1 < (int)plVar3[0x80] - 3U) && ((*(byte *)(plVar3 + 0x1d) & 8) == 0))
        goto LAB_ffffffff8adf8fcc;
        func_0xffffffff8ae87520(*plVar3 + 0x18,0,0,0);
        func_0xffffffff8ae86fa0(plVar3[1] + 0x148,0,0,0);
        func_0xffffffff8b5c6830(0xffffffff8bc746cc,_DAT_ffffffff8e2e03d0,0,0x100);
        plVar4 = (long *)func_0xffffffff8b552420((int)*param_2);
        if (plVar4 == (long *)0x0) {
          return 3;
        }
        if (plVar3 != plVar4) {
          plVar6 = plVar4 + 1;
          uVar5 = 3;
          goto LAB_ffffffff8adf9000;
        }
        func_0xffffffff8ae878b0(plVar3,0,0xffffffff8bcd1b07);
      } while (((*(uint *)(plVar3 + 0x1d) & 2) == 0) || ((*(uint *)((long)plVar3 + 0xe4) & 8) == 0))
      ;
      *(uint *)((long)plVar3 + 0xe4) = *(uint *)((long)plVar3 + 0xe4) & 0x7ffff7ff;
      *(undefined4 *)(plVar3 + 0x80) = 1;
      *(uint *)(plVar3 + 0x1d) = *(uint *)(plVar3 + 0x1d) | 0x20;
LAB_ffffffff8adf8fcc:
      uVar5 = 0;
      func_0xffffffff8ae87520(*plVar3 + 0x18,0,0,0);
      goto LAB_ffffffff8adf9000;
    }
    *(undefined4 *)(plVar3 + 0x80) = 1;
    uVar5 = 0;
    *(uint *)(plVar3 + 0x1d) = uVar1 | 0x20;
    func_0xffffffff8ae87520(*plVar3 + 0x18,0,0,0);
  }
  else {
    func_0xffffffff8ae87520(*plVar3 + 0x18,0,0,0);
    uVar5 = 0x16;
  }
  plVar6 = plVar3 + 1;
LAB_ffffffff8adf9000:
  func_0xffffffff8ae86fa0(*plVar6 + 0x148,0,0,0);
  return uVar5;
}



/* Input +0x028, VA 0xffffffff8ac25ee8, JMP target 0xffffffff8adf9070; Evidence ev_cbdcc90163d396e144346a142163cc19e542ef9cc78d2d9f36deaf25b6ca921b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adf9070); register/stack arguments unchanged. */

undefined4 handler_body_633(long param_1,long *param_2)

{
  undefined4 uVar1;
  uint uVar2;
  long *plVar3;
  
  if (*param_2 == (long)*(int *)(param_1 + 0x9c)) {
    return 0x16;
  }
  plVar3 = (long *)func_0xffffffff8b552420(*param_2,*(undefined4 *)(*(long *)(param_1 + 8) + 0xbc));
  if (plVar3 == (long *)0x0) {
    return 3;
  }
  func_0xffffffff8ae878b0(plVar3,0,0xffffffff8bcd1b07,0x36c);
  uVar2 = *(uint *)((long)plVar3 + 0xe4);
  if ((*(uint *)(plVar3 + 0x1d) & 0x20) == 0) {
    uVar1 = 0x16;
    if (-1 < (int)uVar2) goto LAB_ffffffff8adf9112;
LAB_ffffffff8adf9104:
    *(uint *)((long)plVar3 + 0xe4) = uVar2 & 0x7fffffff;
  }
  else {
    if ((int)uVar2 < 0) goto LAB_ffffffff8adf9104;
    uVar2 = *(uint *)(plVar3 + 0x1d) & 0xffffffdf;
    *(uint *)(plVar3 + 0x1d) = uVar2;
    if (uVar2 == 0) {
      *(undefined4 *)(plVar3 + 0x80) = 2;
    }
    func_0xffffffff8b5c6b20(plVar3);
  }
  uVar1 = 0;
LAB_ffffffff8adf9112:
  func_0xffffffff8ae87520(*plVar3 + 0x18,0,0,0);
  func_0xffffffff8ae86fa0(plVar3[1] + 0x148,0,0,0);
  return uVar1;
}



/* Input +0x030, VA 0xffffffff8ac25ef0, JMP target 0xffffffff8adf9150; Evidence ev_d01f48c6d3de85ee2d44311c9e2d6926853483ea9fbcadc5af2ea28add6da6fa */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adf9150); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 handler_body_634(long param_1,undefined4 *param_2)

{
  int iVar1;
  code *pcVar2;
  long *plVar3;
  undefined8 uVar4;
  undefined8 *in_GS_OFFSET;
  undefined1 auStack_538 [64];
  undefined1 auStack_4f8 [1216];
  long lStack_38;
  
  lStack_38 = _DAT_ffffffff8e2dc310;
  plVar3 = (long *)func_0xffffffff8b552420(*param_2,*(undefined4 *)(*(long *)(param_1 + 8) + 0xbc));
  uVar4 = 3;
  if (plVar3 != (long *)0x0) {
    do {
      func_0xffffffff8ae878b0(plVar3,0,0xffffffff8bcd1b07,0x390);
      if ((((*(byte *)(param_1 + 0x529) & 1) == 0) && ((*(byte *)(plVar3 + 0x1d) & 0x20) == 0)) &&
         (-1 < *(int *)((long)plVar3 + 0xe4))) {
        func_0xffffffff8ae87520(*plVar3 + 0x18,0,0,0);
        func_0xffffffff8ae86fa0(plVar3[1] + 0x148,0,0,0);
        uVar4 = 0x16;
        goto LAB_ffffffff8adf9341;
      }
      iVar1 = (int)plVar3[0x80];
      if (2 < iVar1 - 2U) {
        if (iVar1 == 1) {
          func_0xffffffff8ac18ff0(auStack_538,0x500);
          func_0xffffffff8b3cbb60(plVar3,auStack_4f8,0);
          func_0xffffffff8ae87520(*plVar3 + 0x18,0,0,0);
          func_0xffffffff8ae86fa0(plVar3[1] + 0x148,0,0,0);
          uVar4 = *(undefined8 *)(param_2 + 2);
          func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd0f297,0);
          uVar4 = func_0xffffffff8ac191d0(auStack_538,uVar4,0x4c0);
          goto LAB_ffffffff8adf9341;
        }
        if (iVar1 != 0) {
          func_0xffffffff8b1b1950();
          func_0xffffffff8b1b18a0(0xffffffff8adf935c,(int)plVar3[0x80]);
          func_0xffffffff8b65aa10(3,0xffffffff8bcc726f,(int)plVar3[0x80]);
                    /* WARNING: Does not return */
          pcVar2 = (code *)invalidInstructionException();
          (*pcVar2)();
        }
        func_0xffffffff8ae87520(*plVar3 + 0x18,0,0,0);
        func_0xffffffff8ae86fa0(plVar3[1] + 0x148,0,0,0);
        break;
      }
      func_0xffffffff8ae87520(*plVar3 + 0x18,0,0,0);
      func_0xffffffff8ae86fa0(plVar3[1] + 0x148,0,0,0);
      func_0xffffffff8b5c6830(0xffffffff8bc746cc,_DAT_ffffffff8e2e03d0,0,0x100);
      plVar3 = (long *)func_0xffffffff8b552420(*param_2);
    } while (plVar3 != (long *)0x0);
    uVar4 = 3;
  }
LAB_ffffffff8adf9341:
  if (_DAT_ffffffff8e2dc310 != lStack_38) {
    func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
    pcVar2 = (code *)invalidInstructionException();
    (*pcVar2)();
  }
  return uVar4;
}



/* Input +0x038, VA 0xffffffff8ac25ef8, JMP target 0xffffffff8adf93a0; Evidence ev_b1d1f110ab704ed8a66910e3337c8018c772cb489e2603f95289d19d322ec929 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adf93a0); register/stack arguments unchanged. */

undefined8 handler_body_635(void)

{
  return 0x4e;
}



/* Input +0x040, VA 0xffffffff8ac25f00, JMP target 0xffffffff8b07e4d0; Evidence ev_0192932dffa26a12ca79e92367a118daa0294defe98cb7daa2896b09b64f8b05 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b07e4d0); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int handler_body_636(long param_1,undefined8 *param_2)

{
  uint uVar1;
  undefined8 uVar2;
  int iVar3;
  undefined8 *in_GS_OFFSET;
  
  iVar3 = func_0xffffffff8afc8f90(*(undefined8 *)(param_1 + 0x140));
  if (iVar3 == 0) {
    iVar3 = 1;
  }
  else {
    iVar3 = 0x16;
    if (0xfffffdff < *(int *)(param_2 + 1) - 0x201U) {
      func_0xffffffff8b60bb20(0xffffffff8e2d5900,0,0,0);
      uVar1 = *(uint *)(param_2 + 1);
      uVar2 = *param_2;
      func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd57f3d,0);
      iVar3 = func_0xffffffff8ac19280(uVar2,&DAT_ffffffff8e2d5920,(ulong)uVar1 << 4);
      if (iVar3 == 0) {
        _DAT_ffffffff8e2d7920 = *(undefined4 *)(param_2 + 1);
        func_0xffffffff8b35e490(&DAT_ffffffff8e2d5920,_DAT_ffffffff8e2d7920,0x10,0xffffffff8ac2ba00)
        ;
      }
      func_0xffffffff8b60c4b0(0xffffffff8e2d5900,0,0);
    }
  }
  return iVar3;
}



/* Input +0x048, VA 0xffffffff8ac25f08, JMP target 0xffffffff8b47d930; Evidence ev_6aa82b3349c2f857779f1aedcdeabc2121ab1553066296d2ce5c87979c3e258e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b47d930); register/stack arguments unchanged. */

undefined8 handler_body_637(long param_1,int *param_2)

{
  long lVar1;
  int iVar2;
  long lVar3;
  undefined8 uVar4;
  long *in_GS_OFFSET;
  
  if (*(long *)(param_2 + 2) < 0x11) {
    return 0x16;
  }
  if ((*param_2 == 0) || (*param_2 == *(int *)(*(long *)(*in_GS_OFFSET + 8) + 0xbc))) {
    lVar3 = *(long *)(*in_GS_OFFSET + 8);
    func_0xffffffff8ae86a00(lVar3 + 0x148,0,0,0);
  }
  else {
    iVar2 = func_0xffffffff8afc8f90(*(undefined8 *)(param_1 + 0x140));
    if (iVar2 == 0) {
      return 1;
    }
    lVar3 = func_0xffffffff8aefc170(*param_2);
    if (lVar3 == 0) {
      return 3;
    }
  }
  if (((*(uint *)(lVar3 + 0xb0) & 0x2200) == 0) && (*(int *)(lVar3 + 0xb8) == 1)) {
    *(int *)(lVar3 + 0x358) = *(int *)(lVar3 + 0x358) + 1;
    if ((*(uint *)(lVar3 + 0xb0) & 0x10000000) == 0) {
      func_0xffffffff8aefaa10(lVar3);
    }
    uVar4 = 0;
    func_0xffffffff8ae86fa0(lVar3 + 0x148,0,0,0);
    lVar1 = *(long *)(lVar3 + 0x200);
    if (lVar1 != 0) {
      func_0xffffffff8ae86a00(lVar1 + 0x278,0,0,0);
      *(undefined8 *)(lVar1 + 0x280) = *(undefined8 *)(param_2 + 2);
      func_0xffffffff8ae86fa0(lVar1 + 0x278,0,0,0);
      func_0xffffffff8b051c70(lVar1);
    }
    func_0xffffffff8ae86a00(lVar3 + 0x148,0,0,0);
    iVar2 = *(int *)(lVar3 + 0x358) + -1;
    *(int *)(lVar3 + 0x358) = iVar2;
    if ((iVar2 == 0 & *(byte *)(lVar3 + 0xb1) >> 5) == 1) {
      func_0xffffffff8b5c6910(lVar3 + 0x358);
    }
  }
  else {
    uVar4 = 3;
  }
  func_0xffffffff8ae86fa0(lVar3 + 0x148,0,0,0);
  return uVar4;
}



/* Input +0x050, VA 0xffffffff8ac25f10, JMP target 0xffffffff8b07e5c0; Evidence ev_beba8deb3a12b31c1e57ba2d9a1e42d3419b7e51f133ba302cae01f30df352a8 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b07e5c0); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 handler_body_638(undefined8 param_1,long *param_2)

{
  bool bVar1;
  code *pcVar2;
  long lVar3;
  undefined8 uVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  int iVar10;
  undefined8 *in_GS_OFFSET;
  int iStack_44;
  long lStack_40;
  undefined8 uStack_38;
  undefined8 uStack_30;
  long lStack_28;
  
  lStack_28 = _DAT_ffffffff8e2dc310;
  func_0xffffffff8b60b350(0xffffffff8e2d5900,0,0,0);
  if (_DAT_ffffffff8e2d7920 == 0) {
    func_0xffffffff8b60c300(0xffffffff8e2d5900,0,0);
    uVar4 = 0x22;
  }
  else {
    iVar8 = 1;
    if (1 < (int)_DAT_ffffffff8e2d7920) {
      iVar8 = 1;
      uVar6 = _DAT_ffffffff8e2d7920;
      do {
        while (uVar9 = (int)(uVar6 + iVar8) / 2,
              *(long *)(&DAT_ffffffff8e2d5920 + (long)(int)uVar9 * 0x10) <= *param_2) {
          iVar8 = uVar9 + 1;
          if ((int)uVar6 <= iVar8) goto LAB_ffffffff8b07e64f;
        }
        uVar6 = uVar9;
      } while (iVar8 < (int)uVar9);
    }
LAB_ffffffff8b07e64f:
    iStack_44 = 0;
    uStack_38 = *(undefined8 *)((long)iVar8 * 0x10 + -0x71d2a6f0);
    uStack_30 = *(ulong *)((long)iVar8 * 0x10 + -0x71d2a6e8);
    if (-1 < _DAT_ffffffff8e4305b0) {
      uVar6 = iVar8 - 1;
      if (0 < iVar8) {
        iVar7 = 0;
        iVar5 = iVar8;
        do {
          iVar10 = *(int *)((ulong)(iVar5 - 1) * 0x10 + -0x71d2a6d4);
          if (iVar10 != 0) {
            iStack_44 = iVar10;
            if (_DAT_ffffffff8e2d7920 <= uVar6) goto LAB_ffffffff8b07e705;
            goto LAB_ffffffff8b07e6d6;
          }
          iVar7 = iVar7 + 1;
          iVar10 = iVar5 + -1;
          bVar1 = 0 < iVar5;
          iVar5 = iVar10;
        } while (iVar10 != 0 && bVar1);
      }
      iVar7 = 0x201;
      if (uVar6 < _DAT_ffffffff8e2d7920) {
LAB_ffffffff8b07e6d6:
        iVar5 = 0;
        do {
          iVar10 = *(int *)((long)(int)(uVar6 + iVar5) * 0x10 + -0x71d2a6d4);
          if (iVar10 != 0) {
            if (iVar5 < iVar7) {
              iStack_44 = iVar10;
            }
            break;
          }
          iVar5 = iVar5 + 1;
        } while ((_DAT_ffffffff8e2d7920 - iVar8) + 1 != iVar5);
      }
    }
LAB_ffffffff8b07e705:
    func_0xffffffff8b60c300(0xffffffff8e2d5900,0,0);
    if (_DAT_ffffffff8e4305b0 < 0) {
      lVar3 = 0;
      uStack_30 = uStack_30 & 0xffffffff;
    }
    else {
      lVar3 = (long)uStack_30._4_4_;
    }
    lStack_40 = lVar3 + *param_2 + (long)(int)uStack_30;
    lVar3 = param_2[1];
    if (lVar3 != 0) {
      func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd0f297,0);
      uVar4 = func_0xffffffff8ac191d0(&lStack_40,lVar3,8);
      if ((int)uVar4 != 0) goto LAB_ffffffff8b07e7dc;
    }
    lVar3 = param_2[2];
    if (lVar3 != 0) {
      func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd0f297,0);
      uVar4 = func_0xffffffff8ac191d0(&uStack_38,lVar3,0x10);
      if ((int)uVar4 != 0) goto LAB_ffffffff8b07e7dc;
    }
    lVar3 = param_2[3];
    if (lVar3 != 0) {
      func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd0f297,0);
      uVar4 = func_0xffffffff8ac191d0(&iStack_44,lVar3,4);
      if ((int)uVar4 != 0) goto LAB_ffffffff8b07e7dc;
    }
    uVar4 = 0;
  }
LAB_ffffffff8b07e7dc:
  if (_DAT_ffffffff8e2dc310 != lStack_28) {
    func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
    pcVar2 = (code *)invalidInstructionException();
    (*pcVar2)();
  }
  return uVar4;
}



/* Input +0x058, VA 0xffffffff8ac25f18, JMP target 0xffffffff8b07e800; Evidence ev_0299be0325c3e1108d4052967f411df5b831d74aa56f37e136d126999c1fb5f7 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b07e800); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 handler_body_639(undefined8 param_1,long *param_2)

{
  int iVar1;
  int iVar2;
  code *pcVar3;
  undefined8 uVar4;
  bool bVar5;
  ulong uVar6;
  undefined1 *puVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  ulong uVar11;
  long lVar12;
  long lVar13;
  undefined8 *in_GS_OFFSET;
  int iStack_44;
  long lStack_40;
  undefined8 uStack_38;
  undefined8 uStack_30;
  long lStack_28;
  
  lStack_28 = _DAT_ffffffff8e2dc310;
  iStack_44 = 0;
  func_0xffffffff8b60b350(0xffffffff8e2d5900,0,0,0);
  if (_DAT_ffffffff8e2d7920 == 0) {
    func_0xffffffff8b60c300(0xffffffff8e2d5900,0,0);
    uVar4 = 0x22;
  }
  else {
    uVar6 = 1;
    if (1 < (int)_DAT_ffffffff8e2d7920) {
      uVar6 = 1;
      uVar10 = _DAT_ffffffff8e2d7920;
      do {
        while( true ) {
          uVar9 = (int)(uVar10 + (int)uVar6) / 2;
          lVar12 = (long)(int)uVar9 * 0x10;
          if (_DAT_ffffffff8e4305b0 < 0) {
            lVar13 = 0;
          }
          else {
            lVar13 = (long)*(int *)(lVar12 + -0x71d2a6d4);
          }
          if ((long)*(int *)(&DAT_ffffffff8e2d5928 + lVar12) +
              *(long *)(&DAT_ffffffff8e2d5920 + lVar12) + lVar13 <= *param_2) break;
          uVar10 = uVar9;
          if ((int)uVar9 <= (int)uVar6) goto LAB_ffffffff8b07e8cc;
        }
        uVar6 = (ulong)(uVar9 + 1);
      } while ((int)(uVar9 + 1) < (int)uVar10);
    }
LAB_ffffffff8b07e8cc:
    uVar10 = (uint)uVar6;
    uVar9 = uVar10 - 1;
    if (_DAT_ffffffff8e4305b0 < 0) {
      uStack_38 = *(undefined8 *)(&DAT_ffffffff8e2d5920 + (long)(int)uVar9 * 0x10);
      uStack_30 = *(ulong *)(&DAT_ffffffff8e2d5928 + (long)(int)uVar9 * 0x10);
    }
    else {
      iVar1 = (int)param_2[1];
      if ((int)uVar10 < 2 || iVar1 < 0) {
        lVar12 = (long)(int)uVar9 * 0x10;
        uStack_38 = *(undefined8 *)(&DAT_ffffffff8e2d5920 + lVar12);
        puVar7 = &DAT_ffffffff8e2d5920 + lVar12;
        uStack_30 = *(ulong *)(&DAT_ffffffff8e2d5928 + lVar12);
        goto joined_r0xffffffff8b07e9cb;
      }
      uVar11 = (ulong)uVar9;
      uVar10 = uVar10 - 2;
      iVar2 = *(int *)((ulong)uVar10 * 0x10 + -0x71d2a6d4);
      if (*param_2 <
          (long)*(int *)(&DAT_ffffffff8e2d5928 + (ulong)uVar10 * 0x10) +
          *(long *)(&DAT_ffffffff8e2d5920 + uVar11 * 0x10) + (long)iVar2) {
        uVar8 = uVar9;
        if (iVar2 == 0 && iVar1 == 0) {
          uVar8 = uVar10;
        }
        if (iVar2 < 1) {
          uVar10 = uVar8;
        }
        if (iVar1 == 0) {
          uVar10 = uVar8;
        }
        uVar11 = (ulong)uVar10;
      }
      lVar12 = uVar11 * 0x10;
      uStack_38 = *(undefined8 *)(&DAT_ffffffff8e2d5920 + lVar12);
      puVar7 = &DAT_ffffffff8e2d5920 + lVar12;
      uStack_30 = *(ulong *)(&DAT_ffffffff8e2d5928 + lVar12);
      do {
        uVar10 = (int)uVar6 - 1;
        uVar6 = (ulong)uVar10;
        iStack_44 = *(int *)(uVar6 * 0x10 + -0x71d2a6d4);
        if (iStack_44 != 0) {
          bVar5 = (int)uVar9 <= (int)uVar10;
          goto joined_r0xffffffff8b07ea0a;
        }
joined_r0xffffffff8b07e9cb:
      } while (0 < (int)uVar10);
      iStack_44 = 0;
      bVar5 = false;
joined_r0xffffffff8b07ea0a:
      if ((uVar9 < _DAT_ffffffff8e2d7920) && (*(int *)(puVar7 + 0xc) != 0 && !bVar5)) {
        iStack_44 = *(int *)(puVar7 + 0xc);
      }
    }
    func_0xffffffff8b60c300(0xffffffff8e2d5900,0,0);
    if (_DAT_ffffffff8e4305b0 < 0) {
      lVar12 = 0;
      uStack_30 = uStack_30 & 0xffffffff;
    }
    else {
      lVar12 = (long)uStack_30._4_4_;
    }
    lStack_40 = *param_2 - ((int)uStack_30 + lVar12);
    lVar12 = param_2[2];
    if (lVar12 != 0) {
      func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd0f297,0);
      uVar4 = func_0xffffffff8ac191d0(&lStack_40,lVar12,8);
      if ((int)uVar4 != 0) goto LAB_ffffffff8b07eaf8;
    }
    lVar12 = param_2[3];
    if (lVar12 != 0) {
      func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd0f297,0);
      uVar4 = func_0xffffffff8ac191d0(&uStack_38,lVar12,0x10);
      if ((int)uVar4 != 0) goto LAB_ffffffff8b07eaf8;
    }
    lVar12 = param_2[4];
    if (lVar12 != 0) {
      func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd0f297,0);
      uVar4 = func_0xffffffff8ac191d0(&iStack_44,lVar12,4);
      if ((int)uVar4 != 0) goto LAB_ffffffff8b07eaf8;
    }
    uVar4 = 0;
  }
LAB_ffffffff8b07eaf8:
  if (_DAT_ffffffff8e2dc310 == lStack_28) {
    return uVar4;
  }
  func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
  pcVar3 = (code *)invalidInstructionException();
  (*pcVar3)();
}



/* Input +0x060, VA 0xffffffff8ac25f20, JMP target 0xffffffff8b450e10; Evidence ev_c3986da2e65569d0901749cad39df4022f7c785201fc76a778d29e94bc389464 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b450e10); register/stack arguments unchanged. */

undefined8 handler_body_640(void)

{
  return 0;
}



/* Input +0x068, VA 0xffffffff8ac25f28, JMP target 0xffffffff8ae62de0; Evidence ev_e5b84a8edadcaee334cef5790cf4ccb76eb5ffb72bba7ca6dff0722a415ea2d3 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae62de0); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 handler_body_641(long param_1,undefined4 *param_2)

{
  code *pcVar1;
  long lVar2;
  int iVar3;
  long lVar4;
  long *plVar5;
  ulong uVar6;
  undefined8 uVar7;
  undefined8 *in_GS_OFFSET;
  long lStack_100;
  ulong uStack_f8;
  long lStack_f0;
  ulong uStack_e8;
  undefined4 uStack_70;
  undefined4 uStack_6c;
  long lStack_68;
  ulong uStack_60;
  long lStack_58;
  ulong uStack_50;
  ulong uStack_48;
  ulong uStack_40;
  long lStack_38;
  
  lStack_38 = _DAT_ffffffff8e2dc310;
  iVar3 = func_0xffffffff8afc8f90(*(undefined8 *)(param_1 + 0x140));
  if (iVar3 == 0) {
    uVar7 = 0x4e;
  }
  else {
    sub_4a2ce0();
    func_0xffffffff8ac18ff0(&uStack_70,0x38);
    lVar4 = func_0xffffffff8aefc170(*param_2);
    if (lVar4 == 0) {
      lVar4 = *(long *)(param_1 + 8);
      plVar5 = (long *)func_0xffffffff8b552420(*param_2,*(undefined4 *)(lVar4 + 0xbc));
      if (plVar5 != (long *)0x0) {
        func_0xffffffff8ae87190(lVar4 + 0x168,0,0,0);
        func_0xffffffff8ae878b0(plVar5,0,0xffffffff8bc6a1cd,0x68b);
        func_0xffffffff8ae61a20(plVar5,&lStack_100);
        func_0xffffffff8ae87520(*plVar5 + 0x18,0,0,0);
        uStack_60 = uStack_f8;
        lStack_68 = lStack_100;
        uStack_50 = uStack_e8;
        lStack_58 = lStack_f0;
        uVar6 = func_0xffffffff8b4909c0(*(undefined8 *)(lVar4 + 0x2c0));
        func_0xffffffff8ae87520(lVar4 + 0x168,0,0,0);
        uStack_48 = uVar6 / 1000000;
        uStack_40 = uVar6 % 1000000;
        func_0xffffffff8ae86fa0(lVar4 + 0x148,0,0,0);
        uStack_70 = *(undefined4 *)(lVar4 + 0xbc);
        uStack_6c = *param_2;
        uVar7 = *(undefined8 *)(param_2 + 2);
        func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd0f297,0);
        uVar7 = func_0xffffffff8ac191d0(&uStack_70,uVar7,0x38);
        goto LAB_ffffffff8ae63176;
      }
    }
    else {
      if (*(int *)(lVar4 + 0xb8) == 1) {
        func_0xffffffff8ae87190(lVar4 + 0x168,0,0,0);
        for (plVar5 = *(long **)(lVar4 + 0x10); plVar5 != (long *)0x0; plVar5 = (long *)plVar5[2]) {
          func_0xffffffff8ae878b0(plVar5,0,0xffffffff8bc6a1cd,0x6a8);
          func_0xffffffff8ae61a20(plVar5);
          func_0xffffffff8ae87520(*plVar5 + 0x18,0,0,0);
          uStack_60 = uStack_60 + uStack_f8;
          lVar2 = lStack_100;
          if (999999 < (long)uStack_60) {
            uStack_60 = uStack_60 % 1000000;
            lVar2 = lStack_100 + 1;
          }
          lStack_68 = lVar2 + lStack_68;
          uStack_50 = uStack_50 + uStack_e8;
          lVar2 = lStack_f0;
          if (999999 < (long)uStack_50) {
            uStack_50 = uStack_50 % 1000000;
            lVar2 = lStack_f0 + 1;
          }
          lStack_58 = lStack_58 + lVar2;
        }
        uVar6 = func_0xffffffff8b4909c0(*(undefined8 *)(lVar4 + 0x2c0));
        func_0xffffffff8ae87520(lVar4 + 0x168,0,0,0);
        uStack_48 = uVar6 / 1000000;
        uStack_40 = uVar6 % 1000000;
        func_0xffffffff8ae86fa0(lVar4 + 0x148,0,0,0);
        uStack_70 = *param_2;
        uVar7 = *(undefined8 *)(param_2 + 2);
        func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd0f297,0);
        uVar7 = func_0xffffffff8ac191d0(&uStack_70,uVar7,0x38);
        goto LAB_ffffffff8ae63176;
      }
      func_0xffffffff8ae86fa0(lVar4 + 0x148,0,0,0);
    }
    uVar7 = 3;
  }
LAB_ffffffff8ae63176:
  if (_DAT_ffffffff8e2dc310 == lStack_38) {
    return uVar7;
  }
  func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* Input +0x070, VA 0xffffffff8ac25f30, JMP target 0xffffffff8b47dad0; Evidence ev_4798e6510b262229d89aad676f279b5d008601981fab7469c7985c4d7b8b526c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b47dad0); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong handler_body_642(long param_1,undefined4 *param_2)

{
  long lVar1;
  char cVar2;
  long lVar3;
  long lVar4;
  long lVar5;
  long lVar6;
  undefined8 uVar7;
  code *pcVar8;
  int iVar9;
  uint uVar10;
  int iVar11;
  long lVar12;
  ulong uVar13;
  long lVar14;
  long lVar15;
  long lVar16;
  long lVar17;
  long lVar18;
  ulong uVar19;
  undefined8 *in_GS_OFFSET;
  int iStack_a4;
  undefined1 auStack_a0 [32];
  undefined8 uStack_80;
  undefined8 uStack_78;
  long lStack_70;
  uint uStack_68;
  undefined4 uStack_64;
  undefined4 uStack_60;
  int iStack_5c;
  uint uStack_58;
  undefined8 uStack_54;
  undefined8 uStack_4c;
  undefined8 uStack_44;
  int iStack_3c;
  long lStack_38;
  
  lStack_38 = _DAT_ffffffff8e2dc310;
  iVar9 = func_0xffffffff8afc8f90(*(undefined8 *)(param_1 + 0x140));
  if (iVar9 == 0) {
    uVar13 = 1;
  }
  else {
    lVar12 = func_0xffffffff8aefc170(*param_2);
    uVar13 = 2;
    if (lVar12 != 0) {
      if ((*(uint *)(lVar12 + 0xb0) & 0x2000) == 0) {
        *(int *)(lVar12 + 0x358) = *(int *)(lVar12 + 0x358) + 1;
        if ((*(uint *)(lVar12 + 0xb0) & 0x10000000) == 0) {
          func_0xffffffff8aefaa10(lVar12);
        }
        lVar1 = lVar12 + 0x148;
        func_0xffffffff8ae86fa0(lVar1,0,0,0);
        lVar3 = *(long *)(lVar12 + 0x200);
        func_0xffffffff8ac86820(lVar3,0,0);
        iStack_a4 = 0;
        func_0xffffffff8ac18ff0(auStack_a0,0x68);
        for (lVar4 = *(long *)(lVar3 + 8); lVar4 != lVar3; lVar4 = *(long *)(lVar4 + 8)) {
          if ((*(short *)(lVar4 + 0x66) != 0) && ((*(byte *)(lVar4 + 0x60) & 2) == 0)) {
            lVar5 = *(long *)(lVar4 + 0x50);
            uStack_68 = (uint)*(ushort *)(lVar4 + 100);
            uVar10 = *(uint *)(lVar4 + 0x60);
            if ((uVar10 & 0x20) != 0) {
              uStack_68 = uStack_68 | 0x10000;
              uVar10 = *(uint *)(lVar4 + 0x60);
            }
            if ((uVar10 & 0x1000) != 0) {
              uStack_68 = uStack_68 | 0x20000;
            }
            uStack_80 = *(undefined8 *)(lVar4 + 0x20);
            uStack_78 = *(undefined8 *)(lVar4 + 0x28);
            if ((lVar5 == 0) ||
               (((*(byte *)(lVar5 + 0x9d) < 0xb &&
                 ((0x587U >> (*(byte *)(lVar5 + 0x9d) & 0x1f) & 1) != 0)) &&
                ((*(byte *)(lVar5 + 0xa2) & 1) == 0)))) {
              if (*(short *)(lVar4 + 0x66) == 0) {
                iStack_3c = 0;
              }
              else {
                iStack_3c = (int)*(char *)(lVar4 + 0x14c);
              }
              if (lVar5 != 0) goto LAB_ffffffff8b47dc7a;
              func_0xffffffff8ac18ff0(auStack_a0,0x68);
            }
            else {
              iStack_3c = 0;
LAB_ffffffff8b47dc7a:
              lVar18 = lVar5 + 0x18;
              func_0xffffffff8b1946a0(lVar18,0,0);
              if ((byte)(*(char *)(lVar5 + 0x9d) - 3U) < 2) {
                func_0xffffffff8b194eb0(lVar18,0,0);
                goto LAB_ffffffff8b47dbd0;
              }
              uStack_64 = *(undefined4 *)(lVar5 + 0x130);
              uStack_60 = *(undefined4 *)(lVar5 + 0x138);
              iVar9 = 0;
              func_0xffffffff8b194eb0(lVar18,0,0);
              uVar13 = *(ulong *)(lVar4 + 0x20) & 0xffffffffffffc000;
              uVar19 = *(long *)(lVar4 + 0x28) + 0x3fffU & 0xffffffffffffc000;
              if (uVar13 < uVar19) {
                iVar9 = 0;
                do {
                  lVar14 = func_0xffffffff8b29e3e0(*(undefined8 *)(lVar3 + 0x1d8),uVar13);
                  iVar9 = (iVar9 + 1) - (uint)(lVar14 == 0);
                  uVar13 = uVar13 + 0x4000;
                } while (uVar13 < uVar19);
              }
              lStack_70 = (long)(int)((uint)lVar5 ^ 0x8e5b6e18);
              uStack_58 = (uint)*(byte *)(lVar5 + 0x9d);
              uStack_54 = 0;
              uStack_4c = 0;
              uStack_44 = 0;
              uVar10 = (uint)((ulong)(*(long *)(lVar4 + 0x28) - *(long *)(lVar4 + 0x20)) >> 0xe);
              iStack_5c = iVar9;
              if (0 < (int)uVar10) {
                uVar13 = 0;
LAB_ffffffff8b47ddd8:
                lVar14 = *(long *)(lVar4 + 0x58);
                lVar17 = (long)((int)uVar13 << 0xe);
                func_0xffffffff8b1946a0(lVar18,0,0);
                lVar15 = func_0xffffffff8b5497e0(lVar5);
                lVar16 = lVar5;
                while (lVar15 == 0) {
                  lVar6 = *(long *)(lVar16 + 0xb0);
                  if (lVar6 == 0) {
                    func_0xffffffff8b194eb0(lVar16 + 0x18,0,0);
                    lVar14 = *(long *)(lVar4 + 0x58);
                    func_0xffffffff8b1946a0(lVar18,0,0);
                    cVar2 = *(char *)(lVar5 + 0x9d);
                    lVar16 = lVar5;
                    goto joined_r0xffffffff8b47df6d;
                  }
                  lVar14 = lVar14 + *(long *)(lVar16 + 0xb8);
                  func_0xffffffff8b1946a0(lVar6 + 0x18,0,0);
                  func_0xffffffff8b194eb0(lVar16 + 0x18,0,0);
                  lVar15 = func_0xffffffff8b5497e0(lVar6);
                  lVar16 = lVar6;
                }
                func_0xffffffff8b54d8a0(lVar15);
                if (*(int *)(lVar15 + 0x70) == 0) {
                  uStack_4c = CONCAT44(uStack_4c._4_4_ + 1,(int)uStack_4c);
                  cVar2 = *(char *)(lVar15 + 0x66);
                }
                else {
                  uStack_4c = CONCAT44(uStack_4c._4_4_,(int)uStack_4c + 1);
                  cVar2 = *(char *)(lVar15 + 0x66);
                }
                if (cVar2 == '\x01') {
                  uStack_44 = CONCAT44(uStack_44._4_4_,(int)uStack_44 + 1);
                }
                if (*(int *)(lVar15 + 0x70) == 0) {
                  if ((*(long *)(lVar15 + 0x20) == 0) ||
                     (*(char *)(*(long *)(lVar15 + 0x20) + 0x9d) == '\0')) {
LAB_ffffffff8b47dda0:
                    uStack_44 = CONCAT44(uStack_44._4_4_ + 1,(int)uStack_44);
                  }
                  else if (*(char *)(lVar16 + 0x9d) == '\x01') {
                    pcVar8 = *(code **)(_DAT_ffffffff8c483918 + 0x38);
                    if (0xd < (-(long)pcVar8 - 0x753d47b8U >> 3 | -(long)pcVar8 << 0x3d)) {
                      func_0xffffffff8ae0f8c0(0xffffffff8d248d60,pcVar8);
                    }
                    iVar9 = (*pcVar8)(lVar16,lVar14 + lVar17 >> 0xe,0);
                    if (iVar9 == 0) goto LAB_ffffffff8b47dda0;
                  }
                }
                goto LAB_ffffffff8b47dda3;
              }
            }
LAB_ffffffff8b47e03b:
            func_0xffffffff8b317b70(auStack_a0,lVar4 + 0x150,0x20);
            iVar9 = iStack_a4;
            lVar18 = (long)iStack_a4;
            lVar5 = *(long *)(param_2 + 4);
            if ((lVar5 != 0) && (iStack_a4 < (int)param_2[2])) {
              func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd0f297,0);
              iVar11 = func_0xffffffff8ac191d0(auStack_a0,lVar5 + lVar18 * 0x68,0x68);
              if (iVar11 != 0) break;
            }
            iStack_a4 = iVar9 + 1;
          }
LAB_ffffffff8b47dbd0:
        }
        func_0xffffffff8ac86870(lVar3,0,0);
        func_0xffffffff8ae86a00(lVar1,0,0,0);
        iVar9 = *(int *)(lVar12 + 0x358) + -1;
        *(int *)(lVar12 + 0x358) = iVar9;
        if ((iVar9 == 0 & *(byte *)(lVar12 + 0xb1) >> 5) == 1) {
          func_0xffffffff8b5c6910(lVar12 + 0x358);
        }
        func_0xffffffff8ae86fa0(lVar1,0,0,0);
        uVar7 = *(undefined8 *)(param_2 + 6);
        func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd0f297,0);
        uVar13 = func_0xffffffff8ac191d0(&iStack_a4,uVar7,4);
        if ((*(long *)(param_2 + 4) != 0) &&
           (uVar13 = uVar13 & 0xffffffff, (int)param_2[2] < iStack_a4)) {
          uVar13 = 0xc;
        }
      }
      else {
        func_0xffffffff8ae86fa0(lVar12 + 0x148,0,0,0);
        uVar13 = 2;
      }
    }
  }
  if (_DAT_ffffffff8e2dc310 == lStack_38) {
    return uVar13;
  }
  func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
  pcVar8 = (code *)invalidInstructionException();
  (*pcVar8)();
joined_r0xffffffff8b47df6d:
  if (cVar2 == '\x01') {
    pcVar8 = *(code **)(_DAT_ffffffff8c483918 + 0x38);
    if (0xd < (-(long)pcVar8 - 0x753d47b8U >> 3 | -(long)pcVar8 << 0x3d)) {
      func_0xffffffff8ae0f8c0(0xffffffff8d248d60,pcVar8);
    }
    iVar9 = (*pcVar8)(lVar16,lVar14 + lVar17 >> 0xe,0,0);
    if (iVar9 != 0) {
      uStack_54 = CONCAT44(uStack_54._4_4_ + 1,(int)uStack_54);
      goto LAB_ffffffff8b47dda3;
    }
  }
  lVar15 = *(long *)(lVar16 + 0xb0);
  if (lVar15 == 0) goto LAB_ffffffff8b47e006;
  lVar14 = lVar14 + *(long *)(lVar16 + 0xb8);
  func_0xffffffff8b1946a0(lVar15 + 0x18,0,0);
  func_0xffffffff8b194eb0(lVar16 + 0x18,0,0);
  cVar2 = *(char *)(lVar15 + 0x9d);
  lVar16 = lVar15;
  goto joined_r0xffffffff8b47df6d;
LAB_ffffffff8b47e006:
  uStack_54 = CONCAT44(uStack_54._4_4_,(int)uStack_54 + 1);
LAB_ffffffff8b47dda3:
  func_0xffffffff8b194eb0(lVar16 + 0x18,0,0);
  uVar13 = uVar13 + 1;
  if (uVar13 == (uVar10 & 0x7fffffff)) goto LAB_ffffffff8b47e03b;
  goto LAB_ffffffff8b47ddd8;
}



/* Input +0x078, VA 0xffffffff8ac25f38, JMP target 0xffffffff8b3f7660; Evidence ev_3d64cd7693bd60b6d49fecc718bd44be424ba54896cbfc279083e6b20ed40ba3 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3f7660); register/stack arguments unchanged. */

undefined8 sub_a37660(long param_1,uint *param_2)

{
  uint *puVar1;
  
  func_0xffffffff8ac1d410(0xffffffff8bd218e2,*param_2);
  puVar1 = (uint *)(*(long *)(param_1 + 8) + 0xa34);
  *puVar1 = *puVar1 | *param_2;
  return 0;
}



/* Input +0x080, VA 0xffffffff8ac25f40, JMP target 0xffffffff8b47e1c0; Evidence ev_27504ee7e498f06cfe34f87692bdf35f1daeadd868161c6274c80a01a8271efd */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b47e1c0); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_abe1c0(long param_1,undefined8 *param_2)

{
  code *pcVar1;
  int iVar2;
  undefined8 uVar3;
  undefined8 *in_GS_OFFSET;
  undefined1 auStack_420 [1016];
  long lStack_28;
  
  lStack_28 = _DAT_ffffffff8e2dc310;
  iVar2 = func_0xffffffff8afc8f90(*(undefined8 *)(param_1 + 0x140));
  if (iVar2 == 0) {
    uVar3 = 1;
  }
  else {
    func_0xffffffff8ac18ff0(auStack_420,0x3f8);
    uVar3 = *param_2;
    func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd0f297,0);
    uVar3 = func_0xffffffff8ac191d0(auStack_420,uVar3,0x3f8);
  }
  if (_DAT_ffffffff8e2dc310 == lStack_28) {
    return uVar3;
  }
  func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* Input +0x088, VA 0xffffffff8ac25f48, JMP target 0xffffffff8b47e7b0; Evidence ev_bd87842d69d96b63f1ac4c984344aff2373c4de6e92ec72bd13d8ac6e7935638 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b47e7b0); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_abe7b0(long param_1,undefined8 *param_2)

{
  code *pcVar1;
  int iVar2;
  undefined8 uVar3;
  int iStack_2c;
  long lStack_28;
  
  lStack_28 = _DAT_ffffffff8e2dc310;
  iVar2 = func_0xffffffff8afc8f90(*(undefined8 *)(param_1 + 0x140));
  if (iVar2 == 0) {
    uVar3 = 1;
  }
  else {
    iStack_2c = 0;
    uVar3 = sub_abe260(param_1,*param_2,4,&iStack_2c);
    *(long *)(param_1 + 0x408) = (long)iStack_2c;
  }
  if (_DAT_ffffffff8e2dc310 == lStack_28) {
    return uVar3;
  }
  func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* Input +0x090, VA 0xffffffff8ac25f50, JMP target 0xffffffff8b3b81f0; Evidence ev_38992dca2ddd1724dbfdec81bda48eef81258e5e6e19df10401dc8ffe8e78ff4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3b81f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3b81f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x098, VA 0xffffffff8ac25f58, JMP target 0xffffffff8b5a9510; Evidence ev_805e775aea09c7b3d7796ebdbf845026670e35d7bd3812145500f0480286b2ea */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b5a9510); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b5a9510(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x0a0, VA 0xffffffff8ac25f60, JMP target 0xffffffff8b367d10; Evidence ev_f62ff92f01a09e3e75cccb36812c734d0907271222e1acb231f8c2b0496784af */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b367d10); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b367d10(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x0a8, VA 0xffffffff8ac25f68, JMP target 0xffffffff8b369560; Evidence ev_f5b773809125f55f42a2908ea0b18de9e44a208a0a0abbb4864a260929e2f67e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b369560); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b369560(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x0b0, VA 0xffffffff8ac25f70, JMP target 0xffffffff8b369e10; Evidence ev_f698b27e379b94822718be1627289b1544a91dce16110d51fe8bbfde94fb3b4c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b369e10); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b369e10(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x0b8, VA 0xffffffff8ac25f78, JMP target 0xffffffff8b369f40; Evidence ev_2ec1a1251dc535563b19eb28de190b91f4c9683eb251d6eed5e6269bd2db9650 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b369f40); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b369f40(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x0c0, VA 0xffffffff8ac25f80, JMP target 0xffffffff8b2bb440; Evidence ev_fc4bd21907bbcde63d0427cff66be0c481210d3ccf79fb56a3b148aa5cd389e1 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2bb440); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2bb440(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x0c8, VA 0xffffffff8ac25f88, JMP target 0xffffffff8ae631a0; Evidence ev_91fa8140a29e7ac607865a8f1f043ea86a2fad8b51a7dccefac62381f91963f4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae631a0); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_4a31a0(long param_1,long *param_2)

{
  code *pcVar1;
  long lVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  long *plVar8;
  long *plVar9;
  ulong uVar10;
  long *plVar11;
  int iStack_7c;
  long lStack_78;
  ulong uStack_70;
  long *plStack_68;
  undefined4 uStack_60;
  undefined8 uStack_58;
  ulong uStack_50;
  undefined8 uStack_48;
  long lStack_40;
  long lStack_38;
  
  lStack_38 = _DAT_ffffffff8e2dc310;
  iVar3 = func_0xffffffff8afc8f90(*(undefined8 *)(param_1 + 0x140));
  if (iVar3 == 0) {
    iVar3 = 0x4e;
    goto LAB_ffffffff8ae63602;
  }
  if (*param_2 == 0) {
    iVar5 = 0;
    func_0xffffffff8b60b350(0xffffffff8df49e60,0,0,0);
    if (_DAT_ffffffff8df49e80 != (long *)0x0) {
      iVar5 = 0;
      plVar11 = _DAT_ffffffff8df49e80;
      do {
        func_0xffffffff8ae86a00(plVar11 + 0x29,0,0,0);
        if ((1 < *(uint *)(plVar11 + 0xba)) && ((int)plVar11[0x17] == 1)) {
          for (plVar8 = (long *)plVar11[2]; plVar8 != (long *)0x0; plVar8 = (long *)plVar8[2]) {
            func_0xffffffff8ae878b0(plVar8,0,0xffffffff8bc6a1cd);
            if ((plVar8[0xb6] != 0) || (plVar8[0xb8] != 0)) {
              iVar5 = iVar5 + 1;
            }
            func_0xffffffff8ae87520(*plVar8 + 0x18,0,0);
          }
        }
        func_0xffffffff8ae86fa0(plVar11 + 0x29,0,0);
        plVar11 = (long *)*plVar11;
      } while (plVar11 != (long *)0x0);
    }
    func_0xffffffff8b60c300(0xffffffff8df49e60,0,0);
  }
  else {
    iVar4 = func_0xffffffff8b142a40(param_2[1]);
    if (iVar4 == -1) {
      iVar3 = 0xe;
      goto LAB_ffffffff8ae63602;
    }
    iVar3 = 0x16;
    if (iVar4 - 0x2711U < 0xffffd8f0) goto LAB_ffffffff8ae63602;
    lStack_78 = *param_2;
    iVar5 = 0;
    uStack_70 = (ulong)(uint)(iVar4 * 0x28);
    plStack_68 = &lStack_78;
    uStack_60 = 1;
    uStack_58 = 0;
    uStack_48 = 0;
    uStack_50 = uStack_70;
    lStack_40 = param_1;
    func_0xffffffff8b60b350(0xffffffff8df49e60,0,0,0);
    if (_DAT_ffffffff8df49e80 != (long *)0x0) {
      iVar5 = 0;
      plVar11 = _DAT_ffffffff8df49e80;
      do {
        plVar8 = plVar11 + 0x29;
        func_0xffffffff8ae86a00(plVar8,0,0,0);
        if ((1 < *(uint *)(plVar11 + 0xba)) && ((int)plVar11[0x17] == 1)) {
LAB_ffffffff8ae632da:
          lVar2 = plVar11[0x169];
          func_0xffffffff8ae86fa0(plVar8,0,0);
          puVar6 = (undefined4 *)
                   func_0xffffffff8b5c8b50((long)(int)lVar2 * 0x28,0xffffffff8c488120,0x102);
          func_0xffffffff8ae86a00(plVar8,0,0,0);
          if ((int)lVar2 < (int)plVar11[0x169]) goto code_r0xffffffff8ae63321;
          func_0xffffffff8ae87190(plVar11 + 7,0,0);
          plVar9 = (long *)plVar11[2];
          if (plVar9 == (long *)0x0) {
            uVar10 = 0;
          }
          else {
            iStack_7c = 0;
            puVar7 = puVar6;
            do {
              func_0xffffffff8ae878b0(plVar9,0,0xffffffff8bc6a1cd);
              if ((plVar9[0xb6] == 0) && (plVar9[0xb8] == 0)) {
                func_0xffffffff8ae87520(*plVar9 + 0x18,0,0);
              }
              else {
                *puVar7 = *(undefined4 *)((long)plVar11 + 0xbc);
                puVar7[1] = *(undefined4 *)((long)plVar9 + 0x9c);
                *(long *)(puVar7 + 2) = plVar9[0xb6];
                *(long *)(puVar7 + 4) = plVar9[0xb7];
                *(long *)(puVar7 + 6) = plVar9[0xb8];
                *(long *)(puVar7 + 8) = plVar9[0xb9];
                func_0xffffffff8ae87520(*plVar9 + 0x18,0,0);
                iStack_7c = iStack_7c + 1;
                puVar7 = puVar7 + 10;
                iVar5 = iVar5 + 1;
              }
              plVar9 = (long *)plVar9[2];
            } while (plVar9 != (long *)0x0);
            uVar10 = (long)iStack_7c * 0x28;
          }
          func_0xffffffff8ae87520(plVar11 + 7,0,0);
          func_0xffffffff8ae86fa0(plVar8,0,0);
          if (uStack_50 < uVar10) {
            uVar10 = uStack_50;
          }
          iVar3 = func_0xffffffff8b142520(puVar6,uVar10 & 0xffffffff,&plStack_68);
          func_0xffffffff8b5c8df0(puVar6);
          if (iVar3 != 0) {
            func_0xffffffff8b60c300(0xffffffff8df49e60,0,0);
            goto LAB_ffffffff8ae63602;
          }
          goto LAB_ffffffff8ae6329e;
        }
LAB_ffffffff8ae63290:
        func_0xffffffff8ae86fa0(plVar8,0,0);
LAB_ffffffff8ae6329e:
        plVar11 = (long *)*plVar11;
      } while (plVar11 != (long *)0x0);
    }
    func_0xffffffff8b60c300(0xffffffff8df49e60,0,0);
  }
  iVar5 = func_0xffffffff8ac19790(param_2[1],iVar5);
  iVar3 = 0xe;
  if (iVar5 == 0) {
    iVar3 = 0;
  }
LAB_ffffffff8ae63602:
  if (_DAT_ffffffff8e2dc310 != lStack_38) {
    func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
    pcVar1 = (code *)invalidInstructionException();
    (*pcVar1)();
  }
  return iVar3;
code_r0xffffffff8ae63321:
  func_0xffffffff8ae86fa0(plVar8,0,0);
  func_0xffffffff8b5c8df0(puVar6);
  func_0xffffffff8ae86a00(plVar8,0,0,0);
  if ((int)plVar11[0x17] != 1) goto LAB_ffffffff8ae63290;
  goto LAB_ffffffff8ae632da;
}



/* Input +0x0d0, VA 0xffffffff8ac25f90, JMP target 0xffffffff8b47e8b0; Evidence ev_dd831ee0d272d67af73c859afc89e869a2308fcb242cd2934e430f03f5443c8d */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b47e8b0); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_abe8b0(long param_1,uint *param_2)

{
  uint uVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  code *pcVar4;
  int iVar5;
  undefined8 uVar6;
  uint uVar7;
  long *in_GS_OFFSET;
  uint uStack_40;
  uint uStack_3c;
  long lStack_38;
  
  lStack_38 = _DAT_ffffffff8e2dc310;
  uVar2 = *(undefined8 *)(param_2 + 6);
  uVar7 = *param_2;
  uVar1 = param_2[2];
  uVar3 = *(undefined8 *)(param_2 + 4);
  iVar5 = func_0xffffffff8b48c9a0(0);
  if ((iVar5 != 0) || (uVar6 = 2, 0x4ffffff < *(uint *)(*(long *)(*in_GS_OFFSET + 8) + 0x5d4))) {
    if (uVar7 == 0xffffffff) {
      uVar7 = *(uint *)(*(long *)(param_1 + 8) + 0x5c0);
    }
    else {
      iVar5 = func_0xffffffff8afc8f90(*(undefined8 *)(param_1 + 0x140));
      if (iVar5 == 0) {
        uVar6 = 1;
        goto LAB_ffffffff8b47e9f8;
      }
    }
    uVar6 = 0x16;
    if (uVar7 < 0xb) {
      if (uVar1 == 2) {
        func_0xffffffff8b3a3650(uVar7,&uStack_3c,&uStack_40);
        if ((*(byte *)(*(long *)(*(long *)(param_1 + 8) + 0x200) + 0x244) & 2) != 0) {
          uVar7 = uStack_3c + 3;
          if (-1 < (int)uStack_3c) {
            uVar7 = uStack_3c;
          }
          uStack_3c = (int)uVar7 >> 2;
          uVar7 = uStack_40 + 3;
          if (-1 < (int)uStack_40) {
            uVar7 = uStack_40;
          }
          uStack_40 = (int)uVar7 >> 2;
        }
      }
      else {
        if (uVar1 != 1) goto LAB_ffffffff8b47e9f8;
        func_0xffffffff8b2ad4e0(uVar7,&uStack_3c,&uStack_40);
      }
      iVar5 = func_0xffffffff8ac19790(uVar3,~((int)uStack_3c >> 0x1f) & uStack_3c);
      if (iVar5 == -1) {
        uVar6 = 0xe;
      }
      else {
        iVar5 = func_0xffffffff8ac19790(uVar2,~((int)uStack_40 >> 0x1f) & uStack_40);
        uVar6 = 0xe;
        if (iVar5 != -1) {
          uVar6 = 0;
        }
      }
    }
  }
LAB_ffffffff8b47e9f8:
  if (_DAT_ffffffff8e2dc310 != lStack_38) {
    func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
    pcVar4 = (code *)invalidInstructionException();
    (*pcVar4)();
  }
  return uVar6;
}



/* Input +0x0d8, VA 0xffffffff8ac25f98, JMP target 0xffffffff8b36b1f0; Evidence ev_72f4da5b8bd5b72a5862e5b2be4fec520113628f5a8afdd9f51c33ffa8bb3f99 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b36b1f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b36b1f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x0e0, VA 0xffffffff8ac25fa0, JMP target 0xffffffff8b47b980; Evidence ev_216fd71d36ba58686d8ce8b86c578045450d8b9dac37c7d4e37bce87df3d2167 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b47b980); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b47b980(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x0e8, VA 0xffffffff8ac25fa8, JMP target 0xffffffff8b0b92e0; Evidence ev_82acdf71e9e6899e004a426a2141a8776e856f82f6bf71e75144b2de76a05261 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0b92e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0b92e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x0f0, VA 0xffffffff8ac25fb0, JMP target 0xffffffff8adf4da0; Evidence ev_5761db143391b671ba6ab7b241cd61409b0afc0f64ddc42c3cfc9d3be6d428be */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adf4da0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8adf4da0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x0f8, VA 0xffffffff8ac25fb8, JMP target 0xffffffff8adf4db0; Evidence ev_cfa0f745d5ebb5a86a7e3b4d3a314cc7ad8fb83a1002f076ab6020b179c0429d */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adf4db0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8adf4db0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x100, VA 0xffffffff8ac25fc0, JMP target 0xffffffff8adf4dc0; Evidence ev_7502b5e534b2cbb3589cb1756906ac5cecd468bebe20c3f2f64a5010da899ebc */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adf4dc0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8adf4dc0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x108, VA 0xffffffff8ac25fc8, JMP target 0xffffffff8adf7d90; Evidence ev_0f93f89c2d9636281c837dd8daacb79a986b0a485f3da15ae24565b86a59bf07 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adf7d90); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8adf7d90(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x110, VA 0xffffffff8ac25fd0, JMP target 0xffffffff8adf8280; Evidence ev_5d4292882b75cc78743d7ec2208f60678f75a6188690be2329c50b3692ddda8a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adf8280); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_438280(long param_1,undefined8 *param_2)

{
  code *pcVar1;
  int iVar2;
  undefined8 uVar3;
  undefined8 uStack_40;
  undefined8 uStack_38;
  long lStack_28;
  
  lStack_28 = _DAT_ffffffff8e2dc310;
  if (param_2[6] != 0) {
    iVar2 = func_0xffffffff8ac19720(param_2[6],(long)*(int *)(param_1 + 0x9c));
    uVar3 = 0xe;
    if (iVar2 != 0) goto LAB_ffffffff8adf83a1;
  }
  if (param_2[7] != 0) {
    iVar2 = func_0xffffffff8ac19720(param_2[7],(long)*(int *)(param_1 + 0x9c));
    uVar3 = 0xe;
    if (iVar2 != 0) goto LAB_ffffffff8adf83a1;
  }
  uStack_40 = param_2[2];
  uStack_38 = param_2[3];
  if ((*(byte *)(param_2 + 8) & 4) != 0) {
    *(byte *)(param_1 + 0xed) = *(byte *)(param_1 + 0xed) | 0x80;
  }
  *(undefined8 *)(param_1 + 0x4f0) = 0;
  *(undefined8 *)(param_1 + 0x550) = 0;
  *(undefined8 *)(param_1 + 0x5b0) = 0;
  *(undefined8 *)(param_1 + 0x5b8) = 0;
  *(undefined8 *)(param_1 + 0x5c0) = 0;
  *(undefined8 *)(param_1 + 0x5c8) = 0;
  *(undefined8 *)(param_1 + 0x598) = 0;
  *(undefined8 *)(param_1 + 0x5d0) = 0;
  func_0xffffffff8b4111f0(param_1,*param_2,param_2[1],&uStack_40);
  uVar3 = func_0xffffffff8b411300(param_1,param_2[4]);
  if ((int)uVar3 == 0) {
    iVar2 = func_0xffffffff8b4c78d0();
    uVar3 = 0;
    if (iVar2 != 0) {
      func_0xffffffff8aa659e0(param_1,param_2[2],param_2[3]);
      uVar3 = 0;
    }
  }
LAB_ffffffff8adf83a1:
  if (_DAT_ffffffff8e2dc310 == lStack_28) {
    return uVar3;
  }
  func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* Input +0x118, VA 0xffffffff8ac25fd8, JMP target 0xffffffff8b4a6690; Evidence ev_345480c50df82accfe6997c5ba3c93cc6288b477cb0d38855234ef032aabcb76 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b4a6690); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b4a6690(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x120, VA 0xffffffff8ac25fe0, JMP target 0xffffffff8b4a6580; Evidence ev_74f4b185649f54504c0e0913aa8eee2b6657f2c9244213e21d0c7fc905a6ca8f */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b4a6580); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b4a6580(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x128, VA 0xffffffff8ac25fe8, JMP target 0xffffffff8ae090d0; Evidence ev_aea86123378b448ee5adb4635ba3537513173d1d296db4958eea7bf9167c6123 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae090d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae090d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x130, VA 0xffffffff8ac25ff0, JMP target 0xffffffff8aa66dc0; Evidence ev_e80e7a1f6ba99566b3948e67368dd3a40ca97f030fb98ac21c4c322e730c3783 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aa66dc0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aa66dc0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x138, VA 0xffffffff8ac25ff8, JMP target 0xffffffff8ae0aa70; Evidence ev_de1cd106387bbacf81297081f7785122464fc773d16754ed603ff008843021af */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae0aa70); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae0aa70(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x140, VA 0xffffffff8ac26000, JMP target 0xffffffff8b376110; Evidence ev_e7768edda17e5f94003e797fe77d9ff6a6d3196ffe84d79ee64e6641c5909986 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b376110); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b376110(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x148, VA 0xffffffff8ac26008, JMP target 0xffffffff8aa67670; Evidence ev_a422267068a4c10eedc2e7fa946331f07d472c95764b98bd8d75d9f4775978a7 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aa67670); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aa67670(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x150, VA 0xffffffff8ac26010, JMP target 0xffffffff8aa67850; Evidence ev_8d305b98475b7b985c62808bf0d5fb90d11c0e6e3dfc8e3f293e5410b72ec9e4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aa67850); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aa67850(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x158, VA 0xffffffff8ac26018, JMP target 0xffffffff8aa67880; Evidence ev_1104d932b91ccb11d405abad1970915223d066ff2c277d1d00cf44e30d7f9add */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aa67880); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aa67880(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x160, VA 0xffffffff8ac26020, JMP target 0xffffffff8ae12040; Evidence ev_33a72aca933f12546a9a13c9578b72fe6dc057014c0c8d9691816c82a46364f4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae12040); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae12040(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x168, VA 0xffffffff8ac26028, JMP target 0xffffffff8ae14cc0; Evidence ev_b89cb75715584c50918070896305e6076d819c61965ba98950a81e934d53fd86 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae14cc0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae14cc0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x170, VA 0xffffffff8ac26030, JMP target 0xffffffff8ae17820; Evidence ev_ac60b4edb77df0cf766945c7c98f7ab87da17774bf62364c63a00e070da07c53 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae17820); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae17820(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x178, VA 0xffffffff8ac26038, JMP target 0xffffffff8ae2df70; Evidence ev_c204a5a89d587f8a449e183f2ea9415de9bd1f522828ea9a983d6688908bdfb3 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae2df70); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae2df70(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x180, VA 0xffffffff8ac26040, JMP target 0xffffffff8ae2e080; Evidence ev_7f5a81de5386a414c136d761b444f09147d692621cbe1fffb7de77663e01955a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae2e080); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae2e080(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x188, VA 0xffffffff8ac26048, JMP target 0xffffffff8ae32990; Evidence ev_93c6d7eb70c2c45bd13e9e6c872cd234e807b6f8e87612cd1fecc265dd5098a2 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae32990); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae32990(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x190, VA 0xffffffff8ac26050, JMP target 0xffffffff8ae333b0; Evidence ev_11b99e35b16404cc162ccd2684098e85b189f119c31d51e51b88ed27e9afafd8 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae333b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae333b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x198, VA 0xffffffff8ac26058, JMP target 0xffffffff8ae338b0; Evidence ev_0137fdc126f15fe551d7008aa16d1df1926868a21683718a6bbdeb6114c354f7 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae338b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae338b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x1a0, VA 0xffffffff8ac26060, JMP target 0xffffffff8ae34250; Evidence ev_6f5634f26eefda915776c3402fcfcb16e83143b6f237d0ca98a814eb7e172658 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae34250); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae34250(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x1a8, VA 0xffffffff8ac26068, JMP target 0xffffffff8ae34db0; Evidence ev_abb7e8a34cdd190a57825c2f47e62c18f32a48ba9c1cdb9f1478f0412969fdef */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae34db0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae34db0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x1b0, VA 0xffffffff8ac26070, JMP target 0xffffffff8ae3cff0; Evidence ev_a002ef2f50cb75f5d681d0428920dd2cb3b7e3a956f3231f6f59ca01ee1124a3 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae3cff0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae3cff0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x1b8, VA 0xffffffff8ac26078, JMP target 0xffffffff8abddff0; Evidence ev_87975ab5ec25c723c158f862271e9ed9f9c033c69d595518cdec9d1a6dc2e3e9 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8abddff0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8abddff0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x1c0, VA 0xffffffff8ac26080, JMP target 0xffffffff8ae50300; Evidence ev_d7f8e8114938242bd66daaba865e8293f61649a84e5483c16fe1c999e38c41bb */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae50300); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae50300(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x1c8, VA 0xffffffff8ac26088, JMP target 0xffffffff8ae50db0; Evidence ev_be0370ff4227574b166db649fcdea76cf6a7f8b29634d5cdcdca0c4fd7246b56 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae50db0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae50db0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x1d0, VA 0xffffffff8ac26090, JMP target 0xffffffff8ae57fb0; Evidence ev_4099bb659c6297992cc7f698f8308fed393d195e9a72d738078e7d525819296b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae57fb0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae57fb0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x1d8, VA 0xffffffff8ac26098, JMP target 0xffffffff8ae57fe0; Evidence ev_5d43e3355d85ba6e815a09c8398d588324d410206ca92ed3c889c67313dd5d1f */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae57fe0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae57fe0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x1e0, VA 0xffffffff8ac260a0, JMP target 0xffffffff8ae58630; Evidence ev_ae9b3a06170e6eb638d9f8de7866b261ea1c87fc644a7770657fceb8f5b51804 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae58630); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae58630(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x1e8, VA 0xffffffff8ac260a8, JMP target 0xffffffff8ae58640; Evidence ev_a2204c190764d2e6ea10cc45554289a78ebed04098bac1ba685c9e9abb1cc5f7 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae58640); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae58640(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x1f0, VA 0xffffffff8ac260b0, JMP target 0xffffffff8b2b7bc0; Evidence ev_c004ed395f146ce95de524dfd2899a658986391bd13cee3000a1a80b997fd90a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b7bc0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b7bc0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x1f8, VA 0xffffffff8ac260b8, JMP target 0xffffffff8b2b6800; Evidence ev_f3767ae57f5a48c06be41c7591814bcdd086204c342351a7cd0ebf6f382a0766 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b6800); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b6800(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x200, VA 0xffffffff8ac260c0, JMP target 0xffffffff8b2b7420; Evidence ev_112b35961635e07b92ae94f3af096629c7c29afb4ae1e3436a7309dd80eb4e0a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b7420); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b7420(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x208, VA 0xffffffff8ac260c8, JMP target 0xffffffff8b2b9f80; Evidence ev_3647f81d26e724d9e71ed49a557d0bbcddec73885cdfe1562af462bee6e93f74 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b9f80); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b9f80(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x210, VA 0xffffffff8ac260d0, JMP target 0xffffffff8af9f350; Evidence ev_933a6799bbf419ba92d0adc8450efc719630277816ce14b05348d52a0d449488 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af9f350); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af9f350(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x218, VA 0xffffffff8ac260d8, JMP target 0xffffffff8af9f820; Evidence ev_5c16bcc394b1b03438c4796d83d79fb8c4cf2b7ae44e923df7b917100dc2085c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af9f820); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af9f820(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x220, VA 0xffffffff8ac260e0, JMP target 0xffffffff8b3f4ce0; Evidence ev_4d6b4c1a5eb9891949b4679bcea824be6f2863a2bae9793117a053ee2c7a6e14 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3f4ce0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3f4ce0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x228, VA 0xffffffff8ac260e8, JMP target 0xffffffff8afa84a0; Evidence ev_eaf8b36632130452c296371f9dd831cab82d21edd9c1288cab16c033bbd4d171 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afa84a0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8afa84a0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x230, VA 0xffffffff8ac260f0, JMP target 0xffffffff8b2b81f0; Evidence ev_054905ef143786b9fd3b24db0be49d1bfbce38d5737f7c1835c37f3f824a33da */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b81f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b81f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x238, VA 0xffffffff8ac260f8, JMP target 0xffffffff8b2b9410; Evidence ev_d84e121fdaf2a040b5f46418eef7a7eea43f7533ffc7797dd854e0936c4f1afb */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b9410); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b9410(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x240, VA 0xffffffff8ac26100, JMP target 0xffffffff8b2bc3f0; Evidence ev_f7d4dc446ce0f0a19e84ad6690cdc1ae8767d0b8b448946efe221e7e15a71674 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2bc3f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2bc3f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x248, VA 0xffffffff8ac26108, JMP target 0xffffffff8b2b6c90; Evidence ev_16863397b697fc007b495937a270fc990f7ece38fea2b8e260cea8d37d21ccc0 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b6c90); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b6c90(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x250, VA 0xffffffff8ac26110, JMP target 0xffffffff8b671a10; Evidence ev_d67521a6a6535348768673f4f99c1f9de5864fa7933618dd42b32eef0241220a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b671a10); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b671a10(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x258, VA 0xffffffff8ac26118, JMP target 0xffffffff8b4783a0; Evidence ev_e5d0a874029910e8057d8df7e4663d6479784ce142f271ecf7892386153f2a08 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b4783a0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b4783a0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x260, VA 0xffffffff8ac26120, JMP target 0xffffffff8b4783b0; Evidence ev_c5d44d482c7dfeb430e4a65148172b8c26e5545978500773890559a034a4e2e7 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b4783b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b4783b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x268, VA 0xffffffff8ac26128, JMP target 0xffffffff8b2ba1c0; Evidence ev_5a618de85ec75ca14a7e534651ea6b085861eee7842aec8b30bc227b1b25b393 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2ba1c0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2ba1c0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x270, VA 0xffffffff8ac26130, JMP target 0xffffffff8b2b7b40; Evidence ev_debe14baf768c0da433a7c8e6c822224faf8b58012da6ed46e2e64a6cbe07055 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b7b40); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b7b40(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x278, VA 0xffffffff8ac26138, JMP target 0xffffffff8ae60960; Evidence ev_7fc3cad42bb54333a189b6a90f6cb2bc9f177786ef55043440203579343d0019 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae60960); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae60960(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x280, VA 0xffffffff8ac26140, JMP target 0xffffffff8b0e9780; Evidence ev_1d3d7e7dcce01b345dca9480042628f7c03d49efcb8666558d35f1c857f4705e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0e9780); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0e9780(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x288, VA 0xffffffff8ac26148, JMP target 0xffffffff8b0e9790; Evidence ev_befefda6ba4528382755e49532aebfb92404d8c359d10d4d84c5410ddb0ecfff */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0e9790); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0e9790(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x290, VA 0xffffffff8ac26150, JMP target 0xffffffff8b0e97a0; Evidence ev_397487bf3e8420bb7b17a78b75db5f71ebc3615b9289fde8033b796a5b6a13ef */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0e97a0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0e97a0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x298, VA 0xffffffff8ac26158, JMP target 0xffffffff8b07b590; Evidence ev_f6f25779f23992ea580dceaffa40af9e5d5b37505584614e51de35b6560df157 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b07b590); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b07b590(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x2a0, VA 0xffffffff8ac26160, JMP target 0xffffffff8b478da0; Evidence ev_607cacf4864cb52df5c70776c16432f8e0602a33c7ffb008a89c8c1176bb88ae */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b478da0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b478da0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x2a8, VA 0xffffffff8ac26168, JMP target 0xffffffff8b2ba170; Evidence ev_3a00c8fdd0f4b9896f45769d16253314e5b8a04f99af542433a5d459d4ff4a9d */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2ba170); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2ba170(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x2b0, VA 0xffffffff8ac26170, JMP target 0xffffffff8b53f0c0; Evidence ev_e5f86ec02cd93c158e63e3fd158f8689f9bd616ebe49b0270089c9032b44c010 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b53f0c0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b53f0c0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x2b8, VA 0xffffffff8ac26178, JMP target 0xffffffff8b53f100; Evidence ev_377f5e1320f3d530adbecf4c51ac6bceb3c4b95f49164df71bce281ebb04e4ab */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b53f100); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b53f100(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x2c0, VA 0xffffffff8ac26180, JMP target 0xffffffff8b2b9cf0; Evidence ev_2da4191bc20c9ef1e9c9117355e71e7c912f1a0b06e8b29b6dd425fd2eeaf8a1 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b9cf0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b9cf0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x2c8, VA 0xffffffff8ac26188, JMP target 0xffffffff8b2ba740; Evidence ev_e4bfb93a2a6ea5e0e397ab7388b1f223aface7451b487f02413aea2b69a29384 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2ba740); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2ba740(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x2d0, VA 0xffffffff8ac26190, JMP target 0xffffffff8af12b70; Evidence ev_38404cb6753f15a3579cc328e790d4632a35afd20208c8e283cef25d08aa584b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af12b70); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af12b70(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x2d8, VA 0xffffffff8ac26198, JMP target 0xffffffff8af12bf0; Evidence ev_b0e7f0e651de029b075f919bdb07eaaaeb1962c4a7b66d3891631dd685b3cd9e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af12bf0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af12bf0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x2e0, VA 0xffffffff8ac261a0, JMP target 0xffffffff8af12c50; Evidence ev_37dcb2e4b55f0f75397c3f0f1217effd98edb76223fd39fcc8df5d1f79ba4226 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af12c50); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af12c50(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x2e8, VA 0xffffffff8ac261a8, JMP target 0xffffffff8af12c80; Evidence ev_6661c8277dd71a46a0d3cc61a3057109b5c469ad295a4a1f7cce2f330384dd24 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af12c80); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af12c80(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x2f0, VA 0xffffffff8ac261b0, JMP target 0xffffffff8af12cb0; Evidence ev_9ec0a872163921a61559750d4bd60418206624d6f107047ebdca96a5da77b075 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af12cb0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af12cb0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x2f8, VA 0xffffffff8ac261b8, JMP target 0xffffffff8af12ce0; Evidence ev_95ba4c5d64a5fb4287f3f471722b70fece34278aecb89fd0b16829819902b5d7 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af12ce0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af12ce0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x300, VA 0xffffffff8ac261c0, JMP target 0xffffffff8b53e800; Evidence ev_1e64498678e196df2052363234bc0e4edf903f7c2a1b93dc7d99207aeb738aed */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b53e800); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b53e800(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x308, VA 0xffffffff8ac261c8, JMP target 0xffffffff8b53ebe0; Evidence ev_884786577e215161ce3b239d9ab6a4711cb4d56a69b6658bb56731a6086551b3 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b53ebe0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b53ebe0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x310, VA 0xffffffff8ac261d0, JMP target 0xffffffff8b53ef70; Evidence ev_2b68ee165d495f111f02bf427dfdaffe08c7a136a03c3770bd427d5892a201b1 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b53ef70); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b53ef70(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x318, VA 0xffffffff8ac261d8, JMP target 0xffffffff8b5c6d30; Evidence ev_70407a417188d610f07cc250d6bf7bd16ae3a803d9a982c9c2e1f0e161c90341 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b5c6d30); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b5c6d30(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x320, VA 0xffffffff8ac261e0, JMP target 0xffffffff8b152690; Evidence ev_3519f17dde67bea665b1a0d36b3dc205f389329528fcfac480a72e974995a00e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b152690); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b152690(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x328, VA 0xffffffff8ac261e8, JMP target 0xffffffff8afa8b20; Evidence ev_561b181cdbbe0da842ee4c61d2445f72e3f8cba61d61cc3778d1a5ccd3fd75ab */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afa8b20); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8afa8b20(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x330, VA 0xffffffff8ac261f0, JMP target 0xffffffff8af12d10; Evidence ev_cc566ddb32757dfbb8b5a633570c3d00995b25d31d8d38d5532cbea441da3a34 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af12d10); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af12d10(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x338, VA 0xffffffff8ac261f8, JMP target 0xffffffff8b53f160; Evidence ev_b91b2b81f5acdd4ff82d3d01ea2d34e2bf906d91b12c17596ec29ee8c5681a2c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b53f160); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b53f160(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x340, VA 0xffffffff8ac26200, JMP target 0xffffffff8af9e250; Evidence ev_462fbaafe26f4b4cdd944a00b302eb61992dd4244a55fa96d7094252dc358c6e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af9e250); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af9e250(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x348, VA 0xffffffff8ac26208, JMP target 0xffffffff8b414a30; Evidence ev_8aea0ca2edb36dc33d537ce47fcb22757e36d9550b92a8870e441050d9758a70 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b414a30); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b414a30(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x350, VA 0xffffffff8ac26210, JMP target 0xffffffff8b414a40; Evidence ev_604fc366acec3ca6b3842c63c496b84c7ce1aeffbae23111f2957acf97b4193e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b414a40); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b414a40(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x358, VA 0xffffffff8ac26218, JMP target 0xffffffff8b414a50; Evidence ev_36b45c4f53fe9653f07bc2b551cf6481fb98b3602a5fe35cedced2c764850317 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b414a50); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b414a50(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x360, VA 0xffffffff8ac26220, JMP target 0xffffffff8b414a60; Evidence ev_75d19ac7892e72bbdbbf3aafc376736dbfb60ec43d1ea462df45d6a9aac4eeb4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b414a60); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b414a60(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x368, VA 0xffffffff8ac26228, JMP target 0xffffffff8b414a80; Evidence ev_dcf56db5e865730caac7118122b73a384d2b0ca50d655ed69036969d429e88f4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b414a80); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b414a80(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x370, VA 0xffffffff8ac26230, JMP target 0xffffffff8b414a90; Evidence ev_2c4e3bed8847899981b949390d47fffc36ef214b202459f85553b61d02e84f70 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b414a90); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b414a90(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x378, VA 0xffffffff8ac26238, JMP target 0xffffffff8b2b9720; Evidence ev_387d259d720725905cef732c2db37b7b96bcaf2e2a3c9e479b83e102f2ee6465 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b9720); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b9720(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x380, VA 0xffffffff8ac26240, JMP target 0xffffffff8b414ab0; Evidence ev_96b94c16e5dcc762347c995049c3f2ba26bd1501ec7074b39c0dc32622fcc5a0 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b414ab0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b414ab0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x388, VA 0xffffffff8ac26248, JMP target 0xffffffff8b2b64e0; Evidence ev_396510e34fa5273bdb2fe8c6d2a4f4115e09635c0a670f71de53664e2d6a6113 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b64e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b64e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x390, VA 0xffffffff8ac26250, JMP target 0xffffffff8b2b5ef0; Evidence ev_b476d9058899a793358f2d042f92e38b7585061695579bdc6f5bd822221f6595 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b5ef0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b5ef0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x398, VA 0xffffffff8ac26258, JMP target 0xffffffff8b414a20; Evidence ev_13ef6f94e9f61cd66948ea0cceb6c6dc71f2f5d0f784a393c47a1c47b25ee18a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b414a20); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b414a20(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x3a0, VA 0xffffffff8ac26260, JMP target 0xffffffff8b414a70; Evidence ev_4f911349c43a38b3ddf4058d8fd861cdccac43a751d7a380bf23a2e2fc647e18 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b414a70); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b414a70(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x3a8, VA 0xffffffff8ac26268, JMP target 0xffffffff8b414aa0; Evidence ev_54e2666cdd4855702dc8f5ea529450453935839f6682e9e5f6ff5247572df310 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b414aa0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b414aa0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x3b0, VA 0xffffffff8ac26270, JMP target 0xffffffff8b0a54d0; Evidence ev_f6121e5286f207388220489f88cfee231bfd40a03f04b3ab2c180b75a4caf3ad */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0a54d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0a54d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x3b8, VA 0xffffffff8ac26278, JMP target 0xffffffff8b53f4b0; Evidence ev_108a40c4af5ef9f02a85fb5d3ed0e12b24598f53b61cefa0de51917cc16455ea */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b53f4b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b53f4b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x3c0, VA 0xffffffff8ac26280, JMP target 0xffffffff8b1fd660; Evidence ev_a964ccfe3184d0ae5e84eedc7b635a378444c01f5d0af19e0152390915f3e457 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1fd660); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1fd660(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x3c8, VA 0xffffffff8ac26288, JMP target 0xffffffff8b1fd7c0; Evidence ev_febe219384fb62f3660032b3a8f3121b2bd319cbf16b3961078a9ba1fe0374dc */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1fd7c0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1fd7c0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x3d0, VA 0xffffffff8ac26290, JMP target 0xffffffff8b1fdab0; Evidence ev_69f2dd68202dcade90d1430b3334d41aab9b2185ab50230320f9588ca58a980e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1fdab0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1fdab0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x3d8, VA 0xffffffff8ac26298, JMP target 0xffffffff8b1fde80; Evidence ev_3d5fe35786917e6f0a931f43ca989f841a00ee34617a706ba8455d0d686f9cf7 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1fde80); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1fde80(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x3e0, VA 0xffffffff8ac262a0, JMP target 0xffffffff8b2b9c80; Evidence ev_ad882f618471a7df9c4d93c6d5b73573d0a49dd39c27f568c9d5fb8db40d6cbb */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b9c80); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b9c80(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x3e8, VA 0xffffffff8ac262a8, JMP target 0xffffffff8b2ba110; Evidence ev_20c5f9f1976e3f0fd24f456e02fc4b3ba4f4ed70908151b427d86aa3d4d0372b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2ba110); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2ba110(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x3f0, VA 0xffffffff8ac262b0, JMP target 0xffffffff8b2b91b0; Evidence ev_53b542deccf6f4247b3aec5ccaad29927918a6d7de8f0280ed46df03670d89b7 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b91b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b91b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x3f8, VA 0xffffffff8ac262b8, JMP target 0xffffffff8b2ba4f0; Evidence ev_a35fda9a442eda8e385ee0f2b6cfdc659319cc5cf5e7fecf8b864e533a4bebbf */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2ba4f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2ba4f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x400, VA 0xffffffff8ac262c0, JMP target 0xffffffff8b2b8090; Evidence ev_f20997a8f4a01cdf2fe59266c4f14a36c514f2e59bf9e6d2744195cf95907706 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b8090); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b8090(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x408, VA 0xffffffff8ac262c8, JMP target 0xffffffff8b2bbb80; Evidence ev_bcdddb92311ad93d4f8c09aa7af3812f4f7a5003961f976521bab13cdf080e6b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2bbb80); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2bbb80(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x410, VA 0xffffffff8ac262d0, JMP target 0xffffffff8b2b7b80; Evidence ev_93a265d42808f7c9b57ccbfa0a8b02deabc48f8adf060fb46f7714c9f8d21a34 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b7b80); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b7b80(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x418, VA 0xffffffff8ac262d8, JMP target 0xffffffff8b2b7890; Evidence ev_a23eddeaaee22065e579a8e23ba2eea14866f2cf4f5be646c150f59b6941be7f */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b7890); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b7890(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x420, VA 0xffffffff8ac262e0, JMP target 0xffffffff8b2bb8a0; Evidence ev_a52c2e8377fd1facc90e3077b10c4bb2f0e05e4a4411210ac994b76c2eaeeb18 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2bb8a0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2bb8a0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x428, VA 0xffffffff8ac262e8, JMP target 0xffffffff8b2b8510; Evidence ev_fda4df19fd4d2b38bee1759fc2a9e3adb5a412a4f46d5e03414c9c6e308f77f4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b8510); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b8510(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x430, VA 0xffffffff8ac262f0, JMP target 0xffffffff8b2b8800; Evidence ev_b4695e730b201226d20c6c5c9bd4542371c2b8f022e02f1054391d22ef42382f */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b8800); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b8800(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x438, VA 0xffffffff8ac262f8, JMP target 0xffffffff8ae5b080; Evidence ev_0f790fe88934928cf899e0fb523e7b26d8a512039de821fd6f02f1d52000b2e0 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae5b080); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae5b080(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x440, VA 0xffffffff8ac26300, JMP target 0xffffffff8ae5b090; Evidence ev_5e2b07f7d1e828440f1ea1f6e42bde95229d3b8ac616333e95cbe1312d354504 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae5b090); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae5b090(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x448, VA 0xffffffff8ac26308, JMP target 0xffffffff8af1fa50; Evidence ev_0e22ead61a75b051693da4931bd6ce2993ef589b8ac631e033083e6db4941bd5 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af1fa50); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af1fa50(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x450, VA 0xffffffff8ac26310, JMP target 0xffffffff8b5f4870; Evidence ev_9d575e8fb66b0a9ce932ff6005628cdfc270810815e61ab702f162686afc01ec */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b5f4870); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b5f4870(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x458, VA 0xffffffff8ac26318, JMP target 0xffffffff8b19ccf0; Evidence ev_0e7cadf92faf9878eb2b15efb64ff0bb9909ddcf5d78c246aaafe3bdbba17384 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b19ccf0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b19ccf0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x460, VA 0xffffffff8ac26320, JMP target 0xffffffff8b19cd00; Evidence ev_1cb6751a485b057e3a4bda64bd6045cd9a2e754079583804213ff16f5339b8fa */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b19cd00); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b19cd00(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x468, VA 0xffffffff8ac26328, JMP target 0xffffffff8b19cd10; Evidence ev_58405d0c3bfc385c957b555464f72e604c170eefc0bb681f9020f3feb29d789c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b19cd10); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b19cd10(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x470, VA 0xffffffff8ac26330, JMP target 0xffffffff8b19cd20; Evidence ev_4faa7b7044649918f0be4beb682ce143e07946c28ff6258926382ba0a0ddbe39 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b19cd20); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b19cd20(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x478, VA 0xffffffff8ac26338, JMP target 0xffffffff8b19cd30; Evidence ev_b3228fa55f23c163d2dbf05f3feb08b17e080b71a7d3bf934221289d2070d843 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b19cd30); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b19cd30(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x480, VA 0xffffffff8ac26340, JMP target 0xffffffff8af66c90; Evidence ev_7272472501b8b5c4db3debfb27df093835eefbed9978d82fcccff0887381cc0c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af66c90); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af66c90(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x488, VA 0xffffffff8ac26348, JMP target 0xffffffff8af67300; Evidence ev_6a03f60456a1282e14cd61dfcaab27631aedb1a2d89491193faaa6a58392c05e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af67300); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af67300(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x490, VA 0xffffffff8ac26350, JMP target 0xffffffff8af67610; Evidence ev_b0d067a361f6184ff743716842dc908171251b898bf543a6d23843dd5ba0cd30 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af67610); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af67610(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x498, VA 0xffffffff8ac26358, JMP target 0xffffffff8af67900; Evidence ev_458f957bb9e193dd94d08406cd9a99b2c6b95c5ff905ea4516aa43438e6da99f */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af67900); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af67900(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x4a0, VA 0xffffffff8ac26360, JMP target 0xffffffff8b65c830; Evidence ev_56bd8b5be57ec33bae969d2f52c7919fdd2c20608938ecfcbe505b85d17ce265 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b65c830); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b65c830(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x4a8, VA 0xffffffff8ac26368, JMP target 0xffffffff8af67f00; Evidence ev_8bf79f674d107bda371cfda72f93aa7e08e369b5aa962e0b680552c7079c452d */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af67f00); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af67f00(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x4b0, VA 0xffffffff8ac26370, JMP target 0xffffffff8af68070; Evidence ev_b17db34514e892e8f555ebb056c556b16102e39c18e5658c95a00b7bd06910a5 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af68070); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af68070(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x4b8, VA 0xffffffff8ac26378, JMP target 0xffffffff8b5a8480; Evidence ev_0185cee840c5bcacdf9f88cdebcac2d93be3a14f404b0188ad3d911a5fb65dba */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b5a8480); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b5a8480(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x4c0, VA 0xffffffff8ac26380, JMP target 0xffffffff8ae5b0a0; Evidence ev_a4c6f56095cbec4da7606171d68fb16dae48ce417b97836c929a0e680e2919db */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae5b0a0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae5b0a0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x4c8, VA 0xffffffff8ac26388, JMP target 0xffffffff8ae5b0c0; Evidence ev_25a15f6133baec4769d1aa928f63fb538d1ba71e71848cfdee706e26ae006010 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae5b0c0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae5b0c0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x4d0, VA 0xffffffff8ac26390, JMP target 0xffffffff8ae5b0d0; Evidence ev_3b41b316d92bd07a3380d266065a811bac7c2ff9dfd685201e88ea43e8939f29 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae5b0d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae5b0d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x4d8, VA 0xffffffff8ac26398, JMP target 0xffffffff8ae5b0e0; Evidence ev_4f3f8ff54a11a8dd5fc80af797c2f8e40085bd740a36a5939e36a77a807c9d66 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae5b0e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae5b0e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x4e0, VA 0xffffffff8ac263a0, JMP target 0xffffffff8ae5b0f0; Evidence ev_8df25225280002610ee095228b6f0e4cab16eebae64070629350608c605591f3 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae5b0f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae5b0f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x4e8, VA 0xffffffff8ac263a8, JMP target 0xffffffff8aef0720; Evidence ev_236b1fb36ce531949382ab15c4419efab6cfda3f306acfb1ea53f044a632432c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aef0720); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aef0720(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x4f0, VA 0xffffffff8ac263b0, JMP target 0xffffffff8aef1670; Evidence ev_de300636b5c3c87f00bce6b55b39054a830546d2cc741cf1035b94f4c2765860 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aef1670); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aef1670(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x4f8, VA 0xffffffff8ac263b8, JMP target 0xffffffff8b2b96f0; Evidence ev_a930fe842df74b8d51df41ac849dd4649c3895c626d97deac9cc17efc238ede2 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b96f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b96f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x500, VA 0xffffffff8ac263c0, JMP target 0xffffffff8aef1230; Evidence ev_d33e0ccf1129371819aa4ee472b6b81521f370a311e67ca1cd288167d6686438 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aef1230); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aef1230(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x508, VA 0xffffffff8ac263c8, JMP target 0xffffffff8b1c2df0; Evidence ev_9476872c80a5b326b221feec237f38f816c8ac0862f6a31d8f394b0f0aaf733a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1c2df0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1c2df0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x510, VA 0xffffffff8ac263d0, JMP target 0xffffffff8b53f140; Evidence ev_93c91617656444b7b5ba65759becc2131001c0a17c9cc2bb21ad792a08d481aa */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b53f140); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b53f140(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x518, VA 0xffffffff8ac263d8, JMP target 0xffffffff8b4a35e0; Evidence ev_95cb7b15b857deb7b35e34a6ab8d6e38894eff05c351861e05c3471aaf9a9f19 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b4a35e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b4a35e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x520, VA 0xffffffff8ac263e0, JMP target 0xffffffff8aeaee20; Evidence ev_5977a879f76a68348fa16855f08a901ca531f003aaf7a104b22b34a03d8a912d */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeaee20); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeaee20(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x528, VA 0xffffffff8ac263e8, JMP target 0xffffffff8b2bab10; Evidence ev_e4dc9921e1e679ee76488bbf11e0129604650a4a3add9753e668da38d1c72714 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2bab10); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2bab10(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x530, VA 0xffffffff8ac263f0, JMP target 0xffffffff8b2bae30; Evidence ev_77fec82670d8c7adfb8a5d387b5854fa3cef17db77b0a832f07516fd6b6a6509 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2bae30); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2bae30(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x538, VA 0xffffffff8ac263f8, JMP target 0xffffffff8b389220; Evidence ev_8574797d3713753437ebefd8004f6f8c9b58160782f968ed0ced7444d710308f */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b389220); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b389220(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x540, VA 0xffffffff8ac26400, JMP target 0xffffffff8b389100; Evidence ev_ace47fc4b090bd9f2e056e1001c36437cd023d61d685b5c25db2d01c20209a38 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b389100); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b389100(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x548, VA 0xffffffff8ac26408, JMP target 0xffffffff8b002310; Evidence ev_4c657d915a3676e7cb275eafeec1d55a7c29666ed7d7a6a07aeb8bf56cbfe611 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b002310); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b002310(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x550, VA 0xffffffff8ac26410, JMP target 0xffffffff8b002820; Evidence ev_b54a3b91c9bbbb2493cfd8e468d3e73bbc50f059db40527fe1534de56162be67 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b002820); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b002820(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x558, VA 0xffffffff8ac26418, JMP target 0xffffffff8b0036e0; Evidence ev_1627360834da58937cc0443783aabc45750c6c26f41b5d3787f87b6d3381be36 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0036e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0036e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x560, VA 0xffffffff8ac26420, JMP target 0xffffffff8b0038d0; Evidence ev_04f235402bc16520591888a01b64703a1db879c511b00ef801a6c933af7a17d5 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0038d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0038d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x568, VA 0xffffffff8ac26428, JMP target 0xffffffff8b003c60; Evidence ev_98822d5b081012710a784b47e26a47f70850ea4cf23d9457c604f66d1dcd934f */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b003c60); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b003c60(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x570, VA 0xffffffff8ac26430, JMP target 0xffffffff8b3b8290; Evidence ev_b8f5801223fcad0a843082373b3a4395c5bebe43d0e524c851ef165d17ff2e40 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3b8290); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3b8290(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x578, VA 0xffffffff8ac26438, JMP target 0xffffffff8b3bbb70; Evidence ev_7f157bf62c5b17d5846b5708f7d0cccda34bcedb31d957aba989ca357dc3de20 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3bbb70); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3bbb70(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x580, VA 0xffffffff8ac26440, JMP target 0xffffffff8b405280; Evidence ev_cac0caa1ab22a74142c1a9408eda5d48e94a510fb65c33cf1ef3e77f29ca4768 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b405280); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b405280(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x588, VA 0xffffffff8ac26448, JMP target 0xffffffff8b647ca0; Evidence ev_133f074fdac470fc0ab793bb433534f2590cdfcb308158f7a9be0208c4be7559 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b647ca0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b647ca0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x590, VA 0xffffffff8ac26450, JMP target 0xffffffff8b3bf000; Evidence ev_b4e694c12847308c8cca0dd1dc485cb6ad7686f7d17a8b615ec7238e303fda2c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3bf000); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3bf000(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x598, VA 0xffffffff8ac26458, JMP target 0xffffffff8b3c0780; Evidence ev_da6e79b574afbcf3aac9f804d4fd901c0780ca7efcd17db4052864f779e0a1d5 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3c0780); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3c0780(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x5a0, VA 0xffffffff8ac26460, JMP target 0xffffffff8b3c07e0; Evidence ev_6228159e85d07a6d61a9a0f921a75ff43753ea40d37601470afcbc49c1bb9bf2 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3c07e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3c07e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x5a8, VA 0xffffffff8ac26468, JMP target 0xffffffff8b47e830; Evidence ev_6da8db51c65723d573933414ba293a346ffbfb6fcad3229386bb507a68942472 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b47e830); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_abe830(long param_1,undefined8 *param_2)

{
  code *pcVar1;
  int iVar2;
  undefined8 uVar3;
  int iStack_2c;
  long lStack_28;
  
  lStack_28 = _DAT_ffffffff8e2dc310;
  iVar2 = func_0xffffffff8afc8f90(*(undefined8 *)(param_1 + 0x140));
  if (iVar2 == 0) {
    uVar3 = 1;
  }
  else {
    iStack_2c = 0;
    uVar3 = sub_abe260(param_1,*param_2,5,&iStack_2c);
    *(long *)(param_1 + 0x408) = (long)iStack_2c;
  }
  if (_DAT_ffffffff8e2dc310 == lStack_28) {
    return uVar3;
  }
  func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* Input +0x5b0, VA 0xffffffff8ac26470, JMP target 0xffffffff8b3bcf30; Evidence ev_e5af7a2fd1af816a6ccba515febfa3ebc9e47f71a638b99f81b061327cbe1642 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3bcf30); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3bcf30(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x5b8, VA 0xffffffff8ac26478, JMP target 0xffffffff8afb0fc0; Evidence ev_c2c6ec17b41b70baecfec67c12e9a9aabb33ace74282c8516546c3756c7231f4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afb0fc0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8afb0fc0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x5c0, VA 0xffffffff8ac26480, JMP target 0xffffffff8b2b73f0; Evidence ev_5740d90031260a2e842c3541c1bf7ed037d46b1bc6c7607f4ae2fadbd27fb830 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b73f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b73f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x5c8, VA 0xffffffff8ac26488, JMP target 0xffffffff8aeb7250; Evidence ev_fd92fa969f4acca217ea3ed4f849eda66ed2d430b835df6af4d4623345c428bc */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeb7250); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeb7250(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x5d0, VA 0xffffffff8ac26490, JMP target 0xffffffff8b3bdad0; Evidence ev_20c5cdd10bb650acc5afa9f1b30a2d980e2f8ece5be18ee6f371bfa91c852dcb */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3bdad0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3bdad0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x5d8, VA 0xffffffff8ac26498, JMP target 0xffffffff8b3bddb0; Evidence ev_b01910799fd53348d5505d9b12a5c86a5d3936eb91fbf7eba2f50ced2a53a941 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3bddb0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3bddb0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x5e0, VA 0xffffffff8ac264a0, JMP target 0xffffffff8b3bdf10; Evidence ev_58d9fff9168df3131e31c17e412318d4e7816c6a0bae30d5b333c9ea0c82d512 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3bdf10); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3bdf10(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x5e8, VA 0xffffffff8ac264a8, JMP target 0xffffffff8b0044d0; Evidence ev_2a7f1a0326eee2004329ef5320071e4b36caf10e5b7959fb3aaaf39e6cf21773 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0044d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0044d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x5f0, VA 0xffffffff8ac264b0, JMP target 0xffffffff8b010fd0; Evidence ev_1df2f47de9c3a7db92235d7af63d3b8ff4b924719b8b7623a35e86c3b93747c9 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b010fd0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b010fd0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x5f8, VA 0xffffffff8ac264b8, JMP target 0xffffffff8b3bea30; Evidence ev_4cc53fab915f8077e727a903fa8918b7963637d73e5576240b38ff8ae039a2a0 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3bea30); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3bea30(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x600, VA 0xffffffff8ac264c0, JMP target 0xffffffff8aeb7940; Evidence ev_e22678d981b48f42e954411199851093362eb70ee5ae49e6fdb2fde2bfca8013 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeb7940); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeb7940(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x608, VA 0xffffffff8ac264c8, JMP target 0xffffffff8b478ae0; Evidence ev_9c313a46a441798e2f0a379fe6d98b049616ede1ea41e393f02e8cd86ebc3eaf */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b478ae0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b478ae0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x610, VA 0xffffffff8ac264d0, JMP target 0xffffffff8b47b660; Evidence ev_c3b721557d90d4fc0357295def2739e6725a108c1f24caf7a1815ab5fcd215dc */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b47b660); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b47b660(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x618, VA 0xffffffff8ac264d8, JMP target 0xffffffff8b3be260; Evidence ev_a0e4e81f9c19149190830e06eec8a7e9287e8ad98c1edc464902ada1aa49f579 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3be260); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3be260(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x620, VA 0xffffffff8ac264e0, JMP target 0xffffffff8b3be4e0; Evidence ev_e7f43cc4f4954ca4468e66b0a801799e13f9c98e9323e60d84ffa966a97be76d */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3be4e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3be4e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x628, VA 0xffffffff8ac264e8, JMP target 0xffffffff8b3be630; Evidence ev_0bcb736c8872d397307b0dc9648d122d08f90d02fc9ea6e58d8ba345ac3f539b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3be630); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3be630(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x630, VA 0xffffffff8ac264f0, JMP target 0xffffffff8b158330; Evidence ev_aa4e8fcc5014fdaede947ece69a27c6e3b2f444c40ec42253724f0b02b133e0f */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b158330); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b158330(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x638, VA 0xffffffff8ac264f8, JMP target 0xffffffff8b47d000; Evidence ev_349fefb262ea62c710accfcef40795c6e8f249ea1bbd3772eb3d888f940b6828 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b47d000); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_abd000(undefined8 param_1,undefined4 *param_2)

{
  int iVar1;
  code *pcVar2;
  undefined8 uVar3;
  undefined8 *in_GS_OFFSET;
  undefined1 auStack_e0 [8];
  undefined1 auStack_d8 [168];
  long lStack_30;
  
  lStack_30 = _DAT_ffffffff8e2dc310;
  if ((param_2[2] == 10) || (uVar3 = 0x16, param_2[2] == 0)) {
    uVar3 = func_0xffffffff8b47ccc0(param_1,*param_2,auStack_e0);
    if ((int)uVar3 == 0) {
      iVar1 = param_2[2];
      uVar3 = *(undefined8 *)(param_2 + 4);
      func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd0f297,0);
      uVar3 = func_0xffffffff8ac191d0(auStack_e0 + (long)iVar1 * 0x10,uVar3,8);
      if ((int)uVar3 == 0) {
        iVar1 = param_2[2];
        uVar3 = *(undefined8 *)(param_2 + 6);
        func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd0f297,0);
        uVar3 = func_0xffffffff8ac191d0(auStack_d8 + (long)iVar1 * 0x10,uVar3,8);
      }
    }
  }
  if (_DAT_ffffffff8e2dc310 == lStack_30) {
    return uVar3;
  }
  func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
  pcVar2 = (code *)invalidInstructionException();
  (*pcVar2)();
}



/* Input +0x640, VA 0xffffffff8ac26500, JMP target 0xffffffff8aabc890; Evidence ev_4a4ed3812dad39569df1abaf5a009fadb5f3ccd8436c82c27365aea1fff26dd0 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aabc890); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aabc890(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x648, VA 0xffffffff8ac26508, JMP target 0xffffffff8ae5f090; Evidence ev_7800fa911d611e6bc89e076943d7091f71d050db5b772cb60731451eaaf03ec6 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae5f090); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae5f090(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x650, VA 0xffffffff8ac26510, JMP target 0xffffffff8ae5f200; Evidence ev_a6cf3a1eae9a907e151d6a31fa978b62c9ca9d368e8fd9f304726e629455d27c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae5f200); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae5f200(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x658, VA 0xffffffff8ac26518, JMP target 0xffffffff8ae80590; Evidence ev_8c19b1afbc4242b21ff42f2d35c69976eaaded2e348b7a980bf529b48b2568aa */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae80590); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae80590(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x660, VA 0xffffffff8ac26520, JMP target 0xffffffff8ae805b0; Evidence ev_926222c88438f55de067264484aaca97fb1d01b41d9eb4d8bf7d50992422c5fa */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae805b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae805b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x668, VA 0xffffffff8ac26528, JMP target 0xffffffff8aa69430; Evidence ev_8795e8c30cc0d7e7b679db46989e58d3693c6fb87b79549368fcdea0a993b1b7 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aa69430); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aa69430(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x670, VA 0xffffffff8ac26530, JMP target 0xffffffff8ae8a350; Evidence ev_f5df9574f00b539b7d1aa4dc3f1c46fbb424092a56c82712bb0f60590b33013e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae8a350); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae8a350(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x678, VA 0xffffffff8ac26538, JMP target 0xffffffff8ae8aa40; Evidence ev_7c7233a8a8a776ed52ddd265705b715351f3a9a6645f2e3e02ea63f57b8e5d6d */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae8aa40); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae8aa40(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x680, VA 0xffffffff8ac26540, JMP target 0xffffffff8aa6a510; Evidence ev_44db452c0b485d21099003cb9ee631f9ccf995676dc9c7f9807f926fa03a372b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aa6a510); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aa6a510(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x688, VA 0xffffffff8ac26548, JMP target 0xffffffff8ae951d0; Evidence ev_3638fb668dcdbdb27d8f4b41c88a995b0619f4814d0701b0693548769f659202 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae951d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae951d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x690, VA 0xffffffff8ac26550, JMP target 0xffffffff8b1d11b0; Evidence ev_1cd4e758a1024c5017778c424db60407f82915c1776b70260e1d553e27305282 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1d11b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1d11b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x698, VA 0xffffffff8ac26558, JMP target 0xffffffff8a9dae90; Evidence ev_a5d034173325c5624f4ca327edf755467ffd1991fb2610c78bfa1ff188e6d267 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8a9dae90); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8a9dae90(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x6a0, VA 0xffffffff8ac26560, JMP target 0xffffffff8aeb0030; Evidence ev_e6b741f19be7a80f4b9aa260237ca1283179c2628445d8461fc51700e01d805b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeb0030); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeb0030(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x6a8, VA 0xffffffff8ac26568, JMP target 0xffffffff8aebbbd0; Evidence ev_3c400c3fe4be51699559cae96cb0d7c70d89baee6b9e5dc7cf95cafbba333d28 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aebbbd0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aebbbd0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x6b0, VA 0xffffffff8ac26570, JMP target 0xffffffff8aecced0; Evidence ev_4861abbfe14d84d967eaee7d561431ea03f773e52ddc1ee1eadea5b732de91b3 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aecced0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aecced0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x6b8, VA 0xffffffff8ac26578, JMP target 0xffffffff8aeccee0; Evidence ev_b564c5169254e9db29ca3e6ee20ed6bb8f30f4cedf871ce00f6d325bd368187e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeccee0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeccee0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x6c0, VA 0xffffffff8ac26580, JMP target 0xffffffff8aeccf30; Evidence ev_9d305e3b8b6680a71cd8d181f9ea8574e92be26336e73465129c6cb69d88a5d3 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeccf30); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeccf30(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x6c8, VA 0xffffffff8ac26588, JMP target 0xffffffff8aeccf70; Evidence ev_24b4df7f3a28eba613a3306e2bf5e872cf76ee662205de1bd4367449d73f3891 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeccf70); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeccf70(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x6d0, VA 0xffffffff8ac26590, JMP target 0xffffffff8aeccfb0; Evidence ev_f5f864d07431e4a82040600f911f5dd8f6c1a9052808b968eef57a6faaaf5d7d */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeccfb0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeccfb0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x6d8, VA 0xffffffff8ac26598, JMP target 0xffffffff8aeccfe0; Evidence ev_45779d27ce97b987d42fb328f2bacb272ac599c4d54e3940bd2e68a5c0426a9b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeccfe0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeccfe0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x6e0, VA 0xffffffff8ac265a0, JMP target 0xffffffff8aede4d0; Evidence ev_4790d4cb791af3cc18e33fddf190d20a7a8ff18572af65a16112d1b0a2b3dfc0 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aede4d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aede4d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x6e8, VA 0xffffffff8ac265a8, JMP target 0xffffffff8aedef60; Evidence ev_67bd1c7b2e18223e48208765d55dcd1f1ec65d048d7578ba62aca13664bf48a1 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aedef60); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aedef60(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x6f0, VA 0xffffffff8ac265b0, JMP target 0xffffffff8aedf000; Evidence ev_bac672696dd9311e2ba266d0ddee8e6710ba84a94646bc7254c1a5df70f6e0db */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aedf000); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aedf000(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x6f8, VA 0xffffffff8ac265b8, JMP target 0xffffffff8aedf0b0; Evidence ev_68638272c18b36bc7363470d070cf49095293e159e2ea18088eb280cba092b42 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aedf0b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aedf0b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x700, VA 0xffffffff8ac265c0, JMP target 0xffffffff8aedf2e0; Evidence ev_bc85c8cea4a1bfee1c56974f719a015d24055e3359093399ccc74d1a957729d9 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aedf2e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aedf2e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x708, VA 0xffffffff8ac265c8, JMP target 0xffffffff8aedf670; Evidence ev_d270e65fe6a5693bb6f69e232897cefe1ac75a6cc9c603d230d6111cdde88047 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aedf670); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aedf670(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x710, VA 0xffffffff8ac265d0, JMP target 0xffffffff8aedfee0; Evidence ev_a71846936a091fe574f6c593d4cf90ee6f1cfbfa6122682655cac03691f09b13 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aedfee0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aedfee0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x718, VA 0xffffffff8ac265d8, JMP target 0xffffffff8aef6400; Evidence ev_18b5f9e72f928fbfd6422ad2b6849b55f622b0e3ed772df9286bc7698b704d43 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aef6400); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aef6400(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x720, VA 0xffffffff8ac265e0, JMP target 0xffffffff8af04ca0; Evidence ev_b903e9c9b65d79b6312873b8bf0d37fbcfdd363753fb7c4b6883298d9f940d1f */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af04ca0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af04ca0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x728, VA 0xffffffff8ac265e8, JMP target 0xffffffff8af068f0; Evidence ev_08582392a08d2b2b1321394f33d74b736d22066c1127a08d3cc2e03cd0434a2e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af068f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af068f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x730, VA 0xffffffff8ac265f0, JMP target 0xffffffff8aa71630; Evidence ev_0fb43b0dfd9f7c5d64a95535792b71c7b2997d02c521af9153dd417d4804f78b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aa71630); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aa71630(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x738, VA 0xffffffff8ac265f8, JMP target 0xffffffff8aa71fb0; Evidence ev_2124b294bfcb2dd33a72a014273d143bc111f52b43fc04543986472ea3ed6f04 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aa71fb0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aa71fb0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x740, VA 0xffffffff8ac26600, JMP target 0xffffffff8af1bf40; Evidence ev_7da0d1cb287168624e57ccc678c5468352def29e40bc9b51aae6f03064812335 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af1bf40); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af1bf40(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x748, VA 0xffffffff8ac26608, JMP target 0xffffffff8af1c030; Evidence ev_fa4d0d631d420eebba91722dec6d5d4b14399b59adb9b6dd61c6ffac36a7766a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af1c030); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af1c030(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x750, VA 0xffffffff8ac26610, JMP target 0xffffffff8af1c050; Evidence ev_e345a0e575963b0c23b0473bcc0cedfb955e5de5eba7981ec450123095fe768a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af1c050); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af1c050(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x758, VA 0xffffffff8ac26618, JMP target 0xffffffff8af2e200; Evidence ev_26d1ea47cc396aaa05936764f4f2a99c4210ef9aa2e2511faa39a2e0e561e806 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af2e200); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af2e200(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x760, VA 0xffffffff8ac26620, JMP target 0xffffffff8af3f4a0; Evidence ev_b3337828f291a87007c286f771b1c1cb53c5e6ab5b2c99d1f43cbe5c11e59068 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af3f4a0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af3f4a0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x768, VA 0xffffffff8ac26628, JMP target 0xffffffff8b3545e0; Evidence ev_0f62d433f57581de6362c9df11da271ee9e44c018208d400af12644cca0b703a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3545e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3545e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x770, VA 0xffffffff8ac26630, JMP target 0xffffffff8af45950; Evidence ev_d16f44662af65bf722b760c6a7d8c1cfd82a23b1644f03767c671e0657478701 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af45950); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af45950(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x778, VA 0xffffffff8ac26638, JMP target 0xffffffff8af59820; Evidence ev_c83ab875cf41c6e99257f5ef11032a9ac212e10d8adaaea99df61905adf9c867 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af59820); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af59820(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x780, VA 0xffffffff8ac26640, JMP target 0xffffffff8af5a3e0; Evidence ev_d90e6f4dd290734566a43647dcb7799cad4ad92a7228486833f80e03d13981a4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af5a3e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af5a3e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x788, VA 0xffffffff8ac26648, JMP target 0xffffffff8af5a530; Evidence ev_15ff41daf443f1cb2aeabc62a2dae2eec3f9c0201fc348cc10ffb4c9baf59632 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af5a530); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af5a530(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x790, VA 0xffffffff8ac26650, JMP target 0xffffffff8af5a700; Evidence ev_6aed43e99a2586a43cffdfc3dcfff7b09e7a9e95f45c01cffa6968e7fdec8498 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af5a700); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af5a700(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x798, VA 0xffffffff8ac26658, JMP target 0xffffffff8af5a7d0; Evidence ev_9724511d34b103224f142d3bba92773b6296b29d253ad0fe93a44f7d34e2c8ff */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af5a7d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af5a7d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x7a0, VA 0xffffffff8ac26660, JMP target 0xffffffff8af5aa50; Evidence ev_3d45e49ed2fb3c45f131f381696e919a775ff179730169226e66c266d2b10258 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af5aa50); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af5aa50(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x7a8, VA 0xffffffff8ac26668, JMP target 0xffffffff8af5ab60; Evidence ev_b72884bc3e1d673c327de3c0fcf2da6275aa73e01805471164d8b3d00e16ea27 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af5ab60); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af5ab60(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x7b0, VA 0xffffffff8ac26670, JMP target 0xffffffff8af5ac60; Evidence ev_2a8591906f8fdda6e82ce237be34aa1bbcabc18fbc541223e5dad150f4a36f52 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af5ac60); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af5ac60(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x7b8, VA 0xffffffff8ac26678, JMP target 0xffffffff8af9bed0; Evidence ev_d6d6f9182862d7bfc2531c655e6e1993fd093923a20373647ba024aa11a1db9e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af9bed0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af9bed0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x7c0, VA 0xffffffff8ac26680, JMP target 0xffffffff8afab720; Evidence ev_145f7288e71f53a6abb3f38ee592b60515f6348a74170144951d09a5fd82263a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afab720); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8afab720(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x7c8, VA 0xffffffff8ac26688, JMP target 0xffffffff8afac030; Evidence ev_b7bce8a00cf13771b60a56d1057b755238087d90ecb8f1909f54bda5d18ff302 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afac030); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8afac030(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x7d0, VA 0xffffffff8ac26690, JMP target 0xffffffff8afacad0; Evidence ev_ce19077ee5a97c33a094c1ac3943d9fd70f9521fffb036fca0134769ca23c0a5 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afacad0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8afacad0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x7d8, VA 0xffffffff8ac26698, JMP target 0xffffffff8afad440; Evidence ev_88eb17bb11366c0529ecf0c6613b23d21ea0d28589000cc842d281c04e74641b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afad440); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8afad440(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x7e0, VA 0xffffffff8ac266a0, JMP target 0xffffffff8afadb30; Evidence ev_c024131bf8925051740590e121726f7af4ca6a8690ee512c891907ecf53cd489 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afadb30); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8afadb30(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x7e8, VA 0xffffffff8ac266a8, JMP target 0xffffffff8ab0e280; Evidence ev_fc068ad8b0dbf1e1149e146e351d87d74475e49d099ff878b9a5f1a5b56a5a90 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ab0e280); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ab0e280(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x7f0, VA 0xffffffff8ac266b0, JMP target 0xffffffff8afb18b0; Evidence ev_ab3845398a7dd87f2b74ec2cf36ee28a8a7ab508e025bee9e1047bb1ae4c37be */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afb18b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8afb18b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x7f8, VA 0xffffffff8ac266b8, JMP target 0xffffffff8afb2b30; Evidence ev_96f510d0043f883ee78e7ab91802683aaefff0247b219df4711f9e78121b2ece */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afb2b30); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8afb2b30(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x800, VA 0xffffffff8ac266c0, JMP target 0xffffffff8afbd0c0; Evidence ev_8e06e03d898ea2a1837d9445b8da7cf33e5d70321bce0086f224ff8c2a39c6af */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afbd0c0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8afbd0c0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x808, VA 0xffffffff8ac266c8, JMP target 0xffffffff8afc0680; Evidence ev_17f641c834ef7d96749ec623d9bbeb52bb446fdbaeea066d31cec5f615366c6a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afc0680); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8afc0680(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x810, VA 0xffffffff8ac266d0, JMP target 0xffffffff8afc0f40; Evidence ev_f53d252c7db5713389ee23c13a0158e5f7952e1ed90802e694e5a7e106bc42a3 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afc0f40); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8afc0f40(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x818, VA 0xffffffff8ac266d8, JMP target 0xffffffff8b4a64a0; Evidence ev_4361d3f10edce5cd315068992f61b7b6dd4e83b5344fcccee4b80619d3af33df */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b4a64a0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b4a64a0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x820, VA 0xffffffff8ac266e0, JMP target 0xffffffff8afedaa0; Evidence ev_287935e10ae72c74f9b637069eef4d9530b0d66a93a4914d4682b8dc0f97d6fb */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afedaa0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8afedaa0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x828, VA 0xffffffff8ac266e8, JMP target 0xffffffff8aff02d0; Evidence ev_8dc1b9e00346d1e2e93583d94a43358f12ca039cdfaecaca1c276bef60b1a0f7 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aff02d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aff02d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x830, VA 0xffffffff8ac266f0, JMP target 0xffffffff8aff4f10; Evidence ev_df95218690a0d8171052c0c09fae8ca612910659777fe9d5e26000387c5bbd7f */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aff4f10); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aff4f10(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x838, VA 0xffffffff8ac266f8, JMP target 0xffffffff8afff520; Evidence ev_d09d9506bb5f1247bff9edff2f2c682614f3d0f5a64f271dad27b12c097a54dc */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afff520); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8afff520(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x840, VA 0xffffffff8ac26700, JMP target 0xffffffff8b0179b0; Evidence ev_f67050adb0d51299feca971dc8ca248482e31262a1cb08bc2a93043c3e44d61a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0179b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0179b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x848, VA 0xffffffff8ac26708, JMP target 0xffffffff8b667310; Evidence ev_f27e80defa689304e349bdd5bc02360c6c8843b0da73e5a461084a5cdb322db4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b667310); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b667310(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x850, VA 0xffffffff8ac26710, JMP target 0xffffffff8b022e70; Evidence ev_40751d77b9e637d90898d6380d408402bec24e67e93a95549fd7aca21b538ab9 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b022e70); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b022e70(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x858, VA 0xffffffff8ac26718, JMP target 0xffffffff8b022e80; Evidence ev_0faf7686e97662988b08261b609b62c0cc96660fb5d467a7b8051b44e0dcfc5d */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b022e80); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b022e80(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x860, VA 0xffffffff8ac26720, JMP target 0xffffffff8b038e10; Evidence ev_7ed9a3b5f7c89418157233c7c775696de1922ba0d8f063308fa7c244b8b49f66 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b038e10); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b038e10(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x868, VA 0xffffffff8ac26728, JMP target 0xffffffff8b038e60; Evidence ev_1886c3f3bbe4d86203da61d47dcbadf30ae19bd346c981605256cf23bc85ef0a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b038e60); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b038e60(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x870, VA 0xffffffff8ac26730, JMP target 0xffffffff8b038ec0; Evidence ev_5125a843d7228054a47527ef1eb83de0919184035f25027a7b08790f39670731 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b038ec0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b038ec0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x878, VA 0xffffffff8ac26738, JMP target 0xffffffff8b038f60; Evidence ev_1a0ec69a4b9e5a0db730d9fa4d7e0e119503bdb7d35c296d041931627b21e9f2 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b038f60); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b038f60(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x880, VA 0xffffffff8ac26740, JMP target 0xffffffff8b039190; Evidence ev_213a2614c15a1c60272db045007b4d2fc79814b64d21fc9b815a6f9bcf9ec9bc */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b039190); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b039190(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x888, VA 0xffffffff8ac26748, JMP target 0xffffffff8b039360; Evidence ev_185f384351e1489c28bf97a91a7904eb92e3d42d265cdc3e87415af3237b80d4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b039360); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b039360(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x890, VA 0xffffffff8ac26750, JMP target 0xffffffff8b039680; Evidence ev_a7e0ba3c05a3759d8fd4dc33ee86bdc02903ef226bc3443bd2470cadc33f427e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b039680); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b039680(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x898, VA 0xffffffff8ac26758, JMP target 0xffffffff8a9f3b90; Evidence ev_e7d289e5f013b6879fd0c0614cc9a1d61ea827f9a40bb4ac73ed3d54004c512b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8a9f3b90); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8a9f3b90(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x8a0, VA 0xffffffff8ac26760, JMP target 0xffffffff8a9f3ca0; Evidence ev_e941eac59fdf08dd7724bd5f708f5d88777b39010b4fa96d128f3193a04f8618 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8a9f3ca0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8a9f3ca0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x8a8, VA 0xffffffff8ac26768, JMP target 0xffffffff8a9f3d20; Evidence ev_309709e7d1013fd236bd41c5d47ad91ab05bf5b203770915760de484982b2fea */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8a9f3d20); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8a9f3d20(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x8b0, VA 0xffffffff8ac26770, JMP target 0xffffffff8a9fcf70; Evidence ev_ef21622eb60067d48031ce43ab64129664c5cdc26a68e0e79a6352379f3e0ca9 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8a9fcf70); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8a9fcf70(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x8b8, VA 0xffffffff8ac26778, JMP target 0xffffffff8a9fd0e0; Evidence ev_3c671576d34f1528bcd3ef8caadae2533e2d539c327e7ed67a0ca6264a01a435 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8a9fd0e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8a9fd0e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x8c0, VA 0xffffffff8ac26780, JMP target 0xffffffff8a9fd660; Evidence ev_092200d50bd954fffbe24ee866dd215b9decd4e37661ae431ea0bf4119327250 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8a9fd660); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8a9fd660(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x8c8, VA 0xffffffff8ac26788, JMP target 0xffffffff8a9fe100; Evidence ev_28b1c81416ceee9353474bed732c960c3ec9c142ca64baf166e92f16eb7e74ea */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8a9fe100); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8a9fe100(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x8d0, VA 0xffffffff8ac26790, JMP target 0xffffffff8a9fe160; Evidence ev_edbe0c3b930cc8d70403206bc4182fc07c8e16dbd44a2686ee53992ecc987c4f */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8a9fe160); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8a9fe160(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x8d8, VA 0xffffffff8ac26798, JMP target 0xffffffff8a9fe1c0; Evidence ev_237e35ff8c601325e27b3671867d7a808cb15ea865f5706ef9d85e6fd268b141 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8a9fe1c0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8a9fe1c0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x8e0, VA 0xffffffff8ac267a0, JMP target 0xffffffff8a9ff070; Evidence ev_422617ebf4163eff7b95311c40aee341fda583226c550d3eac02616b7e3574a2 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8a9ff070); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8a9ff070(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x8e8, VA 0xffffffff8ac267a8, JMP target 0xffffffff8a9ff0d0; Evidence ev_111f9dda4cf6e088cb8c39399e41a007f290b2b43e4e39180e61a9d42e6669c9 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8a9ff0d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8a9ff0d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x8f0, VA 0xffffffff8ac267b0, JMP target 0xffffffff8a9ff4b0; Evidence ev_ffccb372958b6b6632c44ec001906c6e1fe9f998b9d32dadb006ba5f75d39aa1 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8a9ff4b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8a9ff4b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x8f8, VA 0xffffffff8ac267b8, JMP target 0xffffffff8a9ff510; Evidence ev_78779fb41da1587a354b9742f775079f8a687092ca81116bf28412f0de06ec5f */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8a9ff510); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8a9ff510(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x900, VA 0xffffffff8ac267c0, JMP target 0xffffffff8a9ff570; Evidence ev_0f0d93e5535a3d5484e026697f8799d3b8955e56df3474d86cfe0018748e0b2b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8a9ff570); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8a9ff570(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x908, VA 0xffffffff8ac267c8, JMP target 0xffffffff8a9ffbb0; Evidence ev_2e7b4c012239eb56246becf4740e792e82aef8459e3b7c13a20fc6626f818890 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8a9ffbb0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8a9ffbb0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x910, VA 0xffffffff8ac267d0, JMP target 0xffffffff8a9fffc0; Evidence ev_97c8e517128c3ac26355c6803a34e460d23be580cdf2b63da91226e391af387d */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8a9fffc0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8a9fffc0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x918, VA 0xffffffff8ac267d8, JMP target 0xffffffff8aa00960; Evidence ev_17fa793c3ad62321eada38f706d35a7174254fcdd5177054d2a1d5c305a171f1 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aa00960); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aa00960(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x920, VA 0xffffffff8ac267e0, JMP target 0xffffffff8aa00b50; Evidence ev_53cb5b0704c5f4548f119a6a18ba4dee4711b6739d02b556e0ff38cb1cab6500 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aa00b50); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aa00b50(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x928, VA 0xffffffff8ac267e8, JMP target 0xffffffff8aa00c30; Evidence ev_91fa248f1bca8afdee8069c2bc33ff70ab57ecabb105925c6977c3bbe1435f5d */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aa00c30); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aa00c30(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x930, VA 0xffffffff8ac267f0, JMP target 0xffffffff8aa01630; Evidence ev_0432a13f0021b995b1a27b7296145ebf7f59abb9150a7309a8af08fb1bacfc0a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aa01630); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aa01630(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x938, VA 0xffffffff8ac267f8, JMP target 0xffffffff8aa01750; Evidence ev_644b6dcc8485f20e94882bad3b71fa862a3df5159d46fb64f9d377ad8b8e72e1 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aa01750); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aa01750(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x940, VA 0xffffffff8ac26800, JMP target 0xffffffff8aa01830; Evidence ev_91d281c75d31c0051a5de9a309cc86a29f090fcd6b4b0781753c52b65d8b019e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aa01830); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aa01830(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x948, VA 0xffffffff8ac26808, JMP target 0xffffffff8aa018c0; Evidence ev_ba4b727e52ada88d1b744647255bce9ec8c263ef050a31dc43db59704509ca84 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aa018c0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aa018c0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x950, VA 0xffffffff8ac26810, JMP target 0xffffffff8aa02060; Evidence ev_7ef426d582c1f7602ddb023b3110b810d92ea47bffe13f93c5de27f06f04034a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aa02060); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aa02060(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x958, VA 0xffffffff8ac26818, JMP target 0xffffffff8aa024d0; Evidence ev_50533470792676ad6b0c23f6624637a3dd6ca51b3c1cf33ae149168477170239 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aa024d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aa024d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x960, VA 0xffffffff8ac26820, JMP target 0xffffffff8aa025a0; Evidence ev_92f51f78f07aeae5f94cc9ad359ca10f4bcd09ef261efaa140bf6655c9d1d353 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aa025a0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aa025a0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x968, VA 0xffffffff8ac26828, JMP target 0xffffffff8aa02600; Evidence ev_3089ea5a3ce0a8d8ccff8d4b787138175fe5cd9d7da502cb2c23ca1e9c379bd5 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aa02600); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aa02600(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x970, VA 0xffffffff8ac26830, JMP target 0xffffffff8b050030; Evidence ev_ada49697cc4a806a0acb8e2f1fbab057b9f337f11e2c9cc29379cb56ae1060bb */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b050030); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b050030(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x978, VA 0xffffffff8ac26838, JMP target 0xffffffff8b056cc0; Evidence ev_fd25e80f1a761202024baee66ee2b5d120ee83a197cb6aae6ac6a3a323d5a5b9 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b056cc0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b056cc0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x980, VA 0xffffffff8ac26840, JMP target 0xffffffff8b0585d0; Evidence ev_31fa395ffd6e511e066ee8cc02ab6b3f9975be048f50ffaafb5227c5e14ba0a6 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0585d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0585d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x988, VA 0xffffffff8ac26848, JMP target 0xffffffff8b062050; Evidence ev_1d4a62155160626f8d735346f4b719339404f196c67fa239920eb38bf3b9413b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b062050); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b062050(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x990, VA 0xffffffff8ac26850, JMP target 0xffffffff8b0622b0; Evidence ev_5a840db95a6b7b022b1ccba460e23e836d3b77c41adb99231e357b330f8f6c72 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0622b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0622b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x998, VA 0xffffffff8ac26858, JMP target 0xffffffff8b06e640; Evidence ev_b9036c4b2e7145fcabe7b15079b08001d18406f5e6cdabf688d7ce87e32c2a7c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b06e640); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b06e640(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x9a0, VA 0xffffffff8ac26860, JMP target 0xffffffff8b06e7f0; Evidence ev_cfec2174ee58e79396bbba92560a9fb3bd235fb602754d9dab25381bc6fd8de0 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b06e7f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b06e7f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x9a8, VA 0xffffffff8ac26868, JMP target 0xffffffff8ab413b0; Evidence ev_d7c49e50dd16688185770e56a4c5a8f43da2e7afbf8f395ce4ee15998d1903a7 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ab413b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ab413b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x9b0, VA 0xffffffff8ac26870, JMP target 0xffffffff8b07efa0; Evidence ev_cb15d7dea64bcb1ffdca6327774e9cd3fd22516aa21e20fdc052e7a780e423d3 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b07efa0); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_6befa0(long param_1,undefined8 *param_2)

{
  undefined8 uVar1;
  code *pcVar2;
  long lVar3;
  long lVar4;
  long lStack_38;
  long lStack_30;
  long lStack_28;
  
  lStack_28 = _DAT_ffffffff8e2dc310;
  if (*(int *)(param_1 + 0xa8) == 0) {
    func_0xffffffff8b48f780(&lStack_38);
  }
  else {
    func_0xffffffff8b48f700(&lStack_38);
  }
  lVar3 = *(long *)(param_1 + 0x88);
  param_2[3] = lVar3;
  lVar4 = *(long *)(param_1 + 0x80);
  param_2[2] = lVar4;
  uVar1 = *(undefined8 *)(param_1 + 0x70);
  param_2[1] = *(undefined8 *)(param_1 + 0x78);
  *param_2 = uVar1;
  if (lVar4 != 0 || lVar3 != 0) {
    lVar4 = lVar4 - lStack_38;
    param_2[2] = lVar4;
    lVar3 = lVar3 - lStack_30;
    param_2[3] = lVar3;
    if (lVar3 < 0) {
      lVar4 = lVar4 + -1;
      lVar3 = lVar3 + 1000000000;
      param_2[2] = lVar4;
      param_2[3] = lVar3;
    }
    if ((lVar4 < 0) || (lVar4 == 0 && lVar3 == 0)) {
      param_2[2] = 0;
      param_2[3] = 1;
    }
  }
  if (_DAT_ffffffff8e2dc310 != lStack_28) {
    func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
    pcVar2 = (code *)invalidInstructionException();
    (*pcVar2)();
  }
  return 0;
}



/* Input +0x9b8, VA 0xffffffff8ac26878, JMP target 0xffffffff8ab48040; Evidence ev_f4aea331a14ac5600fa924e633d41f70eaf4baa941d3745a412167c9b3f33554 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ab48040); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ab48040(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x9c0, VA 0xffffffff8ac26880, JMP target 0xffffffff8b090b00; Evidence ev_9dd26ca040226a17ca7d8146970f3b5b8e31be7e5226c9296852d13345c37764 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b090b00); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b090b00(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x9c8, VA 0xffffffff8ac26888, JMP target 0xffffffff8b091100; Evidence ev_d7472d70bece85fd2205b9608664e6f4373bc36a307418bc01adb7fccdc99541 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b091100); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b091100(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x9d0, VA 0xffffffff8ac26890, JMP target 0xffffffff8b091260; Evidence ev_09548b3f13a766753fc1c031fb959e9a27fa67d3da71e406867570170250c68d */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b091260); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b091260(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x9d8, VA 0xffffffff8ac26898, JMP target 0xffffffff8b0913e0; Evidence ev_4105c20ee37acfc4037888908cd0809fa5d327e9789aa1097d91d649ebaf340d */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0913e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0913e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x9e0, VA 0xffffffff8ac268a0, JMP target 0xffffffff8b091520; Evidence ev_01549c074234a86713ab01cf6c084611032b9d5e518936d1f60769007e77808a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b091520); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b091520(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x9e8, VA 0xffffffff8ac268a8, JMP target 0xffffffff8b091640; Evidence ev_eec7484b25190c226bcb7c1c79f4935100e098484fdd343ccacdba80657d8a3a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b091640); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b091640(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x9f0, VA 0xffffffff8ac268b0, JMP target 0xffffffff8b091720; Evidence ev_0bbf99a558a5e4318912968e42d4760278822a40d0dab85f0dba89df879246a7 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b091720); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b091720(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x9f8, VA 0xffffffff8ac268b8, JMP target 0xffffffff8b09c660; Evidence ev_b0a35a6d82279ed8c25dc8f64b156ccf7a2a964213c9614245c0d09d96fbb931 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b09c660); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b09c660(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa00, VA 0xffffffff8ac268c0, JMP target 0xffffffff8b09c690; Evidence ev_47418a844d1e8cf31469e50c1da4fbaab3d02a2d36667fa99d512eeae8046ff3 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b09c690); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b09c690(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa08, VA 0xffffffff8ac268c8, JMP target 0xffffffff8b09c6a0; Evidence ev_2a38a5fe5e57e3305ddbcc55689de9eb68e722984424c701bf721e5546510877 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b09c6a0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b09c6a0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa10, VA 0xffffffff8ac268d0, JMP target 0xffffffff8b0a0920; Evidence ev_94a916e2e60037577a58f0696ffaddf9ed06e7f280dac89fd8696af2c88e4cf9 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0a0920); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0a0920(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa18, VA 0xffffffff8ac268d8, JMP target 0xffffffff8b0a1440; Evidence ev_d9d0daf1187583cb932e2eda95c09e3ee20050e5939c534500a120bc86e0ffa6 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0a1440); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0a1440(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa20, VA 0xffffffff8ac268e0, JMP target 0xffffffff8b0a1450; Evidence ev_e69e2ddf86f809daab6142e89eb13d95d3919bd45e26a585d0bfe1c893d413cb */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0a1450); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0a1450(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa28, VA 0xffffffff8ac268e8, JMP target 0xffffffff8ab49a70; Evidence ev_3677ed9984e8e424d8424aee4ab62570e8f66f4bf5e08b0513ebf707135d8637 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ab49a70); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ab49a70(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa30, VA 0xffffffff8ac268f0, JMP target 0xffffffff8ab50aa0; Evidence ev_de668fcb0fea822c7fb61469cd6d8ef829ca710300e53b7ae07a04cc159740c9 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ab50aa0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ab50aa0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa38, VA 0xffffffff8ac268f8, JMP target 0xffffffff8b0c2970; Evidence ev_919016afe34ea8f0e157c94410dd9504db2e0b9c937a10a22f73381bad44998d */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0c2970); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0c2970(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa40, VA 0xffffffff8ac26900, JMP target 0xffffffff8b0c2d60; Evidence ev_d76ce9b0d37100cbcba73b60a60b4c0bc68b997dbf10e06092f8c85e8d382f76 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0c2d60); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0c2d60(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa48, VA 0xffffffff8ac26908, JMP target 0xffffffff8b0c6170; Evidence ev_845c2264d152304bd347d6e2e0290e99b33115bbf42541a0bc68fb305fb4c96e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0c6170); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0c6170(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa50, VA 0xffffffff8ac26910, JMP target 0xffffffff8b0c61f0; Evidence ev_7e42b15dfb56f443a56d3ab45bab112b121f64fcb68c53a827eaa8d959f338b8 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0c61f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0c61f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa58, VA 0xffffffff8ac26918, JMP target 0xffffffff8b0cff00; Evidence ev_c623c0f8b415466250894a67fb7e2be03709b5cfaee0ceb9c9c93563086c2012 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0cff00); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0cff00(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa60, VA 0xffffffff8ac26920, JMP target 0xffffffff8b0cffb0; Evidence ev_eda00e7984a5e22a4690cfa74dd10b70788a443dfc5b1ef30ad9be044ec5a340 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0cffb0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0cffb0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa68, VA 0xffffffff8ac26928, JMP target 0xffffffff8b0d01c0; Evidence ev_dba6cb421c7ca748d854cd1021e43173606628a19d43ffb16a4ba3e9082f546b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0d01c0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0d01c0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa70, VA 0xffffffff8ac26930, JMP target 0xffffffff8b0d0320; Evidence ev_2983b793c20274f32c26f75e535d5b7f96d6b0ac448f96eb98caba4e87d8554f */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0d0320); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0d0320(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa78, VA 0xffffffff8ac26938, JMP target 0xffffffff8b0d2bb0; Evidence ev_e99f56c09d7c03f3e8d985f3404fce02639863a6bf65696403b1aa7cef0ef0a4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0d2bb0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0d2bb0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa80, VA 0xffffffff8ac26940, JMP target 0xffffffff8b0d6360; Evidence ev_94dcda567bb2f3dceead2c485ee9cec6438f3d0eec6d1959f7cc8ffd6ca2c752 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0d6360); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0d6360(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa88, VA 0xffffffff8ac26948, JMP target 0xffffffff8b0ef970; Evidence ev_880d45a02d40506a753b1ef3e421878cfdc4f5090fa075175cb9c1a43f58f897 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0ef970); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0ef970(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa90, VA 0xffffffff8ac26950, JMP target 0xffffffff8b0ef990; Evidence ev_fdbfb6c845e90bd16ec1dc1d85b658c9ac39e26ad14020102258be22fe06e0ac */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0ef990); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0ef990(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa98, VA 0xffffffff8ac26958, JMP target 0xffffffff8b0efa20; Evidence ev_cf5da2b1ed283089e2f7a0820eb040b5e1d36cc820ccedf1c52132dca8404679 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0efa20); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0efa20(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xaa0, VA 0xffffffff8ac26960, JMP target 0xffffffff8ac06e30; Evidence ev_c63fed6fafafbdb19b67e8a6ba3587d2bb4d45f19126f7db20ed48764d2d37f1 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ac06e30); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ac06e30(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xaa8, VA 0xffffffff8ac26968, JMP target 0xffffffff8b1247f0; Evidence ev_5218b1829e3c013a214903e9c4ceea7cb613a1f29022b959a2c5e7134201de32 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1247f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1247f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xab0, VA 0xffffffff8ac26970, JMP target 0xffffffff8b133710; Evidence ev_6c8dfdee95ce1eac92395588987737fad9bd8365cc3dfb1ef7587408e9cf6f0c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b133710); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b133710(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xab8, VA 0xffffffff8ac26978, JMP target 0xffffffff8b135950; Evidence ev_380b0b213f85981638ad196d6bfb516d480667e5c86804a0304e31d4c89553d6 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b135950); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b135950(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xac0, VA 0xffffffff8ac26980, JMP target 0xffffffff8b159e90; Evidence ev_fd23554ccee302a4965dd64cd52603fc97c7308b02d4f4fb633cd48eb7af96f6 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b159e90); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b159e90(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xac8, VA 0xffffffff8ac26988, JMP target 0xffffffff8b1731f0; Evidence ev_c3adcea299324933eda262b45335e7f76c40d2b80a0aed542f321b2b105d35f3 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1731f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1731f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xad0, VA 0xffffffff8ac26990, JMP target 0xffffffff8b1a23a0; Evidence ev_d394e65b17ba55b97cabefd9d5be249cac8144a67bd8971e665da57d69f1e7ab */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1a23a0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1a23a0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xad8, VA 0xffffffff8ac26998, JMP target 0xffffffff8b1a83e0; Evidence ev_e434fa7dedf6b0b193ef65f1f8772143dab0d3a6d82cf4cd9fc5069b6e831454 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1a83e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1a83e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xae0, VA 0xffffffff8ac269a0, JMP target 0xffffffff8b1a8480; Evidence ev_537c7d746fb9e5a180aca5dbf896f800ebd4f06d909ee7cb2470a9babbc409f5 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1a8480); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1a8480(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xae8, VA 0xffffffff8ac269a8, JMP target 0xffffffff8b5fb1b0; Evidence ev_3f50184960a7fde0d59b0653958b58e0d35d85e1bb81a207665546f95ad2efb4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b5fb1b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b5fb1b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xaf0, VA 0xffffffff8ac269b0, JMP target 0xffffffff8b5fc6e0; Evidence ev_b1162eabd0a31e031189111676a89e7b1984e56023049cf2cd83c02f5220a134 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b5fc6e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b5fc6e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xaf8, VA 0xffffffff8ac269b8, JMP target 0xffffffff8b5fc690; Evidence ev_4ea045b00018bc8e5e35f6167498698c92f19637a1f7a5832622fb5af406e04b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b5fc690); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b5fc690(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb00, VA 0xffffffff8ac269c0, JMP target 0xffffffff8b5fc730; Evidence ev_af64de49c02d6c270e9f1e66a30f7ba627c44a535ab5ab189a416f71451e6188 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b5fc730); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b5fc730(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb08, VA 0xffffffff8ac269c8, JMP target 0xffffffff8b1c2220; Evidence ev_77f1dfdc8b0011d8f7083dec4460533b400e90a203ffd514fe60947557d1c9a7 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1c2220); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1c2220(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb10, VA 0xffffffff8ac269d0, JMP target 0xffffffff8b1c24f0; Evidence ev_0250bc7fcf2882a813814bbaedb2fefe17688bda5a05e8ba118d1462d82b1d00 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1c24f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1c24f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb18, VA 0xffffffff8ac269d8, JMP target 0xffffffff8b1cc570; Evidence ev_7c329013869a28da423c1e231ab106690816c36fc6957b1b12f3a13f211a17c1 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1cc570); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1cc570(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb20, VA 0xffffffff8ac269e0, JMP target 0xffffffff8b1eb300; Evidence ev_561e25a8751062677ac2d7d021ae8377328e4c8fb7e97916025d2f281094a1ae */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1eb300); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1eb300(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb28, VA 0xffffffff8ac269e8, JMP target 0xffffffff8b2e0ee0; Evidence ev_8a9c5ab377f7d34b5b7a436c84a703f7252c885da2b99b578bb3902a1d822ae5 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2e0ee0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2e0ee0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb30, VA 0xffffffff8ac269f0, JMP target 0xffffffff8b2e0b90; Evidence ev_9cb02f501da7d499aac0e95b7b9cd3b137a146e7fcb7b13f71ce93209817f386 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2e0b90); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2e0b90(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb38, VA 0xffffffff8ac269f8, JMP target 0xffffffff8b1f0810; Evidence ev_15ccf9130b5eace5ef7225567f6fb82238348e0f29571509e6ac6ddf1f349998 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1f0810); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1f0810(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb40, VA 0xffffffff8ac26a00, JMP target 0xffffffff8b1f0f00; Evidence ev_e14f1be5e261b35bd2746220a9e03a96e5463205df60593ee94a6a584e190b6a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1f0f00); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1f0f00(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb48, VA 0xffffffff8ac26a08, JMP target 0xffffffff8b1f52b0; Evidence ev_dab1d6b71c579525b1d4050a4c38395818f2d82fe72886629fe12424ff02c1ff */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1f52b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1f52b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb50, VA 0xffffffff8ac26a10, JMP target 0xffffffff8b1f52c0; Evidence ev_71a6249ba9a4cc0464f51c689e31afb64c18ff38ca354ffb113f5c05412db787 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1f52c0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1f52c0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb58, VA 0xffffffff8ac26a18, JMP target 0xffffffff8b1f52d0; Evidence ev_15c393c2ae5e9062f8e41dfde7d4a559c17fea40cc53958d4f8452e37468fcad */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1f52d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1f52d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb60, VA 0xffffffff8ac26a20, JMP target 0xffffffff8b1f52f0; Evidence ev_2329540fb9c04cc624ea1c9c0beefd1391a7bd806dd9bef9025c2f2d6f1875da */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1f52f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1f52f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb68, VA 0xffffffff8ac26a28, JMP target 0xffffffff8b1f5440; Evidence ev_4d58464f5f61b4e3e15fc9b56894a8462de20b7d2d81d5deff7c863ef20431b7 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1f5440); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1f5440(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb70, VA 0xffffffff8ac26a30, JMP target 0xffffffff8b1f5450; Evidence ev_61670b38c0e4421c70d29f4f9e489a4663d617313ab059fad63a838cdd224340 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1f5450); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1f5450(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb78, VA 0xffffffff8ac26a38, JMP target 0xffffffff8b1f5490; Evidence ev_e6278b9916b78bf7f839bf9e668074c768d83c976f638ff322a0d034b25ee244 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1f5490); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1f5490(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb80, VA 0xffffffff8ac26a40, JMP target 0xffffffff8b1f5ad0; Evidence ev_d0c90d50f61fac251182751741ec7bf084ae3bbd14298c410d1ff9317f82172a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1f5ad0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1f5ad0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb88, VA 0xffffffff8ac26a48, JMP target 0xffffffff8b210870; Evidence ev_07965de8f4dfe6031923dcf145d085969a602c4c176ad93ec0f39f4b5569b43d */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b210870); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b210870(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb90, VA 0xffffffff8ac26a50, JMP target 0xffffffff8b2302f0; Evidence ev_29bad9782862e236093c177c1cd06fe379f3b5cf586c82567e6650c6cb2cf646 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2302f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2302f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb98, VA 0xffffffff8ac26a58, JMP target 0xffffffff8b2305d0; Evidence ev_91ad3c5f75918a1cda4190b3727daf8efab7194915e73ad6c589168ec6b496b1 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2305d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2305d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xba0, VA 0xffffffff8ac26a60, JMP target 0xffffffff8b232af0; Evidence ev_2d27e3e3a4792c15efb09365e5df85c859fc5b9c38ad5abddffb6903799b1585 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b232af0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b232af0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xba8, VA 0xffffffff8ac26a68, JMP target 0xffffffff8b233800; Evidence ev_6264d2e2041d0845be20ecf31282310de201c658cf77ec198a30112c8efaaa8e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b233800); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b233800(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xbb0, VA 0xffffffff8ac26a70, JMP target 0xffffffff8aa23a40; Evidence ev_6307710a7f0b37dfaad628aea6515308857a256852c1fc7ba50b35703bef62b4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aa23a40); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aa23a40(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xbb8, VA 0xffffffff8ac26a78, JMP target 0xffffffff8aa26370; Evidence ev_0e3b3b407b667654d076073bf9a8b0e81d42c98b6774cd174bdde1362c16fd25 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aa26370); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aa26370(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xbc0, VA 0xffffffff8ac26a80, JMP target 0xffffffff8aaa6590; Evidence ev_92d3aadeb7aa05e5ba828c2ee6a069661a3dac53ef416d4384f8f8b5687f657b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aaa6590); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aaa6590(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xbc8, VA 0xffffffff8ac26a88, JMP target 0xffffffff8aaa65a0; Evidence ev_13d49cf4a40584f7522c0aac4dba7864ff1db2408f3046f9ecfdb545c93d2659 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aaa65a0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aaa65a0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xbd0, VA 0xffffffff8ac26a90, JMP target 0xffffffff8aaa6760; Evidence ev_cad59b7e21038d51297e290068a6c624486beb3a424f5508a463145b7050271b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aaa6760); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aaa6760(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xbd8, VA 0xffffffff8ac26a98, JMP target 0xffffffff8aaa6870; Evidence ev_1a465db35b7a018d2734fe2303ebebe1ffd9a5f2ad45db664c583b61e196afac */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aaa6870); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aaa6870(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xbe0, VA 0xffffffff8ac26aa0, JMP target 0xffffffff8aaa7f90; Evidence ev_16c71e73e6cae210cf73d93c9f8ad958783c78c2127d4158fcd14644c71d4121 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aaa7f90); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aaa7f90(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xbe8, VA 0xffffffff8ac26aa8, JMP target 0xffffffff8aaa9fa0; Evidence ev_df17df03a859421e3cb01837428523661cfa8adc0b1e89c6d7e2f98378373120 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aaa9fa0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aaa9fa0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xbf0, VA 0xffffffff8ac26ab0, JMP target 0xffffffff8aaaa670; Evidence ev_f210a6cba06c293b57e6d3f36f4495db5b38af410dfa3d781e2d1b7d08e2a36b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aaaa670); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aaaa670(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xbf8, VA 0xffffffff8ac26ab8, JMP target 0xffffffff8aaaa760; Evidence ev_aed8ed510e6b59cd94abd0161038f030ee618eae479d94c8b200b3176523a62f */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aaaa760); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aaaa760(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc00, VA 0xffffffff8ac26ac0, JMP target 0xffffffff8aaab0a0; Evidence ev_b5e233233ab1f5be308ebb4c4ed7acbd455be241a53e78bfc2dd6d9bd658c652 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aaab0a0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aaab0a0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc08, VA 0xffffffff8ac26ac8, JMP target 0xffffffff8aaab190; Evidence ev_1751a71f7fc5995ce29982716a8f86b5f58772b81c9d91fcfab3bbe532d199c2 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aaab190); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aaab190(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc10, VA 0xffffffff8ac26ad0, JMP target 0xffffffff8aaad000; Evidence ev_664d2687841e7ae3e5730e71f05db42073f5a25f41f64124c85982f90da42654 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aaad000); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aaad000(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc18, VA 0xffffffff8ac26ad8, JMP target 0xffffffff8aaad110; Evidence ev_942be2cbe5c96012c0f16369418ddf103f079f7fad9dd4ef2237449032483dec */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aaad110); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aaad110(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc20, VA 0xffffffff8ac26ae0, JMP target 0xffffffff8b24a8a0; Evidence ev_31b0d798c494c2c7f0734ae2935c7f16e2bf386734c299c40a2d2aaa9d4cd6cc */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b24a8a0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b24a8a0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc28, VA 0xffffffff8ac26ae8, JMP target 0xffffffff8b25cdf0; Evidence ev_22e332d6b175f762330fea8e80f9bc0a40bb252c4c8eab218ac1139ca89d8691 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b25cdf0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b25cdf0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc30, VA 0xffffffff8ac26af0, JMP target 0xffffffff8aaaeb50; Evidence ev_b7eeddefb363b5790835d62ade74e87d67c3c3e5c751c59edd93b2ee9a835193 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aaaeb50); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aaaeb50(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc38, VA 0xffffffff8ac26af8, JMP target 0xffffffff8b28b250; Evidence ev_ca7b30f75794ae6b65f25ddc2072a459f0cee4a7685591c349401121295d05e5 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b28b250); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b28b250(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc40, VA 0xffffffff8ac26b00, JMP target 0xffffffff8b28b390; Evidence ev_d6fbf33cfe42fd43ecccb9adc66f3174a552057b7c4fcc6d423f21768a7630ec */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b28b390); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b28b390(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc48, VA 0xffffffff8ac26b08, JMP target 0xffffffff8b292f60; Evidence ev_a5a9b6e6902387eb24dd1afdecd150943013b5f0f26eca0003a62d4a5c581c97 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b292f60); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void sub_8d2f60(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc50, VA 0xffffffff8ac26b10, JMP target 0xffffffff8b292f90; Evidence ev_2701769d9f17f1002311fb8b456094319b88ddf79c21b26e82afa893b7616ac6 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b292f90); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void sub_8d2f90(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc58, VA 0xffffffff8ac26b18, JMP target 0xffffffff8b298230; Evidence ev_690200d6b3e5649ba213f1b359358e238b1ac346ed79ea076718442924728571 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b298230); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b298230(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc60, VA 0xffffffff8ac26b20, JMP target 0xffffffff8b298de0; Evidence ev_5b1734fc2604d2f0647da3fed0c625b33e23ab352b8d7da4b388fd31fe6033e3 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b298de0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b298de0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc68, VA 0xffffffff8ac26b28, JMP target 0xffffffff8b2997b0; Evidence ev_7c3d0b5ec91035899ada76deb9b3c227d1ae868f6ef0c7649a0041c826792112 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2997b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2997b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc70, VA 0xffffffff8ac26b30, JMP target 0xffffffff8b299910; Evidence ev_fc791bc5f07569cf2f24747c53eb7ae8d7cd46358dfbf16c0f211a47c8adddf6 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b299910); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b299910(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc78, VA 0xffffffff8ac26b38, JMP target 0xffffffff8b29a4c0; Evidence ev_a9cea4c7a8c7dee7cc62fef3459d371795ba0c88573929e1274d6a25f537fa6d */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b29a4c0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b29a4c0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc80, VA 0xffffffff8ac26b40, JMP target 0xffffffff8b29a570; Evidence ev_6f3207bbf556266fc8ff0dc9e9400d0cfc3e0b525bf7418405b4c4d0766c1eb7 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b29a570); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b29a570(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc88, VA 0xffffffff8ac26b48, JMP target 0xffffffff8b29a5b0; Evidence ev_fe180a92c151270e33564f432a65861b881fd3446ff9168b7cbad80123108252 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b29a5b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b29a5b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc90, VA 0xffffffff8ac26b50, JMP target 0xffffffff8b2c4c80; Evidence ev_675e320e86c1cc82573aff9743d38355c16742b48125b384bf20e587ffde3dbe */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2c4c80); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2c4c80(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc98, VA 0xffffffff8ac26b58, JMP target 0xffffffff8b2c4e60; Evidence ev_ca747411fd5634d245636a31f2e9502aae8a2a4248ad435361d810aa6cd86c82 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2c4e60); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2c4e60(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xca0, VA 0xffffffff8ac26b60, JMP target 0xffffffff8b2dd400; Evidence ev_bc1504447a5442e42a13ed0ce0d3f80bf712c3fb5c43ac0b13f1c352f54605a3 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2dd400); register/stack arguments unchanged. */

undefined8 sub_91d400(void)

{
  return 0x2d;
}



/* Input +0xca8, VA 0xffffffff8ac26b68, JMP target 0xffffffff8b2dd4a0; Evidence ev_0a670b7fdce0d79e049b3d7e42b0c1e7e65ace8ec19f40d95274e63378164a0a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2dd4a0); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_91d4a0(long *param_1)

{
  int *piVar1;
  int iVar2;
  undefined8 *puVar3;
  
  puVar3 = (undefined8 *)*param_1;
  *param_1 = 0;
  LOCK();
  piVar1 = (int *)((long)puVar3 + 0x14);
  iVar2 = *piVar1;
  *piVar1 = *piVar1 + -1;
  UNLOCK();
  if (iVar2 == 1) {
    func_0xffffffff8ae21ba0(*puVar3);
    func_0xffffffff8adfc0c0(_DAT_ffffffff8e536968,puVar3,0);
  }
  return 0;
}



/* Input +0xcb0, VA 0xffffffff8ac26b70, JMP target 0xffffffff8b4421d0; Evidence ev_9199c8bae018e2e46b6aafea933b75fb5d12a6379f5b233d18e206d8fc3947ef */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b4421d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b4421d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xcb8, VA 0xffffffff8ac26b78, JMP target 0xffffffff8b502120; Evidence ev_26c837679dc93ba9bd1cdf4253704b982abd9bf2e5d9e5816710df300648d353 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b502120); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b502120(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xcc0, VA 0xffffffff8ac26b80, JMP target 0xffffffff8b324f30; Evidence ev_5153df29243a838bb5be8cf2ce4ecf725d512d9c606bcae76038786cad0d4e7c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b324f30); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b324f30(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xcc8, VA 0xffffffff8ac26b88, JMP target 0xffffffff8b335f50; Evidence ev_0b10fe9907b74c8e19e08a6f441593902558e1594e62118c18378bebe563e93e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b335f50); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b335f50(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xcd0, VA 0xffffffff8ac26b90, JMP target 0xffffffff8b336200; Evidence ev_c02c3d1919edde812d91fdb2787e6e34746678871f5bcd3340001e70c5df3379 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b336200); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b336200(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xcd8, VA 0xffffffff8ac26b98, JMP target 0xffffffff8b34c950; Evidence ev_cbc90ffdfef4f5fdf5c46eda2b1da677aafacd997a5d706086c3bc3dd9676698 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b34c950); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b34c950(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xce0, VA 0xffffffff8ac26ba0, JMP target 0xffffffff8b34cc30; Evidence ev_368637e9a01f5adb85f3648705c437c1f59246d3627cd3cc5f5153a0d27312d5 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b34cc30); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b34cc30(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xce8, VA 0xffffffff8ac26ba8, JMP target 0xffffffff8b34cf30; Evidence ev_9c90db884fcff9773d410a3d69aaae8d6f3b7a1c389f684fa5ed16a147bcd863 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b34cf30); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b34cf30(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xcf0, VA 0xffffffff8ac26bb0, JMP target 0xffffffff8b34d6e0; Evidence ev_6ff76dd0ac537fc1fcdac4ccf69410585e8fd0c81aca0311dc193814b241c595 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b34d6e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b34d6e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xcf8, VA 0xffffffff8ac26bb8, JMP target 0xffffffff8b34e5d0; Evidence ev_4de5f0f5541fb61b0632c78b262b8a41a51287b3c2193077037a68a321d6dbd5 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b34e5d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b34e5d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd00, VA 0xffffffff8ac26bc0, JMP target 0xffffffff8b34e700; Evidence ev_d4020cae27352d1fcf55c62ec463245ef41551acfd6541301051390fac01e231 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b34e700); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b34e700(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd08, VA 0xffffffff8ac26bc8, JMP target 0xffffffff8b352170; Evidence ev_a97036e1a7f86682ffff30109303fd6da16b79ea89750b067979c593568442af */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b352170); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b352170(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd10, VA 0xffffffff8ac26bd0, JMP target 0xffffffff8b352240; Evidence ev_f4ddd2dfc0a4b2edaa44f3465918bb42bb7c7ec78bddd7f7136098e958a3d973 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b352240); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b352240(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd18, VA 0xffffffff8ac26bd8, JMP target 0xffffffff8aab5400; Evidence ev_1cbf5e17b8276dfc8b663eb6a23bffbfa92e7418b0858322705468770c8ba997 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aab5400); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aab5400(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd20, VA 0xffffffff8ac26be0, JMP target 0xffffffff8b362320; Evidence ev_841c03dab6fa08561b946d0c57cca78ccb7857029fb3a696ac9a1ac7f07c013c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b362320); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b362320(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd28, VA 0xffffffff8ac26be8, JMP target 0xffffffff8b365720; Evidence ev_f121363b6d1c30f9c5836f7cc45aa054540d7065d7a7dc91a75c71f303cf8d90 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b365720); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b365720(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd30, VA 0xffffffff8ac26bf0, JMP target 0xffffffff8b36c9a0; Evidence ev_7020c8e249acc9f1bd9c7c4d358ec09d14d2ee25b2725b52fea2251196f5ad26 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b36c9a0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b36c9a0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd38, VA 0xffffffff8ac26bf8, JMP target 0xffffffff8b36ca20; Evidence ev_6467904eb2f3425af48e7e364ec1867f7bfeb739f61612649bf2a44765126f8e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b36ca20); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b36ca20(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd40, VA 0xffffffff8ac26c00, JMP target 0xffffffff8ab7e640; Evidence ev_3e51c26ccde968d5d74df4f5c4e77a1d48bd22cc2ba297395598ae1664b12640 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ab7e640); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ab7e640(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd48, VA 0xffffffff8ac26c08, JMP target 0xffffffff8b37ed20; Evidence ev_fe885aa584d04dd099f632765c23f112954ff2aaa907ad560810dbf53f87c232 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b37ed20); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b37ed20(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd50, VA 0xffffffff8ac26c10, JMP target 0xffffffff8b386050; Evidence ev_42a5cb8f181a8cda4a439f504fa6c4238918482ce880d8b043c8fefe567651e2 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b386050); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b386050(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd58, VA 0xffffffff8ac26c18, JMP target 0xffffffff8b3860d0; Evidence ev_d6dadd8a43d06b3fe4dc570e44cd4b101536fc7618017dad299b054a048c9b1b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3860d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3860d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd60, VA 0xffffffff8ac26c20, JMP target 0xffffffff8b386280; Evidence ev_70a95ffaba35bc11428132b74827dc7ebea43542a10f29d965375a405c10cab6 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b386280); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b386280(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd68, VA 0xffffffff8ac26c28, JMP target 0xffffffff8b386310; Evidence ev_c1c362da98b5156f8af42b287a87ab552d52e9680abfbcc4d36d8dca376b4041 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b386310); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b386310(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd70, VA 0xffffffff8ac26c30, JMP target 0xffffffff8b386490; Evidence ev_0a654fdd484fb64cf1b47ce6026c917973f83484019f7ad0eb2fd98f310a142c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b386490); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b386490(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd78, VA 0xffffffff8ac26c38, JMP target 0xffffffff8b3865b0; Evidence ev_640accf1bb2e909af536d0e279670a829c55a0fd4f58ce952b5f7c44b31e5252 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3865b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3865b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd80, VA 0xffffffff8ac26c40, JMP target 0xffffffff8b386890; Evidence ev_837ba81442081e4c3935ff5e67dbdeae34e08d08d7a26e2d4954fd238a29f9bd */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b386890); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b386890(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd88, VA 0xffffffff8ac26c48, JMP target 0xffffffff8b389340; Evidence ev_302003d46488a51c6896167477c7a5307f3f3d1a3950f6d2a36e581231efa097 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b389340); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b389340(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd90, VA 0xffffffff8ac26c50, JMP target 0xffffffff8b389360; Evidence ev_e49abbc980bc2bb0976455607eadb29cfe3b87d0f11dd959682aee63b1abd894 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b389360); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b389360(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd98, VA 0xffffffff8ac26c58, JMP target 0xffffffff8b389370; Evidence ev_f3fbb2c3ce1b57c251a9ec31968882e64223fdd9135e653424b51cab8ae00879 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b389370); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b389370(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xda0, VA 0xffffffff8ac26c60, JMP target 0xffffffff8b389380; Evidence ev_939a0134a712e2e14df8c956e10d7ee5b0bb1adcf51195805ad11552dcb6690c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b389380); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b389380(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xda8, VA 0xffffffff8ac26c68, JMP target 0xffffffff8b39adb0; Evidence ev_7e36300e78fee634eac0516fc6eade178c5cf3feee33d7048cef60456253c98a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b39adb0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b39adb0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xdb0, VA 0xffffffff8ac26c70, JMP target 0xffffffff8b39afa0; Evidence ev_6b99bfb98c687dc812a233cb55e509ba096128f17139315a2c85de71799d0b1c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b39afa0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b39afa0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xdb8, VA 0xffffffff8ac26c78, JMP target 0xffffffff8b39c860; Evidence ev_cb964a9f5d01fb5f22e75932234f38882143ae3f8f70b3408423172c4e792420 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b39c860); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b39c860(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xdc0, VA 0xffffffff8ac26c80, JMP target 0xffffffff8b39cc40; Evidence ev_d44dc4c35c83cd9c7dc0bb1e462fa2f82dd5e6db345aef4608640e68c12b9c30 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b39cc40); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b39cc40(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xdc8, VA 0xffffffff8ac26c88, JMP target 0xffffffff8b39ce80; Evidence ev_becbb7fe76066a03e4ef80123cd6ac45f262abb81a68f7fe83c0e6559adbd9fd */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b39ce80); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b39ce80(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xdd0, VA 0xffffffff8ac26c90, JMP target 0xffffffff8b39d500; Evidence ev_da8ccdbac499e936af61824fe0fa4369bc3d3671546329fe3fcca0378583ed8a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b39d500); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b39d500(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xdd8, VA 0xffffffff8ac26c98, JMP target 0xffffffff8b66acd0; Evidence ev_72828366f712f9ae3820a22b9cd94cbdfce57c0264de1d5b9a439dd3aa1a7c1b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b66acd0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b66acd0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xde0, VA 0xffffffff8ac26ca0, JMP target 0xffffffff8b39d7d0; Evidence ev_08eb82d84e176db98f9a9cf2f492601de477aa7291aed06e047665f41161f283 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b39d7d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b39d7d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xde8, VA 0xffffffff8ac26ca8, JMP target 0xffffffff8b39d990; Evidence ev_9082c7a979be0f0fd603c96e361e80cafc731ce9432bf1e4ed4760bd8845f16b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b39d990); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b39d990(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xdf0, VA 0xffffffff8ac26cb0, JMP target 0xffffffff8b39dba0; Evidence ev_5819c3350f7fa4afb7bf257e69069494f7a4f546f9c6da81f1551f87236d56f0 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b39dba0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b39dba0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xdf8, VA 0xffffffff8ac26cb8, JMP target 0xffffffff8b39dc00; Evidence ev_e5de25104047e1eabff93db22690d233a88cbe42f2a66eda08e2ed656ac1d799 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b39dc00); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b39dc00(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe00, VA 0xffffffff8ac26cc0, JMP target 0xffffffff8b39de50; Evidence ev_464aa8b2f5af7d7a8c9487a998ff6a565c56d53d218ab821936d2dbc3390aca9 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b39de50); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b39de50(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe08, VA 0xffffffff8ac26cc8, JMP target 0xffffffff8b39deb0; Evidence ev_e9397c55966ed8ea9f9c1e998cd1478add64b59f4bfb5285d149ffdaa73a43b5 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b39deb0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b39deb0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe10, VA 0xffffffff8ac26cd0, JMP target 0xffffffff8b39dff0; Evidence ev_8e9345616b8575d5e642caff84b9af829e769a84e56a85910f8f8da209bd36bb */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b39dff0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b39dff0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe18, VA 0xffffffff8ac26cd8, JMP target 0xffffffff8b39e070; Evidence ev_6dd021d887e85f1f3f9768657cdf33553471bb9b77d2e1cf6112eb4547a970d0 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b39e070); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b39e070(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe20, VA 0xffffffff8ac26ce0, JMP target 0xffffffff8b39e0f0; Evidence ev_1eff31fff05dc2b28e8f472b914990fab1952ad58a0fce0129f6ccb1a64396b5 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b39e0f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b39e0f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe28, VA 0xffffffff8ac26ce8, JMP target 0xffffffff8b3a0b90; Evidence ev_7eeff8362c911792a5e4f07d0c87114d8b5cd56cbdd43256baaaef7f4779c3e1 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3a0b90); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3a0b90(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe30, VA 0xffffffff8ac26cf0, JMP target 0xffffffff8b3a0cd0; Evidence ev_c2fbed464afff3d6168d48f03fe87cabb17a1463b5fbf32f78d01cbb4398c623 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3a0cd0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3a0cd0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe38, VA 0xffffffff8ac26cf8, JMP target 0xffffffff8b3a0d70; Evidence ev_611aaa05d2745814fa7bcb1bf92c17c3ec9f06fb65e40731cd4a27780112beda */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3a0d70); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3a0d70(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe40, VA 0xffffffff8ac26d00, JMP target 0xffffffff8b3a0ef0; Evidence ev_6e9f1209185942101b81e6fa3d14c40192cc8165b75ef63aa7536a7f42f92440 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3a0ef0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3a0ef0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe48, VA 0xffffffff8ac26d08, JMP target 0xffffffff8b3a1050; Evidence ev_8c588543e30291d3ba2f3d06219e42431894ecaf8d7a1b725bd67b061ba2edc1 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3a1050); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3a1050(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe50, VA 0xffffffff8ac26d10, JMP target 0xffffffff8b3a1490; Evidence ev_6bd549850171039a78557a0177dc5b07c5b9de7ff658d8ae64efb69ff6522a6a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3a1490); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3a1490(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe58, VA 0xffffffff8ac26d18, JMP target 0xffffffff8b3c65e0; Evidence ev_6f4875796be2893cfd04d40930553712ec03f176f9f0697e84978ba0eac80344 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3c65e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3c65e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe60, VA 0xffffffff8ac26d20, JMP target 0xffffffff8aac1340; Evidence ev_1f27066ee22fd5b8855bda2c6645012dec02b181cfc8f088419d739a00350a67 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aac1340); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aac1340(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe68, VA 0xffffffff8ac26d28, JMP target 0xffffffff8b3f2f30; Evidence ev_c39ea14bbcd1d0e857c6372ea4623e7339d95cc91c930ac0220537fcc5963b74 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3f2f30); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3f2f30(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe70, VA 0xffffffff8ac26d30, JMP target 0xffffffff8b3f36c0; Evidence ev_15b1d41231243f7f396c958091598c202c1af8455a969a06763d7180bf64e786 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3f36c0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3f36c0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe78, VA 0xffffffff8ac26d38, JMP target 0xffffffff8b3f8c90; Evidence ev_aa5f24acefefa0f4e8807eeb279458513a5117a6dddfd791c17ad7ea08605761 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3f8c90); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_a38c90(long param_1,undefined4 *param_2)

{
  long lVar1;
  undefined4 *puVar2;
  code *pcVar3;
  int iVar4;
  undefined8 uStack_30;
  long lStack_28;
  
  lStack_28 = _DAT_ffffffff8e2dc310;
  lVar1 = *(long *)(param_1 + 0x298);
  puVar2 = *(undefined4 **)(lVar1 + 0x30);
  *param_2 = *puVar2;
  *(ulong *)(param_2 + 4) = (ulong)(uint)puVar2[8];
  *(ulong *)(param_2 + 6) = (ulong)(uint)puVar2[8];
  *(undefined8 *)(param_2 + 8) = *(undefined8 *)(puVar2 + 0xe);
  iVar4 = func_0xffffffff8b2ea2b0(lVar1,&uStack_30);
  if (iVar4 == 0) {
    *(undefined8 *)(param_2 + 10) = uStack_30;
    *(undefined8 *)(param_2 + 0xc) = uStack_30;
  }
  else {
    func_0xffffffff8ac1d410(0xffffffff8bd70bb2,0xffffffff8bd070a9,0x11bf,iVar4,iVar4);
  }
  if (_DAT_ffffffff8e2dc310 == lStack_28) {
    return iVar4;
  }
  func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
  pcVar3 = (code *)invalidInstructionException();
  (*pcVar3)();
}



/* Input +0xe80, VA 0xffffffff8ac26d40, JMP target 0xffffffff8b42ab00; Evidence ev_3e3dd98b1db8091e725a1171eb871dee9a04425ccc910a875e7cbb6543fb6775 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b42ab00); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b42ab00(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe88, VA 0xffffffff8ac26d48, JMP target 0xffffffff8b42abb0; Evidence ev_2cde1d005f11d794750ce54d181b73b456934ec42cc43cf0086c52d7de938918 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b42abb0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b42abb0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe90, VA 0xffffffff8ac26d50, JMP target 0xffffffff8b44ec10; Evidence ev_b55767ddd3a9f36d07b3db41bdc3bea0693eb7b0234e01482938ff03525824fe */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b44ec10); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b44ec10(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe98, VA 0xffffffff8ac26d58, JMP target 0xffffffff8b44ee00; Evidence ev_70664c71dd3a224bf7f445018076f4d68292e59f7470a3c4445c08a55285a544 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b44ee00); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b44ee00(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xea0, VA 0xffffffff8ac26d60, JMP target 0xffffffff8b4717b0; Evidence ev_50617a4f06d4d8bc8154216c7f9051a77fc559e43d455bb9e3121dda9584d191 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b4717b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b4717b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xea8, VA 0xffffffff8ac26d68, JMP target 0xffffffff8b4807b0; Evidence ev_58ee5421fea4f39f34955553b909e9c3449295d786f327a1b924fee0b2ae06cd */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b4807b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b4807b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xeb0, VA 0xffffffff8ac26d70, JMP target 0xffffffff8b482af0; Evidence ev_59b0c27dad55bdaa6f8481bef246584aa65264e1514ac61236bc8ff2910dc0ff */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b482af0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b482af0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xeb8, VA 0xffffffff8ac26d78, JMP target 0xffffffff8aada750; Evidence ev_e80e36fb316a3fa9ae44910fbc7f3ca7a6286dd5f365a7aec3d52c3cdc0c3a46 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aada750); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aada750(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xec0, VA 0xffffffff8ac26d80, JMP target 0xffffffff8b4a12a0; Evidence ev_26ca38857aa68db897e20082346284738bd9a5ff1be676887fc2d800ab270a75 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b4a12a0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b4a12a0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xec8, VA 0xffffffff8ac26d88, JMP target 0xffffffff8b4a3400; Evidence ev_1745926dd3238375cd948c46cc1906661ec7058298ee8301a3c9c59e21711b11 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b4a3400); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b4a3400(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xed0, VA 0xffffffff8ac26d90, JMP target 0xffffffff8b4a3530; Evidence ev_04b6b3faacf12903582dcab8dfb30397b83a14b4743726d7721fa149b3e826eb */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b4a3530); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b4a3530(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xed8, VA 0xffffffff8ac26d98, JMP target 0xffffffff8b4a63c0; Evidence ev_c9de50f3d022f5a5d7f9cd2c558f7df766c8235d5364a1c16c476e1831027230 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b4a63c0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b4a63c0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xee0, VA 0xffffffff8ac26da0, JMP target 0xffffffff8b4c7ee0; Evidence ev_f47ab98e1f0296fa4bd1208d8a18963bc1eecbbcaa13fbc70f6d2666578cc668 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b4c7ee0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b4c7ee0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xee8, VA 0xffffffff8ac26da8, JMP target 0xffffffff8b4c8190; Evidence ev_c63b9a39ef9aca6b690cd9f47d65fe15ad2e035958b069b0d3586a80f3927232 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b4c8190); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b4c8190(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xef0, VA 0xffffffff8ac26db0, JMP target 0xffffffff8b4c8530; Evidence ev_e3662be72f478684cd15793aa21bde14d1087f55fdea5538b8addedaf7975bfc */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b4c8530); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b4c8530(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xef8, VA 0xffffffff8ac26db8, JMP target 0xffffffff8b4c8810; Evidence ev_4c4bc82be9961577b35681fcfbdce463982382dae122787763d3daff9a7ddb0a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b4c8810); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b4c8810(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf00, VA 0xffffffff8ac26dc0, JMP target 0xffffffff8b4c96a0; Evidence ev_e76e61b7f91d2ff87fcd90050728e5bc1b08cacdd1ff00b7e6a0ae75f8e700cf */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b4c96a0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b4c96a0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf08, VA 0xffffffff8ac26dc8, JMP target 0xffffffff8b4cb4f0; Evidence ev_d58ef58f716b0bae5ecc15640de4315bca4655392d92611dc196aa90422b1d61 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b4cb4f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b4cb4f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf10, VA 0xffffffff8ac26dd0, JMP target 0xffffffff8abaf0f0; Evidence ev_41fcbb20e7a42d17f02130be170e5bb9acf109b212f0c969fadeb9cdda63e21d */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8abaf0f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8abaf0f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf18, VA 0xffffffff8ac26dd8, JMP target 0xffffffff8abb0060; Evidence ev_4f7fd5650ea1a1e6dc0c7ad9c05193a967492fe2e9e28936ff28ea62e4948565 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8abb0060); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8abb0060(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf20, VA 0xffffffff8ac26de0, JMP target 0xffffffff8aadb9b0; Evidence ev_4b5018fcb3d380d19c8d909879882a061fe1aa61ec221717417a552855ae4339 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aadb9b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aadb9b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf28, VA 0xffffffff8ac26de8, JMP target 0xffffffff8b4fb130; Evidence ev_5db668decf14719027cac7d44ff0914e2a3261cc9c97e67e61ea7d5a39da5679 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b4fb130); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b4fb130(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf30, VA 0xffffffff8ac26df0, JMP target 0xffffffff8b507a40; Evidence ev_e6f15c2c9a5bfe40f96456913212da08fa64be313b567d083e3761913a32bdba */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b507a40); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b507a40(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf38, VA 0xffffffff8ac26df8, JMP target 0xffffffff8b5103c0; Evidence ev_44dbd99e2f7181c5eaa6e552acad4c4e08ca325b6d65b42adf561ee4b0ea219d */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b5103c0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b5103c0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf40, VA 0xffffffff8ac26e00, JMP target 0xffffffff8b510f10; Evidence ev_63587262d96bec2409ac759173275904583f865df56e4bbe9d45be78bc6e2e9d */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b510f10); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b510f10(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf48, VA 0xffffffff8ac26e08, JMP target 0xffffffff8b510fb0; Evidence ev_f7a13e74362d0cb22cb02d84f4e6f7a1c1667a24047ca0b867e8f62a93cd4cf9 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b510fb0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b510fb0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf50, VA 0xffffffff8ac26e10, JMP target 0xffffffff8b5110b0; Evidence ev_17eca24495bc3d03357856f2e3ce53a1147169d9f276575592da2d95b28622da */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b5110b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b5110b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf58, VA 0xffffffff8ac26e18, JMP target 0xffffffff8b511190; Evidence ev_c32a5b9af057df7641e4547732028ec4cb7e82b21cc9a06992013445efd03c96 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b511190); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b511190(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf60, VA 0xffffffff8ac26e20, JMP target 0xffffffff8b511290; Evidence ev_494b76f236bca2645bbcc0f97000077130a730a49952ac13ed034d68ab11a8cc */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b511290); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b511290(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf68, VA 0xffffffff8ac26e28, JMP target 0xffffffff8b5112d0; Evidence ev_50c58277999fc36eafed4af58f50e2c744b7bbc6bdb5189dc43b6b1cdd181c6a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b5112d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b5112d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf70, VA 0xffffffff8ac26e30, JMP target 0xffffffff8b511320; Evidence ev_66bee042e53883d3c2fdd32cbab73b44ad658a40758a73365e78452d45c4df44 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b511320); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b511320(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf78, VA 0xffffffff8ac26e38, JMP target 0xffffffff8b5168a0; Evidence ev_41e9c4f90554d8fb32c228674a34ea0c006b4032d1b8e954dfee3b3b8c7cf6c6 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b5168a0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b5168a0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf80, VA 0xffffffff8ac26e40, JMP target 0xffffffff8aa5a0e0; Evidence ev_ed1adc45d430a79f6cc7b1969a2fb4756b3884b9cb4ff16ed2d2d42014e20106 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aa5a0e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aa5a0e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf88, VA 0xffffffff8ac26e48, JMP target 0xffffffff8b52ae70; Evidence ev_cf8e43d9e123b30b4c500d4a1d33b1a83a111f1d75a052eba1ca0cc89164b7a9 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b52ae70); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b52ae70(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf90, VA 0xffffffff8ac26e50, JMP target 0xffffffff8b52bb90; Evidence ev_c3bceb15548f19947262cffb71ac5fdf7372ef716960ee1f4b27efdf6318b99f */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b52bb90); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b52bb90(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf98, VA 0xffffffff8ac26e58, JMP target 0xffffffff8b52d980; Evidence ev_98667bcf70ecaf32809f86b266e1efe2034ec05235b0c7250a24442e8f47fd10 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b52d980); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b52d980(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xfa0, VA 0xffffffff8ac26e60, JMP target 0xffffffff8b52daa0; Evidence ev_e30585f7668426b28e590ec9656dd1cb49c89edb8b8b4eb652a1ac851ae3e11b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b52daa0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b52daa0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xfa8, VA 0xffffffff8ac26e68, JMP target 0xffffffff8b52e180; Evidence ev_2778f66bd8035b40ca712bf8893d061c3eca36609fb8494a74236c75301132a8 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b52e180); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b52e180(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xfb0, VA 0xffffffff8ac26e70, JMP target 0xffffffff8b531320; Evidence ev_1b5365291822c0e7d3d07c62ee2cbbbbb04887ab2231d0870c8a9887d74cc072 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b531320); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b531320(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xfb8, VA 0xffffffff8ac26e78, JMP target 0xffffffff8b531370; Evidence ev_d7605fd1d47cab7258ca983985016ab960832ff9fc39e164b7b305599d7c8ae6 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b531370); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b531370(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xfc0, VA 0xffffffff8ac26e80, JMP target 0xffffffff8b5313c0; Evidence ev_f599764f769514512a6c6103d689083e64b9d91ae57534574a619e7e4082fcae */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b5313c0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b5313c0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xfc8, VA 0xffffffff8ac26e88, JMP target 0xffffffff8b531410; Evidence ev_7736ffb528ff3c01da97b6760c3ece378ef7015513ebbca3c10b11be5c0caa03 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b531410); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b531410(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xfd0, VA 0xffffffff8ac26e90, JMP target 0xffffffff8b531960; Evidence ev_68bffb53d54890dd79dd5a5e85c62a468189460209d9d7ca60848c25b1230295 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b531960); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b531960(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xfd8, VA 0xffffffff8ac26e98, JMP target 0xffffffff8b5319d0; Evidence ev_ca462e22a857ec18fcb94b93225b65595769d84fbd54a8e683b57b1f76bc0a9f */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b5319d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b5319d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xfe0, VA 0xffffffff8ac26ea0, JMP target 0xffffffff8b531a40; Evidence ev_602b7e5255aa96fc128c3ebff952e73ab41c2683df8b7beae9d8b40cdee16d80 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b531a40); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b531a40(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xfe8, VA 0xffffffff8ac26ea8, JMP target 0xffffffff8b531ab0; Evidence ev_6658ca55d2497cfeb134001169b01fd47afc851c9e025357c930847eaf8a7996 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b531ab0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b531ab0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xff0, VA 0xffffffff8ac26eb0, JMP target 0xffffffff8b532620; Evidence ev_ab1cb56b50bd67247e15bd44a40998e9f86cfeb835ca18986df61f40c9206b9f */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b532620); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b532620(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xff8, VA 0xffffffff8ac26eb8, JMP target 0xffffffff8b532860; Evidence ev_e699fa36671a4f5c9aae9f964510df1d098de73f73632711f752a4ce26d3aeea */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b532860); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b532860(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


