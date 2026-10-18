/* Handler 657: REA 6.7.0 / Ghidra 12.1.4 static recovery.
 * Not original source or a buildable translation unit. Analyst reconstructions are explicitly marked.
 * Raw handler_657.bin:4096 bytes; SHA256 7d576be693fd7630d871724e32c49d9e9c8e53c01957cd07d432e840f6255c1a; file+0=RVA 0x265f78.
 * Target RVA 0x9a9f40; recorded VA = 0xffffffff8a9c0000 + RVA.
 * Extra source-verified body/helper carriers are documented in .rea.analysis.md.
 * Missing external code/data, indirect flows and inferred types remain unresolved.
 */

/* ===== Analyst recovered ABI views and readable entry behavior =====
 * Slot layouts are based on machine-code loads, not recovered original declarations.
 * The original REA output follows unchanged.
 */
#include <stdint.h>
#include <stddef.h>
typedef uintptr_t user_address;
struct h657_args { user_address commands; int32_t count; uint32_t pad0; user_address processed_count; uint32_t flags; uint32_t pad1; };
struct h657_command { uint32_t opcode; uint32_t reserved; uint64_t address; uint64_t length; uint8_t protection; uint8_t memory_type; uint8_t tail[6]; };
_Static_assert(sizeof(struct h657_command)==32, "record stride from assembly");
/* Original entry is an unconditional tail jump to RVA 0x9a9f40; any REA halt_baddata is an out-of-carrier recovery artifact. */
/* Analyst reconstruction of the visible entry and loop, not replacement REA output.
 * err=22 if flags!=0 or count<0; count==0 succeeds. copyin one32-byte record,
 * look up address against td->proc(+8)->map(+0x200), require entry flag(+0x60)&2==0,
 * object(+0x50)!=NULL, object byte(+0x9d)==11. Hold map while processing.
 * For each opcode1..5, dispatch through signed-relative jump table0x18cdb30.
 * Its case-to-helper mapping is unavailable. Visible landing pads call:
 * 9aa0d4->9aa250;9aa0ee->9ab160;9aa108->9aa860;
 * 9aa122->9aa8d0;9aa144->9aa380. These belong to this entry's dispatch.
 * Helpers may advance the next-record cursor; otherwise it advances by32.
 * On error rewind cursor by32, publish (cursor-start)/32 through optional
 * 32-bit store helper259790. The store helper's result is ignored.
 * Cleanup may call process/map callback at1a962e8+0x40 if td+0x117 is set.
 */
/* ===== Executable-form analyst pseudocode of the visible dispatch loop =====
 * Names h657_* below are analyst abstractions. The table resolver is deliberately
 * undefined: the mapping from opcode1..5 to these five landing pads is unknown.
 */
enum h657_landing_pad { pad_9aa0d4, pad_9aa0ee, pad_9aa108, pad_9aa122, pad_9aa144 };
struct h657_lookup { uint8_t unknown00[0x20]; uint64_t lower, upper; uint8_t unknown30[0x20]; void *object; uint8_t unknown58[8]; uint8_t flags60; };
extern int copyin_259280(uintptr_t user, void *kernel, size_t length);
extern int store32_259790(uintptr_t user, uint32_t value);
extern void map_lock_2c6820(void *map, int zero1, int zero2);
extern void map_unlock_2c6870(void *map, int zero1, int zero2);
extern int map_lookup_2c6c40(void *map, uintptr_t address, struct h657_lookup **entry);
extern enum h657_landing_pad h657_unknown_table_mapping(uint32_t opcode);
extern int helper_9aa250(void *,void *,uint64_t,uint64_t,struct h657_command *);
extern int helper_9ab160(void *,void *,uint64_t,uint64_t,struct h657_command *);
extern int helper_9aa860(void *,void *,uint64_t,uint64_t,struct h657_command *);
extern int helper_9aa8d0(void *,void *,uint64_t,uint64_t,struct h657_command *,uintptr_t *,uintptr_t);
extern int helper_9aa380(void *,void *,uint64_t,uint64_t,struct h657_command *,uintptr_t *,uintptr_t);
extern void h657_trace_copyin(void); /* c1a3e0 tracing/accounting call */
extern void h657_atomic_map_reference(void *map); /* increment map+0x1c4 */
extern void h657_optional_callback(void *thread,void *map); /* td+0x117 and1a962e8 */
static int handler_657_visible_loop(void *thread,const struct h657_args *args) {
    struct h657_command record;
    struct h657_lookup *entry;
    uintptr_t current=args->commands, next, end;
    uint64_t lower, upper;
    void *process, *map, *object;
    int error=22;
    if(args->flags!=0 || args->count<0) goto publish;
    if(args->count==0) { error=0; goto publish; }
    process=*(void **)((uint8_t *)thread+8);
    map=*(void **)((uint8_t *)process+0x200);
    h657_trace_copyin();
    error=copyin_259280(current,&record,sizeof(record));
    if(error) goto publish;
    map_lock_2c6820(map,0,0);
    error=22;
    if(!map_lookup_2c6c40(map,record.address,&entry)) goto unlock;
    if(entry->flags60&2) goto unlock;
    object=entry->object;
    if(!object || *((uint8_t *)object+0x9d)!=11) goto unlock;
    h657_atomic_map_reference(map);
    lower=entry->lower; upper=entry->upper;
    end=current+((uint64_t)(uint32_t)args->count<<5);
    for(;;) {
        next=current+32;
        if(record.opcode<1 || record.opcode>5) error=45;
        else switch(h657_unknown_table_mapping(record.opcode)) {
            case pad_9aa0d4: error=helper_9aa250(map,object,lower,upper,&record); break;
            case pad_9aa0ee: error=helper_9ab160(map,object,lower,upper,&record); break;
            case pad_9aa108: error=helper_9aa860(map,object,lower,upper,&record); break;
            case pad_9aa122: error=helper_9aa8d0(map,object,lower,upper,&record,&next,end); break;
            case pad_9aa144: error=helper_9aa380(map,object,lower,upper,&record,&next,end); break;
        }
        if(error) { current=next-32; break; }
        current=next;
        if(current==end) { error=0; break; }
        h657_trace_copyin();
        error=copyin_259280(current,&record,sizeof(record));
        if(error) break;
    }
unlock:
    h657_optional_callback(thread,map);
    map_unlock_2c6870(map,0,0);
publish:
    if(args->processed_count) (void)store32_259790(args->processed_count,(uint32_t)((current-args->commands)>>5));
    return error;
}
/* Stack-cookie checks and exact helper-internal state are omitted only from
 * this analyst-readable version; the attributed REA and assembly retain them.
 */


/* ===== Actual REA pseudocode: original entry and recovered body functions ===== */

/* <EXTERNAL>::thunk_EXT_FUN_009a9f40 | RVA 0x265f78 | original syscall trampoline
 * Evidence ev_da7f3ede978ec0f8913a8bc6ab90ee670e3f279fdce9453c39d875b397f798b4
 * Body [{"start": "0x265f78", "end": "0x265f7c"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_009a9f40(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* handler_657_body | RVA 0x9a9f40 | target syscall body
 * Evidence ev_8b7aa19c6f28267cdcee0d8eac6492d5c6a1207c5f01c4041040eb1005ecd217
 * Body [{"start": "0x9a9f40", "end": "0x9aa0d3"}, {"start": "0x9aa1b9", "end": "0x9aa222"}, {"start": "0x9aa228", "end": "0x9aa24e"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong handler_657_body(long param_1,long *param_2)

{
  long lVar1;
  long lVar2;
  code *pcVar3;
  uint uVar4;
  int iVar5;
  ulong uVar6;
  undefined8 *in_GS_OFFSET;
  long local_68;
  int local_60 [2];
  undefined8 local_58;
  long local_40;
  long local_38;
  
  uVar6 = 0x16;
  local_38 = _DAT_0391c310;
  lVar1 = *param_2;
  if (((int)param_2[3] == 0) && (-1 < (int)param_2[1])) {
    if ((int)param_2[1] == 0) {
      uVar6 = 0;
    }
    else {
      lVar2 = *(long *)(*(long *)(param_1 + 8) + 0x200);
      func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
      uVar4 = func_0x00259280(lVar1,local_60,0x20);
      uVar6 = (ulong)uVar4;
      if (uVar4 == 0) {
        func_0x002c6820(lVar2,0,0);
        iVar5 = func_0x002c6c40(lVar2,local_58,&local_68);
        uVar6 = 0x16;
        if ((((iVar5 != 0) && ((*(byte *)(local_68 + 0x60) & 2) == 0)) &&
            (*(long *)(local_68 + 0x50) != 0)) &&
           (*(char *)(*(long *)(local_68 + 0x50) + 0x9d) == '\v')) {
          LOCK();
          *(int *)(lVar2 + 0x1c4) = *(int *)(lVar2 + 0x1c4) + 1;
          UNLOCK();
          local_40 = lVar1 + 0x20;
          if (local_60[0] - 1U < 5) {
                    /* WARNING: Could not emulate address calculation at 0x009aa0cb */
                    /* WARNING: Treating indirect jump as call */
            uVar6 = (*(code *)((long)*(int *)((ulong)(local_60[0] - 1U) * 4 + 0x18cdb30) + 0x18cdb30
                              ))();
            return uVar6;
          }
          uVar6 = 0x2d;
        }
        if (*(char *)(param_1 + 0x117) != '\0') {
          *(undefined1 *)(param_1 + 0x117) = 0;
          pcVar3 = *(code **)(_DAT_01a962e8 + 0x40);
          if (0x6ff < (-(long)pcVar3 + 0x260ce8U >> 3 | -(long)pcVar3 << 0x3d)) {
            func_0x0044f8c0(0x255fe80,pcVar3);
          }
          (*pcVar3)(lVar2);
        }
        func_0x002c6870(lVar2,0,0);
      }
    }
  }
  if (param_2[2] != 0) {
    func_0x00259790(param_2[2],0);
  }
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar3 = (code *)invalidInstructionException();
    (*pcVar3)();
  }
  return uVar6;
}



/* sub_9aa250 | RVA 0x9aa250 | local helper / adjacent context (reachability below)
 * Evidence ev_747fad2e57d10789f44c61590316037646abcbf92c9696fa8bb0c039f4e58c82
 * Body [{"start": "0x9aa250", "end": "0x9aa371"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_9aa250(long param_1,undefined8 param_2,ulong param_3,ulong param_4,long param_5)

{
  byte bVar1;
  ulong uVar2;
  ulong uVar3;
  int iVar4;
  undefined8 uVar5;
  byte bVar6;
  
  uVar5 = 0x16;
  if (((((*(int *)(param_5 + 4) == 0) && (uVar2 = *(ulong *)(param_5 + 8), (uVar2 & 0xffff) == 0))
       && (uVar3 = *(ulong *)(param_5 + 0x10), (uVar3 & 0xffff) == 0)) &&
      ((param_3 <= uVar2 && (uVar2 < param_4)))) &&
     ((uVar3 <= param_4 - uVar2 && (bVar1 = *(byte *)(param_5 + 0x18), (bVar1 & 0xcc) == 0)))) {
    bVar6 = *(byte *)(param_5 + 0x19);
    if ((bVar6 < 0xb) && ((0x409U >> (bVar6 & 0x1f) & 1) != 0)) {
      if ((*(byte *)(param_1 + 0x244) & 2) == 0) {
        iVar4 = FUN_009acc10(bVar6);
        bVar6 = (iVar4 == 0) * '\x04' + 0xf;
      }
      else if (bVar6 == 10 && (bVar1 & 0x22) != 0) {
        return 0xd;
      }
    }
    else {
      if (bVar6 - 0x15 < 0xfffffff6) {
        return 0x16;
      }
      if ((*(byte *)(param_1 + 0x244) & 2) != 0) {
        return 0x16;
      }
    }
    if (uVar3 == 0) {
      uVar5 = 0;
    }
    else {
      uVar5 = func_0x009a97a0(param_1,param_2,param_3,uVar2 - param_3 >> 0x10,
                              (uVar2 - param_3) + uVar3 >> 0x10 & 0xffffffff,bVar1,bVar6);
    }
  }
  return uVar5;
}



/* sub_9aa380 | RVA 0x9aa380 | local helper / adjacent context (reachability below)
 * Evidence ev_581e2217d83757fdbd3f80a6f4ce7e563271fb02c8a5bd6d475c156a0c70a1cd
 * Body [{"start": "0x9aa380", "end": "0x9aa85a"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_9aa380(long param_1,long param_2,ulong param_3,ulong param_4,int *param_5,long *param_6,
              long param_7)

{
  long lVar1;
  long lVar2;
  code *pcVar3;
  int iVar4;
  long lVar5;
  long lVar6;
  uint uVar7;
  int iVar8;
  ulong uVar9;
  ulong uVar10;
  long lVar11;
  ulong uVar12;
  long *in_GS_OFFSET;
  bool bVar13;
  undefined8 local_48;
  long local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  lVar2 = *in_GS_OFFSET;
  lVar11 = *param_6;
  func_0x004c6a00(0x3ba5e78,0,0,0);
  while (_DAT_03ba5ed8 == 0) {
    func_0x00c06260(&DAT_03ba5ed8,0x3ba5e60,0x44,0x1272dc0,0,0,0x100);
  }
  iVar4 = 0;
  for (uVar12 = _DAT_03ba5ed8; (uVar12 & 1) == 0; uVar12 = uVar12 >> 1 | 0x8000000000000000) {
    iVar4 = iVar4 + 1;
  }
  _DAT_03ba5ed8 = _DAT_03ba5ed8 - 1 & _DAT_03ba5ed8;
  func_0x004c6fa0(0x3ba5e78,0,0,0);
  lVar5 = CONCAT44(uRam0000000003ba5ee4,_DAT_03ba5ee0);
  local_48 = 0;
  lVar1 = lVar5 + (ulong)(uint)(iVar4 << 0xd);
  local_40 = lVar1;
  while (((((lVar6 = local_40, iVar8 = 0x16, param_5[1] == 0 &&
            (uVar12 = *(ulong *)(param_5 + 2), (uVar12 & 0xffff) == 0)) &&
           (uVar10 = *(ulong *)(param_5 + 4), (uVar10 & 0xffff) == 0)) &&
          ((param_3 <= uVar12 && (uVar12 < param_4)))) && (uVar10 <= param_4 - uVar12))) {
    if (uVar10 != 0) {
      uVar9 = uVar12 - param_3 >> 0x10;
      uVar12 = (uVar12 - param_3) + uVar10 >> 0x10;
      if (lVar1 == local_40) {
        uVar10 = uVar12 - uVar9;
      }
      else {
        uVar10 = uVar12 - uVar9;
        if ((long)((lVar5 + 0x2000 + (ulong)(uint)(iVar4 << 0xd)) - local_40) >> 2 <
            (long)(int)uVar10) {
          func_0x008ef340(*(undefined8 *)(param_1 + 0x1d8),local_48);
          local_48 = 0;
          if (*(char *)(lVar2 + 0x117) != '\0') {
            *(undefined1 *)(lVar2 + 0x117) = 0;
            pcVar3 = *(code **)(_DAT_01a962e8 + 0x40);
            if (0x6ff < (-(long)pcVar3 + 0x260ce8U >> 3 | -(long)pcVar3 << 0x3d)) {
              func_0x0044f8c0(0x255ff90,pcVar3);
            }
            (*pcVar3)(param_1);
          }
          func_0x009a86c0(param_2,lVar1,(ulong)(lVar6 - lVar1) >> 2 & 0xffffffff);
          local_40 = lVar1;
        }
      }
      if ((uVar10 & 0xfffff800) == 0) {
        uVar7 = func_0x009a8080(param_2,uVar9 & 0xffffffff,uVar12 & 0xffffffff);
        uVar10 = (ulong)uVar7;
        func_0x009a8570(param_1,param_2,param_3,uVar9 & 0xffffffff,uVar12 & 0xffffffff,&local_48,
                        &local_40);
        func_0x007d46a0(param_2 + 0x18,0,0);
        *(undefined4 *)(param_2 + 0x168 + uVar10 * 0xc) = 0xffffffff;
        if (*(int *)(param_2 + 0x170 + uVar10 * 0xc) != 0) {
          *(undefined4 *)(param_2 + 0x170 + uVar10 * 0xc) = 0;
          func_0x00c06910();
        }
        if (*(int *)(param_2 + 0x198) != 0) {
          *(int *)(param_2 + 0x198) = 0;
          func_0x00c06910();
        }
        func_0x007d4eb0(param_2 + 0x18,0,0);
      }
      else {
        func_0x009a8260(param_1,param_2,param_3,uVar9 & 0xffffffff,uVar12 & 0xffffffff);
      }
    }
    iVar8 = 0;
    if (lVar11 == param_7) break;
    func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
    iVar8 = func_0x00259280(lVar11,param_5,0x20);
    if ((iVar8 != 0) || (iVar8 = 0, *param_5 != 2)) break;
    lVar11 = lVar11 + 0x20;
  }
  lVar5 = local_40;
  if (lVar1 != local_40) {
    func_0x008ef340(*(undefined8 *)(param_1 + 0x1d8),local_48);
    if (*(char *)(lVar2 + 0x117) != '\0') {
      *(undefined1 *)(lVar2 + 0x117) = 0;
      pcVar3 = *(code **)(_DAT_01a962e8 + 0x40);
      if (0x6ff < (-(long)pcVar3 + 0x260ce8U >> 3 | -(long)pcVar3 << 0x3d)) {
        func_0x0044f8c0(0x255ffb0,pcVar3);
      }
      (*pcVar3)(param_1);
    }
    func_0x009a86c0(param_2,lVar1,(ulong)(lVar5 - lVar1) >> 2 & 0xffffffff);
  }
  func_0x004c6a00(0x3ba5e78,0,0,0);
  uVar12 = _DAT_03ba5ed8 | 1L << ((ulong)((uint)((int)lVar1 - _DAT_03ba5ee0) >> 0xd) & 0x3f);
  bVar13 = _DAT_03ba5ed8 == 0;
  _DAT_03ba5ed8 = uVar12;
  if (bVar13) {
    func_0x00c06910(&DAT_03ba5ed8);
  }
  func_0x004c6fa0(0x3ba5e78,0,0,0);
  *param_6 = lVar11;
  if (_DAT_0391c310 == local_38) {
    return iVar8;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar3 = (code *)invalidInstructionException();
  (*pcVar3)();
}



/* sub_9aa860 | RVA 0x9aa860 | local helper / adjacent context (reachability below)
 * Evidence ev_4ae66b92d54f5fd899cf283dce150abde5ebe29d4dc8a02e4dbd7f135da24e9e
 * Body [{"start": "0x9aa860", "end": "0x9aa8cb"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

undefined8
sub_9aa860(undefined8 param_1,undefined8 param_2,ulong param_3,ulong param_4,long param_5)

{
  ulong uVar1;
  ulong uVar2;
  undefined8 uVar3;
  
  uVar3 = 0x16;
  if ((((*(int *)(param_5 + 4) == 0) && (uVar1 = *(ulong *)(param_5 + 8), (uVar1 & 0xffff) == 0)) &&
      (uVar2 = *(ulong *)(param_5 + 0x10), (uVar2 & 0xffff) == 0)) &&
     (((param_3 <= uVar1 && (uVar1 < param_4)) &&
      ((uVar2 <= param_4 - uVar1 && ((*(byte *)(param_5 + 0x18) & 0xcc) == 0)))))) {
    if (uVar2 != 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    uVar3 = 0;
  }
  return uVar3;
}



/* sub_9aa8d0 | RVA 0x9aa8d0 | local helper / adjacent context (reachability below)
 * Evidence ev_64ea9a7a212d6a383a464ec3c7a2aaabe5c375c7cf85c7f638818d22edb3c59c
 * Body [{"start": "0x9aa8d0", "end": "0x9aaa06"}, {"start": "0x9aaa10", "end": "0x9aabd2"}, {"start": "0x9aabe0", "end": "0x9aac28"}, {"start": "0x9aac30", "end": "0x9aad8a"}, {"start": "0x9aad90", "end": "0x9aadd1"}, {"start": "0x9aade0", "end": "0x9aae8d"}, {"start": "0x9aae90", "end": "0x9aaf3e"}, {"start": "0x9aaf40", "end": "0x9ab034"}, {"start": "0x9ab040", "end": "0x9ab07e"}, {"start": "0x9ab080", "end": "0x9ab0c6"}, {"start": "0x9ab0d0", "end": "0x9ab15b"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_9aa8d0(long param_1,long param_2,ulong param_3,ulong param_4,int *param_5,long *param_6,
              long param_7)

{
  byte bVar1;
  byte bVar2;
  uint uVar3;
  long lVar4;
  long lVar5;
  undefined8 uVar6;
  undefined8 uVar7;
  code *pcVar8;
  byte bVar9;
  int iVar10;
  uint uVar11;
  int iVar12;
  ulong uVar13;
  long lVar14;
  byte *pbVar15;
  ulong uVar16;
  long lVar17;
  uint uVar18;
  uint uVar19;
  int iVar20;
  ulong uVar21;
  ulong uVar22;
  long lVar23;
  long *in_GS_OFFSET;
  bool bVar24;
  byte *local_460;
  ulong local_458;
  ulong local_450;
  int local_448;
  undefined8 local_440;
  byte local_438 [8];
  ulong local_430 [2];
  byte local_420 [1000];
  long local_38;
  
  pbVar15 = local_420 + 8;
  local_458 = 0xffffffffffffffff;
  local_450 = 0;
  lVar4 = *(long *)(param_2 + 0xe8);
  bVar1 = *(byte *)(param_1 + 0x244);
  lVar17 = *param_6;
  local_460 = local_438;
  iVar10 = param_5[1];
  local_38 = _DAT_0391c310;
  while (((((iVar10 == 0 && (uVar13 = *(ulong *)(param_5 + 2), (uVar13 & 0xffff) == 0)) &&
           (uVar21 = *(ulong *)(param_5 + 4), (uVar21 & 0xffff) == 0)) &&
          ((param_3 <= uVar13 && (uVar13 < param_4)))) &&
         ((uVar21 <= param_4 - uVar13 && (bVar2 = *(byte *)(param_5 + 6), (bVar2 & 0xcc) == 0))))) {
    bVar9 = *(byte *)((long)param_5 + 0x19);
    if ((bVar9 < 0xb) && ((0x409U >> (bVar9 & 0x1f) & 1) != 0)) {
      if ((bVar1 & 2) == 0) {
        iVar10 = FUN_009acc10();
        bVar9 = (iVar10 == 0) * '\x04' + 0xf;
      }
    }
    else if (((bVar1 & 2) != 0) || (bVar9 - 0x15 < 0xfffffff6)) goto LAB_009aab1f;
    local_460 = local_460 + 0x20;
    *(ulong *)(pbVar15 + -0x18) = uVar13;
    *(ulong *)(pbVar15 + -0x10) = uVar21;
    pbVar15[-8] = bVar2;
    pbVar15[-7] = bVar9;
    if (uVar13 < local_458) {
      local_458 = uVar13 & 0xffffffffffe00000;
    }
    if (local_450 < uVar21 + uVar13) {
      local_450 = uVar21 + 0x1fffff + uVar13 & 0xffffffffffe00000;
    }
    if ((&local_38 <= pbVar15) || (lVar17 == param_7)) {
      local_448 = 0;
      goto LAB_009aab53;
    }
    func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
    local_448 = func_0x00259280(lVar17,param_5,0x20);
    if (local_448 != 0) goto LAB_009aab53;
    if (*param_5 != 4) {
      local_448 = 0;
      local_460 = pbVar15;
      goto LAB_009aab53;
    }
    lVar17 = lVar17 + 0x20;
    pbVar15 = pbVar15 + 0x20;
    iVar10 = param_5[1];
  }
  local_460 = pbVar15 + -0x20;
LAB_009aab1f:
  local_448 = 0x16;
LAB_009aab53:
  if (local_450 <= local_458) goto LAB_009aafff;
  uVar11 = func_0x009a8080(param_2,local_458 - param_3 >> 0x10,
                           local_450 - param_3 >> 0x10 & 0xffffffff);
  lVar5 = *(long *)(param_2 + 0x160);
  uVar6 = *(undefined8 *)(param_1 + 0x1d8);
  pbVar15 = local_438;
  local_440 = 0;
  if (pbVar15 == local_460) {
    bVar24 = false;
    iVar10 = 0;
  }
  else {
    iVar10 = 0;
    uVar13 = 0;
    do {
      bVar2 = pbVar15[0x19];
      if ((bVar1 & 2) == 0) {
        uVar19 = 0;
        if ((byte)(bVar2 - 0xb) < 10) {
          uVar19 = *(uint *)((ulong)(byte)(bVar2 - 0xb) * 4 + 0x18cdb8c);
        }
      }
      else {
        uVar19 = (uint)(bVar2 == 10) << 0x17;
        if (bVar2 == 0) {
          uVar19 = 0xc00000;
        }
      }
      lVar14 = *(long *)(pbVar15 + 8);
      lVar23 = *(long *)(pbVar15 + 0x10);
      func_0x008ee780(uVar6,lVar14,lVar23 + lVar14,&local_440);
      iVar20 = (int)(lVar14 - param_3 >> 0x10);
      iVar12 = (int)((lVar23 + lVar14) - param_3 >> 0x10);
      if (iVar20 < iVar12) {
        lVar14 = (long)iVar20;
        do {
          uVar18 = *(uint *)(lVar5 + lVar14 * 4);
          if (uVar19 != (uVar18 & 0xf00000)) {
            uVar18 = uVar18 & 0x800000;
            if (uVar18 != (uVar19 & 0x800000)) {
              if ((uVar19 & 0x800000) == 0) {
                iVar10 = iVar10 + -1;
              }
              else {
                iVar10 = iVar10 + 1;
              }
            }
            uVar21 = uVar13 + 0x10000;
            if (uVar18 == 0) {
              uVar21 = uVar13;
            }
            if (uVar19 != 0xc00000) {
              uVar13 = uVar21;
            }
          }
          lVar14 = lVar14 + 1;
        } while (iVar12 != lVar14);
      }
      pbVar15 = pbVar15 + 0x20;
    } while (pbVar15 != local_460);
    bVar24 = 0x1fffff < uVar13;
  }
  func_0x008ef340(uVar6,local_440);
  lVar14 = lVar4 + 0x28;
  func_0x004c6a00(lVar14,0,0,0);
  *(int *)(lVar4 + 0x50) = *(int *)(lVar4 + 0x50) + iVar10;
  *(int *)(lVar4 + 0x54) = *(int *)(lVar4 + 0x54) - iVar10;
  if (bVar24) {
    sub_9ac450(lVar4);
    func_0x004c6fa0(lVar14,0,0,0);
LAB_009aad58:
    pbVar15 = local_438;
    local_440 = 0;
    if (pbVar15 != local_460) {
      uVar7 = *(undefined8 *)(lVar4 + 0x30);
      do {
        bVar2 = pbVar15[0x19];
        if ((bVar1 & 2) == 0) {
          uVar19 = 0;
          if ((byte)(bVar2 - 0xb) < 10) {
            uVar19 = *(uint *)((ulong)(byte)(bVar2 - 0xb) * 4 + 0x18cdb8c);
          }
        }
        else {
          uVar19 = (uint)(bVar2 == 10) << 0x17;
          if (bVar2 == 0) {
            uVar19 = 0xc00000;
          }
        }
        uVar13 = *(long *)(pbVar15 + 8) - param_3;
        uVar21 = uVar13 >> 0x10;
        iVar12 = (int)(uVar13 >> 0x10);
        iVar10 = (int)(uVar13 + *(long *)(pbVar15 + 0x10) >> 0x10);
        if (iVar12 < iVar10) {
          uVar22 = (ulong)iVar10;
          bVar2 = pbVar15[0x18];
          uVar18 = (bVar2 & 0x30) << 0x16 | (bVar2 >> 1 & 1 | bVar2 & 3) << 0x18;
          uVar16 = (ulong)uVar18;
          uVar13 = (long)(iVar12 + 1) + 0x1fU & 0xffffffffffffffe0;
          if (uVar22 < uVar13) {
            uVar13 = uVar22;
          }
          uVar18 = uVar18 | uVar19;
          do {
            iVar20 = (int)uVar21;
            lVar23 = (long)iVar20;
            iVar12 = (int)uVar13;
            uVar21 = uVar13 & 0xffffffff;
            lVar4 = lVar5 + lVar23 * 4;
            lVar14 = lVar23 * 0x10000 + param_3;
            func_0x009ed630(param_1,lVar14,uVar7,iVar12 - iVar20,lVar4,uVar18,uVar16);
            if (iVar12 - iVar20 != 0 && iVar20 <= iVar12) {
              do {
                uVar3 = *(uint *)(lVar5 + lVar23 * 4);
                if ((uVar3 & 0x30000000) != 0) {
                  *(uint *)(lVar5 + lVar23 * 4) = uVar3 & 0xf00fffff | uVar18;
                }
                lVar23 = lVar23 + 1;
              } while (iVar12 != lVar23);
            }
            func_0x008eeaa0(uVar6,lVar14,uVar7,iVar12 - iVar20,lVar4,uVar19,uVar16,&local_440);
            uVar13 = (long)iVar12 + 0x20;
            if (uVar22 < uVar13) {
              uVar13 = uVar22;
            }
          } while (iVar12 < iVar10);
        }
        pbVar15 = pbVar15 + 0x20;
      } while (pbVar15 != local_460);
    }
  }
  else {
    func_0x004c6fa0(lVar14,0,0,0);
    pbVar15 = local_438;
    if (pbVar15 != local_460) {
      do {
        bVar2 = pbVar15[0x19];
        if ((bVar1 & 2) == 0) {
          uVar19 = 0;
          if ((byte)(bVar2 - 0xb) < 10) {
            uVar19 = *(uint *)((ulong)(byte)(bVar2 - 0xb) * 4 + 0x18cdb8c);
          }
        }
        else {
          uVar19 = (uint)(bVar2 == 10) << 0x17;
          if (bVar2 == 0) {
            uVar19 = 0xc00000;
          }
        }
        iVar10 = (int)(*(long *)(pbVar15 + 8) - param_3 >> 0x10);
        iVar12 = (int)((*(long *)(pbVar15 + 8) - param_3) + *(long *)(pbVar15 + 0x10) >> 0x10);
        if (iVar10 < iVar12) {
          lVar14 = 0;
          do {
            uVar18 = *(uint *)(lVar5 + (long)iVar10 * 4 + lVar14 * 4);
            if (((uVar18 & 0x30800000) == 0x10800000) && ((uVar18 & 0xf00000) != uVar19)) {
              sub_9ac500(lVar4,uVar18 & 0xfffff);
            }
            lVar14 = lVar14 + 1;
          } while (iVar12 - iVar10 != (int)lVar14);
        }
        pbVar15 = pbVar15 + 0x20;
      } while (pbVar15 != local_460);
      goto LAB_009aad58;
    }
    local_440 = 0;
  }
  uVar13 = (ulong)uVar11;
  func_0x007d46a0(param_2 + 0x18,0,0);
  *(undefined4 *)(param_2 + 0x168 + uVar13 * 0xc) = 0xffffffff;
  if (*(int *)(param_2 + 0x170 + uVar13 * 0xc) == 0) {
    iVar10 = *(int *)(param_2 + 0x198);
  }
  else {
    *(undefined4 *)(param_2 + 0x170 + uVar13 * 0xc) = 0;
    func_0x00c06910();
    iVar10 = *(int *)(param_2 + 0x198);
  }
  if (iVar10 != 0) {
    *(undefined4 *)(param_2 + 0x198) = 0;
    func_0x00c06910((undefined4 *)(param_2 + 0x198));
  }
  func_0x007d4eb0(param_2 + 0x18,0,0);
  *(undefined1 *)(*in_GS_OFFSET + 0x117) = 1;
LAB_009aafff:
  *param_6 = lVar17;
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar8 = (code *)invalidInstructionException();
    (*pcVar8)();
  }
  return local_448;
}



/* sub_9ab160 | RVA 0x9ab160 | local helper / adjacent context (reachability below)
 * Evidence ev_64e75cc322d0d3307e7e56ecc4d3eb852116fb8e045f5b00997ad3145300b7e8
 * Body [{"start": "0x9ab160", "end": "0x9ab1e9"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted.", "Ghidra Listing reports a terminal call at 0x9ab1e3 to 0x9ab370 sub_9ab370 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

undefined8
sub_9ab160(undefined8 param_1,undefined8 param_2,ulong param_3,ulong param_4,long param_5)

{
  ulong uVar1;
  ulong uVar2;
  ulong uVar3;
  undefined8 uVar4;
  
  uVar4 = 0x16;
  if (((((*(int *)(param_5 + 4) == 0) && (uVar1 = *(ulong *)(param_5 + 8), (uVar1 & 0xffff) == 0))
       && (uVar2 = *(ulong *)(param_5 + 0x10), (uVar2 & 0xffff) == 0)) &&
      ((((uVar3 = *(ulong *)(param_5 + 0x18), (uVar3 & 0xffff) == 0 && (param_3 <= uVar1)) &&
        ((uVar1 < param_4 && ((uVar3 <= param_4 - uVar1 && (param_3 <= uVar2)))))) &&
       (uVar2 < param_4)))) &&
     (((uVar3 <= param_4 - uVar2 && (uVar4 = 0, uVar3 != 0)) && (uVar2 != uVar1)))) {
    uVar4 = sub_9ab370();
    return uVar4;
  }
  return uVar4;
}



/* sys_673 | RVA 0x9ab1f0 | local helper / adjacent context (reachability below)
 * Evidence ev_94e672233a4dc9bbea4212ea6e1c79296c6db475bf1230afb53e78aac411970b
 * Body [{"start": "0x9ab1f0", "end": "0x9ab368"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 sys_673(long param_1,ulong *param_2)

{
  ulong uVar1;
  long lVar2;
  ulong uVar3;
  ulong uVar4;
  ulong uVar5;
  long lVar6;
  ulong uVar7;
  code *pcVar8;
  int iVar9;
  undefined4 uVar10;
  long local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  uVar1 = *param_2;
  lVar2 = *(long *)(*(long *)(param_1 + 8) + 0x200);
  uVar10 = 0x16;
  if (*(ulong *)(lVar2 + 0x20) <= uVar1) {
    uVar3 = *(ulong *)(lVar2 + 0x28);
    uVar4 = param_2[1];
    if ((((*(ulong *)(lVar2 + 0x20) <= uVar4 && ((short)uVar1 == 0 && uVar1 < uVar3)) &&
         ((short)uVar4 == 0)) && (uVar4 < uVar3)) &&
       (((uVar5 = param_2[2], (uVar5 & 0xffff) == 0 && (uVar5 <= uVar3 - uVar1)) &&
        ((uVar5 <= uVar3 - uVar4 && ((int)param_2[3] == 0)))))) {
      func_0x002c6820(lVar2,0,0);
      iVar9 = func_0x002c6c40(lVar2,uVar1,&local_40);
      uVar10 = 0x16;
      if ((((iVar9 != 0) && ((*(byte *)(local_40 + 0x60) & 2) == 0)) &&
          ((lVar6 = *(long *)(local_40 + 0x50), lVar6 != 0 &&
           (((*(char *)(lVar6 + 0x9d) == '\v' &&
             (uVar3 = *(ulong *)(local_40 + 0x28), uVar5 <= uVar3 - uVar1)) &&
            (uVar7 = *(ulong *)(local_40 + 0x20),
            uVar5 <= uVar3 - uVar4 && (uVar4 < uVar3 && uVar7 <= uVar4))))))) &&
         (uVar10 = 0, uVar4 != uVar1 && uVar5 != 0)) {
        LOCK();
        *(int *)(lVar2 + 0x1c4) = *(int *)(lVar2 + 0x1c4) + 1;
        UNLOCK();
        uVar10 = sub_9ab370(lVar2,lVar6,uVar7,uVar1 - uVar7 >> 0x10 & 0xffffffff,
                            uVar4 - uVar7 >> 0x10 & 0xffffffff,uVar5 >> 0x10 & 0xffffffff);
      }
      func_0x002c6870(lVar2,0,0);
    }
  }
  if (_DAT_0391c310 == local_38) {
    return uVar10;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar8 = (code *)invalidInstructionException();
  (*pcVar8)();
}



/* sub_9ab370 | RVA 0x9ab370 | local helper / adjacent context (reachability below)
 * Evidence ev_fde9b1a22ddae48c16fab7a4f8ff7b9f871b69079fe96236d0dd1be07e2376c5
 * Body [{"start": "0x9ab370", "end": "0x9ab4d2"}, {"start": "0x9ab4e0", "end": "0x9ab815"}, {"start": "0x9ab820", "end": "0x9ab890"}, {"start": "0x9ab8a0", "end": "0x9ab9a3"}, {"start": "0x9ab9b0", "end": "0x9abc92"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_9ab370(long param_1,long param_2,long param_3,uint param_4,ulong param_5,int param_6)

{
  int *piVar1;
  int *piVar2;
  int *piVar3;
  char *pcVar4;
  char cVar5;
  long lVar6;
  code *pcVar7;
  uint uVar8;
  uint uVar9;
  int iVar10;
  ulong uVar11;
  long lVar12;
  uint uVar13;
  long lVar14;
  long lVar15;
  long lVar16;
  uint uVar17;
  long lVar18;
  int *piVar19;
  uint uVar20;
  long lVar21;
  uint uVar22;
  int iVar23;
  long *in_GS_OFFSET;
  int local_88;
  uint local_80;
  uint local_78;
  ulong local_70;
  undefined8 local_48;
  int local_40 [2];
  long local_38;
  
  uVar20 = (uint)param_5;
  local_78 = param_6 + 0x1f + uVar20;
  local_38 = _DAT_0391c310;
  lVar15 = *(long *)(param_2 + 0xe8);
  local_70._0_4_ = param_6 + 0x1f + param_4;
  lVar6 = *(long *)(param_2 + 0x160);
  lVar16 = *(long *)(param_2 + 400);
  local_48 = 0;
  uVar22 = param_4 & 0xffffffe0;
  uVar13 = param_6 + param_4;
  uVar9 = param_6 + uVar20;
  if ((int)(local_78 & 0xffffffe0) <= (int)uVar22 ||
      (int)((uint)local_70 & 0xffffffe0) <= (int)(uVar20 & 0xffffffe0)) {
    local_78 = local_78 & 0xffffffe0;
    local_70._0_4_ = (uint)local_70 & 0xffffffe0;
    local_80 = uVar20 & 0xffffffe0;
    uVar17 = 0;
    func_0x007d46a0(param_2 + 0x18,0,0);
    piVar1 = (int *)(param_2 + 0x168);
    piVar2 = (int *)(param_2 + 0x174);
    piVar3 = (int *)(param_2 + 0x180);
LAB_009ab488:
    while (iVar10 = *piVar1, -1 < iVar10) {
      piVar19 = piVar1;
      if (((int)(uint)local_70 <= iVar10 || *(int *)(param_2 + 0x16c) <= (int)uVar22) &&
         ((int)local_78 <= iVar10 || *(int *)(param_2 + 0x16c) <= (int)local_80)) goto LAB_009ab4ac;
LAB_009ab678:
      piVar19[2] = 1;
      func_0x00c06260(piVar19 + 2,param_2,0x44,0x1375e9b,0,0,0x100);
    }
    if ((int)uVar17 < 2) {
      uVar11 = (ulong)uVar17;
      uVar17 = uVar17 + 1;
      local_40[uVar11] = 0;
LAB_009ab4ac:
      iVar10 = *piVar2;
      if (iVar10 < 0) {
        uVar8 = 2;
        if ((int)uVar17 < 2) {
          local_40[uVar17] = 1;
          uVar8 = uVar17 + 1;
        }
      }
      else {
LAB_009ab5c4:
        piVar19 = piVar2;
        if ((iVar10 < (int)(uint)local_70 && (int)uVar22 < *(int *)(param_2 + 0x178)) ||
           (uVar8 = uVar17, iVar10 < (int)local_78 && (int)local_80 < *(int *)(param_2 + 0x178)))
        goto LAB_009ab678;
      }
    }
    else {
      iVar10 = *piVar2;
      uVar17 = 2;
      uVar8 = 2;
      if (-1 < iVar10) goto LAB_009ab5c4;
    }
    uVar17 = uVar8;
    iVar10 = *piVar3;
    if (iVar10 < 0) {
      if (1 < (int)uVar17) goto LAB_009ab6dd;
      uVar11 = (ulong)uVar17;
      uVar17 = uVar17 + 1;
      local_40[uVar11] = 2;
    }
    else {
      piVar19 = piVar3;
      if ((iVar10 < (int)(uint)local_70 && (int)uVar22 < *(int *)(param_2 + 0x184)) ||
         (iVar10 < (int)local_78 && (int)local_80 < *(int *)(param_2 + 0x184))) goto LAB_009ab678;
    }
    if (uVar17 == 2) goto LAB_009ab6dd;
    *(undefined4 *)(param_2 + 0x198) = 1;
    do {
      func_0x00c06260((undefined4 *)(param_2 + 0x198),param_2,0x44,0x1394bd1,0,0,0x100);
    } while (*(int *)(param_2 + 0x198) != 0);
    goto LAB_009ab488;
  }
  uVar11 = param_5 & 0xffffffff;
  if ((int)param_4 < (int)uVar20) {
    uVar11 = (ulong)param_4;
  }
  uVar22 = uVar9;
  if ((int)uVar9 < (int)uVar13) {
    uVar22 = uVar13;
  }
  local_88 = func_0x009a8080(param_2,uVar11,uVar22);
  local_70 = 0xffffffff;
LAB_009ab73a:
  lVar12 = (long)(int)param_4;
  lVar21 = (long)(int)uVar9;
  if ((int)param_4 < (int)uVar20) {
    if ((int)param_4 < (int)uVar13) {
      uVar22 = uVar20;
      if ((int)uVar13 < (int)uVar20) {
        uVar22 = uVar13;
      }
      lVar14 = lVar12;
      do {
        if ((*(byte *)(lVar6 + 3 + lVar14 * 4) & 0x30) != 0) goto LAB_009aba41;
        lVar14 = lVar14 + 1;
      } while (lVar14 < (int)uVar22);
    }
  }
  else {
    uVar22 = param_4;
    if ((int)param_4 < (int)uVar9) {
      uVar22 = uVar9;
    }
    if ((int)uVar22 < (int)uVar13) {
      lVar14 = lVar21;
      if (lVar21 < lVar12) {
        lVar14 = lVar12;
      }
      lVar18 = 0;
      do {
        if ((*(byte *)(lVar6 + lVar14 * 4 + 3 + lVar18 * 4) & 0x30) != 0) goto LAB_009aba41;
        lVar18 = lVar18 + 1;
      } while (uVar13 - uVar22 != (int)lVar18);
    }
  }
  iVar23 = 0;
  if ((int)param_4 < (int)uVar13) {
    lVar14 = (int)uVar13 - lVar12;
    uVar11 = param_5 & 0xffffffff;
    iVar23 = 0;
    uVar22 = param_4;
    do {
      if ((*(uint *)(lVar6 + (long)(int)uVar11 * 4) & 0x30000000) == 0x10000000) {
        cVar5 = *(char *)(lVar16 + ((int)uVar22 >> 5));
        *(char *)(lVar16 + ((int)uVar22 >> 5)) = cVar5 + '\x01';
        iVar23 = iVar23 + (uint)(cVar5 == '\0');
      }
      uVar22 = uVar22 + 1;
      uVar11 = (ulong)((int)uVar11 + 1);
      lVar14 = lVar14 + -1;
    } while (lVar14 != 0);
  }
  lVar14 = (long)(int)uVar20;
  if ((int)uVar20 < (int)uVar9) {
    lVar18 = 0;
    do {
      if ((*(uint *)(lVar6 + lVar14 * 4 + lVar18 * 4) & 0x30000000) == 0x10000000) {
        pcVar4 = (char *)(lVar16 + ((int)(uVar20 + (int)lVar18) >> 5));
        *pcVar4 = *pcVar4 + -1;
        iVar23 = iVar23 - (uint)(*pcVar4 == '\0');
      }
      lVar18 = lVar18 + 1;
    } while (lVar21 - lVar14 != lVar18);
  }
  if ((iVar23 < 1) ||
     (iVar10 = func_0x008ed550(*(undefined1 *)(param_2 + 0x19c),iVar23), iVar10 == 0)) {
    iVar10 = func_0x009edec0(param_1,*(undefined8 *)(lVar15 + 0x30),param_3,param_4,param_5,lVar6,
                             param_6,*(char *)(*in_GS_OFFSET + 0x116) == '\0');
    if (iVar10 == 0) {
      func_0x008ee780(*(undefined8 *)(param_1 + 0x1d8),lVar14 * 0x10000 + param_3,
                      lVar21 * 0x10000 + param_3,&local_48);
      func_0x008ef340(*(undefined8 *)(param_1 + 0x1d8),local_48);
      lVar16 = lVar6 + lVar14 * 4;
      func_0x008e4d70(*(undefined8 *)(param_1 + 0x1d8),*(undefined8 *)(lVar15 + 0x30),
                      lVar12 * 0x10000 + param_3,lVar16,param_6);
      func_0x00259be0(lVar16,lVar6 + lVar12 * 4,(long)param_6 << 2);
      if ((int)param_4 < (int)uVar20) {
        if ((int)uVar20 < (int)uVar13) {
          uVar20 = uVar13;
        }
        lVar16 = lVar6 + (long)(int)uVar20 * 4;
        iVar10 = uVar9 - uVar20;
      }
      else {
        if ((int)uVar9 < (int)param_4) {
          param_4 = uVar9;
        }
        iVar10 = param_4 - uVar20;
      }
      func_0x00258ff0(lVar16,(long)iVar10 << 2);
      iVar10 = 0;
      if (iVar23 < 0) {
        func_0x008ed5d0(*(undefined1 *)(param_2 + 0x19c),-iVar23);
      }
      goto joined_r0x009abb42;
    }
    if (0 < iVar23) {
      func_0x008ed5d0(*(undefined1 *)(param_2 + 0x19c),iVar23);
    }
  }
  if ((int)param_4 < (int)uVar13) {
    lVar12 = (int)uVar13 - lVar12;
    param_5 = param_5 & 0xffffffff;
    do {
      if ((*(uint *)(lVar6 + (long)(int)param_5 * 4) & 0x30000000) == 0x10000000) {
        pcVar4 = (char *)(lVar16 + ((int)param_4 >> 5));
        *pcVar4 = *pcVar4 + '\x01';
      }
      param_4 = param_4 + 1;
      param_5 = (ulong)((int)param_5 + 1);
      lVar12 = lVar12 + -1;
    } while (lVar12 != 0);
  }
  if ((int)uVar20 < (int)uVar9) {
    lVar15 = 0;
    do {
      if ((*(uint *)(lVar6 + lVar14 * 4 + lVar15 * 4) & 0x30000000) == 0x10000000) {
        pcVar4 = (char *)(lVar16 + ((int)(uVar20 + (int)lVar15) >> 5));
        *pcVar4 = *pcVar4 + '\x01';
      }
      lVar15 = lVar15 + 1;
    } while (lVar21 - lVar14 != lVar15);
  }
joined_r0x009abb42:
  if (-1 < (int)local_70) {
    local_70 = local_70 & 0xffffffff;
    func_0x007d46a0(param_2 + 0x18,0,0);
    *(undefined4 *)(param_2 + 0x168 + local_70 * 0xc) = 0xffffffff;
    if (*(int *)(param_2 + 0x170 + local_70 * 0xc) == 0) {
      iVar23 = *(int *)(param_2 + 0x198);
    }
    else {
      *(undefined4 *)(param_2 + 0x170 + local_70 * 0xc) = 0;
      func_0x00c06910();
      iVar23 = *(int *)(param_2 + 0x198);
    }
    if (iVar23 != 0) {
      *(undefined4 *)(param_2 + 0x198) = 0;
      func_0x00c06910();
    }
    func_0x007d4eb0(param_2 + 0x18,0,0);
  }
  lVar15 = (long)local_88;
  func_0x007d46a0(param_2 + 0x18,0,0);
  *(undefined4 *)(param_2 + 0x168 + lVar15 * 0xc) = 0xffffffff;
  if (*(int *)(param_2 + 0x170 + lVar15 * 0xc) == 0) {
    iVar23 = *(int *)(param_2 + 0x198);
  }
  else {
    *(undefined4 *)(param_2 + 0x170 + lVar15 * 0xc) = 0;
    func_0x00c06910();
    iVar23 = *(int *)(param_2 + 0x198);
  }
  if (iVar23 != 0) {
    *(undefined4 *)(param_2 + 0x198) = 0;
    func_0x00c06910((undefined4 *)(param_2 + 0x198));
  }
  func_0x007d4eb0(param_2 + 0x18,0,0);
  if (_DAT_0391c310 == local_38) {
    return iVar10;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar7 = (code *)invalidInstructionException();
  (*pcVar7)();
LAB_009ab6dd:
  lVar12 = (long)local_40[0];
  local_88 = local_40[0];
  piVar1[lVar12 * 3] = uVar22;
  *(uint *)(param_2 + 0x16c + lVar12 * 0xc) = (uint)local_70;
  *(undefined4 *)(param_2 + 0x170 + lVar12 * 0xc) = 0;
  local_70 = (ulong)local_40[1];
  piVar1[local_70 * 3] = local_80;
  *(uint *)(param_2 + 0x16c + local_70 * 0xc) = local_78;
  *(undefined4 *)(param_2 + 0x170 + local_70 * 0xc) = 0;
  func_0x007d4eb0(param_2 + 0x18,0,0);
  goto LAB_009ab73a;
LAB_009aba41:
  iVar10 = 0x10;
  goto joined_r0x009abb42;
}



/* sub_9abca0 | RVA 0x9abca0 | local helper / adjacent context (reachability below)
 * Evidence ev_4174179a2f30bd0a0e1fba71c675625d71b19c47c49f871acfaf2277dbac8c08
 * Body [{"start": "0x9abca0", "end": "0x9abd7c"}, {"start": "0x9abd80", "end": "0x9abe73"}, {"start": "0x9abe80", "end": "0x9abf6b"}, {"start": "0x9abf70", "end": "0x9ac08b"}, {"start": "0x9ac090", "end": "0x9ac1a3"}, {"start": "0x9ac1b0", "end": "0x9ac295"}, {"start": "0x9ac2a0", "end": "0x9ac449"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_9abca0(long param_1,uint param_2,int param_3,int param_4,uint *param_5)

{
  ulong uVar1;
  int iVar2;
  uint uVar3;
  uint *puVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  long lVar10;
  int iVar11;
  long lVar12;
  int iVar13;
  int iVar14;
  int iVar15;
  ulong uVar16;
  bool bVar17;
  
  lVar10 = param_1 + 0x28;
  func_0x004c6a00(lVar10,0,0,0);
  uVar9 = *(uint *)(param_1 + 0x4c);
  uVar7 = *(uint *)(param_1 + 0x48);
  if (param_2 <= uVar9 + uVar7) {
    uVar6 = uVar7;
    uVar3 = uVar9;
    do {
      uVar5 = uVar6 - param_2;
      if (param_2 <= uVar6 && param_3 != 0) {
        if (param_2 == 0) goto LAB_009abe48;
        lVar12 = 2;
        puVar4 = param_5;
        uVar9 = param_2;
        goto LAB_009abd8a;
      }
      if (param_3 != 0) {
        if (uVar7 == 0) goto LAB_009abf47;
        lVar12 = 2;
        puVar4 = param_5;
        uVar6 = uVar7;
        goto LAB_009abe8a;
      }
      if (param_2 <= uVar3) {
        if (param_2 == 0) goto LAB_009ac16e;
        lVar12 = 2;
        puVar4 = param_5;
        uVar9 = param_2;
        goto LAB_009ac09a;
      }
      if (uVar6 < 0x20) {
        uVar7 = param_2 - uVar3;
        if (uVar7 == 0) goto LAB_009ac278;
        lVar12 = 2;
        puVar4 = param_5;
        uVar9 = uVar7;
        goto LAB_009ac1ba;
      }
      sub_9ac450(param_1);
      uVar6 = *(uint *)(param_1 + 0x48);
      uVar3 = *(uint *)(param_1 + 0x4c);
    } while (param_2 <= uVar6 + uVar3);
  }
  func_0x004c6fa0(lVar10,0,0,0);
  return 0xc;
LAB_009abd8a:
  do {
    iVar2 = 0;
    do {
      iVar15 = iVar2 + *(int *)(&DAT_013b9ed0 + lVar12 * 4);
      iVar14 = iVar2 * 0x40 + -0x40;
      do {
        iVar14 = iVar14 + 0x40;
        uVar16 = *(ulong *)(param_1 + 0x70 + (long)iVar15 * 8);
        iVar15 = iVar15 + 1;
      } while (uVar16 == 0);
      iVar15 = 0;
      for (; (uVar16 & 1) == 0; uVar16 = uVar16 >> 1 | 0x8000000000000000) {
        iVar15 = iVar15 + 1;
      }
      lVar12 = lVar12 + -1;
      iVar2 = iVar15 + iVar14;
    } while (lVar12 != 0);
    uVar7 = iVar15 + iVar14;
    uVar16 = *(ulong *)(param_1 + 0x70 + (long)(int)uVar7 * 8);
    do {
      uVar6 = uVar9;
      uVar9 = 0;
      for (uVar1 = uVar16; (uVar1 & 1) == 0; uVar1 = uVar1 >> 1 | 0x8000000000000000) {
        uVar9 = uVar9 + 1;
      }
      *puVar4 = uVar9 | uVar7 * 0x40;
      puVar4 = puVar4 + 1;
      uVar16 = uVar16 - 1 & uVar16;
      uVar9 = uVar6 - 1;
    } while ((uVar16 != 0) && (uVar6 != 1));
    *(ulong *)(param_1 + 0x70 + (long)(int)uVar7 * 8) = uVar16;
    if (uVar16 != 0) break;
    lVar12 = 0;
    do {
      uVar16 = (ulong)uVar7;
      uVar7 = (int)uVar7 >> 6;
      uVar16 = *(ulong *)(param_1 + 0x70 +
                         (long)(int)(*(int *)(&DAT_013b9ed4 + lVar12 * 4) + uVar7) * 8) &
               ~(1L << (uVar16 & 0x3f));
      *(ulong *)(param_1 + 0x70 + (long)(int)(*(int *)(&DAT_013b9ed4 + lVar12 * 4) + uVar7) * 8) =
           uVar16;
      bVar17 = lVar12 == 1;
      lVar12 = lVar12 + 1;
      if (bVar17) break;
    } while (uVar16 == 0);
  } while (uVar6 != 1);
LAB_009abe48:
  bVar17 = false;
  uVar7 = 0;
  goto LAB_009ac38b;
LAB_009abe8a:
  do {
    iVar2 = 0;
    do {
      iVar15 = iVar2 + *(int *)(&DAT_013b9ed0 + lVar12 * 4);
      iVar14 = iVar2 * 0x40 + -0x40;
      do {
        iVar14 = iVar14 + 0x40;
        uVar16 = *(ulong *)(param_1 + 0x70 + (long)iVar15 * 8);
        iVar15 = iVar15 + 1;
      } while (uVar16 == 0);
      iVar15 = 0;
      for (; (uVar16 & 1) == 0; uVar16 = uVar16 >> 1 | 0x8000000000000000) {
        iVar15 = iVar15 + 1;
      }
      lVar12 = lVar12 + -1;
      iVar2 = iVar15 + iVar14;
    } while (lVar12 != 0);
    uVar3 = iVar15 + iVar14;
    uVar16 = *(ulong *)(param_1 + 0x70 + (long)(int)uVar3 * 8);
    do {
      uVar5 = uVar6;
      uVar6 = 0;
      for (uVar1 = uVar16; (uVar1 & 1) == 0; uVar1 = uVar1 >> 1 | 0x8000000000000000) {
        uVar6 = uVar6 + 1;
      }
      *puVar4 = uVar6 | uVar3 * 0x40;
      puVar4 = puVar4 + 1;
      uVar16 = uVar16 - 1 & uVar16;
      uVar6 = uVar5 - 1;
    } while ((uVar16 != 0) && (uVar5 != 1));
    *(ulong *)(param_1 + 0x70 + (long)(int)uVar3 * 8) = uVar16;
    if (uVar16 != 0) break;
    lVar12 = 0;
    do {
      uVar16 = (ulong)uVar3;
      uVar3 = (int)uVar3 >> 6;
      uVar16 = *(ulong *)(param_1 + 0x70 +
                         (long)(int)(*(int *)(&DAT_013b9ed4 + lVar12 * 4) + uVar3) * 8) &
               ~(1L << (uVar16 & 0x3f));
      *(ulong *)(param_1 + 0x70 + (long)(int)(*(int *)(&DAT_013b9ed4 + lVar12 * 4) + uVar3) * 8) =
           uVar16;
      bVar17 = lVar12 == 1;
      lVar12 = lVar12 + 1;
      if (bVar17) break;
    } while (uVar16 == 0);
  } while (uVar5 != 1);
LAB_009abf47:
  iVar2 = param_2 - uVar7;
  if (iVar2 != 0) {
    lVar12 = 2;
    puVar4 = param_5 + uVar7;
    iVar14 = iVar2;
    do {
      iVar15 = 0;
      do {
        iVar13 = iVar15 + *(int *)(&DAT_013b9ed0 + lVar12 * 4);
        iVar11 = iVar15 * 0x40 + -0x40;
        do {
          iVar11 = iVar11 + 0x40;
          uVar16 = *(ulong *)(param_1 + 0x20890 + (long)iVar13 * 8);
          iVar13 = iVar13 + 1;
        } while (uVar16 == 0);
        iVar13 = 0;
        for (; (uVar16 & 1) == 0; uVar16 = uVar16 >> 1 | 0x8000000000000000) {
          iVar13 = iVar13 + 1;
        }
        lVar12 = lVar12 + -1;
        iVar15 = iVar13 + iVar11;
      } while (lVar12 != 0);
      uVar7 = iVar13 + iVar11;
      uVar16 = *(ulong *)(param_1 + 0x20890 + (long)(int)uVar7 * 8);
      do {
        iVar15 = iVar14;
        uVar6 = 0;
        for (uVar1 = uVar16; (uVar1 & 1) == 0; uVar1 = uVar1 >> 1 | 0x8000000000000000) {
          uVar6 = uVar6 + 1;
        }
        *puVar4 = uVar6 | uVar7 * 0x40;
        puVar4 = puVar4 + 1;
        uVar16 = uVar16 - 1 & uVar16;
        iVar14 = iVar15 + -1;
      } while ((uVar16 != 0) && (iVar15 != 1));
      *(ulong *)(param_1 + 0x20890 + (long)(int)uVar7 * 8) = uVar16;
      if (uVar16 != 0) break;
      lVar12 = 0;
      do {
        uVar16 = (ulong)uVar7;
        uVar7 = (int)uVar7 >> 6;
        uVar16 = *(ulong *)(param_1 + 0x20890 +
                           (long)(int)(*(int *)(&DAT_013b9ed4 + lVar12 * 4) + uVar7) * 8) &
                 ~(1L << (uVar16 & 0x3f));
        *(ulong *)(param_1 + 0x20890 + (long)(int)(*(int *)(&DAT_013b9ed4 + lVar12 * 4) + uVar7) * 8
                  ) = uVar16;
        bVar17 = lVar12 == 1;
        lVar12 = lVar12 + 1;
        if (bVar17) break;
      } while (uVar16 == 0);
    } while (iVar15 != 1);
  }
  bVar17 = false;
  uVar7 = 0;
  uVar5 = 0;
  uVar3 = uVar9 - iVar2;
  goto LAB_009ac38b;
LAB_009ac09a:
  do {
    iVar2 = 0;
    do {
      iVar15 = iVar2 + *(int *)(&DAT_013b9ed0 + lVar12 * 4);
      iVar14 = iVar2 * 0x40 + -0x40;
      do {
        iVar14 = iVar14 + 0x40;
        uVar16 = *(ulong *)(param_1 + 0x20890 + (long)iVar15 * 8);
        iVar15 = iVar15 + 1;
      } while (uVar16 == 0);
      iVar15 = 0;
      for (; (uVar16 & 1) == 0; uVar16 = uVar16 >> 1 | 0x8000000000000000) {
        iVar15 = iVar15 + 1;
      }
      lVar12 = lVar12 + -1;
      iVar2 = iVar15 + iVar14;
    } while (lVar12 != 0);
    uVar7 = iVar15 + iVar14;
    uVar16 = *(ulong *)(param_1 + 0x20890 + (long)(int)uVar7 * 8);
    do {
      uVar5 = uVar9;
      uVar9 = 0;
      for (uVar1 = uVar16; (uVar1 & 1) == 0; uVar1 = uVar1 >> 1 | 0x8000000000000000) {
        uVar9 = uVar9 + 1;
      }
      *puVar4 = uVar9 | uVar7 * 0x40;
      puVar4 = puVar4 + 1;
      uVar16 = uVar16 - 1 & uVar16;
      uVar9 = uVar5 - 1;
    } while ((uVar16 != 0) && (uVar5 != 1));
    *(ulong *)(param_1 + 0x20890 + (long)(int)uVar7 * 8) = uVar16;
    if (uVar16 != 0) break;
    lVar12 = 0;
    do {
      uVar16 = (ulong)uVar7;
      uVar7 = (int)uVar7 >> 6;
      uVar16 = *(ulong *)(param_1 + 0x20890 +
                         (long)(int)(*(int *)(&DAT_013b9ed4 + lVar12 * 4) + uVar7) * 8) &
               ~(1L << (uVar16 & 0x3f));
      *(ulong *)(param_1 + 0x20890 + (long)(int)(*(int *)(&DAT_013b9ed4 + lVar12 * 4) + uVar7) * 8)
           = uVar16;
      bVar17 = lVar12 == 1;
      lVar12 = lVar12 + 1;
      if (bVar17) break;
    } while (uVar16 == 0);
  } while (uVar5 != 1);
LAB_009ac16e:
  uVar3 = uVar3 - param_2;
  uVar7 = 0;
  uVar5 = uVar6;
  goto LAB_009ac386;
LAB_009ac1ba:
  do {
    iVar2 = 0;
    do {
      iVar15 = iVar2 + *(int *)(&DAT_013b9ed0 + lVar12 * 4);
      iVar14 = iVar2 * 0x40 + -0x40;
      do {
        iVar14 = iVar14 + 0x40;
        uVar16 = *(ulong *)(param_1 + 0x70 + (long)iVar15 * 8);
        iVar15 = iVar15 + 1;
      } while (uVar16 == 0);
      iVar15 = 0;
      for (; (uVar16 & 1) == 0; uVar16 = uVar16 >> 1 | 0x8000000000000000) {
        iVar15 = iVar15 + 1;
      }
      lVar12 = lVar12 + -1;
      iVar2 = iVar15 + iVar14;
    } while (lVar12 != 0);
    uVar5 = iVar15 + iVar14;
    uVar16 = *(ulong *)(param_1 + 0x70 + (long)(int)uVar5 * 8);
    do {
      uVar8 = uVar9;
      uVar9 = 0;
      for (uVar1 = uVar16; (uVar1 & 1) == 0; uVar1 = uVar1 >> 1 | 0x8000000000000000) {
        uVar9 = uVar9 + 1;
      }
      *puVar4 = uVar9 | uVar5 * 0x40;
      puVar4 = puVar4 + 1;
      uVar16 = uVar16 - 1 & uVar16;
      uVar9 = uVar8 - 1;
    } while ((uVar16 != 0) && (uVar8 != 1));
    *(ulong *)(param_1 + 0x70 + (long)(int)uVar5 * 8) = uVar16;
    if (uVar16 != 0) break;
    lVar12 = 0;
    do {
      uVar16 = (ulong)uVar5;
      uVar5 = (int)uVar5 >> 6;
      uVar16 = *(ulong *)(param_1 + 0x70 +
                         (long)(int)(*(int *)(&DAT_013b9ed4 + lVar12 * 4) + uVar5) * 8) &
               ~(1L << (uVar16 & 0x3f));
      *(ulong *)(param_1 + 0x70 + (long)(int)(*(int *)(&DAT_013b9ed4 + lVar12 * 4) + uVar5) * 8) =
           uVar16;
      bVar17 = lVar12 == 1;
      lVar12 = lVar12 + 1;
      if (bVar17) break;
    } while (uVar16 == 0);
  } while (uVar8 != 1);
LAB_009ac278:
  if (uVar3 != 0) {
    lVar12 = 2;
    puVar4 = param_5 + uVar7;
    do {
      iVar2 = 0;
      do {
        iVar15 = iVar2 + *(int *)(&DAT_013b9ed0 + lVar12 * 4);
        iVar14 = iVar2 * 0x40 + -0x40;
        do {
          iVar14 = iVar14 + 0x40;
          uVar16 = *(ulong *)(param_1 + 0x20890 + (long)iVar15 * 8);
          iVar15 = iVar15 + 1;
        } while (uVar16 == 0);
        iVar15 = 0;
        for (; (uVar16 & 1) == 0; uVar16 = uVar16 >> 1 | 0x8000000000000000) {
          iVar15 = iVar15 + 1;
        }
        lVar12 = lVar12 + -1;
        iVar2 = iVar15 + iVar14;
      } while (lVar12 != 0);
      uVar9 = iVar15 + iVar14;
      uVar16 = *(ulong *)(param_1 + 0x20890 + (long)(int)uVar9 * 8);
      do {
        uVar5 = uVar3;
        uVar3 = 0;
        for (uVar1 = uVar16; (uVar1 & 1) == 0; uVar1 = uVar1 >> 1 | 0x8000000000000000) {
          uVar3 = uVar3 + 1;
        }
        *puVar4 = uVar3 | uVar9 * 0x40;
        puVar4 = puVar4 + 1;
        uVar16 = uVar16 - 1 & uVar16;
        uVar3 = uVar5 - 1;
      } while ((uVar16 != 0) && (uVar5 != 1));
      *(ulong *)(param_1 + 0x20890 + (long)(int)uVar9 * 8) = uVar16;
      if (uVar16 != 0) break;
      lVar12 = 0;
      do {
        uVar16 = (ulong)uVar9;
        uVar9 = (int)uVar9 >> 6;
        uVar16 = *(ulong *)(param_1 + 0x20890 +
                           (long)(int)(*(int *)(&DAT_013b9ed4 + lVar12 * 4) + uVar9) * 8) &
                 ~(1L << (uVar16 & 0x3f));
        *(ulong *)(param_1 + 0x20890 + (long)(int)(*(int *)(&DAT_013b9ed4 + lVar12 * 4) + uVar9) * 8
                  ) = uVar16;
        bVar17 = lVar12 == 1;
        lVar12 = lVar12 + 1;
        if (bVar17) break;
      } while (uVar16 == 0);
    } while (uVar5 != 1);
  }
  uVar3 = 0;
  uVar5 = uVar6 - uVar7;
LAB_009ac386:
  bVar17 = true;
LAB_009ac38b:
  *(uint *)(param_1 + 0x48) = uVar5;
  *(uint *)(param_1 + 0x4c) = uVar3;
  if (param_4 == 0) {
    *(int *)(param_1 + 0x54) = *(int *)(param_1 + 0x54) + param_2;
  }
  else {
    *(int *)(param_1 + 0x50) = *(int *)(param_1 + 0x50) + param_2;
  }
  if ((bVar17) && ((*(byte *)(param_1 + 0x68) & 1) != 0)) {
    iVar2 = *(int *)(param_1 + 0x5c);
    *(byte *)(param_1 + 0x68) = *(byte *)(param_1 + 0x68) | 2;
    do {
      func_0x00c06260((int *)(param_1 + 0x5c),param_1 + 0x10,0x44,0x132208a,0,0,0x100);
    } while (iVar2 == *(int *)(param_1 + 0x5c));
  }
  func_0x004c6fa0(lVar10,0,0,0);
  if (0 < (int)uVar7) {
    uVar16 = 0;
    do {
      sub_9ac500(param_1,param_5[uVar16] & 0xfffff);
      uVar16 = uVar16 + 1;
    } while (uVar7 != uVar16);
  }
  return 0;
}



/* sub_9ac450 | RVA 0x9ac450 | local helper / adjacent context (reachability below)
 * Evidence ev_af5a550ba0c26f24a48ec79fe9243aa24f049b8fe68b60e647524b2f9cf75248
 * Body [{"start": "0x9ac450", "end": "0x9ac4f4"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_9ac450(long param_1)

{
  ulong *puVar1;
  byte bVar2;
  long lVar3;
  
  lVar3 = -0x20820;
  do {
    puVar1 = (ulong *)(param_1 + 0x410b0 + lVar3);
    *puVar1 = *puVar1 | *(ulong *)(param_1 + 0x20890 + lVar3);
    *(undefined8 *)(param_1 + 0x20890 + lVar3) = 0;
    lVar3 = lVar3 + 8;
  } while (lVar3 != 0);
  *(int *)(param_1 + 0x4c) = *(int *)(param_1 + 0x4c) + *(int *)(param_1 + 0x48);
  *(undefined4 *)(param_1 + 0x48) = 0;
  *(byte *)(param_1 + 0x68) = *(byte *)(param_1 + 0x68) | 1;
  func_0x004c6fa0(param_1 + 0x28,0,0,0);
  func_0x008de020();
  func_0x004c6a00(param_1 + 0x28,0,0,0);
  bVar2 = *(byte *)(param_1 + 0x68);
  *(byte *)(param_1 + 0x68) = bVar2 & 0xfe;
  if ((bVar2 & 2) == 0) {
    return;
  }
  *(byte *)(param_1 + 0x68) = bVar2 & 0xfc;
  *(int *)(param_1 + 0x5c) = *(int *)(param_1 + 0x5c) + 1;
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* sub_9ac500 | RVA 0x9ac500 | local helper / adjacent context (reachability below)
 * Evidence ev_25a3c187a09e194d4d70656bc6049e7545cf31f7fef1b066e04bce8397953ecc
 * Body [{"start": "0x9ac500", "end": "0x9ac655"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_9ac500(long param_1,uint param_2)

{
  int *piVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  long lVar5;
  int iVar6;
  long lVar7;
  ulong uVar8;
  ulong uVar9;
  long lVar10;
  long *in_GS_OFFSET;
  
  lVar7 = *(long *)(param_1 + 0x30);
  uVar9 = (ulong)_DAT_025567e0;
  lVar10 = (ulong)param_2 * 0x10000;
  LOCK();
  *(int *)(*in_GS_OFFSET + 0x5a8) = *(int *)(*in_GS_OFFSET + 0x5a8) + 1;
  lVar5 = _DAT_03ba5eb8;
  UNLOCK();
  uVar8 = (ulong)(uint)(*(int *)((long)in_GS_OFFSET + 0x34) << 0x10);
  lVar2 = _DAT_03ba5eb8 + uVar8;
  func_0x008de9e0(lVar2,lVar7 + lVar10,1);
  lVar3 = lVar5 + 0x4000 + uVar8;
  func_0x008de9e0(lVar3,lVar7 + 0x4000 + lVar10,1);
  lVar4 = lVar5 + 0x8000 + uVar8;
  func_0x008de9e0(lVar4,lVar7 + 0x8000 + lVar10,1);
  lVar5 = lVar5 + 0xc000 + uVar8;
  func_0x008de9e0(lVar5,lVar7 + 0xc000 + lVar10,1);
  uVar8 = 0;
  do {
    clflush(*(undefined1 *)(lVar2 + uVar8));
    uVar8 = uVar8 + uVar9;
  } while (uVar8 < 0x10000);
  func_0x008deb20(lVar2);
  func_0x008deb20(lVar3);
  func_0x008deb20(lVar4);
  func_0x008deb20(lVar5);
  func_0x008ddbf0(0x3b48ff8,lVar2,lVar2 + 0x10000);
  LOCK();
  piVar1 = (int *)(*in_GS_OFFSET + 0x5a8);
  iVar6 = *piVar1;
  *piVar1 = *piVar1 + -1;
  UNLOCK();
  if (iVar6 == -0x7fffffff) {
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  return;
}



/* sub_9ac660 | RVA 0x9ac660 | local helper / adjacent context (reachability below)
 * Evidence ev_e385e32af382cdd5185505ae92f300c512542cc0e3fa6a3d5abfc0ba59bfd258
 * Body [{"start": "0x9ac660", "end": "0x9ac66a"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_9ac660(void)

{
  return 6;
}



/* sub_9ac670 | RVA 0x9ac670 | local helper / adjacent context (reachability below)
 * Evidence ev_c37e81d7fea037c866f57dbf8816f4c513b4e58163fcb9c2dd7d770aed413ad5
 * Body [{"start": "0x9ac670", "end": "0x9ac67a"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_9ac670(void)

{
  return 6;
}



/* sub_9ac680 | RVA 0x9ac680 | local helper / adjacent context (reachability below)
 * Evidence ev_83900ca412c6f0d826b55504188b5a27e52625580075f57e4dbb45ecaf8f2483
 * Body [{"start": "0x9ac680", "end": "0x9ac987"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_9ac680(long *param_1,long param_2,long *param_3)

{
  long lVar1;
  ulong uVar2;
  long lVar3;
  code *pcVar4;
  byte bVar5;
  int iVar6;
  uint uVar7;
  ulong uVar8;
  ulong uVar9;
  uint uVar10;
  ulong uVar11;
  ulong uVar12;
  long lVar13;
  long lVar14;
  ulong uVar15;
  long lVar16;
  int iVar17;
  long *in_GS_OFFSET;
  bool bVar18;
  long local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  lVar1 = *param_1;
  if (param_2 == 0x4010a802) {
    func_0x004c6a00(lVar1 + 0x28,0,0,0);
    *(undefined4 *)param_3 = *(undefined4 *)(lVar1 + 0x4c);
    *(undefined4 *)((long)param_3 + 4) = *(undefined4 *)(lVar1 + 0x48);
    *(undefined4 *)(param_3 + 1) = *(undefined4 *)(lVar1 + 0x54);
    *(undefined4 *)((long)param_3 + 0xc) = *(undefined4 *)(lVar1 + 0x50);
    func_0x004c6fa0(lVar1 + 0x28,0,0,0);
    iVar17 = 0;
  }
  else {
    iVar17 = 0x19;
    if (param_2 == 0xc020a801) {
      lVar16 = *param_3;
      uVar7 = *(uint *)(param_3 + 3);
      iVar17 = 0x16;
      if ((uVar7 & 0xffffff) == 0 && (short)lVar16 == 0) {
        if (uVar7 == 0) {
          uVar8 = 0x10;
        }
        else {
          uVar8 = (ulong)(uint)((int)uVar7 >> 0x18);
          if ((int)uVar7 >> 0x18 < 0x10) goto LAB_009ac7e6;
        }
        if (lVar16 == 0) {
          iVar17 = 0;
        }
        else if (lVar16 < 0) {
          iVar17 = 0xc;
        }
        else {
          lVar13 = param_3[1];
          if (param_3[1] < *(long *)(lVar1 + 0x38)) {
            lVar13 = *(long *)(lVar1 + 0x38);
          }
          lVar14 = param_3[2];
          if (*(long *)(lVar1 + 0x40) < param_3[2]) {
            lVar14 = *(long *)(lVar1 + 0x40);
          }
          iVar6 = func_0x003c3950(*(undefined4 *)(lVar1 + 0x60),0,*(undefined4 *)(lVar1 + 100),
                                  *(long *)(*in_GS_OFFSET + 8),lVar13,lVar14,lVar16,
                                  1L << (uVar8 & 0x3f),
                                  ((*(byte *)(*(long *)(*in_GS_OFFSET + 8) + 0x588) & 1) == 0) *
                                  '\b' + '\x03',0x20000000,&local_40);
          if (iVar6 == 0) {
            uVar8 = 0;
            func_0x004c6a00(lVar1 + 0x28,0,0,0);
            *(int *)(lVar1 + 0x4c) = *(int *)(lVar1 + 0x4c) + (int)((ulong)lVar16 >> 0x10);
            uVar9 = local_40 - *(long *)(lVar1 + 0x38);
            uVar11 = lVar16 + 0xffffffff0000 + uVar9 >> 0x10;
            uVar9 = uVar9 >> 0x10;
            do {
              iVar17 = *(int *)(&DAT_013b9ed0 + uVar8 * 4);
              bVar5 = (byte)uVar11;
              uVar7 = (int)uVar9 >> 6;
              uVar10 = (int)uVar11 >> 6;
              uVar11 = (ulong)uVar10;
              lVar16 = (long)(int)uVar7;
              uVar15 = 0xffffffffffffffff >> ((ulong)(byte)~bVar5 & 0x3f);
              uVar12 = 0xffffffffffffffff;
              if (uVar7 == uVar10) {
                uVar12 = uVar15;
              }
              lVar13 = lVar1 + 0x20890 + (long)iVar17 * 8;
              uVar2 = *(ulong *)(lVar13 + lVar16 * 8);
              bVar18 = uVar2 == 0;
              *(ulong *)(lVar13 + lVar16 * 8) = (uVar12 >> (uVar9 & 0x3f)) << (uVar9 & 0x3f) | uVar2
              ;
              if (uVar7 != uVar10) {
                if ((int)(uVar7 + 1) < (int)uVar10) {
                  lVar14 = lVar1 + 0x20898 + (long)iVar17 * 8;
                  do {
                    lVar3 = *(long *)(lVar14 + lVar16 * 8);
                    *(undefined8 *)(lVar14 + lVar16 * 8) = 0xffffffffffffffff;
                    lVar16 = lVar16 + 1;
                    bVar18 = (bool)(bVar18 | lVar3 == 0);
                  } while ((long)(int)uVar10 + -1 != lVar16);
                }
                uVar9 = *(ulong *)(lVar13 + (long)(int)uVar10 * 8);
                *(ulong *)(lVar13 + (long)(int)uVar10 * 8) = uVar15 | uVar9;
                bVar18 = (bool)(bVar18 | uVar9 == 0);
              }
            } while ((bVar18) &&
                    (bVar18 = uVar8 < 2, uVar8 = uVar8 + 1, uVar9 = (ulong)uVar7, bVar18));
            func_0x004c6fa0(lVar1 + 0x28,0,0,0);
            param_3[1] = local_40;
            iVar17 = 0;
          }
          else {
            iVar17 = 0xc;
            if (iVar6 != 0x23) {
              iVar17 = iVar6;
            }
          }
        }
      }
    }
  }
LAB_009ac7e6:
  if (_DAT_0391c310 == local_38) {
    return iVar17;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar4 = (code *)invalidInstructionException();
  (*pcVar4)();
}



/* sub_9ac990 | RVA 0x9ac990 | local helper / adjacent context (reachability below)
 * Evidence ev_bb79ccd73cc66626fbcdf8871f286f666a53f4420aa876a83953926d684bc1a9
 * Body [{"start": "0x9ac990", "end": "0x9ac99a"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_9ac990(void)

{
  return 0x2d;
}



/* sub_9ac9a0 | RVA 0x9ac9a0 | local helper / adjacent context (reachability below)
 * Evidence ev_512b588d15e6bd12acd5192a4abcb091d4c414869d3d5b8fb4b34b00ef55cea8
 * Body [{"start": "0x9ac9a0", "end": "0x9ac9aa"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_9ac9a0(void)

{
  return 0x2d;
}



/* sub_9ac9b0 | RVA 0x9ac9b0 | local helper / adjacent context (reachability below)
 * Evidence ev_44348483c051260b0e4ee34b50c8da4e96a3f70db3f944db8aafe503f61433b3
 * Body [{"start": "0x9ac9b0", "end": "0x9aca13"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_9ac9b0(long *param_1,long param_2)

{
  long lVar1;
  long lVar2;
  
  func_0x00258ff0(param_2,0x78);
  lVar2 = *param_1;
  *(undefined4 *)(param_2 + 0x58) = 0x10000;
  *(undefined2 *)(param_2 + 8) = 0xb000;
  lVar1 = lVar2 + 0x28;
  func_0x004c6a00(lVar1,0,0,0);
  *(ulong *)(param_2 + 0x50) = (ulong)(uint)(*(int *)(lVar2 + 0x48) * 2);
  func_0x004c6fa0(lVar1,0,0,0);
  return 0;
}



/* sub_9aca3c | RVA 0x9aca3c | local helper / adjacent context (reachability below)
 * Evidence ev_b570df485c486958df7236d440d367729297c9d3de732b99819d71f90b9cfc60
 * Body [{"start": "0x9aca3c", "end": "0x9aca48"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_9aca3c(void)

{
  func_0x009a7c00();
  return 0;
}



/* sub_9aca50 | RVA 0x9aca50 | local helper / adjacent context (reachability below)
 * Evidence ev_f65959489d0f99043ec878ca7f9209822476a606f748b7768497a9f7ceeea0e2
 * Body [{"start": "0x9aca50", "end": "0x9aca5e"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_9aca50(undefined8 param_1,long param_2)

{
  *(undefined4 *)(param_2 + 4) = 0xff;
  return 0;
}



/* sub_9aca60 | RVA 0x9aca60 | local helper / adjacent context (reachability below)
 * Evidence ev_d7e543bf38af22b885b98dec514492c214282fbbb917cb5ef52f896df6fdeec1
 * Body [{"start": "0x9aca60", "end": "0x9acc0b"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

int sub_9aca60(undefined8 *param_1,undefined8 param_2,ulong *param_3,ulong param_4,ushort param_5,
              ushort param_6,uint param_7,long param_8,long param_9)

{
  ulong uVar1;
  undefined1 uVar2;
  int iVar3;
  long lVar4;
  long *in_GS_OFFSET;
  
  iVar3 = 0x16;
  if (param_8 == 0) {
    if ((param_7 & 0xff000000) == 0) {
      param_7 = param_7 | 0x15000000;
    }
    else if ((int)(param_7 & 0xff000000) < 0x15000000) {
      return 0x16;
    }
    if ((~(param_6 & param_5) & 0x33) == 0 && (param_7 & 3) == 1) {
      if ((param_7 & 0x10) == 0) {
        if ((param_4 & 0x1fffff) != 0) {
          return 0x16;
        }
      }
      else {
        uVar1 = *param_3;
        if ((uVar1 & 0x1fffff) != 0) {
          return 0x16;
        }
        if ((param_4 & 0x1fffff) != 0) {
          return 0x16;
        }
        if (uVar1 >> 0x1c < 0xff && 0x7e < uVar1 + param_4 >> 0x1c) {
          return 0x16;
        }
      }
      lVar4 = func_0x0045da60(0xb,*param_1,param_4,0x33,0,*(undefined8 *)(param_9 + 0x140),
                              *(undefined4 *)(*(long *)(param_9 + 8) + 0x5c0),
                              *(undefined4 *)(*(long *)(param_9 + 8) + 0x5d0));
      if (lVar4 == 0) {
        iVar3 = 0xc;
      }
      else {
        iVar3 = func_0x00ab9f30(param_2,param_3,param_4,param_5,0x33,param_7,lVar4,0,0,param_9);
        if (iVar3 == 0) {
          if ((*param_3 >> 0x1c < 0xff) && (0x7f0000000 < *param_3 + param_4)) {
            uVar2 = 0;
          }
          else {
            uVar2 = *(undefined1 *)(*(long *)(*in_GS_OFFSET + 8) + 0x5c0);
          }
          *(undefined1 *)(lVar4 + 0x19c) = uVar2;
          iVar3 = 0;
        }
        else {
          func_0x00461ba0(lVar4);
        }
      }
    }
  }
  return iVar3;
}



/* FUN_009acc10 | RVA 0x9acc10 | local helper / adjacent context (reachability below)
 * Evidence ev_dd7f854ea45e03982acbdfd7a35d82a08efe81bb4d02facc9f6611a94100e570
 * Body [{"start": "0x9acc10", "end": "0x9acc21"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined4 FUN_009acc10(uint param_1)

{
  code *pcVar1;
  
  if (param_1 < 0x15) {
    return *(undefined4 *)((ulong)param_1 * 4 + 0x18cdbb4);
  }
  func_0x007f1950();
  func_0x007f18a0(sub_9acc22,(long)(int)param_1);
  func_0x00c9aa10(7,0x12947a2,param_1);
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* sub_9acc22 | RVA 0x9acc22 | local helper / adjacent context (reachability below)
 * Evidence ev_9a32cdabb18d359c9028e92022253f47585128f2cb0c3fbb76d2123f4d5d658b
 * Body [{"start": "0x9acc22", "end": "0x9acc54"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_9acc22(int param_1)

{
  code *pcVar1;
  
  func_0x007f1950();
  func_0x007f18a0(sub_9acc22,(long)param_1);
  func_0x00c9aa10(7,0x12947a2,param_1);
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* sub_9acc60 | RVA 0x9acc60 | local helper / adjacent context (reachability below)
 * Evidence ev_8d74b53b1f263902b57715a372fb6c1d119a443247bee1bb6b0457e4b94908b1
 * Body [{"start": "0x9acc60", "end": "0x9accd2"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_9acc60(void)

{
  _DAT_03ba5e80 = 0;
  _DAT_03ba5e88 = &DAT_03ba5e80;
  _DAT_03ba5eb8 = func_0x005033b0(0x400000);
  _DAT_03ba5ec0 = 0x400000004;
  _DAT_03ba5ec8 = 0x80;
  _DAT_03ba5ee0 = func_0x00c08b50(0x8000,0x2bfb810,0x8002);
  _DAT_03ba5ed8 = 0xf;
  return;
}



/* sub_9accec | RVA 0x9accec | local helper / adjacent context (reachability below)
 * Evidence ev_2878e5d36ed85b4e0b2456ec14a540b6e4b58ea3ff6295b0679406de2234a871
 * Body [{"start": "0x9accec", "end": "0x9acd37"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_9accec(void)

{
  int iVar1;
  uint uVar2;
  
  iVar1 = func_0x00b07940();
  uVar2 = 1;
  if (iVar1 == 0) {
    iVar1 = func_0x00b07960();
    uVar2 = 1;
    if (iVar1 == 0) {
      iVar1 = func_0x00b07920();
      if (iVar1 == 0) {
        uVar2 = 0;
      }
      else {
        iVar1 = func_0x00acc9a0(0x6e);
        uVar2 = (uint)(iVar1 != 0);
      }
    }
  }
  _DAT_02560040 = uVar2;
  return;
}



/* sub_9acd40 | RVA 0x9acd40 | local helper / adjacent context (reachability below)
 * Evidence ev_75c4f3fdb18891ab2e24f2a2d33dbca3dabb5a18978f7870f3ba069afc4a8923
 * Body [{"start": "0x9acd40", "end": "0x9acddf"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_9acd40(long param_1,int param_2)

{
  long lVar1;
  int iVar2;
  
  if (param_2 == -1) {
    param_2 = 0x23;
  }
  else {
    iVar2 = sub_9ad320(param_1);
    if (iVar2 != 0) {
      func_0x004c6a00(0x3ba5f00,0,0,0);
      _DAT_03ba5f08 = _DAT_03ba5f08 + -1;
      if ((_DAT_03ba5f08 == 0) && (_DAT_03ba5f0c != 0)) {
        func_0x0073f010(0x3ba5f10,0);
      }
      func_0x004c6fa0(0x3ba5f00,0,0,0);
    }
  }
  lVar1 = *(long *)(param_1 + 0x68);
  if (lVar1 != 0) {
    *(undefined8 *)(param_1 + 0x68) = 0;
    func_0x00c08df0(lVar1,0x255ffd0);
  }
  if (param_2 != 0) {
    *(int *)(param_1 + 0x48) = param_2;
    *(byte *)(param_1 + 2) = *(byte *)(param_1 + 2) | 1;
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* sub_9acde0 | RVA 0x9acde0 | local helper / adjacent context (reachability below)
 * Evidence ev_f47811b4315f3af5690222a545616c760bc22c34e9b3ea9d03181ce9da3b40cd
 * Body [{"start": "0x9acde0", "end": "0x9ad02b"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong sub_9acde0(long param_1,undefined8 param_2,undefined8 param_3)

{
  code *pcVar1;
  bool bVar2;
  uint uVar3;
  int iVar4;
  long lVar5;
  undefined4 uVar6;
  long lVar7;
  char cVar8;
  ulong uVar9;
  long local_48;
  long local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  uVar9 = *(long *)(param_1 + 0x130) + *(long *)(param_1 + 0x20);
  lVar5 = *(long *)(param_1 + 0x30);
  uVar3 = _DAT_02560040;
  if (_DAT_02560040 == 0xffffffff) {
    iVar4 = func_0x00b07940();
    uVar3 = 1;
    if ((iVar4 == 0) && (iVar4 = func_0x00b07960(), iVar4 == 0)) {
      iVar4 = func_0x00b07920();
      if (iVar4 == 0) {
        uVar3 = 0;
      }
      else {
        iVar4 = func_0x00acc9a0(0x6e);
        uVar3 = (uint)(iVar4 != 0);
      }
    }
  }
  _DAT_02560040 = uVar3;
  if (_DAT_02560040 != 0) {
    local_48 = 0;
    iVar4 = func_0x003d6df0(0x10003,&local_40,&local_48);
    if (iVar4 == 0) {
      if ((local_40 <= (long)(uVar9 >> 0x10)) && ((long)((uVar9 >> 0x10) - local_40) < local_48)) {
        bVar2 = false;
        cVar8 = '\x03';
        goto LAB_009acf23;
      }
    }
    else {
      func_0x0025d410(0x127c65f,0x12af557,iVar4);
    }
  }
  uVar3 = _DAT_02560040;
  if (_DAT_02560040 == 0xffffffff) {
    iVar4 = func_0x00b07940();
    uVar3 = 1;
    if ((iVar4 == 0) && (iVar4 = func_0x00b07960(), iVar4 == 0)) {
      iVar4 = func_0x00b07920();
      if (iVar4 == 0) {
        uVar3 = 0;
      }
      else {
        iVar4 = func_0x00acc9a0(0x6e);
        uVar3 = (uint)(iVar4 != 0);
      }
    }
  }
  _DAT_02560040 = uVar3;
  bVar2 = true;
  cVar8 = (_DAT_02560040 == 0) + '\x01';
LAB_009acf23:
  if (((short)uVar9 == 0) &&
     (0xffff < (ulong)(*(long *)(param_1 + 0x128) - *(long *)(param_1 + 0x130)))) {
    lVar7 = 0;
  }
  else if ((*(long *)(param_1 + 0x130) == 0) ||
          (lVar5 = *(long *)(param_1 + 0x68), lVar7 = lVar5, lVar5 == 0)) {
    lVar5 = func_0x00c08b50(0x10000,0x255ffd0,0x102);
    lVar7 = lVar5;
  }
  uVar9 = uVar9 >> 9 & 0xffffffffffffff80;
  *(long *)(param_1 + 0x68) = lVar7;
  uVar6 = 0x20010401;
  if (!bVar2) {
    uVar9 = func_0x009e1f40(uVar9);
    uVar6 = 0x80010500;
  }
  uVar9 = func_0x00689b00(cVar8,uVar9 | 0x400000000000,lVar5,param_2,0,uVar6,param_3);
  if ((lVar7 != 0) && ((int)uVar9 != 0)) {
    uVar9 = uVar9 & 0xffffffff;
    *(undefined8 *)(param_1 + 0x68) = 0;
    func_0x00c08df0(lVar7,0x255ffd0);
  }
  if (_DAT_0391c310 == local_38) {
    return uVar9;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* sub_9ad030 | RVA 0x9ad030 | local helper / adjacent context (reachability below)
 * Evidence ev_fb4f0c706b760e03583754e1b0cc91bf84cd7ab2afbdde9515bdbac9d978f5cd
 * Body [{"start": "0x9ad030", "end": "0x9ad318"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_9ad030(long *param_1,undefined4 param_2)

{
  long lVar1;
  long lVar2;
  long lVar3;
  code *pcVar4;
  undefined4 uVar5;
  uint uVar6;
  int iVar7;
  long *plVar8;
  ulong uVar9;
  long *plVar10;
  undefined8 uVar11;
  undefined8 uVar12;
  ulong uVar13;
  ulong uVar14;
  undefined4 local_44;
  ushort local_3e;
  undefined4 local_3c;
  long local_38;
  
  local_38 = _DAT_0391c310;
  lVar1 = *param_1;
  lVar2 = param_1[1];
  uVar13 = (ulong)*(ushort *)(lVar1 + 0x20);
  lVar3 = *(long *)(lVar1 + 0x68);
  local_3e = 0;
  local_44 = 0;
  iVar7 = 0x21c1;
  if (*(int *)(lVar1 + 0x198) != 0) {
    iVar7 = *(int *)(lVar1 + 0x198);
  }
  uVar5 = func_0x005f0f70(iVar7);
  uVar6 = func_0x0068e1a0(param_2,&local_3e,&local_44,0);
  if (uVar6 == 0) {
    func_0x00c08df0(param_1,0x255ffd0);
    uVar6 = (uint)local_3e;
    if (local_3e != 0) {
      uVar12 = 0x13079f2;
      uVar11 = 0x13b0051;
      param_2 = local_44;
      goto LAB_009ad0f2;
    }
    if (lVar3 == 0) {
      uVar14 = 0x10000 - uVar13;
    }
    else {
      uVar14 = 0x10000 - uVar13;
      uVar9 = *(ulong *)(lVar1 + 0x128);
      if (0x10000 < *(ulong *)(lVar1 + 0x128) + uVar13) {
        uVar9 = uVar14;
      }
      func_0x00259be0(lVar3 + uVar13,*(undefined8 *)(lVar1 + 0x30),uVar9);
    }
    uVar13 = *(ulong *)(lVar1 + 0x128);
    if (uVar13 < uVar14 || uVar13 - uVar14 == 0) {
      *(ulong *)(lVar1 + 0x130) = uVar13;
      uVar11 = 0;
      uVar6 = 0;
    }
    else {
      *(ulong *)(lVar1 + 0x130) = uVar14;
      *(ulong *)(lVar1 + 0x50) = uVar13 - uVar14;
      if ((short)((short)*(undefined8 *)(lVar1 + 0x20) + (short)uVar14) != 0) {
        func_0x0025d410(0x1394bd8,0x12b97ff,*(undefined8 *)(lVar1 + 0x20),uVar14);
        uVar13 = *(ulong *)(lVar1 + 0x128);
        uVar14 = *(ulong *)(lVar1 + 0x130);
      }
      if ((long)uVar14 < (long)uVar13) {
        plVar8 = (long *)func_0x00c08b50(0x20,0x255ffd0,2);
        *plVar8 = lVar1;
        if (lVar2 == 0) {
          plVar8[1] = 0;
          plVar10 = (long *)0x0;
          *(undefined4 *)((long)plVar8 + 0x14) = 0xffffffff;
        }
        else {
          uVar13 = *(long *)(lVar1 + 0x130) + *(long *)(lVar1 + 0x20);
          plVar10 = plVar8 + 2;
          iVar7 = func_0x003d6f60(uVar13);
          *(int *)((long)plVar8 + 0x14) = iVar7;
          if (iVar7 != -1) {
            plVar8[3] = uVar13 >> 0x10;
            *(undefined4 *)(plVar8 + 2) = 0xc;
          }
          plVar8[1] = (long)plVar10;
        }
        uVar6 = sub_9acde0(lVar1,plVar10,&local_3c);
        if (uVar6 == 0) {
          iVar7 = func_0x005b01d0(0x26a580,plVar8,&local_3c,1);
          if (iVar7 != 0) {
            func_0x0025d410(0x12d95db,0x12b97ff,iVar7,local_3c);
            sub_9ad490(plVar8,local_3c);
          }
          goto LAB_009ad10f;
        }
        func_0x0025d410(0x134550c,0x12b97ff,uVar6);
        func_0x00c08df0(plVar8,0x255ffd0);
        uVar11 = *(undefined8 *)(lVar1 + 0x128);
      }
      else {
        func_0x0025d410(0x13aa80b,0x12b97ff,uVar13,uVar14);
        uVar11 = *(undefined8 *)(lVar1 + 0x128);
        uVar6 = 0x16;
      }
    }
  }
  else {
    uVar12 = 0x1384734;
    uVar11 = 0x12edd61;
LAB_009ad0f2:
    func_0x0025d410(uVar12,uVar11,uVar6,param_2);
    uVar11 = *(undefined8 *)(lVar1 + 0x128);
  }
  *(undefined8 *)(lVar1 + 0x50) = uVar11;
  sub_9acd40(lVar1,uVar6);
LAB_009ad10f:
  func_0x005f0f70(uVar5);
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar4 = (code *)invalidInstructionException();
    (*pcVar4)();
  }
  return;
}



/* sub_9ad320 | RVA 0x9ad320 | local helper / adjacent context (reachability below)
 * Evidence ev_2d43bafcd07ed8dcc86251ad307a5e95345e0abaa5d5dbd83ed14eeb683d1332
 * Body [{"start": "0x9ad320", "end": "0x9ad483"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

bool sub_9ad320(long param_1)

{
  uint uVar1;
  int iVar2;
  bool bVar3;
  
  uVar1 = _DAT_025600d0;
  if (_DAT_025600d0 == 0xffffffff) {
    iVar2 = func_0x00b07940();
    uVar1 = 1;
    if ((iVar2 == 0) && (iVar2 = func_0x00b07960(), iVar2 == 0)) {
      iVar2 = func_0x00acc9a0(0x6d);
      uVar1 = (uint)(iVar2 != 0);
    }
  }
  _DAT_025600d0 = uVar1;
  bVar3 = false;
  if (_DAT_025600d0 != 0) {
    uVar1 = _DAT_02560040;
    if (_DAT_02560040 == 0xffffffff) {
      iVar2 = func_0x00b07940();
      uVar1 = 1;
      if ((iVar2 == 0) && (iVar2 = func_0x00b07960(), iVar2 == 0)) {
        iVar2 = func_0x00b07920();
        if (iVar2 == 0) {
          uVar1 = 0;
        }
        else {
          iVar2 = func_0x00acc9a0(0x6e);
          uVar1 = (uint)(iVar2 != 0);
        }
      }
    }
    _DAT_02560040 = uVar1;
    if (_DAT_02560040 != 0) {
      if (DAT_03ba5f20 == '\0') {
        iVar2 = func_0x003d6df0(0x10009,&DAT_03ba5f28,0x3ba5f30);
        if ((iVar2 != 0) ||
           (iVar2 = func_0x003d6df0(0x10010,&DAT_03ba5f38,&DAT_03ba5f40), iVar2 != 0)) {
          func_0x0025d410(0x132c55b,0x138a7c2,iVar2);
          return false;
        }
        DAT_03ba5f20 = '\x01';
      }
      if (_DAT_03ba5f28 <= (long)(*(ulong *)(param_1 + 0x20) >> 0x10)) {
        bVar3 = (long)(*(ulong *)(param_1 + 0x20) + 0xffff + *(long *)(param_1 + 0x128) >> 0x10) <=
                _DAT_03ba5f40 + _DAT_03ba5f38;
      }
    }
  }
  return bVar3;
}



/* sub_9ad490 | RVA 0x9ad490 | local helper / adjacent context (reachability below)
 * Evidence ev_402b5ecd2eb04db901d1027ea5edee1eb227a63c10ebfeb9cdb1e667840b3a6d
 * Body [{"start": "0x9ad490", "end": "0x9ad63d"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_9ad490(long *param_1,undefined4 param_2)

{
  long lVar1;
  code *pcVar2;
  undefined4 uVar3;
  uint uVar4;
  ulong uVar5;
  ulong uVar6;
  undefined8 uVar7;
  int iVar8;
  undefined8 uVar9;
  long lVar10;
  undefined4 local_40;
  ushort local_3a;
  long local_38;
  
  local_38 = _DAT_0391c310;
  lVar1 = *param_1;
  lVar10 = *(long *)(lVar1 + 0x68);
  local_3a = 0;
  local_40 = 0;
  iVar8 = 0x21c1;
  if (*(int *)(lVar1 + 0x198) != 0) {
    iVar8 = *(int *)(lVar1 + 0x198);
  }
  uVar3 = func_0x005f0f70(iVar8);
  uVar4 = func_0x0068e1a0(param_2,&local_3a,&local_40,0);
  if (uVar4 == 0) {
    func_0x00c08df0(param_1,0x255ffd0);
    uVar4 = (uint)local_3a;
    if (local_3a != 0) {
      uVar9 = 0x13079f2;
      uVar7 = 0x13b0051;
      param_2 = local_40;
      goto LAB_009ad540;
    }
    if (lVar10 != 0) {
      uVar5 = *(long *)(lVar1 + 0x128) - *(long *)(lVar1 + 0x130);
      uVar6 = 0x10000;
      if (uVar5 < 0x10000) {
        uVar6 = uVar5;
      }
      func_0x00259be0(lVar10,*(long *)(lVar1 + 0x30) + *(long *)(lVar1 + 0x130),uVar6);
    }
    if ((ulong)(*(long *)(lVar1 + 0x128) - *(long *)(lVar1 + 0x130)) < 0x10001) {
      *(long *)(lVar1 + 0x130) = *(long *)(lVar1 + 0x128);
      *(undefined8 *)(lVar1 + 0x50) = 0;
      uVar4 = 0;
      goto LAB_009ad579;
    }
    uVar4 = 0;
    *(long *)(lVar1 + 0x130) = *(long *)(lVar1 + 0x130) + 0x10000;
    lVar10 = *(long *)(lVar1 + 0x50) + -0x10000;
  }
  else {
    uVar9 = 0x1384734;
    uVar7 = 0x132c586;
LAB_009ad540:
    func_0x0025d410(uVar9,uVar7,uVar4,param_2);
    lVar10 = *(long *)(lVar1 + 0x128);
  }
  *(long *)(lVar1 + 0x50) = lVar10;
  if (lVar10 != 0) {
    func_0x0025d410(0x12f7bcb,0x132c586,lVar1,*(undefined8 *)(lVar1 + 0x130),lVar10,uVar4);
  }
LAB_009ad579:
  sub_9acd40(lVar1,uVar4);
  func_0x005f0f70(uVar3);
  if (_DAT_0391c310 == local_38) {
    return;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar2 = (code *)invalidInstructionException();
  (*pcVar2)();
}



/* sub_9ad640 | RVA 0x9ad640 | local helper / adjacent context (reachability below)
 * Evidence ev_9f58077e9501e65365f71eaa6a11384be00a5817dd699e832c373e7191465c88
 * Body [{"start": "0x9ad640", "end": "0x9ad740"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_9ad640(long param_1,undefined4 param_2)

{
  code *pcVar1;
  ushort uVar2;
  undefined4 uVar3;
  uint uVar4;
  int iVar5;
  undefined4 local_40;
  ushort local_3a;
  long local_38;
  
  local_38 = _DAT_0391c310;
  iVar5 = 0x21c1;
  if (*(int *)(param_1 + 0x198) != 0) {
    iVar5 = *(int *)(param_1 + 0x198);
  }
  uVar3 = func_0x005f0f70(iVar5);
  local_3a = 0;
  local_40 = 0;
  uVar4 = func_0x0068e1a0(param_2,&local_3a,&local_40,0);
  uVar2 = local_3a;
  if (uVar4 == 0) {
    uVar4 = (uint)local_3a;
    if (local_3a != 0) {
      func_0x0025d410(0x13079f2,0x13b0051,uVar4,local_40);
      if (uVar2 != 5) goto LAB_009ad6be;
      func_0x00258ff0(*(undefined8 *)(param_1 + 0x68),0x10000);
    }
    sub_9ad750(param_1,0);
  }
  else {
    func_0x0025d410(0x1384734,0x132c5a6,uVar4,param_2);
LAB_009ad6be:
    *(undefined8 *)(param_1 + 0x50) = *(undefined8 *)(param_1 + 0x128);
    sub_9acd40(param_1,uVar4);
  }
  func_0x005f0f70(uVar3);
  if (_DAT_0391c310 == local_38) {
    return;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* sub_9ad750 | RVA 0x9ad750 | local helper / adjacent context (reachability below)
 * Evidence ev_8977da5ee7adefdfde81902f197b5c40c41f3888ca5ea53e665edb363b83e3e9
 * Body [{"start": "0x9ad750", "end": "0x9ad89b"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_9ad750(long param_1,long *param_2)

{
  code *pcVar1;
  int iVar2;
  ulong uVar3;
  long *plVar4;
  long lVar5;
  long *plVar6;
  undefined4 local_34;
  long local_30;
  
  local_30 = _DAT_0391c310;
  uVar3 = (ulong)*(ushort *)(param_1 + 0x20);
  lVar5 = 0x10000 - uVar3;
  if (*(long *)(param_1 + 0x128) + uVar3 < 0x10001) {
    lVar5 = *(long *)(param_1 + 0x128);
  }
  func_0x00259be0(*(undefined8 *)(param_1 + 0x30),*(long *)(param_1 + 0x68) + uVar3,lVar5);
  plVar4 = (long *)func_0x00c08b50(0x20,0x255ffd0,2);
  *plVar4 = param_1;
  if ((param_2 == (long *)0x0) || (*(int *)((long)param_2 + 4) == -1)) {
    plVar6 = (long *)0x0;
  }
  else {
    lVar5 = *param_2;
    plVar6 = plVar4 + 2;
    plVar4[3] = param_2[1];
    plVar4[2] = lVar5;
  }
  plVar4[1] = (long)plVar6;
  iVar2 = sub_9ad8a0(param_1,plVar6,&local_34);
  if (iVar2 == 0) {
    iVar2 = func_0x005b01d0(0x26a590,plVar4,&local_34,1);
    if (iVar2 != 0) {
      func_0x0025d410(0x12d95db,0x12d9617,iVar2,local_34);
      sub_9ada30(plVar4,local_34);
    }
  }
  else {
    func_0x0025d410(0x12c877d,0x12d9617,iVar2);
    func_0x00c08df0(plVar4,0x255ffd0);
    *(undefined8 *)(param_1 + 0x50) = *(undefined8 *)(param_1 + 0x128);
    sub_9acd40(param_1,iVar2);
  }
  if (_DAT_0391c310 == local_30) {
    return;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* sub_9ad8a0 | RVA 0x9ad8a0 | local helper / adjacent context (reachability below)
 * Evidence ev_ae69703104ef703c7c338f2b4109aaec322b8548cc53761a8bd4cef27af4fea1
 * Body [{"start": "0x9ad8a0", "end": "0x9ada2b"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_9ad8a0(long param_1,undefined8 param_2,undefined8 param_3)

{
  code *pcVar1;
  uint uVar2;
  int iVar3;
  char cVar4;
  undefined8 uVar5;
  ulong uVar6;
  ulong uVar7;
  long lVar8;
  long local_48;
  long local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  uVar6 = *(long *)(param_1 + 0x130) + *(long *)(param_1 + 0x20);
  lVar8 = *(long *)(param_1 + 0x68);
  if (lVar8 == 0) {
    lVar8 = *(long *)(param_1 + 0x30);
  }
  uVar2 = _DAT_02560040;
  if (_DAT_02560040 == 0xffffffff) {
    iVar3 = func_0x00b07940();
    uVar2 = 1;
    if ((iVar3 == 0) && (iVar3 = func_0x00b07960(), iVar3 == 0)) {
      iVar3 = func_0x00b07920();
      if (iVar3 == 0) {
        uVar2 = 0;
      }
      else {
        iVar3 = func_0x00acc9a0(0x6e);
        uVar2 = (uint)(iVar3 != 0);
      }
    }
  }
  _DAT_02560040 = uVar2;
  uVar7 = uVar6 >> 9 & 0xffffffffffffff80;
  if (_DAT_02560040 != 0) {
    local_48 = 0;
    iVar3 = func_0x003d6df0(0x10003,&local_40,&local_48);
    if (iVar3 == 0) {
      uVar6 = uVar6 >> 0x10;
      if ((local_40 <= (long)uVar6) && ((long)(uVar6 - local_40) < local_48)) {
        uVar7 = func_0x009e1f40(uVar7);
        uVar5 = 0x80010500;
        cVar4 = '\x03';
        goto LAB_009ad9e6;
      }
    }
    else {
      func_0x0025d410(0x127c65f,0x12af557,iVar3);
    }
  }
  uVar2 = _DAT_02560040;
  if (_DAT_02560040 == 0xffffffff) {
    iVar3 = func_0x00b07940();
    uVar2 = 1;
    if ((iVar3 == 0) && (iVar3 = func_0x00b07960(), iVar3 == 0)) {
      iVar3 = func_0x00b07920();
      if (iVar3 == 0) {
        uVar2 = 0;
      }
      else {
        iVar3 = func_0x00acc9a0(0x6e);
        uVar2 = (uint)(iVar3 != 0);
      }
    }
  }
  _DAT_02560040 = uVar2;
  uVar5 = 0x20010001;
  cVar4 = (_DAT_02560040 == 0) + '\x01';
LAB_009ad9e6:
  func_0x0068a090(cVar4,uVar7 | 0x400000000000,lVar8,param_2,0,uVar5,param_3);
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar1 = (code *)invalidInstructionException();
    (*pcVar1)();
  }
  return;
}



/* sub_9ada30 | RVA 0x9ada30 | local helper / adjacent context (reachability below)
 * Evidence ev_dfea233ea818303c36a73306de6f6911dec267a60b6c06a45a582b429ec2240e
 * Body [{"start": "0x9ada30", "end": "0x9adb82"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_9ada30(long *param_1,undefined4 param_2)

{
  ushort uVar1;
  long lVar2;
  long lVar3;
  ulong uVar4;
  code *pcVar5;
  undefined4 uVar6;
  uint uVar7;
  ulong uVar8;
  long lVar9;
  undefined8 uVar10;
  int iVar11;
  undefined8 uVar12;
  undefined4 local_40;
  ushort local_3a;
  long local_38;
  
  local_38 = _DAT_0391c310;
  lVar2 = *param_1;
  lVar3 = param_1[1];
  uVar1 = *(ushort *)(lVar2 + 0x20);
  local_3a = 0;
  local_40 = 0;
  iVar11 = 0x21c1;
  if (*(int *)(lVar2 + 0x198) != 0) {
    iVar11 = *(int *)(lVar2 + 0x198);
  }
  uVar6 = func_0x005f0f70(iVar11);
  uVar7 = func_0x0068e1a0(param_2,&local_3a,&local_40,0);
  if (uVar7 == 0) {
    func_0x00c08df0(param_1,0x255ffd0);
    uVar7 = (uint)local_3a;
    if (local_3a != 0) {
      uVar12 = 0x13079f2;
      uVar10 = 0x13b0051;
      param_2 = local_40;
      goto LAB_009adaed;
    }
    uVar4 = *(ulong *)(lVar2 + 0x128);
    uVar8 = 0x10000 - (ulong)uVar1;
    lVar9 = uVar4 - uVar8;
    if (uVar8 <= uVar4 && lVar9 != 0) {
      *(ulong *)(lVar2 + 0x130) = uVar8;
      *(long *)(lVar2 + 0x50) = lVar9;
      if ((short)lVar9 == 0) {
        sub_9add90(lVar2,lVar3 != 0);
      }
      else {
        sub_9adb90();
      }
      goto LAB_009adb0a;
    }
    *(ulong *)(lVar2 + 0x130) = uVar4;
    uVar10 = 0;
    uVar7 = 0;
  }
  else {
    uVar12 = 0x1384734;
    uVar10 = 0x1375eb2;
LAB_009adaed:
    func_0x0025d410(uVar12,uVar10,uVar7,param_2);
    uVar10 = *(undefined8 *)(lVar2 + 0x128);
  }
  *(undefined8 *)(lVar2 + 0x50) = uVar10;
  sub_9acd40(lVar2,uVar7);
LAB_009adb0a:
  func_0x005f0f70(uVar6);
  if (_DAT_0391c310 == local_38) {
    return;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar5 = (code *)invalidInstructionException();
  (*pcVar5)();
}



/* sub_9adb90 | RVA 0x9adb90 | local helper / adjacent context (reachability below)
 * Evidence ev_a543d2869603ad2cda3ecb485c3835915d6dca7471c5b6017218ad188c611ab7
 * Body [{"start": "0x9adb90", "end": "0x9add81"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted.", "Ghidra Listing reports a terminal call at 0x9adcb5 to 0x9acd40 sub_9acd40 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_9adb90(long param_1,int param_2)

{
  code *pcVar1;
  int iVar2;
  long *plVar3;
  long lVar4;
  ulong uVar5;
  long *plVar6;
  undefined4 local_3c;
  long local_38;
  
  local_38 = _DAT_0391c310;
  lVar4 = *(long *)(param_1 + 0x130);
  if ((lVar4 == 0) || (((int)lVar4 + (int)*(undefined8 *)(param_1 + 0x20) & 0xffffU) != 0)) {
    func_0x0025d410(0x1394bd8,0x1394c0e);
    lVar4 = *(long *)(param_1 + 0x130);
  }
  if (lVar4 < *(long *)(param_1 + 0x128)) {
    if ((short)*(long *)(param_1 + 0x128) == (short)lVar4) {
      func_0x0025d410(0x13aa80b,0x1394c0e);
    }
    plVar3 = (long *)func_0x00c08b50(0x20,0x255ffd0,2);
    *plVar3 = param_1;
    if (param_2 == 0) {
      plVar3[1] = 0;
      plVar6 = (long *)0x0;
      *(undefined4 *)((long)plVar3 + 0x14) = 0xffffffff;
    }
    else {
      uVar5 = *(long *)(param_1 + 0x130) + *(long *)(param_1 + 0x20);
      plVar6 = plVar3 + 2;
      iVar2 = func_0x003d6f60(uVar5);
      *(int *)((long)plVar3 + 0x14) = iVar2;
      if (iVar2 != -1) {
        plVar3[3] = uVar5 >> 0x10;
        *(undefined4 *)(plVar3 + 2) = 0xc;
      }
      plVar3[1] = (long)plVar6;
    }
    iVar2 = sub_9acde0(param_1,plVar6,&local_3c);
    if (iVar2 == 0) {
      iVar2 = func_0x005b01d0(0x26a598,plVar3,&local_3c,1);
      if (iVar2 != 0) {
        func_0x0025d410(0x12d95db,0x1394c0e,iVar2,local_3c);
        sub_9adeb0(plVar3,local_3c);
      }
    }
    else {
      func_0x0025d410(0x134550c,0x1394c0e,iVar2);
      func_0x00c08df0(plVar3,0x255ffd0);
      *(undefined8 *)(param_1 + 0x50) = *(undefined8 *)(param_1 + 0x128);
      sub_9acd40(param_1,iVar2);
    }
    if (_DAT_0391c310 == local_38) {
      return;
    }
  }
  else {
    func_0x0025d410(0x13aa80b,0x1394c0e);
    *(undefined8 *)(param_1 + 0x50) = *(undefined8 *)(param_1 + 0x128);
    if (_DAT_0391c310 == local_38) {
      sub_9acd40(param_1,0x16);
      return;
    }
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* sub_9add90 | RVA 0x9add90 | local helper / adjacent context (reachability below)
 * Evidence ev_bf68724c716f17815ceed775ece343c17656e4ed344fa5da5f0d80155ae05bee
 * Body [{"start": "0x9add90", "end": "0x9adeaf"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted.", "Ghidra Listing reports a terminal call at 0x9ade88 to 0x9acd40 sub_9acd40 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_9add90(long param_1,int param_2)

{
  int iVar1;
  long *plVar2;
  long lVar3;
  ulong uVar4;
  
  lVar3 = *(long *)(param_1 + 0x130);
  if ((lVar3 == 0) || (((int)lVar3 + (int)*(undefined8 *)(param_1 + 0x20) & 0xffffU) != 0)) {
    func_0x0025d410(0x1394bd8,0x13613bd);
    lVar3 = *(long *)(param_1 + 0x130);
  }
  if (lVar3 < *(long *)(param_1 + 0x128)) {
    if ((short)*(long *)(param_1 + 0x128) != (short)lVar3) {
      func_0x0025d410(0x13aa80b,0x13613bd);
    }
    plVar2 = (long *)func_0x00c08b50(0x20,0x255ffd0,2);
    *plVar2 = param_1;
    if (param_2 == 0) {
      plVar2[1] = 0;
      *(undefined4 *)((long)plVar2 + 0x14) = 0xffffffff;
    }
    else {
      uVar4 = *(long *)(param_1 + 0x130) + *(long *)(param_1 + 0x20);
      iVar1 = func_0x003d6f60(uVar4);
      *(int *)((long)plVar2 + 0x14) = iVar1;
      if (iVar1 != -1) {
        plVar2[3] = uVar4 >> 0x10;
        *(undefined4 *)(plVar2 + 2) = 0x8c;
      }
      plVar2[1] = (long)(plVar2 + 2);
    }
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  func_0x0025d410(0x13aa80b,0x13613bd);
  *(undefined8 *)(param_1 + 0x50) = *(undefined8 *)(param_1 + 0x128);
  sub_9acd40(param_1,0x16);
  return;
}



/* sub_9adeb0 | RVA 0x9adeb0 | local helper / adjacent context (reachability below)
 * Evidence ev_dcf48bb156bcfe2bf28ccbf764da4fcc54381238080f793ff4501498b3c60b5f
 * Body [{"start": "0x9adeb0", "end": "0x9adf3e"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_9adeb0(long *param_1,undefined4 param_2,undefined8 param_3,undefined8 param_4,char *param_5
               )

{
  char cVar1;
  int iVar2;
  undefined4 local_40;
  undefined2 local_3a;
  undefined8 local_38;
  
  local_38 = _DAT_0391c310;
  iVar2 = 0x21c1;
  if (*(int *)(*param_1 + 0x198) != 0) {
    iVar2 = *(int *)(*param_1 + 0x198);
  }
  func_0x005f0f70(iVar2);
  local_3a = 0;
  local_40 = 0;
  iVar2 = func_0x0068e1a0(param_2,&local_3a,&local_40,0);
  if (iVar2 != 0) {
    func_0x0025d410(0x1384734,0x132c5a6,iVar2,param_2);
    cVar1 = func_0x00c08df0(param_1,0x255ffd0);
    *param_5 = *param_5 + cVar1;
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* zero_fill_helper | RVA 0x258ff0 | local helper / adjacent context (reachability below)
 * Evidence ev_9f715f53ca8e7945dcf5dd090a09697d620766198f5ec9c1ad147fd5676b3ea0
 * Body [{"start": "0x258ff0", "end": "0x259031"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void zero_fill_helper(undefined8 *param_1,ulong param_2)

{
  ulong uVar1;
  
  if (!CARRY8((ulong)param_1,param_2)) {
    if (((undefined1 *)((long)param_1 + param_2) <= &stack0xfffffffffffffff8) ||
       ((long)&stack0x00000008 <= (long)param_1)) goto LAB_0025901a;
    func_0x00258fd0();
  }
  func_0x00258fe0();
LAB_0025901a:
  for (uVar1 = param_2 >> 3; uVar1 != 0; uVar1 = uVar1 - 1) {
    *param_1 = 0;
    param_1 = param_1 + 1;
  }
  for (param_2 = param_2 & 7; param_2 != 0; param_2 = param_2 - 1) {
    *(undefined1 *)param_1 = 0;
    param_1 = (undefined8 *)((long)param_1 + 1);
  }
  return;
}



/* copyout_candidate | RVA 0x2591d0 | local helper / adjacent context (reachability below)
 * Evidence ev_71486184be245b984abbb9be576981c38f613a7db64a834e00ab1b4e60ea2113
 * Body [{"start": "0x2591d0", "end": "0x259258"}, {"start": "0x259260", "end": "0x25927f"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 copyout_candidate(undefined8 *param_1,ulong param_2,ulong param_3)

{
  ulong uVar1;
  undefined8 *puVar2;
  long *in_GS_OFFSET;
  
  *(undefined8 *)(in_GS_OFFSET[4] + 0x108) = 0x259260;
  if (param_3 != 0) {
    if (((CARRY8(param_2,param_3)) || (0x800000000000 < param_2 + param_3)) ||
       (*(char *)(*(long *)(*in_GS_OFFSET + 8) + 0x591) != '\0')) {
      *(undefined8 *)(in_GS_OFFSET[4] + 0x108) = 0;
      return 0xe;
    }
    puVar2 = (undefined8 *)(param_2 & 0x7fffffffffff);
    for (uVar1 = param_3 >> 3; uVar1 != 0; uVar1 = uVar1 - 1) {
      *puVar2 = *param_1;
      param_1 = param_1 + 1;
      puVar2 = puVar2 + 1;
    }
    for (param_3 = param_3 & 7; param_3 != 0; param_3 = param_3 - 1) {
      *(undefined1 *)puVar2 = *(undefined1 *)param_1;
      param_1 = (undefined8 *)((long)param_1 + 1);
      puVar2 = (undefined8 *)((long)puVar2 + 1);
    }
  }
  *(undefined8 *)(in_GS_OFFSET[4] + 0x108) = 0;
  return 0;
}



/* copyin_candidate | RVA 0x259280 | local helper / adjacent context (reachability below)
 * Evidence ev_5d07d221cf60ecec155e82677b4906065788d1c1d1f1444ffffeccc565bd92ad
 * Body [{"start": "0x259280", "end": "0x25932f"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void copyin_candidate(undefined8 *param_1,undefined8 *param_2,undefined8 *param_3)

{
  ulong uVar1;
  undefined8 *extraout_RDX;
  undefined8 *puVar2;
  long *in_GS_OFFSET;
  
  if (!CARRY8((ulong)param_2,(ulong)param_3)) {
    if (((undefined1 *)((long)param_2 + (long)param_3) <= &stack0xfffffffffffffff8) ||
       ((long)&stack0x00000008 <= (long)param_2)) goto LAB_002592aa;
    param_1 = param_2;
    func_0x00258fd0();
    param_2 = param_3;
  }
  func_0x00258fe0();
  param_3 = extraout_RDX;
LAB_002592aa:
  *(undefined1 **)(in_GS_OFFSET[4] + 0x108) = &LAB_00259340;
  if (param_3 != (undefined8 *)0x0) {
    if (((CARRY8((ulong)param_1,(ulong)param_3)) ||
        ((undefined1 *)0x800000000000 < (undefined1 *)((long)param_1 + (long)param_3))) ||
       (*(char *)(*(long *)(*in_GS_OFFSET + 8) + 0x591) != '\0')) {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    puVar2 = (undefined8 *)((ulong)param_1 & 0x7fffffffffff);
    for (uVar1 = (ulong)param_3 >> 3; uVar1 != 0; uVar1 = uVar1 - 1) {
      *param_2 = *puVar2;
      puVar2 = puVar2 + 1;
      param_2 = param_2 + 1;
    }
    for (uVar1 = (ulong)param_3 & 7; uVar1 != 0; uVar1 = uVar1 - 1) {
      *(undefined1 *)param_2 = *(undefined1 *)puVar2;
      puVar2 = (undefined8 *)((long)puVar2 + 1);
      param_2 = (undefined8 *)((long)param_2 + 1);
    }
  }
  *(undefined8 *)(in_GS_OFFSET[4] + 0x108) = 0;
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


