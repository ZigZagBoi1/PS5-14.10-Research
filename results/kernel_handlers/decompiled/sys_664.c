/* Handler 664: REA 6.7.0 / Ghidra 12.1.4 static recovery.
 * Not original source or a buildable translation unit. Analyst reconstructions are explicitly marked.
 * Raw handler_664.bin:4096 bytes; SHA256 aa0645475503bd6a3ad9b2b6f25cfa6cdce8860c81b5cf8d2ec6c41be56b7e6b; file+0=RVA 0x265728.
 * Target RVA 0x3b0fb0; recorded VA = 0xffffffff8a9c0000 + RVA.
 * Extra source-verified body/helper carriers are documented in .rea.analysis.md.
 * Missing external code/data, indirect flows and inferred types remain unresolved.
 */

/* ===== Analyst recovered ABI views and readable entry behavior =====
 * Slot layouts are based on machine-code loads, not recovered original declarations.
 * The original REA output follows unchanged.
 */
#include <stdint.h>
#include <stddef.h>
typedef uint32_t aio_id_t;
typedef uint32_t aio_state_t;
struct h664_args { uintptr_t ids; int32_t count; uint32_t pad0; uintptr_t states; };
#define H664_ALREADY_OBSERVED 0x10000u
#define H664_BAD_ID 0x80020003u
#define H664_ACCESS_CHECK_FAILED 0x80020001u

/* Original entry is an unconditional tail jump to RVA 0x3b0fb0; any REA halt_baddata is an out-of-carrier recovery artifact. */
extern int aio_multi_poll_3b0fd0(void *thread,uintptr_t ids,int32_t count,uintptr_t states);
static int handler_664_recovered(void *thread,const struct h664_args *args) {
    return aio_multi_poll_3b0fd0(thread,args->ids,args->count,args->states);
}
/* Backend: count1..128; copyin IDs; process-scoped handle/slot lookup;
 * inspect request state under synchronization; record each state/error;
 * terminal states can set request completion-observed byte+0xc;
 * copyout count*4 bytes. No timeout or wait-mode syscall argument is read.
 */

/* ===== Actual REA pseudocode: original entry and recovered body functions ===== */

/* <EXTERNAL>::thunk_EXT_FUN_003b0fb0 | RVA 0x265728 | original syscall trampoline
 * Evidence ev_32400ec745415978a55caaffa2d4c93a36c86ce36cff33606db0d6e23535d844
 * Body [{"start": "0x265728", "end": "0x26572c"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_003b0fb0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* sub_3b3410 | RVA 0x3b3410 | local helper / adjacent context (reachability below)
 * Evidence ev_74d5cc5f8079c896c216796da3fac7955b0326cfd5e69a1a6f8046d4cbcead50
 * Body [{"start": "0x3b3410", "end": "0x3b3a33"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_3b3410(int param_1,undefined8 *param_2)

{
  int iVar1;
  code *pcVar2;
  long lVar3;
  int iVar4;
  int iVar5;
  long lVar6;
  undefined8 uVar7;
  long lVar8;
  long lVar9;
  long *in_GS_OFFSET;
  undefined8 local_48;
  uint local_3c;
  long local_38;
  
  local_38 = _DAT_0391c310;
  uVar7 = *(undefined8 *)(*in_GS_OFFSET + 8);
  iVar4 = func_0x009f81c0(uVar7,&local_3c);
  func_0x004c6a00(0x34cf2e8,0,0,0);
  iVar1 = *(int *)(param_2 + 0x94);
  if (iVar1 != 0) {
    iVar5 = 0x10;
    do {
      if (0 < iVar1) {
        if (param_2 == (undefined8 *)0x34cf8c8) {
          iVar5 = 0;
        }
        goto LAB_003b37a1;
      }
      iVar5 = func_0x0073e780(0x34cf2f0,0x34cf2d0,0);
      if (*(int *)(param_2 + 0x94) != 0) goto LAB_003b37a1;
      func_0x004c6fa0(0x34cf2e8,0,0,0);
      func_0x004c6a00(0x34cf2e8,0,0);
      iVar1 = *(int *)(param_2 + 0x94);
    } while (iVar1 != 0);
  }
  if (DAT_034d09d0 == '\0') {
    func_0x0073e520(0x34cf2f0,0x138ecf8);
    DAT_034d09d0 = '\x01';
  }
  *(undefined4 *)(param_2 + 0x94) = 0xffffffff;
  func_0x004c7dd0(param_2 + 0x1b,0x138ecff,0,0);
  *param_2 = 0;
  param_2[1] = param_2;
  param_2[8] = 0;
  param_2[9] = param_2 + 8;
  param_2[0x10] = 0;
  param_2[0x11] = param_2 + 0x10;
  *(undefined4 *)(param_2 + 0x38) = 0;
  *(undefined4 *)(param_2 + 0x3a) = 0;
  func_0x004c7dd0(param_2 + 0x1f,0x138ecff,0,0);
  param_2[2] = 0;
  param_2[3] = param_2 + 2;
  param_2[10] = 0;
  param_2[0xb] = param_2 + 10;
  param_2[0x12] = 0;
  param_2[0x13] = param_2 + 0x12;
  *(undefined4 *)((long)param_2 + 0x1c4) = 0;
  *(undefined4 *)((long)param_2 + 0x1d4) = 0;
  func_0x004c7dd0(param_2 + 0x23,0x138ecff,0,0);
  param_2[4] = 0;
  param_2[5] = param_2 + 4;
  param_2[0xc] = 0;
  param_2[0xd] = param_2 + 0xc;
  param_2[0x14] = 0;
  param_2[0x15] = param_2 + 0x14;
  *(undefined4 *)(param_2 + 0x39) = 0;
  *(undefined4 *)(param_2 + 0x3b) = 0;
  func_0x004c7dd0(param_2 + 0x27,0x138ecff,0,0);
  param_2[6] = 0;
  param_2[7] = param_2 + 6;
  param_2[0xe] = 0;
  param_2[0xf] = param_2 + 0xe;
  param_2[0x16] = 0;
  param_2[0x17] = param_2 + 0x16;
  *(undefined4 *)((long)param_2 + 0x1cc) = 0;
  *(undefined4 *)((long)param_2 + 0x1dc) = 0;
  func_0x004c6fa0(0x34cf2e8,0,0,0);
  local_48 = 0;
  param_2[0x99] = param_2;
  iVar5 = func_0x009262d0(0x261790,param_2 + 0x96,&local_48,param_2 + 0x97,0,0,0x126d8c2,0x12bdaa1,
                          0x12e78ee,0);
  if (iVar5 == 0) {
    param_2[0x96] = 0;
    local_48 = 0;
    param_2[0xa8] = param_2;
    iVar5 = func_0x009262d0(0x261790,param_2 + 0xa5,&local_48,param_2 + 0xa6,0,0,0x126d8c2,0x12bdaa1
                            ,0x12e78ee,1);
    if (iVar5 == 0) {
      param_2[0xa5] = 0;
      func_0x00c4bb20(0x34cf300,0,0,0);
      if (_DAT_034d09d8 == 0) {
        lVar9 = 0;
        _DAT_034d09d8 = func_0x0073dd40(0,0x1364ab4,0x267320,0x12bdaa7,0,20000);
        _DAT_034d09e0 = func_0x0073dd40(0,0x12f120f,0x267328,0x128aa97,0,20000);
        _DAT_034d09e8 = func_0x0073dd40(0,0x13a2f6d,0x267330,0x131134c,0,20000);
        _DAT_034d09f0 = func_0x0073dd40(0,0x12e769e,0x265768,0x12955ab,0,20000);
        _DAT_034d09f8 = func_0x0073dd40(0,0x1276a25,0x265770,0x133ac86,0,20000);
        _DAT_034d0a00 = func_0x0073dd40(0,0x131bf16,0x267338,0x12dd858,0,9999);
        _DAT_034d09c0 = 0;
        lVar3 = 0x34d0a10;
        lVar8 = 0;
        do {
          lVar6 = lVar3;
          *(long *)(lVar6 + 8) = lVar8;
          lVar9 = lVar9 + -0x10;
          lVar3 = lVar6 + 0x10;
          lVar8 = lVar6;
        } while (lVar9 != -0x400);
        _DAT_034d09c8 = 0x34d0e00;
      }
      func_0x00c4c4b0(0x34cf300,0,0);
      func_0x004c6a00(0x34cf2e8,0,0,0);
      *(undefined4 *)(param_2 + 0x94) = 1;
      if (iVar4 == 0 && local_3c < 0x1000000) {
        uVar7 = func_0x009f8180(uVar7);
        param_2[0x95] = uVar7;
      }
      if (param_1 != 0) {
        *(undefined4 *)((long)param_2 + 0x1ac) = 0;
        *(undefined4 *)((long)param_2 + 0x1bc) = 0x100000;
        *(undefined4 *)((long)param_2 + 0x19c) = 0x100000;
        *(undefined4 *)((long)param_2 + 0x17c) = 0x20;
        *(undefined4 *)((long)param_2 + 0x18c) = 0x20;
        *(undefined8 *)((long)param_2 + 0x1a4) = 0x100000001;
        *(undefined8 *)((long)param_2 + 0x1b4) = 0x10000000100000;
        *(undefined8 *)((long)param_2 + 0x194) = 0x10000000100000;
        *(undefined8 *)((long)param_2 + 0x174) = 0x2000000020;
        *(undefined8 *)((long)param_2 + 0x184) = 0x2000000020;
      }
      func_0x0073f010(0x34cf2f0,0);
      iVar5 = 0;
      goto LAB_003b37a1;
    }
  }
  func_0x004c6a00(0x34cf2e8,0,0,0);
  func_0x0073f010(0x34cf2f0,0);
LAB_003b37a1:
  func_0x004c6fa0(0x34cf2e8,0,0,0);
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar2 = (code *)invalidInstructionException();
    (*pcVar2)();
  }
  return iVar5;
}



/* sub_3b3a40 | RVA 0x3b3a40 | local helper / adjacent context (reachability below)
 * Evidence ev_694b8cff8ad74a417656cc9386c49ae271f8378872f8600cf2e7c213b1e0989f
 * Body [{"start": "0x3b3a40", "end": "0x3b3a81"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_3b3a40(void)

{
  undefined8 *in_GS_OFFSET;
  
  func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* sub_3b3e90 | RVA 0x3b3e90 | local helper / adjacent context (reachability below)
 * Evidence ev_8765ebdf675588c4321ccad1b596b6e4c38ed092c1b1173e037712c3028c8a14
 * Body [{"start": "0x3b3e90", "end": "0x3b3f00"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_3b3e90(long param_1)

{
  int *piVar1;
  int iVar2;
  undefined8 *in_GS_OFFSET;
  
  if (*(long *)(param_1 + 0x28) != 0) {
    func_0x0025d410(0x13069f7,0x136fb7e,0xb35);
  }
  if (*(long *)(param_1 + 0x40) != 0) {
    LOCK();
    piVar1 = (int *)(*(long *)(param_1 + 0x40) + 0x28);
    iVar2 = *piVar1;
    *piVar1 = *piVar1 + -1;
    UNLOCK();
    if (iVar2 == 1) {
      func_0x0072b380(*(undefined8 *)(param_1 + 0x40),*in_GS_OFFSET);
    }
    *(undefined8 *)(param_1 + 0x40) = 0;
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* sub_3b3f50 | RVA 0x3b3f50 | local helper / adjacent context (reachability below)
 * Evidence ev_9c4159689177afd755aee1ca75260a5d7102288d97838ddf3fa70b1d5cb4dd36
 * Body [{"start": "0x3b3f50", "end": "0x3b3fa3"}, {"start": "0x3b3fb0", "end": "0x3b4188"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_3b3f50(undefined8 param_1,long param_2,undefined8 param_3,long param_4,ulong param_5,
               int param_6)

{
  int *piVar1;
  byte *pbVar2;
  undefined4 uVar3;
  long lVar4;
  code *pcVar5;
  bool bVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  undefined8 uVar10;
  long lVar11;
  short *psVar12;
  ulong uVar13;
  uint uVar14;
  uint uVar15;
  long *in_GS_OFFSET;
  undefined8 local_58;
  long local_50;
  undefined1 local_48 [16];
  long local_38;
  
  psVar12 = (short *)&DAT_0391c310;
  local_38 = _DAT_0391c310;
  if (((*(int *)(param_2 + 0x5a0) == 0x60) || (*(int *)(param_2 + 0x5a0) == 5)) && (param_6 != 0)) {
    uVar13 = 0;
    uVar7 = 0;
    bVar6 = false;
    do {
      uVar15 = *(uint *)(param_4 + uVar13 * 4);
      uVar14 = (int)uVar15 >> 0x10;
      uVar15 = uVar15 & 0xffff;
      if (uVar14 < 0x80 && uVar15 != 0) {
        if (uVar15 != uVar7) {
          if (bVar6) {
            func_0x00399eb0(local_58);
          }
          psVar12 = (short *)func_0x00399ee0(param_3,uVar15,0x160,&local_58);
          if (psVar12 == (short *)0x0) {
            bVar6 = false;
            psVar12 = (short *)0x0;
            uVar7 = 0;
            goto LAB_003b3fb3;
          }
          bVar6 = true;
        }
        uVar7 = uVar15;
        if ((((int)uVar14 < (int)*psVar12) && (iVar8 = func_0x00399e20(local_58), iVar8 == 0)) &&
           ((lVar11 = *(long *)(*(long *)(psVar12 + 0x14) + (ulong)uVar14 * 8), lVar11 != 0 &&
            ((iVar8 = *(int *)(lVar11 + 0x30), iVar8 == -0x7ffdffa0 || (iVar8 == -0x7ffdfffb)))))) {
          uVar3 = *(undefined4 *)(*(long *)(lVar11 + 0x10) + 0x20);
          uVar10 = func_0x002bc220(0,local_48,0x400000000000080,0x20000000000000d,0);
          iVar9 = func_0x0072c3d0(param_1,uVar3,uVar10,&local_50);
          if (iVar9 == 0) {
            lVar11 = func_0x003b6860(local_50);
            if (lVar11 != 0) {
              lVar4 = *in_GS_OFFSET;
              pbVar2 = (byte *)(lVar4 + 0x3a8);
              *pbVar2 = *pbVar2 | 1;
              func_0x0055a6a0(iVar8 + 0x7ffe0000,1,lVar11,lVar4,0);
              LOCK();
              piVar1 = (int *)(local_50 + 0x28);
              iVar8 = *piVar1;
              *piVar1 = *piVar1 + -1;
              UNLOCK();
              if (iVar8 == 1) {
                func_0x0072b380(local_50,param_1);
              }
              break;
            }
            LOCK();
            piVar1 = (int *)(local_50 + 0x28);
            iVar8 = *piVar1;
            *piVar1 = *piVar1 + -1;
            UNLOCK();
            if (iVar8 == 1) {
              func_0x0072b380(local_50,param_1);
            }
          }
        }
      }
LAB_003b3fb3:
      uVar13 = uVar13 + 1;
    } while ((param_5 & 0xffffffff) != uVar13);
    if (bVar6) {
      func_0x00399eb0(local_58);
    }
  }
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar5 = (code *)invalidInstructionException();
    (*pcVar5)();
  }
  return;
}



/* handler_668_body | RVA 0x3af8e0 | local helper / adjacent context (reachability below)
 * Evidence ev_fc99bb6787dcc738c22b502b69849b8ff29b74271f0148f9f1c3836ea0a00f8d
 * Body [{"start": "0x3af8e0", "end": "0x3af8eb"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void processEntry handler_668_body(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* handler_661_body | RVA 0x3af8f0 | local helper / adjacent context (reachability below)
 * Evidence ev_28085dcf3678a7fd0ee9b2ec66b8e24897a27ce91f37b545aaa2bd7f6adf46dd
 * Body [{"start": "0x3af8f0", "end": "0x3af8fb"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void handler_661_body(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* handler_662_body | RVA 0x3af900 | local helper / adjacent context (reachability below)
 * Evidence ev_17cf5f7c7556c4104056c11dcae597607504b869c70271155d51206e4cb0394e
 * Body [{"start": "0x3af900", "end": "0x3af916"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted.", "Ghidra Listing reports a terminal call at 0x3af912 to 0x3af920 adjacent_3af920 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

void handler_662_body(undefined8 param_1,undefined8 *param_2)

{
  adjacent_3af920(param_1,*param_2,*(undefined4 *)(param_2 + 1),param_2[2]);
  return;
}



/* adjacent_3af920 | RVA 0x3af920 | local helper / adjacent context (reachability below)
 * Evidence ev_a36d95dbaafde34c4e74cdfc296895c750709be2e9399155d760a7b24233d251
 * Body [{"start": "0x3af920", "end": "0x3afb82"}, {"start": "0x3afb90", "end": "0x3afc1d"}, {"start": "0x3afc20", "end": "0x3b01e7"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int adjacent_3af920(long param_1,undefined4 *param_2,ulong param_3,undefined8 param_4)

{
  short *psVar1;
  code *pcVar2;
  int iVar3;
  int iVar4;
  long lVar5;
  short *psVar6;
  undefined8 uVar7;
  long lVar8;
  undefined4 *puVar9;
  undefined4 *puVar10;
  ulong uVar11;
  undefined8 uVar12;
  uint uVar13;
  ulong uVar14;
  uint uVar15;
  undefined4 *puVar16;
  uint *puVar17;
  uint uVar18;
  undefined8 *in_GS_OFFSET;
  bool bVar19;
  undefined1 auStack_e0 [8];
  undefined4 *local_d8;
  undefined4 *local_d0;
  ulong local_c8;
  short *local_c0;
  undefined8 local_b8;
  ulong local_b0;
  short *local_a8;
  short *local_a0;
  ulong local_98;
  undefined8 local_90;
  long local_88;
  undefined8 local_80;
  long local_78;
  undefined4 local_70;
  undefined4 local_6c;
  uint local_68;
  undefined4 uStack_64;
  long local_60;
  
  puVar10 = (undefined4 *)auStack_e0;
  local_60 = _DAT_0391c310;
  lVar8 = *(long *)(param_1 + 8);
  local_90 = *(undefined8 *)(lVar8 + 0xc48);
  local_6c = 0;
  local_70 = 0;
  local_98 = param_3;
  local_80 = param_4;
  local_78 = param_1;
  lVar5 = func_0x009f8180(lVar8);
  iVar3 = func_0x009f81c0(lVar8,&local_68);
  if ((iVar3 == 0) && (local_68 < 0x1000000)) {
    if (local_68 < 0x10000) {
      if (_DAT_034cf7c8 == lVar5) {
        lVar8 = 0x34cf320;
      }
      else if (_DAT_034d08c0 == lVar5) {
        lVar8 = 0x34d0418;
      }
      else {
        lVar8 = 0x34d0418;
        if (_DAT_034cf7c0 == 0) {
          lVar8 = 0x34cf320;
        }
      }
    }
    else {
      if ((local_68 & 0xff0000) != 0x10000) goto LAB_003af9bf;
      lVar8 = 0x34cfe70;
    }
  }
  else {
LAB_003af9bf:
    lVar8 = 0x34cf8c8;
  }
  if ((*(int *)(lVar8 + 0x4a0) == 1) || (iVar3 = adjacent_3b3410(1), iVar3 == 0)) {
    uVar11 = local_98;
    uVar13 = (uint)local_98;
    if (0xffffff7f < uVar13 - 0x81) {
      local_d0 = param_2;
      if (uVar13 < 2) {
        local_d8 = &local_70;
        puVar16 = &local_6c;
        puVar10 = (undefined4 *)auStack_e0;
      }
      else {
        uVar14 = (ulong)(uVar13 * 4 + 0xf & 0xfffffff0);
        puVar16 = (undefined4 *)((ulong)(auStack_e0 + -uVar14) & 0xffffffffffffffe0);
        puVar10 = (undefined4 *)((long)puVar16 - uVar14 & 0xffffffffffffffe0);
        *(undefined8 *)(puVar10 + -2) = 0x3afa73;
        local_d8 = puVar10;
        func_0x00258ff0(puVar10,uVar13 * 4);
      }
      uVar7 = *in_GS_OFFSET;
      lVar8 = (uVar11 & 0xffffffff) * 4;
      *(undefined8 *)(puVar10 + -2) = 0x3afaa3;
      func_0x00c1a3e0(uVar7,"copyin",0);
      puVar9 = local_d0;
      *(undefined8 *)(puVar10 + -2) = 0x3afab2;
      iVar3 = func_0x00259280(puVar9,puVar16,lVar8);
      if (iVar3 == 0) {
        local_d0 = puVar16;
        local_c8 = uVar11 & 0xffffffff;
        *(undefined8 *)(puVar10 + -2) = 0x3afaee;
        psVar6 = (short *)func_0x00b078d0();
        uVar11 = local_c8;
        local_88 = lVar8;
        if ((int)psVar6 == 0) {
          local_a0 = (short *)0x0;
        }
        else {
          lVar8 = local_c8 * 0x18;
          *(undefined8 *)(puVar10 + -2) = 0x3afb17;
          psVar6 = (short *)func_0x00c08b50(lVar8,0x1a7d800,0x102);
          local_a0 = psVar6;
        }
        uVar14 = 0;
        local_b8 = (uint *)((ulong)local_b8._4_4_ << 0x20);
        puVar16 = local_d8;
        puVar9 = local_d0;
        uVar13 = 0;
        do {
          uVar18 = puVar9[uVar14];
          puVar16[uVar14] = 0;
          uVar15 = (int)uVar18 >> 0x10;
          uVar18 = uVar18 & 0xffff;
          if (uVar18 == 0 || 0x7f < uVar15) {
            puVar16[uVar14] = 0x80020003;
            uVar18 = uVar13;
          }
          else if (uVar18 == uVar13) {
            if (psVar6 == (short *)0x0) {
              puVar16[uVar14] = 0x80020003;
              *(undefined8 *)(puVar10 + -2) = 0x3afc0c;
              func_0x0025d410("[0]%s() line=%d i=%d err=0x%x\n","_aio_multi_delete",0xeda,
                              uVar14 & 0xffffffff,3);
              psVar6 = (short *)0x0;
              puVar16 = local_d8;
              puVar9 = local_d0;
              uVar11 = local_c8;
              uVar18 = uVar13;
            }
            else {
LAB_003afc58:
              if ((int)uVar15 < (int)*psVar6) {
                uVar7 = CONCAT44(uStack_64,local_68);
                *(undefined8 *)(puVar10 + -2) = 0x3afc6c;
                iVar3 = func_0x00399e20(uVar7);
                puVar16 = local_d8;
                if (iVar3 == 0) {
                  lVar8 = *(long *)(*(long *)(psVar6 + 0x14) + (ulong)uVar15 * 8);
                  if (lVar8 != 0) {
                    local_a8 = (short *)CONCAT71(local_a8._1_7_,local_a0 != (short *)0x0);
                    local_b0 = (ulong)uVar15;
                    *(undefined8 *)(puVar10 + -2) = 0x3afd33;
                    iVar3 = func_0x00b078d0();
                    if ((iVar3 != 0 & (byte)local_a8) == 1) {
                      *(undefined4 *)(local_a0 + uVar14 * 0xc) = local_d0[uVar14];
                      *(undefined8 *)(local_a0 + uVar14 * 0xc + 4) = **(undefined8 **)(lVar8 + 0x18)
                      ;
                      *(ulong *)(local_a0 + uVar14 * 0xc + 8) =
                           (long)*(ulong *)(lVar8 + 0x10) >> 4 ^ *(ulong *)(lVar8 + 0x10);
                    }
                    psVar1 = *(short **)(lVar8 + 0x20);
                    if (*(int *)(psVar1 + 4) - 3U < 2) {
                      local_a8 = psVar1 + 0x10;
                      *(undefined8 *)(puVar10 + -2) = 0;
                      *(undefined8 *)(puVar10 + -4) = 0;
                      *(undefined8 *)(puVar10 + -6) = 0x3afda6;
                      func_0x00bf1770(psVar1 + 0x10,0x80000,0,0,0,0);
                      if ((char)psVar1[6] == '\0') {
                        *(undefined8 *)(puVar10 + -2) = 0x3afdd0;
                        func_0x0025d410("%s:%d err=%d\n","_aio_multi_delete",0xf0a,0x10);
                        local_d8[uVar14] = 0x80020010;
                      }
                      puVar16 = local_d8;
                      local_c0 = psVar1;
                      if (*(long *)(psVar1 + 0x28) != 0) {
                        *(undefined8 *)(puVar10 + -2) = 0x3afe0a;
                        func_0x0025d410("%s:%d err=%d\n","_aio_multi_delete",0xf0f,0x10);
                        puVar16[uVar14] = 0x80020010;
                      }
                      psVar1 = local_a8;
                      *(undefined8 *)(puVar10 + -2) = 0;
                      *(undefined8 *)(puVar10 + -4) = 0;
                      *(undefined8 *)(puVar10 + -6) = 0x3afe2e;
                      func_0x00bf1770(psVar1,0x100000,0,0,0,0);
                      puVar9 = local_d0;
                      uVar11 = local_c8;
                      if (((puVar16[uVar14] == 0) && (*(int *)(local_c0 + 2) == 0)) &&
                         ((char)local_c0[6] != '\0')) {
                        uVar7 = CONCAT44(uStack_64,local_68);
                        *(undefined8 *)(puVar10 + -2) = 0x3afe6c;
                        func_0x00399eb0(uVar7);
                        uVar7 = local_90;
                        *(undefined8 *)(puVar10 + -2) = 0x3afe81;
                        psVar6 = (short *)func_0x0039a2a0(uVar7,uVar18,0x160,&local_68);
                        psVar1 = local_a8;
                        if (psVar6 == (short *)0x0) {
                          local_d8[uVar14] = 0;
                          goto LAB_003afcf3;
                        }
                        lVar8 = *(long *)(*(long *)(psVar6 + 0x14) + local_b0 * 8);
                        local_c0 = psVar6;
                        if (psVar6[1] == 1) {
                          if (lVar8 != 0) {
                            lVar5 = *(long *)(lVar8 + 0x18);
                            if (lVar5 != 0) {
                              if (*(long *)(lVar5 + 0x10) != 0) {
                                *(undefined8 *)(puVar10 + -2) = 0x3afed6;
                                func_0x002a9670();
                                *(undefined8 *)(lVar5 + 0x10) = 0;
                              }
                              *(undefined8 *)(puVar10 + -2) = 0x3afeed;
                              func_0x00c08df0(lVar5,0x1ab59e0);
                              *(undefined8 *)(lVar8 + 0x18) = 0;
                            }
                            if (*local_c0 == 1) {
                              puVar17 = *(uint **)(lVar8 + 0x20);
                              if (puVar17 != (uint *)0x0) {
                                *(undefined8 *)(lVar8 + 0x20) = 0;
                                uVar13 = *puVar17;
                                if (uVar13 != 0) {
                                  uVar15 = 0;
                                  psVar6 = local_c0;
                                  local_b8 = puVar17;
                                  do {
                                    if (*(long *)(*(long *)(psVar6 + 0x14) + (long)(int)uVar15 * 8)
                                        != 0) {
                                      *(undefined8 *)(puVar10 + -2) = 0x3aff93;
                                      func_0x003b3e90();
                                      *(undefined8 *)
                                       (*(long *)(local_c0 + 0x14) + (long)(int)uVar15 * 8) = 0;
                                      uVar13 = *local_b8;
                                      psVar6 = local_c0;
                                    }
                                    puVar17 = local_b8;
                                    uVar15 = uVar15 + 1;
                                  } while (uVar15 < uVar13);
                                  if (1 < uVar13) {
                                    uVar15 = 0;
                                    do {
                                      if (*(long *)(*(long *)(psVar6 + 0x14) + (long)(int)uVar15 * 8
                                                   ) != 0) {
                                        *(undefined8 *)(puVar10 + -2) = 0x3b006c;
                                        func_0x0025d410(
                                                  "[0]%s() line=%d [%d] aio_obj->queue_ent[%d]=%p\n"
                                                  ,"_aio_multi_delete",0xf4d,uVar15,uVar15);
                                        uVar13 = *puVar17;
                                        psVar6 = local_c0;
                                      }
                                      uVar15 = uVar15 + 1;
                                    } while (uVar15 < uVar13);
                                  }
                                }
                                *(undefined8 *)(puVar10 + -2) = 0x3b0081;
                                func_0x00bf1760(puVar17 + 8);
                              }
                            }
                            else {
                              *(undefined8 *)(puVar10 + -2) = 0x3b001c;
                              func_0x003b3e90(lVar8);
                            }
                            psVar6 = local_c0;
                            *(undefined8 *)(*(long *)(local_c0 + 0x14) + local_b0 * 8) = 0;
                            uVar7 = *(undefined8 *)(local_c0 + 8);
                            *(undefined8 *)(puVar10 + -2) = 0x3b00a8;
                            func_0x00c08df0(uVar7,0x1ab5970);
                            uVar7 = *(undefined8 *)(psVar6 + 0x10);
                            *(undefined8 *)(puVar10 + -2) = 0x3b00b9;
                            func_0x00c08df0(uVar7,0x1ab5890);
                            uVar7 = *(undefined8 *)(psVar6 + 0x14);
                            *(undefined8 *)(puVar10 + -2) = 0x3b00cd;
                            func_0x00c08df0(uVar7,0x1ab5a50);
                            *(undefined8 *)(puVar10 + -2) = 0x3b00d8;
                            func_0x00c08df0(psVar6,0x1ab5a50);
                            uVar12 = local_90;
                            uVar7 = CONCAT44(uStack_64,local_68);
                            *(undefined8 *)(puVar10 + -2) = 0x3b00e8;
                            func_0x00399e30(uVar12,uVar18,uVar7);
                          }
                          uVar7 = CONCAT44(uStack_64,local_68);
                          *(undefined8 *)(puVar10 + -2) = 0x3b00f1;
                          func_0x00399eb0(uVar7);
                          local_b8 = (uint *)((ulong)local_b8 & 0xffffffff00000000);
                          psVar6 = local_c0;
                          puVar16 = local_d8;
                          puVar9 = local_d0;
                          uVar11 = local_c8;
                          uVar18 = 0;
                        }
                        else {
                          puVar16 = local_d8;
                          puVar9 = local_d0;
                          uVar11 = local_c8;
                          if (lVar8 != 0) {
                            psVar6[1] = psVar6[1] + -1;
                            if (*(long *)(lVar8 + 0x20) != 0) {
                              *(undefined8 *)(puVar10 + -2) = 0x3affe6;
                              func_0x00bf1760(psVar1);
                              *(undefined8 *)(lVar8 + 0x20) = 0;
                            }
                            *(undefined8 *)(puVar10 + -2) = 0x3afff7;
                            func_0x003b3e90(lVar8);
                            *(undefined8 *)(*(long *)(local_c0 + 0x14) + local_b0 * 8) = 0;
                            psVar6 = local_c0;
                            puVar16 = local_d8;
                            puVar9 = local_d0;
                            uVar11 = local_c8;
                          }
                        }
                      }
                    }
                    else {
                      local_d8[uVar14] = 0x80020010;
                      puVar16 = local_d8;
                      puVar9 = local_d0;
                      uVar11 = local_c8;
                    }
                    goto LAB_003afb9b;
                  }
                  uVar7 = 0xef0;
                  uVar12 = 3;
                  local_d8[uVar14] = 0x80020003;
                }
                else {
                  uVar7 = 0xee9;
                  uVar12 = 1;
                  local_d8[uVar14] = 0x80020001;
                }
                *(undefined8 *)(puVar10 + -2) = 0x3afca3;
                func_0x0025d410("[0]%s() line=%d i=%d err=0x%x\n","_aio_multi_delete",uVar7,
                                uVar14 & 0xffffffff,uVar12);
                puVar9 = local_d0;
                uVar11 = local_c8;
              }
              else {
                puVar16[uVar14] = 0x80020003;
                *(undefined8 *)(puVar10 + -2) = 0x3afcd3;
                func_0x0025d410("[0]%s() line=%d i=%d err=0x%x\n","_aio_multi_delete",0xee3,
                                uVar14 & 0xffffffff,3);
                puVar16 = local_d8;
                puVar9 = local_d0;
                uVar11 = local_c8;
              }
            }
          }
          else {
            if ((int)local_b8 != 0) {
              uVar7 = CONCAT44(uStack_64,local_68);
              *(undefined8 *)(puVar10 + -2) = 0x3afc2f;
              func_0x00399eb0(uVar7);
            }
            uVar7 = local_90;
            *(undefined8 *)(puVar10 + -2) = 0x3afc44;
            psVar6 = (short *)func_0x00399ee0(uVar7,uVar18,0x160,&local_68);
            if (psVar6 != (short *)0x0) {
              local_b8 = (uint *)CONCAT44(local_b8._4_4_,1);
              puVar16 = local_d8;
              goto LAB_003afc58;
            }
            local_d8[uVar14] = 0x80020003;
LAB_003afcf3:
            uVar18 = 0;
            local_b8 = (uint *)((ulong)local_b8 & 0xffffffff00000000);
            psVar6 = (short *)0x0;
            puVar16 = local_d8;
            puVar9 = local_d0;
            uVar11 = local_c8;
          }
LAB_003afb9b:
          psVar1 = local_a0;
          uVar14 = uVar14 + 1;
          uVar13 = uVar18;
        } while (uVar14 != uVar11);
        bVar19 = local_a0 != (short *)0x0;
        *(undefined8 *)(puVar10 + -2) = 0x3b0120;
        iVar3 = func_0x00b078d0();
        lVar8 = local_78;
        uVar11 = local_98;
        if (iVar3 != 0 && bVar19) {
          *(undefined8 *)(puVar10 + -2) = 0x3b0146;
          func_0x000a3960(lVar8,uVar11,psVar1);
          *(undefined8 *)(puVar10 + -2) = 0x3b0155;
          func_0x00c08df0(psVar1,0x1a7d800);
        }
        if ((int)local_b8 != 0) {
          *(undefined8 *)(puVar10 + -2) = 0x3b0164;
          func_0x00399eb0(CONCAT44(uStack_64,local_68));
        }
        uVar7 = *in_GS_OFFSET;
        *(undefined8 *)(puVar10 + -2) = 0x3b017b;
        func_0x00c1a3e0(uVar7,"copyout",0);
        uVar7 = local_80;
        lVar5 = local_88;
        puVar16 = local_d8;
        *(undefined8 *)(puVar10 + -2) = 0x3b018f;
        iVar3 = func_0x002591d0(puVar16,uVar7,lVar5);
        *(undefined8 *)(puVar10 + -2) = 0x3b0197;
        iVar4 = func_0x00b078d0();
        uVar11 = local_98;
        if (iVar4 != 0) {
          *(undefined8 *)(puVar10 + -2) = 0x3b01aa;
          func_0x000a39f0(uVar11,puVar16,lVar8);
        }
      }
      else {
        *(undefined8 *)(puVar10 + -2) = 0x3afad5;
        func_0x0025d410("%s:%d err=%d\n","_aio_multi_delete",0xeb0,iVar3);
      }
      goto LAB_003b01aa;
    }
    iVar3 = 0x16;
    uVar7 = 0xea1;
  }
  else {
    uVar7 = 0xe9b;
  }
  func_0x0025d410("%s:%d err=%d\n","_aio_multi_delete",uVar7,iVar3);
LAB_003b01aa:
  if (_DAT_0391c310 != local_60) {
    *(undefined8 *)((long)puVar10 + -8) = 0x3b01e6;
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar2 = (code *)invalidInstructionException();
    (*pcVar2)();
  }
  return iVar3;
}



/* handler_663_body | RVA 0x3b01f0 | local helper / adjacent context (reachability below)
 * Evidence ev_2466c2d119eee7bd3f1b638ba5258d20c1ad6bd53868611e17df66f4fc32242a
 * Body [{"start": "0x3b01f0", "end": "0x3b020e"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted.", "Ghidra Listing reports a terminal call at 0x3b020a to 0x3b0210 adjacent_3b0210 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

void handler_663_body(undefined8 param_1,undefined8 *param_2)

{
  adjacent_3b0210(param_1,*param_2,*(undefined4 *)(param_2 + 1),param_2[2],
                  *(undefined4 *)(param_2 + 3),param_2[4]);
  return;
}



/* adjacent_3b0210 | RVA 0x3b0210 | local helper / adjacent context (reachability below)
 * Evidence ev_60132c6eb695d11dc24ba22220e4081cf0ec74166747aa65a369acfa98760376
 * Body [{"start": "0x3b0210", "end": "0x3b05cd"}, {"start": "0x3b05d0", "end": "0x3b068e"}, {"start": "0x3b0690", "end": "0x3b0dad"}, {"start": "0x3b0db0", "end": "0x3b0e55"}, {"start": "0x3b0e60", "end": "0x3b0ebb"}, {"start": "0x3b0ec0", "end": "0x3b0fae"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Type propagation algorithm not settling */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int adjacent_3b0210(long param_1,undefined8 param_2,ulong param_3,undefined8 param_4,uint param_5,
                   long param_6)

{
  long *plVar1;
  byte *pbVar2;
  code *pcVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  long lVar7;
  long *plVar8;
  long *plVar9;
  ulong uVar10;
  uint uVar11;
  undefined8 uVar12;
  long lVar13;
  int *piVar14;
  ulong *puVar15;
  undefined8 uVar16;
  undefined4 uVar17;
  uint uVar18;
  uint uVar19;
  int *piVar20;
  ulong uVar21;
  ulong uVar22;
  undefined8 *in_GS_OFFSET;
  bool bVar23;
  undefined1 auStack_180 [20];
  int local_16c;
  long local_168;
  ulong local_160;
  uint local_154;
  int *local_150;
  int *local_148;
  long *local_140;
  ulong *local_138;
  long local_130;
  short *local_128;
  long local_120;
  long local_118;
  ulong local_110;
  undefined4 local_104;
  long local_100;
  long local_f8;
  long local_f0;
  undefined8 local_e8;
  undefined8 local_e0;
  ulong local_d8;
  ulong local_d0;
  long local_c8;
  ulong local_c0;
  long local_b8;
  long local_b0;
  long local_a8;
  uint local_a0 [6];
  undefined1 local_88 [12];
  int local_7c;
  uint local_78;
  int local_74 [3];
  long local_68;
  long local_60;
  
  piVar14 = (int *)auStack_180;
  local_60 = _DAT_0391c310;
  lVar13 = *(long *)(param_1 + 8);
  local_e0 = *(undefined8 *)(lVar13 + 0xc48);
  local_74[2] = 0;
  local_74[1] = 0;
  local_78 = 0;
  local_120 = param_6;
  local_118 = param_1;
  local_110 = param_3;
  local_e8 = param_4;
  lVar7 = func_0x009f8180(lVar13);
  iVar5 = func_0x009f81c0(lVar13,local_a0);
  lVar13 = 0x34cf8c8;
  uVar17 = 0;
  if ((iVar5 == 0) && (local_a0[0] < 0x1000000)) {
    if (local_a0[0] < 0x10000) {
      uVar17 = 1;
      if (_DAT_034cf7c8 == lVar7) {
        lVar13 = 0x34cf320;
        goto LAB_003b0339;
      }
      if (_DAT_034d08c0 == lVar7) {
        lVar13 = 0x34d0418;
        iVar5 = _DAT_034d08b8;
      }
      else {
        lVar13 = 0x34d0418;
        if (_DAT_034cf7c0 == 0) {
          lVar13 = 0x34cf320;
        }
        iVar5 = *(int *)(lVar13 + 0x4a0);
      }
    }
    else {
      lVar13 = 0x34cf8c8;
      if ((local_a0[0] & 0xff0000) == 0x10000) {
        lVar13 = 0x34cfe70;
      }
      iVar5 = *(int *)(lVar13 + 0x4a0);
    }
    uVar17 = 1;
    uVar4 = 1;
    if (iVar5 == 1) goto LAB_003b0384;
LAB_003b0342:
    uVar17 = uVar4;
    iVar5 = adjacent_3b3410(1);
    if (iVar5 == 0) goto LAB_003b0384;
    uVar12 = 0xffc;
  }
  else {
LAB_003b0339:
    uVar4 = uVar17;
    if (*(int *)(lVar13 + 0x4a0) != 1) goto LAB_003b0342;
LAB_003b0384:
    uVar11 = (uint)local_110;
    if (uVar11 - 0x81 < 0xffffff80) {
      iVar5 = 0x16;
      uVar12 = 0x1002;
      piVar14 = (int *)auStack_180;
    }
    else if (param_5 < 3) {
      local_160 = local_110 & 0xffffffff;
      local_154 = param_5;
      local_f0 = lVar13;
      if (uVar11 < 2) {
        local_148 = local_74 + 1;
        piVar20 = local_74 + 2;
        piVar14 = (int *)auStack_180;
      }
      else {
        uVar22 = (ulong)(uVar11 * 4 + 0xf & 0xfffffff0);
        piVar20 = (int *)((ulong)(auStack_180 + -uVar22) & 0xffffffffffffffe0);
        piVar14 = (int *)((long)piVar20 - uVar22 & 0xffffffffffffffe0);
        piVar14[-2] = 0x3b0408;
        piVar14[-1] = 0;
        local_148 = piVar14;
        func_0x00258ff0(piVar14,uVar11 * 4);
      }
      uVar12 = *in_GS_OFFSET;
      lVar13 = local_160 * 4;
      piVar14[-2] = 0x3b045f;
      piVar14[-1] = 0;
      func_0x00c1a3e0(uVar12,"copyin",0);
      piVar14[-2] = 0x3b046d;
      piVar14[-1] = 0;
      iVar5 = func_0x00259280(param_2,piVar20,lVar13);
      lVar7 = local_120;
      if (iVar5 == 0) {
        local_150 = piVar20;
        local_100 = lVar13;
        if (local_120 != 0) {
          uVar12 = *in_GS_OFFSET;
          piVar14[-2] = 0x3b04e4;
          piVar14[-1] = 0;
          func_0x00c1a3e0(uVar12,"copyin",0);
          piVar14[-2] = 0x3b04f8;
          piVar14[-1] = 0;
          iVar5 = func_0x00259280(lVar7,&local_78,4);
          if (iVar5 != 0) {
            uVar12 = 0x1022;
            goto LAB_003b0489;
          }
        }
        piVar14[-2] = 0x3b051c;
        piVar14[-1] = 0;
        iVar5 = func_0x00b078d0();
        uVar22 = local_160;
        local_104 = uVar17;
        if (iVar5 == 0) {
          local_f8 = 0;
        }
        else {
          lVar13 = local_160 * 0x18;
          piVar14[-2] = 0x3b0545;
          piVar14[-1] = 0;
          local_f8 = func_0x00c08b50(lVar13,0x1a7d800,0x102);
        }
        uVar11 = local_154;
        local_7c = 0;
        piVar14[-2] = 0x3b0576;
        piVar14[-1] = 0;
        func_0x004c7dd0(local_88,"AIO MWait mutex",0,0);
        piVar14[-2] = 0x3b058b;
        piVar14[-1] = 0;
        plVar8 = (long *)func_0x00c08b50(uVar22 * 0x38,0x1ab5a50,0x102);
        if (uVar11 == 2) {
          local_7c = 1;
          local_74[0] = 0;
        }
        puVar15 = (ulong *)(local_f8 + 0x10);
        uVar21 = 0;
        local_16c = 0;
        uVar22 = local_160;
        piVar20 = local_150;
        uVar11 = 0;
        local_140 = plVar8;
        do {
          uVar12 = local_e0;
          uVar19 = piVar20[uVar21] >> 0x10;
          uVar18 = piVar20[uVar21] & 0xffff;
          if (uVar18 == 0 || 0x7f < uVar19) {
            *(undefined4 *)(plVar8 + 4) = 0x80020003;
            uVar18 = uVar11;
          }
          else {
            local_138 = puVar15;
            if (uVar18 != uVar11) {
              piVar14[-2] = 0x3b0639;
              piVar14[-1] = 0;
              local_128 = (short *)func_0x00399ee0(uVar12,uVar18,0x160,&local_68);
              if (local_128 == (short *)0x0) {
                *(undefined4 *)(plVar8 + 4) = 0x80020003;
                uVar18 = 0;
                local_128 = (short *)0x0;
                uVar22 = local_160;
                piVar20 = local_150;
                puVar15 = local_138;
                goto LAB_003b05db;
              }
              plVar8[5] = local_68;
            }
            lVar13 = local_68;
            if ((int)uVar19 < (int)*local_128) {
              piVar14[-2] = 0x3b0665;
              piVar14[-1] = 0;
              iVar5 = func_0x00399e20(lVar13);
              if (iVar5 == 0) {
                lVar13 = *(long *)(*(long *)(local_128 + 0x14) + (ulong)uVar19 * 8);
                if (lVar13 != 0) {
                  local_168 = CONCAT71(local_168._1_7_,local_f8 != 0);
                  local_d8 = (ulong)uVar19;
                  piVar14[-2] = 0x3b0708;
                  piVar14[-1] = 0;
                  iVar5 = func_0x00b078d0();
                  if ((iVar5 != 0 & (byte)local_168) == 1) {
                    *(int *)(local_138 + -2) = local_150[uVar21];
                    local_138[-1] = **(ulong **)(lVar13 + 0x18);
                    *local_138 = (long)*(ulong *)(lVar13 + 0x10) >> 4 ^ *(ulong *)(lVar13 + 0x10);
                  }
                  lVar13 = *(long *)(lVar13 + 0x20);
                  if (lVar13 == 0) {
                    piVar14[-2] = 0x3b0768;
                    piVar14[-1] = 0;
                    func_0x0025d410("[0]%s() line=%d \n\n WARNING [%d] %p\n","_aio_multi_wait",
                                    0x107f,uVar21 & 0xffffffff,0);
                  }
                  local_168 = lVar13 + 0x20;
                  piVar14[-2] = 0;
                  piVar14[-1] = 0;
                  piVar14[-4] = 0;
                  piVar14[-3] = 0;
                  piVar14[-6] = 0x3b0788;
                  piVar14[-5] = 0;
                  func_0x00bf1770(lVar13 + 0x20,0x80000,0,0,0,0);
                  if (local_154 == 1) {
                    uVar11 = *(uint *)(lVar13 + 8);
                    *(uint *)(plVar8 + 4) = uVar11;
                    if ((int)uVar11 < 3) {
                      local_130 = lVar13;
                      piVar14[-2] = 0x3b07c5;
                      piVar14[-1] = 0;
                      func_0x004c6a00(local_88,0,0,0);
                      local_7c = local_7c + 1;
                      *plVar8 = (long)&local_7c;
                      plVar8[2] = (long)local_a0;
                      piVar14[-2] = 0x3b07ee;
                      piVar14[-1] = 0;
                      func_0x004c6fa0(local_88,0,0,0);
                      if (*(int *)(local_130 + 8) < 3) {
                        local_16c = 0;
                        plVar8[6] = *(long *)(local_130 + 0x50);
                        *(long **)(local_130 + 0x50) = plVar8;
                        plVar8[3] = local_130;
                      }
                      else {
LAB_003b0976:
                        piVar14[-2] = 0x3b0990;
                        piVar14[-1] = 0;
                        func_0x0025d410("[0]%s() line=%d WARNING !! already changed to completed ... \n"
                                        ,"set_waiter",0xfa9);
                        piVar14[-2] = 0x3b09a5;
                        piVar14[-1] = 0;
                        func_0x004c6a00(local_88,0,0,0);
                        local_7c = local_7c + -1;
                        piVar14[-2] = 0x3b09b9;
                        piVar14[-1] = 0;
                        func_0x004c6fa0(local_88,0,0,0);
                        local_16c = 0x10;
                      }
                    }
                    else {
LAB_003b08cd:
                      if (*(char *)(lVar13 + 0xc) == '\0') {
                        *(undefined1 *)(lVar13 + 0xc) = 1;
                      }
                      else {
                        *(uint *)(plVar8 + 4) = uVar11 | 0x10000;
                      }
                    }
                  }
                  else if (local_154 == 2) {
                    uVar11 = *(uint *)(lVar13 + 8);
                    *(uint *)(plVar8 + 4) = uVar11;
                    local_130 = lVar13;
                    if (2 < (int)uVar11) goto LAB_003b08cd;
                    piVar14[-2] = 0x3b086f;
                    piVar14[-1] = 0;
                    func_0x004c6a00(local_88,0,0,0);
                    local_74[0] = local_74[0] + 1;
                    *plVar8 = (long)&local_7c;
                    plVar8[2] = (long)local_a0;
                    plVar8[1] = (long)local_74;
                    piVar14[-2] = 0x3b08a3;
                    piVar14[-1] = 0;
                    func_0x004c6fa0(local_88,0,0,0);
                    if (*(int *)(local_130 + 8) < 3) {
                      local_16c = 0;
                      plVar8[6] = *(long *)(local_130 + 0x50);
                      *(long **)(local_130 + 0x50) = plVar8;
                      plVar8[3] = local_130;
                    }
                    else {
                      piVar14[-2] = 0x3b09f3;
                      piVar14[-1] = 0;
                      func_0x0025d410("[0]%s() line=%d WARNING !! already changed to completed ... \n"
                                      ,"set_waiter",0xfa9);
                      local_16c = 0x10;
                    }
                  }
                  else {
                    lVar7 = *(long *)(*(long *)(*(long *)(local_128 + 0x14) + local_d8 * 8) + 0x20);
                    uVar11 = *(uint *)(lVar7 + 8);
                    *(uint *)(local_140 + 4) = uVar11;
                    if ((int)uVar11 < 3) {
                      local_130 = lVar13;
                      piVar14[-2] = 0x3b091e;
                      piVar14[-1] = 0;
                      func_0x004c6a00(local_88,0,0,0);
                      local_7c = local_7c + 1;
                      *local_140 = (long)&local_7c;
                      local_140[2] = (long)local_a0;
                      piVar14[-2] = 0x3b094f;
                      piVar14[-1] = 0;
                      func_0x004c6fa0(local_88,0,0,0);
                      if (2 < *(int *)(lVar7 + 8)) goto LAB_003b0976;
                      local_16c = 0;
                      local_140[6] = *(long *)(lVar7 + 0x50);
                      *(long **)(lVar7 + 0x50) = local_140;
                      local_140[3] = lVar7;
                    }
                    else if (*(char *)(lVar7 + 0xc) == '\0') {
                      *(undefined1 *)(lVar7 + 0xc) = 1;
                      local_130 = lVar13;
                    }
                    else {
                      *(uint *)(local_140 + 4) = uVar11 | 0x10000;
                      local_130 = lVar13;
                    }
                  }
                  lVar13 = local_168;
                  piVar14[-2] = 0;
                  piVar14[-1] = 0;
                  piVar14[-4] = 0;
                  piVar14[-3] = 0;
                  piVar14[-6] = 0x3b0a1d;
                  piVar14[-5] = 0;
                  func_0x00bf1770(lVar13,0x100000,0,0,0,0);
                  uVar22 = local_160;
                  piVar20 = local_150;
                  puVar15 = local_138;
                  goto LAB_003b05db;
                }
                *(undefined4 *)(plVar8 + 4) = 0x80020003;
                uVar12 = 0x1071;
                goto LAB_003b06ab;
              }
              *(undefined4 *)(plVar8 + 4) = 0x80020001;
              uVar12 = 0x106a;
              uVar16 = 1;
            }
            else {
              uVar12 = 0x1064;
              *(undefined4 *)(plVar8 + 4) = 0x80020003;
LAB_003b06ab:
              uVar16 = 3;
            }
            piVar14[-2] = 0x3b06bb;
            piVar14[-1] = 0;
            func_0x0025d410("[0]%s() line=%d i=%d err=0x%x\n","_aio_multi_wait",uVar12,
                            uVar21 & 0xffffffff,uVar16);
            uVar22 = local_160;
            piVar20 = local_150;
            puVar15 = local_138;
          }
LAB_003b05db:
          lVar13 = local_f8;
          uVar21 = uVar21 + 1;
          plVar8 = plVar8 + 7;
          puVar15 = puVar15 + 3;
          uVar11 = uVar18;
        } while (uVar22 != uVar21);
        bVar23 = local_f8 != 0;
        piVar14[-2] = 0x3b0a54;
        piVar14[-1] = 0;
        iVar5 = func_0x00b078d0();
        uVar18 = local_78;
        uVar22 = local_110;
        lVar7 = local_118;
        uVar11 = local_154;
        if (iVar5 != 0 && bVar23) {
          piVar14[-2] = 0x3b0a7d;
          piVar14[-1] = 0;
          func_0x000a3af0(lVar7,uVar22,uVar11,uVar18,lVar13);
          piVar14[-2] = 0x3b0a8c;
          piVar14[-1] = 0;
          func_0x00c08df0(lVar13,0x1a7d800);
        }
        piVar14[-2] = 0x3b0aa1;
        piVar14[-1] = 0;
        func_0x004c6a00(local_88,0,0,0);
        lVar13 = local_120;
        if ((0 < local_7c) && ((uVar11 != 2 || (local_74[0] != 0)))) {
          piVar14[-2] = 0x3b0ad7;
          piVar14[-1] = 0;
          func_0x004c6a00(0x34cf2e8,0,0,0);
          lVar7 = local_f0;
          if (*(long *)(local_f0 + 0x4b0) != 0) {
            piVar14[-2] = 0x3b0af9;
            piVar14[-1] = 0;
            func_0x0073ef80(0x34cf2f0);
          }
          if (*(long *)(lVar7 + 0x528) != 0) {
            piVar14[-2] = 0x3b0b1b;
            piVar14[-1] = 0;
            func_0x0073ef80(0x34cf2f0);
          }
          piVar14[-2] = 0x3b0b2d;
          piVar14[-1] = 0;
          func_0x004c6fa0(0x34cf2e8,0,0,0);
          if (local_78 == 0) {
            piVar14[-4] = 0x100;
            piVar14[-3] = 0;
            piVar14[-6] = 0x3b0cca;
            piVar14[-5] = 0;
            iVar5 = func_0x00c06260(&local_7c,local_a0,0x104c,"aio mwait",0,0);
            local_16c = 4;
            if (iVar5 != -1) {
              local_16c = iVar5;
            }
          }
          else {
            uVar21 = (ulong)local_78 / 1000000;
            uVar22 = (ulong)((local_78 % 1000000) * 1000);
            while( true ) {
              local_c8 = (long)uVar22 / 1000;
              uVar12 = *in_GS_OFFSET;
              local_d0 = uVar21;
              piVar14[-2] = 0x3b0bc2;
              piVar14[-1] = 0;
              func_0x006bc2a0(uVar12,&local_b0);
              lVar13 = _DAT_039203d0;
              piVar14[-2] = 0x3b0bd5;
              piVar14[-1] = 0;
              iVar5 = func_0x00c66c80(&local_d0);
              piVar14[-4] = 0x100;
              piVar14[-3] = 0;
              piVar14[-6] = 0x3b0c07;
              piVar14[-5] = 0;
              iVar5 = func_0x00c06260(&local_7c,local_a0,0x104c,"aio mwait",iVar5 * lVar13,0);
              piVar14[-2] = 0x3b0c1d;
              piVar14[-1] = 0;
              func_0x006bc2a0(uVar12,&local_c0);
              uVar10 = local_c0 - local_b0;
              if ((iVar5 != 0x23 && iVar5 != 0) || (local_7c < 1)) break;
              lVar13 = local_b8 - local_a8;
              if (lVar13 < 0) {
                uVar10 = uVar10 - 1;
                lVar13 = lVar13 + 1000000000;
              }
              lVar7 = uVar21 - uVar10;
              local_c0 = uVar10;
              local_b8 = lVar13;
              if (lVar7 == 0) {
                if ((long)uVar22 <= lVar13) goto LAB_003b0cfa;
              }
              else {
                bVar23 = (long)uVar21 < (long)uVar10;
                uVar21 = uVar10;
                if (lVar7 == 0 || bVar23) goto LAB_003b0cfa;
              }
              uVar21 = uVar22 - lVar13;
              uVar22 = uVar21 + 1000000000;
              if (-1 < (long)uVar21) {
                uVar22 = uVar21;
              }
              uVar21 = lVar7 + ((long)uVar21 >> 0x3f);
            }
            lVar13 = local_b8 - local_a8;
            uVar21 = uVar10;
            if (lVar13 < 0) {
              uVar21 = uVar10 - 1;
              lVar13 = lVar13 + 1000000000;
            }
LAB_003b0cfa:
            iVar6 = 0x3c;
            if (iVar5 != 0x23) {
              iVar6 = iVar5;
            }
            local_16c = 4;
            if (iVar5 != -1) {
              local_16c = iVar6;
            }
            uVar11 = ((int)(SUB168(SEXT816(lVar13) * SEXT816(0x20c49ba5e353f7cf),8) >> 7) -
                     (SUB164(SEXT816(lVar13) * SEXT816(0x20c49ba5e353f7cf),0xc) >> 0x1f)) +
                     (int)uVar21 * 1000000;
            bVar23 = local_78 < uVar11;
            local_78 = local_78 - uVar11;
            lVar13 = local_120;
            if (bVar23 || local_78 == 0) {
              local_78 = 0;
            }
          }
        }
        piVar14[-2] = 0x3b0d71;
        piVar14[-1] = 0;
        func_0x004c6fa0(local_88,0,0,0);
        if (lVar13 != 0) {
          uVar12 = *in_GS_OFFSET;
          piVar14[-2] = 0x3b0d8d;
          piVar14[-1] = 0;
          func_0x00c1a3e0(uVar12,"copyout",0);
          piVar14[-2] = 0x3b0da1;
          piVar14[-1] = 0;
          func_0x002591d0(&local_78,lVar13,4);
        }
        uVar21 = 0;
        plVar8 = local_140;
        uVar22 = local_160;
        do {
          lVar13 = plVar8[uVar21 * 7 + 3];
          plVar1 = plVar8 + uVar21 * 7;
          if (lVar13 == 0) {
            local_148[uVar21] = (int)plVar1[4];
          }
          else {
            piVar14[-2] = 0;
            piVar14[-1] = 0;
            piVar14[-4] = 0;
            piVar14[-3] = 0;
            piVar14[-6] = 0x3b0e15;
            piVar14[-5] = 0;
            func_0x00bf1770(lVar13 + 0x20,0x80000,0,0,0,0);
            local_148[uVar21] = (int)plVar1[4];
            if (*(long *)(lVar13 + 0x50) != 0) {
              plVar8 = *(long **)(plVar1[3] + 0x50);
              if (plVar8 == plVar1) {
                *(long *)(plVar1[3] + 0x50) = plVar8[6];
              }
              else {
                do {
                  plVar9 = plVar8;
                  plVar8 = (long *)plVar9[6];
                } while (plVar8 != plVar1);
                plVar9[6] = plVar8[6];
              }
              plVar1[3] = 0;
            }
            if (*(char *)(lVar13 + 0xc) != '\0') {
              pbVar2 = (byte *)((long)local_148 + uVar21 * 4 + 2);
              *pbVar2 = *pbVar2 | 1;
            }
            if (*(int *)(lVar13 + 8) - 3U < 2) {
              *(undefined1 *)(lVar13 + 0xc) = 1;
            }
            piVar14[-2] = 0;
            piVar14[-1] = 0;
            piVar14[-4] = 0;
            piVar14[-3] = 0;
            piVar14[-6] = 0x3b0dcb;
            piVar14[-5] = 0;
            func_0x00bf1770(lVar13 + 0x20,0x100000,0,0,0,0);
            plVar8 = local_140;
            uVar22 = local_160;
          }
          uVar17 = local_104;
          uVar21 = uVar21 + 1;
        } while (uVar21 != uVar22);
        plVar8 = plVar8 + 5;
        do {
          if (*plVar8 != 0) {
            piVar14[-2] = 0x3b0ed6;
            piVar14[-1] = 0;
            func_0x00399eb0();
          }
          plVar8 = plVar8 + 7;
          uVar22 = uVar22 - 1;
        } while (uVar22 != 0);
        piVar14[-2] = 0x3b0ee4;
        piVar14[-1] = 0;
        func_0x004c7e50(local_88);
        uVar12 = local_e0;
        lVar7 = local_f0;
        uVar22 = local_110;
        lVar13 = local_118;
        piVar20 = local_150;
        piVar14[-2] = 0x3b0f06;
        piVar14[-1] = 0;
        func_0x003b3f50(lVar13,lVar7,uVar12,piVar20,uVar22,uVar17);
        uVar12 = local_e8;
        lVar13 = local_100;
        piVar20 = local_148;
        if (local_16c == 4) {
          piVar14[-2] = 0x3b0f68;
          piVar14[-1] = 0;
          func_0x003b3a40(piVar20,uVar12,lVar13);
          iVar5 = 4;
        }
        else {
          iVar5 = local_16c;
          if (local_16c == 0) {
            piVar14[-2] = 0x3b0f2c;
            piVar14[-1] = 0;
            iVar5 = func_0x003b3a40(piVar20,uVar12,lVar13);
            if (iVar5 == 0) {
              iVar5 = 0;
            }
            else {
              piVar14[-2] = 0x3b0f4f;
              piVar14[-1] = 0;
              func_0x0025d410("%s:%d err=%d\n","_aio_multi_wait",0x118f,iVar5);
            }
          }
        }
        piVar14[-2] = 0x3b0f78;
        piVar14[-1] = 0;
        iVar6 = func_0x00b078d0();
        uVar11 = local_78;
        lVar13 = local_118;
        piVar20 = local_148;
        uVar22 = local_160;
        if (iVar6 != 0) {
          piVar14[-2] = 0x3b0f93;
          piVar14[-1] = 0;
          func_0x000a3b90(lVar13,uVar22,piVar20,uVar11);
        }
        plVar8 = local_140;
        piVar14[-2] = 0x3b0fa3;
        piVar14[-1] = 0;
        func_0x00c08df0(plVar8,0x1ab5a50);
        goto LAB_003b0490;
      }
      uVar12 = 0x101b;
    }
    else {
      iVar5 = 0x16;
      uVar12 = 0x100c;
      piVar14 = (int *)auStack_180;
    }
  }
LAB_003b0489:
  *(undefined8 *)((long)piVar14 + -8) = 0x3b0490;
  func_0x0025d410("%s:%d err=%d\n","_aio_multi_wait",uVar12,iVar5);
LAB_003b0490:
  if (_DAT_0391c310 == local_60) {
    return iVar5;
  }
  *(undefined8 *)((long)piVar14 + -8) = 0x3b0fad;
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar3 = (code *)invalidInstructionException();
  (*pcVar3)();
}



/* handler_664_body | RVA 0x3b0fb0 | target syscall body
 * Evidence ev_4efa00db1710a76855e7627270a97d72e85319a617ba22daef8f01fed37445c7
 * Body [{"start": "0x3b0fb0", "end": "0x3b0fc6"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted.", "Ghidra Listing reports a terminal call at 0x3b0fc2 to 0x3b0fd0 adjacent_3b0fd0 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

void handler_664_body(undefined8 param_1,undefined8 *param_2)

{
  adjacent_3b0fd0(param_1,*param_2,*(undefined4 *)(param_2 + 1),param_2[2]);
  return;
}



/* adjacent_3b0fd0 | RVA 0x3b0fd0 | local helper / adjacent context (reachability below)
 * Evidence ev_48934c8dbc3372567a1ec886ae810d332811cc35f5d7d4584657ac08af78630f
 * Body [{"start": "0x3b0fd0", "end": "0x3b1290"}, {"start": "0x3b12a0", "end": "0x3b13a3"}, {"start": "0x3b13b0", "end": "0x3b1662"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int adjacent_3b0fd0(long param_1,undefined8 param_2,ulong param_3,undefined8 param_4)

{
  uint uVar1;
  uint *puVar2;
  code *pcVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  long lVar7;
  ulong uVar8;
  ulong *puVar9;
  uint uVar10;
  long lVar11;
  undefined8 uVar12;
  undefined4 *puVar14;
  undefined4 uVar15;
  uint uVar16;
  ulong uVar17;
  undefined4 *puVar18;
  ulong uVar19;
  undefined8 *in_GS_OFFSET;
  bool bVar20;
  undefined1 auStack_100 [15];
  byte local_f1;
  undefined4 *local_f0;
  int local_e4;
  ulong local_e0;
  short *local_d8;
  undefined4 *local_d0;
  undefined4 local_c4;
  long local_c0;
  ulong local_b8;
  ulong local_b0;
  undefined8 local_a8;
  ulong *local_a0;
  long local_98;
  long local_90;
  undefined8 local_88;
  long local_80;
  undefined4 local_78;
  undefined4 local_74;
  undefined8 local_70;
  uint local_64;
  long local_60;
  ulong uVar13;
  
  puVar14 = (undefined4 *)auStack_100;
  local_60 = _DAT_0391c310;
  lVar11 = *(long *)(param_1 + 8);
  local_a8 = *(undefined8 *)(lVar11 + 0xc48);
  local_70 = 0;
  local_74 = 0;
  local_78 = 0;
  local_b0 = param_3;
  local_88 = param_4;
  local_80 = param_1;
  lVar7 = func_0x009f8180(lVar11);
  iVar5 = func_0x009f81c0(lVar11,&local_64);
  lVar11 = 0x34cf8c8;
  uVar15 = 0;
  if ((iVar5 == 0) && (local_64 < 0x1000000)) {
    if (local_64 < 0x10000) {
      uVar15 = 1;
      if (_DAT_034cf7c8 == lVar7) {
        lVar11 = 0x34cf320;
        goto LAB_003b10f0;
      }
      if (_DAT_034d08c0 == lVar7) {
        lVar11 = 0x34d0418;
        iVar5 = _DAT_034d08b8;
      }
      else {
        lVar11 = 0x34d0418;
        if (_DAT_034cf7c0 == 0) {
          lVar11 = 0x34cf320;
        }
        iVar5 = *(int *)(lVar11 + 0x4a0);
      }
    }
    else {
      lVar11 = 0x34cf8c8;
      if ((local_64 & 0xff0000) == 0x10000) {
        lVar11 = 0x34cfe70;
      }
      iVar5 = *(int *)(lVar11 + 0x4a0);
    }
    uVar15 = 1;
    uVar4 = 1;
    if (iVar5 == 1) goto LAB_003b113b;
LAB_003b10f9:
    uVar15 = uVar4;
    iVar5 = adjacent_3b3410(1,lVar11);
    if (iVar5 == 0) goto LAB_003b113b;
    uVar12 = 0x13c1;
    puVar14 = (undefined4 *)auStack_100;
  }
  else {
LAB_003b10f0:
    uVar4 = uVar15;
    if (*(int *)(lVar11 + 0x4a0) != 1) goto LAB_003b10f9;
LAB_003b113b:
    uVar1 = (uint)local_b0;
    if (uVar1 - 0x81 < 0xffffff80) {
      iVar5 = 0x16;
      uVar12 = 0x13c7;
      puVar14 = (undefined4 *)auStack_100;
    }
    else {
      uVar13 = local_b0 & 0xffffffff;
      local_c4 = uVar15;
      local_90 = lVar11;
      if (uVar1 < 2) {
        local_f0 = &local_78;
        puVar18 = &local_74;
      }
      else {
        uVar8 = (ulong)(uVar1 * 4 + 0xf & 0xfffffff0);
        puVar18 = (undefined4 *)((ulong)(auStack_100 + -uVar8) & 0xffffffffffffffe0);
        puVar14 = (undefined4 *)((long)puVar18 - uVar8 & 0xffffffffffffffe0);
        *(undefined8 *)(puVar14 + -2) = 0x3b11b6;
        local_f0 = puVar14;
        func_0x00258ff0(puVar14,uVar1 * 4);
      }
      uVar12 = *in_GS_OFFSET;
      lVar11 = uVar13 * 4;
      *(undefined8 *)(puVar14 + -2) = 0x3b11e9;
      func_0x00c1a3e0(uVar12,"copyin",0);
      *(undefined8 *)(puVar14 + -2) = 0x3b11f7;
      iVar5 = func_0x00259280(param_2,puVar18,lVar11);
      if (iVar5 == 0) {
        local_d0 = puVar18;
        *(undefined8 *)(puVar14 + -2) = 0x3b124d;
        iVar5 = func_0x00b078d0();
        local_98 = lVar11;
        if (iVar5 == 0) {
          local_c0 = 0;
        }
        else {
          *(undefined8 *)(puVar14 + -2) = 0x3b1272;
          local_c0 = func_0x00c08b50(uVar13 * 0x18,0x1a7d800,0x102);
        }
        puVar9 = (ulong *)(local_c0 + 0x10);
        uVar19 = 0;
        uVar8 = 0;
        local_e4 = 0;
        local_e0 = uVar13;
        do {
          uVar12 = local_70;
          uVar1 = local_d0[uVar19];
          uVar16 = (int)uVar1 >> 0x10;
          uVar10 = uVar1 & 0xffff;
          uVar13 = (ulong)uVar10;
          local_a0 = puVar9;
          if (uVar10 == 0 || 0x7f < uVar16) {
            local_f0[uVar19] = 0x80020003;
            *(undefined8 *)(puVar14 + -2) = 0x3b12cf;
            func_0x0025d410("[0]%s() line=%d i=%d err=0x%x\n","_aio_multi_poll",0x13e6,
                            uVar19 & 0xffffffff,3);
            uVar17 = local_e0;
          }
          else {
            if (uVar10 != (uint)uVar8) {
              if (local_e4 != 0) {
                *(undefined8 *)(puVar14 + -2) = 0x3b132e;
                func_0x00399eb0(uVar12);
              }
              uVar12 = local_a8;
              *(undefined8 *)(puVar14 + -2) = 0x3b1346;
              local_d8 = (short *)func_0x00399ee0(uVar12,uVar13,0x160,&local_70);
              if (local_d8 == (short *)0x0) {
                uVar8 = 0;
                local_f0[uVar19] = 0x80020003;
                *(undefined8 *)(puVar14 + -2) = 0x3b141a;
                func_0x0025d410("[0]%s() line=%d i=%d err=0x%x\n","_aio_multi_poll",0x13f4,
                                uVar19 & 0xffffffff,3);
                local_e4 = 0;
                local_d8 = (short *)0x0;
                uVar17 = local_e0;
                goto LAB_003b12d3;
              }
              local_e4 = 1;
            }
            uVar12 = local_70;
            if ((int)uVar16 < (int)*local_d8) {
              *(undefined8 *)(puVar14 + -2) = 0x3b1372;
              iVar5 = func_0x00399e20(uVar12);
              if (iVar5 == 0) {
                lVar11 = *(long *)(*(long *)(local_d8 + 0x14) + (ulong)uVar16 * 8);
                local_b8 = uVar13;
                if (lVar11 == 0) {
                  local_f0[uVar19] = 0x80020003;
                  *(undefined8 *)(puVar14 + -2) = 0x3b1546;
                  func_0x0025d410("[0]%s() line=%d i=%d err=0x%x\n","_aio_multi_poll",0x140f,
                                  uVar19 & 0xffffffff,3);
                  uVar17 = local_e0;
                  uVar8 = local_b8;
                }
                else {
                  local_f1 = local_c0 != 0;
                  *(undefined8 *)(puVar14 + -2) = 0x3b145c;
                  iVar5 = func_0x00b078d0();
                  if ((iVar5 != 0 & local_f1) == 1) {
                    *(undefined4 *)(local_a0 + -2) = local_d0[uVar19];
                    local_a0[-1] = **(ulong **)(lVar11 + 0x18);
                    *local_a0 = (long)*(ulong *)(lVar11 + 0x10) >> 4 ^ *(ulong *)(lVar11 + 0x10);
                  }
                  puVar2 = *(uint **)(lVar11 + 0x20);
                  if ((0xffff < uVar1) && (1 < *puVar2)) {
                    *(undefined8 *)(puVar14 + -2) = 0x3b14c3;
                    func_0x0025d410("[0]%s() line=%d Warning !! aio_id_idx is not 0 %d\n",
                                    "_aio_multi_poll",0x141f,uVar16);
                  }
                  *(undefined8 *)(puVar14 + -2) = 0;
                  *(undefined8 *)(puVar14 + -4) = 0;
                  *(undefined8 *)(puVar14 + -6) = 0x3b14e2;
                  func_0x00bf1770(puVar2 + 8,0x80000,0,0,0,0);
                  uVar8 = local_b8;
                  uVar17 = local_e0;
                  uVar1 = puVar2[2];
                  local_f0[uVar19] = uVar1;
                  if (2 < (int)uVar1) {
                    if ((char)puVar2[3] == '\0') {
                      *(undefined1 *)(puVar2 + 3) = 1;
                    }
                    else {
                      local_f0[uVar19] = uVar1 | 0x10000;
                    }
                  }
                  *(undefined8 *)(puVar14 + -2) = 0;
                  *(undefined8 *)(puVar14 + -4) = 0;
                  *(undefined8 *)(puVar14 + -6) = 0x3b1572;
                  func_0x00bf1770(puVar2 + 8,0x100000,0,0,0,0);
                }
                goto LAB_003b12d3;
              }
              uVar12 = 0x1408;
              local_f0[uVar19] = 0x80020001;
            }
            else {
              uVar12 = 0x1402;
              local_f0[uVar19] = 0x80020003;
            }
            *(undefined8 *)(puVar14 + -2) = 0x3b13df;
            func_0x0025d410("[0]%s() line=%d i=%d err=0x%x\n","_aio_multi_poll",uVar12,
                            uVar19 & 0xffffffff);
            uVar17 = local_e0;
            uVar8 = uVar13;
          }
LAB_003b12d3:
          lVar11 = local_c0;
          uVar19 = uVar19 + 1;
          puVar9 = local_a0 + 3;
        } while (uVar17 != uVar19);
        bVar20 = local_c0 != 0;
        *(undefined8 *)(puVar14 + -2) = 0x3b158b;
        iVar5 = func_0x00b078d0();
        lVar7 = local_80;
        uVar13 = local_b0;
        if (iVar5 != 0 && bVar20) {
          uVar8 = local_b0 & 0xffffffff;
          *(undefined8 *)(puVar14 + -2) = 0x3b15b0;
          func_0x000a3fb0(lVar7,uVar8,lVar11);
          *(undefined8 *)(puVar14 + -2) = 0x3b15bf;
          func_0x00c08df0(lVar11,0x1a7d800);
        }
        uVar12 = local_70;
        uVar15 = local_c4;
        if (local_e4 != 0) {
          *(undefined8 *)(puVar14 + -2) = 0x3b15d5;
          func_0x00399eb0(uVar12);
        }
        lVar11 = local_90;
        uVar12 = local_a8;
        puVar18 = local_d0;
        *(undefined8 *)(puVar14 + -2) = 0x3b15ef;
        func_0x003b3f50(lVar7,lVar11,uVar12,puVar18,uVar13 & 0xffffffff,uVar15);
        uVar12 = *in_GS_OFFSET;
        *(undefined8 *)(puVar14 + -2) = 0x3b1606;
        func_0x00c1a3e0(uVar12,"copyout",0);
        uVar12 = local_88;
        lVar11 = local_98;
        puVar18 = local_f0;
        *(undefined8 *)(puVar14 + -2) = 0x3b1617;
        iVar5 = func_0x002591d0(puVar18,uVar12,lVar11);
        if (iVar5 != 0) {
          *(undefined8 *)(puVar14 + -2) = 0x3b163b;
          func_0x0025d410("[0]%s() line=%d tret=%d\n","_aio_multi_poll",0x1444,iVar5);
        }
        *(undefined8 *)(puVar14 + -2) = 0x3b1640;
        iVar6 = func_0x00b078d0();
        puVar18 = local_f0;
        if (iVar6 != 0) {
          *(undefined8 *)(puVar14 + -2) = 0x3b1657;
          func_0x000a4040(lVar7,uVar17 & 0xffffffff,puVar18);
        }
        goto LAB_003b121b;
      }
      uVar12 = 0x13d6;
    }
  }
  *(undefined8 *)((long)puVar14 + -8) = 0x3b121b;
  func_0x0025d410("%s:%d err=%d\n","_aio_multi_poll",uVar12,iVar5);
LAB_003b121b:
  if (_DAT_0391c310 == local_60) {
    return iVar5;
  }
  *(undefined8 *)((long)puVar14 + -8) = 0x3b1661;
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar3 = (code *)invalidInstructionException();
  (*pcVar3)();
}



/* handler_665_body | RVA 0x3b1670 | local helper / adjacent context (reachability below)
 * Evidence ev_f5b33e92ce4feb6b9f305a500a927ca28d34e4336da8ccb2dc389ebf9f7a5cd6
 * Body [{"start": "0x3b1670", "end": "0x3b167b"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void handler_665_body(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* adjacent_3b1680 | RVA 0x3b1680 | local helper / adjacent context (reachability below)
 * Evidence ev_3f38d75afb46a2f0b6c4337446e1e056027adca39fd549d38b320feabb2676a4
 * Body [{"start": "0x3b1680", "end": "0x3b1696"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted.", "Ghidra Listing reports a terminal call at 0x3b1692 to 0x3b16a0 adjacent_3b16a0 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

void adjacent_3b1680(undefined8 param_1,undefined8 *param_2)

{
  adjacent_3b16a0(param_1,*param_2,*(undefined4 *)(param_2 + 1),param_2[2]);
  return;
}



/* adjacent_3b16a0 | RVA 0x3b16a0 | local helper / adjacent context (reachability below)
 * Evidence ev_3c30bca390b38ba11d41c9bd22f81fe3d96060e0b2810a74736c62a1ab89336b
 * Body [{"start": "0x3b16a0", "end": "0x3b1924"}, {"start": "0x3b1930", "end": "0x3b19f8"}, {"start": "0x3b1a00", "end": "0x3b1e04"}, {"start": "0x3b1e10", "end": "0x3b1edc"}, {"start": "0x3b1ee0", "end": "0x3b2058"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int adjacent_3b16a0(long param_1,short *param_2,ulong param_3,undefined8 param_4)

{
  long lVar1;
  long *plVar2;
  uint uVar3;
  undefined4 uVar4;
  int *piVar5;
  long *plVar6;
  long lVar7;
  long lVar8;
  code *pcVar9;
  uint *puVar10;
  int iVar11;
  uint uVar12;
  int iVar13;
  long lVar14;
  undefined8 uVar15;
  uint uVar16;
  undefined4 *puVar17;
  ulong uVar18;
  int *piVar19;
  short *psVar20;
  undefined4 *puVar21;
  undefined8 uVar22;
  long lVar23;
  uint uVar24;
  uint *puVar25;
  undefined4 *puVar26;
  ulong uVar27;
  undefined8 *puVar28;
  undefined8 *in_GS_OFFSET;
  bool bVar29;
  undefined1 auStack_120 [24];
  undefined4 *local_108;
  undefined4 *local_100;
  short *local_f8;
  int local_ec;
  ulong local_e8;
  undefined8 local_e0;
  int local_d4;
  long local_d0;
  long local_c8;
  ulong local_c0;
  long local_b8;
  uint *local_b0;
  long local_a8;
  uint *local_a0;
  long local_98;
  undefined8 local_90;
  undefined8 local_88;
  undefined8 local_80;
  ulong local_78;
  undefined4 local_70;
  undefined4 local_6c;
  undefined8 local_68;
  long local_60;
  
  puVar17 = (undefined4 *)auStack_120;
  local_60 = _DAT_0391c310;
  lVar23 = *(long *)(param_1 + 8);
  local_88 = *(undefined8 *)(lVar23 + 0xc48);
  local_68 = 0;
  local_6c = 0;
  local_70 = 0;
  local_c0 = param_3;
  local_a8 = param_1;
  local_90 = param_4;
  lVar14 = func_0x009f8180(lVar23);
  iVar11 = func_0x009f81c0(lVar23,&local_80);
  if ((iVar11 == 0) && ((uint)local_80 < 0x1000000)) {
    if ((uint)local_80 < 0x10000) {
      if (_DAT_034cf7c8 == lVar14) {
        local_b8 = 0x34cf320;
      }
      else if (_DAT_034d08c0 == lVar14) {
        local_b8 = 0x34d0418;
      }
      else {
        local_b8 = 0x34d0418;
        if (_DAT_034cf7c0 == 0) {
          local_b8 = 0x34cf320;
        }
      }
    }
    else {
      if (((uint)local_80 & 0xff0000) != 0x10000) goto LAB_003b175c;
      local_b8 = 0x34cfe70;
    }
  }
  else {
LAB_003b175c:
    local_b8 = 0x34cf8c8;
  }
  if ((*(int *)(local_b8 + 0x4a0) == 1) || (iVar11 = adjacent_3b3410(1), iVar11 == 0)) {
    uVar18 = local_c0;
    uVar12 = (uint)local_c0;
    if (0xffffff7f < uVar12 - 0x81) {
      local_f8 = param_2;
      if (uVar12 < 2) {
        local_108 = &local_70;
        puVar26 = &local_6c;
        puVar17 = (undefined4 *)auStack_120;
      }
      else {
        uVar27 = (ulong)(uVar12 * 4 + 0xf & 0xfffffff0);
        puVar26 = (undefined4 *)((ulong)(auStack_120 + -uVar27) & 0xffffffffffffffe0);
        puVar17 = (undefined4 *)((long)puVar26 - uVar27 & 0xffffffffffffffe0);
        *(undefined8 *)(puVar17 + -2) = 0x3b1814;
        local_108 = puVar17;
        func_0x00258ff0(puVar17,uVar12 * 4);
      }
      uVar15 = *in_GS_OFFSET;
      lVar23 = (uVar18 & 0xffffffff) * 4;
      *(undefined8 *)(puVar17 + -2) = 0x3b184a;
      func_0x00c1a3e0(uVar15,"copyin",0);
      psVar20 = local_f8;
      *(undefined8 *)(puVar17 + -2) = 0x3b1859;
      iVar11 = func_0x00259280(psVar20,puVar26,lVar23);
      if (iVar11 == 0) {
        local_100 = puVar26;
        local_e8 = uVar18 & 0xffffffff;
        *(undefined8 *)(puVar17 + -2) = 0x3b188e;
        iVar11 = func_0x00b078d0();
        uVar18 = local_e8;
        if (iVar11 == 0) {
          local_c8 = 0;
        }
        else {
          lVar14 = local_e8 * 0x18;
          *(undefined8 *)(puVar17 + -2) = 0x3b18b3;
          local_c8 = func_0x00c08b50(lVar14,0x1a7d800,0x102);
        }
        uVar27 = 0;
        uVar12 = 0;
        local_ec = 0;
        puVar21 = local_100;
        puVar26 = local_108;
        local_98 = lVar23;
        do {
          while( true ) {
            uVar15 = local_68;
            uVar3 = puVar21[uVar27];
            uVar24 = (int)uVar3 >> 0x10;
            uVar16 = uVar3 & 0xffff;
            if (uVar16 != 0 && uVar24 < 0x80) break;
            puVar26[uVar27] = 0x80020003;
LAB_003b1939:
            uVar15 = local_68;
            uVar27 = uVar27 + 1;
            if (uVar27 == uVar18) {
              if (local_ec != 0) {
                *(undefined8 *)(puVar17 + -2) = 0x3b1da8;
                func_0x00399eb0(uVar15);
              }
              goto LAB_003b1da8;
            }
          }
          local_e0 = CONCAT44(local_e0._4_4_,uVar3) & 0xffffffff0000ffff;
          if (uVar16 == uVar12) {
LAB_003b19b2:
            uVar15 = local_68;
            if ((int)uVar24 < (int)*local_f8) {
              *(undefined8 *)(puVar17 + -2) = 0x3b19ca;
              iVar11 = func_0x00399e20(uVar15);
              if (iVar11 != 0) {
                puVar26[uVar27] = 0x80020001;
                uVar15 = 0x1236;
                uVar22 = 1;
                goto LAB_003b1a25;
              }
              lVar23 = *(long *)(*(long *)(local_f8 + 0x14) + (ulong)uVar24 * 8);
              if ((1 < *local_f8) && (lVar23 == 0)) {
                uVar15 = 0x123f;
                puVar26 = local_108;
                goto LAB_003b1a13;
              }
              local_d0 = CONCAT71(local_d0._1_7_,local_c8 != 0);
              *(undefined8 *)(puVar17 + -2) = 0x3b1ad9;
              iVar11 = func_0x00b078d0();
              if ((iVar11 != 0 & (byte)local_d0) == 1) {
                *(undefined4 *)(local_c8 + uVar27 * 0x18) = local_100[uVar27];
                *(undefined8 *)(local_c8 + 8 + uVar27 * 0x18) = **(undefined8 **)(lVar23 + 0x18);
                *(ulong *)(local_c8 + 0x10 + uVar27 * 0x18) =
                     (long)*(ulong *)(lVar23 + 0x10) >> 4 ^ *(ulong *)(lVar23 + 0x10);
              }
              puVar25 = *(uint **)(lVar23 + 0x20);
              if ((0xffff < uVar3) && (1 < *puVar25)) {
                *(undefined8 *)(puVar17 + -2) = 0x3b1b48;
                func_0x0025d410("[0]%s() line=%d Warning !! aio_id_idx is not 0 %d\n",
                                "_aio_multi_cancel",0x1250,uVar24);
              }
              local_b0 = puVar25 + 8;
              *(undefined8 *)(puVar17 + -2) = 0;
              *(undefined8 *)(puVar17 + -4) = 0;
              *(undefined8 *)(puVar17 + -6) = 0x3b1b68;
              func_0x00bf1770(puVar25 + 8,0x80000,0,0,0,0);
              puVar10 = local_b0;
              puVar26 = local_108;
              uVar12 = puVar25[2];
              if (uVar12 - 3 < 2) {
                local_108[uVar27] = uVar12;
                *(undefined8 *)(puVar17 + -2) = 0;
                *(undefined8 *)(puVar17 + -4) = 0;
                *(undefined8 *)(puVar17 + -6) = 0x3b1b9c;
                func_0x00bf1770(puVar10,0x100000,0,0,0,0);
                uVar18 = local_e8;
                puVar21 = local_100;
                uVar12 = (uint)local_e0;
                goto LAB_003b1939;
              }
              uVar3 = *puVar25;
              local_108[uVar27] = uVar12;
              if (*puVar25 != 0) {
                uVar12 = 0;
                local_a0 = puVar25;
                if (1 < (int)uVar3) {
                  uVar24 = uVar12;
                }
                do {
                  lVar14 = local_b8;
                  local_d0 = CONCAT44(local_d0._4_4_,uVar12);
                  lVar23 = *(long *)(*(long *)(local_f8 + 0x14) + (long)(int)uVar24 * 8);
                  if ((lVar23 != 0) && (*(int *)(lVar23 + 0x38) == 1)) {
                    uVar4 = *(undefined4 *)(local_f8 + 2);
                    *(undefined8 *)(puVar17 + -2) = 0x3b1c3f;
                    iVar11 = func_0x003b4190(lVar23,uVar4,1,lVar14);
                    if (iVar11 == 0) {
                      if (*(long *)(*(long *)(lVar23 + 0x10) + 0x18) != 0) {
                        local_80 = 0xffffffff80020055;
                        local_78 = (ulong)*(uint *)(lVar23 + 0x38);
                        uVar15 = *(undefined8 *)(*(long *)(lVar23 + 0x10) + 0x18);
                        uVar22 = *in_GS_OFFSET;
                        *(undefined8 *)(puVar17 + -2) = 0x3b1c8b;
                        func_0x00c1a3e0(uVar22,"copyout",0);
                        *(undefined8 *)(puVar17 + -2) = 0x3b1c9f;
                        func_0x002591d0(&local_80,uVar15,0x10);
                      }
                      if (local_a0[1] == 0) {
                        *(undefined1 *)((long)local_a0 + 0xd) = 1;
                      }
                      else {
                        uVar12 = local_a0[1] - 1;
                        local_a0[1] = uVar12;
                        *(undefined1 *)((long)local_a0 + 0xd) = 1;
                        if (uVar12 != 0) {
                          local_108[uVar27] = 2;
                          goto LAB_003b1bf0;
                        }
                      }
                      local_a0[2] = *(uint *)(lVar23 + 0x38);
                      puVar28 = *(undefined8 **)(local_a0 + 0x14);
                      if (puVar28 != (undefined8 *)0x0) {
                        local_d4 = 0;
                        do {
                          *(undefined4 *)(puVar28 + 4) = *(undefined4 *)(lVar23 + 0x38);
                          lVar14 = puVar28[2];
                          *(undefined8 *)(puVar17 + -2) = 0x3b1d2d;
                          func_0x004c6a00(lVar14 + 0x18,0,0,0);
                          *(int *)*puVar28 = *(int *)*puVar28 + -1;
                          piVar19 = (int *)*puVar28;
                          if (*piVar19 < 1) {
                            piVar5 = (int *)puVar28[1];
                            if (piVar5 != (int *)0x0) {
                              *piVar5 = *piVar5 + -1;
                              if ((local_d4 != 0) && (local_d4 = 1, *(int *)puVar28[1] != 0))
                              goto LAB_003b1cf0;
                              piVar19 = (int *)*puVar28;
                              local_d4 = 1;
                            }
                            *(undefined8 *)(puVar17 + -2) = 0x3b1cf0;
                            func_0x00c06910(piVar19);
                          }
LAB_003b1cf0:
                          lVar14 = puVar28[2];
                          *(undefined8 *)(puVar17 + -2) = 0x3b1d03;
                          func_0x004c6fa0(lVar14 + 0x18,0,0);
                          puVar28 = (undefined8 *)puVar28[6];
                        } while (puVar28 != (undefined8 *)0x0);
                      }
                    }
                  }
LAB_003b1bf0:
                  uVar12 = (int)local_d0 + 1;
                  puVar25 = local_a0;
                  uVar24 = uVar24 + 1;
                } while (uVar12 < *local_a0);
              }
              puVar10 = local_b0;
              puVar26 = local_108;
              if (*(char *)((long)puVar25 + 0xd) != '\0') {
                local_108[uVar27] = 4;
              }
              *(undefined8 *)(puVar17 + -2) = 0;
              *(undefined8 *)(puVar17 + -4) = 0;
              *(undefined8 *)(puVar17 + -6) = 0x3b1d8d;
              func_0x00bf1770(puVar10,0x100000,0,0,0,0);
            }
            else {
              uVar15 = 0x1230;
LAB_003b1a13:
              puVar26[uVar27] = 0x80020003;
              uVar22 = 3;
LAB_003b1a25:
              *(undefined8 *)(puVar17 + -2) = 0x3b1a2c;
              func_0x0025d410("[0]%s() line=%d i=%d err=0x%x\n","_aio_multi_cancel",uVar15,
                              uVar27 & 0xffffffff,uVar22);
            }
            uVar18 = local_e8;
            puVar21 = local_100;
            uVar12 = (uint)local_e0;
            goto LAB_003b1939;
          }
          if (local_ec != 0) {
            *(undefined8 *)(puVar17 + -2) = 0x3b1983;
            func_0x00399eb0(uVar15);
            uVar16 = (uint)local_e0;
          }
          uVar15 = local_88;
          *(undefined8 *)(puVar17 + -2) = 0x3b199e;
          local_f8 = (short *)func_0x00399ee0(uVar15,uVar16,0x160,&local_68);
          if (local_f8 != (short *)0x0) {
            local_ec = 1;
            goto LAB_003b19b2;
          }
          puVar26[uVar27] = 0x80020003;
          local_f8 = (short *)0x0;
          *(undefined8 *)(puVar17 + -2) = 0x3b1a70;
          func_0x0025d410("[0]%s() line=%d i=%d err=0x%x\n","_aio_multi_cancel",0x1222,
                          uVar27 & 0xffffffff,3);
          uVar27 = uVar27 + 1;
          uVar12 = 0;
          local_ec = 0;
          uVar18 = local_e8;
          puVar21 = local_100;
        } while (uVar27 != local_e8);
LAB_003b1da8:
        lVar23 = local_c8;
        bVar29 = local_c8 != 0;
        *(undefined8 *)(puVar17 + -2) = 0x3b1db8;
        iVar11 = func_0x00b078d0();
        lVar14 = local_a8;
        uVar18 = local_c0;
        if (iVar11 != 0 && bVar29) {
          *(undefined8 *)(puVar17 + -2) = 0x3b1dd4;
          func_0x000a3ca0(lVar14,uVar18,lVar23);
          *(undefined8 *)(puVar17 + -2) = 0x3b1de3;
          func_0x00c08df0(lVar23,0x1a7d800);
        }
        local_e0 = local_b8 + 0xd8;
        local_d0 = local_b8 + 0x80;
        uVar18 = 3;
        lVar23 = local_b8;
        do {
          psVar20 = (short *)(uVar18 * 0x20 + local_e0);
          local_f8 = psVar20;
          *(undefined8 *)(puVar17 + -2) = 0x3b1e56;
          func_0x004c6a00(psVar20,0,0,0);
          if ((*(int *)(lVar23 + 0x160 + uVar18 * 4) != 0) &&
             (*(int *)(lVar23 + 0x1c0 + uVar18 * 4) != 0)) {
            lVar14 = uVar18 * 0x10;
            plVar2 = (long *)(local_d0 + lVar14);
LAB_003b1ea7:
            do {
              lVar7 = *plVar2;
              if (lVar7 == 0) break;
              lVar8 = *(long *)(lVar7 + 0x48);
              lVar1 = lVar7 + 0x48;
              if (lVar8 == 0) {
                if (**(long **)(lVar7 + 0x50) != lVar7) goto LAB_003b1fd0;
                plVar2[1] = (long)*(long **)(lVar7 + 0x50);
              }
              else {
                if (*(long *)(lVar8 + 0x50) != lVar1) {
                  *(undefined8 *)(puVar17 + -2) = 0x3b2015;
                  func_0x007f1950();
                  lVar23 = *(long *)(lVar7 + 0x48);
                  uVar15 = *(undefined8 *)(lVar23 + 0x50);
                  *(undefined8 *)(puVar17 + -2) = 0x3b202f;
                  func_0x007f2180(0x3b200d,lVar7,lVar23,uVar15,lVar1);
                  lVar23 = *(long *)(lVar7 + 0x48);
                  uVar15 = *(undefined8 *)(lVar23 + 0x50);
                  *(undefined8 *)(puVar17 + -2) = 0x3b2050;
                  func_0x00c9aa10(0x47,
                                  "Bad link in \"nlist\", elm != next->prev, elm=%p next=%p next->prev=%p &elm->next=%p"
                                  ,lVar7,lVar23,uVar15,lVar1);
                    /* WARNING: Does not return */
                  pcVar9 = (code *)invalidInstructionException();
                  (*pcVar9)();
                }
                if (**(long **)(lVar7 + 0x50) != lVar7) {
LAB_003b1fd0:
                  *(undefined8 *)(puVar17 + -2) = 0x3b1fd8;
                  func_0x007f1950();
                  puVar28 = *(undefined8 **)(lVar7 + 0x50);
                  uVar15 = *puVar28;
                  *(undefined8 *)(puVar17 + -2) = 0x3b1fee;
                  func_0x007f20c0(0x3b1fd0,lVar7,puVar28,uVar15);
                  puVar28 = *(undefined8 **)(lVar7 + 0x50);
                  uVar15 = *puVar28;
                  *(undefined8 *)(puVar17 + -2) = 0x3b200b;
                  func_0x00c9aa10(0x4b,
                                  "Bad link in \"nlist\", elm != prev->next, elm=%p prev=%p prev->next=%p"
                                  ,lVar7,puVar28,uVar15);
                    /* WARNING: Does not return */
                  pcVar9 = (code *)invalidInstructionException();
                  (*pcVar9)();
                }
                *(long **)(lVar8 + 0x50) = *(long **)(lVar7 + 0x50);
              }
              **(undefined8 **)(lVar7 + 0x50) = *(undefined8 *)(lVar7 + 0x48);
              iVar11 = *(int *)(lVar23 + 0x1d0 + uVar18 * 4);
              *(int *)(lVar23 + 0x1d0 + uVar18 * 4) = iVar11 + 1;
              *(int *)(lVar7 + 4) = iVar11;
              if (*(long *)(lVar7 + 8) == 0) {
                *(undefined8 *)(lVar7 + 0x48) = 0;
                plVar6 = *(long **)(lVar23 + 0x48 + lVar14);
                *(long **)(lVar7 + 0x50) = plVar6;
                *plVar6 = lVar7;
                *(long *)(lVar23 + 0x48 + lVar14) = lVar1;
                piVar19 = (int *)(lVar23 + 0x160 + uVar18 * 4);
                *piVar19 = *piVar19 + -1;
                if (*piVar19 == 0) break;
                goto LAB_003b1ea7;
              }
              *(undefined8 *)(puVar17 + -2) = 0x3b1f2a;
              func_0x003b4440();
              piVar19 = (int *)(local_b8 + 0x160 + uVar18 * 4);
              *piVar19 = *piVar19 + -1;
              lVar23 = local_b8;
            } while (*piVar19 != 0);
          }
          psVar20 = local_f8;
          *(undefined4 *)(lVar23 + 0x160 + uVar18 * 4) = 0;
          *(undefined8 *)(puVar17 + -2) = 0x3b1e2e;
          func_0x004c6fa0(psVar20,0,0);
          bVar29 = 1 < uVar18;
          uVar18 = uVar18 - 1;
        } while (bVar29);
        uVar15 = *in_GS_OFFSET;
        *(undefined8 *)(puVar17 + -2) = 0x3b1f58;
        func_0x00c1a3e0(uVar15,"copyout",0);
        uVar15 = local_90;
        lVar23 = local_98;
        puVar26 = local_108;
        *(undefined8 *)(puVar17 + -2) = 0x3b1f72;
        iVar11 = func_0x002591d0(puVar26,uVar15,lVar23);
        *(undefined8 *)(puVar17 + -2) = 0x3b1f7a;
        iVar13 = func_0x00b078d0();
        lVar23 = local_a8;
        uVar18 = local_c0;
        if (iVar13 != 0) {
          *(undefined8 *)(puVar17 + -2) = 0x3b1f8e;
          func_0x000a3d30(lVar23,uVar18,puVar26);
        }
      }
      else {
        *(undefined8 *)(puVar17 + -2) = 0x3b187c;
        func_0x0025d410("%s:%d err=%d\n","_aio_multi_cancel",0x1203,iVar11);
      }
      goto LAB_003b1f95;
    }
    iVar11 = 0x16;
    uVar15 = 0x11f4;
  }
  else {
    uVar15 = 0x11ec;
  }
  func_0x0025d410("%s:%d err=%d\n","_aio_multi_cancel",uVar15,iVar11);
LAB_003b1f95:
  if (_DAT_0391c310 != local_60) {
    *(undefined8 *)((long)puVar17 + -8) = 0x3b2057;
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar9 = (code *)invalidInstructionException();
    (*pcVar9)();
  }
  return iVar11;
}



/* adjacent_3b2060 | RVA 0x3b2060 | local helper / adjacent context (reachability below)
 * Evidence ev_b1bd52ad07296e7950ec17145e6c32e839d47da28f744813fcc7e675784e6524
 * Body [{"start": "0x3b2060", "end": "0x3b207c"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted.", "Ghidra Listing reports a terminal call at 0x3b2078 to 0x3b2080 adjacent_3b2080 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

void adjacent_3b2060(undefined8 param_1,undefined4 *param_2)

{
  adjacent_3b2080(param_1,*param_2,*(undefined8 *)(param_2 + 2),param_2[4],param_2[6],
                  *(undefined8 *)(param_2 + 8));
  return;
}



/* adjacent_3b2080 | RVA 0x3b2080 | local helper / adjacent context (reachability below)
 * Evidence ev_738e06136341ecab4c7fb5594069cea83215183a710a88071e760e821b21e166
 * Body [{"start": "0x3b2080", "end": "0x3b281d"}, {"start": "0x3b2820", "end": "0x3b28c2"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int adjacent_3b2080(long param_1,uint param_2,undefined8 param_3,ulong param_4,ulong param_5,
                   undefined8 param_6)

{
  int *piVar1;
  long lVar2;
  code *pcVar3;
  undefined8 uVar4;
  ulong uVar5;
  undefined2 uVar6;
  int iVar7;
  undefined4 uVar8;
  int iVar9;
  long lVar10;
  undefined8 *puVar11;
  undefined2 *puVar12;
  undefined8 *puVar13;
  undefined4 *puVar14;
  ulong uVar15;
  undefined8 uVar16;
  uint uVar17;
  uint *puVar18;
  uint *puVar19;
  uint uVar20;
  long lVar21;
  ulong uVar22;
  long *in_GS_OFFSET;
  undefined1 auStack_e0 [12];
  uint local_d4;
  ulong local_d0;
  uint local_c4;
  ulong local_c0;
  ulong local_b8;
  undefined8 local_b0;
  ulong local_a8;
  long local_a0;
  undefined2 *local_98;
  long local_90;
  undefined8 *local_88;
  long local_80;
  undefined8 local_78;
  uint local_70;
  undefined4 uStack_6c;
  uint local_64;
  long local_60;
  
  local_60 = _DAT_0391c310;
  lVar21 = *(long *)(param_1 + 8);
  local_b0 = *(undefined8 *)(lVar21 + 0xc48);
  local_d0 = param_4;
  local_a8 = param_5;
  local_80 = param_1;
  local_78 = param_6;
  lVar10 = func_0x009f8180(lVar21);
  iVar7 = func_0x009f81c0(lVar21,&local_70);
  if ((iVar7 == 0) && (local_70 < 0x1000000)) {
    if (local_70 < 0x10000) {
      if (_DAT_034cf7c8 == lVar10) {
        lVar21 = 0x34cf320;
      }
      else if (_DAT_034d08c0 == lVar10) {
        lVar21 = 0x34d0418;
      }
      else {
        lVar21 = 0x34d0418;
        if (_DAT_034cf7c0 == 0) {
          lVar21 = 0x34cf320;
        }
      }
    }
    else {
      if ((local_70 & 0xff0000) != 0x10000) goto LAB_003b2116;
      lVar21 = 0x34cfe70;
    }
  }
  else {
LAB_003b2116:
    lVar21 = 0x34cf8c8;
  }
  iVar7 = 0x16;
  puVar18 = (uint *)auStack_e0;
  if (1 < (param_2 & 0xfff) - 1) goto LAB_003b22e7;
  if ((*(int *)(lVar21 + 0x4a0) == 1) || (iVar7 = adjacent_3b3410(1,lVar21), iVar7 == 0)) {
    iVar7 = (int)local_d0;
    local_90 = lVar21;
    if (iVar7 - 0x81U < 0xffffff80) {
      uVar16 = 0xdbd;
    }
    else {
      if ((int)local_a8 - 1U < 3) {
        local_b8 = (ulong)(param_2 & 0xfff);
        local_64 = func_0x003998e0(local_b0,&local_70);
        if (local_64 != 0xffffffff) {
          iVar7 = iVar7 * 0x28;
          local_c4 = local_64;
          lVar21 = func_0x00c08b50(iVar7,0x1ab5890,0x102);
          func_0x00c1a3e0(*in_GS_OFFSET,"copyin",0);
          iVar7 = func_0x00259280(param_3,lVar21,iVar7);
          uVar22 = local_d0;
          if (iVar7 == 0) {
            local_d4 = param_2 & 0x1000;
            local_a0 = lVar21;
            if ((param_2 & 0x1000) == 0) {
              puVar11 = (undefined8 *)func_0x00c08b50(0x58,0x1ab5970,0x102);
              *(int *)puVar11 = (int)local_d0;
              *(int *)((long)puVar11 + 4) = (int)local_d0;
              *(undefined4 *)(puVar11 + 1) = 1;
              puVar11[10] = 0;
              func_0x00bf1690(puVar11 + 4,0,"AIO req hd lock",0,1);
              uVar17 = local_c4;
            }
            else {
              puVar11 = (undefined8 *)func_0x00c08b50((int)local_d0 * 0x58,0x1ab5970,0x102);
              puVar13 = puVar11;
              do {
                *puVar13 = 0x100000001;
                *(undefined4 *)(puVar13 + 1) = 1;
                puVar13[10] = 0;
                func_0x00bf1690(puVar13 + 4,0,"AIO req hd lock",0,1);
                puVar13 = puVar13 + 0xb;
                uVar20 = (int)uVar22 - 1;
                uVar22 = (ulong)uVar20;
                uVar17 = local_64;
              } while (uVar20 != 0);
            }
            puVar12 = (undefined2 *)func_0x00c08b50(0x30,0x1ab5a50,0x102);
            local_c0 = local_d0 & 0xffffffff;
            uVar16 = func_0x00c08b50(local_c0 * 8,0x1ab5a50,0x102);
            lVar21 = local_a0;
            uVar22 = local_a8;
            *(undefined8 *)(puVar12 + 0x14) = uVar16;
            *(undefined8 **)(puVar12 + 8) = puVar11;
            *(uint *)(puVar12 + 4) = uVar17;
            if (local_d4 == 0) {
              puVar11[3] = uVar16;
              uVar6 = 1;
            }
            else {
              uVar6 = (undefined2)local_d0;
            }
            puVar12[1] = uVar6;
            *puVar12 = uVar6;
            *(int *)(puVar12 + 2) = (int)local_a8;
            *(long *)(puVar12 + 0x10) = local_a0;
            *(long *)(puVar12 + 0xc) = local_90;
            local_c4 = uVar17;
            local_98 = puVar12;
            iVar7 = func_0x00b078d0();
            if (iVar7 != 0) {
              func_0x000a36d0(local_d0,param_2,lVar21,local_80,uVar22 & 0xffffffff);
            }
            puVar13 = (undefined8 *)func_0x00c08b50(0x30,0x1ab59e0,0x102);
            lVar10 = *in_GS_OFFSET;
            *puVar13 = *(undefined8 *)(lVar10 + 0x390);
            puVar13[1] = *(undefined8 *)(lVar10 + 8);
            uVar16 = func_0x002ab3a0(*(undefined8 *)(lVar10 + 0x140));
            puVar12 = local_98;
            puVar13[2] = uVar16;
            puVar13[5] = local_98;
            uVar8 = func_0x005f0f50();
            *(undefined4 *)(puVar13 + 4) = uVar8;
            local_88 = puVar13;
            if (local_d4 == 0) {
              uVar22 = 0;
              puVar11[2] = puVar12;
              do {
                puVar14 = (undefined4 *)func_0x00c08b50(0x58,0x1ab5900,0x102);
                lVar10 = *(long *)(puVar12 + 0x14);
                *puVar14 = (int)local_b8;
                *(long *)(puVar14 + 4) = lVar21;
                *(undefined8 **)(puVar14 + 6) = local_88;
                *(undefined8 **)(puVar14 + 8) = puVar11;
                *(undefined4 **)(lVar10 + uVar22 * 8) = puVar14;
                uVar22 = uVar22 + 1;
                lVar21 = lVar21 + 0x28;
              } while (local_c0 != uVar22);
            }
            else {
              uVar22 = 0;
              do {
                puVar14 = (undefined4 *)func_0x00c08b50(0x58,0x1ab5900,0x102);
                lVar10 = *(long *)(puVar12 + 0x14);
                puVar11[2] = puVar12;
                *puVar14 = (int)local_b8;
                *(long *)(puVar14 + 4) = lVar21;
                *(undefined8 **)(puVar14 + 6) = local_88;
                *(undefined8 **)(puVar14 + 8) = puVar11;
                *(undefined4 **)(lVar10 + uVar22 * 8) = puVar14;
                uVar22 = uVar22 + 1;
                puVar11 = puVar11 + 0xb;
                lVar21 = lVar21 + 0x28;
              } while (local_c0 != uVar22);
            }
            uVar22 = local_c0;
            func_0x00399de0(CONCAT44(uStack_6c,local_70),0x160,puVar12,0);
            func_0x00399eb0(CONCAT44(uStack_6c,local_70));
            uVar16 = local_78;
            if (local_d4 == 0) {
              lVar21 = 4;
              puVar18 = (uint *)auStack_e0;
              puVar19 = &local_64;
            }
            else {
              lVar21 = uVar22 * 4;
              puVar18 = (uint *)((ulong)(auStack_e0 + -(uVar22 * 4 + 0xf & 0xfffffffffffffff0)) &
                                0xffffffffffffffe0);
              uVar15 = 0;
              uVar17 = 0;
              do {
                puVar18[uVar15] = uVar17 | local_c4;
                uVar15 = uVar15 + 1;
                puVar19 = puVar18;
                uVar17 = uVar17 + 0x10000;
              } while (uVar22 != uVar15);
            }
            puVar18[-2] = 0x3b265f;
            puVar18[-1] = 0;
            iVar7 = func_0x003b3a40(puVar19,uVar16,lVar21);
            lVar21 = local_90;
            uVar5 = local_a8;
            uVar15 = local_b8;
            uVar22 = local_d0;
            if (iVar7 == 0) {
              puVar18[-2] = 0x3b2696;
              puVar18[-1] = 0;
              iVar7 = func_0x003b3a90(uVar22,uVar5,uVar15,puVar12,lVar21);
              if (iVar7 == 0) {
                puVar18[-2] = 0x3b285b;
                puVar18[-1] = 0;
                func_0x004c6a00(0x34cf2e8,0,0,0);
                if ((*(long *)(lVar21 + 0x4b0) != 0) || (*(long *)(lVar21 + 0x528) != 0)) {
                  puVar18[-2] = 0x3b287f;
                  puVar18[-1] = 0;
                  func_0x0073ef80(0x34cf2f0);
                }
                iVar7 = 0;
                puVar18[-2] = 0x3b2894;
                puVar18[-1] = 0;
                func_0x004c6fa0(0x34cf2e8,0,0,0);
                puVar18[-2] = 0x3b2899;
                puVar18[-1] = 0;
                iVar9 = func_0x00b078d0();
                lVar21 = local_80;
                uVar22 = local_d0;
                if (iVar9 != 0) {
                  uVar17 = local_d4 >> 0xc;
                  puVar18[-2] = 0x3b28b7;
                  puVar18[-1] = 0;
                  func_0x000a3850(uVar22,uVar17,lVar21,uVar16);
                }
                goto LAB_003b22e7;
              }
              uVar16 = 0xe21;
            }
            else {
              uVar16 = 0xe1a;
            }
            puVar18[-2] = 0x3b26be;
            puVar18[-1] = 0;
            func_0x0025d410("%s:%d err=%d\n","_aio_submit_cmd",uVar16,iVar7);
            uVar17 = local_64;
            uVar4 = local_b0;
            puVar18[-2] = 0x3b26d6;
            puVar18[-1] = 0;
            lVar21 = func_0x0039a2a0(uVar4,uVar17,0x160,&local_70);
            uVar17 = local_64;
            uVar16 = CONCAT44(uStack_6c,local_70);
            puVar18[-2] = 0x3b26e8;
            puVar18[-1] = 0;
            func_0x00399e30(uVar4,uVar17,uVar16);
            puVar18[-2] = 0x3b26f1;
            puVar18[-1] = 0;
            func_0x00399eb0(CONCAT44(uStack_6c,local_70));
            if (local_d4 == 0) {
              lVar10 = *(long *)(**(long **)(lVar21 + 0x28) + 0x20);
              puVar18[-2] = 0x3b270f;
              puVar18[-1] = 0;
              func_0x00bf1760(lVar10 + 0x20);
            }
            else {
              uVar22 = 0;
              do {
                lVar10 = *(long *)(*(long *)(lVar21 + 0x28) + uVar22 * 8);
                if (lVar10 != 0) {
                  lVar10 = *(long *)(lVar10 + 0x20);
                  puVar18[-2] = 0x3b2847;
                  puVar18[-1] = 0;
                  func_0x00bf1760(lVar10 + 0x20);
                }
                uVar22 = uVar22 + 1;
              } while (local_c0 != uVar22);
            }
            uVar16 = *(undefined8 *)(*(long *)(**(long **)(lVar21 + 0x28) + 0x18) + 0x10);
            puVar18[-2] = 0x3b2723;
            puVar18[-1] = 0;
            func_0x002a9670(uVar16);
            uVar16 = *(undefined8 *)(**(long **)(lVar21 + 0x28) + 0x18);
            puVar18[-2] = 0x3b273a;
            puVar18[-1] = 0;
            func_0x00c08df0(uVar16,0x1ab59e0);
            if (0 < (int)local_d0) {
              uVar22 = 0;
              do {
                lVar10 = *(long *)(*(long *)(lVar21 + 0x28) + uVar22 * 8);
                if (lVar10 != 0) {
                  if (*(long *)(lVar10 + 0x28) != 0) {
                    puVar18[-2] = 0x3b27a5;
                    puVar18[-1] = 0;
                    func_0x0025d410("[0]%s() line=%d Warning !! split info is here\n",
                                    "free_queue_entry",0xb35);
                  }
                  if (*(long *)(lVar10 + 0x40) != 0) {
                    LOCK();
                    piVar1 = (int *)(*(long *)(lVar10 + 0x40) + 0x28);
                    iVar9 = *piVar1;
                    *piVar1 = *piVar1 + -1;
                    UNLOCK();
                    if (iVar9 == 1) {
                      uVar16 = *(undefined8 *)(lVar10 + 0x40);
                      lVar2 = *in_GS_OFFSET;
                      puVar18[-2] = 0x3b27d1;
                      puVar18[-1] = 0;
                      func_0x0072b380(uVar16,lVar2);
                    }
                    *(undefined8 *)(lVar10 + 0x40) = 0;
                  }
                  puVar18[-2] = 0x3b2761;
                  puVar18[-1] = 0;
                  func_0x00c08df0(lVar10,0x1ab5900);
                  *(undefined8 *)(*(long *)(lVar21 + 0x28) + uVar22 * 8) = 0;
                }
                uVar22 = uVar22 + 1;
              } while (local_c0 != uVar22);
            }
            uVar16 = *(undefined8 *)(lVar21 + 0x10);
            puVar18[-2] = 0x3b27e6;
            puVar18[-1] = 0;
            func_0x00c08df0(uVar16,0x1ab5970);
            uVar16 = *(undefined8 *)(lVar21 + 0x28);
            puVar18[-2] = 0x3b27f9;
            puVar18[-1] = 0;
            func_0x00c08df0(uVar16,0x1ab5a50);
            puVar18[-2] = 0x3b2804;
            puVar18[-1] = 0;
            func_0x00c08df0(lVar21,0x1ab5a50);
            lVar21 = local_a0;
            puVar18[-2] = 0x3b2814;
            puVar18[-1] = 0;
            func_0x00c08df0(lVar21,0x1ab5890);
          }
          else {
            func_0x0025d410("%s:%d err=%d\n","setup_rwreqs",0xb13,iVar7);
            func_0x00c08df0(lVar21,0x1ab5890);
            func_0x0025d410("%s:%d err=%d\n","_aio_submit_cmd",0xdd6,iVar7);
            func_0x00399e30(local_b0,local_c4,CONCAT44(uStack_6c,local_70));
            func_0x00399eb0(CONCAT44(uStack_6c,local_70));
            puVar18 = (uint *)auStack_e0;
          }
          goto LAB_003b22e7;
        }
        iVar7 = 0x23;
        uVar16 = 0xdcf;
        goto LAB_003b22e0;
      }
      uVar16 = 0xdc7;
    }
    iVar7 = 0x16;
  }
  else {
    uVar16 = 0xdb7;
  }
LAB_003b22e0:
  func_0x0025d410("%s:%d err=%d\n","_aio_submit_cmd",uVar16,iVar7);
  puVar18 = (uint *)auStack_e0;
LAB_003b22e7:
  if (_DAT_0391c310 != local_60) {
    *(undefined8 *)((long)puVar18 + -8) = 0x3b28c1;
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar3 = (code *)invalidInstructionException();
    (*pcVar3)();
  }
  return iVar7;
}



/* adjacent_3b28d0 | RVA 0x3b28d0 | local helper / adjacent context (reachability below)
 * Evidence ev_2acd98848ad6938cdb05b098ec5056026c29aaf1e7e7af4f6a7ebc325a2fb2a0
 * Body [{"start": "0x3b28d0", "end": "0x3b2d4e"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int adjacent_3b28d0(long param_1,long *param_2)

{
  long lVar1;
  long lVar2;
  code *pcVar3;
  bool bVar4;
  long lVar5;
  long lVar6;
  int iVar7;
  int iVar8;
  long lVar9;
  long lVar10;
  undefined8 uVar11;
  uint local_74;
  uint local_70;
  int local_6c;
  int local_68;
  int local_64;
  uint local_60;
  uint local_5c;
  int local_58;
  int local_54;
  int local_50;
  uint local_4c;
  uint local_48;
  int local_44;
  int local_40;
  int local_3c;
  long local_38;
  
  local_38 = _DAT_0391c310;
  uVar11 = *(undefined8 *)(param_1 + 8);
  lVar5 = param_2[1];
  lVar1 = *param_2;
  lVar2 = param_2[2];
  lVar6 = param_2[3];
  lVar9 = func_0x009f8180(uVar11);
  iVar7 = func_0x009f81c0(uVar11,&local_74);
  lVar10 = 0x34cf8c8;
  if ((iVar7 == 0) && (local_74 < 0x1000000)) {
    if (local_74 < 0x10000) {
      bVar4 = true;
      if (_DAT_034cf7c8 == lVar9) {
        lVar10 = 0x34cf320;
      }
      else if (_DAT_034d08c0 == lVar9) {
        lVar10 = 0x34d0418;
      }
      else {
        lVar10 = 0x34d0418;
        if (_DAT_034cf7c0 == 0) {
          lVar10 = 0x34cf320;
        }
      }
    }
    else {
      lVar10 = 0x34cf8c8;
      bVar4 = true;
      if ((local_74 & 0xff0000) == 0x10000) {
        lVar10 = 0x34cfe70;
      }
    }
  }
  else {
    bVar4 = false;
  }
  if (lVar2 == 0) {
    if ((int)lVar6 == 0) {
      func_0x00c4bb20(0x34cf300,0,0,0);
      uVar11 = 1;
      if ((!bVar4 || lVar1 == 0) || (*(int *)(lVar10 + 0x4a0) != 0)) {
LAB_003b2a0a:
        func_0x00c4c4b0(0x34cf300,0,0);
        iVar8 = adjacent_3b3410(uVar11,lVar10);
        iVar7 = 0;
        if (iVar8 != 0) {
          func_0x0025d410("%s:%d err=%d\n","__aio_init",0x1383,iVar8);
          iVar7 = iVar8;
        }
        goto LAB_003b29ab;
      }
      if ((int)lVar5 == 0x3c) {
        iVar7 = func_0x003b3f10(lVar1,&local_74);
        if (iVar7 != 0) {
          func_0x0025d410("%s:%d err=%d\n","__aio_init",0x133a,iVar7);
          func_0x00c4c4b0(0x34cf300,0,0);
          goto LAB_003b29ab;
        }
        if (0x80 < local_74) goto LAB_003b2b23;
        if (0x80 < local_70) goto LAB_003b2b48;
        iVar7 = 0;
        iVar8 = 0;
        if (local_6c != 0) {
          if (local_6c == 1) {
            if (local_68 + 0xfeffffffU < 0xff000000) {
LAB_003b2b87:
              uVar11 = 0x1359;
            }
            else {
              iVar7 = local_68;
              iVar8 = local_64;
              if (0xfeffffff < local_64 + 0xfeffffffU) goto LAB_003b2bd4;
LAB_003b2bb7:
              uVar11 = 0x1361;
            }
          }
          else {
LAB_003b2d2b:
            uVar11 = 0x1352;
          }
          goto LAB_003b2af8;
        }
LAB_003b2bd4:
        *(int *)(lVar10 + 0x1b4) = iVar7;
        *(int *)(lVar10 + 0x194) = iVar8;
        *(int *)(lVar10 + 0x1a4) = local_6c;
        *(uint *)(lVar10 + 0x174) = local_74;
        *(uint *)(lVar10 + 0x184) = local_70;
        if (0x80 < local_60) {
LAB_003b2b23:
          uVar11 = 0x1343;
          goto LAB_003b2af8;
        }
        if (0x80 < local_5c) {
LAB_003b2b48:
          uVar11 = 0x134a;
          goto LAB_003b2af8;
        }
        iVar7 = 0;
        iVar8 = 0;
        if (local_58 != 0) {
          if (local_58 != 1) goto LAB_003b2d2b;
          if (local_54 + 0xfeffffffU < 0xff000000) goto LAB_003b2b87;
          iVar7 = local_54;
          iVar8 = local_50;
          if (local_50 + 0xfeffffffU < 0xff000000) goto LAB_003b2bb7;
        }
        *(int *)(lVar10 + 0x1b8) = iVar7;
        *(int *)(lVar10 + 0x198) = iVar8;
        *(int *)(lVar10 + 0x1a8) = local_58;
        *(uint *)(lVar10 + 0x178) = local_60;
        *(uint *)(lVar10 + 0x188) = local_5c;
        if (0x80 < local_4c) goto LAB_003b2b23;
        if (0x80 < local_48) goto LAB_003b2b48;
        iVar8 = 0;
        iVar7 = 0;
        if (local_44 != 0) {
          if (local_44 != 1) goto LAB_003b2d2b;
          if (local_40 + 0xfeffffffU < 0xff000000) goto LAB_003b2b87;
          iVar8 = local_40;
          iVar7 = local_3c;
          if (local_3c + 0xfeffffffU < 0xff000000) goto LAB_003b2bb7;
        }
        *(int *)(lVar10 + 0x1bc) = iVar8;
        *(int *)(lVar10 + 0x19c) = iVar7;
        *(int *)(lVar10 + 0x1ac) = local_44;
        *(uint *)(lVar10 + 0x17c) = local_4c;
        *(uint *)(lVar10 + 0x18c) = local_48;
        iVar7 = func_0x00b078d0();
        if (iVar7 != 0) {
          func_0x000a3e30(param_1,lVar10);
        }
        uVar11 = 0;
        if (*(int *)(lVar10 + 0x4a0) != 1) goto LAB_003b2a0a;
        iVar7 = 0;
      }
      else {
        uVar11 = 0x1331;
LAB_003b2af8:
        iVar7 = 0x16;
        func_0x0025d410("%s:%d err=%d\n","__aio_init",uVar11,0x16);
      }
      func_0x00c4c4b0(0x34cf300,0,0);
      goto LAB_003b29ab;
    }
    uVar11 = 0x1324;
  }
  else {
    uVar11 = 0x131f;
  }
  func_0x0025d410("%s:%d err=%d\n","__aio_init",uVar11,0x16);
  iVar7 = 0x16;
LAB_003b29ab:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar3 = (code *)invalidInstructionException();
    (*pcVar3)();
  }
  return iVar7;
}



/* adjacent_3b2d50 | RVA 0x3b2d50 | local helper / adjacent context (reachability below)
 * Evidence ev_8c983cbe00e4cf56cea7c1e037756c8b58014d824fc51748084aa7e6c4520f01
 * Body [{"start": "0x3b2d50", "end": "0x3b2f2c"}, {"start": "0x3b2f30", "end": "0x3b2f7c"}, {"start": "0x3b2f80", "end": "0x3b3080"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int adjacent_3b2d50(undefined8 param_1,undefined4 *param_2)

{
  short sVar1;
  undefined4 uVar2;
  uint uVar3;
  long lVar4;
  long lVar5;
  long lVar6;
  undefined4 *puVar7;
  code *pcVar8;
  int iVar9;
  long lVar10;
  short *psVar11;
  undefined8 uVar12;
  undefined8 uVar13;
  undefined8 *puVar14;
  long lVar15;
  long lVar16;
  int iVar17;
  undefined8 *in_GS_OFFSET;
  long local_50;
  undefined8 local_48;
  int local_3c;
  long local_38;
  
  local_38 = _DAT_0391c310;
  lVar4 = *(long *)(param_2 + 2);
  lVar5 = *(long *)(param_2 + 6);
  uVar2 = *param_2;
  uVar3 = param_2[4];
  local_3c = 0;
  if (lVar4 == 0 || lVar5 == 0) {
    iVar9 = 0xe;
    uVar13 = 0x14fe;
  }
  else {
    iVar9 = func_0x0053c260(uVar2,0x15,&local_50);
    if (iVar9 == 0) {
      iVar9 = func_0x005a8110(uVar2);
      if (iVar9 == -1) {
        uVar13 = 0x150d;
LAB_003b2e8b:
        iVar9 = 3;
        uVar12 = 3;
LAB_003b2e90:
        func_0x0025d410("%s:%d err=%d\n","_get_aio_debug_submit_info",uVar13,uVar12);
      }
      else {
        lVar6 = *(long *)(local_50 + 0xc48);
        if (lVar6 == 0) {
          uVar13 = 0x1515;
          goto LAB_003b2e8b;
        }
        if (((int)uVar3 < 1) || (*(int *)(lVar6 + 0x228) < (int)uVar3)) {
          iVar9 = 0x16;
          uVar13 = 0x151c;
          uVar12 = 0x16;
          goto LAB_003b2e90;
        }
        lVar10 = func_0x00c08b50((ulong)uVar3 << 4,0x1ab5ac0,0x102);
        if (0 < *(int *)(lVar6 + 0x220) << 7) {
          iVar9 = 0;
          iVar17 = 0;
          do {
            psVar11 = (short *)func_0x0039a0f0(lVar6,iVar17,0x160,&local_48);
            if (psVar11 != (short *)0x0) {
              sVar1 = *psVar11;
              if (0 < (long)sVar1) {
                puVar14 = *(undefined8 **)(psVar11 + 0x14);
                lVar15 = 0;
                do {
                  puVar7 = (undefined4 *)*puVar14;
                  if (puVar7 != (undefined4 *)0x0) {
                    if (iVar9 < (int)uVar3) {
                      lVar16 = (long)iVar9 * 0x10;
                      *(uint *)(lVar10 + lVar16) = *(uint *)(psVar11 + 4) | (uint)lVar15;
                      *(undefined4 *)(lVar10 + 4 + lVar16) = puVar7[0xe];
                      *(undefined4 *)(lVar10 + 8 + lVar16) = *(undefined4 *)(psVar11 + 2);
                      *(undefined4 *)(lVar10 + 0xc + lVar16) = *puVar7;
                    }
                    iVar9 = iVar9 + 1;
                    local_3c = iVar9;
                  }
                  lVar15 = lVar15 + 0x10000;
                  puVar14 = puVar14 + 1;
                } while ((long)sVar1 * 0x10000 != lVar15);
              }
              func_0x00399eb0(local_48);
            }
            iVar17 = iVar17 + 1;
          } while (iVar17 < *(int *)(lVar6 + 0x220) * 0x80);
        }
        func_0x00c1a3e0(*in_GS_OFFSET,"copyout",0);
        iVar9 = func_0x002591d0(&local_3c,lVar5,4);
        if (iVar9 == 0) {
          iVar9 = 0;
          if (local_3c <= (int)uVar3) {
            iVar17 = func_0x003b3a40(lVar10,lVar4,(long)local_3c << 4);
            if (iVar17 != 0) {
              func_0x0025d410("%s:%d err=%d\n","_get_aio_debug_submit_info",0x1562,iVar17);
              iVar9 = iVar17;
            }
          }
        }
        else {
          func_0x0025d410("%s:%d err=%d\n","_get_aio_debug_submit_info",0x1553,iVar9);
        }
        func_0x00c08df0(lVar10,0x1ab5ac0);
      }
      func_0x004c6a00(local_50 + 0x148,0,0,0);
      *(int *)(local_50 + 0x358) = *(int *)(local_50 + 0x358) + -1;
      if (((*(byte *)(local_50 + 0xb1) & 0x20) != 0) && (*(int *)(local_50 + 0x358) == 0)) {
        func_0x00c06910(local_50 + 0x358);
      }
      func_0x004c6fa0(local_50 + 0x148,0,0,0);
      goto LAB_003b2dec;
    }
    uVar13 = 0x1506;
  }
  func_0x0025d410("%s:%d err=%d\n","_get_aio_debug_submit_info",uVar13,iVar9);
LAB_003b2dec:
  if (_DAT_0391c310 == local_38) {
    return iVar9;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar8 = (code *)invalidInstructionException();
  (*pcVar8)();
}



/* adjacent_3b3090 | RVA 0x3b3090 | local helper / adjacent context (reachability below)
 * Evidence ev_7adc3cb0f847447a466208fb954bb78650ba99926076593d2edf03bd472c1735
 * Body [{"start": "0x3b3090", "end": "0x3b3409"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int adjacent_3b3090(undefined8 param_1,undefined4 *param_2)

{
  undefined4 uVar1;
  uint uVar2;
  uint uVar3;
  long lVar4;
  long lVar5;
  long lVar6;
  code *pcVar7;
  int iVar8;
  int iVar9;
  long lVar10;
  long lVar11;
  uint uVar12;
  undefined8 uVar13;
  undefined8 uVar14;
  long lVar15;
  long lVar16;
  long local_50;
  undefined8 local_48;
  int local_3c;
  long local_38;
  
  local_38 = _DAT_0391c310;
  lVar4 = *(long *)(param_2 + 4);
  lVar5 = *(long *)(param_2 + 8);
  uVar1 = *param_2;
  uVar2 = param_2[2];
  uVar3 = param_2[6];
  local_3c = 0;
  if (lVar4 == 0 || lVar5 == 0) {
    iVar8 = 0xe;
    uVar14 = 0x1466;
  }
  else {
    iVar8 = func_0x0053c260(uVar1,0x15,&local_50);
    if (iVar8 == 0) {
      iVar8 = func_0x005a8110(uVar1);
      if (iVar8 == -1) {
        uVar14 = 0x1475;
LAB_003b31f6:
        iVar8 = 3;
        uVar13 = 3;
LAB_003b31fb:
        func_0x0025d410("%s:%d err=%d\n","_get_aio_debug_request_info",uVar14,uVar13);
      }
      else {
        lVar6 = *(long *)(local_50 + 0xc48);
        if (lVar6 == 0) {
          uVar14 = 0x147d;
          goto LAB_003b31f6;
        }
        if (((int)uVar3 < 1) || (*(int *)(lVar6 + 0x228) < (int)uVar3)) {
          iVar8 = 0x16;
          uVar14 = 0x1484;
          uVar13 = 0x16;
          goto LAB_003b31fb;
        }
        uVar12 = (int)uVar2 >> 0x10;
        if (0x7f < uVar12) {
          uVar14 = 0x148d;
          goto LAB_003b31f6;
        }
        lVar10 = func_0x00c08b50((ulong)uVar3 * 0x18,0x1ab5ac0,0x102);
        if (0 < *(int *)(lVar6 + 0x220) << 7) {
          iVar8 = 0;
LAB_003b32c8:
          lVar11 = func_0x0039a0f0(lVar6,iVar8,0x160,&local_48);
          if (lVar11 == 0) goto LAB_003b32b3;
          if (uVar2 != (*(uint *)(lVar11 + 8) | uVar2 & 0xffff0000)) {
LAB_003b32aa:
            func_0x00399eb0(local_48);
            goto LAB_003b32b3;
          }
          lVar15 = *(long *)(*(long *)(lVar11 + 0x28) + (ulong)uVar12 * 8);
          if (lVar15 == 0) goto LAB_003b32aa;
          iVar8 = **(int **)(lVar15 + 0x20);
          if (iVar8 != 0) {
            local_3c = 0;
            do {
              if (local_3c < (int)uVar3) {
                lVar6 = *(long *)(lVar11 + 0x20);
                lVar16 = (long)local_3c;
                lVar15 = (long)(int)(uVar12 + local_3c);
                *(undefined4 *)(lVar10 + lVar16 * 0x18) =
                     *(undefined4 *)(lVar6 + 0x20 + lVar15 * 0x28);
                *(undefined8 *)(lVar10 + 8 + lVar16 * 0x18) =
                     *(undefined8 *)(lVar6 + 8 + lVar15 * 0x28);
                *(undefined8 *)(lVar10 + 0x10 + lVar16 * 0x18) =
                     *(undefined8 *)(lVar6 + lVar15 * 0x28);
              }
              local_3c = local_3c + 1;
            } while (iVar8 != local_3c);
          }
          func_0x00399eb0(local_48);
        }
LAB_003b3361:
        iVar8 = func_0x003b3a40(&local_3c,lVar5,4);
        if (iVar8 == 0) {
          iVar8 = 0;
          if (local_3c <= (int)uVar3) {
            iVar9 = func_0x003b3a40(lVar10,lVar4,(long)local_3c * 0x18);
            if (iVar9 != 0) {
              func_0x0025d410("%s:%d err=%d\n","_get_aio_debug_request_info",0x14e0,iVar9);
              iVar8 = iVar9;
            }
          }
        }
        else {
          func_0x0025d410("%s:%d err=%d\n","_get_aio_debug_request_info",0x14d1,iVar8);
        }
        func_0x00c08df0(lVar10,0x1ab5ac0);
      }
      func_0x004c6a00(local_50 + 0x148,0,0,0);
      *(int *)(local_50 + 0x358) = *(int *)(local_50 + 0x358) + -1;
      if (((*(byte *)(local_50 + 0xb1) & 0x20) != 0) && (*(int *)(local_50 + 0x358) == 0)) {
        func_0x00c06910(local_50 + 0x358);
      }
      func_0x004c6fa0(local_50 + 0x148,0,0,0);
      goto LAB_003b3131;
    }
    uVar14 = 0x146e;
  }
  func_0x0025d410("%s:%d err=%d\n","_get_aio_debug_request_info",uVar14,iVar8);
LAB_003b3131:
  if (_DAT_0391c310 == local_38) {
    return iVar8;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar7 = (code *)invalidInstructionException();
  (*pcVar7)();
LAB_003b32b3:
  iVar8 = iVar8 + 1;
  if (*(int *)(lVar6 + 0x220) * 0x80 <= iVar8) goto LAB_003b3361;
  goto LAB_003b32c8;
}



/* handler_658_tail_helper | RVA 0x8fb210 | local helper / adjacent context (reachability below)
 * Evidence ev_5d4518385db81b239411ef7993dd56468a80539cc287c1d4586fc1df1825fc94
 * Body [{"start": "0x8fb210", "end": "0x8fb424"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong handler_658_tail_helper(long param_1,undefined4 param_2)

{
  int *piVar1;
  int iVar2;
  long lVar3;
  long lVar4;
  code *pcVar5;
  long lVar6;
  uint uVar7;
  undefined8 uVar8;
  ulong uVar9;
  long lVar10;
  long *in_GS_OFFSET;
  long local_70;
  long local_68;
  long local_60;
  undefined4 local_58;
  long local_50;
  undefined1 local_48 [16];
  long local_38;
  
  local_38 = _DAT_0391c310;
  lVar3 = *in_GS_OFFSET;
  if ((*(byte *)(lVar3 + 0xef) & 1) != 0) {
    func_0x004440d0(param_2);
  }
  uVar8 = func_0x002bc220(0,local_48,0x200000000000100,0);
  uVar9 = func_0x0072b4c0(*(undefined8 *)(*(long *)(param_1 + 8) + 0x48),param_2,uVar8,&local_68,0);
  lVar6 = local_68;
  if ((int)uVar9 == 0) {
    if ((*(long *)(local_68 + 0x18) == 0) || (*(long *)(local_68 + 8) == _DAT_01a5d1a0)) {
      uVar9 = 0x16;
      LOCK();
      piVar1 = (int *)(local_68 + 0x28);
      iVar2 = *piVar1;
      *piVar1 = *piVar1 + -1;
      UNLOCK();
      if (iVar2 == 1) {
        func_0x0072b380(local_68,param_1);
        uVar9 = 0x16;
      }
    }
    else {
      lVar4 = *(long *)(local_68 + 0x18);
      uVar9 = func_0x006af4f0(lVar4,&local_70,0x1001);
      if ((int)uVar9 == 0) {
        lVar10 = local_70;
        if (((local_70 == 0) && (lVar10 = *(long *)(lVar4 + 0x18), lVar10 == 0)) ||
           (uVar8 = 0x200400, (*(byte *)(lVar10 + 0x90) & 0x80) == 0)) {
          uVar8 = 0x80400;
        }
        func_0x006afb50(lVar4,uVar8,"W:/Build/J03950001/sys/freebsd/sys/kern/vfs_syscalls.c",0xe3e);
        if ((*(byte *)(lVar3 + 0xef) & 1) != 0) {
          func_0x004449b0(lVar4);
        }
        if (*(long *)(lVar4 + 0xf8) != 0) {
          func_0x007d46a0(*(long *)(lVar4 + 0xf8) + 0x18,0,0);
          func_0x00462d80(*(undefined8 *)(lVar4 + 0xf8),0,0,0);
          func_0x007d4eb0(*(long *)(lVar4 + 0xf8) + 0x18,0,0);
        }
        local_68 = 0x1adbaf8;
        local_58 = 1;
        local_60 = lVar4;
        local_50 = param_1;
        uVar7 = func_0x0058d3a0(*(undefined8 *)(lVar4 + 8),&local_68);
        uVar9 = (ulong)uVar7;
        local_68 = 0x1adcdc8;
        local_58 = 0;
        local_60 = lVar4;
        func_0x0058ea90(*(undefined8 *)(lVar4 + 8),&local_68);
        func_0x006af5e0(local_70);
      }
      LOCK();
      piVar1 = (int *)(lVar6 + 0x28);
      iVar2 = *piVar1;
      *piVar1 = *piVar1 + -1;
      UNLOCK();
      if (iVar2 == 1) {
        uVar9 = uVar9 & 0xffffffff;
        func_0x0072b380(lVar6,param_1);
      }
    }
  }
  if (_DAT_0391c310 == local_38) {
    return uVar9;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar5 = (code *)invalidInstructionException();
  (*pcVar5)();
}



/* adjacent_8fb430 | RVA 0x8fb430 | local helper / adjacent context (reachability below)
 * Evidence ev_7fa59b572b7653d27af71363a5214f1a5dba7cd2697dd1c3b653f435ca9f98b7
 * Body [{"start": "0x8fb430", "end": "0x8fb43b"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted.", "Ghidra Listing reports a terminal call at 0x8fb437 to 0x8fb210 handler_658_tail_helper (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

void adjacent_8fb430(undefined8 param_1,undefined4 *param_2)

{
  handler_658_tail_helper(param_1,*param_2);
  return;
}



/* handler_658_body | RVA 0x8fb440 | local helper / adjacent context (reachability below)
 * Evidence ev_b3f59366a82e308c18d17f4abc615800f3af536e16230b3de3f8886510ca6c65
 * Body [{"start": "0x8fb440", "end": "0x8fb44b"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted.", "Ghidra Listing reports a terminal call at 0x8fb447 to 0x8fb210 handler_658_tail_helper (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

void handler_658_body(undefined8 param_1,undefined4 *param_2)

{
  handler_658_tail_helper(param_1,*param_2);
  return;
}



/* adjacent_8fb450 | RVA 0x8fb450 | local helper / adjacent context (reachability below)
 * Evidence ev_1f47b78acb4a99c103d491cbbc7f90e422d29b00afe97b1b5ba62dd864357ea1
 * Body [{"start": "0x8fb450", "end": "0x8fb46d"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted.", "Ghidra Listing reports a terminal call at 0x8fb469 to 0x8fb470 adjacent_8fb470 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

void adjacent_8fb450(undefined8 param_1,undefined8 *param_2)

{
  adjacent_8fb470(param_1,0xffffff9c,*param_2,0xffffff9c,param_2[1],0);
  return;
}



/* adjacent_8fb470 | RVA 0x8fb470 | local helper / adjacent context (reachability below)
 * Evidence ev_c69e1610b6b54d823ae1db624d992c653627cc9728711e14c3db217eeec46882
 * Body [{"start": "0x8fb470", "end": "0x8fb4c5"}, {"start": "0x8fb4d0", "end": "0x8fb650"}, {"start": "0x8fb660", "end": "0x8fb899"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong adjacent_8fb470(undefined8 param_1,undefined4 param_2,undefined8 param_3,undefined4 param_4,
                     undefined8 param_5,undefined4 param_6)

{
  code *pcVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  uint uVar5;
  int iVar6;
  undefined8 uVar7;
  ulong uVar8;
  undefined8 local_258;
  undefined8 local_250;
  long local_248;
  long local_240;
  undefined1 *local_238;
  long local_230;
  long local_228;
  undefined1 *local_220;
  undefined1 local_218 [16];
  undefined1 local_208 [32];
  undefined8 local_1e8;
  long local_1a8;
  long local_1a0;
  undefined1 local_180 [10];
  byte local_176;
  undefined1 local_120 [32];
  long local_100;
  long local_c0;
  long local_b8;
  undefined1 local_98 [96];
  long local_38;
  
  local_38 = _DAT_0391c310;
  local_258 = 0;
  while( true ) {
    func_0x00a9eac0(0);
    uVar7 = func_0x002bc220(0,local_218,0x200000004000400,0);
    func_0x005fa6e0(local_120,2,0x4001010,param_6,param_3,param_2,0,uVar7,param_1);
    uVar8 = func_0x005f8c20(local_120);
    lVar4 = local_c0;
    if ((int)uVar8 != 0) break;
    uVar8 = func_0x008f80f0(local_c0);
    uVar7 = func_0x002bc220(0,local_218,0x200040000000400,0);
    func_0x005fa6e0(local_208,3,uVar8 | 0x800102c,param_6,param_5,param_4,0,uVar7,param_1);
    if (*(int *)(local_c0 + 0x1d4) == 2) {
      local_176 = local_176 | 8;
    }
    uVar5 = func_0x005f8c20(local_208);
    lVar3 = local_1a0;
    lVar2 = local_1a8;
    if (uVar5 != 0) {
      if (uVar5 == 0x15) {
        uVar5 = (*(int *)(lVar4 + 0x1d4) == 2) + 0x15;
      }
      func_0x005fa780(local_120,0xffffffdf);
      func_0x0054a120(local_b8);
      func_0x0054a120(lVar4);
LAB_008fb85c:
      if (local_100 != 0) {
        func_0x0054a120();
      }
      uVar8 = 0;
      if (uVar5 != 0xffffffff) {
        uVar8 = (ulong)uVar5;
      }
      break;
    }
    iVar6 = func_0x006af4f0(lVar4,&local_258,2);
    if (iVar6 == 0) {
      if (lVar2 == 0) {
LAB_008fb734:
        if (lVar4 == lVar3) {
          uVar5 = 0x16;
          goto LAB_008fb7ed;
        }
        if (lVar4 == lVar2) {
          uVar5 = 0xffffffff;
          goto LAB_008fb7ed;
        }
        local_238 = local_98;
        local_220 = local_180;
        local_250 = 0x1adc048;
        local_248 = local_b8;
        local_240 = local_c0;
        local_230 = local_1a0;
        local_228 = local_1a8;
        uVar5 = func_0x0058d960(*(undefined8 *)(local_b8 + 8),&local_250);
        func_0x005fa780(local_120,0xffffffdf);
        func_0x005fa780(local_208,0xffffffdf);
      }
      else {
        if (*(int *)(lVar4 + 0x1d4) == 2) {
          uVar5 = 0x14;
          if (*(int *)(lVar2 + 0x1d4) == 2) goto LAB_008fb734;
        }
        else {
          uVar5 = 0x15;
          if (*(int *)(lVar2 + 0x1d4) != 2) goto LAB_008fb734;
        }
LAB_008fb7ed:
        func_0x005fa780(local_120,0xffffffdf);
        func_0x005fa780(local_208,0xffffffdf);
        if (lVar2 != 0) {
          func_0x0054a440(lVar2);
        }
        if (lVar3 == lVar2) {
          func_0x0054a120(lVar3);
        }
        else {
          func_0x0054a440();
        }
        func_0x0054a120(local_b8);
        func_0x0054a120(lVar4);
      }
      func_0x0054a120(local_1e8);
      func_0x006af5e0(local_258);
      goto LAB_008fb85c;
    }
    func_0x005fa780(local_120,0xffffffdf);
    func_0x005fa780(local_208,0xffffffdf);
    if (lVar2 != 0) {
      func_0x0054a440(lVar2);
    }
    if (lVar3 == lVar2) {
      func_0x0054a120(lVar3);
    }
    else {
      func_0x0054a440();
    }
    func_0x0054a120(local_b8);
    func_0x0054a120(lVar4);
    func_0x0054a120(local_1e8);
    if (local_100 != 0) {
      func_0x0054a120();
    }
    uVar8 = func_0x006af4f0(0,&local_258,0x1004);
    if ((int)uVar8 != 0) break;
  }
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar1 = (code *)invalidInstructionException();
    (*pcVar1)();
  }
  return uVar8;
}



/* adjacent_8fb8a0 | RVA 0x8fb8a0 | local helper / adjacent context (reachability below)
 * Evidence ev_a3529087295f4c573b7f89d3e82558e49918efda3c25d8a880df9a53a71b2220
 * Body [{"start": "0x8fb8a0", "end": "0x8fb8dd"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted.", "Ghidra Listing reports a terminal call at 0x8fb8d9 to 0x8fb470 adjacent_8fb470 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

void adjacent_8fb8a0(undefined8 param_1,undefined4 *param_2)

{
  int iVar1;
  
  iVar1 = func_0x00adfa30(param_1,0x2ab);
  if (iVar1 != 0) {
    return;
  }
  adjacent_8fb470(param_1,*param_2,*(undefined8 *)(param_2 + 2),param_2[4],
                  *(undefined8 *)(param_2 + 6),0);
  return;
}



/* adjacent_8fb8e0 | RVA 0x8fb8e0 | local helper / adjacent context (reachability below)
 * Evidence ev_935f2969da2729e920e0f553c956b3da38cab565991079fd7ef8a4d2c0e473ff
 * Body [{"start": "0x8fb8e0", "end": "0x8fb8f7"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted.", "Ghidra Listing reports a terminal call at 0x8fb8f3 to 0x8fb900 adjacent_8fb900 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

void adjacent_8fb8e0(undefined8 param_1,undefined8 *param_2)

{
  adjacent_8fb900(param_1,0xffffff9c,*param_2,0,*(undefined4 *)(param_2 + 1));
  return;
}



/* adjacent_8fb900 | RVA 0x8fb900 | local helper / adjacent context (reachability below)
 * Evidence ev_bab176c86985e2b1605950e622035135defa28c571dc7d7b52935ede7ccc3e06
 * Body [{"start": "0x8fb900", "end": "0x8fbb7b"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int adjacent_8fb900(long param_1,undefined4 param_2,undefined8 param_3,undefined4 param_4,
                   ushort param_5)

{
  code *pcVar1;
  int iVar2;
  undefined8 uVar3;
  long *in_GS_OFFSET;
  undefined4 local_208;
  ushort local_204;
  undefined8 local_160;
  undefined8 local_158;
  long local_150;
  long *local_148;
  undefined1 *local_140;
  undefined4 *local_138;
  undefined1 local_130 [16];
  undefined1 local_120 [96];
  long local_c0;
  long local_b8;
  undefined1 local_98 [10];
  byte local_8e;
  long local_38;
  
  local_38 = _DAT_0391c310;
  if ((*(byte *)(*in_GS_OFFSET + 0xef) & 1) != 0) {
    func_0x00444340(param_5);
  }
  do {
    func_0x00a9eac0(0);
    uVar3 = func_0x002bc220(0,local_130,0x200000000800400,0);
    func_0x005fa6e0(local_120,1,0x4000828,param_4,param_3,param_2,0,uVar3,param_1);
    local_8e = local_8e | 8;
    iVar2 = func_0x005f8c20(local_120);
    if (iVar2 != 0) break;
    if (local_c0 != 0) {
      func_0x005fa780(local_120,0xffffffdf);
      if (local_c0 == local_b8) {
        func_0x0054a120();
      }
      else {
        func_0x0054a440();
      }
      func_0x0054a120(local_c0);
      iVar2 = 0x11;
      break;
    }
    iVar2 = func_0x006af4f0(local_b8,&local_160,2);
    if (iVar2 == 0) {
      func_0x002590b0(&local_208,0x3829a90,0xa8);
      local_208 = 2;
      local_158 = 0x1adc1c8;
      local_148 = &local_c0;
      local_204 = ~(ushort)*(undefined4 *)(*(long *)(*(long *)(param_1 + 8) + 0x48) + 0x30) &
                  param_5 & 0x1ff;
      local_150 = local_b8;
      local_140 = local_98;
      local_138 = &local_208;
      iVar2 = func_0x0058db40(*(undefined8 *)(local_b8 + 8),&local_158);
      func_0x005fa780(local_120,0xffffffdf);
      func_0x0054a440(local_b8);
      if (iVar2 == 0) {
        func_0x0054a440(local_c0);
      }
      func_0x006af5e0(local_160);
      break;
    }
    func_0x005fa780(local_120,0xffffffdf);
    func_0x0054a440();
    iVar2 = func_0x006af4f0(0,&local_160,0x1004);
  } while (iVar2 == 0);
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar1 = (code *)invalidInstructionException();
    (*pcVar1)();
  }
  return iVar2;
}



/* adjacent_8fbb80 | RVA 0x8fbb80 | local helper / adjacent context (reachability below)
 * Evidence ev_c6d74142bdca3ba9d5c15a89bfc336e6e090cca38741e3f0a196694b2bfb8944
 * Body [{"start": "0x8fbb80", "end": "0x8fbbb9"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted.", "Ghidra Listing reports a terminal call at 0x8fbbb5 to 0x8fb900 adjacent_8fb900 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

void adjacent_8fbb80(undefined8 param_1,undefined4 *param_2)

{
  int iVar1;
  
  iVar1 = func_0x00adfa30(param_1,0x2ab);
  if (iVar1 != 0) {
    return;
  }
  adjacent_8fb900(param_1,*param_2,*(undefined8 *)(param_2 + 2),0,*(undefined2 *)(param_2 + 4));
  return;
}



/* adjacent_8fbbc0 | RVA 0x8fbbc0 | local helper / adjacent context (reachability below)
 * Evidence ev_f299fda74984e06ddc0ab2eb6dc47f31632897224530f684da0b1d5838c584b4
 * Body [{"start": "0x8fbbc0", "end": "0x8fbbd3"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void adjacent_8fbbc0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* adjacent_8fbbe0 | RVA 0x8fbbe0 | local helper / adjacent context (reachability below)
 * Evidence ev_373af22d4f72d80e05d0f008a5ee944baa9236f5e4880dc88501669310d0ae81
 * Body [{"start": "0x8fbbe0", "end": "0x8fbe63"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int adjacent_8fbbe0(long param_1,undefined4 *param_2)

{
  ushort uVar1;
  uint uVar2;
  undefined8 uVar3;
  code *pcVar4;
  ulong uVar5;
  int iVar6;
  ulong uVar7;
  ulong uVar8;
  ulong uVar9;
  uint uVar10;
  ulong uVar11;
  long lVar12;
  ulong uVar13;
  ulong uVar14;
  undefined8 *in_GS_OFFSET;
  long local_60;
  long local_58;
  undefined4 local_50 [2];
  long local_48;
  undefined4 local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  iVar6 = adjacent_8fbe70(param_1,*param_2,*(undefined8 *)(param_2 + 2),param_2[4],&local_58,0,0);
  if (iVar6 != 0) {
    if (((*(char *)(*(long *)(param_1 + 8) + 0xc81) != '\0') || (0xffff < (uint)param_2[4])) ||
       (iVar6 = 0x16, (uint)param_2[4] < 0x200)) goto LAB_008fbd95;
    uVar7 = func_0x00c08b50(0x10000,0x2bfc080,2);
    iVar6 = adjacent_8fbe70(param_1,*param_2,uVar7,0x10000,&local_58,&local_60,1);
    if (iVar6 != 0) {
LAB_008fbca4:
      func_0x00c08df0(uVar7,0x2bfc080);
      goto LAB_008fbd95;
    }
    uVar1 = *(ushort *)(uVar7 + 4);
    uVar2 = param_2[4];
    uVar11 = (ulong)uVar2;
    if ((uVar2 < uVar1 || uVar1 < 8) ||
       (uVar10 = (*(byte *)(uVar7 + 7) + 4 & 0xfffffffc) + 8, uVar1 <= uVar10 && uVar10 != uVar1)) {
      if ((uVar2 < uVar1) && ((*(byte *)(uVar7 + 7) + 4 & 0xfffffffc) + 8 < uVar2)) {
        *(short *)(uVar7 + 4) = (short)uVar2;
        uVar14 = uVar11;
      }
      else {
        uVar14 = 0;
      }
LAB_008fbd0d:
      lVar12 = 0;
    }
    else {
      uVar14 = 0;
      uVar9 = (ulong)uVar1;
      uVar5 = uVar7;
      do {
        uVar13 = uVar5;
        uVar8 = uVar9;
        if ((uVar7 + 0x10000) - local_60 <= uVar13) goto LAB_008fbd0d;
        uVar14 = uVar14 + uVar8;
        uVar1 = *(ushort *)(uVar13 + 4 + uVar8);
        uVar9 = (ulong)uVar1;
      } while (((7 < uVar9) && ((long)(uVar14 + uVar9) <= (long)uVar11)) &&
              (uVar5 = uVar13 + uVar8,
              (ushort)((*(byte *)(uVar13 + uVar8 + 7) + 4 & 0xfffc) + 8) <= uVar1));
      lVar12 = uVar11 - uVar14;
      *(short *)(uVar13 + 4) = (short)uVar8 + (short)lVar12;
      func_0x00258ff0();
      local_50[0] = *param_2;
      local_48 = local_58 + uVar14;
      local_40 = 0;
      iVar6 = func_0x008f8ab0(param_1,local_50);
      if (iVar6 != 0) goto LAB_008fbca4;
    }
    uVar3 = *(undefined8 *)(param_2 + 2);
    func_0x00c1a3e0(*in_GS_OFFSET,"copyout",0);
    iVar6 = func_0x002591d0(uVar7,uVar3,uVar14 + lVar12);
    func_0x00c08df0(uVar7,0x2bfc080);
    if (iVar6 != 0) goto LAB_008fbd95;
    *(ulong *)(param_1 + 0x408) = uVar14 + lVar12;
  }
  lVar12 = *(long *)(param_2 + 6);
  iVar6 = 0;
  if (lVar12 != 0) {
    func_0x00c1a3e0(*in_GS_OFFSET,"copyout",0);
    iVar6 = func_0x002591d0(&local_58,lVar12,8);
  }
LAB_008fbd95:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar4 = (code *)invalidInstructionException();
    (*pcVar4)();
  }
  return iVar6;
}



/* adjacent_8fbe70 | RVA 0x8fbe70 | local helper / adjacent context (reachability below)
 * Evidence ev_56308fc7983b8e5fde14a393587603af92d5cff4d40144c6486caa9062157cc5
 * Body [{"start": "0x8fbe70", "end": "0x8fc38d"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong adjacent_8fbe70(long param_1,undefined4 param_2,undefined8 param_3,ulong param_4,
                     undefined8 *param_5,ulong *param_6,undefined4 param_7)

{
  long *plVar1;
  long *plVar2;
  long lVar3;
  long lVar4;
  code *pcVar5;
  uint uVar6;
  ulong uVar7;
  ulong uVar8;
  undefined8 uVar9;
  long lVar10;
  long *in_GS_OFFSET;
  undefined8 local_e0;
  uint local_c8;
  undefined1 local_c4 [4];
  undefined8 local_c0;
  ulong local_b8;
  undefined8 *local_b0;
  undefined4 local_a8;
  undefined8 local_a0;
  ulong local_98;
  undefined4 local_90;
  undefined4 local_8c;
  long local_88;
  long *local_80;
  long local_78;
  undefined8 **local_70;
  long local_68;
  undefined1 *local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined1 local_48 [16];
  long local_38;
  
  local_38 = _DAT_0391c310;
  lVar3 = *in_GS_OFFSET;
  if ((*(byte *)(lVar3 + 0xef) & 1) != 0) {
    func_0x004440d0(param_2);
  }
  param_4 = param_4 & 0xffffffff;
  uVar7 = func_0x004ebfb0();
  uVar8 = 0x16;
  if (param_4 <= uVar7) {
    local_98 = param_4;
    uVar9 = func_0x002bc220(0,local_48,0x200000000000001,0);
    uVar8 = func_0x0072b4c0(*(undefined8 *)(*(long *)(param_1 + 8) + 0x48),param_2,uVar9,&local_80,0
                           );
    plVar1 = local_80;
    if ((int)uVar8 == 0) {
      if ((local_80[3] == 0) || (local_80[1] == _DAT_01a5d1a0)) {
        uVar8 = 0x16;
        LOCK();
        plVar1 = local_80 + 5;
        lVar3 = *plVar1;
        *(int *)plVar1 = (int)*plVar1 + -1;
        UNLOCK();
        if ((int)lVar3 == 1) {
          func_0x0072b380(local_80,param_1);
          uVar8 = 0x16;
        }
      }
      else if ((*(uint *)((long)local_80 + 0x24) & 1) == 0) {
        uVar8 = 9;
        LOCK();
        plVar1 = local_80 + 5;
        lVar3 = *plVar1;
        *(int *)plVar1 = (int)*plVar1 + -1;
        UNLOCK();
        if ((int)lVar3 == 1) {
          func_0x0072b380(local_80,param_1);
          uVar8 = 9;
        }
      }
      else {
        lVar10 = local_80[3];
        uVar9 = func_0x006b06c0(local_80,0);
        local_c8 = 0x16;
        if (*(int *)(lVar10 + 0x1d4) == 2) {
          local_b0 = &local_c0;
          local_a8 = 1;
          local_8c = 0;
          local_90 = param_7;
          local_c0 = param_3;
          local_b8 = param_4;
          local_88 = param_1;
          func_0x006afb50(lVar10,0x200400,"W:/Build/J03950001/sys/freebsd/sys/kern/vfs_syscalls.c",
                          0x10f0);
          if ((*(byte *)(lVar3 + 0xef) & 1) != 0) {
            func_0x004449b0(lVar10);
          }
          local_68 = plVar1[2];
          local_80 = (long *)0x1adc648;
          local_70 = &local_b0;
          local_60 = local_c4;
          local_58 = 0;
          local_50 = 0;
          local_a0 = uVar9;
          local_78 = lVar10;
          uVar6 = func_0x0058e110(*(undefined8 *)(lVar10 + 8),&local_80);
          if (uVar6 == 0) {
            local_e0 = uVar9;
            if (((local_98 == param_4) && ((*(byte *)(lVar10 + 0x1c8) & 1) != 0)) &&
               ((*(byte *)(*(long *)(lVar10 + 0x18) + 0x98) & 0x20) != 0)) {
              lVar4 = *(long *)(*(long *)(lVar10 + 0x18) + 0x48);
              func_0x0054a060();
              plVar1[3] = lVar4;
              *plVar1 = lVar4;
              func_0x0054a440(lVar10);
              if (*(int *)(lVar4 + 0x1d4) == 2) {
                local_e0 = 0;
                lVar10 = lVar4;
                do {
                  local_b0 = &local_c0;
                  local_a8 = 1;
                  local_8c = 0;
                  local_90 = param_7;
                  local_c0 = param_3;
                  local_b8 = param_4;
                  local_88 = param_1;
                  func_0x006afb50(lVar10,0x200400,
                                  "W:/Build/J03950001/sys/freebsd/sys/kern/vfs_syscalls.c",0x10f0);
                  if ((*(byte *)(lVar3 + 0xef) & 1) != 0) {
                    func_0x004449b0(lVar10);
                  }
                  local_a0 = 0;
                  local_70 = &local_b0;
                  local_68 = plVar1[2];
                  local_80 = (long *)0x1adc648;
                  local_60 = local_c4;
                  local_58 = 0;
                  local_50 = 0;
                  local_78 = lVar10;
                  uVar6 = func_0x0058e110(*(undefined8 *)(lVar10 + 8),&local_80);
                  if (uVar6 != 0) goto LAB_008fc0d2;
                  if (((local_98 != param_4) || ((*(byte *)(lVar10 + 0x1c8) & 1) == 0)) ||
                     ((*(byte *)(*(long *)(lVar10 + 0x18) + 0x98) & 0x20) == 0)) goto LAB_008fc2d8;
                  lVar4 = *(long *)(*(long *)(lVar10 + 0x18) + 0x48);
                  func_0x0054a060();
                  plVar1[3] = lVar4;
                  *plVar1 = lVar4;
                  func_0x0054a440(lVar10);
                  lVar10 = lVar4;
                } while (*(int *)(lVar4 + 0x1d4) == 2);
              }
              uVar9 = 0;
            }
            else {
LAB_008fc2d8:
              uVar9 = local_a0;
              local_80 = (long *)0x1adcdc8;
              local_70 = (undefined8 **)((ulong)local_70 & 0xffffffff00000000);
              local_78 = lVar10;
              func_0x0058ea90(*(undefined8 *)(lVar10 + 8),&local_80);
              *param_5 = local_e0;
              if (param_6 != (ulong *)0x0) {
                *param_6 = local_98;
              }
              local_c8 = 0;
              *(ulong *)(param_1 + 0x408) = param_4 - local_98;
            }
          }
          else {
LAB_008fc0d2:
            uVar9 = local_a0;
            local_80 = (long *)0x1adcdc8;
            local_70 = (undefined8 **)((ulong)local_70 & 0xffffffff00000000);
            local_78 = lVar10;
            func_0x0058ea90(*(undefined8 *)(lVar10 + 8),&local_80);
            local_c8 = uVar6;
          }
        }
        func_0x006b0790(plVar1,uVar9,0);
        LOCK();
        plVar2 = plVar1 + 5;
        lVar3 = *plVar2;
        *(int *)plVar2 = (int)*plVar2 + -1;
        UNLOCK();
        if ((int)lVar3 == 1) {
          func_0x0072b380(plVar1,param_1);
        }
        uVar8 = (ulong)local_c8;
      }
    }
  }
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar5 = (code *)invalidInstructionException();
    (*pcVar5)();
  }
  return uVar8;
}



/* adjacent_8fc390 | RVA 0x8fc390 | local helper / adjacent context (reachability below)
 * Evidence ev_e05e7247722ef77cda9d81a78e8ac91aff4f6f0be32ed0636209514a297878b4
 * Body [{"start": "0x8fc390", "end": "0x8fc3e1"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void adjacent_8fc390(undefined8 param_1,undefined4 *param_2)

{
  code *pcVar1;
  undefined4 local_38 [2];
  undefined8 local_30;
  undefined4 local_28;
  undefined8 local_20;
  long local_18;
  
  local_18 = _DAT_0391c310;
  local_38[0] = *param_2;
  local_30 = *(undefined8 *)(param_2 + 2);
  local_28 = param_2[4];
  local_20 = 0;
  adjacent_8fbbe0(param_1,local_38);
  if (_DAT_0391c310 == local_18) {
    return;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* adjacent_8fc3f0 | RVA 0x8fc3f0 | local helper / adjacent context (reachability below)
 * Evidence ev_c7a756773b939500ae541864787284a12b147fdc7067c23bd2e33a05499f791d
 * Body [{"start": "0x8fc3f0", "end": "0x8fc488"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

ulong adjacent_8fc3f0(long param_1,ushort *param_2)

{
  long lVar1;
  ulong uVar2;
  
  if (*(int *)param_2 != 0) {
    func_0x0025d410("%s %d : Warning : Non 0 umask was specified. %07o\n","sys_umask",0x1141);
  }
  uVar2 = func_0x00adfa30(param_1,0x2ab);
  if ((int)uVar2 == 0) {
    uVar2 = uVar2 & 0xffffffff;
    lVar1 = *(long *)(*(long *)(param_1 + 8) + 0x48);
    func_0x00c4bb20(lVar1 + 0x40,0,0,0);
    *(ulong *)(param_1 + 0x408) = (ulong)*(ushort *)(lVar1 + 0x30);
    *(ushort *)(lVar1 + 0x30) = *param_2 & 0xfff;
    func_0x00c4c4b0(lVar1 + 0x40,0,0);
  }
  return uVar2;
}



/* adjacent_8fc490 | RVA 0x8fc490 | local helper / adjacent context (reachability below)
 * Evidence ev_becb06f99af483e1ade0d4a96f4bd43d578952e5a990e96d294c59b0abef4ea3
 * Body [{"start": "0x8fc490", "end": "0x8fc606"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong adjacent_8fc490(long param_1,undefined8 *param_2)

{
  code *pcVar1;
  uint uVar2;
  int iVar3;
  ulong uVar4;
  undefined1 local_1d8 [8];
  int local_1d0;
  undefined8 local_130;
  long local_128;
  undefined1 *local_120;
  undefined8 local_118;
  undefined1 local_110 [96];
  long local_b0;
  long local_28;
  
  local_28 = _DAT_0391c310;
  uVar4 = func_0x00adfa30(param_1,0x2ab);
  if ((int)uVar4 != 0) goto LAB_008fc57f;
  func_0x005fa6e0(local_110,0,0x4000044,0,*param_2,0xffffff9c,0,0,param_1);
  uVar4 = func_0x005f8c20(local_110);
  if ((int)uVar4 != 0) goto LAB_008fc57f;
  func_0x005fa780(local_110,0xffffffdf);
  uVar2 = 0x16;
  if ((*(int *)(local_b0 + 0x1d4) == 4) && (*(long *)(local_b0 + 0x30) != 0)) {
    local_118 = *(undefined8 *)(param_1 + 0x140);
    local_120 = local_1d8;
    local_130 = 0x1adad78;
    local_128 = local_b0;
    uVar2 = func_0x0058c1c0(*(undefined8 *)(local_b0 + 8),&local_130);
    if (uVar2 == 0) {
      if (*(int *)(*(long *)(param_1 + 0x140) + 4) != local_1d0) {
        uVar2 = func_0x00adfa30(param_1,0x138);
        if (uVar2 != 0) goto LAB_008fc573;
      }
      iVar3 = func_0x0054b650(local_b0);
      uVar2 = 0;
      if (1 < iVar3) {
        local_130 = 0x1adb978;
        local_128 = local_b0;
        local_120 = (undefined1 *)CONCAT44(local_120._4_4_,1);
        func_0x0058d1c0(*(undefined8 *)(local_b0 + 8),&local_130);
        uVar2 = 0;
      }
    }
  }
LAB_008fc573:
  uVar4 = (ulong)uVar2;
  func_0x0054a440(local_b0);
LAB_008fc57f:
  if (_DAT_0391c310 == local_28) {
    return uVar4;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* adjacent_8fc610 | RVA 0x8fc610 | local helper / adjacent context (reachability below)
 * Evidence ev_61c8dfd3add10b611c8dd4e34715bbf964f6966f3320c1133e4bade66fcb6487
 * Body [{"start": "0x8fc610", "end": "0x8fc666"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 adjacent_8fc610(long param_1)

{
  long lVar1;
  long lVar2;
  
  lVar2 = *(long *)(*(long *)(param_1 + 8) + 0x48);
  lVar1 = lVar2 + 0x40;
  func_0x00c4bb20(lVar1,0,0,0);
  *(ulong *)(param_1 + 0x408) = (ulong)(*(long *)(lVar2 + 0x10) != _DAT_03e0b510);
  func_0x00c4c4b0(lVar1,0,0);
  return 0;
}



/* adjacent_8fc675 | RVA 0x8fc675 | local helper / adjacent context (reachability below)
 * Evidence ev_16b4bd7f992970bb006340eb8a9fdcc01f904494d5144a73970351dfd37b6daf
 * Body [{"start": "0x8fc675", "end": "0x8fc6df"}, {"start": "0x8fc6e6", "end": "0x8fc707"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

ulong adjacent_8fc675(undefined8 param_1,undefined1 param_2,undefined8 param_3,undefined8 param_4,
                     undefined8 param_5)

{
  uint uVar1;
  ulong uVar2;
  long lVar3;
  
  uVar2 = func_0x00ab7ea0(1);
  if ((int)uVar2 == 0) {
    lVar3 = func_0x00ac6e80(param_1);
    if (lVar3 == 0) {
      uVar1 = 0x1001;
    }
    else {
      uVar1 = func_0x00a87bf0(lVar3,param_2,param_3,param_4,param_5);
      if (uVar1 == 0) {
        func_0x00bebb80(lVar3,param_2,1);
        uVar1 = 0;
      }
    }
    uVar2 = (ulong)uVar1;
    func_0x00ab7f20(1);
  }
  return uVar2;
}



/* adjacent_8fc715 | RVA 0x8fc715 | local helper / adjacent context (reachability below)
 * Evidence ev_3ab17f5cb5d674acad5283d236f41034004b1443423d6516bea2dbc281853d7e
 * Body [{"start": "0x8fc715", "end": "0x8fc789"}, {"start": "0x8fc790", "end": "0x8fc805"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 adjacent_8fc715(undefined8 param_1,char param_2,long param_3)

{
  undefined8 uVar1;
  long lVar2;
  undefined8 *puVar3;
  long lVar4;
  
  uVar1 = func_0x00ab7ea0(1);
  if ((int)uVar1 == 0) {
    lVar2 = func_0x00ac6e80(param_1);
    uVar1 = 0x1001;
    if ((lVar2 != 0) &&
       (((*(byte *)(lVar2 + 9) < 0xe && ((0x3040U >> (*(byte *)(lVar2 + 9) & 0x1f) & 1) != 0)) ||
        (lVar2 == _DAT_039c9698)))) {
      lVar2 = func_0x005d91c0(lVar2);
      if ((lVar2 == 0) || (lVar4 = *(long *)(lVar2 + 0x20), lVar4 == 0)) {
LAB_008fc7d5:
        uVar1 = 6;
      }
      else {
        if (*(char *)(lVar4 + 0xd) == param_2) {
          puVar3 = (undefined8 *)(lVar2 + 0x20);
        }
        else {
          do {
            lVar2 = lVar4;
            lVar4 = *(long *)(lVar2 + 0x38);
            if (lVar4 == 0) goto LAB_008fc7d5;
          } while (*(char *)(lVar4 + 0xd) != param_2);
          puVar3 = (undefined8 *)(lVar2 + 0x38);
        }
        uVar1 = 0x1001;
        if (*(long *)(lVar4 + 0x10) == param_3) {
          while (*(long *)(lVar4 + 0x30) != 0) {
            func_0x00bebfb0(*(long *)(lVar4 + 0x30),1);
          }
          *puVar3 = *(undefined8 *)(lVar4 + 0x38);
          func_0x00b4a4c0(lVar4);
          uVar1 = 0;
        }
      }
    }
    func_0x00ab7f20(1);
  }
  return uVar1;
}



/* adjacent_8fc810 | RVA 0x8fc810 | local helper / adjacent context (reachability below)
 * Evidence ev_e1526c635752cc68f818c88e81bb1c86ff444a651a88e423b2774331bcc49a49
 * Body [{"start": "0x8fc810", "end": "0x8fc819"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void adjacent_8fc810(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* adjacent_8fc820 | RVA 0x8fc820 | local helper / adjacent context (reachability below)
 * Evidence ev_d338a86d4fc75ef2e0451cd40b1261cf949cc9319e4ce5d1894763bfdded3653
 * Body [{"start": "0x8fc820", "end": "0x8fc829"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void adjacent_8fc820(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* adjacent_8fc845 | RVA 0x8fc845 | local helper / adjacent context (reachability below)
 * Evidence ev_b4278bdb410341a7870eb038e14fd28310bb2474d6ba784c6b4a316bdd627920
 * Body [{"start": "0x8fc845", "end": "0x8fc86e"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void adjacent_8fc845(void)

{
  code *pcVar1;
  
  func_0x007f1950();
  func_0x007f1810(adjacent_8fc845);
  func_0x00c9aa10(3,"Dynamic syscall is no longer supported.");
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* adjacent_8fc877 | RVA 0x8fc877 | local helper / adjacent context (reachability below)
 * Evidence ev_86b87f507ee63b18fb01e3d54e2d17ddbd2bcdbfc9cd22abd980070dbb43ada6
 * Body [{"start": "0x8fc877", "end": "0x8fc8a0"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void adjacent_8fc877(void)

{
  code *pcVar1;
  
  func_0x007f1950();
  func_0x007f1810(adjacent_8fc877);
  func_0x00c9aa10(7,"Dynamic syscall is no longer supported.");
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* adjacent_8fc8b0 | RVA 0x8fc8b0 | local helper / adjacent context (reachability below)
 * Evidence ev_14e78fb3568bf2ed6736c226788a7b3248f2b56ec12c5468d3f0b6ffa9e71caa
 * Body [{"start": "0x8fc8b0", "end": "0x8fcdc0"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int adjacent_8fc8b0(long param_1)

{
  short sVar1;
  undefined2 uVar2;
  long lVar3;
  long lVar4;
  code *pcVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  long lVar10;
  long *in_GS_OFFSET;
  long local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  lVar3 = *(long *)(param_1 + 8);
  lVar4 = *(long *)(lVar3 + 0x10);
  local_40 = 0;
  if (*(short *)(lVar4 + 0x8c) == 0) {
    iVar6 = 0;
  }
  else {
    if ((*(int *)(lVar4 + 0x34) == 0) &&
       ((*(uint *)(*(long *)(lVar3 + 0x18) + 0x99) & 0x1002000) != 0)) {
LAB_008fc94e:
      iVar6 = func_0x006b0e70(lVar3,&local_40,2);
      if (iVar6 != 0) {
        do {
          if ((*(byte *)(lVar3 + 0x1c4) & 0x80) != 0) {
            func_0x006b0e70(lVar3,&local_40,1);
            break;
          }
          func_0x004c6a00(local_40 + 0x18,0,0,0);
          if ((*(byte *)(local_40 + 0x93) & 0x14) != 0) {
            iVar6 = 0;
            func_0x004c6a00(lVar3 + 0xb0,0,0,0);
            *(byte *)(lVar3 + 0x1c5) = *(byte *)(lVar3 + 0x1c5) | 0x10;
            func_0x004c6fa0(lVar3 + 0xb0,0,0,0);
            func_0x004c6fa0(local_40 + 0x18,0,0,0);
            goto LAB_008fcbca;
          }
          func_0x004c6fa0(local_40 + 0x18,0,0);
          iVar6 = func_0x006b0e70(lVar3,&local_40,2);
        } while (iVar6 != 0);
      }
    }
    else if (*(short *)(lVar4 + 0x8e) < 1) {
      pcVar5 = *(code **)(*(long *)(lVar4 + 0x18) + 0x200);
      if (0x6ff < (-(long)pcVar5 + 0x260ce8U >> 3 | -(long)pcVar5 << 0x3d)) {
        func_0x0044f8c0(0x254ecc0,pcVar5);
      }
      iVar6 = (*pcVar5)(lVar4);
      if (iVar6 == 0) goto LAB_008fc94e;
    }
    lVar10 = *(long *)(lVar4 + 0x90);
    if (*(long *)(*(long *)(lVar4 + 0x18) + 0x28) == 2) {
      lVar10 = lVar10 + (ulong)*(uint *)(*(long *)(lVar4 + 0xb0) + 0x5c);
    }
    iVar6 = 0;
    if ((*(int *)(lVar4 + 0x34) < 1) && (lVar10 != 0)) {
      pcVar5 = *(code **)(*(long *)(lVar4 + 0x18) + 0x200);
      if (0x6ff < (-(long)pcVar5 + 0x260ce8U >> 3 | -(long)pcVar5 << 0x3d)) {
        func_0x0044f8c0(0x254ece0,pcVar5);
      }
      iVar7 = (*pcVar5)(lVar4);
      if (iVar7 != 0) goto LAB_008fca2c;
      pcVar5 = *(code **)(*(long *)(*(long *)(lVar3 + 0x18) + 0x298) + 0x1d8);
      if (3 < (-(long)pcVar5 + 0x26f7f8U >> 3 | -(long)pcVar5 << 0x3d)) {
        func_0x0044f8c0(0x254ed00,pcVar5);
      }
      iVar6 = (*pcVar5)(lVar3,0,0xc00,0);
      sVar1 = *(short *)(lVar4 + 0x8e);
    }
    else {
LAB_008fca2c:
      sVar1 = *(short *)(lVar4 + 0x8e);
    }
    if ((sVar1 < 1) && (*(short *)(lVar4 + 0x8c) != 0)) {
      pcVar5 = *(code **)(*(long *)(lVar4 + 0x18) + 0x200);
      if (0x6ff < (-(long)pcVar5 + 0x260ce8U >> 3 | -(long)pcVar5 << 0x3d)) {
        func_0x0044f8c0(0x254ed20,pcVar5);
      }
      iVar7 = (*pcVar5)(lVar4);
      if (iVar7 == 0) {
        lVar10 = *(long *)(*(long *)(lVar4 + 0x18) + 0x28);
        if (lVar10 == 2) {
          *(undefined4 *)(*(long *)(lVar4 + 0xb0) + 0xf4) = 0;
          lVar10 = *(long *)(*(long *)(lVar4 + 0x18) + 0x28);
        }
        if (lVar10 == 1) {
          *(undefined4 *)(*(long *)(lVar4 + 0xb0) + 0x28) = 0;
        }
        else {
          *(undefined8 *)(*(long *)(lVar4 + 0xb0) + 0x70) = 0;
        }
        uVar2 = *(undefined2 *)(lVar4 + 0x8c);
        *(undefined2 *)(lVar4 + 0x8c) = 0;
        **(undefined2 **)(lVar4 + 0xb0) = 0;
        *(byte *)(lVar4 + 0x20) = *(byte *)(lVar4 + 0x20) | 6;
        lVar10 = *(long *)(lVar3 + 0x18);
        iVar7 = iVar6;
        if ((*(uint *)(lVar10 + 0x99) & 0x1002000) != 0) {
          iVar8 = func_0x0041a9d0(lVar4);
          if (iVar6 == 0) {
            iVar7 = iVar8;
          }
          lVar10 = *(long *)(lVar3 + 0x18);
          if (iVar8 == 0) {
            iVar7 = iVar6;
          }
        }
        pcVar5 = *(code **)(*(long *)(lVar10 + 0x298) + 0x1f0);
        if (pcVar5 != (code *)0x26f740) {
          func_0x0044f8c0(0x254ed40,pcVar5);
        }
        iVar8 = (*pcVar5)(lVar3,*(undefined4 *)(lVar4 + 0x30),uVar2);
        if (((*(int *)(lVar4 + 0x30) == 0x8100) && (*(long *)(lVar4 + 0xa0) == 0x202)) &&
           (iVar6 = func_0x008d1a30(*(long *)(lVar3 + 0x18) + 0x238,"/app_temp0",0xb), iVar6 == 0))
        {
          func_0x0025d410("%s:%s %s ino:%d, i_gen:%lu (PPRBUG-35487)\n","ufs_inactive",
                          *in_GS_OFFSET + 0x294,"clear bitmap",*(undefined4 *)(lVar4 + 0x30),
                          *(undefined8 *)(lVar4 + 0xa0));
        }
        iVar9 = iVar7;
        if (iVar7 == 0) {
          iVar9 = iVar8;
        }
        iVar6 = iVar7;
        if (iVar8 != 0) {
          iVar6 = iVar9;
        }
      }
    }
    if ((*(uint *)(lVar4 + 0x20) & 0xf) != 0) {
      if ((local_40 == 0 && (*(uint *)(lVar4 + 0x20) & 0xe) == 0) &&
         (iVar7 = func_0x006b0e70(lVar3,&local_40,2), iVar7 != 0)) {
        local_40 = 0;
        *(byte *)(lVar4 + 0x20) = *(byte *)(lVar4 + 0x20) & 0xfe;
      }
      else {
        if (local_40 == 0) {
          func_0x006b0e70(lVar3,&local_40,1);
        }
        pcVar5 = *(code **)(*(long *)(*(long *)(lVar3 + 0x18) + 0x298) + 0x1e0);
        if (0x72 < (-(long)pcVar5 + 0x2690e0U >> 3 | -(long)pcVar5 << 0x3d)) {
          func_0x0044f8c0(0x254ed60,pcVar5);
        }
        (*pcVar5)(lVar3,0);
      }
    }
    if (*(short *)(lVar4 + 0x8c) != 0) goto LAB_008fcbbc;
  }
  func_0x0054b200(lVar3);
LAB_008fcbbc:
  if (local_40 != 0) {
    func_0x006b1020();
  }
LAB_008fcbca:
  if (_DAT_0391c310 == local_38) {
    return iVar6;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar5 = (code *)invalidInstructionException();
  (*pcVar5)();
}



/* adjacent_8fcdd0 | RVA 0x8fcdd0 | local helper / adjacent context (reachability below)
 * Evidence ev_c237298077e4e53150ec9fd986fac15299cee59d17c5e10e33186be3cb886b19
 * Body [{"start": "0x8fcdd0", "end": "0x8fcdd9"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void adjacent_8fcdd0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* adjacent_8fcde0 | RVA 0x8fcde0 | local helper / adjacent context (reachability below)
 * Evidence ev_0e81dcef514c0f701b91d87ad6958985f915132d2df6185f5032f46b5dc0fb6a
 * Body [{"start": "0x8fcde0", "end": "0x8fcf07"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_8fcde0(long param_1)

{
  uint uVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  code *pcVar5;
  
  lVar2 = *(long *)(param_1 + 8);
  lVar3 = *(long *)(lVar2 + 0x10);
  uVar1 = *(uint *)(lVar2 + 0x1c8);
  lVar4 = *(long *)(lVar3 + 0x18);
  func_0x006a8530(lVar2);
  if ((uVar1 & 0x10000) == 0) {
    if ((*(uint *)(lVar3 + 0x20) & 0x40) != 0) {
      *(uint *)(lVar3 + 0x20) = *(uint *)(lVar3 + 0x20) | 8;
    }
    pcVar5 = *(code **)(*(long *)(*(long *)(lVar2 + 0x18) + 0x298) + 0x1e0);
    if (0x72 < (-(long)pcVar5 + 0x2690e0U >> 3 | -(long)pcVar5 << 0x3d)) {
      func_0x0044f8c0(0x254ed80,pcVar5);
    }
    (*pcVar5)(lVar2,0);
    func_0x00adfbb0(lVar2);
    func_0x004c6a00(lVar2 + 0xb0,0,0,0);
    *(undefined8 *)(lVar2 + 0x10) = 0;
    func_0x004c6fa0(lVar2 + 0xb0,0,0,0);
    pcVar5 = *(code **)(lVar4 + 0x1f8);
    if (0x197 < (-(long)pcVar5 + 0x267e88U >> 3 | -(long)pcVar5 << 0x3d)) {
      func_0x0044f8c0(0x254eda0,pcVar5);
    }
    (*pcVar5)(lVar4,lVar3);
  }
  else {
    func_0x004c6a00(lVar2 + 0xb0,0,0,0);
    *(undefined8 *)(lVar2 + 0x10) = 0;
    func_0x004c6fa0(lVar2 + 0xb0,0,0,0);
  }
  return 0;
}



/* adjacent_8fcf10 | RVA 0x8fcf10 | local helper / adjacent context (reachability below)
 * Evidence ev_48a38ff06064561ae56453bc0cf310802c9028da051b62ef43bbbdd1682a2da9
 * Body [{"start": "0x8fcf10", "end": "0x8fcf26"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_8fcf10(undefined8 param_1)

{
  func_0x002b3d30(param_1,"Generic IEEE 802.3u media interface");
  return 0xffffff9c;
}



/* adjacent_8fcf30 | RVA 0x8fcf30 | local helper / adjacent context (reachability below)
 * Evidence ev_6c092865f831e003bcd0e09a2be4f5ea2d46dda50acccf798b5288ade8b59a11
 * Body [{"start": "0x8fcf30", "end": "0x8fcf69"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_8fcf30(undefined8 param_1)

{
  undefined8 uVar1;
  
  uVar1 = func_0x002b2b10();
  func_0x0081a730(param_1,0x100000,0xe8a590,1);
  func_0x00819390(uVar1);
  return 0;
}



/* adjacent_8fcf70 | RVA 0x8fcf70 | local helper / adjacent context (reachability below)
 * Evidence ev_573a729b4490b9a10ea9a65fa281f4cb50d932c22c897dad6e413bf7bd345248
 * Body [{"start": "0x8fcf70", "end": "0x8fcfeb"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_8fcf70(long param_1,undefined8 param_2,int param_3)

{
  code *pcVar1;
  int iVar2;
  
  if (param_3 == 1) {
    iVar2 = func_0x00819a50(param_1);
    if (iVar2 == -2) {
      return 0;
    }
  }
  else if (param_3 == 2) {
    func_0x00819390(param_1);
  }
  pcVar1 = *(code **)(*(long *)(param_1 + 0x38) + 8);
  if (0x8bc < (-(long)pcVar1 + 0x2652d0U >> 3 | -(long)pcVar1 << 0x3d)) {
    func_0x0044f8c0(0x254eec0,pcVar1);
  }
  (*pcVar1)(param_1);
  func_0x00819e90(param_1,param_3);
  return 0;
}



/* adjacent_8fcff0 | RVA 0x8fcff0 | local helper / adjacent context (reachability below)
 * Evidence ev_e444f9d6d3a63a3203b54696cb4666d85af5b758ccb1739a71d09a30180a652e
 * Body [{"start": "0x8fcff0", "end": "0x8fd050"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void adjacent_8fcff0(int param_1)

{
  int iVar1;
  
  iVar1 = func_0x0099fb40(1);
  if (iVar1 == param_1) {
    func_0x004c7190(0x3b49330,0,0,0);
    *(undefined8 *)(&DAT_03b49340 + (long)param_1 * 0x10) = 0xffffffffffffffff;
    *(undefined4 *)(&DAT_03b49348 + (long)param_1 * 0x10) = 0;
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  return;
}



/* adjacent_8fd060 | RVA 0x8fd060 | local helper / adjacent context (reachability below)
 * Evidence ev_60279860f884353e8832f4a637aa701c16b44a825f5debfed4a1511d5c4d476f
 * Body [{"start": "0x8fd060", "end": "0x8fd0dc"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void adjacent_8fd060(int param_1,undefined4 param_2)

{
  undefined4 uVar1;
  int iVar2;
  
  iVar2 = func_0x0099fb40(1);
  if (iVar2 == param_1) {
    func_0x004c7190(0x3b49330,0,0,0);
    uVar1 = _DAT_03b49310;
    *(undefined8 *)(&DAT_03b49340 + (long)param_1 * 0x10) = 0;
    *(undefined4 *)(&DAT_03b49348 + (long)param_1 * 0x10) = param_2;
    func_0x0078e8d0(param_1,uVar1);
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  return;
}



/* adjacent_8fd0e0 | RVA 0x8fd0e0 | local helper / adjacent context (reachability below)
 * Evidence ev_3c6cc27e968875b8f94c1ecf57770722369b77dbb389bacf1ac1669649007f30
 * Body [{"start": "0x8fd0e0", "end": "0x8fd156"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 adjacent_8fd0e0(int param_1,undefined8 param_2)

{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  
  uVar3 = 0;
  iVar1 = func_0x0099fc00(0);
  if (iVar1 == param_1) {
    func_0x004c7190(0x3b49330,0,0,0);
    uVar2 = func_0x0099fb40(1);
    if (-1 < (int)uVar2) {
      *(undefined8 *)(&DAT_03b49340 + (ulong)uVar2 * 0x10) = param_2;
    }
    uVar3 = _DAT_03b49310;
    func_0x004c7520(0x3b49330,0,0,0);
  }
  return uVar3;
}



/* adjacent_8fd160 | RVA 0x8fd160 | local helper / adjacent context (reachability below)
 * Evidence ev_d7dd9fc25de5f2a92dce5009270dedac06d75b18fced3961677b86ac0c40df40
 * Body [{"start": "0x8fd160", "end": "0x8fd1e6"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int adjacent_8fd160(int param_1,undefined4 param_2,long *param_3,int *param_4)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = -1;
  if (param_1 == 1) {
    func_0x004c7190(0x3b49330,0,0,0);
    uVar1 = func_0x0099fb40(1);
    if (-1 < (int)uVar1) {
      _DAT_03b49310 = param_2;
      *param_3 = *(long *)(&DAT_03b49340 + (ulong)uVar1 * 0x10) + 1;
      iVar2 = *(int *)(&DAT_03b49348 + (ulong)uVar1 * 0x10);
      *param_4 = iVar2;
      iVar2 = -(uint)(iVar2 == 0);
    }
    func_0x004c7520(0x3b49330,0,0,0);
  }
  return iVar2;
}



/* adjacent_8fd1f0 | RVA 0x8fd1f0 | local helper / adjacent context (reachability below)
 * Evidence ev_cc6c887b0a1a840db0b07dc897a2a0dd97396b75f421139aca46d95363a71f3f
 * Body [{"start": "0x8fd1f0", "end": "0x8fd263"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void adjacent_8fd1f0(void)

{
  func_0x004c7dd0(0x3b49330,"dcecamera",0,1);
  _DAT_03b49340 = 0xffffffffffffffff;
  _DAT_03b49348 = 0;
  _DAT_03b49350 = 0xffffffffffffffff;
  _DAT_03b49358 = 0;
  _DAT_03b49360 = 0xffffffffffffffff;
  _DAT_03b49368 = 0;
  _DAT_03b49370 = 0xffffffffffffffff;
  _DAT_03b49378 = 0;
  return;
}



/* adjacent_8fd270 | RVA 0x8fd270 | local helper / adjacent context (reachability below)
 * Evidence ev_2d521c938e3810dc7c65e59a8fab9e820fc1d0b8562450e6df3bf5d679365179
 * Body [{"start": "0x8fd270", "end": "0x8fd280"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void adjacent_8fd270(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* adjacent_8fd290 | RVA 0x8fd290 | local helper / adjacent context (reachability below)
 * Evidence ev_bd60176cf997c45a1400a35941d2e5d96bbacbc1fb99fe7702c034dd2fd8f3b7
 * Body [{"start": "0x8fd290", "end": "0x8fd297"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_8fd290(void)

{
  return 0;
}



/* adjacent_8fd2b1 | RVA 0x8fd2b1 | local helper / adjacent context (reachability below)
 * Evidence ev_58a5c5e539afee799a455d7cf266ee12bc0274c3b65bcb831266e6e1aa93028c
 * Body [{"start": "0x8fd2b1", "end": "0x8fd353"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong adjacent_8fd2b1(undefined8 param_1,undefined4 param_2,undefined8 param_3,undefined4 param_4,
                     long param_5)

{
  ulong uVar1;
  
  func_0x00c4bb20(0x3b5c008,0,0,0);
  func_0x002590b0(0x3b4c000,param_1,param_2);
  uVar1 = func_0x00b5cbe0(param_4,0x3b4c000,param_2,param_3,0,param_5 == 2);
  if (((_DAT_03b5c020 & 1) == 0) && (0xf < _DAT_03b5c020)) {
    uVar1 = uVar1 & 0xffffffff;
    func_0x00c4c4b0(0x3b5c008,0,0);
  }
  return uVar1;
}



/* adjacent_8fd371 | RVA 0x8fd371 | local helper / adjacent context (reachability below)
 * Evidence ev_c25fa8a2fc9ae64caf7cfd6b78fa6d7dac661b768f98ac5c912cbb7bbb99edc9
 * Body [{"start": "0x8fd371", "end": "0x8fd42b"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong adjacent_8fd371(undefined8 param_1,uint param_2,long param_3,undefined4 param_4)

{
  ulong uVar1;
  
  func_0x00c4bb20(0x3b5c008,0,0,0);
  func_0x002590b0(0x3b4c000,param_1,param_2);
  uVar1 = func_0x00b5d5d0(param_4,0x3b4c000,param_2,param_3 * (ulong)(param_2 >> 0xc));
  if ((int)uVar1 == 0) {
    uVar1 = uVar1 & 0xffffffff;
    func_0x002590b0(param_1,0x3b4c000,param_2);
  }
  if (((_DAT_03b5c020 & 1) == 0) && (0xf < _DAT_03b5c020)) {
    uVar1 = uVar1 & 0xffffffff;
    func_0x00c4c4b0(0x3b5c008,0,0);
  }
  return uVar1;
}



/* adjacent_8fd430 | RVA 0x8fd430 | local helper / adjacent context (reachability below)
 * Evidence ev_877f8dcbcc3759159dd96279091fca9ef4214d7d0cc96ac22a14cb2657185b0c
 * Body [{"start": "0x8fd430", "end": "0x8fd502"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong adjacent_8fd430(undefined8 param_1,uint param_2,long param_3,undefined4 param_4)

{
  ulong uVar1;
  
  uVar1 = 0x37;
  if (param_2 < 0x10001) {
    func_0x00c4bb20(0x3b5c008,0,0,0);
    func_0x002590b0(0x3b4c000,param_1,param_2);
    uVar1 = func_0x00b5d170(param_4,0x3b4c000,0x3b4c000,param_2,param_3 * (ulong)(param_2 >> 0xc));
    if ((int)uVar1 == 0) {
      uVar1 = uVar1 & 0xffffffff;
      func_0x002590b0(param_1,0x3b4c000,param_2);
    }
    if (((_DAT_03b5c020 & 1) == 0) && (0xf < _DAT_03b5c020)) {
      uVar1 = uVar1 & 0xffffffff;
      func_0x00c4c4b0(0x3b5c008,0,0);
    }
  }
  return uVar1;
}



/* adjacent_8fd510 | RVA 0x8fd510 | local helper / adjacent context (reachability below)
 * Evidence ev_a8b24eb336b4ccb01c5c55014731ac5ffc81c110b944d7f6193850f9c2398bb1
 * Body [{"start": "0x8fd510", "end": "0x8fd599"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8
adjacent_8fd510(undefined8 param_1,undefined8 param_2,undefined8 param_3,long param_4,
               undefined4 param_5,undefined8 param_6,undefined8 param_7)

{
  int iVar1;
  undefined8 uVar2;
  bool bVar3;
  
  LOCK();
  iVar1 = _DAT_03b5c000 + 1;
  UNLOCK();
  bVar3 = _DAT_03b5c000 == 0;
  _DAT_03b5c000 = iVar1;
  if (bVar3) {
    func_0x00c4b290(0x3b5c008,"crypt",0);
  }
  if (param_4 == 0) {
    uVar2 = 0x16;
  }
  else {
    uVar2 = func_0x00b5cae0(param_6,param_7,param_1,param_2,param_3,param_4,param_5);
  }
  return uVar2;
}



/* adjacent_8fd5a0 | RVA 0x8fd5a0 | local helper / adjacent context (reachability below)
 * Evidence ev_c402b33b1393d9ce343f63b5074c26fce3e5442f723f47421d27b047ac80350c
 * Body [{"start": "0x8fd5a0", "end": "0x8fd629"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8
adjacent_8fd5a0(undefined8 param_1,undefined8 param_2,undefined8 param_3,long param_4,
               undefined4 param_5,undefined8 param_6,undefined8 param_7)

{
  int iVar1;
  undefined8 uVar2;
  bool bVar3;
  
  LOCK();
  iVar1 = _DAT_03b5c000 + 1;
  UNLOCK();
  bVar3 = _DAT_03b5c000 == 0;
  _DAT_03b5c000 = iVar1;
  if (bVar3) {
    func_0x00c4b290(0x3b5c008,"crypt",0);
  }
  if (param_4 == 0) {
    uVar2 = 0x16;
  }
  else {
    uVar2 = func_0x00b5cb40(param_6,param_7,param_1,param_2,param_3,param_4,param_5);
  }
  return uVar2;
}



/* adjacent_8fd646 | RVA 0x8fd646 | local helper / adjacent context (reachability below)
 * Evidence ev_7f7cb4905600f08f48708e15829cd75e7f8841774d0567385d6b14cd5be588e2
 * Body [{"start": "0x8fd646", "end": "0x8fd66e"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void adjacent_8fd646(void)

{
  func_0x00261090(0x3b5c008);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* adjacent_8fd670 | RVA 0x8fd670 | local helper / adjacent context (reachability below)
 * Evidence ev_c351497140e2a824ea34c68244d525dd19bee7f4e065ad6dacf2b0fa99506fd5
 * Body [{"start": "0x8fd670", "end": "0x8fd679"}, {"start": "0x8fd680", "end": "0x8fd6db"}, {"start": "0x8fd6e0", "end": "0x8fd84c"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void adjacent_8fd670(long *param_1,long *param_2)

{
  long *plVar1;
  long lVar2;
  long lVar3;
  long *plVar4;
  long *plVar5;
  long *plVar6;
  undefined8 *puVar7;
  
  plVar4 = (long *)param_2[2];
  do {
    if ((plVar4 == (long *)0x0) || ((int)plVar4[3] != 1)) {
      *(undefined4 *)(*param_1 + 0x18) = 0;
      return;
    }
    plVar1 = (long *)plVar4[2];
    plVar6 = (long *)*plVar1;
    plVar5 = param_2;
    if (plVar4 == plVar6) {
      plVar6 = (long *)plVar1[1];
      if ((plVar6 != (long *)0x0) && (*(int *)((long)plVar6 + 0x18) == 1)) goto LAB_008fd680;
      plVar6 = (long *)plVar4[1];
      if (plVar6 == param_2) {
        lVar2 = *plVar6;
        plVar4[1] = lVar2;
        if (lVar2 == 0) {
          plVar6[2] = (long)plVar1;
          puVar7 = (undefined8 *)plVar4[2];
          if (plVar4 != (long *)*puVar7) goto LAB_008fd759;
LAB_008fd7e1:
          *puVar7 = plVar6;
        }
        else {
          *(long **)(lVar2 + 0x10) = plVar4;
          puVar7 = (undefined8 *)plVar4[2];
          plVar6[2] = (long)puVar7;
          if (puVar7 == (undefined8 *)0x0) {
            *param_1 = (long)plVar6;
          }
          else {
            if (plVar4 == (long *)*puVar7) goto LAB_008fd7e1;
LAB_008fd759:
            puVar7[1] = plVar6;
          }
        }
        *plVar6 = (long)plVar4;
        plVar4[2] = (long)plVar6;
        plVar5 = plVar4;
        plVar4 = param_2;
      }
      *(undefined4 *)(plVar4 + 3) = 0;
      *(undefined4 *)(plVar1 + 3) = 1;
      lVar2 = *plVar1;
      lVar3 = *(long *)(lVar2 + 8);
      *plVar1 = lVar3;
      if (lVar3 != 0) {
        *(long **)(lVar3 + 0x10) = plVar1;
      }
      plVar4 = (long *)plVar1[2];
      *(long **)(lVar2 + 0x10) = plVar4;
      if (plVar4 == (long *)0x0) {
        *param_1 = lVar2;
      }
      else if (plVar1 == (long *)*plVar4) {
        *plVar4 = lVar2;
      }
      else {
        plVar4[1] = lVar2;
      }
      *(long **)(lVar2 + 8) = plVar1;
      plVar1[2] = lVar2;
    }
    else if ((plVar6 == (long *)0x0) || (*(int *)(plVar6 + 3) != 1)) {
      plVar6 = (long *)*plVar4;
      if (plVar6 == param_2) {
        lVar2 = plVar6[1];
        *plVar4 = lVar2;
        if (lVar2 == 0) {
          plVar6[2] = (long)plVar1;
          puVar7 = (undefined8 *)plVar4[2];
          if (plVar4 != (long *)*puVar7) goto LAB_008fd725;
LAB_008fd76f:
          *puVar7 = plVar6;
        }
        else {
          *(long **)(lVar2 + 0x10) = plVar4;
          puVar7 = (undefined8 *)plVar4[2];
          plVar6[2] = (long)puVar7;
          if (puVar7 == (undefined8 *)0x0) {
            *param_1 = (long)plVar6;
          }
          else {
            if (plVar4 == (long *)*puVar7) goto LAB_008fd76f;
LAB_008fd725:
            puVar7[1] = plVar6;
          }
        }
        plVar6[1] = (long)plVar4;
        plVar4[2] = (long)plVar6;
        plVar5 = plVar4;
        plVar4 = param_2;
      }
      *(undefined4 *)(plVar4 + 3) = 0;
      *(undefined4 *)(plVar1 + 3) = 1;
      plVar4 = (long *)plVar1[1];
      lVar2 = *plVar4;
      plVar1[1] = lVar2;
      if (lVar2 != 0) {
        *(long **)(lVar2 + 0x10) = plVar1;
      }
      puVar7 = (undefined8 *)plVar1[2];
      plVar4[2] = (long)puVar7;
      if (puVar7 == (undefined8 *)0x0) {
        *param_1 = (long)plVar4;
      }
      else if (plVar1 == (long *)*puVar7) {
        *puVar7 = plVar4;
      }
      else {
        puVar7[1] = plVar4;
      }
      *plVar4 = (long)plVar1;
      plVar1[2] = (long)plVar4;
    }
    else {
LAB_008fd680:
      *(undefined4 *)((long)plVar6 + 0x18) = 0;
      *(undefined4 *)(plVar4 + 3) = 0;
      *(undefined4 *)(plVar1 + 3) = 1;
      plVar5 = plVar1;
    }
    plVar4 = (long *)plVar5[2];
    param_2 = plVar5;
  } while( true );
}



/* adjacent_8fd850 | RVA 0x8fd850 | local helper / adjacent context (reachability below)
 * Evidence ev_faf53e1f5c15f29592c3f5b530d2e1b96fac32c61f7263e5b230c26246fea4db
 * Body [{"start": "0x8fd850", "end": "0x8fd942"}, {"start": "0x8fd950", "end": "0x8fd9c3"}, {"start": "0x8fd9d0", "end": "0x8fdc29"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void adjacent_8fd850(long *param_1,long *param_2)

{
  long lVar1;
  undefined8 *puVar2;
  long lVar3;
  long *plVar4;
  long *plVar5;
  long *plVar6;
  int iVar7;
  
  plVar4 = (long *)param_2[1];
  if ((long *)*param_2 == (long *)0x0) {
    plVar5 = (long *)param_2[2];
    iVar7 = (int)param_2[3];
    if (plVar4 != (long *)0x0) goto LAB_008fd8b8;
    plVar4 = (long *)0x0;
  }
  else {
    if (plVar4 != (long *)0x0) {
      do {
        plVar6 = plVar4;
        plVar4 = (long *)*plVar6;
      } while ((long *)*plVar6 != (long *)0x0);
      plVar4 = (long *)plVar6[1];
      plVar5 = (long *)plVar6[2];
      iVar7 = (int)plVar6[3];
      if (plVar4 != (long *)0x0) {
        plVar4[2] = (long)plVar5;
      }
      if (plVar5 == (long *)0x0) {
        *param_1 = (long)plVar4;
      }
      else if ((long *)*plVar5 == plVar6) {
        *plVar5 = (long)plVar4;
      }
      else {
        plVar5[1] = (long)plVar4;
      }
      plVar6[3] = param_2[3];
      if ((long *)plVar6[2] == param_2) {
        plVar5 = plVar6;
      }
      plVar6[2] = param_2[2];
      lVar1 = *param_2;
      plVar6[1] = param_2[1];
      *plVar6 = lVar1;
      puVar2 = (undefined8 *)param_2[2];
      if (puVar2 == (undefined8 *)0x0) {
        *param_1 = (long)plVar6;
      }
      else if ((long *)*puVar2 == param_2) {
        *puVar2 = plVar6;
      }
      else {
        puVar2[1] = plVar6;
      }
      *(long **)(*param_2 + 0x10) = plVar6;
      if (param_2[1] != 0) {
        *(long **)(param_2[1] + 0x10) = plVar6;
      }
      goto LAB_008fd93d;
    }
    plVar5 = (long *)param_2[2];
    iVar7 = (int)param_2[3];
    plVar4 = (long *)*param_2;
LAB_008fd8b8:
    plVar4[2] = (long)plVar5;
  }
  if (plVar5 == (long *)0x0) {
    plVar5 = (long *)0x0;
    *param_1 = (long)plVar4;
  }
  else if ((long *)*plVar5 == param_2) {
    *plVar5 = (long)plVar4;
  }
  else {
    plVar5[1] = (long)plVar4;
  }
LAB_008fd93d:
  if (iVar7 == 0) {
    while( true ) {
      if ((plVar4 != (long *)0x0) && ((int)plVar4[3] != 0)) goto LAB_008fdbab;
      if (plVar4 == (long *)*param_1) goto LAB_008fdba2;
      plVar6 = (long *)*plVar5;
      if (plVar6 == plVar4) {
        plVar6 = (long *)plVar5[1];
        if ((int)plVar6[3] == 1) {
          *(undefined4 *)(plVar6 + 3) = 0;
          *(undefined4 *)(plVar5 + 3) = 1;
          plVar4 = (long *)plVar5[1];
          lVar1 = *plVar4;
          plVar5[1] = lVar1;
          if (lVar1 != 0) {
            *(long **)(lVar1 + 0x10) = plVar5;
          }
          puVar2 = (undefined8 *)plVar5[2];
          plVar4[2] = (long)puVar2;
          if (puVar2 == (undefined8 *)0x0) {
            *param_1 = (long)plVar4;
          }
          else if (plVar5 == (long *)*puVar2) {
            *puVar2 = plVar4;
          }
          else {
            puVar2[1] = plVar4;
          }
          *plVar4 = (long)plVar5;
          plVar5[2] = (long)plVar4;
          plVar6 = (long *)plVar5[1];
        }
        lVar1 = *plVar6;
        if ((lVar1 == 0) || (*(int *)(lVar1 + 0x18) == 0)) {
          if ((plVar6[1] == 0) || (*(int *)(plVar6[1] + 0x18) == 0)) goto LAB_008fd950;
        }
        else if ((plVar6[1] == 0) || (*(int *)(plVar6[1] + 0x18) == 0)) {
          *(undefined4 *)(lVar1 + 0x18) = 0;
          lVar1 = *plVar6;
          *(undefined4 *)(plVar6 + 3) = 1;
          lVar3 = *(long *)(lVar1 + 8);
          *plVar6 = lVar3;
          if (lVar3 != 0) {
            *(long **)(lVar3 + 0x10) = plVar6;
          }
          plVar4 = (long *)plVar6[2];
          *(long **)(lVar1 + 0x10) = plVar4;
          if (plVar4 == (long *)0x0) {
            *param_1 = lVar1;
          }
          else if (plVar6 == (long *)*plVar4) {
            *plVar4 = lVar1;
          }
          else {
            plVar4[1] = lVar1;
          }
          *(long **)(lVar1 + 8) = plVar6;
          plVar6[2] = lVar1;
          plVar6 = (long *)plVar5[1];
        }
        *(int *)(plVar6 + 3) = (int)plVar5[3];
        *(undefined4 *)(plVar5 + 3) = 0;
        if (plVar6[1] != 0) {
          *(undefined4 *)(plVar6[1] + 0x18) = 0;
        }
        plVar4 = (long *)plVar5[1];
        lVar1 = *plVar4;
        plVar5[1] = lVar1;
        if (lVar1 != 0) {
          *(long **)(lVar1 + 0x10) = plVar5;
        }
        puVar2 = (undefined8 *)plVar5[2];
        plVar4[2] = (long)puVar2;
        if (puVar2 == (undefined8 *)0x0) {
          *param_1 = (long)plVar4;
          *plVar4 = (long)plVar5;
        }
        else if (plVar5 == (long *)*puVar2) {
          *puVar2 = plVar4;
          *plVar4 = (long)plVar5;
        }
        else {
          puVar2[1] = plVar4;
          *plVar4 = (long)plVar5;
        }
        goto LAB_008fdb9b;
      }
      if ((int)plVar6[3] == 1) {
        *(undefined4 *)(plVar6 + 3) = 0;
        *(undefined4 *)(plVar5 + 3) = 1;
        lVar1 = *plVar5;
        lVar3 = *(long *)(lVar1 + 8);
        *plVar5 = lVar3;
        if (lVar3 != 0) {
          *(long **)(lVar3 + 0x10) = plVar5;
        }
        plVar4 = (long *)plVar5[2];
        *(long **)(lVar1 + 0x10) = plVar4;
        if (plVar4 == (long *)0x0) {
          *param_1 = lVar1;
        }
        else if (plVar5 == (long *)*plVar4) {
          *plVar4 = lVar1;
        }
        else {
          plVar4[1] = lVar1;
        }
        *(long **)(lVar1 + 8) = plVar5;
        plVar5[2] = lVar1;
        plVar6 = (long *)*plVar5;
      }
      lVar1 = *plVar6;
      if ((lVar1 != 0) && (*(int *)(lVar1 + 0x18) != 0)) goto LAB_008fdb48;
      lVar3 = plVar6[1];
      if ((lVar3 != 0) && (*(int *)(lVar3 + 0x18) != 0)) break;
LAB_008fd950:
      *(undefined4 *)(plVar6 + 3) = 1;
      plVar4 = plVar5;
      plVar5 = (long *)plVar5[2];
    }
    if ((lVar1 == 0) || (*(int *)(lVar1 + 0x18) == 0)) {
      *(undefined4 *)(lVar3 + 0x18) = 0;
      plVar4 = (long *)plVar6[1];
      *(undefined4 *)(plVar6 + 3) = 1;
      lVar1 = *plVar4;
      plVar6[1] = lVar1;
      if (lVar1 != 0) {
        *(long **)(lVar1 + 0x10) = plVar6;
      }
      puVar2 = (undefined8 *)plVar6[2];
      plVar4[2] = (long)puVar2;
      if (puVar2 == (undefined8 *)0x0) {
        *param_1 = (long)plVar4;
      }
      else if (plVar6 == (long *)*puVar2) {
        *puVar2 = plVar4;
      }
      else {
        puVar2[1] = plVar4;
      }
      *plVar4 = (long)plVar6;
      plVar6[2] = (long)plVar4;
      plVar6 = (long *)*plVar5;
    }
LAB_008fdb48:
    *(int *)(plVar6 + 3) = (int)plVar5[3];
    *(undefined4 *)(plVar5 + 3) = 0;
    if (*plVar6 != 0) {
      *(undefined4 *)(*plVar6 + 0x18) = 0;
    }
    plVar4 = (long *)*plVar5;
    lVar1 = plVar4[1];
    *plVar5 = lVar1;
    if (lVar1 != 0) {
      *(long **)(lVar1 + 0x10) = plVar5;
    }
    puVar2 = (undefined8 *)plVar5[2];
    plVar4[2] = (long)puVar2;
    if (puVar2 == (undefined8 *)0x0) {
      *param_1 = (long)plVar4;
    }
    else if (plVar5 == (long *)*puVar2) {
      *puVar2 = plVar4;
    }
    else {
      puVar2[1] = plVar4;
    }
    plVar4[1] = (long)plVar5;
LAB_008fdb9b:
    plVar5[2] = (long)plVar4;
    plVar4 = (long *)*param_1;
LAB_008fdba2:
    if (plVar4 != (long *)0x0) {
LAB_008fdbab:
      *(undefined4 *)(plVar4 + 3) = 0;
      return;
    }
  }
  return;
}



/* adjacent_8fdc30 | RVA 0x8fdc30 | local helper / adjacent context (reachability below)
 * Evidence ev_edf39784269d1966e5a53b987dd35334e63ced2c5ad19d0a5a837ae78fe44455
 * Body [{"start": "0x8fdc30", "end": "0x8fdc47"}, {"start": "0x8fdc50", "end": "0x8fdc7e"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

long * adjacent_8fdc30(long *param_1,long param_2)

{
  int iVar1;
  
  param_1 = (long *)*param_1;
  if (param_1 != (long *)0x0) {
    do {
      iVar1 = func_0x00339bd0(param_2 + 0x20,param_1 + 4,0x10);
      if (-1 < iVar1) {
        if (iVar1 == 0) {
          return param_1;
        }
        param_1 = param_1 + 1;
      }
      param_1 = (long *)*param_1;
    } while (param_1 != (long *)0x0);
  }
  return (long *)0x0;
}



/* adjacent_8fdc80 | RVA 0x8fdc80 | local helper / adjacent context (reachability below)
 * Evidence ev_8f426ee8f080e7bdd5c233f6e8f75b715dfdce3d20e4e19bf6f883d858e630ba
 * Body [{"start": "0x8fdc80", "end": "0x8fdcc7"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

long * adjacent_8fdc80(long *param_1)

{
  long *plVar1;
  long *plVar2;
  bool bVar3;
  
  plVar1 = (long *)param_1[1];
  if ((long *)param_1[1] == (long *)0x0) {
    plVar2 = (long *)param_1[2];
    if ((plVar2 == (long *)0x0) || (param_1 != (long *)*plVar2)) {
      do {
        plVar2 = (long *)param_1[2];
        if (plVar2 == (long *)0x0) {
          return (long *)0x0;
        }
        bVar3 = param_1 == (long *)plVar2[1];
        param_1 = plVar2;
      } while (bVar3);
    }
  }
  else {
    do {
      plVar2 = plVar1;
      plVar1 = (long *)*plVar2;
    } while ((long *)*plVar2 != (long *)0x0);
  }
  return plVar2;
}



/* adjacent_8fdcd8 | RVA 0x8fdcd8 | local helper / adjacent context (reachability below)
 * Evidence ev_51406acf2fb7ce312113bfaa5574a56b3f8029c228de7a447d88b326096166f7
 * Body [{"start": "0x8fdcd8", "end": "0x8fdcfd"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

long adjacent_8fdcd8(undefined8 param_1,uint param_2,undefined8 param_3,long param_4)

{
  long lVar1;
  
  do {
    lVar1 = param_4;
    param_4 = *(long *)(param_4 + (ulong)((~param_2 >> 0x1f) << 3));
  } while (param_4 != 0);
  return lVar1;
}



/* adjacent_8fdd10 | RVA 0x8fdd10 | local helper / adjacent context (reachability below)
 * Evidence ev_fd1f094ae678fdd1f0e01ea17624385d555c25cb149820377955e45fade2a35e
 * Body [{"start": "0x8fdd10", "end": "0x8fdd62"}, {"start": "0x8fdd70", "end": "0x8fde02"}, {"start": "0x8fde10", "end": "0x8fde6e"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 adjacent_8fdd10(long param_1,long param_2,long param_3,long param_4)

{
  char cVar1;
  ushort uVar2;
  long lVar3;
  code *pcVar4;
  int iVar5;
  undefined8 uVar6;
  long lVar7;
  undefined8 *puVar8;
  long *plVar9;
  undefined8 local_58;
  undefined8 local_50;
  long local_38;
  
  local_38 = _DAT_0391c310;
  uVar6 = 1;
  plVar9 = *(long **)(param_1 + 0x10);
  if ((plVar9 != (long *)0x0) && (uVar2 = *(ushort *)(param_1 + 10), uVar2 != 0)) {
    lVar7 = 0;
    do {
      lVar3 = *plVar9;
      if ((lVar3 != 0) &&
         (((param_2 == 0 || (*(long *)(lVar3 + 0x20) == param_2)) &&
          (iVar5 = func_0x00259080(lVar3 + 0x10,param_3 + 8,0x10), iVar5 == 0)))) {
        lVar3 = *(long *)(param_1 + 0x18);
        local_58 = *(undefined8 *)(param_4 + 8);
        local_50 = *(undefined8 *)(param_4 + 0x10);
        cVar1 = *(char *)(lVar3 + 0x11 + lVar7);
        func_0x00b82870(&local_58);
        puVar8 = *(undefined8 **)(lVar3 + lVar7);
        goto LAB_008fde17;
      }
      plVar9 = plVar9 + 1;
      lVar7 = lVar7 + 0x18;
    } while ((uint)uVar2 * 0x18 != (int)lVar7);
    uVar6 = 1;
  }
  goto LAB_008fddb3;
LAB_008fde17:
  if (puVar8 == (undefined8 *)0x0) goto LAB_008fde4b;
  iVar5 = func_0x00339bd0(&local_58,puVar8 + 4,0x10);
  if (-1 < iVar5) {
    if (iVar5 == 0) {
      uVar6 = 2;
      if (*(char *)(puVar8 + 6) == cVar1) goto LAB_008fde61;
      goto LAB_008fddb3;
    }
    puVar8 = puVar8 + 1;
  }
  puVar8 = (undefined8 *)*puVar8;
  goto LAB_008fde17;
LAB_008fde4b:
  uVar6 = 2;
  if (cVar1 != '\x01') {
LAB_008fde61:
    uVar6 = 0;
  }
LAB_008fddb3:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar4 = (code *)invalidInstructionException();
    (*pcVar4)();
  }
  return uVar6;
}



/* adjacent_8fde70 | RVA 0x8fde70 | local helper / adjacent context (reachability below)
 * Evidence ev_1c30186cf755d873f732df6e0b97139b300313ce2ac909680bacf1d82ab55585
 * Body [{"start": "0x8fde70", "end": "0x8fdea6"}, {"start": "0x8fdeb0", "end": "0x8fdefa"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

long adjacent_8fde70(long param_1,long param_2,long param_3)

{
  ushort uVar1;
  long lVar2;
  long lVar3;
  int iVar4;
  long lVar5;
  
  lVar2 = *(long *)(param_1 + 0x10);
  lVar5 = -1;
  if ((lVar2 != 0) && (uVar1 = *(ushort *)(param_1 + 10), uVar1 != 0)) {
    lVar5 = 0;
    do {
      lVar3 = *(long *)(lVar2 + lVar5 * 8);
      if ((lVar3 != 0) &&
         (((param_2 == 0 || (*(long *)(lVar3 + 0x20) == param_2)) &&
          (iVar4 = func_0x00259080(lVar3 + 0x10,param_3 + 8,0x10), iVar4 == 0)))) goto LAB_008fdee9;
      lVar5 = lVar5 + 1;
    } while ((uint)uVar1 != (uint)lVar5);
    lVar5 = 0xffffffff;
LAB_008fdee9:
    lVar5 = (long)(int)lVar5;
  }
  return lVar5;
}



/* adjacent_8fdf00 | RVA 0x8fdf00 | local helper / adjacent context (reachability below)
 * Evidence ev_b5d986dc2973fd9329b20ef882efd356624611dec079edb172779f1da62fd255
 * Body [{"start": "0x8fdf00", "end": "0x8fdf4b"}, {"start": "0x8fdf50", "end": "0x8fdf96"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 * adjacent_8fdf00(long param_1,long param_2,long param_3)

{
  long lVar1;
  code *pcVar2;
  int iVar3;
  undefined8 *puVar4;
  undefined8 local_50;
  undefined8 local_48;
  long local_30;
  
  local_30 = _DAT_0391c310;
  lVar1 = *(long *)(param_1 + 0x18);
  if (lVar1 != 0) {
    local_50 = *(undefined8 *)(param_3 + 8);
    local_48 = *(undefined8 *)(param_3 + 0x10);
    func_0x00b82870(&local_50);
    for (puVar4 = *(undefined8 **)(lVar1 + param_2 * 0x18); puVar4 != (undefined8 *)0x0;
        puVar4 = (undefined8 *)*puVar4) {
      iVar3 = func_0x00339bd0(&local_50,puVar4 + 4,0x10);
      if (-1 < iVar3) {
        if (iVar3 == 0) goto LAB_008fdf77;
        puVar4 = puVar4 + 1;
      }
    }
  }
  puVar4 = (undefined8 *)0x0;
LAB_008fdf77:
  if (_DAT_0391c310 == local_30) {
    return puVar4;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar2 = (code *)invalidInstructionException();
  (*pcVar2)();
}



/* FUN_008fdfa0 | RVA 0x8fdfa0 | local helper / adjacent context (reachability below)
 * Evidence ev_bb1b5f554b545e244f436f5c38c48279e5b7f3102b3dc4345ef97c04aa0f58b0
 * Body [{"start": "0x8fdfa0", "end": "0x8fdfa5"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void FUN_008fdfa0(long param_1)

{
  int *piVar1;
  long lVar2;
  long *plVar3;
  long *plVar4;
  long *plVar5;
  bool bVar6;
  
  piVar1 = (int *)(param_1 + 0x30);
  *piVar1 = *piVar1 + -1;
  if (*piVar1 != 0) {
    return;
  }
  *(undefined8 *)(*(long *)(param_1 + 0x28) + 0x30) = 0;
  if (*(long **)(param_1 + 0x50) != (long *)0x0) {
    plVar3 = *(long **)(param_1 + 0x50);
    do {
      plVar5 = plVar3;
      plVar3 = (long *)*plVar5;
    } while ((long *)*plVar5 != (long *)0x0);
    do {
      plVar3 = (long *)plVar5[1];
      if ((long *)plVar5[1] == (long *)0x0) {
        plVar4 = (long *)plVar5[2];
        plVar3 = plVar5;
        if ((plVar4 == (long *)0x0) || (plVar5 != (long *)*plVar4)) {
          do {
            plVar4 = (long *)plVar3[2];
            if (plVar4 == (long *)0x0) {
              plVar4 = (long *)0x0;
              break;
            }
            bVar6 = plVar3 == (long *)plVar4[1];
            plVar3 = plVar4;
          } while (bVar6);
        }
      }
      else {
        do {
          plVar4 = plVar3;
          plVar3 = (long *)*plVar4;
        } while ((long *)*plVar4 != (long *)0x0);
      }
      adjacent_8fd850(param_1 + 0x50,plVar5);
      func_0x00c08df0(plVar5,0x254f0a0);
      *(long *)(param_1 + 0x58) = *(long *)(param_1 + 0x58) + -1;
      plVar5 = plVar4;
    } while (plVar4 != (long *)0x0);
  }
  lVar2 = *(long *)(param_1 + 0x60);
  *(undefined8 *)(param_1 + 0x60) = 0;
  *(long *)(param_1 + 0x68) = param_1 + 0x60;
  *(undefined4 *)(param_1 + 0x70) = 0;
  while (lVar2 != 0) {
    lVar2 = *(long *)(lVar2 + 8);
    func_0x0042a850();
  }
  func_0x00c08df0(param_1,0x254f080);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* adjacent_8fdfa6 | RVA 0x8fdfa6 | local helper / adjacent context (reachability below)
 * Evidence ev_a8a3ae9ce4b9a0c08377d581c8b966611c6775fc4940684616c55f74fea18a18
 * Body [{"start": "0x8fdfa6", "end": "0x8fe03c"}, {"start": "0x8fe040", "end": "0x8fe0d6"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void adjacent_8fdfa6(long param_1)

{
  long lVar1;
  long *plVar2;
  long *plVar3;
  long *plVar4;
  bool bVar5;
  
  *(undefined8 *)(*(long *)(param_1 + 0x28) + 0x30) = 0;
  if (*(long **)(param_1 + 0x50) != (long *)0x0) {
    plVar2 = *(long **)(param_1 + 0x50);
    do {
      plVar4 = plVar2;
      plVar2 = (long *)*plVar4;
    } while ((long *)*plVar4 != (long *)0x0);
    do {
      plVar2 = (long *)plVar4[1];
      if ((long *)plVar4[1] == (long *)0x0) {
        plVar3 = (long *)plVar4[2];
        plVar2 = plVar4;
        if ((plVar3 == (long *)0x0) || (plVar4 != (long *)*plVar3)) {
          do {
            plVar3 = (long *)plVar2[2];
            if (plVar3 == (long *)0x0) {
              plVar3 = (long *)0x0;
              break;
            }
            bVar5 = plVar2 == (long *)plVar3[1];
            plVar2 = plVar3;
          } while (bVar5);
        }
      }
      else {
        do {
          plVar3 = plVar2;
          plVar2 = (long *)*plVar3;
        } while ((long *)*plVar3 != (long *)0x0);
      }
      adjacent_8fd850(param_1 + 0x50,plVar4);
      func_0x00c08df0(plVar4,0x254f0a0);
      *(long *)(param_1 + 0x58) = *(long *)(param_1 + 0x58) + -1;
      plVar4 = plVar3;
    } while (plVar3 != (long *)0x0);
  }
  lVar1 = *(long *)(param_1 + 0x60);
  *(undefined8 *)(param_1 + 0x60) = 0;
  *(long *)(param_1 + 0x68) = param_1 + 0x60;
  *(undefined4 *)(param_1 + 0x70) = 0;
  while (lVar1 != 0) {
    lVar1 = *(long *)(lVar1 + 8);
    func_0x0042a850();
  }
  func_0x00c08df0(param_1,0x254f080);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* adjacent_8fe0e9 | RVA 0x8fe0e9 | local helper / adjacent context (reachability below)
 * Evidence ev_2449df965bcac8d07876523e47ee318441329000b0f6d02f7ce058c54005d109
 * Body [{"start": "0x8fe0e9", "end": "0x8fe12c"}, {"start": "0x8fe130", "end": "0x8fe155"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void adjacent_8fe0e9(long param_1)

{
  long *plVar1;
  long *in_RAX;
  long *plVar2;
  long *plVar3;
  bool bVar4;
  
  do {
    plVar3 = in_RAX;
    in_RAX = (long *)*plVar3;
  } while ((long *)*plVar3 != (long *)0x0);
  do {
    do {
      while( true ) {
        if ((char)plVar3[7] != '\0') {
          *(undefined1 *)(plVar3 + 7) = 0;
          *(short *)(param_1 + 0x9e) = *(short *)(param_1 + 0x9e) + -1;
        }
        plVar1 = (long *)plVar3[1];
        if ((long *)plVar3[1] == (long *)0x0) break;
        do {
          plVar3 = plVar1;
          plVar1 = (long *)*plVar3;
        } while ((long *)*plVar3 != (long *)0x0);
      }
      plVar1 = (long *)plVar3[2];
      plVar2 = plVar3;
    } while ((plVar1 != (long *)0x0) && (bVar4 = plVar3 == (long *)*plVar1, plVar3 = plVar1, bVar4))
    ;
    do {
      plVar3 = (long *)plVar2[2];
      if (plVar3 == (long *)0x0) {
        return;
      }
      bVar4 = plVar2 == (long *)plVar3[1];
      plVar2 = plVar3;
    } while (bVar4);
  } while( true );
}



/* adjacent_8fe160 | RVA 0x8fe160 | local helper / adjacent context (reachability below)
 * Evidence ev_92fd1003ada597ce438867ce6622a15233e65c19f4865369547cffa61794dcc1
 * Body [{"start": "0x8fe160", "end": "0x8fe19a"}, {"start": "0x8fe1a0", "end": "0x8fe223"}, {"start": "0x8fe230", "end": "0x8fe327"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 adjacent_8fe160(long param_1,undefined8 *param_2)

{
  undefined8 *puVar1;
  code *pcVar2;
  undefined8 *puVar3;
  char cVar4;
  int iVar5;
  undefined8 *puVar6;
  undefined8 *puVar7;
  undefined8 uVar8;
  undefined8 local_58;
  undefined8 local_50;
  long local_38;
  
  local_38 = _DAT_0391c310;
  local_58 = *param_2;
  local_50 = param_2[1];
  for (puVar6 = *(undefined8 **)(param_1 + 0x50); puVar6 != (undefined8 *)0x0;
      puVar6 = (undefined8 *)*puVar6) {
    iVar5 = func_0x00339bd0(&local_58,puVar6 + 4,0x10);
    if (-1 < iVar5) {
      if (iVar5 == 0) {
        uVar8 = 0;
        if (*(char *)(puVar6 + 7) != '\0') goto LAB_008fe309;
        cVar4 = '\x01';
        goto LAB_008fe2f9;
      }
      puVar6 = puVar6 + 1;
    }
  }
  uVar8 = 0xffffffe4;
  if (*(long *)(param_1 + 0x58) != 0x200) {
    puVar6 = (undefined8 *)func_0x00c08b50(0x40,0x254f0a0,0x101);
    if (puVar6 == (undefined8 *)0x0) {
      uVar8 = 0xfffffff4;
    }
    else {
      puVar1 = (undefined8 *)(param_1 + 0x50);
      puVar6[5] = local_50;
      puVar6[4] = local_58;
      if ((undefined8 *)*puVar1 == (undefined8 *)0x0) {
        puVar6[2] = 0;
        puVar6[1] = 0;
        *puVar6 = 0;
        *(undefined4 *)(puVar6 + 3) = 1;
        *puVar1 = puVar6;
      }
      else {
        puVar3 = (undefined8 *)*puVar1;
        do {
          while( true ) {
            puVar7 = puVar3;
            iVar5 = func_0x00339bd0(puVar6 + 4,puVar7 + 4,0x10);
            if (iVar5 < 0) break;
            if (iVar5 == 0) goto LAB_008fe2e7;
            puVar3 = (undefined8 *)puVar7[1];
            if ((undefined8 *)puVar7[1] == (undefined8 *)0x0) {
              puVar6[2] = puVar7;
              puVar6[1] = 0;
              *puVar6 = 0;
              *(undefined4 *)(puVar6 + 3) = 1;
              puVar7[1] = puVar6;
              goto LAB_008fe2dc;
            }
          }
          puVar3 = (undefined8 *)*puVar7;
        } while ((undefined8 *)*puVar7 != (undefined8 *)0x0);
        puVar6[2] = puVar7;
        puVar6[1] = 0;
        *puVar6 = 0;
        *(undefined4 *)(puVar6 + 3) = 1;
        *puVar7 = puVar6;
      }
LAB_008fe2dc:
      adjacent_8fd670(puVar1,puVar6);
LAB_008fe2e7:
      *(long *)(param_1 + 0x58) = *(long *)(param_1 + 0x58) + 1;
      cVar4 = *(char *)(puVar6 + 7) + '\x01';
LAB_008fe2f9:
      *(char *)(puVar6 + 7) = cVar4;
      *(short *)(param_1 + 0x9e) = *(short *)(param_1 + 0x9e) + 1;
      uVar8 = 1;
    }
  }
LAB_008fe309:
  if (_DAT_0391c310 == local_38) {
    return uVar8;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar2 = (code *)invalidInstructionException();
  (*pcVar2)();
}



/* adjacent_8fe330 | RVA 0x8fe330 | local helper / adjacent context (reachability below)
 * Evidence ev_8095733cc2092fb3c228476b16eec6e2befa49b0506cbe39fc89c54480962450
 * Body [{"start": "0x8fe330", "end": "0x8fe38c"}, {"start": "0x8fe390", "end": "0x8fe3d6"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void adjacent_8fe330(long param_1)

{
  long *plVar1;
  long *plVar2;
  long *plVar3;
  bool bVar4;
  
  adjacent_8fe3e0();
  plVar2 = *(long **)(param_1 + 0x50);
  if (plVar2 == (long *)0x0) {
LAB_008fe3b4:
    *(undefined2 *)(param_1 + 0x94) = *(undefined2 *)(param_1 + 0x9e);
    *(undefined8 *)(param_1 + 0x8c) = *(undefined8 *)(param_1 + 0x96);
    return;
  }
  do {
    plVar3 = (long *)*plVar2;
    plVar1 = plVar2;
    plVar2 = plVar3;
  } while (plVar3 != (long *)0x0);
  do {
    do {
      while( true ) {
        plVar3 = plVar1;
        *(undefined4 *)(plVar3 + 6) = *(undefined4 *)((long)plVar3 + 0x34);
        plVar2 = (long *)plVar3[1];
        if (plVar2 == (long *)0x0) break;
        do {
          plVar3 = (long *)*plVar2;
          plVar1 = plVar2;
          plVar2 = plVar3;
        } while (plVar3 != (long *)0x0);
      }
      plVar1 = (long *)plVar3[2];
    } while ((plVar1 != (long *)0x0) && (plVar3 == (long *)*plVar1));
    do {
      plVar1 = (long *)plVar3[2];
      if (plVar1 == (long *)0x0) goto LAB_008fe3b4;
      bVar4 = plVar3 == (long *)plVar1[1];
      plVar3 = plVar1;
    } while (bVar4);
  } while( true );
}



/* adjacent_8fe3e0 | RVA 0x8fe3e0 | local helper / adjacent context (reachability below)
 * Evidence ev_9b7f9c2f4baaad0eadad64f3691d731446339d3e6fc3d41e54b478f6d9d2f321
 * Body [{"start": "0x8fe3e0", "end": "0x8fe575"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void adjacent_8fe3e0(long param_1)

{
  code *pcVar1;
  undefined8 uVar2;
  undefined *puVar3;
  undefined *puVar4;
  undefined1 local_68 [56];
  long local_30;
  
  local_30 = _DAT_0391c310;
  if ((DAT_02bf8953 & 0x10) != 0) {
    func_0x0025d410("%s: --- begin in6m %p ---\n","in6m_print",param_1);
    uVar2 = func_0x00a85f90(local_68,param_1 + 0x10);
    func_0x0025d410("addr %s ifp %p(%s) ifma %p\n",uVar2,*(long *)(param_1 + 0x20),
                    *(long *)(param_1 + 0x20) + 0x60,*(undefined8 *)(param_1 + 0x28));
    puVar4 = &DAT_0139b8ec;
    puVar3 = &DAT_0139b8ec;
    if ((ulong)*(uint *)(param_1 + 0x34) < 10) {
      puVar3 = (undefined *)
               ((long)*(int *)((ulong)*(uint *)(param_1 + 0x34) * 4 + 0x181cb34) + 0x181cb34);
    }
    func_0x0025d410("timer %u state %s refcount %u scq.len %u\n",*(undefined4 *)(param_1 + 0x38),
                    puVar3,*(undefined4 *)(param_1 + 0x30),*(undefined4 *)(param_1 + 0x70));
    func_0x0025d410("mli %p nsrc %lu sctimer %u scrv %u\n",*(undefined8 *)(param_1 + 0x40),
                    *(undefined8 *)(param_1 + 0x58),*(undefined2 *)(param_1 + 0x88),
                    *(undefined2 *)(param_1 + 0x8a));
    puVar3 = &DAT_0139b8ec;
    if ((ulong)*(ushort *)(param_1 + 0x8c) < 3) {
      puVar3 = *(undefined **)((ulong)*(ushort *)(param_1 + 0x8c) * 8 + 0xe8a5b0);
    }
    func_0x0025d410("t%d: fmode %s asm %u ex %u in %u rec %u\n",0,puVar3,
                    *(undefined2 *)(param_1 + 0x8e),*(undefined2 *)(param_1 + 0x90),
                    *(undefined2 *)(param_1 + 0x92),*(undefined2 *)(param_1 + 0x94));
    if ((ulong)*(ushort *)(param_1 + 0x96) < 3) {
      puVar4 = *(undefined **)((ulong)*(ushort *)(param_1 + 0x96) * 8 + 0xe8a5b0);
    }
    func_0x0025d410("t%d: fmode %s asm %u ex %u in %u rec %u\n",1,puVar4,
                    *(undefined2 *)(param_1 + 0x98),*(undefined2 *)(param_1 + 0x9a),
                    *(undefined2 *)(param_1 + 0x9c),*(undefined2 *)(param_1 + 0x9e));
    func_0x0025d410("%s: --- end in6m %p ---\n","in6m_print",param_1);
  }
  if (_DAT_0391c310 == local_30) {
    return;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* adjacent_8fe580 | RVA 0x8fe580 | local helper / adjacent context (reachability below)
 * Evidence ev_50fa97aab5f869cc6455b0d1e09070ea58de8218c2c4f317b9e8bd6171251bd9
 * Body [{"start": "0x8fe580", "end": "0x8fe634"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

long adjacent_8fe580(undefined8 param_1,undefined8 param_2,int *param_3,int param_4)

{
  long lVar1;
  int iVar2;
  long lVar3;
  
  lVar3 = func_0x00c08b50(0x18,0x254f080,1);
  if (lVar3 == 0) {
    *param_3 = 0x37;
  }
  else {
    lVar1 = (long)_DAT_03920440;
    func_0x004c6a00(0x3b5c040,0,0,0);
    iVar2 = adjacent_8fe7b0(param_1,param_2,0,lVar3,(long)(param_4 * 5) / lVar1 & 0xffffffff);
    func_0x004c6fa0(0x3b5c040,0,0,0);
    if (iVar2 == 0) {
      return lVar3;
    }
    *param_3 = iVar2;
    func_0x00c08df0(lVar3,0x254f080);
  }
  return 0;
}



/* adjacent_8fe640 | RVA 0x8fe640 | local helper / adjacent context (reachability below)
 * Evidence ev_ab35d0dbd9e02967246c346477c15cb9342c2ee74d8137abbbd81e015be38859
 * Body [{"start": "0x8fe640", "end": "0x8fe6fa"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 adjacent_8fe640(long *param_1)

{
  long lVar1;
  code *pcVar2;
  undefined8 local_50 [2];
  undefined2 local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  lVar1 = *param_1;
  if (lVar1 != 0) {
    func_0x004c6a00(0x3b5c040,0,0,0);
    func_0x00258ff0(local_50,0x18);
    local_50[0] = 0;
    local_40 = 2;
    adjacent_8fea20(lVar1,local_50);
    func_0x006a5650(lVar1,0);
    FUN_008fdfa0(lVar1);
    func_0x004c6fa0(0x3b5c040,0,0,0);
  }
  func_0x00c08df0(param_1,0x254f080);
  if (_DAT_0391c310 == local_38) {
    return 0;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar2 = (code *)invalidInstructionException();
  (*pcVar2)();
}



/* adjacent_8fe700 | RVA 0x8fe700 | local helper / adjacent context (reachability below)
 * Evidence ev_c8637b38f72633cf899686c1cd5ea1b49783af128220b06f249a082fdf613c95
 * Body [{"start": "0x8fe700", "end": "0x8fe7a6"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 adjacent_8fe700(undefined8 param_1,undefined8 *param_2)

{
  code *pcVar1;
  undefined4 uVar2;
  undefined8 local_40 [2];
  undefined2 local_30;
  long local_28;
  
  local_28 = _DAT_0391c310;
  func_0x004c6a00(0x3b5c040,0,0,0);
  if (param_2 == (undefined8 *)0x0) {
    param_2 = local_40;
    func_0x00258ff0(param_2,0x18);
    local_40[0] = 0;
    local_30 = 2;
  }
  adjacent_8fea20(param_1,param_2);
  uVar2 = func_0x006a5650(param_1,0);
  FUN_008fdfa0(param_1);
  func_0x004c6fa0(0x3b5c040,0,0,0);
  if (_DAT_0391c310 == local_28) {
    return uVar2;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* adjacent_8fe7b0 | RVA 0x8fe7b0 | local helper / adjacent context (reachability below)
 * Evidence ev_6f11c361947793b9000661eb9577898cf95e7f2c15bbab18c29d8081a22d6ee7
 * Body [{"start": "0x8fe7b0", "end": "0x8fe826"}, {"start": "0x8fe830", "end": "0x8fea16"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Type propagation algorithm not settling */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int adjacent_8fe7b0(long param_1,undefined8 *param_2,long *param_3,long *param_4,undefined4 param_5)

{
  long lVar1;
  undefined8 uVar2;
  code *pcVar3;
  int iVar4;
  long lVar5;
  undefined8 *puVar6;
  long local_78 [3];
  undefined2 local_60;
  undefined2 local_54 [4];
  undefined8 local_4c;
  undefined8 local_44;
  long local_38;
  
  local_38 = _DAT_0391c310;
  if (param_3 == (long *)0x0) {
    param_3 = local_78 + 1;
    func_0x00258ff0(param_3,0x18);
    local_78[1] = 0;
    local_60 = 0x200;
  }
  lVar1 = param_1 + 0x278;
  func_0x007d46a0(lVar1,0,0);
  for (puVar6 = *(undefined8 **)(param_1 + 0x290); puVar6 != (undefined8 *)0x0;
      puVar6 = (undefined8 *)*puVar6) {
    if (*(char *)(puVar6[2] + 1) == '\x1c') {
      lVar5 = puVar6[6];
      iVar4 = func_0x00259080(lVar5 + 0x10,param_2,0x10);
      if (iVar4 == 0) {
        if (lVar5 != 0) goto LAB_008fe8c5;
        break;
      }
    }
  }
  func_0x00258ff0(local_54,0x1c);
  local_54[0] = 0x1c1c;
  local_4c = *param_2;
  local_44 = param_2[1];
  func_0x007d4eb0(lVar1,0,0);
  iVar4 = func_0x004be540(param_1,local_54,local_78);
  if (iVar4 == 0) {
    func_0x007d46a0(lVar1,0,0);
    lVar5 = *(long *)(local_78[0] + 0x30);
    if (lVar5 == 0) {
      lVar5 = func_0x00c08b50(0xa0,0x254f080,0x101);
      if (lVar5 == 0) {
        func_0x007d4eb0(lVar1,0,0);
        func_0x004bfb60(local_78[0]);
        iVar4 = 0xc;
        goto LAB_008fe921;
      }
      uVar2 = *param_2;
      *(undefined8 *)(lVar5 + 0x18) = param_2[1];
      *(undefined8 *)(lVar5 + 0x10) = uVar2;
      *(long *)(lVar5 + 0x20) = param_1;
      *(undefined8 *)(lVar5 + 0x40) = *(undefined8 *)(*(long *)(param_1 + 0x3b8) + 0x28);
      *(long *)(lVar5 + 0x28) = local_78[0];
      *(undefined8 *)(lVar5 + 0x30) = 1;
      *(undefined8 *)(lVar5 + 0x60) = 0;
      *(long *)(lVar5 + 0x68) = lVar5 + 0x60;
      *(undefined8 *)(lVar5 + 0x70) = 0x1800000000;
      *(undefined2 *)(lVar5 + 0x8c) = 0;
      *(undefined2 *)(lVar5 + 0x96) = 0;
      *(undefined8 *)(lVar5 + 0x50) = 0;
      *(long *)(local_78[0] + 0x30) = lVar5;
    }
    else {
LAB_008fe8c5:
      *(int *)(lVar5 + 0x30) = *(int *)(lVar5 + 0x30) + 1;
    }
    func_0x007d4eb0(lVar1,0,0);
    if (*(int *)(lVar5 + 0x34) == 9) {
      *(undefined2 *)(lVar5 + 0x8c) = 0;
      *(undefined2 *)(lVar5 + 0x96) = 0;
    }
    iVar4 = adjacent_8fea20(lVar5,param_3);
    if (iVar4 == 0) {
      iVar4 = func_0x006a5650(lVar5,param_5);
      if (iVar4 == 0) {
        iVar4 = 0;
        *param_4 = lVar5;
        goto LAB_008fe921;
      }
    }
    FUN_008fdfa0(lVar5);
  }
LAB_008fe921:
  if (_DAT_0391c310 == local_38) {
    return iVar4;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar3 = (code *)invalidInstructionException();
  (*pcVar3)();
}



/* adjacent_8fea20 | RVA 0x8fea20 | local helper / adjacent context (reachability below)
 * Evidence ev_824c23684a26e5f6f19e41f14177507d13c43dd6459100a67386844580943c9a
 * Body [{"start": "0x8fea20", "end": "0x8feac4"}, {"start": "0x8fead0", "end": "0x8feb05"}, {"start": "0x8feb10", "end": "0x8feb39"}, {"start": "0x8feb40", "end": "0x8feb9a"}, {"start": "0x8feba0", "end": "0x8fed02"}, {"start": "0x8fed10", "end": "0x8fee73"}, {"start": "0x8fee80", "end": "0x8feef4"}, {"start": "0x8fef00", "end": "0x8fefeb"}, {"start": "0x8feff0", "end": "0x8ff034"}, {"start": "0x8ff040", "end": "0x8ff0a8"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 adjacent_8fea20(long param_1,long *param_2)

{
  char cVar1;
  long lVar2;
  code *pcVar3;
  long lVar4;
  int iVar5;
  undefined8 *puVar6;
  undefined8 *puVar7;
  long *plVar8;
  undefined8 *puVar9;
  char cVar10;
  ushort uVar11;
  long *plVar12;
  long lVar13;
  int iVar14;
  long *plVar15;
  int iVar16;
  long *plVar17;
  undefined8 uVar18;
  undefined8 *unaff_R15;
  bool bVar19;
  int local_80;
  undefined1 local_78 [32];
  long local_58;
  long local_50;
  long local_38;
  
  local_38 = _DAT_0391c310;
  plVar8 = (long *)*param_2;
  if ((long *)*param_2 != (long *)0x0) {
    do {
      plVar15 = plVar8;
      plVar8 = (long *)*plVar15;
    } while (plVar8 != (long *)0x0);
    plVar8 = (long *)(param_1 + 0x50);
    iVar16 = 0;
    iVar14 = 0;
    local_80 = 0;
    while( true ) {
      plVar17 = plVar15;
      lVar13 = plVar17[6];
      lVar4 = param_2[2];
      cVar10 = *(char *)((long)plVar17 + 0x31);
      cVar1 = *(char *)((long)param_2 + 0x11);
      if ((char)lVar13 != cVar10) break;
LAB_008fecd1:
      plVar12 = (long *)plVar17[1];
      iVar14 = iVar14 + (uint)((char)lVar13 == (char)lVar4);
      iVar16 = iVar16 + (uint)(cVar10 == cVar1);
      if (plVar12 == (long *)0x0) {
        plVar15 = (long *)plVar17[2];
        if ((plVar15 == (long *)0x0) || (plVar17 != (long *)*plVar15)) {
          do {
            plVar15 = (long *)plVar17[2];
            if (plVar15 == (long *)0x0) {
              bVar19 = iVar14 == 0;
              goto LAB_008fed5d;
            }
            bVar19 = plVar17 == (long *)plVar15[1];
            plVar17 = plVar15;
          } while (bVar19);
        }
      }
      else {
        do {
          plVar17 = (long *)*plVar12;
          plVar15 = plVar12;
          plVar12 = plVar17;
        } while (plVar17 != (long *)0x0);
      }
    }
    local_50 = plVar17[5];
    local_58 = plVar17[4];
    for (puVar6 = (undefined8 *)*plVar8; puVar6 != (undefined8 *)0x0; puVar6 = (undefined8 *)*puVar6
        ) {
      iVar5 = func_0x00339bd0(&local_58,puVar6 + 4,0x10);
      if (-1 < iVar5) {
        if (iVar5 == 0) goto LAB_008fec4c;
        puVar6 = puVar6 + 1;
      }
    }
    if (*(long *)(param_1 + 0x58) == 0x200) {
      uVar18 = 0x1c;
    }
    else {
      puVar6 = (undefined8 *)func_0x00c08b50(0x40,0x254f0a0,0x101);
      if (puVar6 != (undefined8 *)0x0) {
        lVar2 = plVar17[4];
        puVar6[5] = plVar17[5];
        puVar6[4] = lVar2;
        if ((undefined8 *)*plVar8 == (undefined8 *)0x0) {
          puVar6[2] = 0;
          puVar6[1] = 0;
          *puVar6 = 0;
          *(undefined4 *)(puVar6 + 3) = 1;
          *plVar8 = (long)puVar6;
        }
        else {
          puVar9 = (undefined8 *)*plVar8;
          do {
            while( true ) {
              puVar7 = puVar9;
              iVar5 = func_0x00339bd0(puVar6 + 4,puVar7 + 4,0x10);
              if (iVar5 < 0) break;
              if (iVar5 == 0) goto LAB_008fec41;
              puVar9 = (undefined8 *)puVar7[1];
              if ((undefined8 *)puVar7[1] == (undefined8 *)0x0) {
                puVar6[2] = puVar7;
                puVar6[1] = 0;
                *puVar6 = 0;
                *(undefined4 *)(puVar6 + 3) = 1;
                puVar7[1] = puVar6;
                goto LAB_008fec39;
              }
            }
            puVar9 = (undefined8 *)*puVar7;
          } while ((undefined8 *)*puVar7 != (undefined8 *)0x0);
          puVar6[2] = puVar7;
          puVar6[1] = 0;
          *puVar6 = 0;
          *(undefined4 *)(puVar6 + 3) = 1;
          *puVar7 = puVar6;
        }
LAB_008fec39:
        adjacent_8fd670(plVar8,puVar6);
LAB_008fec41:
        *(long *)(param_1 + 0x58) = *(long *)(param_1 + 0x58) + 1;
LAB_008fec4c:
        func_0x00a85f90(local_78,plVar17 + 4);
        if ((char)plVar17[6] == '\x01') {
          *(short *)((long)puVar6 + 0x36) = *(short *)((long)puVar6 + 0x36) + -1;
        }
        else if ((char)plVar17[6] == '\x02') {
          *(short *)((long)puVar6 + 0x34) = *(short *)((long)puVar6 + 0x34) + -1;
        }
        if (*(char *)((long)plVar17 + 0x31) == '\x01') {
          *(short *)((long)puVar6 + 0x36) = *(short *)((long)puVar6 + 0x36) + 1;
        }
        else if (*(char *)((long)plVar17 + 0x31) == '\x02') {
          *(short *)((long)puVar6 + 0x34) = *(short *)((long)puVar6 + 0x34) + 1;
        }
        local_80 = local_80 + 1;
        unaff_R15 = puVar6;
        goto LAB_008fecd1;
      }
      uVar18 = 0xc;
    }
    local_80 = local_80 + 1;
joined_r0x008fef7b:
    puVar6 = unaff_R15;
    if (puVar6 != (undefined8 *)0x0) {
      puVar9 = (undefined8 *)*puVar6;
      if ((undefined8 *)*puVar6 == (undefined8 *)0x0) {
        unaff_R15 = (undefined8 *)puVar6[2];
        puVar9 = puVar6;
        if ((unaff_R15 == (undefined8 *)0x0) || (puVar6 != (undefined8 *)unaff_R15[1])) {
          do {
            unaff_R15 = (undefined8 *)puVar9[2];
            if (unaff_R15 == (undefined8 *)0x0) {
              unaff_R15 = (undefined8 *)0x0;
              break;
            }
            bVar19 = puVar9 == (undefined8 *)*unaff_R15;
            puVar9 = unaff_R15;
          } while (bVar19);
        }
      }
      else {
        do {
          unaff_R15 = puVar9;
          puVar9 = (undefined8 *)unaff_R15[1];
        } while ((undefined8 *)unaff_R15[1] != (undefined8 *)0x0);
      }
      if (*(char *)(puVar6 + 6) != *(char *)((long)puVar6 + 0x31)) {
        local_50 = puVar6[5];
        local_58 = puVar6[4];
        plVar15 = (long *)*plVar8;
        if (plVar15 != (long *)0x0) {
          do {
            iVar14 = func_0x00339bd0(&local_58,plVar15 + 4,0x10);
            if (-1 < iVar14) {
              if (iVar14 == 0) {
                func_0x00a85f90(local_78,puVar6 + 4);
                if (*(char *)(puVar6 + 6) == '\x01') {
                  *(short *)((long)plVar15 + 0x36) = *(short *)((long)plVar15 + 0x36) + 1;
                }
                else if (*(char *)(puVar6 + 6) == '\x02') {
                  *(short *)((long)plVar15 + 0x34) = *(short *)((long)plVar15 + 0x34) + 1;
                }
                if (*(char *)((long)puVar6 + 0x31) == '\x01') {
                  *(short *)((long)plVar15 + 0x36) = *(short *)((long)plVar15 + 0x36) + -1;
                }
                else if (*(char *)((long)puVar6 + 0x31) == '\x02') {
                  *(short *)((long)plVar15 + 0x34) = *(short *)((long)plVar15 + 0x34) + -1;
                }
                break;
              }
              plVar15 = plVar15 + 1;
            }
            plVar15 = (long *)*plVar15;
          } while (plVar15 != (long *)0x0);
        }
      }
      goto joined_r0x008fef7b;
    }
    goto LAB_008fee2a;
  }
  bVar19 = true;
  local_80 = 0;
  iVar16 = 0;
LAB_008fed5d:
  cVar1 = (char)param_2[2];
  cVar10 = *(char *)((long)param_2 + 0x11);
  if (cVar1 == cVar10) {
    if ((cVar1 == '\x01') && (iVar16 == 0)) {
      *(short *)(param_1 + 0x9c) = *(short *)(param_1 + 0x9c) + -1;
      cVar1 = (char)param_2[2];
      cVar10 = *(char *)((long)param_2 + 0x11);
      goto LAB_008fed81;
    }
  }
  else {
LAB_008fed81:
    if (cVar1 != cVar10) {
      if (cVar1 == '\x02') {
        lVar13 = 0x9a;
LAB_008fed9e:
        *(short *)(param_1 + lVar13) = *(short *)(param_1 + lVar13) + -1;
        cVar10 = *(char *)((long)param_2 + 0x11);
      }
      else if (cVar1 == '\x01') {
        lVar13 = 0x9c;
        goto LAB_008fed9e;
      }
      lVar13 = 0x9a;
      if ((cVar10 == '\x02') || ((cVar10 == '\x01' && (lVar13 = 0x9c, 0 < iVar16)))) {
        *(short *)(param_1 + lVar13) = *(short *)(param_1 + lVar13) + 1;
      }
    }
  }
  uVar11 = 2;
  if (*(short *)(param_1 + 0x9a) == 0) {
    uVar11 = (ushort)(*(short *)(param_1 + 0x9c) != 0);
  }
  *(ushort *)(param_1 + 0x96) = uVar11;
  cVar10 = *(char *)((long)param_2 + 0x11);
  if (((bool)((char)param_2[2] == '\x02' & bVar19)) &&
     ((cVar10 != '\x02' || (cVar10 = '\x02', 0 < iVar16)))) {
    *(short *)(param_1 + 0x98) = *(short *)(param_1 + 0x98) + -1;
    cVar10 = *(char *)((long)param_2 + 0x11);
  }
  if ((cVar10 == '\x02') && (iVar16 == 0)) {
    *(short *)(param_1 + 0x98) = *(short *)(param_1 + 0x98) + 1;
  }
  adjacent_8fe3e0(param_1);
  uVar18 = 0;
LAB_008fee2a:
  if ((0 < local_80) && (*(long **)(param_1 + 0x50) != (long *)0x0)) {
    plVar8 = *(long **)(param_1 + 0x50);
    do {
      plVar15 = plVar8;
      plVar8 = (long *)*plVar15;
    } while ((long *)*plVar15 != (long *)0x0);
    do {
      plVar8 = (long *)plVar15[1];
      if ((long *)plVar15[1] == (long *)0x0) {
        plVar17 = (long *)plVar15[2];
        plVar8 = plVar15;
        if ((plVar17 == (long *)0x0) || (plVar15 != (long *)*plVar17)) {
          do {
            plVar17 = (long *)plVar8[2];
            if (plVar17 == (long *)0x0) {
              plVar17 = (long *)0x0;
              break;
            }
            bVar19 = plVar8 == (long *)plVar17[1];
            plVar8 = plVar17;
          } while (bVar19);
        }
      }
      else {
        do {
          plVar17 = plVar8;
          plVar8 = (long *)*plVar17;
        } while ((long *)*plVar17 != (long *)0x0);
      }
      if (((((short)plVar15[6] == 0) && (*(short *)((long)plVar15 + 0x32) == 0)) &&
          (*(short *)((long)plVar15 + 0x34) == 0)) &&
         ((*(short *)((long)plVar15 + 0x36) == 0 && ((char)plVar15[7] == '\0')))) {
        adjacent_8fd850(param_1 + 0x50,plVar15);
        func_0x00c08df0(plVar15,0x254f0a0);
        *(long *)(param_1 + 0x58) = *(long *)(param_1 + 0x58) + -1;
      }
      plVar15 = plVar17;
    } while (plVar17 != (long *)0x0);
  }
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar3 = (code *)invalidInstructionException();
    (*pcVar3)();
  }
  return uVar18;
}



/* adjacent_8ff0b0 | RVA 0x8ff0b0 | local helper / adjacent context (reachability below)
 * Evidence ev_4de4bdf0db56484a614545420da1ee2b997000d566f42708ca3a66a359338a58
 * Body [{"start": "0x8ff0b0", "end": "0x8ff129"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void adjacent_8ff0b0(undefined8 param_1,undefined8 *param_2)

{
  code *pcVar1;
  undefined8 local_40 [2];
  undefined2 local_30;
  long local_28;
  
  local_28 = _DAT_0391c310;
  if (param_2 == (undefined8 *)0x0) {
    param_2 = local_40;
    func_0x00258ff0(param_2,0x18);
    local_40[0] = 0;
    local_30 = 2;
  }
  adjacent_8fea20(param_1,param_2);
  func_0x006a5650(param_1,0);
  FUN_008fdfa0(param_1);
  if (_DAT_0391c310 == local_28) {
    return;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* adjacent_8ff130 | RVA 0x8ff130 | local helper / adjacent context (reachability below)
 * Evidence ev_db023f0556857b5baf029cdedb23afa1133ec11e48c7522ee3e0ea769fe32c67
 * Body [{"start": "0x8ff130", "end": "0x8ff175"}, {"start": "0x8ff180", "end": "0x8ff24c"}, {"start": "0x8ff250", "end": "0x8ff283"}, {"start": "0x8ff290", "end": "0x8ff33c"}, {"start": "0x8ff340", "end": "0x8ff373"}, {"start": "0x8ff380", "end": "0x8ff3e7"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Possible PIC construction at 0x008ff311: Changing call to branch */
/* WARNING: Possible PIC construction at 0x008ff3b3: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x008ff316) */
/* WARNING: Removing unreachable block (ram,0x008ff3b8) */
/* WARNING: Removing unreachable block (ram,0x008ff3e1) */
/* WARNING: Removing unreachable block (ram,0x008ff3c8) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void adjacent_8ff130(long param_1)

{
  ushort uVar1;
  long *plVar2;
  undefined8 uVar3;
  long *plVar4;
  long *plVar5;
  long *plVar6;
  ulong uVar7;
  bool bVar8;
  undefined8 local_50 [2];
  undefined2 local_40;
  undefined8 local_38;
  
  local_38 = _DAT_0391c310;
  uVar1 = *(ushort *)(param_1 + 10);
  if ((ulong)uVar1 != 0) {
    uVar7 = 0;
    do {
      plVar6 = (long *)(uVar7 * 0x18 + *(long *)(param_1 + 0x18));
      if (plVar6 == (long *)0x0 || *(long *)(param_1 + 0x18) == 0) {
        uVar3 = *(undefined8 *)(*(long *)(param_1 + 0x10) + uVar7 * 8);
        func_0x004c6a00(0x3b5c040,0,0,0);
        func_0x00258ff0(local_50,0x18);
        local_50[0] = 0;
        local_40 = 2;
        adjacent_8fea20(uVar3);
        func_0x006a5650(uVar3);
        FUN_008fdfa0(uVar3);
        func_0x004c6fa0(0x3b5c040,0,0,0);
      }
      else {
        plVar4 = (long *)*plVar6;
        if ((long *)*plVar6 != (long *)0x0) {
          do {
            plVar5 = (long *)*plVar4;
            plVar2 = plVar4;
            plVar4 = plVar5;
          } while (plVar5 != (long *)0x0);
          do {
            do {
              while( true ) {
                plVar4 = plVar2;
                *(undefined1 *)((long)plVar4 + 0x31) = 0;
                plVar5 = (long *)plVar4[1];
                if ((long *)plVar4[1] == (long *)0x0) break;
                do {
                  plVar4 = (long *)*plVar5;
                  plVar2 = plVar5;
                  plVar5 = plVar4;
                } while (plVar4 != (long *)0x0);
              }
              plVar2 = (long *)plVar4[2];
            } while ((plVar2 != (long *)0x0) && (plVar4 == (long *)*plVar2));
            do {
              plVar2 = (long *)plVar4[2];
              if (plVar2 == (long *)0x0) goto LAB_008ff290;
              bVar8 = plVar4 == (long *)plVar2[1];
              plVar4 = plVar2;
            } while (bVar8);
          } while( true );
        }
LAB_008ff290:
        *(undefined1 *)((long)plVar6 + 0x11) = 1;
        uVar3 = *(undefined8 *)(*(long *)(param_1 + 0x10) + uVar7 * 8);
        func_0x004c6a00(0x3b5c040,0,0,0);
        adjacent_8fea20(uVar3);
        func_0x006a5650(uVar3);
        FUN_008fdfa0(uVar3);
        func_0x004c6fa0(0x3b5c040,0,0,0);
        plVar4 = (long *)*plVar6;
        if ((long *)*plVar6 != (long *)0x0) goto LAB_008ff2f0;
        *(undefined2 *)(plVar6 + 2) = 0;
      }
      uVar7 = uVar7 + 1;
    } while (uVar7 != uVar1);
  }
  if (*(long *)(param_1 + 0x18) == 0) {
    halt_baddata();
  }
  func_0x00c08df0(*(long *)(param_1 + 0x18),0x254f0c0);
  halt_baddata();
LAB_008ff2f0:
  do {
    plVar5 = plVar4;
    plVar4 = (long *)*plVar5;
  } while ((long *)*plVar5 != (long *)0x0);
  plVar4 = (long *)plVar5[1];
  if (plVar4 == (long *)0x0) {
    plVar4 = plVar5;
    if (((undefined8 *)plVar5[2] == (undefined8 *)0x0) || (plVar5 != *(long **)plVar5[2])) {
      do {
        plVar2 = (long *)plVar4[2];
        if (plVar2 == (long *)0x0) break;
        bVar8 = plVar4 == (long *)plVar2[1];
        plVar4 = plVar2;
      } while (bVar8);
    }
  }
  else {
    do {
      plVar4 = (long *)*plVar4;
    } while (plVar4 != (long *)0x0);
  }
  adjacent_8fd850(plVar6,plVar5);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* adjacent_8ff3f8 | RVA 0x8ff3f8 | local helper / adjacent context (reachability below)
 * Evidence ev_a71fdb660e561243b80de13ba58a6195a1a721f683bb618895e7b15bf590fe8d
 * Body [{"start": "0x8ff3f8", "end": "0x8ff42c"}, {"start": "0x8ff430", "end": "0x8ff43e"}]
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void adjacent_8ff3f8(void)

{
  long *plVar1;
  long *plVar2;
  long *in_RCX;
  
  do {
    plVar2 = in_RCX;
    in_RCX = (long *)*plVar2;
  } while ((long *)*plVar2 != (long *)0x0);
  while( true ) {
    *(undefined1 *)((long)plVar2 + 0x31) = 0;
    plVar1 = (long *)plVar2[1];
    if ((long *)plVar2[1] == (long *)0x0) break;
    do {
      plVar2 = plVar1;
      plVar1 = (long *)*plVar2;
    } while ((long *)*plVar2 != (long *)0x0);
  }
  if (plVar2[2] != 0) {
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


