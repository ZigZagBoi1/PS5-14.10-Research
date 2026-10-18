/* Handler 671: REA6.7.0 / Ghidra12.1.4 recovered pseudocode, not original or buildable C.
 * Original4096-byte input SHA256 d4b0c27a6caf44b0df6d8de55eead2330ab5116f2649e81f1bfb32eba8a7f96c
 * Raw entry RVA 0x265f90 -> actual target 0xabe8b0. narg=4.
 * Kernel RVAs; runtime VA=0xffffffff8a9c0000+RVA. Opaque externals/data remain unknown.
 * Analyst types below are inferred from accesses. Recovered pseudocode is retained verbatim afterward.
 * Original entry is an assembly-verified tail JMP to the target above. An engine halt_baddata
 * at that unmapped edge is a decompiler boundary artifact, not a recovered halt operation.
 */
#include <stdint.h>

/* ===== Analyst recovered interface/types ===== */
struct handler_671_args { int32_t selector; uint32_t pad0; int32_t mode; uint32_t pad1; int32_t *out_a; int32_t *out_b; };
/* Analyst signature: int handler_671(void *thread, const struct handler_671_args *args). */


/* ===== ORIGINAL ENTRY: <EXTERNAL>::thunk_EXT_FUN_00abe8b0 RVA 0x265f90 | Evidence ev_a7150f634f7ce612fda577b8050862314ed7265a5dd5c6e516e3ffdc98d4a6af | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_671.raw.dossier.json | Source /tmp/rea-646-676-5b61b6f2/raw_union.bin SHA256 352988f408bc976411feddb3ef6cd2b18459d2aa3fa6dfd7f2e4a7fe416ce915 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x265f90", "end": "0x265f94"}], "total_bytes": 5, "span_bytes": 5, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_00abe8b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): handler_646_body RVA 0xabe1c0 | Evidence ev_90404a2d8c14d83869dc6ffc7739053f76cef6b4f44b6707a45f2a4ba2cb893a | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabe1c0", "end": "0xabe253"}], "total_bytes": 148, "span_bytes": 148, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 handler_646_body(long param_1,undefined8 *param_2)

{
  code *pcVar1;
  int iVar2;
  undefined8 uVar3;
  undefined8 *in_GS_OFFSET;
  undefined1 local_420 [1016];
  long local_28;
  
  local_28 = _DAT_0391c310;
  iVar2 = func_0x00608f90(*(undefined8 *)(param_1 + 0x140));
  if (iVar2 == 0) {
    uVar3 = 1;
  }
  else {
    func_0x00258ff0(local_420,0x3f8);
    uVar3 = *param_2;
    func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
    uVar3 = func_0x002591d0(local_420,uVar3,0x3f8);
  }
  if (_DAT_0391c310 == local_28) {
    return uVar3;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abe260 RVA 0xabe260 | Evidence ev_4110655df9682c517e32e34ee79e212cd239c54b429b09ede610881342578c97 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabe260", "end": "0xabe7a8"}], "total_bytes": 1353, "span_bytes": 1353, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_abe260(long param_1,undefined8 param_2,int param_3,undefined4 *param_4)

{
  ulong uVar1;
  ulong uVar2;
  code *pcVar3;
  int iVar4;
  undefined8 uVar5;
  long lVar6;
  long lVar7;
  undefined8 uVar8;
  uint uVar9;
  ulong uVar10;
  int *piVar11;
  ulong *puVar12;
  ulong uVar13;
  long lVar14;
  ulong uVar15;
  undefined8 *in_GS_OFFSET;
  long local_1d8;
  ulong local_1c8;
  ulong local_1c0;
  ulong local_1b0;
  int local_1a8;
  uint local_1a4;
  undefined4 local_1a0;
  undefined4 local_19c;
  undefined8 local_150;
  long local_148;
  undefined4 local_140;
  undefined8 local_138;
  long local_130;
  undefined8 local_128;
  undefined1 local_120 [96];
  long local_c0;
  long local_38;
  
  puVar12 = &local_1b0;
  local_38 = _DAT_0391c310;
  func_0x00258ff0(puVar12,0x60);
  uVar5 = func_0x0043b880(_DAT_036d15e0,0,2);
  func_0x00c1a3e0(*in_GS_OFFSET,0x135a084,0);
  iVar4 = func_0x00259900(param_2,uVar5,0x400,0);
  if (iVar4 != 0) goto LAB_00abe3e4;
  func_0x005fa6e0(local_120,0,0x144,1,uVar5,0xffffff9c,0,0,param_1);
  iVar4 = func_0x005f8c20(local_120);
  if (iVar4 != 0) goto LAB_00abe3e4;
  func_0x005fa780(local_120,0xc);
  iVar4 = 0x16;
  if (*(int *)(local_c0 + 0x1d4) != 1) {
LAB_00abe3d9:
    func_0x0054a440(local_c0);
    goto LAB_00abe3e4;
  }
  local_138 = *(undefined8 *)(param_1 + 0x140);
  local_150 = 0x1ada7f8;
  local_148 = local_c0;
  local_140 = 1;
  local_128 = 0;
  local_130 = param_1;
  iVar4 = func_0x0058bb00(*(undefined8 *)(local_c0 + 8),&local_150);
  if (iVar4 != 0) goto LAB_00abe3d9;
  lVar6 = func_0x0045d9c0(7,local_c0,0,1,0,*(undefined8 *)(param_1 + 0x140));
  if (lVar6 == 0) {
    iVar4 = 0xc;
  }
  else {
    func_0x007d46a0(lVar6 + 0x18,0,0);
    iVar4 = func_0x00631850(lVar6);
    if (iVar4 == 0) {
      lVar7 = func_0x006322a0();
      uVar9 = *(ushort *)(lVar7 + 0x10) - 0xfe00;
      if (((0x10 < uVar9) || ((0x10003U >> (uVar9 & 0x1f) & 1) == 0)) &&
         (*(ushort *)(lVar7 + 0x10) != 2)) {
        func_0x0025d410(0x1376c4c,0x1380bd0);
        goto LAB_00abe6cf;
      }
      uVar10 = (ulong)*(ushort *)(lVar7 + 0x38);
      if (uVar10 != 0) {
        lVar14 = 0;
        piVar11 = (int *)(lVar7 + 0x40);
        do {
          if (*(int *)(lVar7 + 0x40 + lVar14) == 0x61000001) {
            uVar1 = *(ulong *)(lVar7 + 0x60 + lVar14);
            if (uVar1 != 0) {
              uVar2 = *(ulong *)(lVar7 + 0x50 + lVar14);
              uVar13 = 0;
              goto LAB_00abe517;
            }
            break;
          }
          lVar14 = lVar14 + 0x38;
        } while (uVar10 * 0x38 - lVar14 != 0);
      }
      goto LAB_00abe6a3;
    }
    func_0x0025d410(0x132d3cb,0x1380bd0,iVar4);
    iVar4 = 8;
  }
  goto LAB_00abe6e4;
  while( true ) {
    uVar13 = uVar13 + 1;
    piVar11 = piVar11 + 0xe;
    if (uVar10 == uVar13) break;
LAB_00abe517:
    if (((*piVar11 == 0x61000010) || (*piVar11 == 1)) &&
       ((uVar15 = uVar2 - *(ulong *)(piVar11 + 4), *(ulong *)(piVar11 + 4) <= uVar2 &&
        ((uVar1 <= *(ulong *)(piVar11 + 10) && (uVar15 <= *(ulong *)(piVar11 + 10) - uVar1)))))) {
      local_1c0 = 0x60;
      if (uVar1 < 0x60) {
        local_1c0 = uVar1;
      }
      local_1c8 = uVar15 & 0xffffffffffffc000;
      local_1d8 = -(uVar15 & 0xffffffffffffc000);
      goto LAB_00abe57d;
    }
  }
LAB_00abe6a3:
  func_0x0025d410(0x134cc6a,0x1380bd0);
LAB_00abe6cf:
  iVar4 = 8;
  goto LAB_00abe6d5;
  while( true ) {
    local_1c8 = local_1c8 + 0x4000;
    uVar10 = local_1c8 - uVar15;
    if ((long)(local_1c0 & 0xffffffff) <= (long)(local_1c8 - uVar15)) {
      uVar10 = local_1c0 & 0xffffffff;
    }
    iVar4 = (int)uVar10;
    func_0x00259be0(((ulong)_DAT_03b49298 << 0x1e | (ulong)_DAT_03b49294 << 0x27 |
                    0xffff800000000000) + *(long *)(lVar7 + 0x30) + local_1d8 + uVar15,puVar12);
    func_0x0053a410(lVar7);
    local_1d8 = local_1d8 + -0x4000;
    uVar9 = (int)local_1c0 - iVar4;
    local_1c0 = (ulong)uVar9;
    puVar12 = (ulong *)((long)puVar12 + (long)iVar4);
    uVar15 = uVar15 + (long)iVar4;
    if ((int)uVar9 < 1) break;
LAB_00abe57d:
    uVar8 = func_0x00630b70(lVar6,uVar13,local_1c8);
    lVar7 = func_0x0053a3d0(lVar6,uVar8);
    if (lVar7 == 0) {
      iVar4 = 5;
      goto LAB_00abe6d5;
    }
  }
  if (local_1b0 < 0x14 || local_1a8 != 0x4942524f) {
    func_0x0025d410(0x1287656,0x1380bd0);
    goto LAB_00abe6cf;
  }
  if ((param_3 == 4) || (local_1a0 = local_19c, 3 < local_1a4)) {
    iVar4 = 0;
    *param_4 = local_1a0;
  }
  else {
    iVar4 = 0x16;
    *param_4 = 0;
  }
LAB_00abe6d5:
  func_0x006321f0(lVar6);
LAB_00abe6e4:
  local_138 = *(undefined8 *)(param_1 + 0x140);
  local_150 = 0x1ada8f8;
  local_148 = local_c0;
  local_140 = 1;
  local_130 = param_1;
  func_0x0058bce0(*(undefined8 *)(local_c0 + 8),&local_150);
  func_0x0054a440(local_c0);
  if (lVar6 != 0) {
    func_0x00461ba0();
  }
LAB_00abe3e4:
  func_0x0043c0c0(_DAT_036d15e0,uVar5,0);
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar3 = (code *)invalidInstructionException();
    (*pcVar3)();
  }
  return iVar4;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_647 RVA 0xabe7b0 | Evidence ev_ace04d2de80b412de6f87925f7f80febbe9335a916a4a7b5240605a1ad898cb5 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabe7b0", "end": "0xabe828"}], "total_bytes": 121, "span_bytes": 121, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sys_647(long param_1,undefined8 *param_2)

{
  code *pcVar1;
  int iVar2;
  undefined8 uVar3;
  int local_2c;
  long local_28;
  
  local_28 = _DAT_0391c310;
  iVar2 = func_0x00608f90(*(undefined8 *)(param_1 + 0x140));
  if (iVar2 == 0) {
    uVar3 = 1;
  }
  else {
    local_2c = 0;
    uVar3 = sub_abe260(param_1,*param_2,4,&local_2c);
    *(long *)(param_1 + 0x408) = (long)local_2c;
  }
  if (_DAT_0391c310 == local_28) {
    return uVar3;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abe830 RVA 0xabe830 | Evidence ev_611e4cac96f8926a51e3eff6cd3ee321642225a5316d66fa01895e4738f665a7 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabe830", "end": "0xabe8a8"}], "total_bytes": 121, "span_bytes": 121, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_abe830(long param_1,undefined8 *param_2)

{
  code *pcVar1;
  int iVar2;
  undefined8 uVar3;
  int local_2c;
  long local_28;
  
  local_28 = _DAT_0391c310;
  iVar2 = func_0x00608f90(*(undefined8 *)(param_1 + 0x140));
  if (iVar2 == 0) {
    uVar3 = 1;
  }
  else {
    local_2c = 0;
    uVar3 = sub_abe260(param_1,*param_2,5,&local_2c);
    *(long *)(param_1 + 0x408) = (long)local_2c;
  }
  if (_DAT_0391c310 == local_28) {
    return uVar3;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}




/* ===== TARGET: sys_671 RVA 0xabe8b0 | Evidence ev_ceb688e7b424412f6cfdcd564b10481cf024d5d334084a8625739add83e347d2 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabe8b0", "end": "0xabea17"}], "total_bytes": 360, "span_bytes": 360, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sys_671(long param_1,uint *param_2)

{
  uint uVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  code *pcVar4;
  int iVar5;
  undefined8 uVar6;
  uint uVar7;
  long *in_GS_OFFSET;
  uint local_40;
  uint local_3c;
  long local_38;
  
  local_38 = _DAT_0391c310;
  uVar2 = *(undefined8 *)(param_2 + 6);
  uVar7 = *param_2;
  uVar1 = param_2[2];
  uVar3 = *(undefined8 *)(param_2 + 4);
  iVar5 = func_0x00acc9a0(0);
  if ((iVar5 != 0) || (uVar6 = 2, 0x4ffffff < *(uint *)(*(long *)(*in_GS_OFFSET + 8) + 0x5d4))) {
    if (uVar7 == 0xffffffff) {
      uVar7 = *(uint *)(*(long *)(param_1 + 8) + 0x5c0);
    }
    else {
      iVar5 = func_0x00608f90(*(undefined8 *)(param_1 + 0x140));
      if (iVar5 == 0) {
        uVar6 = 1;
        goto LAB_00abe9f8;
      }
    }
    uVar6 = 0x16;
    if (uVar7 < 0xb) {
      if (uVar1 == 2) {
        func_0x009e3650(uVar7,&local_3c,&local_40);
        if ((*(byte *)(*(long *)(*(long *)(param_1 + 8) + 0x200) + 0x244) & 2) != 0) {
          uVar7 = local_3c + 3;
          if (-1 < (int)local_3c) {
            uVar7 = local_3c;
          }
          local_3c = (int)uVar7 >> 2;
          uVar7 = local_40 + 3;
          if (-1 < (int)local_40) {
            uVar7 = local_40;
          }
          local_40 = (int)uVar7 >> 2;
        }
      }
      else {
        if (uVar1 != 1) goto LAB_00abe9f8;
        func_0x008ed4e0(uVar7,&local_3c,&local_40);
      }
      iVar5 = func_0x00259790(uVar3,~((int)local_3c >> 0x1f) & local_3c);
      if (iVar5 == -1) {
        uVar6 = 0xe;
      }
      else {
        iVar5 = func_0x00259790(uVar2,~((int)local_40 >> 0x1f) & local_40);
        uVar6 = 0xe;
        if (iVar5 != -1) {
          uVar6 = 0;
        }
      }
    }
  }
LAB_00abe9f8:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar4 = (code *)invalidInstructionException();
    (*pcVar4)();
  }
  return uVar6;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): FUN_00abea41 RVA 0xabea41 | Evidence ev_9dddfe4927a9cc2bf45d85a8ec5d5a13d811c1132fa63268fd3de3d264e3ca0c | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabea41", "end": "0xabea4b"}], "total_bytes": 11, "span_bytes": 11, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void FUN_00abea41(void)

{
  code *UNRECOVERED_JUMPTABLE;
  
                    /* WARNING: Could not recover jumptable at 0x00abea49. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*UNRECOVERED_JUMPTABLE)();
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abea52 RVA 0xabea52 | Evidence ev_118caa65931cd5179d1d4c8718010f594e293f29fba414fb9454ad9301bb4c03 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabea52", "end": "0xabeab2"}], "total_bytes": 97, "span_bytes": 97, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted.", "Ghidra Listing reports a terminal call at 0xabeab1 to 0xabea41 FUN_00abea41 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

void sub_abea52(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
               undefined4 param_5,undefined4 param_6)

{
  func_0x0044f8c0(0x2888d40);
  FUN_00abea41(param_1,param_2,param_3,param_4,param_5,param_6);
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abeac0 RVA 0xabeac0 | Evidence ev_1b48bbb82deb4a451672f6b60e961a8b72ee920c538a78f9c454d5d0eba36da6 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabeac0", "end": "0xabeaef"}], "total_bytes": 48, "span_bytes": 48, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_abeac0(void)

{
  _DAT_03bf6e18 = func_0x0043b0e0(0x129bd39,0x28,0,0,0,0,7,0);
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abeaf0 RVA 0xabeaf0 | Evidence ev_9a8a7ca53ef953966bc22c18d280329276daf0a13b1e343c11f92a761f5f24e9 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabeaf0", "end": "0xabeb98"}], "total_bytes": 169, "span_bytes": 169, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

char sub_abeaf0(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  char cVar4;
  long *in_GS_OFFSET;
  
  iVar1 = func_0x00ae8360();
  iVar3 = iVar1;
  if (iVar1 < 0) {
    iVar2 = func_0x00609910(*(undefined8 *)(*in_GS_OFFSET + 0x140));
    cVar4 = '\0';
    iVar3 = 0;
    if (iVar2 != 1) goto LAB_00abeb4c;
  }
  cVar4 = '\x05';
  iVar1 = iVar3;
  if (param_1 != 2) {
    iVar3 = func_0x00aec390();
    cVar4 = '\0';
    if (iVar3 != 1) {
      if (param_1 == 0) {
        cVar4 = '\x03';
      }
      else if (param_1 == 4) {
        cVar4 = '\n';
      }
      else if (param_1 == 3) {
        cVar4 = '\x04';
      }
      else {
        iVar3 = func_0x00aecc30();
        cVar4 = (iVar3 == 1) * '\x05';
      }
    }
  }
LAB_00abeb4c:
  func_0x00ae8440(iVar1);
  return cVar4;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abeba0 RVA 0xabeba0 | Evidence ev_fafb0be859cf3600b89601fc4e4a966b6ac8e75c76cb44943ae9082bc50068f0 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabeba0", "end": "0xabec23"}], "total_bytes": 132, "span_bytes": 132, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

int sub_abeba0(uint param_1,undefined8 param_2,ulong param_3)

{
  int iVar1;
  int iVar2;
  
  iVar1 = func_0x00ae8360();
  iVar2 = iVar1;
  if (-1 < iVar1) {
    iVar2 = func_0x00aec770(param_2);
    if (((iVar2 == 0) && (iVar2 = -0x7ff2fdfe, param_1 < 5)) &&
       (*(ulong *)((ulong)param_1 * 0x18 + 0xe91438) <= param_3)) {
      func_0x00ae92f0(param_2,*(undefined8 *)((ulong)param_1 * 0x18 + 0xe91440),param_3);
      iVar2 = 0;
    }
  }
  func_0x00ae8440(iVar1);
  return iVar2;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abec30 RVA 0xabec30 | Evidence ev_647d8d4bc66343afd4ebf90b3ea14b1eac2290f68e14f83164de48a5f27b4b1b | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabec30", "end": "0xabecb3"}], "total_bytes": 132, "span_bytes": 132, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

int sub_abec30(uint param_1,undefined8 param_2,ulong param_3)

{
  int iVar1;
  int iVar2;
  
  iVar1 = func_0x00ae8360();
  iVar2 = iVar1;
  if (-1 < iVar1) {
    iVar2 = func_0x00aec770(param_2);
    if (((iVar2 == 0) && (iVar2 = -0x7ff2fdfe, param_1 < 4)) &&
       (*(ulong *)((ulong)param_1 * 0x18 + 0xe914d8) <= param_3)) {
      func_0x00ae92f0(param_2,*(undefined8 *)((ulong)param_1 * 0x18 + 0xe914e0),param_3);
      iVar2 = 0;
    }
  }
  func_0x00ae8440(iVar1);
  return iVar2;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abecc0 RVA 0xabecc0 | Evidence ev_f877ee1b2ecca63e3c8dadab11b19cd0e9eca494437b836b2e911d2e7d94fa50 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabecc0", "end": "0xabed43"}], "total_bytes": 132, "span_bytes": 132, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

int sub_abecc0(uint param_1,undefined8 param_2,ulong param_3)

{
  int iVar1;
  int iVar2;
  
  iVar1 = func_0x00ae8360();
  iVar2 = iVar1;
  if (-1 < iVar1) {
    iVar2 = func_0x00aec770(param_2);
    if (((iVar2 == 0) && (iVar2 = -0x7ff2fdfe, param_1 < 10)) &&
       (*(ulong *)((ulong)param_1 * 0x18 + 0xe91538) <= param_3)) {
      func_0x00ae92f0(param_2,*(undefined8 *)((ulong)param_1 * 0x18 + 0xe91540),param_3);
      iVar2 = 0;
    }
  }
  func_0x00ae8440(iVar1);
  return iVar2;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abed50 RVA 0xabed50 | Evidence ev_7d94c05d9388f72ac506a8912f4de067090409bd1f2a9654c9ab5313a647c0d9 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabed50", "end": "0xabedc8"}], "total_bytes": 121, "span_bytes": 121, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

int sub_abed50(int param_1,undefined8 param_2,ulong param_3)

{
  int iVar1;
  int iVar2;
  
  iVar1 = func_0x00ae8360();
  iVar2 = iVar1;
  if (-1 < iVar1) {
    iVar2 = func_0x00aec770(param_2);
    if (iVar2 == 0) {
      iVar2 = -0x7ff2fdfe;
      if (0x20 < param_3 && param_1 == 0) {
        func_0x00ae92f0(param_2,0x18dc0e0,param_3);
        iVar2 = 0;
      }
    }
  }
  func_0x00ae8440(iVar1);
  return iVar2;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abedd0 RVA 0xabedd0 | Evidence ev_5f07383220be45e82fc69862448ff790f8f6fa1cdf8bdc05bb43d95219ce4863 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabedd0", "end": "0xabee1a"}], "total_bytes": 75, "span_bytes": 75, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

uint sub_abedd0(uint param_1)

{
  int iVar1;
  uint uVar2;
  
  iVar1 = func_0x00ae8360();
  if (param_1 < 5 && -1 < iVar1) {
    uVar2 = *(uint *)((ulong)param_1 * 0x18 + 0xe91430);
    uVar2 = ~((int)uVar2 >> 0x1f) & uVar2;
  }
  else {
    uVar2 = 0;
  }
  func_0x00ae8440(iVar1);
  return uVar2;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abee20 RVA 0xabee20 | Evidence ev_6d779a560be1b58576dfa1817031863973bf309cac3981ff08e1b7ed54be5435 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabee20", "end": "0xabeee3"}, {"start": "0xabef2f", "end": "0xabef60"}], "total_bytes": 246, "span_bytes": 321, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

ulong sub_abee20(uint param_1,undefined8 param_2,ulong param_3)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  ulong uVar4;
  ulong uVar5;
  
  uVar1 = func_0x00ae8360();
  uVar5 = (ulong)uVar1;
  if ((int)uVar1 < 0) goto LAB_00abef48;
  uVar2 = func_0x00aee710();
  if (uVar2 == 0) {
    uVar5 = 0x800d0603;
    if (DAT_03bf6e24 != '\x01') goto LAB_00abef48;
    uVar2 = func_0x00aec770(param_2);
    if (uVar2 == 0) {
      if (param_1 < 5) {
        uVar4 = (ulong)param_1;
        iVar3 = func_0x00aec770(*(undefined8 *)(&DAT_03bf6e30 + uVar4 * 8));
        if ((iVar3 == 0) && (uVar5 = 0x800d0202, param_3 <= *(ulong *)(uVar4 * 0x18 + 0xe91430))) {
          if (param_1 < 5) {
                    /* WARNING: Could not emulate address calculation at 0x00abeedb */
                    /* WARNING: Treating indirect jump as call */
            uVar5 = (*(code *)((long)*(int *)(uVar4 * 4 + 0x18dbfdc) + 0x18dbfdc))();
            return uVar5;
          }
          func_0x002590b0(*(undefined8 *)(&DAT_03bf6e30 + uVar4 * 8),param_2,param_3);
          uVar5 = 0;
        }
      }
      else {
        uVar5 = 0x800d0202;
      }
      goto LAB_00abef48;
    }
  }
  uVar5 = (ulong)uVar2;
LAB_00abef48:
  func_0x00ae8440(uVar1);
  return uVar5;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): FUN_00abef70 RVA 0xabef70 | Evidence ev_72fb96bf768cdc3ffb4b31b9a6eb20b3e8c8d886f58ef4c85b69fec778a10ee5 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabef70", "end": "0xabefa3"}], "total_bytes": 52, "span_bytes": 52, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted.", "Ghidra Listing reports a terminal call at 0xabef9c to 0xabefa4 sub_abefa4 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

void FUN_00abef70(long param_1,ulong param_2,ulong param_3)

{
  byte bVar1;
  byte bVar2;
  ulong uVar3;
  ulong uVar4;
  byte bVar5;
  
  if (param_3 != 0 && (param_2 != 0 && param_1 != 0)) {
    if ((param_3 | param_2) >> 0x20 != 0) {
      sub_abefa4(param_1,(int)param_2,param_3 % param_2);
      return;
    }
    uVar3 = (param_3 & 0xffffffff) % (param_2 & 0xffffffff);
    bVar1 = *(byte *)(param_1 + uVar3);
    uVar4 = 0;
    do {
      bVar5 = *(byte *)(param_1 + uVar4);
      if (bVar5 != 0) {
        bVar2 = *(byte *)((ulong)((uint)bVar1 + (int)uVar4 & 0xf) + 0x13ba300);
        if (bVar5 == bVar2) {
          bVar5 = 0;
        }
        *(byte *)(param_1 + uVar4) = bVar5 ^ bVar2;
      }
      uVar4 = uVar4 + 1;
    } while (param_2 != uVar4);
    *(byte *)(param_1 + uVar3) = bVar1;
  }
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abefa4 RVA 0xabefa4 | Evidence ev_6b9876a7c77c55e9d41b74c6e955e3edab5e4fc722ff2be7a71d4b7750e8fc8a | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabefa4", "end": "0xabefbe"}, {"start": "0xabefc0", "end": "0xabeff7"}], "total_bytes": 83, "span_bytes": 84, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_abefa4(long param_1,long param_2,long param_3)

{
  byte bVar1;
  byte bVar2;
  long lVar3;
  byte bVar4;
  
  bVar1 = *(byte *)(param_1 + param_3);
  lVar3 = 0;
  do {
    bVar4 = *(byte *)(param_1 + lVar3);
    if (bVar4 != 0) {
      bVar2 = *(byte *)((ulong)((uint)bVar1 + (int)lVar3 & 0xf) + 0x13ba300);
      if (bVar4 == bVar2) {
        bVar4 = 0;
      }
      *(byte *)(param_1 + lVar3) = bVar4 ^ bVar2;
    }
    lVar3 = lVar3 + 1;
  } while (param_2 != lVar3);
  *(byte *)(param_1 + param_3) = bVar1;
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf000 RVA 0xabf000 | Evidence ev_f929e6176f35ef28bc3a342d729b90ea481007b3299825d2e749010ec7f13b2e | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabf000", "end": "0xabf0f1"}], "total_bytes": 242, "span_bytes": 242, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

int sub_abf000(uint param_1,undefined8 param_2,ulong param_3)

{
  undefined8 uVar1;
  int iVar2;
  int iVar3;
  ulong uVar4;
  
  iVar2 = func_0x00ae8360();
  iVar3 = iVar2;
  if ((((-1 < iVar2) && (iVar3 = func_0x00aee710(), iVar3 == 0)) &&
      (iVar3 = -0x7ff2f9fd, DAT_03bf6e24 == '\x01')) &&
     (((iVar3 = func_0x00aec770(param_2), iVar3 == 0 && (iVar3 = -0x7ff2fdfe, param_1 < 5)) &&
      (uVar4 = (ulong)param_1, param_3 <= *(ulong *)(uVar4 * 0x18 + 0xe91430))))) {
    func_0x00aef140(param_1);
    if ((0x17U >> (param_1 & 0x1f) & 1) == 0) {
      func_0x002590b0(param_2,*(undefined8 *)(&DAT_03bf6e30 + uVar4 * 8),param_3);
    }
    else {
      uVar1 = *(undefined8 *)(uVar4 * 8 + 0x18dc208);
      func_0x002590b0(param_2,*(undefined8 *)(&DAT_03bf6e30 + uVar4 * 8),param_3);
      FUN_00abef70(param_2,param_3,uVar1);
    }
    iVar3 = 0;
  }
  func_0x00ae8440(iVar2);
  return iVar3;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf100 RVA 0xabf100 | Evidence ev_bd9017cf0e3300e852f7e26c7183d531eda8ea77a79672aa8d09817d0b5167a9 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabf100", "end": "0xabf138"}], "total_bytes": 57, "span_bytes": 57, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

int sub_abf100(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = func_0x00ae8360();
  iVar3 = iVar1;
  if (-1 < iVar1) {
    iVar2 = func_0x00aec390();
    if (iVar2 != 1) {
      iVar3 = sub_abf140();
    }
  }
  func_0x00ae8440(iVar1);
  return iVar3;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf140 RVA 0xabf140 | Evidence ev_a1e8e7a871e69abc48556d9438149a39ceec84a7a39b7087d638d29a62f531e7 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabf140", "end": "0xabf1a6"}], "total_bytes": 103, "span_bytes": 103, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_abf140(void)

{
  int iVar1;
  
  DAT_03bf6e58 = 1;
  iVar1 = func_0x004c6580();
  if (iVar1 == 0) {
    func_0x0056a1c0(1);
    iVar1 = func_0x00ae9350();
    if (iVar1 < 0) {
      return;
    }
  }
  iVar1 = func_0x0056a1c0(2);
  if ((((iVar1 == 0) && (iVar1 = func_0x0056a1c0(3), iVar1 == 0)) &&
      (iVar1 = func_0x0056a1c0(4), iVar1 == 0)) && (iVar1 = func_0x0056a1c0(5), iVar1 == 0)) {
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf1b0 RVA 0xabf1b0 | Evidence ev_091f7c1ba1881a5935a2bbf551bbd4067f9627fedf80ef688ec5af2689b4ffde | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabf1b0", "end": "0xabf1db"}], "total_bytes": 44, "span_bytes": 44, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

int sub_abf1b0(void)

{
  int iVar1;
  int iVar2;
  
  iVar1 = func_0x00ae8360();
  iVar2 = iVar1;
  if (-1 < iVar1) {
    iVar2 = func_0x00aeccd0();
  }
  func_0x00ae8440(iVar1);
  return iVar2;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf1e0 RVA 0xabf1e0 | Evidence ev_d4507ba70eba482176817a813c2e0d5ec517c93a44237738d59237988889bf6c | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabf1e0", "end": "0xabf217"}], "total_bytes": 56, "span_bytes": 56, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

char sub_abf1e0(void)

{
  int iVar1;
  int iVar2;
  char cVar3;
  
  iVar1 = func_0x00ae8360();
  if (iVar1 < 0) {
    cVar3 = '\0';
  }
  else {
    iVar2 = func_0x00aec390();
    cVar3 = (iVar2 != 1) * '\x02';
  }
  func_0x00ae8440(iVar1);
  return cVar3;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf220 RVA 0xabf220 | Evidence ev_a38ba7d3152be64ad51867140d880d617ec5945ffda4b8ada39e7280913fffb0 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabf220", "end": "0xabf23b"}], "total_bytes": 28, "span_bytes": 28, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined4 sub_abf220(uint param_1)

{
  undefined4 uVar1;
  
  uVar1 = 1;
  if (param_1 < 5) {
    uVar1 = *(undefined4 *)((ulong)param_1 * 4 + 0x18dc230);
  }
  return uVar1;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf240 RVA 0xabf240 | Evidence ev_a052d73d7b0edac7aeae6a0cbcd28c418de306b71ebfb8810f4b549f2a596b08 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabf240", "end": "0xabf2c4"}], "total_bytes": 133, "span_bytes": 133, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

int sub_abf240(uint param_1,undefined8 param_2,ulong param_3)

{
  int iVar1;
  int iVar2;
  
  iVar1 = func_0x00ae8360();
  iVar2 = iVar1;
  if (-1 < iVar1) {
    iVar2 = func_0x00aec770(param_2);
    if ((iVar2 == 0) && (iVar2 = -0x7ff2fdfe, param_1 < 2)) {
      if ((ulong)(long)*(int *)((ulong)param_1 * 0x10 + 0xe914b8) <= param_3) {
        func_0x00ae92f0(param_2,*(undefined8 *)((ulong)param_1 * 0x10 + 0xe914b0),param_3);
        iVar2 = 0;
      }
    }
  }
  func_0x00ae8440(iVar1);
  return iVar2;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf2d0 RVA 0xabf2d0 | Evidence ev_5c7fce3683125b0e6e760fac0927f9774b3068660e1181da834c9eefa1b41285 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabf2d0", "end": "0xabf310"}], "total_bytes": 65, "span_bytes": 65, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

int sub_abf2d0(uint param_1)

{
  int iVar1;
  int iVar2;
  
  iVar1 = func_0x00ae8360();
  iVar2 = iVar1;
  if ((-1 < iVar1) && (iVar2 = -0x7ff2fdfe, param_1 < 2)) {
    iVar2 = *(int *)((ulong)param_1 * 0x10 + 0xe914bc);
  }
  func_0x00ae8440(iVar1);
  return iVar2;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf33f RVA 0xabf33f | Evidence ev_dc34029e867c0f248a09693778ab3d4d33ef3e3bd66046bd53d6177165bbd93d | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabf33f", "end": "0xabf455"}], "total_bytes": 279, "span_bytes": 279, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_abf33f(void)

{
  long lVar1;
  
  lVar1 = func_0x00c08b50(0xc00,0x28cdfe0,0x101);
  if (lVar1 != 0) {
    _DAT_03bf6e30 = lVar1;
    func_0x00258ff0(lVar1,0xc00);
    lVar1 = func_0x00c08b50(0xa0000,0x28cdfe0,0x101);
    if (lVar1 != 0) {
      _DAT_03bf6e38 = lVar1;
      func_0x00258ff0(lVar1,0xa0000);
      lVar1 = func_0x00c08b50(0x28000,0x28cdfe0,0x101);
      if (lVar1 != 0) {
        _DAT_03bf6e40 = lVar1;
        func_0x00258ff0(lVar1,0x28000);
        lVar1 = func_0x00c08b50(0x14000,0x28cdfe0,0x101);
        if (lVar1 != 0) {
          _DAT_03bf6e48 = lVar1;
          func_0x00258ff0(lVar1,0x14000);
          lVar1 = func_0x00c08b50(0x1800,0x28cdfe0,0x101);
          if (lVar1 != 0) {
            _DAT_03bf6e50 = lVar1;
            func_0x00258ff0(lVar1,0x1800);
            DAT_03bf6e24 = 1;
            return 0;
          }
          return 0x800d0211;
        }
      }
    }
  }
  return 0x800d0211;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf460 RVA 0xabf460 | Evidence ev_c0132e7eeb3339c4f2a4273c3d2fb0b8c662156d51082b3c6d7cc9a888705c9d | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabf460", "end": "0xabf505"}], "total_bytes": 166, "span_bytes": 166, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_abf460(void)

{
  func_0x00c08df0(_DAT_03bf6e30,0x28cdfe0);
  _DAT_03bf6e30 = 0;
  func_0x00c08df0(_DAT_03bf6e38,0x28cdfe0);
  _DAT_03bf6e38 = 0;
  func_0x00c08df0(_DAT_03bf6e40,0x28cdfe0);
  _DAT_03bf6e40 = 0;
  func_0x00c08df0(_DAT_03bf6e48,0x28cdfe0);
  _DAT_03bf6e48 = 0;
  func_0x00c08df0(_DAT_03bf6e50,0x28cdfe0);
  _DAT_03bf6e50 = 0;
  DAT_03bf6e24 = 0;
  DAT_03bf6e58 = 0;
  return 0;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf510 RVA 0xabf510 | Evidence ev_f74c945c0abb0cbff0e9803aa21325069da303c804d74288b49c23b35c3ea030 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabf510", "end": "0xabf53c"}], "total_bytes": 45, "span_bytes": 45, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_abf510(uint param_1,long param_2)

{
  if ((param_1 < 5) && (param_2 == *(long *)((ulong)param_1 * 0x18 + 0xe91430))) {
    return *(undefined8 *)(&DAT_03bf6e30 + (ulong)param_1 * 8);
  }
  return 0;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf540 RVA 0xabf540 | Evidence ev_add398792b09443468197e805bd4023ccdaa9d295b01f636f844826a3eafa143 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabf540", "end": "0xabf565"}], "total_bytes": 38, "span_bytes": 38, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

long sub_abf540(int param_1)

{
  if (param_1 - 1U < 0x2e) {
    return (long)*(int *)((ulong)(param_1 - 1U) * 4 + 0x18dc304) + 0x18dc304;
  }
  return 0x13185be;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf570 RVA 0xabf570 | Evidence ev_5981fe9e5b0483bedaa829c93c51b51707a01e5a8c482fb50c2456f836fdb1ae | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabf570", "end": "0xabf58b"}, {"start": "0xabf595", "end": "0xabf5ae"}], "total_bytes": 54, "span_bytes": 63, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_abf570(int param_1)

{
  undefined8 uVar1;
  
  if (param_1 - 10U < 0x30) {
                    /* WARNING: Could not emulate address calculation at 0x00abf583 */
                    /* WARNING: Treating indirect jump as call */
    uVar1 = (*(code *)((long)*(int *)((ulong)(param_1 - 10U) * 4 + 0x18dc244) + 0x18dc244))();
    return uVar1;
  }
  if (param_1 == 0x9b) {
    return 0x132304e;
  }
  return 0x127d64c;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf5e0 RVA 0xabf5e0 | Evidence ev_8e5a37a7c8ecfd831603b228b3c5dc4c4d4259e8c571f9ea4d5ea70fa0cfc9cc | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabf5e0", "end": "0xabf8d6"}], "total_bytes": 759, "span_bytes": 759, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Possible PIC construction at 0x00abf603: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00abf62b: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00abf653: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00abf67b: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00abf6a3: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00abf6cb: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00abf6f3: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00abf71b: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00abf743: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00abf76b: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00abf796: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00abf7c4: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00abf7f2: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00abf81d: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00abf845: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00abf86d: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00abf898: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00abf8b8: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x00abf89d) */
/* WARNING: Removing unreachable block (ram,0x00abf872) */
/* WARNING: Removing unreachable block (ram,0x00abf84a) */
/* WARNING: Removing unreachable block (ram,0x00abf822) */
/* WARNING: Removing unreachable block (ram,0x00abf7f7) */
/* WARNING: Removing unreachable block (ram,0x00abf7c9) */
/* WARNING: Removing unreachable block (ram,0x00abf79b) */
/* WARNING: Removing unreachable block (ram,0x00abf770) */
/* WARNING: Removing unreachable block (ram,0x00abf748) */
/* WARNING: Removing unreachable block (ram,0x00abf720) */
/* WARNING: Removing unreachable block (ram,0x00abf6f8) */
/* WARNING: Removing unreachable block (ram,0x00abf6d0) */
/* WARNING: Removing unreachable block (ram,0x00abf6a8) */
/* WARNING: Removing unreachable block (ram,0x00abf680) */
/* WARNING: Removing unreachable block (ram,0x00abf658) */
/* WARNING: Removing unreachable block (ram,0x00abf630) */
/* WARNING: Removing unreachable block (ram,0x00abf608) */
/* WARNING: Removing unreachable block (ram,0x00abf8bd) */

void sub_abf5e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf8e0 RVA 0xabf8e0 | Evidence ev_91d5480ce3eebd6a6f8c47300a831d22c43123693610425b2a239bc885362609 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabf8e0", "end": "0xabfbfa"}], "total_bytes": 795, "span_bytes": 795, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Possible PIC construction at 0x00abf907: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00abf92f: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00abf957: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00abf989: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00abf9b7: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00abf9e1: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00abfa0b: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00abfa35: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00abfa5f: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00abfa89: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00abfab3: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00abfae0: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00abfb0a: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00abfb37: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00abfb64: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00abfb8e: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00abfbbb: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x00abfb93) */
/* WARNING: Removing unreachable block (ram,0x00abfb69) */
/* WARNING: Removing unreachable block (ram,0x00abfb3c) */
/* WARNING: Removing unreachable block (ram,0x00abfb0f) */
/* WARNING: Removing unreachable block (ram,0x00abfae5) */
/* WARNING: Removing unreachable block (ram,0x00abfab8) */
/* WARNING: Removing unreachable block (ram,0x00abfa8e) */
/* WARNING: Removing unreachable block (ram,0x00abfa64) */
/* WARNING: Removing unreachable block (ram,0x00abfa3a) */
/* WARNING: Removing unreachable block (ram,0x00abfa10) */
/* WARNING: Removing unreachable block (ram,0x00abf9e6) */
/* WARNING: Removing unreachable block (ram,0x00abf9bc) */
/* WARNING: Removing unreachable block (ram,0x00abf98e) */
/* WARNING: Removing unreachable block (ram,0x00abf95c) */
/* WARNING: Removing unreachable block (ram,0x00abf934) */
/* WARNING: Removing unreachable block (ram,0x00abf90c) */
/* WARNING: Removing unreachable block (ram,0x00abfbc0) */

void sub_abf8e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abfc00 RVA 0xabfc00 | Evidence ev_720d5ad0d03ceed06ab457c0da9a00b61b8da9b7a38fefd773b0ec24d8147d14 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabfc00", "end": "0xabfc7b"}], "total_bytes": 124, "span_bytes": 124, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_abfc00(undefined8 param_1,uint param_2)

{
  code *pcVar1;
  int iVar2;
  
  pcVar1 = *(code **)(_DAT_03bf6e60 + 0x30);
  if (0x72 < (-(long)pcVar1 + 0x2690e0U >> 3 | -(long)pcVar1 << 0x3d)) {
    func_0x0044f8c0(0x2888ef0,pcVar1);
  }
  iVar2 = (*pcVar1)(param_1,(param_2 & 1) * 2 + 1);
  if ((param_2 & 1) != 0 || iVar2 != 0) {
    return;
  }
  func_0x00a11630(param_1);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abfca1 RVA 0xabfca1 | Evidence ev_13b9c9c64434b883951f6e93ab7e011a2cc83d4dc550ddba3af23259ea93a753 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabfca1", "end": "0xabfcda"}], "total_bytes": 58, "span_bytes": 58, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_abfca1(undefined8 param_1,undefined4 param_2,undefined8 param_3,code *UNRECOVERED_JUMPTABLE
               )

{
  undefined8 extraout_RDX;
  
  func_0x0044f8c0(0x2888ef0,UNRECOVERED_JUMPTABLE);
                    /* WARNING: Could not recover jumptable at 0x00abfcd9. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*UNRECOVERED_JUMPTABLE)(param_1,param_2,extraout_RDX,UNRECOVERED_JUMPTABLE);
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abfce0 RVA 0xabfce0 | Evidence ev_4e7b496bfb9d472111d2cde322121ab46a8efa0ce80d0177a50ddb6b1cd362c0 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabfce0", "end": "0xabfd0a"}], "total_bytes": 43, "span_bytes": 43, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

undefined8 sub_abfce0(undefined8 param_1,uint param_2)

{
  func_0x00a11630();
  if ((param_2 & 4) == 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  return 0;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abfd10 RVA 0xabfd10 | Evidence ev_cbba08a0d8fbc31ac9e3e332b34f64badc2ef6aa06ea794da4954e7ffc7f923a | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabfd10", "end": "0xac0561"}], "total_bytes": 2130, "span_bytes": 2130, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong sub_abfd10(long param_1)

{
  long *plVar1;
  code *pcVar2;
  int iVar3;
  uint uVar4;
  long lVar5;
  undefined8 uVar6;
  undefined8 uVar7;
  ulong uVar8;
  long *plVar9;
  long lVar10;
  uint uVar11;
  long *in_GS_OFFSET;
  bool bVar12;
  uint local_158;
  int local_154;
  long local_150;
  long local_148;
  uint local_13c;
  undefined8 local_138;
  long local_130;
  undefined4 local_128;
  undefined1 local_120 [96];
  long local_c0;
  long local_38;
  
  local_38 = _DAT_0391c310;
  local_158 = 0;
  lVar5 = func_0x005e11d0(*(undefined8 *)(param_1 + 0xa8),0x12d50c7,&local_158);
  if (lVar5 == 0) {
    bVar12 = false;
  }
  else {
    iVar3 = func_0x008d1a30(lVar5,0x1296dec,7);
    bVar12 = iVar3 == 0;
    func_0x005ddca0(*(undefined8 *)(param_1 + 0xa8),0x12d50c7);
  }
  lVar5 = *in_GS_OFFSET;
  uVar6 = func_0x005e11d0(*(undefined8 *)(param_1 + 0xa8),0x12b2da1,&local_138);
  uVar7 = func_0x00c08b50(0x400,0x2bfc080,0x102);
  iVar3 = func_0x004aee40(uVar7,0x400,0x12911f3,uVar6);
  if (iVar3 < 0x400) {
    uVar11 = 0;
    func_0x005fa6e0(local_120,0,0x4000064,1,uVar7,0xffffff9c,0,0,lVar5);
    uVar4 = func_0x005f8c20(local_120);
    if (uVar4 == 0) {
      if (local_c0 != 0) {
        uVar11 = (uint)(*(int *)(local_c0 + 0x1d4) == 2) * 4 + 0x11;
        func_0x0054a440();
      }
      func_0x005fa780(local_120,0xffffffdf);
      uVar4 = uVar11;
    }
    else if ((uVar4 == 2) &&
            ((iVar3 = func_0x004aee40(uVar7,0x400,0x13035f7,uVar6), 0x3ff < iVar3 ||
             (uVar4 = func_0x00a10b30(uVar7,lVar5), uVar4 == 0x11)))) {
      func_0x00c08df0(uVar7,0x2bfc080);
      goto LAB_00abfe0f;
    }
    func_0x00c08df0(uVar7,0x2bfc080);
    if ((uVar4 | 4) == 0x15) {
      uVar8 = 1;
      if (!bVar12 && (*(byte *)(param_1 + 0x98) & 1) == 0) goto LAB_00ac031f;
      func_0x0025d410(0x12eec79);
    }
  }
  else {
    func_0x00c08df0(uVar7,0x2bfc080);
  }
LAB_00abfe0f:
  if (_DAT_03bf6e60 == 0) {
    lVar5 = func_0x0066b580(0x13507c2);
    _DAT_02565f98 = _DAT_022031d0;
    _DAT_02565f60 = _DAT_02203198;
    _DAT_02565f70 = _DAT_022031a8;
    _DAT_02565f40 = _DAT_02203178;
    _DAT_02565e58 = _DAT_02203090;
    _DAT_02565f78 = _DAT_022031b0;
    _DAT_02566010 = _DAT_02203248;
    _DAT_02566068 = _DAT_022032a0;
    _DAT_02566070 = _DAT_022032a8;
    _DAT_02566078 = _DAT_022032b0;
    _DAT_03bf6e60 = *(long *)(lVar5 + 0x18);
  }
  lVar5 = *in_GS_OFFSET;
  iVar3 = func_0x00be9b90(*(undefined8 *)(lVar5 + 0x140),0x100);
  if (iVar3 == 0) {
    uVar8 = 1;
    goto LAB_00ac031f;
  }
  uVar8 = 0x2d;
  if ((*(ulong *)(param_1 + 0x98) & 0x4000) != 0) goto LAB_00ac031f;
  if ((*(ulong *)(param_1 + 0x98) & 0x10000) == 0) {
    iVar3 = func_0x005defd0(*(undefined8 *)(param_1 + 0xa8),0x136e89e,&local_150,&local_154);
    if (iVar3 == 0) {
      bVar12 = false;
    }
    else {
      local_13c = func_0x005defd0(*(undefined8 *)(param_1 + 0xa8),0x12b2da1,&local_150,&local_154);
      bVar12 = local_13c != 0;
    }
    uVar8 = 0x16;
    if ((local_154 == 0 || (local_150 == 0 || bVar12)) ||
       (*(char *)(local_150 + (local_154 + -1)) != '\0')) goto LAB_00ac031f;
    if (*(long *)(*(long *)(param_1 + 0x48) + 8) == _DAT_01a5d458) {
      local_138 = 0x1ad9ef8;
      local_130 = *(long *)(param_1 + 0x48);
      iVar3 = func_0x0058afc0(0x2203080,&local_138);
      if (iVar3 != 0x80000) goto LAB_00ac0254;
      local_130 = *(long *)(param_1 + 0x48);
      local_138 = 0x1adcdc8;
      local_128 = 0;
      func_0x0058ea90(*(undefined8 *)(local_130 + 8),&local_138);
      func_0x005fa6e0(local_120,0,0x44,1,local_150,0xffffff9c,0,0,lVar5);
      uVar4 = func_0x005f8c20(local_120);
      uVar8 = (ulong)uVar4;
      func_0x006afb50(*(undefined8 *)(param_1 + 0x48),0x80400,0x134ccfb,0x87);
    }
    else {
LAB_00ac0254:
      func_0x005fa6e0(local_120,0,0x44,1,local_150,0xffffff9c,0,0,lVar5);
      uVar8 = func_0x005f8c20(local_120);
    }
    if ((int)uVar8 != 0) goto LAB_00ac031f;
    func_0x005fa780(local_120,0xffffffdf);
    plVar9 = (long *)func_0x00c08b50(0x58,0x2888ed0,0x102);
    plVar9[4] = 0;
    *plVar9 = *(long *)(local_c0 + 0x18);
    local_13c = func_0x00592ca0(param_1,local_c0,&local_148);
    lVar5 = local_148;
    if (local_13c != 0) {
      uVar8 = (ulong)local_13c;
      func_0x0025d410(0x12a6333,0x13ab816,local_13c);
      func_0x00c08df0(plVar9,0x2888ed0);
      goto LAB_00ac031f;
    }
    *(uint *)(local_148 + 0x1c8) = *(uint *)(local_148 + 0x1c8) | 0x80;
    *(uint *)(local_148 + 0x1c8) = *(uint *)(local_148 + 0x1c8) | 1;
    plVar9[1] = local_148;
    plVar9[3] = 0;
    lVar10 = func_0x005e11d0(*(undefined8 *)(param_1 + 0xa8),0x126d195,&local_13c);
    if (local_13c == 2) {
      local_13c = 0;
    }
    else if ((lVar10 != 0 && local_13c == 0) &&
            (iVar3 = func_0x008d1a30(lVar10,0x1379884,5), iVar3 == 0)) {
      *(byte *)((long)plVar9 + 0x1b) = *(byte *)((long)plVar9 + 0x1b) | 1;
    }
    *(long **)(*(long *)(local_148 + 0x10) + 0x28) = plVar9;
    func_0x0054a060(local_148);
    local_138 = 0x1adcdc8;
    local_130 = local_148;
    local_128 = 0;
    func_0x0058ea90(*(undefined8 *)(local_148 + 8),&local_138);
    if ((*(byte *)(*(long *)(*(long *)(*(long *)(lVar5 + 0x10) + 0x10) + 0x18) + 0x99) & 0x10) != 0)
    {
      func_0x004c6a00(param_1 + 0x18,0,0,0);
      *(byte *)(param_1 + 0x99) = *(byte *)(param_1 + 0x99) | 0x10;
      func_0x004c6fa0(param_1 + 0x18,0,0,0);
    }
    *(byte *)(plVar9 + 2) = *(byte *)(plVar9 + 2) & 0xfe;
    func_0x004c6a00(param_1 + 0x18,0,0,0);
    if ((*(byte *)(plVar9 + 2) & 1) == 0) {
      uVar4 = *(uint *)(param_1 + 0x90);
    }
    else {
      uVar4 = *(uint *)(*(long *)(local_c0 + 0x18) + 0x90) & 0x400000c0 | *(uint *)(param_1 + 0x90);
    }
    *(uint *)(param_1 + 0x90) = uVar4 | 0x800;
    *(uint *)(param_1 + 0x90) =
         *(uint *)(*(long *)(local_c0 + 0x18) + 0x90) & 0x6100 | uVar4 | 0x800;
    func_0x004c6fa0(param_1 + 0x18,0,0,0);
    *(long **)(param_1 + 0x298) = plVar9;
    func_0x005479c0(param_1);
    if ((*(byte *)(plVar9 + 2) & 1) != 0) {
      func_0x004c6a00(*plVar9 + 0x18,0,0,0);
      *(undefined8 *)(param_1 + 0x310) = 0;
      plVar1 = *(long **)(*plVar9 + 0x328);
      *(long **)(param_1 + 0x318) = plVar1;
      *plVar1 = param_1;
      *(long *)(*plVar9 + 0x328) = param_1 + 0x310;
      func_0x004c6fa0(*plVar9 + 0x18,0,0,0);
    }
    func_0x005e1420(param_1,local_150);
  }
  else {
    iVar3 = func_0x005e1250(*(undefined8 *)(param_1 + 0xa8),0x1339b78,0,0);
    uVar8 = 0x2d;
    if (iVar3 == 0) goto LAB_00ac031f;
  }
  local_158 = 0;
  lVar5 = *(long *)(param_1 + 0x298);
  *(undefined8 *)(lVar5 + 0x40) = 0xffffffffffffffff;
  *(undefined8 *)(lVar5 + 0x50) = 0;
  *(undefined8 *)(lVar5 + 0x48) = 0;
  *(long *)(lVar5 + 0x28) = *in_GS_OFFSET;
  *(undefined8 *)(lVar5 + 0x30) = 0;
  *(undefined8 *)(lVar5 + 0x38) = 0;
  func_0x00a10d30(param_1);
  *(undefined8 *)(lVar5 + 0x28) = 0;
  uVar8 = (ulong)local_158;
LAB_00ac031f:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar2 = (code *)invalidInstructionException();
    (*pcVar2)();
  }
  return uVar8;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac0570 RVA 0xac0570 | Evidence ev_1f40c276051aa40cfff8c59ef3d6a9647216b4015014f30f8986bd6a59d192cc | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac0570", "end": "0xac0598"}], "total_bytes": 41, "span_bytes": 41, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_ac0570(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  func_0x0025d410(0x132d411,0x130e040,param_1,param_2,param_3);
  return 0x2d;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac05a0 RVA 0xac05a0 | Evidence ev_775026f73469df0da153d260001567bf4d4b3e9ae84136a83041491050b18b4d | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac05a0", "end": "0xac06bf"}], "total_bytes": 288, "span_bytes": 288, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

int sub_ac05a0(long param_1,uint param_2)

{
  long lVar1;
  int iVar2;
  undefined8 uVar3;
  uint uVar4;
  undefined8 *in_GS_OFFSET;
  
  lVar1 = *(long *)(param_1 + 0x298);
  if (*(long *)(lVar1 + 0x40) != -1) {
    if ((param_2 & 0x80000) == 0) {
      return 0x10;
    }
    uVar3 = *(undefined8 *)(lVar1 + 0x40);
    iVar2 = func_0x0095c490(uVar3,4);
    if (iVar2 != 0) {
      func_0x0025d410(0x132d434,0x12c4fff,iVar2);
    }
    iVar2 = func_0x0095c2e0(uVar3);
    if (iVar2 != 0) {
      func_0x0025d410(0x12e44b6,0x12c4fff,iVar2);
    }
  }
  uVar3 = *in_GS_OFFSET;
  uVar4 = param_2 >> 0x12 & 2;
  iVar2 = func_0x0054a460(param_1,0,uVar4 + 1,uVar3);
  if (iVar2 == 0) {
    if (*(long *)(lVar1 + 0x20) != 0) {
      func_0x0054a120();
    }
    iVar2 = func_0x0054a460(param_1,1,uVar4,uVar3);
    if (iVar2 == 0) {
      uVar3 = *(undefined8 *)(param_1 + 0x298);
      *(undefined8 *)(param_1 + 0x298) = 0;
      func_0x00c08df0(uVar3,0x2888ed0);
      return 0;
    }
    uVar3 = 0x12cfc72;
  }
  else {
    uVar3 = 0x13a0929;
  }
  func_0x0025d410(uVar3,0x12c4fff,iVar2);
  return iVar2;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac06ea RVA 0xac06ea | Evidence ev_0031d521db2c70b56d92cde5f19fafc25c01383a85b75b54c8f3c78ded5ebe85 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac06ea", "end": "0xac0728"}], "total_bytes": 63, "span_bytes": 63, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_ac06ea(undefined8 param_1,undefined4 param_2,undefined8 param_3,code *UNRECOVERED_JUMPTABLE
               )

{
  func_0x0044f8c0(0x2889050,UNRECOVERED_JUMPTABLE);
                    /* WARNING: Could not recover jumptable at 0x00ac0727. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*UNRECOVERED_JUMPTABLE)(param_1,param_2,param_3,UNRECOVERED_JUMPTABLE);
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac0752 RVA 0xac0752 | Evidence ev_fd79dc75b2adfe7f52ddc5b572617b6f16a172b91fe2b74e2ac926614682963a | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac0752", "end": "0xac07a0"}], "total_bytes": 79, "span_bytes": 79, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_ac0752(undefined8 param_1,undefined4 param_2,undefined4 param_3,undefined8 param_4,
               code *UNRECOVERED_JUMPTABLE)

{
  func_0x0044f8c0(0x2889070,UNRECOVERED_JUMPTABLE);
                    /* WARNING: Could not recover jumptable at 0x00ac079e. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*UNRECOVERED_JUMPTABLE)(param_1,param_2,param_3,param_4,UNRECOVERED_JUMPTABLE);
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac07d3 RVA 0xac07d3 | Evidence ev_aa5e64284564ca4f3c6f4541ad5575e519481d217ae25ab4d739fd53f8150cac | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac07d3", "end": "0xac080c"}], "total_bytes": 58, "span_bytes": 58, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_ac07d3(undefined8 param_1,undefined8 param_2,undefined8 param_3,code *UNRECOVERED_JUMPTABLE
               )

{
  undefined8 extraout_RDX;
  
  func_0x0044f8c0(0x2889090,UNRECOVERED_JUMPTABLE);
                    /* WARNING: Could not recover jumptable at 0x00ac080b. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*UNRECOVERED_JUMPTABLE)(param_1,param_2,extraout_RDX,UNRECOVERED_JUMPTABLE);
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac0810 RVA 0xac0810 | Evidence ev_c4441d0a5e52a84ccb5a461b8e58692491f94151b36ab1456f588937b57dbdd3 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac0810", "end": "0xac08f6"}], "total_bytes": 231, "span_bytes": 231, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

int sub_ac0810(long param_1,ulong param_2,ulong param_3,undefined8 *param_4)

{
  code *pcVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  ulong uVar5;
  long lVar6;
  
  *param_4 = 0;
  iVar3 = -1;
  lVar6 = **(long **)(param_1 + 0x298);
  uVar2 = *(uint *)(*(long *)(lVar6 + 0x40) + 0x28) >> 0x17 & 2;
  if (uVar2 != 0) {
    param_3 = param_3 & 0xffffffff;
    param_2 = param_2 & 0xffffffff;
    iVar3 = func_0x00561cf0(uVar2);
    lVar6 = **(long **)(param_1 + 0x298);
  }
  pcVar1 = *(code **)(*(long *)(lVar6 + 0x38) + 0x38);
  uVar5 = param_3;
  if (0xf < (-(long)pcVar1 + 0x26bad8U >> 3 | -(long)pcVar1 << 0x3d)) {
    uVar5 = param_3 & 0xffffffff;
    func_0x0044f8c0(0x28890b0,pcVar1,param_3);
    param_2 = param_2 & 0xffffffff;
    lVar6 = **(long **)(param_1 + 0x298);
  }
  iVar4 = (*pcVar1)(lVar6,param_2,uVar5,param_4);
  if (iVar3 != -1) {
    func_0x00561de0(iVar3);
  }
  if (iVar4 != 0) {
    return iVar4;
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac0900 RVA 0xac0900 | Evidence ev_5abbd66bf813d9765aff3520457b4f6013bcb0792a16ba0735f5013b6127bef8 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac0900", "end": "0xac09e8"}], "total_bytes": 233, "span_bytes": 233, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

int sub_ac0900(long param_1,undefined8 param_2,ulong param_3,undefined8 *param_4)

{
  code *pcVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  ulong uVar5;
  long lVar6;
  
  *param_4 = 0;
  iVar3 = -1;
  lVar6 = **(long **)(param_1 + 0x298);
  uVar2 = *(uint *)(*(long *)(lVar6 + 0x40) + 0x28) >> 0x17 & 2;
  if (uVar2 != 0) {
    param_3 = param_3 & 0xffffffff;
    iVar3 = func_0x00561cf0(uVar2);
    lVar6 = **(long **)(param_1 + 0x298);
  }
  pcVar1 = *(code **)(*(long *)(lVar6 + 0x38) + 0x40);
  uVar5 = param_3;
  if (0x3b < (-(long)pcVar1 + 0x268068U >> 3 | -(long)pcVar1 << 0x3d)) {
    uVar5 = param_3 & 0xffffffff;
    func_0x0044f8c0(0x28890d0,pcVar1,param_3);
    lVar6 = **(long **)(param_1 + 0x298);
  }
  iVar4 = (*pcVar1)(lVar6,param_2,uVar5,param_4);
  if (iVar3 != -1) {
    func_0x00561de0(iVar3);
  }
  if (iVar4 != 0) {
    return iVar4;
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac09f0 RVA 0xac09f0 | Evidence ev_29672938896fd3a999a0aaea4bea048ea5085d159b5fd61c39396c1e5baf768f | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac09f0", "end": "0xac0a29"}], "total_bytes": 58, "span_bytes": 58, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8
sub_ac09f0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
          undefined8 param_5,undefined8 param_6)

{
  func_0x0025d410(0x12b066d,0x1395b05,param_1,param_2,param_3,param_4,param_5,param_6);
  return 0x2d;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac0a30 RVA 0xac0a30 | Evidence ev_2bf825eb0244e5fc0ac49d60a81f4c4b60989fa483890ed5342884a14a76cf9d | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac0a30", "end": "0xac0a39"}], "total_bytes": 10, "span_bytes": 10, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_ac0a30(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac0a40 RVA 0xac0a40 | Evidence ev_d3e5d84c9495186a823be767a56d09a7d3a7e9fb430897f340de6070db2dac62 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac0a40", "end": "0xac0a5b"}], "total_bytes": 28, "span_bytes": 28, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_ac0a40(void)

{
  int iVar1;
  
  iVar1 = func_0x00592c70();
  if (iVar1 != 0) {
    return;
  }
  _DAT_03bf6e60 = 0;
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac0a82 RVA 0xac0a82 | Evidence ev_8b8aaa33f54595422f021f72df6a75a717f18571321bf6db7935781abb2b0439 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac0a82", "end": "0xac0ad8"}], "total_bytes": 87, "span_bytes": 87, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_ac0a82(undefined8 param_1,undefined4 param_2,undefined8 param_3,undefined4 param_4,
               undefined8 param_5,code *UNRECOVERED_JUMPTABLE)

{
  func_0x0044f8c0(0x28890f0,UNRECOVERED_JUMPTABLE);
                    /* WARNING: Could not recover jumptable at 0x00ac0ad6. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*UNRECOVERED_JUMPTABLE)(param_1,param_2,param_3,param_4,param_5,UNRECOVERED_JUMPTABLE);
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac0ae0 RVA 0xac0ae0 | Evidence ev_2ab86079917bc54c431221b7bea5ad840b82989e0746456198a0c2453d6b1d37 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac0ae0", "end": "0xac0b07"}], "total_bytes": 40, "span_bytes": 40, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_ac0ae0(undefined8 param_1,undefined4 param_2,undefined8 param_3)

{
  func_0x0025d410(0x12da4c1,0x130e055,param_1,param_2,param_3);
  return 0x2d;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac0b10 RVA 0xac0b10 | Evidence ev_fc4cc091063f7876d411626113efb260406520184320299277133add1005766f | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac0b10", "end": "0xac0b2c"}], "total_bytes": 29, "span_bytes": 29, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_ac0b10(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac0b53 RVA 0xac0b53 | Evidence ev_8521ebd93b9ba9d01f20ef642d50652d163e59e6a7e473bfb6394d7340d46608 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac0b53", "end": "0xac0b8c"}], "total_bytes": 58, "span_bytes": 58, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_ac0b53(undefined8 param_1,undefined8 param_2,undefined8 param_3,code *UNRECOVERED_JUMPTABLE
               )

{
  undefined8 extraout_RDX;
  
  func_0x0044f8c0(0x2889110,UNRECOVERED_JUMPTABLE);
                    /* WARNING: Could not recover jumptable at 0x00ac0b8b. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*UNRECOVERED_JUMPTABLE)(param_1,param_2,extraout_RDX,UNRECOVERED_JUMPTABLE);
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac0bb6 RVA 0xac0bb6 | Evidence ev_d31c90bfa42c47490e4e2896fe4defd58bbc915b7b3c32454b3a99222d4ad42f | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac0bb6", "end": "0xac0bef"}], "total_bytes": 58, "span_bytes": 58, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_ac0bb6(undefined8 param_1,undefined8 param_2,undefined8 param_3,code *UNRECOVERED_JUMPTABLE
               )

{
  undefined8 extraout_RDX;
  
  func_0x0044f8c0(0x2889130,UNRECOVERED_JUMPTABLE);
                    /* WARNING: Could not recover jumptable at 0x00ac0bee. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*UNRECOVERED_JUMPTABLE)(param_1,param_2,extraout_RDX,UNRECOVERED_JUMPTABLE);
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac0bf0 RVA 0xac0bf0 | Evidence ev_5d703cec4290258ad5bb88c524bf308f7851b3a2f073ac09b9777a5ba3e6aa38 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac0bf0", "end": "0xac0bf5"}], "total_bytes": 6, "span_bytes": 6, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_ac0bf0(void)

{
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac0c00 RVA 0xac0c00 | Evidence ev_9d2203c55c5cdbfbb1eb54471b9b9a5c25d44384659ecb13a044db6ab77d01f8 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac0c00", "end": "0xac0c05"}], "total_bytes": 6, "span_bytes": 6, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_ac0c00(void)

{
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac0c10 RVA 0xac0c10 | Evidence ev_73aa32b7bcea1e901f8413ebe581962d6c389ffcb7cca43c7b836d51c7a1962e | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac0c10", "end": "0xac0c6a"}], "total_bytes": 91, "span_bytes": 91, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_ac0c10(long param_1,long param_2)

{
  short *psVar1;
  byte bVar2;
  short sVar3;
  long lVar4;
  int iVar5;
  long *in_GS_OFFSET;
  
  lVar4 = *in_GS_OFFSET;
  sVar3 = *(short *)(lVar4 + 0x114);
  if (param_2 == 0) {
    if (sVar3 != 0) {
      return;
    }
    sub_ac14e0(param_1);
    bVar2 = *(byte *)(param_1 + 10);
  }
  else {
    if (sVar3 != 0) {
      return;
    }
    iVar5 = sub_ac0f60(param_1,param_2,0);
    if (iVar5 == 0) {
      return;
    }
    bVar2 = *(byte *)(param_1 + 10);
  }
  if ((bVar2 & 0x10) == 0) {
    psVar1 = (short *)(lVar4 + 0x10a);
    *psVar1 = *psVar1 + 1;
  }
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac0ca0 RVA 0xac0ca0 | Evidence ev_72363299ae0919d928b342f3a241ba466dcf7178e3468da583a9b5a1ba16d87d | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac0ca0", "end": "0xac0cdd"}], "total_bytes": 62, "span_bytes": 62, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_ac0ca0(long param_1,undefined8 param_2,undefined8 param_3,code *UNRECOVERED_JUMPTABLE)

{
  undefined8 extraout_RDX;
  
  func_0x0044f8c0(0x2889210,UNRECOVERED_JUMPTABLE);
                    /* WARNING: Could not recover jumptable at 0x00ac0cdc. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*UNRECOVERED_JUMPTABLE)(param_1 + 0x28,param_2,extraout_RDX,UNRECOVERED_JUMPTABLE);
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac0ce0 RVA 0xac0ce0 | Evidence ev_3231e5f1a100f55492ce27da63df933fb0f9f3d53037811ad0dd794705d8a397 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac0ce0", "end": "0xac0d5a"}, {"start": "0xac0d60", "end": "0xac0d95"}], "total_bytes": 177, "span_bytes": 182, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

long * sub_ac0ce0(long param_1)

{
  long *plVar1;
  long lVar2;
  ulong uVar3;
  long *plVar4;
  long *plVar5;
  ulong *in_GS_OFFSET;
  
  uVar3 = 0xfffffffffffffff1;
  if ((*(uint *)(param_1 + 8) & 0x100000) == 0) {
    uVar3 = 0xfffffffffffffff8;
  }
  if ((uVar3 & *(ulong *)(param_1 + 0x40)) == *in_GS_OFFSET) {
    sub_ac1700(param_1);
    plVar4 = (long *)0x0;
  }
  else {
    func_0x006a2630();
    uVar3 = *in_GS_OFFSET;
    lVar2 = func_0x004c8230(*(undefined4 *)((long)in_GS_OFFSET + 0x34));
    plVar1 = *(long **)(lVar2 + 0x6a0);
    if (*(long **)(lVar2 + 0x6a0) == (long *)(lVar2 + 0x6a0)) {
      plVar5 = (long *)0x0;
      plVar4 = (long *)0x0;
    }
    else {
      do {
        plVar5 = plVar1;
        if ((plVar5[2] == param_1) && (plVar4 = plVar5, plVar5[3] == uVar3)) break;
        plVar1 = (long *)*plVar5;
        plVar4 = (long *)0x0;
      } while ((long *)*plVar5 != (long *)(lVar2 + 0x6a0));
    }
    func_0x006a2650();
    sub_ac1870(param_1,plVar5);
  }
  return plVar4;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac0da0 RVA 0xac0da0 | Evidence ev_2bd74c0c28fe61c169ab09cf5fa897251424f3795ff0e37bcf6910b009b9f9c3 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac0da0", "end": "0xac0e51"}], "total_bytes": 178, "span_bytes": 178, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_ac0da0(long param_1,undefined8 param_2,uint param_3)

{
  *(undefined8 *)(param_1 + 0x18) = _DAT_03d0e8e8;
  *(undefined8 *)(param_1 + 0x20) = 0;
  if ((param_3 & 4) == 0) {
    func_0x004c7dd0(param_1 + 0x40,param_2,0x1323069,(param_3 & 8) * 8 + 8);
  }
  else {
    func_0x00c4b290(param_1 + 0x28,0x13a0950,(param_3 & 8) * 8 + 4,
                    (param_3 & 2) << 0x12 | (param_3 & 1) << 0x11);
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac0e60 RVA 0xac0e60 | Evidence ev_337c8f6469d151a1caea4170495e4fe1572333762e83269fecd6f7ee6590c57b | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac0e60", "end": "0xac0eb2"}], "total_bytes": 83, "span_bytes": 83, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_ac0e60(long param_1,undefined8 param_2)

{
  *(undefined8 *)(param_1 + 0x18) = _DAT_03d0e8e8;
  *(undefined8 *)(param_1 + 0x20) = 0;
  func_0x004c7dd0(param_1 + 0x40,param_2,0x1323069,8);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac0ec0 RVA 0xac0ec0 | Evidence ev_78dd9e6bac72d7b8cfd402514527fff445e4bc72f240f625d30bfdb91554ae7c | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac0ec0", "end": "0xac0ef8"}], "total_bytes": 57, "span_bytes": 57, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_ac0ec0(long param_1)

{
  *(undefined8 *)(param_1 + 0x20) = 0xdead;
  if ((*(byte *)(param_1 + 10) & 0x10) == 0) {
    func_0x004c7e50(param_1 + 0x40);
  }
  else {
    func_0x00261090(param_1 + 0x28);
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac0f00 RVA 0xac0f00 | Evidence ev_c143e483f1c31f7b09ad30b70905e0448f603a868f6332f96a55e3e7b4fe2485 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac0f00", "end": "0xac0f56"}], "total_bytes": 87, "span_bytes": 87, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_ac0f00(long *param_1)

{
  long lVar1;
  long lVar2;
  
  lVar1 = param_1[1];
  lVar2 = *param_1;
  *(undefined8 *)(lVar2 + 0x18) = _DAT_03d0e8e8;
  *(undefined8 *)(lVar2 + 0x20) = 0;
  func_0x004c7dd0(lVar2 + 0x40,lVar1,0x1323069,8);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac0f60 RVA 0xac0f60 | Evidence ev_941647831fcd70e91387baaf87fe914b2f4b7aa213af9df6f298c060a338dc02 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac0f60", "end": "0xac10e9"}, {"start": "0xac10f0", "end": "0xac12c5"}], "total_bytes": 864, "span_bytes": 870, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_ac0f60(long param_1,long *param_2,int param_3)

{
  int *piVar1;
  long lVar2;
  byte bVar3;
  long lVar4;
  long lVar5;
  long *plVar6;
  int iVar7;
  long *plVar8;
  long *in_GS_OFFSET;
  
  lVar4 = *in_GS_OFFSET;
  if (*(short *)(lVar4 + 0x114) != 0) {
    return 1;
  }
  *(undefined4 *)(param_2 + 4) = 0;
  param_2[3] = lVar4;
  param_2[2] = param_1;
  if ((*(byte *)(param_1 + 10) & 0x10) != 0) {
    *(int *)(lVar4 + 0x370) = *(int *)(lVar4 + 0x370) + 1;
  }
  *(int *)(lVar4 + 0x47c) = *(int *)(lVar4 + 0x47c) + 1;
  lVar5 = *(long *)((long)*(int *)(lVar4 + 0x524) * 8 + 0x3538920);
  param_2[1] = lVar5 + 0x6a0;
  lVar2 = *(long *)(lVar5 + 0x6a0);
  *param_2 = lVar2;
  *(long **)(lVar2 + 8) = param_2;
  *(long **)(lVar5 + 0x6a0) = param_2;
  *(short *)(*in_GS_OFFSET + 0x10e) = *(short *)(*in_GS_OFFSET + 0x10e) + 1;
  LOCK();
  *(int *)(*in_GS_OFFSET + 0x5a8) = *(int *)(*in_GS_OFFSET + 0x5a8) + 1;
  UNLOCK();
  func_0x006b7940();
  *(int *)(lVar4 + 0x47c) = *(int *)(lVar4 + 0x47c) + -1;
  if ((((uint)(*(ulong *)(param_1 + 0x18) >> ((ulong)*(byte *)(lVar5 + 0x34) & 0x3f)) |
       (uint)*(byte *)(lVar4 + 0x108)) & 1) == 0) {
    return 1;
  }
  func_0x006a2630();
  lVar4 = func_0x004c8230(*(undefined4 *)((long)in_GS_OFFSET + 0x34));
  if ((*(ulong *)(param_1 + 0x18) >> ((ulong)*(uint *)(lVar4 + 0x34) & 0x3f) & 1) != 0) {
    FUN_00ac12d0(param_2);
    if ((int)param_2[4] == 0) {
      if ((*(byte *)(param_1 + 10) & 8) == 0) {
LAB_00ac117d:
        func_0x006b7960();
        LOCK();
        piVar1 = (int *)(*in_GS_OFFSET + 0x5a8);
        iVar7 = *piVar1;
        *piVar1 = *piVar1 + -1;
        UNLOCK();
        if (iVar7 == -0x7fffffff) {
          func_0x006b7af0();
        }
        func_0x006a2650();
        if (param_3 == 0) {
          if ((*(uint *)(param_1 + 8) & 0x100000) == 0) {
            func_0x004c6a00(param_1 + 0x40,0,0,0);
          }
          else {
            lVar4 = *in_GS_OFFSET;
            piVar1 = (int *)(lVar4 + 0x370);
            *piVar1 = *piVar1 + -1;
            func_0x00c4bb20(param_1 + 0x28,0,0,0);
            piVar1 = (int *)(lVar4 + 0x370);
            *piVar1 = *piVar1 + 1;
          }
        }
        else {
          if ((*(uint *)(param_1 + 8) & 0x100000) == 0) {
            iVar7 = func_0x004c76a0(param_1 + 0x40,0,0,0);
          }
          else {
            iVar7 = func_0x00c4c210(param_1 + 0x28,0,0);
          }
          if (iVar7 == 0) {
            return 0;
          }
        }
        func_0x006a2630();
        lVar5 = func_0x004c8230(*(undefined4 *)((long)in_GS_OFFSET + 0x34));
        bVar3 = *(byte *)(lVar5 + 0x34) & 0x3f;
        *(ulong *)(param_1 + 0x18) =
             *(ulong *)(param_1 + 0x18) & (-2L << bVar3 | 0xfffffffffffffffeU >> 0x40 - bVar3);
        param_2[1] = lVar5 + 0x6a0;
        lVar4 = *(long *)(lVar5 + 0x6a0);
        *param_2 = lVar4;
        *(long **)(lVar4 + 8) = param_2;
        *(long **)(lVar5 + 0x6a0) = param_2;
        *(short *)(*in_GS_OFFSET + 0x10e) = *(short *)(*in_GS_OFFSET + 0x10e) + 1;
        LOCK();
        *(int *)(*in_GS_OFFSET + 0x5a8) = *(int *)(*in_GS_OFFSET + 0x5a8) + 1;
        UNLOCK();
        func_0x006b7940();
        func_0x006a2650();
        if ((*(byte *)(param_1 + 10) & 0x10) == 0) {
          func_0x004c6fa0(param_1 + 0x40,0,0,0);
          return 1;
        }
        func_0x00c4c4b0(param_1 + 0x28,0,0);
        return 1;
      }
      plVar6 = *(long **)(lVar4 + 0x6a0);
      plVar8 = (long *)(lVar4 + 0x6a0);
      if (plVar6 == plVar8) goto LAB_00ac117d;
      iVar7 = 0;
      do {
        if (plVar6[2] == param_1) {
          iVar7 = iVar7 + (uint)(plVar6[3] == *in_GS_OFFSET);
        }
        plVar6 = (long *)*plVar6;
      } while (plVar6 != plVar8);
      if (iVar7 == 0) goto LAB_00ac117d;
      func_0x004c7190(0x3bf6e80,0,0,0);
      lVar4 = *(long *)(param_1 + 0x20);
      param_2[5] = lVar4;
      if (lVar4 != 0) {
        *(long **)(lVar4 + 0x30) = param_2 + 5;
      }
      *(undefined8 *)(param_1 + 0x20) = param_2;
      param_2[6] = param_1 + 0x20;
      *(undefined4 *)(param_2 + 4) = 1;
      func_0x004c7520(0x3bf6e80,0,0,0);
      param_2[1] = (long)plVar8;
      lVar4 = *plVar8;
      *param_2 = lVar4;
      *(long **)(lVar4 + 8) = param_2;
      *plVar8 = (long)param_2;
      lVar4 = *in_GS_OFFSET;
    }
    else {
      param_2[1] = lVar4 + 0x6a0;
      lVar5 = *(long *)(lVar4 + 0x6a0);
      *param_2 = lVar5;
      *(long **)(lVar5 + 8) = param_2;
      *(long **)(lVar4 + 0x6a0) = param_2;
      lVar4 = *in_GS_OFFSET;
    }
    *(short *)(lVar4 + 0x10e) = *(short *)(lVar4 + 0x10e) + 1;
  }
  func_0x006a2650();
  return 1;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): FUN_00ac12d0 RVA 0xac12d0 | Evidence ev_638e08421bcde18ecb3ba6b2b6a6416ce37525755c3e79166d7a5662fe30fe80 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac12d0", "end": "0xac1327"}], "total_bytes": 88, "span_bytes": 88, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void FUN_00ac12d0(long *param_1)

{
  short sVar1;
  long lVar2;
  long *plVar3;
  code *pcVar4;
  short sVar5;
  long *in_GS_OFFSET;
  
  lVar2 = *param_1;
  plVar3 = (long *)param_1[1];
  *(long **)(lVar2 + 8) = plVar3;
  *plVar3 = lVar2;
  lVar2 = *in_GS_OFFSET;
  sVar1 = *(short *)(lVar2 + 0x10e);
  sVar5 = sVar1 + -1;
  *(short *)(lVar2 + 0x10e) = sVar5;
  if (sVar5 < 0) {
    func_0x007f1950();
    func_0x007f2010(sub_ac1328,0x132d45a,(long)*(short *)(lVar2 + 0x10e));
    func_0x00c9aa10(3,0x130e06a,0x132d45a,(int)*(short *)(lVar2 + 0x10e));
                    /* WARNING: Does not return */
    pcVar4 = (code *)invalidInstructionException();
    (*pcVar4)();
  }
  if (((*(byte *)(lVar2 + 0x108) & 4) != 0) &&
     ((int)*(short *)(lVar2 + 0x10c) + (int)*(short *)(lVar2 + 0x10a) == (int)(short)(1 - sVar1))) {
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac1328 RVA 0xac1328 | Evidence ev_a9e07b859718a71e1c7f607a2ff910d5d0c6a21b5fba6d82c936f9cd26bcb16a | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac1328", "end": "0xac1374"}], "total_bytes": 77, "span_bytes": 77, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_ac1328(long param_1)

{
  code *pcVar1;
  
  func_0x007f1950();
  func_0x007f2010(sub_ac1328,0x132d45a,(long)*(short *)(param_1 + 0x10e));
  func_0x00c9aa10(3,0x130e06a,0x132d45a,(int)*(short *)(param_1 + 0x10e));
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac1380 RVA 0xac1380 | Evidence ev_f2423811d10deb2def4ef5858d8262b46b71ef7a8230325822886e5b100597d2 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac1380", "end": "0xac14db"}], "total_bytes": 348, "span_bytes": 348, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Possible PIC construction at 0x00ac1430: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x00ac1435) */
/* WARNING: Removing unreachable block (ram,0x0042d6f0) */

void sub_ac1380(long param_1,long param_2)

{
  long lVar1;
  code *pcVar2;
  long *plVar3;
  long lVar4;
  
  if ((*(byte *)(param_1 + 0x108) & 1) != 0) {
    *(int *)(param_1 + 0x47c) = *(int *)(param_1 + 0x47c) + 1;
    func_0x006a2650();
  }
  if (*(int *)(param_2 + 0x20) == 0) {
    return;
  }
  func_0x004c7190(0x3bf6e80,0,0);
  lVar4 = *(long *)(param_2 + 0x28);
  if (lVar4 == 0) {
    plVar3 = *(long **)(param_2 + 0x30);
    if (*plVar3 != param_2) goto LAB_00ac1460;
    lVar4 = 0;
  }
  else {
    lVar1 = param_2 + 0x28;
    if (*(long *)(lVar4 + 0x30) != lVar1) {
      func_0x007f1950();
      func_0x007f2180(0xac149a,param_2,*(long *)(param_2 + 0x28),
                      *(undefined8 *)(*(long *)(param_2 + 0x28) + 0x30),lVar1);
      func_0x00c9aa10(7,0x130e07f,param_2,*(long *)(param_2 + 0x28),
                      *(undefined8 *)(*(long *)(param_2 + 0x28) + 0x30),lVar1);
                    /* WARNING: Does not return */
      pcVar2 = (code *)invalidInstructionException();
      (*pcVar2)();
    }
    if (**(long **)(param_2 + 0x30) != param_2) {
LAB_00ac1460:
      func_0x007f1950();
      func_0x007f20c0(0xac1460,param_2,*(undefined8 **)(param_2 + 0x30),
                      **(undefined8 **)(param_2 + 0x30));
      func_0x00c9aa10(0xb,0x12da4df,param_2,*(undefined8 **)(param_2 + 0x30),
                      **(undefined8 **)(param_2 + 0x30));
                    /* WARNING: Does not return */
      pcVar2 = (code *)invalidInstructionException();
      (*pcVar2)();
    }
    *(long **)(lVar4 + 0x30) = *(long **)(param_2 + 0x30);
    lVar4 = *(long *)(param_2 + 0x28);
    plVar3 = *(long **)(param_2 + 0x30);
  }
  *plVar3 = lVar4;
  if ((*(byte *)(param_2 + 0x20) & 2) != 0) {
    func_0x0042d560(*(undefined8 *)(param_2 + 0x10));
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac14e0 RVA 0xac14e0 | Evidence ev_88a051db72d73b0dc46f29b61cfb59e14331e08e30a2ccce2751eac50d77142c | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac14e0", "end": "0xac15f1"}], "total_bytes": 274, "span_bytes": 274, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Possible PIC construction at 0x00ac15ad: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x00ac15b2) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_ac14e0(long param_1)

{
  long lVar1;
  ulong uVar2;
  long *in_GS_OFFSET;
  
  if (*(short *)(*in_GS_OFFSET + 0x114) == 0) {
    if ((*(byte *)(param_1 + 10) & 0x10) == 0) {
      func_0x004c6a00(param_1 + 0x40,0,0,0);
    }
    else {
      func_0x00c4bb20(param_1 + 0x28,0,0,0);
    }
    if (_DAT_03d0e8e8 != *(ulong *)(param_1 + 0x18)) {
      uVar2 = ~*(ulong *)(param_1 + 0x18) & _DAT_03d0e8e8;
      *(ulong *)(param_1 + 0x18) = _DAT_03d0e8e8;
      func_0x00b03970(uVar2,0x261e08,0x264840,0x261e08,param_1);
      func_0x004c7190(0x3bf6e80,0,0,0);
      lVar1 = *(long *)(param_1 + 0x20);
      if (lVar1 != 0) {
        func_0x0042d590(param_1);
        *(undefined4 *)(lVar1 + 0x20) = 3;
      }
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
  }
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac1600 RVA 0xac1600 | Evidence ev_61be6079fecfc2cda574be07fa26c58f3a800c2797db91adfc918dad1e7dc3d3 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac1600", "end": "0xac16b6"}], "total_bytes": 183, "span_bytes": 183, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_ac1600(long param_1)

{
  long *plVar1;
  long lVar2;
  long lVar3;
  long *plVar4;
  long in_GS_OFFSET;
  
  lVar3 = func_0x004c8230(*(undefined4 *)(in_GS_OFFSET + 0x34));
  plVar4 = *(long **)(lVar3 + 0x6a0);
  if (plVar4 != (long *)(lVar3 + 0x6a0)) {
    plVar1 = (long *)(param_1 + 0x20);
    do {
      if ((plVar4[2] == param_1) && ((int)plVar4[4] == 0)) {
        *(undefined4 *)(plVar4 + 4) = 1;
        func_0x004c7190(0x3bf6e80,0,0,0);
        lVar2 = *plVar1;
        plVar4[5] = lVar2;
        if (lVar2 != 0) {
          *(long **)(lVar2 + 0x30) = plVar4 + 5;
        }
        *plVar1 = (long)plVar4;
        plVar4[6] = (long)plVar1;
        func_0x004c7520(0x3bf6e80,0,0);
      }
      plVar4 = (long *)*plVar4;
    } while (plVar4 != (long *)(lVar3 + 0x6a0));
  }
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac16c0 RVA 0xac16c0 | Evidence ev_3246e6e7b2572d7eafb76039907710d6527bdc4ea0e622f7d9b6e5e6d81d77b7 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac16c0", "end": "0xac16f5"}], "total_bytes": 54, "span_bytes": 54, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_ac16c0(long param_1)

{
  short *psVar1;
  long lVar2;
  long *in_GS_OFFSET;
  
  lVar2 = *in_GS_OFFSET;
  if (*(short *)(lVar2 + 0x114) == 0) {
    sub_ac14e0();
    if ((*(byte *)(param_1 + 10) & 0x10) == 0) {
      psVar1 = (short *)(lVar2 + 0x10a);
      *psVar1 = *psVar1 + 1;
    }
  }
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac1700 RVA 0xac1700 | Evidence ev_5639547d0cf2abcb2d026b8c71352915e6911df8fc7fc3384513acec7d3f56f4 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac1700", "end": "0xac1812"}], "total_bytes": 275, "span_bytes": 275, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_ac1700(long param_1)

{
  byte bVar1;
  long lVar2;
  code *pcVar3;
  short sVar4;
  undefined8 uVar5;
  long *in_GS_OFFSET;
  
  lVar2 = *in_GS_OFFSET;
  if (*(short *)(lVar2 + 0x114) == 0) {
    if ((*(byte *)(param_1 + 10) & 0x10) == 0) {
      func_0x004c6fa0(param_1 + 0x40,0,0,0);
      bVar1 = *(byte *)(param_1 + 10);
    }
    else {
      func_0x00c4c4b0(param_1 + 0x28,0,0);
      bVar1 = *(byte *)(param_1 + 10);
    }
    if ((bVar1 & 0x10) == 0) {
      sVar4 = *(short *)(lVar2 + 0x10a) + -1;
      *(short *)(lVar2 + 0x10a) = sVar4;
      if (sVar4 < 0) {
        func_0x007f1950();
        func_0x007f2010(0xac17d1,0x1337721,(long)*(short *)(lVar2 + 0x10a));
        sVar4 = *(short *)(lVar2 + 0x10a);
        uVar5 = 0xf;
        goto LAB_00ac1807;
      }
      if (((*(byte *)(lVar2 + 0x108) & 4) != 0) &&
         ((int)*(short *)(lVar2 + 0x10e) + (int)*(short *)(lVar2 + 0x10c) + (int)sVar4 == 0)) {
        func_0x006b6cf0(lVar2);
      }
    }
    if (*(short *)(lVar2 + 0x10a) < 0) {
      func_0x007f1950();
      func_0x007f2010(0xac1799,0x1337721,(long)*(short *)(lVar2 + 0x10a));
      sVar4 = *(short *)(lVar2 + 0x10a);
      uVar5 = 0x13;
LAB_00ac1807:
      func_0x00c9aa10(uVar5,0x134661a,0x1337721,(int)sVar4);
                    /* WARNING: Does not return */
      pcVar3 = (code *)invalidInstructionException();
      (*pcVar3)();
    }
  }
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac1820 RVA 0xac1820 | Evidence ev_593c2a44869b0e2856682997dcff42eb2ad17fcc102bb67cdd191a154b637fe9 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac1820", "end": "0xac186e"}], "total_bytes": 79, "span_bytes": 79, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_ac1820(long param_1)

{
  short *psVar1;
  long lVar2;
  int iVar3;
  undefined8 uVar4;
  long *in_GS_OFFSET;
  
  lVar2 = *in_GS_OFFSET;
  uVar4 = 1;
  if (*(short *)(lVar2 + 0x114) == 0) {
    iVar3 = sub_ac0f60();
    if (iVar3 == 0) {
      uVar4 = 0;
    }
    else if ((*(byte *)(param_1 + 10) & 0x10) == 0) {
      psVar1 = (short *)(lVar2 + 0x10a);
      *psVar1 = *psVar1 + 1;
    }
  }
  return uVar4;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac1870 RVA 0xac1870 | Evidence ev_ab68bdcbcb10aeeaf1a5d166ecf573f5e09cdb68e452eef421eeeb0aaf2fdd0b | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac1870", "end": "0xac19d4"}], "total_bytes": 357, "span_bytes": 357, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_ac1870(long param_1,long param_2)

{
  int *piVar1;
  int iVar2;
  long lVar3;
  long lVar4;
  code *pcVar5;
  short sVar6;
  undefined8 uVar7;
  long *in_GS_OFFSET;
  
  lVar3 = *in_GS_OFFSET;
  if (*(short *)(lVar3 + 0x114) == 0) {
    lVar4 = *(long *)(param_2 + 0x18);
    *(int *)(lVar4 + 0x47c) = *(int *)(lVar4 + 0x47c) + 1;
    FUN_00ac12d0(param_2);
    *(int *)(lVar4 + 0x47c) = *(int *)(lVar4 + 0x47c) + -1;
    func_0x006b7960();
    LOCK();
    piVar1 = (int *)(*in_GS_OFFSET + 0x5a8);
    iVar2 = *piVar1;
    *piVar1 = *piVar1 + -1;
    UNLOCK();
    if (iVar2 == -0x7fffffff) {
      func_0x006b7af0();
    }
    if ((*(byte *)(param_1 + 10) & 0x10) != 0) {
      *(int *)(lVar3 + 0x370) = *(int *)(lVar3 + 0x370) + -1;
    }
    if ((*(byte *)(lVar4 + 0x108) & 1) != 0 || *(int *)(param_2 + 0x20) != 0) {
      sub_ac1380(lVar4,param_2);
    }
    if ((*(byte *)(param_1 + 10) & 0x10) == 0) {
      sVar6 = *(short *)(lVar3 + 0x10a) + -1;
      *(short *)(lVar3 + 0x10a) = sVar6;
      if (sVar6 < 0) {
        func_0x007f1950();
        func_0x007f2010(0xac1993,0x1341f58,(long)*(short *)(lVar3 + 0x10a));
        sVar6 = *(short *)(lVar3 + 0x10a);
        uVar7 = 0x17;
        goto LAB_00ac19c9;
      }
      if ((*(byte *)(lVar3 + 0x108) & 4) != 0) {
        if ((int)*(short *)(lVar3 + 0x10e) + (int)*(short *)(lVar3 + 0x10c) + (int)sVar6 == 0) {
          func_0x006b6cf0(lVar3);
        }
      }
    }
    if (*(short *)(lVar3 + 0x10a) < 0) {
      func_0x007f1950();
      func_0x007f2010(0xac195b,0x1341f58,(long)*(short *)(lVar3 + 0x10a));
      sVar6 = *(short *)(lVar3 + 0x10a);
      uVar7 = 0x1b;
LAB_00ac19c9:
      func_0x00c9aa10(uVar7,0x134661a,0x1341f58,(int)sVar6);
                    /* WARNING: Does not return */
      pcVar5 = (code *)invalidInstructionException();
      (*pcVar5)();
    }
  }
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac19e0 RVA 0xac19e0 | Evidence ev_d27f17df768454d9f970bdcc2ea40b02a68606747a3375f09456b39b3ed6cfae | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac19e0", "end": "0xac19f1"}], "total_bytes": 18, "span_bytes": 18, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined1 * sub_ac19e0(void)

{
  sub_ac1a00();
  return &DAT_03cba190;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac1a00 RVA 0xac1a00 | Evidence ev_e2839777497ff58943c72985ef9b0381ab21f81e9c74f26663594e603363dea9 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac1a00", "end": "0xac1bce"}], "total_bytes": 463, "span_bytes": 463, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_ac1a00(undefined4 param_1,undefined4 param_2)

{
  func_0x00258ff0(&DAT_03cba190,0x3dc8);
  _DAT_03cba190 = 0x10500003dc8;
  _DAT_03cba198 = 0xbc000000b4;
  _DAT_03cba1a8 = 0x13c;
  _DAT_03cba1a0 = 0xd800000002;
  _DAT_03cba1b4 = 0x3d2000003d10;
  _DAT_03cba1ac = 0x3d0000000003;
  _DAT_03cba1c4 = 0x3d6000003d48;
  _DAT_03cba1cc = 0x3d9000003d78;
  _DAT_03cba1bc = 0x3d3000000005;
  _DAT_03cba1d8 = 0x1e0000001a0;
  _DAT_03cba1e0 = 0x700000005b8;
  _DAT_03cba1e8 = 0xd8000000c88;
  _DAT_03cba1f0 = 0x119800000dc0;
  _DAT_03cba1f8 = 0x1868000012e0;
  _DAT_03cba200 = 0x19a000001960;
  _DAT_03cba208 = 0x1ec000001d78;
  _DAT_03cba210 = 0x254000002448;
  _DAT_03cba218 = 0x295800002580;
  _DAT_03cba220 = 0x302800002aa0;
  _DAT_03cba228 = 0x316000003120;
  _DAT_03cba230 = 0x368000003538;
  _DAT_03cba238 = 0x3c08;
  _DAT_03cba1d4 = 5;
  func_0x0027f080(&DAT_03cba190);
  _DAT_03cba24c = 0x1c;
  func_0x009a0640(&DAT_03cba24c);
  sub_ac1cd0(param_1,param_2);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac1bd0 RVA 0xac1bd0 | Evidence ev_65383cdee2d6a9ee0d703683d5b82b420109c1b99a053ef1b2c806f9103dc74c | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac1bd0", "end": "0xac1ccd"}], "total_bytes": 254, "span_bytes": 254, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_ac1bd0(ulong param_1)

{
  code *pcVar1;
  int iVar2;
  undefined1 local_48 [8];
  undefined1 local_40 [8];
  ulong local_38;
  long local_30;
  long local_28;
  
  local_28 = _DAT_0391c310;
  iVar2 = func_0x00c9fe80(param_1,&local_30,&local_38,local_40,local_48);
  if ((iVar2 == 0) && (0xc9247 < local_38)) {
    func_0x00b7b1e0(0x18,0xb2);
    sub_ac1a00(param_1 & 0xffffffff,0xffffffff);
    func_0x00b7b1c0(0x18,0xb6);
    func_0x00258ff0(&DAT_03bf6e88,4);
    _DAT_03bf6e88 = 0x11d;
    iVar2 = func_0x007a90f0(param_1 & 0xffffffff,local_30,&DAT_03bf6e88,4);
    if (iVar2 == 0) {
      func_0x007a90f0(param_1 & 0xffffffff,local_30 + 0xc3308,&DAT_03cba190,0x3dc8);
    }
    else {
      func_0x00b7b1e0(0x18,0xc1);
      func_0x00b7b1c0(0x18,0xc2);
    }
  }
  if (_DAT_0391c310 == local_28) {
    return;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac1cd0 RVA 0xac1cd0 | Evidence ev_1629a90a98102909f6834c26f57dc3a0c1a72268d52b9127a686bf0533a09e65 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac1cd0", "end": "0xac1d0e"}, {"start": "0xac1d10", "end": "0xac1e69"}], "total_bytes": 409, "span_bytes": 410, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_ac1cd0(undefined8 param_1,int param_2)

{
  code *pcVar1;
  int iVar2;
  long lVar3;
  long lVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  long *in_GS_OFFSET;
  
  lVar3 = func_0x008647c0();
  if (lVar3 != 0) {
    iVar5 = 6;
    if (-1 < param_2) {
      iVar5 = param_2;
    }
    if (param_2 < 1) {
      param_2 = 0;
    }
    iVar7 = 0;
    iVar6 = 0;
    do {
      lVar4 = func_0x004d8060(lVar3,param_2,2,0x18,0x53);
      if (lVar4 != 0) {
        iVar2 = func_0x004d7ed0(lVar4);
        if (iVar2 < 0) {
          func_0x00b044d0(0,0,0x18dc3ce,0x12ba7b7,0x58);
          func_0x00b044d0(0,0,0x18dc3dc,param_2,iVar2);
          func_0x007f1950();
          func_0x007f2010(0xac1e2d,0x12ba7b7,0x58);
          func_0x00c9aa10(5,0x128989e,0x12ba7b7,0x58);
                    /* WARNING: Does not return */
          pcVar1 = (code *)invalidInstructionException();
          (*pcVar1)();
        }
        if (iVar7 < 5) {
          func_0x004ddb00(lVar4,(long)iVar7 * 0xbe0 + 0x3cba330,iVar6);
          func_0x004da8d0(lVar4,0x18,0x60);
          iVar7 = iVar7 + 1;
          iVar6 = iVar6 + 1;
        }
        else {
          func_0x00b044d0(0,0,0x18dc3f0,0x12ba7b7,0x5a,
                          *(undefined4 *)(*(long *)(*in_GS_OFFSET + 8) + 0xbc));
          func_0x00b044d0(0,0,0x18dc400,iVar2,iVar7);
        }
      }
      param_2 = param_2 + 1;
    } while (param_2 <= iVar5);
  }
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_ac1e70 RVA 0xac1e70 | Evidence ev_d18857b8b3e9caed80498a2b0c0318ccdda745a4fbaa56ad7cb5e068a8f01134 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_646.body.bin SHA256 b3d91202fe3cf3ebda765e8f158d03c6e6af1747c07cb2d1cfb5cbe2c80ea925 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xac1e70", "end": "0xac21be"}], "total_bytes": 847, "span_bytes": 847, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Removing unreachable block (ram,0x00ac20a2) */
/* WARNING: Removing unreachable block (ram,0x00ac20b8) */
/* WARNING: Removing unreachable block (ram,0x00ac20a9) */
/* WARNING: Removing unreachable block (ram,0x00ac20b1) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_ac1e70(long param_1)

{
  int iVar1;
  char *pcVar2;
  undefined8 uVar3;
  bool bVar4;
  undefined1 local_200 [172];
  uint local_154;
  char *local_150;
  long local_148;
  long local_140 [4];
  undefined8 local_120;
  long local_118;
  undefined1 *local_110;
  undefined8 local_108;
  long local_38;
  
  local_38 = _DAT_0391c310;
  if ((*(ulong *)(param_1 + 0x98) & 0x4000) == 0) {
    if ((*(ulong *)(param_1 + 0x98) & 0x10000) == 0) {
      iVar1 = func_0x005defd0(*(undefined8 *)(param_1 + 0xa8),0x136e89e,local_140,&local_154);
      if (iVar1 == 0) {
        bVar4 = false;
      }
      else {
        iVar1 = func_0x005defd0(*(undefined8 *)(param_1 + 0xa8),0x12b2da1,local_140,&local_154);
        bVar4 = iVar1 != 0;
      }
      if (((int)local_154 < 1 || bVar4) || (*(char *)(local_140[0] + -1 + (ulong)local_154) != '\0')
         ) {
        uVar3 = 0x13579f8;
      }
      else {
        func_0x005defd0(*(undefined8 *)(param_1 + 0xa8),0x1318673,0,0);
        iVar1 = func_0x005defd0(*(undefined8 *)(param_1 + 0xa8),0x12c5015,&local_148,0);
        if (iVar1 == 0) {
          if (((local_148 != 0) && (func_0x007c4e40(local_148,&local_150,8), local_148 != 0)) &&
             (*local_150 == '\0')) {
                    /* WARNING: Bad instruction - Truncating control flow here */
            halt_baddata();
          }
          uVar3 = 0x1291c35;
        }
        else {
          iVar1 = func_0x005defd0(*(undefined8 *)(param_1 + 0xa8),0x130e0df,&local_148,0);
          if (iVar1 != 0) {
            iVar1 = func_0x005defd0(*(undefined8 *)(param_1 + 0xa8),0x1305bf6,&local_148,0);
            pcVar2 = (char *)func_0x005defd0(*(undefined8 *)(param_1 + 0xa8),0x1275d61,&local_148,0)
            ;
            if ((int)pcVar2 == 0 && iVar1 == 0) {
              *pcVar2 = *pcVar2 + (char)pcVar2;
                    /* WARNING: Bad instruction - Truncating control flow here */
              halt_baddata();
            }
            func_0x006afb50(*(undefined8 *)(param_1 + 0x48),0x200400,0x134cd6e,0xb9);
            local_118 = *(long *)(param_1 + 0x48);
            local_108 = *(undefined8 *)(param_1 + 0x290);
            local_110 = local_200;
            local_120 = 0x1adad78;
            iVar1 = func_0x0058c1c0(*(undefined8 *)(local_118 + 8),&local_120);
            if (iVar1 != 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
              halt_baddata();
            }
                    /* WARNING: Bad instruction - Truncating control flow here */
            halt_baddata();
          }
          if (((local_148 != 0) && (func_0x007c4e40(local_148,&local_150,8), local_148 != 0)) &&
             (*local_150 == '\0')) {
                    /* WARNING: Bad instruction - Truncating control flow here */
            halt_baddata();
          }
          uVar3 = 0x1287716;
        }
      }
      func_0x005e0bd0(param_1,uVar3);
      uVar3 = 0x16;
      goto LAB_00ac1f66;
    }
    uVar3 = 0x1395b35;
  }
  else {
    uVar3 = 0x1380c9c;
  }
  func_0x005e0bd0(param_1,uVar3);
  uVar3 = 0x2d;
LAB_00ac1f66:
  if (_DAT_0391c310 == local_38) {
    return uVar3;
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): credential_bit62_predicate RVA 0x608f90 | Evidence ev_d868091f9a6f6b9f04dcc2affd8e4028a0950346d4f8cbeccee7c2384b5c3673 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/common_support.functions/0x608f90.json | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/common_support.elf SHA256 843fa164383f956095dc4042a013c49d64f59c358ea7f43c10f0d9923485fd5a =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x608f90", "end": "0x608fa0"}], "total_bytes": 17, "span_bytes": 17, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

uint processEntry credential_bit62_predicate(void)

{
  long in_RDI;
  
  return (uint)((ulong)*(undefined8 *)(in_RDI + 0x60) >> 0x3e) & 1;
}


