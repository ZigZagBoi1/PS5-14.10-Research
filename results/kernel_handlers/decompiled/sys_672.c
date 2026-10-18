/* Handler 672: REA6.7.0 / Ghidra12.1.4 recovered pseudocode, not original or buildable C.
 * Original4096-byte input SHA256 29b3056b1cba647ae8920fdadfac92af115e427f59fdba6d30cba82f9bd3479e
 * Raw entry RVA 0x2655a8 -> actual target 0x34c670. narg=3.
 * Kernel RVAs; runtime VA=0xffffffff8a9c0000+RVA. Opaque externals/data remain unknown.
 * Analyst types below are inferred from accesses. Recovered pseudocode is retained verbatim afterward.
 * Original entry is an assembly-verified tail JMP to the target above. An engine halt_baddata
 * at that unmapped edge is a decompiler boundary artifact, not a recovered halt operation.
 */
#include <stdint.h>

/* ===== Analyst recovered interface/types ===== */
struct handler_672_args { uint32_t *module_handles; uint64_t capacity; uint64_t *result_count; };
extern int impl_34b540(void *process, uint32_t *module_handles, uint64_t capacity, uint32_t include_flagged_nodes, uint64_t *result_count);
/* This wrapper forwards include_flagged_nodes=1. */


/* ===== ORIGINAL ENTRY: <EXTERNAL>::thunk_EXT_FUN_0034c670 RVA 0x2655a8 | Evidence ev_d01cd7a6e3ea0edaa7ccd4339e00bf942cebf00d18f434637b5cadf1badfce60 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_672.raw.dossier.json | Source /tmp/rea-646-676-5b61b6f2/raw_union.bin SHA256 352988f408bc976411feddb3ef6cd2b18459d2aa3fa6dfd7f2e4a7fe416ce915 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2655a8", "end": "0x2655ac"}], "total_bytes": 5, "span_bytes": 5, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_0034c670(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): handler_659_body RVA 0x34b790 | Evidence ev_66db5dbc6bb440a3c83f47a29715adfde56230b2339e8004128101a6db727409 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34b790", "end": "0x34b7ad"}], "total_bytes": 30, "span_bytes": 30, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void handler_659_body(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_593 RVA 0x34b7b0 | Evidence ev_d4ee4c062a541622112197cff17ff2497d333c53df925be1b0d19a8fdf9d592c | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34b7b0", "end": "0x34b905"}], "total_bytes": 342, "span_bytes": 342, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 sys_593(long param_1,undefined4 *param_2)

{
  undefined4 uVar1;
  long lVar2;
  undefined8 uVar3;
  code *pcVar4;
  int iVar5;
  undefined4 uVar6;
  undefined8 uVar7;
  undefined8 *in_GS_OFFSET;
  long local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  lVar2 = *(long *)(*(long *)(param_1 + 8) + 1000);
  if ((lVar2 == 0) || (*(long *)(*(long *)(lVar2 + 0x10) + 0x148) == 0)) {
    func_0x00b22a30(0x128a660,0x497,0x12fbd8a,0x135ae30);
    uVar6 = 1;
  }
  else {
    uVar1 = *param_2;
    uVar3 = *(undefined8 *)(param_2 + 2);
    func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
    iVar5 = func_0x00259280(uVar3,&local_40,8);
    uVar6 = 0xe;
    if ((iVar5 == 0) && (uVar6 = 0x16, local_40 == 0x160)) {
      uVar7 = func_0x00b2ac60(0x160,10);
      iVar5 = sub_34b950(lVar2,uVar1,1,uVar7);
      if (iVar5 == 0) {
        func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
        uVar6 = func_0x002591d0(uVar7,uVar3,0x160);
        func_0x00b24250(uVar7,0x160,10);
      }
      else {
        func_0x00b24250(uVar7,0x160,10);
        uVar6 = 3;
      }
    }
  }
  if (_DAT_0391c310 == local_38) {
    return uVar6;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar4 = (code *)invalidInstructionException();
  (*pcVar4)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34b910 RVA 0x34b910 | Evidence ev_122c7d60f5c01bfb6bcb746ff3776dc2e6386029fcd347e7e55c0d1fccebddbb | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34b910", "end": "0x34b947"}], "total_bytes": 56, "span_bytes": 56, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_34b910(void)

{
  undefined8 *in_GS_OFFSET;
  
  func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34b950 RVA 0x34b950 | Evidence ev_38e9054f277fec02592d87c23f090fb23de0dd872bec88b9536e118dbbcd1d7f | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34b950", "end": "0x34bbc0"}, {"start": "0x34bbd0", "end": "0x34bc53"}], "total_bytes": 757, "span_bytes": 772, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_34b950(long *param_1,int param_2,int param_3,long param_4)

{
  long *plVar1;
  char *pcVar2;
  int iVar3;
  ulong uVar4;
  long lVar5;
  long lVar6;
  uint uVar7;
  long lVar8;
  uint uVar9;
  long lVar10;
  undefined8 uVar11;
  
  plVar1 = param_1 + 0xe;
  func_0x00c4bb20(plVar1,0,0,0);
  do {
    param_1 = (long *)*param_1;
    if (param_1 == (long *)0x0) {
      uVar11 = 3;
      goto LAB_0034bb70;
    }
  } while (param_2 != *(int *)(param_1 + 5));
  func_0x00258ff0(param_4,0x160);
  if ((param_3 == 0) && (uVar11 = 1, (*(byte *)((long)param_1 + 0x11d) & 1) != 0))
  goto LAB_0034bb70;
  pcVar2 = (char *)param_1[1];
  if (pcVar2 == (char *)0x0) {
LAB_0034ba08:
    uVar11 = 0x2f;
  }
  else {
    uVar4 = func_0x00444eb0(pcVar2,0x400);
    if ((((uVar4 < 6) || (*pcVar2 != '/')) || (pcVar2[1] != 'h')) ||
       (((pcVar2[2] != 'o' || (pcVar2[3] != 's')) ||
        ((pcVar2[4] != 't' || (uVar11 = 0x5c, pcVar2[5] != '/')))))) goto LAB_0034ba08;
  }
  lVar6 = param_1[1];
  lVar5 = func_0x00272200(lVar6,uVar11);
  lVar8 = lVar5 + 1;
  if (lVar5 == 0) {
    lVar8 = lVar6;
  }
  func_0x00984440(param_4 + 8,lVar8,0x100);
  *(undefined1 *)(param_4 + 0x107) = 0;
  iVar3 = func_0x00b2bb00(1);
  if (iVar3 == 0) {
    if (*(int *)(param_1 + 9) == 3) {
      *(undefined8 *)(param_4 + 0x108) = *(undefined8 *)(param_1[10] + 8);
      *(undefined4 *)(param_4 + 0x110) = *(undefined4 *)(param_1[10] + 0x10);
      *(undefined4 *)(param_4 + 0x114) = 5;
      *(undefined8 *)(param_4 + 0x118) = *(undefined8 *)(param_1[0xc] + 8);
      *(undefined4 *)(param_4 + 0x120) = *(undefined4 *)(param_1[0xc] + 0x10);
      *(undefined4 *)(param_4 + 0x124) = 3;
      *(undefined8 *)(param_4 + 0x128) = *(undefined8 *)(param_1[0xb] + 8);
      *(undefined4 *)(param_4 + 0x130) = *(undefined4 *)(param_1[0xb] + 0x10);
      *(undefined4 *)(param_4 + 0x134) = 1;
    }
    else {
      if (*(int *)(param_1 + 9) != 2) {
        *(undefined4 *)(param_4 + 0x148) = 0;
        uVar7 = *(uint *)(param_1 + 9);
        if (uVar7 != 0) {
          uVar4 = 4;
          if (uVar7 < 4) {
            uVar4 = (ulong)uVar7;
          }
          lVar6 = 0;
          uVar7 = 0;
          do {
            lVar5 = param_1[8];
            lVar10 = (ulong)uVar7 * 0x10;
            lVar8 = param_4 + 0x108 + lVar10;
            *(undefined8 *)(param_4 + 0x108 + lVar10) = *(undefined8 *)(lVar5 + 8 + lVar6);
            *(undefined4 *)(param_4 + 0x110 + lVar10) = *(undefined4 *)(lVar5 + 0x10 + lVar6);
            *(undefined4 *)(param_4 + 0x114 + lVar10) = 0;
            uVar9 = *(uint *)(*(long *)(lVar5 + lVar6) + 0xc) & 1;
            *(uint *)(param_4 + 0x114 + lVar10) = uVar9;
            uVar7 = *(uint *)(*(long *)(lVar5 + lVar6) + 0xc);
            if ((uVar7 & 2) != 0) {
              uVar9 = uVar9 | 2;
              *(uint *)(lVar8 + 0xc) = uVar9;
              uVar7 = *(uint *)(*(long *)(lVar5 + lVar6) + 0xc);
            }
            if ((uVar7 & 4) != 0) {
              *(uint *)(lVar8 + 0xc) = uVar9 | 4;
            }
            lVar6 = lVar6 + 0x18;
            uVar7 = *(int *)(param_4 + 0x148) + 1;
            *(uint *)(param_4 + 0x148) = uVar7;
          } while (uVar4 * 0x18 != lVar6);
        }
        goto LAB_0034bb5b;
      }
      *(undefined8 *)(param_4 + 0x108) = *(undefined8 *)(param_1[10] + 8);
      *(undefined4 *)(param_4 + 0x110) = *(undefined4 *)(param_1[10] + 0x10);
      *(undefined4 *)(param_4 + 0x114) = 5;
      *(undefined8 *)(param_4 + 0x118) = *(undefined8 *)(param_1[0xc] + 8);
      *(undefined4 *)(param_4 + 0x120) = *(undefined4 *)(param_1[0xc] + 0x10);
      *(undefined4 *)(param_4 + 0x124) = 3;
    }
    *(undefined4 *)(param_4 + 0x148) = *(undefined4 *)(param_1 + 9);
  }
  else {
    *(undefined4 *)(param_4 + 0x148) = 0;
    func_0x00258ff0(param_4 + 0x108,0x40);
  }
LAB_0034bb5b:
  func_0x00b2b740(param_4 + 0x14c,param_1);
  uVar11 = 0;
LAB_0034bb70:
  func_0x00c4c4b0(plVar1,0,0);
  return uVar11;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_660 RVA 0x34bc60 | Evidence ev_f9e358c5d256624605272091fac1d6e65f799be58fced44d6a9e3daa27c2c5b7 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34bc60", "end": "0x34bdb1"}], "total_bytes": 338, "span_bytes": 338, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sys_660(long param_1,undefined4 *param_2)

{
  undefined4 uVar1;
  long lVar2;
  undefined8 uVar3;
  code *pcVar4;
  int iVar5;
  int iVar6;
  long *plVar7;
  undefined8 *in_GS_OFFSET;
  long local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  lVar2 = *(long *)(*(long *)(param_1 + 8) + 1000);
  if ((lVar2 == 0) || (*(long *)(*(long *)(lVar2 + 0x10) + 0x148) == 0)) {
    func_0x00b22a30(0x133054a,0x4cb,0x12fbd8a,0x135ae30);
    iVar6 = 1;
  }
  else {
    uVar1 = *param_2;
    uVar3 = *(undefined8 *)(param_2 + 2);
    func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
    iVar5 = func_0x00259280(uVar3,&local_40,8);
    iVar6 = 0xe;
    if ((iVar5 == 0) && (iVar6 = 0x16, local_40 == 0x160)) {
      plVar7 = (long *)func_0x00b2ac60(0x160,10);
      iVar6 = sub_34b950(lVar2,uVar1,0,plVar7);
      if (iVar6 == 0) {
        *plVar7 = local_40;
        func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
        iVar6 = func_0x002591d0(plVar7,uVar3,0x160);
      }
      func_0x00b24250(plVar7,0x160,10);
    }
  }
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar4 = (code *)invalidInstructionException();
    (*pcVar4)();
  }
  return iVar6;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_608 RVA 0x34bdc0 | Evidence ev_738694d1b7fb232d245b2fc2a4db775fa6ab33eb9f5acbaf31c883b6839b3a7b | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34bdc0", "end": "0x34c283"}], "total_bytes": 1220, "span_bytes": 1220, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 sys_608(long param_1,int *param_2)

{
  long *plVar1;
  ushort uVar2;
  undefined8 uVar3;
  char *pcVar4;
  long lVar5;
  code *pcVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  undefined4 uVar10;
  long lVar11;
  ulong uVar12;
  long lVar13;
  uint *puVar14;
  undefined8 uVar15;
  long lVar16;
  long lVar17;
  uint uVar18;
  uint uVar19;
  long *plVar20;
  undefined8 *in_GS_OFFSET;
  long local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  lVar17 = *(long *)(param_1 + 8);
  plVar20 = *(long **)(lVar17 + 1000);
  if ((plVar20 == (long *)0x0) || (*(long *)(plVar20[2] + 0x148) == 0)) {
    func_0x00b22a30(0x128a674,0x504,0x12fbd8a,0x135ae30);
    uVar10 = 1;
    goto LAB_0034c0b2;
  }
  uVar19 = param_2[2];
  iVar8 = *param_2;
  uVar3 = *(undefined8 *)(param_2 + 4);
  func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
  iVar7 = func_0x00259280(uVar3,&local_40,8);
  uVar10 = 0xe;
  if ((iVar7 != 0) || (uVar10 = 0x16, local_40 != 0x1a8)) goto LAB_0034c0b2;
  lVar11 = func_0x00b2ac60(0x1a8,10);
  plVar1 = plVar20 + 0xe;
  func_0x00c4bb20(plVar1,0,0,0);
  do {
    plVar20 = (long *)*plVar20;
    if (plVar20 == (long *)0x0) {
      func_0x00c4c4b0(plVar1,0,0);
      func_0x00b24250(lVar11,0x1a8,10);
      uVar10 = 3;
      goto LAB_0034c0b2;
    }
  } while (iVar8 != *(int *)(plVar20 + 5));
  func_0x00258ff0(lVar11,0x1a8);
  pcVar4 = (char *)plVar20[1];
  if (pcVar4 == (char *)0x0) {
LAB_0034beff:
    uVar15 = 0x2f;
  }
  else {
    uVar12 = func_0x00444eb0(pcVar4,0x400);
    if ((((uVar12 < 6) || (*pcVar4 != '/')) || (pcVar4[1] != 'h')) ||
       (((pcVar4[2] != 'o' || (pcVar4[3] != 's')) ||
        ((pcVar4[4] != 't' || (uVar15 = 0x5c, pcVar4[5] != '/')))))) goto LAB_0034beff;
  }
  lVar5 = plVar20[1];
  lVar13 = func_0x00272200(lVar5,uVar15);
  lVar16 = lVar13 + 1;
  if (lVar13 == 0) {
    lVar16 = lVar5;
  }
  func_0x00984440(lVar11 + 8,lVar16,0x100);
  *(undefined1 *)(lVar11 + 0x107) = 0;
  *(undefined4 *)(lVar11 + 0x108) = *(undefined4 *)(plVar20 + 5);
  uVar2 = *(ushort *)(plVar20 + 0xe);
  *(uint *)(lVar11 + 0x10c) = (uint)uVar2;
  if ((uVar19 & 1) != 0) {
    *(uint *)(lVar11 + 0x10c) =
         ((*(ushort *)((long)plVar20 + 0x11c) >> 8 & 1) +
         (*(ushort *)((long)plVar20 + 0x11c) & 1) * 2) * 0x10000 | (uint)uVar2;
  }
  if ((uVar19 & 2) != 0) {
    if ((*(byte *)((long)plVar20 + 0x11d) & 1) == 0) {
      iVar8 = func_0x00b2bb00(2);
      if (iVar8 != 1) goto LAB_0034bfa4;
    }
    func_0x00258ff0(lVar11 + 8);
  }
LAB_0034bfa4:
  *(long *)(lVar11 + 0x110) = plVar20[0xf];
  *(undefined4 *)(lVar11 + 0x118) = *(undefined4 *)(plVar20 + 0x10);
  *(undefined4 *)(lVar11 + 0x11c) = *(undefined4 *)(plVar20 + 0x11);
  *(undefined4 *)(lVar11 + 0x120) = *(undefined4 *)(plVar20 + 0x12);
  *(undefined4 *)(lVar11 + 0x124) = *(undefined4 *)(plVar20 + 0x13);
  *(undefined8 *)(lVar11 + 0x138) = 0;
  *(undefined8 *)(lVar11 + 0x140) = 0;
  *(long *)(lVar11 + 0x148) = plVar20[0x1f];
  *(long *)(lVar11 + 0x150) = plVar20[0x21];
  *(undefined4 *)(lVar11 + 0x158) = *(undefined4 *)(plVar20 + 0x20);
  *(undefined4 *)(lVar11 + 0x15c) = *(undefined4 *)(plVar20 + 0x22);
  *(undefined4 *)(lVar11 + 0x1a4) = *(undefined4 *)(plVar20 + 4);
  iVar8 = func_0x00b2bb00(2);
  if (iVar8 == 0) {
    if ((*(byte *)((long)plVar20 + 0x11d) & 0x10) == 0) {
      *(long *)(lVar11 + 0x128) = plVar20[0x1d];
      uVar15 = plVar20[0x1e];
    }
    else {
      *(undefined8 *)(lVar11 + 0x128) = 0;
      uVar15 = 0;
    }
    *(undefined8 *)(lVar11 + 0x130) = uVar15;
    if (*(char *)(lVar17 + 0xc81) == '\0') {
      *(undefined8 *)(lVar11 + 0x160) = *(undefined8 *)(plVar20[10] + 8);
      *(undefined4 *)(lVar11 + 0x168) = *(undefined4 *)(plVar20[10] + 0x10);
      *(undefined4 *)(lVar11 + 0x16c) = 5;
      *(undefined8 *)(lVar11 + 0x170) = *(undefined8 *)(plVar20[0xc] + 8);
      *(undefined4 *)(lVar11 + 0x178) = *(undefined4 *)(plVar20[0xc] + 0x10);
      *(undefined4 *)(lVar11 + 0x17c) = 3;
      *(undefined4 *)(lVar11 + 0x1a0) = 2;
    }
    else {
      uVar19 = *(uint *)(plVar20 + 9);
      *(undefined4 *)(lVar11 + 0x1a0) = 0;
      uVar9 = 4;
      if (uVar19 < 4) {
        uVar9 = uVar19;
      }
      if (uVar19 != 0) {
        lVar17 = 0;
        puVar14 = (uint *)(lVar11 + 0x16c);
        do {
          lVar5 = plVar20[8];
          *(undefined8 *)(puVar14 + -3) = *(undefined8 *)(lVar5 + 8 + lVar17);
          puVar14[-1] = *(uint *)(lVar5 + 0x10 + lVar17);
          *puVar14 = 0;
          uVar18 = *(uint *)(*(long *)(lVar5 + lVar17) + 0xc) & 1;
          *puVar14 = uVar18;
          uVar19 = *(uint *)(*(long *)(lVar5 + lVar17) + 0xc);
          if ((uVar19 & 2) != 0) {
            uVar18 = uVar18 | 2;
            *puVar14 = uVar18;
            uVar19 = *(uint *)(*(long *)(lVar5 + lVar17) + 0xc);
          }
          if ((uVar19 & 4) != 0) {
            *puVar14 = uVar18 | 4;
          }
          lVar17 = lVar17 + 0x18;
          puVar14 = puVar14 + 4;
        } while ((ulong)uVar9 * 0x18 != lVar17);
      }
      *(uint *)(lVar11 + 0x1a0) = uVar9;
    }
  }
  else {
    *(undefined8 *)(lVar11 + 0x128) = 0;
    *(undefined8 *)(lVar11 + 0x130) = 0;
    *(undefined4 *)(lVar11 + 0x1a0) = 0;
    func_0x00258ff0(lVar11 + 0x160,0x40);
  }
  func_0x00c4c4b0(plVar1,0,0);
  func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
  uVar10 = func_0x002591d0(lVar11,uVar3,0x1a8);
  func_0x00b24250(lVar11,0x1a8,10);
LAB_0034c0b2:
  if (_DAT_0391c310 == local_38) {
    return uVar10;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar6 = (code *)invalidInstructionException();
  (*pcVar6)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34c290 RVA 0x34c290 | Evidence ev_6cf6a3576d9cc0b395f57d7d090a43d5d60e62eb688868851fc04dd699fec14a | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34c290", "end": "0x34c2e5"}], "total_bytes": 86, "span_bytes": 86, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_34c290(char *param_1)

{
  ulong uVar1;
  undefined8 uVar2;
  
  uVar2 = 0;
  if (param_1 != (char *)0x0) {
    uVar1 = func_0x00444eb0(param_1,0x400);
    if ((5 < uVar1) &&
       ((((*param_1 != '/' || (param_1[1] != 'h')) || (param_1[2] != 'o')) ||
        (((param_1[3] != 's' || (param_1[4] != 't')) || (uVar2 = 1, param_1[5] != '/')))))) {
      uVar2 = 0;
    }
  }
  return uVar2;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34c2f0 RVA 0x34c2f0 | Evidence ev_face82640cb3d9e3fa1f2abcda2ff5bc4a8573c256023184d913474158711de6 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34c2f0", "end": "0x34c317"}], "total_bytes": 40, "span_bytes": 40, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

long sub_34c2f0(long param_1)

{
  long lVar1;
  long lVar2;
  
  lVar1 = func_0x00272200(param_1,0x5c);
  lVar2 = lVar1 + 1;
  if (lVar1 == 0) {
    lVar2 = param_1;
  }
  return lVar2;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34c320 RVA 0x34c320 | Evidence ev_e6b0d7d043031dc452fb27b7db4614db0bb2a47a8308e40cd8c3cda21ef8b422 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34c320", "end": "0x34c347"}], "total_bytes": 40, "span_bytes": 40, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

long sub_34c320(long param_1)

{
  long lVar1;
  long lVar2;
  
  lVar1 = func_0x00272200(param_1,0x2f);
  lVar2 = lVar1 + 1;
  if (lVar1 == 0) {
    lVar2 = param_1;
  }
  return lVar2;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_656 RVA 0x34c350 | Evidence ev_88a1bf476d98a26e64eb2a97d62a07f4fcbf40d3da73f0385c0750eb4de8964d | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34c350", "end": "0x34c4fc"}, {"start": "0x34c500", "end": "0x34c66d"}], "total_bytes": 795, "span_bytes": 798, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 sys_656(long param_1,int *param_2)

{
  long *plVar1;
  int iVar2;
  undefined8 uVar3;
  char *pcVar4;
  code *pcVar5;
  int iVar6;
  undefined4 uVar7;
  long *plVar8;
  ulong uVar9;
  long lVar10;
  long lVar11;
  undefined8 uVar12;
  long lVar13;
  uint uVar14;
  uint uVar15;
  ulong uVar16;
  long *plVar17;
  undefined8 *in_GS_OFFSET;
  long local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  iVar2 = *param_2;
  uVar3 = *(undefined8 *)(param_2 + 2);
  plVar17 = *(long **)(*(long *)(param_1 + 8) + 1000);
  iVar6 = func_0x00acce10();
  if (iVar6 == 0) {
    iVar6 = func_0x00acce50();
    if (iVar6 != 0) goto LAB_0034c398;
  }
  else {
LAB_0034c398:
    if ((plVar17 != (long *)0x0) && (*(long *)(plVar17[2] + 0x148) != 0)) {
      func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
      iVar6 = func_0x00259280(uVar3,&local_40,8);
      uVar7 = 0xe;
      if ((iVar6 != 0) || (uVar7 = 0x16, local_40 != 0x160)) goto LAB_0034c5c3;
      plVar8 = (long *)func_0x00b2ac60(0x160,10);
      plVar1 = plVar17 + 0xe;
      func_0x00c4bb20(plVar1,0,0);
      do {
        plVar17 = (long *)*plVar17;
        if (plVar17 == (long *)0x0) {
          func_0x00c4c4b0(plVar1,0,0);
          func_0x00b24250(plVar8,0x160,10);
          uVar7 = 3;
          goto LAB_0034c5c3;
        }
      } while (iVar2 != *(int *)(plVar17 + 5));
      func_0x00258ff0(plVar8,0x160);
      *plVar8 = local_40;
      pcVar4 = (char *)plVar17[1];
      if (pcVar4 == (char *)0x0) {
LAB_0034c4a1:
        uVar12 = 0x2f;
      }
      else {
        uVar9 = func_0x00444eb0(pcVar4,0x400);
        if ((((uVar9 < 6) || (*pcVar4 != '/')) || (pcVar4[1] != 'h')) ||
           (((pcVar4[2] != 'o' || (pcVar4[3] != 's')) ||
            ((pcVar4[4] != 't' || (uVar12 = 0x5c, pcVar4[5] != '/')))))) goto LAB_0034c4a1;
      }
      lVar11 = plVar17[1];
      lVar10 = func_0x00272200(lVar11,uVar12);
      lVar13 = lVar10 + 1;
      if (lVar10 == 0) {
        lVar13 = lVar11;
      }
      func_0x00984440(plVar8 + 1,lVar13,0x100);
      *(undefined1 *)((long)plVar8 + 0x107) = 0;
      *(undefined4 *)(plVar8 + 0x29) = 0;
      if (*(int *)(plVar17 + 9) != 0) {
        lVar11 = 0;
        uVar9 = 0;
        uVar14 = 0;
        do {
          lVar13 = plVar17[8];
          uVar16 = (ulong)uVar14;
          lVar10 = uVar16 * 0x10;
          plVar8[uVar16 * 2 + 0x21] = *(long *)(lVar13 + 8 + lVar11);
          *(undefined4 *)(plVar8 + uVar16 * 2 + 0x22) = *(undefined4 *)(lVar13 + 0x10 + lVar11);
          *(undefined4 *)((long)plVar8 + lVar10 + 0x114) = 0;
          uVar15 = *(uint *)(*(long *)(lVar13 + lVar11) + 0xc) & 1;
          *(uint *)((long)plVar8 + lVar10 + 0x114) = uVar15;
          uVar14 = *(uint *)(*(long *)(lVar13 + lVar11) + 0xc);
          if ((uVar14 & 2) != 0) {
            uVar15 = uVar15 | 2;
            *(uint *)((long)plVar8 + lVar10 + 0x114) = uVar15;
            uVar14 = *(uint *)(*(long *)(lVar13 + lVar11) + 0xc);
          }
          if ((uVar14 & 4) != 0) {
            *(uint *)((long)plVar8 + lVar10 + 0x114) = uVar15 | 4;
          }
          uVar9 = uVar9 + 1;
          uVar14 = (int)plVar8[0x29] + 1;
          *(uint *)(plVar8 + 0x29) = uVar14;
          uVar15 = *(uint *)(plVar17 + 9);
          if (3 < *(uint *)(plVar17 + 9)) {
            uVar15 = 4;
          }
          lVar11 = lVar11 + 0x18;
        } while (uVar9 < uVar15);
      }
      func_0x00b2b740((long)plVar8 + 0x14c,plVar17);
      func_0x00c4c4b0(plVar1,0,0);
      func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
      uVar7 = func_0x002591d0(plVar8,uVar3,0x160);
      func_0x00b24250(plVar8,0x160,10);
      goto LAB_0034c5c3;
    }
    func_0x00b22a30(0x13a3d13,0x5b4,0x12fbd8a,0x135ae30);
  }
  uVar7 = 1;
LAB_0034c5c3:
  if (_DAT_0391c310 == local_38) {
    return uVar7;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar5 = (code *)invalidInstructionException();
  (*pcVar5)();
}




/* ===== TARGET: sys_672 RVA 0x34c670 | Evidence ev_7a9ddfca4cf41dc939f659fe932a537fcb74d606f26cfa93ae145c3b6a99b506 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34c670", "end": "0x34c703"}], "total_bytes": 148, "span_bytes": 148, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

undefined8 sys_672(long param_1)

{
  long lVar1;
  int iVar2;
  
  lVar1 = *(long *)(*(long *)(param_1 + 8) + 1000);
  iVar2 = func_0x00acce10();
  if ((iVar2 == 0) && (iVar2 = func_0x00acce50(), iVar2 == 0)) {
    return 1;
  }
  if ((lVar1 != 0) && (*(long *)(*(long *)(lVar1 + 0x10) + 0x148) != 0)) {
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  func_0x00b22a30(0x1306572,0x617,0x12fbd8a,0x135ae30);
  return 1;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34c710 RVA 0x34c710 | Evidence ev_4dd2c190b62dc1f25af97124193022f9e785c5a8c47bd0b4c5f1c8b554e73c2e | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34c710", "end": "0x34c74e"}], "total_bytes": 63, "span_bytes": 63, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

long sub_34c710(long param_1)

{
  long lVar1;
  long lVar2;
  long lVar3;
  
  lVar1 = func_0x00272200(param_1,0x2f);
  lVar3 = lVar1 + 1;
  if (lVar1 == 0) {
    lVar3 = param_1;
  }
  lVar2 = func_0x00272200(lVar3,0x5c);
  lVar1 = lVar2 + 1;
  if (lVar2 == 0) {
    lVar1 = lVar3;
  }
  return lVar1;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_596 RVA 0x34c750 | Evidence ev_a73c4371fc8e8c8a38299cf6d1a1ad382d19dcbd574996f155a51bb152f723c2 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34c750", "end": "0x34c80c"}], "total_bytes": 189, "span_bytes": 189, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sys_596(long param_1)

{
  long lVar1;
  int iVar2;
  undefined8 uVar3;
  
  lVar1 = *(long *)(*(long *)(param_1 + 8) + 1000);
  if ((lVar1 == 0) || (*(long *)(*(long *)(lVar1 + 0x10) + 0x148) == 0)) {
    func_0x00b22a30(0x1295072,0x65a,0x12fbd8a,0x135ae30);
    uVar3 = 1;
  }
  else {
    uVar3 = 0;
    func_0x00c4bb20(lVar1 + 0x70,0,0,0);
    iVar2 = func_0x00b2b1a0(lVar1,*(undefined8 *)(lVar1 + 0x10));
    func_0x00c4c4b0(lVar1 + 0x70,0,0);
    if (iVar2 != 0) {
      uVar3 = 0x16;
      func_0x00b22a30(0x1295072,0x664,0x12fbd8a,0x1383f80,0x16);
    }
  }
  return uVar3;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34c810 RVA 0x34c810 | Evidence ev_71fa44ccafcf89e93fd6b715cfee5d8a9ba48924c223499afd835b2ef6d2a36b | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34c810", "end": "0x34c81a"}], "total_bytes": 11, "span_bytes": 11, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_34c810(void)

{
  return 0x4e;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34c820 RVA 0x34c820 | Evidence ev_fdca02471c1708a4b5da8a29c20fc60e94f789962f67397eac22828730572b2e | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34c820", "end": "0x34c8ac"}], "total_bytes": 141, "span_bytes": 141, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_34c820(long param_1)

{
  uint *puVar1;
  long lVar2;
  code *pcVar3;
  int iVar4;
  undefined8 uVar5;
  long *in_GS_OFFSET;
  uint local_24;
  long local_20;
  
  local_20 = _DAT_0391c310;
  lVar2 = *(long *)(param_1 + 8);
  iVar4 = func_0x00acce10();
  uVar5 = 0x2d;
  if (iVar4 == 1) {
    iVar4 = func_0x009f81c0(*(undefined8 *)(*in_GS_OFFSET + 8),&local_24);
    uVar5 = 0;
    if ((iVar4 == 0) && (local_24 < 0x1000000)) {
      *(undefined4 *)(*(long *)(lVar2 + 1000) + 0x150) = 1;
      puVar1 = (uint *)(*(long *)(lVar2 + 1000) + 0x140);
      *puVar1 = *puVar1 | 0x40;
    }
  }
  if (_DAT_0391c310 == local_20) {
    return uVar5;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar3 = (code *)invalidInstructionException();
  (*pcVar3)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34c8b0 RVA 0x34c8b0 | Evidence ev_c990b88c62de8b10ec53707805454f866f1f07d004cac1704b390e0b6690cb81 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34c8b0", "end": "0x34c8ba"}], "total_bytes": 11, "span_bytes": 11, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_34c8b0(void)

{
  return 0x4e;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34c8c0 RVA 0x34c8c0 | Evidence ev_6b6ac4d85d73f846dfd5ec8204a11a2556c5a2ec5c1dbed09ea07536f0fab693 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34c8c0", "end": "0x34c98a"}], "total_bytes": 203, "span_bytes": 203, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

long sub_34c8c0(long param_1,ulong *param_2)

{
  long lVar1;
  undefined8 uVar2;
  long lVar3;
  ulong uVar4;
  undefined8 *in_GS_OFFSET;
  
  lVar1 = *(long *)(param_1 + 1000);
  lVar3 = 2;
  if (((lVar1 != 0) && (*(long *)(*(long *)(lVar1 + 0x10) + 0x148) != 0)) &&
     (*(long *)(lVar1 + 200) != 0)) {
    func_0x00258ff0(param_2,0x60);
    uVar2 = *(undefined8 *)(lVar1 + 200);
    uVar4 = 0x60;
    if (*(ulong *)(lVar1 + 0xd0) < 0x60) {
      uVar4 = *(ulong *)(lVar1 + 0xd0);
    }
    func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
    lVar3 = func_0x00259280(uVar2,param_2,uVar4);
    if ((int)lVar3 == 0) {
      uVar4 = *param_2;
      if (uVar4 < 0x60) {
        func_0x00258ff0((long)param_2 + uVar4,0x60 - uVar4);
      }
      lVar3 = (ulong)((int)param_2[1] != 0x4942524f) << 3;
    }
  }
  return lVar3;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_598 RVA 0x34c990 | Evidence ev_3deac02c917aedc938868db2181d36528335c328bf6a6707699e9072bebd5fa5 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34c990", "end": "0x34ca97"}], "total_bytes": 264, "span_bytes": 264, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sys_598(long param_1,undefined8 *param_2)

{
  long lVar1;
  undefined8 uVar2;
  code *pcVar3;
  int iVar4;
  undefined8 uVar5;
  undefined8 *in_GS_OFFSET;
  undefined8 local_38;
  undefined8 local_30;
  long local_28;
  
  local_28 = _DAT_0391c310;
  lVar1 = *(long *)(*(long *)(param_1 + 8) + 1000);
  if ((lVar1 == 0) || (*(long *)(*(long *)(lVar1 + 0x10) + 0x148) == 0)) {
    func_0x00b22a30(0x138e7d0,0x717,0x12fbd8a,0x135ae30);
    uVar5 = 1;
  }
  else {
    local_30 = *(undefined8 *)(lVar1 + 200);
    uVar5 = *param_2;
    uVar2 = param_2[1];
    local_38 = *(undefined8 *)(lVar1 + 0xd0);
    func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
    iVar4 = func_0x002591d0(&local_30,uVar5,8);
    uVar5 = 0xe;
    if (iVar4 == 0) {
      func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
      iVar4 = func_0x002591d0(&local_38,uVar2,8);
      uVar5 = 0xe;
      if (iVar4 == 0) {
        uVar5 = 0;
      }
    }
  }
  if (_DAT_0391c310 != local_28) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar3 = (code *)invalidInstructionException();
    (*pcVar3)();
  }
  return uVar5;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_599 RVA 0x34caa0 | Evidence ev_4955ba1c84b30e8578a861cd84e723393f0c2de28003609406f3e5c6f48149c6 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34caa0", "end": "0x34cbd0"}, {"start": "0x34cbe0", "end": "0x34cc84"}], "total_bytes": 470, "span_bytes": 485, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong sys_599(long param_1)

{
  long lVar1;
  code *pcVar2;
  uint uVar3;
  int iVar4;
  ulong uVar5;
  long lVar6;
  long *plVar7;
  long *in_GS_OFFSET;
  uint local_3c;
  long local_38;
  
  local_38 = _DAT_0391c310;
  lVar6 = *in_GS_OFFSET;
  lVar1 = *(long *)(*(long *)(lVar6 + 8) + 1000);
  if ((lVar1 == 0) || (*(long *)(*(long *)(lVar1 + 0x10) + 0x148) == 0)) {
    func_0x00b22a30(0x12a8ef3,0x760,0x12fbd8a,0x135ae30);
    uVar5 = 0x16;
  }
  else {
    func_0x00c4bb20(*(long *)(*(long *)(param_1 + 8) + 1000) + 0x70,0,0,0);
    uVar3 = func_0x00b27250(*(undefined8 *)(param_1 + 8));
    if (uVar3 == 0) {
      uVar3 = func_0x00b277c0(*(undefined8 *)(param_1 + 8));
    }
    uVar5 = (ulong)uVar3;
    func_0x00c4c4b0(*(long *)(*(long *)(param_1 + 8) + 1000) + 0x70,0,0);
    if (uVar3 == 0) {
      uVar5 = sub_34cc90(*(undefined8 *)(lVar6 + 8));
      local_3c = (uint)uVar5;
      if (local_3c == 0) {
        lVar6 = func_0x0073e2e0(0x1306591);
        if (lVar6 == 0) {
          uVar5 = 0;
        }
        else {
          iVar4 = *(int *)(lVar6 + 0xc);
          *(int *)(lVar6 + 0xc) = iVar4 + 1;
          plVar7 = *(long **)(lVar6 + 0x40);
          if (plVar7 != (long *)0x0) {
            do {
              if ((int)plVar7[2] != -1) {
                func_0x004c6fa0(lVar6 + 0x28,0,0,0);
                pcVar2 = (code *)plVar7[5];
                if (0x42 < (-(long)pcVar2 + 0x268440U >> 3 | -(long)pcVar2 << 0x3d)) {
                  func_0x0044f8c0(0x1a9ca30,pcVar2);
                }
                (*pcVar2)(plVar7[3],*(undefined8 *)(param_1 + 8),&local_3c);
                func_0x004c6a00(lVar6 + 0x28,0,0);
              }
              plVar7 = (long *)*plVar7;
            } while (plVar7 != (long *)0x0);
            iVar4 = *(int *)(lVar6 + 0xc) + -1;
          }
          *(int *)(lVar6 + 0xc) = iVar4;
          if (iVar4 == 0) {
            func_0x0073e370(lVar6);
          }
          func_0x004c6fa0(lVar6 + 0x28,0,0,0);
          uVar5 = (ulong)local_3c;
        }
      }
    }
  }
  if (_DAT_0391c310 == local_38) {
    return uVar5;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar2 = (code *)invalidInstructionException();
  (*pcVar2)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34cc90 RVA 0x34cc90 | Evidence ev_54977efa1f715836fafa851abc56c5e9645f8c341768818baf363dfa24a6f5b9 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34cc90", "end": "0x34ce4e"}], "total_bytes": 447, "span_bytes": 447, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_34cc90(long param_1)

{
  code *pcVar1;
  long lVar2;
  int iVar3;
  undefined8 *in_GS_OFFSET;
  undefined1 local_b8 [8];
  long local_b0;
  ulong local_98;
  uint local_8c;
  long local_50;
  ulong local_38;
  long local_30;
  
  local_30 = _DAT_0391c310;
  *(undefined4 *)(param_1 + 0xcd0) = 0;
  func_0x00258ff0(local_b8,0x20);
  iVar3 = sub_34c8c0(param_1,&local_98);
  lVar2 = local_50;
  if (iVar3 != 0) {
    func_0x0025d410(0x12d2da6,*(undefined4 *)(param_1 + 0xbc),iVar3);
    goto LAB_0034ccfb;
  }
  if (local_50 != 0 && (0x4f < local_98 && 2 < local_8c)) {
    func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
    iVar3 = func_0x00259280(lVar2,&local_38,8);
    if (iVar3 != 0) {
      func_0x0025d410(0x138e7af,*(undefined4 *)(param_1 + 0xbc),iVar3,local_50);
      goto LAB_0034ccfb;
    }
    if (0x20 < local_38) {
      func_0x0025d410(0x13ae857,*(undefined4 *)(param_1 + 0xbc),local_38);
      iVar3 = 0x16;
      goto LAB_0034ccfb;
    }
    func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
    iVar3 = func_0x00259280(local_50,local_b8,local_38);
    if (iVar3 != 0) goto LAB_0034ccfb;
  }
  if (local_b0 == 0) {
    iVar3 = 0;
  }
  else {
    func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
    iVar3 = func_0x00259280(local_b0,param_1 + 0xcd0,4);
  }
LAB_0034ccfb:
  if (_DAT_0391c310 != local_30) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar1 = (code *)invalidInstructionException();
    (*pcVar1)();
  }
  return iVar3;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_612 RVA 0x34ce50 | Evidence ev_68bb280e17055ca117ae61aa591435d2bd6d400bf9e9a1125856d4e3fc4cfeed | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34ce50", "end": "0x34cf9d"}], "total_bytes": 334, "span_bytes": 334, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sys_612(long param_1,undefined8 *param_2)

{
  undefined8 uVar1;
  undefined8 uVar2;
  code *pcVar3;
  int iVar4;
  undefined8 uVar5;
  undefined8 *in_GS_OFFSET;
  long local_40;
  long local_38;
  undefined4 local_30;
  byte local_2c;
  long local_28;
  
  local_28 = _DAT_0391c310;
  uVar1 = *param_2;
  uVar2 = *(undefined8 *)(*(long *)(param_1 + 8) + 0x40);
  func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
  iVar4 = func_0x00259280(uVar1,&local_40,8);
  uVar5 = 0xe;
  if ((iVar4 == 0) && (uVar5 = 0x16, local_40 == 0x10)) {
    func_0x00258ff0(&local_38,0x10);
    local_38 = local_40;
    local_30 = func_0x005a6c70();
    iVar4 = func_0x006095c0(uVar2);
    if (iVar4 != 0) {
      local_2c = local_2c | 1;
    }
    iVar4 = func_0x00609620(uVar2);
    if (iVar4 != 0) {
      local_2c = local_2c | 2;
    }
    iVar4 = func_0x006091f0(uVar2);
    if (iVar4 != 0) {
      local_2c = local_2c | 4;
    }
    iVar4 = func_0x00609230(uVar2);
    if (iVar4 != 0) {
      local_2c = local_2c | 8;
    }
    iVar4 = func_0x00609750(uVar2);
    if (iVar4 != 0) {
      local_2c = local_2c | 0x10;
    }
    iVar4 = func_0x00609270(uVar2);
    if (iVar4 != 0) {
      local_2c = local_2c | 0x20;
    }
    iVar4 = func_0x006096b0(uVar2);
    if (iVar4 != 0) {
      local_2c = local_2c | 0x40;
    }
    iVar4 = func_0x00609890(uVar2);
    if (iVar4 != 0) {
      local_2c = local_2c | 0x80;
    }
    func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
    uVar5 = func_0x002591d0(&local_38,uVar1,0x10);
  }
  if (_DAT_0391c310 == local_28) {
    return uVar5;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar3 = (code *)invalidInstructionException();
  (*pcVar3)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_649 RVA 0x34cfa0 | Evidence ev_00ae4cf44e1d918a77e6620496eef75ed9da470241dd042706d68d2cd58a7017 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34cfa0", "end": "0x34d02d"}, {"start": "0x34d044", "end": "0x34d084"}, {"start": "0x34d093", "end": "0x34d0a5"}, {"start": "0x34d106", "end": "0x34d122"}], "total_bytes": 255, "span_bytes": 387, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sys_649(undefined8 param_1,int *param_2)

{
  long *plVar1;
  code *pcVar2;
  long lVar3;
  undefined8 uVar4;
  long *plVar5;
  long *in_GS_OFFSET;
  
  lVar3 = _DAT_0391c310;
  plVar5 = *(long **)(*(long *)(*in_GS_OFFSET + 8) + 1000);
  if ((plVar5 == (long *)0x0) || (*(long *)(plVar5[2] + 0x148) == 0)) {
    func_0x00b22a30(0x131ba2d,0x7c4,0x12fbd8a,0x135ae30);
    uVar4 = 0x16;
  }
  else {
    plVar1 = plVar5 + 0xe;
    func_0x00c4bb20(plVar1,0,0,0);
    do {
      plVar5 = (long *)*plVar5;
      if (plVar5 == (long *)0x0) {
        func_0x00c4c4b0(plVar1,0,0);
        uVar4 = 3;
        goto LAB_0034d106;
      }
    } while (plVar5[5] != (long)*param_2);
    if (*(byte *)(param_2 + 2) - 1 < 8) {
                    /* WARNING: Could not emulate address calculation at 0x0034d025 */
                    /* WARNING: Treating indirect jump as call */
      uVar4 = (*(code *)((long)*(int *)((ulong)(*(byte *)(param_2 + 2) - 1) * 4 + 0x14c02b0) +
                        0x14c02b0))();
      return uVar4;
    }
    func_0x00c4c4b0(plVar1,0,0);
    uVar4 = 0x16;
  }
LAB_0034d106:
  if (_DAT_0391c310 == lVar3) {
    return uVar4;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar2 = (code *)invalidInstructionException();
  (*pcVar2)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34d130 RVA 0x34d130 | Evidence ev_9ef23d158cd7a3bbeaa69c096f8db4faeca644ee035217f86f1ff360c7d50d64 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34d130", "end": "0x34d5dc"}], "total_bytes": 1197, "span_bytes": 1197, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong sub_34d130(void)

{
  long lVar1;
  undefined8 uVar2;
  int iVar3;
  uint uVar4;
  ulong uVar5;
  long in_RCX;
  code *pcVar6;
  long *in_GS_OFFSET;
  int local_164;
  byte local_160;
  undefined7 uStack_15f;
  int local_154;
  long local_128;
  ulong local_100;
  undefined8 local_f8;
  undefined8 local_f0;
  undefined8 local_88;
  undefined8 local_70;
  undefined8 local_48;
  undefined8 local_40;
  long local_30;
  
  local_30 = _DAT_0391c310;
  local_48 = 0;
  local_40 = 0;
  local_164 = 0;
  lVar1 = *in_GS_OFFSET;
  iVar3 = func_0x0026d0a0(*(undefined8 *)(lVar1 + 0x140));
  if (iVar3 == 1) {
    lVar1 = *(long *)(*in_GS_OFFSET + 8);
    if (*(long *)(lVar1 + 1000) == 0) {
LAB_0034d3fd:
      uVar5 = 0x16;
      goto LAB_0034d509;
    }
    local_f8 = *(undefined8 *)(lVar1 + 0x5a0);
    local_f0 = *(undefined8 *)(lVar1 + 0x5a8);
    pcVar6 = *(code **)(in_RCX + 0x28);
    if (3 < (-(long)pcVar6 + 0x269338U >> 3 | -(long)pcVar6 << 0x3d)) {
      func_0x0044f8c0(0x1a9ca90,pcVar6);
    }
LAB_0034d1db:
    uVar5 = (*pcVar6)(in_RCX,&local_f8,0x10);
  }
  else {
    iVar3 = func_0x00608f90(*(undefined8 *)(lVar1 + 0x140));
    if (iVar3 == 1) {
      uVar4 = func_0x0060ae80();
      if (uVar4 == 1) {
        local_164 = 0;
        uVar4 = func_0x00ae70c0(0x7802be00,&local_164);
        if ((uVar4 == 0) && (local_164 != 0)) {
          lVar1 = *(long *)(*in_GS_OFFSET + 8);
          if (*(long *)(lVar1 + 1000) == 0) goto LAB_0034d3fd;
          local_f8 = *(undefined8 *)(lVar1 + 0x5a0);
          local_f0 = *(undefined8 *)(lVar1 + 0x5a8);
          pcVar6 = *(code **)(in_RCX + 0x28);
          if (3 < (-(long)pcVar6 + 0x269338U >> 3 | -(long)pcVar6 << 0x3d)) {
            func_0x0044f8c0(0x1a9ca90,pcVar6);
          }
          goto LAB_0034d1db;
        }
      }
    }
    else {
      iVar3 = func_0x00609270(*(undefined8 *)(lVar1 + 0x140));
      if (iVar3 == 1) {
        iVar3 = func_0x00acce10();
        uVar4 = 3;
        if ((iVar3 == 1) && (uVar4 = func_0x0060ae80(), uVar4 == 1)) {
          local_164 = 0;
          uVar4 = func_0x00ae70c0(0x7802be00,&local_164);
          if ((uVar4 == 0) && (local_164 != 0)) {
LAB_0034d34d:
            uVar5 = sub_34d5e0(in_RCX);
            goto LAB_0034d509;
          }
        }
      }
      else {
        iVar3 = func_0x0060ae80();
        if ((iVar3 == 1) && (iVar3 = func_0x00acce10(), iVar3 == 1)) {
          local_164 = 0;
          iVar3 = func_0x00ae70c0(0x7802b700,&local_164);
          if ((iVar3 == 0) && (local_164 != 0)) goto LAB_0034d34d;
        }
        iVar3 = func_0x00acce10();
        if ((iVar3 == 1) || (iVar3 = func_0x00acce50(), iVar3 == 1)) {
          local_164 = 0;
          iVar3 = func_0x00ae70c0(0x7802bf00,&local_164);
          if ((iVar3 == 0) && (local_164 != 0)) {
            lVar1 = *(long *)(*in_GS_OFFSET + 8);
            if (*(long *)(lVar1 + 1000) == 0) goto LAB_0034d3fd;
            local_f8 = *(undefined8 *)(lVar1 + 0x5a0);
            local_f0 = *(undefined8 *)(lVar1 + 0x5a8);
            pcVar6 = *(code **)(in_RCX + 0x28);
            if (3 < (-(long)pcVar6 + 0x269338U >> 3 | -(long)pcVar6 << 0x3d)) {
              func_0x0044f8c0(0x1a9ca90,pcVar6);
            }
            goto LAB_0034d1db;
          }
        }
        uVar2 = *(undefined8 *)(lVar1 + 8);
        func_0x00258ff0(&local_f8,0xa8);
        uVar4 = sub_34c8c0(uVar2,&local_160);
        lVar1 = local_128;
        if ((uVar4 == 0) &&
           (uVar4 = 8, (local_128 != 0 && local_154 != 0) && 0x3f < CONCAT71(uStack_15f,local_160)))
        {
          func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
          uVar4 = func_0x00259280(lVar1,&local_100,8);
          if ((uVar4 == 0) && (uVar4 = 0x16, local_100 < 0xa9)) {
            func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
            uVar4 = func_0x00259280(local_128,&local_f8,local_100);
            if (uVar4 == 0) {
              if ((uint)local_f0 < 9) {
                uVar4 = 0;
              }
              else {
                uVar4 = 0;
                if (((local_f0._4_4_ == 1) && (uVar4 = sub_34b910(local_88,&local_160), uVar4 == 0))
                   && (uVar4 = 0, (local_160 & 8) != 0)) goto LAB_0034d34d;
              }
              if (((0xb < (uint)local_f0) && (local_f0._4_4_ == 1)) &&
                 ((uVar4 = sub_34b910(local_70,&local_160), uVar4 == 0 &&
                  (uVar4 = 0, (local_160 & 8) != 0)))) goto LAB_0034d34d;
            }
          }
        }
      }
    }
    pcVar6 = *(code **)(in_RCX + 0x28);
    uVar5 = (ulong)uVar4;
    if (3 < (-(long)pcVar6 + 0x269338U >> 3 | -(long)pcVar6 << 0x3d)) {
      func_0x0044f8c0(0x1a9ca50,pcVar6);
    }
    (*pcVar6)(in_RCX,&local_48,0x10);
  }
LAB_0034d509:
  if (_DAT_0391c310 != local_30) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar6 = (code *)invalidInstructionException();
    (*pcVar6)();
  }
  return uVar5;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34d5e0 RVA 0x34d5e0 | Evidence ev_4fce982f77573a11b568bea3220efc0dff604933dca558b44c5962cd46d7069d | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34d5e0", "end": "0x34d686"}], "total_bytes": 167, "span_bytes": 167, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_34d5e0(long param_1)

{
  long lVar1;
  code *pcVar2;
  undefined8 uVar3;
  long *in_GS_OFFSET;
  undefined8 local_38;
  undefined8 local_30;
  long local_28;
  
  local_28 = _DAT_0391c310;
  lVar1 = *(long *)(*in_GS_OFFSET + 8);
  if (*(long *)(lVar1 + 1000) == 0) {
    uVar3 = 0x16;
  }
  else {
    local_38 = *(undefined8 *)(lVar1 + 0x5a0);
    local_30 = *(undefined8 *)(lVar1 + 0x5a8);
    pcVar2 = *(code **)(param_1 + 0x28);
    if (3 < (-(long)pcVar2 + 0x269338U >> 3 | -(long)pcVar2 << 0x3d)) {
      func_0x0044f8c0(0x1a9ca90,pcVar2);
    }
    uVar3 = (*pcVar2)(param_1,&local_38,0x10);
  }
  if (_DAT_0391c310 == local_28) {
    return uVar3;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar2 = (code *)invalidInstructionException();
  (*pcVar2)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): FUN_0034d6d3 RVA 0x34d6d3 | Evidence ev_f4d8e82cb1ade49587b08c8fb1bd6fb37be29492a154c7364019887779862e23 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34d6d3", "end": "0x34d6dd"}], "total_bytes": 11, "span_bytes": 11, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void FUN_0034d6d3(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 code *UNRECOVERED_JUMPTABLE)

{
                    /* WARNING: Could not recover jumptable at 0x0034d6db. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*UNRECOVERED_JUMPTABLE)(param_4,param_2,0x18);
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34d6de RVA 0x34d6de | Evidence ev_b7087f188f57e03e077f8bb13f2eb918dd5d5a146f65d32bfa58f8b4a14a868d | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34d6de", "end": "0x34d714"}], "total_bytes": 55, "span_bytes": 55, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted.", "Ghidra Listing reports a terminal call at 0x34d713 to 0x34d6d3 FUN_0034d6d3 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

void sub_34d6de(void)

{
  undefined8 in_R8;
  
  func_0x0044f8c0(0x1a9ca70,in_R8);
  FUN_0034d6d3();
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34d720 RVA 0x34d720 | Evidence ev_7ba135f04c117b4ab1e792de13f7a895a8ef097b7b756adbc5faff64eef69b25 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34d720", "end": "0x34d77d"}, {"start": "0x34d780", "end": "0x34d7ab"}], "total_bytes": 138, "span_bytes": 140, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_34d720(long param_1,long param_2)

{
  long lVar1;
  long lVar2;
  undefined8 uVar3;
  
  lVar1 = func_0x00444eb0(param_2,0x400);
  lVar2 = func_0x00444eb0(param_1,0x400);
  uVar3 = 0xffffffff;
  if (0xfffffffffffffbfe < (ulong)(lVar1 + -0x406 + lVar2)) {
    func_0x00886560(param_2,param_1 + 6,0x400);
    lVar1 = 6;
    do {
      if (*(char *)(param_2 + lVar1) == '/') {
        *(undefined1 *)(param_2 + lVar1) = 0x5c;
      }
      else if (*(char *)(param_2 + lVar1) == '\0') {
        return 0;
      }
      lVar1 = lVar1 + 1;
    } while (lVar1 != 0x400);
    uVar3 = 0;
  }
  return uVar3;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34d7b0 RVA 0x34d7b0 | Evidence ev_c495cf3826ba22bed83d609d1ba95fee3435a3e7349ad712ea46fff541f5f66b | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34d7b0", "end": "0x34d86a"}], "total_bytes": 187, "span_bytes": 187, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

bool sub_34d7b0(long param_1,long param_2)

{
  uint uVar1;
  undefined8 uVar2;
  code *pcVar3;
  int iVar4;
  undefined8 *in_GS_OFFSET;
  bool bVar5;
  undefined1 local_58 [8];
  int local_50;
  uint local_4c;
  uint local_44;
  long local_38;
  
  local_38 = _DAT_0391c310;
  bVar5 = false;
  if ((*(byte *)(param_2 + 0x11c) & 1) == 0) {
    uVar1 = *(uint *)(param_1 + 0x5d8);
    func_0x00258ff0(local_58,0x20);
    uVar2 = *(undefined8 *)(param_2 + 0x168);
    func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
    iVar4 = func_0x00259280(uVar2,local_58,0x18);
    bVar5 = false;
    if (((iVar4 == 0) && (local_50 == 0x3c13f4bf)) && (bVar5 = false, 1 < local_4c)) {
      bVar5 = (uVar1 ^ local_44) < 0x10000;
    }
  }
  if (_DAT_0391c310 == local_38) {
    return bVar5;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar3 = (code *)invalidInstructionException();
  (*pcVar3)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34d870 RVA 0x34d870 | Evidence ev_db390d4555b1527c3f4ffe2e95fea96dea984ba47a80584311265a23a7621363 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34d870", "end": "0x34dc36"}], "total_bytes": 967, "span_bytes": 967, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_34d870(long *param_1)

{
  long *plVar1;
  char *pcVar2;
  code *pcVar3;
  int iVar4;
  long lVar5;
  long lVar6;
  undefined8 uVar7;
  ulong uVar8;
  long lVar9;
  long lVar10;
  uint uVar11;
  long *plVar12;
  undefined8 uVar13;
  undefined1 local_58 [32];
  long local_38;
  
  local_38 = _DAT_0391c310;
  lVar5 = func_0x00b2ac60(0x800,0);
  if (lVar5 == 0) {
    func_0x007f1950();
    func_0x007f1810(0x34dc0a);
    func_0x00c9aa10(0xc,0x1384006);
                    /* WARNING: Does not return */
    pcVar3 = (code *)invalidInstructionException();
    (*pcVar3)();
  }
  func_0x00258ff0(lVar5,0x800);
  *(undefined4 *)(lVar5 + 0x44) = 0;
  func_0x00984440(lVar5,0x128040b,0x1b);
  plVar1 = param_1 + 3;
  lVar6 = func_0x00444eb0(plVar1,0x25);
  if (lVar6 == 0x24) {
    uVar7 = sub_34dc40(lVar5 + 0x48,0x1326472,plVar1,0x25);
    *(int *)(lVar5 + 0x44) = *(int *)(lVar5 + 0x44) + 1;
    plVar12 = (long *)param_1[1];
    if ((ulong)plVar12 >> 0x20 == 0) {
      uVar7 = 0x12c828f;
      goto LAB_0034d92a;
    }
    func_0x00258ff0(local_58,0x19);
    uVar11 = (uint)plVar12;
    func_0x004aee40(local_58,0x19,0x13ae895,(ulong)plVar12 >> 0x38,(ulong)plVar12 >> 0x30 & 0xff,
                    (ulong)plVar12 >> 0x28 & 0xff,(ulong)plVar12 >> 0x20 & 0xff,
                    (ulong)plVar12 >> 0x18 & 0xff,uVar11 >> 0x10 & 0xff,(ulong)plVar12 >> 8 & 0xff,
                    uVar11 >> 4 & 0xf,uVar11 & 0xf);
    uVar7 = sub_34dc40(uVar7,0x12bd732,local_58,0x19);
    *(int *)(lVar5 + 0x44) = *(int *)(lVar5 + 0x44) + 1;
    uVar8 = (long)param_1 + 0x3d;
    lVar6 = func_0x00444eb0(uVar8,0x25);
    if (lVar6 == 0x24) {
      uVar7 = sub_34dc40(uVar7,0x1398fc7,uVar8,0x25);
      *(int *)(lVar5 + 0x44) = *(int *)(lVar5 + 0x44) + 1;
      uVar8 = param_1[2];
      if (uVar8 >> 0x20 == 0) {
        uVar7 = 0x13799ce;
        goto LAB_0034da36;
      }
      func_0x00258ff0(local_58,0x19);
      uVar11 = (uint)uVar8;
      func_0x004aee40(local_58,0x19,0x13ae895,uVar8 >> 0x38,uVar8 >> 0x30 & 0xff,
                      uVar8 >> 0x28 & 0xff,uVar8 >> 0x20 & 0xff,uVar8 >> 0x18 & 0xff,
                      uVar11 >> 0x10 & 0xff,uVar8 >> 8 & 0xff,uVar11 >> 4 & 0xf,uVar11 & 0xf);
      uVar7 = sub_34dc40(uVar7,0x12c82bd,local_58,0x19);
      *(int *)(lVar5 + 0x44) = *(int *)(lVar5 + 0x44) + 1;
      pcVar2 = (char *)*param_1;
      if (pcVar2 == (char *)0x0) {
LAB_0034db81:
        uVar13 = 0x2f;
      }
      else {
        uVar8 = func_0x00444eb0(pcVar2,0x400);
        if ((((uVar8 < 6) || (*pcVar2 != '/')) || (pcVar2[1] != 'h')) ||
           (((pcVar2[2] != 'o' || (pcVar2[3] != 's')) ||
            ((pcVar2[4] != 't' || (uVar13 = 0x5c, pcVar2[5] != '/')))))) goto LAB_0034db81;
      }
      lVar6 = *param_1;
      lVar9 = func_0x00272200(lVar6,uVar13);
      lVar10 = lVar9 + 1;
      if (lVar9 == 0) {
        lVar10 = lVar6;
      }
      lVar6 = sub_34dc40(uVar7,0x1310e97,lVar10,0x401);
      *(int *)(lVar5 + 0x44) = *(int *)(lVar5 + 0x44) + 1;
      uVar8 = lVar6 - lVar5;
      if (uVar8 < 0x82) {
        uVar7 = 0x13799fc;
        goto LAB_0034da36;
      }
      iVar4 = func_0x0057e790(4,lVar5,uVar8,4);
      if (iVar4 == 0) goto LAB_0034da67;
      func_0x0025d410(0x12a8f8c,*param_1,iVar4);
    }
    else {
      uVar7 = 0x12dd468;
LAB_0034da36:
      func_0x0025d410(uVar7,uVar8);
    }
  }
  else {
    uVar7 = 0x1398f9d;
    plVar12 = plVar1;
LAB_0034d92a:
    func_0x0025d410(uVar7,plVar12);
  }
  func_0x0025d410(0x138e80a,plVar1,param_1[1],(long)param_1 + 0x3d,param_1[2],*param_1);
LAB_0034da67:
  func_0x00b24250(lVar5,0x800,0);
  if (_DAT_0391c310 == local_38) {
    return;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar3 = (code *)invalidInstructionException();
  (*pcVar3)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34dc40 RVA 0x34dc40 | Evidence ev_7d18af5067696aa417857feb0f6a691a377c139871e15d9349ef2840aff1e57c | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34dc40", "end": "0x34dcc0"}], "total_bytes": 129, "span_bytes": 129, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

long sub_34dc40(int *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  code *pcVar1;
  
  if (param_1 != (int *)0x0) {
    *param_1 = (int)param_4;
    *(undefined1 *)(param_1 + 1) = 2;
    func_0x00957b70((long)param_1 + 5,param_2,0x41);
    func_0x00957b70((long)param_1 + 0x46,param_3,param_4);
    return (ulong)(*param_1 + 0x49U & 0xfffffffc) + (long)param_1;
  }
  func_0x007f1950();
  func_0x007f18a0(0x34dc92,param_2);
  func_0x00c9aa10(4,0x1280426,param_2);
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34dcd0 RVA 0x34dcd0 | Evidence ev_bcb62c2396caf6572682682b02b615e829975afbe44416cf4de2ba22c8a7c5d5 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34dcd0", "end": "0x34dd78"}], "total_bytes": 169, "span_bytes": 169, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_34dcd0(undefined8 param_1,undefined4 param_2,undefined4 param_3,undefined8 param_4,
               undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  code *pcVar1;
  undefined1 local_60 [8];
  undefined1 local_58 [32];
  long local_38;
  
  local_38 = _DAT_0391c310;
  func_0x00258ff0(local_58,0x20);
  func_0x00258ff0(local_60,8);
  func_0x00338550(param_1,param_2,param_3,local_58,local_60,param_4,0x4000,param_5,param_6,param_7,
                  param_8);
  if (_DAT_0391c310 == local_38) {
    return;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34dd80 RVA 0x34dd80 | Evidence ev_41f1fe01f7e8b5c7792ff3a1f0a831f0a281d342d8089c0a9459c96a4a547f4c | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34dd80", "end": "0x34dda9"}], "total_bytes": 42, "span_bytes": 42, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_34dd80(long param_1,ulong param_2)

{
  undefined8 uVar1;
  
  uVar1 = 0xffffffdd;
  if ((0x3f < param_2) &&
     (uVar1 = 0xffffffdd, (ulong)*(ushort *)(param_1 + 0x38) * 0x38 + 0x40 <= param_2)) {
    uVar1 = 0;
  }
  return uVar1;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34ddb0 RVA 0x34ddb0 | Evidence ev_dbdc0f598c225dc17de19073381a8078f4280987e3a20f82731b519c3d39ce46 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34ddb0", "end": "0x34de56"}], "total_bytes": 167, "span_bytes": 167, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8
sub_34ddb0(int *param_1,uint param_2,undefined8 *param_3,undefined8 *param_4,undefined8 *param_5)

{
  long lVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  
  if (*param_1 != 1) {
    return 0xffffffea;
  }
  lVar1 = *(long *)(param_1 + 0xe);
  if (lVar1 == 0) {
    uVar3 = 0xffffffda;
  }
  else {
    uVar3 = 0xffffffde;
    if (param_2 < *(ushort *)(lVar1 + 0x38)) {
      uVar3 = 0xffffffda;
      *param_3 = *(undefined8 *)(lVar1 + 0x48 + (ulong)param_2 * 0x38);
      if (((*param_1 != 0) && (lVar1 = *(long *)(param_1 + 0xe), lVar1 != 0)) &&
         (uVar3 = 0xffffffea, param_2 < *(ushort *)(lVar1 + 0x38))) {
        uVar3 = *(undefined8 *)(lVar1 + 0x60 + (ulong)param_2 * 0x38);
        *param_4 = uVar3;
        *param_5 = uVar3;
        return 0;
      }
      uVar4 = 0x1344efb;
      uVar2 = 0xe0;
      goto LAB_0034de45;
    }
  }
  uVar4 = 0x1280444;
  uVar2 = 0xd4;
LAB_0034de45:
  func_0x0025d410(uVar4,0x135ae9a,uVar2,uVar3);
  return uVar3;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34de60 RVA 0x34de60 | Evidence ev_8647756e89a7fc2afc45d3bff43e34c55ad1e2df41e03555109cabcc5ec072f9 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34de60", "end": "0x34de75"}], "total_bytes": 22, "span_bytes": 22, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_34de60(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34de80 RVA 0x34de80 | Evidence ev_bab40f823b1ce615d781c371e45475462865460d3b631c6b405821c1ada509bc | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34de80", "end": "0x34de9d"}], "total_bytes": 30, "span_bytes": 30, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_34de80(undefined8 param_1)

{
  func_0x0081a730(param_1,0x100000,0xe6ba20,1);
  return 0;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34dea0 RVA 0x34dea0 | Evidence ev_349fc8e39ff5c100cefc25f70a2a1a97ffe08db6bf9e36df59df1701c417f66e | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34dea0", "end": "0x34df9e"}], "total_bytes": 255, "span_bytes": 255, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_34dea0(long param_1,long param_2,int param_3)

{
  uint uVar1;
  long lVar2;
  code *pcVar3;
  int iVar4;
  uint uVar5;
  
  lVar2 = *(long *)(param_2 + 8);
  if (param_3 == 1) {
    iVar4 = func_0x00819a50(param_1);
    if (iVar4 == -2) {
      return 0;
    }
    uVar1 = *(uint *)(lVar2 + 0x10);
    uVar5 = 0x1f;
    if ((uVar1 & 0xe0) == 0x20) {
      uVar5 = 0x781f;
    }
    if (((uVar5 & uVar1) != 0) && (0 < *(int *)(param_1 + 0x68))) {
      *(int *)(param_1 + 0x68) = *(int *)(param_1 + 0x68) + -1;
      return 0;
    }
  }
  else if (param_3 == 2) {
    func_0x00819390(param_1);
    uVar1 = *(uint *)(lVar2 + 0x10);
    uVar5 = 0x1f;
    if ((uVar1 & 0xe0) == 0x20) {
      uVar5 = 0x781f;
    }
    uVar5 = uVar5 & uVar1;
    if ((uVar5 == 6) || (uVar5 == 3)) {
      param_3 = 2;
      *(undefined8 *)(param_2 + 0x3c) = 0x2200000000;
      *(undefined4 *)(param_1 + 0x68) = 3;
      goto LAB_0034df7e;
    }
  }
  pcVar3 = *(code **)(*(long *)(param_1 + 0x38) + 8);
  if (0x8bc < (-(long)pcVar3 + 0x2652d0U >> 3 | -(long)pcVar3 << 0x3d)) {
    func_0x0044f8c0(0x1a9cb90,pcVar3);
  }
  (*pcVar3)(param_1);
LAB_0034df7e:
  func_0x00819e90(param_1,param_3);
  return 0;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34dfa0 RVA 0x34dfa0 | Evidence ev_c60215fe7193e2abd3a4a656e7114dd1bfb8574615266107912007ba3c18ec14 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34dfa0", "end": "0x34e245"}], "total_bytes": 678, "span_bytes": 678, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_34dfa0(undefined8 *param_1)

{
  undefined4 uVar1;
  long lVar2;
  long *plVar3;
  long lVar4;
  code *pcVar5;
  ushort uVar6;
  uint uVar7;
  uint uVar8;
  undefined8 *puVar9;
  ulong uVar10;
  
  lVar2 = param_1[8];
  *(undefined8 *)(lVar2 + 0x3c) = 0x2000000001;
  plVar3 = (long *)*param_1;
  uVar1 = *(undefined4 *)(param_1 + 5);
  lVar4 = *plVar3;
  puVar9 = *(undefined8 **)(lVar4 + (ulong)DAT_02c095b0 * 8);
  if ((undefined1 *)*puVar9 != &DAT_02c095b0) {
    puVar9 = (undefined8 *)
             func_0x00325ff0(*(undefined8 *)(lVar4 + 0x800),lVar4 + (ulong)DAT_02c095b0 * 8,
                             &DAT_02c095b0);
  }
  pcVar5 = (code *)puVar9[1];
  if (0x26 < (-(long)pcVar5 + 0x267140U >> 3 | -(long)pcVar5 << 0x3d)) {
    func_0x0044f8c0(0x1a9cbb0,pcVar5);
  }
  uVar7 = (*pcVar5)(plVar3,uVar1,1);
  plVar3 = (long *)*param_1;
  uVar1 = *(undefined4 *)(param_1 + 5);
  lVar4 = *plVar3;
  puVar9 = *(undefined8 **)(lVar4 + (ulong)DAT_02c095b0 * 8);
  if ((undefined1 *)*puVar9 != &DAT_02c095b0) {
    puVar9 = (undefined8 *)
             func_0x00325ff0(*(undefined8 *)(lVar4 + 0x800),lVar4 + (ulong)DAT_02c095b0 * 8,
                             &DAT_02c095b0);
  }
  pcVar5 = (code *)puVar9[1];
  if (0x26 < (-(long)pcVar5 + 0x267140U >> 3 | -(long)pcVar5 << 0x3d)) {
    func_0x0044f8c0(0x1a9cbb0,pcVar5);
  }
  uVar8 = (*pcVar5)(plVar3,uVar1,1);
  plVar3 = (long *)*param_1;
  uVar1 = *(undefined4 *)(param_1 + 5);
  lVar4 = *plVar3;
  puVar9 = *(undefined8 **)(lVar4 + (ulong)DAT_02c095b0 * 8);
  if ((undefined1 *)*puVar9 != &DAT_02c095b0) {
    puVar9 = (undefined8 *)
             func_0x00325ff0(*(undefined8 *)(lVar4 + 0x800),lVar4 + (ulong)DAT_02c095b0 * 8,
                             &DAT_02c095b0);
  }
  pcVar5 = (code *)puVar9[1];
  if (0x26 < (-(long)pcVar5 + 0x267140U >> 3 | -(long)pcVar5 << 0x3d)) {
    func_0x0044f8c0(0x1a9cbb0,pcVar5);
  }
  uVar6 = (*pcVar5)(plVar3,uVar1,0x16);
  if ((short)uVar6 < 0) {
    *(byte *)(lVar2 + 0x3c) = *(byte *)(lVar2 + 0x3c) | 2;
  }
  plVar3 = (long *)*param_1;
  uVar1 = *(undefined4 *)(param_1 + 5);
  lVar4 = *plVar3;
  puVar9 = *(undefined8 **)(lVar4 + (ulong)DAT_02c095b0 * 8);
  if ((undefined1 *)*puVar9 != &DAT_02c095b0) {
    puVar9 = (undefined8 *)
             func_0x00325ff0(*(undefined8 *)(lVar4 + 0x800),lVar4 + (ulong)DAT_02c095b0 * 8,
                             &DAT_02c095b0);
  }
  pcVar5 = (code *)puVar9[1];
  if (0x26 < (-(long)pcVar5 + 0x267140U >> 3 | -(long)pcVar5 << 0x3d)) {
    func_0x0044f8c0(0x1a9cbb0,pcVar5);
  }
  uVar10 = (*pcVar5)(plVar3,uVar1,0);
  if ((uVar10 & 0x400) == 0) {
    if ((uVar10 & 0x4000) != 0) {
      *(byte *)(lVar2 + 0x43) = *(byte *)(lVar2 + 0x43) | 8;
    }
    if (((uVar10 & 0x1000) == 0) || (((uVar8 | uVar7) & 0x20) != 0)) {
      if ((uVar6 & 0x6000) == 0x2000) {
        uVar7 = 6;
      }
      else {
        if ((uVar6 & 0x6000) != 0) {
          *(uint *)(lVar2 + 0x40) = *(uint *)(lVar2 + 0x40) | 2;
          return;
        }
        uVar7 = 3;
      }
      uVar7 = uVar7 | *(uint *)(lVar2 + 0x40);
      *(uint *)(lVar2 + 0x40) = uVar7;
      if ((uVar6 & 0x1000) == 0) {
        uVar7 = uVar7 | 0x200000;
      }
      else {
        uVar7 = func_0x0081aab0(param_1);
        uVar7 = uVar7 | *(uint *)(lVar2 + 0x40) | 0x100000;
      }
      *(uint *)(lVar2 + 0x40) = uVar7;
    }
    else {
      *(byte *)(lVar2 + 0x40) = *(byte *)(lVar2 + 0x40) | 2;
    }
  }
  else {
    *(byte *)(lVar2 + 0x40) = *(byte *)(lVar2 + 0x40) | 2;
    *(undefined4 *)(lVar2 + 0x3c) = 0;
  }
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34e255 RVA 0x34e255 | Evidence ev_9f4c4090602b6a2a0e6d8b6ad76a50b8457e9053cf45fcae33f01d59f519fb4f | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34e255", "end": "0x34e273"}], "total_bytes": 31, "span_bytes": 31, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

byte sub_34e255(undefined8 param_1,undefined8 param_2)

{
  byte bVar1;
  
  bVar1 = func_0x0069d360(param_1,0,0x68000,5,param_2);
  return bVar1 ^ 1;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34e285 RVA 0x34e285 | Evidence ev_79b90233da1bdb43184daf03b664f1df9fcf869f04701aaa9e5b7926f5999134 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34e285", "end": "0x34e2a3"}], "total_bytes": 31, "span_bytes": 31, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

byte sub_34e285(undefined8 param_1,undefined8 param_2)

{
  byte bVar1;
  
  bVar1 = func_0x0069d360(param_1,0,0x68028,1,param_2);
  return bVar1 ^ 1;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34e2b5 RVA 0x34e2b5 | Evidence ev_4bcab105195ada711958718955c5fbabe2f183f070c2cbd7af78630f2c4582e4 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34e2b5", "end": "0x34e2d3"}], "total_bytes": 31, "span_bytes": 31, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

byte sub_34e2b5(undefined8 param_1,undefined8 param_2)

{
  byte bVar1;
  
  bVar1 = func_0x0069d360(param_1,0,0x68029,1,param_2);
  return bVar1 ^ 1;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34e2e5 RVA 0x34e2e5 | Evidence ev_47cc8dbd9bae002b1f2ab6c152cafc382fa932d756b3bfc858a138e0f20f459a | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34e2e5", "end": "0x34e303"}], "total_bytes": 31, "span_bytes": 31, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

byte sub_34e2e5(undefined8 param_1,undefined8 param_2)

{
  byte bVar1;
  
  bVar1 = func_0x0069d360(param_1,0,0x68005,2,param_2);
  return bVar1 ^ 1;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34e315 RVA 0x34e315 | Evidence ev_76e8b9fa83b75fcd744313f89ed2b12093dccd9639284349bc77ce035f09138f | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34e315", "end": "0x34e333"}], "total_bytes": 31, "span_bytes": 31, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

byte sub_34e315(undefined8 param_1,undefined8 param_2)

{
  byte bVar1;
  
  bVar1 = func_0x0069d360(param_1,0,0x6802c,0xf,param_2);
  return bVar1 ^ 1;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34e340 RVA 0x34e340 | Evidence ev_a5d97c866296888df7d2599920b59f69ad8e50efe5467f977514ff9b689b404b | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34e340", "end": "0x34e40b"}], "total_bytes": 204, "span_bytes": 204, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

byte sub_34e340(ulong param_1,long param_2)

{
  char cVar1;
  byte bVar2;
  
  bVar2 = 1;
  if (param_2 != 0) {
    cVar1 = func_0x0069d360(param_1,0,0x68014,4,param_2);
    if ((cVar1 != '\0') && (param_2 != -4)) {
      cVar1 = func_0x0069d360(param_1 & 0xffffffff,0,0x68018,4);
      if ((cVar1 != '\0') && (param_2 != -8)) {
        cVar1 = func_0x0069d360(param_1 & 0xffffffff,0,0x6801c,4);
        if ((cVar1 != '\0') && (param_2 != -0xc)) {
          cVar1 = func_0x0069d360(param_1 & 0xffffffff,0,0x68020,4);
          if ((cVar1 != '\0') && (param_2 + 0x10 != 0)) {
            bVar2 = func_0x0069d360(param_1 & 0xffffffff,0,0x68024,4,param_2 + 0x10);
            bVar2 = bVar2 ^ 1;
          }
        }
      }
    }
  }
  return bVar2;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34e415 RVA 0x34e415 | Evidence ev_3ddf117c00f9b77d5f4935915ab0db5024f701feec67a1ece68faf998cc9810f | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34e415", "end": "0x34e433"}], "total_bytes": 31, "span_bytes": 31, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

byte sub_34e415(undefined8 param_1,undefined8 param_2)

{
  byte bVar1;
  
  bVar1 = func_0x0069d360(param_1,0,0x6802a,2,param_2);
  return bVar1 ^ 1;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34e445 RVA 0x34e445 | Evidence ev_0449a83b50b6db71a7eb5e75996ed30943a90338d12e26f2e464d0e4ef07c527 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34e445", "end": "0x34e463"}], "total_bytes": 31, "span_bytes": 31, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

byte sub_34e445(undefined8 param_1,undefined8 param_2)

{
  byte bVar1;
  
  bVar1 = func_0x0069efd0(param_1,0,0x68007,5,param_2);
  return bVar1 ^ 1;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34e475 RVA 0x34e475 | Evidence ev_6f1a077c343114478dd9eeb6d998e1bb3447ffb32c56799fb2c27a7ebadcd3ac | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34e475", "end": "0x34e493"}], "total_bytes": 31, "span_bytes": 31, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

byte sub_34e475(undefined8 param_1,undefined8 param_2)

{
  byte bVar1;
  
  bVar1 = func_0x0069efd0(param_1,0,0x6803b,1,param_2);
  return bVar1 ^ 1;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34e4a5 RVA 0x34e4a5 | Evidence ev_054502ec5649b4379378d64bd2b274b7a5fc851ca870ec353e222a536e7beb3b | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34e4a5", "end": "0x34e4c3"}], "total_bytes": 31, "span_bytes": 31, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

byte sub_34e4a5(undefined8 param_1,undefined8 param_2)

{
  byte bVar1;
  
  bVar1 = func_0x0069efd0(param_1,0,0x6800c,8,param_2);
  return bVar1 ^ 1;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34e4d5 RVA 0x34e4d5 | Evidence ev_94fe115c7841d5e0f3db4b3a480548e1db737b537466311ef2d3e5e0776ee9b7 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34e4d5", "end": "0x34e4f3"}], "total_bytes": 31, "span_bytes": 31, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

byte sub_34e4d5(undefined8 param_1,undefined8 param_2)

{
  byte bVar1;
  
  bVar1 = func_0x0069d360(param_1,0,0x6921d,3,param_2);
  return bVar1 ^ 1;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34e505 RVA 0x34e505 | Evidence ev_432ed6279a61cb6ae9b9e4b2ea063beac78c0e2fc55eac6295305ea07eb8ac2b | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34e505", "end": "0x34e523"}], "total_bytes": 31, "span_bytes": 31, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

byte sub_34e505(undefined8 param_1,undefined8 param_2)

{
  byte bVar1;
  
  bVar1 = func_0x0069d360(param_1,0,0x69493,1,param_2);
  return bVar1 ^ 1;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34e530 RVA 0x34e530 | Evidence ev_25f107af73fcec5f9eae08e43bce7a7e646aa1cabab2e776a259d58d29cfae2f | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34e530", "end": "0x34e5aa"}], "total_bytes": 123, "span_bytes": 123, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_34e530(undefined4 param_1,long param_2)

{
  char cVar1;
  undefined8 uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  
  uVar2 = 1;
  if (param_2 + 1 != 0) {
    uVar5 = 0x215;
    uVar3 = 0;
    do {
      uVar4 = 0x10;
      if (uVar5 < 0x10) {
        uVar4 = uVar5;
      }
      cVar1 = func_0x0069d360(param_1,0,uVar3 + 0x6900b,uVar4,(ulong)uVar3 + param_2 + 1);
      if (cVar1 == '\0') {
        return 1;
      }
      uVar3 = uVar3 + uVar4;
      uVar5 = uVar5 - uVar4;
    } while (uVar5 != 0);
    uVar2 = 0;
  }
  return uVar2;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34e5b0 RVA 0x34e5b0 | Evidence ev_0282662f109399c53126150bf1bf301f6698ec63253d1322b0bca5d06d411d5f | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34e5b0", "end": "0x34e611"}], "total_bytes": 98, "span_bytes": 98, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

byte sub_34e5b0(ulong param_1,long param_2)

{
  char cVar1;
  byte bVar2;
  
  bVar2 = 1;
  if (param_2 != -1) {
    cVar1 = func_0x0069d360(param_1,0,0x692c0,0x10);
    if (cVar1 != '\0') {
      bVar2 = func_0x0069d360(param_1 & 0xffffffff,0,0x692d0,0x10,param_2 + 0x11);
      bVar2 = bVar2 ^ 1;
    }
  }
  return bVar2;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34e628 RVA 0x34e628 | Evidence ev_dc45d969908f444ec4abc1c841151e2d1d1d21a4467019727e6ea5c7d2052e2c | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34e628", "end": "0x34e643"}], "total_bytes": 28, "span_bytes": 28, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

byte sub_34e628(undefined8 param_1)

{
  byte bVar1;
  
  bVar1 = func_0x0069d360(param_1,0,0x692e0,0x10);
  return bVar1 ^ 1;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34e650 RVA 0x34e650 | Evidence ev_5eee4ac9e442d870f3a897ed5a6c0b20a1115cab2c1c6dedc3a20520eccf3716 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34e650", "end": "0x34e6b1"}], "total_bytes": 98, "span_bytes": 98, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

byte sub_34e650(ulong param_1,long param_2)

{
  char cVar1;
  byte bVar2;
  
  bVar2 = 1;
  if (param_2 != -1) {
    cVar1 = func_0x0069d360(param_1,0,0x692f8,0x10);
    if (cVar1 != '\0') {
      bVar2 = func_0x0069d360(param_1 & 0xffffffff,0,0x69308,0x10,param_2 + 0x11);
      bVar2 = bVar2 ^ 1;
    }
  }
  return bVar2;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34e6c0 RVA 0x34e6c0 | Evidence ev_cad1beb1acef999eb6a6a542bdbf86ba47494ef736e925f8daf97f3806929384 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34e6c0", "end": "0x34e866"}], "total_bytes": 423, "span_bytes": 423, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

byte sub_34e6c0(ulong param_1,long param_2)

{
  char cVar1;
  byte bVar2;
  ulong uVar3;
  
  bVar2 = 1;
  if (param_2 != -1) {
    uVar3 = param_1 & 0xffffffff;
    cVar1 = func_0x0069d360(param_1,0,0x69330,0x10);
    if (cVar1 != '\0') {
      cVar1 = func_0x0069d360(uVar3,0,0x69340,0x10,param_2 + 0x11);
      if (cVar1 != '\0') {
        cVar1 = func_0x0069d360(param_1 & 0xffffffff,0,0x69350,0x10,param_2 + 0x21);
        if (cVar1 != '\0') {
          cVar1 = func_0x0069d360(uVar3,0,0x69360,0x10,param_2 + 0x31);
          if (cVar1 != '\0') {
            cVar1 = func_0x0069d360(param_1 & 0xffffffff,0,0x69370,0x10,param_2 + 0x41);
            if (cVar1 != '\0') {
              cVar1 = func_0x0069d360(param_1 & 0xffffffff,0,0x69380,0x10,param_2 + 0x51);
              if (cVar1 != '\0') {
                cVar1 = func_0x0069d360(param_1 & 0xffffffff,0,0x69390,0x10,param_2 + 0x61);
                if (cVar1 != '\0') {
                  cVar1 = func_0x0069d360(uVar3,0,0x693a0,0x10,param_2 + 0x71);
                  if (cVar1 != '\0') {
                    cVar1 = func_0x0069d360(param_1 & 0xffffffff,0,0x693b0,0x10,param_2 + 0x81);
                    if (cVar1 != '\0') {
                      cVar1 = func_0x0069d360(param_1 & 0xffffffff,0,0x693c0,0x10,param_2 + 0x91);
                      if (cVar1 != '\0') {
                        cVar1 = func_0x0069d360(param_1 & 0xffffffff,0,0x693d0,0x10,param_2 + 0xa1);
                        if (cVar1 != '\0') {
                          bVar2 = func_0x0069d360(param_1 & 0xffffffff,0,0x693e0,1,param_2 + 0xb1);
                          bVar2 = bVar2 ^ 1;
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return bVar2;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34e870 RVA 0x34e870 | Evidence ev_a6101af9df822aeacb37fd321a5ef4c83f99f00fbebf4e4ccb65c0adeac62162 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34e870", "end": "0x34e8d1"}], "total_bytes": 98, "span_bytes": 98, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

byte sub_34e870(ulong param_1,long param_2)

{
  char cVar1;
  byte bVar2;
  
  bVar2 = 1;
  if (param_2 != -1) {
    cVar1 = func_0x0069d360(param_1,0,0x69473,0x10);
    if (cVar1 != '\0') {
      bVar2 = func_0x0069d360(param_1 & 0xffffffff,0,0x69483,0x10,param_2 + 0x11);
      bVar2 = bVar2 ^ 1;
    }
  }
  return bVar2;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34e8e8 RVA 0x34e8e8 | Evidence ev_d77479e61670ecb05afe27f84153272420ef8c1f125f50ee5134c27a6da63279 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34e8e8", "end": "0x34e903"}], "total_bytes": 28, "span_bytes": 28, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

byte sub_34e8e8(undefined8 param_1)

{
  byte bVar1;
  
  bVar1 = func_0x0069efd0(param_1,0,0x69000,0xb);
  return bVar1 ^ 1;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34e910 RVA 0x34e910 | Evidence ev_c404355ae1780c236779017f5057a5b37efa5762c3bb83c83cdf50bc0a445962 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34e910", "end": "0x34ea26"}], "total_bytes": 279, "span_bytes": 279, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

byte sub_34e910(ulong param_1,long param_2)

{
  char cVar1;
  byte bVar2;
  ulong uVar3;
  
  bVar2 = 1;
  if (param_2 != -1) {
    uVar3 = param_1 & 0xffffffff;
    cVar1 = func_0x0069efd0(param_1,0,0x69220,0x10);
    if (cVar1 != '\0') {
      cVar1 = func_0x0069efd0(uVar3,0,0x69230,0x10,param_2 + 0x11);
      if (cVar1 != '\0') {
        cVar1 = func_0x0069efd0(param_1 & 0xffffffff,0,0x69240,0x10,param_2 + 0x21);
        if (cVar1 != '\0') {
          cVar1 = func_0x0069efd0(uVar3,0,0x69250,0x10,param_2 + 0x31);
          if (cVar1 != '\0') {
            cVar1 = func_0x0069efd0(param_1 & 0xffffffff,0,0x69260,0x10,param_2 + 0x41);
            if (cVar1 != '\0') {
              cVar1 = func_0x0069efd0(param_1 & 0xffffffff,0,0x69270,0x10,param_2 + 0x51);
              if (cVar1 != '\0') {
                cVar1 = func_0x0069efd0(param_1 & 0xffffffff,0,0x69280,0x10,param_2 + 0x61);
                if (cVar1 != '\0') {
                  bVar2 = func_0x0069efd0(uVar3,0,0x69290,0x10,param_2 + 0x71);
                  bVar2 = bVar2 ^ 1;
                }
              }
            }
          }
        }
      }
    }
  }
  return bVar2;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34ea30 RVA 0x34ea30 | Evidence ev_0cc63209a5b0b3584224e41ec8ddea64b7849db20494a2033bf0906ebe955cba | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34ea30", "end": "0x34ea91"}], "total_bytes": 98, "span_bytes": 98, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

byte sub_34ea30(ulong param_1,long param_2)

{
  char cVar1;
  byte bVar2;
  
  bVar2 = 1;
  if (param_2 != -1) {
    cVar1 = func_0x0069efd0(param_1,0,0x692a0,0x10);
    if (cVar1 != '\0') {
      bVar2 = func_0x0069efd0(param_1 & 0xffffffff,0,0x692b0,0x10,param_2 + 0x11);
      bVar2 = bVar2 ^ 1;
    }
  }
  return bVar2;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34eaa8 RVA 0x34eaa8 | Evidence ev_bda2530ad3c3c365fa2076f69043115643394089a85601cf39d118fbdaa5905c | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34eaa8", "end": "0x34eac3"}], "total_bytes": 28, "span_bytes": 28, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

byte sub_34eaa8(undefined8 param_1)

{
  byte bVar1;
  
  bVar1 = func_0x0069efd0(param_1,0,0x692f0,8);
  return bVar1 ^ 1;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34ead0 RVA 0x34ead0 | Evidence ev_a297cada5ccdca923ff132ae971645dd8c957bf0c32585f2f7a7a1bf142fdb23 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34ead0", "end": "0x34eb31"}], "total_bytes": 98, "span_bytes": 98, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

byte sub_34ead0(ulong param_1,long param_2)

{
  char cVar1;
  byte bVar2;
  
  bVar2 = 1;
  if (param_2 != -1) {
    cVar1 = func_0x0069efd0(param_1,0,0x69318,0x10);
    if (cVar1 != '\0') {
      bVar2 = func_0x0069efd0(param_1 & 0xffffffff,0,0x69328,8,param_2 + 0x11);
      bVar2 = bVar2 ^ 1;
    }
  }
  return bVar2;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34eb48 RVA 0x34eb48 | Evidence ev_62f79da0e15bc8bb4ccd5f25c499dc19775fdcdb7f02b872cbc0b136470fc2b5 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34eb48", "end": "0x34eb63"}], "total_bytes": 28, "span_bytes": 28, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

byte sub_34eb48(undefined8 param_1)

{
  byte bVar1;
  
  bVar1 = func_0x0069efd0(param_1,0,0x693e0,0x10);
  return bVar1 ^ 1;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34eb78 RVA 0x34eb78 | Evidence ev_b659e52b05a2c2905bab52017090008502eb5c3a7e1977176f6b692fa3901ede | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34eb78", "end": "0x34eb93"}], "total_bytes": 28, "span_bytes": 28, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

byte sub_34eb78(undefined8 param_1)

{
  byte bVar1;
  
  bVar1 = func_0x0069efd0(param_1,0,0x693f0,7);
  return bVar1 ^ 1;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34eba5 RVA 0x34eba5 | Evidence ev_20fa3f4ca07efbb663973420e1f8b8fb97055cfd8a769dbda4a90f9eb2bca743 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34eba5", "end": "0x34ebc3"}], "total_bytes": 31, "span_bytes": 31, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

byte sub_34eba5(undefined8 param_1,undefined8 param_2)

{
  byte bVar1;
  
  bVar1 = func_0x0069efd0(param_1,0,0x69494,1,param_2);
  return bVar1 ^ 1;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34ebd0 RVA 0x34ebd0 | Evidence ev_b1af541f9e9139a55f4bc51ba87920c536e1f4a17aa68a2bb6cdb1bc72a21560 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34ebd0", "end": "0x34ec15"}, {"start": "0x34ec20", "end": "0x34ed95"}], "total_bytes": 444, "span_bytes": 454, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_34ebd0(undefined4 *param_1)

{
  undefined4 uVar1;
  code *pcVar2;
  char cVar3;
  long lVar4;
  undefined8 uVar5;
  int iVar6;
  long local_100;
  int local_f8 [2];
  undefined1 local_f0 [184];
  long local_38;
  
  local_38 = _DAT_0391c310;
  func_0x0039b1e0(*param_1);
  uVar5 = 0x12f1b6f;
  iVar6 = 0;
  do {
    lVar4 = func_0x002a3970(*param_1,iVar6);
    if (lVar4 == 0) {
      func_0x0025d410(0x126d389,0x136f6ce);
LAB_0034ed6e:
      uVar5 = 1;
      goto LAB_0034ed73;
    }
    cVar3 = func_0x00b95060(*param_1,lVar4,local_f8,0xc0);
    if (cVar3 == '\0') {
      func_0x0025d410(0x12f1b6f,0x136f6ce);
    }
    else if (local_f8[0] == 3) {
      param_1[1] = iVar6;
      func_0x002590b0(param_1 + 2,local_f0,0xb8);
      uVar1 = *param_1;
      lVar4 = func_0x002a3930(uVar1);
      if (lVar4 == 0) {
        func_0x0025d410(0x12fb0b2,0x129f32d);
      }
      else {
        cVar3 = func_0x00b95060(uVar1,lVar4 + 0x30,&local_100,8);
        if (cVar3 != '\0') {
          local_100 = local_100 + 1;
          cVar3 = func_0x00b951c0(uVar1,lVar4 + 0x30,&local_100,8);
          if (cVar3 != '\0') {
            uVar5 = 0;
            goto LAB_0034ed73;
          }
          uVar5 = 0x126d3fa;
        }
        func_0x0025d410(uVar5,0x129f32d);
      }
      func_0x0025d410(0x126d3be,0x136f6ce,1);
      goto LAB_0034ed6e;
    }
    iVar6 = iVar6 + 1;
  } while (iVar6 != 0x10);
  param_1[1] = 0xffffffff;
  uVar5 = 0;
LAB_0034ed73:
  if (_DAT_0391c310 == local_38) {
    return uVar5;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar2 = (code *)invalidInstructionException();
  (*pcVar2)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34eda0 RVA 0x34eda0 | Evidence ev_c64466e3584dd7530ea53886b1378a3a4fc50e658041ddc8502c31e68cdc5b89 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34eda0", "end": "0x34eec4"}], "total_bytes": 293, "span_bytes": 293, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_34eda0(undefined4 *param_1)

{
  undefined4 uVar1;
  code *pcVar2;
  char cVar3;
  undefined8 uVar4;
  long lVar5;
  undefined4 local_34;
  long local_30;
  long local_28;
  
  local_28 = _DAT_0391c310;
  uVar4 = 0x16;
  if (0xf < (uint)param_1[1]) goto LAB_0034eeaa;
  lVar5 = func_0x002a3970(*param_1);
  if (lVar5 == 0) {
    uVar4 = 0x126d389;
LAB_0034ee54:
    func_0x0025d410(uVar4,0x12f1b8b);
  }
  else {
    local_34 = 2;
    cVar3 = func_0x00b951c0(*param_1,lVar5,&local_34,4);
    if (cVar3 == '\0') {
      uVar4 = 0x126d3fa;
      goto LAB_0034ee54;
    }
    uVar1 = *param_1;
    lVar5 = func_0x002a3930(uVar1);
    if (lVar5 == 0) {
      uVar4 = 0x12fb0b2;
    }
    else {
      cVar3 = func_0x00b95060(uVar1,lVar5 + 0x38,&local_30,8);
      if (cVar3 == '\0') {
        uVar4 = 0x12f1b6f;
      }
      else {
        local_30 = local_30 + 1;
        cVar3 = func_0x00b951c0(uVar1,lVar5 + 0x38,&local_30,8);
        if (cVar3 != '\0') {
          uVar4 = 0;
          goto LAB_0034eeaa;
        }
        uVar4 = 0x126d3fa;
      }
    }
    func_0x0025d410(uVar4,0x129f32d);
    func_0x0025d410(0x126d3be,0x12f1b8b,1);
  }
  uVar4 = 1;
LAB_0034eeaa:
  if (_DAT_0391c310 == local_28) {
    return uVar4;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar2 = (code *)invalidInstructionException();
  (*pcVar2)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34eed0 RVA 0x34eed0 | Evidence ev_5878abb3e5ebd60f7bacdc9a02ad6fd9b51f4f78bf8d77abe68e84773cce4e0f | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34eed0", "end": "0x34ef11"}], "total_bytes": 66, "span_bytes": 66, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Possible PIC construction at 0x0034eef9: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x0034eefe) */

void sub_34eed0(void)

{
  int iVar1;
  long *in_GS_OFFSET;
  
  iVar1 = func_0x00c366a0(*(undefined8 *)(*in_GS_OFFSET + 0x140));
  if (iVar1 != 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34ef20 RVA 0x34ef20 | Evidence ev_93ceb025120b6f69fa9b23b5ff4e42e4a58286500cc279a3d8943b65d63a6c2a | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34ef20", "end": "0x34ef35"}], "total_bytes": 22, "span_bytes": 22, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_34ef20(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34ef40 RVA 0x34ef40 | Evidence ev_a0f54d0654e6695b051af98f911009a30c5b563c07d4b26cedf1ffc6c1de7faf | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34ef40", "end": "0x34ef55"}], "total_bytes": 22, "span_bytes": 22, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_34ef40(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34ef60 RVA 0x34ef60 | Evidence ev_10967e7c63261b21d88154701bcb7f007e8d2581dc8aed9d16b7aedb5c7a6d5e | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34ef60", "end": "0x34f01d"}], "total_bytes": 190, "span_bytes": 190, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_34ef60(long param_1)

{
  ulong uVar1;
  ulong uVar2;
  
  if ((*(byte *)(param_1 + 0x510) & 1) != 0) {
    if (_DAT_0345f428 == 0) {
      uVar1 = 0xffffffff;
      uVar2 = 0xffffffff;
      if (*(ulong *)(param_1 + 0x430) << 3 < 0x3e7fffffc18) {
        uVar2 = (*(ulong *)(param_1 + 0x430) & 0x1fffffffffffffff) / 0x7d;
      }
      if (*(uint *)(param_1 + 0x428) < uVar2) {
        *(int *)(param_1 + 0x428) = (int)uVar2;
      }
      *(undefined8 *)(param_1 + 0x430) = 0;
      if (*(ulong *)(param_1 + 0x438) << 3 < 0x3e7fffffc18) {
        uVar1 = (*(ulong *)(param_1 + 0x438) & 0x1fffffffffffffff) / 0x7d;
      }
      if (*(uint *)(param_1 + 0x42c) < uVar1) {
        *(int *)(param_1 + 0x42c) = (int)uVar1;
      }
    }
    else {
      *(undefined8 *)(param_1 + 0x430) = 0;
    }
    *(undefined8 *)(param_1 + 0x438) = 0;
  }
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34f020 RVA 0x34f020 | Evidence ev_c820b03c89247f22daefe266186dfa51fd685b4245564eeb70aea0bb082da93e | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34f020", "end": "0x34f068"}], "total_bytes": 73, "span_bytes": 73, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_34f020(long param_1,long param_2,int param_3,int param_4)

{
  int iVar1;
  
  if ((*(byte *)(param_1 + 0x1f) & 0x20) != 0) {
    iVar1 = 1;
    if (0 < param_4 && param_4 < param_3) {
      iVar1 = (param_3 / param_4 + 1) - (uint)(param_3 % param_4 == 0);
    }
    *(int *)(param_2 + 0x420) = *(int *)(param_2 + 0x420) + iVar1;
    *(int *)(param_2 + 0x418) = *(int *)(param_2 + 0x418) + iVar1;
    *(long *)(param_2 + 0x438) = *(long *)(param_2 + 0x438) + (long)param_3;
  }
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34f070 RVA 0x34f070 | Evidence ev_f5318a9eb2d3cd4721129a3d01ebd465d3267d0a55081382321d016aabc62e08 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34f070", "end": "0x34f0c7"}], "total_bytes": 88, "span_bytes": 88, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_34f070(long param_1)

{
  if (_DAT_0345f428 != 0) {
    *(undefined8 *)(param_1 + 0x41c) = 0;
    return;
  }
  if (*(uint *)(param_1 + 0x40c) < *(uint *)(param_1 + 0x41c)) {
    *(uint *)(param_1 + 0x40c) = *(uint *)(param_1 + 0x41c);
  }
  *(undefined4 *)(param_1 + 0x41c) = 0;
  if (*(uint *)(param_1 + 0x410) < *(uint *)(param_1 + 0x420)) {
    *(uint *)(param_1 + 0x410) = *(uint *)(param_1 + 0x420);
  }
  *(undefined4 *)(param_1 + 0x420) = 0;
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34f0d0 RVA 0x34f0d0 | Evidence ev_5c5ec397af1c13c688db3fe77b8bbe283f2897fee2e367a38e435a2cf781faa5 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34f0d0", "end": "0x34f26a"}], "total_bytes": 411, "span_bytes": 411, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_34f0d0(long param_1)

{
  long lVar1;
  code *pcVar2;
  int iVar3;
  long *plVar4;
  undefined8 uVar5;
  long *in_GS_OFFSET;
  undefined4 local_f0;
  undefined4 local_ec;
  undefined1 local_d0 [6];
  byte local_ca;
  long local_30;
  
  local_30 = _DAT_0391c310;
  plVar4 = (long *)func_0x00c08b50(0xa38,0x2bfc080,0x101);
  if (plVar4 == (long *)0x0) {
    uVar5 = 0xc;
  }
  else {
    *(undefined4 *)(plVar4 + 2) = *(undefined4 *)(param_1 + 0xbc);
    func_0x004c6a00(0x345f448,0,0,0);
    *plVar4 = (long)_DAT_0345f450;
    if (_DAT_0345f450 != (long *)0x0) {
      _DAT_0345f450[1] = (long)plVar4;
    }
    _DAT_0345f450 = plVar4;
    plVar4[1] = (long)&DAT_0345f450;
    uVar5 = 0;
    func_0x004c6fa0(0x345f448,0,0,0);
    func_0x002590b0(local_d0,0x345f460,0xa0);
    local_ca = local_ca | 2;
    lVar1 = *in_GS_OFFSET;
    sub_34f270(lVar1,local_d0,1);
    func_0x00258ff0(&local_f0,0x20);
    local_f0 = 0;
    iVar3 = func_0x00c366d0(*(undefined8 *)(lVar1 + 0x140));
    local_ec = 0x1d;
    if (iVar3 == 0) {
      iVar3 = func_0x00c36710(*(undefined8 *)(lVar1 + 0x140));
      local_ec = 0x1d;
      if (iVar3 == 0) {
        local_ec = 0x10;
      }
    }
    func_0x0034f8f0(lVar1,&local_f0);
    iVar3 = func_0x00c366a0(*(undefined8 *)(*in_GS_OFFSET + 0x140));
    if (iVar3 != 0) {
      func_0x00258ff0(0x345f3f8,0x18);
      func_0x00258ff0(0x345f410,0x18);
    }
  }
  if (_DAT_0391c310 == local_30) {
    return uVar5;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar2 = (code *)invalidInstructionException();
  (*pcVar2)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_34f270 RVA 0x34f270 | Evidence ev_7b99712d925a4867e3802961063240960faa39a199bad3007923e0ed809d913b | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.body.bin SHA256 dccea412671e1155c59757ecd4936dfec39403f153a1dadfafa0bfec74e73ff5 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34f270", "end": "0x34f769"}, {"start": "0x34f776", "end": "0x34f781"}], "total_bytes": 1286, "span_bytes": 1298, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_34f270(long param_1,short *param_2,int param_3)

{
  short sVar1;
  uint uVar2;
  uint uVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  long lVar7;
  undefined1 *puVar8;
  long lVar9;
  long lVar10;
  long lVar11;
  uint uVar12;
  undefined8 *puVar13;
  
  iVar6 = *(int *)(*(long *)(param_1 + 8) + 0xbc);
  iVar5 = func_0x00acc9a0(0);
  if (((iVar5 == 0) && (iVar5 = func_0x00c36710(*(undefined8 *)(param_1 + 0x140)), iVar5 == 0)) ||
     ((param_3 == 0 &&
      (((DAT_0345f46c & 1) != 0 &&
       (iVar5 = func_0x00c36710(*(undefined8 *)(param_1 + 0x140)), iVar5 == 0)))))) {
    return 0x2d;
  }
  uVar2 = *(uint *)(param_2 + 2);
  if ((*(int *)(param_2 + 0x48) == 0) && ((uVar2 & 0x1000000) != 0 && *(int *)(param_2 + 4) != 0)) {
    return 0x16;
  }
  uVar12 = uVar2 & 0x1000000;
  iVar5 = func_0x00c366d0(*(undefined8 *)(param_1 + 0x140));
  if ((uint)(uVar12 == 0 && iVar5 != 0) * 4 + 0xf < *(uint *)(param_2 + 4)) {
    return 0x16;
  }
  iVar5 = func_0x00c366d0(*(undefined8 *)(param_1 + 0x140));
  if ((iVar5 == 0) && (*(int *)(param_2 + 0x48) != 0)) {
    return 0x16;
  }
  func_0x004c6a00(0x345f448,0,0,0);
  puVar13 = (undefined8 *)&DAT_0345f450;
  do {
    puVar13 = (undefined8 *)*puVar13;
    if (puVar13 == (undefined8 *)0x0) {
      iVar6 = 0xc;
      goto LAB_0034f567;
    }
  } while (*(int *)(puVar13 + 2) != iVar6);
  uVar3 = *(uint *)(param_2 + 4);
  sVar1 = *param_2;
  puVar8 = (undefined1 *)((long)puVar13 + (ulong)uVar3 * 0xa0 + 0x14);
  if (0xf < uVar3) {
    puVar8 = (undefined1 *)((ulong)(uVar3 - 0x10) * 0xa0 + 0x345f500);
  }
  if (sVar1 != 0) {
    uVar4 = *(undefined4 *)(param_2 + 0x48);
    func_0x00258ff0(param_2,0xa0);
    if (sVar1 == 3) {
      param_2[8] = 5;
    }
    else if (sVar1 == 2) {
      param_2[0x10] = 0;
      param_2[0x11] = 2;
    }
    else {
      if (sVar1 != 1) {
        iVar6 = 0x1c;
        if (puVar8 != (undefined1 *)0x0) {
          *(undefined2 *)(puVar8 + 2) = 0;
        }
        goto LAB_0034f567;
      }
      param_2[0xb] = 100;
      param_2[0xc] = 0;
    }
    *param_2 = sVar1;
    *(uint *)(param_2 + 4) = uVar3;
    *(undefined4 *)(param_2 + 0x48) = uVar4;
  }
  if (param_2[1] != 0) {
    param_2[1] = 0;
  }
  iVar6 = func_0x00c366d0(*(undefined8 *)(param_1 + 0x140));
  if (iVar6 == 0 && param_3 == 0) {
    uVar3 = uVar2 & 0xfffffeff;
  }
  else {
    uVar3 = uVar2 & 0xfefcfeff;
  }
  if ((uVar3 == 0) && ((uVar12 == 0 || ((uVar2 & 0x30000) == 0 || *(int *)(param_2 + 0x48) == 0))))
  {
    if ((((((char)param_2[0x4a] == '\0') && (*(char *)((long)param_2 + 0x95) == '\0')) &&
         ((char)param_2[0x4b] == '\0')) &&
        ((((*(char *)((long)param_2 + 0x97) == '\0' && ((char)param_2[0x4c] == '\0')) &&
          ((*(char *)((long)param_2 + 0x99) == '\0' &&
           (((char)param_2[0x4d] == '\0' && (*(char *)((long)param_2 + 0x9b) == '\0')))))) &&
         ((char)param_2[0x4e] == '\0')))) &&
       (((*(char *)((long)param_2 + 0x9d) == '\0' && ((char)param_2[0x4f] == '\0')) &&
        (*(char *)((long)param_2 + 0x9f) == '\0')))) {
      iVar6 = func_0x00350000(param_2,puVar8);
      if (iVar6 == 0) {
        func_0x00c36710(*(undefined8 *)(param_1 + 0x140));
        func_0x003503f0(param_2);
        *(uint *)(param_2 + 2) = uVar2;
        puVar13 = _DAT_0345f450;
        if ((uVar2 & 0x30000) == 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        for (; puVar13 != (undefined8 *)0x0; puVar13 = (undefined8 *)*puVar13) {
          lVar9 = 0;
          lVar11 = (long)puVar13 + 0x24;
          lVar10 = (long)puVar13 + 100;
          do {
            if (uVar12 == 0) {
              uVar3 = *(uint *)(puVar13 + lVar9 * 0x14 + 4);
              if ((uVar3 & 0x10000) != 0) {
                lVar7 = 0;
                do {
                  if (*(char *)(lVar7 + 0x345f470) != '\0') {
                    *(undefined1 *)(lVar11 + lVar7) = 0;
                  }
                  lVar7 = lVar7 + 1;
                } while (lVar7 != 0x40);
                lVar7 = 0;
                do {
                  if (*(char *)(lVar7 + 0x345f4b0) != '\0') {
                    *(undefined1 *)(lVar10 + lVar7) = 0;
                  }
                  lVar7 = lVar7 + 1;
                } while (lVar7 != 0x40);
                *(uint *)(puVar13 + lVar9 * 0x14 + 4) = uVar3 & 0xfffefffe;
                lVar7 = 0;
                do {
                  if (*(char *)(lVar11 + lVar7) != '\0') {
                    lVar7 = 0;
                    *(uint *)(puVar13 + lVar9 * 0x14 + 4) = uVar3 & 0xfffeffff | 1;
                    goto LAB_0034f6de;
                  }
                  lVar7 = lVar7 + 1;
                } while (lVar7 != 0x40);
                lVar7 = 0;
LAB_0034f6de:
                do {
                  if (*(char *)(lVar10 + lVar7) != '\0') {
                    *(uint *)(puVar13 + lVar9 * 0x14 + 4) = uVar3 & 0xfffeffff | 1;
                    break;
                  }
                  lVar7 = lVar7 + 1;
                } while (lVar7 != 0x40);
              }
            }
            else {
              func_0x00258ff0((long)puVar13 + lVar9 * 0xa0 + 0x24,0x40);
              func_0x00258ff0((long)puVar13 + lVar9 * 0xa0 + 100,0x40);
              *(uint *)(puVar13 + lVar9 * 0x14 + 4) =
                   *(uint *)(puVar13 + lVar9 * 0x14 + 4) & 0xfffefffe;
            }
            lVar9 = lVar9 + 1;
            lVar11 = lVar11 + 0xa0;
            lVar10 = lVar10 + 0xa0;
          } while (lVar9 != 0x10);
        }
        func_0x002590b0(0x345f460,param_2,0xa0);
        _DAT_0345f468 = 0;
        _DAT_0345f4f0 = 0;
        iVar6 = 0;
        if ((DAT_0345f46c & 1) != 0) {
          if ((uVar2 & 0x10000) != 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
            halt_baddata();
          }
          if (_DAT_0345f450 != (undefined8 *)0x0 && (uVar2 & 0x20000) != 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
            halt_baddata();
          }
        }
      }
    }
    else {
      iVar6 = 0x1c;
      if (puVar8 != (undefined1 *)0x0) {
        *(undefined2 *)(puVar8 + 2) = 0x94;
      }
    }
  }
  else {
    iVar6 = 0x1c;
    if (puVar8 != (undefined1 *)0x0) {
      *(undefined2 *)(puVar8 + 2) = 4;
    }
  }
LAB_0034f567:
  func_0x004c6fa0(0x345f448,0,0,0);
  return iVar6;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): handler_659_tail_helper RVA 0x34b540 | Evidence ev_e2a5616a7db424da3c93382bb2f20c03e7eb0593073d5101a6f472072bb1026b | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.helper.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_659.helper.bin SHA256 ff722ea6957aab38ba3621a1ef52e9c08dd2643b0d63170719d0551ab821e8ba =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x34b540", "end": "0x34b625"}, {"start": "0x34b630", "end": "0x34b781"}], "total_bytes": 568, "span_bytes": 578, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8
handler_659_tail_helper
          (long param_1,undefined8 param_2,ulong param_3,int param_4,undefined8 param_5)

{
  undefined8 *puVar1;
  long lVar2;
  undefined8 *puVar3;
  code *pcVar4;
  int iVar5;
  ulong uVar6;
  undefined8 uVar7;
  long lVar8;
  undefined8 *puVar9;
  ulong uVar10;
  ulong uVar11;
  ulong *in_GS_OFFSET;
  ulong local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  puVar3 = *(undefined8 **)(param_1 + 1000);
  if ((puVar3 == (undefined8 *)0x0) || (*(long *)(puVar3[2] + 0x148) == 0)) {
    func_0x00b22a30(0x1310ed9,0x39b,0x12fbd8a,0x135ae30);
    uVar7 = 1;
  }
  else {
    puVar1 = puVar3 + 0xe;
    func_0x00c4bb20(puVar1,0,0,0);
    uVar6 = (ulong)*(uint *)(puVar3 + 5);
    if ((param_4 == 0) || (uVar6 <= param_3)) {
      lVar2 = uVar6 * 4;
      lVar8 = func_0x00b2ac60(lVar2,9);
      func_0x00258ff0(lVar8,lVar2);
      puVar9 = (undefined8 *)*puVar3;
      local_40 = 0;
      uVar11 = 0;
      while ((puVar9 != (undefined8 *)0x0 && (uVar11 <= *(uint *)(puVar3 + 5)))) {
        if ((param_4 != 0) || (uVar10 = uVar11, (*(byte *)((long)puVar9 + 0x11d) & 1) == 0)) {
          if (param_3 <= uVar11) {
            if ((puVar3[0x11] & 0xfffffffffffffff1) == *in_GS_OFFSET) {
              func_0x00c4c4b0(puVar1,0,0);
            }
            else {
              func_0x00c4c300(puVar1,0,0);
            }
            uVar7 = 0xc;
            goto LAB_0034b747;
          }
          uVar10 = uVar11 + 1;
          *(undefined4 *)(lVar8 + uVar11 * 4) = *(undefined4 *)(puVar9 + 5);
          local_40 = uVar10;
        }
        puVar9 = (undefined8 *)*puVar9;
        uVar11 = uVar10;
      }
      func_0x00c4c4b0(puVar1,0,0);
      if ((param_4 != 0) && (uVar11 != uVar6)) {
        func_0x00b22a30(0x1310ed9,0x3cd,0x131ba47,0x138e83a);
      }
      func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
      iVar5 = func_0x002591d0(lVar8,param_2,uVar11 << 2);
      uVar7 = 0xe;
      if (iVar5 == 0) {
        func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
        iVar5 = func_0x002591d0(&local_40,param_5,8);
        uVar7 = 0xe;
        if (iVar5 == 0) {
          uVar7 = 0;
        }
      }
LAB_0034b747:
      func_0x00b24250(lVar8,lVar2,9);
    }
    else {
      func_0x00c4c4b0(puVar1,0,0);
      uVar7 = 0xc;
    }
  }
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar4 = (code *)invalidInstructionException();
    (*pcVar4)();
  }
  return uVar7;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): copyout_candidate RVA 0x2591d0 | Evidence ev_71486184be245b984abbb9be576981c38f613a7db64a834e00ab1b4e60ea2113 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/common_support.functions/0x2591d0.json | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/common_support.elf SHA256 843fa164383f956095dc4042a013c49d64f59c358ea7f43c10f0d9923485fd5a =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2591d0", "end": "0x259258"}, {"start": "0x259260", "end": "0x25927f"}], "total_bytes": 169, "span_bytes": 176, "non_contiguous": true, "contains_entry": true}
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


