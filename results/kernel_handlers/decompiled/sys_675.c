/* Handler 675: REA6.7.0 / Ghidra12.1.4 recovered pseudocode, not original or buildable C.
 * Original4096-byte input SHA256 32b2efb1029b8e16f2ca860171513b59a018e1302c8dbb741a1bf76f96710582
 * Raw entry RVA 0x265458 -> actual target 0x2d36f0. narg=2.
 * Kernel RVAs; runtime VA=0xffffffff8a9c0000+RVA. Opaque externals/data remain unknown.
 * Analyst types below are inferred from accesses. Recovered pseudocode is retained verbatim afterward.
 * Original entry is an assembly-verified tail JMP to the target above. An engine halt_baddata
 * at that unmapped edge is a decompiler boundary artifact, not a recovered halt operation.
 */
#include <stdint.h>

/* ===== Analyst recovered interface/types ===== */
int analyst_handler_675(void *unused_thread, const void *unused_args) {
    *(volatile uint32_t *)(uintptr_t)0x1a962e0 = 1;
    *(volatile uint64_t *)(uintptr_t)0x2d616c8 = UINT64_MAX;
    *(volatile uint64_t *)(uintptr_t)0x2d60008 = 0;
    return 0;
}
/* Addresses above are kernel RVAs used as symbolic locations, not valid host pointers. */


/* ===== ORIGINAL ENTRY: <EXTERNAL>::thunk_265458 RVA 0x265458 | Evidence ev_fcf2d62420d798896612e67b478001184db0243e9215b3060203bdfedd93be64 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.raw.dossier.json | Source /tmp/rea-646-676-5b61b6f2/raw_union.bin SHA256 352988f408bc976411feddb3ef6cd2b18459d2aa3fa6dfd7f2e4a7fe416ce915 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x265458", "end": "0x26545c"}], "total_bytes": 5, "span_bytes": 5, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void thunk_265458(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}




/* ===== TARGET: handler_675_body RVA 0x2d36f0 | Evidence ev_99ab7b5e3d19dbb381b8d59021ed144f2ec64fd216264a47139b627dd8450a58 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d36f0", "end": "0x2d3717"}], "total_bytes": 40, "span_bytes": 40, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 handler_675_body(void)

{
  _DAT_01a962e0 = 1;
  _DAT_02d616c8 = 0xffffffffffffffff;
  _DAT_02d60008 = 0;
  return 0;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d3720 RVA 0x2d3720 | Evidence ev_29152ee1b4f68973a234dd78b6f50de0e6756418adc3b0939f466b55b82bef7f | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d3720", "end": "0x2d372c"}], "total_bytes": 13, "span_bytes": 13, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_2d3720(void)

{
  return _DAT_02d60008;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d3730 RVA 0x2d3730 | Evidence ev_d30dc3ba3c699e1a924aba4ce6ee58898b85de8b375c18a3933441507ebc2284 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d3730", "end": "0x2d3815"}], "total_bytes": 230, "span_bytes": 230, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_2d3730(long param_1,undefined8 *param_2)

{
  long lVar1;
  long lVar2;
  long lVar3;
  code *pcVar4;
  int iVar5;
  undefined8 uVar6;
  ulong uVar7;
  undefined8 *in_GS_OFFSET;
  undefined1 local_40 [8];
  long local_38;
  
  local_38 = _DAT_0391c310;
  iVar5 = func_0x00609940();
  if (iVar5 == 0) {
    uVar6 = 1;
  }
  else {
    lVar2 = param_2[1];
    uVar6 = 0x16;
    if (lVar2 != 0) {
      uVar6 = *param_2;
      lVar3 = *(long *)(*(long *)(*(long *)(param_1 + 8) + 0x200) + 0x1d8);
      lVar1 = lVar3 + 0x18;
      func_0x004c6a00(lVar1,0,0,0);
      uVar7 = func_0x008ed710(lVar3,uVar6,local_40);
      func_0x004c6fa0(lVar1,0,0,0);
      uVar6 = 0x16;
      if ((uVar7 & 1) != 0) {
        func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
        uVar6 = func_0x002591d0(local_40,lVar2,8);
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




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d3829 RVA 0x2d3829 | Evidence ev_c79896e6207afc8e36a0b8494098e4254597302d7a410ac7bf78e4b546a665ae | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d3829", "end": "0x2d3857"}], "total_bytes": 47, "span_bytes": 47, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_2d3829(long param_1)

{
  func_0x002ce900(param_1,0xc80000000,0xc80048000,0);
  *(byte *)(param_1 + 0x244) = *(byte *)(param_1 + 0x244) & 0xbf;
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): FUN_002d3860 RVA 0x2d3860 | Evidence ev_8b403020561dc38223ff7ed8dd29905c9b3b7f4c7e26b305a425cc36c6f58074 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d3860", "end": "0x2d3878"}], "total_bytes": 25, "span_bytes": 25, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void FUN_002d3860(long param_1)

{
  code *pcVar1;
  
  if (*(int *)(*(long *)(*(long *)(param_1 + 0x200) + 0x1d8) + 0x27c) != 0) {
    return;
  }
  func_0x007f1950();
  func_0x007f18a0(sub_2d3879,(long)*(int *)(param_1 + 0xbc));
  func_0x00c9aa10(0x83,0x127f9f2,*(undefined4 *)(param_1 + 0xbc));
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d3879 RVA 0x2d3879 | Evidence ev_109d02d211647adc4ab082d44a0b996720d3113c9f39f59a43d64048ae994944 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d3879", "end": "0x2d38b4"}], "total_bytes": 60, "span_bytes": 60, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_2d3879(long param_1)

{
  code *pcVar1;
  
  func_0x007f1950();
  func_0x007f18a0(sub_2d3879,(long)*(int *)(param_1 + 0xbc));
  func_0x00c9aa10(0x83,0x127f9f2,*(undefined4 *)(param_1 + 0xbc));
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d38c0 RVA 0x2d38c0 | Evidence ev_5542467bb884213831948eb488e99d3f7233a87c0d7ed4a7516668945758d94e | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d38c0", "end": "0x2d38c9"}], "total_bytes": 10, "span_bytes": 10, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted.", "Ghidra Listing reports a terminal call at 0x2d38c5 to 0x2d3860 FUN_002d3860 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

void sub_2d38c0(void)

{
  FUN_002d3860();
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d38e3 RVA 0x2d38e3 | Evidence ev_1209c777df5cded43e983d4afb628a28dfe779644e7d741eb30fac03b4900bc5 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d38e3", "end": "0x2d391e"}], "total_bytes": 60, "span_bytes": 60, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_2d38e3(long param_1)

{
  code *pcVar1;
  
  func_0x007f1950();
  func_0x007f18a0(sub_2d38e3,(long)*(int *)(param_1 + 0xbc));
  func_0x00c9aa10(0x87,0x138de87,*(undefined4 *)(param_1 + 0xbc));
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d3920 RVA 0x2d3920 | Evidence ev_e14b76d3d6aefa86c52eae21b8309d2546008cb0ba7c571dc0cef6a8d3328b8e | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d3920", "end": "0x2d3f51"}], "total_bytes": 1586, "span_bytes": 1586, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong sub_2d3920(long *param_1,long param_2,ulong param_3,long param_4,uint param_5,long param_6,
                ulong param_7,uint param_8)

{
  long lVar1;
  ulong uVar2;
  code *pcVar3;
  int iVar4;
  int iVar5;
  ulong uVar6;
  long lVar7;
  ulong uVar8;
  long lVar9;
  long lVar10;
  long lVar11;
  ulong *puVar12;
  uint uVar13;
  long lVar14;
  long *in_GS_OFFSET;
  long local_90;
  ulong local_80;
  ulong local_58;
  long local_40;
  long local_38;
  
  uVar13 = 0x16;
  local_38 = _DAT_0391c310;
  lVar1 = *(long *)(param_2 + 0x200);
  *param_1 = param_2;
  param_1[1] = param_3;
  param_1[2] = param_4;
  param_1[3] = param_6;
  param_1[4] = param_7;
  param_1[5] = 0;
  param_1[6] = 0;
  *(undefined4 *)(param_1 + 7) = 0;
  if (3 < param_8) goto LAB_002d3e3e;
  if (param_3 >> 0x2b != 0) {
    uVar6 = sub_2d3f60();
    if (_DAT_0391c310 == local_38) {
      return uVar6;
    }
    goto LAB_002d3f1b;
  }
  uVar6 = param_4 + param_3;
  if (((param_3 < uVar6) && (*(ulong *)(lVar1 + 0x20) <= param_3)) &&
     (uVar6 <= *(ulong *)(lVar1 + 0x28))) {
    param_5 = param_5 & 0xff;
    iVar4 = func_0x002cedc0(lVar1,param_3,uVar6);
    if (iVar4 == 0) {
      if (param_8 < 2) {
LAB_002d3a71:
        lVar7 = func_0x005033b0(param_4);
        param_1[5] = lVar7;
        if (lVar7 == 0) {
          uVar13 = 0x23;
        }
        else {
          uVar13 = 0;
          func_0x002c6480(lVar1,0,0);
          iVar4 = func_0x002c6c40(lVar1,param_3,&local_40);
          if (iVar4 == 0) {
            uVar13 = 0x16;
LAB_002d3e13:
            func_0x002c6c40(lVar1,param_3,&local_40);
          }
          else {
            lVar7 = local_40;
            if (local_40 != lVar1) {
              uVar13 = 0;
              do {
                if (uVar6 <= *(ulong *)(lVar7 + 0x20)) break;
                if (uVar13 == 0xfff) {
                  uVar13 = 0x54;
                  goto LAB_002d3e13;
                }
                lVar7 = *(long *)(lVar7 + 8);
                uVar13 = uVar13 + 1;
              } while (lVar7 != lVar1);
            }
            local_40 = lVar7;
            lVar7 = func_0x00c08b50((ulong)uVar13 << 5,0x2bfc080,2);
            param_1[6] = lVar7;
            *(uint *)(param_1 + 7) = uVar13;
            local_90 = param_1[5];
            func_0x002c6c40(lVar1,param_3,&local_40);
            uVar13 = 0;
            if ((local_40 != lVar1) && (*(ulong *)(local_40 + 0x20) < uVar6)) {
              local_80 = param_3;
              if ((*(byte *)(local_40 + 0x60) & 2) == 0) {
                iVar4 = 0;
                local_58 = param_7;
                do {
                  lVar11 = local_40;
                  puVar12 = (ulong *)(local_40 + 0x20);
                  lVar7 = *(long *)(local_40 + 0x50);
                  if (lVar7 == 0) break;
                  lVar14 = (long)iVar4 * 0x20;
                  func_0x00258ff0(param_1[6] + lVar14,0x20);
                  *(ulong *)(param_1[6] + 0x10 + lVar14) = *(long *)(lVar11 + 0x28) - *puVar12;
                  uVar2 = *puVar12;
                  local_80 = param_3;
                  if (param_3 < uVar2) {
                    local_80 = uVar2;
                  }
                  uVar8 = *(ulong *)(lVar11 + 0x28);
                  if (uVar6 <= *(ulong *)(lVar11 + 0x28)) {
                    uVar8 = uVar6;
                  }
                  lVar10 = (local_80 - uVar2) + *(long *)(lVar11 + 0x58);
                  lVar9 = uVar8 - local_80;
                  iVar5 = *(int *)(lVar1 + 0x1c0);
                  func_0x002c64f0(lVar1,0,0);
                  if (*(char *)(lVar7 + 0x9d) == '\v') {
                    uVar13 = 0x2d;
                  }
                  else if ((*(char *)(lVar7 + 0x9d) == '\x03') &&
                          ((*(byte *)(lVar7 + 0xa2) & 1) != 0)) {
                    sub_2d43e0(lVar7,lVar10,lVar9,param_5,param_6,local_58,local_90,
                               lVar14 + param_1[6]);
                    uVar13 = 0;
                    iVar4 = iVar4 + 1;
                  }
                  else {
                    uVar13 = sub_2d4630(lVar7,lVar10,lVar9,param_5,param_6,local_58,local_90,
                                        lVar14 + param_1[6]);
                    iVar4 = iVar4 + (uint)(uVar13 == 0);
                  }
                  if ((*(byte *)(lVar1 + 0x244) & 0x10) == 0) {
                    if ((*(byte *)(lVar1 + 0x244) & 8) != 0) {
                      LOCK();
                      *(int *)(*in_GS_OFFSET + 0x5a8) = *(int *)(*in_GS_OFFSET + 0x5a8) + 1;
                      UNLOCK();
                    }
                    func_0x00c4bb20(lVar1 + 0x170,0,0,0);
                  }
                  else {
                    func_0x004c6a00(lVar1 + 0x1a8,0,0,0);
                  }
                  *(int *)(lVar1 + 0x1c0) = *(int *)(lVar1 + 0x1c0) + 1;
                  LOCK();
                  *(int *)(lVar1 + 0x1c4) = *(int *)(lVar1 + 0x1c4) + 1;
                  UNLOCK();
                  if ((*(int *)(lVar1 + 0x1c0) != iVar5 + 1) &&
                     (iVar5 = func_0x002c6c40(lVar1,local_80,&local_40), lVar11 = local_40,
                     iVar5 == 0)) {
                    func_0x007f1950();
                    func_0x007f18a0(0x2d3f22,local_80);
                    func_0x00c9aa10(0x9f,0x1364b07,local_80);
                    /* WARNING: Does not return */
                    pcVar3 = (code *)invalidInstructionException();
                    (*pcVar3)();
                  }
                  local_40 = *(long *)(lVar11 + 8);
                  local_58 = local_58 + lVar9;
                  if (((uVar13 != 0) || (uVar13 = 0, local_40 == lVar1)) ||
                     (uVar6 <= *(ulong *)(local_40 + 0x20))) goto LAB_002d3e89;
                  local_90 = local_90 + lVar9;
                } while ((*(byte *)(local_40 + 0x60) & 2) == 0);
                uVar13 = 0xd;
              }
              else {
                uVar13 = 0xd;
                local_58 = param_7;
              }
LAB_002d3e89:
              if (param_7 <= local_58 && local_58 - param_7 != 0) {
                if (uVar13 == 0) {
                  func_0x009f03b0(param_6);
                  uVar13 = 0;
                }
                else {
                  func_0x009f03a0(param_6,param_7,local_58 - param_7,1);
                  sub_2d48b0(param_1);
                  func_0x00c08df0(param_1[6],0x2bfc080);
                  param_1[6] = 0;
                  *(undefined4 *)(param_1 + 7) = 0;
                  func_0x008dedb0(param_1[5],local_80 - param_3 >> 0xe);
                  func_0x00503410(param_1[5],param_4);
                  param_1[5] = 0;
                }
              }
            }
          }
          func_0x002c64f0(lVar1,0,0);
        }
      }
      else {
        iVar4 = sub_2d41d0(lVar1,param_3,param_4);
        uVar13 = 0x3f;
        if (iVar4 == 0) goto LAB_002d3a71;
      }
      func_0x002ce900(lVar1,param_3,uVar6,param_5 * 4);
    }
    else if (iVar4 != 1) {
      if (_DAT_0391c310 == local_38) {
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      goto LAB_002d3f1b;
    }
  }
LAB_002d3e3e:
  if (_DAT_0391c310 == local_38) {
    return (ulong)uVar13;
  }
LAB_002d3f1b:
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar3 = (code *)invalidInstructionException();
  (*pcVar3)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d3f60 RVA 0x2d3f60 | Evidence ev_7bf7c8aed3046da19d09e0047bd29a79136a91953f6489dd140cb89cfb51885e | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d3f60", "end": "0x2d41c6"}], "total_bytes": 615, "span_bytes": 615, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_2d3f60(long param_1,long param_2,ulong param_3,long param_4,uint param_5,undefined8 param_6,
              long param_7)

{
  ulong uVar1;
  undefined4 uVar2;
  code *pcVar3;
  int iVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 *puVar7;
  long lVar8;
  long lVar9;
  undefined4 local_44;
  long local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  uVar2 = *(undefined4 *)(param_2 + 0xbc);
  *(undefined4 *)(param_1 + 0x38) = 1;
  puVar7 = (undefined4 *)func_0x00c08b50(0x20,0x2bfc080,2);
  *(undefined4 **)(param_1 + 0x30) = puVar7;
  *puVar7 = uVar2;
  *(ulong *)(puVar7 + 2) = param_3;
  puVar7[6] = 3;
  *(long *)(puVar7 + 4) = param_4;
  lVar8 = func_0x005033b0(param_4);
  *(long *)(param_1 + 0x28) = lVar8;
  if (lVar8 == 0) {
    func_0x00c08df0(*(undefined8 *)(param_1 + 0x30),0x2bfc080);
    iVar4 = 0x23;
  }
  else {
    iVar4 = func_0x00627450();
    if (iVar4 == 0) {
      if (param_3 < param_4 + param_3) {
        lVar9 = 0;
        do {
          local_40 = 0;
          iVar4 = func_0x006288d0(uVar2,param_3 + lVar9,&local_40,&local_44);
          if (iVar4 != 0) {
            iVar4 = 0xd;
            goto LAB_002d4173;
          }
          if (local_40 == 0) {
            func_0x007f1950();
            func_0x007f1810(0x2d419a);
            func_0x00c9aa10(0x9b,0x1289ce2);
                    /* WARNING: Does not return */
            pcVar3 = (code *)invalidInstructionException();
            (*pcVar3)();
          }
          uVar5 = FUN_002d5730(local_44);
          uVar6 = FUN_002d56e0(local_44);
          func_0x008de9e0(lVar8 + lVar9,local_40,uVar6);
          iVar4 = func_0x009f02f0(param_6,local_40,param_7 + lVar9,0x4000,
                                  (param_5 & 0xff) << 5 | 0x10,uVar5,0);
          if (iVar4 != 0) {
            func_0x008dedb0(*(undefined8 *)(param_1 + 0x28),
                            (lVar8 - param_3) + 0x4000 + lVar9 >> 0xe);
            func_0x00503410(*(undefined8 *)(param_1 + 0x28),param_4);
            *(undefined8 *)(param_1 + 0x28) = 0;
            func_0x00c08df0(*(undefined8 *)(param_1 + 0x30),0x2bfc080);
            func_0x009f03a0(param_6,param_7,lVar9,1);
            goto LAB_002d4173;
          }
          uVar1 = param_3 + 0x4000 + lVar9;
          lVar9 = lVar9 + 0x4000;
        } while (uVar1 < param_4 + param_3);
      }
      func_0x009f03b0(param_6);
      iVar4 = 0;
LAB_002d4173:
      func_0x006274c0();
    }
    else {
      func_0x00c08df0(*(undefined8 *)(param_1 + 0x30),0x2bfc080);
      func_0x00503410(*(undefined8 *)(param_1 + 0x28),param_4);
      iVar4 = 0x23;
    }
  }
  if (_DAT_0391c310 == local_38) {
    return iVar4;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar3 = (code *)invalidInstructionException();
  (*pcVar3)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d41d0 RVA 0x2d41d0 | Evidence ev_0426c4e61593f20f5bc36989d9670d374703cb64bb63d489f2bf6faf0f783f54 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d41d0", "end": "0x2d426e"}, {"start": "0x2d4270", "end": "0x2d43de"}], "total_bytes": 526, "span_bytes": 527, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 sub_2d41d0(long *param_1,ulong param_2,long param_3)

{
  int *piVar1;
  uint uVar2;
  long *plVar3;
  ulong uVar4;
  code *pcVar5;
  int iVar6;
  undefined8 uVar7;
  undefined8 uVar8;
  undefined4 uVar9;
  ulong uVar10;
  long *in_GS_OFFSET;
  long *local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  if ((*(byte *)((long)param_1 + 0x244) & 0x10) == 0) {
    if ((*(byte *)((long)param_1 + 0x244) & 8) != 0) {
      LOCK();
      *(int *)(*in_GS_OFFSET + 0x5a8) = *(int *)(*in_GS_OFFSET + 0x5a8) + 1;
      UNLOCK();
    }
    func_0x00c4b350(param_1 + 0x2e,0,0,0);
  }
  else {
    func_0x004c6a00(param_1 + 0x35,0,0,0);
  }
  uVar10 = param_3 + param_2;
  iVar6 = func_0x002c6c40(param_1,param_2,&local_40);
  if (iVar6 == 0) {
LAB_002d436e:
    func_0x007f1950();
    func_0x007f20c0(0x2d436e,param_2,uVar10,param_1);
    uVar7 = 0x129471f;
    uVar8 = 0xa7;
  }
  else {
    uVar9 = 0;
    plVar3 = local_40;
    while( true ) {
      if ((plVar3 == param_1) || (uVar4 = plVar3[4], uVar10 <= uVar4)) {
        if ((*(byte *)((long)param_1 + 0x244) & 0x10) == 0) {
          func_0x00c4c300(param_1 + 0x2e,0,0);
          if ((*(byte *)((long)param_1 + 0x244) & 8) != 0) {
            LOCK();
            piVar1 = (int *)(*in_GS_OFFSET + 0x5a8);
            iVar6 = *piVar1;
            *piVar1 = *piVar1 + -1;
            UNLOCK();
            if (iVar6 == -0x7fffffff) {
              func_0x006b7af0();
            }
          }
          func_0x002c66f0();
        }
        else {
          func_0x004c6fa0(param_1 + 0x35,0,0,0);
        }
        if (_DAT_0391c310 == local_38) {
          return uVar9;
        }
        func_0x006fd6b0();
                    /* WARNING: Does not return */
        pcVar5 = (code *)invalidInstructionException();
        (*pcVar5)();
      }
      if (((param_2 < uVar4) && (uVar4 != *(ulong *)(*plVar3 + 0x28))) ||
         (uVar2 = *(uint *)(plVar3 + 0xc), (uVar2 & 2) != 0)) goto LAB_002d436e;
      if (((int)(uVar2 << 0x1a) >> 0x1f) + *(int *)((long)plVar3 + 0x6c) ==
          (uint)((uVar2 & 0x20000) == 0 & (*(byte *)(plVar3 + 0x28) & 0x20) >> 5)) break;
      if ((plVar3[10] != 0) && ((*(byte *)(plVar3[10] + 0xa2) & 8) != 0)) {
        uVar9 = 1;
      }
      plVar3 = (long *)plVar3[1];
    }
    func_0x007f1950();
    func_0x007f20c0(0x2d439c,plVar3[4],plVar3[5],param_1);
    param_2 = plVar3[4];
    uVar10 = plVar3[5];
    uVar7 = 0x12fb2de;
    uVar8 = 0xa3;
  }
  func_0x00c9aa10(uVar8,uVar7,param_2,uVar10,param_1);
                    /* WARNING: Does not return */
  pcVar5 = (code *)invalidInstructionException();
  (*pcVar5)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d43e0 RVA 0x2d43e0 | Evidence ev_7c017270f9643735f362dacb9fe197bccee2149166d5cdeab068cfc90cf5acf0 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d43e0", "end": "0x2d4486"}, {"start": "0x2d4490", "end": "0x2d4627"}], "total_bytes": 575, "span_bytes": 584, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_2d43e0(long param_1,ulong param_2,long param_3,uint param_4,undefined8 param_5,long param_6
               ,long param_7,ulong *param_8)

{
  ulong uVar1;
  code *pcVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  long lVar6;
  ulong uVar7;
  undefined8 uVar8;
  undefined8 uVar9;
  ulong uVar10;
  long local_70;
  undefined4 local_4c;
  ulong local_48;
  undefined1 local_40 [8];
  long local_38;
  
  local_38 = _DAT_0391c310;
  uVar8 = *(undefined8 *)(*(long *)(param_1 + 0xe8) + 0xa8);
  iVar3 = func_0x003c6560();
  *(undefined4 *)(param_8 + 3) = 1;
  *param_8 = param_2;
  *(int *)(param_8 + 1) = iVar3;
  iVar4 = func_0x003c65d0(iVar3,param_2,param_3);
  if (iVar4 != 0) {
    func_0x007f1950();
    func_0x007f2180(0x2d459a,(long)iVar4,(long)iVar3,param_2,param_3);
    uVar8 = 0x12e6b8d;
    uVar9 = 0x93;
LAB_002d461f:
    func_0x00c9aa10(uVar9,uVar8,iVar4,iVar3,param_2,param_3);
                    /* WARNING: Does not return */
    pcVar2 = (code *)invalidInstructionException();
    (*pcVar2)();
  }
  uVar1 = param_3 + param_2;
  if (param_2 < uVar1) {
    uVar10 = param_2;
    local_70 = param_6;
    do {
      iVar4 = func_0x003c54f0(param_1,uVar10,local_40,&local_48,&local_4c);
      if (iVar4 != 0) goto LAB_002d4567;
      uVar7 = local_48;
      if (uVar1 < local_48) {
        uVar7 = uVar1;
      }
      local_48 = uVar7;
      uVar5 = FUN_002d5730(local_4c);
      lVar6 = func_0x003c36b0(uVar8,uVar10);
      iVar4 = func_0x009f02f0(param_5,lVar6,local_70,uVar7 - uVar10,(param_4 & 0xff) << 5 | 0x10,
                              uVar5,1);
      uVar5 = FUN_002d56e0(local_4c);
      uVar7 = uVar7 - uVar10;
      if (uVar7 != 0) {
        uVar10 = 0;
        do {
          func_0x008de9e0(param_7 + uVar10,lVar6 + uVar10,uVar5);
          uVar10 = uVar10 + 0x4000;
        } while (uVar10 < uVar7);
      }
      local_70 = local_70 + uVar7;
      param_7 = param_7 + uVar7;
      uVar10 = local_48;
    } while (local_48 < uVar1);
    if (iVar4 != 0) {
LAB_002d4567:
      iVar4 = func_0x003c6ad0(iVar3,param_2,param_3);
      if (iVar4 != 0) {
        func_0x007f1950();
        func_0x007f2180(0x2d45dd,(long)iVar4,(long)iVar3,param_2,param_3);
        uVar8 = 0x12dc986;
        uVar9 = 0x97;
        goto LAB_002d461f;
      }
    }
  }
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar2 = (code *)invalidInstructionException();
    (*pcVar2)();
  }
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d4630 RVA 0x2d4630 | Evidence ev_20f1d0109105b092eb59a726b21c0c1075a130b881a908dee6a76e41fc13026a | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d4630", "end": "0x2d48a9"}], "total_bytes": 634, "span_bytes": 634, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_2d4630(long param_1,long param_2,long param_3,uint param_4,undefined8 param_5,long param_6,
              long param_7,long param_8)

{
  undefined8 uVar1;
  code *pcVar2;
  undefined4 uVar3;
  int iVar4;
  long lVar5;
  long lVar6;
  long lVar7;
  ulong uVar8;
  long local_60;
  long local_40;
  long local_38;
  
  lVar7 = param_1 + 0x18;
  uVar8 = param_2 >> 0xe;
  local_38 = _DAT_0391c310;
  *(undefined4 *)(param_8 + 0x18) = 2;
  func_0x007d50c0(lVar7,0,0);
  lVar5 = func_0x00b897e0(param_1,uVar8);
  if (lVar5 == 0) {
    iVar4 = 0xd;
    local_40 = lVar5;
  }
  else {
    local_60 = param_7;
    lVar6 = lVar5;
    do {
      local_40 = lVar6;
      if (uVar8 != *(ulong *)(lVar6 + 0x28)) goto LAB_002d47f9;
      func_0x004c6a00((*(uint *)(lVar6 + 0x30) >> 0xf & 0x3fc0) + 0x3d7c458,0,0,0);
      func_0x00b8ca20(local_40);
      func_0x004c6fa0((*(uint *)(local_40 + 0x30) >> 0xf & 0x3fc0) + 0x3d7c458,0,0,0);
      uVar3 = 0x412;
      if ((*(long *)(local_40 + 0x20) != 0) &&
         (*(char *)(*(long *)(local_40 + 0x20) + 0x9d) == '\n')) {
        uVar3 = func_0x0091bc90();
        uVar3 = FUN_002d5730(uVar3);
      }
      uVar1 = *(undefined8 *)(local_40 + 0x30);
      func_0x007d56e0(lVar7,0,0);
      func_0x008dec80(local_60,&local_40,1);
      iVar4 = func_0x009f02f0(param_5,uVar1,param_6,0x4000,(param_4 & 0xff) << 5 | 0x10,uVar3,0);
      func_0x007d50c0(lVar7,0,0);
      lVar6 = local_40;
      if (iVar4 != 0) goto joined_r0x002d4816;
      uVar8 = uVar8 + 1;
      if ((ulong)(param_3 + param_2 >> 0xe) <= uVar8) {
        iVar4 = 0;
        goto LAB_002d4874;
      }
      local_60 = local_60 + 0x4000;
      param_6 = param_6 + 0x4000;
      local_40 = *(long *)(local_40 + 0x10);
      lVar6 = local_40;
    } while (local_40 != 0);
    lVar6 = 0;
LAB_002d47f9:
    iVar4 = 0xd;
joined_r0x002d4816:
    if (lVar5 != lVar6) {
      do {
        func_0x004c6a00((*(uint *)(lVar5 + 0x30) >> 0xf & 0x3fc0) + 0x3d7c458,0,0,0);
        func_0x00b8ca70(lVar5);
        func_0x004c6fa0((*(uint *)(lVar5 + 0x30) >> 0xf & 0x3fc0) + 0x3d7c458,0,0);
        lVar5 = *(long *)(lVar5 + 0x10);
      } while (lVar5 != local_40);
    }
  }
LAB_002d4874:
  func_0x007d56e0(lVar7,0,0);
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar2 = (code *)invalidInstructionException();
    (*pcVar2)();
  }
  return iVar4;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d48b0 RVA 0x2d48b0 | Evidence ev_958cf6f270fb36e144ea86cd88afa650ae9ef7fc85597cb07fbf91d3697461cb | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d48b0", "end": "0x2d48e6"}, {"start": "0x2d48f0", "end": "0x2d4957"}, {"start": "0x2d4960", "end": "0x2d4a1d"}], "total_bytes": 349, "span_bytes": 366, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_2d48b0(long param_1)

{
  long lVar1;
  int iVar2;
  int iVar3;
  long lVar4;
  code *pcVar5;
  long lVar6;
  uint uVar7;
  ulong uVar8;
  long lVar9;
  long lVar10;
  long local_38;
  
  iVar2 = *(int *)(param_1 + 0x38);
  if (0 < (long)iVar2) {
    lVar4 = *(long *)(param_1 + 0x30);
    local_38 = *(long *)(param_1 + 0x28);
    lVar9 = 0;
    do {
      lVar1 = lVar4 + lVar9 * 0x20;
      iVar3 = *(int *)(lVar4 + 0x18 + lVar9 * 0x20);
      if (iVar3 == 1) {
        sub_2d6a30();
      }
      else if (iVar3 != 3) {
        if (iVar3 != 2) {
          func_0x007f1950();
          func_0x007f18a0(0x2d49ed,(long)*(int *)(lVar1 + 0x18));
          func_0x00c9aa10(0x8f,0x1383655,*(undefined4 *)(lVar1 + 0x18));
                    /* WARNING: Does not return */
          pcVar5 = (code *)invalidInstructionException();
          (*pcVar5)();
        }
        uVar7 = (uint)(*(ulong *)(lVar1 + 0x10) >> 0xe);
        if (0 < (int)uVar7) {
          uVar8 = (ulong)(uVar7 & 0x7fffffff);
          lVar10 = local_38;
          do {
            lVar6 = func_0x008de330(lVar10);
            if (lVar6 != 0) {
              lVar6 = func_0x00b89290(lVar6);
              func_0x004c6a00((*(uint *)(lVar6 + 0x30) >> 0xf & 0x3fc0) + 0x3d7c458,0,0,0);
              func_0x00b8ca70(lVar6);
              func_0x004c6fa0((*(uint *)(lVar6 + 0x30) >> 0xf & 0x3fc0) + 0x3d7c458,0,0);
            }
            lVar10 = lVar10 + 0x4000;
            uVar8 = uVar8 - 1;
          } while (uVar8 != 0);
        }
      }
      lVar9 = lVar9 + 1;
      local_38 = local_38 + *(long *)(lVar1 + 0x10);
    } while (lVar9 != iVar2);
  }
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d4a2a RVA 0x2d4a2a | Evidence ev_a5d840c1b8a9fc9f2c2ff0ac78d5759d3526572ca6f6b02a916d1b8ce9c24f6e | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d4a2a", "end": "0x2d4aa2"}], "total_bytes": 121, "span_bytes": 121, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_2d4a2a(long param_1)

{
  ulong uVar1;
  
  uVar1 = *(ulong *)(param_1 + 0x10);
  func_0x009f03a0(*(undefined8 *)(param_1 + 0x18),*(undefined8 *)(param_1 + 0x20),uVar1,1);
  sub_2d48b0(param_1);
  func_0x00c08df0(*(undefined8 *)(param_1 + 0x30),0x2bfc080);
  *(undefined8 *)(param_1 + 0x30) = 0;
  *(undefined4 *)(param_1 + 0x38) = 0;
  func_0x008dedb0(*(undefined8 *)(param_1 + 0x28),uVar1 >> 0xe);
  func_0x00503410(*(undefined8 *)(param_1 + 0x28),uVar1);
  *(undefined8 *)(param_1 + 0x28) = 0;
  return 0;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d4ab0 RVA 0x2d4ab0 | Evidence ev_450eb7a5c2a83d6ffe9c61e291a52555161f6c64b1f01c4dfe8dfdda4e5876c7 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d4ab0", "end": "0x2d4c30"}], "total_bytes": 385, "span_bytes": 385, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 sub_2d4ab0(long param_1,ulong param_2,undefined4 *param_3)

{
  byte bVar1;
  long lVar2;
  long lVar3;
  code *pcVar4;
  int iVar5;
  undefined4 uVar6;
  long *in_GS_OFFSET;
  long local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  uVar6 = 0x2d;
  if ((uint)(param_2 >> 0x28) < 0xf) {
    if (param_2 >> 0x2b != 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    lVar2 = *(long *)(param_1 + 0x200);
    if ((*(byte *)(lVar2 + 0x244) & 0x10) == 0) {
      if ((*(byte *)(lVar2 + 0x244) & 8) != 0) {
        LOCK();
        *(int *)(*in_GS_OFFSET + 0x5a8) = *(int *)(*in_GS_OFFSET + 0x5a8) + 1;
        UNLOCK();
      }
      func_0x00c4bb20(lVar2 + 0x170,0,0,0);
    }
    else {
      func_0x004c6a00(lVar2 + 0x1a8,0,0,0);
    }
    *(int *)(lVar2 + 0x1c0) = *(int *)(lVar2 + 0x1c0) + 1;
    LOCK();
    *(int *)(lVar2 + 0x1c4) = *(int *)(lVar2 + 0x1c4) + 1;
    UNLOCK();
    iVar5 = func_0x002c6c40(lVar2,param_2,&local_40);
    if (iVar5 == 0) {
      uVar6 = 2;
    }
    else {
      uVar6 = 0x2d;
      if (((*(byte *)(local_40 + 0x60) & 2) == 0) &&
         (lVar3 = *(long *)(local_40 + 0x50), lVar3 != 0)) {
        bVar1 = *(byte *)(lVar3 + 0x9d);
        if (bVar1 < 2) {
          if ((*(byte *)(lVar3 + 0xa2) & 2) == 0) {
            uVar6 = *(undefined4 *)(param_1 + 0xbc);
          }
          else {
            uVar6 = *(undefined4 *)(lVar3 + 0x14c);
          }
          *param_3 = uVar6;
          uVar6 = 0;
        }
        else if (bVar1 == 3) {
          if ((*(byte *)(lVar3 + 0xa2) & 1) != 0) {
            uVar6 = func_0x003c5730(lVar3,(param_2 - *(long *)(local_40 + 0x20)) +
                                          *(long *)(local_40 + 0x58));
          }
        }
        else if (bVar1 == 10) {
          *param_3 = *(undefined4 *)(lVar3 + 0x14c);
          uVar6 = 0;
        }
      }
    }
    func_0x002c64f0(lVar2,0,0);
  }
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar4 = (code *)invalidInstructionException();
    (*pcVar4)();
  }
  return uVar6;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d4c40 RVA 0x2d4c40 | Evidence ev_7f019765320a7a6466788b8146f12929adb74eea4b6ca45017e4232d60267db4 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d4c40", "end": "0x2d4cab"}], "total_bytes": 108, "span_bytes": 108, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined4 sub_2d4c40(int param_1)

{
  undefined8 *puVar1;
  undefined4 uVar2;
  
  uVar2 = 0;
  func_0x00c4b350(0x3589e60,0,0,0);
  puVar1 = (undefined8 *)&DAT_03589e80;
  do {
    puVar1 = (undefined8 *)*puVar1;
    if (puVar1 == (undefined8 *)0x0) goto LAB_002d4c95;
  } while (*(int *)(*(long *)(puVar1[0x40] + 0x1d8) + 0x27c) != param_1);
  uVar2 = *(undefined4 *)((long)puVar1 + 0xbc);
LAB_002d4c95:
  func_0x00c4c300(0x3589e60,0,0);
  return uVar2;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d4cb0 RVA 0x2d4cb0 | Evidence ev_156b4ac25742868824177ab5ed88e98ef7fa2fad5c43875bbcc1bcfd3f70cdc4 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d4cb0", "end": "0x2d4cf6"}, {"start": "0x2d4d00", "end": "0x2d4d87"}, {"start": "0x2d4d90", "end": "0x2d4e5d"}], "total_bytes": 413, "span_bytes": 430, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_2d4cb0(long param_1)

{
  ushort uVar1;
  undefined8 uVar2;
  code *pcVar3;
  int iVar4;
  long lVar5;
  long *in_GS_OFFSET;
  long local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  lVar5 = *(long *)(param_1 + 8);
  local_40 = lVar5;
  if (lVar5 != param_1) {
    do {
      local_40 = lVar5;
      if ((*(uint *)(lVar5 + 0x60) & 0x40100) == 0) {
LAB_002d4dd4:
        uVar1 = *(ushort *)(lVar5 + 100);
        if ((uVar1 & 0x3c7) != 0) {
          func_0x008df6a0(*(undefined8 *)(param_1 + 0x1d8),*(undefined8 *)(lVar5 + 0x20),
                          *(undefined8 *)(lVar5 + 0x28));
          uVar1 = *(ushort *)(lVar5 + 100);
        }
        if ((uVar1 & 0x30) != 0) {
          pcVar3 = *(code **)(_DAT_01a962e8 + 0x18);
          if (2 < (-(long)pcVar3 + 0x26bf10U >> 3 | -(long)pcVar3 << 0x3d)) {
            func_0x0044f8c0(0x1a960f0,pcVar3);
          }
          (*pcVar3)(param_1,*(long *)(lVar5 + 0x20),
                    *(long *)(lVar5 + 0x28) - *(long *)(lVar5 + 0x20));
        }
      }
      else {
        *(uint *)(lVar5 + 0x60) = *(uint *)(lVar5 + 0x60) | 0x200;
        uVar2 = *(undefined8 *)(lVar5 + 0x20);
        iVar4 = *(int *)(param_1 + 0x1c0);
        func_0x002c6d80(param_1,0,0,0);
        if ((*(byte *)(param_1 + 0x244) & 0x10) == 0) {
          if ((*(byte *)(param_1 + 0x244) & 8) != 0) {
            LOCK();
            *(int *)(*in_GS_OFFSET + 0x5a8) = *(int *)(*in_GS_OFFSET + 0x5a8) + 1;
            UNLOCK();
          }
          func_0x00c4bb20(param_1 + 0x170,0,0);
        }
        else {
          func_0x004c6a00(param_1 + 0x1a8,0,0);
        }
        *(int *)(param_1 + 0x1c0) = *(int *)(param_1 + 0x1c0) + 1;
        LOCK();
        *(int *)(param_1 + 0x1c4) = *(int *)(param_1 + 0x1c4) + 1;
        UNLOCK();
        if (iVar4 + 1 == *(int *)(param_1 + 0x1c0)) goto LAB_002d4dd4;
        iVar4 = func_0x002c6c40(param_1,uVar2,&local_40);
        lVar5 = local_40;
        if (iVar4 != 0) goto LAB_002d4dd4;
      }
      lVar5 = *(long *)(lVar5 + 8);
      local_40 = lVar5;
    } while (lVar5 != param_1);
  }
  if (_DAT_0391c310 == local_38) {
    return;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar3 = (code *)invalidInstructionException();
  (*pcVar3)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d4e60 RVA 0x2d4e60 | Evidence ev_9dafa2640411492ba264bc55049d178ee48037f3531800bf9ae3ee1232c90b13 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d4e60", "end": "0x2d4e96"}, {"start": "0x2d4ea0", "end": "0x2d4f5a"}, {"start": "0x2d4f60", "end": "0x2d4fb6"}], "total_bytes": 329, "span_bytes": 343, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_2d4e60(long param_1)

{
  undefined8 uVar1;
  ulong uVar2;
  long lVar3;
  long lVar4;
  long lVar5;
  long lVar6;
  ulong uVar7;
  
  lVar5 = *(long *)(param_1 + 8);
  if (lVar5 != param_1) {
    uVar7 = *(ulong *)(lVar5 + 0x20);
    uVar1 = *(undefined8 *)(param_1 + 0x1d8);
    do {
      uVar2 = *(ulong *)(lVar5 + 0x20);
      if (uVar7 < uVar2) {
        func_0x008e46d0(uVar1,uVar7,uVar2,0,0,0,0);
      }
      lVar3 = *(long *)(lVar5 + 0x58);
      lVar4 = *(long *)(lVar5 + 0x50);
      lVar6 = lVar5;
      do {
        uVar7 = *(ulong *)(lVar6 + 0x28);
        lVar6 = *(long *)(lVar6 + 8);
        if (((*(ulong *)(lVar6 + 0x20) != uVar7) || (*(long *)(lVar6 + 0x50) != lVar4)) ||
           (*(long *)(lVar6 + 0x58) != (lVar3 - uVar2) + uVar7)) break;
      } while (*(short *)(lVar6 + 100) == *(short *)(lVar5 + 100));
      if ((lVar4 == 0) || (*(char *)(lVar4 + 0x9d) != '\v')) {
        func_0x008e46d0(uVar1,uVar2,uVar7,lVar4,lVar3,*(short *)(lVar5 + 100),
                        *(uint *)(lVar5 + 0x140) >> 3 & 1,lVar3);
        if (((*(byte *)(lVar5 + 0x62) & 2) == 0) || (*(int *)(lVar5 + 0x6c) != 0)) {
          func_0x002cbad0(param_1,uVar2,uVar7);
        }
      }
      else {
        func_0x009a7f30(param_1,uVar2,uVar7);
      }
      lVar5 = lVar6;
    } while (lVar6 != param_1);
  }
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d4fc0 RVA 0x2d4fc0 | Evidence ev_09d0b31bd1a98cc82d3daef4669ae4b4a65b992e6280806171fc6e5f19c5ed6b | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d4fc0", "end": "0x2d500c"}, {"start": "0x2d5010", "end": "0x2d5113"}, {"start": "0x2d5120", "end": "0x2d5191"}, {"start": "0x2d51a0", "end": "0x2d5267"}, {"start": "0x2d5270", "end": "0x2d5311"}], "total_bytes": 813, "span_bytes": 850, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Possible PIC construction at 0x002d5084: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x002d5089) */
/* WARNING: Removing unreachable block (ram,0x002d50c9) */
/* WARNING: Removing unreachable block (ram,0x002d50a0) */
/* WARNING: Removing unreachable block (ram,0x002d50a4) */
/* WARNING: Removing unreachable block (ram,0x002d50b5) */
/* WARNING: Removing unreachable block (ram,0x002d50db) */
/* WARNING: Removing unreachable block (ram,0x002d50fc) */
/* WARNING: Removing unreachable block (ram,0x002d5131) */
/* WARNING: Removing unreachable block (ram,0x002d513f) */
/* WARNING: Removing unreachable block (ram,0x002d51a0) */
/* WARNING: Removing unreachable block (ram,0x002d516c) */
/* WARNING: Removing unreachable block (ram,0x002d5170) */
/* WARNING: Removing unreachable block (ram,0x002d5181) */
/* WARNING: Removing unreachable block (ram,0x002d51af) */
/* WARNING: Removing unreachable block (ram,0x002d51cb) */
/* WARNING: Removing unreachable block (ram,0x002d51e6) */
/* WARNING: Removing unreachable block (ram,0x002d51f0) */
/* WARNING: Removing unreachable block (ram,0x002d51fd) */
/* WARNING: Removing unreachable block (ram,0x002d520f) */
/* WARNING: Removing unreachable block (ram,0x002d521e) */
/* WARNING: Removing unreachable block (ram,0x002d5120) */
/* WARNING: Removing unreachable block (ram,0x002d5270) */
/* WARNING: Removing unreachable block (ram,0x002d52cc) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_2d4fc0(int param_1)

{
  undefined8 *puVar1;
  undefined8 *puVar2;
  code *pcVar3;
  long lVar4;
  
  lVar4 = _DAT_0391c310;
  func_0x00c4b350(0x3589e60,0,0,0);
  puVar2 = _DAT_03589e80;
  while( true ) {
    if (puVar2 == (undefined8 *)0x0) {
      if (_DAT_0391c310 == lVar4) {
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      func_0x006fd6b0();
                    /* WARNING: Does not return */
      pcVar3 = (code *)invalidInstructionException();
      (*pcVar3)();
    }
    puVar1 = puVar2 + 0x29;
    func_0x004c6a00(puVar1,0,0);
    if ((*(int *)(puVar2 + 0xb8) != param_1) && ((*(uint *)(puVar2 + 0x16) & 0x2000) == 0)) break;
    func_0x004c6fa0(puVar1,0,0,0);
    puVar2 = (undefined8 *)*puVar2;
  }
  *(int *)(puVar2 + 0x6b) = *(int *)(puVar2 + 0x6b) + 1;
  if ((*(uint *)(puVar2 + 0x16) & 0x10000000) == 0) {
    func_0x0053aa10(puVar2);
  }
  func_0x004c6fa0(puVar1,0,0,0);
  halt_baddata();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d5320 RVA 0x2d5320 | Evidence ev_8343c217c4f601487030ba31cdf680c48366ed0db5256edcf6fa2d6fdb2da36e | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d5320", "end": "0x2d56d8"}], "total_bytes": 953, "span_bytes": 953, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_2d5320(long param_1,long param_2,long *param_3,long param_4,long param_5)

{
  ushort uVar1;
  long lVar2;
  undefined8 uVar3;
  ulong uVar4;
  code *pcVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  int iVar8;
  undefined8 uVar9;
  long lVar10;
  long lVar11;
  long lVar12;
  ulong uVar13;
  ulong uVar14;
  long *plVar15;
  ulong uVar16;
  long local_58;
  long local_48;
  
  lVar2 = *(long *)(param_1 + 0x10);
  if (param_3[10] == 0) {
    lVar12 = 0;
  }
  else {
    lVar12 = param_3[0xb];
  }
  uVar3 = *(undefined8 *)(lVar2 + 0x40);
  uVar14 = param_4 - (*(long *)(param_1 + 0x30) - 1U & (param_4 - param_3[4]) + lVar12);
  uVar13 = *(long *)(param_1 + 0x30) + uVar14;
  local_58 = func_0x003c36b0(lVar2,param_5);
  do {
    plVar15 = param_3;
    param_3 = (long *)*plVar15;
    if (param_3 == (long *)param_2) break;
  } while (uVar14 < (ulong)param_3[5]);
  uVar9 = func_0x002c76c0(param_2,uVar14,uVar13,param_3);
  if ((int)uVar9 == 0) {
    func_0x00500bb0(uVar3,param_2,uVar14,uVar13,param_5);
    local_48 = param_5;
    if ((ulong)plVar15[4] < uVar14) {
      func_0x002cb4e0(param_2,plVar15);
    }
    while( true ) {
      uVar4 = plVar15[5];
      uVar16 = uVar13;
      if (uVar4 < uVar13) {
        uVar16 = uVar4;
      }
      if (uVar13 < uVar4) {
        func_0x002cb770(param_2,plVar15,uVar13);
      }
      uVar7 = *(undefined4 *)((long)plVar15 + 0x144);
      uVar1 = *(ushort *)(plVar15 + 0x29);
      lVar10 = uVar16 - uVar14;
      lVar11 = func_0x002c7210(param_2);
      *(ulong *)(lVar11 + 0x20) = uVar14;
      *(ulong *)(lVar11 + 0x28) = uVar16;
      *(undefined8 *)(lVar11 + 0x70) = 0;
      *(uint *)(lVar11 + 0x60) = *(uint *)(plVar15 + 0xc) & 0x800000 | 0x100000;
      *(undefined8 *)(lVar11 + 0x50) = uVar3;
      *(long *)(lVar11 + 0x58) = local_48;
      *(undefined8 *)(lVar11 + 0x30) = 0;
      *(ushort *)(lVar11 + 100) = uVar1;
      *(undefined4 *)(lVar11 + 0x66) = 0x30203f3;
      *(undefined4 *)(lVar11 + 0x6c) = 0;
      *(undefined8 *)(lVar11 + 0x78) = 0;
      *(ulong *)(lVar11 + 0x38) = uVar14;
      *(undefined1 *)(lVar11 + 0x14c) = *(undefined1 *)((long)plVar15 + 0x14c);
      *(undefined1 *)(lVar11 + 0x14d) = *(undefined1 *)((long)plVar15 + 0x14d);
      func_0x00259be0(plVar15 + 0x2a,lVar11 + 0x150,0x20);
      *(undefined1 *)(lVar11 + 0x14e) = *(undefined1 *)((long)plVar15 + 0x14e);
      *(long *)(lVar11 + 0x130) = plVar15[0x26];
      *(undefined8 *)(lVar11 + 0x120) = 0;
      *(long *)(lVar11 + 0x128) = param_1;
      *(undefined4 *)(lVar11 + 0x144) = uVar7;
      *(ushort *)(lVar11 + 0x148) = uVar1;
      *(long *)(lVar11 + 0x138) = plVar15[0x27];
      *(undefined4 *)(lVar11 + 0x140) = 0;
      func_0x00461b20(*(undefined8 *)(lVar11 + 0x50));
      func_0x003c3430(lVar2);
      func_0x003c9f70(param_1);
      func_0x003c3580(lVar2);
      lVar12 = *plVar15;
      func_0x002cfe30(param_2,plVar15);
      func_0x002c72e0(param_2,lVar12,lVar11);
      *(long *)(param_2 + 0x1b8) = *(long *)(param_2 + 0x1b8) + lVar10;
      if ((uVar1 & 0x3c7) != 0) {
        uVar9 = *(undefined8 *)(param_2 + 0x1d8);
        uVar6 = FUN_002d56e0(uVar7);
        func_0x008ed820(uVar9,uVar14,uVar16,local_58,uVar1,uVar6);
      }
      if ((uVar1 & 0x30) != 0) {
        uVar7 = FUN_002d5730(uVar7);
        pcVar5 = *(code **)(_DAT_01a962e8 + 0x10);
        if (pcVar5 != (code *)0x26e8d0) {
          func_0x0044f8c0(0x1a96110,pcVar5);
        }
        iVar8 = (*pcVar5)(param_2,uVar14,lVar10,local_58,uVar1 & 0x30,uVar7,1);
        if (iVar8 != 0) {
          func_0x007f1950();
          func_0x007f18a0(0x2d56ac,(long)iVar8);
          func_0x00c9aa10(0xab,0x13105fe,iVar8);
                    /* WARNING: Does not return */
          pcVar5 = (code *)invalidInstructionException();
          (*pcVar5)();
        }
      }
      func_0x002c8910(param_2,lVar11);
      if (uVar13 <= uVar4) break;
      plVar15 = *(long **)(lVar11 + 8);
      local_58 = local_58 + lVar10;
      local_48 = local_48 + lVar10;
      uVar14 = uVar16;
    }
    uVar9 = 0;
  }
  return uVar9;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): FUN_002d56e0 RVA 0x2d56e0 | Evidence ev_6d833c36a197c0d32ffa042efe81992ae13850a82fdfa82ab6d6ff7e78a1600b | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d56e0", "end": "0x2d56f1"}], "total_bytes": 18, "span_bytes": 18, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined4 FUN_002d56e0(uint param_1)

{
  code *pcVar1;
  
  if (param_1 < 0x15) {
    return *(undefined4 *)((ulong)param_1 * 4 + 0x13bc1c0);
  }
  func_0x007f1950();
  func_0x007f18a0(sub_2d56f2,(long)(int)param_1);
  func_0x00c9aa10(3,0x12947a2,param_1);
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d56f2 RVA 0x2d56f2 | Evidence ev_7d6cab91e99dfc940c8937bfe07fbdd343edfc55b9cddc9cb7acbc0de2996956 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d56f2", "end": "0x2d5724"}], "total_bytes": 51, "span_bytes": 51, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_2d56f2(int param_1)

{
  code *pcVar1;
  
  func_0x007f1950();
  func_0x007f18a0(sub_2d56f2,(long)param_1);
  func_0x00c9aa10(3,0x12947a2,param_1);
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): FUN_002d5730 RVA 0x2d5730 | Evidence ev_b9335666faf917a183babd4a97968ac2ba006f30965ab5e474b6909a91faa08e | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d5730", "end": "0x2d5741"}], "total_bytes": 18, "span_bytes": 18, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined4 FUN_002d5730(uint param_1)

{
  code *pcVar1;
  
  if (param_1 < 0x15) {
    return *(undefined4 *)((ulong)param_1 * 4 + 0x13bc214);
  }
  func_0x007f1950();
  func_0x007f18a0(sub_2d5742,(long)(int)param_1);
  func_0x00c9aa10(0xb,0x12947a2,param_1);
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d5742 RVA 0x2d5742 | Evidence ev_914d4b46a47fc331021e4b9b22fd0923dc88138d471e36e90a48f8d878352571 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d5742", "end": "0x2d5774"}], "total_bytes": 51, "span_bytes": 51, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_2d5742(int param_1)

{
  code *pcVar1;
  
  func_0x007f1950();
  func_0x007f18a0(sub_2d5742,(long)param_1);
  func_0x00c9aa10(0xb,0x12947a2,param_1);
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d5780 RVA 0x2d5780 | Evidence ev_122e9a6b1364a98c1ff890f55070d427d6f651ec5f813fac7b8588b389a4a1c3 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d5780", "end": "0x2d582d"}, {"start": "0x2d5830", "end": "0x2d5aa8"}], "total_bytes": 807, "span_bytes": 809, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_2d5780(long param_1,ulong param_2,ulong param_3)

{
  long *plVar1;
  undefined2 uVar2;
  uint uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  ulong uVar6;
  long lVar7;
  undefined8 uVar8;
  ulong uVar9;
  code *pcVar10;
  int iVar11;
  long lVar12;
  undefined8 uVar13;
  long lVar14;
  long *in_GS_OFFSET;
  long local_68;
  long local_60;
  char local_58 [32];
  long local_38;
  
  local_38 = _DAT_0391c310;
  if ((*(byte *)(param_1 + 0x244) & 0x10) == 0) {
    if ((*(byte *)(param_1 + 0x244) & 8) != 0) {
      LOCK();
      *(int *)(*in_GS_OFFSET + 0x5a8) = *(int *)(*in_GS_OFFSET + 0x5a8) + 1;
      UNLOCK();
    }
    func_0x00c4bb20(param_1 + 0x170,0,0,0);
  }
  else {
    func_0x004c6a00(param_1 + 0x1a8,0,0,0);
  }
  *(int *)(param_1 + 0x1c0) = *(int *)(param_1 + 0x1c0) + 1;
  LOCK();
  *(int *)(param_1 + 0x1c4) = *(int *)(param_1 + 0x1c4) + 1;
  UNLOCK();
  iVar11 = func_0x002c6c40(param_1,param_2,&local_68);
  if (iVar11 == 0) {
    local_68 = *(long *)(local_68 + 8);
  }
  lVar12 = local_68;
  if (local_68 != param_1) {
    do {
      uVar6 = *(ulong *)(lVar12 + 0x20);
      lVar14 = local_68;
      if (param_3 < uVar6 || param_3 - uVar6 == 0) break;
      if (((*(long *)(lVar12 + 0x128) != 0) && (*(long *)(lVar12 + 0x50) != 0)) &&
         ((*(byte *)(*(long *)(lVar12 + 0x50) + 0xa2) & 1) != 0)) {
        lVar7 = *(long *)(*(long *)(lVar12 + 0x128) + 0x30);
        if (((uVar6 <= param_2 && param_2 - uVar6 != 0) && ((lVar7 - 1U & param_2 - uVar6) != 0)) ||
           ((param_3 < *(ulong *)(lVar12 + 0x28) && ((lVar7 - 1U & param_3 - uVar6) != 0)))) {
          func_0x002c64f0(param_1,0,0);
          uVar13 = 1;
          goto LAB_002d5a4a;
        }
      }
      plVar1 = (long *)(lVar12 + 8);
      lVar12 = *plVar1;
    } while (*plVar1 != param_1);
    do {
      uVar6 = *(ulong *)(lVar14 + 0x20);
      local_60 = lVar14;
      if (param_3 <= uVar6) break;
      lVar12 = *(long *)(lVar14 + 0x128);
      if (((lVar12 != 0) && (*(long *)(lVar14 + 0x50) != 0)) &&
         ((*(byte *)(*(long *)(lVar14 + 0x50) + 0xa2) & 1) != 0)) {
        uVar13 = *(undefined8 *)(lVar12 + 0x10);
        uVar3 = *(uint *)(lVar14 + 0x60);
        uVar8 = *(undefined8 *)(lVar14 + 0x130);
        uVar9 = *(ulong *)(lVar14 + 0x28);
        uVar4 = *(undefined4 *)(lVar14 + 0x144);
        uVar2 = *(undefined2 *)(lVar14 + 0x148);
        uVar5 = *(undefined4 *)(lVar14 + 0x138);
        func_0x00259be0(lVar14 + 0x150,local_58,0x20);
        func_0x003c3430(uVar13);
        func_0x003c9f70(lVar12);
        func_0x003c3580(uVar13);
        func_0x002c9370(param_1,uVar6,uVar9);
        func_0x002c79f0(param_1,0,0,uVar6,uVar9,0,0,(uVar3 >> 5 & 0x40000) + 1,uVar8,uVar5,lVar12,
                        uVar4,uVar2);
        iVar11 = func_0x002c6c40(param_1,uVar6,&local_60);
        lVar14 = local_60;
        if (iVar11 == 0) {
          func_0x007f1950();
          func_0x007f2010(0x2d5a6c,uVar6,uVar9);
          func_0x00c9aa10(0xaf,0x12b317b,uVar6,uVar9);
                    /* WARNING: Does not return */
          pcVar10 = (code *)invalidInstructionException();
          (*pcVar10)();
        }
        if (local_58[0] != '\0') {
          if (*(ulong *)(local_60 + 0x20) < uVar6) {
            func_0x002cb4e0(param_1,local_60,uVar6);
          }
          if (uVar9 < *(ulong *)(lVar14 + 0x28)) {
            func_0x002cb770(param_1,lVar14);
          }
          func_0x00259be0(local_58,lVar14 + 0x150,0x20);
          func_0x002c8910(param_1,lVar14);
        }
      }
      local_60 = *(long *)(lVar14 + 8);
      lVar14 = local_60;
    } while (local_60 != param_1);
  }
  uVar13 = 0;
  func_0x002c64f0(param_1,0,0);
LAB_002d5a4a:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar10 = (code *)invalidInstructionException();
    (*pcVar10)();
  }
  return uVar13;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d5ab0 RVA 0x2d5ab0 | Evidence ev_0d541ec231962c90608b58b998fcf2e645df64af0907aadbda13dc524bc57cdc | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d5ab0", "end": "0x2d5b46"}], "total_bytes": 151, "span_bytes": 151, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_2d5ab0(undefined4 param_1)

{
  long lVar1;
  long lVar2;
  
  func_0x004c6a00(0x2d60028,0,0,0);
  lVar1 = (long)_DAT_02d60a30 * 0x280;
  lVar2 = lVar1 + 0x2d60030;
  if (*(int *)(lVar1 + 0x2d60030) != 0) {
    if (*(int *)(lVar1 + 0x2d600d0) == 0) {
      lVar2 = lVar1 + 0x2d600d0;
    }
    else if (*(int *)(lVar1 + 0x2d60170) == 0) {
      lVar2 = lVar1 + 0x2d60170;
    }
    else {
      if (*(int *)(lVar1 + 0x2d60210) != 0) {
        halt_baddata();
      }
      lVar2 = lVar1 + 0x2d60210;
    }
  }
  func_0x00614aa0(lVar2);
  *(undefined4 *)(lVar2 + 0x98) = param_1;
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d5b66 RVA 0x2d5b66 | Evidence ev_11d062469fb1c183627f98c99b3fbe909ab4a6303daff9c0b454dc9c0cdd431e | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d5b66", "end": "0x2d5bca"}], "total_bytes": 101, "span_bytes": 101, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_2d5b66(void)

{
  ulong uVar1;
  ulong uVar2;
  ulong uVar3;
  
  uVar1 = func_0x00ad0990();
  uVar3 = rdtsc();
  if ((uVar3 & 0xffffffff00000000 | uVar1) >> 0x20 == 0) {
    uVar2 = (uVar3 & 0xffffffff) / (uVar1 & 0xffffffff);
    uVar3 = (uVar3 & 0xffffffff) % (uVar1 & 0xffffffff);
  }
  else {
    uVar2 = uVar3 / uVar1;
    uVar3 = uVar3 % uVar1;
  }
  uVar3 = uVar3 * 1000;
  if ((uVar1 | uVar3) >> 0x20 == 0) {
    uVar3 = (uVar3 & 0xffffffff) / (uVar1 & 0xffffffff);
  }
  else {
    uVar3 = uVar3 / uVar1;
  }
  func_0x0025d410(0x1325a28,uVar2,uVar3);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d5bd0 RVA 0x2d5bd0 | Evidence ev_33ca57ab0d504b4039d74554ccfa10153baaeb73a028f145e076f4710f9d3835 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d5bd0", "end": "0x2d5ca2"}], "total_bytes": 211, "span_bytes": 211, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_2d5bd0(void)

{
  code *pcVar1;
  int iVar2;
  long in_RCX;
  long *in_GS_OFFSET;
  long local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  iVar2 = *(int *)(*(long *)(*in_GS_OFFSET + 8) + 0x5c0);
  if (iVar2 == 10) {
    iVar2 = 0;
  }
  func_0x004c6a00(0x2d58468,0,0,0);
  local_40 = *(long *)((long)iVar2 * 0x40 + 0x2d58480) - *(long *)((long)iVar2 * 0x40 + 0x2d58488);
  func_0x004c6fa0(0x2d58468,0,0,0);
  pcVar1 = *(code **)(in_RCX + 0x28);
  if (3 < (-(long)pcVar1 + 0x269338U >> 3 | -(long)pcVar1 << 0x3d)) {
    func_0x0044f8c0(0x1a961b0,pcVar1);
  }
  (*pcVar1)(in_RCX,&local_40,8);
  if (_DAT_0391c310 == local_38) {
    return;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d5cb0 RVA 0x2d5cb0 | Evidence ev_c9949489b67d2628dbd69fe4f5656a21720893a6b2c5596b6107466d1efaba60 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d5cb0", "end": "0x2d5d7d"}], "total_bytes": 206, "span_bytes": 206, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_2d5cb0(void)

{
  code *pcVar1;
  int iVar2;
  long in_RCX;
  long *in_GS_OFFSET;
  undefined8 local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  iVar2 = *(int *)(*(long *)(*in_GS_OFFSET + 8) + 0x5c0);
  if (iVar2 == 10) {
    iVar2 = 0;
  }
  func_0x004c6a00(0x2d58468,0,0,0);
  local_40 = *(undefined8 *)((long)iVar2 * 0x40 + 0x2d58480);
  func_0x004c6fa0(0x2d58468,0,0,0);
  pcVar1 = *(code **)(in_RCX + 0x28);
  if (3 < (-(long)pcVar1 + 0x269338U >> 3 | -(long)pcVar1 << 0x3d)) {
    func_0x0044f8c0(0x1a961d0,pcVar1);
  }
  (*pcVar1)(in_RCX,&local_40,8);
  if (_DAT_0391c310 == local_38) {
    return;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d5d80 RVA 0x2d5d80 | Evidence ev_4b2c80d4cf3a6f04d09431549eb35281be7def05d2c4e04e76d020520c3e1538 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d5d80", "end": "0x2d5d8a"}], "total_bytes": 11, "span_bytes": 11, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_2d5d80(void)

{
  return 0x13;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d5d90 RVA 0x2d5d90 | Evidence ev_82d3a66c9abee41af5e667fc771149fef0503487c00cfbbc026451eb5d1180cb | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d5d90", "end": "0x2d5df2"}, {"start": "0x2d5e00", "end": "0x2d5e3c"}], "total_bytes": 160, "span_bytes": 173, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_2d5d90(long param_1,undefined8 param_2)

{
  uint uVar1;
  long lVar2;
  code *pcVar3;
  int iVar4;
  undefined8 uVar5;
  long lVar6;
  ulong local_48;
  undefined8 local_40;
  long local_38;
  long local_30;
  
  local_30 = _DAT_0391c310;
  func_0x005008b0(param_2,param_1,&local_40,&local_48);
  lVar2 = *(long *)(param_1 + 0x10);
  uVar1 = *(uint *)(param_1 + 0x18);
  iVar4 = func_0x002c6c40(lVar2,local_40,&local_38);
  if (iVar4 == 0) {
    local_38 = *(long *)(local_38 + 8);
  }
  uVar5 = 1;
  lVar6 = local_38;
  while( true ) {
    if ((lVar6 == lVar2) || (local_48 <= *(ulong *)(lVar6 + 0x20))) goto LAB_002d5e20;
    if (((*(byte *)(lVar6 + 0x62) & 0x10) != 0) && ((uVar1 & *(ushort *)(lVar6 + 100)) != 0)) break;
    lVar6 = *(long *)(lVar6 + 8);
  }
  uVar5 = 0;
LAB_002d5e20:
  if (_DAT_0391c310 == local_30) {
    return uVar5;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar3 = (code *)invalidInstructionException();
  (*pcVar3)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d5e40 RVA 0x2d5e40 | Evidence ev_0002ebd673bd5729b8354fa534804f6524e62c32eb75698b715be0103a513f94 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d5e40", "end": "0x2d5e47"}], "total_bytes": 8, "span_bytes": 8, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_2d5e40(void)

{
  return 0;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d5e50 RVA 0x2d5e50 | Evidence ev_9cff446f06388806d4663528b97bd48f5ebe3653f7d98f5efc06e97658531cf8 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d5e50", "end": "0x2d5e61"}, {"start": "0x2d5e70", "end": "0x2d5f00"}, {"start": "0x2d5f10", "end": "0x2d5f6b"}, {"start": "0x2d5f70", "end": "0x2d60dc"}], "total_bytes": 620, "span_bytes": 653, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_2d5e50(long *param_1,long *param_2)

{
  long *plVar1;
  long lVar2;
  long lVar3;
  long *plVar4;
  long *plVar5;
  undefined8 *puVar6;
  long *plVar7;
  undefined8 *puVar8;
  
  if ((undefined8 *)*param_1 == (undefined8 *)0x0) {
    param_2[2] = 0;
    param_2[1] = 0;
    *param_2 = 0;
    *(undefined4 *)(param_2 + 3) = 1;
    *param_1 = (long)param_2;
  }
  else {
    puVar8 = (undefined8 *)*param_1;
    do {
      while (puVar6 = puVar8, (ulong)puVar6[6] <= (ulong)param_2[6]) {
        if (param_2[6] == puVar6[6]) {
          return;
        }
        puVar8 = (undefined8 *)puVar6[1];
        if ((undefined8 *)puVar6[1] == (undefined8 *)0x0) {
          param_2[2] = (long)puVar6;
          param_2[1] = 0;
          *param_2 = 0;
          *(undefined4 *)(param_2 + 3) = 1;
          puVar6[1] = param_2;
          goto LAB_002d5efc;
        }
      }
      puVar8 = (undefined8 *)*puVar6;
    } while ((undefined8 *)*puVar6 != (undefined8 *)0x0);
    param_2[2] = (long)puVar6;
    param_2[1] = 0;
    *param_2 = 0;
    *(undefined4 *)(param_2 + 3) = 1;
    *puVar6 = param_2;
  }
LAB_002d5efc:
  plVar4 = (long *)param_2[2];
  do {
    if ((plVar4 == (long *)0x0) || ((int)plVar4[3] != 1)) {
      *(undefined4 *)(*param_1 + 0x18) = 0;
      return;
    }
    plVar1 = (long *)plVar4[2];
    plVar7 = (long *)*plVar1;
    plVar5 = param_2;
    if (plVar4 == plVar7) {
      plVar7 = (long *)plVar1[1];
      if ((plVar7 != (long *)0x0) && ((int)plVar7[3] == 1)) goto LAB_002d5f10;
      plVar7 = (long *)plVar4[1];
      if (plVar7 == param_2) {
        lVar2 = *plVar7;
        plVar4[1] = lVar2;
        if (lVar2 == 0) {
          plVar7[2] = (long)plVar1;
          puVar8 = (undefined8 *)plVar4[2];
          if (plVar4 != (long *)*puVar8) goto LAB_002d5fe9;
LAB_002d6071:
          *puVar8 = plVar7;
        }
        else {
          *(long **)(lVar2 + 0x10) = plVar4;
          puVar8 = (undefined8 *)plVar4[2];
          plVar7[2] = (long)puVar8;
          if (puVar8 == (undefined8 *)0x0) {
            *param_1 = (long)plVar7;
          }
          else {
            if (plVar4 == (long *)*puVar8) goto LAB_002d6071;
LAB_002d5fe9:
            puVar8[1] = plVar7;
          }
        }
        *plVar7 = (long)plVar4;
        plVar4[2] = (long)plVar7;
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
    else if ((plVar7 == (long *)0x0) || ((int)plVar7[3] != 1)) {
      plVar7 = (long *)*plVar4;
      if (plVar7 == param_2) {
        lVar2 = plVar7[1];
        *plVar4 = lVar2;
        if (lVar2 == 0) {
          plVar7[2] = (long)plVar1;
          puVar8 = (undefined8 *)plVar4[2];
          if (plVar4 != (long *)*puVar8) goto LAB_002d5fb5;
LAB_002d5fff:
          *puVar8 = plVar7;
        }
        else {
          *(long **)(lVar2 + 0x10) = plVar4;
          puVar8 = (undefined8 *)plVar4[2];
          plVar7[2] = (long)puVar8;
          if (puVar8 == (undefined8 *)0x0) {
            *param_1 = (long)plVar7;
          }
          else {
            if (plVar4 == (long *)*puVar8) goto LAB_002d5fff;
LAB_002d5fb5:
            puVar8[1] = plVar7;
          }
        }
        plVar7[1] = (long)plVar4;
        plVar4[2] = (long)plVar7;
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
      puVar8 = (undefined8 *)plVar1[2];
      plVar4[2] = (long)puVar8;
      if (puVar8 == (undefined8 *)0x0) {
        *param_1 = (long)plVar4;
      }
      else if (plVar1 == (long *)*puVar8) {
        *puVar8 = plVar4;
      }
      else {
        puVar8[1] = plVar4;
      }
      *plVar4 = (long)plVar1;
      plVar1[2] = (long)plVar4;
    }
    else {
LAB_002d5f10:
      *(undefined4 *)(plVar7 + 3) = 0;
      *(undefined4 *)(plVar4 + 3) = 0;
      *(undefined4 *)(plVar1 + 3) = 1;
      plVar5 = plVar1;
    }
    plVar4 = (long *)plVar5[2];
    param_2 = plVar5;
  } while( true );
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d60e0 RVA 0x2d60e0 | Evidence ev_8e178cf22cb93ddfa8c17fc07b404edb978b5964f4615a33c4d66605f71ec339 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d60e0", "end": "0x2d61d2"}, {"start": "0x2d61e0", "end": "0x2d6253"}, {"start": "0x2d6260", "end": "0x2d64b9"}], "total_bytes": 961, "span_bytes": 986, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_2d60e0(long *param_1,long *param_2)

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
    if (plVar4 != (long *)0x0) goto LAB_002d6148;
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
      goto LAB_002d61cd;
    }
    plVar5 = (long *)param_2[2];
    iVar7 = (int)param_2[3];
    plVar4 = (long *)*param_2;
LAB_002d6148:
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
LAB_002d61cd:
  if (iVar7 == 0) {
    while( true ) {
      if ((plVar4 != (long *)0x0) && ((int)plVar4[3] != 0)) goto LAB_002d643b;
      if (plVar4 == (long *)*param_1) goto LAB_002d6432;
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
          if ((plVar6[1] == 0) || (*(int *)(plVar6[1] + 0x18) == 0)) goto LAB_002d61e0;
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
        goto LAB_002d642b;
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
      if ((lVar1 != 0) && (*(int *)(lVar1 + 0x18) != 0)) goto LAB_002d63d8;
      lVar3 = plVar6[1];
      if ((lVar3 != 0) && (*(int *)(lVar3 + 0x18) != 0)) break;
LAB_002d61e0:
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
LAB_002d63d8:
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
LAB_002d642b:
    plVar5[2] = (long)plVar4;
    plVar4 = (long *)*param_1;
LAB_002d6432:
    if (plVar4 != (long *)0x0) {
LAB_002d643b:
      *(undefined4 *)(plVar4 + 3) = 0;
      return;
    }
  }
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d64c0 RVA 0x2d64c0 | Evidence ev_31224fcd27b0670789d23f69227158a4db6602609941cec67142847ec1726445 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d64c0", "end": "0x2d663e"}], "total_bytes": 383, "span_bytes": 383, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_2d64c0(long param_1,long param_2)

{
  ushort uVar1;
  ushort uVar2;
  long lVar3;
  code *UNRECOVERED_JUMPTABLE;
  char cVar4;
  long lVar5;
  ulong uVar6;
  
  *(byte *)(param_2 + 0x140) = *(byte *)(param_2 + 0x140) & 0xfc;
  uVar1 = *(ushort *)(param_2 + 0x14a);
  uVar2 = *(ushort *)(param_2 + 100);
  *(ushort *)(param_2 + 100) = uVar1;
  if (((uVar1 & 0x3c7) != 0 && (*(byte *)(param_1 + 0x244) & 1) != 0) && (uVar2 & 0x3c7) == 0) {
    lVar3 = *(long *)(param_2 + 0x50);
    if ((*(byte *)(lVar3 + 0xa2) & 1) == 0) {
      func_0x007d46a0(lVar3 + 0x18,0,0);
      cVar4 = func_0x00616d40(*(undefined1 *)(lVar3 + 0x150));
      if (cVar4 != '\0') {
        lVar5 = func_0x00b897f0(lVar3,*(long *)(param_2 + 0x58) >> 0xe);
        if (lVar5 != 0) {
          uVar6 = (*(long *)(lVar5 + 0x28) - (*(ulong *)(param_2 + 0x58) >> 0xe)) * 0x4000 +
                  *(long *)(param_2 + 0x20);
          if (uVar6 < *(ulong *)(param_2 + 0x28)) {
            func_0x008e3d20(*(undefined8 *)(param_1 + 0x1d8),uVar6,*(ulong *)(param_2 + 0x28),lVar5,
                            *(undefined2 *)(param_2 + 100));
          }
        }
      }
      func_0x007d4eb0(lVar3 + 0x18,0,0);
    }
    else {
      func_0x003cc5a0(lVar3,*(undefined8 *)(param_1 + 0x1d8),*(undefined8 *)(param_2 + 0x20),
                      *(undefined8 *)(param_2 + 0x28),*(undefined8 *)(param_2 + 0x58),uVar1);
    }
  }
  if ((((uVar2 & 0x30) == 0 & *(byte *)(param_1 + 0x244)) == 1) && ((uVar1 & 0x30) != 0)) {
    UNRECOVERED_JUMPTABLE = *(code **)(_DAT_01a962e8 + 0x20);
    if (1 < (-(long)UNRECOVERED_JUMPTABLE + 0x26d118U >> 3 | -(long)UNRECOVERED_JUMPTABLE << 0x3d))
    {
      func_0x0044f8c0(0x1a96270,UNRECOVERED_JUMPTABLE);
    }
                    /* WARNING: Could not recover jumptable at 0x002d6616. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    (*UNRECOVERED_JUMPTABLE)
              (param_1,*(long *)(param_2 + 0x20),
               *(long *)(param_2 + 0x28) - *(long *)(param_2 + 0x20),uVar1 & 0x30,1,
               UNRECOVERED_JUMPTABLE);
    return;
  }
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d6640 RVA 0x2d6640 | Evidence ev_e8d772d9b0641aa1d74029e10ad8da2cad0469a386850bf6da5f8fc75855e2d5 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d6640", "end": "0x2d672b"}], "total_bytes": 236, "span_bytes": 236, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_2d6640(long param_1,long param_2)

{
  ushort uVar1;
  code *UNRECOVERED_JUMPTABLE;
  
  *(byte *)(param_2 + 0x140) = *(byte *)(param_2 + 0x140) | 1;
  uVar1 = *(ushort *)(param_2 + 100);
  *(ushort *)(param_2 + 0x14a) = uVar1;
  *(undefined2 *)(param_2 + 100) = 0;
  if ((uVar1 & 0x3c7) != 0 && (*(byte *)(param_1 + 0x244) & 1) != 0) {
    if ((*(byte *)(*(long *)(param_2 + 0x50) + 0xa2) & 1) == 0) {
      func_0x008df6a0();
    }
    else {
      func_0x008ede90(*(undefined8 *)(param_1 + 0x1d8),*(undefined8 *)(param_2 + 0x20),
                      *(undefined8 *)(param_2 + 0x28));
    }
  }
  if ((uVar1 & 0x30) != 0 && (*(byte *)(param_1 + 0x244) & 1) != 0) {
    UNRECOVERED_JUMPTABLE = *(code **)(_DAT_01a962e8 + 0x20);
    if (1 < (-(long)UNRECOVERED_JUMPTABLE + 0x26d118U >> 3 | -(long)UNRECOVERED_JUMPTABLE << 0x3d))
    {
      func_0x0044f8c0(0x1a96290,UNRECOVERED_JUMPTABLE);
    }
                    /* WARNING: Could not recover jumptable at 0x002d6709. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    (*UNRECOVERED_JUMPTABLE)
              (param_1,*(long *)(param_2 + 0x20),
               *(long *)(param_2 + 0x28) - *(long *)(param_2 + 0x20),0,1,UNRECOVERED_JUMPTABLE);
    return;
  }
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d6730 RVA 0x2d6730 | Evidence ev_07374b14c324071949997c3d4559f7ab7dfa30bd0772dd68fad9e907bbe3a147 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d6730", "end": "0x2d67d8"}, {"start": "0x2d67e0", "end": "0x2d6858"}], "total_bytes": 290, "span_bytes": 297, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_2d6730(long param_1,ulong param_2,ulong param_3,int param_4)

{
  code *pcVar1;
  long lVar2;
  long *in_GS_OFFSET;
  long local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  if ((*(byte *)(param_1 + 0x244) & 0x10) == 0) {
    if ((*(byte *)(param_1 + 0x244) & 8) != 0) {
      LOCK();
      *(int *)(*in_GS_OFFSET + 0x5a8) = *(int *)(*in_GS_OFFSET + 0x5a8) + 1;
      UNLOCK();
    }
    func_0x00c4bb20(param_1 + 0x170,0,0,0);
  }
  else {
    func_0x004c6a00(param_1 + 0x1a8,0,0,0);
  }
  *(int *)(param_1 + 0x1c0) = *(int *)(param_1 + 0x1c0) + 1;
  LOCK();
  *(int *)(param_1 + 0x1c4) = *(int *)(param_1 + 0x1c4) + 1;
  UNLOCK();
  func_0x002c6c40(param_1,param_2,&local_40);
  lVar2 = local_40;
  if (*(ulong *)(local_40 + 0x20) < param_2) {
    func_0x002cb4e0(param_1,local_40,param_2);
  }
  for (; (lVar2 != param_1 && (*(ulong *)(lVar2 + 0x20) < param_3)); lVar2 = *(long *)(lVar2 + 8)) {
    if (param_3 < *(ulong *)(lVar2 + 0x28)) {
      func_0x002cb770(param_1,lVar2,param_3);
    }
    if (param_4 == 0) {
      sub_2d6640(param_1,lVar2);
    }
    else {
      sub_2d64c0();
    }
    func_0x002c8910(param_1,lVar2);
  }
  if (_DAT_0391c310 == local_38) {
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d6860 RVA 0x2d6860 | Evidence ev_4aaa25afd55e86c902c902d7f19c954eebae0165e443ba3632bd9804759b31d7 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d6860", "end": "0x2d68f4"}, {"start": "0x2d6900", "end": "0x2d69b2"}, {"start": "0x2d69c0", "end": "0x2d69e5"}], "total_bytes": 366, "span_bytes": 390, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_2d6860(undefined8 param_1,long param_2,long param_3,int param_4,undefined8 param_5,
              undefined8 param_6)

{
  long lVar1;
  code *pcVar2;
  int iVar3;
  long lVar4;
  long *in_GS_OFFSET;
  undefined1 local_78 [16];
  undefined1 local_68 [8];
  undefined4 local_60;
  undefined4 local_5c;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined1 local_40;
  long local_38;
  
  param_3 = param_3 >> 0xe;
  local_38 = _DAT_0391c310;
  if (param_4 == 0) {
    iVar3 = func_0x00460a10(param_1,param_2 >> 0xe);
  }
  else {
    iVar3 = func_0x00460e60();
  }
  if (iVar3 == 0) {
    lVar4 = func_0x00501950(local_78,param_1);
    if (lVar4 == 0) {
      iVar3 = 0;
    }
    else {
      do {
        lVar1 = *(long *)(lVar4 + 0x18);
        if ((*(byte *)(lVar1 + 0x244) & 0x10) == 0) {
          if ((*(byte *)(lVar1 + 0x244) & 8) != 0) {
            LOCK();
            *(int *)(*in_GS_OFFSET + 0x5a8) = *(int *)(*in_GS_OFFSET + 0x5a8) + 1;
            UNLOCK();
          }
          func_0x00c4bb20(lVar1 + 0x170,0,0,0);
        }
        else {
          func_0x004c6a00(lVar1 + 0x1a8,0,0,0,param_5,param_6,param_3);
        }
        *(int *)(lVar1 + 0x1c0) = *(int *)(lVar1 + 0x1c0) + 1;
        LOCK();
        *(int *)(lVar1 + 0x1c4) = *(int *)(lVar1 + 0x1c4) + 1;
        UNLOCK();
        local_60 = (undefined4)(param_2 >> 0xe);
        local_5c = (undefined4)param_3;
        local_58 = *(undefined8 *)(lVar4 + 0x18);
        local_50 = 0x7fffffffffffffff;
        local_48 = 0x7fffffffffffffff;
        local_40 = (undefined1)param_4;
        func_0x00501660(lVar4,local_68,0x2704d8);
        iVar3 = 0;
        func_0x002c64f0(lVar1,0,0);
        lVar4 = func_0x005019d0(local_78);
      } while (lVar4 != 0);
    }
  }
  if (_DAT_0391c310 == local_38) {
    return iVar3;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar2 = (code *)invalidInstructionException();
  (*pcVar2)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d69f0 RVA 0x2d69f0 | Evidence ev_8907fb6d8f1b880af619c900e4e36f6bc2d9a58fcd56ab78a41f06d3f7e330e1 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d69f0", "end": "0x2d6a21"}], "total_bytes": 50, "span_bytes": 50, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_2d69f0(undefined8 param_1)

{
  _DAT_02d60d10 = func_0x0073dd40(0,0x134f852,0x267240,0x138def9,param_1,10000);
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d6a30 RVA 0x2d6a30 | Evidence ev_4caf221428a8640f2b9c6afe4bc4f609e288f6a32d9f69021d815d90542992ac | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d6a30", "end": "0x2d6a7e"}], "total_bytes": 79, "span_bytes": 79, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_2d6a30(undefined8 *param_1)

{
  code *pcVar1;
  int iVar2;
  
  iVar2 = func_0x003c6ad0(*(undefined4 *)(param_1 + 1),*param_1,param_1[2]);
  if (iVar2 == 0) {
    return;
  }
  func_0x007f1950();
  func_0x007f18a0(0x2d6a52,(long)iVar2);
  func_0x00c9aa10(0x8b,0x1275da2,iVar2);
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d6a80 RVA 0x2d6a80 | Evidence ev_e71f1ec7e134858c9a21fbc6286e2b42a5c564999d5d85bdf621f4c9933e0b26 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2d6a80", "end": "0x2d6af4"}, {"start": "0x2d6b30", "end": "0x2d7239"}, {"start": "0x2d7240", "end": "0x2d72b4"}, {"start": "0x2d72c0", "end": "0x2d733d"}, {"start": "0x2d7340", "end": "0x2d7384"}, {"start": "0x2d73fa", "end": "0x2d742e"}, {"start": "0x2d7430", "end": "0x2d76ef"}], "total_bytes": 2988, "span_bytes": 3184, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_2d6a80(void)

{
  long *plVar1;
  int *piVar2;
  long lVar3;
  long lVar4;
  undefined8 uVar5;
  undefined8 uVar6;
  char cVar7;
  int iVar8;
  int iVar9;
  long lVar10;
  long lVar11;
  ulong uVar12;
  ulong uVar13;
  long lVar14;
  ulong uVar15;
  undefined4 *puVar16;
  long lVar17;
  int iVar18;
  long *plVar19;
  long lVar20;
  long *in_GS_OFFSET;
  bool bVar21;
  int local_34;
  
  func_0x00926460(0x12c781a,0x44,7,0);
  lVar10 = func_0x00ad0990();
  uVar5 = rdtsc();
  func_0x004c6a00(0x2d60028,0,0,0);
  _DAT_02d60a30 = _DAT_02d60a30 + 1;
  if (3 < _DAT_02d60a30) {
    _DAT_02d60a30 = 0;
  }
  lVar17 = (long)_DAT_02d60a30;
  uVar6 = rdtsc();
  *(undefined8 *)(&DAT_02d60cc0 + lVar17 * 8) = uVar6;
  func_0x00258ff0(lVar17 * 0x280 + 0x2d60030,0x280);
  lVar4 = lVar17 * 0xa0;
  func_0x00258ff0(&DAT_02d60d20 + lVar4,0xa0);
  func_0x00258ff0(&DAT_02d60fa0 + lVar4,0xa0);
  func_0x00258ff0(lVar4 + 0x2d61220,0xa0);
  func_0x00258ff0(lVar4 + 0x2d60a40,0xa0);
  *(undefined4 *)(&DAT_02d60cf0 + lVar17 * 4) = 0;
  *(undefined4 *)(&DAT_02d60ce0 + lVar17 * 4) = 0;
  func_0x004c6fa0(0x2d60028,0,0,0);
  func_0x007d50c0(0x351e100,0,0);
  iVar18 = _DAT_0351e190;
  func_0x007d56e0(0x351e100,0,0);
  cVar7 = func_0x00616d40(10);
  if (cVar7 != '\0') {
    func_0x007d50c0(0x351e2c8,0,0);
    iVar18 = iVar18 + _DAT_0351e358;
    func_0x007d56e0(0x351e2c8,0,0);
  }
  func_0x007d50c0(0x351e490,0,0);
  iVar18 = iVar18 + _DAT_0351e520;
  func_0x007d56e0(0x351e490,0,0);
  cVar7 = func_0x00616d40(10);
  if (cVar7 != '\0') {
    func_0x007d50c0(0x351e658,0,0);
    iVar18 = iVar18 + _DAT_0351e6e8;
    func_0x007d56e0(0x351e658,0,0);
  }
  *(int *)(lVar17 * 4 + 0x2d60d00) = iVar18;
  func_0x0043e490(lVar4 + 0x2d61220,4);
  func_0x00c06830(0x13ade0f,_DAT_039203d0,0,0x100);
  func_0x00c09650(lVar4 + 0x2d60a40,4);
  func_0x00c06830(0x13ade0f,_DAT_039203d0,0,0x100);
  func_0x00259be0(0x3535ebc,lVar17 * 0x88 + 0x2d614a0,0x88);
  func_0x00c4b350(0x3589e60,0,0,0);
  if (_DAT_03589e80 != (long *)0x0) {
    plVar19 = _DAT_03589e80;
    do {
      plVar1 = plVar19 + 0x29;
      func_0x004c6a00(plVar1,0,0,0);
      if ((((int)plVar19[0x17] == 1) && ((*(byte *)((long)plVar19 + 0xb1) & 0x20) == 0)) &&
         (lVar11 = plVar19[0x40], lVar11 != 0)) {
        do {
          iVar18 = *(int *)(lVar11 + 0x2e0);
          if (iVar18 < 1) goto LAB_002d6e40;
          LOCK();
          bVar21 = iVar18 == *(int *)(lVar11 + 0x2e0);
          if (bVar21) {
            *(int *)(lVar11 + 0x2e0) = iVar18 + 1;
          }
          UNLOCK();
        } while (!bVar21);
        if (lVar11 != plVar19[0x40]) {
          func_0x002c61a0(lVar11);
          goto LAB_002d6e40;
        }
        if ((*(byte *)(lVar11 + 0x244) & 4) == 0) {
          *(int *)(plVar19 + 0x6b) = (int)plVar19[0x6b] + 1;
          func_0x004c6fa0(plVar1,0,0,0);
          func_0x00c4c300(0x3589e60,0,0);
          func_0x00c06830(0x13ade0f,_DAT_039203d0,0,0x100);
          if ((*(byte *)(lVar11 + 0x244) & 0x10) == 0) {
            if ((*(byte *)(lVar11 + 0x244) & 8) != 0) {
              LOCK();
              *(int *)(*in_GS_OFFSET + 0x5a8) = *(int *)(*in_GS_OFFSET + 0x5a8) + 1;
              UNLOCK();
            }
            func_0x00c4b350(lVar11 + 0x170,0,0,0);
          }
          else {
            func_0x004c6a00(lVar11 + 0x1a8,0,0,0);
          }
          lVar20 = *(long *)(lVar11 + 8);
          if (lVar20 == lVar11) {
            iVar18 = 0;
            local_34 = 0;
          }
          else {
            iVar18 = 0;
            local_34 = 0;
            do {
              if ((((*(byte *)(lVar20 + 0x60) & 2) == 0) &&
                  (lVar3 = *(long *)(lVar20 + 0x50), lVar3 != 0)) &&
                 ((*(char *)(lVar3 + 0x150) == '\0' &&
                  ((*(byte *)(lVar3 + 0x9d) < 0xb &&
                   ((0x587U >> (*(byte *)(lVar3 + 0x9d) & 0x1f) & 1) != 0)))))) {
                func_0x007d50c0(lVar3 + 0x18,0,0);
                uVar15 = *(ulong *)(lVar3 + 0x88);
                if (uVar15 != 0) {
                  lVar14 = *(long *)(lVar20 + 0x28) - *(long *)(lVar20 + 0x20) >> 0xe;
                  uVar12 = ((ulong)*(uint *)(lVar3 + 0x140) - (ulong)*(uint *)(lVar3 + 0x144)) *
                           lVar14;
                  if ((uVar12 | uVar15) >> 0x20 == 0) {
                    iVar8 = (int)((uVar12 & 0xffffffff) / (uVar15 & 0xffffffff));
                  }
                  else {
                    iVar8 = (int)((long)uVar12 / (long)uVar15);
                  }
                  uVar12 = lVar14 * *(int *)(lVar3 + 0xa8);
                  if ((uVar12 | uVar15) >> 0x20 == 0) {
                    iVar9 = (int)((uVar12 & 0xffffffff) / (uVar15 & 0xffffffff));
                  }
                  else {
                    iVar9 = (int)((long)uVar12 / (long)uVar15);
                  }
                  iVar18 = iVar18 + iVar8;
                  local_34 = local_34 + iVar9;
                }
                func_0x007d56e0(lVar3 + 0x18,0,0);
              }
              lVar20 = *(long *)(lVar20 + 8);
            } while (lVar20 != lVar11);
          }
          if ((*(byte *)(lVar11 + 0x244) & 0x10) == 0) {
            func_0x00c4c300(lVar11 + 0x170,0,0);
            if ((*(byte *)(lVar11 + 0x244) & 8) != 0) {
              LOCK();
              piVar2 = (int *)(*in_GS_OFFSET + 0x5a8);
              iVar8 = *piVar2;
              *piVar2 = *piVar2 + -1;
              UNLOCK();
              if (iVar8 == -0x7fffffff) {
                func_0x006b7af0();
              }
            }
            func_0x002c66f0();
          }
          else {
            func_0x004c6fa0(lVar11 + 0x1a8,0,0,0);
          }
          func_0x002c61a0(lVar11);
          if (0 < iVar18) {
            if (*(int *)(&DAT_02d60d24 + lVar4) < iVar18) {
              lVar11 = 0;
              puVar16 = (undefined4 *)(&DAT_02d60d20 + lVar4);
            }
            else {
              lVar11 = 1;
              puVar16 = (undefined4 *)(lVar4 + 0x2d60d48);
              if (((iVar18 <= *(int *)(&DAT_02d60d4c + lVar4)) &&
                  (lVar11 = 2, puVar16 = (undefined4 *)(lVar4 + 0x2d60d70),
                  iVar18 <= *(int *)(&DAT_02d60d74 + lVar4))) &&
                 (lVar11 = 3, puVar16 = (undefined4 *)(lVar4 + 0x2d60d98),
                 iVar18 <= *(int *)(&DAT_02d60d9c + lVar4))) goto LAB_002d713c;
            }
            func_0x00259be0(puVar16,lVar17 * 0xa0 + 0x2d60d48 + lVar11 * 0x28,
                            ((uint)lVar11 ^ 3) * 0x28);
            *puVar16 = *(undefined4 *)((long)plVar19 + 0xbc);
            func_0x00259be0((long)plVar19 + 0x5e4,puVar16 + 2,0x20);
            puVar16[1] = iVar18;
          }
LAB_002d713c:
          if (*(int *)(&DAT_02d60fa4 + lVar4) < local_34) {
            lVar11 = 0;
            puVar16 = (undefined4 *)(&DAT_02d60fa0 + lVar4);
LAB_002d718e:
            func_0x00259be0(puVar16,lVar17 * 0xa0 + 0x2d60fc8 + lVar11 * 0x28,
                            ((uint)lVar11 ^ 3) * 0x28);
            *puVar16 = *(undefined4 *)((long)plVar19 + 0xbc);
            puVar16[1] = local_34;
            func_0x00259be0((long)plVar19 + 0x5e4,puVar16 + 2,0x20);
          }
          else {
            lVar11 = 1;
            puVar16 = (undefined4 *)(lVar4 + 0x2d60fc8);
            if (((*(int *)(&DAT_02d60fcc + lVar4) < local_34) ||
                (lVar11 = 2, puVar16 = (undefined4 *)(lVar4 + 0x2d60ff0),
                *(int *)(&DAT_02d60ff4 + lVar4) < local_34)) ||
               (lVar11 = 3, puVar16 = (undefined4 *)(lVar4 + 0x2d61018),
               *(int *)(&DAT_02d6101c + lVar4) < local_34)) goto LAB_002d718e;
          }
          func_0x00c4b350(0x3589e60,0,0,0);
          func_0x004c6a00(plVar1,0,0,0);
          iVar18 = (int)plVar19[0x6b] + -1;
          *(int *)(plVar19 + 0x6b) = iVar18;
          if ((iVar18 == 0 & *(byte *)((long)plVar19 + 0xb1) >> 5) == 1) {
            func_0x00c06910(plVar19 + 0x6b);
          }
          goto LAB_002d6e40;
        }
        func_0x004c6fa0(plVar1,0,0);
        func_0x002c61a0(lVar11);
      }
      else {
LAB_002d6e40:
        func_0x004c6fa0(plVar1,0,0);
      }
      plVar19 = (long *)*plVar19;
    } while (plVar19 != (long *)0x0);
  }
  func_0x00c4c300(0x3589e60,0,0);
  func_0x004c6a00(0x351e0b8,0,0,0);
  for (lVar4 = _DAT_0351e098; lVar4 != 0; lVar4 = *(long *)(lVar4 + 0x40)) {
    if (((*(char *)(lVar4 + 0x150) == '\0') && (*(byte *)(lVar4 + 0x9d) < 0xb)) &&
       ((0x587U >> (*(byte *)(lVar4 + 0x9d) & 0x1f) & 1) != 0)) {
      func_0x007d46a0(lVar4 + 0x18,0,0);
      iVar18 = *(int *)(lVar4 + 0x140);
      iVar8 = *(int *)(lVar4 + 0x144);
      *(undefined8 *)(lVar4 + 0x140) = 0;
      func_0x007d4eb0(lVar4 + 0x18,0,0);
      *(int *)(&DAT_02d60ce0 + lVar17 * 4) = *(int *)(&DAT_02d60ce0 + lVar17 * 4) + iVar18;
      *(int *)(&DAT_02d60cf0 + lVar17 * 4) = *(int *)(&DAT_02d60cf0 + lVar17 * 4) + iVar8;
    }
  }
  func_0x004c6fa0(0x351e0b8,0,0,0);
  iVar18 = _DAT_02d60a34;
  uVar15 = rdtsc();
  if ((ulong)(lVar10 * 0xf) <= uVar15) {
    LOCK();
    _DAT_02d60a34 = 0;
    UNLOCK();
    if (iVar18 != 0) {
      uVar12 = func_0x00ad0990(uVar5);
      func_0x0025d410(0x13ade17,iVar18);
      lVar10 = (long)(_DAT_02d60a30 + -3 + (_DAT_02d60a30 + -3 >> 0x1f) * -4);
      uVar15 = *(ulong *)(&DAT_02d60cc0 + lVar10 * 8);
      if ((uVar15 | uVar12) >> 0x20 == 0) {
        uVar13 = (uVar15 & 0xffffffff) / (uVar12 & 0xffffffff);
        uVar15 = (uVar15 & 0xffffffff) % (uVar12 & 0xffffffff);
      }
      else {
        uVar13 = uVar15 / uVar12;
        uVar15 = uVar15 % uVar12;
      }
      uVar15 = uVar15 * 1000;
      if ((uVar15 | uVar12) >> 0x20 == 0) {
        uVar15 = (uVar15 & 0xffffffff) / (uVar12 & 0xffffffff);
      }
      else {
        uVar15 = uVar15 / uVar12;
      }
      func_0x0025d410(0x1383664,uVar13,uVar15);
      lVar4 = lVar10 * 0x88;
      func_0x0025d410(0x1289d09,*(undefined4 *)(lVar4 + 0x2d614f4),
                      *(undefined4 *)(lVar4 + 0x2d61504),*(undefined4 *)(lVar4 + 0x2d61518));
      func_0x0025d410(0x136ecd7,*(undefined4 *)(lVar4 + 0x2d61514),
                      *(undefined4 *)(lVar4 + 0x2d6150c),*(undefined4 *)(lVar4 + 0x2d61508));
      func_0x0025d410(0x13ade65,(ulong)(long)*(int *)(lVar10 * 4 + 0x2d60d00) >> 6 & 0xfffffffffff);
      lVar10 = lVar10 * 0xa0;
      if (*(ulong *)(lVar10 + 0x2d60a40) != 0) {
        func_0x0025d410(0x131affa,1,*(ulong *)(lVar10 + 0x2d60a40) >> 0x14,lVar10 + 0x2d60a48);
        if (*(ulong *)(lVar10 + 0x2d60a68) != 0) {
          func_0x0025d410(0x131affa,2,*(ulong *)(lVar10 + 0x2d60a68) >> 0x14,lVar10 + 0x2d60a70);
          if (*(ulong *)(lVar10 + 0x2d60a90) != 0) {
            func_0x0025d410(0x131affa,3,*(ulong *)(lVar10 + 0x2d60a90) >> 0x14,lVar10 + 0x2d60a98);
            if (*(ulong *)(lVar10 + 0x2d60ab8) != 0) {
              func_0x0025d410(0x131affa,4,*(ulong *)(lVar10 + 0x2d60ab8) >> 0x14,lVar10 + 0x2d60ac0)
              ;
            }
          }
        }
      }
      if (*(ulong *)(lVar10 + 0x2d61220) != 0) {
        func_0x0025d410(0x12c7827,1,*(ulong *)(lVar10 + 0x2d61220) >> 0x14,lVar10 + 0x2d61228);
        if (*(ulong *)(lVar10 + 0x2d61248) != 0) {
          func_0x0025d410(0x12c7827,2,*(ulong *)(lVar10 + 0x2d61248) >> 0x14,lVar10 + 0x2d61250);
          if (*(ulong *)(lVar10 + 0x2d61270) != 0) {
            func_0x0025d410(0x12c7827,3,*(ulong *)(lVar10 + 0x2d61270) >> 0x14,lVar10 + 0x2d61278);
            if (*(ulong *)(lVar10 + 0x2d61298) != 0) {
              func_0x0025d410(0x12c7827,4,*(ulong *)(lVar10 + 0x2d61298) >> 0x14,lVar10 + 0x2d612a0)
              ;
            }
          }
        }
      }
      if (*(int *)(&DAT_02d60d20 + lVar10) != 0) {
        func_0x0025d410(0x13a3348,1,
                        (ulong)((long)*(int *)(&DAT_02d60d24 + lVar10) << 0xe) / 0x500000,
                        *(int *)(&DAT_02d60d20 + lVar10),lVar10 + 0x2d60d28);
        if ((*(int *)(lVar10 + 0x2d60d48) != 0) &&
           (func_0x0025d410(0x13a3348,2,
                            (ulong)((long)*(int *)(&DAT_02d60d4c + lVar10) << 0xe) / 0x500000,
                            *(int *)(lVar10 + 0x2d60d48),lVar10 + 0x2d60d50),
           *(int *)(lVar10 + 0x2d60d70) != 0)) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
      }
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


