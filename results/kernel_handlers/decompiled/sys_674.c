/* Handler 674: REA6.7.0 / Ghidra12.1.4 recovered pseudocode, not original or buildable C.
 * Original4096-byte input SHA256 2b296f8bf9a7d2c0b88b3664570faeb6bf0325d743aacf1c8c7c5114280302f0
 * Raw entry RVA 0x265fa0 -> actual target 0xabb980. narg=5.
 * Kernel RVAs; runtime VA=0xffffffff8a9c0000+RVA. Opaque externals/data remain unknown.
 * Analyst types below are inferred from accesses. Recovered pseudocode is retained verbatim afterward.
 * Original entry is an assembly-verified tail JMP to the target above. An engine halt_baddata
 * at that unmapped edge is a decompiler boundary artifact, not a recovered halt operation.
 */
#include <stdint.h>

/* ===== Analyst recovered interface/types ===== */
struct handler_674_args { void *records; uint64_t stride; uint64_t maximum_records; uint64_t *total_records; uint32_t mode; uint32_t pad; };
struct handler_674_record { uint64_t value0, value1, value2, value3; uint8_t attributes; uint8_t name_or_payload[39]; };
/* Record is72 bytes; names are analyst placeholders, and only min(stride,72) bytes are copied. */


/* ===== ORIGINAL ENTRY: <EXTERNAL>::thunk_EXT_FUN_00abb980 RVA 0x265fa0 | Evidence ev_bd8233e8f8316684c7e215791837e94c470911b6f244cbbafe614212f710232e | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.raw.dossier.json | Source /tmp/rea-646-676-5b61b6f2/raw_union.bin SHA256 352988f408bc976411feddb3ef6cd2b18459d2aa3fa6dfd7f2e4a7fe416ce915 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x265fa0", "end": "0x265fa4"}], "total_bytes": 5, "span_bytes": 5, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_00abb980(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}




/* ===== TARGET: handler_674_body RVA 0xabb980 | Evidence ev_9af19f4187e845ef82e2ef8a5df3a31b0c4b6e3ff177e9680333fc6166e25c1d | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabb980", "end": "0xabba7b"}, {"start": "0xabba80", "end": "0xabbbca"}, {"start": "0xabbbd0", "end": "0xabbd77"}], "total_bytes": 1007, "span_bytes": 1016, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int handler_674_body(long param_1,long *param_2)

{
  ulong uVar1;
  long lVar2;
  code *pcVar3;
  int iVar4;
  int iVar5;
  ulong uVar6;
  long lVar7;
  ulong uVar8;
  ulong uVar9;
  undefined8 *in_GS_OFFSET;
  bool bVar10;
  ulong local_100;
  ulong local_f8;
  int local_e4;
  long local_e0;
  undefined8 local_d8;
  ulong local_d0;
  undefined8 local_c8;
  ulong local_c0;
  byte local_b8;
  byte local_a8;
  undefined1 local_a4;
  undefined1 local_a3 [35];
  undefined8 local_80;
  ulong local_78;
  undefined8 local_70;
  ulong local_68;
  byte local_60;
  undefined1 local_5f [32];
  undefined1 local_3f;
  long local_38;
  
  local_38 = _DAT_0391c310;
  iVar4 = func_0x00b2bb00(4);
  iVar5 = 0x16;
  if (iVar4 == 0) {
    local_e0 = *param_2;
    if (local_e0 == 0) {
      local_f8 = 0;
      iVar4 = (int)param_2[4];
    }
    else {
      local_f8 = param_2[2];
      iVar4 = (int)param_2[4];
    }
    if (iVar4 == 0x40000000) {
      uVar1 = param_2[1];
      lVar2 = *(long *)(*(long *)(param_1 + 8) + 0x200);
      local_e4 = func_0x00ab54e0(*(undefined4 *)(*(long *)(param_1 + 8) + 0xbc));
      func_0x002c6820(lVar2,0,0);
      lVar7 = *(long *)(lVar2 + 8);
      local_100 = 0xffffffffffffffff;
      uVar6 = 0x48;
      if (uVar1 < 0x48) {
        uVar6 = uVar1;
      }
      uVar8 = 0;
      uVar9 = 0;
LAB_00abba9a:
      do {
        iVar5 = 0;
        if (lVar7 != lVar2) {
          if (uVar9 <= *(ulong *)(lVar7 + 0x20)) {
            uVar9 = *(ulong *)(lVar7 + 0x20);
          }
          func_0x00aba710(lVar2,lVar7,uVar9,&local_80,1,1);
          if (uVar8 < local_f8) {
            func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
            iVar5 = func_0x002591d0(&local_80,local_e0,uVar6);
            if (iVar5 != 0) goto LAB_00abbb46;
            local_e0 = local_e0 + uVar1;
          }
          if (*(ulong *)(lVar7 + 0x28) <= local_78) {
            lVar7 = *(long *)(lVar7 + 8);
          }
          uVar8 = uVar8 + 1;
          uVar9 = local_78;
          iVar5 = 0;
          if (*(ulong *)(lVar7 + 0x20) < 0x80000000000) goto LAB_00abba9a;
        }
LAB_00abbb46:
        if (local_e4 == 0) {
          uVar9 = 0x80000000000;
          if (iVar5 == 0) {
            do {
              iVar4 = func_0x00ab67c0(*(undefined4 *)(*(long *)(param_1 + 8) + 0xbc),uVar9,1,
                                      &local_d8);
              iVar5 = 0;
              if (iVar4 != 0) break;
              func_0x00258ff0(&local_80,0x48);
              local_80 = local_d8;
              local_68 = local_c0 >> 0x20 | local_c0 << 0x20;
              local_78 = local_d0;
              local_70 = local_c8;
              local_60 = (local_b8 & 1) << 6 | local_60 & 0x9f | (local_a8 & 1) << 5;
              local_3f = local_a4;
              func_0x00957b70(local_5f,local_a3,0x20);
              if (uVar8 < local_f8) {
                func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
                iVar5 = func_0x002591d0(&local_80,local_e0,uVar6);
                if (iVar5 != 0) break;
              }
              local_e0 = local_e0 + uVar1;
              uVar8 = uVar8 + 1;
              uVar9 = local_d0;
              iVar5 = 0;
            } while ((uint)(local_d0 >> 0x28) < 0xf);
          }
          func_0x00ab5690(*(undefined4 *)(*(long *)(param_1 + 8) + 0xbc));
          local_e4 = -1;
        }
        if ((iVar5 != 0) || (lVar7 == lVar2)) {
          func_0x002c6870(lVar2,0,0);
          if (iVar5 == 0) {
            iVar5 = 0;
            if (param_2[3] != 0) {
              iVar4 = func_0x00259720(param_2[3],uVar8);
              iVar5 = 0xe;
              if (iVar4 != -1) {
                iVar5 = 0;
              }
            }
          }
          break;
        }
        bVar10 = uVar9 == local_100;
        local_100 = uVar9;
        if (bVar10) {
          func_0x007f1950();
          func_0x007f1810(0xabbd4b);
          func_0x00c9aa10(0x17,0x1395a92);
                    /* WARNING: Does not return */
          pcVar3 = (code *)invalidInstructionException();
          (*pcVar3)();
        }
      } while( true );
    }
  }
  if (_DAT_0391c310 == local_38) {
    return iVar5;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar3 = (code *)invalidInstructionException();
  (*pcVar3)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abbd80 RVA 0xabbd80 | Evidence ev_4b38709f0844b2b81b7c96c48d75a703ae14ea1dce65bda1e85cf421cacdadf8 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabbd80", "end": "0xabbe52"}], "total_bytes": 211, "span_bytes": 211, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined4 sub_abbd80(long param_1,ulong *param_2)

{
  ulong uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  undefined4 uVar5;
  ulong uVar6;
  ulong uVar7;
  
  uVar1 = *param_2;
  uVar5 = 0x16;
  uVar6 = param_2[1] + uVar1;
  if ((!CARRY8(param_2[1],uVar1)) && (uVar7 = uVar6 + 0x3fff & 0xffffffffffffc000, uVar6 <= uVar7))
  {
    uVar6 = param_2[2];
    iVar3 = func_0x003c33e0((int)uVar6,*(undefined8 *)(param_1 + 8));
    if (iVar3 == 0) {
      uVar5 = 0x16;
    }
    else {
      uVar4 = (uint)param_2[3];
      uVar5 = 0x16;
      if (*(char *)(*(long *)(param_1 + 8) + 0xc81) == '\0') {
        uVar2 = uVar4 & 8;
      }
      else {
        uVar2 = uVar4 & 0xfc08;
      }
      if (uVar2 == 0) {
        uVar4 = func_0x002cd3c0(*(undefined8 *)(*(long *)(param_1 + 8) + 0x200),
                                uVar1 & 0xffffffffffffc000,uVar7,(int)uVar6,
                                uVar4 >> 1 & 0x141 | uVar4 & 0xffff);
        uVar5 = 0x16;
        if (uVar4 < 10) {
          uVar5 = *(undefined4 *)((ulong)uVar4 * 4 + 0x18dbfb4);
        }
      }
    }
  }
  return uVar5;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_548 RVA 0xabbe60 | Evidence ev_ab5c89413b5a43b7f0ae9fc855df45b95a38cd06053a20c03453748b732e079c | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabbe60", "end": "0xabbf19"}, {"start": "0xabbf68", "end": "0xabbff2"}, {"start": "0xabc24d", "end": "0xabc256"}, {"start": "0xabc29e", "end": "0xabc2ab"}, {"start": "0xabc2b8", "end": "0xabc3a3"}], "total_bytes": 585, "span_bytes": 1348, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong sys_548(long param_1,long param_2)

{
  undefined8 uVar1;
  long *plVar2;
  code *pcVar3;
  ulong uVar4;
  int iVar5;
  ulong uVar6;
  long *plVar7;
  undefined8 *in_GS_OFFSET;
  undefined1 local_a0 [28];
  uint local_84;
  long *local_80;
  long **local_78;
  int local_70 [14];
  long local_38;
  
  local_38 = _DAT_0391c310;
  iVar5 = *(int *)(param_2 + 0x18);
  if (iVar5 < 0) {
    uVar4 = 0x16;
    if (*(long *)(param_2 + 0x20) != 0) {
      func_0x00259790(*(long *)(param_2 + 0x20),0);
      uVar4 = 0x16;
    }
    goto LAB_00abc371;
  }
  uVar4 = 0x16;
  if ((*(uint *)(param_2 + 8) &
      (uint)(*(char *)(*(long *)(param_1 + 8) + 0xc81) != '\0') * 0x20000000 + 0xe0bffb6f) != 0)
  goto LAB_00abc371;
  local_78 = &local_80;
  *(undefined2 *)(param_1 + 0x116) = 1;
  *(undefined1 *)(param_1 + 0x5f0) = 0;
  local_80 = (long *)0x0;
  if (iVar5 == 0) {
    uVar4 = 0;
    iVar5 = 0;
  }
  else {
    uVar1 = *(undefined8 *)(param_2 + 0x10);
    func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
    uVar4 = func_0x00259280(uVar1,local_a0,0x20);
    iVar5 = 0;
    if ((int)uVar4 == 0) {
      uVar6 = (ulong)local_84;
      if ((local_84 != 4) && (local_80 != (long *)0x0)) {
        uVar4 = sub_abc3b0(&local_80,local_70);
        if ((int)uVar4 != 0) {
          iVar5 = local_70[0] + -1;
          goto LAB_00abc2b8;
        }
        uVar6 = (ulong)local_84;
      }
      uVar4 = 0x16;
      iVar5 = 0;
      if ((uint)uVar6 < 5) {
                    /* WARNING: Could not emulate address calculation at 0x00abbfea */
                    /* WARNING: Treating indirect jump as call */
        uVar4 = (*(code *)((long)*(int *)(uVar6 * 4 + 0x18dbf54) + 0x18dbf54))();
        return uVar4;
      }
    }
LAB_00abc2b8:
    if (local_80 != (long *)0x0) {
      uVar4 = uVar4 & 0xffffffff;
      plVar7 = local_80;
      do {
        plVar2 = (long *)*plVar7;
        func_0x0043c0c0(_DAT_03bf6e18,plVar7,0);
        plVar7 = plVar2;
      } while (plVar2 != (long *)0x0);
    }
  }
  *(undefined1 *)(param_1 + 0x116) = 0;
  if (*(char *)(param_1 + 0x117) != '\0') {
    uVar4 = uVar4 & 0xffffffff;
    pcVar3 = *(code **)(_DAT_01a962e8 + 0x40);
    if (0x6ff < (-(long)pcVar3 + 0x260ce8U >> 3 | -(long)pcVar3 << 0x3d)) {
      func_0x0044f8c0(0x2888cf0,pcVar3);
    }
    (*pcVar3)(*(undefined8 *)(*(long *)(param_1 + 8) + 0x200));
    if (*(char *)(param_1 + 0x5f0) != '\0') {
      LOCK();
      _DAT_02d616c0 = _DAT_02d616c0 + -1;
      UNLOCK();
    }
  }
  if (*(long *)(param_2 + 0x20) != 0) {
    uVar4 = uVar4 & 0xffffffff;
    func_0x00259790(*(long *)(param_2 + 0x20),iVar5);
  }
LAB_00abc371:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar3 = (code *)invalidInstructionException();
    (*pcVar3)();
  }
  return uVar4;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abc3b0 RVA 0xabc3b0 | Evidence ev_862e7c7e53da059d7a77bdd62498f2bc0b4fc7d6778b5ed856e02961e4e75cbf | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabc3b0", "end": "0xabc505"}], "total_bytes": 342, "span_bytes": 342, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 sub_abc3b0(long *param_1,int *param_2)

{
  long lVar1;
  undefined8 *puVar2;
  code *pcVar3;
  undefined8 *puVar4;
  int iVar5;
  uint uVar6;
  ulong uVar7;
  long *plVar8;
  int iVar9;
  undefined4 uVar10;
  long *in_GS_OFFSET;
  int local_3c;
  long local_38;
  
  local_38 = _DAT_0391c310;
  lVar1 = *in_GS_OFFSET;
  iVar5 = func_0x00609560(*(undefined8 *)(lVar1 + 0x140));
  uVar10 = 1;
  if ((iVar5 == 0) && (iVar5 = func_0x006095a0(*(undefined8 *)(lVar1 + 0x140)), iVar5 == 0)) {
    local_3c = 0;
    plVar8 = (long *)*param_1;
    if (plVar8 != (long *)0x0) {
      uVar10 = 0x16;
      iVar5 = 1;
      do {
        iVar9 = iVar5;
        uVar7 = plVar8[3] + plVar8[1];
        if ((((CARRY8(plVar8[3],plVar8[1])) || ((uVar7 + 0x3fff & 0xffffffffffffc000) < uVar7)) ||
            (iVar5 = func_0x003c33e0((int)*(char *)((long)plVar8 + 0x21),*(undefined8 *)(lVar1 + 8))
            , iVar5 == 0)) || ((*(byte *)(plVar8 + 4) & 8) != 0)) goto LAB_00abc4a2;
        plVar8 = (long *)*plVar8;
        iVar5 = iVar9 + 1;
        local_3c = iVar9;
      } while (plVar8 != (long *)0x0);
    }
    uVar6 = func_0x002cdc10(*(undefined8 *)(*(long *)(lVar1 + 8) + 0x200),param_1,&local_3c);
    uVar10 = 0x16;
    if (uVar6 < 10) {
      uVar10 = *(undefined4 *)((ulong)uVar6 * 4 + 0x18dbfb4);
    }
LAB_00abc4a2:
    puVar4 = (undefined8 *)*param_1;
    while (puVar4 != (undefined8 *)0x0) {
      puVar2 = (undefined8 *)*puVar4;
      func_0x0043c0c0(_DAT_03bf6e18,puVar4,0);
      puVar4 = puVar2;
    }
    *param_1 = 0;
    param_1[1] = (long)param_1;
    *param_2 = local_3c;
  }
  if (_DAT_0391c310 == local_38) {
    return uVar10;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar3 = (code *)invalidInstructionException();
  (*pcVar3)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_559 RVA 0xabc510 | Evidence ev_fce39945524d3a5c1b09e9564a7c639882765fa755ebf5f4a2435f50b43dbc3a | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabc510", "end": "0xabc5e0"}], "total_bytes": 209, "span_bytes": 209, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sys_559(long param_1,uint *param_2)

{
  int iVar1;
  uint uVar2;
  long lVar3;
  int iVar4;
  undefined8 uVar5;
  long *in_GS_OFFSET;
  
  lVar3 = *in_GS_OFFSET;
  iVar1 = *(int *)(*(long *)(lVar3 + 8) + 0x5c0);
  iVar4 = 0x16;
  if (0xfffffffc < iVar1 - 2U) {
    if (iVar1 == -1) {
      iVar4 = -1;
    }
    else {
      iVar4 = func_0x00adfa30(lVar3,0x2ad);
      if (iVar4 == 0) {
        *(int *)(*(long *)(lVar3 + 8) + 0x5c0) = iVar1;
        iVar4 = iVar1;
      }
    }
  }
  uVar5 = 0x16;
  *(long *)(param_1 + 0x408) = (long)iVar4;
  uVar2 = *param_2;
  if ((0xfffffffc < uVar2 - 2) && (uVar5 = 0, uVar2 != 0xffffffff)) {
    uVar5 = func_0x00adfa30(param_1,0x2ad);
    if (((int)uVar5 == 0) && (uVar5 = 0x16, *(int *)((ulong)uVar2 * 0x88 + 0x3535f10) != 0)) {
      *(uint *)(*(long *)(lVar3 + 8) + 0x5c0) = uVar2;
      uVar5 = 0;
    }
  }
  return uVar5;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_588 RVA 0xabc5f0 | Evidence ev_1230a6df00feef96e6b74390f2018bebeeed24a4a4636478bbc2901671ef49a5 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabc5f0", "end": "0xabc70d"}], "total_bytes": 286, "span_bytes": 286, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sys_588(long param_1,ulong *param_2)

{
  ulong uVar1;
  long lVar2;
  ulong uVar3;
  code *pcVar4;
  undefined8 uVar5;
  ulong uVar6;
  ulong uVar7;
  undefined8 *in_GS_OFFSET;
  undefined1 local_58 [32];
  long local_38;
  
  local_38 = _DAT_0391c310;
  uVar1 = *param_2;
  lVar2 = *(long *)(*(long *)(param_1 + 8) + 0x200);
  uVar5 = 0x16;
  if (*(ulong *)(lVar2 + 0x20) <= uVar1) {
    uVar3 = param_2[1];
    if (uVar3 <= *(ulong *)(lVar2 + 0x28) - uVar1 && uVar1 < *(ulong *)(lVar2 + 0x28)) {
      uVar6 = param_2[2];
      func_0x00c1a3e0(*in_GS_OFFSET,0x135a084,0);
      uVar5 = func_0x00259900(uVar6,local_58,0x20,0);
      if ((int)uVar5 == 0) {
        uVar7 = uVar1 & 0xffffffffffffc000;
        uVar6 = uVar3 + 0x3fff + (ulong)((uint)uVar1 & 0x3fff) & 0xffffffffffffc000;
        uVar3 = uVar6 + uVar7;
        if (((uint)(uVar1 >> 0x28) < 0xf) && (0x80000000000 < uVar3)) {
          uVar5 = func_0x0081f770(*(undefined8 *)(param_1 + 8),uVar7,uVar6,local_58);
          if (((int)uVar5 != 0xd) && ((int)uVar5 != 0)) goto LAB_00abc6ee;
        }
        func_0x002d2e50(lVar2,uVar7,uVar3,local_58);
        uVar5 = 0;
      }
    }
  }
LAB_00abc6ee:
  if (_DAT_0391c310 == local_38) {
    return uVar5;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar4 = (code *)invalidInstructionException();
  (*pcVar4)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_607 RVA 0xabc710 | Evidence ev_f46d1c40bc8a04c4e5503a98663bf84f2d49756a4b709a8b4590f337dda0f907 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabc710", "end": "0xabca04"}], "total_bytes": 757, "span_bytes": 757, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sys_607(long param_1,undefined8 *param_2)

{
  undefined8 uVar1;
  code *pcVar2;
  int iVar3;
  int iVar4;
  undefined8 uVar5;
  long lVar6;
  undefined8 *in_GS_OFFSET;
  undefined8 local_1d0;
  long local_1c8;
  undefined4 local_1c0;
  undefined8 local_1b8;
  long local_1b0;
  undefined8 local_1a8;
  long local_1a0;
  undefined4 local_198;
  undefined8 local_190;
  long local_188;
  undefined8 local_180;
  undefined1 local_120 [96];
  long local_c0;
  long local_38;
  
  local_38 = _DAT_0391c310;
  uVar1 = *param_2;
  uVar5 = func_0x0043b880(_DAT_036d15e0,0,2);
  func_0x00c1a3e0(*in_GS_OFFSET,0x135a084,0);
  iVar3 = func_0x00259900(uVar1,uVar5,0x400,0);
  if (iVar3 == 0) {
    func_0x005fa6e0(local_120,0,0x144,1,uVar5,0xffffff9c,0,0,param_1);
    iVar3 = func_0x005f8c20(local_120);
    func_0x005fa780(local_120,0xc);
    if (iVar3 == 0) {
      iVar3 = 0x16;
      if (*(int *)(local_c0 + 0x1d4) == 1) {
        local_190 = *(undefined8 *)(param_1 + 0x140);
        local_1a8 = 0x1ada7f8;
        local_1a0 = local_c0;
        local_198 = 1;
        local_180 = 0;
        local_188 = param_1;
        iVar3 = func_0x0058bb00(*(undefined8 *)(local_c0 + 8),&local_1a8);
        if (iVar3 == 0) {
          lVar6 = func_0x0045d9c0(7,local_c0,0,1,0,*(undefined8 *)(param_1 + 0x140));
          if (lVar6 == 0) {
            iVar3 = 0xc;
          }
          else {
            func_0x007d46a0(lVar6 + 0x18,0,0);
            iVar3 = func_0x00631850(lVar6);
            if (iVar3 == 0) {
              iVar3 = func_0x00632330(lVar6,uVar5,*(undefined8 *)(param_1 + 0x140),&local_1a8);
              func_0x006321f0(lVar6);
            }
            else {
              func_0x0025d410(0x132d3cb,0x1318557,iVar3);
              iVar3 = 8;
            }
          }
          local_1b8 = *(undefined8 *)(param_1 + 0x140);
          local_1d0 = 0x1ada8f8;
          local_1c8 = local_c0;
          local_1c0 = 1;
          local_1b0 = param_1;
          func_0x0058bce0(*(undefined8 *)(local_c0 + 8),&local_1d0);
          func_0x0054a440(local_c0);
          if (lVar6 != 0) {
            func_0x00461ba0();
          }
          func_0x0043c0c0(_DAT_036d15e0,uVar5,0);
          if (iVar3 == 0) {
            iVar4 = func_0x00609c00(*(long *)(param_1 + 0x140) + 0x58,&local_1a8);
            iVar3 = 1;
            if (iVar4 == 0) {
              uVar1 = param_2[1];
              func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
              iVar3 = func_0x002591d0(&local_1a8,uVar1,0x88);
            }
          }
          goto LAB_00abc869;
        }
      }
      func_0x0054a440(local_c0);
    }
  }
  func_0x0043c0c0(_DAT_036d15e0,uVar5,0);
LAB_00abc869:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar2 = (code *)invalidInstructionException();
    (*pcVar2)();
  }
  return iVar3;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_613 RVA 0xabca10 | Evidence ev_a9e82d21b81c47e495a8c135c15d78b1a9e7235a580afa4cbe18b16396036028 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabca10", "end": "0xabcbf3"}], "total_bytes": 484, "span_bytes": 484, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sys_613(long param_1,undefined4 *param_2)

{
  long lVar1;
  long lVar2;
  code *pcVar3;
  int iVar4;
  long lVar5;
  undefined8 uVar6;
  long lVar7;
  undefined8 *in_GS_OFFSET;
  undefined8 local_48;
  long local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  iVar4 = func_0x00608f90(*(undefined8 *)(param_1 + 0x140));
  if (iVar4 == 0) {
    uVar6 = 1;
  }
  else {
    lVar5 = func_0x0053c170(*param_2);
    uVar6 = 3;
    if (lVar5 != 0) {
      if ((*(uint *)(lVar5 + 0xb0) & 0x2000) == 0) {
        *(int *)(lVar5 + 0x358) = *(int *)(lVar5 + 0x358) + 1;
        if ((*(uint *)(lVar5 + 0xb0) & 0x10000000) == 0) {
          func_0x0053aa10(lVar5);
        }
        lVar1 = lVar5 + 0x148;
        func_0x004c6fa0(lVar1,0,0);
        lVar2 = *(long *)(lVar5 + 0x200);
        func_0x002c6820(lVar2,0,0);
        local_40 = 0;
        local_48 = func_0x002c6e90(*(undefined8 *)(lVar5 + 0x200));
        lVar7 = *(long *)(lVar2 + 8);
        if (lVar7 != lVar2) {
          local_40 = 0;
          do {
            local_40 = local_40 +
                       ((ulong)(*(long *)(lVar7 + 0x28) - *(long *)(lVar7 + 0x20)) >> 0xe);
            lVar7 = *(long *)(lVar7 + 8);
          } while (lVar7 != lVar2);
        }
        func_0x002c6870(lVar2,0,0);
        func_0x004c6a00(lVar1,0,0,0);
        iVar4 = *(int *)(lVar5 + 0x358) + -1;
        *(int *)(lVar5 + 0x358) = iVar4;
        if ((*(byte *)(lVar5 + 0xb1) >> 5 & iVar4 == 0) != 0) {
          func_0x00c06910(lVar5 + 0x358);
        }
        func_0x004c6fa0(lVar1,0,0,0);
        uVar6 = *(undefined8 *)(param_2 + 2);
        func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
        uVar6 = func_0x002591d0(&local_48,uVar6,8);
        if ((int)uVar6 == 0) {
          uVar6 = *(undefined8 *)(param_2 + 4);
          func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
          uVar6 = func_0x002591d0(&local_40,uVar6,8);
        }
      }
      else {
        func_0x004c6fa0(lVar5 + 0x148,0,0,0);
        uVar6 = 3;
      }
    }
  }
  if (_DAT_0391c310 == local_38) {
    return uVar6;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar3 = (code *)invalidInstructionException();
  (*pcVar3)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_615 RVA 0xabcc00 | Evidence ev_0a94b4d13de5ac5bccc55ee56b6722c86072cc4791c073bba4c3930bf4a71959 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabcc00", "end": "0xabccb5"}], "total_bytes": 182, "span_bytes": 182, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sys_615(undefined8 param_1,undefined4 *param_2)

{
  undefined8 uVar1;
  code *pcVar2;
  int iVar3;
  undefined8 *in_GS_OFFSET;
  undefined1 local_d8 [8];
  undefined1 local_d0 [168];
  long local_28;
  
  local_28 = _DAT_0391c310;
  iVar3 = sub_abccc0(param_1,*param_2,local_d8);
  if (iVar3 == 0) {
    uVar1 = *(undefined8 *)(param_2 + 2);
    func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
    iVar3 = func_0x002591d0(local_d8,uVar1,8);
    if (iVar3 == 0) {
      uVar1 = *(undefined8 *)(param_2 + 4);
      func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
      func_0x002591d0(local_d0,uVar1,8);
    }
  }
  if (_DAT_0391c310 == local_28) {
    return;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar2 = (code *)invalidInstructionException();
  (*pcVar2)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abccc0 RVA 0xabccc0 | Evidence ev_f0003a884b2e572eca5232efa48c9adf8c3c77dc5cbbc0143c5e3ccb8fffc32a | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabccc0", "end": "0xabcda9"}, {"start": "0xabcdb0", "end": "0xabcff6"}], "total_bytes": 817, "span_bytes": 823, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_abccc0(long param_1,int param_2,long param_3)

{
  long lVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  long lVar5;
  long lVar6;
  ulong uVar7;
  code *pcVar8;
  int iVar9;
  undefined4 extraout_var;
  undefined4 extraout_var_00;
  long lVar10;
  long lVar11;
  long lVar12;
  long *plVar13;
  undefined8 uVar14;
  ulong uVar15;
  long *in_GS_OFFSET;
  long local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  if ((param_2 == 0) || (param_2 == *(int *)(*(long *)(*in_GS_OFFSET + 8) + 0xbc))) {
    lVar11 = *(long *)(*in_GS_OFFSET + 8);
    func_0x004c6a00(lVar11 + 0x148,0,0,0);
  }
  else {
    iVar9 = func_0x00608f90(*(undefined8 *)(param_1 + 0x140));
    if (iVar9 == 0) {
      uVar14 = 1;
      goto LAB_00abcfd5;
    }
    lVar11 = func_0x0053c170(param_2);
    if (lVar11 == 0) {
      uVar14 = 3;
      goto LAB_00abcfd5;
    }
  }
  if ((*(uint *)(lVar11 + 0xb0) & 0x2000) == 0) {
    *(int *)(lVar11 + 0x358) = *(int *)(lVar11 + 0x358) + 1;
    if ((*(uint *)(lVar11 + 0xb0) & 0x10000000) == 0) {
      func_0x0053aa10(lVar11);
    }
    lVar1 = lVar11 + 0x148;
    func_0x004c6fa0(lVar1,0,0,0);
    lVar2 = *(long *)(lVar11 + 0x200);
    func_0x002c6820(lVar2,0,0);
    uVar15 = rdtsc();
    func_0x00258ff0(param_3,0xb0);
    local_40 = *(long *)(lVar2 + 8);
    if (local_40 != lVar2) {
      uVar15 = CONCAT44(extraout_var,(int)uVar15) | uVar15 & 0xffffffff00000000;
      do {
        lVar3 = *(long *)(local_40 + 0x20);
        uVar7 = rdtsc();
        if ((uVar7 & 0xffffffff00000000 | CONCAT44((int)((ulong)local_40 >> 0x20),(int)uVar7)) -
            uVar15 < 0x27101) {
LAB_00abce60:
          if (((*(byte *)(local_40 + 0x60) & 2) == 0) &&
             (((lVar4 = *(long *)(local_40 + 0x50), lVar4 != 0 && (*(byte *)(lVar4 + 0x9d) < 9)) &&
              ((0x187U >> (*(byte *)(lVar4 + 0x9d) & 0x1f) & 1) != 0)))) {
            func_0x007d50c0(lVar4 + 0x18,0,0);
            lVar12 = (long)*(char *)(local_40 + 0x14c) * 0x10;
            plVar13 = (long *)(param_3 + 8 + lVar12);
            *plVar13 = *plVar13 + ((ulong)(*(long *)(local_40 + 0x28) - lVar3) >> 0xe);
            lVar5 = *(long *)(local_40 + 0x58);
            lVar6 = *(long *)(local_40 + 0x28);
            lVar10 = func_0x00b897f0(lVar4);
            if (lVar10 != 0) {
              plVar13 = (long *)(lVar12 + param_3);
              do {
                if ((ulong)((lVar5 - lVar3) + lVar6 >> 0xe) <= *(ulong *)(lVar10 + 0x28)) break;
                *plVar13 = *plVar13 + 1;
                lVar10 = *(long *)(lVar10 + 0x10);
              } while (lVar10 != 0);
            }
            func_0x007d56e0(lVar4 + 0x18,0,0);
          }
        }
        else {
          iVar9 = *(int *)(lVar2 + 0x1c0);
          func_0x002c6870(lVar2,0,0);
          func_0x00c06830(0x1291b82,_DAT_039203d0,0,0x100);
          func_0x002c6820(lVar2,0,0);
          uVar15 = rdtsc();
          uVar15 = uVar15 & 0xffffffff00000000 | CONCAT44(extraout_var_00,(int)uVar15);
          if ((*(int *)(lVar2 + 0x1c0) == iVar9) ||
             (iVar9 = func_0x002c6c40(lVar2,lVar3,&local_40), iVar9 != 0)) goto LAB_00abce60;
        }
        local_40 = *(long *)(local_40 + 8);
      } while (local_40 != lVar2);
    }
    uVar14 = 0;
    func_0x002c6870(lVar2,0,0);
    func_0x004c6a00(lVar1,0,0,0);
    iVar9 = *(int *)(lVar11 + 0x358) + -1;
    *(int *)(lVar11 + 0x358) = iVar9;
    if ((*(byte *)(lVar11 + 0xb1) >> 5 & iVar9 == 0) != 0) {
      func_0x00c06910(lVar11 + 0x358);
    }
    func_0x004c6fa0(lVar1,0,0,0);
  }
  else {
    func_0x004c6fa0(lVar11 + 0x148,0,0,0);
    uVar14 = 3;
  }
LAB_00abcfd5:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar8 = (code *)invalidInstructionException();
    (*pcVar8)();
  }
  return uVar14;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abd000 RVA 0xabd000 | Evidence ev_a0c048c56652b5f4bbbe2a3ba2fad042f8575d3dc00b99e2875773d407f1f623 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabd000", "end": "0xabd0e5"}], "total_bytes": 230, "span_bytes": 230, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_abd000(undefined8 param_1,undefined4 *param_2)

{
  int iVar1;
  code *pcVar2;
  undefined8 uVar3;
  undefined8 *in_GS_OFFSET;
  undefined1 local_e0 [8];
  undefined1 auStack_d8 [168];
  long local_30;
  
  local_30 = _DAT_0391c310;
  if ((param_2[2] == 10) || (uVar3 = 0x16, param_2[2] == 0)) {
    uVar3 = sub_abccc0(param_1,*param_2,local_e0);
    if ((int)uVar3 == 0) {
      iVar1 = param_2[2];
      uVar3 = *(undefined8 *)(param_2 + 4);
      func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
      uVar3 = func_0x002591d0(local_e0 + (long)iVar1 * 0x10,uVar3,8);
      if ((int)uVar3 == 0) {
        iVar1 = param_2[2];
        uVar3 = *(undefined8 *)(param_2 + 6);
        func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
        uVar3 = func_0x002591d0(auStack_d8 + (long)iVar1 * 0x10,uVar3,8);
      }
    }
  }
  if (_DAT_0391c310 == local_30) {
    return uVar3;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar2 = (code *)invalidInstructionException();
  (*pcVar2)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_618 RVA 0xabd0f0 | Evidence ev_b0b1b79cbd2ba2c4e61e9f671ca545ec08ea476bba2c7aa3dc70404aa70f0c51 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabd0f0", "end": "0xabd20c"}, {"start": "0xabd261", "end": "0xabd2d6"}, {"start": "0xabd340", "end": "0xabd423"}], "total_bytes": 631, "span_bytes": 820, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong sys_618(long param_1,undefined8 *param_2)

{
  long *plVar1;
  long lVar2;
  code *pcVar3;
  int iVar4;
  uint uVar5;
  long lVar6;
  undefined8 uVar7;
  ulong uVar8;
  undefined8 local_78;
  long local_70;
  undefined8 *local_68;
  undefined4 local_60;
  undefined8 local_58;
  long local_50;
  undefined8 local_48;
  long local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  iVar4 = func_0x00608f90(*(undefined8 *)(param_1 + 0x140));
  if (iVar4 == 0) {
    uVar8 = 1;
LAB_00abd405:
    if (_DAT_0391c310 == local_38) {
      return uVar8;
    }
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar3 = (code *)invalidInstructionException();
    (*pcVar3)();
  }
  local_78 = *param_2;
  local_68 = &local_78;
  local_70 = (long)*(int *)(param_2 + 1);
  local_60 = 1;
  local_58 = 0;
  local_48 = 0;
  local_50 = local_70;
  local_40 = param_1;
LAB_00abd17e:
  func_0x004c6a00(0x351e060,0,0,0);
  iVar4 = 0;
  if (_DAT_0351e038 != 0) {
    iVar4 = 0;
    lVar6 = _DAT_0351e038;
    do {
      lVar6 = *(long *)(lVar6 + 0x20);
      iVar4 = iVar4 + 1;
    } while (lVar6 != 0);
  }
  func_0x004c6fa0(0x351e060,0,0,0);
  uVar7 = func_0x00c08b50((long)iVar4 * 0x128,0x2bfc080,0x102);
  func_0x004c6a00(0x351e060,0,0,0);
  lVar6 = _DAT_0351e038;
  if (_DAT_0351e038 != 0) {
    do {
      lVar2 = lVar6 + 0x18;
      func_0x007d46a0(lVar2,0,0);
      if ((*(uint *)(lVar6 + 0xa0) & 8) == 0) {
        if (iVar4 < 1) goto LAB_00abd340;
        if ((ulong)*(byte *)(lVar6 + 0x9d) < 9) {
                    /* WARNING: Could not emulate address calculation at 0x00abd2c3 */
                    /* WARNING: Treating indirect jump as call */
          uVar8 = (*(code *)((long)*(int *)((ulong)*(byte *)(lVar6 + 0x9d) * 4 + 0x18dbf68) +
                            0x18dbf68))();
          return uVar8;
        }
      }
      func_0x007d4eb0(lVar2,0,0);
      plVar1 = (long *)(lVar6 + 0x20);
      lVar6 = *plVar1;
      if (*plVar1 == 0) break;
    } while( true );
  }
  func_0x004c6fa0(0x351e060,0,0,0);
  uVar5 = func_0x00782520(uVar7,0,&local_68);
  uVar8 = (ulong)uVar5;
  func_0x00c08df0(uVar7,0x2bfc080);
  if (uVar5 == 0) {
    uVar8 = 0;
    if (param_2[2] != 0) {
      iVar4 = func_0x00259720(param_2[2],0);
      uVar8 = 0xe;
      if (iVar4 == 0) {
        uVar8 = 0;
      }
    }
  }
  goto LAB_00abd405;
LAB_00abd340:
  func_0x007d4eb0(lVar2,0,0);
  func_0x004c6fa0(0x351e060,0,0);
  func_0x00c08df0(uVar7);
  goto LAB_00abd17e;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_620 RVA 0xabd430 | Evidence ev_497d9ca3a51c9cabe5168491267763226ddb46c80642a8942c342d63d95dfb04 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabd430", "end": "0xabd4e7"}], "total_bytes": 184, "span_bytes": 184, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sys_620(long param_1)

{
  undefined8 uVar1;
  code *pcVar2;
  int iVar3;
  uint uVar4;
  ulong uVar5;
  long local_30;
  long local_28;
  
  local_28 = _DAT_0391c310;
  uVar1 = *(undefined8 *)(*(long *)(param_1 + 8) + 0x200);
  uVar5 = *(long *)(*(long *)(param_1 + 0x460) + 0x100) - 0x80U & 0xffffffffffffc000;
  func_0x002c6820(uVar1,0,0);
  iVar3 = func_0x002c6c40(uVar1,uVar5,&local_30);
  if (iVar3 != 0) {
    uVar4 = (uint)(uVar5 - *(long *)(local_30 + 0x20) >> 0xe);
    if (0 < (int)uVar4) {
      func_0x00463610(*(undefined8 *)(local_30 + 0x50),*(long *)(local_30 + 0x58) >> 0xe,
                      uVar4 & 0x7fffffff,5);
    }
  }
  func_0x002c6870(uVar1,0,0);
  if (_DAT_0391c310 == local_28) {
    return 0;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar2 = (code *)invalidInstructionException();
  (*pcVar2)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_624 RVA 0xabd4f0 | Evidence ev_fb8ce107f4e0b0ef2ecf94bc66584bc4eae775ba6c96d1dbc5ee7af3244f5e70 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabd4f0", "end": "0xabd531"}], "total_bytes": 66, "span_bytes": 66, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sys_624(long param_1)

{
  long lVar1;
  
  lVar1 = *(long *)(*(long *)(param_1 + 8) + 0x200);
  func_0x002c6820(lVar1,0,0);
  *(ulong *)(param_1 + 0x408) = (ulong)*(uint *)(lVar1 + 0x1c4);
  func_0x002c6870(lVar1,0,0);
  return 0;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_628 RVA 0xabd540 | Evidence ev_f486b8d9b62f02454ea2d880a34eae6d8ff485577fe8c415db5c78d33cfadcfe | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabd540", "end": "0xabd922"}], "total_bytes": 995, "span_bytes": 995, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 sys_628(long param_1,ulong *param_2)

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
  ulong local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
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
  local_40 = uVar14;
  iVar10 = func_0x00609560(*(undefined8 *)(param_1 + 0x140));
  uVar11 = 1;
  if (iVar10 != 0) goto LAB_00abd60e;
  iVar10 = func_0x006095a0(*(undefined8 *)(lVar5 + 0x140));
  if (iVar10 == 0) {
    iVar10 = func_0x006092d0(*(undefined8 *)(param_1 + 0x140));
    if (iVar10 == 0) {
      uVar11 = 0x16;
      if (((uVar14 & 0x3fff) != 0) || (uVar3 < 0x4000 || (uVar3 & 0x3fff) != 0)) goto LAB_00abd60e;
      if ((iVar2 == -1) ||
         (iVar10 = func_0x003c33e0(iVar2,*(undefined8 *)(param_1 + 8)), iVar10 != 0)) {
        uVar11 = 0x16;
        if ((((uVar8 & 0xfffffc0c) != 0) ||
            (uVar11 = 0x16, (uVar4 & 0x3fff) != 0 || (uVar1 & 0x9fdf2f) != 0)) ||
           (((uVar1 & 0x40) != 0 && ((0x4000 < uVar3 || ((uVar8 & 3) == 0)))))) goto LAB_00abd60e;
        if (((uVar1 & 0x200000) == 0) ||
           (iVar10 = func_0x00b24300(*(undefined8 *)(lVar5 + 8)), iVar10 != 0)) {
          lVar12 = func_0x00ab8320(param_1);
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
                uVar9 = local_40;
              }
              local_40 = uVar9;
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
                goto LAB_00abd60e;
              }
              uVar11 = 0x16;
              if (((CARRY8(uVar14,uVar3) || uVar14 < *(ulong *)(lVar6 + 0x20)) ||
                  (*(ulong *)(lVar6 + 0x28) < uVar14 + uVar3)) ||
                 ((0x7ffffffff < uVar13 && (uVar14 >> 0x1c < 0xff && 0x7efffffff < uVar14 + uVar3)))
                 ) goto LAB_00abd60e;
              uVar11 = *(undefined4 *)(*(long *)(lVar5 + 8) + 0x5c4);
              uVar15 = 0;
            }
            uVar11 = func_0x003cb450(param_1,lVar6,&local_40,uVar11,uVar4,uVar14,uVar3,iVar2,
                                     uVar8 >> 1 & 0x141 | uVar8,uVar15,uVar1,lVar12,0);
            *(ulong *)(param_1 + 0x408) = local_40;
            goto LAB_00abd60e;
          }
        }
      }
      uVar11 = 0x16;
      goto LAB_00abd60e;
    }
    func_0x0025d410(0x1376c18);
  }
  uVar11 = 1;
LAB_00abd60e:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar7 = (code *)invalidInstructionException();
    (*pcVar7)();
  }
  return uVar11;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_637 RVA 0xabd930 | Evidence ev_3afbdf37c73afc1b50e1b4b818ae5ae3a702538591d483250ec5653ed5984a9c | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabd930", "end": "0xabdac6"}], "total_bytes": 407, "span_bytes": 407, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sys_637(long param_1,int *param_2)

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
    func_0x004c6a00(lVar3 + 0x148,0,0,0);
  }
  else {
    iVar2 = func_0x00608f90(*(undefined8 *)(param_1 + 0x140));
    if (iVar2 == 0) {
      return 1;
    }
    lVar3 = func_0x0053c170(*param_2);
    if (lVar3 == 0) {
      return 3;
    }
  }
  if (((*(uint *)(lVar3 + 0xb0) & 0x2200) == 0) && (*(int *)(lVar3 + 0xb8) == 1)) {
    *(int *)(lVar3 + 0x358) = *(int *)(lVar3 + 0x358) + 1;
    if ((*(uint *)(lVar3 + 0xb0) & 0x10000000) == 0) {
      func_0x0053aa10(lVar3);
    }
    uVar4 = 0;
    func_0x004c6fa0(lVar3 + 0x148,0,0,0);
    lVar1 = *(long *)(lVar3 + 0x200);
    if (lVar1 != 0) {
      func_0x004c6a00(lVar1 + 0x278,0,0,0);
      *(undefined8 *)(lVar1 + 0x280) = *(undefined8 *)(param_2 + 2);
      func_0x004c6fa0(lVar1 + 0x278,0,0,0);
      func_0x00691c70(lVar1);
    }
    func_0x004c6a00(lVar3 + 0x148,0,0,0);
    iVar2 = *(int *)(lVar3 + 0x358) + -1;
    *(int *)(lVar3 + 0x358) = iVar2;
    if ((iVar2 == 0 & *(byte *)(lVar3 + 0xb1) >> 5) == 1) {
      func_0x00c06910(lVar3 + 0x358);
    }
  }
  else {
    uVar4 = 3;
  }
  func_0x004c6fa0(lVar3 + 0x148,0,0,0);
  return uVar4;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_642 RVA 0xabdad0 | Evidence ev_8a6fc96d4e5aeb69b9415b4a881dbc669248a860eaede24c0193e682745ec773 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabdad0", "end": "0xabdd9e"}, {"start": "0xabdda0", "end": "0xabdf16"}, {"start": "0xabdf20", "end": "0xabe1be"}], "total_bytes": 1765, "span_bytes": 1775, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong sys_642(long param_1,undefined4 *param_2)

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
  int local_a4;
  undefined1 local_a0 [32];
  undefined8 local_80;
  undefined8 local_78;
  long local_70;
  uint local_68;
  undefined4 local_64;
  undefined4 local_60;
  int local_5c;
  uint local_58;
  undefined8 local_54;
  undefined8 local_4c;
  undefined8 local_44;
  int local_3c;
  long local_38;
  
  local_38 = _DAT_0391c310;
  iVar9 = func_0x00608f90(*(undefined8 *)(param_1 + 0x140));
  if (iVar9 == 0) {
    uVar13 = 1;
  }
  else {
    lVar12 = func_0x0053c170(*param_2);
    uVar13 = 2;
    if (lVar12 != 0) {
      if ((*(uint *)(lVar12 + 0xb0) & 0x2000) == 0) {
        *(int *)(lVar12 + 0x358) = *(int *)(lVar12 + 0x358) + 1;
        if ((*(uint *)(lVar12 + 0xb0) & 0x10000000) == 0) {
          func_0x0053aa10(lVar12);
        }
        lVar1 = lVar12 + 0x148;
        func_0x004c6fa0(lVar1,0,0,0);
        lVar3 = *(long *)(lVar12 + 0x200);
        func_0x002c6820(lVar3,0,0);
        local_a4 = 0;
        func_0x00258ff0(local_a0,0x68);
        for (lVar4 = *(long *)(lVar3 + 8); lVar4 != lVar3; lVar4 = *(long *)(lVar4 + 8)) {
          if ((*(short *)(lVar4 + 0x66) != 0) && ((*(byte *)(lVar4 + 0x60) & 2) == 0)) {
            lVar5 = *(long *)(lVar4 + 0x50);
            local_68 = (uint)*(ushort *)(lVar4 + 100);
            uVar10 = *(uint *)(lVar4 + 0x60);
            if ((uVar10 & 0x20) != 0) {
              local_68 = local_68 | 0x10000;
              uVar10 = *(uint *)(lVar4 + 0x60);
            }
            if ((uVar10 & 0x1000) != 0) {
              local_68 = local_68 | 0x20000;
            }
            local_80 = *(undefined8 *)(lVar4 + 0x20);
            local_78 = *(undefined8 *)(lVar4 + 0x28);
            if ((lVar5 == 0) ||
               (((*(byte *)(lVar5 + 0x9d) < 0xb &&
                 ((0x587U >> (*(byte *)(lVar5 + 0x9d) & 0x1f) & 1) != 0)) &&
                ((*(byte *)(lVar5 + 0xa2) & 1) == 0)))) {
              if (*(short *)(lVar4 + 0x66) == 0) {
                local_3c = 0;
              }
              else {
                local_3c = (int)*(char *)(lVar4 + 0x14c);
              }
              if (lVar5 != 0) goto LAB_00abdc7a;
              func_0x00258ff0(local_a0,0x68);
            }
            else {
              local_3c = 0;
LAB_00abdc7a:
              lVar18 = lVar5 + 0x18;
              func_0x007d46a0(lVar18,0,0);
              if ((byte)(*(char *)(lVar5 + 0x9d) - 3U) < 2) {
                func_0x007d4eb0(lVar18,0,0);
                goto LAB_00abdbd0;
              }
              local_64 = *(undefined4 *)(lVar5 + 0x130);
              local_60 = *(undefined4 *)(lVar5 + 0x138);
              iVar9 = 0;
              func_0x007d4eb0(lVar18,0,0);
              uVar13 = *(ulong *)(lVar4 + 0x20) & 0xffffffffffffc000;
              uVar19 = *(long *)(lVar4 + 0x28) + 0x3fffU & 0xffffffffffffc000;
              if (uVar13 < uVar19) {
                iVar9 = 0;
                do {
                  lVar14 = func_0x008de3e0(*(undefined8 *)(lVar3 + 0x1d8),uVar13);
                  iVar9 = (iVar9 + 1) - (uint)(lVar14 == 0);
                  uVar13 = uVar13 + 0x4000;
                } while (uVar13 < uVar19);
              }
              local_70 = (long)(int)((uint)lVar5 ^ 0x3bf6e18);
              local_58 = (uint)*(byte *)(lVar5 + 0x9d);
              local_54 = 0;
              local_4c = 0;
              local_44 = 0;
              uVar10 = (uint)((ulong)(*(long *)(lVar4 + 0x28) - *(long *)(lVar4 + 0x20)) >> 0xe);
              local_5c = iVar9;
              if (0 < (int)uVar10) {
                uVar13 = 0;
LAB_00abddd8:
                lVar14 = *(long *)(lVar4 + 0x58);
                lVar17 = (long)((int)uVar13 << 0xe);
                func_0x007d46a0(lVar18,0,0);
                lVar15 = func_0x00b897e0(lVar5);
                lVar16 = lVar5;
                while (lVar15 == 0) {
                  lVar6 = *(long *)(lVar16 + 0xb0);
                  if (lVar6 == 0) {
                    func_0x007d4eb0(lVar16 + 0x18,0,0);
                    lVar14 = *(long *)(lVar4 + 0x58);
                    func_0x007d46a0(lVar18,0,0);
                    cVar2 = *(char *)(lVar5 + 0x9d);
                    lVar16 = lVar5;
                    goto joined_r0x00abdf6d;
                  }
                  lVar14 = lVar14 + *(long *)(lVar16 + 0xb8);
                  func_0x007d46a0(lVar6 + 0x18,0,0);
                  func_0x007d4eb0(lVar16 + 0x18,0,0);
                  lVar15 = func_0x00b897e0(lVar6);
                  lVar16 = lVar6;
                }
                func_0x00b8d8a0(lVar15);
                if (*(int *)(lVar15 + 0x70) == 0) {
                  local_4c = CONCAT44(local_4c._4_4_ + 1,(int)local_4c);
                  cVar2 = *(char *)(lVar15 + 0x66);
                }
                else {
                  local_4c = CONCAT44(local_4c._4_4_,(int)local_4c + 1);
                  cVar2 = *(char *)(lVar15 + 0x66);
                }
                if (cVar2 == '\x01') {
                  local_44 = CONCAT44(local_44._4_4_,(int)local_44 + 1);
                }
                if (*(int *)(lVar15 + 0x70) == 0) {
                  if ((*(long *)(lVar15 + 0x20) == 0) ||
                     (*(char *)(*(long *)(lVar15 + 0x20) + 0x9d) == '\0')) {
LAB_00abdda0:
                    local_44 = CONCAT44(local_44._4_4_ + 1,(int)local_44);
                  }
                  else if (*(char *)(lVar16 + 0x9d) == '\x01') {
                    pcVar8 = *(code **)(_DAT_01ac3918 + 0x38);
                    if (0xd < (-(long)pcVar8 + 0x26b848U >> 3 | -(long)pcVar8 << 0x3d)) {
                      func_0x0044f8c0(0x2888d60,pcVar8);
                    }
                    iVar9 = (*pcVar8)(lVar16,lVar14 + lVar17 >> 0xe,0);
                    if (iVar9 == 0) goto LAB_00abdda0;
                  }
                }
                goto LAB_00abdda3;
              }
            }
LAB_00abe03b:
            func_0x00957b70(local_a0,lVar4 + 0x150,0x20);
            iVar9 = local_a4;
            lVar18 = (long)local_a4;
            lVar5 = *(long *)(param_2 + 4);
            if ((lVar5 != 0) && (local_a4 < (int)param_2[2])) {
              func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
              iVar11 = func_0x002591d0(local_a0,lVar5 + lVar18 * 0x68,0x68);
              if (iVar11 != 0) break;
            }
            local_a4 = iVar9 + 1;
          }
LAB_00abdbd0:
        }
        func_0x002c6870(lVar3,0,0);
        func_0x004c6a00(lVar1,0,0,0);
        iVar9 = *(int *)(lVar12 + 0x358) + -1;
        *(int *)(lVar12 + 0x358) = iVar9;
        if ((iVar9 == 0 & *(byte *)(lVar12 + 0xb1) >> 5) == 1) {
          func_0x00c06910(lVar12 + 0x358);
        }
        func_0x004c6fa0(lVar1,0,0,0);
        uVar7 = *(undefined8 *)(param_2 + 6);
        func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
        uVar13 = func_0x002591d0(&local_a4,uVar7,4);
        if ((*(long *)(param_2 + 4) != 0) &&
           (uVar13 = uVar13 & 0xffffffff, (int)param_2[2] < local_a4)) {
          uVar13 = 0xc;
        }
      }
      else {
        func_0x004c6fa0(lVar12 + 0x148,0,0,0);
        uVar13 = 2;
      }
    }
  }
  if (_DAT_0391c310 == local_38) {
    return uVar13;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar8 = (code *)invalidInstructionException();
  (*pcVar8)();
joined_r0x00abdf6d:
  if (cVar2 == '\x01') {
    pcVar8 = *(code **)(_DAT_01ac3918 + 0x38);
    if (0xd < (-(long)pcVar8 + 0x26b848U >> 3 | -(long)pcVar8 << 0x3d)) {
      func_0x0044f8c0(0x2888d60,pcVar8);
    }
    iVar9 = (*pcVar8)(lVar16,lVar14 + lVar17 >> 0xe,0,0);
    if (iVar9 != 0) {
      local_54 = CONCAT44(local_54._4_4_ + 1,(int)local_54);
      goto LAB_00abdda3;
    }
  }
  lVar15 = *(long *)(lVar16 + 0xb0);
  if (lVar15 == 0) goto LAB_00abe006;
  lVar14 = lVar14 + *(long *)(lVar16 + 0xb8);
  func_0x007d46a0(lVar15 + 0x18,0,0);
  func_0x007d4eb0(lVar16 + 0x18,0,0);
  cVar2 = *(char *)(lVar15 + 0x9d);
  lVar16 = lVar15;
  goto joined_r0x00abdf6d;
LAB_00abe006:
  local_54 = CONCAT44(local_54._4_4_,(int)local_54 + 1);
LAB_00abdda3:
  func_0x007d4eb0(lVar16 + 0x18,0,0);
  uVar13 = uVar13 + 1;
  if (uVar13 == (uVar10 & 0x7fffffff)) goto LAB_00abe03b;
  goto LAB_00abddd8;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_646 RVA 0xabe1c0 | Evidence ev_6dd8e331a72e689da69e2cc7753a5ea3dbbbaaa6735db7eb8f7956636b0f69e0 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabe1c0", "end": "0xabe253"}], "total_bytes": 148, "span_bytes": 148, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sys_646(long param_1,undefined8 *param_2)

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




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abe260 RVA 0xabe260 | Evidence ev_e1ec54065c9bdcce5a4467fbd5ff29f804268b4bd587c680f5d7b550fe501fa1 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_647 RVA 0xabe7b0 | Evidence ev_ad2157b997c3b0aa40a8bcb48bc446bd954e1c5c6788107ffac71438d61e19d9 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abe830 RVA 0xabe830 | Evidence ev_ae2cea8c19be902aa4e2141e8ec636a21762ad45be069d73a63acd4e387f774c | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sys_671 RVA 0xabe8b0 | Evidence ev_6a0ba9616ee77ccb98dfcd9acca905ff80cf2a82c90f2b8900038d432aa39c9f | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): FUN_00abea41 RVA 0xabea41 | Evidence ev_ea01537287aeb556de8584df4b2f40ba13f34aa3f6adc6d31b99d3f04dc92984 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abea52 RVA 0xabea52 | Evidence ev_8ffcde751a32377c9bb727047203cbce16b175ecc691ecd07e879bf668ad1b47 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abeac0 RVA 0xabeac0 | Evidence ev_1b2dd65089db4984a5595e6facb2d67d1b90060dbcf1092a6f9159b727c3d85c | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabeac0", "end": "0xabeaef"}], "total_bytes": 48, "span_bytes": 48, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_abeac0(void)

{
  _DAT_03bf6e18 = func_0x0043b0e0(0x129bd39,0x28,0,0,0,0,7,0);
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abeaf0 RVA 0xabeaf0 | Evidence ev_0ac3946f0308b9689a6eafb7811282180ab6d421c233354117674809e8bfb3e8 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abeba0 RVA 0xabeba0 | Evidence ev_e57310a4c9d5b607b2da89162f63a4be05c0a5bb02322220524b3d0139ba09c5 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abec30 RVA 0xabec30 | Evidence ev_8193ff149d38a96c3942e0f42dc1c5c8d82e02066cbf4d730d0f70ddddf31fc2 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abecc0 RVA 0xabecc0 | Evidence ev_e86028d8e8be786027e776c54359b5b8ed03cd55c133e7554bfb3e405bc68be4 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abed50 RVA 0xabed50 | Evidence ev_529edab37eb87921384e40ecc8c6d4c92b681bc9905bd37fe0e7c64900e085df | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abedd0 RVA 0xabedd0 | Evidence ev_91310290c354165ea3ad79efda3b29c1916ae83af77e6205f9b5346376eb7715 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abee20 RVA 0xabee20 | Evidence ev_8212aaf2e1553ab7ad9dd1a50b45c2e0d155ac424dd588b3bc7a272ef3d076c7 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): FUN_00abef70 RVA 0xabef70 | Evidence ev_74a8cfc7afe83b1d2d7344b26add4d3375f6a33f1dd3c978dbebbb2f7e948b61 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abefa4 RVA 0xabefa4 | Evidence ev_1cc18d9973341292c5341586098c6b7dedddf8766b6450c1cd13a49da0c2f4e6 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf000 RVA 0xabf000 | Evidence ev_72745f7ffa2cba9befc2c36738e4b590737d291edeaead17db1b61f3485f839d | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf100 RVA 0xabf100 | Evidence ev_2cc58f92c555f00996c45434240c23e8ed0eb74ea8cec49f03cf3915631a0f3f | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf140 RVA 0xabf140 | Evidence ev_d14f764bb12998a552db9511f3b6ad55230f423d84dec99f02eb5d22187e088b | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf1b0 RVA 0xabf1b0 | Evidence ev_451e6cd32033d210ef621f1fbb25cac2e0e61daf3da6fb58883bf5b3f33fb236 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf1e0 RVA 0xabf1e0 | Evidence ev_faf45e73336220ea790a8ff7c70ae77a4a0e399b4dd6d5ea058abd596e182d36 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf220 RVA 0xabf220 | Evidence ev_fed1875767baa41d299bb6ffcdd369b4080bb1c5ff42c63f85b913d9f215dba6 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf240 RVA 0xabf240 | Evidence ev_ae365cc45b3ad92ac7d8373c9934d5d0c6603d9c46b87bef49ebf82f71b8ed6c | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf2d0 RVA 0xabf2d0 | Evidence ev_c276ad7c900dfa94a89f98f8c180dc1595321642d744ae26ed6bf2fe5c6e416d | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf33f RVA 0xabf33f | Evidence ev_289690e91e90bcbd74062a539f6d390cfc93192f9e3fbfb61669a403fe5ad0c6 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf460 RVA 0xabf460 | Evidence ev_c7fe6e3587bf7f9defe0a7d65b41e26ae6de3720ece1eddb2222be2fc3a842f5 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf510 RVA 0xabf510 | Evidence ev_d93df06e0aa0766b8610e6ba614d06f0acb395be773851680d68bddda5f4b65d | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf540 RVA 0xabf540 | Evidence ev_918f5feab5e8aadfd8bac1076658fe4bde79dbd34d89d5d4e0e412f387801228 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf570 RVA 0xabf570 | Evidence ev_054a0ea8af0834f949fbd0b838e11c80f4b54303cea77c47ab7bb82156f63489 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf5e0 RVA 0xabf5e0 | Evidence ev_6408a80daa750bd6e5fe4ddea25f72259b6864803d69929d8cf6a64ec96a4a0d | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
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




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_abf8e0 RVA 0xabf8e0 | Evidence ev_afedb27937d64eb5d0dfe1ddc3ae082009dbb6b23b1bfb13365216a5ca925195 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_674.body.bin SHA256 f380bc90ee293463e4ecb67094492662c1abf5a491536cc6ca1ad323d6d2cffe =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xabf8e0", "end": "0xabf97e"}], "total_bytes": 159, "span_bytes": 159, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_abf8e0(long param_1)

{
  char *pcVar1;
  char in_R8B;
  
  func_0x0025d410(0x1291c0e,0x129bd7c,*(undefined4 *)(param_1 + 8));
  func_0x0025d410(0x1362125,0x129bd7c,*(undefined4 *)(param_1 + 0xc));
  func_0x0025d410(0x1380c58,0x129bd7c,*(undefined4 *)(param_1 + 0x10));
  func_0x0025d410(0x1273c12,0x129bd7c,*(undefined4 *)(param_1 + 0x14));
  func_0x0025d410(0x12a630b,0x129bd7c,*(undefined4 *)(param_1 + 0x18));
  pcVar1 = (char *)func_0x0025d410(0x131863e,0x129bd7c,0,*(undefined4 *)(param_1 + 0x1c));
  *pcVar1 = *pcVar1 + in_R8B;
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
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




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): zero_fill_helper RVA 0x258ff0 | Evidence ev_9f715f53ca8e7945dcf5dd090a09697d620766198f5ec9c1ad147fd5676b3ea0 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/common_support.functions/0x258ff0.json | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/common_support.elf SHA256 843fa164383f956095dc4042a013c49d64f59c358ea7f43c10f0d9923485fd5a =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x258ff0", "end": "0x259031"}], "total_bytes": 66, "span_bytes": 66, "non_contiguous": false, "contains_entry": true}
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


