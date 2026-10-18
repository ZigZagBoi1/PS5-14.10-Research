/* Handler 667: REA6.7.0 / Ghidra12.1.4 recovered pseudocode, not original or buildable C.
 * Original4096-byte input SHA256 76916c6277404292f362d87da356811c8f660568d17f97536b15041696d3b53d
 * Raw entry RVA 0x265f88 -> actual target 0x4a31a0. narg=2.
 * Kernel RVAs; runtime VA=0xffffffff8a9c0000+RVA. Opaque externals/data remain unknown.
 * Analyst types below are inferred from accesses. Recovered pseudocode is retained verbatim afterward.
 * Original entry is an assembly-verified tail JMP to the target above. An engine halt_baddata
 * at that unmapped edge is a decompiler boundary artifact, not a recovered halt operation.
 */
#include <stdint.h>

/* ===== Analyst recovered interface/types ===== */
struct handler_667_args { void *records; int32_t *capacity_in_count_out; };
struct handler_667_record { uint32_t process_id_candidate; uint32_t thread_id_candidate; uint64_t value_5b0, value_5b8, value_5c0, value_5c8; };
/* sizeof(record)=40; the four value names preserve observed source offsets rather than invent semantics. */


/* ===== ORIGINAL ENTRY: <EXTERNAL>::thunk_EXT_FUN_004a31a0 RVA 0x265f88 | Evidence ev_945b3fa14b1db0a237666aa1ef10aca1f595f78b99b753ebbabe64580e66fdd9 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.raw.dossier.json | Source /tmp/rea-646-676-5b61b6f2/raw_union.bin SHA256 352988f408bc976411feddb3ef6cd2b18459d2aa3fa6dfd7f2e4a7fe416ce915 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x265f88", "end": "0x265f8c"}], "total_bytes": 5, "span_bytes": 5, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_004a31a0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}




/* ===== TARGET: handler_667_body RVA 0x4a31a0 | Evidence ev_5c6f3d82be891f04e277b0b9855430becdd8c003a447b3ae38846b1f3d033af1 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.bin SHA256 df8542b3b0477cbd17a978023a797cc26ad67a2c17868054a15dcde1e45daab9 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x4a31a0", "end": "0x4a3287"}, {"start": "0x4a3290", "end": "0x4a3388"}, {"start": "0x4a3390", "end": "0x4a3506"}, {"start": "0x4a3510", "end": "0x4a3559"}, {"start": "0x4a3560", "end": "0x4a3620"}], "total_bytes": 1123, "span_bytes": 1153, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int handler_667_body(long param_1,long *param_2)

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
  int local_7c;
  long local_78;
  ulong local_70;
  long *local_68;
  undefined4 local_60;
  undefined8 local_58;
  ulong local_50;
  undefined8 local_48;
  long local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  iVar3 = func_0x00608f90(*(undefined8 *)(param_1 + 0x140));
  if (iVar3 == 0) {
    iVar3 = 0x4e;
    goto LAB_004a3602;
  }
  if (*param_2 == 0) {
    iVar5 = 0;
    func_0x00c4b350(0x3589e60,0,0,0);
    if (_DAT_03589e80 != (long *)0x0) {
      iVar5 = 0;
      plVar11 = _DAT_03589e80;
      do {
        func_0x004c6a00(plVar11 + 0x29,0,0,0);
        if ((1 < *(uint *)(plVar11 + 0xba)) && ((int)plVar11[0x17] == 1)) {
          for (plVar8 = (long *)plVar11[2]; plVar8 != (long *)0x0; plVar8 = (long *)plVar8[2]) {
            func_0x004c78b0(plVar8,0,0x12aa1cd);
            if ((plVar8[0xb6] != 0) || (plVar8[0xb8] != 0)) {
              iVar5 = iVar5 + 1;
            }
            func_0x004c7520(*plVar8 + 0x18,0,0);
          }
        }
        func_0x004c6fa0(plVar11 + 0x29,0,0);
        plVar11 = (long *)*plVar11;
      } while (plVar11 != (long *)0x0);
    }
    func_0x00c4c300(0x3589e60,0,0);
  }
  else {
    iVar4 = func_0x00782a40(param_2[1]);
    if (iVar4 == -1) {
      iVar3 = 0xe;
      goto LAB_004a3602;
    }
    iVar3 = 0x16;
    if (iVar4 - 0x2711U < 0xffffd8f0) goto LAB_004a3602;
    local_78 = *param_2;
    iVar5 = 0;
    local_70 = (ulong)(uint)(iVar4 * 0x28);
    local_68 = &local_78;
    local_60 = 1;
    local_58 = 0;
    local_48 = 0;
    local_50 = local_70;
    local_40 = param_1;
    func_0x00c4b350(0x3589e60,0,0,0);
    if (_DAT_03589e80 != (long *)0x0) {
      iVar5 = 0;
      plVar11 = _DAT_03589e80;
      do {
        plVar8 = plVar11 + 0x29;
        func_0x004c6a00(plVar8,0,0,0);
        if ((1 < *(uint *)(plVar11 + 0xba)) && ((int)plVar11[0x17] == 1)) {
LAB_004a32da:
          lVar2 = plVar11[0x169];
          func_0x004c6fa0(plVar8,0,0);
          puVar6 = (undefined4 *)func_0x00c08b50((long)(int)lVar2 * 0x28,0x1ac8120,0x102);
          func_0x004c6a00(plVar8,0,0,0);
          if ((int)lVar2 < (int)plVar11[0x169]) goto code_r0x004a3321;
          func_0x004c7190(plVar11 + 7,0,0);
          plVar9 = (long *)plVar11[2];
          if (plVar9 == (long *)0x0) {
            uVar10 = 0;
          }
          else {
            local_7c = 0;
            puVar7 = puVar6;
            do {
              func_0x004c78b0(plVar9,0,0x12aa1cd);
              if ((plVar9[0xb6] == 0) && (plVar9[0xb8] == 0)) {
                func_0x004c7520(*plVar9 + 0x18,0,0);
              }
              else {
                *puVar7 = *(undefined4 *)((long)plVar11 + 0xbc);
                puVar7[1] = *(undefined4 *)((long)plVar9 + 0x9c);
                *(long *)(puVar7 + 2) = plVar9[0xb6];
                *(long *)(puVar7 + 4) = plVar9[0xb7];
                *(long *)(puVar7 + 6) = plVar9[0xb8];
                *(long *)(puVar7 + 8) = plVar9[0xb9];
                func_0x004c7520(*plVar9 + 0x18,0,0);
                local_7c = local_7c + 1;
                puVar7 = puVar7 + 10;
                iVar5 = iVar5 + 1;
              }
              plVar9 = (long *)plVar9[2];
            } while (plVar9 != (long *)0x0);
            uVar10 = (long)local_7c * 0x28;
          }
          func_0x004c7520(plVar11 + 7,0,0);
          func_0x004c6fa0(plVar8,0,0);
          if (local_50 < uVar10) {
            uVar10 = local_50;
          }
          iVar3 = func_0x00782520(puVar6,uVar10 & 0xffffffff,&local_68);
          func_0x00c08df0(puVar6);
          if (iVar3 != 0) {
            func_0x00c4c300(0x3589e60,0,0);
            goto LAB_004a3602;
          }
          goto LAB_004a329e;
        }
LAB_004a3290:
        func_0x004c6fa0(plVar8,0,0);
LAB_004a329e:
        plVar11 = (long *)*plVar11;
      } while (plVar11 != (long *)0x0);
    }
    func_0x00c4c300(0x3589e60,0,0);
  }
  iVar5 = func_0x00259790(param_2[1],iVar5);
  iVar3 = 0xe;
  if (iVar5 == 0) {
    iVar3 = 0;
  }
LAB_004a3602:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar1 = (code *)invalidInstructionException();
    (*pcVar1)();
  }
  return iVar3;
code_r0x004a3321:
  func_0x004c6fa0(plVar8,0,0);
  func_0x00c08df0(puVar6);
  func_0x004c6a00(plVar8,0,0,0);
  if ((int)plVar11[0x17] != 1) goto LAB_004a3290;
  goto LAB_004a32da;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_4a3630 RVA 0x4a3630 | Evidence ev_1f2eb6ebfb7f6cd0b7f2115c5232ee01e5c81e30f370e816985f23c6a15cc824 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.bin SHA256 df8542b3b0477cbd17a978023a797cc26ad67a2c17868054a15dcde1e45daab9 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x4a3630", "end": "0x4a3635"}], "total_bytes": 6, "span_bytes": 6, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_4a3630(void)

{
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_4a3640 RVA 0x4a3640 | Evidence ev_19188f123cd393ef691d3b4b12fec0cb2cfa3a6206f54f072cf7edf687e0622d | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.bin SHA256 df8542b3b0477cbd17a978023a797cc26ad67a2c17868054a15dcde1e45daab9 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x4a3640", "end": "0x4a37f2"}], "total_bytes": 435, "span_bytes": 435, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong sub_4a3640(long param_1,long param_2)

{
  code *pcVar1;
  uint uVar2;
  ulong uVar3;
  bool bVar4;
  long local_38;
  long local_30;
  long local_28;
  
  local_28 = _DAT_0391c310;
  local_38 = 0;
  *(undefined2 *)(*(long *)(param_1 + 0x340) + 0xc) = 0;
  if (param_2 == 0) {
    uVar3 = func_0x005aafb0(param_1,*(undefined8 *)(param_1 + 0x378),0);
    if ((int)uVar3 != 0) goto LAB_004a37d8;
    uVar3 = func_0x00593190((long *)(param_1 + 0x2e0),param_1);
    if ((int)uVar3 != 0) goto LAB_004a37d8;
    local_30 = *(long *)(param_1 + 0x2e0);
  }
  else {
    uVar2 = func_0x00b56140(&local_30,param_1);
    if (uVar2 != 0) {
      uVar3 = (ulong)uVar2;
      func_0x006f7a90(0x1593014,0x6f,uVar2,0x13afe9f);
      goto LAB_004a37d8;
    }
  }
  if (local_30 == 0) {
    func_0x006f79f0(0x1593014,0x88,0x1351368,0,param_1);
    uVar3 = 0x3002;
  }
  else {
    uVar2 = func_0x0032b460(local_30,&local_38,0x10);
    uVar3 = (ulong)uVar2;
    if (uVar2 == 0) {
      if (*(char *)(local_38 + 9) == '\x01') {
        func_0x009bd8b0();
        bVar4 = *(long *)(local_38 + 0x10) != 0;
        uVar3 = 0x4005;
        if (bVar4) {
          uVar3 = 0;
        }
        *(ushort *)(*(long *)(param_1 + 0x340) + 10) = (ushort)bVar4;
        func_0x005aaca0(local_38,param_1,1);
      }
      else {
        func_0x006f79f0(0x1593014,0x9b,0x13667db,local_30,param_1,*(undefined1 *)(local_30 + 9));
        uVar3 = 0x3003;
      }
    }
    if (local_38 != local_30) {
      func_0x00b4a4c0(local_38);
    }
    func_0x00b4a4c0(local_30);
    *(undefined2 *)(*(long *)(param_1 + 0x340) + 0xc) = 0xc0;
  }
LAB_004a37d8:
  if (_DAT_0391c310 == local_28) {
    return uVar3;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_4a3800 RVA 0x4a3800 | Evidence ev_2f870266df1e881129aa7d3033b1f1858c4380272d1dce85d7add9363d93af32 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.bin SHA256 df8542b3b0477cbd17a978023a797cc26ad67a2c17868054a15dcde1e45daab9 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x4a3800", "end": "0x4a3940"}], "total_bytes": 321, "span_bytes": 321, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Possible PIC construction at 0x004a3892: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x004a3897) */
/* WARNING: Removing unreachable block (ram,0x004a38cc) */
/* WARNING: Removing unreachable block (ram,0x004a38fc) */
/* WARNING: Removing unreachable block (ram,0x004a3908) */
/* WARNING: Removing unreachable block (ram,0x004a389b) */
/* WARNING: Removing unreachable block (ram,0x004f1c00) */

undefined8 sub_4a3800(long param_1,long *param_2)

{
  long lVar1;
  long lVar2;
  char cVar3;
  
  lVar1 = *(long *)(param_1 + 0x378);
  if (lVar1 == 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  if (lVar1 == *(long *)(param_1 + 0x388)) {
    if (param_2 != (long *)0x0) {
      *param_2 = lVar1;
    }
  }
  else {
    lVar2 = *(long *)(param_1 + 0x340);
    if ((lVar2 != 0) && (*(short *)(lVar2 + 0xc) == 0xc1)) {
      *(undefined2 *)(lVar2 + 0xc) = 0xc2;
      *(long *)(*(long *)(param_1 + 0x340) + 0x10) = lVar1;
    }
    cVar3 = '\x03';
    if (*(short *)(lVar1 + 10) != 0x2d) {
      cVar3 = *(char *)(*(long *)(param_1 + 0x380) + 0xb);
    }
    if (cVar3 == '\x03') {
      if ((*(byte *)(param_1 + 9) & 1) != 0) {
        if (*(short *)(lVar1 + 10) != 0x10) {
          halt_baddata();
        }
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
    }
    else if (cVar3 == '\x04') {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
  }
  return 0;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_4a3950 RVA 0x4a3950 | Evidence ev_89522e11c87561c0959626e768a735e724dd456d16f0e4093c791206d4049710 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.bin SHA256 df8542b3b0477cbd17a978023a797cc26ad67a2c17868054a15dcde1e45daab9 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x4a3950", "end": "0x4a3a1d"}, {"start": "0x4a3a36", "end": "0x4a3aff"}, {"start": "0x4a3b56", "end": "0x4a3b86"}, {"start": "0x4a3c48", "end": "0x4a3cf8"}, {"start": "0x4a3d63", "end": "0x4a3dbe"}, {"start": "0x4a3dc6", "end": "0x4a3dd9"}], "total_bytes": 746, "span_bytes": 1162, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_4a3950(long param_1)

{
  char cVar1;
  byte bVar2;
  long lVar3;
  long lVar4;
  code *pcVar5;
  long lVar6;
  short sVar7;
  int iVar8;
  undefined8 uVar9;
  
  lVar3 = *(long *)(param_1 + 0x378);
  cVar1 = *(char *)(*(long *)(param_1 + 0x380) + 0xb);
  if (cVar1 == '\n') {
    func_0x006f79f0(0x1593014,0x199,0x12779d2,*(undefined2 *)(lVar3 + 10));
    return 0xe;
  }
  bVar2 = *(byte *)(*(long *)(param_1 + 0x380) + 0xc);
  uVar9 = *(undefined8 *)(lVar3 + 0x28);
  *(undefined2 *)(param_1 + 0xd) = 0;
  *(undefined8 *)(param_1 + 0x3a0) = 0;
  *(undefined8 *)(param_1 + 0x390) = 0;
  if (cVar1 == '\0') {
    iVar8 = func_0x005ab210(param_1,uVar9);
    if (iVar8 == 0) {
      if (((*(byte *)(*(long *)(param_1 + 0x380) + 9) & 0x40) == 0) &&
         (iVar8 = func_0x00ab7700(*(undefined2 *)(param_1 + 10),
                                  param_1 + 0x2d8 + (ulong)*(byte *)(param_1 + 0xd) * 8,param_1),
         iVar8 != 0)) {
        if (iVar8 != 0x3005) {
          sVar7 = *(short *)(param_1 + 10);
LAB_004a3c4c:
          uVar9 = func_0x00bb3d60(sVar7);
          func_0x006f7a90(0x1593014,0x1f1,iVar8,0x12779e6,uVar9);
          goto LAB_004a3c74;
        }
        sVar7 = *(short *)(param_1 + 10);
        if (sVar7 != 0x70) goto LAB_004a3c4c;
        lVar6 = *(long *)(param_1 + 0x2e0);
        sVar7 = 0x70;
        if ((((*(char *)(lVar6 + 9) != '\x14') ||
             (lVar4 = *(long *)(param_1 + 0x2e8), *(char *)(lVar4 + 9) != '\x14')) ||
            (*(char *)(lVar6 + 0xd) != *(char *)(lVar4 + 0xd))) ||
           (*(int *)(lVar6 + 0x30) != *(int *)(lVar4 + 0x30))) goto LAB_004a3c4c;
        func_0x005aaf60(param_1);
      }
      else {
        pcVar5 = *(code **)((ulong)bVar2 * 8 + 0xe7f820);
        if (0x37 < (-(long)pcVar5 + 0x269d78U >> 3 | -(long)pcVar5 << 0x3d)) {
          func_0x0044f8c0(0x1ac8160,pcVar5);
        }
        iVar8 = (*pcVar5)(param_1);
LAB_004a3c74:
        func_0x005aaf60(param_1);
        if (iVar8 != 0) goto LAB_004a3c81;
      }
      if (*(long *)(param_1 + 0x390) == 0) goto LAB_004a3ca2;
      iVar8 = func_0x00b56250(*(long *)(param_1 + 0x390),param_1);
      func_0x009bd8b0(*(undefined8 *)(param_1 + 0x390));
      if (iVar8 == 0) goto LAB_004a3cae;
    }
  }
  else if (cVar1 == '\x02') {
    if ((*(short *)(param_1 + 10) == 0x2d) && (iVar8 = func_0x005ab320(param_1), iVar8 != 0))
    goto LAB_004a3d83;
LAB_004a3ca2:
    func_0x009bd8b0(*(undefined8 *)(param_1 + 0x390));
LAB_004a3cae:
    lVar6 = *(long *)(param_1 + 0x340);
    iVar8 = 0;
    if (((lVar6 != 0) && (*(short *)(lVar6 + 0xc) == 0xc2)) &&
       (iVar8 = 0, *(long *)(lVar6 + 0x10) == lVar3)) {
      iVar8 = sub_4a3640(param_1,*(undefined8 *)(param_1 + 0x390));
      *(undefined8 *)(param_1 + 0x390) = 0;
      goto LAB_004a3d9a;
    }
  }
  else {
    if (bVar2 - 0x10 < 0xb) {
                    /* WARNING: Could not emulate address calculation at 0x004a3a15 */
                    /* WARNING: Treating indirect jump as call */
      uVar9 = (*(code *)((long)*(int *)((ulong)(bVar2 - 0x10) * 4 + 0x1592fe8) + 0x1592fe8))();
      return uVar9;
    }
    func_0x006f79f0(0x1593014,0x2d3,0x128b6f8,cVar1,(ulong)bVar2,*(undefined2 *)(lVar3 + 10),lVar3);
    iVar8 = 0xe;
LAB_004a3c81:
    func_0x009bd8b0(*(undefined8 *)(param_1 + 0x390));
  }
LAB_004a3d83:
  if (*(long *)(param_1 + 0x390) != 0) {
    func_0x005aae70(lVar3,*(long *)(param_1 + 0x390),param_1);
  }
LAB_004a3d9a:
  if (iVar8 == 0) {
    uVar9 = 0;
  }
  else {
    uVar9 = func_0x004f1c00(iVar8,param_1);
  }
  *(undefined1 *)(param_1 + 0xd) = 0;
  return uVar9;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_4a3de0 RVA 0x4a3de0 | Evidence ev_46f1e5f06488afbfe0e706522d68c729f59bc5b8e4580a6f5bdd939236ff3543 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.bin SHA256 df8542b3b0477cbd17a978023a797cc26ad67a2c17868054a15dcde1e45daab9 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x4a3de0", "end": "0x4a3e49"}], "total_bytes": 106, "span_bytes": 106, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

uint sub_4a3de0(long param_1,long param_2,uint param_3)

{
  int iVar1;
  uint uVar2;
  long lVar3;
  
  if (param_2 != 0) {
    lVar3 = 0;
    do {
      iVar1 = *(int *)(param_1 + lVar3 * 4);
      lVar3 = lVar3 + 1;
      param_3 = ((uint)(iVar1 * -0x3361d2af) >> 0x11 | iVar1 * 0x16a88000) * 0x1b873593 ^ param_3;
      param_3 = (param_3 >> 0x13 | param_3 << 0xd) * 5 + 0xe6546b64;
    } while (param_2 != lVar3);
  }
  param_3 = (uint)param_2 ^ param_3;
  uVar2 = (param_3 >> 0x10 ^ param_3) * -0x7a143595;
  uVar2 = (uVar2 >> 0xd ^ uVar2) * -0x3d4d51cb;
  return uVar2 >> 0x10 ^ uVar2;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_4a3e50 RVA 0x4a3e50 | Evidence ev_aba9ed87a218b14ac7690431cb062731e5b0f5f81c212fa9ba3b07917a089031 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.bin SHA256 df8542b3b0477cbd17a978023a797cc26ad67a2c17868054a15dcde1e45daab9 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x4a3e50", "end": "0x4a3fb5"}], "total_bytes": 358, "span_bytes": 358, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

double sub_4a3e50(undefined8 param_1,double param_2,double param_3)

{
  int iVar1;
  ulong uVar2;
  uint uVar3;
  double dVar4;
  double dVar5;
  undefined1 in_ZMM0 [64];
  
  dVar4 = in_ZMM0._0_8_;
  uVar3 = in_ZMM0._4_4_ & 0x7fffffff;
  if (uVar3 < 0x40900000) {
    if (uVar3 < 0x3c900000) {
      return dVar4 + _DAT_013ba6e0;
    }
  }
  else {
    if (0x7fefffff < uVar3) {
      dVar5 = dVar4 + dVar4;
      if ((in_ZMM0._4_4_ & 0xfffff) == 0 && in_ZMM0._0_4_ == 0) {
        dVar5 = 0.0;
      }
      if (-1 < (long)dVar4) {
        return dVar4 + dVar4;
      }
      return dVar5;
    }
    if (_DAT_013bab30 <= dVar4) {
      return _DAT_013ba588;
    }
    dVar5 = _DAT_01ac8180;
    if (dVar4 <= _DAT_013bab00) goto LAB_004a3fac;
  }
  uVar3 = SUB84(dVar4 + _DAT_013bacf0,0) + 0x80;
  uVar2 = (ulong)((uVar3 & 0xff) << 4);
  uVar3 = uVar3 & 0xfff00;
  iVar1 = uVar3 * 0x1000;
  dVar5 = (dVar4 - (dVar4 + _DAT_013bacf0 + _DAT_013bac60)) - *(double *)(uVar2 + 0x1593038);
  dVar4 = *(double *)(uVar2 + 0x1593030);
  if (iVar1 < -0x3fd00000) {
    param_3 = (double)((ulong)(iVar1 + 0x7e700000) << 0x20);
  }
  else {
    param_2 = (double)((ulong)(iVar1 + 0x3ff00000) << 0x20);
  }
  dVar4 = dVar4 + dVar4 * dVar5 *
                  (dVar5 * (dVar5 * (dVar5 * (dVar5 * _DAT_013ba4d8 + _DAT_013bacf8) + _DAT_013ba590
                                    ) + _DAT_013ba670) + _DAT_013baaa0);
  if (-0x3fd00001 < iVar1) {
    if (uVar3 == 0x40000) {
      return (dVar4 + dVar4) * _DAT_013ba8a0;
    }
    return dVar4 * param_2;
  }
  dVar5 = dVar4 * param_3;
LAB_004a3fac:
  return dVar5 * _DAT_01ac8180;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_4a3fc0 RVA 0x4a3fc0 | Evidence ev_9e33f6283fc4e31bd266d29b808c698c63d163cd1ef6ccdcc1da3a48b398de60 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.bin SHA256 df8542b3b0477cbd17a978023a797cc26ad67a2c17868054a15dcde1e45daab9 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x4a3fc0", "end": "0x4a4428"}], "total_bytes": 1129, "span_bytes": 1129, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_4a3fc0(long param_1,long param_2)

{
  char cVar1;
  uint uVar2;
  uint uVar3;
  char *pcVar4;
  code *pcVar5;
  undefined2 uVar6;
  short sVar7;
  ushort uVar8;
  int iVar9;
  ulong uVar10;
  char cVar11;
  undefined8 uVar12;
  ushort *puVar13;
  long lVar14;
  undefined8 local_50 [2];
  ushort local_3a;
  long local_38;
  
  local_38 = _DAT_0391c310;
  lVar14 = *(long *)(param_1 + 0x48);
  uVar2 = *(uint *)(param_1 + 0x78);
  func_0x00acf740(local_50);
  if ((*(byte *)(param_1 + 0x78) & 1) != 0) {
    func_0x004bbf00(param_1,5,*(int *)(lVar14 + 0x84) + *(int *)(param_2 + 0x30));
    *(undefined8 *)(lVar14 + 0xf0) = local_50[0];
  }
  uVar3 = *(uint *)(param_2 + 0x30);
  if (uVar3 < 5) {
    func_0x0025d410(0x12c958b,param_1 + 0x60);
    goto LAB_004a403a;
  }
  if ((*(int *)(param_2 + 0x18) < (int)uVar3) &&
     (param_2 = func_0x00a19150(param_2,uVar3), param_2 == 0)) goto LAB_004a4066;
  pcVar4 = *(char **)(param_2 + 0x10);
  if ((*(byte *)(lVar14 + 0x80) & 0x20) == 0) {
    puVar13 = (ushort *)(pcVar4 + 2);
    func_0x00a19060(param_2,4);
    cVar11 = *pcVar4;
    if ((cVar11 == '\x0f') || (cVar11 == -0x71)) {
      if ((*(byte *)(lVar14 + 0x80) & 2) != 0) {
        sVar7 = CONCAT11((char)*puVar13,(char)(*puVar13 >> 8));
        if (sVar7 == 0x800) goto LAB_004a428a;
        if (sVar7 == -0x7fcb) {
          sub_4a4430(param_1,param_2);
          func_0x0042a850(param_2);
          goto LAB_004a4066;
        }
        func_0x004bbf00(param_1,0xb,1);
        cVar11 = *pcVar4;
        goto LAB_004a439f;
      }
      if ((uVar2 & 4) == 0) goto LAB_004a403a;
      uVar6 = CONCAT11((char)*(undefined2 *)(pcVar4 + 2),
                       (char)((ushort)*(undefined2 *)(pcVar4 + 2) >> 8));
      cVar1 = pcVar4[1];
      uVar12 = 0x12e86c3;
    }
    else {
      if ((cVar11 == -1) && (cVar11 = -1, pcVar4[1] == '\x03')) {
        if ((*(byte *)(lVar14 + 0x80) & 2) == 0) {
          uVar8 = *puVar13;
          local_3a = CONCAT11((char)uVar8,(char)(uVar8 >> 8));
          uVar8 = uVar8 << 8 | uVar8 >> 8;
          goto LAB_004a4143;
        }
        if ((uVar2 & 4) != 0) {
          func_0x0025d410(0x12aa20d,param_1 + 0x60,0xff,3,
                          CONCAT11((char)*puVar13,(char)(*puVar13 >> 8)));
        }
        goto LAB_004a403a;
      }
LAB_004a439f:
      uVar6 = CONCAT11((char)*(undefined2 *)(pcVar4 + 2),
                       (char)((ushort)*(undefined2 *)(pcVar4 + 2) >> 8));
      cVar1 = pcVar4[1];
      uVar12 = 0x1366818;
    }
    func_0x0025d410(uVar12,param_1 + 0x60,cVar11,cVar1,uVar6);
LAB_004a403a:
    func_0x004bbf00(param_1,1,1);
    func_0x004bbf00(param_1,9,1);
  }
  else {
    func_0x002590b0(&local_3a,pcVar4,2);
    local_3a = CONCAT11((char)local_3a,(char)(local_3a >> 8));
    puVar13 = *(ushort **)(param_2 + 0x10);
    func_0x00a19060(param_2,2);
    uVar8 = local_3a;
LAB_004a4143:
    if (uVar8 < 0xc021) {
      if (uVar8 == 0x21) {
        func_0x00acf740(local_50);
        if (*(int *)(lVar14 + 0x130) == 9) {
          *(undefined8 *)(lVar14 + 0x100) = local_50[0];
LAB_004a428a:
          if ((*(byte *)(param_1 + 0x78) & 1) != 0) {
            lVar14 = lVar14 + 0x188;
            func_0x004c6a00(lVar14,0,0,0);
            iVar9 = func_0x002f82c0(1,param_2);
            if (iVar9 == 0) {
              func_0x004c6fa0(lVar14,0,0,0);
            }
            else {
              func_0x0025d410(0x1277a08,param_1 + 0x60);
              func_0x004c6fa0(lVar14,0,0,0);
              func_0x004bbf00(param_1,1,1);
              func_0x004bbf00(param_1,9,1);
            }
            goto LAB_004a4066;
          }
        }
      }
      else {
        if (uVar8 == 0x8021) {
          if (*(int *)(lVar14 + 0x118) == 4) {
            uVar12 = 0xe7fa90;
            goto LAB_004a423a;
          }
          goto LAB_004a405e;
        }
LAB_004a429d:
        if (*(int *)(lVar14 + 300) == 9) {
          uVar10 = *(long *)(lVar14 + 0x98) + 1;
          *(ulong *)(lVar14 + 0x98) = uVar10;
          sub_4a4650(lVar14,0xc021,8,uVar10 & 0xff,*(int *)(param_2 + 0x30) + 2U & 0xffff,puVar13);
          uVar8 = local_3a;
        }
        func_0x0025d410(0x131cc1b,param_1 + 0x60,uVar8 << 8 | uVar8 >> 8);
        func_0x004bbf00(param_1,0xb,1);
      }
      goto LAB_004a403a;
    }
    if (uVar8 == 0xc021) {
      uVar12 = 0xe7f880;
LAB_004a423a:
      sub_4a4a40(uVar12,lVar14,param_2);
    }
    else if (uVar8 == 0xc023) {
      if (2 < *(int *)(lVar14 + 0x118)) {
        sub_4a5d70(lVar14,param_2);
      }
    }
    else {
      if (uVar8 != 0xc223) goto LAB_004a429d;
      if (2 < *(int *)(lVar14 + 0x118)) {
        sub_4a63b0(lVar14,param_2);
      }
    }
  }
LAB_004a405e:
  func_0x0042a850(param_2);
LAB_004a4066:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar5 = (code *)invalidInstructionException();
    (*pcVar5)();
  }
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_4a4430 RVA 0x4a4430 | Evidence ev_8d3fec92029b9eba5e0e1ede84e7772918e9c7927dc651b505b92f70ed7cb55f | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.bin SHA256 df8542b3b0477cbd17a978023a797cc26ad67a2c17868054a15dcde1e45daab9 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x4a4430", "end": "0x4a4603"}, {"start": "0x4a4610", "end": "0x4a4643"}], "total_bytes": 520, "span_bytes": 532, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Possible PIC construction at 0x004a44b6: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x004a44bb) */

void sub_4a4430(long *param_1,long param_2)

{
  undefined4 uVar1;
  uint uVar2;
  long lVar3;
  undefined4 *puVar4;
  long *plVar5;
  long lVar6;
  int iVar7;
  uint uVar8;
  ulong uVar9;
  
  lVar3 = *param_1;
  if (0x11 < *(int *)(param_2 + 0x30)) {
    puVar4 = *(undefined4 **)(param_2 + 0x10);
    if ((*(uint *)(lVar3 + 0x78) & 4) == 0) {
      uVar1 = *puVar4;
      iVar7 = CONCAT13((char)uVar1,
                       CONCAT12((char)((uint)uVar1 >> 8),
                                CONCAT11((char)((uint)uVar1 >> 0x10),(char)((uint)uVar1 >> 0x18))));
      if (iVar7 == 0) {
        for (plVar5 = *(long **)(*param_1 + 0x280); uVar8 = 0, plVar5 != (long *)0x0;
            plVar5 = (long *)plVar5[5]) {
          if (*(char *)(*plVar5 + 1) == '\x02') {
            uVar2 = *(uint *)(*plVar5 + 4);
            uVar8 = 0;
            if (uVar2 != 0) {
              uVar8 = uVar2;
            }
            break;
          }
        }
        if (((uVar8 >> 0x18 != 0 || (uVar8 & 0xff0000) != 0) || (uVar8 & 0xff00) != 0) ||
            (uVar8 & 0xff) != 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
      }
      else if (iVar7 != 1) {
        if (iVar7 == 2) {
          *(undefined4 *)(param_1 + 0x11) = 0;
          uVar1 = puVar4[1];
          uVar9 = (ulong)CONCAT13((char)uVar1,
                                  CONCAT12((char)((uint)uVar1 >> 8),
                                           CONCAT11((char)((uint)uVar1 >> 0x10),
                                                    (char)((uint)uVar1 >> 0x18))));
          param_1[0x18] = uVar9;
          if (param_1[0x13] == uVar9) {
            if (2 < *(uint *)((long)param_1 + 0x8c)) {
              func_0x0025d410(0x12a054b,lVar3 + 0x60);
              *(undefined4 *)((long)param_1 + 0x8c) = 0;
              if ((*(byte *)(lVar3 + 0x78) & 1) != 0) {
                func_0x004bd120(lVar3);
                while (lVar3 = param_1[8], lVar3 != 0) {
                  lVar6 = *(long *)(lVar3 + 8);
                  param_1[8] = lVar6;
                  if (lVar6 == 0) {
                    param_1[9] = 0;
                  }
                  *(undefined8 *)(lVar3 + 8) = 0;
                  *(int *)(param_1 + 10) = (int)param_1[10] + -1;
                  func_0x0042a850();
                }
              }
            }
            *(int *)((long)param_1 + 0x8c) = *(int *)((long)param_1 + 0x8c) + 1;
            uVar8 = func_0x00992cd0();
            param_1[0x13] = (ulong)uVar8;
          }
          else {
            *(undefined4 *)((long)param_1 + 0x8c) = 0;
            if ((*(uint *)(lVar3 + 0x78) & 0x41) == 0x40) {
                    /* WARNING: Bad instruction - Truncating control flow here */
              halt_baddata();
            }
          }
        }
        else if ((*(uint *)(lVar3 + 0x78) & 4) != 0) {
          halt_baddata();
        }
      }
      return;
    }
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_4a4650 RVA 0x4a4650 | Evidence ev_aaf9e4f999f984677ad334d89d6ca364779db1c046a72dd447ccc96d1e980e8a | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.bin SHA256 df8542b3b0477cbd17a978023a797cc26ad67a2c17868054a15dcde1e45daab9 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x4a4650", "end": "0x4a4a35"}], "total_bytes": 998, "span_bytes": 998, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_4a4650(long *param_1,uint param_2,char param_3,char param_4,uint param_5,undefined8 param_6
               )

{
  uint uVar1;
  long lVar2;
  undefined2 *puVar3;
  code *pcVar4;
  undefined1 uVar5;
  uint uVar6;
  long lVar7;
  int iVar8;
  undefined8 uVar9;
  uint uVar10;
  int iVar11;
  char *pcVar12;
  undefined8 uVar13;
  long lVar14;
  short local_4c;
  undefined4 local_40;
  undefined2 local_3c;
  long local_38;
  
  local_38 = _DAT_0391c310;
  lVar2 = *param_1;
  uVar1 = *(uint *)(lVar2 + 0x78);
  local_40 = 2;
  local_3c = 1;
  uVar6 = (uint)((*(uint *)(param_1 + 0x10) & 0x20) == 0) * 2;
  uVar10 = uVar6 ^ 0x82;
  if (param_5 <= uVar10) {
    uVar10 = param_5;
  }
  lVar7 = func_0x0043b880(_DAT_034f5020,&local_40,1);
  pcVar4 = _DAT_01a9bf28;
  if (_DAT_02566c58 != 0) {
    if (1 < (-(long)_DAT_01a9bf28 + 0x2681e8U >> 3 | -(long)_DAT_01a9bf28 << 0x3d)) {
      func_0x0044f8c0(0x1ac8450,_DAT_01a9bf28);
    }
    (*pcVar4)(_DAT_02566c58,1,1,lVar7,0,0);
  }
  if (lVar7 == 0) goto LAB_004a49a0;
  iVar8 = uVar10 + 4;
  iVar11 = uVar6 + 2 + iVar8;
  *(int *)(lVar7 + 0x18) = iVar11;
  *(int *)(lVar7 + 0x30) = iVar11;
  *(undefined8 *)(lVar7 + 0x20) = 0;
  uVar5 = (undefined1)(param_2 >> 8);
  if ((*(byte *)(param_1 + 0x10) & 0x20) == 0) {
    puVar3 = *(undefined2 **)(lVar7 + 0x10);
    *puVar3 = 0x3ff;
    puVar3[1] = CONCAT11((char)param_2,uVar5);
    pcVar12 = (char *)(puVar3 + 2);
  }
  else {
    **(undefined2 **)(lVar7 + 0x10) = CONCAT11((char)param_2,uVar5);
    pcVar12 = (char *)(*(long *)(lVar7 + 0x10) + 2);
  }
  local_4c = (short)param_5;
  *pcVar12 = param_3;
  pcVar12[1] = param_4;
  *(ushort *)(pcVar12 + 2) = CONCAT11((char)iVar8,(char)((uint)iVar8 >> 8));
  if (local_4c != 0) {
    func_0x00259be0(param_6,pcVar12 + 4,uVar10);
  }
  if ((uVar1 & 4) != 0) {
    param_2 = param_2 & 0xffff;
    if (param_2 < 0xc021) {
      if (param_2 == 0x8021) {
        uVar13 = 0x12b4b50;
      }
      else if (param_2 == 0x8057) {
        uVar13 = 0x131cc49;
      }
      else {
LAB_004a47e5:
        uVar13 = 0x35365d4;
        func_0x004aee40(0x35365d4,0xc,0x1383910);
      }
    }
    else if (param_2 == 0xc021) {
      uVar13 = 0x137098a;
    }
    else if (param_2 == 0xc023) {
      uVar13 = 0x12be8f2;
    }
    else {
      if (param_2 != 0xc223) goto LAB_004a47e5;
      uVar13 = 0x131cc44;
    }
    if ((byte)(*pcVar12 - 1U) < 0xb) {
      uVar9 = *(undefined8 *)((ulong)(byte)(*pcVar12 - 1U) * 8 + 0xe7fb60);
    }
    else {
      uVar9 = 0x3536610;
      func_0x004aee40(0x3536610,0xc,0x1383910);
    }
    func_0x0025d410(0x12fd358,lVar2 + 0x60,uVar13,uVar9,pcVar12[1],
                    CONCAT11((char)*(undefined2 *)(pcVar12 + 2),
                             (char)((ushort)*(undefined2 *)(pcVar12 + 2) >> 8)));
    if (local_4c != 0) {
      func_0x0025d410(0x13af03e,pcVar12[4]);
      if ((short)uVar10 != 1) {
        lVar14 = 0;
        do {
          func_0x0025d410(0x131cc50,pcVar12[lVar14 + 5]);
          lVar14 = lVar14 + 1;
        } while ((short)((short)uVar10 + -1) != (short)lVar14);
      }
    }
    func_0x0025d410(0x135c29e);
  }
  if ((int)param_1[10] < *(int *)((long)param_1 + 0x54)) {
    func_0x004c6a00(param_1 + 0xe,0,0,0);
    *(undefined8 *)(lVar7 + 8) = 0;
    if (param_1[9] == 0) {
      param_1[8] = lVar7;
    }
    else {
      *(long *)(param_1[9] + 8) = lVar7;
    }
    param_1[9] = lVar7;
    *(int *)(param_1 + 10) = (int)param_1[10] + 1;
    func_0x004c6fa0(param_1 + 0xe,0,0,0);
    if ((*(byte *)(lVar2 + 0x79) & 4) == 0) {
      pcVar4 = *(code **)(lVar2 + 0x498);
      if (0x8bc < (-(long)pcVar4 + 0x2652d0U >> 3 | -(long)pcVar4 << 0x3d)) {
        func_0x0044f8c0(0x1ac8570,pcVar4);
      }
      (*pcVar4)(lVar2);
    }
    iVar8 = *(int *)((long)param_1 + 0x84) + *(int *)(lVar7 + 0x30);
    uVar13 = 6;
  }
  else {
    func_0x004bbf00(lVar2,10,1);
    func_0x0042a850(lVar7);
    iVar8 = 1;
    uVar13 = 3;
  }
  func_0x004bbf00(lVar2,uVar13,iVar8);
LAB_004a49a0:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar4 = (code *)invalidInstructionException();
    (*pcVar4)();
  }
  return;
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_4a4a40 RVA 0x4a4a40 | Evidence ev_4a09755eb126d85ce01a2919371ab12252d9ea52fe11fd5cacbdd6ffb9c940be | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.bin SHA256 df8542b3b0477cbd17a978023a797cc26ad67a2c17868054a15dcde1e45daab9 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x4a4a40", "end": "0x4a4c2b"}, {"start": "0x4a4f51", "end": "0x4a4fc5"}, {"start": "0x4a50a4", "end": "0x4a50d0"}, {"start": "0x4a5c20", "end": "0x4a5c26"}], "total_bytes": 661, "span_bytes": 4583, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Possible PIC construction at 0x004a4b6f: Changing call to branch */
/* WARNING: Possible PIC construction at 0x004a4bba: Changing call to branch */
/* WARNING: Possible PIC construction at 0x004a4f78: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x004a4bbf) */
/* WARNING: Removing unreachable block (ram,0x004a4b74) */
/* WARNING: Removing unreachable block (ram,0x004a4b7e) */
/* WARNING: Removing unreachable block (ram,0x004a4bc8) */
/* WARNING: Removing unreachable block (ram,0x004a4b99) */
/* WARNING: Removing unreachable block (ram,0x004a4bb0) */
/* WARNING: Removing unreachable block (ram,0x004a4f7d) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_4a4a40(undefined2 *param_1,long *param_2,long param_3)

{
  undefined2 uVar1;
  uint uVar2;
  byte *pbVar3;
  long lVar4;
  long lVar5;
  ulong uVar6;
  uint uVar7;
  code *UNRECOVERED_JUMPTABLE;
  undefined8 uVar8;
  
  lVar5 = _DAT_0391c310;
  uVar2 = *(uint *)(param_3 + 0x30);
  if (3 < (int)uVar2) {
    pbVar3 = *(byte **)(param_3 + 0x10);
    if ((*(uint *)(*param_2 + 0x78) & 4) == 0) {
      uVar7 = (uint)CONCAT11((char)*(undefined2 *)(pbVar3 + 2),
                             (char)((ushort)*(undefined2 *)(pbVar3 + 2) >> 8));
      if (uVar2 < uVar7) {
        uVar7 = uVar2;
      }
      if (*pbVar3 - 1 < 0xb) {
        UNRECOVERED_JUMPTABLE =
             (code *)((long)*(int *)((ulong)(*pbVar3 - 1) * 4 + 0x1594030) + 0x1594030);
                    /* WARNING: Could not emulate address calculation at 0x004a4c23 */
                    /* WARNING: Treating indirect jump as call */
        (*UNRECOVERED_JUMPTABLE)(0x1594030,UNRECOVERED_JUMPTABLE,uVar7);
        return;
      }
      if ((*(uint *)(*param_2 + 0x78) & 4) == 0) {
        uVar1 = *param_1;
        lVar4 = param_2[(ulong)*(byte *)(param_1 + 1) + 0x13];
        param_2[(ulong)*(byte *)(param_1 + 1) + 0x13] = lVar4 + 1U;
        sub_4a4650(param_2,uVar1,7,lVar4 + 1U & 0xff,*(undefined2 *)(param_3 + 0x30),pbVar3);
        if (_DAT_0391c310 == lVar5) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        func_0x006fd6b0();
                    /* WARNING: Does not return */
        UNRECOVERED_JUMPTABLE = (code *)invalidInstructionException();
        (*UNRECOVERED_JUMPTABLE)();
      }
    }
    else {
      uVar6 = (ulong)*(uint *)((long)param_2 + (ulong)*(byte *)(param_1 + 1) * 4 + 300);
      if (uVar6 < 10) {
        uVar8 = *(undefined8 *)(uVar6 * 8 + 0xe7fbb8);
      }
      else {
        uVar8 = 0x139a485;
      }
      if (10 < (byte)(*pbVar3 - 1)) {
        func_0x004aee40(0x3536610,0xc,0x1383910,*pbVar3,uVar8);
      }
    }
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_4a5d70 RVA 0x4a5d70 | Evidence ev_397b63a58cb9d2f84c59998fc61ffe22caa3b0042a072e6a2a62aa221c2bff1b | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.bin SHA256 df8542b3b0477cbd17a978023a797cc26ad67a2c17868054a15dcde1e45daab9 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x4a5d70", "end": "0x4a5f00"}, {"start": "0x4a5f10", "end": "0x4a615b"}, {"start": "0x4a6160", "end": "0x4a63af"}], "total_bytes": 1581, "span_bytes": 1600, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Possible PIC construction at 0x004a5e67: Changing call to branch */
/* WARNING: Possible PIC construction at 0x004a6236: Changing call to branch */
/* WARNING: Possible PIC construction at 0x004a6251: Changing call to branch */
/* WARNING: Possible PIC construction at 0x004a626c: Changing call to branch */
/* WARNING: Possible PIC construction at 0x004a5f9f: Changing call to branch */
/* WARNING: Possible PIC construction at 0x004a5fea: Changing call to branch */
/* WARNING: Possible PIC construction at 0x004a5ec0: Changing call to branch */
/* WARNING: Possible PIC construction at 0x004a5f12: Changing call to branch */
/* WARNING: Possible PIC construction at 0x004a60c4: Changing call to branch */
/* WARNING: Possible PIC construction at 0x004a6118: Changing call to branch */
/* WARNING: Possible PIC construction at 0x004a6162: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x004a611d) */
/* WARNING: Removing unreachable block (ram,0x004a6133) */
/* WARNING: Removing unreachable block (ram,0x004a60c9) */
/* WARNING: Removing unreachable block (ram,0x004a61b5) */
/* WARNING: Removing unreachable block (ram,0x004a61c9) */
/* WARNING: Removing unreachable block (ram,0x004ab270) */
/* WARNING: Removing unreachable block (ram,0x004a60d7) */
/* WARNING: Removing unreachable block (ram,0x004a60ef) */
/* WARNING: Removing unreachable block (ram,0x004a5f17) */
/* WARNING: Removing unreachable block (ram,0x004a5ec5) */
/* WARNING: Removing unreachable block (ram,0x004a6035) */
/* WARNING: Removing unreachable block (ram,0x004a5edf) */
/* WARNING: Removing unreachable block (ram,0x004a5f24) */
/* WARNING: Removing unreachable block (ram,0x004a5f34) */
/* WARNING: Removing unreachable block (ram,0x004a5f10) */
/* WARNING: Removing unreachable block (ram,0x004a5fef) */
/* WARNING: Removing unreachable block (ram,0x004a5fa4) */
/* WARNING: Removing unreachable block (ram,0x004a5faa) */
/* WARNING: Removing unreachable block (ram,0x004a5ff8) */
/* WARNING: Removing unreachable block (ram,0x004a5fc3) */
/* WARNING: Removing unreachable block (ram,0x004a5fd6) */
/* WARNING: Removing unreachable block (ram,0x004a5fda) */
/* WARNING: Removing unreachable block (ram,0x004a5fe0) */
/* WARNING: Removing unreachable block (ram,0x004a6271) */
/* WARNING: Removing unreachable block (ram,0x004a6256) */
/* WARNING: Removing unreachable block (ram,0x004a623b) */
/* WARNING: Removing unreachable block (ram,0x004a5e6c) */
/* WARNING: Removing unreachable block (ram,0x004a5e72) */
/* WARNING: Removing unreachable block (ram,0x004a5e86) */
/* WARNING: Removing unreachable block (ram,0x004a6002) */
/* WARNING: Removing unreachable block (ram,0x004a600c) */
/* WARNING: Removing unreachable block (ram,0x004a6167) */
/* WARNING: Removing unreachable block (ram,0x004a6185) */
/* WARNING: Removing unreachable block (ram,0x004a6199) */
/* WARNING: Removing unreachable block (ram,0x004a61a0) */
/* WARNING: Removing unreachable block (ram,0x004a6170) */
/* WARNING: Removing unreachable block (ram,0x004a6180) */
/* WARNING: Removing unreachable block (ram,0x004a6160) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_4a5d70(long *param_1,long param_2)

{
  char cVar1;
  uint uVar2;
  char *pcVar3;
  code *pcVar4;
  int iVar5;
  uint uVar6;
  long lVar7;
  uint uVar8;
  undefined1 local_39;
  long local_38;
  
  local_38 = _DAT_0391c310;
  uVar6 = *(uint *)(param_2 + 0x30);
  if (4 < (int)uVar6) {
    pcVar3 = *(char **)(param_2 + 0x10);
    uVar2 = *(uint *)(*param_1 + 0x78);
    cVar1 = *pcVar3;
    uVar8 = (uint)CONCAT11((char)*(undefined2 *)(pcVar3 + 2),
                           (char)((ushort)*(undefined2 *)(pcVar3 + 2) >> 8));
    if (uVar6 < uVar8) {
      uVar8 = uVar6;
    }
    if (cVar1 == '\x03') {
      func_0x00b9afd0(param_1 + 0x5a,0,0);
      *(int *)(param_1 + 0x22) = (int)param_1[0x22] + 1;
      if (((uVar2 & 4) == 0) && (_DAT_0391c310 != local_38)) {
LAB_004a63a9:
        func_0x006fd6b0();
                    /* WARNING: Does not return */
        pcVar4 = (code *)invalidInstructionException();
        (*pcVar4)();
      }
    }
    else if (cVar1 == '\x02') {
      func_0x00b9afd0(param_1 + 0x5a,0,0);
      if ((uVar2 & 4) == 0) {
        func_0x004c6a00(param_1 + 0x31,0,0,0);
        *(undefined4 *)(param_1 + 0x22) = 0;
        *(byte *)(param_1 + 0x10) = *(byte *)(param_1 + 0x10) & 0xef;
        if (((((short)param_1[0x70] != -0x3fdd) || ((*(byte *)(param_1 + 0x62) & 8) == 0)) ||
            ((*(byte *)(param_1 + 0x66) & 8) != 0)) || (_DAT_0391c310 == local_38)) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        goto LAB_004a63a9;
      }
    }
    else if (((cVar1 == '\x01') && (param_1[0x77] != 0)) && (param_1[0x78] != 0)) {
      cVar1 = pcVar3[4];
      lVar7 = (long)cVar1;
      if (((int)cVar1 <= (int)(uVar8 - 6)) &&
         (uVar6 = (uint)pcVar3[lVar7 + 5], (int)uVar6 <= (int)((uVar8 - 6) - (int)cVar1))) {
        if ((uVar2 & 4) == 0) {
          if (((((int)cVar1 == (uint)*(byte *)(param_1 + 0x79)) &&
               (uVar6 == *(byte *)((long)param_1 + 0x3c9))) &&
              (iVar5 = func_0x00339bd0(pcVar3 + 5,param_1[0x77],lVar7), iVar5 == 0)) &&
             (iVar5 = func_0x00339bd0(pcVar3 + lVar7 + 6,param_1[0x78],uVar6), iVar5 == 0)) {
            iVar5 = (int)param_1[0x27];
            if ((iVar5 == 9) || (iVar5 == 6)) {
              local_39 = 8;
              func_0x004ab310(0xe7f9a0,param_1,2,pcVar3[1],1,&local_39,8,0x1277a6f,0);
              iVar5 = (int)param_1[0x27];
            }
            if (iVar5 == 6) {
              *(undefined4 *)(param_1 + 0x27) = 9;
              func_0x00b9afd0(param_1 + 0x4a,0,0);
              func_0x004ab020(param_1);
            }
          }
          else {
            *(int *)(param_1 + 0x22) = (int)param_1[0x22] + 1;
            local_39 = 9;
            func_0x004ab310(0xe7f9a0,param_1,3,pcVar3[1],1,&local_39,9,0x13aff38,0);
            func_0x004ab0c0(param_1);
          }
          if (_DAT_0391c310 == local_38) {
            return;
          }
          goto LAB_004a63a9;
        }
      }
    }
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_4a63b0 RVA 0x4a63b0 | Evidence ev_58db8d422962e5bb71fa7d528a07a1796d4aecd3dae0f2f99fac98ff6a40c5d4 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.bin SHA256 df8542b3b0477cbd17a978023a797cc26ad67a2c17868054a15dcde1e45daab9 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x4a63b0", "end": "0x4a6451"}, {"start": "0x4a669b", "end": "0x4a66be"}, {"start": "0x4a6814", "end": "0x4a68ba"}, {"start": "0x4a6e6a", "end": "0x4a6e70"}], "total_bytes": 372, "span_bytes": 2753, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Possible PIC construction at 0x004a682c: Changing call to branch */
/* WARNING: Possible PIC construction at 0x004a687a: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x004a6831) */
/* WARNING: Removing unreachable block (ram,0x004a6837) */
/* WARNING: Removing unreachable block (ram,0x004a6850) */
/* WARNING: Removing unreachable block (ram,0x004a6863) */
/* WARNING: Removing unreachable block (ram,0x004a6867) */
/* WARNING: Removing unreachable block (ram,0x004a687f) */
/* WARNING: Removing unreachable block (ram,0x004a6870) */
/* WARNING: Removing unreachable block (ram,0x004a6888) */
/* WARNING: Removing unreachable block (ram,0x004a689c) */
/* WARNING: Removing unreachable block (ram,0x004a6e6a) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_4a63b0(undefined8 param_1,long param_2)

{
  uint uVar1;
  
  if ((3 < *(int *)(param_2 + 0x30)) && (uVar1 = **(byte **)(param_2 + 0x10) - 1, uVar1 < 4)) {
                    /* WARNING: Could not emulate address calculation at 0x004a6449 */
                    /* WARNING: Treating indirect jump as call */
    (*(code *)((long)*(int *)((ulong)uVar1 * 4 + 0x15940d8) + 0x15940d8))();
    return;
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_4a6e80 RVA 0x4a6e80 | Evidence ev_86068867b9b139429704cbcb8b074e85b6393456e2a71baaf995f23e9600e779 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_667.body.bin SHA256 df8542b3b0477cbd17a978023a797cc26ad67a2c17868054a15dcde1e45daab9 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x4a6e80", "end": "0x4a7195"}], "total_bytes": 790, "span_bytes": 790, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_4a6e80(long param_1)

{
  long *plVar1;
  
  plVar1 = *(long **)(param_1 + 0x48);
  func_0x004c7dd0(plVar1 + 0x31,0x1277a25,0x132590a,4);
  if (_DAT_03536580 == (long *)0x0) {
    func_0x00b9b640(0x3536588,8);
    func_0x00b9aa40(0x3536588,(_DAT_03920440 * 10) * _DAT_039203d0,0,0x261eb0,0,0xffffffff,0x100);
  }
  plVar1[0xf] = (long)_DAT_03536580;
  _DAT_03536580 = plVar1;
  *(undefined1 *)(*plVar1 + 0x9c) = 0x17;
  *(undefined8 *)(*plVar1 + 0x488) = 0x26f418;
  *(undefined4 *)((long)plVar1 + 0x1c) = 0x20;
  *(undefined4 *)((long)plVar1 + 0x54) = 0x14;
  plVar1[0x11] = 0;
  plVar1[0x20] = 0;
  plVar1[0x1e] = 0;
  *(undefined4 *)(plVar1 + 0x12) = 3;
  plVar1[0x1f] = 0xf;
  plVar1[0x21] = 0;
  func_0x00258ff0(plVar1 + 0x13,0x28);
  func_0x00258ff0(plVar1 + 0x18,0x28);
  plVar1[0x22] = 0x500000000;
  *(undefined4 *)(plVar1 + 0x23) = 0;
  plVar1[0x7c] = 0x261eb8;
  plVar1[0x7d] = 0x261ec0;
  if ((*(byte *)((long)plVar1 + 0x62) & 1) == 0) {
    func_0x004c7dd0(plVar1 + 0xe,0x12e8702,0,0);
  }
  if ((*(byte *)((long)plVar1 + 0x2a) & 1) == 0) {
    func_0x004c7dd0(plVar1 + 7,0x129637f,0,0);
  }
  func_0x00258ff0(plVar1 + 0x70,0x30);
  func_0x00258ff0(plVar1 + 0x76,0x30);
  plVar1[0x62] = 0x20;
  plVar1[99] = 0;
  *(undefined4 *)((long)plVar1 + 300) = 0;
  *(undefined4 *)((long)plVar1 + 0x15c) = 0;
  plVar1[0x13] = 0;
  plVar1[0x18] = 0;
  plVar1[0x66] = 0;
  plVar1[0x65] = 0x5dc;
  plVar1[100] = 0x5dc;
  *(int *)((long)plVar1 + 0x33c) = _DAT_03920440;
  plVar1[0x68] = 0xa00000002;
  *(undefined4 *)(plVar1 + 0x69) = 10;
  func_0x00b9b640(plVar1 + 0x32,8);
  plVar1[0x6a] = 0;
  *(undefined4 *)(plVar1 + 0x6b) = 0;
  *(undefined4 *)(plVar1 + 0x26) = 0;
  *(undefined4 *)(plVar1 + 0x2c) = 0;
  plVar1[0x14] = 0;
  plVar1[0x19] = 0;
  func_0x00b9b640(plVar1 + 0x3a,8);
  *(undefined4 *)(plVar1 + 0x27) = 2;
  *(undefined4 *)(plVar1 + 0x2d) = 0;
  plVar1[0x16] = 0;
  plVar1[0x1b] = 0;
  func_0x00b9b640(plVar1 + 0x4a,8);
  func_0x00b9b640(plVar1 + 0x5a,8);
  *(undefined4 *)((long)plVar1 + 0x13c) = 2;
  *(undefined4 *)((long)plVar1 + 0x16c) = 0;
  plVar1[0x17] = 0;
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


