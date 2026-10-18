/* Handler 668: REA6.7.0 / Ghidra12.1.4 recovered pseudocode, not original or buildable C.
 * Original4096-byte input SHA256 ab1f0022f2fc7a338f010efc5bb908bc38634819a456ec64af2d2ed326f6e67c
 * Raw entry RVA 0x265708 -> actual target 0x3af8e0. narg=2.
 * Kernel RVAs; runtime VA=0xffffffff8a9c0000+RVA. Opaque externals/data remain unknown.
 * Analyst types below are inferred from accesses. Recovered pseudocode is retained verbatim afterward.
 * Original entry is an assembly-verified tail JMP to the target above. An engine halt_baddata
 * at that unmapped edge is a decompiler boundary artifact, not a recovered halt operation.
 */
#include <stdint.h>

/* ===== Analyst recovered interface/types ===== */
extern int common_265760(void *thread, void *ignored_null);
int analyst_handler_668(void *thread, const void *unused_args) { return common_265760(thread, 0); }


/* ===== ORIGINAL ENTRY: <EXTERNAL>::thunk_EXT_FUN_003af8e0 RVA 0x265708 | Evidence ev_719a817fad8756d6ec35956743113e97eb79ebb9e3e168c17c198f4b1dfe51a9 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_668.raw.dossier.json | Source /tmp/rea-646-676-5b61b6f2/raw_union.bin SHA256 352988f408bc976411feddb3ef6cd2b18459d2aa3fa6dfd7f2e4a7fe416ce915 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x265708", "end": "0x26570c"}], "total_bytes": 5, "span_bytes": 5, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_003af8e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}




/* ===== TARGET: handler_668_body RVA 0x3af8e0 | Evidence ev_fc99bb6787dcc738c22b502b69849b8ff29b74271f0148f9f1c3836ea0a00f8d | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_668.support.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handlers_b_support.elf SHA256 2b4ed3a3b88bdc0018718feb8e7ce9ce648fd045fa4512fac963c78239d66301 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x3af8e0", "end": "0x3af8eb"}], "total_bytes": 12, "span_bytes": 12, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void processEntry handler_668_body(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): handler_650_651_nosys_body RVA 0x5620e0 | Evidence ev_d3bc602c2586b12228e23650aa2a3b4c6f855acfc2f0888aecc081fca0243cc6 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/common_nosys.functions/0x5620e0.json | Source /tmp/handlers-a/context.elf SHA256 e50f48d9ed939fec51c4f6fdf27ccd27c17f070a4162880470aa7bb609f504a0 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x5620e0", "end": "0x562187"}], "total_bytes": 168, "span_bytes": 168, "non_contiguous": false, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 processEntry handler_650_651_nosys_body(void)

{
  code *pcVar1;
  long lVar2;
  long in_RDI;
  undefined1 local_a0 [16];
  undefined4 local_90;
  undefined4 local_88;
  long local_30;
  
  local_30 = _DAT_0391c310;
  lVar2 = *(long *)(in_RDI + 8) + 0x148;
  func_0x004c6a00(lVar2,0,0,0);
  func_0x00258ff0(local_a0,0x70);
  local_90 = 0xc;
  local_88 = 0x10006;
  adjacent_560540(*(undefined8 *)(in_RDI + 8));
  func_0x004c6fa0(lVar2,0,0,0);
  if (_DAT_0391c310 == local_30) {
    return 0x4e;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}




/* ===== LINKED/ADJACENT CONTEXT (reachability must be checked): adjacent_560540 RVA 0x560540 | Evidence ev_81d91fc02d2da7a03b70e167dcf730885ffa6b4960cc9fa24a9f7ba9a6464e1d | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/common_nosys.functions/0x560540.json | Source /tmp/handlers-a/context.elf SHA256 e50f48d9ed939fec51c4f6fdf27ccd27c17f070a4162880470aa7bb609f504a0 =====
 * Body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x560540", "end": "0x560690"}, {"start": "0x5606a0", "end": "0x561025"}], "total_bytes": 2775, "span_bytes": 2790, "non_contiguous": true, "contains_entry": true}
 * Limitations ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int adjacent_560540(long param_1,long *param_2,ulong param_3,long param_4)

{
  long lVar1;
  uint uVar2;
  uint uVar3;
  bool bVar4;
  code *pcVar5;
  ulong uVar6;
  int iVar7;
  int iVar8;
  long *plVar9;
  char cVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  long lVar14;
  long *plVar15;
  long *in_GS_OFFSET;
  bool bVar16;
  undefined8 local_88;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 *local_50;
  undefined8 local_48;
  undefined4 local_40;
  long local_38;
  
  uVar11 = (uint)param_3;
  uVar13 = uVar11 - 1;
  local_38 = _DAT_0391c310;
  if (0x7f < uVar13) {
    func_0x007f1950();
    func_0x007f2010(0x560fa6,0x12a11e7,(long)(int)uVar11);
    func_0x00c9aa10(0x2b,0x137158a,0x12a11e7,param_3 & 0xffffffff);
                    /* WARNING: Does not return */
    pcVar5 = (code *)invalidInstructionException();
    (*pcVar5)();
  }
  if (*(int *)(param_1 + 0xb8) == 2) {
    iVar7 = 0;
    if (param_4 == 0) goto LAB_0056091e;
    uVar11 = *(uint *)(param_4 + 0x60);
  }
  else {
    if ((*(byte *)(param_1 + 0xb1) & 8) == 0) {
      uVar12 = 9;
      if ((*(byte *)(param_1 + 0x562) & 2) == 0) {
        uVar12 = uVar11;
      }
      uVar13 = uVar12 - 1;
      param_3 = (ulong)uVar12;
    }
    lVar14 = *(long *)(param_1 + 0xa8);
    uVar12 = (uint)param_3;
    func_0x00313d50(*(undefined8 *)(param_1 + 0xb40),uVar12 | 0x8000000,1);
    uVar11 = 0;
    if (uVar13 < 0x1f) {
      uVar11 = *(uint *)((ulong)uVar13 * 4 + 0x15925c0);
    }
    if (param_2 == (long *)0x0) {
      if (uVar12 == 9) {
        for (lVar1 = *(long *)(param_1 + 0x10); lVar1 != 0; lVar1 = *(long *)(lVar1 + 0x10)) {
          *(byte *)(lVar1 + 0x2c0) = *(byte *)(lVar1 + 0x2c0) & 0xfe;
        }
      }
      param_2 = (long *)*in_GS_OFFSET;
      if ((param_2[1] != param_1) ||
         ((*(uint *)((long)param_2 + (ulong)(uVar13 >> 5) * 4 + 0x3b0) >> (uVar13 & 0x1f) & 1) != 0)
         ) {
        plVar9 = *(long **)(param_1 + 0x10);
        if (plVar9 == (long *)0x0) {
          param_2 = (long *)0x0;
        }
        else {
          plVar15 = plVar9;
          do {
            if ((((*(uint *)((long)plVar15 + (ulong)(uVar13 >> 5) * 4 + 0x3b0) &
                  1 << (uVar13 & 0x1f)) == 0) && ((*(byte *)(plVar15 + 0x58) & 1) == 0)) &&
               (param_2 = plVar15, (*(byte *)(plVar15 + 0x1d) & 0x20) == 0)) break;
            plVar15 = (long *)plVar15[2];
            param_2 = plVar9;
          } while (plVar15 != (long *)0x0);
        }
      }
      plVar9 = (long *)(param_1 + 0x1b8);
    }
    else {
      plVar9 = param_2 + 0x14;
    }
    pcVar5 = _DAT_01a9bf28;
    if (_DAT_01ad6bf8 != 0) {
      if (1 < (-(long)_DAT_01a9bf28 + 0x2681e8U >> 3 | -(long)_DAT_01a9bf28 << 0x3d)) {
        func_0x0044f8c0(0x1ad72e0,_DAT_01a9bf28);
      }
      (*pcVar5)(_DAT_01ad6bf8,param_2,param_1,uVar12,0,0);
    }
    lVar1 = lVar14 + 0xcc0;
    func_0x004c6a00(lVar1,0,0,0);
    pcVar5 = _DAT_01a9bf28;
    uVar6 = (ulong)(uVar13 >> 5);
    if ((*(uint *)(lVar14 + 0xc50 + uVar6 * 4) >> (uVar13 & 0x1f) & 1) == 0) {
      uVar2 = *(uint *)((long)param_2 + uVar6 * 4 + 0x3b0);
      uVar13 = 1 << (uVar13 & 0x1f);
      if ((uVar2 & uVar13) == 0) {
        bVar16 = (*(uint *)(lVar14 + 0xc60 + uVar6 * 4) & uVar13) == 0;
        bVar4 = !bVar16;
        cVar10 = bVar4 * '\x02';
      }
      else {
        cVar10 = '\x03';
        bVar16 = false;
        bVar4 = false;
      }
      uVar3 = *(uint *)(lVar14 + 0xc10 + uVar6 * 4);
      func_0x004c6fa0(lVar1,0,0,0);
      if ((uVar11 & 0x20) == 0) {
        if ((uVar11 & 4) != 0) {
          if (((uVar11 & 8) != 0) && (bVar16 && *(int *)(*(long *)(param_1 + 0xb38) + 0x2c) == 0))
          goto joined_r0x00560844;
          local_50 = &local_58;
          local_80 = 0;
          local_78 = 0;
          local_70 = 0;
          local_68 = 0;
          local_60 = 0;
          local_58 = 0;
          local_88 = 0x40000;
          local_48 = 0;
          local_40 = 1;
          adjacent_562560(param_1 + 0x1b8,&local_78,&local_88);
          lVar14 = *(long *)(param_1 + 0x10);
          if (lVar14 != 0) {
            do {
              adjacent_562560(lVar14 + 0xa0,&local_78,&local_88);
              lVar14 = *(long *)(lVar14 + 0x10);
            } while (lVar14 != 0);
          }
          func_0x0055c4e0(&local_78);
          if ((*(uint *)(param_1 + 0xb0) & 0x10000) != 0) {
            *(uint *)(param_1 + 0xb0) = *(uint *)(param_1 + 0xb0) & 0xfffeffff;
            func_0x004c6a00(*(long *)(param_1 + 0xe0) + 0x148,0,0,0);
            func_0x0055c390(*(undefined8 *)(param_1 + 0x1b0));
            func_0x004c6fa0(*(long *)(param_1 + 0xe0) + 0x148,0,0,0);
          }
        }
      }
      else {
        local_50 = &local_58;
        local_80 = 0;
        local_78 = 0;
        local_70 = 0;
        local_68 = 0;
        local_60 = 0;
        local_58 = 0;
        local_88 = 0x330000;
        local_48 = 0;
        local_40 = 1;
        adjacent_562560(param_1 + 0x1b8,&local_78,&local_88);
        lVar14 = *(long *)(param_1 + 0x10);
        if (lVar14 != 0) {
          do {
            adjacent_562560(lVar14 + 0xa0,&local_78,&local_88);
            lVar14 = *(long *)(lVar14 + 0x10);
          } while (lVar14 != 0);
        }
        func_0x0055c4e0(&local_78);
      }
      iVar7 = adjacent_5612a0(plVar9,param_3,param_4);
      if (iVar7 != 0) goto LAB_0056091e;
      func_0x0055cf70(param_2);
      if ((uVar13 & uVar2) != 0) {
        iVar7 = 0;
        if (((uVar11 & 0x20) == 0) || (iVar7 = 0, (*(byte *)(param_1 + 0xb2) & 2) == 0))
        goto LAB_0056091e;
      }
      if (uVar12 == 9) {
        *(undefined4 *)(param_1 + 0x378) = 0;
        *(undefined1 *)(param_1 + 0x380) = 0;
        func_0x00c06910(param_1 + 0x380);
      }
      if ((*(ulong *)(param_1 + 0x560) & 2) == 0) {
        *(byte *)(param_1 + 0xb2) = *(byte *)(param_1 + 0xb2) & 0xfb;
      }
      iVar8 = (uint)((uVar3 & uVar13) != 0) * 5 + -1;
      if (uVar12 == 9) {
        for (plVar15 = *(long **)(param_1 + 0x10); plVar15 != (long *)0x0;
            plVar15 = (long *)plVar15[2]) {
          func_0x004c78b0(plVar15,0,0x12b5611,0x95a);
          func_0x006f93a0(plVar15);
          func_0x004c7520(*plVar15 + 0x18,0,0,0);
        }
        uVar13 = *(uint *)(param_1 + 0xb0);
        if ((uVar13 & 0xe0000) == 0) {
LAB_00560c02:
          if (*(int *)(param_1 + 0xb8) == 1) {
            if (!(bool)(~bVar4 & (uVar13 & 0x800) == 0)) {
              adjacent_561470(param_2,param_3,cVar10,iVar8);
              iVar7 = 0;
              goto LAB_0056091e;
            }
            if ((uVar11 & 4) == 0) goto LAB_00560db6;
            if ((uVar13 & 0x2010) == 0) {
              lVar14 = param_1 + 0x38;
              *(uint *)(param_1 + 0xb0) = uVar13 | 0x20000;
              *(uint *)(param_1 + 0xa30) = uVar12;
              func_0x004c7190(lVar14,0,0,0);
              iVar8 = adjacent_561730(param_2,param_1);
              if (*(int *)(param_1 + 0xb48) == *(int *)(param_1 + 0x3a0)) {
                FUN_005619e0(param_1);
                func_0x004c7520(lVar14,0,0,0);
                func_0x00a91ce0(param_1);
                func_0x0055c820(param_1,*(undefined4 *)(param_1 + 0xa30));
              }
              else {
                func_0x004c7520(lVar14,0,0,0);
              }
              iVar7 = 0;
              if (iVar8 != 0) {
                func_0x0053acf0();
              }
              goto LAB_0056091e;
            }
          }
          else {
            func_0x0055c620(plVar9,param_3);
          }
        }
        else if ((uVar13 & 0x800) == 0) {
          *(uint *)(param_1 + 0xb0) = uVar13 & 0xfffdf7ff;
LAB_00560db6:
          adjacent_561470(param_2,param_3,cVar10,iVar8);
          func_0x004c7190(param_1 + 0x38,0,0,0);
          if (uVar12 != 9) goto LAB_00560df8;
          func_0x00b921e0(param_1);
          func_0x00b92070(param_1,param_2);
          goto LAB_00560e00;
        }
LAB_00560d5f:
        iVar7 = 0;
      }
      else {
        uVar13 = *(uint *)(param_1 + 0xb0);
        if ((uVar13 & 0xe0000) == 0) goto LAB_00560c02;
        if ((uVar11 & 0x20) == 0) {
          if ((uVar11 & 4) != 0) {
            iVar7 = 0;
            if ((uVar13 & 0x800) == 0) {
              *(uint *)(param_1 + 0xb0) = uVar13 | 0x20000;
              func_0x0055c620(plVar9,param_3);
            }
            goto LAB_0056091e;
          }
          param_1 = param_1 + 0x38;
          iVar7 = 0;
          func_0x004c7190(param_1,0,0,0);
          func_0x004c78b0(param_2,0,0x12b5611,0x9cb);
          if ((param_2[0x1f] == 0) || ((*(uint *)((long)param_2 + 0xe4) & 8) == 0)) {
            func_0x004c7520(*param_2 + 0x18,0,0,0);
            func_0x004c7520(param_1,0,0,0);
            goto LAB_0056091e;
          }
          if ((*(uint *)(param_2 + 0x1d) & 0x20) != 0) {
            uVar11 = *(uint *)(param_2 + 0x1d) & 0xffffffdf;
            *(uint *)(param_2 + 0x1d) = uVar11;
            if (uVar11 == 0) {
              *(undefined4 *)(param_2 + 0x80) = 2;
            }
            *(uint *)((long)param_2 + 0xe4) = *(uint *)((long)param_2 + 0xe4) | 0x80000800;
          }
          iVar8 = func_0x00c1b3e0(param_2,iVar8);
          iVar7 = 0;
          func_0x004c7520(*param_2 + 0x18,0,0,0);
          func_0x004c7520(param_1,0,0,0);
          if (iVar8 != 0) {
            func_0x0053acf0();
            goto LAB_0056091e;
          }
          goto LAB_0056084a;
        }
        if ((uVar13 >> 0xb & (uint)(*(ulong *)(param_1 + 0x560) >> 1) & 0x7fffffff & 1) != 0)
        goto LAB_00560d5f;
        lVar14 = param_1 + 0x38;
        *(uint *)(param_1 + 0xb0) = uVar13 & 0xfffdffff;
        func_0x004c7190(lVar14,0,0,0);
        if (*(int *)(param_1 + 0xb48) == *(int *)(param_1 + 0x3a0)) {
          func_0x004c7520(lVar14,0,0,0);
          *(byte *)(param_1 + 0xb2) = *(byte *)(param_1 + 0xb2) | 1;
          *(undefined4 *)(param_1 + 0xa30) = 0x13;
          func_0x004c6a00(*(long *)(param_1 + 0xe0) + 0x148,0,0,0);
          adjacent_561f10(param_1,6,0x13);
          func_0x004c6fa0(*(long *)(param_1 + 0xe0) + 0x148,0,0,0);
          func_0x004c7190(lVar14,0,0,0);
        }
        if (bVar16) {
          func_0x00b91ed0(param_1);
          iVar7 = 0;
          func_0x004c7520(lVar14,0,0,0);
          func_0x0055c620(plVar9,param_3);
          goto LAB_0056091e;
        }
        if (bVar4) {
          func_0x004c7520(lVar14,0,0,0);
          goto LAB_00560db6;
        }
LAB_00560df8:
        func_0x00b91ed0(param_1);
LAB_00560e00:
        iVar7 = 0;
        func_0x004c7520(param_1 + 0x38,0,0,0);
      }
      goto LAB_0056091e;
    }
    if (_DAT_01ad6cb8 != 0) {
      if (1 < (-(long)_DAT_01a9bf28 + 0x2681e8U >> 3 | -(long)_DAT_01a9bf28 << 0x3d)) {
        func_0x0044f8c0(0x1ad7300,_DAT_01a9bf28);
      }
      (*pcVar5)(_DAT_01ad6cb8,param_2,param_1,param_3 & 0xffffffff,0,0);
    }
    func_0x004c6fa0(lVar1,0,0,0);
joined_r0x00560844:
    if (param_4 == 0) {
LAB_0056084a:
      iVar7 = 0;
      goto LAB_0056091e;
    }
    uVar11 = *(uint *)(param_4 + 0x60);
  }
  iVar7 = 0;
  if ((uVar11 & 6) == 4) {
    func_0x0043c0c0(_DAT_035ab098,param_4,0);
    iVar7 = 0;
  }
LAB_0056091e:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar5 = (code *)invalidInstructionException();
    (*pcVar5)();
  }
  return iVar7;
}


