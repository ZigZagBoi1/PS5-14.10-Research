/* Handler 650: Shared nosys implementation with signal delivery side effect
 * Original handler_650.bin,4096bytes,SHA256c22afc5c7cc3a6c3a1387f51b7dfa46b1ee55bb4b399853fd85ca6e05596c78e
 * Raw RVA0x265760 -> target RVA0x5620e0; VA=0xffffffff8a9c0000+RVA.
 * REA6.7.0/Ghidra12.1.4; pseudocode, not original/buildable source.
 * Shared evidence source: /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/a_context.dossiers.jsonl.gz
 * Opaque pointers, unknown external prototypes and missing data limit type precision.
 */
#include <stdint.h>
#include <stddef.h>

/* ANALYST RECOVERED LAYOUTS / CLEARER ENTRY MODEL.
 * Names ending in an RVA are labels; undefined helper declarations are deliberate.
 * Numeric fields and offsets are observed; semantic labels are hypotheses.
 */
typedef struct { uint8_t opaque_00[0x10]; int32_t number;
                 uint8_t opaque_14[4]; uint32_t event_type;
                 uint8_t opaque_1c[0x54]; } NosysEvent70;
/* uint8_t arrays preserve exact observed layout, not original kernel types. */
int handler650_651_model(uint8_t *thread) {
    uint8_t *process = *(uint8_t **)(thread + 8);
    lock_4c6a00(process + 0x148, 0, 0, 0);
    NosysEvent70 ev; zero_258ff0(&ev, 0x70);
    ev.number = 12; ev.event_type = 0x10006;
    deliver_560540(process, thread, 12, &ev);
    unlock_4c6fa0(process + 0x148, 0, 0, 0);
    return 78;
}
/* Verified machine-code thunk; raw decompiler halt_baddata is an unmapped-target artifact. */
int handler_650_entry_model(void *thread, void *args) { return body_5620e0(thread, args); }


/* ACTUAL REA ORIGINAL RAW-ENTRY PSEUDOCODE */
/* ev_7ce22bbe7a19c6cb0ed297ee85c93ef86256728ad76157702783423ba9d6fd20 */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_005620e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ACTUAL REA RECOVERED PSEUDOCODE: TARGET AND CARRIER CONTEXT */

/* CONTEXT / separate function: adjacent_560540 @ 0x560540; ev_81d91fc02d2da7a03b70e167dcf730885ffa6b4960cc9fa24a9f7ba9a6464e1d
 * Ghidra body ranges: 0x560540..0x560690, 0x5606a0..0x561025
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
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



/* CONTEXT / separate function: adjacent_561030 @ 0x561030; ev_698e462ee4d2c4ec0878cb4ebfee3cc1e7cb622ff6cbe5e7067f9bbef92cd60d
 * Ghidra body ranges: 0x561030..0x56119c
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Possible PIC construction at 0x00561071: Changing call to branch */
/* WARNING: Possible PIC construction at 0x0056109f: Changing call to branch */
/* WARNING: Possible PIC construction at 0x005610d1: Changing call to branch */
/* WARNING: Possible PIC construction at 0x0056111f: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00561159: Changing call to branch */
/* WARNING: Possible PIC construction at 0x0056117d: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x0056115e) */
/* WARNING: Removing unreachable block (ram,0x00561124) */
/* WARNING: Removing unreachable block (ram,0x005610d6) */
/* WARNING: Removing unreachable block (ram,0x00561145) */
/* WARNING: Removing unreachable block (ram,0x0056114c) */
/* WARNING: Removing unreachable block (ram,0x00561112) */
/* WARNING: Removing unreachable block (ram,0x005610a4) */
/* WARNING: Removing unreachable block (ram,0x00561076) */
/* WARNING: Removing unreachable block (ram,0x005610bd) */
/* WARNING: Removing unreachable block (ram,0x0056108c) */
/* WARNING: Removing unreachable block (ram,0x00561182) */

void adjacent_561030(long param_1)

{
  int iVar1;
  
  iVar1 = func_0x005a4c90();
  if (iVar1 == 0) {
    iVar1 = func_0x00609940();
    if (iVar1 == 0) {
      iVar1 = func_0x00609890(*(undefined8 *)(param_1 + 0x140));
      if (iVar1 == 0) {
        return;
      }
    }
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* CONTEXT / separate function: adjacent_5611a0 @ 0x5611a0; ev_24454a380f2cc54c10e6eee188438bbcd42301dc7cff2b590e77ffd26bd33ada
 * Ghidra body ranges: 0x5611a0..0x5611f4
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_5611a0(long param_1,int *param_2,long *param_3)

{
  long lVar1;
  undefined8 uVar2;
  
  if (*param_2 == 4) {
    lVar1 = func_0x00b92420(param_2[4],*(undefined4 *)(param_1 + 0xbc));
    if (lVar1 == 0) {
      uVar2 = 3;
    }
    else {
      *param_3 = lVar1;
      uVar2 = 0;
    }
  }
  else {
    *param_3 = 0;
    uVar2 = 0;
    func_0x004c6a00(param_1 + 0x148,0,0,0);
  }
  return uVar2;
}



/* CONTEXT / separate function: adjacent_561200 @ 0x561200; ev_e0dacecb78674187c661757a2e75304cdd4a34266cdb1476702948c5dfd31d69
 * Ghidra body ranges: 0x561200..0x561278
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void adjacent_561200(long param_1,undefined4 param_2)

{
  code *pcVar1;
  undefined1 local_a0 [16];
  undefined4 local_90;
  undefined4 local_88;
  long local_30;
  
  local_30 = _DAT_0391c310;
  func_0x00258ff0(local_a0,0x70);
  local_88 = 0x10006;
  local_90 = param_2;
  adjacent_560540(*(undefined8 *)(param_1 + 8),param_1,param_2,local_a0);
  if (_DAT_0391c310 == local_30) {
    return;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* CONTEXT / separate function: adjacent_561280 @ 0x561280; ev_8e037def32ab9594d1f61ddd28784ce44460876120326928e402ca774b796c4f
 * Ghidra body ranges: 0x561280..0x561295
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted.", "Ghidra Listing reports a terminal call at 0x561291 to 0x560540 adjacent_560540 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

void adjacent_561280(long param_1,undefined4 param_2,undefined8 param_3)

{
  adjacent_560540(*(undefined8 *)(param_1 + 8),param_1,param_2,param_3);
  return;
}



/* CONTEXT / separate function: adjacent_5612a0 @ 0x5612a0; ev_4b395dfef217fd9bb37ed9cbc7f8f3603cae27a6936f447aadb325573bb73f8d
 * Ghidra body ranges: 0x5612a0..0x561469
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 adjacent_5612a0(long param_1,int param_2,long *param_3)

{
  uint *puVar1;
  undefined8 *puVar2;
  long *plVar3;
  int *piVar4;
  long lVar5;
  long *plVar6;
  long *plVar7;
  byte bVar8;
  
  bVar8 = 0;
  if (((param_3 != (long *)0x0) && (param_2 != 0x11)) && (param_2 != 9)) {
    if ((*(uint *)(param_3 + 0xc) & 4) != 0) {
      if ((*(uint *)(param_3 + 0xc) & 0x10) == 0) {
        *param_3 = 0;
        puVar2 = *(undefined8 **)(param_1 + 0x28);
        param_3[1] = (long)puVar2;
        *puVar2 = param_3;
        *(long **)(param_1 + 0x28) = param_3;
        param_3[0xd] = param_1;
      }
      else {
        lVar5 = *(long *)(param_1 + 0x20);
        *param_3 = lVar5;
        if (lVar5 == 0) {
          *(long **)(param_1 + 0x28) = param_3;
        }
        else {
          *(long **)(lVar5 + 8) = param_3;
        }
        *(undefined8 *)(param_1 + 0x20) = param_3;
        param_3[1] = param_1 + 0x20;
        param_3[0xd] = param_1;
      }
      goto LAB_005612d2;
    }
    if (_DAT_035ab098 != 0) {
      lVar5 = *(long *)(param_1 + 0x30);
      if (lVar5 == 0) {
        plVar3 = (long *)func_0x0043b880(_DAT_035ab098,0,0x101);
        if (plVar3 != (long *)0x0) {
LAB_005613a8:
          plVar6 = param_3 + 2;
          plVar7 = plVar3 + 2;
          for (lVar5 = 10; lVar5 != 0; lVar5 = lVar5 + -1) {
            *plVar7 = *plVar6;
            plVar6 = plVar6 + (ulong)bVar8 * -2 + 1;
            plVar7 = plVar7 + (ulong)bVar8 * -2 + 1;
          }
          *(uint *)(plVar3 + 0xc) = *(uint *)(param_3 + 0xc) & 9;
          *(int *)(plVar3 + 2) = param_2;
          if ((*(byte *)(param_3 + 0xc) & 0x10) == 0) {
            *plVar3 = 0;
            puVar2 = *(undefined8 **)(param_1 + 0x28);
            plVar3[1] = (long)puVar2;
            *puVar2 = plVar3;
            *(long **)(param_1 + 0x28) = plVar3;
            plVar3[0xd] = param_1;
          }
          else {
            lVar5 = *(long *)(param_1 + 0x20);
            *plVar3 = lVar5;
            if (lVar5 == 0) {
              *(long **)(param_1 + 0x28) = plVar3;
            }
            else {
              *(long **)(lVar5 + 8) = plVar3;
            }
            *(undefined8 *)(param_1 + 0x20) = plVar3;
            plVar3[1] = param_1 + 0x20;
            plVar3[0xd] = param_1;
          }
          goto LAB_005612d2;
        }
        piVar4 = (int *)&DAT_035ab0ac;
      }
      else if (*(int *)(lVar5 + 0x3b4) < _DAT_01ad75b0) {
        plVar3 = (long *)func_0x0043b880(_DAT_035ab098,0,0x101);
        if (plVar3 != (long *)0x0) {
          *(int *)(lVar5 + 0x3b4) = *(int *)(lVar5 + 0x3b4) + 1;
          goto LAB_005613a8;
        }
        piVar4 = (int *)&DAT_035ab0ac;
      }
      else {
        piVar4 = (int *)&DAT_035ab0a8;
      }
      *piVar4 = *piVar4 + 1;
      if ((*(uint *)(param_3 + 0xc) & 9) == 8) {
        return 0x23;
      }
    }
  }
  puVar1 = (uint *)(param_1 + 0x10 + (long)((int)(param_2 - 1U) >> 5) * 4);
  *puVar1 = *puVar1 | 1 << (param_2 - 1U & 0x1f);
LAB_005612d2:
  puVar1 = (uint *)(param_1 + (long)((int)(param_2 - 1U) >> 5) * 4);
  *puVar1 = *puVar1 | 1 << (param_2 - 1U & 0x1f);
  return 0;
}



/* CONTEXT / separate function: adjacent_561470 @ 0x561470; ev_4c264439ece5dfac3127776f8714ed582602aa872ab799a5c3043a4973eda929
 * Ghidra body ranges: 0x561470..0x561720
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void adjacent_561470(long *param_1,uint param_2,long param_3,undefined4 param_4)

{
  long lVar1;
  uint uVar2;
  long lVar3;
  code *pcVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  undefined8 *in_GS_OFFSET;
  uint local_48 [4];
  long local_38;
  
  uVar6 = 0;
  uVar7 = param_2 - 1;
  local_38 = _DAT_0391c310;
  lVar3 = param_1[1];
  if (param_2 < 0x20) {
    uVar6 = *(uint *)((ulong)uVar7 * 4 + 0x15925c0);
  }
  lVar1 = lVar3 + 0x38;
  func_0x004c7190(lVar1,0,0,0);
  func_0x004c78b0(param_1,0,0x12b5611,0xa2f);
  if (param_3 == 0) {
    if ((param_2 == 0x11) || ((uVar6 & 1) != 0)) goto LAB_00561501;
  }
  else if (param_2 == 0x11) {
LAB_00561501:
    if (0xff < *(ushort *)((long)param_1 + 0x3c4)) {
      *(byte *)((long)param_1 + 0xe6) = *(byte *)((long)param_1 + 0xe6) | 0x80;
      func_0x006b5910(param_1,0xff);
    }
  }
  if (param_1[0x1f] == 0) {
    iVar5 = 0;
    if (((int)param_1[0x80] == 4) && (param_1 != (long *)*in_GS_OFFSET)) {
      func_0x00b035d0(param_1);
    }
LAB_005616b2:
    func_0x004c7520(lVar1,0,0,0);
    func_0x004c7520(*param_1 + 0x18,0,0,0);
    if (iVar5 != 0) {
      if (_DAT_0391c310 == local_38) {
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      goto LAB_0056171a;
    }
  }
  else {
    if ((uVar6 & 0x24) != 0) {
      *(byte *)((long)param_1 + 0x52a) = *(byte *)((long)param_1 + 0x52a) | 4;
    }
    if ((*(byte *)((long)param_1 + 0xed) & 0x30) != 0) {
      *(byte *)((long)param_1 + 0x52a) = *(byte *)((long)param_1 + 0x52a) | 0x40;
    }
    uVar2 = *(uint *)((long)param_1 + 0xe4);
    iVar5 = 0;
    if ((uVar2 & 8) == 0) goto LAB_005616b2;
    if ((param_3 != 0) || ((uVar6 & 0x20) == 0)) {
      if (((byte)uVar6 >> 2 & (uVar2 & 0x282000) == 0x2000) == 0) {
        if (((uVar2 & 0x20) == 0) && (700 < *(ushort *)((long)param_1 + 0x3c4))) {
          func_0x006b5910(param_1,700);
        }
        if ((*(uint *)(param_1 + 0x1d) & 0x20) != 0) {
          uVar7 = *(uint *)(param_1 + 0x1d) & 0xffffffdf;
          *(uint *)(param_1 + 0x1d) = uVar7;
          if (uVar7 == 0) {
            *(undefined4 *)(param_1 + 0x80) = 2;
          }
          *(uint *)((long)param_1 + 0xe4) = *(uint *)((long)param_1 + 0xe4) | 0x80000800;
        }
        iVar5 = func_0x00c1b3e0(param_1,param_4);
        if ((param_3 == 2) || ((uVar6 & 0x20) != 0)) {
          param_1[0xa6] = 0;
        }
      }
      goto LAB_005616b2;
    }
    func_0x004c7520(*param_1 + 0x18,0,0,0);
    func_0x004c7520(lVar1,0,0,0);
    local_48[0] = 0;
    local_48[1] = 0;
    local_48[2] = 0;
    local_48[3] = 0;
    uVar6 = 1 << (uVar7 & 0x1f);
    local_48[(int)uVar7 >> 5] = local_48[(int)uVar7 >> 5] | uVar6;
    func_0x0055c680(lVar3 + 0x1b8,local_48);
    local_48[0] = 0;
    local_48[1] = 0;
    local_48[2] = 0;
    local_48[3] = 0;
    local_48[(int)uVar7 >> 5] = local_48[(int)uVar7 >> 5] | uVar6;
    func_0x0055c680(param_1 + 0x14,local_48);
  }
  if (_DAT_0391c310 == local_38) {
    return;
  }
LAB_0056171a:
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar4 = (code *)invalidInstructionException();
  (*pcVar4)();
}



/* CONTEXT / separate function: adjacent_561730 @ 0x561730; ev_87422e19e45d66c97c5717bea0e1f4c9c88c6002b61528ac35232302b9b3a9fa
 * Ghidra body ranges: 0x561730..0x561759, 0x561760..0x561889, 0x561890..0x5618a4, 0x5618b0..0x5619db
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

uint adjacent_561730(long *param_1,long param_2)

{
  uint uVar1;
  code *pcVar2;
  uint uVar3;
  ulong uVar4;
  ulong uVar5;
  long *plVar6;
  uint uVar7;
  
  plVar6 = *(long **)(param_2 + 0x10);
  if (plVar6 == (long *)0x0) {
    uVar7 = 0;
  }
  else {
    uVar7 = 0;
    do {
      func_0x004c78b0(plVar6,0,0x12b5611,0xa94);
      if (((*(byte *)(plVar6 + 0x58) & 1) == 0) && (uVar4 = plVar6[0xa5], (uVar4 & 0x100000) == 0))
      {
        if ((uVar4 & 0x40000) == 0) {
          uVar4 = uVar4 & 0xffffffffffe8ffff;
          plVar6[0xa5] = uVar4;
          if ((int)plVar6[0x80] == 3) {
            uVar5 = 0x20000;
LAB_005617ee:
            uVar4 = uVar4 | uVar5;
            plVar6[0xa5] = uVar4;
          }
          else if ((int)plVar6[0x80] == 4) {
            uVar5 = 0x10000;
            goto LAB_005617ee;
          }
          if ((*(byte *)((long)plVar6 + 0xed) & 0x30) == 0) goto LAB_0056180e;
          uVar4 = uVar4 | 0x400000;
        }
        else {
          uVar4 = uVar4 & 0xffffffffffebffff;
        }
        plVar6[0xa5] = uVar4;
      }
LAB_0056180e:
      uVar3 = *(uint *)((long)plVar6 + 0xe4);
      uVar1 = *(uint *)(plVar6 + 0x1d);
      *(uint *)((long)plVar6 + 0xe4) = uVar3 | 0x8800;
      if ((uVar3 & 8) == 0 || (uVar1 & 6) == 0) {
        if ((uVar1 & 1) == 0) {
          if ((uVar1 & 0x20) == 0) {
            if ((param_1 != plVar6) && ((int)plVar6[0x80] == 4)) {
              func_0x00b035d0(plVar6);
            }
            if (0xff < *(ushort *)((long)plVar6 + 0x3c4)) {
              *(byte *)((long)plVar6 + 0xe6) = *(byte *)((long)plVar6 + 0xe6) | 0x80;
              func_0x006b5910(plVar6);
            }
          }
          else {
LAB_00561760:
            func_0x00b91e30(plVar6);
          }
        }
      }
      else if ((uVar3 & 0x2000) == 0) {
        if ((uVar1 & 1) == 0) goto LAB_00561760;
      }
      else {
        if ((uVar1 & 1) != 0) {
          func_0x007f1950();
          func_0x007f2310(0x56194b,(long)*(int *)(plVar6[1] + 0xbc),plVar6[1] + 0x5e4,
                          (long)*(int *)((long)plVar6 + 0x9c),(long)plVar6 + 0x294,
                          (long)*(int *)((long)plVar6 + 0xe4),(long)(int)plVar6[0x1d]);
          func_0x00c9aa10(0x2f,0x137b5af,*(undefined4 *)(plVar6[1] + 0xbc),plVar6[1] + 0x5e4,
                          *(undefined4 *)((long)plVar6 + 0x9c),(long)plVar6 + 0x294,
                          *(undefined4 *)((long)plVar6 + 0xe4),(int)plVar6[0x1d]);
                    /* WARNING: Does not return */
          pcVar2 = (code *)invalidInstructionException();
          (*pcVar2)();
        }
        if (plVar6[0x1f] != 0) {
          if ((uVar1 & 0x20) != 0) {
            *(uint *)(plVar6 + 0x1d) = uVar1 & 0xffffffde;
            if ((uVar1 & 0xffffffde) == 0) {
              *(undefined4 *)(plVar6 + 0x80) = 2;
            }
            *(uint *)((long)plVar6 + 0xe4) = uVar3 | 0x80008800;
          }
          uVar3 = func_0x00c1b3e0(plVar6);
          uVar7 = uVar3 | uVar7;
          if (0xff < *(ushort *)((long)plVar6 + 0x3c4)) {
            *(byte *)((long)plVar6 + 0xe6) = *(byte *)((long)plVar6 + 0xe6) | 0x80;
            func_0x006b5910(plVar6);
          }
        }
      }
      func_0x004c7520(*plVar6 + 0x18,0,0,0);
      plVar6 = (long *)plVar6[2];
    } while (plVar6 != (long *)0x0);
  }
  return uVar7;
}



/* CONTEXT / separate function: FUN_005619e0 @ 0x5619e0; ev_c116da6225907a9e9c5ad109f3d04eebf4cacd1ca499171ab116af7cf2cf0a0a
 * Ghidra body ranges: 0x5619e0..0x561a10, 0x561abe..0x561abe
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void FUN_005619e0(long param_1)

{
  long *in_GS_OFFSET;
  
  if (((*(byte *)(param_1 + 0xb2) & 2) != 0) &&
     ((uint)(param_1 == *(long *)(*in_GS_OFFSET + 8)) + *(int *)(param_1 + 0x3a0) ==
      *(int *)(param_1 + 0xb48))) {
    func_0x004c7520(param_1 + 0x38,0,0,0);
    *(byte *)(param_1 + 0xb1) = *(byte *)(param_1 + 0xb1) & 0xef;
    func_0x004c6a00(*(long *)(param_1 + 0xe0) + 0x148,0,0,0);
    adjacent_561f10(param_1,((*(uint *)(param_1 + 0xb0) & 0x800) == 0) + '\x04',
                    *(undefined4 *)(param_1 + 0xa30));
    *(ulong *)(param_1 + 0x560) = *(ulong *)(param_1 + 0x560) & 0x7fffffff;
    func_0x00c06910(param_1 + 0x560);
    func_0x004c6fa0(*(long *)(param_1 + 0xe0) + 0x148,0,0,0);
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  return;
}



/* CONTEXT / separate function: adjacent_561a11 @ 0x561a11; ev_8549772420f5b2a209cc844b2c636bfc79806f0edbe4d74f1b4808506ac789a1
 * Ghidra body ranges: 0x561a11..0x561abd
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void adjacent_561a11(long param_1)

{
  func_0x004c7520(param_1 + 0x38,0,0,0);
  *(byte *)(param_1 + 0xb1) = *(byte *)(param_1 + 0xb1) & 0xef;
  func_0x004c6a00(*(long *)(param_1 + 0xe0) + 0x148,0,0,0);
  adjacent_561f10(param_1,((*(uint *)(param_1 + 0xb0) & 0x800) == 0) + '\x04',
                  *(undefined4 *)(param_1 + 0xa30));
  *(ulong *)(param_1 + 0x560) = *(ulong *)(param_1 + 0x560) & 0x7fffffff;
  func_0x00c06910(param_1 + 0x560);
  func_0x004c6fa0(*(long *)(param_1 + 0xe0) + 0x148,0,0,0);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* CONTEXT / separate function: adjacent_561ac0 @ 0x561ac0; ev_59ec830e2af2d331cbac6b0e7c76328b4b4c49f3c11f3b38c81576cfa3a7953c
 * Ghidra body ranges: 0x561ac0..0x561c8f
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

int adjacent_561ac0(long param_1,int param_2)

{
  long lVar1;
  long lVar2;
  undefined4 uVar3;
  uint uVar4;
  uint uVar5;
  
  lVar2 = *(long *)(param_1 + 8);
  *(byte *)(param_1 + 0x2c0) = *(byte *)(param_1 + 0x2c0) | 2;
  *(int *)(param_1 + 0x280) = param_2;
  if ((*(byte *)(lVar2 + 0x560) & 0x10) == 0) {
    uVar3 = func_0x00c9c410(param_1,param_2);
    func_0x00c9dfb0(param_1,uVar3,0);
  }
  lVar1 = lVar2 + 0x38;
  func_0x004c7190(lVar1,0,0,0);
  uVar4 = *(uint *)(lVar2 + 0xb0);
  if (((uVar4 & 0x800) != 0) && (uVar5 = *(uint *)(param_1 + 0x2c0), (uVar5 & 2) != 0)) {
    do {
      if ((uVar5 >> 10 & 1) == 0 && (uVar4 & 0x400) != 0) {
        *(uint *)(param_1 + 0x2c0) = uVar5 & 0xfffffbfd;
        func_0x004c7520(lVar1,0,0,0);
        return param_2;
      }
      *(int *)(lVar2 + 0xa30) = param_2;
      *(long *)(lVar2 + 0x3a8) = param_1;
      *(uint *)(lVar2 + 0xb0) = uVar4 | 0x60000;
      func_0x004c7520(lVar1,0,0,0);
      func_0x00a91b90(lVar2,2,0,param_2,0xffffffff);
      func_0x004c7190(lVar1,0,0,0);
      adjacent_561730(param_1,lVar2);
      if ((char)*(uint *)(param_1 + 0x2c0) < '\0') {
        *(uint *)(param_1 + 0x2c0) = *(uint *)(param_1 + 0x2c0) & 0xffffff7f;
        func_0x0073f010(lVar2 + 0xc00,0);
      }
      if (param_2 == 0x11) {
        *(byte *)(lVar2 + 0x561) = *(byte *)(lVar2 + 0x561) & 0xdf;
      }
      while( true ) {
        func_0x00b91850(param_1,lVar2);
        if ((param_2 == 0x11) && ((*(ulong *)(lVar2 + 0x560) & 1) != 0)) {
          *(byte *)(param_1 + 0x2c0) = *(byte *)(param_1 + 0x2c0) & 0xfd;
        }
        if (*(long *)(lVar2 + 0x3a8) == param_1) {
          *(undefined8 *)(lVar2 + 0x3a8) = 0;
        }
        uVar4 = *(uint *)(lVar2 + 0xb0);
        if ((uVar4 & 0x800) == 0) goto LAB_00561b30;
        uVar5 = *(uint *)(param_1 + 0x2c0);
        if ((uVar5 & 1) == 0) break;
        if ((uVar4 & 0x400) != 0) goto LAB_00561b30;
      }
    } while ((uVar5 & 2) != 0);
  }
LAB_00561b30:
  func_0x004c7520(lVar1,0,0,0);
  return *(int *)(param_1 + 0x280);
}



/* CONTEXT / separate function: adjacent_561c90 @ 0x561c90; ev_8ec11e8b00fddda39a6fdd9ca81c28249149116561a6ae10146f09cad5b58736
 * Ghidra body ranges: 0x561c90..0x561cef
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void adjacent_561c90(long param_1)

{
  long lVar1;
  
  lVar1 = *(long *)(param_1 + 8);
  func_0x0055c4e0(param_1 + 0xa0);
  if (*(int *)(lVar1 + 0xb48) == 1) {
    return;
  }
  *(undefined8 *)(param_1 + 0x3b0) = 0xffffffffffffffff;
  *(undefined8 *)(param_1 + 0x3b8) = 0xffffffffffffffff;
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* CONTEXT / separate function: adjacent_561cf0 @ 0x561cf0; ev_6b6486b70ba0f569259ac3ca05b31c166a0282b2321d9b5ee4963de6de6101c1
 * Ghidra body ranges: 0x561cf0..0x561d2f, 0x561da7..0x561dd3
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void adjacent_561cf0(uint param_1)

{
  code *pcVar1;
  
  if (param_1 < 5) {
                    /* WARNING: Could not emulate address calculation at 0x00561d27 */
                    /* WARNING: Treating indirect jump as call */
    (*(code *)((long)*(int *)((ulong)param_1 * 4 + 0x159b8b0) + 0x159b8b0))();
    return;
  }
  func_0x007f1950();
  func_0x007f18a0(0x561da7,(long)(int)param_1);
  func_0x00c9aa10(0x33,0x1346fd5,param_1);
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* CONTEXT / separate function: adjacent_561de0 @ 0x561de0; ev_cd0509598fbaab7ad3b8a03ac19d6b2b604a53b024f945c6a60adf76755a7294
 * Ghidra body ranges: 0x561de0..0x561e56
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void adjacent_561de0(uint param_1)

{
  long lVar1;
  uint uVar2;
  long *in_GS_OFFSET;
  
  lVar1 = *in_GS_OFFSET;
  uVar2 = *(uint *)(lVar1 + 0xe4) & 0x282000;
  if (uVar2 == param_1) {
    return;
  }
  func_0x004c78b0(lVar1,0,0x12b5611,0xbb3);
  *(uint *)(lVar1 + 0xe4) = ~uVar2 & *(uint *)(lVar1 + 0xe4) | param_1;
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* CONTEXT / separate function: adjacent_561e60 @ 0x561e60; ev_45e7f41acec0b8fe642842b852ff6e232928e908e4bdb4b967c3ae4acfba05b0
 * Ghidra body ranges: 0x561e60..0x561f0b
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void adjacent_561e60(long param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined4 uVar2;
  undefined1 local_98 [16];
  undefined4 local_88;
  undefined4 local_80;
  long local_28;
  
  local_28 = _DAT_0391c310;
  if (*(long *)(param_1 + 0x40) == 0) {
    uVar2 = 0xffffffff;
  }
  else {
    uVar2 = *(undefined4 *)(*(long *)(param_1 + 0x40) + 4);
  }
  func_0x004ad5e0(3,0x13715a2,*(undefined4 *)(param_1 + 0xbc),param_1 + 0x5e4,uVar2,param_2);
  *(byte *)(param_1 + 0xb1) = *(byte *)(param_1 + 0xb1) | 0x80;
  func_0x00258ff0(local_98,0x70);
  local_88 = 9;
  local_80 = 0x10006;
  adjacent_560540(param_1,0,9,local_98);
  if (_DAT_0391c310 == local_28) {
    return;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* CONTEXT / separate function: adjacent_561f10 @ 0x561f10; ev_34f7336e5fa2bf67b66e111c80c609c9ad5292ccc20efb542e4a05182023cfe3
 * Ghidra body ranges: 0x561f10..0x562026
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted.", "Ghidra Listing reports a terminal call at 0x562022 to 0x560540 adjacent_560540 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

void adjacent_561f10(long param_1,undefined4 param_2,undefined4 param_3)

{
  uint *puVar1;
  ulong *puVar2;
  uint uVar3;
  long lVar4;
  long lVar5;
  
  puVar1 = (uint *)(*(long *)(param_1 + 0xe0) + 0xb0);
  *puVar1 = *puVar1 | 0x8000000;
  if ((*(byte *)(param_1 + 0x562) & 2) != 0) {
    puVar2 = (ulong *)(*(long *)(param_1 + 0xe0) + 0x560);
    *puVar2 = *puVar2 | 0x20000000;
  }
  func_0x00c06910(*(undefined8 *)(param_1 + 0xe0));
  lVar4 = *(long *)(*(long *)(param_1 + 0xe0) + 0xa8);
  lVar5 = lVar4 + 0xcc0;
  func_0x004c6a00(lVar5,0,0,0);
  uVar3 = *(uint *)(lVar4 + 0xca0);
  func_0x004c6fa0(lVar5,0,0,0);
  if ((uVar3 & 2) != 0) {
    return;
  }
  if (*(long *)(param_1 + 0x1b0) == 0) {
    lVar5 = 0;
  }
  else {
    *(undefined4 *)(*(long *)(param_1 + 0x1b0) + 0x10) = 0x14;
    *(undefined4 *)(*(long *)(param_1 + 0x1b0) + 0x18) = param_2;
    *(undefined4 *)(*(long *)(param_1 + 0x1b0) + 0x24) = param_3;
    *(undefined4 *)(*(long *)(param_1 + 0x1b0) + 0x1c) = *(undefined4 *)(param_1 + 0xbc);
    *(undefined4 *)(*(long *)(param_1 + 0x1b0) + 0x20) =
         *(undefined4 *)(*(long *)(param_1 + 0x40) + 8);
    lVar5 = *(long *)(param_1 + 0x1b0);
    if (*(long *)(lVar5 + 0x68) != 0) {
      return;
    }
  }
  adjacent_560540(*(undefined8 *)(param_1 + 0xe0),0,0x14,lVar5);
  return;
}



/* CONTEXT / separate function: adjacent_562030 @ 0x562030; ev_24c8669292f2bbf41e58554b7ea5473c61959baadff1f04308571122d1997940
 * Ghidra body ranges: 0x562030..0x5620d3
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted.", "Ghidra Listing reports a terminal call at 0x5620cf to 0x560540 adjacent_560540 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

void adjacent_562030(long param_1)

{
  uint uVar1;
  uint uVar2;
  undefined4 uVar3;
  long lVar4;
  
  uVar1 = *(uint *)(param_1 + 0xa30);
  uVar3 = 3;
  uVar2 = uVar1 & 0x7f;
  if ((-1 < (char)uVar1) && (((uVar2 == 0 || (uVar2 == 0x7f)) || (uVar3 = 2, uVar1 == 0x13)))) {
    uVar2 = *(uint *)(param_1 + 0xa2c);
    uVar3 = 1;
  }
  if (*(long *)(param_1 + 0x1b0) == 0) {
    lVar4 = 0;
  }
  else {
    *(undefined4 *)(*(long *)(param_1 + 0x1b0) + 0x10) = 0x14;
    *(undefined4 *)(*(long *)(param_1 + 0x1b0) + 0x18) = uVar3;
    *(uint *)(*(long *)(param_1 + 0x1b0) + 0x24) = uVar2;
    *(undefined4 *)(*(long *)(param_1 + 0x1b0) + 0x1c) = *(undefined4 *)(param_1 + 0xbc);
    *(undefined4 *)(*(long *)(param_1 + 0x1b0) + 0x20) =
         *(undefined4 *)(*(long *)(param_1 + 0x40) + 8);
    lVar4 = *(long *)(param_1 + 0x1b0);
    if (*(long *)(lVar4 + 0x68) != 0) {
      return;
    }
  }
  adjacent_560540(*(undefined8 *)(param_1 + 0xe0),0,0x14,lVar4);
  return;
}



/* TARGET: handler_650_651_nosys_body @ 0x5620e0; ev_d3bc602c2586b12228e23650aa2a3b4c6f855acfc2f0888aecc081fca0243cc6
 * Ghidra body ranges: 0x5620e0..0x562187
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
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



/* CONTEXT / separate function: adjacent_562190 @ 0x562190; ev_6475db03a3a4a247e98360ad68047d3f532e1de79e2ba849e8ca5650302b5893
 * Ghidra body ranges: 0x562190..0x5622f7, 0x562300..0x5623c9
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void adjacent_562190(long *param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  code *pcVar4;
  long lVar5;
  long lVar6;
  undefined1 local_118 [16];
  undefined4 local_108;
  undefined4 local_100;
  undefined1 local_a8 [16];
  undefined4 local_98;
  undefined4 local_90;
  long local_38;
  
  local_38 = _DAT_0391c310;
  func_0x00258ff0(local_118,0x70);
  local_100 = 0x10006;
  local_108 = param_2;
  func_0x004c6a00(0x3981e70,0,0,0);
  param_1 = (long *)*param_1;
  if (param_1 == (long *)0x0) goto LAB_00562293;
  if ((int)param_1[4] < 1) {
    if (-1 < (int)param_1[4]) goto LAB_00562293;
    func_0x004c6a00(*param_1 + 0x48,0,0,0);
    lVar5 = *param_1;
    lVar6 = *(long *)(lVar5 + 0x10);
    if (lVar6 != 0) {
      do {
        func_0x004c6a00(lVar6 + 0x148,0,0,0);
        if (*(int *)(lVar6 + 0xb8) == 1) {
          iVar1 = *(int *)(param_1[3] + 4);
          if (iVar1 != 0) {
            iVar2 = *(int *)(param_1[3] + 8);
            iVar3 = *(int *)(*(long *)(lVar6 + 0x40) + 8);
            if ((((iVar2 != iVar3) && (iVar1 != iVar3)) &&
                (iVar3 = *(int *)(*(long *)(lVar6 + 0x40) + 4), iVar2 != iVar3)) && (iVar1 != iVar3)
               ) goto LAB_0056232c;
          }
          if ((param_3 == 0) || ((*(byte *)(lVar6 + 0xb0) & 2) != 0)) {
            func_0x00258ff0(local_a8);
            local_90 = 0x10006;
            local_98 = param_2;
            adjacent_560540(lVar6,0,param_2);
          }
        }
LAB_0056232c:
        func_0x004c6fa0(lVar6 + 0x148,0,0);
        lVar6 = *(long *)(lVar6 + 0xd0);
      } while (lVar6 != 0);
      lVar5 = *param_1;
    }
    lVar5 = lVar5 + 0x48;
  }
  else {
    func_0x004c6a00(*param_1 + 0x148,0,0,0);
    lVar5 = *param_1;
    iVar1 = *(int *)(param_1[3] + 4);
    if (iVar1 == 0) {
LAB_00562244:
      func_0x00258ff0(local_a8,0x70);
      local_90 = 0x10006;
      local_98 = param_2;
      adjacent_560540(lVar5,0,param_2,local_a8);
      lVar5 = *param_1;
    }
    else {
      iVar2 = *(int *)(param_1[3] + 8);
      iVar3 = *(int *)(*(long *)(lVar5 + 0x40) + 8);
      if (((iVar2 == iVar3) || (iVar1 == iVar3)) ||
         ((iVar3 = *(int *)(*(long *)(lVar5 + 0x40) + 4), iVar2 == iVar3 || (iVar1 == iVar3))))
      goto LAB_00562244;
    }
    lVar5 = lVar5 + 0x148;
  }
  func_0x004c6fa0(lVar5,0,0,0);
LAB_00562293:
  func_0x004c6fa0(0x3981e70,0,0,0);
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar4 = (code *)invalidInstructionException();
    (*pcVar4)();
  }
  return;
}



/* CONTEXT / separate function: adjacent_5623d0 @ 0x5623d0; ev_cc73a5b9de3f6e5430fd4a46fee65ca962b327cc64380620cfe07520bc91789a
 * Ghidra body ranges: 0x5623d0..0x562419
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

long adjacent_5623d0(void)

{
  long lVar1;
  
  lVar1 = func_0x00c08b50(0xcc8,0x1ad1be0,0x102);
  *(undefined4 *)(lVar1 + 0xca4) = 1;
  func_0x004c7dd0(lVar1 + 0xcc0,0x128c1da,0,0);
  return lVar1;
}



/* CONTEXT / separate function: FUN_00562420 @ 0x562420; ev_4c69051c30cb0505173f87125bc0dfea8251358f5f6cbd0d3b9366cf17088d01
 * Ghidra body ranges: 0x562420..0x562431, 0x56245f..0x56245f
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void FUN_00562420(long param_1)

{
  int *piVar1;
  int iVar2;
  
  LOCK();
  piVar1 = (int *)(param_1 + 0xca4);
  iVar2 = *piVar1;
  *piVar1 = *piVar1 + -1;
  UNLOCK();
  if (iVar2 == 1) {
    func_0x004c7e50(param_1 + 0xcc0);
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  return;
}



/* CONTEXT / separate function: adjacent_562432 @ 0x562432; ev_2c43695f815ab3f56c656565f615da39a8a7b3e452f6fb5ebb9bba35fa8c39a3
 * Ghidra body ranges: 0x562432..0x56245e
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void adjacent_562432(long param_1)

{
  func_0x004c7e50(param_1 + 0xcc0);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* CONTEXT / separate function: adjacent_562460 @ 0x562460; ev_90f39c8d8d9bda978e0576fada82144d9d9c67ea556cd770a839eb499baede63
 * Ghidra body ranges: 0x562460..0x562470
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

long adjacent_562460(long param_1)

{
  LOCK();
  *(int *)(param_1 + 0xca4) = *(int *)(param_1 + 0xca4) + 1;
  UNLOCK();
  return param_1;
}



/* CONTEXT / separate function: adjacent_562480 @ 0x562480; ev_a20e8a330a263a4749108119f1f40473b29bcbc659d7c3071e9e780a3091dd7a
 * Ghidra body ranges: 0x562480..0x5624cc
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void adjacent_562480(undefined8 param_1,long param_2)

{
  func_0x004c6a00(param_2 + 0xcc0,0,0,0);
  func_0x00259be0(param_2,param_1,0xca4);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* CONTEXT / separate function: adjacent_5624d0 @ 0x5624d0; ev_b3d9213581cc86e35c8b37fe9385e78684640514b3c8123a042eba55432c13f3
 * Ghidra body ranges: 0x5624d0..0x5624e1
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

bool adjacent_5624d0(long param_1)

{
  return 1 < *(uint *)(param_1 + 0xca4);
}



/* CONTEXT / separate function: adjacent_5624f0 @ 0x5624f0; ev_a7dee76f09501ad9e54852528a9818ebc84cfd1858ec588aa274edc5dbf72067
 * Ghidra body ranges: 0x5624f0..0x56255a
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Possible PIC construction at 0x00562536: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x0056253b) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void adjacent_5624f0(void)

{
  _DAT_035ab098 = func_0x0043b0e0(0x12d4fec,0x70,0,0,0,0,7,0);
  func_0x0043d710(_DAT_035ab098,_DAT_01ad75b4);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* CONTEXT / separate function: adjacent_562560 @ 0x562560; ev_a98d70e0267586305fb0546eba623c8644aa2b5f469bcb1321e0af68cbc96ea6
 * Ghidra body ranges: 0x562560..0x56257c, 0x562580..0x5625cb, 0x5625d0..0x56271f
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void adjacent_562560(uint *param_1,uint *param_2,uint *param_3)

{
  int *piVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  long lVar9;
  long lVar10;
  long *plVar11;
  undefined8 *puVar12;
  code *pcVar13;
  long *plVar14;
  uint uVar15;
  
  if (*(long **)(param_1 + 8) != (long *)0x0) {
    lVar9 = *(long *)(param_2 + 0xc);
    lVar10 = *(long *)(param_1 + 0xc);
    plVar14 = *(long **)(param_1 + 8);
    do {
      plVar11 = (long *)*plVar14;
      uVar15 = (int)plVar14[2] - 1;
      if ((param_3[(int)uVar15 >> 5] >> (uVar15 & 0x1f) & 1) != 0) {
        if (plVar11 == (long *)0x0) {
          if (*(long **)plVar14[1] != plVar14) goto LAB_005626a6;
          *(undefined8 **)(param_1 + 10) = (undefined8 *)plVar14[1];
        }
        else {
          if ((long *)plVar11[1] != plVar14) {
            func_0x007f1950();
            func_0x007f2180(0x5626e0,plVar14,*plVar14,*(undefined8 *)(*plVar14 + 8),plVar14);
            func_0x00c9aa10(0x1b,0x12a1191,plVar14,*plVar14,*(undefined8 *)(*plVar14 + 8),plVar14);
                    /* WARNING: Does not return */
            pcVar13 = (code *)invalidInstructionException();
            (*pcVar13)();
          }
          if (*(long **)plVar14[1] != plVar14) {
LAB_005626a6:
            func_0x007f1950();
            func_0x007f20c0(0x5626a6,plVar14,(undefined8 *)plVar14[1],*(undefined8 *)plVar14[1]);
            func_0x00c9aa10(0x1f,0x139aea6,plVar14,(undefined8 *)plVar14[1],
                            *(undefined8 *)plVar14[1]);
                    /* WARNING: Does not return */
            pcVar13 = (code *)invalidInstructionException();
            (*pcVar13)();
          }
          plVar11[1] = (long)plVar14[1];
        }
        *(long *)plVar14[1] = *plVar14;
        if (lVar10 != 0) {
          piVar1 = (int *)(lVar10 + 0x3b4);
          *piVar1 = *piVar1 + -1;
        }
        *plVar14 = 0;
        puVar12 = *(undefined8 **)(param_2 + 10);
        plVar14[1] = (long)puVar12;
        *puVar12 = plVar14;
        *(long **)(param_2 + 10) = plVar14;
        plVar14[0xd] = (long)param_2;
        if (lVar9 != 0) {
          piVar1 = (int *)(lVar9 + 0x3b4);
          *piVar1 = *piVar1 + 1;
        }
      }
      plVar14 = plVar11;
    } while (plVar11 != (long *)0x0);
  }
  uVar15 = *param_3;
  uVar2 = param_3[1];
  uVar3 = param_3[2];
  uVar4 = param_3[3];
  uVar5 = param_1[4];
  uVar6 = param_1[5];
  uVar7 = param_1[6];
  uVar8 = param_1[7];
  param_2[4] = param_2[4] | uVar15 & uVar5;
  param_2[5] = param_2[5] | uVar2 & uVar6;
  param_2[6] = param_2[6] | uVar3 & uVar7;
  param_2[7] = param_2[7] | uVar4 & uVar8;
  param_1[4] = param_1[4] & ~(uVar15 & uVar5);
  param_1[5] = param_1[5] & ~(uVar2 & uVar6);
  param_1[6] = param_1[6] & ~(uVar3 & uVar7);
  param_1[7] = param_1[7] & ~(uVar4 & uVar8);
  uVar15 = *param_3;
  uVar2 = param_3[1];
  uVar3 = param_3[2];
  uVar4 = param_3[3];
  uVar5 = *param_1;
  uVar6 = param_1[1];
  uVar7 = param_1[2];
  uVar8 = param_1[3];
  *param_2 = *param_2 | uVar15 & uVar5;
  param_2[1] = param_2[1] | uVar2 & uVar6;
  param_2[2] = param_2[2] | uVar3 & uVar7;
  param_2[3] = param_2[3] | uVar4 & uVar8;
  *param_1 = *param_1 & ~(uVar15 & uVar5);
  param_1[1] = param_1[1] & ~(uVar2 & uVar6);
  param_1[2] = param_1[2] & ~(uVar3 & uVar7);
  param_1[3] = param_1[3] & ~(uVar4 & uVar8);
  return;
}



/* CONTEXT / separate function: adjacent_562720 @ 0x562720; ev_5d8e4a1d4e9ffc4519262273cc53a1da4260d9d52b0d560d0c2eed81b8cadf14
 * Ghidra body ranges: 0x562720..0x562791
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void adjacent_562720(undefined8 param_1,undefined8 param_2,undefined8 param_3,long param_4)

{
  code *pcVar1;
  int iVar2;
  uint uVar3;
  uint local_24;
  long local_20;
  
  local_20 = _DAT_0391c310;
  local_24 = _DAT_01ad75f0;
  iVar2 = func_0x002709e8(param_1,&local_24,0);
  if ((iVar2 == 0) && (*(long *)(param_4 + 0x30) != 0)) {
    uVar3 = ~((int)local_24 >> 0x1f) & local_24;
    _DAT_01ad75f0 = 10;
    if ((int)uVar3 < 10) {
      _DAT_01ad75f0 = uVar3;
    }
  }
  if (_DAT_0391c310 != local_20) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar1 = (code *)invalidInstructionException();
    (*pcVar1)();
  }
  return;
}



/* CONTEXT / separate function: adjacent_5627a0 @ 0x5627a0; ev_cdf2a81043482e002955dc9eb4ed908d12d6a5465eaec6eac784891a054bf58b
 * Ghidra body ranges: 0x5627a0..0x5627f6
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined4
adjacent_5627a0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  undefined4 uVar1;
  
  func_0x00c4bb20(0x3589e60,0,0,0);
  uVar1 = func_0x00270ab0(param_1,0x1ad7600,0x400,param_4);
  func_0x00c4c4b0(0x3589e60,0,0);
  return uVar1;
}



/* CONTEXT / separate function: adjacent_562800 @ 0x562800; ev_018bce5b495ffba6761c2a1d65d0378600fd1003b8d481fd10b65cec102eaf8b
 * Ghidra body ranges: 0x562800..0x5628e0, 0x5628f0..0x562986, 0x562990..0x562bba
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted.", "Ghidra Listing reports a terminal call at 0x562b9b to 0x562bc0 adjacent_562bc0 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void adjacent_562800(long param_1)

{
  code *pcVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  uint *puVar5;
  undefined4 *puVar6;
  undefined8 uVar7;
  short sVar8;
  
  iVar2 = func_0x002b3be0(*(undefined8 *)(param_1 + 0x18dc38));
  if ((iVar2 != 0) && (iVar2 = func_0x002b3be0(*(undefined8 *)(param_1 + 0x18dc38)), iVar2 == 0)) {
    puVar5 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
    if (*(long *)(param_1 + 0x18e320) == 0) {
      uVar3 = in((short)puVar5);
      puVar5 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
      uVar3 = uVar3 & 0xfffffffb;
      if (*(long *)(param_1 + 0x18e320) == 0) {
        out((short)puVar5,uVar3);
        goto LAB_00562869;
      }
    }
    else {
      uVar3 = *puVar5 & 0xfffffffb;
    }
    *puVar5 = uVar3;
  }
LAB_00562869:
  puVar6 = (undefined4 *)((ulong)*(uint *)(param_1 + 0x18e348) + *(long *)(param_1 + 0x18e328));
  if (*(long *)(param_1 + 0x18e320) == 0) {
    out((short)puVar6,2);
    sVar8 = 0x19;
  }
  else {
    *puVar6 = 2;
    sVar8 = 0x19;
  }
  do {
    func_0x00beda40(0,_DAT_03920440 / 100);
    puVar5 = (uint *)((ulong)*(uint *)(param_1 + 0x18e348) + *(long *)(param_1 + 0x18e328));
    if (*(long *)(param_1 + 0x18e320) == 0) {
      uVar3 = in((short)puVar5);
    }
    else {
      uVar3 = *puVar5;
    }
    if ((uVar3 & 2) == 0) {
      sVar8 = 100;
      goto LAB_00562940;
    }
    sVar8 = sVar8 + -1;
  } while (sVar8 != 0);
  func_0x002b3c70(*(undefined8 *)(param_1 + 0x18dc38),0x139060d);
  func_0x007f1950();
  func_0x007f1810(0x562910);
  uVar7 = 0xf;
LAB_005629d0:
  func_0x00c9aa10(uVar7,0x12bf330);
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
  while (sVar8 = sVar8 + -1, sVar8 != 0) {
LAB_00562940:
    func_0x00beda40(0,_DAT_03920440 / 100);
    puVar5 = (uint *)((ulong)(*(int *)(param_1 + 0x18e348) + 4) + *(long *)(param_1 + 0x18e328));
    if (*(long *)(param_1 + 0x18e320) == 0) {
      uVar3 = in((short)puVar5);
    }
    else {
      uVar3 = *puVar5;
    }
    if ((uVar3 & 0x800) == 0) {
      iVar2 = func_0x002b3be0(*(undefined8 *)(param_1 + 0x18dc38));
      iVar4 = func_0x002b3be0(*(undefined8 *)(param_1 + 0x18dc38));
      if (iVar2 == 0) {
        if (iVar4 == 0) {
          puVar5 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
          if (*(long *)(param_1 + 0x18e320) == 0) {
            uVar3 = in((short)puVar5);
            puVar5 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
            uVar3 = uVar3 & 0xfffffffd;
            if (*(long *)(param_1 + 0x18e320) == 0) {
              out((short)puVar5,uVar3);
              goto LAB_00562aec;
            }
          }
          else {
            uVar3 = *puVar5 & 0xfffffffd;
          }
          *puVar5 = uVar3;
        }
LAB_00562aec:
        iVar2 = func_0x002b3be0(*(undefined8 *)(param_1 + 0x18dc38));
        if (iVar2 == 0) {
          puVar5 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
          if (*(long *)(param_1 + 0x18e320) == 0) {
            uVar3 = in((short)puVar5);
            puVar5 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
            uVar3 = uVar3 & 0xfffdffff;
            if (*(long *)(param_1 + 0x18e320) == 0) {
              out((short)puVar5,uVar3);
              goto LAB_00562b3b;
            }
          }
          else {
            uVar3 = *puVar5 & 0xfffdffff;
          }
          *puVar5 = uVar3;
        }
LAB_00562b3b:
        iVar2 = func_0x002b3be0(*(undefined8 *)(param_1 + 0x18dc38));
        if (iVar2 == 0) {
          puVar5 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
          if (*(long *)(param_1 + 0x18e320) == 0) {
            uVar3 = in((short)puVar5);
            puVar5 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
            uVar3 = uVar3 & 0xfdffffff;
            if (*(long *)(param_1 + 0x18e320) == 0) {
              out((short)puVar5,uVar3);
              goto LAB_00562b8a;
            }
          }
          else {
            uVar3 = *puVar5 & 0xfdffffff;
          }
          *puVar5 = uVar3;
        }
LAB_00562b8a:
        func_0x0046e1e0(20000);
        goto LAB_00562b94;
      }
      if (iVar4 == 0) {
        puVar5 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
        if (*(long *)(param_1 + 0x18e320) == 0) {
          uVar3 = in((short)puVar5);
          puVar5 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
          uVar3 = uVar3 & 0xfffffffd;
          if (*(long *)(param_1 + 0x18e320) == 0) {
            out((short)puVar5,uVar3);
            goto LAB_00562a69;
          }
        }
        else {
          uVar3 = *puVar5 & 0xfffffffd;
        }
        *puVar5 = uVar3;
      }
LAB_00562a69:
      func_0x0046e1e0(10000);
      iVar2 = func_0x002b3be0(*(undefined8 *)(param_1 + 0x18dc38));
      if (iVar2 == 0) {
        puVar5 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
        if (*(long *)(param_1 + 0x18e320) == 0) {
          uVar3 = in((short)puVar5);
          puVar5 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
          uVar3 = uVar3 | 4;
          if (*(long *)(param_1 + 0x18e320) == 0) {
            out((short)puVar5,uVar3);
            goto LAB_00562b94;
          }
        }
        else {
          uVar3 = *puVar5 | 4;
        }
        *puVar5 = uVar3;
      }
LAB_00562b94:
      adjacent_562bc0(param_1);
      return;
    }
  }
  func_0x002b3c70(*(undefined8 *)(param_1 + 0x18dc38),0x135cc13);
  func_0x007f1950();
  func_0x007f1810(0x5629b3);
  uVar7 = 0x13;
  goto LAB_005629d0;
}



/* CONTEXT / separate function: adjacent_562bc0 @ 0x562bc0; ev_80aa37c7c2e34b13e9c2ae868564c0b63d2f401c6861714e93bd95df7b9fe7bd
 * Ghidra body ranges: 0x562bc0..0x562cc4
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

uint adjacent_562bc0(long param_1)

{
  uint uVar1;
  uint *puVar2;
  undefined4 *puVar3;
  
  puVar2 = (uint *)((ulong)(*(int *)(param_1 + 0x18e34c) + 0xc100) + *(long *)(param_1 + 0x18e328));
  if (*(long *)(param_1 + 0x18e320) == 0) {
    uVar1 = in((short)puVar2);
    puVar2 = (uint *)((ulong)(*(int *)(param_1 + 0x18e34c) + 0xc100) + *(long *)(param_1 + 0x18e328)
                     );
    uVar1 = uVar1 & 0xfffffff0 | 0xe;
    if (*(long *)(param_1 + 0x18e320) == 0) {
      out((short)puVar2,uVar1);
      goto LAB_00562c13;
    }
  }
  else {
    uVar1 = *puVar2 & 0xfffffff0 | 0xe;
  }
  *puVar2 = uVar1;
LAB_00562c13:
  puVar3 = (undefined4 *)
           ((ulong)(*(int *)(param_1 + 0x18e34c) + 0xc12c) + *(long *)(param_1 + 0x18e328));
  if (*(long *)(param_1 + 0x18e320) == 0) {
    uVar1 = 0x7fc0c010;
    out((short)puVar3,0x7fc0c010);
  }
  else {
    *puVar3 = 0x7fc0c010;
  }
  puVar3 = (undefined4 *)
           ((ulong)(*(int *)(param_1 + 0x18e34c) + 0xc200) + *(long *)(param_1 + 0x18e328));
  if (*(long *)(param_1 + 0x18e320) == 0) {
    uVar1 = 0x1548;
    out((short)puVar3,0x1548);
  }
  else {
    *puVar3 = 0x1548;
  }
  puVar3 = (undefined4 *)
           ((ulong)(*(int *)(param_1 + 0x18e34c) + 0xc204) + *(long *)(param_1 + 0x18e328));
  if (*(long *)(param_1 + 0x18e320) == 0) {
    uVar1 = 0x1548;
    out((short)puVar3,0x1548);
  }
  else {
    *puVar3 = 0x1548;
  }
  puVar3 = (undefined4 *)
           ((ulong)(*(int *)(param_1 + 0x18e34c) + 0xc208) + *(long *)(param_1 + 0x18e328));
  if (*(long *)(param_1 + 0x18e320) == 0) {
    out((short)puVar3,0x1548);
    return 0x1548;
  }
  *puVar3 = 0x1548;
  return uVar1;
}



/* CONTEXT / separate function: adjacent_562cd0 @ 0x562cd0; ev_c6753dab5094c9bb1a402c1f4985e2a6a1fb0647e80354940b0948aaf280a0f5
 * Ghidra body ranges: 0x562cd0..0x562eb9
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Possible PIC construction at 0x00562de6: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x00562deb) */
/* WARNING: Removing unreachable block (ram,0x00562dfb) */
/* WARNING: Removing unreachable block (ram,0x00562e19) */
/* WARNING: Removing unreachable block (ram,0x00562e44) */
/* WARNING: Removing unreachable block (ram,0x00562e12) */
/* WARNING: Removing unreachable block (ram,0x00562e34) */
/* WARNING: Removing unreachable block (ram,0x00562e36) */

void adjacent_562cd0(long param_1,char param_2)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint *puVar4;
  
  iVar1 = func_0x002b3be0(*(undefined8 *)(param_1 + 0x18dc38));
  iVar2 = func_0x002b3be0(*(undefined8 *)(param_1 + 0x18dc38));
  if (iVar1 != 0) {
    if (iVar2 != 0) {
      halt_baddata();
    }
    puVar4 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
    if (*(long *)(param_1 + 0x18e320) == 0) {
      uVar3 = in((short)puVar4);
      puVar4 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
      uVar3 = uVar3 & 0xfffffffd;
      if (*(long *)(param_1 + 0x18e320) == 0) {
        out((short)puVar4,uVar3);
        halt_baddata();
      }
    }
    else {
      uVar3 = *puVar4 & 0xfffffffd;
    }
    *puVar4 = uVar3;
    halt_baddata();
  }
  if (param_2 == '\x02') {
    if (iVar2 != 0) {
      halt_baddata();
    }
    puVar4 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
    if (*(long *)(param_1 + 0x18e320) == 0) {
      uVar3 = in((short)puVar4);
      puVar4 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
      uVar3 = uVar3 & 0xfffdffff;
      if (*(long *)(param_1 + 0x18e320) == 0) {
        out((short)puVar4,uVar3);
        halt_baddata();
      }
      goto LAB_00562dae;
    }
    uVar3 = 0xfffdffff;
  }
  else {
    if (param_2 == '\x01') {
      if (iVar2 != 0) {
        halt_baddata();
      }
      puVar4 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
      if (*(long *)(param_1 + 0x18e320) == 0) {
        uVar3 = in((short)puVar4);
        puVar4 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
        uVar3 = uVar3 & 0xfffffffd;
        if (*(long *)(param_1 + 0x18e320) == 0) {
          out((short)puVar4,uVar3);
          halt_baddata();
        }
      }
      else {
        uVar3 = *puVar4 & 0xfffffffd;
      }
      goto LAB_00562dae;
    }
    if (iVar2 != 0) {
      halt_baddata();
    }
    puVar4 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
    if (*(long *)(param_1 + 0x18e320) == 0) {
      uVar3 = in((short)puVar4);
      puVar4 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
      uVar3 = uVar3 & 0xfdffffff;
      if (*(long *)(param_1 + 0x18e320) == 0) {
        out((short)puVar4,uVar3);
        halt_baddata();
      }
      goto LAB_00562dae;
    }
    uVar3 = 0xfdffffff;
  }
  uVar3 = uVar3 & *puVar4;
LAB_00562dae:
  *puVar4 = uVar3;
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* CONTEXT / separate function: adjacent_562ec0 @ 0x562ec0; ev_365809bd8534f6393fb2f197450a47ac2a0413bd3644c8007a115847d42d3e59
 * Ghidra body ranges: 0x562ec0..0x56319f
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void adjacent_562ec0(long param_1,char param_2)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint *puVar4;
  
  iVar1 = func_0x002b3be0(*(undefined8 *)(param_1 + 0x18dc38));
  iVar2 = func_0x002b3be0(*(undefined8 *)(param_1 + 0x18dc38));
  if (iVar1 == 0) {
    if (param_2 == '\x02') {
      if (iVar2 == 0) {
        puVar4 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
        if (*(long *)(param_1 + 0x18e320) == 0) {
          uVar3 = in((short)puVar4);
          puVar4 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
          uVar3 = uVar3 | 0x20000;
          if (*(long *)(param_1 + 0x18e320) == 0) {
            out((short)puVar4,uVar3);
            goto LAB_005630c5;
          }
        }
        else {
          uVar3 = *puVar4 | 0x20000;
        }
        *puVar4 = uVar3;
      }
LAB_005630c5:
      iVar1 = func_0x002b3be0(*(undefined8 *)(param_1 + 0x18dc38));
      if (iVar1 != 0) {
        return;
      }
      puVar4 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
      if (*(long *)(param_1 + 0x18e320) == 0) {
        uVar3 = in((short)puVar4);
        puVar4 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
        uVar3 = uVar3 & 0xfffbffff;
        if (*(long *)(param_1 + 0x18e320) == 0) {
          out((short)puVar4,uVar3);
          return;
        }
        goto LAB_00563164;
      }
      uVar3 = 0xfffbffff;
    }
    else {
      if (param_2 == '\x01') {
        if (iVar2 == 0) {
          puVar4 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
          if (*(long *)(param_1 + 0x18e320) == 0) {
            uVar3 = in((short)puVar4);
            puVar4 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
            uVar3 = uVar3 | 2;
            if (*(long *)(param_1 + 0x18e320) == 0) {
              out((short)puVar4,uVar3);
              goto LAB_00563052;
            }
          }
          else {
            uVar3 = *puVar4 | 2;
          }
          *puVar4 = uVar3;
        }
LAB_00563052:
        iVar1 = func_0x002b3be0(*(undefined8 *)(param_1 + 0x18dc38));
        if (iVar1 != 0) {
          return;
        }
        puVar4 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
        if (*(long *)(param_1 + 0x18e320) == 0) {
          uVar3 = in((short)puVar4);
          puVar4 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
          uVar3 = uVar3 & 0xfffffffb;
          if (*(long *)(param_1 + 0x18e320) == 0) {
            out((short)puVar4,uVar3);
            return;
          }
          goto LAB_00563164;
        }
        goto LAB_00562fff;
      }
      if (iVar2 == 0) {
        puVar4 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
        if (*(long *)(param_1 + 0x18e320) == 0) {
          uVar3 = in((short)puVar4);
          puVar4 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
          uVar3 = uVar3 | 0x2000000;
          if (*(long *)(param_1 + 0x18e320) == 0) {
            out((short)puVar4,uVar3);
            goto LAB_00563136;
          }
        }
        else {
          uVar3 = *puVar4 | 0x2000000;
        }
        *puVar4 = uVar3;
      }
LAB_00563136:
      iVar1 = func_0x002b3be0(*(undefined8 *)(param_1 + 0x18dc38));
      if (iVar1 != 0) {
        return;
      }
      puVar4 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
      if (*(long *)(param_1 + 0x18e320) == 0) {
        uVar3 = in((short)puVar4);
        puVar4 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
        uVar3 = uVar3 & 0xfbffffff;
        if (*(long *)(param_1 + 0x18e320) == 0) {
          out((short)puVar4,uVar3);
          return;
        }
        goto LAB_00563164;
      }
      uVar3 = 0xfbffffff;
    }
    uVar3 = uVar3 & *puVar4;
  }
  else {
    if (iVar2 == 0) {
      puVar4 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
      if (*(long *)(param_1 + 0x18e320) == 0) {
        uVar3 = in((short)puVar4);
        puVar4 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
        uVar3 = uVar3 | 2;
        if (*(long *)(param_1 + 0x18e320) == 0) {
          out((short)puVar4,uVar3);
          goto LAB_00562fd4;
        }
      }
      else {
        uVar3 = *puVar4 | 2;
      }
      *puVar4 = uVar3;
    }
LAB_00562fd4:
    iVar1 = func_0x002b3be0(*(undefined8 *)(param_1 + 0x18dc38));
    if (iVar1 != 0) {
      return;
    }
    puVar4 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
    if (*(long *)(param_1 + 0x18e320) == 0) {
      uVar3 = in((short)puVar4);
      puVar4 = (uint *)((ulong)*(uint *)(param_1 + 0x18e360) + *(long *)(param_1 + 0x18e328));
      uVar3 = uVar3 & 0xfffffffb;
      if (*(long *)(param_1 + 0x18e320) == 0) {
        out((short)puVar4,uVar3);
        return;
      }
      goto LAB_00563164;
    }
LAB_00562fff:
    uVar3 = *puVar4 & 0xfffffffb;
  }
LAB_00563164:
  *puVar4 = uVar3;
  return;
}



/* CONTEXT / separate function: adjacent_5631a0 @ 0x5631a0; ev_94c228a15bc7e807f43dcf457876016da8e844fe030d3f3a10d2bbe5956dff6c
 * Ghidra body ranges: 0x5631a0..0x563369
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_5631a0(long param_1)

{
  int iVar1;
  uint uVar2;
  uint *puVar3;
  
  func_0x002b3c70(*(undefined8 *)(param_1 + 0x18dc38),0x139aef4);
  *(undefined4 *)(param_1 + 0x18e360) = 0x100000;
  iVar1 = func_0x002b3be0(*(undefined8 *)(param_1 + 0x18dc38));
  if (iVar1 == 0) {
    uVar2 = func_0x002b9880(0x24);
    func_0x002b98b0(0x24,uVar2 | 2);
  }
  iVar1 = func_0x002b3be0(*(undefined8 *)(param_1 + 0x18dc38));
  if (iVar1 == 0) {
    uVar2 = func_0x002b9880(0x24);
    func_0x002b98b0(0x24,uVar2 | 1);
  }
  iVar1 = func_0x002b3be0(*(undefined8 *)(param_1 + 0x18dc38));
  if (iVar1 == 0) {
    uVar2 = func_0x002b9880(0x24);
    func_0x002b98b0(0x24,uVar2 & 0xfffffffd);
  }
  iVar1 = func_0x002b3be0(*(undefined8 *)(param_1 + 0x18dc38));
  if (iVar1 == 0) {
    adjacent_563370(param_1,0);
    adjacent_563370(param_1,1);
    adjacent_563370(param_1,2);
  }
  iVar1 = func_0x002b3be0(*(undefined8 *)(param_1 + 0x18dc38));
  if (iVar1 == 0) {
    uVar2 = func_0x002b9880(0x24);
    func_0x002b98b0(0x24,uVar2 & 0xfffffffe);
  }
  func_0x0046e1e0(2000);
  iVar1 = func_0x002b3be0(*(undefined8 *)(param_1 + 0x18dc38));
  if (iVar1 == 0) {
    adjacent_5638e0(param_1,0);
    adjacent_5638e0(param_1,1);
    adjacent_5638e0(param_1,2);
  }
  iVar1 = func_0x002b3be0(*(undefined8 *)(param_1 + 0x18dc38));
  if (iVar1 == 0) {
    adjacent_563ca0(param_1,1);
    adjacent_563ca0(param_1,2);
    adjacent_563ca0(param_1,3);
  }
  puVar3 = (uint *)((ulong)(*(int *)(param_1 + 0x18e360) + 4) + *(long *)(param_1 + 0x18e328));
  if (*(long *)(param_1 + 0x18e320) == 0) {
    uVar2 = in((short)puVar3);
    uVar2 = uVar2 & 0xfffffffe;
    puVar3 = (uint *)((ulong)(*(int *)(param_1 + 0x18e360) + 4) + *(long *)(param_1 + 0x18e328));
    if (*(long *)(param_1 + 0x18e320) == 0) {
      out((short)puVar3,uVar2);
      goto LAB_00563356;
    }
  }
  else {
    uVar2 = *puVar3 & 0xfffffffe;
  }
  *puVar3 = uVar2;
LAB_00563356:
  adjacent_562bc0(param_1);
  return 0;
}



/* CONTEXT / separate function: adjacent_563370 @ 0x563370; ev_7999dce76e5549c856d1743a2cce1457d57f80109497af6a547f2f5eaac9b134
 * Ghidra body ranges: 0x563370..0x5638d9
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void adjacent_563370(long param_1,int param_2)

{
  undefined8 uVar1;
  long lVar2;
  code *pcVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  undefined2 uVar8;
  undefined4 *puVar9;
  uint *puVar10;
  uint *puVar11;
  uint *puVar12;
  undefined2 local_3a;
  long local_38;
  
  local_38 = _DAT_0391c310;
  iVar4 = func_0x002b3be0(*(undefined8 *)(param_1 + 0x18dc38));
  iVar7 = 0x120000;
  if (iVar4 == 0) {
    iVar7 = 0x128000;
    if (param_2 != 2) {
      iVar7 = (param_2 == 1 | 0x48) << 0xe;
    }
  }
  *(int *)(param_1 + 0x18e364) = iVar7;
  uVar5 = func_0x002b98e0(0x6c);
  uVar6 = func_0x002b98e0(0x6c);
  uVar1 = *(undefined8 *)(param_1 + 0x18dc38);
  iVar7 = func_0x002b3be0(uVar1);
  if ((uVar6 >> 0x19 & uVar5 >> 0x11 & 1) == 0) {
    func_0x002b3c70(uVar1,0x13715c7,iVar7);
    uVar5 = 0x98;
  }
  else {
    uVar5 = 0x98;
    if (iVar7 == 0) {
      uVar5 = func_0x002b98e0(0x44);
      if (param_2 == 1) {
        uVar5 = uVar5 >> 0x15 & 0x1f;
      }
      else if (param_2 == 0) {
        uVar5 = uVar5 >> 0x10 & 0x1f;
      }
      else {
        uVar5 = uVar5 >> 0x1a & 0x1f;
      }
    }
  }
  puVar9 = (undefined4 *)
           ((ulong)(*(int *)(param_1 + 0x18e364) + 0x800) + *(long *)(param_1 + 0x18e328));
  if (*(long *)(param_1 + 0x18e320) == 0) {
    in((short)puVar9);
    puVar9 = (undefined4 *)
             ((ulong)(*(int *)(param_1 + 0x18e364) + 0x800) + *(long *)(param_1 + 0x18e328));
    if (*(long *)(param_1 + 0x18e320) != 0) goto LAB_00563491;
    out((short)puVar9,0x480a);
  }
  else {
LAB_00563491:
    *puVar9 = 0x480a;
  }
  puVar9 = (undefined4 *)
           ((ulong)(*(int *)(param_1 + 0x18e364) + 0x814) + *(long *)(param_1 + 0x18e328));
  if (*(long *)(param_1 + 0x18e320) == 0) {
    in((short)puVar9);
    puVar9 = (undefined4 *)
             ((ulong)(*(int *)(param_1 + 0x18e364) + 0x814) + *(long *)(param_1 + 0x18e328));
    if (*(long *)(param_1 + 0x18e320) != 0) goto LAB_005634d8;
    out((short)puVar9,0x10a01000);
  }
  else {
LAB_005634d8:
    *puVar9 = 0x10a01000;
  }
  puVar10 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x818) + *(long *)(param_1 + 0x18e328));
  if (*(long *)(param_1 + 0x18e320) == 0) {
    uVar6 = in((short)puVar10);
    uVar6 = uVar6 & 0xff7fffff;
    puVar10 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x818) + *(long *)(param_1 + 0x18e328)
                      );
    if (*(long *)(param_1 + 0x18e320) != 0) goto LAB_00563529;
    out((short)puVar10,uVar6);
  }
  else {
    uVar6 = *puVar10 & 0xff7fffff;
LAB_00563529:
    *puVar10 = uVar6;
  }
  puVar10 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x800) + *(long *)(param_1 + 0x18e328));
  if (*(long *)(param_1 + 0x18e320) == 0) {
    uVar6 = in((short)puVar10);
    uVar6 = uVar6 | 0x20;
    puVar10 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x800) + *(long *)(param_1 + 0x18e328)
                      );
    if (*(long *)(param_1 + 0x18e320) != 0) goto LAB_00563572;
    out((short)puVar10,uVar6);
  }
  else {
    uVar6 = *puVar10 | 0x20;
LAB_00563572:
    *puVar10 = uVar6;
  }
  puVar10 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x868) + *(long *)(param_1 + 0x18e328));
  if (*(long *)(param_1 + 0x18e320) == 0) {
    uVar6 = in((short)puVar10);
    uVar6 = uVar6 & 0xfffbffff;
    puVar10 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x868) + *(long *)(param_1 + 0x18e328)
                      );
    if (*(long *)(param_1 + 0x18e320) != 0) goto LAB_005635bf;
    out((short)puVar10,uVar6);
  }
  else {
    uVar6 = *puVar10 & 0xfffbffff;
LAB_005635bf:
    *puVar10 = uVar6;
  }
  puVar10 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x804) + *(long *)(param_1 + 0x18e328));
  if (*(long *)(param_1 + 0x18e320) == 0) {
    uVar6 = in((short)puVar10);
    puVar10 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x804) + *(long *)(param_1 + 0x18e328)
                      );
    uVar5 = uVar5 << 0x13 | uVar6 & 0xff07ffff;
    puVar12 = puVar10;
    if (*(long *)(param_1 + 0x18e320) != 0) goto LAB_00563616;
    puVar11 = (uint *)((ulong)puVar10 & 0xffffffff);
    out((short)puVar11,uVar5);
  }
  else {
    uVar5 = uVar5 << 0x13 | *puVar10 & 0xff07ffff;
    puVar12 = (uint *)0x804;
LAB_00563616:
    *puVar10 = uVar5;
    puVar11 = puVar10;
    puVar10 = puVar12;
  }
  local_3a = 0;
  iVar7 = func_0x002b3be0(*(undefined8 *)(param_1 + 0x18dc38),puVar10,puVar11);
  uVar5 = 0;
  if (iVar7 == 0) {
    func_0x006da870(0,param_2,&local_3a);
    uVar5 = (uint)local_3a._1_1_;
    if (uVar5 == 0xff) {
      uVar5 = 0xff;
    }
    else {
      if (local_3a._1_1_ < 0x60) goto LAB_00563630;
      uVar5 = ((local_3a._1_1_ >> 5) - 2) + (local_3a._1_1_ & 0x1f);
    }
  }
  else {
LAB_00563630:
    uVar5 = uVar5 & 0x1f;
  }
  puVar10 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x818) + *(long *)(param_1 + 0x18e328));
  if (*(long *)(param_1 + 0x18e320) == 0) {
    uVar6 = in((short)puVar10);
    puVar10 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x818) + *(long *)(param_1 + 0x18e328)
                      );
    uVar6 = uVar6 & 0xffffff0f | 0xa0;
    if (*(long *)(param_1 + 0x18e320) != 0) goto LAB_005636ba;
    out((short)puVar10,uVar6);
  }
  else {
    uVar6 = *puVar10 & 0xffffff0f | 0xa0;
LAB_005636ba:
    *puVar10 = uVar6;
  }
  puVar10 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x818) + *(long *)(param_1 + 0x18e328));
  if (*(long *)(param_1 + 0x18e320) == 0) {
    uVar6 = in((short)puVar10);
    if (uVar5 < 3) goto LAB_005636df;
LAB_00563711:
    if (uVar5 < 6) {
      uVar6 = uVar6 & 0xfffffff0 | 7;
      puVar10 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x818) +
                        *(long *)(param_1 + 0x18e328));
      if (*(long *)(param_1 + 0x18e320) == 0) {
        out((short)puVar10,uVar6);
        goto LAB_00563832;
      }
    }
    else if (uVar5 < 8) {
      uVar6 = uVar6 & 0xfffffff0 | 6;
      puVar10 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x818) +
                        *(long *)(param_1 + 0x18e328));
      if (*(long *)(param_1 + 0x18e320) == 0) {
        out((short)puVar10,uVar6);
        goto LAB_00563832;
      }
    }
    else if (uVar5 < 10) {
      uVar6 = uVar6 & 0xfffffff0 | 5;
      puVar10 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x818) +
                        *(long *)(param_1 + 0x18e328));
      if (*(long *)(param_1 + 0x18e320) == 0) {
        out((short)puVar10,uVar6);
        goto LAB_00563832;
      }
    }
    else if (uVar5 < 0xd) {
      uVar6 = uVar6 & 0xfffffff0 | 4;
      puVar10 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x818) +
                        *(long *)(param_1 + 0x18e328));
      if (*(long *)(param_1 + 0x18e320) == 0) {
        out((short)puVar10,uVar6);
        goto LAB_00563832;
      }
    }
    else {
      func_0x002b3c70(*(undefined8 *)(param_1 + 0x18dc38),0x13a5a60);
      iVar7 = func_0x002b3be0(*(undefined8 *)(param_1 + 0x18dc38));
      if (iVar7 != 0) goto LAB_00563832;
      lVar2 = *(long *)(param_1 + 0x18e320);
      puVar10 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x818) +
                        *(long *)(param_1 + 0x18e328));
      uVar6 = uVar6 & 0xfffffff0;
      uVar8 = SUB82(puVar10,0);
      if (param_2 == 1) {
        uVar6 = uVar6 | 6;
        if (lVar2 == 0) {
          out(uVar8,uVar6);
          goto LAB_00563832;
        }
      }
      else if (param_2 == 0) {
        uVar6 = uVar6 | 4;
        if (lVar2 == 0) {
          out(uVar8,uVar6);
          goto LAB_00563832;
        }
      }
      else {
        uVar6 = uVar6 | 7;
        if (lVar2 == 0) {
          out(uVar8,uVar6);
          goto LAB_00563832;
        }
      }
    }
  }
  else {
    uVar6 = *puVar10;
    if (2 < uVar5) goto LAB_00563711;
LAB_005636df:
    uVar6 = uVar6 & 0xfffffff0 | 8;
    puVar10 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x818) + *(long *)(param_1 + 0x18e328)
                      );
    if (*(long *)(param_1 + 0x18e320) == 0) {
      out((short)puVar10,uVar6);
      goto LAB_00563832;
    }
  }
  *puVar10 = uVar6;
LAB_00563832:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar3 = (code *)invalidInstructionException();
    (*pcVar3)();
  }
  return;
}



/* CONTEXT / separate function: adjacent_5638e0 @ 0x5638e0; ev_ec14c6cc41c416fbc7a12105d077d39a17b93a9d88c467bfd739f6605b6a935c
 * Ghidra body ranges: 0x5638e0..0x563aa3, 0x563ab0..0x563c9d
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void adjacent_5638e0(long param_1,int param_2)

{
  code *pcVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint *puVar5;
  
  iVar2 = func_0x002b3be0(*(undefined8 *)(param_1 + 0x18dc38));
  uVar3 = 0x120000;
  if (iVar2 == 0) {
    uVar3 = 0x128000;
    if (param_2 != 2) {
      uVar3 = (param_2 == 1 | 0x48) << 0xe;
    }
  }
  *(uint *)(param_1 + 0x18e364) = uVar3;
  puVar5 = (uint *)((ulong)uVar3 + 0x814 + *(long *)(param_1 + 0x18e328));
  if (*(long *)(param_1 + 0x18e320) == 0) {
    uVar3 = in((short)puVar5);
    uVar3 = uVar3 | 0x8000;
    puVar5 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x814) + *(long *)(param_1 + 0x18e328))
    ;
    if (*(long *)(param_1 + 0x18e320) != 0) goto LAB_00563974;
    out((short)puVar5,uVar3);
  }
  else {
    uVar3 = *puVar5 | 0x8000;
LAB_00563974:
    *puVar5 = uVar3;
  }
  func_0x0046e1e0(1);
  puVar5 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x110) + *(long *)(param_1 + 0x18e328));
  if (*(long *)(param_1 + 0x18e320) == 0) {
    uVar3 = in((short)puVar5);
    uVar3 = uVar3 | 0x100;
    puVar5 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x110) + *(long *)(param_1 + 0x18e328))
    ;
    if (*(long *)(param_1 + 0x18e320) != 0) goto LAB_005639cb;
    out((short)puVar5,uVar3);
  }
  else {
    uVar3 = *puVar5 | 0x100;
LAB_005639cb:
    *puVar5 = uVar3;
  }
  puVar5 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x100) + *(long *)(param_1 + 0x18e328));
  if (*(long *)(param_1 + 0x18e320) == 0) {
    uVar3 = in((short)puVar5);
    puVar5 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x100) + *(long *)(param_1 + 0x18e328))
    ;
    uVar3 = uVar3 & 0xff000000 | 0x400;
    if (*(long *)(param_1 + 0x18e320) != 0) goto LAB_00563a22;
    out((short)puVar5,uVar3);
  }
  else {
    uVar3 = *puVar5 & 0xff000000 | 0x400;
LAB_00563a22:
    *puVar5 = uVar3;
  }
  puVar5 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x100) + *(long *)(param_1 + 0x18e328));
  if (*(long *)(param_1 + 0x18e320) == 0) {
    uVar3 = in((short)puVar5);
    uVar3 = uVar3 | 0x1000000;
    puVar5 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x100) + *(long *)(param_1 + 0x18e328))
    ;
    if (*(long *)(param_1 + 0x18e320) != 0) goto LAB_00563a6f;
    out((short)puVar5,uVar3);
  }
  else {
    uVar3 = *puVar5 | 0x1000000;
LAB_00563a6f:
    *puVar5 = uVar3;
  }
  iVar2 = 1000;
  do {
    puVar5 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x10c) + *(long *)(param_1 + 0x18e328))
    ;
    if (*(long *)(param_1 + 0x18e320) == 0) {
      uVar3 = in((short)puVar5);
    }
    else {
      uVar3 = *puVar5;
    }
    if (uVar3 != 0) break;
    func_0x0046e1e0(1);
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  puVar5 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x100) + *(long *)(param_1 + 0x18e328));
  if (*(long *)(param_1 + 0x18e320) == 0) {
    uVar4 = in((short)puVar5);
    uVar4 = uVar4 & 0xfeffffff;
    puVar5 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x100) + *(long *)(param_1 + 0x18e328))
    ;
    if (*(long *)(param_1 + 0x18e320) != 0) goto LAB_00563b13;
    out((short)puVar5,uVar4);
  }
  else {
    uVar4 = *puVar5 & 0xfeffffff;
LAB_00563b13:
    *puVar5 = uVar4;
  }
  puVar5 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x110) + *(long *)(param_1 + 0x18e328));
  if (*(long *)(param_1 + 0x18e320) == 0) {
    uVar4 = in((short)puVar5);
    uVar4 = uVar4 & 0xfffffeff;
    puVar5 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x110) + *(long *)(param_1 + 0x18e328))
    ;
    if (*(long *)(param_1 + 0x18e320) != 0) goto LAB_00563b60;
    out((short)puVar5,uVar4);
  }
  else {
    uVar4 = *puVar5 & 0xfffffeff;
LAB_00563b60:
    *puVar5 = uVar4;
  }
  if (uVar3 == 0) {
    func_0x007f1950();
    func_0x007f18a0(0x563c56,param_2);
    func_0x00c9aa10(0x17,0x13715e8,param_2);
                    /* WARNING: Does not return */
    pcVar1 = (code *)invalidInstructionException();
    (*pcVar1)();
  }
  puVar5 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x814) + *(long *)(param_1 + 0x18e328));
  iVar2 = (int)((0xb9000 / (ulong)uVar3) / 1000);
  if (*(long *)(param_1 + 0x18e320) == 0) {
    uVar3 = in((short)puVar5);
    puVar5 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x814) + *(long *)(param_1 + 0x18e328))
    ;
    uVar3 = iVar2 << 0xc | uVar3 & 0xffff8fff;
    if (*(long *)(param_1 + 0x18e320) == 0) {
      out((short)puVar5,uVar3);
      goto LAB_00563bd7;
    }
  }
  else {
    uVar3 = iVar2 << 0xc | *puVar5 & 0xffff8fff;
  }
  *puVar5 = uVar3;
LAB_00563bd7:
  puVar5 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x814) + *(long *)(param_1 + 0x18e328));
  if (*(long *)(param_1 + 0x18e320) == 0) {
    uVar3 = in((short)puVar5);
    puVar5 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x814) + *(long *)(param_1 + 0x18e328))
    ;
    if (*(long *)(param_1 + 0x18e320) == 0) {
      out((short)puVar5,uVar3 & 0xffff7fff);
    }
    else {
      *puVar5 = uVar3 & 0xffff7fff;
    }
  }
  else {
    *puVar5 = *puVar5 & 0xffff7fff;
  }
  return;
}



/* CONTEXT / separate function: adjacent_563ca0 @ 0x563ca0; ev_1d696576ee4de56159e08e078509b7e21ab3d4c1b7786a824904bbf0822c9ad1
 * Ghidra body ranges: 0x563ca0..0x563de5
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void adjacent_563ca0(long param_1,char param_2)

{
  int iVar1;
  uint uVar2;
  uint *puVar3;
  
  iVar1 = func_0x002b3be0(*(undefined8 *)(param_1 + 0x18dc38));
  if (iVar1 != 0) {
    return;
  }
  iVar1 = func_0x002b3be0(*(undefined8 *)(param_1 + 0x18dc38));
  uVar2 = 0x120000;
  if (iVar1 == 0) {
    uVar2 = 0x128000;
    if (param_2 != '\x03') {
      uVar2 = (param_2 == '\x02' | 0x48) << 0xe;
    }
  }
  *(uint *)(param_1 + 0x18e364) = uVar2;
  puVar3 = (uint *)((ulong)uVar2 + 0x800 + *(long *)(param_1 + 0x18e328));
  if (*(long *)(param_1 + 0x18e320) == 0) {
    uVar2 = in((short)puVar3);
    uVar2 = uVar2 | 1;
    puVar3 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x800) + *(long *)(param_1 + 0x18e328))
    ;
    if (*(long *)(param_1 + 0x18e320) != 0) goto LAB_00563d41;
    out((short)puVar3,uVar2);
  }
  else {
    uVar2 = *puVar3 | 1;
LAB_00563d41:
    *puVar3 = uVar2;
  }
  puVar3 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x808) + *(long *)(param_1 + 0x18e328));
  if (*(long *)(param_1 + 0x18e320) == 0) {
    uVar2 = in((short)puVar3);
    uVar2 = uVar2 & 0xfffdffff;
    puVar3 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x808) + *(long *)(param_1 + 0x18e328))
    ;
    if (*(long *)(param_1 + 0x18e320) == 0) {
      out((short)puVar3,uVar2);
      goto LAB_00563d8c;
    }
  }
  else {
    uVar2 = *puVar3 & 0xfffdffff;
  }
  *puVar3 = uVar2;
LAB_00563d8c:
  puVar3 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x880) + *(long *)(param_1 + 0x18e328));
  if (*(long *)(param_1 + 0x18e320) == 0) {
    uVar2 = in((short)puVar3);
    uVar2 = uVar2 | 1;
    puVar3 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x880) + *(long *)(param_1 + 0x18e328))
    ;
    if (*(long *)(param_1 + 0x18e320) == 0) {
      out((short)puVar3,uVar2);
      return;
    }
  }
  else {
    uVar2 = *puVar3 | 1;
  }
  *puVar3 = uVar2;
  return;
}



/* CONTEXT / separate function: adjacent_563df0 @ 0x563df0; ev_6389ec39f29b6cf96051a02ef10f4c5c23f92732eaad936749c817a866a1133a
 * Ghidra body ranges: 0x563df0..0x563df5
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void adjacent_563df0(void)

{
  return;
}



/* CONTEXT / separate function: adjacent_563e00 @ 0x563e00; ev_ffa5916ba4fbb93771fbd0a03ac017e34404256bf53b0f5037cedc273c6250c2
 * Ghidra body ranges: 0x563e00..0x563ea2
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void adjacent_563e00(long param_1,char param_2)

{
  int iVar1;
  uint uVar2;
  uint *puVar3;
  
  iVar1 = func_0x002b3be0(*(undefined8 *)(param_1 + 0x18dc38));
  if (iVar1 == 0) {
    iVar1 = func_0x002b3be0(*(undefined8 *)(param_1 + 0x18dc38));
    uVar2 = 0x120000;
    if (iVar1 == 0) {
      uVar2 = 0x128000;
      if (param_2 != '\x03') {
        uVar2 = (param_2 == '\x02' | 0x48) << 0xe;
      }
    }
    *(uint *)(param_1 + 0x18e364) = uVar2;
    puVar3 = (uint *)((ulong)uVar2 + 0x880 + *(long *)(param_1 + 0x18e328));
    if (*(long *)(param_1 + 0x18e320) == 0) {
      uVar2 = in((short)puVar3);
      uVar2 = uVar2 & 0xfffffffe;
      puVar3 = (uint *)((ulong)(*(int *)(param_1 + 0x18e364) + 0x880) +
                       *(long *)(param_1 + 0x18e328));
      if (*(long *)(param_1 + 0x18e320) == 0) {
        out((short)puVar3,uVar2);
        return;
      }
    }
    else {
      uVar2 = *puVar3 & 0xfffffffe;
    }
    *puVar3 = uVar2;
  }
  return;
}



/* CONTEXT / separate function: adjacent_563eb0 @ 0x563eb0; ev_bde96842e567771ecf1595e4763b79b73cf072fe940d89616d19c58cd1699cc1
 * Ghidra body ranges: 0x563eb0..0x563edc
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void adjacent_563eb0(undefined8 param_1)

{
  func_0x005a4200(0x13b0af5,0,0,0,0,1,param_1);
  return;
}



/* CONTEXT / separate function: adjacent_563ee0 @ 0x563ee0; ev_2b3f28c4717652c121bb39b524828078cada910cbf49a35bb1d6b2d16d0e3715
 * Ghidra body ranges: 0x563ee0..0x563fc0
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int adjacent_563ee0(undefined8 param_1)

{
  code *pcVar1;
  int iVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  undefined2 local_a8 [2];
  int local_a4;
  long local_28;
  
  local_28 = _DAT_0391c310;
  func_0x00258ff0(local_a8,0x80);
  local_a8[0] = 0xffff;
  iVar2 = func_0x005a4610(param_1,local_a8,local_a8);
  if (iVar2 == 0) {
    if (local_a4 != 0) {
      func_0x0025d410(0x134ff00,0x12a1208,0x3c);
      goto LAB_00563f7a;
    }
    iVar2 = func_0x005a4570(param_1);
    if (iVar2 == 0) {
      local_a4 = 0;
      goto LAB_00563f7a;
    }
    uVar4 = 0x12be1ec;
    uVar3 = 0x41;
  }
  else {
    uVar4 = 0x138e44e;
    uVar3 = 0x38;
  }
  func_0x0025d410(uVar4,0x12a1208,uVar3,iVar2);
  local_a4 = iVar2;
LAB_00563f7a:
  if (_DAT_0391c310 == local_28) {
    return local_a4;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* CONTEXT / separate function: adjacent_563fd0 @ 0x563fd0; ev_e46afc25ccdfcc6f2c954f3d2fa72616bb2aca047372994b7c79ec87dfe37d7d
 * Ghidra body ranges: 0x563fd0..0x56411d
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int adjacent_563fd0(undefined8 param_1,undefined4 param_2,undefined4 param_3,undefined8 param_4)

{
  code *pcVar1;
  int iVar2;
  long lVar3;
  long lVar4;
  undefined8 local_b8;
  undefined4 local_b0;
  undefined4 local_ac;
  long local_a0;
  long local_98;
  long local_38;
  
  local_38 = _DAT_0391c310;
  func_0x00258ff0(&local_b8,0x80);
  local_b8 = 2;
  lVar3 = func_0x00c08b50(0x4000,0x1ad7a20,0x102);
  lVar4 = func_0x008de330(lVar3);
  func_0x002590b0(lVar3,param_4,0x470);
  local_98 = lVar4 + 0x470;
  local_b0 = param_2;
  local_ac = param_3;
  local_a0 = lVar4;
  iVar2 = func_0x005a4610(param_1,&local_b8);
  if (iVar2 == 0) {
    iVar2 = local_b8._4_4_;
    if (local_b8._4_4_ == 0) {
      func_0x002590b0(param_4,lVar3 + 0x470,0x470);
      iVar2 = 0;
    }
  }
  else {
    func_0x0025d410(0x126c717,0x13b0afe,0x68,iVar2);
  }
  if (lVar3 != 0) {
    func_0x00c08df0(lVar3,0x1ad7a20);
  }
  if (_DAT_0391c310 == local_38) {
    return iVar2;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* CONTEXT / separate function: adjacent_564120 @ 0x564120; ev_db36ba81c08a1e98f94c4dcde3bc6dcc9376f58e8b0cab3e6a3cbdcb9eb337a5
 * Ghidra body ranges: 0x564120..0x56426d
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int adjacent_564120(undefined8 param_1,undefined4 param_2,undefined4 param_3,undefined8 param_4,
                   undefined8 param_5)

{
  code *pcVar1;
  int iVar2;
  long lVar3;
  long lVar4;
  undefined8 local_b8;
  undefined4 local_b0;
  undefined4 local_ac;
  long local_a0;
  long local_98;
  long local_38;
  
  local_38 = _DAT_0391c310;
  func_0x00258ff0(&local_b8,0x80);
  local_b8 = 1;
  lVar3 = func_0x00c08b50(0x4000,0x1ad7a20,0x102);
  lVar4 = func_0x008de330(lVar3);
  func_0x002590b0(lVar3,param_5,0x90);
  local_98 = lVar4 + 0x90;
  local_b0 = param_2;
  local_ac = param_3;
  local_a0 = lVar4;
  iVar2 = func_0x005a4610(param_1,&local_b8);
  if (iVar2 == 0) {
    iVar2 = local_b8._4_4_;
    if (local_b8._4_4_ == 0) {
      func_0x002590b0(param_5,lVar3 + 0x90,0x90);
      iVar2 = 0;
    }
  }
  else {
    func_0x0025d410(0x126c717,0x1390628,0x93,iVar2);
  }
  if (lVar3 != 0) {
    func_0x00c08df0(lVar3,0x1ad7a20);
  }
  if (_DAT_0391c310 == local_38) {
    return iVar2;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* CONTEXT / separate function: adjacent_564270 @ 0x564270; ev_245117842c38e9253cbf1c8f533197704cbb5ae7f0aa8a62599b3a838fb1ed48
 * Ghidra body ranges: 0x564270..0x56428c
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void adjacent_564270(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* CONTEXT / separate function: adjacent_564290 @ 0x564290; ev_e97c899a8f671e3eacf2b436ecfc8b4655a4a3658aac125de7722bd5df22b4af
 * Ghidra body ranges: 0x564290..0x5642b0
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

char adjacent_564290(int param_1,int param_2,char param_3)

{
  if (param_2 != 0 || param_1 != 0) {
    return (param_3 == '\x0f' || (char)param_1 == '\0') + '\x01';
  }
  return '\0';
}



/* CONTEXT / separate function: adjacent_5642c0 @ 0x5642c0; ev_8b25eab7ba464e1e7ca4bdb39169facdad4b24f0a6d3a903cba9c8dbab795a1b
 * Ghidra body ranges: 0x5642c0..0x5642d5
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

uint adjacent_5642c0(int param_1)

{
  return (uint)((param_1 * 0xf + 0x31) * 0x147b) >> 0x13;
}



/* CONTEXT / separate function: adjacent_5642e0 @ 0x5642e0; ev_f203ac083ab882e3b3b4e4c762aa9fd036cb9bc0eb3d8745892e95c606d47810
 * Ghidra body ranges: 0x5642e0..0x5643f8
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int adjacent_5642e0(ulong param_1,code *param_2,long param_3)

{
  code *pcVar1;
  int iVar2;
  undefined8 uVar3;
  undefined4 local_38 [2];
  long local_30;
  long local_28;
  
  local_28 = _DAT_0391c310;
  if (param_3 == 0) {
    func_0x0025d410(0x1378d1c,0x13082e2,0x6e);
    uVar3 = 0x128a048;
  }
  else {
    local_38[0] = 9;
    local_30 = param_3;
    if (param_2 != (code *)0x0) {
      if (0x1b < (-(long)param_2 + 0x26c328U >> 3 | -(long)param_2 << 0x3d)) {
        param_1 = param_1 & 0xffffffff;
        func_0x0044f8c0(0x1ad7a90,param_2);
      }
      iVar2 = (*param_2)(param_1,local_38);
      if (iVar2 == 0) {
        iVar2 = 0;
      }
      else {
        func_0x0025d410(0x1378d1c,0x13082e2,0x87);
        func_0x0025d410(0x13129f0,param_1 & 0xffffffff);
      }
      goto LAB_005643bd;
    }
    func_0x0025d410(0x1378d1c,0x13082e2,0x80);
    uVar3 = 0x12f3637;
  }
  func_0x0025d410(uVar3);
  iVar2 = -0x7fc4ffff;
LAB_005643bd:
  if (_DAT_0391c310 == local_28) {
    return iVar2;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* CONTEXT / separate function: adjacent_564400 @ 0x564400; ev_efe2cd46a47a346c5819f7e29e2dbbd49dcd3f4d1a51d9f0a0f0c32459878cd2
 * Ghidra body ranges: 0x564400..0x564518
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int adjacent_564400(ulong param_1,code *param_2,long param_3)

{
  code *pcVar1;
  int iVar2;
  undefined8 uVar3;
  undefined4 local_38 [2];
  long local_30;
  long local_28;
  
  local_28 = _DAT_0391c310;
  if (param_3 == 0) {
    func_0x0025d410(0x1378d1c,0x1296d75,0x91);
    uVar3 = 0x128a048;
  }
  else {
    local_38[0] = 10;
    local_30 = param_3;
    if (param_2 != (code *)0x0) {
      if (0x1b < (-(long)param_2 + 0x26c328U >> 3 | -(long)param_2 << 0x3d)) {
        param_1 = param_1 & 0xffffffff;
        func_0x0044f8c0(0x1ad7ab0,param_2);
      }
      iVar2 = (*param_2)(param_1,local_38);
      if (iVar2 == 0) {
        iVar2 = 0;
      }
      else {
        func_0x0025d410(0x1378d1c,0x1296d75,0xa7);
        func_0x0025d410(0x13129f0,param_1 & 0xffffffff);
      }
      goto LAB_005644dd;
    }
    func_0x0025d410(0x1378d1c,0x1296d75,0xa0);
    uVar3 = 0x12f3637;
  }
  func_0x0025d410(uVar3);
  iVar2 = -0x7fc4ffff;
LAB_005644dd:
  if (_DAT_0391c310 == local_28) {
    return iVar2;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* CONTEXT / separate function: adjacent_564520 @ 0x564520; ev_cc02e8cc696a939adbd20a41279cd067a6002b8af7ff82eec12773045e65bc85
 * Ghidra body ranges: 0x564520..0x5646da
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int adjacent_564520(undefined4 param_1,undefined4 param_2,undefined8 param_3,long param_4,
                   long param_5,undefined8 param_6)

{
  code *pcVar1;
  int iVar2;
  int iVar3;
  undefined1 local_571;
  undefined4 local_570;
  undefined4 local_56c;
  undefined4 local_568 [8];
  undefined8 local_548;
  undefined8 local_540;
  undefined1 local_538 [5];
  undefined1 local_533 [507];
  ulong local_338;
  long local_38;
  
  local_38 = _DAT_0391c310;
  if (param_4 == 0 || param_5 == 0) {
    func_0x0025d410(0x1378d1c,0x12aac7b,0xb5);
    func_0x0025d410(0x128a048);
    iVar3 = -0x7fc4ffff;
  }
  else {
    func_0x0049af30(local_568,0,0x530);
    local_56c = 0;
    if (param_5 + 5U < 0x201) {
      local_571 = 0x20;
      local_570 = 0x52000060;
      func_0x002590b0(local_538,&local_571,5);
      func_0x002590b0(local_533,param_4,param_5);
      local_540 = 2;
      local_568[0] = param_1;
      local_548 = param_6;
      local_338 = param_5 + 5U;
      iVar2 = adjacent_564400(param_2,param_3,local_568);
      iVar3 = 0;
      if (iVar2 != 0) {
        func_0x0025d410(0x1378d1c,0x12aac7b,0xde);
        func_0x0025d410(0x1344791);
        iVar3 = iVar2;
      }
    }
    else {
      func_0x0025d410(0x1378d1c,0x12aac7b,0xbf);
      func_0x0025d410(0x1296d8e);
      iVar3 = -0x7fc4fff6;
    }
  }
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar1 = (code *)invalidInstructionException();
    (*pcVar1)();
  }
  return iVar3;
}



/* CONTEXT / separate function: adjacent_5646e0 @ 0x5646e0; ev_948a755d617bdec496f7f388d2c7d78ecc0d6a14b500ab1de10de2db23b126b8
 * Ghidra body ranges: 0x5646e0..0x564742, 0x564781..0x5647b2, 0x5648e0..0x5648ff, 0x564979..0x5649b5
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 adjacent_5646e0(void)

{
  code *pcVar1;
  undefined8 uVar2;
  uint *in_RCX;
  undefined1 local_198 [352];
  long local_38;
  
  local_38 = _DAT_0391c310;
  if (in_RCX == (uint *)0x0) {
    func_0x0025d410(0x1378d1c,0x137b610,0xea);
    func_0x0025d410(0x128a048);
  }
  else {
    func_0x00258ff0(local_198,0x160);
    if ((ulong)*in_RCX < 0x2f) {
                    /* WARNING: Could not emulate address calculation at 0x0056473a */
                    /* WARNING: Treating indirect jump as call */
      uVar2 = (*(code *)((long)*(int *)((ulong)*in_RCX * 4 + 0x159ba7c) + 0x159ba7c))();
      return uVar2;
    }
    func_0x0025d410(0x1378d1c,0x137b610,0x15b);
    func_0x0025d410(0x1364e59,*in_RCX);
  }
  if (_DAT_0391c310 == local_38) {
    return 0x803b0001;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* CONTEXT / separate function: adjacent_5649c0 @ 0x5649c0; ev_c6d65258e9f0aa68779c3ef3ecef7eb6530256b69d4cfbee9948b26fde4ee0d0
 * Ghidra body ranges: 0x5649c0..0x564a08, 0x564a76..0x564ade, 0x564be4..0x564c03, 0x564c81..0x564c87
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 adjacent_5649c0(void)

{
  code *pcVar1;
  long lVar2;
  undefined8 uVar3;
  uint *in_RCX;
  
  lVar2 = _DAT_0391c310;
  if (in_RCX == (uint *)0x0) {
    func_0x0025d410(0x1378d1c,0x12c9f86,0x169);
    func_0x0025d410(0x128a048);
    uVar3 = 0x803b0001;
  }
  else {
    if ((ulong)*in_RCX < 0x30) {
                    /* WARNING: Could not emulate address calculation at 0x005649ff */
                    /* WARNING: Treating indirect jump as call */
      uVar3 = (*(code *)((long)*(int *)((ulong)*in_RCX * 4 + 0x159bb38) + 0x159bb38))();
      return uVar3;
    }
    func_0x0025d410(0x1378d1c,0x12c9f86,0x1c5);
    func_0x0025d410(0x1332380,*in_RCX);
    uVar3 = 0x803b0004;
  }
  if (_DAT_0391c310 == lVar2) {
    return uVar3;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* CONTEXT / separate function: adjacent_564c90 @ 0x564c90; ev_5ecfb091cf67a61cc8ad23805b5f6618f9a46e5ecaf6144dbd7969fb59c1b580
 * Ghidra body ranges: 0x564c90..0x564dc8
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int adjacent_564c90(uint param_1,undefined4 param_2,code *param_3,long param_4)

{
  code *pcVar1;
  int iVar2;
  undefined8 uVar3;
  ulong local_40;
  long local_38;
  long local_30;
  
  local_30 = _DAT_0391c310;
  if (param_4 == 0) {
    func_0x0025d410(0x1378d1c,0x1328109,0x1d3);
    uVar3 = 0x1281fb0;
  }
  else {
    local_40 = (ulong)param_1;
    local_38 = param_4;
    if (param_3 != (code *)0x0) {
      if (0x1b < (-(long)param_3 + 0x26c328U >> 3 | -(long)param_3 << 0x3d)) {
        func_0x0044f8c0(0x1ad7ad0,param_3);
      }
      iVar2 = (*param_3)(param_2,&local_40);
      if (iVar2 == 0) {
        iVar2 = 0;
      }
      else {
        func_0x0025d410(0x1378d1c,0x1328109,0x1e6);
        func_0x0025d410(0x1278384,param_2,param_1,iVar2);
      }
      goto LAB_00564d87;
    }
    func_0x0025d410(0x1378d1c,0x1328109,0x1dd);
    uVar3 = 0x12f3637;
  }
  func_0x0025d410(uVar3);
  iVar2 = -0x7fc4ffff;
LAB_00564d87:
  if (_DAT_0391c310 == local_30) {
    return iVar2;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* CONTEXT / separate function: adjacent_564dd0 @ 0x564dd0; ev_112b73a9bf38e70408cc03acaf07c889ea0b314bc86fc54e074a1da5c2863e4b
 * Ghidra body ranges: 0x564dd0..0x564f31
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Removing unreachable block (ram,0x00564e9a) */
/* WARNING: Removing unreachable block (ram,0x00564f1e) */
/* WARNING: Removing unreachable block (ram,0x00564eae) */
/* WARNING: Removing unreachable block (ram,0x00564f10) */
/* WARNING: Removing unreachable block (ram,0x00564ebb) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int adjacent_564dd0(undefined4 param_1,undefined8 param_2,undefined8 param_3,long param_4)

{
  code *pcVar1;
  long lVar2;
  int iVar3;
  undefined8 uVar4;
  
  lVar2 = _DAT_0391c310;
  if (param_4 == 0) {
    func_0x0025d410(0x1378d1c,0x12df168,0x1f5);
    uVar4 = 0x1281fb0;
  }
  else {
    iVar3 = adjacent_564c90();
    if (iVar3 != 0) {
      func_0x0025d410(0x1378d1c,0x12df168,0x1fd);
      func_0x0025d410(0x137b630,param_1);
      goto LAB_00564e79;
    }
    func_0x0025d410(0x1378d1c,0x12df168,0x204);
    uVar4 = 0x12bf337;
  }
  func_0x0025d410(uVar4);
  iVar3 = -0x7fc4ffff;
LAB_00564e79:
  if (_DAT_0391c310 != lVar2) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar1 = (code *)invalidInstructionException();
    (*pcVar1)();
  }
  return iVar3;
}



/* CONTEXT / separate function: adjacent_564f40 @ 0x564f40; ev_1e72af05421b63e96bf3c162df719bb6ff44c795625b940029967dafc2a4c027
 * Ghidra body ranges: 0x564f40..0x56500f
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Possible PIC construction at 0x00564f6c: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x00564f71) */

void adjacent_564f40(int *param_1,int *param_2)

{
  undefined8 uVar1;
  
  if (param_1 == (int *)0x0 || param_2 == (int *)0x0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  *param_1 = param_2[0xd];
  func_0x002590b0(param_1 + 1,param_2 + 1,0x10);
  func_0x002590b0(param_1 + 5,param_2 + 5,0x10);
  param_1[0x13] = param_1[0x13] | (uint)(*param_2 == 0) * 0x400 + 0x400;
  uVar1 = func_0x003472d0();
  *(undefined8 *)(param_1 + 10) = uVar1;
  if (*param_1 - 3U < 3) {
    if ((short)param_2[0x27] != 0) {
      *(short *)(param_1 + 0x11) = (short)param_2[0x27];
      *(byte *)((long)param_1 + 0x49) = *(byte *)((long)param_1 + 0x49) | 1;
      *(byte *)(param_1 + 0x12) = *(byte *)(param_1 + 0x12) | 1;
    }
    if (*(short *)((long)param_2 + 0x9e) != 0) {
      *(short *)((long)param_1 + 0x46) = *(short *)((long)param_2 + 0x9e);
      *(byte *)((long)param_1 + 0x49) = *(byte *)((long)param_1 + 0x49) | 2;
      *(byte *)(param_1 + 0x12) = *(byte *)(param_1 + 0x12) | 2;
    }
  }
  return;
}



/* CONTEXT / separate function: adjacent_565010 @ 0x565010; ev_aa27ed5dc66b62cd9a053cd414c191559898dc4b9c8e3a27d0d090e6342aa272
 * Ghidra body ranges: 0x565010..0x56512c
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int adjacent_565010(undefined4 param_1,code *param_2,long param_3)

{
  code *pcVar1;
  int iVar2;
  undefined4 local_40 [2];
  long local_38;
  long local_30;
  
  local_30 = _DAT_0391c310;
  if (param_3 == 0) {
    func_0x0025d410(0x1378d1c,0x13521d6,0x321);
    func_0x0025d410(0x1371616);
  }
  local_40[0] = 0xb;
  local_38 = param_3;
  if (param_2 == (code *)0x0) {
    func_0x0025d410(0x1378d1c,0x13521d6,0x32e);
    func_0x0025d410(0x12f3637);
    iVar2 = -0x7fc4ffff;
  }
  else {
    if (0x1b < (-(long)param_2 + 0x26c328U >> 3 | -(long)param_2 << 0x3d)) {
      func_0x0044f8c0(0x1ad7b10,param_2);
    }
    iVar2 = (*param_2)(param_1,local_40);
    if (iVar2 == 0) {
      iVar2 = 0;
    }
    else {
      func_0x0025d410(0x1378d1c,0x13521d6,0x335);
      func_0x0025d410(0x13129f0,param_1);
    }
  }
  if (_DAT_0391c310 == local_30) {
    return iVar2;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* CONTEXT / separate function: adjacent_565130 @ 0x565130; ev_aca0b27d7b4264cadfdd6f4132838c26305904bb6972016dbe46eed65ff6c803
 * Ghidra body ranges: 0x565130..0x56524c
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int adjacent_565130(undefined4 param_1,code *param_2,long param_3)

{
  code *pcVar1;
  int iVar2;
  undefined4 local_40 [2];
  long local_38;
  long local_30;
  
  local_30 = _DAT_0391c310;
  if (param_3 == 0) {
    func_0x0025d410(0x1378d1c,0x12bf359,0x340);
    func_0x0025d410(0x1371616);
  }
  local_40[0] = 0xc;
  local_38 = param_3;
  if (param_2 == (code *)0x0) {
    func_0x0025d410(0x1378d1c,0x12bf359,0x34d);
    func_0x0025d410(0x12f3637);
    iVar2 = -0x7fc4ffff;
  }
  else {
    if (0x1b < (-(long)param_2 + 0x26c328U >> 3 | -(long)param_2 << 0x3d)) {
      func_0x0044f8c0(0x1ad7b30,param_2);
    }
    iVar2 = (*param_2)(param_1,local_40);
    if (iVar2 == 0) {
      iVar2 = 0;
    }
    else {
      func_0x0025d410(0x1378d1c,0x12bf359,0x354);
      func_0x0025d410(0x13129f0,param_1);
    }
  }
  if (_DAT_0391c310 == local_30) {
    return iVar2;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* CONTEXT / separate function: FUN_00565250 @ 0x565250; ev_9b15040bec8efd4c9a7c7f61fcebb169e62f607c0a570ef1354749f703473690
 * Ghidra body ranges: 0x565250..0x56525f, 0x565293..0x56538f
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

byte FUN_00565250(int *param_1,long param_2)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  byte bVar4;
  byte bVar5;
  
  if (param_1 == (int *)0x0 || param_2 == 0) {
    func_0x0025d410(0x1378d1c,0x128c202,0x35f);
    func_0x0025d410(0x12b5653);
    return 0xc;
  }
  uVar1 = *(uint *)(param_2 + 0x4c);
  uVar2 = param_1[0x13];
  uVar3 = uVar1 ^ uVar2;
  bVar5 = uVar3 != 0;
  if ((((uVar3 & 0x3000) != 0) || (*(char *)(param_2 + 0x34) != (char)param_1[0xd])) ||
     (*(char *)(param_2 + 0x33) != *(char *)((long)param_1 + 0x33))) {
    bVar5 = bVar5 | 4;
  }
  bVar4 = bVar5 + 8;
  if (((uint)((uVar1 & 0x200) == 0) & uVar2 >> 9) == 0) {
    bVar4 = bVar5;
  }
  bVar5 = bVar4 + 0x10;
  if (((uint)((uVar1 & 0x40) == 0) & uVar2 >> 6) == 0) {
    bVar5 = bVar4;
  }
  bVar4 = bVar5 + 0x20;
  if (((uint)(-1 < (char)uVar1) & uVar2 >> 7) == 0) {
    bVar4 = bVar5;
  }
  bVar5 = bVar4 | 0x40;
  if (((uint)((uVar1 & 0x100) == 0) & uVar2 >> 8) == 0) {
    bVar5 = bVar4;
  }
  bVar4 = bVar5 | 0x80;
  if (*(char *)(param_2 + 0x31) != *(char *)((long)param_1 + 0x31)) {
    bVar5 = bVar4;
  }
  if ((uVar3 & 0xc) != 0) {
    bVar5 = bVar4;
  }
  if (*param_1 - 3U < 2) {
    if (((*(char *)(param_2 + 0x40) != (char)param_1[0x10]) ||
        (*(char *)(param_2 + 0x41) != *(char *)((long)param_1 + 0x41))) ||
       (*(char *)(param_2 + 0x42) != *(char *)((long)param_1 + 0x42))) {
      bVar5 = bVar4;
    }
    if ((*(char *)(param_2 + 0x48) != (char)param_1[0x12]) ||
       (*(char *)(param_2 + 0x4a) != *(char *)((long)param_1 + 0x4a))) {
      bVar5 = bVar5 | 1;
    }
  }
  return bVar5;
}



/* CONTEXT / separate function: adjacent_565260 @ 0x565260; ev_a6b41a270d5bd8eed34e4400707690c32ea937af08d33d9389808207345c308c
 * Ghidra body ranges: 0x565260..0x565292
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_565260(void)

{
  func_0x0025d410(0x1378d1c,0x128c202,0x35f);
  func_0x0025d410(0x12b5653);
  return 0xc;
}



/* CONTEXT / separate function: adjacent_565390 @ 0x565390; ev_648c0dffc6427dd001a10f53cbaf3dae26d90db1b34474045471f0df915c3bed
 * Ghidra body ranges: 0x565390..0x5657cf
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 adjacent_565390(int *param_1,long param_2,long param_3)

{
  code *pcVar1;
  char cVar2;
  undefined2 uVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  undefined8 uVar7;
  uint uVar8;
  int iVar9;
  undefined1 local_80 [80];
  long local_30;
  
  local_30 = _DAT_0391c310;
  if ((param_2 == 0 || param_1 == (int *)0x0) || param_3 == 0) {
    func_0x0025d410(0x1378d1c,0x1281fc2,0x3bc);
    func_0x0025d410(0x12ddb93);
    uVar7 = 0xc;
  }
  else {
    func_0x002590b0(local_80,param_1,0x50);
    adjacent_564f40(param_1,param_2);
    if ((*(byte *)(param_3 + 0x27) & 6) == 0) {
      cVar2 = '\0';
    }
    else {
      cVar2 = ((~*(ushort *)(param_3 + 0x2b) & 0xf) == 0 || (*(byte *)(param_3 + 0x27) & 4) == 0) +
              '\x01';
    }
    *(char *)(param_1 + 0xc) = cVar2;
    *(byte *)((long)param_1 + 0x31) = *(byte *)(param_3 + 0x2b) & 0xf;
    *(byte *)(param_1 + 0xd) = *(byte *)(param_3 + 0x2b) >> 4;
    *(byte *)((long)param_1 + 0x33) = *(byte *)(param_3 + 0x2c) & 0xf;
    uVar6 = param_1[0x13];
    uVar4 = *(uint *)(param_3 + 0x27) & 1;
    param_1[0x13] = uVar6 & 0xfffffffe | uVar4;
    uVar6 = (uVar6 & 0xfffffffa | uVar4) + (*(uint *)(param_3 + 0x27) & 2) * 2;
    param_1[0x13] = uVar6;
    uVar6 = (uVar6 & 0xffffff37) + (*(uint *)(param_3 + 0x27) & 4) * 2;
    param_1[0x13] = uVar6;
    if ((*(byte *)(param_2 + 0x58) & 0x80) != 0) {
      iVar5 = uVar6 + (*(uint *)(param_3 + 0x27) & 8) * 8;
      param_1[0x13] = iVar5;
      uVar6 = iVar5 + (*(uint *)(param_3 + 0x27) & 0x10) * 8;
    }
    uVar6 = uVar6 & 0xfffffeff;
    param_1[0x13] = uVar6;
    if ((*(byte *)(param_2 + 0x58) & 0x40) != 0) {
      uVar6 = uVar6 + (*(uint *)(param_3 + 0x27) & 0x20) * 8;
      param_1[0x13] = uVar6;
    }
    uVar4 = (*(uint *)(param_3 + 0x27) & 0x40) << 6;
    param_1[0x13] = uVar6 & 0xffffefff | uVar4;
    uVar8 = (*(uint *)(param_3 + 0x27) & 0x80) << 6;
    param_1[0x13] = uVar6 & 0xffffcfff | uVar4 | uVar8;
    uVar4 = (uVar6 & 0xffffcdff | uVar4 | uVar8) + (*(uint *)(param_3 + 0x27) & 0x100) * 2;
    param_1[0x13] = uVar4;
    uVar4 = (uVar4 & 0xfffffffd) + (*(uint *)(param_3 + 0x27) >> 9 & 1) * 2;
    uVar8 = 0;
    param_1[0x13] = uVar4;
    uVar6 = uVar6 >> 3 & 0x20;
    if ((*(byte *)(param_2 + 0x5a) & 1) == 0) {
      uVar6 = uVar8;
    }
    param_1[0x13] = uVar4 & 0xffffffdf | uVar6;
    iVar5 = *param_1;
    if (iVar5 - 3U < 2) {
      if (((*(byte *)(param_3 + 0x27) >> 1 | *(byte *)(param_3 + 0x3d)) & 1) != 0) {
        uVar8 = ((uint)((~*(ushort *)(param_3 + 0x37) & 0xf) == 0) |
                LZCOUNT((uint)(*(byte *)(param_3 + 0x3d) & 1)) - 0x18U >> 3) + 1;
      }
      param_1[0xe] = uVar8;
      iVar9 = 0;
      if (((*(byte *)(param_3 + 0x27) | *(byte *)(param_3 + 0x3d)) & 2) != 0) {
        iVar9 = ((uint)((~*(ushort *)(param_3 + 0x37) & 0xf0) == 0) |
                LZCOUNT((uint)(*(byte *)(param_3 + 0x3d) & 2)) - 0x18U >> 3) + 1;
      }
      param_1[0xf] = iVar9;
      if (iVar5 == 3) {
        param_1[0xe] = 0;
        param_1[0xf] = 0;
      }
      *(byte *)(param_1 + 0x10) = *(byte *)(param_3 + 0x37) & 0xf;
      *(byte *)((long)param_1 + 0x41) = *(byte *)(param_3 + 0x37) >> 4;
      *(byte *)((long)param_1 + 0x42) = *(byte *)(param_3 + 0x38) & 0xf;
      uVar3 = func_0x0032ddf0(param_3 + 0x39,2);
      *(undefined2 *)(param_1 + 0x11) = uVar3;
      uVar3 = func_0x0032ddf0(param_3 + 0x3b,2);
      *(undefined2 *)((long)param_1 + 0x46) = uVar3;
      *(byte *)(param_1 + 0x12) = (byte)((ushort)*(undefined2 *)(param_3 + 0x37) >> 0xc) & 3;
      *(byte *)((long)param_1 + 0x49) = (byte)((ushort)*(undefined2 *)(param_3 + 0x37) >> 0xe);
      *(byte *)((long)param_1 + 0x4a) = *(byte *)(param_3 + 0x3d) & 3;
      if ((((*(byte *)(param_2 + 0x5a) & 2) != 0) ||
          (uVar6 = 0, (*(byte *)(param_3 + 0x38) & 0x10) == 0)) &&
         (uVar6 = 0x10, (*(byte *)(param_2 + 0x5a) & 4) == 0)) {
        uVar6 = (uint)((*(byte *)(param_3 + 0x38) & 0x20) == 0) << 4;
      }
      param_1[0x13] = param_1[0x13] & 0xffffffefU | uVar6;
    }
    else if (iVar5 == 5) {
      iVar9 = 0;
      iVar5 = 0;
      if (((*(byte *)(param_3 + 0x27) >> 1 | *(byte *)(param_3 + 0x3d)) & 1) != 0) {
        iVar9 = ((uint)((~*(ushort *)(param_3 + 0x37) & 0xf) == 0) |
                LZCOUNT((uint)(*(byte *)(param_3 + 0x3d) & 1)) - 0x18U >> 3) + 1;
      }
      param_1[0xe] = iVar9;
      if (((*(byte *)(param_3 + 0x27) | *(byte *)(param_3 + 0x3d)) & 2) != 0) {
        iVar5 = ((uint)((~*(ushort *)(param_3 + 0x37) & 0xf0) == 0) |
                LZCOUNT((uint)(*(byte *)(param_3 + 0x3d) & 2)) - 0x18U >> 3) + 1;
      }
      param_1[0xf] = iVar5;
      *(byte *)(param_1 + 0x10) = *(byte *)(param_3 + 0x37) & 0xf;
      *(byte *)((long)param_1 + 0x41) = *(byte *)(param_3 + 0x37) >> 4;
      *(byte *)((long)param_1 + 0x42) = *(byte *)(param_3 + 0x38) & 0xf;
      uVar3 = func_0x0032ddf0(param_3 + 0x39,2);
      *(undefined2 *)(param_1 + 0x11) = uVar3;
      uVar3 = func_0x0032ddf0(param_3 + 0x3b,2);
      *(undefined2 *)((long)param_1 + 0x46) = uVar3;
      *(byte *)(param_1 + 0x12) =
           (byte)((ushort)*(undefined2 *)(param_3 + 0x37) >> 0xc) & 3 |
           *(byte *)(param_3 + 0x3d) & 4;
      *(byte *)((long)param_1 + 0x4a) = *(byte *)(param_3 + 0x3d) & 3;
      *(byte *)((long)param_1 + 0x4b) = *(byte *)(param_3 + 0x3d) >> 3 & 1;
    }
    else if (iVar5 == 2) {
      param_1[0x13] = (uVar4 & 0xffffffcf | uVar6) + (*(byte *)(param_2 + 0x5a) & 2) * 8;
    }
    uVar7 = func_0x003472d0();
    *(undefined8 *)(param_1 + 10) = uVar7;
    uVar7 = FUN_00565250(param_1,local_80);
  }
  if (_DAT_0391c310 == local_30) {
    return uVar7;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* CONTEXT / separate function: adjacent_5657d0 @ 0x5657d0; ev_0892e60ffa5ed7962b4ecdeeac5f81a0443be4227473d40466c54b86eade40b6
 * Ghidra body ranges: 0x5657d0..0x565ad5
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_5657d0(undefined1 *param_1,ushort *param_2,uint param_3,long param_4)

{
  ushort uVar1;
  byte bVar2;
  ushort uVar3;
  undefined8 uVar4;
  ushort uVar5;
  ushort uVar6;
  ushort uVar7;
  ushort uVar8;
  ushort uVar9;
  ushort uVar10;
  ushort uVar11;
  ushort uVar12;
  ushort uVar13;
  ushort uVar14;
  ushort uVar15;
  
  if ((param_2 == (ushort *)0x0 || param_1 == (undefined1 *)0x0) || param_4 == 0) {
    func_0x0025d410(0x1378d1c,0x12e90b0,0x3d5);
    func_0x0025d410(0x12ddb93);
    uVar4 = 0x803b0001;
  }
  else {
    func_0x00258ff0(param_1,0x40);
    *param_1 = 1;
    param_1[1] = (char)param_2[1];
    param_1[2] = *(undefined1 *)((long)param_2 + 3);
    param_1[3] = (char)param_2[2];
    param_1[4] = *(undefined1 *)((long)param_2 + 5);
    param_1[5] = (char)param_2[3];
    param_1[6] = *(undefined1 *)((long)param_2 + 7);
    param_1[7] = 0;
    uVar1 = *(ushort *)(param_1 + 8);
    uVar5 = param_2[4] & 0xf;
    *(ushort *)(param_1 + 8) = uVar1 & 0xfff0 | uVar5;
    uVar6 = param_2[4] & 0x10;
    *(ushort *)(param_1 + 8) = uVar1 & 0xffe0 | uVar5 | uVar6;
    uVar7 = param_2[4] & 0x20;
    *(ushort *)(param_1 + 8) = uVar1 & 0xffc0 | uVar5 | uVar6 | uVar7;
    uVar8 = param_2[4] & 0x40;
    *(ushort *)(param_1 + 8) = uVar1 & 0xff80 | uVar5 | uVar6 | uVar7 | uVar8;
    uVar9 = param_2[4] & 0x80;
    *(ushort *)(param_1 + 8) = uVar1 & 0xff00 | uVar5 | uVar6 | uVar7 | uVar8 | uVar9;
    uVar10 = param_2[4] & 0x100;
    *(ushort *)(param_1 + 8) = uVar1 & 0xfe00 | uVar5 | uVar6 | uVar7 | uVar8 | uVar9 | uVar10;
    uVar11 = param_2[4] & 0x200;
    *(ushort *)(param_1 + 8) =
         uVar1 & 0xfc00 | uVar5 | uVar6 | uVar7 | uVar8 | uVar9 | uVar10 | uVar11;
    uVar12 = param_2[4] & 0x400;
    *(ushort *)(param_1 + 8) =
         uVar1 & 0xf800 | uVar5 | uVar6 | uVar7 | uVar8 | uVar9 | uVar10 | uVar11 | uVar12;
    uVar13 = param_2[4] & 0x800;
    *(ushort *)(param_1 + 8) =
         uVar1 & 0xf000 | uVar5 | uVar6 | uVar7 | uVar8 | uVar9 | uVar10 | uVar11 | uVar12 | uVar13;
    uVar14 = param_2[4] & 0x1000;
    *(ushort *)(param_1 + 8) =
         uVar1 & 0xe000 | uVar5 | uVar6 | uVar7 | uVar8 | uVar9 | uVar10 | uVar11 | uVar12 | uVar13
         | uVar14;
    uVar15 = param_2[4] & 0x2000;
    *(ushort *)(param_1 + 8) =
         uVar1 & 0xc000 | uVar5 | uVar6 | uVar7 | uVar8 | uVar9 | uVar10 | uVar11 | uVar12 | uVar13
         | uVar14 | uVar15;
    uVar3 = param_2[4];
    *(ushort *)(param_1 + 8) =
         uVar1 & 0x8000 | uVar5 | uVar6 | uVar7 | uVar8 | uVar9 | uVar10 | uVar11 | uVar12 | uVar13
         | uVar14 | uVar15 | uVar3 & 0x4000;
    *(ushort *)(param_1 + 8) =
         uVar5 | uVar6 | uVar7 | uVar8 | uVar9 | uVar10 | uVar11 | uVar12 | uVar13 | uVar14 | uVar15
         | uVar3 & 0x4000 | param_2[4] & 0x8000;
    bVar2 = (byte)param_2[5] & 1;
    param_1[10] = param_1[10] & 0xfe | bVar2;
    param_1[10] = (byte)param_2[5] & 2 | bVar2;
    param_1[0xb] = 0;
    *(uint *)(param_1 + 0xc) = (param_3 & 0x7fff) << 0x10 | (uint)*param_2;
    param_1[0x10] = *(undefined1 *)((long)param_2 + 0xb);
    param_1[0x12] = *(undefined1 *)((long)param_2 + 0xd);
    param_1[0x14] = *(undefined1 *)((long)param_2 + 0xf);
    param_1[0x16] = *(undefined1 *)((long)param_2 + 0x11);
    param_1[0x18] = *(undefined1 *)((long)param_2 + 0x13);
    param_1[0x1a] = *(undefined1 *)((long)param_2 + 0x15);
    param_1[0x1c] = *(undefined1 *)((long)param_2 + 0x17);
    param_1[0x11] = (char)param_2[6];
    param_1[0x13] = (char)param_2[7];
    param_1[0x15] = (char)param_2[8];
    param_1[0x17] = (char)param_2[9];
    param_1[0x19] = (char)param_2[10];
    param_1[0x1b] = (char)param_2[0xb];
    param_1[0x1d] = (char)param_2[0xc];
    uVar1 = *(ushort *)(param_1 + 0x1e);
    uVar3 = *(byte *)(param_4 + 0x32) / 10 | uVar1 & 0xffe0;
    *(ushort *)(param_1 + 0x1e) = uVar3;
    if ((*(char *)(param_4 + 0x32) == 'd') && ((*(byte *)(param_4 + 0x4c) & 4) != 0)) {
      uVar3 = uVar1 & 0xffe0 | 0xb;
      *(ushort *)(param_1 + 0x1e) = uVar3;
    }
    uVar1 = (ushort)((*(uint *)(param_4 + 0x4c) & 4) << 2);
    *(ushort *)(param_1 + 0x1e) = uVar3 & 0xff1f | uVar1;
    *(ushort *)(param_1 + 0x1e) = uVar3 & 0x1f | uVar1 | *(ushort *)(param_4 + 0x4c) >> 3 & 0x100;
    param_1[0x20] = *(undefined1 *)((long)param_2 + 0x19);
    param_1[0x21] = (char)param_2[0xd];
    param_1[0x22] = *(undefined1 *)((long)param_2 + 0x1b);
    param_1[0x23] = (char)param_2[0xe];
    param_1[0x24] = *(undefined1 *)((long)param_2 + 0x1d);
    param_1[0x25] = (char)param_2[0xf];
    param_1[0x26] = *(undefined1 *)((long)param_2 + 0x1f);
    param_1[0x27] = (char)param_2[0x10];
    uVar4 = 0;
  }
  return uVar4;
}



/* CONTEXT / separate function: adjacent_565ae0 @ 0x565ae0; ev_052e047b834e6f657738dad473a3fd8bad39234b2e76b406f3966ab83fa10566
 * Ghidra body ranges: 0x565ae0..0x565b96
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_565ae0(undefined2 *param_1,long param_2,undefined2 param_3)

{
  undefined8 uVar1;
  
  if (param_1 == (undefined2 *)0x0 || param_2 == 0) {
    func_0x0025d410(0x1378d1c,0x12f3659,0x434);
    func_0x0025d410(0x12ddb93);
    uVar1 = 0x803b0001;
  }
  else {
    func_0x00258ff0(param_1,0x26);
    *param_1 = param_3;
    func_0x002590b0(param_1 + 1,param_2 + 1,2);
    *(undefined1 *)(param_1 + 2) = *(undefined1 *)(param_2 + 3);
    *(undefined1 *)((long)param_1 + 5) = *(undefined1 *)(param_2 + 4);
    *(undefined1 *)(param_1 + 3) = *(undefined1 *)(param_2 + 6);
    *(undefined1 *)((long)param_1 + 0x1d) = *(undefined1 *)(param_2 + 0x2c);
    *(undefined1 *)(param_1 + 0xf) = *(undefined1 *)(param_2 + 0x2d);
    *(undefined1 *)((long)param_1 + 0x1f) = *(undefined1 *)(param_2 + 0x2e);
    *(undefined1 *)(param_1 + 0x10) = *(undefined1 *)(param_2 + 0x2f);
    uVar1 = 0;
  }
  return uVar1;
}



/* CONTEXT / separate function: adjacent_565ba0 @ 0x565ba0; ev_e535962ff7e3724ea95620a497f13052d671092cf487c8be95ac105a60708a51
 * Ghidra body ranges: 0x565ba0..0x565c1f
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_565ba0(undefined2 *param_1,long param_2)

{
  undefined8 uVar1;
  
  if (param_1 == (undefined2 *)0x0 || param_2 == 0) {
    func_0x0025d410(0x1378d1c,0x12df18d,0x465);
    func_0x0025d410(0x12ddb93);
    uVar1 = 0x803b0001;
  }
  else {
    func_0x00258ff0(param_1,0x30);
    *param_1 = 0x2103;
    *(undefined1 *)(param_1 + 1) = 0x28;
    func_0x002590b0((long)param_1 + 3,param_2 + 5,0x20);
    uVar1 = 0;
  }
  return uVar1;
}



/* CONTEXT / separate function: adjacent_565c20 @ 0x565c20; ev_d6d040777eaa2b89748d6d140e8b8f85927c280effe7741f474c6ce159d866a5
 * Ghidra body ranges: 0x565c20..0x565c25
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void adjacent_565c20(void)

{
  return;
}



/* CONTEXT / separate function: adjacent_565c30 @ 0x565c30; ev_41a8279a5fb3c84b0f6506e8cb525ccda4a0d51bd498d31d8aaf887a1ad24a77
 * Ghidra body ranges: 0x565c30..0x5660df
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int adjacent_565c30(byte *param_1,long param_2,undefined1 param_3,undefined1 param_4,uint *param_5)

{
  ulong uVar1;
  byte bVar2;
  sbyte sVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  undefined8 uVar8;
  undefined8 uVar9;
  uint uVar10;
  uint uVar11;
  long local_48;
  uint local_3c;
  long local_38;
  
  local_38 = _DAT_0391c310;
  if (((param_2 == 0) || (param_1 == (byte *)0x0)) || (param_5 == (uint *)0x0)) {
    func_0x0025d410(0x1378d1c,0x12e90dc,0x4a4);
    func_0x0025d410(0x1281fb0);
    iVar4 = -0x7fc4ffff;
  }
  else {
    uVar1 = param_2 * 8;
    if (uVar1 == 0) {
      func_0x0025d410(0x1378d1c,0x13a5a87,0x5b7);
      func_0x0025d410(0x13b0b18);
      iVar4 = -0x7fc4fff6;
      uVar9 = 0x12bf388;
      uVar8 = 0x4bd;
    }
    else {
      bVar2 = *param_1;
      if (bVar2 - 4 < 0xfffffffd) {
        func_0x0025d410(0x1398a66,0x12e90dc,0x4c3);
        func_0x0025d410(0x128c224,bVar2);
      }
      if (uVar1 < 0xb) {
        func_0x0025d410(0x1378d1c,0x13a5a87,0x5b7);
        func_0x0025d410(0x13b0b18);
        iVar4 = -0x7fc4fff6;
        uVar9 = 0x1352203;
        uVar8 = 0x4cf;
      }
      else {
        *param_5 = (uint)(param_1[1] >> 5);
        local_48 = 0xb;
        iVar4 = func_0x00566380(param_1,param_2,param_5 + 1,&local_48,1);
        uVar9 = 0x12aac99;
        if (iVar4 == 0) {
          if (local_48 + 5U <= uVar1) {
            uVar7 = 5;
            uVar5 = 0;
            do {
              uVar11 = (uint)local_48;
              uVar7 = uVar7 & 0xff;
              uVar10 = 8 - (uVar11 & 7);
              uVar6 = uVar7;
              if (uVar10 < uVar7) {
                uVar6 = uVar10;
              }
              uVar7 = uVar7 - uVar6;
              local_48 = local_48 + (ulong)uVar6;
              sVar3 = ((byte)uVar6 < 0x21) * (' ' - (byte)uVar6);
              uVar5 = uVar5 | (((uint)(param_1[uVar11 >> 3 & 0xff] >> (uVar10 - uVar6 & 0x1f)) <<
                               sVar3) >> sVar3) << (uVar7 & 0x1f);
            } while ((char)uVar7 != '\0');
            *(char *)(param_5 + 2) = (char)uVar5;
            if ((char)uVar5 == '\0') {
                    /* WARNING: Bad instruction - Truncating control flow here */
              halt_baddata();
            }
            if (uVar1 < local_48 + 4U) {
                    /* WARNING: Bad instruction - Truncating control flow here */
              halt_baddata();
            }
            uVar7 = 4;
            uVar5 = 0;
            do {
              uVar11 = (uint)local_48;
              uVar7 = uVar7 & 0xff;
              uVar10 = 8 - (uVar11 & 7);
              uVar6 = uVar7;
              if (uVar10 < uVar7) {
                uVar6 = uVar10;
              }
              uVar7 = uVar7 - uVar6;
              local_48 = local_48 + (ulong)uVar6;
              sVar3 = ((byte)uVar6 < 0x21) * (' ' - (byte)uVar6);
              uVar5 = uVar5 | (((uint)(param_1[uVar11 >> 3 & 0xff] >> (uVar10 - uVar6 & 0x1f)) <<
                               sVar3) >> sVar3) << (uVar7 & 0x1f);
            } while ((char)uVar7 != '\0');
            if ((uVar5 == 0x10) || (uVar5 == 1)) {
              *(undefined1 *)(param_5 + 3) = param_3;
            }
            if (uVar1 < local_48 + 5U) {
                    /* WARNING: Bad instruction - Truncating control flow here */
              halt_baddata();
            }
            uVar5 = 5;
            local_3c = 0;
            do {
              uVar6 = (uint)local_48;
              uVar5 = uVar5 & 0xff;
              uVar11 = 8 - (uVar6 & 7);
              uVar7 = uVar5;
              if (uVar11 < uVar5) {
                uVar7 = uVar11;
              }
              uVar5 = uVar5 - uVar7;
              local_48 = local_48 + (ulong)uVar7;
              sVar3 = ((byte)uVar7 < 0x21) * (' ' - (byte)uVar7);
              local_3c = local_3c |
                         (((uint)(param_1[uVar6 >> 3 & 0xff] >> (uVar11 - uVar7 & 0x1f)) << sVar3)
                         >> sVar3) << (uVar5 & 0x1f);
            } while ((char)uVar5 != '\0');
            if ((local_3c == 0x10) || (local_3c == 1)) {
              *(undefined1 *)((long)param_5 + 0xd) = param_4;
            }
            iVar4 = func_0x00566380(param_1,param_2,&local_3c,&local_48,4,uVar11 - uVar7,0,
                                    param_5 + 3,uVar1);
            *(undefined1 *)((long)param_5 + 0xe) = (undefined1)local_3c;
            if (iVar4 != 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
              halt_baddata();
            }
            iVar4 = func_0x00566380(param_1,param_2,&local_3c,&local_48,6);
            *(undefined1 *)((long)param_5 + 0xf) = (undefined1)local_3c;
            if (iVar4 != 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
              halt_baddata();
            }
            iVar4 = func_0x00566380(param_1,param_2,&local_3c,&local_48,6);
            *(undefined1 *)(param_5 + 4) = (undefined1)local_3c;
            if (iVar4 == 0) {
              iVar4 = func_0x00566380(param_1,param_2,param_5 + 5,&local_48,1);
              if (iVar4 != 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
                halt_baddata();
              }
              if (param_5[5] != 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
                halt_baddata();
              }
                    /* WARNING: Bad instruction - Truncating control flow here */
              halt_baddata();
            }
                    /* WARNING: Bad instruction - Truncating control flow here */
            halt_baddata();
          }
          func_0x0025d410(0x1378d1c,0x13a5a87,0x5b7);
          func_0x0025d410(0x13b0b18);
          iVar4 = -0x7fc4fff6;
          uVar8 = 0x4e7;
          *(undefined1 *)(param_5 + 2) = 0;
        }
        else {
          uVar8 = 0x4da;
        }
      }
    }
    func_0x0025d410(0x1378d1c,0x12e90dc,uVar8);
    func_0x0025d410(uVar9);
  }
  if (_DAT_0391c310 == local_38) {
    return iVar4;
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* CONTEXT / separate function: adjacent_9a8080 @ 0x9a8080; ev_ad693b3e1423cdeb8521aca1a74769cd9e7f9ec4054d34852a8a5ec84ce647e5
 * Ghidra body ranges: 0x9a8080..0x9a8256
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

ulong adjacent_9a8080(long param_1,uint param_2,int param_3)

{
  int *piVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  int *piVar5;
  uint uVar6;
  ulong uVar7;
  
  param_2 = param_2 & 0xffffffe0;
  uVar4 = param_3 + 0x1fU & 0xffffffe0;
  func_0x007d46a0(param_1 + 0x18,0,0);
  piVar1 = (int *)(param_1 + 0x168);
  do {
    while( true ) {
      uVar3 = 0;
      if (((*piVar1 < 0) || (uVar3 = 0xffffffff, (int)uVar4 <= *piVar1)) ||
         (piVar5 = piVar1, *(int *)(param_1 + 0x16c) <= (int)param_2)) break;
LAB_009a81c8:
      piVar5[2] = 1;
      func_0x00c06260(piVar5 + 2,param_1,0x44,0x1375e9b,0,0,0x100);
    }
    iVar2 = *(int *)(param_1 + 0x174);
    uVar6 = 1;
    if (((-1 < iVar2) && (uVar6 = uVar3, iVar2 < (int)uVar4)) &&
       (piVar5 = (int *)(param_1 + 0x174), (int)param_2 < *(int *)(param_1 + 0x178)))
    goto LAB_009a81c8;
    iVar2 = *(int *)(param_1 + 0x180);
    uVar7 = 2;
    if (iVar2 < 0) {
LAB_009a821f:
      piVar1[uVar7 * 3] = param_2;
      *(uint *)(param_1 + 0x16c + uVar7 * 0xc) = uVar4;
      *(undefined4 *)(param_1 + 0x170 + uVar7 * 0xc) = 0;
      func_0x007d4eb0(param_1 + 0x18,0,0);
      return uVar7;
    }
    if ((iVar2 < (int)uVar4) &&
       (piVar5 = (int *)(param_1 + 0x180), (int)param_2 < *(int *)(param_1 + 0x184)))
    goto LAB_009a81c8;
    uVar7 = (ulong)uVar6;
    if (-1 < (int)uVar6) goto LAB_009a821f;
    *(undefined4 *)(param_1 + 0x198) = 1;
    do {
      func_0x00c06260((undefined4 *)(param_1 + 0x198),param_1,0x44,0x1394bd1,0,0,0x100);
    } while (*(int *)(param_1 + 0x198) != 0);
  } while( true );
}



/* CONTEXT / separate function: adjacent_9a8260 @ 0x9a8260; ev_b9f6569fe8ef0d8d1f1d5240ef2827d0c6f11b9018f4a783570c231f28d3f3cf
 * Ghidra body ranges: 0x9a8260..0x9a856a
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void adjacent_9a8260(long param_1,long param_2,undefined8 param_3,uint param_4,int param_5)

{
  long lVar1;
  code *pcVar2;
  int iVar3;
  uint uVar4;
  ulong uVar5;
  ulong uVar6;
  long lVar7;
  long *in_GS_OFFSET;
  bool bVar8;
  undefined8 local_48;
  long local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  if ((*(byte *)(param_1 + 0x244) & 1) != 0) {
    lVar1 = *in_GS_OFFSET;
    func_0x004c6a00(0x3ba5e78,0,0,0);
    while (_DAT_03ba5ed8 == 0) {
      func_0x00c06260(&DAT_03ba5ed8,0x3ba5e60,0x44,0x1272dc0,0,0,0x100);
    }
    iVar3 = 0;
    for (uVar5 = _DAT_03ba5ed8; (uVar5 & 1) == 0; uVar5 = uVar5 >> 1 | 0x8000000000000000) {
      iVar3 = iVar3 + 1;
    }
    _DAT_03ba5ed8 = _DAT_03ba5ed8 - 1 & _DAT_03ba5ed8;
    func_0x004c6fa0(0x3ba5e78,0,0,0);
    lVar7 = (ulong)(uint)(iVar3 << 0xd) + CONCAT44(uRam0000000003ba5ee4,_DAT_03ba5ee0);
    if ((int)param_4 < param_5) {
      uVar5 = (ulong)param_4;
      do {
        local_48 = 0;
        uVar6 = (long)(int)uVar5 + 0x800;
        if ((ulong)(long)param_5 <= uVar6) {
          uVar6 = (long)param_5;
        }
        local_40 = lVar7;
        uVar4 = adjacent_9a8080(param_2,param_4,param_5);
        adjacent_9a8570(param_1,param_2,param_3,uVar5 & 0xffffffff,uVar6 & 0xffffffff,&local_48,
                        &local_40);
        func_0x008ef340(*(undefined8 *)(param_1 + 0x1d8),local_48);
        if (*(char *)(lVar1 + 0x117) != '\0') {
          *(undefined1 *)(lVar1 + 0x117) = 0;
          pcVar2 = *(code **)(_DAT_01a962e8 + 0x40);
          if (0x6ff < (-(long)pcVar2 + 0x260ce8U >> 3 | -(long)pcVar2 << 0x3d)) {
            func_0x0044f8c0(0x255fe40,pcVar2);
          }
          (*pcVar2)(param_1);
        }
        FUN_009a86c0(param_2,lVar7,(ulong)(local_40 - lVar7) >> 2);
        uVar5 = (ulong)uVar4;
        func_0x007d46a0(param_2 + 0x18,0,0);
        *(undefined4 *)(param_2 + 0x168 + uVar5 * 0xc) = 0xffffffff;
        if (*(int *)(param_2 + 0x170 + uVar5 * 0xc) != 0) {
          *(undefined4 *)(param_2 + 0x170 + uVar5 * 0xc) = 0;
          func_0x00c06910();
        }
        if (*(int *)(param_2 + 0x198) != 0) {
          *(int *)(param_2 + 0x198) = 0;
          func_0x00c06910();
        }
        func_0x007d4eb0(param_2 + 0x18,0,0);
        uVar5 = uVar6;
      } while ((int)uVar6 < param_5);
    }
    func_0x004c6a00(0x3ba5e78,0,0,0);
    uVar5 = _DAT_03ba5ed8 | 1L << ((ulong)((uint)((int)lVar7 - _DAT_03ba5ee0) >> 0xd) & 0x3f);
    bVar8 = _DAT_03ba5ed8 == 0;
    _DAT_03ba5ed8 = uVar5;
    if (bVar8) {
      func_0x00c06910(&DAT_03ba5ed8);
    }
    func_0x004c6fa0(0x3ba5e78,0,0,0);
  }
  if (_DAT_0391c310 == local_38) {
    return;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar2 = (code *)invalidInstructionException();
  (*pcVar2)();
}



/* CONTEXT / separate function: adjacent_9a8570 @ 0x9a8570; ev_35f29b19e130302b4818587bace919479437cc9f8445ede06ddffc0be6585058
 * Ghidra body ranges: 0x9a8570..0x9a85fe, 0x9a8600..0x9a86bd
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void adjacent_9a8570(long param_1,long param_2,long param_3,int param_4,int param_5,
                    undefined8 param_6,undefined8 *param_7)

{
  char *pcVar1;
  uint uVar2;
  long lVar3;
  undefined8 uVar4;
  code *pcVar5;
  uint uVar6;
  uint *puVar7;
  long lVar8;
  int iVar9;
  uint *puVar10;
  long *in_GS_OFFSET;
  
  lVar3 = *(long *)(param_2 + 400);
  iVar9 = 0;
  puVar10 = (uint *)*param_7;
  uVar4 = *(undefined8 *)(param_1 + 0x1d8);
  puVar7 = (uint *)(*(long *)(param_2 + 0x160) + (long)param_4 * 4);
  *(undefined1 *)(*in_GS_OFFSET + 0x117) = 1;
  lVar8 = (long)param_4 * 0x10000 + param_3;
  func_0x009ec410(param_1,lVar8,param_5 - param_4,puVar7,0);
  if (param_4 < param_5) {
    do {
      uVar2 = *puVar7;
      uVar6 = uVar2 >> 0x1c & 3;
      if (uVar6 != 0) {
        if (uVar6 != 1) {
          func_0x007f1950();
          func_0x007f18a0(0x9a8692,uVar2);
          func_0x00c9aa10(0x2b,0x12c3f7e,uVar2);
                    /* WARNING: Does not return */
          pcVar5 = (code *)invalidInstructionException();
          (*pcVar5)();
        }
        *puVar7 = 0;
        *puVar10 = uVar2;
        puVar10 = puVar10 + 1;
        pcVar1 = (char *)(lVar3 + (param_4 >> 5));
        *pcVar1 = *pcVar1 + -1;
        iVar9 = iVar9 + (uint)(*pcVar1 == '\0');
      }
      param_4 = param_4 + 1;
      puVar7 = puVar7 + 1;
    } while (param_5 != param_4);
    if (0 < iVar9) {
      func_0x008ed5d0(*(undefined1 *)(param_2 + 0x19c),iVar9);
    }
  }
  func_0x008ee780(uVar4,lVar8,(long)param_5 * 0x10000 + param_3,param_6);
  *param_7 = puVar10;
  return;
}



/* CONTEXT / separate function: FUN_009a86c0 @ 0x9a86c0; ev_a534727e2bf83b81f17dcd13de1ba62f875af6024c1915a6b162a7c35cbee98a
 * Ghidra body ranges: 0x9a86c0..0x9a86c7, 0x9a87cc..0x9a87cc
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void FUN_009a86c0(long param_1,long param_2,int param_3)

{
  ulong *puVar1;
  uint uVar2;
  long lVar3;
  ulong uVar4;
  ulong uVar5;
  long lVar6;
  uint uVar7;
  long lVar8;
  
  if (param_3 != 0) {
    lVar3 = *(long *)(param_1 + 0xe8);
    lVar8 = 0;
    func_0x004c6a00(lVar3 + 0x28,0,0,0);
    do {
      uVar2 = *(uint *)(param_2 + lVar8 * 4);
      if ((uVar2 & 0x800000) == 0) {
        *(int *)(lVar3 + 0x54) = *(int *)(lVar3 + 0x54) + -1;
        *(int *)(lVar3 + 0x4c) = *(int *)(lVar3 + 0x4c) + 1;
        lVar6 = 0x20890;
      }
      else {
        *(int *)(lVar3 + 0x50) = *(int *)(lVar3 + 0x50) + -1;
        *(int *)(lVar3 + 0x48) = *(int *)(lVar3 + 0x48) + 1;
        lVar6 = 0x70;
      }
      lVar6 = lVar6 + lVar3;
      uVar7 = uVar2 >> 6 & 0x3fff;
      uVar4 = *(ulong *)(lVar6 + (ulong)uVar7 * 8);
      *(ulong *)(lVar6 + (ulong)uVar7 * 8) = uVar4 | 1L << ((ulong)uVar2 & 0x3f);
      if (uVar4 == 0) {
        uVar5 = (ulong)(uVar7 >> 6);
        uVar4 = *(ulong *)(lVar6 + 0x20000 + uVar5 * 8);
        *(ulong *)(lVar6 + 0x20000 + uVar5 * 8) = uVar4 | 1L << ((ulong)(uVar2 >> 6) & 0x3f);
        if (uVar4 == 0) {
          puVar1 = (ulong *)(lVar6 + 0x20800 + (ulong)(uVar7 >> 0xc) * 8);
          *puVar1 = *puVar1 | 1L << (uVar5 & 0x3f);
        }
      }
      lVar8 = lVar8 + 1;
    } while (param_3 != (int)lVar8);
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  return;
}



/* CONTEXT / separate function: adjacent_9a86c8 @ 0x9a86c8; ev_41ca5ee738ea294fb920c8800848603874aae8a1d3fcd57e5935b7befaa16550
 * Ghidra body ranges: 0x9a86c8..0x9a8702, 0x9a8710..0x9a8738, 0x9a8740..0x9a87cb
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void adjacent_9a86c8(long param_1,long param_2,int param_3)

{
  ulong *puVar1;
  uint uVar2;
  long lVar3;
  ulong uVar4;
  ulong uVar5;
  long lVar6;
  uint uVar7;
  long lVar8;
  
  lVar3 = *(long *)(param_1 + 0xe8);
  lVar8 = 0;
  func_0x004c6a00(lVar3 + 0x28,0,0,0);
  do {
    uVar2 = *(uint *)(param_2 + lVar8 * 4);
    if ((uVar2 & 0x800000) == 0) {
      *(int *)(lVar3 + 0x54) = *(int *)(lVar3 + 0x54) + -1;
      *(int *)(lVar3 + 0x4c) = *(int *)(lVar3 + 0x4c) + 1;
      lVar6 = 0x20890;
    }
    else {
      *(int *)(lVar3 + 0x50) = *(int *)(lVar3 + 0x50) + -1;
      *(int *)(lVar3 + 0x48) = *(int *)(lVar3 + 0x48) + 1;
      lVar6 = 0x70;
    }
    lVar6 = lVar6 + lVar3;
    uVar7 = uVar2 >> 6 & 0x3fff;
    uVar4 = *(ulong *)(lVar6 + (ulong)uVar7 * 8);
    *(ulong *)(lVar6 + (ulong)uVar7 * 8) = uVar4 | 1L << ((ulong)uVar2 & 0x3f);
    if (uVar4 == 0) {
      uVar5 = (ulong)(uVar7 >> 6);
      uVar4 = *(ulong *)(lVar6 + 0x20000 + uVar5 * 8);
      *(ulong *)(lVar6 + 0x20000 + uVar5 * 8) = uVar4 | 1L << ((ulong)(uVar2 >> 6) & 0x3f);
      if (uVar4 == 0) {
        puVar1 = (ulong *)(lVar6 + 0x20800 + (ulong)(uVar7 >> 0xc) * 8);
        *puVar1 = *puVar1 | 1L << (uVar5 & 0x3f);
      }
    }
    lVar8 = lVar8 + 1;
  } while (param_3 != (int)lVar8);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* CONTEXT / separate function: adjacent_9a87d0 @ 0x9a87d0; ev_ed4eccb7202554e9ea943f9a090a33197b612b183abf9a39b369abb42c97b7b7
 * Ghidra body ranges: 0x9a87d0..0x9a88dd, 0x9a88e0..0x9a895a, 0x9a8960..0x9a8a9e
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8
adjacent_9a87d0(long param_1,long param_2,long param_3,uint param_4,int param_5,uint param_6)

{
  uint uVar1;
  int iVar2;
  long lVar3;
  undefined8 uVar4;
  code *pcVar5;
  uint uVar6;
  uint uVar7;
  ulong uVar8;
  long lVar9;
  long lVar10;
  undefined8 uVar11;
  ulong uVar12;
  uint uVar13;
  long lVar14;
  long *in_GS_OFFSET;
  undefined8 local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  uVar6 = adjacent_9a8080(param_2,param_4,param_5);
  lVar3 = *(long *)(param_2 + 0x160);
  if ((((param_6 & 0x2a2) != 0) && ((int)param_4 < param_5)) &&
     ((*(byte *)(param_1 + 0x244) & 2) != 0)) {
    lVar9 = 0;
    do {
      if ((*(uint *)(lVar3 + (long)(int)param_4 * 4 + lVar9 * 4) & 0xf00000) == 0x800000) {
        uVar11 = 0xd;
        goto LAB_009a89e2;
      }
      lVar9 = lVar9 + 1;
    } while (param_5 - param_4 != (int)lVar9);
  }
  uVar11 = *(undefined8 *)(param_1 + 0x1d8);
  local_40 = 0;
  if ((int)param_4 < param_5) {
    uVar4 = *(undefined8 *)(*(long *)(param_2 + 0xe8) + 0x30);
    uVar12 = (ulong)param_5;
    uVar8 = (long)(int)(param_4 & 0xffffffe0) + 0x20;
    uVar13 = (param_6 & 0x30) << 0x16 | (param_6 >> 1 & 1 | param_6 & 3) << 0x18;
    if (uVar12 <= uVar8) {
      uVar8 = uVar12;
    }
    do {
      lVar14 = (long)(int)param_4;
      uVar7 = (uint)uVar8;
      lVar9 = lVar3 + lVar14 * 4;
      lVar10 = lVar14 * 0x10000 + param_3;
      func_0x009ed000(param_1,lVar10,uVar4,uVar7 - param_4,lVar9,uVar13);
      if (uVar7 - param_4 != 0 && (int)param_4 <= (int)uVar7) {
        do {
          uVar1 = *(uint *)(lVar3 + lVar14 * 4);
          if ((uVar1 & 0x30000000) != 0) {
            *(uint *)(lVar3 + lVar14 * 4) = uVar1 & 0xf0ffffff | uVar13;
          }
          lVar14 = lVar14 + 1;
        } while ((int)uVar7 != lVar14);
      }
      func_0x008ee310(uVar11,lVar10,uVar4,uVar7 - param_4,lVar9,uVar13,&local_40);
      uVar8 = (long)(int)uVar7 + 0x20;
      if (uVar12 <= uVar8) {
        uVar8 = uVar12;
      }
      param_4 = uVar7;
    } while ((int)uVar7 < param_5);
  }
  if (*(char *)(*in_GS_OFFSET + 0x116) == '\0') {
    pcVar5 = *(code **)(_DAT_01a962e8 + 0x40);
    if (0x6ff < (-(long)pcVar5 + 0x260ce8U >> 3 | -(long)pcVar5 << 0x3d)) {
      func_0x0044f8c0(0x255ff50,pcVar5);
    }
    (*pcVar5)(param_1);
  }
  func_0x008ef340(uVar11,local_40);
  uVar11 = 0;
LAB_009a89e2:
  uVar8 = (ulong)uVar6;
  func_0x007d46a0(param_2 + 0x18,0,0);
  *(undefined4 *)(param_2 + 0x168 + uVar8 * 0xc) = 0xffffffff;
  if (*(int *)(param_2 + 0x170 + uVar8 * 0xc) == 0) {
    iVar2 = *(int *)(param_2 + 0x198);
  }
  else {
    *(undefined4 *)(param_2 + 0x170 + uVar8 * 0xc) = 0;
    func_0x00c06910();
    iVar2 = *(int *)(param_2 + 0x198);
  }
  if (iVar2 != 0) {
    *(undefined4 *)(param_2 + 0x198) = 0;
    func_0x00c06910((undefined4 *)(param_2 + 0x198));
  }
  func_0x007d4eb0(param_2 + 0x18,0,0);
  if (_DAT_0391c310 == local_38) {
    return uVar11;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar5 = (code *)invalidInstructionException();
  (*pcVar5)();
}



/* CONTEXT / separate function: adjacent_9a8aa0 @ 0x9a8aa0; ev_cd573b5766ea472b3e0544bf2d7efb3f55ad6db32aab713a3dd37302108115fa
 * Ghidra body ranges: 0x9a8aa0..0x9a8cf2, 0x9a8d00..0x9a8da2, 0x9a8db0..0x9a8e38, 0x9a8e40..0x9a8f74
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8
adjacent_9a8aa0(long param_1,long param_2,long param_3,uint param_4,int param_5,uint param_6,
               uint param_7)

{
  uint uVar1;
  long lVar2;
  long lVar3;
  undefined8 uVar4;
  code *pcVar5;
  byte bVar6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  ulong uVar10;
  uint uVar11;
  ulong uVar12;
  uint uVar13;
  undefined8 uVar14;
  ulong uVar15;
  long lVar16;
  long lVar17;
  ulong uVar18;
  long *in_GS_OFFSET;
  uint local_48;
  uint local_44;
  undefined8 local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  uVar7 = adjacent_9a8080(param_2,param_4,param_5);
  bVar6 = *(byte *)(param_1 + 0x244);
  if ((param_6 < 0xb) && ((0x409U >> (param_6 & 0x1f) & 1) != 0)) {
    if ((bVar6 & 2) == 0) {
      iVar8 = FUN_009acc10(param_6);
      param_6 = (uint)(iVar8 == 0) * 4 + 0xf;
      bVar6 = *(byte *)(param_1 + 0x244);
    }
  }
  else {
    uVar14 = 0x16;
    if ((param_6 - 0x15 < 0xfffffff6) || ((bVar6 & 2) != 0)) goto LAB_009a8ebe;
  }
  if ((bVar6 & 2) == 0) {
    local_44 = 0;
    if (param_6 - 0xb < 10) {
      local_44 = *(uint *)((ulong)(param_6 - 0xb) * 4 + 0x18cdb8c);
    }
  }
  else {
    local_44 = 0xc00000;
    if (param_6 != 0) {
      local_44 = (uint)(param_6 == 10) << 0x17;
    }
  }
  uVar15 = (ulong)(int)param_4;
  lVar2 = *(long *)(param_2 + 0xe8);
  lVar3 = *(long *)(param_2 + 0x160);
  local_40 = 0;
  uVar12 = (ulong)param_5;
  uVar14 = *(undefined8 *)(param_1 + 0x1d8);
  func_0x008ee780(uVar14,uVar15 * 0x10000 + param_3,uVar12 * 0x10000 + param_3,&local_40);
  func_0x008ef340(uVar14,local_40);
  if ((int)param_4 < param_5) {
    iVar8 = 0;
    uVar18 = 0;
    uVar10 = uVar15;
    do {
      uVar11 = *(uint *)(lVar3 + uVar10 * 4);
      if (local_44 != (uVar11 & 0xf00000)) {
        uVar11 = uVar11 & 0x800000;
        if (uVar11 == (local_44 & 0x800000)) {
LAB_009a8c54:
          if (((uVar11 == 0) || (local_44 != 0x800000)) || ((*(byte *)(param_1 + 0x244) & 2) != 0))
          goto LAB_009a8c20;
        }
        else {
          if ((local_44 & 0x800000) != 0) {
            iVar8 = iVar8 + 1;
            goto LAB_009a8c54;
          }
          iVar8 = iVar8 + -1;
          if (uVar11 == 0) goto LAB_009a8c20;
        }
        uVar18 = uVar18 + 0x10000;
      }
LAB_009a8c20:
      uVar10 = uVar10 + 1;
    } while (uVar12 != uVar10);
  }
  else {
    uVar18 = 0;
    iVar8 = 0;
  }
  lVar16 = lVar2 + 0x28;
  func_0x004c6a00(lVar16,0,0,0);
  *(int *)(lVar2 + 0x50) = *(int *)(lVar2 + 0x50) + iVar8;
  *(int *)(lVar2 + 0x54) = *(int *)(lVar2 + 0x54) - iVar8;
  if (uVar18 < 0x200000) {
    func_0x004c6fa0(lVar16,0,0,0);
    if (uVar18 != 0 && (int)param_4 < param_5) {
      lVar16 = 0;
      do {
        uVar11 = *(uint *)(lVar3 + uVar15 * 4 + lVar16 * 4);
        if (((uVar11 & 0x30800000) == 0x10800000) && ((uVar11 & 0xf00000) != local_44)) {
          adjacent_9ac500(lVar2,uVar11 & 0xfffff);
        }
        lVar16 = lVar16 + 1;
      } while (param_5 - param_4 != (int)lVar16);
    }
  }
  else {
    adjacent_9ac450(lVar2);
    func_0x004c6fa0(lVar16,0,0,0);
  }
  uVar14 = *(undefined8 *)(param_1 + 0x1d8);
  local_40 = 0;
  if ((int)param_4 < param_5) {
    uVar4 = *(undefined8 *)(lVar2 + 0x30);
    uVar11 = (param_7 & 0x30) << 0x16 | (param_7 >> 1 & 1 | param_7 & 3) << 0x18;
    uVar15 = (long)(int)(param_4 & 0xffffffe0) + 0x20;
    if (uVar12 <= uVar15) {
      uVar15 = uVar12;
    }
    uVar13 = local_44 | uVar11;
    local_48 = param_4;
    do {
      lVar17 = (long)(int)local_48;
      uVar9 = (uint)uVar15;
      lVar2 = lVar3 + lVar17 * 4;
      lVar16 = lVar17 * 0x10000 + param_3;
      func_0x009ed630(param_1,lVar16,uVar4,uVar9 - local_48,lVar2,uVar13);
      if (uVar9 - local_48 != 0 && (int)local_48 <= (int)uVar9) {
        do {
          uVar1 = *(uint *)(lVar3 + lVar17 * 4);
          if ((uVar1 & 0x30000000) != 0) {
            *(uint *)(lVar3 + lVar17 * 4) = uVar1 & 0xf00fffff | uVar13;
          }
          lVar17 = lVar17 + 1;
        } while ((int)uVar9 != lVar17);
      }
      func_0x008eeaa0(uVar14,lVar16,uVar4,uVar9 - local_48,lVar2,local_44,uVar11,&local_40);
      uVar15 = (long)(int)uVar9 + 0x20;
      if (uVar12 <= uVar15) {
        uVar15 = uVar12;
      }
      local_48 = uVar9;
    } while ((int)uVar9 < param_5);
  }
  if (*(char *)(*in_GS_OFFSET + 0x116) == '\0') {
    pcVar5 = *(code **)(_DAT_01a962e8 + 0x40);
    if (0x6ff < (-(long)pcVar5 + 0x260ce8U >> 3 | -(long)pcVar5 << 0x3d)) {
      func_0x0044f8c0(0x255ff70,pcVar5);
    }
    (*pcVar5)(param_1);
  }
  func_0x008ef340(uVar14,local_40);
  uVar14 = 0;
LAB_009a8ebe:
  uVar12 = (ulong)uVar7;
  func_0x007d46a0(param_2 + 0x18,0,0);
  *(undefined4 *)(param_2 + 0x168 + uVar12 * 0xc) = 0xffffffff;
  if (*(int *)(param_2 + 0x170 + uVar12 * 0xc) == 0) {
    iVar8 = *(int *)(param_2 + 0x198);
  }
  else {
    *(undefined4 *)(param_2 + 0x170 + uVar12 * 0xc) = 0;
    func_0x00c06910();
    iVar8 = *(int *)(param_2 + 0x198);
  }
  if (iVar8 != 0) {
    *(undefined4 *)(param_2 + 0x198) = 0;
    func_0x00c06910((undefined4 *)(param_2 + 0x198));
  }
  func_0x007d4eb0(param_2 + 0x18,0,0);
  if (_DAT_0391c310 == local_38) {
    return uVar14;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar5 = (code *)invalidInstructionException();
  (*pcVar5)();
}



/* CONTEXT / separate function: adjacent_9a8f80 @ 0x9a8f80; ev_7e94c4dce191c5c0d18da4e06eb23e76d95656c9e9fefc8a28da7c37766c2175
 * Ghidra body ranges: 0x9a8f80..0x9a9267
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8
adjacent_9a8f80(undefined8 param_1,long param_2,ulong param_3,undefined8 param_4,long *param_5)

{
  long lVar1;
  uint uVar2;
  int iVar3;
  char cVar4;
  uint uVar5;
  long lVar6;
  long lVar7;
  ulong uVar8;
  long lVar9;
  undefined8 uVar10;
  
  if (param_5 == (long *)0x0) {
    uVar10 = 5;
  }
  else {
    lVar9 = *(long *)(param_2 + 0xe8);
    lVar6 = *(long *)(param_2 + 0x160);
    iVar3 = (int)(param_3 >> 0x10);
    uVar5 = adjacent_9a8080(param_2,param_3 >> 0x10 & 0xffffffff,iVar3 + 1);
    uVar2 = *(uint *)(lVar6 + (long)iVar3 * 4);
    if ((uVar2 & 0x30000000) == 0x10000000) {
      lVar1 = param_2 + 0x18;
      lVar9 = (param_3 & 0xffff | (ulong)(uVar2 & 0xfffff) << 0x10) + *(long *)(lVar9 + 0x30);
      func_0x007d46a0(lVar1,0,0);
      lVar6 = func_0x00b897e0(param_2,(long)param_3 >> 0xe);
      if (lVar6 == 0) {
        lVar7 = 0;
        cVar4 = ((uVar2 & 0x800000) != 0) * '\x05' + '\x01';
        do {
          for (lVar6 = *(long *)(param_2 + 0x68); lVar6 != 0; lVar6 = *(long *)(lVar6 + 0x10)) {
            func_0x004c6a00((*(uint *)(lVar6 + 0x30) >> 0xf & 0x3fc0) + 0x3d7c458,0,0,0);
            if (*(short *)(lVar6 + 0x60) == 0) {
              func_0x00b89600(lVar6);
              func_0x004c6fa0((*(uint *)(lVar6 + 0x30) >> 0xf & 0x3fc0) + 0x3d7c458,0,0,0);
              func_0x00b89350(lVar6,lVar9,cVar4);
              lVar9 = lVar7;
              goto LAB_009a9150;
            }
            func_0x004c6fa0((*(uint *)(lVar6 + 0x30) >> 0xf & 0x3fc0) + 0x3d7c458,0,0);
          }
          if (lVar7 != 0) {
            lVar9 = 0;
            lVar6 = lVar7;
LAB_009a9150:
            lVar7 = lVar9;
            func_0x00b89580(lVar6,param_2,(long)param_3 >> 0xe);
            break;
          }
          func_0x007d4eb0(lVar1,0,0);
          lVar7 = func_0x00b892c0(lVar9,cVar4);
          *(undefined4 *)(lVar7 + 0x5c) = 1;
          func_0x007d46a0(lVar1,0,0);
          lVar6 = func_0x00b897e0(param_2);
        } while (lVar6 == 0);
      }
      else {
        lVar7 = 0;
      }
      func_0x004c6a00((*(uint *)(lVar6 + 0x30) >> 0xf & 0x3fc0) + 0x3d7c458,0,0,0);
      func_0x00b88f30(lVar6);
      func_0x004c6fa0((*(uint *)(lVar6 + 0x30) >> 0xf & 0x3fc0) + 0x3d7c458,0,0,0);
      func_0x007d4eb0(lVar1,0,0);
      uVar10 = 0;
      if (lVar7 != 0) {
        func_0x00b89330(lVar7);
      }
    }
    else {
      uVar10 = 2;
    }
    uVar8 = (ulong)uVar5;
    func_0x007d46a0(param_2 + 0x18,0,0);
    *(undefined4 *)(param_2 + 0x168 + uVar8 * 0xc) = 0xffffffff;
    if (*(int *)(param_2 + 0x170 + uVar8 * 0xc) == 0) {
      iVar3 = *(int *)(param_2 + 0x198);
    }
    else {
      *(undefined4 *)(param_2 + 0x170 + uVar8 * 0xc) = 0;
      func_0x00c06910();
      iVar3 = *(int *)(param_2 + 0x198);
    }
    if (iVar3 != 0) {
      *(undefined4 *)(param_2 + 0x198) = 0;
      func_0x00c06910((undefined4 *)(param_2 + 0x198));
    }
    func_0x007d4eb0(param_2 + 0x18,0,0);
    if ((uVar2 & 0x30000000) == 0x10000000) {
      *param_5 = lVar6;
    }
  }
  return uVar10;
}



/* CONTEXT / separate function: adjacent_9a9270 @ 0x9a9270; ev_d69eab01088e524a41beaf048b6ffd9b52af71368fd1c795cf25094eb9a35291
 * Ghidra body ranges: 0x9a9270..0x9a9553
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

bool adjacent_9a9270(long param_1,long param_2,ulong param_3,long param_4,long *param_5,
                    long *param_6,uint *param_7,undefined4 *param_8,undefined8 param_9,int param_10)

{
  long lVar1;
  uint uVar2;
  code *pcVar3;
  uint uVar4;
  ulong uVar5;
  int iVar6;
  int iVar7;
  undefined4 uVar8;
  ulong uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  long lVar13;
  long lVar14;
  undefined4 uVar15;
  int iVar16;
  uint uVar17;
  ulong uVar18;
  int iVar19;
  int iVar20;
  long local_48;
  ulong local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  uVar4 = adjacent_9a8080(param_2,0,*(ulong *)(param_2 + 0x88) >> 2);
  uVar5 = *(ulong *)(param_2 + 0x88);
  lVar14 = *(long *)(param_2 + 0x160);
  uVar18 = param_4 - param_3 >> 0x10;
  func_0x002c70a0(param_1,param_4,&local_40,&local_48,param_9);
  iVar16 = (int)(param_4 - param_3 >> 0x10);
  lVar13 = (long)iVar16;
  uVar2 = *(uint *)(lVar14 + lVar13 * 4);
  iVar20 = 0;
  if (param_3 <= local_40) {
    iVar20 = (int)(local_40 - param_3 >> 0x10);
  }
  uVar9 = (ulong)(int)(uVar5 >> 2);
  uVar5 = local_48 - param_3 >> 0x10;
  if (uVar9 < uVar5) {
    uVar5 = uVar9;
  }
  iVar6 = iVar16 + 1;
  iVar19 = iVar20;
  if (iVar16 < iVar20) {
    iVar19 = iVar16;
  }
  uVar12 = (uint)uVar5;
  if ((uVar2 & 0x30000000) == 0) {
    do {
      iVar7 = iVar19;
      if (lVar13 <= iVar20) break;
      iVar6 = iVar6 + -1;
      lVar1 = lVar13 * 4;
      lVar13 = lVar13 + -1;
      iVar7 = iVar6;
    } while ((*(byte *)(lVar14 + -1 + lVar1) & 0x30) == 0);
    uVar10 = iVar16 + 1U;
    if ((int)(iVar16 + 1U) <= (int)uVar12) {
      uVar10 = uVar12;
    }
    do {
      uVar17 = (int)uVar18 + 1;
      uVar18 = (ulong)uVar17;
      uVar11 = uVar10;
      if ((int)uVar12 <= (int)uVar17) break;
      uVar11 = uVar17;
    } while ((*(byte *)(lVar14 + 3 + (long)(int)uVar17 * 4) & 0x30) == 0);
  }
  else {
    do {
      iVar7 = iVar19;
      if (lVar13 <= iVar20) break;
      lVar1 = lVar13 * 4;
      lVar13 = lVar13 + -1;
      iVar6 = iVar6 + -1;
      iVar7 = iVar6;
    } while (((*(uint *)(lVar14 + -4 + lVar1) ^ uVar2) & 0x3ff00000) == 0);
    uVar10 = iVar16 + 1U;
    if ((int)(iVar16 + 1U) <= (int)uVar12) {
      uVar10 = uVar12;
    }
    do {
      uVar17 = (int)uVar18 + 1;
      uVar18 = (ulong)uVar17;
      uVar11 = uVar10;
      if ((int)uVar12 <= (int)uVar17) break;
      uVar11 = uVar17;
    } while (((*(uint *)(lVar14 + (long)(int)uVar17 * 4) ^ uVar2) & 0x3ff00000) == 0);
  }
  if (param_10 == 0) {
    lVar13 = (long)(iVar7 << 0x10);
    lVar14 = (long)(int)(uVar11 << 0x10);
  }
  else {
    lVar13 = (long)iVar7 << 0x10;
    lVar14 = (long)(int)uVar11 << 0x10;
  }
  uVar12 = 3;
  if ((uVar2 & 0x2000000) == 0) {
    uVar12 = uVar2 >> 0x18 & 1;
  }
  *param_5 = lVar13 + param_3;
  *param_6 = lVar14 + param_3;
  *param_7 = uVar2 >> 0x16 & 0x30 | uVar12;
  if ((uVar2 & 0x30000000) != 0) {
    if ((*(byte *)(param_1 + 0x244) & 2) == 0) {
      uVar12 = uVar2 >> 0x14 & 0xf;
      uVar8 = 0;
      if (uVar12 != 0xf) {
        uVar8 = *(undefined4 *)((ulong)uVar12 * 4 + 0x18cdb50);
      }
    }
    else {
      uVar15 = 10;
      if ((uVar2 & 0xf00000) != 0x800000) {
        uVar15 = 0;
      }
      uVar8 = 3;
      if ((uVar2 & 0xf00000) != 0) {
        uVar8 = uVar15;
      }
    }
    *param_8 = uVar8;
  }
  uVar5 = (ulong)uVar4;
  func_0x007d46a0(param_2 + 0x18,0,0);
  *(undefined4 *)(param_2 + 0x168 + uVar5 * 0xc) = 0xffffffff;
  if (*(int *)(param_2 + 0x170 + uVar5 * 0xc) == 0) {
    iVar20 = *(int *)(param_2 + 0x198);
  }
  else {
    *(undefined4 *)(param_2 + 0x170 + uVar5 * 0xc) = 0;
    func_0x00c06910();
    iVar20 = *(int *)(param_2 + 0x198);
  }
  if (iVar20 != 0) {
    *(undefined4 *)(param_2 + 0x198) = 0;
    func_0x00c06910((undefined4 *)(param_2 + 0x198));
  }
  func_0x007d4eb0(param_2 + 0x18,0,0);
  if (_DAT_0391c310 == local_38) {
    return (uVar2 & 0x30000000) != 0;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar3 = (code *)invalidInstructionException();
  (*pcVar3)();
}



/* CONTEXT / separate function: handler_654_body @ 0x9a9560; ev_069ea497cc5c1642f27513743242bb7ee9aae17b230c7307b847eaf0e0c874c5
 * Ghidra body ranges: 0x9a9560..0x9a979b
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 handler_654_body(long param_1,ulong *param_2)

{
  uint uVar1;
  long lVar2;
  ulong uVar3;
  long lVar4;
  long lVar5;
  code *pcVar6;
  ulong uVar7;
  int iVar8;
  undefined4 uVar9;
  uint uVar10;
  ulong uVar11;
  long local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  uVar11 = *param_2;
  lVar2 = *(long *)(*(long *)(param_1 + 8) + 0x200);
  uVar9 = 0x16;
  if (((*(ulong *)(lVar2 + 0x20) <= uVar11) && ((short)uVar11 == 0)) &&
     (uVar11 < *(ulong *)(lVar2 + 0x28))) {
    uVar3 = param_2[1];
    if (((uVar3 & 0xffff) == 0) && (uVar3 <= *(ulong *)(lVar2 + 0x28) - uVar11)) {
      uVar10 = (uint)param_2[2];
      uVar1 = (uint)param_2[3];
      uVar7 = param_2[4];
      if ((uVar10 < 0xb) && ((0x409U >> (uVar10 & 0x1f) & 1) != 0)) {
        if ((*(byte *)(lVar2 + 0x244) & 2) == 0) {
          iVar8 = FUN_009acc10(uVar10);
          uVar10 = (uint)(iVar8 == 0) * 4 + 0xf;
        }
      }
      else if ((uVar10 - 0x15 < 0xfffffff6) || ((*(byte *)(lVar2 + 0x244) & 2) != 0))
      goto LAB_009a9598;
      uVar9 = 0x16;
      if ((uVar1 & 0xffffffcc) == 0 && (int)uVar7 == 0) {
        uVar9 = 0xd;
        if ((uVar1 & 0x22) == 0 || uVar10 != 10) {
          func_0x002c6820(lVar2,0,0);
          iVar8 = func_0x002c6c40(lVar2,uVar11,&local_40);
          uVar9 = 0x16;
          if ((((iVar8 != 0) && ((*(byte *)(local_40 + 0x60) & 2) == 0)) &&
              (lVar4 = *(long *)(local_40 + 0x50), lVar4 != 0)) &&
             ((*(char *)(lVar4 + 0x9d) == '\v' && (uVar3 <= *(long *)(local_40 + 0x28) - uVar11))))
          {
            if (uVar3 == 0) {
              uVar9 = 0;
            }
            else {
              lVar5 = *(long *)(local_40 + 0x20);
              LOCK();
              *(int *)(lVar2 + 0x1c4) = *(int *)(lVar2 + 0x1c4) + 1;
              UNLOCK();
              uVar11 = uVar11 - lVar5;
              uVar9 = adjacent_9a97a0(lVar2,lVar4,lVar5,uVar11 >> 0x10 & 0xffffffff,
                                      (int)(uVar3 >> 0x10) + (int)(uVar11 >> 0x10),uVar1,uVar10);
              if (*(char *)(param_1 + 0x117) != '\0') {
                *(undefined1 *)(param_1 + 0x117) = 0;
                pcVar6 = *(code **)(_DAT_01a962e8 + 0x40);
                if (0x6ff < (-(long)pcVar6 + 0x260ce8U >> 3 | -(long)pcVar6 << 0x3d)) {
                  func_0x0044f8c0(0x255fe60,pcVar6);
                }
                (*pcVar6)(lVar2);
              }
            }
          }
          func_0x002c6870(lVar2,0,0);
        }
      }
    }
  }
LAB_009a9598:
  if (_DAT_0391c310 == local_38) {
    return uVar9;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar6 = (code *)invalidInstructionException();
  (*pcVar6)();
}



/* CONTEXT / separate function: adjacent_9a97a0 @ 0x9a97a0; ev_e1a1a0108739942da5ae8426a6ffd2d1afd70b187339f39f79ea7e7d96c72d35
 * Ghidra body ranges: 0x9a97a0..0x9a9a79, 0x9a9a80..0x9a9e01
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int adjacent_9a97a0(long param_1,long param_2,long param_3,uint param_4,uint param_5,uint param_6,
                   int param_7)

{
  char *pcVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  undefined8 uVar5;
  undefined8 uVar6;
  code *pcVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  int iVar11;
  uint uVar12;
  uint uVar13;
  uint uVar14;
  uint uVar15;
  long lVar16;
  uint uVar17;
  long lVar18;
  uint uVar19;
  uint uVar20;
  int iVar21;
  int iVar22;
  uint uVar23;
  uint uVar24;
  ulong uVar25;
  long lVar26;
  long lVar27;
  long lVar28;
  long *in_GS_OFFSET;
  bool bVar29;
  uint local_dc;
  undefined8 local_c0;
  uint local_b8 [32];
  long local_38;
  
  local_38 = _DAT_0391c310;
  if ((*(byte *)(param_1 + 0x244) & 2) == 0) {
    uVar20 = 0;
    if (param_7 - 0xbU < 10) {
      uVar20 = *(uint *)((ulong)(param_7 - 0xbU) * 4 + 0x18cdb8c);
    }
  }
  else {
    uVar20 = 0xc00000;
    if (param_7 != 0) {
      uVar20 = (uint)(param_7 == 10) << 0x17;
    }
  }
  uVar14 = param_6 & 0x30;
  uVar17 = (uVar20 & 0x800000) >> 0x17;
  local_dc = uVar17;
  if ((*(byte *)(param_1 + 0x244) & 2) != 0) {
    local_dc = (uint)((uVar20 & 0xf00000) != 0x800000 && (uVar20 & 0x800000) != 0);
  }
  lVar2 = *(long *)(param_2 + 0xe8);
  lVar3 = *(long *)(param_2 + 0x160);
  lVar4 = *(long *)(param_2 + 400);
  uVar10 = adjacent_9a8080(param_2,param_4,param_5);
  if ((int)param_4 < (int)param_5) {
    lVar18 = 0;
    do {
      if (*(int *)(lVar3 + (long)(int)param_4 * 4 + lVar18 * 4) != 0) {
        iVar11 = 0x10;
        goto LAB_009a9d44;
      }
      lVar18 = lVar18 + 1;
    } while (param_5 - param_4 != (int)lVar18);
  }
  iVar11 = (int)param_4 >> 5;
  iVar21 = (int)param_5 >> 5;
  uVar12 = (uint)(*(char *)(lVar4 + iVar11) == '\0');
  if ((iVar11 < iVar21 && (param_5 & 0x1f) != 0) && (*(char *)(lVar4 + iVar21) == '\0')) {
    uVar12 = (*(char *)(lVar4 + iVar11) == '\0') + 1;
  }
  iVar22 = iVar21 - (iVar11 + 1);
  if (iVar22 == 0 || iVar21 < iVar11 + 1) {
    iVar22 = 0;
  }
  iVar21 = iVar22 + uVar12;
  if ((iVar21 == 0 || SCARRY4(iVar22,uVar12) != iVar21 < 0) ||
     (iVar11 = func_0x008ed550(*(undefined1 *)(param_2 + 0x19c)), iVar11 == 0)) {
    bVar29 = (*(byte *)(param_1 + 0x244) & 2) != 0;
    iVar11 = 0;
    uVar12 = 0x700;
    if (bVar29) {
      uVar12 = 2;
    }
    uVar15 = 0xa00;
    if (!bVar29) {
      uVar15 = 2;
    }
    if ((int)param_4 < (int)param_5) {
      lVar26 = (long)(int)param_4;
      lVar27 = lVar26 * 0x10000 + param_3;
      uVar24 = param_6 >> 1 & 1;
      uVar23 = uVar24 | param_6 & 3;
      uVar13 = param_4 & 0xffffffe0;
      uVar5 = *(undefined8 *)(param_1 + 0x1d8);
      uVar6 = *(undefined8 *)(lVar2 + 0x30);
      lVar18 = lVar27;
      uVar9 = uVar13 + 0x20;
      uVar8 = param_4;
      do {
        uVar19 = uVar9;
        lVar28 = (long)(int)uVar19;
        if ((long)(int)param_5 < (long)(int)uVar19) {
          lVar28 = (long)(int)param_5;
        }
        uVar9 = uVar19;
        if ((int)param_5 < (int)uVar19) {
          uVar9 = param_5;
        }
        iVar22 = uVar9 - uVar8;
        iVar11 = adjacent_9abca0(lVar2,iVar22,local_dc,uVar17,local_b8);
        if (iVar11 != 0) {
LAB_009a9be7:
          if (uVar23 != 0) {
            local_c0 = 0;
            func_0x008ee780(uVar5,lVar27,(long)(int)uVar8 * 0x10000 + param_3,&local_c0);
            func_0x008ef340(uVar5,local_c0);
          }
          if (uVar14 == 0) {
            iVar22 = uVar8 - param_4;
          }
          else {
            *(undefined1 *)(*in_GS_OFFSET + 0x117) = 0;
            iVar22 = uVar8 - param_4;
            func_0x009ec410(param_1,lVar27,iVar22,lVar3 + lVar26 * 4,1);
          }
          lVar3 = lVar3 + lVar26 * 4;
          FUN_009a86c0(param_2,lVar3,iVar22);
          func_0x00258ff0(lVar3,(long)iVar22 << 2);
          uVar17 = uVar13 + 0x20;
          uVar20 = param_4;
          while (uVar12 = uVar17, (int)uVar20 < (int)uVar8) {
            uVar13 = uVar13 + 0x20;
            uVar20 = uVar13;
            if ((int)uVar8 < (int)uVar13) {
              uVar20 = uVar8;
            }
            pcVar1 = (char *)(lVar4 + ((int)param_4 >> 5));
            *pcVar1 = *pcVar1 + ((char)param_4 - (char)uVar20);
            uVar17 = uVar12 + 0x20;
            param_4 = uVar12;
            uVar20 = uVar13;
          }
          func_0x008ed5d0(*(undefined1 *)(param_2 + 0x19c),iVar21);
          goto LAB_009a9d44;
        }
        pcVar1 = (char *)(lVar4 + ((int)uVar8 >> 5));
        *pcVar1 = *pcVar1 + (char)iVar22;
        if ((int)uVar8 < (int)uVar9) {
          lVar16 = 0;
          do {
            *(uint *)(lVar3 + (long)(int)uVar8 * 4 + lVar16 * 4) =
                 local_b8[(int)lVar16] | uVar20 | uVar23 << 0x18 | uVar14 << 0x16 | 0x10000000;
            lVar16 = lVar16 + 1;
          } while (lVar28 - (int)uVar8 != lVar16);
        }
        if (uVar23 != 0) {
          func_0x008edf10(uVar5,lVar18,uVar6,iVar22,local_b8,uVar24 | param_6 & 0xffff,uVar17);
        }
        if ((uVar14 != 0) &&
           (iVar11 = func_0x009ec220(param_1,lVar18,uVar6,iVar22,local_b8,uVar24 | param_6,
                                     uVar20 >> (uint)bVar29 * 9 + 0xc & uVar12 | uVar15),
           uVar8 = uVar9, iVar11 != 0)) goto LAB_009a9be7;
        lVar18 = lVar18 + iVar22 * 0x10000;
        uVar9 = uVar19 + 0x20;
        uVar8 = uVar19;
      } while ((int)uVar19 < (int)param_5);
      iVar11 = 0;
    }
  }
LAB_009a9d44:
  uVar25 = (ulong)uVar10;
  func_0x007d46a0(param_2 + 0x18,0,0);
  *(undefined4 *)(param_2 + 0x168 + uVar25 * 0xc) = 0xffffffff;
  if (*(int *)(param_2 + 0x170 + uVar25 * 0xc) == 0) {
    iVar21 = *(int *)(param_2 + 0x198);
  }
  else {
    *(undefined4 *)(param_2 + 0x170 + uVar25 * 0xc) = 0;
    func_0x00c06910();
    iVar21 = *(int *)(param_2 + 0x198);
  }
  if (iVar21 != 0) {
    *(undefined4 *)(param_2 + 0x198) = 0;
    func_0x00c06910((undefined4 *)(param_2 + 0x198));
  }
  func_0x007d4eb0(param_2 + 0x18,0,0);
  if (uVar14 != 0) {
    *(undefined1 *)(*in_GS_OFFSET + 0x117) = 1;
  }
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar7 = (code *)invalidInstructionException();
    (*pcVar7)();
  }
  return iVar11;
}



/* CONTEXT / separate function: handler_655_body @ 0x9a9e10; ev_44e6a1a8105669fc7fb26464f55e24fa49428aad6ecb434e08d897ab9cd6c054
 * Ghidra body ranges: 0x9a9e10..0x9a9f3d
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 handler_655_body(long param_1,ulong *param_2)

{
  ulong uVar1;
  long lVar2;
  ulong uVar3;
  long lVar4;
  code *pcVar5;
  int iVar6;
  undefined8 uVar7;
  long local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  uVar1 = *param_2;
  lVar2 = *(long *)(*(long *)(param_1 + 8) + 0x200);
  uVar7 = 0x16;
  if (*(ulong *)(lVar2 + 0x20) <= uVar1) {
    uVar3 = param_2[1];
    if (((((short)uVar1 == 0 && (short)uVar3 == 0) && uVar1 < *(ulong *)(lVar2 + 0x28)) &&
        (uVar3 <= *(ulong *)(lVar2 + 0x28) - uVar1)) && ((int)param_2[2] == 0)) {
      func_0x002c6820(lVar2,0,0);
      iVar6 = func_0x002c6c40(lVar2,uVar1,&local_40);
      if ((iVar6 == 0) || ((*(byte *)(local_40 + 0x60) & 2) != 0)) {
        uVar7 = 0x16;
      }
      else {
        lVar4 = *(long *)(local_40 + 0x50);
        uVar7 = 0x16;
        if (((lVar4 != 0) && (*(char *)(lVar4 + 0x9d) == '\v')) &&
           ((uVar3 <= *(long *)(local_40 + 0x28) - uVar1 && (uVar7 = 0, uVar3 != 0)))) {
          LOCK();
          *(int *)(lVar2 + 0x1c4) = *(int *)(lVar2 + 0x1c4) + 1;
          UNLOCK();
          iVar6 = (int)(uVar1 - *(long *)(local_40 + 0x20) >> 0x10);
          adjacent_9a8260(lVar2,lVar4,*(long *)(local_40 + 0x20),iVar6,(int)(uVar3 >> 0x10) + iVar6)
          ;
        }
      }
      func_0x002c6870(lVar2,0,0);
    }
  }
  if (_DAT_0391c310 == local_38) {
    return uVar7;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar5 = (code *)invalidInstructionException();
  (*pcVar5)();
}



/* CONTEXT / separate function: handler_657_body @ 0x9a9f40; ev_072f7ec51740318cfd6704c365cb5277a108266184df6f3f92512cdcc84c9525
 * Ghidra body ranges: 0x9a9f40..0x9aa0d3, 0x9aa1b9..0x9aa222, 0x9aa228..0x9aa24e
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
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



/* CONTEXT / separate function: adjacent_9aa250 @ 0x9aa250; ev_f4e7f69decabffda14471c80a8c1abdfac6eeb6fbedec7c363495ff09e2f04b3
 * Ghidra body ranges: 0x9aa250..0x9aa371
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_9aa250(long param_1,undefined8 param_2,ulong param_3,ulong param_4,long param_5)

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
      uVar5 = adjacent_9a97a0(param_1,param_2,param_3,uVar2 - param_3 >> 0x10,
                              (uVar2 - param_3) + uVar3 >> 0x10 & 0xffffffff,bVar1,bVar6);
    }
  }
  return uVar5;
}



/* CONTEXT / separate function: adjacent_9aa380 @ 0x9aa380; ev_93e798132fd13fb13a101b97cc948b67536b7327bc4fe9cf738fd25e807aca2d
 * Ghidra body ranges: 0x9aa380..0x9aa85a
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int adjacent_9aa380(long param_1,long param_2,ulong param_3,ulong param_4,int *param_5,long *param_6
                   ,long param_7)

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
          FUN_009a86c0(param_2,lVar1,(ulong)(lVar6 - lVar1) >> 2 & 0xffffffff);
          local_40 = lVar1;
        }
      }
      if ((uVar10 & 0xfffff800) == 0) {
        uVar7 = adjacent_9a8080(param_2,uVar9 & 0xffffffff,uVar12 & 0xffffffff);
        uVar10 = (ulong)uVar7;
        adjacent_9a8570(param_1,param_2,param_3,uVar9 & 0xffffffff,uVar12 & 0xffffffff,&local_48,
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
        adjacent_9a8260(param_1,param_2,param_3,uVar9 & 0xffffffff,uVar12 & 0xffffffff);
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
    FUN_009a86c0(param_2,lVar1,(ulong)(lVar5 - lVar1) >> 2 & 0xffffffff);
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



/* CONTEXT / separate function: adjacent_9aa860 @ 0x9aa860; ev_6246bdf30fa01c0e4fc7129fa4da3c2b0869ad5ada7822e5e8d0ce6f808e9d64
 * Ghidra body ranges: 0x9aa860..0x9aa8cb
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted.", "Ghidra Listing reports a terminal call at 0x9aa8c3 to 0x9a87d0 adjacent_9a87d0 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

undefined8
adjacent_9aa860(undefined8 param_1,undefined8 param_2,ulong param_3,ulong param_4,long param_5)

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
      uVar3 = adjacent_9a87d0();
      return uVar3;
    }
    uVar3 = 0;
  }
  return uVar3;
}



/* CONTEXT / separate function: adjacent_9aa8d0 @ 0x9aa8d0; ev_fa19f81799ecddd9dafc4124b6a097e00b90b45aa55a362d5d7068e0edc537e8
 * Ghidra body ranges: 0x9aa8d0..0x9aaa06, 0x9aaa10..0x9aabd2, 0x9aabe0..0x9aac28, 0x9aac30..0x9aad8a, 0x9aad90..0x9aadd1, 0x9aade0..0x9aae8d, 0x9aae90..0x9aaf3e, 0x9aaf40..0x9ab034, 0x9ab040..0x9ab07e, 0x9ab080..0x9ab0c6, 0x9ab0d0..0x9ab15b
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int adjacent_9aa8d0(long param_1,long param_2,ulong param_3,ulong param_4,int *param_5,long *param_6
                   ,long param_7)

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
  uVar11 = adjacent_9a8080(param_2,local_458 - param_3 >> 0x10,
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
    adjacent_9ac450(lVar4);
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
              adjacent_9ac500(lVar4,uVar18 & 0xfffff);
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



/* CONTEXT / separate function: adjacent_9ab160 @ 0x9ab160; ev_4433f1342a8f4288e8e933e6efd426b0d9247390cea85ebed5fb7ec36661ce54
 * Ghidra body ranges: 0x9ab160..0x9ab1e9
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted.", "Ghidra Listing reports a terminal call at 0x9ab1e3 to 0x9ab370 adjacent_9ab370 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

undefined8
adjacent_9ab160(undefined8 param_1,undefined8 param_2,ulong param_3,ulong param_4,long param_5)

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
    uVar4 = adjacent_9ab370();
    return uVar4;
  }
  return uVar4;
}



/* CONTEXT / separate function: handler_673_body @ 0x9ab1f0; ev_b7c7572f5a1f1e9f8273d43aa6756cb02dbafab235da9dcd081a250b4e7b7507
 * Ghidra body ranges: 0x9ab1f0..0x9ab368
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 handler_673_body(long param_1,ulong *param_2)

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
        uVar10 = adjacent_9ab370(lVar2,lVar6,uVar7,uVar1 - uVar7 >> 0x10 & 0xffffffff,
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



/* CONTEXT / separate function: adjacent_9ab370 @ 0x9ab370; ev_dbbf7c1c0eb7721ed3bee48ffb5d780c784660c4c58d3c833b82d1321ed14f40
 * Ghidra body ranges: 0x9ab370..0x9ab4d2, 0x9ab4e0..0x9ab815, 0x9ab820..0x9ab890, 0x9ab8a0..0x9ab9a3, 0x9ab9b0..0x9abc92
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int adjacent_9ab370(long param_1,long param_2,long param_3,uint param_4,ulong param_5,int param_6)

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
  local_88 = adjacent_9a8080(param_2,uVar11,uVar22);
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



/* CONTEXT / separate function: adjacent_9abca0 @ 0x9abca0; ev_dcd94ce5c928131f024b70a33630d75fd4d13a82c7468289b712b14f72b3ca97
 * Ghidra body ranges: 0x9abca0..0x9abd7c, 0x9abd80..0x9abe73, 0x9abe80..0x9abf6b, 0x9abf70..0x9ac08b, 0x9ac090..0x9ac1a3, 0x9ac1b0..0x9ac295, 0x9ac2a0..0x9ac449
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_9abca0(long param_1,uint param_2,int param_3,int param_4,uint *param_5)

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
      adjacent_9ac450(param_1);
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
      adjacent_9ac500(param_1,param_5[uVar16] & 0xfffff);
      uVar16 = uVar16 + 1;
    } while (uVar7 != uVar16);
  }
  return 0;
}



/* CONTEXT / separate function: adjacent_9ac450 @ 0x9ac450; ev_04e0b9c1cb34f23b2899d32b1e2621d3bc2c3e3c24133c7aec581ab5c8b48dd4
 * Ghidra body ranges: 0x9ac450..0x9ac4f4
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void adjacent_9ac450(long param_1)

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



/* CONTEXT / separate function: adjacent_9ac500 @ 0x9ac500; ev_830c33bb3dd26a19da8a1c2d39a7995afe3f8dd584fcec467906997978356567
 * Ghidra body ranges: 0x9ac500..0x9ac655
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void adjacent_9ac500(long param_1,uint param_2)

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



/* CONTEXT / separate function: adjacent_9ac660 @ 0x9ac660; ev_a51c7d9c54819ecf54abfe2909eebea5033339fef76f1e780e98aab2e18db982
 * Ghidra body ranges: 0x9ac660..0x9ac66a
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_9ac660(void)

{
  return 6;
}



/* CONTEXT / separate function: adjacent_9ac670 @ 0x9ac670; ev_d6d437fcfd111a02323485ebefcd6cdae3c99d216c80b9f6e50051ff61ec610f
 * Ghidra body ranges: 0x9ac670..0x9ac67a
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_9ac670(void)

{
  return 6;
}



/* CONTEXT / separate function: adjacent_9ac680 @ 0x9ac680; ev_5c0de0968c741bdbc35847d7f189e95a4c17c1403c7c32bbd66b1375fafb1be2
 * Ghidra body ranges: 0x9ac680..0x9ac987
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int adjacent_9ac680(long *param_1,long param_2,long *param_3)

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



/* CONTEXT / separate function: adjacent_9ac990 @ 0x9ac990; ev_cc8b9abf2a640bcd034bda9bf91cde04ad8e1a28ea24fb2b6d6b5a0fff43a29a
 * Ghidra body ranges: 0x9ac990..0x9ac99a
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_9ac990(void)

{
  return 0x2d;
}



/* CONTEXT / separate function: adjacent_9ac9a0 @ 0x9ac9a0; ev_64c31f29acd7a5e99b9993f4f3bb61c1554cc4c61bf5e113e8e15cd0705e5efa
 * Ghidra body ranges: 0x9ac9a0..0x9ac9aa
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_9ac9a0(void)

{
  return 0x2d;
}



/* CONTEXT / separate function: adjacent_9ac9b0 @ 0x9ac9b0; ev_693e624576a0abe8155443b83ab1ba4af4e766fd961780b90cf293bf3db56d9f
 * Ghidra body ranges: 0x9ac9b0..0x9aca13
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_9ac9b0(long *param_1,long param_2)

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



/* CONTEXT / separate function: adjacent_9aca3c @ 0x9aca3c; ev_4fc02718d3a9c75544d7a0a2a3cf49e61dfe360ce6df343a5edcf315f9cb0ba0
 * Ghidra body ranges: 0x9aca3c..0x9aca48
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_9aca3c(void)

{
  func_0x009a7c00();
  return 0;
}



/* CONTEXT / separate function: adjacent_9aca50 @ 0x9aca50; ev_f86fc823e531dbdd8e5b8fa3181db11fc3f93b39a84f2d7455400508d8a7d702
 * Ghidra body ranges: 0x9aca50..0x9aca5e
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_9aca50(undefined8 param_1,long param_2)

{
  *(undefined4 *)(param_2 + 4) = 0xff;
  return 0;
}



/* CONTEXT / separate function: adjacent_9aca60 @ 0x9aca60; ev_671702526a8c84af736b240291f59f651bbb768cd4e1561f4d9c1796cab0f1a5
 * Ghidra body ranges: 0x9aca60..0x9acc0b
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

int adjacent_9aca60(undefined8 *param_1,undefined8 param_2,ulong *param_3,ulong param_4,
                   ushort param_5,ushort param_6,uint param_7,long param_8,long param_9)

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



/* CONTEXT / separate function: FUN_009acc10 @ 0x9acc10; ev_02109c8e45caef6584ebfa2e81cc6d7591fbab7a85683d78ce1ed00dd4320067
 * Ghidra body ranges: 0x9acc10..0x9acc21
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined4 FUN_009acc10(uint param_1)

{
  code *pcVar1;
  
  if (param_1 < 0x15) {
    return *(undefined4 *)((ulong)param_1 * 4 + 0x18cdbb4);
  }
  func_0x007f1950();
  func_0x007f18a0(adjacent_9acc22,(long)(int)param_1);
  func_0x00c9aa10(7,0x12947a2,param_1);
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* CONTEXT / separate function: adjacent_9acc22 @ 0x9acc22; ev_5c42af15d271be0784776ce5d639508a3302c66726505999ab160d53c4537d7f
 * Ghidra body ranges: 0x9acc22..0x9acc54
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void adjacent_9acc22(int param_1)

{
  code *pcVar1;
  
  func_0x007f1950();
  func_0x007f18a0(adjacent_9acc22,(long)param_1);
  func_0x00c9aa10(7,0x12947a2,param_1);
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* CONTEXT / separate function: adjacent_9acc60 @ 0x9acc60; ev_754f9c4ac5c74dfba6091d781301a74d07851ba4d719121898cf6b7f5f2f7a9a
 * Ghidra body ranges: 0x9acc60..0x9accd2
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void adjacent_9acc60(void)

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



/* CONTEXT / separate function: adjacent_9accec @ 0x9accec; ev_8ebfe47970b96e905be52757f1385f6068b50897703d50ea9cb4189d14d40575
 * Ghidra body ranges: 0x9accec..0x9acd37
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void adjacent_9accec(void)

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



/* CONTEXT / separate function: adjacent_9acd40 @ 0x9acd40; ev_952a04209428d3c66c39ba5a3da38cacad5b89d1151e6d4b576700d1102e33e8
 * Ghidra body ranges: 0x9acd40..0x9acddf
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void adjacent_9acd40(long param_1,int param_2)

{
  long lVar1;
  int iVar2;
  
  if (param_2 == -1) {
    param_2 = 0x23;
  }
  else {
    iVar2 = adjacent_9ad320(param_1);
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



/* CONTEXT / separate function: adjacent_9acde0 @ 0x9acde0; ev_9ce9985e54da547ac1f9b6a3c02864cec08731da95abc30d3d4d967e3cd7d04b
 * Ghidra body ranges: 0x9acde0..0x9ad02b
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong adjacent_9acde0(long param_1,undefined8 param_2,undefined8 param_3)

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



/* CONTEXT / separate function: adjacent_9ad030 @ 0x9ad030; ev_75d77823cd6313863d46fc937f963fb349b68c781a7a0898e15271626b5424d9
 * Ghidra body ranges: 0x9ad030..0x9ad318
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void adjacent_9ad030(long *param_1,undefined4 param_2)

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
        uVar6 = adjacent_9acde0(lVar1,plVar10,&local_3c);
        if (uVar6 == 0) {
          iVar7 = func_0x005b01d0(0x26a580,plVar8,&local_3c,1);
          if (iVar7 != 0) {
            func_0x0025d410(0x12d95db,0x12b97ff,iVar7,local_3c);
            adjacent_9ad490(plVar8,local_3c);
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
  adjacent_9acd40(lVar1,uVar6);
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



/* CONTEXT / separate function: adjacent_9ad320 @ 0x9ad320; ev_5a60665465574e9c4e32e96c58b09a1b56515d80c4176f4690e0038918f69a03
 * Ghidra body ranges: 0x9ad320..0x9ad483
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

bool adjacent_9ad320(long param_1)

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



/* CONTEXT / separate function: adjacent_9ad490 @ 0x9ad490; ev_b9b9bb60e8c44064ff52e3283de451ace0b9c3e8226486485c67ec4db1536250
 * Ghidra body ranges: 0x9ad490..0x9ad55d
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void adjacent_9ad490(long *param_1,undefined4 param_2)

{
  long lVar1;
  uint uVar2;
  undefined8 uVar3;
  int iVar4;
  undefined8 uVar5;
  undefined4 local_40;
  ushort local_3a;
  undefined8 local_38;
  
  local_38 = _DAT_0391c310;
  lVar1 = *param_1;
  local_3a = 0;
  local_40 = 0;
  iVar4 = 0x21c1;
  if (*(int *)(lVar1 + 0x198) != 0) {
    iVar4 = *(int *)(lVar1 + 0x198);
  }
  func_0x005f0f70(iVar4);
  uVar2 = func_0x0068e1a0(param_2,&local_3a,&local_40,0);
  if (uVar2 == 0) {
    func_0x00c08df0(param_1,0x255ffd0);
    uVar2 = (uint)local_3a;
    if (local_3a == 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    uVar5 = 0x13079f2;
    uVar3 = 0x13b0051;
    param_2 = local_40;
  }
  else {
    uVar5 = 0x1384734;
    uVar3 = 0x132c586;
  }
  func_0x0025d410(uVar5,uVar3,uVar2,param_2);
  *(long *)(lVar1 + 0x50) = *(long *)(lVar1 + 0x128);
  if (*(long *)(lVar1 + 0x128) != 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* CONTEXT / separate function: adjacent_be6f60 @ 0xbe6f60; ev_a486a9723106f0b331e4e26155701db5e890530c756026993773b0e7cbd2c6df
 * Ghidra body ranges: 0xbe6f60..0xbe7232
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void adjacent_be6f60(long param_1,long param_2)

{
  long lVar1;
  code *pcVar2;
  long *plVar3;
  long lVar4;
  long lVar5;
  undefined8 uVar6;
  undefined8 uVar7;
  undefined8 uVar8;
  long *plVar9;
  
  if (*(long *)(param_1 + 0xe0) != param_2) {
    func_0x004c6a00(*(long *)(param_1 + 0xe0) + 0x148,0,0);
    func_0x0055c390(*(undefined8 *)(param_1 + 0x1b0));
    func_0x004c6fa0(*(long *)(param_1 + 0xe0) + 0x148,0,0);
    lVar5 = *(long *)(param_1 + 0xe8);
    plVar9 = (long *)(param_1 + 0xe8);
    if (lVar5 == 0) {
      plVar3 = *(long **)(param_1 + 0xf0);
      if (*plVar3 != param_1) {
LAB_00be7140:
        func_0x007f1950();
        func_0x007f20c0(0xbe7140,param_1,*(undefined8 **)(param_1 + 0xf0),
                        **(undefined8 **)(param_1 + 0xf0));
        func_0x00c9aa10(0x57,0x138cc1e,param_1,*(undefined8 **)(param_1 + 0xf0),
                        **(undefined8 **)(param_1 + 0xf0));
                    /* WARNING: Does not return */
        pcVar2 = (code *)invalidInstructionException();
        (*pcVar2)();
      }
      lVar5 = 0;
    }
    else {
      if (*(long **)(lVar5 + 0xf0) != plVar9) {
        func_0x007f1950();
        func_0x007f2180(0xbe7180,param_1,*(long *)(param_1 + 0xe8),
                        *(undefined8 *)(*(long *)(param_1 + 0xe8) + 0xf0),plVar9);
        lVar5 = *(long *)(param_1 + 0xe8);
        uVar6 = 0x1288932;
        uVar7 = 0x53;
        uVar8 = *(undefined8 *)(lVar5 + 0xf0);
        goto LAB_00be722a;
      }
      if (**(long **)(param_1 + 0xf0) != param_1) goto LAB_00be7140;
      *(long **)(lVar5 + 0xf0) = *(long **)(param_1 + 0xf0);
      lVar5 = *(long *)(param_1 + 0xe8);
      plVar3 = *(long **)(param_1 + 0xf0);
    }
    *plVar3 = lVar5;
    lVar5 = *(long *)(param_2 + 0xf8);
    *plVar9 = lVar5;
    if (lVar5 != 0) {
      *(long **)(lVar5 + 0xf0) = plVar9;
    }
    *(long *)(param_2 + 0xf8) = param_1;
    *(long **)(param_1 + 0xf0) = (long *)(param_2 + 0xf8);
    adjacent_be8160(param_1);
    if ((*(byte *)(param_1 + 0xb1) & 8) != 0) {
      lVar4 = *(long *)(param_1 + 0xe0);
      lVar5 = *(long *)(lVar4 + 0xc40);
      if (lVar5 == 0) {
        *(byte *)(param_1 + 0x3c8) = *(byte *)(param_1 + 0x3c8) | 2;
        lVar5 = *(long *)(lVar4 + 0xc40);
        *(long *)(param_1 + 0xc30) = lVar5;
        if (lVar5 != 0) {
          *(long *)(lVar5 + 0xc38) = param_1 + 0xc30;
          lVar4 = *(long *)(param_1 + 0xe0);
        }
        *(long *)(lVar4 + 0xc40) = param_1;
        lVar5 = *(long *)(param_1 + 0xe0) + 0xc40;
      }
      else {
        lVar1 = *(long *)(lVar5 + 0xc30);
        if (lVar1 == 0) {
          *(undefined8 *)(param_1 + 0xc30) = 0;
        }
        else {
          if (*(long *)(lVar1 + 0xc38) != lVar5 + 0xc30) {
            func_0x007f1950();
            lVar5 = *(long *)(*(long *)(param_1 + 0xe0) + 0xc40);
            func_0x007f2180(0xbe71c7,lVar5,*(long *)(lVar5 + 0xc30),
                            *(undefined8 *)(*(long *)(lVar5 + 0xc30) + 0xc38),lVar5 + 0xc30);
            uVar6 = 0x13a1f68;
            uVar7 = 0x5b;
            param_1 = *(long *)(*(long *)(param_1 + 0xe0) + 0xc40);
            lVar5 = *(long *)(param_1 + 0xc30);
            plVar9 = (long *)(param_1 + 0xc30);
            uVar8 = *(undefined8 *)(lVar5 + 0xc38);
LAB_00be722a:
            func_0x00c9aa10(uVar7,uVar6,param_1,lVar5,uVar8,plVar9);
                    /* WARNING: Does not return */
            pcVar2 = (code *)invalidInstructionException();
            (*pcVar2)();
          }
          *(long *)(param_1 + 0xc30) = lVar1;
          *(long *)(*(long *)(*(long *)(lVar4 + 0xc40) + 0xc30) + 0xc38) = param_1 + 0xc30;
          lVar4 = *(long *)(param_1 + 0xe0);
        }
        *(long *)(*(long *)(lVar4 + 0xc40) + 0xc30) = param_1;
        lVar5 = *(long *)(*(long *)(param_1 + 0xe0) + 0xc40) + 0xc30;
      }
      *(long *)(param_1 + 0xc38) = lVar5;
      *(byte *)(param_1 + 0x3c8) = *(byte *)(param_1 + 0x3c8) | 1;
    }
    *(long *)(param_1 + 0xe0) = param_2;
  }
  return;
}



/* CONTEXT / separate function: adjacent_be7240 @ 0xbe7240; ev_92d0cd90921789bb51ffb7bd0ebca20e2bbd10c93166265d060eb5e9565d2971
 * Ghidra body ranges: 0xbe7240..0xbe7346
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_be7240(long param_1,undefined4 *param_2)

{
  long lVar1;
  long lVar2;
  code *pcVar3;
  int iVar4;
  long *in_GS_OFFSET;
  
  lVar2 = *(long *)(param_1 + 8);
  lVar1 = lVar2 + 0x5e4;
  func_0x0025d410(0x12b1959,*(undefined4 *)(lVar2 + 0xbc),lVar1,*param_2);
  iVar4 = func_0x0026b9b0(lVar1,0x135853f);
  if (iVar4 == 0) {
    if (param_1 == *in_GS_OFFSET) {
      func_0x0025d410(0x132481a,*(undefined4 *)(param_1 + 0x9c));
      func_0x0025d410(0x13048f1,param_1 + 0x294);
    }
    func_0x0025d410(0x1363886,*(undefined4 *)(lVar2 + 0xbc));
    func_0x0025d410(0x139719b,lVar1);
    func_0x00a0b2c0(param_1);
    func_0x004f6050(param_1,1);
  }
  if ((*(byte *)(lVar2 + 0x464) & 1) != 0) {
    iVar4 = func_0x00acce10();
    if (iVar4 == 0) {
      iVar4 = func_0x00acce50();
      if (iVar4 == 0) {
        func_0x0055fba0(lVar2,0xc);
        return 0;
      }
    }
  }
  func_0x00c9b6b0(param_1);
  adjacent_be7350(param_1,*param_2,0);
                    /* WARNING: Does not return */
  pcVar3 = (code *)invalidInstructionException();
  (*pcVar3)();
}



/* CONTEXT / separate function: adjacent_be7350 @ 0xbe7350; ev_ae2d37e67b789083dee3c63e8919aed3e5007fbfb50301b8635d543c3018b1fc
 * Ghidra body ranges: 0xbe7350..0xbe765d, 0xbe7660..0xbe77d5, 0xbe77e0..0xbe797a, 0xbe7980..0xbe7a16, 0xbe7a20..0xbe7c54, 0xbe7c60..0xbe7d26, 0xbe7d30..0xbe7dc5, 0xbe7dd0..0xbe8157
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void adjacent_be7350(long *param_1,undefined4 param_2,uint param_3)

{
  long *plVar1;
  uint uVar2;
  long *plVar3;
  long lVar4;
  code *pcVar5;
  int iVar6;
  long lVar7;
  long *plVar8;
  long lVar9;
  undefined8 *puVar10;
  char cVar11;
  undefined8 uVar12;
  undefined8 uVar13;
  undefined8 uVar14;
  long *plVar15;
  long *in_GS_OFFSET;
  
  plVar3 = (long *)param_1[1];
  if ((plVar3 == _DAT_03588730) && (_DAT_03a35178 == 0)) {
    func_0x0025d410(0x12f00c9,param_3,param_2);
    func_0x007f1950();
    func_0x007f1810(0xbe7394);
    func_0x00c9aa10(0x23,0x132482b);
                    /* WARNING: Does not return */
    pcVar5 = (code *)invalidInstructionException();
    (*pcVar5)();
  }
  func_0x004c78b0(param_1,0,0x12d0f66);
  if (0xff < *(ushort *)(param_1 + 0x79)) {
    func_0x006b6830(param_1,0xff);
  }
  func_0x004c7520(*param_1 + 0x18,0,0);
  if (_DAT_03543950 != (code *)0x0) {
    (*_DAT_03543950)();
  }
  plVar1 = plVar3 + 0x29;
  func_0x004c6a00(plVar1,0,0);
  do {
    func_0x00b91a90(0);
    if ((*(byte *)(plVar3 + 0x16) & 0x80) == 0) break;
    iVar6 = func_0x00b911e0(plVar3,1);
  } while (iVar6 != 0);
  *(undefined4 *)((long)plVar3 + 0xa2c) = param_2;
  *(uint *)(plVar3 + 0x146) = param_3;
  if ((*(byte *)(plVar3 + 0x6f) & 0x20) != 0) {
    func_0x00a36730(plVar3,0x20,0);
  }
  *(uint *)(plVar3 + 0x16) = *(uint *)(plVar3 + 0x16) & 0xfffddfff | 0x2000;
  func_0x00c06910((long)plVar3 + 0x37c);
  if ((int)plVar3[0x6b] != 0) {
    do {
      func_0x00c06260(plVar3 + 0x6b,plVar3 + 0x26,0x5c,0x1319ca4,0,0,0x100);
    } while ((int)plVar3[0x6b] != 0);
  }
  func_0x004c6fa0(plVar1,0,0);
  func_0x00b9afd0(plVar3 + 0xd,1,0);
  if ((*(byte *)(*in_GS_OFFSET + 0xef) & 1) != 0) {
    func_0x00444040(param_2,0);
  }
  if ((*(byte *)((long)param_1 + 0xef) & 1) != 0) {
    func_0x003d4340(0,param_1);
  }
  if ((plVar3[0x176] != 0) && (plVar3 == (long *)plVar3[0x177])) {
    func_0x004c6a00(0x3589e00,0,0);
    lVar7 = plVar3[0x176];
    if (lVar7 != 0) {
      do {
        func_0x004c6a00(lVar7 + 0x148,0,0);
        func_0x0055fba0(lVar7);
        func_0x004c6fa0(lVar7 + 0x148,0,0);
        lVar7 = *(long *)(lVar7 + 0xbb0);
      } while (lVar7 != 0);
      lVar7 = plVar3[0x176];
      while (lVar7 != 0) {
        func_0x00c06260(plVar3,0x3589de8,0x5c,0x12fa088,0,0,0x100);
        lVar7 = plVar3[0x176];
      }
    }
    func_0x004c6fa0(0x3589e00,0,0);
  }
  func_0x0037dca0(param_1);
  func_0x005a8370(plVar3);
  lVar7 = func_0x0073e2e0(0x12e769e);
  if (lVar7 != 0) {
    iVar6 = *(int *)(lVar7 + 0xc);
    *(int *)(lVar7 + 0xc) = iVar6 + 1;
    plVar15 = *(long **)(lVar7 + 0x40);
    if (plVar15 != (long *)0x0) {
      do {
        if ((int)plVar15[2] != -1) {
          func_0x004c6fa0(lVar7 + 0x28,0,0);
          (*(code *)plVar15[5])(plVar15[3]);
          func_0x004c6a00(lVar7 + 0x28,0,0);
        }
        plVar15 = (long *)*plVar15;
      } while (plVar15 != (long *)0x0);
      iVar6 = *(int *)(lVar7 + 0xc) + -1;
    }
    *(int *)(lVar7 + 0xc) = iVar6;
    if (iVar6 == 0) {
      func_0x0073e370(lVar7);
    }
    func_0x004c6fa0(lVar7 + 0x28,0,0);
  }
  func_0x00b27ad0(plVar3);
  func_0x00b2b220();
  func_0x004c6a00(plVar1,0,0);
  func_0x00c66dc0(plVar3);
  *(uint *)(plVar3 + 0x16) = *(uint *)(plVar3 + 0x16) & 0x7ffff7ef;
  if ((plVar3[0x44] != 0) || (plVar3[0x45] != 0)) {
    iVar6 = func_0x00b9afd0(plVar3 + 0x16d,2,0);
    if (iVar6 == 0) {
      plVar3[0x43] = 0;
      plVar3[0x42] = 0;
      func_0x00c06260(plVar3 + 0x16d,plVar3 + 0x26,0x5c,0x12c642b,0,0,0x100);
    }
  }
  func_0x004c6fa0(plVar1,0,0);
  func_0x0037ed80(param_1);
  func_0x0072bad0(plVar3 + 0x6c);
  func_0x0072d280(param_1);
  iVar6 = func_0x005a83f0(plVar3,5);
  if (0 < iVar6) {
    func_0x0025d410(0x12c6433,iVar6);
  }
  lVar7 = func_0x0073e2e0(0x1276a25);
  if (lVar7 != 0) {
    iVar6 = *(int *)(lVar7 + 0xc);
    *(int *)(lVar7 + 0xc) = iVar6 + 1;
    plVar15 = *(long **)(lVar7 + 0x40);
    if (plVar15 != (long *)0x0) {
      do {
        if ((int)plVar15[2] != -1) {
          func_0x004c6fa0(lVar7 + 0x28,0,0);
          (*(code *)plVar15[5])(plVar15[3]);
          func_0x004c6a00(lVar7 + 0x28,0,0);
        }
        plVar15 = (long *)*plVar15;
      } while (plVar15 != (long *)0x0);
      iVar6 = *(int *)(lVar7 + 0xc) + -1;
    }
    *(int *)(lVar7 + 0xc) = iVar6;
    if (iVar6 == 0) {
      func_0x0073e370(lVar7);
    }
    func_0x004c6fa0(lVar7 + 0x28,0,0);
  }
  if ((*(byte *)((long)param_1 + 0xee) & 1) != 0) {
    func_0x007ba890();
  }
  if (*(long *)(plVar3[0x177] + 0xbb0) != 0) {
    func_0x004c6a00(0x3589e00,0,0);
    plVar15 = (long *)plVar3[0x177];
    if (((long *)plVar3[0x177])[0x176] != 0) {
      do {
        plVar8 = plVar15;
        plVar15 = (long *)plVar8[0x176];
      } while (plVar15 != plVar3);
      plVar8[0x176] = plVar3[0x176];
      func_0x00c06910(plVar3[0x177]);
    }
    func_0x004c6fa0(0x3589e00,0,0);
  }
  lVar7 = plVar3[0x40];
  func_0x002d3820(lVar7);
  func_0x002c6480(lVar7,0,0);
  iVar6 = *(int *)(lVar7 + 0x1ec);
  if (iVar6 != -1) {
    func_0x002c9370(lVar7,*(undefined8 *)(lVar7 + 0x20),*(undefined8 *)(lVar7 + 0x28));
    if ((*(byte *)(lVar7 + 0x244) & 1) == 0) {
      iVar6 = func_0x009ebe80(plVar3);
      if (iVar6 != 0) {
        func_0x0025d410(0x12932ff,*(undefined4 *)((long)plVar3 + 0xbc),iVar6);
      }
    }
    else {
      (**(code **)(_DAT_01a962e8 + 8))(iVar6);
    }
  }
  func_0x002c64f0(lVar7,0,0);
  lVar7 = func_0x0073e2e0(0x131bf16);
  if (lVar7 != 0) {
    iVar6 = *(int *)(lVar7 + 0xc);
    *(int *)(lVar7 + 0xc) = iVar6 + 1;
    plVar15 = *(long **)(lVar7 + 0x40);
    if (plVar15 != (long *)0x0) {
      do {
        if ((int)plVar15[2] != -1) {
          func_0x004c6fa0(lVar7 + 0x28,0,0);
          (*(code *)plVar15[5])(plVar15[3]);
          func_0x004c6a00(lVar7 + 0x28,0,0);
        }
        plVar15 = (long *)*plVar15;
      } while (plVar15 != (long *)0x0);
      iVar6 = *(int *)(lVar7 + 0xc) + -1;
    }
    *(int *)(lVar7 + 0xc) = iVar6;
    if (iVar6 == 0) {
      func_0x0073e370(lVar7);
    }
    func_0x004c6fa0(lVar7 + 0x28,0,0);
  }
  func_0x002c62a0(param_1);
  lVar7 = func_0x0073e2e0(0x12b4067);
  if (lVar7 != 0) {
    iVar6 = *(int *)(lVar7 + 0xc);
    *(int *)(lVar7 + 0xc) = iVar6 + 1;
    plVar15 = *(long **)(lVar7 + 0x40);
    if (plVar15 != (long *)0x0) {
      do {
        if ((int)plVar15[2] != -1) {
          func_0x004c6fa0(lVar7 + 0x28,0,0);
          (*(code *)plVar15[5])(plVar15[3]);
          func_0x004c6a00(lVar7 + 0x28,0,0);
        }
        plVar15 = (long *)*plVar15;
      } while (plVar15 != (long *)0x0);
      iVar6 = *(int *)(lVar7 + 0xc) + -1;
    }
    *(int *)(lVar7 + 0xc) = iVar6;
    if (iVar6 == 0) {
      func_0x0073e370(lVar7);
    }
    func_0x004c6fa0(lVar7 + 0x28,0,0);
  }
  func_0x0053cdd0();
  func_0x00bfc7a0(param_1);
  iVar6 = func_0x00b07920();
  if (iVar6 != 0) {
    func_0x0002e8a0(param_1);
  }
  if (plVar3[0x6a] != 0) {
    func_0x0054a120();
    plVar3[0x6a] = 0;
  }
  func_0x004a1140(plVar3[0xc]);
  plVar3[0xc] = 0;
  func_0x00b92720(param_1);
  func_0x00c4bb20(0x3589e60,0,0);
  lVar7 = *plVar3;
  if (lVar7 == 0) {
    plVar15 = (long *)plVar3[1];
    if ((long *)*plVar15 != plVar3) {
LAB_00be7b65:
      func_0x007f1950();
      func_0x007f20c0(0xbe7b65,plVar3,(undefined8 *)plVar3[1],*(undefined8 *)plVar3[1]);
      puVar10 = (undefined8 *)plVar3[1];
      uVar12 = 0x1308037;
      uVar13 = 0x2b;
      goto LAB_00be7f02;
    }
    lVar7 = 0;
  }
  else {
    if (*(long **)(lVar7 + 8) != plVar3) {
      func_0x007f1950();
      func_0x007f2180(0xbe7b95,plVar3,*plVar3,*(undefined8 *)(*plVar3 + 8),plVar3);
      lVar7 = *plVar3;
      uVar13 = 0x1366e8e;
      uVar14 = 0x27;
      uVar12 = *(undefined8 *)(lVar7 + 8);
      plVar15 = plVar3;
      goto LAB_00be7f56;
    }
    if (*(long **)plVar3[1] != plVar3) goto LAB_00be7b65;
    *(undefined8 **)(lVar7 + 8) = (undefined8 *)plVar3[1];
    lVar7 = *plVar3;
    plVar15 = (long *)plVar3[1];
  }
  *plVar15 = lVar7;
  *plVar3 = (long)_DAT_03589e08;
  if (_DAT_03589e08 != (long *)0x0) {
    _DAT_03589e08[1] = (long)plVar3;
  }
  _DAT_03589e08 = plVar3;
  plVar3[1] = (long)&DAT_03589e08;
  lVar7 = plVar3[0x18];
  if (lVar7 == 0) {
    plVar15 = (long *)plVar3[0x19];
    if ((long *)*plVar15 != plVar3) {
LAB_00be7ed1:
      func_0x007f1950();
      func_0x007f20c0(0xbe7ed1,plVar3,(undefined8 *)plVar3[0x19],*(undefined8 *)plVar3[0x19]);
      puVar10 = (undefined8 *)plVar3[0x19];
      uVar12 = 0x12db88b;
      uVar13 = 0x33;
LAB_00be7f02:
      func_0x00c9aa10(uVar13,uVar12,plVar3,puVar10,*puVar10);
                    /* WARNING: Does not return */
      pcVar5 = (code *)invalidInstructionException();
      (*pcVar5)();
    }
    lVar7 = 0;
  }
  else {
    plVar15 = plVar3 + 0x18;
    if (*(long **)(lVar7 + 200) != plVar15) {
      func_0x007f1950();
      func_0x007f2180(0xbe7f11,plVar3,plVar3[0x18],*(undefined8 *)(plVar3[0x18] + 200),plVar15);
      lVar7 = plVar3[0x18];
      uVar13 = 0x130f2e0;
      uVar14 = 0x2f;
      uVar12 = *(undefined8 *)(lVar7 + 200);
LAB_00be7f56:
      func_0x00c9aa10(uVar14,uVar13,plVar3,lVar7,uVar12,plVar15);
                    /* WARNING: Does not return */
      pcVar5 = (code *)invalidInstructionException();
      (*pcVar5)();
    }
    if (*(long **)plVar3[0x19] != plVar3) goto LAB_00be7ed1;
    *(undefined8 **)(lVar7 + 200) = (undefined8 *)plVar3[0x19];
    lVar7 = plVar3[0x18];
    plVar15 = (long *)plVar3[0x19];
  }
  *plVar15 = lVar7;
  func_0x00c4c4b0(0x3589e60,0,0);
  func_0x00a50e90(param_1);
  func_0x00c4bb20(0x3589e40,0,0,0);
  lVar7 = plVar3[0x1f];
  if (lVar7 != 0) {
    func_0x00c06910(*(undefined8 *)(lVar7 + 0x100));
    do {
      lVar4 = *(long *)(lVar7 + 0xe8);
      func_0x004c6a00(lVar7 + 0x148,0,0,0);
      *(undefined4 *)(lVar7 + 0x368) = 0x14;
      if ((*(byte *)(lVar7 + 0xb1) & 8) == 0) {
        adjacent_be6f60(lVar7);
      }
      else {
        if ((*(uint *)(lVar7 + 0x3c8) & 1) == 0) {
          if ((*(int *)(lVar7 + 0x1f8) == 0) ||
             (puVar10 = (undefined8 *)&DAT_03588730,
             *(int *)(*(long *)(lVar7 + 0xe0) + 0xbc) == *(int *)(lVar7 + 0x1f8))) {
            puVar10 = (undefined8 *)(lVar7 + 0xe0);
          }
          plVar15 = (long *)*puVar10;
          if (plVar15 == plVar3) goto LAB_00be7d6d;
LAB_00be7cf6:
          func_0x004c6a00(plVar15 + 0x29,0,0,0);
          adjacent_be6f60(lVar7,plVar15);
          func_0x004c6fa0(plVar15 + 0x29,0,0);
        }
        else {
          lVar9 = lVar7;
          if ((*(uint *)(lVar7 + 0x3c8) & 2) == 0) {
            do {
              plVar15 = (long *)(lVar9 + 0xc38);
              lVar9 = *plVar15 + -0xc30;
            } while ((*(byte *)(*plVar15 + -0x868) & 2) == 0);
          }
          plVar15 = (long *)(*(long *)(lVar9 + 0xc38) + -0xc40);
          if (plVar15 != plVar3) goto LAB_00be7cf6;
LAB_00be7d6d:
          adjacent_be6f60(lVar7,*(undefined8 *)(lVar7 + 0x100));
        }
        adjacent_be8160(lVar7);
        *(uint *)(lVar7 + 0xb0) = *(uint *)(lVar7 + 0xb0) & 0xfffbf7ff;
        for (lVar9 = *(long *)(lVar7 + 0x10); lVar9 != 0; lVar9 = *(long *)(lVar9 + 0x10)) {
          *(byte *)(lVar9 + 0x2c0) = *(byte *)(lVar9 + 0x2c0) & 0xfe;
        }
        func_0x0055fba0(lVar7);
      }
      func_0x004c6fa0(lVar7 + 0x148,0,0);
      lVar7 = lVar4;
    } while (lVar4 != 0);
  }
  while (lVar7 = plVar3[0x188], lVar7 != 0) {
    func_0x004c6a00(lVar7 + 0x148,0,0,0);
    adjacent_be8160(lVar7);
    func_0x004c6fa0(lVar7 + 0x148,0,0);
  }
  func_0x004c6a00(plVar1,0,0,0);
  plVar3[0x75] = (long)param_1;
  adjacent_be9ca0(*(undefined8 *)(plVar3[8] + 0x30));
  if (_DAT_03d96b68 != (code *)0x0) {
    (*_DAT_03d96b68)(plVar3);
  }
  func_0x00313d50(plVar3[0x168],0x80000000,1);
  cVar11 = '\x03';
  if (-1 < (char)param_3) {
    cVar11 = '\x01';
    if ((param_3 & 0x7f) != 0x7f) {
      cVar11 = (param_3 != 0x13 && (param_3 & 0x7f) != 0) + '\x01';
    }
  }
  if (_DAT_02bf4828 == 0) {
    lVar7 = plVar3[0x78];
  }
  else {
    (*_DAT_01a9bf28)(_DAT_02bf4828,cVar11,0,0,0,0);
    lVar7 = plVar3[0x78];
  }
  if ((lVar7 != 0) && (iVar6 = func_0x00c34a40(plVar3), iVar6 == 0)) {
    func_0x004c6a00(plVar3[0x1c] + 0x148,0,0,0);
    goto LAB_00be807d;
  }
  func_0x004c6a00(plVar3[0x1c] + 0x148,0,0,0);
  func_0x004c6a00(*(long *)(plVar3[0x1c] + 0xa8) + 0xcc0,0,0,0);
  uVar2 = *(uint *)(*(long *)(plVar3[0x1c] + 0xa8) + 0xca0);
  func_0x004c6fa0(*(long *)(plVar3[0x1c] + 0xa8) + 0xcc0,0,0,0);
  if ((uVar2 & 5) != 0) {
    lVar7 = plVar3[0x1c];
    func_0x004c6fa0(lVar7 + 0x148,0,0,0);
    adjacent_be6f60(plVar3,plVar3[0x20]);
    *(undefined4 *)(plVar3 + 0x6d) = 0x14;
    func_0x004c6a00(plVar3[0x1c] + 0x148,0,0,0);
    func_0x00c06910(lVar7);
  }
  if (((long *)plVar3[0x1c] != (long *)plVar3[0x20]) && ((long *)plVar3[0x1c] != _DAT_03588730)) {
    if ((int)plVar3[0x6d] == 0) goto LAB_00be807d;
    if ((int)plVar3[0x6d] != 0x14) {
      func_0x0055fba0();
      goto LAB_00be807d;
    }
  }
  adjacent_562030(plVar3);
LAB_00be807d:
  func_0x00c4c4b0(0x3589e40,0,0);
  func_0x0055c4e0(plVar3 + 0x37);
  func_0x0055c4e0(param_1 + 0x14);
  func_0x00c06910(plVar3[0x1c]);
  func_0x0073f010(plVar3 + 0x17e,0);
  func_0x006b5410(plVar3[0x1c],param_1);
  func_0x004c7190(plVar3 + 7,0,0,0);
  *(undefined4 *)(plVar3 + 0x17) = 2;
  func_0x004c6fa0(plVar3[0x1c] + 0x148,0,0,0);
  func_0x004c7190(plVar3 + 0x2d,0,0,0);
  func_0x004a1e50(plVar3 + 0x46,plVar3 + 0x58,plVar3[0xb],plVar3 + 0x5f);
  func_0x004c7520(plVar3 + 0x2d,0,0,0);
  func_0x00b90cf0();
                    /* WARNING: Does not return */
  pcVar5 = (code *)invalidInstructionException();
  (*pcVar5)();
}



/* CONTEXT / separate function: adjacent_be8160 @ 0xbe8160; ev_d05f994c43a4c72873e5f47ae3e44fab31004caf5f261bfcbbe04f94fa0e13a0
 * Ghidra body ranges: 0xbe8160..0xbe828e
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void adjacent_be8160(long param_1)

{
  byte *pbVar1;
  long lVar2;
  code *pcVar3;
  uint uVar4;
  long *plVar5;
  long lVar6;
  
  uVar4 = *(uint *)(param_1 + 0x3c8);
  if ((uVar4 & 1) != 0) {
    if ((uVar4 & 2) != 0) {
      if (*(long *)(param_1 + 0xc30) != 0) {
        pbVar1 = (byte *)(*(long *)(param_1 + 0xc30) + 0x3c8);
        *pbVar1 = *pbVar1 | 2;
        uVar4 = *(uint *)(param_1 + 0x3c8);
      }
      *(uint *)(param_1 + 0x3c8) = uVar4 & 0xfffffffd;
    }
    lVar6 = *(long *)(param_1 + 0xc30);
    if (lVar6 == 0) {
      plVar5 = *(long **)(param_1 + 0xc38);
      if (*plVar5 != param_1) goto LAB_00be81fb;
      lVar6 = 0;
    }
    else {
      lVar2 = param_1 + 0xc30;
      if (*(long *)(lVar6 + 0xc38) != lVar2) {
        func_0x007f1950();
        func_0x007f2180(0xbe823e,param_1,*(long *)(param_1 + 0xc30),
                        *(undefined8 *)(*(long *)(param_1 + 0xc30) + 0xc38),lVar2);
        func_0x00c9aa10(0x1b,0x13a1f68,param_1,*(long *)(param_1 + 0xc30),
                        *(undefined8 *)(*(long *)(param_1 + 0xc30) + 0xc38),lVar2);
                    /* WARNING: Does not return */
        pcVar3 = (code *)invalidInstructionException();
        (*pcVar3)();
      }
      if (**(long **)(param_1 + 0xc38) != param_1) {
LAB_00be81fb:
        func_0x007f1950();
        func_0x007f20c0(0xbe81fb,param_1,*(undefined8 **)(param_1 + 0xc38),
                        **(undefined8 **)(param_1 + 0xc38));
        func_0x00c9aa10(0x1f,0x13971ac,param_1,*(undefined8 **)(param_1 + 0xc38),
                        **(undefined8 **)(param_1 + 0xc38));
                    /* WARNING: Does not return */
        pcVar3 = (code *)invalidInstructionException();
        (*pcVar3)();
      }
      *(long **)(lVar6 + 0xc38) = *(long **)(param_1 + 0xc38);
      lVar6 = *(long *)(param_1 + 0xc30);
      plVar5 = *(long **)(param_1 + 0xc38);
    }
    *plVar5 = lVar6;
    *(byte *)(param_1 + 0x3c8) = *(byte *)(param_1 + 0x3c8) & 0xfe;
  }
  return;
}



/* CONTEXT / separate function: adjacent_be8290 @ 0xbe8290; ev_48af8f6f403d38897b19792d209f506ef02bab91cfa9957eab26f2e5b607a72b
 * Ghidra body ranges: 0xbe8290..0xbe8470
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong adjacent_be8290(long param_1,uint *param_2)

{
  long lVar1;
  code *pcVar2;
  int iVar3;
  uint uVar4;
  ulong uVar5;
  undefined8 uVar6;
  undefined8 *in_GS_OFFSET;
  undefined4 local_1ec;
  undefined1 local_1e8 [144];
  undefined1 local_158 [288];
  long local_38;
  
  local_38 = _DAT_0391c310;
  iVar3 = func_0x00608f90(*(undefined8 *)(param_1 + 0x140));
  if (iVar3 == 0) {
    uVar5 = 1;
  }
  else {
    local_1ec = 0;
    func_0x00258ff0(local_1e8,0x90);
    uVar4 = *param_2;
    uVar5 = (ulong)uVar4;
    if (uVar5 == 0xffffffff) {
      uVar5 = 0;
      uVar6 = 7;
    }
    else if ((int)uVar4 < 0) {
      uVar6 = 2;
      uVar5 = (ulong)(int)-uVar4;
    }
    else {
      uVar6 = 0;
    }
    uVar4 = param_2[4];
    if (*(long *)(param_2 + 6) == 0) {
      uVar4 = adjacent_be8620(param_1,uVar6,uVar5,&local_1ec,uVar4 | 0x30,0,0);
    }
    else {
      func_0x00258ff0(local_158,0x90);
      uVar4 = adjacent_be8620(param_1,uVar6,uVar5,&local_1ec,uVar4 | 0x30,local_158,0);
      func_0x002590b0(local_1e8,local_158,0x90);
    }
    uVar5 = (ulong)uVar4;
    lVar1 = *(long *)(param_2 + 2);
    if ((lVar1 != 0) && (uVar4 == 0)) {
      if (*(long *)(param_1 + 0x408) == 0) {
        uVar5 = 0;
      }
      else {
        func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
        uVar5 = func_0x002591d0(&local_1ec,lVar1,4);
      }
    }
    lVar1 = *(long *)(param_2 + 6);
    if ((lVar1 != 0) && ((int)uVar5 == 0)) {
      if (*(long *)(param_1 + 0x408) == 0) {
        uVar5 = 0;
      }
      else {
        func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
        uVar5 = func_0x002591d0(local_1e8,lVar1,0x90);
      }
    }
  }
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar2 = (code *)invalidInstructionException();
    (*pcVar2)();
  }
  return uVar5;
}



/* CONTEXT / separate function: adjacent_be8480 @ 0xbe8480; ev_aacebc8385daa6e0e73ba50d4262248747ad59c96958fcb7614bd26c9464ddc9
 * Ghidra body ranges: 0xbe8480..0xbe8618
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void adjacent_be8480(long param_1,undefined4 *param_2)

{
  undefined4 uVar1;
  undefined8 uVar2;
  long lVar3;
  code *pcVar4;
  int iVar5;
  undefined1 *puVar6;
  undefined1 *puVar7;
  undefined8 *in_GS_OFFSET;
  undefined4 local_1ac;
  undefined1 local_1a8 [288];
  undefined1 local_88 [80];
  long local_38;
  
  local_38 = _DAT_0391c310;
  local_1ac = 0;
  uVar1 = *param_2;
  uVar2 = *(undefined8 *)(param_2 + 2);
  if (*(long *)(param_2 + 8) == 0) {
    puVar6 = (undefined1 *)0x0;
    lVar3 = *(long *)(param_2 + 10);
  }
  else {
    puVar6 = local_1a8;
    func_0x00258ff0(puVar6,0x120);
    lVar3 = *(long *)(param_2 + 10);
  }
  if (lVar3 == 0) {
    puVar7 = (undefined1 *)0x0;
  }
  else {
    puVar7 = local_88;
    func_0x00258ff0(puVar7,0x50);
  }
  iVar5 = adjacent_be8620(param_1,uVar1,uVar2,&local_1ac,param_2[6],puVar6,puVar7);
  lVar3 = *(long *)(param_2 + 4);
  if (iVar5 == 0 && lVar3 != 0) {
    if (*(long *)(param_1 + 0x408) == 0) {
      iVar5 = 0;
    }
    else {
      func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
      iVar5 = func_0x002591d0(&local_1ac,lVar3,4);
    }
  }
  lVar3 = *(long *)(param_2 + 8);
  if ((lVar3 != 0) && (iVar5 == 0)) {
    if (*(long *)(param_1 + 0x408) == 0) {
      iVar5 = 0;
    }
    else {
      func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
      iVar5 = func_0x002591d0(local_1a8,lVar3,0x120);
    }
  }
  lVar3 = *(long *)(param_2 + 10);
  if ((lVar3 != 0) && (iVar5 == 0)) {
    func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
    func_0x002591d0(local_88,lVar3,0x50);
  }
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar4 = (code *)invalidInstructionException();
    (*pcVar4)();
  }
  return;
}



/* CONTEXT / separate function: adjacent_be8620 @ 0xbe8620; ev_2c488c3343a3f340efff56c13162839f9d446bcebe6950acfd801d68193b262e
 * Ghidra body ranges: 0xbe8620..0xbe88de, 0xbe88e0..0xbe8971, 0xbe8980..0xbe89cb, 0xbe89d0..0xbe8c5a
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

int adjacent_be8620(long param_1,uint param_2,long param_3,uint *param_4,uint param_5,
                   undefined8 param_6,long param_7)

{
  long lVar1;
  long lVar2;
  long lVar3;
  uint uVar4;
  long lVar5;
  bool bVar6;
  int iVar7;
  long lVar8;
  int iVar9;
  long lVar10;
  long *in_GS_OFFSET;
  long local_48;
  
  lVar5 = *in_GS_OFFSET;
  if ((((*(byte *)(lVar5 + 0xef) & 1) != 0) &&
      (func_0x004443a0((long)(int)param_2), (*(byte *)(lVar5 + 0xef) & 1) != 0)) &&
     (func_0x00444400(param_3), (*(byte *)(lVar5 + 0xef) & 1) != 0)) {
    func_0x004443a0((long)(int)param_5);
  }
  lVar5 = *(long *)(param_1 + 8);
  local_48._0_4_ = (int)param_3;
  bVar6 = (int)local_48 == 0;
  local_48 = param_3;
  if ((param_2 & 0xfffffffd) == 0 && bVar6) {
    func_0x004c6a00(lVar5 + 0x148,0,0,0);
    local_48 = (long)*(int *)(*(long *)(lVar5 + 0xb38) + 0x28);
    func_0x004c6fa0(lVar5 + 0x148,0,0,0);
    param_2 = 2;
  }
  iVar9 = 0x16;
  if ((param_5 & 0x36) != 0 && (param_5 & 0x7fffffc0) == 0) {
    lVar2 = lVar5 + 0x148;
    do {
      if ((*(byte *)(lVar5 + 0xb3) & 8) != 0) {
        func_0x004c6a00(lVar2,0,0,0);
        *(byte *)(lVar5 + 0xb3) = *(byte *)(lVar5 + 0xb3) & 0xf7;
        func_0x004c6fa0(lVar2,0,0,0);
      }
      if ((*(byte *)(param_1 + 0x52a) & 0x80) != 0) {
        func_0x004c6a00(lVar2,0,0,0);
        *(byte *)(lVar5 + 0x563) = *(byte *)(lVar5 + 0x563) & 0xdf;
        func_0x004c6fa0(lVar2,0,0,0);
      }
      func_0x00c4bb20(0x3589e40,0,0,0);
      lVar10 = *(long *)(lVar5 + 0xf8);
      if (lVar10 == 0) {
LAB_00be8980:
        lVar10 = *(long *)(lVar5 + 0xc40);
        while( true ) {
          if (lVar10 == 0) {
            func_0x00c4c4b0(0x3589e40,0,0);
            func_0x004c6a00(lVar2,0,0,0);
            if ((long)*(int *)(lVar5 + 0x1f8) != 0) {
              *(long *)(param_1 + 0x408) = (long)*(int *)(lVar5 + 0x1f8);
              *(undefined4 *)(lVar5 + 0x1f8) = 0;
              func_0x004c6fa0(lVar2,0,0,0);
              return 0;
            }
            func_0x004c6fa0(lVar2,0,0,0);
            return 10;
          }
          iVar9 = adjacent_be9250(param_1,lVar10,param_2,local_48,0,param_5,0,0,1);
          if (iVar9 != 0) break;
          lVar10 = *(long *)(lVar10 + 0xc30);
        }
      }
      else {
        iVar9 = 0;
        do {
          lVar8 = (long)*(int *)(lVar10 + 0xbc);
          iVar7 = adjacent_be9250(param_1,lVar10,param_2,local_48,param_4,param_5,param_6,param_7,0)
          ;
          if (iVar7 != 0) {
            if (iVar7 != 1) {
              *(long *)(param_1 + 0x408) = lVar8;
              return 0;
            }
            lVar3 = lVar10 + 0x148;
            func_0x004c6a00(lVar3,0,0,0);
            if (((*(uint *)(lVar10 + 0x560) >> 0x11 ^ *(uint *)(param_1 + 0x528) >> 0x17) & 1) == 0)
            {
              lVar1 = lVar10 + 0x38;
              func_0x004c7190(lVar1,0,0);
              if ((((param_5 & 0x20) != 0) &&
                  (uVar4 = *(uint *)(lVar10 + 0xb0), (uVar4 & 0x60000) != 0 && (uVar4 & 0x800) != 0)
                  ) && (((uVar4 & 0x1000) == 0 &&
                        (*(int *)(lVar10 + 0x3a0) == *(int *)(lVar10 + 0xb48))))) {
                func_0x004c7520(lVar1,0,0,0);
                if ((param_5 & 8) == 0) {
                  *(byte *)(lVar10 + 0xb1) = *(byte *)(lVar10 + 0xb1) | 0x10;
                }
                func_0x00c4c4b0(0x3589e40,0,0);
                *param_4 = *(int *)(lVar10 + 0xa30) << 8 | 0x7f;
                if (param_7 != 0) {
                  *(undefined4 *)(param_7 + 0x14) = *(undefined4 *)(lVar10 + 0xa30);
                  *(undefined4 *)(param_7 + 8) = 4;
                }
LAB_00be8bda:
                if ((param_5 & 8) == 0) {
                  func_0x004c6a00(lVar2,0,0,0);
                  func_0x0055c390(*(undefined8 *)(lVar10 + 0x1b0));
                  func_0x004c6fa0(lVar2,0,0,0);
                }
                func_0x004c6fa0(lVar3,0,0,0);
                *(long *)(param_1 + 0x408) = lVar8;
                return 0;
              }
              if ((((param_5 & 2) != 0) && ((*(uint *)(lVar10 + 0xb0) & 0x20000) != 0)) &&
                 (((*(uint *)(lVar10 + 0xb0) & 0x1000) == 0 &&
                  (*(int *)(lVar10 + 0x3a0) == *(int *)(lVar10 + 0xb48))))) {
                func_0x004c7520(lVar1,0,0,0);
                if ((param_5 & 8) == 0) {
                  *(byte *)(lVar10 + 0xb1) = *(byte *)(lVar10 + 0xb1) | 0x10;
                }
                func_0x00c4c4b0(0x3589e40,0,0);
                *param_4 = *(int *)(lVar10 + 0xa30) << 8 | 0x7f;
                if (param_7 != 0) {
                  *(undefined4 *)(param_7 + 0x14) = *(undefined4 *)(lVar10 + 0xa30);
                  *(undefined4 *)(param_7 + 8) = 5;
                }
                goto LAB_00be8bda;
              }
              func_0x004c7520(lVar1,0,0);
              if (((param_5 & 4) != 0) && ((*(byte *)(lVar10 + 0xb2) & 1) != 0)) {
                func_0x00c4c4b0(0x3589e40,0,0);
                if ((param_5 & 8) == 0) {
                  *(byte *)(lVar10 + 0xb2) = *(byte *)(lVar10 + 0xb2) & 0xfe;
                  func_0x004c6a00(lVar2,0,0,0);
                  func_0x0055c390(*(undefined8 *)(lVar10 + 0x1b0));
                  func_0x004c6fa0(lVar2,0,0,0);
                }
                func_0x004c6fa0(lVar3,0,0,0);
                *param_4 = 0x13;
                if (param_7 != 0) {
                  *(undefined4 *)(param_7 + 0x14) = 0x13;
                  *(undefined4 *)(param_7 + 8) = 6;
                }
                *(long *)(param_1 + 0x408) = lVar8;
                return 0;
              }
            }
            iVar9 = iVar9 + 1;
            func_0x004c6fa0(lVar3,0,0);
          }
          lVar10 = *(long *)(lVar10 + 0xe8);
        } while (lVar10 != 0);
        if (iVar9 == 0) goto LAB_00be8980;
      }
      if ((param_5 & 1) != 0) {
        func_0x00c4c4b0(0x3589e40,0,0);
        *(undefined8 *)(param_1 + 0x408) = 0;
        return 0;
      }
      func_0x004c6a00(lVar2,0,0);
      func_0x00c4c4b0(0x3589e40,0,0);
      if ((*(uint *)(lVar5 + 0xb0) & 0x8000000) == 0) {
        if (((*(byte *)(param_1 + 0x52a) & 0x80) == 0) ||
           ((*(ulong *)(lVar5 + 0x560) & 0x20000000) == 0)) {
          iVar9 = func_0x00c06260(lVar5,lVar5 + 0x130,0x105c,0x12f2759,0,0,0x100);
        }
        else {
          iVar9 = 0;
          *(ulong *)(lVar5 + 0x560) = *(ulong *)(lVar5 + 0x560) & 0xffffffffdfffffff;
        }
      }
      else {
        iVar9 = 0;
        *(uint *)(lVar5 + 0xb0) = *(uint *)(lVar5 + 0xb0) & 0xf7ffffff;
      }
      func_0x004c6fa0(lVar2,0,0);
    } while (iVar9 == 0);
  }
  return iVar9;
}



/* CONTEXT / separate function: adjacent_be8c60 @ 0xbe8c60; ev_1f8a46aa0b2ed4a8e8edbfc088c911afe584ddf599372b3b6aa688d4716f11d5
 * Ghidra body ranges: 0xbe8c60..0xbe924f
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Possible PIC construction at 0x00be8de9: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00be8efc: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x00be8dee) */
/* WARNING: Removing unreachable block (ram,0x00be8e35) */
/* WARNING: Removing unreachable block (ram,0x00be8e45) */
/* WARNING: Removing unreachable block (ram,0x00be8dfa) */
/* WARNING: Removing unreachable block (ram,0x00be91c1) */
/* WARNING: Removing unreachable block (ram,0x00be8e0e) */
/* WARNING: Removing unreachable block (ram,0x00be9112) */
/* WARNING: Removing unreachable block (ram,0x00be8e1e) */
/* WARNING: Removing unreachable block (ram,0x00be8e47) */
/* WARNING: Removing unreachable block (ram,0x00be8e9e) */
/* WARNING: Removing unreachable block (ram,0x00be8eae) */
/* WARNING: Removing unreachable block (ram,0x00be8e63) */
/* WARNING: Removing unreachable block (ram,0x00be9202) */
/* WARNING: Removing unreachable block (ram,0x00be9241) */
/* WARNING: Removing unreachable block (ram,0x00be8e77) */
/* WARNING: Removing unreachable block (ram,0x00be9145) */
/* WARNING: Removing unreachable block (ram,0x00be8e87) */
/* WARNING: Removing unreachable block (ram,0x00be8eb0) */
/* WARNING: Removing unreachable block (ram,0x00be8ee9) */
/* WARNING: Removing unreachable block (ram,0x00be8ef1) */
/* WARNING: Removing unreachable block (ram,0x00be8f01) */

void adjacent_be8c60(long param_1,long *param_2,uint *param_3,uint param_4)

{
  long *plVar1;
  long *plVar2;
  code *pcVar3;
  uint uVar4;
  long *plVar5;
  long lVar6;
  
  lVar6 = *(long *)(param_1 + 8);
  func_0x004c7520(param_2 + 7,0,0);
  if (param_3 != (uint *)0x0) {
    uVar4 = (*(uint *)((long)param_2 + 0xa2c) & 0xff) << 8 | *(uint *)(param_2 + 0x146);
    *param_3 = uVar4;
    if ((~*(uint *)(param_2 + 0xac) & 9) == 0) {
      *param_3 = uVar4 | 0x80;
    }
  }
  if ((param_4 & 8) == 0) {
    lVar6 = lVar6 + 0x148;
    func_0x004c6a00(lVar6,0,0);
    func_0x0055c390(param_2[0x36]);
    func_0x004c6fa0(lVar6,0,0);
    if (((int)param_2[0x3f] == 0) || ((int)param_2[0x3f] == *(int *)(param_2[0x1c] + 0xbc))) {
      *(undefined4 *)(param_2 + 0x3f) = 0;
      func_0x004c6fa0(param_2 + 0x29,0,0);
      func_0x00c4bb20(0x3589e60,0,0);
      lVar6 = *param_2;
      if (lVar6 == 0) {
        plVar5 = (long *)param_2[1];
        if ((long *)*plVar5 != param_2) goto LAB_00be90e5;
        lVar6 = 0;
      }
      else {
        if (*(long **)(lVar6 + 8) != param_2) {
          func_0x007f1950();
          func_0x007f2180(0xbe9185,param_2,*param_2,*(undefined8 *)(*param_2 + 8),param_2);
          func_0x00c9aa10(0x37,0x1366e8e,param_2,*param_2,*(undefined8 *)(*param_2 + 8),param_2);
                    /* WARNING: Does not return */
          pcVar3 = (code *)invalidInstructionException();
          (*pcVar3)();
        }
        if (*(long **)param_2[1] != param_2) {
LAB_00be90e5:
          func_0x007f1950();
          func_0x007f20c0(0xbe90e5,param_2,(undefined8 *)param_2[1],*(undefined8 *)param_2[1]);
          func_0x00c9aa10(0x3b,0x1308037,param_2,(undefined8 *)param_2[1],*(undefined8 *)param_2[1])
          ;
                    /* WARNING: Does not return */
          pcVar3 = (code *)invalidInstructionException();
          (*pcVar3)();
        }
        *(undefined8 **)(lVar6 + 8) = (undefined8 *)param_2[1];
        lVar6 = *param_2;
        plVar5 = (long *)param_2[1];
      }
      *plVar5 = lVar6;
      halt_baddata();
    }
    plVar1 = param_2 + 0x29;
    func_0x004c6fa0(plVar1,0,0,0);
    if ((*(uint *)(param_2 + 0x79) & 1) == 0) {
      plVar5 = param_2 + 0x1c;
      if (((int)param_2[0x3f] != 0) && (*(int *)(*plVar5 + 0xbc) != (int)param_2[0x3f])) {
        plVar5 = (long *)&DAT_03588730;
      }
      lVar6 = *plVar5;
    }
    else {
      plVar5 = param_2;
      if ((*(uint *)(param_2 + 0x79) & 2) == 0) {
        do {
          plVar2 = plVar5 + 0x187;
          plVar5 = (long *)(*plVar2 + -0xc30);
        } while ((*(byte *)(*plVar2 + -0x868) & 2) == 0);
      }
      lVar6 = plVar5[0x187] + -0xc40;
    }
    plVar5 = (long *)(lVar6 + 0x148);
    func_0x004c6a00(plVar5,0,0,0);
    func_0x004c6a00(plVar1,0,0,0);
    adjacent_be6f60(param_2,lVar6);
    *(undefined4 *)(param_2 + 0x3f) = 0;
    func_0x004c6fa0(plVar1,0,0,0);
    func_0x0055f820(lVar6,0x14,param_2[0x36]);
    func_0x00c06910(lVar6);
    func_0x0073f010(param_2 + 0x17e,0);
  }
  else {
    plVar5 = param_2 + 0x29;
  }
  func_0x004c6fa0(plVar5,0,0,0);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* CONTEXT / separate function: adjacent_be9250 @ 0xbe9250; ev_bd02e3b2a2644c7cd0b210dceed72e7aa057f69ac4b0f7659b7a8e858d7ea00e
 * Ghidra body ranges: 0xbe9250..0xbe92aa, 0xbe9324..0xbe9343
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8
adjacent_be9250(undefined8 param_1,long param_2,uint param_3,undefined8 param_4,undefined8 param_5,
               undefined4 param_6)

{
  undefined8 uVar1;
  
  func_0x004c6a00(param_2 + 0x148,0,0,0,param_5,param_6,param_5,param_1);
  if (param_3 < 0xd) {
                    /* WARNING: Could not emulate address calculation at 0x00be92a2 */
                    /* WARNING: Treating indirect jump as call */
    uVar1 = (*(code *)((long)*(int *)((ulong)param_3 * 4 + 0x1a477b8) + 0x1a477b8))();
    return uVar1;
  }
  func_0x004c6fa0(param_2 + 0x148,0,0,0);
  return 0;
}



/* CONTEXT / separate function: handler_652_body @ 0xbe9510; ev_c5b34c6130449e4f339cea8614dfe2556df34d65f59531504600afe70efa0fd9
 * Ghidra body ranges: 0xbe9510..0xbe95c3, 0xbe95d0..0xbe9921, 0xbe9930..0xbe9a73
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int handler_652_body(long *param_1,uint *param_2)

{
  uint uVar1;
  long lVar2;
  code *pcVar3;
  int iVar4;
  undefined4 uVar5;
  int iVar6;
  long lVar7;
  ulong uVar8;
  undefined8 uVar9;
  undefined8 uVar10;
  ulong uVar11;
  ulong uVar12;
  long *in_GS_OFFSET;
  uint local_3c;
  long local_38;
  
  local_38 = _DAT_0391c310;
  uVar1 = *param_2;
  uVar11 = (ulong)uVar1;
  iVar4 = func_0x00608f90(param_1[0x28]);
  iVar6 = 1;
  if ((iVar4 != 0) &&
     ((*(int *)(param_1[1] + 0xbc) == _DAT_035ab090 ||
      (iVar4 = func_0x006090d0(param_1[0x28]), iVar4 != 0)))) {
    uVar8 = (ulong)(int)uVar1;
    func_0x0025d410(0x1358e18);
    func_0x00c4bb20(0x3589e40,0,0,0);
    lVar7 = func_0x0053c170(uVar1);
    if (lVar7 != 0) {
LAB_00be95f6:
      iVar4 = func_0x009fcb90();
      if (((iVar4 == 0) || (*(long *)(lVar7 + 0x580) == 0)) ||
         (iVar4 = func_0x009fccb0(), iVar4 != 1)) {
        adjacent_be6f60(lVar7,*(undefined8 *)(*in_GS_OFFSET + 8));
        func_0x00c4c4b0(0x3589e40,0,0);
        func_0x00c9d880(lVar7);
        *(byte *)(lVar7 + 0x562) = *(byte *)(lVar7 + 0x562) | 2;
        *(undefined4 *)(lVar7 + 0x1f8) = 0;
        *(undefined8 *)(lVar7 + 0x3a8) = 0;
        for (lVar2 = *(long *)(lVar7 + 0x10); lVar2 != 0; lVar2 = *(long *)(lVar2 + 0x10)) {
          *(byte *)(lVar2 + 0x2c0) = *(byte *)(lVar2 + 0x2c0) & 0xfc;
          *(undefined4 *)(lVar2 + 0x280) = 9;
        }
        *(undefined4 *)(lVar7 + 0x378) = 0;
        func_0x004c7190(lVar7 + 0x38,0,0,0);
        *(uint *)(lVar7 + 0xb0) = *(uint *)(lVar7 + 0xb0) & 0xfff9e7f7;
        func_0x004c7520(lVar7 + 0x38,0,0,0);
        func_0x0055c4e0(lVar7 + 0x1b8);
        for (lVar2 = *(long *)(lVar7 + 0x10); lVar2 != 0; lVar2 = *(long *)(lVar2 + 0x10)) {
          func_0x0055c4e0(lVar2 + 0xa0);
        }
        func_0x004c78b0(param_1,0,0x12d0f66,0x627);
        *(byte *)((long)param_1 + 0x52a) = *(byte *)((long)param_1 + 0x52a) | 0x80;
        func_0x004c7520(*param_1 + 0x18,0,0,0);
        func_0x0055fba0(lVar7,9);
        goto LAB_00be97e2;
      }
      uVar5 = func_0x009fcc90(*(undefined8 *)(lVar7 + 0x580));
      func_0x004c6fa0(lVar7 + 0x148,0,0);
      func_0x00c4c4b0(0x3589e40,0,0);
      iVar6 = func_0x009ffbc0(uVar5,0xffffffff,1);
      if ((iVar6 == 0x25) || (iVar6 == 0)) goto LAB_00be95d0;
      func_0x0025d410(0x13b7585,uVar5,iVar6);
      goto LAB_00be98fd;
    }
LAB_00be968d:
    func_0x00c4c4b0(0x3589e40,0,0);
    lVar7 = func_0x0053d460(uVar11);
    if (lVar7 == 0) {
      iVar6 = 3;
    }
    else {
LAB_00be97e2:
      func_0x004c6fa0(lVar7 + 0x148,0,0,0);
      local_3c = 0;
      iVar4 = ((int)uVar1 >> 0x1f) * -2;
      uVar12 = (long)(int)-uVar1;
      if (-1 < (int)uVar1) {
        uVar12 = uVar11;
      }
      if (uVar1 == 0xffffffff) {
        uVar12 = 0;
        iVar4 = 7;
      }
      iVar6 = adjacent_be8620(param_1,iVar4,uVar12,&local_3c,0x30,0,0);
      if (iVar6 == 0) {
        do {
          if ((local_3c & 0x7f) == 0) {
LAB_00be9987:
            param_1[0x81] = 0;
            lVar7 = func_0x0053c170(uVar8);
            if (lVar7 == 0) {
              lVar7 = func_0x0053d460(uVar11);
              if (lVar7 == 0) {
                uVar9 = *(undefined8 *)(param_2 + 2);
                func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
                iVar6 = func_0x002591d0(&local_3c,uVar9,4);
                break;
              }
            }
            else {
              func_0x0055fba0(lVar7,9);
            }
            func_0x004c6fa0(lVar7 + 0x148,0,0,0);
          }
          else if ((local_3c & 0x7f) == 0x7f) {
            func_0x00a34f80(param_1,7,uVar11,0,9);
          }
          else if (local_3c != 0x13) goto LAB_00be9987;
          iVar6 = adjacent_be8620(param_1,iVar4,uVar12,&local_3c,0x30,0,0);
        } while (iVar6 == 0);
      }
      if (iVar6 == 10) {
        local_3c = 9;
        uVar9 = *(undefined8 *)(param_2 + 2);
        func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
        iVar6 = func_0x002591d0(&local_3c,uVar9,4);
      }
      func_0x004c78b0(param_1,0,0x12d0f66,0x64b);
      *(byte *)((long)param_1 + 0x52a) = *(byte *)((long)param_1 + 0x52a) & 0x7f;
      func_0x004c7520(*param_1 + 0x18,0,0,0);
      if (iVar6 == 0) {
        lVar7 = func_0x0053c170(uVar8);
        if (lVar7 == 0) {
          lVar7 = func_0x0053d460(uVar11);
          iVar6 = 0;
          if (lVar7 == 0) goto LAB_00be98fd;
          func_0x007f1950();
          func_0x007f18a0(0xbe9a45,uVar8);
          uVar9 = 0x129d40c;
          uVar10 = 99;
          uVar11 = uVar8;
        }
        else {
          func_0x007f1950();
          func_0x007f18a0(0xbe9a1f,uVar8);
          uVar9 = 0x12bb8b4;
          uVar10 = 0x5f;
        }
        func_0x00c9aa10(uVar10,uVar9,uVar11 & 0xffffffff);
                    /* WARNING: Does not return */
        pcVar3 = (code *)invalidInstructionException();
        (*pcVar3)();
      }
    }
  }
LAB_00be98fd:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar3 = (code *)invalidInstructionException();
    (*pcVar3)();
  }
  return iVar6;
LAB_00be95d0:
  func_0x00c4bb20(0x3589e40,0,0);
  lVar7 = func_0x0053c170(uVar11);
  if (lVar7 == 0) goto LAB_00be968d;
  goto LAB_00be95f6;
}



/* CONTEXT / separate function: adjacent_be9a80 @ 0xbe9a80; ev_d6171bee690e6455d16761e0cd32c04a7d62ea9ad87eae971fcb2a21cd4f8336
 * Ghidra body ranges: 0xbe9a80..0xbe9abe
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void adjacent_be9a80(void)

{
  _DAT_02bf65c0 = func_0x0083c370(_DAT_035888c0);
  _DAT_02bf6634 = _DAT_01a84070;
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* CONTEXT / separate function: adjacent_be9ac0 @ 0xbe9ac0; ev_b28d5d8ba5ff210e49fcc8f600afea77ca5bf65be8e0e2c7f5eca65c62334182
 * Ghidra body ranges: 0xbe9ac0..0xbe9ad5
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

bool adjacent_be9ac0(long param_1)

{
  return *(long *)(param_1 + 0x30) != 0x2bf6520;
}



/* CONTEXT / separate function: adjacent_be9ae0 @ 0xbe9ae0; ev_1ca21378c230994d641570062c13824c07c14fe69d42d7d29958001df942feeb
 * Ghidra body ranges: 0xbe9ae0..0xbe9afa, 0xbe9b00..0xbe9b78
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

long adjacent_be9ae0(long param_1,int param_2)

{
  long lVar1;
  long lVar2;
  bool bVar3;
  
  bVar3 = false;
  lVar2 = param_1;
  do {
    while ((!bVar3 && (lVar1 = *(long *)(lVar2 + 0x20), *(long *)(lVar2 + 0x20) != 0))) {
LAB_00be9b29:
      lVar2 = lVar1;
      bVar3 = false;
      if (*(int *)(lVar2 + 0x10) == param_2) {
        func_0x004c6a00(lVar2 + 0x58,0,0,0);
        if (0 < *(int *)(lVar2 + 0x14)) {
          return lVar2;
        }
        bVar3 = false;
        func_0x004c6fa0(lVar2 + 0x58,0,0);
      }
    }
    if (lVar2 == param_1) {
      return 0;
    }
    lVar1 = *(long *)(lVar2 + 0x28);
    if (*(long *)(lVar2 + 0x28) != 0) goto LAB_00be9b29;
    lVar2 = *(long *)(lVar2 + 0x38);
    bVar3 = true;
    if (lVar2 == 0) {
      return 0;
    }
  } while( true );
}



/* CONTEXT / separate function: adjacent_be9b80 @ 0xbe9b80; ev_d4d8333f094e192e2f8c110d157a0221db744a1f98f012a8779942442faa4cbf
 * Ghidra body ranges: 0xbe9b80..0xbe9b8e
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

uint adjacent_be9b80(long param_1,uint param_2)

{
  return param_2 & *(uint *)(*(long *)(param_1 + 0x30) + 0x1c);
}



/* CONTEXT / separate function: adjacent_be9b90 @ 0xbe9b90; ev_e885d95b4098a3fb27c5f88b6378d18d85fc8500c73b51b2285194f11fd1a6e0
 * Ghidra body ranges: 0xbe9b90..0xbe9ba1
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

uint adjacent_be9b90(long param_1,uint param_2)

{
  return param_2 & *(uint *)(*(long *)(param_1 + 0x30) + 0xf8);
}



/* CONTEXT / separate function: adjacent_be9bb0 @ 0xbe9bb0; ev_c56bbe9e3aa680361780731ddb013f839fdf9601fc5a8cfc002798245f5cd7cb
 * Ghidra body ranges: 0xbe9bb0..0xbe9c10
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void adjacent_be9bb0(long param_1)

{
  int *piVar1;
  int iVar2;
  
  func_0x004c6a00(param_1 + 0x58,0,0,0);
  piVar1 = (int *)(param_1 + 0x14);
  *piVar1 = *piVar1 + -1;
  iVar2 = *piVar1;
  func_0x004c6fa0(param_1 + 0x58,0,0,0);
  if (iVar2 != 0) {
    return;
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* CONTEXT / separate function: adjacent_be9c20 @ 0xbe9c20; ev_f6a157d0c9996a4437188e18a4738f63fed4e690de98027dd36ef46d4e504538
 * Ghidra body ranges: 0xbe9c20..0xbe9c50
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void adjacent_be9c20(long param_1)

{
  func_0x004c6a00(param_1 + 0x58,0,0,0);
  *(int *)(param_1 + 0x14) = *(int *)(param_1 + 0x14) + 1;
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* CONTEXT / separate function: adjacent_be9c60 @ 0xbe9c60; ev_2813aeb46f88b27a92898c61741adc11216f41cc6d3a4adea18b99357ecca3a9
 * Ghidra body ranges: 0xbe9c60..0xbe9c90
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void adjacent_be9c60(long param_1)

{
  func_0x004c6a00(param_1 + 0x58,0,0,0);
  *(int *)(param_1 + 0x18) = *(int *)(param_1 + 0x18) + 1;
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* CONTEXT / separate function: adjacent_be9ca0 @ 0xbe9ca0; ev_2be3804508d0f32bd4d871ec2acbcd0fd0ff80e848a3cb890022b7c1e023a9ee
 * Ghidra body ranges: 0xbe9ca0..0xbe9d02
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Possible PIC construction at 0x00be9ce7: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x00be9cec) */
/* WARNING: Removing unreachable block (ram,0x004ea9b0) */

void adjacent_be9ca0(long param_1)

{
  func_0x004c6a00(param_1 + 0x58,0,0,0);
  if (*(int *)(param_1 + 0x18) < 2) {
    *(int *)(param_1 + 0x14) = *(int *)(param_1 + 0x14) + 1;
  }
  else {
    *(int *)(param_1 + 0x18) = *(int *)(param_1 + 0x18) + -1;
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* CONTEXT / separate function: adjacent_be9d10 @ 0xbe9d10; ev_70f755e04af834add94e59afdeddefd3c15c4060dc6532687f62c3d148ae44a0
 * Ghidra body ranges: 0xbe9d10..0xbe9d77
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_be9d10(long param_1,undefined4 *param_2)

{
  long lVar1;
  undefined8 uVar2;
  
  lVar1 = *(long *)(param_1 + 0x30);
  uVar2 = 0;
  if ((*(byte *)(lVar1 + 0x1f) & 2) != 0) {
    uVar2 = 0;
    func_0x004c6a00(lVar1 + 0x58,0,0,0);
    if ((*(byte *)(lVar1 + 0x1f) & 2) != 0) {
      if (*(undefined4 **)(lVar1 + 0xc0) == (undefined4 *)0x0) {
        uVar2 = 0x2f;
      }
      else {
        *param_2 = **(undefined4 **)(lVar1 + 0xc0);
      }
    }
    func_0x004c6fa0(lVar1 + 0x58,0,0,0);
  }
  return uVar2;
}



/* CONTEXT / separate function: adjacent_be9d80 @ 0xbe9d80; ev_3d02d3136ffb69a075a710220de6c2e1372b738da77df624d10bb8ded5e34877
 * Ghidra body ranges: 0xbe9d80..0xbe9e30
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_be9d80(long param_1,int *param_2)

{
  long lVar1;
  int iVar2;
  long lVar3;
  undefined8 uVar4;
  
  lVar3 = *(long *)(param_1 + 0x30);
  uVar4 = 1;
  if ((lVar3 != 0x2bf6520) && ((*(uint *)(lVar3 + 0x1c) & 0x2000080) == 0x2000000)) {
    lVar1 = lVar3 + 0x58;
    func_0x004c6a00(lVar1,0,0,0);
    if ((*(byte *)(lVar3 + 0x1f) & 2) == 0) {
      func_0x004c6fa0(lVar1,0,0,0);
      uVar4 = 1;
    }
    else if (*(int **)(lVar3 + 0xc0) == (int *)0x0) {
      func_0x004c6fa0(lVar1,0,0,0);
      uVar4 = 0x2f;
    }
    else {
      iVar2 = **(int **)(lVar3 + 0xc0);
      func_0x004c6fa0(lVar1,0,0,0);
      uVar4 = 1;
      if (iVar2 != 0) {
        uVar4 = 0;
        *param_2 = iVar2;
      }
    }
  }
  return uVar4;
}



/* CONTEXT / separate function: adjacent_be9e45 @ 0xbe9e45; ev_d0dd4af0ecdf2ce24b40761385f31282dac363c80b3726145018c41157692944
 * Ghidra body ranges: 0xbe9e45..0xbe9e75, 0xbe9e7c..0xbe9ead
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

bool adjacent_be9e45(long param_1,long param_2)

{
  long lVar1;
  
  for (; param_1 != 0x2bf6520; param_1 = *(long *)(param_1 + 0x38)) {
    if ((*(byte *)(param_1 + 0x1c) & 4) != 0) goto joined_r0x00be9e82;
  }
  param_1 = 0x2bf6520;
joined_r0x00be9e82:
  lVar1 = 0x2bf6520;
  if (param_2 != 0x2bf6520) {
    do {
      lVar1 = param_2;
      if ((*(byte *)(param_2 + 0x1c) & 4) != 0) break;
      param_2 = *(long *)(param_2 + 0x38);
      lVar1 = 0x2bf6520;
    } while (param_2 != 0x2bf6520);
  }
  return param_1 == lVar1;
}



/* CONTEXT / separate function: adjacent_be9eb0 @ 0xbe9eb0; ev_2b44b6595e3c643772ce23805534d881fc92aa9a4cc92a5dfeb0ada85dfe2351
 * Ghidra body ranges: 0xbe9eb0..0xbe9f8c
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_be9eb0(long param_1,uint *param_2)

{
  uint uVar1;
  long lVar2;
  uint *puVar3;
  uint uVar4;
  int iVar5;
  undefined8 uVar6;
  int iVar7;
  int iVar8;
  
  lVar2 = *(long *)(param_1 + 0x30);
  if ((*(byte *)(lVar2 + 0x1f) & 2) == 0) {
    return 0;
  }
  uVar6 = 0;
  func_0x004c6a00(lVar2 + 0x58,0,0,0);
  if ((*(byte *)(lVar2 + 0x1f) & 2) != 0) {
    puVar3 = *(uint **)(lVar2 + 0xc0);
    if (puVar3 == (uint *)0x0) {
      uVar6 = 0x2f;
    }
    else {
      uVar1 = *param_2;
      uVar4 = uVar1 >> 0x18 | (uVar1 & 0xff0000) >> 8 | (uVar1 & 0xff00) << 8 | uVar1 << 0x18;
      if (uVar4 != 0x7f000001) {
        if (uVar4 != 0) {
          uVar6 = 0;
          if (*puVar3 != uVar1) {
            uVar6 = 0x31;
            iVar5 = *(int *)(lVar2 + 0xb8) + -2;
            if (-1 < iVar5) {
              iVar8 = 0;
              do {
                while( true ) {
                  iVar7 = (iVar8 + iVar5) / 2;
                  uVar1 = puVar3[(long)iVar7 + 1];
                  uVar1 = CONCAT13((char)uVar1,
                                   CONCAT12((char)(uVar1 >> 8),
                                            CONCAT11((char)(uVar1 >> 0x10),(char)(uVar1 >> 0x18))));
                  if (uVar4 < uVar1) break;
                  if (uVar4 <= uVar1) {
                    uVar6 = 0;
                    goto LAB_00be9f74;
                  }
                  iVar8 = iVar7 + 1;
                  if (iVar5 < iVar8) goto LAB_00be9f74;
                }
                iVar5 = iVar7 + -1;
              } while (iVar8 <= iVar5);
            }
          }
          goto LAB_00be9f74;
        }
        if (*(int *)(lVar2 + 0xb8) != 1) goto LAB_00be9f74;
      }
      *param_2 = *puVar3;
    }
  }
LAB_00be9f74:
  func_0x004c6fa0(lVar2 + 0x58,0,0,0);
  return uVar6;
}



/* CONTEXT / separate function: adjacent_be9f90 @ 0xbe9f90; ev_fb2fd863baae34df627b3ad34f6b5eb0e195a986ce0fb62efd8405a08c22a8f9
 * Ghidra body ranges: 0xbe9f90..0xbea005
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_be9f90(long param_1,undefined4 *param_2)

{
  undefined4 uVar1;
  long lVar2;
  undefined8 uVar3;
  
  lVar2 = *(long *)(param_1 + 0x30);
  uVar3 = 0;
  if ((*(byte *)(lVar2 + 0x1f) & 2) != 0) {
    uVar3 = 0;
    func_0x004c6a00(lVar2 + 0x58,0,0,0);
    if ((*(byte *)(lVar2 + 0x1f) & 2) != 0) {
      if (*(undefined4 **)(lVar2 + 0xc0) == (undefined4 *)0x0) {
        uVar3 = 0x2f;
      }
      else {
        uVar1 = *param_2;
        if (CONCAT13((char)uVar1,
                     CONCAT12((char)((uint)uVar1 >> 8),
                              CONCAT11((char)((uint)uVar1 >> 0x10),(char)((uint)uVar1 >> 0x18)))) ==
            0x7f000001) {
          *param_2 = **(undefined4 **)(lVar2 + 0xc0);
        }
      }
    }
    func_0x004c6fa0(lVar2 + 0x58,0,0,0);
  }
  return uVar3;
}



/* CONTEXT / separate function: adjacent_bea010 @ 0xbea010; ev_20cc843735dff83df4ddfe8d32ca16bff8575a150672f4124f93563acaf7ad1e
 * Ghidra body ranges: 0xbea010..0xbea074, 0xbea080..0xbea0d3
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_bea010(long param_1,uint *param_2)

{
  uint uVar1;
  long lVar2;
  uint *puVar3;
  uint uVar4;
  int iVar5;
  undefined8 uVar6;
  int iVar7;
  int iVar8;
  
  lVar2 = *(long *)(param_1 + 0x30);
  uVar6 = 0;
  if ((*(byte *)(lVar2 + 0x1f) & 2) != 0) {
    uVar6 = 0;
    func_0x004c6a00(lVar2 + 0x58,0,0,0);
    if ((*(byte *)(lVar2 + 0x1f) & 2) != 0) {
      puVar3 = *(uint **)(lVar2 + 0xc0);
      if (puVar3 == (uint *)0x0) {
        uVar6 = 0x2f;
      }
      else {
        uVar4 = *param_2;
        if (*puVar3 != uVar4) {
          uVar6 = 0x31;
          iVar5 = *(int *)(lVar2 + 0xb8) + -2;
          if (-1 < iVar5) {
            uVar4 = uVar4 >> 0x18 | (uVar4 & 0xff0000) >> 8 | (uVar4 & 0xff00) << 8 | uVar4 << 0x18;
            iVar8 = 0;
            do {
              while( true ) {
                iVar7 = (iVar8 + iVar5) / 2;
                uVar1 = puVar3[(long)iVar7 + 1];
                uVar1 = CONCAT13((char)uVar1,
                                 CONCAT12((char)(uVar1 >> 8),
                                          CONCAT11((char)(uVar1 >> 0x10),(char)(uVar1 >> 0x18))));
                if (uVar4 < uVar1) break;
                if (uVar4 <= uVar1) {
                  uVar6 = 0;
                  goto LAB_00bea0b7;
                }
                iVar8 = iVar7 + 1;
                if (iVar5 < iVar8) goto LAB_00bea0b7;
              }
              iVar5 = iVar7 + -1;
            } while (iVar8 <= iVar5);
          }
        }
      }
    }
LAB_00bea0b7:
    func_0x004c6fa0(lVar2 + 0x58,0,0,0);
  }
  return uVar6;
}



/* CONTEXT / separate function: adjacent_bea0e0 @ 0xbea0e0; ev_18904bfe94f78e0b4b9d70ae12e9f06fc05e05364f22598fb15b1db950e04d01
 * Ghidra body ranges: 0xbea0e0..0xbea152
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_bea0e0(long param_1,undefined8 param_2)

{
  long lVar1;
  undefined8 uVar2;
  
  lVar1 = *(long *)(param_1 + 0x30);
  uVar2 = 0;
  if ((*(byte *)(lVar1 + 0x1f) & 4) != 0) {
    uVar2 = 0;
    func_0x004c6a00(lVar1 + 0x58,0,0,0);
    if ((*(byte *)(lVar1 + 0x1f) & 4) != 0) {
      if (*(long *)(lVar1 + 200) == 0) {
        uVar2 = 0x2f;
      }
      else {
        func_0x00259be0(*(long *)(lVar1 + 200),param_2,0x10);
      }
    }
    func_0x004c6fa0(lVar1 + 0x58,0,0,0);
  }
  return uVar2;
}



/* CONTEXT / separate function: adjacent_bea160 @ 0xbea160; ev_0b45105c30af812c45a1718bc0d129b32d482f0661bc5a9347121c5ebca926f3
 * Ghidra body ranges: 0xbea160..0xbea26b
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 adjacent_bea160(long param_1,undefined8 param_2)

{
  long lVar1;
  long lVar2;
  code *pcVar3;
  undefined8 uVar4;
  undefined8 local_40;
  undefined8 local_38;
  long local_30;
  
  local_30 = _DAT_0391c310;
  uVar4 = 1;
  lVar2 = *(long *)(param_1 + 0x30);
  if ((lVar2 != 0x2bf6520) && ((*(uint *)(lVar2 + 0x1c) & 0x100) == 0)) {
    local_38 = 0;
    local_40 = 0;
    if ((*(uint *)(lVar2 + 0x1c) & 0x4000000) != 0) {
      lVar1 = lVar2 + 0x58;
      func_0x004c6a00(lVar1,0,0,0);
      if ((*(byte *)(lVar2 + 0x1f) & 4) != 0) {
        if (*(long *)(lVar2 + 200) == 0) {
          func_0x004c6fa0(lVar1,0,0,0);
          uVar4 = 0x2f;
          goto LAB_00bea24f;
        }
        func_0x00259be0(*(long *)(lVar2 + 200),&local_40,0x10);
      }
      func_0x004c6fa0(lVar1,0,0,0);
      uVar4 = 1;
      if (((((int)local_40 != 0) || (local_40._4_4_ != 0)) || ((int)local_38 != 0)) ||
         (local_38._4_4_ != 0)) {
        func_0x00259be0(&local_40,param_2,0x10);
        uVar4 = 0;
      }
    }
  }
LAB_00bea24f:
  if (_DAT_0391c310 == local_30) {
    return uVar4;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar3 = (code *)invalidInstructionException();
  (*pcVar3)();
}



/* CONTEXT / separate function: adjacent_bea275 @ 0xbea275; ev_041de45dbe1caa5beb2b07ea5d86b39cdb191f6714bf6c0ddde1bc6e7a7133a7
 * Ghidra body ranges: 0xbea275..0xbea2a5, 0xbea2ac..0xbea2dd
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

bool adjacent_bea275(long param_1,long param_2)

{
  long lVar1;
  
  for (; param_1 != 0x2bf6520; param_1 = *(long *)(param_1 + 0x38)) {
    if ((*(byte *)(param_1 + 0x1c) & 8) != 0) goto joined_r0x00bea2b2;
  }
  param_1 = 0x2bf6520;
joined_r0x00bea2b2:
  lVar1 = 0x2bf6520;
  if (param_2 != 0x2bf6520) {
    do {
      lVar1 = param_2;
      if ((*(byte *)(param_2 + 0x1c) & 8) != 0) break;
      param_2 = *(long *)(param_2 + 0x38);
      lVar1 = 0x2bf6520;
    } while (param_2 != 0x2bf6520);
  }
  return param_1 == lVar1;
}



/* CONTEXT / separate function: adjacent_bea2e0 @ 0xbea2e0; ev_253e1e5fdb404a8fe2b140a41b3fa14d46a474b38c75f27eac6c66c6e20940dc
 * Ghidra body ranges: 0xbea2e0..0xbea37e, 0xbea380..0xbea429
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_bea2e0(long param_1,int *param_2,int param_3)

{
  byte bVar1;
  byte bVar2;
  long lVar3;
  long lVar4;
  int iVar5;
  undefined8 uVar6;
  undefined8 uVar7;
  int iVar8;
  int iVar9;
  ulong uVar10;
  bool bVar11;
  
  lVar3 = *(long *)(param_1 + 0x30);
  if ((*(byte *)(lVar3 + 0x1f) & 4) == 0) {
    return 0;
  }
  uVar6 = 0;
  func_0x004c6a00(lVar3 + 0x58,0,0,0);
  uVar7 = 0;
  if ((*(byte *)(lVar3 + 0x1f) & 4) == 0) goto LAB_00bea3d9;
  lVar4 = *(long *)(lVar3 + 200);
  if (lVar4 == 0) {
    uVar7 = 0x2f;
    goto LAB_00bea3d9;
  }
  if (((*param_2 == 0) && (param_2[1] == 0)) && (param_2[2] == 0)) {
    uVar7 = uVar6;
    if (param_2[3] != 0x1000000) {
      if (param_2[3] != 0) goto LAB_00bea350;
      if ((param_3 == 0) || (*(int *)(lVar3 + 0xbc) != 1)) goto LAB_00bea3d9;
    }
    func_0x00259be0(lVar4,param_2,0x10);
  }
  else {
LAB_00bea350:
    iVar5 = func_0x00259080(lVar4,param_2,0x10);
    uVar7 = 0;
    if (iVar5 != 0) {
      iVar5 = *(int *)(lVar3 + 0xbc) + -2;
      uVar7 = 0x31;
      if (-1 < iVar5) {
        iVar8 = 0;
        do {
          uVar10 = 0;
          iVar9 = (iVar8 + iVar5) / 2;
          do {
            bVar1 = *(byte *)((long)iVar9 * 0x10 + 0x10 + *(long *)(lVar3 + 200) + uVar10);
            bVar2 = *(byte *)((long)param_2 + uVar10);
            if (bVar1 != bVar2) break;
            bVar11 = uVar10 < 0xf;
            uVar10 = uVar10 + 1;
          } while (bVar11);
          if (bVar2 < bVar1) {
            iVar5 = iVar9 + -1;
          }
          else {
            iVar8 = iVar9 + 1;
            if (bVar2 <= bVar1) {
              uVar7 = 0;
              break;
            }
          }
        } while (iVar8 <= iVar5);
      }
    }
  }
LAB_00bea3d9:
  func_0x004c6fa0(lVar3 + 0x58,0,0,0);
  return uVar7;
}



/* CONTEXT / separate function: adjacent_bea430 @ 0xbea430; ev_3157e4e4e3a78c5b72c3d2b7096607c55af82c92f2368e45448c3189dc83716d
 * Ghidra body ranges: 0xbea430..0xbea4bc
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_bea430(long param_1,int *param_2)

{
  long lVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  
  lVar1 = *(long *)(param_1 + 0x30);
  uVar3 = 0;
  if ((*(byte *)(lVar1 + 0x1f) & 4) != 0) {
    uVar3 = 0;
    uVar2 = 0;
    func_0x004c6a00(lVar1 + 0x58,0,0,0);
    if ((*(byte *)(lVar1 + 0x1f) & 4) != 0) {
      if (*(long *)(lVar1 + 200) == 0) {
        uVar3 = 0x2f;
      }
      else if ((((*param_2 == 0) && (param_2[1] == 0)) && (uVar3 = uVar2, param_2[2] == 0)) &&
              (param_2[3] == 0x1000000)) {
        func_0x00259be0(*(long *)(lVar1 + 200),param_2,0x10);
      }
    }
    func_0x004c6fa0(lVar1 + 0x58,0,0,0);
  }
  return uVar3;
}



/* CONTEXT / separate function: adjacent_bea4c0 @ 0xbea4c0; ev_46a86dc697e0f5add90f4a27cad9fa31e383cf710591e4cb4b634768410563ba
 * Ghidra body ranges: 0xbea4c0..0xbea544, 0xbea550..0xbea5c1
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_bea4c0(long param_1,long param_2)

{
  byte bVar1;
  byte bVar2;
  long lVar3;
  int iVar4;
  undefined8 uVar5;
  int iVar6;
  int iVar7;
  ulong uVar8;
  bool bVar9;
  
  lVar3 = *(long *)(param_1 + 0x30);
  uVar5 = 0;
  if ((*(byte *)(lVar3 + 0x1f) & 4) != 0) {
    uVar5 = 0;
    func_0x004c6a00(lVar3 + 0x58,0,0,0);
    if ((*(byte *)(lVar3 + 0x1f) & 4) != 0) {
      if (*(long *)(lVar3 + 200) == 0) {
        uVar5 = 0x2f;
      }
      else {
        iVar4 = func_0x00259080(*(long *)(lVar3 + 200),param_2,0x10);
        if (iVar4 != 0) {
          uVar5 = 0x31;
          iVar4 = *(int *)(lVar3 + 0xbc) + -2;
          if (-1 < iVar4) {
            iVar6 = 0;
            do {
              uVar8 = 0;
              iVar7 = (iVar6 + iVar4) / 2;
              do {
                bVar1 = *(byte *)((long)iVar7 * 0x10 + 0x10 + *(long *)(lVar3 + 200) + uVar8);
                bVar2 = *(byte *)(param_2 + uVar8);
                if (bVar1 != bVar2) break;
                bVar9 = uVar8 < 0xf;
                uVar8 = uVar8 + 1;
              } while (bVar9);
              if (bVar2 < bVar1) {
                iVar4 = iVar7 + -1;
              }
              else {
                iVar6 = iVar7 + 1;
                if (bVar2 <= bVar1) {
                  uVar5 = 0;
                  break;
                }
              }
            } while (iVar6 <= iVar4);
          }
        }
      }
    }
    func_0x004c6fa0(lVar3 + 0x58,0,0,0);
  }
  return uVar5;
}



/* CONTEXT / separate function: adjacent_bea5d0 @ 0xbea5d0; ev_1b7248b02b239ceb6752732127b6d53fb14b456afd2a9e5e71cd790678f7be8d
 * Ghidra body ranges: 0xbea5d0..0xbea5fa, 0xbea66d..0xbea68b
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

ulong adjacent_bea5d0(long param_1,int param_2)

{
  ulong uVar1;
  uint uVar2;
  
  if (param_2 - 1U < 0x1c) {
                    /* WARNING: Could not emulate address calculation at 0x00bea5f2 */
                    /* WARNING: Treating indirect jump as call */
    uVar1 = (*(code *)((long)*(int *)((ulong)(param_2 - 1U) * 4 + 0x1a477ec) + 0x1a477ec))();
    return uVar1;
  }
  uVar2 = 0x2f;
  if ((*(byte *)(*(long *)(param_1 + 0x30) + 0xf8) & 0x40) != 0) {
    uVar2 = 0;
  }
  return (ulong)uVar2;
}



/* CONTEXT / separate function: adjacent_bea690 @ 0xbea690; ev_8f562029c00b429afc87071c53f9fc43bb5e3073bd620393de85876529f54c4d
 * Ghidra body ranges: 0xbea690..0xbea6cc
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted.", "Ghidra Listing reports a terminal call at 0xbea6a7 to 0xbea010 adjacent_bea010 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation.", "Ghidra Listing reports a terminal call at 0xbea6b1 to 0xbea4c0 adjacent_bea4c0 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

undefined8 adjacent_bea690(long param_1,long param_2)

{
  undefined8 uVar1;
  
  if (*(char *)(param_2 + 1) == '\x1c') {
    uVar1 = adjacent_bea4c0(param_1,param_2 + 8);
    return uVar1;
  }
  if (*(char *)(param_2 + 1) == '\x02') {
    uVar1 = adjacent_bea010(param_1,param_2 + 4);
    return uVar1;
  }
  uVar1 = 0x2f;
  if ((*(byte *)(*(long *)(param_1 + 0x30) + 0xf8) & 0x40) != 0) {
    uVar1 = 0;
  }
  return uVar1;
}



/* CONTEXT / separate function: adjacent_bea6df @ 0xbea6df; ev_524c05f97b68664a0cdf946445157f66ed897635efb95d44073dc6baafdaeb58
 * Ghidra body ranges: 0xbea6df..0xbea706
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void adjacent_bea6df(undefined8 param_1,undefined8 param_2,long param_3,long param_4)

{
  do {
    param_3 = *(long *)(param_3 + 0x38);
    if (param_3 == 0) {
      return;
    }
  } while (param_4 != param_3);
  return;
}



/* CONTEXT / separate function: adjacent_bea710 @ 0xbea710; ev_46d107310efff89974808f0652e5202e4b2cc0f38c36393745b31fe766743a32
 * Ghidra body ranges: 0xbea710..0xbea725
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

bool adjacent_bea710(long param_1)

{
  return *(long *)(param_1 + 0x30) != 0x2bf6520;
}



/* CONTEXT / separate function: adjacent_bea730 @ 0xbea730; ev_e38c537e3d87340a3bcd56ee797c2431d9ecba7d19c12bebe1bc637ce43a43b3
 * Ghidra body ranges: 0xbea730..0xbea78f
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void adjacent_bea730(long param_1,undefined8 param_2,undefined8 param_3)

{
  long lVar1;
  
  if (param_1 == 0) {
    lVar1 = 0x2bf6520;
  }
  else {
    lVar1 = *(long *)(param_1 + 0x30);
  }
  func_0x004c6a00(lVar1 + 0x58,0,0,0);
  func_0x00957b70(param_2,lVar1 + 0x620,param_3);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* CONTEXT / separate function: adjacent_bea790 @ 0xbea790; ev_961ee62aaac6c8544720ed8b49e15b6d087e81ec27f4b209afef5a6f9c303a2e
 * Ghidra body ranges: 0xbea790..0xbea832
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

char adjacent_bea790(long param_1,long param_2)

{
  char cVar1;
  char cVar2;
  int iVar3;
  long lVar4;
  long lVar5;
  
  lVar5 = *(long *)(param_1 + 0x30);
  cVar2 = '\0';
  if ((*(int *)(lVar5 + 0x100) != 0) && (*(long *)(*(long *)(lVar5 + 0xb0) + 0x18) != param_2)) {
    if (*(int *)(lVar5 + 0x100) == 2) {
      cVar2 = '\x02';
    }
    else {
      lVar5 = lVar5 + 0x220;
      iVar3 = func_0x0026b9b0(lVar5,0x12aab2e);
      cVar2 = '\0';
      if (iVar3 != 0) {
        lVar4 = func_0x008327a0(lVar5);
        iVar3 = func_0x008d1a30(lVar5,param_2 + 0x238,lVar4);
        cVar2 = '\x02';
        if (iVar3 == 0) {
          cVar1 = *(char *)(param_2 + 0x238 + lVar4);
          cVar2 = '\0';
          if (cVar1 != '\0') {
            cVar2 = (cVar1 != '/') * '\x02';
          }
        }
      }
    }
  }
  return cVar2;
}



/* CONTEXT / separate function: adjacent_bea840 @ 0xbea840; ev_6e6d41cbccce64536febdb67970104080c69db869366233b9136c33125bf0520
 * Ghidra body ranges: 0xbea840..0xbea9ee
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Possible PIC construction at 0x00bea97e: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00bea9a8: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x00bea983) */
/* WARNING: Removing unreachable block (ram,0x00bea9c9) */
/* WARNING: Removing unreachable block (ram,0x00bea999) */
/* WARNING: Removing unreachable block (ram,0x00bea9ad) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void adjacent_bea840(long param_1,long param_2,long param_3)

{
  long lVar1;
  char cVar2;
  long lVar3;
  code *pcVar4;
  long lVar5;
  int iVar6;
  long lVar7;
  
  lVar5 = _DAT_0391c310;
  lVar3 = *(long *)(param_1 + 0x30);
  if (*(int *)(lVar3 + 0x100) != 0) {
    if (*(long *)(*(long *)(lVar3 + 0xb0) + 0x18) != param_2) {
      if (*(int *)(lVar3 + 0x100) == 2) {
LAB_00bea8d8:
        func_0x00258ff0(param_3 + 0x180,0x58);
        if (_DAT_0391c310 == lVar5) {
          halt_baddata();
        }
        goto LAB_00bea9e8;
      }
      lVar1 = lVar3 + 0x220;
      iVar6 = func_0x0026b9b0(lVar1,0x12aab2e);
      if (iVar6 != 0) {
        lVar7 = func_0x008327a0(lVar1);
        iVar6 = func_0x008d1a30(lVar1,param_2 + 0x238,lVar7);
        if ((iVar6 != 0) ||
           ((cVar2 = *(char *)(param_2 + 0x238 + lVar7), cVar2 != '\0' && (cVar2 != '/'))))
        goto LAB_00bea8d8;
      }
    }
    if (*(long *)(*(long *)(lVar3 + 0xb0) + 0x18) == param_2) {
      func_0x00258ff0(param_3 + 0x180,0x58);
      *(undefined1 *)(param_3 + 0x180) = 0x2f;
    }
    else {
      iVar6 = func_0x0026b9b0(lVar3 + 0x220,0x12aab2e);
      if (iVar6 != 0) {
        func_0x008327a0(lVar3 + 0x220);
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
    }
  }
  if (_DAT_0391c310 == lVar5) {
    return;
  }
LAB_00bea9e8:
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar4 = (code *)invalidInstructionException();
  (*pcVar4)();
}



/* CONTEXT / separate function: adjacent_bea9f0 @ 0xbea9f0; ev_e6225fd43af5145da46f7227eaaf417e0ddd435318846f2d1fd111488acb55ae
 * Ghidra body ranges: 0xbea9f0..0xbeaa22, 0xbeaa37..0xbeaa45
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_bea9f0(long param_1,int param_2)

{
  undefined8 uVar1;
  code *UNRECOVERED_JUMPTABLE;
  
  if (*(long *)(param_1 + 0x30) != 0x2bf6520) {
    if (param_2 - 5U < 0x1f5) {
      UNRECOVERED_JUMPTABLE =
           (code *)((long)*(int *)((ulong)(param_2 - 5U) * 4 + 0x1a4785c) + 0x1a4785c);
                    /* WARNING: Could not emulate address calculation at 0x00beaa18 */
                    /* WARNING: Treating indirect jump as call */
      uVar1 = (*UNRECOVERED_JUMPTABLE)(param_1,0x1a4785c,UNRECOVERED_JUMPTABLE);
      return uVar1;
    }
    if (param_2 != 0x2b1) {
      return 1;
    }
  }
  return 0;
}



/* CONTEXT / separate function: adjacent_beaa60 @ 0xbeaa60; ev_4dac1c32ed3b0c3f4598c3fb12ce5f1f0cfe752006a54368ac33e630934b5a3b
 * Ghidra body ranges: 0xbeaa60..0xbeaaa1, 0xbeab3b..0xbeab51, 0xbeab90..0xbeab96
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Removing unreachable block (ram,0x00beab90) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 adjacent_beaa60(long param_1)

{
  undefined8 uVar1;
  uint uVar2;
  code *UNRECOVERED_JUMPTABLE;
  
  uVar2 = (*(uint *)(param_1 + 0x1c) & 0xf) - 2;
  if (6 < uVar2) {
    return 0;
  }
  UNRECOVERED_JUMPTABLE = (code *)((long)*(int *)((ulong)uVar2 * 4 + 0x1a48030) + 0x1a48030);
                    /* WARNING: Could not emulate address calculation at 0x00beaa99 */
                    /* WARNING: Treating indirect jump as call */
  uVar1 = (*UNRECOVERED_JUMPTABLE)(param_1,UNRECOVERED_JUMPTABLE);
  return uVar1;
}



/* CONTEXT / separate function: adjacent_beabd0 @ 0xbeabd0; ev_82ea48883846423bb5503d5ca92ea8fdbe6ac1bb1e78f9bca226322fb77211bc
 * Ghidra body ranges: 0xbeabd0..0xbeac6b, 0xbeac70..0xbead62, 0xbead70..0xbeae0a, 0xbeae10..0xbeb0a7
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

int adjacent_beabd0(void)

{
  long lVar1;
  long lVar2;
  char cVar3;
  long lVar4;
  code *pcVar5;
  int iVar6;
  long lVar7;
  int iVar8;
  int iVar9;
  uint uVar10;
  undefined4 *puVar11;
  undefined8 uVar12;
  long *in_RCX;
  long lVar13;
  long lVar14;
  long lVar15;
  int iVar16;
  undefined8 local_40;
  
  puVar11 = (undefined4 *)func_0x00c08b50(0x618,0x2bfc080,2);
  local_40 = 0;
  lVar4 = *(long *)(*(long *)(*in_RCX + 0x140) + 0x30);
  func_0x00c4b350(0x3d96b70,0,0,0);
  lVar2 = lVar4 + 0x220;
  iVar6 = 0;
  uVar12 = 0;
  iVar16 = 0;
  lVar13 = lVar4;
LAB_00beac81:
  do {
    lVar1 = *(long *)(lVar13 + 0x20);
    if (*(long *)(lVar13 + 0x20) == 0) {
      if (lVar13 == lVar4) {
LAB_00beb054:
        iVar8 = 0;
        goto LAB_00beb05c;
      }
      lVar1 = *(long *)(lVar13 + 0x28);
      if (*(long *)(lVar13 + 0x28) == 0) {
        lVar13 = *(long *)(lVar13 + 0x38);
        while( true ) {
          if ((lVar13 == 0) || (lVar13 == lVar4)) goto LAB_00beb054;
          lVar1 = *(long *)(lVar13 + 0x28);
          if (*(long *)(lVar13 + 0x28) != 0) break;
          lVar13 = *(long *)(lVar13 + 0x38);
        }
      }
    }
    lVar13 = lVar1;
    lVar1 = lVar13 + 0x58;
LAB_00beacb0:
    while( true ) {
      func_0x004c6a00(lVar1,0,0,0);
      iVar8 = *(int *)(lVar13 + 0xb8);
      if ((long)iVar8 < 1) break;
      if (iVar8 <= iVar6) {
        func_0x00259be0(*(undefined8 *)(lVar13 + 0xc0));
        break;
      }
      func_0x004c6fa0(lVar1,0,0,0);
      local_40 = func_0x00c08f60(local_40,(long)iVar8 << 2,0x2bfc080);
      iVar6 = iVar8;
    }
    iVar8 = *(int *)(lVar13 + 0xbc);
    lVar14 = (long)iVar8;
    if (lVar14 < 1) goto LAB_00bead86;
    if (iVar16 < iVar8) {
      func_0x004c6fa0(lVar1,0,0,0);
      uVar12 = func_0x00c08f60(uVar12,lVar14 << 4,0x2bfc080);
      iVar16 = iVar8;
      goto LAB_00beacb0;
    }
    func_0x00259be0(*(undefined8 *)(lVar13 + 200),uVar12,lVar14 << 4);
LAB_00bead86:
    if (*(int *)(lVar13 + 0x14) == 0) {
      func_0x004c6fa0(lVar1,0,0,0);
      goto LAB_00beac81;
    }
    func_0x00258ff0(puVar11,0x618);
    *puVar11 = 3;
    puVar11[1] = *(undefined4 *)(lVar13 + 0x10);
    puVar11[2] = (*(int *)(lVar13 + 0x18) < 1) + 1;
    lVar14 = lVar13 + 0x220;
    iVar8 = func_0x0026b9b0(lVar2,0x12aab2e);
    lVar15 = lVar14;
    if (iVar8 != 0) {
      iVar8 = func_0x008327a0(lVar2);
      iVar9 = func_0x008d1a30(lVar2,lVar14);
      if (iVar9 == 0) {
        cVar3 = *(char *)(lVar14 + iVar8);
        lVar15 = 0x12aab2e;
        if ((cVar3 != '\0') && (lVar15 = lVar14, cVar3 == '/')) {
          lVar15 = lVar14 + iVar8;
        }
      }
    }
    func_0x00957b70(puVar11 + 4,lVar15,0x400);
    func_0x00957b70(puVar11 + 0x104,lVar13 + 0x620,0x100);
    lVar14 = 0x135c63b;
    if (lVar4 != lVar13) {
      lVar14 = lVar13 + 0x120;
      lVar15 = lVar13;
      do {
        lVar15 = *(long *)(lVar15 + 0x38);
        if (lVar15 == 0) goto LAB_00beaea0;
        lVar7 = lVar4;
      } while (lVar4 != lVar15);
      for (; lVar7 != 0x2bf6520; lVar7 = *(long *)(lVar7 + 0x38)) {
        lVar14 = func_0x009b3ce0(lVar14,0x2e);
        lVar14 = lVar14 + 1;
      }
    }
LAB_00beaea0:
    func_0x00957b70(puVar11 + 0x144,lVar14,0x100);
    puVar11[0x184] = *(undefined4 *)(lVar13 + 0xb8);
    puVar11[0x185] = *(undefined4 *)(lVar13 + 0xbc);
    func_0x004c6fa0(lVar1,0,0,0);
    pcVar5 = (code *)in_RCX[5];
    if (3 < (-(long)pcVar5 + 0x269338U >> 3 | -(long)pcVar5 << 0x3d)) {
      func_0x0044f8c0(0x2bf6480,pcVar5);
    }
    iVar8 = (*pcVar5)(in_RCX,puVar11,0x618);
    if (iVar8 != 0) goto LAB_00beb05c;
    uVar10 = puVar11[0x184];
    if (uVar10 != 0) {
      pcVar5 = (code *)in_RCX[5];
      if (3 < (-(long)pcVar5 + 0x269338U >> 3 | -(long)pcVar5 << 0x3d)) {
        func_0x0044f8c0(0x2bf64a0,pcVar5);
        uVar10 = puVar11[0x184];
      }
      iVar8 = (*pcVar5)(in_RCX,local_40,(ulong)uVar10 << 2);
      if (iVar8 != 0) goto LAB_00beb05c;
    }
    uVar10 = puVar11[0x185];
    if (uVar10 != 0) {
      pcVar5 = (code *)in_RCX[5];
      if (3 < (-(long)pcVar5 + 0x269338U >> 3 | -(long)pcVar5 << 0x3d)) {
        func_0x0044f8c0(0x2bf64c0,pcVar5);
        uVar10 = puVar11[0x185];
      }
      iVar8 = (*pcVar5)(in_RCX,uVar12,(ulong)uVar10 << 4);
      if (iVar8 != 0) {
LAB_00beb05c:
        func_0x00c4c300(0x3d96b70,0,0);
        func_0x00c08df0(puVar11,0x2bfc080);
        func_0x00c08df0(local_40,0x2bfc080);
        func_0x00c08df0(uVar12,0x2bfc080);
        return iVar8;
      }
    }
  } while( true );
}



/* CONTEXT / separate function: adjacent_beb0b0 @ 0xbeb0b0; ev_8323b85390ed00e89d8dfcddce8c6744607fb755eb50d09f377e6a2c337ab35f
 * Ghidra body ranges: 0xbeb0b0..0xbeb140
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void adjacent_beb0b0(void)

{
  code *pcVar1;
  long *in_RCX;
  uint local_2c;
  long local_28;
  
  local_28 = _DAT_0391c310;
  local_2c = (uint)(*(long *)(*(long *)(*in_RCX + 0x140) + 0x30) != 0x2bf6520);
  pcVar1 = (code *)in_RCX[5];
  if (3 < (-(long)pcVar1 + 0x269338U >> 3 | -(long)pcVar1 << 0x3d)) {
    func_0x0044f8c0(0x2bf64e0,pcVar1);
  }
  (*pcVar1)(in_RCX,&local_2c,4);
  if (_DAT_0391c310 == local_28) {
    return;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* CONTEXT / separate function: adjacent_beb150 @ 0xbeb150; ev_4546aef2b524fb3d8f7d220d8210a097a22469378021ee92f3976303aed7dec1
 * Ghidra body ranges: 0xbeb150..0xbeb1c9
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void adjacent_beb150(void)

{
  code *pcVar1;
  long in_RCX;
  undefined4 local_2c;
  long local_28;
  
  local_28 = _DAT_0391c310;
  local_2c = 0;
  pcVar1 = *(code **)(in_RCX + 0x28);
  if (3 < (-(long)pcVar1 + 0x269338U >> 3 | -(long)pcVar1 << 0x3d)) {
    func_0x0044f8c0(0x2bf6500,pcVar1);
  }
  (*pcVar1)(in_RCX,&local_2c,4);
  if (_DAT_0391c310 == local_28) {
    return;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* CONTEXT / separate function: adjacent_beb1d0 @ 0xbeb1d0; ev_8a41b9ddb8c9a436b66abeec2d34e9c890bb9b9be96d0484433f3887ccd55424
 * Ghidra body ranges: 0xbeb1d0..0xbeb2c0
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong adjacent_beb1d0(undefined8 param_1,long param_2,ulong param_3,long *param_4)

{
  long lVar1;
  code *pcVar2;
  ulong uVar3;
  uint uVar4;
  uint uVar5;
  int *piVar6;
  uint local_34;
  long local_30;
  
  local_30 = _DAT_0391c310;
  lVar1 = *(long *)(*(long *)(*param_4 + 0x140) + 0x30);
  piVar6 = (int *)&DAT_02bf49e0;
  if (lVar1 != 0x2bf6520) {
    piVar6 = (int *)(lVar1 + 0xf8);
  }
  local_34 = (uint)((param_2 == 0) != ((param_3 & (long)*piVar6) == 0));
  uVar3 = func_0x002709e8(param_1,&local_34,0,param_4);
  if (((int)uVar3 == 0) && (param_4[6] != 0)) {
    uVar5 = (uint)param_3;
    uVar3 = uVar3 & 0xffffffff;
    uVar4 = 0;
    if (local_34 != 0) {
      uVar4 = uVar5;
    }
    local_34 = uVar5;
    if (param_2 == 0) {
      local_34 = 0;
    }
    local_34 = local_34 ^ uVar4;
    func_0x004c6a00(0x2bf6578,0,0,0);
    _DAT_02bf49e0 = ~uVar5 & _DAT_02bf49e0 | local_34;
    func_0x004c6fa0(0x2bf6578,0,0,0);
  }
  if (_DAT_0391c310 == local_30) {
    return uVar3;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar2 = (code *)invalidInstructionException();
  (*pcVar2)();
}



/* CONTEXT / separate function: adjacent_beb2d0 @ 0xbeb2d0; ev_df72aead693db0eeda7b951cd6d2fdee8a5928ecb828aefd296bd239dcd9530a
 * Ghidra body ranges: 0xbeb2d0..0xbeb34d
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void adjacent_beb2d0(undefined8 param_1,undefined4 *param_2,long param_3,long *param_4)

{
  long lVar1;
  code *pcVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 local_2c;
  long local_28;
  
  local_28 = _DAT_0391c310;
  lVar1 = *(long *)(*(long *)(*param_4 + 0x140) + 0x30);
  puVar4 = (undefined4 *)(param_3 + lVar1);
  if (lVar1 == 0x2bf6520) {
    puVar4 = param_2;
  }
  local_2c = *puVar4;
  iVar3 = func_0x002709e8(param_1,&local_2c,0,param_4);
  if ((iVar3 == 0) && (param_4[6] != 0)) {
    *param_2 = local_2c;
  }
  if (_DAT_0391c310 == local_28) {
    return;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar2 = (code *)invalidInstructionException();
  (*pcVar2)();
}



/* CONTEXT / separate function: adjacent_beb350 @ 0xbeb350; ev_72ec3b08781e2538c3a9dd27cb602dfd99af9c6d50b9765930984c3196afc054
 * Ghidra body ranges: 0xbeb350..0xbeb4b2
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

int adjacent_beb350(ulong param_1,uint param_2,code *param_3,undefined8 param_4,code *param_5,
                   undefined8 param_6,undefined8 *param_7,undefined8 *param_8,ulong *param_9)

{
  int iVar1;
  ulong uVar2;
  
  uVar2 = -(long)param_3 + 0x26f590U >> 3 | -(long)param_3 << 0x3d;
  *param_7 = 0;
  *param_8 = 0;
  *param_9 = param_1 & 0xffffffffffffc000;
  do {
    if (2 < uVar2) {
      func_0x0044f8c0(0x2bf7820,param_3);
    }
    iVar1 = (*param_3)(*param_9,param_7,param_4);
  } while ((iVar1 == -1) || (iVar1 == 4));
  if (iVar1 == 0) {
    iVar1 = 0;
    if ((*param_9 != param_1) && (0x4000 < (param_1 + param_2) - *param_9)) {
      do {
        if (2 < uVar2) {
          func_0x0044f8c0(0x2bf7840,param_3);
        }
        iVar1 = (*param_3)(*param_9 + 0x4000,param_8,param_4);
      } while ((iVar1 == -1) || (iVar1 == 4));
      if (iVar1 != 0) {
        if (param_5 != (code *)0x26f5a0) {
          func_0x0044f8c0(0x2bf7860,param_5);
        }
        (*param_5)(*param_9,param_6);
        *param_8 = 0;
      }
    }
  }
  else {
    *param_7 = 0;
  }
  return iVar1;
}



/* CONTEXT / separate function: adjacent_beb4c0 @ 0xbeb4c0; ev_dde4e451914038ae25bb92675687bb43a73fb792906446bae36b2d72e4d09d0c
 * Ghidra body ranges: 0xbeb4c0..0xbeb54e, 0xbeb550..0xbeb658
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

ulong adjacent_beb4c0(ulong param_1,uint param_2,long param_3,code *param_4,undefined8 param_5,
                     code *param_6,undefined8 param_7)

{
  int iVar1;
  ulong uVar2;
  ulong uVar3;
  ulong uVar4;
  uint uVar5;
  
  uVar4 = param_1 & 0xffffffffffffc000;
  if (param_2 != 0) {
    uVar3 = 0;
    do {
      uVar5 = (uint)uVar3;
      do {
        if (2 < (-(long)param_4 + 0x26f590U >> 3 | -(long)param_4 << 0x3d)) {
          func_0x0044f8c0(0x2bf7880,param_4);
        }
        uVar2 = (*param_4)((uVar5 << 0xe) + uVar4,param_3 + uVar3 * 8,param_5);
        iVar1 = (int)uVar2;
      } while ((iVar1 == -1) || (iVar1 == 4));
      if (iVar1 != 0) {
        if (uVar5 == 0) {
          return uVar2;
        }
        goto LAB_00beb5da;
      }
      uVar3 = uVar3 + 1;
    } while (uVar3 != param_2);
  }
  uVar2 = 0;
  if (param_1 != uVar4) {
    do {
      if (2 < (-(long)param_4 + 0x26f590U >> 3 | -(long)param_4 << 0x3d)) {
        func_0x0044f8c0(0x2bf78a0,param_4);
      }
      uVar2 = (*param_4)((param_2 << 0xe) + uVar4,param_3 + (ulong)param_2 * 8,param_5);
      iVar1 = (int)uVar2;
    } while ((iVar1 == -1) || (iVar1 == 4));
    if ((iVar1 != 0) && (uVar5 = param_2, param_2 != 0)) {
LAB_00beb5da:
      uVar3 = 0;
      do {
        if (param_6 != (code *)0x26f5a0) {
          func_0x0044f8c0(0x2bf78c0,param_6);
        }
        (*param_6)((uVar3 & 0xffffffff) + uVar4,param_7);
        uVar3 = uVar3 + 0x4000;
      } while ((ulong)uVar5 << 0xe != uVar3);
      uVar2 = uVar2 & 0xffffffff;
    }
  }
  return uVar2;
}



/* CONTEXT / separate function: adjacent_beb660 @ 0xbeb660; ev_c67f12d4b19735bd542544dcf992b58dc27f94fc77095ad9f74d2a5c6aa58f7a
 * Ghidra body ranges: 0xbeb660..0xbeb717
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_beb660(long param_1,long param_2,code *param_3,undefined8 param_4,long param_5)

{
  int iVar1;
  undefined8 uVar2;
  
  if (param_1 != 0) {
    do {
      if (param_3 != (code *)0x26f5a0) {
        func_0x0044f8c0(0x2bf78e0,param_3);
      }
      uVar2 = (*param_3)(param_5,param_4);
      iVar1 = (int)uVar2;
    } while ((iVar1 == -1) || (iVar1 == 4));
    if (iVar1 != 0) {
      return uVar2;
    }
  }
  if (param_2 == 0) {
    uVar2 = 0;
  }
  else {
    do {
      if (param_3 != (code *)0x26f5a0) {
        func_0x0044f8c0(0x2bf7900,param_3);
      }
      uVar2 = (*param_3)(param_5 + 0x4000,param_4);
    } while (((int)uVar2 == -1) || ((int)uVar2 == 4));
  }
  return uVar2;
}



/* CONTEXT / separate function: adjacent_beb720 @ 0xbeb720; ev_756a6cad5235d9c3c927f631b425cefe5dcd97c3028e9b6cc78b2575572b9be0
 * Ghidra body ranges: 0xbeb720..0xbeb79a, 0xbeb7a0..0xbeb806
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_beb720(ulong param_1,uint param_2,code *param_3,undefined8 param_4)

{
  int iVar1;
  undefined8 uVar2;
  ulong uVar3;
  ulong uVar4;
  
  uVar4 = param_1 & 0xffffffffffffc000;
  if (param_2 != 0) {
    uVar3 = 0;
    do {
      do {
        if (param_3 != (code *)0x26f5a0) {
          func_0x0044f8c0(0x2bf7920,param_3);
        }
        uVar2 = (*param_3)((uint)((int)uVar3 << 0xe) + uVar4,param_4);
        iVar1 = (int)uVar2;
      } while ((iVar1 == -1) || (iVar1 == 4));
      if (iVar1 != 0) {
        return uVar2;
      }
      uVar3 = uVar3 + 1;
    } while (uVar3 != param_2);
  }
  uVar2 = 0;
  if (uVar4 != param_1) {
    do {
      if (param_3 != (code *)0x26f5a0) {
        func_0x0044f8c0(0x2bf7940,param_3);
      }
      uVar2 = (*param_3)(uVar4 + (param_2 << 0xe),param_4);
    } while (((int)uVar2 == -1) || ((int)uVar2 == 4));
  }
  return uVar2;
}



/* CONTEXT / separate function: adjacent_beb810 @ 0xbeb810; ev_b072c16b04f1bdd8022cb216a01e7d84156b0a0bb2777f43bd9cb67624470594
 * Ghidra body ranges: 0xbeb810..0xbeb9e7
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int adjacent_beb810(ulong param_1,uint param_2,long param_3,undefined8 param_4,code *param_5,
                   undefined8 param_6,code *param_7,undefined8 param_8)

{
  code *pcVar1;
  int iVar2;
  ulong uVar3;
  ulong uVar4;
  undefined8 uVar5;
  long lVar6;
  ulong uVar7;
  long lVar8;
  undefined8 uVar9;
  ulong uVar10;
  long local_58;
  ulong local_48;
  long local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  if (param_2 == 0) {
    iVar2 = 0;
  }
  else {
    local_48 = (ulong)param_2;
    uVar7 = (ulong)((uint)param_1 & 0x3fff);
    local_58 = 0;
    uVar3 = 0x4000 - uVar7;
    uVar10 = param_1 & 0xffffffffffffc000;
    do {
      do {
        if (2 < (-(long)param_5 + 0x26f590U >> 3 | -(long)param_5 << 0x3d)) {
          func_0x0044f8c0(0x2bf7960,param_5);
        }
        iVar2 = (*param_5)(uVar10,&local_40,param_6);
      } while ((iVar2 == -1) || (iVar2 == 4));
      if (iVar2 != 0) {
        uVar9 = 0x13a1fc3;
        uVar5 = 0xd5;
LAB_00beb9b5:
        func_0x0025d410(uVar9,0x136d7dd,uVar5,iVar2);
        break;
      }
      if (uVar10 == (param_1 & 0xffffffffffffc000)) {
        uVar4 = uVar3;
        if (local_48 < uVar3) {
          uVar4 = local_48;
        }
        lVar6 = local_40 + uVar7;
        lVar8 = param_3;
      }
      else {
        lVar8 = param_3 + local_58;
        uVar4 = 0x4000;
        lVar6 = local_40;
        if (local_48 < 0x4000) {
          uVar4 = local_48;
        }
      }
      func_0x002590b0(lVar8,lVar6);
      do {
        if (param_7 != (code *)0x26f5a0) {
          func_0x0044f8c0(0x2bf7980,param_7);
        }
        iVar2 = (*param_7)(uVar10,param_8);
      } while ((iVar2 == -1) || (iVar2 == 4));
      if (iVar2 != 0) {
        uVar9 = 0x129d4a0;
        uVar5 = 0xf4;
        goto LAB_00beb9b5;
      }
      uVar10 = uVar10 + 0x4000;
      iVar2 = 0;
      local_58 = local_58 + uVar4;
      local_48 = local_48 - uVar4;
    } while (local_48 != 0);
  }
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar1 = (code *)invalidInstructionException();
    (*pcVar1)();
  }
  return iVar2;
}



/* CONTEXT / separate function: adjacent_beb9f0 @ 0xbeb9f0; ev_f32c2a06d84e017fb31306c8c606b2d5b320afce0a6ae33bf8dc12f68116a267
 * Ghidra body ranges: 0xbeb9f0..0xbebb78
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong adjacent_beb9f0(void)

{
  code *pcVar1;
  char cVar2;
  ulong uVar3;
  undefined1 local_2c [4];
  undefined8 local_28;
  long local_20;
  
  local_20 = _DAT_0391c310;
  uVar3 = func_0x00ab7ea0(1);
  if ((int)uVar3 == 0) {
    uVar3 = uVar3 & 0xffffffff;
    cVar2 = func_0x00a87e60(_DAT_039c9698,0);
    if (cVar2 != '\0') {
      local_2c[0] = 0;
      local_28 = 1;
      func_0x006f2150(0,_DAT_039c9698,0xffffffff,1,0x2701a0,0,local_2c,0);
    }
    cVar2 = func_0x00a87e60(_DAT_039c9698,1);
    if (cVar2 != '\0') {
      local_2c[0] = 1;
      local_28 = 1;
      func_0x006f2150(0,_DAT_039c9698,0xffffffff,1,0x2701a0,0,local_2c,0);
    }
    cVar2 = func_0x00a87e60(_DAT_039c9698,2);
    if (cVar2 != '\0') {
      local_2c[0] = 2;
      local_28 = 1;
      func_0x006f2150(0,_DAT_039c9698,0xffffffff,1,0x2701a0,0,local_2c,0);
    }
    cVar2 = func_0x00a87e60(_DAT_039c9698,0x7e);
    if (cVar2 != '\0') {
      local_2c[0] = 0x7e;
      local_28 = 1;
      func_0x006f2150(0,_DAT_039c9698,0xffffffff,1,0x2701a0,0,local_2c,0);
    }
    func_0x00ab7f20(1);
  }
  if (_DAT_0391c310 == local_20) {
    return uVar3;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* CONTEXT / separate function: adjacent_bebb80 @ 0xbebb80; ev_c9417aeacf6d5f349db686dace38f1b9980bf2e8d14ff6ef0e1e1f16eae72885
 * Ghidra body ranges: 0xbebb80..0xbebc12, 0xbebc20..0xbebca8
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void adjacent_bebb80(long param_1,int param_2,undefined4 param_3)

{
  code *pcVar1;
  int iVar2;
  long *plVar3;
  undefined1 local_7c [4];
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70 [2];
  undefined4 *local_68;
  undefined8 local_60;
  undefined4 local_58 [2];
  undefined8 local_50;
  undefined4 local_40;
  undefined8 local_38;
  long local_28;
  
  local_28 = _DAT_0391c310;
  local_7c[0] = (undefined1)param_2;
  local_74 = 0;
  local_78 = param_3;
  func_0x006f2150(0,param_1,0xffffffff,1,0x2701a0,0,local_7c,0);
  if ((param_2 == 3) && (param_1 != 0)) {
    func_0x00ab7f20(1);
    iVar2 = func_0x00912a30(param_1,0x12d10cd,&local_60);
    if (iVar2 == 0) {
      plVar3 = (long *)0x0;
      do {
        plVar3 = (long *)func_0x006f2130(param_1,plVar3);
        if (plVar3 == (long *)0x0) {
          local_68 = local_58;
          local_70[0] = 2;
          local_58[0] = 1;
          local_50 = 3;
          local_40 = 1;
          local_38 = 1;
          func_0x0088e3f0(local_60,0,local_70,0);
          break;
        }
      } while (((*(char *)((long)plVar3 + 9) != '\n') || (*plVar3 == 0)) ||
              (*(char *)(*plVar3 + 0xd) != '\x03'));
    }
    func_0x00ab7ea0(1);
  }
  if (_DAT_0391c310 != local_28) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar1 = (code *)invalidInstructionException();
    (*pcVar1)();
  }
  return;
}



/* CONTEXT / separate function: adjacent_bebcb0 @ 0xbebcb0; ev_bc2f4f3130b019a4c8fd787a52796e4a2f5217fd36cdb86492e74b622dcd1dc3
 * Ghidra body ranges: 0xbebcb0..0xbebfa4
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int adjacent_bebcb0(long param_1,long param_2,undefined4 param_3,uint param_4,undefined4 param_5,
                   undefined8 param_6)

{
  long lVar1;
  undefined8 *puVar2;
  code *pcVar3;
  int iVar4;
  long lVar5;
  undefined8 uVar6;
  undefined8 uVar7;
  char cVar8;
  ulong uVar9;
  undefined8 extraout_RDX;
  undefined8 extraout_RDX_00;
  ulong uVar10;
  undefined1 auVar11 [16];
  undefined4 local_54;
  undefined8 local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  local_40 = 0;
  auVar11 = func_0x005d9220();
  uVar6 = auVar11._8_8_;
  lVar5 = auVar11._0_8_;
  iVar4 = 6;
  if (lVar5 != 0) {
    lVar1 = *(long *)(param_1 + 0x18);
    if (lVar1 == 0) {
      uVar6 = func_0x004c9c80(*(undefined8 *)(param_1 + 0x10));
      uVar7 = func_0x004c9b70(*(undefined1 *)(param_1 + 0xd));
      func_0x006f79f0(0x1a48096,0xb4,0x134e405,uVar6,param_1,uVar7);
    }
    else {
      puVar2 = *(undefined8 **)(lVar1 + 0x20);
      if ((*(byte *)(param_1 + 0xc) & 0x20) == 0) {
        pcVar3 = *(code **)(lVar1 + 0x28);
        if (pcVar3 == (code *)0x0) {
          uVar6 = func_0x004c9b70(*(undefined1 *)(param_1 + 0xd));
          func_0x006f79f0(0x1a48096,0xcb,0x1358e93,param_1,uVar6);
          goto LAB_00bebf44;
        }
        func_0x009bd880();
        if (0x12 < (-(long)pcVar3 + 0x2701c0U >> 3 | -(long)pcVar3 << 0x3d)) {
          func_0x0044f8c0(0x2bf79a0,pcVar3);
        }
        iVar4 = (*pcVar3)(param_1,0,puVar2,&local_40);
        func_0x009bd850();
        if (iVar4 != 0) {
          uVar6 = func_0x004c9b70(*(undefined1 *)(param_1 + 0xd));
          func_0x006f7a90(0x1a48096,0xe3,iVar4,0x136d807,uVar6);
          goto LAB_00bebf44;
        }
        uVar6 = extraout_RDX;
        if (((*(byte *)(param_1 + 0xc) & 0x20) == 0) &&
           (*(byte *)(param_1 + 0xc) = *(byte *)(param_1 + 0xc) | 0x20, *(long *)(lVar5 + 0x20) == 0
           )) {
          *(undefined8 *)(lVar5 + 0x20) = local_40;
        }
      }
      uVar10 = (ulong)param_4 + *(long *)(param_1 + 0x28);
      pcVar3 = *(code **)(lVar1 + 0x10);
      cVar8 = *(char *)(param_1 + 0xd);
      if (((param_2 != 0) && (cVar8 == '\t')) && (puVar2 != (undefined8 *)0x0)) {
        *puVar2 = *(undefined8 *)(param_2 + 0x30);
        *(undefined2 *)(puVar2 + 1) = *(undefined2 *)(param_2 + 0x26);
        *(undefined1 *)((long)puVar2 + 10) = *(undefined1 *)(param_2 + 0x25);
        cVar8 = *(char *)(param_1 + 0xd);
      }
      local_54 = param_5;
      if (((param_2 != 0) && (cVar8 == '\b')) && (puVar2 != (undefined8 *)0x0)) {
        *puVar2 = *(undefined8 *)(param_2 + 0x30);
        *(undefined2 *)(puVar2 + 1) = *(undefined2 *)(param_2 + 0x26);
        *(undefined1 *)((long)puVar2 + 10) = *(undefined1 *)(param_2 + 0x25);
        uVar10 = (ulong)*(ushort *)(param_2 + 0x38);
        local_54 = *(undefined4 *)(param_2 + 0x18);
      }
      if ((*(byte *)(lVar1 + 0xe) & 1) == 0) {
        func_0x009bd880();
        uVar6 = extraout_RDX_00;
      }
      uVar9 = -(long)pcVar3 + 0x270210U >> 3 | -(long)pcVar3 << 0x3d;
      if (6 < uVar9) {
        func_0x0044f8c0(0x2bf79c0,pcVar3,uVar6,uVar9,puVar2);
      }
      iVar4 = (*pcVar3)(param_3,uVar10,local_54,param_6,puVar2,*(undefined8 *)(lVar5 + 0x20));
      if (iVar4 != 0) {
        uVar6 = func_0x004c9b70(*(undefined1 *)(param_1 + 0xd));
        func_0x006f7a90(0x1a48096,0x13c,iVar4,0x134e42d,uVar6);
      }
      if ((*(byte *)(lVar1 + 0xe) & 1) == 0) {
        func_0x009bd850();
      }
    }
  }
LAB_00bebf44:
  if (_DAT_0391c310 == local_38) {
    return iVar4;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar3 = (code *)invalidInstructionException();
  (*pcVar3)();
}



/* CONTEXT / separate function: adjacent_bebfb0 @ 0xbebfb0; ev_799e1f0ef0ae8e1bd3ba89ae150dd5fb1dd39cc2781ae8c243a502239803c90b
 * Ghidra body ranges: 0xbebfb0..0xbec15e
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void adjacent_bebfb0(long param_1,char param_2)

{
  long *plVar1;
  long lVar2;
  code *pcVar3;
  int iVar4;
  long lVar5;
  undefined8 *puVar6;
  undefined8 uVar7;
  long *plVar8;
  undefined8 extraout_RDX;
  undefined8 extraout_RDX_00;
  undefined8 extraout_RDX_01;
  bool bVar9;
  
  lVar5 = func_0x005d9220();
  if ((lVar5 != 0) && (lVar2 = *(long *)(param_1 + 0x18), lVar2 != 0)) {
    puVar6 = (undefined8 *)(lVar5 + 0x20);
    plVar8 = (long *)(lVar2 + 0x30);
    lVar5 = *(long *)(lVar2 + 0x30);
    while (lVar5 != 0) {
      plVar1 = (long *)(lVar5 + 0x20);
      bVar9 = lVar5 == param_1;
      lVar5 = *(long *)(lVar5 + 0x20);
      if (bVar9) {
        *plVar8 = lVar5;
        *plVar1 = 0;
        if ((param_2 != '\0') && (iVar4 = func_0x00ab7f20(1), iVar4 != 0)) {
          return;
        }
        iVar4 = adjacent_bec160(param_1,0);
        uVar7 = extraout_RDX;
        if (iVar4 != 0) {
          uVar7 = func_0x004c9b70(*(undefined1 *)(param_1 + 0xd));
          func_0x006f7a90(0x1a48096,0x1a2,iVar4,0x12b19c4,uVar7);
          uVar7 = extraout_RDX_00;
        }
        if ((param_2 != '\0') && (iVar4 = func_0x00ab7ea0(1), uVar7 = extraout_RDX_01, iVar4 != 0))
        {
          return;
        }
        if ((*(byte *)(param_1 + 0xc) & 0x20) != 0) {
          pcVar3 = *(code **)(lVar2 + 0x28);
          if (0x12 < (-(long)pcVar3 + 0x2701c0U >> 3 | -(long)pcVar3 << 0x3d)) {
            func_0x0044f8c0(0x2bf79e0,pcVar3,uVar7,puVar6);
          }
          iVar4 = (*pcVar3)(param_1,1,*(undefined8 *)(lVar2 + 0x20),puVar6);
          if (puVar6 != (undefined8 *)0x0) {
            *puVar6 = 0;
          }
          if (iVar4 != 0) {
            uVar7 = func_0x004c9b70(*(undefined1 *)(param_1 + 0xd));
            func_0x006f7a90(0x1a48096,0x1c6,iVar4,0x12db97d,uVar7);
          }
          *(byte *)(param_1 + 0xc) = *(byte *)(param_1 + 0xc) & 0xdf;
        }
        *(undefined8 *)(param_1 + 0x18) = 0;
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      plVar8 = plVar1;
      if (lVar5 == *(long *)(lVar2 + 0x30)) {
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
    }
  }
  return;
}



/* CONTEXT / separate function: adjacent_bec160 @ 0xbec160; ev_298329025b625180338254ec746547726f8a0a9d98f8fbfd454d653b1480c24c
 * Ghidra body ranges: 0xbec160..0xbec2fd
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int adjacent_bec160(long param_1,int param_2)

{
  code *pcVar1;
  int iVar2;
  long lVar3;
  undefined8 *puVar4;
  long local_60;
  long local_58;
  long local_50;
  undefined8 local_48;
  long local_38;
  
  local_38 = _DAT_0391c310;
  iVar2 = 0;
  if ((DAT_039c9324 != '\0') && (*(long *)(param_1 + 0x18) != 0)) {
    lVar3 = func_0x005d9220(param_1);
    if (lVar3 == 0) {
      iVar2 = 6;
    }
    else {
      iVar2 = func_0x009b81e0(0x4745525f,*(undefined8 *)(*(long *)(param_1 + 0x10) + 0x10),8,
                              &local_60);
      if (iVar2 == 0) {
        *(long *)(lVar3 + 0x10) = local_60;
      }
      else {
        local_60 = *(long *)(lVar3 + 0x10);
      }
      iVar2 = 0;
      if (local_60 != 0) {
        iVar2 = 0;
        if (param_2 == 1) {
          if ((*(byte *)(param_1 + 0xc) & 0x10) != 0) goto LAB_00bec2db;
        }
        else if ((param_2 == 0) && ((*(byte *)(param_1 + 0xc) & 0x10) == 0)) goto LAB_00bec2db;
        puVar4 = (undefined8 *)func_0x005356f0(0x58);
        if (puVar4 == (undefined8 *)0x0) {
          iVar2 = 4;
        }
        else {
          *puVar4 = *(undefined8 *)(lVar3 + 0x10);
          puVar4[1] = 0;
          puVar4[2] = &local_58;
          *(undefined1 *)((long)puVar4 + 0x55) = 1;
          local_58 = func_0x00cac6e0(*(undefined1 *)(param_1 + 0xd));
          if (local_58 == 0) {
            iVar2 = 4;
          }
          else {
            local_50 = func_0x00cac6e0(param_2);
            if (local_50 == 0) {
              iVar2 = 4;
            }
            else {
              local_48 = 0;
              iVar2 = func_0x003397d0(puVar4);
              func_0x00b4a4c0(local_50);
              if (iVar2 == 0) {
                iVar2 = 0;
                *(byte *)(param_1 + 0xc) = (param_2 == 1) << 4 | *(byte *)(param_1 + 0xc) & 0xef;
              }
            }
            func_0x00b4a4c0(local_58);
          }
          func_0x009bf3a0(puVar4);
        }
      }
    }
  }
LAB_00bec2db:
  if (_DAT_0391c310 == local_38) {
    return iVar2;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* CONTEXT / separate function: adjacent_bec30d @ 0xbec30d; ev_58890792d792f160de611abf0893875fae3a7877e240801b05668692f6dd4354
 * Ghidra body ranges: 0xbec30d..0xbec329
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_bec30d(long param_1,long param_2)

{
  *(undefined8 *)(param_2 + 0x20) = *(undefined8 *)(param_1 + 0x30);
  *(long *)(param_1 + 0x30) = param_2;
  *(long *)(param_2 + 0x18) = param_1;
  func_0x00b4aab0();
  return 0;
}



/* CONTEXT / separate function: adjacent_bec330 @ 0xbec330; ev_0125f33a221bdc0335d0d0ccd012dfe303a8c15404889dfa230cedf0e5494f51
 * Ghidra body ranges: 0xbec330..0xbec391
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted.", "Ghidra Listing reports a terminal call at 0xbec37d to 0xbec160 adjacent_bec160 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 adjacent_bec330(undefined8 param_1,undefined8 param_2,char *param_3)

{
  long lVar1;
  undefined8 uVar2;
  
  lVar1 = func_0x00ac6e80();
  if (lVar1 == 0) {
    uVar2 = 0x1001;
  }
  else {
    uVar2 = 0;
    if ((*(char *)(lVar1 + 9) == '\n') || (lVar1 == _DAT_039c9698)) {
      lVar1 = func_0x005d91c0();
      if (lVar1 == 0) {
        uVar2 = 0;
      }
      else {
        uVar2 = 0;
        if (*(char *)(lVar1 + 0xd) == *param_3) {
          *(int *)(param_3 + 8) = *(int *)(param_3 + 8) + 1;
          uVar2 = adjacent_bec160(lVar1,*(undefined4 *)(param_3 + 4));
          return uVar2;
        }
      }
    }
  }
  return uVar2;
}



/* CONTEXT / separate function: adjacent_bec3a0 @ 0xbec3a0; ev_da7f733735f40933e668eb120fff3069c4025ed1c78926c42f0e7e5a80fe0bd4
 * Ghidra body ranges: 0xbec3a0..0xbec45e, 0xbec474..0xbec494, 0xbec49e..0xbec53a, 0xbec587..0xbec5bd
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Possible PIC construction at 0x00bec508: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x00bec50d) */

void adjacent_bec3a0(float param_1)

{
  ulong uVar1;
  float fVar2;
  int iVar3;
  float fVar4;
  float fVar5;
  undefined1 auVar6 [16];
  undefined1 in_ZMM0 [64];
  
  fVar5 = in_ZMM0._0_4_;
  fVar4 = ABS(param_1);
  fVar2 = ABS(fVar5);
  if ((uint)fVar2 < 0x7f800001 && (uint)fVar4 < 0x7f800001) {
    if (param_1 == 1.0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    if (fVar2 != 0.0) {
      if (fVar4 == INFINITY) {
        uVar1 = (ulong)(uint)(((int)param_1 >> 0x1f) * -2 - ((int)fVar5 >> 0x1f));
        if (fVar2 != INFINITY) {
                    /* WARNING: Could not recover jumptable at 0x00bec493. Too many branches */
                    /* WARNING: Treating indirect jump as call */
          (*(code *)((long)*(int *)(uVar1 * 4 + 0x1a480a8) + 0x1a480a8))();
          return;
        }
                    /* WARNING: Could not recover jumptable at 0x00bec45d. Too many branches */
                    /* WARNING: Treating indirect jump as call */
        (*(code *)((long)*(int *)(uVar1 * 4 + 0x1a480b8) + 0x1a480b8))();
        return;
      }
      if ((((fVar4 != 0.0) && (fVar2 != INFINITY)) &&
          (iVar3 = (int)fVar2 - (int)fVar4 >> 0x17, iVar3 < 0x1b)) &&
         (-1 < (int)param_1 || -0x1b < iVar3)) {
        auVar6._0_4_ = fVar5 / param_1;
        auVar6._4_12_ = in_ZMM0._4_12_;
        func_0x006e2c00(auVar6._0_8_);
        halt_baddata();
      }
    }
  }
  return;
}



/* CONTEXT / separate function: adjacent_bec5c0 @ 0xbec5c0; ev_7fff44eeca770a526794fffa2e4f69917ed65a9edf1ed557cb7afc4971b05493
 * Ghidra body ranges: 0xbec5c0..0xbec739
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void adjacent_bec5c0(char param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  int iVar1;
  ulong uVar2;
  
  if (DAT_03d96f88 == '\0' || DAT_03d96f88 == param_1) {
    iVar1 = 0;
  }
  else {
    iVar1 = 1;
    if ((((((DAT_03d96fa8 != '\0' && DAT_03d96fa8 != param_1) &&
           (iVar1 = 2, DAT_03d96fc8 != '\0' && DAT_03d96fc8 != param_1)) &&
          (iVar1 = 3, DAT_03d96fe8 != '\0' && DAT_03d96fe8 != param_1)) &&
         ((iVar1 = 4, DAT_03d97008 != '\0' && DAT_03d97008 != param_1 &&
          (iVar1 = 5, DAT_03d97028 != '\0' && DAT_03d97028 != param_1)))) &&
        ((iVar1 = 6, DAT_03d97048 != '\0' && DAT_03d97048 != param_1 &&
         ((iVar1 = 7, DAT_03d97068 != '\0' && DAT_03d97068 != param_1 &&
          (iVar1 = 8, DAT_03d97088 != '\0' && DAT_03d97088 != param_1)))))) &&
       (iVar1 = 9, DAT_03d970a8 != '\0' && DAT_03d970a8 != param_1)) {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
  }
  uVar2 = (ulong)(uint)(iVar1 << 5);
  (&DAT_03d96f88)[uVar2] = param_1;
  *(undefined8 *)(uVar2 + 0x3d96f70) = param_2;
  *(undefined8 *)(uVar2 + 0x3d96f78) = param_3;
  *(undefined8 *)(uVar2 + 0x3d96f80) = param_4;
  return;
}



/* CONTEXT / separate function: adjacent_bec740 @ 0xbec740; ev_2e3fbe4434690c991d4ad568554c3ee0c8a9e7bf5a8a78c8d00fe92b7cdcfc7f
 * Ghidra body ranges: 0xbec740..0xbec968
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Possible PIC construction at 0x00bec881: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x00bec886) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void adjacent_bec740(char param_1,long param_2)

{
  code *pcVar1;
  int iVar2;
  ulong uVar3;
  uint uVar4;
  ulong uVar5;
  
  if (DAT_03d96f88 == param_1) {
    iVar2 = 0;
  }
  else {
    iVar2 = 1;
    if ((((((DAT_03d96fa8 != param_1) && (iVar2 = 2, DAT_03d96fc8 != param_1)) &&
          (iVar2 = 3, DAT_03d96fe8 != param_1)) &&
         ((iVar2 = 4, DAT_03d97008 != param_1 && (iVar2 = 5, DAT_03d97028 != param_1)))) &&
        ((iVar2 = 6, DAT_03d97048 != param_1 &&
         ((iVar2 = 7, DAT_03d97068 != param_1 && (iVar2 = 8, DAT_03d97088 != param_1)))))) &&
       (iVar2 = 9, DAT_03d970a8 != param_1)) {
      halt_baddata();
    }
  }
  uVar3 = (ulong)(uint)(iVar2 << 5);
  pcVar1 = *(code **)(uVar3 + 0x3d96f70);
  if (pcVar1 != (code *)0x0) {
    if (0x197 < (-(long)pcVar1 + 0x267e88U >> 3 | -(long)pcVar1 << 0x3d)) {
      func_0x0044f8c0(0x2bf7a10,pcVar1);
    }
    (*pcVar1)(*(undefined8 *)(uVar3 + 0x3d96f80),param_2);
  }
  if (*(long *)(uVar3 + 0x3d96f78) != 0) {
    func_0x004c6a00(0x3d96c90,0,0,0);
    if (_DAT_03d96f6c + 1 + ((_DAT_03d96f6c + 1) / 0x1e) * -0x1f + (_DAT_03d96f6c + 1) / 0x1e ==
        _DAT_03d96f68) {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    *(undefined2 *)((ulong)_DAT_03d96f6c * 0x18 + 0x3d96c9c) = *(undefined2 *)(param_2 + 2);
    uVar5 = (ulong)_DAT_03d96f6c;
    *(undefined4 *)(uVar5 * 0x18 + 0x3d96c98) = *(undefined4 *)(param_2 + 0xc);
    *(undefined8 *)(uVar5 * 0x18 + 0x3d96ca0) = *(undefined8 *)(uVar3 + 0x3d96f78);
    *(undefined8 *)(uVar5 * 0x18 + 0x3d96ca8) = *(undefined8 *)(uVar3 + 0x3d96f80);
    uVar4 = _DAT_03d96f6c + 1;
    _DAT_03d96f6c = _DAT_03d96f6c + 1 + uVar4 / 0x1e + uVar4 / 0x1e + (uVar4 / 0x1e) * -0x20;
    func_0x00c06910(0x3d96c98);
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  return;
}



/* CONTEXT / separate function: adjacent_bec970 @ 0xbec970; ev_d09f70a8f1b2e238f9b30fef98410f50ccec0e5d797296c2ef06508180cc5802
 * Ghidra body ranges: 0xbec970..0xbeca22
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void adjacent_bec970(long param_1)

{
  undefined2 *puVar1;
  ulong uVar2;
  
  func_0x0025d410(0x13432eb);
  func_0x0025d410(0x1319d03,*(undefined4 *)(param_1 + 0x2d0));
  func_0x0025d410(0x129338d,*(undefined4 *)(param_1 + 0x2d4));
  puVar1 = (undefined2 *)(param_1 + 4);
  uVar2 = 0;
  do {
    func_0x0025d410(0x12bb918,uVar2 & 0xffffffff);
    func_0x0025d410(0x12f0127,*puVar1);
    func_0x0025d410(0x1377fc3,*(undefined4 *)(puVar1 + -2));
    uVar2 = uVar2 + 1;
    puVar1 = puVar1 + 0xc;
  } while (uVar2 != 0x1e);
  return;
}



/* CONTEXT / separate function: adjacent_beca30 @ 0xbeca30; ev_58afea5e9731a78326c5db3910443a11e49df8e85da378c3518762e65657c016
 * Ghidra body ranges: 0xbeca30..0xbeca85
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void adjacent_beca30(void)

{
  func_0x00258ff0(0x3d96c70,0x448);
  func_0x004c7dd0(0x3d96c90,0x13432e2,0,0);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* CONTEXT / separate function: adjacent_beca90 @ 0xbeca90; ev_11f76f1da0964dda26ba8d9e81e302c3f75c55701008322eebb18bf918175750
 * Ghidra body ranges: 0xbeca90..0xbecb48, 0xbecb50..0xbecba6, 0xbecbb0..0xbecc47
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void adjacent_beca90(undefined8 *param_1)

{
  undefined8 *puVar1;
  uint uVar2;
  undefined8 uVar3;
  code *pcVar4;
  undefined8 *in_GS_OFFSET;
  
  func_0x00926460(0x138cd14,0x44,0x21000000,0);
  uVar3 = *in_GS_OFFSET;
  *param_1 = uVar3;
  *(undefined4 *)(param_1 + 0x88) = 1;
  func_0x0073e000(0,0x1378c65,0x2609e0,param_1,10000,uVar3,0x2610d0);
  func_0x0073e000(0,0x1364ad9,0x2609e8,param_1,0,uVar3,0x2610d8);
  puVar1 = param_1 + 4;
LAB_00becb63:
  do {
    func_0x004c6a00(puVar1,0,0,0);
    while (uVar2 = *(uint *)(param_1 + 0x5f), uVar2 == *(uint *)((long)param_1 + 0x2fc)) {
      if (*(int *)(param_1 + 0x88) == 2) {
        func_0x004c6fa0(puVar1,0,0);
        func_0x009261b0();
        goto LAB_00becb63;
      }
      func_0x00c06260(param_1 + 5,param_1 + 1,0,0x13ac966,0,0,0x100);
    }
    pcVar4 = (code *)param_1[(ulong)uVar2 * 3 + 6];
    uVar3 = param_1[(ulong)uVar2 * 3 + 7];
    *(uint *)(param_1 + 0x5f) = uVar2 + 1 + ((uVar2 + 1) / 0x1e) * -0x1f + (uVar2 + 1) / 0x1e;
    func_0x004c6fa0(puVar1,0,0);
    if (0x197 < (-(long)pcVar4 + 0x267e88U >> 3 | -(long)pcVar4 << 0x3d)) {
      func_0x0044f8c0(0x2bf7a30,pcVar4);
    }
    (*pcVar4)(uVar3);
  } while( true );
}



/* CONTEXT / separate function: adjacent_becc50 @ 0xbecc50; ev_ccf296e6fc2b306fa8df322ebf8259c281848eab2ec253c4d449d2fb4dcbc635
 * Ghidra body ranges: 0xbecc50..0xbecd2f
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 adjacent_becc50(undefined8 *param_1)

{
  undefined8 *puVar1;
  code *pcVar2;
  int iVar3;
  undefined8 uVar4;
  undefined8 uVar5;
  
  iVar3 = func_0x00925fa0(*param_1);
  if (iVar3 == 0) {
    puVar1 = param_1 + 4;
    func_0x004c6a00(puVar1,0,0,0);
    *(undefined4 *)(param_1 + 0x88) = 2;
    func_0x00c06910(param_1 + 5);
    func_0x004c6fa0(puVar1,0,0,0);
    iVar3 = func_0x00926030(*param_1,_DAT_03920440 * 0x3c);
    if (iVar3 == 0) {
      return 0;
    }
    func_0x004c6a00(puVar1,0,0,0);
    adjacent_bec970(param_1 + 5);
    func_0x004c6fa0(puVar1,0,0,0);
    func_0x007f1c70(*param_1);
    func_0x007f1950();
    func_0x007f1810(0xbecd0a);
    uVar4 = 0x13b7627;
    uVar5 = 7;
  }
  else {
    func_0x007f1950();
    func_0x007f1810(0xbeccbf);
    uVar4 = 0x12db9a4;
    uVar5 = 3;
  }
  func_0x00c9aa10(uVar5,uVar4);
                    /* WARNING: Does not return */
  pcVar2 = (code *)invalidInstructionException();
  (*pcVar2)();
}



/* CONTEXT / separate function: adjacent_becd30 @ 0xbecd30; ev_347dc7158ebbfa64bfad26b4e2a960293b1bba99df9bdd46eed87ba5b3f34002
 * Ghidra body ranges: 0xbecd30..0xbecd9c
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_becd30(undefined8 *param_1)

{
  code *pcVar1;
  int iVar2;
  
  func_0x004c6a00(param_1 + 4,0,0,0);
  *(undefined4 *)(param_1 + 0x88) = 1;
  func_0x004c6fa0(param_1 + 4,0,0,0);
  iVar2 = func_0x00926120(*param_1);
  if (iVar2 == 0) {
    return 0;
  }
  func_0x007f1950();
  func_0x007f1810(0xbecd77);
  func_0x00c9aa10(0xb,0x136d82a);
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* CONTEXT / separate function: FUN_00becda0 @ 0xbecda0; ev_3aa6f64b48c60396523314e9e5a1ca1f3809ac8d829b3ed74234979cf2b1b079
 * Ghidra body ranges: 0xbecda0..0xbecded
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

long FUN_00becda0(long param_1,undefined8 param_2,uint param_3)

{
  code *pcVar1;
  ulong *in_GS_OFFSET;
  
  if ((_DAT_03d974c8 & 0xfffffffffffffff8) == *in_GS_OFFSET) {
    return param_1 + (ulong)((param_3 ^ (uint)param_2 ^ (uint)((ulong)param_2 >> 0x20)) % 0x7f) *
                     0x38;
  }
  func_0x007f1950();
  func_0x007f18a0(adjacent_becdee,0x6b);
  func_0x00c9aa10(0xb,0x1363945,0x6b);
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* CONTEXT / separate function: adjacent_becdee @ 0xbecdee; ev_3c6dc1650b15015dfddc3fec76ce23987ea32d95f5b4f1b9f4a578452163c0ee
 * Ghidra body ranges: 0xbecdee..0xbece21
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void adjacent_becdee(void)

{
  code *pcVar1;
  
  func_0x007f1950();
  func_0x007f18a0(adjacent_becdee,0x6b);
  func_0x00c9aa10(0xb,0x1363945,0x6b);
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* CONTEXT / separate function: FUN_00bece30 @ 0xbece30; ev_582f85298d917bc228cdaaa71a5305cdca1f8399d60e6c165371fa48efa7adcc
 * Ghidra body ranges: 0xbece30..0xbece77
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

long FUN_00bece30(int param_1)

{
  code *pcVar1;
  ulong *in_GS_OFFSET;
  
  if ((_DAT_03d974c8 & 0xfffffffffffffff8) == *in_GS_OFFSET) {
    return (ulong)(uint)(param_1 % 0x7f) * 8 + 0x3d970b8;
  }
  func_0x007f1950();
  func_0x007f18a0(adjacent_bece78,0x73);
  func_0x00c9aa10(0xf,0x1363945,0x73);
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* CONTEXT / separate function: adjacent_bece78 @ 0xbece78; ev_467658be93ec6062d25641c61c4c946733ad4b0ea3ff1f06ba79b8fecaa45155
 * Ghidra body ranges: 0xbece78..0xbeceab
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void adjacent_bece78(void)

{
  code *pcVar1;
  
  func_0x007f1950();
  func_0x007f18a0(adjacent_bece78,0x73);
  func_0x00c9aa10(0xf,0x1363945,0x73);
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* CONTEXT / separate function: adjacent_beceb0 @ 0xbeceb0; ev_15d81c457e10400f57efc9bdb59138cabc71a95051c9b6100d9e1ee21296350c
 * Ghidra body ranges: 0xbeceb0..0xbecf43
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int * adjacent_beceb0(int param_1)

{
  int *piVar1;
  code *pcVar2;
  undefined8 *puVar3;
  ulong *in_GS_OFFSET;
  
  if ((_DAT_03d974c8 & 0xfffffffffffffff8) != *in_GS_OFFSET) {
    func_0x007f1950();
    func_0x007f18a0(0xbecf14,0x7c);
    func_0x00c9aa10(0x13,0x1363945,0x7c);
                    /* WARNING: Does not return */
    pcVar2 = (code *)invalidInstructionException();
    (*pcVar2)();
  }
  puVar3 = (undefined8 *)FUN_00bece30();
  FUN_00becf50(puVar3 != (undefined8 *)0x0,0x12c656f,0x12b1a16);
  piVar1 = (int *)*puVar3;
  while( true ) {
    if (piVar1 == (int *)0x0) {
      return (int *)0x0;
    }
    if (*piVar1 == param_1) break;
    piVar1 = *(int **)(piVar1 + 2);
  }
  return piVar1;
}



/* CONTEXT / separate function: FUN_00becf50 @ 0xbecf50; ev_b5ca48d3877ee133e9281ac2451b76784ee6c69597992495e32826eabd2bebe8
 * Ghidra body ranges: 0xbecf50..0xbecf54
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void FUN_00becf50(int param_1)

{
  code *pcVar1;
  
  if (param_1 != 0) {
    return;
  }
  func_0x0025d410(0x12c65b5);
  func_0x007f1950();
  func_0x007f1810(0xbecf67);
  func_0x00c9aa10(0x23,0x138216d);
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* CONTEXT / separate function: adjacent_becf55 @ 0xbecf55; ev_3243d3226fa842ab34bea3d8f85a6d6efab4beb270181aba94da63948c07d656
 * Ghidra body ranges: 0xbecf55..0xbecf8c
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void adjacent_becf55(void)

{
  code *pcVar1;
  
  func_0x0025d410(0x12c65b5);
  func_0x007f1950();
  func_0x007f1810(0xbecf67);
  func_0x00c9aa10(0x23,0x138216d);
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* CONTEXT / separate function: adjacent_becf90 @ 0xbecf90; ev_59a0737d3758ee4cfd5fe1ea802a0a9f7304f4bc17c6fd14d7d30496c3042869
 * Ghidra body ranges: 0xbecf90..0xbed195
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

char adjacent_becf90(undefined4 param_1,ulong param_2,undefined4 param_3,undefined8 param_4)

{
  long lVar1;
  code *pcVar2;
  int iVar3;
  long lVar4;
  long lVar5;
  char cVar6;
  long local_60;
  undefined4 local_58 [2];
  ulong local_50;
  undefined8 local_48;
  int local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  lVar4 = func_0x0053c170();
  cVar6 = '\x16';
  if (lVar4 != 0) {
    *(int *)(lVar4 + 0x358) = *(int *)(lVar4 + 0x358) + 1;
    if ((*(byte *)(lVar4 + 0xb3) & 0x10) == 0) {
      func_0x0053aa10(lVar4);
    }
    lVar1 = lVar4 + 0x148;
    func_0x004c6fa0(lVar1,0,0,0);
    local_60 = 0;
    lVar5 = func_0x00399ee0(*(undefined8 *)(lVar4 + 0xc48),param_2 >> 0x20,0x1107,&local_60);
    func_0x004c6a00(lVar1,0,0,0);
    iVar3 = *(int *)(lVar4 + 0x358) + -1;
    *(int *)(lVar4 + 0x358) = iVar3;
    if ((iVar3 == 0 & *(byte *)(lVar4 + 0xb1) >> 5) == 1) {
      func_0x00c06910(lVar4 + 0x358);
    }
    func_0x004c6fa0(lVar1,0,0,0);
    cVar6 = '\t';
    if (lVar5 != 0) {
      lVar4 = *(long *)(lVar5 + 8);
      if (local_60 != 0) {
        func_0x00399eb0();
      }
      if ((int)param_2 == (int)lVar4 && lVar4 != 0) {
        func_0x004c6a00(&DAT_03d974c8,0,0,0);
        lVar4 = adjacent_beceb0(param_1);
        if (lVar4 == 0) {
          func_0x004c6fa0(&DAT_03d974c8,0,0,0);
          cVar6 = '\x16';
        }
        else {
          lVar4 = FUN_00becda0(lVar4 + 0x10,param_2,param_3);
          FUN_00becf50(lVar4 != 0,0x12e568c,0x13639aa);
          local_40 = 0;
          local_58[0] = param_3;
          local_50 = param_2;
          local_48 = param_4;
          func_0x00313d50(lVar4,local_58,1);
          func_0x004c6fa0(&DAT_03d974c8,0,0,0);
          cVar6 = (local_40 == 0) * '\x02';
        }
      }
    }
  }
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar2 = (code *)invalidInstructionException();
    (*pcVar2)();
  }
  return cVar6;
}



/* CONTEXT / separate function: adjacent_bed1a0 @ 0xbed1a0; ev_6cb3151ae004885c4aaf3f5b95a238915efcd7153c6b9b53218ce93dd876124d
 * Ghidra body ranges: 0xbed1a0..0xbed1b7
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 adjacent_bed1a0(undefined4 param_1)

{
  func_0x00313d50(0x3d974d0,param_1,0);
  return 0;
}



/* CONTEXT / separate function: adjacent_bed1c0 @ 0xbed1c0; ev_8d2251919410c2cd6dd14453009b924acbed39676e1a6bffadfc111973fe564c
 * Ghidra body ranges: 0xbed1c0..0xbed2a1
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void adjacent_bed1c0(void)

{
  code *pcVar1;
  int iVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  
  func_0x004c7dd0(&DAT_03d974c8,0x12db9bc,0,0);
  func_0x004c7dd0(0x3d97520,0x1338d40,0,0);
  _DAT_03d97528 = func_0x0073dd40(0,0x1276a25,0x267d98,0x13432f7,0,20000);
  iVar2 = func_0x00313c10(0xffffffe7,0x2bf7a78);
  if (iVar2 == 0) {
    func_0x003142c0(0x3d974d0,0x3d97508);
    iVar2 = func_0x00313c10(0xffffffe2,0x2bf7aa0);
    if (iVar2 == 0) {
      return;
    }
    func_0x007f1950();
    func_0x007f1810(0xbed27c);
    uVar3 = 0x13ac96c;
    uVar4 = 0x2f;
  }
  else {
    func_0x007f1950();
    func_0x007f1810(0xbed25d);
    uVar3 = 0x13639b9;
    uVar4 = 0x2b;
  }
  func_0x00c9aa10(uVar4,uVar3);
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* CONTEXT / separate function: adjacent_bed2b0 @ 0xbed2b0; ev_caa99ed05d8a80518c83c4edbd4c055300e1539395a39fc839690118d3054e59
 * Ghidra body ranges: 0xbed2b0..0xbed373
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Possible PIC construction at 0x00bed35c: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x00bed361) */
/* WARNING: Removing unreachable block (ram,0x00c08df0) */

void adjacent_bed2b0(undefined8 param_1,long param_2)

{
  undefined4 uVar1;
  long lVar2;
  long lVar3;
  long *plVar4;
  long lVar5;
  
  uVar1 = *(undefined4 *)(param_2 + 0xbc);
  func_0x004c6a00(&DAT_03d974c8,0,0,0);
  lVar3 = adjacent_beceb0(uVar1);
  if (lVar3 != 0) {
    plVar4 = (long *)FUN_00bece30(uVar1);
    FUN_00becf50(plVar4 != (long *)0x0,0x12bb922,0x12b1a16);
    lVar2 = *plVar4;
    if (lVar2 == lVar3) {
      *plVar4 = *(long *)(lVar2 + 8);
    }
    else {
      do {
        lVar5 = lVar2;
        lVar2 = *(long *)(lVar5 + 8);
      } while (lVar2 != lVar3);
      *(undefined8 *)(lVar5 + 8) = *(undefined8 *)(lVar2 + 8);
    }
    adjacent_bed380(lVar3 + 0x10);
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* CONTEXT / separate function: adjacent_bed380 @ 0xbed380; ev_4a220cedc604ec06042a5f04a82d0edaa879432f02a85cd6f951ad3d47cbebfd
 * Ghidra body ranges: 0xbed380..0xbed42d
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void adjacent_bed380(long param_1)

{
  code *pcVar1;
  long lVar2;
  ulong *in_GS_OFFSET;
  
  if ((_DAT_03d974c8 & 0xfffffffffffffff8) == *in_GS_OFFSET) {
    lVar2 = 0;
    do {
      FUN_00becf50(*(long *)(param_1 + lVar2) == 0,0x1319d14,0x130f44d);
      func_0x003143a0(param_1 + lVar2);
      lVar2 = lVar2 + 0x38;
    } while (lVar2 != 0x1bc8);
    return;
  }
  func_0x007f1950();
  func_0x007f18a0(0xbed3fe,0x5d);
  func_0x00c9aa10(7,0x1363945,0x5d);
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* CONTEXT / separate function: adjacent_bed430 @ 0xbed430; ev_960fd4743d8ce552284a39c17748e97217e6f96da16faa0db327fa16178db19b
 * Ghidra body ranges: 0xbed430..0xbed50c
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void adjacent_bed430(void)

{
  undefined4 uVar1;
  long lVar2;
  undefined4 *puVar3;
  long *plVar4;
  long in_R8;
  long *in_GS_OFFSET;
  
  uVar1 = *(undefined4 *)(*(long *)(*in_GS_OFFSET + 8) + 0xbc);
  func_0x004c6a00(&DAT_03d974c8,0,0,0);
  lVar2 = adjacent_beceb0(uVar1);
  if (lVar2 == 0) {
    func_0x004c6fa0(&DAT_03d974c8,0,0,0);
    puVar3 = (undefined4 *)func_0x00c08b50(0x1bd8,0x2bfc080,0x102);
    *puVar3 = uVar1;
    func_0x004c6a00(&DAT_03d974c8,0,0,0);
    lVar2 = adjacent_beceb0(uVar1);
    if (lVar2 == 0) {
      func_0x00bed790(puVar3 + 4);
      plVar4 = (long *)FUN_00bece30(uVar1);
      FUN_00becf50(plVar4 != (long *)0x0,0x138cd3d,0x12b1a16);
      lVar2 = *plVar4;
      *(long *)(puVar3 + 2) = lVar2;
      *(undefined4 **)(in_R8 + lVar2) = puVar3;
    }
    else {
      func_0x00c08df0(puVar3,0x2bfc080);
    }
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* CONTEXT / separate function: zero_fill_helper @ 0x258ff0; ev_9f715f53ca8e7945dcf5dd090a09697d620766198f5ec9c1ad147fd5676b3ea0
 * Ghidra body ranges: 0x258ff0..0x259031
 * Dossier limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
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


