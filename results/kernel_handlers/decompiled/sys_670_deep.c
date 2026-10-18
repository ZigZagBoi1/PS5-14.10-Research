/* REA 6.7.0 / Ghidra 12.1.4 recovered pseudocode, not original or buildable C.
 * Input: deep_670.bin, SHA256 ecf646d679e85e42f524f5e475185754b63df65bf3dc1bc3430cac6f553e0123
 * File offset zero maps to kernel RVA 0x3b28d0; runtime VA = 0xffffffff8a9c0000 + RVA.
 * External bodies/types/data missing from this raw window remain unknown.
 * Function names are analyst seeds or Ghidra-generated; instruction truth is in .rea.asm.
 */

/* ===== sys_670 | RVA 0x3b28d0 | file +0x0 | ev_890f4b6e7354bdfebc976f954a51f8d56fa5e32d4c3f935b4817e0d7c096d8b6 =====
 * Body: [{"start":"0x3b28d0","end":"0x3b2d4e"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sys_670(long param_1,long *param_2)

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
        iVar8 = sub_003b3410(uVar11,lVar10);
        iVar7 = 0;
        if (iVar8 != 0) {
          func_0x0025d410(0x131bf08,0x1379db0,0x1383,iVar8);
          iVar7 = iVar8;
        }
        goto LAB_003b29ab;
      }
      if ((int)lVar5 == 0x3c) {
        iVar7 = sub_003b3f10(lVar1,&local_74);
        if (iVar7 != 0) {
          func_0x0025d410(0x131bf08,0x1379db0,0x133a,iVar7);
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
        func_0x0025d410(0x131bf08,0x1379db0,uVar11,0x16);
      }
      func_0x00c4c4b0(0x34cf300,0,0);
      goto LAB_003b29ab;
    }
    uVar11 = 0x1324;
  }
  else {
    uVar11 = 0x131f;
  }
  func_0x0025d410(0x131bf08,0x1379db0,uVar11,0x16);
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



/* ===== sub_003b2d50 | RVA 0x3b2d50 | file +0x480 | ev_8a497eaf4907acb28469a8d43948a6fc7579b86b615409ecc9f96bcc70cb4438 =====
 * Body: [{"start":"0x3b2d50","end":"0x3b2f2c"},{"start":"0x3b2f30","end":"0x3b2f7c"},{"start":"0x3b2f80","end":"0x3b3080"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_003b2d50(undefined8 param_1,undefined4 *param_2)

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
        func_0x0025d410(0x131bf08,0x13507c9,uVar13,uVar12);
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
        func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
        iVar9 = func_0x002591d0(&local_3c,lVar5,4);
        if (iVar9 == 0) {
          iVar9 = 0;
          if (local_3c <= (int)uVar3) {
            iVar17 = sub_003b3a40(lVar10,lVar4,(long)local_3c << 4);
            if (iVar17 != 0) {
              func_0x0025d410(0x131bf08,0x13507c9,0x1562,iVar17);
              iVar9 = iVar17;
            }
          }
        }
        else {
          func_0x0025d410(0x131bf08,0x13507c9,0x1553,iVar9);
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
  func_0x0025d410(0x131bf08,0x13507c9,uVar13,iVar9);
LAB_003b2dec:
  if (_DAT_0391c310 == local_38) {
    return iVar9;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar8 = (code *)invalidInstructionException();
  (*pcVar8)();
}



/* ===== sub_003b3090 | RVA 0x3b3090 | file +0x7c0 | ev_e2388affa5d31d5f1ba6a51280cd446c04078bd4b55932a22c1451d224ad3ae9 =====
 * Body: [{"start":"0x3b3090","end":"0x3b3409"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_003b3090(undefined8 param_1,undefined4 *param_2)

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
        func_0x0025d410(0x131bf08,0x12a94cb,uVar14,uVar13);
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
        iVar8 = sub_003b3a40(&local_3c,lVar5,4);
        if (iVar8 == 0) {
          iVar8 = 0;
          if (local_3c <= (int)uVar3) {
            iVar9 = sub_003b3a40(lVar10,lVar4,(long)local_3c * 0x18);
            if (iVar9 != 0) {
              func_0x0025d410(0x131bf08,0x12a94cb,0x14e0,iVar9);
              iVar8 = iVar9;
            }
          }
        }
        else {
          func_0x0025d410(0x131bf08,0x12a94cb,0x14d1,iVar8);
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
  func_0x0025d410(0x131bf08,0x12a94cb,uVar14,iVar8);
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



/* ===== sub_003b3410 | RVA 0x3b3410 | file +0xb40 | ev_09fb36886a39ae787a7e3e79a850d8b3c9b8e1268fee81b1c9f84f76d75aa197 =====
 * Body: [{"start":"0x3b3410","end":"0x3b3a33"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_003b3410(int param_1,undefined8 *param_2)

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



/* ===== sub_003b3a40 | RVA 0x3b3a40 | file +0x1170 | ev_8dd39206857e6e1b2e2e8dedd8c0b84ea23d2ffdd9befb2e70159c9137ad897e =====
 * Body: [{"start":"0x3b3a40","end":"0x3b3a81"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_003b3a40(void)

{
  undefined8 *in_GS_OFFSET;
  
  func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== sub_003b3a90 | RVA 0x3b3a90 | file +0x11c0 | ev_699961f3d549250fe183c95e3c8a76c6c311f8ed972be6900aa34a4dc8c68b26 =====
 * Body: [{"start":"0x3b3a90","end":"0x3b3be0"},{"start":"0x3b3bf0","end":"0x3b3cf3"},{"start":"0x3b3d00","end":"0x3b3e85"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_003b3a90(ulong param_1,int param_2,int param_3,long param_4,long param_5)

{
  long lVar1;
  int *piVar2;
  int iVar3;
  long lVar4;
  long *plVar5;
  long lVar6;
  code *pcVar7;
  long lVar8;
  int iVar9;
  undefined8 uVar10;
  long lVar11;
  long lVar12;
  ulong uVar13;
  undefined4 uVar14;
  long *in_GS_OFFSET;
  undefined8 local_78;
  long local_58;
  long local_50;
  undefined1 local_48 [16];
  long local_38;
  
  uVar13 = 0;
  local_38 = _DAT_0391c310;
  lVar11 = (long)param_2;
  local_78 = 0x20000000000000e;
  lVar12 = lVar11 * 0x10;
  lVar1 = param_5 + 0xd8 + lVar11 * 0x20;
  do {
    lVar4 = *(long *)(*(long *)(param_4 + 0x28) + uVar13 * 8);
    plVar5 = *(long **)(lVar4 + 0x10);
    local_50 = *plVar5;
    lVar6 = *in_GS_OFFSET;
    if (param_3 == 2) {
      if ((*(uint *)(*(long *)(lVar6 + 8) + 0x5d4) < 0x11090001) &&
         (*(uint *)(*(long *)(lVar6 + 8) + 0x5d8) < 0x8000000)) {
        uVar14 = (undefined4)plVar5[4];
        uVar10 = local_78;
LAB_003b3d6a:
        uVar10 = func_0x002bc220(0,local_48,0x400000000000080,uVar10,0);
        iVar9 = func_0x0072c3d0(lVar6,uVar14,uVar10,&local_58);
      }
      else {
        lVar8 = plVar5[4];
        uVar10 = func_0x002bc220(0,local_48,0x400000000000080,0x20000000000000e,0);
        iVar9 = func_0x0072e1a0(lVar6,(int)lVar8,uVar10,&local_58);
      }
      if (iVar9 == 0) goto LAB_003b3d8e;
LAB_003b3c4c:
      *(undefined8 *)(lVar4 + 0x40) = 0;
      *(long *)(lVar4 + 0x30) = (long)iVar9;
LAB_003b3c5c:
      local_50 = 0;
    }
    else {
      if (param_3 != 1) {
        uVar10 = 0x16;
        break;
      }
      if ((*(uint *)(*(long *)(lVar6 + 8) + 0x5d4) < 0x11090001) &&
         (*(uint *)(*(long *)(lVar6 + 8) + 0x5d8) < 0x8000000)) {
        uVar14 = (undefined4)plVar5[4];
        uVar10 = 0x20000000000000d;
        goto LAB_003b3d6a;
      }
      lVar8 = plVar5[4];
      uVar10 = func_0x002bc220(0,local_48,0x400000000000080,0x20000000000000d,0);
      iVar9 = func_0x0072e180(lVar6,(int)lVar8,uVar10,&local_58);
      if (iVar9 != 0) goto LAB_003b3c4c;
LAB_003b3d8e:
      lVar8 = local_58;
      if ((*(uint *)(local_58 + 0x24) & 3) == 0) {
        LOCK();
        piVar2 = (int *)(local_58 + 0x28);
        iVar9 = *piVar2;
        *piVar2 = *piVar2 + -1;
        UNLOCK();
        if (iVar9 == 1) {
          func_0x0072b380(local_58,lVar6);
        }
        *(undefined8 *)(lVar4 + 0x30) = 0;
        *(undefined8 *)(lVar4 + 0x40) = 0;
        goto LAB_003b3c5c;
      }
      *(long *)(lVar4 + 0x40) = local_58;
      *(long *)(lVar6 + 0x5a0) = local_58;
      uVar10 = *(undefined8 *)(lVar6 + 0x140);
      pcVar7 = *(code **)(*(long *)(local_58 + 8) + 0x18);
      if (0x12 < (-(long)pcVar7 + 0x2684e0U >> 3 | -(long)pcVar7 << 0x3d)) {
        func_0x0044f8c0(0x1ab5ca0,pcVar7);
      }
      iVar9 = (*pcVar7)(lVar8,0x80089169,&local_50,uVar10);
      *(undefined8 *)(lVar6 + 0x5a0) = 0;
      if (iVar9 != 0) goto LAB_003b3c5c;
    }
    *(long *)(lVar4 + 8) = local_50;
    func_0x004c6a00(lVar1,0,0,0);
    iVar9 = *(int *)(param_5 + 0x1d0 + lVar11 * 4);
    *(int *)(param_5 + 0x1d0 + lVar11 * 4) = iVar9 + 1;
    *(int *)(lVar4 + 4) = iVar9;
    iVar9 = *(int *)(param_5 + 0x170 + lVar11 * 4);
    iVar3 = *(int *)(param_5 + 0x1c0 + lVar11 * 4);
    if (((iVar3 == 0) || (local_50 == 0)) || (iVar9 < iVar3)) {
      *(undefined8 *)(lVar4 + 0x48) = 0;
      if (iVar3 < iVar9 || iVar9 == 0) {
        plVar5 = *(long **)(param_5 + 0x48 + lVar12);
        *(long **)(lVar4 + 0x50) = plVar5;
        *plVar5 = lVar4;
        *(long *)(param_5 + 0x48 + lVar12) = lVar4 + 0x48;
      }
      else {
        plVar5 = *(long **)(param_5 + 0x88 + lVar12);
        *(long **)(lVar4 + 0x50) = plVar5;
        *plVar5 = lVar4;
        *(long *)(param_5 + 0x88 + lVar12) = lVar4 + 0x48;
        *(undefined4 *)(lVar4 + 4) = 0;
        piVar2 = (int *)(param_5 + 0x1d0 + lVar11 * 4);
        *piVar2 = *piVar2 + -1;
      }
    }
    else {
      sub_003b4440(lVar4,param_2,local_50,param_5);
    }
    piVar2 = (int *)(param_5 + 0x1c0 + lVar11 * 4);
    *piVar2 = *piVar2 + 1;
    *(undefined4 *)(lVar4 + 0x38) = 1;
    uVar10 = 0;
    func_0x004c6fa0(lVar1,0,0,0);
    uVar13 = uVar13 + 1;
  } while ((param_1 & 0xffffffff) != uVar13);
  if (_DAT_0391c310 == local_38) {
    return uVar10;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar7 = (code *)invalidInstructionException();
  (*pcVar7)();
}



/* ===== sub_003b3e90 | RVA 0x3b3e90 | file +0x15c0 | ev_84a3bfb8e256918fb7e0e9b7e5420a7152fa85303ae008e2a859ef737c9155ba =====
 * Body: [{"start":"0x3b3e90","end":"0x3b3f00"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_003b3e90(long param_1)

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



/* ===== sub_003b3f10 | RVA 0x3b3f10 | file +0x1640 | ev_3f91f51bba7d284e379d531933c85a3f54e5c8cba319a5fefdeefcd29fde97ad =====
 * Body: [{"start":"0x3b3f10","end":"0x3b3f47"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_003b3f10(void)

{
  undefined8 *in_GS_OFFSET;
  
  func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== sub_003b3f50 | RVA 0x3b3f50 | file +0x1680 | ev_83b7732681148924ba7b983e3c21b88b8fbbe66a6498d5a1576236fef01d1876 =====
 * Body: [{"start":"0x3b3f50","end":"0x3b3fa3"},{"start":"0x3b3fb0","end":"0x3b4188"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_003b3f50(undefined8 param_1,long param_2,undefined8 param_3,long param_4,ulong param_5,
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



/* ===== sub_003b4190 | RVA 0x3b4190 | file +0x18c0 | ev_5f682a18c207c4fc58082569055d3fa9e9a53b95ffc4d54b710fbb3e0ad0fc2c =====
 * Body: [{"start":"0x3b4190","end":"0x3b427a"},{"start":"0x3b4280","end":"0x3b4439"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_003b4190(long param_1,int param_2,int param_3,long param_4)

{
  long *plVar1;
  int *piVar2;
  long lVar3;
  code *pcVar4;
  undefined8 *puVar5;
  long lVar6;
  long lVar7;
  long *plVar8;
  long lVar9;
  undefined8 uVar10;
  
  lVar9 = (long)param_2;
  lVar6 = param_4 + 0xd8 + lVar9 * 0x20;
  func_0x004c6a00(lVar6,0,0,0);
  if (*(int *)(param_1 + 4) == 0) {
    uVar10 = 3;
    lVar7 = *(long *)(param_4 + 0x80 + lVar9 * 0x10);
    if (lVar7 != 0) {
      do {
        plVar8 = (long *)(lVar7 + 0x48);
        if ((param_1 == lVar7) && (*(int *)(lVar7 + 0x38) == param_3)) {
          piVar2 = (int *)(param_4 + 0x1c0 + lVar9 * 4);
          *piVar2 = *piVar2 + -1;
          *(undefined4 *)(lVar7 + 0x38) = 4;
          plVar8 = (long *)(lVar7 + 0x48);
          lVar3 = *(long *)(lVar7 + 0x48);
          if (lVar3 == 0) {
            if (**(long **)(lVar7 + 0x50) != param_1) {
LAB_003b43ba:
              func_0x007f1950();
              func_0x007f20c0(0x3b43ba,param_1,*(undefined8 **)(lVar7 + 0x50),
                              **(undefined8 **)(lVar7 + 0x50));
              puVar5 = *(undefined8 **)(lVar7 + 0x50);
              uVar10 = 0x3b;
              goto LAB_003b43e7;
            }
            *(long **)(param_4 + lVar9 * 0x10 + 0x88) = *(long **)(lVar7 + 0x50);
          }
          else {
            if (*(long **)(lVar3 + 0x50) != plVar8) {
              func_0x007f1950();
              func_0x007f2180(0x3b43f6,param_1,*(long *)(lVar7 + 0x48),
                              *(undefined8 *)(*(long *)(lVar7 + 0x48) + 0x50),plVar8);
              lVar6 = *(long *)(lVar7 + 0x48);
              uVar10 = 0x37;
              goto LAB_003b442d;
            }
            if (**(long **)(lVar7 + 0x50) != param_1) goto LAB_003b43ba;
            *(long **)(lVar3 + 0x50) = *(long **)(lVar7 + 0x50);
          }
          uVar10 = 0;
          **(long **)(lVar7 + 0x50) = *plVar8;
          break;
        }
        lVar7 = *plVar8;
      } while (*plVar8 != 0);
    }
  }
  else {
    uVar10 = 3;
    plVar1 = (long *)(param_4 + 0x40 + lVar9 * 0x10);
    plVar8 = plVar1;
    do {
      lVar7 = *plVar8;
      if (lVar7 == 0) goto LAB_003b4331;
      plVar8 = (long *)(lVar7 + 0x48);
    } while (param_1 != lVar7);
    if (*(int *)(lVar7 + 0x38) == param_3) {
      piVar2 = (int *)(param_4 + 0x1c0 + lVar9 * 4);
      *piVar2 = *piVar2 + -1;
      *(undefined4 *)(lVar7 + 0x38) = 4;
      lVar3 = *(long *)(lVar7 + 0x48);
      if (lVar3 == 0) {
        if (**(long **)(lVar7 + 0x50) != param_1) goto LAB_003b4352;
        plVar1[1] = (long)*(long **)(lVar7 + 0x50);
      }
      else {
        if (*(long **)(lVar3 + 0x50) != plVar8) {
          func_0x007f1950();
          func_0x007f2180(0x3b4381,param_1,*(long *)(lVar7 + 0x48),
                          *(undefined8 *)(*(long *)(lVar7 + 0x48) + 0x50),plVar8);
          lVar6 = *(long *)(lVar7 + 0x48);
          uVar10 = 0x2f;
LAB_003b442d:
          func_0x00c9aa10(uVar10,0x136f6f3,lVar7,lVar6,*(undefined8 *)(lVar6 + 0x50),plVar8);
                    /* WARNING: Does not return */
          pcVar4 = (code *)invalidInstructionException();
          (*pcVar4)();
        }
        if (**(long **)(lVar7 + 0x50) != param_1) {
LAB_003b4352:
          func_0x007f1950();
          func_0x007f20c0(0x3b4352,param_1,*(undefined8 **)(lVar7 + 0x50),
                          **(undefined8 **)(lVar7 + 0x50));
          puVar5 = *(undefined8 **)(lVar7 + 0x50);
          uVar10 = 0x33;
LAB_003b43e7:
          func_0x00c9aa10(uVar10,0x131bb64,lVar7,puVar5,*puVar5);
                    /* WARNING: Does not return */
          pcVar4 = (code *)invalidInstructionException();
          (*pcVar4)();
        }
        *(long **)(lVar3 + 0x50) = *(long **)(lVar7 + 0x50);
      }
      uVar10 = 0;
      **(undefined8 **)(lVar7 + 0x50) = *(undefined8 *)(lVar7 + 0x48);
      if (0 < *(int *)(lVar7 + 4)) {
        piVar2 = (int *)(param_4 + 0x160 + lVar9 * 4);
        *piVar2 = *piVar2 + 1;
      }
    }
  }
LAB_003b4331:
  func_0x004c6fa0(lVar6,0,0,0);
  return uVar10;
}



/* ===== sub_003b4440 | RVA 0x3b4440 | file +0x1b70 | ev_e33d17b0153a0a0972d997ce568d535b426485c1d3de2064c94d5cec17b76fac =====
 * Body: [{"start":"0x3b4440","end":"0x3b45b2"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_003b4440(long param_1,int param_2,ulong param_3,long param_4)

{
  ulong uVar1;
  code *pcVar2;
  long lVar3;
  long *plVar4;
  undefined8 *puVar5;
  long lVar6;
  long lVar7;
  undefined8 uVar8;
  int iVar9;
  
  lVar7 = (long)param_2;
  uVar1 = *(ulong *)(param_4 + 0x140 + lVar7 * 8);
  lVar3 = lVar7 * 0x10;
  lVar6 = *(long *)(param_4 + 0x40 + lVar3);
  if (param_3 < uVar1) {
    if (lVar6 != 0) {
      iVar9 = 0;
      do {
        if ((param_3 < *(ulong *)(lVar6 + 8) && *(ulong *)(lVar6 + 8) < uVar1) &&
           (*(int *)(param_4 + 0x1d0 + lVar7 * 4) - *(int *)(lVar6 + 4) <
            *(int *)(param_4 + 0x180 + lVar7 * 4))) {
          *(int *)(param_1 + 4) = *(int *)(lVar6 + 4);
          plVar4 = *(long **)(lVar6 + 0x50);
          if (*plVar4 == lVar6) {
LAB_003b4560:
            *(long **)(param_1 + 0x50) = plVar4;
            *(long *)(param_1 + 0x48) = lVar6;
            **(long **)(lVar6 + 0x50) = param_1;
            *(long *)(lVar6 + 0x50) = param_1 + 0x48;
            return;
          }
          func_0x007f1950();
          func_0x007f20c0(0x3b4526,lVar6,*(undefined8 **)(lVar6 + 0x50),
                          **(undefined8 **)(lVar6 + 0x50));
          puVar5 = *(undefined8 **)(lVar6 + 0x50);
          uVar8 = 0x27;
LAB_003b45a4:
          func_0x00c9aa10(uVar8,0x131bb64,lVar6,puVar5,*puVar5);
                    /* WARNING: Does not return */
          pcVar2 = (code *)invalidInstructionException();
          (*pcVar2)();
        }
        iVar9 = iVar9 + 1;
      } while ((iVar9 < *(int *)(param_4 + 0x170 + lVar7 * 4)) &&
              (lVar6 = *(long *)(lVar6 + 0x48), lVar6 != 0));
    }
  }
  else if (lVar6 != 0) {
    iVar9 = 0;
    do {
      if ((param_3 < *(ulong *)(lVar6 + 8)) &&
         (*(int *)(param_4 + 0x1d0 + lVar7 * 4) - *(int *)(lVar6 + 4) <
          *(int *)(param_4 + 0x180 + lVar7 * 4))) {
        *(int *)(param_1 + 4) = *(int *)(lVar6 + 4);
        plVar4 = *(long **)(lVar6 + 0x50);
        if (*plVar4 == lVar6) goto LAB_003b4560;
        func_0x007f1950();
        func_0x007f20c0(0x3b4579,lVar6,*(undefined8 **)(lVar6 + 0x50),
                        **(undefined8 **)(lVar6 + 0x50));
        puVar5 = *(undefined8 **)(lVar6 + 0x50);
        uVar8 = 0x2b;
        goto LAB_003b45a4;
      }
      iVar9 = iVar9 + 1;
    } while ((iVar9 < *(int *)(param_4 + 0x170 + lVar7 * 4)) &&
            (lVar6 = *(long *)(lVar6 + 0x48), lVar6 != 0));
  }
  *(undefined8 *)(param_1 + 0x48) = 0;
  plVar4 = *(long **)(param_4 + 0x48 + lVar3);
  *(long **)(param_1 + 0x50) = plVar4;
  *plVar4 = param_1;
  *(long *)(param_4 + 0x48 + lVar3) = param_1 + 0x48;
  return;
}



/* ===== sub_003b45c0 | RVA 0x3b45c0 | file +0x1cf0 | ev_c4171eeec2fe3fcf9ae935a9751d6474adda36bba741da904ac8e260a4a63476 =====
 * Body: [{"start":"0x3b45c0","end":"0x3b4736"},{"start":"0x3b4740","end":"0x3b479e"},{"start":"0x3b47a0","end":"0x3b48b6"},{"start":"0x3b48c0","end":"0x3b49de"},{"start":"0x3b49e0","end":"0x3b4a70"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Possible PIC construction at 0x003b47af: Changing call to branch */
/* WARNING: Possible PIC construction at 0x003b48d2: Changing call to branch */
/* WARNING: Possible PIC construction at 0x003b49b0: Changing call to branch */
/* WARNING: Possible PIC construction at 0x003b4a30: Changing call to branch */
/* WARNING: Possible PIC construction at 0x003b4a53: Changing call to branch */
/* WARNING: Possible PIC construction at 0x003b4994: Changing call to branch */
/* WARNING: Possible PIC construction at 0x003b4710: Changing call to branch */
/* WARNING: Possible PIC construction at 0x003b477e: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x003b4715) */
/* WARNING: Removing unreachable block (ram,0x003b4a58) */
/* WARNING: Removing unreachable block (ram,0x003b4a35) */
/* WARNING: Removing unreachable block (ram,0x003b49b5) */
/* WARNING: Removing unreachable block (ram,0x003b49cc) */
/* WARNING: Removing unreachable block (ram,0x003b49e8) */
/* WARNING: Removing unreachable block (ram,0x003b49f8) */
/* WARNING: Removing unreachable block (ram,0x003b49e0) */
/* WARNING: Removing unreachable block (ram,0x003b4a18) */
/* WARNING: Removing unreachable block (ram,0x003b48d7) */
/* WARNING: Removing unreachable block (ram,0x003b47b4) */
/* WARNING: Removing unreachable block (ram,0x003b4783) */

void sub_003b45c0(short *param_1,int param_2)

{
  int *piVar1;
  short sVar2;
  undefined4 uVar3;
  int iVar4;
  undefined8 uVar5;
  long lVar6;
  uint *puVar7;
  long lVar8;
  uint uVar9;
  long lVar10;
  uint uVar11;
  long lVar12;
  undefined8 *in_GS_OFFSET;
  
  if (param_2 == 0x160) {
    sVar2 = *param_1;
    lVar10 = (long)sVar2;
    if (0 < lVar10) {
      uVar5 = *(undefined8 *)(param_1 + 0xc);
      lVar12 = 0;
      do {
        lVar6 = *(long *)(*(long *)(param_1 + 0x14) + lVar12 * 8);
        if (lVar6 != 0) {
          if (sVar2 == 1) {
            puVar7 = *(uint **)(lVar6 + 0x20);
            uVar9 = *puVar7;
            if (uVar9 != 0) {
              uVar11 = 0;
              do {
                lVar6 = *(long *)(*(long *)(param_1 + 0x14) + (long)(int)uVar11 * 8);
                if (lVar6 != 0) {
                  uVar3 = *(undefined4 *)(param_1 + 2);
                  iVar4 = *(int *)(lVar6 + 0x38);
                  if (iVar4 != 1) {
                    if (iVar4 != 2) goto LAB_003b46bc;
                    lVar8 = *(long *)(lVar6 + 0x28);
                    if (lVar8 == 0) {
                      func_0x0025d410(0x13659da,0x12bdacb,0x1574);
                    }
                    else {
                      if (*(char *)(lVar8 + 0x48) == '\0') {
                        halt_baddata();
                      }
                      *(undefined1 *)(lVar8 + 0x48) = 0;
                      *(undefined8 *)(lVar6 + 0x28) = 0;
                    }
                  }
                  sub_003b4190(lVar6,uVar3,iVar4,uVar5);
                  uVar9 = *puVar7;
                }
LAB_003b46bc:
                uVar11 = uVar11 + 1;
              } while (uVar11 < uVar9);
            }
          }
          else {
            uVar3 = *(undefined4 *)(param_1 + 2);
            iVar4 = *(int *)(lVar6 + 0x38);
            if (iVar4 != 1) {
              if (iVar4 != 2) goto LAB_003b463e;
              lVar8 = *(long *)(lVar6 + 0x28);
              if (lVar8 == 0) {
                func_0x0025d410(0x13659da,0x12bdacb,0x1574);
              }
              else {
                if (*(char *)(lVar8 + 0x48) == '\0') {
                  halt_baddata();
                }
                *(undefined1 *)(lVar8 + 0x48) = 0;
                *(undefined8 *)(lVar6 + 0x28) = 0;
              }
            }
            sub_003b4190(lVar6,uVar3,iVar4,uVar5);
          }
        }
LAB_003b463e:
        lVar12 = lVar12 + 1;
      } while (lVar12 != lVar10);
      lVar12 = 0;
      do {
        lVar6 = *(long *)(*(long *)(param_1 + 0x14) + lVar12 * 8);
        if (lVar6 != 0) {
          puVar7 = *(uint **)(lVar6 + 0x20);
          lVar10 = *(long *)(lVar6 + 0x28);
          if (lVar10 != 0) {
            if (*(char *)(lVar10 + 0x48) == '\0') {
              func_0x00c08df0(lVar10,0x1ab5a50);
            }
            else {
              *(undefined1 *)(lVar10 + 0x48) = 0;
            }
            *(undefined8 *)(lVar6 + 0x28) = 0;
          }
          if (param_1[1] != 1) {
            param_1[1] = param_1[1] + -1;
            func_0x00bf1760(puVar7 + 8);
            if (*(long *)(lVar6 + 0x28) != 0) {
              func_0x0025d410(0x13069f7,0x136fb7e,0xb35);
            }
            if (*(long *)(lVar6 + 0x40) == 0) {
              halt_baddata();
            }
            LOCK();
            piVar1 = (int *)(*(long *)(lVar6 + 0x40) + 0x28);
            iVar4 = *piVar1;
            *piVar1 = *piVar1 + -1;
            UNLOCK();
            if (iVar4 == 1) {
              func_0x0072b380(*(undefined8 *)(lVar6 + 0x40),*in_GS_OFFSET);
            }
            *(undefined8 *)(lVar6 + 0x40) = 0;
            halt_baddata();
          }
          if (*param_1 != 1) {
            if (*(long *)(lVar6 + 0x40) == 0) {
              halt_baddata();
            }
            LOCK();
            piVar1 = (int *)(*(long *)(lVar6 + 0x40) + 0x28);
            iVar4 = *piVar1;
            *piVar1 = *piVar1 + -1;
            UNLOCK();
            if (iVar4 == 1) {
              func_0x0072b380(*(undefined8 *)(lVar6 + 0x40),*in_GS_OFFSET);
            }
            *(undefined8 *)(lVar6 + 0x40) = 0;
            halt_baddata();
          }
          uVar9 = *puVar7;
          if (uVar9 != 0) {
            uVar11 = 0;
            do {
              lVar10 = *(long *)(*(long *)(param_1 + 0x14) + (long)(int)uVar11 * 8);
              if (lVar10 != 0) {
                if (*(long *)(lVar10 + 0x28) != 0) {
                  func_0x0025d410(0x13069f7,0x136fb7e,0xb35);
                }
                if (*(long *)(lVar10 + 0x40) == 0) {
                  halt_baddata();
                }
                LOCK();
                piVar1 = (int *)(*(long *)(lVar10 + 0x40) + 0x28);
                iVar4 = *piVar1;
                *piVar1 = *piVar1 + -1;
                UNLOCK();
                if (iVar4 == 1) {
                  func_0x0072b380(*(undefined8 *)(lVar10 + 0x40),*in_GS_OFFSET);
                }
                *(undefined8 *)(lVar10 + 0x40) = 0;
                halt_baddata();
              }
              uVar11 = uVar11 + 1;
            } while (uVar11 < uVar9);
          }
          func_0x002a9670(*(undefined8 *)(*(long *)(lVar6 + 0x18) + 0x10));
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        lVar12 = lVar12 + 1;
      } while (lVar10 != lVar12);
    }
  }
  return;
}



/* ===== sub_003b4a80 | RVA 0x3b4a80 | file +0x21b0 | ev_a0c2d4b84065d3522fb1a6b294370dc9d45d0e16d2d9fe441ee4ab98775cc6ec =====
 * Body: [{"start":"0x3b4a80","end":"0x3b4bf9"},{"start":"0x3b4c27","end":"0x3b4d33"},{"start":"0x3b4d40","end":"0x3b4d80"},{"start":"0x3b4d90","end":"0x3b4e2b"},{"start":"0x3b4e30","end":"0x3b4e3b"},{"start":"0x3b4e40","end":"0x3b5152"},{"start":"0x3b5160","end":"0x3b542a"},{"start":"0x3b5430","end":"0x3b58ce"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_003b4a80(long *param_1)

{
  ulong uVar1;
  long lVar2;
  long lVar3;
  undefined8 *puVar4;
  code *pcVar5;
  int *piVar6;
  undefined1 uVar7;
  int iVar8;
  undefined4 uVar9;
  uint uVar10;
  long *plVar11;
  long lVar12;
  char *pcVar13;
  long lVar14;
  ulong uVar15;
  undefined8 uVar16;
  ulong uVar17;
  undefined8 uVar18;
  int *piVar19;
  long lVar20;
  long lVar21;
  long lVar22;
  long *in_GS_OFFSET;
  bool bVar23;
  long *local_f8;
  undefined4 local_f0;
  long local_e8;
  ulong local_e0;
  undefined8 local_d8;
  long local_d0;
  long local_c8;
  ulong local_c0;
  long local_b8;
  long local_b0;
  long local_a8;
  long *local_a0;
  ulong local_98;
  ulong local_90;
  undefined8 local_88;
  long local_80;
  long *local_78;
  long local_70;
  undefined8 *local_68;
  long local_60;
  int local_54;
  long local_50;
  long local_48;
  undefined4 local_3c;
  long *local_38;
  
  local_54 = 0;
  lVar20 = *in_GS_OFFSET;
  lVar12 = param_1[3];
  param_1[5] = (long)&local_54;
  func_0x00926460(0,0x4c,0x10000000,0);
  func_0x0073e000(0,0x134f73f,0x25da80,lVar20,0x2719,lVar20,0x2610d0);
  func_0x0073e000(0,0x1294465,0x25da88,lVar20,0xb,lVar20,0x2610d8);
  local_a8 = lVar20;
  func_0x00265358(lVar20,0);
  func_0x004c6a00(0x34cf2e8,0,0,0);
  if ((*(int *)(lVar12 + 0x4a0) < 0) && (iVar8 = func_0x0073e780(0x34cf2f0,0x34cf2d0,0), iVar8 != 0)
     ) {
    func_0x0025d410(0x1350799,0x13a42dc,0x720,iVar8,iVar8);
  }
  func_0x004c6fa0(0x34cf2e8,0,0,0);
  iVar8 = func_0x00b078d0();
  if (iVar8 != 0) {
    *(undefined4 *)(param_1 + 4) = 0;
  }
  lVar20 = lVar12 + 0x40;
  lVar14 = lVar12 + 0xd8;
  local_a0 = param_1 + 6;
  local_b8 = lVar12 + 0x80;
  local_48 = lVar12;
  local_38 = param_1;
  do {
    func_0x009261b0();
    uVar17 = 3;
    do {
      lVar21 = uVar17 * 0x20 + lVar14;
      func_0x004c6a00(lVar21,0,0,0);
      piVar19 = (int *)0x0;
      if (*(int *)(lVar12 + 0x1c0 + uVar17 * 4) != 0) {
        lVar22 = uVar17 * 0x10;
        piVar19 = *(int **)(lVar20 + lVar22);
        if (piVar19 == (int *)0x0) {
LAB_003b4e30:
          piVar19 = (int *)0x0;
          lVar12 = local_48;
        }
        else {
          local_50 = lVar20 + lVar22;
LAB_003b4cc2:
          param_1[2] = *(long *)(*(long *)(piVar19 + 6) + 8);
          if (piVar19[0xe] == 2) {
            lVar2 = *(long *)(piVar19 + 10);
            if (lVar2 == 0) {
              func_0x0025d410(0x12fc3ea,0x13a42dc,0x77f);
            }
            if (*(char *)(lVar2 + 0x4a) == '\0') {
              if (*(char *)(lVar2 + 0x49) != '\0') goto LAB_003b4cb0;
              uVar7 = 1;
            }
            else {
              uVar7 = 0;
            }
            *(undefined1 *)(lVar2 + 0x49) = 1;
            *(undefined1 *)((long)local_38 + 0x75) = uVar7;
            local_78 = *(long **)(piVar19 + 10);
            local_80 = local_38[3];
            iVar8 = (int)local_78[5] + 1;
            *(int *)(local_78 + 5) = iVar8;
            *(int *)(local_38 + 0xe) = iVar8;
            func_0x00259be0(local_78,local_a0,0x28);
            local_38[0xc] = (long)(local_78 + 6);
            uVar1 = local_78[7];
            uVar15 = (ulong)*(uint *)(local_80 + 400 + uVar17 * 4);
            if (uVar1 < uVar15) {
              local_38[7] = uVar1;
              local_78[7] = 0;
            }
            else {
              local_78[7] = uVar1 - uVar15;
              local_38[7] = (ulong)*(uint *)(local_80 + 400 + uVar17 * 4);
              *local_78 = *local_78 + (ulong)*(uint *)(local_80 + 400 + uVar17 * 4);
              local_78[2] = local_78[2] + (ulong)*(uint *)(local_80 + 400 + uVar17 * 4);
            }
            *(undefined1 *)((long)local_38 + 0x74) = 0;
            if (*(int *)(lVar2 + 0x4c) != 0) {
              do {
                iVar8 = *(int *)(lVar2 + 0x30);
                LOCK();
                bVar23 = iVar8 == *(int *)(lVar2 + 0x30);
                if (bVar23) {
                  *(int *)(lVar2 + 0x30) = (*(int *)(lVar2 + 0x28) + iVar8) - *(int *)(lVar2 + 0x2c)
                  ;
                }
                UNLOCK();
              } while (!bVar23);
            }
            if ((*(long *)(lVar2 + 0x38) != 0) &&
               (param_1 = local_38, lVar12 = local_48, *(int *)(lVar2 + 0x4c) == 0))
            goto LAB_003b50e0;
            lVar12 = *(long *)(piVar19 + 0x12);
            if (lVar12 == 0) {
              if ((int *)**(undefined8 **)(piVar19 + 0x14) != piVar19) {
                halt_baddata();
              }
              *(undefined8 **)(local_50 + 8) = *(undefined8 **)(piVar19 + 0x14);
            }
            else {
              if (*(int **)(lVar12 + 0x50) != piVar19 + 0x12) {
                    /* WARNING: Bad instruction - Truncating control flow here */
                halt_baddata();
              }
              if ((int *)**(undefined8 **)(piVar19 + 0x14) != piVar19) {
                    /* WARNING: Bad instruction - Truncating control flow here */
                halt_baddata();
              }
              *(undefined8 **)(lVar12 + 0x50) = *(undefined8 **)(piVar19 + 0x14);
            }
            **(undefined8 **)(piVar19 + 0x14) = *(undefined8 *)(piVar19 + 0x12);
            piVar6 = (int *)(local_48 + 0x1c0 + uVar17 * 4);
            *piVar6 = *piVar6 + -1;
          }
          else {
            if (piVar19[0xe] != 1) goto LAB_003b4cb0;
            if (_DAT_034d09c0 != (long *)0x0) {
              func_0x004c6a00(0x34cf2e8,0,0,0);
              if (_DAT_034d09c0 != (long *)0x0) {
                plVar11 = _DAT_034d09c0;
                while (*(long *)(*(long *)(piVar19 + 6) + 8) != *plVar11) {
                  plVar11 = (long *)plVar11[1];
                  if (plVar11 == (long *)0x0) goto LAB_003b4d90;
                }
                func_0x004c6fa0(0x34cf2e8,0,0);
                goto LAB_003b4cb0;
              }
LAB_003b4d90:
              func_0x004c6fa0(0x34cf2e8,0,0,0);
            }
            param_1 = local_38;
            if ((*(int *)(local_48 + 0x1a0 + uVar17 * 4) == 0) || (*piVar19 != 1)) {
              lVar12 = *(long *)(piVar19 + 0x12);
              if (lVar12 == 0) {
                if ((int *)**(undefined8 **)(piVar19 + 0x14) != piVar19) {
                  halt_baddata();
                }
                *(undefined8 **)(local_50 + 8) = *(undefined8 **)(piVar19 + 0x14);
              }
              else {
                if (*(int **)(lVar12 + 0x50) != piVar19 + 0x12) {
                    /* WARNING: Bad instruction - Truncating control flow here */
                  halt_baddata();
                }
                if ((int *)**(undefined8 **)(piVar19 + 0x14) != piVar19) {
                    /* WARNING: Bad instruction - Truncating control flow here */
                  halt_baddata();
                }
                *(undefined8 **)(lVar12 + 0x50) = *(undefined8 **)(piVar19 + 0x14);
              }
              **(undefined8 **)(piVar19 + 0x14) = *(undefined8 *)(piVar19 + 0x12);
              piVar19[0xe] = 2;
              piVar6 = (int *)(local_48 + 0x1c0 + uVar17 * 4);
              *piVar6 = *piVar6 + -1;
            }
            else {
              uVar1 = *(ulong *)(*(long *)(piVar19 + 4) + 8);
              if (((*(uint *)(local_48 + 0x1b0 + uVar17 * 4) < uVar1) && (uVar1 < 0x80000000)) &&
                 (*(uint *)(local_48 + 400 + uVar17 * 4) < uVar1)) {
                func_0x003b66b0(piVar19,uVar17 & 0xffffffff,local_38);
                piVar19[0xe] = 2;
                *(undefined8 *)(local_48 + 0x140 + uVar17 * 8) = *(undefined8 *)(piVar19 + 2);
                lVar12 = local_48;
                goto LAB_003b50e0;
              }
              lVar12 = *(long *)(piVar19 + 0x12);
              if (lVar12 == 0) {
                if ((int *)**(undefined8 **)(piVar19 + 0x14) != piVar19) {
                  halt_baddata();
                }
                *(undefined8 **)(local_50 + 8) = *(undefined8 **)(piVar19 + 0x14);
              }
              else {
                if (*(int **)(lVar12 + 0x50) != piVar19 + 0x12) {
                    /* WARNING: Bad instruction - Truncating control flow here */
                  halt_baddata();
                }
                if ((int *)**(undefined8 **)(piVar19 + 0x14) != piVar19) {
                    /* WARNING: Bad instruction - Truncating control flow here */
                  halt_baddata();
                }
                *(undefined8 **)(lVar12 + 0x50) = *(undefined8 **)(piVar19 + 0x14);
              }
              **(undefined8 **)(piVar19 + 0x14) = *(undefined8 *)(piVar19 + 0x12);
              piVar6 = (int *)(local_48 + 0x1c0 + uVar17 * 4);
              *piVar6 = *piVar6 + -1;
              piVar19[0xe] = 2;
            }
            *(undefined8 *)(local_48 + 0x140 + uVar17 * 8) = *(undefined8 *)(piVar19 + 2);
          }
          lVar12 = local_48;
          lVar2 = *(long *)(local_b8 + lVar22);
          param_1 = local_38;
          if (lVar2 != 0) {
            lVar3 = *(long *)(lVar2 + 0x48);
            if (lVar3 == 0) {
              if (**(long **)(lVar2 + 0x50) != lVar2) {
                halt_baddata();
              }
              *(long **)(lVar22 + local_b8 + 8) = *(long **)(lVar2 + 0x50);
            }
            else {
              if (*(long *)(lVar3 + 0x50) != lVar2 + 0x48) {
                    /* WARNING: Bad instruction - Truncating control flow here */
                halt_baddata();
              }
              if (**(long **)(lVar2 + 0x50) != lVar2) {
                    /* WARNING: Bad instruction - Truncating control flow here */
                halt_baddata();
              }
              *(long **)(lVar3 + 0x50) = *(long **)(lVar2 + 0x50);
            }
            **(undefined8 **)(lVar2 + 0x50) = *(undefined8 *)(lVar2 + 0x48);
            iVar8 = *(int *)(local_48 + 0x1d0 + uVar17 * 4);
            *(int *)(local_48 + 0x1d0 + uVar17 * 4) = iVar8 + 1;
            *(int *)(lVar2 + 4) = iVar8;
            if (*(long *)(lVar2 + 8) == 0) {
              *(undefined8 *)(lVar2 + 0x48) = 0;
              plVar11 = *(long **)(local_50 + 8);
              *(long **)(lVar2 + 0x50) = plVar11;
              *plVar11 = lVar2;
              *(long *)(local_50 + 8) = lVar2 + 0x48;
            }
            else {
              sub_003b4440(lVar2);
              param_1 = local_38;
            }
          }
        }
      }
LAB_003b50e0:
      iVar8 = func_0x00b078d0();
      if ((iVar8 != 0) && ((int)param_1[4] != 0)) {
        *(undefined4 *)(param_1 + 4) = 0;
      }
      func_0x004c6fa0(lVar21,0,0);
      if (piVar19 != (int *)0x0) {
        lVar12 = *(long *)(piVar19 + 8);
        lVar20 = lVar12 + 0x20;
        func_0x00bf1770(lVar20,0x80000,0,0,0,0,0,0);
        if (*(int *)(lVar12 + 8) == 1) {
          *(undefined4 *)(lVar12 + 8) = 2;
        }
        func_0x00bf1770(lVar20,0x100000,0,0,0,0,0,0);
        func_0x004c6a00(0x34cf2e8,0,0,0);
        if (*(long *)(local_48 + 0x4b0) != 0) {
          func_0x0073ef80(0x34cf2f0);
        }
        local_b0 = lVar20;
        if (*(long *)(local_48 + 0x528) != 0) {
          func_0x0073ef80(0x34cf2f0);
        }
        func_0x004c6fa0(0x34cf2e8,0,0,0);
        lVar20 = *in_GS_OFFSET;
        local_88 = 0;
        local_90 = 0;
        puVar4 = *(undefined8 **)(piVar19 + 6);
        local_78 = *(long **)(lVar20 + 8);
        local_50 = *(long *)((long)local_78 + 0x200);
        local_80 = *(long *)(puVar4[1] + 0x200);
        *(undefined8 *)(lVar20 + 0x390) = *puVar4;
        *(undefined8 *)(lVar20 + 0x140) = puVar4[2];
        *(undefined8 *)(lVar20 + 0x5d0) = *(undefined8 *)(piVar19 + 4);
        if (local_50 != local_80) {
          lVar12 = *(long *)((long)local_78 + 0x200);
          *(long *)((long)local_78 + 0x200) = local_80;
          LOCK();
          *(int *)(local_80 + 0x2e0) = *(int *)(local_80 + 0x2e0) + 1;
          UNLOCK();
          func_0x008def40(lVar20);
          if (local_50 != lVar12) {
            func_0x002c61a0(local_50);
          }
        }
        iVar8 = func_0x00b078d0();
        if (iVar8 != 0) {
          func_0x000a4550(*piVar19,puVar4[1],
                          (long)*(ulong *)(piVar19 + 4) >> 4 ^ *(ulong *)(piVar19 + 4),*puVar4);
        }
        uVar9 = func_0x005f0f70(*(undefined4 *)(puVar4 + 4));
        local_70 = lVar20;
        local_68 = puVar4;
        if (*piVar19 == 2) {
          lVar20 = *in_GS_OFFSET;
          if (*(long *)(piVar19 + 0x10) == 0) {
LAB_003b5516:
            iVar8 = piVar19[0xc];
            lVar20 = 0;
          }
          else {
            plVar11 = *(long **)(piVar19 + 4);
            local_3c = uVar9;
            func_0x007b1b50(lVar20);
            uVar17 = plVar11[1];
            iVar8 = 0x16;
            if (uVar17 < 0x80000000) {
              lVar12 = *(long *)(piVar19 + 0x10);
              lVar14 = *plVar11;
              if ((lVar14 < 0) && (*(int *)(*(long *)(lVar12 + 0x18) + 0x1d4) != 4)) {
                uVar18 = 0x13aedf1;
                uVar16 = 0x45b;
LAB_003b563e:
                iVar8 = 0x16;
                func_0x0025d410(0x13a42ee,uVar18,uVar16);
                lVar20 = 0;
                uVar9 = local_3c;
                goto LAB_003b5653;
              }
              if (*(long *)(piVar19 + 10) != 0) {
                iVar8 = *(int *)(*(long *)(piVar19 + 10) + 0x4c);
                if (iVar8 != 0) goto LAB_003b5503;
                lVar14 = local_38[6];
                uVar17 = local_38[7];
                plVar11 = local_a0;
              }
              local_c8 = plVar11[2];
              local_f8 = &local_c8;
              local_f0 = 1;
              local_d8 = 0x100000000;
              uVar16 = *(undefined8 *)(lVar12 + 0x10);
              local_e8 = lVar14;
              local_e0 = uVar17;
              local_d0 = lVar20;
              local_c0 = uVar17;
              local_98 = uVar17;
              uVar10 = func_0x005f0f50();
              local_60 = lVar12;
              iVar8 = func_0x004eccf0(lVar12);
              if (iVar8 != 0) {
                func_0x005f0f70(uVar10 | 0x4000000);
              }
              pcVar5 = *(code **)(*(long *)(local_60 + 8) + 8);
              lVar12 = -(long)pcVar5;
              if (0x14 < (lVar12 + 0x26eab0U >> 3 | lVar12 << 0x3d)) {
                    /* WARNING: Bad instruction - Truncating control flow here */
                halt_baddata();
              }
              iVar8 = (*pcVar5)(local_60,&local_f8,uVar16,1,lVar20);
              func_0x005f0f70(uVar10);
              uVar17 = local_98;
              goto LAB_003b560d;
            }
LAB_003b5503:
            lVar20 = 0;
            uVar9 = local_3c;
          }
        }
        else if (*piVar19 == 1) {
          lVar20 = *in_GS_OFFSET;
          if (*(long *)(piVar19 + 0x10) == 0) goto LAB_003b5516;
          plVar11 = *(long **)(piVar19 + 4);
          local_3c = uVar9;
          func_0x007b1b50(lVar20);
          uVar17 = plVar11[1];
          iVar8 = 0x16;
          if (0x7fffffff < uVar17) goto LAB_003b5503;
          lVar12 = *(long *)(piVar19 + 0x10);
          lVar14 = *plVar11;
          if ((lVar14 < 0) && (*(int *)(*(long *)(lVar12 + 0x18) + 0x1d4) != 4)) {
            uVar18 = 0x138459e;
            uVar16 = 0x41d;
            goto LAB_003b563e;
          }
          if (*(long *)(piVar19 + 10) != 0) {
            iVar8 = *(int *)(*(long *)(piVar19 + 10) + 0x4c);
            if (iVar8 != 0) goto LAB_003b5503;
            lVar14 = local_38[6];
            uVar17 = local_38[7];
            plVar11 = local_a0;
          }
          local_c8 = plVar11[2];
          local_f8 = &local_c8;
          local_f0 = 1;
          local_d8 = 0;
          lVar21 = -(long)**(undefined8 **)(lVar12 + 8);
          if (0x14 < (lVar21 + 0x26eab0U >> 3 | lVar21 << 0x3d)) {
                    /* WARNING: Bad instruction - Truncating control flow here */
            halt_baddata();
          }
          local_e8 = lVar14;
          local_e0 = uVar17;
          local_d0 = lVar20;
          local_c0 = uVar17;
          iVar8 = (*(code *)**(undefined8 **)(lVar12 + 8))
                            (lVar12,&local_f8,*(undefined8 *)(lVar12 + 0x10),1,lVar20);
LAB_003b560d:
          lVar20 = uVar17 - local_e0;
          uVar9 = local_3c;
        }
        else {
          lVar20 = 0;
          iVar8 = 0;
        }
LAB_003b5653:
        func_0x005f0f70(uVar9);
        plVar11 = local_38;
        lVar12 = *(long *)(piVar19 + 10);
        if (lVar12 != 0) {
          if (iVar8 == 0) {
            if (*(int *)(lVar12 + 0x4c) == 0) {
              LOCK();
              *(long *)(lVar12 + 0x40) = *(long *)(lVar12 + 0x40) + lVar20;
              UNLOCK();
              piVar6 = (int *)local_38[0xc];
              LOCK();
              iVar8 = *piVar6;
              *piVar6 = *piVar6 + -1;
              UNLOCK();
              lVar20 = local_70;
              if (iVar8 == 1) {
                *(undefined1 *)((long)local_38 + 0x74) = 1;
                piVar19[0xe] = 3;
                iVar8 = func_0x00b078d0();
                if (iVar8 != 0) {
                  func_0x000a45e0(piVar19,plVar11,local_68);
                }
                lVar20 = *(long *)(piVar19 + 4);
                if (*(long *)(lVar20 + 0x18) != 0) {
                  uVar17 = *(ulong *)(lVar12 + 0x40);
                  *(ulong *)(piVar19 + 0xc) = uVar17;
                  if (*(int *)(lVar12 + 0x4c) != 0) {
                    if (uVar17 == 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
                      halt_baddata();
                    }
                    uVar17 = (ulong)(uint)((*(int *)(lVar12 + 0x54) + -1) * *(int *)(lVar12 + 0x50))
                    ;
                    *(ulong *)(lVar12 + 0x40) = uVar17;
                    if (*(ulong *)(piVar19 + 0xc) != uVar17) {
                      func_0x0025d410(0x12dd87c,0x12dd8b7,0x60d);
                      func_0x0025d410(0x1379dcb,0x12dd8b7,0x60f,*(undefined4 *)(lVar12 + 0x54),
                                      *(undefined4 *)(lVar12 + 0x50));
                      uVar17 = *(ulong *)(lVar12 + 0x40);
                    }
                  }
                  local_88 = CONCAT44(local_88._4_4_,piVar19[0xe]);
                  uVar16 = *(undefined8 *)(lVar20 + 0x18);
                  local_90 = uVar17;
                  func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
                  func_0x002591d0(&local_90,uVar16,0x10);
                }
                if (*(char *)(lVar12 + 0x48) == '\0') {
                  func_0x00c08df0(lVar12,0x1ab5a50);
                }
                else {
                  *(undefined1 *)(lVar12 + 0x48) = 0;
                }
                piVar19[10] = 0;
                piVar19[0xb] = 0;
                lVar20 = local_70;
              }
              goto LAB_003b58af;
            }
          }
          else if ((*(int *)(lVar12 + 0x4c) == 0) && (*(int *)(lVar12 + 0x54) == 0)) {
            LOCK();
            bVar23 = *(int *)(lVar12 + 0x54) == 0;
            if (bVar23) {
              *(int *)(lVar12 + 0x54) = (int)local_38[0xe];
            }
            UNLOCK();
            if (bVar23) {
                    /* WARNING: Bad instruction - Truncating control flow here */
              halt_baddata();
            }
          }
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        if (iVar8 == 0) {
          *(long *)(piVar19 + 0xc) = lVar20;
        }
        else {
          *(long *)(piVar19 + 0xc) = (long)(iVar8 + -0x7ffe0000);
          if (((iVar8 == 0x60) || (iVar8 == 5)) && (*piVar19 == 1)) {
            lVar20 = local_38[3];
            lVar12 = func_0x003b6860(*(undefined8 *)(piVar19 + 0x10));
            if (lVar12 != 0) {
              *(int *)(lVar20 + 0x5a0) = iVar8;
            }
          }
        }
        piVar19[0xe] = 3;
        iVar8 = func_0x00b078d0();
        if (iVar8 != 0) {
          func_0x000a45e0(piVar19,local_38,local_68);
        }
        lVar20 = local_70;
        if (*(long *)(*(long *)(piVar19 + 4) + 0x18) != 0) {
          local_90 = *(ulong *)(piVar19 + 0xc);
          local_88 = CONCAT44(local_88._4_4_,piVar19[0xe]);
          uVar16 = *(undefined8 *)(*(long *)(piVar19 + 4) + 0x18);
          func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
          func_0x002591d0(&local_90,uVar16,0x10);
        }
LAB_003b58af:
        *(long *)((long)local_78 + 0x200) = local_50;
        func_0x008def40(lVar20);
        pcVar13 = (char *)func_0x002c61a0(local_80);
        *pcVar13 = *pcVar13 + (char)pcVar13;
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      bVar23 = 1 < uVar17;
      uVar17 = uVar17 - 1;
    } while (bVar23);
    param_1[2] = 0;
    func_0x004c6a00(0x34cf2e8,0,0);
    *param_1 = local_a8;
    iVar8 = func_0x0073e780(0x34cf2f0,0x34cf2d0,0);
    *param_1 = 0;
    func_0x004c6fa0(0x34cf2e8,0,0);
    if (local_54 != 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    if (iVar8 != 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
  } while( true );
LAB_003b4cb0:
  piVar19 = *(int **)(piVar19 + 0x12);
  param_1 = local_38;
  if (piVar19 == (int *)0x0) goto LAB_003b4e30;
  goto LAB_003b4cc2;
}


