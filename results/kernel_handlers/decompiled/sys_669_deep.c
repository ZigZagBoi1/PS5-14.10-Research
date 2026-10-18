/* REA 6.7.0 / Ghidra 12.1.4 recovered pseudocode, not original or buildable C.
 * Input: deep_669.bin, SHA256 30a89c6bcbe0dc50989fa6b3ee2eba7a195b05ee8bb4c99b4cca56a0ecc160f6
 * File offset zero maps to kernel RVA 0x3b2060; runtime VA = 0xffffffff8a9c0000 + RVA.
 * External bodies/types/data missing from this raw window remain unknown.
 * Function names are analyst seeds or Ghidra-generated; instruction truth is in .rea.asm.
 */

/* ===== sys_669 | RVA 0x3b2060 | file +0x0 | ev_1fa2a9c2ed7f12ed1dc7101ca89032965da8099854d4b3b6d25d717d76d0b362 =====
 * Body: [{"start":"0x3b2060","end":"0x3b207c"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted.","Ghidra Listing reports a terminal call at 0x3b2078 to 0x3b2080 sub_003b2080 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

void sys_669(undefined8 param_1,undefined4 *param_2)

{
  sub_003b2080(param_1,*param_2,*(undefined8 *)(param_2 + 2),param_2[4],param_2[6],
               *(undefined8 *)(param_2 + 8));
  return;
}



/* ===== sub_003b2080 | RVA 0x3b2080 | file +0x20 | ev_579b0c99e50ec99f774c8cde87ce62f98a5d9574e866bb20b08c30f4d589aa3b =====
 * Body: [{"start":"0x3b2080","end":"0x3b281d"},{"start":"0x3b2820","end":"0x3b28c2"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_003b2080(long param_1,uint param_2,undefined8 param_3,ulong param_4,ulong param_5,
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
  if ((*(int *)(lVar21 + 0x4a0) == 1) || (iVar7 = sub_003b3410(1,lVar21), iVar7 == 0)) {
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
          func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
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
              func_0x00bf1690(puVar11 + 4,0,0x1330a9f,0,1);
              uVar17 = local_c4;
            }
            else {
              puVar11 = (undefined8 *)func_0x00c08b50((int)local_d0 * 0x58,0x1ab5970,0x102);
              puVar13 = puVar11;
              do {
                *puVar13 = 0x100000001;
                *(undefined4 *)(puVar13 + 1) = 1;
                puVar13[10] = 0;
                func_0x00bf1690(puVar13 + 4,0,0x1330a9f,0,1);
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
            iVar7 = sub_003b3a40(puVar19,uVar16,lVar21);
            lVar21 = local_90;
            uVar5 = local_a8;
            uVar15 = local_b8;
            uVar22 = local_d0;
            if (iVar7 == 0) {
              puVar18[-2] = 0x3b2696;
              puVar18[-1] = 0;
              iVar7 = sub_003b3a90(uVar22,uVar5,uVar15,puVar12,lVar21);
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
            func_0x0025d410(0x131bf08,0x1379d6c,uVar16,iVar7);
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
                    func_0x0025d410(0x13069f7,0x136fb7e,0xb35);
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
            func_0x0025d410(0x131bf08,0x12fc41c,0xb13,iVar7);
            func_0x00c08df0(lVar21,0x1ab5890);
            func_0x0025d410(0x131bf08,0x1379d6c,0xdd6,iVar7);
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
  func_0x0025d410(0x131bf08,0x1379d6c,uVar16,iVar7);
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



/* ===== sys_670 | RVA 0x3b28d0 | file +0x870 | ev_636d07ac5fda5e39904811cdeeefeb3acb964ebc68ce3119d15f1f298ee74918 =====
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



/* ===== sub_003b2d50 | RVA 0x3b2d50 | file +0xcf0 | ev_9cc158ff8a0834c1e36c01b0f5c71c17db098e8c9b66e43bf365d0c930fb5b4a =====
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



/* ===== sub_003b3090 | RVA 0x3b3090 | file +0x1030 | ev_cb996cd14eb6ae55e142fa9292b62f1571b1b2f2aeacd539a9aba778145d718e =====
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



/* ===== sub_003b3410 | RVA 0x3b3410 | file +0x13b0 | ev_51d2e9401af7bee42f1552a611145b212384ab029f151898ea295e4b8eca8e53 =====
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



/* ===== sub_003b3a40 | RVA 0x3b3a40 | file +0x19e0 | ev_6f49814be2475d18820f07347d9dfa16905bd09f1c6db25ad8de67a609471d41 =====
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



/* ===== sub_003b3a90 | RVA 0x3b3a90 | file +0x1a30 | ev_91ae7b21faa25fca9cf3e91eea3920d2814fb95cc223f9a4a4e916de6b32edc1 =====
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



/* ===== sub_003b3e90 | RVA 0x3b3e90 | file +0x1e30 | ev_b58cab6c08536de31eeb275844bb94ea907bc6576d6f72a1da6fdcf594f34484 =====
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



/* ===== sub_003b3f10 | RVA 0x3b3f10 | file +0x1eb0 | ev_1aebc4bf54cbce62189e759fcc1a66738f69722cd394287159f8128970e4ea1f =====
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



/* ===== sub_003b3f50 | RVA 0x3b3f50 | file +0x1ef0 | ev_447ec428dd72654fcfb148c8beed9820a8078556512ae027271d8d199d2dbd3d =====
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



/* ===== sub_003b4190 | RVA 0x3b4190 | file +0x2130 | ev_c87329424604f02d21296ac71f2e27d336042b53a1ca8494e3ebefb19661a13c =====
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



/* ===== sub_003b4440 | RVA 0x3b4440 | file +0x23e0 | ev_7edf70aada842a4f6e12dba02b159a25a8cff5c3229d77a173341d38d8c1ceab =====
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



/* ===== sub_003b45c0 | RVA 0x3b45c0 | file +0x2560 | ev_b441326f3f58365712b836286be3c54475bb4be12b662e54718293629e94ac82 =====
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



/* ===== sub_003b4a80 | RVA 0x3b4a80 | file +0x2a20 | ev_35f5309c076369467af9886e65f374abdaa0482c28b1385dd9e758338283e7c7 =====
 * Body: [{"start":"0x3b4a80","end":"0x3b4bf9"},{"start":"0x3b4c00","end":"0x3b4d33"},{"start":"0x3b4d40","end":"0x3b4d80"},{"start":"0x3b4d90","end":"0x3b4e2b"},{"start":"0x3b4e30","end":"0x3b4e3b"},{"start":"0x3b4e40","end":"0x3b5152"},{"start":"0x3b5160","end":"0x3b542a"},{"start":"0x3b5430","end":"0x3b5acb"},{"start":"0x3b5ad0","end":"0x3b5d20"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_003b4a80(long *param_1)

{
  long lVar1;
  int *piVar2;
  undefined8 uVar3;
  code *pcVar4;
  undefined1 uVar5;
  int iVar6;
  undefined4 uVar7;
  uint uVar8;
  undefined8 uVar9;
  undefined8 uVar10;
  long *plVar11;
  long lVar12;
  long lVar13;
  undefined8 *puVar14;
  ulong uVar15;
  ulong uVar16;
  undefined8 uVar17;
  ulong uVar18;
  undefined8 uVar19;
  int *piVar20;
  int *piVar21;
  long lVar22;
  long lVar23;
  long *in_GS_OFFSET;
  bool bVar24;
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
  lVar13 = *in_GS_OFFSET;
  lVar1 = param_1[3];
  param_1[5] = (long)&local_54;
  func_0x00926460(0,0x4c,0x10000000,0);
  uVar9 = func_0x0073e000(0,0x134f73f,0x25da80,lVar13,0x2719,lVar13,0x2610d0);
  uVar10 = func_0x0073e000(0,0x1294465,0x25da88,lVar13,0xb,lVar13,0x2610d8);
  local_a8 = lVar13;
  func_0x00265358(lVar13,0);
  func_0x004c6a00(0x34cf2e8,0,0,0);
  if ((*(int *)(lVar1 + 0x4a0) < 0) && (iVar6 = func_0x0073e780(0x34cf2f0,0x34cf2d0,0), iVar6 != 0))
  {
    func_0x0025d410(0x1350799,0x13a42dc,0x720,iVar6,iVar6);
  }
  func_0x004c6fa0(0x34cf2e8,0,0,0);
  iVar6 = func_0x00b078d0();
  if (iVar6 != 0) {
    *(undefined4 *)(param_1 + 4) = 0;
  }
  local_a0 = param_1 + 6;
  local_b8 = lVar1 + 0x80;
  lVar13 = lVar1;
  local_48 = lVar1;
  local_38 = param_1;
LAB_003b4c27:
  do {
    func_0x009261b0();
    uVar18 = 3;
LAB_003b4c40:
    lVar22 = uVar18 * 0x20 + lVar1 + 0xd8;
    func_0x004c6a00(lVar22,0,0,0);
    piVar21 = (int *)0x0;
    if (*(int *)(lVar13 + 0x1c0 + uVar18 * 4) != 0) {
      lVar23 = uVar18 * 0x10;
      piVar21 = *(int **)(lVar1 + 0x40 + lVar23);
      if (piVar21 == (int *)0x0) {
LAB_003b4e30:
        piVar21 = (int *)0x0;
        lVar13 = local_48;
      }
      else {
        local_50 = lVar1 + 0x40 + lVar23;
LAB_003b4cc2:
        param_1[2] = *(long *)(*(long *)(piVar21 + 6) + 8);
        if (piVar21[0xe] == 2) {
          lVar12 = *(long *)(piVar21 + 10);
          if (lVar12 == 0) {
            func_0x0025d410(0x12fc3ea,0x13a42dc,0x77f);
          }
          if (*(char *)(lVar12 + 0x4a) == '\0') {
            if (*(char *)(lVar12 + 0x49) != '\0') break;
            uVar5 = 1;
          }
          else {
            uVar5 = 0;
          }
          *(undefined1 *)(lVar12 + 0x49) = 1;
          *(undefined1 *)((long)local_38 + 0x75) = uVar5;
          local_78 = *(long **)(piVar21 + 10);
          local_80 = local_38[3];
          iVar6 = (int)local_78[5] + 1;
          *(int *)(local_78 + 5) = iVar6;
          *(int *)(local_38 + 0xe) = iVar6;
          func_0x00259be0(local_78,local_a0,0x28);
          local_38[0xc] = (long)(local_78 + 6);
          uVar16 = local_78[7];
          uVar15 = (ulong)*(uint *)(local_80 + 400 + uVar18 * 4);
          if (uVar16 < uVar15) {
            local_38[7] = uVar16;
            local_78[7] = 0;
          }
          else {
            local_78[7] = uVar16 - uVar15;
            local_38[7] = (ulong)*(uint *)(local_80 + 400 + uVar18 * 4);
            *local_78 = *local_78 + (ulong)*(uint *)(local_80 + 400 + uVar18 * 4);
            local_78[2] = local_78[2] + (ulong)*(uint *)(local_80 + 400 + uVar18 * 4);
          }
          *(undefined1 *)((long)local_38 + 0x74) = 0;
          if (*(int *)(lVar12 + 0x4c) != 0) {
            do {
              iVar6 = *(int *)(lVar12 + 0x30);
              LOCK();
              bVar24 = iVar6 == *(int *)(lVar12 + 0x30);
              if (bVar24) {
                *(int *)(lVar12 + 0x30) =
                     (*(int *)(lVar12 + 0x28) + iVar6) - *(int *)(lVar12 + 0x2c);
              }
              UNLOCK();
            } while (!bVar24);
          }
          if ((*(long *)(lVar12 + 0x38) != 0) &&
             (param_1 = local_38, lVar13 = local_48, *(int *)(lVar12 + 0x4c) == 0))
          goto LAB_003b50e0;
          lVar13 = *(long *)(piVar21 + 0x12);
          piVar20 = piVar21 + 0x12;
          if (lVar13 == 0) {
            if ((int *)**(undefined8 **)(piVar21 + 0x14) != piVar21) {
LAB_003b5ca1:
              func_0x007f1950();
              func_0x007f20c0(0x3b5ca1,piVar21,*(undefined8 **)(piVar21 + 0x14),
                              **(undefined8 **)(piVar21 + 0x14));
              puVar14 = *(undefined8 **)(piVar21 + 0x14);
              uVar9 = 0x1b;
LAB_003b5cce:
              uVar10 = *puVar14;
              goto LAB_003b5cd4;
            }
            *(undefined8 **)(local_50 + 8) = *(undefined8 **)(piVar21 + 0x14);
          }
          else {
            if (*(int **)(lVar13 + 0x50) != piVar20) {
              func_0x007f1950();
              func_0x007f2180(0x3b5cdd,piVar21,*(long *)(piVar21 + 0x12),
                              *(undefined8 *)(*(long *)(piVar21 + 0x12) + 0x50),piVar20);
              lVar13 = *(long *)(piVar21 + 0x12);
              uVar9 = 0x17;
LAB_003b5d0e:
              piVar20 = piVar21 + 0x12;
              uVar10 = *(undefined8 *)(lVar13 + 0x50);
              goto LAB_003b5d18;
            }
            if ((int *)**(undefined8 **)(piVar21 + 0x14) != piVar21) goto LAB_003b5ca1;
            *(undefined8 **)(lVar13 + 0x50) = *(undefined8 **)(piVar21 + 0x14);
          }
          **(undefined8 **)(piVar21 + 0x14) = *(undefined8 *)piVar20;
          piVar20 = (int *)(local_48 + 0x1c0 + uVar18 * 4);
          *piVar20 = *piVar20 + -1;
        }
        else {
          if (piVar21[0xe] != 1) break;
          if (_DAT_034d09c0 != (long *)0x0) {
            func_0x004c6a00(0x34cf2e8,0,0,0);
            if (_DAT_034d09c0 != (long *)0x0) {
              plVar11 = _DAT_034d09c0;
              while (*(long *)(*(long *)(piVar21 + 6) + 8) != *plVar11) {
                plVar11 = (long *)plVar11[1];
                if (plVar11 == (long *)0x0) goto LAB_003b4d90;
              }
              func_0x004c6fa0(0x34cf2e8,0,0);
              break;
            }
LAB_003b4d90:
            func_0x004c6fa0(0x34cf2e8,0,0,0);
          }
          param_1 = local_38;
          if ((*(int *)(local_48 + 0x1a0 + uVar18 * 4) == 0) || (*piVar21 != 1)) {
            lVar13 = *(long *)(piVar21 + 0x12);
            if (lVar13 == 0) {
              if ((int *)**(undefined8 **)(piVar21 + 0x14) != piVar21) {
LAB_003b5af7:
                func_0x007f1950();
                func_0x007f20c0(0x3b5af7,piVar21,*(undefined8 **)(piVar21 + 0x14),
                                **(undefined8 **)(piVar21 + 0x14));
                puVar14 = *(undefined8 **)(piVar21 + 0x14);
                uVar9 = 0x13;
                goto LAB_003b5cce;
              }
              *(undefined8 **)(local_50 + 8) = *(undefined8 **)(piVar21 + 0x14);
            }
            else {
              if (*(int **)(lVar13 + 0x50) != piVar21 + 0x12) {
                func_0x007f1950();
                func_0x007f2180(0x3b5b5f,piVar21,*(long *)(piVar21 + 0x12),
                                *(undefined8 *)(*(long *)(piVar21 + 0x12) + 0x50),piVar21 + 0x12);
                lVar13 = *(long *)(piVar21 + 0x12);
                uVar9 = 0xf;
                goto LAB_003b5d0e;
              }
              if ((int *)**(undefined8 **)(piVar21 + 0x14) != piVar21) goto LAB_003b5af7;
              *(undefined8 **)(lVar13 + 0x50) = *(undefined8 **)(piVar21 + 0x14);
            }
            **(undefined8 **)(piVar21 + 0x14) = *(undefined8 *)(piVar21 + 0x12);
            piVar21[0xe] = 2;
            piVar20 = (int *)(local_48 + 0x1c0 + uVar18 * 4);
            *piVar20 = *piVar20 + -1;
          }
          else {
            uVar16 = *(ulong *)(*(long *)(piVar21 + 4) + 8);
            if (((*(uint *)(local_48 + 0x1b0 + uVar18 * 4) < uVar16) && (uVar16 < 0x80000000)) &&
               (*(uint *)(local_48 + 400 + uVar18 * 4) < uVar16)) {
              func_0x003b66b0(piVar21,uVar18 & 0xffffffff,local_38);
              piVar21[0xe] = 2;
              *(undefined8 *)(local_48 + 0x140 + uVar18 * 8) = *(undefined8 *)(piVar21 + 2);
              lVar13 = local_48;
              goto LAB_003b50e0;
            }
            lVar13 = *(long *)(piVar21 + 0x12);
            if (lVar13 == 0) {
              if ((int *)**(undefined8 **)(piVar21 + 0x14) != piVar21) {
LAB_003b5bd6:
                func_0x007f1950();
                func_0x007f20c0(0x3b5bd6,piVar21,*(undefined8 **)(piVar21 + 0x14),
                                **(undefined8 **)(piVar21 + 0x14));
                puVar14 = *(undefined8 **)(piVar21 + 0x14);
                uVar9 = 0xb;
                goto LAB_003b5cce;
              }
              *(undefined8 **)(local_50 + 8) = *(undefined8 **)(piVar21 + 0x14);
            }
            else {
              if (*(int **)(lVar13 + 0x50) != piVar21 + 0x12) {
                func_0x007f1950();
                func_0x007f2180(0x3b5c08,piVar21,*(long *)(piVar21 + 0x12),
                                *(undefined8 *)(*(long *)(piVar21 + 0x12) + 0x50),piVar21 + 0x12);
                lVar13 = *(long *)(piVar21 + 0x12);
                uVar9 = 7;
                goto LAB_003b5d0e;
              }
              if ((int *)**(undefined8 **)(piVar21 + 0x14) != piVar21) goto LAB_003b5bd6;
              *(undefined8 **)(lVar13 + 0x50) = *(undefined8 **)(piVar21 + 0x14);
            }
            **(undefined8 **)(piVar21 + 0x14) = *(undefined8 *)(piVar21 + 0x12);
            piVar20 = (int *)(local_48 + 0x1c0 + uVar18 * 4);
            *piVar20 = *piVar20 + -1;
            piVar21[0xe] = 2;
          }
          *(undefined8 *)(local_48 + 0x140 + uVar18 * 8) = *(undefined8 *)(piVar21 + 2);
        }
        lVar13 = local_48;
        piVar2 = *(int **)(local_b8 + lVar23);
        param_1 = local_38;
        if (piVar2 != (int *)0x0) {
          lVar12 = *(long *)(piVar2 + 0x12);
          piVar20 = piVar2 + 0x12;
          if (lVar12 == 0) {
            if ((int *)**(undefined8 **)(piVar2 + 0x14) != piVar2) {
LAB_003b5b29:
              func_0x007f1950();
              func_0x007f20c0(0x3b5b29,piVar2,*(undefined8 **)(piVar2 + 0x14),
                              **(undefined8 **)(piVar2 + 0x14));
              puVar14 = *(undefined8 **)(piVar2 + 0x14);
              uVar9 = 0x23;
              uVar10 = *puVar14;
              piVar21 = piVar2;
LAB_003b5cd4:
              func_0x00c9aa10(uVar9,0x131bb64,piVar21,puVar14,uVar10);
                    /* WARNING: Does not return */
              pcVar4 = (code *)invalidInstructionException();
              (*pcVar4)();
            }
            *(undefined8 **)(lVar23 + local_b8 + 8) = *(undefined8 **)(piVar2 + 0x14);
          }
          else {
            if (*(int **)(lVar12 + 0x50) != piVar20) {
              func_0x007f1950();
              func_0x007f2180(0x3b5b95,piVar2,*(long *)(piVar2 + 0x12),
                              *(undefined8 *)(*(long *)(piVar2 + 0x12) + 0x50),piVar20);
              lVar13 = *(long *)(piVar2 + 0x12);
              uVar9 = 0x1f;
              uVar10 = *(undefined8 *)(lVar13 + 0x50);
              piVar21 = piVar2;
LAB_003b5d18:
              func_0x00c9aa10(uVar9,0x136f6f3,piVar21,lVar13,uVar10,piVar20);
                    /* WARNING: Does not return */
              pcVar4 = (code *)invalidInstructionException();
              (*pcVar4)();
            }
            if ((int *)**(undefined8 **)(piVar2 + 0x14) != piVar2) goto LAB_003b5b29;
            *(undefined8 **)(lVar12 + 0x50) = *(undefined8 **)(piVar2 + 0x14);
          }
          **(undefined8 **)(piVar2 + 0x14) = *(undefined8 *)(piVar2 + 0x12);
          iVar6 = *(int *)(local_48 + 0x1d0 + uVar18 * 4);
          *(int *)(local_48 + 0x1d0 + uVar18 * 4) = iVar6 + 1;
          piVar2[1] = iVar6;
          if (*(long *)(piVar2 + 2) == 0) {
            piVar2[0x12] = 0;
            piVar2[0x13] = 0;
            puVar14 = *(undefined8 **)(local_50 + 8);
            *(undefined8 **)(piVar2 + 0x14) = puVar14;
            *puVar14 = piVar2;
            *(int **)(local_50 + 8) = piVar20;
          }
          else {
            sub_003b4440(piVar2);
            param_1 = local_38;
          }
        }
      }
    }
LAB_003b50e0:
    iVar6 = func_0x00b078d0();
    if ((iVar6 != 0) && ((int)param_1[4] != 0)) {
      *(undefined4 *)(param_1 + 4) = 0;
    }
    func_0x004c6fa0(lVar22,0,0);
    if (piVar21 == (int *)0x0) {
      bVar24 = uVar18 < 2;
      uVar18 = uVar18 - 1;
      if (bVar24) goto LAB_003b5430;
      goto LAB_003b4c40;
    }
    lVar22 = *(long *)(piVar21 + 8);
    lVar13 = lVar22 + 0x20;
    func_0x00bf1770(lVar13,0x80000,0,0,0,0,0,0);
    if (*(int *)(lVar22 + 8) == 1) {
      *(undefined4 *)(lVar22 + 8) = 2;
    }
    func_0x00bf1770(lVar13,0x100000,0,0,0,0,0,0);
    func_0x004c6a00(0x34cf2e8,0,0,0);
    if (*(long *)(local_48 + 0x4b0) != 0) {
      func_0x0073ef80(0x34cf2f0);
    }
    local_b0 = lVar13;
    if (*(long *)(local_48 + 0x528) != 0) {
      func_0x0073ef80(0x34cf2f0);
    }
    func_0x004c6fa0(0x34cf2e8,0,0,0);
    lVar13 = *in_GS_OFFSET;
    local_88 = 0;
    local_90 = 0;
    puVar14 = *(undefined8 **)(piVar21 + 6);
    uVar3 = *(undefined8 *)(lVar13 + 0x140);
    local_78 = *(long **)(lVar13 + 8);
    local_50 = local_78[0x40];
    local_80 = *(long *)(puVar14[1] + 0x200);
    *(undefined8 *)(lVar13 + 0x390) = *puVar14;
    *(undefined8 *)(lVar13 + 0x140) = puVar14[2];
    *(undefined8 *)(lVar13 + 0x5d0) = *(undefined8 *)(piVar21 + 4);
    if (local_50 != local_80) {
      lVar23 = local_78[0x40];
      local_78[0x40] = local_80;
      LOCK();
      *(int *)(local_80 + 0x2e0) = *(int *)(local_80 + 0x2e0) + 1;
      UNLOCK();
      func_0x008def40(lVar13);
      if (local_50 != lVar23) {
        func_0x002c61a0(local_50);
      }
    }
    iVar6 = func_0x00b078d0();
    if (iVar6 != 0) {
      func_0x000a4550(*piVar21,puVar14[1],
                      (long)*(ulong *)(piVar21 + 4) >> 4 ^ *(ulong *)(piVar21 + 4),*puVar14);
    }
    uVar7 = func_0x005f0f70(*(undefined4 *)(puVar14 + 4));
    local_70 = lVar13;
    local_68 = puVar14;
    if (*piVar21 == 2) {
      lVar13 = *in_GS_OFFSET;
      if (*(long *)(piVar21 + 0x10) == 0) {
LAB_003b5516:
        iVar6 = piVar21[0xc];
        lVar13 = 0;
      }
      else {
        plVar11 = *(long **)(piVar21 + 4);
        local_3c = uVar7;
        func_0x007b1b50(lVar13);
        uVar18 = plVar11[1];
        iVar6 = 0x16;
        if (uVar18 < 0x80000000) {
          lVar23 = *(long *)(piVar21 + 0x10);
          lVar12 = *plVar11;
          if ((lVar12 < 0) && (*(int *)(*(long *)(lVar23 + 0x18) + 0x1d4) != 4)) {
            uVar19 = 0x13aedf1;
            uVar17 = 0x45b;
LAB_003b563e:
            iVar6 = 0x16;
            func_0x0025d410(0x13a42ee,uVar19,uVar17);
            lVar13 = 0;
            uVar7 = local_3c;
            goto LAB_003b5653;
          }
          if (*(long *)(piVar21 + 10) != 0) {
            iVar6 = *(int *)(*(long *)(piVar21 + 10) + 0x4c);
            if (iVar6 != 0) goto LAB_003b5503;
            lVar12 = local_38[6];
            uVar18 = local_38[7];
            plVar11 = local_a0;
          }
          local_c8 = plVar11[2];
          local_f8 = &local_c8;
          local_f0 = 1;
          local_d8 = 0x100000000;
          uVar17 = *(undefined8 *)(lVar23 + 0x10);
          local_e8 = lVar12;
          local_e0 = uVar18;
          local_d0 = lVar13;
          local_c0 = uVar18;
          local_98 = uVar18;
          uVar8 = func_0x005f0f50();
          local_60 = lVar23;
          iVar6 = func_0x004eccf0(lVar23);
          if (iVar6 != 0) {
            func_0x005f0f70(uVar8 | 0x4000000);
          }
          pcVar4 = *(code **)(*(long *)(local_60 + 8) + 8);
          if (0x14 < (-(long)pcVar4 + 0x26eab0U >> 3 | -(long)pcVar4 << 0x3d)) {
            func_0x0044f8c0(0x1ab5c40,pcVar4);
          }
          iVar6 = (*pcVar4)(local_60,&local_f8,uVar17,1);
          func_0x005f0f70(uVar8);
          uVar18 = local_98;
          goto LAB_003b560d;
        }
LAB_003b5503:
        lVar13 = 0;
        uVar7 = local_3c;
      }
    }
    else if (*piVar21 == 1) {
      lVar13 = *in_GS_OFFSET;
      if (*(long *)(piVar21 + 0x10) == 0) goto LAB_003b5516;
      plVar11 = *(long **)(piVar21 + 4);
      local_3c = uVar7;
      func_0x007b1b50(lVar13);
      uVar18 = plVar11[1];
      iVar6 = 0x16;
      if (0x7fffffff < uVar18) goto LAB_003b5503;
      lVar23 = *(long *)(piVar21 + 0x10);
      lVar12 = *plVar11;
      if ((lVar12 < 0) && (*(int *)(*(long *)(lVar23 + 0x18) + 0x1d4) != 4)) {
        uVar19 = 0x138459e;
        uVar17 = 0x41d;
        goto LAB_003b563e;
      }
      if (*(long *)(piVar21 + 10) != 0) {
        iVar6 = *(int *)(*(long *)(piVar21 + 10) + 0x4c);
        if (iVar6 != 0) goto LAB_003b5503;
        lVar12 = local_38[6];
        uVar18 = local_38[7];
        plVar11 = local_a0;
      }
      local_c8 = plVar11[2];
      local_f8 = &local_c8;
      local_f0 = 1;
      local_d8 = 0;
      pcVar4 = (code *)**(undefined8 **)(lVar23 + 8);
      uVar16 = *(ulong *)(lVar23 + 0x10);
      local_e8 = lVar12;
      local_e0 = uVar18;
      local_d0 = lVar13;
      local_c0 = uVar18;
      if (0x14 < (-(long)pcVar4 + 0x26eab0U >> 3 | -(long)pcVar4 << 0x3d)) {
        local_98 = *(ulong *)(lVar23 + 0x10);
        local_60 = lVar23;
        func_0x0044f8c0(0x1ab5c20,pcVar4);
        uVar16 = local_98;
        lVar23 = local_60;
      }
      iVar6 = (*pcVar4)(lVar23,&local_f8,uVar16,1);
LAB_003b560d:
      lVar13 = uVar18 - local_e0;
      uVar7 = local_3c;
    }
    else {
      lVar13 = 0;
      iVar6 = 0;
    }
LAB_003b5653:
    func_0x005f0f70(uVar7);
    plVar11 = local_38;
    lVar23 = *(long *)(piVar21 + 10);
    if (lVar23 == 0) {
      if (iVar6 == 0) {
        *(long *)(piVar21 + 0xc) = lVar13;
      }
      else {
        *(long *)(piVar21 + 0xc) = (long)(iVar6 + -0x7ffe0000);
        if (((iVar6 == 0x60) || (iVar6 == 5)) && (*piVar21 == 1)) {
          lVar13 = local_38[3];
          lVar23 = func_0x003b6860(*(undefined8 *)(piVar21 + 0x10));
          if (lVar23 != 0) {
            *(int *)(lVar13 + 0x5a0) = iVar6;
          }
        }
      }
      piVar21[0xe] = 3;
      iVar6 = func_0x00b078d0();
      if (iVar6 != 0) {
        func_0x000a45e0(piVar21,local_38,local_68);
      }
      lVar13 = local_70;
      if (*(long *)(*(long *)(piVar21 + 4) + 0x18) != 0) {
        local_90 = *(ulong *)(piVar21 + 0xc);
        local_88 = CONCAT44(local_88._4_4_,piVar21[0xe]);
        uVar17 = *(undefined8 *)(*(long *)(piVar21 + 4) + 0x18);
        func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
        func_0x002591d0(&local_90,uVar17,0x10);
      }
    }
    else {
      if (iVar6 == 0) {
        if (*(int *)(lVar23 + 0x4c) != 0) goto LAB_003b5ad4;
        LOCK();
        *(long *)(lVar23 + 0x40) = *(long *)(lVar23 + 0x40) + lVar13;
        UNLOCK();
      }
      else {
        if ((*(int *)(lVar23 + 0x4c) == 0) && (*(int *)(lVar23 + 0x54) == 0)) {
          LOCK();
          bVar24 = *(int *)(lVar23 + 0x54) == 0;
          if (bVar24) {
            *(int *)(lVar23 + 0x54) = (int)local_38[0xe];
          }
          UNLOCK();
          if (bVar24) goto LAB_003b5ad0;
        }
LAB_003b5ad4:
        while ((int)local_38[0xe] < *(int *)(lVar23 + 0x54)) {
          if (iVar6 != 0) {
            LOCK();
            bVar24 = *(int *)(lVar23 + 0x54) == *(int *)(lVar23 + 0x54);
            if (bVar24) {
              *(int *)(lVar23 + 0x54) = (int)local_38[0xe];
            }
            UNLOCK();
            if (bVar24) {
LAB_003b5ad0:
              *(int *)(lVar23 + 0x4c) = iVar6;
            }
          }
        }
      }
      piVar20 = (int *)local_38[0xc];
      LOCK();
      iVar6 = *piVar20;
      *piVar20 = *piVar20 + -1;
      UNLOCK();
      lVar13 = local_70;
      if (iVar6 == 1) {
        *(undefined1 *)((long)local_38 + 0x74) = 1;
        piVar21[0xe] = 3;
        iVar6 = func_0x00b078d0();
        if (iVar6 != 0) {
          func_0x000a45e0(piVar21,plVar11,local_68);
        }
        lVar13 = *(long *)(piVar21 + 4);
        if (*(long *)(lVar13 + 0x18) != 0) {
          uVar18 = *(ulong *)(lVar23 + 0x40);
          *(ulong *)(piVar21 + 0xc) = uVar18;
          if (*(int *)(lVar23 + 0x4c) != 0) {
            if (uVar18 == 0) {
              local_90 = (ulong)(*(int *)(lVar23 + 0x4c) + -0x7ffe0000);
              iVar6 = *(int *)(lVar23 + 0x4c);
              uVar18 = local_90;
              if (((iVar6 == 0x60) || (iVar6 == 5)) && (*piVar21 == 1)) {
                local_68 = (undefined8 *)local_38[3];
                lVar12 = func_0x003b6860(*(undefined8 *)(piVar21 + 0x10));
                uVar18 = local_90;
                if (lVar12 != 0) {
                  *(int *)(local_68 + 0xb4) = iVar6;
                }
              }
            }
            else {
              uVar18 = (ulong)(uint)((*(int *)(lVar23 + 0x54) + -1) * *(int *)(lVar23 + 0x50));
              *(ulong *)(lVar23 + 0x40) = uVar18;
              if (*(ulong *)(piVar21 + 0xc) != uVar18) {
                func_0x0025d410(0x12dd87c,0x12dd8b7,0x60d);
                func_0x0025d410(0x1379dcb,0x12dd8b7,0x60f,*(undefined4 *)(lVar23 + 0x54));
                uVar18 = *(ulong *)(lVar23 + 0x40);
              }
            }
          }
          local_90 = uVar18;
          local_88 = CONCAT44(local_88._4_4_,piVar21[0xe]);
          uVar17 = *(undefined8 *)(lVar13 + 0x18);
          func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
          func_0x002591d0(&local_90,uVar17,0x10);
        }
        if (*(char *)(lVar23 + 0x48) == '\0') {
          func_0x00c08df0(lVar23);
        }
        else {
          *(undefined1 *)(lVar23 + 0x48) = 0;
        }
        piVar21[10] = 0;
        piVar21[0xb] = 0;
        lVar13 = local_70;
      }
    }
    local_78[0x40] = local_50;
    func_0x008def40(lVar13);
    func_0x002c61a0(local_80);
    param_1 = local_38;
    *(undefined8 *)(lVar13 + 0x140) = uVar3;
    *(undefined8 *)(lVar13 + 0x5d0) = 0;
    if (((int)local_38[0xe] != 0) && (*(char *)((long)local_38 + 0x74) == '\0')) {
      if (*(char *)((long)local_38 + 0x75) != '\0') {
        *(undefined1 *)(*(long *)(piVar21 + 10) + 0x49) = 0;
      }
      *(undefined4 *)(local_38 + 0xe) = 0;
      lVar13 = local_48;
      goto LAB_003b4c27;
    }
    *(undefined4 *)(local_38 + 0xe) = 0;
    func_0x00bf1770(local_b0,0x80000,0,0,0,0,0,0);
    *(int *)(lVar22 + 4) = *(int *)(lVar22 + 4) + -1;
    piVar21[0xe] = 3;
    if (*(long *)(piVar21 + 0x10) != 0) {
      LOCK();
      piVar20 = (int *)(*(long *)(piVar21 + 0x10) + 0x28);
      iVar6 = *piVar20;
      *piVar20 = *piVar20 + -1;
      UNLOCK();
      if (iVar6 == 1) {
        func_0x0072b380(*(undefined8 *)(piVar21 + 0x10),local_a8);
      }
      piVar21[0x10] = 0;
      piVar21[0x11] = 0;
    }
    if (*(int *)(lVar22 + 4) == 0) {
      *(uint *)(lVar22 + 8) = 4 - (uint)(*(char *)(lVar22 + 0xd) == '\0');
      puVar14 = *(undefined8 **)(lVar22 + 0x50);
      if (puVar14 != (undefined8 *)0x0) {
        bVar24 = false;
        do {
          *(undefined4 *)(puVar14 + 4) = *(undefined4 *)(lVar22 + 8);
          func_0x004c6a00(puVar14[2] + 0x18,0,0);
          *(int *)*puVar14 = *(int *)*puVar14 + -1;
          piVar21 = (int *)*puVar14;
          if (*piVar21 < 1) {
            piVar20 = (int *)puVar14[1];
            if (piVar20 != (int *)0x0) {
              *piVar20 = *piVar20 + -1;
              if ((bVar24) && (bVar24 = true, *(int *)puVar14[1] != 0)) goto LAB_003b59a5;
              piVar21 = (int *)*puVar14;
              bVar24 = true;
            }
            func_0x00c06910(piVar21);
          }
LAB_003b59a5:
          func_0x004c6fa0(puVar14[2] + 0x18,0,0);
          puVar14 = (undefined8 *)puVar14[6];
        } while (puVar14 != (undefined8 *)0x0);
      }
    }
    func_0x00bf1770(local_b0,0x100000,0,0,0,0,0,0);
    lVar13 = local_48;
  } while( true );
  piVar21 = *(int **)(piVar21 + 0x12);
  param_1 = local_38;
  if (piVar21 == (int *)0x0) goto LAB_003b4e30;
  goto LAB_003b4cc2;
LAB_003b5430:
  param_1[2] = 0;
  func_0x004c6a00(0x34cf2e8,0,0);
  *param_1 = local_a8;
  iVar6 = func_0x0073e780(0x34cf2f0,0x34cf2d0,0);
  *param_1 = 0;
  func_0x004c6fa0(0x34cf2e8,0,0);
  if (local_54 != 0) goto LAB_003b5c5a;
  if (iVar6 != 0) {
    func_0x0025d410(0x131bf08,0x13a42dc,0x850,iVar6);
LAB_003b5c5a:
    lVar13 = func_0x0073e2e0(0x134f73f);
    if (lVar13 != 0) {
      func_0x0073e080(lVar13,uVar9);
    }
    lVar13 = func_0x0073e2e0(0x1294465);
    if (lVar13 != 0) {
      func_0x0073e080(lVar13,uVar10);
    }
    func_0x00925d80();
                    /* WARNING: Does not return */
    pcVar4 = (code *)invalidInstructionException();
    (*pcVar4)();
  }
  goto LAB_003b4c27;
}



/* ===== sub_003b5d30 | RVA 0x3b5d30 | file +0x3cd0 | ev_3ef11e6c5bade0c9cd744cb7800c3f7af816a664683e72c219cda97030c093c6 =====
 * Body: [{"start":"0x3b5d30","end":"0x3b5d87"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_003b5d30(undefined8 param_1,undefined8 param_2)

{
  undefined8 *puVar1;
  undefined8 *puVar2;
  
  func_0x004c6a00(0x34cf2e8,0,0,0);
  puVar2 = _DAT_034d09c8;
  *_DAT_034d09c8 = param_2;
  puVar1 = _DAT_034d09c8 + 1;
  _DAT_034d09c8 = (undefined8 *)_DAT_034d09c8[1];
  *puVar1 = _DAT_034d09c0;
  _DAT_034d09c0 = puVar2;
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== sub_003b5d90 | RVA 0x3b5d90 | file +0x3d30 | ev_f86bd286dcd14ea4bdd291c32867b97f885624a6c0644eed1b70fb5028f2ec22 =====
 * Body: [{"start":"0x3b5d90","end":"0x3b5e8c"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_003b5d90(undefined8 param_1,long param_2)

{
  code *pcVar1;
  int iVar2;
  long lVar3;
  uint local_2c;
  long local_28;
  
  local_28 = _DAT_0391c310;
  lVar3 = func_0x009f8180(param_2);
  iVar2 = func_0x009f81c0(param_2,&local_2c);
  if ((iVar2 == 0) && (local_2c < 0x1000000)) {
    if (local_2c < 0x10000) {
      if (_DAT_034cf7c8 == lVar3) {
        lVar3 = 0x34cf320;
      }
      else if (_DAT_034d08c0 == lVar3) {
        lVar3 = 0x34d0418;
      }
      else {
        lVar3 = 0x34d0418;
        if (_DAT_034cf7c0 == 0) {
          lVar3 = 0x34cf320;
        }
      }
      goto LAB_003b5df6;
    }
    if ((local_2c & 0xff0000) == 0x10000) {
      lVar3 = 0x34cfe70;
      goto LAB_003b5df6;
    }
  }
  lVar3 = 0x34cf8c8;
LAB_003b5df6:
  if (*(long *)(lVar3 + 0x4c0) == param_2) {
    func_0x002bc8b0(param_2,0x80);
    lVar3 = *(long *)(lVar3 + 0x538);
  }
  else {
    lVar3 = *(long *)(lVar3 + 0x538);
  }
  if (lVar3 == param_2) {
    func_0x002bc8b0(param_2,0x80);
  }
  if (_DAT_0391c310 == local_28) {
    return;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* ===== sub_003b5e90 | RVA 0x3b5e90 | file +0x3e30 | ev_5b63946abdda904c02eba6a2e9ed0ae01aae2c1dd9dc3090099c5d1d0b3c4914 =====
 * Body: [{"start":"0x3b5e90","end":"0x3b6017"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_003b5e90(undefined8 param_1,long param_2)

{
  long *plVar1;
  long *plVar2;
  code *pcVar3;
  int iVar4;
  long lVar5;
  long *plVar6;
  uint local_2c;
  long local_28;
  
  local_28 = _DAT_0391c310;
  lVar5 = func_0x009f8180(param_2);
  iVar4 = func_0x009f81c0(param_2,&local_2c);
  if ((iVar4 == 0) && (local_2c < 0x1000000)) {
    if (local_2c < 0x10000) {
      if (_DAT_034cf7c8 == lVar5) {
        lVar5 = 0x34cf320;
      }
      else if (_DAT_034d08c0 == lVar5) {
        lVar5 = 0x34d0418;
      }
      else {
        lVar5 = 0x34d0418;
        if (_DAT_034cf7c0 == 0) {
          lVar5 = 0x34cf320;
        }
      }
      goto LAB_003b5efa;
    }
    if ((local_2c & 0xff0000) == 0x10000) {
      lVar5 = 0x34cfe70;
      goto LAB_003b5efa;
    }
  }
  lVar5 = 0x34cf8c8;
LAB_003b5efa:
  func_0x004c6a00(0x34cf2e8,0,0,0);
  plVar1 = _DAT_034d09c0;
  while( true ) {
    if (plVar1 == (long *)0x0) goto LAB_003b5f73;
    if (param_2 == *plVar1) break;
    plVar1 = (long *)plVar1[1];
  }
  plVar2 = _DAT_034d09c0;
  if (_DAT_034d09c0 == plVar1) {
    _DAT_034d09c0 = (long *)_DAT_034d09c0[1];
  }
  else {
    do {
      plVar6 = plVar2;
      plVar2 = (long *)plVar6[1];
    } while (plVar2 != plVar1);
    plVar6[1] = plVar2[1];
  }
  plVar1[1] = (long)_DAT_034d09c8;
  _DAT_034d09c8 = plVar1;
LAB_003b5f73:
  if (*(long *)(lVar5 + 0x4b0) != 0) {
    func_0x0073ef80(0x34cf2f0);
  }
  if (*(long *)(lVar5 + 0x528) != 0) {
    func_0x0073ef80(0x34cf2f0);
  }
  func_0x004c6fa0(0x34cf2e8,0,0,0);
  if (_DAT_0391c310 == local_28) {
    return;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar3 = (code *)invalidInstructionException();
  (*pcVar3)();
}



/* ===== sub_003b6020 | RVA 0x3b6020 | file +0x3fc0 | ev_0e48701ede19d5178b5b45ff62a783f7531c25519c34880630ec77830173b4a6 =====
 * Body: [{"start":"0x3b6020","end":"0x3b605d"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_003b6020(undefined8 param_1,undefined8 param_2)

{
  int iVar1;
  undefined1 local_3c [4];
  undefined8 local_38;
  
  local_38 = _DAT_0391c310;
  func_0x009f8180(param_2);
  iVar1 = func_0x009f81c0(param_2,local_3c);
  if (iVar1 == 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


