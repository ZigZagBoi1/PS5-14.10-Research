/* REA 6.7.0 / Ghidra 12.1.4 recovered pseudocode, not original or buildable C.
 * Input: deep_643.bin, SHA256 710eca73f4191dd85e9b1ee3c73fb644e380f7dbaddaa49ab5c3866d0a8bde95
 * File offset zero maps to kernel RVA 0xa37660; runtime VA = 0xffffffff8a9c0000 + RVA.
 * External bodies/types/data missing from this raw window remain unknown.
 * Function names are analyst seeds or Ghidra-generated; instruction truth is in .rea.asm.
 */

/* ===== sys_643 | RVA 0xa37660 | file +0x0 | ev_00adfffcd4816d62b006e1f422e67525c3287c5f286724310b2900a5113473dd =====
 * Body: [{"start":"0xa37660","end":"0xa3768f"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sys_643(long param_1,uint *param_2)

{
  uint *puVar1;
  
  func_0x0025d410(0x13618e2,*param_2);
  puVar1 = (uint *)(*(long *)(param_1 + 8) + 0xa34);
  *puVar1 = *puVar1 | *param_2;
  return 0;
}



/* ===== sub_00a37690 | RVA 0xa37690 | file +0x30 | ev_109a0fea091fa900fb7d33d9edee893146559860203b5f098bf4c62eafdd45cf =====
 * Body: [{"start":"0xa37690","end":"0xa376f2"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_00a37690(long param_1)

{
  code *UNRECOVERED_JUMPTABLE_00;
  
  UNRECOVERED_JUMPTABLE_00 =
       *(code **)(*(long *)((ulong)*(byte *)(*(long *)(param_1 + 0x20) + 0x9d) * 8 + 0x1ac3910) +
                 0x40);
  if (UNRECOVERED_JUMPTABLE_00 == (code *)0x0) {
    return;
  }
  if ((-(long)UNRECOVERED_JUMPTABLE_00 + 0x2652d0U >> 3 | -(long)UNRECOVERED_JUMPTABLE_00 << 0x3d) <
      0x8bd) {
                    /* WARNING: Could not emulate address calculation at 0x00a376a2 */
                    /* WARNING: Treating indirect jump as call */
    (*UNRECOVERED_JUMPTABLE_00)();
    return;
  }
  func_0x0044f8c0(0x25686b0,UNRECOVERED_JUMPTABLE_00);
                    /* WARNING: Could not emulate address calculation at 0x00a376a2 */
                    /* WARNING: Treating indirect jump as call */
  (*UNRECOVERED_JUMPTABLE_00)(param_1);
  return;
}



/* ===== sub_00a37700 | RVA 0xa37700 | file +0xa0 | ev_e3386cdfca1f4e9520a0d351fb3eaec0a17fbe0af6a9695db7e74e6bb55b05cd =====
 * Body: [{"start":"0xa37700","end":"0xa37e4b"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_00a37700(long param_1)

{
  long lVar1;
  long lVar2;
  long lVar3;
  code *pcVar4;
  int iVar5;
  int iVar6;
  undefined8 uVar7;
  long lVar8;
  long *in_GS_OFFSET;
  undefined8 local_158;
  int local_14c;
  undefined8 local_148;
  long local_140;
  int local_138;
  undefined8 local_130;
  long local_128;
  undefined8 local_120;
  long local_118;
  undefined4 local_110;
  undefined8 local_108;
  long local_100;
  long local_c0;
  long local_38;
  
  local_38 = _DAT_0391c310;
  lVar1 = *in_GS_OFFSET;
  iVar5 = func_0x005e0ca0(*(undefined8 *)(param_1 + 0xa8),0x2568bb0);
  iVar6 = 0x16;
  if (iVar5 != 0) goto LAB_00a37aa2;
  if (_DAT_03bef390 == 0) {
    _DAT_03bef390 = func_0x0043b0e0(0x132caf8,0x110,0,0,0,0,7,0);
    _DAT_03bef398 = func_0x0043b0e0(0x13aaf92,0xa8,0,0,0,0,7,0);
    _DAT_03bef3a0 = func_0x0043b0e0(0x12afebf,0x2c8,0,0,0,0,7,0);
    _DAT_03bef3a8 = func_0x0043b0e0(0x1395320,0x310,0,0,0,0,7,0);
    if ((*(byte *)(param_1 + 0x9a) & 1) == 0) goto LAB_00a37767;
LAB_00a37824:
    lVar8 = *(long *)(param_1 + 0x298);
    lVar2 = *(long *)(lVar8 + 0x30);
    if (*(char *)(lVar2 + 0x1a) == '\0') {
      iVar6 = func_0x005e1250(*(undefined8 *)(param_1 + 0xa8),0x12812c1,0,0);
      if (iVar6 != 0) {
        iVar5 = -1;
        if ((*(uint *)(*(long *)(param_1 + 0x40) + 0x28) >> 0x17 & 2) != 0) {
          iVar5 = func_0x00561cf0();
        }
        pcVar4 = *(code **)(*(long *)(param_1 + 0x38) + 0x30);
        if (0x72 < (-(long)pcVar4 + 0x2690e0U >> 3 | -(long)pcVar4 << 0x3d)) {
          func_0x0044f8c0(0x2568c80,pcVar4);
        }
        iVar6 = (*pcVar4)(param_1,1);
        if (iVar5 != -1) {
          func_0x00561de0(iVar5);
        }
        if (iVar6 == 0) {
          iVar6 = func_0x0054a460(param_1,0,(*(uint *)(param_1 + 0x98) >> 0x13 & 1) * 2 + 4,lVar1);
          if (iVar6 == 0) {
            func_0x00c4bb20(0x34fb368,0,0,0);
            iVar6 = func_0x007fd900(*(undefined8 *)(lVar8 + 0x10),0,0xffffffff,0);
            func_0x00c4c4b0(0x34fb368,0,0);
            if (iVar6 == 0) {
              *(undefined1 *)(lVar2 + 0x1a) = 1;
              func_0x004c6a00(param_1 + 0x18,0,0,0);
              func_0x0025d410(0x13a015c);
              *(byte *)(param_1 + 0x98) = *(byte *)(param_1 + 0x98) | 1;
              func_0x004c6fa0(param_1 + 0x18,0,0,0);
              goto LAB_00a379f1;
            }
            uVar7 = 0x204;
          }
          else {
            uVar7 = 0x1fb;
          }
        }
        else {
          uVar7 = 0x1ef;
        }
        goto LAB_00a37a9b;
      }
      if (*(char *)(lVar2 + 0x1a) == '\x01') goto LAB_00a37845;
      goto LAB_00a379f1;
    }
    if (*(char *)(lVar2 + 0x1a) != '\x01') goto LAB_00a379f1;
LAB_00a37845:
    iVar6 = 0;
    iVar5 = func_0x005e1250(*(undefined8 *)(param_1 + 0xa8),0x12812c1,0,0);
    if (iVar5 != 0) goto LAB_00a379f1;
    lVar3 = *(long *)(lVar8 + 0x20);
    func_0x006afb50(lVar3,0x80400,0x138b1db,0x21b);
    local_108 = *(undefined8 *)(lVar1 + 0x140);
    local_120 = 0x1adaa78;
    local_110 = 0x180;
    local_118 = lVar3;
    local_100 = lVar1;
    iVar5 = func_0x0058be00(*(undefined8 *)(lVar3 + 8),&local_120);
    if (iVar5 != 0) {
      iVar6 = func_0x00adfa30(lVar1,0x150);
    }
    local_120 = 0x1adcdc8;
    local_110 = 0;
    local_118 = lVar3;
    func_0x0058ea90(*(undefined8 *)(lVar3 + 8),&local_120);
    if (iVar6 == 0) {
      if (*(char *)(lVar2 + 0x19) == '\x01') {
        iVar6 = 1;
        if ((*(byte *)(param_1 + 0x9a) & 8) == 0) goto LAB_00a37aa2;
        func_0x0025d410(0x12d9d66,0x1347069);
      }
      func_0x00c4bb20(0x34fb368,0,0,0);
      iVar6 = func_0x007fd900(*(undefined8 *)(lVar8 + 0x10),0,1,0);
      local_14c = iVar6;
      func_0x00c4c4b0(0x34fb368,0,0);
      if (iVar6 == 0) {
        *(undefined1 *)(lVar2 + 0x1a) = 0;
        func_0x004c6a00(param_1 + 0x18,0,0,0);
        *(byte *)(param_1 + 0x98) = *(byte *)(param_1 + 0x98) & 0xfe;
        func_0x004c6fa0(param_1 + 0x18,0,0,0);
        *(undefined1 *)(lVar2 + 0x19) = 0;
        goto LAB_00a379f1;
      }
      uVar7 = 0x23c;
    }
    else {
      uVar7 = 0x226;
    }
  }
  else {
    if ((*(byte *)(param_1 + 0x9a) & 1) != 0) goto LAB_00a37824;
LAB_00a37767:
    lVar8 = 0;
LAB_00a379f1:
    iVar6 = func_0x005defd0(*(undefined8 *)(param_1 + 0xa8),0x12b2da1,&local_158,0);
    if (iVar6 == 0) {
      func_0x005fa6e0(&local_120,0,0x44,1,local_158,0xffffff9c,0,0,lVar1);
      local_14c = func_0x005f8c20(&local_120);
      if (local_14c == 0) {
        func_0x005fa780(&local_120,0xffffffdf);
        iVar6 = func_0x0054ca00(local_c0,&local_14c);
        if (iVar6 == 0) {
          func_0x0054a440(local_c0);
          uVar7 = 0x260;
        }
        else {
          local_130 = *(undefined8 *)(lVar1 + 0x140);
          local_148 = 0x1adaa78;
          local_140 = local_c0;
          local_138 = ((*(ulong *)(param_1 + 0x98) & 1) == 0 | 2) << 7;
          local_128 = lVar1;
          local_14c = func_0x0058be00(*(undefined8 *)(local_c0 + 8),&local_148);
          if ((local_14c == 0) || (local_14c = func_0x00adfa30(lVar1,0x150), local_14c == 0)) {
            if ((*(byte *)(param_1 + 0x9a) & 1) == 0) {
              local_14c = sub_00a397b0(local_c0,param_1);
              if (local_14c == 0) {
LAB_00a37d32:
                func_0x005e1420(param_1,local_158);
                iVar6 = 0;
                goto LAB_00a37aa2;
              }
              func_0x0054a120(local_c0);
              uVar7 = 0x288;
            }
            else {
              if (*(long *)(local_c0 + 0x30) != *(long *)(*(long *)(lVar8 + 0x20) + 0x30)) {
                local_14c = 0x16;
              }
              func_0x0054a440(local_c0);
              if (local_14c == 0) goto LAB_00a37d32;
              uVar7 = 0x281;
            }
          }
          else {
            func_0x0054a440(local_c0);
            uVar7 = 0x273;
          }
        }
        func_0x0025d410(0x128a216,0x13570a7,uVar7,local_14c,local_14c);
        iVar6 = local_14c;
        goto LAB_00a37aa2;
      }
      uVar7 = 599;
      iVar6 = local_14c;
    }
    else {
      uVar7 = 0x24e;
      iVar6 = 0x16;
    }
  }
LAB_00a37a9b:
  func_0x0025d410(0x128a216,0x13570a7,uVar7,iVar6,iVar6);
LAB_00a37aa2:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar4 = (code *)invalidInstructionException();
    (*pcVar4)();
  }
  return iVar6;
}



/* ===== sub_00a37e50 | RVA 0xa37e50 | file +0x7f0 | ev_245010c3b7e8dc41deb19992e221848adf6dcb5a8f44177f62895247c9fb65e8 =====
 * Body: [{"start":"0xa37e50","end":"0xa37ef3"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_00a37e50(undefined8 param_1,long param_2,undefined8 param_3)

{
  code *pcVar1;
  undefined8 uVar2;
  undefined8 *in_GS_OFFSET;
  undefined1 local_160 [160];
  undefined1 local_c0 [8];
  undefined1 local_b8 [136];
  long local_30;
  
  local_30 = _DAT_0391c310;
  if (param_2 == 0) {
    uVar2 = 0x16;
  }
  else {
    func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
    uVar2 = func_0x00259280(param_2,local_c0,0x90);
    if ((int)uVar2 == 0) {
      func_0x005e1620(local_b8,local_160);
      uVar2 = func_0x005e1550(param_1,param_3);
    }
  }
  if (_DAT_0391c310 == local_30) {
    return uVar2;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* ===== sub_00a37f00 | RVA 0xa37f00 | file +0x8a0 | ev_4e46d9ddcda3be49da0fb7dc2b4a6adaff550f8231c345f1f577de056ec32a92 =====
 * Body: [{"start":"0xa37f00","end":"0xa38b25"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_00a37f00(long param_1,uint param_2)

{
  byte *pbVar1;
  uint *puVar2;
  long lVar3;
  code *pcVar4;
  undefined8 uVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  ulong uVar9;
  undefined8 uVar10;
  long lVar11;
  long lVar12;
  undefined8 *in_GS_OFFSET;
  bool bVar13;
  long local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  lVar3 = *(long *)(param_1 + 0x298);
  uVar9 = (ulong)*(uint *)(*(long *)(lVar3 + 0x30) + 0x20);
  if (-1 < *(int *)(lVar3 + 0x410)) {
    iVar6 = -1;
    if ((*(uint *)(*(long *)(param_1 + 0x40) + 0x28) >> 0x17 & 2) != 0) {
      iVar6 = func_0x00561cf0();
    }
    pcVar4 = *(code **)(*(long *)(param_1 + 0x38) + 0x30);
    if (0x72 < (-(long)pcVar4 + 0x2690e0U >> 3 | -(long)pcVar4 << 0x3d)) {
      func_0x0044f8c0(0x2568e10,pcVar4);
    }
    iVar7 = (*pcVar4)(param_1,1);
    if (iVar6 != -1) {
      func_0x00561de0(iVar6);
    }
    if (iVar7 != 0) {
      func_0x0025d410(0x128a216,0x1395395,0xff1,iVar7,iVar7);
      iVar6 = 0x13;
      if (iVar7 != 6) {
        iVar6 = iVar7;
      }
      goto LAB_00a38a50;
    }
  }
  uVar10 = 3;
  if (((param_2 & 0x80000) == 0) && (uVar10 = 1, *(long *)(lVar3 + 0x210) != 0)) {
    iVar6 = func_0x0054a110();
    uVar10 = 1;
    if (iVar6 < 2) goto LAB_00a38052;
    uVar10 = 0x1001;
    iVar6 = 0x10;
LAB_00a38219:
    func_0x0025d410(0x128a216,0x1395395,uVar10,iVar6,iVar6);
    goto LAB_00a38a50;
  }
LAB_00a38052:
  uVar5 = *in_GS_OFFSET;
  iVar7 = func_0x0054a460(param_1,0,uVar10,uVar5);
  if (iVar7 != 0) {
    func_0x0025d410(0x128a216,0x1395395,0x100e,iVar7,iVar7);
LAB_00a38090:
    iVar6 = 0x13;
    if (iVar7 != 6) {
      iVar6 = iVar7;
    }
    goto LAB_00a38a50;
  }
  if (-1 < *(int *)(lVar3 + 0x410)) {
    if (*(long *)(lVar3 + 0x868) != 0) {
      lVar11 = *(long *)(*(long *)(lVar3 + 0xd8) + 0x10);
      pcVar4 = *(code **)(*(long *)(lVar11 + 0x18) + 0x8c8);
      if (5 < (-(long)pcVar4 + 0x25d488U >> 3 | -(long)pcVar4 << 0x3d)) {
        func_0x0044f8c0(0x2568e30,pcVar4);
      }
      iVar7 = (*pcVar4)(lVar11,0,uVar9,0,&local_40);
      if (iVar7 != 0) {
        func_0x0025d410(0x128a216,0x1395395,0x1022,iVar7,iVar7);
        iVar6 = 0x13;
        if (iVar7 != 6) {
          iVar6 = iVar7;
        }
        func_0x00870990(*(undefined8 *)(lVar3 + 0x868),0,0x100);
        func_0x00c08df0(*(undefined8 *)(lVar3 + 0x868),0x2568820);
        *(undefined8 *)(lVar3 + 0x868) = 0;
        goto LAB_00a38a50;
      }
      iVar6 = func_0x00b5e730(*(long *)(local_40 + 0x18) + -0x1420 + uVar9,
                              *(undefined8 *)(lVar3 + 0x868));
      func_0x00870990(*(undefined8 *)(lVar3 + 0x868),0,0x100);
      func_0x00c08df0(*(undefined8 *)(lVar3 + 0x868),0x2568820);
      *(undefined8 *)(lVar3 + 0x868) = 0;
      if (iVar6 == 0) {
        pcVar4 = *(code **)(*(long *)(lVar11 + 0x18) + 0x8d8);
        if (0x16 < (-(long)pcVar4 + 0x269f00U >> 3 | -(long)pcVar4 << 0x3d)) {
          func_0x0044f8c0(0x2568e50,pcVar4);
        }
        iVar7 = (*pcVar4)(lVar11,local_40,0);
        if (iVar7 != 0) {
          func_0x0025d410(0x128a216,0x1395395,0x103d,iVar7,iVar7);
          goto LAB_00a38090;
        }
        func_0x009349e0(lVar11);
      }
      else {
        func_0x00a9d690(local_40);
      }
    }
    iVar7 = func_0x009482c0(lVar3);
    if (iVar7 != 0) {
      uVar10 = 0x1054;
      iVar6 = 0x13;
      if (iVar7 != 6) {
        iVar6 = iVar7;
      }
      goto LAB_00a38219;
    }
    if ((*(byte *)(lVar3 + 0x413) & 0x10) != 0) {
      func_0x00945760(lVar3);
      func_0x009349e0(*(undefined8 *)(*(long *)(lVar3 + 0x348) + 0x10));
    }
    iVar7 = func_0x00a9db90(*(undefined8 *)(lVar3 + 0x20),0,uVar9,0,0,0,0,0,&local_40);
    if (iVar7 != 0) {
      func_0x0025d410(0x128a216,0x1395395,0x1060,iVar7,iVar7);
      iVar6 = 0x13;
      if (iVar7 != 6) {
        iVar6 = iVar7;
      }
      func_0x00a9d690(local_40);
      goto LAB_00a38a50;
    }
    pbVar1 = (byte *)(*(long *)(lVar3 + 0x30) + 0x18);
    *pbVar1 = *pbVar1 & 0x80;
    if ((*(byte *)(lVar3 + 0x410) & 1) != 0) {
      func_0x009382b0(lVar3);
    }
    func_0x00259be0(*(undefined8 *)(lVar3 + 0x30),*(undefined8 *)(local_40 + 0x18),0x5a0);
    if (*(int *)(lVar3 + 0x450) == 3) {
      func_0x00b5e9e0(*(long *)(local_40 + 0x18) + -0x70 + uVar9,*(long *)(lVar3 + 0x30) + 0x380);
      iVar6 = func_0x002889f0(*(undefined8 *)(local_40 + 0x18),0x5a0);
      if (iVar6 != 0) {
        func_0x0025d410(0x128a216,0x1395395,0x107f,iVar6,iVar6);
      }
    }
    func_0x00a3e9f0(local_40);
  }
  if ((*(int *)(lVar3 + 0x450) == 1) && (*(int *)(lVar3 + 0x784) != -1)) {
    func_0x004c6a00(0x35ab448,0,0,0);
    func_0x00a1f360((long)*(int *)(lVar3 + 0x784) * 0xc0 + 0x35ab480);
    func_0x004c6fa0(0x35ab448,0,0,0);
    *(undefined4 *)(lVar3 + 0x784) = 0xffffffff;
  }
  uVar8 = *(uint *)(lVar3 + 0x410);
  if ((uVar8 & 1) != 0) {
    iVar6 = func_0x00b93850(lVar3);
    if (iVar6 != 0) {
      func_0x0025d410(0x12e9181,0x1395395,0x109e,iVar6);
      goto LAB_00a38a50;
    }
    uVar8 = *(uint *)(lVar3 + 0x410);
  }
  iVar6 = *(int *)(lVar3 + 0x450);
  if ((uVar8 & 1) == 0) {
    if (iVar6 == 1) {
      func_0x0094a9d0(lVar3,lVar3 + 0x5f8);
      if (*(long *)(lVar3 + 0x6f8) != 0) {
        func_0x004c6a00(*(long *)(lVar3 + 0x6f8) + 0xb0,0,0);
        lVar11 = *(long *)(lVar3 + 0x6f8);
        if ((*(byte *)(lVar11 + 0x1c4) & 0x80) == 0) {
          *(undefined8 *)(*(long *)(*(long *)(lVar11 + 0x10) + 0x18) + 0x710) = 0;
          lVar11 = *(long *)(lVar3 + 0x6f8);
        }
        func_0x004c6fa0(lVar11 + 0xb0,0,0);
        uVar10 = *(undefined8 *)(lVar3 + 0x6f8);
        *(undefined8 *)(lVar3 + 0x6f8) = 0;
        func_0x0054a120(uVar10);
      }
      func_0x004c7e50(*(long *)(lVar3 + 0x6b0) + 0x48);
      func_0x004c7e50(*(long *)(lVar3 + 0x6b0) + 0xf0);
      func_0x004c7e50(*(long *)(lVar3 + 0x6b0) + 0x198);
      func_0x004c7e50(*(long *)(lVar3 + 0x6b0) + 0x240);
      func_0x00c08df0(*(undefined8 *)(lVar3 + 0x6b0),0x2568820);
      func_0x004c7e50(lVar3 + 0x618);
      func_0x004c7e50(lVar3 + 0x660);
      func_0x004c7e50(lVar3 + 0x6d0);
      func_0x004c7e50(lVar3 + 0x6f0);
      func_0x00c08df0(*(undefined8 *)(lVar3 + 0x720),0x2568820);
      lVar11 = 0x770;
      goto LAB_00a386de;
    }
  }
  else {
    if (iVar6 == 1) {
      func_0x0094a9d0(lVar3,lVar3 + 0x5f8);
      func_0x00c08df0(*(undefined8 *)(lVar3 + 0x5b0),0x2568820);
      lVar12 = 0x14;
      lVar11 = 0x48;
      if (*(int *)(param_1 + 0x330) == 1) {
        lVar12 = 8;
      }
      do {
        func_0x004c7e50(*(long *)(lVar3 + 0x6b0) + lVar11);
        lVar11 = lVar11 + 0xa8;
        lVar12 = lVar12 + -1;
      } while (lVar12 != 0);
      func_0x00c08df0(*(undefined8 *)(lVar3 + 0x6b0),0x2568820);
      func_0x004c7e50(lVar3 + 0x558);
      func_0x004c7e50(lVar3 + 0x5f0);
      func_0x004c7e50(lVar3 + 0x5d0);
      func_0x004c7e50(lVar3 + 0x618);
      func_0x004c7e50(lVar3 + 0x660);
      func_0x004c7e50(lVar3 + 0x6d0);
      lVar11 = 0x6f0;
    }
    else {
      if (iVar6 != 3) goto LAB_00a386e6;
      func_0x0094a910(lVar3,lVar3 + 0x4a8);
      func_0x0094a910(lVar3,lVar3 + 0x4f0);
      func_0x00c08df0(*(undefined8 *)(lVar3 + 0x5b0),0x2568820);
      func_0x004c7e50(lVar3 + 0x4c8);
      func_0x004c7e50(lVar3 + 0x510);
      func_0x004c7e50(lVar3 + 0x558);
      func_0x004c7e50(lVar3 + 0x5f0);
      lVar11 = 0x5d0;
    }
LAB_00a386de:
    func_0x004c7e50(lVar11 + lVar3);
  }
LAB_00a386e6:
  if (*(long *)(lVar3 + 0x1a8) != 0) {
    func_0x00bf1760(lVar3 + 0x1e0);
    func_0x00c08df0(*(undefined8 *)(lVar3 + 0x1c8),0x25686d0);
    puVar2 = (uint *)(*(long *)(lVar3 + 0x1a8) + 0x1c8);
    *puVar2 = *puVar2 & 0xffffff7f;
    func_0x0054a120(*(undefined8 *)(lVar3 + 0x1a8));
    *(undefined8 *)(lVar3 + 0x1a8) = 0;
  }
  if (*(long *)(lVar3 + 0x140) != 0) {
    func_0x00bf1760(lVar3 + 0x178);
    func_0x00c08df0(*(undefined8 *)(lVar3 + 0x160),0x25686d0);
    puVar2 = (uint *)(*(long *)(lVar3 + 0x140) + 0x1c8);
    *puVar2 = *puVar2 & 0xffffff7f;
    func_0x0054a120(*(undefined8 *)(lVar3 + 0x140));
    *(undefined8 *)(lVar3 + 0x140) = 0;
  }
  if (*(long *)(lVar3 + 0x210) != 0) {
    func_0x00bf1760(lVar3 + 0x248);
    puVar2 = (uint *)(*(long *)(lVar3 + 0x210) + 0x1c8);
    *puVar2 = *puVar2 & 0xffffff7f;
    func_0x0054a120(*(undefined8 *)(lVar3 + 0x210));
    *(undefined8 *)(lVar3 + 0x210) = 0;
  }
  if (*(long *)(lVar3 + 0x348) != 0) {
    func_0x00bf1760(lVar3 + 0x380);
    puVar2 = (uint *)(*(long *)(lVar3 + 0x348) + 0x1c8);
    *puVar2 = *puVar2 & 0xffffff7f;
    func_0x00c08df0(*(undefined8 *)(lVar3 + 0x368),0x25686d0);
    func_0x0054a120(*(undefined8 *)(lVar3 + 0x348));
    *(undefined8 *)(lVar3 + 0x348) = 0;
  }
  if (*(long *)(lVar3 + 0x278) != 0) {
    if (**(long **)(lVar3 + 0x30) == 2) {
      lVar11 = *(long *)(lVar3 + 0x298);
      LOCK();
      bVar13 = lVar11 == *(long *)(lVar3 + 0x298);
      if (bVar13) {
        *(long *)(lVar3 + 0x298) = 0;
      }
      UNLOCK();
      if (!bVar13) {
        func_0x007f1950();
        func_0x007f1810(0xa38aec);
        uVar10 = 0x14;
        goto LAB_00a38b09;
      }
      func_0x00568950(lVar11);
      func_0x00c08df0(lVar11,0x2568890);
    }
    func_0x00bf1760(lVar3 + 0x2b0);
    puVar2 = (uint *)(*(long *)(lVar3 + 0x278) + 0x1c8);
    *puVar2 = *puVar2 & 0xffffff7f;
    func_0x0054a120(*(undefined8 *)(lVar3 + 0x278));
    *(undefined8 *)(lVar3 + 0x278) = 0;
  }
  if (*(long *)(lVar3 + 0x2e0) != 0) {
    func_0x00bf1760(lVar3 + 0x318);
    puVar2 = (uint *)(*(long *)(lVar3 + 0x2e0) + 0x1c8);
    *puVar2 = *puVar2 & 0xffffff7f;
    func_0x0054a120(*(undefined8 *)(lVar3 + 0x2e0));
    *(undefined8 *)(lVar3 + 0x2e0) = 0;
  }
  puVar2 = (uint *)(*(long *)(lVar3 + 0xd0) + 0x1c8);
  *puVar2 = *puVar2 & 0xffffff7f;
  func_0x0054a120(*(undefined8 *)(lVar3 + 0xd0));
  puVar2 = (uint *)(*(long *)(lVar3 + 0xd8) + 0x1c8);
  *puVar2 = *puVar2 & 0xffffff7f;
  func_0x0054a120(*(undefined8 *)(lVar3 + 0xd8));
  iVar6 = func_0x0054a460(param_1,0,2,uVar5);
  if (iVar6 != 0) {
    func_0x0025d410(0x13a5ae3,0x1395395,0x1151,iVar6);
  }
  func_0x0036b470(lVar3);
  func_0x006afb50(*(undefined8 *)(lVar3 + 0x20),0x80400,0x138b1db,0x1156);
  func_0x00c4bb20(0x34fb368,0,0,0);
  func_0x00741a80(*(undefined8 *)(lVar3 + 0x10));
  func_0x00c4c4b0(0x34fb368,0,0);
  func_0x0054a440(*(undefined8 *)(lVar3 + 0x20));
  func_0x006dea70(*(undefined8 *)(lVar3 + 8));
  lVar11 = *(long *)(lVar3 + 0x30);
  LOCK();
  bVar13 = lVar11 == *(long *)(lVar3 + 0x30);
  if (bVar13) {
    *(long *)(lVar3 + 0x30) = 0;
  }
  UNLOCK();
  if (bVar13) {
    func_0x00c08df0(lVar11,0x25686d0);
    func_0x00bf1760(lVar3 + 0x68);
    func_0x004c7e50(lVar3 + 0x430);
    LOCK();
    bVar13 = lVar3 == *(long *)(param_1 + 0x298);
    if (bVar13) {
      *(long *)(param_1 + 0x298) = 0;
    }
    UNLOCK();
    if (bVar13) {
      func_0x00c08df0(lVar3,0x25686d0);
      func_0x004c6a00(param_1 + 0x18,0,0,0);
      *(byte *)(param_1 + 0x99) = *(byte *)(param_1 + 0x99) & 0xef;
      func_0x004c6fa0(param_1 + 0x18,0,0,0);
      uVar10 = func_0x007148b0(param_1);
      func_0x0025d410(0x13aafc2,param_2,uVar10,0);
      iVar6 = 0;
LAB_00a38a50:
      if (_DAT_0391c310 != local_38) {
        func_0x006fd6b0();
                    /* WARNING: Does not return */
        pcVar4 = (code *)invalidInstructionException();
        (*pcVar4)();
      }
      return iVar6;
    }
    func_0x007f1950();
    func_0x007f1810(0xa38acd);
    uVar10 = 0x1c;
  }
  else {
    func_0x007f1950();
    func_0x007f1810(0xa38aae);
    uVar10 = 0x18;
  }
LAB_00a38b09:
  func_0x00c9aa10(uVar10,0x1379b13);
                    /* WARNING: Does not return */
  pcVar4 = (code *)invalidInstructionException();
  (*pcVar4)();
}



/* ===== sub_00a38b30 | RVA 0xa38b30 | file +0x14d0 | ev_ee8dd59906347535624cd7c4fbf5f9bcc141620eb430c1253ea88c73392156fa =====
 * Body: [{"start":"0xa38b30","end":"0xa38c88"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_00a38b30(long param_1,undefined4 param_2,undefined8 *param_3)

{
  long lVar1;
  code *pcVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined8 local_40;
  long local_38;
  
  iVar4 = -1;
  local_38 = _DAT_0391c310;
  lVar1 = *(long *)(param_1 + 0x298);
  uVar3 = *(uint *)(*(long *)(param_1 + 0x40) + 0x28) >> 0x17 & 2;
  if (uVar3 != 0) {
    iVar4 = func_0x00561cf0(uVar3);
  }
  pcVar2 = *(code **)(*(long *)(param_1 + 0x38) + 0x38);
  if (0xf < (-(long)pcVar2 + 0x26bad8U >> 3 | -(long)pcVar2 << 0x3d)) {
    func_0x0044f8c0(0x2568e90,pcVar2);
  }
  iVar5 = (*pcVar2)(param_1,*(undefined4 *)(lVar1 + 0x218),param_2,&local_40);
  if (iVar4 != -1) {
    func_0x00561de0(iVar4);
  }
  if (iVar5 == 0) {
    if (*(long *)(lVar1 + 0x448) == _DAT_03bef3a0) {
      iVar5 = func_0x0036b040(lVar1,local_40);
      if (iVar5 != 0) {
        func_0x0025d410(0x128a216,0x135ccc5,0x119b,iVar5,iVar5);
        func_0x0054a440(local_40);
        goto LAB_00a38c41;
      }
    }
    iVar5 = 0;
    *param_3 = local_40;
  }
  else {
    func_0x0025d410(0x128a216,0x135ccc5,0x1194,iVar5,iVar5);
  }
LAB_00a38c41:
  if (_DAT_0391c310 == local_38) {
    return iVar5;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar2 = (code *)invalidInstructionException();
  (*pcVar2)();
}



/* ===== sub_00a38c90 | RVA 0xa38c90 | file +0x1630 | ev_67c434fbc0248958cfe97ecb58020c1ea1db34c7b56532d91c345c456e4a66a2 =====
 * Body: [{"start":"0xa38c90","end":"0xa38d2e"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_00a38c90(long param_1,undefined4 *param_2)

{
  long lVar1;
  undefined4 *puVar2;
  code *pcVar3;
  int iVar4;
  undefined8 local_30;
  long local_28;
  
  local_28 = _DAT_0391c310;
  lVar1 = *(long *)(param_1 + 0x298);
  puVar2 = *(undefined4 **)(lVar1 + 0x30);
  *param_2 = *puVar2;
  *(ulong *)(param_2 + 4) = (ulong)(uint)puVar2[8];
  *(ulong *)(param_2 + 6) = (ulong)(uint)puVar2[8];
  *(undefined8 *)(param_2 + 8) = *(undefined8 *)(puVar2 + 0xe);
  iVar4 = func_0x0092a2b0(lVar1,&local_30);
  if (iVar4 == 0) {
    *(undefined8 *)(param_2 + 10) = local_30;
    *(undefined8 *)(param_2 + 0xc) = local_30;
  }
  else {
    func_0x0025d410(0x13b0bb2,0x13470a9,0x11bf,iVar4,iVar4);
  }
  if (_DAT_0391c310 == local_28) {
    return iVar4;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar3 = (code *)invalidInstructionException();
  (*pcVar3)();
}



/* ===== sub_00a38d30 | RVA 0xa38d30 | file +0x16d0 | ev_0fef14b1af01ed5861593173c311f0511c99bdab523810a409a84667f3dfd467 =====
 * Body: [{"start":"0xa38d30","end":"0xa39199"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_00a38d30(long param_1,int param_2)

{
  undefined4 uVar1;
  long lVar2;
  undefined8 uVar3;
  code *pcVar4;
  int iVar5;
  int iVar6;
  long lVar7;
  undefined8 *in_GS_OFFSET;
  int local_70;
  long *local_68;
  undefined1 local_60 [8];
  undefined8 local_58;
  long local_50;
  int local_48;
  undefined8 local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  lVar2 = *(long *)(param_1 + 0x298);
  lVar7 = lVar2 + 0x68;
  uVar1 = *(undefined4 *)(*(long *)(lVar2 + 0x30) + 0x20);
  uVar3 = *in_GS_OFFSET;
  func_0x00bf1770(lVar7,0x80000,0,0,0,0,0,0);
  if (*(int *)(lVar2 + 0x438) == 0) {
    func_0x00bf1770(lVar7,0x100000,0,0,0,0,0,0);
  }
  else {
    if (*(int *)(lVar2 + 0x410) < 0) {
      func_0x007f1950();
      func_0x007f1810(0xa39157);
      func_0x00c9aa10(0x20,0x135cca1);
                    /* WARNING: Does not return */
      pcVar4 = (code *)invalidInstructionException();
      (*pcVar4)();
    }
    local_70 = func_0x00a9db90(*(undefined8 *)(lVar2 + 0x20),0,uVar1,0,0,0,0,0,&local_68);
    if (local_70 != 0) {
      func_0x00a9d690(local_68);
      func_0x00bf1770(lVar7,0x100000,0,0,0,0,0,0);
      func_0x0025d410(0x128a216,0x1312acc,0x11e0,local_70,local_70);
      goto LAB_00a39134;
    }
    func_0x00259be0(*(undefined8 *)(lVar2 + 0x30),local_68[3],0x5a0);
    *(undefined4 *)(lVar2 + 0x438) = 0;
    func_0x00bf1770(lVar7,0x100000,0,0,0,0,0,0);
    pcVar4 = *(code **)(*(long *)(*local_68 + 0x20) + 8);
    if (0x6ff < (-(long)pcVar4 + 0x260ce8U >> 3 | -(long)pcVar4 << 0x3d)) {
      func_0x0044f8c0(0x2568e70,pcVar4);
    }
    (*pcVar4)(local_68);
  }
  iVar6 = 1;
  if (param_2 != 4) {
    iVar6 = param_2;
  }
  lVar7 = func_0x0054aa30(local_60,param_1);
  if (lVar7 == 0) {
    local_70 = 0;
  }
  else {
    local_70 = 0;
    do {
      if (((*(int *)(lVar7 + 0x1d4) == 0) || ((*(byte *)(lVar7 + 0x1c4) & 0x80) != 0)) ||
         (((*(byte *)(*(long *)(lVar7 + 0x10) + 0x20) & 0xd) == 0 &&
          ((iVar6 == 3 || (*(int *)(lVar7 + 0x158) == 0)))))) {
        func_0x004c6fa0(lVar7 + 0xb0,0,0,0);
LAB_00a3902a:
        lVar7 = func_0x0054afe0(local_60);
      }
      else {
        iVar5 = func_0x00549d70(lVar7,(uint)(iVar6 != 1) << 9 | 0x80900,uVar3);
        if ((iVar5 != 2) && (iVar5 != 0x4d)) {
          if (iVar5 == 0) {
            local_58 = 0x1adbaf8;
            local_50 = lVar7;
            local_48 = iVar6;
            local_40 = uVar3;
            iVar5 = func_0x0058d3a0(*(undefined8 *)(lVar7 + 8),&local_58);
            if (iVar5 != 0) {
              func_0x0025d410(0x128a216,0x1312acc,0x1218,iVar5,iVar5);
              local_70 = iVar5;
            }
            func_0x0054a440(lVar7);
          }
          goto LAB_00a3902a;
        }
        func_0x0025d410(0x128a216,0x1312acc,0x120f,iVar5,iVar5);
        func_0x004c6a00(param_1 + 0x18,0,0);
        func_0x0054abb0(local_60,param_1);
        lVar7 = func_0x0054aa30(local_60);
      }
    } while (lVar7 != 0);
  }
  lVar2 = *(long *)(lVar2 + 0x20);
  lVar7 = lVar2 + 0xe8;
  func_0x007d46a0(lVar7,0,0);
  if ((iVar6 == 3) || ((*(long *)(lVar2 + 0x160) < 1 && (*(int *)(lVar2 + 0x158) < 1)))) {
    func_0x007d4eb0(lVar7,0,0);
  }
  else {
    func_0x007d4eb0(lVar7,0,0);
    func_0x006afb50(lVar2,0x80400,0x138b1db,0x122b);
    local_58 = 0x1adbaf8;
    local_50 = lVar2;
    local_48 = iVar6;
    local_40 = uVar3;
    iVar6 = func_0x0058d3a0(*(undefined8 *)(lVar2 + 8),&local_58);
    if (iVar6 != 0) {
      func_0x0025d410(0x128a216,0x1312acc,0x122e,iVar6,iVar6);
      local_70 = iVar6;
    }
    local_58 = 0x1adcdc8;
    local_48 = 0;
    local_50 = lVar2;
    func_0x0058ea90(*(undefined8 *)(lVar2 + 8),&local_58);
  }
LAB_00a39134:
  if (_DAT_0391c310 == local_38) {
    return local_70;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar4 = (code *)invalidInstructionException();
  (*pcVar4)();
}



/* ===== sub_00a391a0 | RVA 0xa391a0 | file +0x1b40 | ev_9846c8f598f98fd919d5d1f88c70fdc6366775e02868db52676aa8e74302479c =====
 * Body: [{"start":"0xa391a0","end":"0xa39631"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_00a391a0(long param_1,uint param_2,uint param_3,long *param_4)

{
  ushort uVar1;
  long lVar2;
  undefined8 uVar3;
  long *plVar4;
  code *pcVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  long lVar9;
  ushort *puVar10;
  undefined8 *puVar11;
  undefined8 uVar12;
  undefined8 *in_GS_OFFSET;
  long local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  uVar12 = *in_GS_OFFSET;
  iVar6 = func_0x00adfa70();
  if (iVar6 == 0) {
    iVar6 = 0;
    if (*param_4 == 0) {
      lVar2 = *(long *)(param_1 + 0x298);
      uVar8 = param_3 & 0xff00ffff | 0x80000;
      if ((param_3 & 0xff0000) != 0x200000) {
        uVar8 = param_3;
      }
      uVar3 = *(undefined8 *)(lVar2 + 8);
      plVar4 = *(long **)(lVar2 + 0x30);
      lVar9 = func_0x0043b880(_DAT_03bef390,0,0x102);
      iVar6 = func_0x00547f60(0x1311039,param_1,0x1ac4100,&local_40);
      if (iVar6 == 0) {
        func_0x00bf1770(*(undefined8 *)(local_40 + 0xb8),0x80000,0,0,0,0,0,0);
        func_0x00bf1740(*(undefined8 *)(local_40 + 0xb8));
        *(long *)(local_40 + 0x10) = lVar9;
        *(int *)(local_40 + 0x16c) = (int)plVar4[4];
        *(long *)(lVar9 + 0x10) = local_40;
        *(long *)(lVar9 + 0x18) = lVar2;
        *(long **)(lVar9 + 0x40) = plVar4;
        *(undefined8 *)(lVar9 + 0x28) = uVar3;
        *(ulong *)(lVar9 + 0x30) = (ulong)param_2;
        *(undefined8 *)(lVar9 + 0xa0) = 0;
        *(undefined8 *)(local_40 + 0xf0) = 0x2568ce0;
        *(long *)(local_40 + 0x110) = local_40;
        iVar6 = func_0x005483b0(local_40,param_1);
        if (iVar6 == 0) {
          *(uint *)(local_40 + 0x1c8) = *(uint *)(local_40 + 0x1c8) & 0xffffefff;
          iVar6 = 0;
          iVar7 = func_0x00adfca0(local_40,param_2,uVar8,uVar12,param_4,0,0);
          if (iVar7 != 0) {
            func_0x0025d410(0x128a216,0x12c4886,0x1299,iVar7,iVar7);
            iVar6 = iVar7;
            goto LAB_00a393cb;
          }
          if (*param_4 != 0) goto LAB_00a393cb;
          puVar10 = (ushort *)func_0x0043b880(*(undefined8 *)(lVar2 + 0x448),0,2);
          *(ushort **)(lVar9 + 0x88) = puVar10;
          func_0x00bf1690(lVar9 + 200,0,0x12d50db,0,0);
          uVar8 = *(uint *)(lVar2 + 0x410);
          if (-1 < (int)uVar8) {
            func_0x00bf1770(lVar2 + 0x68,0x80000,0,0,0,0,0,0);
            uVar8 = *(uint *)(lVar2 + 0x410);
          }
          if ((uVar8 & 1) == 0) {
            iVar6 = func_0x00365d00(param_2,lVar2,puVar10);
          }
          else {
            iVar6 = func_0x003667f0(param_2,lVar2,puVar10);
          }
          if (-1 < *(int *)(lVar2 + 0x410)) {
            func_0x00bf1770(lVar2 + 0x68,0x100000,0,0,0,0,0,0);
          }
          if (iVar6 == 0) {
            *(undefined8 *)(lVar9 + 0x58) = 0;
            uVar1 = *puVar10;
            *(ushort *)(lVar9 + 0x60) = uVar1;
            *(undefined4 *)(lVar9 + 0x84) = *(undefined4 *)(puVar10 + 2);
            *(undefined8 *)(lVar9 + 0x68) = *(undefined8 *)(puVar10 + 4);
            *(undefined4 *)(lVar9 + 0x7c) = *(undefined4 *)(puVar10 + 0x24);
            *(undefined4 *)(lVar9 + 0x80) = *(undefined4 *)(puVar10 + 0x26);
            *(ushort *)(lVar9 + 0x62) = puVar10[1];
            *(undefined8 *)(lVar9 + 0x70) = *(undefined8 *)(puVar10 + 8);
            *(undefined4 *)(local_40 + 0x1d4) =
                 *(undefined4 *)((ulong)(uVar1 >> 0xc) * 4 + 0x1ad40a0);
            func_0x00bf1730(*(undefined8 *)(local_40 + 0xb8));
            if (*(ulong *)(lVar9 + 0x30) == (ulong)*(uint *)(lVar2 + 0x218)) {
              *(uint *)(local_40 + 0x1c8) = *(uint *)(local_40 + 0x1c8) | 1;
              if ((*plVar4 == 1) && (*(long *)(lVar2 + 0x278) != 0)) {
                puVar11 = (undefined8 *)func_0x00c08b50(0x10,0x2568890,0x102);
                *puVar11 = 1;
                *(undefined1 *)(puVar11 + 1) = 0x2f;
                *(undefined8 **)(lVar9 + 0xb8) = puVar11;
              }
            }
            iVar6 = 0;
            *param_4 = local_40;
            goto LAB_00a393cb;
          }
          func_0x0054b1c0(local_40);
          func_0x0054a440(local_40);
          *param_4 = 0;
          uVar12 = 0x12b3;
        }
        else {
          func_0x0043c0c0(_DAT_03bef390,lVar9,0);
          uVar12 = 0x128f;
          *param_4 = 0;
        }
      }
      else {
        *param_4 = 0;
        func_0x0043c0c0(_DAT_03bef390,lVar9,0);
        uVar12 = 0x1272;
      }
      func_0x0025d410(0x128a216,0x12c4886,uVar12,iVar6,iVar6);
    }
  }
  else {
    func_0x0025d410(0x128a216,0x12c4886,0x124f,iVar6,iVar6);
  }
LAB_00a393cb:
  if (_DAT_0391c310 == local_38) {
    return iVar6;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar5 = (code *)invalidInstructionException();
  (*pcVar5)();
}



/* ===== sub_00a39640 | RVA 0xa39640 | file +0x1fe0 | ev_cea5999014976dd876398958757ed5ba896d856b23cd737e70540b2049632250 =====
 * Body: [{"start":"0xa39640","end":"0xa3976a"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong sub_00a39640(long param_1,long param_2,ulong param_3,long *param_4)

{
  code *pcVar1;
  long lVar2;
  int iVar3;
  ulong uVar4;
  undefined8 *in_GS_OFFSET;
  long local_40;
  long local_38;
  
  iVar3 = -1;
  local_38 = _DAT_0391c310;
  if ((param_1 != 0) && ((*(uint *)(*(long *)(param_1 + 0x40) + 0x28) >> 0x17 & 2) != 0)) {
    param_3 = param_3 & 0xffffffff;
    iVar3 = func_0x00561cf0();
  }
  pcVar1 = *(code **)(*(long *)(param_1 + 0x38) + 0x38);
  if (0xf < (-(long)pcVar1 + 0x26bad8U >> 3 | -(long)pcVar1 << 0x3d)) {
    func_0x0044f8c0(0x2568eb0,pcVar1);
    param_3 = param_3 & 0xffffffff;
  }
  uVar4 = (*pcVar1)(param_1,*(undefined4 *)(param_2 + 4),param_3,&local_40);
  if (iVar3 != -1) {
    uVar4 = uVar4 & 0xffffffff;
    func_0x00561de0(iVar3);
  }
  if ((int)uVar4 == 0) {
    lVar2 = *(long *)(local_40 + 0x10);
    if (*(short *)(lVar2 + 0x60) == 0) {
      func_0x0054a440();
      *param_4 = 0;
      uVar4 = 0x46;
    }
    else {
      *param_4 = local_40;
      func_0x006a82e0(local_40,*(undefined8 *)(lVar2 + 0x68),*in_GS_OFFSET,
                      *(undefined4 *)(param_1 + 0x334),*(undefined4 *)(param_1 + 0x330));
      uVar4 = 0;
    }
  }
  else {
    *param_4 = 0;
  }
  if (_DAT_0391c310 == local_38) {
    return uVar4;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* ===== sub_00a39770 | RVA 0xa39770 | file +0x2110 | ev_996d80374a9492375a2beb1dd2f8ef9e60d2e1368c3bab3311b3caf6eda0d6e2 =====
 * Body: [{"start":"0xa39770","end":"0xa39781"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_00a39770(void)

{
  func_0x00466510();
  func_0x003654c0();
  return 0;
}



/* ===== sub_00a39790 | RVA 0xa39790 | file +0x2130 | ev_a5a6cbc8d9511482e7557997c8fd5433d365ad59b43f52b8cf43edd8f18adb4b =====
 * Body: [{"start":"0xa39790","end":"0xa397a1"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_00a39790(void)

{
  func_0x00365530();
  func_0x00466770();
  return 0;
}



/* ===== sub_00a397b0 | RVA 0xa397b0 | file +0x2150 | ev_1fa52579708b205ea60c09eea415de21cf279bd217af56503474af8c39115399 =====
 * Body: [{"start":"0xa397b0","end":"0xa3ac0d"},{"start":"0xa3acc7","end":"0xa3adf4"},{"start":"0xa3b04e","end":"0xa3b0af"},{"start":"0xa3b522","end":"0xa3b650"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Removing unreachable block (ram,0x00a3a03c) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong sub_00a397b0(long param_1,long param_2)

{
  byte *pbVar1;
  long lVar2;
  long lVar3;
  code *pcVar4;
  undefined8 *puVar5;
  uint uVar6;
  int iVar7;
  undefined4 uVar8;
  long *plVar9;
  long *plVar10;
  long *plVar11;
  undefined8 uVar12;
  undefined8 uVar13;
  undefined8 uVar14;
  long lVar15;
  long lVar16;
  ulong uVar17;
  undefined8 *in_GS_OFFSET;
  bool bVar18;
  long local_168;
  long local_160;
  ulong *local_158;
  ulong local_150;
  long local_148;
  undefined8 local_140;
  long local_138;
  undefined8 local_130;
  undefined8 *local_128;
  long local_120;
  undefined8 local_118;
  undefined8 local_110;
  ulong local_108;
  int local_fc;
  long local_f8;
  undefined8 *local_f0;
  undefined8 *local_e8;
  ulong local_e0 [7];
  ulong local_a8;
  uint uStack_a4;
  undefined8 local_a0;
  undefined8 local_98;
  undefined8 local_90;
  undefined8 local_88;
  long local_80;
  long local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  ulong local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  local_160 = 0;
  local_168 = 0;
  uVar12 = *(undefined8 *)(param_2 + 0x98);
  lVar2 = *(long *)(param_1 + 0x30);
  func_0x006dea20();
  func_0x00c4bb20(0x34fb368,0,0,0);
  uVar6 = func_0x00741920(param_1,&local_168,0x138ed0f,(uint)uVar12 & 1 ^ 1,
                          *(undefined4 *)(param_2 + 0x334),*(undefined4 *)(param_2 + 0x330));
  uVar17 = (ulong)uVar6;
  func_0x00c4c4b0(0x34fb368,0,0);
  local_e0[5] = 0x1adcdc8;
  local_a8 = (ulong)uStack_a4 << 0x20;
  local_e0[6] = param_1;
  func_0x0058ea90(*(undefined8 *)(param_1 + 8),local_e0 + 5);
  if (uVar6 == 0) {
    plVar9 = (long *)func_0x00c08b50(0x998,0x25686d0,0x102);
    if (plVar9 == (long *)0x0) {
      uVar13 = 0x13b574e;
      plVar9 = (long *)0x0;
      uVar17 = 0xc;
      uVar12 = 0xd77;
      goto LAB_00a398b7;
    }
    func_0x00bf1690(plVar9 + 0xd,0,0x1296df3,0,1);
    func_0x004c7dd0(plVar9 + 0x86,0x13afa51,0x13906c2,0);
    *(undefined4 *)((long)plVar9 + 0x43c) = 9;
    local_e0[5] = 0;
    plVar9[0x88] = 0x7fffffffffffffff;
    plVar9[0x16] = -1;
    *(undefined8 *)((long)plVar9 + 0x474) = 0xffffffffffffffff;
    *plVar9 = param_2;
    iVar7 = func_0x005e12d0(*(undefined8 *)(param_2 + 0xa8),0x127f783,0x13440ee,&local_158);
    if (iVar7 == 1) {
      *(int *)(plVar9 + 0x19) = (int)local_158;
    }
    iVar7 = func_0x005e12d0(*(undefined8 *)(param_2 + 0xa8),0x1325738,0x13440ee,&local_158);
    if (iVar7 == 1) {
      *(int *)((long)plVar9 + 0xc4) = (int)local_158;
    }
    iVar7 = func_0x005e12d0(*(undefined8 *)(param_2 + 0xa8),0x126eb5c,0x13440ee);
    if ((iVar7 == 1) && ((int)local_158 != 0)) {
      if ((int)local_158 == 1) {
        *(byte *)((long)plVar9 + 0x414) = *(byte *)((long)plVar9 + 0x414) | 1;
        goto LAB_00a39bf7;
      }
    }
    else {
LAB_00a39bf7:
      iVar7 = func_0x005defd0(*(undefined8 *)(param_2 + 0xa8),0x131d6e7,local_e0 + 5,0);
      if (iVar7 == 0) {
        func_0x0025d410(0x1380400,0x138041d,0xbc2,local_e0[5]);
        iVar7 = func_0x008d1a30(local_e0[5],0x12f2d82,3);
        if (iVar7 == 0) {
          uVar8 = 3;
        }
        else {
          iVar7 = func_0x008d1a30(local_e0[5],0x13860d0,3);
          if (iVar7 == 0) {
            uVar8 = 1;
          }
          else {
            iVar7 = func_0x008d1a30(local_e0[5],0x13a5ae0,3);
            if (iVar7 != 0) {
              func_0x0025d410(0x13b0b58,0x138041d,0xbcb);
              goto LAB_00a39c3a;
            }
            uVar8 = 2;
          }
        }
        *(undefined4 *)(plVar9 + 0x8a) = uVar8;
        local_158 = (ulong *)0x0;
        local_e8 = (undefined8 *)((ulong)local_e8 & 0xffffffff00000000);
        lVar15 = *plVar9;
        iVar7 = func_0x005defd0(*(undefined8 *)(lVar15 + 0xa8),0x13aea7d,&local_158,&local_e8);
        if ((iVar7 == 2) || ((int)local_e8 != 8)) {
          uVar13 = 0x139532f;
          uVar12 = 0xb85;
LAB_00a3a2ed:
          uVar17 = 0x16;
          goto LAB_00a398b7;
        }
        func_0x0025d410(0x129b6c8,0x139532f,0xb8a,*local_158);
        local_e0[5] = 0;
        local_e0[0] = local_e0[0] & 0xffffffff00000000;
        uVar6 = func_0x005defd0(*(undefined8 *)(lVar15 + 0xa8),0x1361905,local_e0 + 5,local_e0);
        if (uVar6 == 2) {
          lVar15 = 2;
          bVar18 = false;
        }
        else {
          uVar17 = (ulong)uVar6;
          if (uVar6 != 0) {
            uVar13 = 0x132cb2c;
            uVar12 = 0x5a7;
            goto LAB_00a398b7;
          }
          if ((int)local_e0[0] != 0x90) {
            uVar13 = 0x132cb2c;
            uVar12 = 0x59e;
            goto LAB_00a3a2ed;
          }
          lVar15 = 1;
          bVar18 = true;
        }
        plVar9[0x10f] = lVar15;
        if ((int)plVar9[0x8a] == 3) {
          uVar14 = 0x1341753;
          uVar13 = 0x139532f;
          uVar12 = 0xb9b;
          goto LAB_00a39c33;
        }
        plVar9[2] = local_168;
        plVar9[3] = param_1 + 0xd0;
        plVar9[4] = param_1;
        plVar9[1] = lVar2;
        if (bVar18) {
          plVar9[0x10f] = 0;
          *(undefined8 *)((long)plVar9 + 0x474) = 0xffffffffffffffff;
          local_f8 = 0;
          local_fc = 0;
          iVar7 = func_0x005defd0(*(undefined8 *)(*plVar9 + 0xa8),0x1361905,&local_f8,&local_fc);
          lVar15 = local_f8;
          uVar12 = 0x5ba;
          if (((iVar7 == 2) || (uVar12 = 0x5bd, local_fc != 0x90)) ||
             (uVar12 = 0x5c4, *(long *)(local_f8 + 0x18) != 0x10000)) {
            uVar17 = 0x16;
          }
          else {
            lVar16 = *(long *)(local_f8 + 0x28);
            lVar3 = *(long *)(local_f8 + 0x20);
            func_0x0025d410(0x12735d1,0x1317d82,0x5c9,lVar3,lVar16 + lVar3,
                            *(undefined8 *)(local_f8 + 0x30));
            local_48 = 0;
            local_50 = 0;
            local_58 = 0;
            local_60 = 0;
            local_68 = 0;
            local_70 = 0;
            local_78 = 0;
            local_80 = 0;
            local_88 = 0;
            local_90 = 0;
            local_98 = 0;
            local_a0 = 0;
            local_a8 = 0;
            local_e0[6] = 0;
            local_e0[5] = 0;
            local_158 = local_e0 + 5;
            uVar6 = *(uint *)(lVar15 + 0x38);
            local_110 = 0;
            local_118 = 0;
            local_120 = 0;
            local_128 = (undefined8 *)0x0;
            local_130 = 0;
            local_138 = 0;
            local_140 = 0;
            local_148 = 0;
            local_150 = (ulong)(lVar16 + -0x10000 + lVar3) >> 0xd & 0xfffffffffffffff8;
            local_40 = (ulong)uVar6;
            local_108 = (ulong)uVar6;
            if ((undefined8 *)plVar9[4] == (undefined8 *)0x0) {
              uVar12 = 0x3d2;
LAB_00a3a8d7:
              uVar17 = 6;
              uVar6 = 6;
LAB_00a3a8e2:
              func_0x0025d410(0x128a216,0x12fbf3e,uVar12,uVar17,uVar6);
            }
            else {
              iVar7 = func_0x008d1a30(*(undefined8 *)plVar9[4],0x126d514,6);
              if (iVar7 != 0) {
                uVar12 = 0x3d7;
                goto LAB_00a3a8d7;
              }
              if (plVar9[2] == 0) {
                uVar12 = 0x3dd;
                goto LAB_00a3a8d7;
              }
              lVar16 = *(long *)(plVar9[2] + 0x18);
              if (lVar16 == 0) {
                uVar12 = 0x3e3;
                goto LAB_00a3a8d7;
              }
              local_e0[4] = 0;
              local_e0[3] = 0;
              local_e0[1] = 0;
              local_e0[0] = 0;
              local_e0[2] = 0xffffffff;
              uVar6 = func_0x002eb120(*(undefined8 *)(*(long *)(lVar16 + 0x18) + 0xa0),local_e0);
              if (uVar6 == 0) {
                local_e8 = (undefined8 *)0x0;
                uVar6 = func_0x002eb0a0(*(undefined8 *)(*(long *)(lVar16 + 0x18) + 0xa0),
                                        local_e0[2] & 0xffffffff,&local_e8);
                if (uVar6 != 0) {
                  uVar12 = 0x3f8;
                  goto LAB_00a3ab31;
                }
                local_f0 = (undefined8 *)0x0;
                uVar6 = func_0x0072e490(local_e8,&local_f0);
                if (uVar6 == 0) {
                  if (local_e8 != local_f0) {
                    func_0x0054a060(local_f0);
                    func_0x0054a120(local_e8);
                    local_e8 = local_f0;
                  }
                  iVar7 = func_0x008d1a30(*local_e8,0x12dd4ac,4);
                  if (iVar7 == 0) {
LAB_00a3b04e:
                    uVar6 = func_0x006afb50(local_e8,0x200000,0x138b1db,0x416);
                    puVar5 = local_e8;
                    if (uVar6 == 0) {
                      local_120 = local_e0[4] + local_e0[3];
                      local_128 = local_e8;
                      local_148 = func_0x00c08b50(0x4000,0x25686d0,0x102);
                      local_138 = local_148 + 0x1000;
                      local_140 = 0x1000;
                      local_130 = 0x3000;
                      uVar6 = *(int *)(lVar15 + 0x38) - 0x101;
                      if ((uVar6 < 0xd) && ((0x1b2dU >> (uVar6 & 0x1f) & 1) != 0)) {
                        func_0x00a3e010(plVar9,&local_158);
                      }
                      func_0x0054a440(puVar5);
                      if (local_80 != 0) {
                        func_0x0036b350(plVar9,local_e0 + 5);
                      }
                      if (local_78 != 0) {
                        iVar7 = func_0x0036b350(plVar9,local_e0 + 5);
                        if (iVar7 != 0) {
                          func_0x00c08df0(local_78,0x25686d0);
                    /* WARNING: Bad instruction - Truncating control flow here */
                          halt_baddata();
                        }
                    /* WARNING: Bad instruction - Truncating control flow here */
                        halt_baddata();
                      }
                    /* WARNING: Bad instruction - Truncating control flow here */
                      halt_baddata();
                    }
                    func_0x0054b6b0(local_e8,0x131bc1e,0x12fbf3e,uVar6);
                    func_0x0054a120(local_e8);
                    bVar18 = uVar6 == 2;
                    goto LAB_00a3ab42;
                  }
                  func_0x0025d410(0x12bd7f7,0x12fbf3e,0x40f,*local_e8);
                  iVar7 = func_0x008d1a30(*local_e8,0x12c83c6,4);
                  if (iVar7 == 0) goto LAB_00a3b04e;
                  func_0x0054a120(local_e8);
                  uVar17 = 0x2d;
                  goto LAB_00a3a8e9;
                }
                uVar17 = (ulong)uVar6;
                func_0x0054a120();
                uVar12 = 0x403;
                goto LAB_00a3a8e2;
              }
              uVar12 = 0x3ed;
LAB_00a3ab31:
              func_0x0025d410(0x128a216,0x12fbf3e,uVar12,uVar6,uVar6);
              bVar18 = uVar6 == 0xffffffff;
LAB_00a3ab42:
              uVar17 = 6;
              if (!bVar18) {
                uVar17 = (ulong)uVar6;
              }
            }
LAB_00a3a8e9:
            uVar12 = 0x625;
          }
          func_0x0025d410(0x128a216,0x1317d82,uVar12,uVar17,uVar17);
          uVar12 = 0xcc6;
LAB_00a3a7ed:
          uVar13 = 0x1376485;
LAB_00a3a7f3:
          func_0x0025d410(0x128a216,uVar13,uVar12,uVar17,uVar17);
        }
        else {
          local_158 = (ulong *)0x0;
          local_e0[0] = local_e0[0] & 0xffffffff00000000;
          iVar7 = func_0x005defd0(*(undefined8 *)(*plVar9 + 0xa8),0x13aea7d,&local_158,local_e0);
          if ((iVar7 == 2) || ((int)local_e0[0] != 8)) {
            uVar17 = 0x16;
            func_0x0025d410(0x128a216,0x134177f,0xc27,0x16,0x16);
LAB_00a3a7da:
            uVar12 = 0xccf;
            goto LAB_00a3a7ed;
          }
          uVar17 = *local_158;
          plVar10 = (long *)func_0x00c08b50(0x5a0,0x25686d0,0x102);
          if (plVar9[0x10f] != 2) {
            uVar17 = 0x2d;
            func_0x0025d410(0x128a216,0x130d7d5,0xc04,0x2d,0x2d);
            uVar12 = 0xc33;
            uVar6 = 0x2d;
LAB_00a3a7b8:
            func_0x0025d410(0x128a216,0x134177f,uVar12,uVar17,uVar6);
            func_0x00c08df0(plVar10,0x25686d0);
            plVar9[6] = 0;
            goto LAB_00a3a7da;
          }
          local_e0[5] = 0;
          uVar6 = func_0x00a9db90(plVar9[4],uVar17 >> 9,0x10000,0,0,0,0,0,local_e0 + 5);
          if (uVar6 != 0) {
            uVar17 = (ulong)uVar6;
            func_0x0025d410(0x128a216,0x134c402,0xbdf,uVar6,uVar6);
            uVar12 = 0xc3a;
            goto LAB_00a3a7b8;
          }
          plVar11 = plVar10;
          if (plVar10 == (long *)0x0) {
            plVar11 = (long *)func_0x00c08b50(0x5a0,0x25686d0,0x102);
          }
          func_0x00259be0(*(undefined8 *)(local_e0[5] + 0x18),plVar11,0x5a0);
          plVar9[6] = (long)plVar11;
          *(uint *)(local_e0[5] + 0x68) = *(uint *)(local_e0[5] + 0x68) | 0x8000;
          func_0x00a9d690(local_e0[5]);
          plVar9[6] = (long)plVar10;
          uVar17 = plVar10[1];
          if (0x1332a0a < uVar17) {
            if (*(char *)((long)plVar10 + 0x1b) == '\0') {
              if (*plVar10 != 2) {
                if (*plVar10 != 1) {
                  func_0x0025d410(0x1312ae0,0x1376485,0xcee);
                  uVar13 = 0x1376485;
                  uVar12 = 0xcf0;
                  goto LAB_00a3a92a;
                }
                if (plVar9[0x10f] != 0) {
                  uVar12 = 0x139534a;
                  goto LAB_00a3a8ac;
                }
              }
              local_e0[5] = 0;
              if ((int)plVar9[0x8a] - 1U < 2) {
                iVar7 = func_0x005defd0(*(undefined8 *)(*plVar9 + 0xa8),0x13a5ac6,local_e0 + 5,0);
                if ((iVar7 != 0) || (iVar7 = func_0x008d1a30(local_e0[5],0x131d0d7,2), iVar7 == 0))
                goto LAB_00a3ab5a;
              }
              else if ((int)plVar9[0x8a] == 3) {
LAB_00a3ab5a:
                if ((*(ushort *)((long)plVar10 + 0x1c) & 1) == 0) {
                  func_0x0025d410(0x12e9123,0x130d7e5,0xc5b,0x60);
                  lVar15 = *plVar9;
                  uVar12 = *in_GS_OFFSET;
                }
                else {
                  if ((*(ushort *)((long)plVar10 + 0x1c) & 4) != 0) goto LAB_00a3abe5;
                  func_0x0025d410(0x12e9123,0x130d7e5,0xc63,0x60);
                  lVar15 = *plVar9;
                  uVar12 = *in_GS_OFFSET;
                }
                uVar17 = 0x60;
                func_0x0055a6a0(0x60,0,lVar15,uVar12,0);
                goto LAB_00a3a7fa;
              }
LAB_00a3abe5:
              uVar6 = *(ushort *)((long)plVar10 + 0x1c) & 0x13;
              if (uVar6 < 0x11) {
                    /* WARNING: Could not emulate address calculation at 0x00a3ac05 */
                    /* WARNING: Treating indirect jump as call */
                uVar17 = (*(code *)((long)*(int *)((ulong)uVar6 * 4 + 0x18d3f38) + 0x18d3f38))();
                return uVar17;
              }
              uVar13 = 0x130d7e5;
              func_0x0025d410(0x12f848c,0x130d7e5,0xc96);
              uVar12 = 0xc98;
            }
            else {
              uVar13 = 0x1376485;
              uVar12 = 0xcdf;
            }
LAB_00a3a92a:
            uVar17 = 0x16;
            goto LAB_00a3a7f3;
          }
          func_0x0025d410(0x12df1df,0x1376485,0xcd6,uVar17,uVar17);
          uVar12 = 0x12cf128;
LAB_00a3a8ac:
          func_0x0025d410(uVar12);
          uVar17 = 0x2d;
        }
LAB_00a3a7fa:
        uVar13 = 0x13b574e;
        uVar12 = 0xd99;
        goto LAB_00a398b7;
      }
      uVar14 = 0x12e9123;
      uVar13 = 0x138041d;
      uVar12 = 0xbd1;
LAB_00a39c33:
      func_0x0025d410(uVar14,uVar13,uVar12);
    }
LAB_00a39c3a:
    uVar17 = 0x16;
  }
  else {
    uVar13 = 0x13b574e;
    plVar9 = (long *)0x0;
    uVar12 = 0xd6a;
LAB_00a398b7:
    func_0x0025d410(0x128a216,uVar13,uVar12,uVar17,uVar17);
  }
  if (local_160 != 0) {
    func_0x00a9d690();
  }
  if (local_168 != 0) {
    func_0x006afb50(param_1,0x80400,0x138b1db);
    func_0x00c4bb20(0x34fb368,0,0);
    func_0x00741a80(local_168);
    func_0x00c4c4b0(0x34fb368,0,0);
    local_e0[5] = 0x1adcdc8;
    local_a8 = local_a8 & 0xffffffff00000000;
    local_e0[6] = param_1;
    func_0x0058ea90(*(undefined8 *)(param_1 + 8),local_e0 + 5);
  }
  if (plVar9 == (long *)0x0) goto LAB_00a3a0fc;
  iVar7 = (int)plVar9[0x8a];
  if ((*(byte *)(plVar9 + 0x82) & 1) == 0) {
    if (iVar7 == 1) {
      if (plVar9[0xbf] != 0) {
        func_0x0094a9d0(plVar9,plVar9 + 0xbf);
      }
      if (plVar9[0xdf] != 0) {
        func_0x004c6a00(plVar9[0xdf] + 0xb0,0,0);
        lVar15 = plVar9[0xdf];
        if ((*(byte *)(lVar15 + 0x1c4) & 0x80) == 0) {
          *(undefined8 *)(*(long *)(*(long *)(lVar15 + 0x10) + 0x18) + 0x710) = 0;
          lVar15 = plVar9[0xdf];
        }
        func_0x004c6fa0(lVar15 + 0xb0,0,0);
        lVar15 = plVar9[0xdf];
        plVar9[0xdf] = 0;
        func_0x0054a120(lVar15);
      }
      if (plVar9[0xd6] != 0) {
        func_0x004c7e50(plVar9[0xd6] + 0x48);
        func_0x004c7e50(plVar9[0xd6] + 0xf0);
        func_0x004c7e50(plVar9[0xd6] + 0x198);
        func_0x004c7e50(plVar9[0xd6] + 0x240);
        func_0x00c08df0(plVar9[0xd6],0x2568820);
        func_0x004c7e50(plVar9 + 0xc3);
        func_0x004c7e50(plVar9 + 0xcc);
        func_0x004c7e50(plVar9 + 0xda);
        func_0x004c7e50(plVar9 + 0xde);
      }
      if (plVar9[0xe4] != 0) {
        func_0x00c08df0(plVar9[0xe4],0x2568820);
        plVar10 = plVar9 + 0xee;
LAB_00a39e29:
        func_0x004c7e50(plVar10);
      }
      goto LAB_00a39e2e;
    }
  }
  else {
    if (iVar7 == 1) {
      func_0x0036b470(plVar9);
      if (plVar9[0xbf] != 0) {
        func_0x0094a9d0(plVar9,plVar9 + 0xbf);
      }
      if (plVar9[0xb6] != 0) {
        func_0x00c08df0(plVar9[0xb6],0x2568820);
        func_0x004c7e50(plVar9 + 0xab);
        func_0x004c7e50(plVar9 + 0xbe);
        func_0x004c7e50(plVar9 + 0xba);
      }
      if (plVar9[0xd6] != 0) {
        lVar15 = 0x14;
        lVar16 = 0x48;
        if (*(int *)(param_2 + 0x330) == 1) {
          lVar15 = 8;
        }
        do {
          func_0x004c7e50(plVar9[0xd6] + lVar16);
          lVar16 = lVar16 + 0xa8;
          lVar15 = lVar15 + -1;
        } while (lVar15 != 0);
        func_0x00c08df0(plVar9[0xd6],0x2568820);
        func_0x004c7e50(plVar9 + 0xc3);
        func_0x004c7e50(plVar9 + 0xcc);
        func_0x004c7e50(plVar9 + 0xda);
        plVar10 = plVar9 + 0xde;
        goto LAB_00a39e29;
      }
    }
    else if (iVar7 == 2) {
      func_0x0025d410(0x128a216,0x13b574e,0xf22,uVar17,uVar17);
      func_0x0036b470(plVar9);
    }
    else {
      if (iVar7 != 3) goto LAB_00a39e67;
      if (plVar9[0x95] != 0) {
        func_0x0094a910(plVar9,plVar9 + 0x95);
      }
      if (plVar9[0x9e] != 0) {
        func_0x0094a910(plVar9,plVar9 + 0x9e);
      }
      if (plVar9[0xb6] != 0) {
        func_0x00c08df0(plVar9[0xb6],0x2568820);
        func_0x004c7e50(plVar9 + 0x99);
        func_0x004c7e50(plVar9 + 0xa2);
        func_0x004c7e50(plVar9 + 0xab);
        func_0x004c7e50(plVar9 + 0xbe);
        plVar10 = plVar9 + 0xba;
        goto LAB_00a39e29;
      }
    }
LAB_00a39e2e:
    if (((int)plVar9[0x8a] == 1) && ((long)*(int *)((long)plVar9 + 0x784) != -1)) {
      *(undefined8 *)((long)*(int *)((long)plVar9 + 0x784) * 0xc0 + 0x35ab480) = 0;
      *(undefined4 *)((long)plVar9 + 0x784) = 0xffffffff;
    }
  }
LAB_00a39e67:
  if (plVar9[0x35] != 0) {
    func_0x00c08df0(plVar9[0x39],0x25686d0);
    func_0x00bf1760(plVar9 + 0x3c);
    *(uint *)(plVar9[0x35] + 0x1c8) = *(uint *)(plVar9[0x35] + 0x1c8) & 0xffffff7f;
    func_0x0054a120(plVar9[0x35]);
  }
  if (plVar9[0x28] != 0) {
    func_0x00c08df0(plVar9[0x2c],0x25686d0);
    func_0x00bf1760(plVar9 + 0x2f);
    *(uint *)(plVar9[0x28] + 0x1c8) = *(uint *)(plVar9[0x28] + 0x1c8) & 0xffffff7f;
    func_0x0054a120(plVar9[0x28]);
  }
  if (plVar9[0x42] != 0) {
    func_0x00bf1760(plVar9 + 0x49);
    *(uint *)(plVar9[0x42] + 0x1c8) = *(uint *)(plVar9[0x42] + 0x1c8) & 0xffffff7f;
    func_0x0054a120(plVar9[0x42]);
  }
  if (plVar9[0x69] != 0) {
    func_0x00bf1760(plVar9 + 0x70);
    *(uint *)(plVar9[0x69] + 0x1c8) = *(uint *)(plVar9[0x69] + 0x1c8) & 0xffffff7f;
    func_0x0054a120(plVar9[0x69]);
  }
  if (plVar9[0x4f] != 0) {
    if (*(int *)plVar9[6] == 2) {
      lVar15 = plVar9[0x53];
      LOCK();
      bVar18 = lVar15 == plVar9[0x53];
      if (bVar18) {
        plVar9[0x53] = 0;
      }
      UNLOCK();
      if (!bVar18) {
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      func_0x00568950(lVar15);
      func_0x00c08df0(lVar15,0x2568890);
    }
    func_0x00bf1760(plVar9 + 0x56);
    *(uint *)(plVar9[0x4f] + 0x1c8) = *(uint *)(plVar9[0x4f] + 0x1c8) & 0xffffff7f;
    func_0x0054a120(plVar9[0x4f]);
  }
  if (plVar9[0x5c] != 0) {
    func_0x00bf1760(plVar9 + 99);
    *(uint *)(plVar9[0x5c] + 0x1c8) = *(uint *)(plVar9[0x5c] + 0x1c8) & 0xffffff7f;
    func_0x0054a120(plVar9[0x5c]);
  }
  if (plVar9[0x10d] != 0) {
    func_0x00870990(plVar9[0x10d],0,0x100);
    func_0x00c08df0(plVar9[0x10d],0x2568820);
    plVar9[0x10d] = 0;
  }
  if (plVar9[0x1a] != 0) {
    pbVar1 = (byte *)(plVar9[0x1a] + 0x1c8);
    *pbVar1 = *pbVar1 & 0x7f;
    func_0x0054a120(plVar9[0x1a]);
    func_0x0054a460(param_2,0,0);
  }
  lVar15 = plVar9[6];
  if (lVar15 != 0) {
    LOCK();
    bVar18 = lVar15 == plVar9[6];
    if (bVar18) {
      plVar9[6] = 0;
    }
    UNLOCK();
    if (!bVar18) {
      func_0x007f1950();
      func_0x007f1810(0xa3b62f);
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    func_0x00c08df0(lVar15,0x25686d0);
  }
  if ((*(byte *)(plVar9 + 0x82) & 1) != 0) {
    func_0x00b93850(plVar9);
  }
  func_0x00bf1760(plVar9 + 0xd);
  func_0x004c7e50(plVar9 + 0x86);
  if (*(long **)(param_2 + 0x298) == plVar9) {
    LOCK();
    bVar18 = plVar9 == *(long **)(param_2 + 0x298);
    if (bVar18) {
      *(long *)(param_2 + 0x298) = 0;
    }
    UNLOCK();
    if (!bVar18) {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
  }
  func_0x00c08df0(plVar9,0x25686d0);
LAB_00a3a0fc:
  func_0x006dea70(lVar2);
  if (_DAT_0391c310 == local_38) {
    return uVar17;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar4 = (code *)invalidInstructionException();
  (*pcVar4)();
}


