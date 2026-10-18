/* REA 6.7.0 / Ghidra 12.1.4 recovered pseudocode, not original or buildable C.
 * Input: deep_558.bin, SHA256 1552cf0c8972d5c84ab72d094a5c34b8edec69b384db25645f0614b1437d390a
 * File offset zero maps to kernel RVA 0xac73c0; runtime VA = 0xffffffff8a9c0000 + RVA.
 * External bodies/types/data missing from this raw window remain unknown.
 * Function names are analyst seeds or Ghidra-generated; instruction truth is in .rea.asm.
 */

/* ===== sys_558 | RVA 0xac73c0 | file +0x0 | ev_4bb0b10d45b08cafcacbc39e397310c75bc876384f8c92449f3806b8010dce84 =====
 * Body: [{"start":"0xac73c0","end":"0xac7467"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sys_558(long param_1,undefined4 *param_2)

{
  code *pcVar1;
  undefined8 *puVar2;
  undefined8 uVar3;
  undefined8 local_38;
  long local_30;
  
  local_30 = _DAT_0391c310;
  uVar3 = *(undefined8 *)(*(long *)(param_1 + 8) + 0xc48);
  puVar2 = (undefined8 *)func_0x0039a2a0(uVar3,*param_2,*(ushort *)(param_2 + 2) | 0x1000,&local_38)
  ;
  if (puVar2 == (undefined8 *)0x0) {
    uVar3 = 3;
  }
  else {
    func_0x00399e30(uVar3,*param_2,local_38);
    func_0x00399eb0(local_38);
    func_0x00c08df0(*puVar2,0x2889dd0);
    func_0x00c08df0(puVar2,0x2889dd0);
    uVar3 = 0;
  }
  if (_DAT_0391c310 == local_30) {
    return uVar3;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* ===== sub_00ac7470 | RVA 0xac7470 | file +0xb0 | ev_23c971c853b795422810242df5a0d01bc711c188d67d7f9a71cce4ea4307bfe6 =====
 * Body: [{"start":"0xac7470","end":"0xac7554"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_00ac7470(long param_1,long *param_2)

{
  code *pcVar1;
  undefined8 uVar2;
  bool bVar3;
  long local_48;
  ulong local_40;
  long local_38;
  
  uVar2 = 0x16;
  local_38 = _DAT_0391c310;
  if (*(int *)(param_1 + 0x40) - 1U < 2) {
    uVar2 = 0;
    func_0x004c7190(0x3cc1210,0,0,0);
    func_0x00acf200(&local_48);
    bVar3 = CARRY8(local_40,param_2[1]);
    local_40 = local_40 + param_2[1];
    local_48 = local_48 + *param_2 + (ulong)bVar3;
    *(undefined4 *)(param_1 + 0x44) = 0;
    sub_00ac7560(param_1,&local_48);
    *(byte *)(param_1 + 0x40) = *(byte *)(param_1 + 0x40) | 4;
    if (_DAT_03cc1218 == param_1) {
      func_0x00c3d7f0(_DAT_03cc1228);
      func_0x00c3d740(_DAT_03cc1228,*param_2 << 0x20 | (ulong)*(uint *)((long)param_2 + 0xc),0);
    }
    func_0x004c7520(0x3cc1210,0,0,0);
  }
  if (_DAT_0391c310 == local_38) {
    return uVar2;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* ===== sub_00ac7560 | RVA 0xac7560 | file +0x1a0 | ev_63bbf1bc566045f27df84375ae947d67481c63754701a53f9a0fdb654f6301e1 =====
 * Body: [{"start":"0xac7560","end":"0xac7576"},{"start":"0xac7580","end":"0xac7622"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_00ac7560(undefined8 *param_1,long *param_2)

{
  long lVar1;
  code *pcVar2;
  long *plVar3;
  
  if (_DAT_03cc1218 != (long *)0x0) {
    plVar3 = _DAT_03cc1218;
    do {
      if (plVar3[2] != *param_2) {
        if (plVar3[2] <= *param_2) goto LAB_00ac7582;
LAB_00ac759a:
        if (*(long **)plVar3[1] != plVar3) {
          func_0x007f1950();
          func_0x007f20c0(0xac75e9,plVar3,(undefined8 *)plVar3[1],*(undefined8 *)plVar3[1]);
          func_0x00c9aa10(7,0x1378db8,plVar3,(undefined8 *)plVar3[1],*(undefined8 *)plVar3[1]);
                    /* WARNING: Does not return */
          pcVar2 = (code *)invalidInstructionException();
          (*pcVar2)();
        }
        param_1[1] = (undefined8 *)plVar3[1];
        *param_1 = plVar3;
        *(undefined8 **)plVar3[1] = param_1;
        plVar3[1] = (long)param_1;
        goto LAB_00ac75d3;
      }
      if ((ulong)param_2[1] < (ulong)plVar3[3]) goto LAB_00ac759a;
LAB_00ac7582:
      plVar3 = (long *)*plVar3;
    } while (plVar3 != (long *)0x0);
  }
  *param_1 = 0;
  param_1[1] = _DAT_03cc1220;
  *_DAT_03cc1220 = param_1;
  _DAT_03cc1220 = param_1;
LAB_00ac75d3:
  lVar1 = *param_2;
  param_1[3] = param_2[1];
  param_1[2] = lVar1;
  return;
}



/* ===== sub_00ac7630 | RVA 0xac7630 | file +0x270 | ev_c4fc749e872e5d028baab892907a5ef597b4023b725cdbfd924808cf32d7ab50 =====
 * Body: [{"start":"0xac7630","end":"0xac787e"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_00ac7630(long *param_1)

{
  ulong uVar1;
  code *pcVar2;
  undefined8 *puVar3;
  long lVar4;
  undefined8 uVar5;
  uint uVar6;
  int local_40 [2];
  ulong local_38;
  long local_30;
  
  local_30 = _DAT_0391c310;
  func_0x004c7190(0x3cc1210,0,0,0);
  uVar6 = *(uint *)(param_1 + 8);
  if ((uVar6 & 4) == 0) goto LAB_00ac7766;
  if (_DAT_03cc1218 == param_1) {
    func_0x00c3d7f0(_DAT_03cc1228);
    lVar4 = *param_1;
    if (lVar4 == 0) {
      puVar3 = (undefined8 *)param_1[1];
      if (*(long **)param_1[1] != param_1) {
LAB_00ac7805:
        func_0x007f1950();
        func_0x007f20c0(0xac7805,param_1,(undefined8 *)param_1[1],*(undefined8 *)param_1[1]);
        puVar3 = (undefined8 *)param_1[1];
        uVar5 = 0x1f;
        goto LAB_00ac7830;
      }
    }
    else {
      if (*(long **)(lVar4 + 8) != param_1) {
        func_0x007f1950();
        func_0x007f2180(0xac783f,param_1,*param_1,*(undefined8 *)(*param_1 + 8),param_1);
        lVar4 = *param_1;
        uVar5 = 0x1b;
        goto LAB_00ac786c;
      }
      if (*(long **)param_1[1] != param_1) goto LAB_00ac7805;
      *(undefined8 **)(lVar4 + 8) = (undefined8 *)param_1[1];
      puVar3 = _DAT_03cc1220;
    }
    _DAT_03cc1220 = puVar3;
    *(long *)param_1[1] = *param_1;
    uVar6 = *(uint *)(param_1 + 8) & 0xfffffffb;
    *(uint *)(param_1 + 8) = uVar6;
    if (_DAT_03cc1218 != (long *)0x0) {
      lVar4 = _DAT_03cc1218[2];
      uVar1 = _DAT_03cc1218[3];
      func_0x00acf200(local_40);
      func_0x00c3d740(_DAT_03cc1228,
                      uVar1 - local_38 >> 0x20 |
                      (ulong)(((int)lVar4 - local_40[0]) - (uint)(uVar1 < local_38)) << 0x20,0);
      uVar6 = *(uint *)(param_1 + 8);
    }
    goto LAB_00ac7766;
  }
  lVar4 = *param_1;
  if (lVar4 == 0) {
    puVar3 = (undefined8 *)param_1[1];
    if (*(long **)param_1[1] != param_1) {
LAB_00ac77a9:
      func_0x007f1950();
      func_0x007f20c0(0xac77a9,param_1,(undefined8 *)param_1[1],*(undefined8 *)param_1[1]);
      puVar3 = (undefined8 *)param_1[1];
      uVar5 = 0x27;
LAB_00ac7830:
      func_0x00c9aa10(uVar5,0x1378db8,param_1,puVar3,*puVar3);
                    /* WARNING: Does not return */
      pcVar2 = (code *)invalidInstructionException();
      (*pcVar2)();
    }
  }
  else {
    if (*(long **)(lVar4 + 8) != param_1) {
      func_0x007f1950();
      func_0x007f2180(0xac77d6,param_1,*param_1,*(undefined8 *)(*param_1 + 8),param_1);
      lVar4 = *param_1;
      uVar5 = 0x23;
LAB_00ac786c:
      func_0x00c9aa10(uVar5,0x12899e6,param_1,lVar4,*(undefined8 *)(lVar4 + 8),param_1);
                    /* WARNING: Does not return */
      pcVar2 = (code *)invalidInstructionException();
      (*pcVar2)();
    }
    if (*(long **)param_1[1] != param_1) goto LAB_00ac77a9;
    *(undefined8 **)(lVar4 + 8) = (undefined8 *)param_1[1];
    puVar3 = _DAT_03cc1220;
  }
  _DAT_03cc1220 = puVar3;
  *(long *)param_1[1] = *param_1;
  uVar6 = *(uint *)(param_1 + 8) & 0xfffffffb;
LAB_00ac7766:
  *(uint *)(param_1 + 8) = uVar6 | 0x10;
  func_0x004c7520(0x3cc1210,0,0,0);
  if (_DAT_0391c310 != local_30) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar2 = (code *)invalidInstructionException();
    (*pcVar2)();
  }
  return (int)(uVar6 << 0x1c) >> 0x1f;
}



/* ===== sub_00ac7880 | RVA 0xac7880 | file +0x4c0 | ev_6449b497deedb6d6b01f1aed54fe9ce5e287a0aefa58d4ed88f333759dc3f786 =====
 * Body: [{"start":"0xac7880","end":"0xac78cd"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

uint sub_00ac7880(long param_1)

{
  uint uVar1;
  
  func_0x004c7190(0x3cc1210,0,0,0);
  uVar1 = *(uint *)(param_1 + 0x40);
  *(uint *)(param_1 + 0x40) = uVar1 & 0xffffffe7;
  func_0x004c7520(0x3cc1210,0,0,0);
  return uVar1 & 0x10;
}



/* ===== sub_00ac78d0 | RVA 0xac78d0 | file +0x510 | ev_d69071b445c761f1725a8e1bf4d7b8dd46856e45e87bedefdf5c750ad040fb7a =====
 * Body: [{"start":"0xac78d0","end":"0xac7962"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_00ac78d0(void)

{
  code *pcVar1;
  
  func_0x004c7dd0(0x3cc1210,0x136c62d,0,1);
  _DAT_03cc1218 = 0;
  _DAT_03cc1220 = &DAT_03cc1218;
  _DAT_03cc1228 = func_0x00c3d680(0x12ba7c3,2,2);
  if (_DAT_03cc1228 != 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  func_0x007f1950();
  func_0x007f1810(0xac793d);
  func_0x00c9aa10(3,0x1380cbf);
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* ===== sub_00ac7970 | RVA 0xac7970 | file +0x5b0 | ev_65a382b1d2e068f0092350eb12ab00267848ee5d9c7a6c18d5128b5e9eb832f7 =====
 * Body: [{"start":"0xac7970","end":"0xac79d4"},{"start":"0xac79e0","end":"0xac7a93"},{"start":"0xac7aa0","end":"0xac7ad0"},{"start":"0xac7ae0","end":"0xac7cde"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_00ac7970(undefined8 param_1)

{
  long *plVar1;
  bool bVar2;
  long *plVar3;
  undefined8 *puVar4;
  long lVar5;
  undefined8 uVar6;
  code *pcVar7;
  long local_58;
  ulong local_50;
  long local_48;
  ulong local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  func_0x004c7190(0x3cc1210,0,0,0);
  func_0x00acf200(&local_48);
  if (_DAT_03cc1218 != (long *)0x0) {
    do {
      plVar3 = _DAT_03cc1218;
      lVar5 = _DAT_03cc1218[2];
      plVar1 = _DAT_03cc1218 + 2;
      if (lVar5 == local_48) {
        if (local_40 < (ulong)_DAT_03cc1218[3]) {
LAB_00ac7ba3:
          local_58 = *plVar1;
          local_50 = _DAT_03cc1218[3];
          func_0x00c3d740(param_1,(ulong)(((int)local_58 - (int)lVar5) - (uint)(local_50 < local_40)
                                         ) << 0x20 | local_50 - local_40 >> 0x20,0);
          break;
        }
      }
      else {
        bVar2 = local_48 < lVar5;
        lVar5 = local_48;
        if (bVar2) goto LAB_00ac7ba3;
      }
      lVar5 = *_DAT_03cc1218;
      if ((*(byte *)(_DAT_03cc1218 + 8) & 2) == 0) {
        if (lVar5 == 0) {
          puVar4 = (undefined8 *)_DAT_03cc1218[1];
          if (*(long **)_DAT_03cc1218[1] != _DAT_03cc1218) {
LAB_00ac7c02:
            func_0x007f1950();
            func_0x007f20c0(0xac7c02,plVar3,(undefined8 *)plVar3[1],*(undefined8 *)plVar3[1]);
            puVar4 = (undefined8 *)plVar3[1];
            uVar6 = 0x17;
LAB_00ac7c5a:
            func_0x00c9aa10(uVar6,0x1378db8,plVar3,puVar4,*puVar4);
                    /* WARNING: Does not return */
            pcVar7 = (code *)invalidInstructionException();
            (*pcVar7)();
          }
        }
        else {
          if (*(long **)(lVar5 + 8) != _DAT_03cc1218) {
            func_0x007f1950();
            func_0x007f2180(0xac7c98,plVar3,*plVar3,*(undefined8 *)(*plVar3 + 8),plVar3);
            lVar5 = *plVar3;
            uVar6 = 0x13;
LAB_00ac7cc5:
            func_0x00c9aa10(uVar6,0x12899e6,plVar3,lVar5,*(undefined8 *)(lVar5 + 8),plVar3);
                    /* WARNING: Does not return */
            pcVar7 = (code *)invalidInstructionException();
            (*pcVar7)();
          }
          if (*(long **)_DAT_03cc1218[1] != _DAT_03cc1218) goto LAB_00ac7c02;
          *(undefined8 **)(lVar5 + 8) = (undefined8 *)_DAT_03cc1218[1];
          puVar4 = _DAT_03cc1220;
        }
        _DAT_03cc1220 = puVar4;
        *(long *)plVar3[1] = *plVar3;
        *(uint *)(plVar3 + 8) = *(uint *)(plVar3 + 8) & 0xfffffff3 | 8;
        func_0x004c7520(0x3cc1210,0,0,0);
        pcVar7 = (code *)plVar3[6];
        if (0x197 < (-(long)pcVar7 + 0x267e88U >> 3 | -(long)pcVar7 << 0x3d)) {
          func_0x0044f8c0(0x2889ec0,pcVar7);
        }
      }
      else {
        if (lVar5 == 0) {
          puVar4 = (undefined8 *)_DAT_03cc1218[1];
          if (*(long **)_DAT_03cc1218[1] != _DAT_03cc1218) {
LAB_00ac7c2f:
            func_0x007f1950();
            func_0x007f20c0(0xac7c2f,plVar3,(undefined8 *)plVar3[1],*(undefined8 *)plVar3[1]);
            puVar4 = (undefined8 *)plVar3[1];
            uVar6 = 0xf;
            goto LAB_00ac7c5a;
          }
        }
        else {
          if (*(long **)(lVar5 + 8) != _DAT_03cc1218) {
            func_0x007f1950();
            func_0x007f2180(0xac7c69,plVar3,*plVar3,*(undefined8 *)(*plVar3 + 8),plVar3);
            lVar5 = *plVar3;
            uVar6 = 0xb;
            goto LAB_00ac7cc5;
          }
          if (*(long **)_DAT_03cc1218[1] != _DAT_03cc1218) goto LAB_00ac7c2f;
          *(undefined8 **)(lVar5 + 8) = (undefined8 *)_DAT_03cc1218[1];
          puVar4 = _DAT_03cc1220;
        }
        _DAT_03cc1220 = puVar4;
        *(long *)plVar3[1] = *plVar3;
        local_50 = plVar3[3] + plVar3[5];
        local_58 = *plVar1 + plVar3[4] + (ulong)CARRY8(plVar3[3],plVar3[5]);
        sub_00ac7560(plVar3,&local_58);
        *(byte *)(plVar3 + 8) = *(byte *)(plVar3 + 8) | 8;
        func_0x004c7520(0x3cc1210,0,0,0);
        *(int *)((long)plVar3 + 0x44) = *(int *)((long)plVar3 + 0x44) + 1;
        pcVar7 = (code *)plVar3[6];
        if (0x197 < (-(long)pcVar7 + 0x267e88U >> 3 | -(long)pcVar7 << 0x3d)) {
          func_0x0044f8c0(0x2889ea0,pcVar7);
        }
      }
      (*pcVar7)(plVar3,plVar3[7]);
      func_0x004c7190(0x3cc1210,0,0,0);
      func_0x00acf200(&local_48);
    } while (_DAT_03cc1218 != (long *)0x0);
  }
  func_0x004c7520(0x3cc1210,0,0,0);
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar7 = (code *)invalidInstructionException();
    (*pcVar7)();
  }
  return;
}



/* ===== sub_00ac7ce0 | RVA 0xac7ce0 | file +0x920 | ev_44b6a5cf60e2c03a2bd575c9ed4854b4f922ce4007ca38451506d04a619560f7 =====
 * Body: [{"start":"0xac7ce0","end":"0xac7d24"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_00ac7ce0(void)

{
  func_0x00258ff0(&DAT_03cc1230,0x80);
  func_0x00258ff0(0x3cc12b0,0x40);
  func_0x00258ff0(&DAT_03cc12f0,0x1c);
  _DAT_03cc1310 = func_0x003472d0();
  return;
}



/* ===== sub_00ac7d30 | RVA 0xac7d30 | file +0x970 | ev_76a7a06db7db0222afceba7b975ce17666b25b43b23046e88d30f98e9cacc40a =====
 * Body: [{"start":"0xac7d30","end":"0xac7f96"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_00ac7d30(long param_1)

{
  int iVar1;
  int *piVar2;
  undefined4 uVar3;
  long lVar4;
  long lVar5;
  undefined8 uVar6;
  long lVar7;
  long lVar8;
  
  if (_DAT_03cc1230 == 0) {
    lVar8 = 0;
  }
  else if (_DAT_03cc1238 == 0) {
    lVar8 = 1;
  }
  else if (_DAT_03cc1240 == 0) {
    lVar8 = 2;
  }
  else if (_DAT_03cc1248 == 0) {
    lVar8 = 3;
  }
  else if (_DAT_03cc1250 == 0) {
    lVar8 = 4;
  }
  else if (_DAT_03cc1258 == 0) {
    lVar8 = 5;
  }
  else if (_DAT_03cc1260 == 0) {
    lVar8 = 6;
  }
  else if (_DAT_03cc1268 == 0) {
    lVar8 = 7;
  }
  else if (_DAT_03cc1270 == 0) {
    lVar8 = 8;
  }
  else if (_DAT_03cc1278 == 0) {
    lVar8 = 9;
  }
  else if (_DAT_03cc1280 == 0) {
    lVar8 = 10;
  }
  else if (_DAT_03cc1288 == 0) {
    lVar8 = 0xb;
  }
  else if (_DAT_03cc1290 == 0) {
    lVar8 = 0xc;
  }
  else if (_DAT_03cc1298 == 0) {
    lVar8 = 0xd;
  }
  else if (_DAT_03cc12a0 == 0) {
    lVar8 = 0xe;
  }
  else {
    if (_DAT_03cc12a8 != 0) {
      return 0x803b000a;
    }
    lVar8 = 0xf;
  }
  lVar4 = func_0x00346d70(0x2750);
  if (lVar4 == 0) {
    uVar6 = 0x803b000a;
  }
  else {
    func_0x00258ff0(lVar4,0x2750);
    uVar3 = func_0x003a7140(0,lVar8,0);
    *(undefined4 *)(param_1 + 4) = uVar3;
    *(long *)(param_1 + 0x198) = lVar4;
    if (_DAT_03cc12f0 != 0) {
      *(undefined4 *)(lVar4 + 0x273c) = _DAT_03cc1304;
      *(undefined8 *)(lVar4 + 0x2734) = _DAT_03cc12fc;
      *(undefined8 *)(lVar4 + 0x272c) = _DAT_03cc12f4;
    }
    *(undefined8 *)(lVar4 + 0x2740) = 0x400000000;
    *(undefined4 *)(lVar4 + 0x2748) = 1;
    if ((*(char *)(param_1 + 0x18) == '\x02') && (0 < *(int *)(lVar4 + 0x272c))) {
      iVar1 = *(int *)(lVar4 + 0x2730);
      lVar5 = func_0x0045f3f0();
      if ((lVar5 != 0) && (*(int *)(lVar5 + 4) == iVar1)) {
        lVar7 = 0;
        do {
          piVar2 = *(int **)(lVar5 + 0xe8 + lVar7 * 8);
          if ((piVar2 != (int *)0x0) && (*piVar2 != 0)) {
            *(int *)(lVar4 + 0x2748) = piVar2[0xe];
          }
          lVar7 = lVar7 + 1;
        } while (lVar7 != 0x18);
      }
    }
    *(long *)(&DAT_03cc1230 + lVar8 * 8) = param_1;
    uVar6 = 0;
  }
  return uVar6;
}



/* ===== sub_00ac7fa0 | RVA 0xac7fa0 | file +0xbe0 | ev_fabc5cd03046fc92dfec7cc4acacb75ab1c93a9dfa4453db94425ceffe706e04 =====
 * Body: [{"start":"0xac7fa0","end":"0xac7ff0"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_00ac7fa0(long param_1)

{
  int iVar1;
  
  iVar1 = func_0x003a7a00(param_1,&DAT_03cc1230,0x10);
  if (-1 < iVar1) {
    if (*(int *)(param_1 + 8) != 0) {
      func_0x003a7730(param_1,0);
    }
    if (*(long *)(param_1 + 0x198) != 0) {
      func_0x00346f40();
      *(undefined8 *)(param_1 + 0x198) = 0;
    }
  }
  return;
}



/* ===== sub_00ac8000 | RVA 0xac8000 | file +0xc40 | ev_50c417863cbeb8e90e35ee8d5bcbe8cf52c4f4c7814b0c15911bcfeba5eb1355 =====
 * Body: [{"start":"0xac8000","end":"0xac8046"},{"start":"0xac8050","end":"0xac8181"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_00ac8000(long param_1,int param_2,short *param_3,short *param_4,uint param_5)

{
  short sVar1;
  long lVar2;
  undefined4 *puVar3;
  uint uVar4;
  long lVar5;
  int iVar6;
  bool bVar7;
  
  lVar2 = *(long *)(param_1 + 0x198);
  sVar1 = *param_3;
  if (sVar1 == 0xc) {
    if (((param_5 & 7) == 6) && (*param_4 == 0x238)) {
      *(undefined4 *)(lVar2 + 0x78) = 1;
      *(char *)(lVar2 + 0x7c) = (char)param_3[0xc];
      *(int *)(lVar2 + 0x80) = param_2;
      *(undefined4 *)(lVar2 + 0x84) = *(undefined4 *)(param_3 + 10);
      *(undefined4 *)(lVar2 + 0x88) = 1;
    }
  }
  else if (sVar1 == 9) {
    if (((((param_5 & 7) == 2) && (*(int *)(param_3 + 2) == 0)) && (*(int *)(param_3 + 4) == 1)) &&
       (*(int *)(param_3 + 10) == 1)) {
      uVar4 = (uint)(ushort)param_4[0x20];
      if ((ushort)param_4[0x20] <= (ushort)param_4[0x21]) {
        iVar6 = 0;
        do {
          if (*(int *)(param_3 + 0xe) <= iVar6) {
            return;
          }
          if (uVar4 - 1 < 5) {
                    /* WARNING: Could not emulate address calculation at 0x00ac8175 */
                    /* WARNING: Treating indirect jump as call */
            (*(code *)((long)*(int *)((ulong)(uVar4 - 1) * 4 + 0x18dc4c8) + 0x18dc4c8))();
            return;
          }
          iVar6 = iVar6 + 1;
          bVar7 = uVar4 < (ushort)param_4[0x21];
          uVar4 = uVar4 + 1;
        } while (bVar7);
      }
    }
  }
  else if (sVar1 == 1) {
    lVar5 = 0;
    do {
      if (*(int *)(param_3 + 0xe) <= lVar5) {
        return;
      }
      sVar1 = param_4[lVar5];
      if (sVar1 == 0) {
        return;
      }
      if ((((param_5 & 7) == 6) &&
          (((puVar3 = (undefined4 *)(lVar2 + 0x3c), sVar1 == 0x30 ||
            (puVar3 = (undefined4 *)(lVar2 + 100), sVar1 == 0x38)) ||
           (puVar3 = (undefined4 *)(lVar2 + 0x50), sVar1 == 0x31)))) &&
         (puVar3 != (undefined4 *)0x0)) {
        *puVar3 = 1;
        *(char *)(puVar3 + 1) = (char)param_3[0xc];
        puVar3[2] = *(int *)(param_3 + 10) * (int)lVar5 + param_2;
        puVar3[3] = *(undefined4 *)(param_3 + 10);
        puVar3[4] = 1;
      }
      lVar5 = lVar5 + 1;
    } while (lVar5 != 0x20);
  }
  return;
}



/* ===== sub_00ac81c0 | RVA 0xac81c0 | file +0xe00 | ev_f009ffab08f8c0346330b2e509c4b20553ea90b2ccd78dcdc052767882c80dea =====
 * Body: [{"start":"0xac81c0","end":"0xac81c5"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_00ac81c0(void)

{
  return;
}



/* ===== sub_00ac81d0 | RVA 0xac81d0 | file +0xe10 | ev_753b886bb4782a4ab46fc86b0fc36a5afbf8f25bbf91a2685265f6899ebba306 =====
 * Body: [{"start":"0xac81d0","end":"0xac81d5"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_00ac81d0(void)

{
  return;
}



/* ===== sub_00ac81e0 | RVA 0xac81e0 | file +0xe20 | ev_77cec38a4b79af6b5c0327854c28b8b384fd4e3c896de14e82db32956e5b584a =====
 * Body: [{"start":"0xac81e0","end":"0xac824e"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_00ac81e0(long param_1)

{
  int iVar1;
  
  iVar1 = func_0x00a5f940(0);
  if (iVar1 == 0) {
    *(undefined4 *)(param_1 + 8) = 1;
    iVar1 = func_0x003a7730(param_1,1);
    if (iVar1 != 0) {
      func_0x0025d410(0x12f0dd3,0x127d6c2,0x274);
      func_0x0025d410(0x129ff8f,iVar1);
    }
    *(undefined4 *)(param_1 + 400) = 1;
  }
  return 1;
}



/* ===== sub_00ac8250 | RVA 0xac8250 | file +0xe90 | ev_34f76f02aed4e7972932d224d0b1000528c9b333a228ba95b3e90322f818079a =====
 * Body: [{"start":"0xac8250","end":"0xac82fa"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_00ac8250(long param_1,char param_2)

{
  int *piVar1;
  undefined8 uVar2;
  
  piVar1 = *(int **)(param_1 + 0x198);
  if ((((((*piVar1 == 0) || (uVar2 = 1, (char)piVar1[1] != param_2)) &&
        ((piVar1[3] == 0 || (uVar2 = 1, (char)piVar1[4] != param_2)))) &&
       ((piVar1[6] == 0 || (uVar2 = 1, (char)piVar1[7] != param_2)))) &&
      ((piVar1[9] == 0 || (uVar2 = 1, (char)piVar1[10] != param_2)))) &&
     (((((piVar1[0xc] == 0 || (uVar2 = 1, (char)piVar1[0xd] != param_2)) &&
        ((piVar1[0xf] == 0 || (uVar2 = 1, (char)piVar1[0x10] != param_2)))) &&
       ((piVar1[0x14] == 0 || (uVar2 = 1, (char)piVar1[0x15] != param_2)))) &&
      (((piVar1[0x19] == 0 || (uVar2 = 1, (char)piVar1[0x1a] != param_2)) &&
       ((piVar1[0x1e] == 0 || (uVar2 = 1, (char)piVar1[0x1f] != param_2)))))))) {
    uVar2 = 0;
  }
  return uVar2;
}



/* ===== sub_00ac8300 | RVA 0xac8300 | file +0xf40 | ev_a30eb163690e189be7e6d82a8b1965dc945dc895f8c173b6ff20b7ebc35a2a02 =====
 * Body: [{"start":"0xac8300","end":"0xac875d"},{"start":"0xac8760","end":"0xac8793"},{"start":"0xac87a0","end":"0xac884e"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Possible PIC construction at 0x00ac861c: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00ac86d5: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x00ac8621) */
/* WARNING: Removing unreachable block (ram,0x00ac8646) */
/* WARNING: Removing unreachable block (ram,0x00ac8653) */
/* WARNING: Removing unreachable block (ram,0x00ac8660) */
/* WARNING: Removing unreachable block (ram,0x00ac8669) */
/* WARNING: Removing unreachable block (ram,0x00ac8672) */
/* WARNING: Removing unreachable block (ram,0x00ac867b) */
/* WARNING: Removing unreachable block (ram,0x00ac8684) */
/* WARNING: Removing unreachable block (ram,0x00ac868d) */
/* WARNING: Removing unreachable block (ram,0x00ac8696) */
/* WARNING: Removing unreachable block (ram,0x00ac869f) */
/* WARNING: Removing unreachable block (ram,0x00ac86a8) */
/* WARNING: Removing unreachable block (ram,0x00ac86b1) */
/* WARNING: Removing unreachable block (ram,0x00ac86ba) */
/* WARNING: Removing unreachable block (ram,0x00ac86c3) */
/* WARNING: Removing unreachable block (ram,0x00ac86cc) */
/* WARNING: Removing unreachable block (ram,0x00ac86e6) */
/* WARNING: Removing unreachable block (ram,0x00ac8727) */
/* WARNING: Removing unreachable block (ram,0x00ac8753) */
/* WARNING: Removing unreachable block (ram,0x00ac876d) */
/* WARNING: Removing unreachable block (ram,0x00ac877a) */
/* WARNING: Removing unreachable block (ram,0x00ac87a0) */
/* WARNING: Removing unreachable block (ram,0x00ac8785) */
/* WARNING: Removing unreachable block (ram,0x00ac87d8) */
/* WARNING: Removing unreachable block (ram,0x00ac878a) */
/* WARNING: Removing unreachable block (ram,0x00ac878f) */
/* WARNING: Removing unreachable block (ram,0x00ac8814) */
/* WARNING: Removing unreachable block (ram,0x00ac8760) */
/* WARNING: Removing unreachable block (ram,0x00ac883e) */
/* WARNING: Removing unreachable block (ram,0x00ac86d5) */
/* WARNING: Removing unreachable block (ram,0x00ac86da) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_00ac8300(long param_1,undefined1 param_2,long param_3,int param_4,undefined8 param_5)

{
  long lVar1;
  long lVar2;
  code *pcVar3;
  byte bVar4;
  char cVar5;
  char cVar6;
  char cVar7;
  char cVar8;
  undefined1 uVar9;
  byte bVar10;
  byte bVar11;
  undefined2 uVar12;
  int iVar13;
  long lVar14;
  ushort uVar15;
  bool bVar16;
  
  lVar1 = _DAT_0391c310;
  if ((((param_1 == 0) || (param_3 == 0)) || (param_4 < 1)) ||
     (iVar13 = func_0x00347190(), iVar13 != 0)) {
    if (_DAT_0391c310 == lVar1) {
      return;
    }
LAB_00ac8848:
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar3 = (code *)invalidInstructionException();
    (*pcVar3)();
  }
  lVar2 = *(long *)(param_1 + 0x198);
  if (lVar2 == 0) {
    if (_DAT_0391c310 == lVar1) {
      halt_baddata();
    }
    goto LAB_00ac8848;
  }
  lVar14 = (long)*(int *)(param_1 + 0x104) * 0x98;
  lVar1 = lVar2 + 0x90 + lVar14;
  func_0x00258ff0(lVar1,0x98);
  *(undefined8 *)(lVar2 + 0x90 + lVar14) = param_5;
  *(undefined8 *)(lVar2 + 0x98 + lVar14) = 0;
  bVar4 = func_0x00331520(lVar2,param_2,param_3,param_4);
  cVar5 = func_0x00331520(lVar2 + 0xc,param_2,param_3,param_4);
  cVar6 = func_0x00331520(lVar2 + 0x18,param_2,param_3,param_4);
  cVar7 = func_0x00331520(lVar2 + 0x24,param_2,param_3,param_4);
  cVar8 = func_0x00331520(lVar2 + 0x30,param_2,param_3,param_4);
  *(byte *)(lVar2 + 0xaa + lVar14) = cVar8 << 4 | cVar7 << 3 | cVar6 << 2 | cVar5 * '\x02' | bVar4;
  uVar12 = func_0x003314d0(lVar2 + 0x3c,param_2,param_3,param_4);
  *(undefined2 *)(lVar2 + 0xa6 + lVar14) = uVar12;
  uVar12 = func_0x003314d0(lVar2 + 0x50,param_2,param_3,param_4);
  *(undefined2 *)(lVar2 + 0xa8 + lVar14) = uVar12;
  uVar9 = func_0x003314d0(lVar2 + 100,param_2,param_3,param_4);
  *(undefined1 *)(lVar2 + 0xab + lVar14) = uVar9;
  cVar5 = func_0x003314d0(lVar2 + 0x78,param_2,param_3,param_4);
  *(char *)(lVar2 + 0xac + lVar14) = cVar5;
  *(undefined1 *)(lVar2 + 0xa0 + lVar14) = 1;
  *(undefined2 *)(lVar2 + 0xa4 + lVar14) = 0;
  bVar16 = true;
  if (*(char *)(lVar2 + 0xaa + lVar14) == '\0') {
    uVar15 = -*(ushort *)(lVar1 + 0x16);
    if ((short)uVar15 < 0) {
      uVar15 = *(ushort *)(lVar1 + 0x16);
    }
    if ((uVar15 < 0x1e) && (*(char *)(lVar1 + 0x1b) == '\0')) {
      bVar16 = cVar5 != '\0';
    }
  }
  iVar13 = func_0x00a5f940(0);
  if (iVar13 == 0) {
    func_0x003a8440(param_1,bVar16);
  }
  if ((*(int *)(param_1 + 8) != 0) && (bVar16 != false)) {
    _DAT_03cc1310 = param_5;
  }
  iVar13 = *(int *)(lVar2 + 0x2728);
  if (iVar13 != 0) {
    bVar10 = *(byte *)(param_1 + 0x18) & 0xfe;
    bVar4 = *(byte *)(lVar1 + 0x1a) & 0x3f;
    if (bVar10 != 2) {
      bVar4 = *(byte *)(lVar1 + 0x1a);
    }
    if ((bVar4 != 0) && (*(int *)(param_1 + 0x100) != *(int *)(param_1 + 0x104))) {
      bVar4 = *(byte *)(lVar2 + 0xaa + (long)*(int *)(param_1 + 0x100) * 0x98);
      bVar11 = bVar4 & 0x3f;
      if (bVar10 != 2) {
        bVar11 = bVar4;
      }
      if (bVar11 != 0) goto LAB_00ac8601;
    }
    *(undefined4 *)(lVar2 + 0x273c) = _DAT_03cc1304;
    *(undefined8 *)(lVar2 + 0x2734) = _DAT_03cc12fc;
    *(undefined8 *)(lVar2 + 0x272c) = _DAT_03cc12f4;
    *(undefined4 *)(lVar2 + 0x2728) = 0;
  }
  iVar13 = 0;
LAB_00ac8601:
  func_0x003a82a0(&DAT_03cc12f4,lVar2 + 0x272c,lVar1 + 0x50,iVar13);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== sub_00ac8850 | RVA 0xac8850 | file +0x1490 | ev_01d5e6e2eb6e5736b761f3ed58ef1c92e9405c4c76ce07869a631063a2b968ae =====
 * Body: [{"start":"0xac8850","end":"0xac8ac2"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_00ac8850(int *param_1,undefined8 *param_2,int *param_3,undefined4 *param_4)

{
  code *pcVar1;
  int iVar2;
  undefined8 uVar3;
  long lVar4;
  undefined8 *puVar5;
  undefined8 *puVar6;
  byte bVar7;
  undefined8 local_88 [10];
  long local_38;
  
  bVar7 = 0;
  local_38 = _DAT_0391c310;
  func_0x00347190();
  if (((((((_DAT_03cc1230 == param_1) || (_DAT_03cc1238 == param_1)) || (_DAT_03cc1240 == param_1))
        || (((_DAT_03cc1248 == param_1 || (_DAT_03cc1250 == param_1)) ||
            ((_DAT_03cc1258 == param_1 || ((_DAT_03cc1260 == param_1 || (_DAT_03cc1268 == param_1)))
             ))))) ||
       ((_DAT_03cc1270 == param_1 ||
        (((((_DAT_03cc1278 == param_1 || (_DAT_03cc1280 == param_1)) || (_DAT_03cc1288 == param_1))
          || ((_DAT_03cc1290 == param_1 || (_DAT_03cc1298 == param_1)))) ||
         (_DAT_03cc12a0 == param_1)))))) || (_DAT_03cc12a8 == param_1)) &&
     (((*param_1 == 0 && (_DAT_03cc1318 != (code *)0x0)) && (param_1[2] != 0)))) {
    iVar2 = func_0x00a601b0(0,param_1[1]);
    if (-1 < iVar2) {
      *param_3 = 0;
      *param_4 = 0;
      puVar5 = param_2;
      puVar6 = local_88;
      for (lVar4 = 10; lVar4 != 0; lVar4 = lVar4 + -1) {
        *puVar6 = *puVar5;
        puVar5 = puVar5 + (ulong)bVar7 * -2 + 1;
        puVar6 = puVar6 + (ulong)bVar7 * -2 + 1;
      }
      func_0x003471e0();
      pcVar1 = _DAT_03cc1318;
      if (1 < (-(long)_DAT_03cc1318 + 0x26f318U >> 3 | -(long)_DAT_03cc1318 << 0x3d)) {
        func_0x0044f8c0(0x2889ee0,_DAT_03cc1318);
      }
      (*pcVar1)(iVar2,local_88,param_3,param_4);
      func_0x00347190();
      if ((((((_DAT_03cc1230 == param_1) || (_DAT_03cc1238 == param_1)) ||
            (_DAT_03cc1240 == param_1)) ||
           (((((_DAT_03cc1248 == param_1 || (_DAT_03cc1250 == param_1)) ||
              ((_DAT_03cc1258 == param_1 ||
               ((_DAT_03cc1260 == param_1 || (_DAT_03cc1268 == param_1)))))) ||
             (_DAT_03cc1270 == param_1)) ||
            ((((_DAT_03cc1278 == param_1 || (_DAT_03cc1280 == param_1)) ||
              (_DAT_03cc1288 == param_1)) ||
             ((_DAT_03cc1290 == param_1 || (_DAT_03cc1298 == param_1)))))))) ||
          ((_DAT_03cc12a0 == param_1 || (_DAT_03cc12a8 == param_1)))) && (*param_3 == 1)) {
        uVar3 = *param_2;
        puVar5 = local_88;
        puVar6 = param_2;
        for (lVar4 = 10; lVar4 != 0; lVar4 = lVar4 + -1) {
          *puVar6 = *puVar5;
          puVar5 = puVar5 + (ulong)bVar7 * -2 + 1;
          puVar6 = puVar6 + (ulong)bVar7 * -2 + 1;
        }
        *param_2 = uVar3;
        *(undefined1 *)(param_2 + 2) = 1;
        *(undefined2 *)((long)param_2 + 0x12) = 0;
      }
      func_0x003471e0();
      uVar3 = 0;
      goto LAB_00ac8a90;
    }
  }
  func_0x003471e0();
  uVar3 = 0x803b0003;
LAB_00ac8a90:
  if (_DAT_0391c310 == local_38) {
    return uVar3;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* ===== sub_00ac8ad0 | RVA 0xac8ad0 | file +0x1710 | ev_5acf8451527b5c5aa7df72b7174b4ceb9fe268a89a4b1e924e7cd2543b9f55a4 =====
 * Body: [{"start":"0xac8ad0","end":"0xac8aff"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

undefined8 sub_00ac8ad0(uint param_1,undefined4 *param_2)

{
  if (param_2 != (undefined4 *)0x0) {
    if (0xf < param_1) {
      *param_2 = 1;
      return 0;
    }
    *param_2 = 0;
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== sub_00ac8b00 | RVA 0xac8b00 | file +0x1740 | ev_16b56d8951951fe9712711e85ff95b92d2dbb1df6280e6c3849e1c66e850c766 =====
 * Body: [{"start":"0xac8b00","end":"0xac8b15"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_00ac8b00(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== sub_00ac8b20 | RVA 0xac8b20 | file +0x1760 | ev_769d974c85eba10d0ea78e448602800551771fc7418e929f90333a261de8e274 =====
 * Body: [{"start":"0xac8b20","end":"0xac8b46"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_00ac8b20(undefined8 param_1,int param_2)

{
  if (param_2 != 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== sub_00ac8b50 | RVA 0xac8b50 | file +0x1790 | ev_b26b38cf259179c8ad4d0afe984327591f991a2fc4cd55b5be5c97b3013a154e =====
 * Body: [{"start":"0xac8b50","end":"0xac8ba0"},{"start":"0xac8bb0","end":"0xac8bee"},{"start":"0xac8bf0","end":"0xac8e10"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_00ac8b50(int *param_1,int param_2)

{
  int iVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  long lVar5;
  bool bVar6;
  long lVar7;
  bool bVar8;
  
  if (param_1 == (int *)0x0) {
    return 0x803b0001;
  }
  if (param_2 != 0) {
    return 0;
  }
  if (*param_1 != 0) {
    iVar1 = param_1[1];
    lVar5 = 0;
    do {
      lVar2 = *(long *)(&DAT_03cc1230 + lVar5 * 8);
      if (lVar2 != 0) {
        lVar3 = *(long *)(lVar2 + 0x198);
        bVar6 = true;
        lVar7 = 0;
        do {
          while (((lVar4 = *(long *)(lVar2 + 0x110 + lVar7 * 8), lVar4 == 0 ||
                  (*(long *)(lVar4 + 8) == 0)) || (*(int *)(*(long *)(lVar4 + 8) + 4) != iVar1))) {
            lVar7 = lVar7 + 1;
            if (lVar7 == 0x10) {
              if (bVar6) {
                *(undefined4 *)(lVar3 + 0x2748) = 1;
              }
              goto LAB_00ac8b80;
            }
          }
          *(undefined4 *)(lVar3 + 0x2748) = *(undefined4 *)(lVar4 + 0x38);
          bVar6 = false;
          bVar8 = lVar7 != 0xf;
          lVar7 = lVar7 + 1;
        } while (bVar8);
      }
LAB_00ac8b80:
      lVar5 = lVar5 + 1;
    } while (lVar5 != 0x10);
  }
  if ((_DAT_03cc12f0 == 0) && (0 < *param_1)) {
    _DAT_03cc12f0 = 1;
  }
  _DAT_03cc1304 = param_1[4];
  _DAT_03cc12f4 = *(undefined8 *)param_1;
  _DAT_03cc12fc = *(undefined8 *)(param_1 + 2);
  if (_DAT_03cc1230 != 0) {
    *(undefined4 *)(*(long *)(_DAT_03cc1230 + 0x198) + 0x2728) = 1;
  }
  if (_DAT_03cc1238 != 0) {
    *(undefined4 *)(*(long *)(_DAT_03cc1238 + 0x198) + 0x2728) = 1;
  }
  if (_DAT_03cc1240 != 0) {
    *(undefined4 *)(*(long *)(_DAT_03cc1240 + 0x198) + 0x2728) = 1;
  }
  if (_DAT_03cc1248 != 0) {
    *(undefined4 *)(*(long *)(_DAT_03cc1248 + 0x198) + 0x2728) = 1;
  }
  if (_DAT_03cc1250 != 0) {
    *(undefined4 *)(*(long *)(_DAT_03cc1250 + 0x198) + 0x2728) = 1;
  }
  if (_DAT_03cc1258 != 0) {
    *(undefined4 *)(*(long *)(_DAT_03cc1258 + 0x198) + 0x2728) = 1;
  }
  if (_DAT_03cc1260 != 0) {
    *(undefined4 *)(*(long *)(_DAT_03cc1260 + 0x198) + 0x2728) = 1;
  }
  if (_DAT_03cc1268 != 0) {
    *(undefined4 *)(*(long *)(_DAT_03cc1268 + 0x198) + 0x2728) = 1;
  }
  if (_DAT_03cc1270 != 0) {
    *(undefined4 *)(*(long *)(_DAT_03cc1270 + 0x198) + 0x2728) = 1;
  }
  if (_DAT_03cc1278 != 0) {
    *(undefined4 *)(*(long *)(_DAT_03cc1278 + 0x198) + 0x2728) = 1;
  }
  if (_DAT_03cc1280 != 0) {
    *(undefined4 *)(*(long *)(_DAT_03cc1280 + 0x198) + 0x2728) = 1;
  }
  if (_DAT_03cc1288 != 0) {
    *(undefined4 *)(*(long *)(_DAT_03cc1288 + 0x198) + 0x2728) = 1;
  }
  if (_DAT_03cc1290 != 0) {
    *(undefined4 *)(*(long *)(_DAT_03cc1290 + 0x198) + 0x2728) = 1;
  }
  if (_DAT_03cc1298 != 0) {
    *(undefined4 *)(*(long *)(_DAT_03cc1298 + 0x198) + 0x2728) = 1;
  }
  if (_DAT_03cc12a0 != 0) {
    *(undefined4 *)(*(long *)(_DAT_03cc12a0 + 0x198) + 0x2728) = 1;
  }
  if (_DAT_03cc12a8 != 0) {
    *(undefined4 *)(*(long *)(_DAT_03cc12a8 + 0x198) + 0x2728) = 1;
  }
  return 0;
}



/* ===== sub_00ac8e20 | RVA 0xac8e20 | file +0x1a60 | ev_52a929f50ad33481d69ceacde091399c4ca8b532e4c97c2969928024a363f478 =====
 * Body: [{"start":"0xac8e20","end":"0xac8e5a"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_00ac8e20(undefined4 param_1)

{
  int iVar1;
  
  iVar1 = func_0x003a8100(0x3cc12b0,8,param_1);
  if (iVar1 != 0) {
    func_0x003a8190(0x3cc12b0,8,param_1);
  }
  return 0;
}



/* ===== sub_00ac8e60 | RVA 0xac8e60 | file +0x1aa0 | ev_6d687fa2740b2db048f28f79af686ebf64c6adc3a208a7984de23193147eb947 =====
 * Body: [{"start":"0xac8e60","end":"0xac8e6e"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_00ac8e60(undefined8 param_1)

{
  _DAT_03cc1318 = param_1;
  return 0;
}



/* ===== sub_00ac8e70 | RVA 0xac8e70 | file +0x1ab0 | ev_e9b48835f910ac7364739d56333263ae8c401d780139afc9c7219d7cb62f5190 =====
 * Body: [{"start":"0xac8e70","end":"0xac8ea6"},{"start":"0xac8eb0","end":"0xac8f5d"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_00ac8e70(void)

{
  long lVar1;
  code *pcVar2;
  int iVar3;
  undefined8 uVar4;
  long lVar5;
  int local_90;
  int local_8c;
  undefined8 local_88 [10];
  long local_38;
  
  lVar5 = 0;
  local_38 = _DAT_0391c310;
  uVar4 = func_0x003472d0();
  do {
    lVar1 = *(long *)(&DAT_03cc1230 + lVar5);
    if (((lVar1 != 0) && (*(char *)(lVar1 + 0x18) == '\x03')) && (*(char *)(lVar1 + 0x38) == '\x02')
       ) {
      local_8c = 0;
      local_90 = 0;
      func_0x00258ff0(local_88,0x50);
      local_88[0] = uVar4;
      iVar3 = sub_00ac8850(lVar1,local_88,&local_8c,&local_90);
      if (((iVar3 == 0) && (local_8c == 1)) && (local_90 == 0)) {
        sub_00ac9610(lVar1,local_88);
      }
    }
    lVar5 = lVar5 + 8;
  } while (lVar5 != 0x80);
  if (_DAT_0391c310 == local_38) {
    return;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar2 = (code *)invalidInstructionException();
  (*pcVar2)();
}



/* ===== sub_00ac8f60 | RVA 0xac8f60 | file +0x1ba0 | ev_259637b49be7b18c092bdf610917fb1c795672e85b4f96638a1fc77f1d3a2a57 =====
 * Body: [{"start":"0xac8f60","end":"0xac8fdc"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_00ac8f60(long param_1)

{
  int iVar1;
  long lVar2;
  int iVar3;
  
  if (*(char *)(param_1 + 0x18) != '\0') {
    return 0;
  }
  iVar1 = *(int *)(param_1 + 0x104);
  if (iVar1 != *(int *)(param_1 + 0x108)) {
    iVar3 = 0x40;
    if (iVar1 != 0) {
      iVar3 = iVar1 + -1;
    }
    lVar2 = (long)iVar3 * 0x98 + *(long *)(param_1 + 0x198);
    if ((lVar2 != -0x90) && (*(char *)(lVar2 + 0xaa) != '\0')) {
      func_0x003a8400();
      goto LAB_00ac8fc5;
    }
  }
  *(undefined8 *)(param_1 + 400) = 0;
LAB_00ac8fc5:
  *(undefined4 *)(param_1 + 0x108) = 0;
  *(undefined8 *)(param_1 + 0x100) = 0;
  return 0;
}



/* ===== sub_00ac8fe0 | RVA 0xac8fe0 | file +0x1c20 | ev_27479052143067bc3cf2e337b8b9cf067ca36ab3c5b14cffc8d3d2a180c3523a =====
 * Body: [{"start":"0xac8fe0","end":"0xac91be"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

uint sub_00ac8fe0(undefined8 param_1,undefined8 *param_2,uint param_3,int param_4,
                 undefined4 *param_5)

{
  long lVar1;
  uint uVar2;
  long lVar3;
  undefined8 uVar4;
  long lVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  undefined8 *puVar9;
  undefined4 uVar10;
  undefined8 *puVar11;
  ulong uVar12;
  byte bVar13;
  
  bVar13 = 0;
  if (param_3 - 0x42 < 0xffffffbf || param_2 == (undefined8 *)0x0) {
    return 0x803b0001;
  }
  lVar3 = func_0x003a78d0(param_1,&DAT_03cc1230,0x10);
  uVar2 = 0;
  if (lVar3 == 0) {
    uVar8 = 0;
    uVar10 = 0;
    goto joined_r0x00ac9071;
  }
  if (param_4 == 0) {
    iVar7 = *(int *)(lVar3 + 0x104);
    iVar6 = *(int *)(lVar3 + 0x108);
  }
  else {
    iVar7 = *(int *)(lVar3 + 0x104);
    iVar6 = iVar7 + 1 + ((iVar7 + 1) / 0x41) * -0x41;
  }
  uVar10 = *(undefined4 *)(lVar3 + 4);
  uVar8 = iVar7 - iVar6;
  if (uVar8 == 0) {
    uVar8 = 0;
    goto joined_r0x00ac9071;
  }
  lVar1 = *(long *)(lVar3 + 0x198);
  uVar2 = uVar8 + 0x41;
  if (-1 < (int)uVar8) {
    uVar2 = uVar8;
  }
  if ((int)param_3 < (int)uVar2) {
    iVar6 = (int)((iVar6 - param_3) + uVar2) % 0x41;
    uVar2 = param_3;
LAB_00ac90e5:
    uVar12 = (ulong)uVar2;
    do {
      puVar9 = (undefined8 *)((long)iVar6 * 0x98 + lVar1 + 0x90);
      puVar11 = param_2;
      for (lVar5 = 10; lVar5 != 0; lVar5 = lVar5 + -1) {
        *puVar11 = *puVar9;
        puVar9 = puVar9 + (ulong)bVar13 * -2 + 1;
        puVar11 = puVar11 + (ulong)bVar13 * -2 + 1;
      }
      uVar4 = func_0x003473c0(0,*param_2);
      *param_2 = uVar4;
      *(undefined4 *)(param_2 + 4) = *(undefined4 *)(lVar1 + 0x2740);
      *(undefined4 *)((long)param_2 + 0x24) = *(undefined4 *)(lVar1 + 0x2744);
      param_2 = param_2 + 10;
      uVar12 = uVar12 - 1;
      iVar6 = iVar6 + 1 + ((iVar6 + 1) / 0x41) * -0x41;
    } while (uVar12 != 0);
  }
  else if (0 < (int)uVar2) goto LAB_00ac90e5;
  if (param_4 == 0) {
    *(undefined4 *)(lVar3 + 0x108) = *(undefined4 *)(lVar3 + 0x104);
  }
  uVar8 = (int)uVar2 >> 0x1f & uVar2;
joined_r0x00ac9071:
  if (param_5 != (undefined4 *)0x0) {
    *param_5 = uVar10;
  }
  if ((int)uVar8 < 0) {
    uVar2 = uVar8;
  }
  return uVar2;
}



/* ===== sub_00ac91c0 | RVA 0xac91c0 | file +0x1e00 | ev_895a03664f7619ffc6ee5222dab30342b0ce3de77ca321ce13a8b190a1ce488d =====
 * Body: [{"start":"0xac91c0","end":"0xac9383"},{"start":"0xac9390","end":"0xac94b6"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong sub_00ac91c0(undefined8 param_1,undefined4 param_2,undefined8 *param_3,uint param_4,
                  uint param_5)

{
  undefined1 uVar1;
  undefined4 uVar2;
  long lVar3;
  long lVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  long lVar9;
  long lVar10;
  undefined8 uVar11;
  long lVar12;
  ulong uVar13;
  uint uVar14;
  undefined8 *puVar15;
  undefined8 *puVar16;
  ulong uVar17;
  long lVar18;
  undefined8 *puVar19;
  long lVar20;
  undefined8 *puVar21;
  bool bVar22;
  byte bVar23;
  long local_70;
  
  bVar23 = 0;
  if (param_4 - 0x42 < 0xffffffbf || param_3 == (undefined8 *)0x0) {
    return 0x803b0001;
  }
  lVar9 = func_0x003a7890(param_1,&DAT_03cc1230,0x10);
  if ((lVar9 == 0) || (lVar10 = func_0x003a7f90(lVar9,param_2), lVar10 == 0)) {
    return 0;
  }
  lVar3 = *(long *)(lVar10 + 8);
  if (lVar3 == 0) {
    return 0x803b0001;
  }
  lVar4 = *(long *)(lVar9 + 0x198);
  iVar6 = func_0x003a8100(0x3cc12b0,8,*(undefined4 *)(lVar3 + 4));
  func_0x003471e0();
  local_70 = *(long *)(lVar3 + 0x18);
  if (local_70 == -1) {
    local_70 = func_0x00347320(*(undefined4 *)(lVar3 + 4));
    *(long *)(lVar3 + 0x18) = local_70;
  }
  func_0x00347190();
  iVar7 = func_0x003a79c0(lVar9,&DAT_03cc1230,0x10);
  if (iVar7 == 0) {
    return 0;
  }
  bVar22 = _DAT_03cc12f0 == 0;
  iVar8 = *(int *)(lVar9 + 0x104);
  iVar7 = *(int *)(lVar10 + 0x18 + (ulong)param_5 * 4);
  uVar14 = iVar8 - iVar7;
  if (uVar14 == 0) {
    return 0;
  }
  uVar5 = uVar14 + 0x41;
  if (-1 < (int)uVar14) {
    uVar5 = uVar14;
  }
  uVar17 = (ulong)uVar5;
  if ((int)param_4 < (int)uVar5) {
    uVar17 = (ulong)param_4;
    iVar7 = (int)((iVar7 - param_4) + uVar5) % 0x41;
  }
  else if ((int)uVar5 < 1) goto LAB_00ac94ad;
  lVar18 = 0;
  uVar13 = uVar17;
  puVar21 = param_3;
  do {
    if ((bVar22 || param_5 == 1) || iVar6 != 0) {
      puVar15 = (undefined8 *)((long)iVar7 * 0x98 + lVar4 + 0x90);
      puVar16 = puVar21;
      for (lVar12 = 10; puVar19 = param_3 + lVar18 * 10, lVar12 != 0; lVar12 = lVar12 + -1) {
        *puVar16 = *puVar15;
        puVar15 = puVar15 + (ulong)bVar23 * -2 + 1;
        puVar16 = puVar16 + (ulong)bVar23 * -2 + 1;
      }
    }
    else {
      lVar20 = (long)iVar7 * 0x98;
      iVar8 = func_0x003a8240(lVar4 + 0xe0 + lVar20,*(undefined4 *)(lVar3 + 4));
      puVar15 = (undefined8 *)(lVar20 + lVar4 + 0x90);
      puVar16 = puVar21;
      for (lVar12 = 10; lVar12 != 0; lVar12 = lVar12 + -1) {
        *puVar16 = *puVar15;
        puVar15 = puVar15 + (ulong)bVar23 * -2 + 1;
        puVar16 = puVar16 + (ulong)bVar23 * -2 + 1;
      }
      puVar19 = puVar21;
      if (iVar8 == 0) {
        uVar1 = *(undefined1 *)(puVar21 + 2);
        uVar2 = *(undefined4 *)((long)puVar21 + 0x12);
        uVar11 = *puVar21;
        func_0x00258ff0(puVar21,0x50);
        *puVar21 = uVar11;
        *(undefined1 *)(puVar21 + 2) = uVar1;
        *(undefined4 *)((long)puVar21 + 0x12) = uVar2;
      }
      else if (iVar8 != 2) goto LAB_00ac93b3;
      *(undefined1 *)((long)puVar21 + 0x11) = 1;
    }
LAB_00ac93b3:
    uVar11 = func_0x003473c0(local_70,*puVar19);
    *puVar19 = uVar11;
    lVar18 = lVar18 + 1;
    *(undefined4 *)(puVar21 + 4) = *(undefined4 *)(lVar4 + 0x2740);
    *(undefined4 *)((long)puVar21 + 0x24) = *(undefined4 *)(lVar4 + 0x2744);
    puVar21 = puVar21 + 10;
    iVar7 = (iVar7 + 1) % 0x41;
    uVar13 = uVar13 - 1;
  } while (uVar13 != 0);
  iVar8 = *(int *)(lVar9 + 0x104);
LAB_00ac94ad:
  *(int *)(lVar10 + 0x18 + (ulong)param_5 * 4) = iVar8;
  return uVar17;
}



/* ===== sub_00ac94c0 | RVA 0xac94c0 | file +0x2100 | ev_57aab943eb75a8a5f330ff11eee0bd8592925cc1cfded16f0fd4876e56e91693 =====
 * Body: [{"start":"0xac94c0","end":"0xac94f3"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_00ac94c0(undefined8 *param_1)

{
  undefined8 uVar1;
  
  if (param_1 != (undefined8 *)0x0) {
    uVar1 = func_0x003472d0();
    uVar1 = func_0x003473b0(uVar1,_DAT_03cc1310);
    *param_1 = uVar1;
    return 0;
  }
  return 0x803b0001;
}



/* ===== sub_00ac9500 | RVA 0xac9500 | file +0x2140 | ev_2940eedfa0328d2a38f7fe539d34ab3b32dc34d61a9b8d55934cfb08226912ed =====
 * Body: [{"start":"0xac9500","end":"0xac9550"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_00ac9500(undefined8 param_1,uint param_2)

{
  undefined8 uVar1;
  long lVar2;
  
  uVar1 = 0x803b0001;
  if (param_2 < 2) {
    lVar2 = func_0x003a7890(param_1,&DAT_03cc1230,0x10);
    if (lVar2 == 0) {
      uVar1 = 0x803b0003;
    }
    else if (*(long *)(lVar2 + 0x198) == 0) {
      uVar1 = 0x803b0002;
    }
    else {
      *(uint *)(*(long *)(lVar2 + 0x198) + 0x2740) = param_2;
      uVar1 = 0;
    }
  }
  return uVar1;
}



/* ===== sub_00ac9560 | RVA 0xac9560 | file +0x21a0 | ev_57ecb7b18c1a71d44473141e27e7e8d81f18e4c5190dace21be6a0ea048bd452 =====
 * Body: [{"start":"0xac9560","end":"0xac95b0"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_00ac9560(undefined8 param_1,uint param_2)

{
  undefined8 uVar1;
  long lVar2;
  
  uVar1 = 0x803b0001;
  if (param_2 < 9) {
    lVar2 = func_0x003a7890(param_1,&DAT_03cc1230,0x10);
    if (lVar2 == 0) {
      uVar1 = 0x803b0003;
    }
    else if (*(long *)(lVar2 + 0x198) == 0) {
      uVar1 = 0x803b0002;
    }
    else {
      *(uint *)(*(long *)(lVar2 + 0x198) + 0x2744) = param_2;
      uVar1 = 0;
    }
  }
  return uVar1;
}



/* ===== sub_00ac95c0 | RVA 0xac95c0 | file +0x2200 | ev_c4f2217cff7894c5fd22bb4c2ea534e67a70d6711374e1716f8392507dbae36a =====
 * Body: [{"start":"0xac95c0","end":"0xac960f"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted.","Ghidra Listing reports a terminal call at 0xac95fa to 0xac9610 sub_00ac9610 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

undefined8 sub_00ac95c0(undefined8 param_1,undefined8 *param_2)

{
  long lVar1;
  undefined8 uVar2;
  
  lVar1 = func_0x003a7890(param_1,&DAT_03cc1230,0x10);
  if (lVar1 == 0) {
    uVar2 = 0x803b0003;
  }
  else {
    if (param_2 != (undefined8 *)0x0) {
      uVar2 = func_0x003472d0();
      *param_2 = uVar2;
      uVar2 = sub_00ac9610(lVar1,param_2);
      return uVar2;
    }
    uVar2 = 0x803b0001;
  }
  return uVar2;
}



/* ===== sub_00ac9610 | RVA 0xac9610 | file +0x2250 | ev_5542cc526eeaf7c248b604875016f7c1d306fda520cee4977613dc8079c1a518 =====
 * Body: [{"start":"0xac9610","end":"0xac97f0"},{"start":"0xac9800","end":"0xac9833"},{"start":"0xac9840","end":"0xac98fc"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_00ac9610(long param_1,undefined8 *param_2)

{
  undefined8 *puVar1;
  uint uVar2;
  byte bVar3;
  byte bVar4;
  char cVar5;
  int iVar6;
  undefined8 uVar7;
  long lVar8;
  ushort uVar9;
  long lVar10;
  undefined8 *puVar11;
  long lVar12;
  bool bVar13;
  byte bVar14;
  
  bVar14 = 0;
  uVar7 = func_0x00347190();
  if ((int)uVar7 != 0) {
    return uVar7;
  }
  lVar8 = *(long *)(param_1 + 0x198);
  if (lVar8 == 0) {
    uVar7 = 0x803b0003;
    goto LAB_00ac98e7;
  }
  lVar12 = (long)*(int *)(param_1 + 0x104) * 0x98;
  puVar1 = (undefined8 *)(lVar8 + 0x90 + lVar12);
  func_0x00258ff0(puVar1,0x98);
  bVar13 = true;
  puVar11 = puVar1;
  for (lVar10 = 10; lVar10 != 0; lVar10 = lVar10 + -1) {
    *puVar11 = *param_2;
    param_2 = param_2 + (ulong)bVar14 * -2 + 1;
    puVar11 = puVar11 + (ulong)bVar14 * -2 + 1;
  }
  if (*(char *)(lVar8 + 0xaa + lVar12) == '\0') {
    uVar9 = -*(ushort *)((long)puVar1 + 0x16);
    if ((short)uVar9 < 0) {
      uVar9 = *(ushort *)((long)puVar1 + 0x16);
    }
    if ((uVar9 < 0x1e) && (*(char *)((long)puVar1 + 0x1b) == '\0')) {
      bVar13 = *(char *)((long)puVar1 + 0x1c) != '\0';
    }
  }
  func_0x003a8440(param_1,bVar13);
  if ((bVar13 != false) && (*(int *)(param_1 + 8) != 0)) {
    _DAT_03cc1310 = *puVar1;
  }
  iVar6 = *(int *)(lVar8 + 0x2728);
  if (iVar6 == 0) {
LAB_00ac9761:
    iVar6 = 0;
  }
  else {
    bVar3 = *(byte *)(param_1 + 0x18) & 0xfe;
    bVar14 = *(byte *)((long)puVar1 + 0x1a) & 0x3f;
    if (bVar3 != 2) {
      bVar14 = *(byte *)((long)puVar1 + 0x1a);
    }
    if ((bVar14 == 0) || (*(int *)(param_1 + 0x100) == *(int *)(param_1 + 0x104))) {
LAB_00ac972d:
      *(undefined4 *)(lVar8 + 0x273c) = _DAT_03cc1304;
      *(undefined8 *)(lVar8 + 0x2734) = _DAT_03cc12fc;
      *(undefined8 *)(lVar8 + 0x272c) = _DAT_03cc12f4;
      *(undefined4 *)(lVar8 + 0x2728) = 0;
      goto LAB_00ac9761;
    }
    bVar14 = *(byte *)(lVar8 + 0xaa + (long)*(int *)(param_1 + 0x100) * 0x98);
    bVar4 = bVar14 & 0x3f;
    if (bVar3 != 2) {
      bVar4 = bVar14;
    }
    if (bVar4 == 0) goto LAB_00ac972d;
  }
  func_0x003a82a0(&DAT_03cc12f4,lVar8 + 0x272c,puVar1 + 10,iVar6);
  iVar6 = *(int *)(param_1 + 0x104);
  *(int *)(param_1 + 0x100) = iVar6;
  iVar6 = iVar6 + 1 + ((iVar6 + 1) / 0x41) * -0x41;
  *(int *)(param_1 + 0x104) = iVar6;
  if (iVar6 == *(int *)(param_1 + 0x108)) {
    cVar5 = (char)iVar6 + '\x01';
    uVar2 = cVar5 * 0x7f;
    *(int *)(param_1 + 0x108) =
         (int)(char)(cVar5 + ((char)((uVar2 & 0xffff) >> 0xf) + (char)(uVar2 >> 0xd)) * -0x41);
  }
  lVar8 = 0;
  do {
    lVar10 = *(long *)(param_1 + 0x110 + lVar8 * 8);
    if (lVar10 != 0) {
      iVar6 = *(int *)(param_1 + 0x104);
      if (iVar6 == *(int *)(lVar10 + 0x18)) {
        *(int *)(lVar10 + 0x18) = (iVar6 + 1) % 0x41;
        iVar6 = *(int *)(param_1 + 0x104);
        lVar10 = *(long *)(param_1 + 0x110 + lVar8 * 8);
        if (iVar6 == *(int *)(lVar10 + 0x1c)) goto LAB_00ac9878;
LAB_00ac982a:
        if (iVar6 != *(int *)(lVar10 + 0x20)) goto LAB_00ac9800;
      }
      else {
        if (iVar6 != *(int *)(lVar10 + 0x1c)) goto LAB_00ac982a;
LAB_00ac9878:
        *(int *)(lVar10 + 0x1c) = (iVar6 + 1) % 0x41;
        iVar6 = *(int *)(param_1 + 0x104);
        lVar10 = *(long *)(param_1 + 0x110 + lVar8 * 8);
        if (iVar6 != *(int *)(lVar10 + 0x20)) goto LAB_00ac9800;
      }
      *(int *)(lVar10 + 0x20) = (iVar6 + 1) % 0x41;
    }
LAB_00ac9800:
    lVar8 = lVar8 + 1;
  } while (lVar8 != 0x10);
  uVar7 = 0;
LAB_00ac98e7:
  func_0x003471e0();
  return uVar7;
}



/* ===== sub_00ac9900 | RVA 0xac9900 | file +0x2540 | ev_fff32f8e01a7af1844a28f645372bb90c7158b9ef5829624d8529d12e56a29de =====
 * Body: [{"start":"0xac9900","end":"0xac995e"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_00ac9900(undefined8 param_1,undefined4 param_2,int param_3,int param_4)

{
  long lVar1;
  undefined8 uVar2;
  
  lVar1 = func_0x003a7890(param_1,&DAT_03cc1230,0x10);
  uVar2 = 0x803b0003;
  if (((lVar1 != 0) && (lVar1 = *(long *)(lVar1 + 0x198), lVar1 != 0)) &&
     ((param_4 == 0 || (uVar2 = 0, param_3 == *(int *)(lVar1 + 0x2730))))) {
    uVar2 = 0;
    *(undefined4 *)(lVar1 + 0x2748) = param_2;
  }
  return uVar2;
}



/* ===== sub_00ac9960 | RVA 0xac9960 | file +0x25a0 | ev_0a512292ef6af70fcbf67db29a7c005d715f8ef26d01bbb7edd923bdf1eccb37 =====
 * Body: [{"start":"0xac9960","end":"0xac99a8"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_00ac9960(undefined8 param_1,undefined4 *param_2)

{
  long lVar1;
  undefined8 uVar2;
  
  lVar1 = func_0x003a7890(param_1,&DAT_03cc1230,0x10);
  uVar2 = 0x803b0003;
  if (((lVar1 != 0) && (*(long *)(lVar1 + 0x198) != 0)) && (uVar2 = 0, param_2 != (undefined4 *)0x0)
     ) {
    *param_2 = *(undefined4 *)(*(long *)(lVar1 + 0x198) + 0x2748);
  }
  return uVar2;
}



/* ===== sub_00ac99b0 | RVA 0xac99b0 | file +0x25f0 | ev_31fa27636deb081b5430bc3e5070533d0f595f3b5cba173874831d6e7138b82b =====
 * Body: [{"start":"0xac99b0","end":"0xac99cb"},{"start":"0xac99d0","end":"0xac9a0d"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_00ac99b0(int *param_1)

{
  ulong uVar1;
  long *plVar2;
  int iVar3;
  
  if (param_1 == (int *)0x0) {
    return 0x803b0001;
  }
  plVar2 = (long *)&DAT_03cc1230;
  *param_1 = 0;
  uVar1 = 0;
  iVar3 = 0;
  do {
    if (*plVar2 == 0) {
      if (0xe < uVar1) {
        return 0;
      }
    }
    else {
      param_1[(long)iVar3 + 1] = *(int *)(*plVar2 + 4);
      iVar3 = *param_1 + 1;
      *param_1 = iVar3;
      if ((0xe < uVar1) || (iVar3 == 0x10)) {
        return 0;
      }
    }
    uVar1 = uVar1 + 1;
    plVar2 = plVar2 + 1;
  } while( true );
}



/* ===== sub_00ac9a10 | RVA 0xac9a10 | file +0x2650 | ev_026ea072450e38763f0d28e3f8d990d945ec9e82ecaf5f9b9758f329214430da =====
 * Body: [{"start":"0xac9a10","end":"0xac9a31"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

bool sub_00ac9a10(long *param_1)

{
  long lVar1;
  
  lVar1 = func_0x006c9820();
  *param_1 = lVar1;
  return lVar1 != 0;
}



/* ===== sub_00ac9a40 | RVA 0xac9a40 | file +0x2680 | ev_25ffd95fb6db6a44f4a252ec0f474098996ff9c0e63a533f0a6dd5d8ab509ceb =====
 * Body: [{"start":"0xac9a40","end":"0xac9a63"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_00ac9a40(long *param_1)

{
  if (*param_1 != 0) {
    func_0x006c9750();
    *param_1 = 0;
  }
  return;
}



/* ===== sub_00ac9a70 | RVA 0xac9a70 | file +0x26b0 | ev_6cef54cdbddeb92ac36974ce7254c29846931eb1b4689a3ac0060e99df857d82 =====
 * Body: [{"start":"0xac9a70","end":"0xac9ad9"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_00ac9a70(long *param_1,undefined8 param_2,undefined4 param_3)

{
  long lVar1;
  undefined8 uVar2;
  
  lVar1 = *param_1;
  if (lVar1 == 0) {
    lVar1 = func_0x006c9820();
    *param_1 = lVar1;
    if (lVar1 == 0) {
      return 0;
    }
  }
  lVar1 = func_0x006c9c50(param_2,param_3,lVar1);
  uVar2 = 1;
  if ((lVar1 == 0) && (uVar2 = 0, *param_1 != 0)) {
    func_0x006c9750();
    uVar2 = 0;
    *param_1 = 0;
  }
  return uVar2;
}



/* ===== sub_00ac9ae0 | RVA 0xac9ae0 | file +0x2720 | ev_03b2303297364c1f2a9a9d4fc67dd495cb1493d5b9136f5e778ef450e47c8ed5 =====
 * Body: [{"start":"0xac9ae0","end":"0xac9b4c"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

int sub_00ac9ae0(long *param_1,undefined1 *param_2)

{
  long lVar1;
  int iVar2;
  int iVar3;
  ulong uVar4;
  
  lVar1 = *param_1;
  if (lVar1 == 0) {
    iVar2 = -1;
  }
  else {
    uVar4 = func_0x006c9660(lVar1);
    if (param_2 == (undefined1 *)0x0) {
      iVar3 = func_0x006c9660(lVar1);
      iVar2 = iVar3 + 0xe;
      if (-1 < iVar3 + 7) {
        iVar2 = iVar3 + 7;
      }
      iVar2 = iVar2 >> 3;
    }
    else {
      if ((uVar4 & 7) == 0) {
        *param_2 = 0;
        param_2 = param_2 + 1;
      }
      iVar2 = func_0x006c9e30(lVar1,param_2);
    }
    iVar2 = iVar2 + (uint)((uVar4 & 7) == 0);
  }
  return iVar2;
}



/* ===== sub_00ac9b50 | RVA 0xac9b50 | file +0x2790 | ev_82454ddcb2cdce5cd98139137399af07076c850f453b4a36e0b2dffed3e0949a =====
 * Body: [{"start":"0xac9b50","end":"0xac9d1a"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

int sub_00ac9b50(long param_1,long param_2)

{
  long lVar1;
  undefined4 uVar2;
  int iVar3;
  undefined8 uVar4;
  
  uVar2 = *(undefined4 *)(param_2 + 0xbc);
  *(undefined4 *)(param_1 + 0x90) = uVar2;
  func_0x00b7b1c0(0x14,0xa4);
  lVar1 = param_1 + 0x10;
  iVar3 = func_0x00befdd0(param_2,lVar1,(long)*(int *)(*(long *)(param_1 + 8) + 0x20a3c),
                          *(undefined4 *)(param_1 + 0x88),0x10);
  func_0x00b7b1e0(0x14,0xa6);
  if (iVar3 != 0) {
    return iVar3;
  }
  if (*(int *)(param_1 + 0x7c) == 0) {
    if (*(char *)(param_1 + 0x80) == '\x01') {
      func_0x00b7b1c0(0x14,0xb7);
      iVar3 = func_0x00befdd0(param_2,param_1 + 0x50,
                              (long)*(int *)(*(long *)(param_1 + 8) + 0x20a48),
                              *(undefined4 *)(param_1 + 0x88),0x10);
      func_0x00b7b1e0(0x14,0xb9);
      if (iVar3 != 0) {
        func_0x00b7b1c0(0x14,0xbb);
        func_0x00befbc0(uVar2,lVar1,(long)*(int *)(*(long *)(param_1 + 8) + 0x20a3c));
        uVar4 = 0xbd;
        goto LAB_00ac9cd2;
      }
    }
  }
  else {
    func_0x00b7b1c0(0x14,0xad);
    iVar3 = func_0x00befdd0(param_2,param_1 + 0x30,(long)*(int *)(*(long *)(param_1 + 8) + 0x20a3c),
                            *(undefined4 *)(param_1 + 0x88),0x10);
    func_0x00b7b1e0(0x14,0xaf);
    if (iVar3 != 0) {
      func_0x00b7b1c0(0x14,0xb1);
      func_0x00befbc0(uVar2,lVar1,(long)*(int *)(*(long *)(param_1 + 8) + 0x20a3c));
      uVar4 = 0xb3;
LAB_00ac9cd2:
      func_0x00b7b1e0(0x14,uVar4);
      return iVar3;
    }
  }
  if (*(char *)(*(long *)(param_1 + 8) + 0x29a) != '\0') {
    *(ulong *)(param_1 + 0x58) =
         (ulong)(uint)(*(int *)(*(long *)(param_1 + 8) + 0x2b8) * 2) / 3 + *(long *)(param_1 + 0x18)
    ;
  }
  return 0;
}



/* ===== sub_00ac9d20 | RVA 0xac9d20 | file +0x2960 | ev_8c271a40ab585aec1036328e887d84052d088bc4cfc9a1221c136d9d47c1f6c5 =====
 * Body: [{"start":"0xac9d20","end":"0xac9d34"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_00ac9d20(long param_1)

{
  if (*(uint *)(param_1 + 0x84) < 0x10) {
    *(int *)(param_1 + 0x9c) = *(int *)(param_1 + 0x9c) + 1;
  }
  return;
}



/* ===== sub_00ac9d40 | RVA 0xac9d40 | file +0x2980 | ev_d56671f699c5a063d45625ea0445130ba72c5184cd9ab563c8edc4e72cb6ad8e =====
 * Body: [{"start":"0xac9d40","end":"0xac9d54"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_00ac9d40(long param_1)

{
  if (*(uint *)(param_1 + 0x84) < 0x10) {
    *(int *)(param_1 + 0x9c) = *(int *)(param_1 + 0x9c) + -1;
  }
  return;
}



/* ===== sub_00ac9d60 | RVA 0xac9d60 | file +0x29a0 | ev_ab7ce426adaa9fd4dbaaeaf10f884f951493fc9deee4c039c831c764d0365ddd =====
 * Body: [{"start":"0xac9d60","end":"0xac9d74"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_00ac9d60(long param_1)

{
  if (*(uint *)(param_1 + 0x84) < 0x10) {
    *(int *)(param_1 + 0xa0) = *(int *)(param_1 + 0xa0) + 1;
  }
  return;
}



/* ===== sub_00ac9d80 | RVA 0xac9d80 | file +0x29c0 | ev_c5e557644f42014faf0b44077062b036027849329e07037e5e72f8565876eece =====
 * Body: [{"start":"0xac9d80","end":"0xac9d90"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_00ac9d80(long param_1)

{
  **(undefined8 **)(param_1 + 0x70) = 0;
  return;
}



/* ===== sub_00ac9da0 | RVA 0xac9da0 | file +0x29e0 | ev_4f6e33e48dc41af7dbc071520f6c3a7a7bd52ea1bac4d0c18f2eb6cf2e432ab3 =====
 * Body: [{"start":"0xac9da0","end":"0xac9db9"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_00ac9da0(long param_1)

{
  if (*(uint *)(param_1 + 0x84) < 0x10) {
    **(undefined8 **)(param_1 + 0x70) = 1;
  }
  return;
}



/* ===== sub_00ac9dc0 | RVA 0xac9dc0 | file +0x2a00 | ev_0b459651d1efef894864c8408a5eb2cb289db2bc53dafa773babf0880a5f609b =====
 * Body: [{"start":"0xac9dc0","end":"0xac9de2"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_00ac9dc0(long param_1)

{
  int *piVar1;
  
  if (*(uint *)(param_1 + 0x84) < 0x10) {
    piVar1 = (int *)(param_1 + 0xa0);
    *piVar1 = *piVar1 + -1;
    if (*piVar1 == 0) {
      **(undefined8 **)(param_1 + 0x70) = 0;
      return;
    }
  }
  return;
}



/* ===== sub_00ac9df0 | RVA 0xac9df0 | file +0x2a30 | ev_e41c68899d89f2a2dba269b21599b6a41eabff436ee90953514a6b2eb86f225c =====
 * Body: [{"start":"0xac9df0","end":"0xac9dfb"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_00ac9df0(long param_1,undefined4 param_2)

{
  *(undefined4 *)(param_1 + 0x94) = param_2;
  return;
}



/* ===== sub_00ac9e00 | RVA 0xac9e00 | file +0x2a40 | ev_ac8ec6b95991e1430c53fa73d59042005ba3db050572f5e0f795320ace88e92a =====
 * Body: [{"start":"0xac9e00","end":"0xac9e0f"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

bool sub_00ac9e00(long param_1)

{
  return *(int *)(param_1 + 0x94) == 1;
}



/* ===== sub_00ac9e10 | RVA 0xac9e10 | file +0x2a50 | ev_b31dcb7be3a1d8bfeb05c6e79d175f606e007e8d2c359a5e78db40ca1b52339f =====
 * Body: [{"start":"0xac9e10","end":"0xac9ff3"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Possible PIC construction at 0x00ac9e8b: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00ac9f0a: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x00ac9e90) */
/* WARNING: Removing unreachable block (ram,0x00ac9f0f) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_00ac9e10(void)

{
  code *pcVar1;
  int iVar2;
  long lVar3;
  undefined8 uVar4;
  undefined8 local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  lVar3 = func_0x00bf03a0(0x4c000,0x14,0x130);
  if (lVar3 == 0) {
    if (_DAT_0391c310 != local_38) goto LAB_00ac9fed;
  }
  else {
    uVar4 = func_0x008de330(lVar3);
    iVar2 = func_0x009e9690(uVar4,0x4c000,0x4000,0x160,&local_40);
    if ((iVar2 == 0) && (iVar2 = func_0x00cb66e0(2,uVar4,0x4c000), iVar2 == 0)) {
      _DAT_028aab08 = 0xffffffff;
      _DAT_02889f48 = 0x288a0d0;
      _DAT_02889f50 = local_40;
      _DAT_02889fc4 = 0xffffffff;
      _DAT_02889fd8 = 0xffffffff;
      _DAT_02889f58 = uVar4;
      func_0x002590b0(0x28aab38,0x288a0d0,0x20a68);
      func_0x002590b0(0x288a008,0x2889f40,200);
      _DAT_0288a010 = 0x28aab38;
      _DAT_0288a020 = uVar4;
      _DAT_0288a018 = local_40;
      _DAT_0288a08c = 0xfffffffe;
      _DAT_028cb570 = 0xfffffffe;
      _DAT_0288a0a0 = 0xfffffffe;
      if (_DAT_0391c310 == local_38) {
        return;
      }
LAB_00ac9fed:
      func_0x006fd6b0();
                    /* WARNING: Does not return */
      pcVar1 = (code *)invalidInstructionException();
      (*pcVar1)();
    }
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== sub_00aca000 | RVA 0xaca000 | file +0x2c40 | ev_d5a1c3a6631912af10ec3915e5aae98bf31bbb09126e4e3625e8d477aea5a894 =====
 * Body: [{"start":"0xaca000","end":"0xaca0f3"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8
sub_00aca000(undefined8 *param_1,long param_2,undefined8 param_3,long param_4,undefined4 param_5,
            undefined4 param_6,long param_7)

{
  long lVar1;
  
  if ((*(int *)((long)param_1 + 0x94) == 0) && (*(int *)(param_2 + 0x20a54) == 1)) {
    func_0x00258ff0(param_1,200);
    *(undefined4 *)((long)param_1 + 0x2c) = 0;
    *(undefined4 *)((long)param_1 + 0x4c) = 1;
    *(undefined4 *)((long)param_1 + 0x6c) = 2;
    *param_1 = param_3;
    *(undefined4 *)((long)param_1 + 0x84) = param_5;
    param_1[1] = param_2;
    *(undefined4 *)(param_1 + 0x13) = param_6;
    *(undefined4 *)(param_1 + 0x11) = *(undefined4 *)(*(long *)(param_4 + 0x200) + 0x1ec);
    *(uint *)((long)param_1 + 0x7c) = (uint)(*(long *)(param_7 + 0x18) != 0);
    param_1[2] = *(undefined8 *)(param_7 + 0x10);
    if (*(int *)(param_2 + 0x20a44) == 0) {
      if (*(int *)(param_2 + 0x20a4c) != 0) {
        param_1[6] = *(undefined8 *)(param_7 + 0x18);
      }
    }
    else {
      param_1[10] = *(undefined8 *)(param_7 + 0x20);
      *(undefined1 *)(param_1 + 0x10) = 1;
    }
    lVar1 = _DAT_03cc1320 + 1;
    param_1[0x15] = _DAT_03cc1320;
    _DAT_03cc1320 = lVar1;
    return 0;
  }
  return 0x16;
}



/* ===== sub_00aca100 | RVA 0xaca100 | file +0x2d40 | ev_f59479483cf1859fa41617462d03924e2faa26bae0392bff92e77abbe4ccf43e =====
 * Body: [{"start":"0xaca100","end":"0xaca125"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined1 sub_00aca100(long param_1)

{
  undefined1 uVar1;
  
  uVar1 = 2;
  if ((*(ulong *)(param_1 + 0x2c8) & 0x200) == 0) {
    uVar1 = (~(uint)*(ulong *)(param_1 + 0x2c8) & 7) == 0;
  }
  return uVar1;
}



/* ===== sub_00aca130 | RVA 0xaca130 | file +0x2d70 | ev_dfc6aa8a8dc75653ee4940199d7062a0f62d114fdf1f175aa0134d6c5e0979fe =====
 * Body: [{"start":"0xaca130","end":"0xaca3bd"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_00aca130(uint param_1,long param_2,long param_3)

{
  byte bVar1;
  byte bVar2;
  ushort uVar3;
  uint uVar4;
  uint uVar5;
  undefined8 uVar6;
  int iVar7;
  uint uVar8;
  
  if (((3 < param_1) || (1 < *(byte *)(param_3 + 9))) ||
     (bVar1 = *(byte *)(param_3 + 10), 1 < bVar1)) {
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  bVar2 = *(byte *)(param_3 + 0xb);
  if (((((bVar2 < 2) && (*(uint *)(param_3 + 0x14) < 0x2001)) &&
       ((uVar4 = *(uint *)(param_3 + 0x18), uVar4 < 0x2001 &&
        ((uVar5 = *(uint *)(param_3 + 0x1c), uVar5 < 0x2001 && (*(char *)(param_3 + 0x21) == '\0')))
        ))) && (*(char *)(param_3 + 0x20) == '\0')) && (bVar1 == 0 || bVar2 == 0)) {
    iVar7 = *(int *)(param_3 + 0x2c);
    if (bVar2 == 0) {
      if (iVar7 != 0) {
        halt_baddata();
      }
      if (*(long *)(param_3 + 0x38) != 0) {
        halt_baddata();
      }
    }
    else if (iVar7 < 0x208) {
      if ((iVar7 != 0x24) && (iVar7 != 0x48)) {
        halt_baddata();
      }
    }
    else if ((iVar7 != 0x208) && (iVar7 != 0x100024)) {
      halt_baddata();
    }
    if ((uVar4 <= *(uint *)(param_3 + 0x14) && 0x13f < uVar4) &&
        (*(byte *)(param_3 + 9) == 0 || bVar1 == 0)) {
      uVar6 = *(undefined8 *)(param_3 + 0x30);
      iVar7 = func_0x00aca460(uVar6);
      if (iVar7 == 0) {
        uVar4 = (uint)((ulong)uVar6 >> 0x20);
        uVar8 = (uVar4 >> 8 & 0xff) - 0xc;
        if (uVar8 < 7) {
          if ((int)uVar5 < 0x438) {
            if (((uVar5 != 0x168) && (uVar5 != 0x21c)) && (uVar5 != 0x2d0)) {
                    /* WARNING: Bad instruction - Truncating control flow here */
              halt_baddata();
            }
          }
          else if (((uVar5 != 0x438) && (uVar5 != 0x5a0)) && (uVar5 != 0x870)) {
            halt_baddata();
          }
          if (bVar2 != 0) {
            halt_baddata();
          }
          if (*(int *)(param_3 + 0x10) != 0) {
            halt_baddata();
          }
        }
        iVar7 = func_0x00aca740(*(undefined2 *)(param_3 + 0x22));
        if (iVar7 == 0) {
          *(undefined8 *)(param_2 + 0x290) = uVar6;
          *(undefined4 *)(param_2 + 0x2a0) = *(undefined4 *)(param_3 + 0x10);
          *(undefined4 *)(param_2 + 0x2a4) = *(undefined4 *)(param_3 + 0x14);
          *(undefined4 *)(param_2 + 0x2a8) = *(undefined4 *)(param_3 + 0x18);
          *(undefined4 *)(param_2 + 0x2ac) = *(undefined4 *)(param_3 + 0x1c);
          *(uint *)(param_2 + 0x2b0) = (uint)*(byte *)(param_3 + 0x20);
          *(undefined8 *)(param_2 + 0xbc8) = *(undefined8 *)(param_3 + 0x38);
          uVar3 = *(ushort *)(param_3 + 0x22);
          *(bool *)(param_2 + 0x29a) = uVar8 < 7;
          *(ulong *)(param_2 + 0x2c8) = (ulong)uVar3;
          *(uint *)(param_2 + 0x2b4) = uVar4 >> 0x1e;
          if (uVar8 < 7) {
            *(undefined4 *)(param_2 + 0x2a0) = 0x100;
          }
          if (((byte)((ulong)uVar6 >> 0x28) < 0x13) && ((0x40380U >> (uVar4 >> 8 & 0x1f) & 1) != 0))
          {
            *(undefined1 *)(param_2 + 0x29b) = 1;
            *(ushort *)(param_2 + 0x298) = (ushort)*(byte *)(param_3 + 0xb);
            *(undefined4 *)(param_2 + 0x29c) = *(undefined4 *)(param_3 + 0x2c);
            func_0x00aca4a0();
                    /* WARNING: Bad instruction - Truncating control flow here */
            halt_baddata();
          }
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
      }
    }
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


