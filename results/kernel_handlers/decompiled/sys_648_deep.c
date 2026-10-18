/* REA 6.7.0 / Ghidra 12.1.4 recovered pseudocode, not original or buildable C.
 * Input: deep_648.bin, SHA256 06cfe2e4d2d586dc85a2dc13623a14b84671bc0c4a9ee7de040751ccf5685a71
 * File offset zero maps to kernel RVA 0x9f81f0; runtime VA = 0xffffffff8a9c0000 + RVA.
 * External bodies/types/data missing from this raw window remain unknown.
 * Function names are analyst seeds or Ghidra-generated; instruction truth is in .rea.asm.
 */

/* ===== sys_648 | RVA 0x9f81f0 | file +0x0 | ev_ef4c2611b5b2d4c868d28ec41df5e724f1bece079cab263d30cba920a13dcb71 =====
 * Body: [{"start":"0x9f81f0","end":"0x9f8264"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sys_648(long param_1,int *param_2)

{
  int iVar1;
  undefined8 uVar2;
  
  iVar1 = func_0x00609110(*(undefined8 *)(param_1 + 0x140));
  if (iVar1 == 0) {
    uVar2 = 1;
  }
  else {
    uVar2 = 0;
    func_0x00c4bb20(0x3badfc0,0,0,0);
    if (*param_2 == 7) {
      if (_DAT_03badfe0 == 0) {
        func_0x0025d410(0x132ca02);
      }
      else {
        *(byte *)(_DAT_03badfe0 + 0x140) = *(byte *)(_DAT_03badfe0 + 0x140) | 8;
      }
    }
    func_0x00c4c4b0(0x3badfc0,0,0);
  }
  return uVar2;
}



/* ===== sub_009f8270 | RVA 0x9f8270 | file +0x80 | ev_c89aaf39e6ac866e5a1e1344b960282e4544022665b6881f33b3755de4e957af =====
 * Body: [{"start":"0x9f8270","end":"0x9f8285"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_009f8270(long param_1)

{
  if (param_1 != 0) {
    return *(undefined8 *)(param_1 + 0x5a0);
  }
  return 0;
}



/* ===== sub_009f8290 | RVA 0x9f8290 | file +0xa0 | ev_b5ec3b1af28c985f0382f880ad4ae16fcc4aaadad7025e8efc35e28483a139f1 =====
 * Body: [{"start":"0x9f8290","end":"0x9f8573"},{"start":"0x9f8580","end":"0x9f8cdd"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_009f8290(long param_1,undefined8 *param_2)

{
  undefined8 uVar1;
  ulong uVar2;
  code *pcVar3;
  char cVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  long lVar8;
  long *plVar9;
  ulong *in_GS_OFFSET;
  undefined1 local_1d1;
  undefined4 local_1d0;
  int local_1cc;
  long local_1c8;
  long local_1c0;
  undefined8 local_1b8;
  undefined1 local_1b0 [16];
  undefined1 local_1a0 [56];
  char local_168;
  uint local_160;
  undefined8 local_110;
  undefined8 local_108;
  long local_100;
  undefined8 local_f0;
  long local_e8;
  uint local_e0;
  undefined1 local_dc [36];
  undefined1 local_b8 [128];
  long local_38;
  
  local_38 = _DAT_0391c310;
  local_1b8 = 0;
  local_1d0 = 0xffffffff;
  iVar5 = func_0x0026d0a0(*(undefined8 *)(param_1 + 0x140));
  if ((((iVar5 == 0) && (iVar5 = func_0x00609110(*(undefined8 *)(param_1 + 0x140)), iVar5 == 0)) &&
      (iVar5 = func_0x006090d0(*(undefined8 *)(param_1 + 0x140)), iVar5 == 0)) &&
     (iVar5 = func_0x006090a0(*(undefined8 *)(param_1 + 0x140)), iVar5 == 0)) {
    func_0x0025d410(0x12c4685,*(undefined4 *)(*(long *)(param_1 + 8) + 0xbc));
    iVar5 = 1;
    goto LAB_009f835f;
  }
  uVar1 = *param_2;
  func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
  local_1cc = func_0x00259280(uVar1,local_1b0,0x178);
  if (local_1cc != 0) {
    func_0x0025d410(0x13225b0);
    iVar5 = local_1cc;
    goto LAB_009f835f;
  }
  if (local_100 == 0) {
    iVar5 = 0x16;
    goto LAB_009f835f;
  }
  func_0x0025d410(0x129b4c6,local_160);
  if ((local_160 == 0x20f00 || local_100 != 0) &&
     (local_1cc = sub_009f8ce0(local_1b0,&local_1d0,&local_1b8), local_1cc != 0)) {
    func_0x0025d410(0x12f81d3,local_1cc);
    iVar5 = local_1cc;
    goto LAB_009f835f;
  }
  local_1c0 = 0;
  if (0xffffff < local_160) {
    iVar5 = func_0x00b07920();
    if ((iVar5 != 0) && (local_1cc = sub_009f9290(local_110,local_108,&local_1c0), local_1cc == 0))
    {
      sub_009f9500(local_1b8,local_1c0);
    }
    if (local_100 != 0) {
      func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
      local_1cc = func_0x002591d0(&local_1d0,local_100,4);
      if (local_1cc != 0) {
        func_0x0025d410(0x1356d5a);
        sub_009f9960(local_1d0);
        iVar5 = local_1cc;
        if (local_1c0 != 0) {
          func_0x00b5a1c0();
          iVar5 = local_1cc;
        }
        goto LAB_009f835f;
      }
    }
    if (local_1c0 != 0) {
      func_0x00b5a1c0();
    }
    func_0x00c4bb20(0x3badfe8,0,0,0);
    lVar8 = func_0x0073e2e0(0x12774f2);
    if (lVar8 != 0) {
      iVar5 = *(int *)(lVar8 + 0xc);
      *(int *)(lVar8 + 0xc) = iVar5 + 1;
      plVar9 = *(long **)(lVar8 + 0x40);
      if (plVar9 != (long *)0x0) {
        do {
          if ((int)plVar9[2] != -1) {
            func_0x004c6fa0(lVar8 + 0x28,0,0,0);
            pcVar3 = (code *)plVar9[5];
            if (0x197 < (-(long)pcVar3 + 0x267e88U >> 3 | -(long)pcVar3 << 0x3d)) {
              func_0x0044f8c0(0x2563f10,pcVar3);
            }
            (*pcVar3)(plVar9[3]);
            func_0x004c6a00(lVar8 + 0x28,0,0);
          }
          plVar9 = (long *)*plVar9;
        } while (plVar9 != (long *)0x0);
        iVar5 = *(int *)(lVar8 + 0xc) + -1;
      }
      *(int *)(lVar8 + 0xc) = iVar5;
      if (iVar5 == 0) {
        func_0x0073e370(lVar8);
      }
      func_0x004c6fa0(lVar8 + 0x28,0,0,0);
    }
    iVar5 = 0;
    if ((_DAT_03bae000 & 0xfffffffffffffff1) == *in_GS_OFFSET) {
      func_0x00c4c4b0();
    }
    else {
      func_0x00c4c300(0x3badfe8,0,0);
    }
    goto LAB_009f835f;
  }
  local_1cc = sub_009f9290(local_110,local_108,&local_1c0);
  if (local_1cc == 0) {
    iVar5 = func_0x00b07920();
    if (iVar5 != 0) {
      sub_009f9500(local_1b8,local_1c0);
    }
    if ((local_160 == 0xf000) && (local_168 == '\0')) {
      func_0x0025d410(0x1356d91,0xf000,0);
      local_160 = 0;
    }
    if (local_e8 == -1) {
      local_1c8 = 0;
      local_e8 = 0;
LAB_009f8727:
      local_1d1 = 1;
      local_1cc = sub_009f9cc0(local_e8);
    }
    else {
      if (local_e8 != 0) {
        local_1c8 = local_e8 << 0x14;
        goto LAB_009f8727;
      }
      local_1cc = sub_009f9bf0(local_1c0,&local_1d1,&local_1c8);
    }
    uVar1 = local_1b8;
    lVar8 = local_1c0;
    if ((local_1cc != 0) || (local_1cc = sub_009f9d50(local_1b8,local_1c0), local_1cc != 0)) {
      func_0x00b5a1c0(lVar8);
      goto joined_r0x009f8769;
    }
    func_0x00c4bb20(0x3badfc0,0,0,0);
    uVar2 = *in_GS_OFFSET;
    _DAT_03bae008 = uVar2;
    if (_DAT_03badfe0 != 0) {
      func_0x007f1950();
      func_0x007f1810(0x9f8cb8);
      func_0x00c9aa10(0xaa,0x138aefe);
                    /* WARNING: Does not return */
      pcVar3 = (code *)invalidInstructionException();
      (*pcVar3)();
    }
    iVar5 = func_0x008d1a30(local_1a0,0x1291071,10);
    iVar6 = func_0x008d1a30(local_1a0,0x12733da,10);
    iVar7 = func_0x006090d0(*(undefined8 *)(param_1 + 0x140));
    sub_009f9e10(iVar7 == 0,iVar6 == 0,local_168,iVar5 == 0,local_160 == 0x20f00,local_1d1,local_1c8
                );
    local_1cc = sub_009fa210(local_160,local_1d0,uVar1,lVar8);
    iVar5 = local_1cc;
    if (local_1cc == 0) {
      if (iVar6 == 0) {
        *(ushort *)(_DAT_03badfe0 + 0x140) = *(ushort *)(_DAT_03badfe0 + 0x140) | 0x80;
      }
      iVar5 = 0x16;
      if ((0x10 < local_e0) ||
         (local_1cc = func_0x00653ad0(_DAT_03badfe0,local_b8,local_dc), iVar5 = local_1cc,
         local_1cc != 0)) goto LAB_009f89c4;
      lVar8 = func_0x0073e2e0(0x12d6139);
      if (lVar8 != 0) {
        iVar5 = *(int *)(lVar8 + 0xc);
        *(int *)(lVar8 + 0xc) = iVar5 + 1;
        plVar9 = *(long **)(lVar8 + 0x40);
        if (plVar9 != (long *)0x0) {
          do {
            if ((int)plVar9[2] != -1) {
              func_0x004c6fa0(lVar8 + 0x28,0,0,0);
              pcVar3 = (code *)plVar9[5];
              if (0x42 < (-(long)pcVar3 + 0x268440U >> 3 | -(long)pcVar3 << 0x3d)) {
                func_0x0044f8c0(0x2563f30,pcVar3);
              }
              (*pcVar3)(plVar9[3],_DAT_03badfe0,&local_1cc);
              func_0x004c6a00(lVar8 + 0x28,0,0);
            }
            plVar9 = (long *)*plVar9;
          } while (plVar9 != (long *)0x0);
          iVar5 = *(int *)(lVar8 + 0xc) + -1;
        }
        *(int *)(lVar8 + 0xc) = iVar5;
        if (iVar5 == 0) {
          func_0x0073e370(lVar8);
        }
        func_0x004c6fa0(lVar8 + 0x28,0,0,0);
      }
      iVar5 = local_1cc;
      if (local_1cc != 0) goto LAB_009f89c4;
      sub_009fa690();
      local_1cc = sub_009fa7b0(local_f0);
      iVar5 = local_1cc;
      if (local_1cc != 0) goto LAB_009f89c4;
      cVar4 = func_0x00616d40(*(undefined4 *)(_DAT_03badfe0 + 0x124));
      if (cVar4 == '\0') {
        func_0x0025d410(0x1302b26,*(undefined4 *)(_DAT_03badfe0 + 0x124));
        iVar5 = 0x58;
        goto LAB_009f89c4;
      }
      lVar8 = func_0x0073e2e0(0x133b4bc);
      if (lVar8 != 0) {
        iVar5 = *(int *)(lVar8 + 0xc);
        *(int *)(lVar8 + 0xc) = iVar5 + 1;
        plVar9 = *(long **)(lVar8 + 0x40);
        if (plVar9 != (long *)0x0) {
          do {
            if ((int)plVar9[2] != -1) {
              func_0x004c6fa0(lVar8 + 0x28,0,0,0);
              pcVar3 = (code *)plVar9[5];
              if (0x42 < (-(long)pcVar3 + 0x268440U >> 3 | -(long)pcVar3 << 0x3d)) {
                func_0x0044f8c0(0x2563f50,pcVar3);
              }
              (*pcVar3)(plVar9[3],_DAT_03badfe0,&local_1cc);
              func_0x004c6a00(lVar8 + 0x28,0,0);
            }
            plVar9 = (long *)*plVar9;
          } while (plVar9 != (long *)0x0);
          iVar5 = *(int *)(lVar8 + 0xc) + -1;
        }
        *(int *)(lVar8 + 0xc) = iVar5;
        if (iVar5 == 0) {
          func_0x0073e370(lVar8);
        }
        func_0x004c6fa0(lVar8 + 0x28,0,0,0);
      }
      *(ushort *)(_DAT_03badfe0 + 0x140) = *(ushort *)(_DAT_03badfe0 + 0x140) | 0x200;
      iVar5 = local_1cc;
      if (local_1cc != 0) goto LAB_009f89c4;
    }
    else {
LAB_009f89c4:
      local_1cc = iVar5;
      if ((_DAT_03badfe0 != 0) && (iVar5 = func_0x009fb4e0(), iVar5 != 0 && local_1cc == 0)) {
        local_1cc = iVar5;
      }
      func_0x009fba30();
    }
    func_0x00c4c4b0(0x3badfc0,0,0);
    if (local_1cc == 0) {
      func_0x00c4bb20(0x3badfe8,0,0,0);
      lVar8 = func_0x0073e2e0(0x12774f2);
      if (lVar8 != 0) {
        iVar5 = *(int *)(lVar8 + 0xc);
        *(int *)(lVar8 + 0xc) = iVar5 + 1;
        plVar9 = *(long **)(lVar8 + 0x40);
        if (plVar9 != (long *)0x0) {
          do {
            if ((int)plVar9[2] != -1) {
              func_0x004c6fa0(lVar8 + 0x28,0,0,0);
              pcVar3 = (code *)plVar9[5];
              if (0x197 < (-(long)pcVar3 + 0x267e88U >> 3 | -(long)pcVar3 << 0x3d)) {
                func_0x0044f8c0(0x2563f70,pcVar3);
              }
              (*pcVar3)(plVar9[3]);
              func_0x004c6a00(lVar8 + 0x28,0,0);
            }
            plVar9 = (long *)*plVar9;
          } while (plVar9 != (long *)0x0);
          iVar5 = *(int *)(lVar8 + 0xc) + -1;
        }
        *(int *)(lVar8 + 0xc) = iVar5;
        if (iVar5 == 0) {
          func_0x0073e370(lVar8);
        }
        func_0x004c6fa0(lVar8 + 0x28,0,0,0);
      }
      if ((_DAT_03bae000 & 0xfffffffffffffff1) == uVar2) {
        func_0x00c4c4b0(0x3badfe8,0,0);
      }
      else {
        func_0x00c4c300(0x3badfe8,0,0);
      }
    }
    iVar5 = local_1cc;
    if (local_100 == 0) goto LAB_009f835f;
    if (local_1cc == 0) {
      local_1cc = sub_009f9920(&local_1d0);
      if (local_1cc == 0) {
        iVar5 = 0;
        goto LAB_009f835f;
      }
      func_0x0025d410(0x1356d5a);
    }
  }
  else {
joined_r0x009f8769:
    iVar5 = local_1cc;
    if (local_100 == 0) goto LAB_009f835f;
  }
  sub_009f9960(local_1d0);
  iVar5 = local_1cc;
LAB_009f835f:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar3 = (code *)invalidInstructionException();
    (*pcVar3)();
  }
  return iVar5;
}



/* ===== sub_009f8ce0 | RVA 0x9f8ce0 | file +0xaf0 | ev_6044adcdc5a791717cad191916526a2f42f5d04b5b752410bf038150a8b31f40 =====
 * Body: [{"start":"0x9f8ce0","end":"0x9f928f"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_009f8ce0(long param_1,undefined4 *param_2,undefined8 *param_3)

{
  code *pcVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  undefined8 *puVar5;
  long lVar6;
  long lVar7;
  undefined8 *puVar8;
  undefined2 *puVar9;
  ulong uVar10;
  undefined8 uVar11;
  ulong *in_GS_OFFSET;
  undefined8 local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  puVar5 = (undefined8 *)func_0x00c08b50(0x5c0,0x2563d50,0x102);
  func_0x002590b0(puVar5 + 2,param_1,0x98);
  if (*(uint *)(param_1 + 0x50) < 0x1000000) {
    lVar6 = func_0x00c08b50(0x3200,0x2563d50,0x102);
    if (*(int *)(param_1 + 0x50) == 0) {
      lVar7 = func_0x00c08b50(400,0x2563d50,0x102);
    }
    else {
      lVar7 = 0;
    }
  }
  else {
    lVar6 = 0;
    lVar7 = 0;
  }
  iVar2 = func_0x003998e0(_DAT_02563dc0,&local_40);
  if (iVar2 == -1) {
    if (lVar6 != 0) {
      func_0x00c08df0(lVar6,0x2563d50);
    }
    if (lVar7 != 0) {
      func_0x00c08df0(lVar7,0x2563d50);
    }
    func_0x00c08df0(puVar5,0x2563d50);
    iVar3 = 0x23;
    goto LAB_009f923a;
  }
  func_0x00c4bb20(0x3badfe8,0,0,0);
  if (0x1f < _DAT_03bae020) {
    if ((_DAT_03bae000 & 0xfffffffffffffff1) == *in_GS_OFFSET) {
      func_0x00c4c4b0();
    }
    else {
      func_0x00c4c300(0x3badfe8,0,0);
    }
    func_0x00399e30(_DAT_02563dc0,iVar2,local_40);
    func_0x00399eb0(local_40);
    if (lVar6 != 0) {
      func_0x00c08df0(lVar6,0x2563d50);
    }
    if (lVar7 != 0) {
      func_0x00c08df0(lVar7,0x2563d50);
    }
    func_0x00c08df0(puVar5,0x2563d50);
    func_0x0025d410(0x1336b5f,_DAT_03bae020);
    iVar3 = 0x23;
    goto LAB_009f923a;
  }
  uVar4 = *(uint *)(param_1 + 0x50);
  if (uVar4 < 0x1000000) {
    puVar8 = _DAT_03bae010;
    if (_DAT_03bb413c != 0 || DAT_03bb4138 != '\0') {
      func_0x0025d410(0x138b015);
      uVar10 = *in_GS_OFFSET;
LAB_009f8f99:
      if ((_DAT_03bae000 & 0xfffffffffffffff1) == uVar10) {
        func_0x00c4c4b0();
      }
      else {
        func_0x00c4c300(0x3badfe8,0,0);
      }
      func_0x00399e30(_DAT_02563dc0,iVar2,local_40);
      func_0x00399eb0(local_40);
      if (lVar6 != 0) {
        func_0x00c08df0(lVar6,0x2563d50);
      }
      if (lVar7 != 0) {
        func_0x00c08df0(lVar7,0x2563d50);
      }
      func_0x00c08df0(puVar5,0x2563d50);
      iVar3 = 0x10;
      goto LAB_009f923a;
    }
    for (; puVar8 != (undefined8 *)0x0; puVar8 = (undefined8 *)*puVar8) {
      if (*(uint *)(puVar8 + 0xc) < 0x1000000) {
        iVar3 = *(int *)(puVar8 + 0x16);
        if (iVar3 == 2) {
          iVar3 = *(int *)((long)puVar8 + 0xb4);
joined_r0x009f8f53:
          if (iVar3 != 1) goto LAB_009f8f55;
        }
        else if (2 < iVar3 - 3U) goto joined_r0x009f8f53;
        uVar10 = *in_GS_OFFSET;
        goto LAB_009f8f99;
      }
LAB_009f8f55:
    }
    if (_DAT_03bae034 == -1) {
      puVar9 = (undefined2 *)&DAT_03bae030;
    }
    else {
      if (_DAT_03bae03c != -1) goto LAB_009f90ac;
      puVar9 = (undefined2 *)&DAT_03bae038;
    }
    *(int *)(puVar9 + 2) = iVar2;
    iVar3 = func_0x0085a780(*puVar9);
    if (iVar3 != 0) {
      func_0x007f1950();
      func_0x007f18a0(0x9f9263,(long)iVar3);
      func_0x00c9aa10(0xd1,0x12ceed0,iVar3);
                    /* WARNING: Does not return */
      pcVar1 = (code *)invalidInstructionException();
      (*pcVar1)();
    }
LAB_009f90ac:
    uVar4 = *(uint *)(param_1 + 0x50);
  }
  else if (uVar4 == 0x2000100) {
    iVar3 = func_0x005a5b40(iVar2);
    if (iVar3 != 0) {
      if ((_DAT_03bae000 & 0xfffffffffffffff1) == *in_GS_OFFSET) {
        func_0x00c4c4b0();
      }
      else {
        func_0x00c4c300(0x3badfe8,0,0);
      }
      func_0x00399e30(_DAT_02563dc0,iVar2,local_40);
      func_0x00399eb0(local_40);
      if (lVar6 != 0) {
        func_0x00c08df0(lVar6,0x2563d50);
      }
      if (lVar7 != 0) {
        func_0x00c08df0(lVar7,0x2563d50);
      }
      func_0x00c08df0(puVar5,0x2563d50);
      goto LAB_009f923a;
    }
    goto LAB_009f90ac;
  }
  uVar11 = 0x600000;
  if ((uVar4 == 0x10300) || (uVar4 == 0x10000)) {
LAB_009f90e8:
    puVar5[0xb5] = uVar11;
    puVar5[0xb6] = 0;
    if (((uVar4 | 0x100) == 0xf100) && (*(char *)(param_1 + 0x4a) == '\x01')) {
      func_0x0025d410(0x1286f81);
    }
  }
  else {
    if (uVar4 != 0) {
      uVar11 = 0x40000000;
      goto LAB_009f90e8;
    }
    puVar5[0xb5] = 0xf00000;
    puVar5[0xb6] = 0;
  }
  *puVar5 = 0;
  _DAT_03bae020 = _DAT_03bae020 + 1;
  puVar5[1] = _DAT_03bae018;
  *_DAT_03bae018 = puVar5;
  _DAT_03bae018 = puVar5;
  *(undefined4 *)(puVar5 + 0x16) = 5;
  if ((_DAT_03bae000 & 0xfffffffffffffff1) == *in_GS_OFFSET) {
    func_0x00c4c4b0();
  }
  else {
    func_0x00c4c300(0x3badfe8,0,0);
  }
  *(int *)(puVar5 + 2) = iVar2;
  puVar5[0x15] = 0;
  *(undefined4 *)((long)puVar5 + 0xb4) = 0;
  *(undefined4 *)((long)puVar5 + 0xbc) = 0xffffffff;
  puVar5[0x18] = lVar6;
  *(undefined4 *)(puVar5 + 0x19) = 4;
  func_0x00258ff0((long)puVar5 + 0xcc,0x400);
  func_0x00258ff0((long)puVar5 + 0x4cc,8);
  if (*(char *)(param_1 + 0x53) == '\x03') {
    *(undefined4 *)((long)puVar5 + 0xbc) = *(undefined4 *)(param_1 + 0xb8);
  }
  puVar5[0xb7] = lVar7;
  *param_2 = *(undefined4 *)(puVar5 + 2);
  *param_3 = puVar5;
  func_0x00399de0(local_40,0x8010,puVar5,puVar5 + 4);
  func_0x00399eb0(local_40);
  iVar3 = 0;
  func_0x0025d410(0x12ceef1,*param_2,*(undefined4 *)(param_1 + 0x50));
LAB_009f923a:
  if (_DAT_0391c310 == local_38) {
    return iVar3;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* ===== sub_009f9290 | RVA 0x9f9290 | file +0x10a0 | ev_9f86d3648f2d7e2f230a3bf3bc4f30c66a06801f27dd50bd8b8725d488b33550 =====
 * Body: [{"start":"0x9f9290","end":"0x9f9340"},{"start":"0x9f9350","end":"0x9f94fc"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_009f9290(long param_1,ulong param_2,undefined8 *param_3)

{
  undefined8 *puVar1;
  code *pcVar2;
  char cVar3;
  int iVar4;
  undefined8 *puVar5;
  undefined8 uVar6;
  ulong uVar7;
  undefined8 *in_GS_OFFSET;
  undefined8 local_60;
  undefined8 local_58;
  long local_50;
  undefined4 local_48;
  undefined4 local_44;
  undefined8 local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  if (0x100000 < param_2) {
    func_0x0025d410(0x1376381,param_2,0x100000);
    iVar4 = 0xc;
    goto LAB_009f94dc;
  }
  if (param_2 == 0) {
    iVar4 = 0;
    uVar6 = func_0x00b5a150(0);
    *param_3 = uVar6;
    goto LAB_009f94dc;
  }
  puVar5 = (undefined8 *)func_0x0042a4e0(0,param_2 & 0xffffffff,2,1,0);
  for (puVar1 = puVar5; puVar1 != (undefined8 *)0x0; puVar1 = (undefined8 *)*puVar1) {
    if ((*(uint *)((long)puVar1 + 0x1c) & 0x100) == 0) {
      uVar7 = 0x88;
      if ((*(uint *)((long)puVar1 + 0x1c) & 0x200) == 0) {
        uVar7 = 0xe0;
      }
    }
    else {
      uVar7 = (ulong)*(uint *)(puVar1 + 0x11);
    }
    uVar6 = puVar1[2];
    if (param_2 < uVar7) {
      uVar7 = param_2;
    }
    func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
    iVar4 = func_0x00259280(param_1,uVar6,uVar7);
    if (iVar4 != 0) {
      func_0x0042a850(puVar5);
      goto LAB_009f94dc;
    }
    *(int *)(puVar1 + 3) = (int)uVar7;
    param_1 = param_1 + uVar7;
    param_2 = param_2 - uVar7;
  }
  func_0x00258ff0(&local_60,0x20);
  local_40 = 0;
  cVar3 = func_0x00b5ab50(&local_40,&local_60,puVar5,0x10);
  if (cVar3 == '\0') {
    iVar4 = func_0x0026b9b0(local_60,0x129b561);
    if (iVar4 == 0) {
      local_40 = func_0x00b5a150(0);
      goto LAB_009f949b;
    }
    func_0x00b044d0(0,0,0x18d0e50,local_60,local_58);
    if (local_50 != 0) {
      uVar6 = func_0x008bebc0();
      func_0x00b044d0(0,0,0x18d0ea0,uVar6);
      func_0x008be5b0(local_50);
    }
    func_0x00b044d0(0,0,0x18d0eb0,local_48,local_44);
    func_0x0042a850(puVar5);
  }
  else {
LAB_009f949b:
    func_0x0042a850(puVar5);
    iVar4 = func_0x00b5a330(local_40);
    if (iVar4 == 2) {
      iVar4 = 0;
      *param_3 = local_40;
      goto LAB_009f94dc;
    }
    func_0x00b044d0(0,0,0x18d0ed0);
    func_0x00b5a1c0(local_40);
  }
  iVar4 = 0x16;
LAB_009f94dc:
  if (_DAT_0391c310 == local_38) {
    return iVar4;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar2 = (code *)invalidInstructionException();
  (*pcVar2)();
}



/* ===== sub_009f9500 | RVA 0x9f9500 | file +0x1310 | ev_8ba2cd8dde7ffa6dea8a802cb78ea3bc3c8c39f31be292fb50aa05eae09e4303 =====
 * Body: [{"start":"0x9f9500","end":"0x9f9912"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Possible PIC construction at 0x009f9646: Changing call to branch */
/* WARNING: Possible PIC construction at 0x009f971b: Changing call to branch */
/* WARNING: Possible PIC construction at 0x009f97bf: Changing call to branch */
/* WARNING: Possible PIC construction at 0x009f97d3: Changing call to branch */
/* WARNING: Possible PIC construction at 0x009f967e: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x009f97d8) */
/* WARNING: Removing unreachable block (ram,0x009f97c4) */
/* WARNING: Removing unreachable block (ram,0x009f9720) */
/* WARNING: Removing unreachable block (ram,0x009f964b) */
/* WARNING: Removing unreachable block (ram,0x009f9683) */

void sub_009f9500(long param_1,undefined8 param_2)

{
  int iVar1;
  long lVar2;
  undefined1 *puVar3;
  long lVar4;
  undefined8 uVar5;
  
  lVar2 = func_0x00b5aac0(param_2,0x12e67d8);
  if (lVar2 != 0) {
    iVar1 = func_0x00b5a330(lVar2);
    if (iVar1 != 2) {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    lVar2 = func_0x00b5aac0(lVar2,0x129b571);
    if (lVar2 != 0) {
      iVar1 = func_0x00b5a330(lVar2);
      if (iVar1 != 2) {
        halt_baddata();
      }
      lVar2 = func_0x00b5aac0(lVar2,0x132264a);
      if (lVar2 != 0) {
        iVar1 = func_0x00b5a330(lVar2);
        if (iVar1 != 2) {
          halt_baddata();
        }
        puVar3 = (undefined1 *)func_0x00c08b50(4,0x2563d50,0x102);
        *(undefined1 **)(param_1 + 0x5a0) = puVar3;
        *puVar3 = 1;
        lVar4 = func_0x00b5aac0(lVar2,0x133c2bc);
        if (lVar4 != 0) {
          iVar1 = func_0x00b5a330(lVar4);
          if (iVar1 != 5) {
            halt_baddata();
          }
          uVar5 = func_0x00b5a360(lVar4);
          iVar1 = func_0x008d1a30(uVar5,0x131bd67,2);
          if (iVar1 == 0) {
            *(ushort *)(puVar3 + 2) = (*(ushort *)(puVar3 + 2) & 0xfff0) + 1;
          }
          else {
            iVar1 = func_0x008d1a30(uVar5,0x127695b,2);
            if (iVar1 == 0) {
              *(ushort *)(puVar3 + 2) = *(ushort *)(puVar3 + 2) & 0xfff0 | 2;
            }
            else {
              iVar1 = func_0x008d1a30(uVar5,0x13831ec,2);
              if (iVar1 != 0) {
                halt_baddata();
              }
              puVar3[2] = puVar3[2] & 0xf0;
            }
          }
        }
        lVar4 = func_0x00b5aac0(lVar2,0x133cdc0);
        if (lVar4 != 0) {
          iVar1 = func_0x00b5a330(lVar4);
          if (iVar1 == 5) {
            uVar5 = func_0x00b5a360(lVar4);
            iVar1 = func_0x008d1a30(uVar5,0x131bd67,2);
            if (iVar1 == 0) {
              *(ushort *)(puVar3 + 2) = *(ushort *)(puVar3 + 2) & 0xff0f | 0x10;
            }
            else {
              iVar1 = func_0x008d1a30(uVar5,0x13831ec,2);
              if (iVar1 != 0) {
                halt_baddata();
              }
              puVar3[2] = puVar3[2] & 0xf;
            }
          }
          else {
            func_0x00b044d0(0,0,0x18d1090);
          }
        }
        lVar4 = func_0x00b5aac0(lVar2,0x130d5a2);
        if (lVar4 != 0) {
          iVar1 = func_0x00b5a330(lVar4);
          if (iVar1 != 5) {
            halt_baddata();
          }
          uVar5 = func_0x00b5a360(lVar4);
          iVar1 = func_0x008d1a30(uVar5,0x131bd67,2);
          if (iVar1 == 0) {
            *(ushort *)(puVar3 + 2) = *(ushort *)(puVar3 + 2) & 0xf0ff | 0x100;
          }
          else {
            iVar1 = func_0x008d1a30(uVar5,0x13831ec,2);
            if (iVar1 != 0) {
              halt_baddata();
            }
            puVar3[3] = puVar3[3] & 0xf0;
          }
        }
        lVar2 = func_0x00b5aac0(lVar2,0x12a5754);
        if (lVar2 != 0) {
          iVar1 = func_0x00b5a330(lVar2);
          if (iVar1 != 5) {
            halt_baddata();
          }
          uVar5 = func_0x00b5a360(lVar2);
          iVar1 = func_0x008d1a30(uVar5,0x131bd67,2);
          if (iVar1 == 0) {
            *(ushort *)(puVar3 + 2) = *(ushort *)(puVar3 + 2) & 0xfff | 0x1000;
          }
          else {
            iVar1 = func_0x008d1a30(uVar5,0x1317c3f,3);
            if (iVar1 == 0) {
              *(ushort *)(puVar3 + 2) = *(ushort *)(puVar3 + 2) & 0xfff | 0x3000;
            }
            else {
              iVar1 = func_0x008d1a30(uVar5,0x1322652,3);
              if (iVar1 == 0) {
                *(ushort *)(puVar3 + 2) = *(ushort *)(puVar3 + 2) & 0xfff | 0x4000;
              }
              else {
                iVar1 = func_0x008d1a30(uVar5,0x13831ec,2);
                if (iVar1 != 0) {
                  halt_baddata();
                }
                puVar3[3] = puVar3[3] & 0xf;
              }
            }
          }
        }
      }
    }
  }
  return;
}



/* ===== sub_009f9920 | RVA 0x9f9920 | file +0x1730 | ev_b4c975e2b2302d7deb5f1ba7bc9cf5529a2f901f72d960890fb7aaf2136e383d =====
 * Body: [{"start":"0x9f9920","end":"0x9f9957"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_009f9920(void)

{
  undefined8 *in_GS_OFFSET;
  
  func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== sub_009f9960 | RVA 0x9f9960 | file +0x1770 | ev_7a56f059517c862d0b99097d50971b2fbea75ad633aeb5c2194df6d5f47a86c4 =====
 * Body: [{"start":"0x9f9960","end":"0x9f9bed"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_009f9960(int param_1)

{
  long lVar1;
  code *pcVar2;
  undefined8 *puVar3;
  int iVar4;
  long *plVar5;
  undefined2 *puVar6;
  ulong *in_GS_OFFSET;
  undefined8 local_30;
  long local_28;
  
  local_28 = _DAT_0391c310;
  if ((param_1 == 0) ||
     (plVar5 = (long *)func_0x00399ee0(_DAT_02563dc0,param_1,0x8010,&local_30),
     plVar5 == (long *)0x0)) goto LAB_009f9b2c;
  func_0x00c4bb20(0x3badfe8,0,0,0);
  if ((*(uint *)(plVar5 + 0x16) & 0xfffffffe) != 4) {
    if ((_DAT_03bae000 & 0xfffffffffffffff1) == *in_GS_OFFSET) {
      func_0x00c4c4b0();
    }
    else {
      func_0x00c4c300(0x3badfe8,0,0);
    }
    func_0x0025d410(0x12d9bb5,param_1,(int)plVar5[0x16]);
    func_0x00399eb0(local_30);
    goto LAB_009f9b2c;
  }
  lVar1 = *plVar5;
  if (lVar1 == 0) {
    puVar3 = (undefined8 *)plVar5[1];
    if (*(long **)plVar5[1] != plVar5) goto LAB_009f9b47;
  }
  else {
    if (*(long **)(lVar1 + 8) != plVar5) {
      func_0x007f1950();
      func_0x007f2180(0x9f9bae,plVar5,*plVar5,*(undefined8 *)(*plVar5 + 8),plVar5);
      func_0x00c9aa10(0xd5,0x1339cb6,plVar5,*plVar5,*(undefined8 *)(*plVar5 + 8),plVar5);
                    /* WARNING: Does not return */
      pcVar2 = (code *)invalidInstructionException();
      (*pcVar2)();
    }
    if (*(long **)plVar5[1] != plVar5) {
LAB_009f9b47:
      func_0x007f1950();
      func_0x007f20c0(0x9f9b47,plVar5,(undefined8 *)plVar5[1],*(undefined8 *)plVar5[1]);
      func_0x00c9aa10(0xd9,0x12fc56b,plVar5,(undefined8 *)plVar5[1],*(undefined8 *)plVar5[1]);
                    /* WARNING: Does not return */
      pcVar2 = (code *)invalidInstructionException();
      (*pcVar2)();
    }
    *(undefined8 **)(lVar1 + 8) = (undefined8 *)plVar5[1];
    puVar3 = _DAT_03bae018;
  }
  _DAT_03bae018 = puVar3;
  *(long *)plVar5[1] = *plVar5;
  _DAT_03bae020 = _DAT_03bae020 + -1;
  if ((_DAT_03bae000 & 0xfffffffffffffff1) == *in_GS_OFFSET) {
    func_0x00c4c4b0();
  }
  else {
    func_0x00c4c300(0x3badfe8,0,0);
  }
  iVar4 = func_0x006e7500(param_1);
  if ((iVar4 != 0) && (iVar4 = func_0x006e7130(param_1), iVar4 != 0)) {
    func_0x0025d410(0x1380147,iVar4);
  }
  func_0x005a5b90(param_1,(int)plVar5[0xc]);
  if ((int)plVar5[0xc] == 0x2000100) {
    func_0x005a5b70();
  }
  if (_DAT_03bae034 == param_1) {
    puVar6 = (undefined2 *)&DAT_03bae030;
LAB_009f9af7:
    iVar4 = func_0x0085a880(*puVar6);
    if (iVar4 != 0) {
      func_0x007f1950();
      func_0x007f18a0(0x9f9b81,(long)iVar4);
      func_0x00c9aa10(0xdd,0x12e3ad2,iVar4);
                    /* WARNING: Does not return */
      pcVar2 = (code *)invalidInstructionException();
      (*pcVar2)();
    }
    *(undefined4 *)(puVar6 + 2) = 0xffffffff;
  }
  else if (_DAT_03bae03c == param_1) {
    puVar6 = (undefined2 *)&DAT_03bae038;
    goto LAB_009f9af7;
  }
  func_0x00399eb0(local_30);
  func_0x009fc050(param_1);
  func_0x0025d410(0x13617fc,param_1);
LAB_009f9b2c:
  if (_DAT_0391c310 != local_28) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar2 = (code *)invalidInstructionException();
    (*pcVar2)();
  }
  return;
}



/* ===== sub_009f9bf0 | RVA 0x9f9bf0 | file +0x1a00 | ev_d2b0be19d6d0ad6fd589fe9002aeb4eaae3ea6ab6bfcf8b1e1443d2b7c1c21d6 =====
 * Body: [{"start":"0x9f9bf0","end":"0x9f9cbc"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_009f9bf0(long param_1,undefined1 *param_2,long *param_3)

{
  int iVar1;
  long lVar2;
  undefined8 uVar3;
  
  *param_2 = 0;
  if (param_1 == 0) {
    return 0;
  }
  iVar1 = func_0x00acce10();
  if ((iVar1 != 0) && (lVar2 = func_0x00b5aac0(param_1,0x12e67d8), lVar2 != 0)) {
    iVar1 = func_0x00b5a330(lVar2);
    if (iVar1 != 2) {
      uVar3 = 0x18d12d0;
LAB_009f9ca2:
      func_0x00b044d0(0,0,uVar3);
      return 0x16;
    }
    lVar2 = func_0x00b5aac0(lVar2,0x12f8258);
    if (lVar2 != 0) {
      iVar1 = func_0x00b5a330(lVar2);
      if (iVar1 != 3) {
        uVar3 = 0x18d1320;
        goto LAB_009f9ca2;
      }
      lVar2 = func_0x00b5a340(lVar2);
      uVar3 = sub_009f9cc0(lVar2);
      if ((int)uVar3 != 0) {
        return uVar3;
      }
      if (_DAT_03bb4110 == 0) {
        *param_3 = lVar2 << 0x14;
        *param_2 = 1;
      }
    }
  }
  return 0;
}



/* ===== sub_009f9cc0 | RVA 0x9f9cc0 | file +0x1ad0 | ev_e69618c97679fb771868c49d0e6ffb291906b999bb70a5589090597ec1c95018 =====
 * Body: [{"start":"0x9f9cc0","end":"0x9f9d49"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_009f9cc0(ulong param_1)

{
  ulong uVar1;
  undefined8 uVar2;
  
  if (((long)param_1 < 0) || (uVar1 = func_0x00a08640(), uVar1 >> 0x14 < param_1)) {
    uVar2 = 0x18d1380;
  }
  else {
    if ((param_1 & 1) == 0) {
      if (_DAT_03bb4110 == 0) {
        return 0;
      }
      if (param_1 << 0x14 == _DAT_03bb40b8) {
        return 0;
      }
      func_0x00b044d0(0,0,0x18d1410,param_1 << 0x14);
      return 0x73;
    }
    uVar2 = 0x18d13c0;
  }
  func_0x00b044d0(0,0,uVar2,param_1 << 0x14);
  return 0x16;
}



/* ===== sub_009f9d50 | RVA 0x9f9d50 | file +0x1b60 | ev_458c9997b9e98f1ca55a58f8b431df8ff217d6f43034aa779b93505f7676dfcb =====
 * Body: [{"start":"0x9f9d50","end":"0x9f9e0d"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_009f9d50(long param_1,undefined8 param_2)

{
  code *pcVar1;
  undefined8 uVar2;
  ulong local_28;
  long local_20;
  
  local_20 = _DAT_0391c310;
  if (param_1 != 0) {
    local_28 = 0;
    uVar2 = func_0x00a026f0(param_2,0x12cee87,&local_28);
    if ((int)uVar2 != 0) goto LAB_009f9df5;
    if (local_28 != 0) {
      if (0xa00000 < local_28) {
        func_0x00b044d0(0,0,0x18d1460,0xa00000);
        uVar2 = 0x16;
        goto LAB_009f9df5;
      }
      if ((local_28 & 0x3fff) != 0) {
        func_0x00b044d0(0,0,0x18d14e0,local_28);
        uVar2 = 0x16;
        goto LAB_009f9df5;
      }
      *(long *)(param_1 + 0x5a8) = *(long *)(param_1 + 0x5a8) + local_28;
    }
  }
  uVar2 = 0;
LAB_009f9df5:
  if (_DAT_0391c310 == local_20) {
    return uVar2;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* ===== sub_009f9e10 | RVA 0x9f9e10 | file +0x1c20 | ev_31d7828845eda28f03ee4d5249ea995ec403c9bfd8873c97498d0a1a1a70905e =====
 * Body: [{"start":"0x9f9e10","end":"0x9fa07a"},{"start":"0x9fa080","end":"0x9fa158"},{"start":"0x9fa160","end":"0x9fa20d"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_009f9e10(char param_1,char param_2,char param_3,uint param_4,char param_5,char param_6,
                 ulong param_7)

{
  bool bVar1;
  code *pcVar2;
  char cVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  ulong uVar7;
  long lVar8;
  undefined8 uVar9;
  ulong uVar10;
  undefined8 *puVar11;
  long lVar12;
  ulong uVar13;
  uint uVar14;
  ulong uVar15;
  int local_70;
  int local_6c;
  char acStack_68 [48];
  long local_38;
  
  local_38 = _DAT_0391c310;
  iVar4 = _DAT_03bb4110 + 1;
  bVar1 = _DAT_03bb4110 < 1;
  _DAT_03bb4110 = iVar4;
  if ((bVar1) && (*(int *)(_DAT_03bae088 + 0x84) < 1)) {
    uVar7 = func_0x00a08640();
    lVar12 = _DAT_03bb4118;
    if (uVar7 != 0) {
      lVar8 = func_0x00a08640();
      uVar9 = func_0x00a08640();
      func_0x00a08390(0x3bb5310,0x3bb5300,lVar12 - lVar8,uVar9);
    }
    uVar10 = uVar7;
    if ((param_5 == '\0') && (uVar10 = param_7, param_6 == '\0')) {
      if (param_2 == '\0') {
        if (((param_1 == '\0') || (iVar4 = func_0x00acce10(), iVar4 == 0)) ||
           (iVar4 = func_0x00ae70c0(0x78280100,&local_6c), iVar4 != 0)) {
          local_6c = 0;
        }
      }
      else if (param_3 == '\x02') {
        local_6c = 0x1500;
      }
      else if (param_3 == '\x01') {
        local_6c = 0x1280;
      }
      else {
        func_0x00b044d0(0,0,0x18d15f0);
        local_6c = 0;
      }
    }
    else {
      local_6c = (int)(uVar10 >> 0x14);
    }
    _DAT_03bb40b8 = (long)local_6c * 0x100000;
    uVar10 = 0;
    if (_DAT_03bb40b8 <= uVar7) {
      uVar10 = uVar7 + (long)local_6c * -0x100000;
    }
    _DAT_03bb4120 = _DAT_03bb4118 - uVar10;
    if ((_DAT_03bb40b8 < uVar7) && (func_0x003c95a0(), param_1 != '\0')) {
      func_0x003c3490(_DAT_03bae088);
      func_0x003c3610(_DAT_03bae088);
      func_0x003c3580(_DAT_03bae088);
      func_0x003c8150(_DAT_03bae088,0,_DAT_03bb4120,uVar10);
      func_0x003c3430(_DAT_03bae088);
      func_0x003c3540(_DAT_03bae088);
      func_0x003c3580(_DAT_03bae088);
      iVar4 = func_0x00cb66e0(4,_DAT_03bb4120,uVar10);
      if (iVar4 != 0) {
        func_0x00b044d0(0,0,0x18d0d60,iVar4);
      }
      cVar3 = func_0x00a085c0();
      if (cVar3 != '\0') {
        func_0x00b044d0(0,0,0x18d1650);
      }
      puVar11 = (undefined8 *)&DAT_02564b28;
      iVar4 = 0x78288001;
      uVar15 = 0;
      uVar7 = 0;
      do {
        iVar5 = func_0x00ae70c0(iVar4,&local_70);
        if (iVar5 != 0) {
          iVar6 = func_0x00acce10();
          if (iVar6 != 0) {
            func_0x00b044d0(0,0,0x18d16d0,iVar5);
          }
          local_70 = 0;
        }
        cVar3 = func_0x00a085c0();
        uVar14 = (uint)uVar15;
        if (cVar3 == '\0') {
LAB_009fa0a0:
          if ((uVar15 == 0x13) && (iVar5 = func_0x00a08740(), iVar5 != 0)) {
            local_70 = 2;
            *puVar11 = 0x20000000;
          }
        }
        else if (uVar14 - 6 < 8) {
          local_70 = 5;
        }
        else {
          if (uVar15 != 0xe) {
            local_70 = 0;
            goto LAB_009fa0a0;
          }
          local_70 = 2;
          *puVar11 = 0x1000000;
        }
        acStack_68[uVar15] = local_70 == 5;
        uVar13 = uVar7;
        if ((local_70 - 1U < 4) &&
           ((((ulong)(param_4 & 0xff) - 1 | 0x8011) & (long)(1 << (uVar14 & 0x1f))) != 0)) {
          uVar13 = puVar11[(ulong)(local_70 - 1U) - 1] + uVar7;
          if (uVar10 < uVar13) {
            func_0x00b044d0(0,0,0x18d1720,uVar15 & 0xffffffff);
            uVar13 = uVar7;
          }
          else {
            func_0x003c9570(uVar14 + 1,uVar7,uVar13);
          }
        }
        uVar15 = uVar15 + 1;
        puVar11 = puVar11 + 4;
        iVar4 = iVar4 + 0x100;
        uVar7 = uVar13;
      } while (uVar15 != 0x30);
      lVar12 = 0;
      do {
        if (acStack_68[lVar12] == '\x01') {
          func_0x003c9570((int)lVar12 + 1,uVar13,uVar10);
        }
        lVar12 = lVar12 + 1;
      } while (lVar12 != 0x30);
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



/* ===== sub_009fa210 | RVA 0x9fa210 | file +0x2020 | ev_2281861be49d47fafc35812fe8312c8e6ed37272795a2144a6d14a17ed7f4752 =====
 * Body: [{"start":"0x9fa210","end":"0x9fa68f"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_009fa210(uint param_1,undefined4 param_2,long param_3,undefined8 param_4)

{
  long lVar1;
  uint uVar2;
  byte bVar3;
  int iVar4;
  uint uVar5;
  undefined8 *puVar6;
  undefined8 uVar7;
  ulong uVar8;
  long lVar9;
  char *pcVar10;
  ulong *in_GS_OFFSET;
  
  if (_DAT_03bb412c == 0) {
LAB_009fa465:
    func_0x00b5a1c0(param_4);
    return 0xc;
  }
  uVar5 = 0;
  for (uVar2 = _DAT_03bb412c; (uVar2 & 1) == 0; uVar2 = uVar2 >> 1 | 0x80000000) {
    uVar5 = uVar5 + 1;
  }
  _DAT_03bb412c = _DAT_03bb412c & ~(1 << (uVar5 & 0x1f));
  if (uVar5 == 0) goto LAB_009fa465;
  func_0x0025d410(0x130d5a7,param_1,uVar5);
  puVar6 = (undefined8 *)func_0x00c08b50(0x1a6cb40 - _DAT_01a5d1f8,0x2563c90,0x102);
  uVar7 = func_0x00c08b50(((_DAT_03bb4118 - _DAT_03badfb8) + 0x1fffffU >> 0x15) + 0x3f &
                          0xffffffffffffffc0,0x2563c90,0x102);
  puVar6[5] = uVar7;
  *puVar6 = 0;
  puVar6[2] = param_4;
  *(uint *)(puVar6 + 0x24) = uVar5;
  uVar7 = func_0x003c3920(uVar5,0);
  puVar6[3] = uVar7;
  uVar7 = func_0x0043b0e0(0x1336b13,0x170,0,0,0,0,7,(uint)((~param_1 & 0xf000) != 0) << 0x10 | 0x400
                         );
  puVar6[6] = uVar7;
  *(uint *)(puVar6 + 0x23) = param_1;
  uVar8 = _DAT_03bb4120;
  if ((((0xffff < param_1) && (param_1 != 0x10300)) && (param_1 != 0x20f00)) && (param_1 != 0x1f000)
     ) {
    uVar8 = _DAT_03bb4120 - 0x63400000;
  }
  puVar6[0xf] = uVar8;
  puVar6[0x10] = uVar8;
  uVar7 = func_0x005033b0(0x40000000);
  puVar6[0x13] = uVar7;
  puVar6[0x11] = _DAT_03badfb8;
  *(undefined4 *)((long)puVar6 + 0x11c) = param_2;
  puVar6[1] = param_3;
  *(undefined8 **)(param_3 + 0xa8) = puVar6;
  iVar4 = func_0x00609940();
  if (iVar4 != 0) {
    bVar3 = func_0x00a027a0(puVar6,0x1356ed2,puVar6 + 0x22);
    *(ushort *)(puVar6 + 0x28) =
         ((ushort)*(undefined4 *)(puVar6 + 0x28) & 0xfffd) + (ushort)bVar3 * 2;
    bVar3 = func_0x00a027a0(puVar6,0x12910b2,(long)puVar6 + 0x114);
    *(ushort *)(puVar6 + 0x28) =
         ((ushort)*(undefined4 *)(puVar6 + 0x28) & 0xfffb) + (ushort)bVar3 * 4;
  }
  _DAT_02d585c0 = *(undefined4 *)(puVar6 + 0x24);
  _DAT_03badfe0 = puVar6;
  if (_DAT_03bb4128 != 0) {
    if ((_DAT_03bb4100 != 0) && (*(ulong *)(_DAT_03bb4100 + 0x90) < uVar8)) {
      uVar8 = *(ulong *)(_DAT_03bb4100 + 0x90);
    }
    func_0x008ef3f0(_DAT_03bb4128,_DAT_03badfb8,uVar8);
  }
  _DAT_03bb4128 = uVar5;
  if ((int)param_1 < 0x1f300) {
    if (((param_1 != 0xf000) && (param_1 != 0xf100)) && (param_1 != 0x1f000)) goto LAB_009fa552;
  }
  else if (((param_1 != 0x1f300) && (param_1 != 0x200f100)) && (param_1 != 0x2f000))
  goto LAB_009fa552;
  if ((_DAT_03badfd8 & 1) == 0) {
    uVar8 = _DAT_03badfd8 & 0xfffffffffffffff0;
  }
  else {
    uVar8 = 0;
  }
  if (uVar8 == *in_GS_OFFSET) {
    uVar7 = func_0x009f7bc0(0xb400000,0x200000,0,0);
  }
  else {
    func_0x00c4bb20(0x3badfc0,0,0,0);
    uVar7 = func_0x009f7bc0(0xb400000,0x200000,0,0);
    func_0x00c4c4b0(0x3badfc0,0,0);
  }
  puVar6[0xe] = uVar7;
  _DAT_03badfb0 = puVar6;
LAB_009fa552:
  if (*(int *)(puVar6 + 0x23) != 0) {
    return 0;
  }
  lVar1 = puVar6[1];
  lVar9 = func_0x00b5aac0(puVar6[2],0x1395177);
  if (lVar9 != 0) {
    iVar4 = func_0x00b5a330(lVar9);
    if (iVar4 == 2) {
      lVar9 = func_0x00b5aac0(lVar9,0x139fefa);
      if (lVar9 == 0) {
        return 0;
      }
      iVar4 = func_0x00b5a330(lVar9);
      if (((iVar4 == 5) && (uVar5 = func_0x00b5a350(lVar9), 0xfffffffd < uVar5 - 7)) &&
         ((((pcVar10 = (char *)func_0x00b5a360(lVar9), (byte)(*pcVar10 - 0x30U) < 10 &&
            (((byte)(pcVar10[1] - 0x30U) < 10 && (pcVar10[2] == '.')))) &&
           ((byte)(pcVar10[3] - 0x30U) < 10)) &&
          (((byte)(pcVar10[4] - 0x30U) < 10 &&
           ((uVar5 == 5 || ((byte)((pcVar10[(ulong)uVar5 - 1] & 0xdfU) + 0xbf) < 0x1a)))))))) {
        uVar7 = func_0x00b5a360(lVar9);
        func_0x00675a00(uVar7,0x12f0d2b,lVar1 + 0x92);
      }
      else {
        func_0x00b044d0(0,0,0x18d1830,0x139fefa);
      }
    }
    else {
      func_0x00b044d0(0,0,0x18d17f0);
    }
  }
  return 0;
}



/* ===== sub_009fa690 | RVA 0x9fa690 | file +0x24a0 | ev_a98902b48c5cc713eb6cf06f8b36913f2189fe0fa89c721c0bba9ee88ba8a87d =====
 * Body: [{"start":"0x9fa690","end":"0x9fa7ac"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_009fa690(void)

{
  code *pcVar1;
  long lVar2;
  long lVar3;
  ulong uVar4;
  undefined8 uVar5;
  ulong uVar6;
  ulong *in_GS_OFFSET;
  
  lVar2 = _DAT_03badfe0;
  lVar3 = func_0x00653ab0(_DAT_03badfe0);
  uVar6 = lVar3 + 0x1fffffU & 0xffffffffffe00000;
  if ((uVar6 < 0x5000001) && (uVar6 <= (*(long *)(lVar2 + 0x80) - _DAT_03bb4120) + 0x63400000U)) {
    if (uVar6 != 0) {
      if ((_DAT_03badfd8 & 1) == 0) {
        uVar4 = _DAT_03badfd8 & 0xfffffffffffffff0;
      }
      else {
        uVar4 = 0;
      }
      if (uVar4 == *in_GS_OFFSET) {
        uVar5 = func_0x009f7bc0(uVar6,0x200000,uVar6,0);
      }
      else {
        func_0x00c4bb20(0x3badfc0,0,0,0);
        uVar5 = func_0x009f7bc0(uVar6,0x200000,uVar6,0);
        func_0x00c4c4b0(0x3badfc0,0,0);
      }
      *(undefined8 *)(lVar2 + 0x90) = uVar5;
      *(ulong *)(lVar2 + 200) = uVar6;
      _DAT_03bb4100 = lVar2;
    }
    return;
  }
  func_0x007f1950();
  func_0x007f18a0(0x9fa781,uVar6);
  func_0x00c9aa10(0x42,0x1322655,uVar6);
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* ===== sub_009fa7b0 | RVA 0x9fa7b0 | file +0x25c0 | ev_642a92544a0a4a3fdc1bcd0f7fa8b5e69a2399c14dc170dd0293e9c08b83e6d0 =====
 * Body: [{"start":"0x9fa7b0","end":"0x9fb1eb"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong sub_009fa7b0(ulong param_1)

{
  uint uVar1;
  undefined4 uVar2;
  long lVar3;
  long lVar4;
  int iVar5;
  int iVar6;
  long lVar7;
  ulong uVar8;
  long lVar9;
  int iVar10;
  undefined8 uVar11;
  ulong uVar12;
  undefined8 uVar13;
  undefined8 uVar14;
  ulong uVar15;
  undefined8 uVar16;
  ulong *in_GS_OFFSET;
  bool bVar17;
  long local_78;
  ulong local_70;
  ulong local_68;
  undefined8 local_60;
  undefined8 local_58;
  ulong local_50;
  ulong local_48;
  uint local_3c;
  long local_38;
  
  lVar4 = _DAT_03badfe0;
  local_38 = _DAT_0391c310;
  iVar6 = *(int *)(_DAT_03badfe0 + 0x118);
  iVar5 = iVar6;
  if (iVar6 < 0x1f500) {
    if (((iVar6 == 0x1f100) || (iVar6 == 0x1f200)) || (iVar6 == 0x1f400)) {
LAB_009fa831:
      if (_DAT_03bb4090 != 0) {
        func_0x00461ba0();
        _DAT_03bb4090 = 0;
        iVar5 = *(int *)(lVar4 + 0x118);
      }
    }
  }
  else if (((iVar6 == 0x1f500) || (iVar6 == 0x200f200)) || (iVar6 == 0x2f100)) goto LAB_009fa831;
  uVar15 = 0x70000000;
  uVar16 = 0x1800000;
  iVar10 = 0x200000;
  uVar14 = 0x8000000;
  uVar11 = 0x2800000;
  local_78 = 0;
  if (iVar5 < 0x1f200) {
    if (iVar5 < 0x10100) {
      if (iVar5 < 0xf100) {
        if (iVar5 == 0) goto LAB_009fab71;
        if (iVar5 == 0xf000) goto LAB_009faaa4;
      }
      else {
        if (iVar5 == 0xf100) {
LAB_009faaa4:
          func_0x0025d410(0x13617b5);
          *(byte *)(lVar4 + 0x141) = *(byte *)(lVar4 + 0x141) | 0x20;
          local_78 = 0x8000000;
LAB_009faabe:
          *(byte *)(lVar4 + 0x141) = *(byte *)(lVar4 + 0x141) | 1;
          uVar15 = 0x1c000000;
          uVar12 = 0x10000000;
          uVar11 = 0xa800000;
          local_50 = 0;
          uVar14 = 0xa800000;
          iVar10 = 0xa800000;
          uVar16 = 0x9800000;
          local_70 = 0x20000000;
          local_60 = 0x9800000;
          local_58 = 0x9800000;
          local_68 = 0x1c000000;
          local_48 = local_68;
          goto LAB_009fac07;
        }
        if (iVar5 == 0x10000) {
          *(byte *)(lVar4 + 0x141) = *(byte *)(lVar4 + 0x141) | 1;
          goto LAB_009faa63;
        }
      }
LAB_009fab5f:
      func_0x00b044d0(0,0,0x18d1870);
    }
    else {
      if (iVar5 < 0x10300) {
        if (iVar5 == 0x10100) goto LAB_009faa63;
        if (iVar5 == 0x10200) {
          uVar15 = 0x60000000;
          uVar12 = 0;
          uVar14 = 0x2800000;
          iVar10 = 0x2800000;
          local_70 = 0;
          local_78 = 0;
          local_50 = 0x70000000;
          local_60 = 0x1800000;
          local_58 = 0x1800000;
          local_68 = 0x60000000;
          local_48 = local_68;
          goto LAB_009fac07;
        }
        goto LAB_009fab5f;
      }
      if (iVar5 != 0x10300) {
        if (iVar5 == 0x1f000) goto LAB_009faabe;
        if (iVar5 == 0x1f100) goto LAB_009faa06;
        goto LAB_009fab5f;
      }
    }
LAB_009fab71:
    *(byte *)(lVar4 + 0x141) = *(byte *)(lVar4 + 0x141) | 1;
    lVar7 = func_0x00a08670();
    local_68 = 0x1c000000;
    if (lVar7 == 0) {
      uVar15 = 0x40000000;
    }
    else {
      iVar5 = func_0x00acce10();
      uVar15 = (ulong)((uint)(iVar5 != 0) << 0x1e) + 0x40000000;
    }
    uVar14 = 0x10000000;
    uVar11 = 0x4000000;
    uVar16 = 0x4000000;
    iVar10 = 0x200000;
    uVar12 = 0;
    local_70 = 0;
    local_78 = 0;
    local_50 = 0;
    local_60 = 0x200000;
    local_58 = 0x10000000;
    local_48 = 0x200000;
  }
  else {
    if (iVar5 < 0x20100) {
      if (iVar5 < 0x1f400) {
        if ((iVar5 != 0x1f200) && (iVar5 != 0x1f300)) goto LAB_009fab5f;
      }
      else if ((iVar5 != 0x1f400) && (iVar5 != 0x1f500)) {
        if (iVar5 == 0x20000) goto LAB_009faa63;
        goto LAB_009fab5f;
      }
LAB_009faa06:
      uVar11 = 0x1800000;
      uVar14 = 0x1800000;
      iVar10 = 0x1800000;
      local_60 = 0x1800000;
      local_58 = 0x1800000;
      local_68 = 0x70000000;
    }
    else {
      if (iVar5 < 0x20f00) {
        if ((iVar5 != 0x20100) && (iVar5 != 0x20200)) goto LAB_009fab5f;
LAB_009faa63:
        uVar12 = 0;
        local_70 = 0;
        local_78 = 0;
        local_50 = 0;
        local_60 = 0x200000;
        local_58 = 0x8000000;
        local_48 = 0x200000;
        local_68 = 0x70000000;
        goto LAB_009fac07;
      }
      if (iVar5 != 0x20f00) {
        if (iVar5 == 0x2f000) goto LAB_009faabe;
        if (iVar5 == 0x2f100) goto LAB_009faa06;
        goto LAB_009fab5f;
      }
      uVar15 = 0x1c000000;
      uVar11 = 0x7000000;
      uVar14 = 0x7000000;
      iVar10 = 0x7000000;
      uVar16 = 0x7000000;
      local_60 = 0x7000000;
      local_58 = 0x7000000;
      local_68 = 0x1c000000;
    }
    local_70 = 0;
    local_78 = 0;
    uVar12 = 0;
    local_50 = 0;
    local_48 = local_68;
  }
LAB_009fac07:
  iVar5 = *(int *)(lVar4 + 0x118);
  if (iVar5 < 0x1f100) {
    _DAT_036c678c = 8;
    if (0x100ff < iVar5) {
      if (iVar5 < 0x10300) {
        if ((iVar5 == 0x10100) || (iVar5 == 0x10200)) goto LAB_009fad0f;
      }
      else {
        if (iVar5 == 0x10300) goto LAB_009fad1e;
        if (iVar5 == 0x1f000) goto LAB_009facf0;
      }
      goto LAB_009faf87;
    }
    if (iVar5 < 0xf100) {
      if (iVar5 != 0) {
        if (iVar5 == 0xf000) goto LAB_009facf0;
        goto LAB_009faf87;
      }
LAB_009fad1e:
      uVar8 = 0x200000;
    }
    else {
      if (iVar5 != 0xf100) {
        if (iVar5 == 0x10000) goto LAB_009fad0f;
        goto LAB_009faf87;
      }
LAB_009facf0:
      _DAT_036c678c = *(int *)(lVar4 + 0x120);
      uVar8 = 0x4000000;
    }
  }
  else {
    if (iVar5 < 0x1f500) {
      if (iVar5 < 0x1f300) {
        if ((iVar5 == 0x1f100) || (iVar5 == 0x1f200)) {
LAB_009fad0f:
          uVar8 = 0x200000;
          _DAT_036c678c = 9;
          goto LAB_009fad26;
        }
      }
      else if ((iVar5 == 0x1f300) || (iVar5 == 0x1f400)) goto LAB_009fad0f;
    }
    else if (iVar5 < 0x20100) {
      if ((iVar5 == 0x1f500) || (iVar5 == 0x20000)) goto LAB_009fad0f;
    }
    else if ((iVar5 == 0x20100) || (iVar5 == 0x20200)) goto LAB_009fad0f;
LAB_009faf87:
    uVar8 = 0x200000;
    _DAT_036c678c = 0;
  }
LAB_009fad26:
  *(int *)(lVar4 + 0x124) = _DAT_036c678c;
  uVar1 = *(uint *)(lVar4 + 0x110);
  if (uVar1 != 0) {
    func_0x00b044d0(0,0,0x18d18a0,uVar1 >> 0x18,uVar1 >> 0xc & 0xfff,uVar1 & 0xfff);
  }
  uVar1 = *(uint *)(lVar4 + 0x114);
  if (uVar1 != 0) {
    func_0x00b044d0(0,0,0x18d18e0,uVar1 >> 0x18,uVar1 >> 0xc & 0xfff,uVar1 & 0xfff);
  }
  if (param_1 == 0) {
    uVar13 = 0x12f8276;
    if (iVar6 == 0x10300) {
      uVar13 = 0x139517c;
    }
    uVar15 = func_0x00a029f0(uVar13,local_48,uVar15,local_68,lVar4 + 0xb0);
    if ((int)uVar15 != 0) goto LAB_009faf61;
  }
  else {
    if ((((param_1 & 0x1fffff) != 0) || (param_1 < local_48)) || (uVar15 < param_1)) {
      func_0x00b044d0(0,0,0x18d1920,param_1);
      uVar15 = 0x16;
      goto LAB_009faf61;
    }
    *(ulong *)(lVar4 + 0xb0) = param_1;
    *(long *)(lVar4 + 0x40) = *(long *)(lVar4 + 0x40) + (param_1 - local_68);
  }
  uVar15 = func_0x00a029f0(0x130d5e4,0,0,0,(long *)(lVar4 + 0xa0));
  if ((int)uVar15 == 0) {
    uVar13 = 0x1286f66;
    if (iVar6 == 0x10300) {
      uVar13 = 0x12b9e14;
    }
    uVar15 = func_0x00a029f0(uVar13,local_60,local_58,uVar16,lVar4 + 0xd8);
    if ((int)uVar15 == 0) {
      uVar16 = 0x13617eb;
      if (iVar6 == 0x10300) {
        uVar16 = 0x13617d8;
      }
      uVar15 = func_0x00a029f0(uVar16,iVar10,uVar14,uVar11,lVar4 + 0xf8);
      local_3c = (uint)uVar15;
      if (local_3c == 0) {
        *(ulong *)(lVar4 + 0xb8) = local_70;
        *(ulong *)(lVar4 + 0xc0) = uVar12;
        lVar7 = local_78 + uVar8 + (local_70 | uVar12) + *(ulong *)(lVar4 + 0xb0);
        *(long *)(lVar4 + 0xa8) = lVar7;
        *(int *)(lVar4 + 0x134) = (int)(uVar8 >> 0xe);
        *(ushort *)(lVar4 + 0x140) =
             (ushort)*(undefined4 *)(lVar4 + 0x140) & 0xefff |
             (ushort)(*(ulong *)(lVar4 + 0xb0) < local_50 ||
                     _DAT_036c678c == *(int *)(lVar4 + 0x120)) << 0xc;
        if ((_DAT_03badfd8 & 1) == 0) {
          uVar15 = _DAT_03badfd8 & 0xfffffffffffffff0;
        }
        else {
          uVar15 = 0;
        }
        if (uVar15 == *in_GS_OFFSET) {
          uVar15 = func_0x009f7bc0(lVar7,0x200000,0,0);
        }
        else {
          func_0x00c4bb20(0x3badfc0,0,0,0);
          uVar15 = func_0x009f7bc0(lVar7,0x200000,0,0);
          func_0x00c4c4b0(0x3badfc0,0,0);
        }
        *(ulong *)(lVar4 + 0x68) = uVar15;
        iVar6 = *(int *)(lVar4 + 0x120);
        if ((*(int *)(lVar4 + 0x124) == iVar6) && (uVar15 < _DAT_03bb4120 - 0x63400000U)) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
        lVar7 = *(long *)(lVar4 + 0xa0);
        if (lVar7 == 0) {
          *(int *)(lVar4 + 0x128) = iVar6;
        }
        else {
          iVar10 = iVar6 + 4;
          *(int *)(lVar4 + 0x128) = iVar10;
          uVar11 = func_0x009f7b30(lVar7,0x200000,0,0);
          *(undefined8 *)(lVar4 + 0x60) = uVar11;
        }
        if ((*(byte *)(*(long *)(lVar4 + 8) + 0x5f) & 0x20) != 0) {
          *(byte *)(lVar4 + 0x141) = *(byte *)(lVar4 + 0x141) | 0x40;
        }
        uVar15 = *(ulong *)(lVar4 + 0xd8);
        uVar12 = 0x4000000;
        if (uVar15 < 0x4000000) {
          uVar12 = uVar15;
        }
        if ((_DAT_03badfd8 & 1) == 0) {
          uVar8 = _DAT_03badfd8 & 0xfffffffffffffff0;
        }
        else {
          uVar8 = 0;
        }
        if (uVar8 == *in_GS_OFFSET) {
          func_0x009f7ea0(0,uVar15,uVar12,0x200000,0,1,lVar4 + 0xd0,lVar4 + 0xe0,lVar4 + 0xe8);
        }
        else {
          func_0x00c4bb20(0x3badfc0,0,0,0);
          func_0x009f7ea0(0,uVar15,uVar12,0x200000,0,1,lVar4 + 0xd0,lVar4 + 0xe0,lVar4 + 0xe8);
          func_0x00c4c4b0(0x3badfc0,0,0);
        }
        bVar17 = false;
        func_0x00ab2f00(0,lVar4,&local_3c);
        uVar15 = (ulong)local_3c;
        if (local_3c == 0) {
          lVar7 = *(long *)(lVar4 + 0x68);
          lVar3 = *(long *)(lVar4 + 0xa8);
          uVar2 = *(undefined4 *)(lVar4 + 0x120);
          if (((*(int *)(lVar4 + 0x118) == 0x10300) || (*(int *)(lVar4 + 0x118) == 0)) &&
             (lVar9 = func_0x00a08670(7), lVar9 != 0)) {
            iVar6 = func_0x00acce10();
            bVar17 = iVar6 != 0;
          }
          func_0x006166c0(uVar2,lVar7,lVar3 + lVar7,bVar17);
          func_0x00616cb0(*(undefined4 *)(lVar4 + 0x120));
          if (*(long *)(lVar4 + 0xa0) != 0) {
            func_0x006166c0(iVar10,*(long *)(lVar4 + 0x60),
                            *(long *)(lVar4 + 0xa0) + *(long *)(lVar4 + 0x60),0);
            *(int *)((long)*(int *)(lVar4 + 0x120) * 0x8c0 + 0x36ed9a0) = iVar10;
          }
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
      }
    }
  }
LAB_009faf61:
  if (_DAT_0391c310 != local_38) {
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  return uVar15;
}


