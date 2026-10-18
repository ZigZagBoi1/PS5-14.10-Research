/* REA 6.7.0 / Ghidra 12.1.4 recovered pseudocode, not original or buildable C.
 * Input: deep_601.bin, SHA256 c77f3250fe8e9a05eef2ad3cf668f0fd3a912ea740faab21408cc3157068a086
 * File offset zero maps to kernel RVA 0xca0630; runtime VA = 0xffffffff8a9c0000 + RVA.
 * External bodies/types/data missing from this raw window remain unknown.
 * Function names are analyst seeds or Ghidra-generated; instruction truth is in .rea.asm.
 */

/* ===== sys_601 | RVA 0xca0630 | file +0x0 | ev_79718a47f331a9203eb4753d52c57b2fd3bc1fc5d2a640c9bb4d7a0d73e5e0cb =====
 * Body: [{"start":"0xca0630","end":"0xca067e"},{"start":"0xca221c","end":"0xca223d"},{"start":"0xca230a","end":"0xca2310"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Removing unreachable block (ram,0x00ca230a) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sys_601(undefined8 param_1,uint *param_2)

{
  undefined8 uVar1;
  code *UNRECOVERED_JUMPTABLE;
  
  if (0x27 < (ulong)*param_2) {
    return 0x4e;
  }
  UNRECOVERED_JUMPTABLE = (code *)((long)*(int *)((ulong)*param_2 * 4 + 0x1a51160) + 0x1a51160);
                    /* WARNING: Could not emulate address calculation at 0x00ca0676 */
                    /* WARNING: Treating indirect jump as call */
  uVar1 = (*UNRECOVERED_JUMPTABLE)(param_1,param_2,UNRECOVERED_JUMPTABLE,0x1a51160,param_1);
  return uVar1;
}



/* ===== sub_00ca2320 | RVA 0xca2320 | file +0x1cf0 | ev_18f521ec9792bb0b32e5bee445c40deb11bd6e370458a52499d0d817a1b05db7 =====
 * Body: [{"start":"0xca2320","end":"0xca244c"},{"start":"0xca2450","end":"0xca29df"},{"start":"0xca2a56","end":"0xca2a62"},{"start":"0xca2d9a","end":"0xca2dd6"},{"start":"0xca2e18","end":"0xca2e1e"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong sub_00ca2320(long param_1,undefined8 param_2,long param_3)

{
  long lVar1;
  code *pcVar2;
  uint uVar3;
  long *plVar4;
  undefined8 uVar5;
  long *plVar6;
  int iVar7;
  uint uVar8;
  long lVar9;
  ulong uVar10;
  long *plVar11;
  undefined8 *in_GS_OFFSET;
  undefined8 local_90;
  undefined4 local_88;
  undefined1 local_7c [8];
  uint local_74;
  long local_70;
  uint local_68;
  uint local_5c;
  uint local_58;
  undefined4 local_50;
  undefined8 local_4c;
  undefined4 local_44;
  ulong local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  local_40 = 0;
  func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
  uVar3 = func_0x00259280(param_2,local_7c,0x3c);
  uVar10 = (ulong)uVar3;
  if (uVar3 != 0) goto LAB_00ca2383;
  if ((*(ulong *)(param_1 + 0x528) & 0x100) == 0) {
    uVar10 = 1;
    if ((7 < local_58) || ((0xb8U >> (local_58 & 0x1f) & 1) == 0)) goto LAB_00ca2383;
    if (((local_58 & 0xfffffffe) == 4) && (local_68 == 0)) {
      func_0x004c6a00(*(long *)(param_1 + 8) + 0x148,0,0,0);
      lVar1 = *(long *)(*(long *)(param_1 + 8) + 0x568);
      if (lVar1 != 0) {
        plVar11 = (long *)0x0;
        func_0x004c6a00(lVar1 + 0x28,0,0,0);
        plVar6 = *(long **)(lVar1 + 0x40);
        if (plVar6 != (long *)0x0) {
          plVar11 = plVar6;
          do {
            plVar4 = (long *)*plVar11;
            if (((*(long *)((long)plVar11 + 0x14) == local_70) &&
                (*(uint *)((long)plVar11 + 0x2c) == local_58)) &&
               (*(uint *)(plVar11 + 2) == local_74)) {
              if (plVar6 != plVar11) goto LAB_00ca2476;
              plVar6 = (long *)*plVar6;
              *(long *)(lVar1 + 0x40) = (long)plVar6;
              if (plVar6 == (long *)0x0) {
                *(long **)(lVar1 + 0x48) = (long *)(lVar1 + 0x40);
                iVar7 = *(int *)(lVar1 + 0xf8) + -1;
                *(int *)(lVar1 + 0xf8) = iVar7;
                *(int *)(lVar1 + 0x30) = iVar7;
                goto LAB_00ca24d6;
              }
              iVar7 = *(int *)(lVar1 + 0xf8) + -1;
              *(int *)(lVar1 + 0xf8) = iVar7;
              *(int *)(lVar1 + 0x30) = iVar7;
              goto LAB_00ca28f6;
            }
            plVar11 = plVar4;
          } while (plVar4 != (long *)0x0);
          plVar11 = (long *)0x0;
        }
        goto LAB_00ca24d6;
      }
      func_0x004c6fa0(*(long *)(param_1 + 8) + 0x148,0,0,0);
    }
  }
  goto LAB_00ca2530;
LAB_00ca2476:
  do {
    plVar4 = plVar6;
    plVar6 = (long *)*plVar4;
  } while (plVar6 != plVar11);
  lVar9 = *plVar6;
  *plVar4 = lVar9;
  if (lVar9 == 0) {
    *(long **)(lVar1 + 0x48) = plVar4;
  }
  plVar6 = *(long **)(lVar1 + 0x40);
  iVar7 = *(int *)(lVar1 + 0xf8) + -1;
  *(int *)(lVar1 + 0xf8) = iVar7;
  *(int *)(lVar1 + 0x30) = iVar7;
  if (plVar6 != (long *)0x0) {
LAB_00ca28f6:
    iVar7 = 0;
    do {
      plVar4 = (long *)*plVar6;
      *(int *)(plVar6 + 1) = iVar7;
      if (*(int *)((long)plVar6 + 0xc) == 1) {
        *(int *)(lVar1 + 0x9c) = iVar7;
      }
      iVar7 = iVar7 + 1;
      plVar6 = plVar4;
    } while (plVar4 != (long *)0x0);
  }
LAB_00ca24d6:
  func_0x004c6fa0(lVar1 + 0x28,0,0,0);
  func_0x004c6fa0(*(long *)(param_1 + 8) + 0x148,0,0,0);
  if (plVar11 != (long *)0x0) {
    if (plVar11[9] != 0) {
      func_0x00c08df0(plVar11[9],0x2c03e80);
    }
    func_0x00c08df0(plVar11,0x2c03e80);
    uVar10 = 0;
    goto LAB_00ca2383;
  }
LAB_00ca2530:
  func_0x00acf5f0(&local_90);
  local_50 = local_88;
  local_4c = local_90;
  local_44 = 0;
  func_0x00c9afc0(*(undefined8 *)(param_1 + 8));
  func_0x004c6a00(*(long *)(param_1 + 8) + 0x148,0,0,0);
  lVar1 = *(long *)(*(long *)(param_1 + 8) + 0x568);
  if (lVar1 == 0) {
    func_0x004c6fa0(*(long *)(param_1 + 8) + 0x148,0,0,0);
    uVar10 = 0x16;
    goto LAB_00ca2383;
  }
  func_0x004c6a00(lVar1 + 0x28,0,0,0);
  iVar7 = *(int *)(lVar1 + 0x30);
  func_0x004c6fa0(lVar1 + 0x28,0,0,0);
  func_0x004c6fa0(*(long *)(param_1 + 8) + 0x148,0,0,0);
  uVar10 = 0x1c;
  if (0x100 < iVar7) goto LAB_00ca2383;
  if ((int)local_58 < 7) {
    if (local_58 - 3 < 2) {
      uVar10 = 0x3f;
      if (0x10000 < local_5c) goto LAB_00ca2383;
    }
    else if (local_58 == 1) {
      lVar1 = *(long *)(param_1 + 8);
      func_0x00c9afc0(lVar1);
      func_0x004c6a00(lVar1 + 0x148,0,0,0);
      lVar9 = *(long *)(lVar1 + 0x568);
      func_0x004c6fa0(lVar1 + 0x148,0,0,0);
      if (*(long *)(lVar9 + 0x58) == 0) {
        uVar5 = func_0x00c08b50(0x80000,0x2c03e10,0x102);
        *(undefined8 *)(lVar9 + 0x58) = uVar5;
      }
      func_0x004c6a00(*(long *)(param_1 + 8) + 0x148,0,0,0);
      lVar1 = *(long *)(*(long *)(param_1 + 8) + 0x568);
      if (lVar1 == 0) {
        func_0x004c6fa0(*(long *)(param_1 + 8) + 0x148,0,0,0);
        uVar10 = 0x16;
        goto LAB_00ca2383;
      }
      func_0x004c6a00(lVar1 + 0x28,0,0,0);
      uVar8 = 0x80000 - *(int *)(lVar1 + 0x50);
      func_0x004c6fa0(lVar1 + 0x28,0,0,0);
      func_0x004c6fa0(*(long *)(param_1 + 8) + 0x148,0,0,0);
      uVar3 = local_68;
      if (uVar8 < local_68) {
        uVar3 = uVar8;
      }
      uVar10 = (ulong)uVar3;
      if ((int)uVar8 < 1) {
        local_40 = 0;
      }
      else {
        uVar5 = func_0x00c08b50(uVar10,0x2bfc080,0x102);
        uVar8 = func_0x00c9c9a0(local_70,uVar5,uVar10);
        if (uVar8 != 0) {
          uVar10 = (ulong)uVar8;
          goto LAB_00ca2836;
        }
        func_0x004c6a00(*(long *)(param_1 + 8) + 0x148,0,0,0);
        lVar9 = *(long *)(param_1 + 8);
        lVar1 = *(long *)(lVar9 + 0x568);
        if (lVar1 == 0) {
          uVar10 = 0x16;
        }
        else {
          func_0x004c6a00(lVar1 + 0x28,0,0,0);
          if ((int)(*(int *)(lVar1 + 0x50) + uVar3) < 0x80001) {
            func_0x002590b0((long)*(int *)(lVar1 + 0x50) + *(long *)(lVar1 + 0x58),uVar5,uVar10);
            *(int *)(lVar1 + 0x50) = *(int *)(lVar1 + 0x50) + uVar3;
            local_40 = uVar10;
          }
          else {
            local_40 = 0;
          }
          uVar10 = 0;
          func_0x004c6fa0(lVar1 + 0x28,0,0,0);
          lVar9 = *(long *)(param_1 + 8);
        }
        func_0x004c6fa0(lVar9 + 0x148,0,0,0);
        func_0x00c08df0(uVar5,0x2bfc080);
        if (lVar1 == 0) goto LAB_00ca2383;
      }
    }
  }
  else if (local_58 == 7) {
    uVar10 = 0x16;
    if ((0x100 < local_68) || (0xf < local_74)) goto LAB_00ca2383;
  }
  else if (local_58 == 100) {
    uVar3 = 0x1000;
    if (local_68 < 0x1000) {
      uVar3 = local_68;
    }
    uVar5 = func_0x00c08b50(uVar3 + 1,0x2bfc080,0x102);
    uVar10 = 0;
    func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
    uVar8 = func_0x00259280(local_70,uVar5,uVar3);
    if (uVar8 != 0) {
      func_0x00c08df0(uVar5,0x2bfc080);
      uVar10 = (ulong)uVar8;
      goto LAB_00ca2383;
    }
    func_0x007b0ae0(uVar5,uVar3);
LAB_00ca2836:
    func_0x00c08df0(uVar5,0x2bfc080);
    goto LAB_00ca2383;
  }
  if (local_58 - 1 < 7) {
                    /* WARNING: Could not emulate address calculation at 0x00ca29d7 */
                    /* WARNING: Treating indirect jump as call */
    uVar10 = (*(code *)((long)*(int *)((ulong)(local_58 - 1) * 4 + 0x1a51234) + 0x1a51234))();
    return uVar10;
  }
  local_40 = 0x16;
  if (param_3 == 0) {
    uVar10 = 0;
  }
  else {
    func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
    uVar3 = func_0x002591d0(&local_40,param_3,8);
    uVar10 = (ulong)uVar3;
  }
LAB_00ca2383:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar2 = (code *)invalidInstructionException();
    (*pcVar2)();
  }
  return uVar10;
}



/* ===== sub_00ca2e20 | RVA 0xca2e20 | file +0x27f0 | ev_865991239f0cdb932d88a309006a63a01e780242cb621ed9cbe6d7f55f60aaf9 =====
 * Body: [{"start":"0xca2e20","end":"0xca2e5c"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_00ca2e20(long param_1)

{
  int iVar1;
  
  if ((*(byte *)(param_1 + 0x468) & 2) == 0) {
    iVar1 = func_0x005e2e80();
    if (iVar1 != 0) {
      return;
    }
  }
  else {
    func_0x00b044d0(0,0,0x1a51400);
  }
  *(byte *)(param_1 + 0x562) = *(byte *)(param_1 + 0x562) | 0x10;
  return;
}



/* ===== sub_00ca2e60 | RVA 0xca2e60 | file +0x2830 | ev_9cfd06788e4534df94e3b8eff45f358b42d970ebf43c5cfbdadc0a0db666ba5b =====
 * Body: [{"start":"0xca2e60","end":"0xca2ebe"},{"start":"0xca2ec0","end":"0xca2fcb"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_00ca2e60(long param_1,undefined8 param_2)

{
  code *pcVar1;
  bool bVar2;
  uint uVar3;
  undefined8 uVar4;
  long *plVar5;
  ulong uVar6;
  undefined8 *in_GS_OFFSET;
  ulong local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  local_40 = 0;
  bVar2 = false;
  func_0x00c4b350(0x3589e60,0,0,0);
  if (_DAT_03589e80 == (long *)0x0) {
    func_0x00c4c300(0x3589e60,0,0);
    uVar4 = 3;
  }
  else {
    uVar6 = 0;
    plVar5 = _DAT_03589e80;
    do {
      func_0x004c6a00(plVar5 + 0x29,0,0,0);
      if (param_1 == (int)plVar5[0x8c]) {
        uVar3 = (uint)plVar5[0xac];
        bVar2 = true;
        uVar6 = (uVar3 >> 1 & 1) + (uVar3 >> 0x16 & 1) * 2 + (uVar3 >> 0x1c & 1) * 4 | uVar6;
        if ((plVar5[0xac] & 0x10400002U) != 0) {
          local_40 = uVar6;
        }
      }
      func_0x004c6fa0(plVar5 + 0x29,0,0);
      plVar5 = (long *)*plVar5;
    } while (plVar5 != (long *)0x0);
    func_0x00c4c300(0x3589e60,0,0);
    if (bVar2) {
      func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
      uVar4 = func_0x002591d0(&local_40,param_2,8);
    }
    else {
      uVar4 = 3;
    }
  }
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar1 = (code *)invalidInstructionException();
    (*pcVar1)();
  }
  return uVar4;
}



/* ===== sub_00ca2fd0 | RVA 0xca2fd0 | file +0x29a0 | ev_98df58d1d7a2eadf563eda5d51c0eb4c7c8e8f2173624a4258904344f356b758 =====
 * Body: [{"start":"0xca2fd0","end":"0xca3051"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_00ca2fd0(undefined4 param_1,undefined4 param_2,undefined8 param_3)

{
  undefined8 *puVar1;
  
  puVar1 = (undefined8 *)func_0x00c08b50(0x28,0x2bfc080,0x102);
  *puVar1 = 3;
  puVar1[1] = 8;
  puVar1[2] = CONCAT44(param_1,param_2);
  puVar1[3] = 8;
  puVar1[4] = param_3;
  func_0x00c9aa90(puVar1,0x28);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== sub_00ca3060 | RVA 0xca3060 | file +0x2a30 | ev_71b8517731bcefce6f56609530366a562364ded744da47646eed2aae64aade1c =====
 * Body: [{"start":"0xca3060","end":"0xca30d0"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_00ca3060(long param_1,ulong param_2,undefined8 param_3,undefined8 param_4,
                 undefined4 param_5,undefined4 param_6)

{
  code *pcVar1;
  undefined8 local_50;
  undefined8 local_48;
  ulong local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined4 local_20;
  undefined4 local_1c;
  long local_18;
  
  local_18 = _DAT_0391c310;
  local_50 = 3;
  local_48 = 9;
  local_40 = param_2 & 0xffffffff | param_1 << 0x20;
  local_38 = 0x18;
  local_30 = param_3;
  local_28 = param_4;
  local_20 = param_5;
  local_1c = param_6;
  func_0x00c9aa90(&local_50,0x38);
  if (_DAT_0391c310 == local_18) {
    return;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* ===== sub_00ca30e0 | RVA 0xca30e0 | file +0x2ab0 | ev_4dfb6dd13394af129e13ba235bba292ae1b93c7ad32080a076ec8e5f0f4e0815 =====
 * Body: [{"start":"0xca30e0","end":"0xca32af"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_00ca30e0(undefined8 param_1,int param_2)

{
  if (param_2 != 2) {
    if (param_2 == 1) {
      func_0x006dfbb0(_DAT_03e0d880);
    }
    else {
      if (param_2 != 0) {
        return 0x2d;
      }
      _DAT_03e0d8ac = 0;
      _DAT_03e0d8a8 = 0;
      func_0x004c7dd0(0x3e0d8a0,0x136dfed,0x136dfed,0);
      _DAT_03e0d870 = 0;
      _DAT_03e0d878 = &DAT_03e0d870;
      _DAT_03e0d880 = func_0x006df570(0x10,0x2c04180,0,0,0,0,0x180,0x1293d1d);
      _DAT_03e0d960 = func_0x0073dd40(0,0x12e769e,0x267e18,0x1305180,0,20000);
      _DAT_03e0d968 = func_0x0073dd40(0,0x13842de,0x268440,0x12dc099,0,20000);
      _DAT_03e0d970 = func_0x0073dd40(0,0x133ab8b,0x267e20,0x127ef0c,0,20000);
      _DAT_03e0d978 = func_0x0073dd40(0,0x13251c7,0x26fc98,0x12d1b27,0,20000);
      _DAT_03e0d980 = func_0x0073dd40(0,0x132fb0b,0x267e28,0x138d554,0,20000);
      _DAT_03e0d988 = func_0x0073dd40(0,0x13a2f6d,0x267e30,0x127ef21,0,20000);
      func_0x00258ff0(0x3e0d8b0,0x78);
      DAT_03e0d720 = 1;
    }
  }
  return 0;
}



/* ===== sub_00ca32b0 | RVA 0xca32b0 | file +0x2c80 | ev_33ec68434fc15808ef0bd9b5f3dcf38389efaac86206aa995ef0dd727c1156fb =====
 * Body: [{"start":"0xca32b0","end":"0xca3412"},{"start":"0xca3420","end":"0xca34a3"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_00ca32b0(undefined8 param_1,long param_2)

{
  long *plVar1;
  long *plVar2;
  int iVar3;
  undefined8 uVar4;
  int iVar5;
  ulong uVar6;
  int iVar7;
  
  iVar3 = 0;
  func_0x004c6a00(0x3e0d868,0,0,0);
  if (_DAT_03e0d870 == (long *)0x0) {
    iVar3 = func_0x00c06260(_DAT_03e0d880,0x3e0d850,0x1000,0x1305178,0,0,0x100);
  }
  func_0x004c6fa0(0x3e0d868,0,0,0);
  uVar4 = func_0x00c08b50(0x4000,0x2bfc080,2);
  uVar6 = *(ulong *)(param_2 + 0x18);
  if (iVar3 == 0 && 0 < (long)uVar6) {
    while( true ) {
      if (0x3fff < uVar6) {
        uVar6 = 0x4000;
      }
      func_0x004c6a00(0x3e0d868,0,0,0);
      plVar2 = _DAT_03e0d870;
      if (_DAT_03e0d870 == (long *)0x0) break;
      iVar3 = (int)_DAT_03e0d870[2];
      plVar1 = _DAT_03e0d870 + 1;
      iVar7 = *(int *)((long)_DAT_03e0d870 + 0x14) - iVar3;
      iVar5 = (int)uVar6;
      if (iVar7 < iVar5) {
        func_0x002590b0(uVar4,(long)iVar3 + *plVar1,(long)iVar7);
        _DAT_03e0d870 = (long *)*_DAT_03e0d870;
        if (_DAT_03e0d870 == (long *)0x0) {
          _DAT_03e0d878 = &DAT_03e0d870;
        }
        iVar3 = 0;
        func_0x004c6fa0(0x3e0d868,0,0);
        func_0x00c08df0(plVar2[1],0x2c03da0);
        func_0x00c08df0(plVar2,0x2c03da0);
        iVar5 = iVar7;
        if (iVar7 == 0) goto LAB_00ca3482;
      }
      else {
        *(int *)(_DAT_03e0d870 + 2) = iVar3 + iVar5;
        func_0x002590b0(uVar4,(long)iVar3 + *plVar1,uVar6);
        func_0x004c6fa0(0x3e0d868,0,0);
      }
      iVar3 = func_0x00782520(uVar4,iVar5,param_2);
      uVar6 = *(ulong *)(param_2 + 0x18);
      if (((long)uVar6 < 1) || (iVar3 != 0)) goto LAB_00ca3482;
    }
    iVar3 = 0;
    func_0x004c6fa0(0x3e0d868,0,0,0);
  }
LAB_00ca3482:
  func_0x00c08df0(uVar4,0x2bfc080);
  return iVar3;
}



/* ===== sub_00ca34b0 | RVA 0xca34b0 | file +0x2e80 | ev_73635c7ec9cbeb3a5a9065079ef20fa7053ee547825c83801964f1a6e87feea5 =====
 * Body: [{"start":"0xca34b0","end":"0xca3758"},{"start":"0xca3760","end":"0xca37f6"},{"start":"0xca3800","end":"0xca3826"},{"start":"0xca3830","end":"0xca38c0"},{"start":"0xca38d0","end":"0xca3ae0"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_00ca34b0(undefined8 param_1,long param_2)

{
  long *plVar1;
  long lVar2;
  long lVar3;
  ulong uVar4;
  long lVar5;
  code *pcVar6;
  uint uVar7;
  uint uVar8;
  int iVar9;
  undefined8 *puVar10;
  uint uVar11;
  long *plVar12;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  uVar8 = (*(uint *)(param_2 + 0xa2c) & 0xff) << 8 | *(uint *)(param_2 + 0xa30);
  uVar7 = uVar8 | 0x80;
  if ((~*(uint *)(param_2 + 0x560) & 9) != 0) {
    uVar7 = uVar8;
  }
  lVar2 = *(long *)(param_2 + 0x10);
  if (((((lVar2 != 0) && (lVar3 = *(long *)(lVar2 + 8), lVar3 != 0)) && (lVar3 != 0x3588ef8)) &&
      ((*(ulong *)(lVar3 + 0x560) & 1) != 0)) &&
     ((*(long *)(lVar3 + 0xe0) == 0 || (*(int *)(*(long *)(lVar3 + 0xe0) + 0xbc) != 0)))) {
    local_58 = 3;
    local_50 = 6;
    local_48 = CONCAT44(*(undefined4 *)(lVar3 + 0xbc),*(undefined4 *)(lVar2 + 0x9c));
    local_40 = 0;
    if (DAT_03e0d720 == '\x01') {
      func_0x00c9aa90(&local_58,0x20);
    }
  }
  uVar8 = 0;
  func_0x00c4b350(0x3589e40,0,0,0);
  lVar2 = param_2 + 0x148;
  func_0x004c6a00(lVar2,0,0,0);
  if (*(long *)(param_2 + 0xe0) != 0) {
    iVar9 = func_0x00609110(*(undefined8 *)(*(long *)(param_2 + 0xe0) + 0x40));
    uVar8 = (uint)(iVar9 != 0);
  }
  iVar9 = func_0x00609110(*(undefined8 *)(param_2 + 0x40));
  uVar11 = uVar8;
  if ((iVar9 != 0) && (uVar11 = uVar8 + 2, *(int *)(param_2 + 0xbc) == _DAT_035ab090)) {
    uVar11 = uVar8;
  }
  lVar3 = *(long *)(param_2 + 0x568);
  *(undefined8 *)(param_2 + 0x568) = 0;
  func_0x004c6fa0(lVar2,0,0,0);
  func_0x00c4c300(0x3589e40,0,0);
  func_0x004c6a00(lVar2,0,0,0);
  if (lVar3 != 0) {
    uVar4 = *(ulong *)(param_2 + 0x560);
    if ((uVar4 & 0xffffffff80000000) != 0) {
      *(ulong *)(param_2 + 0x560) = (ulong)((uint)uVar4 & 0x7fffffff);
      *(undefined4 *)(lVar3 + 0x100) = 7;
      func_0x00c06910();
      func_0x004c6fa0(lVar2,0,0,0);
      while (iVar9 = func_0x004eb160(_DAT_03bf6aa0,lVar3 + 0x130,0), iVar9 != 0) {
        func_0x004eb3c0(_DAT_03bf6aa0,lVar3 + 0x130);
      }
      while (iVar9 = func_0x004eb160(_DAT_03bf6aa0,lVar3 + 0x110,0), iVar9 != 0) {
        func_0x004eb3c0(_DAT_03bf6aa0,lVar3 + 0x110);
      }
      goto LAB_00ca36b8;
    }
    *(undefined4 *)(lVar3 + 0x100) = 7;
    func_0x00c06910();
  }
  func_0x004c6fa0(lVar2,0,0,0);
LAB_00ca36b8:
  uVar8 = *(uint *)(param_2 + 0xbc);
  puVar10 = (undefined8 *)func_0x00c08b50(0x28,0x2bfc080,0x102);
  *puVar10 = 3;
  puVar10[1] = 2;
  puVar10[2] = (long)(int)uVar7 | (ulong)uVar8 << 0x20;
  puVar10[3] = 8;
  *(uint *)(puVar10 + 4) = uVar11;
  func_0x00c9aa90(puVar10,0x28);
  func_0x00c08df0(puVar10,0x2bfc080);
  func_0x004c6a00(lVar2,0,0,0);
  if (lVar3 != 0) {
    *(undefined4 *)(lVar3 + 200) = 0xffffffff;
  }
  for (lVar5 = *(long *)(param_2 + 0x10); lVar5 != 0; lVar5 = *(long *)(lVar5 + 0x10)) {
    if ((*(ulong *)(lVar5 + 0x528) & 0x400) != 0) {
      *(ulong *)(lVar5 + 0x528) = *(ulong *)(lVar5 + 0x528) & 0xfffffffffffffbff;
      if (*(long *)(lVar5 + 0x578) != 0) {
        func_0x00c08df0(*(long *)(lVar5 + 0x578),0x2c03e10);
        *(undefined8 *)(lVar5 + 0x578) = 0;
      }
      if (*(long *)(lVar5 + 0x580) != 0) {
        func_0x00c08df0(*(long *)(lVar5 + 0x580),0x2c03e10);
        *(undefined8 *)(lVar5 + 0x580) = 0;
      }
    }
  }
  func_0x004c6fa0(lVar2,0,0,0);
  if (lVar3 != 0) {
    plVar12 = *(long **)(lVar3 + 0xd0);
    if (plVar12 != (long *)0x0) {
      plVar1 = (long *)(lVar3 + 0xd0);
      do {
        lVar2 = *plVar12;
        *plVar1 = lVar2;
        if (lVar2 == 0) {
          *(long **)(lVar3 + 0xd8) = plVar1;
          lVar2 = plVar12[4];
        }
        else {
          lVar2 = plVar12[4];
        }
        if ((lVar2 != 0) && (plVar12[3] != 0)) {
          func_0x00c08df0(plVar12[3],0x2c03e10);
        }
        func_0x00c08df0(plVar12,0x2c03e10);
        plVar12 = (long *)*plVar1;
      } while (plVar12 != (long *)0x0);
    }
    lVar2 = lVar3 + 0x28;
    func_0x004c6a00(lVar2,0,0,0);
    *(undefined4 *)(lVar3 + 0x88) = 1;
    *(undefined4 *)(lVar3 + 0x38) = 1;
    if (*(int *)(lVar3 + 0x34) == 2) {
      func_0x0073ef00(lVar3);
    }
    func_0x004c6fa0(lVar2,0,0,0);
    func_0x0073e530(lVar3);
    func_0x004c6a00(lVar2,0,0,0);
    iVar9 = *(int *)(lVar3 + 0x30);
    while (iVar9 != 0) {
      func_0x004c6fa0(lVar2,0,0,0);
      func_0x004c6a00(lVar2,0,0);
      *(int *)(lVar3 + 0x30) = *(int *)(lVar3 + 0x30) + -1;
      plVar12 = *(long **)(lVar3 + 0x40);
      lVar5 = *plVar12;
      *(long *)(lVar3 + 0x40) = lVar5;
      if (lVar5 == 0) {
        *(long **)(lVar3 + 0x48) = (long *)(lVar3 + 0x40);
      }
      func_0x004c6fa0(lVar2,0,0,0);
      if (plVar12[9] != 0) {
        func_0x00c08df0(plVar12[9],0x2c03e80);
      }
      func_0x00c08df0(plVar12);
      func_0x004c6a00(lVar2,0,0);
      iVar9 = *(int *)(lVar3 + 0x30);
    }
    if (*(long *)(lVar3 + 0x40) != 0) {
      func_0x0025d410(0x128925e);
    }
    func_0x004c6fa0(lVar2,0,0,0);
    func_0x004c7e50(lVar2);
    if (*(long *)(lVar3 + 0xc0) != 0) {
      func_0x00c08df0(*(long *)(lVar3 + 0xc0),0x2c03e10);
      *(undefined8 *)(lVar3 + 0xc0) = 0;
    }
    if (*(long *)(lVar3 + 0x58) != 0) {
      func_0x00c08df0(*(long *)(lVar3 + 0x58),0x2c03e10);
      *(undefined8 *)(lVar3 + 0x58) = 0;
    }
    if (*(long *)(lVar3 + 0xf0) != 0) {
      func_0x00c08df0(*(long *)(lVar3 + 0xf0),0x2c03e10);
      *(undefined8 *)(lVar3 + 0xf0) = 0;
    }
    if (*(long *)(lVar3 + 0x188) != 0) {
      func_0x00c08df0(*(long *)(lVar3 + 0x188),0x2c03e10);
      *(undefined8 *)(lVar3 + 0x188) = 0;
    }
    if (*(long *)(lVar3 + 400) != 0) {
      func_0x00c08df0(*(long *)(lVar3 + 400),0x2c03e10);
      *(undefined8 *)(lVar3 + 400) = 0;
    }
    func_0x00c08df0(lVar3,0x2c03e10);
  }
  iVar9 = *(int *)(param_2 + 0xbc);
  func_0x004c6a00(0x3e0d8a0,0,0,0);
  if ((_DAT_03e0d8a8 == iVar9) || (_DAT_03e0d8ac == iVar9)) {
    _DAT_03e0d8ac = 0;
    _DAT_03e0d8a8 = 0;
  }
  func_0x004c6fa0(0x3e0d8a0,0,0,0);
  if (_DAT_0391c310 == local_38) {
    return;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar6 = (code *)invalidInstructionException();
  (*pcVar6)();
}



/* ===== sub_00ca3af0 | RVA 0xca3af0 | file +0x34c0 | ev_c107d1b42ef56acfd530a5845ca4d299d0546bb080f2793cd2e6f510fc5223ce =====
 * Body: [{"start":"0xca3af0","end":"0xca3b2a"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_00ca3af0(undefined8 param_1,long param_2)

{
  ulong uVar1;
  
  uVar1 = *(ulong *)(param_2 + 0x560);
  *(ulong *)(param_2 + 0x560) = uVar1 | 0x100;
  if ((*(byte *)(param_2 + 0xb1) & 8) != 0) {
    *(ulong *)(param_2 + 0x560) = uVar1 | 0x101;
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== sub_00ca3b30 | RVA 0xca3b30 | file +0x3500 | ev_8792064ac48246e59efb4a30e39025a952598259fdd729a17de65e5e0d437184 =====
 * Body: [{"start":"0xca3b30","end":"0xca3bee"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_00ca3b30(undefined8 param_1,long param_2)

{
  code *pcVar1;
  int iVar2;
  undefined8 local_50;
  undefined8 local_48;
  ulong local_40;
  undefined8 local_38;
  long local_30;
  
  local_30 = _DAT_0391c310;
  func_0x004c6a00(param_2 + 0x148,0,0,0);
  iVar2 = func_0x00b078d0();
  if (iVar2 != 0) {
    iVar2 = func_0x00609890(*(undefined8 *)(param_2 + 0x40));
    local_40 = 4;
    if (iVar2 != 0) goto LAB_00ca3b84;
  }
  local_40 = 0;
LAB_00ca3b84:
  func_0x004c6fa0(param_2 + 0x148,0,0,0);
  local_50 = 3;
  local_48 = 7;
  local_40 = (ulong)*(uint *)(param_2 + 0xbc) << 0x20 | local_40;
  local_38 = 0;
  if (DAT_03e0d720 == '\x01') {
    func_0x00c9aa90(&local_50,0x20);
  }
  if (_DAT_0391c310 == local_30) {
    return;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* ===== sub_00ca3bf0 | RVA 0xca3bf0 | file +0x35c0 | ev_de6674377cc45b0e2649989c494b9f673e3634111999ec508666ffb601a14064 =====
 * Body: [{"start":"0xca3bf0","end":"0xca3c63"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_00ca3bf0(undefined8 param_1,long param_2,long param_3)

{
  code *pcVar1;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  long local_18;
  
  local_18 = _DAT_0391c310;
  local_38 = 3;
  local_30 = 4;
  local_28 = CONCAT44(*(undefined4 *)(param_2 + 0xbc),*(undefined4 *)(param_3 + 0xbc));
  local_20 = 0;
  if (DAT_03e0d720 == '\x01') {
    func_0x00c9aa90(&local_38,0x20);
  }
  if (_DAT_0391c310 == local_18) {
    return;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* ===== sub_00ca3c70 | RVA 0xca3c70 | file +0x3640 | ev_1daca938e19e724667b2898b28814abd836a38aae8aeb6f61144843a6cb21f2c =====
 * Body: [{"start":"0xca3c70","end":"0xca3ce8"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_00ca3c70(undefined8 param_1,long param_2)

{
  short sVar1;
  int iVar2;
  
  func_0x004c6a00(param_2 + 0x148,0,0,0);
  sVar1 = *(short *)(param_2 + 0x560);
  func_0x004c6fa0(param_2 + 0x148,0,0,0);
  if (sVar1 < 0) {
    iVar2 = func_0x00c9d940(*(undefined4 *)(param_2 + 0xbc),1000000,0);
    if (iVar2 != 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
  }
  return;
}



/* ===== sub_00ca3cf0 | RVA 0xca3cf0 | file +0x36c0 | ev_754d136893e887f379c8c82b971e23ba229f54317ca7787d84d212eafe32d6a4 =====
 * Body: [{"start":"0xca3cf0","end":"0xca3d49"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_00ca3cf0(undefined8 param_1,long param_2)

{
  func_0x004c6a00(param_2 + 0x148,0,0,0);
  if ((*(byte *)(param_2 + 0x562) & 0x40) != 0) {
    func_0x00b044d0(0,0,0x1a51260);
    func_0x0055fba0(param_2,9);
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== sub_00ca3d50 | RVA 0xca3d50 | file +0x3720 | ev_119f9eccaa1fd25f23faadb74f4f718343f21c36c24ab95c55f82354e4e5a21e =====
 * Body: [{"start":"0xca3d50","end":"0xca3d7d"},{"start":"0xca3d80","end":"0xca3e28"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Possible PIC construction at 0x00ca3df4: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x00ca3df9) */
/* WARNING: Removing unreachable block (ram,0x00ca3e20) */
/* WARNING: Removing unreachable block (ram,0x00ca3e06) */
/* WARNING: Removing unreachable block (ram,0x00c9f3e0) */

void sub_00ca3d50(int param_1)

{
  undefined8 *puVar1;
  int iVar2;
  
  func_0x00c4b350(0x3589e60,0,0,0);
  puVar1 = (undefined8 *)&DAT_03589e80;
  iVar2 = -1;
  do {
    puVar1 = (undefined8 *)*puVar1;
    if (puVar1 == (undefined8 *)0x0) {
      halt_baddata();
    }
    func_0x004c6a00(puVar1 + 0x29,0,0,0);
    if ((*(int *)(puVar1 + 0xba) == param_1) && ((*(byte *)((long)puVar1 + 0x464) & 1) != 0)) {
      iVar2 = *(int *)((long)puVar1 + 0xbc);
    }
    func_0x004c6fa0(puVar1 + 0x29,0,0);
  } while (iVar2 < 1);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== sub_00ca3e30 | RVA 0xca3e30 | file +0x3800 | ev_29c7e2e0532506f190a731eaa5a2c894d57fa092a73d503a6918b6a3c93b1923 =====
 * Body: [{"start":"0xca3e30","end":"0xca4087"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

bool sub_00ca3e30(undefined8 param_1,long param_2,long param_3)

{
  code *pcVar1;
  long lVar2;
  long lVar3;
  int iVar4;
  long lVar5;
  bool bVar6;
  bool bVar7;
  undefined1 local_120 [96];
  long local_c0;
  long local_b8;
  long local_38;
  
  bVar7 = false;
  local_38 = _DAT_0391c310;
  if (param_3 == 0 || param_2 == 0) goto LAB_00ca3f0e;
  lVar5 = func_0x00c08b50(param_3 + 1,0x2bfc080,0x102);
  func_0x00957b70(lVar5,param_2,param_3 + 1);
  bVar7 = false;
  if (*(char *)(param_2 + -1 + param_3) != '/') {
    func_0x005fa6e0(local_120,0,0x4000010,1,lVar5,0xffffff9c,0,0,param_1);
    iVar4 = func_0x005f8c20(local_120);
    lVar3 = local_b8;
    lVar2 = local_c0;
    if (iVar4 == 0) {
      if (local_c0 == 0) {
LAB_00ca4027:
        func_0x005fa780(local_120,0);
      }
      else {
        iVar4 = *(int *)(local_c0 + 0x1d4);
        func_0x005fa780(local_120,0);
        if (iVar4 == 1) {
          bVar6 = lVar2 == lVar3;
          while (bVar7 = false, !bVar6) {
            do {
              param_3 = param_3 + -1;
              if (param_3 == 0) {
                iVar4 = func_0x008f8c20(param_1,0xffffff9c,param_2,1,0,4);
                bVar7 = iVar4 == 0;
                goto LAB_00ca3eff;
              }
            } while (*(char *)(lVar5 + param_3) != '/');
            *(undefined1 *)(lVar5 + param_3) = 0;
            func_0x005fa6e0(local_120,0,0x4000010,1,lVar5,0xffffff9c,0,0,param_1);
            iVar4 = func_0x005f8c20(local_120);
            lVar3 = local_b8;
            lVar2 = local_c0;
            if (iVar4 != 0) {
              bVar7 = false;
              break;
            }
            if (local_c0 == 0) goto LAB_00ca4027;
            iVar4 = *(int *)(local_c0 + 0x1d4);
            func_0x005fa780(local_120);
            if (iVar4 != 2) goto LAB_00ca3ef8;
            bVar6 = lVar2 == lVar3;
          }
          goto LAB_00ca3eff;
        }
      }
    }
LAB_00ca3ef8:
    bVar7 = false;
  }
LAB_00ca3eff:
  func_0x00c08df0(lVar5,0x2bfc080);
LAB_00ca3f0e:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar1 = (code *)invalidInstructionException();
    (*pcVar1)();
  }
  return bVar7;
}



/* ===== sub_00ca4090 | RVA 0xca4090 | file +0x3a60 | ev_28973ba8ffa7859e948d88dafd0ddf038d8567253139ab1eb14095fca501a887 =====
 * Body: [{"start":"0xca4090","end":"0xca4164"},{"start":"0xca4170","end":"0xca41d0"},{"start":"0xca41e0","end":"0xca4567"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_00ca4090(long param_1,uint param_2)

{
  undefined4 uVar1;
  uint uVar2;
  undefined4 *puVar3;
  long lVar4;
  code *pcVar5;
  char cVar6;
  int iVar7;
  uint uVar8;
  long lVar9;
  long lVar10;
  long lVar11;
  bool bVar12;
  ulong extraout_RDX;
  ulong uVar13;
  undefined7 uVar14;
  char cVar15;
  ulong uVar16;
  undefined1 auVar17 [16];
  long local_50;
  long local_48;
  long local_38;
  
  local_38 = _DAT_0391c310;
  puVar3 = *(undefined4 **)(param_1 + 0xa8);
  if ((((param_2 & 1) != 0) && (iVar7 = 1, (*(byte *)(puVar3 + 3) & 1) == 0)) ||
     (((param_2 & 2) != 0 && (iVar7 = 1, (*(byte *)(puVar3 + 3) & 2) == 0)))) goto LAB_00ca4548;
  lVar9 = func_0x00c08b50(0x30,0x2c01960,0x8102);
  uVar1 = puVar3[2];
  *(undefined4 *)(lVar9 + 0x18) = *puVar3;
  *(undefined4 *)(lVar9 + 0x1c) = puVar3[1];
  *(undefined4 *)(lVar9 + 0x20) = uVar1;
  *(undefined1 *)(lVar9 + 0x28) = *(undefined1 *)(puVar3 + 4);
  iVar7 = func_0x00ca64b0(lVar9,&local_50,1);
  if (iVar7 != 0) {
    func_0x00c08df0(lVar9,0x2c01960);
    iVar7 = 6;
    goto LAB_00ca4548;
  }
  *(uint *)(lVar9 + 0x24) = param_2;
  lVar4 = *(long *)(lVar9 + 8);
  uVar2 = *(uint *)(lVar9 + 0x20);
  if ((int)uVar2 < 0) {
    lVar10 = local_48;
    uVar13 = extraout_RDX;
    if ((((param_2 & 2) == 0) ||
        (lVar10 = *(long *)(lVar4 + 0x2b8 + (ulong)*(byte *)(lVar9 + 0x28) * 8), lVar10 != 0)) &&
       ((local_48 = lVar10, lVar10 = local_50, (param_2 & 1) == 0 ||
        (lVar10 = *(long *)(lVar4 + 0x2c0 + (ulong)*(byte *)(lVar9 + 0x28) * 8), lVar10 != 0)))) {
joined_r0x00ca42fe:
      local_50 = lVar10;
      if (((param_2 & 1) == 0) || (iVar7 = func_0x00ca67c0(lVar9,local_50,param_2), iVar7 == 0)) {
        if (((param_2 & 2) == 0) || (iVar7 = func_0x00ca67c0(lVar9,local_48,param_2), iVar7 == 0)) {
          func_0x00ca6700(lVar9,&local_50);
          func_0x0049bb40(lVar9,0x265228);
          iVar7 = 0;
        }
        else {
          if ((param_2 & 1) != 0) {
            func_0x00ca5660(local_50,param_2);
          }
          func_0x00ca6700(lVar9,&local_50);
          func_0x00c08df0(lVar9,0x2c01960);
        }
      }
      else {
        func_0x00ca6700(lVar9,&local_50);
        func_0x00c08df0(lVar9,0x2c01960);
      }
      goto LAB_00ca4548;
    }
LAB_00ca451b:
    iVar7 = 0x16;
  }
  else {
    bVar12 = true;
    uVar16 = 0;
    uVar8 = 0;
LAB_00ca4180:
    uVar13 = (ulong)(byte)-(char)uVar16;
    if (SBORROW1('\0',(char)uVar16)) {
      if (!bVar12) goto LAB_00ca4514;
      uVar16 = 0;
      bVar12 = false;
    }
    cVar15 = (char)uVar16;
    if ((param_2 & 2) != 0) {
      lVar10 = *(long *)(lVar4 + 0x2b8 + uVar16 * 8);
      if (lVar10 == 0) {
        if (!bVar12) goto LAB_00ca419e;
      }
      else if (uVar2 == *(ushort *)(lVar10 + 0x11c)) {
        uVar13 = CONCAT71((uint7)(byte)(*(ushort *)(lVar10 + 0x11c) >> 8),1);
        if (*(long *)(lVar10 + 0xf0) == 0) goto LAB_00ca419e;
        goto LAB_00ca417a;
      }
LAB_00ca4178:
      uVar13 = (ulong)uVar8;
LAB_00ca417a:
      uVar16 = (ulong)(byte)(cVar15 + 2);
      uVar8 = (uint)uVar13;
      goto LAB_00ca4180;
    }
LAB_00ca419e:
    if ((param_2 & 1) == 0) goto LAB_00ca4263;
    lVar10 = *(long *)(lVar4 + 0x2c0 + uVar16 * 8);
    if (lVar10 != 0) {
      if (uVar2 != *(ushort *)(lVar10 + 0x11c)) goto LAB_00ca4178;
      uVar13 = CONCAT71((uint7)(byte)(*(ushort *)(lVar10 + 0x11c) >> 8),1);
      if (*(long *)(lVar10 + 0xf0) == 0) goto LAB_00ca4263;
      goto LAB_00ca417a;
    }
    if (bVar12) goto LAB_00ca4178;
    bVar12 = false;
LAB_00ca4263:
    uVar14 = (undefined7)(uVar13 >> 8);
    bVar12 = (int)uVar2 < 0x10 || bVar12;
    uVar13 = CONCAT71(uVar14,bVar12);
    cVar6 = (char)uVar8;
    if (bVar12) {
      iVar7 = 0x10;
      uVar13 = CONCAT71(uVar14,cVar6 != '\0');
      if (uVar2 == 0 || cVar6 == '\0') {
        if (((param_2 & 2) == 0) || (*(long *)(lVar4 + 0x2b8 + uVar16 * 8) != 0)) {
joined_r0x00ca42b6:
          if ((param_2 & 1) != 0) {
            uVar8 = (int)uVar16 + 1;
            if (*(long *)(lVar4 + 0x2b8 + (ulong)uVar8 * 8) == 0) {
              auVar17 = func_0x00ca69e0(lVar4,uVar2 & 0xff,1);
              uVar13 = auVar17._8_8_;
              lVar10 = auVar17._0_8_;
              if (lVar10 == 0) goto LAB_00ca451b;
              auVar17 = func_0x00ca5a00(lVar4 + 0x90);
              uVar13 = auVar17._8_8_;
              lVar11 = auVar17._0_8_;
              if (lVar11 == 0) goto LAB_00ca4514;
              *(char *)(lVar11 + 0x128) = (char)uVar8;
              *(short *)(lVar11 + 0x11c) = (short)uVar2;
              *(long *)(lVar11 + 0xf8) = lVar10;
              *(undefined8 *)(lVar11 + 0xa0) = 0x2bf37e0;
              *(undefined1 *)(lVar11 + 0x127) = *(undefined1 *)(lVar10 + 0x15b);
              *(long *)(lVar11 + 200) = lVar4;
              func_0x004c6a00(0x3e0daa8,0,0,0);
              *(long *)(lVar4 + 0x2b8 + (ulong)uVar8 * 8) = lVar11;
              func_0x004c6fa0(0x3e0daa8,0,0,0);
            }
          }
          if ((param_2 & 2) != 0) {
            local_48 = *(long *)(lVar4 + 0x2b8 + uVar16 * 8);
          }
          if ((param_2 & 1) != 0) {
            local_50 = *(long *)(lVar4 + 0x2c0 + uVar16 * 8);
          }
          *(char *)(lVar9 + 0x28) = cVar15;
          lVar10 = local_50;
          goto joined_r0x00ca42fe;
        }
        auVar17 = func_0x00ca69e0(lVar4,uVar2 & 0xff,0);
        uVar13 = auVar17._8_8_;
        lVar10 = auVar17._0_8_;
        if (lVar10 == 0) goto LAB_00ca451b;
        auVar17 = func_0x00ca5a00(lVar4 + 0x90);
        uVar13 = auVar17._8_8_;
        lVar11 = auVar17._0_8_;
        if (lVar11 != 0) {
          *(char *)(lVar11 + 0x128) = cVar15;
          *(short *)(lVar11 + 0x11c) = (short)uVar2;
          *(long *)(lVar11 + 0xf8) = lVar10;
          *(undefined8 *)(lVar11 + 0xa0) = 0x2bf37e0;
          *(undefined1 *)(lVar11 + 0x127) = *(undefined1 *)(lVar10 + 0x15b);
          *(long *)(lVar11 + 200) = lVar4;
          func_0x004c6a00(0x3e0daa8,0,0,0);
          *(long *)(lVar4 + 0x2b8 + uVar16 * 8) = lVar11;
          func_0x004c6fa0(0x3e0daa8,0,0,0);
          goto joined_r0x00ca42b6;
        }
LAB_00ca4514:
        iVar7 = 0xc;
      }
    }
    else {
      iVar7 = 0x10;
      if (cVar6 == '\0') {
        iVar7 = 0x16;
      }
    }
  }
  func_0x00ca6700(lVar9,&local_50,uVar13);
  func_0x00c08df0(lVar9,0x2c01960);
LAB_00ca4548:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar5 = (code *)invalidInstructionException();
    (*pcVar5)();
  }
  return iVar7;
}



/* ===== sub_00ca4570 | RVA 0xca4570 | file +0x3f40 | ev_2a6f865f163344ba24a1e1dbea1a2274da7c3811c46551c27d08aee9c2af996c =====
 * Body: [{"start":"0xca4570","end":"0xca462c"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_00ca4570(void)

{
  int iVar1;
  undefined8 local_58;
  long local_50 [2];
  char local_3d;
  undefined8 local_38;
  
  local_38 = _DAT_0391c310;
  iVar1 = func_0x0049bb00(&local_58);
  if ((iVar1 == 0) && (iVar1 = func_0x00ca64b0(local_58,local_50,0), iVar1 == 0)) {
    if (local_50[0] != 0) {
      func_0x004c6a00(*(long *)(local_50[0] + 0xe8) + 0x18,0,0,0);
      if ((*(char *)(local_50[0] + 0x120) == '\0') && (local_3d == '\0')) {
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      func_0x004c6fa0(*(long *)(local_50[0] + 0xe8) + 0x18,0,0,0);
    }
    func_0x00ca6700(local_58,local_50);
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


