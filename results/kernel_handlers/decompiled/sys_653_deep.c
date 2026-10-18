/* REA 6.7.0 / Ghidra 12.1.4 recovered pseudocode, not original or buildable C.
 * Input: deep_653.bin, SHA256 c5ccba93edf5b75f29421da2e37df0dfb420ee340f65f914529287cc16520a44
 * File offset zero maps to kernel RVA 0x9a7d10; runtime VA = 0xffffffff8a9c0000 + RVA.
 * External bodies/types/data missing from this raw window remain unknown.
 * Function names are analyst seeds or Ghidra-generated; instruction truth is in .rea.asm.
 */

/* ===== sys_653 | RVA 0x9a7d10 | file +0x0 | ev_dadf6757a063ce0b607408e3984342673c3cc761854c15abd24090bfd47fd7cd =====
 * Body: [{"start":"0x9a7d10","end":"0x9a7f27"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong sys_653(long param_1,uint *param_2)

{
  int *piVar1;
  uint uVar2;
  undefined4 uVar3;
  code *pcVar4;
  int iVar5;
  ulong uVar6;
  undefined8 *puVar7;
  undefined8 uVar8;
  long lVar9;
  uint uVar10;
  long *in_GS_OFFSET;
  int local_44;
  long local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  uVar6 = 0x16;
  uVar10 = *param_2;
  if ((uVar10 & 0xffafffff) == 0) {
    lVar9 = *in_GS_OFFSET;
    uVar2 = *(uint *)(*(long *)(lVar9 + 8) + 0x5d0);
    uVar6 = (ulong)uVar2;
    puVar7 = (undefined8 *)func_0x00c08b50(0x410b0,0x255fdd0,0x8102);
    func_0x004c7dd0(puVar7 + 5,0x13b5057,0,0);
    uVar3 = *(undefined4 *)(*(long *)(lVar9 + 8) + 0x5c4);
    *(undefined4 *)(puVar7 + 0xc) = uVar3;
    *(uint *)((long)puVar7 + 100) = uVar2;
    uVar8 = func_0x003c3920(uVar3,0);
    lVar9 = (ulong)(*(int *)(puVar7 + 0xc) == 0) << 0x26;
    puVar7[7] = lVar9;
    iVar5 = func_0x003c3640(uVar8,lVar9,0,&local_40);
    if (iVar5 == 0) {
      puVar7[8] = local_40 + puVar7[7];
      uVar8 = func_0x003c36b0(uVar8);
    }
    else {
      uVar8 = 0;
      puVar7[8] = puVar7[7];
    }
    puVar7[6] = uVar8;
    func_0x004c6a00(0x3ba5e78,0,0,0);
    if (-1 < (int)uVar2) {
      uVar2 = *(uint *)(uVar6 * 4 + 0x3ba5e90);
      if (*(uint *)(uVar6 * 4 + 0x3ba5ec0) <= uVar2) {
        func_0x004c6fa0(0x3ba5e78,0,0,0);
        func_0x00c08df0(puVar7,0x255fdd0);
        uVar6 = 0x18;
        goto LAB_009a7f09;
      }
      *(uint *)(uVar6 * 4 + 0x3ba5e90) = uVar2 + 1;
    }
    *puVar7 = 0;
    uVar10 = uVar10 | 2;
    puVar7[1] = _DAT_03ba5e88;
    *_DAT_03ba5e88 = puVar7;
    _DAT_03ba5e88 = puVar7;
    func_0x004c6fa0(0x3ba5e78,0,0,0);
    LOCK();
    *(int *)(puVar7 + 0xb) = *(int *)(puVar7 + 0xb) + 1;
    UNLOCK();
    uVar6 = func_0x0072c7a0(param_1,&local_40,&local_44,uVar10,0);
    if ((int)uVar6 == 0) {
      func_0x0072e000(local_40,uVar10,0x11,puVar7,0x255fec8);
      LOCK();
      piVar1 = (int *)(local_40 + 0x28);
      iVar5 = *piVar1;
      *piVar1 = *piVar1 + -1;
      UNLOCK();
      if (iVar5 == 1) {
        func_0x0072b380(local_40,param_1);
      }
      *(long *)(param_1 + 0x408) = (long)local_44;
      uVar6 = 0;
    }
    else {
      LOCK();
      piVar1 = (int *)(puVar7 + 0xb);
      iVar5 = *piVar1;
      *piVar1 = *piVar1 + -1;
      UNLOCK();
      if (iVar5 == 1) {
        uVar6 = uVar6 & 0xffffffff;
        func_0x009a7c00(puVar7);
      }
    }
  }
LAB_009a7f09:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar4 = (code *)invalidInstructionException();
    (*pcVar4)();
  }
  return uVar6;
}



/* ===== sub_009a7f30 | RVA 0x9a7f30 | file +0x220 | ev_589230a4195c07af9a17c5a73e4f8ebe7a7b719ce0f0ef72df6e725a67a49a38 =====
 * Body: [{"start":"0x9a7f30","end":"0x9a807b"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_009a7f30(long param_1,long param_2,long param_3,long param_4)

{
  undefined8 uVar1;
  undefined8 uVar2;
  code *pcVar3;
  uint uVar4;
  int iVar5;
  long lVar6;
  uint uVar7;
  ulong uVar8;
  
  uVar1 = *(undefined8 *)(param_1 + 0x1d8);
  lVar6 = *(long *)(param_4 + 0xe8);
  uVar8 = (ulong)(param_3 - param_2) >> 0x15;
  uVar4 = sub_009a8080(param_4,0,(ulong)(param_3 - param_2) >> 0x10);
  if (0 < (int)uVar8) {
    uVar2 = *(undefined8 *)(lVar6 + 0x30);
    lVar6 = *(long *)(param_4 + 0x160);
    do {
      func_0x008e4990(uVar1,param_2,uVar2,lVar6);
      iVar5 = func_0x009edc50(param_1,param_2,uVar2,lVar6);
      if (iVar5 != 0) {
        func_0x007f1950();
        func_0x007f1810(0x9a8056);
        func_0x00c9aa10(0x2f,0x127c5f5);
                    /* WARNING: Does not return */
        pcVar3 = (code *)invalidInstructionException();
        (*pcVar3)();
      }
      param_2 = param_2 + 0x200000;
      lVar6 = lVar6 + 0x80;
      uVar7 = (int)uVar8 - 1;
      uVar8 = (ulong)uVar7;
    } while (uVar7 != 0);
  }
  uVar8 = (ulong)uVar4;
  func_0x007d46a0(param_4 + 0x18,0,0);
  *(undefined4 *)(param_4 + 0x168 + uVar8 * 0xc) = 0xffffffff;
  if (*(int *)(param_4 + 0x170 + uVar8 * 0xc) == 0) {
    iVar5 = *(int *)(param_4 + 0x198);
  }
  else {
    *(undefined4 *)(param_4 + 0x170 + uVar8 * 0xc) = 0;
    func_0x00c06910();
    iVar5 = *(int *)(param_4 + 0x198);
  }
  if (iVar5 != 0) {
    *(undefined4 *)(param_4 + 0x198) = 0;
    func_0x00c06910((undefined4 *)(param_4 + 0x198));
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== sub_009a8080 | RVA 0x9a8080 | file +0x370 | ev_ecf1946fa9c69931a1a6e515242461b9e663076c9f105e8c868816d02828791e =====
 * Body: [{"start":"0x9a8080","end":"0x9a8256"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

ulong sub_009a8080(long param_1,uint param_2,int param_3)

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



/* ===== sub_009a8260 | RVA 0x9a8260 | file +0x550 | ev_3f0a69565aabb07f44606cb940b2d79f1593ed64e613fcfb5d888b958a74cc5f =====
 * Body: [{"start":"0x9a8260","end":"0x9a856a"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_009a8260(long param_1,long param_2,undefined8 param_3,uint param_4,int param_5)

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
        uVar4 = sub_009a8080(param_2,param_4,param_5);
        sub_009a8570(param_1,param_2,param_3,uVar5 & 0xffffffff,uVar6 & 0xffffffff,&local_48,
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
        sub_009a86c0(param_2,lVar7,(ulong)(local_40 - lVar7) >> 2);
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



/* ===== sub_009a8570 | RVA 0x9a8570 | file +0x860 | ev_678268bea55acef65bc273d00e131a717394d7de182848e77ae29c3b45470f9d =====
 * Body: [{"start":"0x9a8570","end":"0x9a85fe"},{"start":"0x9a8600","end":"0x9a86bd"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_009a8570(long param_1,long param_2,long param_3,int param_4,int param_5,undefined8 param_6,
                 undefined8 *param_7)

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



/* ===== sub_009a86c0 | RVA 0x9a86c0 | file +0x9b0 | ev_dc22eacd5bf034cd6a051e2df9a1c9ebae0a11d8e2c1a9b01ea5b38f1e1c3a6f =====
 * Body: [{"start":"0x9a86c0","end":"0x9a8702"},{"start":"0x9a8710","end":"0x9a8738"},{"start":"0x9a8740","end":"0x9a87cc"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_009a86c0(long param_1,long param_2,int param_3)

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



/* ===== sub_009a87d0 | RVA 0x9a87d0 | file +0xac0 | ev_0bfd4f94c9713acae8c810b42cb5e7bdf3947fdf78c126553ef10ee14687af1a =====
 * Body: [{"start":"0x9a87d0","end":"0x9a88dd"},{"start":"0x9a88e0","end":"0x9a895a"},{"start":"0x9a8960","end":"0x9a8a9e"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8
sub_009a87d0(long param_1,long param_2,long param_3,uint param_4,int param_5,uint param_6)

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
  uVar6 = sub_009a8080(param_2,param_4,param_5);
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



/* ===== sub_009a8aa0 | RVA 0x9a8aa0 | file +0xd90 | ev_b9efccd7c375748626c37029685d50092f050bfa6a79125ade1cdd93aa30ba49 =====
 * Body: [{"start":"0x9a8aa0","end":"0x9a8cf2"},{"start":"0x9a8d00","end":"0x9a8da2"},{"start":"0x9a8db0","end":"0x9a8e38"},{"start":"0x9a8e40","end":"0x9a8f74"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8
sub_009a8aa0(long param_1,long param_2,long param_3,uint param_4,int param_5,uint param_6,
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
  uVar7 = sub_009a8080(param_2,param_4,param_5);
  bVar6 = *(byte *)(param_1 + 0x244);
  if ((param_6 < 0xb) && ((0x409U >> (param_6 & 0x1f) & 1) != 0)) {
    if ((bVar6 & 2) == 0) {
      iVar8 = func_0x009acc10(param_6);
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
          func_0x009ac500(lVar2,uVar11 & 0xfffff);
        }
        lVar16 = lVar16 + 1;
      } while (param_5 - param_4 != (int)lVar16);
    }
  }
  else {
    func_0x009ac450(lVar2);
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



/* ===== sub_009a8f80 | RVA 0x9a8f80 | file +0x1270 | ev_59995de386148e1b352b2f74b51a18069e8070b7a7a76ab3a24ebf36f670fc7e =====
 * Body: [{"start":"0x9a8f80","end":"0x9a9267"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8
sub_009a8f80(undefined8 param_1,long param_2,ulong param_3,undefined8 param_4,long *param_5)

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
    uVar5 = sub_009a8080(param_2,param_3 >> 0x10 & 0xffffffff,iVar3 + 1);
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



/* ===== sub_009a9270 | RVA 0x9a9270 | file +0x1560 | ev_890d169e30683eb6ce378f153958667e836f873d2ad7142493093c80462e9bb2 =====
 * Body: [{"start":"0x9a9270","end":"0x9a9553"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

bool sub_009a9270(long param_1,long param_2,ulong param_3,long param_4,long *param_5,long *param_6,
                 uint *param_7,undefined4 *param_8,undefined8 param_9,int param_10)

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
  uVar4 = sub_009a8080(param_2,0,*(ulong *)(param_2 + 0x88) >> 2);
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



/* ===== sys_654 | RVA 0x9a9560 | file +0x1850 | ev_edeb3329c9a0c2e108c1362562c224c3b349090019b9c0d02bc103131181535a =====
 * Body: [{"start":"0x9a9560","end":"0x9a979b"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 sys_654(long param_1,ulong *param_2)

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
          iVar8 = func_0x009acc10(uVar10);
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
              uVar9 = sub_009a97a0(lVar2,lVar4,lVar5,uVar11 >> 0x10 & 0xffffffff,
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



/* ===== sub_009a97a0 | RVA 0x9a97a0 | file +0x1a90 | ev_1973dfdb61b1ecee355a6e8ec95abb779d9592cd3848d22b066e7d83bfb9af10 =====
 * Body: [{"start":"0x9a97a0","end":"0x9a9a79"},{"start":"0x9a9a80","end":"0x9a9d0f"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_009a97a0(long param_1,long param_2,long param_3,uint param_4,uint param_5,uint param_6,
                 int param_7)

{
  char *pcVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  undefined8 uVar5;
  undefined8 uVar6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  ulong uVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  long lVar15;
  uint uVar16;
  long lVar17;
  uint uVar18;
  uint uVar19;
  int iVar20;
  int iVar21;
  uint uVar22;
  long lVar23;
  uint uVar24;
  long lVar25;
  long lVar26;
  long lVar27;
  long *in_GS_OFFSET;
  bool bVar28;
  uint local_dc;
  undefined8 local_c0;
  uint local_b8 [32];
  undefined8 local_38;
  ulong uVar14;
  
  local_38 = _DAT_0391c310;
  if ((*(byte *)(param_1 + 0x244) & 2) == 0) {
    uVar19 = 0;
    if (param_7 - 0xbU < 10) {
      uVar19 = *(uint *)((ulong)(param_7 - 0xbU) * 4 + 0x18cdb8c);
    }
  }
  else {
    uVar19 = 0xc00000;
    if (param_7 != 0) {
      uVar19 = (uint)(param_7 == 10) << 0x17;
    }
  }
  uVar11 = param_6 & 0x30;
  uVar16 = (uVar19 & 0x800000) >> 0x17;
  local_dc = uVar16;
  if ((*(byte *)(param_1 + 0x244) & 2) != 0) {
    local_dc = (uint)((uVar19 & 0xf00000) != 0x800000 && (uVar19 & 0x800000) != 0);
  }
  lVar2 = *(long *)(param_2 + 0xe8);
  lVar3 = *(long *)(param_2 + 0x160);
  lVar4 = *(long *)(param_2 + 400);
  sub_009a8080(param_2,param_4,param_5);
  if ((int)param_4 < (int)param_5) {
    lVar17 = 0;
    do {
      if (*(int *)(lVar3 + (long)(int)param_4 * 4 + lVar17 * 4) != 0) {
        halt_baddata();
      }
      lVar17 = lVar17 + 1;
    } while (param_5 - param_4 != (int)lVar17);
  }
  iVar8 = (int)param_4 >> 5;
  iVar20 = (int)param_5 >> 5;
  uVar9 = (uint)(*(char *)(lVar4 + iVar8) == '\0');
  if ((iVar8 < iVar20 && (param_5 & 0x1f) != 0) && (*(char *)(lVar4 + iVar20) == '\0')) {
    uVar9 = (*(char *)(lVar4 + iVar8) == '\0') + 1;
  }
  iVar21 = iVar20 - (iVar8 + 1);
  if (iVar21 == 0 || iVar20 < iVar8 + 1) {
    iVar21 = 0;
  }
  if ((iVar21 + uVar9 == 0 || SCARRY4(iVar21,uVar9) != (int)(iVar21 + uVar9) < 0) ||
     (iVar20 = func_0x008ed550(*(undefined1 *)(param_2 + 0x19c)), iVar20 == 0)) {
    bVar28 = (*(byte *)(param_1 + 0x244) & 2) != 0;
    uVar9 = 0x700;
    if (bVar28) {
      uVar9 = 2;
    }
    uVar12 = 0xa00;
    if (!bVar28) {
      uVar12 = 2;
    }
    if ((int)param_4 < (int)param_5) {
      lVar25 = (long)(int)param_4;
      lVar26 = lVar25 * 0x10000 + param_3;
      uVar24 = param_6 >> 1 & 1;
      uVar22 = uVar24 | param_6 & 3;
      uVar10 = (ulong)(param_4 & 0xffffffe0);
      lVar23 = (long)(int)param_5;
      uVar13 = (param_4 & 0xffffffe0) + 0x20;
      uVar14 = (ulong)uVar13;
      uVar5 = *(undefined8 *)(param_1 + 0x1d8);
      uVar6 = *(undefined8 *)(lVar2 + 0x30);
      lVar17 = lVar26;
      uVar7 = param_4;
      while( true ) {
        uVar18 = uVar13;
        lVar27 = (long)(int)uVar18;
        if (lVar23 < (int)uVar18) {
          lVar27 = lVar23;
        }
        uVar13 = uVar18;
        if ((int)param_5 < (int)uVar18) {
          uVar13 = param_5;
        }
        iVar21 = uVar13 - uVar7;
        iVar20 = func_0x009abca0(lVar2,iVar21,local_dc,uVar16,local_b8);
        if (iVar20 != 0) break;
        pcVar1 = (char *)(lVar4 + ((int)uVar7 >> 5));
        *pcVar1 = *pcVar1 + (char)iVar21;
        if ((int)uVar7 < (int)uVar13) {
          lVar15 = 0;
          do {
            *(uint *)(lVar3 + (long)(int)uVar7 * 4 + lVar15 * 4) =
                 local_b8[(int)lVar15] | uVar19 | uVar22 << 0x18 | uVar11 << 0x16 | 0x10000000;
            lVar15 = lVar15 + 1;
          } while (lVar27 - (int)uVar7 != lVar15);
        }
        if (uVar22 != 0) {
          func_0x008edf10(uVar5,lVar17,uVar6,iVar21,local_b8,uVar24 | param_6 & 0xffff,uVar16,lVar23
                          ,uVar10,uVar14);
        }
        if ((uVar11 != 0) &&
           (iVar20 = func_0x009ec220(param_1,lVar17,uVar6,iVar21,local_b8,uVar24 | param_6,
                                     uVar19 >> (uint)bVar28 * 9 + 0xc & uVar9 | uVar12),
           uVar7 = uVar13, iVar20 != 0)) break;
        lVar17 = lVar17 + iVar21 * 0x10000;
        uVar13 = uVar18 + 0x20;
        uVar7 = uVar18;
        if ((int)param_5 <= (int)uVar18) {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
      }
      iVar20 = (int)uVar10;
      if (uVar22 != 0) {
        local_c0 = 0;
        func_0x008ee780(uVar5,lVar26,(long)(int)uVar7 * 0x10000 + param_3,&local_c0);
        func_0x008ef340(uVar5,local_c0);
      }
      if (uVar11 == 0) {
        iVar21 = uVar7 - param_4;
      }
      else {
        *(undefined1 *)(*in_GS_OFFSET + 0x117) = 0;
        iVar21 = uVar7 - param_4;
        func_0x009ec410(param_1,lVar26,iVar21,lVar3 + lVar25 * 4,1);
      }
      lVar3 = lVar3 + lVar25 * 4;
      sub_009a86c0(param_2,lVar3,iVar21);
      func_0x00258ff0(lVar3,(long)iVar21 << 2);
      if ((int)param_4 < (int)uVar7) {
        uVar19 = iVar20 + 0x20U;
        if ((int)uVar7 < (int)(iVar20 + 0x20U)) {
          uVar19 = uVar7;
        }
        *(char *)(lVar4 + iVar8) = *(char *)(lVar4 + iVar8) + ((char)param_4 - (char)uVar19);
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


