/* REA 6.7.0 / Ghidra 12.1.4 recovered pseudocode, not original or buildable C.
 * Input: deep_630.bin, SHA256 e31b2f0f58de8b562ce6ca7fedc09af580e1e5f72f622846c4fac8776432f3a1
 * File offset zero maps to kernel RVA 0x91cc70; runtime VA = 0xffffffff8a9c0000 + RVA.
 * External bodies/types/data missing from this raw window remain unknown.
 * Function names are analyst seeds or Ghidra-generated; instruction truth is in .rea.asm.
 */

/* ===== sys_630 | RVA 0x91cc70 | file +0x0 | ev_93cd5e5a551da49dc5a1f9b9987c72a287e98286763e45dcd64b14b158f5548f =====
 * Body: [{"start":"0x91cc70","end":"0x91cd3f"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

int sys_630(long param_1,undefined8 *param_2)

{
  undefined8 uVar1;
  int iVar2;
  undefined8 uVar3;
  undefined8 *in_GS_OFFSET;
  
  uVar3 = func_0x00c08b50(0x400,0x2551e10,2);
  uVar1 = *param_2;
  func_0x00c1a3e0(*in_GS_OFFSET,0x135a084,0);
  iVar2 = func_0x00259900(uVar1,uVar3,0x400,0);
  if (iVar2 == 0) {
    iVar2 = func_0x006092d0(*(undefined8 *)(param_1 + 0x140));
    if (iVar2 != 0) {
      iVar2 = func_0x008d1a30(uVar3,0x181d4a1,0xc);
      if (iVar2 != 0) {
        func_0x0080d5a0(0x1389e5d,param_1,uVar3,0x181d4a1);
        iVar2 = 2;
        goto LAB_0091cd23;
      }
    }
    iVar2 = func_0x0091c740(param_1,uVar3);
  }
LAB_0091cd23:
  func_0x00c08df0(uVar3,0x2551e10);
  return iVar2;
}



/* ===== sub_0091cd40 | RVA 0x91cd40 | file +0xd0 | ev_dc8966de07de40e0080e2774ad719e74aecc543c1306925b8a823248849502eb =====
 * Body: [{"start":"0x91cd40","end":"0x91cdec"},{"start":"0x91cdf0","end":"0x91ce54"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_0091cd40(long param_1,int *param_2,int *param_3)

{
  undefined8 *puVar1;
  undefined8 *puVar2;
  int iVar3;
  int iVar4;
  undefined8 *puVar5;
  undefined8 uVar6;
  bool bVar7;
  
  if (param_3 == (int *)0x0) {
    uVar6 = 0x16;
  }
  else {
    iVar3 = 0;
    if (param_2 != (int *)0x0 && param_1 != 0) {
      iVar3 = *param_2;
    }
    func_0x004c6a00(0x3b76950,0,0,0);
    puVar1 = (undefined8 *)&DAT_03b76960;
    puVar2 = (undefined8 *)0x0;
    do {
      puVar5 = puVar2;
      puVar1 = (undefined8 *)*puVar1;
      puVar2 = puVar1;
    } while (puVar1 != (undefined8 *)0x0);
    iVar4 = 0;
    if (puVar5 != (undefined8 *)0x0) {
      do {
        do {
          while( true ) {
            puVar1 = puVar5;
            if (iVar4 < iVar3) {
              *(undefined8 *)(param_1 + (long)iVar4 * 8) = puVar1[5];
            }
            iVar4 = iVar4 + 1;
            puVar2 = (undefined8 *)puVar1[1];
            if ((undefined8 *)puVar1[1] == (undefined8 *)0x0) break;
            do {
              puVar1 = (undefined8 *)*puVar2;
              puVar5 = puVar2;
              puVar2 = puVar1;
            } while (puVar1 != (undefined8 *)0x0);
          }
          puVar5 = (undefined8 *)puVar1[2];
        } while ((puVar5 != (undefined8 *)0x0) && (puVar1 == (undefined8 *)*puVar5));
        do {
          puVar5 = (undefined8 *)puVar1[2];
          if (puVar5 == (undefined8 *)0x0) goto LAB_0091ce14;
          bVar7 = puVar1 == (undefined8 *)puVar5[1];
          puVar1 = puVar5;
        } while (bVar7);
      } while( true );
    }
LAB_0091ce14:
    uVar6 = 0;
    func_0x004c6fa0(0x3b76950,0,0,0);
    if (param_2 != (int *)0x0) {
      if (iVar4 <= iVar3) {
        iVar3 = iVar4;
      }
      *param_2 = iVar3;
    }
    *param_3 = iVar4;
  }
  return uVar6;
}



/* ===== sub_0091ce60 | RVA 0x91ce60 | file +0x1f0 | ev_987a685a73665509fb42e51a5a435d12b3afd40698968eba5c3cc264f5aaa39b =====
 * Body: [{"start":"0x91ce60","end":"0x91cf13"},{"start":"0x91cf20","end":"0x91cf4c"},{"start":"0x91cf50","end":"0x91cf73"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_0091ce60(long param_1,long param_2,long param_3)

{
  long lVar1;
  undefined8 *puVar2;
  undefined8 *puVar3;
  undefined8 uVar4;
  undefined8 *puVar5;
  bool bVar6;
  
  func_0x004c6a00(0x3b76950,0,0,0);
  puVar3 = (undefined8 *)&DAT_03b76960;
  puVar5 = (undefined8 *)0x0;
  do {
    puVar2 = puVar5;
    puVar3 = (undefined8 *)*puVar3;
    puVar5 = puVar3;
  } while (puVar3 != (undefined8 *)0x0);
  uVar4 = 9;
  if (puVar2 != (undefined8 *)0x0) {
    lVar1 = puVar2[5];
    while (lVar1 != param_1) {
      puVar3 = (undefined8 *)puVar2[1];
      if ((undefined8 *)puVar2[1] == (undefined8 *)0x0) {
        puVar5 = (undefined8 *)puVar2[2];
        if ((puVar5 == (undefined8 *)0x0) || (puVar2 != (undefined8 *)*puVar5)) {
          do {
            puVar5 = (undefined8 *)puVar2[2];
            if (puVar5 == (undefined8 *)0x0) goto LAB_0091cef0;
            bVar6 = puVar2 == (undefined8 *)puVar5[1];
            puVar2 = puVar5;
          } while (bVar6);
        }
      }
      else {
        do {
          puVar5 = puVar3;
          puVar3 = (undefined8 *)*puVar5;
        } while ((undefined8 *)*puVar5 != (undefined8 *)0x0);
      }
      puVar2 = puVar5;
      lVar1 = puVar5[5];
    }
    if (param_2 != 0) {
      func_0x00259be0(param_1,param_2,0x20);
    }
    uVar4 = 0;
    if (param_3 != 0) {
      func_0x00957b70(param_3,puVar2[4],0x400);
    }
  }
LAB_0091cef0:
  func_0x004c6fa0(0x3b76950,0,0,0);
  return uVar4;
}



/* ===== sub_0091cf80 | RVA 0x91cf80 | file +0x310 | ev_ebe6a7e1646a9680690c37ad2aeded38144eb7811e82bee7f947226df63bcdee =====
 * Body: [{"start":"0x91cf80","end":"0x91cfe6"},{"start":"0x91cff0","end":"0x91d029"},{"start":"0x91d030","end":"0x91d0b2"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_0091cf80(long param_1,int *param_2,int *param_3)

{
  long *plVar1;
  undefined8 *puVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  long *plVar7;
  undefined8 uVar8;
  
  if (param_3 == (int *)0x0) {
    uVar8 = 0x16;
  }
  else {
    iVar5 = 0;
    iVar6 = 0;
    if (param_2 != (int *)0x0 && param_1 != 0) {
      iVar5 = *param_2;
    }
    func_0x00c4b350(0x3589e60,0,0,0);
    if (_DAT_03589e80 != (long *)0x0) {
      iVar6 = 0;
      plVar7 = _DAT_03589e80;
      do {
        plVar1 = (long *)plVar7[9];
        func_0x00c4b350(plVar1 + 8,0,0,0);
        iVar4 = (int)plVar1[5];
        if (-1 < iVar4) {
          iVar3 = 0;
          do {
            puVar2 = *(undefined8 **)(*plVar1 + 8 + (long)iVar3 * 0x30);
            if ((puVar2 != (undefined8 *)0x0) && (*(short *)(puVar2 + 4) == 0x10)) {
              if (iVar6 < iVar5) {
                *(undefined8 *)(param_1 + (long)iVar6 * 8) = *puVar2;
                iVar4 = (int)plVar1[5];
              }
              iVar6 = iVar6 + 1;
            }
            iVar3 = iVar3 + 1;
          } while (iVar3 <= iVar4);
        }
        func_0x00c4c300(plVar1 + 8,0,0);
        plVar7 = (long *)*plVar7;
      } while (plVar7 != (long *)0x0);
    }
    uVar8 = 0;
    func_0x00c4c300(0x3589e60,0,0);
    if (param_2 != (int *)0x0) {
      if (iVar6 <= iVar5) {
        iVar5 = iVar6;
      }
      *param_2 = iVar5;
    }
    *param_3 = iVar6;
  }
  return uVar8;
}



/* ===== sub_0091d0c0 | RVA 0x91d0c0 | file +0x450 | ev_e3a3a1f7a6092001360e3f524391afc4bade1d5db89550280082eac7dee29057 =====
 * Body: [{"start":"0x91d0c0","end":"0x91d149"},{"start":"0x91d150","end":"0x91d193"},{"start":"0x91d1a0","end":"0x91d232"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_0091d0c0(long param_1,long param_2,int *param_3,int *param_4)

{
  long *plVar1;
  int iVar2;
  long *plVar3;
  long *plVar4;
  long *plVar5;
  undefined8 uVar6;
  int iVar7;
  
  iVar2 = *param_3;
  iVar7 = 0;
  func_0x00c4b350(0x3589e60,0,0,0);
  plVar5 = _DAT_03589e80;
  if (iVar2 != 0) {
    plVar5 = (long *)func_0x0053c170(iVar2);
    if (plVar5 == (long *)0x0) {
      uVar6 = 3;
      goto LAB_0091d211;
    }
    func_0x004c6fa0(plVar5 + 0x29,0,0,0);
    iVar7 = -1;
    if (-1 < *param_4) {
      iVar7 = *param_4;
    }
    iVar7 = iVar7 + 1;
  }
  do {
    plVar3 = (long *)plVar5[9];
    plVar1 = plVar3 + 8;
    func_0x00c4b350(plVar1,0,0,0);
    if (iVar7 <= (int)plVar3[5]) {
      do {
        plVar4 = *(long **)(*plVar3 + 8 + (long)iVar7 * 0x30);
        if (((plVar4 != (long *)0x0) && ((short)plVar4[4] == 0x10)) && (*plVar4 == param_1)) {
          if (param_2 != 0) {
            func_0x00259be0(param_1,param_2,0x20);
          }
          uVar6 = 0;
          *param_3 = *(int *)((long)plVar5 + 0xbc);
          *param_4 = iVar7;
          func_0x00c4c300(plVar1,0,0);
          goto LAB_0091d211;
        }
        iVar7 = iVar7 + 1;
      } while (iVar7 <= (int)plVar3[5]);
    }
    iVar7 = 0;
    func_0x00c4c300(plVar1,0,0);
    plVar5 = (long *)*plVar5;
  } while (plVar5 != (long *)0x0);
  uVar6 = 9;
LAB_0091d211:
  func_0x00c4c300(0x3589e60,0,0);
  return uVar6;
}



/* ===== sub_0091d240 | RVA 0x91d240 | file +0x5d0 | ev_82155c0b8177953989bc6d35d6981ee6d26a9298a88e081a0ffe58488db471fe =====
 * Body: [{"start":"0x91d240","end":"0x91d26f"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_0091d240(void)

{
  _DAT_03b76968 = func_0x0043b0e0(0x1290447,0x20,0,0,0,0,7,0);
  return;
}



/* ===== sub_0091d270 | RVA 0x91d270 | file +0x600 | ev_1b6f25208684f9c58f24a80686919f54cf77e6f91cc6533ee7b9f4c15563b2bf =====
 * Body: [{"start":"0x91d270","end":"0x91d2c1"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_0091d270(void)

{
  func_0x004c7dd0(0x3b76950,0x1340770,0,0);
  _DAT_03b76960 = 0;
  _DAT_03b76958 = func_0x0043b0e0(0x1375673,0x30,0,0,0,0,7,0);
  return;
}



/* ===== sub_0091d2d0 | RVA 0x91d2d0 | file +0x660 | ev_6fdbc32e8434c8e2d0e015b893632720acdbe725b65fd0899ce3d82dc16e52b0 =====
 * Body: [{"start":"0x91d2d0","end":"0x91d322"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined4 sub_0091d2d0(uint param_1)

{
  code *pcVar1;
  
  if ((param_1 < 0x15) && ((0x1ffbffU >> (param_1 & 0x1f) & 1) != 0)) {
    return *(undefined4 *)((ulong)param_1 * 4 + 0x181d4b0);
  }
  func_0x007f1950();
  func_0x007f18a0(0x91d2f0,(long)(int)param_1);
  func_0x00c9aa10(3,0x12947a2,param_1);
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* ===== sub_0091d330 | RVA 0x91d330 | file +0x6c0 | ev_130ff874cf04a3de16bf345529b447778d9f4458d40b224e9fef13d74f2d1115 =====
 * Body: [{"start":"0x91d330","end":"0x91d33a"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_0091d330(void)

{
  return 0x2d;
}



/* ===== sub_0091d340 | RVA 0x91d340 | file +0x6d0 | ev_a8edb475eb5c2fd667ff221316737c4d02f33975516a9a3eb28021542ef914bc =====
 * Body: [{"start":"0x91d340","end":"0x91d34a"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_0091d340(void)

{
  return 0x2d;
}



/* ===== sub_0091d350 | RVA 0x91d350 | file +0x6e0 | ev_d4f5f2dd094c53cea87878f800812d16d0881c6941e3859c397caff48fe7248c =====
 * Body: [{"start":"0x91d350","end":"0x91d3b4"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined4 sub_0091d350(undefined8 *param_1,long param_2)

{
  long lVar1;
  undefined4 uVar2;
  
  lVar1 = *(long *)*param_1;
  func_0x007d46a0(lVar1 + 0x18,0,0);
  uVar2 = 0x2d;
  if (*(ulong *)(lVar1 + 0x88) <= (ulong)(param_2 + 0x3fff >> 0xe)) {
    uVar2 = func_0x0091ba00(lVar1);
  }
  func_0x007d4eb0(lVar1 + 0x18,0,0);
  return uVar2;
}



/* ===== sub_0091d3c0 | RVA 0x91d3c0 | file +0x750 | ev_8063b3152614291df0eb8d2e3dd418e340f368758fd2d4adf1735e5be842de44 =====
 * Body: [{"start":"0x91d3c0","end":"0x91d3e3"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_0091d3c0(long *param_1,long param_2,uint *param_3)

{
  undefined8 uVar1;
  
  uVar1 = 0x19;
  if (param_2 == 0x4004a200) {
    uVar1 = 0;
    *param_3 = (uint)(*(int *)(*param_1 + 0x18) != 0);
  }
  return uVar1;
}



/* ===== sub_0091d3f0 | RVA 0x91d3f0 | file +0x780 | ev_940750409147d28a310ff538cde16494360212235c1d12f7654bbe1d573cc25b =====
 * Body: [{"start":"0x91d3f0","end":"0x91d3fa"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_0091d3f0(void)

{
  return 0x2d;
}



/* ===== sub_0091d400 | RVA 0x91d400 | file +0x790 | ev_315221115bfd7a107ad67c6ec8a5bae69b1f6b0ea4be7e92428e872016c6ac9b =====
 * Body: [{"start":"0x91d400","end":"0x91d40a"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_0091d400(void)

{
  return 0x2d;
}



/* ===== sub_0091d410 | RVA 0x91d410 | file +0x7a0 | ev_4a6d68f36b1932f70dcb7bd007a29777a7f155d193d30a3146c2228ff78d20b7 =====
 * Body: [{"start":"0x91d410","end":"0x91d491"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_0091d410(long *param_1,long param_2)

{
  long lVar1;
  long lVar2;
  
  param_1 = (long *)*param_1;
  lVar2 = *param_1;
  lVar1 = lVar2 + 0x18;
  func_0x007d46a0(lVar1,0,0);
  lVar2 = *(long *)(lVar2 + 0x88);
  func_0x007d4eb0(lVar1,0,0);
  func_0x00258ff0(param_2,0x78);
  *(undefined4 *)(param_2 + 0x58) = 0x4000;
  *(long *)(param_2 + 0x48) = lVar2 << 0xe;
  *(long *)(param_2 + 0x50) = lVar2;
  *(ushort *)(param_2 + 8) = (ushort)(int)param_1[2] | 0x9000;
  *(int *)(param_2 + 0xc) = (int)param_1[1];
  *(undefined4 *)(param_2 + 0x10) = *(undefined4 *)((long)param_1 + 0xc);
  return 0;
}



/* ===== sub_0091d4a0 | RVA 0x91d4a0 | file +0x830 | ev_6a8312136e81c915563f5cd7033d2fd005f3606fd577179277a8e201214a5491 =====
 * Body: [{"start":"0x91d4a0","end":"0x91d4e0"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_0091d4a0(long *param_1)

{
  int *piVar1;
  int iVar2;
  undefined8 *puVar3;
  
  puVar3 = (undefined8 *)*param_1;
  *param_1 = 0;
  LOCK();
  piVar1 = (int *)((long)puVar3 + 0x14);
  iVar2 = *piVar1;
  *piVar1 = *piVar1 + -1;
  UNLOCK();
  if (iVar2 == 1) {
    func_0x00461ba0(*puVar3);
    func_0x0043c0c0(_DAT_03b76968,puVar3,0);
  }
  return 0;
}



/* ===== sub_0091d4f0 | RVA 0x91d4f0 | file +0x880 | ev_fb221e9a3e8468c696e85c1ebfc438653dd888e650e1bf7ede70f42692ea1b61 =====
 * Body: [{"start":"0x91d4f0","end":"0x91d4fa"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_0091d4f0(void)

{
  return 0x2d;
}



/* ===== sub_0091d500 | RVA 0x91d500 | file +0x890 | ev_9894d6c0a7af48ab84c16bcb757ae981c10ee46cd2c431e84b94c78b233ef2c2 =====
 * Body: [{"start":"0x91d500","end":"0x91d50a"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_0091d500(void)

{
  return 0x2d;
}



/* ===== sub_0091d510 | RVA 0x91d510 | file +0x8a0 | ev_a968281f313f394db485f4e4b71bffab5bac08f5f11540e4610a10fa51f129fd =====
 * Body: [{"start":"0x91d510","end":"0x91d51e"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_0091d510(undefined8 param_1,long param_2)

{
  *(undefined4 *)(param_2 + 4) = 0xff;
  return 0;
}



/* ===== sub_0091d520 | RVA 0x91d520 | file +0x8b0 | ev_85d501a7886d452f01a154491eededbfc1853b4fd683f9bab4f2efb3d0dcaa6d =====
 * Body: [{"start":"0x91d520","end":"0x91d5ba"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined4
sub_0091d520(undefined8 *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined2 param_5,uint param_6,uint param_7,undefined8 param_8,undefined8 param_9)

{
  undefined8 *puVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  undefined4 uVar5;
  
  uVar5 = 0x16;
  if ((param_7 & 2) == 0) {
    uVar3 = 0x11;
    if ((*(uint *)((long)param_1 + 0x24) & 1) == 0) {
      uVar3 = *(uint *)((long)param_1 + 0x24) & 1;
    }
    puVar1 = (undefined8 *)*param_1;
    uVar4 = uVar3 + 0x22;
    if ((*(uint *)((long)param_1 + 0x24) & 2) == 0) {
      uVar4 = uVar3;
    }
    func_0x00461b20(*puVar1);
    iVar2 = func_0x00ab9f30(param_2,param_3,param_4,param_5,param_6 & uVar4,param_7,*puVar1,param_8,
                            0,param_9);
    uVar5 = 0;
    if (iVar2 != 0) {
      func_0x00461ba0(*puVar1);
    }
  }
  return uVar5;
}



/* ===== sub_0091d5c0 | RVA 0x91d5c0 | file +0x950 | ev_003d079bd9399c3eb7b9c7ca22549c065ad6d3eb9a8da7fed15df91f11f34612 =====
 * Body: [{"start":"0x91d5c0","end":"0x91d669"},{"start":"0x91d670","end":"0x91d761"},{"start":"0x91d76f","end":"0x91d776"},{"start":"0x91d81f","end":"0x91d876"},{"start":"0x91d882","end":"0x91d89e"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong sub_0091d5c0(void)

{
  byte bVar1;
  long lVar2;
  code *pcVar3;
  uint uVar4;
  ulong uVar5;
  long lVar6;
  long lVar7;
  long local_48;
  undefined1 local_40 [8];
  long local_38;
  
  local_38 = _DAT_0391c310;
  local_48 = 0;
  uVar4 = func_0x00ab7ea0(1);
  uVar5 = (ulong)uVar4;
  if (uVar4 == 0) {
    if (_DAT_039c9698 == 0) {
      lVar6 = 0xe83d80;
      lVar7 = 0x12d66cb;
      _DAT_039c9698 = 0x39c9670;
      do {
        func_0x0026b9b0(lVar7,0x131fbd7);
        bVar1 = *(byte *)(lVar6 + 8);
        uVar4 = sub_0091d8a0(0,lVar7,bVar1,2,0,0,local_40);
        if (uVar4 == 0) {
          lVar2 = *(long *)(lVar6 + 0x10);
          if (lVar2 == 0) {
            uVar5 = 0;
          }
          else {
            uVar4 = func_0x0096edb0(lVar6,&local_48);
            uVar5 = (ulong)uVar4;
            if (uVar4 != 0) {
              func_0x006f79f0(0x181d528,0x8b,0x1356015,lVar7);
            }
            if (local_48 == 0) {
              local_48 = lVar2;
            }
            lVar7 = func_0x00cac520(0x181d528,0x99,0x10,bVar1);
            if (lVar7 == 0) {
              uVar5 = 4;
              func_0x00ab7f20(1);
              goto LAB_0091d626;
            }
            if (bVar1 - 1 < 9) {
                    /* WARNING: Could not emulate address calculation at 0x0091d759 */
                    /* WARNING: Treating indirect jump as call */
              uVar5 = (*(code *)((long)*(int *)((ulong)(bVar1 - 1) * 4 + 0x181d504) + 0x181d504))();
              return uVar5;
            }
            func_0x006f79f0(0x181d528,0xe9,0x12c38a4,bVar1);
            func_0x00b4a4c0(lVar7);
          }
        }
        else {
          uVar5 = (ulong)uVar4;
          func_0x006f7a90(0x181d528,0x7c,uVar4,0x1290450);
        }
        lVar7 = *(long *)(lVar6 + 0x18);
        lVar6 = lVar6 + 0x18;
      } while (lVar7 != 0);
      func_0x00ab7f20(1);
      if ((int)uVar5 != 0) goto LAB_0091d626;
    }
    else {
      func_0x00ab7f20(1);
    }
    uVar4 = func_0x00ac6f00(0,0x133605e,0,0x39c96a0);
    uVar5 = (ulong)uVar4;
  }
LAB_0091d626:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar3 = (code *)invalidInstructionException();
    (*pcVar3)();
  }
  return uVar5;
}



/* ===== sub_0091d8a0 | RVA 0x91d8a0 | file +0xc30 | ev_47e1b16c41c57889409dcae3b9b7149e9151f982edc2967261ead8ffe2a4d250 =====
 * Body: [{"start":"0x91d8a0","end":"0x91da5e"},{"start":"0x91da60","end":"0x91dc77"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8
sub_0091d8a0(long param_1,char *param_2,uint param_3,undefined4 param_4,uint param_5,long param_6,
            long *param_7)

{
  byte *pbVar1;
  long *plVar2;
  code *pcVar3;
  char cVar4;
  int iVar5;
  uint uVar6;
  undefined8 uVar7;
  undefined8 uVar8;
  long *plVar9;
  char *pcVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  uint uVar14;
  long lVar15;
  bool bVar16;
  int local_60;
  undefined4 local_44;
  long *local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  if (param_7 == (long *)0x0) {
    uVar7 = 0x1001;
    goto LAB_0091dbb2;
  }
  *param_7 = 0;
  _DAT_039c9654 = _DAT_039c9654 + 1;
  if (_DAT_039c9698 == (long *)0x0) {
    uVar7 = 3;
    goto LAB_0091dbb2;
  }
  plVar9 = _DAT_039c9698;
  if ((param_1 != 0) && (plVar2 = *(long **)(param_1 + 0x10), plVar2 != (long *)0x0)) {
    if ((char)plVar2[1] != '\x0f') {
      uVar7 = func_0x004c9cd0(plVar2);
      func_0x006f79f0(0x181d528,0x15d,0x12d909f,plVar2,uVar7);
      uVar7 = 0x300f;
      goto LAB_0091dbb2;
    }
    plVar9 = plVar2;
    if ((param_5 & 0x10) == 0) {
      iVar5 = func_0x00ac6eb0(*(undefined1 *)((long)plVar2 + 9));
      while ((iVar5 == 0 && (*(char *)((long)plVar9 + 9) != '\0'))) {
        plVar9 = (long *)plVar9[2];
        iVar5 = func_0x00ac6eb0(*(undefined1 *)((long)plVar9 + 9));
      }
    }
  }
  if (param_2 == (char *)0x0) {
    local_40 = _DAT_039c9698;
    plVar9 = _DAT_039c9698;
  }
  else {
    cVar4 = *param_2;
    if (cVar4 == '\\') {
      uVar14 = 0;
      cVar4 = param_2[1];
      param_2 = param_2 + 1;
      local_40 = _DAT_039c9698;
    }
    else {
      uVar14 = 1;
      pcVar10 = param_2;
      local_40 = plVar9;
      if (cVar4 == '^') {
        do {
          plVar9 = (long *)plVar9[2];
          local_40 = plVar9;
          if (plVar9 == (long *)0x0) {
            func_0x006f79f0(0x181d528,0x1c2,0x12f7596,param_2);
            uVar7 = 5;
            goto LAB_0091dbb2;
          }
          cVar4 = pcVar10[1];
          pcVar10 = pcVar10 + 1;
        } while (cVar4 == '^');
        uVar14 = 0;
        param_2 = pcVar10;
      }
    }
    plVar9 = local_40;
    if (cVar4 == '/') {
      pbVar1 = (byte *)(param_2 + 1);
      uVar6 = (uint)*pbVar1;
      param_2 = param_2 + 2;
      uVar14 = 0;
      if (*pbVar1 != 0) goto LAB_0091da2e;
    }
    else {
      if (cVar4 == '.') {
        param_2 = param_2 + 1;
        uVar14 = 0;
        uVar6 = 2;
      }
      else {
        uVar6 = 1;
        if (cVar4 == '\0') {
          param_3 = (uint)*(byte *)((long)local_40 + 9);
          goto LAB_0091db74;
        }
      }
      if (uVar6 != 0) {
LAB_0091da2e:
        if (local_40 != (long *)0x0) {
          lVar15 = 0;
          local_60 = uVar6 - 1;
          uVar12 = param_5 & 0xffffff76;
          do {
            bVar16 = local_60 == (int)lVar15;
            local_44 = *(undefined4 *)(param_2 + lVar15 * 4);
            uVar11 = 0;
            if (bVar16) {
              uVar11 = param_3;
            }
            uVar13 = 0;
            if (bVar16) {
              uVar13 = (uVar14 | 0x88) & param_5;
            }
            uVar12 = uVar13 | uVar12;
            uVar7 = func_0x009b8230(local_44,param_6,local_40,param_4,uVar11,uVar12,&local_40);
            if ((int)uVar7 != 0) {
              *param_7 = (long)local_40;
              goto LAB_0091dbb2;
            }
            lVar15 = lVar15 + 1;
            if (uVar6 == (uint)lVar15) {
              if (((0x1b < param_3) || ((0x8600001U >> (param_3 & 0x1f) & 1) == 0)) &&
                 (param_3 != *(byte *)((long)local_40 + 9) && *(byte *)((long)local_40 + 9) != 0)) {
                uVar7 = func_0x004c9c00();
                uVar8 = func_0x004c9c00(param_3);
                func_0x006f7b50(0x181d528,0x294,0x12b92cf,&local_44,uVar7,uVar8);
              }
              plVar9 = local_40;
              if (param_3 == 0) {
                param_3 = (uint)*(byte *)((long)local_40 + 9);
              }
              goto LAB_0091db74;
            }
            if (*(char *)((long)local_40 + 9) == '\x15') {
              if (*local_40 == 0) {
                uVar7 = 6;
                goto LAB_0091dbb2;
              }
              iVar5 = func_0x00ac6eb0(*(undefined1 *)(*local_40 + 9));
              if (iVar5 != 0) {
                local_40 = (long *)*local_40;
              }
            }
          } while (local_40 != (long *)0x0);
          plVar9 = (long *)0x0;
        }
      }
    }
  }
LAB_0091db74:
  if (((param_6 == 0 || (char)((param_5 & 2) >> 1) != '\0') ||
      (iVar5 = func_0x00ac6eb0(param_3), plVar9 = local_40, iVar5 == 0)) ||
     (uVar7 = func_0x007ffc50(local_40,param_3,param_6), plVar9 = local_40, (int)uVar7 == 0)) {
    uVar7 = 0;
    *param_7 = (long)plVar9;
  }
LAB_0091dbb2:
  if (_DAT_0391c310 == local_38) {
    return uVar7;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar3 = (code *)invalidInstructionException();
  (*pcVar3)();
}



/* ===== sub_0091dc80 | RVA 0x91dc80 | file +0x1010 | ev_43bb81d6c89e649dcbc535f20dd9340330f52d3eb320696c9cbcc5623fe978c3 =====
 * Body: [{"start":"0x91dc80","end":"0x91dd87"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_0091dc80(int *param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  uint uVar15;
  
  uVar1 = func_0x00a90cb0();
  iVar2 = func_0x00a90b30();
  iVar3 = func_0x00a90bb0();
  iVar4 = func_0x00a90bf0(0xd7);
  iVar5 = func_0x00a90bf0(0x110);
  iVar6 = func_0x00a90bf0(4);
  iVar7 = func_0x00a90bf0(0x9e);
  iVar8 = func_0x00a90bf0(2);
  iVar9 = func_0x00a90bf0(1);
  iVar10 = func_0x00a90bf0(0x42);
  iVar11 = func_0x00a90bf0(0xcb);
  iVar12 = func_0x00a90c20();
  iVar13 = func_0x00a90b30();
  iVar14 = func_0x00a90ca0();
  uVar15 = iVar14 + -1 +
           iVar13 + iVar12 +
           iVar9 + iVar8 + iVar10 + iVar11 + iVar6 + iVar5 + iVar7 + iVar4 + iVar3 + iVar2 + uVar1;
  *param_1 = (uVar15 - uVar15 % uVar1) * 4;
  return 0;
}



/* ===== sub_0091dd90 | RVA 0x91dd90 | file +0x1120 | ev_ac1401a81c65d0e650716bf8a28f4ce27953c74d780dbbe87a5ed72e15fe845a =====
 * Body: [{"start":"0x91dd90","end":"0x91dfb1"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_0091dd90(undefined4 param_1,long param_2)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  
  uVar1 = func_0x00a90cb0();
  func_0x00a90ab0(2,param_2);
  uVar2 = func_0x00a90b30();
  func_0x00a90b40(param_2 + (ulong)uVar2 * 4);
  iVar3 = func_0x00a90bb0();
  func_0x00a90bc0(0xa000,0x181d540,0xd7,param_2 + (ulong)(iVar3 + uVar2) * 4);
  iVar4 = func_0x00a90bf0(0xd7);
  uVar2 = iVar4 + iVar3 + uVar2;
  func_0x00a90bc0(0xa0d8,0x181db40,0x110,param_2 + (ulong)uVar2 * 4);
  iVar3 = func_0x00a90bf0(0x110);
  uVar2 = iVar3 + uVar2;
  func_0x00a90bc0(0xa1f5,0x181d8a0,4,param_2 + (ulong)uVar2 * 4);
  iVar3 = func_0x00a90bf0(4);
  uVar2 = iVar3 + uVar2;
  func_0x00a90bc0(0xa1ff,0x181d8b0,0x9e,param_2 + (ulong)uVar2 * 4);
  iVar3 = func_0x00a90bf0(0x9e);
  uVar2 = iVar3 + uVar2;
  func_0x00a90bc0(0xa2a0,0x181db28,2,param_2 + (ulong)uVar2 * 4);
  iVar3 = func_0x00a90bf0(2);
  uVar2 = iVar3 + uVar2;
  func_0x00a90bc0(0xa2a3,0x181db30,1,param_2 + (ulong)uVar2 * 4);
  iVar3 = func_0x00a90bf0(1);
  uVar2 = iVar3 + uVar2;
  func_0x00a90bc0(0xa2a5,0x181df80,0x42,param_2 + (ulong)uVar2 * 4);
  iVar3 = func_0x00a90bf0(0x42);
  uVar2 = iVar3 + uVar2;
  func_0x00a90bc0(0xa2f5,0x181e090,0xcb,param_2 + (ulong)uVar2 * 4);
  iVar3 = func_0x00a90bf0(0xcb);
  uVar2 = iVar3 + uVar2;
  func_0x00a90c00(0xa0d7,param_1,param_2 + (ulong)uVar2 * 4);
  iVar3 = func_0x00a90c20();
  uVar2 = iVar3 + uVar2;
  func_0x00a90ab0(3,param_2 + (ulong)uVar2 * 4);
  iVar3 = func_0x00a90b30();
  uVar2 = iVar3 + uVar2;
  func_0x00a90c30(param_2 + (ulong)uVar2 * 4);
  iVar3 = func_0x00a90ca0();
  uVar2 = iVar3 + uVar2;
  uVar5 = uVar2 % uVar1;
  if (uVar5 != 0) {
    iVar4 = uVar1 - uVar5;
    iVar3 = 0x4001;
    if (iVar4 != 1) {
      iVar3 = iVar4;
    }
    func_0x00a90cc0(param_2 + (ulong)uVar2 * 4,iVar3);
  }
  return 0;
}



/* ===== sub_0091dfc0 | RVA 0x91dfc0 | file +0x1350 | ev_6f43b732fdbd6b93b2abf25fef9aad3bf68df6fe774fac40d04aa574497b9492 =====
 * Body: [{"start":"0x91dfc0","end":"0x91e0ac"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

byte * sub_0091dfc0(byte *param_1,byte param_2,long param_3)

{
  long lVar1;
  byte *pbVar2;
  byte *pbVar3;
  long lVar4;
  long *plVar5;
  
  if (param_3 == 0) {
    return (byte *)0x0;
  }
  pbVar3 = param_1 + param_3;
  plVar5 = (long *)((ulong)param_1 & 0xfffffffffffffff8);
  lVar4 = CONCAT44((uint)param_2 * 0x1010101,(uint)param_2 * 0x1010101);
  if ((param_1 < plVar5 + 1) && (*plVar5 != lVar4)) {
    pbVar2 = param_1 + (-8 - (long)plVar5);
    do {
      if (*param_1 != param_2) goto LAB_0091e0a2;
      param_1 = param_1 + 1;
      pbVar2 = pbVar2 + 1;
    } while (pbVar2 != (byte *)0x0);
  }
  param_1 = (byte *)(plVar5 + 1);
  while( true ) {
    if (pbVar3 <= param_1) {
      return (byte *)0x0;
    }
    lVar1 = *(long *)param_1;
    if (lVar1 != lVar4) break;
    param_1 = param_1 + 8;
  }
  if ((byte)lVar1 == param_2) {
    if ((byte)((ulong)lVar1 >> 8) == param_2) {
      if ((byte)((ulong)lVar1 >> 0x10) == param_2) {
        if ((byte)((ulong)lVar1 >> 0x18) == param_2) {
          if ((byte)((ulong)lVar1 >> 0x20) == param_2) {
            if ((byte)((ulong)lVar1 >> 0x28) == param_2) {
              param_1 = param_1 + (ulong)((byte)((ulong)lVar1 >> 0x30) == param_2) + 6;
            }
            else {
              param_1 = param_1 + 5;
            }
          }
          else {
            param_1 = param_1 + 4;
          }
        }
        else {
          param_1 = param_1 + 3;
        }
      }
      else {
        param_1 = param_1 + 2;
      }
    }
    else {
      param_1 = param_1 + 1;
    }
  }
LAB_0091e0a2:
  pbVar2 = (byte *)0x0;
  if (param_1 < pbVar3) {
    pbVar2 = param_1;
  }
  return pbVar2;
}



/* ===== sub_0091e0b0 | RVA 0x91e0b0 | file +0x1440 | ev_d4f93c564197a2ebca0b9f0c1282b8a65fc0b52b5ee0b2bd73823314bf5c182f =====
 * Body: [{"start":"0x91e0b0","end":"0x91e123"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 sub_0091e0b0(long param_1)

{
  long lVar1;
  
  lVar1 = 0;
  func_0x00c4bb20(0x3b769a0,0,0,0);
  do {
    if (*(long *)(&DAT_03b78028 + lVar1 * 8) == param_1) {
      func_0x00c4c4b0(0x3b769a0,0,0);
      return _DAT_03b78004;
    }
    lVar1 = lVar1 + 1;
  } while (lVar1 != 0x80);
  func_0x00c4c4b0(0x3b769a0,0,0);
  return 0;
}



/* ===== sub_0091e130 | RVA 0x91e130 | file +0x14c0 | ev_bf2d5aefa3e4661470636d61ce0db586dd1dfe884b35c9f6dd7c18f5fda4b89f =====
 * Body: [{"start":"0x91e130","end":"0x91e201"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_0091e130(undefined8 param_1,int param_2)

{
  undefined8 uVar1;
  
  if (param_2 == 1) {
    func_0x00261090(0x3b769a0);
    uVar1 = 0;
    if (_DAT_03b78430 != 0) {
      func_0x006dfbb0();
      _DAT_03b78430 = 0;
    }
  }
  else {
    uVar1 = 0x2d;
    if (param_2 == 0) {
      uVar1 = 0;
      _DAT_03b78430 = func_0x006df480(0x2551fb8,0,0,0,0x180,0x12a4d9f);
      if (_DAT_03b78430 == 0) {
        uVar1 = 0xc;
      }
      else {
        func_0x00c4b290(0x3b769a0,0x12e302d,0);
        func_0x00258ff0(&DAT_03b78438,0x808);
        func_0x0073dd40(0,0x12a82d8,0x263f18,0x1286492,0,20000);
      }
    }
  }
  return uVar1;
}



/* ===== sub_0091e210 | RVA 0x91e210 | file +0x15a0 | ev_3bdb134d6eca3a96e4b392e7b7c7db18d82409ba02586ffd6377e30d606db45c =====
 * Body: [{"start":"0x91e210","end":"0x91e260"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_0091e210(void)

{
  int iVar1;
  
  if (_DAT_03b78438 != 0) {
    iVar1 = sub_0091e450(0,0,0x3b78440,0x800,_DAT_03b7843c,1);
    if (iVar1 != 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
  }
  return;
}



/* ===== sub_0091e270 | RVA 0x91e270 | file +0x1600 | ev_1e31a6fba655e6d41e39811e35bd1bc5666de2b42b626c8efca6ec9a6d117100 =====
 * Body: [{"start":"0x91e270","end":"0x91e28a"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

bool sub_0091e270(void)

{
  int iVar1;
  long in_RCX;
  
  iVar1 = func_0x0026d0a0(*(undefined8 *)(in_RCX + 0x140));
  return iVar1 == 0;
}



/* ===== sub_0091e290 | RVA 0x91e290 | file +0x1620 | ev_e6b689bb48498197850f74f24db295fd5509989e13ea81086b4e9b548d75fc61 =====
 * Body: [{"start":"0x91e290","end":"0x91e297"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_0091e290(void)

{
  return 0;
}



/* ===== sub_0091e2a0 | RVA 0x91e2a0 | file +0x1630 | ev_2fb0578786338e683a8ad618bf151ee4fef12928beca7a9e3a4a2aa99043fa26 =====
 * Body: [{"start":"0x91e2a0","end":"0x91e448"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_0091e2a0(undefined8 param_1,long param_2,undefined8 *param_3)

{
  ulong uVar1;
  code *pcVar2;
  int iVar3;
  int iVar4;
  undefined8 uVar5;
  long lVar6;
  ulong uVar7;
  undefined8 *in_GS_OFFSET;
  undefined4 local_44;
  ulong local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  if (param_2 == 0xc0305203) {
    if (_DAT_03b78438 == 0) {
      iVar3 = -0x28;
    }
    else {
      iVar3 = sub_0091e450(0,0,0x3b78440,0x800,_DAT_03b7843c,1);
    }
  }
  else {
    if (param_2 == 0xc0305202) {
      local_44 = 1;
      uVar7 = 0x100800;
    }
    else {
      uVar5 = 0xfffffffd;
      if (param_2 != 0xc0305201) goto LAB_0091e3f2;
      uVar7 = 0x8800;
      local_44 = 0;
    }
    lVar6 = func_0x00c08b50(0x100800,0x2551eb0,0x102);
    uVar1 = param_3[4];
    local_40 = 0;
    if (uVar7 < uVar1 || uVar1 < 0x801) {
      iVar3 = -0x16;
      iVar4 = -0x16;
      if (lVar6 == 0) goto LAB_0091e3ec;
    }
    else {
      uVar5 = param_3[3];
      func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
      iVar3 = func_0x00259280(uVar5,lVar6,uVar1);
      iVar4 = -0xe;
      if ((iVar3 == 0) && (iVar4 = sub_0091e450(lVar6,&local_40,lVar6,uVar1,local_44,0), iVar4 == 0)
         ) {
        iVar4 = -0x16;
        if ((param_3[1] != 0) && (local_40 <= (ulong)param_3[1])) {
          param_3[2] = local_40;
          iVar3 = sub_0091e810(lVar6,*param_3);
          iVar4 = -0xe;
          if (iVar3 == 0) {
            iVar4 = 0;
          }
        }
      }
    }
    iVar3 = iVar4;
    func_0x00c08df0(lVar6,0x2551eb0);
  }
LAB_0091e3ec:
  uVar5 = 0;
  *(int *)(param_3 + 5) = iVar3;
LAB_0091e3f2:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar2 = (code *)invalidInstructionException();
    (*pcVar2)();
  }
  return uVar5;
}



/* ===== sub_0091e450 | RVA 0x91e450 | file +0x17e0 | ev_7619b418817ba5362a20ff2f8d7f877ea802e6f9e6cda3876e0c93884e0cfec1 =====
 * Body: [{"start":"0x91e450","end":"0x91e80b"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_0091e450(undefined8 param_1,ulong *param_2,long param_3,ulong param_4,int param_5,
                int param_6)

{
  code *pcVar1;
  long lVar2;
  ulong uVar3;
  int iVar4;
  int iVar5;
  ulong uVar6;
  long local_150;
  ulong local_148;
  long local_140;
  undefined8 local_138;
  ulong local_130;
  ulong local_128;
  undefined8 local_120;
  undefined8 local_118;
  undefined8 local_110;
  undefined8 local_108;
  undefined8 local_100;
  undefined8 local_f8;
  undefined8 local_f0;
  undefined8 local_e8;
  undefined8 local_e0;
  undefined8 local_d8;
  undefined8 local_d0;
  undefined8 local_c8;
  undefined8 local_c0;
  undefined8 local_b8;
  undefined8 local_b0;
  undefined8 local_a8;
  undefined8 local_a0;
  undefined8 local_98;
  undefined8 local_90;
  undefined8 local_88;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  long local_38;
  
  uVar6 = 0x100800;
  local_38 = _DAT_0391c310;
  local_140 = -1;
  local_c0 = 0;
  local_c8 = 0;
  local_d0 = 0;
  local_d8 = 0;
  local_e0 = 0;
  local_e8 = 0;
  local_f0 = 0;
  local_f8 = 0;
  local_100 = 0;
  local_108 = 0;
  local_110 = 0;
  local_118 = 0;
  local_120 = 0;
  local_128 = 0;
  local_130 = 0;
  local_138 = 0;
  local_148 = 0;
  local_150 = 0;
  if (param_5 == 0) {
    uVar6 = 0x8800;
  }
  func_0x00c4bb20(0x3b769a0,0,0,0);
  if (param_6 == 0) {
    _DAT_03b78438 = 1;
    _DAT_03b7843c = param_5;
    func_0x002590b0(0x3b78440,param_3,0x800);
  }
  iVar4 = func_0x00637a70(&local_148,&local_150,param_3,param_4,0x3b7c000,0x4000);
  if ((iVar4 == 0) && (iVar4 = func_0x005a4200(0x1336064,0,0,0,0,1,&local_140), iVar4 == 0)) {
    local_138 = (ulong)(ushort)(2 - (param_5 == 0));
    local_130 = local_148;
    local_128 = param_4;
    local_120 = func_0x008de330(0x3b78000);
    local_118 = CONCAT44(local_118._4_4_,param_6);
    iVar5 = func_0x005a4610(local_140,&local_138);
    uVar3 = local_128;
    if (iVar5 == 0 && local_138._4_4_ == 0) {
      iVar4 = 0;
      if (((param_6 == 0) && (iVar4 = -0x26, local_130 < 0x801)) && (local_128 <= uVar6)) {
        func_0x002590b0(param_1,param_3 + local_130,local_128);
        *param_2 = uVar3;
        iVar4 = 0;
      }
    }
    else {
      iVar4 = local_138._4_4_;
      if (iVar5 != 0) {
        iVar4 = iVar5;
      }
    }
  }
  lVar2 = local_140;
  if (local_140 != -1) {
    local_40 = 0;
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
    local_b0 = 0;
    local_b8 = 0xffff;
    iVar5 = func_0x005a4610(local_140,&local_b8);
    if (iVar5 == 0) {
      func_0x005a4570(lVar2);
    }
  }
  if (local_150 != 0) {
    func_0x00637a90();
  }
  func_0x00c4c4b0(0x3b769a0,0,0);
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar1 = (code *)invalidInstructionException();
    (*pcVar1)();
  }
  return iVar4;
}



/* ===== sub_0091e810 | RVA 0x91e810 | file +0x1ba0 | ev_699876fb2cc11ebd4c9f0fd5ab685e6fe6d0c27196eecf497c971f0a30f47024 =====
 * Body: [{"start":"0x91e810","end":"0x91e851"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_0091e810(void)

{
  undefined8 *in_GS_OFFSET;
  
  func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== sub_0091e860 | RVA 0x91e860 | file +0x1bf0 | ev_f5008aab168451143e50c5ba29b08b254184e38c0a71ea047ccc4bc070b99847 =====
 * Body: [{"start":"0x91e860","end":"0x91e886"},{"start":"0x91e890","end":"0x91e8ef"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_0091e860(long param_1,undefined8 *param_2,int param_3)

{
  undefined8 *puVar1;
  undefined8 *puVar2;
  
  puVar1 = *(undefined8 **)(param_1 + 0xb8);
  puVar2 = param_2;
  if (0 < param_3) {
    do {
      *(uint *)((long)puVar2 + 0x1c) =
           *(uint *)((long)puVar2 + 0x1c) & ((uint)(puVar1 != param_2) << 0x15 | 0xffcfffff);
      if (puVar1 == param_2) {
        *(int *)(param_1 + 0xc4) = *(int *)(param_1 + 0xc4) + *(int *)(puVar2 + 3);
      }
      puVar2 = (undefined8 *)*puVar2;
      param_3 = param_3 + -1;
    } while (param_3 != 0);
  }
  if (puVar1 != param_2) {
    return 0x24;
  }
  for (; puVar2 != (undefined8 *)0x0; puVar2 = (undefined8 *)*puVar2) {
    if ((*(uint *)((long)puVar2 + 0x1c) & 0x100000) != 0) goto LAB_0091e8e7;
    *(uint *)((long)puVar2 + 0x1c) = *(uint *)((long)puVar2 + 0x1c) & 0xffcfffff;
    *(int *)(param_1 + 0xc4) = *(int *)(param_1 + 0xc4) + *(int *)(puVar2 + 3);
  }
  puVar2 = (undefined8 *)0x0;
LAB_0091e8e7:
  *(undefined8 **)(param_1 + 0xb8) = puVar2;
  return 0;
}



/* ===== sub_0091e8f0 | RVA 0x91e8f0 | file +0x1c80 | ev_5104db1d4040265a9350fef5e98cb117b843bfc338016a39a73ac3ea9328cbaa =====
 * Body: [{"start":"0x91e8f0","end":"0x91e9a3"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_0091e8f0(long param_1,long param_2)

{
  int iVar1;
  
  *(int *)(param_1 + 200) = *(int *)(param_1 + 200) + *(int *)(param_2 + 0x18);
  func_0x00697590(param_1,*(undefined4 *)(param_2 + 0x18));
  if (*(uint *)(param_1 + 0x94) < *(uint *)(param_1 + 200)) {
    *(uint *)(param_1 + 0x94) = *(uint *)(param_1 + 200);
  }
  if (*(long *)(param_1 + 0xb8) == 0) {
    if ((*(uint *)(param_2 + 0x1c) & 0x100000) == 0) {
      *(int *)(param_1 + 0xc4) = *(int *)(param_1 + 0xc4) + *(int *)(param_2 + 0x18);
    }
    else {
      *(long *)(param_1 + 0xb8) = param_2;
    }
  }
  else {
    *(uint *)(param_2 + 0x1c) = *(uint *)(param_2 + 0x1c) | 0x200000;
  }
  if ((*(char *)(param_2 + 0x1c) != '\x01') && (*(char *)(param_2 + 0x1c) != '\x10')) {
    *(int *)(param_1 + 0xe0) = *(int *)(param_1 + 0xe0) + *(int *)(param_2 + 0x18);
  }
  iVar1 = *(int *)(param_1 + 0xd0) + 0x100;
  *(int *)(param_1 + 0xd0) = iVar1;
  *(int *)(param_1 + 0xd4) = *(int *)(param_1 + 0xd4) + 1;
  if ((*(byte *)(param_2 + 0x1d) & 1) != 0) {
    *(int *)(param_1 + 0xd0) = iVar1 + *(int *)(param_2 + 0x88);
    *(int *)(param_1 + 0xd8) = *(int *)(param_1 + 0xd8) + 1;
  }
  return;
}



/* ===== sub_0091e9b0 | RVA 0x91e9b0 | file +0x1d40 | ev_9532ff27f665afe00c25504c9c758b6a94ba3fba45d1d276d8dd8e8086435444 =====
 * Body: [{"start":"0x91e9b0","end":"0x91eab0"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_0091e9b0(long param_1,undefined8 *param_2)

{
  int iVar1;
  undefined8 *puVar2;
  
  *(int *)(param_1 + 200) = *(int *)(param_1 + 200) - *(int *)(param_2 + 3);
  func_0x00697650(param_1,*(undefined4 *)(param_2 + 3));
  if ((*(byte *)((long)param_2 + 0x1e) & 0x30) == 0) {
    *(int *)(param_1 + 0xc4) = *(int *)(param_1 + 0xc4) - *(int *)(param_2 + 3);
    puVar2 = *(undefined8 **)(param_1 + 0xb8);
  }
  else {
    puVar2 = *(undefined8 **)(param_1 + 0xb8);
  }
  if (param_2 == puVar2) {
    for (puVar2 = (undefined8 *)*param_2; puVar2 != (undefined8 *)0x0;
        puVar2 = (undefined8 *)*puVar2) {
      if ((*(uint *)((long)puVar2 + 0x1c) & 0x100000) != 0) goto LAB_0091ea27;
      *(uint *)((long)puVar2 + 0x1c) = *(uint *)((long)puVar2 + 0x1c) & 0xffcfffff;
      *(int *)(param_1 + 0xc4) = *(int *)(param_1 + 0xc4) + *(int *)(puVar2 + 3);
    }
    puVar2 = (undefined8 *)0x0;
LAB_0091ea27:
    *(undefined8 **)(param_1 + 0xb8) = puVar2;
  }
  if ((*(char *)((long)param_2 + 0x1c) != '\x01') && (*(char *)((long)param_2 + 0x1c) != '\x10')) {
    *(int *)(param_1 + 0xe0) = *(int *)(param_1 + 0xe0) - *(int *)(param_2 + 3);
  }
  iVar1 = *(int *)(param_1 + 0xd0) + -0x100;
  *(int *)(param_1 + 0xd0) = iVar1;
  *(int *)(param_1 + 0xd4) = *(int *)(param_1 + 0xd4) + -1;
  if ((*(byte *)((long)param_2 + 0x1d) & 1) != 0) {
    *(int *)(param_1 + 0xd0) = iVar1 - *(int *)(param_2 + 0x11);
    *(int *)(param_1 + 0xd8) = *(int *)(param_1 + 0xd8) + -1;
  }
  if (*(undefined8 **)(param_1 + 0xb0) == param_2) {
    *(undefined8 *)(param_1 + 0xb0) = 0;
    *(undefined4 *)(param_1 + 0xc0) = 0;
  }
  else if (*(int *)(param_1 + 0xc0) != 0) {
    *(int *)(param_1 + 0xc0) = *(int *)(param_1 + 0xc0) - *(int *)(param_2 + 3);
  }
  return;
}



/* ===== sub_0091eac0 | RVA 0x91eac0 | file +0x1e50 | ev_73a48874e135bf56648a6c9d0fc17a2e17aae9c2482fae6c240efe01a59b63e8 =====
 * Body: [{"start":"0x91eac0","end":"0x91eb6c"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted.","Ghidra Listing reports a terminal call at 0x91eb51 to 0x91eb70 sub_0091eb70 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Possible PIC construction at 0x0091eb09: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x0091eb0e) */

void sub_0091eac0(long param_1)

{
  long lVar1;
  
  *(byte *)(param_1 + 0x260) = *(byte *)(param_1 + 0x260) | 0x10;
  lVar1 = *(long *)(param_1 + 0x448);
  if ((*(ushort *)(param_1 + 0x2c0) & 0x1bc) != 0) {
    sub_0091eb70(param_1,param_1 + 0x1d0);
    if ((lVar1 == 0) || ((*(byte *)(param_1 + 0x10) & 1) != 0)) {
      return;
    }
    func_0x004c6a00(lVar1 + 0x238,0,0,0);
    *(undefined2 *)(lVar1 + 0x76) = 0xa5;
    if ((*(ushort *)(lVar1 + 0x2c0) & 0x1bc) != 0) {
      sub_0091eb70(lVar1,lVar1 + 0x1d0);
      return;
    }
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== sub_0091eb70 | RVA 0x91eb70 | file +0x1f00 | ev_1e7e7de2792d890d706a7a51d95febfe24da3aa707e66a913da3160f810347ab =====
 * Body: [{"start":"0x91eb70","end":"0x91ecac"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_0091eb70(long param_1,long *param_2)

{
  byte bVar1;
  ushort uVar2;
  code *pcVar3;
  ushort uVar4;
  int iVar5;
  
  func_0x004ef210(param_2,0x58);
  uVar2 = *(ushort *)(param_2 + 0x1e);
  uVar4 = uVar2;
  if (*param_2 == 0) {
    *(ushort *)(param_2 + 0x1e) = uVar2 & 0xfff7;
    uVar4 = uVar2 & 0xfff7;
  }
  if ((uVar2 & 4) != 0) {
    *(ushort *)(param_2 + 0x1e) = uVar4 & 0xfffb;
    func_0x00c06910((long)param_2 + 0xc4);
  }
  func_0x00313d50(param_2 + 2,0,1);
  pcVar3 = (code *)param_2[0x21];
  if (pcVar3 != (code *)0x0) {
    if (0xa4 < (-(long)pcVar3 + 0x26b550U >> 3 | -(long)pcVar3 << 0x3d)) {
      func_0x0044f8c0(0x2552090,pcVar3);
    }
    iVar5 = (*pcVar3)(param_1,param_2[0x22],1);
    if (iVar5 == 1) {
      func_0x0050d4f0(param_1,1);
      func_0x004c6fa0(param_2 + 0xd,0,0,0);
      func_0x0050d030(param_1);
      bVar1 = *(byte *)(param_1 + 0x11);
      goto joined_r0x0091ec4e;
    }
  }
  func_0x004c6fa0(param_2 + 0xd,0,0,0);
  bVar1 = *(byte *)(param_1 + 0x11);
joined_r0x0091ec4e:
  if (((bVar1 & 2) != 0) && (*(long *)(param_1 + 0x78) != 0)) {
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  return;
}



/* ===== sub_0091ecb0 | RVA 0x91ecb0 | file +0x2040 | ev_fcc5f84e47641f74b90c3ac88025d3fdd0cfb6a86538ed480b1d8087435e1bfd =====
 * Body: [{"start":"0x91ecb0","end":"0x91ecd8"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted.","Ghidra Listing reports a terminal call at 0x91ecd4 to 0x91eac0 sub_0091eac0 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

void sub_0091ecb0(long param_1)

{
  func_0x004c6a00(param_1 + 0x238,0,0,0);
  sub_0091eac0(param_1);
  return;
}



/* ===== sub_0091ece0 | RVA 0x91ece0 | file +0x2070 | ev_9336f0c7fbd9dce1ff1ea8f8bc56b83bdecaebd4cdef89492952b63593d7f2af =====
 * Body: [{"start":"0x91ece0","end":"0x91ed8c"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted.","Ghidra Listing reports a terminal call at 0x91ed71 to 0x91eb70 sub_0091eb70 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Possible PIC construction at 0x0091ed29: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x0091ed2e) */

void sub_0091ece0(long param_1)

{
  long lVar1;
  
  *(byte *)(param_1 + 0x118) = *(byte *)(param_1 + 0x118) | 0x20;
  lVar1 = *(long *)(param_1 + 0x448);
  if ((*(ushort *)(param_1 + 0x178) & 0x1bc) != 0) {
    sub_0091eb70(param_1,param_1 + 0x88);
    if ((lVar1 == 0) || ((*(byte *)(param_1 + 0x10) & 1) != 0)) {
      return;
    }
    func_0x004c6a00(lVar1 + 0xf0,0,0,0);
    *(undefined2 *)(lVar1 + 0x76) = 0xa5;
    if ((*(ushort *)(lVar1 + 0x178) & 0x1bc) != 0) {
      sub_0091eb70(lVar1,lVar1 + 0x88);
      return;
    }
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== sub_0091ed90 | RVA 0x91ed90 | file +0x2120 | ev_92e53b63a3ad3a5deabbedb4507188c0f04a3a45a4bb6894f23bb6f1a7047053 =====
 * Body: [{"start":"0x91ed90","end":"0x91edb8"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted.","Ghidra Listing reports a terminal call at 0x91edb4 to 0x91ece0 sub_0091ece0 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

void sub_0091ed90(long param_1)

{
  func_0x004c6a00(param_1 + 0xf0,0,0,0);
  sub_0091ece0(param_1);
  return;
}



/* ===== sub_0091edc0 | RVA 0x91edc0 | file +0x2150 | ev_d3b60f116450244ef2341477151cea3f5e95b5f4b3ee0f25a5e972450163f464 =====
 * Body: [{"start":"0x91edc0","end":"0x91eef3"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_0091edc0(long param_1)

{
  long lVar1;
  code *pcVar2;
  undefined8 uVar3;
  ushort uVar4;
  long lVar5;
  long lVar6;
  ulong uVar7;
  long local_38;
  long local_30;
  long local_28;
  
  local_28 = _DAT_0391c310;
  *(byte *)(param_1 + 0xf0) = *(byte *)(param_1 + 0xf0) | 4;
  func_0x00acf7c0(&local_38);
  uVar4 = *(ushort *)(param_1 + 0xf0);
  if ((uVar4 & 0x4000) == 0) {
    uVar7 = (ulong)(local_30 * 0x10c6f7a0b5ed) >> 0x20 | local_38 << 0x20;
    lVar6 = *(long *)(param_1 + 0xe8);
LAB_0091ee82:
    uVar3 = func_0x00c06260(param_1 + 0xc4,param_1 + 0x50,(uint)((uVar4 & 0x40) == 0) << 0xc | 0x58,
                            0x13944a6,lVar6,0,0);
    uVar4 = *(ushort *)(param_1 + 0xf0);
    if ((int)uVar3 == -1) {
      *(ulong *)(param_1 + 0x100) = uVar7;
      uVar4 = uVar4 | 0x4000;
      uVar3 = 0xffffffff;
      goto LAB_0091eed2;
    }
  }
  else {
    lVar1 = *(long *)(param_1 + 0xe8);
    uVar7 = *(ulong *)(param_1 + 0x100);
    lVar6 = lVar1;
    if (lVar1 < 1) goto LAB_0091ee82;
    uVar3 = 0x23;
    lVar5 = ((ulong)(local_30 * 0x10c6f7a0b5ed) >> 0x20 | local_38 << 0x20) - uVar7;
    lVar6 = lVar1 - lVar5;
    if (lVar6 != 0 && lVar5 <= lVar1) goto LAB_0091ee82;
  }
  uVar4 = uVar4 & 0xbfff;
  *(undefined8 *)(param_1 + 0x100) = 0;
LAB_0091eed2:
  *(ushort *)(param_1 + 0xf0) = uVar4;
  if (_DAT_0391c310 != local_28) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar2 = (code *)invalidInstructionException();
    (*pcVar2)();
  }
  return uVar3;
}



/* ===== sub_0091ef00 | RVA 0x91ef00 | file +0x2290 | ev_6aef0a28f200319a7987bd944ce08b5f089bf3633bacaffe0ea53831f46a80f9 =====
 * Body: [{"start":"0x91ef00","end":"0x91ef6b"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Possible PIC construction at 0x0091ef60: Changing call to branch */

undefined4 sub_0091ef00(long param_1,ulong param_2)

{
  int iVar1;
  undefined4 uVar2;
  
  if ((param_2 & 1) != 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  iVar1 = func_0x00c4c210(param_1 + 0x70,0,0);
  uVar2 = 0x23;
  if (iVar1 != 0) {
    uVar2 = 0;
  }
  return uVar2;
}



/* ===== sub_0091ef70 | RVA 0x91ef70 | file +0x2300 | ev_8b6f778e52749adedbbdb52d9cd4dd2f0e8b43b2fb01a879f254a036e264e642 =====
 * Body: [{"start":"0x91ef70","end":"0x91ef81"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_0091ef70(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== sub_0091ef90 | RVA 0x91ef90 | file +0x2320 | ev_7c0cd0b8ca7c161cb17f23c8db774b60d122d93f31b1761df046acb90bddec5f =====
 * Body: [{"start":"0x91ef90","end":"0x91f143"},{"start":"0x91f150","end":"0x91f1e9"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_0091ef90(long param_1,ulong param_2,ulong param_3)

{
  uint *puVar1;
  uint uVar2;
  long lVar3;
  uint uVar4;
  int iVar5;
  undefined8 uVar6;
  undefined8 extraout_RDX;
  undefined8 extraout_RDX_00;
  uint uVar7;
  long *in_GS_OFFSET;
  
  lVar3 = *in_GS_OFFSET;
  func_0x004c6a00(param_1 + 0x238,0,0,0);
  func_0x004c6a00(param_1 + 0xf0,0,0,0);
  if (param_2 <= _DAT_02552080) {
    uVar6 = 0x7fffffffffffffff;
    if (lVar3 != 0) {
      uVar6 = func_0x004a21b0(lVar3,9,extraout_RDX,0x7fffffffffffffff);
    }
    puVar1 = (uint *)(param_1 + 0x29c);
    iVar5 = func_0x004a26d0(*(undefined8 *)(*(long *)(param_1 + 0x318) + 0x20),puVar1,
                            param_2 & 0xffffffff,uVar6);
    if (iVar5 != 0) {
      uVar7 = (int)param_2 * _DAT_025520b0;
      if (_DAT_02552078 <= uVar7) {
        uVar7 = _DAT_02552078;
      }
      *(uint *)(param_1 + 0x2ac) = uVar7;
      if (*(uint *)(param_1 + 0x29c) < *(uint *)(param_1 + 0x2b4)) {
        *(uint *)(param_1 + 0x2b4) = *(uint *)(param_1 + 0x29c);
      }
      if (param_3 <= _DAT_02552080) {
        uVar6 = 0x7fffffffffffffff;
        if (lVar3 != 0) {
          uVar6 = func_0x004a21b0(lVar3,9,extraout_RDX_00,0x7fffffffffffffff);
        }
        iVar5 = func_0x004a26d0(*(undefined8 *)(*(long *)(param_1 + 0x318) + 0x20),param_1 + 0x154,
                                param_3 & 0xffffffff,uVar6);
        if (iVar5 != 0) {
          uVar7 = (int)param_3 * _DAT_025520b0;
          if (_DAT_02552078 <= uVar7) {
            uVar7 = _DAT_02552078;
          }
          *(uint *)(param_1 + 0x164) = uVar7;
          uVar7 = *(uint *)(param_1 + 0x154);
          uVar2 = *(uint *)(param_1 + 0x16c);
          uVar4 = uVar7;
          if (uVar2 < uVar7) {
            uVar4 = uVar2;
          }
          if (uVar7 < uVar2 || uVar4 == 0) {
            *(uint *)(param_1 + 0x16c) = uVar4 + (uVar4 == 0);
          }
          uVar7 = *(uint *)(param_1 + 0x2b4);
          if (uVar7 == 0) {
            uVar7 = 0x800;
            *(undefined4 *)(param_1 + 0x2b4) = 0x800;
          }
          uVar6 = 0;
          if (*puVar1 < uVar7) {
            *(uint *)(param_1 + 0x2b4) = *puVar1;
          }
          goto LAB_0091f1bc;
        }
      }
      if (*(int *)(param_1 + 0x2a0) != 0) {
        do {
          if ((*(int *)(param_1 + 0x298) == 0) &&
             ((*(long *)(param_1 + 0x268) == 0 || (*(int *)(*(long *)(param_1 + 0x268) + 0x18) != 0)
              ))) break;
          uVar6 = func_0x0091ff20(param_1 + 0x1d0);
          func_0x0042a850(uVar6);
        } while (*(int *)(param_1 + 0x2a0) != 0);
      }
      func_0x004a26d0(*(undefined8 *)(*(long *)(param_1 + 0x318) + 0x20),puVar1,0,0x7fffffffffffffff
                     );
      *(undefined4 *)(param_1 + 0x2ac) = 0;
    }
  }
  uVar6 = 0x37;
LAB_0091f1bc:
  func_0x004c6fa0(param_1 + 0xf0,0,0,0);
  func_0x004c6fa0(param_1 + 0x238,0,0,0);
  return uVar6;
}



/* ===== sub_0091f1f0 | RVA 0x91f1f0 | file +0x2580 | ev_efd1f06c300a7330e5342b447c5986c2d9a5937481fcb7c98e4778ecd2b2e270 =====
 * Body: [{"start":"0x91f1f0","end":"0x91f297"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_0091f1f0(long param_1,ulong param_2,long param_3,long param_4)

{
  int iVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  uint uVar4;
  
  uVar3 = 0;
  if (param_2 <= _DAT_02552080) {
    if (param_4 == 0) {
      uVar2 = 0x7fffffffffffffff;
    }
    else {
      uVar2 = func_0x004a21b0(param_4,9);
    }
    iVar1 = func_0x004a26d0(*(undefined8 *)(*(long *)(param_3 + 0x318) + 0x20),param_1 + 0xcc,
                            param_2 & 0xffffffff,uVar2);
    if (iVar1 != 0) {
      uVar4 = (int)param_2 * _DAT_025520b0;
      uVar3 = 1;
      if (_DAT_02552078 <= uVar4) {
        uVar4 = _DAT_02552078;
      }
      *(uint *)(param_1 + 0xdc) = uVar4;
      if (*(uint *)(param_1 + 0xcc) < *(uint *)(param_1 + 0xe4)) {
        *(uint *)(param_1 + 0xe4) = *(uint *)(param_1 + 0xcc);
      }
    }
  }
  return uVar3;
}



/* ===== sub_0091f2a0 | RVA 0x91f2a0 | file +0x2630 | ev_443d362c246845d73007f0e4375191bb95a6ec25e1e9883c8d5b02ce43958763 =====
 * Body: [{"start":"0x91f2a0","end":"0x91f374"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_0091f2a0(long param_1,ulong param_2,long param_3,long param_4)

{
  int iVar1;
  undefined8 uVar2;
  uint uVar3;
  undefined8 uVar4;
  
  func_0x004c6a00(param_1 + 0x68,0,0,0);
  if (_DAT_02552080 < param_2) {
    uVar4 = 0;
  }
  else {
    if (param_4 == 0) {
      uVar2 = 0x7fffffffffffffff;
    }
    else {
      uVar2 = func_0x004a21b0(param_4,9);
    }
    uVar4 = 0;
    iVar1 = func_0x004a26d0(*(undefined8 *)(*(long *)(param_3 + 0x318) + 0x20),param_1 + 0xcc,
                            param_2 & 0xffffffff,uVar2);
    if (iVar1 != 0) {
      uVar3 = (int)param_2 * _DAT_025520b0;
      uVar4 = 1;
      if (_DAT_02552078 <= uVar3) {
        uVar3 = _DAT_02552078;
      }
      *(uint *)(param_1 + 0xdc) = uVar3;
      if (*(uint *)(param_1 + 0xcc) < *(uint *)(param_1 + 0xe4)) {
        *(uint *)(param_1 + 0xe4) = *(uint *)(param_1 + 0xcc);
      }
    }
  }
  func_0x004c6fa0(param_1 + 0x68,0,0,0);
  return uVar4;
}



/* ===== sub_0091f380 | RVA 0x91f380 | file +0x2710 | ev_f72fce427e32046d43bb5c156d26d2679d1467fc7a634f7c7c422eb4c87d07c9 =====
 * Body: [{"start":"0x91f380","end":"0x91f397"},{"start":"0x91f3a0","end":"0x91f406"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_0091f380(long param_1,long param_2)

{
  int iVar1;
  undefined8 uVar2;
  
  iVar1 = *(int *)(param_1 + 0xd0);
  while ((iVar1 != 0 &&
         ((*(int *)(param_1 + 200) != 0 ||
          ((*(long *)(param_1 + 0x98) != 0 && (*(int *)(*(long *)(param_1 + 0x98) + 0x18) == 0))))))
        ) {
    uVar2 = func_0x0091ff20(param_1);
    func_0x0042a850(uVar2);
    iVar1 = *(int *)(param_1 + 0xd0);
  }
  func_0x004a26d0(*(undefined8 *)(*(long *)(param_2 + 0x318) + 0x20),param_1 + 0xcc,0,
                  0x7fffffffffffffff);
  *(undefined4 *)(param_1 + 0xdc) = 0;
  return;
}



/* ===== sub_0091f410 | RVA 0x91f410 | file +0x27a0 | ev_bce02912adbc4dd0136b08ae65bfe03a63d2a986571f6577c899111d802d13dd =====
 * Body: [{"start":"0x91f410","end":"0x91f427"},{"start":"0x91f430","end":"0x91f496"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_0091f410(long param_1,long param_2)

{
  int iVar1;
  undefined8 uVar2;
  
  iVar1 = *(int *)(param_1 + 0xd0);
  while ((iVar1 != 0 &&
         ((*(int *)(param_1 + 200) != 0 ||
          ((*(long *)(param_1 + 0x98) != 0 && (*(int *)(*(long *)(param_1 + 0x98) + 0x18) == 0))))))
        ) {
    uVar2 = func_0x0091ff20(param_1);
    func_0x0042a850(uVar2);
    iVar1 = *(int *)(param_1 + 0xd0);
  }
  func_0x004a26d0(*(undefined8 *)(*(long *)(param_2 + 0x318) + 0x20),param_1 + 0xcc,0,
                  0x7fffffffffffffff);
  *(undefined4 *)(param_1 + 0xdc) = 0;
  return;
}



/* ===== sub_0091f4a0 | RVA 0x91f4a0 | file +0x2830 | ev_ba4f4f7267dc7eaa57cf8fbc3f20ffeb1498723906e536b9b072fa36c043df6a =====
 * Body: [{"start":"0x91f4a0","end":"0x91f4ed"},{"start":"0x91f4f0","end":"0x91f5e4"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted.","Ghidra Listing reports a terminal call at 0x91f5e0 to 0x91f5f0 sub_0091f5f0 (external=false, thunk=false, hasNoReturn=false); fallthrough is excluded by Ghidra's flow model. The reason for the terminal flow is not established by this observation."]
 */

void sub_0091f4a0(long param_1,undefined8 *param_2,uint param_3)

{
  undefined8 *puVar1;
  undefined8 *puVar2;
  uint uVar3;
  undefined8 *puVar5;
  undefined8 *puVar6;
  undefined8 *puVar4;
  
  if (param_2 == (undefined8 *)0x0) {
    return;
  }
  uVar3 = (param_3 & 8) << 0x11 | 0xe00fffff;
  puVar4 = (undefined8 *)(ulong)uVar3;
  puVar2 = param_2;
  do {
    *(uint *)((long)puVar2 + 0x1c) = *(uint *)((long)puVar2 + 0x1c) & uVar3;
    puVar2 = (undefined8 *)*puVar2;
  } while (puVar2 != (undefined8 *)0x0);
  puVar2 = *(undefined8 **)(param_1 + 0x98);
  puVar6 = param_2;
  if (puVar2 == (undefined8 *)0x0) {
    puVar2 = *(undefined8 **)(param_1 + 0xa8);
    if (*(undefined8 **)(param_1 + 0xa8) == (undefined8 *)0x0) {
      puVar5 = (undefined8 *)0x0;
      *(undefined8 **)(param_1 + 0xa8) = param_2;
    }
    else {
      do {
        puVar5 = puVar2;
        puVar2 = param_2;
        if ((*(byte *)((long)puVar5 + 0x1d) & 4) != 0) goto LAB_0091f570;
        puVar2 = (undefined8 *)*puVar5;
        puVar4 = puVar5;
      } while ((undefined8 *)*puVar5 != (undefined8 *)0x0);
    }
  }
  else {
    do {
      puVar5 = puVar2 + 1;
      puVar1 = puVar2;
      puVar2 = (undefined8 *)*puVar5;
    } while ((undefined8 *)*puVar5 != (undefined8 *)0x0);
    do {
      puVar5 = puVar1;
      puVar2 = param_2;
      if ((*(byte *)((long)puVar5 + 0x1d) & 4) != 0) goto LAB_0091f510;
      puVar1 = (undefined8 *)*puVar5;
      puVar4 = puVar5;
    } while ((undefined8 *)*puVar5 != (undefined8 *)0x0);
  }
  goto LAB_0091f5dc;
LAB_0091f570:
  do {
    *(uint *)((long)puVar2 + 0x1c) = *(uint *)((long)puVar2 + 0x1c) & 0xe00fffff;
    puVar2 = (undefined8 *)*puVar2;
  } while (puVar2 != (undefined8 *)0x0);
  goto LAB_0091f57f;
LAB_0091f510:
  do {
    *(uint *)((long)puVar2 + 0x1c) = *(uint *)((long)puVar2 + 0x1c) & 0xe00fffff;
    puVar2 = (undefined8 *)*puVar2;
  } while (puVar2 != (undefined8 *)0x0);
LAB_0091f57f:
  sub_0091e8f0(param_1,param_2,puVar4);
  if (*(long *)(param_1 + 0xa8) == 0) {
    *(undefined8 **)(param_1 + 0x98) = param_2;
  }
  else {
    *(undefined8 **)(*(long *)(param_1 + 0xa8) + 8) = param_2;
  }
  *(undefined8 **)(param_1 + 0xa8) = param_2;
  *(undefined8 **)(param_1 + 0xa0) = param_2;
  puVar6 = (undefined8 *)*param_2;
  *param_2 = 0;
  puVar5 = param_2;
  if ((puVar6 != (undefined8 *)0x0) && ((*(uint *)((long)param_2 + 0x1c) & 0x400) != 0)) {
    *(uint *)((long)param_2 + 0x1c) = *(uint *)((long)param_2 + 0x1c) & 0xfffffbff;
    *(byte *)((long)puVar6 + 0x1d) = *(byte *)((long)puVar6 + 0x1d) | 4;
  }
LAB_0091f5dc:
  sub_0091f5f0(param_1,puVar6,puVar5);
  return;
}



/* ===== sub_0091f5f0 | RVA 0x91f5f0 | file +0x2980 | ev_81c23d4830934f8caea95bdd4fde8e47668fc63bdd54120ab7eb8dd900256ed4 =====
 * Body: [{"start":"0x91f5f0","end":"0x91f713"},{"start":"0x91f720","end":"0x91f7a7"},{"start":"0x91f7b0","end":"0x91f915"},{"start":"0x91f920","end":"0x91f97b"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_0091f5f0(long param_1,undefined8 *param_2,undefined8 *param_3)

{
  int *piVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  long lVar5;
  undefined8 *puVar6;
  int *piVar7;
  undefined8 *puVar8;
  uint uVar9;
  code *pcVar10;
  uint uVar11;
  undefined8 *puVar12;
  
  if (param_2 == (undefined8 *)0x0) {
    return;
  }
  uVar11 = 0;
LAB_0091f620:
  piVar1 = (int *)(param_3 + 0xf);
  puVar12 = param_2;
  do {
    uVar4 = *(uint *)((long)puVar12 + 0x1c);
    uVar11 = uVar4 >> 8 & 4 | uVar11;
    iVar2 = *(int *)(puVar12 + 3);
    lVar5 = (long)iVar2;
    if (lVar5 == 0) {
      puVar8 = (undefined8 *)*puVar12;
      if (uVar11 != 0) {
        if (param_3 == (undefined8 *)0x0 && puVar8 == (undefined8 *)0x0) goto LAB_0091f925;
        puVar6 = param_3;
        if (puVar8 != (undefined8 *)0x0) {
          puVar6 = puVar8;
        }
        if (*(char *)((long)puVar6 + 0x1c) != (char)uVar4) goto LAB_0091f676;
      }
      if (*(undefined8 **)(param_1 + 0xa8) == puVar12) {
        *(undefined8 **)(param_1 + 0xa8) = puVar8;
      }
      pcVar10 = _DAT_01a9bf28;
      if (_DAT_02566d18 != 0) {
        if (1 < (-(long)_DAT_01a9bf28 + 0x2681e8U >> 3 | -(long)_DAT_01a9bf28 << 0x3d)) {
          func_0x0044f8c0(0x25521e0,_DAT_01a9bf28);
        }
        goto LAB_0091f8e0;
      }
    }
    else {
LAB_0091f676:
      if (param_3 == (undefined8 *)0x0) {
LAB_0091f925:
        *(undefined8 **)(param_1 + 0x98) = puVar12;
        goto LAB_0091f92c;
      }
      uVar3 = *(uint *)((long)param_3 + 0x1c);
      if ((uVar3 & 0xc00) != 0) break;
      if ((uVar3 & 0x100) != 0) {
        piVar7 = piVar1;
        if ((*(byte *)((long)param_3 + 0x8d) & 1) == 0) {
          piVar7 = *(int **)piVar1;
        }
        if (*piVar7 != 1) break;
      }
      if (((0x200 < iVar2) || ((*(ushort *)(param_1 + 0xf0) & 0x200) != 0)) ||
         (((uVar3 | uVar4) & 0x100000) != 0)) break;
      if ((uVar3 & 0x100) == 0) {
        uVar9 = 0x88;
        puVar8 = param_3 + 0xf;
        if ((uVar3 & 0x200) == 0) {
          uVar9 = 0xe0;
          puVar8 = param_3 + 4;
        }
LAB_0091f7da:
        if ((long)((long)puVar8 + ((ulong)uVar9 - ((long)*(int *)(param_3 + 3) + param_3[2]))) <
            lVar5) break;
      }
      else {
        piVar7 = piVar1;
        if ((*(byte *)((long)param_3 + 0x8d) & 1) == 0) {
          piVar7 = *(int **)piVar1;
        }
        if (*piVar7 == 1) {
          uVar9 = *(uint *)(param_3 + 0x11);
          puVar8 = (undefined8 *)param_3[0x10];
          goto LAB_0091f7da;
        }
        if (0 < lVar5) break;
      }
      if ((char)uVar3 != (char)uVar4) break;
      func_0x00259be0(puVar12[2],(long)*(int *)(param_3 + 3) + param_3[2],iVar2);
      *(int *)(param_3 + 3) = *(int *)(param_3 + 3) + *(int *)(puVar12 + 3);
      *(int *)(param_1 + 200) = *(int *)(param_1 + 200) + *(int *)(puVar12 + 3);
      func_0x00697590(param_1,*(undefined4 *)(puVar12 + 3));
      if (*(long *)(param_1 + 0xb8) == 0) {
        *(int *)(param_1 + 0xc4) = *(int *)(param_1 + 0xc4) + *(int *)(puVar12 + 3);
      }
      if ((*(char *)((long)puVar12 + 0x1c) != '\x01') && (*(char *)((long)puVar12 + 0x1c) != '\x10')
         ) {
        *(int *)(param_1 + 0xe0) = *(int *)(param_1 + 0xe0) + *(int *)(puVar12 + 3);
      }
      pcVar10 = _DAT_01a9bf28;
      puVar8 = (undefined8 *)*puVar12;
      if (_DAT_02566d18 != 0) {
        if (1 < (-(long)_DAT_01a9bf28 + 0x2681e8U >> 3 | -(long)_DAT_01a9bf28 << 0x3d)) {
          func_0x0044f8c0(0x25521e0,_DAT_01a9bf28);
        }
LAB_0091f8e0:
        (*pcVar10)(_DAT_02566d18,puVar12,0,0,0,0);
      }
    }
    uVar4 = *(uint *)((long)puVar12 + 0x1c);
    if ((~uVar4 & 0x20200) == 0) {
      func_0x002c5090(puVar12,0);
      uVar4 = *(uint *)((long)puVar12 + 0x1c);
    }
    if ((uVar4 & 0x100) == 0) {
      if ((uVar4 & 0x20000) == 0) {
        func_0x0043c0c0(_DAT_034f5020,puVar12,0);
      }
    }
    else {
      func_0x00429fb0();
    }
    puVar12 = puVar8;
    if (puVar8 == (undefined8 *)0x0) {
      if (uVar11 == 0) {
        return;
      }
      goto LAB_0091f95b;
    }
  } while( true );
  *param_3 = puVar12;
LAB_0091f92c:
  *(undefined8 **)(param_1 + 0xa0) = puVar12;
  sub_0091e8f0(param_1,puVar12);
  *(byte *)((long)puVar12 + 0x1d) = *(byte *)((long)puVar12 + 0x1d) & 0xfb;
  param_2 = (undefined8 *)*puVar12;
  *puVar12 = 0;
  param_3 = puVar12;
  if (param_2 == (undefined8 *)0x0) {
    if (uVar11 == 0) {
      return;
    }
LAB_0091f95b:
    *(uint *)((long)param_3 + 0x1c) = *(uint *)((long)param_3 + 0x1c) | uVar11 << 8;
    return;
  }
  goto LAB_0091f620;
}



/* ===== sub_0091f980 | RVA 0x91f980 | file +0x2d10 | ev_63ac0f749d9c7b6294fe37272946adae6b98527524a1c05bd3ad89136fe6c604 =====
 * Body: [{"start":"0x91f980","end":"0x91f9c4"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_0091f980(long param_1,undefined8 param_2,uint param_3)

{
  func_0x00a17e50(param_2,1,(param_3 & 8) << 9);
  sub_0091f5f0(param_1,param_2,*(undefined8 *)(param_1 + 0xa0));
  *(undefined8 *)(param_1 + 0xa8) = *(undefined8 *)(param_1 + 0x98);
  return;
}



/* ===== sub_0091f9d0 | RVA 0x91f9d0 | file +0x2d60 | ev_4d92cca93503416a32085a19023c653a217116f517cc41f103ac33db0d5004fd =====
 * Body: [{"start":"0x91f9d0","end":"0x91fa43"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_0091f9d0(long param_1,undefined8 param_2,uint param_3)

{
  func_0x004c6a00(param_1 + 0x68,0,0,0);
  func_0x00a17e50(param_2,1,(param_3 & 8) << 9);
  sub_0091f5f0(param_1,param_2,*(undefined8 *)(param_1 + 0xa0));
  *(undefined8 *)(param_1 + 0xa8) = *(undefined8 *)(param_1 + 0x98);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== sub_0091fa50 | RVA 0x91fa50 | file +0x2de0 | ev_4bee66deffa10dd519e04b100a7d5e4a9374a0b649d4ecaac4fe8148786345f3 =====
 * Body: [{"start":"0x91fa50","end":"0x91fb48"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_0091fa50(long param_1,byte *param_2,long param_3,undefined8 param_4)

{
  code *pcVar1;
  int iVar2;
  undefined8 uVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  undefined8 local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  uVar6 = (uint)*param_2;
  if (param_3 != 0) {
    if ((*(byte *)(param_3 + 0x1d) & 2) == 0) {
      func_0x007f1950();
      func_0x007f1810(0x91fb23);
      func_0x00c9aa10(0xf,0x1316c9a);
                    /* WARNING: Does not return */
      pcVar1 = (code *)invalidInstructionException();
      (*pcVar1)();
    }
    uVar6 = (uint)*param_2 + *(int *)(param_3 + 0x30);
  }
  iVar2 = func_0x00a1a010(param_4,&local_40);
  uVar3 = 0;
  if ((*(byte *)(param_1 + 0xf1) & 0x10) == 0) {
    iVar4 = *(int *)(param_1 + 0xcc) - *(int *)(param_1 + 200);
    iVar5 = *(int *)(param_1 + 0xdc) - *(int *)(param_1 + 0xd0);
    if (iVar4 < iVar5) {
      iVar5 = iVar4;
    }
    if (iVar5 < (int)(iVar2 + uVar6)) goto LAB_0091fafd;
  }
  else if (0 < (int)(iVar2 + uVar6)) goto LAB_0091fafd;
  uVar3 = sub_0091fb50(param_1,param_2,param_3,param_4,local_40);
LAB_0091fafd:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar1 = (code *)invalidInstructionException();
    (*pcVar1)();
  }
  return uVar3;
}



/* ===== sub_0091fb50 | RVA 0x91fb50 | file +0x2ee0 | ev_7d3b2303f76e1e2c8aa6bb7a65549a1e8aaf446018f423012bbe00c47356d9ea =====
 * Body: [{"start":"0x91fb50","end":"0x91fc6d"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_0091fb50(undefined8 param_1,byte *param_2,long *param_3,long *param_4,undefined8 *param_5)

{
  undefined8 *puVar1;
  long *plVar2;
  undefined8 *puVar3;
  undefined4 local_40;
  undefined2 local_3c;
  undefined8 local_38;
  
  local_38 = _DAT_0391c310;
  if (*param_2 < 0xe1) {
    local_40 = 0;
    local_3c = 8;
    puVar3 = param_5;
    puVar1 = (undefined8 *)func_0x0043b880(_DAT_034f5020,&local_40,1);
    if (_DAT_02566cb8 != 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    if (puVar1 != (undefined8 *)0x0) {
      *(uint *)(puVar1 + 3) = (uint)*param_2;
      func_0x00259be0(param_2,puVar1[2],*param_2);
      plVar2 = param_3;
      if (param_3 != (long *)0x0) {
        do {
          *(uint *)((long)plVar2 + 0x1c) = *(uint *)((long)plVar2 + 0x1c) & 0xe00fffff;
          plVar2 = (long *)*plVar2;
        } while (plVar2 != (long *)0x0);
        func_0x002c5090(param_3,0);
        param_3[4] = 0;
        *(undefined4 *)((long)param_3 + 0x34) = 0;
        param_3[7] = 0;
        *(undefined2 *)(param_3 + 8) = 0;
        *(undefined1 *)((long)param_3 + 0x43) = 0;
      }
      if (param_5 != (undefined8 *)0x0) {
        *param_5 = param_3;
        param_3 = param_4;
      }
      *puVar1 = param_3;
      if (param_3 == (long *)0x0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      sub_0091e8f0(param_1,puVar1);
      *puVar3 = *puVar3;
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


