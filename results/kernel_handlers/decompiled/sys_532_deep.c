/* REA 6.7.0 / Ghidra 12.1.4 recovered pseudocode, not original or buildable C.
 * Input: deep_532.bin, SHA256 224f00c5c860df9cd127f2178d70e606ae0b3d51e0e3e5462412490965e26191
 * File offset zero maps to kernel RVA 0xaf0040; runtime VA = 0xffffffff8a9c0000 + RVA.
 * External bodies/types/data missing from this raw window remain unknown.
 * Function names are analyst seeds or Ghidra-generated; instruction truth is in .rea.asm.
 */

/* ===== sys_532 | RVA 0xaf0040 | file +0x0 | ev_675afce21a2065ecfeea8f8e4bb2de5679596c5aa6cf410d7ef96990eadc284a =====
 * Body: [{"start":"0xaf0040","end":"0xaf016c"},{"start":"0xaf0170","end":"0xaf0381"},{"start":"0xaf03ab","end":"0xaf03d1"},{"start":"0xaf04f1","end":"0xaf04ff"},{"start":"0xaf07b9","end":"0xaf07ce"},{"start":"0xaf11f2","end":"0xaf1248"},{"start":"0xaf1337","end":"0xaf133d"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sys_532(long param_1,uint *param_2)

{
  long lVar1;
  byte bVar2;
  uint uVar3;
  uint uVar4;
  long lVar5;
  ulong uVar6;
  long lVar7;
  code *pcVar8;
  int iVar9;
  ulong uVar10;
  uint uVar11;
  undefined8 *in_GS_OFFSET;
  undefined4 local_860 [2];
  undefined1 local_858 [2080];
  long local_38;
  
  local_38 = _DAT_0391c310;
  lVar5 = *(long *)(param_2 + 6);
  uVar3 = param_2[2];
  uVar6 = *(ulong *)(param_2 + 8);
  uVar4 = *param_2;
  lVar7 = *(long *)(param_2 + 4);
  if (*(long *)(param_1 + 8) != 0) {
    lVar1 = *(long *)(param_1 + 8) + 0x148;
    func_0x004c6a00(lVar1,0,0,0);
    func_0x004c6fa0(lVar1,0,0,0);
  }
  iVar9 = func_0x00adfa30(param_1,0x2aa);
  if (iVar9 == 0) {
    iVar9 = func_0x00609080(*(undefined8 *)(param_1 + 0x140));
    if (iVar9 != 1) goto LAB_00af02a6;
    if (uVar4 < 0x21) {
      uVar10 = (ulong)uVar4;
      if ((0x800003d4UL >> (uVar10 & 0x3f) & 1) == 0) {
        if ((0x2aUL >> (uVar10 & 0x3f) & 1) == 0) {
          if ((0x100001000U >> (uVar10 & 0x3f) & 1) != 0) goto LAB_00af02a6;
          goto LAB_00af04f1;
        }
        local_860[0] = 0x800d0203;
        if ((ulong)_DAT_03cf7e40 != 0) {
          uVar10 = 0;
          do {
            if (uVar3 == *(uint *)(&DAT_03cf7e50 + uVar10 * 0x28)) {
LAB_00af03ab:
              if (-1 < (int)(uint)uVar10) {
                bVar2 = *(byte *)((ulong)((uint)uVar10 & 0x7fffffff) * 0x28 + 0x3cf7e6d) & 2;
                goto joined_r0x00af03c7;
              }
              break;
            }
            bVar2 = (&DAT_03cf7e65)[uVar10 * 0x28];
            if ((bVar2 != 0) && (bVar2 != 1)) {
              uVar11 = 1;
              do {
                if (uVar3 == (uVar11 << ((byte)(&DAT_03cf7e66)[uVar10 * 0x28] & 0x1f)) +
                             *(uint *)(&DAT_03cf7e50 + uVar10 * 0x28)) goto LAB_00af03ab;
                uVar11 = uVar11 + 1;
              } while (bVar2 != uVar11);
            }
            uVar10 = uVar10 + 1;
          } while (uVar10 != _DAT_03cf7e40);
        }
      }
      else {
        local_860[0] = 0x800d0203;
        if ((ulong)_DAT_03cf7e40 != 0) {
          uVar10 = 0;
LAB_00af017c:
          if (uVar3 != *(uint *)(&DAT_03cf7e50 + uVar10 * 0x28)) goto code_r0x00af0191;
LAB_00af026f:
          if (-1 < (int)(uint)uVar10) {
            bVar2 = *(byte *)((ulong)((uint)uVar10 & 0x7fffffff) * 0x28 + 0x3cf7e6d) & 1;
joined_r0x00af03c7:
            local_860[0] = 0x800d0218;
            if (bVar2 != 0) goto LAB_00af02a6;
          }
        }
      }
    }
    else {
LAB_00af04f1:
      local_860[0] = 0x800d0218;
    }
  }
  else {
    if (((6 < uVar4 - 0x18) && (uVar4 != 0x2f)) && (uVar4 != 0x20)) goto LAB_00af1223;
LAB_00af02a6:
    if (lVar7 == 0) {
      local_860[0] = 0x800d0202;
    }
    else {
      local_860[0] = 0;
      if (lVar5 == 0) {
        if (uVar4 < 0x47) {
          local_860[0] = 0x800d0202;
                    /* WARNING: Could not emulate address calculation at 0x00af02eb */
                    /* WARNING: Treating indirect jump as call */
          (*(code *)((long)*(int *)((ulong)uVar4 * 4 + 0x18de230) + 0x18de230))();
          return;
        }
        local_860[0] = 0x800d0202;
      }
      else if (uVar6 < 0x801) {
LAB_00af0345:
        func_0x00258ff0(local_858,0x818);
        if (uVar4 < 0x47) {
                    /* WARNING: Could not emulate address calculation at 0x00af0363 */
                    /* WARNING: Treating indirect jump as call */
          (*(code *)((long)*(int *)((ulong)uVar4 * 4 + 0x18de34c) + 0x18de34c))();
          return;
        }
        local_860[0] = 0x800d0219;
      }
      else {
        if (uVar4 - 0x1a < 4) {
          if (uVar6 < 0x819) goto LAB_00af0345;
        }
        else if ((uVar4 - 0x20 < 0x21) &&
                ((0x150409101U >> ((ulong)(uVar4 - 0x20) & 0x3f) & 1) != 0)) goto LAB_00af0345;
        local_860[0] = 0x800d0208;
      }
    }
  }
LAB_00af11f8:
  func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
  func_0x002591d0(local_860,lVar7,4);
LAB_00af1223:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar8 = (code *)invalidInstructionException();
    (*pcVar8)();
  }
  return;
code_r0x00af0191:
  bVar2 = (&DAT_03cf7e65)[uVar10 * 0x28];
  if ((bVar2 != 0) && (bVar2 != 1)) {
    uVar11 = 1;
    do {
      if (uVar3 == (uVar11 << ((byte)(&DAT_03cf7e66)[uVar10 * 0x28] & 0x1f)) +
                   *(uint *)(&DAT_03cf7e50 + uVar10 * 0x28)) goto LAB_00af026f;
      uVar11 = uVar11 + 1;
    } while (bVar2 != uVar11);
  }
  uVar10 = uVar10 + 1;
  if (uVar10 == _DAT_03cf7e40) goto LAB_00af11f8;
  goto LAB_00af017c;
}



/* ===== sub_00af1340 | RVA 0xaf1340 | file +0x1300 | ev_3c5f2cbdff24ce3e406cead9689b4166ba9da4810def16fdad1239281b7e6ca7 =====
 * Body: [{"start":"0xaf1340","end":"0xaf1381"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_00af1340(void)

{
  undefined8 *in_GS_OFFSET;
  
  func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== sub_00af1390 | RVA 0xaf1390 | file +0x1350 | ev_2c522d245588d55915d172d7be15dbc214f2fb108db3a7041d2fe57bd836e2bf =====
 * Body: [{"start":"0xaf1390","end":"0xaf13d1"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_00af1390(void)

{
  undefined8 *in_GS_OFFSET;
  
  func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== sub_00af13e0 | RVA 0xaf13e0 | file +0x13a0 | ev_40aa62ffe3c77096d92210e49cba03d5787760d7b30216965d82d82f5e752e43 =====
 * Body: [{"start":"0xaf13e0","end":"0xaf14ee"},{"start":"0xaf14f0","end":"0xaf1725"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong sub_00af13e0(int param_1,undefined8 param_2,uint param_3,long param_4,int param_5,int *param_6
                  )

{
  byte bVar1;
  int iVar2;
  byte bVar5;
  ulong uVar3;
  ulong uVar4;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  byte bVar9;
  long lVar10;
  uint uVar11;
  uint uVar12;
  
  if (param_4 == 0) {
    return 0x800d0202;
  }
  uVar11 = (uint)param_2 & 0xff;
  bVar5 = (byte)((ulong)param_2 >> 8);
  uVar12 = (uint)((ulong)param_2 >> 0x18) & 0xff;
  uVar7 = (uint)param_2 >> 0x10 & 0xff;
  uVar6 = (uint)(byte)((ulong)param_2 >> 0x28);
  uVar3 = 0x800d0204;
  if ((uVar12 + uVar11 + (uint)bVar5 + uVar7 + ((uint)((ulong)param_2 >> 0x20) & 0xff) * uVar6 &
      0xffff) == (uint)(ushort)((ulong)param_2 >> 0x30)) {
    uVar3 = (ulong)uVar6 ^ 0x6b;
    if ((uint)uVar3 < 0xd) {
      lVar10 = 0x13b9d00;
      bVar9 = (byte)((ulong)param_2 >> 0x20) ^ *(byte *)(0x13b9d0f - uVar3);
      if (bVar9 == 0x19) {
        lVar10 = 0x13b9fd0;
      }
      else if (bVar9 != 0x72) {
        return 0x800d0205;
      }
      if ((ulong)_DAT_03cf7e40 != 0) {
        bVar9 = *(byte *)(lVar10 + uVar3);
        uVar6 = (uint)*(byte *)(lVar10 + 1 + uVar3);
        uVar12 = uVar12 ^ uVar6;
        bVar5 = bVar5 ^ bVar9;
        uVar4 = 0;
        uVar11 = uVar11 ^ *(byte *)(lVar10 + 3 + uVar3) |
                 (uVar7 ^ *(byte *)(lVar10 + 2 + uVar3)) << 8 | uVar12 << 0x10 | (uint)bVar5 << 0x18
        ;
        do {
          if (uVar11 == *(uint *)(&DAT_03cf7e50 + uVar4 * 0x28)) {
LAB_00af1556:
            if ((int)(uint)uVar4 < 0) {
              return uVar4;
            }
            lVar10 = (ulong)((uint)uVar4 & 0x7fffffff) * 0x28;
            iVar2 = func_0x006092d0(param_4);
            if (iVar2 == 1) {
LAB_00af15a0:
              uVar7 = 1;
            }
            else {
              iVar2 = func_0x00609310(param_4);
              uVar7 = 0;
              if (iVar2 == 1) goto LAB_00af15a0;
            }
            iVar2 = func_0x00608fd0(param_4);
            uVar8 = *(uint *)(lVar10 + 0x3cf7e6c);
            if (param_5 == 1) {
              if (iVar2 != 1) {
                if ((uVar8 & 1) == 0) {
                  if (param_1 != 1) {
                    return 0x800d0214;
                  }
                  if ((uVar8 & 0x10) == 0) {
                    return 0x800d0214;
                  }
                }
                uVar8 = ~(uVar8 >> 0xc);
joined_r0x00af167d:
                if ((uVar7 & uVar8) != 0) {
                  return 0x800d021f;
                }
                goto LAB_00af1683;
              }
              if ((uVar8 & 0x10) != 0) goto LAB_00af1683;
              if (param_1 != 1) {
                return 0x800d0216;
              }
              uVar8 = uVar8 & 1;
            }
            else {
              if (iVar2 != 1) {
                if ((uVar8 & 2) == 0) {
                  if (param_1 != 1) {
                    return 0x800d0214;
                  }
                  if ((uVar8 & 0x20) == 0) {
                    return 0x800d0214;
                  }
                }
                uVar8 = ~uVar8 >> 0xd;
                goto joined_r0x00af167d;
              }
              if ((uVar8 & 0x20) != 0) goto LAB_00af1683;
              if (param_1 != 1) {
                return 0x800d0216;
              }
              uVar8 = uVar8 & 2;
            }
            if (uVar8 == 0) {
              return 0x800d0216;
            }
LAB_00af1683:
            if ((&DAT_03cf7e66)[lVar10] == '\b') {
              if ((byte)((byte)(param_3 >> 8) & ~bVar9) != 0) {
                return 0x800d0206;
              }
              uVar6 = param_3 & 0xff ^ uVar6;
              if (uVar6 == 0) {
                return 0x800d0206;
              }
              if ((byte)(&DAT_03cf7e65)[lVar10] < uVar6) {
                return 0x800d0206;
              }
              iVar2 = uVar6 * 0x100 + -0x100;
            }
            else if ((&DAT_03cf7e66)[lVar10] == '\x10') {
              if (bVar9 != (byte)param_3) {
                return 0x800d0206;
              }
              uVar6 = param_3 >> 8 & 0xff ^ uVar6;
              if (uVar6 == 0) {
                return 0x800d0206;
              }
              if ((byte)(&DAT_03cf7e65)[lVar10] < uVar6) {
                return 0x800d0206;
              }
              if ((bVar5 == 7) && (uVar12 - 0x80 < 0x14 && 0x10 < uVar6)) {
                return 0x800d0206;
              }
              iVar2 = uVar6 * 0x10000 + -0x10000;
            }
            else {
              if (param_3 != 0) {
                return 0x800d0206;
              }
              iVar2 = 0;
            }
            *param_6 = iVar2 + uVar11;
            return 0;
          }
          bVar1 = (&DAT_03cf7e65)[uVar4 * 0x28];
          if ((bVar1 != 0) && (bVar1 != 1)) {
            uVar7 = 1;
            do {
              if (uVar11 == (uVar7 << ((byte)(&DAT_03cf7e66)[uVar4 * 0x28] & 0x1f)) +
                            *(uint *)(&DAT_03cf7e50 + uVar4 * 0x28)) goto LAB_00af1556;
              uVar7 = uVar7 + 1;
            } while (bVar1 != uVar7);
          }
          uVar4 = uVar4 + 1;
        } while (uVar4 != _DAT_03cf7e40);
      }
    }
    uVar3 = 0x800d0203;
  }
  return uVar3;
}



/* ===== sub_00af1730 | RVA 0xaf1730 | file +0x16f0 | ev_a93233515977243c90a1352929acedfeeff5d651d776a60b0926a990741b39dc =====
 * Body: [{"start":"0xaf1730","end":"0xaf195d"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

uint sub_00af1730(undefined4 param_1,long param_2,ulong param_3,ulong param_4)

{
  code *pcVar1;
  uint uVar2;
  long lVar3;
  uint uVar4;
  uint local_3c;
  long local_38;
  
  local_38 = _DAT_0391c310;
  uVar4 = 0x800d0202;
  if ((param_4 == 0 || param_2 == 0) || (uVar4 = 0x800d0208, param_4 <= param_3 - 1))
  goto LAB_00af193c;
  if (param_3 == param_4) {
    if (_DAT_03cf7c00 == 0) {
      uVar2 = 0x800d0201;
    }
    else if ((_DAT_03cf7c04 == 0) || (_DAT_03cf7bc0 == 1)) {
      uVar4 = 0;
      uVar2 = func_0x00aee460(1,5,param_1,2,param_4,0,&local_3c);
      if ((-1 < (int)uVar2) &&
         (((local_3c & 0x800d00f0) == 0x800d0000 ||
          (uVar4 = func_0x00aecd70(1,param_1,param_2,param_4), uVar2 = uVar4, -1 < (int)uVar4))))
      goto LAB_00af193c;
    }
    else {
      uVar2 = 0x800d020d;
      if ((int)_DAT_03cf7c04 < 0) {
        uVar2 = _DAT_03cf7c04;
      }
    }
    func_0x006aa500(5,param_1,uVar2 & 0xffff);
    uVar4 = uVar2;
    goto LAB_00af193c;
  }
  lVar3 = func_0x00c08b50(param_4,0x28cdfe0,0x101);
  if (lVar3 == 0) {
    uVar4 = 0x800d0211;
    goto LAB_00af193c;
  }
  func_0x002590b0(lVar3,param_2,param_3);
  if (_DAT_03cf7c00 == 0) {
    uVar2 = 0x800d0201;
LAB_00af191d:
    uVar4 = uVar2;
    func_0x006aa500(5,param_1,uVar4 & 0xffff);
  }
  else {
    if ((_DAT_03cf7c04 != 0) && (_DAT_03cf7bc0 != 1)) {
      uVar2 = 0x800d020d;
      if ((int)_DAT_03cf7c04 < 0) {
        uVar2 = _DAT_03cf7c04;
      }
      goto LAB_00af191d;
    }
    uVar4 = 0;
    uVar2 = func_0x00aee460(1,5,param_1,2,param_4,0,&local_3c);
    if (((int)uVar2 < 0) ||
       (((local_3c & 0x800d00f0) != 0x800d0000 &&
        (uVar4 = func_0x00aecd70(1,param_1,lVar3,param_4), uVar2 = uVar4, (int)uVar4 < 0))))
    goto LAB_00af191d;
  }
  func_0x00c08df0(lVar3,0x28cdfe0);
LAB_00af193c:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar1 = (code *)invalidInstructionException();
    (*pcVar1)();
  }
  return uVar4;
}



/* ===== sub_00af1960 | RVA 0xaf1960 | file +0x1920 | ev_b34cd07240eb1dfbe2319c3c7d8f9b1717df0cab5b5ad94f50e38c55bfec44de =====
 * Body: [{"start":"0xaf1960","end":"0xaf1a81"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

uint sub_00af1960(undefined8 param_1,ulong param_2,long param_3,undefined8 param_4)

{
  code *pcVar1;
  uint uVar2;
  ulong uVar3;
  uint local_50;
  undefined4 local_4c;
  undefined8 local_48 [2];
  long local_38;
  
  local_38 = _DAT_0391c310;
  if (_DAT_03cf7c00 == 0) {
    uVar2 = 0x800d0201;
  }
  else if ((_DAT_03cf7c04 == 0) || (_DAT_03cf7bc0 == 1)) {
    if (param_3 == 0) {
      uVar2 = 0x800d0202;
    }
    else {
      uVar3 = param_2 & 0xffffffff;
      param_2 = param_2 & 0xffffffff;
      uVar2 = func_0x00aee460(param_1,6,uVar3,2,param_4,&local_4c,&local_50);
      if (-1 < (int)uVar2) {
        if ((local_50 & 0x800d00f0) == 0x800d0000) {
          func_0x00258ff0(local_48,0x10);
          uVar2 = func_0x00aedc20(uVar2,local_48,local_4c);
          if (uVar2 == 0) {
            func_0x002590b0(param_3,local_48[0],param_4);
            uVar2 = 0;
            goto LAB_00af1a60;
          }
        }
        else {
          uVar2 = func_0x00aec070(param_2,param_3,param_4);
          if (-1 < (int)uVar2) goto LAB_00af1a60;
        }
      }
    }
  }
  else {
    uVar2 = 0x800d020d;
    if ((int)_DAT_03cf7c04 < 0) {
      uVar2 = _DAT_03cf7c04;
    }
  }
  func_0x006aa500(5,param_2,uVar2 & 0xffff);
LAB_00af1a60:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar1 = (code *)invalidInstructionException();
    (*pcVar1)();
  }
  return uVar2;
}



/* ===== sub_00af1a90 | RVA 0xaf1a90 | file +0x1a50 | ev_52fdf6a44ff86b75666a2929a2251bad5f57649ae4b5eb98541174e49dbfe674 =====
 * Body: [{"start":"0xaf1a90","end":"0xaf1b84"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

uint sub_00af1a90(undefined8 param_1,ulong param_2,undefined8 param_3,undefined8 param_4)

{
  code *pcVar1;
  uint uVar2;
  ulong uVar3;
  undefined4 local_4c;
  undefined8 local_48 [2];
  long local_38;
  
  local_38 = _DAT_0391c310;
  if (_DAT_03cf7c00 == 0) {
    uVar2 = 0x800d0201;
  }
  else if ((_DAT_03cf7c04 == 0) || (_DAT_03cf7bc0 == 1)) {
    uVar3 = param_2 & 0xffffffff;
    param_2 = param_2 & 0xffffffff;
    uVar2 = func_0x00aee460(param_1,9,uVar3,2,param_4,&local_4c,0);
    if (-1 < (int)uVar2) {
      func_0x00258ff0(local_48,0x10);
      uVar2 = func_0x00aedc20(uVar2,local_48,local_4c);
      if (uVar2 == 0) {
        func_0x002590b0(param_3,local_48[0],param_4);
        uVar2 = 0;
        goto LAB_00af1b62;
      }
    }
  }
  else {
    uVar2 = 0x800d020d;
    if ((int)_DAT_03cf7c04 < 0) {
      uVar2 = _DAT_03cf7c04;
    }
  }
  func_0x006aa500(5,param_2,uVar2 & 0xffff);
LAB_00af1b62:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar1 = (code *)invalidInstructionException();
    (*pcVar1)();
  }
  return uVar2;
}



/* ===== sub_00af1b90 | RVA 0xaf1b90 | file +0x1b50 | ev_c6085a5bb9e05deb787dddc30bda5e6bf736d8ba71c5bfa4b7c1a3497946e523 =====
 * Body: [{"start":"0xaf1b90","end":"0xaf1bf5"},{"start":"0xaf1c00","end":"0xaf1cfe"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_00af1b90(void)

{
  code *pcVar1;
  int iVar2;
  uint uVar3;
  
  func_0x00926460(0x13775d5,0x44,0x22000000,0);
  func_0x004c7dd0(0x3cf7c88,0x130ea29,0,4);
  func_0x0073e520(0x3cf7c90,0x130ea29);
  func_0x003d5430();
  do {
    func_0x003b7710();
    _DAT_03cf7c64 = 1;
    while( true ) {
      func_0x004c6a00(0x3cf7c88,0,0,0);
      func_0x0073e540(0x3cf7c90);
      func_0x004c6fa0(0x3cf7c88,0,0);
      if (_DAT_03cf7c64 == 2) break;
      if (_DAT_03cf7c64 == 3) goto LAB_00af1cd4;
      uVar3 = 0;
      do {
        func_0x004c6a00(0x3cf7c88,0,0,0);
        iVar2 = func_0x0073ea00(0x3cf7c90,0x3cf7c70,_DAT_039203d0 * 500,0,0x100);
        func_0x004c6fa0(0x3cf7c88,0,0);
        if ((iVar2 != 0) || (999 < uVar3)) break;
        uVar3 = uVar3 + 1;
      } while (_DAT_03cf7c64 == 1);
      func_0x003b7710();
      if (_DAT_03cf7c64 == 2) break;
      if (_DAT_03cf7c64 == 3) {
LAB_00af1cd4:
        func_0x0073e530(0x3cf7c90);
        func_0x004c7e50(0x3cf7c88);
        func_0x00c06910(&DAT_03cf7c64);
        func_0x00925d80();
                    /* WARNING: Does not return */
        pcVar1 = (code *)invalidInstructionException();
        (*pcVar1)();
      }
    }
    func_0x009261b0();
  } while( true );
}



/* ===== sub_00af1d00 | RVA 0xaf1d00 | file +0x1cc0 | ev_30f506928f2601f6d3c5fc40de4afa2721f1f6f2ee731f5df856f4eb346bc9a0 =====
 * Body: [{"start":"0xaf1d00","end":"0xaf1dda"},{"start":"0xaf1de0","end":"0xaf1f80"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_00af1d00(int param_1)

{
  long lVar1;
  char cVar2;
  byte bVar3;
  ushort uVar4;
  int iVar5;
  ulong uVar6;
  ulong uVar7;
  ulong uVar8;
  int iVar9;
  uint uVar10;
  uint uVar11;
  bool bVar12;
  
  uVar8 = 0;
  while (*(char *)(uVar8 + 0x3d0de68) != '=') {
    if (*(char *)(uVar8 + 0x3d0de68) == '\0') {
      return -0x7ff2fefb;
    }
    bVar12 = 0x7fe < uVar8;
    uVar8 = uVar8 + 1;
    if (bVar12) {
      return -0x7ff2fefb;
    }
  }
  if (0xfe < uVar8 - 1) {
    return -0x7ff2fefb;
  }
  func_0x002590b0(&DAT_03d0e66c,0x3d0de68,uVar8);
  uVar7 = 0;
  (&DAT_03d0e66c)[uVar8] = 0;
  while (cVar2 = (&DAT_03d0e66c)[uVar7], cVar2 == ' ') {
    uVar7 = uVar7 + 1;
    if (uVar7 == 0x100) {
      return 0;
    }
  }
  if (cVar2 == '0') {
    uVar6 = 0;
    if (((&DAT_03d0e66d)[uVar7] | 0x20) == 0x78) {
      if (0xfd < uVar7) {
        return 0;
      }
      iVar5 = 0;
      do {
        bVar3 = (&DAT_03d0e66e)[uVar7];
        iVar9 = -0x30;
        if (((9 < (byte)(bVar3 - 0x30)) && (iVar9 = -0x57, 5 < (byte)(bVar3 + 0x9f))) &&
           (iVar9 = -0x37, 5 < (byte)(bVar3 + 0xbf))) break;
        uVar7 = uVar7 + 1;
        iVar5 = iVar5 * 0x10 + iVar9 + (uint)bVar3;
      } while (uVar7 != 0xfe);
      uVar10 = 1;
      goto LAB_00af1e8c;
    }
    uVar10 = 1;
  }
  else {
    uVar6 = (ulong)(cVar2 == '-');
    uVar10 = -(uint)(cVar2 == '-') | 1;
  }
  if (0xff < (uint)((int)uVar6 + (int)uVar7)) {
    return 0;
  }
  iVar5 = 0;
  do {
    bVar3 = *(byte *)((uVar6 | 0x1c0c) + uVar7 + 0x3d0ca60);
    if (9 < (byte)(bVar3 - 0x30)) break;
    lVar1 = (uVar6 | 0x1c0c) + 1 + uVar7;
    uVar7 = uVar7 + 1;
    iVar5 = (bVar3 - 0x30) + iVar5 * 10;
  } while (lVar1 != 0x1d0c);
LAB_00af1e8c:
  if ((iVar5 != 0) && ((ulong)_DAT_03cf7e40 != 0)) {
    uVar7 = 0;
    do {
      if (uVar10 * iVar5 == *(int *)(&DAT_03cf7e50 + uVar7 * 0x28)) {
LAB_00af1f17:
        if ((int)(uint)uVar7 < 0) {
          return 0;
        }
        if (((param_1 == 0) && (_DAT_03cf7bb8 != 1)) &&
           (uVar4 = *(ushort *)((ulong)((uint)uVar7 & 0x7fffffff) * 0x28 + 0x3cf7e58),
           (short)uVar4 < 0 || (uVar4 & 0x19ff) == 0x10)) {
          return 0;
        }
        iVar5 = sub_00af2140(uVar7,uVar8 + 0x3d0de69,0x7ff - uVar8,0);
        if (iVar5 != 1) {
          return iVar5;
        }
        return -0x7ff2fdf2;
      }
      bVar3 = (&DAT_03cf7e65)[uVar7 * 0x28];
      if ((bVar3 != 0) && (bVar3 != 1)) {
        uVar11 = 1;
        do {
          if (uVar10 * iVar5 ==
              (uVar11 << ((byte)(&DAT_03cf7e66)[uVar7 * 0x28] & 0x1f)) +
              *(int *)(&DAT_03cf7e50 + uVar7 * 0x28)) goto LAB_00af1f17;
          uVar11 = uVar11 + 1;
        } while (bVar3 != uVar11);
      }
      uVar7 = uVar7 + 1;
    } while (uVar7 != _DAT_03cf7e40);
  }
  return 0;
}



/* ===== sub_00af1f90 | RVA 0xaf1f90 | file +0x1f50 | ev_1333e4ae71bee15c0f4622535783feb69d938326c88af9fbf487b8b9ae37cf94 =====
 * Body: [{"start":"0xaf1f90","end":"0xaf20be"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

long sub_00af1f90(long param_1,ulong param_2)

{
  byte *pbVar1;
  char cVar2;
  byte bVar3;
  bool bVar4;
  uint uVar5;
  ulong uVar6;
  long lVar7;
  int iVar8;
  uint uVar9;
  ulong uVar10;
  long lVar11;
  
  if (param_2 == 0) {
    uVar5 = 1;
LAB_00af20b5:
    lVar7 = 0;
  }
  else {
    lVar7 = 0;
    uVar6 = 0;
    uVar10 = 1;
    do {
      cVar2 = *(char *)(param_1 + uVar6);
      iVar8 = (int)uVar10;
      if (cVar2 != ' ') {
        if (cVar2 == '0') {
          if ((*(byte *)(param_1 + uVar10) | 0x20) == 0x78) {
            uVar6 = (ulong)(iVar8 + 1);
            uVar5 = 1;
            if (param_2 <= uVar6) goto LAB_00af20b5;
            uVar9 = iVar8 + 2;
            lVar7 = 0;
            goto LAB_00af2018;
          }
          uVar5 = 1;
          uVar9 = 0;
        }
        else {
          uVar9 = (uint)(cVar2 == '-');
          uVar5 = -uVar9 | 1;
        }
        uVar6 = (ulong)((uVar9 - 1) + iVar8);
        if (param_2 <= uVar6) goto LAB_00af20b5;
        uVar9 = uVar9 + iVar8;
        lVar7 = 0;
        goto LAB_00af2090;
      }
      bVar4 = uVar10 < param_2;
      uVar6 = uVar10;
      uVar10 = (ulong)(iVar8 + 1);
    } while (bVar4);
    uVar5 = 1;
  }
  goto LAB_00af20b7;
  while( true ) {
    lVar7 = lVar7 * 0x10 + lVar11 + (ulong)bVar3;
    uVar6 = (ulong)uVar9;
    uVar9 = uVar9 + 1;
    if (param_2 <= uVar6) break;
LAB_00af2018:
    bVar3 = *(byte *)(param_1 + uVar6);
    lVar11 = -0x30;
    if (((9 < (byte)(bVar3 - 0x30)) && (lVar11 = -0x57, 5 < (byte)(bVar3 + 0x9f))) &&
       (lVar11 = -0x37, 5 < (byte)(bVar3 + 0xbf))) break;
  }
  goto LAB_00af20b7;
  while( true ) {
    uVar6 = (ulong)uVar9;
    uVar9 = uVar9 + 1;
    lVar7 = ((ulong)*pbVar1 - 0x30) + lVar7 * 10;
    if (param_2 <= uVar6) break;
LAB_00af2090:
    pbVar1 = (byte *)(param_1 + uVar6);
    if (9 < (byte)(*pbVar1 - 0x30)) break;
  }
LAB_00af20b7:
  return (int)uVar5 * lVar7;
}



/* ===== sub_00af20c0 | RVA 0xaf20c0 | file +0x2080 | ev_8135da0024e61648975f64c3b76c04994e807546dfb915f2f4c0e890d4189f51 =====
 * Body: [{"start":"0xaf20c0","end":"0xaf2137"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

int sub_00af20c0(long param_1,uint param_2)

{
  int iVar1;
  ulong uVar2;
  
  iVar1 = -1;
  if (0 < (int)param_2) {
    uVar2 = 0;
    while (*(char *)(param_1 + uVar2) != ':') {
      if (*(char *)(param_1 + uVar2) == '\0') {
        return -1;
      }
      uVar2 = uVar2 + 1;
      if ((param_2 & 0x7fffffff) <= uVar2) {
        return -1;
      }
    }
    if (uVar2 == 0) {
      iVar1 = 0;
    }
    else if (uVar2 < 0x100) {
      func_0x002590b0(&DAT_03d0e66c,param_1,uVar2);
      (&DAT_03d0e66c)[uVar2] = 0;
      iVar1 = (int)uVar2 + 1;
    }
  }
  return iVar1;
}



/* ===== sub_00af2140 | RVA 0xaf2140 | file +0x2100 | ev_2b3eb4e38350a10f9ab608b9f2487830c67826cfe43fbd4668dabbee059105dd =====
 * Body: [{"start":"0xaf2140","end":"0xaf224e"},{"start":"0xaf2250","end":"0xaf37aa"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Type propagation algorithm not settling */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_00af2140(uint param_1,long param_2,ulong param_3,int param_4)

{
  long lVar1;
  uint *puVar2;
  long lVar3;
  int *piVar4;
  char cVar5;
  short sVar6;
  undefined1 uVar7;
  byte bVar8;
  uint uVar9;
  int iVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  uint uVar14;
  uint uVar15;
  uint uVar16;
  uint uVar17;
  uint uVar18;
  uint uVar19;
  uint uVar20;
  uint uVar21;
  uint uVar22;
  undefined4 uVar23;
  long lVar24;
  undefined8 uVar25;
  ushort uVar26;
  int iVar27;
  uint uVar28;
  ulong uVar29;
  long lVar30;
  long lVar31;
  char *pcVar32;
  uint uVar33;
  ulong uVar34;
  long lVar35;
  ulong uVar36;
  ulong uVar37;
  bool bVar38;
  char cVar39;
  ulong local_58;
  uint local_50;
  uint local_4c;
  
  if (param_3 == 0) {
    return 0x800d0106;
  }
  lVar30 = param_3 - 5;
  uVar34 = 0;
  lVar1 = (ulong)param_1 * 0x28;
  puVar2 = (uint *)(&DAT_03cf7e50 + lVar1);
  while (*(char *)(param_2 + uVar34) != ':') {
    if (*(char *)(param_2 + uVar34) == '\0') {
      return 0x800d0106;
    }
    uVar34 = uVar34 + 1;
    lVar30 = lVar30 + -1;
    if (param_3 <= uVar34) {
      return 0x800d0106;
    }
  }
  if (0xfe < uVar34 - 1) {
    return 0x800d0106;
  }
  func_0x002590b0(&DAT_03d0e66c,param_2,uVar34);
  bVar38 = _DAT_03cf7bb4 == 1;
  (&DAT_03d0e66c)[uVar34] = 0;
  uVar29 = 0xfff7fff7;
  if (bVar38) {
    lVar31 = 0;
    uVar29 = 0;
    do {
      cVar39 = (&DAT_03d0e66c)[uVar29];
      if (cVar39 != ' ') {
        if (cVar39 == '0') {
          if (((&DAT_03d0e66d)[uVar29] | 0x20) == 0x78) {
            uVar9 = 1;
            lVar31 = 0;
            if (uVar29 < 0xfe) goto LAB_00af226a;
            goto LAB_00af2311;
          }
          uVar9 = 1;
          uVar36 = 0;
        }
        else {
          uVar36 = (ulong)(cVar39 == '-');
          uVar9 = -(uint)(cVar39 == '-') | 1;
        }
        if (0xff < (uint)((int)uVar36 + (int)uVar29)) {
          lVar31 = 0;
          goto LAB_00af2311;
        }
        lVar31 = 0;
        goto LAB_00af22e0;
      }
      uVar29 = uVar29 + 1;
    } while (uVar29 != 0x100);
    uVar9 = 1;
    goto LAB_00af2311;
  }
  goto LAB_00af234f;
  while( true ) {
    uVar29 = uVar29 + 1;
    lVar31 = lVar31 * 0x10 + lVar35 + (ulong)bVar8;
    if (uVar29 == 0xfe) break;
LAB_00af226a:
    bVar8 = (&DAT_03d0e66e)[uVar29];
    lVar35 = -0x30;
    if (((9 < (byte)(bVar8 - 0x30)) && (lVar35 = -0x57, 5 < (byte)(bVar8 + 0x9f))) &&
       (lVar35 = -0x37, 5 < (byte)(bVar8 + 0xbf))) break;
  }
  goto LAB_00af2311;
  while( true ) {
    lVar35 = (uVar36 | 0x1c0c) + 1 + uVar29;
    uVar29 = uVar29 + 1;
    lVar31 = ((ulong)bVar8 - 0x30) + lVar31 * 10;
    if (lVar35 == 0x1d0c) break;
LAB_00af22e0:
    bVar8 = *(byte *)((uVar36 | 0x1c0c) + uVar29 + 0x3d0ca60);
    if (9 < (byte)(bVar8 - 0x30)) break;
  }
LAB_00af2311:
  uVar29 = (int)uVar9 * lVar31;
  if (*puVar2 == 0x39010000) {
    uVar36 = 0xffffffffffffffff;
    iVar10 = _DAT_03cf7bb8;
LAB_00af234b:
    if (iVar10 == 1) {
      uVar29 = uVar36;
    }
  }
  else if ((*puVar2 == 0x58800500) && (_DAT_03cf7bb8 == 1)) {
    uVar36 = 0;
    iVar10 = _DAT_03cf7bdc;
    goto LAB_00af234b;
  }
LAB_00af234f:
  iVar10 = (int)param_3;
  if ((int)(~(uint)uVar34 + iVar10) < 1) {
    return 0x800d0106;
  }
  uVar36 = 0;
  while (cVar39 = *(char *)(uVar34 + 1 + param_2 + uVar36), cVar39 != ':') {
    if (cVar39 == '\0') {
      return 0x800d0106;
    }
    uVar36 = uVar36 + 1;
    if ((~(uint)uVar34 + iVar10 & 0x7fffffff) <= uVar36) {
      return 0x800d0106;
    }
  }
  if (0xfe < uVar36 - 1) {
    return 0x800d0106;
  }
  func_0x002590b0(&DAT_03d0e66c,param_2 + 1 + uVar34,uVar36);
  bVar38 = _DAT_03cf7bb4 == 3;
  (&DAT_03d0e66c)[uVar36] = 0;
  if (bVar38) {
    lVar31 = 0;
    uVar29 = 0;
    do {
      cVar39 = (&DAT_03d0e66c)[uVar29];
      if (cVar39 != ' ') {
        if (cVar39 == '0') {
          if (((&DAT_03d0e66d)[uVar29] | 0x20) == 0x78) {
            uVar9 = 1;
            lVar31 = 0;
            if (uVar29 < 0xfe) goto LAB_00af245b;
            goto LAB_00af24fa;
          }
          uVar9 = 1;
          uVar37 = 0;
        }
        else {
          uVar37 = (ulong)(cVar39 == '-');
          uVar9 = -(uint)(cVar39 == '-') | 1;
        }
        if (0xff < (uint)((int)uVar37 + (int)uVar29)) {
          lVar31 = 0;
          goto LAB_00af24fa;
        }
        lVar31 = 0;
        goto LAB_00af24c9;
      }
      uVar29 = uVar29 + 1;
    } while (uVar29 != 0x100);
    uVar9 = 1;
    goto LAB_00af24fa;
  }
  goto LAB_00af2501;
  while( true ) {
    uVar29 = uVar29 + 1;
    lVar31 = lVar31 * 0x10 + lVar35 + (ulong)bVar8;
    if (uVar29 == 0xfe) break;
LAB_00af245b:
    bVar8 = (&DAT_03d0e66e)[uVar29];
    lVar35 = -0x30;
    if (((9 < (byte)(bVar8 - 0x30)) && (lVar35 = -0x57, 5 < (byte)(bVar8 + 0x9f))) &&
       (lVar35 = -0x37, 5 < (byte)(bVar8 + 0xbf))) break;
  }
  goto LAB_00af24fa;
  while( true ) {
    lVar35 = (uVar37 | 0x1c0c) + 1 + uVar29;
    uVar29 = uVar29 + 1;
    lVar31 = ((ulong)bVar8 - 0x30) + lVar31 * 10;
    if (lVar35 == 0x1d0c) break;
LAB_00af24c9:
    bVar8 = *(byte *)((uVar37 | 0x1c0c) + uVar29 + 0x3d0ca60);
    if (9 < (byte)(bVar8 - 0x30)) break;
  }
LAB_00af24fa:
  uVar29 = (int)uVar9 * lVar31;
LAB_00af2501:
  if (((int)lVar30 - (int)uVar36) + 3 < 1) {
    return 0x800d0106;
  }
  lVar35 = uVar34 + uVar36;
  lVar31 = lVar30 - uVar36;
  uVar37 = 0;
  while (cVar39 = *(char *)(param_2 + 2 + lVar35), cVar39 != ':') {
    if (cVar39 == '\0') {
      return 0x800d0106;
    }
    uVar37 = uVar37 + 1;
    lVar31 = lVar31 + -1;
    lVar35 = lVar35 + 1;
    if ((((int)lVar30 - (int)uVar36) + 3U & 0x7fffffff) <= uVar37) {
      return 0x800d0106;
    }
  }
  if (0xfe < uVar37 - 1) {
    return 0x800d0106;
  }
  func_0x002590b0(&DAT_03d0e66c,uVar36 + 2 + param_2 + uVar34,uVar37);
  bVar38 = _DAT_03cf7bb4 == 2;
  (&DAT_03d0e66c)[uVar37] = 0;
  if (bVar38) {
    lVar30 = 0;
    uVar34 = 0;
    do {
      cVar39 = (&DAT_03d0e66c)[uVar34];
      if (cVar39 != ' ') {
        if (cVar39 == '0') {
          if (((&DAT_03d0e66d)[uVar34] | 0x20) == 0x78) {
            uVar9 = 1;
            lVar30 = 0;
            if (uVar34 < 0xfe) goto LAB_00af260f;
            goto LAB_00af26ac;
          }
          uVar9 = 1;
          uVar29 = 0;
        }
        else {
          uVar29 = (ulong)(cVar39 == '-');
          uVar9 = -(uint)(cVar39 == '-') | 1;
        }
        if (0xff < (uint)((int)uVar29 + (int)uVar34)) {
          lVar30 = 0;
          goto LAB_00af26ac;
        }
        lVar30 = 0;
        goto LAB_00af267b;
      }
      uVar34 = uVar34 + 1;
    } while (uVar34 != 0x100);
    uVar9 = 1;
    goto LAB_00af26ac;
  }
  goto LAB_00af26b3;
  while( true ) {
    uVar34 = uVar34 + 1;
    lVar30 = lVar30 * 0x10 + lVar24 + (ulong)bVar8;
    if (uVar34 == 0xfe) break;
LAB_00af260f:
    bVar8 = (&DAT_03d0e66e)[uVar34];
    lVar24 = -0x30;
    if (((9 < (byte)(bVar8 - 0x30)) && (lVar24 = -0x57, 5 < (byte)(bVar8 + 0x9f))) &&
       (lVar24 = -0x37, 5 < (byte)(bVar8 + 0xbf))) break;
  }
  goto LAB_00af26ac;
  while( true ) {
    uVar36 = uVar36 + 1;
    iVar10 = iVar10 * 0x10 + iVar27 + (uint)bVar8;
    if (uVar36 == 0xfe) break;
LAB_00af2924:
    bVar8 = (&DAT_03d0e66e)[uVar36];
    iVar27 = -0x30;
    if (((9 < (byte)(bVar8 - 0x30)) && (iVar27 = -0x57, 5 < (byte)(bVar8 + 0x9f))) &&
       (iVar27 = -0x37, 5 < (byte)(bVar8 + 0xbf))) break;
  }
  goto LAB_00af29c1;
  while( true ) {
    lVar3 = (uVar37 | 0x1c0c) + 1 + uVar36;
    uVar36 = uVar36 + 1;
    iVar10 = (bVar8 - 0x30) + iVar10 * 10;
    if (lVar3 == 0x1d0c) break;
LAB_00af2990:
    bVar8 = *(byte *)((uVar37 | 0x1c0c) + uVar36 + 0x3d0ca60);
    if (9 < (byte)(bVar8 - 0x30)) break;
  }
  goto LAB_00af29c1;
  while( true ) {
    lVar24 = (uVar29 | 0x1c0c) + 1 + uVar34;
    uVar34 = uVar34 + 1;
    lVar30 = ((ulong)bVar8 - 0x30) + lVar30 * 10;
    if (lVar24 == 0x1d0c) break;
LAB_00af267b:
    bVar8 = *(byte *)((uVar29 | 0x1c0c) + uVar34 + 0x3d0ca60);
    if (9 < (byte)(bVar8 - 0x30)) break;
  }
LAB_00af26ac:
  uVar29 = (int)uVar9 * lVar30;
LAB_00af26b3:
  if (_DAT_03cf7bb8 == 3) {
    uVar9 = *puVar2;
    if ((int)uVar9 < 0x78023700) {
      if ((int)uVar9 < 0x41c40000) {
        if (uVar9 == 0x14288300) {
          return 1;
        }
        if (uVar9 == 0x14840000) {
          return 1;
        }
      }
      else {
        if (uVar9 == 0x41c40000) {
          return 1;
        }
        if (uVar9 == 0x78022200) {
          return 1;
        }
      }
    }
    else if ((int)uVar9 < 0x78024000) {
      if (uVar9 == 0x78023700) {
        return 1;
      }
      if (uVar9 == 0x78023d00) {
        return 1;
      }
    }
    else {
      if (uVar9 == 0x78024000) {
        return 1;
      }
      if (uVar9 == 0x78025500) {
        return 1;
      }
    }
  }
  if (uVar29 == 0xfff7fff7) {
    return 0x800d0106;
  }
  if (uVar29 != 0) {
    if (uVar29 == 0xffffffffffffffff) {
      return 1;
    }
    uVar34 = (long)uVar29 >> 8;
    if (_DAT_03cf7bc4 != 1) {
      uVar34 = uVar29;
    }
    if ((uVar34 & 1) == 0) {
      return 1;
    }
    if (((uVar34 & 0x10) != 0) && (_DAT_03cf7bd8 != 1)) {
      return 1;
    }
    if (((uVar34 & 0x40) != 0) && (_DAT_03cf7bb0 != 0xe)) {
      return 1;
    }
    uVar9 = 0;
    if (((uVar34 & 8) == 0) || (uVar9 = 8, _DAT_03cf7bcc != 1)) {
      if ((uVar34 & 4) != 0) {
        if (_DAT_03cf7bd4 == 1) goto LAB_00af2809;
        uVar9 = uVar9 | 4;
      }
      if ((uVar34 & 0x20) != 0) {
        if (_DAT_03cf7be0 == 1) goto LAB_00af2809;
        uVar9 = uVar9 | 0x20;
      }
      if (((uVar34 & 2) == 0) || (uVar9 = 1, _DAT_03cf7be4 != 1)) {
        if ((char)uVar34 < '\0') {
          if (_DAT_03cf7be8 != 1) {
            if ((uVar34 >> 0x32 & 1) == 0) {
              return 1;
            }
            goto LAB_00af27f7;
          }
        }
        else {
          if ((uVar34 >> 0x32 & 1) == 0) {
            bVar38 = uVar9 == 0;
          }
          else {
LAB_00af27f7:
            bVar38 = _DAT_03cf7bec == 1;
          }
          if (!bVar38) {
            return 1;
          }
        }
      }
    }
  }
LAB_00af2809:
  if ((iVar10 - (int)lVar35) + -3 < 1) {
    return 0x800d0107;
  }
  uVar29 = 0;
  uVar34 = (param_3 - lVar35) - 4;
  pcVar32 = (char *)(param_2 + 3 + lVar35);
  while( true ) {
    if (*pcVar32 == ':') break;
    if (*pcVar32 == '\0') {
      return 0x800d0107;
    }
    uVar29 = uVar29 + 1;
    uVar34 = (ulong)((int)uVar34 - 1);
    pcVar32 = pcVar32 + 1;
    if (((int)(param_3 - lVar35) - 3U & 0x7fffffff) <= uVar29) {
      return 0x800d0107;
    }
  }
  if (0xfe < uVar29 - 1) {
    return 0x800d0107;
  }
  lVar30 = uVar29 + 7 + param_2 + lVar35;
  lVar24 = lVar31 - uVar29;
  func_0x002590b0(&DAT_03d0e66c,param_2 + 3 + lVar35,uVar29);
  (&DAT_03d0e66c)[uVar29] = 0;
  iVar10 = 0;
  uVar36 = 0;
  do {
    cVar39 = (&DAT_03d0e66c)[uVar36];
    if (cVar39 != ' ') {
      if (cVar39 == '0') {
        if (((&DAT_03d0e66d)[uVar36] | 0x20) == 0x78) {
          uVar9 = 1;
          iVar10 = 0;
          if (uVar36 < 0xfe) goto LAB_00af2924;
          goto LAB_00af29c1;
        }
        uVar9 = 1;
        uVar37 = 0;
      }
      else {
        uVar37 = (ulong)(cVar39 == '-');
        uVar9 = -(uint)(cVar39 == '-') | 1;
      }
      if (0xff < (uint)((int)uVar37 + (int)uVar36)) {
        iVar10 = 0;
        goto LAB_00af29c1;
      }
      iVar10 = 0;
      goto LAB_00af2990;
    }
    uVar36 = uVar36 + 1;
  } while (uVar36 != 0x100);
  uVar9 = 1;
LAB_00af29c1:
  if (uVar9 * iVar10 < 3) {
    *(short *)(lVar1 + 0x3cf7e54) = (short)(uVar9 * iVar10);
    if (0 < (int)uVar34) {
      uVar34 = 0;
      do {
        if (*(char *)(lVar30 + -3) == ':') {
          if (uVar34 - 1 < 0xff) {
            func_0x002590b0(&DAT_03d0e66c,uVar29 + 4 + param_2 + lVar35,uVar34);
            (&DAT_03d0e66c)[uVar34] = 0;
            iVar10 = sub_00af1f90(&DAT_03d0e66c,0x100);
            if (0xfffff800 < iVar10 - 0x800U) {
              *(short *)(lVar1 + 0x3cf7e56) = (short)iVar10;
              uVar9 = sub_00af20c0(lVar30 + -2,lVar24);
              if ((int)uVar9 < 1) {
                return 0x800d0118;
              }
              uVar34 = (ulong)uVar9;
              uVar9 = sub_00af1f90(&DAT_03d0e66c,0x100);
              if (*(char *)(lVar1 + 0x3cf7e5b) == '\0') {
                if ((uVar9 & 2) == 0) {
                  if (*(ushort *)(lVar1 + 0x3cf7e56) < 5) {
                    *(undefined1 *)(lVar1 + 0x3cf7e5a) = 1;
                  }
                  else {
                    *(undefined1 *)(lVar1 + 0x3cf7e5a) = 2;
                  }
                }
                else {
                  *(undefined2 *)(lVar1 + 0x3cf7e5a) = 0x200;
                }
              }
              if ((uVar9 & 0xfffffffd) != 0) {
                if ((uVar9 & 0xfffffffd) != 1) {
                  return 0x800d0118;
                }
                *(byte *)(lVar1 + 0x3cf7e62) = *(byte *)(lVar1 + 0x3cf7e62) | 4;
              }
              uVar9 = sub_00af20c0(lVar30 + -2 + uVar34,lVar24 - uVar34);
              if ((int)uVar9 < 1) {
                return 0x800d010a;
              }
              uVar11 = sub_00af1f90(&DAT_03d0e66c,0x100);
              if ((uVar11 & 0x10000) != 0) {
                uVar11 = uVar11 & 0xfffeffff;
                *(byte *)(lVar1 + 0x3cf7e62) = *(byte *)(lVar1 + 0x3cf7e62) | 0x20;
              }
              if ((uVar11 & 0x20000) != 0) {
                uVar11 = uVar11 & 0xfffdffff;
                *(byte *)(lVar1 + 0x3cf7e62) = *(byte *)(lVar1 + 0x3cf7e62) | 0x80;
              }
              uVar28 = uVar11 & 0xffff19ff;
              if ((int)uVar28 < 0x100) {
                if (((0x30 < uVar28 - 0x10) ||
                    ((0x1000100010001U >> ((ulong)(uVar28 - 0x10) & 0x3f) & 1) == 0)) &&
                   (uVar28 != 0)) {
                  return 0x800d010a;
                }
              }
              else if ((uVar28 != 0x1000) && (uVar28 != 0x100)) {
                return 0x800d010a;
              }
              lVar31 = uVar34 + uVar9;
              if (_DAT_03cf7bc0 == 1) {
                uVar11 = 0x1000;
              }
              *(short *)(lVar1 + 0x3cf7e58) = (short)uVar11;
              uVar11 = sub_00af20c0(lVar30 + -2 + lVar31,lVar24 - lVar31);
              if ((int)uVar11 < 1) {
                return 0x800d010b;
              }
              iVar10 = sub_00af1f90(&DAT_03d0e66c,0x100);
              if (iVar10 == 0) {
                *(undefined2 *)(lVar1 + 0x3cf7e60) = 0;
                *(byte *)(lVar1 + 0x3cf7e62) = *(byte *)(lVar1 + 0x3cf7e62) & 0xfe;
              }
              else if (iVar10 == 1) {
                *(undefined2 *)(lVar1 + 0x3cf7e60) = 0;
                *(byte *)(lVar1 + 0x3cf7e62) = *(byte *)(lVar1 + 0x3cf7e62) | 1;
              }
              else {
                if (0xbff < (uint)*(ushort *)(lVar1 + 0x3cf7e56) + iVar10) {
                  return 0x800d010b;
                }
                *(short *)(lVar1 + 0x3cf7e60) = (short)iVar10;
              }
              lVar31 = lVar31 + (ulong)uVar11;
              uVar28 = sub_00af20c0(lVar30 + -2 + lVar31,lVar24 - lVar31);
              if ((int)uVar28 < 1) {
                return 0x800d010c;
              }
              uVar12 = sub_00af1f90(&DAT_03d0e66c,0x100);
              if (uVar12 == 0) {
                local_4c = 0;
                local_50 = 0;
              }
              else {
                local_50 = 0;
                cVar39 = (uVar12 & 1) != 0;
                if ((bool)cVar39) {
                  *(byte *)(lVar1 + 0x3cf7e62) = *(byte *)(lVar1 + 0x3cf7e62) | 2;
                }
                if ((uVar12 & 2) != 0) {
                  cVar39 = cVar39 + '\x01';
                  *(byte *)(lVar1 + 0x3cf7e6a) = *(byte *)(lVar1 + 0x3cf7e6a) | 2;
                  local_50 = (uint)*(ushort *)(lVar1 + 0x3cf7e56);
                }
                local_4c = 0;
                if ((uVar12 & 4) != 0) {
                  *(byte *)(lVar1 + 0x3cf7e6a) = *(byte *)(lVar1 + 0x3cf7e6a) | 4;
                  local_4c = (uint)*(ushort *)(lVar1 + 0x3cf7e56);
                  cVar39 = '\x01';
                }
                if ((char)uVar12 < '\0') {
                  uVar26 = *(ushort *)(lVar1 + 0x3cf7e62) | 0x100;
                  *(ushort *)(lVar1 + 0x3cf7e62) = uVar26;
                  if ((uVar12 & 0x100) != 0) goto LAB_00af2d4b;
                }
                else if ((uVar12 & 0x100) == 0) {
                  if (cVar39 == '\0') {
                    return 0x800d010c;
                  }
                }
                else {
                  uVar26 = *(ushort *)(lVar1 + 0x3cf7e62);
LAB_00af2d4b:
                  *(ushort *)(lVar1 + 0x3cf7e62) = uVar26 | 0x300;
                }
              }
              lVar31 = lVar31 + (ulong)uVar28;
              uVar12 = sub_00af20c0(lVar30 + -2 + lVar31,lVar24 - lVar31);
              if ((int)uVar12 < 1) {
                return 0x800d010d;
              }
              lVar31 = lVar31 + (ulong)uVar12;
              uVar13 = 0xffffffff;
              if (((_DAT_03cf7bb8 == 1) &&
                  (uVar13 = sub_00af1f90(&DAT_03d0e66c,0x100), *puVar2 == 0x19800000)) &&
                 (_DAT_03cf7be0 == 1)) {
                uVar13 = 6;
                *(byte *)(lVar1 + 0x3cf7e59) = *(byte *)(lVar1 + 0x3cf7e59) & 0x19;
              }
              uVar14 = sub_00af20c0(lVar30 + -2 + lVar31,lVar24 - lVar31);
              if ((int)uVar14 < 1) {
                return 0x800d010d;
              }
              lVar31 = lVar31 + (ulong)uVar14;
              if (_DAT_03cf7bb8 == 3) {
                uVar13 = sub_00af1f90(&DAT_03d0e66c,0x100);
              }
              uVar15 = sub_00af20c0(lVar30 + -2 + lVar31,lVar24 - lVar31);
              if ((int)uVar15 < 1) {
                return 0x800d010d;
              }
              if (_DAT_03cf7bb8 == 2) {
                uVar13 = sub_00af1f90(&DAT_03d0e66c,0x100);
                uVar33 = uVar13;
                if ((uVar13 & 0x20) == 0) goto LAB_00af2eb8;
LAB_00af2e70:
                uVar33 = uVar13 & 0xffffffdf;
                *(byte *)(lVar1 + 0x3cf7e62) = *(byte *)(lVar1 + 0x3cf7e62) | 8;
                if ((uVar13 & 0x40) == 0) goto LAB_00af2ebe;
LAB_00af2e82:
                uVar33 = uVar33 & 0xffffffbf;
                *(byte *)(lVar1 + 0x3cf7e62) = *(byte *)(lVar1 + 0x3cf7e62) | 0x10;
                cVar39 = (char)uVar33;
              }
              else {
                uVar33 = uVar13;
                if ((uVar13 & 0x20) != 0) goto LAB_00af2e70;
LAB_00af2eb8:
                if ((uVar33 & 0x40) != 0) goto LAB_00af2e82;
LAB_00af2ebe:
                cVar39 = (char)uVar33;
              }
              if (cVar39 < '\0') {
                uVar33 = uVar33 & 0xffffff7f;
                *(byte *)(lVar1 + 0x3cf7e62) = *(byte *)(lVar1 + 0x3cf7e62) | 0x40;
              }
              if (9 < uVar33) {
                return 0x800d010d;
              }
              if ((0x253U >> (uVar33 & 0x1f) & 1) == 0) {
                return 0x800d010d;
              }
              lVar31 = lVar31 + (ulong)uVar15;
              *(char *)(lVar1 + 0x3cf7e64) = (char)uVar33;
              uVar13 = sub_00af20c0(lVar30 + -2 + lVar31,lVar24 - lVar31);
              if ((int)uVar13 < 1) {
                return 0x800d010e;
              }
              uVar33 = sub_00af1f90(&DAT_03d0e66c,0x100);
              if (uVar33 != 0) {
                bVar38 = false;
                if ((uVar33 & 1) == 0) {
                  if ((uVar33 & 2) != 0) goto LAB_00af2f5d;
LAB_00af2f2c:
                  if ((uVar33 & 4) != 0) goto LAB_00af2f6e;
LAB_00af2f30:
                  if ((uVar33 & 8) == 0) {
                    if (!bVar38) {
                      return 0x800d010e;
                    }
                    goto LAB_00af2f92;
                  }
                  uVar16 = *(uint *)(lVar1 + 0x3cf7e6c);
                }
                else {
                  *(byte *)(lVar1 + 0x3cf7e6c) = *(byte *)(lVar1 + 0x3cf7e6c) | 1;
                  bVar38 = true;
                  if ((uVar33 & 2) == 0) goto LAB_00af2f2c;
LAB_00af2f5d:
                  *(byte *)(lVar1 + 0x3cf7e6c) = *(byte *)(lVar1 + 0x3cf7e6c) | 2;
                  bVar38 = true;
                  if ((uVar33 & 4) == 0) goto LAB_00af2f30;
LAB_00af2f6e:
                  uVar16 = *(uint *)(lVar1 + 0x3cf7e6c) | 4;
                  *(uint *)(lVar1 + 0x3cf7e6c) = uVar16;
                  if ((uVar33 & 8) == 0) goto LAB_00af2f92;
                }
                *(uint *)(lVar1 + 0x3cf7e6c) = uVar16 | 8;
              }
LAB_00af2f92:
              lVar31 = lVar31 + (ulong)uVar13;
              uVar33 = sub_00af20c0(lVar30 + -2 + lVar31,lVar24 - lVar31);
              if ((int)uVar33 < 1) {
                return 0x800d010f;
              }
              uVar16 = sub_00af1f90(&DAT_03d0e66c,0x100);
              if (uVar16 != 0) {
                bVar38 = false;
                if ((uVar16 & 1) == 0) {
                  if ((uVar16 & 2) != 0) goto LAB_00af300c;
LAB_00af2fdb:
                  if ((uVar16 & 4) != 0) goto LAB_00af301d;
LAB_00af2fdf:
                  if ((uVar16 & 8) == 0) {
                    if (!bVar38) {
                      return 0x800d010f;
                    }
                    goto LAB_00af3044;
                  }
                  uVar17 = *(uint *)(lVar1 + 0x3cf7e6c);
                }
                else {
                  *(byte *)(lVar1 + 0x3cf7e6c) = *(byte *)(lVar1 + 0x3cf7e6c) | 0x10;
                  bVar38 = true;
                  if ((uVar16 & 2) == 0) goto LAB_00af2fdb;
LAB_00af300c:
                  *(byte *)(lVar1 + 0x3cf7e6c) = *(byte *)(lVar1 + 0x3cf7e6c) | 0x20;
                  bVar38 = true;
                  if ((uVar16 & 4) == 0) goto LAB_00af2fdf;
LAB_00af301d:
                  uVar17 = *(uint *)(lVar1 + 0x3cf7e6c) | 0x40;
                  *(uint *)(lVar1 + 0x3cf7e6c) = uVar17;
                  if ((uVar16 & 8) == 0) goto LAB_00af3044;
                }
                *(uint *)(lVar1 + 0x3cf7e6c) = uVar17 | 0x80;
              }
LAB_00af3044:
              lVar31 = lVar31 + (ulong)uVar33;
              uVar16 = sub_00af20c0(lVar30 + -2 + lVar31,lVar24 - lVar31);
              if ((int)uVar16 < 1) {
                return 0x800d0115;
              }
              uVar17 = sub_00af1f90(&DAT_03d0e66c,0x100);
              if (uVar17 != 0) {
                iVar10 = 0;
                iVar27 = 0;
                if ((uVar17 & 1) == 0) {
                  if ((uVar17 & 2) != 0) goto LAB_00af30ca;
LAB_00af3091:
                  if ((uVar17 & 4) != 0) goto LAB_00af30d8;
LAB_00af3095:
                  if ((uVar17 & 8) != 0) goto LAB_00af30e6;
LAB_00af3099:
                  if ((uVar17 & 0x10) != 0) goto LAB_00af30f7;
LAB_00af309d:
                  if ((uVar17 & 0x20) == 0) {
                    if (iVar10 == 0) {
                      return 0x800d0115;
                    }
                    goto LAB_00af3120;
                  }
                  uVar18 = *(uint *)(lVar1 + 0x3cf7e6c);
                }
                else {
                  *(byte *)(lVar1 + 0x3cf7e6d) = *(byte *)(lVar1 + 0x3cf7e6d) | 4;
                  iVar10 = 1;
                  iVar27 = 1;
                  if ((uVar17 & 2) == 0) goto LAB_00af3091;
LAB_00af30ca:
                  iVar10 = iVar27 + 1;
                  *(byte *)(lVar1 + 0x3cf7e6d) = *(byte *)(lVar1 + 0x3cf7e6d) | 8;
                  if ((uVar17 & 4) == 0) goto LAB_00af3095;
LAB_00af30d8:
                  iVar10 = iVar10 + 1;
                  *(byte *)(lVar1 + 0x3cf7e6d) = *(byte *)(lVar1 + 0x3cf7e6d) | 0x10;
                  if ((uVar17 & 8) == 0) goto LAB_00af3099;
LAB_00af30e6:
                  *(byte *)(lVar1 + 0x3cf7e6d) = *(byte *)(lVar1 + 0x3cf7e6d) | 0x20;
                  iVar10 = 1;
                  if ((uVar17 & 0x10) == 0) goto LAB_00af309d;
LAB_00af30f7:
                  uVar18 = *(uint *)(lVar1 + 0x3cf7e6c) | 0x4000;
                  *(uint *)(lVar1 + 0x3cf7e6c) = uVar18;
                  if ((uVar17 & 0x20) == 0) goto LAB_00af3120;
                }
                *(uint *)(lVar1 + 0x3cf7e6c) = uVar18 | 0x8000;
              }
LAB_00af3120:
              lVar31 = lVar31 + (ulong)uVar16;
              uVar17 = sub_00af20c0(lVar30 + -2 + lVar31,lVar24 - lVar31);
              if ((int)uVar17 < 1) {
                return 0x800d0110;
              }
              lVar31 = lVar31 + (ulong)uVar17;
              uVar18 = 0xffffffff;
              if (_DAT_03cf7bc4 == 1) {
                uVar18 = sub_00af1f90(&DAT_03d0e66c,0x100);
              }
              uVar19 = sub_00af20c0(lVar30 + -2 + lVar31,lVar24 - lVar31);
              if ((int)uVar19 < 1) {
                return 0x800d0110;
              }
              if (_DAT_03cf7bc4 != 1) {
                uVar18 = sub_00af1f90(&DAT_03d0e66c,0x100);
              }
              if (uVar18 == 0xffffffff) {
                return 0x800d0110;
              }
              lVar31 = lVar31 + (ulong)uVar19;
              if ((uVar18 & 1) != 0) {
                *(byte *)(lVar1 + 0x3cf7e6d) = *(byte *)(lVar1 + 0x3cf7e6d) | 1;
              }
              if ((uVar18 & 2) != 0) {
                *(byte *)(lVar1 + 0x3cf7e6d) = *(byte *)(lVar1 + 0x3cf7e6d) | 2;
              }
              uVar18 = sub_00af20c0(lVar30 + -2 + lVar31,lVar24 - lVar31);
              if ((int)uVar18 < 1) {
                return 0x800d0119;
              }
              iVar10 = sub_00af1f90(&DAT_03d0e66c,0x100);
              if (iVar10 < 0x23) {
                if (iVar10 - 1U < 3) {
LAB_00af328a:
                  uVar7 = (undefined1)iVar10;
                }
                else {
                  if (iVar10 != 0x13) {
                    return 0x800d0119;
                  }
                  uVar7 = 0x12;
                }
              }
              else if (iVar10 < 0x53) {
                uVar7 = 0x22;
                if (iVar10 != 0x23) {
                  if (iVar10 != 0x43) {
                    return 0x800d0119;
                  }
                  uVar7 = 0x42;
                }
              }
              else {
                if (iVar10 != 0x53) {
                  if (iVar10 != 0x83) {
                    return 0x800d0119;
                  }
                  goto LAB_00af328a;
                }
                uVar7 = 0x52;
              }
              lVar31 = lVar31 + (ulong)uVar18;
              *(undefined1 *)(lVar1 + 0x3cf7e68) = uVar7;
              uVar20 = sub_00af20c0(lVar30 + -2 + lVar31,lVar24 - lVar31);
              if ((int)uVar20 < 1) {
                return 0x800d0112;
              }
              uVar21 = sub_00af1f90(&DAT_03d0e66c,0x100);
              cVar39 = (char)(uVar21 & 0xffffff7f);
              if (99 < (int)(uVar21 & 0xffffff7f)) {
                return 0x800d0112;
              }
              if ((char)uVar21 < '\0') {
                uVar7 = 0x10;
LAB_00af3306:
                (&DAT_03cf7e65)[lVar1] = cVar39;
                (&DAT_03cf7e66)[lVar1] = uVar7;
              }
              else if (uVar21 != 0) {
                uVar7 = 8;
                cVar39 = (char)uVar21;
                goto LAB_00af3306;
              }
              if (*(char *)(lVar1 + 0x3cf7e5b) == '\0') {
                bVar8 = (&DAT_03cf7e65)[lVar1];
                if (bVar8 == 0) {
                  if (*(char *)(lVar1 + 0x3cf7e5a) != '\x01') {
                    *(uint *)(lVar1 + 0x3cf7e5c) = _DAT_03cf7e44;
                    _DAT_03cf7e44 = _DAT_03cf7e44 + *(ushort *)(lVar1 + 0x3cf7e56);
                  }
                }
                else {
                  *(undefined1 *)(lVar1 + 0x3cf7e5a) = 0x10;
                  *(uint *)(lVar1 + 0x3cf7e5c) = _DAT_03cf7e44;
                  _DAT_03cf7e44 = (uint)*(ushort *)(lVar1 + 0x3cf7e56) * (uint)bVar8 + _DAT_03cf7e44
                  ;
                }
                if (0x64000 < _DAT_03cf7e44) {
                  return 0x800d0212;
                }
                *(undefined1 *)(lVar1 + 0x3cf7e5b) = 1;
              }
              lVar31 = lVar31 + (ulong)uVar20;
              uVar21 = sub_00af20c0(lVar30 + -2 + lVar31,lVar24 - lVar31);
              if (0 < (int)uVar21) {
                uVar22 = sub_00af1f90(&DAT_03d0e66c,0x100);
                if (uVar22 < 2 || (char)uVar22 < '\0') {
                  lVar31 = lVar31 + (ulong)uVar21;
                  lVar35 = lVar30 + -2 + lVar31;
                  *(short *)(lVar1 + 0x3cf7e70) = (short)uVar22;
                  uVar22 = sub_00af20c0(lVar35,lVar24 - lVar31);
                  if (0 < (int)uVar22) {
                    if (*(ushort *)(lVar1 + 0x3cf7e54) - 1 < 2) {
                      if ((ushort)(*(short *)(lVar1 + 0x3cf7e56) - 0x801U) < 0xf800) {
                        return 0x800d0108;
                      }
                      sVar6 = *(short *)(lVar1 + 0x3cf7e70);
                      if (sVar6 != 0 && -1 < (char)sVar6) {
                        if (sVar6 != 1) {
                          return 0x800d0111;
                        }
                        uVar29 = func_0x00444eb0(&DAT_03d0e66c,0xff);
                        local_58 = (ulong)((uint)uVar29 + 1);
                        if (*(char *)(lVar30 + -2 + (ulong)uVar22 + lVar31) == '\0') {
                          if ((DAT_03d0e66c == 'b') && (DAT_03d0e66d == '\'')) {
                            if (*(short *)(lVar1 + 0x3cf7e54) != 2) {
                              return 0x800d0107;
                            }
                            if ((uVar29 & 1) != 0) {
                              return 0x800d0113;
                            }
                            func_0x00258ff0(&DAT_03d0e66c);
                            local_58 = 0;
                            if (2 < ((uint)uVar29 & 0xfffe)) {
                              cVar39 = '\x10';
                              lVar31 = 0;
                              do {
                                cVar5 = *(char *)(lVar30 + (ulong)uVar15 + (ulong)uVar14 +
                                                           (ulong)uVar12 + (ulong)uVar28 +
                                                           (ulong)uVar11 + (ulong)uVar9 +
                                                           (ulong)uVar20 + (ulong)uVar18 +
                                                           (ulong)uVar19 + (ulong)uVar17 +
                                                           (ulong)uVar16 + (ulong)uVar33 +
                                                           (ulong)uVar13 + uVar34 + uVar21 + lVar31)
                                ;
                                if ((byte)(cVar5 + 0xbfU) < 6) {
                                  bVar8 = cVar5 - 0x37;
                                }
                                else if ((byte)(cVar5 + 0x9fU) < 6) {
                                  bVar8 = cVar5 + 0xa9;
                                }
                                else {
                                  bVar8 = cVar5 - 0x30;
                                  if (9 < bVar8) {
                                    return 0x800d0113;
                                  }
                                }
                                (&DAT_03d0e66c)[(int)local_58] =
                                     (&DAT_03d0e66c)[(int)local_58] + bVar8 * cVar39;
                                bVar38 = cVar39 != '\x10';
                                cVar39 = '\x01';
                                if (bVar38) {
                                  cVar39 = '\x10';
                                }
                                lVar31 = lVar31 + 1;
                                local_58 = (ulong)((int)local_58 + (uint)bVar38);
                              } while ((uVar29 & 0xffff) - 2 != lVar31);
                            }
                          }
                        }
                        else {
                          uVar34 = func_0x00444eb0(lVar35,0x100);
                          uVar29 = uVar34 & 0xffff;
                          if (*(char *)(lVar30 + -3 + lVar31 + uVar29) == ':') {
                            func_0x002590b0(&DAT_03d0e66c,lVar35,uVar29);
                            *(undefined1 *)(uVar29 + 0x3d0e66b) = 0;
                            local_58 = uVar34;
                          }
                        }
                        if (0xa00 < (uint)_DAT_03cf7e42 + (uint)(ushort)local_58) {
                          return 0x800d0113;
                        }
                        func_0x002590b0((ulong)(uint)_DAT_03cf7e42 + _DAT_03d0be50,&DAT_03d0e66c,
                                        local_58 & 0xffff);
                        *(ushort *)(lVar1 + 0x3cf7e72) = (ushort)local_58;
                        *(uint *)(lVar1 + 0x3cf7e74) = (uint)_DAT_03cf7e42;
                        _DAT_03cf7e42 = _DAT_03cf7e42 + (ushort)local_58;
joined_r0x00af37a0:
                        if (param_4 != 0) {
                          if ((&DAT_03cf7e65)[lVar1] == 0) {
                            uVar9 = 1;
                          }
                          else if (((*puVar2 & 0xff000000) != 0x7000000) ||
                                  (uVar9 = 0x10, 0x13 < (*puVar2 >> 0x12 & 0x3f) * 4 - 0x80)) {
                            uVar9 = (uint)(byte)(&DAT_03cf7e65)[lVar1];
                          }
                          uVar34 = (ulong)(*(short *)(lVar1 + 0x3cf7e60) == 0);
                          if (local_50 != 0) {
                            piVar4 = (int *)(uVar34 * 4 + 0x3cf7c38);
                            *piVar4 = *piVar4 + uVar9;
                            piVar4 = (int *)(uVar34 * 4 + 0x3cf7c40);
                            *piVar4 = *piVar4 + ((local_50 - 1 & 0xfffffffc) + 8) * uVar9;
                          }
                          if (local_4c != 0) {
                            piVar4 = (int *)(uVar34 * 4 + 0x3cf7c4c);
                            *piVar4 = *piVar4 + uVar9;
                            piVar4 = (int *)(uVar34 * 4 + 0x3cf7c54);
                            *piVar4 = *piVar4 + ((local_4c - 1 & 0xfffffffc) + 8) * uVar9;
                          }
                        }
                        return 0;
                      }
                      *(short *)(lVar1 + 0x3cf7e72) = *(short *)(lVar1 + 0x3cf7e56);
                    }
                    else {
                      if (*(ushort *)(lVar1 + 0x3cf7e54) != 0) {
                        return 0x800d0107;
                      }
                      if (*(short *)(lVar1 + 0x3cf7e56) != 4) {
                        return 0x800d0108;
                      }
                      if (*(short *)(lVar1 + 0x3cf7e70) != 1 &&
                          -1 < (char)*(short *)(lVar1 + 0x3cf7e70)) {
                        return 0x800d0111;
                      }
                      *(undefined2 *)(lVar1 + 0x3cf7e56) = 4;
                      *(undefined2 *)(lVar1 + 0x3cf7e72) = 4;
                    }
                    uVar23 = sub_00af1f90(&DAT_03d0e66c,0x100);
                    *(undefined4 *)(lVar1 + 0x3cf7e74) = uVar23;
                    goto joined_r0x00af37a0;
                  }
                }
              }
              return 0x800d0111;
            }
          }
          break;
        }
        if (*(char *)(lVar30 + -3) == '\0') break;
        uVar34 = uVar34 + 1;
        lVar30 = lVar30 + 1;
        lVar24 = lVar24 + -1;
      } while (uVar34 < (((int)lVar31 - (int)uVar29) + 1U & 0x7fffffff));
    }
    uVar25 = 0x800d0108;
  }
  else {
    uVar25 = 0x800d0107;
  }
  return uVar25;
}



/* ===== sub_00af37b0 | RVA 0xaf37b0 | file +0x3770 | ev_facb8e7a1a222f5553b1d9459bfdfb1ddf2f4dbe0ea10d619595c81d54c53b86 =====
 * Body: [{"start":"0xaf37b0","end":"0xaf37ce"},{"start":"0xaf37d0","end":"0xaf3855"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_00af37b0(int param_1)

{
  byte bVar1;
  ulong uVar2;
  uint uVar3;
  
  if ((ulong)_DAT_03cf7e40 != 0) {
    uVar2 = 0;
    do {
      if (param_1 == *(int *)(&DAT_03cf7e50 + uVar2 * 0x28)) {
LAB_00af3826:
        if ((int)(uint)uVar2 < 0) {
          return 0x800d0203;
        }
        if (*(char *)((ulong)((uint)uVar2 & 0x7fffffff) * 0x28 + 0x3cf7e5a) != '\0') {
                    /* WARNING: Bad instruction - Truncating control flow here */
          halt_baddata();
        }
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      }
      bVar1 = (&DAT_03cf7e65)[uVar2 * 0x28];
      if ((bVar1 != 0) && (bVar1 != 1)) {
        uVar3 = 1;
        do {
          if (param_1 ==
              (uVar3 << ((byte)(&DAT_03cf7e66)[uVar2 * 0x28] & 0x1f)) +
              *(int *)(&DAT_03cf7e50 + uVar2 * 0x28)) goto LAB_00af3826;
          uVar3 = uVar3 + 1;
        } while (bVar1 != uVar3);
      }
      uVar2 = uVar2 + 1;
    } while (uVar2 != _DAT_03cf7e40);
  }
  return 0x800d0203;
}



/* ===== sub_00af3860 | RVA 0xaf3860 | file +0x3820 | ev_7661d2326682bfe65fe9bb8232097bd6a6bf2f45cc8e37a21ca28902d833677f =====
 * Body: [{"start":"0xaf3860","end":"0xaf38d0"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_00af3860(uint param_1)

{
  if ((_DAT_03d0be78 != 0) &&
     (param_1 !=
      ((uint)DAT_03d0be77 |
      (uint)DAT_03d0be80 << 8 | (uint)DAT_03d0be7f << 0x10 | (uint)DAT_03d0be7e << 0x18))) {
    DAT_03d0be77 = (byte)param_1;
    _DAT_03cf7c28 = 1;
    DAT_03d0be7e = (byte)(param_1 >> 0x18);
    DAT_03d0be7f = (byte)(param_1 >> 0x10);
    DAT_03d0be80 = (byte)(param_1 >> 8);
  }
  return;
}



/* ===== sub_00af38e0 | RVA 0xaf38e0 | file +0x38a0 | ev_f000e4da1783eb8e65afddd7496ee41ff0d2333ef9c0a17e553125908802b531 =====
 * Body: [{"start":"0xaf38e0","end":"0xaf403f"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_00af38e0(undefined8 param_1,int param_2)

{
  ulong uVar1;
  char cVar2;
  int iVar3;
  uint uVar4;
  long lVar5;
  ulong uVar6;
  ulong uVar7;
  long lVar8;
  undefined4 uVar9;
  long *in_GS_OFFSET;
  char local_40;
  undefined7 uStack_3f;
  undefined1 local_38;
  undefined8 local_30;
  
  local_30 = _DAT_0391c310;
  if (param_2 == 2) {
    func_0x004c6560();
    func_0x006aa5e0();
    if (_DAT_03d0e778 != 0) {
      lVar8 = func_0x0073e2e0(0x127812a);
      if (lVar8 != 0) {
        func_0x0073e080(lVar8,_DAT_03d0e778);
      }
      _DAT_03d0e778 = 0;
    }
    if (_DAT_03d0e788 != 0) {
      lVar8 = func_0x0073e2e0(0x1294465);
      if (lVar8 != 0) {
        func_0x0073e080(lVar8,_DAT_03d0e788);
      }
      _DAT_03d0e788 = 0;
    }
    if (_DAT_03d0e780 != 0) {
      lVar8 = func_0x0073e2e0(0x12f0eb4);
      if (lVar8 != 0) {
        func_0x0073e080(lVar8,_DAT_03d0e780);
      }
      _DAT_03d0e780 = 0;
    }
    if (_DAT_03d0e770 != 0) {
      lVar8 = func_0x0073e2e0(0x127ff5b);
      if (lVar8 != 0) {
        func_0x0073e080(lVar8,_DAT_03d0e770);
      }
      _DAT_03d0e770 = 0;
    }
  }
  else if (param_2 == 1) {
    func_0x0056a280(4);
    func_0x0056a280(3);
    func_0x0056a280(2);
    func_0x0056a280(1);
    func_0x0056a280(0);
    func_0x00abf460();
  }
  else if (param_2 == 0) {
    _DAT_03d0e770 = func_0x0073dd40(0,0x127ff5b,0x26adc0,0x128823f,0x28ce120,0);
    uVar4 = 0x800d0213;
    if ((_DAT_03d0e770 != 0) &&
       (_DAT_03d0e780 = func_0x0073dd40(0,0x12f0eb4,0x2649d8,0x1342a54,0x28ce130,19999),
       _DAT_03d0e780 != 0)) {
      uVar9 = 1;
      _DAT_03d0e788 = func_0x0073dd40(0,0x1294465,0x2649e0,0x12d04b4,0,1);
      if (_DAT_03d0e788 != 0) {
        func_0x00258ff0(0x3cf7b90,0x2a8);
        _DAT_03cf7bb0 = 0x200000000;
        _DAT_03cf7bb8 = 2;
        _DAT_03cf7bc0 = 0;
        _DAT_03cf7bc8 = 0;
        _DAT_03cf7bd0 = 0;
        _DAT_03cf7bd8 = 0;
        _DAT_03cf7be0 = 0;
        _DAT_03cf7be8 = 0;
        _DAT_03cf7bf8 = 0;
        _DAT_03cf7bf0 = 0;
        _DAT_03cf7c00 = 0;
        _DAT_03cf7c08 = 0;
        _DAT_03cf7c10 = 0;
        _DAT_03cf7c18 = 0;
        _DAT_03cf7c20 = 0;
        _DAT_03cf7c28 = 0;
        _DAT_03cf7c64 = 0x100000000;
        _DAT_03cf7df0 = 0;
        _DAT_03cf7df8 = 0;
        _DAT_03cf7e00 = 0;
        _DAT_03cf7e08 = 0;
        _DAT_03cf7e2c = 0;
        _DAT_03cf7e34 = 0;
        _DAT_03cf7c60 = 0;
        func_0x00258ff0(0x3cf7e38,0x14028);
        func_0x00258ff0(0x3d0ca60,0x1d0c);
        func_0x00258ff0(0x3d0be60,0xc00);
        _DAT_03cf7e04 = 0;
        iVar3 = func_0x005a4c90();
        _DAT_03cf7bc0 = (ulong)CONCAT14(iVar3 == 1,_DAT_03cf7bc0);
        iVar3 = func_0x005a4de0();
        _DAT_03cf7bc8 = CONCAT44(_DAT_03cf7bcc,(uint)(iVar3 == 1));
        iVar3 = func_0x005a4d00();
        _DAT_03cf7be0 = CONCAT44(_DAT_03cf7be4,(uint)(iVar3 == 1));
        iVar3 = func_0x005a53f0();
        _DAT_03cf7be0 = (ulong)CONCAT14(iVar3 == 1,_DAT_03cf7be0);
        iVar3 = func_0x005a5460();
        _DAT_03cf7be8 = CONCAT44(_DAT_03cf7bec,(uint)(iVar3 == 1));
        iVar3 = func_0x005a4d70();
        _DAT_03cf7be8 = (ulong)CONCAT14(iVar3 == 1,_DAT_03cf7be8);
        iVar3 = func_0x005a4f70();
        _DAT_03cf7bd0 = (ulong)CONCAT14(iVar3 == 1,_DAT_03cf7bd0);
        iVar3 = func_0x00b07940();
        if (((iVar3 == 0) && (iVar3 = func_0x00b07960(), iVar3 == 0)) &&
           ((iVar3 = func_0x00b07920(), iVar3 == 0 || (iVar3 = func_0x00acc9a0(0x6d), iVar3 == 0))))
        {
          uVar9 = 0;
        }
        _DAT_03cf7bf0 = CONCAT44(DAT_03cf7bf0_4,uVar9);
        _DAT_03d0e76c = 0;
        iVar3 = func_0x006da890();
        if (iVar3 == 0) {
          _DAT_03d0e76c = _DAT_03d0e76c | 2;
        }
        func_0x004c5c50();
        _DAT_03d0be50 = func_0x00c08b50(0xa00,0x28cdfe0,0x101);
        if ((_DAT_03d0be50 != 0) &&
           (_DAT_03d0be58 = func_0x00c08b50(0x64000,0x28cdfe0,0x101), _DAT_03d0be58 != 0)) {
          func_0x004c7dd0(0x3cf7ba8,0x12f968b,0,4);
          _DAT_03cf7c00 = _DAT_03cf7c00 | 1;
          func_0x006aa570();
          if ((DAT_01a5c158 != '\0') && (cVar2 = func_0x006da0f0(), cVar2 != '\x01')) {
            _DAT_03cf7bf8 = CONCAT44(1,_DAT_03cf7bf8);
            _DAT_03cf7bc0 = CONCAT44(_DAT_03cf7bc4,1);
          }
        }
        if (*in_GS_OFFSET == 0) {
          lVar8 = 0x12bd3c0;
        }
        else {
          lVar5 = *(long *)(*in_GS_OFFSET + 8);
          if (lVar5 == 0) {
            lVar8 = 0x13a3af8;
          }
          else {
            lVar5 = lVar5 + 0x5e4;
            lVar8 = 0x138e50a;
            if (lVar5 != 0) {
              lVar8 = lVar5;
            }
          }
        }
        uVar6 = func_0x00444eb0(lVar8,9);
        if (uVar6 < 9) {
          func_0x00984440(&local_40,lVar8,9);
        }
        else {
          func_0x002590b0(&local_40,lVar8,8);
        }
        local_38 = 0;
        uVar6 = 0;
        if (local_40 == '\0') {
          uVar7 = 0;
        }
        else {
          iVar3 = 1;
          uVar7 = 0;
          do {
            uVar1 = uVar6 & 0x3f;
            uVar6 = (ulong)((int)uVar6 + 8);
            uVar7 = uVar7 | 0xffL << uVar1 & 0x2004112419990816U;
            lVar8 = (long)iVar3;
            iVar3 = iVar3 + 1;
          } while ((&local_40)[lVar8] != '\0');
        }
        func_0x0025d410(0x134ffde,0x3e98,uVar7 ^ CONCAT71(uStack_3f,local_40),0x211d1ae3,0);
        uVar4 = func_0x00abf320();
        if (uVar4 == 0) {
          func_0x004c6440();
          uVar4 = func_0x0056a1c0(0);
          if (uVar4 == 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
            halt_baddata();
          }
        }
      }
    }
    if (_DAT_03cf7c04 != 0) {
      _DAT_03cf7c00 = CONCAT44(uVar4,_DAT_03cf7c00);
      if ((uVar4 & 0xffff0000) == 0x800d0000) {
        _DAT_03cf7c00 = CONCAT44(uVar4,_DAT_03cf7c00) | 0x800d800000000000;
      }
    }
    if (*in_GS_OFFSET == 0) {
      lVar8 = 0x12bd3c0;
    }
    else {
      lVar5 = *(long *)(*in_GS_OFFSET + 8);
      if (lVar5 == 0) {
        lVar8 = 0x13a3af8;
      }
      else {
        lVar5 = lVar5 + 0x5e4;
        lVar8 = 0x138e50a;
        if (lVar5 != 0) {
          lVar8 = lVar5;
        }
      }
    }
    uVar6 = func_0x00444eb0(lVar8,9);
    if (uVar6 < 9) {
      func_0x00984440(&local_40,lVar8,9);
    }
    else {
      func_0x002590b0(&local_40,lVar8,8);
    }
    if (local_40 == '\0') {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  if (*in_GS_OFFSET == 0) {
    lVar8 = 0x12bd3c0;
  }
  else {
    lVar5 = *(long *)(*in_GS_OFFSET + 8);
    if (lVar5 == 0) {
      lVar8 = 0x13a3af8;
    }
    else {
      lVar5 = lVar5 + 0x5e4;
      lVar8 = 0x138e50a;
      if (lVar5 != 0) {
        lVar8 = lVar5;
      }
    }
  }
  uVar6 = func_0x00444eb0(lVar8,9);
  if (uVar6 < 9) {
    func_0x00984440(&local_40,lVar8,9);
  }
  else {
    func_0x002590b0(&local_40,lVar8,8);
  }
  local_38 = 0;
  if (local_40 != '\0') {
    iVar3 = 1;
    do {
      lVar8 = (long)iVar3;
      iVar3 = iVar3 + 1;
    } while ((&local_40)[lVar8] != '\0');
  }
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


