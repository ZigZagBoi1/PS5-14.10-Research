/* REA 6.7.0 / Ghidra 12.1.4 recovered pseudocode, not original or buildable C.
 * Input: deep_622.bin, SHA256 aa1748307e2ed3e489b43664631fbf30aa9178bc2ac5668580225337cb0db258
 * File offset zero maps to kernel RVA 0x7dcd40; runtime VA = 0xffffffff8a9c0000 + RVA.
 * External bodies/types/data missing from this raw window remain unknown.
 * Function names are analyst seeds or Ghidra-generated; instruction truth is in .rea.asm.
 */

/* ===== sys_622 | RVA 0x7dcd40 | file +0x0 | ev_d579e5771932cd7b6c81661f0e76081f3f17507ec8f57834184b681c546ba871 =====
 * Body: [{"start":"0x7dcd40","end":"0x7dce9a"},{"start":"0x7dceca","end":"0x7dcee9"},{"start":"0x7dcf16","end":"0x7dcf90"},{"start":"0x7dcfc0","end":"0x7dcfdb"},{"start":"0x7dd00b","end":"0x7dd0a1"},{"start":"0x7ddb42","end":"0x7ddba2"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong sys_622(long param_1,uint *param_2)

{
  uint uVar1;
  uint uVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  code *pcVar5;
  uint uVar6;
  int iVar7;
  undefined4 uVar8;
  ulong uVar9;
  undefined8 *in_GS_OFFSET;
  undefined4 local_7c;
  undefined1 local_78 [64];
  long local_38;
  
  local_38 = _DAT_0391c310;
  uVar3 = *(undefined8 *)(param_2 + 4);
  uVar6 = *param_2;
  uVar2 = param_2[2];
  uVar4 = *(undefined8 *)(param_2 + 6);
  uVar9 = *(ulong *)(param_2 + 8);
  local_7c = 0;
  uVar8 = 0x800e0001;
  if (uVar9 < 0x41) {
    if ((int)uVar6 < 0x271) {
      uVar1 = uVar6 - 0x100;
      if (uVar1 < 0x34) {
        if ((0xf8fff000000d5U >> ((ulong)uVar1 & 0x3f) & 1) == 0) {
          if (((0x600000000000U >> ((ulong)uVar1 & 0x3f) & 1) != 0) &&
             (iVar7 = func_0x00609110(*(undefined8 *)(param_1 + 0x140)), iVar7 != 1)) {
            iVar7 = func_0x006090d0(*(undefined8 *)(param_1 + 0x140));
            goto LAB_007dce3f;
          }
        }
        else {
          iVar7 = func_0x00609110(*(undefined8 *)(param_1 + 0x140));
          if (iVar7 != 1) {
            iVar7 = func_0x00609040(*(undefined8 *)(param_1 + 0x140));
LAB_007dce3f:
            uVar8 = 0x8002004e;
            if (iVar7 != 1) goto LAB_007dcd8e;
          }
        }
      }
    }
    else if ((((uVar6 == 0x271) || (uVar6 == 0x372)) || (uVar6 == 0x473)) &&
            ((iVar7 = func_0x00609110(*(undefined8 *)(param_1 + 0x140)), iVar7 != 1 &&
             (iVar7 = func_0x006090d0(*(undefined8 *)(param_1 + 0x140)), iVar7 != 1)))) {
      iVar7 = func_0x0026d0a0(*(undefined8 *)(param_1 + 0x140));
      goto LAB_007dce3f;
    }
    func_0x00258ff0(local_78,0x40);
    uVar8 = 0xffffffff;
    if ((int)uVar6 < 0x302) {
      if (uVar6 < 0x134) {
                    /* WARNING: Could not emulate address calculation at 0x007dcee1 */
                    /* WARNING: Treating indirect jump as call */
        uVar9 = (*(code *)((long)*(int *)((ulong)uVar6 * 4 + 0x178057c) + 0x178057c))();
        return uVar9;
      }
      if (uVar6 - 0x201 < 0x71) {
                    /* WARNING: Could not emulate address calculation at 0x007dcf88 */
                    /* WARNING: Treating indirect jump as call */
        uVar9 = (*(code *)((long)*(int *)((ulong)(uVar6 - 0x201) * 4 + 0x1780a4c) + 0x1780a4c))();
        return uVar9;
      }
    }
    else if ((int)uVar6 < 0x400) {
      if (uVar6 - 0x302 < 0x1f) {
                    /* WARNING: Could not emulate address calculation at 0x007dcfd3 */
                    /* WARNING: Treating indirect jump as call */
        uVar9 = (*(code *)((long)*(int *)((ulong)(uVar6 - 0x302) * 4 + 0x1780c10) + 0x1780c10))();
        return uVar9;
      }
      if (uVar6 == 0x372) {
        uVar6 = sub_007ddbb0(uVar4,local_78,uVar9);
        if (uVar6 != 0) goto LAB_007dcdb7;
        uVar6 = func_0x00c02050(param_1,uVar2,local_78,&local_7c);
        goto LAB_007ddb42;
      }
    }
    else {
      if (uVar6 - 0x400 < 0x94) {
                    /* WARNING: Could not emulate address calculation at 0x007dce92 */
                    /* WARNING: Treating indirect jump as call */
        uVar9 = (*(code *)((long)*(int *)((ulong)(uVar6 - 0x400) * 4 + 0x1780c8c) + 0x1780c8c))();
        return uVar9;
      }
      if (uVar6 == 0x520) {
        uVar6 = func_0x0029a570(param_1,uVar2,&local_7c);
LAB_007ddb42:
        uVar8 = local_7c;
        if (uVar6 != 0) goto LAB_007dcdb7;
      }
    }
  }
LAB_007dcd8e:
  local_7c = uVar8;
  func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
  uVar6 = func_0x002591d0(&local_7c,uVar3,4);
LAB_007dcdb7:
  uVar9 = 4;
  if (uVar6 != 4) {
    if (*(int *)(param_1 + 0x398) != 0) {
      func_0x007f1950();
      func_0x007f20c0(0x7ddb56,(long)*(int *)(param_1 + 0x9c),(long)(int)uVar6,
                      (long)*(int *)(param_1 + 0x398));
      func_0x00c9aa10(0x30,0x12998d8,*(undefined4 *)(param_1 + 0x9c),uVar6,
                      *(undefined4 *)(param_1 + 0x398));
                    /* WARNING: Does not return */
      pcVar5 = (code *)invalidInstructionException();
      (*pcVar5)();
    }
    uVar9 = (ulong)uVar6;
  }
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar5 = (code *)invalidInstructionException();
    (*pcVar5)();
  }
  return uVar9;
}



/* ===== sub_007ddbb0 | RVA 0x7ddbb0 | file +0xe70 | ev_8b422f7086f2fe45d6fc8609dc4ddb36c764decc484b576395eef432d117a510 =====
 * Body: [{"start":"0x7ddbb0","end":"0x7ddbf1"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */

void sub_007ddbb0(void)

{
  undefined8 *in_GS_OFFSET;
  
  func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* ===== sub_007ddc00 | RVA 0x7ddc00 | file +0xec0 | ev_4a3c6576f3cd636368ea0f71d69f33a4dcbbd7f5b11f2390d739dcb11f8fdc3c =====
 * Body: [{"start":"0x7ddc00","end":"0x7de187"},{"start":"0x7de190","end":"0x7de2e1"},{"start":"0x7de2f0","end":"0x7de327"},{"start":"0x7de330","end":"0x7de48a"},{"start":"0x7de490","end":"0x7de581"},{"start":"0x7de590","end":"0x7df176"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_007ddc00(long param_1,uint param_2,long *param_3,undefined4 *param_4)

{
  long lVar1;
  undefined4 uVar2;
  long lVar3;
  ulong uVar4;
  ulong uVar5;
  long lVar6;
  undefined8 *puVar7;
  long lVar8;
  code *pcVar9;
  long lVar10;
  int iVar11;
  uint uVar12;
  int iVar13;
  long lVar14;
  undefined8 uVar15;
  int iVar16;
  long lVar17;
  ulong uVar18;
  long lVar19;
  undefined8 uVar20;
  undefined8 uVar21;
  ulong uVar22;
  ulong uVar23;
  long lVar24;
  uint uVar25;
  long *in_GS_OFFSET;
  uint *local_2c0;
  uint local_284;
  long local_250;
  uint local_248;
  uint local_244;
  undefined8 local_240;
  ulong local_238;
  undefined8 local_230;
  uint local_224;
  long local_220;
  ulong local_218;
  ulong local_210;
  long local_208;
  undefined8 local_200;
  long local_1f8;
  long local_1f0;
  long local_1e8;
  long local_1e0;
  undefined1 local_1d8;
  undefined7 uStack_1d7;
  undefined8 local_1d0;
  undefined8 local_1c8;
  undefined8 local_1c0;
  long local_1b8;
  undefined8 local_1b0;
  undefined8 local_1a8;
  long local_188;
  long local_180;
  long local_38;
  
  uVar22 = (ulong)param_2;
  local_38 = _DAT_0391c310;
  local_208 = 0;
  local_210 = 0;
  local_218 = 0x2010000;
  uVar18 = param_3[1];
  lVar3 = *param_3;
  uVar4 = param_3[2];
  uVar5 = param_3[3];
  local_224 = 0;
  func_0x00258ff0(&local_248,0x20);
  local_248 = 0xfff;
  local_240 = 0xffffffffffffffff;
  local_244 = param_2;
  iVar11 = func_0x00c02220(uVar22,&local_1d8);
  if (iVar11 != 0) {
    local_1d8 = 0;
  }
  func_0x00bff970(param_1,0x970a,uVar22,0xffffffff,0xffffffff,(int)param_3[1],0,*param_3,&local_1d8)
  ;
  iVar11 = func_0x00b078d0();
  pcVar9 = _DAT_03bf6920;
  if ((iVar11 != 0) && (_DAT_02cb0000 != 0)) {
    if (1 < (-(long)_DAT_03bf6920 + 0x2693e8U >> 3 | -(long)_DAT_03bf6920 << 0x3d)) {
      func_0x0044f8c0(0x253db50,_DAT_03bf6920);
    }
    (*pcVar9)(8,2,0x970a,CONCAT71(uStack_1d7,local_1d8),local_1d0,local_1c8,local_1c0,
              (ulong)param_2 | 0xffffffff0000,(int)param_3[1],*param_3);
  }
  if (uVar4 == 0 || lVar3 == 0) {
    uVar18 = 0x2010000;
    local_208 = 0xa0020320;
    local_210 = 0;
    iVar11 = 0x16;
  }
  else if (uVar18 == 0) {
    uVar18 = 0x2010001;
    local_208 = 0xa0020320;
    local_218 = CONCAT44(local_218._4_4_,0x2010001);
    local_210 = 0;
    iVar11 = 0xc;
  }
  else if (uVar5 == 0) {
    local_2c0 = (uint *)0x0;
LAB_007dde7d:
    func_0x00258ff0(&local_248,0x20);
    local_248 = 0xfff;
    local_240 = 0xffffffffffffffff;
    local_244 = param_2;
    iVar13 = func_0x0060ec10(param_2,0x8001,&local_250,0x3ffffff);
    if (iVar13 == 0) {
      do {
        lVar10 = local_250;
        lVar8 = local_250 + 0x28;
        func_0x00c4bb20(lVar8,0,0,0);
        lVar14 = *(long *)(lVar10 + 0x60);
        if (lVar14 == 0) {
          uVar20 = *(undefined8 *)(lVar10 + 0x98);
          func_0x00c4c4b0(lVar8,0,0);
        }
        else {
          iVar13 = 0;
          local_284 = (uint)local_218;
          uVar23 = local_210;
          lVar24 = local_208;
          do {
            func_0x00acf2b0(&local_188);
            lVar17 = local_180 / 1000 + local_188 * 1000000;
            func_0x00c4bb20(lVar14,0,0,0);
            lVar6 = *(long *)(lVar14 + 0x460);
            if ((lVar6 != 0) && (*(int *)(lVar6 + 4) == 0)) {
              uVar12 = *(uint *)(lVar14 + 0x58);
              if (uVar12 == 0) {
                iVar11 = 0;
              }
              else {
                iVar16 = *(int *)(param_1 + 0x9c);
                iVar11 = 0;
                uVar25 = 0;
                do {
                  if (*(int *)(lVar14 + 0x47c + (long)(int)uVar25 * 0x18) == iVar16) {
                    lVar19 = lVar14 + 0x478 + (long)(int)uVar25 * 0x18;
                    lVar24 = lVar17 - *(long *)(lVar19 + 8);
                    func_0x00bff970(param_1,0x1715,param_2,0xffffffff,*(undefined4 *)(lVar6 + 8),
                                    *(undefined4 *)(lVar19 + 0x10),uVar25,lVar24,&local_1d8);
                    iVar11 = func_0x00b078d0();
                    pcVar9 = _DAT_03bf6920;
                    if ((iVar11 != 0) && (_DAT_02cb0000 != 0)) {
                      if (1 < (-(long)_DAT_03bf6920 + 0x2693e8U >> 3 | -(long)_DAT_03bf6920 << 0x3d)
                         ) {
                        func_0x0044f8c0(0x253dbb0,_DAT_03bf6920);
                      }
                      (*pcVar9)(8,2,0x1715,CONCAT71(uStack_1d7,local_1d8),local_1d0,local_1c8,
                                local_1c0,
                                (((ulong)*(uint *)(lVar6 + 8) & 0xffff) << 0x20) +
                                (ulong)(param_2 | 0xffff0000),
                                CONCAT44(uVar25,*(undefined4 *)(lVar19 + 0x10)),lVar24);
                    }
                    local_284 = local_284 | 6;
                    iVar11 = 0x10;
                    lVar24 = 0xa0020320;
                    iVar16 = *(int *)(param_1 + 0x9c);
                    uVar12 = *(uint *)(lVar14 + 0x58);
                    uVar23 = CONCAT44(*(undefined4 *)(lVar19 + 4),iVar16);
                  }
                  uVar25 = uVar25 + 1;
                } while (uVar25 < uVar12);
              }
              uVar12 = *(uint *)(lVar14 + 0x70);
              if (uVar12 != 0) {
                iVar16 = *(int *)(param_1 + 0x9c);
                uVar25 = 0;
                do {
                  lVar19 = (long)(int)uVar25;
                  if (*(int *)(lVar14 + 0x618 + lVar19 * 0x28) == iVar16) {
                    lVar1 = lVar14 + 0x5f8 + lVar19 * 0x28;
                    lVar24 = lVar17 - *(long *)(lVar14 + 0x480 + lVar19 * 0x18);
                    func_0x00bff970(param_1,0x1716,param_2,0xffffffff,*(undefined4 *)(lVar6 + 8),
                                    *(undefined4 *)(lVar1 + 0x10),lVar19,lVar24,&local_1d8);
                    iVar11 = func_0x00b078d0();
                    pcVar9 = _DAT_03bf6920;
                    if ((iVar11 != 0) && (_DAT_02cb0000 != 0)) {
                      if (1 < (-(long)_DAT_03bf6920 + 0x2693e8U >> 3 | -(long)_DAT_03bf6920 << 0x3d)
                         ) {
                        func_0x0044f8c0(0x253dbd0,_DAT_03bf6920);
                      }
                      (*pcVar9)(8,2,0x1716,CONCAT71(uStack_1d7,local_1d8),local_1d0,local_1c8,
                                local_1c0,
                                (((ulong)*(uint *)(lVar6 + 8) & 0xffff) << 0x20) +
                                (ulong)(param_2 | 0xffff0000),
                                CONCAT44(uVar25,*(undefined4 *)(lVar1 + 0x10)),lVar24);
                    }
                    local_284 = local_284 | 7;
                    iVar11 = 0x10;
                    lVar24 = 0xa0020320;
                    iVar16 = *(int *)(param_1 + 0x9c);
                    uVar12 = *(uint *)(lVar14 + 0x70);
                    uVar23 = CONCAT44(*(undefined4 *)(lVar1 + 0x20),iVar16);
                  }
                  uVar25 = uVar25 + 1;
                } while (uVar25 < uVar12);
              }
              if (iVar11 != 0) {
                iVar13 = iVar11;
              }
            }
            lVar6 = *(long *)(lVar14 + 0x198);
            if (((lVar6 != 0) && (*(int *)(lVar6 + 4) == 0)) &&
               (*(int *)(lVar14 + 0x4c) == *(int *)(param_1 + 0x9c))) {
              lVar17 = lVar17 - *(long *)(lVar14 + 0x50);
              lVar24 = (ulong)(*(int *)(lVar14 + 0x48) != 1) + 0x1713;
              func_0x00bff970(param_1,lVar24,param_2,*(undefined4 *)(lVar6 + 8),0xffffffff,
                              *(int *)(lVar14 + 0x48),0,lVar17,&local_1d8);
              iVar11 = func_0x00b078d0();
              pcVar9 = _DAT_03bf6920;
              if ((iVar11 != 0) && (_DAT_02cb0000 != 0)) {
                if (1 < (-(long)_DAT_03bf6920 + 0x2693e8U >> 3 | -(long)_DAT_03bf6920 << 0x3d)) {
                  func_0x0044f8c0(0x253dbf0,_DAT_03bf6920);
                }
                (*pcVar9)(8,2,lVar24,CONCAT71(uStack_1d7,local_1d8),local_1d0,local_1c8,local_1c0,
                          (ulong)(uint)(*(int *)(lVar6 + 8) << 0x10) |
                          uVar22 & 0xffff | 0xffff00000000,*(undefined4 *)(lVar14 + 0x48),lVar17);
              }
              local_284 = local_284 | 8;
              uVar23 = CONCAT44(*(undefined4 *)(lVar14 + 0x4c),*(undefined4 *)(param_1 + 0x9c));
              func_0x0025d410(0x1289a38,0x30a);
              func_0x0025d410(0x12ebe26,*(undefined4 *)(param_1 + 0x9c),param_1 + 0x294,
                              *(undefined4 *)(lVar6 + 8),*(undefined8 *)(lVar6 + 0x18),
                              *(undefined4 *)(lVar14 + 0x48));
              lVar24 = 0xa0020320;
              iVar13 = 0x10;
            }
            func_0x00c4c4b0(lVar14,0,0);
            lVar14 = *(long *)(lVar14 + 0x28);
          } while (lVar14 != 0);
          local_218 = CONCAT44(local_218._4_4_,local_284);
          uVar20 = *(undefined8 *)(lVar10 + 0x98);
          local_210 = uVar23;
          local_208 = lVar24;
          func_0x00c4c4b0(lVar8,0,0);
          if (iVar13 != 0) {
            func_0x0060ecd0(param_2,0x8001,0);
            goto LAB_007ded6f;
          }
        }
        if ((uVar18 < *(long *)(local_250 + 0x88) + 0x100U) ||
           (uVar18 < *(long *)(local_250 + 0x80) + 0x100U)) {
          local_208 = 0xa0020320;
          local_218 = local_218 | 9;
          local_210 = uVar18;
          func_0x0060ecd0(param_2,0x8001,0);
          iVar13 = 0xc;
          goto LAB_007ded6f;
        }
        if ((local_2c0 == (uint *)0x0) || (local_224 != 0)) {
          iVar13 = func_0x00b670f0(local_250,local_2c0,&local_220);
        }
        else {
          iVar13 = func_0x00b67a40(local_250,&local_220);
        }
        if (iVar13 != 0) {
          local_208 = 0;
          local_218 = local_218 | 10;
          local_210 = 0;
          goto LAB_007ded6f;
        }
        uVar12 = func_0x0060ecd0(param_2,0x8001,0);
        lVar8 = local_220;
        if (1 < uVar12) {
          func_0x007f1950();
          func_0x007f18a0(0x7df0d6,(long)(int)uVar12);
          uVar20 = 0x132a9a7;
          uVar21 = 4;
          goto LAB_007df0fa;
        }
        iVar11 = *(int *)(local_220 + 0x10);
        if (iVar11 < 0x30) {
          if (iVar11 != 1) {
            if (iVar11 != 0x10) {
              if (iVar11 == 0x20) goto LAB_007de712;
              goto LAB_007df103;
            }
            iVar13 = sub_007e1080(param_1,local_220,lVar3,uVar18,uVar4,param_2,uVar20,&local_1b8,
                                  &local_248,&local_218);
            goto LAB_007de749;
          }
          local_1b0 = 0xffffffff000000b0;
          local_1b8 = 0;
          local_1a8 = uVar20;
          func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
          iVar13 = func_0x002591d0(&local_1b8,uVar4,0x18);
          if (iVar13 == 0) {
            local_248 = 0x1710;
            local_240 = 0xffffffffffffffff;
            local_238 = 0;
            local_230 = 0;
            func_0x00b670a0(lVar8);
            iVar13 = 0;
            goto LAB_007ded6f;
          }
          func_0x00b670a0(lVar8);
          local_208 = 0xa0020320;
          local_218 = local_218 | 0x12;
          local_210 = uVar4;
        }
        else if (iVar11 < 0x50) {
          if (iVar11 == 0x30) goto LAB_007de712;
          if (iVar11 != 0x40) goto LAB_007df103;
          iVar11 = *(int *)(local_220 + 0x18);
          iVar16 = *(int *)(local_220 + 0x1c);
          iVar13 = func_0x0060ec10(iVar11,0x8004,&local_1f0,0x7ffffff);
          if (iVar13 == 0) {
            local_200 = 0;
            func_0x00258ff0(&local_188,0x150);
            func_0x00c4bb20(_DAT_0253daa8,0,0,0);
            iVar13 = sub_007e1cd0(param_1,param_2,iVar11,iVar16,lVar3,&local_1f8,&local_200,
                                  &local_188);
            uVar21 = local_200;
            if (iVar13 == 0) {
              func_0x00c4c4b0(_DAT_0253daa8,0,0);
              func_0x0060ecd0(iVar11,0x8004,0);
              goto LAB_007de6d9;
            }
            lVar14 = func_0x0039f100(local_200);
            if (uVar18 < lVar14 - 0x18U) {
              *(undefined8 *)(local_1f8 + 0x70) = uVar21;
              *(undefined8 *)(local_1f8 + 0x58) = 0;
              *(undefined4 *)(local_1f8 + 0x4c) = 0xffffffff;
              func_0x00c4c4b0(_DAT_0253daa8,0,0);
              func_0x0060ecd0(local_1b0._4_4_,0x8004,0);
              iVar11 = func_0x00b67bb0(param_2,lVar8,0x3ffffff);
              if (iVar11 != 0) {
                func_0x00b670a0(lVar8);
              }
              iVar13 = 0xc;
              local_208 = 0xa0020320;
              local_218 = local_218 | 0x13;
              local_210 = lVar14 - 0x18U;
            }
            else {
              func_0x00c4c4b0(_DAT_0253daa8,0,0);
              uVar15 = func_0x0039f0f0(uVar21);
              func_0x0039f310(&local_1b8,uVar15,0,0x30);
              local_1a8 = uVar20;
              func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
              iVar13 = func_0x002591d0(&local_1b8,uVar4,0x18);
              if (iVar13 == 0) {
                func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
                iVar13 = func_0x002591d0(&local_188,lVar3,0x150);
                if (iVar13 == 0) {
                  lVar14 = local_1b8 + -0x150;
                  uVar20 = func_0x0039f0f0(uVar21);
                  iVar13 = func_0x0039f4e0(lVar3 + 0x150,uVar20,0x30,lVar14);
                  if (iVar13 == 0) {
                    func_0x00c4bb20(*(undefined8 *)(local_1f0 + 0x28),0,0,0);
                    func_0x00acf2b0(&local_1e8);
                    lVar14 = *(long *)(local_1f0 + 0x28);
                    uVar2 = *(undefined4 *)(param_1 + 0x9c);
                    *(uint *)(lVar14 + 0x48) = (uint)local_1b0;
                    *(undefined4 *)(lVar14 + 0x4c) = uVar2;
                    *(long *)(lVar14 + 0x50) = local_1e0 / 1000 + local_1e8 * 1000000;
                    func_0x00c4c4b0(*(undefined8 *)(local_1f0 + 0x28),0,0);
                    func_0x0060ecd0(local_1b0._4_4_,0x8004,0);
                    uVar20 = func_0x0039f0f0(uVar21);
                    func_0x0039efc0(uVar21,uVar20);
                    func_0x0039ed50(uVar21);
                    func_0x0043c0c0(_DAT_0253dac0,uVar21,0);
                    func_0x00b670a0(lVar8);
                    iVar13 = 0;
                    local_248 = 0x170b;
                    local_240 = CONCAT44(iVar11,0xffffffff);
                    local_238 = (ulong)*(uint *)(local_1f0 + 0x10);
                    local_230 = 0;
                    goto LAB_007de749;
                  }
                }
              }
              func_0x00c4bb20(_DAT_0253daa8,0,0,0);
              for (puVar7 = *(undefined8 **)(_DAT_0253daa8 + 0x38); puVar7 != (undefined8 *)0x0;
                  puVar7 = (undefined8 *)*puVar7) {
                if ((((*(int *)(puVar7 + 3) == iVar11) && (*(int *)((long)puVar7 + 0x1c) == iVar16))
                    && (*(uint *)(puVar7 + 9) == param_2)) &&
                   (*(int *)((long)puVar7 + 0x4c) == *(int *)(param_1 + 0x9c))) {
                  puVar7[0xe] = uVar21;
                  puVar7[0xb] = 0;
                  *(undefined4 *)((long)puVar7 + 0x4c) = 0xffffffff;
                  func_0x00c4c4b0(_DAT_0253daa8,0,0);
                  func_0x0060ecd0(iVar11,0x8004,0);
                  iVar11 = func_0x00b67bb0(param_2,lVar8,0x3ffffff);
                  if (iVar11 != 0) goto LAB_007deadd;
                  goto LAB_007deae5;
                }
              }
              func_0x00c4c4b0(_DAT_0253daa8,0,0);
              func_0x0060ecd0(iVar11,0x8004,0);
LAB_007deadd:
              func_0x00b670a0(lVar8);
LAB_007deae5:
              local_208 = 0xa0020320;
              local_218 = local_218 | 0x14;
              local_210 = uVar4;
            }
          }
          else {
LAB_007de6d9:
            func_0x00b670a0(lVar8);
            iVar13 = -1;
          }
        }
        else {
          if ((iVar11 != 0x50) && (iVar11 != 0x60)) {
LAB_007df103:
            func_0x007f1950();
            func_0x007f18a0(0x7df103,(long)*(int *)(local_220 + 0x10));
            uVar20 = 0x1349e18;
            uVar21 = 8;
            uVar12 = *(uint *)(local_220 + 0x10);
            goto LAB_007df0fa;
          }
LAB_007de712:
          iVar13 = sub_007e14a0(param_1,local_220,lVar3,uVar4,uVar20,&local_1b8,&local_248,
                                &local_218);
        }
LAB_007de749:
        if (-1 < iVar13) goto LAB_007ded6f;
        func_0x00258ff0(&local_248,0x20);
        local_248 = 0xfff;
        local_240 = 0xffffffffffffffff;
        local_244 = param_2;
        iVar13 = func_0x0060ec10(param_2,0x8001,&local_250);
      } while (iVar13 == 0);
      uVar12 = (uint)local_218 | 5;
    }
    else {
      uVar12 = 0x2010005;
    }
    local_208 = 0xa0020320;
    local_218 = CONCAT44(local_218._4_4_,uVar12);
    local_210 = 0;
LAB_007ded6f:
    if (uVar5 != 0) {
LAB_007ded74:
      func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
      iVar11 = func_0x002591d0(&local_224,uVar5,4);
      if (iVar11 != 0) {
        local_208 = 0xa0020320;
        uVar18 = (ulong)((uint)local_218 | 0x15);
        local_218 = local_218 | 0x15;
        local_210 = uVar5;
        goto LAB_007dedec;
      }
    }
    iVar11 = iVar13;
    if (iVar11 == 0) {
      if (local_248 == 0xfff) {
        func_0x007f1950();
        func_0x007f18a0(0x7df137,(long)(int)(uint)local_1b0);
        uVar20 = 0x12cc97a;
        uVar21 = 0xc;
        uVar12 = (uint)local_1b0;
LAB_007df0fa:
        func_0x00c9aa10(uVar21,uVar20,uVar12);
                    /* WARNING: Does not return */
        pcVar9 = (code *)invalidInstructionException();
        (*pcVar9)();
      }
      func_0x00bff970(param_1,local_248 & 0xffff,(ulong)param_2,local_240._4_4_,
                      local_240 & 0xffffffff,local_238 & 0xffffffff,local_238 >> 0x20,local_230,
                      &local_1d8);
      iVar11 = func_0x00b078d0();
      pcVar9 = _DAT_03bf6920;
      if ((iVar11 != 0) && (_DAT_02cb0000 != 0)) {
        if (1 < (-(long)_DAT_03bf6920 + 0x2693e8U >> 3 | -(long)_DAT_03bf6920 << 0x3d)) {
          func_0x0044f8c0(0x253db70,_DAT_03bf6920);
        }
        (*pcVar9)(8,2,(undefined2)local_248,CONCAT71(uStack_1d7,local_1d8),local_1d0,local_1c8,
                  local_1c0,
                  (ulong)param_2 & 0xffff | (ulong)((uint)local_240 & 0xffff) << 0x20 |
                  (ulong)(uint)(local_240._4_4_ << 0x10),local_238,local_230);
      }
      *param_4 = 0;
      iVar11 = 0;
      goto LAB_007deed1;
    }
    uVar18 = local_218 & 0xffffffff;
  }
  else {
    func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
    local_2c0 = &local_224;
    iVar11 = func_0x00259280(uVar5,local_2c0,4);
    if (iVar11 == 0) {
      if ((ulong)local_224 == 0) goto LAB_007dde7d;
      iVar13 = 0x16;
      local_208 = 0xa0020320;
      local_218 = CONCAT44(local_218._4_4_,0x2010004);
      local_210 = (ulong)local_224;
      goto LAB_007ded74;
    }
    uVar18 = 0x2010003;
    local_208 = 0xa0020320;
    local_218 = CONCAT44(local_218._4_4_,0x2010003);
    local_210 = uVar5;
  }
LAB_007dedec:
  uVar4 = local_210;
  func_0x00bff970(param_1,0x1712,(ulong)param_2,local_240._4_4_,local_240 & 0xffffffff,
                  iVar11 + 0x80020000U,uVar18,local_210,&local_1d8);
  iVar13 = func_0x00b078d0();
  pcVar9 = _DAT_03bf6920;
  if ((iVar13 != 0) && (_DAT_02cb0000 != 0)) {
    if (1 < (-(long)_DAT_03bf6920 + 0x2693e8U >> 3 | -(long)_DAT_03bf6920 << 0x3d)) {
      func_0x0044f8c0(0x253db90,_DAT_03bf6920);
    }
    (*pcVar9)(8,2,0x1712,CONCAT71(uStack_1d7,local_1d8),local_1d0,local_1c8,local_1c0,
              (ulong)param_2 & 0xffff | (ulong)((uint)local_240 & 0xffff) << 0x20 |
              (ulong)(uint)(local_240._4_4_ << 0x10),(ulong)(iVar11 + 0x80020000U) | uVar18 << 0x20,
              uVar4);
  }
LAB_007deed1:
  lVar3 = local_208;
  if ((local_208 != 0) &&
     (lVar8 = *in_GS_OFFSET, 0x34fffff < *(uint *)(*(long *)(lVar8 + 8) + 0x5d4))) {
    func_0x0025d410(0x1289a38,0xc2);
    func_0x0025d410(0x126c6a7,*(undefined4 *)(lVar8 + 0x9c),lVar8 + 0x294,lVar3,
                    local_218 & 0xffffffff,local_210);
    func_0x00c9fa20(lVar8,lVar3);
  }
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar9 = (code *)invalidInstructionException();
    (*pcVar9)();
  }
  return iVar11;
}



/* ===== sub_007df180 | RVA 0x7df180 | file +0x2440 | ev_e3c27f680dd13a07763b49875a9e7440b14121beaf537c8a78068a471de9ca1a =====
 * Body: [{"start":"0x7df180","end":"0x7df49e"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_007df180(long param_1,uint param_2,ulong *param_3,undefined4 *param_4)

{
  uint uVar1;
  long lVar2;
  code *pcVar3;
  bool bVar4;
  int iVar5;
  int iVar6;
  ulong uVar7;
  uint uVar8;
  long *in_GS_OFFSET;
  undefined8 local_80;
  undefined4 local_64;
  long local_60;
  undefined1 local_58;
  undefined7 uStack_57;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  local_60 = 0;
  local_58 = 0;
  local_64 = 0xffffffff;
  iVar5 = func_0x0060ec10(param_2,0x8002,&local_60,0x3ffffff);
  if (iVar5 == 0) {
    func_0x00957b70(&local_58,*(undefined8 *)(local_60 + 0x18),0x20);
    iVar5 = 0;
    func_0x00c4bb20(*(undefined8 *)(local_60 + 0x28),0,0,0);
    lVar2 = *(long *)(local_60 + 0x28);
    uVar1 = *(uint *)(lVar2 + 0x20);
    uVar7 = (ulong)uVar1;
    if ((uVar1 & 0x20000) == 0) {
      uVar8 = 0x3020001;
      iVar5 = 3;
    }
    else {
      local_64 = *(undefined4 *)(lVar2 + 0x194);
      uVar7 = 0;
      uVar8 = 0x3020000;
    }
    local_80 = 0;
    func_0x00c4c4b0(lVar2,0,0);
    func_0x0060ecd0(param_2,0x8002,0);
    if ((uVar1 & 0x20000) == 0) {
      bVar4 = true;
    }
    else {
      uVar7 = *param_3;
      iVar6 = 0;
      func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
      iVar5 = func_0x002591d0(&local_64,uVar7,4);
      if (iVar5 == 0) {
        *param_4 = 0;
        goto LAB_007df463;
      }
      uVar7 = *param_3;
      bVar4 = false;
      local_80 = 0xa0020320;
      uVar8 = uVar8 | 2;
    }
  }
  else {
    bVar4 = false;
    func_0x0025d410(0x132f977,0x724);
    func_0x0025d410(0x130ae96,*(undefined4 *)(param_1 + 0x9c),param_2,param_2,iVar5);
    uVar8 = 0x3020000;
    iVar5 = 2;
    uVar7 = 0;
    local_80 = 0xa0020320;
  }
  func_0x00bff970(*in_GS_OFFSET,0x4714,0xffffffff,0xffffffff,param_2,iVar5 + -0x7ffe0000,uVar8,uVar7
                  ,&local_58);
  iVar6 = func_0x00b078d0();
  pcVar3 = _DAT_03bf6920;
  if ((iVar6 != 0) && (_DAT_02cb0000 != 0)) {
    if (1 < (-(long)_DAT_03bf6920 + 0x2693e8U >> 3 | -(long)_DAT_03bf6920 << 0x3d)) {
      func_0x0044f8c0(0x253dc10,_DAT_03bf6920);
    }
    (*pcVar3)(8,2,0x4714,CONCAT71(uStack_57,local_58),local_50,local_48,local_40,
              (ulong)(param_2 & 0xffff) << 0x20 | 0xffffffff,CONCAT44(uVar8,iVar5 + -0x7ffe0000),
              uVar7);
  }
  iVar6 = iVar5;
  if ((!bVar4) && (lVar2 = *in_GS_OFFSET, 0x34fffff < *(uint *)(*(long *)(lVar2 + 8) + 0x5d4))) {
    func_0x0025d410(0x1289a38,0xc2);
    func_0x0025d410(0x126c6a7,*(undefined4 *)(lVar2 + 0x9c),lVar2 + 0x294,local_80,uVar8,uVar7);
    func_0x00c9fa20(lVar2,local_80);
  }
LAB_007df463:
  if (_DAT_0391c310 == local_38) {
    return iVar6;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar3 = (code *)invalidInstructionException();
  (*pcVar3)();
}



/* ===== sub_007df4a0 | RVA 0x7df4a0 | file +0x2760 | ev_dba077f5bfe0366fbfa7b7ac2d25c04b7c756301ede17e25d60ad2b527928b69 =====
 * Body: [{"start":"0x7df4a0","end":"0x7df890"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_007df4a0(ulong param_1,ulong *param_2,undefined4 *param_3)

{
  long lVar1;
  long lVar2;
  code *pcVar3;
  bool bVar4;
  bool bVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  ulong uVar9;
  long *in_GS_OFFSET;
  undefined8 local_78;
  undefined4 local_64;
  long local_60;
  undefined1 local_58;
  undefined7 uStack_57;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  long local_38;
  
  iVar7 = 0x391c310;
  local_38 = _DAT_0391c310;
  local_60 = 0;
  local_58 = 0;
  iVar6 = func_0x0060ec10(param_1,0x8002,&local_60,0x3ffffff);
  if (iVar6 == 0) {
    func_0x00957b70(&local_58,*(undefined8 *)(local_60 + 0x18),0x20);
    iVar6 = 0;
    func_0x00c4bb20(*(undefined8 *)(local_60 + 0x28),0,0,0);
    lVar2 = *(long *)(local_60 + 0x28);
    uVar9 = (ulong)*(uint *)(lVar2 + 0x20);
    if ((*(uint *)(lVar2 + 0x20) & 0x20000) == 0) {
      uVar8 = 0x4630002;
      iVar6 = 3;
      bVar4 = false;
    }
    else {
      iVar7 = *(int *)(lVar2 + 0x194);
      if (iVar7 == -1) {
        uVar8 = 0x4630001;
        iVar7 = -1;
        iVar6 = 3;
        uVar9 = 0;
        bVar4 = false;
      }
      else {
        uVar8 = 0x4630000;
        bVar4 = true;
        uVar9 = 0;
      }
    }
    local_78 = 0;
    func_0x00c4c4b0(lVar2,0,0);
    func_0x0060ecd0(param_1 & 0xffffffff,0x8002,0);
    bVar5 = true;
    if (bVar4) {
      local_64 = 0;
      func_0x00c4b350(0x3589e60,0,0,0);
      for (lVar2 = *(long *)(_DAT_03589e18 + ((long)iVar7 & _DAT_03589e10) * 8); lVar2 != 0;
          lVar2 = *(long *)(lVar2 + 0xc0)) {
        if (*(int *)(lVar2 + 0xbc) == iVar7) {
          lVar1 = lVar2 + 0x148;
          func_0x004c6a00(lVar1,0,0,0);
          if (*(int *)(lVar2 + 0xb8) != 0) {
            local_64 = *(undefined4 *)(lVar2 + 0x460);
            iVar7 = 0;
            func_0x004c6fa0(lVar1,0,0,0);
            func_0x00c4c300(0x3589e60,0,0);
            uVar9 = *param_2;
            func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
            iVar6 = func_0x002591d0(&local_64,uVar9,4);
            if (iVar6 != 0) {
              uVar9 = *param_2;
              bVar5 = false;
              local_78 = 0xa0020320;
              uVar8 = uVar8 | 4;
              goto LAB_007df71a;
            }
            *param_3 = 0;
            goto LAB_007df84a;
          }
          func_0x004c6fa0(lVar1,0,0,0);
          break;
        }
      }
      local_78 = 0;
      func_0x00c4c300(0x3589e60,0,0);
      uVar8 = 0x4630003;
      iVar6 = 3;
      uVar9 = 0;
    }
  }
  else {
    uVar8 = 0x4630000;
    bVar5 = false;
    uVar9 = 0;
    local_78 = 0xa0020320;
  }
LAB_007df71a:
  func_0x00bff970(*in_GS_OFFSET,0x4715,0xffffffff,0xffffffff,param_1 & 0xffffffff,
                  iVar6 + -0x7ffe0000,uVar8,uVar9,&local_58);
  iVar7 = func_0x00b078d0();
  pcVar3 = _DAT_03bf6920;
  if ((iVar7 != 0) && (_DAT_02cb0000 != 0)) {
    if (1 < (-(long)_DAT_03bf6920 + 0x2693e8U >> 3 | -(long)_DAT_03bf6920 << 0x3d)) {
      func_0x0044f8c0(0x253dc30,_DAT_03bf6920);
    }
    (*pcVar3)(8,2,0x4715,CONCAT71(uStack_57,local_58),local_50,local_48,local_40,
              (param_1 & 0xffff) << 0x20 | 0xffffffff,CONCAT44(uVar8,iVar6 + -0x7ffe0000),uVar9);
  }
  iVar7 = iVar6;
  if ((!bVar5) && (lVar2 = *in_GS_OFFSET, 0x34fffff < *(uint *)(*(long *)(lVar2 + 8) + 0x5d4))) {
    func_0x0025d410(0x1289a38,0xc2);
    func_0x0025d410(0x126c6a7,*(undefined4 *)(lVar2 + 0x9c),lVar2 + 0x294,local_78,uVar8,uVar9);
    func_0x00c9fa20(lVar2,local_78);
  }
LAB_007df84a:
  if (_DAT_0391c310 == local_38) {
    return iVar7;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar3 = (code *)invalidInstructionException();
  (*pcVar3)();
}



/* ===== sub_007df8a0 | RVA 0x7df8a0 | file +0x2b60 | ev_fb2009403dfecadc8183fbd11a97408e2b7722290a3816b78a2cd31dd81295e9 =====
 * Body: [{"start":"0x7df8a0","end":"0x7dfc92"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_007df8a0(ulong param_1,ulong *param_2,undefined4 *param_3)

{
  long lVar1;
  long lVar2;
  code *pcVar3;
  bool bVar4;
  bool bVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  ulong uVar9;
  long *in_GS_OFFSET;
  undefined8 local_78;
  undefined4 local_64;
  long local_60;
  undefined1 local_58;
  undefined7 uStack_57;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  long local_38;
  
  iVar7 = 0x391c310;
  local_38 = _DAT_0391c310;
  local_60 = 0;
  local_58 = 0;
  iVar6 = func_0x0060ec10(param_1,0x8002,&local_60,0x3ffffff);
  if (iVar6 == 0) {
    func_0x00957b70(&local_58,*(undefined8 *)(local_60 + 0x18),0x20);
    iVar6 = 0;
    func_0x00c4bb20(*(undefined8 *)(local_60 + 0x28),0,0,0);
    lVar2 = *(long *)(local_60 + 0x28);
    uVar9 = (ulong)*(uint *)(lVar2 + 0x20);
    if ((*(uint *)(lVar2 + 0x20) & 0x20000) == 0) {
      uVar8 = 0x4640002;
      iVar6 = 3;
      bVar4 = false;
    }
    else {
      iVar7 = *(int *)(lVar2 + 0x194);
      if (iVar7 == -1) {
        uVar8 = 0x4640001;
        iVar7 = -1;
        iVar6 = 3;
        uVar9 = 0;
        bVar4 = false;
      }
      else {
        uVar8 = 0x4640000;
        bVar4 = true;
        uVar9 = 0;
      }
    }
    local_78 = 0;
    func_0x00c4c4b0(lVar2,0,0);
    func_0x0060ecd0(param_1 & 0xffffffff,0x8002,0);
    bVar5 = true;
    if (bVar4) {
      local_64 = 0;
      func_0x00c4b350(0x3589e60,0,0,0);
      for (lVar2 = *(long *)(_DAT_03589e18 + ((long)iVar7 & _DAT_03589e10) * 8); lVar2 != 0;
          lVar2 = *(long *)(lVar2 + 0xc0)) {
        if (*(int *)(lVar2 + 0xbc) == iVar7) {
          lVar1 = lVar2 + 0x148;
          func_0x004c6a00(lVar1,0,0,0);
          if (*(int *)(lVar2 + 0xb8) != 0) {
            local_64 = func_0x00608f90(*(undefined8 *)(lVar2 + 0x40));
            iVar7 = 0;
            func_0x004c6fa0(lVar1,0,0,0);
            func_0x00c4c300(0x3589e60,0,0);
            uVar9 = *param_2;
            func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
            iVar6 = func_0x002591d0(&local_64,uVar9,4);
            if (iVar6 != 0) {
              uVar9 = *param_2;
              bVar5 = false;
              local_78 = 0xa0020320;
              uVar8 = uVar8 | 4;
              goto LAB_007dfb1c;
            }
            *param_3 = 0;
            goto LAB_007dfc4c;
          }
          func_0x004c6fa0(lVar1,0,0,0);
          break;
        }
      }
      local_78 = 0;
      func_0x00c4c300(0x3589e60,0,0);
      uVar8 = 0x4640003;
      iVar6 = 3;
      uVar9 = 0;
    }
  }
  else {
    uVar8 = 0x4640000;
    bVar5 = false;
    uVar9 = 0;
    local_78 = 0xa0020320;
  }
LAB_007dfb1c:
  func_0x00bff970(*in_GS_OFFSET,0x4716,0xffffffff,0xffffffff,param_1 & 0xffffffff,
                  iVar6 + -0x7ffe0000,uVar8,uVar9,&local_58);
  iVar7 = func_0x00b078d0();
  pcVar3 = _DAT_03bf6920;
  if ((iVar7 != 0) && (_DAT_02cb0000 != 0)) {
    if (1 < (-(long)_DAT_03bf6920 + 0x2693e8U >> 3 | -(long)_DAT_03bf6920 << 0x3d)) {
      func_0x0044f8c0(0x253dc50,_DAT_03bf6920);
    }
    (*pcVar3)(8,2,0x4716,CONCAT71(uStack_57,local_58),local_50,local_48,local_40,
              (param_1 & 0xffff) << 0x20 | 0xffffffff,CONCAT44(uVar8,iVar6 + -0x7ffe0000),uVar9);
  }
  iVar7 = iVar6;
  if ((!bVar5) && (lVar2 = *in_GS_OFFSET, 0x34fffff < *(uint *)(*(long *)(lVar2 + 8) + 0x5d4))) {
    func_0x0025d410(0x1289a38,0xc2);
    func_0x0025d410(0x126c6a7,*(undefined4 *)(lVar2 + 0x9c),lVar2 + 0x294,local_78,uVar8,uVar9);
    func_0x00c9fa20(lVar2,local_78);
  }
LAB_007dfc4c:
  if (_DAT_0391c310 == local_38) {
    return iVar7;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar3 = (code *)invalidInstructionException();
  (*pcVar3)();
}



/* ===== sub_007dfca0 | RVA 0x7dfca0 | file +0x2f60 | ev_4b914a9f6a3ee650245ac99aa84eedd36d39ea262576497b17db02dea7c0c7cf =====
 * Body: [{"start":"0x7dfca0","end":"0x7e0038"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_007dfca0(ulong param_1,ulong *param_2,undefined4 *param_3)

{
  uint uVar1;
  uint uVar2;
  long lVar3;
  code *pcVar4;
  bool bVar5;
  int iVar6;
  int iVar7;
  ulong uVar8;
  uint uVar9;
  ulong uVar10;
  long *in_GS_OFFSET;
  undefined8 local_80;
  undefined8 local_70;
  long local_68;
  long local_60;
  undefined1 local_58;
  undefined7 uStack_57;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  local_60 = 0;
  local_68 = 0;
  local_70 = 0;
  local_58 = 0;
  iVar6 = func_0x0060ec10(param_1,0x8002,&local_60,0x3ffffff);
  if (iVar6 == 0) {
    func_0x00957b70(&local_58,*(undefined8 *)(local_60 + 0x18),0x20);
    iVar6 = 0;
    func_0x00c4bb20(*(undefined8 *)(local_60 + 0x28),0,0,0);
    lVar3 = *(long *)(local_60 + 0x28);
    uVar1 = *(uint *)(lVar3 + 0x20);
    uVar10 = (ulong)uVar1;
    if ((uVar1 & 0x20000) == 0) {
      iVar6 = 3;
      uVar9 = 0x4650001;
      uVar2 = 0xffffffff;
    }
    else {
      uVar2 = *(uint *)(lVar3 + 0x38);
      uVar9 = 0x4650000;
      uVar10 = 0;
    }
    func_0x00c4c4b0(lVar3,0,0);
    func_0x0060ecd0(param_1,0x8002,0);
    bVar5 = true;
    if ((uVar1 & 0x20000) == 0) {
      local_80 = 0;
    }
    else {
      iVar6 = func_0x0060ec10(uVar2,0x8001,&local_68,0x3ffffff);
      if (iVar6 != 0) {
        uVar8 = (ulong)uVar2;
        local_80 = 0;
        uVar10 = 0;
        uVar9 = uVar9 | 2;
        goto LAB_007dfe11;
      }
      iVar6 = 0;
      func_0x00c4bb20(local_68 + 0x28,0,0,0);
      local_70 = *(undefined8 *)(local_68 + 0x48);
      func_0x00c4c4b0(local_68 + 0x28,0,0);
      func_0x0060ecd0(uVar2,0x8001,0);
      uVar10 = *param_2;
      func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
      iVar7 = func_0x002591d0(&local_70,uVar10,8);
      if (iVar7 == 0) {
        *param_3 = 0;
        goto LAB_007dff56;
      }
      uVar10 = *param_2;
      uVar9 = 0x4650003;
      bVar5 = false;
      local_80 = 0xa0020320;
      iVar6 = iVar7;
    }
    uVar8 = (ulong)uVar2;
  }
  else {
    uVar9 = 0x4650000;
    uVar8 = 0xffffffff;
    bVar5 = false;
    uVar10 = 0;
    local_80 = 0xa0020320;
  }
LAB_007dfe11:
  func_0x00bff970(*in_GS_OFFSET,0x4717,uVar8,0xffffffff,param_1,iVar6 + -0x7ffe0000,uVar9,uVar10,
                  &local_58);
  iVar7 = func_0x00b078d0();
  pcVar4 = _DAT_03bf6920;
  if ((iVar7 != 0) && (_DAT_02cb0000 != 0)) {
    if (1 < (-(long)_DAT_03bf6920 + 0x2693e8U >> 3 | -(long)_DAT_03bf6920 << 0x3d)) {
      func_0x0044f8c0(0x253dc70,_DAT_03bf6920);
    }
    (*pcVar4)(8,2,0x4717,CONCAT71(uStack_57,local_58),local_50,local_48,local_40,
              uVar8 | (param_1 & 0xffff) << 0x20 | 0xffff0000,CONCAT44(uVar9,iVar6 + -0x7ffe0000),
              uVar10);
  }
  if ((!bVar5) && (lVar3 = *in_GS_OFFSET, 0x34fffff < *(uint *)(*(long *)(lVar3 + 8) + 0x5d4))) {
    func_0x0025d410(0x1289a38,0xc2);
    func_0x0025d410(0x126c6a7,*(undefined4 *)(lVar3 + 0x9c),lVar3 + 0x294,local_80,uVar9,uVar10);
    func_0x00c9fa20(lVar3,local_80);
  }
LAB_007dff56:
  if (_DAT_0391c310 == local_38) {
    return iVar6;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar4 = (code *)invalidInstructionException();
  (*pcVar4)();
}



/* ===== sub_007e0040 | RVA 0x7e0040 | file +0x3300 | ev_5026d2f0df07ba771785bd8ca9d82b7fbdc8624ddd4350cda72133be44701afd =====
 * Body: [{"start":"0x7e0040","end":"0x7e02b8"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_007e0040(ulong param_1,undefined8 *param_2,undefined4 *param_3)

{
  long lVar1;
  code *pcVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined8 uVar6;
  long lVar7;
  ulong uVar8;
  long *in_GS_OFFSET;
  undefined8 local_70;
  undefined8 local_68;
  long local_60;
  undefined1 local_58;
  undefined7 uStack_57;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  long local_38;
  
  uVar8 = param_1 & 0xffffffff;
  local_38 = _DAT_0391c310;
  local_60 = 0;
  local_58 = 0;
  iVar3 = func_0x0060ec10(param_1,0x8001,&local_60,0x3ffffff);
  if (iVar3 == 0) {
    func_0x00957b70(&local_58,*(undefined8 *)(local_60 + 0x18),0x20);
    func_0x00c4bb20(local_60 + 0x28,0,0,0);
    local_68 = *(undefined8 *)(local_60 + 0x90);
    func_0x00c4c4b0(local_60 + 0x28,0,0);
    func_0x0060ecd0(uVar8,0x8001,0);
    uVar6 = *param_2;
    func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
    iVar4 = func_0x002591d0(&local_68,uVar6,8);
    if (iVar4 == 0) {
      *param_3 = 0;
      iVar4 = 0;
      goto LAB_007e027c;
    }
    uVar6 = *param_2;
    lVar7 = 0x4660001;
    local_70 = 0xa0020320;
  }
  else {
    lVar7 = 0x4660000;
    uVar6 = 0;
    local_70 = 0;
    iVar4 = iVar3;
  }
  func_0x00bff970(*in_GS_OFFSET,0x1718,uVar8,0xffffffff,0xffffffff,iVar4 + 0x80020000U,lVar7,uVar6,
                  &local_58);
  iVar5 = func_0x00b078d0();
  pcVar2 = _DAT_03bf6920;
  if ((iVar5 != 0) && (_DAT_02cb0000 != 0)) {
    if (1 < (-(long)_DAT_03bf6920 + 0x2693e8U >> 3 | -(long)_DAT_03bf6920 << 0x3d)) {
      func_0x0044f8c0(0x253dc90,_DAT_03bf6920);
    }
    (*pcVar2)(8,2,0x1718,CONCAT71(uStack_57,local_58),local_50,local_48,local_40,
              uVar8 | 0xffffffff0000,(ulong)(iVar4 + 0x80020000U) | lVar7 << 0x20,uVar6);
  }
  if ((iVar3 == 0) && (lVar1 = *in_GS_OFFSET, 0x34fffff < *(uint *)(*(long *)(lVar1 + 8) + 0x5d4)))
  {
    func_0x0025d410(0x1289a38,0xc2);
    func_0x0025d410(0x126c6a7,*(undefined4 *)(lVar1 + 0x9c),lVar1 + 0x294,local_70,lVar7,uVar6);
    func_0x00c9fa20(lVar1,local_70);
  }
LAB_007e027c:
  if (_DAT_0391c310 == local_38) {
    return iVar4;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar2 = (code *)invalidInstructionException();
  (*pcVar2)();
}



/* ===== sub_007e02c0 | RVA 0x7e02c0 | file +0x3580 | ev_05ad6ba76922ab280f219275571782314d99a88999624322dcf1fa6ebcab80a4 =====
 * Body: [{"start":"0x7e02c0","end":"0x7e059d"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_007e02c0(ulong param_1,ulong *param_2,undefined4 *param_3)

{
  uint uVar1;
  long lVar2;
  code *pcVar3;
  bool bVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  ulong uVar8;
  long *in_GS_OFFSET;
  undefined8 local_80;
  undefined8 local_68;
  long local_60;
  undefined1 local_58;
  undefined7 uStack_57;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  local_60 = 0;
  local_68 = 0;
  local_58 = 0;
  iVar5 = func_0x0060ec10(param_1,0x8004,&local_60,0x3ffffff);
  bVar4 = true;
  if (iVar5 == 0) {
    func_0x00957b70(&local_58,*(undefined8 *)(local_60 + 0x18),0x20);
    iVar5 = 0;
    func_0x00c4bb20(*(undefined8 *)(local_60 + 0x28),0,0,0);
    lVar2 = *(long *)(local_60 + 0x28);
    uVar1 = *(uint *)(lVar2 + 0x20);
    uVar8 = (ulong)uVar1;
    if ((uVar1 & 0x20000000) == 0) {
      local_68 = *(undefined8 *)(lVar2 + 0x1b0);
      uVar8 = 0;
      uVar7 = 0x4670000;
    }
    else {
      uVar7 = 0x4670001;
      iVar5 = 2;
    }
    local_80 = 0;
    func_0x00c4c4b0(lVar2,0,0);
    func_0x0060ecd0(param_1 & 0xffffffff,0x8004,0);
    if ((uVar1 & 0x20000000) == 0) {
      uVar8 = *param_2;
      iVar6 = 0;
      func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
      iVar5 = func_0x002591d0(&local_68,uVar8,8);
      if (iVar5 == 0) {
        *param_3 = 0;
        goto LAB_007e0569;
      }
      uVar8 = *param_2;
      bVar4 = false;
      local_80 = 0xa0020320;
      uVar7 = uVar7 | 2;
    }
  }
  else {
    uVar7 = 0x4670000;
    local_80 = 0;
    uVar8 = 0;
  }
  func_0x00bff970(*in_GS_OFFSET,0x271b,0xffffffff,param_1 & 0xffffffff,0xffffffff,
                  iVar5 + -0x7ffe0000,uVar7,uVar8,&local_58);
  iVar6 = func_0x00b078d0();
  pcVar3 = _DAT_03bf6920;
  if ((iVar6 != 0) && (_DAT_02cb0000 != 0)) {
    if (1 < (-(long)_DAT_03bf6920 + 0x2693e8U >> 3 | -(long)_DAT_03bf6920 << 0x3d)) {
      func_0x0044f8c0(0x253dcb0,_DAT_03bf6920);
    }
    (*pcVar3)(8,2,0x271b,CONCAT71(uStack_57,local_58),local_50,local_48,local_40,
              (ulong)(uint)((int)param_1 << 0x10) | 0xffff0000ffff,
              CONCAT44(uVar7,iVar5 + -0x7ffe0000),uVar8);
  }
  iVar6 = iVar5;
  if ((!bVar4) && (lVar2 = *in_GS_OFFSET, 0x34fffff < *(uint *)(*(long *)(lVar2 + 8) + 0x5d4))) {
    func_0x0025d410(0x1289a38,0xc2);
    func_0x0025d410(0x126c6a7,*(undefined4 *)(lVar2 + 0x9c),lVar2 + 0x294,local_80,uVar7,uVar8);
    func_0x00c9fa20(lVar2,local_80);
  }
LAB_007e0569:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar3 = (code *)invalidInstructionException();
    (*pcVar3)();
  }
  return iVar6;
}



/* ===== sub_007e05a0 | RVA 0x7e05a0 | file +0x3860 | ev_2aba40164821622dbcb240ffe8babb2878908c13741661036cf9dea729c3c68e =====
 * Body: [{"start":"0x7e05a0","end":"0x7e0880"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_007e05a0(ulong param_1,ulong *param_2,undefined4 *param_3)

{
  uint uVar1;
  long lVar2;
  code *pcVar3;
  bool bVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  ulong uVar8;
  long *in_GS_OFFSET;
  undefined8 local_80;
  undefined8 local_68;
  long local_60;
  undefined1 local_58;
  undefined7 uStack_57;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  local_60 = 0;
  local_68 = 0;
  local_58 = 0;
  iVar5 = func_0x0060ec10(param_1,0x8002,&local_60,0x3ffffff);
  bVar4 = true;
  if (iVar5 == 0) {
    func_0x00957b70(&local_58,*(undefined8 *)(local_60 + 0x18),0x20);
    iVar5 = 0;
    func_0x00c4bb20(*(undefined8 *)(local_60 + 0x28),0,0,0);
    lVar2 = *(long *)(local_60 + 0x28);
    uVar1 = *(uint *)(lVar2 + 0x20);
    uVar8 = (ulong)uVar1;
    if ((uVar1 & 0x10000) == 0) {
      local_68 = *(undefined8 *)(lVar2 + 0x8f8);
      uVar8 = 0;
      uVar7 = 0x4680000;
    }
    else {
      uVar7 = 0x4680001;
      iVar5 = 2;
    }
    local_80 = 0;
    func_0x00c4c4b0(lVar2,0,0);
    func_0x0060ecd0(param_1 & 0xffffffff,0x8002,0);
    if ((uVar1 & 0x10000) == 0) {
      uVar8 = *param_2;
      iVar6 = 0;
      func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
      iVar5 = func_0x002591d0(&local_68,uVar8,8);
      if (iVar5 == 0) {
        *param_3 = 0;
        goto LAB_007e084c;
      }
      uVar8 = *param_2;
      bVar4 = false;
      local_80 = 0xa0020320;
      uVar7 = uVar7 | 2;
    }
  }
  else {
    uVar7 = 0x4680000;
    local_80 = 0;
    uVar8 = 0;
  }
  func_0x00bff970(*in_GS_OFFSET,0x4718,0xffffffff,0xffffffff,param_1 & 0xffffffff,
                  iVar5 + -0x7ffe0000,uVar7,uVar8,&local_58);
  iVar6 = func_0x00b078d0();
  pcVar3 = _DAT_03bf6920;
  if ((iVar6 != 0) && (_DAT_02cb0000 != 0)) {
    if (1 < (-(long)_DAT_03bf6920 + 0x2693e8U >> 3 | -(long)_DAT_03bf6920 << 0x3d)) {
      func_0x0044f8c0(0x253dcd0,_DAT_03bf6920);
    }
    (*pcVar3)(8,2,0x4718,CONCAT71(uStack_57,local_58),local_50,local_48,local_40,
              ((param_1 & 0xffff) << 0x20) + 0xffffffff,CONCAT44(uVar7,iVar5 + -0x7ffe0000),uVar8);
  }
  iVar6 = iVar5;
  if ((!bVar4) && (lVar2 = *in_GS_OFFSET, 0x34fffff < *(uint *)(*(long *)(lVar2 + 8) + 0x5d4))) {
    func_0x0025d410(0x1289a38,0xc2);
    func_0x0025d410(0x126c6a7,*(undefined4 *)(lVar2 + 0x9c),lVar2 + 0x294,local_80,uVar7,uVar8);
    func_0x00c9fa20(lVar2,local_80);
  }
LAB_007e084c:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar3 = (code *)invalidInstructionException();
    (*pcVar3)();
  }
  return iVar6;
}



/* ===== sub_007e0890 | RVA 0x7e0890 | file +0x3b50 | ev_6df472d3120f2d9fa5e66c0de4d24f25c6dd7d4beec290ccf06a018fa1557f49 =====
 * Body: [{"start":"0x7e0890","end":"0x7e0b67"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_007e0890(ulong param_1,ulong *param_2,undefined4 *param_3)

{
  uint uVar1;
  long lVar2;
  code *pcVar3;
  bool bVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  ulong uVar8;
  long *in_GS_OFFSET;
  undefined8 local_80;
  undefined4 local_64;
  long local_60;
  undefined1 local_58;
  undefined7 uStack_57;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  local_60 = 0;
  local_64 = 0xffffffff;
  local_58 = 0;
  iVar5 = func_0x0060ec10(param_1,0x8004,&local_60,0x3ffffff);
  bVar4 = true;
  if (iVar5 == 0) {
    func_0x00957b70(&local_58,*(undefined8 *)(local_60 + 0x18),0x20);
    iVar5 = 0;
    func_0x00c4bb20(*(undefined8 *)(local_60 + 0x28),0,0,0);
    lVar2 = *(long *)(local_60 + 0x28);
    uVar1 = *(uint *)(lVar2 + 0x20);
    uVar8 = (ulong)uVar1;
    if ((uVar1 & 0x4000000) == 0) {
      uVar7 = 0x4690001;
      iVar5 = 3;
    }
    else {
      local_64 = *(undefined4 *)(lVar2 + 0x3c);
      uVar8 = 0;
      uVar7 = 0x4690000;
    }
    local_80 = 0;
    func_0x00c4c4b0(lVar2,0,0);
    func_0x0060ecd0(param_1 & 0xffffffff,0x8004,0);
    if ((uVar1 & 0x4000000) != 0) {
      uVar8 = *param_2;
      iVar6 = 0;
      func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
      iVar5 = func_0x002591d0(&local_64,uVar8,4);
      if (iVar5 == 0) {
        *param_3 = 0;
        goto LAB_007e0b33;
      }
      uVar8 = *param_2;
      bVar4 = false;
      local_80 = 0xa0020320;
      uVar7 = uVar7 | 2;
    }
  }
  else {
    uVar7 = 0x4690000;
    local_80 = 0;
    uVar8 = 0;
  }
  func_0x00bff970(*in_GS_OFFSET,0x271a,0xffffffff,param_1 & 0xffffffff,0xffffffff,
                  iVar5 + -0x7ffe0000,uVar7,uVar8,&local_58);
  iVar6 = func_0x00b078d0();
  pcVar3 = _DAT_03bf6920;
  if ((iVar6 != 0) && (_DAT_02cb0000 != 0)) {
    if (1 < (-(long)_DAT_03bf6920 + 0x2693e8U >> 3 | -(long)_DAT_03bf6920 << 0x3d)) {
      func_0x0044f8c0(0x253dcf0,_DAT_03bf6920);
    }
    (*pcVar3)(8,2,0x271a,CONCAT71(uStack_57,local_58),local_50,local_48,local_40,
              (ulong)(uint)((int)param_1 << 0x10) | 0xffff0000ffff,
              CONCAT44(uVar7,iVar5 + -0x7ffe0000),uVar8);
  }
  iVar6 = iVar5;
  if ((!bVar4) && (lVar2 = *in_GS_OFFSET, 0x34fffff < *(uint *)(*(long *)(lVar2 + 8) + 0x5d4))) {
    func_0x0025d410(0x1289a38,0xc2);
    func_0x0025d410(0x126c6a7,*(undefined4 *)(lVar2 + 0x9c),lVar2 + 0x294,local_80,uVar7,uVar8);
    func_0x00c9fa20(lVar2,local_80);
  }
LAB_007e0b33:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar3 = (code *)invalidInstructionException();
    (*pcVar3)();
  }
  return iVar6;
}



/* ===== sub_007e0b70 | RVA 0x7e0b70 | file +0x3e30 | ev_ac7ac272d7ada7763761b5a7c4d493dbc810be703db04828f00509715d82e5ea =====
 * Body: [{"start":"0x7e0b70","end":"0x7e0dc9"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_007e0b70(ulong param_1,undefined8 *param_2,undefined4 *param_3)

{
  undefined8 uVar1;
  undefined8 uVar2;
  long lVar3;
  code *pcVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  long lVar8;
  ulong uVar9;
  long *in_GS_OFFSET;
  undefined8 local_70;
  long local_60;
  undefined1 local_58;
  undefined7 uStack_57;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  long local_38;
  
  uVar9 = param_1 & 0xffffffff;
  local_38 = _DAT_0391c310;
  local_60 = 0;
  local_58 = 0;
  iVar5 = func_0x0060ec10(param_1,0x8001,&local_60,0x3ffffff);
  if (iVar5 == 0) {
    func_0x00957b70(&local_58,*(undefined8 *)(local_60 + 0x18),0x20);
    uVar1 = *param_2;
    iVar7 = 0;
    uVar2 = *(undefined8 *)(local_60 + 0x18);
    func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
    iVar6 = func_0x002591d0(uVar2,uVar1,0x19);
    func_0x0060ecd0(uVar9,0x8001,0);
    if (iVar6 == 0) {
      *param_3 = 0;
      goto LAB_007e0d94;
    }
    lVar8 = 0x46a0001;
    local_70 = 0xa0020320;
  }
  else {
    lVar8 = 0x46a0000;
    local_70 = 0;
    iVar6 = iVar5;
  }
  func_0x00bff970(*in_GS_OFFSET,0x1719,uVar9,0xffffffff,0xffffffff,iVar6 + 0x80020000U,lVar8,0,
                  &local_58);
  iVar7 = func_0x00b078d0();
  pcVar4 = _DAT_03bf6920;
  if ((iVar7 != 0) && (_DAT_02cb0000 != 0)) {
    if (1 < (-(long)_DAT_03bf6920 + 0x2693e8U >> 3 | -(long)_DAT_03bf6920 << 0x3d)) {
      func_0x0044f8c0(0x253dd10,_DAT_03bf6920);
    }
    (*pcVar4)(8,2,0x1719,CONCAT71(uStack_57,local_58),local_50,local_48,local_40,
              uVar9 | 0xffffffff0000,(ulong)(iVar6 + 0x80020000U) | lVar8 << 0x20,0);
  }
  iVar7 = iVar6;
  if ((iVar5 == 0) && (lVar3 = *in_GS_OFFSET, 0x34fffff < *(uint *)(*(long *)(lVar3 + 8) + 0x5d4)))
  {
    func_0x0025d410(0x1289a38,0xc2);
    func_0x0025d410(0x126c6a7,*(undefined4 *)(lVar3 + 0x9c),lVar3 + 0x294,local_70,lVar8,0);
    func_0x00c9fa20(lVar3,local_70);
  }
LAB_007e0d94:
  if (_DAT_0391c310 == local_38) {
    return iVar7;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar4 = (code *)invalidInstructionException();
  (*pcVar4)();
}



/* ===== sub_007e0dd0 | RVA 0x7e0dd0 | file +0x4090 | ev_0b8b5a139f98d57a2cf78bcf865e0a3b2e3b3043380e095b44985f91515dcb36 =====
 * Body: [{"start":"0x7e0dd0","end":"0x7e1077"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_007e0dd0(ulong param_1,undefined8 *param_2,undefined4 *param_3)

{
  long lVar1;
  code *pcVar2;
  bool bVar3;
  int iVar4;
  int iVar5;
  long lVar6;
  undefined8 uVar7;
  long *in_GS_OFFSET;
  long local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  local_60 = 0;
  local_40 = 0;
  local_48 = 0;
  local_50 = 0;
  local_58 = 0;
  iVar4 = func_0x0060ec10(param_1,0x8004,&local_60,0x3ffffff);
  if (iVar4 == 0) {
    func_0x00c4bb20(*(undefined8 *)(local_60 + 0x28),0,0,0);
    if ((*(byte *)(*(long *)(local_60 + 0x28) + 0x23) & 0x20) == 0) {
      func_0x00957b70(&local_58,*(undefined8 *)(local_60 + 0x18),0x20);
      iVar5 = 0;
      func_0x00c4c4b0(*(undefined8 *)(local_60 + 0x28),0,0);
      func_0x0060ecd0(param_1 & 0xffffffff,0x8004,0);
      uVar7 = *param_2;
      func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
      iVar4 = func_0x002591d0(&local_58,uVar7,0x19);
      if (iVar4 == 0) {
        *param_3 = 0;
        goto LAB_007e103c;
      }
      lVar6 = 0x46b0001;
      uVar7 = 0xa0020320;
      bVar3 = false;
    }
    else {
      bVar3 = true;
      uVar7 = 0;
      func_0x00c4c4b0(*(long *)(local_60 + 0x28),0,0);
      iVar4 = 2;
      lVar6 = 0x46b0001;
    }
  }
  else {
    bVar3 = true;
    lVar6 = 0x46b0000;
    uVar7 = 0;
  }
  func_0x00bff970(*in_GS_OFFSET,0x271c,0xffffffff,param_1 & 0xffffffff,0xffffffff,
                  iVar4 + 0x80020000U,lVar6,0,&local_58);
  iVar5 = func_0x00b078d0();
  pcVar2 = _DAT_03bf6920;
  if ((iVar5 != 0) && (_DAT_02cb0000 != 0)) {
    if (1 < (-(long)_DAT_03bf6920 + 0x2693e8U >> 3 | -(long)_DAT_03bf6920 << 0x3d)) {
      func_0x0044f8c0(0x253dd30,_DAT_03bf6920);
    }
    (*pcVar2)(8,2,0x271c,local_58,local_50,local_48,local_40,
              (ulong)(uint)((int)param_1 << 0x10) | 0xffff0000ffff,
              (ulong)(iVar4 + 0x80020000U) | lVar6 << 0x20,0);
  }
  iVar5 = iVar4;
  if ((!bVar3) && (lVar1 = *in_GS_OFFSET, 0x34fffff < *(uint *)(*(long *)(lVar1 + 8) + 0x5d4))) {
    func_0x0025d410(0x1289a38,0xc2);
    func_0x0025d410(0x126c6a7,*(undefined4 *)(lVar1 + 0x9c),lVar1 + 0x294,uVar7,lVar6,0);
    func_0x00c9fa20(lVar1,uVar7);
  }
LAB_007e103c:
  if (_DAT_0391c310 == local_38) {
    return iVar5;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar2 = (code *)invalidInstructionException();
  (*pcVar2)();
}



/* ===== sub_007e1080 | RVA 0x7e1080 | file +0x4340 | ev_48e47452d4da0044846a310853b027902d9611af0f4b3f2704667ecf31f9e1f3 =====
 * Body: [{"start":"0x7e1080","end":"0x7e10e9"},{"start":"0x7e10fd","end":"0x7e1145"},{"start":"0x7e13af","end":"0x7e1411"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8
sub_007e1080(undefined8 param_1,long param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,int param_6)

{
  code *pcVar1;
  uint uVar2;
  int iVar3;
  undefined8 uVar4;
  byte *in_stack_00000020;
  undefined1 local_60 [8];
  undefined1 local_58 [32];
  long local_38;
  
  local_38 = _DAT_0391c310;
  uVar2 = func_0x003a1110(*(undefined4 *)(param_2 + 0x18),param_4,local_58,local_60,param_6,
                          0x3ffffff);
  if (uVar2 < 0x24) {
                    /* WARNING: Could not emulate address calculation at 0x007e10e1 */
                    /* WARNING: Treating indirect jump as call */
    uVar4 = (*(code *)((long)*(int *)((ulong)uVar2 * 4 + 0x1780edc) + 0x1780edc))();
    return uVar4;
  }
  if (uVar2 == 0x59) {
    iVar3 = func_0x00b67bb0(param_6,param_2,0x3ffffff);
    if (iVar3 != 0) {
      func_0x00b670a0(param_2);
    }
    in_stack_00000020[0x10] = 0x20;
    in_stack_00000020[0x11] = 3;
    in_stack_00000020[0x12] = 2;
    in_stack_00000020[0x13] = 0xa0;
    in_stack_00000020[0x14] = 0;
    in_stack_00000020[0x15] = 0;
    in_stack_00000020[0x16] = 0;
    in_stack_00000020[0x17] = 0;
    *in_stack_00000020 = *in_stack_00000020 | 0xc;
    in_stack_00000020[8] = 0;
    in_stack_00000020[9] = 0;
    in_stack_00000020[10] = 0;
    in_stack_00000020[0xb] = 0;
    in_stack_00000020[0xc] = 0;
    in_stack_00000020[0xd] = 0;
    in_stack_00000020[0xe] = 0;
    in_stack_00000020[0xf] = 0;
    if (_DAT_0391c310 == local_38) {
      return 0xc;
    }
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar1 = (code *)invalidInstructionException();
    (*pcVar1)();
  }
  func_0x007f1950();
  func_0x007f20c0(0x7e13d8,(long)param_6,(long)*(int *)(param_2 + 0x18),(long)(int)uVar2);
  func_0x00c9aa10(0x1c,0x1349e31,param_6,*(undefined4 *)(param_2 + 0x18),(ulong)uVar2);
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* ===== sub_007e14a0 | RVA 0x7e14a0 | file +0x4760 | ev_f9648d4ae634c75aaf32350a2cf2c3460a913cd1de0ca2c0645d49f96d5219c0 =====
 * Body: [{"start":"0x7e14a0","end":"0x7e179f"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_007e14a0(long param_1,long param_2,undefined8 param_3,undefined8 param_4,undefined8 param_5,
                undefined8 *param_6,undefined4 *param_7,byte *param_8)

{
  undefined4 uVar1;
  uint uVar2;
  long lVar3;
  code *pcVar4;
  int iVar5;
  undefined4 uVar6;
  int iVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  long lVar10;
  undefined4 uVar11;
  undefined8 *in_GS_OFFSET;
  undefined8 local_58;
  long local_50;
  long local_48;
  long local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  uVar1 = *(undefined4 *)(param_2 + 0x18);
  iVar5 = func_0x0060ec10(uVar1,0x8002,&local_50,0x3ffffff);
  if (iVar5 == 0) {
    local_58 = *(undefined8 *)(*(long *)(local_50 + 0x28) + 0x468);
    func_0x00c4bb20(*(long *)(local_50 + 0x28),0,0,0);
    lVar10 = *(long *)(local_50 + 0x28);
    lVar3 = *(long *)(lVar10 + 0x198);
    if (lVar3 == 0) {
      uVar11 = 0xffffffff;
      uVar8 = 0xffffffff;
    }
    else {
      uVar11 = *(undefined4 *)(lVar3 + 8);
      uVar8 = *(undefined4 *)(lVar3 + 0x10);
    }
    uVar2 = *(uint *)(lVar10 + 0x20);
    if ((uVar2 & 0x20020) == 0x20000) {
      if (*(int *)(lVar10 + 0x900) == 0) {
        uVar9 = 0xa0;
        iVar5 = *(int *)(param_2 + 0x10);
        *(uint *)(lVar10 + 0x20) = uVar2 | 0x20;
        uVar6 = uVar1;
        if (iVar5 == 0x50) {
          func_0x00acf2b0(&local_48);
          uVar9 = 3;
          lVar10 = *(long *)(local_50 + 0x28);
          uVar6 = *(undefined4 *)(param_1 + 0x9c);
          *(undefined4 *)(lVar10 + 0x48) = 3;
          *(undefined4 *)(lVar10 + 0x4c) = uVar6;
          *(long *)(lVar10 + 0x50) = local_40 / 1000 + local_48 * 1000000;
          uVar6 = uVar11;
        }
        func_0x00c4c4b0(*(undefined8 *)(local_50 + 0x28),0,0);
        func_0x0060ecd0(uVar1,0x8002,0);
        *(undefined4 *)(param_6 + 1) = uVar9;
        *(undefined4 *)((long)param_6 + 0xc) = uVar6;
        *param_6 = 8;
        param_6[2] = param_5;
        func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
        iVar7 = func_0x002591d0(param_6,param_4,0x18);
        if (iVar7 == 0) {
          func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
          iVar7 = func_0x002591d0(&local_58,param_3,8);
          if (iVar7 == 0) {
            iVar7 = *(int *)(param_6 + 1);
            uVar6 = 0x170c;
            if ((long)iVar7 != 3) {
              if (iVar7 != 0xa0) {
                func_0x007f1950(param_2);
                func_0x007f18a0(0x7e1774,(long)iVar7);
                func_0x00c9aa10(0x20,0x12a3a16,iVar7);
                    /* WARNING: Does not return */
                pcVar4 = (code *)invalidInstructionException();
                (*pcVar4)();
              }
              uVar6 = 0x170f;
            }
            *param_7 = uVar6;
            param_7[2] = uVar1;
            param_7[3] = uVar11;
            param_7[4] = uVar8;
            param_7[5] = iVar5;
            *(undefined8 *)(param_7 + 6) = 0;
            func_0x00b670a0();
            iVar7 = 0;
          }
          else {
            func_0x00b670a0(param_2);
            param_8[0x10] = 0x20;
            param_8[0x11] = 3;
            param_8[0x12] = 2;
            param_8[0x13] = 0xa0;
            param_8[0x14] = 0;
            param_8[0x15] = 0;
            param_8[0x16] = 0;
            param_8[0x17] = 0;
            *param_8 = *param_8 | 0x11;
            *(undefined8 *)(param_8 + 8) = param_3;
          }
        }
        else {
          func_0x00b670a0(param_2);
          param_8[0x10] = 0x20;
          param_8[0x11] = 3;
          param_8[0x12] = 2;
          param_8[0x13] = 0xa0;
          param_8[0x14] = 0;
          param_8[0x15] = 0;
          param_8[0x16] = 0;
          param_8[0x17] = 0;
          *param_8 = *param_8 | 0x10;
          *(undefined8 *)(param_8 + 8) = param_4;
        }
        goto LAB_007e1598;
      }
      *(uint *)(lVar10 + 0x20) = uVar2 | 0x200;
      lVar10 = *(long *)(local_50 + 0x28);
    }
    func_0x00c4c4b0(lVar10,0,0);
    func_0x0060ecd0(uVar1,0x8002,0);
  }
  else {
    func_0x00b670a0(param_2);
  }
  iVar7 = -1;
LAB_007e1598:
  if (_DAT_0391c310 == local_38) {
    return iVar7;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar4 = (code *)invalidInstructionException();
  (*pcVar4)();
}



/* ===== sub_007e17a0 | RVA 0x7e17a0 | file +0x4a60 | ev_ab5a95deba9a44e8d88f80d6bbc2366c9e13b21507a3e4dc42db6adc9efa1d79 =====
 * Body: [{"start":"0x7e17a0","end":"0x7e191b"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

int sub_007e17a0(undefined8 param_1,undefined8 param_2,undefined8 param_3,int param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 *param_8,
                uint *param_9)

{
  code *pcVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  undefined8 uVar5;
  undefined8 *in_GS_OFFSET;
  
  func_0x0039f310(param_8,param_7,0,0x30);
  param_8[2] = param_3;
  func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
  iVar2 = func_0x002591d0(param_8,param_5,0x18);
  if (iVar2 == 0) {
    iVar2 = func_0x0039f4e0(param_1,param_7,0x30,*param_8);
    if (iVar2 == 0) {
      return 0;
    }
    iVar3 = func_0x003a0c70(param_6);
    if (iVar3 != 0) {
      func_0x007f1950();
      func_0x007f2010(0x7e18e5,(long)param_4,(long)iVar3);
      uVar5 = 0x28;
      goto LAB_007e1911;
    }
    iVar3 = func_0x00b67bb0(param_4,param_2,0x3ffffff);
    uVar4 = 0xf;
  }
  else {
    iVar3 = func_0x003a0c70(param_6);
    if (iVar3 != 0) {
      func_0x007f1950();
      func_0x007f2010(0x7e18b7,(long)param_4,(long)iVar3);
      uVar5 = 0x24;
LAB_007e1911:
      func_0x00c9aa10(uVar5,0x1388b31,param_4,iVar3);
                    /* WARNING: Does not return */
      pcVar1 = (code *)invalidInstructionException();
      (*pcVar1)();
    }
    iVar3 = func_0x00b67bb0(param_4,param_2,0x3ffffff);
    uVar4 = 0xe;
    param_1 = param_5;
  }
  if (iVar3 != 0) {
    func_0x00b670a0(param_2);
  }
  param_9[4] = 0xa0020320;
  param_9[5] = 0;
  *param_9 = *param_9 | uVar4;
  *(undefined8 *)(param_9 + 2) = param_1;
  return iVar2;
}



/* ===== sub_007e1920 | RVA 0x7e1920 | file +0x4be0 | ev_a9bd2795078944214652fd7dbdf57b1509704c7350246733ecd597403ca357de =====
 * Body: [{"start":"0x7e1920","end":"0x7e1ccf"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_007e1920(long param_1,long param_2,undefined4 *param_3)

{
  int *piVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  code *pcVar5;
  long lVar6;
  int iVar7;
  undefined4 uVar8;
  long lVar9;
  undefined4 uVar10;
  undefined8 uVar11;
  undefined4 uVar12;
  long lVar13;
  undefined8 uVar14;
  undefined4 *local_58;
  long local_50;
  long local_48;
  long local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  uVar2 = *(undefined4 *)(param_2 + 0xc);
  iVar7 = func_0x0060ec10(uVar2,0x8002,&local_50,0x3ffffff);
  uVar14 = 0xffffffff;
  if (iVar7 == 0) {
    func_0x00c4bb20(*(undefined8 *)(local_50 + 0x28),0,0,0);
    lVar6 = local_50;
    lVar13 = *(long *)(local_50 + 0x28);
    if ((*(uint *)(lVar13 + 0x20) & 0x4000320) == 0x4000000) {
      if ((*(uint *)(param_2 + 8) | 0x10) == 0x53) {
        lVar9 = (long)*(int *)(param_2 + 0x18);
        if (((*(int *)(lVar13 + 0x608 + lVar9 * 0x28) != -1) ||
            (lVar13 = lVar13 + 0x5f8 + lVar9 * 0x28, *(int *)(lVar13 + 4) != -1)) ||
           (*(int *)(lVar13 + 0x20) != -1)) {
          func_0x0025d410(0x1289a38,0x662);
          lVar13 = *(long *)(lVar6 + 0x28);
          func_0x0025d410(0x13a88e1,*(undefined4 *)(param_1 + 0x9c),*(undefined8 *)(lVar6 + 0x18),
                          *(undefined4 *)(param_2 + 0x18),
                          *(undefined4 *)(lVar13 + 0x608 + lVar9 * 0x28),
                          *(undefined4 *)(lVar13 + 0x5fc + lVar9 * 0x28),
                          *(undefined4 *)(lVar13 + 0x618 + lVar9 * 0x28));
        }
        func_0x00acf2b0(&local_48);
        lVar9 = lVar9 * 0x28;
        *(undefined4 *)(*(long *)(lVar6 + 0x28) + 0x608 + lVar9) = *(undefined4 *)(param_2 + 0x1c);
        *(undefined4 *)(*(long *)(lVar6 + 0x28) + 0x5fc + lVar9) = *(undefined4 *)(param_2 + 0x20);
        *(long *)(*(long *)(lVar6 + 0x28) + 0x600 + lVar9) = local_40 / 1000 + local_48 * 1000000;
        *(undefined4 *)(*(long *)(lVar6 + 0x28) + 0x60c + lVar9) = *(undefined4 *)(param_2 + 0x24);
        *(undefined8 *)(*(long *)(lVar6 + 0x28) + 0x610 + lVar9) = *(undefined8 *)(param_2 + 0x28);
        *(undefined4 *)(*(long *)(lVar6 + 0x28) + 0x618 + lVar9) = *(undefined4 *)(param_1 + 0x9c);
        uVar10 = 0xffffffff;
        *(undefined4 *)(*(long *)(lVar6 + 0x28) + 0x61c + lVar9) = 0;
        uVar8 = 0xffffffff;
        lVar13 = *(long *)(*(long *)(lVar6 + 0x28) + 0x460);
        if (lVar13 != 0) {
          uVar10 = *(undefined4 *)(lVar13 + 8);
        }
        lVar13 = *(long *)(*(long *)(lVar6 + 0x28) + 0x198);
        if (lVar13 != 0) {
          uVar8 = *(undefined4 *)(lVar13 + 8);
        }
        uVar11 = *(undefined8 *)(param_2 + 0x20);
        uVar12 = 0x970e;
      }
      else {
        lVar9 = (long)*(int *)(param_2 + 0x18);
        if ((*(int *)(lVar13 + 0x488 + lVar9 * 0x18) != -1) ||
           (*(int *)(lVar13 + lVar9 * 0x18 + 0x47c) != -1)) {
          func_0x0025d410(0x1289a38,0x620);
          func_0x0025d410(0x12ebe5c,*(undefined4 *)(param_1 + 0x9c),*(undefined8 *)(lVar6 + 0x18),
                          *(undefined4 *)(param_2 + 0x18),
                          *(undefined4 *)(*(long *)(lVar6 + 0x28) + 0x488 + lVar9 * 0x18),
                          *(undefined4 *)(*(long *)(lVar6 + 0x28) + 0x47c + lVar9 * 0x18));
        }
        func_0x00acf2b0(&local_48);
        lVar9 = lVar9 * 0x18;
        *(undefined4 *)(*(long *)(lVar6 + 0x28) + 0x488 + lVar9) = *(undefined4 *)(param_2 + 0x1c);
        *(undefined4 *)(*(long *)(lVar6 + 0x28) + 0x47c + lVar9) = *(undefined4 *)(param_1 + 0x9c);
        uVar10 = 0xffffffff;
        *(long *)(*(long *)(lVar6 + 0x28) + 0x480 + lVar9) = local_40 / 1000 + local_48 * 1000000;
        uVar8 = 0xffffffff;
        lVar13 = *(long *)(*(long *)(lVar6 + 0x28) + 0x460);
        if (lVar13 != 0) {
          uVar10 = *(undefined4 *)(lVar13 + 8);
        }
        lVar13 = *(long *)(*(long *)(lVar6 + 0x28) + 0x198);
        uVar12 = 0x970d;
        if (lVar13 != 0) {
          uVar8 = *(undefined4 *)(lVar13 + 8);
        }
        uVar11 = 0;
      }
      local_58 = (undefined4 *)(param_2 + 0x18);
      uVar3 = *(undefined4 *)(param_2 + 0x1c);
      uVar14 = 0;
      uVar4 = *local_58;
      *param_3 = uVar12;
      param_3[2] = uVar10;
      param_3[3] = uVar8;
      param_3[4] = uVar3;
      param_3[5] = uVar4;
      *(undefined8 *)(param_3 + 6) = uVar11;
      piVar1 = (int *)(*(long *)(local_50 + 0x28) + 0x900);
      *piVar1 = *piVar1 + 1;
      lVar13 = *(long *)(local_50 + 0x28);
    }
    func_0x00c4c4b0(lVar13,0,0);
    func_0x0060ecd0(uVar2,0x8002,0);
  }
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar5 = (code *)invalidInstructionException();
    (*pcVar5)();
  }
  return uVar14;
}



/* ===== sub_007e1cd0 | RVA 0x7e1cd0 | file +0x4f90 | ev_761382ea0bb6a087ff464c3786132a077f69c530544b343fab98d05aa312c6cd =====
 * Body: [{"start":"0x7e1cd0","end":"0x7e1cf5"},{"start":"0x7e1d00","end":"0x7e1d90"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8
sub_007e1cd0(long param_1,int param_2,int param_3,int param_4,undefined8 param_5,undefined8 *param_6
            ,undefined8 *param_7,undefined8 param_8)

{
  undefined8 *puVar1;
  code *pcVar2;
  
  puVar1 = *(undefined8 **)(_DAT_0253daa8 + 0x38);
  while( true ) {
    if (puVar1 == (undefined8 *)0x0) {
      return 0;
    }
    if ((*(uint *)((long)puVar1 + 0x14) & 1) == 0) break;
    if (((((*(uint *)((long)puVar1 + 0x14) & 0x500) == 0) && (*(int *)(puVar1 + 3) == param_3)) &&
        (*(int *)((long)puVar1 + 0x1c) == param_4)) &&
       ((*(int *)(puVar1 + 9) == param_2 && (*(int *)((long)puVar1 + 0x4c) == -1)))) {
      *(undefined4 *)((long)puVar1 + 0x4c) = *(undefined4 *)(param_1 + 0x9c);
      puVar1[0xb] = param_5;
      *param_7 = puVar1[0xe];
      puVar1[0xe] = 0;
      func_0x002590b0(param_8,puVar1 + 0xf,0x150);
      *param_6 = puVar1;
      return 1;
    }
    puVar1 = (undefined8 *)*puVar1;
  }
  func_0x007f1950(param_8);
  func_0x007f1810(0x7e1d6b);
  func_0x00c9aa10(0x2c,0x1299912);
                    /* WARNING: Does not return */
  pcVar2 = (code *)invalidInstructionException();
  (*pcVar2)();
}



/* ===== sub_007e1da0 | RVA 0x7e1da0 | file +0x5060 | ev_ad43b655f2016e18bc9feb05e66222236d18059f3f582208d7b85adabbb7e7a2 =====
 * Body: [{"start":"0x7e1da0","end":"0x7e1e5c"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_007e1da0(undefined8 param_1,int param_2)

{
  code *pcVar1;
  long lVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  
  if (param_2 != 0) {
    return 0;
  }
  lVar2 = func_0x0073dd40(0,0x136581e,0x2678a0,0x12ad8c6,0,10000);
  if (lVar2 == 0) {
    func_0x007f1950();
    func_0x007f18a0(0x7e1e05,0xffffffff800e0040);
    uVar3 = 0x1373b58;
    uVar4 = 0x48;
  }
  else {
    lVar2 = func_0x0073dd40(0,0x12e769e,0x2678a8,0x12e1a56,0,10000);
    if (lVar2 != 0) {
      sub_007e2070();
      return 0;
    }
    func_0x007f1950();
    func_0x007f18a0(0x7e1e2b,0xffffffff800e0040);
    uVar3 = 0x13a895f;
    uVar4 = 0x4c;
  }
  func_0x00c9aa10(uVar4,uVar3,0x800e0040);
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* ===== sub_007e1e60 | RVA 0x7e1e60 | file +0x5120 | ev_b7c4a4574e7e67682215c29f9491bd7f1b5c0b64895b2070dfebde2e2ec14520 =====
 * Body: [{"start":"0x7e1e60","end":"0x7e1e7a"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

void sub_007e1e60(undefined8 param_1,long param_2)

{
  *(undefined8 *)(param_2 + 0x540) = 0;
  *(undefined4 *)(param_2 + 0x548) = 0;
  return;
}



/* ===== sub_007e1e80 | RVA 0x7e1e80 | file +0x5140 | ev_a8c3b8bc4fa2f7276b9e1321d242c268edbc92be0700863581dfcf8e63c00c1b =====
 * Body: [{"start":"0x7e1e80","end":"0x7e2062"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Possible PIC construction at 0x007e202e: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x007e2033) */
/* WARNING: Removing unreachable block (ram,0x007e2042) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_007e1e80(undefined8 param_1,long param_2)

{
  code *pcVar1;
  long lVar2;
  uint uVar3;
  uint local_34;
  long local_30;
  
  local_30 = _DAT_0391c310;
  lVar2 = func_0x00c08b50(0x4000,0x253da30,0x102);
  if (lVar2 == 0) {
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  local_34 = 0;
  func_0x003997f0(_DAT_0253daa0,0x8002,lVar2,0x4000,&local_34);
  if (local_34 != 0) {
    uVar3 = 0;
    do {
      func_0x00298940(*(undefined4 *)(lVar2 + (long)(int)uVar3 * 4),param_2,0);
      uVar3 = uVar3 + 1;
    } while (uVar3 < local_34);
  }
  local_34 = 0;
  func_0x003997f0(_DAT_0253daa0,0x8004,lVar2,0x4000,&local_34);
  if (local_34 != 0) {
    uVar3 = 0;
    do {
      func_0x00a6b8a0(*(undefined4 *)(lVar2 + (long)(int)uVar3 * 4),param_2,0);
      uVar3 = uVar3 + 1;
    } while (uVar3 < local_34);
  }
  local_34 = 0;
  func_0x003997f0(_DAT_0253daa0,0x8001,lVar2,0x4000,&local_34);
  if (local_34 != 0) {
    uVar3 = 0;
    do {
      func_0x00a6aca0(*(undefined4 *)(lVar2 + (long)(int)uVar3 * 4),param_2,0);
      uVar3 = uVar3 + 1;
    } while (uVar3 < local_34);
  }
  local_34 = 0;
  func_0x003997f0(_DAT_0253daa0,0x8008,lVar2,0x4000,&local_34);
  if (local_34 != 0) {
    uVar3 = 0;
    do {
      func_0x0039f970(*(undefined4 *)(lVar2 + (long)(int)uVar3 * 4),*(undefined4 *)(param_2 + 0xbc))
      ;
      uVar3 = uVar3 + 1;
    } while (uVar3 < local_34);
  }
  func_0x00c08df0(lVar2,0x253da30);
  if (_DAT_0391c310 == local_30) {
    return;
  }
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* ===== sub_007e2070 | RVA 0x7e2070 | file +0x5330 | ev_9b15c519e5303d81d6cc87211d6f049848667f3ba7f0fb765b6f848a5b4f028e =====
 * Body: [{"start":"0x7e2070","end":"0x7e2270"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_007e2070(void)

{
  code *pcVar1;
  long lVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  undefined8 uVar5;
  
  _DAT_0253daa0 = func_0x003997e0(0x1320195);
  if (_DAT_0253daa0 == 0) {
    func_0x007f1950();
    func_0x007f1810(0x7e21aa);
    uVar3 = 0x137e045;
    uVar4 = 0x34;
  }
  else {
    lVar2 = func_0x00c08b50(0x48,0x253da30,0x102);
    _DAT_0253daa8 = lVar2;
    if (lVar2 != 0) {
      *(undefined8 *)(lVar2 + 0x30) = 0;
      *(undefined8 *)(lVar2 + 0x20) = 0;
      *(long *)(lVar2 + 0x28) = lVar2 + 0x20;
      *(undefined8 *)(lVar2 + 0x38) = 0;
      *(long *)(lVar2 + 0x40) = lVar2 + 0x38;
      func_0x00c4b290(lVar2,0x12ad8d8,0);
      _DAT_0253dab0 = func_0x0043b0e0(0x1388b6f,0x908,0,0,0,0,7,0);
      if (_DAT_0253dab0 == 0) {
        func_0x007f1950();
        func_0x007f18a0(0x7e21ef,0x908);
        uVar4 = 0x12a3a33;
        uVar3 = 0x908;
        uVar5 = 0x3c;
      }
      else {
        _DAT_0253dab8 = func_0x0043b0e0(0x127b001,0x1c8,0,0,0,0,7,0);
        if (_DAT_0253dab8 == 0) {
          func_0x007f1950();
          func_0x007f18a0(0x7e2218,0x1c8);
          uVar4 = 0x1349e73;
          uVar3 = 0x1c8;
          uVar5 = 0x40;
        }
        else {
          _DAT_0253dac0 = func_0x0043b0e0(0x130080a,0x20,0,0,0,0,7,0);
          if (_DAT_0253dac0 != 0) {
            func_0x0060ee90();
            func_0x003a1a30();
            func_0x00b68090();
            func_0x00bff720();
            func_0x00c00af0();
                    /* WARNING: Bad instruction - Truncating control flow here */
            halt_baddata();
          }
          func_0x007f1950();
          func_0x007f18a0(0x7e2241,0x20);
          uVar4 = 0x12a3a66;
          uVar3 = 0x20;
          uVar5 = 0x44;
        }
      }
      func_0x00c9aa10(uVar5,uVar4,uVar3);
                    /* WARNING: Does not return */
      pcVar1 = (code *)invalidInstructionException();
      (*pcVar1)();
    }
    func_0x007f1950();
    func_0x007f1810(0x7e21c9);
    uVar3 = 0x132a9d1;
    uVar4 = 0x38;
  }
  func_0x00c9aa10(uVar4,uVar3);
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* ===== sub_007e2280 | RVA 0x7e2280 | file +0x5540 | ev_c3e9c7cd6aab319d8c5cf64e35840bfe21328d8c81062d781a1b26387367de21 =====
 * Body: [{"start":"0x7e2280","end":"0x7e2298"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

undefined8 sub_007e2280(int *param_1,undefined4 *param_2)

{
  *param_2 = *(undefined4 *)((long)param_1 + (ulong)(*param_1 + 3U & 0xfffffffc) + 0xc);
  return 1;
}



/* ===== sub_007e22a0 | RVA 0x7e22a0 | file +0x5560 | ev_5a9d9c0d0845474956a070047de832d4a7f7c56a2cc49de99183f8f44621b372 =====
 * Body: [{"start":"0x7e22a0","end":"0x7e22d3"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

bool sub_007e22a0(int *param_1,int *param_2)

{
  ulong uVar1;
  bool bVar2;
  
  uVar1 = (ulong)(*param_1 + 3U & 0xfffffffc);
  bVar2 = *(int *)((long)param_1 + uVar1 + 0xc) == 3;
  if (bVar2) {
    *param_2 = *(int *)((long)param_1 + uVar1 + 0x14) * 1000 +
               *(int *)((long)param_1 + uVar1 + 0x10) * 100000 +
               *(int *)((long)param_1 + uVar1 + 0x18);
  }
  return bVar2;
}



/* ===== sub_007e22e0 | RVA 0x7e22e0 | file +0x55a0 | ev_016f490b7cd74797fd10e0503aaf641db5fe710b99137015d85831e98dbfee28 =====
 * Body: [{"start":"0x7e22e0","end":"0x7e239e"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_007e22e0(undefined8 param_1)

{
  undefined8 *puVar1;
  
  if (_DAT_03a34ff0 == 0) {
    puVar1 = (undefined8 *)&DAT_03a34ff0;
  }
  else if (_DAT_03a34ff8 == 0) {
    puVar1 = (undefined8 *)&DAT_03a34ff8;
  }
  else if (_DAT_03a35000 == 0) {
    puVar1 = (undefined8 *)&DAT_03a35000;
  }
  else if (_DAT_03a35008 == 0) {
    puVar1 = (undefined8 *)&DAT_03a35008;
  }
  else if (_DAT_03a35010 == 0) {
    puVar1 = (undefined8 *)&DAT_03a35010;
  }
  else if (_DAT_03a35018 == 0) {
    puVar1 = (undefined8 *)&DAT_03a35018;
  }
  else if (_DAT_03a35020 == 0) {
    puVar1 = (undefined8 *)&DAT_03a35020;
  }
  else {
    if (_DAT_03a35028 != 0) {
      func_0x0025d410(0x1373b93,0x1354db5);
      return 0xffffffff;
    }
    puVar1 = (undefined8 *)&DAT_03a35028;
  }
  *puVar1 = param_1;
  return 0;
}



/* ===== sub_007e23a0 | RVA 0x7e23a0 | file +0x5660 | ev_e333f466d23dec410eb0b5f0a0515c8bdf67147c67b1bd3ec97d5bb16a19e4a6 =====
 * Body: [{"start":"0x7e23a0","end":"0x7e2712"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_007e23a0(long *param_1,long *param_2)

{
  long *plVar1;
  uint uVar2;
  undefined8 extraout_RDX;
  long lVar3;
  long lVar4;
  long lVar5;
  
  plVar1 = (long *)param_2[9];
  lVar3 = *param_1;
  lVar4 = lVar3 + (long)(*(int *)(param_2[0xd] + 0x34) + 2 + *(int *)(param_2[0xd] + 0x38)) * 8;
  if (*plVar1 != -1) {
    lVar5 = lVar4 + 8;
    func_0x00259720(lVar4,2);
    lVar4 = lVar4 + 0x10;
    func_0x00259720(lVar5,*plVar1);
  }
  func_0x00259720(lVar4,3);
  func_0x00259720(lVar4 + 8,plVar1[1]);
  func_0x00259720(lVar4 + 0x10,4);
  func_0x00259720(lVar4 + 0x18,plVar1[2]);
  func_0x00259720(lVar4 + 0x20,5);
  func_0x00259720(lVar4 + 0x28,plVar1[3]);
  func_0x00259720(lVar4 + 0x30,6);
  func_0x00259720(lVar4 + 0x38,plVar1[4]);
  func_0x00259720(lVar4 + 0x40,8);
  func_0x00259720(lVar4 + 0x48,plVar1[6]);
  func_0x00259720(lVar4 + 0x50,9);
  func_0x00259720(lVar4 + 0x58,plVar1[7]);
  func_0x00259720(lVar4 + 0x60,7);
  lVar5 = lVar4 + 0x70;
  func_0x00259720(lVar4 + 0x68,plVar1[5]);
  if (param_2[0x10] != 0) {
    func_0x00259720(lVar5,0xf);
    lVar5 = lVar4 + 0x80;
    func_0x00259720(lVar4 + 0x78,param_2[0x10]);
  }
  func_0x00259720(lVar5,0x12);
  lVar4 = lVar5 + 0x10;
  func_0x00259720(lVar5 + 8,(long)*(int *)(*(long *)(*(long *)(*param_2 + 0x40) + 0x30) + 0x114));
  if (param_2[0x12] != 0) {
    func_0x00259720(lVar4,0x10);
    func_0x00259720(lVar5 + 0x18,param_2[0x12]);
    func_0x00259720(lVar5 + 0x20,0x11);
    lVar4 = lVar5 + 0x30;
    func_0x00259720(lVar5 + 0x28,(long)(int)param_2[0x13]);
  }
  func_0x00259720(lVar4,0x13);
  lVar5 = lVar4 + 0x10;
  func_0x00259720(lVar4 + 8,(long)_DAT_03d0e8bc);
  if (param_2[0x14] != 0) {
    func_0x00259720(lVar5,0x14);
    func_0x00259720(lVar4 + 0x18,param_2[0x14]);
    func_0x00259720(lVar4 + 0x20,0x15);
    lVar5 = lVar4 + 0x30;
    func_0x00259720(lVar4 + 0x28,(long)(int)param_2[0x15]);
  }
  if (*(ulong *)(param_2[0xe] + 0xc0) <= *(ulong *)(param_2[0xe] + 200)) {
    lVar4 = lVar5 + 8;
    func_0x00259720(lVar5,0x16);
    lVar5 = lVar5 + 0x10;
    func_0x00259720(lVar4,*(long *)(*(long *)(*param_2 + 0x200) + 0x218) +
                          *(long *)(param_2[0xe] + 200));
  }
  func_0x00259720(lVar5,0x17);
  if ((*(long *)(param_2[0xe] + 0xd8) == 0) ||
     (uVar2 = (uint)*(ushort *)((long)param_2 + 0xac), *(ushort *)((long)param_2 + 0xac) == 0)) {
    uVar2 = *(uint *)(param_2[0xe] + 0x78);
  }
  func_0x00259720(lVar5 + 8,(long)(int)uVar2,extraout_RDX,uVar2);
  func_0x00259720(lVar5 + 0x10,0);
  func_0x00259720(lVar5 + 0x18,0);
  func_0x00c08df0(param_2[9],0x2bfc080);
  param_2[9] = 0;
  lVar3 = lVar3 + -8;
  func_0x00259720(lVar3,(long)*(int *)(param_2[0xd] + 0x34));
  *param_1 = lVar3;
  return 0;
}



/* ===== sub_007e2720 | RVA 0x7e2720 | file +0x59e0 | ev_045baada16b175d5aaa1ffa3f5006f7127dc77a3282fb469ee3281853fe4e3a5 =====
 * Body: [{"start":"0x7e2720","end":"0x7e27e2"},{"start":"0x7e27f0","end":"0x7e2919"},{"start":"0x7e2920","end":"0x7e2d3c"}]
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.","Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.","Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.","Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_007e2720(long param_1)

{
  int iVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  undefined4 *puVar5;
  undefined8 uVar6;
  long *plVar7;
  long lVar8;
  bool bVar9;
  undefined8 local_a0 [6];
  undefined8 local_70;
  undefined8 *local_68;
  undefined4 local_60;
  undefined8 local_58;
  undefined4 local_50 [6];
  undefined8 local_38;
  
  local_68 = &local_70;
  local_38 = _DAT_0391c310;
  local_70 = 0;
  local_60 = 0;
  local_58 = 0;
  lVar2 = *(long *)(*(long *)(param_1 + 8) + 0x200);
  func_0x002c6820(lVar2,0,0);
  lVar8 = *(long *)(lVar2 + 8);
  do {
    if (lVar8 == lVar2) {
      func_0x002c6870(lVar2,0,0);
      lVar2 = *(long *)(param_1 + 8);
      puVar5 = (undefined4 *)func_0x00c08b50(0x30,0x2bfc080,0x102);
      *puVar5 = 3;
      *(undefined8 *)(puVar5 + 2) = 0x268318;
      *(long *)(puVar5 + 4) = lVar2;
      *(undefined8 *)(puVar5 + 6) = 0x78;
      *(undefined8 *)(puVar5 + 8) = 0;
      *(undefined8 **)(puVar5 + 10) = local_68;
      *local_68 = puVar5;
      lVar8 = param_1;
      local_68 = (undefined8 *)(puVar5 + 8);
      do {
        puVar5 = (undefined4 *)func_0x00c08b50(0x30,0x2bfc080,0x102);
        *puVar5 = 1;
        *(undefined8 *)(puVar5 + 2) = 0x268320;
        *(long *)(puVar5 + 4) = lVar8;
        *(undefined8 *)(puVar5 + 6) = 0xe0;
        *(undefined8 *)(puVar5 + 8) = 0;
        *(undefined8 **)(puVar5 + 10) = local_68;
        *local_68 = puVar5;
        local_68 = (undefined8 *)(puVar5 + 8);
        puVar5 = (undefined4 *)func_0x00c08b50(0x30,0x2bfc080,0x102);
        *puVar5 = 2;
        *(undefined8 *)(puVar5 + 2) = 0x268328;
        *(long *)(puVar5 + 4) = lVar8;
        *(undefined8 *)(puVar5 + 6) = 0x200;
        *(undefined8 *)(puVar5 + 8) = 0;
        *(undefined8 **)(puVar5 + 10) = local_68;
        *local_68 = puVar5;
        local_68 = (undefined8 *)(puVar5 + 8);
        puVar5 = (undefined4 *)func_0x00c08b50(0x30,0x2bfc080,0x102);
        *puVar5 = 7;
        *(undefined8 *)(puVar5 + 2) = 0x268330;
        *(long *)(puVar5 + 4) = lVar8;
        *(undefined8 *)(puVar5 + 6) = 0x18;
        *(undefined8 *)(puVar5 + 8) = 0;
        *(undefined8 **)(puVar5 + 10) = local_68;
        *local_68 = puVar5;
        local_a0[0] = 0;
        local_68 = (undefined8 *)(puVar5 + 8);
        func_0x00b5ef00(lVar8,0,local_a0);
        func_0x00c08df0(0,0x2bfc080);
        uVar6 = local_a0[0];
        puVar5 = (undefined4 *)func_0x00c08b50(0x30,0x2bfc080,0x102);
        *puVar5 = 0xffffffff;
        *(undefined8 *)(puVar5 + 2) = 0x268338;
        *(long *)(puVar5 + 4) = lVar8;
        *(undefined8 *)(puVar5 + 6) = uVar6;
        *(undefined8 *)(puVar5 + 8) = 0;
        *(undefined8 **)(puVar5 + 10) = local_68;
        *local_68 = puVar5;
        if (lVar8 == param_1) {
          lVar8 = lVar2;
        }
        lVar8 = *(long *)(lVar8 + 0x10);
        if (lVar8 == param_1) {
          lVar8 = *(long *)(lVar8 + 0x10);
        }
        local_68 = (undefined8 *)(puVar5 + 8);
      } while (lVar8 != 0);
      iVar1 = *(int *)(lVar2 + 0xb48);
      puVar5 = (undefined4 *)func_0x00c08b50(0x30,0x2bfc080,0x102);
      *puVar5 = 8;
      *(undefined8 *)(puVar5 + 2) = 0x268340;
      *(long *)(puVar5 + 4) = lVar2;
      *(long *)(puVar5 + 6) = (long)iVar1 * 0x448 + 4;
      *(undefined8 *)(puVar5 + 8) = 0;
      *(undefined8 **)(puVar5 + 10) = local_68;
      *local_68 = puVar5;
      local_50[0] = 0x570;
      local_a0[0] = 0;
      bVar9 = _DAT_021fa440 != 0;
      local_68 = (undefined8 *)(puVar5 + 8);
      uVar6 = func_0x008be420(0,0,0x80,0);
      func_0x008be660(uVar6,0x26c0d0,local_a0);
      func_0x008be670(uVar6,local_50,4);
      func_0x004c6a00(lVar2 + 0x148,0,0,0);
      func_0x0072f300(lVar2,uVar6,0xffffffffffffffff,bVar9);
      func_0x008beae0(uVar6);
      func_0x008be5b0(uVar6);
      uVar6 = local_a0[0];
      puVar5 = (undefined4 *)func_0x00c08b50(0x30,0x2bfc080,0x102);
      *puVar5 = 9;
      *(undefined8 *)(puVar5 + 2) = 0x268348;
      *(long *)(puVar5 + 4) = lVar2;
      *(undefined8 *)(puVar5 + 6) = uVar6;
      *(undefined8 *)(puVar5 + 8) = 0;
      *(undefined8 **)(puVar5 + 10) = local_68;
      *local_68 = puVar5;
      local_50[0] = 0x488;
      local_a0[0] = 0;
      bVar9 = _DAT_021fa4a8 != 0;
      local_68 = (undefined8 *)(puVar5 + 8);
      uVar6 = func_0x008be420(0,0,0x80,0);
      func_0x008be660(uVar6,0x26c0d0,local_a0);
      func_0x008be670(uVar6,local_50,4);
      func_0x004c6a00(lVar2 + 0x148,0,0,0);
      func_0x0053e1b0(lVar2,uVar6,0xffffffffffffffff,bVar9);
      func_0x008beae0(uVar6);
      func_0x008be5b0(uVar6);
      uVar6 = local_a0[0];
      puVar5 = (undefined4 *)func_0x00c08b50(0x30,0x2bfc080,0x102);
      *puVar5 = 10;
      *(undefined8 *)(puVar5 + 2) = 0x268350;
      *(long *)(puVar5 + 4) = lVar2;
      *(undefined8 *)(puVar5 + 6) = uVar6;
      *(undefined8 *)(puVar5 + 8) = 0;
      *(undefined8 **)(puVar5 + 10) = local_68;
      *local_68 = puVar5;
      iVar1 = *(int *)(*(long *)(lVar2 + 0x40) + 0x10);
      local_68 = (undefined8 *)(puVar5 + 8);
      plVar7 = (long *)func_0x00c08b50(0x30,0x2bfc080,0x102);
      *(undefined4 *)plVar7 = 0xb;
      plVar7[1] = 0x268358;
      plVar7[2] = lVar2;
      *plVar7 = (long)iVar1 * 4 + 4;
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    if (_DAT_03a35030 == 0) {
      if ((*(ushort *)(lVar8 + 100) & 7) != 0) goto LAB_007e27f4;
    }
    else if ((~*(ushort *)(lVar8 + 100) & 3) == 0) {
LAB_007e27f4:
      if (((*(ushort *)(lVar8 + 0x60) & 0x402) == 0) &&
         (lVar3 = *(long *)(lVar8 + 0x50), lVar3 != 0)) {
        func_0x007d50c0(lVar3 + 0x18,0,0);
        for (lVar4 = *(long *)(lVar3 + 0xb0); lVar4 != 0; lVar4 = *(long *)(lVar4 + 0xb0)) {
          func_0x007d50c0(lVar4 + 0x18,0,0);
          func_0x007d56e0(lVar3 + 0x18,0,0);
          lVar3 = lVar4;
        }
        if ((*(byte *)(lVar3 + 0x9d) < 5) && (*(byte *)(lVar3 + 0x9d) != 3)) {
          func_0x007d56e0(lVar3 + 0x18,0,0);
          func_0x002678b0(lVar8);
        }
        else {
          func_0x007d56e0(lVar3 + 0x18,0,0);
        }
      }
    }
    lVar8 = *(long *)(lVar8 + 8);
  } while( true );
}


