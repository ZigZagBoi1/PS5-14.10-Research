/* 13.60-labeled; acquisition authenticity unresolved; Ghidra pseudocode, not original source. */

/* WARNING: Type propagation algorithm not settling */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int ref_body_003b0210(long param_1,undefined8 param_2,ulong param_3,undefined8 param_4,uint param_5,
                     long param_6)

{
  long *plVar1;
  byte *pbVar2;
  code *pcVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  long lVar7;
  long *plVar8;
  long *plVar9;
  ulong uVar10;
  uint uVar11;
  undefined8 uVar12;
  long lVar13;
  int *piVar14;
  ulong *puVar15;
  undefined8 uVar16;
  undefined4 uVar17;
  uint uVar18;
  uint uVar19;
  int *piVar20;
  ulong uVar21;
  ulong uVar22;
  undefined8 *in_GS_OFFSET;
  bool bVar23;
  undefined1 auStack_180 [20];
  int iStack_16c;
  long lStack_168;
  ulong uStack_160;
  uint uStack_154;
  int *piStack_150;
  int *piStack_148;
  long *plStack_140;
  ulong *puStack_138;
  long lStack_130;
  short *psStack_128;
  long lStack_120;
  long lStack_118;
  ulong uStack_110;
  undefined4 uStack_104;
  long lStack_100;
  long lStack_f8;
  long lStack_f0;
  undefined8 uStack_e8;
  undefined8 uStack_e0;
  ulong uStack_d8;
  ulong uStack_d0;
  long lStack_c8;
  ulong uStack_c0;
  long lStack_b8;
  long lStack_b0;
  long lStack_a8;
  uint auStack_a0 [6];
  undefined1 auStack_88 [12];
  int iStack_7c;
  uint uStack_78;
  int aiStack_74 [3];
  long lStack_68;
  long lStack_60;

  piVar14 = (int *)auStack_180;
  lStack_60 = lRam000000000391c310;
  lVar13 = *(long *)(param_1 + 8);
  uStack_e0 = *(undefined8 *)(lVar13 + 0xc48);
  aiStack_74[2] = 0;
  aiStack_74[1] = 0;
  uStack_78 = 0;
  lStack_120 = param_6;
  lStack_118 = param_1;
  uStack_110 = param_3;
  uStack_e8 = param_4;
  lVar7 = func_0x009f8180(lVar13);
  iVar5 = func_0x009f81c0(lVar13,auStack_a0);
  lVar13 = 0x34cf8c8;
  uVar17 = 0;
  if ((iVar5 == 0) && (auStack_a0[0] < 0x1000000)) {
    if (auStack_a0[0] < 0x10000) {
      uVar17 = 1;
      if (_DAT_034cf7c8 == lVar7) {
        lVar13 = 0x34cf320;
        goto LAB_003b0339;
      }
      if (_DAT_034d08c0 == lVar7) {
        lVar13 = 0x34d0418;
        iVar5 = iRam00000000034d08b8;
      }
      else {
        lVar13 = 0x34d0418;
        if (_DAT_034cf7c0 == 0) {
          lVar13 = 0x34cf320;
        }
        iVar5 = *(int *)(lVar13 + 0x4a0);
      }
    }
    else {
      lVar13 = 0x34cf8c8;
      if ((auStack_a0[0] & 0xff0000) == 0x10000) {
        lVar13 = 0x34cfe70;
      }
      iVar5 = *(int *)(lVar13 + 0x4a0);
    }
    uVar17 = 1;
    uVar4 = 1;
    if (iVar5 == 1) goto LAB_003b0384;
LAB_003b0342:
    uVar17 = uVar4;
    iVar5 = func_0x003b3410(1);
    if (iVar5 == 0) goto LAB_003b0384;
    uVar12 = 0xffc;
  }
  else {
LAB_003b0339:
    uVar4 = uVar17;
    if (*(int *)(lVar13 + 0x4a0) != 1) goto LAB_003b0342;
LAB_003b0384:
    uVar11 = (uint)uStack_110;
    if (uVar11 - 0x81 < 0xffffff80) {
      iVar5 = 0x16;
      uVar12 = 0x1002;
      piVar14 = (int *)auStack_180;
    }
    else if (param_5 < 3) {
      uStack_160 = uStack_110 & 0xffffffff;
      uStack_154 = param_5;
      lStack_f0 = lVar13;
      if (uVar11 < 2) {
        piStack_148 = aiStack_74 + 1;
        piVar20 = aiStack_74 + 2;
        piVar14 = (int *)auStack_180;
      }
      else {
        uVar22 = (ulong)(uVar11 * 4 + 0xf & 0xfffffff0);
        piVar20 = (int *)((ulong)(auStack_180 + -uVar22) & 0xffffffffffffffe0);
        piVar14 = (int *)((long)piVar20 - uVar22 & 0xffffffffffffffe0);
        piVar14[-2] = 0x3b0408;
        piVar14[-1] = 0;
        piStack_148 = piVar14;
        func_0x00258ff0(piVar14,uVar11 * 4);
      }
      uVar12 = *in_GS_OFFSET;
      lVar13 = uStack_160 * 4;
      piVar14[-2] = 0x3b045f;
      piVar14[-1] = 0;
      func_0x00c1a3e0(uVar12,&UNK_01397f3d,0);
      piVar14[-2] = 0x3b046d;
      piVar14[-1] = 0;
      iVar5 = func_0x00259280(param_2,piVar20,lVar13);
      lVar7 = lStack_120;
      if (iVar5 == 0) {
        piStack_150 = piVar20;
        lStack_100 = lVar13;
        if (lStack_120 != 0) {
          uVar12 = *in_GS_OFFSET;
          piVar14[-2] = 0x3b04e4;
          piVar14[-1] = 0;
          func_0x00c1a3e0(uVar12,&UNK_01397f3d,0);
          piVar14[-2] = 0x3b04f8;
          piVar14[-1] = 0;
          iVar5 = func_0x00259280(lVar7,&uStack_78,4);
          if (iVar5 != 0) {
            uVar12 = 0x1022;
            goto LAB_003b0489;
          }
        }
        piVar14[-2] = 0x3b051c;
        piVar14[-1] = 0;
        iVar5 = func_0x00b078d0();
        uVar22 = uStack_160;
        uStack_104 = uVar17;
        if (iVar5 == 0) {
          lStack_f8 = 0;
        }
        else {
          lVar13 = uStack_160 * 0x18;
          piVar14[-2] = 0x3b0545;
          piVar14[-1] = 0;
          lStack_f8 = func_0x00c08b50(lVar13,0x1a7d800,0x102);
        }
        uVar11 = uStack_154;
        iStack_7c = 0;
        piVar14[-2] = 0x3b0576;
        piVar14[-1] = 0;
        func_0x004c7dd0(auStack_88,&UNK_012e78de,0,0);
        piVar14[-2] = 0x3b058b;
        piVar14[-1] = 0;
        plVar8 = (long *)func_0x00c08b50(uVar22 * 0x38,0x1ab5a50,0x102);
        if (uVar11 == 2) {
          iStack_7c = 1;
          aiStack_74[0] = 0;
        }
        puVar15 = (ulong *)(lStack_f8 + 0x10);
        uVar21 = 0;
        iStack_16c = 0;
        uVar22 = uStack_160;
        piVar20 = piStack_150;
        uVar11 = 0;
        plStack_140 = plVar8;
        do {
          uVar12 = uStack_e0;
          uVar19 = piVar20[uVar21] >> 0x10;
          uVar18 = piVar20[uVar21] & 0xffff;
          if (uVar18 == 0 || 0x7f < uVar19) {
            *(undefined4 *)(plVar8 + 4) = 0x80020003;
            uVar18 = uVar11;
          }
          else {
            puStack_138 = puVar15;
            if (uVar18 != uVar11) {
              piVar14[-2] = 0x3b0639;
              piVar14[-1] = 0;
              psStack_128 = (short *)func_0x00399ee0(uVar12,uVar18,0x160,&lStack_68);
              if (psStack_128 == (short *)0x0) {
                *(undefined4 *)(plVar8 + 4) = 0x80020003;
                uVar18 = 0;
                psStack_128 = (short *)0x0;
                uVar22 = uStack_160;
                piVar20 = piStack_150;
                puVar15 = puStack_138;
                goto LAB_003b05db;
              }
              plVar8[5] = lStack_68;
            }
            lVar13 = lStack_68;
            if ((int)uVar19 < (int)*psStack_128) {
              piVar14[-2] = 0x3b0665;
              piVar14[-1] = 0;
              iVar5 = func_0x00399e20(lVar13);
              if (iVar5 == 0) {
                lVar13 = *(long *)(*(long *)(psStack_128 + 0x14) + (ulong)uVar19 * 8);
                if (lVar13 != 0) {
                  lStack_168 = CONCAT71(lStack_168._1_7_,lStack_f8 != 0);
                  uStack_d8 = (ulong)uVar19;
                  piVar14[-2] = 0x3b0708;
                  piVar14[-1] = 0;
                  iVar5 = func_0x00b078d0();
                  if ((iVar5 != 0 & (byte)lStack_168) == 1) {
                    *(int *)(puStack_138 + -2) = piStack_150[uVar21];
                    puStack_138[-1] = **(ulong **)(lVar13 + 0x18);
                    *puStack_138 = (long)*(ulong *)(lVar13 + 0x10) >> 4 ^ *(ulong *)(lVar13 + 0x10);
                  }
                  lVar13 = *(long *)(lVar13 + 0x20);
                  if (lVar13 == 0) {
                    piVar14[-2] = 0x3b0768;
                    piVar14[-1] = 0;
                    func_0x0025d410(&UNK_01379d8c,&UNK_01379d7c,0x107f,uVar21 & 0xffffffff,0);
                  }
                  lStack_168 = lVar13 + 0x20;
                  piVar14[-2] = 0;
                  piVar14[-1] = 0;
                  piVar14[-4] = 0;
                  piVar14[-3] = 0;
                  piVar14[-6] = 0x3b0788;
                  piVar14[-5] = 0;
                  func_0x00bf1770(lVar13 + 0x20,0x80000,0,0,0,0);
                  if (uStack_154 == 1) {
                    uVar11 = *(uint *)(lVar13 + 8);
                    *(uint *)(plVar8 + 4) = uVar11;
                    if ((int)uVar11 < 3) {
                      lStack_130 = lVar13;
                      piVar14[-2] = 0x3b07c5;
                      piVar14[-1] = 0;
                      func_0x004c6a00(auStack_88,0,0,0);
                      iStack_7c = iStack_7c + 1;
                      *plVar8 = (long)&iStack_7c;
                      plVar8[2] = (long)auStack_a0;
                      piVar14[-2] = 0x3b07ee;
                      piVar14[-1] = 0;
                      func_0x004c6fa0(auStack_88,0,0,0);
                      if (*(int *)(lStack_130 + 8) < 3) {
                        iStack_16c = 0;
                        plVar8[6] = *(long *)(lStack_130 + 0x50);
                        *(long **)(lStack_130 + 0x50) = plVar8;
                        plVar8[3] = lStack_130;
                      }
                      else {
LAB_003b0976:
                        piVar14[-2] = 0x3b0990;
                        piVar14[-1] = 0;
                        func_0x0025d410(&UNK_0136599c,&UNK_012bdac0,0xfa9);
                        piVar14[-2] = 0x3b09a5;
                        piVar14[-1] = 0;
                        func_0x004c6a00(auStack_88,0,0,0);
                        iStack_7c = iStack_7c + -1;
                        piVar14[-2] = 0x3b09b9;
                        piVar14[-1] = 0;
                        func_0x004c6fa0(auStack_88,0,0,0);
                        iStack_16c = 0x10;
                      }
                    }
                    else {
LAB_003b08cd:
                      if (*(char *)(lVar13 + 0xc) == '\0') {
                        *(undefined1 *)(lVar13 + 0xc) = 1;
                      }
                      else {
                        *(uint *)(plVar8 + 4) = uVar11 | 0x10000;
                      }
                    }
                  }
                  else if (uStack_154 == 2) {
                    uVar11 = *(uint *)(lVar13 + 8);
                    *(uint *)(plVar8 + 4) = uVar11;
                    lStack_130 = lVar13;
                    if (2 < (int)uVar11) goto LAB_003b08cd;
                    piVar14[-2] = 0x3b086f;
                    piVar14[-1] = 0;
                    func_0x004c6a00(auStack_88,0,0,0);
                    aiStack_74[0] = aiStack_74[0] + 1;
                    *plVar8 = (long)&iStack_7c;
                    plVar8[2] = (long)auStack_a0;
                    plVar8[1] = (long)aiStack_74;
                    piVar14[-2] = 0x3b08a3;
                    piVar14[-1] = 0;
                    func_0x004c6fa0(auStack_88,0,0,0);
                    if (*(int *)(lStack_130 + 8) < 3) {
                      iStack_16c = 0;
                      plVar8[6] = *(long *)(lStack_130 + 0x50);
                      *(long **)(lStack_130 + 0x50) = plVar8;
                      plVar8[3] = lStack_130;
                    }
                    else {
                      piVar14[-2] = 0x3b09f3;
                      piVar14[-1] = 0;
                      func_0x0025d410(&UNK_0136599c,&UNK_012bdac0,0xfa9);
                      iStack_16c = 0x10;
                    }
                  }
                  else {
                    lVar7 = *(long *)(*(long *)(*(long *)(psStack_128 + 0x14) + uStack_d8 * 8) +
                                     0x20);
                    uVar11 = *(uint *)(lVar7 + 8);
                    *(uint *)(plStack_140 + 4) = uVar11;
                    if ((int)uVar11 < 3) {
                      lStack_130 = lVar13;
                      piVar14[-2] = 0x3b091e;
                      piVar14[-1] = 0;
                      func_0x004c6a00(auStack_88,0,0,0);
                      iStack_7c = iStack_7c + 1;
                      *plStack_140 = (long)&iStack_7c;
                      plStack_140[2] = (long)auStack_a0;
                      piVar14[-2] = 0x3b094f;
                      piVar14[-1] = 0;
                      func_0x004c6fa0(auStack_88,0,0,0);
                      if (2 < *(int *)(lVar7 + 8)) goto LAB_003b0976;
                      iStack_16c = 0;
                      plStack_140[6] = *(long *)(lVar7 + 0x50);
                      *(long **)(lVar7 + 0x50) = plStack_140;
                      plStack_140[3] = lVar7;
                    }
                    else if (*(char *)(lVar7 + 0xc) == '\0') {
                      *(undefined1 *)(lVar7 + 0xc) = 1;
                      lStack_130 = lVar13;
                    }
                    else {
                      *(uint *)(plStack_140 + 4) = uVar11 | 0x10000;
                      lStack_130 = lVar13;
                    }
                  }
                  lVar13 = lStack_168;
                  piVar14[-2] = 0;
                  piVar14[-1] = 0;
                  piVar14[-4] = 0;
                  piVar14[-3] = 0;
                  piVar14[-6] = 0x3b0a1d;
                  piVar14[-5] = 0;
                  func_0x00bf1770(lVar13,0x100000,0,0,0,0);
                  uVar22 = uStack_160;
                  piVar20 = piStack_150;
                  puVar15 = puStack_138;
                  goto LAB_003b05db;
                }
                *(undefined4 *)(plVar8 + 4) = 0x80020003;
                uVar12 = 0x1071;
                goto LAB_003b06ab;
              }
              *(undefined4 *)(plVar8 + 4) = 0x80020001;
              uVar12 = 0x106a;
              uVar16 = 1;
            }
            else {
              uVar12 = 0x1064;
              *(undefined4 *)(plVar8 + 4) = 0x80020003;
LAB_003b06ab:
              uVar16 = 3;
            }
            piVar14[-2] = 0x3b06bb;
            piVar14[-1] = 0;
            func_0x0025d410(&UNK_0135b377,&UNK_01379d7c,uVar12,uVar21 & 0xffffffff,uVar16);
            uVar22 = uStack_160;
            piVar20 = piStack_150;
            puVar15 = puStack_138;
          }
LAB_003b05db:
          lVar13 = lStack_f8;
          uVar21 = uVar21 + 1;
          plVar8 = plVar8 + 7;
          puVar15 = puVar15 + 3;
          uVar11 = uVar18;
        } while (uVar22 != uVar21);
        bVar23 = lStack_f8 != 0;
        piVar14[-2] = 0x3b0a54;
        piVar14[-1] = 0;
        iVar5 = func_0x00b078d0();
        uVar18 = uStack_78;
        uVar22 = uStack_110;
        lVar7 = lStack_118;
        uVar11 = uStack_154;
        if (iVar5 != 0 && bVar23) {
          piVar14[-2] = 0x3b0a7d;
          piVar14[-1] = 0;
          func_0x000a3af0(lVar7,uVar22,uVar11,uVar18,lVar13);
          piVar14[-2] = 0x3b0a8c;
          piVar14[-1] = 0;
          func_0x00c08df0(lVar13,0x1a7d800);
        }
        piVar14[-2] = 0x3b0aa1;
        piVar14[-1] = 0;
        func_0x004c6a00(auStack_88,0,0,0);
        lVar13 = lStack_120;
        if ((0 < iStack_7c) && ((uVar11 != 2 || (aiStack_74[0] != 0)))) {
          piVar14[-2] = 0x3b0ad7;
          piVar14[-1] = 0;
          func_0x004c6a00(0x34cf2e8,0,0,0);
          lVar7 = lStack_f0;
          if (*(long *)(lStack_f0 + 0x4b0) != 0) {
            piVar14[-2] = 0x3b0af9;
            piVar14[-1] = 0;
            func_0x0073ef80(0x34cf2f0);
          }
          if (*(long *)(lVar7 + 0x528) != 0) {
            piVar14[-2] = 0x3b0b1b;
            piVar14[-1] = 0;
            func_0x0073ef80(0x34cf2f0);
          }
          piVar14[-2] = 0x3b0b2d;
          piVar14[-1] = 0;
          func_0x004c6fa0(0x34cf2e8,0,0,0);
          if (uStack_78 == 0) {
            piVar14[-4] = 0x100;
            piVar14[-3] = 0;
            piVar14[-6] = 0x3b0cca;
            piVar14[-5] = 0;
            iVar5 = func_0x00c06260(&iStack_7c,auStack_a0,0x104c,&UNK_012f1fc8,0,0);
            iStack_16c = 4;
            if (iVar5 != -1) {
              iStack_16c = iVar5;
            }
          }
          else {
            uVar21 = (ulong)uStack_78 / 1000000;
            uVar22 = (ulong)((uStack_78 % 1000000) * 1000);
            while( true ) {
              lStack_c8 = (long)uVar22 / 1000;
              uVar12 = *in_GS_OFFSET;
              uStack_d0 = uVar21;
              piVar14[-2] = 0x3b0bc2;
              piVar14[-1] = 0;
              func_0x006bc2a0(uVar12,&lStack_b0);
              lVar13 = _DAT_039203d0;
              piVar14[-2] = 0x3b0bd5;
              piVar14[-1] = 0;
              iVar5 = func_0x00c66c80(&uStack_d0);
              piVar14[-4] = 0x100;
              piVar14[-3] = 0;
              piVar14[-6] = 0x3b0c07;
              piVar14[-5] = 0;
              iVar5 = func_0x00c06260(&iStack_7c,auStack_a0,0x104c,&UNK_012f1fc8,iVar5 * lVar13,0);
              piVar14[-2] = 0x3b0c1d;
              piVar14[-1] = 0;
              func_0x006bc2a0(uVar12,&uStack_c0);
              uVar10 = uStack_c0 - lStack_b0;
              if ((iVar5 != 0x23 && iVar5 != 0) || (iStack_7c < 1)) break;
              lVar13 = lStack_b8 - lStack_a8;
              if (lVar13 < 0) {
                uVar10 = uVar10 - 1;
                lVar13 = lVar13 + 1000000000;
              }
              lVar7 = uVar21 - uVar10;
              uStack_c0 = uVar10;
              lStack_b8 = lVar13;
              if (lVar7 == 0) {
                if ((long)uVar22 <= lVar13) goto LAB_003b0cfa;
              }
              else {
                bVar23 = (long)uVar21 < (long)uVar10;
                uVar21 = uVar10;
                if (lVar7 == 0 || bVar23) goto LAB_003b0cfa;
              }
              uVar21 = uVar22 - lVar13;
              uVar22 = uVar21 + 1000000000;
              if (-1 < (long)uVar21) {
                uVar22 = uVar21;
              }
              uVar21 = lVar7 + ((long)uVar21 >> 0x3f);
            }
            lVar13 = lStack_b8 - lStack_a8;
            uVar21 = uVar10;
            if (lVar13 < 0) {
              uVar21 = uVar10 - 1;
              lVar13 = lVar13 + 1000000000;
            }
LAB_003b0cfa:
            iVar6 = 0x3c;
            if (iVar5 != 0x23) {
              iVar6 = iVar5;
            }
            iStack_16c = 4;
            if (iVar5 != -1) {
              iStack_16c = iVar6;
            }
            uVar11 = ((int)(SUB168(SEXT816(lVar13) * SEXT816(0x20c49ba5e353f7cf),8) >> 7) -
                     (SUB164(SEXT816(lVar13) * SEXT816(0x20c49ba5e353f7cf),0xc) >> 0x1f)) +
                     (int)uVar21 * 1000000;
            bVar23 = uStack_78 < uVar11;
            uStack_78 = uStack_78 - uVar11;
            lVar13 = lStack_120;
            if (bVar23 || uStack_78 == 0) {
              uStack_78 = 0;
            }
          }
        }
        piVar14[-2] = 0x3b0d71;
        piVar14[-1] = 0;
        func_0x004c6fa0(auStack_88,0,0,0);
        if (lVar13 != 0) {
          uVar12 = *in_GS_OFFSET;
          piVar14[-2] = 0x3b0d8d;
          piVar14[-1] = 0;
          func_0x00c1a3e0(uVar12,&UNK_0134f297,0);
          piVar14[-2] = 0x3b0da1;
          piVar14[-1] = 0;
          func_0x002591d0(&uStack_78,lVar13,4);
        }
        uVar21 = 0;
        plVar8 = plStack_140;
        uVar22 = uStack_160;
        do {
          lVar13 = plVar8[uVar21 * 7 + 3];
          plVar1 = plVar8 + uVar21 * 7;
          if (lVar13 == 0) {
            piStack_148[uVar21] = (int)plVar1[4];
          }
          else {
            piVar14[-2] = 0;
            piVar14[-1] = 0;
            piVar14[-4] = 0;
            piVar14[-3] = 0;
            piVar14[-6] = 0x3b0e15;
            piVar14[-5] = 0;
            func_0x00bf1770(lVar13 + 0x20,0x80000,0,0,0,0);
            piStack_148[uVar21] = (int)plVar1[4];
            if (*(long *)(lVar13 + 0x50) != 0) {
              plVar8 = *(long **)(plVar1[3] + 0x50);
              if (plVar8 == plVar1) {
                *(long *)(plVar1[3] + 0x50) = plVar8[6];
              }
              else {
                do {
                  plVar9 = plVar8;
                  plVar8 = (long *)plVar9[6];
                } while (plVar8 != plVar1);
                plVar9[6] = plVar8[6];
              }
              plVar1[3] = 0;
            }
            if (*(char *)(lVar13 + 0xc) != '\0') {
              pbVar2 = (byte *)((long)piStack_148 + uVar21 * 4 + 2);
              *pbVar2 = *pbVar2 | 1;
            }
            if (*(int *)(lVar13 + 8) - 3U < 2) {
              *(undefined1 *)(lVar13 + 0xc) = 1;
            }
            piVar14[-2] = 0;
            piVar14[-1] = 0;
            piVar14[-4] = 0;
            piVar14[-3] = 0;
            piVar14[-6] = 0x3b0dcb;
            piVar14[-5] = 0;
            func_0x00bf1770(lVar13 + 0x20,0x100000,0,0,0,0);
            plVar8 = plStack_140;
            uVar22 = uStack_160;
          }
          uVar17 = uStack_104;
          uVar21 = uVar21 + 1;
        } while (uVar21 != uVar22);
        plVar8 = plVar8 + 5;
        do {
          if (*plVar8 != 0) {
            piVar14[-2] = 0x3b0ed6;
            piVar14[-1] = 0;
            func_0x00399eb0();
          }
          plVar8 = plVar8 + 7;
          uVar22 = uVar22 - 1;
        } while (uVar22 != 0);
        piVar14[-2] = 0x3b0ee4;
        piVar14[-1] = 0;
        func_0x004c7e50(auStack_88);
        uVar12 = uStack_e0;
        lVar7 = lStack_f0;
        uVar22 = uStack_110;
        lVar13 = lStack_118;
        piVar20 = piStack_150;
        piVar14[-2] = 0x3b0f06;
        piVar14[-1] = 0;
        func_0x003b3f50(lVar13,lVar7,uVar12,piVar20,uVar22,uVar17);
        uVar12 = uStack_e8;
        lVar13 = lStack_100;
        piVar20 = piStack_148;
        if (iStack_16c == 4) {
          piVar14[-2] = 0x3b0f68;
          piVar14[-1] = 0;
          func_0x003b3a40(piVar20,uVar12,lVar13);
          iVar5 = 4;
        }
        else {
          iVar5 = iStack_16c;
          if (iStack_16c == 0) {
            piVar14[-2] = 0x3b0f2c;
            piVar14[-1] = 0;
            iVar5 = func_0x003b3a40(piVar20,uVar12,lVar13);
            if (iVar5 == 0) {
              iVar5 = 0;
            }
            else {
              piVar14[-2] = 0x3b0f4f;
              piVar14[-1] = 0;
              func_0x0025d410(&UNK_0131bf08,&UNK_01379d7c,0x118f,iVar5);
            }
          }
        }
        piVar14[-2] = 0x3b0f78;
        piVar14[-1] = 0;
        iVar6 = func_0x00b078d0();
        uVar11 = uStack_78;
        lVar13 = lStack_118;
        piVar20 = piStack_148;
        uVar22 = uStack_160;
        if (iVar6 != 0) {
          piVar14[-2] = 0x3b0f93;
          piVar14[-1] = 0;
          func_0x000a3b90(lVar13,uVar22,piVar20,uVar11);
        }
        plVar8 = plStack_140;
        piVar14[-2] = 0x3b0fa3;
        piVar14[-1] = 0;
        func_0x00c08df0(plVar8,0x1ab5a50);
        goto LAB_003b0490;
      }
      uVar12 = 0x101b;
    }
    else {
      iVar5 = 0x16;
      uVar12 = 0x100c;
      piVar14 = (int *)auStack_180;
    }
  }
LAB_003b0489:
  *(undefined8 *)((long)piVar14 + -8) = 0x3b0490;
  func_0x0025d410(&UNK_0131bf08,&UNK_01379d7c,uVar12,iVar5);
LAB_003b0490:
  if (lRam000000000391c310 == lStack_60) {
    return iVar5;
  }
  *(undefined8 *)((long)piVar14 + -8) = 0x3b0fad;
  func_0x006fd6b0();
                    /* WARNING: Does not return */
  pcVar3 = (code *)invalidInstructionException();
  (*pcVar3)();
}
