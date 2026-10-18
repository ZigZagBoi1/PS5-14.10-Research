; Handler 675: REA6.7.0 / Ghidra12.1.4 static function-aware assembly.
; All addresses are kernel RVAs; runtime VA = 0xffffffff8a9c0000 + RVA.
; Original 4096-byte input SHA256 32b2efb1029b8e16f2ca860171513b59a018e1302c8dbb741a1bf76f96710582.
; Actual target RVA 0x2d36f0; adjacent recovered functions are context.

; ===== REA full original-window trampoline functions and verified padding =====
; COMPLETE ORIGINAL INPUT WINDOW: handler_675.bin, 4096 bytes
; SHA256 32b2efb1029b8e16f2ca860171513b59a018e1302c8dbb741a1bf76f96710582; file offset zero = kernel RVA 0x265458.
; REA 6.7.0 / Ghidra 12.1.4 procedure_assembly disassembled every JMP below.
; Each function range is its five-byte tail-JMP; three CC padding bytes follow.
; INT3 padding is decoded from verified original bytes; GNU full-byte listing is supplied separately.
; Evidence source: byte-identical slice of raw_union.bin; evidence IDs per procedure.

; FUNCTION thunk_265458 [0x265458, 0x26545c] | file +0x0 | ev_9b00ea5998ba823d1e90a293bdf6e1fe822534470a5319eb78c58ae0b722c179
thunk_265458:
0x265458: JMP 0x002d36f0
; END FUNCTION thunk_265458
0x26545d: INT3 ; original byte CC, padding
0x26545e: INT3 ; original byte CC, padding
0x26545f: INT3 ; original byte CC, padding

; FUNCTION thunk_265460 [0x265460, 0x265464] | file +0x8 | ev_a069dd2bdab54e6c8c3f6715efd61ccc450bb4ba8c19306d81a5307f8f08a83e
thunk_265460:
0x265460: JMP 0x002d3730
; END FUNCTION thunk_265460
0x265465: INT3 ; original byte CC, padding
0x265466: INT3 ; original byte CC, padding
0x265467: INT3 ; original byte CC, padding

; FUNCTION thunk_265468 [0x265468, 0x26546c] | file +0x10 | ev_c80b1f25f7a760b08a1a150324a5d4b44959b1a43f2c8f0275bbf72c43a94c6e
thunk_265468:
0x265468: JMP 0x002e1180
; END FUNCTION thunk_265468
0x26546d: INT3 ; original byte CC, padding
0x26546e: INT3 ; original byte CC, padding
0x26546f: INT3 ; original byte CC, padding

; FUNCTION thunk_265470 [0x265470, 0x265474] | file +0x18 | ev_176a9511c13e430edf1b65c7091b763845bd33a685af491839de16b5396f08de
thunk_265470:
0x265470: JMP 0x002e5fd0
; END FUNCTION thunk_265470
0x265475: INT3 ; original byte CC, padding
0x265476: INT3 ; original byte CC, padding
0x265477: INT3 ; original byte CC, padding

; FUNCTION thunk_265478 [0x265478, 0x26547c] | file +0x20 | ev_862be3ad642cd70ecbdd5d685b8ff4c1b2b6583f13b324f5260030e0e3923604
thunk_265478:
0x265478: JMP 0x002efb30
; END FUNCTION thunk_265478
0x26547d: INT3 ; original byte CC, padding
0x26547e: INT3 ; original byte CC, padding
0x26547f: INT3 ; original byte CC, padding

; FUNCTION thunk_265480 [0x265480, 0x265484] | file +0x28 | ev_fd1088ea233b839c46de8cb7004dcdd7f21b649a6ab9cb21cb9637bc75cd646f
thunk_265480:
0x265480: JMP 0x002efd00
; END FUNCTION thunk_265480
0x265485: INT3 ; original byte CC, padding
0x265486: INT3 ; original byte CC, padding
0x265487: INT3 ; original byte CC, padding

; FUNCTION thunk_265488 [0x265488, 0x26548c] | file +0x30 | ev_02cb42269f757c4577dd5b6cfe272780e591d1efb305801a49f5a1fd7d19eda3
thunk_265488:
0x265488: JMP 0x00303960
; END FUNCTION thunk_265488
0x26548d: INT3 ; original byte CC, padding
0x26548e: INT3 ; original byte CC, padding
0x26548f: INT3 ; original byte CC, padding

; FUNCTION thunk_265490 [0x265490, 0x265494] | file +0x38 | ev_af4b3bebc5129d757c5dd0a0cb01e65d0f1943a5302f15b358b3355a53c2af05
thunk_265490:
0x265490: JMP 0x00303990
; END FUNCTION thunk_265490
0x265495: INT3 ; original byte CC, padding
0x265496: INT3 ; original byte CC, padding
0x265497: INT3 ; original byte CC, padding

; FUNCTION thunk_265498 [0x265498, 0x26549c] | file +0x40 | ev_02bdd6aac02e166c28f2d5ab4192830d336aef5147eb5ed5b6961a1579130cc6
thunk_265498:
0x265498: JMP 0x003039c0
; END FUNCTION thunk_265498
0x26549d: INT3 ; original byte CC, padding
0x26549e: INT3 ; original byte CC, padding
0x26549f: INT3 ; original byte CC, padding

; FUNCTION thunk_2654a0 [0x2654a0, 0x2654a4] | file +0x48 | ev_ed971e0593e6adc6ef7c825e2f302dfc39fcfbcdc0ba8d42360674ad45f1016b
thunk_2654a0:
0x2654a0: JMP 0x003053e0
; END FUNCTION thunk_2654a0
0x2654a5: INT3 ; original byte CC, padding
0x2654a6: INT3 ; original byte CC, padding
0x2654a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2654a8 [0x2654a8, 0x2654ac] | file +0x50 | ev_558e8d0bd00e158bd494dfbc6e564dacc688d63dddc1039bc6131cc6807827a4
thunk_2654a8:
0x2654a8: JMP 0x003059d0
; END FUNCTION thunk_2654a8
0x2654ad: INT3 ; original byte CC, padding
0x2654ae: INT3 ; original byte CC, padding
0x2654af: INT3 ; original byte CC, padding

; FUNCTION thunk_2654b0 [0x2654b0, 0x2654b4] | file +0x58 | ev_686cbcecdf5ef7baae38f3c6148ce1da5f63c3e31ce39ba87a5304dedb51b4a3
thunk_2654b0:
0x2654b0: JMP 0x00305ec0
; END FUNCTION thunk_2654b0
0x2654b5: INT3 ; original byte CC, padding
0x2654b6: INT3 ; original byte CC, padding
0x2654b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2654b8 [0x2654b8, 0x2654bc] | file +0x60 | ev_eb55a21bae939bf25d2e4531d78f52b26c97a68a59b0d0c80f4f7032fba729c2
thunk_2654b8:
0x2654b8: JMP 0x00305f60
; END FUNCTION thunk_2654b8
0x2654bd: INT3 ; original byte CC, padding
0x2654be: INT3 ; original byte CC, padding
0x2654bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2654c0 [0x2654c0, 0x2654c4] | file +0x68 | ev_affa456e6f0492a6886eb547db67229ba8d74b23ab0fd92b760cd91482e0d1a9
thunk_2654c0:
0x2654c0: JMP 0x00306070
; END FUNCTION thunk_2654c0
0x2654c5: INT3 ; original byte CC, padding
0x2654c6: INT3 ; original byte CC, padding
0x2654c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2654c8 [0x2654c8, 0x2654cc] | file +0x70 | ev_39fe2ed2c8a2401c5370dd36e90b8b93c6063cd9497f2020648e15dae4c93b5e
thunk_2654c8:
0x2654c8: JMP 0x0030cb50
; END FUNCTION thunk_2654c8
0x2654cd: INT3 ; original byte CC, padding
0x2654ce: INT3 ; original byte CC, padding
0x2654cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2654d0 [0x2654d0, 0x2654d4] | file +0x78 | ev_733dd91de5577380393f6131816836d367a28fdd178f84f496e1ec989270c36c
thunk_2654d0:
0x2654d0: JMP 0x0030cb90
; END FUNCTION thunk_2654d0
0x2654d5: INT3 ; original byte CC, padding
0x2654d6: INT3 ; original byte CC, padding
0x2654d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2654d8 [0x2654d8, 0x2654dc] | file +0x80 | ev_9c8fd10c16d8111a4f69bf11b71d346b9e47e18786d54f535be1047a4632bf71
thunk_2654d8:
0x2654d8: JMP 0x0030ddc0
; END FUNCTION thunk_2654d8
0x2654dd: INT3 ; original byte CC, padding
0x2654de: INT3 ; original byte CC, padding
0x2654df: INT3 ; original byte CC, padding

; FUNCTION thunk_2654e0 [0x2654e0, 0x2654e4] | file +0x88 | ev_1b0ad173778b2462b056b7b16846b52e4124dd0e9ed38da69663361b5fc1c29a
thunk_2654e0:
0x2654e0: JMP 0x00310220
; END FUNCTION thunk_2654e0
0x2654e5: INT3 ; original byte CC, padding
0x2654e6: INT3 ; original byte CC, padding
0x2654e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2654e8 [0x2654e8, 0x2654ec] | file +0x90 | ev_ab331c60055278af4bc0bcf141789a8dff2793914a68f98361ad87dcb9a4269f
thunk_2654e8:
0x2654e8: JMP 0x00312ed0
; END FUNCTION thunk_2654e8
0x2654ed: INT3 ; original byte CC, padding
0x2654ee: INT3 ; original byte CC, padding
0x2654ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2654f0 [0x2654f0, 0x2654f4] | file +0x98 | ev_0f7498c4b104be2fcce8767f75bd50bde98cbdc5cb9759f3fa6fbcb2d3e6d7cb
thunk_2654f0:
0x2654f0: JMP 0x00313160
; END FUNCTION thunk_2654f0
0x2654f5: INT3 ; original byte CC, padding
0x2654f6: INT3 ; original byte CC, padding
0x2654f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2654f8 [0x2654f8, 0x2654fc] | file +0xa0 | ev_0758231de867dee2361d41f2560fb1c4761b3d3d5b31e111f41b29fa828d316c
thunk_2654f8:
0x2654f8: JMP 0x003134e0
; END FUNCTION thunk_2654f8
0x2654fd: INT3 ; original byte CC, padding
0x2654fe: INT3 ; original byte CC, padding
0x2654ff: INT3 ; original byte CC, padding

; FUNCTION thunk_265500 [0x265500, 0x265504] | file +0xa8 | ev_6a21707b87227f3ca13e7104a351420daa9e6a5abe203a80fd9965dfe02a6eee
thunk_265500:
0x265500: JMP 0x00315020
; END FUNCTION thunk_265500
0x265505: INT3 ; original byte CC, padding
0x265506: INT3 ; original byte CC, padding
0x265507: INT3 ; original byte CC, padding

; FUNCTION thunk_265508 [0x265508, 0x26550c] | file +0xb0 | ev_d6172344d92875c6f694de003d474980fc60aae687671d0ce9cc5dcb55ac2c94
thunk_265508:
0x265508: JMP 0x00315220
; END FUNCTION thunk_265508
0x26550d: INT3 ; original byte CC, padding
0x26550e: INT3 ; original byte CC, padding
0x26550f: INT3 ; original byte CC, padding

; FUNCTION thunk_265510 [0x265510, 0x265514] | file +0xb8 | ev_5423d11f7ab434f9f7c4df3e317f0641da940b97cc17f39f5c9e04346aa29e4d
thunk_265510:
0x265510: JMP 0x00315290
; END FUNCTION thunk_265510
0x265515: INT3 ; original byte CC, padding
0x265516: INT3 ; original byte CC, padding
0x265517: INT3 ; original byte CC, padding

; FUNCTION thunk_265518 [0x265518, 0x26551c] | file +0xc0 | ev_92a21a08b36b2edb739ccd44821c939624bc8ff2716cded3f717b79bb0a9f16b
thunk_265518:
0x265518: JMP 0x0032adb0
; END FUNCTION thunk_265518
0x26551d: INT3 ; original byte CC, padding
0x26551e: INT3 ; original byte CC, padding
0x26551f: INT3 ; original byte CC, padding

; FUNCTION thunk_265520 [0x265520, 0x265524] | file +0xc8 | ev_ca007f8d3ba5dcff3c2118f40ca8f3673ff5dd2c4c4fe8225aab54364fe1b4e7
thunk_265520:
0x265520: JMP 0x0032df80
; END FUNCTION thunk_265520
0x265525: INT3 ; original byte CC, padding
0x265526: INT3 ; original byte CC, padding
0x265527: INT3 ; original byte CC, padding

; FUNCTION thunk_265528 [0x265528, 0x26552c] | file +0xd0 | ev_995635a6b386f041f43433de59c7bab131bfd35dde7a4fc1b1b26b4ff5f5338b
thunk_265528:
0x265528: JMP 0x0032e170
; END FUNCTION thunk_265528
0x26552d: INT3 ; original byte CC, padding
0x26552e: INT3 ; original byte CC, padding
0x26552f: INT3 ; original byte CC, padding

; FUNCTION thunk_265530 [0x265530, 0x265534] | file +0xd8 | ev_cb70e20410011f1908ffdb937abb89a361fabf226c5f556d8b9bffcde8980610
thunk_265530:
0x265530: JMP 0x00330fa0
; END FUNCTION thunk_265530
0x265535: INT3 ; original byte CC, padding
0x265536: INT3 ; original byte CC, padding
0x265537: INT3 ; original byte CC, padding

; FUNCTION thunk_265538 [0x265538, 0x26553c] | file +0xe0 | ev_07fd9caf04e7c12c124c5b8f010446c9cb8d6a8d032ae8c5efb3863b2cdc0243
thunk_265538:
0x265538: JMP 0x00331100
; END FUNCTION thunk_265538
0x26553d: INT3 ; original byte CC, padding
0x26553e: INT3 ; original byte CC, padding
0x26553f: INT3 ; original byte CC, padding

; FUNCTION thunk_265540 [0x265540, 0x265544] | file +0xe8 | ev_3683e2317484207c9b3fa0295882c77cd193bce0fdd535ef8566024aba89095c
thunk_265540:
0x265540: JMP 0x003490a0
; END FUNCTION thunk_265540
0x265545: INT3 ; original byte CC, padding
0x265546: INT3 ; original byte CC, padding
0x265547: INT3 ; original byte CC, padding

; FUNCTION thunk_265548 [0x265548, 0x26554c] | file +0xf0 | ev_08853d123c21258301e320da857415a72e4be6fb40d21412cbf784793b0af655
thunk_265548:
0x265548: JMP 0x00349110
; END FUNCTION thunk_265548
0x26554d: INT3 ; original byte CC, padding
0x26554e: INT3 ; original byte CC, padding
0x26554f: INT3 ; original byte CC, padding

; FUNCTION thunk_265550 [0x265550, 0x265554] | file +0xf8 | ev_068720d5e9eba99cff23d49d47e7172b2dfbdaef45b9902a066dcbf5806a773f
thunk_265550:
0x265550: JMP 0x003491e0
; END FUNCTION thunk_265550
0x265555: INT3 ; original byte CC, padding
0x265556: INT3 ; original byte CC, padding
0x265557: INT3 ; original byte CC, padding

; FUNCTION thunk_265558 [0x265558, 0x26555c] | file +0x100 | ev_9dd9857b5b7e6225dab8f1a70a86f840e12e93df1d82b7a02651f4e12fc98a19
thunk_265558:
0x265558: JMP 0x0034a060
; END FUNCTION thunk_265558
0x26555d: INT3 ; original byte CC, padding
0x26555e: INT3 ; original byte CC, padding
0x26555f: INT3 ; original byte CC, padding

; FUNCTION thunk_265560 [0x265560, 0x265564] | file +0x108 | ev_b286addb6fca46a2aab040ad1df5c4e9fbc84b42e1aaa3953a480c491174f1b0
thunk_265560:
0x265560: JMP 0x0034a470
; END FUNCTION thunk_265560
0x265565: INT3 ; original byte CC, padding
0x265566: INT3 ; original byte CC, padding
0x265567: INT3 ; original byte CC, padding

; FUNCTION thunk_265568 [0x265568, 0x26556c] | file +0x110 | ev_e5081598d051b781cb86c209871cdc7aee3165cc992480d796ad9891980dd65b
thunk_265568:
0x265568: JMP 0x0034ad30
; END FUNCTION thunk_265568
0x26556d: INT3 ; original byte CC, padding
0x26556e: INT3 ; original byte CC, padding
0x26556f: INT3 ; original byte CC, padding

; FUNCTION thunk_265570 [0x265570, 0x265574] | file +0x118 | ev_c49221ef2c6e8d19c3ab2444df8821e6ceb0cc3e131d023edcedba7f00f32073
thunk_265570:
0x265570: JMP 0x0034ae90
; END FUNCTION thunk_265570
0x265575: INT3 ; original byte CC, padding
0x265576: INT3 ; original byte CC, padding
0x265577: INT3 ; original byte CC, padding

; FUNCTION thunk_265578 [0x265578, 0x26557c] | file +0x120 | ev_96a098b82e95771e9afd64b2bcbd5e3d103b6e6962665877fff312b548894a45
thunk_265578:
0x265578: JMP 0x0034b510
; END FUNCTION thunk_265578
0x26557d: INT3 ; original byte CC, padding
0x26557e: INT3 ; original byte CC, padding
0x26557f: INT3 ; original byte CC, padding

; FUNCTION thunk_265580 [0x265580, 0x265584] | file +0x128 | ev_1ab9ad6ff32df1e3795148b6f1228d049dc01593adf2fdc1149a866193f7405d
thunk_265580:
0x265580: JMP 0x0034b790
; END FUNCTION thunk_265580
0x265585: INT3 ; original byte CC, padding
0x265586: INT3 ; original byte CC, padding
0x265587: INT3 ; original byte CC, padding

; FUNCTION thunk_265588 [0x265588, 0x26558c] | file +0x130 | ev_f4e81bb0d9dfc2e20656f707dea1bc1de7224eaffcddf169be8a39936ebb1f76
thunk_265588:
0x265588: JMP 0x0034b7b0
; END FUNCTION thunk_265588
0x26558d: INT3 ; original byte CC, padding
0x26558e: INT3 ; original byte CC, padding
0x26558f: INT3 ; original byte CC, padding

; FUNCTION thunk_265590 [0x265590, 0x265594] | file +0x138 | ev_b9ba35792009c51828677e17a2da474cb23c8626fb96da7fa1a5f24593472fd4
thunk_265590:
0x265590: JMP 0x0034bc60
; END FUNCTION thunk_265590
0x265595: INT3 ; original byte CC, padding
0x265596: INT3 ; original byte CC, padding
0x265597: INT3 ; original byte CC, padding

; FUNCTION thunk_265598 [0x265598, 0x26559c] | file +0x140 | ev_0304b164712f10b6d6746d3aa884d36a6079e66ab3bb437f58e998a42d73185e
thunk_265598:
0x265598: JMP 0x0034bdc0
; END FUNCTION thunk_265598
0x26559d: INT3 ; original byte CC, padding
0x26559e: INT3 ; original byte CC, padding
0x26559f: INT3 ; original byte CC, padding

; FUNCTION thunk_2655a0 [0x2655a0, 0x2655a4] | file +0x148 | ev_554c83803be55e3e3024b313be6493ceef76cc42c19d10d52f8ecc80fafa360d
thunk_2655a0:
0x2655a0: JMP 0x0034c350
; END FUNCTION thunk_2655a0
0x2655a5: INT3 ; original byte CC, padding
0x2655a6: INT3 ; original byte CC, padding
0x2655a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2655a8 [0x2655a8, 0x2655ac] | file +0x150 | ev_1578fb1e7b740d5ffe02b721e15b4dd1b77c88560f20ab3cc3855e383a007791
thunk_2655a8:
0x2655a8: JMP 0x0034c670
; END FUNCTION thunk_2655a8
0x2655ad: INT3 ; original byte CC, padding
0x2655ae: INT3 ; original byte CC, padding
0x2655af: INT3 ; original byte CC, padding

; FUNCTION thunk_2655b0 [0x2655b0, 0x2655b4] | file +0x158 | ev_2ee5dfb2fed11cea8505bf20752010f0fde4904cc9e9e3a8df5a20d5460535b1
thunk_2655b0:
0x2655b0: JMP 0x0034c750
; END FUNCTION thunk_2655b0
0x2655b5: INT3 ; original byte CC, padding
0x2655b6: INT3 ; original byte CC, padding
0x2655b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2655b8 [0x2655b8, 0x2655bc] | file +0x160 | ev_8814e4a4fc146a4afcc60461584d39cdc6781cf5bb24f5d9d830d72fdafa17f4
thunk_2655b8:
0x2655b8: JMP 0x0034c810
; END FUNCTION thunk_2655b8
0x2655bd: INT3 ; original byte CC, padding
0x2655be: INT3 ; original byte CC, padding
0x2655bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2655c0 [0x2655c0, 0x2655c4] | file +0x168 | ev_577b029dcfcb1e88105b67515b4d55ef2d73e30d1447a25b00399c891acabfa6
thunk_2655c0:
0x2655c0: JMP 0x0034c820
; END FUNCTION thunk_2655c0
0x2655c5: INT3 ; original byte CC, padding
0x2655c6: INT3 ; original byte CC, padding
0x2655c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2655c8 [0x2655c8, 0x2655cc] | file +0x170 | ev_90bc0b8332e4e854f8643f076f596fad69e8994a4ee3d8d85b9fc34b951dea7e
thunk_2655c8:
0x2655c8: JMP 0x0034c8b0
; END FUNCTION thunk_2655c8
0x2655cd: INT3 ; original byte CC, padding
0x2655ce: INT3 ; original byte CC, padding
0x2655cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2655d0 [0x2655d0, 0x2655d4] | file +0x178 | ev_87bfa9fa7045c1fbea958ab7a6a37cb3ed25c9ab88a09de1a15baee674a7e204
thunk_2655d0:
0x2655d0: JMP 0x0034c990
; END FUNCTION thunk_2655d0
0x2655d5: INT3 ; original byte CC, padding
0x2655d6: INT3 ; original byte CC, padding
0x2655d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2655d8 [0x2655d8, 0x2655dc] | file +0x180 | ev_1e5cc023c0edb574ba0da46a8492d10edd9430c9e4bbd75e17fd213d840876d4
thunk_2655d8:
0x2655d8: JMP 0x0034caa0
; END FUNCTION thunk_2655d8
0x2655dd: INT3 ; original byte CC, padding
0x2655de: INT3 ; original byte CC, padding
0x2655df: INT3 ; original byte CC, padding

; FUNCTION thunk_2655e0 [0x2655e0, 0x2655e4] | file +0x188 | ev_014c8cd818ae4cabf2e335c219f1e60ba4a1c44941e5bd274e6930204ddcf229
thunk_2655e0:
0x2655e0: JMP 0x0034ce50
; END FUNCTION thunk_2655e0
0x2655e5: INT3 ; original byte CC, padding
0x2655e6: INT3 ; original byte CC, padding
0x2655e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2655e8 [0x2655e8, 0x2655ec] | file +0x190 | ev_d04f42a05898d8bd4b8960e81b16dbdc885ee891feec0db2bbbd6745a734b881
thunk_2655e8:
0x2655e8: JMP 0x0034cfa0
; END FUNCTION thunk_2655e8
0x2655ed: INT3 ; original byte CC, padding
0x2655ee: INT3 ; original byte CC, padding
0x2655ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2655f0 [0x2655f0, 0x2655f4] | file +0x198 | ev_a583b0b1a1b77d4401d93efdb7fdc69ed43822c0ccfbc9d84a83cae5c1067db6
thunk_2655f0:
0x2655f0: JMP 0x0037caa0
; END FUNCTION thunk_2655f0
0x2655f5: INT3 ; original byte CC, padding
0x2655f6: INT3 ; original byte CC, padding
0x2655f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2655f8 [0x2655f8, 0x2655fc] | file +0x1a0 | ev_5972dda5b00da72808982c8d711bb5bff9fffa07aeeb6cfdeb909c109d128315
thunk_2655f8:
0x2655f8: JMP 0x0037cb20
; END FUNCTION thunk_2655f8
0x2655fd: INT3 ; original byte CC, padding
0x2655fe: INT3 ; original byte CC, padding
0x2655ff: INT3 ; original byte CC, padding

; FUNCTION thunk_265600 [0x265600, 0x265604] | file +0x1a8 | ev_8ff1316c7a4e64179e85baffffd024e42fadc1fe73aae463a4e5c3e6409c1afc
thunk_265600:
0x265600: JMP 0x0037ec40
; END FUNCTION thunk_265600
0x265605: INT3 ; original byte CC, padding
0x265606: INT3 ; original byte CC, padding
0x265607: INT3 ; original byte CC, padding

; FUNCTION thunk_265608 [0x265608, 0x26560c] | file +0x1b0 | ev_e532461b9c87f5f7609d71aa5c26ea1fa782ee7a6a5bc6691c1d3cbee0d557d1
thunk_265608:
0x265608: JMP 0x0037fa90
; END FUNCTION thunk_265608
0x26560d: INT3 ; original byte CC, padding
0x26560e: INT3 ; original byte CC, padding
0x26560f: INT3 ; original byte CC, padding

; FUNCTION thunk_265610 [0x265610, 0x265614] | file +0x1b8 | ev_7dbb4d99ff69671662f6b3799f461d45a8e60d8aadd5d44c5ded7270eb1afebf
thunk_265610:
0x265610: JMP 0x0037faa0
; END FUNCTION thunk_265610
0x265615: INT3 ; original byte CC, padding
0x265616: INT3 ; original byte CC, padding
0x265617: INT3 ; original byte CC, padding

; FUNCTION thunk_265618 [0x265618, 0x26561c] | file +0x1c0 | ev_00e874f5ec55b08ab1e90458551cc980df9fd7e6cac1c963c0000dbfc5e3cd2d
thunk_265618:
0x265618: JMP 0x0037fbc0
; END FUNCTION thunk_265618
0x26561d: INT3 ; original byte CC, padding
0x26561e: INT3 ; original byte CC, padding
0x26561f: INT3 ; original byte CC, padding

; FUNCTION thunk_265620 [0x265620, 0x265624] | file +0x1c8 | ev_b27291283b87566ebbf7402b46548974c36fb0a5669365bafd2af714a6da1a43
thunk_265620:
0x265620: JMP 0x0037fc70
; END FUNCTION thunk_265620
0x265625: INT3 ; original byte CC, padding
0x265626: INT3 ; original byte CC, padding
0x265627: INT3 ; original byte CC, padding

; FUNCTION thunk_265628 [0x265628, 0x26562c] | file +0x1d0 | ev_d57b5a725c90110c6e5b9a32b9fa69d662be87ba05bc19f321ddcef413e11870
thunk_265628:
0x265628: JMP 0x0037fc90
; END FUNCTION thunk_265628
0x26562d: INT3 ; original byte CC, padding
0x26562e: INT3 ; original byte CC, padding
0x26562f: INT3 ; original byte CC, padding

; FUNCTION thunk_265630 [0x265630, 0x265634] | file +0x1d8 | ev_46b1d35f9c7f7b763b35faf4b2cb7326aaef1746f3be8719d673dc85ad8b9ed8
thunk_265630:
0x265630: JMP 0x0037fd70
; END FUNCTION thunk_265630
0x265635: INT3 ; original byte CC, padding
0x265636: INT3 ; original byte CC, padding
0x265637: INT3 ; original byte CC, padding

; FUNCTION thunk_265638 [0x265638, 0x26563c] | file +0x1e0 | ev_ded72901a04864b5314aa55188fcf32ed509f53882971d5d485e088198909f72
thunk_265638:
0x265638: JMP 0x0037fd80
; END FUNCTION thunk_265638
0x26563d: INT3 ; original byte CC, padding
0x26563e: INT3 ; original byte CC, padding
0x26563f: INT3 ; original byte CC, padding

; FUNCTION thunk_265640 [0x265640, 0x265644] | file +0x1e8 | ev_032c15880de00d704df86f91ddb4dd549390ff43b06954783dfb05ae33c656a4
thunk_265640:
0x265640: JMP 0x00380260
; END FUNCTION thunk_265640
0x265645: INT3 ; original byte CC, padding
0x265646: INT3 ; original byte CC, padding
0x265647: INT3 ; original byte CC, padding

; FUNCTION thunk_265648 [0x265648, 0x26564c] | file +0x1f0 | ev_9a9940b367a2d434f043d987327963484706a7c35d52889e196df8cd8d4953c9
thunk_265648:
0x265648: JMP 0x00380760
; END FUNCTION thunk_265648
0x26564d: INT3 ; original byte CC, padding
0x26564e: INT3 ; original byte CC, padding
0x26564f: INT3 ; original byte CC, padding

; FUNCTION thunk_265650 [0x265650, 0x265654] | file +0x1f8 | ev_9f0def260481557902a1cd7fb54a56718b9221f3dd58c97820cf9f6a4f9085b6
thunk_265650:
0x265650: JMP 0x00380c90
; END FUNCTION thunk_265650
0x265655: INT3 ; original byte CC, padding
0x265656: INT3 ; original byte CC, padding
0x265657: INT3 ; original byte CC, padding

; FUNCTION thunk_265658 [0x265658, 0x26565c] | file +0x200 | ev_a822354efe7fca8962e45d7586031032de48afa47b4b3ef905b9f0c5abce4dc0
thunk_265658:
0x265658: JMP 0x00381140
; END FUNCTION thunk_265658
0x26565d: INT3 ; original byte CC, padding
0x26565e: INT3 ; original byte CC, padding
0x26565f: INT3 ; original byte CC, padding

; FUNCTION thunk_265660 [0x265660, 0x265664] | file +0x208 | ev_46b96ebed1fd2c2ddf1bdcc4b65ad190c22b31aa6c05e2867e1033d05d5c6a9f
thunk_265660:
0x265660: JMP 0x00381230
; END FUNCTION thunk_265660
0x265665: INT3 ; original byte CC, padding
0x265666: INT3 ; original byte CC, padding
0x265667: INT3 ; original byte CC, padding

; FUNCTION thunk_265668 [0x265668, 0x26566c] | file +0x210 | ev_50d2fc3a7d8fab4abcc03d4dc91f823b43793aa59ba4a13ce1a133fd9550970f
thunk_265668:
0x265668: JMP 0x00381330
; END FUNCTION thunk_265668
0x26566d: INT3 ; original byte CC, padding
0x26566e: INT3 ; original byte CC, padding
0x26566f: INT3 ; original byte CC, padding

; FUNCTION thunk_265670 [0x265670, 0x265674] | file +0x218 | ev_52b0d1e59f807fe153e1c36fe7cffc36424474d9b7125cbbf21c95af359229e5
thunk_265670:
0x265670: JMP 0x00381430
; END FUNCTION thunk_265670
0x265675: INT3 ; original byte CC, padding
0x265676: INT3 ; original byte CC, padding
0x265677: INT3 ; original byte CC, padding

; FUNCTION thunk_265678 [0x265678, 0x26567c] | file +0x220 | ev_90f27185bc0396128019a8eb015d78728f68be97c3d5f19a60b1ac13d70f46c7
thunk_265678:
0x265678: JMP 0x00381900
; END FUNCTION thunk_265678
0x26567d: INT3 ; original byte CC, padding
0x26567e: INT3 ; original byte CC, padding
0x26567f: INT3 ; original byte CC, padding

; FUNCTION thunk_265680 [0x265680, 0x265684] | file +0x228 | ev_3cc54f03858cf10549e3643f93fcc7212ae0c23ca647b90059b3b6175d3816cc
thunk_265680:
0x265680: JMP 0x003819f0
; END FUNCTION thunk_265680
0x265685: INT3 ; original byte CC, padding
0x265686: INT3 ; original byte CC, padding
0x265687: INT3 ; original byte CC, padding

; FUNCTION thunk_265688 [0x265688, 0x26568c] | file +0x230 | ev_43f7f36df2779a9a1e50bfd9cc73e276dd78c156abbd2d36260b312a00612f38
thunk_265688:
0x265688: JMP 0x00381a10
; END FUNCTION thunk_265688
0x26568d: INT3 ; original byte CC, padding
0x26568e: INT3 ; original byte CC, padding
0x26568f: INT3 ; original byte CC, padding

; FUNCTION thunk_265690 [0x265690, 0x265694] | file +0x238 | ev_cc8d59b63f127c42e47d0fdb641bb0453566ae62fa911d6df68e619a95b8ed62
thunk_265690:
0x265690: JMP 0x00381af0
; END FUNCTION thunk_265690
0x265695: INT3 ; original byte CC, padding
0x265696: INT3 ; original byte CC, padding
0x265697: INT3 ; original byte CC, padding

; FUNCTION thunk_265698 [0x265698, 0x26569c] | file +0x240 | ev_252e45b17cc1ee0b1d1595451cca0b16c65c057bba1160a7315e261d9388374b
thunk_265698:
0x265698: JMP 0x00381e70
; END FUNCTION thunk_265698
0x26569d: INT3 ; original byte CC, padding
0x26569e: INT3 ; original byte CC, padding
0x26569f: INT3 ; original byte CC, padding

; FUNCTION thunk_2656a0 [0x2656a0, 0x2656a4] | file +0x248 | ev_99c7624a168e538f6280896f1c2e9f5f0fc759c375b2dc6094e9ae80fcd2d1bb
thunk_2656a0:
0x2656a0: JMP 0x00382280
; END FUNCTION thunk_2656a0
0x2656a5: INT3 ; original byte CC, padding
0x2656a6: INT3 ; original byte CC, padding
0x2656a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2656a8 [0x2656a8, 0x2656ac] | file +0x250 | ev_4ccd85983d473ecbf1be16a517252cbf47ed884f400a76029b693a6982832e66
thunk_2656a8:
0x2656a8: JMP 0x00382480
; END FUNCTION thunk_2656a8
0x2656ad: INT3 ; original byte CC, padding
0x2656ae: INT3 ; original byte CC, padding
0x2656af: INT3 ; original byte CC, padding

; FUNCTION thunk_2656b0 [0x2656b0, 0x2656b4] | file +0x258 | ev_b4c7378155e1869861aea18bd21c7165afa04ef19d1e6142864a19faccd622e6
thunk_2656b0:
0x2656b0: JMP 0x00382590
; END FUNCTION thunk_2656b0
0x2656b5: INT3 ; original byte CC, padding
0x2656b6: INT3 ; original byte CC, padding
0x2656b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2656b8 [0x2656b8, 0x2656bc] | file +0x260 | ev_ef0fa7476e30d003032ec3edc8d22189f985dc0e224da3a36c4d56354f2ea4ff
thunk_2656b8:
0x2656b8: JMP 0x00382a60
; END FUNCTION thunk_2656b8
0x2656bd: INT3 ; original byte CC, padding
0x2656be: INT3 ; original byte CC, padding
0x2656bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2656c0 [0x2656c0, 0x2656c4] | file +0x268 | ev_3d29a0bceadcf1c9026875f0b00049d0c3a0a19ff77db6026d2147f1494fcc4f
thunk_2656c0:
0x2656c0: JMP 0x00383120
; END FUNCTION thunk_2656c0
0x2656c5: INT3 ; original byte CC, padding
0x2656c6: INT3 ; original byte CC, padding
0x2656c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2656c8 [0x2656c8, 0x2656cc] | file +0x270 | ev_6509d1d0b3bc88941cc429dbbabea8512da76a0c9176eb4c6403802b02bdfd32
thunk_2656c8:
0x2656c8: JMP 0x003835b0
; END FUNCTION thunk_2656c8
0x2656cd: INT3 ; original byte CC, padding
0x2656ce: INT3 ; original byte CC, padding
0x2656cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2656d0 [0x2656d0, 0x2656d4] | file +0x278 | ev_b09732798b8219c326cf8e746d2bb94629bf7c9c7656fab1b50b1a12a13d7714
thunk_2656d0:
0x2656d0: JMP 0x003837f0
; END FUNCTION thunk_2656d0
0x2656d5: INT3 ; original byte CC, padding
0x2656d6: INT3 ; original byte CC, padding
0x2656d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2656d8 [0x2656d8, 0x2656dc] | file +0x280 | ev_0e56407053a5d4093c5bfd1b973f5d0874fb4bc1fe0e52c7ea9e54f575242e1f
thunk_2656d8:
0x2656d8: JMP 0x00383800
; END FUNCTION thunk_2656d8
0x2656dd: INT3 ; original byte CC, padding
0x2656de: INT3 ; original byte CC, padding
0x2656df: INT3 ; original byte CC, padding

; FUNCTION thunk_2656e0 [0x2656e0, 0x2656e4] | file +0x288 | ev_7503b2fa859c9d0e4642ab19ed425a8035ccf51b94fe362963147005584afc34
thunk_2656e0:
0x2656e0: JMP 0x0038a2a0
; END FUNCTION thunk_2656e0
0x2656e5: INT3 ; original byte CC, padding
0x2656e6: INT3 ; original byte CC, padding
0x2656e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2656e8 [0x2656e8, 0x2656ec] | file +0x290 | ev_837feaf04ffb74158744d7ea0d7d53b3da9448d769e6f3f3ade6c216e9452bd8
thunk_2656e8:
0x2656e8: JMP 0x003ef380
; END FUNCTION thunk_2656e8
0x2656ed: INT3 ; original byte CC, padding
0x2656ee: INT3 ; original byte CC, padding
0x2656ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2656f0 [0x2656f0, 0x2656f4] | file +0x298 | ev_018891b17eb2eaba28cb20355a3236beb3c0192f9110dc20df1baf2778f42f34
thunk_2656f0:
0x2656f0: JMP 0x003a60e0
; END FUNCTION thunk_2656f0
0x2656f5: INT3 ; original byte CC, padding
0x2656f6: INT3 ; original byte CC, padding
0x2656f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2656f8 [0x2656f8, 0x2656fc] | file +0x2a0 | ev_640fefc2deaa24bb5083fc4750cb11729edd91835a3c189a01bbd7348445e8d3
thunk_2656f8:
0x2656f8: JMP 0x003aeb00
; END FUNCTION thunk_2656f8
0x2656fd: INT3 ; original byte CC, padding
0x2656fe: INT3 ; original byte CC, padding
0x2656ff: INT3 ; original byte CC, padding

; FUNCTION thunk_265700 [0x265700, 0x265704] | file +0x2a8 | ev_0fb1c1111094d4f95aeb3879b22865c21e89c9041b0379467a3b95cea62e35be
thunk_265700:
0x265700: JMP 0x003aebf0
; END FUNCTION thunk_265700
0x265705: INT3 ; original byte CC, padding
0x265706: INT3 ; original byte CC, padding
0x265707: INT3 ; original byte CC, padding

; FUNCTION thunk_265708 [0x265708, 0x26570c] | file +0x2b0 | ev_b6bdfcb7fa6b476800c032a87f312ce12794bc79da48eebe5d32541e885939e1
thunk_265708:
0x265708: JMP 0x003af8e0
; END FUNCTION thunk_265708
0x26570d: INT3 ; original byte CC, padding
0x26570e: INT3 ; original byte CC, padding
0x26570f: INT3 ; original byte CC, padding

; FUNCTION thunk_265710 [0x265710, 0x265714] | file +0x2b8 | ev_a7bbccaa887f1dc74dd5a20eceae5368575f08b1d5ecd8282f6df24e299ce536
thunk_265710:
0x265710: JMP 0x003af8f0
; END FUNCTION thunk_265710
0x265715: INT3 ; original byte CC, padding
0x265716: INT3 ; original byte CC, padding
0x265717: INT3 ; original byte CC, padding

; FUNCTION thunk_265718 [0x265718, 0x26571c] | file +0x2c0 | ev_38789675eca62443741b8e1bab095e841cecf87a00496a78c4bf3372253bc2b2
thunk_265718:
0x265718: JMP 0x003af900
; END FUNCTION thunk_265718
0x26571d: INT3 ; original byte CC, padding
0x26571e: INT3 ; original byte CC, padding
0x26571f: INT3 ; original byte CC, padding

; FUNCTION thunk_265720 [0x265720, 0x265724] | file +0x2c8 | ev_663b0a68a7b3c2be7c9493c0aead17e89f76910d56519503799ba2ffda9209d0
thunk_265720:
0x265720: JMP 0x003b01f0
; END FUNCTION thunk_265720
0x265725: INT3 ; original byte CC, padding
0x265726: INT3 ; original byte CC, padding
0x265727: INT3 ; original byte CC, padding

; FUNCTION thunk_265728 [0x265728, 0x26572c] | file +0x2d0 | ev_d69bbc7a859c476d6141155d3b2d923da60bf9e3f5f4355d77f3bcedce013985
thunk_265728:
0x265728: JMP 0x003b0fb0
; END FUNCTION thunk_265728
0x26572d: INT3 ; original byte CC, padding
0x26572e: INT3 ; original byte CC, padding
0x26572f: INT3 ; original byte CC, padding

; FUNCTION thunk_265730 [0x265730, 0x265734] | file +0x2d8 | ev_cf4a0758f2319cf7845c9debebe9582bfd69286eb3a26b66f296653aa9038eb8
thunk_265730:
0x265730: JMP 0x003b1670
; END FUNCTION thunk_265730
0x265735: INT3 ; original byte CC, padding
0x265736: INT3 ; original byte CC, padding
0x265737: INT3 ; original byte CC, padding

; FUNCTION thunk_265738 [0x265738, 0x26573c] | file +0x2e0 | ev_92ce22eed051fe8e75b8bc76827733d13e499e4d8d596bf46af0d7d5c1429ef3
thunk_265738:
0x265738: JMP 0x003b1680
; END FUNCTION thunk_265738
0x26573d: INT3 ; original byte CC, padding
0x26573e: INT3 ; original byte CC, padding
0x26573f: INT3 ; original byte CC, padding

; FUNCTION thunk_265740 [0x265740, 0x265744] | file +0x2e8 | ev_33530924e7685bff9fddd82f68a628a756c5337ce46b62cbd6d38d80f5fa6096
thunk_265740:
0x265740: JMP 0x003b2060
; END FUNCTION thunk_265740
0x265745: INT3 ; original byte CC, padding
0x265746: INT3 ; original byte CC, padding
0x265747: INT3 ; original byte CC, padding

; FUNCTION thunk_265748 [0x265748, 0x26574c] | file +0x2f0 | ev_de67cf534443a31bebab6a25bf45f5fd82945002817eb37fa40aaff619e6d23a
thunk_265748:
0x265748: JMP 0x003b28d0
; END FUNCTION thunk_265748
0x26574d: INT3 ; original byte CC, padding
0x26574e: INT3 ; original byte CC, padding
0x26574f: INT3 ; original byte CC, padding

; FUNCTION thunk_265750 [0x265750, 0x265754] | file +0x2f8 | ev_132234fcaf537fa6a42b874d00a2e1aad642c7a28a779da7ebbeaa20c0874aaa
thunk_265750:
0x265750: JMP 0x003b2d50
; END FUNCTION thunk_265750
0x265755: INT3 ; original byte CC, padding
0x265756: INT3 ; original byte CC, padding
0x265757: INT3 ; original byte CC, padding

; FUNCTION thunk_265758 [0x265758, 0x26575c] | file +0x300 | ev_068558a7684bdcceb36c61662c628b8e88ef07ac65492f923014b5c82b93fade
thunk_265758:
0x265758: JMP 0x003b3090
; END FUNCTION thunk_265758
0x26575d: INT3 ; original byte CC, padding
0x26575e: INT3 ; original byte CC, padding
0x26575f: INT3 ; original byte CC, padding

; FUNCTION thunk_265760 [0x265760, 0x265764] | file +0x308 | ev_bd63dc1cd6837db427a1056eb97158fe259206066faca40c28dcf7934f20ba4d
thunk_265760:
0x265760: JMP 0x005620e0
; END FUNCTION thunk_265760
0x265765: INT3 ; original byte CC, padding
0x265766: INT3 ; original byte CC, padding
0x265767: INT3 ; original byte CC, padding

; FUNCTION thunk_265768 [0x265768, 0x26576c] | file +0x310 | ev_1d901a1b7fdb0a3a9f237abaa418c80c2b2fea99395acd4e1fbac26e3445716b
thunk_265768:
0x265768: JMP 0x003b6020
; END FUNCTION thunk_265768
0x26576d: INT3 ; original byte CC, padding
0x26576e: INT3 ; original byte CC, padding
0x26576f: INT3 ; original byte CC, padding

; FUNCTION thunk_265770 [0x265770, 0x265774] | file +0x318 | ev_b6804c0eb21d9151919aae4a42f9c0cfc063fb2f53e6396e6dc77cbac8e2a1ba
thunk_265770:
0x265770: JMP 0x003b6240
; END FUNCTION thunk_265770
0x265775: INT3 ; original byte CC, padding
0x265776: INT3 ; original byte CC, padding
0x265777: INT3 ; original byte CC, padding

; FUNCTION thunk_265778 [0x265778, 0x26577c] | file +0x320 | ev_34f74d2743a15a04b1f71fa6f65bd4bd17e95b886cba7359e78b5faeff6c856d
thunk_265778:
0x265778: JMP 0x003c1e10
; END FUNCTION thunk_265778
0x26577d: INT3 ; original byte CC, padding
0x26577e: INT3 ; original byte CC, padding
0x26577f: INT3 ; original byte CC, padding

; FUNCTION thunk_265780 [0x265780, 0x265784] | file +0x328 | ev_10c0daa579f734a4a7decbb86d19d366ccc650fa23eb00375ad24032a5e6e0b8
thunk_265780:
0x265780: JMP 0x003c2240
; END FUNCTION thunk_265780
0x265785: INT3 ; original byte CC, padding
0x265786: INT3 ; original byte CC, padding
0x265787: INT3 ; original byte CC, padding

; FUNCTION thunk_265788 [0x265788, 0x26578c] | file +0x330 | ev_f3de7310226151c0183fe0d6a12e4162a8775d55c90b0d1ecb962e5e74c27fbf
thunk_265788:
0x265788: JMP 0x0012f7e0
; END FUNCTION thunk_265788
0x26578d: INT3 ; original byte CC, padding
0x26578e: INT3 ; original byte CC, padding
0x26578f: INT3 ; original byte CC, padding

; FUNCTION thunk_265790 [0x265790, 0x265794] | file +0x338 | ev_ce96bb8ef60d99823c5763a8166e15725e79734fa2c841d7a584703f32adc295
thunk_265790:
0x265790: JMP 0x003ce150
; END FUNCTION thunk_265790
0x265795: INT3 ; original byte CC, padding
0x265796: INT3 ; original byte CC, padding
0x265797: INT3 ; original byte CC, padding

; FUNCTION thunk_265798 [0x265798, 0x26579c] | file +0x340 | ev_0f8dc4e185eda329d0f5b8a0e374280c6e3304d1ed60a8d7d32f05850edf66e6
thunk_265798:
0x265798: JMP 0x003d52b0
; END FUNCTION thunk_265798
0x26579d: INT3 ; original byte CC, padding
0x26579e: INT3 ; original byte CC, padding
0x26579f: INT3 ; original byte CC, padding

; FUNCTION thunk_2657a0 [0x2657a0, 0x2657a4] | file +0x348 | ev_e2f761a65fdd84dab59b1b13e22a3b855068bf5d9a5be19d82c77854c4429308
thunk_2657a0:
0x2657a0: JMP 0x003e5aa0
; END FUNCTION thunk_2657a0
0x2657a5: INT3 ; original byte CC, padding
0x2657a6: INT3 ; original byte CC, padding
0x2657a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2657a8 [0x2657a8, 0x2657ac] | file +0x350 | ev_6697810b038fc1b12c4d4c9a9b0dd049ff025f425f50042e871cec4631353f94
thunk_2657a8:
0x2657a8: JMP 0x003e5ad0
; END FUNCTION thunk_2657a8
0x2657ad: INT3 ; original byte CC, padding
0x2657ae: INT3 ; original byte CC, padding
0x2657af: INT3 ; original byte CC, padding

; FUNCTION thunk_2657b0 [0x2657b0, 0x2657b4] | file +0x358 | ev_ebf7b57120fb86445774a5dca464139125d8f4d01fa8fb9287d3638ebaef2c34
thunk_2657b0:
0x2657b0: JMP 0x003e5af0
; END FUNCTION thunk_2657b0
0x2657b5: INT3 ; original byte CC, padding
0x2657b6: INT3 ; original byte CC, padding
0x2657b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2657b8 [0x2657b8, 0x2657bc] | file +0x360 | ev_f18742952a9bc02a461e135a15fb6ef707ecbaf16ba12b4da18dbdae79073308
thunk_2657b8:
0x2657b8: JMP 0x003ec340
; END FUNCTION thunk_2657b8
0x2657bd: INT3 ; original byte CC, padding
0x2657be: INT3 ; original byte CC, padding
0x2657bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2657c0 [0x2657c0, 0x2657c4] | file +0x368 | ev_91f732a1a4e63f6a6eb155545811fa0e43b164dacb291025c69d8da804414ace
thunk_2657c0:
0x2657c0: JMP 0x003f05c0
; END FUNCTION thunk_2657c0
0x2657c5: INT3 ; original byte CC, padding
0x2657c6: INT3 ; original byte CC, padding
0x2657c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2657c8 [0x2657c8, 0x2657cc] | file +0x370 | ev_c7b98d7ba8ab37f6d1800ccac069f4d56bde69cdec76707b570744d7e7dc1d69
thunk_2657c8:
0x2657c8: JMP 0x003f2810
; END FUNCTION thunk_2657c8
0x2657cd: INT3 ; original byte CC, padding
0x2657ce: INT3 ; original byte CC, padding
0x2657cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2657d0 [0x2657d0, 0x2657d4] | file +0x378 | ev_4f51d5c363cf402cd2db4e9f992362fbab4776f0ecbd528c24eb13344bbd3dca
thunk_2657d0:
0x2657d0: JMP 0x003f2b60
; END FUNCTION thunk_2657d0
0x2657d5: INT3 ; original byte CC, padding
0x2657d6: INT3 ; original byte CC, padding
0x2657d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2657d8 [0x2657d8, 0x2657dc] | file +0x380 | ev_1fa68ba64ca0d7c70f430e815cb0b0f22e75fe57ded1c269a505586d5c58f4d2
thunk_2657d8:
0x2657d8: JMP 0x0050ce20
; END FUNCTION thunk_2657d8
0x2657dd: INT3 ; original byte CC, padding
0x2657de: INT3 ; original byte CC, padding
0x2657df: INT3 ; original byte CC, padding

; FUNCTION thunk_2657e0 [0x2657e0, 0x2657e4] | file +0x388 | ev_cdf4533c696eba4277540c786b459e9ea015d47fce9d5d76f4a652cb6ac58172
thunk_2657e0:
0x2657e0: JMP 0x003f3f90
; END FUNCTION thunk_2657e0
0x2657e5: INT3 ; original byte CC, padding
0x2657e6: INT3 ; original byte CC, padding
0x2657e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2657e8 [0x2657e8, 0x2657ec] | file +0x390 | ev_374afdf2cce64a46acab5a174134a7f968029c9c59d14d6742cd560ce5213f23
thunk_2657e8:
0x2657e8: JMP 0x00409790
; END FUNCTION thunk_2657e8
0x2657ed: INT3 ; original byte CC, padding
0x2657ee: INT3 ; original byte CC, padding
0x2657ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2657f0 [0x2657f0, 0x2657f4] | file +0x398 | ev_58e9f1700ab212c7bbdd085f1ce9a5bdbaedb7fab614a122c69f2a9c6762e1bd
thunk_2657f0:
0x2657f0: JMP 0x00be7240
; END FUNCTION thunk_2657f0
0x2657f5: INT3 ; original byte CC, padding
0x2657f6: INT3 ; original byte CC, padding
0x2657f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2657f8 [0x2657f8, 0x2657fc] | file +0x3a0 | ev_f6bc973f7dcabf9e89f903c9e2bf5dbf21259650a2b611915c1164b66fa72741
thunk_2657f8:
0x2657f8: JMP 0x00cb1390
; END FUNCTION thunk_2657f8
0x2657fd: INT3 ; original byte CC, padding
0x2657fe: INT3 ; original byte CC, padding
0x2657ff: INT3 ; original byte CC, padding

; FUNCTION thunk_265800 [0x265800, 0x265804] | file +0x3a8 | ev_21b84e85838248825fd2de74126e431447c58868f9b80275e73f098e74c945cf
thunk_265800:
0x265800: JMP 0x004ec000
; END FUNCTION thunk_265800
0x265805: INT3 ; original byte CC, padding
0x265806: INT3 ; original byte CC, padding
0x265807: INT3 ; original byte CC, padding

; FUNCTION thunk_265808 [0x265808, 0x26580c] | file +0x3b0 | ev_ed36ff2d496580222b1f83b896dfddfaf483e38fce8c3c285a7c9581d5ef186f
thunk_265808:
0x265808: JMP 0x004ec560
; END FUNCTION thunk_265808
0x26580d: INT3 ; original byte CC, padding
0x26580e: INT3 ; original byte CC, padding
0x26580f: INT3 ; original byte CC, padding

; FUNCTION thunk_265810 [0x265810, 0x265814] | file +0x3b8 | ev_89727ec834a0cfe20eb32510eb9c2eae50ce027f3e6a558042ad62d7e27d8e1b
thunk_265810:
0x265810: JMP 0x008f6e00
; END FUNCTION thunk_265810
0x265815: INT3 ; original byte CC, padding
0x265816: INT3 ; original byte CC, padding
0x265817: INT3 ; original byte CC, padding

; FUNCTION thunk_265818 [0x265818, 0x26581c] | file +0x3c0 | ev_eefb66ff0c291781258b8a7b7ae899d7e3dcf66c5c651f06811347f6134cff7e
thunk_265818:
0x265818: JMP 0x0072bf00
; END FUNCTION thunk_265818
0x26581d: INT3 ; original byte CC, padding
0x26581e: INT3 ; original byte CC, padding
0x26581f: INT3 ; original byte CC, padding

; FUNCTION thunk_265820 [0x265820, 0x265824] | file +0x3c8 | ev_b01c8ded1e53f1229648a8fc823292f76ba1e191912f08da40a003017916d032
thunk_265820:
0x265820: JMP 0x00be8290
; END FUNCTION thunk_265820
0x265825: INT3 ; original byte CC, padding
0x265826: INT3 ; original byte CC, padding
0x265827: INT3 ; original byte CC, padding

; FUNCTION thunk_265828 [0x265828, 0x26582c] | file +0x3d0 | ev_e877aa9a22237e98d7eb06a87171e8dc74a5766852423ce01502627d2dfb95bb
thunk_265828:
0x265828: JMP 0x008f8550
; END FUNCTION thunk_265828
0x26582d: INT3 ; original byte CC, padding
0x26582e: INT3 ; original byte CC, padding
0x26582f: INT3 ; original byte CC, padding

; FUNCTION thunk_265830 [0x265830, 0x265834] | file +0x3d8 | ev_ba7051f63021a6fd1c6284d1f82b4898b77f53988089d8426c18b784cb611820
thunk_265830:
0x265830: JMP 0x008f6b20
; END FUNCTION thunk_265830
0x265835: INT3 ; original byte CC, padding
0x265836: INT3 ; original byte CC, padding
0x265837: INT3 ; original byte CC, padding

; FUNCTION thunk_265838 [0x265838, 0x26583c] | file +0x3e0 | ev_29e270b89c7ed4c79f5d94bb4bd94f9805dda1cdee86aa988991baafe5cab9bf
thunk_265838:
0x265838: JMP 0x008f9b40
; END FUNCTION thunk_265838
0x26583d: INT3 ; original byte CC, padding
0x26583e: INT3 ; original byte CC, padding
0x26583f: INT3 ; original byte CC, padding

; FUNCTION thunk_265840 [0x265840, 0x265844] | file +0x3e8 | ev_2286b3dda1e7e72b42d6a92a0a0aefa2f61011e9c731cefc24e2698890829772
thunk_265840:
0x265840: JMP 0x005329e0
; END FUNCTION thunk_265840
0x265845: INT3 ; original byte CC, padding
0x265846: INT3 ; original byte CC, padding
0x265847: INT3 ; original byte CC, padding

; FUNCTION thunk_265848 [0x265848, 0x26584c] | file +0x3f0 | ev_01217ef4807cb3458c4e52bd4cc87292cea659508dadb94fb69d13110186d725
thunk_265848:
0x265848: JMP 0x005321e0
; END FUNCTION thunk_265848
0x26584d: INT3 ; original byte CC, padding
0x26584e: INT3 ; original byte CC, padding
0x26584f: INT3 ; original byte CC, padding

; FUNCTION thunk_265850 [0x265850, 0x265854] | file +0x3f8 | ev_6d5fd951eb8cbb265a712cc176037c10716ffd34adb58ee287e6ce7605307018
thunk_265850:
0x265850: JMP 0x005328d0
; END FUNCTION thunk_265850
0x265855: INT3 ; original byte CC, padding
0x265856: INT3 ; original byte CC, padding
0x265857: INT3 ; original byte CC, padding

; FUNCTION thunk_265858 [0x265858, 0x26585c] | file +0x400 | ev_5090551b84c0f978635bfd1de6823dd5bef2c93d319a2411da7d400cedf97693
thunk_265858:
0x265858: JMP 0x00531080
; END FUNCTION thunk_265858
0x26585d: INT3 ; original byte CC, padding
0x26585e: INT3 ; original byte CC, padding
0x26585f: INT3 ; original byte CC, padding

; FUNCTION thunk_265860 [0x265860, 0x265864] | file +0x408 | ev_01c5c090c8cdb41592a81f1781d3f81583f8dd4d4fe769363a8450c7d1f7a771
thunk_265860:
0x265860: JMP 0x00533310
; END FUNCTION thunk_265860
0x265865: INT3 ; original byte CC, padding
0x265866: INT3 ; original byte CC, padding
0x265867: INT3 ; original byte CC, padding

; FUNCTION thunk_265868 [0x265868, 0x26586c] | file +0x410 | ev_c24a1e048aeb103df20b0435af6b29a74f5df513f9f5c72aaa03666f01eb6fdc
thunk_265868:
0x265868: JMP 0x00533030
; END FUNCTION thunk_265868
0x26586d: INT3 ; original byte CC, padding
0x26586e: INT3 ; original byte CC, padding
0x26586f: INT3 ; original byte CC, padding

; FUNCTION thunk_265870 [0x265870, 0x265874] | file +0x418 | ev_76ba314b67213efa76858206a61bcd4163406a9f26e42af0d8698645842db016
thunk_265870:
0x265870: JMP 0x008f8be0
; END FUNCTION thunk_265870
0x265875: INT3 ; original byte CC, padding
0x265876: INT3 ; original byte CC, padding
0x265877: INT3 ; original byte CC, padding

; FUNCTION thunk_265878 [0x265878, 0x26587c] | file +0x420 | ev_896c34d770fdd0c212052502dd983d487250108abf025f4f05b524748fb80c86
thunk_265878:
0x265878: JMP 0x008f95b0
; END FUNCTION thunk_265878
0x26587d: INT3 ; original byte CC, padding
0x26587e: INT3 ; original byte CC, padding
0x26587f: INT3 ; original byte CC, padding

; FUNCTION thunk_265880 [0x265880, 0x265884] | file +0x428 | ev_f8863d096867a30cdba9addd987914e5d320e078b4aade3ac9e818e1f98319d5
thunk_265880:
0x265880: JMP 0x008f9760
; END FUNCTION thunk_265880
0x265885: INT3 ; original byte CC, padding
0x265886: INT3 ; original byte CC, padding
0x265887: INT3 ; original byte CC, padding

; FUNCTION thunk_265888 [0x265888, 0x26588c] | file +0x430 | ev_85141131e97cdc037a66618a2dab05c4883afdef7550bb962d7c3b1108406661
thunk_265888:
0x265888: JMP 0x008f5d20
; END FUNCTION thunk_265888
0x26588d: INT3 ; original byte CC, padding
0x26588e: INT3 ; original byte CC, padding
0x26588f: INT3 ; original byte CC, padding

; FUNCTION thunk_265890 [0x265890, 0x265894] | file +0x438 | ev_5ede924fc5154e62e37e7bf8c3f811e88e9b2faec58b249284bb80f0fb48025b
thunk_265890:
0x265890: JMP 0x0055f5b0
; END FUNCTION thunk_265890
0x265895: INT3 ; original byte CC, padding
0x265896: INT3 ; original byte CC, padding
0x265897: INT3 ; original byte CC, padding

; FUNCTION thunk_265898 [0x265898, 0x26589c] | file +0x440 | ev_a23d17f391f4d36d97e50a18a5186539d45e2bed5fc87ffe4a0dcc4d6db07939
thunk_265898:
0x265898: JMP 0x00729d80
; END FUNCTION thunk_265898
0x26589d: INT3 ; original byte CC, padding
0x26589e: INT3 ; original byte CC, padding
0x26589f: INT3 ; original byte CC, padding

; FUNCTION thunk_2658a0 [0x2658a0, 0x2658a4] | file +0x448 | ev_b7a1dccb9d6a6d2325e92a7739fa6f321de83fb32cf43179dc7d2b1beed1ac61
thunk_2658a0:
0x2658a0: JMP 0x00802d90
; END FUNCTION thunk_2658a0
0x2658a5: INT3 ; original byte CC, padding
0x2658a6: INT3 ; original byte CC, padding
0x2658a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2658a8 [0x2658a8, 0x2658ac] | file +0x450 | ev_b19515a52787f810c0fc8a150c253edf5a09f1ecb6685c5ddb19a7fcbd31e7f0
thunk_2658a8:
0x2658a8: JMP 0x0045e4d0
; END FUNCTION thunk_2658a8
0x2658ad: INT3 ; original byte CC, padding
0x2658ae: INT3 ; original byte CC, padding
0x2658af: INT3 ; original byte CC, padding

; FUNCTION thunk_2658b0 [0x2658b0, 0x2658b4] | file +0x458 | ev_5b2cef43eb0f5d13ddd9c2fd9b7fa4dd2b081756fab4a5992d820a192c878767
thunk_2658b0:
0x2658b0: JMP 0x0055f400
; END FUNCTION thunk_2658b0
0x2658b5: INT3 ; original byte CC, padding
0x2658b6: INT3 ; original byte CC, padding
0x2658b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2658b8 [0x2658b8, 0x2658bc] | file +0x460 | ev_17fe6fbebe1335a99ecaeac06f571ba24b9ad7de60e42acf82b9b228106d6104
thunk_2658b8:
0x2658b8: JMP 0x004ecf40
; END FUNCTION thunk_2658b8
0x2658bd: INT3 ; original byte CC, padding
0x2658be: INT3 ; original byte CC, padding
0x2658bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2658c0 [0x2658c0, 0x2658c4] | file +0x468 | ev_eee7a1b6ecdce4e0b77d92dfc20a43dc2782e75827d3f98726902e4b96738d77
thunk_2658c0:
0x2658c0: JMP 0x007e4810
; END FUNCTION thunk_2658c0
0x2658c5: INT3 ; original byte CC, padding
0x2658c6: INT3 ; original byte CC, padding
0x2658c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2658c8 [0x2658c8, 0x2658cc] | file +0x470 | ev_845ed6badef4ae9ef77ba2e779a2375a56564fca34ec6fbcd0911725b268c459
thunk_2658c8:
0x2658c8: JMP 0x008fc490
; END FUNCTION thunk_2658c8
0x2658cd: INT3 ; original byte CC, padding
0x2658ce: INT3 ; original byte CC, padding
0x2658cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2658d0 [0x2658d0, 0x2658d4] | file +0x478 | ev_d1b9e0d38d6434e6a73c7cd5580db593062890703035603def4048e5f0f70516
thunk_2658d0:
0x2658d0: JMP 0x006e2dc0
; END FUNCTION thunk_2658d0
0x2658d5: INT3 ; original byte CC, padding
0x2658d6: INT3 ; original byte CC, padding
0x2658d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2658d8 [0x2658d8, 0x2658dc] | file +0x480 | ev_ef22b085ea6deaa05e80e7ecc0348d6d86c49968e69baffefc4836914656a99f
thunk_2658d8:
0x2658d8: JMP 0x00ab8af0
; END FUNCTION thunk_2658d8
0x2658dd: INT3 ; original byte CC, padding
0x2658de: INT3 ; original byte CC, padding
0x2658df: INT3 ; original byte CC, padding

; FUNCTION thunk_2658e0 [0x2658e0, 0x2658e4] | file +0x488 | ev_4f526ca80fe3367a5a614419397741f41bb8b497bda0c49a4d7663d093a8a633
thunk_2658e0:
0x2658e0: JMP 0x00ab8bb0
; END FUNCTION thunk_2658e0
0x2658e5: INT3 ; original byte CC, padding
0x2658e6: INT3 ; original byte CC, padding
0x2658e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2658e8 [0x2658e8, 0x2658ec] | file +0x490 | ev_6df4f33e4cce4fbceedd1cb5393b063a0eedd64e4998eb6e45e4de8a5ac03640
thunk_2658e8:
0x2658e8: JMP 0x00ab8d20
; END FUNCTION thunk_2658e8
0x2658ed: INT3 ; original byte CC, padding
0x2658ee: INT3 ; original byte CC, padding
0x2658ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2658f0 [0x2658f0, 0x2658f4] | file +0x498 | ev_890257df8433a0b7603458bc3bad772ae2bbe8da754402853cc8349d35c35c69
thunk_2658f0:
0x2658f0: JMP 0x00ab8e00
; END FUNCTION thunk_2658f0
0x2658f5: INT3 ; original byte CC, padding
0x2658f6: INT3 ; original byte CC, padding
0x2658f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2658f8 [0x2658f8, 0x2658fc] | file +0x4a0 | ev_fccee6840eafe44da8599577bb9231c256a751d24cfad1a211d736e7cc16a240
thunk_2658f8:
0x2658f8: JMP 0x00ab8ec0
; END FUNCTION thunk_2658f8
0x2658fd: INT3 ; original byte CC, padding
0x2658fe: INT3 ; original byte CC, padding
0x2658ff: INT3 ; original byte CC, padding

; FUNCTION thunk_265900 [0x265900, 0x265904] | file +0x4a8 | ev_c4d18df255e8b78afdffc056ebfd253100811ec71a1ccc354048d17e93f0b70a
thunk_265900:
0x265900: JMP 0x006bccc0
; END FUNCTION thunk_265900
0x265905: INT3 ; original byte CC, padding
0x265906: INT3 ; original byte CC, padding
0x265907: INT3 ; original byte CC, padding

; FUNCTION thunk_265908 [0x265908, 0x26590c] | file +0x4b0 | ev_1d8c648b8c949bddfa542a680881a2b6d34989bc252b7c050d7498240ee980e3
thunk_265908:
0x265908: JMP 0x006bca20
; END FUNCTION thunk_265908
0x26590d: INT3 ; original byte CC, padding
0x26590e: INT3 ; original byte CC, padding
0x26590f: INT3 ; original byte CC, padding

; FUNCTION thunk_265910 [0x265910, 0x265914] | file +0x4b8 | ev_2fbce8ef0f6b1d956a901b81cb57c9f16ae0b93127324c46ac5e0c8dc797f3fb
thunk_265910:
0x265910: JMP 0x007299f0
; END FUNCTION thunk_265910
0x265915: INT3 ; original byte CC, padding
0x265916: INT3 ; original byte CC, padding
0x265917: INT3 ; original byte CC, padding

; FUNCTION thunk_265918 [0x265918, 0x26591c] | file +0x4c0 | ev_51a7fedd9d37821417b557dbf67683f2594f508d9320da3f13e506d0066051e8
thunk_265918:
0x265918: JMP 0x00729a40
; END FUNCTION thunk_265918
0x26591d: INT3 ; original byte CC, padding
0x26591e: INT3 ; original byte CC, padding
0x26591f: INT3 ; original byte CC, padding

; FUNCTION thunk_265920 [0x265920, 0x265924] | file +0x4c8 | ev_c39c0d1fff985a45fbc3bd1198cf1b0ecd31692fb4a457f2d3a91762a9715145
thunk_265920:
0x265920: JMP 0x00729dc0
; END FUNCTION thunk_265920
0x265925: INT3 ; original byte CC, padding
0x265926: INT3 ; original byte CC, padding
0x265927: INT3 ; original byte CC, padding

; FUNCTION thunk_265928 [0x265928, 0x26592c] | file +0x4d0 | ev_6ed115f20180546ca451c6a4143e4cbcf49238cec1d7281f9c760435a3f48a16
thunk_265928:
0x265928: JMP 0x004ee4b0
; END FUNCTION thunk_265928
0x26592d: INT3 ; original byte CC, padding
0x26592e: INT3 ; original byte CC, padding
0x26592f: INT3 ; original byte CC, padding

; FUNCTION thunk_265930 [0x265930, 0x265934] | file +0x4d8 | ev_168128ab332fee133851c8c2c0dfed0372d386808a7ee24636fca3e8f350e72b
thunk_265930:
0x265930: JMP 0x008fb430
; END FUNCTION thunk_265930
0x265935: INT3 ; original byte CC, padding
0x265936: INT3 ; original byte CC, padding
0x265937: INT3 ; original byte CC, padding

; FUNCTION thunk_265938 [0x265938, 0x26593c] | file +0x4e0 | ev_c519c25eba1520b948eb17ada921ff130548b371bb9e749cd1a8197150ae7c7e
thunk_265938:
0x265938: JMP 0x0049ff80
; END FUNCTION thunk_265938
0x26593d: INT3 ; original byte CC, padding
0x26593e: INT3 ; original byte CC, padding
0x26593f: INT3 ; original byte CC, padding

; FUNCTION thunk_265940 [0x265940, 0x265944] | file +0x4e8 | ev_b31257a300ab503ae550e8b75e4beed9089c4d8aeff2ef13c06811b5f847cdcf
thunk_265940:
0x265940: JMP 0x0052f8f0
; END FUNCTION thunk_265940
0x265945: INT3 ; original byte CC, padding
0x265946: INT3 ; original byte CC, padding
0x265947: INT3 ; original byte CC, padding

; FUNCTION thunk_265948 [0x265948, 0x26594c] | file +0x4f0 | ev_6a0bec579f7db081777d62e5e84debe5bdb67589729a3712805f516afce5c16d
thunk_265948:
0x265948: JMP 0x00531260
; END FUNCTION thunk_265948
0x26594d: INT3 ; original byte CC, padding
0x26594e: INT3 ; original byte CC, padding
0x26594f: INT3 ; original byte CC, padding

; FUNCTION thunk_265950 [0x265950, 0x265954] | file +0x4f8 | ev_4ce2255d03764bdadf7c883b0fef92a89073cd0f77961ad7c78a4b7f395b1148
thunk_265950:
0x265950: JMP 0x0052fce0
; END FUNCTION thunk_265950
0x265955: INT3 ; original byte CC, padding
0x265956: INT3 ; original byte CC, padding
0x265957: INT3 ; original byte CC, padding

; FUNCTION thunk_265958 [0x265958, 0x26595c] | file +0x500 | ev_46ac121cd15ec4f1eef7e953216a00693eb003f1b8f3a51d54159f9c8db904ba
thunk_265958:
0x265958: JMP 0x0049fcf0
; END FUNCTION thunk_265958
0x26595d: INT3 ; original byte CC, padding
0x26595e: INT3 ; original byte CC, padding
0x26595f: INT3 ; original byte CC, padding

; FUNCTION thunk_265960 [0x265960, 0x265964] | file +0x508 | ev_58f2dc23be3ba21d60623d9e300f14eff0866f1b9d61326b6f93f17a5fe0e31d
thunk_265960:
0x265960: JMP 0x0052fd00
; END FUNCTION thunk_265960
0x265965: INT3 ; original byte CC, padding
0x265966: INT3 ; original byte CC, padding
0x265967: INT3 ; original byte CC, padding

; FUNCTION thunk_265968 [0x265968, 0x26596c] | file +0x510 | ev_7edf4937f75b34607d7282f661231292fd6b0e1043adabcdb3cec2032a84ae52
thunk_265968:
0x265968: JMP 0x0052fe00
; END FUNCTION thunk_265968
0x26596d: INT3 ; original byte CC, padding
0x26596e: INT3 ; original byte CC, padding
0x26596f: INT3 ; original byte CC, padding

; FUNCTION thunk_265970 [0x265970, 0x265974] | file +0x518 | ev_a61179069aea9d46cde19c9c505ec477bfafb1f1307b2ecb9a5dd4481f9599b0
thunk_265970:
0x265970: JMP 0x00530480
; END FUNCTION thunk_265970
0x265975: INT3 ; original byte CC, padding
0x265976: INT3 ; original byte CC, padding
0x265977: INT3 ; original byte CC, padding

; FUNCTION thunk_265978 [0x265978, 0x26597c] | file +0x520 | ev_8f68cf96d5c5641edab50be0cecfebf44ffa93a70f88e3e350a9ed6c39d0444f
thunk_265978:
0x265978: JMP 0x00532bc0
; END FUNCTION thunk_265978
0x26597d: INT3 ; original byte CC, padding
0x26597e: INT3 ; original byte CC, padding
0x26597f: INT3 ; original byte CC, padding

; FUNCTION thunk_265980 [0x265980, 0x265984] | file +0x528 | ev_96bd70da6010511498989cf153467883d54c72197753f7d56914e6848963c666
thunk_265980:
0x265980: JMP 0x005307d0
; END FUNCTION thunk_265980
0x265985: INT3 ; original byte CC, padding
0x265986: INT3 ; original byte CC, padding
0x265987: INT3 ; original byte CC, padding

; FUNCTION thunk_265988 [0x265988, 0x26598c] | file +0x530 | ev_ad263442a4957628c3651d02ff31caf3ff123d91ac6e612316130ef55a06fc41
thunk_265988:
0x265988: JMP 0x0052fae0
; END FUNCTION thunk_265988
0x26598d: INT3 ; original byte CC, padding
0x26598e: INT3 ; original byte CC, padding
0x26598f: INT3 ; original byte CC, padding

; FUNCTION thunk_265990 [0x265990, 0x265994] | file +0x538 | ev_6ddca225a8844f0a956e72eb36adca2fe53bd90a89eff3a53ef68aef49eda57d
thunk_265990:
0x265990: JMP 0x0072c140
; END FUNCTION thunk_265990
0x265995: INT3 ; original byte CC, padding
0x265996: INT3 ; original byte CC, padding
0x265997: INT3 ; original byte CC, padding

; FUNCTION thunk_265998 [0x265998, 0x26599c] | file +0x540 | ev_65c2b3b478763fa59180871059f420c13f43e74bbb5db32ea6e8a3ba14aed9c9
thunk_265998:
0x265998: JMP 0x006bc800
; END FUNCTION thunk_265998
0x26599d: INT3 ; original byte CC, padding
0x26599e: INT3 ; original byte CC, padding
0x26599f: INT3 ; original byte CC, padding

; FUNCTION thunk_2659a0 [0x2659a0, 0x2659a4] | file +0x548 | ev_3737c135be6511a09efc868cc07a5c07499ffae8ae300ed846470a34637263b2
thunk_2659a0:
0x2659a0: JMP 0x004a1ba0
; END FUNCTION thunk_2659a0
0x2659a5: INT3 ; original byte CC, padding
0x2659a6: INT3 ; original byte CC, padding
0x2659a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2659a8 [0x2659a8, 0x2659ac] | file +0x550 | ev_1c8053eb5bc3aa09b01e0bc4d2c28858562f68c983c137ac0e898b243011a3f4
thunk_2659a8:
0x2659a8: JMP 0x00532cd0
; END FUNCTION thunk_2659a8
0x2659ad: INT3 ; original byte CC, padding
0x2659ae: INT3 ; original byte CC, padding
0x2659af: INT3 ; original byte CC, padding

; FUNCTION thunk_2659b0 [0x2659b0, 0x2659b4] | file +0x558 | ev_1a5b353552123c0d975b18fde8275291d3bc26fef98318c05a592f13ef508e30
thunk_2659b0:
0x2659b0: JMP 0x004ec2c0
; END FUNCTION thunk_2659b0
0x2659b5: INT3 ; original byte CC, padding
0x2659b6: INT3 ; original byte CC, padding
0x2659b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2659b8 [0x2659b8, 0x2659bc] | file +0x560 | ev_ed5e8fd16ab4df76ed7f71c3c304a25e832678c51f3912fc41e30f28750c643e
thunk_2659b8:
0x2659b8: JMP 0x004ec8e0
; END FUNCTION thunk_2659b8
0x2659bd: INT3 ; original byte CC, padding
0x2659be: INT3 ; original byte CC, padding
0x2659bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2659c0 [0x2659c0, 0x2659c4] | file +0x568 | ev_42388928d43dbee314a6c1ce3245c8d49c8390da3c4bc594fb5aaddafc070ab7
thunk_2659c0:
0x2659c0: JMP 0x006bc8d0
; END FUNCTION thunk_2659c0
0x2659c5: INT3 ; original byte CC, padding
0x2659c6: INT3 ; original byte CC, padding
0x2659c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2659c8 [0x2659c8, 0x2659cc] | file +0x570 | ev_aa1de99500333816fe82e6a0e9e23204b7b21bb793b90cf9923a4574ffd80d7c
thunk_2659c8:
0x2659c8: JMP 0x008f9d40
; END FUNCTION thunk_2659c8
0x2659cd: INT3 ; original byte CC, padding
0x2659ce: INT3 ; original byte CC, padding
0x2659cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2659d0 [0x2659d0, 0x2659d4] | file +0x578 | ev_d7c4da6f51e0244008bec03e69af471e068616e27e56eaaba7cd17e57aee7856
thunk_2659d0:
0x2659d0: JMP 0x0052fe70
; END FUNCTION thunk_2659d0
0x2659d5: INT3 ; original byte CC, padding
0x2659d6: INT3 ; original byte CC, padding
0x2659d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2659d8 [0x2659d8, 0x2659dc] | file +0x580 | ev_d812c2321b5e8acb07f8f189c4f83d49099c0d10ab687c950cf9040645c78369
thunk_2659d8:
0x2659d8: JMP 0x008fb450
; END FUNCTION thunk_2659d8
0x2659dd: INT3 ; original byte CC, padding
0x2659de: INT3 ; original byte CC, padding
0x2659df: INT3 ; original byte CC, padding

; FUNCTION thunk_2659e0 [0x2659e0, 0x2659e4] | file +0x588 | ev_eeaf3a8beaaed8e90f29f246e32ffa9b14bf76351f9c7cdd7b75a5907064074e
thunk_2659e0:
0x2659e0: JMP 0x0072e590
; END FUNCTION thunk_2659e0
0x2659e5: INT3 ; original byte CC, padding
0x2659e6: INT3 ; original byte CC, padding
0x2659e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2659e8 [0x2659e8, 0x2659ec] | file +0x590 | ev_93e5bf490834f1047815cb55d92a50b3522304ffe4de081ae3e2a6297c559350
thunk_2659e8:
0x2659e8: JMP 0x00531b30
; END FUNCTION thunk_2659e8
0x2659ed: INT3 ; original byte CC, padding
0x2659ee: INT3 ; original byte CC, padding
0x2659ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2659f0 [0x2659f0, 0x2659f4] | file +0x598 | ev_57eee56aad063f12744228690ca7ce45177d557dbda4f1cfc4949d59a3dd76f2
thunk_2659f0:
0x2659f0: JMP 0x00532af0
; END FUNCTION thunk_2659f0
0x2659f5: INT3 ; original byte CC, padding
0x2659f6: INT3 ; original byte CC, padding
0x2659f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2659f8 [0x2659f8, 0x2659fc] | file +0x5a0 | ev_db6ed9d2e0cae311a8d595ad0e20575d70be3c6634b7afa4daa42c7afdd41d1c
thunk_2659f8:
0x2659f8: JMP 0x00531720
; END FUNCTION thunk_2659f8
0x2659fd: INT3 ; original byte CC, padding
0x2659fe: INT3 ; original byte CC, padding
0x2659ff: INT3 ; original byte CC, padding

; FUNCTION thunk_265a00 [0x265a00, 0x265a04] | file +0x5a8 | ev_b9362fe323a442adbbe22eddd8cb779a87e9f35aa42d1392c2f78475a282a46c
thunk_265a00:
0x265a00: JMP 0x008fb8e0
; END FUNCTION thunk_265a00
0x265a05: INT3 ; original byte CC, padding
0x265a06: INT3 ; original byte CC, padding
0x265a07: INT3 ; original byte CC, padding

; FUNCTION thunk_265a08 [0x265a08, 0x265a0c] | file +0x5b0 | ev_e101e165d55e3c023ea9702dfff16f6e79246d887abaaf2a48215537ac448782
thunk_265a08:
0x265a08: JMP 0x008fbbc0
; END FUNCTION thunk_265a08
0x265a0d: INT3 ; original byte CC, padding
0x265a0e: INT3 ; original byte CC, padding
0x265a0f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a10 [0x265a10, 0x265a14] | file +0x5b8 | ev_ab047a2ffd77c7fb21b69d50e06b794aa9de69186983e5cd51eb5c80a01023a4
thunk_265a10:
0x265a10: JMP 0x008fa310
; END FUNCTION thunk_265a10
0x265a15: INT3 ; original byte CC, padding
0x265a16: INT3 ; original byte CC, padding
0x265a17: INT3 ; original byte CC, padding

; FUNCTION thunk_265a18 [0x265a18, 0x265a1c] | file +0x5c0 | ev_457281366867d82ba2e84e2eeef2531b31b5cda653fa8dea15200204f38ec3dc
thunk_265a18:
0x265a18: JMP 0x0047b030
; END FUNCTION thunk_265a18
0x265a1d: INT3 ; original byte CC, padding
0x265a1e: INT3 ; original byte CC, padding
0x265a1f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a20 [0x265a20, 0x265a24] | file +0x5c8 | ev_4cb9f4b02ac3982206479c7a415db43ef9663b9930a274e8917298018a4f8c09
thunk_265a20:
0x265a20: JMP 0x008f8e20
; END FUNCTION thunk_265a20
0x265a25: INT3 ; original byte CC, padding
0x265a26: INT3 ; original byte CC, padding
0x265a27: INT3 ; original byte CC, padding

; FUNCTION thunk_265a28 [0x265a28, 0x265a2c] | file +0x5d0 | ev_6aeeb89ab9fdd62d9997b8bb32c9bed71748578a672c0ba09686d984be5a9bdc
thunk_265a28:
0x265a28: JMP 0x0072c150
; END FUNCTION thunk_265a28
0x265a2d: INT3 ; original byte CC, padding
0x265a2e: INT3 ; original byte CC, padding
0x265a2f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a30 [0x265a30, 0x265a34] | file +0x5d8 | ev_be064326b7431503cdcb02908a7217e744357b729e72e1614dc1328bc1ea66b1
thunk_265a30:
0x265a30: JMP 0x008f9260
; END FUNCTION thunk_265a30
0x265a35: INT3 ; original byte CC, padding
0x265a36: INT3 ; original byte CC, padding
0x265a37: INT3 ; original byte CC, padding

; FUNCTION thunk_265a38 [0x265a38, 0x265a3c] | file +0x5e0 | ev_eb91a911fcc71da70f30352af205783637b459c9f8d67b0eed63722a8d86b1cf
thunk_265a38:
0x265a38: JMP 0x008f9310
; END FUNCTION thunk_265a38
0x265a3d: INT3 ; original byte CC, padding
0x265a3e: INT3 ; original byte CC, padding
0x265a3f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a40 [0x265a40, 0x265a44] | file +0x5e8 | ev_a3a52775b98c6fc5df9d7b69dd708e06229385519208b8f9465b77c8a0e0b83d
thunk_265a40:
0x265a40: JMP 0x0072c3e0
; END FUNCTION thunk_265a40
0x265a45: INT3 ; original byte CC, padding
0x265a46: INT3 ; original byte CC, padding
0x265a47: INT3 ; original byte CC, padding

; FUNCTION thunk_265a48 [0x265a48, 0x265a4c] | file +0x5f0 | ev_96925a78451c47ba5cdc7f70b51a7168ab595113055ce5d9d6b7261f687e8714
thunk_265a48:
0x265a48: JMP 0x004a13e0
; END FUNCTION thunk_265a48
0x265a4d: INT3 ; original byte CC, padding
0x265a4e: INT3 ; original byte CC, padding
0x265a4f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a50 [0x265a50, 0x265a54] | file +0x5f8 | ev_06598b27113e0dd15bfe1ee2bc7d1d3b941c688d483dbbb8500b929308de0685
thunk_265a50:
0x265a50: JMP 0x004a0c30
; END FUNCTION thunk_265a50
0x265a55: INT3 ; original byte CC, padding
0x265a56: INT3 ; original byte CC, padding
0x265a57: INT3 ; original byte CC, padding

; FUNCTION thunk_265a58 [0x265a58, 0x265a5c] | file +0x600 | ev_ee56e932effb8cd11abcdecf19d018c0439a597586b5af12955784334c9c2e4c
thunk_265a58:
0x265a58: JMP 0x008fbbe0
; END FUNCTION thunk_265a58
0x265a5d: INT3 ; original byte CC, padding
0x265a5e: INT3 ; original byte CC, padding
0x265a5f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a60 [0x265a60, 0x265a64] | file +0x608 | ev_c95aaa86727ffe60a4df1d510d7c3093e8db94cd313c902d93a5997623489575
thunk_265a60:
0x265a60: JMP 0x005581e0
; END FUNCTION thunk_265a60
0x265a65: INT3 ; original byte CC, padding
0x265a66: INT3 ; original byte CC, padding
0x265a67: INT3 ; original byte CC, padding

; FUNCTION thunk_265a68 [0x265a68, 0x265a6c] | file +0x610 | ev_a0b1537d4bc5be6705b058b5985864a5157864850b1bd21bf57c9b2325380cf6
thunk_265a68:
0x265a68: JMP 0x00ab9450
; END FUNCTION thunk_265a68
0x265a6d: INT3 ; original byte CC, padding
0x265a6e: INT3 ; original byte CC, padding
0x265a6f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a70 [0x265a70, 0x265a74] | file +0x618 | ev_e362c6c038b8a2de4031260263b33b300becdbb2a86e2dc2d06b1a513f67a290
thunk_265a70:
0x265a70: JMP 0x00ab9710
; END FUNCTION thunk_265a70
0x265a75: INT3 ; original byte CC, padding
0x265a76: INT3 ; original byte CC, padding
0x265a77: INT3 ; original byte CC, padding

; FUNCTION thunk_265a78 [0x265a78, 0x265a7c] | file +0x620 | ev_495d3038041b1a058b06ff2e731663ea4085c3483dad60be8c277ec4650ae131
thunk_265a78:
0x265a78: JMP 0x008fa8e0
; END FUNCTION thunk_265a78
0x265a7d: INT3 ; original byte CC, padding
0x265a7e: INT3 ; original byte CC, padding
0x265a7f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a80 [0x265a80, 0x265a84] | file +0x628 | ev_01494b260f43259ae66379dfaa4ec3220cf27d283f5fa293cc9016f999ef5a95
thunk_265a80:
0x265a80: JMP 0x004ee550
; END FUNCTION thunk_265a80
0x265a85: INT3 ; original byte CC, padding
0x265a86: INT3 ; original byte CC, padding
0x265a87: INT3 ; original byte CC, padding

; FUNCTION thunk_265a88 [0x265a88, 0x265a8c] | file +0x630 | ev_44497fb3e04c8f7d5d0ac5c7e05dd2da54ffa2c8543f7248613743fa2124e22e
thunk_265a88:
0x265a88: JMP 0x008fc810
; END FUNCTION thunk_265a88
0x265a8d: INT3 ; original byte CC, padding
0x265a8e: INT3 ; original byte CC, padding
0x265a8f: INT3 ; original byte CC, padding

; FUNCTION thunk_265a90 [0x265a90, 0x265a94] | file +0x638 | ev_9ae732fc69c6cc412b0330c58f2d0bb51a78ab4d537f32b719ec38209eac178a
thunk_265a90:
0x265a90: JMP 0x008fc820
; END FUNCTION thunk_265a90
0x265a95: INT3 ; original byte CC, padding
0x265a96: INT3 ; original byte CC, padding
0x265a97: INT3 ; original byte CC, padding

; FUNCTION thunk_265a98 [0x265a98, 0x265a9c] | file +0x640 | ev_703f3a9a7f45ff25eec1878f102b43f3b14214814250fb5f5c02f5bb7cae1c1b
thunk_265a98:
0x265a98: JMP 0x006bb670
; END FUNCTION thunk_265a98
0x265a9d: INT3 ; original byte CC, padding
0x265a9e: INT3 ; original byte CC, padding
0x265a9f: INT3 ; original byte CC, padding

; FUNCTION thunk_265aa0 [0x265aa0, 0x265aa4] | file +0x648 | ev_74184725994ed2974629c910264ae0ce707c4aedf51a50f3a0ed2fdb4811bafd
thunk_265aa0:
0x265aa0: JMP 0x006bbd20
; END FUNCTION thunk_265aa0
0x265aa5: INT3 ; original byte CC, padding
0x265aa6: INT3 ; original byte CC, padding
0x265aa7: INT3 ; original byte CC, padding

; FUNCTION thunk_265aa8 [0x265aa8, 0x265aac] | file +0x650 | ev_e9fefd27bc7e8195f87b57be11e34664c183dddbdafa1971b6354208ba73289c
thunk_265aa8:
0x265aa8: JMP 0x006bc030
; END FUNCTION thunk_265aa8
0x265aad: INT3 ; original byte CC, padding
0x265aae: INT3 ; original byte CC, padding
0x265aaf: INT3 ; original byte CC, padding

; FUNCTION thunk_265ab0 [0x265ab0, 0x265ab4] | file +0x658 | ev_d6bb2d3864dfa8653d8b0a1a1a301a0ec61fc622efb8ed1a8c716a6616500d8c
thunk_265ab0:
0x265ab0: JMP 0x006bd570
; END FUNCTION thunk_265ab0
0x265ab5: INT3 ; original byte CC, padding
0x265ab6: INT3 ; original byte CC, padding
0x265ab7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ab8 [0x265ab8, 0x265abc] | file +0x660 | ev_da8086beb71b8289e8a89ced618b14099f0e550d9c8b00b77e86342eb26afc6b
thunk_265ab8:
0x265ab8: JMP 0x006bdfa0
; END FUNCTION thunk_265ab8
0x265abd: INT3 ; original byte CC, padding
0x265abe: INT3 ; original byte CC, padding
0x265abf: INT3 ; original byte CC, padding

; FUNCTION thunk_265ac0 [0x265ac0, 0x265ac4] | file +0x668 | ev_a7a4b472e4d5050be1e8b517eb6b54f185b39ba3a423190aeff61c75a894d6a6
thunk_265ac0:
0x265ac0: JMP 0x006bdfb0
; END FUNCTION thunk_265ac0
0x265ac5: INT3 ; original byte CC, padding
0x265ac6: INT3 ; original byte CC, padding
0x265ac7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ac8 [0x265ac8, 0x265acc] | file +0x670 | ev_f5662ab849c8da53ecae1ad0eeaddb1df22fad5b85181d96d1a93b3c3137080b
thunk_265ac8:
0x265ac8: JMP 0x006be1d0
; END FUNCTION thunk_265ac8
0x265acd: INT3 ; original byte CC, padding
0x265ace: INT3 ; original byte CC, padding
0x265acf: INT3 ; original byte CC, padding

; FUNCTION thunk_265ad0 [0x265ad0, 0x265ad4] | file +0x678 | ev_a83086b17cb41202f8a783e29293a14cf7083aef07c71243350a67baf6a55783
thunk_265ad0:
0x265ad0: JMP 0x006be370
; END FUNCTION thunk_265ad0
0x265ad5: INT3 ; original byte CC, padding
0x265ad6: INT3 ; original byte CC, padding
0x265ad7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ad8 [0x265ad8, 0x265adc] | file +0x680 | ev_8b313a4cd4e03d138294806bc1259185344520a276b48d244c4a89477c4c787c
thunk_265ad8:
0x265ad8: JMP 0x006bc4e0
; END FUNCTION thunk_265ad8
0x265add: INT3 ; original byte CC, padding
0x265ade: INT3 ; original byte CC, padding
0x265adf: INT3 ; original byte CC, padding

; FUNCTION thunk_265ae0 [0x265ae0, 0x265ae4] | file +0x688 | ev_f30b4d187411d67d73401e1457f57a54727fc2e9e0ff00e7587ba82b85313d03
thunk_265ae0:
0x265ae0: JMP 0x00cb1ab0
; END FUNCTION thunk_265ae0
0x265ae5: INT3 ; original byte CC, padding
0x265ae6: INT3 ; original byte CC, padding
0x265ae7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ae8 [0x265ae8, 0x265aec] | file +0x690 | ev_afba907846997d56d0b1e5c1e415974c601de5cf6166c57a19b6f6715465b552
thunk_265ae8:
0x265ae8: JMP 0x008fc390
; END FUNCTION thunk_265ae8
0x265aed: INT3 ; original byte CC, padding
0x265aee: INT3 ; original byte CC, padding
0x265aef: INT3 ; original byte CC, padding

; FUNCTION thunk_265af0 [0x265af0, 0x265af4] | file +0x698 | ev_cd81f5026adc4e739b1631c6db8bc6dfcb618f6a8d7556dd3134662e421e165f
thunk_265af0:
0x265af0: JMP 0x004ec4e0
; END FUNCTION thunk_265af0
0x265af5: INT3 ; original byte CC, padding
0x265af6: INT3 ; original byte CC, padding
0x265af7: INT3 ; original byte CC, padding

; FUNCTION thunk_265af8 [0x265af8, 0x265afc] | file +0x6a0 | ev_3a07c8c9cac85f4902d53fd0bdeb88f36620f674b725f543cc5ddc1cfe02744f
thunk_265af8:
0x265af8: JMP 0x004ecc70
; END FUNCTION thunk_265af8
0x265afd: INT3 ; original byte CC, padding
0x265afe: INT3 ; original byte CC, padding
0x265aff: INT3 ; original byte CC, padding

; FUNCTION thunk_265b00 [0x265b00, 0x265b04] | file +0x6a8 | ev_3421d95e17cc4a1925878bcf237c85a181496eb13254fc09214051717e3bf956
thunk_265b00:
0x265b00: JMP 0x00b7e960
; END FUNCTION thunk_265b00
0x265b05: INT3 ; original byte CC, padding
0x265b06: INT3 ; original byte CC, padding
0x265b07: INT3 ; original byte CC, padding

; FUNCTION thunk_265b08 [0x265b08, 0x265b0c] | file +0x6b0 | ev_75fd94589e78a26fe265113c01ec72d5cc7b39e10c9ab4703526f635bb918b90
thunk_265b08:
0x265b08: JMP 0x00ab9580
; END FUNCTION thunk_265b08
0x265b0d: INT3 ; original byte CC, padding
0x265b0e: INT3 ; original byte CC, padding
0x265b0f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b10 [0x265b10, 0x265b14] | file +0x6b8 | ev_af1b623e4e48ac4d33130b6c322bad5504b08c7fcfd69f2794de5fdd99e36ba2
thunk_265b10:
0x265b10: JMP 0x00ab9690
; END FUNCTION thunk_265b10
0x265b15: INT3 ; original byte CC, padding
0x265b16: INT3 ; original byte CC, padding
0x265b17: INT3 ; original byte CC, padding

; FUNCTION thunk_265b18 [0x265b18, 0x265b1c] | file +0x6c0 | ev_6f08de602f743b11af2a3ca81a92e66b4599a09ea231bf06d2b2b6b3b5eaaca6
thunk_265b18:
0x265b18: JMP 0x005a3a60
; END FUNCTION thunk_265b18
0x265b1d: INT3 ; original byte CC, padding
0x265b1e: INT3 ; original byte CC, padding
0x265b1f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b20 [0x265b20, 0x265b24] | file +0x6c8 | ev_c564b04ab0134458f3ec21037b36c3c93539d25c908e0ad6ca22354547c06438
thunk_265b20:
0x265b20: JMP 0x005a3b50
; END FUNCTION thunk_265b20
0x265b25: INT3 ; original byte CC, padding
0x265b26: INT3 ; original byte CC, padding
0x265b27: INT3 ; original byte CC, padding

; FUNCTION thunk_265b28 [0x265b28, 0x265b2c] | file +0x6d0 | ev_5affb35aa9906b7dce9056179ac6876de7facd3be39c71c34d941337286ca5a6
thunk_265b28:
0x265b28: JMP 0x005a3c60
; END FUNCTION thunk_265b28
0x265b2d: INT3 ; original byte CC, padding
0x265b2e: INT3 ; original byte CC, padding
0x265b2f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b30 [0x265b30, 0x265b34] | file +0x6d8 | ev_c7936173b4efa1a6af8d0aa07fef51e96aec939bed94b875ebdf5c5837764184
thunk_265b30:
0x265b30: JMP 0x005a3d80
; END FUNCTION thunk_265b30
0x265b35: INT3 ; original byte CC, padding
0x265b36: INT3 ; original byte CC, padding
0x265b37: INT3 ; original byte CC, padding

; FUNCTION thunk_265b38 [0x265b38, 0x265b3c] | file +0x6e0 | ev_0e76e0fad593dfb982ea3a62cc569e5ea657347adda0b8922d71b521086b1c2b
thunk_265b38:
0x265b38: JMP 0x005a3e70
; END FUNCTION thunk_265b38
0x265b3d: INT3 ; original byte CC, padding
0x265b3e: INT3 ; original byte CC, padding
0x265b3f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b40 [0x265b40, 0x265b44] | file +0x6e8 | ev_f1fc0fe618834671b18566b6c97f93eb32d77f7ff6bc3a5c418a0488c6417721
thunk_265b40:
0x265b40: JMP 0x005a3e90
; END FUNCTION thunk_265b40
0x265b45: INT3 ; original byte CC, padding
0x265b46: INT3 ; original byte CC, padding
0x265b47: INT3 ; original byte CC, padding

; FUNCTION thunk_265b48 [0x265b48, 0x265b4c] | file +0x6f0 | ev_297e4ad1506e4fa588be7ffb3cc64d2c156a60c7398949f2861c53f18d5b17d2
thunk_265b48:
0x265b48: JMP 0x005a3ef0
; END FUNCTION thunk_265b48
0x265b4d: INT3 ; original byte CC, padding
0x265b4e: INT3 ; original byte CC, padding
0x265b4f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b50 [0x265b50, 0x265b54] | file +0x6f8 | ev_957aacb527787eb0bbe4be89cd09cb9d646bdb0b0eef73532724401411d3f83f
thunk_265b50:
0x265b50: JMP 0x005a3f50
; END FUNCTION thunk_265b50
0x265b55: INT3 ; original byte CC, padding
0x265b56: INT3 ; original byte CC, padding
0x265b57: INT3 ; original byte CC, padding

; FUNCTION thunk_265b58 [0x265b58, 0x265b5c] | file +0x700 | ev_cdf8cfb3dbfa1c991b88c6fb6c622969311bf5929ddd06d485acb7358d3b157f
thunk_265b58:
0x265b58: JMP 0x0055ddc0
; END FUNCTION thunk_265b58
0x265b5d: INT3 ; original byte CC, padding
0x265b5e: INT3 ; original byte CC, padding
0x265b5f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b60 [0x265b60, 0x265b64] | file +0x708 | ev_ff82123b8e6c256e78638c22fe7f10d74d0dfa36b00ec56cab6d9ea3a0aa3319
thunk_265b60:
0x265b60: JMP 0x0055ed70
; END FUNCTION thunk_265b60
0x265b65: INT3 ; original byte CC, padding
0x265b66: INT3 ; original byte CC, padding
0x265b67: INT3 ; original byte CC, padding

; FUNCTION thunk_265b68 [0x265b68, 0x265b6c] | file +0x710 | ev_741b6004488946980cd7fb46c8ac97d67f459efd27fe6f2f52fb1230a023caee
thunk_265b68:
0x265b68: JMP 0x0055ec90
; END FUNCTION thunk_265b68
0x265b6d: INT3 ; original byte CC, padding
0x265b6e: INT3 ; original byte CC, padding
0x265b6f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b70 [0x265b70, 0x265b74] | file +0x718 | ev_a80907af4d4322c151a28c2e6b435566f63b91608759d6b7eed94f2c1d82e756
thunk_265b70:
0x265b70: JMP 0x0055e550
; END FUNCTION thunk_265b70
0x265b75: INT3 ; original byte CC, padding
0x265b76: INT3 ; original byte CC, padding
0x265b77: INT3 ; original byte CC, padding

; FUNCTION thunk_265b78 [0x265b78, 0x265b7c] | file +0x720 | ev_fdf4707818758567a82e30ec2143b122d38d08eb7ed927cd231371fdc7e00e94
thunk_265b78:
0x265b78: JMP 0x0055e680
; END FUNCTION thunk_265b78
0x265b7d: INT3 ; original byte CC, padding
0x265b7e: INT3 ; original byte CC, padding
0x265b7f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b80 [0x265b80, 0x265b84] | file +0x728 | ev_799415689b58e85117b40d602cd6f0ae72c9367f920780d6dac67533b8fab27b
thunk_265b80:
0x265b80: JMP 0x00abbd80
; END FUNCTION thunk_265b80
0x265b85: INT3 ; original byte CC, padding
0x265b86: INT3 ; original byte CC, padding
0x265b87: INT3 ; original byte CC, padding

; FUNCTION thunk_265b88 [0x265b88, 0x265b8c] | file +0x730 | ev_f76ebe4feb3b350240ced19a248ba11b57b55594dfd79f35b9487d256cc6a04d
thunk_265b88:
0x265b88: JMP 0x008340e0
; END FUNCTION thunk_265b88
0x265b8d: INT3 ; original byte CC, padding
0x265b8e: INT3 ; original byte CC, padding
0x265b8f: INT3 ; original byte CC, padding

; FUNCTION thunk_265b90 [0x265b90, 0x265b94] | file +0x738 | ev_e804e814208779b292184c09528d5b06b191b5e662769ad648d37c00fa89bdff
thunk_265b90:
0x265b90: JMP 0x008f6120
; END FUNCTION thunk_265b90
0x265b95: INT3 ; original byte CC, padding
0x265b96: INT3 ; original byte CC, padding
0x265b97: INT3 ; original byte CC, padding

; FUNCTION thunk_265b98 [0x265b98, 0x265b9c] | file +0x740 | ev_8e023189980448d6df30dad824c60fca8197963af4cd274e52ca66e3592e2094
thunk_265b98:
0x265b98: JMP 0x00c42f00
; END FUNCTION thunk_265b98
0x265b9d: INT3 ; original byte CC, padding
0x265b9e: INT3 ; original byte CC, padding
0x265b9f: INT3 ; original byte CC, padding

; FUNCTION thunk_265ba0 [0x265ba0, 0x265ba4] | file +0x748 | ev_14db88a56f2d598b9fe53ff7e638f60ded442f1493152fa12749722dc00d28f1
thunk_265ba0:
0x265ba0: JMP 0x00c43010
; END FUNCTION thunk_265ba0
0x265ba5: INT3 ; original byte CC, padding
0x265ba6: INT3 ; original byte CC, padding
0x265ba7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ba8 [0x265ba8, 0x265bac] | file +0x750 | ev_32b9f7cf53a0920034e238f86f0960da31d0a690a74474aa4d053cbe623c8890
thunk_265ba8:
0x265ba8: JMP 0x00c43170
; END FUNCTION thunk_265ba8
0x265bad: INT3 ; original byte CC, padding
0x265bae: INT3 ; original byte CC, padding
0x265baf: INT3 ; original byte CC, padding

; FUNCTION thunk_265bb0 [0x265bb0, 0x265bb4] | file +0x758 | ev_d4fef26238f87cdb8b610f00be41942cd7a349cc61e68316a81cb39b0b1c2fce
thunk_265bb0:
0x265bb0: JMP 0x00c434a0
; END FUNCTION thunk_265bb0
0x265bb5: INT3 ; original byte CC, padding
0x265bb6: INT3 ; original byte CC, padding
0x265bb7: INT3 ; original byte CC, padding

; FUNCTION thunk_265bb8 [0x265bb8, 0x265bbc] | file +0x760 | ev_4b8412f013e4a4161e3b194fda8f6cb9c414b2af1de1c4afbc24c0ea4644503e
thunk_265bb8:
0x265bb8: JMP 0x00c42760
; END FUNCTION thunk_265bb8
0x265bbd: INT3 ; original byte CC, padding
0x265bbe: INT3 ; original byte CC, padding
0x265bbf: INT3 ; original byte CC, padding

; FUNCTION thunk_265bc0 [0x265bc0, 0x265bc4] | file +0x768 | ev_542f037da7f8c1fbbbbe4388bc2a8965614ae5b299d19f951ab10f851c55470f
thunk_265bc0:
0x265bc0: JMP 0x00c42b90
; END FUNCTION thunk_265bc0
0x265bc5: INT3 ; original byte CC, padding
0x265bc6: INT3 ; original byte CC, padding
0x265bc7: INT3 ; original byte CC, padding

; FUNCTION thunk_265bc8 [0x265bc8, 0x265bcc] | file +0x770 | ev_2abf1503fb82f595215032a28e2b77328058162fd3991569beaaaa185103b9d0
thunk_265bc8:
0x265bc8: JMP 0x00c42bc0
; END FUNCTION thunk_265bc8
0x265bcd: INT3 ; original byte CC, padding
0x265bce: INT3 ; original byte CC, padding
0x265bcf: INT3 ; original byte CC, padding

; FUNCTION thunk_265bd0 [0x265bd0, 0x265bd4] | file +0x778 | ev_387932b9517a57a82c27fdbdcbf9e370a164e0a05fff89ca14b8746cdc73bab3
thunk_265bd0:
0x265bd0: JMP 0x00c434c0
; END FUNCTION thunk_265bd0
0x265bd5: INT3 ; original byte CC, padding
0x265bd6: INT3 ; original byte CC, padding
0x265bd7: INT3 ; original byte CC, padding

; FUNCTION thunk_265bd8 [0x265bd8, 0x265bdc] | file +0x780 | ev_26ee89d746438e99e644a6e16f3f2b9c9ff970be35a07e54a2046ea564c57865
thunk_265bd8:
0x265bd8: JMP 0x00c43620
; END FUNCTION thunk_265bd8
0x265bdd: INT3 ; original byte CC, padding
0x265bde: INT3 ; original byte CC, padding
0x265bdf: INT3 ; original byte CC, padding

; FUNCTION thunk_265be0 [0x265be0, 0x265be4] | file +0x788 | ev_0d9cd2755c606972ae8da0395a90246782c03e5283edfa37f3d50fb9cae6a53a
thunk_265be0:
0x265be0: JMP 0x0055d0c0
; END FUNCTION thunk_265be0
0x265be5: INT3 ; original byte CC, padding
0x265be6: INT3 ; original byte CC, padding
0x265be7: INT3 ; original byte CC, padding

; FUNCTION thunk_265be8 [0x265be8, 0x265bec] | file +0x790 | ev_a8aa7da9f0f61c34383d7c33eac6c441db1c5fc2aa8b978bdcf95961ef7abd04
thunk_265be8:
0x265be8: JMP 0x00a07280
; END FUNCTION thunk_265be8
0x265bed: INT3 ; original byte CC, padding
0x265bee: INT3 ; original byte CC, padding
0x265bef: INT3 ; original byte CC, padding

; FUNCTION thunk_265bf0 [0x265bf0, 0x265bf4] | file +0x798 | ev_679c3d1f43637f11cd7695c288b451925ec6002f64d269f54c771928525841a5
thunk_265bf0:
0x265bf0: JMP 0x00c37860
; END FUNCTION thunk_265bf0
0x265bf5: INT3 ; original byte CC, padding
0x265bf6: INT3 ; original byte CC, padding
0x265bf7: INT3 ; original byte CC, padding

; FUNCTION thunk_265bf8 [0x265bf8, 0x265bfc] | file +0x7a0 | ev_be190519692c8275063e286d6fffd6a64efe639bb6af22a923b4fd232f4105db
thunk_265bf8:
0x265bf8: JMP 0x00c37970
; END FUNCTION thunk_265bf8
0x265bfd: INT3 ; original byte CC, padding
0x265bfe: INT3 ; original byte CC, padding
0x265bff: INT3 ; original byte CC, padding

; FUNCTION thunk_265c00 [0x265c00, 0x265c04] | file +0x7a8 | ev_376b188e787a152b612ae47a3648a443bb8a8cfcaff267f96a1ec4874ac9450a
thunk_265c00:
0x265c00: JMP 0x00c37a20
; END FUNCTION thunk_265c00
0x265c05: INT3 ; original byte CC, padding
0x265c06: INT3 ; original byte CC, padding
0x265c07: INT3 ; original byte CC, padding

; FUNCTION thunk_265c08 [0x265c08, 0x265c0c] | file +0x7b0 | ev_f434a76a40f2b0300bd3a5e9385326262ff52dd8d7886dc762ba81360a2ddf87
thunk_265c08:
0x265c08: JMP 0x0055deb0
; END FUNCTION thunk_265c08
0x265c0d: INT3 ; original byte CC, padding
0x265c0e: INT3 ; original byte CC, padding
0x265c0f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c10 [0x265c10, 0x265c14] | file +0x7b8 | ev_931e459cfa2bc89ce67e5db8224a8c392853e680b03a61f1c4b53790ccfef13e
thunk_265c10:
0x265c10: JMP 0x00437cf0
; END FUNCTION thunk_265c10
0x265c15: INT3 ; original byte CC, padding
0x265c16: INT3 ; original byte CC, padding
0x265c17: INT3 ; original byte CC, padding

; FUNCTION thunk_265c18 [0x265c18, 0x265c1c] | file +0x7c0 | ev_438aeee9179dc8a6bb52273c75cf0e13486940563f28b22cd10ca70617ffdc84
thunk_265c18:
0x265c18: JMP 0x004383f0
; END FUNCTION thunk_265c18
0x265c1d: INT3 ; original byte CC, padding
0x265c1e: INT3 ; original byte CC, padding
0x265c1f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c20 [0x265c20, 0x265c24] | file +0x7c8 | ev_4c312f6e9064ce367f20897f87104b54edcf7a4040d829ac34ce64a41d5cccef
thunk_265c20:
0x265c20: JMP 0x004383c0
; END FUNCTION thunk_265c20
0x265c25: INT3 ; original byte CC, padding
0x265c26: INT3 ; original byte CC, padding
0x265c27: INT3 ; original byte CC, padding

; FUNCTION thunk_265c28 [0x265c28, 0x265c2c] | file +0x7d0 | ev_0ab289f3bd62320e6566baa85db7e1202ddfc9373809b3e3b041b9f8ffd735c7
thunk_265c28:
0x265c28: JMP 0x00438560
; END FUNCTION thunk_265c28
0x265c2d: INT3 ; original byte CC, padding
0x265c2e: INT3 ; original byte CC, padding
0x265c2f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c30 [0x265c30, 0x265c34] | file +0x7d8 | ev_bb6054e8c6fb2f121bcafd7a5c5ec8cff8a0d4c62a9156a3ea7fba134abf1536
thunk_265c30:
0x265c30: JMP 0x00c433f0
; END FUNCTION thunk_265c30
0x265c35: INT3 ; original byte CC, padding
0x265c36: INT3 ; original byte CC, padding
0x265c37: INT3 ; original byte CC, padding

; FUNCTION thunk_265c38 [0x265c38, 0x265c3c] | file +0x7e0 | ev_1696320a0b23b1fbe9014e786637c3aa0ebe7eb95ac14323feb57d182773a829
thunk_265c38:
0x265c38: JMP 0x004388c0
; END FUNCTION thunk_265c38
0x265c3d: INT3 ; original byte CC, padding
0x265c3e: INT3 ; original byte CC, padding
0x265c3f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c40 [0x265c40, 0x265c44] | file +0x7e8 | ev_91a591a481a2b0fa31e530f862c8de090450922e52945aee314f278a55712a96
thunk_265c40:
0x265c40: JMP 0x00438ab0
; END FUNCTION thunk_265c40
0x265c45: INT3 ; original byte CC, padding
0x265c46: INT3 ; original byte CC, padding
0x265c47: INT3 ; original byte CC, padding

; FUNCTION thunk_265c48 [0x265c48, 0x265c4c] | file +0x7f0 | ev_709ff95251ab30ee92ca67ec919accb694556039b483a052b3e048988602a70c
thunk_265c48:
0x265c48: JMP 0x00552c20
; END FUNCTION thunk_265c48
0x265c4d: INT3 ; original byte CC, padding
0x265c4e: INT3 ; original byte CC, padding
0x265c4f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c50 [0x265c50, 0x265c54] | file +0x7f8 | ev_4eafb23dc2edda248c508804926a68aac0c3aea458e04a43c2944debfa602ca4
thunk_265c50:
0x265c50: JMP 0x00437de0
; END FUNCTION thunk_265c50
0x265c55: INT3 ; original byte CC, padding
0x265c56: INT3 ; original byte CC, padding
0x265c57: INT3 ; original byte CC, padding

; FUNCTION thunk_265c58 [0x265c58, 0x265c5c] | file +0x800 | ev_cc3a07b8d71a1d4520dc7a3471d16d389cb9a545dbea33c1f9ead630c8c24e8c
thunk_265c58:
0x265c58: JMP 0x0055fc20
; END FUNCTION thunk_265c58
0x265c5d: INT3 ; original byte CC, padding
0x265c5e: INT3 ; original byte CC, padding
0x265c5f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c60 [0x265c60, 0x265c64] | file +0x808 | ev_a9da2e1f21296d36267a024dc9f6baa872bd760111b710b4e17e73fab083ee82
thunk_265c60:
0x265c60: JMP 0x00438b60
; END FUNCTION thunk_265c60
0x265c65: INT3 ; original byte CC, padding
0x265c66: INT3 ; original byte CC, padding
0x265c67: INT3 ; original byte CC, padding

; FUNCTION thunk_265c68 [0x265c68, 0x265c6c] | file +0x810 | ev_ade79c344fa8f9813a509184257a796302ce52c97d848f153069b605de1f1255
thunk_265c68:
0x265c68: JMP 0x004a0400
; END FUNCTION thunk_265c68
0x265c6d: INT3 ; original byte CC, padding
0x265c6e: INT3 ; original byte CC, padding
0x265c6f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c70 [0x265c70, 0x265c74] | file +0x818 | ev_93839e631c81c2700fc2f343594258766f1e42358948e7d0d9f8d4bac559696a
thunk_265c70:
0x265c70: JMP 0x004ec120
; END FUNCTION thunk_265c70
0x265c75: INT3 ; original byte CC, padding
0x265c76: INT3 ; original byte CC, padding
0x265c77: INT3 ; original byte CC, padding

; FUNCTION thunk_265c78 [0x265c78, 0x265c7c] | file +0x820 | ev_10871a7c7ae092e887b02fb009ac16eb48ee7f55f6163c265dcb6fb32f10ebcd
thunk_265c78:
0x265c78: JMP 0x004ec740
; END FUNCTION thunk_265c78
0x265c7d: INT3 ; original byte CC, padding
0x265c7e: INT3 ; original byte CC, padding
0x265c7f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c80 [0x265c80, 0x265c84] | file +0x828 | ev_0e11dae06b7985255741a13a2e75201ff96088ebbdc4cb6c011b2b4b9d93dddc
thunk_265c80:
0x265c80: JMP 0x00ab83c0
; END FUNCTION thunk_265c80
0x265c85: INT3 ; original byte CC, padding
0x265c86: INT3 ; original byte CC, padding
0x265c87: INT3 ; original byte CC, padding

; FUNCTION thunk_265c88 [0x265c88, 0x265c8c] | file +0x830 | ev_ca4309404d7e3f813e8c3bdf066f86347e96654cb670f2fc40c3d6f4e27ed389
thunk_265c88:
0x265c88: JMP 0x008f8ab0
; END FUNCTION thunk_265c88
0x265c8d: INT3 ; original byte CC, padding
0x265c8e: INT3 ; original byte CC, padding
0x265c8f: INT3 ; original byte CC, padding

; FUNCTION thunk_265c90 [0x265c90, 0x265c94] | file +0x838 | ev_bda1c7672eafac7c695ffd553b29b18e662a3681aa39f879c1bb0c52ae1c896d
thunk_265c90:
0x265c90: JMP 0x008fafa0
; END FUNCTION thunk_265c90
0x265c95: INT3 ; original byte CC, padding
0x265c96: INT3 ; original byte CC, padding
0x265c97: INT3 ; original byte CC, padding

; FUNCTION thunk_265c98 [0x265c98, 0x265c9c] | file +0x840 | ev_78454f2614f7a8c5aa0ce1cc9f62c1aa06794fd78c8d46cb05f945f619e752d6
thunk_265c98:
0x265c98: JMP 0x004ecf20
; END FUNCTION thunk_265c98
0x265c9d: INT3 ; original byte CC, padding
0x265c9e: INT3 ; original byte CC, padding
0x265c9f: INT3 ; original byte CC, padding

; FUNCTION thunk_265ca0 [0x265ca0, 0x265ca4] | file +0x848 | ev_260b63cf8aaa76d66b218e0f85b6398abb5808a76e2f61128df3ff7e757ecae0
thunk_265ca0:
0x265ca0: JMP 0x004386f0
; END FUNCTION thunk_265ca0
0x265ca5: INT3 ; original byte CC, padding
0x265ca6: INT3 ; original byte CC, padding
0x265ca7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ca8 [0x265ca8, 0x265cac] | file +0x850 | ev_ff272acd78e9f5676eecf4bdd04b9434bee5314e6ff5aa418a1d299d01201bb5
thunk_265ca8:
0x265ca8: JMP 0x0080d740
; END FUNCTION thunk_265ca8
0x265cad: INT3 ; original byte CC, padding
0x265cae: INT3 ; original byte CC, padding
0x265caf: INT3 ; original byte CC, padding

; FUNCTION thunk_265cb0 [0x265cb0, 0x265cb4] | file +0x858 | ev_6f1a3bda27ebdb29a3f400241102983207b2bfad15583ecd4555d9330af029ed
thunk_265cb0:
0x265cb0: JMP 0x0080dbd0
; END FUNCTION thunk_265cb0
0x265cb5: INT3 ; original byte CC, padding
0x265cb6: INT3 ; original byte CC, padding
0x265cb7: INT3 ; original byte CC, padding

; FUNCTION thunk_265cb8 [0x265cb8, 0x265cbc] | file +0x860 | ev_e1fa139b401f6c9470b4fa81c12a54c9a5f32c84d99ca333038c5ed29ad90765
thunk_265cb8:
0x265cb8: JMP 0x0083d830
; END FUNCTION thunk_265cb8
0x265cbd: INT3 ; original byte CC, padding
0x265cbe: INT3 ; original byte CC, padding
0x265cbf: INT3 ; original byte CC, padding

; FUNCTION thunk_265cc0 [0x265cc0, 0x265cc4] | file +0x868 | ev_a8e7b48f6f0f8d93bd1602d0953c8af3f8fdd570ad0089e5fd0e55eab5ed37b8
thunk_265cc0:
0x265cc0: JMP 0x0083de60
; END FUNCTION thunk_265cc0
0x265cc5: INT3 ; original byte CC, padding
0x265cc6: INT3 ; original byte CC, padding
0x265cc7: INT3 ; original byte CC, padding

; FUNCTION thunk_265cc8 [0x265cc8, 0x265ccc] | file +0x870 | ev_88c2cc843bca285bfdccb1db75a05ab3b1a284ae03f9a895638b74e0eddca2ac
thunk_265cc8:
0x265cc8: JMP 0x0083e320
; END FUNCTION thunk_265cc8
0x265ccd: INT3 ; original byte CC, padding
0x265cce: INT3 ; original byte CC, padding
0x265ccf: INT3 ; original byte CC, padding

; FUNCTION thunk_265cd0 [0x265cd0, 0x265cd4] | file +0x878 | ev_f750b507c4e2d19e5d98f168eeeb8418fecfabdb7a02fc8699620ec54d8bdb56
thunk_265cd0:
0x265cd0: JMP 0x008f6e50
; END FUNCTION thunk_265cd0
0x265cd5: INT3 ; original byte CC, padding
0x265cd6: INT3 ; original byte CC, padding
0x265cd7: INT3 ; original byte CC, padding

; FUNCTION thunk_265cd8 [0x265cd8, 0x265cdc] | file +0x880 | ev_6eeb7e7ddd34548c87c2bdde79cfe3f25d5b61dd128d96f044c33c798a9b1c6c
thunk_265cd8:
0x265cd8: JMP 0x0049b0b0
; END FUNCTION thunk_265cd8
0x265cdd: INT3 ; original byte CC, padding
0x265cde: INT3 ; original byte CC, padding
0x265cdf: INT3 ; original byte CC, padding

; FUNCTION thunk_265ce0 [0x265ce0, 0x265ce4] | file +0x888 | ev_955b59f34dcc82d326f8019b5a4ef7d192713861deb00f603f64834614e2f0db
thunk_265ce0:
0x265ce0: JMP 0x004ed3c0
; END FUNCTION thunk_265ce0
0x265ce5: INT3 ; original byte CC, padding
0x265ce6: INT3 ; original byte CC, padding
0x265ce7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ce8 [0x265ce8, 0x265cec] | file +0x890 | ev_ddd096685219d6ca376c0ace419e984924567abf06917bc2cdfb8084533d37cf
thunk_265ce8:
0x265ce8: JMP 0x00af0040
; END FUNCTION thunk_265ce8
0x265ced: INT3 ; original byte CC, padding
0x265cee: INT3 ; original byte CC, padding
0x265cef: INT3 ; original byte CC, padding

; FUNCTION thunk_265cf0 [0x265cf0, 0x265cf4] | file +0x898 | ev_eb3f8a47c49ea4c24498ce29ef78200d49662ce3715f6d19d2959697e1e145d3
thunk_265cf0:
0x265cf0: JMP 0x00705880
; END FUNCTION thunk_265cf0
0x265cf5: INT3 ; original byte CC, padding
0x265cf6: INT3 ; original byte CC, padding
0x265cf7: INT3 ; original byte CC, padding

; FUNCTION thunk_265cf8 [0x265cf8, 0x265cfc] | file +0x8a0 | ev_11ce4b2a7e8dafd791795576150b7e1fbf7fc1d3e8daa84958e281d2f2f0500a
thunk_265cf8:
0x265cf8: JMP 0x00705c60
; END FUNCTION thunk_265cf8
0x265cfd: INT3 ; original byte CC, padding
0x265cfe: INT3 ; original byte CC, padding
0x265cff: INT3 ; original byte CC, padding

; FUNCTION thunk_265d00 [0x265d00, 0x265d04] | file +0x8a8 | ev_da3f4081ffd1cca782d99510df16611df388a87eebce2f5108c2fa7c8173b36a
thunk_265d00:
0x265d00: JMP 0x004f65f0
; END FUNCTION thunk_265d00
0x265d05: INT3 ; original byte CC, padding
0x265d06: INT3 ; original byte CC, padding
0x265d07: INT3 ; original byte CC, padding

; FUNCTION thunk_265d08 [0x265d08, 0x265d0c] | file +0x8b0 | ev_91f3053d25aad314c50b29f764dc1a5ac85bdd695d16fb9c87e18cc475c3e9f0
thunk_265d08:
0x265d08: JMP 0x004f6a70
; END FUNCTION thunk_265d08
0x265d0d: INT3 ; original byte CC, padding
0x265d0e: INT3 ; original byte CC, padding
0x265d0f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d10 [0x265d10, 0x265d14] | file +0x8b8 | ev_141bedc32617e72efe65c1855a21c5bc10119939626978056e0e307ade7c92a3
thunk_265d10:
0x265d10: JMP 0x00bafa80
; END FUNCTION thunk_265d10
0x265d15: INT3 ; original byte CC, padding
0x265d16: INT3 ; original byte CC, padding
0x265d17: INT3 ; original byte CC, padding

; FUNCTION thunk_265d18 [0x265d18, 0x265d1c] | file +0x8c0 | ev_b24101c8493214775072a4b243b882c271212957cc7bac7568a9482b23581da1
thunk_265d18:
0x265d18: JMP 0x00bafcf0
; END FUNCTION thunk_265d18
0x265d1d: INT3 ; original byte CC, padding
0x265d1e: INT3 ; original byte CC, padding
0x265d1f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d20 [0x265d20, 0x265d24] | file +0x8c8 | ev_3f2696dc3468757284ec2bbccc5407f8851ad569f6a2098b096e4c156360a8f2
thunk_265d20:
0x265d20: JMP 0x00bb0330
; END FUNCTION thunk_265d20
0x265d25: INT3 ; original byte CC, padding
0x265d26: INT3 ; original byte CC, padding
0x265d27: INT3 ; original byte CC, padding

; FUNCTION thunk_265d28 [0x265d28, 0x265d2c] | file +0x8d0 | ev_9e1a530419c38b63f1c5c7f52f378f12933697777c29a2da5b9ab03f35a25121
thunk_265d28:
0x265d28: JMP 0x00bb0490
; END FUNCTION thunk_265d28
0x265d2d: INT3 ; original byte CC, padding
0x265d2e: INT3 ; original byte CC, padding
0x265d2f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d30 [0x265d30, 0x265d34] | file +0x8d8 | ev_017269beca73fffa4d0e24415f9e851d880f86cbab93db9eca9ee4b129e29848
thunk_265d30:
0x265d30: JMP 0x00bafe50
; END FUNCTION thunk_265d30
0x265d35: INT3 ; original byte CC, padding
0x265d36: INT3 ; original byte CC, padding
0x265d37: INT3 ; original byte CC, padding

; FUNCTION thunk_265d38 [0x265d38, 0x265d3c] | file +0x8e0 | ev_7e8aa0703fa40d1dc25c26b650facf9165e8413fb00e01a9cb67b371c16e4761
thunk_265d38:
0x265d38: JMP 0x00bb0030
; END FUNCTION thunk_265d38
0x265d3d: INT3 ; original byte CC, padding
0x265d3e: INT3 ; original byte CC, padding
0x265d3f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d40 [0x265d40, 0x265d44] | file +0x8e8 | ev_c6bd5b3b4689c932c0734de76323ffb6e492cd71b7f45059a8ee63b1b8c956c9
thunk_265d40:
0x265d40: JMP 0x00bb0150
; END FUNCTION thunk_265d40
0x265d45: INT3 ; original byte CC, padding
0x265d46: INT3 ; original byte CC, padding
0x265d47: INT3 ; original byte CC, padding

; FUNCTION thunk_265d48 [0x265d48, 0x265d4c] | file +0x8f0 | ev_139615a2fdde2cf350858d9f99c761a3bffb85be8daeae5c86b4510bc7b09c47
thunk_265d48:
0x265d48: JMP 0x00bb01d0
; END FUNCTION thunk_265d48
0x265d4d: INT3 ; original byte CC, padding
0x265d4e: INT3 ; original byte CC, padding
0x265d4f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d50 [0x265d50, 0x265d54] | file +0x8f8 | ev_8e719955e834476320223e8cef9d48b6df5226ae75bcb7e95f0b800f19159d18
thunk_265d50:
0x265d50: JMP 0x00bb0280
; END FUNCTION thunk_265d50
0x265d55: INT3 ; original byte CC, padding
0x265d56: INT3 ; original byte CC, padding
0x265d57: INT3 ; original byte CC, padding

; FUNCTION thunk_265d58 [0x265d58, 0x265d5c] | file +0x900 | ev_572d12d696e0f9e3cebbf9442f0836c3e6d0e75fa7911b310cd02e3443ebaddd
thunk_265d58:
0x265d58: JMP 0x00aba540
; END FUNCTION thunk_265d58
0x265d5d: INT3 ; original byte CC, padding
0x265d5e: INT3 ; original byte CC, padding
0x265d5f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d60 [0x265d60, 0x265d64] | file +0x908 | ev_cd34b10aeff44368d17a22690ff8671d8217d50f3346247d9fa38371455636fe
thunk_265d60:
0x265d60: JMP 0x00abbe60
; END FUNCTION thunk_265d60
0x265d65: INT3 ; original byte CC, padding
0x265d66: INT3 ; original byte CC, padding
0x265d67: INT3 ; original byte CC, padding

; FUNCTION thunk_265d68 [0x265d68, 0x265d6c] | file +0x910 | ev_ee7d3692358008761769bce5e91ce6601167a43b7111c85cc4784ff8ad6d3bde
thunk_265d68:
0x265d68: JMP 0x00c16020
; END FUNCTION thunk_265d68
0x265d6d: INT3 ; original byte CC, padding
0x265d6e: INT3 ; original byte CC, padding
0x265d6f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d70 [0x265d70, 0x265d74] | file +0x918 | ev_853d03a7b64b35632fb036feb750d9f78ec2536e8b530ba4ab6afc35d8f1d24d
thunk_265d70:
0x265d70: JMP 0x00c16270
; END FUNCTION thunk_265d70
0x265d75: INT3 ; original byte CC, padding
0x265d76: INT3 ; original byte CC, padding
0x265d77: INT3 ; original byte CC, padding

; FUNCTION thunk_265d78 [0x265d78, 0x265d7c] | file +0x920 | ev_470381e6a7ac04b89f9f77aa051e4885ac56ec195c7b436ac9ad7c5e0046851e
thunk_265d78:
0x265d78: JMP 0x00c16720
; END FUNCTION thunk_265d78
0x265d7d: INT3 ; original byte CC, padding
0x265d7e: INT3 ; original byte CC, padding
0x265d7f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d80 [0x265d80, 0x265d84] | file +0x928 | ev_b3a359056b1cc38b9cfdd428c2a96dceba507535f64dfe81267ffcc5df21a579
thunk_265d80:
0x265d80: JMP 0x00c16880
; END FUNCTION thunk_265d80
0x265d85: INT3 ; original byte CC, padding
0x265d86: INT3 ; original byte CC, padding
0x265d87: INT3 ; original byte CC, padding

; FUNCTION thunk_265d88 [0x265d88, 0x265d8c] | file +0x930 | ev_cda830d9a5b4a90b869dad8f56aaf69560ea49a89ebde10424aa99d79655dcef
thunk_265d88:
0x265d88: JMP 0x00c163d0
; END FUNCTION thunk_265d88
0x265d8d: INT3 ; original byte CC, padding
0x265d8e: INT3 ; original byte CC, padding
0x265d8f: INT3 ; original byte CC, padding

; FUNCTION thunk_265d90 [0x265d90, 0x265d94] | file +0x938 | ev_4ea4d752366a09794902acd3fe0b4bd1ce883c98227d2b06608bfaf43c6cf3ac
thunk_265d90:
0x265d90: JMP 0x00c164f0
; END FUNCTION thunk_265d90
0x265d95: INT3 ; original byte CC, padding
0x265d96: INT3 ; original byte CC, padding
0x265d97: INT3 ; original byte CC, padding

; FUNCTION thunk_265d98 [0x265d98, 0x265d9c] | file +0x940 | ev_67145635d96053dc90aef304f72ee68efa38f57d726896667daf6347ff26cf97
thunk_265d98:
0x265d98: JMP 0x00c165d0
; END FUNCTION thunk_265d98
0x265d9d: INT3 ; original byte CC, padding
0x265d9e: INT3 ; original byte CC, padding
0x265d9f: INT3 ; original byte CC, padding

; FUNCTION thunk_265da0 [0x265da0, 0x265da4] | file +0x948 | ev_b269cf020b1a2b49192d23123b900d40fdfd1262e814a7c11b1158bf584f301e
thunk_265da0:
0x265da0: JMP 0x00c16660
; END FUNCTION thunk_265da0
0x265da5: INT3 ; original byte CC, padding
0x265da6: INT3 ; original byte CC, padding
0x265da7: INT3 ; original byte CC, padding

; FUNCTION thunk_265da8 [0x265da8, 0x265dac] | file +0x950 | ev_8b66b6a15fdc1e32825941008d7389a84c5f3bfab207a8160af754f27c44ec26
thunk_265da8:
0x265da8: JMP 0x00ac7240
; END FUNCTION thunk_265da8
0x265dad: INT3 ; original byte CC, padding
0x265dae: INT3 ; original byte CC, padding
0x265daf: INT3 ; original byte CC, padding

; FUNCTION thunk_265db0 [0x265db0, 0x265db4] | file +0x958 | ev_caa1cbb55e05df95cb7a1c0ce004a24f59594389be3f808e779476ba59b0e12d
thunk_265db0:
0x265db0: JMP 0x00ac73c0
; END FUNCTION thunk_265db0
0x265db5: INT3 ; original byte CC, padding
0x265db6: INT3 ; original byte CC, padding
0x265db7: INT3 ; original byte CC, padding

; FUNCTION thunk_265db8 [0x265db8, 0x265dbc] | file +0x960 | ev_f72dc88d903f73c825320375b4c5b23400d62ed612ceea71d002d5806cc18bd5
thunk_265db8:
0x265db8: JMP 0x00abc510
; END FUNCTION thunk_265db8
0x265dbd: INT3 ; original byte CC, padding
0x265dbe: INT3 ; original byte CC, padding
0x265dbf: INT3 ; original byte CC, padding

; FUNCTION thunk_265dc0 [0x265dc0, 0x265dc4] | file +0x968 | ev_df8ffb00941eaaf1b014b9d6c1debb830d74d4b57a56dfe8ab7727dd09742b59
thunk_265dc0:
0x265dc0: JMP 0x004f5e60
; END FUNCTION thunk_265dc0
0x265dc5: INT3 ; original byte CC, padding
0x265dc6: INT3 ; original byte CC, padding
0x265dc7: INT3 ; original byte CC, padding

; FUNCTION thunk_265dc8 [0x265dc8, 0x265dcc] | file +0x970 | ev_b994f7e6a252748c518087af66f7152ad8d94eabf90061c7d242006164705cd4
thunk_265dc8:
0x265dc8: JMP 0x00602fe0
; END FUNCTION thunk_265dc8
0x265dcd: INT3 ; original byte CC, padding
0x265dce: INT3 ; original byte CC, padding
0x265dcf: INT3 ; original byte CC, padding

; FUNCTION thunk_265dd0 [0x265dd0, 0x265dd4] | file +0x978 | ev_b9500ecd1e28f4f0264d22e68110cfb13a646405f1b50760c958118427d85260
thunk_265dd0:
0x265dd0: JMP 0x00603260
; END FUNCTION thunk_265dd0
0x265dd5: INT3 ; original byte CC, padding
0x265dd6: INT3 ; original byte CC, padding
0x265dd7: INT3 ; original byte CC, padding

; FUNCTION thunk_265dd8 [0x265dd8, 0x265ddc] | file +0x980 | ev_7425e6bc0085d8c1456a00d22cd5d65cd23b05743dad6a46e24781fb3e860bda
thunk_265dd8:
0x265dd8: JMP 0x006034e0
; END FUNCTION thunk_265dd8
0x265ddd: INT3 ; original byte CC, padding
0x265dde: INT3 ; original byte CC, padding
0x265ddf: INT3 ; original byte CC, padding

; FUNCTION thunk_265de0 [0x265de0, 0x265de4] | file +0x988 | ev_c756130153707d47e6f24f71ad62949a6e53f64ef061495df5aa42fa423d1347
thunk_265de0:
0x265de0: JMP 0x00603710
; END FUNCTION thunk_265de0
0x265de5: INT3 ; original byte CC, padding
0x265de6: INT3 ; original byte CC, padding
0x265de7: INT3 ; original byte CC, padding

; FUNCTION thunk_265de8 [0x265de8, 0x265dec] | file +0x990 | ev_dd794267e63b1a5d75db5ef8f5a9ec6ac215c996345f89df19f48e44500dbd91
thunk_265de8:
0x265de8: JMP 0x006039d0
; END FUNCTION thunk_265de8
0x265ded: INT3 ; original byte CC, padding
0x265dee: INT3 ; original byte CC, padding
0x265def: INT3 ; original byte CC, padding

; FUNCTION thunk_265df0 [0x265df0, 0x265df4] | file +0x998 | ev_53445b4101b0607d7f53ee9f9b9f829a516dfcc063bd5e9678540b6141875405
thunk_265df0:
0x265df0: JMP 0x00abac50
; END FUNCTION thunk_265df0
0x265df5: INT3 ; original byte CC, padding
0x265df6: INT3 ; original byte CC, padding
0x265df7: INT3 ; original byte CC, padding

; FUNCTION thunk_265df8 [0x265df8, 0x265dfc] | file +0x9a0 | ev_9053ea6113d1fcbce07ea7bc6c773a1d6f872daaa256ef7f8d5d773b8df8a05f
thunk_265df8:
0x265df8: JMP 0x008fc610
; END FUNCTION thunk_265df8
0x265dfd: INT3 ; original byte CC, padding
0x265dfe: INT3 ; original byte CC, padding
0x265dff: INT3 ; original byte CC, padding

; FUNCTION thunk_265e00 [0x265e00, 0x265e04] | file +0x9a8 | ev_2d379c587a389af961b4e370bc502d7a019631a3244916178756499037519ad1
thunk_265e00:
0x265e00: JMP 0x004e1a70
; END FUNCTION thunk_265e00
0x265e05: INT3 ; original byte CC, padding
0x265e06: INT3 ; original byte CC, padding
0x265e07: INT3 ; original byte CC, padding

; FUNCTION thunk_265e08 [0x265e08, 0x265e0c] | file +0x9b0 | ev_722615ccce74c58107e60906b1e967da2cf0d8bcd78bf5b3a5b0de5a214caa92
thunk_265e08:
0x265e08: JMP 0x00abc5f0
; END FUNCTION thunk_265e08
0x265e0d: INT3 ; original byte CC, padding
0x265e0e: INT3 ; original byte CC, padding
0x265e0f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e10 [0x265e10, 0x265e14] | file +0x9b8 | ev_37aca5cf7d1c28c8bf849e9f04e45dfb04b41d726aaf5258a5d30105bdb04598
thunk_265e10:
0x265e10: JMP 0x00a367e0
; END FUNCTION thunk_265e10
0x265e15: INT3 ; original byte CC, padding
0x265e16: INT3 ; original byte CC, padding
0x265e17: INT3 ; original byte CC, padding

; FUNCTION thunk_265e18 [0x265e18, 0x265e1c] | file +0x9c0 | ev_43884718e58292c832ea8a998b28d3eebdf76b31de0e8e8b295848bcb18f19c2
thunk_265e18:
0x265e18: JMP 0x00ca0630
; END FUNCTION thunk_265e18
0x265e1d: INT3 ; original byte CC, padding
0x265e1e: INT3 ; original byte CC, padding
0x265e1f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e20 [0x265e20, 0x265e24] | file +0x9c8 | ev_d1bafefb5ca66c2b59f724e32941436f01a1d668cb2dcf44bb98e501c91513bb
thunk_265e20:
0x265e20: JMP 0x00a368e0
; END FUNCTION thunk_265e20
0x265e25: INT3 ; original byte CC, padding
0x265e26: INT3 ; original byte CC, padding
0x265e27: INT3 ; original byte CC, padding

; FUNCTION thunk_265e28 [0x265e28, 0x265e2c] | file +0x9d0 | ev_76740d04bd0fa44e04809a29e736e4d4de8c1aa42303e07fba3012a1ad03f667
thunk_265e28:
0x265e28: JMP 0x0072ecc0
; END FUNCTION thunk_265e28
0x265e2d: INT3 ; original byte CC, padding
0x265e2e: INT3 ; original byte CC, padding
0x265e2f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e30 [0x265e30, 0x265e34] | file +0x9d8 | ev_5b470392df3096545b35171d8830430e529dc2885ed7fd63673b636ec696f9f9
thunk_265e30:
0x265e30: JMP 0x004f7370
; END FUNCTION thunk_265e30
0x265e35: INT3 ; original byte CC, padding
0x265e36: INT3 ; original byte CC, padding
0x265e37: INT3 ; original byte CC, padding

; FUNCTION thunk_265e38 [0x265e38, 0x265e3c] | file +0x9e0 | ev_6f9f1ce71e9ea4c394db6586515d83d76fa68b271bc3da58988e7910cbc2fb54
thunk_265e38:
0x265e38: JMP 0x00a36b00
; END FUNCTION thunk_265e38
0x265e3d: INT3 ; original byte CC, padding
0x265e3e: INT3 ; original byte CC, padding
0x265e3f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e40 [0x265e40, 0x265e44] | file +0x9e8 | ev_ef143793367f3451c5a8e0bdc8eb37f1f6c13b48c2e7c0e098d30077555b904d
thunk_265e40:
0x265e40: JMP 0x00a36b90
; END FUNCTION thunk_265e40
0x265e45: INT3 ; original byte CC, padding
0x265e46: INT3 ; original byte CC, padding
0x265e47: INT3 ; original byte CC, padding

; FUNCTION thunk_265e48 [0x265e48, 0x265e4c] | file +0x9f0 | ev_2f42ab8d4c7f316be09068c535ab8450158592cf54991840e19304610d5a1d07
thunk_265e48:
0x265e48: JMP 0x00abc710
; END FUNCTION thunk_265e48
0x265e4d: INT3 ; original byte CC, padding
0x265e4e: INT3 ; original byte CC, padding
0x265e4f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e50 [0x265e50, 0x265e54] | file +0x9f8 | ev_85c7b01fc12753dce03c87eee1509d51a78a63de5f53132f6e6614707b3c8db5
thunk_265e50:
0x265e50: JMP 0x005a7f60
; END FUNCTION thunk_265e50
0x265e55: INT3 ; original byte CC, padding
0x265e56: INT3 ; original byte CC, padding
0x265e57: INT3 ; original byte CC, padding

; FUNCTION thunk_265e58 [0x265e58, 0x265e5c] | file +0xa00 | ev_df8ea304f646c11a583b14aae4ca1a483f4782e1e9354dce034d074761991e9d
thunk_265e58:
0x265e58: JMP 0x00a36bc0
; END FUNCTION thunk_265e58
0x265e5d: INT3 ; original byte CC, padding
0x265e5e: INT3 ; original byte CC, padding
0x265e5f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e60 [0x265e60, 0x265e64] | file +0xa08 | ev_6198524f60231153a0e06f7b2780b66fc77694781b03b7891c043a5d885ab756
thunk_265e60:
0x265e60: JMP 0x00abca10
; END FUNCTION thunk_265e60
0x265e65: INT3 ; original byte CC, padding
0x265e66: INT3 ; original byte CC, padding
0x265e67: INT3 ; original byte CC, padding

; FUNCTION thunk_265e68 [0x265e68, 0x265e6c] | file +0xa10 | ev_8623a41ef8f18a1433f4d8d8d8c4ae56a20bc22464b1afdd5e3060271c537bb3
thunk_265e68:
0x265e68: JMP 0x00abcc00
; END FUNCTION thunk_265e68
0x265e6d: INT3 ; original byte CC, padding
0x265e6e: INT3 ; original byte CC, padding
0x265e6f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e70 [0x265e70, 0x265e74] | file +0xa18 | ev_4b8b732890c7585fee162dd206d6db0bca27e0c19731e4fc6697ccd7f847c1bf
thunk_265e70:
0x265e70: JMP 0x00438c90
; END FUNCTION thunk_265e70
0x265e75: INT3 ; original byte CC, padding
0x265e76: INT3 ; original byte CC, padding
0x265e77: INT3 ; original byte CC, padding

; FUNCTION thunk_265e78 [0x265e78, 0x265e7c] | file +0xa20 | ev_1768279b2851f65325ade262735a2b5161d0b00c0cb0153a8119e17cfac138e3
thunk_265e78:
0x265e78: JMP 0x008d2570
; END FUNCTION thunk_265e78
0x265e7d: INT3 ; original byte CC, padding
0x265e7e: INT3 ; original byte CC, padding
0x265e7f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e80 [0x265e80, 0x265e84] | file +0xa28 | ev_4d0dc7aa1e73570e5e303d05b62b42265a0a127393c36cc0ffb723f7e92ae586
thunk_265e80:
0x265e80: JMP 0x00abd0f0
; END FUNCTION thunk_265e80
0x265e85: INT3 ; original byte CC, padding
0x265e86: INT3 ; original byte CC, padding
0x265e87: INT3 ; original byte CC, padding

; FUNCTION thunk_265e88 [0x265e88, 0x265e8c] | file +0xa30 | ev_327b227bd6c213499654b0860aa855d48da53a03261343aaf271ac55682e0e1b
thunk_265e88:
0x265e88: JMP 0x00a37650
; END FUNCTION thunk_265e88
0x265e8d: INT3 ; original byte CC, padding
0x265e8e: INT3 ; original byte CC, padding
0x265e8f: INT3 ; original byte CC, padding

; FUNCTION thunk_265e90 [0x265e90, 0x265e94] | file +0xa38 | ev_c570d0bb05504dfdb65b965e7ab8343f01e31ce22848c7beb6085619a0f039d1
thunk_265e90:
0x265e90: JMP 0x00abd430
; END FUNCTION thunk_265e90
0x265e95: INT3 ; original byte CC, padding
0x265e96: INT3 ; original byte CC, padding
0x265e97: INT3 ; original byte CC, padding

; FUNCTION thunk_265e98 [0x265e98, 0x265e9c] | file +0xa40 | ev_9f8fcd7e7582e90f4ae8d10d3700626945970635f835f002c08ae61b8aef4e2c
thunk_265e98:
0x265e98: JMP 0x007dcd40
; END FUNCTION thunk_265e98
0x265e9d: INT3 ; original byte CC, padding
0x265e9e: INT3 ; original byte CC, padding
0x265e9f: INT3 ; original byte CC, padding

; FUNCTION thunk_265ea0 [0x265ea0, 0x265ea4] | file +0xa48 | ev_5d32621c61a283e9ed381e98bbdc04f8f8e60e693addd2854e40ea89656581d7
thunk_265ea0:
0x265ea0: JMP 0x008d25a0
; END FUNCTION thunk_265ea0
0x265ea5: INT3 ; original byte CC, padding
0x265ea6: INT3 ; original byte CC, padding
0x265ea7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ea8 [0x265ea8, 0x265eac] | file +0xa50 | ev_581d77043fca64b9008dbb77b35ef67701738522ff4a29c87647c8175679d453
thunk_265ea8:
0x265ea8: JMP 0x00abd4f0
; END FUNCTION thunk_265ea8
0x265ead: INT3 ; original byte CC, padding
0x265eae: INT3 ; original byte CC, padding
0x265eaf: INT3 ; original byte CC, padding

; FUNCTION thunk_265eb0 [0x265eb0, 0x265eb4] | file +0xa58 | ev_98633b69352d8d9e092c2f8a57ed6c394087995b60f18753830b9031469b16fb
thunk_265eb0:
0x265eb0: JMP 0x00603c90
; END FUNCTION thunk_265eb0
0x265eb5: INT3 ; original byte CC, padding
0x265eb6: INT3 ; original byte CC, padding
0x265eb7: INT3 ; original byte CC, padding

; FUNCTION thunk_265eb8 [0x265eb8, 0x265ebc] | file +0xa60 | ev_cab9ba7fa07157798e9f5cadc43dcf8c8285cfde5e57ed64baa9330bdb4b3364
thunk_265eb8:
0x265eb8: JMP 0x00604cf0
; END FUNCTION thunk_265eb8
0x265ebd: INT3 ; original byte CC, padding
0x265ebe: INT3 ; original byte CC, padding
0x265ebf: INT3 ; original byte CC, padding

; FUNCTION thunk_265ec0 [0x265ec0, 0x265ec4] | file +0xa68 | ev_cac1613c2427686035e9e95ee09e19b96ec40c6b3c8b1ebaece49035e0658fe3
thunk_265ec0:
0x265ec0: JMP 0x004a2850
; END FUNCTION thunk_265ec0
0x265ec5: INT3 ; original byte CC, padding
0x265ec6: INT3 ; original byte CC, padding
0x265ec7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ec8 [0x265ec8, 0x265ecc] | file +0xa70 | ev_b54802e9cb78880b4fcd87bbbf1e79334bfe9d710c70defaf9d16dcf467d49e5
thunk_265ec8:
0x265ec8: JMP 0x00abd540
; END FUNCTION thunk_265ec8
0x265ecd: INT3 ; original byte CC, padding
0x265ece: INT3 ; original byte CC, padding
0x265ecf: INT3 ; original byte CC, padding

; FUNCTION thunk_265ed0 [0x265ed0, 0x265ed4] | file +0xa78 | ev_b4dff738d0aa6573e8ba8ee944a868d36f40233c03506de9cd019889e249d2ae
thunk_265ed0:
0x265ed0: JMP 0x0091c640
; END FUNCTION thunk_265ed0
0x265ed5: INT3 ; original byte CC, padding
0x265ed6: INT3 ; original byte CC, padding
0x265ed7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ed8 [0x265ed8, 0x265edc] | file +0xa80 | ev_2ca4a5aae0e3cb568cb359f5a033eb6c099fe6e02d90047fe6e63bfdb4e4e39a
thunk_265ed8:
0x265ed8: JMP 0x0091cc70
; END FUNCTION thunk_265ed8
0x265edd: INT3 ; original byte CC, padding
0x265ede: INT3 ; original byte CC, padding
0x265edf: INT3 ; original byte CC, padding

; FUNCTION thunk_265ee0 [0x265ee0, 0x265ee4] | file +0xa88 | ev_d6cb9b9d3c6df35bf074ba1290f1451b1704e84cbd4f89e4635d0a2f9a7f33cf
thunk_265ee0:
0x265ee0: JMP 0x00438e30
; END FUNCTION thunk_265ee0
0x265ee5: INT3 ; original byte CC, padding
0x265ee6: INT3 ; original byte CC, padding
0x265ee7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ee8 [0x265ee8, 0x265eec] | file +0xa90 | ev_17e3eae79b71b98f1e0494ebf42f465c42d9d98f8fe67f6e80e7a8148ca93d38
thunk_265ee8:
0x265ee8: JMP 0x00439070
; END FUNCTION thunk_265ee8
0x265eed: INT3 ; original byte CC, padding
0x265eee: INT3 ; original byte CC, padding
0x265eef: INT3 ; original byte CC, padding

; FUNCTION thunk_265ef0 [0x265ef0, 0x265ef4] | file +0xa98 | ev_3d7f77fcd4287dd192f950799646d851d1d0457ce890de81f01f63e41251b5ee
thunk_265ef0:
0x265ef0: JMP 0x00439150
; END FUNCTION thunk_265ef0
0x265ef5: INT3 ; original byte CC, padding
0x265ef6: INT3 ; original byte CC, padding
0x265ef7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ef8 [0x265ef8, 0x265efc] | file +0xaa0 | ev_a4235e90b5a1ccc8ef061ee289bbbd9ef9237b96b7d7228147c2913d89618ad1
thunk_265ef8:
0x265ef8: JMP 0x004393a0
; END FUNCTION thunk_265ef8
0x265efd: INT3 ; original byte CC, padding
0x265efe: INT3 ; original byte CC, padding
0x265eff: INT3 ; original byte CC, padding

; FUNCTION thunk_265f00 [0x265f00, 0x265f04] | file +0xaa8 | ev_23d77d4e06bbb9201cb88289fdc0b83e75b775d8a447532847bc445292f7ab97
thunk_265f00:
0x265f00: JMP 0x006be4d0
; END FUNCTION thunk_265f00
0x265f05: INT3 ; original byte CC, padding
0x265f06: INT3 ; original byte CC, padding
0x265f07: INT3 ; original byte CC, padding

; FUNCTION thunk_265f08 [0x265f08, 0x265f0c] | file +0xab0 | ev_4a3d68654cb86cabcd329a43c71f0fce03f29fb5842108f0b2d34544c0e9902d
thunk_265f08:
0x265f08: JMP 0x00abd930
; END FUNCTION thunk_265f08
0x265f0d: INT3 ; original byte CC, padding
0x265f0e: INT3 ; original byte CC, padding
0x265f0f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f10 [0x265f10, 0x265f14] | file +0xab8 | ev_660c54ded613992dab25244ea16008eaafa9d5e79b9cf48de63fec28375f1716
thunk_265f10:
0x265f10: JMP 0x006be5c0
; END FUNCTION thunk_265f10
0x265f15: INT3 ; original byte CC, padding
0x265f16: INT3 ; original byte CC, padding
0x265f17: INT3 ; original byte CC, padding

; FUNCTION thunk_265f18 [0x265f18, 0x265f1c] | file +0xac0 | ev_15b54fa76534d52deb873287223794be86b404d5facfe580439958524b83ae50
thunk_265f18:
0x265f18: JMP 0x006be800
; END FUNCTION thunk_265f18
0x265f1d: INT3 ; original byte CC, padding
0x265f1e: INT3 ; original byte CC, padding
0x265f1f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f20 [0x265f20, 0x265f24] | file +0xac8 | ev_afc3f4e0d4ec43c8cc6a116e19a7e52381c8ef5e786ddb343a6f23efaab97fda
thunk_265f20:
0x265f20: JMP 0x00a90e10
; END FUNCTION thunk_265f20
0x265f25: INT3 ; original byte CC, padding
0x265f26: INT3 ; original byte CC, padding
0x265f27: INT3 ; original byte CC, padding

; FUNCTION thunk_265f28 [0x265f28, 0x265f2c] | file +0xad0 | ev_9554eb5c1b3cacc00bfb98e60ea7963298dc3f5f36e79f3bc6a971a0cf819738
thunk_265f28:
0x265f28: JMP 0x004a2de0
; END FUNCTION thunk_265f28
0x265f2d: INT3 ; original byte CC, padding
0x265f2e: INT3 ; original byte CC, padding
0x265f2f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f30 [0x265f30, 0x265f34] | file +0xad8 | ev_166a9b8a86592e83f4fb0f60fcac35a44507e80e51f768c7d42f07b667cfdb97
thunk_265f30:
0x265f30: JMP 0x00abdad0
; END FUNCTION thunk_265f30
0x265f35: INT3 ; original byte CC, padding
0x265f36: INT3 ; original byte CC, padding
0x265f37: INT3 ; original byte CC, padding

; FUNCTION thunk_265f38 [0x265f38, 0x265f3c] | file +0xae0 | ev_9d6132a5187a9c01a46635876dc1bcee476c5ffc93037fc4a301ce043d948ba3
thunk_265f38:
0x265f38: JMP 0x00a37660
; END FUNCTION thunk_265f38
0x265f3d: INT3 ; original byte CC, padding
0x265f3e: INT3 ; original byte CC, padding
0x265f3f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f40 [0x265f40, 0x265f44] | file +0xae8 | ev_3d107f6f1eaf2f4090a9431586134de3e3b751f954de14e4d0a0f6bf88ce19b3
thunk_265f40:
0x265f40: JMP 0x00abe1c0
; END FUNCTION thunk_265f40
0x265f45: INT3 ; original byte CC, padding
0x265f46: INT3 ; original byte CC, padding
0x265f47: INT3 ; original byte CC, padding

; FUNCTION thunk_265f48 [0x265f48, 0x265f4c] | file +0xaf0 | ev_90e30bd2294293ce2a3416705c0cd745a1d6ba504f8bf45f007ccdacd3dfae05
thunk_265f48:
0x265f48: JMP 0x00abe7b0
; END FUNCTION thunk_265f48
0x265f4d: INT3 ; original byte CC, padding
0x265f4e: INT3 ; original byte CC, padding
0x265f4f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f50 [0x265f50, 0x265f54] | file +0xaf8 | ev_7a6c201331064d4f27c60fe9598670d33c09a953fe0624a08f78c3e1d95d47ae
thunk_265f50:
0x265f50: JMP 0x009f81f0
; END FUNCTION thunk_265f50
0x265f55: INT3 ; original byte CC, padding
0x265f56: INT3 ; original byte CC, padding
0x265f57: INT3 ; original byte CC, padding

; FUNCTION thunk_265f58 [0x265f58, 0x265f5c] | file +0xb00 | ev_a1eb78dbbdea733c5de2d066d4df609278988e5e0cd5eb75ce20ed31a730dfcc
thunk_265f58:
0x265f58: JMP 0x00be9510
; END FUNCTION thunk_265f58
0x265f5d: INT3 ; original byte CC, padding
0x265f5e: INT3 ; original byte CC, padding
0x265f5f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f60 [0x265f60, 0x265f64] | file +0xb08 | ev_3ce5dde8008e04c265e5bf4d50b808fd7dde164f1b953bc506e8957fea941364
thunk_265f60:
0x265f60: JMP 0x009a7d10
; END FUNCTION thunk_265f60
0x265f65: INT3 ; original byte CC, padding
0x265f66: INT3 ; original byte CC, padding
0x265f67: INT3 ; original byte CC, padding

; FUNCTION thunk_265f68 [0x265f68, 0x265f6c] | file +0xb10 | ev_30fb1503914bfcc9ed442526904c06863c13c21f71c813cb207a809a8b26e288
thunk_265f68:
0x265f68: JMP 0x009a9560
; END FUNCTION thunk_265f68
0x265f6d: INT3 ; original byte CC, padding
0x265f6e: INT3 ; original byte CC, padding
0x265f6f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f70 [0x265f70, 0x265f74] | file +0xb18 | ev_5a722f62fadb8a29429713bcc4bb02986a139904c60356d3956a39654cd442c6
thunk_265f70:
0x265f70: JMP 0x009a9e10
; END FUNCTION thunk_265f70
0x265f75: INT3 ; original byte CC, padding
0x265f76: INT3 ; original byte CC, padding
0x265f77: INT3 ; original byte CC, padding

; FUNCTION thunk_265f78 [0x265f78, 0x265f7c] | file +0xb20 | ev_bcf43827b5c2e17a463acbcf525c45f60b468982552d619865a6bfe7665a37ba
thunk_265f78:
0x265f78: JMP 0x009a9f40
; END FUNCTION thunk_265f78
0x265f7d: INT3 ; original byte CC, padding
0x265f7e: INT3 ; original byte CC, padding
0x265f7f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f80 [0x265f80, 0x265f84] | file +0xb28 | ev_dd33df4d2f9001ee6ac780697739b18182526436a92e50b0414b4999641f292f
thunk_265f80:
0x265f80: JMP 0x008fb440
; END FUNCTION thunk_265f80
0x265f85: INT3 ; original byte CC, padding
0x265f86: INT3 ; original byte CC, padding
0x265f87: INT3 ; original byte CC, padding

; FUNCTION thunk_265f88 [0x265f88, 0x265f8c] | file +0xb30 | ev_ba2dc3f034d56072bd875df79ad909a59c7c7208e8624ef6ffed97aa89dffa93
thunk_265f88:
0x265f88: JMP 0x004a31a0
; END FUNCTION thunk_265f88
0x265f8d: INT3 ; original byte CC, padding
0x265f8e: INT3 ; original byte CC, padding
0x265f8f: INT3 ; original byte CC, padding

; FUNCTION thunk_265f90 [0x265f90, 0x265f94] | file +0xb38 | ev_095469638dfbce825802a80d7715201dbce0a7c679a97b6a1a02cf82121354f8
thunk_265f90:
0x265f90: JMP 0x00abe8b0
; END FUNCTION thunk_265f90
0x265f95: INT3 ; original byte CC, padding
0x265f96: INT3 ; original byte CC, padding
0x265f97: INT3 ; original byte CC, padding

; FUNCTION thunk_265f98 [0x265f98, 0x265f9c] | file +0xb40 | ev_fb01c7296a796c2556b1d847b82e434772757b61df9e17d6c416e7579607cada
thunk_265f98:
0x265f98: JMP 0x009ab1f0
; END FUNCTION thunk_265f98
0x265f9d: INT3 ; original byte CC, padding
0x265f9e: INT3 ; original byte CC, padding
0x265f9f: INT3 ; original byte CC, padding

; FUNCTION thunk_265fa0 [0x265fa0, 0x265fa4] | file +0xb48 | ev_a2e5f09fdea58579b0b34f882641d1c11784819e6375326f32636cf81033081a
thunk_265fa0:
0x265fa0: JMP 0x00abb980
; END FUNCTION thunk_265fa0
0x265fa5: INT3 ; original byte CC, padding
0x265fa6: INT3 ; original byte CC, padding
0x265fa7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fa8 [0x265fa8, 0x265fac] | file +0xb50 | ev_007d1966682d3fb2830ab3ff5fd5f30a8b0c7a994a7cf0ab704ace1290990328
thunk_265fa8:
0x265fa8: JMP 0x006f92e0
; END FUNCTION thunk_265fa8
0x265fad: INT3 ; original byte CC, padding
0x265fae: INT3 ; original byte CC, padding
0x265faf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fb0 [0x265fb0, 0x265fb4] | file +0xb58 | ev_b5e3fe99e245a1f4fcac38bb44ae8ede96ce62ba89baa6e030602ac74cd4e2aa
thunk_265fb0:
0x265fb0: JMP 0x00434da0
; END FUNCTION thunk_265fb0
0x265fb5: INT3 ; original byte CC, padding
0x265fb6: INT3 ; original byte CC, padding
0x265fb7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fb8 [0x265fb8, 0x265fbc] | file +0xb60 | ev_7672c80ba3199670ff9accf5f0a035019deb6746b16a3408477b03c96a6c5a59
thunk_265fb8:
0x265fb8: JMP 0x00434db0
; END FUNCTION thunk_265fb8
0x265fbd: INT3 ; original byte CC, padding
0x265fbe: INT3 ; original byte CC, padding
0x265fbf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fc0 [0x265fc0, 0x265fc4] | file +0xb68 | ev_8e2240493a12bdc4b99dadf1ed7df42990082653e92f2ff14062831045d343e0
thunk_265fc0:
0x265fc0: JMP 0x00434dc0
; END FUNCTION thunk_265fc0
0x265fc5: INT3 ; original byte CC, padding
0x265fc6: INT3 ; original byte CC, padding
0x265fc7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fc8 [0x265fc8, 0x265fcc] | file +0xb70 | ev_5bc36022326d27a478db45be2056e64d81fcc7129c079daca457659d2408596e
thunk_265fc8:
0x265fc8: JMP 0x00437d90
; END FUNCTION thunk_265fc8
0x265fcd: INT3 ; original byte CC, padding
0x265fce: INT3 ; original byte CC, padding
0x265fcf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fd0 [0x265fd0, 0x265fd4] | file +0xb78 | ev_085d5e1e35ff8b5e66880ad7c2e04e4467175a4f31f04ebb7d9393cf13d3f1b3
thunk_265fd0:
0x265fd0: JMP 0x00438280
; END FUNCTION thunk_265fd0
0x265fd5: INT3 ; original byte CC, padding
0x265fd6: INT3 ; original byte CC, padding
0x265fd7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fd8 [0x265fd8, 0x265fdc] | file +0xb80 | ev_4c12611f4973bb95e6930c4a8e7ef5dbbee03d57b570547f98eb8d209fab5390
thunk_265fd8:
0x265fd8: JMP 0x00ae6690
; END FUNCTION thunk_265fd8
0x265fdd: INT3 ; original byte CC, padding
0x265fde: INT3 ; original byte CC, padding
0x265fdf: INT3 ; original byte CC, padding

; FUNCTION thunk_265fe0 [0x265fe0, 0x265fe4] | file +0xb88 | ev_bf6dcc0bad4786ad10277760d33efbdb7edba577f48cb79630de67009f81ffcf
thunk_265fe0:
0x265fe0: JMP 0x00ae6580
; END FUNCTION thunk_265fe0
0x265fe5: INT3 ; original byte CC, padding
0x265fe6: INT3 ; original byte CC, padding
0x265fe7: INT3 ; original byte CC, padding

; FUNCTION thunk_265fe8 [0x265fe8, 0x265fec] | file +0xb90 | ev_71ecfb830571598653e281d3aff5b493d821d784e85e4c6587c26283338629ed
thunk_265fe8:
0x265fe8: JMP 0x004490d0
; END FUNCTION thunk_265fe8
0x265fed: INT3 ; original byte CC, padding
0x265fee: INT3 ; original byte CC, padding
0x265fef: INT3 ; original byte CC, padding

; FUNCTION thunk_265ff0 [0x265ff0, 0x265ff4] | file +0xb98 | ev_20d51f9828264b13131e9cc56afd8f93012bd4f3f0874f592b9469011c13f2d0
thunk_265ff0:
0x265ff0: JMP 0x000a6dc0
; END FUNCTION thunk_265ff0
0x265ff5: INT3 ; original byte CC, padding
0x265ff6: INT3 ; original byte CC, padding
0x265ff7: INT3 ; original byte CC, padding

; FUNCTION thunk_265ff8 [0x265ff8, 0x265ffc] | file +0xba0 | ev_beeb742ebbf9feeea40159b7e4e9da77f11e0cb72de20fa239ab2205a287db21
thunk_265ff8:
0x265ff8: JMP 0x0044aa70
; END FUNCTION thunk_265ff8
0x265ffd: INT3 ; original byte CC, padding
0x265ffe: INT3 ; original byte CC, padding
0x265fff: INT3 ; original byte CC, padding

; FUNCTION thunk_266000 [0x266000, 0x266004] | file +0xba8 | ev_13271d488428427b098ed29297bd6f0d51a9592c4538b98664e46709e6fc2237
thunk_266000:
0x266000: JMP 0x009b6110
; END FUNCTION thunk_266000
0x266005: INT3 ; original byte CC, padding
0x266006: INT3 ; original byte CC, padding
0x266007: INT3 ; original byte CC, padding

; FUNCTION thunk_266008 [0x266008, 0x26600c] | file +0xbb0 | ev_75bd3fb8ec5fe183e20e5f97247dd25019c7d16cd04af1302ee4213661395ea0
thunk_266008:
0x266008: JMP 0x000a7670
; END FUNCTION thunk_266008
0x26600d: INT3 ; original byte CC, padding
0x26600e: INT3 ; original byte CC, padding
0x26600f: INT3 ; original byte CC, padding

; FUNCTION thunk_266010 [0x266010, 0x266014] | file +0xbb8 | ev_9241eefa311a80deb03ac0f658ff745e258a28a4f5240ccd14c8c8025756bf71
thunk_266010:
0x266010: JMP 0x000a7850
; END FUNCTION thunk_266010
0x266015: INT3 ; original byte CC, padding
0x266016: INT3 ; original byte CC, padding
0x266017: INT3 ; original byte CC, padding

; FUNCTION thunk_266018 [0x266018, 0x26601c] | file +0xbc0 | ev_77e192304c9e51060989921f10742631b6c86945dea766a66cde5a5603ae5a03
thunk_266018:
0x266018: JMP 0x000a7880
; END FUNCTION thunk_266018
0x26601d: INT3 ; original byte CC, padding
0x26601e: INT3 ; original byte CC, padding
0x26601f: INT3 ; original byte CC, padding

; FUNCTION thunk_266020 [0x266020, 0x266024] | file +0xbc8 | ev_08817f0e48324fa1734eebf5afd693d461d4f25faa9a57614305dbeec79fe7c5
thunk_266020:
0x266020: JMP 0x00452040
; END FUNCTION thunk_266020
0x266025: INT3 ; original byte CC, padding
0x266026: INT3 ; original byte CC, padding
0x266027: INT3 ; original byte CC, padding

; FUNCTION thunk_266028 [0x266028, 0x26602c] | file +0xbd0 | ev_1e5a04d67b16d2fa526870e464a7a9b92615f08e45de21b528d6a0e169950e95
thunk_266028:
0x266028: JMP 0x00454cc0
; END FUNCTION thunk_266028
0x26602d: INT3 ; original byte CC, padding
0x26602e: INT3 ; original byte CC, padding
0x26602f: INT3 ; original byte CC, padding

; FUNCTION thunk_266030 [0x266030, 0x266034] | file +0xbd8 | ev_cc10ac34cdc34cc724edd95074b755226bea7e251a7b28ab616c70c7e7e3b6f6
thunk_266030:
0x266030: JMP 0x00457820
; END FUNCTION thunk_266030
0x266035: INT3 ; original byte CC, padding
0x266036: INT3 ; original byte CC, padding
0x266037: INT3 ; original byte CC, padding

; FUNCTION thunk_266038 [0x266038, 0x26603c] | file +0xbe0 | ev_67aa9e5fd76f1c965fc090011e512499a3a3b198c77aab350e1d0473784fea18
thunk_266038:
0x266038: JMP 0x0046df70
; END FUNCTION thunk_266038
0x26603d: INT3 ; original byte CC, padding
0x26603e: INT3 ; original byte CC, padding
0x26603f: INT3 ; original byte CC, padding

; FUNCTION thunk_266040 [0x266040, 0x266044] | file +0xbe8 | ev_0284f5842ab359d45c0563372236b145cdde7902ac94bd430f6a223a9830dcd7
thunk_266040:
0x266040: JMP 0x0046e080
; END FUNCTION thunk_266040
0x266045: INT3 ; original byte CC, padding
0x266046: INT3 ; original byte CC, padding
0x266047: INT3 ; original byte CC, padding

; FUNCTION thunk_266048 [0x266048, 0x26604c] | file +0xbf0 | ev_274829a26a30245653849082cc72e6e35fed236ce0bbdb3ec6faab0eada81538
thunk_266048:
0x266048: JMP 0x00472990
; END FUNCTION thunk_266048
0x26604d: INT3 ; original byte CC, padding
0x26604e: INT3 ; original byte CC, padding
0x26604f: INT3 ; original byte CC, padding

; FUNCTION thunk_266050 [0x266050, 0x266054] | file +0xbf8 | ev_ba4f7a680946cc24f7d64ad866a978721163a825432c7cf1640b506b2eb8784d
thunk_266050:
0x266050: JMP 0x004733b0
; END FUNCTION thunk_266050
0x266055: INT3 ; original byte CC, padding
0x266056: INT3 ; original byte CC, padding
0x266057: INT3 ; original byte CC, padding

; FUNCTION thunk_266058 [0x266058, 0x26605c] | file +0xc00 | ev_8d6f5eab901c31a67905fdcd53e3dc1c0fbc315b09039f6f12e50ade27b3174e
thunk_266058:
0x266058: JMP 0x004738b0
; END FUNCTION thunk_266058
0x26605d: INT3 ; original byte CC, padding
0x26605e: INT3 ; original byte CC, padding
0x26605f: INT3 ; original byte CC, padding

; FUNCTION thunk_266060 [0x266060, 0x266064] | file +0xc08 | ev_e8b4123b0dba35e5d807682900886d6e11de80f9778dd14c6f7aaba6269b6938
thunk_266060:
0x266060: JMP 0x00474250
; END FUNCTION thunk_266060
0x266065: INT3 ; original byte CC, padding
0x266066: INT3 ; original byte CC, padding
0x266067: INT3 ; original byte CC, padding

; FUNCTION thunk_266068 [0x266068, 0x26606c] | file +0xc10 | ev_f75afc0429bb5c477bea05f362dc59833ce7113d6a65211ba6ab62563bdc61ad
thunk_266068:
0x266068: JMP 0x00474db0
; END FUNCTION thunk_266068
0x26606d: INT3 ; original byte CC, padding
0x26606e: INT3 ; original byte CC, padding
0x26606f: INT3 ; original byte CC, padding

; FUNCTION thunk_266070 [0x266070, 0x266074] | file +0xc18 | ev_f2aa6b1b31f49271e828c16308725efe4f855d10cb85de9cff13f6cdbda35fb3
thunk_266070:
0x266070: JMP 0x0047cff0
; END FUNCTION thunk_266070
0x266075: INT3 ; original byte CC, padding
0x266076: INT3 ; original byte CC, padding
0x266077: INT3 ; original byte CC, padding

; FUNCTION thunk_266078 [0x266078, 0x26607c] | file +0xc20 | ev_51642329c1bbde0e93e8dec02d8735898e1286b91137062d76126033999a3d32
thunk_266078:
0x266078: JMP 0x0021dff0
; END FUNCTION thunk_266078
0x26607d: INT3 ; original byte CC, padding
0x26607e: INT3 ; original byte CC, padding
0x26607f: INT3 ; original byte CC, padding

; FUNCTION thunk_266080 [0x266080, 0x266084] | file +0xc28 | ev_813edcb664f5a4436816b054fe42fdbf47ba1bcffa004d50477f7cf091d814be
thunk_266080:
0x266080: JMP 0x00490300
; END FUNCTION thunk_266080
0x266085: INT3 ; original byte CC, padding
0x266086: INT3 ; original byte CC, padding
0x266087: INT3 ; original byte CC, padding

; FUNCTION thunk_266088 [0x266088, 0x26608c] | file +0xc30 | ev_bb9d9eb4c7788123aa96c895346d74ee3fcfb19ec4015518bd51902322271c89
thunk_266088:
0x266088: JMP 0x00490db0
; END FUNCTION thunk_266088
0x26608d: INT3 ; original byte CC, padding
0x26608e: INT3 ; original byte CC, padding
0x26608f: INT3 ; original byte CC, padding

; FUNCTION thunk_266090 [0x266090, 0x266094] | file +0xc38 | ev_5f37661cb7d598c9dc86a7cefc47d3cf985f370da26ca037d619cb73a5ca4b8e
thunk_266090:
0x266090: JMP 0x00497fb0
; END FUNCTION thunk_266090
0x266095: INT3 ; original byte CC, padding
0x266096: INT3 ; original byte CC, padding
0x266097: INT3 ; original byte CC, padding

; FUNCTION thunk_266098 [0x266098, 0x26609c] | file +0xc40 | ev_228fbdbd5af4919e2970004de3681f60847a1febed9f5d2595709cbb8462d11b
thunk_266098:
0x266098: JMP 0x00497fe0
; END FUNCTION thunk_266098
0x26609d: INT3 ; original byte CC, padding
0x26609e: INT3 ; original byte CC, padding
0x26609f: INT3 ; original byte CC, padding

; FUNCTION thunk_2660a0 [0x2660a0, 0x2660a4] | file +0xc48 | ev_ed6831e278bd783f3be5cb487656b3e4fbd09e14c5253eef5c2f3bd4fd69d74e
thunk_2660a0:
0x2660a0: JMP 0x00498630
; END FUNCTION thunk_2660a0
0x2660a5: INT3 ; original byte CC, padding
0x2660a6: INT3 ; original byte CC, padding
0x2660a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660a8 [0x2660a8, 0x2660ac] | file +0xc50 | ev_c8ed06089cd894204da39e1cac0194ac9499dfa20bfb4873e4db9564a46f5e29
thunk_2660a8:
0x2660a8: JMP 0x00498640
; END FUNCTION thunk_2660a8
0x2660ad: INT3 ; original byte CC, padding
0x2660ae: INT3 ; original byte CC, padding
0x2660af: INT3 ; original byte CC, padding

; FUNCTION thunk_2660b0 [0x2660b0, 0x2660b4] | file +0xc58 | ev_2504a752eb3543760284d7669f69d99c6776905f0b697402ee78f8025cb45d24
thunk_2660b0:
0x2660b0: JMP 0x008f7bc0
; END FUNCTION thunk_2660b0
0x2660b5: INT3 ; original byte CC, padding
0x2660b6: INT3 ; original byte CC, padding
0x2660b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660b8 [0x2660b8, 0x2660bc] | file +0xc60 | ev_e75168b4c23bf70efaf2133494a544d5d58e397acbb367674bb96a93020a891b
thunk_2660b8:
0x2660b8: JMP 0x008f6800
; END FUNCTION thunk_2660b8
0x2660bd: INT3 ; original byte CC, padding
0x2660be: INT3 ; original byte CC, padding
0x2660bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2660c0 [0x2660c0, 0x2660c4] | file +0xc68 | ev_da7e97c369a81ea579dcdd4063c45b34ce659b954f7474a798c98d18f5072f48
thunk_2660c0:
0x2660c0: JMP 0x008f7420
; END FUNCTION thunk_2660c0
0x2660c5: INT3 ; original byte CC, padding
0x2660c6: INT3 ; original byte CC, padding
0x2660c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660c8 [0x2660c8, 0x2660cc] | file +0xc70 | ev_757ca60740b8f73bb6ff2a575203849b790702722e8d4687c36fb07a63dc9d6a
thunk_2660c8:
0x2660c8: JMP 0x008f9f80
; END FUNCTION thunk_2660c8
0x2660cd: INT3 ; original byte CC, padding
0x2660ce: INT3 ; original byte CC, padding
0x2660cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2660d0 [0x2660d0, 0x2660d4] | file +0xc78 | ev_b14e0cde435fef81d6524b07ab25a64c832dfa4e07ec4813d36cb68c5a2542e6
thunk_2660d0:
0x2660d0: JMP 0x005df350
; END FUNCTION thunk_2660d0
0x2660d5: INT3 ; original byte CC, padding
0x2660d6: INT3 ; original byte CC, padding
0x2660d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660d8 [0x2660d8, 0x2660dc] | file +0xc80 | ev_695ca4375c51c495d91c54720b2ee5edbe4646386d7bdf42b6f1f7f1096ab7aa
thunk_2660d8:
0x2660d8: JMP 0x005df820
; END FUNCTION thunk_2660d8
0x2660dd: INT3 ; original byte CC, padding
0x2660de: INT3 ; original byte CC, padding
0x2660df: INT3 ; original byte CC, padding

; FUNCTION thunk_2660e0 [0x2660e0, 0x2660e4] | file +0xc88 | ev_7b89d84bc17a972cb085dda05242e82715a0d3c4e9b5c80e1d1a10d3cf703d8e
thunk_2660e0:
0x2660e0: JMP 0x00a34ce0
; END FUNCTION thunk_2660e0
0x2660e5: INT3 ; original byte CC, padding
0x2660e6: INT3 ; original byte CC, padding
0x2660e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660e8 [0x2660e8, 0x2660ec] | file +0xc90 | ev_e88176bc6d92c2a8a7349783a3ea17eb1596a47cc8519ecba94f4b20c0525334
thunk_2660e8:
0x2660e8: JMP 0x005e84a0
; END FUNCTION thunk_2660e8
0x2660ed: INT3 ; original byte CC, padding
0x2660ee: INT3 ; original byte CC, padding
0x2660ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2660f0 [0x2660f0, 0x2660f4] | file +0xc98 | ev_338488211248baab7b79b0818ed3b67f3ca1443ece0ee1265a6eecf7dd0d3ecd
thunk_2660f0:
0x2660f0: JMP 0x008f81f0
; END FUNCTION thunk_2660f0
0x2660f5: INT3 ; original byte CC, padding
0x2660f6: INT3 ; original byte CC, padding
0x2660f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2660f8 [0x2660f8, 0x2660fc] | file +0xca0 | ev_7967a6f62a6c6d7ec9772ad9b5eac8becd562619cecab980b52874d1b54dca4b
thunk_2660f8:
0x2660f8: JMP 0x008f9410
; END FUNCTION thunk_2660f8
0x2660fd: INT3 ; original byte CC, padding
0x2660fe: INT3 ; original byte CC, padding
0x2660ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266100 [0x266100, 0x266104] | file +0xca8 | ev_849951bba96cef9609da76002488e8a1d20f07ec9230cefd95bfb3ad861b36a1
thunk_266100:
0x266100: JMP 0x008fc3f0
; END FUNCTION thunk_266100
0x266105: INT3 ; original byte CC, padding
0x266106: INT3 ; original byte CC, padding
0x266107: INT3 ; original byte CC, padding

; FUNCTION thunk_266108 [0x266108, 0x26610c] | file +0xcb0 | ev_1e6da3dff07fe59402a80c14648d04826df148070707dd9c0ef6a4e1fd74fafd
thunk_266108:
0x266108: JMP 0x008f6c90
; END FUNCTION thunk_266108
0x26610d: INT3 ; original byte CC, padding
0x26610e: INT3 ; original byte CC, padding
0x26610f: INT3 ; original byte CC, padding

; FUNCTION thunk_266110 [0x266110, 0x266114] | file +0xcb8 | ev_d2c807990d94f945e00cd701e68c26292cb1e2009d73f8f84b655ea38e88c052
thunk_266110:
0x266110: JMP 0x00cb1a10
; END FUNCTION thunk_266110
0x266115: INT3 ; original byte CC, padding
0x266116: INT3 ; original byte CC, padding
0x266117: INT3 ; original byte CC, padding

; FUNCTION thunk_266118 [0x266118, 0x26611c] | file +0xcc0 | ev_53472b939b20ba25a57ab4d91660139c63e4a4ba8839cddb43837794fa57e6e5
thunk_266118:
0x266118: JMP 0x00ab83a0
; END FUNCTION thunk_266118
0x26611d: INT3 ; original byte CC, padding
0x26611e: INT3 ; original byte CC, padding
0x26611f: INT3 ; original byte CC, padding

; FUNCTION thunk_266120 [0x266120, 0x266124] | file +0xcc8 | ev_e3874429a2cd73930fad18d5594175104a6647df9411fdc9fdaba20f544869ac
thunk_266120:
0x266120: JMP 0x00ab83b0
; END FUNCTION thunk_266120
0x266125: INT3 ; original byte CC, padding
0x266126: INT3 ; original byte CC, padding
0x266127: INT3 ; original byte CC, padding

; FUNCTION thunk_266128 [0x266128, 0x26612c] | file +0xcd0 | ev_9c8c416f951cb9e26ea8daf6254d67a2a2cb5f1e29a81b93155052ba74848071
thunk_266128:
0x266128: JMP 0x008fa1c0
; END FUNCTION thunk_266128
0x26612d: INT3 ; original byte CC, padding
0x26612e: INT3 ; original byte CC, padding
0x26612f: INT3 ; original byte CC, padding

; FUNCTION thunk_266130 [0x266130, 0x266134] | file +0xcd8 | ev_f75fd383e35d1954533ca22638803f3c72f6a82546cd3a8ceccad79fa1daf4b7
thunk_266130:
0x266130: JMP 0x008f7b40
; END FUNCTION thunk_266130
0x266135: INT3 ; original byte CC, padding
0x266136: INT3 ; original byte CC, padding
0x266137: INT3 ; original byte CC, padding

; FUNCTION thunk_266138 [0x266138, 0x26613c] | file +0xce0 | ev_8207120065dabc5b19c2f962cda8ae9f598c7325173c735e6d269bcccae85a15
thunk_266138:
0x266138: JMP 0x004a0960
; END FUNCTION thunk_266138
0x26613d: INT3 ; original byte CC, padding
0x26613e: INT3 ; original byte CC, padding
0x26613f: INT3 ; original byte CC, padding

; FUNCTION thunk_266140 [0x266140, 0x266144] | file +0xce8 | ev_6d7cc7b56a7cd224e4e1ca39aa3c2a2d97be8d247b1b879fbe064c464bd07514
thunk_266140:
0x266140: JMP 0x00729780
; END FUNCTION thunk_266140
0x266145: INT3 ; original byte CC, padding
0x266146: INT3 ; original byte CC, padding
0x266147: INT3 ; original byte CC, padding

; FUNCTION thunk_266148 [0x266148, 0x26614c] | file +0xcf0 | ev_62c7b086c5573b195bb72867047d219ff493c01e81f65173fdda18ed43941bca
thunk_266148:
0x266148: JMP 0x00729790
; END FUNCTION thunk_266148
0x26614d: INT3 ; original byte CC, padding
0x26614e: INT3 ; original byte CC, padding
0x26614f: INT3 ; original byte CC, padding

; FUNCTION thunk_266150 [0x266150, 0x266154] | file +0xcf8 | ev_efe9729a0a63c617fe6c009276ba9db0563058f4462ea9ff1bd507ed71a70a62
thunk_266150:
0x266150: JMP 0x007297a0
; END FUNCTION thunk_266150
0x266155: INT3 ; original byte CC, padding
0x266156: INT3 ; original byte CC, padding
0x266157: INT3 ; original byte CC, padding

; FUNCTION thunk_266158 [0x266158, 0x26615c] | file +0xd00 | ev_b0621322d51d31fb36c314eb23a97a956aceffc0a88da9f9970a8a68d289a159
thunk_266158:
0x266158: JMP 0x006bb590
; END FUNCTION thunk_266158
0x26615d: INT3 ; original byte CC, padding
0x26615e: INT3 ; original byte CC, padding
0x26615f: INT3 ; original byte CC, padding

; FUNCTION thunk_266160 [0x266160, 0x266164] | file +0xd08 | ev_fcc1bfa009ab0ece3e52445710d3c3b56a294709c05cf127ebc6989ec52073a0
thunk_266160:
0x266160: JMP 0x00ab8da0
; END FUNCTION thunk_266160
0x266165: INT3 ; original byte CC, padding
0x266166: INT3 ; original byte CC, padding
0x266167: INT3 ; original byte CC, padding

; FUNCTION thunk_266168 [0x266168, 0x26616c] | file +0xd10 | ev_85fe954f6e700c0007bf50bcb5abe7fa8945362eb645e2117df19c1cb45cfd0f
thunk_266168:
0x266168: JMP 0x008fa170
; END FUNCTION thunk_266168
0x26616d: INT3 ; original byte CC, padding
0x26616e: INT3 ; original byte CC, padding
0x26616f: INT3 ; original byte CC, padding

; FUNCTION thunk_266170 [0x266170, 0x266174] | file +0xd18 | ev_c890e498bbcc6f8ac6e3e30792c03ca2289ba3e9f242a390489aa6aea5228cf5
thunk_266170:
0x266170: JMP 0x00b7f0c0
; END FUNCTION thunk_266170
0x266175: INT3 ; original byte CC, padding
0x266176: INT3 ; original byte CC, padding
0x266177: INT3 ; original byte CC, padding

; FUNCTION thunk_266178 [0x266178, 0x26617c] | file +0xd20 | ev_e1430f65ea8ac5404922d82f740706346a0b3b614afea6cb0d6d4ab94bd94f4d
thunk_266178:
0x266178: JMP 0x00b7f100
; END FUNCTION thunk_266178
0x26617d: INT3 ; original byte CC, padding
0x26617e: INT3 ; original byte CC, padding
0x26617f: INT3 ; original byte CC, padding

; FUNCTION thunk_266180 [0x266180, 0x266184] | file +0xd28 | ev_fd48f8dae2e01b6715b9a25b9598a63851195089c4d557d8e15a01f560b938a8
thunk_266180:
0x266180: JMP 0x008f9cf0
; END FUNCTION thunk_266180
0x266185: INT3 ; original byte CC, padding
0x266186: INT3 ; original byte CC, padding
0x266187: INT3 ; original byte CC, padding

; FUNCTION thunk_266188 [0x266188, 0x26618c] | file +0xd30 | ev_544cba46ca25c52016b06b1336491047811985c85719c88aca599bb88ca2fe9e
thunk_266188:
0x266188: JMP 0x008fa740
; END FUNCTION thunk_266188
0x26618d: INT3 ; original byte CC, padding
0x26618e: INT3 ; original byte CC, padding
0x26618f: INT3 ; original byte CC, padding

; FUNCTION thunk_266190 [0x266190, 0x266194] | file +0xd38 | ev_c59a83c527ec2c14aefac1b9685ab1f5033a1302df2ae7c904635b8c49564da7
thunk_266190:
0x266190: JMP 0x00552b70
; END FUNCTION thunk_266190
0x266195: INT3 ; original byte CC, padding
0x266196: INT3 ; original byte CC, padding
0x266197: INT3 ; original byte CC, padding

; FUNCTION thunk_266198 [0x266198, 0x26619c] | file +0xd40 | ev_48793e7f58ef9e0f869d5bf7e4197a1365c5204a853d9f6e86f272e062ecad5f
thunk_266198:
0x266198: JMP 0x00552bf0
; END FUNCTION thunk_266198
0x26619d: INT3 ; original byte CC, padding
0x26619e: INT3 ; original byte CC, padding
0x26619f: INT3 ; original byte CC, padding

; FUNCTION thunk_2661a0 [0x2661a0, 0x2661a4] | file +0xd48 | ev_21f6a74ead4cf7febff2d4196b2a7986d4cd72a85ab83c1e027b9eb014c9db41
thunk_2661a0:
0x2661a0: JMP 0x00552c50
; END FUNCTION thunk_2661a0
0x2661a5: INT3 ; original byte CC, padding
0x2661a6: INT3 ; original byte CC, padding
0x2661a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661a8 [0x2661a8, 0x2661ac] | file +0xd50 | ev_08c7efec6159a4231f725feeb2ae4667652444949af05bfad614ed486cc10726
thunk_2661a8:
0x2661a8: JMP 0x00552c80
; END FUNCTION thunk_2661a8
0x2661ad: INT3 ; original byte CC, padding
0x2661ae: INT3 ; original byte CC, padding
0x2661af: INT3 ; original byte CC, padding

; FUNCTION thunk_2661b0 [0x2661b0, 0x2661b4] | file +0xd58 | ev_e62aa65b183e4f6ea7ab3b5cd9bfe757dfa71a58a3191566234425bdfd6b468c
thunk_2661b0:
0x2661b0: JMP 0x00552cb0
; END FUNCTION thunk_2661b0
0x2661b5: INT3 ; original byte CC, padding
0x2661b6: INT3 ; original byte CC, padding
0x2661b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661b8 [0x2661b8, 0x2661bc] | file +0xd60 | ev_59a4649b3a618147c0f8e7d991262dccbb38b62bab46745d9dc86f95ee01c0f8
thunk_2661b8:
0x2661b8: JMP 0x00552ce0
; END FUNCTION thunk_2661b8
0x2661bd: INT3 ; original byte CC, padding
0x2661be: INT3 ; original byte CC, padding
0x2661bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2661c0 [0x2661c0, 0x2661c4] | file +0xd68 | ev_6ab3dee911315061b49dc3807ba7a64a017fe2ef5e7edcc67e0a8b25af23a042
thunk_2661c0:
0x2661c0: JMP 0x00b7e800
; END FUNCTION thunk_2661c0
0x2661c5: INT3 ; original byte CC, padding
0x2661c6: INT3 ; original byte CC, padding
0x2661c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661c8 [0x2661c8, 0x2661cc] | file +0xd70 | ev_255f396dca8f49de3450f7d86252eaee6b5c42959e9628c715fbd35c890e38e7
thunk_2661c8:
0x2661c8: JMP 0x00b7ebe0
; END FUNCTION thunk_2661c8
0x2661cd: INT3 ; original byte CC, padding
0x2661ce: INT3 ; original byte CC, padding
0x2661cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2661d0 [0x2661d0, 0x2661d4] | file +0xd78 | ev_c9d1cac1498546eeeab2fce1f6faafc853cb664e949cc88c10d0bee8e3abeb57
thunk_2661d0:
0x2661d0: JMP 0x00b7ef70
; END FUNCTION thunk_2661d0
0x2661d5: INT3 ; original byte CC, padding
0x2661d6: INT3 ; original byte CC, padding
0x2661d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661d8 [0x2661d8, 0x2661dc] | file +0xd80 | ev_0b00bb178d5769719b66fc3253ea231d0f2d95e28ca0c9c7dde96e4f42e76c33
thunk_2661d8:
0x2661d8: JMP 0x00c06d30
; END FUNCTION thunk_2661d8
0x2661dd: INT3 ; original byte CC, padding
0x2661de: INT3 ; original byte CC, padding
0x2661df: INT3 ; original byte CC, padding

; FUNCTION thunk_2661e0 [0x2661e0, 0x2661e4] | file +0xd88 | ev_498718fb310bd1eb2b790209f3a3d38511b8173ce987d8063b228403a1c56ad7
thunk_2661e0:
0x2661e0: JMP 0x00792690
; END FUNCTION thunk_2661e0
0x2661e5: INT3 ; original byte CC, padding
0x2661e6: INT3 ; original byte CC, padding
0x2661e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661e8 [0x2661e8, 0x2661ec] | file +0xd90 | ev_8a8290c5607724f7392ee63f16aadf7e18422517ed6a4e904e9edc27d524cc6b
thunk_2661e8:
0x2661e8: JMP 0x005e8b20
; END FUNCTION thunk_2661e8
0x2661ed: INT3 ; original byte CC, padding
0x2661ee: INT3 ; original byte CC, padding
0x2661ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2661f0 [0x2661f0, 0x2661f4] | file +0xd98 | ev_8c1ed7bc8853604e5acf55448a86e622f5ce0b7e72c7ce4cb732a0f49b42d130
thunk_2661f0:
0x2661f0: JMP 0x00552d10
; END FUNCTION thunk_2661f0
0x2661f5: INT3 ; original byte CC, padding
0x2661f6: INT3 ; original byte CC, padding
0x2661f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2661f8 [0x2661f8, 0x2661fc] | file +0xda0 | ev_5dd1aefd4eafac7c3e2c0dd0b2f9a465137289585f5cde83e19c612c55283277
thunk_2661f8:
0x2661f8: JMP 0x00b7f160
; END FUNCTION thunk_2661f8
0x2661fd: INT3 ; original byte CC, padding
0x2661fe: INT3 ; original byte CC, padding
0x2661ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266200 [0x266200, 0x266204] | file +0xda8 | ev_757ed4e16199c82a0c607920c217f95085b37f8a6717d7dbb7978116461ae164
thunk_266200:
0x266200: JMP 0x005de250
; END FUNCTION thunk_266200
0x266205: INT3 ; original byte CC, padding
0x266206: INT3 ; original byte CC, padding
0x266207: INT3 ; original byte CC, padding

; FUNCTION thunk_266208 [0x266208, 0x26620c] | file +0xdb0 | ev_a91a98e2442ba222b625021ef2f015620cb04418f3424570d5a614e1076c3fcb
thunk_266208:
0x266208: JMP 0x00a54a30
; END FUNCTION thunk_266208
0x26620d: INT3 ; original byte CC, padding
0x26620e: INT3 ; original byte CC, padding
0x26620f: INT3 ; original byte CC, padding

; FUNCTION thunk_266210 [0x266210, 0x266214] | file +0xdb8 | ev_62abc88f2ffa6f5a0735a3c380225d00d1cc5230fe6196dbd4554708b105ba38
thunk_266210:
0x266210: JMP 0x00a54a40
; END FUNCTION thunk_266210
0x266215: INT3 ; original byte CC, padding
0x266216: INT3 ; original byte CC, padding
0x266217: INT3 ; original byte CC, padding

; FUNCTION thunk_266218 [0x266218, 0x26621c] | file +0xdc0 | ev_316646bb0eb8fd79801320346e50eaec76dfa54cb81513b797abe9e2b4888da0
thunk_266218:
0x266218: JMP 0x00a54a50
; END FUNCTION thunk_266218
0x26621d: INT3 ; original byte CC, padding
0x26621e: INT3 ; original byte CC, padding
0x26621f: INT3 ; original byte CC, padding

; FUNCTION thunk_266220 [0x266220, 0x266224] | file +0xdc8 | ev_4a106cd82fbe8c86da526794caa3df2f7d5aef9eaae4cff41d637e9c2cd824be
thunk_266220:
0x266220: JMP 0x00a54a60
; END FUNCTION thunk_266220
0x266225: INT3 ; original byte CC, padding
0x266226: INT3 ; original byte CC, padding
0x266227: INT3 ; original byte CC, padding

; FUNCTION thunk_266228 [0x266228, 0x26622c] | file +0xdd0 | ev_351475a479b8e03694262bc8dcef5bbd2294aeaff31eeaa55316389e51414995
thunk_266228:
0x266228: JMP 0x00a54a80
; END FUNCTION thunk_266228
0x26622d: INT3 ; original byte CC, padding
0x26622e: INT3 ; original byte CC, padding
0x26622f: INT3 ; original byte CC, padding

; FUNCTION thunk_266230 [0x266230, 0x266234] | file +0xdd8 | ev_068172e45f643e23c2637d51152a476b51dec1fd8b501c50c998a097591390c2
thunk_266230:
0x266230: JMP 0x00a54a90
; END FUNCTION thunk_266230
0x266235: INT3 ; original byte CC, padding
0x266236: INT3 ; original byte CC, padding
0x266237: INT3 ; original byte CC, padding

; FUNCTION thunk_266238 [0x266238, 0x26623c] | file +0xde0 | ev_dfc19b0d494a5652a47ade31009b1e4c990f00087fde5e625a98a44c96cf0818
thunk_266238:
0x266238: JMP 0x008f9720
; END FUNCTION thunk_266238
0x26623d: INT3 ; original byte CC, padding
0x26623e: INT3 ; original byte CC, padding
0x26623f: INT3 ; original byte CC, padding

; FUNCTION thunk_266240 [0x266240, 0x266244] | file +0xde8 | ev_c4b0a4d54127ab7bacb8213d7c83b00ba3119ecb6a1ed4bcefb4af04d714bff9
thunk_266240:
0x266240: JMP 0x00a54ab0
; END FUNCTION thunk_266240
0x266245: INT3 ; original byte CC, padding
0x266246: INT3 ; original byte CC, padding
0x266247: INT3 ; original byte CC, padding

; FUNCTION thunk_266248 [0x266248, 0x26624c] | file +0xdf0 | ev_3955365d4f354d375284caa65baa7fdc58b06cbf43962a43f4403daf1e6ca121
thunk_266248:
0x266248: JMP 0x008f64e0
; END FUNCTION thunk_266248
0x26624d: INT3 ; original byte CC, padding
0x26624e: INT3 ; original byte CC, padding
0x26624f: INT3 ; original byte CC, padding

; FUNCTION thunk_266250 [0x266250, 0x266254] | file +0xdf8 | ev_f96adbdce6189ddf520dc792bf796a549b63d30d28bf78afb120432ba46da586
thunk_266250:
0x266250: JMP 0x008f5ef0
; END FUNCTION thunk_266250
0x266255: INT3 ; original byte CC, padding
0x266256: INT3 ; original byte CC, padding
0x266257: INT3 ; original byte CC, padding

; FUNCTION thunk_266258 [0x266258, 0x26625c] | file +0xe00 | ev_1b34325666d3c9c6d915c324fbccf4635988b46d93e5a9c542d2c00f603b09aa
thunk_266258:
0x266258: JMP 0x00a54a20
; END FUNCTION thunk_266258
0x26625d: INT3 ; original byte CC, padding
0x26625e: INT3 ; original byte CC, padding
0x26625f: INT3 ; original byte CC, padding

; FUNCTION thunk_266260 [0x266260, 0x266264] | file +0xe08 | ev_4d1b8a3331344e715a72a250a7d7161a2ccd108eb7ebf2facdfab957a5a66bb3
thunk_266260:
0x266260: JMP 0x00a54a70
; END FUNCTION thunk_266260
0x266265: INT3 ; original byte CC, padding
0x266266: INT3 ; original byte CC, padding
0x266267: INT3 ; original byte CC, padding

; FUNCTION thunk_266268 [0x266268, 0x26626c] | file +0xe10 | ev_22e4db3caf86ff04a9eee13f105b1058dc4863b54bce4a01374f8889e8a30600
thunk_266268:
0x266268: JMP 0x00a54aa0
; END FUNCTION thunk_266268
0x26626d: INT3 ; original byte CC, padding
0x26626e: INT3 ; original byte CC, padding
0x26626f: INT3 ; original byte CC, padding

; FUNCTION thunk_266270 [0x266270, 0x266274] | file +0xe18 | ev_890be6f1c7920f0033104ee575247e1908f0c97280a687224b3a7da85c57310a
thunk_266270:
0x266270: JMP 0x006e54d0
; END FUNCTION thunk_266270
0x266275: INT3 ; original byte CC, padding
0x266276: INT3 ; original byte CC, padding
0x266277: INT3 ; original byte CC, padding

; FUNCTION thunk_266278 [0x266278, 0x26627c] | file +0xe20 | ev_38a9d23e776f221c1f5b721b4f7c272ef04b2b40606ad30cb41ed2f6fe414c12
thunk_266278:
0x266278: JMP 0x00b7f4b0
; END FUNCTION thunk_266278
0x26627d: INT3 ; original byte CC, padding
0x26627e: INT3 ; original byte CC, padding
0x26627f: INT3 ; original byte CC, padding

; FUNCTION thunk_266280 [0x266280, 0x266284] | file +0xe28 | ev_2f26b0745ccafe1db376effabe7a0a78b79d483ba1574dca7a4e24346f526141
thunk_266280:
0x266280: JMP 0x0083d660
; END FUNCTION thunk_266280
0x266285: INT3 ; original byte CC, padding
0x266286: INT3 ; original byte CC, padding
0x266287: INT3 ; original byte CC, padding

; FUNCTION thunk_266288 [0x266288, 0x26628c] | file +0xe30 | ev_f9d0bb27935ce47d742649223a7e2e81d68bc42ed16701b18f269579e25bb4e0
thunk_266288:
0x266288: JMP 0x0083d7c0
; END FUNCTION thunk_266288
0x26628d: INT3 ; original byte CC, padding
0x26628e: INT3 ; original byte CC, padding
0x26628f: INT3 ; original byte CC, padding

; FUNCTION thunk_266290 [0x266290, 0x266294] | file +0xe38 | ev_a1a078ae92c7980fc788d3c99d9298c6590db02a5982d9127f09f838f9409650
thunk_266290:
0x266290: JMP 0x0083dab0
; END FUNCTION thunk_266290
0x266295: INT3 ; original byte CC, padding
0x266296: INT3 ; original byte CC, padding
0x266297: INT3 ; original byte CC, padding

; FUNCTION thunk_266298 [0x266298, 0x26629c] | file +0xe40 | ev_a78e29a1ea04bf6d30594d3b19849395bc30b22f59337d3f40a121a6320dc5ab
thunk_266298:
0x266298: JMP 0x0083de80
; END FUNCTION thunk_266298
0x26629d: INT3 ; original byte CC, padding
0x26629e: INT3 ; original byte CC, padding
0x26629f: INT3 ; original byte CC, padding

; FUNCTION thunk_2662a0 [0x2662a0, 0x2662a4] | file +0xe48 | ev_155d45ce5e405802c8aeeaba1343bdef4231a636cf536cf310fc69c4c61f7313
thunk_2662a0:
0x2662a0: JMP 0x008f9c80
; END FUNCTION thunk_2662a0
0x2662a5: INT3 ; original byte CC, padding
0x2662a6: INT3 ; original byte CC, padding
0x2662a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662a8 [0x2662a8, 0x2662ac] | file +0xe50 | ev_bd1796ad561e4782dded9a21477730f4bdf304f5dabc5868b80761969759fad6
thunk_2662a8:
0x2662a8: JMP 0x008fa110
; END FUNCTION thunk_2662a8
0x2662ad: INT3 ; original byte CC, padding
0x2662ae: INT3 ; original byte CC, padding
0x2662af: INT3 ; original byte CC, padding

; FUNCTION thunk_2662b0 [0x2662b0, 0x2662b4] | file +0xe58 | ev_0480d28ab6222af2b93e4fd113f16ba734ff8878a8f42b06d5158480225cf901
thunk_2662b0:
0x2662b0: JMP 0x008f91b0
; END FUNCTION thunk_2662b0
0x2662b5: INT3 ; original byte CC, padding
0x2662b6: INT3 ; original byte CC, padding
0x2662b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662b8 [0x2662b8, 0x2662bc] | file +0xe60 | ev_1c690d03a8e9640305178c7da5cb0928be57685cc88733f8570a0a2b2d1e3e1e
thunk_2662b8:
0x2662b8: JMP 0x008fa4f0
; END FUNCTION thunk_2662b8
0x2662bd: INT3 ; original byte CC, padding
0x2662be: INT3 ; original byte CC, padding
0x2662bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2662c0 [0x2662c0, 0x2662c4] | file +0xe68 | ev_719922efa405ef9eca04e783fe6e621ff2a66e1ad1adbeffd20ce01bd1b0ed53
thunk_2662c0:
0x2662c0: JMP 0x008f8090
; END FUNCTION thunk_2662c0
0x2662c5: INT3 ; original byte CC, padding
0x2662c6: INT3 ; original byte CC, padding
0x2662c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662c8 [0x2662c8, 0x2662cc] | file +0xe70 | ev_a91a6620a8b9164f6f8704cd2c44855feabb5aee9594bdae24707f232e57d539
thunk_2662c8:
0x2662c8: JMP 0x008fbb80
; END FUNCTION thunk_2662c8
0x2662cd: INT3 ; original byte CC, padding
0x2662ce: INT3 ; original byte CC, padding
0x2662cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2662d0 [0x2662d0, 0x2662d4] | file +0xe78 | ev_a29cf940ec7347209b1f1e1e1df6ed80e1b76b49b50c65175eeb8dbb2f48f37d
thunk_2662d0:
0x2662d0: JMP 0x008f7b80
; END FUNCTION thunk_2662d0
0x2662d5: INT3 ; original byte CC, padding
0x2662d6: INT3 ; original byte CC, padding
0x2662d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662d8 [0x2662d8, 0x2662dc] | file +0xe80 | ev_1b6cc0fa753ccd5b1d7037a0c83ca39e8938cd8ce9dae47fdab2114c3a3f30a0
thunk_2662d8:
0x2662d8: JMP 0x008f7890
; END FUNCTION thunk_2662d8
0x2662dd: INT3 ; original byte CC, padding
0x2662de: INT3 ; original byte CC, padding
0x2662df: INT3 ; original byte CC, padding

; FUNCTION thunk_2662e0 [0x2662e0, 0x2662e4] | file +0xe88 | ev_3f3429b265d0817f87fde71c226edb3414a5e56742e62e83e7ba9c5eb129e695
thunk_2662e0:
0x2662e0: JMP 0x008fb8a0
; END FUNCTION thunk_2662e0
0x2662e5: INT3 ; original byte CC, padding
0x2662e6: INT3 ; original byte CC, padding
0x2662e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662e8 [0x2662e8, 0x2662ec] | file +0xe90 | ev_5fc1e1d8cefa479de1df321dd78e3e0fcec232438431dd18a61fa054ab7b3e6a
thunk_2662e8:
0x2662e8: JMP 0x008f8510
; END FUNCTION thunk_2662e8
0x2662ed: INT3 ; original byte CC, padding
0x2662ee: INT3 ; original byte CC, padding
0x2662ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2662f0 [0x2662f0, 0x2662f4] | file +0xe98 | ev_069bad0ed13080f7e9635297f56d86b4d2e1c4617a1fe0b1e4cf75f1ccc2c916
thunk_2662f0:
0x2662f0: JMP 0x008f8800
; END FUNCTION thunk_2662f0
0x2662f5: INT3 ; original byte CC, padding
0x2662f6: INT3 ; original byte CC, padding
0x2662f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2662f8 [0x2662f8, 0x2662fc] | file +0xea0 | ev_d3234eeed367638025138ce92a20673c4286efccda25b5770c0733c2eb4a83e4
thunk_2662f8:
0x2662f8: JMP 0x0049b080
; END FUNCTION thunk_2662f8
0x2662fd: INT3 ; original byte CC, padding
0x2662fe: INT3 ; original byte CC, padding
0x2662ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266300 [0x266300, 0x266304] | file +0xea8 | ev_75056b65a1d2bedd343eb1adcf1cef2a1c0fda4e054c7388d54dbd2caba2e0b9
thunk_266300:
0x266300: JMP 0x0049b090
; END FUNCTION thunk_266300
0x266305: INT3 ; original byte CC, padding
0x266306: INT3 ; original byte CC, padding
0x266307: INT3 ; original byte CC, padding

; FUNCTION thunk_266308 [0x266308, 0x26630c] | file +0xeb0 | ev_91ea1293d69e9c30d64b99d8801790056e6736a65b95aea27ec12055f57b1083
thunk_266308:
0x266308: JMP 0x0055fa50
; END FUNCTION thunk_266308
0x26630d: INT3 ; original byte CC, padding
0x26630e: INT3 ; original byte CC, padding
0x26630f: INT3 ; original byte CC, padding

; FUNCTION thunk_266310 [0x266310, 0x266314] | file +0xeb8 | ev_bf5a4d512d418182601ed746a6835acf3eb5afe4f7852dfadc904c056465c94b
thunk_266310:
0x266310: JMP 0x00c34870
; END FUNCTION thunk_266310
0x266315: INT3 ; original byte CC, padding
0x266316: INT3 ; original byte CC, padding
0x266317: INT3 ; original byte CC, padding

; FUNCTION thunk_266318 [0x266318, 0x26631c] | file +0xec0 | ev_208b12d33f8755d90604b90a10a2c17d58b0947f24fd776ac8b17d17f6313ee8
thunk_266318:
0x266318: JMP 0x007dccf0
; END FUNCTION thunk_266318
0x26631d: INT3 ; original byte CC, padding
0x26631e: INT3 ; original byte CC, padding
0x26631f: INT3 ; original byte CC, padding

; FUNCTION thunk_266320 [0x266320, 0x266324] | file +0xec8 | ev_dd4ca9088204fa7e974a87d0b009a8ebc2fd2759fb8b63a52a185ba34cf8eb29
thunk_266320:
0x266320: JMP 0x007dcd00
; END FUNCTION thunk_266320
0x266325: INT3 ; original byte CC, padding
0x266326: INT3 ; original byte CC, padding
0x266327: INT3 ; original byte CC, padding

; FUNCTION thunk_266328 [0x266328, 0x26632c] | file +0xed0 | ev_69848362de2103bd5cf50d86ad439e274738f701958fe202143e54df6f1453c8
thunk_266328:
0x266328: JMP 0x007dcd10
; END FUNCTION thunk_266328
0x26632d: INT3 ; original byte CC, padding
0x26632e: INT3 ; original byte CC, padding
0x26632f: INT3 ; original byte CC, padding

; FUNCTION thunk_266330 [0x266330, 0x266334] | file +0xed8 | ev_a9629abec3308aca2457491628273649a887f0f033e06071bf19d59e7c25aeb6
thunk_266330:
0x266330: JMP 0x007dcd20
; END FUNCTION thunk_266330
0x266335: INT3 ; original byte CC, padding
0x266336: INT3 ; original byte CC, padding
0x266337: INT3 ; original byte CC, padding

; FUNCTION thunk_266338 [0x266338, 0x26633c] | file +0xee0 | ev_2c9fc9579a5e8f0951e68ec4ee69f8bab5819987d27b92dac0e5ca9ab7aa9585
thunk_266338:
0x266338: JMP 0x007dcd30
; END FUNCTION thunk_266338
0x26633d: INT3 ; original byte CC, padding
0x26633e: INT3 ; original byte CC, padding
0x26633f: INT3 ; original byte CC, padding

; FUNCTION thunk_266340 [0x266340, 0x266344] | file +0xee8 | ev_28d00ff55ee14bddc3a396e9c941f0914c680d54e45f0e7d0a0fe6bcaf0abdfd
thunk_266340:
0x266340: JMP 0x005a6c90
; END FUNCTION thunk_266340
0x266345: INT3 ; original byte CC, padding
0x266346: INT3 ; original byte CC, padding
0x266347: INT3 ; original byte CC, padding

; FUNCTION thunk_266348 [0x266348, 0x26634c] | file +0xef0 | ev_a0a92a8617b94cc57cf896b02840e085453db69e9b9b89b42fd08675b520d877
thunk_266348:
0x266348: JMP 0x005a7300
; END FUNCTION thunk_266348
0x26634d: INT3 ; original byte CC, padding
0x26634e: INT3 ; original byte CC, padding
0x26634f: INT3 ; original byte CC, padding

; FUNCTION thunk_266350 [0x266350, 0x266354] | file +0xef8 | ev_0a57f3bca0315a687f07d3f9b7f70316f45c7906a2d0cf0fa17dc9062c3dee7c
thunk_266350:
0x266350: JMP 0x005a7610
; END FUNCTION thunk_266350
0x266355: INT3 ; original byte CC, padding
0x266356: INT3 ; original byte CC, padding
0x266357: INT3 ; original byte CC, padding

; FUNCTION thunk_266358 [0x266358, 0x26635c] | file +0xf00 | ev_af4fded32a25b1dd2506f0fa8d3a6fe561debf05b2f66c733b119322209b6aaf
thunk_266358:
0x266358: JMP 0x005a7900
; END FUNCTION thunk_266358
0x26635d: INT3 ; original byte CC, padding
0x26635e: INT3 ; original byte CC, padding
0x26635f: INT3 ; original byte CC, padding

; FUNCTION thunk_266360 [0x266360, 0x266364] | file +0xf08 | ev_9c6af11e7c8dd305336c3838898236fd05099b0aa65104622374b160736ab5b6
thunk_266360:
0x266360: JMP 0x00c9c830
; END FUNCTION thunk_266360
0x266365: INT3 ; original byte CC, padding
0x266366: INT3 ; original byte CC, padding
0x266367: INT3 ; original byte CC, padding

; FUNCTION thunk_266368 [0x266368, 0x26636c] | file +0xf10 | ev_87f009c7ed6a037fc6a2e695d59a03270e62b3b2b19528404427fdbc1ab4ee9e
thunk_266368:
0x266368: JMP 0x005a7f00
; END FUNCTION thunk_266368
0x26636d: INT3 ; original byte CC, padding
0x26636e: INT3 ; original byte CC, padding
0x26636f: INT3 ; original byte CC, padding

; FUNCTION thunk_266370 [0x266370, 0x266374] | file +0xf18 | ev_3070545cbae7a2801f820e3271e277b6b50e272261694c2bd8e9e12e4aae5233
thunk_266370:
0x266370: JMP 0x005a8070
; END FUNCTION thunk_266370
0x266375: INT3 ; original byte CC, padding
0x266376: INT3 ; original byte CC, padding
0x266377: INT3 ; original byte CC, padding

; FUNCTION thunk_266378 [0x266378, 0x26637c] | file +0xf20 | ev_ca921bb3120b8324a1de915ed3013883e4fa47822426fb4cd29d45496c86f8d4
thunk_266378:
0x266378: JMP 0x00be8480
; END FUNCTION thunk_266378
0x26637d: INT3 ; original byte CC, padding
0x26637e: INT3 ; original byte CC, padding
0x26637f: INT3 ; original byte CC, padding

; FUNCTION thunk_266380 [0x266380, 0x266384] | file +0xf28 | ev_a8a021cff5d62e81b20c04597b03ae061b60365d11847b3152df272cc8acdd6f
thunk_266380:
0x266380: JMP 0x0049b0a0
; END FUNCTION thunk_266380
0x266385: INT3 ; original byte CC, padding
0x266386: INT3 ; original byte CC, padding
0x266387: INT3 ; original byte CC, padding

; FUNCTION thunk_266388 [0x266388, 0x26638c] | file +0xf30 | ev_2997099199ab42db19428062e874712cd6df17198b3e9050eab123c8e272e909
thunk_266388:
0x266388: JMP 0x0049b0c0
; END FUNCTION thunk_266388
0x26638d: INT3 ; original byte CC, padding
0x26638e: INT3 ; original byte CC, padding
0x26638f: INT3 ; original byte CC, padding

; FUNCTION thunk_266390 [0x266390, 0x266394] | file +0xf38 | ev_b65bf17266f25edcb08139f6c59009a5ffaaa52228678f32ef1ea053d7b820ea
thunk_266390:
0x266390: JMP 0x0049b0d0
; END FUNCTION thunk_266390
0x266395: INT3 ; original byte CC, padding
0x266396: INT3 ; original byte CC, padding
0x266397: INT3 ; original byte CC, padding

; FUNCTION thunk_266398 [0x266398, 0x26639c] | file +0xf40 | ev_4bf27f9aa04b2929a3570e0657827ba247a75006d293b78e64abaff44da59012
thunk_266398:
0x266398: JMP 0x0049b0e0
; END FUNCTION thunk_266398
0x26639d: INT3 ; original byte CC, padding
0x26639e: INT3 ; original byte CC, padding
0x26639f: INT3 ; original byte CC, padding

; FUNCTION thunk_2663a0 [0x2663a0, 0x2663a4] | file +0xf48 | ev_67bb7eec5a2d6bdffe57a922696a5236cd5e44e0462ecd023f1a1790e17462b7
thunk_2663a0:
0x2663a0: JMP 0x0049b0f0
; END FUNCTION thunk_2663a0
0x2663a5: INT3 ; original byte CC, padding
0x2663a6: INT3 ; original byte CC, padding
0x2663a7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663a8 [0x2663a8, 0x2663ac] | file +0xf50 | ev_68a25a408bff8ab52323616e1566b09b1bdfef1050073934b37bcd78f8bff273
thunk_2663a8:
0x2663a8: JMP 0x00530720
; END FUNCTION thunk_2663a8
0x2663ad: INT3 ; original byte CC, padding
0x2663ae: INT3 ; original byte CC, padding
0x2663af: INT3 ; original byte CC, padding

; FUNCTION thunk_2663b0 [0x2663b0, 0x2663b4] | file +0xf58 | ev_83ae655e96cd90c09eb9dc0ce6bd23f77ef191df92f56a0d59db6f4464af597e
thunk_2663b0:
0x2663b0: JMP 0x00531670
; END FUNCTION thunk_2663b0
0x2663b5: INT3 ; original byte CC, padding
0x2663b6: INT3 ; original byte CC, padding
0x2663b7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663b8 [0x2663b8, 0x2663bc] | file +0xf60 | ev_1afdd0cffa8bf6b0d345f517b61d8ebdb86433a05beb859e3375a00d0567815c
thunk_2663b8:
0x2663b8: JMP 0x008f96f0
; END FUNCTION thunk_2663b8
0x2663bd: INT3 ; original byte CC, padding
0x2663be: INT3 ; original byte CC, padding
0x2663bf: INT3 ; original byte CC, padding

; FUNCTION thunk_2663c0 [0x2663c0, 0x2663c4] | file +0xf68 | ev_a2681b835dabbb2bbe1018977711d8e7a6b25088c1c3b1bd12d40314ae174cdd
thunk_2663c0:
0x2663c0: JMP 0x00531230
; END FUNCTION thunk_2663c0
0x2663c5: INT3 ; original byte CC, padding
0x2663c6: INT3 ; original byte CC, padding
0x2663c7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663c8 [0x2663c8, 0x2663cc] | file +0xf70 | ev_1202d226e0b0dc8c3cdef6d838d3717b0e0b43e88f3997d1a0aa7e109050b457
thunk_2663c8:
0x2663c8: JMP 0x00802df0
; END FUNCTION thunk_2663c8
0x2663cd: INT3 ; original byte CC, padding
0x2663ce: INT3 ; original byte CC, padding
0x2663cf: INT3 ; original byte CC, padding

; FUNCTION thunk_2663d0 [0x2663d0, 0x2663d4] | file +0xf78 | ev_22ff5ff4908294967385a694e23aaac6ac0ea8916a63f1fa973d669ba6fb8df0
thunk_2663d0:
0x2663d0: JMP 0x00b7f140
; END FUNCTION thunk_2663d0
0x2663d5: INT3 ; original byte CC, padding
0x2663d6: INT3 ; original byte CC, padding
0x2663d7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663d8 [0x2663d8, 0x2663dc] | file +0xf80 | ev_34a23c6ea3b7a2d859dc68cf0179d2e6e3f54574cdd2132544206387c29aa21e
thunk_2663d8:
0x2663d8: JMP 0x00ae35e0
; END FUNCTION thunk_2663d8
0x2663dd: INT3 ; original byte CC, padding
0x2663de: INT3 ; original byte CC, padding
0x2663df: INT3 ; original byte CC, padding

; FUNCTION thunk_2663e0 [0x2663e0, 0x2663e4] | file +0xf88 | ev_5cb448dfe07b9a4edd1fcf0107805a9bd7ea03b9d2747e2e94001efd67a9feb3
thunk_2663e0:
0x2663e0: JMP 0x004eee20
; END FUNCTION thunk_2663e0
0x2663e5: INT3 ; original byte CC, padding
0x2663e6: INT3 ; original byte CC, padding
0x2663e7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663e8 [0x2663e8, 0x2663ec] | file +0xf90 | ev_197bd45d13ebaabd9a99bf7238e2da2d83a7c121b47a589578b35369fae3ff3b
thunk_2663e8:
0x2663e8: JMP 0x008fab10
; END FUNCTION thunk_2663e8
0x2663ed: INT3 ; original byte CC, padding
0x2663ee: INT3 ; original byte CC, padding
0x2663ef: INT3 ; original byte CC, padding

; FUNCTION thunk_2663f0 [0x2663f0, 0x2663f4] | file +0xf98 | ev_390cff6484046a0500dd687e1027f4b3ccfb2934b44486aa755a95431a7fe4a2
thunk_2663f0:
0x2663f0: JMP 0x008fae30
; END FUNCTION thunk_2663f0
0x2663f5: INT3 ; original byte CC, padding
0x2663f6: INT3 ; original byte CC, padding
0x2663f7: INT3 ; original byte CC, padding

; FUNCTION thunk_2663f8 [0x2663f8, 0x2663fc] | file +0xfa0 | ev_3c5fc25132a91f686abd292661e26aae09b02682ce5c53c831b4f6f03827049a
thunk_2663f8:
0x2663f8: JMP 0x009c9220
; END FUNCTION thunk_2663f8
0x2663fd: INT3 ; original byte CC, padding
0x2663fe: INT3 ; original byte CC, padding
0x2663ff: INT3 ; original byte CC, padding

; FUNCTION thunk_266400 [0x266400, 0x266404] | file +0xfa8 | ev_57db6d921f8026b55dc8e147118e9d9cb10f40830fcbb9a59701387c437a9d1b
thunk_266400:
0x266400: JMP 0x009c9100
; END FUNCTION thunk_266400
0x266405: INT3 ; original byte CC, padding
0x266406: INT3 ; original byte CC, padding
0x266407: INT3 ; original byte CC, padding

; FUNCTION thunk_266408 [0x266408, 0x26640c] | file +0xfb0 | ev_d0a17fb65beb653cf741b97d5f412cf3674a53cfab34f587c8e6b0c6abb9c4c8
thunk_266408:
0x266408: JMP 0x00642310
; END FUNCTION thunk_266408
0x26640d: INT3 ; original byte CC, padding
0x26640e: INT3 ; original byte CC, padding
0x26640f: INT3 ; original byte CC, padding

; FUNCTION thunk_266410 [0x266410, 0x266414] | file +0xfb8 | ev_9fc7135a6d4d0bcf4f8046fe5a5ef91b770aeba84442b46d8339d885842b2c6b
thunk_266410:
0x266410: JMP 0x00642820
; END FUNCTION thunk_266410
0x266415: INT3 ; original byte CC, padding
0x266416: INT3 ; original byte CC, padding
0x266417: INT3 ; original byte CC, padding

; FUNCTION thunk_266418 [0x266418, 0x26641c] | file +0xfc0 | ev_2b57d9748536f30d1ad30c74b67122f3d29f2da19d2d2c776b1e549e6b375495
thunk_266418:
0x266418: JMP 0x006436e0
; END FUNCTION thunk_266418
0x26641d: INT3 ; original byte CC, padding
0x26641e: INT3 ; original byte CC, padding
0x26641f: INT3 ; original byte CC, padding

; FUNCTION thunk_266420 [0x266420, 0x266424] | file +0xfc8 | ev_5731453af60ee21737f0a19f8df3841abc1185e5f887c5a2651f9da56f35dd45
thunk_266420:
0x266420: JMP 0x006438d0
; END FUNCTION thunk_266420
0x266425: INT3 ; original byte CC, padding
0x266426: INT3 ; original byte CC, padding
0x266427: INT3 ; original byte CC, padding

; FUNCTION thunk_266428 [0x266428, 0x26642c] | file +0xfd0 | ev_e36675918b3af93a0ba702a21607e01ed6c6402aec3ced61dede9f937ad73f86
thunk_266428:
0x266428: JMP 0x00643c60
; END FUNCTION thunk_266428
0x26642d: INT3 ; original byte CC, padding
0x26642e: INT3 ; original byte CC, padding
0x26642f: INT3 ; original byte CC, padding

; FUNCTION thunk_266430 [0x266430, 0x266434] | file +0xfd8 | ev_6a04f2314e3bd552a5cfa9f286543184288bcceb388acd83f0f89386e77844c5
thunk_266430:
0x266430: JMP 0x009f8290
; END FUNCTION thunk_266430
0x266435: INT3 ; original byte CC, padding
0x266436: INT3 ; original byte CC, padding
0x266437: INT3 ; original byte CC, padding

; FUNCTION thunk_266438 [0x266438, 0x26643c] | file +0xfe0 | ev_f0f29b9b58193821f977a76d6075531fc649104ed3ff9888e799ce9604452c14
thunk_266438:
0x266438: JMP 0x009fbb70
; END FUNCTION thunk_266438
0x26643d: INT3 ; original byte CC, padding
0x26643e: INT3 ; original byte CC, padding
0x26643f: INT3 ; original byte CC, padding

; FUNCTION thunk_266440 [0x266440, 0x266444] | file +0xfe8 | ev_127a5173d91f5372221bc3d6a59f5ee274647c47100ccb53d2c9971e8f04095e
thunk_266440:
0x266440: JMP 0x00a45280
; END FUNCTION thunk_266440
0x266445: INT3 ; original byte CC, padding
0x266446: INT3 ; original byte CC, padding
0x266447: INT3 ; original byte CC, padding

; FUNCTION thunk_266448 [0x266448, 0x26644c] | file +0xff0 | ev_9f62465d050ae1689681c25f188166de765fef7a456d5df8e48326754e89d912
thunk_266448:
0x266448: JMP 0x00c87ca0
; END FUNCTION thunk_266448
0x26644d: INT3 ; original byte CC, padding
0x26644e: INT3 ; original byte CC, padding
0x26644f: INT3 ; original byte CC, padding

; FUNCTION thunk_266450 [0x266450, 0x266454] | file +0xff8 | ev_c67e3645f3916bc52308fafa2c022bb81b0d570232e6162a3b5bf0e618b49e6f
thunk_266450:
0x266450: JMP 0x009ff000
; END FUNCTION thunk_266450
0x266455: INT3 ; original byte CC, padding
0x266456: INT3 ; original byte CC, padding
0x266457: INT3 ; original byte CC, padding



; ===== ORIGINAL ENTRY: <EXTERNAL>::thunk_265458 RVA 0x265458 | Evidence ev_fcf2d62420d798896612e67b478001184db0243e9215b3060203bdfedd93be64 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.raw.dossier.json | Source /tmp/rea-646-676-5b61b6f2/raw_union.bin SHA256 352988f408bc976411feddb3ef6cd2b18459d2aa3fa6dfd7f2e4a7fe416ce915 =====
<EXTERNAL>::thunk_265458:
0x265458: JMP 0x002d36f0


; ===== TARGET: handler_675_body RVA 0x2d36f0 | Evidence ev_99ab7b5e3d19dbb381b8d59021ed144f2ec64fd216264a47139b627dd8450a58 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
handler_675_body:
0x2d36f0: PUSH RBP
0x2d36f1: MOV RBP, RSP
0x2d36f4: MOV dword ptr [0x01a962e0], 0x1
0x2d36fe: MOV qword ptr [0x02d616c8], -0x1
0x2d3709: MOV qword ptr [0x02d60008], 0x0
0x2d3714: XOR EAX, EAX
0x2d3716: POP RBP
0x2d3717: RET


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d3720 RVA 0x2d3720 | Evidence ev_29152ee1b4f68973a234dd78b6f50de0e6756418adc3b0939f466b55b82bef7f | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d3720:
0x2d3720: PUSH RBP
0x2d3721: MOV RBP, RSP
0x2d3724: MOV RAX, qword ptr [0x02d60008]
0x2d372b: POP RBP
0x2d372c: RET


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d3730 RVA 0x2d3730 | Evidence ev_d30dc3ba3c699e1a924aba4ce6ee58898b85de8b375c18a3933441507ebc2284 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d3730:
0x2d3730: PUSH RBP
0x2d3731: MOV RBP, RSP
0x2d3734: PUSH R15
0x2d3736: PUSH R14
0x2d3738: PUSH R13
0x2d373a: PUSH R12
0x2d373c: PUSH RBX
0x2d373d: SUB RSP, 0x18
0x2d3741: LEA R13, [0x391c310]
0x2d3748: MOV R15, RSI
0x2d374b: MOV R14, RDI
0x2d374e: MOV RAX, qword ptr [R13]
0x2d3752: MOV qword ptr [RBP + -0x30], RAX
0x2d3756: CALL 0x00609940
0x2d375b: TEST EAX, EAX
0x2d375d: JZ 0x002d37f1
0x2d3763: MOV RBX, qword ptr [R15 + 0x8]
0x2d3767: MOV EAX, 0x16
0x2d376c: TEST RBX, RBX
0x2d376f: JZ 0x002d37f6
0x2d3775: MOV RAX, qword ptr [R14 + 0x8]
0x2d3779: MOV R15, qword ptr [R15]
0x2d377c: XOR ESI, ESI
0x2d377e: XOR EDX, EDX
0x2d3780: XOR ECX, ECX
0x2d3782: MOV RAX, qword ptr [RAX + 0x200]
0x2d3789: MOV R14, qword ptr [RAX + 0x1d8]
0x2d3790: LEA R12, [R14 + 0x18]
0x2d3794: MOV RDI, R12
0x2d3797: CALL 0x004c6a00
0x2d379c: LEA RDX, [RBP + -0x38]
0x2d37a0: MOV RDI, R14
0x2d37a3: MOV RSI, R15
0x2d37a6: CALL 0x008ed710
0x2d37ab: MOV RDI, R12
0x2d37ae: MOV R14, RAX
0x2d37b1: XOR ESI, ESI
0x2d37b3: XOR EDX, EDX
0x2d37b5: XOR ECX, ECX
0x2d37b7: CALL 0x004c6fa0
0x2d37bc: MOV EAX, 0x16
0x2d37c1: TEST R14B, 0x1
0x2d37c5: JZ 0x002d37f6
0x2d37c7: MOV RDI, qword ptr GS:[0x0]
0x2d37d0: LEA RSI, [0x134f297]
0x2d37d7: XOR EDX, EDX
0x2d37d9: CALL 0x00c1a3e0
0x2d37de: LEA RDI, [RBP + -0x38]
0x2d37e2: MOV EDX, 0x8
0x2d37e7: MOV RSI, RBX
0x2d37ea: CALL 0x002591d0
0x2d37ef: JMP 0x002d37f6
0x2d37f1: MOV EAX, 0x1
0x2d37f6: MOV RCX, qword ptr [R13]
0x2d37fa: CMP RCX, qword ptr [RBP + -0x30]
0x2d37fe: JNZ 0x002d380f
0x2d3800: ADD RSP, 0x18
0x2d3804: POP RBX
0x2d3805: POP R12
0x2d3807: POP R13
0x2d3809: POP R14
0x2d380b: POP R15
0x2d380d: POP RBP
0x2d380e: RET
0x2d380f: CALL 0x006fd6b0
0x2d3814: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d3829 RVA 0x2d3829 | Evidence ev_c79896e6207afc8e36a0b8494098e4254597302d7a410ac7bf78e4b546a665ae | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d3829:
0x2d3829: PUSH RBP
0x2d382a: MOV RBP, RSP
0x2d382d: PUSH RBX
0x2d382e: PUSH RAX
0x2d382f: MOV RSI, 0xc80000000
0x2d3839: MOV RBX, RDI
0x2d383c: XOR ECX, ECX
0x2d383e: LEA RDX, [RSI + 0x48000]
0x2d3845: CALL 0x002ce900
0x2d384a: AND byte ptr [RBX + 0x244], 0xbf
0x2d3851: ADD RSP, 0x8
0x2d3855: POP RBX
0x2d3856: POP RBP
0x2d3857: RET


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): FUN_002d3860 RVA 0x2d3860 | Evidence ev_8b403020561dc38223ff7ed8dd29905c9b3b7f4c7e26b305a425cc36c6f58074 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
FUN_002d3860:
0x2d3860: MOV RAX, qword ptr [RDI + 0x200]
0x2d3867: MOV RAX, qword ptr [RAX + 0x1d8]
0x2d386e: MOV EAX, dword ptr [RAX + 0x27c]
0x2d3874: TEST EAX, EAX
0x2d3876: JZ 0x002d3879
0x2d3878: RET


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d3879 RVA 0x2d3879 | Evidence ev_109d02d211647adc4ab082d44a0b996720d3113c9f39f59a43d64048ae994944 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d3879:
0x2d3879: PUSH RBP
0x2d387a: MOV RBP, RSP
0x2d387d: PUSH RBX
0x2d387e: PUSH RAX
0x2d387f: MOV RBX, RDI
0x2d3882: CALL 0x007f1950
0x2d3887: MOVSXD RSI, dword ptr [RBX + 0xbc]
0x2d388e: LEA RDI, [0x2d3879]
0x2d3895: CALL 0x007f18a0
0x2d389a: MOV EDX, dword ptr [RBX + 0xbc]
0x2d38a0: LEA RSI, [0x127f9f2]
0x2d38a7: MOV EDI, 0x83
0x2d38ac: XOR EAX, EAX
0x2d38ae: CALL 0x00c9aa10
0x2d38b3: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d38c0 RVA 0x2d38c0 | Evidence ev_5542467bb884213831948eb488e99d3f7233a87c0d7ed4a7516668945758d94e | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d38c0:
0x2d38c0: PUSH RBP
0x2d38c1: MOV RBP, RSP
0x2d38c4: POP RBP
0x2d38c5: JMP 0x002d3860


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d38e3 RVA 0x2d38e3 | Evidence ev_1209c777df5cded43e983d4afb628a28dfe779644e7d741eb30fac03b4900bc5 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d38e3:
0x2d38e3: PUSH RBP
0x2d38e4: MOV RBP, RSP
0x2d38e7: PUSH RBX
0x2d38e8: PUSH RAX
0x2d38e9: MOV RBX, RDI
0x2d38ec: CALL 0x007f1950
0x2d38f1: MOVSXD RSI, dword ptr [RBX + 0xbc]
0x2d38f8: LEA RDI, [0x2d38e3]
0x2d38ff: CALL 0x007f18a0
0x2d3904: MOV EDX, dword ptr [RBX + 0xbc]
0x2d390a: LEA RSI, [0x138de87]
0x2d3911: MOV EDI, 0x87
0x2d3916: XOR EAX, EAX
0x2d3918: CALL 0x00c9aa10
0x2d391d: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d3920 RVA 0x2d3920 | Evidence ev_e14b76d3d6aefa86c52eae21b8309d2546008cb0ba7c571dc0cef6a8d3328b8e | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d3920:
0x2d3920: PUSH RBP
0x2d3921: MOV RBP, RSP
0x2d3924: PUSH R15
0x2d3926: PUSH R14
0x2d3928: PUSH R13
0x2d392a: PUSH R12
0x2d392c: PUSH RBX
0x2d392d: SUB RSP, 0xa8
0x2d3934: LEA R15, [0x391c310]
0x2d393b: MOV R14D, dword ptr [RBP + 0x18]
0x2d393f: MOV R13, qword ptr [RBP + 0x10]
0x2d3943: MOV R12D, 0x16
0x2d3949: MOV RAX, qword ptr [R15]
0x2d394c: MOV qword ptr [RBP + -0x30], RAX
0x2d3950: MOV RBX, qword ptr [RSI + 0x200]
0x2d3957: MOV qword ptr [RDI], RSI
0x2d395a: MOV qword ptr [RDI + 0x8], RDX
0x2d395e: MOV qword ptr [RDI + 0x10], RCX
0x2d3962: MOV qword ptr [RDI + 0x18], R9
0x2d3966: MOV qword ptr [RDI + 0x20], R13
0x2d396a: MOV qword ptr [RDI + 0x28], 0x0
0x2d3972: MOV qword ptr [RDI + 0x30], 0x0
0x2d397a: MOV dword ptr [RDI + 0x38], 0x0
0x2d3981: CMP R14D, 0x3
0x2d3985: JA 0x002d3e3e
0x2d398b: MOV RAX, RDX
0x2d398e: SHR RAX, 0x2b
0x2d3992: JZ 0x002d39b9
0x2d3994: SUB RSP, 0x8
0x2d3998: MOVZX R8D, R8B
0x2d399c: PUSH R13
0x2d399e: CALL 0x002d3f60
0x2d39a3: ADD RSP, 0x10
0x2d39a7: MOV RCX, qword ptr [R15]
0x2d39aa: CMP RCX, qword ptr [RBP + -0x30]
0x2d39ae: JZ 0x002d3e4e
0x2d39b4: JMP 0x002d3f1b
0x2d39b9: LEA RAX, [RCX + RDX*0x1]
0x2d39bd: CMP RAX, RDX
0x2d39c0: JBE 0x002d3e3e
0x2d39c6: CMP RDX, qword ptr [RBX + 0x20]
0x2d39ca: JC 0x002d3e3e
0x2d39d0: CMP qword ptr [RBX + 0x28], RAX
0x2d39d4: JC 0x002d3e3e
0x2d39da: MOV qword ptr [RBP + -0x68], R9
0x2d39de: MOV qword ptr [RBP + -0x48], RDI
0x2d39e2: MOV qword ptr [RBP + -0x90], RCX
0x2d39e9: MOVZX ECX, R8B
0x2d39ed: MOV RDI, RBX
0x2d39f0: MOV RSI, RDX
0x2d39f3: MOV qword ptr [RBP + -0xb8], RCX
0x2d39fa: LEA ECX, [RCX*0x4]
0x2d3a01: MOV qword ptr [RBP + -0x40], RDX
0x2d3a05: MOV RDX, RAX
0x2d3a08: MOV dword ptr [RBP + -0x54], ECX
0x2d3a0b: MOV qword ptr [RBP + -0x70], RAX
0x2d3a0f: CALL 0x002cedc0
0x2d3a14: TEST EAX, EAX
0x2d3a16: JZ 0x002d3a46
0x2d3a18: CMP EAX, 0x1
0x2d3a1b: JZ 0x002d3e3e
0x2d3a21: MOV RCX, qword ptr [R15]
0x2d3a24: CMP RCX, qword ptr [RBP + -0x30]
0x2d3a28: JNZ 0x002d3f1b
0x2d3a2e: MOV EDI, EAX
0x2d3a30: ADD RSP, 0xa8
0x2d3a37: POP RBX
0x2d3a38: POP R12
0x2d3a3a: POP R13
0x2d3a3c: POP R14
0x2d3a3e: POP R15
0x2d3a40: POP RBP
0x2d3a41: JMP 0x00ab8cb0
0x2d3a46: CMP R14D, 0x2
0x2d3a4a: MOV R14D, dword ptr [RBP + -0x54]
0x2d3a4e: JC 0x002d3a71
0x2d3a50: MOV RSI, qword ptr [RBP + -0x40]
0x2d3a54: MOV RDX, qword ptr [RBP + -0x90]
0x2d3a5b: MOV RDI, RBX
0x2d3a5e: CALL 0x002d41d0
0x2d3a63: MOV R12D, 0x3f
0x2d3a69: TEST EAX, EAX
0x2d3a6b: JNZ 0x002d3e2b
0x2d3a71: MOV RDI, qword ptr [RBP + -0x90]
0x2d3a78: CALL 0x005033b0
0x2d3a7d: MOV RCX, qword ptr [RBP + -0x48]
0x2d3a81: MOV qword ptr [RCX + 0x28], RAX
0x2d3a85: TEST RAX, RAX
0x2d3a88: JZ 0x002d3df9
0x2d3a8e: MOV RDI, RBX
0x2d3a91: XOR R12D, R12D
0x2d3a94: XOR ESI, ESI
0x2d3a96: XOR EDX, EDX
0x2d3a98: CALL 0x002c6480
0x2d3a9d: MOV RSI, qword ptr [RBP + -0x40]
0x2d3aa1: LEA RDX, [RBP + -0x38]
0x2d3aa5: MOV RDI, RBX
0x2d3aa8: CALL 0x002c6c40
0x2d3aad: TEST EAX, EAX
0x2d3aaf: JZ 0x002d3e01
0x2d3ab5: MOV RCX, qword ptr [RBP + -0x38]
0x2d3ab9: CMP RCX, RBX
0x2d3abc: JZ 0x002d3ae8
0x2d3abe: MOV RSI, qword ptr [RBP + -0x40]
0x2d3ac2: MOV RDX, qword ptr [RBP + -0x70]
0x2d3ac6: XOR R12D, R12D
0x2d3ac9: CMP qword ptr [RCX + 0x20], RDX
0x2d3acd: JNC 0x002d3ae8
0x2d3acf: CMP R12D, 0xfff
0x2d3ad6: JZ 0x002d3e0d
0x2d3adc: MOV RCX, qword ptr [RCX + 0x8]
0x2d3ae0: INC R12D
0x2d3ae3: CMP RCX, RBX
0x2d3ae6: JNZ 0x002d3ac9
0x2d3ae8: LEA RSI, [0x2bfc080]
0x2d3aef: MOV EDI, R12D
0x2d3af2: MOV EDX, 0x2
0x2d3af7: MOV qword ptr [RBP + -0x38], RCX
0x2d3afb: SHL RDI, 0x5
0x2d3aff: CALL 0x00c08b50
0x2d3b04: MOV RCX, qword ptr [RBP + -0x48]
0x2d3b08: LEA RDX, [RBP + -0x38]
0x2d3b0c: MOV RDI, RBX
0x2d3b0f: MOV qword ptr [RCX + 0x30], RAX
0x2d3b13: MOV dword ptr [RCX + 0x38], R12D
0x2d3b17: MOV RAX, qword ptr [RCX + 0x28]
0x2d3b1b: MOV qword ptr [RBP + -0x88], RAX
0x2d3b22: MOV RSI, qword ptr [RBP + -0x40]
0x2d3b26: CALL 0x002c6c40
0x2d3b2b: MOV RSI, qword ptr [RBP + -0x38]
0x2d3b2f: XOR R12D, R12D
0x2d3b32: CMP RSI, RBX
0x2d3b35: JZ 0x002d3e1f
0x2d3b3b: MOV RDX, qword ptr [RBP + -0x70]
0x2d3b3f: CMP qword ptr [RSI + 0x20], RDX
0x2d3b43: JNC 0x002d3e1f
0x2d3b49: TEST byte ptr [RSI + 0x60], 0x2
0x2d3b4d: JNZ 0x002d3e60
0x2d3b53: LEA RAX, [RBX + 0x1a8]
0x2d3b5a: LEA RCX, [RBX + 0x170]
0x2d3b61: LEA R9, [RSI + 0x20]
0x2d3b65: MOV qword ptr [RBP + -0xc8], RAX
0x2d3b6c: MOV qword ptr [RBP + -0xc0], RCX
0x2d3b73: MOV qword ptr [RBP + -0x80], 0x0
0x2d3b7b: MOV RCX, qword ptr [RBP + -0x40]
0x2d3b7f: MOV qword ptr [RBP + -0x78], RCX
0x2d3b83: MOV qword ptr [RBP + -0x50], R13
0x2d3b87: MOV RAX, qword ptr [RBP + -0x48]
0x2d3b8b: MOV RDI, qword ptr [RBP + -0x68]
0x2d3b8f: MOV R8, qword ptr [RSI + 0x50]
0x2d3b93: MOV qword ptr [RBP + -0xb0], RSI
0x2d3b9a: MOV qword ptr [RBP + -0x60], R9
0x2d3b9e: MOV qword ptr [RBP + -0xd0], R8
0x2d3ba5: TEST R8, R8
0x2d3ba8: JZ 0x002d3dea
0x2d3bae: MOVSXD R14, dword ptr [RBP + -0x80]
0x2d3bb2: MOV RDI, qword ptr [RAX + 0x30]
0x2d3bb6: MOV ESI, 0x20
0x2d3bbb: SHL R14, 0x5
0x2d3bbf: ADD RDI, R14
0x2d3bc2: CALL 0x00258ff0
0x2d3bc7: MOV RSI, qword ptr [RBP + -0xb0]
0x2d3bce: MOV RDX, qword ptr [RBP + -0x60]
0x2d3bd2: MOV RCX, qword ptr [RBP + -0x48]
0x2d3bd6: MOV qword ptr [RBP + -0xa8], R14
0x2d3bdd: MOV RDI, RBX
0x2d3be0: MOV RAX, qword ptr [RSI + 0x28]
0x2d3be4: SUB RAX, qword ptr [RDX]
0x2d3be7: MOV RCX, qword ptr [RCX + 0x30]
0x2d3beb: MOV qword ptr [RCX + R14*0x1 + 0x10], RAX
0x2d3bf0: MOV R14, qword ptr [RBP + -0x40]
0x2d3bf4: MOV RAX, qword ptr [RDX]
0x2d3bf7: MOV RCX, qword ptr [RSI + 0x28]
0x2d3bfb: MOV RDX, qword ptr [RBP + -0x70]
0x2d3bff: CMP RAX, R14
0x2d3c02: CMOVA R14, RAX
0x2d3c06: CMP RCX, RDX
0x2d3c09: CMOVNC RCX, RDX
0x2d3c0d: MOV RDX, R14
0x2d3c10: SUB RDX, RAX
0x2d3c13: ADD RDX, qword ptr [RSI + 0x58]
0x2d3c17: SUB RCX, R14
0x2d3c1a: XOR ESI, ESI
0x2d3c1c: MOV qword ptr [RBP + -0xa0], RDX
0x2d3c23: MOV qword ptr [RBP + -0x78], R14
0x2d3c27: MOV R14D, dword ptr [RBX + 0x1c0]
0x2d3c2e: XOR EDX, EDX
0x2d3c30: MOV qword ptr [RBP + -0x60], RCX
0x2d3c34: CALL 0x002c64f0
0x2d3c39: MOV RDI, qword ptr [RBP + -0xd0]
0x2d3c40: MOV dword ptr [RBP + -0x94], R14D
0x2d3c47: MOVZX EAX, byte ptr [RDI + 0x9d]
0x2d3c4e: CMP EAX, 0xb
0x2d3c51: JZ 0x002d3caa
0x2d3c53: CMP EAX, 0x3
0x2d3c56: JNZ 0x002d3c61
0x2d3c58: TEST byte ptr [RDI + 0xa2], 0x1
0x2d3c5f: JNZ 0x002d3cb2
0x2d3c61: MOV RAX, qword ptr [RBP + -0x48]
0x2d3c65: MOV R10, qword ptr [RBP + -0xa8]
0x2d3c6c: MOV RSI, qword ptr [RBP + -0xa0]
0x2d3c73: MOV RDX, qword ptr [RBP + -0x60]
0x2d3c77: MOV R8, qword ptr [RBP + -0x68]
0x2d3c7b: MOV R9, qword ptr [RBP + -0x50]
0x2d3c7f: MOV RCX, qword ptr [RBP + -0xb8]
0x2d3c86: ADD R10, qword ptr [RAX + 0x30]
0x2d3c8a: PUSH R10
0x2d3c8c: PUSH qword ptr [RBP + -0x88]
0x2d3c92: CALL 0x002d4630
0x2d3c97: ADD RSP, 0x10
0x2d3c9b: MOV R14D, EAX
0x2d3c9e: CMP EAX, 0x1
0x2d3ca1: MOV RAX, qword ptr [RBP + -0x80]
0x2d3ca5: ADC EAX, 0x0
0x2d3ca8: JMP 0x002d3cf5
0x2d3caa: MOV R14D, 0x2d
0x2d3cb0: JMP 0x002d3cf9
0x2d3cb2: MOV RAX, qword ptr [RBP + -0x48]
0x2d3cb6: MOV R10, qword ptr [RBP + -0xa8]
0x2d3cbd: MOV RSI, qword ptr [RBP + -0xa0]
0x2d3cc4: MOV RDX, qword ptr [RBP + -0x60]
0x2d3cc8: MOV R8, qword ptr [RBP + -0x68]
0x2d3ccc: MOV R9, qword ptr [RBP + -0x50]
0x2d3cd0: MOV RCX, qword ptr [RBP + -0xb8]
0x2d3cd7: ADD R10, qword ptr [RAX + 0x30]
0x2d3cdb: PUSH R10
0x2d3cdd: PUSH qword ptr [RBP + -0x88]
0x2d3ce3: CALL 0x002d43e0
0x2d3ce8: ADD RSP, 0x10
0x2d3cec: MOV RAX, qword ptr [RBP + -0x80]
0x2d3cf0: XOR R14D, R14D
0x2d3cf3: INC EAX
0x2d3cf5: MOV qword ptr [RBP + -0x80], RAX
0x2d3cf9: MOVZX EAX, byte ptr [RBX + 0x244]
0x2d3d00: TEST AL, 0x10
0x2d3d02: JNZ 0x002d3d2d
0x2d3d04: TEST AL, 0x8
0x2d3d06: JZ 0x002d3d19
0x2d3d08: MOV RAX, qword ptr GS:[0x0]
0x2d3d11: ADD.LOCK dword ptr [RAX + 0x5a8], 0x1
0x2d3d19: MOV RDI, qword ptr [RBP + -0xc0]
0x2d3d20: XOR ESI, ESI
0x2d3d22: XOR EDX, EDX
0x2d3d24: XOR ECX, ECX
0x2d3d26: CALL 0x00c4bb20
0x2d3d2b: JMP 0x002d3d3f
0x2d3d2d: MOV RDI, qword ptr [RBP + -0xc8]
0x2d3d34: XOR ESI, ESI
0x2d3d36: XOR EDX, EDX
0x2d3d38: XOR ECX, ECX
0x2d3d3a: CALL 0x004c6a00
0x2d3d3f: INC dword ptr [RBX + 0x1c0]
0x2d3d45: MOV R8D, R14D
0x2d3d48: ADD.LOCK dword ptr [RBX + 0x1c4], 0x1
0x2d3d50: MOV EAX, dword ptr [RBP + -0x94]
0x2d3d56: MOV RDI, qword ptr [RBP + -0x68]
0x2d3d5a: MOV RDX, qword ptr [RBP + -0x70]
0x2d3d5e: MOV RSI, qword ptr [RBP + -0xb0]
0x2d3d65: INC EAX
0x2d3d67: CMP dword ptr [RBX + 0x1c0], EAX
0x2d3d6d: MOV RAX, qword ptr [RBP + -0x48]
0x2d3d71: JZ 0x002d3d9e
0x2d3d73: MOV RSI, qword ptr [RBP + -0x78]
0x2d3d77: MOV RDI, RBX
0x2d3d7a: LEA RDX, [RBP + -0x38]
0x2d3d7e: CALL 0x002c6c40
0x2d3d83: TEST EAX, EAX
0x2d3d85: JZ 0x002d3f22
0x2d3d8b: MOV RSI, qword ptr [RBP + -0x38]
0x2d3d8f: MOV RAX, qword ptr [RBP + -0x48]
0x2d3d93: MOV RDI, qword ptr [RBP + -0x68]
0x2d3d97: MOV RDX, qword ptr [RBP + -0x70]
0x2d3d9b: MOV R8D, R14D
0x2d3d9e: MOV R9, qword ptr [RBP + -0x60]
0x2d3da2: MOV RSI, qword ptr [RSI + 0x8]
0x2d3da6: ADD qword ptr [RBP + -0x50], R9
0x2d3daa: MOV qword ptr [RBP + -0x38], RSI
0x2d3dae: TEST R8D, R8D
0x2d3db1: JNZ 0x002d3e81
0x2d3db7: MOV R14D, dword ptr [RBP + -0x54]
0x2d3dbb: XOR R8D, R8D
0x2d3dbe: CMP RSI, RBX
0x2d3dc1: JZ 0x002d3e7b
0x2d3dc7: CMP qword ptr [RSI + 0x20], RDX
0x2d3dcb: JNC 0x002d3e7b
0x2d3dd1: MOV R8, qword ptr [RBP + -0x60]
0x2d3dd5: LEA R9, [RSI + 0x20]
0x2d3dd9: ADD qword ptr [RBP + -0x88], R8
0x2d3de0: TEST byte ptr [RSI + 0x60], 0x2
0x2d3de4: JZ 0x002d3b8f
0x2d3dea: MOV RDX, qword ptr [RBP + -0x50]
0x2d3dee: MOV R8D, 0xd
0x2d3df4: JMP 0x002d3e89
0x2d3df9: MOV R12D, 0x23
0x2d3dff: JMP 0x002d3e2b
0x2d3e01: MOV RSI, qword ptr [RBP + -0x40]
0x2d3e05: MOV R12D, 0x16
0x2d3e0b: JMP 0x002d3e13
0x2d3e0d: MOV R12D, 0x54
0x2d3e13: LEA RDX, [RBP + -0x38]
0x2d3e17: MOV RDI, RBX
0x2d3e1a: CALL 0x002c6c40
0x2d3e1f: MOV RDI, RBX
0x2d3e22: XOR ESI, ESI
0x2d3e24: XOR EDX, EDX
0x2d3e26: CALL 0x002c64f0
0x2d3e2b: MOV RSI, qword ptr [RBP + -0x40]
0x2d3e2f: MOV RDX, qword ptr [RBP + -0x70]
0x2d3e33: MOV RDI, RBX
0x2d3e36: MOV ECX, R14D
0x2d3e39: CALL 0x002ce900
0x2d3e3e: MOV RAX, qword ptr [R15]
0x2d3e41: CMP RAX, qword ptr [RBP + -0x30]
0x2d3e45: JNZ 0x002d3f1b
0x2d3e4b: MOV EAX, R12D
0x2d3e4e: ADD RSP, 0xa8
0x2d3e55: POP RBX
0x2d3e56: POP R12
0x2d3e58: POP R13
0x2d3e5a: POP R14
0x2d3e5c: POP R15
0x2d3e5e: POP RBP
0x2d3e5f: RET
0x2d3e60: MOV RAX, qword ptr [RBP + -0x40]
0x2d3e64: MOV RDX, R13
0x2d3e67: MOV R8D, 0xd
0x2d3e6d: MOV qword ptr [RBP + -0x78], RAX
0x2d3e71: MOV RAX, qword ptr [RBP + -0x48]
0x2d3e75: MOV RDI, qword ptr [RBP + -0x68]
0x2d3e79: JMP 0x002d3e89
0x2d3e7b: MOV RDX, qword ptr [RBP + -0x50]
0x2d3e7f: JMP 0x002d3e89
0x2d3e81: MOV RDX, qword ptr [RBP + -0x50]
0x2d3e85: MOV R14D, dword ptr [RBP + -0x54]
0x2d3e89: SUB RDX, R13
0x2d3e8c: JBE 0x002d3f09
0x2d3e8e: TEST R8D, R8D
0x2d3e91: JZ 0x002d3f11
0x2d3e93: MOV RSI, R13
0x2d3e96: MOV ECX, 0x1
0x2d3e9b: MOV R12, RAX
0x2d3e9e: MOV R13D, R8D
0x2d3ea1: CALL 0x009f03a0
0x2d3ea6: MOV RDI, R12
0x2d3ea9: CALL 0x002d48b0
0x2d3eae: MOV RDI, qword ptr [R12 + 0x30]
0x2d3eb3: LEA RSI, [0x2bfc080]
0x2d3eba: CALL 0x00c08df0
0x2d3ebf: MOV RSI, qword ptr [RBP + -0x78]
0x2d3ec3: SUB RSI, qword ptr [RBP + -0x40]
0x2d3ec7: MOV qword ptr [R12 + 0x30], 0x0
0x2d3ed0: MOV dword ptr [R12 + 0x38], 0x0
0x2d3ed9: MOV RDI, qword ptr [R12 + 0x28]
0x2d3ede: SHR RSI, 0xe
0x2d3ee2: CALL 0x008dedb0
0x2d3ee7: MOV RDI, qword ptr [R12 + 0x28]
0x2d3eec: MOV RSI, qword ptr [RBP + -0x90]
0x2d3ef3: CALL 0x00503410
0x2d3ef8: MOV qword ptr [R12 + 0x28], 0x0
0x2d3f01: MOV R12D, R13D
0x2d3f04: JMP 0x002d3e1f
0x2d3f09: MOV R12D, R8D
0x2d3f0c: JMP 0x002d3e1f
0x2d3f11: CALL 0x009f03b0
0x2d3f16: JMP 0x002d3e1f
0x2d3f1b: CALL 0x006fd6b0
0x2d3f20: UD2
0x2d3f22: CALL 0x007f1950
0x2d3f27: MOV RBX, qword ptr [RBP + -0x78]
0x2d3f2b: LEA RDI, [0x2d3f22]
0x2d3f32: MOV RSI, RBX
0x2d3f35: CALL 0x007f18a0
0x2d3f3a: LEA RSI, [0x1364b07]
0x2d3f41: MOV EDI, 0x9f
0x2d3f46: MOV RDX, RBX
0x2d3f49: XOR EAX, EAX
0x2d3f4b: CALL 0x00c9aa10
0x2d3f50: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d3f60 RVA 0x2d3f60 | Evidence ev_7bf7c8aed3046da19d09e0047bd29a79136a91953f6489dd140cb89cfb51885e | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d3f60:
0x2d3f60: PUSH RBP
0x2d3f61: MOV RBP, RSP
0x2d3f64: PUSH R15
0x2d3f66: PUSH R14
0x2d3f68: PUSH R13
0x2d3f6a: PUSH R12
0x2d3f6c: PUSH RBX
0x2d3f6d: SUB RSP, 0x58
0x2d3f71: LEA RAX, [0x391c310]
0x2d3f78: MOV qword ptr [RBP + -0x50], R9
0x2d3f7c: MOV R12, RDX
0x2d3f7f: MOV R15, RDI
0x2d3f82: MOV EDX, 0x2
0x2d3f87: MOV EBX, R8D
0x2d3f8a: MOV R14, RCX
0x2d3f8d: MOV RAX, qword ptr [RAX]
0x2d3f90: MOV qword ptr [RBP + -0x30], RAX
0x2d3f94: MOV R13D, dword ptr [RSI + 0xbc]
0x2d3f9b: LEA RSI, [0x2bfc080]
0x2d3fa2: MOV dword ptr [RDI + 0x38], 0x1
0x2d3fa9: MOV EDI, 0x20
0x2d3fae: CALL 0x00c08b50
0x2d3fb3: MOV RDI, R14
0x2d3fb6: MOV qword ptr [R15 + 0x30], RAX
0x2d3fba: MOV dword ptr [RAX], R13D
0x2d3fbd: MOV qword ptr [RAX + 0x8], R12
0x2d3fc1: MOV dword ptr [RAX + 0x18], 0x3
0x2d3fc8: MOV dword ptr [RBP + -0x58], R13D
0x2d3fcc: MOV qword ptr [RAX + 0x10], R14
0x2d3fd0: MOV qword ptr [RBP + -0x48], R14
0x2d3fd4: CALL 0x005033b0
0x2d3fd9: MOV qword ptr [R15 + 0x28], RAX
0x2d3fdd: MOV qword ptr [RBP + -0x68], RAX
0x2d3fe1: TEST RAX, RAX
0x2d3fe4: JZ 0x002d401f
0x2d3fe6: MOV qword ptr [RBP + -0x60], R15
0x2d3fea: CALL 0x00627450
0x2d3fef: TEST EAX, EAX
0x2d3ff1: JZ 0x002d403a
0x2d3ff3: MOV RBX, qword ptr [RBP + -0x60]
0x2d3ff7: LEA RSI, [0x2bfc080]
0x2d3ffe: MOV RDI, qword ptr [RBX + 0x30]
0x2d4002: CALL 0x00c08df0
0x2d4007: MOV RDI, qword ptr [RBX + 0x28]
0x2d400b: MOV RSI, qword ptr [RBP + -0x48]
0x2d400f: CALL 0x00503410
0x2d4014: MOV R13D, 0x23
0x2d401a: JMP 0x002d4178
0x2d401f: MOV RDI, qword ptr [R15 + 0x30]
0x2d4023: LEA RSI, [0x2bfc080]
0x2d402a: CALL 0x00c08df0
0x2d402f: MOV R13D, 0x23
0x2d4035: JMP 0x002d4178
0x2d403a: MOV RAX, qword ptr [RBP + -0x48]
0x2d403e: ADD RAX, R12
0x2d4041: MOV qword ptr [RBP + -0x70], RAX
0x2d4045: CMP R12, RAX
0x2d4048: JNC 0x002d4100
0x2d404e: MOVZX EAX, BL
0x2d4051: XOR EBX, EBX
0x2d4053: SHL EAX, 0x5
0x2d4056: OR EAX, 0x10
0x2d4059: MOV dword ptr [RBP + -0x54], EAX
0x2d405c: NOP dword ptr [RAX]
0x2d4060: MOV EDI, dword ptr [RBP + -0x58]
0x2d4063: LEA RSI, [R12 + RBX*0x1]
0x2d4067: LEA RDX, [RBP + -0x38]
0x2d406b: LEA RCX, [RBP + -0x3c]
0x2d406f: MOV qword ptr [RBP + -0x38], 0x0
0x2d4077: CALL 0x006288d0
0x2d407c: TEST EAX, EAX
0x2d407e: JNZ 0x002d410e
0x2d4084: CMP qword ptr [RBP + -0x38], 0x0
0x2d4089: JZ 0x002d419a
0x2d408f: MOV RAX, qword ptr [RBP + 0x10]
0x2d4093: MOV EDI, dword ptr [RBP + -0x3c]
0x2d4096: LEA R13, [RAX + RBX*0x1]
0x2d409a: MOV RAX, qword ptr [RBP + -0x68]
0x2d409e: LEA R15, [RAX + RBX*0x1]
0x2d40a2: CALL 0x002d5730
0x2d40a7: MOV EDI, dword ptr [RBP + -0x3c]
0x2d40aa: MOV R14D, EAX
0x2d40ad: CALL 0x002d56e0
0x2d40b2: MOV RSI, qword ptr [RBP + -0x38]
0x2d40b6: MOV RDI, R15
0x2d40b9: MOV EDX, EAX
0x2d40bb: CALL 0x008de9e0
0x2d40c0: MOV RSI, qword ptr [RBP + -0x38]
0x2d40c4: MOV RDI, qword ptr [RBP + -0x50]
0x2d40c8: MOV R8D, dword ptr [RBP + -0x54]
0x2d40cc: MOV ECX, 0x4000
0x2d40d1: MOV RDX, R13
0x2d40d4: MOV R9D, R14D
0x2d40d7: MOV dword ptr [RSP], 0x0
0x2d40de: CALL 0x009f02f0
0x2d40e3: TEST EAX, EAX
0x2d40e5: JNZ 0x002d4116
0x2d40e7: LEA RAX, [R12 + RBX*0x1 + 0x4000]
0x2d40ef: ADD RBX, 0x4000
0x2d40f6: CMP RAX, qword ptr [RBP + -0x70]
0x2d40fa: JC 0x002d4060
0x2d4100: MOV RDI, qword ptr [RBP + -0x50]
0x2d4104: CALL 0x009f03b0
0x2d4109: XOR R13D, R13D
0x2d410c: JMP 0x002d4173
0x2d410e: MOV R13D, 0xd
0x2d4114: JMP 0x002d4173
0x2d4116: MOV R15, qword ptr [RBP + -0x60]
0x2d411a: MOV R13D, EAX
0x2d411d: MOV RAX, qword ptr [RBP + -0x68]
0x2d4121: MOV RDI, qword ptr [R15 + 0x28]
0x2d4125: SUB RAX, R12
0x2d4128: LEA RSI, [RAX + RBX*0x1 + 0x4000]
0x2d4130: SHR RSI, 0xe
0x2d4134: CALL 0x008dedb0
0x2d4139: MOV RDI, qword ptr [R15 + 0x28]
0x2d413d: MOV RSI, qword ptr [RBP + -0x48]
0x2d4141: CALL 0x00503410
0x2d4146: MOV qword ptr [R15 + 0x28], 0x0
0x2d414e: LEA RSI, [0x2bfc080]
0x2d4155: MOV RDI, qword ptr [R15 + 0x30]
0x2d4159: CALL 0x00c08df0
0x2d415e: MOV RDI, qword ptr [RBP + -0x50]
0x2d4162: MOV RSI, qword ptr [RBP + 0x10]
0x2d4166: MOV RDX, RBX
0x2d4169: MOV ECX, 0x1
0x2d416e: CALL 0x009f03a0
0x2d4173: CALL 0x006274c0
0x2d4178: LEA RAX, [0x391c310]
0x2d417f: MOV RAX, qword ptr [RAX]
0x2d4182: CMP RAX, qword ptr [RBP + -0x30]
0x2d4186: JNZ 0x002d41c0
0x2d4188: MOV EAX, R13D
0x2d418b: ADD RSP, 0x58
0x2d418f: POP RBX
0x2d4190: POP R12
0x2d4192: POP R13
0x2d4194: POP R14
0x2d4196: POP R15
0x2d4198: POP RBP
0x2d4199: RET
0x2d419a: CALL 0x007f1950
0x2d419f: LEA RDI, [0x2d419a]
0x2d41a6: CALL 0x007f1810
0x2d41ab: LEA RSI, [0x1289ce2]
0x2d41b2: MOV EDI, 0x9b
0x2d41b7: XOR EAX, EAX
0x2d41b9: CALL 0x00c9aa10
0x2d41be: UD2
0x2d41c0: CALL 0x006fd6b0
0x2d41c5: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d41d0 RVA 0x2d41d0 | Evidence ev_0426c4e61593f20f5bc36989d9670d374703cb64bb63d489f2bf6faf0f783f54 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d41d0:
0x2d41d0: PUSH RBP
0x2d41d1: MOV RBP, RSP
0x2d41d4: PUSH R15
0x2d41d6: PUSH R14
0x2d41d8: PUSH R13
0x2d41da: PUSH R12
0x2d41dc: PUSH RBX
0x2d41dd: SUB RSP, 0x18
0x2d41e1: LEA RAX, [0x391c310]
0x2d41e8: MOV R14, RDX
0x2d41eb: MOV R15, RSI
0x2d41ee: MOV RBX, RDI
0x2d41f1: MOV RAX, qword ptr [RAX]
0x2d41f4: MOV qword ptr [RBP + -0x30], RAX
0x2d41f8: MOVZX EAX, byte ptr [RDI + 0x244]
0x2d41ff: TEST AL, 0x10
0x2d4201: JNZ 0x002d422c
0x2d4203: TEST AL, 0x8
0x2d4205: JZ 0x002d4218
0x2d4207: MOV RAX, qword ptr GS:[0x0]
0x2d4210: ADD.LOCK dword ptr [RAX + 0x5a8], 0x1
0x2d4218: LEA RDI, [RBX + 0x170]
0x2d421f: XOR ESI, ESI
0x2d4221: XOR EDX, EDX
0x2d4223: XOR ECX, ECX
0x2d4225: CALL 0x00c4b350
0x2d422a: JMP 0x002d423e
0x2d422c: LEA RDI, [RBX + 0x1a8]
0x2d4233: XOR ESI, ESI
0x2d4235: XOR EDX, EDX
0x2d4237: XOR ECX, ECX
0x2d4239: CALL 0x004c6a00
0x2d423e: LEA RDX, [RBP + -0x38]
0x2d4242: MOV RDI, RBX
0x2d4245: MOV RSI, R15
0x2d4248: ADD R14, R15
0x2d424b: CALL 0x002c6c40
0x2d4250: TEST EAX, EAX
0x2d4252: JZ 0x002d436e
0x2d4258: MOV R13, qword ptr [RBP + -0x38]
0x2d425c: XOR R12D, R12D
0x2d425f: CMP R13, RBX
0x2d4262: JZ 0x002d42eb
0x2d4268: MOV EAX, 0x1
0x2d426d: JMP 0x002d4279
0x2d4270: MOV R13, qword ptr [R13 + 0x8]
0x2d4274: CMP R13, RBX
0x2d4277: JZ 0x002d42eb
0x2d4279: MOV RCX, qword ptr [R13 + 0x20]
0x2d427d: CMP RCX, R14
0x2d4280: JNC 0x002d42eb
0x2d4282: CMP R15, RCX
0x2d4285: JNC 0x002d4295
0x2d4287: MOV RDX, qword ptr [R13]
0x2d428b: CMP RCX, qword ptr [RDX + 0x28]
0x2d428f: JNZ 0x002d436e
0x2d4295: MOV ECX, dword ptr [R13 + 0x60]
0x2d4299: TEST CL, 0x2
0x2d429c: JNZ 0x002d436e
0x2d42a2: MOVZX ESI, byte ptr [R13 + 0x140]
0x2d42aa: MOV EDX, ECX
0x2d42ac: SHL EDX, 0x1a
0x2d42af: SAR EDX, 0x1f
0x2d42b2: AND SIL, 0x20
0x2d42b6: SHR SIL, 0x5
0x2d42ba: TEST ECX, 0x20000
0x2d42c0: SETZ CL
0x2d42c3: ADD EDX, dword ptr [R13 + 0x6c]
0x2d42c7: AND CL, SIL
0x2d42ca: MOVZX ECX, CL
0x2d42cd: CMP EDX, ECX
0x2d42cf: JZ 0x002d439c
0x2d42d5: MOV RCX, qword ptr [R13 + 0x50]
0x2d42d9: TEST RCX, RCX
0x2d42dc: JZ 0x002d4270
0x2d42de: TEST byte ptr [RCX + 0xa2], 0x8
0x2d42e5: CMOVNZ R12D, EAX
0x2d42e9: JMP 0x002d4270
0x2d42eb: TEST byte ptr [RBX + 0x244], 0x10
0x2d42f2: JNZ 0x002d4337
0x2d42f4: LEA RDI, [RBX + 0x170]
0x2d42fb: XOR ESI, ESI
0x2d42fd: XOR EDX, EDX
0x2d42ff: CALL 0x00c4c300
0x2d4304: TEST byte ptr [RBX + 0x244], 0x8
0x2d430b: JZ 0x002d4330
0x2d430d: MOV RAX, qword ptr GS:[0x0]
0x2d4316: MOV ECX, 0xffffffff
0x2d431b: XADD.LOCK dword ptr [RAX + 0x5a8], ECX
0x2d4323: CMP ECX, 0x80000001
0x2d4329: JNZ 0x002d4330
0x2d432b: CALL 0x006b7af0
0x2d4330: CALL 0x002c66f0
0x2d4335: JMP 0x002d434c
0x2d4337: ADD RBX, 0x1a8
0x2d433e: XOR ESI, ESI
0x2d4340: XOR EDX, EDX
0x2d4342: XOR ECX, ECX
0x2d4344: MOV RDI, RBX
0x2d4347: CALL 0x004c6fa0
0x2d434c: LEA RAX, [0x391c310]
0x2d4353: MOV RAX, qword ptr [RAX]
0x2d4356: CMP RAX, qword ptr [RBP + -0x30]
0x2d435a: JNZ 0x002d43d8
0x2d435c: MOV EAX, R12D
0x2d435f: ADD RSP, 0x18
0x2d4363: POP RBX
0x2d4364: POP R12
0x2d4366: POP R13
0x2d4368: POP R14
0x2d436a: POP R15
0x2d436c: POP RBP
0x2d436d: RET
0x2d436e: CALL 0x007f1950
0x2d4373: LEA RDI, [0x2d436e]
0x2d437a: MOV RSI, R15
0x2d437d: MOV RDX, R14
0x2d4380: MOV RCX, RBX
0x2d4383: CALL 0x007f20c0
0x2d4388: LEA RSI, [0x129471f]
0x2d438f: MOV EDI, 0xa7
0x2d4394: MOV RDX, R15
0x2d4397: MOV RCX, R14
0x2d439a: JMP 0x002d43cc
0x2d439c: CALL 0x007f1950
0x2d43a1: MOV RSI, qword ptr [R13 + 0x20]
0x2d43a5: MOV RDX, qword ptr [R13 + 0x28]
0x2d43a9: LEA RDI, [0x2d439c]
0x2d43b0: MOV RCX, RBX
0x2d43b3: CALL 0x007f20c0
0x2d43b8: MOV RDX, qword ptr [R13 + 0x20]
0x2d43bc: MOV RCX, qword ptr [R13 + 0x28]
0x2d43c0: LEA RSI, [0x12fb2de]
0x2d43c7: MOV EDI, 0xa3
0x2d43cc: MOV R8, RBX
0x2d43cf: XOR EAX, EAX
0x2d43d1: CALL 0x00c9aa10
0x2d43d6: UD2
0x2d43d8: CALL 0x006fd6b0
0x2d43dd: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d43e0 RVA 0x2d43e0 | Evidence ev_7c017270f9643735f362dacb9fe197bccee2149166d5cdeab068cfc90cf5acf0 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d43e0:
0x2d43e0: PUSH RBP
0x2d43e1: MOV RBP, RSP
0x2d43e4: PUSH R15
0x2d43e6: PUSH R14
0x2d43e8: PUSH R13
0x2d43ea: PUSH R12
0x2d43ec: PUSH RBX
0x2d43ed: SUB RSP, 0x68
0x2d43f1: LEA RAX, [0x391c310]
0x2d43f8: MOV qword ptr [RBP + -0x68], R9
0x2d43fc: MOV qword ptr [RBP + -0x80], R8
0x2d4400: MOV R14, qword ptr [RBP + 0x18]
0x2d4404: MOV EBX, ECX
0x2d4406: MOV R15, RDX
0x2d4409: MOV R12, RSI
0x2d440c: MOV RAX, qword ptr [RAX]
0x2d440f: MOV qword ptr [RBP + -0x30], RAX
0x2d4413: MOV qword ptr [RBP + -0x88], RDI
0x2d441a: MOV RAX, qword ptr [RDI + 0xe8]
0x2d4421: MOV RAX, qword ptr [RAX + 0xa8]
0x2d4428: MOV qword ptr [RBP + -0x78], RAX
0x2d442c: CALL 0x003c6560
0x2d4431: MOV EDI, EAX
0x2d4433: MOV RSI, R12
0x2d4436: MOV RDX, R15
0x2d4439: MOV dword ptr [R14 + 0x18], 0x1
0x2d4441: MOV qword ptr [R14], R12
0x2d4444: MOV dword ptr [R14 + 0x8], EAX
0x2d4448: MOV dword ptr [RBP + -0x48], EAX
0x2d444b: CALL 0x003c65d0
0x2d4450: TEST EAX, EAX
0x2d4452: JNZ 0x002d459a
0x2d4458: LEA R14, [R15 + R12*0x1]
0x2d445c: MOV qword ptr [RBP + -0x60], R15
0x2d4460: MOV qword ptr [RBP + -0x50], R12
0x2d4464: CMP R12, R14
0x2d4467: JNC 0x002d457b
0x2d446d: MOV R12, qword ptr [RBP + 0x10]
0x2d4471: MOV R13, qword ptr [RBP + -0x50]
0x2d4475: MOVZX EAX, BL
0x2d4478: MOV qword ptr [RBP + -0x70], R14
0x2d447c: SHL EAX, 0x5
0x2d447f: OR EAX, 0x10
0x2d4482: MOV dword ptr [RBP + -0x58], EAX
0x2d4485: JMP 0x002d44a8
0x2d4490: ADD qword ptr [RBP + -0x68], RBX
0x2d4494: MOV R13, qword ptr [RBP + -0x40]
0x2d4498: MOV R14, qword ptr [RBP + -0x70]
0x2d449c: ADD R12, RBX
0x2d449f: CMP R13, R14
0x2d44a2: JNC 0x002d4561
0x2d44a8: MOV RDI, qword ptr [RBP + -0x88]
0x2d44af: MOV RSI, R13
0x2d44b2: LEA RDX, [RBP + -0x38]
0x2d44b6: LEA RCX, [RBP + -0x40]
0x2d44ba: LEA R8, [RBP + -0x44]
0x2d44be: CALL 0x003c54f0
0x2d44c3: TEST EAX, EAX
0x2d44c5: JNZ 0x002d4567
0x2d44cb: MOV RBX, qword ptr [RBP + -0x40]
0x2d44cf: MOV EDI, dword ptr [RBP + -0x44]
0x2d44d2: CMP R14, RBX
0x2d44d5: CMOVC RBX, R14
0x2d44d9: MOV qword ptr [RBP + -0x40], RBX
0x2d44dd: CALL 0x002d5730
0x2d44e2: MOV RDI, qword ptr [RBP + -0x78]
0x2d44e6: MOV RSI, R13
0x2d44e9: MOV R14D, EAX
0x2d44ec: CALL 0x003c36b0
0x2d44f1: MOV RDI, qword ptr [RBP + -0x80]
0x2d44f5: MOV RDX, qword ptr [RBP + -0x68]
0x2d44f9: MOV R8D, dword ptr [RBP + -0x58]
0x2d44fd: MOV RCX, RBX
0x2d4500: MOV RSI, RAX
0x2d4503: MOV R9D, R14D
0x2d4506: MOV R15, RAX
0x2d4509: MOV dword ptr [RSP], 0x1
0x2d4510: SUB RCX, R13
0x2d4513: CALL 0x009f02f0
0x2d4518: MOV EDI, dword ptr [RBP + -0x44]
0x2d451b: MOV dword ptr [RBP + -0x54], EAX
0x2d451e: CALL 0x002d56e0
0x2d4523: SUB RBX, R13
0x2d4526: JZ 0x002d4490
0x2d452c: MOV R14D, EAX
0x2d452f: XOR R13D, R13D
0x2d4532: NOP word ptr CS:[RAX + RAX*0x1]
0x2d4540: LEA RDI, [R12 + R13*0x1]
0x2d4544: LEA RSI, [R15 + R13*0x1]
0x2d4548: MOV EDX, R14D
0x2d454b: CALL 0x008de9e0
0x2d4550: ADD R13, 0x4000
0x2d4557: CMP R13, RBX
0x2d455a: JC 0x002d4540
0x2d455c: JMP 0x002d4490
0x2d4561: CMP dword ptr [RBP + -0x54], 0x0
0x2d4565: JZ 0x002d457b
0x2d4567: MOV EDI, dword ptr [RBP + -0x48]
0x2d456a: MOV RSI, qword ptr [RBP + -0x50]
0x2d456e: MOV RDX, qword ptr [RBP + -0x60]
0x2d4572: CALL 0x003c6ad0
0x2d4577: TEST EAX, EAX
0x2d4579: JNZ 0x002d45dd
0x2d457b: LEA RAX, [0x391c310]
0x2d4582: MOV RAX, qword ptr [RAX]
0x2d4585: CMP RAX, qword ptr [RBP + -0x30]
0x2d4589: JNZ 0x002d45d6
0x2d458b: ADD RSP, 0x68
0x2d458f: POP RBX
0x2d4590: POP R12
0x2d4592: POP R13
0x2d4594: POP R14
0x2d4596: POP R15
0x2d4598: POP RBP
0x2d4599: RET
0x2d459a: MOV EBX, EAX
0x2d459c: CALL 0x007f1950
0x2d45a1: MOV R14D, dword ptr [RBP + -0x48]
0x2d45a5: MOVSXD RSI, EBX
0x2d45a8: LEA RDI, [0x2d459a]
0x2d45af: MOV RCX, R12
0x2d45b2: MOV R8, R15
0x2d45b5: MOVSXD RDX, R14D
0x2d45b8: CALL 0x007f2180
0x2d45bd: LEA RSI, [0x12e6b8d]
0x2d45c4: MOV EDI, 0x93
0x2d45c9: MOV EDX, EBX
0x2d45cb: MOV ECX, R14D
0x2d45ce: MOV R8, R12
0x2d45d1: MOV R9, R15
0x2d45d4: JMP 0x002d461f
0x2d45d6: CALL 0x006fd6b0
0x2d45db: UD2
0x2d45dd: MOV EBX, EAX
0x2d45df: CALL 0x007f1950
0x2d45e4: MOV R12D, dword ptr [RBP + -0x48]
0x2d45e8: MOV R15, qword ptr [RBP + -0x50]
0x2d45ec: MOV R14, qword ptr [RBP + -0x60]
0x2d45f0: MOVSXD RSI, EBX
0x2d45f3: LEA RDI, [0x2d45dd]
0x2d45fa: MOVSXD RDX, R12D
0x2d45fd: MOV RCX, R15
0x2d4600: MOV R8, R14
0x2d4603: CALL 0x007f2180
0x2d4608: LEA RSI, [0x12dc986]
0x2d460f: MOV EDI, 0x97
0x2d4614: MOV EDX, EBX
0x2d4616: MOV ECX, R12D
0x2d4619: MOV R8, R15
0x2d461c: MOV R9, R14
0x2d461f: XOR EAX, EAX
0x2d4621: CALL 0x00c9aa10
0x2d4626: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d4630 RVA 0x2d4630 | Evidence ev_20f1d0109105b092eb59a726b21c0c1075a130b881a908dee6a76e41fc13026a | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d4630:
0x2d4630: PUSH RBP
0x2d4631: MOV RBP, RSP
0x2d4634: PUSH R15
0x2d4636: PUSH R14
0x2d4638: PUSH R13
0x2d463a: PUSH R12
0x2d463c: PUSH RBX
0x2d463d: SUB RSP, 0x48
0x2d4641: MOV qword ptr [RBP + -0x68], R8
0x2d4645: LEA R8, [0x391c310]
0x2d464c: MOV dword ptr [RBP + -0x48], ECX
0x2d464f: MOV RAX, qword ptr [RBP + 0x18]
0x2d4653: MOV R13, RSI
0x2d4656: MOV RBX, RDI
0x2d4659: ADD RDI, 0x18
0x2d465d: MOV R15, RDX
0x2d4660: MOV R12, R9
0x2d4663: XOR EDX, EDX
0x2d4665: SAR R13, 0xe
0x2d4669: MOV RCX, qword ptr [R8]
0x2d466c: MOV qword ptr [RBP + -0x30], RCX
0x2d4670: MOV qword ptr [RBP + -0x40], RSI
0x2d4674: XOR ESI, ESI
0x2d4676: MOV dword ptr [RAX + 0x18], 0x2
0x2d467d: MOV qword ptr [RBP + -0x50], RDI
0x2d4681: CALL 0x007d50c0
0x2d4686: MOV RDI, RBX
0x2d4689: MOV RSI, R13
0x2d468c: CALL 0x00b897e0
0x2d4691: MOV qword ptr [RBP + -0x38], RAX
0x2d4695: TEST RAX, RAX
0x2d4698: JZ 0x002d4800
0x2d469e: ADD R15, qword ptr [RBP + -0x40]
0x2d46a2: MOVZX ECX, byte ptr [RBP + -0x48]
0x2d46a6: MOV RDX, qword ptr [RBP + 0x10]
0x2d46aa: MOV R14, RAX
0x2d46ad: LEA RBX, [0x3d7c440]
0x2d46b4: MOV RAX, R14
0x2d46b7: SHL ECX, 0x5
0x2d46ba: MOV qword ptr [RBP + -0x58], RDX
0x2d46be: SAR R15, 0xe
0x2d46c2: OR ECX, 0x10
0x2d46c5: MOV dword ptr [RBP + -0x40], ECX
0x2d46c8: MOV qword ptr [RBP + -0x60], R15
0x2d46cc: NOP dword ptr [RAX]
0x2d46d0: MOV R15D, 0xd
0x2d46d6: CMP R13, qword ptr [RAX + 0x28]
0x2d46da: JNZ 0x002d47f9
0x2d46e0: MOV EAX, dword ptr [RAX + 0x30]
0x2d46e3: XOR ESI, ESI
0x2d46e5: XOR EDX, EDX
0x2d46e7: XOR ECX, ECX
0x2d46e9: SHR EAX, 0xf
0x2d46ec: AND EAX, 0x3fc0
0x2d46f1: LEA RDI, [RAX + RBX*0x1 + 0x18]
0x2d46f6: CALL 0x004c6a00
0x2d46fb: MOV RDI, qword ptr [RBP + -0x38]
0x2d46ff: CALL 0x00b8ca20
0x2d4704: MOV RAX, qword ptr [RBP + -0x38]
0x2d4708: XOR ESI, ESI
0x2d470a: XOR EDX, EDX
0x2d470c: XOR ECX, ECX
0x2d470e: MOV EAX, dword ptr [RAX + 0x30]
0x2d4711: SHR EAX, 0xf
0x2d4714: AND EAX, 0x3fc0
0x2d4719: LEA RDI, [RAX + RBX*0x1 + 0x18]
0x2d471e: CALL 0x004c6fa0
0x2d4723: MOV RAX, qword ptr [RBP + -0x38]
0x2d4727: MOV R15D, 0x412
0x2d472d: MOV qword ptr [RBP + -0x48], R12
0x2d4731: MOV RDI, qword ptr [RAX + 0x20]
0x2d4735: TEST RDI, RDI
0x2d4738: JZ 0x002d4756
0x2d473a: CMP byte ptr [RDI + 0x9d], 0xa
0x2d4741: JNZ 0x002d4756
0x2d4743: CALL 0x0091bc90
0x2d4748: MOV EDI, EAX
0x2d474a: CALL 0x002d5730
0x2d474f: MOV R15D, EAX
0x2d4752: MOV RAX, qword ptr [RBP + -0x38]
0x2d4756: MOV RBX, qword ptr [RBP + -0x50]
0x2d475a: MOV R12, qword ptr [RAX + 0x30]
0x2d475e: XOR ESI, ESI
0x2d4760: XOR EDX, EDX
0x2d4762: MOV RDI, RBX
0x2d4765: CALL 0x007d56e0
0x2d476a: MOV RDI, qword ptr [RBP + -0x58]
0x2d476e: LEA RSI, [RBP + -0x38]
0x2d4772: MOV EDX, 0x1
0x2d4777: CALL 0x008dec80
0x2d477c: MOV RSI, R12
0x2d477f: MOV R12, qword ptr [RBP + -0x48]
0x2d4783: MOV RDI, qword ptr [RBP + -0x68]
0x2d4787: MOV R8D, dword ptr [RBP + -0x40]
0x2d478b: MOV ECX, 0x4000
0x2d4790: MOV R9D, R15D
0x2d4793: MOV dword ptr [RSP], 0x0
0x2d479a: MOV RDX, R12
0x2d479d: CALL 0x009f02f0
0x2d47a2: MOV RDI, RBX
0x2d47a5: MOV R15D, EAX
0x2d47a8: XOR ESI, ESI
0x2d47aa: XOR EDX, EDX
0x2d47ac: CALL 0x007d50c0
0x2d47b1: TEST R15D, R15D
0x2d47b4: JNZ 0x002d4808
0x2d47b6: MOV RCX, qword ptr [RBP + -0x60]
0x2d47ba: INC R13
0x2d47bd: LEA RBX, [0x3d7c440]
0x2d47c4: CMP RCX, R13
0x2d47c7: JBE 0x002d4871
0x2d47cd: MOV RAX, qword ptr [RBP + -0x38]
0x2d47d1: ADD qword ptr [RBP + -0x58], 0x4000
0x2d47d9: ADD R12, 0x4000
0x2d47e0: MOV RAX, qword ptr [RAX + 0x10]
0x2d47e4: MOV qword ptr [RBP + -0x38], RAX
0x2d47e8: TEST RAX, RAX
0x2d47eb: JNZ 0x002d46d0
0x2d47f1: MOV R15D, 0xd
0x2d47f7: XOR EAX, EAX
0x2d47f9: CMP R14, RAX
0x2d47fc: JNZ 0x002d4820
0x2d47fe: JMP 0x002d4874
0x2d4800: MOV R15D, 0xd
0x2d4806: JMP 0x002d4874
0x2d4808: MOV RAX, qword ptr [RBP + -0x38]
0x2d480c: LEA RBX, [0x3d7c440]
0x2d4813: CMP R14, RAX
0x2d4816: JZ 0x002d4874
0x2d4818: NOP dword ptr [RAX + RAX*0x1]
0x2d4820: MOV EAX, dword ptr [R14 + 0x30]
0x2d4824: XOR ESI, ESI
0x2d4826: XOR EDX, EDX
0x2d4828: XOR ECX, ECX
0x2d482a: SHR EAX, 0xf
0x2d482d: AND EAX, 0x3fc0
0x2d4832: LEA RDI, [RAX + RBX*0x1 + 0x18]
0x2d4837: CALL 0x004c6a00
0x2d483c: MOV RDI, R14
0x2d483f: MOV ESI, 0x1
0x2d4844: CALL 0x00b8ca70
0x2d4849: MOV EAX, dword ptr [R14 + 0x30]
0x2d484d: XOR ESI, ESI
0x2d484f: XOR EDX, EDX
0x2d4851: XOR ECX, ECX
0x2d4853: SHR EAX, 0xf
0x2d4856: AND EAX, 0x3fc0
0x2d485b: LEA RDI, [RAX + RBX*0x1 + 0x18]
0x2d4860: CALL 0x004c6fa0
0x2d4865: MOV R14, qword ptr [R14 + 0x10]
0x2d4869: CMP R14, qword ptr [RBP + -0x38]
0x2d486d: JNZ 0x002d4820
0x2d486f: JMP 0x002d4874
0x2d4871: XOR R15D, R15D
0x2d4874: MOV RDI, qword ptr [RBP + -0x50]
0x2d4878: XOR ESI, ESI
0x2d487a: XOR EDX, EDX
0x2d487c: CALL 0x007d56e0
0x2d4881: LEA RAX, [0x391c310]
0x2d4888: MOV RAX, qword ptr [RAX]
0x2d488b: CMP RAX, qword ptr [RBP + -0x30]
0x2d488f: JNZ 0x002d48a3
0x2d4891: MOV EAX, R15D
0x2d4894: ADD RSP, 0x48
0x2d4898: POP RBX
0x2d4899: POP R12
0x2d489b: POP R13
0x2d489d: POP R14
0x2d489f: POP R15
0x2d48a1: POP RBP
0x2d48a2: RET
0x2d48a3: CALL 0x006fd6b0
0x2d48a8: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d48b0 RVA 0x2d48b0 | Evidence ev_958cf6f270fb36e144ea86cd88afa650ae9ef7fc85597cb07fbf91d3697461cb | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d48b0:
0x2d48b0: PUSH RBP
0x2d48b1: MOV RBP, RSP
0x2d48b4: PUSH R15
0x2d48b6: PUSH R14
0x2d48b8: PUSH R13
0x2d48ba: PUSH R12
0x2d48bc: PUSH RBX
0x2d48bd: SUB RSP, 0x28
0x2d48c1: MOVSXD RAX, dword ptr [RDI + 0x38]
0x2d48c5: MOV qword ptr [RBP + -0x48], RAX
0x2d48c9: TEST RAX, RAX
0x2d48cc: JLE 0x002d49de
0x2d48d2: MOV RAX, qword ptr [RDI + 0x30]
0x2d48d6: MOV RCX, qword ptr [RDI + 0x28]
0x2d48da: XOR R13D, R13D
0x2d48dd: MOV qword ptr [RBP + -0x40], RAX
0x2d48e1: MOV qword ptr [RBP + -0x30], RCX
0x2d48e5: JMP 0x002d4912
0x2d48f0: CALL 0x002d6a30
0x2d48f5: MOV RCX, qword ptr [RBP + -0x38]
0x2d48f9: MOV RAX, qword ptr [RBP + -0x30]
0x2d48fd: INC R13
0x2d4900: ADD RAX, qword ptr [RCX + 0x10]
0x2d4904: MOV qword ptr [RBP + -0x30], RAX
0x2d4908: CMP R13, qword ptr [RBP + -0x48]
0x2d490c: JZ 0x002d49de
0x2d4912: MOV RCX, qword ptr [RBP + -0x40]
0x2d4916: MOV RAX, R13
0x2d4919: SHL RAX, 0x5
0x2d491d: LEA RDI, [RCX + RAX*0x1]
0x2d4921: MOV EAX, dword ptr [RCX + RAX*0x1 + 0x18]
0x2d4925: MOV qword ptr [RBP + -0x38], RDI
0x2d4929: CMP EAX, 0x1
0x2d492c: JZ 0x002d48f0
0x2d492e: CMP EAX, 0x3
0x2d4931: JZ 0x002d48f5
0x2d4933: CMP EAX, 0x2
0x2d4936: JNZ 0x002d49ed
0x2d493c: MOV RAX, qword ptr [RBP + -0x38]
0x2d4940: MOV RBX, qword ptr [RAX + 0x10]
0x2d4944: SHR RBX, 0xe
0x2d4948: TEST EBX, EBX
0x2d494a: JLE 0x002d48f5
0x2d494c: MOV R14, qword ptr [RBP + -0x30]
0x2d4950: AND EBX, 0x7fffffff
0x2d4956: JMP 0x002d496c
0x2d4960: ADD R14, 0x4000
0x2d4967: DEC RBX
0x2d496a: JZ 0x002d48f5
0x2d496c: MOV RDI, R14
0x2d496f: CALL 0x008de330
0x2d4974: TEST RAX, RAX
0x2d4977: JZ 0x002d4960
0x2d4979: MOV RDI, RAX
0x2d497c: CALL 0x00b89290
0x2d4981: MOV R15, RAX
0x2d4984: MOV EAX, dword ptr [RAX + 0x30]
0x2d4987: LEA R12, [0x3d7c440]
0x2d498e: XOR ESI, ESI
0x2d4990: XOR EDX, EDX
0x2d4992: XOR ECX, ECX
0x2d4994: SHR EAX, 0xf
0x2d4997: AND EAX, 0x3fc0
0x2d499c: LEA RDI, [RAX + R12*0x1 + 0x18]
0x2d49a1: CALL 0x004c6a00
0x2d49a6: TEST byte ptr [R15 + 0x65], 0x4
0x2d49ab: MOV ESI, 0xff
0x2d49b0: MOV EAX, 0x1
0x2d49b5: MOV RDI, R15
0x2d49b8: CMOVZ ESI, EAX
0x2d49bb: CALL 0x00b8ca70
0x2d49c0: MOV EAX, dword ptr [R15 + 0x30]
0x2d49c4: XOR ESI, ESI
0x2d49c6: XOR EDX, EDX
0x2d49c8: XOR ECX, ECX
0x2d49ca: SHR EAX, 0xf
0x2d49cd: AND EAX, 0x3fc0
0x2d49d2: LEA RDI, [RAX + R12*0x1 + 0x18]
0x2d49d7: CALL 0x004c6fa0
0x2d49dc: JMP 0x002d4960
0x2d49de: ADD RSP, 0x28
0x2d49e2: POP RBX
0x2d49e3: POP R12
0x2d49e5: POP R13
0x2d49e7: POP R14
0x2d49e9: POP R15
0x2d49eb: POP RBP
0x2d49ec: RET
0x2d49ed: CALL 0x007f1950
0x2d49f2: MOV RBX, qword ptr [RBP + -0x38]
0x2d49f6: LEA RDI, [0x2d49ed]
0x2d49fd: MOVSXD RSI, dword ptr [RBX + 0x18]
0x2d4a01: CALL 0x007f18a0
0x2d4a06: MOV EDX, dword ptr [RBX + 0x18]
0x2d4a09: LEA RSI, [0x1383655]
0x2d4a10: MOV EDI, 0x8f
0x2d4a15: XOR EAX, EAX
0x2d4a17: CALL 0x00c9aa10
0x2d4a1c: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d4a2a RVA 0x2d4a2a | Evidence ev_a5d840c1b8a9fc9f2c2ff0ac78d5759d3526572ca6f6b02a916d1b8ce9c24f6e | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d4a2a:
0x2d4a2a: PUSH RBP
0x2d4a2b: MOV RBP, RSP
0x2d4a2e: PUSH R14
0x2d4a30: PUSH RBX
0x2d4a31: MOV RBX, qword ptr [RDI + 0x10]
0x2d4a35: MOV RAX, qword ptr [RDI + 0x18]
0x2d4a39: MOV RSI, qword ptr [RDI + 0x20]
0x2d4a3d: MOV R14, RDI
0x2d4a40: MOV ECX, 0x1
0x2d4a45: MOV RDI, RAX
0x2d4a48: MOV RDX, RBX
0x2d4a4b: CALL 0x009f03a0
0x2d4a50: MOV RDI, R14
0x2d4a53: CALL 0x002d48b0
0x2d4a58: MOV RDI, qword ptr [R14 + 0x30]
0x2d4a5c: LEA RSI, [0x2bfc080]
0x2d4a63: CALL 0x00c08df0
0x2d4a68: MOV qword ptr [R14 + 0x30], 0x0
0x2d4a70: MOV dword ptr [R14 + 0x38], 0x0
0x2d4a78: MOV RSI, RBX
0x2d4a7b: MOV RDI, qword ptr [R14 + 0x28]
0x2d4a7f: SHR RSI, 0xe
0x2d4a83: CALL 0x008dedb0
0x2d4a88: MOV RDI, qword ptr [R14 + 0x28]
0x2d4a8c: MOV RSI, RBX
0x2d4a8f: CALL 0x00503410
0x2d4a94: XOR EAX, EAX
0x2d4a96: MOV qword ptr [R14 + 0x28], 0x0
0x2d4a9e: POP RBX
0x2d4a9f: POP R14
0x2d4aa1: POP RBP
0x2d4aa2: RET


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d4ab0 RVA 0x2d4ab0 | Evidence ev_450eb7a5c2a83d6ffe9c61e291a52555161f6c64b1f01c4dfe8dfdda4e5876c7 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d4ab0:
0x2d4ab0: PUSH RBP
0x2d4ab1: MOV RBP, RSP
0x2d4ab4: PUSH R15
0x2d4ab6: PUSH R14
0x2d4ab8: PUSH R13
0x2d4aba: PUSH R12
0x2d4abc: PUSH RBX
0x2d4abd: SUB RSP, 0x18
0x2d4ac1: LEA R15, [0x391c310]
0x2d4ac8: MOV RCX, RSI
0x2d4acb: SHR RCX, 0x28
0x2d4acf: MOV RAX, qword ptr [R15]
0x2d4ad2: MOV qword ptr [RBP + -0x30], RAX
0x2d4ad6: MOV EAX, 0x2d
0x2d4adb: CMP ECX, 0xe
0x2d4ade: JA 0x002d4bd6
0x2d4ae4: MOV RAX, RSI
0x2d4ae7: SHR RAX, 0x2b
0x2d4aeb: JZ 0x002d4b0d
0x2d4aed: MOV RAX, qword ptr [R15]
0x2d4af0: CMP RAX, qword ptr [RBP + -0x30]
0x2d4af4: JNZ 0x002d4c2a
0x2d4afa: ADD RSP, 0x18
0x2d4afe: POP RBX
0x2d4aff: POP R12
0x2d4b01: POP R13
0x2d4b03: POP R14
0x2d4b05: POP R15
0x2d4b07: POP RBP
0x2d4b08: JMP 0x0062b800
0x2d4b0d: MOV RBX, qword ptr [RDI + 0x200]
0x2d4b14: MOV R12, RDI
0x2d4b17: MOV R14, RSI
0x2d4b1a: MOV R13, RDX
0x2d4b1d: MOVZX EAX, byte ptr [RBX + 0x244]
0x2d4b24: TEST AL, 0x10
0x2d4b26: JNZ 0x002d4b51
0x2d4b28: TEST AL, 0x8
0x2d4b2a: JZ 0x002d4b3d
0x2d4b2c: MOV RAX, qword ptr GS:[0x0]
0x2d4b35: ADD.LOCK dword ptr [RAX + 0x5a8], 0x1
0x2d4b3d: LEA RDI, [RBX + 0x170]
0x2d4b44: XOR ESI, ESI
0x2d4b46: XOR EDX, EDX
0x2d4b48: XOR ECX, ECX
0x2d4b4a: CALL 0x00c4bb20
0x2d4b4f: JMP 0x002d4b63
0x2d4b51: LEA RDI, [RBX + 0x1a8]
0x2d4b58: XOR ESI, ESI
0x2d4b5a: XOR EDX, EDX
0x2d4b5c: XOR ECX, ECX
0x2d4b5e: CALL 0x004c6a00
0x2d4b63: INC dword ptr [RBX + 0x1c0]
0x2d4b69: LEA RDX, [RBP + -0x38]
0x2d4b6d: MOV RDI, RBX
0x2d4b70: MOV RSI, R14
0x2d4b73: ADD.LOCK dword ptr [RBX + 0x1c4], 0x1
0x2d4b7b: CALL 0x002c6c40
0x2d4b80: TEST EAX, EAX
0x2d4b82: JZ 0x002d4bc1
0x2d4b84: MOV RCX, qword ptr [RBP + -0x38]
0x2d4b88: MOV EAX, 0x2d
0x2d4b8d: TEST byte ptr [RCX + 0x60], 0x2
0x2d4b91: JNZ 0x002d4bc6
0x2d4b93: MOV RDI, qword ptr [RCX + 0x50]
0x2d4b97: TEST RDI, RDI
0x2d4b9a: JZ 0x002d4bc6
0x2d4b9c: MOVZX ESI, byte ptr [RDI + 0x9d]
0x2d4ba3: CMP ESI, 0x2
0x2d4ba6: JC 0x002d4bee
0x2d4ba8: MOV RDX, R13
0x2d4bab: CMP ESI, 0x3
0x2d4bae: JZ 0x002d4c01
0x2d4bb0: CMP ESI, 0xa
0x2d4bb3: JNZ 0x002d4bc6
0x2d4bb5: MOV EAX, dword ptr [RDI + 0x14c]
0x2d4bbb: MOV dword ptr [RDX], EAX
0x2d4bbd: XOR EAX, EAX
0x2d4bbf: JMP 0x002d4bc6
0x2d4bc1: MOV EAX, 0x2
0x2d4bc6: MOV RDI, RBX
0x2d4bc9: XOR ESI, ESI
0x2d4bcb: XOR EDX, EDX
0x2d4bcd: MOV EBX, EAX
0x2d4bcf: CALL 0x002c64f0
0x2d4bd4: MOV EAX, EBX
0x2d4bd6: MOV RCX, qword ptr [R15]
0x2d4bd9: CMP RCX, qword ptr [RBP + -0x30]
0x2d4bdd: JNZ 0x002d4c2a
0x2d4bdf: ADD RSP, 0x18
0x2d4be3: POP RBX
0x2d4be4: POP R12
0x2d4be6: POP R13
0x2d4be8: POP R14
0x2d4bea: POP R15
0x2d4bec: POP RBP
0x2d4bed: RET
0x2d4bee: TEST byte ptr [RDI + 0xa2], 0x2
0x2d4bf5: JNZ 0x002d4c1c
0x2d4bf7: MOV EAX, dword ptr [R12 + 0xbc]
0x2d4bff: JMP 0x002d4c22
0x2d4c01: TEST byte ptr [RDI + 0xa2], 0x1
0x2d4c08: JZ 0x002d4bc6
0x2d4c0a: SUB R14, qword ptr [RCX + 0x20]
0x2d4c0e: ADD R14, qword ptr [RCX + 0x58]
0x2d4c12: MOV RSI, R14
0x2d4c15: CALL 0x003c5730
0x2d4c1a: JMP 0x002d4bc6
0x2d4c1c: MOV EAX, dword ptr [RDI + 0x14c]
0x2d4c22: MOV dword ptr [R13], EAX
0x2d4c26: XOR EAX, EAX
0x2d4c28: JMP 0x002d4bc6
0x2d4c2a: CALL 0x006fd6b0
0x2d4c2f: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d4c40 RVA 0x2d4c40 | Evidence ev_7f019765320a7a6466788b8146f12929adb74eea4b6ca45017e4232d60267db4 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d4c40:
0x2d4c40: PUSH RBP
0x2d4c41: MOV RBP, RSP
0x2d4c44: PUSH R14
0x2d4c46: PUSH RBX
0x2d4c47: MOV R14D, EDI
0x2d4c4a: LEA RDI, [0x3589e60]
0x2d4c51: XOR EBX, EBX
0x2d4c53: XOR ESI, ESI
0x2d4c55: XOR EDX, EDX
0x2d4c57: XOR ECX, ECX
0x2d4c59: CALL 0x00c4b350
0x2d4c5e: LEA RAX, [0x3589e80]
0x2d4c65: NOP dword ptr CS:[RAX + RAX*0x1]
0x2d4c70: MOV RAX, qword ptr [RAX]
0x2d4c73: TEST RAX, RAX
0x2d4c76: JZ 0x002d4c95
0x2d4c78: MOV RCX, qword ptr [RAX + 0x200]
0x2d4c7f: MOV RCX, qword ptr [RCX + 0x1d8]
0x2d4c86: CMP dword ptr [RCX + 0x27c], R14D
0x2d4c8d: JNZ 0x002d4c70
0x2d4c8f: MOV EBX, dword ptr [RAX + 0xbc]
0x2d4c95: LEA RDI, [0x3589e60]
0x2d4c9c: XOR ESI, ESI
0x2d4c9e: XOR EDX, EDX
0x2d4ca0: CALL 0x00c4c300
0x2d4ca5: MOV EAX, EBX
0x2d4ca7: POP RBX
0x2d4ca8: POP R14
0x2d4caa: POP RBP
0x2d4cab: RET


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d4cb0 RVA 0x2d4cb0 | Evidence ev_156b4ac25742868824177ab5ed88e98ef7fa2fad5c43875bbcc1bcfd3f70cdc4 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d4cb0:
0x2d4cb0: PUSH RBP
0x2d4cb1: MOV RBP, RSP
0x2d4cb4: PUSH R15
0x2d4cb6: PUSH R14
0x2d4cb8: PUSH R13
0x2d4cba: PUSH R12
0x2d4cbc: PUSH RBX
0x2d4cbd: SUB RSP, 0x18
0x2d4cc1: LEA RAX, [0x391c310]
0x2d4cc8: MOV RAX, qword ptr [RAX]
0x2d4ccb: MOV qword ptr [RBP + -0x30], RAX
0x2d4ccf: MOV R13, qword ptr [RDI + 0x8]
0x2d4cd3: MOV qword ptr [RBP + -0x38], R13
0x2d4cd7: CMP R13, RDI
0x2d4cda: JZ 0x002d4e38
0x2d4ce0: LEA RAX, [RDI + 0x1a8]
0x2d4ce7: MOV RBX, RDI
0x2d4cea: LEA R15, [RDI + 0x170]
0x2d4cf1: MOV qword ptr [RBP + -0x40], RAX
0x2d4cf5: JMP 0x002d4d27
0x2d4d00: MOV RSI, qword ptr [R13 + 0x20]
0x2d4d04: MOV RDX, qword ptr [R13 + 0x28]
0x2d4d08: MOV RDI, RBX
0x2d4d0b: MOV ECX, 0x1
0x2d4d10: SUB RDX, RSI
0x2d4d13: CALL R12
0x2d4d16: MOV R13, qword ptr [R13 + 0x8]
0x2d4d1a: MOV qword ptr [RBP + -0x38], R13
0x2d4d1e: CMP R13, RBX
0x2d4d21: JZ 0x002d4e38
0x2d4d27: MOV EAX, dword ptr [R13 + 0x60]
0x2d4d2b: TEST EAX, 0x40100
0x2d4d30: JZ 0x002d4dd4
0x2d4d36: OR EAX, 0x200
0x2d4d3b: MOV RDI, RBX
0x2d4d3e: XOR ESI, ESI
0x2d4d40: XOR EDX, EDX
0x2d4d42: XOR ECX, ECX
0x2d4d44: MOV dword ptr [R13 + 0x60], EAX
0x2d4d48: MOV R12, qword ptr [R13 + 0x20]
0x2d4d4c: MOV R14D, dword ptr [RBX + 0x1c0]
0x2d4d53: CALL 0x002c6d80
0x2d4d58: MOVZX EAX, byte ptr [RBX + 0x244]
0x2d4d5f: TEST AL, 0x10
0x2d4d61: JNZ 0x002d4d90
0x2d4d63: TEST AL, 0x8
0x2d4d65: JZ 0x002d4d78
0x2d4d67: MOV RAX, qword ptr GS:[0x0]
0x2d4d70: ADD.LOCK dword ptr [RAX + 0x5a8], 0x1
0x2d4d78: MOV RDI, R15
0x2d4d7b: XOR ESI, ESI
0x2d4d7d: XOR EDX, EDX
0x2d4d7f: XOR ECX, ECX
0x2d4d81: CALL 0x00c4bb20
0x2d4d86: JMP 0x002d4d9f
0x2d4d90: MOV RDI, qword ptr [RBP + -0x40]
0x2d4d94: XOR ESI, ESI
0x2d4d96: XOR EDX, EDX
0x2d4d98: XOR ECX, ECX
0x2d4d9a: CALL 0x004c6a00
0x2d4d9f: INC dword ptr [RBX + 0x1c0]
0x2d4da5: INC R14D
0x2d4da8: ADD.LOCK dword ptr [RBX + 0x1c4], 0x1
0x2d4db0: CMP R14D, dword ptr [RBX + 0x1c0]
0x2d4db7: JZ 0x002d4dd4
0x2d4db9: MOV RDI, RBX
0x2d4dbc: MOV RSI, R12
0x2d4dbf: LEA RDX, [RBP + -0x38]
0x2d4dc3: CALL 0x002c6c40
0x2d4dc8: MOV R13, qword ptr [RBP + -0x38]
0x2d4dcc: TEST EAX, EAX
0x2d4dce: JZ 0x002d4d16
0x2d4dd4: MOVZX EAX, word ptr [R13 + 0x64]
0x2d4dd9: TEST EAX, 0x3c7
0x2d4dde: JZ 0x002d4df9
0x2d4de0: MOV RDI, qword ptr [RBX + 0x1d8]
0x2d4de7: MOV RSI, qword ptr [R13 + 0x20]
0x2d4deb: MOV RDX, qword ptr [R13 + 0x28]
0x2d4def: CALL 0x008df6a0
0x2d4df4: MOVZX EAX, word ptr [R13 + 0x64]
0x2d4df9: TEST AL, 0x30
0x2d4dfb: JZ 0x002d4d16
0x2d4e01: MOV RAX, qword ptr [0x01a962e8]
0x2d4e08: MOV R12, qword ptr [RAX + 0x18]
0x2d4e0c: LEA RAX, [0x26bf10]
0x2d4e13: SUB RAX, R12
0x2d4e16: ROR RAX, 0x3
0x2d4e1a: CMP RAX, 0x2
0x2d4e1e: JBE 0x002d4d00
0x2d4e24: LEA RDI, [0x1a960f0]
0x2d4e2b: MOV RSI, R12
0x2d4e2e: CALL 0x0044f8c0
0x2d4e33: JMP 0x002d4d00
0x2d4e38: LEA RAX, [0x391c310]
0x2d4e3f: MOV RAX, qword ptr [RAX]
0x2d4e42: CMP RAX, qword ptr [RBP + -0x30]
0x2d4e46: JNZ 0x002d4e57
0x2d4e48: ADD RSP, 0x18
0x2d4e4c: POP RBX
0x2d4e4d: POP R12
0x2d4e4f: POP R13
0x2d4e51: POP R14
0x2d4e53: POP R15
0x2d4e55: POP RBP
0x2d4e56: RET
0x2d4e57: CALL 0x006fd6b0
0x2d4e5c: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d4e60 RVA 0x2d4e60 | Evidence ev_9dafa2640411492ba264bc55049d178ee48037f3531800bf9ae3ee1232c90b13 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d4e60:
0x2d4e60: PUSH RBP
0x2d4e61: MOV RBP, RSP
0x2d4e64: PUSH R15
0x2d4e66: PUSH R14
0x2d4e68: PUSH R13
0x2d4e6a: PUSH R12
0x2d4e6c: PUSH RBX
0x2d4e6d: SUB RSP, 0x28
0x2d4e71: MOV R14, qword ptr [RDI + 0x8]
0x2d4e75: MOV qword ptr [RBP + -0x30], RDI
0x2d4e79: CMP R14, RDI
0x2d4e7c: JZ 0x002d4fa8
0x2d4e82: MOV RAX, qword ptr [RBP + -0x30]
0x2d4e86: MOV R15, qword ptr [R14 + 0x20]
0x2d4e8a: MOV RAX, qword ptr [RAX + 0x1d8]
0x2d4e91: MOV qword ptr [RBP + -0x40], RAX
0x2d4e95: JMP 0x002d4ec4
0x2d4ea0: MOV RDI, qword ptr [RBP + -0x30]
0x2d4ea4: MOV R8, qword ptr [RBP + -0x48]
0x2d4ea8: MOV R9D, dword ptr [RBP + -0x34]
0x2d4eac: MOV RSI, R12
0x2d4eaf: MOV RDX, R15
0x2d4eb2: MOV RCX, R13
0x2d4eb5: CALL 0x002cbad0
0x2d4eba: CMP R14, qword ptr [RBP + -0x30]
0x2d4ebe: JZ 0x002d4fa8
0x2d4ec4: MOV R12, qword ptr [R14 + 0x20]
0x2d4ec8: MOV RBX, R14
0x2d4ecb: CMP R15, R12
0x2d4ece: JNC 0x002d4eee
0x2d4ed0: MOV RDI, qword ptr [RBP + -0x40]
0x2d4ed4: MOV RSI, R15
0x2d4ed7: MOV RDX, R12
0x2d4eda: MOV dword ptr [RSP], 0x0
0x2d4ee1: XOR ECX, ECX
0x2d4ee3: XOR R8D, R8D
0x2d4ee6: XOR R9D, R9D
0x2d4ee9: CALL 0x008e46d0
0x2d4eee: MOV R8, qword ptr [RBX + 0x58]
0x2d4ef2: MOV R13, qword ptr [RBX + 0x50]
0x2d4ef6: MOVZX EAX, word ptr [RBX + 0x64]
0x2d4efa: MOV R14, RBX
0x2d4efd: MOV RCX, R8
0x2d4f00: SUB RCX, R12
0x2d4f03: NOP dword ptr CS:[RAX + RAX*0x1]
0x2d4f10: MOV R15, qword ptr [R14 + 0x28]
0x2d4f14: MOV R14, qword ptr [R14 + 0x8]
0x2d4f18: CMP qword ptr [R14 + 0x20], R15
0x2d4f1c: JNZ 0x002d4f35
0x2d4f1e: CMP qword ptr [R14 + 0x50], R13
0x2d4f22: JNZ 0x002d4f35
0x2d4f24: LEA RDX, [RCX + R15*0x1]
0x2d4f28: CMP qword ptr [R14 + 0x58], RDX
0x2d4f2c: JNZ 0x002d4f35
0x2d4f2e: CMP word ptr [R14 + 0x64], AX
0x2d4f33: JZ 0x002d4f10
0x2d4f35: TEST R13, R13
0x2d4f38: JZ 0x002d4f60
0x2d4f3a: CMP byte ptr [R13 + 0x9d], 0xb
0x2d4f42: JNZ 0x002d4f60
0x2d4f44: MOV RDI, qword ptr [RBP + -0x30]
0x2d4f48: MOV RSI, R12
0x2d4f4b: MOV RDX, R15
0x2d4f4e: MOV RCX, R13
0x2d4f51: CALL 0x009a7f30
0x2d4f56: JMP 0x002d4eba
0x2d4f60: MOV ECX, 0x103
0x2d4f65: MOV RDI, qword ptr [RBP + -0x40]
0x2d4f69: MOVZX R9D, AX
0x2d4f6d: MOV RSI, R12
0x2d4f70: MOV RDX, R15
0x2d4f73: MOV qword ptr [RBP + -0x48], R8
0x2d4f77: BEXTR ECX, dword ptr [RBX + 0x140], ECX
0x2d4f80: MOV dword ptr [RBP + -0x34], R9D
0x2d4f84: MOV dword ptr [RSP], ECX
0x2d4f87: MOV RCX, R13
0x2d4f8a: CALL 0x008e46d0
0x2d4f8f: TEST byte ptr [RBX + 0x62], 0x2
0x2d4f93: JZ 0x002d4ea0
0x2d4f99: CMP dword ptr [RBX + 0x6c], 0x0
0x2d4f9d: JNZ 0x002d4ea0
0x2d4fa3: JMP 0x002d4eba
0x2d4fa8: ADD RSP, 0x28
0x2d4fac: POP RBX
0x2d4fad: POP R12
0x2d4faf: POP R13
0x2d4fb1: POP R14
0x2d4fb3: POP R15
0x2d4fb5: POP RBP
0x2d4fb6: RET


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d4fc0 RVA 0x2d4fc0 | Evidence ev_09d0b31bd1a98cc82d3daef4669ae4b4a65b992e6280806171fc6e5f19c5ed6b | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d4fc0:
0x2d4fc0: PUSH RBP
0x2d4fc1: MOV RBP, RSP
0x2d4fc4: PUSH R15
0x2d4fc6: PUSH R14
0x2d4fc8: PUSH R13
0x2d4fca: PUSH R12
0x2d4fcc: PUSH RBX
0x2d4fcd: SUB RSP, 0x38
0x2d4fd1: LEA RAX, [0x391c310]
0x2d4fd8: MOV dword ptr [RBP + -0x3c], EDI
0x2d4fdb: LEA RDI, [0x3589e60]
0x2d4fe2: XOR ESI, ESI
0x2d4fe4: XOR EDX, EDX
0x2d4fe6: XOR ECX, ECX
0x2d4fe8: MOV RAX, qword ptr [RAX]
0x2d4feb: MOV qword ptr [RBP + -0x30], RAX
0x2d4fef: CALL 0x00c4b350
0x2d4ff4: MOV R14, qword ptr [0x03589e80]
0x2d4ffb: TEST R14, R14
0x2d4ffe: JZ 0x002d52dd
0x2d5004: LEA RBX, [0x3589e60]
0x2d500b: JMP 0x002d502a
0x2d5010: MOV RDI, R12
0x2d5013: XOR ESI, ESI
0x2d5015: XOR EDX, EDX
0x2d5017: XOR ECX, ECX
0x2d5019: CALL 0x004c6fa0
0x2d501e: MOV R14, qword ptr [R14]
0x2d5021: TEST R14, R14
0x2d5024: JZ 0x002d52dd
0x2d502a: LEA R12, [R14 + 0x148]
0x2d5031: XOR ESI, ESI
0x2d5033: XOR EDX, EDX
0x2d5035: XOR ECX, ECX
0x2d5037: MOV RDI, R12
0x2d503a: CALL 0x004c6a00
0x2d503f: MOV EAX, dword ptr [RBP + -0x3c]
0x2d5042: CMP dword ptr [R14 + 0x5c0], EAX
0x2d5049: JZ 0x002d5010
0x2d504b: MOV EAX, dword ptr [R14 + 0xb0]
0x2d5052: TEST EAX, 0x2000
0x2d5057: JNZ 0x002d5010
0x2d5059: INC dword ptr [R14 + 0x358]
0x2d5060: TEST EAX, 0x10000000
0x2d5065: JNZ 0x002d506f
0x2d5067: MOV RDI, R14
0x2d506a: CALL 0x0053aa10
0x2d506f: MOV RDI, R12
0x2d5072: XOR ESI, ESI
0x2d5074: XOR EDX, EDX
0x2d5076: XOR ECX, ECX
0x2d5078: CALL 0x004c6fa0
0x2d507d: MOV RDI, RBX
0x2d5080: XOR ESI, ESI
0x2d5082: XOR EDX, EDX
0x2d5084: CALL 0x00c4c300
0x2d5089: MOV R15, qword ptr [R14 + 0x200]
0x2d5090: MOV qword ptr [RBP + -0x48], R12
0x2d5094: MOVZX EAX, byte ptr [R15 + 0x244]
0x2d509c: TEST AL, 0x10
0x2d509e: JNZ 0x002d50c9
0x2d50a0: TEST AL, 0x8
0x2d50a2: JZ 0x002d50b5
0x2d50a4: MOV RAX, qword ptr GS:[0x0]
0x2d50ad: ADD.LOCK dword ptr [RAX + 0x5a8], 0x1
0x2d50b5: LEA RDI, [R15 + 0x170]
0x2d50bc: XOR ESI, ESI
0x2d50be: XOR EDX, EDX
0x2d50c0: XOR ECX, ECX
0x2d50c2: CALL 0x00c4bb20
0x2d50c7: JMP 0x002d50db
0x2d50c9: LEA RDI, [R15 + 0x1a8]
0x2d50d0: XOR ESI, ESI
0x2d50d2: XOR EDX, EDX
0x2d50d4: XOR ECX, ECX
0x2d50d6: CALL 0x004c6a00
0x2d50db: INC dword ptr [R15 + 0x1c0]
0x2d50e2: ADD.LOCK dword ptr [R15 + 0x1c4], 0x1
0x2d50eb: MOV RBX, qword ptr [R15 + 0x8]
0x2d50ef: MOV qword ptr [RBP + -0x38], RBX
0x2d50f3: CMP RBX, R15
0x2d50f6: JZ 0x002d5270
0x2d50fc: LEA RAX, [R15 + 0x1a8]
0x2d5103: LEA RCX, [R15 + 0x170]
0x2d510a: MOV qword ptr [RBP + -0x58], RAX
0x2d510e: MOV qword ptr [RBP + -0x50], RCX
0x2d5112: JMP 0x002d5131
0x2d5120: MOV RBX, qword ptr [RBX + 0x8]
0x2d5124: MOV qword ptr [RBP + -0x38], RBX
0x2d5128: CMP RBX, R15
0x2d512b: JZ 0x002d5270
0x2d5131: MOV EAX, dword ptr [RBX + 0x60]
0x2d5134: TEST EAX, 0x40100
0x2d5139: JZ 0x002d51e6
0x2d513f: OR EAX, 0x200
0x2d5144: MOV RDI, R15
0x2d5147: XOR ESI, ESI
0x2d5149: XOR EDX, EDX
0x2d514b: XOR ECX, ECX
0x2d514d: MOV dword ptr [RBX + 0x60], EAX
0x2d5150: MOV R12, qword ptr [RBX + 0x20]
0x2d5154: MOV R13D, dword ptr [R15 + 0x1c0]
0x2d515b: CALL 0x002c6d80
0x2d5160: MOVZX EAX, byte ptr [R15 + 0x244]
0x2d5168: TEST AL, 0x10
0x2d516a: JNZ 0x002d51a0
0x2d516c: TEST AL, 0x8
0x2d516e: JZ 0x002d5181
0x2d5170: MOV RAX, qword ptr GS:[0x0]
0x2d5179: ADD.LOCK dword ptr [RAX + 0x5a8], 0x1
0x2d5181: MOV RDI, qword ptr [RBP + -0x50]
0x2d5185: XOR ESI, ESI
0x2d5187: XOR EDX, EDX
0x2d5189: XOR ECX, ECX
0x2d518b: CALL 0x00c4bb20
0x2d5190: JMP 0x002d51af
0x2d51a0: MOV RDI, qword ptr [RBP + -0x58]
0x2d51a4: XOR ESI, ESI
0x2d51a6: XOR EDX, EDX
0x2d51a8: XOR ECX, ECX
0x2d51aa: CALL 0x004c6a00
0x2d51af: INC dword ptr [R15 + 0x1c0]
0x2d51b6: INC R13D
0x2d51b9: ADD.LOCK dword ptr [R15 + 0x1c4], 0x1
0x2d51c2: CMP R13D, dword ptr [R15 + 0x1c0]
0x2d51c9: JZ 0x002d51e6
0x2d51cb: MOV RDI, R15
0x2d51ce: MOV RSI, R12
0x2d51d1: LEA RDX, [RBP + -0x38]
0x2d51d5: CALL 0x002c6c40
0x2d51da: MOV RBX, qword ptr [RBP + -0x38]
0x2d51de: TEST EAX, EAX
0x2d51e0: JZ 0x002d5120
0x2d51e6: CMP dword ptr [RBX + 0x6c], 0x0
0x2d51ea: JZ 0x002d5120
0x2d51f0: MOV R12, qword ptr [RBX + 0x50]
0x2d51f4: TEST R12, R12
0x2d51f7: JZ 0x002d5120
0x2d51fd: MOVZX EAX, byte ptr [R12 + 0x150]
0x2d5206: CMP dword ptr [RBP + -0x3c], EAX
0x2d5209: JNZ 0x002d5120
0x2d520f: MOVZX EAX, word ptr [RBX + 0x64]
0x2d5213: TEST EAX, 0x3c7
0x2d5218: JZ 0x002d5120
0x2d521e: MOV RDI, qword ptr [R15 + 0x1d8]
0x2d5225: MOV RSI, qword ptr [RBX + 0x20]
0x2d5229: MOV RDX, qword ptr [RBX + 0x28]
0x2d522d: CALL 0x008df6a0
0x2d5232: MOV EAX, 0x103
0x2d5237: MOV RDI, qword ptr [R15 + 0x1d8]
0x2d523e: MOV RSI, qword ptr [RBX + 0x20]
0x2d5242: MOV RDX, qword ptr [RBX + 0x28]
0x2d5246: MOV R8, qword ptr [RBX + 0x58]
0x2d524a: MOVZX R9D, word ptr [RBX + 0x64]
0x2d524f: MOV RCX, R12
0x2d5252: BEXTR EAX, dword ptr [RBX + 0x140], EAX
0x2d525b: MOV dword ptr [RSP], EAX
0x2d525e: CALL 0x008e46d0
0x2d5263: JMP 0x002d5120
0x2d5270: MOV RDI, R15
0x2d5273: XOR ESI, ESI
0x2d5275: XOR EDX, EDX
0x2d5277: CALL 0x002c64f0
0x2d527c: LEA RBX, [0x3589e60]
0x2d5283: XOR ESI, ESI
0x2d5285: XOR EDX, EDX
0x2d5287: XOR ECX, ECX
0x2d5289: MOV RDI, RBX
0x2d528c: CALL 0x00c4b350
0x2d5291: MOV R12, qword ptr [RBP + -0x48]
0x2d5295: XOR ESI, ESI
0x2d5297: XOR EDX, EDX
0x2d5299: XOR ECX, ECX
0x2d529b: MOV RDI, R12
0x2d529e: CALL 0x004c6a00
0x2d52a3: MOVZX ECX, byte ptr [R14 + 0xb1]
0x2d52ab: MOV EAX, dword ptr [R14 + 0x358]
0x2d52b2: SHR CL, 0x5
0x2d52b5: DEC EAX
0x2d52b7: SETZ DL
0x2d52ba: MOV dword ptr [R14 + 0x358], EAX
0x2d52c1: AND DL, CL
0x2d52c3: CMP DL, 0x1
0x2d52c6: JNZ 0x002d5010
0x2d52cc: LEA RDI, [R14 + 0x358]
0x2d52d3: CALL 0x00c06910
0x2d52d8: JMP 0x002d5010
0x2d52dd: LEA RAX, [0x391c310]
0x2d52e4: MOV RAX, qword ptr [RAX]
0x2d52e7: CMP RAX, qword ptr [RBP + -0x30]
0x2d52eb: JNZ 0x002d530b
0x2d52ed: LEA RDI, [0x3589e60]
0x2d52f4: XOR ESI, ESI
0x2d52f6: XOR EDX, EDX
0x2d52f8: ADD RSP, 0x38
0x2d52fc: POP RBX
0x2d52fd: POP R12
0x2d52ff: POP R13
0x2d5301: POP R14
0x2d5303: POP R15
0x2d5305: POP RBP
0x2d5306: JMP 0x00c4c300
0x2d530b: CALL 0x006fd6b0
0x2d5310: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d5320 RVA 0x2d5320 | Evidence ev_8343c217c4f601487030ba31cdf680c48366ed0db5256edcf6fa2d6fdb2da36e | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d5320:
0x2d5320: PUSH RBP
0x2d5321: MOV RBP, RSP
0x2d5324: PUSH R15
0x2d5326: PUSH R14
0x2d5328: PUSH R13
0x2d532a: PUSH R12
0x2d532c: PUSH RBX
0x2d532d: SUB RSP, 0x78
0x2d5331: MOV RAX, qword ptr [RDI + 0x10]
0x2d5335: MOV qword ptr [RBP + -0x40], R8
0x2d5339: MOV R8, RCX
0x2d533c: MOV RBX, RDX
0x2d533f: MOV R15, RSI
0x2d5342: MOV qword ptr [RBP + -0x78], RDI
0x2d5346: MOV qword ptr [RBP + -0x70], RAX
0x2d534a: MOV RAX, RCX
0x2d534d: SUB RAX, qword ptr [RDX + 0x20]
0x2d5351: CMP qword ptr [RDX + 0x50], 0x0
0x2d5356: JZ 0x002d535e
0x2d5358: MOV RCX, qword ptr [RBX + 0x58]
0x2d535c: JMP 0x002d5360
0x2d535e: XOR ECX, ECX
0x2d5360: MOV RDX, qword ptr [RBP + -0x78]
0x2d5364: MOV RDI, qword ptr [RBP + -0x70]
0x2d5368: ADD RAX, RCX
0x2d536b: MOV RSI, qword ptr [RBP + -0x40]
0x2d536f: MOV RCX, qword ptr [RDI + 0x40]
0x2d5373: MOV RDX, qword ptr [RDX + 0x30]
0x2d5377: MOV qword ptr [RBP + -0x68], RCX
0x2d537b: LEA RCX, [RDX + -0x1]
0x2d537f: AND RCX, RAX
0x2d5382: SUB R8, RCX
0x2d5385: ADD RDX, R8
0x2d5388: MOV qword ptr [RBP + -0x38], R8
0x2d538c: MOV qword ptr [RBP + -0x48], RDX
0x2d5390: CALL 0x003c36b0
0x2d5395: MOV R14, qword ptr [RBP + -0x38]
0x2d5399: MOV qword ptr [RBP + -0x50], RAX
0x2d539d: NOP dword ptr [RAX]
0x2d53a0: MOV R12, RBX
0x2d53a3: MOV RBX, qword ptr [RBX]
0x2d53a6: CMP RBX, R15
0x2d53a9: JZ 0x002d53b1
0x2d53ab: CMP R14, qword ptr [RBX + 0x28]
0x2d53af: JC 0x002d53a0
0x2d53b1: MOV R13, qword ptr [RBP + -0x48]
0x2d53b5: MOV RDI, R15
0x2d53b8: MOV RSI, R14
0x2d53bb: MOV RCX, RBX
0x2d53be: MOV RDX, R13
0x2d53c1: CALL 0x002c76c0
0x2d53c6: TEST EAX, EAX
0x2d53c8: JNZ 0x002d569d
0x2d53ce: MOV RDI, qword ptr [RBP + -0x68]
0x2d53d2: MOV R8, qword ptr [RBP + -0x40]
0x2d53d6: MOV RSI, R15
0x2d53d9: MOV RDX, R14
0x2d53dc: MOV RCX, R13
0x2d53df: CALL 0x00500bb0
0x2d53e4: MOV RDX, R14
0x2d53e7: CMP R14, qword ptr [R12 + 0x20]
0x2d53ec: JBE 0x002d53fd
0x2d53ee: MOV RDI, R15
0x2d53f1: MOV RSI, R12
0x2d53f4: CALL 0x002cb4e0
0x2d53f9: MOV RDX, qword ptr [RBP + -0x38]
0x2d53fd: MOV R14, qword ptr [RBP + -0x48]
0x2d5401: MOV qword ptr [RBP + -0x88], R15
0x2d5408: NOP dword ptr [RAX + RAX*0x1]
0x2d5410: MOV RAX, qword ptr [R12 + 0x28]
0x2d5415: MOV R13, R14
0x2d5418: MOV qword ptr [RBP + -0x38], RDX
0x2d541c: MOV qword ptr [RBP + -0x90], RAX
0x2d5423: CMP RAX, R14
0x2d5426: CMOVC R13, RAX
0x2d542a: JBE 0x002d543e
0x2d542c: MOV RDI, R15
0x2d542f: MOV RSI, R12
0x2d5432: MOV RDX, R14
0x2d5435: CALL 0x002cb770
0x2d543a: MOV RDX, qword ptr [RBP + -0x38]
0x2d543e: MOV ECX, dword ptr [R12 + 0x144]
0x2d5446: MOVZX EBX, word ptr [R12 + 0x148]
0x2d544f: MOV RAX, R13
0x2d5452: MOV RDI, R15
0x2d5455: MOV R14, RDX
0x2d5458: SUB RAX, RDX
0x2d545b: MOV qword ptr [RBP + -0x58], RAX
0x2d545f: MOV dword ptr [RBP + -0x5c], ECX
0x2d5462: MOV dword ptr [RBP + -0x2c], EBX
0x2d5465: CALL 0x002c7210
0x2d546a: MOV qword ptr [RAX + 0x20], R14
0x2d546e: MOV qword ptr [RAX + 0x28], R13
0x2d5472: MOV qword ptr [RAX + 0x70], 0x0
0x2d547a: MOV R15, RAX
0x2d547d: MOV ECX, 0x800000
0x2d5482: LEA RDI, [R12 + 0x150]
0x2d548a: MOV EDX, 0x20
0x2d548f: MOV qword ptr [RBP + -0x80], R13
0x2d5493: MOV EAX, dword ptr [R12 + 0x60]
0x2d5498: LEA RSI, [R15 + 0x150]
0x2d549f: AND EAX, ECX
0x2d54a1: MOV RCX, qword ptr [RBP + -0x68]
0x2d54a5: OR EAX, 0x100000
0x2d54aa: MOV dword ptr [R15 + 0x60], EAX
0x2d54ae: MOV RAX, qword ptr [RBP + -0x40]
0x2d54b2: MOV qword ptr [R15 + 0x50], RCX
0x2d54b6: MOV qword ptr [R15 + 0x58], RAX
0x2d54ba: MOV qword ptr [R15 + 0x30], 0x0
0x2d54c2: MOV word ptr [R15 + 0x64], BX
0x2d54c7: MOV dword ptr [R15 + 0x66], 0x30203f3
0x2d54cf: MOV dword ptr [R15 + 0x6c], 0x0
0x2d54d7: MOV qword ptr [R15 + 0x78], 0x0
0x2d54df: MOV qword ptr [R15 + 0x38], R14
0x2d54e3: MOVZX EAX, byte ptr [R12 + 0x14c]
0x2d54ec: MOV byte ptr [R15 + 0x14c], AL
0x2d54f3: MOVZX EAX, byte ptr [R12 + 0x14d]
0x2d54fc: MOV byte ptr [R15 + 0x14d], AL
0x2d5503: CALL 0x00259be0
0x2d5508: MOVZX EAX, byte ptr [R12 + 0x14e]
0x2d5511: MOV RBX, qword ptr [RBP + -0x78]
0x2d5515: MOV R13D, dword ptr [RBP + -0x5c]
0x2d5519: MOV byte ptr [R15 + 0x14e], AL
0x2d5520: MOV RAX, qword ptr [R12 + 0x130]
0x2d5528: MOV qword ptr [R15 + 0x130], RAX
0x2d552f: MOV EAX, dword ptr [RBP + -0x2c]
0x2d5532: MOV qword ptr [R15 + 0x120], 0x0
0x2d553d: MOV qword ptr [R15 + 0x128], RBX
0x2d5544: MOV dword ptr [R15 + 0x144], R13D
0x2d554b: MOV word ptr [R15 + 0x148], AX
0x2d5553: MOV RAX, qword ptr [R12 + 0x138]
0x2d555b: MOV qword ptr [R15 + 0x138], RAX
0x2d5562: MOV dword ptr [R15 + 0x140], 0x0
0x2d556d: MOV RDI, qword ptr [R15 + 0x50]
0x2d5571: CALL 0x00461b20
0x2d5576: MOV R14, qword ptr [RBP + -0x70]
0x2d557a: MOV RDI, R14
0x2d557d: CALL 0x003c3430
0x2d5582: MOV RDI, RBX
0x2d5585: CALL 0x003c9f70
0x2d558a: MOV RDI, R14
0x2d558d: MOV R14D, R13D
0x2d5590: MOV R13, qword ptr [RBP + -0x88]
0x2d5597: CALL 0x003c3580
0x2d559c: MOV RBX, qword ptr [R12]
0x2d55a0: MOV RSI, R12
0x2d55a3: MOV R12D, dword ptr [RBP + -0x2c]
0x2d55a7: MOV RDI, R13
0x2d55aa: CALL 0x002cfe30
0x2d55af: MOV RDI, R13
0x2d55b2: MOV RSI, RBX
0x2d55b5: MOV RDX, R15
0x2d55b8: CALL 0x002c72e0
0x2d55bd: MOV RAX, qword ptr [RBP + -0x58]
0x2d55c1: ADD qword ptr [R13 + 0x1b8], RAX
0x2d55c8: TEST R12D, 0x3c7
0x2d55cf: JZ 0x002d55fa
0x2d55d1: MOV RBX, qword ptr [R13 + 0x1d8]
0x2d55d8: MOV EDI, R14D
0x2d55db: CALL 0x002d56e0
0x2d55e0: MOV RSI, qword ptr [RBP + -0x38]
0x2d55e4: MOV RDX, qword ptr [RBP + -0x80]
0x2d55e8: MOV RCX, qword ptr [RBP + -0x50]
0x2d55ec: MOV RDI, RBX
0x2d55ef: MOV R8D, R12D
0x2d55f2: MOV R9D, EAX
0x2d55f5: CALL 0x008ed820
0x2d55fa: MOV EDI, R14D
0x2d55fd: MOV RBX, qword ptr [RBP + -0x40]
0x2d5601: MOV R14, qword ptr [RBP + -0x48]
0x2d5605: AND R12D, 0x30
0x2d5609: JZ 0x002d564f
0x2d560b: MOV dword ptr [RBP + -0x2c], R12D
0x2d560f: CALL 0x002d5730
0x2d5614: MOV RCX, qword ptr [0x01a962e8]
0x2d561b: MOV R12, qword ptr [RCX + 0x10]
0x2d561f: LEA RCX, [0x26e8d0]
0x2d5626: CMP R12, RCX
0x2d5629: JNZ 0x002d5682
0x2d562b: MOV RSI, qword ptr [RBP + -0x38]
0x2d562f: MOV RDX, qword ptr [RBP + -0x58]
0x2d5633: MOV RCX, qword ptr [RBP + -0x50]
0x2d5637: MOV R8D, dword ptr [RBP + -0x2c]
0x2d563b: MOV RDI, R13
0x2d563e: MOV R9D, EAX
0x2d5641: MOV dword ptr [RSP], 0x1
0x2d5648: CALL R12
0x2d564b: TEST EAX, EAX
0x2d564d: JNZ 0x002d56ac
0x2d564f: MOV RDI, R13
0x2d5652: MOV RSI, R15
0x2d5655: CALL 0x002c8910
0x2d565a: CMP R14, qword ptr [RBP + -0x90]
0x2d5661: JBE 0x002d569b
0x2d5663: MOV RAX, qword ptr [RBP + -0x58]
0x2d5667: MOV R12, qword ptr [R15 + 0x8]
0x2d566b: MOV RDX, qword ptr [RBP + -0x80]
0x2d566f: MOV R15, R13
0x2d5672: ADD qword ptr [RBP + -0x50], RAX
0x2d5676: ADD RBX, RAX
0x2d5679: MOV qword ptr [RBP + -0x40], RBX
0x2d567d: JMP 0x002d5410
0x2d5682: LEA RDI, [0x1a96110]
0x2d5689: MOV RSI, R12
0x2d568c: MOV EBX, EAX
0x2d568e: CALL 0x0044f8c0
0x2d5693: MOV EAX, EBX
0x2d5695: MOV RBX, qword ptr [RBP + -0x40]
0x2d5699: JMP 0x002d562b
0x2d569b: XOR EAX, EAX
0x2d569d: ADD RSP, 0x78
0x2d56a1: POP RBX
0x2d56a2: POP R12
0x2d56a4: POP R13
0x2d56a6: POP R14
0x2d56a8: POP R15
0x2d56aa: POP RBP
0x2d56ab: RET
0x2d56ac: MOV EBX, EAX
0x2d56ae: CALL 0x007f1950
0x2d56b3: MOVSXD RSI, EBX
0x2d56b6: LEA RDI, [0x2d56ac]
0x2d56bd: CALL 0x007f18a0
0x2d56c2: LEA RSI, [0x13105fe]
0x2d56c9: MOV EDI, 0xab
0x2d56ce: MOV EDX, EBX
0x2d56d0: XOR EAX, EAX
0x2d56d2: CALL 0x00c9aa10
0x2d56d7: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): FUN_002d56e0 RVA 0x2d56e0 | Evidence ev_6d833c36a197c0d32ffa042efe81992ae13850a82fdfa82ab6d6ff7e78a1600b | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
FUN_002d56e0:
0x2d56e0: CMP EDI, 0x15
0x2d56e3: JNC 0x002d56f2
0x2d56e5: MOV EAX, EDI
0x2d56e7: LEA RCX, [0x13bc1c0]
0x2d56ee: MOV EAX, dword ptr [RCX + RAX*0x4]
0x2d56f1: RET


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d56f2 RVA 0x2d56f2 | Evidence ev_7d6cab91e99dfc940c8937bfe07fbdd343edfc55b9cddc9cb7acbc0de2996956 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d56f2:
0x2d56f2: PUSH RBP
0x2d56f3: MOV RBP, RSP
0x2d56f6: PUSH RBX
0x2d56f7: PUSH RAX
0x2d56f8: MOV EBX, EDI
0x2d56fa: CALL 0x007f1950
0x2d56ff: MOVSXD RSI, EBX
0x2d5702: LEA RDI, [0x2d56f2]
0x2d5709: CALL 0x007f18a0
0x2d570e: LEA RSI, [0x12947a2]
0x2d5715: MOV EDI, 0x3
0x2d571a: MOV EDX, EBX
0x2d571c: XOR EAX, EAX
0x2d571e: CALL 0x00c9aa10
0x2d5723: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): FUN_002d5730 RVA 0x2d5730 | Evidence ev_b9335666faf917a183babd4a97968ac2ba006f30965ab5e474b6909a91faa08e | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
FUN_002d5730:
0x2d5730: CMP EDI, 0x15
0x2d5733: JNC 0x002d5742
0x2d5735: MOV EAX, EDI
0x2d5737: LEA RCX, [0x13bc214]
0x2d573e: MOV EAX, dword ptr [RCX + RAX*0x4]
0x2d5741: RET


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d5742 RVA 0x2d5742 | Evidence ev_914d4b46a47fc331021e4b9b22fd0923dc88138d471e36e90a48f8d878352571 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d5742:
0x2d5742: PUSH RBP
0x2d5743: MOV RBP, RSP
0x2d5746: PUSH RBX
0x2d5747: PUSH RAX
0x2d5748: MOV EBX, EDI
0x2d574a: CALL 0x007f1950
0x2d574f: MOVSXD RSI, EBX
0x2d5752: LEA RDI, [0x2d5742]
0x2d5759: CALL 0x007f18a0
0x2d575e: LEA RSI, [0x12947a2]
0x2d5765: MOV EDI, 0xb
0x2d576a: MOV EDX, EBX
0x2d576c: XOR EAX, EAX
0x2d576e: CALL 0x00c9aa10
0x2d5773: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d5780 RVA 0x2d5780 | Evidence ev_122e9a6b1364a98c1ff890f55070d427d6f651ec5f813fac7b8588b389a4a1c3 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d5780:
0x2d5780: PUSH RBP
0x2d5781: MOV RBP, RSP
0x2d5784: PUSH R15
0x2d5786: PUSH R14
0x2d5788: PUSH R13
0x2d578a: PUSH R12
0x2d578c: PUSH RBX
0x2d578d: SUB RSP, 0x78
0x2d5791: LEA RAX, [0x391c310]
0x2d5798: MOV qword ptr [RBP + -0x70], RDX
0x2d579c: MOV R12, RSI
0x2d579f: MOV RBX, RDI
0x2d57a2: MOV RAX, qword ptr [RAX]
0x2d57a5: MOV qword ptr [RBP + -0x30], RAX
0x2d57a9: MOVZX EAX, byte ptr [RDI + 0x244]
0x2d57b0: TEST AL, 0x10
0x2d57b2: JNZ 0x002d57dd
0x2d57b4: TEST AL, 0x8
0x2d57b6: JZ 0x002d57c9
0x2d57b8: MOV RAX, qword ptr GS:[0x0]
0x2d57c1: ADD.LOCK dword ptr [RAX + 0x5a8], 0x1
0x2d57c9: LEA RDI, [RBX + 0x170]
0x2d57d0: XOR ESI, ESI
0x2d57d2: XOR EDX, EDX
0x2d57d4: XOR ECX, ECX
0x2d57d6: CALL 0x00c4bb20
0x2d57db: JMP 0x002d57ef
0x2d57dd: LEA RDI, [RBX + 0x1a8]
0x2d57e4: XOR ESI, ESI
0x2d57e6: XOR EDX, EDX
0x2d57e8: XOR ECX, ECX
0x2d57ea: CALL 0x004c6a00
0x2d57ef: INC dword ptr [RBX + 0x1c0]
0x2d57f5: LEA RDX, [RBP + -0x60]
0x2d57f9: MOV RDI, RBX
0x2d57fc: MOV RSI, R12
0x2d57ff: ADD.LOCK dword ptr [RBX + 0x1c4], 0x1
0x2d5807: CALL 0x002c6c40
0x2d580c: MOV R15, qword ptr [RBP + -0x60]
0x2d5810: TEST EAX, EAX
0x2d5812: JNZ 0x002d581c
0x2d5814: MOV R15, qword ptr [R15 + 0x8]
0x2d5818: MOV qword ptr [RBP + -0x60], R15
0x2d581c: MOV R8, qword ptr [RBP + -0x70]
0x2d5820: CMP R15, RBX
0x2d5823: JZ 0x002d5a3b
0x2d5829: MOV RAX, R15
0x2d582c: JMP 0x002d5839
0x2d5830: MOV RAX, qword ptr [RAX + 0x8]
0x2d5834: CMP RAX, RBX
0x2d5837: JZ 0x002d589d
0x2d5839: MOV RDX, qword ptr [RAX + 0x20]
0x2d583d: MOV RCX, R8
0x2d5840: SUB RCX, RDX
0x2d5843: JBE 0x002d589d
0x2d5845: MOV RSI, qword ptr [RAX + 0x128]
0x2d584c: TEST RSI, RSI
0x2d584f: JZ 0x002d5830
0x2d5851: MOV RDI, qword ptr [RAX + 0x50]
0x2d5855: TEST RDI, RDI
0x2d5858: JZ 0x002d5830
0x2d585a: TEST byte ptr [RDI + 0xa2], 0x1
0x2d5861: JZ 0x002d5830
0x2d5863: MOV RSI, qword ptr [RSI + 0x30]
0x2d5867: MOV RDI, R12
0x2d586a: SUB RDI, RDX
0x2d586d: JBE 0x002d5878
0x2d586f: LEA RDX, [RSI + -0x1]
0x2d5873: TEST RDX, RDI
0x2d5876: JNZ 0x002d5886
0x2d5878: CMP R8, qword ptr [RAX + 0x28]
0x2d587c: JNC 0x002d5830
0x2d587e: DEC RSI
0x2d5881: TEST RSI, RCX
0x2d5884: JZ 0x002d5830
0x2d5886: MOV RDI, RBX
0x2d5889: XOR ESI, ESI
0x2d588b: XOR EDX, EDX
0x2d588d: CALL 0x002c64f0
0x2d5892: MOV R14D, 0x1
0x2d5898: JMP 0x002d5a4a
0x2d589d: MOV qword ptr [RBP + -0x58], R15
0x2d58a1: MOV qword ptr [RBP + -0x78], RBX
0x2d58a5: JMP 0x002d58e1
0x2d58a7: LEA RSI, [R15 + 0x150]
0x2d58ae: MOV EDX, 0x20
0x2d58b3: LEA RDI, [RBP + -0x50]
0x2d58b7: CALL 0x00259be0
0x2d58bc: MOV RDI, RBX
0x2d58bf: MOV RSI, R15
0x2d58c2: CALL 0x002c8910
0x2d58c7: MOV R8, qword ptr [RBP + -0x70]
0x2d58cb: NOP dword ptr [RAX + RAX*0x1]
0x2d58d0: MOV R15, qword ptr [R15 + 0x8]
0x2d58d4: MOV qword ptr [RBP + -0x58], R15
0x2d58d8: CMP R15, RBX
0x2d58db: JZ 0x002d5a3b
0x2d58e1: MOV R13, qword ptr [R15 + 0x20]
0x2d58e5: CMP R13, R8
0x2d58e8: JNC 0x002d5a3b
0x2d58ee: MOV R14, qword ptr [R15 + 0x128]
0x2d58f5: TEST R14, R14
0x2d58f8: JZ 0x002d58d0
0x2d58fa: MOV RAX, qword ptr [R15 + 0x50]
0x2d58fe: TEST RAX, RAX
0x2d5901: JZ 0x002d58d0
0x2d5903: TEST byte ptr [RAX + 0xa2], 0x1
0x2d590a: JZ 0x002d58d0
0x2d590c: MOV RAX, qword ptr [R14 + 0x10]
0x2d5910: MOV R12D, dword ptr [R15 + 0x60]
0x2d5914: MOV RCX, qword ptr [R15 + 0x130]
0x2d591b: MOV RBX, qword ptr [R15 + 0x28]
0x2d591f: MOV EDX, 0x20
0x2d5924: LEA RSI, [RBP + -0x50]
0x2d5928: MOV qword ptr [RBP + -0x68], RAX
0x2d592c: MOV EAX, dword ptr [R15 + 0x144]
0x2d5933: SHR R12D, 0x5
0x2d5937: MOV qword ptr [RBP + -0x98], RCX
0x2d593e: AND R12D, 0x40000
0x2d5945: INC R12D
0x2d5948: MOV qword ptr [RBP + -0x88], RAX
0x2d594f: MOVZX EAX, word ptr [R15 + 0x148]
0x2d5957: MOV qword ptr [RBP + -0x80], RAX
0x2d595b: MOV EAX, dword ptr [R15 + 0x138]
0x2d5962: ADD R15, 0x150
0x2d5969: MOV RDI, R15
0x2d596c: MOV qword ptr [RBP + -0x90], RAX
0x2d5973: CALL 0x00259be0
0x2d5978: MOV R15, qword ptr [RBP + -0x68]
0x2d597c: MOV RDI, R15
0x2d597f: CALL 0x003c3430
0x2d5984: MOV RDI, R14
0x2d5987: CALL 0x003c9f70
0x2d598c: MOV RDI, R15
0x2d598f: CALL 0x003c3580
0x2d5994: MOV RDI, qword ptr [RBP + -0x78]
0x2d5998: MOV RSI, R13
0x2d599b: MOV RDX, RBX
0x2d599e: CALL 0x002c9370
0x2d59a3: SUB RSP, 0x8
0x2d59a7: MOV qword ptr [RBP + -0x68], RBX
0x2d59ab: MOV R8, RBX
0x2d59ae: MOV RBX, qword ptr [RBP + -0x78]
0x2d59b2: MOV RDI, qword ptr [RBP + -0x78]
0x2d59b6: XOR ESI, ESI
0x2d59b8: XOR EDX, EDX
0x2d59ba: MOV RCX, R13
0x2d59bd: XOR R9D, R9D
0x2d59c0: PUSH qword ptr [RBP + -0x80]
0x2d59c3: PUSH qword ptr [RBP + -0x88]
0x2d59c9: PUSH R14
0x2d59cb: PUSH qword ptr [RBP + -0x90]
0x2d59d1: PUSH qword ptr [RBP + -0x98]
0x2d59d7: PUSH R12
0x2d59d9: PUSH 0x0
0x2d59db: CALL 0x002c79f0
0x2d59e0: ADD RSP, 0x40
0x2d59e4: MOV RDI, RBX
0x2d59e7: MOV RSI, R13
0x2d59ea: LEA RDX, [RBP + -0x58]
0x2d59ee: CALL 0x002c6c40
0x2d59f3: TEST EAX, EAX
0x2d59f5: JZ 0x002d5a6c
0x2d59f7: CMP byte ptr [RBP + -0x50], 0x0
0x2d59fb: MOV R15, qword ptr [RBP + -0x58]
0x2d59ff: MOV R8, qword ptr [RBP + -0x70]
0x2d5a03: JZ 0x002d58d0
0x2d5a09: CMP R13, qword ptr [R15 + 0x20]
0x2d5a0d: JBE 0x002d5a1d
0x2d5a0f: MOV RDI, RBX
0x2d5a12: MOV RSI, R15
0x2d5a15: MOV RDX, R13
0x2d5a18: CALL 0x002cb4e0
0x2d5a1d: MOV RDX, qword ptr [RBP + -0x68]
0x2d5a21: CMP RDX, qword ptr [R15 + 0x28]
0x2d5a25: JNC 0x002d58a7
0x2d5a2b: MOV RDI, RBX
0x2d5a2e: MOV RSI, R15
0x2d5a31: CALL 0x002cb770
0x2d5a36: JMP 0x002d58a7
0x2d5a3b: MOV RDI, RBX
0x2d5a3e: XOR R14D, R14D
0x2d5a41: XOR ESI, ESI
0x2d5a43: XOR EDX, EDX
0x2d5a45: CALL 0x002c64f0
0x2d5a4a: LEA RAX, [0x391c310]
0x2d5a51: MOV RAX, qword ptr [RAX]
0x2d5a54: CMP RAX, qword ptr [RBP + -0x30]
0x2d5a58: JNZ 0x002d5aa2
0x2d5a5a: MOV EAX, R14D
0x2d5a5d: ADD RSP, 0x78
0x2d5a61: POP RBX
0x2d5a62: POP R12
0x2d5a64: POP R13
0x2d5a66: POP R14
0x2d5a68: POP R15
0x2d5a6a: POP RBP
0x2d5a6b: RET
0x2d5a6c: CALL 0x007f1950
0x2d5a71: MOV RBX, qword ptr [RBP + -0x68]
0x2d5a75: LEA RDI, [0x2d5a6c]
0x2d5a7c: MOV RSI, R13
0x2d5a7f: MOV RDX, RBX
0x2d5a82: CALL 0x007f2010
0x2d5a87: LEA RSI, [0x12b317b]
0x2d5a8e: MOV EDI, 0xaf
0x2d5a93: MOV RDX, R13
0x2d5a96: MOV RCX, RBX
0x2d5a99: XOR EAX, EAX
0x2d5a9b: CALL 0x00c9aa10
0x2d5aa0: UD2
0x2d5aa2: CALL 0x006fd6b0
0x2d5aa7: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d5ab0 RVA 0x2d5ab0 | Evidence ev_0d541ec231962c90608b58b998fcf2e645df64af0907aadbda13dc524bc57cdc | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d5ab0:
0x2d5ab0: PUSH RBP
0x2d5ab1: MOV RBP, RSP
0x2d5ab4: PUSH R14
0x2d5ab6: PUSH RBX
0x2d5ab7: MOV EBX, EDI
0x2d5ab9: LEA RDI, [0x2d60028]
0x2d5ac0: XOR ESI, ESI
0x2d5ac2: XOR EDX, EDX
0x2d5ac4: XOR ECX, ECX
0x2d5ac6: CALL 0x004c6a00
0x2d5acb: MOVSXD RAX, dword ptr [0x02d60a30]
0x2d5ad2: LEA RCX, [0x2d60030]
0x2d5ad9: LEA RAX, [RAX + RAX*0x4]
0x2d5add: SHL RAX, 0x7
0x2d5ae1: CMP dword ptr [RAX + RCX*0x1], 0x0
0x2d5ae5: LEA R14, [RCX + RAX*0x1]
0x2d5ae9: JZ 0x002d5b22
0x2d5aeb: CMP dword ptr [R14 + 0xa0], 0x0
0x2d5af3: JZ 0x002d5b12
0x2d5af5: CMP dword ptr [R14 + 0x140], 0x0
0x2d5afd: JZ 0x002d5b1b
0x2d5aff: CMP dword ptr [R14 + 0x1e0], 0x0
0x2d5b07: JNZ 0x002d5b31
0x2d5b09: ADD R14, 0x1e0
0x2d5b10: JMP 0x002d5b22
0x2d5b12: ADD R14, 0xa0
0x2d5b19: JMP 0x002d5b22
0x2d5b1b: ADD R14, 0x140
0x2d5b22: MOV RDI, R14
0x2d5b25: CALL 0x00614aa0
0x2d5b2a: MOV dword ptr [R14 + 0x98], EBX
0x2d5b31: LEA RDI, [0x2d60028]
0x2d5b38: XOR ESI, ESI
0x2d5b3a: XOR EDX, EDX
0x2d5b3c: XOR ECX, ECX
0x2d5b3e: POP RBX
0x2d5b3f: POP R14
0x2d5b41: POP RBP
0x2d5b42: JMP 0x004c6fa0


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d5b66 RVA 0x2d5b66 | Evidence ev_11d062469fb1c183627f98c99b3fbe909ab4a6303daff9c0b454dc9c0cdd431e | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d5b66:
0x2d5b66: PUSH RBP
0x2d5b67: MOV RBP, RSP
0x2d5b6a: CALL 0x00ad0990
0x2d5b6f: MOV RCX, RAX
0x2d5b72: RDTSC
0x2d5b74: MOV EAX, EAX
0x2d5b76: SHL RDX, 0x20
0x2d5b7a: OR RAX, RDX
0x2d5b7d: OR RDX, RCX
0x2d5b80: SHR RDX, 0x20
0x2d5b84: JZ 0x002d5b90
0x2d5b86: XOR EDX, EDX
0x2d5b88: DIV RCX
0x2d5b8b: MOV RSI, RAX
0x2d5b8e: JMP 0x002d5b96
0x2d5b90: XOR EDX, EDX
0x2d5b92: DIV ECX
0x2d5b94: MOV ESI, EAX
0x2d5b96: IMUL RAX, RDX, 0x3e8
0x2d5b9d: MOV RDX, RCX
0x2d5ba0: OR RDX, RAX
0x2d5ba3: SHR RDX, 0x20
0x2d5ba7: JZ 0x002d5bb0
0x2d5ba9: XOR EDX, EDX
0x2d5bab: DIV RCX
0x2d5bae: JMP 0x002d5bb4
0x2d5bb0: XOR EDX, EDX
0x2d5bb2: DIV ECX
0x2d5bb4: MOV RDX, RAX
0x2d5bb7: LEA RDI, [0x1325a28]
0x2d5bbe: XOR EAX, EAX
0x2d5bc0: CALL 0x0025d410
0x2d5bc5: POP RBP
0x2d5bc6: JMP 0x004f2230


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d5bd0 RVA 0x2d5bd0 | Evidence ev_33ca57ab0d504b4039d74554ccfa10153baaeb73a028f145e076f4710f9d3835 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d5bd0:
0x2d5bd0: PUSH RBP
0x2d5bd1: MOV RBP, RSP
0x2d5bd4: PUSH R15
0x2d5bd6: PUSH R14
0x2d5bd8: PUSH R13
0x2d5bda: PUSH R12
0x2d5bdc: PUSH RBX
0x2d5bdd: SUB RSP, 0x18
0x2d5be1: LEA R15, [0x391c310]
0x2d5be8: MOV RBX, RCX
0x2d5beb: XOR ECX, ECX
0x2d5bed: LEA R14, [0x2d58468]
0x2d5bf4: LEA R13, [0x2d58470]
0x2d5bfb: MOV RDI, R14
0x2d5bfe: MOV RAX, qword ptr [R15]
0x2d5c01: MOV qword ptr [RBP + -0x30], RAX
0x2d5c05: MOV RAX, qword ptr GS:[0x0]
0x2d5c0e: MOV RAX, qword ptr [RAX + 0x8]
0x2d5c12: MOV EAX, dword ptr [RAX + 0x5c0]
0x2d5c18: CMP EAX, 0xa
0x2d5c1b: CMOVZ EAX, ECX
0x2d5c1e: XOR ESI, ESI
0x2d5c20: XOR EDX, EDX
0x2d5c22: XOR ECX, ECX
0x2d5c24: MOVSXD R12, EAX
0x2d5c27: SHL R12, 0x6
0x2d5c2b: CALL 0x004c6a00
0x2d5c30: MOV RAX, qword ptr [R12 + R13*0x1 + 0x10]
0x2d5c35: SUB RAX, qword ptr [R12 + R13*0x1 + 0x18]
0x2d5c3a: MOV RDI, R14
0x2d5c3d: XOR ESI, ESI
0x2d5c3f: XOR EDX, EDX
0x2d5c41: XOR ECX, ECX
0x2d5c43: MOV qword ptr [RBP + -0x38], RAX
0x2d5c47: CALL 0x004c6fa0
0x2d5c4c: MOV R14, qword ptr [RBX + 0x28]
0x2d5c50: LEA RAX, [0x269338]
0x2d5c57: SUB RAX, R14
0x2d5c5a: ROR RAX, 0x3
0x2d5c5e: CMP RAX, 0x3
0x2d5c62: JA 0x002d5c8b
0x2d5c64: LEA RSI, [RBP + -0x38]
0x2d5c68: MOV EDX, 0x8
0x2d5c6d: MOV RDI, RBX
0x2d5c70: CALL R14
0x2d5c73: MOV RCX, qword ptr [R15]
0x2d5c76: CMP RCX, qword ptr [RBP + -0x30]
0x2d5c7a: JNZ 0x002d5c9c
0x2d5c7c: ADD RSP, 0x18
0x2d5c80: POP RBX
0x2d5c81: POP R12
0x2d5c83: POP R13
0x2d5c85: POP R14
0x2d5c87: POP R15
0x2d5c89: POP RBP
0x2d5c8a: RET
0x2d5c8b: LEA RDI, [0x1a961b0]
0x2d5c92: MOV RSI, R14
0x2d5c95: CALL 0x0044f8c0
0x2d5c9a: JMP 0x002d5c64
0x2d5c9c: CALL 0x006fd6b0
0x2d5ca1: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d5cb0 RVA 0x2d5cb0 | Evidence ev_c9949489b67d2628dbd69fe4f5656a21720893a6b2c5596b6107466d1efaba60 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d5cb0:
0x2d5cb0: PUSH RBP
0x2d5cb1: MOV RBP, RSP
0x2d5cb4: PUSH R15
0x2d5cb6: PUSH R14
0x2d5cb8: PUSH R13
0x2d5cba: PUSH R12
0x2d5cbc: PUSH RBX
0x2d5cbd: SUB RSP, 0x18
0x2d5cc1: LEA R15, [0x391c310]
0x2d5cc8: MOV RBX, RCX
0x2d5ccb: XOR ECX, ECX
0x2d5ccd: LEA R14, [0x2d58468]
0x2d5cd4: LEA R13, [0x2d58470]
0x2d5cdb: MOV RDI, R14
0x2d5cde: MOV RAX, qword ptr [R15]
0x2d5ce1: MOV qword ptr [RBP + -0x30], RAX
0x2d5ce5: MOV RAX, qword ptr GS:[0x0]
0x2d5cee: MOV RAX, qword ptr [RAX + 0x8]
0x2d5cf2: MOV EAX, dword ptr [RAX + 0x5c0]
0x2d5cf8: CMP EAX, 0xa
0x2d5cfb: CMOVZ EAX, ECX
0x2d5cfe: XOR ESI, ESI
0x2d5d00: XOR EDX, EDX
0x2d5d02: XOR ECX, ECX
0x2d5d04: MOVSXD R12, EAX
0x2d5d07: SHL R12, 0x6
0x2d5d0b: CALL 0x004c6a00
0x2d5d10: MOV RAX, qword ptr [R12 + R13*0x1 + 0x10]
0x2d5d15: MOV RDI, R14
0x2d5d18: XOR ESI, ESI
0x2d5d1a: XOR EDX, EDX
0x2d5d1c: XOR ECX, ECX
0x2d5d1e: MOV qword ptr [RBP + -0x38], RAX
0x2d5d22: CALL 0x004c6fa0
0x2d5d27: MOV R14, qword ptr [RBX + 0x28]
0x2d5d2b: LEA RAX, [0x269338]
0x2d5d32: SUB RAX, R14
0x2d5d35: ROR RAX, 0x3
0x2d5d39: CMP RAX, 0x3
0x2d5d3d: JA 0x002d5d66
0x2d5d3f: LEA RSI, [RBP + -0x38]
0x2d5d43: MOV EDX, 0x8
0x2d5d48: MOV RDI, RBX
0x2d5d4b: CALL R14
0x2d5d4e: MOV RCX, qword ptr [R15]
0x2d5d51: CMP RCX, qword ptr [RBP + -0x30]
0x2d5d55: JNZ 0x002d5d77
0x2d5d57: ADD RSP, 0x18
0x2d5d5b: POP RBX
0x2d5d5c: POP R12
0x2d5d5e: POP R13
0x2d5d60: POP R14
0x2d5d62: POP R15
0x2d5d64: POP RBP
0x2d5d65: RET
0x2d5d66: LEA RDI, [0x1a961d0]
0x2d5d6d: MOV RSI, R14
0x2d5d70: CALL 0x0044f8c0
0x2d5d75: JMP 0x002d5d3f
0x2d5d77: CALL 0x006fd6b0
0x2d5d7c: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d5d80 RVA 0x2d5d80 | Evidence ev_4b2c80d4cf3a6f04d09431549eb35281be7def05d2c4e04e76d020520c3e1538 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d5d80:
0x2d5d80: PUSH RBP
0x2d5d81: MOV RBP, RSP
0x2d5d84: MOV EAX, 0x13
0x2d5d89: POP RBP
0x2d5d8a: RET


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d5d90 RVA 0x2d5d90 | Evidence ev_82d3a66c9abee41af5e667fc771149fef0503487c00cfbbc026451eb5d1180cb | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d5d90:
0x2d5d90: PUSH RBP
0x2d5d91: MOV RBP, RSP
0x2d5d94: PUSH R15
0x2d5d96: PUSH R14
0x2d5d98: PUSH R12
0x2d5d9a: PUSH RBX
0x2d5d9b: SUB RSP, 0x20
0x2d5d9f: LEA R15, [0x391c310]
0x2d5da6: MOV R14, RDI
0x2d5da9: MOV RDI, RSI
0x2d5dac: LEA RDX, [RBP + -0x38]
0x2d5db0: LEA RCX, [RBP + -0x40]
0x2d5db4: MOV RSI, R14
0x2d5db7: MOV RAX, qword ptr [R15]
0x2d5dba: MOV qword ptr [RBP + -0x28], RAX
0x2d5dbe: CALL 0x005008b0
0x2d5dc3: MOV RBX, qword ptr [R14 + 0x10]
0x2d5dc7: MOV RSI, qword ptr [RBP + -0x38]
0x2d5dcb: MOV R12, qword ptr [RBP + -0x40]
0x2d5dcf: MOV R14D, dword ptr [R14 + 0x18]
0x2d5dd3: LEA RDX, [RBP + -0x30]
0x2d5dd7: MOV RDI, RBX
0x2d5dda: CALL 0x002c6c40
0x2d5ddf: MOV RCX, qword ptr [RBP + -0x30]
0x2d5de3: TEST EAX, EAX
0x2d5de5: JNZ 0x002d5def
0x2d5de7: MOV RCX, qword ptr [RCX + 0x8]
0x2d5deb: MOV qword ptr [RBP + -0x30], RCX
0x2d5def: MOV AL, 0x1
0x2d5df1: JMP 0x002d5e04
0x2d5e00: MOV RCX, qword ptr [RCX + 0x8]
0x2d5e04: CMP RCX, RBX
0x2d5e07: JZ 0x002d5e20
0x2d5e09: CMP qword ptr [RCX + 0x20], R12
0x2d5e0d: JNC 0x002d5e20
0x2d5e0f: TEST byte ptr [RCX + 0x62], 0x10
0x2d5e13: JZ 0x002d5e00
0x2d5e15: MOVZX EDX, word ptr [RCX + 0x64]
0x2d5e19: TEST R14D, EDX
0x2d5e1c: JZ 0x002d5e00
0x2d5e1e: XOR EAX, EAX
0x2d5e20: MOV RCX, qword ptr [R15]
0x2d5e23: CMP RCX, qword ptr [RBP + -0x28]
0x2d5e27: JNZ 0x002d5e36
0x2d5e29: ADD RSP, 0x20
0x2d5e2d: POP RBX
0x2d5e2e: POP R12
0x2d5e30: POP R14
0x2d5e32: POP R15
0x2d5e34: POP RBP
0x2d5e35: RET
0x2d5e36: CALL 0x006fd6b0
0x2d5e3b: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d5e40 RVA 0x2d5e40 | Evidence ev_0002ebd673bd5729b8354fa534804f6524e62c32eb75698b715be0103a513f94 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d5e40:
0x2d5e40: PUSH RBP
0x2d5e41: MOV RBP, RSP
0x2d5e44: XOR EAX, EAX
0x2d5e46: POP RBP
0x2d5e47: RET


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d5e50 RVA 0x2d5e50 | Evidence ev_9cff446f06388806d4663528b97bd48f5ebe3653f7d98f5efc06e97658531cf8 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d5e50:
0x2d5e50: PUSH RBP
0x2d5e51: MOV RBP, RSP
0x2d5e54: MOV RDX, qword ptr [RDI]
0x2d5e57: TEST RDX, RDX
0x2d5e5a: JZ 0x002d5eb4
0x2d5e5c: MOV RCX, qword ptr [RSI + 0x30]
0x2d5e60: JMP 0x002d5e78
0x2d5e70: MOV RDX, qword ptr [RAX]
0x2d5e73: TEST RDX, RDX
0x2d5e76: JZ 0x002d5edb
0x2d5e78: MOV RAX, RDX
0x2d5e7b: CMP RCX, qword ptr [RDX + 0x30]
0x2d5e7f: JC 0x002d5e70
0x2d5e81: JZ 0x002d60db
0x2d5e87: MOV RDX, qword ptr [RAX + 0x8]
0x2d5e8b: TEST RDX, RDX
0x2d5e8e: JNZ 0x002d5e78
0x2d5e90: MOV qword ptr [RSI + 0x10], RAX
0x2d5e94: MOV qword ptr [RSI + 0x8], 0x0
0x2d5e9c: MOV qword ptr [RSI], 0x0
0x2d5ea3: MOV dword ptr [RSI + 0x18], 0x1
0x2d5eaa: LEA RCX, [RSI + 0x10]
0x2d5eae: MOV qword ptr [RAX + 0x8], RSI
0x2d5eb2: JMP 0x002d5efc
0x2d5eb4: LEA RCX, [RSI + 0x10]
0x2d5eb8: MOV qword ptr [RSI + 0x10], 0x0
0x2d5ec0: MOV qword ptr [RSI + 0x8], 0x0
0x2d5ec8: MOV qword ptr [RSI], 0x0
0x2d5ecf: MOV dword ptr [RSI + 0x18], 0x1
0x2d5ed6: MOV qword ptr [RDI], RSI
0x2d5ed9: JMP 0x002d5efc
0x2d5edb: MOV qword ptr [RSI + 0x10], RAX
0x2d5edf: MOV qword ptr [RSI + 0x8], 0x0
0x2d5ee7: MOV qword ptr [RSI], 0x0
0x2d5eee: MOV dword ptr [RSI + 0x18], 0x1
0x2d5ef5: LEA RCX, [RSI + 0x10]
0x2d5ef9: MOV qword ptr [RAX], RSI
0x2d5efc: MOV RAX, qword ptr [RCX]
0x2d5eff: JMP 0x002d5f2f
0x2d5f10: MOV dword ptr [RDX + 0x18], 0x0
0x2d5f17: MOV dword ptr [RAX + 0x18], 0x0
0x2d5f1e: MOV RAX, RCX
0x2d5f21: MOV dword ptr [RCX + 0x18], 0x1
0x2d5f28: MOV RSI, RAX
0x2d5f2b: MOV RAX, qword ptr [RAX + 0x10]
0x2d5f2f: TEST RAX, RAX
0x2d5f32: JZ 0x002d60d1
0x2d5f38: CMP dword ptr [RAX + 0x18], 0x1
0x2d5f3c: JNZ 0x002d60d1
0x2d5f42: MOV RCX, qword ptr [RAX + 0x10]
0x2d5f46: MOV RDX, qword ptr [RCX]
0x2d5f49: CMP RAX, RDX
0x2d5f4c: JZ 0x002d5f70
0x2d5f4e: TEST RDX, RDX
0x2d5f51: JZ 0x002d5f59
0x2d5f53: CMP dword ptr [RDX + 0x18], 0x1
0x2d5f57: JZ 0x002d5f10
0x2d5f59: MOV RDX, qword ptr [RAX]
0x2d5f5c: CMP RDX, RSI
0x2d5f5f: JZ 0x002d5f93
0x2d5f61: MOV RDX, RAX
0x2d5f64: MOV RAX, RSI
0x2d5f67: JMP 0x002d6012
0x2d5f70: MOV RDX, qword ptr [RCX + 0x8]
0x2d5f74: TEST RDX, RDX
0x2d5f77: JZ 0x002d5f7f
0x2d5f79: CMP dword ptr [RDX + 0x18], 0x1
0x2d5f7d: JZ 0x002d5f10
0x2d5f7f: MOV RDX, qword ptr [RAX + 0x8]
0x2d5f83: CMP RDX, RSI
0x2d5f86: JZ 0x002d5fbb
0x2d5f88: MOV RDX, RAX
0x2d5f8b: MOV RAX, RSI
0x2d5f8e: JMP 0x002d6083
0x2d5f93: MOV R8, qword ptr [RDX + 0x8]
0x2d5f97: MOV qword ptr [RAX], R8
0x2d5f9a: TEST R8, R8
0x2d5f9d: JZ 0x002d5ff2
0x2d5f9f: MOV qword ptr [R8 + 0x10], RAX
0x2d5fa3: MOV R8, qword ptr [RAX + 0x10]
0x2d5fa7: MOV qword ptr [RDX + 0x10], R8
0x2d5fab: TEST R8, R8
0x2d5fae: JZ 0x002d6004
0x2d5fb0: CMP RAX, qword ptr [R8]
0x2d5fb3: JZ 0x002d5fff
0x2d5fb5: MOV qword ptr [R8 + 0x8], RDX
0x2d5fb9: JMP 0x002d6007
0x2d5fbb: MOV R8, qword ptr [RDX]
0x2d5fbe: MOV qword ptr [RAX + 0x8], R8
0x2d5fc2: TEST R8, R8
0x2d5fc5: JZ 0x002d6060
0x2d5fcb: MOV qword ptr [R8 + 0x10], RAX
0x2d5fcf: MOV R8, qword ptr [RAX + 0x10]
0x2d5fd3: MOV qword ptr [RDX + 0x10], R8
0x2d5fd7: TEST R8, R8
0x2d5fda: JZ 0x002d6076
0x2d5fe0: CMP RAX, qword ptr [R8]
0x2d5fe3: JZ 0x002d6071
0x2d5fe9: MOV qword ptr [R8 + 0x8], RDX
0x2d5fed: JMP 0x002d6079
0x2d5ff2: MOV qword ptr [RDX + 0x10], RCX
0x2d5ff6: MOV R8, qword ptr [RAX + 0x10]
0x2d5ffa: CMP RAX, qword ptr [R8]
0x2d5ffd: JNZ 0x002d5fb5
0x2d5fff: MOV qword ptr [R8], RDX
0x2d6002: JMP 0x002d6007
0x2d6004: MOV qword ptr [RDI], RDX
0x2d6007: MOV qword ptr [RDX + 0x8], RAX
0x2d600b: MOV qword ptr [RAX + 0x10], RDX
0x2d600f: MOV RDX, RSI
0x2d6012: MOV dword ptr [RDX + 0x18], 0x0
0x2d6019: MOV dword ptr [RCX + 0x18], 0x1
0x2d6020: MOV RDX, qword ptr [RCX + 0x8]
0x2d6024: MOV RSI, qword ptr [RDX]
0x2d6027: MOV qword ptr [RCX + 0x8], RSI
0x2d602b: TEST RSI, RSI
0x2d602e: JZ 0x002d6034
0x2d6030: MOV qword ptr [RSI + 0x10], RCX
0x2d6034: MOV RSI, qword ptr [RCX + 0x10]
0x2d6038: MOV qword ptr [RDX + 0x10], RSI
0x2d603c: TEST RSI, RSI
0x2d603f: JZ 0x002d604c
0x2d6041: CMP RCX, qword ptr [RSI]
0x2d6044: JZ 0x002d6051
0x2d6046: MOV qword ptr [RSI + 0x8], RDX
0x2d604a: JMP 0x002d6054
0x2d604c: MOV qword ptr [RDI], RDX
0x2d604f: JMP 0x002d6054
0x2d6051: MOV qword ptr [RSI], RDX
0x2d6054: MOV qword ptr [RDX], RCX
0x2d6057: MOV qword ptr [RCX + 0x10], RDX
0x2d605b: JMP 0x002d5f28
0x2d6060: MOV qword ptr [RDX + 0x10], RCX
0x2d6064: MOV R8, qword ptr [RAX + 0x10]
0x2d6068: CMP RAX, qword ptr [R8]
0x2d606b: JNZ 0x002d5fe9
0x2d6071: MOV qword ptr [R8], RDX
0x2d6074: JMP 0x002d6079
0x2d6076: MOV qword ptr [RDI], RDX
0x2d6079: MOV qword ptr [RDX], RAX
0x2d607c: MOV qword ptr [RAX + 0x10], RDX
0x2d6080: MOV RDX, RSI
0x2d6083: MOV dword ptr [RDX + 0x18], 0x0
0x2d608a: MOV dword ptr [RCX + 0x18], 0x1
0x2d6091: MOV RDX, qword ptr [RCX]
0x2d6094: MOV RSI, qword ptr [RDX + 0x8]
0x2d6098: MOV qword ptr [RCX], RSI
0x2d609b: TEST RSI, RSI
0x2d609e: JZ 0x002d60a4
0x2d60a0: MOV qword ptr [RSI + 0x10], RCX
0x2d60a4: MOV RSI, qword ptr [RCX + 0x10]
0x2d60a8: MOV qword ptr [RDX + 0x10], RSI
0x2d60ac: TEST RSI, RSI
0x2d60af: JZ 0x002d60bc
0x2d60b1: CMP RCX, qword ptr [RSI]
0x2d60b4: JZ 0x002d60c1
0x2d60b6: MOV qword ptr [RSI + 0x8], RDX
0x2d60ba: JMP 0x002d60c4
0x2d60bc: MOV qword ptr [RDI], RDX
0x2d60bf: JMP 0x002d60c4
0x2d60c1: MOV qword ptr [RSI], RDX
0x2d60c4: MOV qword ptr [RDX + 0x8], RCX
0x2d60c8: MOV qword ptr [RCX + 0x10], RDX
0x2d60cc: JMP 0x002d5f28
0x2d60d1: MOV RAX, qword ptr [RDI]
0x2d60d4: MOV dword ptr [RAX + 0x18], 0x0
0x2d60db: POP RBP
0x2d60dc: RET


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d60e0 RVA 0x2d60e0 | Evidence ev_8e178cf22cb93ddfa8c17fc07b404edb978b5964f4615a33c4d66605f71ec339 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d60e0:
0x2d60e0: PUSH RBP
0x2d60e1: MOV RBP, RSP
0x2d60e4: MOV RCX, qword ptr [RSI]
0x2d60e7: MOV R9, qword ptr [RSI + 0x8]
0x2d60eb: MOV RAX, RSI
0x2d60ee: TEST RCX, RCX
0x2d60f1: JZ 0x002d6130
0x2d60f3: TEST R9, R9
0x2d60f6: JZ 0x002d6141
0x2d60f8: NOP dword ptr [RAX + RAX*0x1]
0x2d6100: MOV R8, R9
0x2d6103: MOV R9, qword ptr [R9]
0x2d6106: TEST R9, R9
0x2d6109: JNZ 0x002d6100
0x2d610b: MOV RCX, qword ptr [R8 + 0x8]
0x2d610f: MOV RDX, qword ptr [R8 + 0x10]
0x2d6113: MOV ESI, dword ptr [R8 + 0x18]
0x2d6117: TEST RCX, RCX
0x2d611a: JZ 0x002d6120
0x2d611c: MOV qword ptr [RCX + 0x10], RDX
0x2d6120: TEST RDX, RDX
0x2d6123: JZ 0x002d615c
0x2d6125: CMP qword ptr [RDX], R8
0x2d6128: JZ 0x002d6174
0x2d612a: MOV qword ptr [RDX + 0x8], RCX
0x2d612e: JMP 0x002d6177
0x2d6130: MOV RDX, qword ptr [RAX + 0x10]
0x2d6134: MOV ESI, dword ptr [RAX + 0x18]
0x2d6137: TEST R9, R9
0x2d613a: JZ 0x002d6166
0x2d613c: MOV RCX, R9
0x2d613f: JMP 0x002d6148
0x2d6141: MOV RDX, qword ptr [RAX + 0x10]
0x2d6145: MOV ESI, dword ptr [RAX + 0x18]
0x2d6148: MOV qword ptr [RCX + 0x10], RDX
0x2d614c: TEST RDX, RDX
0x2d614f: JZ 0x002d616d
0x2d6151: CMP qword ptr [RDX], RAX
0x2d6154: JZ 0x002d6161
0x2d6156: MOV qword ptr [RDX + 0x8], RCX
0x2d615a: JMP 0x002d61cd
0x2d615c: MOV qword ptr [RDI], RCX
0x2d615f: JMP 0x002d6177
0x2d6161: MOV qword ptr [RDX], RCX
0x2d6164: JMP 0x002d61cd
0x2d6166: XOR ECX, ECX
0x2d6168: TEST RDX, RDX
0x2d616b: JNZ 0x002d6151
0x2d616d: XOR EDX, EDX
0x2d616f: MOV qword ptr [RDI], RCX
0x2d6172: JMP 0x002d61cd
0x2d6174: MOV qword ptr [RDX], RCX
0x2d6177: MOV R9, qword ptr [RAX + 0x18]
0x2d617b: CMP qword ptr [R8 + 0x10], RAX
0x2d617f: MOV qword ptr [R8 + 0x18], R9
0x2d6183: MOV R9, qword ptr [RAX + 0x10]
0x2d6187: CMOVZ RDX, R8
0x2d618b: MOV qword ptr [R8 + 0x10], R9
0x2d618f: MOV R9, qword ptr [RAX]
0x2d6192: MOV R10, qword ptr [RAX + 0x8]
0x2d6196: MOV qword ptr [R8 + 0x8], R10
0x2d619a: MOV qword ptr [R8], R9
0x2d619d: MOV R9, qword ptr [RAX + 0x10]
0x2d61a1: TEST R9, R9
0x2d61a4: JZ 0x002d61b1
0x2d61a6: CMP qword ptr [R9], RAX
0x2d61a9: JZ 0x002d61b6
0x2d61ab: MOV qword ptr [R9 + 0x8], R8
0x2d61af: JMP 0x002d61b9
0x2d61b1: MOV qword ptr [RDI], R8
0x2d61b4: JMP 0x002d61b9
0x2d61b6: MOV qword ptr [R9], R8
0x2d61b9: MOV R9, qword ptr [RAX]
0x2d61bc: MOV qword ptr [R9 + 0x10], R8
0x2d61c0: MOV R9, qword ptr [RAX + 0x8]
0x2d61c4: TEST R9, R9
0x2d61c7: JZ 0x002d61cd
0x2d61c9: MOV qword ptr [R9 + 0x10], R8
0x2d61cd: TEST ESI, ESI
0x2d61cf: JZ 0x002d61eb
0x2d61d1: POP RBP
0x2d61d2: RET
0x2d61e0: MOV dword ptr [RDX + 0x18], 0x1
0x2d61e7: MOV RDX, qword ptr [RCX + 0x10]
0x2d61eb: MOV RSI, RCX
0x2d61ee: MOV RCX, RDX
0x2d61f1: TEST RSI, RSI
0x2d61f4: JZ 0x002d6200
0x2d61f6: CMP dword ptr [RSI + 0x18], 0x0
0x2d61fa: JNZ 0x002d643b
0x2d6200: CMP RSI, qword ptr [RDI]
0x2d6203: JZ 0x002d6432
0x2d6209: MOV RDX, qword ptr [RCX]
0x2d620c: CMP RDX, RSI
0x2d620f: JZ 0x002d6260
0x2d6211: CMP dword ptr [RDX + 0x18], 0x1
0x2d6215: JNZ 0x002d62bb
0x2d621b: MOV dword ptr [RDX + 0x18], 0x0
0x2d6222: MOV dword ptr [RCX + 0x18], 0x1
0x2d6229: MOV RDX, qword ptr [RCX]
0x2d622c: MOV RSI, qword ptr [RDX + 0x8]
0x2d6230: MOV qword ptr [RCX], RSI
0x2d6233: TEST RSI, RSI
0x2d6236: JZ 0x002d623c
0x2d6238: MOV qword ptr [RSI + 0x10], RCX
0x2d623c: MOV RSI, qword ptr [RCX + 0x10]
0x2d6240: MOV qword ptr [RDX + 0x10], RSI
0x2d6244: TEST RSI, RSI
0x2d6247: JZ 0x002d62a8
0x2d6249: CMP RCX, qword ptr [RSI]
0x2d624c: JZ 0x002d62ad
0x2d624e: MOV qword ptr [RSI + 0x8], RDX
0x2d6252: JMP 0x002d62b0
0x2d6260: MOV RDX, qword ptr [RCX + 0x8]
0x2d6264: CMP dword ptr [RDX + 0x18], 0x1
0x2d6268: JNZ 0x002d62fa
0x2d626e: MOV dword ptr [RDX + 0x18], 0x0
0x2d6275: MOV dword ptr [RCX + 0x18], 0x1
0x2d627c: MOV RDX, qword ptr [RCX + 0x8]
0x2d6280: MOV RSI, qword ptr [RDX]
0x2d6283: MOV qword ptr [RCX + 0x8], RSI
0x2d6287: TEST RSI, RSI
0x2d628a: JZ 0x002d6290
0x2d628c: MOV qword ptr [RSI + 0x10], RCX
0x2d6290: MOV RSI, qword ptr [RCX + 0x10]
0x2d6294: MOV qword ptr [RDX + 0x10], RSI
0x2d6298: TEST RSI, RSI
0x2d629b: JZ 0x002d62e7
0x2d629d: CMP RCX, qword ptr [RSI]
0x2d62a0: JZ 0x002d62ec
0x2d62a2: MOV qword ptr [RSI + 0x8], RDX
0x2d62a6: JMP 0x002d62ef
0x2d62a8: MOV qword ptr [RDI], RDX
0x2d62ab: JMP 0x002d62b0
0x2d62ad: MOV qword ptr [RSI], RDX
0x2d62b0: MOV qword ptr [RDX + 0x8], RCX
0x2d62b4: MOV qword ptr [RCX + 0x10], RDX
0x2d62b8: MOV RDX, qword ptr [RCX]
0x2d62bb: MOV RSI, qword ptr [RDX]
0x2d62be: TEST RSI, RSI
0x2d62c1: JZ 0x002d62cd
0x2d62c3: CMP dword ptr [RSI + 0x18], 0x0
0x2d62c7: JNZ 0x002d63d8
0x2d62cd: MOV R8, qword ptr [RDX + 0x8]
0x2d62d1: TEST R8, R8
0x2d62d4: JZ 0x002d61e0
0x2d62da: CMP dword ptr [R8 + 0x18], 0x0
0x2d62df: JZ 0x002d61e0
0x2d62e5: JMP 0x002d6324
0x2d62e7: MOV qword ptr [RDI], RDX
0x2d62ea: JMP 0x002d62ef
0x2d62ec: MOV qword ptr [RSI], RDX
0x2d62ef: MOV qword ptr [RDX], RCX
0x2d62f2: MOV qword ptr [RCX + 0x10], RDX
0x2d62f6: MOV RDX, qword ptr [RCX + 0x8]
0x2d62fa: MOV RSI, qword ptr [RDX]
0x2d62fd: TEST RSI, RSI
0x2d6300: JZ 0x002d6308
0x2d6302: CMP dword ptr [RSI + 0x18], 0x0
0x2d6306: JNZ 0x002d636e
0x2d6308: MOV RSI, qword ptr [RDX + 0x8]
0x2d630c: TEST RSI, RSI
0x2d630f: JZ 0x002d61e0
0x2d6315: CMP dword ptr [RSI + 0x18], 0x0
0x2d6319: JZ 0x002d61e0
0x2d631f: JMP 0x002d6458
0x2d6324: TEST RSI, RSI
0x2d6327: JZ 0x002d6333
0x2d6329: CMP dword ptr [RSI + 0x18], 0x0
0x2d632d: JNZ 0x002d63d8
0x2d6333: MOV dword ptr [R8 + 0x18], 0x0
0x2d633b: MOV RSI, qword ptr [RDX + 0x8]
0x2d633f: MOV dword ptr [RDX + 0x18], 0x1
0x2d6346: MOV R8, qword ptr [RSI]
0x2d6349: MOV qword ptr [RDX + 0x8], R8
0x2d634d: TEST R8, R8
0x2d6350: JZ 0x002d6356
0x2d6352: MOV qword ptr [R8 + 0x10], RDX
0x2d6356: MOV R8, qword ptr [RDX + 0x10]
0x2d635a: MOV qword ptr [RSI + 0x10], R8
0x2d635e: TEST R8, R8
0x2d6361: JZ 0x002d63c6
0x2d6363: CMP RDX, qword ptr [R8]
0x2d6366: JZ 0x002d63cb
0x2d6368: MOV qword ptr [R8 + 0x8], RSI
0x2d636c: JMP 0x002d63ce
0x2d636e: MOV R8, qword ptr [RDX + 0x8]
0x2d6372: TEST R8, R8
0x2d6375: JZ 0x002d6382
0x2d6377: CMP dword ptr [R8 + 0x18], 0x0
0x2d637c: JNZ 0x002d6458
0x2d6382: MOV dword ptr [RSI + 0x18], 0x0
0x2d6389: MOV RSI, qword ptr [RDX]
0x2d638c: MOV dword ptr [RDX + 0x18], 0x1
0x2d6393: MOV R8, qword ptr [RSI + 0x8]
0x2d6397: MOV qword ptr [RDX], R8
0x2d639a: TEST R8, R8
0x2d639d: JZ 0x002d63a3
0x2d639f: MOV qword ptr [R8 + 0x10], RDX
0x2d63a3: MOV R8, qword ptr [RDX + 0x10]
0x2d63a7: MOV qword ptr [RSI + 0x10], R8
0x2d63ab: TEST R8, R8
0x2d63ae: JZ 0x002d6444
0x2d63b4: CMP RDX, qword ptr [R8]
0x2d63b7: JZ 0x002d6449
0x2d63bd: MOV qword ptr [R8 + 0x8], RSI
0x2d63c1: JMP 0x002d644c
0x2d63c6: MOV qword ptr [RDI], RSI
0x2d63c9: JMP 0x002d63ce
0x2d63cb: MOV qword ptr [R8], RSI
0x2d63ce: MOV qword ptr [RSI], RDX
0x2d63d1: MOV qword ptr [RDX + 0x10], RSI
0x2d63d5: MOV RDX, qword ptr [RCX]
0x2d63d8: MOV ESI, dword ptr [RCX + 0x18]
0x2d63db: MOV dword ptr [RDX + 0x18], ESI
0x2d63de: MOV dword ptr [RCX + 0x18], 0x0
0x2d63e5: MOV RDX, qword ptr [RDX]
0x2d63e8: TEST RDX, RDX
0x2d63eb: JZ 0x002d63f4
0x2d63ed: MOV dword ptr [RDX + 0x18], 0x0
0x2d63f4: MOV RDX, qword ptr [RCX]
0x2d63f7: MOV RSI, qword ptr [RDX + 0x8]
0x2d63fb: MOV qword ptr [RCX], RSI
0x2d63fe: TEST RSI, RSI
0x2d6401: JZ 0x002d6407
0x2d6403: MOV qword ptr [RSI + 0x10], RCX
0x2d6407: MOV RSI, qword ptr [RCX + 0x10]
0x2d640b: MOV qword ptr [RDX + 0x10], RSI
0x2d640f: TEST RSI, RSI
0x2d6412: JZ 0x002d641f
0x2d6414: CMP RCX, qword ptr [RSI]
0x2d6417: JZ 0x002d6424
0x2d6419: MOV qword ptr [RSI + 0x8], RDX
0x2d641d: JMP 0x002d6427
0x2d641f: MOV qword ptr [RDI], RDX
0x2d6422: JMP 0x002d6427
0x2d6424: MOV qword ptr [RSI], RDX
0x2d6427: MOV qword ptr [RDX + 0x8], RCX
0x2d642b: MOV qword ptr [RCX + 0x10], RDX
0x2d642f: MOV RSI, qword ptr [RDI]
0x2d6432: TEST RSI, RSI
0x2d6435: JZ 0x002d61d1
0x2d643b: MOV dword ptr [RSI + 0x18], 0x0
0x2d6442: POP RBP
0x2d6443: RET
0x2d6444: MOV qword ptr [RDI], RSI
0x2d6447: JMP 0x002d644c
0x2d6449: MOV qword ptr [R8], RSI
0x2d644c: MOV qword ptr [RSI + 0x8], RDX
0x2d6450: MOV qword ptr [RDX + 0x10], RSI
0x2d6454: MOV RDX, qword ptr [RCX + 0x8]
0x2d6458: MOV ESI, dword ptr [RCX + 0x18]
0x2d645b: MOV dword ptr [RDX + 0x18], ESI
0x2d645e: MOV dword ptr [RCX + 0x18], 0x0
0x2d6465: MOV RDX, qword ptr [RDX + 0x8]
0x2d6469: TEST RDX, RDX
0x2d646c: JZ 0x002d6475
0x2d646e: MOV dword ptr [RDX + 0x18], 0x0
0x2d6475: MOV RDX, qword ptr [RCX + 0x8]
0x2d6479: MOV RSI, qword ptr [RDX]
0x2d647c: MOV qword ptr [RCX + 0x8], RSI
0x2d6480: TEST RSI, RSI
0x2d6483: JZ 0x002d6489
0x2d6485: MOV qword ptr [RSI + 0x10], RCX
0x2d6489: MOV RSI, qword ptr [RCX + 0x10]
0x2d648d: MOV qword ptr [RDX + 0x10], RSI
0x2d6491: TEST RSI, RSI
0x2d6494: JZ 0x002d64a4
0x2d6496: CMP RCX, qword ptr [RSI]
0x2d6499: JZ 0x002d64af
0x2d649b: MOV qword ptr [RSI + 0x8], RDX
0x2d649f: MOV qword ptr [RDX], RCX
0x2d64a2: JMP 0x002d642b
0x2d64a4: MOV qword ptr [RDI], RDX
0x2d64a7: MOV qword ptr [RDX], RCX
0x2d64aa: JMP 0x002d642b
0x2d64af: MOV qword ptr [RSI], RDX
0x2d64b2: MOV qword ptr [RDX], RCX
0x2d64b5: JMP 0x002d642b


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d64c0 RVA 0x2d64c0 | Evidence ev_31224fcd27b0670789d23f69227158a4db6602609941cec67142847ec1726445 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d64c0:
0x2d64c0: PUSH RBP
0x2d64c1: MOV RBP, RSP
0x2d64c4: PUSH R15
0x2d64c6: PUSH R14
0x2d64c8: PUSH R13
0x2d64ca: PUSH R12
0x2d64cc: PUSH RBX
0x2d64cd: PUSH RAX
0x2d64ce: AND byte ptr [RSI + 0x140], 0xfc
0x2d64d5: MOV R14, RSI
0x2d64d8: MOV RBX, RDI
0x2d64db: MOVZX EAX, word ptr [RSI + 0x14a]
0x2d64e2: MOVZX R12D, word ptr [RSI + 0x64]
0x2d64e7: MOV word ptr [RSI + 0x64], AX
0x2d64eb: MOVZX R15D, AX
0x2d64ef: TEST byte ptr [RDI + 0x244], 0x1
0x2d64f6: SETZ CL
0x2d64f9: TEST R12D, 0x3c7
0x2d6500: SETNZ DL
0x2d6503: TEST EAX, 0x3c7
0x2d6508: SETZ AL
0x2d650b: OR AL, CL
0x2d650d: OR AL, DL
0x2d650f: JNZ 0x002d65bb
0x2d6515: MOV R13, qword ptr [R14 + 0x50]
0x2d6519: TEST byte ptr [R13 + 0xa2], 0x1
0x2d6521: JNZ 0x002d659d
0x2d6523: LEA RDI, [R13 + 0x18]
0x2d6527: XOR ESI, ESI
0x2d6529: XOR EDX, EDX
0x2d652b: MOV qword ptr [RBP + -0x30], RDI
0x2d652f: CALL 0x007d46a0
0x2d6534: MOVZX EDI, byte ptr [R13 + 0x150]
0x2d653c: CALL 0x00616d40
0x2d6541: TEST AL, AL
0x2d6543: JZ 0x002d658e
0x2d6545: MOV RSI, qword ptr [R14 + 0x58]
0x2d6549: MOV RDI, R13
0x2d654c: SAR RSI, 0xe
0x2d6550: CALL 0x00b897f0
0x2d6555: TEST RAX, RAX
0x2d6558: JZ 0x002d658e
0x2d655a: MOV RCX, qword ptr [R14 + 0x58]
0x2d655e: MOV RSI, qword ptr [RAX + 0x28]
0x2d6562: MOV RDX, qword ptr [R14 + 0x28]
0x2d6566: SHR RCX, 0xe
0x2d656a: SUB RSI, RCX
0x2d656d: SHL RSI, 0xe
0x2d6571: ADD RSI, qword ptr [R14 + 0x20]
0x2d6575: CMP RSI, RDX
0x2d6578: JNC 0x002d658e
0x2d657a: MOV RDI, qword ptr [RBX + 0x1d8]
0x2d6581: MOVZX R8D, word ptr [R14 + 0x64]
0x2d6586: MOV RCX, RAX
0x2d6589: CALL 0x008e3d20
0x2d658e: MOV RDI, qword ptr [RBP + -0x30]
0x2d6592: XOR ESI, ESI
0x2d6594: XOR EDX, EDX
0x2d6596: CALL 0x007d4eb0
0x2d659b: JMP 0x002d65bb
0x2d659d: MOV RSI, qword ptr [RBX + 0x1d8]
0x2d65a4: MOV RDX, qword ptr [R14 + 0x20]
0x2d65a8: MOV RCX, qword ptr [R14 + 0x28]
0x2d65ac: MOV R8, qword ptr [R14 + 0x58]
0x2d65b0: MOV RDI, R13
0x2d65b3: MOV R9D, R15D
0x2d65b6: CALL 0x003cc5a0
0x2d65bb: TEST R12B, 0x30
0x2d65bf: SETZ AL
0x2d65c2: AND AL, byte ptr [RBX + 0x244]
0x2d65c8: CMP AL, 0x1
0x2d65ca: JNZ 0x002d6619
0x2d65cc: AND R15D, 0x30
0x2d65d0: JZ 0x002d6619
0x2d65d2: MOV RAX, qword ptr [0x01a962e8]
0x2d65d9: MOV R9, qword ptr [RAX + 0x20]
0x2d65dd: LEA RAX, [0x26d118]
0x2d65e4: SUB RAX, R9
0x2d65e7: ROR RAX, 0x3
0x2d65eb: CMP RAX, 0x1
0x2d65ef: JA 0x002d6628
0x2d65f1: MOV RSI, qword ptr [R14 + 0x20]
0x2d65f5: MOV RDX, qword ptr [R14 + 0x28]
0x2d65f9: MOV RDI, RBX
0x2d65fc: MOV ECX, R15D
0x2d65ff: MOV R8D, 0x1
0x2d6605: SUB RDX, RSI
0x2d6608: ADD RSP, 0x8
0x2d660c: POP RBX
0x2d660d: POP R12
0x2d660f: POP R13
0x2d6611: POP R14
0x2d6613: POP R15
0x2d6615: POP RBP
0x2d6616: JMP R9
0x2d6619: ADD RSP, 0x8
0x2d661d: POP RBX
0x2d661e: POP R12
0x2d6620: POP R13
0x2d6622: POP R14
0x2d6624: POP R15
0x2d6626: POP RBP
0x2d6627: RET
0x2d6628: LEA RDI, [0x1a96270]
0x2d662f: MOV RSI, R9
0x2d6632: MOV R12, R9
0x2d6635: CALL 0x0044f8c0
0x2d663a: MOV R9, R12
0x2d663d: JMP 0x002d65f1


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d6640 RVA 0x2d6640 | Evidence ev_e8d772d9b0641aa1d74029e10ad8da2cad0469a386850bf6da5f8fc75855e2d5 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d6640:
0x2d6640: PUSH RBP
0x2d6641: MOV RBP, RSP
0x2d6644: PUSH R15
0x2d6646: PUSH R14
0x2d6648: PUSH RBX
0x2d6649: PUSH RAX
0x2d664a: OR byte ptr [RSI + 0x140], 0x1
0x2d6651: MOV RBX, RSI
0x2d6654: MOVZX R14D, word ptr [RSI + 0x64]
0x2d6659: MOV word ptr [RSI + 0x14a], R14W
0x2d6661: MOV word ptr [RSI + 0x64], 0x0
0x2d6667: TEST byte ptr [RDI + 0x244], 0x1
0x2d666e: SETZ AL
0x2d6671: TEST R14D, 0x3c7
0x2d6678: SETZ CL
0x2d667b: OR CL, AL
0x2d667d: JNZ 0x002d66ad
0x2d667f: MOV RAX, qword ptr [RBX + 0x50]
0x2d6683: MOV R15, RDI
0x2d6686: MOV RDI, qword ptr [RDI + 0x1d8]
0x2d668d: MOV RSI, qword ptr [RBX + 0x20]
0x2d6691: MOV RDX, qword ptr [RBX + 0x28]
0x2d6695: TEST byte ptr [RAX + 0xa2], 0x1
0x2d669c: JNZ 0x002d66a5
0x2d669e: CALL 0x008df6a0
0x2d66a3: JMP 0x002d66aa
0x2d66a5: CALL 0x008ede90
0x2d66aa: MOV RDI, R15
0x2d66ad: TEST byte ptr [RDI + 0x244], 0x1
0x2d66b4: SETZ AL
0x2d66b7: TEST R14B, 0x30
0x2d66bb: SETZ CL
0x2d66be: OR CL, AL
0x2d66c0: JZ 0x002d66cd
0x2d66c2: ADD RSP, 0x8
0x2d66c6: POP RBX
0x2d66c7: POP R14
0x2d66c9: POP R15
0x2d66cb: POP RBP
0x2d66cc: RET
0x2d66cd: MOV RAX, qword ptr [0x01a962e8]
0x2d66d4: MOV R9, qword ptr [RAX + 0x20]
0x2d66d8: LEA RAX, [0x26d118]
0x2d66df: SUB RAX, R9
0x2d66e2: ROR RAX, 0x3
0x2d66e6: CMP RAX, 0x1
0x2d66ea: JA 0x002d670c
0x2d66ec: MOV RSI, qword ptr [RBX + 0x20]
0x2d66f0: MOV RDX, qword ptr [RBX + 0x28]
0x2d66f4: XOR ECX, ECX
0x2d66f6: MOV R8D, 0x1
0x2d66fc: SUB RDX, RSI
0x2d66ff: ADD RSP, 0x8
0x2d6703: POP RBX
0x2d6704: POP R14
0x2d6706: POP R15
0x2d6708: POP RBP
0x2d6709: JMP R9
0x2d670c: LEA RAX, [0x1a96290]
0x2d6713: MOV R14, RDI
0x2d6716: MOV RSI, R9
0x2d6719: MOV R15, R9
0x2d671c: MOV RDI, RAX
0x2d671f: CALL 0x0044f8c0
0x2d6724: MOV R9, R15
0x2d6727: MOV RDI, R14
0x2d672a: JMP 0x002d66ec


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d6730 RVA 0x2d6730 | Evidence ev_07374b14c324071949997c3d4559f7ab7dfa30bd0772dd68fad9e907bbe3a147 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d6730:
0x2d6730: PUSH RBP
0x2d6731: MOV RBP, RSP
0x2d6734: PUSH R15
0x2d6736: PUSH R14
0x2d6738: PUSH R13
0x2d673a: PUSH R12
0x2d673c: PUSH RBX
0x2d673d: SUB RSP, 0x18
0x2d6741: LEA RAX, [0x391c310]
0x2d6748: MOV R14D, ECX
0x2d674b: MOV R15, RDX
0x2d674e: MOV R13, RSI
0x2d6751: MOV RBX, RDI
0x2d6754: MOV RAX, qword ptr [RAX]
0x2d6757: MOV qword ptr [RBP + -0x30], RAX
0x2d675b: MOVZX EAX, byte ptr [RDI + 0x244]
0x2d6762: TEST AL, 0x10
0x2d6764: JNZ 0x002d678f
0x2d6766: TEST AL, 0x8
0x2d6768: JZ 0x002d677b
0x2d676a: MOV RAX, qword ptr GS:[0x0]
0x2d6773: ADD.LOCK dword ptr [RAX + 0x5a8], 0x1
0x2d677b: LEA RDI, [RBX + 0x170]
0x2d6782: XOR ESI, ESI
0x2d6784: XOR EDX, EDX
0x2d6786: XOR ECX, ECX
0x2d6788: CALL 0x00c4bb20
0x2d678d: JMP 0x002d67a1
0x2d678f: LEA RDI, [RBX + 0x1a8]
0x2d6796: XOR ESI, ESI
0x2d6798: XOR EDX, EDX
0x2d679a: XOR ECX, ECX
0x2d679c: CALL 0x004c6a00
0x2d67a1: INC dword ptr [RBX + 0x1c0]
0x2d67a7: LEA RDX, [RBP + -0x38]
0x2d67ab: MOV RDI, RBX
0x2d67ae: MOV RSI, R13
0x2d67b1: ADD.LOCK dword ptr [RBX + 0x1c4], 0x1
0x2d67b9: CALL 0x002c6c40
0x2d67be: MOV R12, qword ptr [RBP + -0x38]
0x2d67c2: CMP R13, qword ptr [R12 + 0x20]
0x2d67c7: JBE 0x002d67f5
0x2d67c9: MOV RDI, RBX
0x2d67cc: MOV RSI, R12
0x2d67cf: MOV RDX, R13
0x2d67d2: CALL 0x002cb4e0
0x2d67d7: JMP 0x002d67f5
0x2d67e0: CALL 0x002d6640
0x2d67e5: MOV RDI, RBX
0x2d67e8: MOV RSI, R12
0x2d67eb: CALL 0x002c8910
0x2d67f0: MOV R12, qword ptr [R12 + 0x8]
0x2d67f5: CMP R12, RBX
0x2d67f8: JZ 0x002d6828
0x2d67fa: CMP qword ptr [R12 + 0x20], R15
0x2d67ff: JNC 0x002d6828
0x2d6801: CMP R15, qword ptr [R12 + 0x28]
0x2d6806: JNC 0x002d6816
0x2d6808: MOV RDI, RBX
0x2d680b: MOV RSI, R12
0x2d680e: MOV RDX, R15
0x2d6811: CALL 0x002cb770
0x2d6816: MOV RDI, RBX
0x2d6819: MOV RSI, R12
0x2d681c: TEST R14D, R14D
0x2d681f: JZ 0x002d67e0
0x2d6821: CALL 0x002d64c0
0x2d6826: JMP 0x002d67e5
0x2d6828: LEA RAX, [0x391c310]
0x2d682f: MOV RAX, qword ptr [RAX]
0x2d6832: CMP RAX, qword ptr [RBP + -0x30]
0x2d6836: JNZ 0x002d6852
0x2d6838: MOV RDI, RBX
0x2d683b: XOR ESI, ESI
0x2d683d: XOR EDX, EDX
0x2d683f: ADD RSP, 0x18
0x2d6843: POP RBX
0x2d6844: POP R12
0x2d6846: POP R13
0x2d6848: POP R14
0x2d684a: POP R15
0x2d684c: POP RBP
0x2d684d: JMP 0x002c64f0
0x2d6852: CALL 0x006fd6b0
0x2d6857: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d6860 RVA 0x2d6860 | Evidence ev_4aaa25afd55e86c902c902d7f19c954eebae0165e443ba3632bd9804759b31d7 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d6860:
0x2d6860: PUSH RBP
0x2d6861: MOV RBP, RSP
0x2d6864: PUSH R15
0x2d6866: PUSH R14
0x2d6868: PUSH R13
0x2d686a: PUSH R12
0x2d686c: PUSH RBX
0x2d686d: SUB RSP, 0x58
0x2d6871: LEA RAX, [0x391c310]
0x2d6878: MOV R15, RSI
0x2d687b: MOV RBX, RDI
0x2d687e: SAR RDX, 0xe
0x2d6882: SAR R15, 0xe
0x2d6886: MOV RSI, R15
0x2d6889: MOV RAX, qword ptr [RAX]
0x2d688c: MOV qword ptr [RBP + -0x30], RAX
0x2d6890: MOV dword ptr [RBP + -0x74], ECX
0x2d6893: MOV qword ptr [RBP + -0x80], RDX
0x2d6897: TEST ECX, ECX
0x2d6899: JZ 0x002d68a2
0x2d689b: CALL 0x00460e60
0x2d68a0: JMP 0x002d68a7
0x2d68a2: CALL 0x00460a10
0x2d68a7: MOV R14D, EAX
0x2d68aa: TEST EAX, EAX
0x2d68ac: JZ 0x002d68d4
0x2d68ae: LEA RAX, [0x391c310]
0x2d68b5: MOV RAX, qword ptr [RAX]
0x2d68b8: CMP RAX, qword ptr [RBP + -0x30]
0x2d68bc: JNZ 0x002d69df
0x2d68c2: MOV EAX, R14D
0x2d68c5: ADD RSP, 0x58
0x2d68c9: POP RBX
0x2d68ca: POP R12
0x2d68cc: POP R13
0x2d68ce: POP R14
0x2d68d0: POP R15
0x2d68d2: POP RBP
0x2d68d3: RET
0x2d68d4: LEA RDI, [RBP + -0x70]
0x2d68d8: MOV RSI, RBX
0x2d68db: CALL 0x00501950
0x2d68e0: TEST RAX, RAX
0x2d68e3: JZ 0x002d69d7
0x2d68e9: MOV R12, RAX
0x2d68ec: LEA R13, [RBP + -0x60]
0x2d68f0: JMP 0x002d6985
0x2d6900: LEA RDI, [RBX + 0x170]
0x2d6907: XOR ESI, ESI
0x2d6909: XOR EDX, EDX
0x2d690b: XOR ECX, ECX
0x2d690d: CALL 0x00c4bb20
0x2d6912: INC dword ptr [RBX + 0x1c0]
0x2d6918: MOV RDI, R12
0x2d691b: MOV RSI, R13
0x2d691e: LEA RDX, [0x2704d8]
0x2d6925: MOV RCX, R13
0x2d6928: ADD.LOCK dword ptr [RBX + 0x1c4], 0x1
0x2d6930: MOV dword ptr [RBP + -0x58], R15D
0x2d6934: MOV RAX, qword ptr [RBP + -0x80]
0x2d6938: MOV dword ptr [RBP + -0x54], EAX
0x2d693b: MOV RAX, qword ptr [R12 + 0x18]
0x2d6940: MOV qword ptr [RBP + -0x50], RAX
0x2d6944: MOV RAX, 0x7fffffffffffffff
0x2d694e: MOV qword ptr [RBP + -0x48], RAX
0x2d6952: MOV qword ptr [RBP + -0x40], RAX
0x2d6956: MOV EAX, dword ptr [RBP + -0x74]
0x2d6959: MOV byte ptr [RBP + -0x38], AL
0x2d695c: CALL 0x00501660
0x2d6961: MOV RDI, RBX
0x2d6964: XOR R14D, R14D
0x2d6967: XOR ESI, ESI
0x2d6969: XOR EDX, EDX
0x2d696b: CALL 0x002c64f0
0x2d6970: LEA RDI, [RBP + -0x70]
0x2d6974: CALL 0x005019d0
0x2d6979: MOV R12, RAX
0x2d697c: TEST RAX, RAX
0x2d697f: JZ 0x002d68ae
0x2d6985: MOV RBX, qword ptr [R12 + 0x18]
0x2d698a: MOVZX EAX, byte ptr [RBX + 0x244]
0x2d6991: TEST AL, 0x10
0x2d6993: JNZ 0x002d69c0
0x2d6995: TEST AL, 0x8
0x2d6997: JZ 0x002d6900
0x2d699d: MOV RAX, qword ptr GS:[0x0]
0x2d69a6: ADD.LOCK dword ptr [RAX + 0x5a8], 0x1
0x2d69ae: JMP 0x002d6900
0x2d69c0: LEA RDI, [RBX + 0x1a8]
0x2d69c7: XOR ESI, ESI
0x2d69c9: XOR EDX, EDX
0x2d69cb: XOR ECX, ECX
0x2d69cd: CALL 0x004c6a00
0x2d69d2: JMP 0x002d6912
0x2d69d7: XOR R14D, R14D
0x2d69da: JMP 0x002d68ae
0x2d69df: CALL 0x006fd6b0
0x2d69e4: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d69f0 RVA 0x2d69f0 | Evidence ev_8907fb6d8f1b880af619c900e4e36f6bc2d9a58fcd56ab78a41f06d3f7e330e1 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d69f0:
0x2d69f0: PUSH RBP
0x2d69f1: MOV RBP, RSP
0x2d69f4: MOV R8, RDI
0x2d69f7: LEA RSI, [0x134f852]
0x2d69fe: LEA RDX, [0x267240]
0x2d6a05: LEA RCX, [0x138def9]
0x2d6a0c: MOV R9D, 0x2710
0x2d6a12: XOR EDI, EDI
0x2d6a14: CALL 0x0073dd40
0x2d6a19: MOV qword ptr [0x02d60d10], RAX
0x2d6a20: POP RBP
0x2d6a21: RET


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d6a30 RVA 0x2d6a30 | Evidence ev_4caf221428a8640f2b9c6afe4bc4f609e288f6a32d9f69021d815d90542992ac | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d6a30:
0x2d6a30: PUSH RBP
0x2d6a31: MOV RBP, RSP
0x2d6a34: PUSH RBX
0x2d6a35: PUSH RAX
0x2d6a36: MOV EAX, dword ptr [RDI + 0x8]
0x2d6a39: MOV RSI, qword ptr [RDI]
0x2d6a3c: MOV RDX, qword ptr [RDI + 0x10]
0x2d6a40: MOV EDI, EAX
0x2d6a42: CALL 0x003c6ad0
0x2d6a47: TEST EAX, EAX
0x2d6a49: JNZ 0x002d6a52
0x2d6a4b: ADD RSP, 0x8
0x2d6a4f: POP RBX
0x2d6a50: POP RBP
0x2d6a51: RET
0x2d6a52: MOV EBX, EAX
0x2d6a54: CALL 0x007f1950
0x2d6a59: MOVSXD RSI, EBX
0x2d6a5c: LEA RDI, [0x2d6a52]
0x2d6a63: CALL 0x007f18a0
0x2d6a68: LEA RSI, [0x1275da2]
0x2d6a6f: MOV EDI, 0x8b
0x2d6a74: MOV EDX, EBX
0x2d6a76: XOR EAX, EAX
0x2d6a78: CALL 0x00c9aa10
0x2d6a7d: UD2


; ===== LINKED/ADJACENT CONTEXT (reachability must be checked): sub_2d6a80 RVA 0x2d6a80 | Evidence ev_e71f1ec7e134858c9a21fbc6286e2b42a5c564999d5d85bdf621f4c9933e0b26 | Dossier file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.dossiers.jsonl.gz | Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e =====
sub_2d6a80:
0x2d6a80: PUSH RBP
0x2d6a81: MOV RBP, RSP
0x2d6a84: PUSH R15
0x2d6a86: PUSH R14
0x2d6a88: PUSH R13
0x2d6a8a: PUSH R12
0x2d6a8c: PUSH RBX
0x2d6a8d: SUB RSP, 0x98
0x2d6a94: LEA RDI, [0x12c781a]
0x2d6a9b: MOV ESI, 0x44
0x2d6aa0: MOV EDX, 0x7
0x2d6aa5: XOR ECX, ECX
0x2d6aa7: CALL 0x00926460
0x2d6aac: CALL 0x00ad0990
0x2d6ab1: MOV qword ptr [RBP + -0x58], RAX
0x2d6ab5: LEA RAX, [RAX + RAX*0x4]
0x2d6ab9: LEA R15, [0x2d60d20]
0x2d6ac0: LEA RBX, [0x2d60fa0]
0x2d6ac7: LEA R13, [0x2d60a40]
0x2d6ace: MOV qword ptr [RBP + -0xa0], RAX
0x2d6ad5: LEA RAX, [RAX + RAX*0x2]
0x2d6ad9: MOV qword ptr [RBP + -0x98], RAX
0x2d6ae0: RDTSC
0x2d6ae2: MOV EAX, EAX
0x2d6ae4: SHL RDX, 0x20
0x2d6ae8: MOV qword ptr [RBP + -0x60], 0x0
0x2d6af0: OR RDX, RAX
0x2d6af3: JMP 0x002d6b30
0x2d6b30: LEA RDI, [0x2d60028]
0x2d6b37: MOV qword ptr [RBP + -0x48], RDX
0x2d6b3b: XOR ESI, ESI
0x2d6b3d: XOR EDX, EDX
0x2d6b3f: XOR ECX, ECX
0x2d6b41: CALL 0x004c6a00
0x2d6b46: MOV ECX, dword ptr [0x02d60a30]
0x2d6b4c: MOV EAX, 0x0
0x2d6b51: MOV ESI, 0x280
0x2d6b56: INC ECX
0x2d6b58: CMP ECX, 0x4
0x2d6b5b: CMOVGE ECX, EAX
0x2d6b5e: MOVSXD R12, ECX
0x2d6b61: MOV dword ptr [0x02d60a30], ECX
0x2d6b67: RDTSC
0x2d6b69: MOV EAX, EAX
0x2d6b6b: SHL RDX, 0x20
0x2d6b6f: LEA RDI, [R12 + R12*0x4]
0x2d6b73: OR RDX, RAX
0x2d6b76: LEA RAX, [0x2d60cc0]
0x2d6b7d: MOV qword ptr [RAX + R12*0x8], RDX
0x2d6b81: LEA RAX, [0x2d60030]
0x2d6b88: MOV qword ptr [RBP + -0x68], RDI
0x2d6b8c: SHL RDI, 0x7
0x2d6b90: ADD RDI, RAX
0x2d6b93: CALL 0x00258ff0
0x2d6b98: MOV RAX, R12
0x2d6b9b: MOV RCX, R15
0x2d6b9e: MOV ESI, 0xa0
0x2d6ba3: SHL RAX, 0x5
0x2d6ba7: LEA R15, [RAX + RAX*0x4]
0x2d6bab: LEA RDI, [RCX + R15*0x1]
0x2d6baf: MOV qword ptr [RBP + -0xb0], RDI
0x2d6bb6: CALL 0x00258ff0
0x2d6bbb: LEA RDI, [RBX + R15*0x1]
0x2d6bbf: MOV ESI, 0xa0
0x2d6bc4: MOV qword ptr [RBP + -0xb8], RDI
0x2d6bcb: CALL 0x00258ff0
0x2d6bd0: LEA RAX, [0x2d61220]
0x2d6bd7: MOV ESI, 0xa0
0x2d6bdc: LEA R14, [RAX + R15*0x1]
0x2d6be0: MOV RDI, R14
0x2d6be3: CALL 0x00258ff0
0x2d6be8: LEA RBX, [R13 + R15*0x1]
0x2d6bed: MOV ESI, 0xa0
0x2d6bf2: MOV RDI, RBX
0x2d6bf5: CALL 0x00258ff0
0x2d6bfa: LEA RDI, [0x2d60cf0]
0x2d6c01: LEA RAX, [0x2d60ce0]
0x2d6c08: MOV qword ptr [RBP + -0x40], R12
0x2d6c0c: XOR ESI, ESI
0x2d6c0e: XOR EDX, EDX
0x2d6c10: XOR ECX, ECX
0x2d6c12: MOV dword ptr [RDI + R12*0x4], 0x0
0x2d6c1a: LEA RDI, [0x2d60028]
0x2d6c21: MOV dword ptr [RAX + R12*0x4], 0x0
0x2d6c29: CALL 0x004c6fa0
0x2d6c2e: LEA R12, [0x351e100]
0x2d6c35: XOR ESI, ESI
0x2d6c37: XOR EDX, EDX
0x2d6c39: MOV RDI, R12
0x2d6c3c: CALL 0x007d50c0
0x2d6c41: MOV R13D, dword ptr [0x0351e190]
0x2d6c48: MOV RDI, R12
0x2d6c4b: XOR ESI, ESI
0x2d6c4d: XOR EDX, EDX
0x2d6c4f: CALL 0x007d56e0
0x2d6c54: MOV EDI, 0xa
0x2d6c59: CALL 0x00616d40
0x2d6c5e: TEST AL, AL
0x2d6c60: JZ 0x002d6c88
0x2d6c62: LEA R12, [0x351e2c8]
0x2d6c69: XOR ESI, ESI
0x2d6c6b: XOR EDX, EDX
0x2d6c6d: MOV RDI, R12
0x2d6c70: CALL 0x007d50c0
0x2d6c75: ADD R13D, dword ptr [0x0351e358]
0x2d6c7c: MOV RDI, R12
0x2d6c7f: XOR ESI, ESI
0x2d6c81: XOR EDX, EDX
0x2d6c83: CALL 0x007d56e0
0x2d6c88: LEA R12, [0x351e490]
0x2d6c8f: XOR ESI, ESI
0x2d6c91: XOR EDX, EDX
0x2d6c93: MOV RDI, R12
0x2d6c96: CALL 0x007d50c0
0x2d6c9b: ADD R13D, dword ptr [0x0351e520]
0x2d6ca2: MOV RDI, R12
0x2d6ca5: XOR ESI, ESI
0x2d6ca7: XOR EDX, EDX
0x2d6ca9: CALL 0x007d56e0
0x2d6cae: MOV EDI, 0xa
0x2d6cb3: CALL 0x00616d40
0x2d6cb8: TEST AL, AL
0x2d6cba: JZ 0x002d6ce2
0x2d6cbc: LEA R12, [0x351e658]
0x2d6cc3: XOR ESI, ESI
0x2d6cc5: XOR EDX, EDX
0x2d6cc7: MOV RDI, R12
0x2d6cca: CALL 0x007d50c0
0x2d6ccf: ADD R13D, dword ptr [0x0351e6e8]
0x2d6cd6: MOV RDI, R12
0x2d6cd9: XOR ESI, ESI
0x2d6cdb: XOR EDX, EDX
0x2d6cdd: CALL 0x007d56e0
0x2d6ce2: MOV R12, qword ptr [RBP + -0x40]
0x2d6ce6: LEA RAX, [0x2d60d00]
0x2d6ced: MOV RDI, R14
0x2d6cf0: MOV ESI, 0x4
0x2d6cf5: MOV dword ptr [RAX + R12*0x4], R13D
0x2d6cf9: CALL 0x0043e490
0x2d6cfe: MOV RSI, qword ptr [0x039203d0]
0x2d6d05: LEA R14, [0x13ade0f]
0x2d6d0c: MOV ECX, 0x100
0x2d6d11: XOR EDX, EDX
0x2d6d13: MOV RDI, R14
0x2d6d16: CALL 0x00c06830
0x2d6d1b: MOV RDI, RBX
0x2d6d1e: MOV ESI, 0x4
0x2d6d23: CALL 0x00c09650
0x2d6d28: MOV RSI, qword ptr [0x039203d0]
0x2d6d2f: MOV RDI, R14
0x2d6d32: MOV ECX, 0x100
0x2d6d37: XOR EDX, EDX
0x2d6d39: CALL 0x00c06830
0x2d6d3e: MOV RAX, R12
0x2d6d41: MOV EDX, 0x88
0x2d6d46: LEA RDI, [0x3535ebc]
0x2d6d4d: SHL RAX, 0x7
0x2d6d51: LEA RSI, [RAX + R12*0x8]
0x2d6d55: LEA RAX, [0x2d614a0]
0x2d6d5c: ADD RSI, RAX
0x2d6d5f: CALL 0x00259be0
0x2d6d64: LEA RDI, [0x3589e60]
0x2d6d6b: XOR ESI, ESI
0x2d6d6d: XOR EDX, EDX
0x2d6d6f: XOR ECX, ECX
0x2d6d71: CALL 0x00c4b350
0x2d6d76: MOV R13, qword ptr [0x03589e80]
0x2d6d7d: TEST R13, R13
0x2d6d80: JZ 0x002d7240
0x2d6d86: LEA RAX, [0x2d60d20]
0x2d6d8d: LEA RSI, [RAX + R15*0x1 + 0x50]
0x2d6d92: LEA RCX, [RAX + R15*0x1 + 0x28]
0x2d6d97: LEA RAX, [RAX + R15*0x1 + 0x78]
0x2d6d9c: MOV qword ptr [RBP + -0x78], RSI
0x2d6da0: LEA RSI, [0x2d60fa0]
0x2d6da7: MOV qword ptr [RBP + -0x88], RCX
0x2d6dae: MOV qword ptr [RBP + -0x70], RAX
0x2d6db2: LEA RCX, [RSI + R15*0x1 + 0x28]
0x2d6db7: LEA RDX, [RSI + R15*0x1 + 0x50]
0x2d6dbc: LEA R15, [RSI + R15*0x1 + 0x78]
0x2d6dc1: MOV qword ptr [RBP + -0x90], RCX
0x2d6dc8: MOV qword ptr [RBP + -0x80], RDX
0x2d6dcc: NOP dword ptr [RAX]
0x2d6dd0: LEA R14, [R13 + 0x148]
0x2d6dd7: XOR ESI, ESI
0x2d6dd9: XOR EDX, EDX
0x2d6ddb: XOR ECX, ECX
0x2d6ddd: MOV RDI, R14
0x2d6de0: CALL 0x004c6a00
0x2d6de5: CMP dword ptr [R13 + 0xb8], 0x1
0x2d6ded: JNZ 0x002d6e40
0x2d6def: TEST byte ptr [R13 + 0xb1], 0x20
0x2d6df7: JNZ 0x002d6e40
0x2d6df9: MOV RBX, qword ptr [R13 + 0x200]
0x2d6e00: TEST RBX, RBX
0x2d6e03: JZ 0x002d6e40
0x2d6e05: NOP dword ptr CS:[RAX + RAX*0x1]
0x2d6e10: MOV EAX, dword ptr [RBX + 0x2e0]
0x2d6e16: TEST EAX, EAX
0x2d6e18: JLE 0x002d6e40
0x2d6e1a: LEA ECX, [RAX + 0x1]
0x2d6e1d: CMPXCHG.LOCK dword ptr [RBX + 0x2e0], ECX
0x2d6e25: JNZ 0x002d6e10
0x2d6e27: CMP RBX, qword ptr [R13 + 0x200]
0x2d6e2e: JZ 0x002d6e60
0x2d6e30: MOV RDI, RBX
0x2d6e33: CALL 0x002c61a0
0x2d6e38: NOP dword ptr [RAX + RAX*0x1]
0x2d6e40: MOV RDI, R14
0x2d6e43: XOR ESI, ESI
0x2d6e45: XOR EDX, EDX
0x2d6e47: XOR ECX, ECX
0x2d6e49: CALL 0x004c6fa0
0x2d6e4e: MOV R13, qword ptr [R13]
0x2d6e52: TEST R13, R13
0x2d6e55: JNZ 0x002d6dd0
0x2d6e5b: JMP 0x002d7240
0x2d6e60: TEST byte ptr [RBX + 0x244], 0x4
0x2d6e67: JNZ 0x002d6ee0
0x2d6e69: INC dword ptr [R13 + 0x358]
0x2d6e70: MOV RDI, R14
0x2d6e73: XOR ESI, ESI
0x2d6e75: XOR EDX, EDX
0x2d6e77: XOR ECX, ECX
0x2d6e79: CALL 0x004c6fa0
0x2d6e7e: LEA RDI, [0x3589e60]
0x2d6e85: XOR ESI, ESI
0x2d6e87: XOR EDX, EDX
0x2d6e89: CALL 0x00c4c300
0x2d6e8e: MOV RSI, qword ptr [0x039203d0]
0x2d6e95: LEA RDI, [0x13ade0f]
0x2d6e9c: MOV ECX, 0x100
0x2d6ea1: XOR EDX, EDX
0x2d6ea3: CALL 0x00c06830
0x2d6ea8: MOVZX EAX, byte ptr [RBX + 0x244]
0x2d6eaf: MOV qword ptr [RBP + -0x50], R15
0x2d6eb3: TEST AL, 0x10
0x2d6eb5: JNZ 0x002d6efb
0x2d6eb7: TEST AL, 0x8
0x2d6eb9: JZ 0x002d6ecc
0x2d6ebb: MOV RAX, qword ptr GS:[0x0]
0x2d6ec4: ADD.LOCK dword ptr [RAX + 0x5a8], 0x1
0x2d6ecc: LEA RDI, [RBX + 0x170]
0x2d6ed3: XOR ESI, ESI
0x2d6ed5: XOR EDX, EDX
0x2d6ed7: XOR ECX, ECX
0x2d6ed9: CALL 0x00c4b350
0x2d6ede: JMP 0x002d6f0d
0x2d6ee0: MOV RDI, R14
0x2d6ee3: XOR ESI, ESI
0x2d6ee5: XOR EDX, EDX
0x2d6ee7: XOR ECX, ECX
0x2d6ee9: CALL 0x004c6fa0
0x2d6eee: MOV RDI, RBX
0x2d6ef1: CALL 0x002c61a0
0x2d6ef6: JMP 0x002d6e4e
0x2d6efb: LEA RDI, [RBX + 0x1a8]
0x2d6f02: XOR ESI, ESI
0x2d6f04: XOR EDX, EDX
0x2d6f06: XOR ECX, ECX
0x2d6f08: CALL 0x004c6a00
0x2d6f0d: MOV R15, qword ptr [RBX + 0x8]
0x2d6f11: CMP R15, RBX
0x2d6f14: JZ 0x002d7021
0x2d6f1a: XOR EDX, EDX
0x2d6f1c: MOV dword ptr [RBP + -0x2c], 0x0
0x2d6f23: JMP 0x002d6f5d
0x2d6f25: MOV EAX, ECX
0x2d6f27: XOR EDX, EDX
0x2d6f29: DIV EDI
0x2d6f2b: ADD dword ptr [RBP + -0x38], ESI
0x2d6f2e: ADD dword ptr [RBP + -0x2c], EAX
0x2d6f31: MOV RDI, qword ptr [RBP + -0xa8]
0x2d6f38: XOR ESI, ESI
0x2d6f3a: XOR EDX, EDX
0x2d6f3c: CALL 0x007d56e0
0x2d6f41: MOV EDX, dword ptr [RBP + -0x38]
0x2d6f44: NOP word ptr CS:[RAX + RAX*0x1]
0x2d6f50: MOV R15, qword ptr [R15 + 0x8]
0x2d6f54: CMP R15, RBX
0x2d6f57: JZ 0x002d702a
0x2d6f5d: TEST byte ptr [R15 + 0x60], 0x2
0x2d6f62: JNZ 0x002d6f50
0x2d6f64: MOV R12, qword ptr [R15 + 0x50]
0x2d6f68: TEST R12, R12
0x2d6f6b: JZ 0x002d6f50
0x2d6f6d: CMP byte ptr [R12 + 0x150], 0x0
0x2d6f76: JNZ 0x002d6f50
0x2d6f78: MOVZX EAX, byte ptr [R12 + 0x9d]
0x2d6f81: CMP EAX, 0xa
0x2d6f84: JA 0x002d6f50
0x2d6f86: MOV ECX, 0x587
0x2d6f8b: BT ECX, EAX
0x2d6f8e: JNC 0x002d6f50
0x2d6f90: LEA RDI, [R12 + 0x18]
0x2d6f95: MOV dword ptr [RBP + -0x38], EDX
0x2d6f98: XOR ESI, ESI
0x2d6f9a: XOR EDX, EDX
0x2d6f9c: MOV qword ptr [RBP + -0xa8], RDI
0x2d6fa3: CALL 0x007d50c0
0x2d6fa8: MOV RDI, qword ptr [R12 + 0x88]
0x2d6fb0: TEST RDI, RDI
0x2d6fb3: JZ 0x002d6f31
0x2d6fb9: MOV EAX, dword ptr [R12 + 0x140]
0x2d6fc1: MOV ECX, dword ptr [R12 + 0x144]
0x2d6fc9: SUB RAX, RCX
0x2d6fcc: MOV RCX, qword ptr [R15 + 0x28]
0x2d6fd0: SUB RCX, qword ptr [R15 + 0x20]
0x2d6fd4: SAR RCX, 0xe
0x2d6fd8: IMUL RAX, RCX
0x2d6fdc: MOV RDX, RAX
0x2d6fdf: OR RDX, RDI
0x2d6fe2: SHR RDX, 0x20
0x2d6fe6: JZ 0x002d6ff2
0x2d6fe8: CQO
0x2d6fea: IDIV RDI
0x2d6fed: MOV RSI, RAX
0x2d6ff0: JMP 0x002d6ff8
0x2d6ff2: XOR EDX, EDX
0x2d6ff4: DIV EDI
0x2d6ff6: MOV ESI, EAX
0x2d6ff8: MOVSXD RAX, dword ptr [R12 + 0xa8]
0x2d7000: IMUL RCX, RAX
0x2d7004: MOV RAX, RCX
0x2d7007: OR RAX, RDI
0x2d700a: SHR RAX, 0x20
0x2d700e: JZ 0x002d6f25
0x2d7014: MOV RAX, RCX
0x2d7017: CQO
0x2d7019: IDIV RDI
0x2d701c: JMP 0x002d6f2b
0x2d7021: XOR EDX, EDX
0x2d7023: MOV dword ptr [RBP + -0x2c], 0x0
0x2d702a: TEST byte ptr [RBX + 0x244], 0x10
0x2d7031: MOV R12D, EDX
0x2d7034: JNZ 0x002d7080
0x2d7036: LEA RDI, [RBX + 0x170]
0x2d703d: XOR ESI, ESI
0x2d703f: XOR EDX, EDX
0x2d7041: CALL 0x00c4c300
0x2d7046: TEST byte ptr [RBX + 0x244], 0x8
0x2d704d: LEA R15, [0x2d60d20]
0x2d7054: JZ 0x002d7079
0x2d7056: MOV RAX, qword ptr GS:[0x0]
0x2d705f: MOV ECX, 0xffffffff
0x2d7064: XADD.LOCK dword ptr [RAX + 0x5a8], ECX
0x2d706c: CMP ECX, 0x80000001
0x2d7072: JNZ 0x002d7079
0x2d7074: CALL 0x006b7af0
0x2d7079: CALL 0x002c66f0
0x2d707e: JMP 0x002d7099
0x2d7080: LEA RDI, [RBX + 0x1a8]
0x2d7087: XOR ESI, ESI
0x2d7089: XOR EDX, EDX
0x2d708b: XOR ECX, ECX
0x2d708d: CALL 0x004c6fa0
0x2d7092: LEA R15, [0x2d60d20]
0x2d7099: MOV RDI, RBX
0x2d709c: CALL 0x002c61a0
0x2d70a1: TEST R12D, R12D
0x2d70a4: JLE 0x002d713c
0x2d70aa: MOV RBX, qword ptr [RBP + -0xb0]
0x2d70b1: CMP R12D, dword ptr [RBX + 0x4]
0x2d70b5: JLE 0x002d70bb
0x2d70b7: XOR EAX, EAX
0x2d70b9: JMP 0x002d70f4
0x2d70bb: MOV RCX, qword ptr [RBP + -0x88]
0x2d70c2: MOV EAX, 0x1
0x2d70c7: MOV RBX, RCX
0x2d70ca: CMP R12D, dword ptr [RCX + 0x4]
0x2d70ce: JG 0x002d70f4
0x2d70d0: MOV RCX, qword ptr [RBP + -0x78]
0x2d70d4: MOV EAX, 0x2
0x2d70d9: MOV RBX, RCX
0x2d70dc: CMP R12D, dword ptr [RCX + 0x4]
0x2d70e0: JG 0x002d70f4
0x2d70e2: MOV RCX, qword ptr [RBP + -0x70]
0x2d70e6: MOV EAX, 0x3
0x2d70eb: MOV RBX, RCX
0x2d70ee: CMP R12D, dword ptr [RCX + 0x4]
0x2d70f2: JLE 0x002d713c
0x2d70f4: MOV RDX, qword ptr [RBP + -0x68]
0x2d70f8: LEA RCX, [RAX + RAX*0x4]
0x2d70fc: XOR EAX, 0x3
0x2d70ff: MOV RDI, RBX
0x2d7102: SHL EAX, 0x3
0x2d7105: SHL RDX, 0x5
0x2d7109: ADD RDX, R15
0x2d710c: LEA RSI, [RDX + RCX*0x8 + 0x28]
0x2d7111: LEA RDX, [RAX + RAX*0x4]
0x2d7115: CALL 0x00259be0
0x2d711a: MOV EAX, dword ptr [R13 + 0xbc]
0x2d7121: LEA RDI, [R13 + 0x5e4]
0x2d7128: LEA RSI, [RBX + 0x8]
0x2d712c: MOV EDX, 0x20
0x2d7131: MOV dword ptr [RBX], EAX
0x2d7133: CALL 0x00259be0
0x2d7138: MOV dword ptr [RBX + 0x4], R12D
0x2d713c: MOV RBX, qword ptr [RBP + -0xb8]
0x2d7143: MOV R12D, dword ptr [RBP + -0x2c]
0x2d7147: CMP R12D, dword ptr [RBX + 0x4]
0x2d714b: JLE 0x002d7155
0x2d714d: MOV R15, qword ptr [RBP + -0x50]
0x2d7151: XOR EAX, EAX
0x2d7153: JMP 0x002d718e
0x2d7155: MOV RCX, qword ptr [RBP + -0x90]
0x2d715c: MOV R15, qword ptr [RBP + -0x50]
0x2d7160: MOV EAX, 0x1
0x2d7165: MOV RBX, RCX
0x2d7168: CMP R12D, dword ptr [RCX + 0x4]
0x2d716c: JG 0x002d718e
0x2d716e: MOV RCX, qword ptr [RBP + -0x80]
0x2d7172: MOV EAX, 0x2
0x2d7177: MOV RBX, RCX
0x2d717a: CMP R12D, dword ptr [RCX + 0x4]
0x2d717e: JG 0x002d718e
0x2d7180: MOV EAX, 0x3
0x2d7185: MOV RBX, R15
0x2d7188: CMP R12D, dword ptr [R15 + 0x4]
0x2d718c: JLE 0x002d71e0
0x2d718e: MOV RDX, qword ptr [RBP + -0x68]
0x2d7192: LEA RCX, [RAX + RAX*0x4]
0x2d7196: XOR EAX, 0x3
0x2d7199: LEA RSI, [0x2d60fa0]
0x2d71a0: MOV RDI, RBX
0x2d71a3: SHL EAX, 0x3
0x2d71a6: SHL RDX, 0x5
0x2d71aa: ADD RDX, RSI
0x2d71ad: LEA RSI, [RDX + RCX*0x8 + 0x28]
0x2d71b2: LEA RDX, [RAX + RAX*0x4]
0x2d71b6: CALL 0x00259be0
0x2d71bb: MOV EAX, dword ptr [R13 + 0xbc]
0x2d71c2: LEA RDI, [R13 + 0x5e4]
0x2d71c9: MOV EDX, 0x20
0x2d71ce: MOV dword ptr [RBX], EAX
0x2d71d0: MOV dword ptr [RBX + 0x4], R12D
0x2d71d4: ADD RBX, 0x8
0x2d71d8: MOV RSI, RBX
0x2d71db: CALL 0x00259be0
0x2d71e0: LEA RDI, [0x3589e60]
0x2d71e7: XOR ESI, ESI
0x2d71e9: XOR EDX, EDX
0x2d71eb: XOR ECX, ECX
0x2d71ed: CALL 0x00c4b350
0x2d71f2: MOV RDI, R14
0x2d71f5: XOR ESI, ESI
0x2d71f7: XOR EDX, EDX
0x2d71f9: XOR ECX, ECX
0x2d71fb: CALL 0x004c6a00
0x2d7200: MOVZX ECX, byte ptr [R13 + 0xb1]
0x2d7208: MOV EAX, dword ptr [R13 + 0x358]
0x2d720f: SHR CL, 0x5
0x2d7212: DEC EAX
0x2d7214: SETZ DL
0x2d7217: MOV dword ptr [R13 + 0x358], EAX
0x2d721e: AND DL, CL
0x2d7220: CMP DL, 0x1
0x2d7223: JNZ 0x002d6e40
0x2d7229: LEA RDI, [R13 + 0x358]
0x2d7230: CALL 0x00c06910
0x2d7235: JMP 0x002d6e40
0x2d7240: LEA RDI, [0x3589e60]
0x2d7247: XOR ESI, ESI
0x2d7249: XOR EDX, EDX
0x2d724b: CALL 0x00c4c300
0x2d7250: LEA RDI, [0x351e0b8]
0x2d7257: XOR ESI, ESI
0x2d7259: XOR EDX, EDX
0x2d725b: XOR ECX, ECX
0x2d725d: CALL 0x004c6a00
0x2d7262: MOV R14, qword ptr [0x0351e098]
0x2d7269: LEA R15, [0x2d60d20]
0x2d7270: MOV R13D, 0x587
0x2d7276: TEST R14, R14
0x2d7279: JNZ 0x002d72c9
0x2d727b: LEA RDI, [0x351e0b8]
0x2d7282: XOR ESI, ESI
0x2d7284: XOR EDX, EDX
0x2d7286: XOR ECX, ECX
0x2d7288: CALL 0x004c6fa0
0x2d728d: RDTSC
0x2d728f: MOV EAX, EAX
0x2d7291: SHL RDX, 0x20
0x2d7295: OR RDX, RAX
0x2d7298: MOV RAX, RDX
0x2d729b: SUB RAX, qword ptr [RBP + -0x60]
0x2d729f: CMP qword ptr [RBP + -0x98], RAX
0x2d72a6: JBE 0x002d7340
0x2d72ac: MOV RDI, qword ptr [RBP + -0x48]
0x2d72b0: JMP 0x002d7863
0x2d72c0: MOV R14, qword ptr [R14 + 0x40]
0x2d72c4: TEST R14, R14
0x2d72c7: JZ 0x002d727b
0x2d72c9: CMP byte ptr [R14 + 0x150], 0x0
0x2d72d1: JNZ 0x002d72c0
0x2d72d3: MOVZX EAX, byte ptr [R14 + 0x9d]
0x2d72db: CMP EAX, 0xa
0x2d72de: JA 0x002d72c0
0x2d72e0: BT R13D, EAX
0x2d72e4: JNC 0x002d72c0
0x2d72e6: LEA RBX, [R14 + 0x18]
0x2d72ea: XOR ESI, ESI
0x2d72ec: XOR EDX, EDX
0x2d72ee: MOV RDI, RBX
0x2d72f1: CALL 0x007d46a0
0x2d72f6: MOV R15D, dword ptr [R14 + 0x140]
0x2d72fd: MOV R12D, dword ptr [R14 + 0x144]
0x2d7304: MOV RDI, RBX
0x2d7307: MOV qword ptr [R14 + 0x140], 0x0
0x2d7312: XOR ESI, ESI
0x2d7314: XOR EDX, EDX
0x2d7316: CALL 0x007d4eb0
0x2d731b: MOV RCX, qword ptr [RBP + -0x40]
0x2d731f: LEA RAX, [0x2d60ce0]
0x2d7326: LEA RDX, [0x2d60cf0]
0x2d732d: ADD dword ptr [RAX + RCX*0x4], R15D
0x2d7331: ADD dword ptr [RDX + RCX*0x4], R12D
0x2d7335: LEA R15, [0x2d60d20]
0x2d733c: JMP 0x002d72c0
0x2d7340: XOR R13D, R13D
0x2d7343: XCHG dword ptr [0x02d60a34], R13D
0x2d734a: MOV RDI, qword ptr [RBP + -0x48]
0x2d734e: TEST R13D, R13D
0x2d7351: JZ 0x002d7863
0x2d7357: MOV qword ptr [RBP + -0x38], RDX
0x2d735b: CALL 0x00ad0990
0x2d7360: LEA RDI, [0x13ade17]
0x2d7367: MOV ESI, R13D
0x2d736a: MOV RBX, RAX
0x2d736d: XOR EAX, EAX
0x2d736f: CALL 0x0025d410
0x2d7374: MOV R12D, dword ptr [0x02d60a30]
0x2d737b: MOV qword ptr [RBP + -0x40], RBX
0x2d737f: ADD R12D, -0x3
0x2d7383: JMP 0x002d73fa
0x2d73fa: MOV EAX, R12D
0x2d73fd: LEA RCX, [0x2d60cc0]
0x2d7404: LEA R15, [0x2d61220]
0x2d740b: SHR EAX, 0x1f
0x2d740e: LEA EAX, [R12 + RAX*0x4]
0x2d7412: MOVSXD R13, EAX
0x2d7415: MOV RAX, qword ptr [RCX + R13*0x8]
0x2d7419: MOV RCX, RAX
0x2d741c: OR RCX, RBX
0x2d741f: SHR RCX, 0x20
0x2d7423: JZ 0x002d7430
0x2d7425: XOR EDX, EDX
0x2d7427: DIV RBX
0x2d742a: MOV RSI, RAX
0x2d742d: JMP 0x002d7436
0x2d7430: XOR EDX, EDX
0x2d7432: DIV EBX
0x2d7434: MOV ESI, EAX
0x2d7436: IMUL RAX, RDX, 0x3e8
0x2d743d: MOV RCX, RAX
0x2d7440: OR RCX, RBX
0x2d7443: SHR RCX, 0x20
0x2d7447: JZ 0x002d7450
0x2d7449: XOR EDX, EDX
0x2d744b: DIV RBX
0x2d744e: JMP 0x002d7454
0x2d7450: XOR EDX, EDX
0x2d7452: DIV EBX
0x2d7454: MOV RDX, RAX
0x2d7457: LEA RDI, [0x1383664]
0x2d745e: XOR EAX, EAX
0x2d7460: CALL 0x0025d410
0x2d7465: MOV RAX, R13
0x2d7468: LEA RBX, [0x2d614a0]
0x2d746f: LEA RDI, [0x1289d09]
0x2d7476: SHL RAX, 0x7
0x2d747a: LEA R14, [RAX + R13*0x8]
0x2d747e: XOR EAX, EAX
0x2d7480: MOV ESI, dword ptr [RBX + R14*0x1 + 0x54]
0x2d7485: MOV EDX, dword ptr [RBX + R14*0x1 + 0x64]
0x2d748a: MOV ECX, dword ptr [RBX + R14*0x1 + 0x78]
0x2d748f: CALL 0x0025d410
0x2d7494: MOV ESI, dword ptr [RBX + R14*0x1 + 0x74]
0x2d7499: MOV ECX, dword ptr [RBX + R14*0x1 + 0x68]
0x2d749e: MOV EDX, dword ptr [RBX + R14*0x1 + 0x6c]
0x2d74a3: LEA RDI, [0x136ecd7]
0x2d74aa: XOR EAX, EAX
0x2d74ac: CALL 0x0025d410
0x2d74b1: LEA RAX, [0x2d60d00]
0x2d74b8: MOV ECX, 0x2c06
0x2d74bd: LEA RDI, [0x13ade65]
0x2d74c4: MOVSXD RAX, dword ptr [RAX + R13*0x4]
0x2d74c8: BEXTR RSI, RAX, RCX
0x2d74cd: XOR EAX, EAX
0x2d74cf: CALL 0x0025d410
0x2d74d4: LEA R14, [R13 + R13*0x4]
0x2d74d9: LEA RBX, [0x2d60a40]
0x2d74e0: SHL R14, 0x5
0x2d74e4: MOV RDX, qword ptr [R14 + RBX*0x1]
0x2d74e8: TEST RDX, RDX
0x2d74eb: JZ 0x002d7590
0x2d74f1: LEA RCX, [RBX + R14*0x1]
0x2d74f5: SHR RDX, 0x14
0x2d74f9: LEA RDI, [0x131affa]
0x2d7500: MOV ESI, 0x1
0x2d7505: XOR EAX, EAX
0x2d7507: ADD RCX, 0x8
0x2d750b: CALL 0x0025d410
0x2d7510: MOV RDX, qword ptr [R14 + RBX*0x1 + 0x28]
0x2d7515: TEST RDX, RDX
0x2d7518: JZ 0x002d7590
0x2d751a: LEA RCX, [R14 + RBX*0x1 + 0x28]
0x2d751f: SHR RDX, 0x14
0x2d7523: LEA RDI, [0x131affa]
0x2d752a: MOV ESI, 0x2
0x2d752f: XOR EAX, EAX
0x2d7531: ADD RCX, 0x8
0x2d7535: CALL 0x0025d410
0x2d753a: MOV RDX, qword ptr [R14 + RBX*0x1 + 0x50]
0x2d753f: TEST RDX, RDX
0x2d7542: JZ 0x002d7590
0x2d7544: LEA RCX, [R14 + RBX*0x1 + 0x50]
0x2d7549: SHR RDX, 0x14
0x2d754d: LEA RDI, [0x131affa]
0x2d7554: MOV ESI, 0x3
0x2d7559: XOR EAX, EAX
0x2d755b: ADD RCX, 0x8
0x2d755f: CALL 0x0025d410
0x2d7564: MOV RDX, qword ptr [R14 + RBX*0x1 + 0x78]
0x2d7569: TEST RDX, RDX
0x2d756c: JZ 0x002d7590
0x2d756e: LEA RCX, [R14 + RBX*0x1 + 0x78]
0x2d7573: SHR RDX, 0x14
0x2d7577: LEA RDI, [0x131affa]
0x2d757e: MOV ESI, 0x4
0x2d7583: XOR EAX, EAX
0x2d7585: ADD RCX, 0x8
0x2d7589: CALL 0x0025d410
0x2d758e: NOP
0x2d7590: MOV RDX, qword ptr [R14 + R15*0x1]
0x2d7594: TEST RDX, RDX
0x2d7597: JZ 0x002d7640
0x2d759d: LEA RCX, [R15 + R14*0x1]
0x2d75a1: SHR RDX, 0x14
0x2d75a5: LEA RDI, [0x12c7827]
0x2d75ac: MOV ESI, 0x1
0x2d75b1: XOR EAX, EAX
0x2d75b3: ADD RCX, 0x8
0x2d75b7: CALL 0x0025d410
0x2d75bc: MOV RDX, qword ptr [R14 + R15*0x1 + 0x28]
0x2d75c1: TEST RDX, RDX
0x2d75c4: JZ 0x002d7640
0x2d75c6: LEA RCX, [R14 + R15*0x1 + 0x28]
0x2d75cb: SHR RDX, 0x14
0x2d75cf: LEA RDI, [0x12c7827]
0x2d75d6: MOV ESI, 0x2
0x2d75db: XOR EAX, EAX
0x2d75dd: ADD RCX, 0x8
0x2d75e1: CALL 0x0025d410
0x2d75e6: MOV RDX, qword ptr [R14 + R15*0x1 + 0x50]
0x2d75eb: TEST RDX, RDX
0x2d75ee: JZ 0x002d7640
0x2d75f0: LEA RCX, [R14 + R15*0x1 + 0x50]
0x2d75f5: SHR RDX, 0x14
0x2d75f9: LEA RDI, [0x12c7827]
0x2d7600: MOV ESI, 0x3
0x2d7605: XOR EAX, EAX
0x2d7607: ADD RCX, 0x8
0x2d760b: CALL 0x0025d410
0x2d7610: MOV RDX, qword ptr [R14 + R15*0x1 + 0x78]
0x2d7615: TEST RDX, RDX
0x2d7618: JZ 0x002d7640
0x2d761a: LEA RCX, [R14 + R15*0x1 + 0x78]
0x2d761f: SHR RDX, 0x14
0x2d7623: LEA RDI, [0x12c7827]
0x2d762a: MOV ESI, 0x4
0x2d762f: XOR EAX, EAX
0x2d7631: ADD RCX, 0x8
0x2d7635: CALL 0x0025d410
0x2d763a: NOP word ptr [RAX + RAX*0x1]
0x2d7640: LEA RBX, [0x2d60d20]
0x2d7647: MOV ECX, dword ptr [R14 + RBX*0x1]
0x2d764b: TEST ECX, ECX
0x2d764d: JZ 0x002d7760
0x2d7653: LEA R8, [RBX + R14*0x1]
0x2d7657: MOV RAX, -0x3333333333333333
0x2d7661: LEA RDI, [0x13a3348]
0x2d7668: MOV ESI, 0x1
0x2d766d: MOVSXD RDX, dword ptr [R8 + 0x4]
0x2d7671: ADD R8, 0x8
0x2d7675: SHL RDX, 0xe
0x2d7679: MULX RDX, RDX, RAX
0x2d767e: XOR EAX, EAX
0x2d7680: SHR RDX, 0x16
0x2d7684: CALL 0x0025d410
0x2d7689: MOV ECX, dword ptr [R14 + RBX*0x1 + 0x28]
0x2d768e: TEST ECX, ECX
0x2d7690: JZ 0x002d7760
0x2d7696: LEA R8, [R14 + RBX*0x1 + 0x28]
0x2d769b: MOV RAX, -0x3333333333333333
0x2d76a5: LEA RDI, [0x13a3348]
0x2d76ac: MOV ESI, 0x2
0x2d76b1: MOVSXD RDX, dword ptr [R8 + 0x4]
0x2d76b5: ADD R8, 0x8
0x2d76b9: SHL RDX, 0xe
0x2d76bd: MULX RDX, RDX, RAX
0x2d76c2: XOR EAX, EAX
0x2d76c4: SHR RDX, 0x16
0x2d76c8: CALL 0x0025d410
0x2d76cd: MOV ECX, dword ptr [R14 + RBX*0x1 + 0x50]
0x2d76d2: TEST ECX, ECX
0x2d76d4: JZ 0x002d7760
0x2d76da: LEA R8, [R14 + RBX*0x1 + 0x50]
0x2d76df: MOV RAX, -0x3333333333333333
0x2d76e9: LEA RDI, [0x13a3348]


; ===== SUPPLEMENTAL GNU objdump full linear disassembly of every original4096 input byte =====
; Source raw file /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/handler_675.bin
; This is independent linear decoding, not REA function discovery; padding/data may decode as instructions.

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/handler_675.bin:     file format binary


Disassembly of section .data:

0000000000265458 <.data>:
  265458:	e9 93 e2 06 00       	jmp    0x2d36f0
  26545d:	cc                   	int3
  26545e:	cc                   	int3
  26545f:	cc                   	int3
  265460:	e9 cb e2 06 00       	jmp    0x2d3730
  265465:	cc                   	int3
  265466:	cc                   	int3
  265467:	cc                   	int3
  265468:	e9 13 bd 07 00       	jmp    0x2e1180
  26546d:	cc                   	int3
  26546e:	cc                   	int3
  26546f:	cc                   	int3
  265470:	e9 5b 0b 08 00       	jmp    0x2e5fd0
  265475:	cc                   	int3
  265476:	cc                   	int3
  265477:	cc                   	int3
  265478:	e9 b3 a6 08 00       	jmp    0x2efb30
  26547d:	cc                   	int3
  26547e:	cc                   	int3
  26547f:	cc                   	int3
  265480:	e9 7b a8 08 00       	jmp    0x2efd00
  265485:	cc                   	int3
  265486:	cc                   	int3
  265487:	cc                   	int3
  265488:	e9 d3 e4 09 00       	jmp    0x303960
  26548d:	cc                   	int3
  26548e:	cc                   	int3
  26548f:	cc                   	int3
  265490:	e9 fb e4 09 00       	jmp    0x303990
  265495:	cc                   	int3
  265496:	cc                   	int3
  265497:	cc                   	int3
  265498:	e9 23 e5 09 00       	jmp    0x3039c0
  26549d:	cc                   	int3
  26549e:	cc                   	int3
  26549f:	cc                   	int3
  2654a0:	e9 3b ff 09 00       	jmp    0x3053e0
  2654a5:	cc                   	int3
  2654a6:	cc                   	int3
  2654a7:	cc                   	int3
  2654a8:	e9 23 05 0a 00       	jmp    0x3059d0
  2654ad:	cc                   	int3
  2654ae:	cc                   	int3
  2654af:	cc                   	int3
  2654b0:	e9 0b 0a 0a 00       	jmp    0x305ec0
  2654b5:	cc                   	int3
  2654b6:	cc                   	int3
  2654b7:	cc                   	int3
  2654b8:	e9 a3 0a 0a 00       	jmp    0x305f60
  2654bd:	cc                   	int3
  2654be:	cc                   	int3
  2654bf:	cc                   	int3
  2654c0:	e9 ab 0b 0a 00       	jmp    0x306070
  2654c5:	cc                   	int3
  2654c6:	cc                   	int3
  2654c7:	cc                   	int3
  2654c8:	e9 83 76 0a 00       	jmp    0x30cb50
  2654cd:	cc                   	int3
  2654ce:	cc                   	int3
  2654cf:	cc                   	int3
  2654d0:	e9 bb 76 0a 00       	jmp    0x30cb90
  2654d5:	cc                   	int3
  2654d6:	cc                   	int3
  2654d7:	cc                   	int3
  2654d8:	e9 e3 88 0a 00       	jmp    0x30ddc0
  2654dd:	cc                   	int3
  2654de:	cc                   	int3
  2654df:	cc                   	int3
  2654e0:	e9 3b ad 0a 00       	jmp    0x310220
  2654e5:	cc                   	int3
  2654e6:	cc                   	int3
  2654e7:	cc                   	int3
  2654e8:	e9 e3 d9 0a 00       	jmp    0x312ed0
  2654ed:	cc                   	int3
  2654ee:	cc                   	int3
  2654ef:	cc                   	int3
  2654f0:	e9 6b dc 0a 00       	jmp    0x313160
  2654f5:	cc                   	int3
  2654f6:	cc                   	int3
  2654f7:	cc                   	int3
  2654f8:	e9 e3 df 0a 00       	jmp    0x3134e0
  2654fd:	cc                   	int3
  2654fe:	cc                   	int3
  2654ff:	cc                   	int3
  265500:	e9 1b fb 0a 00       	jmp    0x315020
  265505:	cc                   	int3
  265506:	cc                   	int3
  265507:	cc                   	int3
  265508:	e9 13 fd 0a 00       	jmp    0x315220
  26550d:	cc                   	int3
  26550e:	cc                   	int3
  26550f:	cc                   	int3
  265510:	e9 7b fd 0a 00       	jmp    0x315290
  265515:	cc                   	int3
  265516:	cc                   	int3
  265517:	cc                   	int3
  265518:	e9 93 58 0c 00       	jmp    0x32adb0
  26551d:	cc                   	int3
  26551e:	cc                   	int3
  26551f:	cc                   	int3
  265520:	e9 5b 8a 0c 00       	jmp    0x32df80
  265525:	cc                   	int3
  265526:	cc                   	int3
  265527:	cc                   	int3
  265528:	e9 43 8c 0c 00       	jmp    0x32e170
  26552d:	cc                   	int3
  26552e:	cc                   	int3
  26552f:	cc                   	int3
  265530:	e9 6b ba 0c 00       	jmp    0x330fa0
  265535:	cc                   	int3
  265536:	cc                   	int3
  265537:	cc                   	int3
  265538:	e9 c3 bb 0c 00       	jmp    0x331100
  26553d:	cc                   	int3
  26553e:	cc                   	int3
  26553f:	cc                   	int3
  265540:	e9 5b 3b 0e 00       	jmp    0x3490a0
  265545:	cc                   	int3
  265546:	cc                   	int3
  265547:	cc                   	int3
  265548:	e9 c3 3b 0e 00       	jmp    0x349110
  26554d:	cc                   	int3
  26554e:	cc                   	int3
  26554f:	cc                   	int3
  265550:	e9 8b 3c 0e 00       	jmp    0x3491e0
  265555:	cc                   	int3
  265556:	cc                   	int3
  265557:	cc                   	int3
  265558:	e9 03 4b 0e 00       	jmp    0x34a060
  26555d:	cc                   	int3
  26555e:	cc                   	int3
  26555f:	cc                   	int3
  265560:	e9 0b 4f 0e 00       	jmp    0x34a470
  265565:	cc                   	int3
  265566:	cc                   	int3
  265567:	cc                   	int3
  265568:	e9 c3 57 0e 00       	jmp    0x34ad30
  26556d:	cc                   	int3
  26556e:	cc                   	int3
  26556f:	cc                   	int3
  265570:	e9 1b 59 0e 00       	jmp    0x34ae90
  265575:	cc                   	int3
  265576:	cc                   	int3
  265577:	cc                   	int3
  265578:	e9 93 5f 0e 00       	jmp    0x34b510
  26557d:	cc                   	int3
  26557e:	cc                   	int3
  26557f:	cc                   	int3
  265580:	e9 0b 62 0e 00       	jmp    0x34b790
  265585:	cc                   	int3
  265586:	cc                   	int3
  265587:	cc                   	int3
  265588:	e9 23 62 0e 00       	jmp    0x34b7b0
  26558d:	cc                   	int3
  26558e:	cc                   	int3
  26558f:	cc                   	int3
  265590:	e9 cb 66 0e 00       	jmp    0x34bc60
  265595:	cc                   	int3
  265596:	cc                   	int3
  265597:	cc                   	int3
  265598:	e9 23 68 0e 00       	jmp    0x34bdc0
  26559d:	cc                   	int3
  26559e:	cc                   	int3
  26559f:	cc                   	int3
  2655a0:	e9 ab 6d 0e 00       	jmp    0x34c350
  2655a5:	cc                   	int3
  2655a6:	cc                   	int3
  2655a7:	cc                   	int3
  2655a8:	e9 c3 70 0e 00       	jmp    0x34c670
  2655ad:	cc                   	int3
  2655ae:	cc                   	int3
  2655af:	cc                   	int3
  2655b0:	e9 9b 71 0e 00       	jmp    0x34c750
  2655b5:	cc                   	int3
  2655b6:	cc                   	int3
  2655b7:	cc                   	int3
  2655b8:	e9 53 72 0e 00       	jmp    0x34c810
  2655bd:	cc                   	int3
  2655be:	cc                   	int3
  2655bf:	cc                   	int3
  2655c0:	e9 5b 72 0e 00       	jmp    0x34c820
  2655c5:	cc                   	int3
  2655c6:	cc                   	int3
  2655c7:	cc                   	int3
  2655c8:	e9 e3 72 0e 00       	jmp    0x34c8b0
  2655cd:	cc                   	int3
  2655ce:	cc                   	int3
  2655cf:	cc                   	int3
  2655d0:	e9 bb 73 0e 00       	jmp    0x34c990
  2655d5:	cc                   	int3
  2655d6:	cc                   	int3
  2655d7:	cc                   	int3
  2655d8:	e9 c3 74 0e 00       	jmp    0x34caa0
  2655dd:	cc                   	int3
  2655de:	cc                   	int3
  2655df:	cc                   	int3
  2655e0:	e9 6b 78 0e 00       	jmp    0x34ce50
  2655e5:	cc                   	int3
  2655e6:	cc                   	int3
  2655e7:	cc                   	int3
  2655e8:	e9 b3 79 0e 00       	jmp    0x34cfa0
  2655ed:	cc                   	int3
  2655ee:	cc                   	int3
  2655ef:	cc                   	int3
  2655f0:	e9 ab 74 11 00       	jmp    0x37caa0
  2655f5:	cc                   	int3
  2655f6:	cc                   	int3
  2655f7:	cc                   	int3
  2655f8:	e9 23 75 11 00       	jmp    0x37cb20
  2655fd:	cc                   	int3
  2655fe:	cc                   	int3
  2655ff:	cc                   	int3
  265600:	e9 3b 96 11 00       	jmp    0x37ec40
  265605:	cc                   	int3
  265606:	cc                   	int3
  265607:	cc                   	int3
  265608:	e9 83 a4 11 00       	jmp    0x37fa90
  26560d:	cc                   	int3
  26560e:	cc                   	int3
  26560f:	cc                   	int3
  265610:	e9 8b a4 11 00       	jmp    0x37faa0
  265615:	cc                   	int3
  265616:	cc                   	int3
  265617:	cc                   	int3
  265618:	e9 a3 a5 11 00       	jmp    0x37fbc0
  26561d:	cc                   	int3
  26561e:	cc                   	int3
  26561f:	cc                   	int3
  265620:	e9 4b a6 11 00       	jmp    0x37fc70
  265625:	cc                   	int3
  265626:	cc                   	int3
  265627:	cc                   	int3
  265628:	e9 63 a6 11 00       	jmp    0x37fc90
  26562d:	cc                   	int3
  26562e:	cc                   	int3
  26562f:	cc                   	int3
  265630:	e9 3b a7 11 00       	jmp    0x37fd70
  265635:	cc                   	int3
  265636:	cc                   	int3
  265637:	cc                   	int3
  265638:	e9 43 a7 11 00       	jmp    0x37fd80
  26563d:	cc                   	int3
  26563e:	cc                   	int3
  26563f:	cc                   	int3
  265640:	e9 1b ac 11 00       	jmp    0x380260
  265645:	cc                   	int3
  265646:	cc                   	int3
  265647:	cc                   	int3
  265648:	e9 13 b1 11 00       	jmp    0x380760
  26564d:	cc                   	int3
  26564e:	cc                   	int3
  26564f:	cc                   	int3
  265650:	e9 3b b6 11 00       	jmp    0x380c90
  265655:	cc                   	int3
  265656:	cc                   	int3
  265657:	cc                   	int3
  265658:	e9 e3 ba 11 00       	jmp    0x381140
  26565d:	cc                   	int3
  26565e:	cc                   	int3
  26565f:	cc                   	int3
  265660:	e9 cb bb 11 00       	jmp    0x381230
  265665:	cc                   	int3
  265666:	cc                   	int3
  265667:	cc                   	int3
  265668:	e9 c3 bc 11 00       	jmp    0x381330
  26566d:	cc                   	int3
  26566e:	cc                   	int3
  26566f:	cc                   	int3
  265670:	e9 bb bd 11 00       	jmp    0x381430
  265675:	cc                   	int3
  265676:	cc                   	int3
  265677:	cc                   	int3
  265678:	e9 83 c2 11 00       	jmp    0x381900
  26567d:	cc                   	int3
  26567e:	cc                   	int3
  26567f:	cc                   	int3
  265680:	e9 6b c3 11 00       	jmp    0x3819f0
  265685:	cc                   	int3
  265686:	cc                   	int3
  265687:	cc                   	int3
  265688:	e9 83 c3 11 00       	jmp    0x381a10
  26568d:	cc                   	int3
  26568e:	cc                   	int3
  26568f:	cc                   	int3
  265690:	e9 5b c4 11 00       	jmp    0x381af0
  265695:	cc                   	int3
  265696:	cc                   	int3
  265697:	cc                   	int3
  265698:	e9 d3 c7 11 00       	jmp    0x381e70
  26569d:	cc                   	int3
  26569e:	cc                   	int3
  26569f:	cc                   	int3
  2656a0:	e9 db cb 11 00       	jmp    0x382280
  2656a5:	cc                   	int3
  2656a6:	cc                   	int3
  2656a7:	cc                   	int3
  2656a8:	e9 d3 cd 11 00       	jmp    0x382480
  2656ad:	cc                   	int3
  2656ae:	cc                   	int3
  2656af:	cc                   	int3
  2656b0:	e9 db ce 11 00       	jmp    0x382590
  2656b5:	cc                   	int3
  2656b6:	cc                   	int3
  2656b7:	cc                   	int3
  2656b8:	e9 a3 d3 11 00       	jmp    0x382a60
  2656bd:	cc                   	int3
  2656be:	cc                   	int3
  2656bf:	cc                   	int3
  2656c0:	e9 5b da 11 00       	jmp    0x383120
  2656c5:	cc                   	int3
  2656c6:	cc                   	int3
  2656c7:	cc                   	int3
  2656c8:	e9 e3 de 11 00       	jmp    0x3835b0
  2656cd:	cc                   	int3
  2656ce:	cc                   	int3
  2656cf:	cc                   	int3
  2656d0:	e9 1b e1 11 00       	jmp    0x3837f0
  2656d5:	cc                   	int3
  2656d6:	cc                   	int3
  2656d7:	cc                   	int3
  2656d8:	e9 23 e1 11 00       	jmp    0x383800
  2656dd:	cc                   	int3
  2656de:	cc                   	int3
  2656df:	cc                   	int3
  2656e0:	e9 bb 4b 12 00       	jmp    0x38a2a0
  2656e5:	cc                   	int3
  2656e6:	cc                   	int3
  2656e7:	cc                   	int3
  2656e8:	e9 93 9c 18 00       	jmp    0x3ef380
  2656ed:	cc                   	int3
  2656ee:	cc                   	int3
  2656ef:	cc                   	int3
  2656f0:	e9 eb 09 14 00       	jmp    0x3a60e0
  2656f5:	cc                   	int3
  2656f6:	cc                   	int3
  2656f7:	cc                   	int3
  2656f8:	e9 03 94 14 00       	jmp    0x3aeb00
  2656fd:	cc                   	int3
  2656fe:	cc                   	int3
  2656ff:	cc                   	int3
  265700:	e9 eb 94 14 00       	jmp    0x3aebf0
  265705:	cc                   	int3
  265706:	cc                   	int3
  265707:	cc                   	int3
  265708:	e9 d3 a1 14 00       	jmp    0x3af8e0
  26570d:	cc                   	int3
  26570e:	cc                   	int3
  26570f:	cc                   	int3
  265710:	e9 db a1 14 00       	jmp    0x3af8f0
  265715:	cc                   	int3
  265716:	cc                   	int3
  265717:	cc                   	int3
  265718:	e9 e3 a1 14 00       	jmp    0x3af900
  26571d:	cc                   	int3
  26571e:	cc                   	int3
  26571f:	cc                   	int3
  265720:	e9 cb aa 14 00       	jmp    0x3b01f0
  265725:	cc                   	int3
  265726:	cc                   	int3
  265727:	cc                   	int3
  265728:	e9 83 b8 14 00       	jmp    0x3b0fb0
  26572d:	cc                   	int3
  26572e:	cc                   	int3
  26572f:	cc                   	int3
  265730:	e9 3b bf 14 00       	jmp    0x3b1670
  265735:	cc                   	int3
  265736:	cc                   	int3
  265737:	cc                   	int3
  265738:	e9 43 bf 14 00       	jmp    0x3b1680
  26573d:	cc                   	int3
  26573e:	cc                   	int3
  26573f:	cc                   	int3
  265740:	e9 1b c9 14 00       	jmp    0x3b2060
  265745:	cc                   	int3
  265746:	cc                   	int3
  265747:	cc                   	int3
  265748:	e9 83 d1 14 00       	jmp    0x3b28d0
  26574d:	cc                   	int3
  26574e:	cc                   	int3
  26574f:	cc                   	int3
  265750:	e9 fb d5 14 00       	jmp    0x3b2d50
  265755:	cc                   	int3
  265756:	cc                   	int3
  265757:	cc                   	int3
  265758:	e9 33 d9 14 00       	jmp    0x3b3090
  26575d:	cc                   	int3
  26575e:	cc                   	int3
  26575f:	cc                   	int3
  265760:	e9 7b c9 2f 00       	jmp    0x5620e0
  265765:	cc                   	int3
  265766:	cc                   	int3
  265767:	cc                   	int3
  265768:	e9 b3 08 15 00       	jmp    0x3b6020
  26576d:	cc                   	int3
  26576e:	cc                   	int3
  26576f:	cc                   	int3
  265770:	e9 cb 0a 15 00       	jmp    0x3b6240
  265775:	cc                   	int3
  265776:	cc                   	int3
  265777:	cc                   	int3
  265778:	e9 93 c6 15 00       	jmp    0x3c1e10
  26577d:	cc                   	int3
  26577e:	cc                   	int3
  26577f:	cc                   	int3
  265780:	e9 bb ca 15 00       	jmp    0x3c2240
  265785:	cc                   	int3
  265786:	cc                   	int3
  265787:	cc                   	int3
  265788:	e9 53 a0 ec ff       	jmp    0x12f7e0
  26578d:	cc                   	int3
  26578e:	cc                   	int3
  26578f:	cc                   	int3
  265790:	e9 bb 89 16 00       	jmp    0x3ce150
  265795:	cc                   	int3
  265796:	cc                   	int3
  265797:	cc                   	int3
  265798:	e9 13 fb 16 00       	jmp    0x3d52b0
  26579d:	cc                   	int3
  26579e:	cc                   	int3
  26579f:	cc                   	int3
  2657a0:	e9 fb 02 18 00       	jmp    0x3e5aa0
  2657a5:	cc                   	int3
  2657a6:	cc                   	int3
  2657a7:	cc                   	int3
  2657a8:	e9 23 03 18 00       	jmp    0x3e5ad0
  2657ad:	cc                   	int3
  2657ae:	cc                   	int3
  2657af:	cc                   	int3
  2657b0:	e9 3b 03 18 00       	jmp    0x3e5af0
  2657b5:	cc                   	int3
  2657b6:	cc                   	int3
  2657b7:	cc                   	int3
  2657b8:	e9 83 6b 18 00       	jmp    0x3ec340
  2657bd:	cc                   	int3
  2657be:	cc                   	int3
  2657bf:	cc                   	int3
  2657c0:	e9 fb ad 18 00       	jmp    0x3f05c0
  2657c5:	cc                   	int3
  2657c6:	cc                   	int3
  2657c7:	cc                   	int3
  2657c8:	e9 43 d0 18 00       	jmp    0x3f2810
  2657cd:	cc                   	int3
  2657ce:	cc                   	int3
  2657cf:	cc                   	int3
  2657d0:	e9 8b d3 18 00       	jmp    0x3f2b60
  2657d5:	cc                   	int3
  2657d6:	cc                   	int3
  2657d7:	cc                   	int3
  2657d8:	e9 43 76 2a 00       	jmp    0x50ce20
  2657dd:	cc                   	int3
  2657de:	cc                   	int3
  2657df:	cc                   	int3
  2657e0:	e9 ab e7 18 00       	jmp    0x3f3f90
  2657e5:	cc                   	int3
  2657e6:	cc                   	int3
  2657e7:	cc                   	int3
  2657e8:	e9 a3 3f 1a 00       	jmp    0x409790
  2657ed:	cc                   	int3
  2657ee:	cc                   	int3
  2657ef:	cc                   	int3
  2657f0:	e9 4b 1a 98 00       	jmp    0xbe7240
  2657f5:	cc                   	int3
  2657f6:	cc                   	int3
  2657f7:	cc                   	int3
  2657f8:	e9 93 bb a4 00       	jmp    0xcb1390
  2657fd:	cc                   	int3
  2657fe:	cc                   	int3
  2657ff:	cc                   	int3
  265800:	e9 fb 67 28 00       	jmp    0x4ec000
  265805:	cc                   	int3
  265806:	cc                   	int3
  265807:	cc                   	int3
  265808:	e9 53 6d 28 00       	jmp    0x4ec560
  26580d:	cc                   	int3
  26580e:	cc                   	int3
  26580f:	cc                   	int3
  265810:	e9 eb 15 69 00       	jmp    0x8f6e00
  265815:	cc                   	int3
  265816:	cc                   	int3
  265817:	cc                   	int3
  265818:	e9 e3 66 4c 00       	jmp    0x72bf00
  26581d:	cc                   	int3
  26581e:	cc                   	int3
  26581f:	cc                   	int3
  265820:	e9 6b 2a 98 00       	jmp    0xbe8290
  265825:	cc                   	int3
  265826:	cc                   	int3
  265827:	cc                   	int3
  265828:	e9 23 2d 69 00       	jmp    0x8f8550
  26582d:	cc                   	int3
  26582e:	cc                   	int3
  26582f:	cc                   	int3
  265830:	e9 eb 12 69 00       	jmp    0x8f6b20
  265835:	cc                   	int3
  265836:	cc                   	int3
  265837:	cc                   	int3
  265838:	e9 03 43 69 00       	jmp    0x8f9b40
  26583d:	cc                   	int3
  26583e:	cc                   	int3
  26583f:	cc                   	int3
  265840:	e9 9b d1 2c 00       	jmp    0x5329e0
  265845:	cc                   	int3
  265846:	cc                   	int3
  265847:	cc                   	int3
  265848:	e9 93 c9 2c 00       	jmp    0x5321e0
  26584d:	cc                   	int3
  26584e:	cc                   	int3
  26584f:	cc                   	int3
  265850:	e9 7b d0 2c 00       	jmp    0x5328d0
  265855:	cc                   	int3
  265856:	cc                   	int3
  265857:	cc                   	int3
  265858:	e9 23 b8 2c 00       	jmp    0x531080
  26585d:	cc                   	int3
  26585e:	cc                   	int3
  26585f:	cc                   	int3
  265860:	e9 ab da 2c 00       	jmp    0x533310
  265865:	cc                   	int3
  265866:	cc                   	int3
  265867:	cc                   	int3
  265868:	e9 c3 d7 2c 00       	jmp    0x533030
  26586d:	cc                   	int3
  26586e:	cc                   	int3
  26586f:	cc                   	int3
  265870:	e9 6b 33 69 00       	jmp    0x8f8be0
  265875:	cc                   	int3
  265876:	cc                   	int3
  265877:	cc                   	int3
  265878:	e9 33 3d 69 00       	jmp    0x8f95b0
  26587d:	cc                   	int3
  26587e:	cc                   	int3
  26587f:	cc                   	int3
  265880:	e9 db 3e 69 00       	jmp    0x8f9760
  265885:	cc                   	int3
  265886:	cc                   	int3
  265887:	cc                   	int3
  265888:	e9 93 04 69 00       	jmp    0x8f5d20
  26588d:	cc                   	int3
  26588e:	cc                   	int3
  26588f:	cc                   	int3
  265890:	e9 1b 9d 2f 00       	jmp    0x55f5b0
  265895:	cc                   	int3
  265896:	cc                   	int3
  265897:	cc                   	int3
  265898:	e9 e3 44 4c 00       	jmp    0x729d80
  26589d:	cc                   	int3
  26589e:	cc                   	int3
  26589f:	cc                   	int3
  2658a0:	e9 eb d4 59 00       	jmp    0x802d90
  2658a5:	cc                   	int3
  2658a6:	cc                   	int3
  2658a7:	cc                   	int3
  2658a8:	e9 23 8c 1f 00       	jmp    0x45e4d0
  2658ad:	cc                   	int3
  2658ae:	cc                   	int3
  2658af:	cc                   	int3
  2658b0:	e9 4b 9b 2f 00       	jmp    0x55f400
  2658b5:	cc                   	int3
  2658b6:	cc                   	int3
  2658b7:	cc                   	int3
  2658b8:	e9 83 76 28 00       	jmp    0x4ecf40
  2658bd:	cc                   	int3
  2658be:	cc                   	int3
  2658bf:	cc                   	int3
  2658c0:	e9 4b ef 57 00       	jmp    0x7e4810
  2658c5:	cc                   	int3
  2658c6:	cc                   	int3
  2658c7:	cc                   	int3
  2658c8:	e9 c3 6b 69 00       	jmp    0x8fc490
  2658cd:	cc                   	int3
  2658ce:	cc                   	int3
  2658cf:	cc                   	int3
  2658d0:	e9 eb d4 47 00       	jmp    0x6e2dc0
  2658d5:	cc                   	int3
  2658d6:	cc                   	int3
  2658d7:	cc                   	int3
  2658d8:	e9 13 32 85 00       	jmp    0xab8af0
  2658dd:	cc                   	int3
  2658de:	cc                   	int3
  2658df:	cc                   	int3
  2658e0:	e9 cb 32 85 00       	jmp    0xab8bb0
  2658e5:	cc                   	int3
  2658e6:	cc                   	int3
  2658e7:	cc                   	int3
  2658e8:	e9 33 34 85 00       	jmp    0xab8d20
  2658ed:	cc                   	int3
  2658ee:	cc                   	int3
  2658ef:	cc                   	int3
  2658f0:	e9 0b 35 85 00       	jmp    0xab8e00
  2658f5:	cc                   	int3
  2658f6:	cc                   	int3
  2658f7:	cc                   	int3
  2658f8:	e9 c3 35 85 00       	jmp    0xab8ec0
  2658fd:	cc                   	int3
  2658fe:	cc                   	int3
  2658ff:	cc                   	int3
  265900:	e9 bb 73 45 00       	jmp    0x6bccc0
  265905:	cc                   	int3
  265906:	cc                   	int3
  265907:	cc                   	int3
  265908:	e9 13 71 45 00       	jmp    0x6bca20
  26590d:	cc                   	int3
  26590e:	cc                   	int3
  26590f:	cc                   	int3
  265910:	e9 db 40 4c 00       	jmp    0x7299f0
  265915:	cc                   	int3
  265916:	cc                   	int3
  265917:	cc                   	int3
  265918:	e9 23 41 4c 00       	jmp    0x729a40
  26591d:	cc                   	int3
  26591e:	cc                   	int3
  26591f:	cc                   	int3
  265920:	e9 9b 44 4c 00       	jmp    0x729dc0
  265925:	cc                   	int3
  265926:	cc                   	int3
  265927:	cc                   	int3
  265928:	e9 83 8b 28 00       	jmp    0x4ee4b0
  26592d:	cc                   	int3
  26592e:	cc                   	int3
  26592f:	cc                   	int3
  265930:	e9 fb 5a 69 00       	jmp    0x8fb430
  265935:	cc                   	int3
  265936:	cc                   	int3
  265937:	cc                   	int3
  265938:	e9 43 a6 23 00       	jmp    0x49ff80
  26593d:	cc                   	int3
  26593e:	cc                   	int3
  26593f:	cc                   	int3
  265940:	e9 ab 9f 2c 00       	jmp    0x52f8f0
  265945:	cc                   	int3
  265946:	cc                   	int3
  265947:	cc                   	int3
  265948:	e9 13 b9 2c 00       	jmp    0x531260
  26594d:	cc                   	int3
  26594e:	cc                   	int3
  26594f:	cc                   	int3
  265950:	e9 8b a3 2c 00       	jmp    0x52fce0
  265955:	cc                   	int3
  265956:	cc                   	int3
  265957:	cc                   	int3
  265958:	e9 93 a3 23 00       	jmp    0x49fcf0
  26595d:	cc                   	int3
  26595e:	cc                   	int3
  26595f:	cc                   	int3
  265960:	e9 9b a3 2c 00       	jmp    0x52fd00
  265965:	cc                   	int3
  265966:	cc                   	int3
  265967:	cc                   	int3
  265968:	e9 93 a4 2c 00       	jmp    0x52fe00
  26596d:	cc                   	int3
  26596e:	cc                   	int3
  26596f:	cc                   	int3
  265970:	e9 0b ab 2c 00       	jmp    0x530480
  265975:	cc                   	int3
  265976:	cc                   	int3
  265977:	cc                   	int3
  265978:	e9 43 d2 2c 00       	jmp    0x532bc0
  26597d:	cc                   	int3
  26597e:	cc                   	int3
  26597f:	cc                   	int3
  265980:	e9 4b ae 2c 00       	jmp    0x5307d0
  265985:	cc                   	int3
  265986:	cc                   	int3
  265987:	cc                   	int3
  265988:	e9 53 a1 2c 00       	jmp    0x52fae0
  26598d:	cc                   	int3
  26598e:	cc                   	int3
  26598f:	cc                   	int3
  265990:	e9 ab 67 4c 00       	jmp    0x72c140
  265995:	cc                   	int3
  265996:	cc                   	int3
  265997:	cc                   	int3
  265998:	e9 63 6e 45 00       	jmp    0x6bc800
  26599d:	cc                   	int3
  26599e:	cc                   	int3
  26599f:	cc                   	int3
  2659a0:	e9 fb c1 23 00       	jmp    0x4a1ba0
  2659a5:	cc                   	int3
  2659a6:	cc                   	int3
  2659a7:	cc                   	int3
  2659a8:	e9 23 d3 2c 00       	jmp    0x532cd0
  2659ad:	cc                   	int3
  2659ae:	cc                   	int3
  2659af:	cc                   	int3
  2659b0:	e9 0b 69 28 00       	jmp    0x4ec2c0
  2659b5:	cc                   	int3
  2659b6:	cc                   	int3
  2659b7:	cc                   	int3
  2659b8:	e9 23 6f 28 00       	jmp    0x4ec8e0
  2659bd:	cc                   	int3
  2659be:	cc                   	int3
  2659bf:	cc                   	int3
  2659c0:	e9 0b 6f 45 00       	jmp    0x6bc8d0
  2659c5:	cc                   	int3
  2659c6:	cc                   	int3
  2659c7:	cc                   	int3
  2659c8:	e9 73 43 69 00       	jmp    0x8f9d40
  2659cd:	cc                   	int3
  2659ce:	cc                   	int3
  2659cf:	cc                   	int3
  2659d0:	e9 9b a4 2c 00       	jmp    0x52fe70
  2659d5:	cc                   	int3
  2659d6:	cc                   	int3
  2659d7:	cc                   	int3
  2659d8:	e9 73 5a 69 00       	jmp    0x8fb450
  2659dd:	cc                   	int3
  2659de:	cc                   	int3
  2659df:	cc                   	int3
  2659e0:	e9 ab 8b 4c 00       	jmp    0x72e590
  2659e5:	cc                   	int3
  2659e6:	cc                   	int3
  2659e7:	cc                   	int3
  2659e8:	e9 43 c1 2c 00       	jmp    0x531b30
  2659ed:	cc                   	int3
  2659ee:	cc                   	int3
  2659ef:	cc                   	int3
  2659f0:	e9 fb d0 2c 00       	jmp    0x532af0
  2659f5:	cc                   	int3
  2659f6:	cc                   	int3
  2659f7:	cc                   	int3
  2659f8:	e9 23 bd 2c 00       	jmp    0x531720
  2659fd:	cc                   	int3
  2659fe:	cc                   	int3
  2659ff:	cc                   	int3
  265a00:	e9 db 5e 69 00       	jmp    0x8fb8e0
  265a05:	cc                   	int3
  265a06:	cc                   	int3
  265a07:	cc                   	int3
  265a08:	e9 b3 61 69 00       	jmp    0x8fbbc0
  265a0d:	cc                   	int3
  265a0e:	cc                   	int3
  265a0f:	cc                   	int3
  265a10:	e9 fb 48 69 00       	jmp    0x8fa310
  265a15:	cc                   	int3
  265a16:	cc                   	int3
  265a17:	cc                   	int3
  265a18:	e9 13 56 21 00       	jmp    0x47b030
  265a1d:	cc                   	int3
  265a1e:	cc                   	int3
  265a1f:	cc                   	int3
  265a20:	e9 fb 33 69 00       	jmp    0x8f8e20
  265a25:	cc                   	int3
  265a26:	cc                   	int3
  265a27:	cc                   	int3
  265a28:	e9 23 67 4c 00       	jmp    0x72c150
  265a2d:	cc                   	int3
  265a2e:	cc                   	int3
  265a2f:	cc                   	int3
  265a30:	e9 2b 38 69 00       	jmp    0x8f9260
  265a35:	cc                   	int3
  265a36:	cc                   	int3
  265a37:	cc                   	int3
  265a38:	e9 d3 38 69 00       	jmp    0x8f9310
  265a3d:	cc                   	int3
  265a3e:	cc                   	int3
  265a3f:	cc                   	int3
  265a40:	e9 9b 69 4c 00       	jmp    0x72c3e0
  265a45:	cc                   	int3
  265a46:	cc                   	int3
  265a47:	cc                   	int3
  265a48:	e9 93 b9 23 00       	jmp    0x4a13e0
  265a4d:	cc                   	int3
  265a4e:	cc                   	int3
  265a4f:	cc                   	int3
  265a50:	e9 db b1 23 00       	jmp    0x4a0c30
  265a55:	cc                   	int3
  265a56:	cc                   	int3
  265a57:	cc                   	int3
  265a58:	e9 83 61 69 00       	jmp    0x8fbbe0
  265a5d:	cc                   	int3
  265a5e:	cc                   	int3
  265a5f:	cc                   	int3
  265a60:	e9 7b 27 2f 00       	jmp    0x5581e0
  265a65:	cc                   	int3
  265a66:	cc                   	int3
  265a67:	cc                   	int3
  265a68:	e9 e3 39 85 00       	jmp    0xab9450
  265a6d:	cc                   	int3
  265a6e:	cc                   	int3
  265a6f:	cc                   	int3
  265a70:	e9 9b 3c 85 00       	jmp    0xab9710
  265a75:	cc                   	int3
  265a76:	cc                   	int3
  265a77:	cc                   	int3
  265a78:	e9 63 4e 69 00       	jmp    0x8fa8e0
  265a7d:	cc                   	int3
  265a7e:	cc                   	int3
  265a7f:	cc                   	int3
  265a80:	e9 cb 8a 28 00       	jmp    0x4ee550
  265a85:	cc                   	int3
  265a86:	cc                   	int3
  265a87:	cc                   	int3
  265a88:	e9 83 6d 69 00       	jmp    0x8fc810
  265a8d:	cc                   	int3
  265a8e:	cc                   	int3
  265a8f:	cc                   	int3
  265a90:	e9 8b 6d 69 00       	jmp    0x8fc820
  265a95:	cc                   	int3
  265a96:	cc                   	int3
  265a97:	cc                   	int3
  265a98:	e9 d3 5b 45 00       	jmp    0x6bb670
  265a9d:	cc                   	int3
  265a9e:	cc                   	int3
  265a9f:	cc                   	int3
  265aa0:	e9 7b 62 45 00       	jmp    0x6bbd20
  265aa5:	cc                   	int3
  265aa6:	cc                   	int3
  265aa7:	cc                   	int3
  265aa8:	e9 83 65 45 00       	jmp    0x6bc030
  265aad:	cc                   	int3
  265aae:	cc                   	int3
  265aaf:	cc                   	int3
  265ab0:	e9 bb 7a 45 00       	jmp    0x6bd570
  265ab5:	cc                   	int3
  265ab6:	cc                   	int3
  265ab7:	cc                   	int3
  265ab8:	e9 e3 84 45 00       	jmp    0x6bdfa0
  265abd:	cc                   	int3
  265abe:	cc                   	int3
  265abf:	cc                   	int3
  265ac0:	e9 eb 84 45 00       	jmp    0x6bdfb0
  265ac5:	cc                   	int3
  265ac6:	cc                   	int3
  265ac7:	cc                   	int3
  265ac8:	e9 03 87 45 00       	jmp    0x6be1d0
  265acd:	cc                   	int3
  265ace:	cc                   	int3
  265acf:	cc                   	int3
  265ad0:	e9 9b 88 45 00       	jmp    0x6be370
  265ad5:	cc                   	int3
  265ad6:	cc                   	int3
  265ad7:	cc                   	int3
  265ad8:	e9 03 6a 45 00       	jmp    0x6bc4e0
  265add:	cc                   	int3
  265ade:	cc                   	int3
  265adf:	cc                   	int3
  265ae0:	e9 cb bf a4 00       	jmp    0xcb1ab0
  265ae5:	cc                   	int3
  265ae6:	cc                   	int3
  265ae7:	cc                   	int3
  265ae8:	e9 a3 68 69 00       	jmp    0x8fc390
  265aed:	cc                   	int3
  265aee:	cc                   	int3
  265aef:	cc                   	int3
  265af0:	e9 eb 69 28 00       	jmp    0x4ec4e0
  265af5:	cc                   	int3
  265af6:	cc                   	int3
  265af7:	cc                   	int3
  265af8:	e9 73 71 28 00       	jmp    0x4ecc70
  265afd:	cc                   	int3
  265afe:	cc                   	int3
  265aff:	cc                   	int3
  265b00:	e9 5b 8e 91 00       	jmp    0xb7e960
  265b05:	cc                   	int3
  265b06:	cc                   	int3
  265b07:	cc                   	int3
  265b08:	e9 73 3a 85 00       	jmp    0xab9580
  265b0d:	cc                   	int3
  265b0e:	cc                   	int3
  265b0f:	cc                   	int3
  265b10:	e9 7b 3b 85 00       	jmp    0xab9690
  265b15:	cc                   	int3
  265b16:	cc                   	int3
  265b17:	cc                   	int3
  265b18:	e9 43 df 33 00       	jmp    0x5a3a60
  265b1d:	cc                   	int3
  265b1e:	cc                   	int3
  265b1f:	cc                   	int3
  265b20:	e9 2b e0 33 00       	jmp    0x5a3b50
  265b25:	cc                   	int3
  265b26:	cc                   	int3
  265b27:	cc                   	int3
  265b28:	e9 33 e1 33 00       	jmp    0x5a3c60
  265b2d:	cc                   	int3
  265b2e:	cc                   	int3
  265b2f:	cc                   	int3
  265b30:	e9 4b e2 33 00       	jmp    0x5a3d80
  265b35:	cc                   	int3
  265b36:	cc                   	int3
  265b37:	cc                   	int3
  265b38:	e9 33 e3 33 00       	jmp    0x5a3e70
  265b3d:	cc                   	int3
  265b3e:	cc                   	int3
  265b3f:	cc                   	int3
  265b40:	e9 4b e3 33 00       	jmp    0x5a3e90
  265b45:	cc                   	int3
  265b46:	cc                   	int3
  265b47:	cc                   	int3
  265b48:	e9 a3 e3 33 00       	jmp    0x5a3ef0
  265b4d:	cc                   	int3
  265b4e:	cc                   	int3
  265b4f:	cc                   	int3
  265b50:	e9 fb e3 33 00       	jmp    0x5a3f50
  265b55:	cc                   	int3
  265b56:	cc                   	int3
  265b57:	cc                   	int3
  265b58:	e9 63 82 2f 00       	jmp    0x55ddc0
  265b5d:	cc                   	int3
  265b5e:	cc                   	int3
  265b5f:	cc                   	int3
  265b60:	e9 0b 92 2f 00       	jmp    0x55ed70
  265b65:	cc                   	int3
  265b66:	cc                   	int3
  265b67:	cc                   	int3
  265b68:	e9 23 91 2f 00       	jmp    0x55ec90
  265b6d:	cc                   	int3
  265b6e:	cc                   	int3
  265b6f:	cc                   	int3
  265b70:	e9 db 89 2f 00       	jmp    0x55e550
  265b75:	cc                   	int3
  265b76:	cc                   	int3
  265b77:	cc                   	int3
  265b78:	e9 03 8b 2f 00       	jmp    0x55e680
  265b7d:	cc                   	int3
  265b7e:	cc                   	int3
  265b7f:	cc                   	int3
  265b80:	e9 fb 61 85 00       	jmp    0xabbd80
  265b85:	cc                   	int3
  265b86:	cc                   	int3
  265b87:	cc                   	int3
  265b88:	e9 53 e5 5c 00       	jmp    0x8340e0
  265b8d:	cc                   	int3
  265b8e:	cc                   	int3
  265b8f:	cc                   	int3
  265b90:	e9 8b 05 69 00       	jmp    0x8f6120
  265b95:	cc                   	int3
  265b96:	cc                   	int3
  265b97:	cc                   	int3
  265b98:	e9 63 d3 9d 00       	jmp    0xc42f00
  265b9d:	cc                   	int3
  265b9e:	cc                   	int3
  265b9f:	cc                   	int3
  265ba0:	e9 6b d4 9d 00       	jmp    0xc43010
  265ba5:	cc                   	int3
  265ba6:	cc                   	int3
  265ba7:	cc                   	int3
  265ba8:	e9 c3 d5 9d 00       	jmp    0xc43170
  265bad:	cc                   	int3
  265bae:	cc                   	int3
  265baf:	cc                   	int3
  265bb0:	e9 eb d8 9d 00       	jmp    0xc434a0
  265bb5:	cc                   	int3
  265bb6:	cc                   	int3
  265bb7:	cc                   	int3
  265bb8:	e9 a3 cb 9d 00       	jmp    0xc42760
  265bbd:	cc                   	int3
  265bbe:	cc                   	int3
  265bbf:	cc                   	int3
  265bc0:	e9 cb cf 9d 00       	jmp    0xc42b90
  265bc5:	cc                   	int3
  265bc6:	cc                   	int3
  265bc7:	cc                   	int3
  265bc8:	e9 f3 cf 9d 00       	jmp    0xc42bc0
  265bcd:	cc                   	int3
  265bce:	cc                   	int3
  265bcf:	cc                   	int3
  265bd0:	e9 eb d8 9d 00       	jmp    0xc434c0
  265bd5:	cc                   	int3
  265bd6:	cc                   	int3
  265bd7:	cc                   	int3
  265bd8:	e9 43 da 9d 00       	jmp    0xc43620
  265bdd:	cc                   	int3
  265bde:	cc                   	int3
  265bdf:	cc                   	int3
  265be0:	e9 db 74 2f 00       	jmp    0x55d0c0
  265be5:	cc                   	int3
  265be6:	cc                   	int3
  265be7:	cc                   	int3
  265be8:	e9 93 16 7a 00       	jmp    0xa07280
  265bed:	cc                   	int3
  265bee:	cc                   	int3
  265bef:	cc                   	int3
  265bf0:	e9 6b 1c 9d 00       	jmp    0xc37860
  265bf5:	cc                   	int3
  265bf6:	cc                   	int3
  265bf7:	cc                   	int3
  265bf8:	e9 73 1d 9d 00       	jmp    0xc37970
  265bfd:	cc                   	int3
  265bfe:	cc                   	int3
  265bff:	cc                   	int3
  265c00:	e9 1b 1e 9d 00       	jmp    0xc37a20
  265c05:	cc                   	int3
  265c06:	cc                   	int3
  265c07:	cc                   	int3
  265c08:	e9 a3 82 2f 00       	jmp    0x55deb0
  265c0d:	cc                   	int3
  265c0e:	cc                   	int3
  265c0f:	cc                   	int3
  265c10:	e9 db 20 1d 00       	jmp    0x437cf0
  265c15:	cc                   	int3
  265c16:	cc                   	int3
  265c17:	cc                   	int3
  265c18:	e9 d3 27 1d 00       	jmp    0x4383f0
  265c1d:	cc                   	int3
  265c1e:	cc                   	int3
  265c1f:	cc                   	int3
  265c20:	e9 9b 27 1d 00       	jmp    0x4383c0
  265c25:	cc                   	int3
  265c26:	cc                   	int3
  265c27:	cc                   	int3
  265c28:	e9 33 29 1d 00       	jmp    0x438560
  265c2d:	cc                   	int3
  265c2e:	cc                   	int3
  265c2f:	cc                   	int3
  265c30:	e9 bb d7 9d 00       	jmp    0xc433f0
  265c35:	cc                   	int3
  265c36:	cc                   	int3
  265c37:	cc                   	int3
  265c38:	e9 83 2c 1d 00       	jmp    0x4388c0
  265c3d:	cc                   	int3
  265c3e:	cc                   	int3
  265c3f:	cc                   	int3
  265c40:	e9 6b 2e 1d 00       	jmp    0x438ab0
  265c45:	cc                   	int3
  265c46:	cc                   	int3
  265c47:	cc                   	int3
  265c48:	e9 d3 cf 2e 00       	jmp    0x552c20
  265c4d:	cc                   	int3
  265c4e:	cc                   	int3
  265c4f:	cc                   	int3
  265c50:	e9 8b 21 1d 00       	jmp    0x437de0
  265c55:	cc                   	int3
  265c56:	cc                   	int3
  265c57:	cc                   	int3
  265c58:	e9 c3 9f 2f 00       	jmp    0x55fc20
  265c5d:	cc                   	int3
  265c5e:	cc                   	int3
  265c5f:	cc                   	int3
  265c60:	e9 fb 2e 1d 00       	jmp    0x438b60
  265c65:	cc                   	int3
  265c66:	cc                   	int3
  265c67:	cc                   	int3
  265c68:	e9 93 a7 23 00       	jmp    0x4a0400
  265c6d:	cc                   	int3
  265c6e:	cc                   	int3
  265c6f:	cc                   	int3
  265c70:	e9 ab 64 28 00       	jmp    0x4ec120
  265c75:	cc                   	int3
  265c76:	cc                   	int3
  265c77:	cc                   	int3
  265c78:	e9 c3 6a 28 00       	jmp    0x4ec740
  265c7d:	cc                   	int3
  265c7e:	cc                   	int3
  265c7f:	cc                   	int3
  265c80:	e9 3b 27 85 00       	jmp    0xab83c0
  265c85:	cc                   	int3
  265c86:	cc                   	int3
  265c87:	cc                   	int3
  265c88:	e9 23 2e 69 00       	jmp    0x8f8ab0
  265c8d:	cc                   	int3
  265c8e:	cc                   	int3
  265c8f:	cc                   	int3
  265c90:	e9 0b 53 69 00       	jmp    0x8fafa0
  265c95:	cc                   	int3
  265c96:	cc                   	int3
  265c97:	cc                   	int3
  265c98:	e9 83 72 28 00       	jmp    0x4ecf20
  265c9d:	cc                   	int3
  265c9e:	cc                   	int3
  265c9f:	cc                   	int3
  265ca0:	e9 4b 2a 1d 00       	jmp    0x4386f0
  265ca5:	cc                   	int3
  265ca6:	cc                   	int3
  265ca7:	cc                   	int3
  265ca8:	e9 93 7a 5a 00       	jmp    0x80d740
  265cad:	cc                   	int3
  265cae:	cc                   	int3
  265caf:	cc                   	int3
  265cb0:	e9 1b 7f 5a 00       	jmp    0x80dbd0
  265cb5:	cc                   	int3
  265cb6:	cc                   	int3
  265cb7:	cc                   	int3
  265cb8:	e9 73 7b 5d 00       	jmp    0x83d830
  265cbd:	cc                   	int3
  265cbe:	cc                   	int3
  265cbf:	cc                   	int3
  265cc0:	e9 9b 81 5d 00       	jmp    0x83de60
  265cc5:	cc                   	int3
  265cc6:	cc                   	int3
  265cc7:	cc                   	int3
  265cc8:	e9 53 86 5d 00       	jmp    0x83e320
  265ccd:	cc                   	int3
  265cce:	cc                   	int3
  265ccf:	cc                   	int3
  265cd0:	e9 7b 11 69 00       	jmp    0x8f6e50
  265cd5:	cc                   	int3
  265cd6:	cc                   	int3
  265cd7:	cc                   	int3
  265cd8:	e9 d3 53 23 00       	jmp    0x49b0b0
  265cdd:	cc                   	int3
  265cde:	cc                   	int3
  265cdf:	cc                   	int3
  265ce0:	e9 db 76 28 00       	jmp    0x4ed3c0
  265ce5:	cc                   	int3
  265ce6:	cc                   	int3
  265ce7:	cc                   	int3
  265ce8:	e9 53 a3 88 00       	jmp    0xaf0040
  265ced:	cc                   	int3
  265cee:	cc                   	int3
  265cef:	cc                   	int3
  265cf0:	e9 8b fb 49 00       	jmp    0x705880
  265cf5:	cc                   	int3
  265cf6:	cc                   	int3
  265cf7:	cc                   	int3
  265cf8:	e9 63 ff 49 00       	jmp    0x705c60
  265cfd:	cc                   	int3
  265cfe:	cc                   	int3
  265cff:	cc                   	int3
  265d00:	e9 eb 08 29 00       	jmp    0x4f65f0
  265d05:	cc                   	int3
  265d06:	cc                   	int3
  265d07:	cc                   	int3
  265d08:	e9 63 0d 29 00       	jmp    0x4f6a70
  265d0d:	cc                   	int3
  265d0e:	cc                   	int3
  265d0f:	cc                   	int3
  265d10:	e9 6b 9d 94 00       	jmp    0xbafa80
  265d15:	cc                   	int3
  265d16:	cc                   	int3
  265d17:	cc                   	int3
  265d18:	e9 d3 9f 94 00       	jmp    0xbafcf0
  265d1d:	cc                   	int3
  265d1e:	cc                   	int3
  265d1f:	cc                   	int3
  265d20:	e9 0b a6 94 00       	jmp    0xbb0330
  265d25:	cc                   	int3
  265d26:	cc                   	int3
  265d27:	cc                   	int3
  265d28:	e9 63 a7 94 00       	jmp    0xbb0490
  265d2d:	cc                   	int3
  265d2e:	cc                   	int3
  265d2f:	cc                   	int3
  265d30:	e9 1b a1 94 00       	jmp    0xbafe50
  265d35:	cc                   	int3
  265d36:	cc                   	int3
  265d37:	cc                   	int3
  265d38:	e9 f3 a2 94 00       	jmp    0xbb0030
  265d3d:	cc                   	int3
  265d3e:	cc                   	int3
  265d3f:	cc                   	int3
  265d40:	e9 0b a4 94 00       	jmp    0xbb0150
  265d45:	cc                   	int3
  265d46:	cc                   	int3
  265d47:	cc                   	int3
  265d48:	e9 83 a4 94 00       	jmp    0xbb01d0
  265d4d:	cc                   	int3
  265d4e:	cc                   	int3
  265d4f:	cc                   	int3
  265d50:	e9 2b a5 94 00       	jmp    0xbb0280
  265d55:	cc                   	int3
  265d56:	cc                   	int3
  265d57:	cc                   	int3
  265d58:	e9 e3 47 85 00       	jmp    0xaba540
  265d5d:	cc                   	int3
  265d5e:	cc                   	int3
  265d5f:	cc                   	int3
  265d60:	e9 fb 60 85 00       	jmp    0xabbe60
  265d65:	cc                   	int3
  265d66:	cc                   	int3
  265d67:	cc                   	int3
  265d68:	e9 b3 02 9b 00       	jmp    0xc16020
  265d6d:	cc                   	int3
  265d6e:	cc                   	int3
  265d6f:	cc                   	int3
  265d70:	e9 fb 04 9b 00       	jmp    0xc16270
  265d75:	cc                   	int3
  265d76:	cc                   	int3
  265d77:	cc                   	int3
  265d78:	e9 a3 09 9b 00       	jmp    0xc16720
  265d7d:	cc                   	int3
  265d7e:	cc                   	int3
  265d7f:	cc                   	int3
  265d80:	e9 fb 0a 9b 00       	jmp    0xc16880
  265d85:	cc                   	int3
  265d86:	cc                   	int3
  265d87:	cc                   	int3
  265d88:	e9 43 06 9b 00       	jmp    0xc163d0
  265d8d:	cc                   	int3
  265d8e:	cc                   	int3
  265d8f:	cc                   	int3
  265d90:	e9 5b 07 9b 00       	jmp    0xc164f0
  265d95:	cc                   	int3
  265d96:	cc                   	int3
  265d97:	cc                   	int3
  265d98:	e9 33 08 9b 00       	jmp    0xc165d0
  265d9d:	cc                   	int3
  265d9e:	cc                   	int3
  265d9f:	cc                   	int3
  265da0:	e9 bb 08 9b 00       	jmp    0xc16660
  265da5:	cc                   	int3
  265da6:	cc                   	int3
  265da7:	cc                   	int3
  265da8:	e9 93 14 86 00       	jmp    0xac7240
  265dad:	cc                   	int3
  265dae:	cc                   	int3
  265daf:	cc                   	int3
  265db0:	e9 0b 16 86 00       	jmp    0xac73c0
  265db5:	cc                   	int3
  265db6:	cc                   	int3
  265db7:	cc                   	int3
  265db8:	e9 53 67 85 00       	jmp    0xabc510
  265dbd:	cc                   	int3
  265dbe:	cc                   	int3
  265dbf:	cc                   	int3
  265dc0:	e9 9b 00 29 00       	jmp    0x4f5e60
  265dc5:	cc                   	int3
  265dc6:	cc                   	int3
  265dc7:	cc                   	int3
  265dc8:	e9 13 d2 39 00       	jmp    0x602fe0
  265dcd:	cc                   	int3
  265dce:	cc                   	int3
  265dcf:	cc                   	int3
  265dd0:	e9 8b d4 39 00       	jmp    0x603260
  265dd5:	cc                   	int3
  265dd6:	cc                   	int3
  265dd7:	cc                   	int3
  265dd8:	e9 03 d7 39 00       	jmp    0x6034e0
  265ddd:	cc                   	int3
  265dde:	cc                   	int3
  265ddf:	cc                   	int3
  265de0:	e9 2b d9 39 00       	jmp    0x603710
  265de5:	cc                   	int3
  265de6:	cc                   	int3
  265de7:	cc                   	int3
  265de8:	e9 e3 db 39 00       	jmp    0x6039d0
  265ded:	cc                   	int3
  265dee:	cc                   	int3
  265def:	cc                   	int3
  265df0:	e9 5b 4e 85 00       	jmp    0xabac50
  265df5:	cc                   	int3
  265df6:	cc                   	int3
  265df7:	cc                   	int3
  265df8:	e9 13 68 69 00       	jmp    0x8fc610
  265dfd:	cc                   	int3
  265dfe:	cc                   	int3
  265dff:	cc                   	int3
  265e00:	e9 6b bc 27 00       	jmp    0x4e1a70
  265e05:	cc                   	int3
  265e06:	cc                   	int3
  265e07:	cc                   	int3
  265e08:	e9 e3 67 85 00       	jmp    0xabc5f0
  265e0d:	cc                   	int3
  265e0e:	cc                   	int3
  265e0f:	cc                   	int3
  265e10:	e9 cb 09 7d 00       	jmp    0xa367e0
  265e15:	cc                   	int3
  265e16:	cc                   	int3
  265e17:	cc                   	int3
  265e18:	e9 13 a8 a3 00       	jmp    0xca0630
  265e1d:	cc                   	int3
  265e1e:	cc                   	int3
  265e1f:	cc                   	int3
  265e20:	e9 bb 0a 7d 00       	jmp    0xa368e0
  265e25:	cc                   	int3
  265e26:	cc                   	int3
  265e27:	cc                   	int3
  265e28:	e9 93 8e 4c 00       	jmp    0x72ecc0
  265e2d:	cc                   	int3
  265e2e:	cc                   	int3
  265e2f:	cc                   	int3
  265e30:	e9 3b 15 29 00       	jmp    0x4f7370
  265e35:	cc                   	int3
  265e36:	cc                   	int3
  265e37:	cc                   	int3
  265e38:	e9 c3 0c 7d 00       	jmp    0xa36b00
  265e3d:	cc                   	int3
  265e3e:	cc                   	int3
  265e3f:	cc                   	int3
  265e40:	e9 4b 0d 7d 00       	jmp    0xa36b90
  265e45:	cc                   	int3
  265e46:	cc                   	int3
  265e47:	cc                   	int3
  265e48:	e9 c3 68 85 00       	jmp    0xabc710
  265e4d:	cc                   	int3
  265e4e:	cc                   	int3
  265e4f:	cc                   	int3
  265e50:	e9 0b 21 34 00       	jmp    0x5a7f60
  265e55:	cc                   	int3
  265e56:	cc                   	int3
  265e57:	cc                   	int3
  265e58:	e9 63 0d 7d 00       	jmp    0xa36bc0
  265e5d:	cc                   	int3
  265e5e:	cc                   	int3
  265e5f:	cc                   	int3
  265e60:	e9 ab 6b 85 00       	jmp    0xabca10
  265e65:	cc                   	int3
  265e66:	cc                   	int3
  265e67:	cc                   	int3
  265e68:	e9 93 6d 85 00       	jmp    0xabcc00
  265e6d:	cc                   	int3
  265e6e:	cc                   	int3
  265e6f:	cc                   	int3
  265e70:	e9 1b 2e 1d 00       	jmp    0x438c90
  265e75:	cc                   	int3
  265e76:	cc                   	int3
  265e77:	cc                   	int3
  265e78:	e9 f3 c6 66 00       	jmp    0x8d2570
  265e7d:	cc                   	int3
  265e7e:	cc                   	int3
  265e7f:	cc                   	int3
  265e80:	e9 6b 72 85 00       	jmp    0xabd0f0
  265e85:	cc                   	int3
  265e86:	cc                   	int3
  265e87:	cc                   	int3
  265e88:	e9 c3 17 7d 00       	jmp    0xa37650
  265e8d:	cc                   	int3
  265e8e:	cc                   	int3
  265e8f:	cc                   	int3
  265e90:	e9 9b 75 85 00       	jmp    0xabd430
  265e95:	cc                   	int3
  265e96:	cc                   	int3
  265e97:	cc                   	int3
  265e98:	e9 a3 6e 57 00       	jmp    0x7dcd40
  265e9d:	cc                   	int3
  265e9e:	cc                   	int3
  265e9f:	cc                   	int3
  265ea0:	e9 fb c6 66 00       	jmp    0x8d25a0
  265ea5:	cc                   	int3
  265ea6:	cc                   	int3
  265ea7:	cc                   	int3
  265ea8:	e9 43 76 85 00       	jmp    0xabd4f0
  265ead:	cc                   	int3
  265eae:	cc                   	int3
  265eaf:	cc                   	int3
  265eb0:	e9 db dd 39 00       	jmp    0x603c90
  265eb5:	cc                   	int3
  265eb6:	cc                   	int3
  265eb7:	cc                   	int3
  265eb8:	e9 33 ee 39 00       	jmp    0x604cf0
  265ebd:	cc                   	int3
  265ebe:	cc                   	int3
  265ebf:	cc                   	int3
  265ec0:	e9 8b c9 23 00       	jmp    0x4a2850
  265ec5:	cc                   	int3
  265ec6:	cc                   	int3
  265ec7:	cc                   	int3
  265ec8:	e9 73 76 85 00       	jmp    0xabd540
  265ecd:	cc                   	int3
  265ece:	cc                   	int3
  265ecf:	cc                   	int3
  265ed0:	e9 6b 67 6b 00       	jmp    0x91c640
  265ed5:	cc                   	int3
  265ed6:	cc                   	int3
  265ed7:	cc                   	int3
  265ed8:	e9 93 6d 6b 00       	jmp    0x91cc70
  265edd:	cc                   	int3
  265ede:	cc                   	int3
  265edf:	cc                   	int3
  265ee0:	e9 4b 2f 1d 00       	jmp    0x438e30
  265ee5:	cc                   	int3
  265ee6:	cc                   	int3
  265ee7:	cc                   	int3
  265ee8:	e9 83 31 1d 00       	jmp    0x439070
  265eed:	cc                   	int3
  265eee:	cc                   	int3
  265eef:	cc                   	int3
  265ef0:	e9 5b 32 1d 00       	jmp    0x439150
  265ef5:	cc                   	int3
  265ef6:	cc                   	int3
  265ef7:	cc                   	int3
  265ef8:	e9 a3 34 1d 00       	jmp    0x4393a0
  265efd:	cc                   	int3
  265efe:	cc                   	int3
  265eff:	cc                   	int3
  265f00:	e9 cb 85 45 00       	jmp    0x6be4d0
  265f05:	cc                   	int3
  265f06:	cc                   	int3
  265f07:	cc                   	int3
  265f08:	e9 23 7a 85 00       	jmp    0xabd930
  265f0d:	cc                   	int3
  265f0e:	cc                   	int3
  265f0f:	cc                   	int3
  265f10:	e9 ab 86 45 00       	jmp    0x6be5c0
  265f15:	cc                   	int3
  265f16:	cc                   	int3
  265f17:	cc                   	int3
  265f18:	e9 e3 88 45 00       	jmp    0x6be800
  265f1d:	cc                   	int3
  265f1e:	cc                   	int3
  265f1f:	cc                   	int3
  265f20:	e9 eb ae 82 00       	jmp    0xa90e10
  265f25:	cc                   	int3
  265f26:	cc                   	int3
  265f27:	cc                   	int3
  265f28:	e9 b3 ce 23 00       	jmp    0x4a2de0
  265f2d:	cc                   	int3
  265f2e:	cc                   	int3
  265f2f:	cc                   	int3
  265f30:	e9 9b 7b 85 00       	jmp    0xabdad0
  265f35:	cc                   	int3
  265f36:	cc                   	int3
  265f37:	cc                   	int3
  265f38:	e9 23 17 7d 00       	jmp    0xa37660
  265f3d:	cc                   	int3
  265f3e:	cc                   	int3
  265f3f:	cc                   	int3
  265f40:	e9 7b 82 85 00       	jmp    0xabe1c0
  265f45:	cc                   	int3
  265f46:	cc                   	int3
  265f47:	cc                   	int3
  265f48:	e9 63 88 85 00       	jmp    0xabe7b0
  265f4d:	cc                   	int3
  265f4e:	cc                   	int3
  265f4f:	cc                   	int3
  265f50:	e9 9b 22 79 00       	jmp    0x9f81f0
  265f55:	cc                   	int3
  265f56:	cc                   	int3
  265f57:	cc                   	int3
  265f58:	e9 b3 35 98 00       	jmp    0xbe9510
  265f5d:	cc                   	int3
  265f5e:	cc                   	int3
  265f5f:	cc                   	int3
  265f60:	e9 ab 1d 74 00       	jmp    0x9a7d10
  265f65:	cc                   	int3
  265f66:	cc                   	int3
  265f67:	cc                   	int3
  265f68:	e9 f3 35 74 00       	jmp    0x9a9560
  265f6d:	cc                   	int3
  265f6e:	cc                   	int3
  265f6f:	cc                   	int3
  265f70:	e9 9b 3e 74 00       	jmp    0x9a9e10
  265f75:	cc                   	int3
  265f76:	cc                   	int3
  265f77:	cc                   	int3
  265f78:	e9 c3 3f 74 00       	jmp    0x9a9f40
  265f7d:	cc                   	int3
  265f7e:	cc                   	int3
  265f7f:	cc                   	int3
  265f80:	e9 bb 54 69 00       	jmp    0x8fb440
  265f85:	cc                   	int3
  265f86:	cc                   	int3
  265f87:	cc                   	int3
  265f88:	e9 13 d2 23 00       	jmp    0x4a31a0
  265f8d:	cc                   	int3
  265f8e:	cc                   	int3
  265f8f:	cc                   	int3
  265f90:	e9 1b 89 85 00       	jmp    0xabe8b0
  265f95:	cc                   	int3
  265f96:	cc                   	int3
  265f97:	cc                   	int3
  265f98:	e9 53 52 74 00       	jmp    0x9ab1f0
  265f9d:	cc                   	int3
  265f9e:	cc                   	int3
  265f9f:	cc                   	int3
  265fa0:	e9 db 59 85 00       	jmp    0xabb980
  265fa5:	cc                   	int3
  265fa6:	cc                   	int3
  265fa7:	cc                   	int3
  265fa8:	e9 33 33 49 00       	jmp    0x6f92e0
  265fad:	cc                   	int3
  265fae:	cc                   	int3
  265faf:	cc                   	int3
  265fb0:	e9 eb ed 1c 00       	jmp    0x434da0
  265fb5:	cc                   	int3
  265fb6:	cc                   	int3
  265fb7:	cc                   	int3
  265fb8:	e9 f3 ed 1c 00       	jmp    0x434db0
  265fbd:	cc                   	int3
  265fbe:	cc                   	int3
  265fbf:	cc                   	int3
  265fc0:	e9 fb ed 1c 00       	jmp    0x434dc0
  265fc5:	cc                   	int3
  265fc6:	cc                   	int3
  265fc7:	cc                   	int3
  265fc8:	e9 c3 1d 1d 00       	jmp    0x437d90
  265fcd:	cc                   	int3
  265fce:	cc                   	int3
  265fcf:	cc                   	int3
  265fd0:	e9 ab 22 1d 00       	jmp    0x438280
  265fd5:	cc                   	int3
  265fd6:	cc                   	int3
  265fd7:	cc                   	int3
  265fd8:	e9 b3 06 88 00       	jmp    0xae6690
  265fdd:	cc                   	int3
  265fde:	cc                   	int3
  265fdf:	cc                   	int3
  265fe0:	e9 9b 05 88 00       	jmp    0xae6580
  265fe5:	cc                   	int3
  265fe6:	cc                   	int3
  265fe7:	cc                   	int3
  265fe8:	e9 e3 30 1e 00       	jmp    0x4490d0
  265fed:	cc                   	int3
  265fee:	cc                   	int3
  265fef:	cc                   	int3
  265ff0:	e9 cb 0d e4 ff       	jmp    0xa6dc0
  265ff5:	cc                   	int3
  265ff6:	cc                   	int3
  265ff7:	cc                   	int3
  265ff8:	e9 73 4a 1e 00       	jmp    0x44aa70
  265ffd:	cc                   	int3
  265ffe:	cc                   	int3
  265fff:	cc                   	int3
  266000:	e9 0b 01 75 00       	jmp    0x9b6110
  266005:	cc                   	int3
  266006:	cc                   	int3
  266007:	cc                   	int3
  266008:	e9 63 16 e4 ff       	jmp    0xa7670
  26600d:	cc                   	int3
  26600e:	cc                   	int3
  26600f:	cc                   	int3
  266010:	e9 3b 18 e4 ff       	jmp    0xa7850
  266015:	cc                   	int3
  266016:	cc                   	int3
  266017:	cc                   	int3
  266018:	e9 63 18 e4 ff       	jmp    0xa7880
  26601d:	cc                   	int3
  26601e:	cc                   	int3
  26601f:	cc                   	int3
  266020:	e9 1b c0 1e 00       	jmp    0x452040
  266025:	cc                   	int3
  266026:	cc                   	int3
  266027:	cc                   	int3
  266028:	e9 93 ec 1e 00       	jmp    0x454cc0
  26602d:	cc                   	int3
  26602e:	cc                   	int3
  26602f:	cc                   	int3
  266030:	e9 eb 17 1f 00       	jmp    0x457820
  266035:	cc                   	int3
  266036:	cc                   	int3
  266037:	cc                   	int3
  266038:	e9 33 7f 20 00       	jmp    0x46df70
  26603d:	cc                   	int3
  26603e:	cc                   	int3
  26603f:	cc                   	int3
  266040:	e9 3b 80 20 00       	jmp    0x46e080
  266045:	cc                   	int3
  266046:	cc                   	int3
  266047:	cc                   	int3
  266048:	e9 43 c9 20 00       	jmp    0x472990
  26604d:	cc                   	int3
  26604e:	cc                   	int3
  26604f:	cc                   	int3
  266050:	e9 5b d3 20 00       	jmp    0x4733b0
  266055:	cc                   	int3
  266056:	cc                   	int3
  266057:	cc                   	int3
  266058:	e9 53 d8 20 00       	jmp    0x4738b0
  26605d:	cc                   	int3
  26605e:	cc                   	int3
  26605f:	cc                   	int3
  266060:	e9 eb e1 20 00       	jmp    0x474250
  266065:	cc                   	int3
  266066:	cc                   	int3
  266067:	cc                   	int3
  266068:	e9 43 ed 20 00       	jmp    0x474db0
  26606d:	cc                   	int3
  26606e:	cc                   	int3
  26606f:	cc                   	int3
  266070:	e9 7b 6f 21 00       	jmp    0x47cff0
  266075:	cc                   	int3
  266076:	cc                   	int3
  266077:	cc                   	int3
  266078:	e9 73 7f fb ff       	jmp    0x21dff0
  26607d:	cc                   	int3
  26607e:	cc                   	int3
  26607f:	cc                   	int3
  266080:	e9 7b a2 22 00       	jmp    0x490300
  266085:	cc                   	int3
  266086:	cc                   	int3
  266087:	cc                   	int3
  266088:	e9 23 ad 22 00       	jmp    0x490db0
  26608d:	cc                   	int3
  26608e:	cc                   	int3
  26608f:	cc                   	int3
  266090:	e9 1b 1f 23 00       	jmp    0x497fb0
  266095:	cc                   	int3
  266096:	cc                   	int3
  266097:	cc                   	int3
  266098:	e9 43 1f 23 00       	jmp    0x497fe0
  26609d:	cc                   	int3
  26609e:	cc                   	int3
  26609f:	cc                   	int3
  2660a0:	e9 8b 25 23 00       	jmp    0x498630
  2660a5:	cc                   	int3
  2660a6:	cc                   	int3
  2660a7:	cc                   	int3
  2660a8:	e9 93 25 23 00       	jmp    0x498640
  2660ad:	cc                   	int3
  2660ae:	cc                   	int3
  2660af:	cc                   	int3
  2660b0:	e9 0b 1b 69 00       	jmp    0x8f7bc0
  2660b5:	cc                   	int3
  2660b6:	cc                   	int3
  2660b7:	cc                   	int3
  2660b8:	e9 43 07 69 00       	jmp    0x8f6800
  2660bd:	cc                   	int3
  2660be:	cc                   	int3
  2660bf:	cc                   	int3
  2660c0:	e9 5b 13 69 00       	jmp    0x8f7420
  2660c5:	cc                   	int3
  2660c6:	cc                   	int3
  2660c7:	cc                   	int3
  2660c8:	e9 b3 3e 69 00       	jmp    0x8f9f80
  2660cd:	cc                   	int3
  2660ce:	cc                   	int3
  2660cf:	cc                   	int3
  2660d0:	e9 7b 92 37 00       	jmp    0x5df350
  2660d5:	cc                   	int3
  2660d6:	cc                   	int3
  2660d7:	cc                   	int3
  2660d8:	e9 43 97 37 00       	jmp    0x5df820
  2660dd:	cc                   	int3
  2660de:	cc                   	int3
  2660df:	cc                   	int3
  2660e0:	e9 fb eb 7c 00       	jmp    0xa34ce0
  2660e5:	cc                   	int3
  2660e6:	cc                   	int3
  2660e7:	cc                   	int3
  2660e8:	e9 b3 23 38 00       	jmp    0x5e84a0
  2660ed:	cc                   	int3
  2660ee:	cc                   	int3
  2660ef:	cc                   	int3
  2660f0:	e9 fb 20 69 00       	jmp    0x8f81f0
  2660f5:	cc                   	int3
  2660f6:	cc                   	int3
  2660f7:	cc                   	int3
  2660f8:	e9 13 33 69 00       	jmp    0x8f9410
  2660fd:	cc                   	int3
  2660fe:	cc                   	int3
  2660ff:	cc                   	int3
  266100:	e9 eb 62 69 00       	jmp    0x8fc3f0
  266105:	cc                   	int3
  266106:	cc                   	int3
  266107:	cc                   	int3
  266108:	e9 83 0b 69 00       	jmp    0x8f6c90
  26610d:	cc                   	int3
  26610e:	cc                   	int3
  26610f:	cc                   	int3
  266110:	e9 fb b8 a4 00       	jmp    0xcb1a10
  266115:	cc                   	int3
  266116:	cc                   	int3
  266117:	cc                   	int3
  266118:	e9 83 22 85 00       	jmp    0xab83a0
  26611d:	cc                   	int3
  26611e:	cc                   	int3
  26611f:	cc                   	int3
  266120:	e9 8b 22 85 00       	jmp    0xab83b0
  266125:	cc                   	int3
  266126:	cc                   	int3
  266127:	cc                   	int3
  266128:	e9 93 40 69 00       	jmp    0x8fa1c0
  26612d:	cc                   	int3
  26612e:	cc                   	int3
  26612f:	cc                   	int3
  266130:	e9 0b 1a 69 00       	jmp    0x8f7b40
  266135:	cc                   	int3
  266136:	cc                   	int3
  266137:	cc                   	int3
  266138:	e9 23 a8 23 00       	jmp    0x4a0960
  26613d:	cc                   	int3
  26613e:	cc                   	int3
  26613f:	cc                   	int3
  266140:	e9 3b 36 4c 00       	jmp    0x729780
  266145:	cc                   	int3
  266146:	cc                   	int3
  266147:	cc                   	int3
  266148:	e9 43 36 4c 00       	jmp    0x729790
  26614d:	cc                   	int3
  26614e:	cc                   	int3
  26614f:	cc                   	int3
  266150:	e9 4b 36 4c 00       	jmp    0x7297a0
  266155:	cc                   	int3
  266156:	cc                   	int3
  266157:	cc                   	int3
  266158:	e9 33 54 45 00       	jmp    0x6bb590
  26615d:	cc                   	int3
  26615e:	cc                   	int3
  26615f:	cc                   	int3
  266160:	e9 3b 2c 85 00       	jmp    0xab8da0
  266165:	cc                   	int3
  266166:	cc                   	int3
  266167:	cc                   	int3
  266168:	e9 03 40 69 00       	jmp    0x8fa170
  26616d:	cc                   	int3
  26616e:	cc                   	int3
  26616f:	cc                   	int3
  266170:	e9 4b 8f 91 00       	jmp    0xb7f0c0
  266175:	cc                   	int3
  266176:	cc                   	int3
  266177:	cc                   	int3
  266178:	e9 83 8f 91 00       	jmp    0xb7f100
  26617d:	cc                   	int3
  26617e:	cc                   	int3
  26617f:	cc                   	int3
  266180:	e9 6b 3b 69 00       	jmp    0x8f9cf0
  266185:	cc                   	int3
  266186:	cc                   	int3
  266187:	cc                   	int3
  266188:	e9 b3 45 69 00       	jmp    0x8fa740
  26618d:	cc                   	int3
  26618e:	cc                   	int3
  26618f:	cc                   	int3
  266190:	e9 db c9 2e 00       	jmp    0x552b70
  266195:	cc                   	int3
  266196:	cc                   	int3
  266197:	cc                   	int3
  266198:	e9 53 ca 2e 00       	jmp    0x552bf0
  26619d:	cc                   	int3
  26619e:	cc                   	int3
  26619f:	cc                   	int3
  2661a0:	e9 ab ca 2e 00       	jmp    0x552c50
  2661a5:	cc                   	int3
  2661a6:	cc                   	int3
  2661a7:	cc                   	int3
  2661a8:	e9 d3 ca 2e 00       	jmp    0x552c80
  2661ad:	cc                   	int3
  2661ae:	cc                   	int3
  2661af:	cc                   	int3
  2661b0:	e9 fb ca 2e 00       	jmp    0x552cb0
  2661b5:	cc                   	int3
  2661b6:	cc                   	int3
  2661b7:	cc                   	int3
  2661b8:	e9 23 cb 2e 00       	jmp    0x552ce0
  2661bd:	cc                   	int3
  2661be:	cc                   	int3
  2661bf:	cc                   	int3
  2661c0:	e9 3b 86 91 00       	jmp    0xb7e800
  2661c5:	cc                   	int3
  2661c6:	cc                   	int3
  2661c7:	cc                   	int3
  2661c8:	e9 13 8a 91 00       	jmp    0xb7ebe0
  2661cd:	cc                   	int3
  2661ce:	cc                   	int3
  2661cf:	cc                   	int3
  2661d0:	e9 9b 8d 91 00       	jmp    0xb7ef70
  2661d5:	cc                   	int3
  2661d6:	cc                   	int3
  2661d7:	cc                   	int3
  2661d8:	e9 53 0b 9a 00       	jmp    0xc06d30
  2661dd:	cc                   	int3
  2661de:	cc                   	int3
  2661df:	cc                   	int3
  2661e0:	e9 ab c4 52 00       	jmp    0x792690
  2661e5:	cc                   	int3
  2661e6:	cc                   	int3
  2661e7:	cc                   	int3
  2661e8:	e9 33 29 38 00       	jmp    0x5e8b20
  2661ed:	cc                   	int3
  2661ee:	cc                   	int3
  2661ef:	cc                   	int3
  2661f0:	e9 1b cb 2e 00       	jmp    0x552d10
  2661f5:	cc                   	int3
  2661f6:	cc                   	int3
  2661f7:	cc                   	int3
  2661f8:	e9 63 8f 91 00       	jmp    0xb7f160
  2661fd:	cc                   	int3
  2661fe:	cc                   	int3
  2661ff:	cc                   	int3
  266200:	e9 4b 80 37 00       	jmp    0x5de250
  266205:	cc                   	int3
  266206:	cc                   	int3
  266207:	cc                   	int3
  266208:	e9 23 e8 7e 00       	jmp    0xa54a30
  26620d:	cc                   	int3
  26620e:	cc                   	int3
  26620f:	cc                   	int3
  266210:	e9 2b e8 7e 00       	jmp    0xa54a40
  266215:	cc                   	int3
  266216:	cc                   	int3
  266217:	cc                   	int3
  266218:	e9 33 e8 7e 00       	jmp    0xa54a50
  26621d:	cc                   	int3
  26621e:	cc                   	int3
  26621f:	cc                   	int3
  266220:	e9 3b e8 7e 00       	jmp    0xa54a60
  266225:	cc                   	int3
  266226:	cc                   	int3
  266227:	cc                   	int3
  266228:	e9 53 e8 7e 00       	jmp    0xa54a80
  26622d:	cc                   	int3
  26622e:	cc                   	int3
  26622f:	cc                   	int3
  266230:	e9 5b e8 7e 00       	jmp    0xa54a90
  266235:	cc                   	int3
  266236:	cc                   	int3
  266237:	cc                   	int3
  266238:	e9 e3 34 69 00       	jmp    0x8f9720
  26623d:	cc                   	int3
  26623e:	cc                   	int3
  26623f:	cc                   	int3
  266240:	e9 6b e8 7e 00       	jmp    0xa54ab0
  266245:	cc                   	int3
  266246:	cc                   	int3
  266247:	cc                   	int3
  266248:	e9 93 02 69 00       	jmp    0x8f64e0
  26624d:	cc                   	int3
  26624e:	cc                   	int3
  26624f:	cc                   	int3
  266250:	e9 9b fc 68 00       	jmp    0x8f5ef0
  266255:	cc                   	int3
  266256:	cc                   	int3
  266257:	cc                   	int3
  266258:	e9 c3 e7 7e 00       	jmp    0xa54a20
  26625d:	cc                   	int3
  26625e:	cc                   	int3
  26625f:	cc                   	int3
  266260:	e9 0b e8 7e 00       	jmp    0xa54a70
  266265:	cc                   	int3
  266266:	cc                   	int3
  266267:	cc                   	int3
  266268:	e9 33 e8 7e 00       	jmp    0xa54aa0
  26626d:	cc                   	int3
  26626e:	cc                   	int3
  26626f:	cc                   	int3
  266270:	e9 5b f2 47 00       	jmp    0x6e54d0
  266275:	cc                   	int3
  266276:	cc                   	int3
  266277:	cc                   	int3
  266278:	e9 33 92 91 00       	jmp    0xb7f4b0
  26627d:	cc                   	int3
  26627e:	cc                   	int3
  26627f:	cc                   	int3
  266280:	e9 db 73 5d 00       	jmp    0x83d660
  266285:	cc                   	int3
  266286:	cc                   	int3
  266287:	cc                   	int3
  266288:	e9 33 75 5d 00       	jmp    0x83d7c0
  26628d:	cc                   	int3
  26628e:	cc                   	int3
  26628f:	cc                   	int3
  266290:	e9 1b 78 5d 00       	jmp    0x83dab0
  266295:	cc                   	int3
  266296:	cc                   	int3
  266297:	cc                   	int3
  266298:	e9 e3 7b 5d 00       	jmp    0x83de80
  26629d:	cc                   	int3
  26629e:	cc                   	int3
  26629f:	cc                   	int3
  2662a0:	e9 db 39 69 00       	jmp    0x8f9c80
  2662a5:	cc                   	int3
  2662a6:	cc                   	int3
  2662a7:	cc                   	int3
  2662a8:	e9 63 3e 69 00       	jmp    0x8fa110
  2662ad:	cc                   	int3
  2662ae:	cc                   	int3
  2662af:	cc                   	int3
  2662b0:	e9 fb 2e 69 00       	jmp    0x8f91b0
  2662b5:	cc                   	int3
  2662b6:	cc                   	int3
  2662b7:	cc                   	int3
  2662b8:	e9 33 42 69 00       	jmp    0x8fa4f0
  2662bd:	cc                   	int3
  2662be:	cc                   	int3
  2662bf:	cc                   	int3
  2662c0:	e9 cb 1d 69 00       	jmp    0x8f8090
  2662c5:	cc                   	int3
  2662c6:	cc                   	int3
  2662c7:	cc                   	int3
  2662c8:	e9 b3 58 69 00       	jmp    0x8fbb80
  2662cd:	cc                   	int3
  2662ce:	cc                   	int3
  2662cf:	cc                   	int3
  2662d0:	e9 ab 18 69 00       	jmp    0x8f7b80
  2662d5:	cc                   	int3
  2662d6:	cc                   	int3
  2662d7:	cc                   	int3
  2662d8:	e9 b3 15 69 00       	jmp    0x8f7890
  2662dd:	cc                   	int3
  2662de:	cc                   	int3
  2662df:	cc                   	int3
  2662e0:	e9 bb 55 69 00       	jmp    0x8fb8a0
  2662e5:	cc                   	int3
  2662e6:	cc                   	int3
  2662e7:	cc                   	int3
  2662e8:	e9 23 22 69 00       	jmp    0x8f8510
  2662ed:	cc                   	int3
  2662ee:	cc                   	int3
  2662ef:	cc                   	int3
  2662f0:	e9 0b 25 69 00       	jmp    0x8f8800
  2662f5:	cc                   	int3
  2662f6:	cc                   	int3
  2662f7:	cc                   	int3
  2662f8:	e9 83 4d 23 00       	jmp    0x49b080
  2662fd:	cc                   	int3
  2662fe:	cc                   	int3
  2662ff:	cc                   	int3
  266300:	e9 8b 4d 23 00       	jmp    0x49b090
  266305:	cc                   	int3
  266306:	cc                   	int3
  266307:	cc                   	int3
  266308:	e9 43 97 2f 00       	jmp    0x55fa50
  26630d:	cc                   	int3
  26630e:	cc                   	int3
  26630f:	cc                   	int3
  266310:	e9 5b e5 9c 00       	jmp    0xc34870
  266315:	cc                   	int3
  266316:	cc                   	int3
  266317:	cc                   	int3
  266318:	e9 d3 69 57 00       	jmp    0x7dccf0
  26631d:	cc                   	int3
  26631e:	cc                   	int3
  26631f:	cc                   	int3
  266320:	e9 db 69 57 00       	jmp    0x7dcd00
  266325:	cc                   	int3
  266326:	cc                   	int3
  266327:	cc                   	int3
  266328:	e9 e3 69 57 00       	jmp    0x7dcd10
  26632d:	cc                   	int3
  26632e:	cc                   	int3
  26632f:	cc                   	int3
  266330:	e9 eb 69 57 00       	jmp    0x7dcd20
  266335:	cc                   	int3
  266336:	cc                   	int3
  266337:	cc                   	int3
  266338:	e9 f3 69 57 00       	jmp    0x7dcd30
  26633d:	cc                   	int3
  26633e:	cc                   	int3
  26633f:	cc                   	int3
  266340:	e9 4b 09 34 00       	jmp    0x5a6c90
  266345:	cc                   	int3
  266346:	cc                   	int3
  266347:	cc                   	int3
  266348:	e9 b3 0f 34 00       	jmp    0x5a7300
  26634d:	cc                   	int3
  26634e:	cc                   	int3
  26634f:	cc                   	int3
  266350:	e9 bb 12 34 00       	jmp    0x5a7610
  266355:	cc                   	int3
  266356:	cc                   	int3
  266357:	cc                   	int3
  266358:	e9 a3 15 34 00       	jmp    0x5a7900
  26635d:	cc                   	int3
  26635e:	cc                   	int3
  26635f:	cc                   	int3
  266360:	e9 cb 64 a3 00       	jmp    0xc9c830
  266365:	cc                   	int3
  266366:	cc                   	int3
  266367:	cc                   	int3
  266368:	e9 93 1b 34 00       	jmp    0x5a7f00
  26636d:	cc                   	int3
  26636e:	cc                   	int3
  26636f:	cc                   	int3
  266370:	e9 fb 1c 34 00       	jmp    0x5a8070
  266375:	cc                   	int3
  266376:	cc                   	int3
  266377:	cc                   	int3
  266378:	e9 03 21 98 00       	jmp    0xbe8480
  26637d:	cc                   	int3
  26637e:	cc                   	int3
  26637f:	cc                   	int3
  266380:	e9 1b 4d 23 00       	jmp    0x49b0a0
  266385:	cc                   	int3
  266386:	cc                   	int3
  266387:	cc                   	int3
  266388:	e9 33 4d 23 00       	jmp    0x49b0c0
  26638d:	cc                   	int3
  26638e:	cc                   	int3
  26638f:	cc                   	int3
  266390:	e9 3b 4d 23 00       	jmp    0x49b0d0
  266395:	cc                   	int3
  266396:	cc                   	int3
  266397:	cc                   	int3
  266398:	e9 43 4d 23 00       	jmp    0x49b0e0
  26639d:	cc                   	int3
  26639e:	cc                   	int3
  26639f:	cc                   	int3
  2663a0:	e9 4b 4d 23 00       	jmp    0x49b0f0
  2663a5:	cc                   	int3
  2663a6:	cc                   	int3
  2663a7:	cc                   	int3
  2663a8:	e9 73 a3 2c 00       	jmp    0x530720
  2663ad:	cc                   	int3
  2663ae:	cc                   	int3
  2663af:	cc                   	int3
  2663b0:	e9 bb b2 2c 00       	jmp    0x531670
  2663b5:	cc                   	int3
  2663b6:	cc                   	int3
  2663b7:	cc                   	int3
  2663b8:	e9 33 33 69 00       	jmp    0x8f96f0
  2663bd:	cc                   	int3
  2663be:	cc                   	int3
  2663bf:	cc                   	int3
  2663c0:	e9 6b ae 2c 00       	jmp    0x531230
  2663c5:	cc                   	int3
  2663c6:	cc                   	int3
  2663c7:	cc                   	int3
  2663c8:	e9 23 ca 59 00       	jmp    0x802df0
  2663cd:	cc                   	int3
  2663ce:	cc                   	int3
  2663cf:	cc                   	int3
  2663d0:	e9 6b 8d 91 00       	jmp    0xb7f140
  2663d5:	cc                   	int3
  2663d6:	cc                   	int3
  2663d7:	cc                   	int3
  2663d8:	e9 03 d2 87 00       	jmp    0xae35e0
  2663dd:	cc                   	int3
  2663de:	cc                   	int3
  2663df:	cc                   	int3
  2663e0:	e9 3b 8a 28 00       	jmp    0x4eee20
  2663e5:	cc                   	int3
  2663e6:	cc                   	int3
  2663e7:	cc                   	int3
  2663e8:	e9 23 47 69 00       	jmp    0x8fab10
  2663ed:	cc                   	int3
  2663ee:	cc                   	int3
  2663ef:	cc                   	int3
  2663f0:	e9 3b 4a 69 00       	jmp    0x8fae30
  2663f5:	cc                   	int3
  2663f6:	cc                   	int3
  2663f7:	cc                   	int3
  2663f8:	e9 23 2e 76 00       	jmp    0x9c9220
  2663fd:	cc                   	int3
  2663fe:	cc                   	int3
  2663ff:	cc                   	int3
  266400:	e9 fb 2c 76 00       	jmp    0x9c9100
  266405:	cc                   	int3
  266406:	cc                   	int3
  266407:	cc                   	int3
  266408:	e9 03 bf 3d 00       	jmp    0x642310
  26640d:	cc                   	int3
  26640e:	cc                   	int3
  26640f:	cc                   	int3
  266410:	e9 0b c4 3d 00       	jmp    0x642820
  266415:	cc                   	int3
  266416:	cc                   	int3
  266417:	cc                   	int3
  266418:	e9 c3 d2 3d 00       	jmp    0x6436e0
  26641d:	cc                   	int3
  26641e:	cc                   	int3
  26641f:	cc                   	int3
  266420:	e9 ab d4 3d 00       	jmp    0x6438d0
  266425:	cc                   	int3
  266426:	cc                   	int3
  266427:	cc                   	int3
  266428:	e9 33 d8 3d 00       	jmp    0x643c60
  26642d:	cc                   	int3
  26642e:	cc                   	int3
  26642f:	cc                   	int3
  266430:	e9 5b 1e 79 00       	jmp    0x9f8290
  266435:	cc                   	int3
  266436:	cc                   	int3
  266437:	cc                   	int3
  266438:	e9 33 57 79 00       	jmp    0x9fbb70
  26643d:	cc                   	int3
  26643e:	cc                   	int3
  26643f:	cc                   	int3
  266440:	e9 3b ee 7d 00       	jmp    0xa45280
  266445:	cc                   	int3
  266446:	cc                   	int3
  266447:	cc                   	int3
  266448:	e9 53 18 a2 00       	jmp    0xc87ca0
  26644d:	cc                   	int3
  26644e:	cc                   	int3
  26644f:	cc                   	int3
  266450:	e9 ab 8b 79 00       	jmp    0x9ff000
  266455:	cc                   	int3
  266456:	cc                   	int3
  266457:	cc                   	int3


; ===== SUPPLEMENTAL GNU objdump FULL original target-window bytes =====
; Source /tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin SHA256 c0261c0296d1c5c20d2ca1e543f4dc9d04da20e82e15eecd27bfc040556de56e
; RVA 0x2d36f0; size16384 bytes. This linear decode may include adjacent code/data and is not a REA boundary claim.

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/handler_rea_evidence/handler_675.body.bin:     file format binary


Disassembly of section .data:

00000000002d36f0 <.data>:
  2d36f0:	55                   	push   rbp
  2d36f1:	48 89 e5             	mov    rbp,rsp
  2d36f4:	c7 05 e2 2b 7c 01 01 	mov    DWORD PTR [rip+0x17c2be2],0x1        # 0x1a962e0
  2d36fb:	00 00 00 
  2d36fe:	48 c7 05 bf df a8 02 	mov    QWORD PTR [rip+0x2a8dfbf],0xffffffffffffffff        # 0x2d616c8
  2d3705:	ff ff ff ff 
  2d3709:	48 c7 05 f4 c8 a8 02 	mov    QWORD PTR [rip+0x2a8c8f4],0x0        # 0x2d60008
  2d3710:	00 00 00 00 
  2d3714:	31 c0                	xor    eax,eax
  2d3716:	5d                   	pop    rbp
  2d3717:	c3                   	ret
  2d3718:	90                   	nop
  2d3719:	90                   	nop
  2d371a:	90                   	nop
  2d371b:	90                   	nop
  2d371c:	90                   	nop
  2d371d:	90                   	nop
  2d371e:	90                   	nop
  2d371f:	90                   	nop
  2d3720:	55                   	push   rbp
  2d3721:	48 89 e5             	mov    rbp,rsp
  2d3724:	48 8b 05 dd c8 a8 02 	mov    rax,QWORD PTR [rip+0x2a8c8dd]        # 0x2d60008
  2d372b:	5d                   	pop    rbp
  2d372c:	c3                   	ret
  2d372d:	90                   	nop
  2d372e:	90                   	nop
  2d372f:	90                   	nop
  2d3730:	55                   	push   rbp
  2d3731:	48 89 e5             	mov    rbp,rsp
  2d3734:	41 57                	push   r15
  2d3736:	41 56                	push   r14
  2d3738:	41 55                	push   r13
  2d373a:	41 54                	push   r12
  2d373c:	53                   	push   rbx
  2d373d:	48 83 ec 18          	sub    rsp,0x18
  2d3741:	4c 8d 2d c8 8b 64 03 	lea    r13,[rip+0x3648bc8]        # 0x391c310
  2d3748:	49 89 f7             	mov    r15,rsi
  2d374b:	49 89 fe             	mov    r14,rdi
  2d374e:	49 8b 45 00          	mov    rax,QWORD PTR [r13+0x0]
  2d3752:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  2d3756:	e8 e5 61 33 00       	call   0x609940
  2d375b:	85 c0                	test   eax,eax
  2d375d:	0f 84 8e 00 00 00    	je     0x2d37f1
  2d3763:	49 8b 5f 08          	mov    rbx,QWORD PTR [r15+0x8]
  2d3767:	b8 16 00 00 00       	mov    eax,0x16
  2d376c:	48 85 db             	test   rbx,rbx
  2d376f:	0f 84 81 00 00 00    	je     0x2d37f6
  2d3775:	49 8b 46 08          	mov    rax,QWORD PTR [r14+0x8]
  2d3779:	4d 8b 3f             	mov    r15,QWORD PTR [r15]
  2d377c:	31 f6                	xor    esi,esi
  2d377e:	31 d2                	xor    edx,edx
  2d3780:	31 c9                	xor    ecx,ecx
  2d3782:	48 8b 80 00 02 00 00 	mov    rax,QWORD PTR [rax+0x200]
  2d3789:	4c 8b b0 d8 01 00 00 	mov    r14,QWORD PTR [rax+0x1d8]
  2d3790:	4d 8d 66 18          	lea    r12,[r14+0x18]
  2d3794:	4c 89 e7             	mov    rdi,r12
  2d3797:	e8 64 32 1f 00       	call   0x4c6a00
  2d379c:	48 8d 55 c8          	lea    rdx,[rbp-0x38]
  2d37a0:	4c 89 f7             	mov    rdi,r14
  2d37a3:	4c 89 fe             	mov    rsi,r15
  2d37a6:	e8 65 9f 61 00       	call   0x8ed710
  2d37ab:	4c 89 e7             	mov    rdi,r12
  2d37ae:	49 89 c6             	mov    r14,rax
  2d37b1:	31 f6                	xor    esi,esi
  2d37b3:	31 d2                	xor    edx,edx
  2d37b5:	31 c9                	xor    ecx,ecx
  2d37b7:	e8 e4 37 1f 00       	call   0x4c6fa0
  2d37bc:	b8 16 00 00 00       	mov    eax,0x16
  2d37c1:	41 f6 c6 01          	test   r14b,0x1
  2d37c5:	74 2f                	je     0x2d37f6
  2d37c7:	65 48 8b 3c 25 00 00 	mov    rdi,QWORD PTR gs:0x0
  2d37ce:	00 00 
  2d37d0:	48 8d 35 c0 ba 07 01 	lea    rsi,[rip+0x107bac0]        # 0x134f297
  2d37d7:	31 d2                	xor    edx,edx
  2d37d9:	e8 02 6c 94 00       	call   0xc1a3e0
  2d37de:	48 8d 7d c8          	lea    rdi,[rbp-0x38]
  2d37e2:	ba 08 00 00 00       	mov    edx,0x8
  2d37e7:	48 89 de             	mov    rsi,rbx
  2d37ea:	e8 e1 59 f8 ff       	call   0x2591d0
  2d37ef:	eb 05                	jmp    0x2d37f6
  2d37f1:	b8 01 00 00 00       	mov    eax,0x1
  2d37f6:	49 8b 4d 00          	mov    rcx,QWORD PTR [r13+0x0]
  2d37fa:	48 3b 4d d0          	cmp    rcx,QWORD PTR [rbp-0x30]
  2d37fe:	75 0f                	jne    0x2d380f
  2d3800:	48 83 c4 18          	add    rsp,0x18
  2d3804:	5b                   	pop    rbx
  2d3805:	41 5c                	pop    r12
  2d3807:	41 5d                	pop    r13
  2d3809:	41 5e                	pop    r14
  2d380b:	41 5f                	pop    r15
  2d380d:	5d                   	pop    rbp
  2d380e:	c3                   	ret
  2d380f:	e8 9c 9e 42 00       	call   0x6fd6b0
  2d3814:	0f 0b                	ud2
  2d3816:	90                   	nop
  2d3817:	90                   	nop
  2d3818:	90                   	nop
  2d3819:	90                   	nop
  2d381a:	90                   	nop
  2d381b:	90                   	nop
  2d381c:	90                   	nop
  2d381d:	90                   	nop
  2d381e:	90                   	nop
  2d381f:	90                   	nop
  2d3820:	f6 87 44 02 00 00 40 	test   BYTE PTR [rdi+0x244],0x40
  2d3827:	74 2e                	je     0x2d3857
  2d3829:	55                   	push   rbp
  2d382a:	48 89 e5             	mov    rbp,rsp
  2d382d:	53                   	push   rbx
  2d382e:	50                   	push   rax
  2d382f:	48 be 00 00 00 80 0c 	movabs rsi,0xc80000000
  2d3836:	00 00 00 
  2d3839:	48 89 fb             	mov    rbx,rdi
  2d383c:	31 c9                	xor    ecx,ecx
  2d383e:	48 8d 96 00 80 04 00 	lea    rdx,[rsi+0x48000]
  2d3845:	e8 b6 b0 ff ff       	call   0x2ce900
  2d384a:	80 a3 44 02 00 00 bf 	and    BYTE PTR [rbx+0x244],0xbf
  2d3851:	48 83 c4 08          	add    rsp,0x8
  2d3855:	5b                   	pop    rbx
  2d3856:	5d                   	pop    rbp
  2d3857:	c3                   	ret
  2d3858:	90                   	nop
  2d3859:	90                   	nop
  2d385a:	90                   	nop
  2d385b:	90                   	nop
  2d385c:	90                   	nop
  2d385d:	90                   	nop
  2d385e:	90                   	nop
  2d385f:	90                   	nop
  2d3860:	48 8b 87 00 02 00 00 	mov    rax,QWORD PTR [rdi+0x200]
  2d3867:	48 8b 80 d8 01 00 00 	mov    rax,QWORD PTR [rax+0x1d8]
  2d386e:	8b 80 7c 02 00 00    	mov    eax,DWORD PTR [rax+0x27c]
  2d3874:	85 c0                	test   eax,eax
  2d3876:	74 01                	je     0x2d3879
  2d3878:	c3                   	ret
  2d3879:	55                   	push   rbp
  2d387a:	48 89 e5             	mov    rbp,rsp
  2d387d:	53                   	push   rbx
  2d387e:	50                   	push   rax
  2d387f:	48 89 fb             	mov    rbx,rdi
  2d3882:	e8 c9 e0 51 00       	call   0x7f1950
  2d3887:	48 63 b3 bc 00 00 00 	movsxd rsi,DWORD PTR [rbx+0xbc]
  2d388e:	48 8d 3d e4 ff ff ff 	lea    rdi,[rip+0xffffffffffffffe4]        # 0x2d3879
  2d3895:	e8 06 e0 51 00       	call   0x7f18a0
  2d389a:	8b 93 bc 00 00 00    	mov    edx,DWORD PTR [rbx+0xbc]
  2d38a0:	48 8d 35 4b c1 fa 00 	lea    rsi,[rip+0xfac14b]        # 0x127f9f2
  2d38a7:	bf 83 00 00 00       	mov    edi,0x83
  2d38ac:	31 c0                	xor    eax,eax
  2d38ae:	e8 5d 71 9c 00       	call   0xc9aa10
  2d38b3:	0f 0b                	ud2
  2d38b5:	90                   	nop
  2d38b6:	90                   	nop
  2d38b7:	90                   	nop
  2d38b8:	90                   	nop
  2d38b9:	90                   	nop
  2d38ba:	90                   	nop
  2d38bb:	90                   	nop
  2d38bc:	90                   	nop
  2d38bd:	90                   	nop
  2d38be:	90                   	nop
  2d38bf:	90                   	nop
  2d38c0:	55                   	push   rbp
  2d38c1:	48 89 e5             	mov    rbp,rsp
  2d38c4:	5d                   	pop    rbp
  2d38c5:	e9 96 ff ff ff       	jmp    0x2d3860
  2d38ca:	90                   	nop
  2d38cb:	90                   	nop
  2d38cc:	90                   	nop
  2d38cd:	90                   	nop
  2d38ce:	90                   	nop
  2d38cf:	90                   	nop
  2d38d0:	48 8b 87 00 02 00 00 	mov    rax,QWORD PTR [rdi+0x200]
  2d38d7:	8b 80 ec 01 00 00    	mov    eax,DWORD PTR [rax+0x1ec]
  2d38dd:	83 f8 ff             	cmp    eax,0xffffffff
  2d38e0:	74 01                	je     0x2d38e3
  2d38e2:	c3                   	ret
  2d38e3:	55                   	push   rbp
  2d38e4:	48 89 e5             	mov    rbp,rsp
  2d38e7:	53                   	push   rbx
  2d38e8:	50                   	push   rax
  2d38e9:	48 89 fb             	mov    rbx,rdi
  2d38ec:	e8 5f e0 51 00       	call   0x7f1950
  2d38f1:	48 63 b3 bc 00 00 00 	movsxd rsi,DWORD PTR [rbx+0xbc]
  2d38f8:	48 8d 3d e4 ff ff ff 	lea    rdi,[rip+0xffffffffffffffe4]        # 0x2d38e3
  2d38ff:	e8 9c df 51 00       	call   0x7f18a0
  2d3904:	8b 93 bc 00 00 00    	mov    edx,DWORD PTR [rbx+0xbc]
  2d390a:	48 8d 35 76 a5 0b 01 	lea    rsi,[rip+0x10ba576]        # 0x138de87
  2d3911:	bf 87 00 00 00       	mov    edi,0x87
  2d3916:	31 c0                	xor    eax,eax
  2d3918:	e8 f3 70 9c 00       	call   0xc9aa10
  2d391d:	0f 0b                	ud2
  2d391f:	90                   	nop
  2d3920:	55                   	push   rbp
  2d3921:	48 89 e5             	mov    rbp,rsp
  2d3924:	41 57                	push   r15
  2d3926:	41 56                	push   r14
  2d3928:	41 55                	push   r13
  2d392a:	41 54                	push   r12
  2d392c:	53                   	push   rbx
  2d392d:	48 81 ec a8 00 00 00 	sub    rsp,0xa8
  2d3934:	4c 8d 3d d5 89 64 03 	lea    r15,[rip+0x36489d5]        # 0x391c310
  2d393b:	44 8b 75 18          	mov    r14d,DWORD PTR [rbp+0x18]
  2d393f:	4c 8b 6d 10          	mov    r13,QWORD PTR [rbp+0x10]
  2d3943:	41 bc 16 00 00 00    	mov    r12d,0x16
  2d3949:	49 8b 07             	mov    rax,QWORD PTR [r15]
  2d394c:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  2d3950:	48 8b 9e 00 02 00 00 	mov    rbx,QWORD PTR [rsi+0x200]
  2d3957:	48 89 37             	mov    QWORD PTR [rdi],rsi
  2d395a:	48 89 57 08          	mov    QWORD PTR [rdi+0x8],rdx
  2d395e:	48 89 4f 10          	mov    QWORD PTR [rdi+0x10],rcx
  2d3962:	4c 89 4f 18          	mov    QWORD PTR [rdi+0x18],r9
  2d3966:	4c 89 6f 20          	mov    QWORD PTR [rdi+0x20],r13
  2d396a:	48 c7 47 28 00 00 00 	mov    QWORD PTR [rdi+0x28],0x0
  2d3971:	00 
  2d3972:	48 c7 47 30 00 00 00 	mov    QWORD PTR [rdi+0x30],0x0
  2d3979:	00 
  2d397a:	c7 47 38 00 00 00 00 	mov    DWORD PTR [rdi+0x38],0x0
  2d3981:	41 83 fe 03          	cmp    r14d,0x3
  2d3985:	0f 87 b3 04 00 00    	ja     0x2d3e3e
  2d398b:	48 89 d0             	mov    rax,rdx
  2d398e:	48 c1 e8 2b          	shr    rax,0x2b
  2d3992:	74 25                	je     0x2d39b9
  2d3994:	48 83 ec 08          	sub    rsp,0x8
  2d3998:	45 0f b6 c0          	movzx  r8d,r8b
  2d399c:	41 55                	push   r13
  2d399e:	e8 bd 05 00 00       	call   0x2d3f60
  2d39a3:	48 83 c4 10          	add    rsp,0x10
  2d39a7:	49 8b 0f             	mov    rcx,QWORD PTR [r15]
  2d39aa:	48 3b 4d d0          	cmp    rcx,QWORD PTR [rbp-0x30]
  2d39ae:	0f 84 9a 04 00 00    	je     0x2d3e4e
  2d39b4:	e9 62 05 00 00       	jmp    0x2d3f1b
  2d39b9:	48 8d 04 11          	lea    rax,[rcx+rdx*1]
  2d39bd:	48 39 d0             	cmp    rax,rdx
  2d39c0:	0f 86 78 04 00 00    	jbe    0x2d3e3e
  2d39c6:	48 3b 53 20          	cmp    rdx,QWORD PTR [rbx+0x20]
  2d39ca:	0f 82 6e 04 00 00    	jb     0x2d3e3e
  2d39d0:	48 39 43 28          	cmp    QWORD PTR [rbx+0x28],rax
  2d39d4:	0f 82 64 04 00 00    	jb     0x2d3e3e
  2d39da:	4c 89 4d 98          	mov    QWORD PTR [rbp-0x68],r9
  2d39de:	48 89 7d b8          	mov    QWORD PTR [rbp-0x48],rdi
  2d39e2:	48 89 8d 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rcx
  2d39e9:	41 0f b6 c8          	movzx  ecx,r8b
  2d39ed:	48 89 df             	mov    rdi,rbx
  2d39f0:	48 89 d6             	mov    rsi,rdx
  2d39f3:	48 89 8d 48 ff ff ff 	mov    QWORD PTR [rbp-0xb8],rcx
  2d39fa:	8d 0c 8d 00 00 00 00 	lea    ecx,[rcx*4+0x0]
  2d3a01:	48 89 55 c0          	mov    QWORD PTR [rbp-0x40],rdx
  2d3a05:	48 89 c2             	mov    rdx,rax
  2d3a08:	89 4d ac             	mov    DWORD PTR [rbp-0x54],ecx
  2d3a0b:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
  2d3a0f:	e8 ac b3 ff ff       	call   0x2cedc0
  2d3a14:	85 c0                	test   eax,eax
  2d3a16:	74 2e                	je     0x2d3a46
  2d3a18:	83 f8 01             	cmp    eax,0x1
  2d3a1b:	0f 84 1d 04 00 00    	je     0x2d3e3e
  2d3a21:	49 8b 0f             	mov    rcx,QWORD PTR [r15]
  2d3a24:	48 3b 4d d0          	cmp    rcx,QWORD PTR [rbp-0x30]
  2d3a28:	0f 85 ed 04 00 00    	jne    0x2d3f1b
  2d3a2e:	89 c7                	mov    edi,eax
  2d3a30:	48 81 c4 a8 00 00 00 	add    rsp,0xa8
  2d3a37:	5b                   	pop    rbx
  2d3a38:	41 5c                	pop    r12
  2d3a3a:	41 5d                	pop    r13
  2d3a3c:	41 5e                	pop    r14
  2d3a3e:	41 5f                	pop    r15
  2d3a40:	5d                   	pop    rbp
  2d3a41:	e9 6a 52 7e 00       	jmp    0xab8cb0
  2d3a46:	41 83 fe 02          	cmp    r14d,0x2
  2d3a4a:	44 8b 75 ac          	mov    r14d,DWORD PTR [rbp-0x54]
  2d3a4e:	72 21                	jb     0x2d3a71
  2d3a50:	48 8b 75 c0          	mov    rsi,QWORD PTR [rbp-0x40]
  2d3a54:	48 8b 95 70 ff ff ff 	mov    rdx,QWORD PTR [rbp-0x90]
  2d3a5b:	48 89 df             	mov    rdi,rbx
  2d3a5e:	e8 6d 07 00 00       	call   0x2d41d0
  2d3a63:	41 bc 3f 00 00 00    	mov    r12d,0x3f
  2d3a69:	85 c0                	test   eax,eax
  2d3a6b:	0f 85 ba 03 00 00    	jne    0x2d3e2b
  2d3a71:	48 8b bd 70 ff ff ff 	mov    rdi,QWORD PTR [rbp-0x90]
  2d3a78:	e8 33 f9 22 00       	call   0x5033b0
  2d3a7d:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
  2d3a81:	48 89 41 28          	mov    QWORD PTR [rcx+0x28],rax
  2d3a85:	48 85 c0             	test   rax,rax
  2d3a88:	0f 84 6b 03 00 00    	je     0x2d3df9
  2d3a8e:	48 89 df             	mov    rdi,rbx
  2d3a91:	45 31 e4             	xor    r12d,r12d
  2d3a94:	31 f6                	xor    esi,esi
  2d3a96:	31 d2                	xor    edx,edx
  2d3a98:	e8 e3 29 ff ff       	call   0x2c6480
  2d3a9d:	48 8b 75 c0          	mov    rsi,QWORD PTR [rbp-0x40]
  2d3aa1:	48 8d 55 c8          	lea    rdx,[rbp-0x38]
  2d3aa5:	48 89 df             	mov    rdi,rbx
  2d3aa8:	e8 93 31 ff ff       	call   0x2c6c40
  2d3aad:	85 c0                	test   eax,eax
  2d3aaf:	0f 84 4c 03 00 00    	je     0x2d3e01
  2d3ab5:	48 8b 4d c8          	mov    rcx,QWORD PTR [rbp-0x38]
  2d3ab9:	48 39 d9             	cmp    rcx,rbx
  2d3abc:	74 2a                	je     0x2d3ae8
  2d3abe:	48 8b 75 c0          	mov    rsi,QWORD PTR [rbp-0x40]
  2d3ac2:	48 8b 55 90          	mov    rdx,QWORD PTR [rbp-0x70]
  2d3ac6:	45 31 e4             	xor    r12d,r12d
  2d3ac9:	48 39 51 20          	cmp    QWORD PTR [rcx+0x20],rdx
  2d3acd:	73 19                	jae    0x2d3ae8
  2d3acf:	41 81 fc ff 0f 00 00 	cmp    r12d,0xfff
  2d3ad6:	0f 84 31 03 00 00    	je     0x2d3e0d
  2d3adc:	48 8b 49 08          	mov    rcx,QWORD PTR [rcx+0x8]
  2d3ae0:	41 ff c4             	inc    r12d
  2d3ae3:	48 39 d9             	cmp    rcx,rbx
  2d3ae6:	75 e1                	jne    0x2d3ac9
  2d3ae8:	48 8d 35 91 85 92 02 	lea    rsi,[rip+0x2928591]        # 0x2bfc080
  2d3aef:	44 89 e7             	mov    edi,r12d
  2d3af2:	ba 02 00 00 00       	mov    edx,0x2
  2d3af7:	48 89 4d c8          	mov    QWORD PTR [rbp-0x38],rcx
  2d3afb:	48 c1 e7 05          	shl    rdi,0x5
  2d3aff:	e8 4c 50 93 00       	call   0xc08b50
  2d3b04:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
  2d3b08:	48 8d 55 c8          	lea    rdx,[rbp-0x38]
  2d3b0c:	48 89 df             	mov    rdi,rbx
  2d3b0f:	48 89 41 30          	mov    QWORD PTR [rcx+0x30],rax
  2d3b13:	44 89 61 38          	mov    DWORD PTR [rcx+0x38],r12d
  2d3b17:	48 8b 41 28          	mov    rax,QWORD PTR [rcx+0x28]
  2d3b1b:	48 89 85 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rax
  2d3b22:	48 8b 75 c0          	mov    rsi,QWORD PTR [rbp-0x40]
  2d3b26:	e8 15 31 ff ff       	call   0x2c6c40
  2d3b2b:	48 8b 75 c8          	mov    rsi,QWORD PTR [rbp-0x38]
  2d3b2f:	45 31 e4             	xor    r12d,r12d
  2d3b32:	48 39 de             	cmp    rsi,rbx
  2d3b35:	0f 84 e4 02 00 00    	je     0x2d3e1f
  2d3b3b:	48 8b 55 90          	mov    rdx,QWORD PTR [rbp-0x70]
  2d3b3f:	48 39 56 20          	cmp    QWORD PTR [rsi+0x20],rdx
  2d3b43:	0f 83 d6 02 00 00    	jae    0x2d3e1f
  2d3b49:	f6 46 60 02          	test   BYTE PTR [rsi+0x60],0x2
  2d3b4d:	0f 85 0d 03 00 00    	jne    0x2d3e60
  2d3b53:	48 8d 83 a8 01 00 00 	lea    rax,[rbx+0x1a8]
  2d3b5a:	48 8d 8b 70 01 00 00 	lea    rcx,[rbx+0x170]
  2d3b61:	4c 8d 4e 20          	lea    r9,[rsi+0x20]
  2d3b65:	48 89 85 38 ff ff ff 	mov    QWORD PTR [rbp-0xc8],rax
  2d3b6c:	48 89 8d 40 ff ff ff 	mov    QWORD PTR [rbp-0xc0],rcx
  2d3b73:	48 c7 45 80 00 00 00 	mov    QWORD PTR [rbp-0x80],0x0
  2d3b7a:	00 
  2d3b7b:	48 8b 4d c0          	mov    rcx,QWORD PTR [rbp-0x40]
  2d3b7f:	48 89 4d 88          	mov    QWORD PTR [rbp-0x78],rcx
  2d3b83:	4c 89 6d b0          	mov    QWORD PTR [rbp-0x50],r13
  2d3b87:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
  2d3b8b:	48 8b 7d 98          	mov    rdi,QWORD PTR [rbp-0x68]
  2d3b8f:	4c 8b 46 50          	mov    r8,QWORD PTR [rsi+0x50]
  2d3b93:	48 89 b5 50 ff ff ff 	mov    QWORD PTR [rbp-0xb0],rsi
  2d3b9a:	4c 89 4d a0          	mov    QWORD PTR [rbp-0x60],r9
  2d3b9e:	4c 89 85 30 ff ff ff 	mov    QWORD PTR [rbp-0xd0],r8
  2d3ba5:	4d 85 c0             	test   r8,r8
  2d3ba8:	0f 84 3c 02 00 00    	je     0x2d3dea
  2d3bae:	4c 63 75 80          	movsxd r14,DWORD PTR [rbp-0x80]
  2d3bb2:	48 8b 78 30          	mov    rdi,QWORD PTR [rax+0x30]
  2d3bb6:	be 20 00 00 00       	mov    esi,0x20
  2d3bbb:	49 c1 e6 05          	shl    r14,0x5
  2d3bbf:	4c 01 f7             	add    rdi,r14
  2d3bc2:	e8 29 54 f8 ff       	call   0x258ff0
  2d3bc7:	48 8b b5 50 ff ff ff 	mov    rsi,QWORD PTR [rbp-0xb0]
  2d3bce:	48 8b 55 a0          	mov    rdx,QWORD PTR [rbp-0x60]
  2d3bd2:	48 8b 4d b8          	mov    rcx,QWORD PTR [rbp-0x48]
  2d3bd6:	4c 89 b5 58 ff ff ff 	mov    QWORD PTR [rbp-0xa8],r14
  2d3bdd:	48 89 df             	mov    rdi,rbx
  2d3be0:	48 8b 46 28          	mov    rax,QWORD PTR [rsi+0x28]
  2d3be4:	48 2b 02             	sub    rax,QWORD PTR [rdx]
  2d3be7:	48 8b 49 30          	mov    rcx,QWORD PTR [rcx+0x30]
  2d3beb:	4a 89 44 31 10       	mov    QWORD PTR [rcx+r14*1+0x10],rax
  2d3bf0:	4c 8b 75 c0          	mov    r14,QWORD PTR [rbp-0x40]
  2d3bf4:	48 8b 02             	mov    rax,QWORD PTR [rdx]
  2d3bf7:	48 8b 4e 28          	mov    rcx,QWORD PTR [rsi+0x28]
  2d3bfb:	48 8b 55 90          	mov    rdx,QWORD PTR [rbp-0x70]
  2d3bff:	4c 39 f0             	cmp    rax,r14
  2d3c02:	4c 0f 47 f0          	cmova  r14,rax
  2d3c06:	48 39 d1             	cmp    rcx,rdx
  2d3c09:	48 0f 43 ca          	cmovae rcx,rdx
  2d3c0d:	4c 89 f2             	mov    rdx,r14
  2d3c10:	48 29 c2             	sub    rdx,rax
  2d3c13:	48 03 56 58          	add    rdx,QWORD PTR [rsi+0x58]
  2d3c17:	4c 29 f1             	sub    rcx,r14
  2d3c1a:	31 f6                	xor    esi,esi
  2d3c1c:	48 89 95 60 ff ff ff 	mov    QWORD PTR [rbp-0xa0],rdx
  2d3c23:	4c 89 75 88          	mov    QWORD PTR [rbp-0x78],r14
  2d3c27:	44 8b b3 c0 01 00 00 	mov    r14d,DWORD PTR [rbx+0x1c0]
  2d3c2e:	31 d2                	xor    edx,edx
  2d3c30:	48 89 4d a0          	mov    QWORD PTR [rbp-0x60],rcx
  2d3c34:	e8 b7 28 ff ff       	call   0x2c64f0
  2d3c39:	48 8b bd 30 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xd0]
  2d3c40:	44 89 b5 6c ff ff ff 	mov    DWORD PTR [rbp-0x94],r14d
  2d3c47:	0f b6 87 9d 00 00 00 	movzx  eax,BYTE PTR [rdi+0x9d]
  2d3c4e:	83 f8 0b             	cmp    eax,0xb
  2d3c51:	74 57                	je     0x2d3caa
  2d3c53:	83 f8 03             	cmp    eax,0x3
  2d3c56:	75 09                	jne    0x2d3c61
  2d3c58:	f6 87 a2 00 00 00 01 	test   BYTE PTR [rdi+0xa2],0x1
  2d3c5f:	75 51                	jne    0x2d3cb2
  2d3c61:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
  2d3c65:	4c 8b 95 58 ff ff ff 	mov    r10,QWORD PTR [rbp-0xa8]
  2d3c6c:	48 8b b5 60 ff ff ff 	mov    rsi,QWORD PTR [rbp-0xa0]
  2d3c73:	48 8b 55 a0          	mov    rdx,QWORD PTR [rbp-0x60]
  2d3c77:	4c 8b 45 98          	mov    r8,QWORD PTR [rbp-0x68]
  2d3c7b:	4c 8b 4d b0          	mov    r9,QWORD PTR [rbp-0x50]
  2d3c7f:	48 8b 8d 48 ff ff ff 	mov    rcx,QWORD PTR [rbp-0xb8]
  2d3c86:	4c 03 50 30          	add    r10,QWORD PTR [rax+0x30]
  2d3c8a:	41 52                	push   r10
  2d3c8c:	ff b5 78 ff ff ff    	push   QWORD PTR [rbp-0x88]
  2d3c92:	e8 99 09 00 00       	call   0x2d4630
  2d3c97:	48 83 c4 10          	add    rsp,0x10
  2d3c9b:	41 89 c6             	mov    r14d,eax
  2d3c9e:	83 f8 01             	cmp    eax,0x1
  2d3ca1:	48 8b 45 80          	mov    rax,QWORD PTR [rbp-0x80]
  2d3ca5:	83 d0 00             	adc    eax,0x0
  2d3ca8:	eb 4b                	jmp    0x2d3cf5
  2d3caa:	41 be 2d 00 00 00    	mov    r14d,0x2d
  2d3cb0:	eb 47                	jmp    0x2d3cf9
  2d3cb2:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
  2d3cb6:	4c 8b 95 58 ff ff ff 	mov    r10,QWORD PTR [rbp-0xa8]
  2d3cbd:	48 8b b5 60 ff ff ff 	mov    rsi,QWORD PTR [rbp-0xa0]
  2d3cc4:	48 8b 55 a0          	mov    rdx,QWORD PTR [rbp-0x60]
  2d3cc8:	4c 8b 45 98          	mov    r8,QWORD PTR [rbp-0x68]
  2d3ccc:	4c 8b 4d b0          	mov    r9,QWORD PTR [rbp-0x50]
  2d3cd0:	48 8b 8d 48 ff ff ff 	mov    rcx,QWORD PTR [rbp-0xb8]
  2d3cd7:	4c 03 50 30          	add    r10,QWORD PTR [rax+0x30]
  2d3cdb:	41 52                	push   r10
  2d3cdd:	ff b5 78 ff ff ff    	push   QWORD PTR [rbp-0x88]
  2d3ce3:	e8 f8 06 00 00       	call   0x2d43e0
  2d3ce8:	48 83 c4 10          	add    rsp,0x10
  2d3cec:	48 8b 45 80          	mov    rax,QWORD PTR [rbp-0x80]
  2d3cf0:	45 31 f6             	xor    r14d,r14d
  2d3cf3:	ff c0                	inc    eax
  2d3cf5:	48 89 45 80          	mov    QWORD PTR [rbp-0x80],rax
  2d3cf9:	0f b6 83 44 02 00 00 	movzx  eax,BYTE PTR [rbx+0x244]
  2d3d00:	a8 10                	test   al,0x10
  2d3d02:	75 29                	jne    0x2d3d2d
  2d3d04:	a8 08                	test   al,0x8
  2d3d06:	74 11                	je     0x2d3d19
  2d3d08:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  2d3d0f:	00 00 
  2d3d11:	f0 83 80 a8 05 00 00 	lock add DWORD PTR [rax+0x5a8],0x1
  2d3d18:	01 
  2d3d19:	48 8b bd 40 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xc0]
  2d3d20:	31 f6                	xor    esi,esi
  2d3d22:	31 d2                	xor    edx,edx
  2d3d24:	31 c9                	xor    ecx,ecx
  2d3d26:	e8 f5 7d 97 00       	call   0xc4bb20
  2d3d2b:	eb 12                	jmp    0x2d3d3f
  2d3d2d:	48 8b bd 38 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xc8]
  2d3d34:	31 f6                	xor    esi,esi
  2d3d36:	31 d2                	xor    edx,edx
  2d3d38:	31 c9                	xor    ecx,ecx
  2d3d3a:	e8 c1 2c 1f 00       	call   0x4c6a00
  2d3d3f:	ff 83 c0 01 00 00    	inc    DWORD PTR [rbx+0x1c0]
  2d3d45:	45 89 f0             	mov    r8d,r14d
  2d3d48:	f0 83 83 c4 01 00 00 	lock add DWORD PTR [rbx+0x1c4],0x1
  2d3d4f:	01 
  2d3d50:	8b 85 6c ff ff ff    	mov    eax,DWORD PTR [rbp-0x94]
  2d3d56:	48 8b 7d 98          	mov    rdi,QWORD PTR [rbp-0x68]
  2d3d5a:	48 8b 55 90          	mov    rdx,QWORD PTR [rbp-0x70]
  2d3d5e:	48 8b b5 50 ff ff ff 	mov    rsi,QWORD PTR [rbp-0xb0]
  2d3d65:	ff c0                	inc    eax
  2d3d67:	39 83 c0 01 00 00    	cmp    DWORD PTR [rbx+0x1c0],eax
  2d3d6d:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
  2d3d71:	74 2b                	je     0x2d3d9e
  2d3d73:	48 8b 75 88          	mov    rsi,QWORD PTR [rbp-0x78]
  2d3d77:	48 89 df             	mov    rdi,rbx
  2d3d7a:	48 8d 55 c8          	lea    rdx,[rbp-0x38]
  2d3d7e:	e8 bd 2e ff ff       	call   0x2c6c40
  2d3d83:	85 c0                	test   eax,eax
  2d3d85:	0f 84 97 01 00 00    	je     0x2d3f22
  2d3d8b:	48 8b 75 c8          	mov    rsi,QWORD PTR [rbp-0x38]
  2d3d8f:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
  2d3d93:	48 8b 7d 98          	mov    rdi,QWORD PTR [rbp-0x68]
  2d3d97:	48 8b 55 90          	mov    rdx,QWORD PTR [rbp-0x70]
  2d3d9b:	45 89 f0             	mov    r8d,r14d
  2d3d9e:	4c 8b 4d a0          	mov    r9,QWORD PTR [rbp-0x60]
  2d3da2:	48 8b 76 08          	mov    rsi,QWORD PTR [rsi+0x8]
  2d3da6:	4c 01 4d b0          	add    QWORD PTR [rbp-0x50],r9
  2d3daa:	48 89 75 c8          	mov    QWORD PTR [rbp-0x38],rsi
  2d3dae:	45 85 c0             	test   r8d,r8d
  2d3db1:	0f 85 ca 00 00 00    	jne    0x2d3e81
  2d3db7:	44 8b 75 ac          	mov    r14d,DWORD PTR [rbp-0x54]
  2d3dbb:	45 31 c0             	xor    r8d,r8d
  2d3dbe:	48 39 de             	cmp    rsi,rbx
  2d3dc1:	0f 84 b4 00 00 00    	je     0x2d3e7b
  2d3dc7:	48 39 56 20          	cmp    QWORD PTR [rsi+0x20],rdx
  2d3dcb:	0f 83 aa 00 00 00    	jae    0x2d3e7b
  2d3dd1:	4c 8b 45 a0          	mov    r8,QWORD PTR [rbp-0x60]
  2d3dd5:	4c 8d 4e 20          	lea    r9,[rsi+0x20]
  2d3dd9:	4c 01 85 78 ff ff ff 	add    QWORD PTR [rbp-0x88],r8
  2d3de0:	f6 46 60 02          	test   BYTE PTR [rsi+0x60],0x2
  2d3de4:	0f 84 a5 fd ff ff    	je     0x2d3b8f
  2d3dea:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
  2d3dee:	41 b8 0d 00 00 00    	mov    r8d,0xd
  2d3df4:	e9 90 00 00 00       	jmp    0x2d3e89
  2d3df9:	41 bc 23 00 00 00    	mov    r12d,0x23
  2d3dff:	eb 2a                	jmp    0x2d3e2b
  2d3e01:	48 8b 75 c0          	mov    rsi,QWORD PTR [rbp-0x40]
  2d3e05:	41 bc 16 00 00 00    	mov    r12d,0x16
  2d3e0b:	eb 06                	jmp    0x2d3e13
  2d3e0d:	41 bc 54 00 00 00    	mov    r12d,0x54
  2d3e13:	48 8d 55 c8          	lea    rdx,[rbp-0x38]
  2d3e17:	48 89 df             	mov    rdi,rbx
  2d3e1a:	e8 21 2e ff ff       	call   0x2c6c40
  2d3e1f:	48 89 df             	mov    rdi,rbx
  2d3e22:	31 f6                	xor    esi,esi
  2d3e24:	31 d2                	xor    edx,edx
  2d3e26:	e8 c5 26 ff ff       	call   0x2c64f0
  2d3e2b:	48 8b 75 c0          	mov    rsi,QWORD PTR [rbp-0x40]
  2d3e2f:	48 8b 55 90          	mov    rdx,QWORD PTR [rbp-0x70]
  2d3e33:	48 89 df             	mov    rdi,rbx
  2d3e36:	44 89 f1             	mov    ecx,r14d
  2d3e39:	e8 c2 aa ff ff       	call   0x2ce900
  2d3e3e:	49 8b 07             	mov    rax,QWORD PTR [r15]
  2d3e41:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  2d3e45:	0f 85 d0 00 00 00    	jne    0x2d3f1b
  2d3e4b:	44 89 e0             	mov    eax,r12d
  2d3e4e:	48 81 c4 a8 00 00 00 	add    rsp,0xa8
  2d3e55:	5b                   	pop    rbx
  2d3e56:	41 5c                	pop    r12
  2d3e58:	41 5d                	pop    r13
  2d3e5a:	41 5e                	pop    r14
  2d3e5c:	41 5f                	pop    r15
  2d3e5e:	5d                   	pop    rbp
  2d3e5f:	c3                   	ret
  2d3e60:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
  2d3e64:	4c 89 ea             	mov    rdx,r13
  2d3e67:	41 b8 0d 00 00 00    	mov    r8d,0xd
  2d3e6d:	48 89 45 88          	mov    QWORD PTR [rbp-0x78],rax
  2d3e71:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
  2d3e75:	48 8b 7d 98          	mov    rdi,QWORD PTR [rbp-0x68]
  2d3e79:	eb 0e                	jmp    0x2d3e89
  2d3e7b:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
  2d3e7f:	eb 08                	jmp    0x2d3e89
  2d3e81:	48 8b 55 b0          	mov    rdx,QWORD PTR [rbp-0x50]
  2d3e85:	44 8b 75 ac          	mov    r14d,DWORD PTR [rbp-0x54]
  2d3e89:	4c 29 ea             	sub    rdx,r13
  2d3e8c:	76 7b                	jbe    0x2d3f09
  2d3e8e:	45 85 c0             	test   r8d,r8d
  2d3e91:	74 7e                	je     0x2d3f11
  2d3e93:	4c 89 ee             	mov    rsi,r13
  2d3e96:	b9 01 00 00 00       	mov    ecx,0x1
  2d3e9b:	49 89 c4             	mov    r12,rax
  2d3e9e:	45 89 c5             	mov    r13d,r8d
  2d3ea1:	e8 fa c4 71 00       	call   0x9f03a0
  2d3ea6:	4c 89 e7             	mov    rdi,r12
  2d3ea9:	e8 02 0a 00 00       	call   0x2d48b0
  2d3eae:	49 8b 7c 24 30       	mov    rdi,QWORD PTR [r12+0x30]
  2d3eb3:	48 8d 35 c6 81 92 02 	lea    rsi,[rip+0x29281c6]        # 0x2bfc080
  2d3eba:	e8 31 4f 93 00       	call   0xc08df0
  2d3ebf:	48 8b 75 88          	mov    rsi,QWORD PTR [rbp-0x78]
  2d3ec3:	48 2b 75 c0          	sub    rsi,QWORD PTR [rbp-0x40]
  2d3ec7:	49 c7 44 24 30 00 00 	mov    QWORD PTR [r12+0x30],0x0
  2d3ece:	00 00 
  2d3ed0:	41 c7 44 24 38 00 00 	mov    DWORD PTR [r12+0x38],0x0
  2d3ed7:	00 00 
  2d3ed9:	49 8b 7c 24 28       	mov    rdi,QWORD PTR [r12+0x28]
  2d3ede:	48 c1 ee 0e          	shr    rsi,0xe
  2d3ee2:	e8 c9 ae 60 00       	call   0x8dedb0
  2d3ee7:	49 8b 7c 24 28       	mov    rdi,QWORD PTR [r12+0x28]
  2d3eec:	48 8b b5 70 ff ff ff 	mov    rsi,QWORD PTR [rbp-0x90]
  2d3ef3:	e8 18 f5 22 00       	call   0x503410
  2d3ef8:	49 c7 44 24 28 00 00 	mov    QWORD PTR [r12+0x28],0x0
  2d3eff:	00 00 
  2d3f01:	45 89 ec             	mov    r12d,r13d
  2d3f04:	e9 16 ff ff ff       	jmp    0x2d3e1f
  2d3f09:	45 89 c4             	mov    r12d,r8d
  2d3f0c:	e9 0e ff ff ff       	jmp    0x2d3e1f
  2d3f11:	e8 9a c4 71 00       	call   0x9f03b0
  2d3f16:	e9 04 ff ff ff       	jmp    0x2d3e1f
  2d3f1b:	e8 90 97 42 00       	call   0x6fd6b0
  2d3f20:	0f 0b                	ud2
  2d3f22:	e8 29 da 51 00       	call   0x7f1950
  2d3f27:	48 8b 5d 88          	mov    rbx,QWORD PTR [rbp-0x78]
  2d3f2b:	48 8d 3d f0 ff ff ff 	lea    rdi,[rip+0xfffffffffffffff0]        # 0x2d3f22
  2d3f32:	48 89 de             	mov    rsi,rbx
  2d3f35:	e8 66 d9 51 00       	call   0x7f18a0
  2d3f3a:	48 8d 35 c6 0b 09 01 	lea    rsi,[rip+0x1090bc6]        # 0x1364b07
  2d3f41:	bf 9f 00 00 00       	mov    edi,0x9f
  2d3f46:	48 89 da             	mov    rdx,rbx
  2d3f49:	31 c0                	xor    eax,eax
  2d3f4b:	e8 c0 6a 9c 00       	call   0xc9aa10
  2d3f50:	0f 0b                	ud2
  2d3f52:	90                   	nop
  2d3f53:	90                   	nop
  2d3f54:	90                   	nop
  2d3f55:	90                   	nop
  2d3f56:	90                   	nop
  2d3f57:	90                   	nop
  2d3f58:	90                   	nop
  2d3f59:	90                   	nop
  2d3f5a:	90                   	nop
  2d3f5b:	90                   	nop
  2d3f5c:	90                   	nop
  2d3f5d:	90                   	nop
  2d3f5e:	90                   	nop
  2d3f5f:	90                   	nop
  2d3f60:	55                   	push   rbp
  2d3f61:	48 89 e5             	mov    rbp,rsp
  2d3f64:	41 57                	push   r15
  2d3f66:	41 56                	push   r14
  2d3f68:	41 55                	push   r13
  2d3f6a:	41 54                	push   r12
  2d3f6c:	53                   	push   rbx
  2d3f6d:	48 83 ec 58          	sub    rsp,0x58
  2d3f71:	48 8d 05 98 83 64 03 	lea    rax,[rip+0x3648398]        # 0x391c310
  2d3f78:	4c 89 4d b0          	mov    QWORD PTR [rbp-0x50],r9
  2d3f7c:	49 89 d4             	mov    r12,rdx
  2d3f7f:	49 89 ff             	mov    r15,rdi
  2d3f82:	ba 02 00 00 00       	mov    edx,0x2
  2d3f87:	44 89 c3             	mov    ebx,r8d
  2d3f8a:	49 89 ce             	mov    r14,rcx
  2d3f8d:	48 8b 00             	mov    rax,QWORD PTR [rax]
  2d3f90:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  2d3f94:	44 8b ae bc 00 00 00 	mov    r13d,DWORD PTR [rsi+0xbc]
  2d3f9b:	48 8d 35 de 80 92 02 	lea    rsi,[rip+0x29280de]        # 0x2bfc080
  2d3fa2:	c7 47 38 01 00 00 00 	mov    DWORD PTR [rdi+0x38],0x1
  2d3fa9:	bf 20 00 00 00       	mov    edi,0x20
  2d3fae:	e8 9d 4b 93 00       	call   0xc08b50
  2d3fb3:	4c 89 f7             	mov    rdi,r14
  2d3fb6:	49 89 47 30          	mov    QWORD PTR [r15+0x30],rax
  2d3fba:	44 89 28             	mov    DWORD PTR [rax],r13d
  2d3fbd:	4c 89 60 08          	mov    QWORD PTR [rax+0x8],r12
  2d3fc1:	c7 40 18 03 00 00 00 	mov    DWORD PTR [rax+0x18],0x3
  2d3fc8:	44 89 6d a8          	mov    DWORD PTR [rbp-0x58],r13d
  2d3fcc:	4c 89 70 10          	mov    QWORD PTR [rax+0x10],r14
  2d3fd0:	4c 89 75 b8          	mov    QWORD PTR [rbp-0x48],r14
  2d3fd4:	e8 d7 f3 22 00       	call   0x5033b0
  2d3fd9:	49 89 47 28          	mov    QWORD PTR [r15+0x28],rax
  2d3fdd:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
  2d3fe1:	48 85 c0             	test   rax,rax
  2d3fe4:	74 39                	je     0x2d401f
  2d3fe6:	4c 89 7d a0          	mov    QWORD PTR [rbp-0x60],r15
  2d3fea:	e8 61 34 35 00       	call   0x627450
  2d3fef:	85 c0                	test   eax,eax
  2d3ff1:	74 47                	je     0x2d403a
  2d3ff3:	48 8b 5d a0          	mov    rbx,QWORD PTR [rbp-0x60]
  2d3ff7:	48 8d 35 82 80 92 02 	lea    rsi,[rip+0x2928082]        # 0x2bfc080
  2d3ffe:	48 8b 7b 30          	mov    rdi,QWORD PTR [rbx+0x30]
  2d4002:	e8 e9 4d 93 00       	call   0xc08df0
  2d4007:	48 8b 7b 28          	mov    rdi,QWORD PTR [rbx+0x28]
  2d400b:	48 8b 75 b8          	mov    rsi,QWORD PTR [rbp-0x48]
  2d400f:	e8 fc f3 22 00       	call   0x503410
  2d4014:	41 bd 23 00 00 00    	mov    r13d,0x23
  2d401a:	e9 59 01 00 00       	jmp    0x2d4178
  2d401f:	49 8b 7f 30          	mov    rdi,QWORD PTR [r15+0x30]
  2d4023:	48 8d 35 56 80 92 02 	lea    rsi,[rip+0x2928056]        # 0x2bfc080
  2d402a:	e8 c1 4d 93 00       	call   0xc08df0
  2d402f:	41 bd 23 00 00 00    	mov    r13d,0x23
  2d4035:	e9 3e 01 00 00       	jmp    0x2d4178
  2d403a:	48 8b 45 b8          	mov    rax,QWORD PTR [rbp-0x48]
  2d403e:	4c 01 e0             	add    rax,r12
  2d4041:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
  2d4045:	49 39 c4             	cmp    r12,rax
  2d4048:	0f 83 b2 00 00 00    	jae    0x2d4100
  2d404e:	0f b6 c3             	movzx  eax,bl
  2d4051:	31 db                	xor    ebx,ebx
  2d4053:	c1 e0 05             	shl    eax,0x5
  2d4056:	83 c8 10             	or     eax,0x10
  2d4059:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
  2d405c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  2d4060:	8b 7d a8             	mov    edi,DWORD PTR [rbp-0x58]
  2d4063:	49 8d 34 1c          	lea    rsi,[r12+rbx*1]
  2d4067:	48 8d 55 c8          	lea    rdx,[rbp-0x38]
  2d406b:	48 8d 4d c4          	lea    rcx,[rbp-0x3c]
  2d406f:	48 c7 45 c8 00 00 00 	mov    QWORD PTR [rbp-0x38],0x0
  2d4076:	00 
  2d4077:	e8 54 48 35 00       	call   0x6288d0
  2d407c:	85 c0                	test   eax,eax
  2d407e:	0f 85 8a 00 00 00    	jne    0x2d410e
  2d4084:	48 83 7d c8 00       	cmp    QWORD PTR [rbp-0x38],0x0
  2d4089:	0f 84 0b 01 00 00    	je     0x2d419a
  2d408f:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
  2d4093:	8b 7d c4             	mov    edi,DWORD PTR [rbp-0x3c]
  2d4096:	4c 8d 2c 18          	lea    r13,[rax+rbx*1]
  2d409a:	48 8b 45 98          	mov    rax,QWORD PTR [rbp-0x68]
  2d409e:	4c 8d 3c 18          	lea    r15,[rax+rbx*1]
  2d40a2:	e8 89 16 00 00       	call   0x2d5730
  2d40a7:	8b 7d c4             	mov    edi,DWORD PTR [rbp-0x3c]
  2d40aa:	41 89 c6             	mov    r14d,eax
  2d40ad:	e8 2e 16 00 00       	call   0x2d56e0
  2d40b2:	48 8b 75 c8          	mov    rsi,QWORD PTR [rbp-0x38]
  2d40b6:	4c 89 ff             	mov    rdi,r15
  2d40b9:	89 c2                	mov    edx,eax
  2d40bb:	e8 20 a9 60 00       	call   0x8de9e0
  2d40c0:	48 8b 75 c8          	mov    rsi,QWORD PTR [rbp-0x38]
  2d40c4:	48 8b 7d b0          	mov    rdi,QWORD PTR [rbp-0x50]
  2d40c8:	44 8b 45 ac          	mov    r8d,DWORD PTR [rbp-0x54]
  2d40cc:	b9 00 40 00 00       	mov    ecx,0x4000
  2d40d1:	4c 89 ea             	mov    rdx,r13
  2d40d4:	45 89 f1             	mov    r9d,r14d
  2d40d7:	c7 04 24 00 00 00 00 	mov    DWORD PTR [rsp],0x0
  2d40de:	e8 0d c2 71 00       	call   0x9f02f0
  2d40e3:	85 c0                	test   eax,eax
  2d40e5:	75 2f                	jne    0x2d4116
  2d40e7:	49 8d 84 1c 00 40 00 	lea    rax,[r12+rbx*1+0x4000]
  2d40ee:	00 
  2d40ef:	48 81 c3 00 40 00 00 	add    rbx,0x4000
  2d40f6:	48 3b 45 90          	cmp    rax,QWORD PTR [rbp-0x70]
  2d40fa:	0f 82 60 ff ff ff    	jb     0x2d4060
  2d4100:	48 8b 7d b0          	mov    rdi,QWORD PTR [rbp-0x50]
  2d4104:	e8 a7 c2 71 00       	call   0x9f03b0
  2d4109:	45 31 ed             	xor    r13d,r13d
  2d410c:	eb 65                	jmp    0x2d4173
  2d410e:	41 bd 0d 00 00 00    	mov    r13d,0xd
  2d4114:	eb 5d                	jmp    0x2d4173
  2d4116:	4c 8b 7d a0          	mov    r15,QWORD PTR [rbp-0x60]
  2d411a:	41 89 c5             	mov    r13d,eax
  2d411d:	48 8b 45 98          	mov    rax,QWORD PTR [rbp-0x68]
  2d4121:	49 8b 7f 28          	mov    rdi,QWORD PTR [r15+0x28]
  2d4125:	4c 29 e0             	sub    rax,r12
  2d4128:	48 8d b4 18 00 40 00 	lea    rsi,[rax+rbx*1+0x4000]
  2d412f:	00 
  2d4130:	48 c1 ee 0e          	shr    rsi,0xe
  2d4134:	e8 77 ac 60 00       	call   0x8dedb0
  2d4139:	49 8b 7f 28          	mov    rdi,QWORD PTR [r15+0x28]
  2d413d:	48 8b 75 b8          	mov    rsi,QWORD PTR [rbp-0x48]
  2d4141:	e8 ca f2 22 00       	call   0x503410
  2d4146:	49 c7 47 28 00 00 00 	mov    QWORD PTR [r15+0x28],0x0
  2d414d:	00 
  2d414e:	48 8d 35 2b 7f 92 02 	lea    rsi,[rip+0x2927f2b]        # 0x2bfc080
  2d4155:	49 8b 7f 30          	mov    rdi,QWORD PTR [r15+0x30]
  2d4159:	e8 92 4c 93 00       	call   0xc08df0
  2d415e:	48 8b 7d b0          	mov    rdi,QWORD PTR [rbp-0x50]
  2d4162:	48 8b 75 10          	mov    rsi,QWORD PTR [rbp+0x10]
  2d4166:	48 89 da             	mov    rdx,rbx
  2d4169:	b9 01 00 00 00       	mov    ecx,0x1
  2d416e:	e8 2d c2 71 00       	call   0x9f03a0
  2d4173:	e8 48 33 35 00       	call   0x6274c0
  2d4178:	48 8d 05 91 81 64 03 	lea    rax,[rip+0x3648191]        # 0x391c310
  2d417f:	48 8b 00             	mov    rax,QWORD PTR [rax]
  2d4182:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  2d4186:	75 38                	jne    0x2d41c0
  2d4188:	44 89 e8             	mov    eax,r13d
  2d418b:	48 83 c4 58          	add    rsp,0x58
  2d418f:	5b                   	pop    rbx
  2d4190:	41 5c                	pop    r12
  2d4192:	41 5d                	pop    r13
  2d4194:	41 5e                	pop    r14
  2d4196:	41 5f                	pop    r15
  2d4198:	5d                   	pop    rbp
  2d4199:	c3                   	ret
  2d419a:	e8 b1 d7 51 00       	call   0x7f1950
  2d419f:	48 8d 3d f4 ff ff ff 	lea    rdi,[rip+0xfffffffffffffff4]        # 0x2d419a
  2d41a6:	e8 65 d6 51 00       	call   0x7f1810
  2d41ab:	48 8d 35 30 5b fb 00 	lea    rsi,[rip+0xfb5b30]        # 0x1289ce2
  2d41b2:	bf 9b 00 00 00       	mov    edi,0x9b
  2d41b7:	31 c0                	xor    eax,eax
  2d41b9:	e8 52 68 9c 00       	call   0xc9aa10
  2d41be:	0f 0b                	ud2
  2d41c0:	e8 eb 94 42 00       	call   0x6fd6b0
  2d41c5:	0f 0b                	ud2
  2d41c7:	90                   	nop
  2d41c8:	90                   	nop
  2d41c9:	90                   	nop
  2d41ca:	90                   	nop
  2d41cb:	90                   	nop
  2d41cc:	90                   	nop
  2d41cd:	90                   	nop
  2d41ce:	90                   	nop
  2d41cf:	90                   	nop
  2d41d0:	55                   	push   rbp
  2d41d1:	48 89 e5             	mov    rbp,rsp
  2d41d4:	41 57                	push   r15
  2d41d6:	41 56                	push   r14
  2d41d8:	41 55                	push   r13
  2d41da:	41 54                	push   r12
  2d41dc:	53                   	push   rbx
  2d41dd:	48 83 ec 18          	sub    rsp,0x18
  2d41e1:	48 8d 05 28 81 64 03 	lea    rax,[rip+0x3648128]        # 0x391c310
  2d41e8:	49 89 d6             	mov    r14,rdx
  2d41eb:	49 89 f7             	mov    r15,rsi
  2d41ee:	48 89 fb             	mov    rbx,rdi
  2d41f1:	48 8b 00             	mov    rax,QWORD PTR [rax]
  2d41f4:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  2d41f8:	0f b6 87 44 02 00 00 	movzx  eax,BYTE PTR [rdi+0x244]
  2d41ff:	a8 10                	test   al,0x10
  2d4201:	75 29                	jne    0x2d422c
  2d4203:	a8 08                	test   al,0x8
  2d4205:	74 11                	je     0x2d4218
  2d4207:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  2d420e:	00 00 
  2d4210:	f0 83 80 a8 05 00 00 	lock add DWORD PTR [rax+0x5a8],0x1
  2d4217:	01 
  2d4218:	48 8d bb 70 01 00 00 	lea    rdi,[rbx+0x170]
  2d421f:	31 f6                	xor    esi,esi
  2d4221:	31 d2                	xor    edx,edx
  2d4223:	31 c9                	xor    ecx,ecx
  2d4225:	e8 26 71 97 00       	call   0xc4b350
  2d422a:	eb 12                	jmp    0x2d423e
  2d422c:	48 8d bb a8 01 00 00 	lea    rdi,[rbx+0x1a8]
  2d4233:	31 f6                	xor    esi,esi
  2d4235:	31 d2                	xor    edx,edx
  2d4237:	31 c9                	xor    ecx,ecx
  2d4239:	e8 c2 27 1f 00       	call   0x4c6a00
  2d423e:	48 8d 55 c8          	lea    rdx,[rbp-0x38]
  2d4242:	48 89 df             	mov    rdi,rbx
  2d4245:	4c 89 fe             	mov    rsi,r15
  2d4248:	4d 01 fe             	add    r14,r15
  2d424b:	e8 f0 29 ff ff       	call   0x2c6c40
  2d4250:	85 c0                	test   eax,eax
  2d4252:	0f 84 16 01 00 00    	je     0x2d436e
  2d4258:	4c 8b 6d c8          	mov    r13,QWORD PTR [rbp-0x38]
  2d425c:	45 31 e4             	xor    r12d,r12d
  2d425f:	49 39 dd             	cmp    r13,rbx
  2d4262:	0f 84 83 00 00 00    	je     0x2d42eb
  2d4268:	b8 01 00 00 00       	mov    eax,0x1
  2d426d:	eb 0a                	jmp    0x2d4279
  2d426f:	90                   	nop
  2d4270:	4d 8b 6d 08          	mov    r13,QWORD PTR [r13+0x8]
  2d4274:	49 39 dd             	cmp    r13,rbx
  2d4277:	74 72                	je     0x2d42eb
  2d4279:	49 8b 4d 20          	mov    rcx,QWORD PTR [r13+0x20]
  2d427d:	4c 39 f1             	cmp    rcx,r14
  2d4280:	73 69                	jae    0x2d42eb
  2d4282:	49 39 cf             	cmp    r15,rcx
  2d4285:	73 0e                	jae    0x2d4295
  2d4287:	49 8b 55 00          	mov    rdx,QWORD PTR [r13+0x0]
  2d428b:	48 3b 4a 28          	cmp    rcx,QWORD PTR [rdx+0x28]
  2d428f:	0f 85 d9 00 00 00    	jne    0x2d436e
  2d4295:	41 8b 4d 60          	mov    ecx,DWORD PTR [r13+0x60]
  2d4299:	f6 c1 02             	test   cl,0x2
  2d429c:	0f 85 cc 00 00 00    	jne    0x2d436e
  2d42a2:	41 0f b6 b5 40 01 00 	movzx  esi,BYTE PTR [r13+0x140]
  2d42a9:	00 
  2d42aa:	89 ca                	mov    edx,ecx
  2d42ac:	c1 e2 1a             	shl    edx,0x1a
  2d42af:	c1 fa 1f             	sar    edx,0x1f
  2d42b2:	40 80 e6 20          	and    sil,0x20
  2d42b6:	40 c0 ee 05          	shr    sil,0x5
  2d42ba:	f7 c1 00 00 02 00    	test   ecx,0x20000
  2d42c0:	0f 94 c1             	sete   cl
  2d42c3:	41 03 55 6c          	add    edx,DWORD PTR [r13+0x6c]
  2d42c7:	40 20 f1             	and    cl,sil
  2d42ca:	0f b6 c9             	movzx  ecx,cl
  2d42cd:	39 ca                	cmp    edx,ecx
  2d42cf:	0f 84 c7 00 00 00    	je     0x2d439c
  2d42d5:	49 8b 4d 50          	mov    rcx,QWORD PTR [r13+0x50]
  2d42d9:	48 85 c9             	test   rcx,rcx
  2d42dc:	74 92                	je     0x2d4270
  2d42de:	f6 81 a2 00 00 00 08 	test   BYTE PTR [rcx+0xa2],0x8
  2d42e5:	44 0f 45 e0          	cmovne r12d,eax
  2d42e9:	eb 85                	jmp    0x2d4270
  2d42eb:	f6 83 44 02 00 00 10 	test   BYTE PTR [rbx+0x244],0x10
  2d42f2:	75 43                	jne    0x2d4337
  2d42f4:	48 8d bb 70 01 00 00 	lea    rdi,[rbx+0x170]
  2d42fb:	31 f6                	xor    esi,esi
  2d42fd:	31 d2                	xor    edx,edx
  2d42ff:	e8 fc 7f 97 00       	call   0xc4c300
  2d4304:	f6 83 44 02 00 00 08 	test   BYTE PTR [rbx+0x244],0x8
  2d430b:	74 23                	je     0x2d4330
  2d430d:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  2d4314:	00 00 
  2d4316:	b9 ff ff ff ff       	mov    ecx,0xffffffff
  2d431b:	f0 0f c1 88 a8 05 00 	lock xadd DWORD PTR [rax+0x5a8],ecx
  2d4322:	00 
  2d4323:	81 f9 01 00 00 80    	cmp    ecx,0x80000001
  2d4329:	75 05                	jne    0x2d4330
  2d432b:	e8 c0 37 3e 00       	call   0x6b7af0
  2d4330:	e8 bb 23 ff ff       	call   0x2c66f0
  2d4335:	eb 15                	jmp    0x2d434c
  2d4337:	48 81 c3 a8 01 00 00 	add    rbx,0x1a8
  2d433e:	31 f6                	xor    esi,esi
  2d4340:	31 d2                	xor    edx,edx
  2d4342:	31 c9                	xor    ecx,ecx
  2d4344:	48 89 df             	mov    rdi,rbx
  2d4347:	e8 54 2c 1f 00       	call   0x4c6fa0
  2d434c:	48 8d 05 bd 7f 64 03 	lea    rax,[rip+0x3647fbd]        # 0x391c310
  2d4353:	48 8b 00             	mov    rax,QWORD PTR [rax]
  2d4356:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  2d435a:	75 7c                	jne    0x2d43d8
  2d435c:	44 89 e0             	mov    eax,r12d
  2d435f:	48 83 c4 18          	add    rsp,0x18
  2d4363:	5b                   	pop    rbx
  2d4364:	41 5c                	pop    r12
  2d4366:	41 5d                	pop    r13
  2d4368:	41 5e                	pop    r14
  2d436a:	41 5f                	pop    r15
  2d436c:	5d                   	pop    rbp
  2d436d:	c3                   	ret
  2d436e:	e8 dd d5 51 00       	call   0x7f1950
  2d4373:	48 8d 3d f4 ff ff ff 	lea    rdi,[rip+0xfffffffffffffff4]        # 0x2d436e
  2d437a:	4c 89 fe             	mov    rsi,r15
  2d437d:	4c 89 f2             	mov    rdx,r14
  2d4380:	48 89 d9             	mov    rcx,rbx
  2d4383:	e8 38 dd 51 00       	call   0x7f20c0
  2d4388:	48 8d 35 90 03 fc 00 	lea    rsi,[rip+0xfc0390]        # 0x129471f
  2d438f:	bf a7 00 00 00       	mov    edi,0xa7
  2d4394:	4c 89 fa             	mov    rdx,r15
  2d4397:	4c 89 f1             	mov    rcx,r14
  2d439a:	eb 30                	jmp    0x2d43cc
  2d439c:	e8 af d5 51 00       	call   0x7f1950
  2d43a1:	49 8b 75 20          	mov    rsi,QWORD PTR [r13+0x20]
  2d43a5:	49 8b 55 28          	mov    rdx,QWORD PTR [r13+0x28]
  2d43a9:	48 8d 3d ec ff ff ff 	lea    rdi,[rip+0xffffffffffffffec]        # 0x2d439c
  2d43b0:	48 89 d9             	mov    rcx,rbx
  2d43b3:	e8 08 dd 51 00       	call   0x7f20c0
  2d43b8:	49 8b 55 20          	mov    rdx,QWORD PTR [r13+0x20]
  2d43bc:	49 8b 4d 28          	mov    rcx,QWORD PTR [r13+0x28]
  2d43c0:	48 8d 35 17 6f 02 01 	lea    rsi,[rip+0x1026f17]        # 0x12fb2de
  2d43c7:	bf a3 00 00 00       	mov    edi,0xa3
  2d43cc:	49 89 d8             	mov    r8,rbx
  2d43cf:	31 c0                	xor    eax,eax
  2d43d1:	e8 3a 66 9c 00       	call   0xc9aa10
  2d43d6:	0f 0b                	ud2
  2d43d8:	e8 d3 92 42 00       	call   0x6fd6b0
  2d43dd:	0f 0b                	ud2
  2d43df:	90                   	nop
  2d43e0:	55                   	push   rbp
  2d43e1:	48 89 e5             	mov    rbp,rsp
  2d43e4:	41 57                	push   r15
  2d43e6:	41 56                	push   r14
  2d43e8:	41 55                	push   r13
  2d43ea:	41 54                	push   r12
  2d43ec:	53                   	push   rbx
  2d43ed:	48 83 ec 68          	sub    rsp,0x68
  2d43f1:	48 8d 05 18 7f 64 03 	lea    rax,[rip+0x3647f18]        # 0x391c310
  2d43f8:	4c 89 4d 98          	mov    QWORD PTR [rbp-0x68],r9
  2d43fc:	4c 89 45 80          	mov    QWORD PTR [rbp-0x80],r8
  2d4400:	4c 8b 75 18          	mov    r14,QWORD PTR [rbp+0x18]
  2d4404:	89 cb                	mov    ebx,ecx
  2d4406:	49 89 d7             	mov    r15,rdx
  2d4409:	49 89 f4             	mov    r12,rsi
  2d440c:	48 8b 00             	mov    rax,QWORD PTR [rax]
  2d440f:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  2d4413:	48 89 bd 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rdi
  2d441a:	48 8b 87 e8 00 00 00 	mov    rax,QWORD PTR [rdi+0xe8]
  2d4421:	48 8b 80 a8 00 00 00 	mov    rax,QWORD PTR [rax+0xa8]
  2d4428:	48 89 45 88          	mov    QWORD PTR [rbp-0x78],rax
  2d442c:	e8 2f 21 0f 00       	call   0x3c6560
  2d4431:	89 c7                	mov    edi,eax
  2d4433:	4c 89 e6             	mov    rsi,r12
  2d4436:	4c 89 fa             	mov    rdx,r15
  2d4439:	41 c7 46 18 01 00 00 	mov    DWORD PTR [r14+0x18],0x1
  2d4440:	00 
  2d4441:	4d 89 26             	mov    QWORD PTR [r14],r12
  2d4444:	41 89 46 08          	mov    DWORD PTR [r14+0x8],eax
  2d4448:	89 45 b8             	mov    DWORD PTR [rbp-0x48],eax
  2d444b:	e8 80 21 0f 00       	call   0x3c65d0
  2d4450:	85 c0                	test   eax,eax
  2d4452:	0f 85 42 01 00 00    	jne    0x2d459a
  2d4458:	4f 8d 34 27          	lea    r14,[r15+r12*1]
  2d445c:	4c 89 7d a0          	mov    QWORD PTR [rbp-0x60],r15
  2d4460:	4c 89 65 b0          	mov    QWORD PTR [rbp-0x50],r12
  2d4464:	4d 39 f4             	cmp    r12,r14
  2d4467:	0f 83 0e 01 00 00    	jae    0x2d457b
  2d446d:	4c 8b 65 10          	mov    r12,QWORD PTR [rbp+0x10]
  2d4471:	4c 8b 6d b0          	mov    r13,QWORD PTR [rbp-0x50]
  2d4475:	0f b6 c3             	movzx  eax,bl
  2d4478:	4c 89 75 90          	mov    QWORD PTR [rbp-0x70],r14
  2d447c:	c1 e0 05             	shl    eax,0x5
  2d447f:	83 c8 10             	or     eax,0x10
  2d4482:	89 45 a8             	mov    DWORD PTR [rbp-0x58],eax
  2d4485:	eb 21                	jmp    0x2d44a8
  2d4487:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
  2d448e:	00 00 
  2d4490:	48 01 5d 98          	add    QWORD PTR [rbp-0x68],rbx
  2d4494:	4c 8b 6d c0          	mov    r13,QWORD PTR [rbp-0x40]
  2d4498:	4c 8b 75 90          	mov    r14,QWORD PTR [rbp-0x70]
  2d449c:	49 01 dc             	add    r12,rbx
  2d449f:	4d 39 f5             	cmp    r13,r14
  2d44a2:	0f 83 b9 00 00 00    	jae    0x2d4561
  2d44a8:	48 8b bd 78 ff ff ff 	mov    rdi,QWORD PTR [rbp-0x88]
  2d44af:	4c 89 ee             	mov    rsi,r13
  2d44b2:	48 8d 55 c8          	lea    rdx,[rbp-0x38]
  2d44b6:	48 8d 4d c0          	lea    rcx,[rbp-0x40]
  2d44ba:	4c 8d 45 bc          	lea    r8,[rbp-0x44]
  2d44be:	e8 2d 10 0f 00       	call   0x3c54f0
  2d44c3:	85 c0                	test   eax,eax
  2d44c5:	0f 85 9c 00 00 00    	jne    0x2d4567
  2d44cb:	48 8b 5d c0          	mov    rbx,QWORD PTR [rbp-0x40]
  2d44cf:	8b 7d bc             	mov    edi,DWORD PTR [rbp-0x44]
  2d44d2:	49 39 de             	cmp    r14,rbx
  2d44d5:	49 0f 42 de          	cmovb  rbx,r14
  2d44d9:	48 89 5d c0          	mov    QWORD PTR [rbp-0x40],rbx
  2d44dd:	e8 4e 12 00 00       	call   0x2d5730
  2d44e2:	48 8b 7d 88          	mov    rdi,QWORD PTR [rbp-0x78]
  2d44e6:	4c 89 ee             	mov    rsi,r13
  2d44e9:	41 89 c6             	mov    r14d,eax
  2d44ec:	e8 bf f1 0e 00       	call   0x3c36b0
  2d44f1:	48 8b 7d 80          	mov    rdi,QWORD PTR [rbp-0x80]
  2d44f5:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
  2d44f9:	44 8b 45 a8          	mov    r8d,DWORD PTR [rbp-0x58]
  2d44fd:	48 89 d9             	mov    rcx,rbx
  2d4500:	48 89 c6             	mov    rsi,rax
  2d4503:	45 89 f1             	mov    r9d,r14d
  2d4506:	49 89 c7             	mov    r15,rax
  2d4509:	c7 04 24 01 00 00 00 	mov    DWORD PTR [rsp],0x1
  2d4510:	4c 29 e9             	sub    rcx,r13
  2d4513:	e8 d8 bd 71 00       	call   0x9f02f0
  2d4518:	8b 7d bc             	mov    edi,DWORD PTR [rbp-0x44]
  2d451b:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
  2d451e:	e8 bd 11 00 00       	call   0x2d56e0
  2d4523:	4c 29 eb             	sub    rbx,r13
  2d4526:	0f 84 64 ff ff ff    	je     0x2d4490
  2d452c:	41 89 c6             	mov    r14d,eax
  2d452f:	45 31 ed             	xor    r13d,r13d
  2d4532:	66 66 66 66 66 2e 0f 	data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  2d4539:	1f 84 00 00 00 00 00 
  2d4540:	4b 8d 3c 2c          	lea    rdi,[r12+r13*1]
  2d4544:	4b 8d 34 2f          	lea    rsi,[r15+r13*1]
  2d4548:	44 89 f2             	mov    edx,r14d
  2d454b:	e8 90 a4 60 00       	call   0x8de9e0
  2d4550:	49 81 c5 00 40 00 00 	add    r13,0x4000
  2d4557:	49 39 dd             	cmp    r13,rbx
  2d455a:	72 e4                	jb     0x2d4540
  2d455c:	e9 2f ff ff ff       	jmp    0x2d4490
  2d4561:	83 7d ac 00          	cmp    DWORD PTR [rbp-0x54],0x0
  2d4565:	74 14                	je     0x2d457b
  2d4567:	8b 7d b8             	mov    edi,DWORD PTR [rbp-0x48]
  2d456a:	48 8b 75 b0          	mov    rsi,QWORD PTR [rbp-0x50]
  2d456e:	48 8b 55 a0          	mov    rdx,QWORD PTR [rbp-0x60]
  2d4572:	e8 59 25 0f 00       	call   0x3c6ad0
  2d4577:	85 c0                	test   eax,eax
  2d4579:	75 62                	jne    0x2d45dd
  2d457b:	48 8d 05 8e 7d 64 03 	lea    rax,[rip+0x3647d8e]        # 0x391c310
  2d4582:	48 8b 00             	mov    rax,QWORD PTR [rax]
  2d4585:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  2d4589:	75 4b                	jne    0x2d45d6
  2d458b:	48 83 c4 68          	add    rsp,0x68
  2d458f:	5b                   	pop    rbx
  2d4590:	41 5c                	pop    r12
  2d4592:	41 5d                	pop    r13
  2d4594:	41 5e                	pop    r14
  2d4596:	41 5f                	pop    r15
  2d4598:	5d                   	pop    rbp
  2d4599:	c3                   	ret
  2d459a:	89 c3                	mov    ebx,eax
  2d459c:	e8 af d3 51 00       	call   0x7f1950
  2d45a1:	44 8b 75 b8          	mov    r14d,DWORD PTR [rbp-0x48]
  2d45a5:	48 63 f3             	movsxd rsi,ebx
  2d45a8:	48 8d 3d eb ff ff ff 	lea    rdi,[rip+0xffffffffffffffeb]        # 0x2d459a
  2d45af:	4c 89 e1             	mov    rcx,r12
  2d45b2:	4d 89 f8             	mov    r8,r15
  2d45b5:	49 63 d6             	movsxd rdx,r14d
  2d45b8:	e8 c3 db 51 00       	call   0x7f2180
  2d45bd:	48 8d 35 c9 25 01 01 	lea    rsi,[rip+0x10125c9]        # 0x12e6b8d
  2d45c4:	bf 93 00 00 00       	mov    edi,0x93
  2d45c9:	89 da                	mov    edx,ebx
  2d45cb:	44 89 f1             	mov    ecx,r14d
  2d45ce:	4d 89 e0             	mov    r8,r12
  2d45d1:	4d 89 f9             	mov    r9,r15
  2d45d4:	eb 49                	jmp    0x2d461f
  2d45d6:	e8 d5 90 42 00       	call   0x6fd6b0
  2d45db:	0f 0b                	ud2
  2d45dd:	89 c3                	mov    ebx,eax
  2d45df:	e8 6c d3 51 00       	call   0x7f1950
  2d45e4:	44 8b 65 b8          	mov    r12d,DWORD PTR [rbp-0x48]
  2d45e8:	4c 8b 7d b0          	mov    r15,QWORD PTR [rbp-0x50]
  2d45ec:	4c 8b 75 a0          	mov    r14,QWORD PTR [rbp-0x60]
  2d45f0:	48 63 f3             	movsxd rsi,ebx
  2d45f3:	48 8d 3d e3 ff ff ff 	lea    rdi,[rip+0xffffffffffffffe3]        # 0x2d45dd
  2d45fa:	49 63 d4             	movsxd rdx,r12d
  2d45fd:	4c 89 f9             	mov    rcx,r15
  2d4600:	4d 89 f0             	mov    r8,r14
  2d4603:	e8 78 db 51 00       	call   0x7f2180
  2d4608:	48 8d 35 77 83 00 01 	lea    rsi,[rip+0x1008377]        # 0x12dc986
  2d460f:	bf 97 00 00 00       	mov    edi,0x97
  2d4614:	89 da                	mov    edx,ebx
  2d4616:	44 89 e1             	mov    ecx,r12d
  2d4619:	4d 89 f8             	mov    r8,r15
  2d461c:	4d 89 f1             	mov    r9,r14
  2d461f:	31 c0                	xor    eax,eax
  2d4621:	e8 ea 63 9c 00       	call   0xc9aa10
  2d4626:	0f 0b                	ud2
  2d4628:	90                   	nop
  2d4629:	90                   	nop
  2d462a:	90                   	nop
  2d462b:	90                   	nop
  2d462c:	90                   	nop
  2d462d:	90                   	nop
  2d462e:	90                   	nop
  2d462f:	90                   	nop
  2d4630:	55                   	push   rbp
  2d4631:	48 89 e5             	mov    rbp,rsp
  2d4634:	41 57                	push   r15
  2d4636:	41 56                	push   r14
  2d4638:	41 55                	push   r13
  2d463a:	41 54                	push   r12
  2d463c:	53                   	push   rbx
  2d463d:	48 83 ec 48          	sub    rsp,0x48
  2d4641:	4c 89 45 98          	mov    QWORD PTR [rbp-0x68],r8
  2d4645:	4c 8d 05 c4 7c 64 03 	lea    r8,[rip+0x3647cc4]        # 0x391c310
  2d464c:	89 4d b8             	mov    DWORD PTR [rbp-0x48],ecx
  2d464f:	48 8b 45 18          	mov    rax,QWORD PTR [rbp+0x18]
  2d4653:	49 89 f5             	mov    r13,rsi
  2d4656:	48 89 fb             	mov    rbx,rdi
  2d4659:	48 83 c7 18          	add    rdi,0x18
  2d465d:	49 89 d7             	mov    r15,rdx
  2d4660:	4d 89 cc             	mov    r12,r9
  2d4663:	31 d2                	xor    edx,edx
  2d4665:	49 c1 fd 0e          	sar    r13,0xe
  2d4669:	49 8b 08             	mov    rcx,QWORD PTR [r8]
  2d466c:	48 89 4d d0          	mov    QWORD PTR [rbp-0x30],rcx
  2d4670:	48 89 75 c0          	mov    QWORD PTR [rbp-0x40],rsi
  2d4674:	31 f6                	xor    esi,esi
  2d4676:	c7 40 18 02 00 00 00 	mov    DWORD PTR [rax+0x18],0x2
  2d467d:	48 89 7d b0          	mov    QWORD PTR [rbp-0x50],rdi
  2d4681:	e8 3a 0a 50 00       	call   0x7d50c0
  2d4686:	48 89 df             	mov    rdi,rbx
  2d4689:	4c 89 ee             	mov    rsi,r13
  2d468c:	e8 4f 51 8b 00       	call   0xb897e0
  2d4691:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
  2d4695:	48 85 c0             	test   rax,rax
  2d4698:	0f 84 62 01 00 00    	je     0x2d4800
  2d469e:	4c 03 7d c0          	add    r15,QWORD PTR [rbp-0x40]
  2d46a2:	0f b6 4d b8          	movzx  ecx,BYTE PTR [rbp-0x48]
  2d46a6:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
  2d46aa:	49 89 c6             	mov    r14,rax
  2d46ad:	48 8d 1d 8c 7d aa 03 	lea    rbx,[rip+0x3aa7d8c]        # 0x3d7c440
  2d46b4:	4c 89 f0             	mov    rax,r14
  2d46b7:	c1 e1 05             	shl    ecx,0x5
  2d46ba:	48 89 55 a8          	mov    QWORD PTR [rbp-0x58],rdx
  2d46be:	49 c1 ff 0e          	sar    r15,0xe
  2d46c2:	83 c9 10             	or     ecx,0x10
  2d46c5:	89 4d c0             	mov    DWORD PTR [rbp-0x40],ecx
  2d46c8:	4c 89 7d a0          	mov    QWORD PTR [rbp-0x60],r15
  2d46cc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  2d46d0:	41 bf 0d 00 00 00    	mov    r15d,0xd
  2d46d6:	4c 3b 68 28          	cmp    r13,QWORD PTR [rax+0x28]
  2d46da:	0f 85 19 01 00 00    	jne    0x2d47f9
  2d46e0:	8b 40 30             	mov    eax,DWORD PTR [rax+0x30]
  2d46e3:	31 f6                	xor    esi,esi
  2d46e5:	31 d2                	xor    edx,edx
  2d46e7:	31 c9                	xor    ecx,ecx
  2d46e9:	c1 e8 0f             	shr    eax,0xf
  2d46ec:	25 c0 3f 00 00       	and    eax,0x3fc0
  2d46f1:	48 8d 7c 18 18       	lea    rdi,[rax+rbx*1+0x18]
  2d46f6:	e8 05 23 1f 00       	call   0x4c6a00
  2d46fb:	48 8b 7d c8          	mov    rdi,QWORD PTR [rbp-0x38]
  2d46ff:	e8 1c 83 8b 00       	call   0xb8ca20
  2d4704:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
  2d4708:	31 f6                	xor    esi,esi
  2d470a:	31 d2                	xor    edx,edx
  2d470c:	31 c9                	xor    ecx,ecx
  2d470e:	8b 40 30             	mov    eax,DWORD PTR [rax+0x30]
  2d4711:	c1 e8 0f             	shr    eax,0xf
  2d4714:	25 c0 3f 00 00       	and    eax,0x3fc0
  2d4719:	48 8d 7c 18 18       	lea    rdi,[rax+rbx*1+0x18]
  2d471e:	e8 7d 28 1f 00       	call   0x4c6fa0
  2d4723:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
  2d4727:	41 bf 12 04 00 00    	mov    r15d,0x412
  2d472d:	4c 89 65 b8          	mov    QWORD PTR [rbp-0x48],r12
  2d4731:	48 8b 78 20          	mov    rdi,QWORD PTR [rax+0x20]
  2d4735:	48 85 ff             	test   rdi,rdi
  2d4738:	74 1c                	je     0x2d4756
  2d473a:	80 bf 9d 00 00 00 0a 	cmp    BYTE PTR [rdi+0x9d],0xa
  2d4741:	75 13                	jne    0x2d4756
  2d4743:	e8 48 75 64 00       	call   0x91bc90
  2d4748:	89 c7                	mov    edi,eax
  2d474a:	e8 e1 0f 00 00       	call   0x2d5730
  2d474f:	41 89 c7             	mov    r15d,eax
  2d4752:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
  2d4756:	48 8b 5d b0          	mov    rbx,QWORD PTR [rbp-0x50]
  2d475a:	4c 8b 60 30          	mov    r12,QWORD PTR [rax+0x30]
  2d475e:	31 f6                	xor    esi,esi
  2d4760:	31 d2                	xor    edx,edx
  2d4762:	48 89 df             	mov    rdi,rbx
  2d4765:	e8 76 0f 50 00       	call   0x7d56e0
  2d476a:	48 8b 7d a8          	mov    rdi,QWORD PTR [rbp-0x58]
  2d476e:	48 8d 75 c8          	lea    rsi,[rbp-0x38]
  2d4772:	ba 01 00 00 00       	mov    edx,0x1
  2d4777:	e8 04 a5 60 00       	call   0x8dec80
  2d477c:	4c 89 e6             	mov    rsi,r12
  2d477f:	4c 8b 65 b8          	mov    r12,QWORD PTR [rbp-0x48]
  2d4783:	48 8b 7d 98          	mov    rdi,QWORD PTR [rbp-0x68]
  2d4787:	44 8b 45 c0          	mov    r8d,DWORD PTR [rbp-0x40]
  2d478b:	b9 00 40 00 00       	mov    ecx,0x4000
  2d4790:	45 89 f9             	mov    r9d,r15d
  2d4793:	c7 04 24 00 00 00 00 	mov    DWORD PTR [rsp],0x0
  2d479a:	4c 89 e2             	mov    rdx,r12
  2d479d:	e8 4e bb 71 00       	call   0x9f02f0
  2d47a2:	48 89 df             	mov    rdi,rbx
  2d47a5:	41 89 c7             	mov    r15d,eax
  2d47a8:	31 f6                	xor    esi,esi
  2d47aa:	31 d2                	xor    edx,edx
  2d47ac:	e8 0f 09 50 00       	call   0x7d50c0
  2d47b1:	45 85 ff             	test   r15d,r15d
  2d47b4:	75 52                	jne    0x2d4808
  2d47b6:	48 8b 4d a0          	mov    rcx,QWORD PTR [rbp-0x60]
  2d47ba:	49 ff c5             	inc    r13
  2d47bd:	48 8d 1d 7c 7c aa 03 	lea    rbx,[rip+0x3aa7c7c]        # 0x3d7c440
  2d47c4:	4c 39 e9             	cmp    rcx,r13
  2d47c7:	0f 86 a4 00 00 00    	jbe    0x2d4871
  2d47cd:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
  2d47d1:	48 81 45 a8 00 40 00 	add    QWORD PTR [rbp-0x58],0x4000
  2d47d8:	00 
  2d47d9:	49 81 c4 00 40 00 00 	add    r12,0x4000
  2d47e0:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
  2d47e4:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
  2d47e8:	48 85 c0             	test   rax,rax
  2d47eb:	0f 85 df fe ff ff    	jne    0x2d46d0
  2d47f1:	41 bf 0d 00 00 00    	mov    r15d,0xd
  2d47f7:	31 c0                	xor    eax,eax
  2d47f9:	49 39 c6             	cmp    r14,rax
  2d47fc:	75 22                	jne    0x2d4820
  2d47fe:	eb 74                	jmp    0x2d4874
  2d4800:	41 bf 0d 00 00 00    	mov    r15d,0xd
  2d4806:	eb 6c                	jmp    0x2d4874
  2d4808:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
  2d480c:	48 8d 1d 2d 7c aa 03 	lea    rbx,[rip+0x3aa7c2d]        # 0x3d7c440
  2d4813:	49 39 c6             	cmp    r14,rax
  2d4816:	74 5c                	je     0x2d4874
  2d4818:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
  2d481f:	00 
  2d4820:	41 8b 46 30          	mov    eax,DWORD PTR [r14+0x30]
  2d4824:	31 f6                	xor    esi,esi
  2d4826:	31 d2                	xor    edx,edx
  2d4828:	31 c9                	xor    ecx,ecx
  2d482a:	c1 e8 0f             	shr    eax,0xf
  2d482d:	25 c0 3f 00 00       	and    eax,0x3fc0
  2d4832:	48 8d 7c 18 18       	lea    rdi,[rax+rbx*1+0x18]
  2d4837:	e8 c4 21 1f 00       	call   0x4c6a00
  2d483c:	4c 89 f7             	mov    rdi,r14
  2d483f:	be 01 00 00 00       	mov    esi,0x1
  2d4844:	e8 27 82 8b 00       	call   0xb8ca70
  2d4849:	41 8b 46 30          	mov    eax,DWORD PTR [r14+0x30]
  2d484d:	31 f6                	xor    esi,esi
  2d484f:	31 d2                	xor    edx,edx
  2d4851:	31 c9                	xor    ecx,ecx
  2d4853:	c1 e8 0f             	shr    eax,0xf
  2d4856:	25 c0 3f 00 00       	and    eax,0x3fc0
  2d485b:	48 8d 7c 18 18       	lea    rdi,[rax+rbx*1+0x18]
  2d4860:	e8 3b 27 1f 00       	call   0x4c6fa0
  2d4865:	4d 8b 76 10          	mov    r14,QWORD PTR [r14+0x10]
  2d4869:	4c 3b 75 c8          	cmp    r14,QWORD PTR [rbp-0x38]
  2d486d:	75 b1                	jne    0x2d4820
  2d486f:	eb 03                	jmp    0x2d4874
  2d4871:	45 31 ff             	xor    r15d,r15d
  2d4874:	48 8b 7d b0          	mov    rdi,QWORD PTR [rbp-0x50]
  2d4878:	31 f6                	xor    esi,esi
  2d487a:	31 d2                	xor    edx,edx
  2d487c:	e8 5f 0e 50 00       	call   0x7d56e0
  2d4881:	48 8d 05 88 7a 64 03 	lea    rax,[rip+0x3647a88]        # 0x391c310
  2d4888:	48 8b 00             	mov    rax,QWORD PTR [rax]
  2d488b:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  2d488f:	75 12                	jne    0x2d48a3
  2d4891:	44 89 f8             	mov    eax,r15d
  2d4894:	48 83 c4 48          	add    rsp,0x48
  2d4898:	5b                   	pop    rbx
  2d4899:	41 5c                	pop    r12
  2d489b:	41 5d                	pop    r13
  2d489d:	41 5e                	pop    r14
  2d489f:	41 5f                	pop    r15
  2d48a1:	5d                   	pop    rbp
  2d48a2:	c3                   	ret
  2d48a3:	e8 08 8e 42 00       	call   0x6fd6b0
  2d48a8:	0f 0b                	ud2
  2d48aa:	90                   	nop
  2d48ab:	90                   	nop
  2d48ac:	90                   	nop
  2d48ad:	90                   	nop
  2d48ae:	90                   	nop
  2d48af:	90                   	nop
  2d48b0:	55                   	push   rbp
  2d48b1:	48 89 e5             	mov    rbp,rsp
  2d48b4:	41 57                	push   r15
  2d48b6:	41 56                	push   r14
  2d48b8:	41 55                	push   r13
  2d48ba:	41 54                	push   r12
  2d48bc:	53                   	push   rbx
  2d48bd:	48 83 ec 28          	sub    rsp,0x28
  2d48c1:	48 63 47 38          	movsxd rax,DWORD PTR [rdi+0x38]
  2d48c5:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
  2d48c9:	48 85 c0             	test   rax,rax
  2d48cc:	0f 8e 0c 01 00 00    	jle    0x2d49de
  2d48d2:	48 8b 47 30          	mov    rax,QWORD PTR [rdi+0x30]
  2d48d6:	48 8b 4f 28          	mov    rcx,QWORD PTR [rdi+0x28]
  2d48da:	45 31 ed             	xor    r13d,r13d
  2d48dd:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
  2d48e1:	48 89 4d d0          	mov    QWORD PTR [rbp-0x30],rcx
  2d48e5:	eb 2b                	jmp    0x2d4912
  2d48e7:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
  2d48ee:	00 00 
  2d48f0:	e8 3b 21 00 00       	call   0x2d6a30
  2d48f5:	48 8b 4d c8          	mov    rcx,QWORD PTR [rbp-0x38]
  2d48f9:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
  2d48fd:	49 ff c5             	inc    r13
  2d4900:	48 03 41 10          	add    rax,QWORD PTR [rcx+0x10]
  2d4904:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  2d4908:	4c 3b 6d b8          	cmp    r13,QWORD PTR [rbp-0x48]
  2d490c:	0f 84 cc 00 00 00    	je     0x2d49de
  2d4912:	48 8b 4d c0          	mov    rcx,QWORD PTR [rbp-0x40]
  2d4916:	4c 89 e8             	mov    rax,r13
  2d4919:	48 c1 e0 05          	shl    rax,0x5
  2d491d:	48 8d 3c 01          	lea    rdi,[rcx+rax*1]
  2d4921:	8b 44 01 18          	mov    eax,DWORD PTR [rcx+rax*1+0x18]
  2d4925:	48 89 7d c8          	mov    QWORD PTR [rbp-0x38],rdi
  2d4929:	83 f8 01             	cmp    eax,0x1
  2d492c:	74 c2                	je     0x2d48f0
  2d492e:	83 f8 03             	cmp    eax,0x3
  2d4931:	74 c2                	je     0x2d48f5
  2d4933:	83 f8 02             	cmp    eax,0x2
  2d4936:	0f 85 b1 00 00 00    	jne    0x2d49ed
  2d493c:	48 8b 45 c8          	mov    rax,QWORD PTR [rbp-0x38]
  2d4940:	48 8b 58 10          	mov    rbx,QWORD PTR [rax+0x10]
  2d4944:	48 c1 eb 0e          	shr    rbx,0xe
  2d4948:	85 db                	test   ebx,ebx
  2d494a:	7e a9                	jle    0x2d48f5
  2d494c:	4c 8b 75 d0          	mov    r14,QWORD PTR [rbp-0x30]
  2d4950:	81 e3 ff ff ff 7f    	and    ebx,0x7fffffff
  2d4956:	eb 14                	jmp    0x2d496c
  2d4958:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
  2d495f:	00 
  2d4960:	49 81 c6 00 40 00 00 	add    r14,0x4000
  2d4967:	48 ff cb             	dec    rbx
  2d496a:	74 89                	je     0x2d48f5
  2d496c:	4c 89 f7             	mov    rdi,r14
  2d496f:	e8 bc 99 60 00       	call   0x8de330
  2d4974:	48 85 c0             	test   rax,rax
  2d4977:	74 e7                	je     0x2d4960
  2d4979:	48 89 c7             	mov    rdi,rax
  2d497c:	e8 0f 49 8b 00       	call   0xb89290
  2d4981:	49 89 c7             	mov    r15,rax
  2d4984:	8b 40 30             	mov    eax,DWORD PTR [rax+0x30]
  2d4987:	4c 8d 25 b2 7a aa 03 	lea    r12,[rip+0x3aa7ab2]        # 0x3d7c440
  2d498e:	31 f6                	xor    esi,esi
  2d4990:	31 d2                	xor    edx,edx
  2d4992:	31 c9                	xor    ecx,ecx
  2d4994:	c1 e8 0f             	shr    eax,0xf
  2d4997:	25 c0 3f 00 00       	and    eax,0x3fc0
  2d499c:	4a 8d 7c 20 18       	lea    rdi,[rax+r12*1+0x18]
  2d49a1:	e8 5a 20 1f 00       	call   0x4c6a00
  2d49a6:	41 f6 47 65 04       	test   BYTE PTR [r15+0x65],0x4
  2d49ab:	be ff 00 00 00       	mov    esi,0xff
  2d49b0:	b8 01 00 00 00       	mov    eax,0x1
  2d49b5:	4c 89 ff             	mov    rdi,r15
  2d49b8:	0f 44 f0             	cmove  esi,eax
  2d49bb:	e8 b0 80 8b 00       	call   0xb8ca70
  2d49c0:	41 8b 47 30          	mov    eax,DWORD PTR [r15+0x30]
  2d49c4:	31 f6                	xor    esi,esi
  2d49c6:	31 d2                	xor    edx,edx
  2d49c8:	31 c9                	xor    ecx,ecx
  2d49ca:	c1 e8 0f             	shr    eax,0xf
  2d49cd:	25 c0 3f 00 00       	and    eax,0x3fc0
  2d49d2:	4a 8d 7c 20 18       	lea    rdi,[rax+r12*1+0x18]
  2d49d7:	e8 c4 25 1f 00       	call   0x4c6fa0
  2d49dc:	eb 82                	jmp    0x2d4960
  2d49de:	48 83 c4 28          	add    rsp,0x28
  2d49e2:	5b                   	pop    rbx
  2d49e3:	41 5c                	pop    r12
  2d49e5:	41 5d                	pop    r13
  2d49e7:	41 5e                	pop    r14
  2d49e9:	41 5f                	pop    r15
  2d49eb:	5d                   	pop    rbp
  2d49ec:	c3                   	ret
  2d49ed:	e8 5e cf 51 00       	call   0x7f1950
  2d49f2:	48 8b 5d c8          	mov    rbx,QWORD PTR [rbp-0x38]
  2d49f6:	48 8d 3d f0 ff ff ff 	lea    rdi,[rip+0xfffffffffffffff0]        # 0x2d49ed
  2d49fd:	48 63 73 18          	movsxd rsi,DWORD PTR [rbx+0x18]
  2d4a01:	e8 9a ce 51 00       	call   0x7f18a0
  2d4a06:	8b 53 18             	mov    edx,DWORD PTR [rbx+0x18]
  2d4a09:	48 8d 35 45 ec 0a 01 	lea    rsi,[rip+0x10aec45]        # 0x1383655
  2d4a10:	bf 8f 00 00 00       	mov    edi,0x8f
  2d4a15:	31 c0                	xor    eax,eax
  2d4a17:	e8 f4 5f 9c 00       	call   0xc9aa10
  2d4a1c:	0f 0b                	ud2
  2d4a1e:	90                   	nop
  2d4a1f:	90                   	nop
  2d4a20:	b8 16 00 00 00       	mov    eax,0x16
  2d4a25:	85 f6                	test   esi,esi
  2d4a27:	74 01                	je     0x2d4a2a
  2d4a29:	c3                   	ret
  2d4a2a:	55                   	push   rbp
  2d4a2b:	48 89 e5             	mov    rbp,rsp
  2d4a2e:	41 56                	push   r14
  2d4a30:	53                   	push   rbx
  2d4a31:	48 8b 5f 10          	mov    rbx,QWORD PTR [rdi+0x10]
  2d4a35:	48 8b 47 18          	mov    rax,QWORD PTR [rdi+0x18]
  2d4a39:	48 8b 77 20          	mov    rsi,QWORD PTR [rdi+0x20]
  2d4a3d:	49 89 fe             	mov    r14,rdi
  2d4a40:	b9 01 00 00 00       	mov    ecx,0x1
  2d4a45:	48 89 c7             	mov    rdi,rax
  2d4a48:	48 89 da             	mov    rdx,rbx
  2d4a4b:	e8 50 b9 71 00       	call   0x9f03a0
  2d4a50:	4c 89 f7             	mov    rdi,r14
  2d4a53:	e8 58 fe ff ff       	call   0x2d48b0
  2d4a58:	49 8b 7e 30          	mov    rdi,QWORD PTR [r14+0x30]
  2d4a5c:	48 8d 35 1d 76 92 02 	lea    rsi,[rip+0x292761d]        # 0x2bfc080
  2d4a63:	e8 88 43 93 00       	call   0xc08df0
  2d4a68:	49 c7 46 30 00 00 00 	mov    QWORD PTR [r14+0x30],0x0
  2d4a6f:	00 
  2d4a70:	41 c7 46 38 00 00 00 	mov    DWORD PTR [r14+0x38],0x0
  2d4a77:	00 
  2d4a78:	48 89 de             	mov    rsi,rbx
  2d4a7b:	49 8b 7e 28          	mov    rdi,QWORD PTR [r14+0x28]
  2d4a7f:	48 c1 ee 0e          	shr    rsi,0xe
  2d4a83:	e8 28 a3 60 00       	call   0x8dedb0
  2d4a88:	49 8b 7e 28          	mov    rdi,QWORD PTR [r14+0x28]
  2d4a8c:	48 89 de             	mov    rsi,rbx
  2d4a8f:	e8 7c e9 22 00       	call   0x503410
  2d4a94:	31 c0                	xor    eax,eax
  2d4a96:	49 c7 46 28 00 00 00 	mov    QWORD PTR [r14+0x28],0x0
  2d4a9d:	00 
  2d4a9e:	5b                   	pop    rbx
  2d4a9f:	41 5e                	pop    r14
  2d4aa1:	5d                   	pop    rbp
  2d4aa2:	c3                   	ret
  2d4aa3:	90                   	nop
  2d4aa4:	90                   	nop
  2d4aa5:	90                   	nop
  2d4aa6:	90                   	nop
  2d4aa7:	90                   	nop
  2d4aa8:	90                   	nop
  2d4aa9:	90                   	nop
  2d4aaa:	90                   	nop
  2d4aab:	90                   	nop
  2d4aac:	90                   	nop
  2d4aad:	90                   	nop
  2d4aae:	90                   	nop
  2d4aaf:	90                   	nop
  2d4ab0:	55                   	push   rbp
  2d4ab1:	48 89 e5             	mov    rbp,rsp
  2d4ab4:	41 57                	push   r15
  2d4ab6:	41 56                	push   r14
  2d4ab8:	41 55                	push   r13
  2d4aba:	41 54                	push   r12
  2d4abc:	53                   	push   rbx
  2d4abd:	48 83 ec 18          	sub    rsp,0x18
  2d4ac1:	4c 8d 3d 48 78 64 03 	lea    r15,[rip+0x3647848]        # 0x391c310
  2d4ac8:	48 89 f1             	mov    rcx,rsi
  2d4acb:	48 c1 e9 28          	shr    rcx,0x28
  2d4acf:	49 8b 07             	mov    rax,QWORD PTR [r15]
  2d4ad2:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  2d4ad6:	b8 2d 00 00 00       	mov    eax,0x2d
  2d4adb:	83 f9 0e             	cmp    ecx,0xe
  2d4ade:	0f 87 f2 00 00 00    	ja     0x2d4bd6
  2d4ae4:	48 89 f0             	mov    rax,rsi
  2d4ae7:	48 c1 e8 2b          	shr    rax,0x2b
  2d4aeb:	74 20                	je     0x2d4b0d
  2d4aed:	49 8b 07             	mov    rax,QWORD PTR [r15]
  2d4af0:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  2d4af4:	0f 85 30 01 00 00    	jne    0x2d4c2a
  2d4afa:	48 83 c4 18          	add    rsp,0x18
  2d4afe:	5b                   	pop    rbx
  2d4aff:	41 5c                	pop    r12
  2d4b01:	41 5d                	pop    r13
  2d4b03:	41 5e                	pop    r14
  2d4b05:	41 5f                	pop    r15
  2d4b07:	5d                   	pop    rbp
  2d4b08:	e9 f3 6c 35 00       	jmp    0x62b800
  2d4b0d:	48 8b 9f 00 02 00 00 	mov    rbx,QWORD PTR [rdi+0x200]
  2d4b14:	49 89 fc             	mov    r12,rdi
  2d4b17:	49 89 f6             	mov    r14,rsi
  2d4b1a:	49 89 d5             	mov    r13,rdx
  2d4b1d:	0f b6 83 44 02 00 00 	movzx  eax,BYTE PTR [rbx+0x244]
  2d4b24:	a8 10                	test   al,0x10
  2d4b26:	75 29                	jne    0x2d4b51
  2d4b28:	a8 08                	test   al,0x8
  2d4b2a:	74 11                	je     0x2d4b3d
  2d4b2c:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  2d4b33:	00 00 
  2d4b35:	f0 83 80 a8 05 00 00 	lock add DWORD PTR [rax+0x5a8],0x1
  2d4b3c:	01 
  2d4b3d:	48 8d bb 70 01 00 00 	lea    rdi,[rbx+0x170]
  2d4b44:	31 f6                	xor    esi,esi
  2d4b46:	31 d2                	xor    edx,edx
  2d4b48:	31 c9                	xor    ecx,ecx
  2d4b4a:	e8 d1 6f 97 00       	call   0xc4bb20
  2d4b4f:	eb 12                	jmp    0x2d4b63
  2d4b51:	48 8d bb a8 01 00 00 	lea    rdi,[rbx+0x1a8]
  2d4b58:	31 f6                	xor    esi,esi
  2d4b5a:	31 d2                	xor    edx,edx
  2d4b5c:	31 c9                	xor    ecx,ecx
  2d4b5e:	e8 9d 1e 1f 00       	call   0x4c6a00
  2d4b63:	ff 83 c0 01 00 00    	inc    DWORD PTR [rbx+0x1c0]
  2d4b69:	48 8d 55 c8          	lea    rdx,[rbp-0x38]
  2d4b6d:	48 89 df             	mov    rdi,rbx
  2d4b70:	4c 89 f6             	mov    rsi,r14
  2d4b73:	f0 83 83 c4 01 00 00 	lock add DWORD PTR [rbx+0x1c4],0x1
  2d4b7a:	01 
  2d4b7b:	e8 c0 20 ff ff       	call   0x2c6c40
  2d4b80:	85 c0                	test   eax,eax
  2d4b82:	74 3d                	je     0x2d4bc1
  2d4b84:	48 8b 4d c8          	mov    rcx,QWORD PTR [rbp-0x38]
  2d4b88:	b8 2d 00 00 00       	mov    eax,0x2d
  2d4b8d:	f6 41 60 02          	test   BYTE PTR [rcx+0x60],0x2
  2d4b91:	75 33                	jne    0x2d4bc6
  2d4b93:	48 8b 79 50          	mov    rdi,QWORD PTR [rcx+0x50]
  2d4b97:	48 85 ff             	test   rdi,rdi
  2d4b9a:	74 2a                	je     0x2d4bc6
  2d4b9c:	0f b6 b7 9d 00 00 00 	movzx  esi,BYTE PTR [rdi+0x9d]
  2d4ba3:	83 fe 02             	cmp    esi,0x2
  2d4ba6:	72 46                	jb     0x2d4bee
  2d4ba8:	4c 89 ea             	mov    rdx,r13
  2d4bab:	83 fe 03             	cmp    esi,0x3
  2d4bae:	74 51                	je     0x2d4c01
  2d4bb0:	83 fe 0a             	cmp    esi,0xa
  2d4bb3:	75 11                	jne    0x2d4bc6
  2d4bb5:	8b 87 4c 01 00 00    	mov    eax,DWORD PTR [rdi+0x14c]
  2d4bbb:	89 02                	mov    DWORD PTR [rdx],eax
  2d4bbd:	31 c0                	xor    eax,eax
  2d4bbf:	eb 05                	jmp    0x2d4bc6
  2d4bc1:	b8 02 00 00 00       	mov    eax,0x2
  2d4bc6:	48 89 df             	mov    rdi,rbx
  2d4bc9:	31 f6                	xor    esi,esi
  2d4bcb:	31 d2                	xor    edx,edx
  2d4bcd:	89 c3                	mov    ebx,eax
  2d4bcf:	e8 1c 19 ff ff       	call   0x2c64f0
  2d4bd4:	89 d8                	mov    eax,ebx
  2d4bd6:	49 8b 0f             	mov    rcx,QWORD PTR [r15]
  2d4bd9:	48 3b 4d d0          	cmp    rcx,QWORD PTR [rbp-0x30]
  2d4bdd:	75 4b                	jne    0x2d4c2a
  2d4bdf:	48 83 c4 18          	add    rsp,0x18
  2d4be3:	5b                   	pop    rbx
  2d4be4:	41 5c                	pop    r12
  2d4be6:	41 5d                	pop    r13
  2d4be8:	41 5e                	pop    r14
  2d4bea:	41 5f                	pop    r15
  2d4bec:	5d                   	pop    rbp
  2d4bed:	c3                   	ret
  2d4bee:	f6 87 a2 00 00 00 02 	test   BYTE PTR [rdi+0xa2],0x2
  2d4bf5:	75 25                	jne    0x2d4c1c
  2d4bf7:	41 8b 84 24 bc 00 00 	mov    eax,DWORD PTR [r12+0xbc]
  2d4bfe:	00 
  2d4bff:	eb 21                	jmp    0x2d4c22
  2d4c01:	f6 87 a2 00 00 00 01 	test   BYTE PTR [rdi+0xa2],0x1
  2d4c08:	74 bc                	je     0x2d4bc6
  2d4c0a:	4c 2b 71 20          	sub    r14,QWORD PTR [rcx+0x20]
  2d4c0e:	4c 03 71 58          	add    r14,QWORD PTR [rcx+0x58]
  2d4c12:	4c 89 f6             	mov    rsi,r14
  2d4c15:	e8 16 0b 0f 00       	call   0x3c5730
  2d4c1a:	eb aa                	jmp    0x2d4bc6
  2d4c1c:	8b 87 4c 01 00 00    	mov    eax,DWORD PTR [rdi+0x14c]
  2d4c22:	41 89 45 00          	mov    DWORD PTR [r13+0x0],eax
  2d4c26:	31 c0                	xor    eax,eax
  2d4c28:	eb 9c                	jmp    0x2d4bc6
  2d4c2a:	e8 81 8a 42 00       	call   0x6fd6b0
  2d4c2f:	0f 0b                	ud2
  2d4c31:	90                   	nop
  2d4c32:	90                   	nop
  2d4c33:	90                   	nop
  2d4c34:	90                   	nop
  2d4c35:	90                   	nop
  2d4c36:	90                   	nop
  2d4c37:	90                   	nop
  2d4c38:	90                   	nop
  2d4c39:	90                   	nop
  2d4c3a:	90                   	nop
  2d4c3b:	90                   	nop
  2d4c3c:	90                   	nop
  2d4c3d:	90                   	nop
  2d4c3e:	90                   	nop
  2d4c3f:	90                   	nop
  2d4c40:	55                   	push   rbp
  2d4c41:	48 89 e5             	mov    rbp,rsp
  2d4c44:	41 56                	push   r14
  2d4c46:	53                   	push   rbx
  2d4c47:	41 89 fe             	mov    r14d,edi
  2d4c4a:	48 8d 3d 0f 52 2b 03 	lea    rdi,[rip+0x32b520f]        # 0x3589e60
  2d4c51:	31 db                	xor    ebx,ebx
  2d4c53:	31 f6                	xor    esi,esi
  2d4c55:	31 d2                	xor    edx,edx
  2d4c57:	31 c9                	xor    ecx,ecx
  2d4c59:	e8 f2 66 97 00       	call   0xc4b350
  2d4c5e:	48 8d 05 1b 52 2b 03 	lea    rax,[rip+0x32b521b]        # 0x3589e80
  2d4c65:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  2d4c6c:	00 00 00 00 
  2d4c70:	48 8b 00             	mov    rax,QWORD PTR [rax]
  2d4c73:	48 85 c0             	test   rax,rax
  2d4c76:	74 1d                	je     0x2d4c95
  2d4c78:	48 8b 88 00 02 00 00 	mov    rcx,QWORD PTR [rax+0x200]
  2d4c7f:	48 8b 89 d8 01 00 00 	mov    rcx,QWORD PTR [rcx+0x1d8]
  2d4c86:	44 39 b1 7c 02 00 00 	cmp    DWORD PTR [rcx+0x27c],r14d
  2d4c8d:	75 e1                	jne    0x2d4c70
  2d4c8f:	8b 98 bc 00 00 00    	mov    ebx,DWORD PTR [rax+0xbc]
  2d4c95:	48 8d 3d c4 51 2b 03 	lea    rdi,[rip+0x32b51c4]        # 0x3589e60
  2d4c9c:	31 f6                	xor    esi,esi
  2d4c9e:	31 d2                	xor    edx,edx
  2d4ca0:	e8 5b 76 97 00       	call   0xc4c300
  2d4ca5:	89 d8                	mov    eax,ebx
  2d4ca7:	5b                   	pop    rbx
  2d4ca8:	41 5e                	pop    r14
  2d4caa:	5d                   	pop    rbp
  2d4cab:	c3                   	ret
  2d4cac:	90                   	nop
  2d4cad:	90                   	nop
  2d4cae:	90                   	nop
  2d4caf:	90                   	nop
  2d4cb0:	55                   	push   rbp
  2d4cb1:	48 89 e5             	mov    rbp,rsp
  2d4cb4:	41 57                	push   r15
  2d4cb6:	41 56                	push   r14
  2d4cb8:	41 55                	push   r13
  2d4cba:	41 54                	push   r12
  2d4cbc:	53                   	push   rbx
  2d4cbd:	48 83 ec 18          	sub    rsp,0x18
  2d4cc1:	48 8d 05 48 76 64 03 	lea    rax,[rip+0x3647648]        # 0x391c310
  2d4cc8:	48 8b 00             	mov    rax,QWORD PTR [rax]
  2d4ccb:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  2d4ccf:	4c 8b 6f 08          	mov    r13,QWORD PTR [rdi+0x8]
  2d4cd3:	4c 89 6d c8          	mov    QWORD PTR [rbp-0x38],r13
  2d4cd7:	49 39 fd             	cmp    r13,rdi
  2d4cda:	0f 84 58 01 00 00    	je     0x2d4e38
  2d4ce0:	48 8d 87 a8 01 00 00 	lea    rax,[rdi+0x1a8]
  2d4ce7:	48 89 fb             	mov    rbx,rdi
  2d4cea:	4c 8d bf 70 01 00 00 	lea    r15,[rdi+0x170]
  2d4cf1:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
  2d4cf5:	eb 30                	jmp    0x2d4d27
  2d4cf7:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
  2d4cfe:	00 00 
  2d4d00:	49 8b 75 20          	mov    rsi,QWORD PTR [r13+0x20]
  2d4d04:	49 8b 55 28          	mov    rdx,QWORD PTR [r13+0x28]
  2d4d08:	48 89 df             	mov    rdi,rbx
  2d4d0b:	b9 01 00 00 00       	mov    ecx,0x1
  2d4d10:	48 29 f2             	sub    rdx,rsi
  2d4d13:	41 ff d4             	call   r12
  2d4d16:	4d 8b 6d 08          	mov    r13,QWORD PTR [r13+0x8]
  2d4d1a:	4c 89 6d c8          	mov    QWORD PTR [rbp-0x38],r13
  2d4d1e:	49 39 dd             	cmp    r13,rbx
  2d4d21:	0f 84 11 01 00 00    	je     0x2d4e38
  2d4d27:	41 8b 45 60          	mov    eax,DWORD PTR [r13+0x60]
  2d4d2b:	a9 00 01 04 00       	test   eax,0x40100
  2d4d30:	0f 84 9e 00 00 00    	je     0x2d4dd4
  2d4d36:	0d 00 02 00 00       	or     eax,0x200
  2d4d3b:	48 89 df             	mov    rdi,rbx
  2d4d3e:	31 f6                	xor    esi,esi
  2d4d40:	31 d2                	xor    edx,edx
  2d4d42:	31 c9                	xor    ecx,ecx
  2d4d44:	41 89 45 60          	mov    DWORD PTR [r13+0x60],eax
  2d4d48:	4d 8b 65 20          	mov    r12,QWORD PTR [r13+0x20]
  2d4d4c:	44 8b b3 c0 01 00 00 	mov    r14d,DWORD PTR [rbx+0x1c0]
  2d4d53:	e8 28 20 ff ff       	call   0x2c6d80
  2d4d58:	0f b6 83 44 02 00 00 	movzx  eax,BYTE PTR [rbx+0x244]
  2d4d5f:	a8 10                	test   al,0x10
  2d4d61:	75 2d                	jne    0x2d4d90
  2d4d63:	a8 08                	test   al,0x8
  2d4d65:	74 11                	je     0x2d4d78
  2d4d67:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  2d4d6e:	00 00 
  2d4d70:	f0 83 80 a8 05 00 00 	lock add DWORD PTR [rax+0x5a8],0x1
  2d4d77:	01 
  2d4d78:	4c 89 ff             	mov    rdi,r15
  2d4d7b:	31 f6                	xor    esi,esi
  2d4d7d:	31 d2                	xor    edx,edx
  2d4d7f:	31 c9                	xor    ecx,ecx
  2d4d81:	e8 9a 6d 97 00       	call   0xc4bb20
  2d4d86:	eb 17                	jmp    0x2d4d9f
  2d4d88:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
  2d4d8f:	00 
  2d4d90:	48 8b 7d c0          	mov    rdi,QWORD PTR [rbp-0x40]
  2d4d94:	31 f6                	xor    esi,esi
  2d4d96:	31 d2                	xor    edx,edx
  2d4d98:	31 c9                	xor    ecx,ecx
  2d4d9a:	e8 61 1c 1f 00       	call   0x4c6a00
  2d4d9f:	ff 83 c0 01 00 00    	inc    DWORD PTR [rbx+0x1c0]
  2d4da5:	41 ff c6             	inc    r14d
  2d4da8:	f0 83 83 c4 01 00 00 	lock add DWORD PTR [rbx+0x1c4],0x1
  2d4daf:	01 
  2d4db0:	44 3b b3 c0 01 00 00 	cmp    r14d,DWORD PTR [rbx+0x1c0]
  2d4db7:	74 1b                	je     0x2d4dd4
  2d4db9:	48 89 df             	mov    rdi,rbx
  2d4dbc:	4c 89 e6             	mov    rsi,r12
  2d4dbf:	48 8d 55 c8          	lea    rdx,[rbp-0x38]
  2d4dc3:	e8 78 1e ff ff       	call   0x2c6c40
  2d4dc8:	4c 8b 6d c8          	mov    r13,QWORD PTR [rbp-0x38]
  2d4dcc:	85 c0                	test   eax,eax
  2d4dce:	0f 84 42 ff ff ff    	je     0x2d4d16
  2d4dd4:	41 0f b7 45 64       	movzx  eax,WORD PTR [r13+0x64]
  2d4dd9:	a9 c7 03 00 00       	test   eax,0x3c7
  2d4dde:	74 19                	je     0x2d4df9
  2d4de0:	48 8b bb d8 01 00 00 	mov    rdi,QWORD PTR [rbx+0x1d8]
  2d4de7:	49 8b 75 20          	mov    rsi,QWORD PTR [r13+0x20]
  2d4deb:	49 8b 55 28          	mov    rdx,QWORD PTR [r13+0x28]
  2d4def:	e8 ac a8 60 00       	call   0x8df6a0
  2d4df4:	41 0f b7 45 64       	movzx  eax,WORD PTR [r13+0x64]
  2d4df9:	a8 30                	test   al,0x30
  2d4dfb:	0f 84 15 ff ff ff    	je     0x2d4d16
  2d4e01:	48 8b 05 e0 14 7c 01 	mov    rax,QWORD PTR [rip+0x17c14e0]        # 0x1a962e8
  2d4e08:	4c 8b 60 18          	mov    r12,QWORD PTR [rax+0x18]
  2d4e0c:	48 8d 05 fd 70 f9 ff 	lea    rax,[rip+0xfffffffffff970fd]        # 0x26bf10
  2d4e13:	4c 29 e0             	sub    rax,r12
  2d4e16:	48 c1 c8 03          	ror    rax,0x3
  2d4e1a:	48 83 f8 02          	cmp    rax,0x2
  2d4e1e:	0f 86 dc fe ff ff    	jbe    0x2d4d00
  2d4e24:	48 8d 3d c5 12 7c 01 	lea    rdi,[rip+0x17c12c5]        # 0x1a960f0
  2d4e2b:	4c 89 e6             	mov    rsi,r12
  2d4e2e:	e8 8d aa 17 00       	call   0x44f8c0
  2d4e33:	e9 c8 fe ff ff       	jmp    0x2d4d00
  2d4e38:	48 8d 05 d1 74 64 03 	lea    rax,[rip+0x36474d1]        # 0x391c310
  2d4e3f:	48 8b 00             	mov    rax,QWORD PTR [rax]
  2d4e42:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  2d4e46:	75 0f                	jne    0x2d4e57
  2d4e48:	48 83 c4 18          	add    rsp,0x18
  2d4e4c:	5b                   	pop    rbx
  2d4e4d:	41 5c                	pop    r12
  2d4e4f:	41 5d                	pop    r13
  2d4e51:	41 5e                	pop    r14
  2d4e53:	41 5f                	pop    r15
  2d4e55:	5d                   	pop    rbp
  2d4e56:	c3                   	ret
  2d4e57:	e8 54 88 42 00       	call   0x6fd6b0
  2d4e5c:	0f 0b                	ud2
  2d4e5e:	90                   	nop
  2d4e5f:	90                   	nop
  2d4e60:	55                   	push   rbp
  2d4e61:	48 89 e5             	mov    rbp,rsp
  2d4e64:	41 57                	push   r15
  2d4e66:	41 56                	push   r14
  2d4e68:	41 55                	push   r13
  2d4e6a:	41 54                	push   r12
  2d4e6c:	53                   	push   rbx
  2d4e6d:	48 83 ec 28          	sub    rsp,0x28
  2d4e71:	4c 8b 77 08          	mov    r14,QWORD PTR [rdi+0x8]
  2d4e75:	48 89 7d d0          	mov    QWORD PTR [rbp-0x30],rdi
  2d4e79:	49 39 fe             	cmp    r14,rdi
  2d4e7c:	0f 84 26 01 00 00    	je     0x2d4fa8
  2d4e82:	48 8b 45 d0          	mov    rax,QWORD PTR [rbp-0x30]
  2d4e86:	4d 8b 7e 20          	mov    r15,QWORD PTR [r14+0x20]
  2d4e8a:	48 8b 80 d8 01 00 00 	mov    rax,QWORD PTR [rax+0x1d8]
  2d4e91:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
  2d4e95:	eb 2d                	jmp    0x2d4ec4
  2d4e97:	66 0f 1f 84 00 00 00 	nop    WORD PTR [rax+rax*1+0x0]
  2d4e9e:	00 00 
  2d4ea0:	48 8b 7d d0          	mov    rdi,QWORD PTR [rbp-0x30]
  2d4ea4:	4c 8b 45 b8          	mov    r8,QWORD PTR [rbp-0x48]
  2d4ea8:	44 8b 4d cc          	mov    r9d,DWORD PTR [rbp-0x34]
  2d4eac:	4c 89 e6             	mov    rsi,r12
  2d4eaf:	4c 89 fa             	mov    rdx,r15
  2d4eb2:	4c 89 e9             	mov    rcx,r13
  2d4eb5:	e8 16 6c ff ff       	call   0x2cbad0
  2d4eba:	4c 3b 75 d0          	cmp    r14,QWORD PTR [rbp-0x30]
  2d4ebe:	0f 84 e4 00 00 00    	je     0x2d4fa8
  2d4ec4:	4d 8b 66 20          	mov    r12,QWORD PTR [r14+0x20]
  2d4ec8:	4c 89 f3             	mov    rbx,r14
  2d4ecb:	4d 39 e7             	cmp    r15,r12
  2d4ece:	73 1e                	jae    0x2d4eee
  2d4ed0:	48 8b 7d c0          	mov    rdi,QWORD PTR [rbp-0x40]
  2d4ed4:	4c 89 fe             	mov    rsi,r15
  2d4ed7:	4c 89 e2             	mov    rdx,r12
  2d4eda:	c7 04 24 00 00 00 00 	mov    DWORD PTR [rsp],0x0
  2d4ee1:	31 c9                	xor    ecx,ecx
  2d4ee3:	45 31 c0             	xor    r8d,r8d
  2d4ee6:	45 31 c9             	xor    r9d,r9d
  2d4ee9:	e8 e2 f7 60 00       	call   0x8e46d0
  2d4eee:	4c 8b 43 58          	mov    r8,QWORD PTR [rbx+0x58]
  2d4ef2:	4c 8b 6b 50          	mov    r13,QWORD PTR [rbx+0x50]
  2d4ef6:	0f b7 43 64          	movzx  eax,WORD PTR [rbx+0x64]
  2d4efa:	49 89 de             	mov    r14,rbx
  2d4efd:	4c 89 c1             	mov    rcx,r8
  2d4f00:	4c 29 e1             	sub    rcx,r12
  2d4f03:	66 66 66 66 2e 0f 1f 	data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  2d4f0a:	84 00 00 00 00 00 
  2d4f10:	4d 8b 7e 28          	mov    r15,QWORD PTR [r14+0x28]
  2d4f14:	4d 8b 76 08          	mov    r14,QWORD PTR [r14+0x8]
  2d4f18:	4d 39 7e 20          	cmp    QWORD PTR [r14+0x20],r15
  2d4f1c:	75 17                	jne    0x2d4f35
  2d4f1e:	4d 39 6e 50          	cmp    QWORD PTR [r14+0x50],r13
  2d4f22:	75 11                	jne    0x2d4f35
  2d4f24:	4a 8d 14 39          	lea    rdx,[rcx+r15*1]
  2d4f28:	49 39 56 58          	cmp    QWORD PTR [r14+0x58],rdx
  2d4f2c:	75 07                	jne    0x2d4f35
  2d4f2e:	66 41 39 46 64       	cmp    WORD PTR [r14+0x64],ax
  2d4f33:	74 db                	je     0x2d4f10
  2d4f35:	4d 85 ed             	test   r13,r13
  2d4f38:	74 26                	je     0x2d4f60
  2d4f3a:	41 80 bd 9d 00 00 00 	cmp    BYTE PTR [r13+0x9d],0xb
  2d4f41:	0b 
  2d4f42:	75 1c                	jne    0x2d4f60
  2d4f44:	48 8b 7d d0          	mov    rdi,QWORD PTR [rbp-0x30]
  2d4f48:	4c 89 e6             	mov    rsi,r12
  2d4f4b:	4c 89 fa             	mov    rdx,r15
  2d4f4e:	4c 89 e9             	mov    rcx,r13
  2d4f51:	e8 da 2f 6d 00       	call   0x9a7f30
  2d4f56:	e9 5f ff ff ff       	jmp    0x2d4eba
  2d4f5b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
  2d4f60:	b9 03 01 00 00       	mov    ecx,0x103
  2d4f65:	48 8b 7d c0          	mov    rdi,QWORD PTR [rbp-0x40]
  2d4f69:	44 0f b7 c8          	movzx  r9d,ax
  2d4f6d:	4c 89 e6             	mov    rsi,r12
  2d4f70:	4c 89 fa             	mov    rdx,r15
  2d4f73:	4c 89 45 b8          	mov    QWORD PTR [rbp-0x48],r8
  2d4f77:	c4 e2 70 f7 8b 40 01 	bextr  ecx,DWORD PTR [rbx+0x140],ecx
  2d4f7e:	00 00 
  2d4f80:	44 89 4d cc          	mov    DWORD PTR [rbp-0x34],r9d
  2d4f84:	89 0c 24             	mov    DWORD PTR [rsp],ecx
  2d4f87:	4c 89 e9             	mov    rcx,r13
  2d4f8a:	e8 41 f7 60 00       	call   0x8e46d0
  2d4f8f:	f6 43 62 02          	test   BYTE PTR [rbx+0x62],0x2
  2d4f93:	0f 84 07 ff ff ff    	je     0x2d4ea0
  2d4f99:	83 7b 6c 00          	cmp    DWORD PTR [rbx+0x6c],0x0
  2d4f9d:	0f 85 fd fe ff ff    	jne    0x2d4ea0
  2d4fa3:	e9 12 ff ff ff       	jmp    0x2d4eba
  2d4fa8:	48 83 c4 28          	add    rsp,0x28
  2d4fac:	5b                   	pop    rbx
  2d4fad:	41 5c                	pop    r12
  2d4faf:	41 5d                	pop    r13
  2d4fb1:	41 5e                	pop    r14
  2d4fb3:	41 5f                	pop    r15
  2d4fb5:	5d                   	pop    rbp
  2d4fb6:	c3                   	ret
  2d4fb7:	90                   	nop
  2d4fb8:	90                   	nop
  2d4fb9:	90                   	nop
  2d4fba:	90                   	nop
  2d4fbb:	90                   	nop
  2d4fbc:	90                   	nop
  2d4fbd:	90                   	nop
  2d4fbe:	90                   	nop
  2d4fbf:	90                   	nop
  2d4fc0:	55                   	push   rbp
  2d4fc1:	48 89 e5             	mov    rbp,rsp
  2d4fc4:	41 57                	push   r15
  2d4fc6:	41 56                	push   r14
  2d4fc8:	41 55                	push   r13
  2d4fca:	41 54                	push   r12
  2d4fcc:	53                   	push   rbx
  2d4fcd:	48 83 ec 38          	sub    rsp,0x38
  2d4fd1:	48 8d 05 38 73 64 03 	lea    rax,[rip+0x3647338]        # 0x391c310
  2d4fd8:	89 7d c4             	mov    DWORD PTR [rbp-0x3c],edi
  2d4fdb:	48 8d 3d 7e 4e 2b 03 	lea    rdi,[rip+0x32b4e7e]        # 0x3589e60
  2d4fe2:	31 f6                	xor    esi,esi
  2d4fe4:	31 d2                	xor    edx,edx
  2d4fe6:	31 c9                	xor    ecx,ecx
  2d4fe8:	48 8b 00             	mov    rax,QWORD PTR [rax]
  2d4feb:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  2d4fef:	e8 5c 63 97 00       	call   0xc4b350
  2d4ff4:	4c 8b 35 85 4e 2b 03 	mov    r14,QWORD PTR [rip+0x32b4e85]        # 0x3589e80
  2d4ffb:	4d 85 f6             	test   r14,r14
  2d4ffe:	0f 84 d9 02 00 00    	je     0x2d52dd
  2d5004:	48 8d 1d 55 4e 2b 03 	lea    rbx,[rip+0x32b4e55]        # 0x3589e60
  2d500b:	eb 1d                	jmp    0x2d502a
  2d500d:	0f 1f 00             	nop    DWORD PTR [rax]
  2d5010:	4c 89 e7             	mov    rdi,r12
  2d5013:	31 f6                	xor    esi,esi
  2d5015:	31 d2                	xor    edx,edx
  2d5017:	31 c9                	xor    ecx,ecx
  2d5019:	e8 82 1f 1f 00       	call   0x4c6fa0
  2d501e:	4d 8b 36             	mov    r14,QWORD PTR [r14]
  2d5021:	4d 85 f6             	test   r14,r14
  2d5024:	0f 84 b3 02 00 00    	je     0x2d52dd
  2d502a:	4d 8d a6 48 01 00 00 	lea    r12,[r14+0x148]
  2d5031:	31 f6                	xor    esi,esi
  2d5033:	31 d2                	xor    edx,edx
  2d5035:	31 c9                	xor    ecx,ecx
  2d5037:	4c 89 e7             	mov    rdi,r12
  2d503a:	e8 c1 19 1f 00       	call   0x4c6a00
  2d503f:	8b 45 c4             	mov    eax,DWORD PTR [rbp-0x3c]
  2d5042:	41 39 86 c0 05 00 00 	cmp    DWORD PTR [r14+0x5c0],eax
  2d5049:	74 c5                	je     0x2d5010
  2d504b:	41 8b 86 b0 00 00 00 	mov    eax,DWORD PTR [r14+0xb0]
  2d5052:	a9 00 20 00 00       	test   eax,0x2000
  2d5057:	75 b7                	jne    0x2d5010
  2d5059:	41 ff 86 58 03 00 00 	inc    DWORD PTR [r14+0x358]
  2d5060:	a9 00 00 00 10       	test   eax,0x10000000
  2d5065:	75 08                	jne    0x2d506f
  2d5067:	4c 89 f7             	mov    rdi,r14
  2d506a:	e8 a1 59 26 00       	call   0x53aa10
  2d506f:	4c 89 e7             	mov    rdi,r12
  2d5072:	31 f6                	xor    esi,esi
  2d5074:	31 d2                	xor    edx,edx
  2d5076:	31 c9                	xor    ecx,ecx
  2d5078:	e8 23 1f 1f 00       	call   0x4c6fa0
  2d507d:	48 89 df             	mov    rdi,rbx
  2d5080:	31 f6                	xor    esi,esi
  2d5082:	31 d2                	xor    edx,edx
  2d5084:	e8 77 72 97 00       	call   0xc4c300
  2d5089:	4d 8b be 00 02 00 00 	mov    r15,QWORD PTR [r14+0x200]
  2d5090:	4c 89 65 b8          	mov    QWORD PTR [rbp-0x48],r12
  2d5094:	41 0f b6 87 44 02 00 	movzx  eax,BYTE PTR [r15+0x244]
  2d509b:	00 
  2d509c:	a8 10                	test   al,0x10
  2d509e:	75 29                	jne    0x2d50c9
  2d50a0:	a8 08                	test   al,0x8
  2d50a2:	74 11                	je     0x2d50b5
  2d50a4:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  2d50ab:	00 00 
  2d50ad:	f0 83 80 a8 05 00 00 	lock add DWORD PTR [rax+0x5a8],0x1
  2d50b4:	01 
  2d50b5:	49 8d bf 70 01 00 00 	lea    rdi,[r15+0x170]
  2d50bc:	31 f6                	xor    esi,esi
  2d50be:	31 d2                	xor    edx,edx
  2d50c0:	31 c9                	xor    ecx,ecx
  2d50c2:	e8 59 6a 97 00       	call   0xc4bb20
  2d50c7:	eb 12                	jmp    0x2d50db
  2d50c9:	49 8d bf a8 01 00 00 	lea    rdi,[r15+0x1a8]
  2d50d0:	31 f6                	xor    esi,esi
  2d50d2:	31 d2                	xor    edx,edx
  2d50d4:	31 c9                	xor    ecx,ecx
  2d50d6:	e8 25 19 1f 00       	call   0x4c6a00
  2d50db:	41 ff 87 c0 01 00 00 	inc    DWORD PTR [r15+0x1c0]
  2d50e2:	f0 41 83 87 c4 01 00 	lock add DWORD PTR [r15+0x1c4],0x1
  2d50e9:	00 01 
  2d50eb:	49 8b 5f 08          	mov    rbx,QWORD PTR [r15+0x8]
  2d50ef:	48 89 5d c8          	mov    QWORD PTR [rbp-0x38],rbx
  2d50f3:	4c 39 fb             	cmp    rbx,r15
  2d50f6:	0f 84 74 01 00 00    	je     0x2d5270
  2d50fc:	49 8d 87 a8 01 00 00 	lea    rax,[r15+0x1a8]
  2d5103:	49 8d 8f 70 01 00 00 	lea    rcx,[r15+0x170]
  2d510a:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
  2d510e:	48 89 4d b0          	mov    QWORD PTR [rbp-0x50],rcx
  2d5112:	eb 1d                	jmp    0x2d5131
  2d5114:	66 66 66 2e 0f 1f 84 	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  2d511b:	00 00 00 00 00 
  2d5120:	48 8b 5b 08          	mov    rbx,QWORD PTR [rbx+0x8]
  2d5124:	48 89 5d c8          	mov    QWORD PTR [rbp-0x38],rbx
  2d5128:	4c 39 fb             	cmp    rbx,r15
  2d512b:	0f 84 3f 01 00 00    	je     0x2d5270
  2d5131:	8b 43 60             	mov    eax,DWORD PTR [rbx+0x60]
  2d5134:	a9 00 01 04 00       	test   eax,0x40100
  2d5139:	0f 84 a7 00 00 00    	je     0x2d51e6
  2d513f:	0d 00 02 00 00       	or     eax,0x200
  2d5144:	4c 89 ff             	mov    rdi,r15
  2d5147:	31 f6                	xor    esi,esi
  2d5149:	31 d2                	xor    edx,edx
  2d514b:	31 c9                	xor    ecx,ecx
  2d514d:	89 43 60             	mov    DWORD PTR [rbx+0x60],eax
  2d5150:	4c 8b 63 20          	mov    r12,QWORD PTR [rbx+0x20]
  2d5154:	45 8b af c0 01 00 00 	mov    r13d,DWORD PTR [r15+0x1c0]
  2d515b:	e8 20 1c ff ff       	call   0x2c6d80
  2d5160:	41 0f b6 87 44 02 00 	movzx  eax,BYTE PTR [r15+0x244]
  2d5167:	00 
  2d5168:	a8 10                	test   al,0x10
  2d516a:	75 34                	jne    0x2d51a0
  2d516c:	a8 08                	test   al,0x8
  2d516e:	74 11                	je     0x2d5181
  2d5170:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  2d5177:	00 00 
  2d5179:	f0 83 80 a8 05 00 00 	lock add DWORD PTR [rax+0x5a8],0x1
  2d5180:	01 
  2d5181:	48 8b 7d b0          	mov    rdi,QWORD PTR [rbp-0x50]
  2d5185:	31 f6                	xor    esi,esi
  2d5187:	31 d2                	xor    edx,edx
  2d5189:	31 c9                	xor    ecx,ecx
  2d518b:	e8 90 69 97 00       	call   0xc4bb20
  2d5190:	eb 1d                	jmp    0x2d51af
  2d5192:	66 66 66 66 66 2e 0f 	data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  2d5199:	1f 84 00 00 00 00 00 
  2d51a0:	48 8b 7d a8          	mov    rdi,QWORD PTR [rbp-0x58]
  2d51a4:	31 f6                	xor    esi,esi
  2d51a6:	31 d2                	xor    edx,edx
  2d51a8:	31 c9                	xor    ecx,ecx
  2d51aa:	e8 51 18 1f 00       	call   0x4c6a00
  2d51af:	41 ff 87 c0 01 00 00 	inc    DWORD PTR [r15+0x1c0]
  2d51b6:	41 ff c5             	inc    r13d
  2d51b9:	f0 41 83 87 c4 01 00 	lock add DWORD PTR [r15+0x1c4],0x1
  2d51c0:	00 01 
  2d51c2:	45 3b af c0 01 00 00 	cmp    r13d,DWORD PTR [r15+0x1c0]
  2d51c9:	74 1b                	je     0x2d51e6
  2d51cb:	4c 89 ff             	mov    rdi,r15
  2d51ce:	4c 89 e6             	mov    rsi,r12
  2d51d1:	48 8d 55 c8          	lea    rdx,[rbp-0x38]
  2d51d5:	e8 66 1a ff ff       	call   0x2c6c40
  2d51da:	48 8b 5d c8          	mov    rbx,QWORD PTR [rbp-0x38]
  2d51de:	85 c0                	test   eax,eax
  2d51e0:	0f 84 3a ff ff ff    	je     0x2d5120
  2d51e6:	83 7b 6c 00          	cmp    DWORD PTR [rbx+0x6c],0x0
  2d51ea:	0f 84 30 ff ff ff    	je     0x2d5120
  2d51f0:	4c 8b 63 50          	mov    r12,QWORD PTR [rbx+0x50]
  2d51f4:	4d 85 e4             	test   r12,r12
  2d51f7:	0f 84 23 ff ff ff    	je     0x2d5120
  2d51fd:	41 0f b6 84 24 50 01 	movzx  eax,BYTE PTR [r12+0x150]
  2d5204:	00 00 
  2d5206:	39 45 c4             	cmp    DWORD PTR [rbp-0x3c],eax
  2d5209:	0f 85 11 ff ff ff    	jne    0x2d5120
  2d520f:	0f b7 43 64          	movzx  eax,WORD PTR [rbx+0x64]
  2d5213:	a9 c7 03 00 00       	test   eax,0x3c7
  2d5218:	0f 84 02 ff ff ff    	je     0x2d5120
  2d521e:	49 8b bf d8 01 00 00 	mov    rdi,QWORD PTR [r15+0x1d8]
  2d5225:	48 8b 73 20          	mov    rsi,QWORD PTR [rbx+0x20]
  2d5229:	48 8b 53 28          	mov    rdx,QWORD PTR [rbx+0x28]
  2d522d:	e8 6e a4 60 00       	call   0x8df6a0
  2d5232:	b8 03 01 00 00       	mov    eax,0x103
  2d5237:	49 8b bf d8 01 00 00 	mov    rdi,QWORD PTR [r15+0x1d8]
  2d523e:	48 8b 73 20          	mov    rsi,QWORD PTR [rbx+0x20]
  2d5242:	48 8b 53 28          	mov    rdx,QWORD PTR [rbx+0x28]
  2d5246:	4c 8b 43 58          	mov    r8,QWORD PTR [rbx+0x58]
  2d524a:	44 0f b7 4b 64       	movzx  r9d,WORD PTR [rbx+0x64]
  2d524f:	4c 89 e1             	mov    rcx,r12
  2d5252:	c4 e2 78 f7 83 40 01 	bextr  eax,DWORD PTR [rbx+0x140],eax
  2d5259:	00 00 
  2d525b:	89 04 24             	mov    DWORD PTR [rsp],eax
  2d525e:	e8 6d f4 60 00       	call   0x8e46d0
  2d5263:	e9 b8 fe ff ff       	jmp    0x2d5120
  2d5268:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
  2d526f:	00 
  2d5270:	4c 89 ff             	mov    rdi,r15
  2d5273:	31 f6                	xor    esi,esi
  2d5275:	31 d2                	xor    edx,edx
  2d5277:	e8 74 12 ff ff       	call   0x2c64f0
  2d527c:	48 8d 1d dd 4b 2b 03 	lea    rbx,[rip+0x32b4bdd]        # 0x3589e60
  2d5283:	31 f6                	xor    esi,esi
  2d5285:	31 d2                	xor    edx,edx
  2d5287:	31 c9                	xor    ecx,ecx
  2d5289:	48 89 df             	mov    rdi,rbx
  2d528c:	e8 bf 60 97 00       	call   0xc4b350
  2d5291:	4c 8b 65 b8          	mov    r12,QWORD PTR [rbp-0x48]
  2d5295:	31 f6                	xor    esi,esi
  2d5297:	31 d2                	xor    edx,edx
  2d5299:	31 c9                	xor    ecx,ecx
  2d529b:	4c 89 e7             	mov    rdi,r12
  2d529e:	e8 5d 17 1f 00       	call   0x4c6a00
  2d52a3:	41 0f b6 8e b1 00 00 	movzx  ecx,BYTE PTR [r14+0xb1]
  2d52aa:	00 
  2d52ab:	41 8b 86 58 03 00 00 	mov    eax,DWORD PTR [r14+0x358]
  2d52b2:	c0 e9 05             	shr    cl,0x5
  2d52b5:	ff c8                	dec    eax
  2d52b7:	0f 94 c2             	sete   dl
  2d52ba:	41 89 86 58 03 00 00 	mov    DWORD PTR [r14+0x358],eax
  2d52c1:	20 ca                	and    dl,cl
  2d52c3:	80 fa 01             	cmp    dl,0x1
  2d52c6:	0f 85 44 fd ff ff    	jne    0x2d5010
  2d52cc:	49 8d be 58 03 00 00 	lea    rdi,[r14+0x358]
  2d52d3:	e8 38 16 93 00       	call   0xc06910
  2d52d8:	e9 33 fd ff ff       	jmp    0x2d5010
  2d52dd:	48 8d 05 2c 70 64 03 	lea    rax,[rip+0x364702c]        # 0x391c310
  2d52e4:	48 8b 00             	mov    rax,QWORD PTR [rax]
  2d52e7:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  2d52eb:	75 1e                	jne    0x2d530b
  2d52ed:	48 8d 3d 6c 4b 2b 03 	lea    rdi,[rip+0x32b4b6c]        # 0x3589e60
  2d52f4:	31 f6                	xor    esi,esi
  2d52f6:	31 d2                	xor    edx,edx
  2d52f8:	48 83 c4 38          	add    rsp,0x38
  2d52fc:	5b                   	pop    rbx
  2d52fd:	41 5c                	pop    r12
  2d52ff:	41 5d                	pop    r13
  2d5301:	41 5e                	pop    r14
  2d5303:	41 5f                	pop    r15
  2d5305:	5d                   	pop    rbp
  2d5306:	e9 f5 6f 97 00       	jmp    0xc4c300
  2d530b:	e8 a0 83 42 00       	call   0x6fd6b0
  2d5310:	0f 0b                	ud2
  2d5312:	90                   	nop
  2d5313:	90                   	nop
  2d5314:	90                   	nop
  2d5315:	90                   	nop
  2d5316:	90                   	nop
  2d5317:	90                   	nop
  2d5318:	90                   	nop
  2d5319:	90                   	nop
  2d531a:	90                   	nop
  2d531b:	90                   	nop
  2d531c:	90                   	nop
  2d531d:	90                   	nop
  2d531e:	90                   	nop
  2d531f:	90                   	nop
  2d5320:	55                   	push   rbp
  2d5321:	48 89 e5             	mov    rbp,rsp
  2d5324:	41 57                	push   r15
  2d5326:	41 56                	push   r14
  2d5328:	41 55                	push   r13
  2d532a:	41 54                	push   r12
  2d532c:	53                   	push   rbx
  2d532d:	48 83 ec 78          	sub    rsp,0x78
  2d5331:	48 8b 47 10          	mov    rax,QWORD PTR [rdi+0x10]
  2d5335:	4c 89 45 c0          	mov    QWORD PTR [rbp-0x40],r8
  2d5339:	49 89 c8             	mov    r8,rcx
  2d533c:	48 89 d3             	mov    rbx,rdx
  2d533f:	49 89 f7             	mov    r15,rsi
  2d5342:	48 89 7d 88          	mov    QWORD PTR [rbp-0x78],rdi
  2d5346:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
  2d534a:	48 89 c8             	mov    rax,rcx
  2d534d:	48 2b 42 20          	sub    rax,QWORD PTR [rdx+0x20]
  2d5351:	48 83 7a 50 00       	cmp    QWORD PTR [rdx+0x50],0x0
  2d5356:	74 06                	je     0x2d535e
  2d5358:	48 8b 4b 58          	mov    rcx,QWORD PTR [rbx+0x58]
  2d535c:	eb 02                	jmp    0x2d5360
  2d535e:	31 c9                	xor    ecx,ecx
  2d5360:	48 8b 55 88          	mov    rdx,QWORD PTR [rbp-0x78]
  2d5364:	48 8b 7d 90          	mov    rdi,QWORD PTR [rbp-0x70]
  2d5368:	48 01 c8             	add    rax,rcx
  2d536b:	48 8b 75 c0          	mov    rsi,QWORD PTR [rbp-0x40]
  2d536f:	48 8b 4f 40          	mov    rcx,QWORD PTR [rdi+0x40]
  2d5373:	48 8b 52 30          	mov    rdx,QWORD PTR [rdx+0x30]
  2d5377:	48 89 4d 98          	mov    QWORD PTR [rbp-0x68],rcx
  2d537b:	48 8d 4a ff          	lea    rcx,[rdx-0x1]
  2d537f:	48 21 c1             	and    rcx,rax
  2d5382:	49 29 c8             	sub    r8,rcx
  2d5385:	4c 01 c2             	add    rdx,r8
  2d5388:	4c 89 45 c8          	mov    QWORD PTR [rbp-0x38],r8
  2d538c:	48 89 55 b8          	mov    QWORD PTR [rbp-0x48],rdx
  2d5390:	e8 1b e3 0e 00       	call   0x3c36b0
  2d5395:	4c 8b 75 c8          	mov    r14,QWORD PTR [rbp-0x38]
  2d5399:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
  2d539d:	0f 1f 00             	nop    DWORD PTR [rax]
  2d53a0:	49 89 dc             	mov    r12,rbx
  2d53a3:	48 8b 1b             	mov    rbx,QWORD PTR [rbx]
  2d53a6:	4c 39 fb             	cmp    rbx,r15
  2d53a9:	74 06                	je     0x2d53b1
  2d53ab:	4c 3b 73 28          	cmp    r14,QWORD PTR [rbx+0x28]
  2d53af:	72 ef                	jb     0x2d53a0
  2d53b1:	4c 8b 6d b8          	mov    r13,QWORD PTR [rbp-0x48]
  2d53b5:	4c 89 ff             	mov    rdi,r15
  2d53b8:	4c 89 f6             	mov    rsi,r14
  2d53bb:	48 89 d9             	mov    rcx,rbx
  2d53be:	4c 89 ea             	mov    rdx,r13
  2d53c1:	e8 fa 22 ff ff       	call   0x2c76c0
  2d53c6:	85 c0                	test   eax,eax
  2d53c8:	0f 85 cf 02 00 00    	jne    0x2d569d
  2d53ce:	48 8b 7d 98          	mov    rdi,QWORD PTR [rbp-0x68]
  2d53d2:	4c 8b 45 c0          	mov    r8,QWORD PTR [rbp-0x40]
  2d53d6:	4c 89 fe             	mov    rsi,r15
  2d53d9:	4c 89 f2             	mov    rdx,r14
  2d53dc:	4c 89 e9             	mov    rcx,r13
  2d53df:	e8 cc b7 22 00       	call   0x500bb0
  2d53e4:	4c 89 f2             	mov    rdx,r14
  2d53e7:	4d 3b 74 24 20       	cmp    r14,QWORD PTR [r12+0x20]
  2d53ec:	76 0f                	jbe    0x2d53fd
  2d53ee:	4c 89 ff             	mov    rdi,r15
  2d53f1:	4c 89 e6             	mov    rsi,r12
  2d53f4:	e8 e7 60 ff ff       	call   0x2cb4e0
  2d53f9:	48 8b 55 c8          	mov    rdx,QWORD PTR [rbp-0x38]
  2d53fd:	4c 8b 75 b8          	mov    r14,QWORD PTR [rbp-0x48]
  2d5401:	4c 89 bd 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],r15
  2d5408:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
  2d540f:	00 
  2d5410:	49 8b 44 24 28       	mov    rax,QWORD PTR [r12+0x28]
  2d5415:	4d 89 f5             	mov    r13,r14
  2d5418:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
  2d541c:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
  2d5423:	4c 39 f0             	cmp    rax,r14
  2d5426:	4c 0f 42 e8          	cmovb  r13,rax
  2d542a:	76 12                	jbe    0x2d543e
  2d542c:	4c 89 ff             	mov    rdi,r15
  2d542f:	4c 89 e6             	mov    rsi,r12
  2d5432:	4c 89 f2             	mov    rdx,r14
  2d5435:	e8 36 63 ff ff       	call   0x2cb770
  2d543a:	48 8b 55 c8          	mov    rdx,QWORD PTR [rbp-0x38]
  2d543e:	41 8b 8c 24 44 01 00 	mov    ecx,DWORD PTR [r12+0x144]
  2d5445:	00 
  2d5446:	41 0f b7 9c 24 48 01 	movzx  ebx,WORD PTR [r12+0x148]
  2d544d:	00 00 
  2d544f:	4c 89 e8             	mov    rax,r13
  2d5452:	4c 89 ff             	mov    rdi,r15
  2d5455:	49 89 d6             	mov    r14,rdx
  2d5458:	48 29 d0             	sub    rax,rdx
  2d545b:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
  2d545f:	89 4d a4             	mov    DWORD PTR [rbp-0x5c],ecx
  2d5462:	89 5d d4             	mov    DWORD PTR [rbp-0x2c],ebx
  2d5465:	e8 a6 1d ff ff       	call   0x2c7210
  2d546a:	4c 89 70 20          	mov    QWORD PTR [rax+0x20],r14
  2d546e:	4c 89 68 28          	mov    QWORD PTR [rax+0x28],r13
  2d5472:	48 c7 40 70 00 00 00 	mov    QWORD PTR [rax+0x70],0x0
  2d5479:	00 
  2d547a:	49 89 c7             	mov    r15,rax
  2d547d:	b9 00 00 80 00       	mov    ecx,0x800000
  2d5482:	49 8d bc 24 50 01 00 	lea    rdi,[r12+0x150]
  2d5489:	00 
  2d548a:	ba 20 00 00 00       	mov    edx,0x20
  2d548f:	4c 89 6d 80          	mov    QWORD PTR [rbp-0x80],r13
  2d5493:	41 8b 44 24 60       	mov    eax,DWORD PTR [r12+0x60]
  2d5498:	49 8d b7 50 01 00 00 	lea    rsi,[r15+0x150]
  2d549f:	21 c8                	and    eax,ecx
  2d54a1:	48 8b 4d 98          	mov    rcx,QWORD PTR [rbp-0x68]
  2d54a5:	0d 00 00 10 00       	or     eax,0x100000
  2d54aa:	41 89 47 60          	mov    DWORD PTR [r15+0x60],eax
  2d54ae:	48 8b 45 c0          	mov    rax,QWORD PTR [rbp-0x40]
  2d54b2:	49 89 4f 50          	mov    QWORD PTR [r15+0x50],rcx
  2d54b6:	49 89 47 58          	mov    QWORD PTR [r15+0x58],rax
  2d54ba:	49 c7 47 30 00 00 00 	mov    QWORD PTR [r15+0x30],0x0
  2d54c1:	00 
  2d54c2:	66 41 89 5f 64       	mov    WORD PTR [r15+0x64],bx
  2d54c7:	41 c7 47 66 f3 03 02 	mov    DWORD PTR [r15+0x66],0x30203f3
  2d54ce:	03 
  2d54cf:	41 c7 47 6c 00 00 00 	mov    DWORD PTR [r15+0x6c],0x0
  2d54d6:	00 
  2d54d7:	49 c7 47 78 00 00 00 	mov    QWORD PTR [r15+0x78],0x0
  2d54de:	00 
  2d54df:	4d 89 77 38          	mov    QWORD PTR [r15+0x38],r14
  2d54e3:	41 0f b6 84 24 4c 01 	movzx  eax,BYTE PTR [r12+0x14c]
  2d54ea:	00 00 
  2d54ec:	41 88 87 4c 01 00 00 	mov    BYTE PTR [r15+0x14c],al
  2d54f3:	41 0f b6 84 24 4d 01 	movzx  eax,BYTE PTR [r12+0x14d]
  2d54fa:	00 00 
  2d54fc:	41 88 87 4d 01 00 00 	mov    BYTE PTR [r15+0x14d],al
  2d5503:	e8 d8 46 f8 ff       	call   0x259be0
  2d5508:	41 0f b6 84 24 4e 01 	movzx  eax,BYTE PTR [r12+0x14e]
  2d550f:	00 00 
  2d5511:	48 8b 5d 88          	mov    rbx,QWORD PTR [rbp-0x78]
  2d5515:	44 8b 6d a4          	mov    r13d,DWORD PTR [rbp-0x5c]
  2d5519:	41 88 87 4e 01 00 00 	mov    BYTE PTR [r15+0x14e],al
  2d5520:	49 8b 84 24 30 01 00 	mov    rax,QWORD PTR [r12+0x130]
  2d5527:	00 
  2d5528:	49 89 87 30 01 00 00 	mov    QWORD PTR [r15+0x130],rax
  2d552f:	8b 45 d4             	mov    eax,DWORD PTR [rbp-0x2c]
  2d5532:	49 c7 87 20 01 00 00 	mov    QWORD PTR [r15+0x120],0x0
  2d5539:	00 00 00 00 
  2d553d:	49 89 9f 28 01 00 00 	mov    QWORD PTR [r15+0x128],rbx
  2d5544:	45 89 af 44 01 00 00 	mov    DWORD PTR [r15+0x144],r13d
  2d554b:	66 41 89 87 48 01 00 	mov    WORD PTR [r15+0x148],ax
  2d5552:	00 
  2d5553:	49 8b 84 24 38 01 00 	mov    rax,QWORD PTR [r12+0x138]
  2d555a:	00 
  2d555b:	49 89 87 38 01 00 00 	mov    QWORD PTR [r15+0x138],rax
  2d5562:	41 c7 87 40 01 00 00 	mov    DWORD PTR [r15+0x140],0x0
  2d5569:	00 00 00 00 
  2d556d:	49 8b 7f 50          	mov    rdi,QWORD PTR [r15+0x50]
  2d5571:	e8 aa c5 18 00       	call   0x461b20
  2d5576:	4c 8b 75 90          	mov    r14,QWORD PTR [rbp-0x70]
  2d557a:	4c 89 f7             	mov    rdi,r14
  2d557d:	e8 ae de 0e 00       	call   0x3c3430
  2d5582:	48 89 df             	mov    rdi,rbx
  2d5585:	e8 e6 49 0f 00       	call   0x3c9f70
  2d558a:	4c 89 f7             	mov    rdi,r14
  2d558d:	45 89 ee             	mov    r14d,r13d
  2d5590:	4c 8b ad 78 ff ff ff 	mov    r13,QWORD PTR [rbp-0x88]
  2d5597:	e8 e4 df 0e 00       	call   0x3c3580
  2d559c:	49 8b 1c 24          	mov    rbx,QWORD PTR [r12]
  2d55a0:	4c 89 e6             	mov    rsi,r12
  2d55a3:	44 8b 65 d4          	mov    r12d,DWORD PTR [rbp-0x2c]
  2d55a7:	4c 89 ef             	mov    rdi,r13
  2d55aa:	e8 81 a8 ff ff       	call   0x2cfe30
  2d55af:	4c 89 ef             	mov    rdi,r13
  2d55b2:	48 89 de             	mov    rsi,rbx
  2d55b5:	4c 89 fa             	mov    rdx,r15
  2d55b8:	e8 23 1d ff ff       	call   0x2c72e0
  2d55bd:	48 8b 45 a8          	mov    rax,QWORD PTR [rbp-0x58]
  2d55c1:	49 01 85 b8 01 00 00 	add    QWORD PTR [r13+0x1b8],rax
  2d55c8:	41 f7 c4 c7 03 00 00 	test   r12d,0x3c7
  2d55cf:	74 29                	je     0x2d55fa
  2d55d1:	49 8b 9d d8 01 00 00 	mov    rbx,QWORD PTR [r13+0x1d8]
  2d55d8:	44 89 f7             	mov    edi,r14d
  2d55db:	e8 00 01 00 00       	call   0x2d56e0
  2d55e0:	48 8b 75 c8          	mov    rsi,QWORD PTR [rbp-0x38]
  2d55e4:	48 8b 55 80          	mov    rdx,QWORD PTR [rbp-0x80]
  2d55e8:	48 8b 4d b0          	mov    rcx,QWORD PTR [rbp-0x50]
  2d55ec:	48 89 df             	mov    rdi,rbx
  2d55ef:	45 89 e0             	mov    r8d,r12d
  2d55f2:	41 89 c1             	mov    r9d,eax
  2d55f5:	e8 26 82 61 00       	call   0x8ed820
  2d55fa:	44 89 f7             	mov    edi,r14d
  2d55fd:	48 8b 5d c0          	mov    rbx,QWORD PTR [rbp-0x40]
  2d5601:	4c 8b 75 b8          	mov    r14,QWORD PTR [rbp-0x48]
  2d5605:	41 83 e4 30          	and    r12d,0x30
  2d5609:	74 44                	je     0x2d564f
  2d560b:	44 89 65 d4          	mov    DWORD PTR [rbp-0x2c],r12d
  2d560f:	e8 1c 01 00 00       	call   0x2d5730
  2d5614:	48 8b 0d cd 0c 7c 01 	mov    rcx,QWORD PTR [rip+0x17c0ccd]        # 0x1a962e8
  2d561b:	4c 8b 61 10          	mov    r12,QWORD PTR [rcx+0x10]
  2d561f:	48 8d 0d aa 92 f9 ff 	lea    rcx,[rip+0xfffffffffff992aa]        # 0x26e8d0
  2d5626:	49 39 cc             	cmp    r12,rcx
  2d5629:	75 57                	jne    0x2d5682
  2d562b:	48 8b 75 c8          	mov    rsi,QWORD PTR [rbp-0x38]
  2d562f:	48 8b 55 a8          	mov    rdx,QWORD PTR [rbp-0x58]
  2d5633:	48 8b 4d b0          	mov    rcx,QWORD PTR [rbp-0x50]
  2d5637:	44 8b 45 d4          	mov    r8d,DWORD PTR [rbp-0x2c]
  2d563b:	4c 89 ef             	mov    rdi,r13
  2d563e:	41 89 c1             	mov    r9d,eax
  2d5641:	c7 04 24 01 00 00 00 	mov    DWORD PTR [rsp],0x1
  2d5648:	41 ff d4             	call   r12
  2d564b:	85 c0                	test   eax,eax
  2d564d:	75 5d                	jne    0x2d56ac
  2d564f:	4c 89 ef             	mov    rdi,r13
  2d5652:	4c 89 fe             	mov    rsi,r15
  2d5655:	e8 b6 32 ff ff       	call   0x2c8910
  2d565a:	4c 3b b5 70 ff ff ff 	cmp    r14,QWORD PTR [rbp-0x90]
  2d5661:	76 38                	jbe    0x2d569b
  2d5663:	48 8b 45 a8          	mov    rax,QWORD PTR [rbp-0x58]
  2d5667:	4d 8b 67 08          	mov    r12,QWORD PTR [r15+0x8]
  2d566b:	48 8b 55 80          	mov    rdx,QWORD PTR [rbp-0x80]
  2d566f:	4d 89 ef             	mov    r15,r13
  2d5672:	48 01 45 b0          	add    QWORD PTR [rbp-0x50],rax
  2d5676:	48 01 c3             	add    rbx,rax
  2d5679:	48 89 5d c0          	mov    QWORD PTR [rbp-0x40],rbx
  2d567d:	e9 8e fd ff ff       	jmp    0x2d5410
  2d5682:	48 8d 3d 87 0a 7c 01 	lea    rdi,[rip+0x17c0a87]        # 0x1a96110
  2d5689:	4c 89 e6             	mov    rsi,r12
  2d568c:	89 c3                	mov    ebx,eax
  2d568e:	e8 2d a2 17 00       	call   0x44f8c0
  2d5693:	89 d8                	mov    eax,ebx
  2d5695:	48 8b 5d c0          	mov    rbx,QWORD PTR [rbp-0x40]
  2d5699:	eb 90                	jmp    0x2d562b
  2d569b:	31 c0                	xor    eax,eax
  2d569d:	48 83 c4 78          	add    rsp,0x78
  2d56a1:	5b                   	pop    rbx
  2d56a2:	41 5c                	pop    r12
  2d56a4:	41 5d                	pop    r13
  2d56a6:	41 5e                	pop    r14
  2d56a8:	41 5f                	pop    r15
  2d56aa:	5d                   	pop    rbp
  2d56ab:	c3                   	ret
  2d56ac:	89 c3                	mov    ebx,eax
  2d56ae:	e8 9d c2 51 00       	call   0x7f1950
  2d56b3:	48 63 f3             	movsxd rsi,ebx
  2d56b6:	48 8d 3d ef ff ff ff 	lea    rdi,[rip+0xffffffffffffffef]        # 0x2d56ac
  2d56bd:	e8 de c1 51 00       	call   0x7f18a0
  2d56c2:	48 8d 35 35 af 03 01 	lea    rsi,[rip+0x103af35]        # 0x13105fe
  2d56c9:	bf ab 00 00 00       	mov    edi,0xab
  2d56ce:	89 da                	mov    edx,ebx
  2d56d0:	31 c0                	xor    eax,eax
  2d56d2:	e8 39 53 9c 00       	call   0xc9aa10
  2d56d7:	0f 0b                	ud2
  2d56d9:	90                   	nop
  2d56da:	90                   	nop
  2d56db:	90                   	nop
  2d56dc:	90                   	nop
  2d56dd:	90                   	nop
  2d56de:	90                   	nop
  2d56df:	90                   	nop
  2d56e0:	83 ff 15             	cmp    edi,0x15
  2d56e3:	73 0d                	jae    0x2d56f2
  2d56e5:	89 f8                	mov    eax,edi
  2d56e7:	48 8d 0d d2 6a 0e 01 	lea    rcx,[rip+0x10e6ad2]        # 0x13bc1c0
  2d56ee:	8b 04 81             	mov    eax,DWORD PTR [rcx+rax*4]
  2d56f1:	c3                   	ret
  2d56f2:	55                   	push   rbp
  2d56f3:	48 89 e5             	mov    rbp,rsp
  2d56f6:	53                   	push   rbx
  2d56f7:	50                   	push   rax
  2d56f8:	89 fb                	mov    ebx,edi
  2d56fa:	e8 51 c2 51 00       	call   0x7f1950
  2d56ff:	48 63 f3             	movsxd rsi,ebx
  2d5702:	48 8d 3d e9 ff ff ff 	lea    rdi,[rip+0xffffffffffffffe9]        # 0x2d56f2
  2d5709:	e8 92 c1 51 00       	call   0x7f18a0
  2d570e:	48 8d 35 8d f0 fb 00 	lea    rsi,[rip+0xfbf08d]        # 0x12947a2
  2d5715:	bf 03 00 00 00       	mov    edi,0x3
  2d571a:	89 da                	mov    edx,ebx
  2d571c:	31 c0                	xor    eax,eax
  2d571e:	e8 ed 52 9c 00       	call   0xc9aa10
  2d5723:	0f 0b                	ud2
  2d5725:	90                   	nop
  2d5726:	90                   	nop
  2d5727:	90                   	nop
  2d5728:	90                   	nop
  2d5729:	90                   	nop
  2d572a:	90                   	nop
  2d572b:	90                   	nop
  2d572c:	90                   	nop
  2d572d:	90                   	nop
  2d572e:	90                   	nop
  2d572f:	90                   	nop
  2d5730:	83 ff 15             	cmp    edi,0x15
  2d5733:	73 0d                	jae    0x2d5742
  2d5735:	89 f8                	mov    eax,edi
  2d5737:	48 8d 0d d6 6a 0e 01 	lea    rcx,[rip+0x10e6ad6]        # 0x13bc214
  2d573e:	8b 04 81             	mov    eax,DWORD PTR [rcx+rax*4]
  2d5741:	c3                   	ret
  2d5742:	55                   	push   rbp
  2d5743:	48 89 e5             	mov    rbp,rsp
  2d5746:	53                   	push   rbx
  2d5747:	50                   	push   rax
  2d5748:	89 fb                	mov    ebx,edi
  2d574a:	e8 01 c2 51 00       	call   0x7f1950
  2d574f:	48 63 f3             	movsxd rsi,ebx
  2d5752:	48 8d 3d e9 ff ff ff 	lea    rdi,[rip+0xffffffffffffffe9]        # 0x2d5742
  2d5759:	e8 42 c1 51 00       	call   0x7f18a0
  2d575e:	48 8d 35 3d f0 fb 00 	lea    rsi,[rip+0xfbf03d]        # 0x12947a2
  2d5765:	bf 0b 00 00 00       	mov    edi,0xb
  2d576a:	89 da                	mov    edx,ebx
  2d576c:	31 c0                	xor    eax,eax
  2d576e:	e8 9d 52 9c 00       	call   0xc9aa10
  2d5773:	0f 0b                	ud2
  2d5775:	90                   	nop
  2d5776:	90                   	nop
  2d5777:	90                   	nop
  2d5778:	90                   	nop
  2d5779:	90                   	nop
  2d577a:	90                   	nop
  2d577b:	90                   	nop
  2d577c:	90                   	nop
  2d577d:	90                   	nop
  2d577e:	90                   	nop
  2d577f:	90                   	nop
  2d5780:	55                   	push   rbp
  2d5781:	48 89 e5             	mov    rbp,rsp
  2d5784:	41 57                	push   r15
  2d5786:	41 56                	push   r14
  2d5788:	41 55                	push   r13
  2d578a:	41 54                	push   r12
  2d578c:	53                   	push   rbx
  2d578d:	48 83 ec 78          	sub    rsp,0x78
  2d5791:	48 8d 05 78 6b 64 03 	lea    rax,[rip+0x3646b78]        # 0x391c310
  2d5798:	48 89 55 90          	mov    QWORD PTR [rbp-0x70],rdx
  2d579c:	49 89 f4             	mov    r12,rsi
  2d579f:	48 89 fb             	mov    rbx,rdi
  2d57a2:	48 8b 00             	mov    rax,QWORD PTR [rax]
  2d57a5:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  2d57a9:	0f b6 87 44 02 00 00 	movzx  eax,BYTE PTR [rdi+0x244]
  2d57b0:	a8 10                	test   al,0x10
  2d57b2:	75 29                	jne    0x2d57dd
  2d57b4:	a8 08                	test   al,0x8
  2d57b6:	74 11                	je     0x2d57c9
  2d57b8:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  2d57bf:	00 00 
  2d57c1:	f0 83 80 a8 05 00 00 	lock add DWORD PTR [rax+0x5a8],0x1
  2d57c8:	01 
  2d57c9:	48 8d bb 70 01 00 00 	lea    rdi,[rbx+0x170]
  2d57d0:	31 f6                	xor    esi,esi
  2d57d2:	31 d2                	xor    edx,edx
  2d57d4:	31 c9                	xor    ecx,ecx
  2d57d6:	e8 45 63 97 00       	call   0xc4bb20
  2d57db:	eb 12                	jmp    0x2d57ef
  2d57dd:	48 8d bb a8 01 00 00 	lea    rdi,[rbx+0x1a8]
  2d57e4:	31 f6                	xor    esi,esi
  2d57e6:	31 d2                	xor    edx,edx
  2d57e8:	31 c9                	xor    ecx,ecx
  2d57ea:	e8 11 12 1f 00       	call   0x4c6a00
  2d57ef:	ff 83 c0 01 00 00    	inc    DWORD PTR [rbx+0x1c0]
  2d57f5:	48 8d 55 a0          	lea    rdx,[rbp-0x60]
  2d57f9:	48 89 df             	mov    rdi,rbx
  2d57fc:	4c 89 e6             	mov    rsi,r12
  2d57ff:	f0 83 83 c4 01 00 00 	lock add DWORD PTR [rbx+0x1c4],0x1
  2d5806:	01 
  2d5807:	e8 34 14 ff ff       	call   0x2c6c40
  2d580c:	4c 8b 7d a0          	mov    r15,QWORD PTR [rbp-0x60]
  2d5810:	85 c0                	test   eax,eax
  2d5812:	75 08                	jne    0x2d581c
  2d5814:	4d 8b 7f 08          	mov    r15,QWORD PTR [r15+0x8]
  2d5818:	4c 89 7d a0          	mov    QWORD PTR [rbp-0x60],r15
  2d581c:	4c 8b 45 90          	mov    r8,QWORD PTR [rbp-0x70]
  2d5820:	49 39 df             	cmp    r15,rbx
  2d5823:	0f 84 12 02 00 00    	je     0x2d5a3b
  2d5829:	4c 89 f8             	mov    rax,r15
  2d582c:	eb 0b                	jmp    0x2d5839
  2d582e:	66 90                	xchg   ax,ax
  2d5830:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
  2d5834:	48 39 d8             	cmp    rax,rbx
  2d5837:	74 64                	je     0x2d589d
  2d5839:	48 8b 50 20          	mov    rdx,QWORD PTR [rax+0x20]
  2d583d:	4c 89 c1             	mov    rcx,r8
  2d5840:	48 29 d1             	sub    rcx,rdx
  2d5843:	76 58                	jbe    0x2d589d
  2d5845:	48 8b b0 28 01 00 00 	mov    rsi,QWORD PTR [rax+0x128]
  2d584c:	48 85 f6             	test   rsi,rsi
  2d584f:	74 df                	je     0x2d5830
  2d5851:	48 8b 78 50          	mov    rdi,QWORD PTR [rax+0x50]
  2d5855:	48 85 ff             	test   rdi,rdi
  2d5858:	74 d6                	je     0x2d5830
  2d585a:	f6 87 a2 00 00 00 01 	test   BYTE PTR [rdi+0xa2],0x1
  2d5861:	74 cd                	je     0x2d5830
  2d5863:	48 8b 76 30          	mov    rsi,QWORD PTR [rsi+0x30]
  2d5867:	4c 89 e7             	mov    rdi,r12
  2d586a:	48 29 d7             	sub    rdi,rdx
  2d586d:	76 09                	jbe    0x2d5878
  2d586f:	48 8d 56 ff          	lea    rdx,[rsi-0x1]
  2d5873:	48 85 fa             	test   rdx,rdi
  2d5876:	75 0e                	jne    0x2d5886
  2d5878:	4c 3b 40 28          	cmp    r8,QWORD PTR [rax+0x28]
  2d587c:	73 b2                	jae    0x2d5830
  2d587e:	48 ff ce             	dec    rsi
  2d5881:	48 85 ce             	test   rsi,rcx
  2d5884:	74 aa                	je     0x2d5830
  2d5886:	48 89 df             	mov    rdi,rbx
  2d5889:	31 f6                	xor    esi,esi
  2d588b:	31 d2                	xor    edx,edx
  2d588d:	e8 5e 0c ff ff       	call   0x2c64f0
  2d5892:	41 be 01 00 00 00    	mov    r14d,0x1
  2d5898:	e9 ad 01 00 00       	jmp    0x2d5a4a
  2d589d:	4c 89 7d a8          	mov    QWORD PTR [rbp-0x58],r15
  2d58a1:	48 89 5d 88          	mov    QWORD PTR [rbp-0x78],rbx
  2d58a5:	eb 3a                	jmp    0x2d58e1
  2d58a7:	49 8d b7 50 01 00 00 	lea    rsi,[r15+0x150]
  2d58ae:	ba 20 00 00 00       	mov    edx,0x20
  2d58b3:	48 8d 7d b0          	lea    rdi,[rbp-0x50]
  2d58b7:	e8 24 43 f8 ff       	call   0x259be0
  2d58bc:	48 89 df             	mov    rdi,rbx
  2d58bf:	4c 89 fe             	mov    rsi,r15
  2d58c2:	e8 49 30 ff ff       	call   0x2c8910
  2d58c7:	4c 8b 45 90          	mov    r8,QWORD PTR [rbp-0x70]
  2d58cb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]
  2d58d0:	4d 8b 7f 08          	mov    r15,QWORD PTR [r15+0x8]
  2d58d4:	4c 89 7d a8          	mov    QWORD PTR [rbp-0x58],r15
  2d58d8:	49 39 df             	cmp    r15,rbx
  2d58db:	0f 84 5a 01 00 00    	je     0x2d5a3b
  2d58e1:	4d 8b 6f 20          	mov    r13,QWORD PTR [r15+0x20]
  2d58e5:	4d 39 c5             	cmp    r13,r8
  2d58e8:	0f 83 4d 01 00 00    	jae    0x2d5a3b
  2d58ee:	4d 8b b7 28 01 00 00 	mov    r14,QWORD PTR [r15+0x128]
  2d58f5:	4d 85 f6             	test   r14,r14
  2d58f8:	74 d6                	je     0x2d58d0
  2d58fa:	49 8b 47 50          	mov    rax,QWORD PTR [r15+0x50]
  2d58fe:	48 85 c0             	test   rax,rax
  2d5901:	74 cd                	je     0x2d58d0
  2d5903:	f6 80 a2 00 00 00 01 	test   BYTE PTR [rax+0xa2],0x1
  2d590a:	74 c4                	je     0x2d58d0
  2d590c:	49 8b 46 10          	mov    rax,QWORD PTR [r14+0x10]
  2d5910:	45 8b 67 60          	mov    r12d,DWORD PTR [r15+0x60]
  2d5914:	49 8b 8f 30 01 00 00 	mov    rcx,QWORD PTR [r15+0x130]
  2d591b:	49 8b 5f 28          	mov    rbx,QWORD PTR [r15+0x28]
  2d591f:	ba 20 00 00 00       	mov    edx,0x20
  2d5924:	48 8d 75 b0          	lea    rsi,[rbp-0x50]
  2d5928:	48 89 45 98          	mov    QWORD PTR [rbp-0x68],rax
  2d592c:	41 8b 87 44 01 00 00 	mov    eax,DWORD PTR [r15+0x144]
  2d5933:	41 c1 ec 05          	shr    r12d,0x5
  2d5937:	48 89 8d 68 ff ff ff 	mov    QWORD PTR [rbp-0x98],rcx
  2d593e:	41 81 e4 00 00 04 00 	and    r12d,0x40000
  2d5945:	41 ff c4             	inc    r12d
  2d5948:	48 89 85 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rax
  2d594f:	41 0f b7 87 48 01 00 	movzx  eax,WORD PTR [r15+0x148]
  2d5956:	00 
  2d5957:	48 89 45 80          	mov    QWORD PTR [rbp-0x80],rax
  2d595b:	41 8b 87 38 01 00 00 	mov    eax,DWORD PTR [r15+0x138]
  2d5962:	49 81 c7 50 01 00 00 	add    r15,0x150
  2d5969:	4c 89 ff             	mov    rdi,r15
  2d596c:	48 89 85 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rax
  2d5973:	e8 68 42 f8 ff       	call   0x259be0
  2d5978:	4c 8b 7d 98          	mov    r15,QWORD PTR [rbp-0x68]
  2d597c:	4c 89 ff             	mov    rdi,r15
  2d597f:	e8 ac da 0e 00       	call   0x3c3430
  2d5984:	4c 89 f7             	mov    rdi,r14
  2d5987:	e8 e4 45 0f 00       	call   0x3c9f70
  2d598c:	4c 89 ff             	mov    rdi,r15
  2d598f:	e8 ec db 0e 00       	call   0x3c3580
  2d5994:	48 8b 7d 88          	mov    rdi,QWORD PTR [rbp-0x78]
  2d5998:	4c 89 ee             	mov    rsi,r13
  2d599b:	48 89 da             	mov    rdx,rbx
  2d599e:	e8 cd 39 ff ff       	call   0x2c9370
  2d59a3:	48 83 ec 08          	sub    rsp,0x8
  2d59a7:	48 89 5d 98          	mov    QWORD PTR [rbp-0x68],rbx
  2d59ab:	49 89 d8             	mov    r8,rbx
  2d59ae:	48 8b 5d 88          	mov    rbx,QWORD PTR [rbp-0x78]
  2d59b2:	48 8b 7d 88          	mov    rdi,QWORD PTR [rbp-0x78]
  2d59b6:	31 f6                	xor    esi,esi
  2d59b8:	31 d2                	xor    edx,edx
  2d59ba:	4c 89 e9             	mov    rcx,r13
  2d59bd:	45 31 c9             	xor    r9d,r9d
  2d59c0:	ff 75 80             	push   QWORD PTR [rbp-0x80]
  2d59c3:	ff b5 78 ff ff ff    	push   QWORD PTR [rbp-0x88]
  2d59c9:	41 56                	push   r14
  2d59cb:	ff b5 70 ff ff ff    	push   QWORD PTR [rbp-0x90]
  2d59d1:	ff b5 68 ff ff ff    	push   QWORD PTR [rbp-0x98]
  2d59d7:	41 54                	push   r12
  2d59d9:	6a 00                	push   0x0
  2d59db:	e8 10 20 ff ff       	call   0x2c79f0
  2d59e0:	48 83 c4 40          	add    rsp,0x40
  2d59e4:	48 89 df             	mov    rdi,rbx
  2d59e7:	4c 89 ee             	mov    rsi,r13
  2d59ea:	48 8d 55 a8          	lea    rdx,[rbp-0x58]
  2d59ee:	e8 4d 12 ff ff       	call   0x2c6c40
  2d59f3:	85 c0                	test   eax,eax
  2d59f5:	74 75                	je     0x2d5a6c
  2d59f7:	80 7d b0 00          	cmp    BYTE PTR [rbp-0x50],0x0
  2d59fb:	4c 8b 7d a8          	mov    r15,QWORD PTR [rbp-0x58]
  2d59ff:	4c 8b 45 90          	mov    r8,QWORD PTR [rbp-0x70]
  2d5a03:	0f 84 c7 fe ff ff    	je     0x2d58d0
  2d5a09:	4d 3b 6f 20          	cmp    r13,QWORD PTR [r15+0x20]
  2d5a0d:	76 0e                	jbe    0x2d5a1d
  2d5a0f:	48 89 df             	mov    rdi,rbx
  2d5a12:	4c 89 fe             	mov    rsi,r15
  2d5a15:	4c 89 ea             	mov    rdx,r13
  2d5a18:	e8 c3 5a ff ff       	call   0x2cb4e0
  2d5a1d:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
  2d5a21:	49 3b 57 28          	cmp    rdx,QWORD PTR [r15+0x28]
  2d5a25:	0f 83 7c fe ff ff    	jae    0x2d58a7
  2d5a2b:	48 89 df             	mov    rdi,rbx
  2d5a2e:	4c 89 fe             	mov    rsi,r15
  2d5a31:	e8 3a 5d ff ff       	call   0x2cb770
  2d5a36:	e9 6c fe ff ff       	jmp    0x2d58a7
  2d5a3b:	48 89 df             	mov    rdi,rbx
  2d5a3e:	45 31 f6             	xor    r14d,r14d
  2d5a41:	31 f6                	xor    esi,esi
  2d5a43:	31 d2                	xor    edx,edx
  2d5a45:	e8 a6 0a ff ff       	call   0x2c64f0
  2d5a4a:	48 8d 05 bf 68 64 03 	lea    rax,[rip+0x36468bf]        # 0x391c310
  2d5a51:	48 8b 00             	mov    rax,QWORD PTR [rax]
  2d5a54:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  2d5a58:	75 48                	jne    0x2d5aa2
  2d5a5a:	44 89 f0             	mov    eax,r14d
  2d5a5d:	48 83 c4 78          	add    rsp,0x78
  2d5a61:	5b                   	pop    rbx
  2d5a62:	41 5c                	pop    r12
  2d5a64:	41 5d                	pop    r13
  2d5a66:	41 5e                	pop    r14
  2d5a68:	41 5f                	pop    r15
  2d5a6a:	5d                   	pop    rbp
  2d5a6b:	c3                   	ret
  2d5a6c:	e8 df be 51 00       	call   0x7f1950
  2d5a71:	48 8b 5d 98          	mov    rbx,QWORD PTR [rbp-0x68]
  2d5a75:	48 8d 3d f0 ff ff ff 	lea    rdi,[rip+0xfffffffffffffff0]        # 0x2d5a6c
  2d5a7c:	4c 89 ee             	mov    rsi,r13
  2d5a7f:	48 89 da             	mov    rdx,rbx
  2d5a82:	e8 89 c5 51 00       	call   0x7f2010
  2d5a87:	48 8d 35 ed d6 fd 00 	lea    rsi,[rip+0xfdd6ed]        # 0x12b317b
  2d5a8e:	bf af 00 00 00       	mov    edi,0xaf
  2d5a93:	4c 89 ea             	mov    rdx,r13
  2d5a96:	48 89 d9             	mov    rcx,rbx
  2d5a99:	31 c0                	xor    eax,eax
  2d5a9b:	e8 70 4f 9c 00       	call   0xc9aa10
  2d5aa0:	0f 0b                	ud2
  2d5aa2:	e8 09 7c 42 00       	call   0x6fd6b0
  2d5aa7:	0f 0b                	ud2
  2d5aa9:	90                   	nop
  2d5aaa:	90                   	nop
  2d5aab:	90                   	nop
  2d5aac:	90                   	nop
  2d5aad:	90                   	nop
  2d5aae:	90                   	nop
  2d5aaf:	90                   	nop
  2d5ab0:	55                   	push   rbp
  2d5ab1:	48 89 e5             	mov    rbp,rsp
  2d5ab4:	41 56                	push   r14
  2d5ab6:	53                   	push   rbx
  2d5ab7:	89 fb                	mov    ebx,edi
  2d5ab9:	48 8d 3d 68 a5 a8 02 	lea    rdi,[rip+0x2a8a568]        # 0x2d60028
  2d5ac0:	31 f6                	xor    esi,esi
  2d5ac2:	31 d2                	xor    edx,edx
  2d5ac4:	31 c9                	xor    ecx,ecx
  2d5ac6:	e8 35 0f 1f 00       	call   0x4c6a00
  2d5acb:	48 63 05 5e af a8 02 	movsxd rax,DWORD PTR [rip+0x2a8af5e]        # 0x2d60a30
  2d5ad2:	48 8d 0d 57 a5 a8 02 	lea    rcx,[rip+0x2a8a557]        # 0x2d60030
  2d5ad9:	48 8d 04 80          	lea    rax,[rax+rax*4]
  2d5add:	48 c1 e0 07          	shl    rax,0x7
  2d5ae1:	83 3c 08 00          	cmp    DWORD PTR [rax+rcx*1],0x0
  2d5ae5:	4c 8d 34 01          	lea    r14,[rcx+rax*1]
  2d5ae9:	74 37                	je     0x2d5b22
  2d5aeb:	41 83 be a0 00 00 00 	cmp    DWORD PTR [r14+0xa0],0x0
  2d5af2:	00 
  2d5af3:	74 1d                	je     0x2d5b12
  2d5af5:	41 83 be 40 01 00 00 	cmp    DWORD PTR [r14+0x140],0x0
  2d5afc:	00 
  2d5afd:	74 1c                	je     0x2d5b1b
  2d5aff:	41 83 be e0 01 00 00 	cmp    DWORD PTR [r14+0x1e0],0x0
  2d5b06:	00 
  2d5b07:	75 28                	jne    0x2d5b31
  2d5b09:	49 81 c6 e0 01 00 00 	add    r14,0x1e0
  2d5b10:	eb 10                	jmp    0x2d5b22
  2d5b12:	49 81 c6 a0 00 00 00 	add    r14,0xa0
  2d5b19:	eb 07                	jmp    0x2d5b22
  2d5b1b:	49 81 c6 40 01 00 00 	add    r14,0x140
  2d5b22:	4c 89 f7             	mov    rdi,r14
  2d5b25:	e8 76 ef 33 00       	call   0x614aa0
  2d5b2a:	41 89 9e 98 00 00 00 	mov    DWORD PTR [r14+0x98],ebx
  2d5b31:	48 8d 3d f0 a4 a8 02 	lea    rdi,[rip+0x2a8a4f0]        # 0x2d60028
  2d5b38:	31 f6                	xor    esi,esi
  2d5b3a:	31 d2                	xor    edx,edx
  2d5b3c:	31 c9                	xor    ecx,ecx
  2d5b3e:	5b                   	pop    rbx
  2d5b3f:	41 5e                	pop    r14
  2d5b41:	5d                   	pop    rbp
  2d5b42:	e9 59 14 1f 00       	jmp    0x4c6fa0
  2d5b47:	90                   	nop
  2d5b48:	90                   	nop
  2d5b49:	90                   	nop
  2d5b4a:	90                   	nop
  2d5b4b:	90                   	nop
  2d5b4c:	90                   	nop
  2d5b4d:	90                   	nop
  2d5b4e:	90                   	nop
  2d5b4f:	90                   	nop
  2d5b50:	85 ff                	test   edi,edi
  2d5b52:	75 11                	jne    0x2d5b65
  2d5b54:	b8 01 00 00 00       	mov    eax,0x1
  2d5b59:	f0 0f c1 05 d3 ae a8 	lock xadd DWORD PTR [rip+0x2a8aed3],eax        # 0x2d60a34
  2d5b60:	02 
  2d5b61:	85 c0                	test   eax,eax
  2d5b63:	74 01                	je     0x2d5b66
  2d5b65:	c3                   	ret
  2d5b66:	55                   	push   rbp
  2d5b67:	48 89 e5             	mov    rbp,rsp
  2d5b6a:	e8 21 ae 7f 00       	call   0xad0990
  2d5b6f:	48 89 c1             	mov    rcx,rax
  2d5b72:	0f 31                	rdtsc
  2d5b74:	89 c0                	mov    eax,eax
  2d5b76:	48 c1 e2 20          	shl    rdx,0x20
  2d5b7a:	48 09 d0             	or     rax,rdx
  2d5b7d:	48 09 ca             	or     rdx,rcx
  2d5b80:	48 c1 ea 20          	shr    rdx,0x20
  2d5b84:	74 0a                	je     0x2d5b90
  2d5b86:	31 d2                	xor    edx,edx
  2d5b88:	48 f7 f1             	div    rcx
  2d5b8b:	48 89 c6             	mov    rsi,rax
  2d5b8e:	eb 06                	jmp    0x2d5b96
  2d5b90:	31 d2                	xor    edx,edx
  2d5b92:	f7 f1                	div    ecx
  2d5b94:	89 c6                	mov    esi,eax
  2d5b96:	48 69 c2 e8 03 00 00 	imul   rax,rdx,0x3e8
  2d5b9d:	48 89 ca             	mov    rdx,rcx
  2d5ba0:	48 09 c2             	or     rdx,rax
  2d5ba3:	48 c1 ea 20          	shr    rdx,0x20
  2d5ba7:	74 07                	je     0x2d5bb0
  2d5ba9:	31 d2                	xor    edx,edx
  2d5bab:	48 f7 f1             	div    rcx
  2d5bae:	eb 04                	jmp    0x2d5bb4
  2d5bb0:	31 d2                	xor    edx,edx
  2d5bb2:	f7 f1                	div    ecx
  2d5bb4:	48 89 c2             	mov    rdx,rax
  2d5bb7:	48 8d 3d 6a fe 04 01 	lea    rdi,[rip+0x104fe6a]        # 0x1325a28
  2d5bbe:	31 c0                	xor    eax,eax
  2d5bc0:	e8 4b 78 f8 ff       	call   0x25d410
  2d5bc5:	5d                   	pop    rbp
  2d5bc6:	e9 65 c6 21 00       	jmp    0x4f2230
  2d5bcb:	90                   	nop
  2d5bcc:	90                   	nop
  2d5bcd:	90                   	nop
  2d5bce:	90                   	nop
  2d5bcf:	90                   	nop
  2d5bd0:	55                   	push   rbp
  2d5bd1:	48 89 e5             	mov    rbp,rsp
  2d5bd4:	41 57                	push   r15
  2d5bd6:	41 56                	push   r14
  2d5bd8:	41 55                	push   r13
  2d5bda:	41 54                	push   r12
  2d5bdc:	53                   	push   rbx
  2d5bdd:	48 83 ec 18          	sub    rsp,0x18
  2d5be1:	4c 8d 3d 28 67 64 03 	lea    r15,[rip+0x3646728]        # 0x391c310
  2d5be8:	48 89 cb             	mov    rbx,rcx
  2d5beb:	31 c9                	xor    ecx,ecx
  2d5bed:	4c 8d 35 74 28 a8 02 	lea    r14,[rip+0x2a82874]        # 0x2d58468
  2d5bf4:	4c 8d 2d 75 28 a8 02 	lea    r13,[rip+0x2a82875]        # 0x2d58470
  2d5bfb:	4c 89 f7             	mov    rdi,r14
  2d5bfe:	49 8b 07             	mov    rax,QWORD PTR [r15]
  2d5c01:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  2d5c05:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  2d5c0c:	00 00 
  2d5c0e:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
  2d5c12:	8b 80 c0 05 00 00    	mov    eax,DWORD PTR [rax+0x5c0]
  2d5c18:	83 f8 0a             	cmp    eax,0xa
  2d5c1b:	0f 44 c1             	cmove  eax,ecx
  2d5c1e:	31 f6                	xor    esi,esi
  2d5c20:	31 d2                	xor    edx,edx
  2d5c22:	31 c9                	xor    ecx,ecx
  2d5c24:	4c 63 e0             	movsxd r12,eax
  2d5c27:	49 c1 e4 06          	shl    r12,0x6
  2d5c2b:	e8 d0 0d 1f 00       	call   0x4c6a00
  2d5c30:	4b 8b 44 2c 10       	mov    rax,QWORD PTR [r12+r13*1+0x10]
  2d5c35:	4b 2b 44 2c 18       	sub    rax,QWORD PTR [r12+r13*1+0x18]
  2d5c3a:	4c 89 f7             	mov    rdi,r14
  2d5c3d:	31 f6                	xor    esi,esi
  2d5c3f:	31 d2                	xor    edx,edx
  2d5c41:	31 c9                	xor    ecx,ecx
  2d5c43:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
  2d5c47:	e8 54 13 1f 00       	call   0x4c6fa0
  2d5c4c:	4c 8b 73 28          	mov    r14,QWORD PTR [rbx+0x28]
  2d5c50:	48 8d 05 e1 36 f9 ff 	lea    rax,[rip+0xfffffffffff936e1]        # 0x269338
  2d5c57:	4c 29 f0             	sub    rax,r14
  2d5c5a:	48 c1 c8 03          	ror    rax,0x3
  2d5c5e:	48 83 f8 03          	cmp    rax,0x3
  2d5c62:	77 27                	ja     0x2d5c8b
  2d5c64:	48 8d 75 c8          	lea    rsi,[rbp-0x38]
  2d5c68:	ba 08 00 00 00       	mov    edx,0x8
  2d5c6d:	48 89 df             	mov    rdi,rbx
  2d5c70:	41 ff d6             	call   r14
  2d5c73:	49 8b 0f             	mov    rcx,QWORD PTR [r15]
  2d5c76:	48 3b 4d d0          	cmp    rcx,QWORD PTR [rbp-0x30]
  2d5c7a:	75 20                	jne    0x2d5c9c
  2d5c7c:	48 83 c4 18          	add    rsp,0x18
  2d5c80:	5b                   	pop    rbx
  2d5c81:	41 5c                	pop    r12
  2d5c83:	41 5d                	pop    r13
  2d5c85:	41 5e                	pop    r14
  2d5c87:	41 5f                	pop    r15
  2d5c89:	5d                   	pop    rbp
  2d5c8a:	c3                   	ret
  2d5c8b:	48 8d 3d 1e 05 7c 01 	lea    rdi,[rip+0x17c051e]        # 0x1a961b0
  2d5c92:	4c 89 f6             	mov    rsi,r14
  2d5c95:	e8 26 9c 17 00       	call   0x44f8c0
  2d5c9a:	eb c8                	jmp    0x2d5c64
  2d5c9c:	e8 0f 7a 42 00       	call   0x6fd6b0
  2d5ca1:	0f 0b                	ud2
  2d5ca3:	90                   	nop
  2d5ca4:	90                   	nop
  2d5ca5:	90                   	nop
  2d5ca6:	90                   	nop
  2d5ca7:	90                   	nop
  2d5ca8:	90                   	nop
  2d5ca9:	90                   	nop
  2d5caa:	90                   	nop
  2d5cab:	90                   	nop
  2d5cac:	90                   	nop
  2d5cad:	90                   	nop
  2d5cae:	90                   	nop
  2d5caf:	90                   	nop
  2d5cb0:	55                   	push   rbp
  2d5cb1:	48 89 e5             	mov    rbp,rsp
  2d5cb4:	41 57                	push   r15
  2d5cb6:	41 56                	push   r14
  2d5cb8:	41 55                	push   r13
  2d5cba:	41 54                	push   r12
  2d5cbc:	53                   	push   rbx
  2d5cbd:	48 83 ec 18          	sub    rsp,0x18
  2d5cc1:	4c 8d 3d 48 66 64 03 	lea    r15,[rip+0x3646648]        # 0x391c310
  2d5cc8:	48 89 cb             	mov    rbx,rcx
  2d5ccb:	31 c9                	xor    ecx,ecx
  2d5ccd:	4c 8d 35 94 27 a8 02 	lea    r14,[rip+0x2a82794]        # 0x2d58468
  2d5cd4:	4c 8d 2d 95 27 a8 02 	lea    r13,[rip+0x2a82795]        # 0x2d58470
  2d5cdb:	4c 89 f7             	mov    rdi,r14
  2d5cde:	49 8b 07             	mov    rax,QWORD PTR [r15]
  2d5ce1:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  2d5ce5:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  2d5cec:	00 00 
  2d5cee:	48 8b 40 08          	mov    rax,QWORD PTR [rax+0x8]
  2d5cf2:	8b 80 c0 05 00 00    	mov    eax,DWORD PTR [rax+0x5c0]
  2d5cf8:	83 f8 0a             	cmp    eax,0xa
  2d5cfb:	0f 44 c1             	cmove  eax,ecx
  2d5cfe:	31 f6                	xor    esi,esi
  2d5d00:	31 d2                	xor    edx,edx
  2d5d02:	31 c9                	xor    ecx,ecx
  2d5d04:	4c 63 e0             	movsxd r12,eax
  2d5d07:	49 c1 e4 06          	shl    r12,0x6
  2d5d0b:	e8 f0 0c 1f 00       	call   0x4c6a00
  2d5d10:	4b 8b 44 2c 10       	mov    rax,QWORD PTR [r12+r13*1+0x10]
  2d5d15:	4c 89 f7             	mov    rdi,r14
  2d5d18:	31 f6                	xor    esi,esi
  2d5d1a:	31 d2                	xor    edx,edx
  2d5d1c:	31 c9                	xor    ecx,ecx
  2d5d1e:	48 89 45 c8          	mov    QWORD PTR [rbp-0x38],rax
  2d5d22:	e8 79 12 1f 00       	call   0x4c6fa0
  2d5d27:	4c 8b 73 28          	mov    r14,QWORD PTR [rbx+0x28]
  2d5d2b:	48 8d 05 06 36 f9 ff 	lea    rax,[rip+0xfffffffffff93606]        # 0x269338
  2d5d32:	4c 29 f0             	sub    rax,r14
  2d5d35:	48 c1 c8 03          	ror    rax,0x3
  2d5d39:	48 83 f8 03          	cmp    rax,0x3
  2d5d3d:	77 27                	ja     0x2d5d66
  2d5d3f:	48 8d 75 c8          	lea    rsi,[rbp-0x38]
  2d5d43:	ba 08 00 00 00       	mov    edx,0x8
  2d5d48:	48 89 df             	mov    rdi,rbx
  2d5d4b:	41 ff d6             	call   r14
  2d5d4e:	49 8b 0f             	mov    rcx,QWORD PTR [r15]
  2d5d51:	48 3b 4d d0          	cmp    rcx,QWORD PTR [rbp-0x30]
  2d5d55:	75 20                	jne    0x2d5d77
  2d5d57:	48 83 c4 18          	add    rsp,0x18
  2d5d5b:	5b                   	pop    rbx
  2d5d5c:	41 5c                	pop    r12
  2d5d5e:	41 5d                	pop    r13
  2d5d60:	41 5e                	pop    r14
  2d5d62:	41 5f                	pop    r15
  2d5d64:	5d                   	pop    rbp
  2d5d65:	c3                   	ret
  2d5d66:	48 8d 3d 63 04 7c 01 	lea    rdi,[rip+0x17c0463]        # 0x1a961d0
  2d5d6d:	4c 89 f6             	mov    rsi,r14
  2d5d70:	e8 4b 9b 17 00       	call   0x44f8c0
  2d5d75:	eb c8                	jmp    0x2d5d3f
  2d5d77:	e8 34 79 42 00       	call   0x6fd6b0
  2d5d7c:	0f 0b                	ud2
  2d5d7e:	90                   	nop
  2d5d7f:	90                   	nop
  2d5d80:	55                   	push   rbp
  2d5d81:	48 89 e5             	mov    rbp,rsp
  2d5d84:	b8 13 00 00 00       	mov    eax,0x13
  2d5d89:	5d                   	pop    rbp
  2d5d8a:	c3                   	ret
  2d5d8b:	90                   	nop
  2d5d8c:	90                   	nop
  2d5d8d:	90                   	nop
  2d5d8e:	90                   	nop
  2d5d8f:	90                   	nop
  2d5d90:	55                   	push   rbp
  2d5d91:	48 89 e5             	mov    rbp,rsp
  2d5d94:	41 57                	push   r15
  2d5d96:	41 56                	push   r14
  2d5d98:	41 54                	push   r12
  2d5d9a:	53                   	push   rbx
  2d5d9b:	48 83 ec 20          	sub    rsp,0x20
  2d5d9f:	4c 8d 3d 6a 65 64 03 	lea    r15,[rip+0x364656a]        # 0x391c310
  2d5da6:	49 89 fe             	mov    r14,rdi
  2d5da9:	48 89 f7             	mov    rdi,rsi
  2d5dac:	48 8d 55 c8          	lea    rdx,[rbp-0x38]
  2d5db0:	48 8d 4d c0          	lea    rcx,[rbp-0x40]
  2d5db4:	4c 89 f6             	mov    rsi,r14
  2d5db7:	49 8b 07             	mov    rax,QWORD PTR [r15]
  2d5dba:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
  2d5dbe:	e8 ed aa 22 00       	call   0x5008b0
  2d5dc3:	49 8b 5e 10          	mov    rbx,QWORD PTR [r14+0x10]
  2d5dc7:	48 8b 75 c8          	mov    rsi,QWORD PTR [rbp-0x38]
  2d5dcb:	4c 8b 65 c0          	mov    r12,QWORD PTR [rbp-0x40]
  2d5dcf:	45 8b 76 18          	mov    r14d,DWORD PTR [r14+0x18]
  2d5dd3:	48 8d 55 d0          	lea    rdx,[rbp-0x30]
  2d5dd7:	48 89 df             	mov    rdi,rbx
  2d5dda:	e8 61 0e ff ff       	call   0x2c6c40
  2d5ddf:	48 8b 4d d0          	mov    rcx,QWORD PTR [rbp-0x30]
  2d5de3:	85 c0                	test   eax,eax
  2d5de5:	75 08                	jne    0x2d5def
  2d5de7:	48 8b 49 08          	mov    rcx,QWORD PTR [rcx+0x8]
  2d5deb:	48 89 4d d0          	mov    QWORD PTR [rbp-0x30],rcx
  2d5def:	b0 01                	mov    al,0x1
  2d5df1:	eb 11                	jmp    0x2d5e04
  2d5df3:	66 66 66 66 2e 0f 1f 	data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  2d5dfa:	84 00 00 00 00 00 
  2d5e00:	48 8b 49 08          	mov    rcx,QWORD PTR [rcx+0x8]
  2d5e04:	48 39 d9             	cmp    rcx,rbx
  2d5e07:	74 17                	je     0x2d5e20
  2d5e09:	4c 39 61 20          	cmp    QWORD PTR [rcx+0x20],r12
  2d5e0d:	73 11                	jae    0x2d5e20
  2d5e0f:	f6 41 62 10          	test   BYTE PTR [rcx+0x62],0x10
  2d5e13:	74 eb                	je     0x2d5e00
  2d5e15:	0f b7 51 64          	movzx  edx,WORD PTR [rcx+0x64]
  2d5e19:	41 85 d6             	test   r14d,edx
  2d5e1c:	74 e2                	je     0x2d5e00
  2d5e1e:	31 c0                	xor    eax,eax
  2d5e20:	49 8b 0f             	mov    rcx,QWORD PTR [r15]
  2d5e23:	48 3b 4d d8          	cmp    rcx,QWORD PTR [rbp-0x28]
  2d5e27:	75 0d                	jne    0x2d5e36
  2d5e29:	48 83 c4 20          	add    rsp,0x20
  2d5e2d:	5b                   	pop    rbx
  2d5e2e:	41 5c                	pop    r12
  2d5e30:	41 5e                	pop    r14
  2d5e32:	41 5f                	pop    r15
  2d5e34:	5d                   	pop    rbp
  2d5e35:	c3                   	ret
  2d5e36:	e8 75 78 42 00       	call   0x6fd6b0
  2d5e3b:	0f 0b                	ud2
  2d5e3d:	90                   	nop
  2d5e3e:	90                   	nop
  2d5e3f:	90                   	nop
  2d5e40:	55                   	push   rbp
  2d5e41:	48 89 e5             	mov    rbp,rsp
  2d5e44:	31 c0                	xor    eax,eax
  2d5e46:	5d                   	pop    rbp
  2d5e47:	c3                   	ret
  2d5e48:	90                   	nop
  2d5e49:	90                   	nop
  2d5e4a:	90                   	nop
  2d5e4b:	90                   	nop
  2d5e4c:	90                   	nop
  2d5e4d:	90                   	nop
  2d5e4e:	90                   	nop
  2d5e4f:	90                   	nop
  2d5e50:	55                   	push   rbp
  2d5e51:	48 89 e5             	mov    rbp,rsp
  2d5e54:	48 8b 17             	mov    rdx,QWORD PTR [rdi]
  2d5e57:	48 85 d2             	test   rdx,rdx
  2d5e5a:	74 58                	je     0x2d5eb4
  2d5e5c:	48 8b 4e 30          	mov    rcx,QWORD PTR [rsi+0x30]
  2d5e60:	eb 16                	jmp    0x2d5e78
  2d5e62:	66 66 66 66 66 2e 0f 	data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  2d5e69:	1f 84 00 00 00 00 00 
  2d5e70:	48 8b 10             	mov    rdx,QWORD PTR [rax]
  2d5e73:	48 85 d2             	test   rdx,rdx
  2d5e76:	74 63                	je     0x2d5edb
  2d5e78:	48 89 d0             	mov    rax,rdx
  2d5e7b:	48 3b 4a 30          	cmp    rcx,QWORD PTR [rdx+0x30]
  2d5e7f:	72 ef                	jb     0x2d5e70
  2d5e81:	0f 84 54 02 00 00    	je     0x2d60db
  2d5e87:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
  2d5e8b:	48 85 d2             	test   rdx,rdx
  2d5e8e:	75 e8                	jne    0x2d5e78
  2d5e90:	48 89 46 10          	mov    QWORD PTR [rsi+0x10],rax
  2d5e94:	48 c7 46 08 00 00 00 	mov    QWORD PTR [rsi+0x8],0x0
  2d5e9b:	00 
  2d5e9c:	48 c7 06 00 00 00 00 	mov    QWORD PTR [rsi],0x0
  2d5ea3:	c7 46 18 01 00 00 00 	mov    DWORD PTR [rsi+0x18],0x1
  2d5eaa:	48 8d 4e 10          	lea    rcx,[rsi+0x10]
  2d5eae:	48 89 70 08          	mov    QWORD PTR [rax+0x8],rsi
  2d5eb2:	eb 48                	jmp    0x2d5efc
  2d5eb4:	48 8d 4e 10          	lea    rcx,[rsi+0x10]
  2d5eb8:	48 c7 46 10 00 00 00 	mov    QWORD PTR [rsi+0x10],0x0
  2d5ebf:	00 
  2d5ec0:	48 c7 46 08 00 00 00 	mov    QWORD PTR [rsi+0x8],0x0
  2d5ec7:	00 
  2d5ec8:	48 c7 06 00 00 00 00 	mov    QWORD PTR [rsi],0x0
  2d5ecf:	c7 46 18 01 00 00 00 	mov    DWORD PTR [rsi+0x18],0x1
  2d5ed6:	48 89 37             	mov    QWORD PTR [rdi],rsi
  2d5ed9:	eb 21                	jmp    0x2d5efc
  2d5edb:	48 89 46 10          	mov    QWORD PTR [rsi+0x10],rax
  2d5edf:	48 c7 46 08 00 00 00 	mov    QWORD PTR [rsi+0x8],0x0
  2d5ee6:	00 
  2d5ee7:	48 c7 06 00 00 00 00 	mov    QWORD PTR [rsi],0x0
  2d5eee:	c7 46 18 01 00 00 00 	mov    DWORD PTR [rsi+0x18],0x1
  2d5ef5:	48 8d 4e 10          	lea    rcx,[rsi+0x10]
  2d5ef9:	48 89 30             	mov    QWORD PTR [rax],rsi
  2d5efc:	48 8b 01             	mov    rax,QWORD PTR [rcx]
  2d5eff:	eb 2e                	jmp    0x2d5f2f
  2d5f01:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  2d5f08:	0f 1f 84 00 00 00 00 
  2d5f0f:	00 
  2d5f10:	c7 42 18 00 00 00 00 	mov    DWORD PTR [rdx+0x18],0x0
  2d5f17:	c7 40 18 00 00 00 00 	mov    DWORD PTR [rax+0x18],0x0
  2d5f1e:	48 89 c8             	mov    rax,rcx
  2d5f21:	c7 41 18 01 00 00 00 	mov    DWORD PTR [rcx+0x18],0x1
  2d5f28:	48 89 c6             	mov    rsi,rax
  2d5f2b:	48 8b 40 10          	mov    rax,QWORD PTR [rax+0x10]
  2d5f2f:	48 85 c0             	test   rax,rax
  2d5f32:	0f 84 99 01 00 00    	je     0x2d60d1
  2d5f38:	83 78 18 01          	cmp    DWORD PTR [rax+0x18],0x1
  2d5f3c:	0f 85 8f 01 00 00    	jne    0x2d60d1
  2d5f42:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
  2d5f46:	48 8b 11             	mov    rdx,QWORD PTR [rcx]
  2d5f49:	48 39 d0             	cmp    rax,rdx
  2d5f4c:	74 22                	je     0x2d5f70
  2d5f4e:	48 85 d2             	test   rdx,rdx
  2d5f51:	74 06                	je     0x2d5f59
  2d5f53:	83 7a 18 01          	cmp    DWORD PTR [rdx+0x18],0x1
  2d5f57:	74 b7                	je     0x2d5f10
  2d5f59:	48 8b 10             	mov    rdx,QWORD PTR [rax]
  2d5f5c:	48 39 f2             	cmp    rdx,rsi
  2d5f5f:	74 32                	je     0x2d5f93
  2d5f61:	48 89 c2             	mov    rdx,rax
  2d5f64:	48 89 f0             	mov    rax,rsi
  2d5f67:	e9 a6 00 00 00       	jmp    0x2d6012
  2d5f6c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  2d5f70:	48 8b 51 08          	mov    rdx,QWORD PTR [rcx+0x8]
  2d5f74:	48 85 d2             	test   rdx,rdx
  2d5f77:	74 06                	je     0x2d5f7f
  2d5f79:	83 7a 18 01          	cmp    DWORD PTR [rdx+0x18],0x1
  2d5f7d:	74 91                	je     0x2d5f10
  2d5f7f:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
  2d5f83:	48 39 f2             	cmp    rdx,rsi
  2d5f86:	74 33                	je     0x2d5fbb
  2d5f88:	48 89 c2             	mov    rdx,rax
  2d5f8b:	48 89 f0             	mov    rax,rsi
  2d5f8e:	e9 f0 00 00 00       	jmp    0x2d6083
  2d5f93:	4c 8b 42 08          	mov    r8,QWORD PTR [rdx+0x8]
  2d5f97:	4c 89 00             	mov    QWORD PTR [rax],r8
  2d5f9a:	4d 85 c0             	test   r8,r8
  2d5f9d:	74 53                	je     0x2d5ff2
  2d5f9f:	49 89 40 10          	mov    QWORD PTR [r8+0x10],rax
  2d5fa3:	4c 8b 40 10          	mov    r8,QWORD PTR [rax+0x10]
  2d5fa7:	4c 89 42 10          	mov    QWORD PTR [rdx+0x10],r8
  2d5fab:	4d 85 c0             	test   r8,r8
  2d5fae:	74 54                	je     0x2d6004
  2d5fb0:	49 3b 00             	cmp    rax,QWORD PTR [r8]
  2d5fb3:	74 4a                	je     0x2d5fff
  2d5fb5:	49 89 50 08          	mov    QWORD PTR [r8+0x8],rdx
  2d5fb9:	eb 4c                	jmp    0x2d6007
  2d5fbb:	4c 8b 02             	mov    r8,QWORD PTR [rdx]
  2d5fbe:	4c 89 40 08          	mov    QWORD PTR [rax+0x8],r8
  2d5fc2:	4d 85 c0             	test   r8,r8
  2d5fc5:	0f 84 95 00 00 00    	je     0x2d6060
  2d5fcb:	49 89 40 10          	mov    QWORD PTR [r8+0x10],rax
  2d5fcf:	4c 8b 40 10          	mov    r8,QWORD PTR [rax+0x10]
  2d5fd3:	4c 89 42 10          	mov    QWORD PTR [rdx+0x10],r8
  2d5fd7:	4d 85 c0             	test   r8,r8
  2d5fda:	0f 84 96 00 00 00    	je     0x2d6076
  2d5fe0:	49 3b 00             	cmp    rax,QWORD PTR [r8]
  2d5fe3:	0f 84 88 00 00 00    	je     0x2d6071
  2d5fe9:	49 89 50 08          	mov    QWORD PTR [r8+0x8],rdx
  2d5fed:	e9 87 00 00 00       	jmp    0x2d6079
  2d5ff2:	48 89 4a 10          	mov    QWORD PTR [rdx+0x10],rcx
  2d5ff6:	4c 8b 40 10          	mov    r8,QWORD PTR [rax+0x10]
  2d5ffa:	49 3b 00             	cmp    rax,QWORD PTR [r8]
  2d5ffd:	75 b6                	jne    0x2d5fb5
  2d5fff:	49 89 10             	mov    QWORD PTR [r8],rdx
  2d6002:	eb 03                	jmp    0x2d6007
  2d6004:	48 89 17             	mov    QWORD PTR [rdi],rdx
  2d6007:	48 89 42 08          	mov    QWORD PTR [rdx+0x8],rax
  2d600b:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
  2d600f:	48 89 f2             	mov    rdx,rsi
  2d6012:	c7 42 18 00 00 00 00 	mov    DWORD PTR [rdx+0x18],0x0
  2d6019:	c7 41 18 01 00 00 00 	mov    DWORD PTR [rcx+0x18],0x1
  2d6020:	48 8b 51 08          	mov    rdx,QWORD PTR [rcx+0x8]
  2d6024:	48 8b 32             	mov    rsi,QWORD PTR [rdx]
  2d6027:	48 89 71 08          	mov    QWORD PTR [rcx+0x8],rsi
  2d602b:	48 85 f6             	test   rsi,rsi
  2d602e:	74 04                	je     0x2d6034
  2d6030:	48 89 4e 10          	mov    QWORD PTR [rsi+0x10],rcx
  2d6034:	48 8b 71 10          	mov    rsi,QWORD PTR [rcx+0x10]
  2d6038:	48 89 72 10          	mov    QWORD PTR [rdx+0x10],rsi
  2d603c:	48 85 f6             	test   rsi,rsi
  2d603f:	74 0b                	je     0x2d604c
  2d6041:	48 3b 0e             	cmp    rcx,QWORD PTR [rsi]
  2d6044:	74 0b                	je     0x2d6051
  2d6046:	48 89 56 08          	mov    QWORD PTR [rsi+0x8],rdx
  2d604a:	eb 08                	jmp    0x2d6054
  2d604c:	48 89 17             	mov    QWORD PTR [rdi],rdx
  2d604f:	eb 03                	jmp    0x2d6054
  2d6051:	48 89 16             	mov    QWORD PTR [rsi],rdx
  2d6054:	48 89 0a             	mov    QWORD PTR [rdx],rcx
  2d6057:	48 89 51 10          	mov    QWORD PTR [rcx+0x10],rdx
  2d605b:	e9 c8 fe ff ff       	jmp    0x2d5f28
  2d6060:	48 89 4a 10          	mov    QWORD PTR [rdx+0x10],rcx
  2d6064:	4c 8b 40 10          	mov    r8,QWORD PTR [rax+0x10]
  2d6068:	49 3b 00             	cmp    rax,QWORD PTR [r8]
  2d606b:	0f 85 78 ff ff ff    	jne    0x2d5fe9
  2d6071:	49 89 10             	mov    QWORD PTR [r8],rdx
  2d6074:	eb 03                	jmp    0x2d6079
  2d6076:	48 89 17             	mov    QWORD PTR [rdi],rdx
  2d6079:	48 89 02             	mov    QWORD PTR [rdx],rax
  2d607c:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
  2d6080:	48 89 f2             	mov    rdx,rsi
  2d6083:	c7 42 18 00 00 00 00 	mov    DWORD PTR [rdx+0x18],0x0
  2d608a:	c7 41 18 01 00 00 00 	mov    DWORD PTR [rcx+0x18],0x1
  2d6091:	48 8b 11             	mov    rdx,QWORD PTR [rcx]
  2d6094:	48 8b 72 08          	mov    rsi,QWORD PTR [rdx+0x8]
  2d6098:	48 89 31             	mov    QWORD PTR [rcx],rsi
  2d609b:	48 85 f6             	test   rsi,rsi
  2d609e:	74 04                	je     0x2d60a4
  2d60a0:	48 89 4e 10          	mov    QWORD PTR [rsi+0x10],rcx
  2d60a4:	48 8b 71 10          	mov    rsi,QWORD PTR [rcx+0x10]
  2d60a8:	48 89 72 10          	mov    QWORD PTR [rdx+0x10],rsi
  2d60ac:	48 85 f6             	test   rsi,rsi
  2d60af:	74 0b                	je     0x2d60bc
  2d60b1:	48 3b 0e             	cmp    rcx,QWORD PTR [rsi]
  2d60b4:	74 0b                	je     0x2d60c1
  2d60b6:	48 89 56 08          	mov    QWORD PTR [rsi+0x8],rdx
  2d60ba:	eb 08                	jmp    0x2d60c4
  2d60bc:	48 89 17             	mov    QWORD PTR [rdi],rdx
  2d60bf:	eb 03                	jmp    0x2d60c4
  2d60c1:	48 89 16             	mov    QWORD PTR [rsi],rdx
  2d60c4:	48 89 4a 08          	mov    QWORD PTR [rdx+0x8],rcx
  2d60c8:	48 89 51 10          	mov    QWORD PTR [rcx+0x10],rdx
  2d60cc:	e9 57 fe ff ff       	jmp    0x2d5f28
  2d60d1:	48 8b 07             	mov    rax,QWORD PTR [rdi]
  2d60d4:	c7 40 18 00 00 00 00 	mov    DWORD PTR [rax+0x18],0x0
  2d60db:	5d                   	pop    rbp
  2d60dc:	c3                   	ret
  2d60dd:	90                   	nop
  2d60de:	90                   	nop
  2d60df:	90                   	nop
  2d60e0:	55                   	push   rbp
  2d60e1:	48 89 e5             	mov    rbp,rsp
  2d60e4:	48 8b 0e             	mov    rcx,QWORD PTR [rsi]
  2d60e7:	4c 8b 4e 08          	mov    r9,QWORD PTR [rsi+0x8]
  2d60eb:	48 89 f0             	mov    rax,rsi
  2d60ee:	48 85 c9             	test   rcx,rcx
  2d60f1:	74 3d                	je     0x2d6130
  2d60f3:	4d 85 c9             	test   r9,r9
  2d60f6:	74 49                	je     0x2d6141
  2d60f8:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
  2d60ff:	00 
  2d6100:	4d 89 c8             	mov    r8,r9
  2d6103:	4d 8b 09             	mov    r9,QWORD PTR [r9]
  2d6106:	4d 85 c9             	test   r9,r9
  2d6109:	75 f5                	jne    0x2d6100
  2d610b:	49 8b 48 08          	mov    rcx,QWORD PTR [r8+0x8]
  2d610f:	49 8b 50 10          	mov    rdx,QWORD PTR [r8+0x10]
  2d6113:	41 8b 70 18          	mov    esi,DWORD PTR [r8+0x18]
  2d6117:	48 85 c9             	test   rcx,rcx
  2d611a:	74 04                	je     0x2d6120
  2d611c:	48 89 51 10          	mov    QWORD PTR [rcx+0x10],rdx
  2d6120:	48 85 d2             	test   rdx,rdx
  2d6123:	74 37                	je     0x2d615c
  2d6125:	4c 39 02             	cmp    QWORD PTR [rdx],r8
  2d6128:	74 4a                	je     0x2d6174
  2d612a:	48 89 4a 08          	mov    QWORD PTR [rdx+0x8],rcx
  2d612e:	eb 47                	jmp    0x2d6177
  2d6130:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
  2d6134:	8b 70 18             	mov    esi,DWORD PTR [rax+0x18]
  2d6137:	4d 85 c9             	test   r9,r9
  2d613a:	74 2a                	je     0x2d6166
  2d613c:	4c 89 c9             	mov    rcx,r9
  2d613f:	eb 07                	jmp    0x2d6148
  2d6141:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
  2d6145:	8b 70 18             	mov    esi,DWORD PTR [rax+0x18]
  2d6148:	48 89 51 10          	mov    QWORD PTR [rcx+0x10],rdx
  2d614c:	48 85 d2             	test   rdx,rdx
  2d614f:	74 1c                	je     0x2d616d
  2d6151:	48 39 02             	cmp    QWORD PTR [rdx],rax
  2d6154:	74 0b                	je     0x2d6161
  2d6156:	48 89 4a 08          	mov    QWORD PTR [rdx+0x8],rcx
  2d615a:	eb 71                	jmp    0x2d61cd
  2d615c:	48 89 0f             	mov    QWORD PTR [rdi],rcx
  2d615f:	eb 16                	jmp    0x2d6177
  2d6161:	48 89 0a             	mov    QWORD PTR [rdx],rcx
  2d6164:	eb 67                	jmp    0x2d61cd
  2d6166:	31 c9                	xor    ecx,ecx
  2d6168:	48 85 d2             	test   rdx,rdx
  2d616b:	75 e4                	jne    0x2d6151
  2d616d:	31 d2                	xor    edx,edx
  2d616f:	48 89 0f             	mov    QWORD PTR [rdi],rcx
  2d6172:	eb 59                	jmp    0x2d61cd
  2d6174:	48 89 0a             	mov    QWORD PTR [rdx],rcx
  2d6177:	4c 8b 48 18          	mov    r9,QWORD PTR [rax+0x18]
  2d617b:	49 39 40 10          	cmp    QWORD PTR [r8+0x10],rax
  2d617f:	4d 89 48 18          	mov    QWORD PTR [r8+0x18],r9
  2d6183:	4c 8b 48 10          	mov    r9,QWORD PTR [rax+0x10]
  2d6187:	49 0f 44 d0          	cmove  rdx,r8
  2d618b:	4d 89 48 10          	mov    QWORD PTR [r8+0x10],r9
  2d618f:	4c 8b 08             	mov    r9,QWORD PTR [rax]
  2d6192:	4c 8b 50 08          	mov    r10,QWORD PTR [rax+0x8]
  2d6196:	4d 89 50 08          	mov    QWORD PTR [r8+0x8],r10
  2d619a:	4d 89 08             	mov    QWORD PTR [r8],r9
  2d619d:	4c 8b 48 10          	mov    r9,QWORD PTR [rax+0x10]
  2d61a1:	4d 85 c9             	test   r9,r9
  2d61a4:	74 0b                	je     0x2d61b1
  2d61a6:	49 39 01             	cmp    QWORD PTR [r9],rax
  2d61a9:	74 0b                	je     0x2d61b6
  2d61ab:	4d 89 41 08          	mov    QWORD PTR [r9+0x8],r8
  2d61af:	eb 08                	jmp    0x2d61b9
  2d61b1:	4c 89 07             	mov    QWORD PTR [rdi],r8
  2d61b4:	eb 03                	jmp    0x2d61b9
  2d61b6:	4d 89 01             	mov    QWORD PTR [r9],r8
  2d61b9:	4c 8b 08             	mov    r9,QWORD PTR [rax]
  2d61bc:	4d 89 41 10          	mov    QWORD PTR [r9+0x10],r8
  2d61c0:	4c 8b 48 08          	mov    r9,QWORD PTR [rax+0x8]
  2d61c4:	4d 85 c9             	test   r9,r9
  2d61c7:	74 04                	je     0x2d61cd
  2d61c9:	4d 89 41 10          	mov    QWORD PTR [r9+0x10],r8
  2d61cd:	85 f6                	test   esi,esi
  2d61cf:	74 1a                	je     0x2d61eb
  2d61d1:	5d                   	pop    rbp
  2d61d2:	c3                   	ret
  2d61d3:	66 66 66 66 2e 0f 1f 	data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  2d61da:	84 00 00 00 00 00 
  2d61e0:	c7 42 18 01 00 00 00 	mov    DWORD PTR [rdx+0x18],0x1
  2d61e7:	48 8b 51 10          	mov    rdx,QWORD PTR [rcx+0x10]
  2d61eb:	48 89 ce             	mov    rsi,rcx
  2d61ee:	48 89 d1             	mov    rcx,rdx
  2d61f1:	48 85 f6             	test   rsi,rsi
  2d61f4:	74 0a                	je     0x2d6200
  2d61f6:	83 7e 18 00          	cmp    DWORD PTR [rsi+0x18],0x0
  2d61fa:	0f 85 3b 02 00 00    	jne    0x2d643b
  2d6200:	48 3b 37             	cmp    rsi,QWORD PTR [rdi]
  2d6203:	0f 84 29 02 00 00    	je     0x2d6432
  2d6209:	48 8b 11             	mov    rdx,QWORD PTR [rcx]
  2d620c:	48 39 f2             	cmp    rdx,rsi
  2d620f:	74 4f                	je     0x2d6260
  2d6211:	83 7a 18 01          	cmp    DWORD PTR [rdx+0x18],0x1
  2d6215:	0f 85 a0 00 00 00    	jne    0x2d62bb
  2d621b:	c7 42 18 00 00 00 00 	mov    DWORD PTR [rdx+0x18],0x0
  2d6222:	c7 41 18 01 00 00 00 	mov    DWORD PTR [rcx+0x18],0x1
  2d6229:	48 8b 11             	mov    rdx,QWORD PTR [rcx]
  2d622c:	48 8b 72 08          	mov    rsi,QWORD PTR [rdx+0x8]
  2d6230:	48 89 31             	mov    QWORD PTR [rcx],rsi
  2d6233:	48 85 f6             	test   rsi,rsi
  2d6236:	74 04                	je     0x2d623c
  2d6238:	48 89 4e 10          	mov    QWORD PTR [rsi+0x10],rcx
  2d623c:	48 8b 71 10          	mov    rsi,QWORD PTR [rcx+0x10]
  2d6240:	48 89 72 10          	mov    QWORD PTR [rdx+0x10],rsi
  2d6244:	48 85 f6             	test   rsi,rsi
  2d6247:	74 5f                	je     0x2d62a8
  2d6249:	48 3b 0e             	cmp    rcx,QWORD PTR [rsi]
  2d624c:	74 5f                	je     0x2d62ad
  2d624e:	48 89 56 08          	mov    QWORD PTR [rsi+0x8],rdx
  2d6252:	eb 5c                	jmp    0x2d62b0
  2d6254:	66 66 66 2e 0f 1f 84 	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  2d625b:	00 00 00 00 00 
  2d6260:	48 8b 51 08          	mov    rdx,QWORD PTR [rcx+0x8]
  2d6264:	83 7a 18 01          	cmp    DWORD PTR [rdx+0x18],0x1
  2d6268:	0f 85 8c 00 00 00    	jne    0x2d62fa
  2d626e:	c7 42 18 00 00 00 00 	mov    DWORD PTR [rdx+0x18],0x0
  2d6275:	c7 41 18 01 00 00 00 	mov    DWORD PTR [rcx+0x18],0x1
  2d627c:	48 8b 51 08          	mov    rdx,QWORD PTR [rcx+0x8]
  2d6280:	48 8b 32             	mov    rsi,QWORD PTR [rdx]
  2d6283:	48 89 71 08          	mov    QWORD PTR [rcx+0x8],rsi
  2d6287:	48 85 f6             	test   rsi,rsi
  2d628a:	74 04                	je     0x2d6290
  2d628c:	48 89 4e 10          	mov    QWORD PTR [rsi+0x10],rcx
  2d6290:	48 8b 71 10          	mov    rsi,QWORD PTR [rcx+0x10]
  2d6294:	48 89 72 10          	mov    QWORD PTR [rdx+0x10],rsi
  2d6298:	48 85 f6             	test   rsi,rsi
  2d629b:	74 4a                	je     0x2d62e7
  2d629d:	48 3b 0e             	cmp    rcx,QWORD PTR [rsi]
  2d62a0:	74 4a                	je     0x2d62ec
  2d62a2:	48 89 56 08          	mov    QWORD PTR [rsi+0x8],rdx
  2d62a6:	eb 47                	jmp    0x2d62ef
  2d62a8:	48 89 17             	mov    QWORD PTR [rdi],rdx
  2d62ab:	eb 03                	jmp    0x2d62b0
  2d62ad:	48 89 16             	mov    QWORD PTR [rsi],rdx
  2d62b0:	48 89 4a 08          	mov    QWORD PTR [rdx+0x8],rcx
  2d62b4:	48 89 51 10          	mov    QWORD PTR [rcx+0x10],rdx
  2d62b8:	48 8b 11             	mov    rdx,QWORD PTR [rcx]
  2d62bb:	48 8b 32             	mov    rsi,QWORD PTR [rdx]
  2d62be:	48 85 f6             	test   rsi,rsi
  2d62c1:	74 0a                	je     0x2d62cd
  2d62c3:	83 7e 18 00          	cmp    DWORD PTR [rsi+0x18],0x0
  2d62c7:	0f 85 0b 01 00 00    	jne    0x2d63d8
  2d62cd:	4c 8b 42 08          	mov    r8,QWORD PTR [rdx+0x8]
  2d62d1:	4d 85 c0             	test   r8,r8
  2d62d4:	0f 84 06 ff ff ff    	je     0x2d61e0
  2d62da:	41 83 78 18 00       	cmp    DWORD PTR [r8+0x18],0x0
  2d62df:	0f 84 fb fe ff ff    	je     0x2d61e0
  2d62e5:	eb 3d                	jmp    0x2d6324
  2d62e7:	48 89 17             	mov    QWORD PTR [rdi],rdx
  2d62ea:	eb 03                	jmp    0x2d62ef
  2d62ec:	48 89 16             	mov    QWORD PTR [rsi],rdx
  2d62ef:	48 89 0a             	mov    QWORD PTR [rdx],rcx
  2d62f2:	48 89 51 10          	mov    QWORD PTR [rcx+0x10],rdx
  2d62f6:	48 8b 51 08          	mov    rdx,QWORD PTR [rcx+0x8]
  2d62fa:	48 8b 32             	mov    rsi,QWORD PTR [rdx]
  2d62fd:	48 85 f6             	test   rsi,rsi
  2d6300:	74 06                	je     0x2d6308
  2d6302:	83 7e 18 00          	cmp    DWORD PTR [rsi+0x18],0x0
  2d6306:	75 66                	jne    0x2d636e
  2d6308:	48 8b 72 08          	mov    rsi,QWORD PTR [rdx+0x8]
  2d630c:	48 85 f6             	test   rsi,rsi
  2d630f:	0f 84 cb fe ff ff    	je     0x2d61e0
  2d6315:	83 7e 18 00          	cmp    DWORD PTR [rsi+0x18],0x0
  2d6319:	0f 84 c1 fe ff ff    	je     0x2d61e0
  2d631f:	e9 34 01 00 00       	jmp    0x2d6458
  2d6324:	48 85 f6             	test   rsi,rsi
  2d6327:	74 0a                	je     0x2d6333
  2d6329:	83 7e 18 00          	cmp    DWORD PTR [rsi+0x18],0x0
  2d632d:	0f 85 a5 00 00 00    	jne    0x2d63d8
  2d6333:	41 c7 40 18 00 00 00 	mov    DWORD PTR [r8+0x18],0x0
  2d633a:	00 
  2d633b:	48 8b 72 08          	mov    rsi,QWORD PTR [rdx+0x8]
  2d633f:	c7 42 18 01 00 00 00 	mov    DWORD PTR [rdx+0x18],0x1
  2d6346:	4c 8b 06             	mov    r8,QWORD PTR [rsi]
  2d6349:	4c 89 42 08          	mov    QWORD PTR [rdx+0x8],r8
  2d634d:	4d 85 c0             	test   r8,r8
  2d6350:	74 04                	je     0x2d6356
  2d6352:	49 89 50 10          	mov    QWORD PTR [r8+0x10],rdx
  2d6356:	4c 8b 42 10          	mov    r8,QWORD PTR [rdx+0x10]
  2d635a:	4c 89 46 10          	mov    QWORD PTR [rsi+0x10],r8
  2d635e:	4d 85 c0             	test   r8,r8
  2d6361:	74 63                	je     0x2d63c6
  2d6363:	49 3b 10             	cmp    rdx,QWORD PTR [r8]
  2d6366:	74 63                	je     0x2d63cb
  2d6368:	49 89 70 08          	mov    QWORD PTR [r8+0x8],rsi
  2d636c:	eb 60                	jmp    0x2d63ce
  2d636e:	4c 8b 42 08          	mov    r8,QWORD PTR [rdx+0x8]
  2d6372:	4d 85 c0             	test   r8,r8
  2d6375:	74 0b                	je     0x2d6382
  2d6377:	41 83 78 18 00       	cmp    DWORD PTR [r8+0x18],0x0
  2d637c:	0f 85 d6 00 00 00    	jne    0x2d6458
  2d6382:	c7 46 18 00 00 00 00 	mov    DWORD PTR [rsi+0x18],0x0
  2d6389:	48 8b 32             	mov    rsi,QWORD PTR [rdx]
  2d638c:	c7 42 18 01 00 00 00 	mov    DWORD PTR [rdx+0x18],0x1
  2d6393:	4c 8b 46 08          	mov    r8,QWORD PTR [rsi+0x8]
  2d6397:	4c 89 02             	mov    QWORD PTR [rdx],r8
  2d639a:	4d 85 c0             	test   r8,r8
  2d639d:	74 04                	je     0x2d63a3
  2d639f:	49 89 50 10          	mov    QWORD PTR [r8+0x10],rdx
  2d63a3:	4c 8b 42 10          	mov    r8,QWORD PTR [rdx+0x10]
  2d63a7:	4c 89 46 10          	mov    QWORD PTR [rsi+0x10],r8
  2d63ab:	4d 85 c0             	test   r8,r8
  2d63ae:	0f 84 90 00 00 00    	je     0x2d6444
  2d63b4:	49 3b 10             	cmp    rdx,QWORD PTR [r8]
  2d63b7:	0f 84 8c 00 00 00    	je     0x2d6449
  2d63bd:	49 89 70 08          	mov    QWORD PTR [r8+0x8],rsi
  2d63c1:	e9 86 00 00 00       	jmp    0x2d644c
  2d63c6:	48 89 37             	mov    QWORD PTR [rdi],rsi
  2d63c9:	eb 03                	jmp    0x2d63ce
  2d63cb:	49 89 30             	mov    QWORD PTR [r8],rsi
  2d63ce:	48 89 16             	mov    QWORD PTR [rsi],rdx
  2d63d1:	48 89 72 10          	mov    QWORD PTR [rdx+0x10],rsi
  2d63d5:	48 8b 11             	mov    rdx,QWORD PTR [rcx]
  2d63d8:	8b 71 18             	mov    esi,DWORD PTR [rcx+0x18]
  2d63db:	89 72 18             	mov    DWORD PTR [rdx+0x18],esi
  2d63de:	c7 41 18 00 00 00 00 	mov    DWORD PTR [rcx+0x18],0x0
  2d63e5:	48 8b 12             	mov    rdx,QWORD PTR [rdx]
  2d63e8:	48 85 d2             	test   rdx,rdx
  2d63eb:	74 07                	je     0x2d63f4
  2d63ed:	c7 42 18 00 00 00 00 	mov    DWORD PTR [rdx+0x18],0x0
  2d63f4:	48 8b 11             	mov    rdx,QWORD PTR [rcx]
  2d63f7:	48 8b 72 08          	mov    rsi,QWORD PTR [rdx+0x8]
  2d63fb:	48 89 31             	mov    QWORD PTR [rcx],rsi
  2d63fe:	48 85 f6             	test   rsi,rsi
  2d6401:	74 04                	je     0x2d6407
  2d6403:	48 89 4e 10          	mov    QWORD PTR [rsi+0x10],rcx
  2d6407:	48 8b 71 10          	mov    rsi,QWORD PTR [rcx+0x10]
  2d640b:	48 89 72 10          	mov    QWORD PTR [rdx+0x10],rsi
  2d640f:	48 85 f6             	test   rsi,rsi
  2d6412:	74 0b                	je     0x2d641f
  2d6414:	48 3b 0e             	cmp    rcx,QWORD PTR [rsi]
  2d6417:	74 0b                	je     0x2d6424
  2d6419:	48 89 56 08          	mov    QWORD PTR [rsi+0x8],rdx
  2d641d:	eb 08                	jmp    0x2d6427
  2d641f:	48 89 17             	mov    QWORD PTR [rdi],rdx
  2d6422:	eb 03                	jmp    0x2d6427
  2d6424:	48 89 16             	mov    QWORD PTR [rsi],rdx
  2d6427:	48 89 4a 08          	mov    QWORD PTR [rdx+0x8],rcx
  2d642b:	48 89 51 10          	mov    QWORD PTR [rcx+0x10],rdx
  2d642f:	48 8b 37             	mov    rsi,QWORD PTR [rdi]
  2d6432:	48 85 f6             	test   rsi,rsi
  2d6435:	0f 84 96 fd ff ff    	je     0x2d61d1
  2d643b:	c7 46 18 00 00 00 00 	mov    DWORD PTR [rsi+0x18],0x0
  2d6442:	5d                   	pop    rbp
  2d6443:	c3                   	ret
  2d6444:	48 89 37             	mov    QWORD PTR [rdi],rsi
  2d6447:	eb 03                	jmp    0x2d644c
  2d6449:	49 89 30             	mov    QWORD PTR [r8],rsi
  2d644c:	48 89 56 08          	mov    QWORD PTR [rsi+0x8],rdx
  2d6450:	48 89 72 10          	mov    QWORD PTR [rdx+0x10],rsi
  2d6454:	48 8b 51 08          	mov    rdx,QWORD PTR [rcx+0x8]
  2d6458:	8b 71 18             	mov    esi,DWORD PTR [rcx+0x18]
  2d645b:	89 72 18             	mov    DWORD PTR [rdx+0x18],esi
  2d645e:	c7 41 18 00 00 00 00 	mov    DWORD PTR [rcx+0x18],0x0
  2d6465:	48 8b 52 08          	mov    rdx,QWORD PTR [rdx+0x8]
  2d6469:	48 85 d2             	test   rdx,rdx
  2d646c:	74 07                	je     0x2d6475
  2d646e:	c7 42 18 00 00 00 00 	mov    DWORD PTR [rdx+0x18],0x0
  2d6475:	48 8b 51 08          	mov    rdx,QWORD PTR [rcx+0x8]
  2d6479:	48 8b 32             	mov    rsi,QWORD PTR [rdx]
  2d647c:	48 89 71 08          	mov    QWORD PTR [rcx+0x8],rsi
  2d6480:	48 85 f6             	test   rsi,rsi
  2d6483:	74 04                	je     0x2d6489
  2d6485:	48 89 4e 10          	mov    QWORD PTR [rsi+0x10],rcx
  2d6489:	48 8b 71 10          	mov    rsi,QWORD PTR [rcx+0x10]
  2d648d:	48 89 72 10          	mov    QWORD PTR [rdx+0x10],rsi
  2d6491:	48 85 f6             	test   rsi,rsi
  2d6494:	74 0e                	je     0x2d64a4
  2d6496:	48 3b 0e             	cmp    rcx,QWORD PTR [rsi]
  2d6499:	74 14                	je     0x2d64af
  2d649b:	48 89 56 08          	mov    QWORD PTR [rsi+0x8],rdx
  2d649f:	48 89 0a             	mov    QWORD PTR [rdx],rcx
  2d64a2:	eb 87                	jmp    0x2d642b
  2d64a4:	48 89 17             	mov    QWORD PTR [rdi],rdx
  2d64a7:	48 89 0a             	mov    QWORD PTR [rdx],rcx
  2d64aa:	e9 7c ff ff ff       	jmp    0x2d642b
  2d64af:	48 89 16             	mov    QWORD PTR [rsi],rdx
  2d64b2:	48 89 0a             	mov    QWORD PTR [rdx],rcx
  2d64b5:	e9 71 ff ff ff       	jmp    0x2d642b
  2d64ba:	90                   	nop
  2d64bb:	90                   	nop
  2d64bc:	90                   	nop
  2d64bd:	90                   	nop
  2d64be:	90                   	nop
  2d64bf:	90                   	nop
  2d64c0:	55                   	push   rbp
  2d64c1:	48 89 e5             	mov    rbp,rsp
  2d64c4:	41 57                	push   r15
  2d64c6:	41 56                	push   r14
  2d64c8:	41 55                	push   r13
  2d64ca:	41 54                	push   r12
  2d64cc:	53                   	push   rbx
  2d64cd:	50                   	push   rax
  2d64ce:	80 a6 40 01 00 00 fc 	and    BYTE PTR [rsi+0x140],0xfc
  2d64d5:	49 89 f6             	mov    r14,rsi
  2d64d8:	48 89 fb             	mov    rbx,rdi
  2d64db:	0f b7 86 4a 01 00 00 	movzx  eax,WORD PTR [rsi+0x14a]
  2d64e2:	44 0f b7 66 64       	movzx  r12d,WORD PTR [rsi+0x64]
  2d64e7:	66 89 46 64          	mov    WORD PTR [rsi+0x64],ax
  2d64eb:	44 0f b7 f8          	movzx  r15d,ax
  2d64ef:	f6 87 44 02 00 00 01 	test   BYTE PTR [rdi+0x244],0x1
  2d64f6:	0f 94 c1             	sete   cl
  2d64f9:	41 f7 c4 c7 03 00 00 	test   r12d,0x3c7
  2d6500:	0f 95 c2             	setne  dl
  2d6503:	a9 c7 03 00 00       	test   eax,0x3c7
  2d6508:	0f 94 c0             	sete   al
  2d650b:	08 c8                	or     al,cl
  2d650d:	08 d0                	or     al,dl
  2d650f:	0f 85 a6 00 00 00    	jne    0x2d65bb
  2d6515:	4d 8b 6e 50          	mov    r13,QWORD PTR [r14+0x50]
  2d6519:	41 f6 85 a2 00 00 00 	test   BYTE PTR [r13+0xa2],0x1
  2d6520:	01 
  2d6521:	75 7a                	jne    0x2d659d
  2d6523:	49 8d 7d 18          	lea    rdi,[r13+0x18]
  2d6527:	31 f6                	xor    esi,esi
  2d6529:	31 d2                	xor    edx,edx
  2d652b:	48 89 7d d0          	mov    QWORD PTR [rbp-0x30],rdi
  2d652f:	e8 6c e1 4f 00       	call   0x7d46a0
  2d6534:	41 0f b6 bd 50 01 00 	movzx  edi,BYTE PTR [r13+0x150]
  2d653b:	00 
  2d653c:	e8 ff 07 34 00       	call   0x616d40
  2d6541:	84 c0                	test   al,al
  2d6543:	74 49                	je     0x2d658e
  2d6545:	49 8b 76 58          	mov    rsi,QWORD PTR [r14+0x58]
  2d6549:	4c 89 ef             	mov    rdi,r13
  2d654c:	48 c1 fe 0e          	sar    rsi,0xe
  2d6550:	e8 9b 32 8b 00       	call   0xb897f0
  2d6555:	48 85 c0             	test   rax,rax
  2d6558:	74 34                	je     0x2d658e
  2d655a:	49 8b 4e 58          	mov    rcx,QWORD PTR [r14+0x58]
  2d655e:	48 8b 70 28          	mov    rsi,QWORD PTR [rax+0x28]
  2d6562:	49 8b 56 28          	mov    rdx,QWORD PTR [r14+0x28]
  2d6566:	48 c1 e9 0e          	shr    rcx,0xe
  2d656a:	48 29 ce             	sub    rsi,rcx
  2d656d:	48 c1 e6 0e          	shl    rsi,0xe
  2d6571:	49 03 76 20          	add    rsi,QWORD PTR [r14+0x20]
  2d6575:	48 39 d6             	cmp    rsi,rdx
  2d6578:	73 14                	jae    0x2d658e
  2d657a:	48 8b bb d8 01 00 00 	mov    rdi,QWORD PTR [rbx+0x1d8]
  2d6581:	45 0f b7 46 64       	movzx  r8d,WORD PTR [r14+0x64]
  2d6586:	48 89 c1             	mov    rcx,rax
  2d6589:	e8 92 d7 60 00       	call   0x8e3d20
  2d658e:	48 8b 7d d0          	mov    rdi,QWORD PTR [rbp-0x30]
  2d6592:	31 f6                	xor    esi,esi
  2d6594:	31 d2                	xor    edx,edx
  2d6596:	e8 15 e9 4f 00       	call   0x7d4eb0
  2d659b:	eb 1e                	jmp    0x2d65bb
  2d659d:	48 8b b3 d8 01 00 00 	mov    rsi,QWORD PTR [rbx+0x1d8]
  2d65a4:	49 8b 56 20          	mov    rdx,QWORD PTR [r14+0x20]
  2d65a8:	49 8b 4e 28          	mov    rcx,QWORD PTR [r14+0x28]
  2d65ac:	4d 8b 46 58          	mov    r8,QWORD PTR [r14+0x58]
  2d65b0:	4c 89 ef             	mov    rdi,r13
  2d65b3:	45 89 f9             	mov    r9d,r15d
  2d65b6:	e8 e5 5f 0f 00       	call   0x3cc5a0
  2d65bb:	41 f6 c4 30          	test   r12b,0x30
  2d65bf:	0f 94 c0             	sete   al
  2d65c2:	22 83 44 02 00 00    	and    al,BYTE PTR [rbx+0x244]
  2d65c8:	3c 01                	cmp    al,0x1
  2d65ca:	75 4d                	jne    0x2d6619
  2d65cc:	41 83 e7 30          	and    r15d,0x30
  2d65d0:	74 47                	je     0x2d6619
  2d65d2:	48 8b 05 0f fd 7b 01 	mov    rax,QWORD PTR [rip+0x17bfd0f]        # 0x1a962e8
  2d65d9:	4c 8b 48 20          	mov    r9,QWORD PTR [rax+0x20]
  2d65dd:	48 8d 05 34 6b f9 ff 	lea    rax,[rip+0xfffffffffff96b34]        # 0x26d118
  2d65e4:	4c 29 c8             	sub    rax,r9
  2d65e7:	48 c1 c8 03          	ror    rax,0x3
  2d65eb:	48 83 f8 01          	cmp    rax,0x1
  2d65ef:	77 37                	ja     0x2d6628
  2d65f1:	49 8b 76 20          	mov    rsi,QWORD PTR [r14+0x20]
  2d65f5:	49 8b 56 28          	mov    rdx,QWORD PTR [r14+0x28]
  2d65f9:	48 89 df             	mov    rdi,rbx
  2d65fc:	44 89 f9             	mov    ecx,r15d
  2d65ff:	41 b8 01 00 00 00    	mov    r8d,0x1
  2d6605:	48 29 f2             	sub    rdx,rsi
  2d6608:	48 83 c4 08          	add    rsp,0x8
  2d660c:	5b                   	pop    rbx
  2d660d:	41 5c                	pop    r12
  2d660f:	41 5d                	pop    r13
  2d6611:	41 5e                	pop    r14
  2d6613:	41 5f                	pop    r15
  2d6615:	5d                   	pop    rbp
  2d6616:	41 ff e1             	jmp    r9
  2d6619:	48 83 c4 08          	add    rsp,0x8
  2d661d:	5b                   	pop    rbx
  2d661e:	41 5c                	pop    r12
  2d6620:	41 5d                	pop    r13
  2d6622:	41 5e                	pop    r14
  2d6624:	41 5f                	pop    r15
  2d6626:	5d                   	pop    rbp
  2d6627:	c3                   	ret
  2d6628:	48 8d 3d 41 fc 7b 01 	lea    rdi,[rip+0x17bfc41]        # 0x1a96270
  2d662f:	4c 89 ce             	mov    rsi,r9
  2d6632:	4d 89 cc             	mov    r12,r9
  2d6635:	e8 86 92 17 00       	call   0x44f8c0
  2d663a:	4d 89 e1             	mov    r9,r12
  2d663d:	eb b2                	jmp    0x2d65f1
  2d663f:	90                   	nop
  2d6640:	55                   	push   rbp
  2d6641:	48 89 e5             	mov    rbp,rsp
  2d6644:	41 57                	push   r15
  2d6646:	41 56                	push   r14
  2d6648:	53                   	push   rbx
  2d6649:	50                   	push   rax
  2d664a:	80 8e 40 01 00 00 01 	or     BYTE PTR [rsi+0x140],0x1
  2d6651:	48 89 f3             	mov    rbx,rsi
  2d6654:	44 0f b7 76 64       	movzx  r14d,WORD PTR [rsi+0x64]
  2d6659:	66 44 89 b6 4a 01 00 	mov    WORD PTR [rsi+0x14a],r14w
  2d6660:	00 
  2d6661:	66 c7 46 64 00 00    	mov    WORD PTR [rsi+0x64],0x0
  2d6667:	f6 87 44 02 00 00 01 	test   BYTE PTR [rdi+0x244],0x1
  2d666e:	0f 94 c0             	sete   al
  2d6671:	41 f7 c6 c7 03 00 00 	test   r14d,0x3c7
  2d6678:	0f 94 c1             	sete   cl
  2d667b:	08 c1                	or     cl,al
  2d667d:	75 2e                	jne    0x2d66ad
  2d667f:	48 8b 43 50          	mov    rax,QWORD PTR [rbx+0x50]
  2d6683:	49 89 ff             	mov    r15,rdi
  2d6686:	48 8b bf d8 01 00 00 	mov    rdi,QWORD PTR [rdi+0x1d8]
  2d668d:	48 8b 73 20          	mov    rsi,QWORD PTR [rbx+0x20]
  2d6691:	48 8b 53 28          	mov    rdx,QWORD PTR [rbx+0x28]
  2d6695:	f6 80 a2 00 00 00 01 	test   BYTE PTR [rax+0xa2],0x1
  2d669c:	75 07                	jne    0x2d66a5
  2d669e:	e8 fd 8f 60 00       	call   0x8df6a0
  2d66a3:	eb 05                	jmp    0x2d66aa
  2d66a5:	e8 e6 77 61 00       	call   0x8ede90
  2d66aa:	4c 89 ff             	mov    rdi,r15
  2d66ad:	f6 87 44 02 00 00 01 	test   BYTE PTR [rdi+0x244],0x1
  2d66b4:	0f 94 c0             	sete   al
  2d66b7:	41 f6 c6 30          	test   r14b,0x30
  2d66bb:	0f 94 c1             	sete   cl
  2d66be:	08 c1                	or     cl,al
  2d66c0:	74 0b                	je     0x2d66cd
  2d66c2:	48 83 c4 08          	add    rsp,0x8
  2d66c6:	5b                   	pop    rbx
  2d66c7:	41 5e                	pop    r14
  2d66c9:	41 5f                	pop    r15
  2d66cb:	5d                   	pop    rbp
  2d66cc:	c3                   	ret
  2d66cd:	48 8b 05 14 fc 7b 01 	mov    rax,QWORD PTR [rip+0x17bfc14]        # 0x1a962e8
  2d66d4:	4c 8b 48 20          	mov    r9,QWORD PTR [rax+0x20]
  2d66d8:	48 8d 05 39 6a f9 ff 	lea    rax,[rip+0xfffffffffff96a39]        # 0x26d118
  2d66df:	4c 29 c8             	sub    rax,r9
  2d66e2:	48 c1 c8 03          	ror    rax,0x3
  2d66e6:	48 83 f8 01          	cmp    rax,0x1
  2d66ea:	77 20                	ja     0x2d670c
  2d66ec:	48 8b 73 20          	mov    rsi,QWORD PTR [rbx+0x20]
  2d66f0:	48 8b 53 28          	mov    rdx,QWORD PTR [rbx+0x28]
  2d66f4:	31 c9                	xor    ecx,ecx
  2d66f6:	41 b8 01 00 00 00    	mov    r8d,0x1
  2d66fc:	48 29 f2             	sub    rdx,rsi
  2d66ff:	48 83 c4 08          	add    rsp,0x8
  2d6703:	5b                   	pop    rbx
  2d6704:	41 5e                	pop    r14
  2d6706:	41 5f                	pop    r15
  2d6708:	5d                   	pop    rbp
  2d6709:	41 ff e1             	jmp    r9
  2d670c:	48 8d 05 7d fb 7b 01 	lea    rax,[rip+0x17bfb7d]        # 0x1a96290
  2d6713:	49 89 fe             	mov    r14,rdi
  2d6716:	4c 89 ce             	mov    rsi,r9
  2d6719:	4d 89 cf             	mov    r15,r9
  2d671c:	48 89 c7             	mov    rdi,rax
  2d671f:	e8 9c 91 17 00       	call   0x44f8c0
  2d6724:	4d 89 f9             	mov    r9,r15
  2d6727:	4c 89 f7             	mov    rdi,r14
  2d672a:	eb c0                	jmp    0x2d66ec
  2d672c:	90                   	nop
  2d672d:	90                   	nop
  2d672e:	90                   	nop
  2d672f:	90                   	nop
  2d6730:	55                   	push   rbp
  2d6731:	48 89 e5             	mov    rbp,rsp
  2d6734:	41 57                	push   r15
  2d6736:	41 56                	push   r14
  2d6738:	41 55                	push   r13
  2d673a:	41 54                	push   r12
  2d673c:	53                   	push   rbx
  2d673d:	48 83 ec 18          	sub    rsp,0x18
  2d6741:	48 8d 05 c8 5b 64 03 	lea    rax,[rip+0x3645bc8]        # 0x391c310
  2d6748:	41 89 ce             	mov    r14d,ecx
  2d674b:	49 89 d7             	mov    r15,rdx
  2d674e:	49 89 f5             	mov    r13,rsi
  2d6751:	48 89 fb             	mov    rbx,rdi
  2d6754:	48 8b 00             	mov    rax,QWORD PTR [rax]
  2d6757:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  2d675b:	0f b6 87 44 02 00 00 	movzx  eax,BYTE PTR [rdi+0x244]
  2d6762:	a8 10                	test   al,0x10
  2d6764:	75 29                	jne    0x2d678f
  2d6766:	a8 08                	test   al,0x8
  2d6768:	74 11                	je     0x2d677b
  2d676a:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  2d6771:	00 00 
  2d6773:	f0 83 80 a8 05 00 00 	lock add DWORD PTR [rax+0x5a8],0x1
  2d677a:	01 
  2d677b:	48 8d bb 70 01 00 00 	lea    rdi,[rbx+0x170]
  2d6782:	31 f6                	xor    esi,esi
  2d6784:	31 d2                	xor    edx,edx
  2d6786:	31 c9                	xor    ecx,ecx
  2d6788:	e8 93 53 97 00       	call   0xc4bb20
  2d678d:	eb 12                	jmp    0x2d67a1
  2d678f:	48 8d bb a8 01 00 00 	lea    rdi,[rbx+0x1a8]
  2d6796:	31 f6                	xor    esi,esi
  2d6798:	31 d2                	xor    edx,edx
  2d679a:	31 c9                	xor    ecx,ecx
  2d679c:	e8 5f 02 1f 00       	call   0x4c6a00
  2d67a1:	ff 83 c0 01 00 00    	inc    DWORD PTR [rbx+0x1c0]
  2d67a7:	48 8d 55 c8          	lea    rdx,[rbp-0x38]
  2d67ab:	48 89 df             	mov    rdi,rbx
  2d67ae:	4c 89 ee             	mov    rsi,r13
  2d67b1:	f0 83 83 c4 01 00 00 	lock add DWORD PTR [rbx+0x1c4],0x1
  2d67b8:	01 
  2d67b9:	e8 82 04 ff ff       	call   0x2c6c40
  2d67be:	4c 8b 65 c8          	mov    r12,QWORD PTR [rbp-0x38]
  2d67c2:	4d 3b 6c 24 20       	cmp    r13,QWORD PTR [r12+0x20]
  2d67c7:	76 2c                	jbe    0x2d67f5
  2d67c9:	48 89 df             	mov    rdi,rbx
  2d67cc:	4c 89 e6             	mov    rsi,r12
  2d67cf:	4c 89 ea             	mov    rdx,r13
  2d67d2:	e8 09 4d ff ff       	call   0x2cb4e0
  2d67d7:	eb 1c                	jmp    0x2d67f5
  2d67d9:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
  2d67e0:	e8 5b fe ff ff       	call   0x2d6640
  2d67e5:	48 89 df             	mov    rdi,rbx
  2d67e8:	4c 89 e6             	mov    rsi,r12
  2d67eb:	e8 20 21 ff ff       	call   0x2c8910
  2d67f0:	4d 8b 64 24 08       	mov    r12,QWORD PTR [r12+0x8]
  2d67f5:	49 39 dc             	cmp    r12,rbx
  2d67f8:	74 2e                	je     0x2d6828
  2d67fa:	4d 39 7c 24 20       	cmp    QWORD PTR [r12+0x20],r15
  2d67ff:	73 27                	jae    0x2d6828
  2d6801:	4d 3b 7c 24 28       	cmp    r15,QWORD PTR [r12+0x28]
  2d6806:	73 0e                	jae    0x2d6816
  2d6808:	48 89 df             	mov    rdi,rbx
  2d680b:	4c 89 e6             	mov    rsi,r12
  2d680e:	4c 89 fa             	mov    rdx,r15
  2d6811:	e8 5a 4f ff ff       	call   0x2cb770
  2d6816:	48 89 df             	mov    rdi,rbx
  2d6819:	4c 89 e6             	mov    rsi,r12
  2d681c:	45 85 f6             	test   r14d,r14d
  2d681f:	74 bf                	je     0x2d67e0
  2d6821:	e8 9a fc ff ff       	call   0x2d64c0
  2d6826:	eb bd                	jmp    0x2d67e5
  2d6828:	48 8d 05 e1 5a 64 03 	lea    rax,[rip+0x3645ae1]        # 0x391c310
  2d682f:	48 8b 00             	mov    rax,QWORD PTR [rax]
  2d6832:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  2d6836:	75 1a                	jne    0x2d6852
  2d6838:	48 89 df             	mov    rdi,rbx
  2d683b:	31 f6                	xor    esi,esi
  2d683d:	31 d2                	xor    edx,edx
  2d683f:	48 83 c4 18          	add    rsp,0x18
  2d6843:	5b                   	pop    rbx
  2d6844:	41 5c                	pop    r12
  2d6846:	41 5d                	pop    r13
  2d6848:	41 5e                	pop    r14
  2d684a:	41 5f                	pop    r15
  2d684c:	5d                   	pop    rbp
  2d684d:	e9 9e fc fe ff       	jmp    0x2c64f0
  2d6852:	e8 59 6e 42 00       	call   0x6fd6b0
  2d6857:	0f 0b                	ud2
  2d6859:	90                   	nop
  2d685a:	90                   	nop
  2d685b:	90                   	nop
  2d685c:	90                   	nop
  2d685d:	90                   	nop
  2d685e:	90                   	nop
  2d685f:	90                   	nop
  2d6860:	55                   	push   rbp
  2d6861:	48 89 e5             	mov    rbp,rsp
  2d6864:	41 57                	push   r15
  2d6866:	41 56                	push   r14
  2d6868:	41 55                	push   r13
  2d686a:	41 54                	push   r12
  2d686c:	53                   	push   rbx
  2d686d:	48 83 ec 58          	sub    rsp,0x58
  2d6871:	48 8d 05 98 5a 64 03 	lea    rax,[rip+0x3645a98]        # 0x391c310
  2d6878:	49 89 f7             	mov    r15,rsi
  2d687b:	48 89 fb             	mov    rbx,rdi
  2d687e:	48 c1 fa 0e          	sar    rdx,0xe
  2d6882:	49 c1 ff 0e          	sar    r15,0xe
  2d6886:	4c 89 fe             	mov    rsi,r15
  2d6889:	48 8b 00             	mov    rax,QWORD PTR [rax]
  2d688c:	48 89 45 d0          	mov    QWORD PTR [rbp-0x30],rax
  2d6890:	89 4d 8c             	mov    DWORD PTR [rbp-0x74],ecx
  2d6893:	48 89 55 80          	mov    QWORD PTR [rbp-0x80],rdx
  2d6897:	85 c9                	test   ecx,ecx
  2d6899:	74 07                	je     0x2d68a2
  2d689b:	e8 c0 a5 18 00       	call   0x460e60
  2d68a0:	eb 05                	jmp    0x2d68a7
  2d68a2:	e8 69 a1 18 00       	call   0x460a10
  2d68a7:	41 89 c6             	mov    r14d,eax
  2d68aa:	85 c0                	test   eax,eax
  2d68ac:	74 26                	je     0x2d68d4
  2d68ae:	48 8d 05 5b 5a 64 03 	lea    rax,[rip+0x3645a5b]        # 0x391c310
  2d68b5:	48 8b 00             	mov    rax,QWORD PTR [rax]
  2d68b8:	48 3b 45 d0          	cmp    rax,QWORD PTR [rbp-0x30]
  2d68bc:	0f 85 1d 01 00 00    	jne    0x2d69df
  2d68c2:	44 89 f0             	mov    eax,r14d
  2d68c5:	48 83 c4 58          	add    rsp,0x58
  2d68c9:	5b                   	pop    rbx
  2d68ca:	41 5c                	pop    r12
  2d68cc:	41 5d                	pop    r13
  2d68ce:	41 5e                	pop    r14
  2d68d0:	41 5f                	pop    r15
  2d68d2:	5d                   	pop    rbp
  2d68d3:	c3                   	ret
  2d68d4:	48 8d 7d 90          	lea    rdi,[rbp-0x70]
  2d68d8:	48 89 de             	mov    rsi,rbx
  2d68db:	e8 70 b0 22 00       	call   0x501950
  2d68e0:	48 85 c0             	test   rax,rax
  2d68e3:	0f 84 ee 00 00 00    	je     0x2d69d7
  2d68e9:	49 89 c4             	mov    r12,rax
  2d68ec:	4c 8d 6d a0          	lea    r13,[rbp-0x60]
  2d68f0:	e9 90 00 00 00       	jmp    0x2d6985
  2d68f5:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  2d68fc:	00 00 00 00 
  2d6900:	48 8d bb 70 01 00 00 	lea    rdi,[rbx+0x170]
  2d6907:	31 f6                	xor    esi,esi
  2d6909:	31 d2                	xor    edx,edx
  2d690b:	31 c9                	xor    ecx,ecx
  2d690d:	e8 0e 52 97 00       	call   0xc4bb20
  2d6912:	ff 83 c0 01 00 00    	inc    DWORD PTR [rbx+0x1c0]
  2d6918:	4c 89 e7             	mov    rdi,r12
  2d691b:	4c 89 ee             	mov    rsi,r13
  2d691e:	48 8d 15 b3 9b f9 ff 	lea    rdx,[rip+0xfffffffffff99bb3]        # 0x2704d8
  2d6925:	4c 89 e9             	mov    rcx,r13
  2d6928:	f0 83 83 c4 01 00 00 	lock add DWORD PTR [rbx+0x1c4],0x1
  2d692f:	01 
  2d6930:	44 89 7d a8          	mov    DWORD PTR [rbp-0x58],r15d
  2d6934:	48 8b 45 80          	mov    rax,QWORD PTR [rbp-0x80]
  2d6938:	89 45 ac             	mov    DWORD PTR [rbp-0x54],eax
  2d693b:	49 8b 44 24 18       	mov    rax,QWORD PTR [r12+0x18]
  2d6940:	48 89 45 b0          	mov    QWORD PTR [rbp-0x50],rax
  2d6944:	48 b8 ff ff ff ff ff 	movabs rax,0x7fffffffffffffff
  2d694b:	ff ff 7f 
  2d694e:	48 89 45 b8          	mov    QWORD PTR [rbp-0x48],rax
  2d6952:	48 89 45 c0          	mov    QWORD PTR [rbp-0x40],rax
  2d6956:	8b 45 8c             	mov    eax,DWORD PTR [rbp-0x74]
  2d6959:	88 45 c8             	mov    BYTE PTR [rbp-0x38],al
  2d695c:	e8 ff ac 22 00       	call   0x501660
  2d6961:	48 89 df             	mov    rdi,rbx
  2d6964:	45 31 f6             	xor    r14d,r14d
  2d6967:	31 f6                	xor    esi,esi
  2d6969:	31 d2                	xor    edx,edx
  2d696b:	e8 80 fb fe ff       	call   0x2c64f0
  2d6970:	48 8d 7d 90          	lea    rdi,[rbp-0x70]
  2d6974:	e8 57 b0 22 00       	call   0x5019d0
  2d6979:	49 89 c4             	mov    r12,rax
  2d697c:	48 85 c0             	test   rax,rax
  2d697f:	0f 84 29 ff ff ff    	je     0x2d68ae
  2d6985:	49 8b 5c 24 18       	mov    rbx,QWORD PTR [r12+0x18]
  2d698a:	0f b6 83 44 02 00 00 	movzx  eax,BYTE PTR [rbx+0x244]
  2d6991:	a8 10                	test   al,0x10
  2d6993:	75 2b                	jne    0x2d69c0
  2d6995:	a8 08                	test   al,0x8
  2d6997:	0f 84 63 ff ff ff    	je     0x2d6900
  2d699d:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  2d69a4:	00 00 
  2d69a6:	f0 83 80 a8 05 00 00 	lock add DWORD PTR [rax+0x5a8],0x1
  2d69ad:	01 
  2d69ae:	e9 4d ff ff ff       	jmp    0x2d6900
  2d69b3:	66 66 66 66 2e 0f 1f 	data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  2d69ba:	84 00 00 00 00 00 
  2d69c0:	48 8d bb a8 01 00 00 	lea    rdi,[rbx+0x1a8]
  2d69c7:	31 f6                	xor    esi,esi
  2d69c9:	31 d2                	xor    edx,edx
  2d69cb:	31 c9                	xor    ecx,ecx
  2d69cd:	e8 2e 00 1f 00       	call   0x4c6a00
  2d69d2:	e9 3b ff ff ff       	jmp    0x2d6912
  2d69d7:	45 31 f6             	xor    r14d,r14d
  2d69da:	e9 cf fe ff ff       	jmp    0x2d68ae
  2d69df:	e8 cc 6c 42 00       	call   0x6fd6b0
  2d69e4:	0f 0b                	ud2
  2d69e6:	90                   	nop
  2d69e7:	90                   	nop
  2d69e8:	90                   	nop
  2d69e9:	90                   	nop
  2d69ea:	90                   	nop
  2d69eb:	90                   	nop
  2d69ec:	90                   	nop
  2d69ed:	90                   	nop
  2d69ee:	90                   	nop
  2d69ef:	90                   	nop
  2d69f0:	55                   	push   rbp
  2d69f1:	48 89 e5             	mov    rbp,rsp
  2d69f4:	49 89 f8             	mov    r8,rdi
  2d69f7:	48 8d 35 54 8e 07 01 	lea    rsi,[rip+0x1078e54]        # 0x134f852
  2d69fe:	48 8d 15 3b 08 f9 ff 	lea    rdx,[rip+0xfffffffffff9083b]        # 0x267240
  2d6a05:	48 8d 0d ed 74 0b 01 	lea    rcx,[rip+0x10b74ed]        # 0x138def9
  2d6a0c:	41 b9 10 27 00 00    	mov    r9d,0x2710
  2d6a12:	31 ff                	xor    edi,edi
  2d6a14:	e8 27 73 46 00       	call   0x73dd40
  2d6a19:	48 89 05 f0 a2 a8 02 	mov    QWORD PTR [rip+0x2a8a2f0],rax        # 0x2d60d10
  2d6a20:	5d                   	pop    rbp
  2d6a21:	c3                   	ret
  2d6a22:	90                   	nop
  2d6a23:	90                   	nop
  2d6a24:	90                   	nop
  2d6a25:	90                   	nop
  2d6a26:	90                   	nop
  2d6a27:	90                   	nop
  2d6a28:	90                   	nop
  2d6a29:	90                   	nop
  2d6a2a:	90                   	nop
  2d6a2b:	90                   	nop
  2d6a2c:	90                   	nop
  2d6a2d:	90                   	nop
  2d6a2e:	90                   	nop
  2d6a2f:	90                   	nop
  2d6a30:	55                   	push   rbp
  2d6a31:	48 89 e5             	mov    rbp,rsp
  2d6a34:	53                   	push   rbx
  2d6a35:	50                   	push   rax
  2d6a36:	8b 47 08             	mov    eax,DWORD PTR [rdi+0x8]
  2d6a39:	48 8b 37             	mov    rsi,QWORD PTR [rdi]
  2d6a3c:	48 8b 57 10          	mov    rdx,QWORD PTR [rdi+0x10]
  2d6a40:	89 c7                	mov    edi,eax
  2d6a42:	e8 89 00 0f 00       	call   0x3c6ad0
  2d6a47:	85 c0                	test   eax,eax
  2d6a49:	75 07                	jne    0x2d6a52
  2d6a4b:	48 83 c4 08          	add    rsp,0x8
  2d6a4f:	5b                   	pop    rbx
  2d6a50:	5d                   	pop    rbp
  2d6a51:	c3                   	ret
  2d6a52:	89 c3                	mov    ebx,eax
  2d6a54:	e8 f7 ae 51 00       	call   0x7f1950
  2d6a59:	48 63 f3             	movsxd rsi,ebx
  2d6a5c:	48 8d 3d ef ff ff ff 	lea    rdi,[rip+0xffffffffffffffef]        # 0x2d6a52
  2d6a63:	e8 38 ae 51 00       	call   0x7f18a0
  2d6a68:	48 8d 35 33 f3 f9 00 	lea    rsi,[rip+0xf9f333]        # 0x1275da2
  2d6a6f:	bf 8b 00 00 00       	mov    edi,0x8b
  2d6a74:	89 da                	mov    edx,ebx
  2d6a76:	31 c0                	xor    eax,eax
  2d6a78:	e8 93 3f 9c 00       	call   0xc9aa10
  2d6a7d:	0f 0b                	ud2
  2d6a7f:	90                   	nop
  2d6a80:	55                   	push   rbp
  2d6a81:	48 89 e5             	mov    rbp,rsp
  2d6a84:	41 57                	push   r15
  2d6a86:	41 56                	push   r14
  2d6a88:	41 55                	push   r13
  2d6a8a:	41 54                	push   r12
  2d6a8c:	53                   	push   rbx
  2d6a8d:	48 81 ec 98 00 00 00 	sub    rsp,0x98
  2d6a94:	48 8d 3d 7f 0d ff 00 	lea    rdi,[rip+0xff0d7f]        # 0x12c781a
  2d6a9b:	be 44 00 00 00       	mov    esi,0x44
  2d6aa0:	ba 07 00 00 00       	mov    edx,0x7
  2d6aa5:	31 c9                	xor    ecx,ecx
  2d6aa7:	e8 b4 f9 64 00       	call   0x926460
  2d6aac:	e8 df 9e 7f 00       	call   0xad0990
  2d6ab1:	48 89 45 a8          	mov    QWORD PTR [rbp-0x58],rax
  2d6ab5:	48 8d 04 80          	lea    rax,[rax+rax*4]
  2d6ab9:	4c 8d 3d 60 a2 a8 02 	lea    r15,[rip+0x2a8a260]        # 0x2d60d20
  2d6ac0:	48 8d 1d d9 a4 a8 02 	lea    rbx,[rip+0x2a8a4d9]        # 0x2d60fa0
  2d6ac7:	4c 8d 2d 72 9f a8 02 	lea    r13,[rip+0x2a89f72]        # 0x2d60a40
  2d6ace:	48 89 85 60 ff ff ff 	mov    QWORD PTR [rbp-0xa0],rax
  2d6ad5:	48 8d 04 40          	lea    rax,[rax+rax*2]
  2d6ad9:	48 89 85 68 ff ff ff 	mov    QWORD PTR [rbp-0x98],rax
  2d6ae0:	0f 31                	rdtsc
  2d6ae2:	89 c0                	mov    eax,eax
  2d6ae4:	48 c1 e2 20          	shl    rdx,0x20
  2d6ae8:	48 c7 45 a0 00 00 00 	mov    QWORD PTR [rbp-0x60],0x0
  2d6aef:	00 
  2d6af0:	48 09 c2             	or     rdx,rax
  2d6af3:	eb 3b                	jmp    0x2d6b30
  2d6af5:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  2d6afc:	00 00 00 00 
  2d6b00:	48 8d 1d 99 a4 a8 02 	lea    rbx,[rip+0x2a8a499]        # 0x2d60fa0
  2d6b07:	4c 8d 2d 32 9f a8 02 	lea    r13,[rip+0x2a89f32]        # 0x2d60a40
  2d6b0e:	48 0f af f1          	imul   rsi,rcx
  2d6b12:	48 8d 3d f6 72 0d 01 	lea    rdi,[rip+0x10d72f6]        # 0x13ade0f
  2d6b19:	b9 00 01 00 00       	mov    ecx,0x100
  2d6b1e:	31 d2                	xor    edx,edx
  2d6b20:	e8 0b fd 92 00       	call   0xc06830
  2d6b25:	0f 31                	rdtsc
  2d6b27:	89 c0                	mov    eax,eax
  2d6b29:	48 c1 e2 20          	shl    rdx,0x20
  2d6b2d:	48 09 c2             	or     rdx,rax
  2d6b30:	48 8d 3d f1 94 a8 02 	lea    rdi,[rip+0x2a894f1]        # 0x2d60028
  2d6b37:	48 89 55 b8          	mov    QWORD PTR [rbp-0x48],rdx
  2d6b3b:	31 f6                	xor    esi,esi
  2d6b3d:	31 d2                	xor    edx,edx
  2d6b3f:	31 c9                	xor    ecx,ecx
  2d6b41:	e8 ba fe 1e 00       	call   0x4c6a00
  2d6b46:	8b 0d e4 9e a8 02    	mov    ecx,DWORD PTR [rip+0x2a89ee4]        # 0x2d60a30
  2d6b4c:	b8 00 00 00 00       	mov    eax,0x0
  2d6b51:	be 80 02 00 00       	mov    esi,0x280
  2d6b56:	ff c1                	inc    ecx
  2d6b58:	83 f9 04             	cmp    ecx,0x4
  2d6b5b:	0f 4d c8             	cmovge ecx,eax
  2d6b5e:	4c 63 e1             	movsxd r12,ecx
  2d6b61:	89 0d c9 9e a8 02    	mov    DWORD PTR [rip+0x2a89ec9],ecx        # 0x2d60a30
  2d6b67:	0f 31                	rdtsc
  2d6b69:	89 c0                	mov    eax,eax
  2d6b6b:	48 c1 e2 20          	shl    rdx,0x20
  2d6b6f:	4b 8d 3c a4          	lea    rdi,[r12+r12*4]
  2d6b73:	48 09 c2             	or     rdx,rax
  2d6b76:	48 8d 05 43 a1 a8 02 	lea    rax,[rip+0x2a8a143]        # 0x2d60cc0
  2d6b7d:	4a 89 14 e0          	mov    QWORD PTR [rax+r12*8],rdx
  2d6b81:	48 8d 05 a8 94 a8 02 	lea    rax,[rip+0x2a894a8]        # 0x2d60030
  2d6b88:	48 89 7d 98          	mov    QWORD PTR [rbp-0x68],rdi
  2d6b8c:	48 c1 e7 07          	shl    rdi,0x7
  2d6b90:	48 01 c7             	add    rdi,rax
  2d6b93:	e8 58 24 f8 ff       	call   0x258ff0
  2d6b98:	4c 89 e0             	mov    rax,r12
  2d6b9b:	4c 89 f9             	mov    rcx,r15
  2d6b9e:	be a0 00 00 00       	mov    esi,0xa0
  2d6ba3:	48 c1 e0 05          	shl    rax,0x5
  2d6ba7:	4c 8d 3c 80          	lea    r15,[rax+rax*4]
  2d6bab:	4a 8d 3c 39          	lea    rdi,[rcx+r15*1]
  2d6baf:	48 89 bd 50 ff ff ff 	mov    QWORD PTR [rbp-0xb0],rdi
  2d6bb6:	e8 35 24 f8 ff       	call   0x258ff0
  2d6bbb:	4a 8d 3c 3b          	lea    rdi,[rbx+r15*1]
  2d6bbf:	be a0 00 00 00       	mov    esi,0xa0
  2d6bc4:	48 89 bd 48 ff ff ff 	mov    QWORD PTR [rbp-0xb8],rdi
  2d6bcb:	e8 20 24 f8 ff       	call   0x258ff0
  2d6bd0:	48 8d 05 49 a6 a8 02 	lea    rax,[rip+0x2a8a649]        # 0x2d61220
  2d6bd7:	be a0 00 00 00       	mov    esi,0xa0
  2d6bdc:	4e 8d 34 38          	lea    r14,[rax+r15*1]
  2d6be0:	4c 89 f7             	mov    rdi,r14
  2d6be3:	e8 08 24 f8 ff       	call   0x258ff0
  2d6be8:	4b 8d 5c 3d 00       	lea    rbx,[r13+r15*1+0x0]
  2d6bed:	be a0 00 00 00       	mov    esi,0xa0
  2d6bf2:	48 89 df             	mov    rdi,rbx
  2d6bf5:	e8 f6 23 f8 ff       	call   0x258ff0
  2d6bfa:	48 8d 3d ef a0 a8 02 	lea    rdi,[rip+0x2a8a0ef]        # 0x2d60cf0
  2d6c01:	48 8d 05 d8 a0 a8 02 	lea    rax,[rip+0x2a8a0d8]        # 0x2d60ce0
  2d6c08:	4c 89 65 c0          	mov    QWORD PTR [rbp-0x40],r12
  2d6c0c:	31 f6                	xor    esi,esi
  2d6c0e:	31 d2                	xor    edx,edx
  2d6c10:	31 c9                	xor    ecx,ecx
  2d6c12:	42 c7 04 a7 00 00 00 	mov    DWORD PTR [rdi+r12*4],0x0
  2d6c19:	00 
  2d6c1a:	48 8d 3d 07 94 a8 02 	lea    rdi,[rip+0x2a89407]        # 0x2d60028
  2d6c21:	42 c7 04 a0 00 00 00 	mov    DWORD PTR [rax+r12*4],0x0
  2d6c28:	00 
  2d6c29:	e8 72 03 1f 00       	call   0x4c6fa0
  2d6c2e:	4c 8d 25 cb 74 24 03 	lea    r12,[rip+0x32474cb]        # 0x351e100
  2d6c35:	31 f6                	xor    esi,esi
  2d6c37:	31 d2                	xor    edx,edx
  2d6c39:	4c 89 e7             	mov    rdi,r12
  2d6c3c:	e8 7f e4 4f 00       	call   0x7d50c0
  2d6c41:	44 8b 2d 48 75 24 03 	mov    r13d,DWORD PTR [rip+0x3247548]        # 0x351e190
  2d6c48:	4c 89 e7             	mov    rdi,r12
  2d6c4b:	31 f6                	xor    esi,esi
  2d6c4d:	31 d2                	xor    edx,edx
  2d6c4f:	e8 8c ea 4f 00       	call   0x7d56e0
  2d6c54:	bf 0a 00 00 00       	mov    edi,0xa
  2d6c59:	e8 e2 00 34 00       	call   0x616d40
  2d6c5e:	84 c0                	test   al,al
  2d6c60:	74 26                	je     0x2d6c88
  2d6c62:	4c 8d 25 5f 76 24 03 	lea    r12,[rip+0x324765f]        # 0x351e2c8
  2d6c69:	31 f6                	xor    esi,esi
  2d6c6b:	31 d2                	xor    edx,edx
  2d6c6d:	4c 89 e7             	mov    rdi,r12
  2d6c70:	e8 4b e4 4f 00       	call   0x7d50c0
  2d6c75:	44 03 2d dc 76 24 03 	add    r13d,DWORD PTR [rip+0x32476dc]        # 0x351e358
  2d6c7c:	4c 89 e7             	mov    rdi,r12
  2d6c7f:	31 f6                	xor    esi,esi
  2d6c81:	31 d2                	xor    edx,edx
  2d6c83:	e8 58 ea 4f 00       	call   0x7d56e0
  2d6c88:	4c 8d 25 01 78 24 03 	lea    r12,[rip+0x3247801]        # 0x351e490
  2d6c8f:	31 f6                	xor    esi,esi
  2d6c91:	31 d2                	xor    edx,edx
  2d6c93:	4c 89 e7             	mov    rdi,r12
  2d6c96:	e8 25 e4 4f 00       	call   0x7d50c0
  2d6c9b:	44 03 2d 7e 78 24 03 	add    r13d,DWORD PTR [rip+0x324787e]        # 0x351e520
  2d6ca2:	4c 89 e7             	mov    rdi,r12
  2d6ca5:	31 f6                	xor    esi,esi
  2d6ca7:	31 d2                	xor    edx,edx
  2d6ca9:	e8 32 ea 4f 00       	call   0x7d56e0
  2d6cae:	bf 0a 00 00 00       	mov    edi,0xa
  2d6cb3:	e8 88 00 34 00       	call   0x616d40
  2d6cb8:	84 c0                	test   al,al
  2d6cba:	74 26                	je     0x2d6ce2
  2d6cbc:	4c 8d 25 95 79 24 03 	lea    r12,[rip+0x3247995]        # 0x351e658
  2d6cc3:	31 f6                	xor    esi,esi
  2d6cc5:	31 d2                	xor    edx,edx
  2d6cc7:	4c 89 e7             	mov    rdi,r12
  2d6cca:	e8 f1 e3 4f 00       	call   0x7d50c0
  2d6ccf:	44 03 2d 12 7a 24 03 	add    r13d,DWORD PTR [rip+0x3247a12]        # 0x351e6e8
  2d6cd6:	4c 89 e7             	mov    rdi,r12
  2d6cd9:	31 f6                	xor    esi,esi
  2d6cdb:	31 d2                	xor    edx,edx
  2d6cdd:	e8 fe e9 4f 00       	call   0x7d56e0
  2d6ce2:	4c 8b 65 c0          	mov    r12,QWORD PTR [rbp-0x40]
  2d6ce6:	48 8d 05 13 a0 a8 02 	lea    rax,[rip+0x2a8a013]        # 0x2d60d00
  2d6ced:	4c 89 f7             	mov    rdi,r14
  2d6cf0:	be 04 00 00 00       	mov    esi,0x4
  2d6cf5:	46 89 2c a0          	mov    DWORD PTR [rax+r12*4],r13d
  2d6cf9:	e8 92 77 16 00       	call   0x43e490
  2d6cfe:	48 8b 35 cb 96 64 03 	mov    rsi,QWORD PTR [rip+0x36496cb]        # 0x39203d0
  2d6d05:	4c 8d 35 03 71 0d 01 	lea    r14,[rip+0x10d7103]        # 0x13ade0f
  2d6d0c:	b9 00 01 00 00       	mov    ecx,0x100
  2d6d11:	31 d2                	xor    edx,edx
  2d6d13:	4c 89 f7             	mov    rdi,r14
  2d6d16:	e8 15 fb 92 00       	call   0xc06830
  2d6d1b:	48 89 df             	mov    rdi,rbx
  2d6d1e:	be 04 00 00 00       	mov    esi,0x4
  2d6d23:	e8 28 29 93 00       	call   0xc09650
  2d6d28:	48 8b 35 a1 96 64 03 	mov    rsi,QWORD PTR [rip+0x36496a1]        # 0x39203d0
  2d6d2f:	4c 89 f7             	mov    rdi,r14
  2d6d32:	b9 00 01 00 00       	mov    ecx,0x100
  2d6d37:	31 d2                	xor    edx,edx
  2d6d39:	e8 f2 fa 92 00       	call   0xc06830
  2d6d3e:	4c 89 e0             	mov    rax,r12
  2d6d41:	ba 88 00 00 00       	mov    edx,0x88
  2d6d46:	48 8d 3d 6f f1 25 03 	lea    rdi,[rip+0x325f16f]        # 0x3535ebc
  2d6d4d:	48 c1 e0 07          	shl    rax,0x7
  2d6d51:	4a 8d 34 e0          	lea    rsi,[rax+r12*8]
  2d6d55:	48 8d 05 44 a7 a8 02 	lea    rax,[rip+0x2a8a744]        # 0x2d614a0
  2d6d5c:	48 01 c6             	add    rsi,rax
  2d6d5f:	e8 7c 2e f8 ff       	call   0x259be0
  2d6d64:	48 8d 3d f5 30 2b 03 	lea    rdi,[rip+0x32b30f5]        # 0x3589e60
  2d6d6b:	31 f6                	xor    esi,esi
  2d6d6d:	31 d2                	xor    edx,edx
  2d6d6f:	31 c9                	xor    ecx,ecx
  2d6d71:	e8 da 45 97 00       	call   0xc4b350
  2d6d76:	4c 8b 2d 03 31 2b 03 	mov    r13,QWORD PTR [rip+0x32b3103]        # 0x3589e80
  2d6d7d:	4d 85 ed             	test   r13,r13
  2d6d80:	0f 84 ba 04 00 00    	je     0x2d7240
  2d6d86:	48 8d 05 93 9f a8 02 	lea    rax,[rip+0x2a89f93]        # 0x2d60d20
  2d6d8d:	4a 8d 74 38 50       	lea    rsi,[rax+r15*1+0x50]
  2d6d92:	4a 8d 4c 38 28       	lea    rcx,[rax+r15*1+0x28]
  2d6d97:	4a 8d 44 38 78       	lea    rax,[rax+r15*1+0x78]
  2d6d9c:	48 89 75 88          	mov    QWORD PTR [rbp-0x78],rsi
  2d6da0:	48 8d 35 f9 a1 a8 02 	lea    rsi,[rip+0x2a8a1f9]        # 0x2d60fa0
  2d6da7:	48 89 8d 78 ff ff ff 	mov    QWORD PTR [rbp-0x88],rcx
  2d6dae:	48 89 45 90          	mov    QWORD PTR [rbp-0x70],rax
  2d6db2:	4a 8d 4c 3e 28       	lea    rcx,[rsi+r15*1+0x28]
  2d6db7:	4a 8d 54 3e 50       	lea    rdx,[rsi+r15*1+0x50]
  2d6dbc:	4e 8d 7c 3e 78       	lea    r15,[rsi+r15*1+0x78]
  2d6dc1:	48 89 8d 70 ff ff ff 	mov    QWORD PTR [rbp-0x90],rcx
  2d6dc8:	48 89 55 80          	mov    QWORD PTR [rbp-0x80],rdx
  2d6dcc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  2d6dd0:	4d 8d b5 48 01 00 00 	lea    r14,[r13+0x148]
  2d6dd7:	31 f6                	xor    esi,esi
  2d6dd9:	31 d2                	xor    edx,edx
  2d6ddb:	31 c9                	xor    ecx,ecx
  2d6ddd:	4c 89 f7             	mov    rdi,r14
  2d6de0:	e8 1b fc 1e 00       	call   0x4c6a00
  2d6de5:	41 83 bd b8 00 00 00 	cmp    DWORD PTR [r13+0xb8],0x1
  2d6dec:	01 
  2d6ded:	75 51                	jne    0x2d6e40
  2d6def:	41 f6 85 b1 00 00 00 	test   BYTE PTR [r13+0xb1],0x20
  2d6df6:	20 
  2d6df7:	75 47                	jne    0x2d6e40
  2d6df9:	49 8b 9d 00 02 00 00 	mov    rbx,QWORD PTR [r13+0x200]
  2d6e00:	48 85 db             	test   rbx,rbx
  2d6e03:	74 3b                	je     0x2d6e40
  2d6e05:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  2d6e0c:	00 00 00 00 
  2d6e10:	8b 83 e0 02 00 00    	mov    eax,DWORD PTR [rbx+0x2e0]
  2d6e16:	85 c0                	test   eax,eax
  2d6e18:	7e 26                	jle    0x2d6e40
  2d6e1a:	8d 48 01             	lea    ecx,[rax+0x1]
  2d6e1d:	f0 0f b1 8b e0 02 00 	lock cmpxchg DWORD PTR [rbx+0x2e0],ecx
  2d6e24:	00 
  2d6e25:	75 e9                	jne    0x2d6e10
  2d6e27:	49 3b 9d 00 02 00 00 	cmp    rbx,QWORD PTR [r13+0x200]
  2d6e2e:	74 30                	je     0x2d6e60
  2d6e30:	48 89 df             	mov    rdi,rbx
  2d6e33:	e8 68 f3 fe ff       	call   0x2c61a0
  2d6e38:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
  2d6e3f:	00 
  2d6e40:	4c 89 f7             	mov    rdi,r14
  2d6e43:	31 f6                	xor    esi,esi
  2d6e45:	31 d2                	xor    edx,edx
  2d6e47:	31 c9                	xor    ecx,ecx
  2d6e49:	e8 52 01 1f 00       	call   0x4c6fa0
  2d6e4e:	4d 8b 6d 00          	mov    r13,QWORD PTR [r13+0x0]
  2d6e52:	4d 85 ed             	test   r13,r13
  2d6e55:	0f 85 75 ff ff ff    	jne    0x2d6dd0
  2d6e5b:	e9 e0 03 00 00       	jmp    0x2d7240
  2d6e60:	f6 83 44 02 00 00 04 	test   BYTE PTR [rbx+0x244],0x4
  2d6e67:	75 77                	jne    0x2d6ee0
  2d6e69:	41 ff 85 58 03 00 00 	inc    DWORD PTR [r13+0x358]
  2d6e70:	4c 89 f7             	mov    rdi,r14
  2d6e73:	31 f6                	xor    esi,esi
  2d6e75:	31 d2                	xor    edx,edx
  2d6e77:	31 c9                	xor    ecx,ecx
  2d6e79:	e8 22 01 1f 00       	call   0x4c6fa0
  2d6e7e:	48 8d 3d db 2f 2b 03 	lea    rdi,[rip+0x32b2fdb]        # 0x3589e60
  2d6e85:	31 f6                	xor    esi,esi
  2d6e87:	31 d2                	xor    edx,edx
  2d6e89:	e8 72 54 97 00       	call   0xc4c300
  2d6e8e:	48 8b 35 3b 95 64 03 	mov    rsi,QWORD PTR [rip+0x364953b]        # 0x39203d0
  2d6e95:	48 8d 3d 73 6f 0d 01 	lea    rdi,[rip+0x10d6f73]        # 0x13ade0f
  2d6e9c:	b9 00 01 00 00       	mov    ecx,0x100
  2d6ea1:	31 d2                	xor    edx,edx
  2d6ea3:	e8 88 f9 92 00       	call   0xc06830
  2d6ea8:	0f b6 83 44 02 00 00 	movzx  eax,BYTE PTR [rbx+0x244]
  2d6eaf:	4c 89 7d b0          	mov    QWORD PTR [rbp-0x50],r15
  2d6eb3:	a8 10                	test   al,0x10
  2d6eb5:	75 44                	jne    0x2d6efb
  2d6eb7:	a8 08                	test   al,0x8
  2d6eb9:	74 11                	je     0x2d6ecc
  2d6ebb:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  2d6ec2:	00 00 
  2d6ec4:	f0 83 80 a8 05 00 00 	lock add DWORD PTR [rax+0x5a8],0x1
  2d6ecb:	01 
  2d6ecc:	48 8d bb 70 01 00 00 	lea    rdi,[rbx+0x170]
  2d6ed3:	31 f6                	xor    esi,esi
  2d6ed5:	31 d2                	xor    edx,edx
  2d6ed7:	31 c9                	xor    ecx,ecx
  2d6ed9:	e8 72 44 97 00       	call   0xc4b350
  2d6ede:	eb 2d                	jmp    0x2d6f0d
  2d6ee0:	4c 89 f7             	mov    rdi,r14
  2d6ee3:	31 f6                	xor    esi,esi
  2d6ee5:	31 d2                	xor    edx,edx
  2d6ee7:	31 c9                	xor    ecx,ecx
  2d6ee9:	e8 b2 00 1f 00       	call   0x4c6fa0
  2d6eee:	48 89 df             	mov    rdi,rbx
  2d6ef1:	e8 aa f2 fe ff       	call   0x2c61a0
  2d6ef6:	e9 53 ff ff ff       	jmp    0x2d6e4e
  2d6efb:	48 8d bb a8 01 00 00 	lea    rdi,[rbx+0x1a8]
  2d6f02:	31 f6                	xor    esi,esi
  2d6f04:	31 d2                	xor    edx,edx
  2d6f06:	31 c9                	xor    ecx,ecx
  2d6f08:	e8 f3 fa 1e 00       	call   0x4c6a00
  2d6f0d:	4c 8b 7b 08          	mov    r15,QWORD PTR [rbx+0x8]
  2d6f11:	49 39 df             	cmp    r15,rbx
  2d6f14:	0f 84 07 01 00 00    	je     0x2d7021
  2d6f1a:	31 d2                	xor    edx,edx
  2d6f1c:	c7 45 d4 00 00 00 00 	mov    DWORD PTR [rbp-0x2c],0x0
  2d6f23:	eb 38                	jmp    0x2d6f5d
  2d6f25:	89 c8                	mov    eax,ecx
  2d6f27:	31 d2                	xor    edx,edx
  2d6f29:	f7 f7                	div    edi
  2d6f2b:	01 75 c8             	add    DWORD PTR [rbp-0x38],esi
  2d6f2e:	01 45 d4             	add    DWORD PTR [rbp-0x2c],eax
  2d6f31:	48 8b bd 58 ff ff ff 	mov    rdi,QWORD PTR [rbp-0xa8]
  2d6f38:	31 f6                	xor    esi,esi
  2d6f3a:	31 d2                	xor    edx,edx
  2d6f3c:	e8 9f e7 4f 00       	call   0x7d56e0
  2d6f41:	8b 55 c8             	mov    edx,DWORD PTR [rbp-0x38]
  2d6f44:	66 66 66 2e 0f 1f 84 	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  2d6f4b:	00 00 00 00 00 
  2d6f50:	4d 8b 7f 08          	mov    r15,QWORD PTR [r15+0x8]
  2d6f54:	49 39 df             	cmp    r15,rbx
  2d6f57:	0f 84 cd 00 00 00    	je     0x2d702a
  2d6f5d:	41 f6 47 60 02       	test   BYTE PTR [r15+0x60],0x2
  2d6f62:	75 ec                	jne    0x2d6f50
  2d6f64:	4d 8b 67 50          	mov    r12,QWORD PTR [r15+0x50]
  2d6f68:	4d 85 e4             	test   r12,r12
  2d6f6b:	74 e3                	je     0x2d6f50
  2d6f6d:	41 80 bc 24 50 01 00 	cmp    BYTE PTR [r12+0x150],0x0
  2d6f74:	00 00 
  2d6f76:	75 d8                	jne    0x2d6f50
  2d6f78:	41 0f b6 84 24 9d 00 	movzx  eax,BYTE PTR [r12+0x9d]
  2d6f7f:	00 00 
  2d6f81:	83 f8 0a             	cmp    eax,0xa
  2d6f84:	77 ca                	ja     0x2d6f50
  2d6f86:	b9 87 05 00 00       	mov    ecx,0x587
  2d6f8b:	0f a3 c1             	bt     ecx,eax
  2d6f8e:	73 c0                	jae    0x2d6f50
  2d6f90:	49 8d 7c 24 18       	lea    rdi,[r12+0x18]
  2d6f95:	89 55 c8             	mov    DWORD PTR [rbp-0x38],edx
  2d6f98:	31 f6                	xor    esi,esi
  2d6f9a:	31 d2                	xor    edx,edx
  2d6f9c:	48 89 bd 58 ff ff ff 	mov    QWORD PTR [rbp-0xa8],rdi
  2d6fa3:	e8 18 e1 4f 00       	call   0x7d50c0
  2d6fa8:	49 8b bc 24 88 00 00 	mov    rdi,QWORD PTR [r12+0x88]
  2d6faf:	00 
  2d6fb0:	48 85 ff             	test   rdi,rdi
  2d6fb3:	0f 84 78 ff ff ff    	je     0x2d6f31
  2d6fb9:	41 8b 84 24 40 01 00 	mov    eax,DWORD PTR [r12+0x140]
  2d6fc0:	00 
  2d6fc1:	41 8b 8c 24 44 01 00 	mov    ecx,DWORD PTR [r12+0x144]
  2d6fc8:	00 
  2d6fc9:	48 29 c8             	sub    rax,rcx
  2d6fcc:	49 8b 4f 28          	mov    rcx,QWORD PTR [r15+0x28]
  2d6fd0:	49 2b 4f 20          	sub    rcx,QWORD PTR [r15+0x20]
  2d6fd4:	48 c1 f9 0e          	sar    rcx,0xe
  2d6fd8:	48 0f af c1          	imul   rax,rcx
  2d6fdc:	48 89 c2             	mov    rdx,rax
  2d6fdf:	48 09 fa             	or     rdx,rdi
  2d6fe2:	48 c1 ea 20          	shr    rdx,0x20
  2d6fe6:	74 0a                	je     0x2d6ff2
  2d6fe8:	48 99                	cqo
  2d6fea:	48 f7 ff             	idiv   rdi
  2d6fed:	48 89 c6             	mov    rsi,rax
  2d6ff0:	eb 06                	jmp    0x2d6ff8
  2d6ff2:	31 d2                	xor    edx,edx
  2d6ff4:	f7 f7                	div    edi
  2d6ff6:	89 c6                	mov    esi,eax
  2d6ff8:	49 63 84 24 a8 00 00 	movsxd rax,DWORD PTR [r12+0xa8]
  2d6fff:	00 
  2d7000:	48 0f af c8          	imul   rcx,rax
  2d7004:	48 89 c8             	mov    rax,rcx
  2d7007:	48 09 f8             	or     rax,rdi
  2d700a:	48 c1 e8 20          	shr    rax,0x20
  2d700e:	0f 84 11 ff ff ff    	je     0x2d6f25
  2d7014:	48 89 c8             	mov    rax,rcx
  2d7017:	48 99                	cqo
  2d7019:	48 f7 ff             	idiv   rdi
  2d701c:	e9 0a ff ff ff       	jmp    0x2d6f2b
  2d7021:	31 d2                	xor    edx,edx
  2d7023:	c7 45 d4 00 00 00 00 	mov    DWORD PTR [rbp-0x2c],0x0
  2d702a:	f6 83 44 02 00 00 10 	test   BYTE PTR [rbx+0x244],0x10
  2d7031:	41 89 d4             	mov    r12d,edx
  2d7034:	75 4a                	jne    0x2d7080
  2d7036:	48 8d bb 70 01 00 00 	lea    rdi,[rbx+0x170]
  2d703d:	31 f6                	xor    esi,esi
  2d703f:	31 d2                	xor    edx,edx
  2d7041:	e8 ba 52 97 00       	call   0xc4c300
  2d7046:	f6 83 44 02 00 00 08 	test   BYTE PTR [rbx+0x244],0x8
  2d704d:	4c 8d 3d cc 9c a8 02 	lea    r15,[rip+0x2a89ccc]        # 0x2d60d20
  2d7054:	74 23                	je     0x2d7079
  2d7056:	65 48 8b 04 25 00 00 	mov    rax,QWORD PTR gs:0x0
  2d705d:	00 00 
  2d705f:	b9 ff ff ff ff       	mov    ecx,0xffffffff
  2d7064:	f0 0f c1 88 a8 05 00 	lock xadd DWORD PTR [rax+0x5a8],ecx
  2d706b:	00 
  2d706c:	81 f9 01 00 00 80    	cmp    ecx,0x80000001
  2d7072:	75 05                	jne    0x2d7079
  2d7074:	e8 77 0a 3e 00       	call   0x6b7af0
  2d7079:	e8 72 f6 fe ff       	call   0x2c66f0
  2d707e:	eb 19                	jmp    0x2d7099
  2d7080:	48 8d bb a8 01 00 00 	lea    rdi,[rbx+0x1a8]
  2d7087:	31 f6                	xor    esi,esi
  2d7089:	31 d2                	xor    edx,edx
  2d708b:	31 c9                	xor    ecx,ecx
  2d708d:	e8 0e ff 1e 00       	call   0x4c6fa0
  2d7092:	4c 8d 3d 87 9c a8 02 	lea    r15,[rip+0x2a89c87]        # 0x2d60d20
  2d7099:	48 89 df             	mov    rdi,rbx
  2d709c:	e8 ff f0 fe ff       	call   0x2c61a0
  2d70a1:	45 85 e4             	test   r12d,r12d
  2d70a4:	0f 8e 92 00 00 00    	jle    0x2d713c
  2d70aa:	48 8b 9d 50 ff ff ff 	mov    rbx,QWORD PTR [rbp-0xb0]
  2d70b1:	44 3b 63 04          	cmp    r12d,DWORD PTR [rbx+0x4]
  2d70b5:	7e 04                	jle    0x2d70bb
  2d70b7:	31 c0                	xor    eax,eax
  2d70b9:	eb 39                	jmp    0x2d70f4
  2d70bb:	48 8b 8d 78 ff ff ff 	mov    rcx,QWORD PTR [rbp-0x88]
  2d70c2:	b8 01 00 00 00       	mov    eax,0x1
  2d70c7:	48 89 cb             	mov    rbx,rcx
  2d70ca:	44 3b 61 04          	cmp    r12d,DWORD PTR [rcx+0x4]
  2d70ce:	7f 24                	jg     0x2d70f4
  2d70d0:	48 8b 4d 88          	mov    rcx,QWORD PTR [rbp-0x78]
  2d70d4:	b8 02 00 00 00       	mov    eax,0x2
  2d70d9:	48 89 cb             	mov    rbx,rcx
  2d70dc:	44 3b 61 04          	cmp    r12d,DWORD PTR [rcx+0x4]
  2d70e0:	7f 12                	jg     0x2d70f4
  2d70e2:	48 8b 4d 90          	mov    rcx,QWORD PTR [rbp-0x70]
  2d70e6:	b8 03 00 00 00       	mov    eax,0x3
  2d70eb:	48 89 cb             	mov    rbx,rcx
  2d70ee:	44 3b 61 04          	cmp    r12d,DWORD PTR [rcx+0x4]
  2d70f2:	7e 48                	jle    0x2d713c
  2d70f4:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
  2d70f8:	48 8d 0c 80          	lea    rcx,[rax+rax*4]
  2d70fc:	83 f0 03             	xor    eax,0x3
  2d70ff:	48 89 df             	mov    rdi,rbx
  2d7102:	c1 e0 03             	shl    eax,0x3
  2d7105:	48 c1 e2 05          	shl    rdx,0x5
  2d7109:	4c 01 fa             	add    rdx,r15
  2d710c:	48 8d 74 ca 28       	lea    rsi,[rdx+rcx*8+0x28]
  2d7111:	48 8d 14 80          	lea    rdx,[rax+rax*4]
  2d7115:	e8 c6 2a f8 ff       	call   0x259be0
  2d711a:	41 8b 85 bc 00 00 00 	mov    eax,DWORD PTR [r13+0xbc]
  2d7121:	49 8d bd e4 05 00 00 	lea    rdi,[r13+0x5e4]
  2d7128:	48 8d 73 08          	lea    rsi,[rbx+0x8]
  2d712c:	ba 20 00 00 00       	mov    edx,0x20
  2d7131:	89 03                	mov    DWORD PTR [rbx],eax
  2d7133:	e8 a8 2a f8 ff       	call   0x259be0
  2d7138:	44 89 63 04          	mov    DWORD PTR [rbx+0x4],r12d
  2d713c:	48 8b 9d 48 ff ff ff 	mov    rbx,QWORD PTR [rbp-0xb8]
  2d7143:	44 8b 65 d4          	mov    r12d,DWORD PTR [rbp-0x2c]
  2d7147:	44 3b 63 04          	cmp    r12d,DWORD PTR [rbx+0x4]
  2d714b:	7e 08                	jle    0x2d7155
  2d714d:	4c 8b 7d b0          	mov    r15,QWORD PTR [rbp-0x50]
  2d7151:	31 c0                	xor    eax,eax
  2d7153:	eb 39                	jmp    0x2d718e
  2d7155:	48 8b 8d 70 ff ff ff 	mov    rcx,QWORD PTR [rbp-0x90]
  2d715c:	4c 8b 7d b0          	mov    r15,QWORD PTR [rbp-0x50]
  2d7160:	b8 01 00 00 00       	mov    eax,0x1
  2d7165:	48 89 cb             	mov    rbx,rcx
  2d7168:	44 3b 61 04          	cmp    r12d,DWORD PTR [rcx+0x4]
  2d716c:	7f 20                	jg     0x2d718e
  2d716e:	48 8b 4d 80          	mov    rcx,QWORD PTR [rbp-0x80]
  2d7172:	b8 02 00 00 00       	mov    eax,0x2
  2d7177:	48 89 cb             	mov    rbx,rcx
  2d717a:	44 3b 61 04          	cmp    r12d,DWORD PTR [rcx+0x4]
  2d717e:	7f 0e                	jg     0x2d718e
  2d7180:	b8 03 00 00 00       	mov    eax,0x3
  2d7185:	4c 89 fb             	mov    rbx,r15
  2d7188:	45 3b 67 04          	cmp    r12d,DWORD PTR [r15+0x4]
  2d718c:	7e 52                	jle    0x2d71e0
  2d718e:	48 8b 55 98          	mov    rdx,QWORD PTR [rbp-0x68]
  2d7192:	48 8d 0c 80          	lea    rcx,[rax+rax*4]
  2d7196:	83 f0 03             	xor    eax,0x3
  2d7199:	48 8d 35 00 9e a8 02 	lea    rsi,[rip+0x2a89e00]        # 0x2d60fa0
  2d71a0:	48 89 df             	mov    rdi,rbx
  2d71a3:	c1 e0 03             	shl    eax,0x3
  2d71a6:	48 c1 e2 05          	shl    rdx,0x5
  2d71aa:	48 01 f2             	add    rdx,rsi
  2d71ad:	48 8d 74 ca 28       	lea    rsi,[rdx+rcx*8+0x28]
  2d71b2:	48 8d 14 80          	lea    rdx,[rax+rax*4]
  2d71b6:	e8 25 2a f8 ff       	call   0x259be0
  2d71bb:	41 8b 85 bc 00 00 00 	mov    eax,DWORD PTR [r13+0xbc]
  2d71c2:	49 8d bd e4 05 00 00 	lea    rdi,[r13+0x5e4]
  2d71c9:	ba 20 00 00 00       	mov    edx,0x20
  2d71ce:	89 03                	mov    DWORD PTR [rbx],eax
  2d71d0:	44 89 63 04          	mov    DWORD PTR [rbx+0x4],r12d
  2d71d4:	48 83 c3 08          	add    rbx,0x8
  2d71d8:	48 89 de             	mov    rsi,rbx
  2d71db:	e8 00 2a f8 ff       	call   0x259be0
  2d71e0:	48 8d 3d 79 2c 2b 03 	lea    rdi,[rip+0x32b2c79]        # 0x3589e60
  2d71e7:	31 f6                	xor    esi,esi
  2d71e9:	31 d2                	xor    edx,edx
  2d71eb:	31 c9                	xor    ecx,ecx
  2d71ed:	e8 5e 41 97 00       	call   0xc4b350
  2d71f2:	4c 89 f7             	mov    rdi,r14
  2d71f5:	31 f6                	xor    esi,esi
  2d71f7:	31 d2                	xor    edx,edx
  2d71f9:	31 c9                	xor    ecx,ecx
  2d71fb:	e8 00 f8 1e 00       	call   0x4c6a00
  2d7200:	41 0f b6 8d b1 00 00 	movzx  ecx,BYTE PTR [r13+0xb1]
  2d7207:	00 
  2d7208:	41 8b 85 58 03 00 00 	mov    eax,DWORD PTR [r13+0x358]
  2d720f:	c0 e9 05             	shr    cl,0x5
  2d7212:	ff c8                	dec    eax
  2d7214:	0f 94 c2             	sete   dl
  2d7217:	41 89 85 58 03 00 00 	mov    DWORD PTR [r13+0x358],eax
  2d721e:	20 ca                	and    dl,cl
  2d7220:	80 fa 01             	cmp    dl,0x1
  2d7223:	0f 85 17 fc ff ff    	jne    0x2d6e40
  2d7229:	49 8d bd 58 03 00 00 	lea    rdi,[r13+0x358]
  2d7230:	e8 db f6 92 00       	call   0xc06910
  2d7235:	e9 06 fc ff ff       	jmp    0x2d6e40
  2d723a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
  2d7240:	48 8d 3d 19 2c 2b 03 	lea    rdi,[rip+0x32b2c19]        # 0x3589e60
  2d7247:	31 f6                	xor    esi,esi
  2d7249:	31 d2                	xor    edx,edx
  2d724b:	e8 b0 50 97 00       	call   0xc4c300
  2d7250:	48 8d 3d 61 6e 24 03 	lea    rdi,[rip+0x3246e61]        # 0x351e0b8
  2d7257:	31 f6                	xor    esi,esi
  2d7259:	31 d2                	xor    edx,edx
  2d725b:	31 c9                	xor    ecx,ecx
  2d725d:	e8 9e f7 1e 00       	call   0x4c6a00
  2d7262:	4c 8b 35 2f 6e 24 03 	mov    r14,QWORD PTR [rip+0x3246e2f]        # 0x351e098
  2d7269:	4c 8d 3d b0 9a a8 02 	lea    r15,[rip+0x2a89ab0]        # 0x2d60d20
  2d7270:	41 bd 87 05 00 00    	mov    r13d,0x587
  2d7276:	4d 85 f6             	test   r14,r14
  2d7279:	75 4e                	jne    0x2d72c9
  2d727b:	48 8d 3d 36 6e 24 03 	lea    rdi,[rip+0x3246e36]        # 0x351e0b8
  2d7282:	31 f6                	xor    esi,esi
  2d7284:	31 d2                	xor    edx,edx
  2d7286:	31 c9                	xor    ecx,ecx
  2d7288:	e8 13 fd 1e 00       	call   0x4c6fa0
  2d728d:	0f 31                	rdtsc
  2d728f:	89 c0                	mov    eax,eax
  2d7291:	48 c1 e2 20          	shl    rdx,0x20
  2d7295:	48 09 c2             	or     rdx,rax
  2d7298:	48 89 d0             	mov    rax,rdx
  2d729b:	48 2b 45 a0          	sub    rax,QWORD PTR [rbp-0x60]
  2d729f:	48 39 85 68 ff ff ff 	cmp    QWORD PTR [rbp-0x98],rax
  2d72a6:	0f 86 94 00 00 00    	jbe    0x2d7340
  2d72ac:	48 8b 7d b8          	mov    rdi,QWORD PTR [rbp-0x48]
  2d72b0:	e9 ae 05 00 00       	jmp    0x2d7863
  2d72b5:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  2d72bc:	00 00 00 00 
  2d72c0:	4d 8b 76 40          	mov    r14,QWORD PTR [r14+0x40]
  2d72c4:	4d 85 f6             	test   r14,r14
  2d72c7:	74 b2                	je     0x2d727b
  2d72c9:	41 80 be 50 01 00 00 	cmp    BYTE PTR [r14+0x150],0x0
  2d72d0:	00 
  2d72d1:	75 ed                	jne    0x2d72c0
  2d72d3:	41 0f b6 86 9d 00 00 	movzx  eax,BYTE PTR [r14+0x9d]
  2d72da:	00 
  2d72db:	83 f8 0a             	cmp    eax,0xa
  2d72de:	77 e0                	ja     0x2d72c0
  2d72e0:	41 0f a3 c5          	bt     r13d,eax
  2d72e4:	73 da                	jae    0x2d72c0
  2d72e6:	49 8d 5e 18          	lea    rbx,[r14+0x18]
  2d72ea:	31 f6                	xor    esi,esi
  2d72ec:	31 d2                	xor    edx,edx
  2d72ee:	48 89 df             	mov    rdi,rbx
  2d72f1:	e8 aa d3 4f 00       	call   0x7d46a0
  2d72f6:	45 8b be 40 01 00 00 	mov    r15d,DWORD PTR [r14+0x140]
  2d72fd:	45 8b a6 44 01 00 00 	mov    r12d,DWORD PTR [r14+0x144]
  2d7304:	48 89 df             	mov    rdi,rbx
  2d7307:	49 c7 86 40 01 00 00 	mov    QWORD PTR [r14+0x140],0x0
  2d730e:	00 00 00 00 
  2d7312:	31 f6                	xor    esi,esi
  2d7314:	31 d2                	xor    edx,edx
  2d7316:	e8 95 db 4f 00       	call   0x7d4eb0
  2d731b:	48 8b 4d c0          	mov    rcx,QWORD PTR [rbp-0x40]
  2d731f:	48 8d 05 ba 99 a8 02 	lea    rax,[rip+0x2a899ba]        # 0x2d60ce0
  2d7326:	48 8d 15 c3 99 a8 02 	lea    rdx,[rip+0x2a899c3]        # 0x2d60cf0
  2d732d:	44 01 3c 88          	add    DWORD PTR [rax+rcx*4],r15d
  2d7331:	44 01 24 8a          	add    DWORD PTR [rdx+rcx*4],r12d
  2d7335:	4c 8d 3d e4 99 a8 02 	lea    r15,[rip+0x2a899e4]        # 0x2d60d20
  2d733c:	eb 82                	jmp    0x2d72c0
  2d733e:	66 90                	xchg   ax,ax
  2d7340:	45 31 ed             	xor    r13d,r13d
  2d7343:	44 87 2d ea 96 a8 02 	xchg   DWORD PTR [rip+0x2a896ea],r13d        # 0x2d60a34
  2d734a:	48 8b 7d b8          	mov    rdi,QWORD PTR [rbp-0x48]
  2d734e:	45 85 ed             	test   r13d,r13d
  2d7351:	0f 84 0c 05 00 00    	je     0x2d7863
  2d7357:	48 89 55 c8          	mov    QWORD PTR [rbp-0x38],rdx
  2d735b:	e8 30 96 7f 00       	call   0xad0990
  2d7360:	48 8d 3d b0 6a 0d 01 	lea    rdi,[rip+0x10d6ab0]        # 0x13ade17
  2d7367:	44 89 ee             	mov    esi,r13d
  2d736a:	48 89 c3             	mov    rbx,rax
  2d736d:	31 c0                	xor    eax,eax
  2d736f:	e8 9c 60 f8 ff       	call   0x25d410
  2d7374:	44 8b 25 b5 96 a8 02 	mov    r12d,DWORD PTR [rip+0x2a896b5]        # 0x2d60a30
  2d737b:	48 89 5d c0          	mov    QWORD PTR [rbp-0x40],rbx
  2d737f:	41 83 c4 fd          	add    r12d,0xfffffffd
  2d7383:	eb 75                	jmp    0x2d73fa
  2d7385:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  2d738c:	00 00 00 00 
  2d7390:	48 8d 05 49 99 a8 02 	lea    rax,[rip+0x2a89949]        # 0x2d60ce0
  2d7397:	48 bb cd cc cc cc cc 	movabs rbx,0xcccccccccccccccd
  2d739e:	cc cc cc 
  2d73a1:	48 8d 3d 6d 6b 0b 01 	lea    rdi,[rip+0x10b6b6d]        # 0x138df15
  2d73a8:	4a 63 14 a8          	movsxd rdx,DWORD PTR [rax+r13*4]
  2d73ac:	31 c0                	xor    eax,eax
  2d73ae:	48 c1 e2 0e          	shl    rdx,0xe
  2d73b2:	c4 e2 cb f6 f3       	mulx   rsi,rsi,rbx
  2d73b7:	48 c1 ee 16          	shr    rsi,0x16
  2d73bb:	e8 50 60 f8 ff       	call   0x25d410
  2d73c0:	48 8d 05 29 99 a8 02 	lea    rax,[rip+0x2a89929]        # 0x2d60cf0
  2d73c7:	48 8d 3d 44 1d 0a 01 	lea    rdi,[rip+0x10a1d44]        # 0x1379112
  2d73ce:	4a 63 14 a8          	movsxd rdx,DWORD PTR [rax+r13*4]
  2d73d2:	31 c0                	xor    eax,eax
  2d73d4:	48 c1 e2 0e          	shl    rdx,0xe
  2d73d8:	c4 e2 cb f6 f3       	mulx   rsi,rsi,rbx
  2d73dd:	48 c1 ee 16          	shr    rsi,0x16
  2d73e1:	e8 2a 60 f8 ff       	call   0x25d410
  2d73e6:	48 8b 5d c0          	mov    rbx,QWORD PTR [rbp-0x40]
  2d73ea:	41 ff c4             	inc    r12d
  2d73ed:	44 3b 25 3c 96 a8 02 	cmp    r12d,DWORD PTR [rip+0x2a8963c]        # 0x2d60a30
  2d73f4:	0f 84 56 04 00 00    	je     0x2d7850
  2d73fa:	44 89 e0             	mov    eax,r12d
  2d73fd:	48 8d 0d bc 98 a8 02 	lea    rcx,[rip+0x2a898bc]        # 0x2d60cc0
  2d7404:	4c 8d 3d 15 9e a8 02 	lea    r15,[rip+0x2a89e15]        # 0x2d61220
  2d740b:	c1 e8 1f             	shr    eax,0x1f
  2d740e:	41 8d 04 84          	lea    eax,[r12+rax*4]
  2d7412:	4c 63 e8             	movsxd r13,eax
  2d7415:	4a 8b 04 e9          	mov    rax,QWORD PTR [rcx+r13*8]
  2d7419:	48 89 c1             	mov    rcx,rax
  2d741c:	48 09 d9             	or     rcx,rbx
  2d741f:	48 c1 e9 20          	shr    rcx,0x20
  2d7423:	74 0b                	je     0x2d7430
  2d7425:	31 d2                	xor    edx,edx
  2d7427:	48 f7 f3             	div    rbx
  2d742a:	48 89 c6             	mov    rsi,rax
  2d742d:	eb 07                	jmp    0x2d7436
  2d742f:	90                   	nop
  2d7430:	31 d2                	xor    edx,edx
  2d7432:	f7 f3                	div    ebx
  2d7434:	89 c6                	mov    esi,eax
  2d7436:	48 69 c2 e8 03 00 00 	imul   rax,rdx,0x3e8
  2d743d:	48 89 c1             	mov    rcx,rax
  2d7440:	48 09 d9             	or     rcx,rbx
  2d7443:	48 c1 e9 20          	shr    rcx,0x20
  2d7447:	74 07                	je     0x2d7450
  2d7449:	31 d2                	xor    edx,edx
  2d744b:	48 f7 f3             	div    rbx
  2d744e:	eb 04                	jmp    0x2d7454
  2d7450:	31 d2                	xor    edx,edx
  2d7452:	f7 f3                	div    ebx
  2d7454:	48 89 c2             	mov    rdx,rax
  2d7457:	48 8d 3d 06 c2 0a 01 	lea    rdi,[rip+0x10ac206]        # 0x1383664
  2d745e:	31 c0                	xor    eax,eax
  2d7460:	e8 ab 5f f8 ff       	call   0x25d410
  2d7465:	4c 89 e8             	mov    rax,r13
  2d7468:	48 8d 1d 31 a0 a8 02 	lea    rbx,[rip+0x2a8a031]        # 0x2d614a0
  2d746f:	48 8d 3d 93 28 fb 00 	lea    rdi,[rip+0xfb2893]        # 0x1289d09
  2d7476:	48 c1 e0 07          	shl    rax,0x7
  2d747a:	4e 8d 34 e8          	lea    r14,[rax+r13*8]
  2d747e:	31 c0                	xor    eax,eax
  2d7480:	42 8b 74 33 54       	mov    esi,DWORD PTR [rbx+r14*1+0x54]
  2d7485:	42 8b 54 33 64       	mov    edx,DWORD PTR [rbx+r14*1+0x64]
  2d748a:	42 8b 4c 33 78       	mov    ecx,DWORD PTR [rbx+r14*1+0x78]
  2d748f:	e8 7c 5f f8 ff       	call   0x25d410
  2d7494:	42 8b 74 33 74       	mov    esi,DWORD PTR [rbx+r14*1+0x74]
  2d7499:	42 8b 4c 33 68       	mov    ecx,DWORD PTR [rbx+r14*1+0x68]
  2d749e:	42 8b 54 33 6c       	mov    edx,DWORD PTR [rbx+r14*1+0x6c]
  2d74a3:	48 8d 3d 2d 78 09 01 	lea    rdi,[rip+0x109782d]        # 0x136ecd7
  2d74aa:	31 c0                	xor    eax,eax
  2d74ac:	e8 5f 5f f8 ff       	call   0x25d410
  2d74b1:	48 8d 05 48 98 a8 02 	lea    rax,[rip+0x2a89848]        # 0x2d60d00
  2d74b8:	b9 06 2c 00 00       	mov    ecx,0x2c06
  2d74bd:	48 8d 3d a1 69 0d 01 	lea    rdi,[rip+0x10d69a1]        # 0x13ade65
  2d74c4:	4a 63 04 a8          	movsxd rax,DWORD PTR [rax+r13*4]
  2d74c8:	c4 e2 f0 f7 f0       	bextr  rsi,rax,rcx
  2d74cd:	31 c0                	xor    eax,eax
  2d74cf:	e8 3c 5f f8 ff       	call   0x25d410
  2d74d4:	4f 8d 74 ad 00       	lea    r14,[r13+r13*4+0x0]
  2d74d9:	48 8d 1d 60 95 a8 02 	lea    rbx,[rip+0x2a89560]        # 0x2d60a40
  2d74e0:	49 c1 e6 05          	shl    r14,0x5
  2d74e4:	49 8b 14 1e          	mov    rdx,QWORD PTR [r14+rbx*1]
  2d74e8:	48 85 d2             	test   rdx,rdx
  2d74eb:	0f 84 9f 00 00 00    	je     0x2d7590
  2d74f1:	4a 8d 0c 33          	lea    rcx,[rbx+r14*1]
  2d74f5:	48 c1 ea 14          	shr    rdx,0x14
  2d74f9:	48 8d 3d fa 3a 04 01 	lea    rdi,[rip+0x1043afa]        # 0x131affa
  2d7500:	be 01 00 00 00       	mov    esi,0x1
  2d7505:	31 c0                	xor    eax,eax
  2d7507:	48 83 c1 08          	add    rcx,0x8
  2d750b:	e8 00 5f f8 ff       	call   0x25d410
  2d7510:	49 8b 54 1e 28       	mov    rdx,QWORD PTR [r14+rbx*1+0x28]
  2d7515:	48 85 d2             	test   rdx,rdx
  2d7518:	74 76                	je     0x2d7590
  2d751a:	49 8d 4c 1e 28       	lea    rcx,[r14+rbx*1+0x28]
  2d751f:	48 c1 ea 14          	shr    rdx,0x14
  2d7523:	48 8d 3d d0 3a 04 01 	lea    rdi,[rip+0x1043ad0]        # 0x131affa
  2d752a:	be 02 00 00 00       	mov    esi,0x2
  2d752f:	31 c0                	xor    eax,eax
  2d7531:	48 83 c1 08          	add    rcx,0x8
  2d7535:	e8 d6 5e f8 ff       	call   0x25d410
  2d753a:	49 8b 54 1e 50       	mov    rdx,QWORD PTR [r14+rbx*1+0x50]
  2d753f:	48 85 d2             	test   rdx,rdx
  2d7542:	74 4c                	je     0x2d7590
  2d7544:	49 8d 4c 1e 50       	lea    rcx,[r14+rbx*1+0x50]
  2d7549:	48 c1 ea 14          	shr    rdx,0x14
  2d754d:	48 8d 3d a6 3a 04 01 	lea    rdi,[rip+0x1043aa6]        # 0x131affa
  2d7554:	be 03 00 00 00       	mov    esi,0x3
  2d7559:	31 c0                	xor    eax,eax
  2d755b:	48 83 c1 08          	add    rcx,0x8
  2d755f:	e8 ac 5e f8 ff       	call   0x25d410
  2d7564:	49 8b 54 1e 78       	mov    rdx,QWORD PTR [r14+rbx*1+0x78]
  2d7569:	48 85 d2             	test   rdx,rdx
  2d756c:	74 22                	je     0x2d7590
  2d756e:	49 8d 4c 1e 78       	lea    rcx,[r14+rbx*1+0x78]
  2d7573:	48 c1 ea 14          	shr    rdx,0x14
  2d7577:	48 8d 3d 7c 3a 04 01 	lea    rdi,[rip+0x1043a7c]        # 0x131affa
  2d757e:	be 04 00 00 00       	mov    esi,0x4
  2d7583:	31 c0                	xor    eax,eax
  2d7585:	48 83 c1 08          	add    rcx,0x8
  2d7589:	e8 82 5e f8 ff       	call   0x25d410
  2d758e:	66 90                	xchg   ax,ax
  2d7590:	4b 8b 14 3e          	mov    rdx,QWORD PTR [r14+r15*1]
  2d7594:	48 85 d2             	test   rdx,rdx
  2d7597:	0f 84 a3 00 00 00    	je     0x2d7640
  2d759d:	4b 8d 0c 37          	lea    rcx,[r15+r14*1]
  2d75a1:	48 c1 ea 14          	shr    rdx,0x14
  2d75a5:	48 8d 3d 7b 02 ff 00 	lea    rdi,[rip+0xff027b]        # 0x12c7827
  2d75ac:	be 01 00 00 00       	mov    esi,0x1
  2d75b1:	31 c0                	xor    eax,eax
  2d75b3:	48 83 c1 08          	add    rcx,0x8
  2d75b7:	e8 54 5e f8 ff       	call   0x25d410
  2d75bc:	4b 8b 54 3e 28       	mov    rdx,QWORD PTR [r14+r15*1+0x28]
  2d75c1:	48 85 d2             	test   rdx,rdx
  2d75c4:	74 7a                	je     0x2d7640
  2d75c6:	4b 8d 4c 3e 28       	lea    rcx,[r14+r15*1+0x28]
  2d75cb:	48 c1 ea 14          	shr    rdx,0x14
  2d75cf:	48 8d 3d 51 02 ff 00 	lea    rdi,[rip+0xff0251]        # 0x12c7827
  2d75d6:	be 02 00 00 00       	mov    esi,0x2
  2d75db:	31 c0                	xor    eax,eax
  2d75dd:	48 83 c1 08          	add    rcx,0x8
  2d75e1:	e8 2a 5e f8 ff       	call   0x25d410
  2d75e6:	4b 8b 54 3e 50       	mov    rdx,QWORD PTR [r14+r15*1+0x50]
  2d75eb:	48 85 d2             	test   rdx,rdx
  2d75ee:	74 50                	je     0x2d7640
  2d75f0:	4b 8d 4c 3e 50       	lea    rcx,[r14+r15*1+0x50]
  2d75f5:	48 c1 ea 14          	shr    rdx,0x14
  2d75f9:	48 8d 3d 27 02 ff 00 	lea    rdi,[rip+0xff0227]        # 0x12c7827
  2d7600:	be 03 00 00 00       	mov    esi,0x3
  2d7605:	31 c0                	xor    eax,eax
  2d7607:	48 83 c1 08          	add    rcx,0x8
  2d760b:	e8 00 5e f8 ff       	call   0x25d410
  2d7610:	4b 8b 54 3e 78       	mov    rdx,QWORD PTR [r14+r15*1+0x78]
  2d7615:	48 85 d2             	test   rdx,rdx
  2d7618:	74 26                	je     0x2d7640
  2d761a:	4b 8d 4c 3e 78       	lea    rcx,[r14+r15*1+0x78]
  2d761f:	48 c1 ea 14          	shr    rdx,0x14
  2d7623:	48 8d 3d fd 01 ff 00 	lea    rdi,[rip+0xff01fd]        # 0x12c7827
  2d762a:	be 04 00 00 00       	mov    esi,0x4
  2d762f:	31 c0                	xor    eax,eax
  2d7631:	48 83 c1 08          	add    rcx,0x8
  2d7635:	e8 d6 5d f8 ff       	call   0x25d410
  2d763a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
  2d7640:	48 8d 1d d9 96 a8 02 	lea    rbx,[rip+0x2a896d9]        # 0x2d60d20
  2d7647:	41 8b 0c 1e          	mov    ecx,DWORD PTR [r14+rbx*1]
  2d764b:	85 c9                	test   ecx,ecx
  2d764d:	0f 84 0d 01 00 00    	je     0x2d7760
  2d7653:	4e 8d 04 33          	lea    r8,[rbx+r14*1]
  2d7657:	48 b8 cd cc cc cc cc 	movabs rax,0xcccccccccccccccd
  2d765e:	cc cc cc 
  2d7661:	48 8d 3d e0 bc 0c 01 	lea    rdi,[rip+0x10cbce0]        # 0x13a3348
  2d7668:	be 01 00 00 00       	mov    esi,0x1
  2d766d:	49 63 50 04          	movsxd rdx,DWORD PTR [r8+0x4]
  2d7671:	49 83 c0 08          	add    r8,0x8
  2d7675:	48 c1 e2 0e          	shl    rdx,0xe
  2d7679:	c4 e2 eb f6 d0       	mulx   rdx,rdx,rax
  2d767e:	31 c0                	xor    eax,eax
  2d7680:	48 c1 ea 16          	shr    rdx,0x16
  2d7684:	e8 87 5d f8 ff       	call   0x25d410
  2d7689:	41 8b 4c 1e 28       	mov    ecx,DWORD PTR [r14+rbx*1+0x28]
  2d768e:	85 c9                	test   ecx,ecx
  2d7690:	0f 84 ca 00 00 00    	je     0x2d7760
  2d7696:	4d 8d 44 1e 28       	lea    r8,[r14+rbx*1+0x28]
  2d769b:	48 b8 cd cc cc cc cc 	movabs rax,0xcccccccccccccccd
  2d76a2:	cc cc cc 
  2d76a5:	48 8d 3d 9c bc 0c 01 	lea    rdi,[rip+0x10cbc9c]        # 0x13a3348
  2d76ac:	be 02 00 00 00       	mov    esi,0x2
  2d76b1:	49 63 50 04          	movsxd rdx,DWORD PTR [r8+0x4]
  2d76b5:	49 83 c0 08          	add    r8,0x8
  2d76b9:	48 c1 e2 0e          	shl    rdx,0xe
  2d76bd:	c4 e2 eb f6 d0       	mulx   rdx,rdx,rax
  2d76c2:	31 c0                	xor    eax,eax
  2d76c4:	48 c1 ea 16          	shr    rdx,0x16
  2d76c8:	e8 43 5d f8 ff       	call   0x25d410
  2d76cd:	41 8b 4c 1e 50       	mov    ecx,DWORD PTR [r14+rbx*1+0x50]
  2d76d2:	85 c9                	test   ecx,ecx
  2d76d4:	0f 84 86 00 00 00    	je     0x2d7760
  2d76da:	4d 8d 44 1e 50       	lea    r8,[r14+rbx*1+0x50]
  2d76df:	48 b8 cd cc cc cc cc 	movabs rax,0xcccccccccccccccd
  2d76e6:	cc cc cc 
  2d76e9:	48 8d 3d 58 bc 0c 01 	lea    rdi,[rip+0x10cbc58]        # 0x13a3348
