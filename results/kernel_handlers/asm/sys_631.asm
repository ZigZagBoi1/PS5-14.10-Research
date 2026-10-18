; REA 6.7.0 full disassembly of handler_631.bin
; SHA256 c22afc5c7cc3a6c3a1387f51b7dfa46b1ee55bb4b399853fd85ca6e05596c78e; 4096 source bytes; 512 JMP functions and 1536 INT3 padding bytes.
; Input offset zero: runtime VA 0xffffffff8ac25760, kernel RVA 0x265760.
; REA inspect_with_objdump Evidence: ev_68a8c358dc5d875b44cd91ee2d3fc3736c11f21da13ca107df0ccd87213c33c6
; Exact-byte synthetic ELF adds analyst function symbols, no payload byte changes.
; GNU objdump AT&T syntax. Symbols with +offset are nearest-symbol arithmetic,
; not identification of an external jump destination. Function size is 5 bytes;
; the following 3 INT3 bytes are padding. All 4096 bytes verified below.
; Only first trampoline is syscall 631; remaining 511 are neighboring stubs.
; PART 1: COMPLETE ORIGINAL INPUT WINDOW


/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/rea_616_645_evidence/handler_631.input.elf:     file format elf64-x86-64


Disassembly of section .text:

ffffffff8ac25760 <handler_631_entry>:
ffffffff8ac25760:	e9 7b c9 2f 00       	jmp    ffffffff8af220e0 <neighbor_trampoline_266758+0x2fb988>
ffffffff8ac25765:	cc                   	int3
ffffffff8ac25766:	cc                   	int3
ffffffff8ac25767:	cc                   	int3

ffffffff8ac25768 <neighbor_trampoline_265768>:
ffffffff8ac25768:	e9 b3 08 15 00       	jmp    ffffffff8ad76020 <neighbor_trampoline_266758+0x14f8c8>
ffffffff8ac2576d:	cc                   	int3
ffffffff8ac2576e:	cc                   	int3
ffffffff8ac2576f:	cc                   	int3

ffffffff8ac25770 <neighbor_trampoline_265770>:
ffffffff8ac25770:	e9 cb 0a 15 00       	jmp    ffffffff8ad76240 <neighbor_trampoline_266758+0x14fae8>
ffffffff8ac25775:	cc                   	int3
ffffffff8ac25776:	cc                   	int3
ffffffff8ac25777:	cc                   	int3

ffffffff8ac25778 <neighbor_trampoline_265778>:
ffffffff8ac25778:	e9 93 c6 15 00       	jmp    ffffffff8ad81e10 <neighbor_trampoline_266758+0x15b6b8>
ffffffff8ac2577d:	cc                   	int3
ffffffff8ac2577e:	cc                   	int3
ffffffff8ac2577f:	cc                   	int3

ffffffff8ac25780 <neighbor_trampoline_265780>:
ffffffff8ac25780:	e9 bb ca 15 00       	jmp    ffffffff8ad82240 <neighbor_trampoline_266758+0x15bae8>
ffffffff8ac25785:	cc                   	int3
ffffffff8ac25786:	cc                   	int3
ffffffff8ac25787:	cc                   	int3

ffffffff8ac25788 <neighbor_trampoline_265788>:
ffffffff8ac25788:	e9 53 a0 ec ff       	jmp    ffffffff8aaef7e0 <handler_631_entry-0x135f80>
ffffffff8ac2578d:	cc                   	int3
ffffffff8ac2578e:	cc                   	int3
ffffffff8ac2578f:	cc                   	int3

ffffffff8ac25790 <neighbor_trampoline_265790>:
ffffffff8ac25790:	e9 bb 89 16 00       	jmp    ffffffff8ad8e150 <neighbor_trampoline_266758+0x1679f8>
ffffffff8ac25795:	cc                   	int3
ffffffff8ac25796:	cc                   	int3
ffffffff8ac25797:	cc                   	int3

ffffffff8ac25798 <neighbor_trampoline_265798>:
ffffffff8ac25798:	e9 13 fb 16 00       	jmp    ffffffff8ad952b0 <neighbor_trampoline_266758+0x16eb58>
ffffffff8ac2579d:	cc                   	int3
ffffffff8ac2579e:	cc                   	int3
ffffffff8ac2579f:	cc                   	int3

ffffffff8ac257a0 <neighbor_trampoline_2657a0>:
ffffffff8ac257a0:	e9 fb 02 18 00       	jmp    ffffffff8ada5aa0 <neighbor_trampoline_266758+0x17f348>
ffffffff8ac257a5:	cc                   	int3
ffffffff8ac257a6:	cc                   	int3
ffffffff8ac257a7:	cc                   	int3

ffffffff8ac257a8 <neighbor_trampoline_2657a8>:
ffffffff8ac257a8:	e9 23 03 18 00       	jmp    ffffffff8ada5ad0 <neighbor_trampoline_266758+0x17f378>
ffffffff8ac257ad:	cc                   	int3
ffffffff8ac257ae:	cc                   	int3
ffffffff8ac257af:	cc                   	int3

ffffffff8ac257b0 <neighbor_trampoline_2657b0>:
ffffffff8ac257b0:	e9 3b 03 18 00       	jmp    ffffffff8ada5af0 <neighbor_trampoline_266758+0x17f398>
ffffffff8ac257b5:	cc                   	int3
ffffffff8ac257b6:	cc                   	int3
ffffffff8ac257b7:	cc                   	int3

ffffffff8ac257b8 <neighbor_trampoline_2657b8>:
ffffffff8ac257b8:	e9 83 6b 18 00       	jmp    ffffffff8adac340 <neighbor_trampoline_266758+0x185be8>
ffffffff8ac257bd:	cc                   	int3
ffffffff8ac257be:	cc                   	int3
ffffffff8ac257bf:	cc                   	int3

ffffffff8ac257c0 <neighbor_trampoline_2657c0>:
ffffffff8ac257c0:	e9 fb ad 18 00       	jmp    ffffffff8adb05c0 <neighbor_trampoline_266758+0x189e68>
ffffffff8ac257c5:	cc                   	int3
ffffffff8ac257c6:	cc                   	int3
ffffffff8ac257c7:	cc                   	int3

ffffffff8ac257c8 <neighbor_trampoline_2657c8>:
ffffffff8ac257c8:	e9 43 d0 18 00       	jmp    ffffffff8adb2810 <neighbor_trampoline_266758+0x18c0b8>
ffffffff8ac257cd:	cc                   	int3
ffffffff8ac257ce:	cc                   	int3
ffffffff8ac257cf:	cc                   	int3

ffffffff8ac257d0 <neighbor_trampoline_2657d0>:
ffffffff8ac257d0:	e9 8b d3 18 00       	jmp    ffffffff8adb2b60 <neighbor_trampoline_266758+0x18c408>
ffffffff8ac257d5:	cc                   	int3
ffffffff8ac257d6:	cc                   	int3
ffffffff8ac257d7:	cc                   	int3

ffffffff8ac257d8 <neighbor_trampoline_2657d8>:
ffffffff8ac257d8:	e9 43 76 2a 00       	jmp    ffffffff8aecce20 <neighbor_trampoline_266758+0x2a66c8>
ffffffff8ac257dd:	cc                   	int3
ffffffff8ac257de:	cc                   	int3
ffffffff8ac257df:	cc                   	int3

ffffffff8ac257e0 <neighbor_trampoline_2657e0>:
ffffffff8ac257e0:	e9 ab e7 18 00       	jmp    ffffffff8adb3f90 <neighbor_trampoline_266758+0x18d838>
ffffffff8ac257e5:	cc                   	int3
ffffffff8ac257e6:	cc                   	int3
ffffffff8ac257e7:	cc                   	int3

ffffffff8ac257e8 <neighbor_trampoline_2657e8>:
ffffffff8ac257e8:	e9 a3 3f 1a 00       	jmp    ffffffff8adc9790 <neighbor_trampoline_266758+0x1a3038>
ffffffff8ac257ed:	cc                   	int3
ffffffff8ac257ee:	cc                   	int3
ffffffff8ac257ef:	cc                   	int3

ffffffff8ac257f0 <neighbor_trampoline_2657f0>:
ffffffff8ac257f0:	e9 4b 1a 98 00       	jmp    ffffffff8b5a7240 <neighbor_trampoline_266758+0x980ae8>
ffffffff8ac257f5:	cc                   	int3
ffffffff8ac257f6:	cc                   	int3
ffffffff8ac257f7:	cc                   	int3

ffffffff8ac257f8 <neighbor_trampoline_2657f8>:
ffffffff8ac257f8:	e9 93 bb a4 00       	jmp    ffffffff8b671390 <neighbor_trampoline_266758+0xa4ac38>
ffffffff8ac257fd:	cc                   	int3
ffffffff8ac257fe:	cc                   	int3
ffffffff8ac257ff:	cc                   	int3

ffffffff8ac25800 <neighbor_trampoline_265800>:
ffffffff8ac25800:	e9 fb 67 28 00       	jmp    ffffffff8aeac000 <neighbor_trampoline_266758+0x2858a8>
ffffffff8ac25805:	cc                   	int3
ffffffff8ac25806:	cc                   	int3
ffffffff8ac25807:	cc                   	int3

ffffffff8ac25808 <neighbor_trampoline_265808>:
ffffffff8ac25808:	e9 53 6d 28 00       	jmp    ffffffff8aeac560 <neighbor_trampoline_266758+0x285e08>
ffffffff8ac2580d:	cc                   	int3
ffffffff8ac2580e:	cc                   	int3
ffffffff8ac2580f:	cc                   	int3

ffffffff8ac25810 <neighbor_trampoline_265810>:
ffffffff8ac25810:	e9 eb 15 69 00       	jmp    ffffffff8b2b6e00 <neighbor_trampoline_266758+0x6906a8>
ffffffff8ac25815:	cc                   	int3
ffffffff8ac25816:	cc                   	int3
ffffffff8ac25817:	cc                   	int3

ffffffff8ac25818 <neighbor_trampoline_265818>:
ffffffff8ac25818:	e9 e3 66 4c 00       	jmp    ffffffff8b0ebf00 <neighbor_trampoline_266758+0x4c57a8>
ffffffff8ac2581d:	cc                   	int3
ffffffff8ac2581e:	cc                   	int3
ffffffff8ac2581f:	cc                   	int3

ffffffff8ac25820 <neighbor_trampoline_265820>:
ffffffff8ac25820:	e9 6b 2a 98 00       	jmp    ffffffff8b5a8290 <neighbor_trampoline_266758+0x981b38>
ffffffff8ac25825:	cc                   	int3
ffffffff8ac25826:	cc                   	int3
ffffffff8ac25827:	cc                   	int3

ffffffff8ac25828 <neighbor_trampoline_265828>:
ffffffff8ac25828:	e9 23 2d 69 00       	jmp    ffffffff8b2b8550 <neighbor_trampoline_266758+0x691df8>
ffffffff8ac2582d:	cc                   	int3
ffffffff8ac2582e:	cc                   	int3
ffffffff8ac2582f:	cc                   	int3

ffffffff8ac25830 <neighbor_trampoline_265830>:
ffffffff8ac25830:	e9 eb 12 69 00       	jmp    ffffffff8b2b6b20 <neighbor_trampoline_266758+0x6903c8>
ffffffff8ac25835:	cc                   	int3
ffffffff8ac25836:	cc                   	int3
ffffffff8ac25837:	cc                   	int3

ffffffff8ac25838 <neighbor_trampoline_265838>:
ffffffff8ac25838:	e9 03 43 69 00       	jmp    ffffffff8b2b9b40 <neighbor_trampoline_266758+0x6933e8>
ffffffff8ac2583d:	cc                   	int3
ffffffff8ac2583e:	cc                   	int3
ffffffff8ac2583f:	cc                   	int3

ffffffff8ac25840 <neighbor_trampoline_265840>:
ffffffff8ac25840:	e9 9b d1 2c 00       	jmp    ffffffff8aef29e0 <neighbor_trampoline_266758+0x2cc288>
ffffffff8ac25845:	cc                   	int3
ffffffff8ac25846:	cc                   	int3
ffffffff8ac25847:	cc                   	int3

ffffffff8ac25848 <neighbor_trampoline_265848>:
ffffffff8ac25848:	e9 93 c9 2c 00       	jmp    ffffffff8aef21e0 <neighbor_trampoline_266758+0x2cba88>
ffffffff8ac2584d:	cc                   	int3
ffffffff8ac2584e:	cc                   	int3
ffffffff8ac2584f:	cc                   	int3

ffffffff8ac25850 <neighbor_trampoline_265850>:
ffffffff8ac25850:	e9 7b d0 2c 00       	jmp    ffffffff8aef28d0 <neighbor_trampoline_266758+0x2cc178>
ffffffff8ac25855:	cc                   	int3
ffffffff8ac25856:	cc                   	int3
ffffffff8ac25857:	cc                   	int3

ffffffff8ac25858 <neighbor_trampoline_265858>:
ffffffff8ac25858:	e9 23 b8 2c 00       	jmp    ffffffff8aef1080 <neighbor_trampoline_266758+0x2ca928>
ffffffff8ac2585d:	cc                   	int3
ffffffff8ac2585e:	cc                   	int3
ffffffff8ac2585f:	cc                   	int3

ffffffff8ac25860 <neighbor_trampoline_265860>:
ffffffff8ac25860:	e9 ab da 2c 00       	jmp    ffffffff8aef3310 <neighbor_trampoline_266758+0x2ccbb8>
ffffffff8ac25865:	cc                   	int3
ffffffff8ac25866:	cc                   	int3
ffffffff8ac25867:	cc                   	int3

ffffffff8ac25868 <neighbor_trampoline_265868>:
ffffffff8ac25868:	e9 c3 d7 2c 00       	jmp    ffffffff8aef3030 <neighbor_trampoline_266758+0x2cc8d8>
ffffffff8ac2586d:	cc                   	int3
ffffffff8ac2586e:	cc                   	int3
ffffffff8ac2586f:	cc                   	int3

ffffffff8ac25870 <neighbor_trampoline_265870>:
ffffffff8ac25870:	e9 6b 33 69 00       	jmp    ffffffff8b2b8be0 <neighbor_trampoline_266758+0x692488>
ffffffff8ac25875:	cc                   	int3
ffffffff8ac25876:	cc                   	int3
ffffffff8ac25877:	cc                   	int3

ffffffff8ac25878 <neighbor_trampoline_265878>:
ffffffff8ac25878:	e9 33 3d 69 00       	jmp    ffffffff8b2b95b0 <neighbor_trampoline_266758+0x692e58>
ffffffff8ac2587d:	cc                   	int3
ffffffff8ac2587e:	cc                   	int3
ffffffff8ac2587f:	cc                   	int3

ffffffff8ac25880 <neighbor_trampoline_265880>:
ffffffff8ac25880:	e9 db 3e 69 00       	jmp    ffffffff8b2b9760 <neighbor_trampoline_266758+0x693008>
ffffffff8ac25885:	cc                   	int3
ffffffff8ac25886:	cc                   	int3
ffffffff8ac25887:	cc                   	int3

ffffffff8ac25888 <neighbor_trampoline_265888>:
ffffffff8ac25888:	e9 93 04 69 00       	jmp    ffffffff8b2b5d20 <neighbor_trampoline_266758+0x68f5c8>
ffffffff8ac2588d:	cc                   	int3
ffffffff8ac2588e:	cc                   	int3
ffffffff8ac2588f:	cc                   	int3

ffffffff8ac25890 <neighbor_trampoline_265890>:
ffffffff8ac25890:	e9 1b 9d 2f 00       	jmp    ffffffff8af1f5b0 <neighbor_trampoline_266758+0x2f8e58>
ffffffff8ac25895:	cc                   	int3
ffffffff8ac25896:	cc                   	int3
ffffffff8ac25897:	cc                   	int3

ffffffff8ac25898 <neighbor_trampoline_265898>:
ffffffff8ac25898:	e9 e3 44 4c 00       	jmp    ffffffff8b0e9d80 <neighbor_trampoline_266758+0x4c3628>
ffffffff8ac2589d:	cc                   	int3
ffffffff8ac2589e:	cc                   	int3
ffffffff8ac2589f:	cc                   	int3

ffffffff8ac258a0 <neighbor_trampoline_2658a0>:
ffffffff8ac258a0:	e9 eb d4 59 00       	jmp    ffffffff8b1c2d90 <neighbor_trampoline_266758+0x59c638>
ffffffff8ac258a5:	cc                   	int3
ffffffff8ac258a6:	cc                   	int3
ffffffff8ac258a7:	cc                   	int3

ffffffff8ac258a8 <neighbor_trampoline_2658a8>:
ffffffff8ac258a8:	e9 23 8c 1f 00       	jmp    ffffffff8ae1e4d0 <neighbor_trampoline_266758+0x1f7d78>
ffffffff8ac258ad:	cc                   	int3
ffffffff8ac258ae:	cc                   	int3
ffffffff8ac258af:	cc                   	int3

ffffffff8ac258b0 <neighbor_trampoline_2658b0>:
ffffffff8ac258b0:	e9 4b 9b 2f 00       	jmp    ffffffff8af1f400 <neighbor_trampoline_266758+0x2f8ca8>
ffffffff8ac258b5:	cc                   	int3
ffffffff8ac258b6:	cc                   	int3
ffffffff8ac258b7:	cc                   	int3

ffffffff8ac258b8 <neighbor_trampoline_2658b8>:
ffffffff8ac258b8:	e9 83 76 28 00       	jmp    ffffffff8aeacf40 <neighbor_trampoline_266758+0x2867e8>
ffffffff8ac258bd:	cc                   	int3
ffffffff8ac258be:	cc                   	int3
ffffffff8ac258bf:	cc                   	int3

ffffffff8ac258c0 <neighbor_trampoline_2658c0>:
ffffffff8ac258c0:	e9 4b ef 57 00       	jmp    ffffffff8b1a4810 <neighbor_trampoline_266758+0x57e0b8>
ffffffff8ac258c5:	cc                   	int3
ffffffff8ac258c6:	cc                   	int3
ffffffff8ac258c7:	cc                   	int3

ffffffff8ac258c8 <neighbor_trampoline_2658c8>:
ffffffff8ac258c8:	e9 c3 6b 69 00       	jmp    ffffffff8b2bc490 <neighbor_trampoline_266758+0x695d38>
ffffffff8ac258cd:	cc                   	int3
ffffffff8ac258ce:	cc                   	int3
ffffffff8ac258cf:	cc                   	int3

ffffffff8ac258d0 <neighbor_trampoline_2658d0>:
ffffffff8ac258d0:	e9 eb d4 47 00       	jmp    ffffffff8b0a2dc0 <neighbor_trampoline_266758+0x47c668>
ffffffff8ac258d5:	cc                   	int3
ffffffff8ac258d6:	cc                   	int3
ffffffff8ac258d7:	cc                   	int3

ffffffff8ac258d8 <neighbor_trampoline_2658d8>:
ffffffff8ac258d8:	e9 13 32 85 00       	jmp    ffffffff8b478af0 <neighbor_trampoline_266758+0x852398>
ffffffff8ac258dd:	cc                   	int3
ffffffff8ac258de:	cc                   	int3
ffffffff8ac258df:	cc                   	int3

ffffffff8ac258e0 <neighbor_trampoline_2658e0>:
ffffffff8ac258e0:	e9 cb 32 85 00       	jmp    ffffffff8b478bb0 <neighbor_trampoline_266758+0x852458>
ffffffff8ac258e5:	cc                   	int3
ffffffff8ac258e6:	cc                   	int3
ffffffff8ac258e7:	cc                   	int3

ffffffff8ac258e8 <neighbor_trampoline_2658e8>:
ffffffff8ac258e8:	e9 33 34 85 00       	jmp    ffffffff8b478d20 <neighbor_trampoline_266758+0x8525c8>
ffffffff8ac258ed:	cc                   	int3
ffffffff8ac258ee:	cc                   	int3
ffffffff8ac258ef:	cc                   	int3

ffffffff8ac258f0 <neighbor_trampoline_2658f0>:
ffffffff8ac258f0:	e9 0b 35 85 00       	jmp    ffffffff8b478e00 <neighbor_trampoline_266758+0x8526a8>
ffffffff8ac258f5:	cc                   	int3
ffffffff8ac258f6:	cc                   	int3
ffffffff8ac258f7:	cc                   	int3

ffffffff8ac258f8 <neighbor_trampoline_2658f8>:
ffffffff8ac258f8:	e9 c3 35 85 00       	jmp    ffffffff8b478ec0 <neighbor_trampoline_266758+0x852768>
ffffffff8ac258fd:	cc                   	int3
ffffffff8ac258fe:	cc                   	int3
ffffffff8ac258ff:	cc                   	int3

ffffffff8ac25900 <neighbor_trampoline_265900>:
ffffffff8ac25900:	e9 bb 73 45 00       	jmp    ffffffff8b07ccc0 <neighbor_trampoline_266758+0x456568>
ffffffff8ac25905:	cc                   	int3
ffffffff8ac25906:	cc                   	int3
ffffffff8ac25907:	cc                   	int3

ffffffff8ac25908 <neighbor_trampoline_265908>:
ffffffff8ac25908:	e9 13 71 45 00       	jmp    ffffffff8b07ca20 <neighbor_trampoline_266758+0x4562c8>
ffffffff8ac2590d:	cc                   	int3
ffffffff8ac2590e:	cc                   	int3
ffffffff8ac2590f:	cc                   	int3

ffffffff8ac25910 <neighbor_trampoline_265910>:
ffffffff8ac25910:	e9 db 40 4c 00       	jmp    ffffffff8b0e99f0 <neighbor_trampoline_266758+0x4c3298>
ffffffff8ac25915:	cc                   	int3
ffffffff8ac25916:	cc                   	int3
ffffffff8ac25917:	cc                   	int3

ffffffff8ac25918 <neighbor_trampoline_265918>:
ffffffff8ac25918:	e9 23 41 4c 00       	jmp    ffffffff8b0e9a40 <neighbor_trampoline_266758+0x4c32e8>
ffffffff8ac2591d:	cc                   	int3
ffffffff8ac2591e:	cc                   	int3
ffffffff8ac2591f:	cc                   	int3

ffffffff8ac25920 <neighbor_trampoline_265920>:
ffffffff8ac25920:	e9 9b 44 4c 00       	jmp    ffffffff8b0e9dc0 <neighbor_trampoline_266758+0x4c3668>
ffffffff8ac25925:	cc                   	int3
ffffffff8ac25926:	cc                   	int3
ffffffff8ac25927:	cc                   	int3

ffffffff8ac25928 <neighbor_trampoline_265928>:
ffffffff8ac25928:	e9 83 8b 28 00       	jmp    ffffffff8aeae4b0 <neighbor_trampoline_266758+0x287d58>
ffffffff8ac2592d:	cc                   	int3
ffffffff8ac2592e:	cc                   	int3
ffffffff8ac2592f:	cc                   	int3

ffffffff8ac25930 <neighbor_trampoline_265930>:
ffffffff8ac25930:	e9 fb 5a 69 00       	jmp    ffffffff8b2bb430 <neighbor_trampoline_266758+0x694cd8>
ffffffff8ac25935:	cc                   	int3
ffffffff8ac25936:	cc                   	int3
ffffffff8ac25937:	cc                   	int3

ffffffff8ac25938 <neighbor_trampoline_265938>:
ffffffff8ac25938:	e9 43 a6 23 00       	jmp    ffffffff8ae5ff80 <neighbor_trampoline_266758+0x239828>
ffffffff8ac2593d:	cc                   	int3
ffffffff8ac2593e:	cc                   	int3
ffffffff8ac2593f:	cc                   	int3

ffffffff8ac25940 <neighbor_trampoline_265940>:
ffffffff8ac25940:	e9 ab 9f 2c 00       	jmp    ffffffff8aeef8f0 <neighbor_trampoline_266758+0x2c9198>
ffffffff8ac25945:	cc                   	int3
ffffffff8ac25946:	cc                   	int3
ffffffff8ac25947:	cc                   	int3

ffffffff8ac25948 <neighbor_trampoline_265948>:
ffffffff8ac25948:	e9 13 b9 2c 00       	jmp    ffffffff8aef1260 <neighbor_trampoline_266758+0x2cab08>
ffffffff8ac2594d:	cc                   	int3
ffffffff8ac2594e:	cc                   	int3
ffffffff8ac2594f:	cc                   	int3

ffffffff8ac25950 <neighbor_trampoline_265950>:
ffffffff8ac25950:	e9 8b a3 2c 00       	jmp    ffffffff8aeefce0 <neighbor_trampoline_266758+0x2c9588>
ffffffff8ac25955:	cc                   	int3
ffffffff8ac25956:	cc                   	int3
ffffffff8ac25957:	cc                   	int3

ffffffff8ac25958 <neighbor_trampoline_265958>:
ffffffff8ac25958:	e9 93 a3 23 00       	jmp    ffffffff8ae5fcf0 <neighbor_trampoline_266758+0x239598>
ffffffff8ac2595d:	cc                   	int3
ffffffff8ac2595e:	cc                   	int3
ffffffff8ac2595f:	cc                   	int3

ffffffff8ac25960 <neighbor_trampoline_265960>:
ffffffff8ac25960:	e9 9b a3 2c 00       	jmp    ffffffff8aeefd00 <neighbor_trampoline_266758+0x2c95a8>
ffffffff8ac25965:	cc                   	int3
ffffffff8ac25966:	cc                   	int3
ffffffff8ac25967:	cc                   	int3

ffffffff8ac25968 <neighbor_trampoline_265968>:
ffffffff8ac25968:	e9 93 a4 2c 00       	jmp    ffffffff8aeefe00 <neighbor_trampoline_266758+0x2c96a8>
ffffffff8ac2596d:	cc                   	int3
ffffffff8ac2596e:	cc                   	int3
ffffffff8ac2596f:	cc                   	int3

ffffffff8ac25970 <neighbor_trampoline_265970>:
ffffffff8ac25970:	e9 0b ab 2c 00       	jmp    ffffffff8aef0480 <neighbor_trampoline_266758+0x2c9d28>
ffffffff8ac25975:	cc                   	int3
ffffffff8ac25976:	cc                   	int3
ffffffff8ac25977:	cc                   	int3

ffffffff8ac25978 <neighbor_trampoline_265978>:
ffffffff8ac25978:	e9 43 d2 2c 00       	jmp    ffffffff8aef2bc0 <neighbor_trampoline_266758+0x2cc468>
ffffffff8ac2597d:	cc                   	int3
ffffffff8ac2597e:	cc                   	int3
ffffffff8ac2597f:	cc                   	int3

ffffffff8ac25980 <neighbor_trampoline_265980>:
ffffffff8ac25980:	e9 4b ae 2c 00       	jmp    ffffffff8aef07d0 <neighbor_trampoline_266758+0x2ca078>
ffffffff8ac25985:	cc                   	int3
ffffffff8ac25986:	cc                   	int3
ffffffff8ac25987:	cc                   	int3

ffffffff8ac25988 <neighbor_trampoline_265988>:
ffffffff8ac25988:	e9 53 a1 2c 00       	jmp    ffffffff8aeefae0 <neighbor_trampoline_266758+0x2c9388>
ffffffff8ac2598d:	cc                   	int3
ffffffff8ac2598e:	cc                   	int3
ffffffff8ac2598f:	cc                   	int3

ffffffff8ac25990 <neighbor_trampoline_265990>:
ffffffff8ac25990:	e9 ab 67 4c 00       	jmp    ffffffff8b0ec140 <neighbor_trampoline_266758+0x4c59e8>
ffffffff8ac25995:	cc                   	int3
ffffffff8ac25996:	cc                   	int3
ffffffff8ac25997:	cc                   	int3

ffffffff8ac25998 <neighbor_trampoline_265998>:
ffffffff8ac25998:	e9 63 6e 45 00       	jmp    ffffffff8b07c800 <neighbor_trampoline_266758+0x4560a8>
ffffffff8ac2599d:	cc                   	int3
ffffffff8ac2599e:	cc                   	int3
ffffffff8ac2599f:	cc                   	int3

ffffffff8ac259a0 <neighbor_trampoline_2659a0>:
ffffffff8ac259a0:	e9 fb c1 23 00       	jmp    ffffffff8ae61ba0 <neighbor_trampoline_266758+0x23b448>
ffffffff8ac259a5:	cc                   	int3
ffffffff8ac259a6:	cc                   	int3
ffffffff8ac259a7:	cc                   	int3

ffffffff8ac259a8 <neighbor_trampoline_2659a8>:
ffffffff8ac259a8:	e9 23 d3 2c 00       	jmp    ffffffff8aef2cd0 <neighbor_trampoline_266758+0x2cc578>
ffffffff8ac259ad:	cc                   	int3
ffffffff8ac259ae:	cc                   	int3
ffffffff8ac259af:	cc                   	int3

ffffffff8ac259b0 <neighbor_trampoline_2659b0>:
ffffffff8ac259b0:	e9 0b 69 28 00       	jmp    ffffffff8aeac2c0 <neighbor_trampoline_266758+0x285b68>
ffffffff8ac259b5:	cc                   	int3
ffffffff8ac259b6:	cc                   	int3
ffffffff8ac259b7:	cc                   	int3

ffffffff8ac259b8 <neighbor_trampoline_2659b8>:
ffffffff8ac259b8:	e9 23 6f 28 00       	jmp    ffffffff8aeac8e0 <neighbor_trampoline_266758+0x286188>
ffffffff8ac259bd:	cc                   	int3
ffffffff8ac259be:	cc                   	int3
ffffffff8ac259bf:	cc                   	int3

ffffffff8ac259c0 <neighbor_trampoline_2659c0>:
ffffffff8ac259c0:	e9 0b 6f 45 00       	jmp    ffffffff8b07c8d0 <neighbor_trampoline_266758+0x456178>
ffffffff8ac259c5:	cc                   	int3
ffffffff8ac259c6:	cc                   	int3
ffffffff8ac259c7:	cc                   	int3

ffffffff8ac259c8 <neighbor_trampoline_2659c8>:
ffffffff8ac259c8:	e9 73 43 69 00       	jmp    ffffffff8b2b9d40 <neighbor_trampoline_266758+0x6935e8>
ffffffff8ac259cd:	cc                   	int3
ffffffff8ac259ce:	cc                   	int3
ffffffff8ac259cf:	cc                   	int3

ffffffff8ac259d0 <neighbor_trampoline_2659d0>:
ffffffff8ac259d0:	e9 9b a4 2c 00       	jmp    ffffffff8aeefe70 <neighbor_trampoline_266758+0x2c9718>
ffffffff8ac259d5:	cc                   	int3
ffffffff8ac259d6:	cc                   	int3
ffffffff8ac259d7:	cc                   	int3

ffffffff8ac259d8 <neighbor_trampoline_2659d8>:
ffffffff8ac259d8:	e9 73 5a 69 00       	jmp    ffffffff8b2bb450 <neighbor_trampoline_266758+0x694cf8>
ffffffff8ac259dd:	cc                   	int3
ffffffff8ac259de:	cc                   	int3
ffffffff8ac259df:	cc                   	int3

ffffffff8ac259e0 <neighbor_trampoline_2659e0>:
ffffffff8ac259e0:	e9 ab 8b 4c 00       	jmp    ffffffff8b0ee590 <neighbor_trampoline_266758+0x4c7e38>
ffffffff8ac259e5:	cc                   	int3
ffffffff8ac259e6:	cc                   	int3
ffffffff8ac259e7:	cc                   	int3

ffffffff8ac259e8 <neighbor_trampoline_2659e8>:
ffffffff8ac259e8:	e9 43 c1 2c 00       	jmp    ffffffff8aef1b30 <neighbor_trampoline_266758+0x2cb3d8>
ffffffff8ac259ed:	cc                   	int3
ffffffff8ac259ee:	cc                   	int3
ffffffff8ac259ef:	cc                   	int3

ffffffff8ac259f0 <neighbor_trampoline_2659f0>:
ffffffff8ac259f0:	e9 fb d0 2c 00       	jmp    ffffffff8aef2af0 <neighbor_trampoline_266758+0x2cc398>
ffffffff8ac259f5:	cc                   	int3
ffffffff8ac259f6:	cc                   	int3
ffffffff8ac259f7:	cc                   	int3

ffffffff8ac259f8 <neighbor_trampoline_2659f8>:
ffffffff8ac259f8:	e9 23 bd 2c 00       	jmp    ffffffff8aef1720 <neighbor_trampoline_266758+0x2cafc8>
ffffffff8ac259fd:	cc                   	int3
ffffffff8ac259fe:	cc                   	int3
ffffffff8ac259ff:	cc                   	int3

ffffffff8ac25a00 <neighbor_trampoline_265a00>:
ffffffff8ac25a00:	e9 db 5e 69 00       	jmp    ffffffff8b2bb8e0 <neighbor_trampoline_266758+0x695188>
ffffffff8ac25a05:	cc                   	int3
ffffffff8ac25a06:	cc                   	int3
ffffffff8ac25a07:	cc                   	int3

ffffffff8ac25a08 <neighbor_trampoline_265a08>:
ffffffff8ac25a08:	e9 b3 61 69 00       	jmp    ffffffff8b2bbbc0 <neighbor_trampoline_266758+0x695468>
ffffffff8ac25a0d:	cc                   	int3
ffffffff8ac25a0e:	cc                   	int3
ffffffff8ac25a0f:	cc                   	int3

ffffffff8ac25a10 <neighbor_trampoline_265a10>:
ffffffff8ac25a10:	e9 fb 48 69 00       	jmp    ffffffff8b2ba310 <neighbor_trampoline_266758+0x693bb8>
ffffffff8ac25a15:	cc                   	int3
ffffffff8ac25a16:	cc                   	int3
ffffffff8ac25a17:	cc                   	int3

ffffffff8ac25a18 <neighbor_trampoline_265a18>:
ffffffff8ac25a18:	e9 13 56 21 00       	jmp    ffffffff8ae3b030 <neighbor_trampoline_266758+0x2148d8>
ffffffff8ac25a1d:	cc                   	int3
ffffffff8ac25a1e:	cc                   	int3
ffffffff8ac25a1f:	cc                   	int3

ffffffff8ac25a20 <neighbor_trampoline_265a20>:
ffffffff8ac25a20:	e9 fb 33 69 00       	jmp    ffffffff8b2b8e20 <neighbor_trampoline_266758+0x6926c8>
ffffffff8ac25a25:	cc                   	int3
ffffffff8ac25a26:	cc                   	int3
ffffffff8ac25a27:	cc                   	int3

ffffffff8ac25a28 <neighbor_trampoline_265a28>:
ffffffff8ac25a28:	e9 23 67 4c 00       	jmp    ffffffff8b0ec150 <neighbor_trampoline_266758+0x4c59f8>
ffffffff8ac25a2d:	cc                   	int3
ffffffff8ac25a2e:	cc                   	int3
ffffffff8ac25a2f:	cc                   	int3

ffffffff8ac25a30 <neighbor_trampoline_265a30>:
ffffffff8ac25a30:	e9 2b 38 69 00       	jmp    ffffffff8b2b9260 <neighbor_trampoline_266758+0x692b08>
ffffffff8ac25a35:	cc                   	int3
ffffffff8ac25a36:	cc                   	int3
ffffffff8ac25a37:	cc                   	int3

ffffffff8ac25a38 <neighbor_trampoline_265a38>:
ffffffff8ac25a38:	e9 d3 38 69 00       	jmp    ffffffff8b2b9310 <neighbor_trampoline_266758+0x692bb8>
ffffffff8ac25a3d:	cc                   	int3
ffffffff8ac25a3e:	cc                   	int3
ffffffff8ac25a3f:	cc                   	int3

ffffffff8ac25a40 <neighbor_trampoline_265a40>:
ffffffff8ac25a40:	e9 9b 69 4c 00       	jmp    ffffffff8b0ec3e0 <neighbor_trampoline_266758+0x4c5c88>
ffffffff8ac25a45:	cc                   	int3
ffffffff8ac25a46:	cc                   	int3
ffffffff8ac25a47:	cc                   	int3

ffffffff8ac25a48 <neighbor_trampoline_265a48>:
ffffffff8ac25a48:	e9 93 b9 23 00       	jmp    ffffffff8ae613e0 <neighbor_trampoline_266758+0x23ac88>
ffffffff8ac25a4d:	cc                   	int3
ffffffff8ac25a4e:	cc                   	int3
ffffffff8ac25a4f:	cc                   	int3

ffffffff8ac25a50 <neighbor_trampoline_265a50>:
ffffffff8ac25a50:	e9 db b1 23 00       	jmp    ffffffff8ae60c30 <neighbor_trampoline_266758+0x23a4d8>
ffffffff8ac25a55:	cc                   	int3
ffffffff8ac25a56:	cc                   	int3
ffffffff8ac25a57:	cc                   	int3

ffffffff8ac25a58 <neighbor_trampoline_265a58>:
ffffffff8ac25a58:	e9 83 61 69 00       	jmp    ffffffff8b2bbbe0 <neighbor_trampoline_266758+0x695488>
ffffffff8ac25a5d:	cc                   	int3
ffffffff8ac25a5e:	cc                   	int3
ffffffff8ac25a5f:	cc                   	int3

ffffffff8ac25a60 <neighbor_trampoline_265a60>:
ffffffff8ac25a60:	e9 7b 27 2f 00       	jmp    ffffffff8af181e0 <neighbor_trampoline_266758+0x2f1a88>
ffffffff8ac25a65:	cc                   	int3
ffffffff8ac25a66:	cc                   	int3
ffffffff8ac25a67:	cc                   	int3

ffffffff8ac25a68 <neighbor_trampoline_265a68>:
ffffffff8ac25a68:	e9 e3 39 85 00       	jmp    ffffffff8b479450 <neighbor_trampoline_266758+0x852cf8>
ffffffff8ac25a6d:	cc                   	int3
ffffffff8ac25a6e:	cc                   	int3
ffffffff8ac25a6f:	cc                   	int3

ffffffff8ac25a70 <neighbor_trampoline_265a70>:
ffffffff8ac25a70:	e9 9b 3c 85 00       	jmp    ffffffff8b479710 <neighbor_trampoline_266758+0x852fb8>
ffffffff8ac25a75:	cc                   	int3
ffffffff8ac25a76:	cc                   	int3
ffffffff8ac25a77:	cc                   	int3

ffffffff8ac25a78 <neighbor_trampoline_265a78>:
ffffffff8ac25a78:	e9 63 4e 69 00       	jmp    ffffffff8b2ba8e0 <neighbor_trampoline_266758+0x694188>
ffffffff8ac25a7d:	cc                   	int3
ffffffff8ac25a7e:	cc                   	int3
ffffffff8ac25a7f:	cc                   	int3

ffffffff8ac25a80 <neighbor_trampoline_265a80>:
ffffffff8ac25a80:	e9 cb 8a 28 00       	jmp    ffffffff8aeae550 <neighbor_trampoline_266758+0x287df8>
ffffffff8ac25a85:	cc                   	int3
ffffffff8ac25a86:	cc                   	int3
ffffffff8ac25a87:	cc                   	int3

ffffffff8ac25a88 <neighbor_trampoline_265a88>:
ffffffff8ac25a88:	e9 83 6d 69 00       	jmp    ffffffff8b2bc810 <neighbor_trampoline_266758+0x6960b8>
ffffffff8ac25a8d:	cc                   	int3
ffffffff8ac25a8e:	cc                   	int3
ffffffff8ac25a8f:	cc                   	int3

ffffffff8ac25a90 <neighbor_trampoline_265a90>:
ffffffff8ac25a90:	e9 8b 6d 69 00       	jmp    ffffffff8b2bc820 <neighbor_trampoline_266758+0x6960c8>
ffffffff8ac25a95:	cc                   	int3
ffffffff8ac25a96:	cc                   	int3
ffffffff8ac25a97:	cc                   	int3

ffffffff8ac25a98 <neighbor_trampoline_265a98>:
ffffffff8ac25a98:	e9 d3 5b 45 00       	jmp    ffffffff8b07b670 <neighbor_trampoline_266758+0x454f18>
ffffffff8ac25a9d:	cc                   	int3
ffffffff8ac25a9e:	cc                   	int3
ffffffff8ac25a9f:	cc                   	int3

ffffffff8ac25aa0 <neighbor_trampoline_265aa0>:
ffffffff8ac25aa0:	e9 7b 62 45 00       	jmp    ffffffff8b07bd20 <neighbor_trampoline_266758+0x4555c8>
ffffffff8ac25aa5:	cc                   	int3
ffffffff8ac25aa6:	cc                   	int3
ffffffff8ac25aa7:	cc                   	int3

ffffffff8ac25aa8 <neighbor_trampoline_265aa8>:
ffffffff8ac25aa8:	e9 83 65 45 00       	jmp    ffffffff8b07c030 <neighbor_trampoline_266758+0x4558d8>
ffffffff8ac25aad:	cc                   	int3
ffffffff8ac25aae:	cc                   	int3
ffffffff8ac25aaf:	cc                   	int3

ffffffff8ac25ab0 <neighbor_trampoline_265ab0>:
ffffffff8ac25ab0:	e9 bb 7a 45 00       	jmp    ffffffff8b07d570 <neighbor_trampoline_266758+0x456e18>
ffffffff8ac25ab5:	cc                   	int3
ffffffff8ac25ab6:	cc                   	int3
ffffffff8ac25ab7:	cc                   	int3

ffffffff8ac25ab8 <neighbor_trampoline_265ab8>:
ffffffff8ac25ab8:	e9 e3 84 45 00       	jmp    ffffffff8b07dfa0 <neighbor_trampoline_266758+0x457848>
ffffffff8ac25abd:	cc                   	int3
ffffffff8ac25abe:	cc                   	int3
ffffffff8ac25abf:	cc                   	int3

ffffffff8ac25ac0 <neighbor_trampoline_265ac0>:
ffffffff8ac25ac0:	e9 eb 84 45 00       	jmp    ffffffff8b07dfb0 <neighbor_trampoline_266758+0x457858>
ffffffff8ac25ac5:	cc                   	int3
ffffffff8ac25ac6:	cc                   	int3
ffffffff8ac25ac7:	cc                   	int3

ffffffff8ac25ac8 <neighbor_trampoline_265ac8>:
ffffffff8ac25ac8:	e9 03 87 45 00       	jmp    ffffffff8b07e1d0 <neighbor_trampoline_266758+0x457a78>
ffffffff8ac25acd:	cc                   	int3
ffffffff8ac25ace:	cc                   	int3
ffffffff8ac25acf:	cc                   	int3

ffffffff8ac25ad0 <neighbor_trampoline_265ad0>:
ffffffff8ac25ad0:	e9 9b 88 45 00       	jmp    ffffffff8b07e370 <neighbor_trampoline_266758+0x457c18>
ffffffff8ac25ad5:	cc                   	int3
ffffffff8ac25ad6:	cc                   	int3
ffffffff8ac25ad7:	cc                   	int3

ffffffff8ac25ad8 <neighbor_trampoline_265ad8>:
ffffffff8ac25ad8:	e9 03 6a 45 00       	jmp    ffffffff8b07c4e0 <neighbor_trampoline_266758+0x455d88>
ffffffff8ac25add:	cc                   	int3
ffffffff8ac25ade:	cc                   	int3
ffffffff8ac25adf:	cc                   	int3

ffffffff8ac25ae0 <neighbor_trampoline_265ae0>:
ffffffff8ac25ae0:	e9 cb bf a4 00       	jmp    ffffffff8b671ab0 <neighbor_trampoline_266758+0xa4b358>
ffffffff8ac25ae5:	cc                   	int3
ffffffff8ac25ae6:	cc                   	int3
ffffffff8ac25ae7:	cc                   	int3

ffffffff8ac25ae8 <neighbor_trampoline_265ae8>:
ffffffff8ac25ae8:	e9 a3 68 69 00       	jmp    ffffffff8b2bc390 <neighbor_trampoline_266758+0x695c38>
ffffffff8ac25aed:	cc                   	int3
ffffffff8ac25aee:	cc                   	int3
ffffffff8ac25aef:	cc                   	int3

ffffffff8ac25af0 <neighbor_trampoline_265af0>:
ffffffff8ac25af0:	e9 eb 69 28 00       	jmp    ffffffff8aeac4e0 <neighbor_trampoline_266758+0x285d88>
ffffffff8ac25af5:	cc                   	int3
ffffffff8ac25af6:	cc                   	int3
ffffffff8ac25af7:	cc                   	int3

ffffffff8ac25af8 <neighbor_trampoline_265af8>:
ffffffff8ac25af8:	e9 73 71 28 00       	jmp    ffffffff8aeacc70 <neighbor_trampoline_266758+0x286518>
ffffffff8ac25afd:	cc                   	int3
ffffffff8ac25afe:	cc                   	int3
ffffffff8ac25aff:	cc                   	int3

ffffffff8ac25b00 <neighbor_trampoline_265b00>:
ffffffff8ac25b00:	e9 5b 8e 91 00       	jmp    ffffffff8b53e960 <neighbor_trampoline_266758+0x918208>
ffffffff8ac25b05:	cc                   	int3
ffffffff8ac25b06:	cc                   	int3
ffffffff8ac25b07:	cc                   	int3

ffffffff8ac25b08 <neighbor_trampoline_265b08>:
ffffffff8ac25b08:	e9 73 3a 85 00       	jmp    ffffffff8b479580 <neighbor_trampoline_266758+0x852e28>
ffffffff8ac25b0d:	cc                   	int3
ffffffff8ac25b0e:	cc                   	int3
ffffffff8ac25b0f:	cc                   	int3

ffffffff8ac25b10 <neighbor_trampoline_265b10>:
ffffffff8ac25b10:	e9 7b 3b 85 00       	jmp    ffffffff8b479690 <neighbor_trampoline_266758+0x852f38>
ffffffff8ac25b15:	cc                   	int3
ffffffff8ac25b16:	cc                   	int3
ffffffff8ac25b17:	cc                   	int3

ffffffff8ac25b18 <neighbor_trampoline_265b18>:
ffffffff8ac25b18:	e9 43 df 33 00       	jmp    ffffffff8af63a60 <neighbor_trampoline_266758+0x33d308>
ffffffff8ac25b1d:	cc                   	int3
ffffffff8ac25b1e:	cc                   	int3
ffffffff8ac25b1f:	cc                   	int3

ffffffff8ac25b20 <neighbor_trampoline_265b20>:
ffffffff8ac25b20:	e9 2b e0 33 00       	jmp    ffffffff8af63b50 <neighbor_trampoline_266758+0x33d3f8>
ffffffff8ac25b25:	cc                   	int3
ffffffff8ac25b26:	cc                   	int3
ffffffff8ac25b27:	cc                   	int3

ffffffff8ac25b28 <neighbor_trampoline_265b28>:
ffffffff8ac25b28:	e9 33 e1 33 00       	jmp    ffffffff8af63c60 <neighbor_trampoline_266758+0x33d508>
ffffffff8ac25b2d:	cc                   	int3
ffffffff8ac25b2e:	cc                   	int3
ffffffff8ac25b2f:	cc                   	int3

ffffffff8ac25b30 <neighbor_trampoline_265b30>:
ffffffff8ac25b30:	e9 4b e2 33 00       	jmp    ffffffff8af63d80 <neighbor_trampoline_266758+0x33d628>
ffffffff8ac25b35:	cc                   	int3
ffffffff8ac25b36:	cc                   	int3
ffffffff8ac25b37:	cc                   	int3

ffffffff8ac25b38 <neighbor_trampoline_265b38>:
ffffffff8ac25b38:	e9 33 e3 33 00       	jmp    ffffffff8af63e70 <neighbor_trampoline_266758+0x33d718>
ffffffff8ac25b3d:	cc                   	int3
ffffffff8ac25b3e:	cc                   	int3
ffffffff8ac25b3f:	cc                   	int3

ffffffff8ac25b40 <neighbor_trampoline_265b40>:
ffffffff8ac25b40:	e9 4b e3 33 00       	jmp    ffffffff8af63e90 <neighbor_trampoline_266758+0x33d738>
ffffffff8ac25b45:	cc                   	int3
ffffffff8ac25b46:	cc                   	int3
ffffffff8ac25b47:	cc                   	int3

ffffffff8ac25b48 <neighbor_trampoline_265b48>:
ffffffff8ac25b48:	e9 a3 e3 33 00       	jmp    ffffffff8af63ef0 <neighbor_trampoline_266758+0x33d798>
ffffffff8ac25b4d:	cc                   	int3
ffffffff8ac25b4e:	cc                   	int3
ffffffff8ac25b4f:	cc                   	int3

ffffffff8ac25b50 <neighbor_trampoline_265b50>:
ffffffff8ac25b50:	e9 fb e3 33 00       	jmp    ffffffff8af63f50 <neighbor_trampoline_266758+0x33d7f8>
ffffffff8ac25b55:	cc                   	int3
ffffffff8ac25b56:	cc                   	int3
ffffffff8ac25b57:	cc                   	int3

ffffffff8ac25b58 <neighbor_trampoline_265b58>:
ffffffff8ac25b58:	e9 63 82 2f 00       	jmp    ffffffff8af1ddc0 <neighbor_trampoline_266758+0x2f7668>
ffffffff8ac25b5d:	cc                   	int3
ffffffff8ac25b5e:	cc                   	int3
ffffffff8ac25b5f:	cc                   	int3

ffffffff8ac25b60 <neighbor_trampoline_265b60>:
ffffffff8ac25b60:	e9 0b 92 2f 00       	jmp    ffffffff8af1ed70 <neighbor_trampoline_266758+0x2f8618>
ffffffff8ac25b65:	cc                   	int3
ffffffff8ac25b66:	cc                   	int3
ffffffff8ac25b67:	cc                   	int3

ffffffff8ac25b68 <neighbor_trampoline_265b68>:
ffffffff8ac25b68:	e9 23 91 2f 00       	jmp    ffffffff8af1ec90 <neighbor_trampoline_266758+0x2f8538>
ffffffff8ac25b6d:	cc                   	int3
ffffffff8ac25b6e:	cc                   	int3
ffffffff8ac25b6f:	cc                   	int3

ffffffff8ac25b70 <neighbor_trampoline_265b70>:
ffffffff8ac25b70:	e9 db 89 2f 00       	jmp    ffffffff8af1e550 <neighbor_trampoline_266758+0x2f7df8>
ffffffff8ac25b75:	cc                   	int3
ffffffff8ac25b76:	cc                   	int3
ffffffff8ac25b77:	cc                   	int3

ffffffff8ac25b78 <neighbor_trampoline_265b78>:
ffffffff8ac25b78:	e9 03 8b 2f 00       	jmp    ffffffff8af1e680 <neighbor_trampoline_266758+0x2f7f28>
ffffffff8ac25b7d:	cc                   	int3
ffffffff8ac25b7e:	cc                   	int3
ffffffff8ac25b7f:	cc                   	int3

ffffffff8ac25b80 <neighbor_trampoline_265b80>:
ffffffff8ac25b80:	e9 fb 61 85 00       	jmp    ffffffff8b47bd80 <neighbor_trampoline_266758+0x855628>
ffffffff8ac25b85:	cc                   	int3
ffffffff8ac25b86:	cc                   	int3
ffffffff8ac25b87:	cc                   	int3

ffffffff8ac25b88 <neighbor_trampoline_265b88>:
ffffffff8ac25b88:	e9 53 e5 5c 00       	jmp    ffffffff8b1f40e0 <neighbor_trampoline_266758+0x5cd988>
ffffffff8ac25b8d:	cc                   	int3
ffffffff8ac25b8e:	cc                   	int3
ffffffff8ac25b8f:	cc                   	int3

ffffffff8ac25b90 <neighbor_trampoline_265b90>:
ffffffff8ac25b90:	e9 8b 05 69 00       	jmp    ffffffff8b2b6120 <neighbor_trampoline_266758+0x68f9c8>
ffffffff8ac25b95:	cc                   	int3
ffffffff8ac25b96:	cc                   	int3
ffffffff8ac25b97:	cc                   	int3

ffffffff8ac25b98 <neighbor_trampoline_265b98>:
ffffffff8ac25b98:	e9 63 d3 9d 00       	jmp    ffffffff8b602f00 <neighbor_trampoline_266758+0x9dc7a8>
ffffffff8ac25b9d:	cc                   	int3
ffffffff8ac25b9e:	cc                   	int3
ffffffff8ac25b9f:	cc                   	int3

ffffffff8ac25ba0 <neighbor_trampoline_265ba0>:
ffffffff8ac25ba0:	e9 6b d4 9d 00       	jmp    ffffffff8b603010 <neighbor_trampoline_266758+0x9dc8b8>
ffffffff8ac25ba5:	cc                   	int3
ffffffff8ac25ba6:	cc                   	int3
ffffffff8ac25ba7:	cc                   	int3

ffffffff8ac25ba8 <neighbor_trampoline_265ba8>:
ffffffff8ac25ba8:	e9 c3 d5 9d 00       	jmp    ffffffff8b603170 <neighbor_trampoline_266758+0x9dca18>
ffffffff8ac25bad:	cc                   	int3
ffffffff8ac25bae:	cc                   	int3
ffffffff8ac25baf:	cc                   	int3

ffffffff8ac25bb0 <neighbor_trampoline_265bb0>:
ffffffff8ac25bb0:	e9 eb d8 9d 00       	jmp    ffffffff8b6034a0 <neighbor_trampoline_266758+0x9dcd48>
ffffffff8ac25bb5:	cc                   	int3
ffffffff8ac25bb6:	cc                   	int3
ffffffff8ac25bb7:	cc                   	int3

ffffffff8ac25bb8 <neighbor_trampoline_265bb8>:
ffffffff8ac25bb8:	e9 a3 cb 9d 00       	jmp    ffffffff8b602760 <neighbor_trampoline_266758+0x9dc008>
ffffffff8ac25bbd:	cc                   	int3
ffffffff8ac25bbe:	cc                   	int3
ffffffff8ac25bbf:	cc                   	int3

ffffffff8ac25bc0 <neighbor_trampoline_265bc0>:
ffffffff8ac25bc0:	e9 cb cf 9d 00       	jmp    ffffffff8b602b90 <neighbor_trampoline_266758+0x9dc438>
ffffffff8ac25bc5:	cc                   	int3
ffffffff8ac25bc6:	cc                   	int3
ffffffff8ac25bc7:	cc                   	int3

ffffffff8ac25bc8 <neighbor_trampoline_265bc8>:
ffffffff8ac25bc8:	e9 f3 cf 9d 00       	jmp    ffffffff8b602bc0 <neighbor_trampoline_266758+0x9dc468>
ffffffff8ac25bcd:	cc                   	int3
ffffffff8ac25bce:	cc                   	int3
ffffffff8ac25bcf:	cc                   	int3

ffffffff8ac25bd0 <neighbor_trampoline_265bd0>:
ffffffff8ac25bd0:	e9 eb d8 9d 00       	jmp    ffffffff8b6034c0 <neighbor_trampoline_266758+0x9dcd68>
ffffffff8ac25bd5:	cc                   	int3
ffffffff8ac25bd6:	cc                   	int3
ffffffff8ac25bd7:	cc                   	int3

ffffffff8ac25bd8 <neighbor_trampoline_265bd8>:
ffffffff8ac25bd8:	e9 43 da 9d 00       	jmp    ffffffff8b603620 <neighbor_trampoline_266758+0x9dcec8>
ffffffff8ac25bdd:	cc                   	int3
ffffffff8ac25bde:	cc                   	int3
ffffffff8ac25bdf:	cc                   	int3

ffffffff8ac25be0 <neighbor_trampoline_265be0>:
ffffffff8ac25be0:	e9 db 74 2f 00       	jmp    ffffffff8af1d0c0 <neighbor_trampoline_266758+0x2f6968>
ffffffff8ac25be5:	cc                   	int3
ffffffff8ac25be6:	cc                   	int3
ffffffff8ac25be7:	cc                   	int3

ffffffff8ac25be8 <neighbor_trampoline_265be8>:
ffffffff8ac25be8:	e9 93 16 7a 00       	jmp    ffffffff8b3c7280 <neighbor_trampoline_266758+0x7a0b28>
ffffffff8ac25bed:	cc                   	int3
ffffffff8ac25bee:	cc                   	int3
ffffffff8ac25bef:	cc                   	int3

ffffffff8ac25bf0 <neighbor_trampoline_265bf0>:
ffffffff8ac25bf0:	e9 6b 1c 9d 00       	jmp    ffffffff8b5f7860 <neighbor_trampoline_266758+0x9d1108>
ffffffff8ac25bf5:	cc                   	int3
ffffffff8ac25bf6:	cc                   	int3
ffffffff8ac25bf7:	cc                   	int3

ffffffff8ac25bf8 <neighbor_trampoline_265bf8>:
ffffffff8ac25bf8:	e9 73 1d 9d 00       	jmp    ffffffff8b5f7970 <neighbor_trampoline_266758+0x9d1218>
ffffffff8ac25bfd:	cc                   	int3
ffffffff8ac25bfe:	cc                   	int3
ffffffff8ac25bff:	cc                   	int3

ffffffff8ac25c00 <neighbor_trampoline_265c00>:
ffffffff8ac25c00:	e9 1b 1e 9d 00       	jmp    ffffffff8b5f7a20 <neighbor_trampoline_266758+0x9d12c8>
ffffffff8ac25c05:	cc                   	int3
ffffffff8ac25c06:	cc                   	int3
ffffffff8ac25c07:	cc                   	int3

ffffffff8ac25c08 <neighbor_trampoline_265c08>:
ffffffff8ac25c08:	e9 a3 82 2f 00       	jmp    ffffffff8af1deb0 <neighbor_trampoline_266758+0x2f7758>
ffffffff8ac25c0d:	cc                   	int3
ffffffff8ac25c0e:	cc                   	int3
ffffffff8ac25c0f:	cc                   	int3

ffffffff8ac25c10 <neighbor_trampoline_265c10>:
ffffffff8ac25c10:	e9 db 20 1d 00       	jmp    ffffffff8adf7cf0 <neighbor_trampoline_266758+0x1d1598>
ffffffff8ac25c15:	cc                   	int3
ffffffff8ac25c16:	cc                   	int3
ffffffff8ac25c17:	cc                   	int3

ffffffff8ac25c18 <neighbor_trampoline_265c18>:
ffffffff8ac25c18:	e9 d3 27 1d 00       	jmp    ffffffff8adf83f0 <neighbor_trampoline_266758+0x1d1c98>
ffffffff8ac25c1d:	cc                   	int3
ffffffff8ac25c1e:	cc                   	int3
ffffffff8ac25c1f:	cc                   	int3

ffffffff8ac25c20 <neighbor_trampoline_265c20>:
ffffffff8ac25c20:	e9 9b 27 1d 00       	jmp    ffffffff8adf83c0 <neighbor_trampoline_266758+0x1d1c68>
ffffffff8ac25c25:	cc                   	int3
ffffffff8ac25c26:	cc                   	int3
ffffffff8ac25c27:	cc                   	int3

ffffffff8ac25c28 <neighbor_trampoline_265c28>:
ffffffff8ac25c28:	e9 33 29 1d 00       	jmp    ffffffff8adf8560 <neighbor_trampoline_266758+0x1d1e08>
ffffffff8ac25c2d:	cc                   	int3
ffffffff8ac25c2e:	cc                   	int3
ffffffff8ac25c2f:	cc                   	int3

ffffffff8ac25c30 <neighbor_trampoline_265c30>:
ffffffff8ac25c30:	e9 bb d7 9d 00       	jmp    ffffffff8b6033f0 <neighbor_trampoline_266758+0x9dcc98>
ffffffff8ac25c35:	cc                   	int3
ffffffff8ac25c36:	cc                   	int3
ffffffff8ac25c37:	cc                   	int3

ffffffff8ac25c38 <neighbor_trampoline_265c38>:
ffffffff8ac25c38:	e9 83 2c 1d 00       	jmp    ffffffff8adf88c0 <neighbor_trampoline_266758+0x1d2168>
ffffffff8ac25c3d:	cc                   	int3
ffffffff8ac25c3e:	cc                   	int3
ffffffff8ac25c3f:	cc                   	int3

ffffffff8ac25c40 <neighbor_trampoline_265c40>:
ffffffff8ac25c40:	e9 6b 2e 1d 00       	jmp    ffffffff8adf8ab0 <neighbor_trampoline_266758+0x1d2358>
ffffffff8ac25c45:	cc                   	int3
ffffffff8ac25c46:	cc                   	int3
ffffffff8ac25c47:	cc                   	int3

ffffffff8ac25c48 <neighbor_trampoline_265c48>:
ffffffff8ac25c48:	e9 d3 cf 2e 00       	jmp    ffffffff8af12c20 <neighbor_trampoline_266758+0x2ec4c8>
ffffffff8ac25c4d:	cc                   	int3
ffffffff8ac25c4e:	cc                   	int3
ffffffff8ac25c4f:	cc                   	int3

ffffffff8ac25c50 <neighbor_trampoline_265c50>:
ffffffff8ac25c50:	e9 8b 21 1d 00       	jmp    ffffffff8adf7de0 <neighbor_trampoline_266758+0x1d1688>
ffffffff8ac25c55:	cc                   	int3
ffffffff8ac25c56:	cc                   	int3
ffffffff8ac25c57:	cc                   	int3

ffffffff8ac25c58 <neighbor_trampoline_265c58>:
ffffffff8ac25c58:	e9 c3 9f 2f 00       	jmp    ffffffff8af1fc20 <neighbor_trampoline_266758+0x2f94c8>
ffffffff8ac25c5d:	cc                   	int3
ffffffff8ac25c5e:	cc                   	int3
ffffffff8ac25c5f:	cc                   	int3

ffffffff8ac25c60 <neighbor_trampoline_265c60>:
ffffffff8ac25c60:	e9 fb 2e 1d 00       	jmp    ffffffff8adf8b60 <neighbor_trampoline_266758+0x1d2408>
ffffffff8ac25c65:	cc                   	int3
ffffffff8ac25c66:	cc                   	int3
ffffffff8ac25c67:	cc                   	int3

ffffffff8ac25c68 <neighbor_trampoline_265c68>:
ffffffff8ac25c68:	e9 93 a7 23 00       	jmp    ffffffff8ae60400 <neighbor_trampoline_266758+0x239ca8>
ffffffff8ac25c6d:	cc                   	int3
ffffffff8ac25c6e:	cc                   	int3
ffffffff8ac25c6f:	cc                   	int3

ffffffff8ac25c70 <neighbor_trampoline_265c70>:
ffffffff8ac25c70:	e9 ab 64 28 00       	jmp    ffffffff8aeac120 <neighbor_trampoline_266758+0x2859c8>
ffffffff8ac25c75:	cc                   	int3
ffffffff8ac25c76:	cc                   	int3
ffffffff8ac25c77:	cc                   	int3

ffffffff8ac25c78 <neighbor_trampoline_265c78>:
ffffffff8ac25c78:	e9 c3 6a 28 00       	jmp    ffffffff8aeac740 <neighbor_trampoline_266758+0x285fe8>
ffffffff8ac25c7d:	cc                   	int3
ffffffff8ac25c7e:	cc                   	int3
ffffffff8ac25c7f:	cc                   	int3

ffffffff8ac25c80 <neighbor_trampoline_265c80>:
ffffffff8ac25c80:	e9 3b 27 85 00       	jmp    ffffffff8b4783c0 <neighbor_trampoline_266758+0x851c68>
ffffffff8ac25c85:	cc                   	int3
ffffffff8ac25c86:	cc                   	int3
ffffffff8ac25c87:	cc                   	int3

ffffffff8ac25c88 <neighbor_trampoline_265c88>:
ffffffff8ac25c88:	e9 23 2e 69 00       	jmp    ffffffff8b2b8ab0 <neighbor_trampoline_266758+0x692358>
ffffffff8ac25c8d:	cc                   	int3
ffffffff8ac25c8e:	cc                   	int3
ffffffff8ac25c8f:	cc                   	int3

ffffffff8ac25c90 <neighbor_trampoline_265c90>:
ffffffff8ac25c90:	e9 0b 53 69 00       	jmp    ffffffff8b2bafa0 <neighbor_trampoline_266758+0x694848>
ffffffff8ac25c95:	cc                   	int3
ffffffff8ac25c96:	cc                   	int3
ffffffff8ac25c97:	cc                   	int3

ffffffff8ac25c98 <neighbor_trampoline_265c98>:
ffffffff8ac25c98:	e9 83 72 28 00       	jmp    ffffffff8aeacf20 <neighbor_trampoline_266758+0x2867c8>
ffffffff8ac25c9d:	cc                   	int3
ffffffff8ac25c9e:	cc                   	int3
ffffffff8ac25c9f:	cc                   	int3

ffffffff8ac25ca0 <neighbor_trampoline_265ca0>:
ffffffff8ac25ca0:	e9 4b 2a 1d 00       	jmp    ffffffff8adf86f0 <neighbor_trampoline_266758+0x1d1f98>
ffffffff8ac25ca5:	cc                   	int3
ffffffff8ac25ca6:	cc                   	int3
ffffffff8ac25ca7:	cc                   	int3

ffffffff8ac25ca8 <neighbor_trampoline_265ca8>:
ffffffff8ac25ca8:	e9 93 7a 5a 00       	jmp    ffffffff8b1cd740 <neighbor_trampoline_266758+0x5a6fe8>
ffffffff8ac25cad:	cc                   	int3
ffffffff8ac25cae:	cc                   	int3
ffffffff8ac25caf:	cc                   	int3

ffffffff8ac25cb0 <neighbor_trampoline_265cb0>:
ffffffff8ac25cb0:	e9 1b 7f 5a 00       	jmp    ffffffff8b1cdbd0 <neighbor_trampoline_266758+0x5a7478>
ffffffff8ac25cb5:	cc                   	int3
ffffffff8ac25cb6:	cc                   	int3
ffffffff8ac25cb7:	cc                   	int3

ffffffff8ac25cb8 <neighbor_trampoline_265cb8>:
ffffffff8ac25cb8:	e9 73 7b 5d 00       	jmp    ffffffff8b1fd830 <neighbor_trampoline_266758+0x5d70d8>
ffffffff8ac25cbd:	cc                   	int3
ffffffff8ac25cbe:	cc                   	int3
ffffffff8ac25cbf:	cc                   	int3

ffffffff8ac25cc0 <neighbor_trampoline_265cc0>:
ffffffff8ac25cc0:	e9 9b 81 5d 00       	jmp    ffffffff8b1fde60 <neighbor_trampoline_266758+0x5d7708>
ffffffff8ac25cc5:	cc                   	int3
ffffffff8ac25cc6:	cc                   	int3
ffffffff8ac25cc7:	cc                   	int3

ffffffff8ac25cc8 <neighbor_trampoline_265cc8>:
ffffffff8ac25cc8:	e9 53 86 5d 00       	jmp    ffffffff8b1fe320 <neighbor_trampoline_266758+0x5d7bc8>
ffffffff8ac25ccd:	cc                   	int3
ffffffff8ac25cce:	cc                   	int3
ffffffff8ac25ccf:	cc                   	int3

ffffffff8ac25cd0 <neighbor_trampoline_265cd0>:
ffffffff8ac25cd0:	e9 7b 11 69 00       	jmp    ffffffff8b2b6e50 <neighbor_trampoline_266758+0x6906f8>
ffffffff8ac25cd5:	cc                   	int3
ffffffff8ac25cd6:	cc                   	int3
ffffffff8ac25cd7:	cc                   	int3

ffffffff8ac25cd8 <neighbor_trampoline_265cd8>:
ffffffff8ac25cd8:	e9 d3 53 23 00       	jmp    ffffffff8ae5b0b0 <neighbor_trampoline_266758+0x234958>
ffffffff8ac25cdd:	cc                   	int3
ffffffff8ac25cde:	cc                   	int3
ffffffff8ac25cdf:	cc                   	int3

ffffffff8ac25ce0 <neighbor_trampoline_265ce0>:
ffffffff8ac25ce0:	e9 db 76 28 00       	jmp    ffffffff8aead3c0 <neighbor_trampoline_266758+0x286c68>
ffffffff8ac25ce5:	cc                   	int3
ffffffff8ac25ce6:	cc                   	int3
ffffffff8ac25ce7:	cc                   	int3

ffffffff8ac25ce8 <neighbor_trampoline_265ce8>:
ffffffff8ac25ce8:	e9 53 a3 88 00       	jmp    ffffffff8b4b0040 <neighbor_trampoline_266758+0x8898e8>
ffffffff8ac25ced:	cc                   	int3
ffffffff8ac25cee:	cc                   	int3
ffffffff8ac25cef:	cc                   	int3

ffffffff8ac25cf0 <neighbor_trampoline_265cf0>:
ffffffff8ac25cf0:	e9 8b fb 49 00       	jmp    ffffffff8b0c5880 <neighbor_trampoline_266758+0x49f128>
ffffffff8ac25cf5:	cc                   	int3
ffffffff8ac25cf6:	cc                   	int3
ffffffff8ac25cf7:	cc                   	int3

ffffffff8ac25cf8 <neighbor_trampoline_265cf8>:
ffffffff8ac25cf8:	e9 63 ff 49 00       	jmp    ffffffff8b0c5c60 <neighbor_trampoline_266758+0x49f508>
ffffffff8ac25cfd:	cc                   	int3
ffffffff8ac25cfe:	cc                   	int3
ffffffff8ac25cff:	cc                   	int3

ffffffff8ac25d00 <neighbor_trampoline_265d00>:
ffffffff8ac25d00:	e9 eb 08 29 00       	jmp    ffffffff8aeb65f0 <neighbor_trampoline_266758+0x28fe98>
ffffffff8ac25d05:	cc                   	int3
ffffffff8ac25d06:	cc                   	int3
ffffffff8ac25d07:	cc                   	int3

ffffffff8ac25d08 <neighbor_trampoline_265d08>:
ffffffff8ac25d08:	e9 63 0d 29 00       	jmp    ffffffff8aeb6a70 <neighbor_trampoline_266758+0x290318>
ffffffff8ac25d0d:	cc                   	int3
ffffffff8ac25d0e:	cc                   	int3
ffffffff8ac25d0f:	cc                   	int3

ffffffff8ac25d10 <neighbor_trampoline_265d10>:
ffffffff8ac25d10:	e9 6b 9d 94 00       	jmp    ffffffff8b56fa80 <neighbor_trampoline_266758+0x949328>
ffffffff8ac25d15:	cc                   	int3
ffffffff8ac25d16:	cc                   	int3
ffffffff8ac25d17:	cc                   	int3

ffffffff8ac25d18 <neighbor_trampoline_265d18>:
ffffffff8ac25d18:	e9 d3 9f 94 00       	jmp    ffffffff8b56fcf0 <neighbor_trampoline_266758+0x949598>
ffffffff8ac25d1d:	cc                   	int3
ffffffff8ac25d1e:	cc                   	int3
ffffffff8ac25d1f:	cc                   	int3

ffffffff8ac25d20 <neighbor_trampoline_265d20>:
ffffffff8ac25d20:	e9 0b a6 94 00       	jmp    ffffffff8b570330 <neighbor_trampoline_266758+0x949bd8>
ffffffff8ac25d25:	cc                   	int3
ffffffff8ac25d26:	cc                   	int3
ffffffff8ac25d27:	cc                   	int3

ffffffff8ac25d28 <neighbor_trampoline_265d28>:
ffffffff8ac25d28:	e9 63 a7 94 00       	jmp    ffffffff8b570490 <neighbor_trampoline_266758+0x949d38>
ffffffff8ac25d2d:	cc                   	int3
ffffffff8ac25d2e:	cc                   	int3
ffffffff8ac25d2f:	cc                   	int3

ffffffff8ac25d30 <neighbor_trampoline_265d30>:
ffffffff8ac25d30:	e9 1b a1 94 00       	jmp    ffffffff8b56fe50 <neighbor_trampoline_266758+0x9496f8>
ffffffff8ac25d35:	cc                   	int3
ffffffff8ac25d36:	cc                   	int3
ffffffff8ac25d37:	cc                   	int3

ffffffff8ac25d38 <neighbor_trampoline_265d38>:
ffffffff8ac25d38:	e9 f3 a2 94 00       	jmp    ffffffff8b570030 <neighbor_trampoline_266758+0x9498d8>
ffffffff8ac25d3d:	cc                   	int3
ffffffff8ac25d3e:	cc                   	int3
ffffffff8ac25d3f:	cc                   	int3

ffffffff8ac25d40 <neighbor_trampoline_265d40>:
ffffffff8ac25d40:	e9 0b a4 94 00       	jmp    ffffffff8b570150 <neighbor_trampoline_266758+0x9499f8>
ffffffff8ac25d45:	cc                   	int3
ffffffff8ac25d46:	cc                   	int3
ffffffff8ac25d47:	cc                   	int3

ffffffff8ac25d48 <neighbor_trampoline_265d48>:
ffffffff8ac25d48:	e9 83 a4 94 00       	jmp    ffffffff8b5701d0 <neighbor_trampoline_266758+0x949a78>
ffffffff8ac25d4d:	cc                   	int3
ffffffff8ac25d4e:	cc                   	int3
ffffffff8ac25d4f:	cc                   	int3

ffffffff8ac25d50 <neighbor_trampoline_265d50>:
ffffffff8ac25d50:	e9 2b a5 94 00       	jmp    ffffffff8b570280 <neighbor_trampoline_266758+0x949b28>
ffffffff8ac25d55:	cc                   	int3
ffffffff8ac25d56:	cc                   	int3
ffffffff8ac25d57:	cc                   	int3

ffffffff8ac25d58 <neighbor_trampoline_265d58>:
ffffffff8ac25d58:	e9 e3 47 85 00       	jmp    ffffffff8b47a540 <neighbor_trampoline_266758+0x853de8>
ffffffff8ac25d5d:	cc                   	int3
ffffffff8ac25d5e:	cc                   	int3
ffffffff8ac25d5f:	cc                   	int3

ffffffff8ac25d60 <neighbor_trampoline_265d60>:
ffffffff8ac25d60:	e9 fb 60 85 00       	jmp    ffffffff8b47be60 <neighbor_trampoline_266758+0x855708>
ffffffff8ac25d65:	cc                   	int3
ffffffff8ac25d66:	cc                   	int3
ffffffff8ac25d67:	cc                   	int3

ffffffff8ac25d68 <neighbor_trampoline_265d68>:
ffffffff8ac25d68:	e9 b3 02 9b 00       	jmp    ffffffff8b5d6020 <neighbor_trampoline_266758+0x9af8c8>
ffffffff8ac25d6d:	cc                   	int3
ffffffff8ac25d6e:	cc                   	int3
ffffffff8ac25d6f:	cc                   	int3

ffffffff8ac25d70 <neighbor_trampoline_265d70>:
ffffffff8ac25d70:	e9 fb 04 9b 00       	jmp    ffffffff8b5d6270 <neighbor_trampoline_266758+0x9afb18>
ffffffff8ac25d75:	cc                   	int3
ffffffff8ac25d76:	cc                   	int3
ffffffff8ac25d77:	cc                   	int3

ffffffff8ac25d78 <neighbor_trampoline_265d78>:
ffffffff8ac25d78:	e9 a3 09 9b 00       	jmp    ffffffff8b5d6720 <neighbor_trampoline_266758+0x9affc8>
ffffffff8ac25d7d:	cc                   	int3
ffffffff8ac25d7e:	cc                   	int3
ffffffff8ac25d7f:	cc                   	int3

ffffffff8ac25d80 <neighbor_trampoline_265d80>:
ffffffff8ac25d80:	e9 fb 0a 9b 00       	jmp    ffffffff8b5d6880 <neighbor_trampoline_266758+0x9b0128>
ffffffff8ac25d85:	cc                   	int3
ffffffff8ac25d86:	cc                   	int3
ffffffff8ac25d87:	cc                   	int3

ffffffff8ac25d88 <neighbor_trampoline_265d88>:
ffffffff8ac25d88:	e9 43 06 9b 00       	jmp    ffffffff8b5d63d0 <neighbor_trampoline_266758+0x9afc78>
ffffffff8ac25d8d:	cc                   	int3
ffffffff8ac25d8e:	cc                   	int3
ffffffff8ac25d8f:	cc                   	int3

ffffffff8ac25d90 <neighbor_trampoline_265d90>:
ffffffff8ac25d90:	e9 5b 07 9b 00       	jmp    ffffffff8b5d64f0 <neighbor_trampoline_266758+0x9afd98>
ffffffff8ac25d95:	cc                   	int3
ffffffff8ac25d96:	cc                   	int3
ffffffff8ac25d97:	cc                   	int3

ffffffff8ac25d98 <neighbor_trampoline_265d98>:
ffffffff8ac25d98:	e9 33 08 9b 00       	jmp    ffffffff8b5d65d0 <neighbor_trampoline_266758+0x9afe78>
ffffffff8ac25d9d:	cc                   	int3
ffffffff8ac25d9e:	cc                   	int3
ffffffff8ac25d9f:	cc                   	int3

ffffffff8ac25da0 <neighbor_trampoline_265da0>:
ffffffff8ac25da0:	e9 bb 08 9b 00       	jmp    ffffffff8b5d6660 <neighbor_trampoline_266758+0x9aff08>
ffffffff8ac25da5:	cc                   	int3
ffffffff8ac25da6:	cc                   	int3
ffffffff8ac25da7:	cc                   	int3

ffffffff8ac25da8 <neighbor_trampoline_265da8>:
ffffffff8ac25da8:	e9 93 14 86 00       	jmp    ffffffff8b487240 <neighbor_trampoline_266758+0x860ae8>
ffffffff8ac25dad:	cc                   	int3
ffffffff8ac25dae:	cc                   	int3
ffffffff8ac25daf:	cc                   	int3

ffffffff8ac25db0 <neighbor_trampoline_265db0>:
ffffffff8ac25db0:	e9 0b 16 86 00       	jmp    ffffffff8b4873c0 <neighbor_trampoline_266758+0x860c68>
ffffffff8ac25db5:	cc                   	int3
ffffffff8ac25db6:	cc                   	int3
ffffffff8ac25db7:	cc                   	int3

ffffffff8ac25db8 <neighbor_trampoline_265db8>:
ffffffff8ac25db8:	e9 53 67 85 00       	jmp    ffffffff8b47c510 <neighbor_trampoline_266758+0x855db8>
ffffffff8ac25dbd:	cc                   	int3
ffffffff8ac25dbe:	cc                   	int3
ffffffff8ac25dbf:	cc                   	int3

ffffffff8ac25dc0 <neighbor_trampoline_265dc0>:
ffffffff8ac25dc0:	e9 9b 00 29 00       	jmp    ffffffff8aeb5e60 <neighbor_trampoline_266758+0x28f708>
ffffffff8ac25dc5:	cc                   	int3
ffffffff8ac25dc6:	cc                   	int3
ffffffff8ac25dc7:	cc                   	int3

ffffffff8ac25dc8 <neighbor_trampoline_265dc8>:
ffffffff8ac25dc8:	e9 13 d2 39 00       	jmp    ffffffff8afc2fe0 <neighbor_trampoline_266758+0x39c888>
ffffffff8ac25dcd:	cc                   	int3
ffffffff8ac25dce:	cc                   	int3
ffffffff8ac25dcf:	cc                   	int3

ffffffff8ac25dd0 <neighbor_trampoline_265dd0>:
ffffffff8ac25dd0:	e9 8b d4 39 00       	jmp    ffffffff8afc3260 <neighbor_trampoline_266758+0x39cb08>
ffffffff8ac25dd5:	cc                   	int3
ffffffff8ac25dd6:	cc                   	int3
ffffffff8ac25dd7:	cc                   	int3

ffffffff8ac25dd8 <neighbor_trampoline_265dd8>:
ffffffff8ac25dd8:	e9 03 d7 39 00       	jmp    ffffffff8afc34e0 <neighbor_trampoline_266758+0x39cd88>
ffffffff8ac25ddd:	cc                   	int3
ffffffff8ac25dde:	cc                   	int3
ffffffff8ac25ddf:	cc                   	int3

ffffffff8ac25de0 <neighbor_trampoline_265de0>:
ffffffff8ac25de0:	e9 2b d9 39 00       	jmp    ffffffff8afc3710 <neighbor_trampoline_266758+0x39cfb8>
ffffffff8ac25de5:	cc                   	int3
ffffffff8ac25de6:	cc                   	int3
ffffffff8ac25de7:	cc                   	int3

ffffffff8ac25de8 <neighbor_trampoline_265de8>:
ffffffff8ac25de8:	e9 e3 db 39 00       	jmp    ffffffff8afc39d0 <neighbor_trampoline_266758+0x39d278>
ffffffff8ac25ded:	cc                   	int3
ffffffff8ac25dee:	cc                   	int3
ffffffff8ac25def:	cc                   	int3

ffffffff8ac25df0 <neighbor_trampoline_265df0>:
ffffffff8ac25df0:	e9 5b 4e 85 00       	jmp    ffffffff8b47ac50 <neighbor_trampoline_266758+0x8544f8>
ffffffff8ac25df5:	cc                   	int3
ffffffff8ac25df6:	cc                   	int3
ffffffff8ac25df7:	cc                   	int3

ffffffff8ac25df8 <neighbor_trampoline_265df8>:
ffffffff8ac25df8:	e9 13 68 69 00       	jmp    ffffffff8b2bc610 <neighbor_trampoline_266758+0x695eb8>
ffffffff8ac25dfd:	cc                   	int3
ffffffff8ac25dfe:	cc                   	int3
ffffffff8ac25dff:	cc                   	int3

ffffffff8ac25e00 <neighbor_trampoline_265e00>:
ffffffff8ac25e00:	e9 6b bc 27 00       	jmp    ffffffff8aea1a70 <neighbor_trampoline_266758+0x27b318>
ffffffff8ac25e05:	cc                   	int3
ffffffff8ac25e06:	cc                   	int3
ffffffff8ac25e07:	cc                   	int3

ffffffff8ac25e08 <neighbor_trampoline_265e08>:
ffffffff8ac25e08:	e9 e3 67 85 00       	jmp    ffffffff8b47c5f0 <neighbor_trampoline_266758+0x855e98>
ffffffff8ac25e0d:	cc                   	int3
ffffffff8ac25e0e:	cc                   	int3
ffffffff8ac25e0f:	cc                   	int3

ffffffff8ac25e10 <neighbor_trampoline_265e10>:
ffffffff8ac25e10:	e9 cb 09 7d 00       	jmp    ffffffff8b3f67e0 <neighbor_trampoline_266758+0x7d0088>
ffffffff8ac25e15:	cc                   	int3
ffffffff8ac25e16:	cc                   	int3
ffffffff8ac25e17:	cc                   	int3

ffffffff8ac25e18 <neighbor_trampoline_265e18>:
ffffffff8ac25e18:	e9 13 a8 a3 00       	jmp    ffffffff8b660630 <neighbor_trampoline_266758+0xa39ed8>
ffffffff8ac25e1d:	cc                   	int3
ffffffff8ac25e1e:	cc                   	int3
ffffffff8ac25e1f:	cc                   	int3

ffffffff8ac25e20 <neighbor_trampoline_265e20>:
ffffffff8ac25e20:	e9 bb 0a 7d 00       	jmp    ffffffff8b3f68e0 <neighbor_trampoline_266758+0x7d0188>
ffffffff8ac25e25:	cc                   	int3
ffffffff8ac25e26:	cc                   	int3
ffffffff8ac25e27:	cc                   	int3

ffffffff8ac25e28 <neighbor_trampoline_265e28>:
ffffffff8ac25e28:	e9 93 8e 4c 00       	jmp    ffffffff8b0eecc0 <neighbor_trampoline_266758+0x4c8568>
ffffffff8ac25e2d:	cc                   	int3
ffffffff8ac25e2e:	cc                   	int3
ffffffff8ac25e2f:	cc                   	int3

ffffffff8ac25e30 <neighbor_trampoline_265e30>:
ffffffff8ac25e30:	e9 3b 15 29 00       	jmp    ffffffff8aeb7370 <neighbor_trampoline_266758+0x290c18>
ffffffff8ac25e35:	cc                   	int3
ffffffff8ac25e36:	cc                   	int3
ffffffff8ac25e37:	cc                   	int3

ffffffff8ac25e38 <neighbor_trampoline_265e38>:
ffffffff8ac25e38:	e9 c3 0c 7d 00       	jmp    ffffffff8b3f6b00 <neighbor_trampoline_266758+0x7d03a8>
ffffffff8ac25e3d:	cc                   	int3
ffffffff8ac25e3e:	cc                   	int3
ffffffff8ac25e3f:	cc                   	int3

ffffffff8ac25e40 <neighbor_trampoline_265e40>:
ffffffff8ac25e40:	e9 4b 0d 7d 00       	jmp    ffffffff8b3f6b90 <neighbor_trampoline_266758+0x7d0438>
ffffffff8ac25e45:	cc                   	int3
ffffffff8ac25e46:	cc                   	int3
ffffffff8ac25e47:	cc                   	int3

ffffffff8ac25e48 <neighbor_trampoline_265e48>:
ffffffff8ac25e48:	e9 c3 68 85 00       	jmp    ffffffff8b47c710 <neighbor_trampoline_266758+0x855fb8>
ffffffff8ac25e4d:	cc                   	int3
ffffffff8ac25e4e:	cc                   	int3
ffffffff8ac25e4f:	cc                   	int3

ffffffff8ac25e50 <neighbor_trampoline_265e50>:
ffffffff8ac25e50:	e9 0b 21 34 00       	jmp    ffffffff8af67f60 <neighbor_trampoline_266758+0x341808>
ffffffff8ac25e55:	cc                   	int3
ffffffff8ac25e56:	cc                   	int3
ffffffff8ac25e57:	cc                   	int3

ffffffff8ac25e58 <neighbor_trampoline_265e58>:
ffffffff8ac25e58:	e9 63 0d 7d 00       	jmp    ffffffff8b3f6bc0 <neighbor_trampoline_266758+0x7d0468>
ffffffff8ac25e5d:	cc                   	int3
ffffffff8ac25e5e:	cc                   	int3
ffffffff8ac25e5f:	cc                   	int3

ffffffff8ac25e60 <neighbor_trampoline_265e60>:
ffffffff8ac25e60:	e9 ab 6b 85 00       	jmp    ffffffff8b47ca10 <neighbor_trampoline_266758+0x8562b8>
ffffffff8ac25e65:	cc                   	int3
ffffffff8ac25e66:	cc                   	int3
ffffffff8ac25e67:	cc                   	int3

ffffffff8ac25e68 <neighbor_trampoline_265e68>:
ffffffff8ac25e68:	e9 93 6d 85 00       	jmp    ffffffff8b47cc00 <neighbor_trampoline_266758+0x8564a8>
ffffffff8ac25e6d:	cc                   	int3
ffffffff8ac25e6e:	cc                   	int3
ffffffff8ac25e6f:	cc                   	int3

ffffffff8ac25e70 <neighbor_trampoline_265e70>:
ffffffff8ac25e70:	e9 1b 2e 1d 00       	jmp    ffffffff8adf8c90 <neighbor_trampoline_266758+0x1d2538>
ffffffff8ac25e75:	cc                   	int3
ffffffff8ac25e76:	cc                   	int3
ffffffff8ac25e77:	cc                   	int3

ffffffff8ac25e78 <neighbor_trampoline_265e78>:
ffffffff8ac25e78:	e9 f3 c6 66 00       	jmp    ffffffff8b292570 <neighbor_trampoline_266758+0x66be18>
ffffffff8ac25e7d:	cc                   	int3
ffffffff8ac25e7e:	cc                   	int3
ffffffff8ac25e7f:	cc                   	int3

ffffffff8ac25e80 <neighbor_trampoline_265e80>:
ffffffff8ac25e80:	e9 6b 72 85 00       	jmp    ffffffff8b47d0f0 <neighbor_trampoline_266758+0x856998>
ffffffff8ac25e85:	cc                   	int3
ffffffff8ac25e86:	cc                   	int3
ffffffff8ac25e87:	cc                   	int3

ffffffff8ac25e88 <neighbor_trampoline_265e88>:
ffffffff8ac25e88:	e9 c3 17 7d 00       	jmp    ffffffff8b3f7650 <neighbor_trampoline_266758+0x7d0ef8>
ffffffff8ac25e8d:	cc                   	int3
ffffffff8ac25e8e:	cc                   	int3
ffffffff8ac25e8f:	cc                   	int3

ffffffff8ac25e90 <neighbor_trampoline_265e90>:
ffffffff8ac25e90:	e9 9b 75 85 00       	jmp    ffffffff8b47d430 <neighbor_trampoline_266758+0x856cd8>
ffffffff8ac25e95:	cc                   	int3
ffffffff8ac25e96:	cc                   	int3
ffffffff8ac25e97:	cc                   	int3

ffffffff8ac25e98 <neighbor_trampoline_265e98>:
ffffffff8ac25e98:	e9 a3 6e 57 00       	jmp    ffffffff8b19cd40 <neighbor_trampoline_266758+0x5765e8>
ffffffff8ac25e9d:	cc                   	int3
ffffffff8ac25e9e:	cc                   	int3
ffffffff8ac25e9f:	cc                   	int3

ffffffff8ac25ea0 <neighbor_trampoline_265ea0>:
ffffffff8ac25ea0:	e9 fb c6 66 00       	jmp    ffffffff8b2925a0 <neighbor_trampoline_266758+0x66be48>
ffffffff8ac25ea5:	cc                   	int3
ffffffff8ac25ea6:	cc                   	int3
ffffffff8ac25ea7:	cc                   	int3

ffffffff8ac25ea8 <neighbor_trampoline_265ea8>:
ffffffff8ac25ea8:	e9 43 76 85 00       	jmp    ffffffff8b47d4f0 <neighbor_trampoline_266758+0x856d98>
ffffffff8ac25ead:	cc                   	int3
ffffffff8ac25eae:	cc                   	int3
ffffffff8ac25eaf:	cc                   	int3

ffffffff8ac25eb0 <neighbor_trampoline_265eb0>:
ffffffff8ac25eb0:	e9 db dd 39 00       	jmp    ffffffff8afc3c90 <neighbor_trampoline_266758+0x39d538>
ffffffff8ac25eb5:	cc                   	int3
ffffffff8ac25eb6:	cc                   	int3
ffffffff8ac25eb7:	cc                   	int3

ffffffff8ac25eb8 <neighbor_trampoline_265eb8>:
ffffffff8ac25eb8:	e9 33 ee 39 00       	jmp    ffffffff8afc4cf0 <neighbor_trampoline_266758+0x39e598>
ffffffff8ac25ebd:	cc                   	int3
ffffffff8ac25ebe:	cc                   	int3
ffffffff8ac25ebf:	cc                   	int3

ffffffff8ac25ec0 <neighbor_trampoline_265ec0>:
ffffffff8ac25ec0:	e9 8b c9 23 00       	jmp    ffffffff8ae62850 <neighbor_trampoline_266758+0x23c0f8>
ffffffff8ac25ec5:	cc                   	int3
ffffffff8ac25ec6:	cc                   	int3
ffffffff8ac25ec7:	cc                   	int3

ffffffff8ac25ec8 <neighbor_trampoline_265ec8>:
ffffffff8ac25ec8:	e9 73 76 85 00       	jmp    ffffffff8b47d540 <neighbor_trampoline_266758+0x856de8>
ffffffff8ac25ecd:	cc                   	int3
ffffffff8ac25ece:	cc                   	int3
ffffffff8ac25ecf:	cc                   	int3

ffffffff8ac25ed0 <neighbor_trampoline_265ed0>:
ffffffff8ac25ed0:	e9 6b 67 6b 00       	jmp    ffffffff8b2dc640 <neighbor_trampoline_266758+0x6b5ee8>
ffffffff8ac25ed5:	cc                   	int3
ffffffff8ac25ed6:	cc                   	int3
ffffffff8ac25ed7:	cc                   	int3

ffffffff8ac25ed8 <neighbor_trampoline_265ed8>:
ffffffff8ac25ed8:	e9 93 6d 6b 00       	jmp    ffffffff8b2dcc70 <neighbor_trampoline_266758+0x6b6518>
ffffffff8ac25edd:	cc                   	int3
ffffffff8ac25ede:	cc                   	int3
ffffffff8ac25edf:	cc                   	int3

ffffffff8ac25ee0 <neighbor_trampoline_265ee0>:
ffffffff8ac25ee0:	e9 4b 2f 1d 00       	jmp    ffffffff8adf8e30 <neighbor_trampoline_266758+0x1d26d8>
ffffffff8ac25ee5:	cc                   	int3
ffffffff8ac25ee6:	cc                   	int3
ffffffff8ac25ee7:	cc                   	int3

ffffffff8ac25ee8 <neighbor_trampoline_265ee8>:
ffffffff8ac25ee8:	e9 83 31 1d 00       	jmp    ffffffff8adf9070 <neighbor_trampoline_266758+0x1d2918>
ffffffff8ac25eed:	cc                   	int3
ffffffff8ac25eee:	cc                   	int3
ffffffff8ac25eef:	cc                   	int3

ffffffff8ac25ef0 <neighbor_trampoline_265ef0>:
ffffffff8ac25ef0:	e9 5b 32 1d 00       	jmp    ffffffff8adf9150 <neighbor_trampoline_266758+0x1d29f8>
ffffffff8ac25ef5:	cc                   	int3
ffffffff8ac25ef6:	cc                   	int3
ffffffff8ac25ef7:	cc                   	int3

ffffffff8ac25ef8 <neighbor_trampoline_265ef8>:
ffffffff8ac25ef8:	e9 a3 34 1d 00       	jmp    ffffffff8adf93a0 <neighbor_trampoline_266758+0x1d2c48>
ffffffff8ac25efd:	cc                   	int3
ffffffff8ac25efe:	cc                   	int3
ffffffff8ac25eff:	cc                   	int3

ffffffff8ac25f00 <neighbor_trampoline_265f00>:
ffffffff8ac25f00:	e9 cb 85 45 00       	jmp    ffffffff8b07e4d0 <neighbor_trampoline_266758+0x457d78>
ffffffff8ac25f05:	cc                   	int3
ffffffff8ac25f06:	cc                   	int3
ffffffff8ac25f07:	cc                   	int3

ffffffff8ac25f08 <neighbor_trampoline_265f08>:
ffffffff8ac25f08:	e9 23 7a 85 00       	jmp    ffffffff8b47d930 <neighbor_trampoline_266758+0x8571d8>
ffffffff8ac25f0d:	cc                   	int3
ffffffff8ac25f0e:	cc                   	int3
ffffffff8ac25f0f:	cc                   	int3

ffffffff8ac25f10 <neighbor_trampoline_265f10>:
ffffffff8ac25f10:	e9 ab 86 45 00       	jmp    ffffffff8b07e5c0 <neighbor_trampoline_266758+0x457e68>
ffffffff8ac25f15:	cc                   	int3
ffffffff8ac25f16:	cc                   	int3
ffffffff8ac25f17:	cc                   	int3

ffffffff8ac25f18 <neighbor_trampoline_265f18>:
ffffffff8ac25f18:	e9 e3 88 45 00       	jmp    ffffffff8b07e800 <neighbor_trampoline_266758+0x4580a8>
ffffffff8ac25f1d:	cc                   	int3
ffffffff8ac25f1e:	cc                   	int3
ffffffff8ac25f1f:	cc                   	int3

ffffffff8ac25f20 <neighbor_trampoline_265f20>:
ffffffff8ac25f20:	e9 eb ae 82 00       	jmp    ffffffff8b450e10 <neighbor_trampoline_266758+0x82a6b8>
ffffffff8ac25f25:	cc                   	int3
ffffffff8ac25f26:	cc                   	int3
ffffffff8ac25f27:	cc                   	int3

ffffffff8ac25f28 <neighbor_trampoline_265f28>:
ffffffff8ac25f28:	e9 b3 ce 23 00       	jmp    ffffffff8ae62de0 <neighbor_trampoline_266758+0x23c688>
ffffffff8ac25f2d:	cc                   	int3
ffffffff8ac25f2e:	cc                   	int3
ffffffff8ac25f2f:	cc                   	int3

ffffffff8ac25f30 <neighbor_trampoline_265f30>:
ffffffff8ac25f30:	e9 9b 7b 85 00       	jmp    ffffffff8b47dad0 <neighbor_trampoline_266758+0x857378>
ffffffff8ac25f35:	cc                   	int3
ffffffff8ac25f36:	cc                   	int3
ffffffff8ac25f37:	cc                   	int3

ffffffff8ac25f38 <neighbor_trampoline_265f38>:
ffffffff8ac25f38:	e9 23 17 7d 00       	jmp    ffffffff8b3f7660 <neighbor_trampoline_266758+0x7d0f08>
ffffffff8ac25f3d:	cc                   	int3
ffffffff8ac25f3e:	cc                   	int3
ffffffff8ac25f3f:	cc                   	int3

ffffffff8ac25f40 <neighbor_trampoline_265f40>:
ffffffff8ac25f40:	e9 7b 82 85 00       	jmp    ffffffff8b47e1c0 <neighbor_trampoline_266758+0x857a68>
ffffffff8ac25f45:	cc                   	int3
ffffffff8ac25f46:	cc                   	int3
ffffffff8ac25f47:	cc                   	int3

ffffffff8ac25f48 <neighbor_trampoline_265f48>:
ffffffff8ac25f48:	e9 63 88 85 00       	jmp    ffffffff8b47e7b0 <neighbor_trampoline_266758+0x858058>
ffffffff8ac25f4d:	cc                   	int3
ffffffff8ac25f4e:	cc                   	int3
ffffffff8ac25f4f:	cc                   	int3

ffffffff8ac25f50 <neighbor_trampoline_265f50>:
ffffffff8ac25f50:	e9 9b 22 79 00       	jmp    ffffffff8b3b81f0 <neighbor_trampoline_266758+0x791a98>
ffffffff8ac25f55:	cc                   	int3
ffffffff8ac25f56:	cc                   	int3
ffffffff8ac25f57:	cc                   	int3

ffffffff8ac25f58 <neighbor_trampoline_265f58>:
ffffffff8ac25f58:	e9 b3 35 98 00       	jmp    ffffffff8b5a9510 <neighbor_trampoline_266758+0x982db8>
ffffffff8ac25f5d:	cc                   	int3
ffffffff8ac25f5e:	cc                   	int3
ffffffff8ac25f5f:	cc                   	int3

ffffffff8ac25f60 <neighbor_trampoline_265f60>:
ffffffff8ac25f60:	e9 ab 1d 74 00       	jmp    ffffffff8b367d10 <neighbor_trampoline_266758+0x7415b8>
ffffffff8ac25f65:	cc                   	int3
ffffffff8ac25f66:	cc                   	int3
ffffffff8ac25f67:	cc                   	int3

ffffffff8ac25f68 <neighbor_trampoline_265f68>:
ffffffff8ac25f68:	e9 f3 35 74 00       	jmp    ffffffff8b369560 <neighbor_trampoline_266758+0x742e08>
ffffffff8ac25f6d:	cc                   	int3
ffffffff8ac25f6e:	cc                   	int3
ffffffff8ac25f6f:	cc                   	int3

ffffffff8ac25f70 <neighbor_trampoline_265f70>:
ffffffff8ac25f70:	e9 9b 3e 74 00       	jmp    ffffffff8b369e10 <neighbor_trampoline_266758+0x7436b8>
ffffffff8ac25f75:	cc                   	int3
ffffffff8ac25f76:	cc                   	int3
ffffffff8ac25f77:	cc                   	int3

ffffffff8ac25f78 <neighbor_trampoline_265f78>:
ffffffff8ac25f78:	e9 c3 3f 74 00       	jmp    ffffffff8b369f40 <neighbor_trampoline_266758+0x7437e8>
ffffffff8ac25f7d:	cc                   	int3
ffffffff8ac25f7e:	cc                   	int3
ffffffff8ac25f7f:	cc                   	int3

ffffffff8ac25f80 <neighbor_trampoline_265f80>:
ffffffff8ac25f80:	e9 bb 54 69 00       	jmp    ffffffff8b2bb440 <neighbor_trampoline_266758+0x694ce8>
ffffffff8ac25f85:	cc                   	int3
ffffffff8ac25f86:	cc                   	int3
ffffffff8ac25f87:	cc                   	int3

ffffffff8ac25f88 <neighbor_trampoline_265f88>:
ffffffff8ac25f88:	e9 13 d2 23 00       	jmp    ffffffff8ae631a0 <neighbor_trampoline_266758+0x23ca48>
ffffffff8ac25f8d:	cc                   	int3
ffffffff8ac25f8e:	cc                   	int3
ffffffff8ac25f8f:	cc                   	int3

ffffffff8ac25f90 <neighbor_trampoline_265f90>:
ffffffff8ac25f90:	e9 1b 89 85 00       	jmp    ffffffff8b47e8b0 <neighbor_trampoline_266758+0x858158>
ffffffff8ac25f95:	cc                   	int3
ffffffff8ac25f96:	cc                   	int3
ffffffff8ac25f97:	cc                   	int3

ffffffff8ac25f98 <neighbor_trampoline_265f98>:
ffffffff8ac25f98:	e9 53 52 74 00       	jmp    ffffffff8b36b1f0 <neighbor_trampoline_266758+0x744a98>
ffffffff8ac25f9d:	cc                   	int3
ffffffff8ac25f9e:	cc                   	int3
ffffffff8ac25f9f:	cc                   	int3

ffffffff8ac25fa0 <neighbor_trampoline_265fa0>:
ffffffff8ac25fa0:	e9 db 59 85 00       	jmp    ffffffff8b47b980 <neighbor_trampoline_266758+0x855228>
ffffffff8ac25fa5:	cc                   	int3
ffffffff8ac25fa6:	cc                   	int3
ffffffff8ac25fa7:	cc                   	int3

ffffffff8ac25fa8 <neighbor_trampoline_265fa8>:
ffffffff8ac25fa8:	e9 33 33 49 00       	jmp    ffffffff8b0b92e0 <neighbor_trampoline_266758+0x492b88>
ffffffff8ac25fad:	cc                   	int3
ffffffff8ac25fae:	cc                   	int3
ffffffff8ac25faf:	cc                   	int3

ffffffff8ac25fb0 <neighbor_trampoline_265fb0>:
ffffffff8ac25fb0:	e9 eb ed 1c 00       	jmp    ffffffff8adf4da0 <neighbor_trampoline_266758+0x1ce648>
ffffffff8ac25fb5:	cc                   	int3
ffffffff8ac25fb6:	cc                   	int3
ffffffff8ac25fb7:	cc                   	int3

ffffffff8ac25fb8 <neighbor_trampoline_265fb8>:
ffffffff8ac25fb8:	e9 f3 ed 1c 00       	jmp    ffffffff8adf4db0 <neighbor_trampoline_266758+0x1ce658>
ffffffff8ac25fbd:	cc                   	int3
ffffffff8ac25fbe:	cc                   	int3
ffffffff8ac25fbf:	cc                   	int3

ffffffff8ac25fc0 <neighbor_trampoline_265fc0>:
ffffffff8ac25fc0:	e9 fb ed 1c 00       	jmp    ffffffff8adf4dc0 <neighbor_trampoline_266758+0x1ce668>
ffffffff8ac25fc5:	cc                   	int3
ffffffff8ac25fc6:	cc                   	int3
ffffffff8ac25fc7:	cc                   	int3

ffffffff8ac25fc8 <neighbor_trampoline_265fc8>:
ffffffff8ac25fc8:	e9 c3 1d 1d 00       	jmp    ffffffff8adf7d90 <neighbor_trampoline_266758+0x1d1638>
ffffffff8ac25fcd:	cc                   	int3
ffffffff8ac25fce:	cc                   	int3
ffffffff8ac25fcf:	cc                   	int3

ffffffff8ac25fd0 <neighbor_trampoline_265fd0>:
ffffffff8ac25fd0:	e9 ab 22 1d 00       	jmp    ffffffff8adf8280 <neighbor_trampoline_266758+0x1d1b28>
ffffffff8ac25fd5:	cc                   	int3
ffffffff8ac25fd6:	cc                   	int3
ffffffff8ac25fd7:	cc                   	int3

ffffffff8ac25fd8 <neighbor_trampoline_265fd8>:
ffffffff8ac25fd8:	e9 b3 06 88 00       	jmp    ffffffff8b4a6690 <neighbor_trampoline_266758+0x87ff38>
ffffffff8ac25fdd:	cc                   	int3
ffffffff8ac25fde:	cc                   	int3
ffffffff8ac25fdf:	cc                   	int3

ffffffff8ac25fe0 <neighbor_trampoline_265fe0>:
ffffffff8ac25fe0:	e9 9b 05 88 00       	jmp    ffffffff8b4a6580 <neighbor_trampoline_266758+0x87fe28>
ffffffff8ac25fe5:	cc                   	int3
ffffffff8ac25fe6:	cc                   	int3
ffffffff8ac25fe7:	cc                   	int3

ffffffff8ac25fe8 <neighbor_trampoline_265fe8>:
ffffffff8ac25fe8:	e9 e3 30 1e 00       	jmp    ffffffff8ae090d0 <neighbor_trampoline_266758+0x1e2978>
ffffffff8ac25fed:	cc                   	int3
ffffffff8ac25fee:	cc                   	int3
ffffffff8ac25fef:	cc                   	int3

ffffffff8ac25ff0 <neighbor_trampoline_265ff0>:
ffffffff8ac25ff0:	e9 cb 0d e4 ff       	jmp    ffffffff8aa66dc0 <handler_631_entry-0x1be9a0>
ffffffff8ac25ff5:	cc                   	int3
ffffffff8ac25ff6:	cc                   	int3
ffffffff8ac25ff7:	cc                   	int3

ffffffff8ac25ff8 <neighbor_trampoline_265ff8>:
ffffffff8ac25ff8:	e9 73 4a 1e 00       	jmp    ffffffff8ae0aa70 <neighbor_trampoline_266758+0x1e4318>
ffffffff8ac25ffd:	cc                   	int3
ffffffff8ac25ffe:	cc                   	int3
ffffffff8ac25fff:	cc                   	int3

ffffffff8ac26000 <neighbor_trampoline_266000>:
ffffffff8ac26000:	e9 0b 01 75 00       	jmp    ffffffff8b376110 <neighbor_trampoline_266758+0x74f9b8>
ffffffff8ac26005:	cc                   	int3
ffffffff8ac26006:	cc                   	int3
ffffffff8ac26007:	cc                   	int3

ffffffff8ac26008 <neighbor_trampoline_266008>:
ffffffff8ac26008:	e9 63 16 e4 ff       	jmp    ffffffff8aa67670 <handler_631_entry-0x1be0f0>
ffffffff8ac2600d:	cc                   	int3
ffffffff8ac2600e:	cc                   	int3
ffffffff8ac2600f:	cc                   	int3

ffffffff8ac26010 <neighbor_trampoline_266010>:
ffffffff8ac26010:	e9 3b 18 e4 ff       	jmp    ffffffff8aa67850 <handler_631_entry-0x1bdf10>
ffffffff8ac26015:	cc                   	int3
ffffffff8ac26016:	cc                   	int3
ffffffff8ac26017:	cc                   	int3

ffffffff8ac26018 <neighbor_trampoline_266018>:
ffffffff8ac26018:	e9 63 18 e4 ff       	jmp    ffffffff8aa67880 <handler_631_entry-0x1bdee0>
ffffffff8ac2601d:	cc                   	int3
ffffffff8ac2601e:	cc                   	int3
ffffffff8ac2601f:	cc                   	int3

ffffffff8ac26020 <neighbor_trampoline_266020>:
ffffffff8ac26020:	e9 1b c0 1e 00       	jmp    ffffffff8ae12040 <neighbor_trampoline_266758+0x1eb8e8>
ffffffff8ac26025:	cc                   	int3
ffffffff8ac26026:	cc                   	int3
ffffffff8ac26027:	cc                   	int3

ffffffff8ac26028 <neighbor_trampoline_266028>:
ffffffff8ac26028:	e9 93 ec 1e 00       	jmp    ffffffff8ae14cc0 <neighbor_trampoline_266758+0x1ee568>
ffffffff8ac2602d:	cc                   	int3
ffffffff8ac2602e:	cc                   	int3
ffffffff8ac2602f:	cc                   	int3

ffffffff8ac26030 <neighbor_trampoline_266030>:
ffffffff8ac26030:	e9 eb 17 1f 00       	jmp    ffffffff8ae17820 <neighbor_trampoline_266758+0x1f10c8>
ffffffff8ac26035:	cc                   	int3
ffffffff8ac26036:	cc                   	int3
ffffffff8ac26037:	cc                   	int3

ffffffff8ac26038 <neighbor_trampoline_266038>:
ffffffff8ac26038:	e9 33 7f 20 00       	jmp    ffffffff8ae2df70 <neighbor_trampoline_266758+0x207818>
ffffffff8ac2603d:	cc                   	int3
ffffffff8ac2603e:	cc                   	int3
ffffffff8ac2603f:	cc                   	int3

ffffffff8ac26040 <neighbor_trampoline_266040>:
ffffffff8ac26040:	e9 3b 80 20 00       	jmp    ffffffff8ae2e080 <neighbor_trampoline_266758+0x207928>
ffffffff8ac26045:	cc                   	int3
ffffffff8ac26046:	cc                   	int3
ffffffff8ac26047:	cc                   	int3

ffffffff8ac26048 <neighbor_trampoline_266048>:
ffffffff8ac26048:	e9 43 c9 20 00       	jmp    ffffffff8ae32990 <neighbor_trampoline_266758+0x20c238>
ffffffff8ac2604d:	cc                   	int3
ffffffff8ac2604e:	cc                   	int3
ffffffff8ac2604f:	cc                   	int3

ffffffff8ac26050 <neighbor_trampoline_266050>:
ffffffff8ac26050:	e9 5b d3 20 00       	jmp    ffffffff8ae333b0 <neighbor_trampoline_266758+0x20cc58>
ffffffff8ac26055:	cc                   	int3
ffffffff8ac26056:	cc                   	int3
ffffffff8ac26057:	cc                   	int3

ffffffff8ac26058 <neighbor_trampoline_266058>:
ffffffff8ac26058:	e9 53 d8 20 00       	jmp    ffffffff8ae338b0 <neighbor_trampoline_266758+0x20d158>
ffffffff8ac2605d:	cc                   	int3
ffffffff8ac2605e:	cc                   	int3
ffffffff8ac2605f:	cc                   	int3

ffffffff8ac26060 <neighbor_trampoline_266060>:
ffffffff8ac26060:	e9 eb e1 20 00       	jmp    ffffffff8ae34250 <neighbor_trampoline_266758+0x20daf8>
ffffffff8ac26065:	cc                   	int3
ffffffff8ac26066:	cc                   	int3
ffffffff8ac26067:	cc                   	int3

ffffffff8ac26068 <neighbor_trampoline_266068>:
ffffffff8ac26068:	e9 43 ed 20 00       	jmp    ffffffff8ae34db0 <neighbor_trampoline_266758+0x20e658>
ffffffff8ac2606d:	cc                   	int3
ffffffff8ac2606e:	cc                   	int3
ffffffff8ac2606f:	cc                   	int3

ffffffff8ac26070 <neighbor_trampoline_266070>:
ffffffff8ac26070:	e9 7b 6f 21 00       	jmp    ffffffff8ae3cff0 <neighbor_trampoline_266758+0x216898>
ffffffff8ac26075:	cc                   	int3
ffffffff8ac26076:	cc                   	int3
ffffffff8ac26077:	cc                   	int3

ffffffff8ac26078 <neighbor_trampoline_266078>:
ffffffff8ac26078:	e9 73 7f fb ff       	jmp    ffffffff8abddff0 <handler_631_entry-0x47770>
ffffffff8ac2607d:	cc                   	int3
ffffffff8ac2607e:	cc                   	int3
ffffffff8ac2607f:	cc                   	int3

ffffffff8ac26080 <neighbor_trampoline_266080>:
ffffffff8ac26080:	e9 7b a2 22 00       	jmp    ffffffff8ae50300 <neighbor_trampoline_266758+0x229ba8>
ffffffff8ac26085:	cc                   	int3
ffffffff8ac26086:	cc                   	int3
ffffffff8ac26087:	cc                   	int3

ffffffff8ac26088 <neighbor_trampoline_266088>:
ffffffff8ac26088:	e9 23 ad 22 00       	jmp    ffffffff8ae50db0 <neighbor_trampoline_266758+0x22a658>
ffffffff8ac2608d:	cc                   	int3
ffffffff8ac2608e:	cc                   	int3
ffffffff8ac2608f:	cc                   	int3

ffffffff8ac26090 <neighbor_trampoline_266090>:
ffffffff8ac26090:	e9 1b 1f 23 00       	jmp    ffffffff8ae57fb0 <neighbor_trampoline_266758+0x231858>
ffffffff8ac26095:	cc                   	int3
ffffffff8ac26096:	cc                   	int3
ffffffff8ac26097:	cc                   	int3

ffffffff8ac26098 <neighbor_trampoline_266098>:
ffffffff8ac26098:	e9 43 1f 23 00       	jmp    ffffffff8ae57fe0 <neighbor_trampoline_266758+0x231888>
ffffffff8ac2609d:	cc                   	int3
ffffffff8ac2609e:	cc                   	int3
ffffffff8ac2609f:	cc                   	int3

ffffffff8ac260a0 <neighbor_trampoline_2660a0>:
ffffffff8ac260a0:	e9 8b 25 23 00       	jmp    ffffffff8ae58630 <neighbor_trampoline_266758+0x231ed8>
ffffffff8ac260a5:	cc                   	int3
ffffffff8ac260a6:	cc                   	int3
ffffffff8ac260a7:	cc                   	int3

ffffffff8ac260a8 <neighbor_trampoline_2660a8>:
ffffffff8ac260a8:	e9 93 25 23 00       	jmp    ffffffff8ae58640 <neighbor_trampoline_266758+0x231ee8>
ffffffff8ac260ad:	cc                   	int3
ffffffff8ac260ae:	cc                   	int3
ffffffff8ac260af:	cc                   	int3

ffffffff8ac260b0 <neighbor_trampoline_2660b0>:
ffffffff8ac260b0:	e9 0b 1b 69 00       	jmp    ffffffff8b2b7bc0 <neighbor_trampoline_266758+0x691468>
ffffffff8ac260b5:	cc                   	int3
ffffffff8ac260b6:	cc                   	int3
ffffffff8ac260b7:	cc                   	int3

ffffffff8ac260b8 <neighbor_trampoline_2660b8>:
ffffffff8ac260b8:	e9 43 07 69 00       	jmp    ffffffff8b2b6800 <neighbor_trampoline_266758+0x6900a8>
ffffffff8ac260bd:	cc                   	int3
ffffffff8ac260be:	cc                   	int3
ffffffff8ac260bf:	cc                   	int3

ffffffff8ac260c0 <neighbor_trampoline_2660c0>:
ffffffff8ac260c0:	e9 5b 13 69 00       	jmp    ffffffff8b2b7420 <neighbor_trampoline_266758+0x690cc8>
ffffffff8ac260c5:	cc                   	int3
ffffffff8ac260c6:	cc                   	int3
ffffffff8ac260c7:	cc                   	int3

ffffffff8ac260c8 <neighbor_trampoline_2660c8>:
ffffffff8ac260c8:	e9 b3 3e 69 00       	jmp    ffffffff8b2b9f80 <neighbor_trampoline_266758+0x693828>
ffffffff8ac260cd:	cc                   	int3
ffffffff8ac260ce:	cc                   	int3
ffffffff8ac260cf:	cc                   	int3

ffffffff8ac260d0 <neighbor_trampoline_2660d0>:
ffffffff8ac260d0:	e9 7b 92 37 00       	jmp    ffffffff8af9f350 <neighbor_trampoline_266758+0x378bf8>
ffffffff8ac260d5:	cc                   	int3
ffffffff8ac260d6:	cc                   	int3
ffffffff8ac260d7:	cc                   	int3

ffffffff8ac260d8 <neighbor_trampoline_2660d8>:
ffffffff8ac260d8:	e9 43 97 37 00       	jmp    ffffffff8af9f820 <neighbor_trampoline_266758+0x3790c8>
ffffffff8ac260dd:	cc                   	int3
ffffffff8ac260de:	cc                   	int3
ffffffff8ac260df:	cc                   	int3

ffffffff8ac260e0 <neighbor_trampoline_2660e0>:
ffffffff8ac260e0:	e9 fb eb 7c 00       	jmp    ffffffff8b3f4ce0 <neighbor_trampoline_266758+0x7ce588>
ffffffff8ac260e5:	cc                   	int3
ffffffff8ac260e6:	cc                   	int3
ffffffff8ac260e7:	cc                   	int3

ffffffff8ac260e8 <neighbor_trampoline_2660e8>:
ffffffff8ac260e8:	e9 b3 23 38 00       	jmp    ffffffff8afa84a0 <neighbor_trampoline_266758+0x381d48>
ffffffff8ac260ed:	cc                   	int3
ffffffff8ac260ee:	cc                   	int3
ffffffff8ac260ef:	cc                   	int3

ffffffff8ac260f0 <neighbor_trampoline_2660f0>:
ffffffff8ac260f0:	e9 fb 20 69 00       	jmp    ffffffff8b2b81f0 <neighbor_trampoline_266758+0x691a98>
ffffffff8ac260f5:	cc                   	int3
ffffffff8ac260f6:	cc                   	int3
ffffffff8ac260f7:	cc                   	int3

ffffffff8ac260f8 <neighbor_trampoline_2660f8>:
ffffffff8ac260f8:	e9 13 33 69 00       	jmp    ffffffff8b2b9410 <neighbor_trampoline_266758+0x692cb8>
ffffffff8ac260fd:	cc                   	int3
ffffffff8ac260fe:	cc                   	int3
ffffffff8ac260ff:	cc                   	int3

ffffffff8ac26100 <neighbor_trampoline_266100>:
ffffffff8ac26100:	e9 eb 62 69 00       	jmp    ffffffff8b2bc3f0 <neighbor_trampoline_266758+0x695c98>
ffffffff8ac26105:	cc                   	int3
ffffffff8ac26106:	cc                   	int3
ffffffff8ac26107:	cc                   	int3

ffffffff8ac26108 <neighbor_trampoline_266108>:
ffffffff8ac26108:	e9 83 0b 69 00       	jmp    ffffffff8b2b6c90 <neighbor_trampoline_266758+0x690538>
ffffffff8ac2610d:	cc                   	int3
ffffffff8ac2610e:	cc                   	int3
ffffffff8ac2610f:	cc                   	int3

ffffffff8ac26110 <neighbor_trampoline_266110>:
ffffffff8ac26110:	e9 fb b8 a4 00       	jmp    ffffffff8b671a10 <neighbor_trampoline_266758+0xa4b2b8>
ffffffff8ac26115:	cc                   	int3
ffffffff8ac26116:	cc                   	int3
ffffffff8ac26117:	cc                   	int3

ffffffff8ac26118 <neighbor_trampoline_266118>:
ffffffff8ac26118:	e9 83 22 85 00       	jmp    ffffffff8b4783a0 <neighbor_trampoline_266758+0x851c48>
ffffffff8ac2611d:	cc                   	int3
ffffffff8ac2611e:	cc                   	int3
ffffffff8ac2611f:	cc                   	int3

ffffffff8ac26120 <neighbor_trampoline_266120>:
ffffffff8ac26120:	e9 8b 22 85 00       	jmp    ffffffff8b4783b0 <neighbor_trampoline_266758+0x851c58>
ffffffff8ac26125:	cc                   	int3
ffffffff8ac26126:	cc                   	int3
ffffffff8ac26127:	cc                   	int3

ffffffff8ac26128 <neighbor_trampoline_266128>:
ffffffff8ac26128:	e9 93 40 69 00       	jmp    ffffffff8b2ba1c0 <neighbor_trampoline_266758+0x693a68>
ffffffff8ac2612d:	cc                   	int3
ffffffff8ac2612e:	cc                   	int3
ffffffff8ac2612f:	cc                   	int3

ffffffff8ac26130 <neighbor_trampoline_266130>:
ffffffff8ac26130:	e9 0b 1a 69 00       	jmp    ffffffff8b2b7b40 <neighbor_trampoline_266758+0x6913e8>
ffffffff8ac26135:	cc                   	int3
ffffffff8ac26136:	cc                   	int3
ffffffff8ac26137:	cc                   	int3

ffffffff8ac26138 <neighbor_trampoline_266138>:
ffffffff8ac26138:	e9 23 a8 23 00       	jmp    ffffffff8ae60960 <neighbor_trampoline_266758+0x23a208>
ffffffff8ac2613d:	cc                   	int3
ffffffff8ac2613e:	cc                   	int3
ffffffff8ac2613f:	cc                   	int3

ffffffff8ac26140 <neighbor_trampoline_266140>:
ffffffff8ac26140:	e9 3b 36 4c 00       	jmp    ffffffff8b0e9780 <neighbor_trampoline_266758+0x4c3028>
ffffffff8ac26145:	cc                   	int3
ffffffff8ac26146:	cc                   	int3
ffffffff8ac26147:	cc                   	int3

ffffffff8ac26148 <neighbor_trampoline_266148>:
ffffffff8ac26148:	e9 43 36 4c 00       	jmp    ffffffff8b0e9790 <neighbor_trampoline_266758+0x4c3038>
ffffffff8ac2614d:	cc                   	int3
ffffffff8ac2614e:	cc                   	int3
ffffffff8ac2614f:	cc                   	int3

ffffffff8ac26150 <neighbor_trampoline_266150>:
ffffffff8ac26150:	e9 4b 36 4c 00       	jmp    ffffffff8b0e97a0 <neighbor_trampoline_266758+0x4c3048>
ffffffff8ac26155:	cc                   	int3
ffffffff8ac26156:	cc                   	int3
ffffffff8ac26157:	cc                   	int3

ffffffff8ac26158 <neighbor_trampoline_266158>:
ffffffff8ac26158:	e9 33 54 45 00       	jmp    ffffffff8b07b590 <neighbor_trampoline_266758+0x454e38>
ffffffff8ac2615d:	cc                   	int3
ffffffff8ac2615e:	cc                   	int3
ffffffff8ac2615f:	cc                   	int3

ffffffff8ac26160 <neighbor_trampoline_266160>:
ffffffff8ac26160:	e9 3b 2c 85 00       	jmp    ffffffff8b478da0 <neighbor_trampoline_266758+0x852648>
ffffffff8ac26165:	cc                   	int3
ffffffff8ac26166:	cc                   	int3
ffffffff8ac26167:	cc                   	int3

ffffffff8ac26168 <neighbor_trampoline_266168>:
ffffffff8ac26168:	e9 03 40 69 00       	jmp    ffffffff8b2ba170 <neighbor_trampoline_266758+0x693a18>
ffffffff8ac2616d:	cc                   	int3
ffffffff8ac2616e:	cc                   	int3
ffffffff8ac2616f:	cc                   	int3

ffffffff8ac26170 <neighbor_trampoline_266170>:
ffffffff8ac26170:	e9 4b 8f 91 00       	jmp    ffffffff8b53f0c0 <neighbor_trampoline_266758+0x918968>
ffffffff8ac26175:	cc                   	int3
ffffffff8ac26176:	cc                   	int3
ffffffff8ac26177:	cc                   	int3

ffffffff8ac26178 <neighbor_trampoline_266178>:
ffffffff8ac26178:	e9 83 8f 91 00       	jmp    ffffffff8b53f100 <neighbor_trampoline_266758+0x9189a8>
ffffffff8ac2617d:	cc                   	int3
ffffffff8ac2617e:	cc                   	int3
ffffffff8ac2617f:	cc                   	int3

ffffffff8ac26180 <neighbor_trampoline_266180>:
ffffffff8ac26180:	e9 6b 3b 69 00       	jmp    ffffffff8b2b9cf0 <neighbor_trampoline_266758+0x693598>
ffffffff8ac26185:	cc                   	int3
ffffffff8ac26186:	cc                   	int3
ffffffff8ac26187:	cc                   	int3

ffffffff8ac26188 <neighbor_trampoline_266188>:
ffffffff8ac26188:	e9 b3 45 69 00       	jmp    ffffffff8b2ba740 <neighbor_trampoline_266758+0x693fe8>
ffffffff8ac2618d:	cc                   	int3
ffffffff8ac2618e:	cc                   	int3
ffffffff8ac2618f:	cc                   	int3

ffffffff8ac26190 <neighbor_trampoline_266190>:
ffffffff8ac26190:	e9 db c9 2e 00       	jmp    ffffffff8af12b70 <neighbor_trampoline_266758+0x2ec418>
ffffffff8ac26195:	cc                   	int3
ffffffff8ac26196:	cc                   	int3
ffffffff8ac26197:	cc                   	int3

ffffffff8ac26198 <neighbor_trampoline_266198>:
ffffffff8ac26198:	e9 53 ca 2e 00       	jmp    ffffffff8af12bf0 <neighbor_trampoline_266758+0x2ec498>
ffffffff8ac2619d:	cc                   	int3
ffffffff8ac2619e:	cc                   	int3
ffffffff8ac2619f:	cc                   	int3

ffffffff8ac261a0 <neighbor_trampoline_2661a0>:
ffffffff8ac261a0:	e9 ab ca 2e 00       	jmp    ffffffff8af12c50 <neighbor_trampoline_266758+0x2ec4f8>
ffffffff8ac261a5:	cc                   	int3
ffffffff8ac261a6:	cc                   	int3
ffffffff8ac261a7:	cc                   	int3

ffffffff8ac261a8 <neighbor_trampoline_2661a8>:
ffffffff8ac261a8:	e9 d3 ca 2e 00       	jmp    ffffffff8af12c80 <neighbor_trampoline_266758+0x2ec528>
ffffffff8ac261ad:	cc                   	int3
ffffffff8ac261ae:	cc                   	int3
ffffffff8ac261af:	cc                   	int3

ffffffff8ac261b0 <neighbor_trampoline_2661b0>:
ffffffff8ac261b0:	e9 fb ca 2e 00       	jmp    ffffffff8af12cb0 <neighbor_trampoline_266758+0x2ec558>
ffffffff8ac261b5:	cc                   	int3
ffffffff8ac261b6:	cc                   	int3
ffffffff8ac261b7:	cc                   	int3

ffffffff8ac261b8 <neighbor_trampoline_2661b8>:
ffffffff8ac261b8:	e9 23 cb 2e 00       	jmp    ffffffff8af12ce0 <neighbor_trampoline_266758+0x2ec588>
ffffffff8ac261bd:	cc                   	int3
ffffffff8ac261be:	cc                   	int3
ffffffff8ac261bf:	cc                   	int3

ffffffff8ac261c0 <neighbor_trampoline_2661c0>:
ffffffff8ac261c0:	e9 3b 86 91 00       	jmp    ffffffff8b53e800 <neighbor_trampoline_266758+0x9180a8>
ffffffff8ac261c5:	cc                   	int3
ffffffff8ac261c6:	cc                   	int3
ffffffff8ac261c7:	cc                   	int3

ffffffff8ac261c8 <neighbor_trampoline_2661c8>:
ffffffff8ac261c8:	e9 13 8a 91 00       	jmp    ffffffff8b53ebe0 <neighbor_trampoline_266758+0x918488>
ffffffff8ac261cd:	cc                   	int3
ffffffff8ac261ce:	cc                   	int3
ffffffff8ac261cf:	cc                   	int3

ffffffff8ac261d0 <neighbor_trampoline_2661d0>:
ffffffff8ac261d0:	e9 9b 8d 91 00       	jmp    ffffffff8b53ef70 <neighbor_trampoline_266758+0x918818>
ffffffff8ac261d5:	cc                   	int3
ffffffff8ac261d6:	cc                   	int3
ffffffff8ac261d7:	cc                   	int3

ffffffff8ac261d8 <neighbor_trampoline_2661d8>:
ffffffff8ac261d8:	e9 53 0b 9a 00       	jmp    ffffffff8b5c6d30 <neighbor_trampoline_266758+0x9a05d8>
ffffffff8ac261dd:	cc                   	int3
ffffffff8ac261de:	cc                   	int3
ffffffff8ac261df:	cc                   	int3

ffffffff8ac261e0 <neighbor_trampoline_2661e0>:
ffffffff8ac261e0:	e9 ab c4 52 00       	jmp    ffffffff8b152690 <neighbor_trampoline_266758+0x52bf38>
ffffffff8ac261e5:	cc                   	int3
ffffffff8ac261e6:	cc                   	int3
ffffffff8ac261e7:	cc                   	int3

ffffffff8ac261e8 <neighbor_trampoline_2661e8>:
ffffffff8ac261e8:	e9 33 29 38 00       	jmp    ffffffff8afa8b20 <neighbor_trampoline_266758+0x3823c8>
ffffffff8ac261ed:	cc                   	int3
ffffffff8ac261ee:	cc                   	int3
ffffffff8ac261ef:	cc                   	int3

ffffffff8ac261f0 <neighbor_trampoline_2661f0>:
ffffffff8ac261f0:	e9 1b cb 2e 00       	jmp    ffffffff8af12d10 <neighbor_trampoline_266758+0x2ec5b8>
ffffffff8ac261f5:	cc                   	int3
ffffffff8ac261f6:	cc                   	int3
ffffffff8ac261f7:	cc                   	int3

ffffffff8ac261f8 <neighbor_trampoline_2661f8>:
ffffffff8ac261f8:	e9 63 8f 91 00       	jmp    ffffffff8b53f160 <neighbor_trampoline_266758+0x918a08>
ffffffff8ac261fd:	cc                   	int3
ffffffff8ac261fe:	cc                   	int3
ffffffff8ac261ff:	cc                   	int3

ffffffff8ac26200 <neighbor_trampoline_266200>:
ffffffff8ac26200:	e9 4b 80 37 00       	jmp    ffffffff8af9e250 <neighbor_trampoline_266758+0x377af8>
ffffffff8ac26205:	cc                   	int3
ffffffff8ac26206:	cc                   	int3
ffffffff8ac26207:	cc                   	int3

ffffffff8ac26208 <neighbor_trampoline_266208>:
ffffffff8ac26208:	e9 23 e8 7e 00       	jmp    ffffffff8b414a30 <neighbor_trampoline_266758+0x7ee2d8>
ffffffff8ac2620d:	cc                   	int3
ffffffff8ac2620e:	cc                   	int3
ffffffff8ac2620f:	cc                   	int3

ffffffff8ac26210 <neighbor_trampoline_266210>:
ffffffff8ac26210:	e9 2b e8 7e 00       	jmp    ffffffff8b414a40 <neighbor_trampoline_266758+0x7ee2e8>
ffffffff8ac26215:	cc                   	int3
ffffffff8ac26216:	cc                   	int3
ffffffff8ac26217:	cc                   	int3

ffffffff8ac26218 <neighbor_trampoline_266218>:
ffffffff8ac26218:	e9 33 e8 7e 00       	jmp    ffffffff8b414a50 <neighbor_trampoline_266758+0x7ee2f8>
ffffffff8ac2621d:	cc                   	int3
ffffffff8ac2621e:	cc                   	int3
ffffffff8ac2621f:	cc                   	int3

ffffffff8ac26220 <neighbor_trampoline_266220>:
ffffffff8ac26220:	e9 3b e8 7e 00       	jmp    ffffffff8b414a60 <neighbor_trampoline_266758+0x7ee308>
ffffffff8ac26225:	cc                   	int3
ffffffff8ac26226:	cc                   	int3
ffffffff8ac26227:	cc                   	int3

ffffffff8ac26228 <neighbor_trampoline_266228>:
ffffffff8ac26228:	e9 53 e8 7e 00       	jmp    ffffffff8b414a80 <neighbor_trampoline_266758+0x7ee328>
ffffffff8ac2622d:	cc                   	int3
ffffffff8ac2622e:	cc                   	int3
ffffffff8ac2622f:	cc                   	int3

ffffffff8ac26230 <neighbor_trampoline_266230>:
ffffffff8ac26230:	e9 5b e8 7e 00       	jmp    ffffffff8b414a90 <neighbor_trampoline_266758+0x7ee338>
ffffffff8ac26235:	cc                   	int3
ffffffff8ac26236:	cc                   	int3
ffffffff8ac26237:	cc                   	int3

ffffffff8ac26238 <neighbor_trampoline_266238>:
ffffffff8ac26238:	e9 e3 34 69 00       	jmp    ffffffff8b2b9720 <neighbor_trampoline_266758+0x692fc8>
ffffffff8ac2623d:	cc                   	int3
ffffffff8ac2623e:	cc                   	int3
ffffffff8ac2623f:	cc                   	int3

ffffffff8ac26240 <neighbor_trampoline_266240>:
ffffffff8ac26240:	e9 6b e8 7e 00       	jmp    ffffffff8b414ab0 <neighbor_trampoline_266758+0x7ee358>
ffffffff8ac26245:	cc                   	int3
ffffffff8ac26246:	cc                   	int3
ffffffff8ac26247:	cc                   	int3

ffffffff8ac26248 <neighbor_trampoline_266248>:
ffffffff8ac26248:	e9 93 02 69 00       	jmp    ffffffff8b2b64e0 <neighbor_trampoline_266758+0x68fd88>
ffffffff8ac2624d:	cc                   	int3
ffffffff8ac2624e:	cc                   	int3
ffffffff8ac2624f:	cc                   	int3

ffffffff8ac26250 <neighbor_trampoline_266250>:
ffffffff8ac26250:	e9 9b fc 68 00       	jmp    ffffffff8b2b5ef0 <neighbor_trampoline_266758+0x68f798>
ffffffff8ac26255:	cc                   	int3
ffffffff8ac26256:	cc                   	int3
ffffffff8ac26257:	cc                   	int3

ffffffff8ac26258 <neighbor_trampoline_266258>:
ffffffff8ac26258:	e9 c3 e7 7e 00       	jmp    ffffffff8b414a20 <neighbor_trampoline_266758+0x7ee2c8>
ffffffff8ac2625d:	cc                   	int3
ffffffff8ac2625e:	cc                   	int3
ffffffff8ac2625f:	cc                   	int3

ffffffff8ac26260 <neighbor_trampoline_266260>:
ffffffff8ac26260:	e9 0b e8 7e 00       	jmp    ffffffff8b414a70 <neighbor_trampoline_266758+0x7ee318>
ffffffff8ac26265:	cc                   	int3
ffffffff8ac26266:	cc                   	int3
ffffffff8ac26267:	cc                   	int3

ffffffff8ac26268 <neighbor_trampoline_266268>:
ffffffff8ac26268:	e9 33 e8 7e 00       	jmp    ffffffff8b414aa0 <neighbor_trampoline_266758+0x7ee348>
ffffffff8ac2626d:	cc                   	int3
ffffffff8ac2626e:	cc                   	int3
ffffffff8ac2626f:	cc                   	int3

ffffffff8ac26270 <neighbor_trampoline_266270>:
ffffffff8ac26270:	e9 5b f2 47 00       	jmp    ffffffff8b0a54d0 <neighbor_trampoline_266758+0x47ed78>
ffffffff8ac26275:	cc                   	int3
ffffffff8ac26276:	cc                   	int3
ffffffff8ac26277:	cc                   	int3

ffffffff8ac26278 <neighbor_trampoline_266278>:
ffffffff8ac26278:	e9 33 92 91 00       	jmp    ffffffff8b53f4b0 <neighbor_trampoline_266758+0x918d58>
ffffffff8ac2627d:	cc                   	int3
ffffffff8ac2627e:	cc                   	int3
ffffffff8ac2627f:	cc                   	int3

ffffffff8ac26280 <neighbor_trampoline_266280>:
ffffffff8ac26280:	e9 db 73 5d 00       	jmp    ffffffff8b1fd660 <neighbor_trampoline_266758+0x5d6f08>
ffffffff8ac26285:	cc                   	int3
ffffffff8ac26286:	cc                   	int3
ffffffff8ac26287:	cc                   	int3

ffffffff8ac26288 <neighbor_trampoline_266288>:
ffffffff8ac26288:	e9 33 75 5d 00       	jmp    ffffffff8b1fd7c0 <neighbor_trampoline_266758+0x5d7068>
ffffffff8ac2628d:	cc                   	int3
ffffffff8ac2628e:	cc                   	int3
ffffffff8ac2628f:	cc                   	int3

ffffffff8ac26290 <neighbor_trampoline_266290>:
ffffffff8ac26290:	e9 1b 78 5d 00       	jmp    ffffffff8b1fdab0 <neighbor_trampoline_266758+0x5d7358>
ffffffff8ac26295:	cc                   	int3
ffffffff8ac26296:	cc                   	int3
ffffffff8ac26297:	cc                   	int3

ffffffff8ac26298 <neighbor_trampoline_266298>:
ffffffff8ac26298:	e9 e3 7b 5d 00       	jmp    ffffffff8b1fde80 <neighbor_trampoline_266758+0x5d7728>
ffffffff8ac2629d:	cc                   	int3
ffffffff8ac2629e:	cc                   	int3
ffffffff8ac2629f:	cc                   	int3

ffffffff8ac262a0 <neighbor_trampoline_2662a0>:
ffffffff8ac262a0:	e9 db 39 69 00       	jmp    ffffffff8b2b9c80 <neighbor_trampoline_266758+0x693528>
ffffffff8ac262a5:	cc                   	int3
ffffffff8ac262a6:	cc                   	int3
ffffffff8ac262a7:	cc                   	int3

ffffffff8ac262a8 <neighbor_trampoline_2662a8>:
ffffffff8ac262a8:	e9 63 3e 69 00       	jmp    ffffffff8b2ba110 <neighbor_trampoline_266758+0x6939b8>
ffffffff8ac262ad:	cc                   	int3
ffffffff8ac262ae:	cc                   	int3
ffffffff8ac262af:	cc                   	int3

ffffffff8ac262b0 <neighbor_trampoline_2662b0>:
ffffffff8ac262b0:	e9 fb 2e 69 00       	jmp    ffffffff8b2b91b0 <neighbor_trampoline_266758+0x692a58>
ffffffff8ac262b5:	cc                   	int3
ffffffff8ac262b6:	cc                   	int3
ffffffff8ac262b7:	cc                   	int3

ffffffff8ac262b8 <neighbor_trampoline_2662b8>:
ffffffff8ac262b8:	e9 33 42 69 00       	jmp    ffffffff8b2ba4f0 <neighbor_trampoline_266758+0x693d98>
ffffffff8ac262bd:	cc                   	int3
ffffffff8ac262be:	cc                   	int3
ffffffff8ac262bf:	cc                   	int3

ffffffff8ac262c0 <neighbor_trampoline_2662c0>:
ffffffff8ac262c0:	e9 cb 1d 69 00       	jmp    ffffffff8b2b8090 <neighbor_trampoline_266758+0x691938>
ffffffff8ac262c5:	cc                   	int3
ffffffff8ac262c6:	cc                   	int3
ffffffff8ac262c7:	cc                   	int3

ffffffff8ac262c8 <neighbor_trampoline_2662c8>:
ffffffff8ac262c8:	e9 b3 58 69 00       	jmp    ffffffff8b2bbb80 <neighbor_trampoline_266758+0x695428>
ffffffff8ac262cd:	cc                   	int3
ffffffff8ac262ce:	cc                   	int3
ffffffff8ac262cf:	cc                   	int3

ffffffff8ac262d0 <neighbor_trampoline_2662d0>:
ffffffff8ac262d0:	e9 ab 18 69 00       	jmp    ffffffff8b2b7b80 <neighbor_trampoline_266758+0x691428>
ffffffff8ac262d5:	cc                   	int3
ffffffff8ac262d6:	cc                   	int3
ffffffff8ac262d7:	cc                   	int3

ffffffff8ac262d8 <neighbor_trampoline_2662d8>:
ffffffff8ac262d8:	e9 b3 15 69 00       	jmp    ffffffff8b2b7890 <neighbor_trampoline_266758+0x691138>
ffffffff8ac262dd:	cc                   	int3
ffffffff8ac262de:	cc                   	int3
ffffffff8ac262df:	cc                   	int3

ffffffff8ac262e0 <neighbor_trampoline_2662e0>:
ffffffff8ac262e0:	e9 bb 55 69 00       	jmp    ffffffff8b2bb8a0 <neighbor_trampoline_266758+0x695148>
ffffffff8ac262e5:	cc                   	int3
ffffffff8ac262e6:	cc                   	int3
ffffffff8ac262e7:	cc                   	int3

ffffffff8ac262e8 <neighbor_trampoline_2662e8>:
ffffffff8ac262e8:	e9 23 22 69 00       	jmp    ffffffff8b2b8510 <neighbor_trampoline_266758+0x691db8>
ffffffff8ac262ed:	cc                   	int3
ffffffff8ac262ee:	cc                   	int3
ffffffff8ac262ef:	cc                   	int3

ffffffff8ac262f0 <neighbor_trampoline_2662f0>:
ffffffff8ac262f0:	e9 0b 25 69 00       	jmp    ffffffff8b2b8800 <neighbor_trampoline_266758+0x6920a8>
ffffffff8ac262f5:	cc                   	int3
ffffffff8ac262f6:	cc                   	int3
ffffffff8ac262f7:	cc                   	int3

ffffffff8ac262f8 <neighbor_trampoline_2662f8>:
ffffffff8ac262f8:	e9 83 4d 23 00       	jmp    ffffffff8ae5b080 <neighbor_trampoline_266758+0x234928>
ffffffff8ac262fd:	cc                   	int3
ffffffff8ac262fe:	cc                   	int3
ffffffff8ac262ff:	cc                   	int3

ffffffff8ac26300 <neighbor_trampoline_266300>:
ffffffff8ac26300:	e9 8b 4d 23 00       	jmp    ffffffff8ae5b090 <neighbor_trampoline_266758+0x234938>
ffffffff8ac26305:	cc                   	int3
ffffffff8ac26306:	cc                   	int3
ffffffff8ac26307:	cc                   	int3

ffffffff8ac26308 <neighbor_trampoline_266308>:
ffffffff8ac26308:	e9 43 97 2f 00       	jmp    ffffffff8af1fa50 <neighbor_trampoline_266758+0x2f92f8>
ffffffff8ac2630d:	cc                   	int3
ffffffff8ac2630e:	cc                   	int3
ffffffff8ac2630f:	cc                   	int3

ffffffff8ac26310 <neighbor_trampoline_266310>:
ffffffff8ac26310:	e9 5b e5 9c 00       	jmp    ffffffff8b5f4870 <neighbor_trampoline_266758+0x9ce118>
ffffffff8ac26315:	cc                   	int3
ffffffff8ac26316:	cc                   	int3
ffffffff8ac26317:	cc                   	int3

ffffffff8ac26318 <neighbor_trampoline_266318>:
ffffffff8ac26318:	e9 d3 69 57 00       	jmp    ffffffff8b19ccf0 <neighbor_trampoline_266758+0x576598>
ffffffff8ac2631d:	cc                   	int3
ffffffff8ac2631e:	cc                   	int3
ffffffff8ac2631f:	cc                   	int3

ffffffff8ac26320 <neighbor_trampoline_266320>:
ffffffff8ac26320:	e9 db 69 57 00       	jmp    ffffffff8b19cd00 <neighbor_trampoline_266758+0x5765a8>
ffffffff8ac26325:	cc                   	int3
ffffffff8ac26326:	cc                   	int3
ffffffff8ac26327:	cc                   	int3

ffffffff8ac26328 <neighbor_trampoline_266328>:
ffffffff8ac26328:	e9 e3 69 57 00       	jmp    ffffffff8b19cd10 <neighbor_trampoline_266758+0x5765b8>
ffffffff8ac2632d:	cc                   	int3
ffffffff8ac2632e:	cc                   	int3
ffffffff8ac2632f:	cc                   	int3

ffffffff8ac26330 <neighbor_trampoline_266330>:
ffffffff8ac26330:	e9 eb 69 57 00       	jmp    ffffffff8b19cd20 <neighbor_trampoline_266758+0x5765c8>
ffffffff8ac26335:	cc                   	int3
ffffffff8ac26336:	cc                   	int3
ffffffff8ac26337:	cc                   	int3

ffffffff8ac26338 <neighbor_trampoline_266338>:
ffffffff8ac26338:	e9 f3 69 57 00       	jmp    ffffffff8b19cd30 <neighbor_trampoline_266758+0x5765d8>
ffffffff8ac2633d:	cc                   	int3
ffffffff8ac2633e:	cc                   	int3
ffffffff8ac2633f:	cc                   	int3

ffffffff8ac26340 <neighbor_trampoline_266340>:
ffffffff8ac26340:	e9 4b 09 34 00       	jmp    ffffffff8af66c90 <neighbor_trampoline_266758+0x340538>
ffffffff8ac26345:	cc                   	int3
ffffffff8ac26346:	cc                   	int3
ffffffff8ac26347:	cc                   	int3

ffffffff8ac26348 <neighbor_trampoline_266348>:
ffffffff8ac26348:	e9 b3 0f 34 00       	jmp    ffffffff8af67300 <neighbor_trampoline_266758+0x340ba8>
ffffffff8ac2634d:	cc                   	int3
ffffffff8ac2634e:	cc                   	int3
ffffffff8ac2634f:	cc                   	int3

ffffffff8ac26350 <neighbor_trampoline_266350>:
ffffffff8ac26350:	e9 bb 12 34 00       	jmp    ffffffff8af67610 <neighbor_trampoline_266758+0x340eb8>
ffffffff8ac26355:	cc                   	int3
ffffffff8ac26356:	cc                   	int3
ffffffff8ac26357:	cc                   	int3

ffffffff8ac26358 <neighbor_trampoline_266358>:
ffffffff8ac26358:	e9 a3 15 34 00       	jmp    ffffffff8af67900 <neighbor_trampoline_266758+0x3411a8>
ffffffff8ac2635d:	cc                   	int3
ffffffff8ac2635e:	cc                   	int3
ffffffff8ac2635f:	cc                   	int3

ffffffff8ac26360 <neighbor_trampoline_266360>:
ffffffff8ac26360:	e9 cb 64 a3 00       	jmp    ffffffff8b65c830 <neighbor_trampoline_266758+0xa360d8>
ffffffff8ac26365:	cc                   	int3
ffffffff8ac26366:	cc                   	int3
ffffffff8ac26367:	cc                   	int3

ffffffff8ac26368 <neighbor_trampoline_266368>:
ffffffff8ac26368:	e9 93 1b 34 00       	jmp    ffffffff8af67f00 <neighbor_trampoline_266758+0x3417a8>
ffffffff8ac2636d:	cc                   	int3
ffffffff8ac2636e:	cc                   	int3
ffffffff8ac2636f:	cc                   	int3

ffffffff8ac26370 <neighbor_trampoline_266370>:
ffffffff8ac26370:	e9 fb 1c 34 00       	jmp    ffffffff8af68070 <neighbor_trampoline_266758+0x341918>
ffffffff8ac26375:	cc                   	int3
ffffffff8ac26376:	cc                   	int3
ffffffff8ac26377:	cc                   	int3

ffffffff8ac26378 <neighbor_trampoline_266378>:
ffffffff8ac26378:	e9 03 21 98 00       	jmp    ffffffff8b5a8480 <neighbor_trampoline_266758+0x981d28>
ffffffff8ac2637d:	cc                   	int3
ffffffff8ac2637e:	cc                   	int3
ffffffff8ac2637f:	cc                   	int3

ffffffff8ac26380 <neighbor_trampoline_266380>:
ffffffff8ac26380:	e9 1b 4d 23 00       	jmp    ffffffff8ae5b0a0 <neighbor_trampoline_266758+0x234948>
ffffffff8ac26385:	cc                   	int3
ffffffff8ac26386:	cc                   	int3
ffffffff8ac26387:	cc                   	int3

ffffffff8ac26388 <neighbor_trampoline_266388>:
ffffffff8ac26388:	e9 33 4d 23 00       	jmp    ffffffff8ae5b0c0 <neighbor_trampoline_266758+0x234968>
ffffffff8ac2638d:	cc                   	int3
ffffffff8ac2638e:	cc                   	int3
ffffffff8ac2638f:	cc                   	int3

ffffffff8ac26390 <neighbor_trampoline_266390>:
ffffffff8ac26390:	e9 3b 4d 23 00       	jmp    ffffffff8ae5b0d0 <neighbor_trampoline_266758+0x234978>
ffffffff8ac26395:	cc                   	int3
ffffffff8ac26396:	cc                   	int3
ffffffff8ac26397:	cc                   	int3

ffffffff8ac26398 <neighbor_trampoline_266398>:
ffffffff8ac26398:	e9 43 4d 23 00       	jmp    ffffffff8ae5b0e0 <neighbor_trampoline_266758+0x234988>
ffffffff8ac2639d:	cc                   	int3
ffffffff8ac2639e:	cc                   	int3
ffffffff8ac2639f:	cc                   	int3

ffffffff8ac263a0 <neighbor_trampoline_2663a0>:
ffffffff8ac263a0:	e9 4b 4d 23 00       	jmp    ffffffff8ae5b0f0 <neighbor_trampoline_266758+0x234998>
ffffffff8ac263a5:	cc                   	int3
ffffffff8ac263a6:	cc                   	int3
ffffffff8ac263a7:	cc                   	int3

ffffffff8ac263a8 <neighbor_trampoline_2663a8>:
ffffffff8ac263a8:	e9 73 a3 2c 00       	jmp    ffffffff8aef0720 <neighbor_trampoline_266758+0x2c9fc8>
ffffffff8ac263ad:	cc                   	int3
ffffffff8ac263ae:	cc                   	int3
ffffffff8ac263af:	cc                   	int3

ffffffff8ac263b0 <neighbor_trampoline_2663b0>:
ffffffff8ac263b0:	e9 bb b2 2c 00       	jmp    ffffffff8aef1670 <neighbor_trampoline_266758+0x2caf18>
ffffffff8ac263b5:	cc                   	int3
ffffffff8ac263b6:	cc                   	int3
ffffffff8ac263b7:	cc                   	int3

ffffffff8ac263b8 <neighbor_trampoline_2663b8>:
ffffffff8ac263b8:	e9 33 33 69 00       	jmp    ffffffff8b2b96f0 <neighbor_trampoline_266758+0x692f98>
ffffffff8ac263bd:	cc                   	int3
ffffffff8ac263be:	cc                   	int3
ffffffff8ac263bf:	cc                   	int3

ffffffff8ac263c0 <neighbor_trampoline_2663c0>:
ffffffff8ac263c0:	e9 6b ae 2c 00       	jmp    ffffffff8aef1230 <neighbor_trampoline_266758+0x2caad8>
ffffffff8ac263c5:	cc                   	int3
ffffffff8ac263c6:	cc                   	int3
ffffffff8ac263c7:	cc                   	int3

ffffffff8ac263c8 <neighbor_trampoline_2663c8>:
ffffffff8ac263c8:	e9 23 ca 59 00       	jmp    ffffffff8b1c2df0 <neighbor_trampoline_266758+0x59c698>
ffffffff8ac263cd:	cc                   	int3
ffffffff8ac263ce:	cc                   	int3
ffffffff8ac263cf:	cc                   	int3

ffffffff8ac263d0 <neighbor_trampoline_2663d0>:
ffffffff8ac263d0:	e9 6b 8d 91 00       	jmp    ffffffff8b53f140 <neighbor_trampoline_266758+0x9189e8>
ffffffff8ac263d5:	cc                   	int3
ffffffff8ac263d6:	cc                   	int3
ffffffff8ac263d7:	cc                   	int3

ffffffff8ac263d8 <neighbor_trampoline_2663d8>:
ffffffff8ac263d8:	e9 03 d2 87 00       	jmp    ffffffff8b4a35e0 <neighbor_trampoline_266758+0x87ce88>
ffffffff8ac263dd:	cc                   	int3
ffffffff8ac263de:	cc                   	int3
ffffffff8ac263df:	cc                   	int3

ffffffff8ac263e0 <neighbor_trampoline_2663e0>:
ffffffff8ac263e0:	e9 3b 8a 28 00       	jmp    ffffffff8aeaee20 <neighbor_trampoline_266758+0x2886c8>
ffffffff8ac263e5:	cc                   	int3
ffffffff8ac263e6:	cc                   	int3
ffffffff8ac263e7:	cc                   	int3

ffffffff8ac263e8 <neighbor_trampoline_2663e8>:
ffffffff8ac263e8:	e9 23 47 69 00       	jmp    ffffffff8b2bab10 <neighbor_trampoline_266758+0x6943b8>
ffffffff8ac263ed:	cc                   	int3
ffffffff8ac263ee:	cc                   	int3
ffffffff8ac263ef:	cc                   	int3

ffffffff8ac263f0 <neighbor_trampoline_2663f0>:
ffffffff8ac263f0:	e9 3b 4a 69 00       	jmp    ffffffff8b2bae30 <neighbor_trampoline_266758+0x6946d8>
ffffffff8ac263f5:	cc                   	int3
ffffffff8ac263f6:	cc                   	int3
ffffffff8ac263f7:	cc                   	int3

ffffffff8ac263f8 <neighbor_trampoline_2663f8>:
ffffffff8ac263f8:	e9 23 2e 76 00       	jmp    ffffffff8b389220 <neighbor_trampoline_266758+0x762ac8>
ffffffff8ac263fd:	cc                   	int3
ffffffff8ac263fe:	cc                   	int3
ffffffff8ac263ff:	cc                   	int3

ffffffff8ac26400 <neighbor_trampoline_266400>:
ffffffff8ac26400:	e9 fb 2c 76 00       	jmp    ffffffff8b389100 <neighbor_trampoline_266758+0x7629a8>
ffffffff8ac26405:	cc                   	int3
ffffffff8ac26406:	cc                   	int3
ffffffff8ac26407:	cc                   	int3

ffffffff8ac26408 <neighbor_trampoline_266408>:
ffffffff8ac26408:	e9 03 bf 3d 00       	jmp    ffffffff8b002310 <neighbor_trampoline_266758+0x3dbbb8>
ffffffff8ac2640d:	cc                   	int3
ffffffff8ac2640e:	cc                   	int3
ffffffff8ac2640f:	cc                   	int3

ffffffff8ac26410 <neighbor_trampoline_266410>:
ffffffff8ac26410:	e9 0b c4 3d 00       	jmp    ffffffff8b002820 <neighbor_trampoline_266758+0x3dc0c8>
ffffffff8ac26415:	cc                   	int3
ffffffff8ac26416:	cc                   	int3
ffffffff8ac26417:	cc                   	int3

ffffffff8ac26418 <neighbor_trampoline_266418>:
ffffffff8ac26418:	e9 c3 d2 3d 00       	jmp    ffffffff8b0036e0 <neighbor_trampoline_266758+0x3dcf88>
ffffffff8ac2641d:	cc                   	int3
ffffffff8ac2641e:	cc                   	int3
ffffffff8ac2641f:	cc                   	int3

ffffffff8ac26420 <neighbor_trampoline_266420>:
ffffffff8ac26420:	e9 ab d4 3d 00       	jmp    ffffffff8b0038d0 <neighbor_trampoline_266758+0x3dd178>
ffffffff8ac26425:	cc                   	int3
ffffffff8ac26426:	cc                   	int3
ffffffff8ac26427:	cc                   	int3

ffffffff8ac26428 <neighbor_trampoline_266428>:
ffffffff8ac26428:	e9 33 d8 3d 00       	jmp    ffffffff8b003c60 <neighbor_trampoline_266758+0x3dd508>
ffffffff8ac2642d:	cc                   	int3
ffffffff8ac2642e:	cc                   	int3
ffffffff8ac2642f:	cc                   	int3

ffffffff8ac26430 <neighbor_trampoline_266430>:
ffffffff8ac26430:	e9 5b 1e 79 00       	jmp    ffffffff8b3b8290 <neighbor_trampoline_266758+0x791b38>
ffffffff8ac26435:	cc                   	int3
ffffffff8ac26436:	cc                   	int3
ffffffff8ac26437:	cc                   	int3

ffffffff8ac26438 <neighbor_trampoline_266438>:
ffffffff8ac26438:	e9 33 57 79 00       	jmp    ffffffff8b3bbb70 <neighbor_trampoline_266758+0x795418>
ffffffff8ac2643d:	cc                   	int3
ffffffff8ac2643e:	cc                   	int3
ffffffff8ac2643f:	cc                   	int3

ffffffff8ac26440 <neighbor_trampoline_266440>:
ffffffff8ac26440:	e9 3b ee 7d 00       	jmp    ffffffff8b405280 <neighbor_trampoline_266758+0x7deb28>
ffffffff8ac26445:	cc                   	int3
ffffffff8ac26446:	cc                   	int3
ffffffff8ac26447:	cc                   	int3

ffffffff8ac26448 <neighbor_trampoline_266448>:
ffffffff8ac26448:	e9 53 18 a2 00       	jmp    ffffffff8b647ca0 <neighbor_trampoline_266758+0xa21548>
ffffffff8ac2644d:	cc                   	int3
ffffffff8ac2644e:	cc                   	int3
ffffffff8ac2644f:	cc                   	int3

ffffffff8ac26450 <neighbor_trampoline_266450>:
ffffffff8ac26450:	e9 ab 8b 79 00       	jmp    ffffffff8b3bf000 <neighbor_trampoline_266758+0x7988a8>
ffffffff8ac26455:	cc                   	int3
ffffffff8ac26456:	cc                   	int3
ffffffff8ac26457:	cc                   	int3

ffffffff8ac26458 <neighbor_trampoline_266458>:
ffffffff8ac26458:	e9 23 a3 79 00       	jmp    ffffffff8b3c0780 <neighbor_trampoline_266758+0x79a028>
ffffffff8ac2645d:	cc                   	int3
ffffffff8ac2645e:	cc                   	int3
ffffffff8ac2645f:	cc                   	int3

ffffffff8ac26460 <neighbor_trampoline_266460>:
ffffffff8ac26460:	e9 7b a3 79 00       	jmp    ffffffff8b3c07e0 <neighbor_trampoline_266758+0x79a088>
ffffffff8ac26465:	cc                   	int3
ffffffff8ac26466:	cc                   	int3
ffffffff8ac26467:	cc                   	int3

ffffffff8ac26468 <neighbor_trampoline_266468>:
ffffffff8ac26468:	e9 c3 83 85 00       	jmp    ffffffff8b47e830 <neighbor_trampoline_266758+0x8580d8>
ffffffff8ac2646d:	cc                   	int3
ffffffff8ac2646e:	cc                   	int3
ffffffff8ac2646f:	cc                   	int3

ffffffff8ac26470 <neighbor_trampoline_266470>:
ffffffff8ac26470:	e9 bb 6a 79 00       	jmp    ffffffff8b3bcf30 <neighbor_trampoline_266758+0x7967d8>
ffffffff8ac26475:	cc                   	int3
ffffffff8ac26476:	cc                   	int3
ffffffff8ac26477:	cc                   	int3

ffffffff8ac26478 <neighbor_trampoline_266478>:
ffffffff8ac26478:	e9 43 ab 38 00       	jmp    ffffffff8afb0fc0 <neighbor_trampoline_266758+0x38a868>
ffffffff8ac2647d:	cc                   	int3
ffffffff8ac2647e:	cc                   	int3
ffffffff8ac2647f:	cc                   	int3

ffffffff8ac26480 <neighbor_trampoline_266480>:
ffffffff8ac26480:	e9 6b 0f 69 00       	jmp    ffffffff8b2b73f0 <neighbor_trampoline_266758+0x690c98>
ffffffff8ac26485:	cc                   	int3
ffffffff8ac26486:	cc                   	int3
ffffffff8ac26487:	cc                   	int3

ffffffff8ac26488 <neighbor_trampoline_266488>:
ffffffff8ac26488:	e9 c3 0d 29 00       	jmp    ffffffff8aeb7250 <neighbor_trampoline_266758+0x290af8>
ffffffff8ac2648d:	cc                   	int3
ffffffff8ac2648e:	cc                   	int3
ffffffff8ac2648f:	cc                   	int3

ffffffff8ac26490 <neighbor_trampoline_266490>:
ffffffff8ac26490:	e9 3b 76 79 00       	jmp    ffffffff8b3bdad0 <neighbor_trampoline_266758+0x797378>
ffffffff8ac26495:	cc                   	int3
ffffffff8ac26496:	cc                   	int3
ffffffff8ac26497:	cc                   	int3

ffffffff8ac26498 <neighbor_trampoline_266498>:
ffffffff8ac26498:	e9 13 79 79 00       	jmp    ffffffff8b3bddb0 <neighbor_trampoline_266758+0x797658>
ffffffff8ac2649d:	cc                   	int3
ffffffff8ac2649e:	cc                   	int3
ffffffff8ac2649f:	cc                   	int3

ffffffff8ac264a0 <neighbor_trampoline_2664a0>:
ffffffff8ac264a0:	e9 6b 7a 79 00       	jmp    ffffffff8b3bdf10 <neighbor_trampoline_266758+0x7977b8>
ffffffff8ac264a5:	cc                   	int3
ffffffff8ac264a6:	cc                   	int3
ffffffff8ac264a7:	cc                   	int3

ffffffff8ac264a8 <neighbor_trampoline_2664a8>:
ffffffff8ac264a8:	e9 23 e0 3d 00       	jmp    ffffffff8b0044d0 <neighbor_trampoline_266758+0x3ddd78>
ffffffff8ac264ad:	cc                   	int3
ffffffff8ac264ae:	cc                   	int3
ffffffff8ac264af:	cc                   	int3

ffffffff8ac264b0 <neighbor_trampoline_2664b0>:
ffffffff8ac264b0:	e9 1b ab 3e 00       	jmp    ffffffff8b010fd0 <neighbor_trampoline_266758+0x3ea878>
ffffffff8ac264b5:	cc                   	int3
ffffffff8ac264b6:	cc                   	int3
ffffffff8ac264b7:	cc                   	int3

ffffffff8ac264b8 <neighbor_trampoline_2664b8>:
ffffffff8ac264b8:	e9 73 85 79 00       	jmp    ffffffff8b3bea30 <neighbor_trampoline_266758+0x7982d8>
ffffffff8ac264bd:	cc                   	int3
ffffffff8ac264be:	cc                   	int3
ffffffff8ac264bf:	cc                   	int3

ffffffff8ac264c0 <neighbor_trampoline_2664c0>:
ffffffff8ac264c0:	e9 7b 14 29 00       	jmp    ffffffff8aeb7940 <neighbor_trampoline_266758+0x2911e8>
ffffffff8ac264c5:	cc                   	int3
ffffffff8ac264c6:	cc                   	int3
ffffffff8ac264c7:	cc                   	int3

ffffffff8ac264c8 <neighbor_trampoline_2664c8>:
ffffffff8ac264c8:	e9 13 26 85 00       	jmp    ffffffff8b478ae0 <neighbor_trampoline_266758+0x852388>
ffffffff8ac264cd:	cc                   	int3
ffffffff8ac264ce:	cc                   	int3
ffffffff8ac264cf:	cc                   	int3

ffffffff8ac264d0 <neighbor_trampoline_2664d0>:
ffffffff8ac264d0:	e9 8b 51 85 00       	jmp    ffffffff8b47b660 <neighbor_trampoline_266758+0x854f08>
ffffffff8ac264d5:	cc                   	int3
ffffffff8ac264d6:	cc                   	int3
ffffffff8ac264d7:	cc                   	int3

ffffffff8ac264d8 <neighbor_trampoline_2664d8>:
ffffffff8ac264d8:	e9 83 7d 79 00       	jmp    ffffffff8b3be260 <neighbor_trampoline_266758+0x797b08>
ffffffff8ac264dd:	cc                   	int3
ffffffff8ac264de:	cc                   	int3
ffffffff8ac264df:	cc                   	int3

ffffffff8ac264e0 <neighbor_trampoline_2664e0>:
ffffffff8ac264e0:	e9 fb 7f 79 00       	jmp    ffffffff8b3be4e0 <neighbor_trampoline_266758+0x797d88>
ffffffff8ac264e5:	cc                   	int3
ffffffff8ac264e6:	cc                   	int3
ffffffff8ac264e7:	cc                   	int3

ffffffff8ac264e8 <neighbor_trampoline_2664e8>:
ffffffff8ac264e8:	e9 43 81 79 00       	jmp    ffffffff8b3be630 <neighbor_trampoline_266758+0x797ed8>
ffffffff8ac264ed:	cc                   	int3
ffffffff8ac264ee:	cc                   	int3
ffffffff8ac264ef:	cc                   	int3

ffffffff8ac264f0 <neighbor_trampoline_2664f0>:
ffffffff8ac264f0:	e9 3b 1e 53 00       	jmp    ffffffff8b158330 <neighbor_trampoline_266758+0x531bd8>
ffffffff8ac264f5:	cc                   	int3
ffffffff8ac264f6:	cc                   	int3
ffffffff8ac264f7:	cc                   	int3

ffffffff8ac264f8 <neighbor_trampoline_2664f8>:
ffffffff8ac264f8:	e9 03 6b 85 00       	jmp    ffffffff8b47d000 <neighbor_trampoline_266758+0x8568a8>
ffffffff8ac264fd:	cc                   	int3
ffffffff8ac264fe:	cc                   	int3
ffffffff8ac264ff:	cc                   	int3

ffffffff8ac26500 <neighbor_trampoline_266500>:
ffffffff8ac26500:	e9 8b 63 e9 ff       	jmp    ffffffff8aabc890 <handler_631_entry-0x168ed0>
ffffffff8ac26505:	cc                   	int3
ffffffff8ac26506:	cc                   	int3
ffffffff8ac26507:	cc                   	int3

ffffffff8ac26508 <neighbor_trampoline_266508>:
ffffffff8ac26508:	e9 83 8b 23 00       	jmp    ffffffff8ae5f090 <neighbor_trampoline_266758+0x238938>
ffffffff8ac2650d:	cc                   	int3
ffffffff8ac2650e:	cc                   	int3
ffffffff8ac2650f:	cc                   	int3

ffffffff8ac26510 <neighbor_trampoline_266510>:
ffffffff8ac26510:	e9 eb 8c 23 00       	jmp    ffffffff8ae5f200 <neighbor_trampoline_266758+0x238aa8>
ffffffff8ac26515:	cc                   	int3
ffffffff8ac26516:	cc                   	int3
ffffffff8ac26517:	cc                   	int3

ffffffff8ac26518 <neighbor_trampoline_266518>:
ffffffff8ac26518:	e9 73 a0 25 00       	jmp    ffffffff8ae80590 <neighbor_trampoline_266758+0x259e38>
ffffffff8ac2651d:	cc                   	int3
ffffffff8ac2651e:	cc                   	int3
ffffffff8ac2651f:	cc                   	int3

ffffffff8ac26520 <neighbor_trampoline_266520>:
ffffffff8ac26520:	e9 8b a0 25 00       	jmp    ffffffff8ae805b0 <neighbor_trampoline_266758+0x259e58>
ffffffff8ac26525:	cc                   	int3
ffffffff8ac26526:	cc                   	int3
ffffffff8ac26527:	cc                   	int3

ffffffff8ac26528 <neighbor_trampoline_266528>:
ffffffff8ac26528:	e9 03 2f e4 ff       	jmp    ffffffff8aa69430 <handler_631_entry-0x1bc330>
ffffffff8ac2652d:	cc                   	int3
ffffffff8ac2652e:	cc                   	int3
ffffffff8ac2652f:	cc                   	int3

ffffffff8ac26530 <neighbor_trampoline_266530>:
ffffffff8ac26530:	e9 1b 3e 26 00       	jmp    ffffffff8ae8a350 <neighbor_trampoline_266758+0x263bf8>
ffffffff8ac26535:	cc                   	int3
ffffffff8ac26536:	cc                   	int3
ffffffff8ac26537:	cc                   	int3

ffffffff8ac26538 <neighbor_trampoline_266538>:
ffffffff8ac26538:	e9 03 45 26 00       	jmp    ffffffff8ae8aa40 <neighbor_trampoline_266758+0x2642e8>
ffffffff8ac2653d:	cc                   	int3
ffffffff8ac2653e:	cc                   	int3
ffffffff8ac2653f:	cc                   	int3

ffffffff8ac26540 <neighbor_trampoline_266540>:
ffffffff8ac26540:	e9 cb 3f e4 ff       	jmp    ffffffff8aa6a510 <handler_631_entry-0x1bb250>
ffffffff8ac26545:	cc                   	int3
ffffffff8ac26546:	cc                   	int3
ffffffff8ac26547:	cc                   	int3

ffffffff8ac26548 <neighbor_trampoline_266548>:
ffffffff8ac26548:	e9 83 ec 26 00       	jmp    ffffffff8ae951d0 <neighbor_trampoline_266758+0x26ea78>
ffffffff8ac2654d:	cc                   	int3
ffffffff8ac2654e:	cc                   	int3
ffffffff8ac2654f:	cc                   	int3

ffffffff8ac26550 <neighbor_trampoline_266550>:
ffffffff8ac26550:	e9 5b ac 5a 00       	jmp    ffffffff8b1d11b0 <neighbor_trampoline_266758+0x5aaa58>
ffffffff8ac26555:	cc                   	int3
ffffffff8ac26556:	cc                   	int3
ffffffff8ac26557:	cc                   	int3

ffffffff8ac26558 <neighbor_trampoline_266558>:
ffffffff8ac26558:	e9 33 49 db ff       	jmp    ffffffff8a9dae90 <handler_631_entry-0x24a8d0>
ffffffff8ac2655d:	cc                   	int3
ffffffff8ac2655e:	cc                   	int3
ffffffff8ac2655f:	cc                   	int3

ffffffff8ac26560 <neighbor_trampoline_266560>:
ffffffff8ac26560:	e9 cb 9a 28 00       	jmp    ffffffff8aeb0030 <neighbor_trampoline_266758+0x2898d8>
ffffffff8ac26565:	cc                   	int3
ffffffff8ac26566:	cc                   	int3
ffffffff8ac26567:	cc                   	int3

ffffffff8ac26568 <neighbor_trampoline_266568>:
ffffffff8ac26568:	e9 63 56 29 00       	jmp    ffffffff8aebbbd0 <neighbor_trampoline_266758+0x295478>
ffffffff8ac2656d:	cc                   	int3
ffffffff8ac2656e:	cc                   	int3
ffffffff8ac2656f:	cc                   	int3

ffffffff8ac26570 <neighbor_trampoline_266570>:
ffffffff8ac26570:	e9 5b 69 2a 00       	jmp    ffffffff8aecced0 <neighbor_trampoline_266758+0x2a6778>
ffffffff8ac26575:	cc                   	int3
ffffffff8ac26576:	cc                   	int3
ffffffff8ac26577:	cc                   	int3

ffffffff8ac26578 <neighbor_trampoline_266578>:
ffffffff8ac26578:	e9 63 69 2a 00       	jmp    ffffffff8aeccee0 <neighbor_trampoline_266758+0x2a6788>
ffffffff8ac2657d:	cc                   	int3
ffffffff8ac2657e:	cc                   	int3
ffffffff8ac2657f:	cc                   	int3

ffffffff8ac26580 <neighbor_trampoline_266580>:
ffffffff8ac26580:	e9 ab 69 2a 00       	jmp    ffffffff8aeccf30 <neighbor_trampoline_266758+0x2a67d8>
ffffffff8ac26585:	cc                   	int3
ffffffff8ac26586:	cc                   	int3
ffffffff8ac26587:	cc                   	int3

ffffffff8ac26588 <neighbor_trampoline_266588>:
ffffffff8ac26588:	e9 e3 69 2a 00       	jmp    ffffffff8aeccf70 <neighbor_trampoline_266758+0x2a6818>
ffffffff8ac2658d:	cc                   	int3
ffffffff8ac2658e:	cc                   	int3
ffffffff8ac2658f:	cc                   	int3

ffffffff8ac26590 <neighbor_trampoline_266590>:
ffffffff8ac26590:	e9 1b 6a 2a 00       	jmp    ffffffff8aeccfb0 <neighbor_trampoline_266758+0x2a6858>
ffffffff8ac26595:	cc                   	int3
ffffffff8ac26596:	cc                   	int3
ffffffff8ac26597:	cc                   	int3

ffffffff8ac26598 <neighbor_trampoline_266598>:
ffffffff8ac26598:	e9 43 6a 2a 00       	jmp    ffffffff8aeccfe0 <neighbor_trampoline_266758+0x2a6888>
ffffffff8ac2659d:	cc                   	int3
ffffffff8ac2659e:	cc                   	int3
ffffffff8ac2659f:	cc                   	int3

ffffffff8ac265a0 <neighbor_trampoline_2665a0>:
ffffffff8ac265a0:	e9 2b 7f 2b 00       	jmp    ffffffff8aede4d0 <neighbor_trampoline_266758+0x2b7d78>
ffffffff8ac265a5:	cc                   	int3
ffffffff8ac265a6:	cc                   	int3
ffffffff8ac265a7:	cc                   	int3

ffffffff8ac265a8 <neighbor_trampoline_2665a8>:
ffffffff8ac265a8:	e9 b3 89 2b 00       	jmp    ffffffff8aedef60 <neighbor_trampoline_266758+0x2b8808>
ffffffff8ac265ad:	cc                   	int3
ffffffff8ac265ae:	cc                   	int3
ffffffff8ac265af:	cc                   	int3

ffffffff8ac265b0 <neighbor_trampoline_2665b0>:
ffffffff8ac265b0:	e9 4b 8a 2b 00       	jmp    ffffffff8aedf000 <neighbor_trampoline_266758+0x2b88a8>
ffffffff8ac265b5:	cc                   	int3
ffffffff8ac265b6:	cc                   	int3
ffffffff8ac265b7:	cc                   	int3

ffffffff8ac265b8 <neighbor_trampoline_2665b8>:
ffffffff8ac265b8:	e9 f3 8a 2b 00       	jmp    ffffffff8aedf0b0 <neighbor_trampoline_266758+0x2b8958>
ffffffff8ac265bd:	cc                   	int3
ffffffff8ac265be:	cc                   	int3
ffffffff8ac265bf:	cc                   	int3

ffffffff8ac265c0 <neighbor_trampoline_2665c0>:
ffffffff8ac265c0:	e9 1b 8d 2b 00       	jmp    ffffffff8aedf2e0 <neighbor_trampoline_266758+0x2b8b88>
ffffffff8ac265c5:	cc                   	int3
ffffffff8ac265c6:	cc                   	int3
ffffffff8ac265c7:	cc                   	int3

ffffffff8ac265c8 <neighbor_trampoline_2665c8>:
ffffffff8ac265c8:	e9 a3 90 2b 00       	jmp    ffffffff8aedf670 <neighbor_trampoline_266758+0x2b8f18>
ffffffff8ac265cd:	cc                   	int3
ffffffff8ac265ce:	cc                   	int3
ffffffff8ac265cf:	cc                   	int3

ffffffff8ac265d0 <neighbor_trampoline_2665d0>:
ffffffff8ac265d0:	e9 0b 99 2b 00       	jmp    ffffffff8aedfee0 <neighbor_trampoline_266758+0x2b9788>
ffffffff8ac265d5:	cc                   	int3
ffffffff8ac265d6:	cc                   	int3
ffffffff8ac265d7:	cc                   	int3

ffffffff8ac265d8 <neighbor_trampoline_2665d8>:
ffffffff8ac265d8:	e9 23 fe 2c 00       	jmp    ffffffff8aef6400 <neighbor_trampoline_266758+0x2cfca8>
ffffffff8ac265dd:	cc                   	int3
ffffffff8ac265de:	cc                   	int3
ffffffff8ac265df:	cc                   	int3

ffffffff8ac265e0 <neighbor_trampoline_2665e0>:
ffffffff8ac265e0:	e9 bb e6 2d 00       	jmp    ffffffff8af04ca0 <neighbor_trampoline_266758+0x2de548>
ffffffff8ac265e5:	cc                   	int3
ffffffff8ac265e6:	cc                   	int3
ffffffff8ac265e7:	cc                   	int3

ffffffff8ac265e8 <neighbor_trampoline_2665e8>:
ffffffff8ac265e8:	e9 03 03 2e 00       	jmp    ffffffff8af068f0 <neighbor_trampoline_266758+0x2e0198>
ffffffff8ac265ed:	cc                   	int3
ffffffff8ac265ee:	cc                   	int3
ffffffff8ac265ef:	cc                   	int3

ffffffff8ac265f0 <neighbor_trampoline_2665f0>:
ffffffff8ac265f0:	e9 3b b0 e4 ff       	jmp    ffffffff8aa71630 <handler_631_entry-0x1b4130>
ffffffff8ac265f5:	cc                   	int3
ffffffff8ac265f6:	cc                   	int3
ffffffff8ac265f7:	cc                   	int3

ffffffff8ac265f8 <neighbor_trampoline_2665f8>:
ffffffff8ac265f8:	e9 b3 b9 e4 ff       	jmp    ffffffff8aa71fb0 <handler_631_entry-0x1b37b0>
ffffffff8ac265fd:	cc                   	int3
ffffffff8ac265fe:	cc                   	int3
ffffffff8ac265ff:	cc                   	int3

ffffffff8ac26600 <neighbor_trampoline_266600>:
ffffffff8ac26600:	e9 3b 59 2f 00       	jmp    ffffffff8af1bf40 <neighbor_trampoline_266758+0x2f57e8>
ffffffff8ac26605:	cc                   	int3
ffffffff8ac26606:	cc                   	int3
ffffffff8ac26607:	cc                   	int3

ffffffff8ac26608 <neighbor_trampoline_266608>:
ffffffff8ac26608:	e9 23 5a 2f 00       	jmp    ffffffff8af1c030 <neighbor_trampoline_266758+0x2f58d8>
ffffffff8ac2660d:	cc                   	int3
ffffffff8ac2660e:	cc                   	int3
ffffffff8ac2660f:	cc                   	int3

ffffffff8ac26610 <neighbor_trampoline_266610>:
ffffffff8ac26610:	e9 3b 5a 2f 00       	jmp    ffffffff8af1c050 <neighbor_trampoline_266758+0x2f58f8>
ffffffff8ac26615:	cc                   	int3
ffffffff8ac26616:	cc                   	int3
ffffffff8ac26617:	cc                   	int3

ffffffff8ac26618 <neighbor_trampoline_266618>:
ffffffff8ac26618:	e9 e3 7b 30 00       	jmp    ffffffff8af2e200 <neighbor_trampoline_266758+0x307aa8>
ffffffff8ac2661d:	cc                   	int3
ffffffff8ac2661e:	cc                   	int3
ffffffff8ac2661f:	cc                   	int3

ffffffff8ac26620 <neighbor_trampoline_266620>:
ffffffff8ac26620:	e9 7b 8e 31 00       	jmp    ffffffff8af3f4a0 <neighbor_trampoline_266758+0x318d48>
ffffffff8ac26625:	cc                   	int3
ffffffff8ac26626:	cc                   	int3
ffffffff8ac26627:	cc                   	int3

ffffffff8ac26628 <neighbor_trampoline_266628>:
ffffffff8ac26628:	e9 b3 df 72 00       	jmp    ffffffff8b3545e0 <neighbor_trampoline_266758+0x72de88>
ffffffff8ac2662d:	cc                   	int3
ffffffff8ac2662e:	cc                   	int3
ffffffff8ac2662f:	cc                   	int3

ffffffff8ac26630 <neighbor_trampoline_266630>:
ffffffff8ac26630:	e9 1b f3 31 00       	jmp    ffffffff8af45950 <neighbor_trampoline_266758+0x31f1f8>
ffffffff8ac26635:	cc                   	int3
ffffffff8ac26636:	cc                   	int3
ffffffff8ac26637:	cc                   	int3

ffffffff8ac26638 <neighbor_trampoline_266638>:
ffffffff8ac26638:	e9 e3 31 33 00       	jmp    ffffffff8af59820 <neighbor_trampoline_266758+0x3330c8>
ffffffff8ac2663d:	cc                   	int3
ffffffff8ac2663e:	cc                   	int3
ffffffff8ac2663f:	cc                   	int3

ffffffff8ac26640 <neighbor_trampoline_266640>:
ffffffff8ac26640:	e9 9b 3d 33 00       	jmp    ffffffff8af5a3e0 <neighbor_trampoline_266758+0x333c88>
ffffffff8ac26645:	cc                   	int3
ffffffff8ac26646:	cc                   	int3
ffffffff8ac26647:	cc                   	int3

ffffffff8ac26648 <neighbor_trampoline_266648>:
ffffffff8ac26648:	e9 e3 3e 33 00       	jmp    ffffffff8af5a530 <neighbor_trampoline_266758+0x333dd8>
ffffffff8ac2664d:	cc                   	int3
ffffffff8ac2664e:	cc                   	int3
ffffffff8ac2664f:	cc                   	int3

ffffffff8ac26650 <neighbor_trampoline_266650>:
ffffffff8ac26650:	e9 ab 40 33 00       	jmp    ffffffff8af5a700 <neighbor_trampoline_266758+0x333fa8>
ffffffff8ac26655:	cc                   	int3
ffffffff8ac26656:	cc                   	int3
ffffffff8ac26657:	cc                   	int3

ffffffff8ac26658 <neighbor_trampoline_266658>:
ffffffff8ac26658:	e9 73 41 33 00       	jmp    ffffffff8af5a7d0 <neighbor_trampoline_266758+0x334078>
ffffffff8ac2665d:	cc                   	int3
ffffffff8ac2665e:	cc                   	int3
ffffffff8ac2665f:	cc                   	int3

ffffffff8ac26660 <neighbor_trampoline_266660>:
ffffffff8ac26660:	e9 eb 43 33 00       	jmp    ffffffff8af5aa50 <neighbor_trampoline_266758+0x3342f8>
ffffffff8ac26665:	cc                   	int3
ffffffff8ac26666:	cc                   	int3
ffffffff8ac26667:	cc                   	int3

ffffffff8ac26668 <neighbor_trampoline_266668>:
ffffffff8ac26668:	e9 f3 44 33 00       	jmp    ffffffff8af5ab60 <neighbor_trampoline_266758+0x334408>
ffffffff8ac2666d:	cc                   	int3
ffffffff8ac2666e:	cc                   	int3
ffffffff8ac2666f:	cc                   	int3

ffffffff8ac26670 <neighbor_trampoline_266670>:
ffffffff8ac26670:	e9 eb 45 33 00       	jmp    ffffffff8af5ac60 <neighbor_trampoline_266758+0x334508>
ffffffff8ac26675:	cc                   	int3
ffffffff8ac26676:	cc                   	int3
ffffffff8ac26677:	cc                   	int3

ffffffff8ac26678 <neighbor_trampoline_266678>:
ffffffff8ac26678:	e9 53 58 37 00       	jmp    ffffffff8af9bed0 <neighbor_trampoline_266758+0x375778>
ffffffff8ac2667d:	cc                   	int3
ffffffff8ac2667e:	cc                   	int3
ffffffff8ac2667f:	cc                   	int3

ffffffff8ac26680 <neighbor_trampoline_266680>:
ffffffff8ac26680:	e9 9b 50 38 00       	jmp    ffffffff8afab720 <neighbor_trampoline_266758+0x384fc8>
ffffffff8ac26685:	cc                   	int3
ffffffff8ac26686:	cc                   	int3
ffffffff8ac26687:	cc                   	int3

ffffffff8ac26688 <neighbor_trampoline_266688>:
ffffffff8ac26688:	e9 a3 59 38 00       	jmp    ffffffff8afac030 <neighbor_trampoline_266758+0x3858d8>
ffffffff8ac2668d:	cc                   	int3
ffffffff8ac2668e:	cc                   	int3
ffffffff8ac2668f:	cc                   	int3

ffffffff8ac26690 <neighbor_trampoline_266690>:
ffffffff8ac26690:	e9 3b 64 38 00       	jmp    ffffffff8afacad0 <neighbor_trampoline_266758+0x386378>
ffffffff8ac26695:	cc                   	int3
ffffffff8ac26696:	cc                   	int3
ffffffff8ac26697:	cc                   	int3

ffffffff8ac26698 <neighbor_trampoline_266698>:
ffffffff8ac26698:	e9 a3 6d 38 00       	jmp    ffffffff8afad440 <neighbor_trampoline_266758+0x386ce8>
ffffffff8ac2669d:	cc                   	int3
ffffffff8ac2669e:	cc                   	int3
ffffffff8ac2669f:	cc                   	int3

ffffffff8ac266a0 <neighbor_trampoline_2666a0>:
ffffffff8ac266a0:	e9 8b 74 38 00       	jmp    ffffffff8afadb30 <neighbor_trampoline_266758+0x3873d8>
ffffffff8ac266a5:	cc                   	int3
ffffffff8ac266a6:	cc                   	int3
ffffffff8ac266a7:	cc                   	int3

ffffffff8ac266a8 <neighbor_trampoline_2666a8>:
ffffffff8ac266a8:	e9 d3 7b ee ff       	jmp    ffffffff8ab0e280 <handler_631_entry-0x1174e0>
ffffffff8ac266ad:	cc                   	int3
ffffffff8ac266ae:	cc                   	int3
ffffffff8ac266af:	cc                   	int3

ffffffff8ac266b0 <neighbor_trampoline_2666b0>:
ffffffff8ac266b0:	e9 fb b1 38 00       	jmp    ffffffff8afb18b0 <neighbor_trampoline_266758+0x38b158>
ffffffff8ac266b5:	cc                   	int3
ffffffff8ac266b6:	cc                   	int3
ffffffff8ac266b7:	cc                   	int3

ffffffff8ac266b8 <neighbor_trampoline_2666b8>:
ffffffff8ac266b8:	e9 73 c4 38 00       	jmp    ffffffff8afb2b30 <neighbor_trampoline_266758+0x38c3d8>
ffffffff8ac266bd:	cc                   	int3
ffffffff8ac266be:	cc                   	int3
ffffffff8ac266bf:	cc                   	int3

ffffffff8ac266c0 <neighbor_trampoline_2666c0>:
ffffffff8ac266c0:	e9 fb 69 39 00       	jmp    ffffffff8afbd0c0 <neighbor_trampoline_266758+0x396968>
ffffffff8ac266c5:	cc                   	int3
ffffffff8ac266c6:	cc                   	int3
ffffffff8ac266c7:	cc                   	int3

ffffffff8ac266c8 <neighbor_trampoline_2666c8>:
ffffffff8ac266c8:	e9 b3 9f 39 00       	jmp    ffffffff8afc0680 <neighbor_trampoline_266758+0x399f28>
ffffffff8ac266cd:	cc                   	int3
ffffffff8ac266ce:	cc                   	int3
ffffffff8ac266cf:	cc                   	int3

ffffffff8ac266d0 <neighbor_trampoline_2666d0>:
ffffffff8ac266d0:	e9 6b a8 39 00       	jmp    ffffffff8afc0f40 <neighbor_trampoline_266758+0x39a7e8>
ffffffff8ac266d5:	cc                   	int3
ffffffff8ac266d6:	cc                   	int3
ffffffff8ac266d7:	cc                   	int3

ffffffff8ac266d8 <neighbor_trampoline_2666d8>:
ffffffff8ac266d8:	e9 c3 fd 87 00       	jmp    ffffffff8b4a64a0 <neighbor_trampoline_266758+0x87fd48>
ffffffff8ac266dd:	cc                   	int3
ffffffff8ac266de:	cc                   	int3
ffffffff8ac266df:	cc                   	int3

ffffffff8ac266e0 <neighbor_trampoline_2666e0>:
ffffffff8ac266e0:	e9 bb 73 3c 00       	jmp    ffffffff8afedaa0 <neighbor_trampoline_266758+0x3c7348>
ffffffff8ac266e5:	cc                   	int3
ffffffff8ac266e6:	cc                   	int3
ffffffff8ac266e7:	cc                   	int3

ffffffff8ac266e8 <neighbor_trampoline_2666e8>:
ffffffff8ac266e8:	e9 e3 9b 3c 00       	jmp    ffffffff8aff02d0 <neighbor_trampoline_266758+0x3c9b78>
ffffffff8ac266ed:	cc                   	int3
ffffffff8ac266ee:	cc                   	int3
ffffffff8ac266ef:	cc                   	int3

ffffffff8ac266f0 <neighbor_trampoline_2666f0>:
ffffffff8ac266f0:	e9 1b e8 3c 00       	jmp    ffffffff8aff4f10 <neighbor_trampoline_266758+0x3ce7b8>
ffffffff8ac266f5:	cc                   	int3
ffffffff8ac266f6:	cc                   	int3
ffffffff8ac266f7:	cc                   	int3

ffffffff8ac266f8 <neighbor_trampoline_2666f8>:
ffffffff8ac266f8:	e9 23 8e 3d 00       	jmp    ffffffff8afff520 <neighbor_trampoline_266758+0x3d8dc8>
ffffffff8ac266fd:	cc                   	int3
ffffffff8ac266fe:	cc                   	int3
ffffffff8ac266ff:	cc                   	int3

ffffffff8ac26700 <neighbor_trampoline_266700>:
ffffffff8ac26700:	e9 ab 12 3f 00       	jmp    ffffffff8b0179b0 <neighbor_trampoline_266758+0x3f1258>
ffffffff8ac26705:	cc                   	int3
ffffffff8ac26706:	cc                   	int3
ffffffff8ac26707:	cc                   	int3

ffffffff8ac26708 <neighbor_trampoline_266708>:
ffffffff8ac26708:	e9 03 0c a4 00       	jmp    ffffffff8b667310 <neighbor_trampoline_266758+0xa40bb8>
ffffffff8ac2670d:	cc                   	int3
ffffffff8ac2670e:	cc                   	int3
ffffffff8ac2670f:	cc                   	int3

ffffffff8ac26710 <neighbor_trampoline_266710>:
ffffffff8ac26710:	e9 5b c7 3f 00       	jmp    ffffffff8b022e70 <neighbor_trampoline_266758+0x3fc718>
ffffffff8ac26715:	cc                   	int3
ffffffff8ac26716:	cc                   	int3
ffffffff8ac26717:	cc                   	int3

ffffffff8ac26718 <neighbor_trampoline_266718>:
ffffffff8ac26718:	e9 63 c7 3f 00       	jmp    ffffffff8b022e80 <neighbor_trampoline_266758+0x3fc728>
ffffffff8ac2671d:	cc                   	int3
ffffffff8ac2671e:	cc                   	int3
ffffffff8ac2671f:	cc                   	int3

ffffffff8ac26720 <neighbor_trampoline_266720>:
ffffffff8ac26720:	e9 eb 26 41 00       	jmp    ffffffff8b038e10 <neighbor_trampoline_266758+0x4126b8>
ffffffff8ac26725:	cc                   	int3
ffffffff8ac26726:	cc                   	int3
ffffffff8ac26727:	cc                   	int3

ffffffff8ac26728 <neighbor_trampoline_266728>:
ffffffff8ac26728:	e9 33 27 41 00       	jmp    ffffffff8b038e60 <neighbor_trampoline_266758+0x412708>
ffffffff8ac2672d:	cc                   	int3
ffffffff8ac2672e:	cc                   	int3
ffffffff8ac2672f:	cc                   	int3

ffffffff8ac26730 <neighbor_trampoline_266730>:
ffffffff8ac26730:	e9 8b 27 41 00       	jmp    ffffffff8b038ec0 <neighbor_trampoline_266758+0x412768>
ffffffff8ac26735:	cc                   	int3
ffffffff8ac26736:	cc                   	int3
ffffffff8ac26737:	cc                   	int3

ffffffff8ac26738 <neighbor_trampoline_266738>:
ffffffff8ac26738:	e9 23 28 41 00       	jmp    ffffffff8b038f60 <neighbor_trampoline_266758+0x412808>
ffffffff8ac2673d:	cc                   	int3
ffffffff8ac2673e:	cc                   	int3
ffffffff8ac2673f:	cc                   	int3

ffffffff8ac26740 <neighbor_trampoline_266740>:
ffffffff8ac26740:	e9 4b 2a 41 00       	jmp    ffffffff8b039190 <neighbor_trampoline_266758+0x412a38>
ffffffff8ac26745:	cc                   	int3
ffffffff8ac26746:	cc                   	int3
ffffffff8ac26747:	cc                   	int3

ffffffff8ac26748 <neighbor_trampoline_266748>:
ffffffff8ac26748:	e9 13 2c 41 00       	jmp    ffffffff8b039360 <neighbor_trampoline_266758+0x412c08>
ffffffff8ac2674d:	cc                   	int3
ffffffff8ac2674e:	cc                   	int3
ffffffff8ac2674f:	cc                   	int3

ffffffff8ac26750 <neighbor_trampoline_266750>:
ffffffff8ac26750:	e9 2b 2f 41 00       	jmp    ffffffff8b039680 <neighbor_trampoline_266758+0x412f28>
ffffffff8ac26755:	cc                   	int3
ffffffff8ac26756:	cc                   	int3
ffffffff8ac26757:	cc                   	int3

ffffffff8ac26758 <neighbor_trampoline_266758>:
ffffffff8ac26758:	e9 33 d4 dc ff       	jmp    ffffffff8a9f3b90 <handler_631_entry-0x231bd0>
ffffffff8ac2675d:	cc                   	int3
ffffffff8ac2675e:	cc                   	int3
ffffffff8ac2675f:	cc                   	int3

; PART 2: SUPPLEMENTAL ACTUAL HANDLER BODY FROM kernel_text.bin
; Entry 0xffffffff8af220e0, handler_body_645; REA Evidence ev_e326e406aa569de360ba62c9cb29aad973c641cc2f683fe09f22df2c896b667d
; Body inclusive ranges: {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xffffffff8af220e0", "end": "0xffffffff8af22187"}], "total_bytes": 168, "span_bytes": 168, "non_contiguous": false, "contains_entry": true}
; This body is outside the original 4096-byte trampoline window.
handler_body_645:
0xffffffff8af220e0: PUSH RBP
0xffffffff8af220e1: MOV RBP, RSP
0xffffffff8af220e4: PUSH R15
0xffffffff8af220e6: PUSH R14
0xffffffff8af220e8: PUSH R12
0xffffffff8af220ea: PUSH RBX
0xffffffff8af220eb: SUB RSP, 0x80
0xffffffff8af220f2: LEA R12, [-0x71d23cf0]
0xffffffff8af220f9: MOV EBX, 0x148
0xffffffff8af220fe: MOV R14, RDI
0xffffffff8af22101: XOR ESI, ESI
0xffffffff8af22103: XOR EDX, EDX
0xffffffff8af22105: XOR ECX, ECX
0xffffffff8af22107: MOV RAX, qword ptr [R12]
0xffffffff8af2210b: MOV qword ptr [RBP + -0x28], RAX
0xffffffff8af2210f: ADD RBX, qword ptr [RDI + 0x8]
0xffffffff8af22113: MOV RDI, RBX
0xffffffff8af22116: CALL 0xffffffff8ae86a00
0xffffffff8af2211b: LEA R15, [RBP + -0x98]
0xffffffff8af22122: MOV ESI, 0x70
0xffffffff8af22127: MOV RDI, R15
0xffffffff8af2212a: CALL 0xffffffff8ac18ff0
0xffffffff8af2212f: MOV dword ptr [RBP + -0x88], 0xc
0xffffffff8af22139: MOV dword ptr [RBP + -0x80], 0x10006
0xffffffff8af22140: MOV RSI, R14
0xffffffff8af22143: MOV EDX, 0xc
0xffffffff8af22148: MOV RCX, R15
0xffffffff8af2214b: MOV RDI, qword ptr [R14 + 0x8]
0xffffffff8af2214f: CALL 0xffffffff8af20540
0xffffffff8af22154: MOV RDI, RBX
0xffffffff8af22157: XOR ESI, ESI
0xffffffff8af22159: XOR EDX, EDX
0xffffffff8af2215b: XOR ECX, ECX
0xffffffff8af2215d: CALL 0xffffffff8ae86fa0
0xffffffff8af22162: MOV RAX, qword ptr [R12]
0xffffffff8af22166: CMP RAX, qword ptr [RBP + -0x28]
0xffffffff8af2216a: JNZ 0xffffffff8af22181
loc_ffffffff8af2216c:
0xffffffff8af2216c: MOV EAX, 0x4e
0xffffffff8af22171: ADD RSP, 0x80
0xffffffff8af22178: POP RBX
0xffffffff8af22179: POP R12
0xffffffff8af2217b: POP R14
0xffffffff8af2217d: POP R15
0xffffffff8af2217f: POP RBP
0xffffffff8af22180: RET
loc_ffffffff8af22181:
0xffffffff8af22181: CALL 0xffffffff8b0bd6b0
0xffffffff8af22186: UD2
; END FUNCTION handler_body_645

; PART 3: FULL SUPPLEMENTAL 8192-BYTE BODY WINDOW
; REA inspect_with_objdump Evidence ev_c46d8043df87ced3194e9b716facda2f3820efc9cc3eca11da09755651a051c4
; Includes branch bodies missed by unresolved jump tables and unrelated neighbors.
; frame_candidate labels are observed prologues, not proven boundaries.
; Tail can split a neighboring instruction; no invented decode beyond source window.

/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/rea_616_645_evidence/handler_631.body.elf:     file format elf64-x86-64


Disassembly of section .text:

ffffffff8af220e0 <handler_631_body>:
ffffffff8af220e0:	55                   	push   %rbp
ffffffff8af220e1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8af220e4:	41 57                	push   %r15
ffffffff8af220e6:	41 56                	push   %r14
ffffffff8af220e8:	41 54                	push   %r12
ffffffff8af220ea:	53                   	push   %rbx
ffffffff8af220eb:	48 81 ec 80 00 00 00 	sub    $0x80,%rsp
ffffffff8af220f2:	4c 8d 25 17 a2 3b 03 	lea    0x33ba217(%rip),%r12        # ffffffff8e2dc310 <frame_candidate_563fd0+0x33b8340>
ffffffff8af220f9:	bb 48 01 00 00       	mov    $0x148,%ebx
ffffffff8af220fe:	49 89 fe             	mov    %rdi,%r14
ffffffff8af22101:	31 f6                	xor    %esi,%esi
ffffffff8af22103:	31 d2                	xor    %edx,%edx
ffffffff8af22105:	31 c9                	xor    %ecx,%ecx
ffffffff8af22107:	49 8b 04 24          	mov    (%r12),%rax
ffffffff8af2210b:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
ffffffff8af2210f:	48 03 5f 08          	add    0x8(%rdi),%rbx
ffffffff8af22113:	48 89 df             	mov    %rbx,%rdi
ffffffff8af22116:	e8 e5 48 f6 ff       	call   ffffffff8ae86a00 <handler_631_body-0x9b6e0>
ffffffff8af2211b:	4c 8d bd 68 ff ff ff 	lea    -0x98(%rbp),%r15
ffffffff8af22122:	be 70 00 00 00       	mov    $0x70,%esi
ffffffff8af22127:	4c 89 ff             	mov    %r15,%rdi
ffffffff8af2212a:	e8 c1 6e cf ff       	call   ffffffff8ac18ff0 <handler_631_body-0x3090f0>
ffffffff8af2212f:	c7 85 78 ff ff ff 0c 	movl   $0xc,-0x88(%rbp)
ffffffff8af22136:	00 00 00 
ffffffff8af22139:	c7 45 80 06 00 01 00 	movl   $0x10006,-0x80(%rbp)
ffffffff8af22140:	4c 89 f6             	mov    %r14,%rsi
ffffffff8af22143:	ba 0c 00 00 00       	mov    $0xc,%edx
ffffffff8af22148:	4c 89 f9             	mov    %r15,%rcx
ffffffff8af2214b:	49 8b 7e 08          	mov    0x8(%r14),%rdi
ffffffff8af2214f:	e8 ec e3 ff ff       	call   ffffffff8af20540 <handler_631_body-0x1ba0>
ffffffff8af22154:	48 89 df             	mov    %rbx,%rdi
ffffffff8af22157:	31 f6                	xor    %esi,%esi
ffffffff8af22159:	31 d2                	xor    %edx,%edx
ffffffff8af2215b:	31 c9                	xor    %ecx,%ecx
ffffffff8af2215d:	e8 3e 4e f6 ff       	call   ffffffff8ae86fa0 <handler_631_body-0x9b140>
ffffffff8af22162:	49 8b 04 24          	mov    (%r12),%rax
ffffffff8af22166:	48 3b 45 d8          	cmp    -0x28(%rbp),%rax
ffffffff8af2216a:	75 15                	jne    ffffffff8af22181 <handler_631_body+0xa1>
ffffffff8af2216c:	b8 4e 00 00 00       	mov    $0x4e,%eax
ffffffff8af22171:	48 81 c4 80 00 00 00 	add    $0x80,%rsp
ffffffff8af22178:	5b                   	pop    %rbx
ffffffff8af22179:	41 5c                	pop    %r12
ffffffff8af2217b:	41 5e                	pop    %r14
ffffffff8af2217d:	41 5f                	pop    %r15
ffffffff8af2217f:	5d                   	pop    %rbp
ffffffff8af22180:	c3                   	ret
ffffffff8af22181:	e8 2a b5 19 00       	call   ffffffff8b0bd6b0 <frame_candidate_563fd0+0x1996e0>
ffffffff8af22186:	0f 0b                	ud2
ffffffff8af22188:	90                   	nop
ffffffff8af22189:	90                   	nop
ffffffff8af2218a:	90                   	nop
ffffffff8af2218b:	90                   	nop
ffffffff8af2218c:	90                   	nop
ffffffff8af2218d:	90                   	nop
ffffffff8af2218e:	90                   	nop
ffffffff8af2218f:	90                   	nop

ffffffff8af22190 <frame_candidate_562190>:
ffffffff8af22190:	55                   	push   %rbp
ffffffff8af22191:	48 89 e5             	mov    %rsp,%rbp
ffffffff8af22194:	41 57                	push   %r15
ffffffff8af22196:	41 56                	push   %r14
ffffffff8af22198:	41 55                	push   %r13
ffffffff8af2219a:	41 54                	push   %r12
ffffffff8af2219c:	53                   	push   %rbx
ffffffff8af2219d:	48 81 ec f8 00 00 00 	sub    $0xf8,%rsp
ffffffff8af221a4:	4c 8d 2d 65 a1 3b 03 	lea    0x33ba165(%rip),%r13        # ffffffff8e2dc310 <frame_candidate_563fd0+0x33b8340>
ffffffff8af221ab:	89 f3                	mov    %esi,%ebx
ffffffff8af221ad:	49 89 ff             	mov    %rdi,%r15
ffffffff8af221b0:	48 8d bd f0 fe ff ff 	lea    -0x110(%rbp),%rdi
ffffffff8af221b7:	be 70 00 00 00       	mov    $0x70,%esi
ffffffff8af221bc:	41 89 d4             	mov    %edx,%r12d
ffffffff8af221bf:	49 8b 45 00          	mov    0x0(%r13),%rax
ffffffff8af221c3:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8af221c7:	e8 24 6e cf ff       	call   ffffffff8ac18ff0 <handler_631_body-0x3090f0>
ffffffff8af221cc:	48 8d 3d 9d fc 41 03 	lea    0x341fc9d(%rip),%rdi        # ffffffff8e341e70 <frame_candidate_563fd0+0x341dea0>
ffffffff8af221d3:	89 9d 00 ff ff ff    	mov    %ebx,-0x100(%rbp)
ffffffff8af221d9:	c7 85 08 ff ff ff 06 	movl   $0x10006,-0xf8(%rbp)
ffffffff8af221e0:	00 01 00 
ffffffff8af221e3:	31 f6                	xor    %esi,%esi
ffffffff8af221e5:	31 d2                	xor    %edx,%edx
ffffffff8af221e7:	31 c9                	xor    %ecx,%ecx
ffffffff8af221e9:	e8 12 48 f6 ff       	call   ffffffff8ae86a00 <handler_631_body-0x9b6e0>
ffffffff8af221ee:	4d 8b 37             	mov    (%r15),%r14
ffffffff8af221f1:	4d 85 f6             	test   %r14,%r14
ffffffff8af221f4:	0f 84 99 00 00 00    	je     ffffffff8af22293 <frame_candidate_562190+0x103>
ffffffff8af221fa:	41 83 7e 20 00       	cmpl   $0x0,0x20(%r14)
ffffffff8af221ff:	0f 8e 8c 00 00 00    	jle    ffffffff8af22291 <frame_candidate_562190+0x101>
ffffffff8af22205:	bf 48 01 00 00       	mov    $0x148,%edi
ffffffff8af2220a:	49 03 3e             	add    (%r14),%rdi
ffffffff8af2220d:	31 f6                	xor    %esi,%esi
ffffffff8af2220f:	31 d2                	xor    %edx,%edx
ffffffff8af22211:	31 c9                	xor    %ecx,%ecx
ffffffff8af22213:	e8 e8 47 f6 ff       	call   ffffffff8ae86a00 <handler_631_body-0x9b6e0>
ffffffff8af22218:	49 8b 4e 18          	mov    0x18(%r14),%rcx
ffffffff8af2221c:	4d 8b 26             	mov    (%r14),%r12
ffffffff8af2221f:	8b 41 04             	mov    0x4(%rcx),%eax
ffffffff8af22222:	85 c0                	test   %eax,%eax
ffffffff8af22224:	74 1e                	je     ffffffff8af22244 <frame_candidate_562190+0xb4>
ffffffff8af22226:	49 8b 54 24 40       	mov    0x40(%r12),%rdx
ffffffff8af2222b:	8b 49 08             	mov    0x8(%rcx),%ecx
ffffffff8af2222e:	8b 72 08             	mov    0x8(%rdx),%esi
ffffffff8af22231:	39 f1                	cmp    %esi,%ecx
ffffffff8af22233:	74 0f                	je     ffffffff8af22244 <frame_candidate_562190+0xb4>
ffffffff8af22235:	39 f0                	cmp    %esi,%eax
ffffffff8af22237:	74 0b                	je     ffffffff8af22244 <frame_candidate_562190+0xb4>
ffffffff8af22239:	8b 52 04             	mov    0x4(%rdx),%edx
ffffffff8af2223c:	39 d1                	cmp    %edx,%ecx
ffffffff8af2223e:	74 04                	je     ffffffff8af22244 <frame_candidate_562190+0xb4>
ffffffff8af22240:	39 d0                	cmp    %edx,%eax
ffffffff8af22242:	75 36                	jne    ffffffff8af2227a <frame_candidate_562190+0xea>
ffffffff8af22244:	4c 8d bd 60 ff ff ff 	lea    -0xa0(%rbp),%r15
ffffffff8af2224b:	be 70 00 00 00       	mov    $0x70,%esi
ffffffff8af22250:	4c 89 ff             	mov    %r15,%rdi
ffffffff8af22253:	e8 98 6d cf ff       	call   ffffffff8ac18ff0 <handler_631_body-0x3090f0>
ffffffff8af22258:	4c 89 e7             	mov    %r12,%rdi
ffffffff8af2225b:	89 da                	mov    %ebx,%edx
ffffffff8af2225d:	4c 89 f9             	mov    %r15,%rcx
ffffffff8af22260:	89 9d 70 ff ff ff    	mov    %ebx,-0x90(%rbp)
ffffffff8af22266:	31 f6                	xor    %esi,%esi
ffffffff8af22268:	c7 85 78 ff ff ff 06 	movl   $0x10006,-0x88(%rbp)
ffffffff8af2226f:	00 01 00 
ffffffff8af22272:	e8 c9 e2 ff ff       	call   ffffffff8af20540 <handler_631_body-0x1ba0>
ffffffff8af22277:	4d 8b 26             	mov    (%r14),%r12
ffffffff8af2227a:	49 81 c4 48 01 00 00 	add    $0x148,%r12
ffffffff8af22281:	4c 89 e7             	mov    %r12,%rdi
ffffffff8af22284:	31 f6                	xor    %esi,%esi
ffffffff8af22286:	31 d2                	xor    %edx,%edx
ffffffff8af22288:	31 c9                	xor    %ecx,%ecx
ffffffff8af2228a:	e8 11 4d f6 ff       	call   ffffffff8ae86fa0 <handler_631_body-0x9b140>
ffffffff8af2228f:	eb 02                	jmp    ffffffff8af22293 <frame_candidate_562190+0x103>
ffffffff8af22291:	78 32                	js     ffffffff8af222c5 <frame_candidate_562190+0x135>
ffffffff8af22293:	48 8d 3d d6 fb 41 03 	lea    0x341fbd6(%rip),%rdi        # ffffffff8e341e70 <frame_candidate_563fd0+0x341dea0>
ffffffff8af2229a:	31 f6                	xor    %esi,%esi
ffffffff8af2229c:	31 d2                	xor    %edx,%edx
ffffffff8af2229e:	31 c9                	xor    %ecx,%ecx
ffffffff8af222a0:	e8 fb 4c f6 ff       	call   ffffffff8ae86fa0 <handler_631_body-0x9b140>
ffffffff8af222a5:	49 8b 45 00          	mov    0x0(%r13),%rax
ffffffff8af222a9:	48 3b 45 d0          	cmp    -0x30(%rbp),%rax
ffffffff8af222ad:	0f 85 10 01 00 00    	jne    ffffffff8af223c3 <frame_candidate_562190+0x233>
ffffffff8af222b3:	48 81 c4 f8 00 00 00 	add    $0xf8,%rsp
ffffffff8af222ba:	5b                   	pop    %rbx
ffffffff8af222bb:	41 5c                	pop    %r12
ffffffff8af222bd:	41 5d                	pop    %r13
ffffffff8af222bf:	41 5e                	pop    %r14
ffffffff8af222c1:	41 5f                	pop    %r15
ffffffff8af222c3:	5d                   	pop    %rbp
ffffffff8af222c4:	c3                   	ret
ffffffff8af222c5:	49 8b 3e             	mov    (%r14),%rdi
ffffffff8af222c8:	44 89 a5 ec fe ff ff 	mov    %r12d,-0x114(%rbp)
ffffffff8af222cf:	31 f6                	xor    %esi,%esi
ffffffff8af222d1:	31 d2                	xor    %edx,%edx
ffffffff8af222d3:	31 c9                	xor    %ecx,%ecx
ffffffff8af222d5:	48 83 c7 48          	add    $0x48,%rdi
ffffffff8af222d9:	e8 22 47 f6 ff       	call   ffffffff8ae86a00 <handler_631_body-0x9b6e0>
ffffffff8af222de:	4d 8b 26             	mov    (%r14),%r12
ffffffff8af222e1:	4d 8b 7c 24 10       	mov    0x10(%r12),%r15
ffffffff8af222e6:	4d 85 ff             	test   %r15,%r15
ffffffff8af222e9:	0f 84 cb 00 00 00    	je     ffffffff8af223ba <frame_candidate_562190+0x22a>
ffffffff8af222ef:	4c 8d a5 60 ff ff ff 	lea    -0xa0(%rbp),%r12
ffffffff8af222f6:	eb 4e                	jmp    ffffffff8af22346 <frame_candidate_562190+0x1b6>
ffffffff8af222f8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
ffffffff8af222ff:	00 
ffffffff8af22300:	be 70 00 00 00       	mov    $0x70,%esi
ffffffff8af22305:	4c 89 e7             	mov    %r12,%rdi
ffffffff8af22308:	e8 e3 6c cf ff       	call   ffffffff8ac18ff0 <handler_631_body-0x3090f0>
ffffffff8af2230d:	4c 89 ff             	mov    %r15,%rdi
ffffffff8af22310:	89 da                	mov    %ebx,%edx
ffffffff8af22312:	4c 89 e1             	mov    %r12,%rcx
ffffffff8af22315:	89 9d 70 ff ff ff    	mov    %ebx,-0x90(%rbp)
ffffffff8af2231b:	31 f6                	xor    %esi,%esi
ffffffff8af2231d:	c7 85 78 ff ff ff 06 	movl   $0x10006,-0x88(%rbp)
ffffffff8af22324:	00 01 00 
ffffffff8af22327:	e8 14 e2 ff ff       	call   ffffffff8af20540 <handler_631_body-0x1ba0>
ffffffff8af2232c:	4c 89 ef             	mov    %r13,%rdi
ffffffff8af2232f:	31 f6                	xor    %esi,%esi
ffffffff8af22331:	31 d2                	xor    %edx,%edx
ffffffff8af22333:	31 c9                	xor    %ecx,%ecx
ffffffff8af22335:	e8 66 4c f6 ff       	call   ffffffff8ae86fa0 <handler_631_body-0x9b140>
ffffffff8af2233a:	4d 8b bf d0 00 00 00 	mov    0xd0(%r15),%r15
ffffffff8af22341:	4d 85 ff             	test   %r15,%r15
ffffffff8af22344:	74 6a                	je     ffffffff8af223b0 <frame_candidate_562190+0x220>
ffffffff8af22346:	4d 8d af 48 01 00 00 	lea    0x148(%r15),%r13
ffffffff8af2234d:	31 f6                	xor    %esi,%esi
ffffffff8af2234f:	31 d2                	xor    %edx,%edx
ffffffff8af22351:	31 c9                	xor    %ecx,%ecx
ffffffff8af22353:	4c 89 ef             	mov    %r13,%rdi
ffffffff8af22356:	e8 a5 46 f6 ff       	call   ffffffff8ae86a00 <handler_631_body-0x9b6e0>
ffffffff8af2235b:	41 83 bf b8 00 00 00 	cmpl   $0x1,0xb8(%r15)
ffffffff8af22362:	01 
ffffffff8af22363:	75 c7                	jne    ffffffff8af2232c <frame_candidate_562190+0x19c>
ffffffff8af22365:	49 8b 4e 18          	mov    0x18(%r14),%rcx
ffffffff8af22369:	8b 41 04             	mov    0x4(%rcx),%eax
ffffffff8af2236c:	85 c0                	test   %eax,%eax
ffffffff8af2236e:	74 20                	je     ffffffff8af22390 <frame_candidate_562190+0x200>
ffffffff8af22370:	49 8b 57 40          	mov    0x40(%r15),%rdx
ffffffff8af22374:	8b 49 08             	mov    0x8(%rcx),%ecx
ffffffff8af22377:	8b 72 08             	mov    0x8(%rdx),%esi
ffffffff8af2237a:	39 f1                	cmp    %esi,%ecx
ffffffff8af2237c:	74 12                	je     ffffffff8af22390 <frame_candidate_562190+0x200>
ffffffff8af2237e:	39 f0                	cmp    %esi,%eax
ffffffff8af22380:	74 0e                	je     ffffffff8af22390 <frame_candidate_562190+0x200>
ffffffff8af22382:	8b 52 04             	mov    0x4(%rdx),%edx
ffffffff8af22385:	39 d1                	cmp    %edx,%ecx
ffffffff8af22387:	74 07                	je     ffffffff8af22390 <frame_candidate_562190+0x200>
ffffffff8af22389:	39 d0                	cmp    %edx,%eax
ffffffff8af2238b:	75 9f                	jne    ffffffff8af2232c <frame_candidate_562190+0x19c>
ffffffff8af2238d:	0f 1f 00             	nopl   (%rax)
ffffffff8af22390:	83 bd ec fe ff ff 00 	cmpl   $0x0,-0x114(%rbp)
ffffffff8af22397:	0f 84 63 ff ff ff    	je     ffffffff8af22300 <frame_candidate_562190+0x170>
ffffffff8af2239d:	41 f6 87 b0 00 00 00 	testb  $0x2,0xb0(%r15)
ffffffff8af223a4:	02 
ffffffff8af223a5:	0f 85 55 ff ff ff    	jne    ffffffff8af22300 <frame_candidate_562190+0x170>
ffffffff8af223ab:	e9 7c ff ff ff       	jmp    ffffffff8af2232c <frame_candidate_562190+0x19c>
ffffffff8af223b0:	4d 8b 26             	mov    (%r14),%r12
ffffffff8af223b3:	4c 8d 2d 56 9f 3b 03 	lea    0x33b9f56(%rip),%r13        # ffffffff8e2dc310 <frame_candidate_563fd0+0x33b8340>
ffffffff8af223ba:	49 83 c4 48          	add    $0x48,%r12
ffffffff8af223be:	e9 be fe ff ff       	jmp    ffffffff8af22281 <frame_candidate_562190+0xf1>
ffffffff8af223c3:	e8 e8 b2 19 00       	call   ffffffff8b0bd6b0 <frame_candidate_563fd0+0x1996e0>
ffffffff8af223c8:	0f 0b                	ud2
ffffffff8af223ca:	90                   	nop
ffffffff8af223cb:	90                   	nop
ffffffff8af223cc:	90                   	nop
ffffffff8af223cd:	90                   	nop
ffffffff8af223ce:	90                   	nop
ffffffff8af223cf:	90                   	nop

ffffffff8af223d0 <frame_candidate_5623d0>:
ffffffff8af223d0:	55                   	push   %rbp
ffffffff8af223d1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8af223d4:	53                   	push   %rbx
ffffffff8af223d5:	50                   	push   %rax
ffffffff8af223d6:	48 8d 35 03 f8 56 01 	lea    0x156f803(%rip),%rsi        # ffffffff8c491be0 <frame_candidate_563fd0+0x156dc10>
ffffffff8af223dd:	bf c8 0c 00 00       	mov    $0xcc8,%edi
ffffffff8af223e2:	ba 02 01 00 00       	mov    $0x102,%edx
ffffffff8af223e7:	e8 64 67 6a 00       	call   ffffffff8b5c8b50 <frame_candidate_563fd0+0x6a4b80>
ffffffff8af223ec:	48 8d b8 c0 0c 00 00 	lea    0xcc0(%rax),%rdi
ffffffff8af223f3:	48 8d 35 e0 9d d2 00 	lea    0xd29de0(%rip),%rsi        # ffffffff8bc4c1da <frame_candidate_563fd0+0xd2820a>
ffffffff8af223fa:	48 89 c3             	mov    %rax,%rbx
ffffffff8af223fd:	c7 80 a4 0c 00 00 01 	movl   $0x1,0xca4(%rax)
ffffffff8af22404:	00 00 00 
ffffffff8af22407:	31 d2                	xor    %edx,%edx
ffffffff8af22409:	31 c9                	xor    %ecx,%ecx
ffffffff8af2240b:	e8 c0 59 f6 ff       	call   ffffffff8ae87dd0 <handler_631_body-0x9a310>
ffffffff8af22410:	48 89 d8             	mov    %rbx,%rax
ffffffff8af22413:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8af22417:	5b                   	pop    %rbx
ffffffff8af22418:	5d                   	pop    %rbp
ffffffff8af22419:	c3                   	ret
ffffffff8af2241a:	90                   	nop
ffffffff8af2241b:	90                   	nop
ffffffff8af2241c:	90                   	nop
ffffffff8af2241d:	90                   	nop
ffffffff8af2241e:	90                   	nop
ffffffff8af2241f:	90                   	nop
ffffffff8af22420:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
ffffffff8af22425:	f0 0f c1 87 a4 0c 00 	lock xadd %eax,0xca4(%rdi)
ffffffff8af2242c:	00 
ffffffff8af2242d:	83 f8 01             	cmp    $0x1,%eax
ffffffff8af22430:	75 2d                	jne    ffffffff8af2245f <frame_candidate_562432+0x2d>

ffffffff8af22432 <frame_candidate_562432>:
ffffffff8af22432:	55                   	push   %rbp
ffffffff8af22433:	48 89 e5             	mov    %rsp,%rbp
ffffffff8af22436:	53                   	push   %rbx
ffffffff8af22437:	50                   	push   %rax
ffffffff8af22438:	48 8d 87 c0 0c 00 00 	lea    0xcc0(%rdi),%rax
ffffffff8af2243f:	48 89 fb             	mov    %rdi,%rbx
ffffffff8af22442:	48 89 c7             	mov    %rax,%rdi
ffffffff8af22445:	e8 06 5a f6 ff       	call   ffffffff8ae87e50 <handler_631_body-0x9a290>
ffffffff8af2244a:	48 8d 35 8f f7 56 01 	lea    0x156f78f(%rip),%rsi        # ffffffff8c491be0 <frame_candidate_563fd0+0x156dc10>
ffffffff8af22451:	48 89 df             	mov    %rbx,%rdi
ffffffff8af22454:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8af22458:	5b                   	pop    %rbx
ffffffff8af22459:	5d                   	pop    %rbp
ffffffff8af2245a:	e9 91 69 6a 00       	jmp    ffffffff8b5c8df0 <frame_candidate_563fd0+0x6a4e20>
ffffffff8af2245f:	c3                   	ret

ffffffff8af22460 <frame_candidate_562460>:
ffffffff8af22460:	55                   	push   %rbp
ffffffff8af22461:	48 89 e5             	mov    %rsp,%rbp
ffffffff8af22464:	f0 83 87 a4 0c 00 00 	lock addl $0x1,0xca4(%rdi)
ffffffff8af2246b:	01 
ffffffff8af2246c:	48 89 f8             	mov    %rdi,%rax
ffffffff8af2246f:	5d                   	pop    %rbp
ffffffff8af22470:	c3                   	ret
ffffffff8af22471:	90                   	nop
ffffffff8af22472:	90                   	nop
ffffffff8af22473:	90                   	nop
ffffffff8af22474:	90                   	nop
ffffffff8af22475:	90                   	nop
ffffffff8af22476:	90                   	nop
ffffffff8af22477:	90                   	nop
ffffffff8af22478:	90                   	nop
ffffffff8af22479:	90                   	nop
ffffffff8af2247a:	90                   	nop
ffffffff8af2247b:	90                   	nop
ffffffff8af2247c:	90                   	nop
ffffffff8af2247d:	90                   	nop
ffffffff8af2247e:	90                   	nop
ffffffff8af2247f:	90                   	nop

ffffffff8af22480 <frame_candidate_562480>:
ffffffff8af22480:	55                   	push   %rbp
ffffffff8af22481:	48 89 e5             	mov    %rsp,%rbp
ffffffff8af22484:	41 57                	push   %r15
ffffffff8af22486:	41 56                	push   %r14
ffffffff8af22488:	53                   	push   %rbx
ffffffff8af22489:	50                   	push   %rax
ffffffff8af2248a:	4c 8d be c0 0c 00 00 	lea    0xcc0(%rsi),%r15
ffffffff8af22491:	49 89 fe             	mov    %rdi,%r14
ffffffff8af22494:	48 89 f3             	mov    %rsi,%rbx
ffffffff8af22497:	31 f6                	xor    %esi,%esi
ffffffff8af22499:	31 d2                	xor    %edx,%edx
ffffffff8af2249b:	31 c9                	xor    %ecx,%ecx
ffffffff8af2249d:	4c 89 ff             	mov    %r15,%rdi
ffffffff8af224a0:	e8 5b 45 f6 ff       	call   ffffffff8ae86a00 <handler_631_body-0x9b6e0>
ffffffff8af224a5:	ba a4 0c 00 00       	mov    $0xca4,%edx
ffffffff8af224aa:	48 89 df             	mov    %rbx,%rdi
ffffffff8af224ad:	4c 89 f6             	mov    %r14,%rsi
ffffffff8af224b0:	e8 2b 77 cf ff       	call   ffffffff8ac19be0 <handler_631_body-0x308500>
ffffffff8af224b5:	4c 89 ff             	mov    %r15,%rdi
ffffffff8af224b8:	31 f6                	xor    %esi,%esi
ffffffff8af224ba:	31 d2                	xor    %edx,%edx
ffffffff8af224bc:	31 c9                	xor    %ecx,%ecx
ffffffff8af224be:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8af224c2:	5b                   	pop    %rbx
ffffffff8af224c3:	41 5e                	pop    %r14
ffffffff8af224c5:	41 5f                	pop    %r15
ffffffff8af224c7:	5d                   	pop    %rbp
ffffffff8af224c8:	e9 d3 4a f6 ff       	jmp    ffffffff8ae86fa0 <handler_631_body-0x9b140>
ffffffff8af224cd:	90                   	nop
ffffffff8af224ce:	90                   	nop
ffffffff8af224cf:	90                   	nop

ffffffff8af224d0 <frame_candidate_5624d0>:
ffffffff8af224d0:	55                   	push   %rbp
ffffffff8af224d1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8af224d4:	31 c0                	xor    %eax,%eax
ffffffff8af224d6:	83 bf a4 0c 00 00 02 	cmpl   $0x2,0xca4(%rdi)
ffffffff8af224dd:	0f 93 c0             	setae  %al
ffffffff8af224e0:	5d                   	pop    %rbp
ffffffff8af224e1:	c3                   	ret
ffffffff8af224e2:	90                   	nop
ffffffff8af224e3:	90                   	nop
ffffffff8af224e4:	90                   	nop
ffffffff8af224e5:	90                   	nop
ffffffff8af224e6:	90                   	nop
ffffffff8af224e7:	90                   	nop
ffffffff8af224e8:	90                   	nop
ffffffff8af224e9:	90                   	nop
ffffffff8af224ea:	90                   	nop
ffffffff8af224eb:	90                   	nop
ffffffff8af224ec:	90                   	nop
ffffffff8af224ed:	90                   	nop
ffffffff8af224ee:	90                   	nop
ffffffff8af224ef:	90                   	nop

ffffffff8af224f0 <frame_candidate_5624f0>:
ffffffff8af224f0:	55                   	push   %rbp
ffffffff8af224f1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8af224f4:	48 8d 3d f1 2a d7 00 	lea    0xd72af1(%rip),%rdi        # ffffffff8bc94fec <frame_candidate_563fd0+0xd7101c>
ffffffff8af224fb:	be 70 00 00 00       	mov    $0x70,%esi
ffffffff8af22500:	31 d2                	xor    %edx,%edx
ffffffff8af22502:	31 c9                	xor    %ecx,%ecx
ffffffff8af22504:	45 31 c0             	xor    %r8d,%r8d
ffffffff8af22507:	45 31 c9             	xor    %r9d,%r9d
ffffffff8af2250a:	6a 00                	push   $0x0
ffffffff8af2250c:	6a 07                	push   $0x7
ffffffff8af2250e:	e8 cd 8b ed ff       	call   ffffffff8adfb0e0 <handler_631_body-0x127000>
ffffffff8af22513:	48 83 c4 10          	add    $0x10,%rsp
ffffffff8af22517:	8b 35 97 50 57 01    	mov    0x1575097(%rip),%esi        # ffffffff8c4975b4 <frame_candidate_563fd0+0x15735e4>
ffffffff8af2251d:	48 89 c7             	mov    %rax,%rdi
ffffffff8af22520:	48 89 05 71 8b 04 03 	mov    %rax,0x3048b71(%rip)        # ffffffff8df6b098 <frame_candidate_563fd0+0x30470c8>
ffffffff8af22527:	e8 e4 b1 ed ff       	call   ffffffff8adfd710 <handler_631_body-0x1249d0>
ffffffff8af2252c:	bf 09 00 00 00       	mov    $0x9,%edi
ffffffff8af22531:	be b0 0d 03 00       	mov    $0x30db0,%esi
ffffffff8af22536:	e8 c5 2e 63 00       	call   ffffffff8b555400 <frame_candidate_563fd0+0x631430>
ffffffff8af2253b:	bf 15 00 00 00       	mov    $0x15,%edi
ffffffff8af22540:	be 3e 00 00 00       	mov    $0x3e,%esi
ffffffff8af22545:	e8 b6 2e 63 00       	call   ffffffff8b555400 <frame_candidate_563fd0+0x631430>
ffffffff8af2254a:	8b 35 60 50 57 01    	mov    0x1575060(%rip),%esi        # ffffffff8c4975b0 <frame_candidate_563fd0+0x15735e0>
ffffffff8af22550:	bf 18 00 00 00       	mov    $0x18,%edi
ffffffff8af22555:	5d                   	pop    %rbp
ffffffff8af22556:	e9 a5 2e 63 00       	jmp    ffffffff8b555400 <frame_candidate_563fd0+0x631430>
ffffffff8af2255b:	90                   	nop
ffffffff8af2255c:	90                   	nop
ffffffff8af2255d:	90                   	nop
ffffffff8af2255e:	90                   	nop
ffffffff8af2255f:	90                   	nop

ffffffff8af22560 <frame_candidate_562560>:
ffffffff8af22560:	55                   	push   %rbp
ffffffff8af22561:	48 89 e5             	mov    %rsp,%rbp
ffffffff8af22564:	53                   	push   %rbx
ffffffff8af22565:	50                   	push   %rax
ffffffff8af22566:	48 8b 47 20          	mov    0x20(%rdi),%rax
ffffffff8af2256a:	48 85 c0             	test   %rax,%rax
ffffffff8af2256d:	0f 84 b2 00 00 00    	je     ffffffff8af22625 <frame_candidate_562560+0xc5>
ffffffff8af22573:	48 8b 4e 30          	mov    0x30(%rsi),%rcx
ffffffff8af22577:	4c 8b 47 30          	mov    0x30(%rdi),%r8
ffffffff8af2257b:	eb 0c                	jmp    ffffffff8af22589 <frame_candidate_562560+0x29>
ffffffff8af2257d:	0f 1f 00             	nopl   (%rax)
ffffffff8af22580:	48 85 c0             	test   %rax,%rax
ffffffff8af22583:	0f 84 9c 00 00 00    	je     ffffffff8af22625 <frame_candidate_562560+0xc5>
ffffffff8af22589:	48 89 c3             	mov    %rax,%rbx
ffffffff8af2258c:	48 8b 00             	mov    (%rax),%rax
ffffffff8af2258f:	44 8b 4b 10          	mov    0x10(%rbx),%r9d
ffffffff8af22593:	41 ff c9             	dec    %r9d
ffffffff8af22596:	45 89 ca             	mov    %r9d,%r10d
ffffffff8af22599:	41 c1 fa 05          	sar    $0x5,%r10d
ffffffff8af2259d:	4d 63 d2             	movslq %r10d,%r10
ffffffff8af225a0:	46 8b 14 92          	mov    (%rdx,%r10,4),%r10d
ffffffff8af225a4:	45 0f a3 ca          	bt     %r9d,%r10d
ffffffff8af225a8:	73 d6                	jae    ffffffff8af22580 <frame_candidate_562560+0x20>
ffffffff8af225aa:	48 85 c0             	test   %rax,%rax
ffffffff8af225ad:	74 21                	je     ffffffff8af225d0 <frame_candidate_562560+0x70>
ffffffff8af225af:	48 39 58 08          	cmp    %rbx,0x8(%rax)
ffffffff8af225b3:	0f 85 27 01 00 00    	jne    ffffffff8af226e0 <frame_candidate_562560+0x180>
ffffffff8af225b9:	4c 8b 4b 08          	mov    0x8(%rbx),%r9
ffffffff8af225bd:	49 39 19             	cmp    %rbx,(%r9)
ffffffff8af225c0:	0f 85 e0 00 00 00    	jne    ffffffff8af226a6 <frame_candidate_562560+0x146>
ffffffff8af225c6:	4c 89 48 08          	mov    %r9,0x8(%rax)
ffffffff8af225ca:	eb 15                	jmp    ffffffff8af225e1 <frame_candidate_562560+0x81>
ffffffff8af225cc:	0f 1f 40 00          	nopl   0x0(%rax)
ffffffff8af225d0:	4c 8b 4b 08          	mov    0x8(%rbx),%r9
ffffffff8af225d4:	49 39 19             	cmp    %rbx,(%r9)
ffffffff8af225d7:	0f 85 c9 00 00 00    	jne    ffffffff8af226a6 <frame_candidate_562560+0x146>
ffffffff8af225dd:	4c 89 4f 28          	mov    %r9,0x28(%rdi)
ffffffff8af225e1:	4c 8b 0b             	mov    (%rbx),%r9
ffffffff8af225e4:	4c 8b 53 08          	mov    0x8(%rbx),%r10
ffffffff8af225e8:	4d 89 0a             	mov    %r9,(%r10)
ffffffff8af225eb:	4d 85 c0             	test   %r8,%r8
ffffffff8af225ee:	74 07                	je     ffffffff8af225f7 <frame_candidate_562560+0x97>
ffffffff8af225f0:	41 ff 88 b4 03 00 00 	decl   0x3b4(%r8)
ffffffff8af225f7:	48 c7 03 00 00 00 00 	movq   $0x0,(%rbx)
ffffffff8af225fe:	4c 8b 4e 28          	mov    0x28(%rsi),%r9
ffffffff8af22602:	4c 89 4b 08          	mov    %r9,0x8(%rbx)
ffffffff8af22606:	49 89 19             	mov    %rbx,(%r9)
ffffffff8af22609:	48 89 5e 28          	mov    %rbx,0x28(%rsi)
ffffffff8af2260d:	48 89 73 68          	mov    %rsi,0x68(%rbx)
ffffffff8af22611:	48 85 c9             	test   %rcx,%rcx
ffffffff8af22614:	0f 84 66 ff ff ff    	je     ffffffff8af22580 <frame_candidate_562560+0x20>
ffffffff8af2261a:	ff 81 b4 03 00 00    	incl   0x3b4(%rcx)
ffffffff8af22620:	e9 5b ff ff ff       	jmp    ffffffff8af22580 <frame_candidate_562560+0x20>
ffffffff8af22625:	8b 02                	mov    (%rdx),%eax
ffffffff8af22627:	8b 4a 04             	mov    0x4(%rdx),%ecx
ffffffff8af2262a:	44 8b 42 08          	mov    0x8(%rdx),%r8d
ffffffff8af2262e:	44 8b 4a 0c          	mov    0xc(%rdx),%r9d
ffffffff8af22632:	23 47 10             	and    0x10(%rdi),%eax
ffffffff8af22635:	23 4f 14             	and    0x14(%rdi),%ecx
ffffffff8af22638:	44 23 47 18          	and    0x18(%rdi),%r8d
ffffffff8af2263c:	44 23 4f 1c          	and    0x1c(%rdi),%r9d
ffffffff8af22640:	09 46 10             	or     %eax,0x10(%rsi)
ffffffff8af22643:	09 4e 14             	or     %ecx,0x14(%rsi)
ffffffff8af22646:	44 09 46 18          	or     %r8d,0x18(%rsi)
ffffffff8af2264a:	44 09 4e 1c          	or     %r9d,0x1c(%rsi)
ffffffff8af2264e:	f7 d0                	not    %eax
ffffffff8af22650:	f7 d1                	not    %ecx
ffffffff8af22652:	41 f7 d0             	not    %r8d
ffffffff8af22655:	41 f7 d1             	not    %r9d
ffffffff8af22658:	21 47 10             	and    %eax,0x10(%rdi)
ffffffff8af2265b:	21 4f 14             	and    %ecx,0x14(%rdi)
ffffffff8af2265e:	44 21 47 18          	and    %r8d,0x18(%rdi)
ffffffff8af22662:	44 21 4f 1c          	and    %r9d,0x1c(%rdi)
ffffffff8af22666:	8b 02                	mov    (%rdx),%eax
ffffffff8af22668:	8b 4a 04             	mov    0x4(%rdx),%ecx
ffffffff8af2266b:	44 8b 42 08          	mov    0x8(%rdx),%r8d
ffffffff8af2266f:	8b 52 0c             	mov    0xc(%rdx),%edx
ffffffff8af22672:	23 07                	and    (%rdi),%eax
ffffffff8af22674:	23 4f 04             	and    0x4(%rdi),%ecx
ffffffff8af22677:	44 23 47 08          	and    0x8(%rdi),%r8d
ffffffff8af2267b:	23 57 0c             	and    0xc(%rdi),%edx
ffffffff8af2267e:	09 06                	or     %eax,(%rsi)
ffffffff8af22680:	09 4e 04             	or     %ecx,0x4(%rsi)
ffffffff8af22683:	44 09 46 08          	or     %r8d,0x8(%rsi)
ffffffff8af22687:	09 56 0c             	or     %edx,0xc(%rsi)
ffffffff8af2268a:	f7 d0                	not    %eax
ffffffff8af2268c:	f7 d1                	not    %ecx
ffffffff8af2268e:	41 f7 d0             	not    %r8d
ffffffff8af22691:	f7 d2                	not    %edx
ffffffff8af22693:	21 07                	and    %eax,(%rdi)
ffffffff8af22695:	21 4f 04             	and    %ecx,0x4(%rdi)
ffffffff8af22698:	44 21 47 08          	and    %r8d,0x8(%rdi)
ffffffff8af2269c:	21 57 0c             	and    %edx,0xc(%rdi)
ffffffff8af2269f:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8af226a3:	5b                   	pop    %rbx
ffffffff8af226a4:	5d                   	pop    %rbp
ffffffff8af226a5:	c3                   	ret
ffffffff8af226a6:	e8 a5 f2 28 00       	call   ffffffff8b1b1950 <frame_candidate_563fd0+0x28d980>
ffffffff8af226ab:	48 8b 53 08          	mov    0x8(%rbx),%rdx
ffffffff8af226af:	48 8d 3d f0 ff ff ff 	lea    -0x10(%rip),%rdi        # ffffffff8af226a6 <frame_candidate_562560+0x146>
ffffffff8af226b6:	48 89 de             	mov    %rbx,%rsi
ffffffff8af226b9:	48 8b 0a             	mov    (%rdx),%rcx
ffffffff8af226bc:	e8 ff f9 28 00       	call   ffffffff8b1b20c0 <frame_candidate_563fd0+0x28e0f0>
ffffffff8af226c1:	48 8b 4b 08          	mov    0x8(%rbx),%rcx
ffffffff8af226c5:	48 8d 35 da 87 e3 00 	lea    0xe387da(%rip),%rsi        # ffffffff8bd5aea6 <frame_candidate_563fd0+0xe36ed6>
ffffffff8af226cc:	bf 1f 00 00 00       	mov    $0x1f,%edi
ffffffff8af226d1:	48 89 da             	mov    %rbx,%rdx
ffffffff8af226d4:	31 c0                	xor    %eax,%eax
ffffffff8af226d6:	4c 8b 01             	mov    (%rcx),%r8
ffffffff8af226d9:	e8 32 83 73 00       	call   ffffffff8b65aa10 <frame_candidate_563fd0+0x736a40>
ffffffff8af226de:	0f 0b                	ud2
ffffffff8af226e0:	e8 6b f2 28 00       	call   ffffffff8b1b1950 <frame_candidate_563fd0+0x28d980>
ffffffff8af226e5:	48 8b 13             	mov    (%rbx),%rdx
ffffffff8af226e8:	48 8d 3d f1 ff ff ff 	lea    -0xf(%rip),%rdi        # ffffffff8af226e0 <frame_candidate_562560+0x180>
ffffffff8af226ef:	48 89 de             	mov    %rbx,%rsi
ffffffff8af226f2:	49 89 d8             	mov    %rbx,%r8
ffffffff8af226f5:	48 8b 4a 08          	mov    0x8(%rdx),%rcx
ffffffff8af226f9:	e8 82 fa 28 00       	call   ffffffff8b1b2180 <frame_candidate_563fd0+0x28e1b0>
ffffffff8af226fe:	48 8b 0b             	mov    (%rbx),%rcx
ffffffff8af22701:	48 8d 35 89 ea d3 00 	lea    0xd3ea89(%rip),%rsi        # ffffffff8bc61191 <frame_candidate_563fd0+0xd3d1c1>
ffffffff8af22708:	bf 1b 00 00 00       	mov    $0x1b,%edi
ffffffff8af2270d:	48 89 da             	mov    %rbx,%rdx
ffffffff8af22710:	49 89 d9             	mov    %rbx,%r9
ffffffff8af22713:	31 c0                	xor    %eax,%eax
ffffffff8af22715:	4c 8b 41 08          	mov    0x8(%rcx),%r8
ffffffff8af22719:	e8 f2 82 73 00       	call   ffffffff8b65aa10 <frame_candidate_563fd0+0x736a40>
ffffffff8af2271e:	0f 0b                	ud2

ffffffff8af22720 <frame_candidate_562720>:
ffffffff8af22720:	55                   	push   %rbp
ffffffff8af22721:	48 89 e5             	mov    %rsp,%rbp
ffffffff8af22724:	41 56                	push   %r14
ffffffff8af22726:	53                   	push   %rbx
ffffffff8af22727:	48 83 ec 10          	sub    $0x10,%rsp
ffffffff8af2272b:	4c 8d 35 de 9b 3b 03 	lea    0x33b9bde(%rip),%r14        # ffffffff8e2dc310 <frame_candidate_563fd0+0x33b8340>
ffffffff8af22732:	48 8d 75 e4          	lea    -0x1c(%rbp),%rsi
ffffffff8af22736:	31 d2                	xor    %edx,%edx
ffffffff8af22738:	48 89 cb             	mov    %rcx,%rbx
ffffffff8af2273b:	49 8b 06             	mov    (%r14),%rax
ffffffff8af2273e:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
ffffffff8af22742:	8b 05 a8 4e 57 01    	mov    0x1574ea8(%rip),%eax        # ffffffff8c4975f0 <frame_candidate_563fd0+0x1573620>
ffffffff8af22748:	89 45 e4             	mov    %eax,-0x1c(%rbp)
ffffffff8af2274b:	e8 98 e2 d0 ff       	call   ffffffff8ac309e8 <handler_631_body-0x2f16f8>
ffffffff8af22750:	85 c0                	test   %eax,%eax
ffffffff8af22752:	75 25                	jne    ffffffff8af22779 <frame_candidate_562720+0x59>
ffffffff8af22754:	48 83 7b 30 00       	cmpq   $0x0,0x30(%rbx)
ffffffff8af22759:	74 1e                	je     ffffffff8af22779 <frame_candidate_562720+0x59>
ffffffff8af2275b:	8b 4d e4             	mov    -0x1c(%rbp),%ecx
ffffffff8af2275e:	89 ca                	mov    %ecx,%edx
ffffffff8af22760:	c1 fa 1f             	sar    $0x1f,%edx
ffffffff8af22763:	c4 e2 68 f2 c9       	andn   %ecx,%edx,%ecx
ffffffff8af22768:	ba 0a 00 00 00       	mov    $0xa,%edx
ffffffff8af2276d:	83 f9 0a             	cmp    $0xa,%ecx
ffffffff8af22770:	0f 4c d1             	cmovl  %ecx,%edx
ffffffff8af22773:	89 15 77 4e 57 01    	mov    %edx,0x1574e77(%rip)        # ffffffff8c4975f0 <frame_candidate_563fd0+0x1573620>
ffffffff8af22779:	49 8b 0e             	mov    (%r14),%rcx
ffffffff8af2277c:	48 3b 4d e8          	cmp    -0x18(%rbp),%rcx
ffffffff8af22780:	75 09                	jne    ffffffff8af2278b <frame_candidate_562720+0x6b>
ffffffff8af22782:	48 83 c4 10          	add    $0x10,%rsp
ffffffff8af22786:	5b                   	pop    %rbx
ffffffff8af22787:	41 5e                	pop    %r14
ffffffff8af22789:	5d                   	pop    %rbp
ffffffff8af2278a:	c3                   	ret
ffffffff8af2278b:	e8 20 af 19 00       	call   ffffffff8b0bd6b0 <frame_candidate_563fd0+0x1996e0>
ffffffff8af22790:	0f 0b                	ud2
ffffffff8af22792:	90                   	nop
ffffffff8af22793:	90                   	nop
ffffffff8af22794:	90                   	nop
ffffffff8af22795:	90                   	nop
ffffffff8af22796:	90                   	nop
ffffffff8af22797:	90                   	nop
ffffffff8af22798:	90                   	nop
ffffffff8af22799:	90                   	nop
ffffffff8af2279a:	90                   	nop
ffffffff8af2279b:	90                   	nop
ffffffff8af2279c:	90                   	nop
ffffffff8af2279d:	90                   	nop
ffffffff8af2279e:	90                   	nop
ffffffff8af2279f:	90                   	nop

ffffffff8af227a0 <frame_candidate_5627a0>:
ffffffff8af227a0:	55                   	push   %rbp
ffffffff8af227a1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8af227a4:	41 57                	push   %r15
ffffffff8af227a6:	41 56                	push   %r14
ffffffff8af227a8:	53                   	push   %rbx
ffffffff8af227a9:	50                   	push   %rax
ffffffff8af227aa:	4c 8d 3d af 76 02 03 	lea    0x30276af(%rip),%r15        # ffffffff8df49e60 <frame_candidate_563fd0+0x3025e90>
ffffffff8af227b1:	49 89 fe             	mov    %rdi,%r14
ffffffff8af227b4:	48 89 cb             	mov    %rcx,%rbx
ffffffff8af227b7:	31 f6                	xor    %esi,%esi
ffffffff8af227b9:	31 d2                	xor    %edx,%edx
ffffffff8af227bb:	31 c9                	xor    %ecx,%ecx
ffffffff8af227bd:	4c 89 ff             	mov    %r15,%rdi
ffffffff8af227c0:	e8 5b 93 6e 00       	call   ffffffff8b60bb20 <frame_candidate_563fd0+0x6e7b50>
ffffffff8af227c5:	48 8d 35 34 4e 57 01 	lea    0x1574e34(%rip),%rsi        # ffffffff8c497600 <frame_candidate_563fd0+0x1573630>
ffffffff8af227cc:	ba 00 04 00 00       	mov    $0x400,%edx
ffffffff8af227d1:	4c 89 f7             	mov    %r14,%rdi
ffffffff8af227d4:	48 89 d9             	mov    %rbx,%rcx
ffffffff8af227d7:	e8 d4 e2 d0 ff       	call   ffffffff8ac30ab0 <handler_631_body-0x2f1630>
ffffffff8af227dc:	4c 89 ff             	mov    %r15,%rdi
ffffffff8af227df:	89 c3                	mov    %eax,%ebx
ffffffff8af227e1:	31 f6                	xor    %esi,%esi
ffffffff8af227e3:	31 d2                	xor    %edx,%edx
ffffffff8af227e5:	e8 c6 9c 6e 00       	call   ffffffff8b60c4b0 <frame_candidate_563fd0+0x6e84e0>
ffffffff8af227ea:	89 d8                	mov    %ebx,%eax
ffffffff8af227ec:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8af227f0:	5b                   	pop    %rbx
ffffffff8af227f1:	41 5e                	pop    %r14
ffffffff8af227f3:	41 5f                	pop    %r15
ffffffff8af227f5:	5d                   	pop    %rbp
ffffffff8af227f6:	c3                   	ret
ffffffff8af227f7:	90                   	nop
ffffffff8af227f8:	90                   	nop
ffffffff8af227f9:	90                   	nop
ffffffff8af227fa:	90                   	nop
ffffffff8af227fb:	90                   	nop
ffffffff8af227fc:	90                   	nop
ffffffff8af227fd:	90                   	nop
ffffffff8af227fe:	90                   	nop
ffffffff8af227ff:	90                   	nop

ffffffff8af22800 <frame_candidate_562800>:
ffffffff8af22800:	55                   	push   %rbp
ffffffff8af22801:	48 89 e5             	mov    %rsp,%rbp
ffffffff8af22804:	41 56                	push   %r14
ffffffff8af22806:	53                   	push   %rbx
ffffffff8af22807:	48 89 fb             	mov    %rdi,%rbx
ffffffff8af2280a:	48 8b bf 38 dc 18 00 	mov    0x18dc38(%rdi),%rdi
ffffffff8af22811:	e8 ca 13 d5 ff       	call   ffffffff8ac73be0 <handler_631_body-0x2ae500>
ffffffff8af22816:	85 c0                	test   %eax,%eax
ffffffff8af22818:	74 4f                	je     ffffffff8af22869 <frame_candidate_562800+0x69>
ffffffff8af2281a:	48 8b bb 38 dc 18 00 	mov    0x18dc38(%rbx),%rdi
ffffffff8af22821:	e8 ba 13 d5 ff       	call   ffffffff8ac73be0 <handler_631_body-0x2ae500>
ffffffff8af22826:	85 c0                	test   %eax,%eax
ffffffff8af22828:	75 3f                	jne    ffffffff8af22869 <frame_candidate_562800+0x69>
ffffffff8af2282a:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af22830:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af22837:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af2283e:	00 
ffffffff8af2283f:	74 07                	je     ffffffff8af22848 <frame_candidate_562800+0x48>
ffffffff8af22841:	8b 02                	mov    (%rdx),%eax
ffffffff8af22843:	83 e0 fb             	and    $0xfffffffb,%eax
ffffffff8af22846:	eb 1f                	jmp    ffffffff8af22867 <frame_candidate_562800+0x67>
ffffffff8af22848:	ed                   	in     (%dx),%eax
ffffffff8af22849:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af2284f:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af22856:	83 e0 fb             	and    $0xfffffffb,%eax
ffffffff8af22859:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af22860:	00 
ffffffff8af22861:	0f 84 39 03 00 00    	je     ffffffff8af22ba0 <frame_candidate_562800+0x3a0>
ffffffff8af22867:	89 02                	mov    %eax,(%rdx)
ffffffff8af22869:	8b 93 48 e3 18 00    	mov    0x18e348(%rbx),%edx
ffffffff8af2286f:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af22876:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af2287d:	00 
ffffffff8af2287e:	74 0d                	je     ffffffff8af2288d <frame_candidate_562800+0x8d>
ffffffff8af22880:	c7 02 02 00 00 00    	movl   $0x2,(%rdx)
ffffffff8af22886:	66 41 be 19 00       	mov    $0x19,%r14w
ffffffff8af2288b:	eb 13                	jmp    ffffffff8af228a0 <frame_candidate_562800+0xa0>
ffffffff8af2288d:	b8 02 00 00 00       	mov    $0x2,%eax
ffffffff8af22892:	ef                   	out    %eax,(%dx)
ffffffff8af22893:	66 41 be 19 00       	mov    $0x19,%r14w
ffffffff8af22898:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
ffffffff8af2289f:	00 
ffffffff8af228a0:	48 63 05 99 db 3b 03 	movslq 0x33bdb99(%rip),%rax        # ffffffff8e2e0440 <frame_candidate_563fd0+0x33bc470>
ffffffff8af228a7:	31 ff                	xor    %edi,%edi
ffffffff8af228a9:	48 69 f0 1f 85 eb 51 	imul   $0x51eb851f,%rax,%rsi
ffffffff8af228b0:	48 89 f0             	mov    %rsi,%rax
ffffffff8af228b3:	48 c1 fe 25          	sar    $0x25,%rsi
ffffffff8af228b7:	48 c1 e8 3f          	shr    $0x3f,%rax
ffffffff8af228bb:	01 c6                	add    %eax,%esi
ffffffff8af228bd:	e8 7e b1 68 00       	call   ffffffff8b5ada40 <frame_candidate_563fd0+0x689a70>
ffffffff8af228c2:	8b 93 48 e3 18 00    	mov    0x18e348(%rbx),%edx
ffffffff8af228c8:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af228cf:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af228d6:	00 
ffffffff8af228d7:	74 17                	je     ffffffff8af228f0 <frame_candidate_562800+0xf0>
ffffffff8af228d9:	8b 02                	mov    (%rdx),%eax
ffffffff8af228db:	a8 02                	test   $0x2,%al
ffffffff8af228dd:	75 16                	jne    ffffffff8af228f5 <frame_candidate_562800+0xf5>
ffffffff8af228df:	eb 51                	jmp    ffffffff8af22932 <frame_candidate_562800+0x132>
ffffffff8af228e1:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
ffffffff8af228e8:	0f 1f 84 00 00 00 00 
ffffffff8af228ef:	00 
ffffffff8af228f0:	ed                   	in     (%dx),%eax
ffffffff8af228f1:	a8 02                	test   $0x2,%al
ffffffff8af228f3:	74 3d                	je     ffffffff8af22932 <frame_candidate_562800+0x132>
ffffffff8af228f5:	66 41 ff ce          	dec    %r14w
ffffffff8af228f9:	75 a5                	jne    ffffffff8af228a0 <frame_candidate_562800+0xa0>
ffffffff8af228fb:	48 8b bb 38 dc 18 00 	mov    0x18dc38(%rbx),%rdi
ffffffff8af22902:	48 8d 35 04 dd e2 00 	lea    0xe2dd04(%rip),%rsi        # ffffffff8bd5060d <frame_candidate_563fd0+0xe2c63d>
ffffffff8af22909:	31 c0                	xor    %eax,%eax
ffffffff8af2290b:	e8 60 13 d5 ff       	call   ffffffff8ac73c70 <handler_631_body-0x2ae470>
ffffffff8af22910:	e8 3b f0 28 00       	call   ffffffff8b1b1950 <frame_candidate_563fd0+0x28d980>
ffffffff8af22915:	48 8d 3d f4 ff ff ff 	lea    -0xc(%rip),%rdi        # ffffffff8af22910 <frame_candidate_562800+0x110>
ffffffff8af2291c:	e8 ef ee 28 00       	call   ffffffff8b1b1810 <frame_candidate_563fd0+0x28d840>
ffffffff8af22921:	48 8d 35 08 ca d5 00 	lea    0xd5ca08(%rip),%rsi        # ffffffff8bc7f330 <frame_candidate_563fd0+0xd5b360>
ffffffff8af22928:	bf 0f 00 00 00       	mov    $0xf,%edi
ffffffff8af2292d:	e9 9e 00 00 00       	jmp    ffffffff8af229d0 <frame_candidate_562800+0x1d0>
ffffffff8af22932:	66 41 be 64 00       	mov    $0x64,%r14w
ffffffff8af22937:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
ffffffff8af2293e:	00 00 
ffffffff8af22940:	48 63 05 f9 da 3b 03 	movslq 0x33bdaf9(%rip),%rax        # ffffffff8e2e0440 <frame_candidate_563fd0+0x33bc470>
ffffffff8af22947:	31 ff                	xor    %edi,%edi
ffffffff8af22949:	48 69 f0 1f 85 eb 51 	imul   $0x51eb851f,%rax,%rsi
ffffffff8af22950:	48 89 f0             	mov    %rsi,%rax
ffffffff8af22953:	48 c1 fe 25          	sar    $0x25,%rsi
ffffffff8af22957:	48 c1 e8 3f          	shr    $0x3f,%rax
ffffffff8af2295b:	01 c6                	add    %eax,%esi
ffffffff8af2295d:	e8 de b0 68 00       	call   ffffffff8b5ada40 <frame_candidate_563fd0+0x689a70>
ffffffff8af22962:	8b 93 48 e3 18 00    	mov    0x18e348(%rbx),%edx
ffffffff8af22968:	83 c2 04             	add    $0x4,%edx
ffffffff8af2296b:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af22972:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af22979:	00 
ffffffff8af2297a:	74 14                	je     ffffffff8af22990 <frame_candidate_562800+0x190>
ffffffff8af2297c:	8b 02                	mov    (%rdx),%eax
ffffffff8af2297e:	a9 00 08 00 00       	test   $0x800,%eax
ffffffff8af22983:	75 13                	jne    ffffffff8af22998 <frame_candidate_562800+0x198>
ffffffff8af22985:	eb 52                	jmp    ffffffff8af229d9 <frame_candidate_562800+0x1d9>
ffffffff8af22987:	66 0f 1f 84 00 00 00 	nopw   0x0(%rax,%rax,1)
ffffffff8af2298e:	00 00 
ffffffff8af22990:	ed                   	in     (%dx),%eax
ffffffff8af22991:	a9 00 08 00 00       	test   $0x800,%eax
ffffffff8af22996:	74 41                	je     ffffffff8af229d9 <frame_candidate_562800+0x1d9>
ffffffff8af22998:	66 41 ff ce          	dec    %r14w
ffffffff8af2299c:	75 a2                	jne    ffffffff8af22940 <frame_candidate_562800+0x140>
ffffffff8af2299e:	48 8b bb 38 dc 18 00 	mov    0x18dc38(%rbx),%rdi
ffffffff8af229a5:	48 8d 35 67 a2 df 00 	lea    0xdfa267(%rip),%rsi        # ffffffff8bd1cc13 <frame_candidate_563fd0+0xdf8c43>
ffffffff8af229ac:	31 c0                	xor    %eax,%eax
ffffffff8af229ae:	e8 bd 12 d5 ff       	call   ffffffff8ac73c70 <handler_631_body-0x2ae470>
ffffffff8af229b3:	e8 98 ef 28 00       	call   ffffffff8b1b1950 <frame_candidate_563fd0+0x28d980>
ffffffff8af229b8:	48 8d 3d f4 ff ff ff 	lea    -0xc(%rip),%rdi        # ffffffff8af229b3 <frame_candidate_562800+0x1b3>
ffffffff8af229bf:	e8 4c ee 28 00       	call   ffffffff8b1b1810 <frame_candidate_563fd0+0x28d840>
ffffffff8af229c4:	48 8d 35 65 c9 d5 00 	lea    0xd5c965(%rip),%rsi        # ffffffff8bc7f330 <frame_candidate_563fd0+0xd5b360>
ffffffff8af229cb:	bf 13 00 00 00       	mov    $0x13,%edi
ffffffff8af229d0:	31 c0                	xor    %eax,%eax
ffffffff8af229d2:	e8 39 80 73 00       	call   ffffffff8b65aa10 <frame_candidate_563fd0+0x736a40>
ffffffff8af229d7:	0f 0b                	ud2
ffffffff8af229d9:	48 8b bb 38 dc 18 00 	mov    0x18dc38(%rbx),%rdi
ffffffff8af229e0:	e8 fb 11 d5 ff       	call   ffffffff8ac73be0 <handler_631_body-0x2ae500>
ffffffff8af229e5:	48 8b bb 38 dc 18 00 	mov    0x18dc38(%rbx),%rdi
ffffffff8af229ec:	41 89 c6             	mov    %eax,%r14d
ffffffff8af229ef:	e8 ec 11 d5 ff       	call   ffffffff8ac73be0 <handler_631_body-0x2ae500>
ffffffff8af229f4:	45 85 f6             	test   %r14d,%r14d
ffffffff8af229f7:	74 22                	je     ffffffff8af22a1b <frame_candidate_562800+0x21b>
ffffffff8af229f9:	85 c0                	test   %eax,%eax
ffffffff8af229fb:	75 6c                	jne    ffffffff8af22a69 <frame_candidate_562800+0x269>
ffffffff8af229fd:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af22a03:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af22a0a:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af22a11:	00 
ffffffff8af22a12:	74 34                	je     ffffffff8af22a48 <frame_candidate_562800+0x248>
ffffffff8af22a14:	8b 02                	mov    (%rdx),%eax
ffffffff8af22a16:	83 e0 fd             	and    $0xfffffffd,%eax
ffffffff8af22a19:	eb 4c                	jmp    ffffffff8af22a67 <frame_candidate_562800+0x267>
ffffffff8af22a1b:	85 c0                	test   %eax,%eax
ffffffff8af22a1d:	0f 85 c9 00 00 00    	jne    ffffffff8af22aec <frame_candidate_562800+0x2ec>
ffffffff8af22a23:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af22a29:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af22a30:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af22a37:	00 
ffffffff8af22a38:	0f 84 8d 00 00 00    	je     ffffffff8af22acb <frame_candidate_562800+0x2cb>
ffffffff8af22a3e:	8b 02                	mov    (%rdx),%eax
ffffffff8af22a40:	83 e0 fd             	and    $0xfffffffd,%eax
ffffffff8af22a43:	e9 a2 00 00 00       	jmp    ffffffff8af22aea <frame_candidate_562800+0x2ea>
ffffffff8af22a48:	ed                   	in     (%dx),%eax
ffffffff8af22a49:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af22a4f:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af22a56:	83 e0 fd             	and    $0xfffffffd,%eax
ffffffff8af22a59:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af22a60:	00 
ffffffff8af22a61:	0f 84 3f 01 00 00    	je     ffffffff8af22ba6 <frame_candidate_562800+0x3a6>
ffffffff8af22a67:	89 02                	mov    %eax,(%rdx)
ffffffff8af22a69:	bf 10 27 00 00       	mov    $0x2710,%edi
ffffffff8af22a6e:	e8 6d b7 f0 ff       	call   ffffffff8ae2e1e0 <handler_631_body-0xf3f00>
ffffffff8af22a73:	48 8b bb 38 dc 18 00 	mov    0x18dc38(%rbx),%rdi
ffffffff8af22a7a:	e8 61 11 d5 ff       	call   ffffffff8ac73be0 <handler_631_body-0x2ae500>
ffffffff8af22a7f:	85 c0                	test   %eax,%eax
ffffffff8af22a81:	0f 85 0d 01 00 00    	jne    ffffffff8af22b94 <frame_candidate_562800+0x394>
ffffffff8af22a87:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af22a8d:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af22a94:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af22a9b:	00 
ffffffff8af22a9c:	74 07                	je     ffffffff8af22aa5 <frame_candidate_562800+0x2a5>
ffffffff8af22a9e:	8b 02                	mov    (%rdx),%eax
ffffffff8af22aa0:	83 c8 04             	or     $0x4,%eax
ffffffff8af22aa3:	eb 1f                	jmp    ffffffff8af22ac4 <frame_candidate_562800+0x2c4>
ffffffff8af22aa5:	ed                   	in     (%dx),%eax
ffffffff8af22aa6:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af22aac:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af22ab3:	83 c8 04             	or     $0x4,%eax
ffffffff8af22ab6:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af22abd:	00 
ffffffff8af22abe:	0f 84 e8 00 00 00    	je     ffffffff8af22bac <frame_candidate_562800+0x3ac>
ffffffff8af22ac4:	89 02                	mov    %eax,(%rdx)
ffffffff8af22ac6:	e9 c9 00 00 00       	jmp    ffffffff8af22b94 <frame_candidate_562800+0x394>
ffffffff8af22acb:	ed                   	in     (%dx),%eax
ffffffff8af22acc:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af22ad2:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af22ad9:	83 e0 fd             	and    $0xfffffffd,%eax
ffffffff8af22adc:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af22ae3:	00 
ffffffff8af22ae4:	0f 84 c5 00 00 00    	je     ffffffff8af22baf <frame_candidate_562800+0x3af>
ffffffff8af22aea:	89 02                	mov    %eax,(%rdx)
ffffffff8af22aec:	48 8b bb 38 dc 18 00 	mov    0x18dc38(%rbx),%rdi
ffffffff8af22af3:	e8 e8 10 d5 ff       	call   ffffffff8ac73be0 <handler_631_body-0x2ae500>
ffffffff8af22af8:	85 c0                	test   %eax,%eax
ffffffff8af22afa:	75 3f                	jne    ffffffff8af22b3b <frame_candidate_562800+0x33b>
ffffffff8af22afc:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af22b02:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af22b09:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af22b10:	00 
ffffffff8af22b11:	74 09                	je     ffffffff8af22b1c <frame_candidate_562800+0x31c>
ffffffff8af22b13:	b8 ff ff fd ff       	mov    $0xfffdffff,%eax
ffffffff8af22b18:	23 02                	and    (%rdx),%eax
ffffffff8af22b1a:	eb 1d                	jmp    ffffffff8af22b39 <frame_candidate_562800+0x339>
ffffffff8af22b1c:	ed                   	in     (%dx),%eax
ffffffff8af22b1d:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af22b23:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af22b2a:	25 ff ff fd ff       	and    $0xfffdffff,%eax
ffffffff8af22b2f:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af22b36:	00 
ffffffff8af22b37:	74 7c                	je     ffffffff8af22bb5 <frame_candidate_562800+0x3b5>
ffffffff8af22b39:	89 02                	mov    %eax,(%rdx)
ffffffff8af22b3b:	48 8b bb 38 dc 18 00 	mov    0x18dc38(%rbx),%rdi
ffffffff8af22b42:	e8 99 10 d5 ff       	call   ffffffff8ac73be0 <handler_631_body-0x2ae500>
ffffffff8af22b47:	85 c0                	test   %eax,%eax
ffffffff8af22b49:	75 3f                	jne    ffffffff8af22b8a <frame_candidate_562800+0x38a>
ffffffff8af22b4b:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af22b51:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af22b58:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af22b5f:	00 
ffffffff8af22b60:	74 09                	je     ffffffff8af22b6b <frame_candidate_562800+0x36b>
ffffffff8af22b62:	b8 ff ff ff fd       	mov    $0xfdffffff,%eax
ffffffff8af22b67:	23 02                	and    (%rdx),%eax
ffffffff8af22b69:	eb 1d                	jmp    ffffffff8af22b88 <frame_candidate_562800+0x388>
ffffffff8af22b6b:	ed                   	in     (%dx),%eax
ffffffff8af22b6c:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af22b72:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af22b79:	25 ff ff ff fd       	and    $0xfdffffff,%eax
ffffffff8af22b7e:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af22b85:	00 
ffffffff8af22b86:	74 30                	je     ffffffff8af22bb8 <frame_candidate_562800+0x3b8>
ffffffff8af22b88:	89 02                	mov    %eax,(%rdx)
ffffffff8af22b8a:	bf 20 4e 00 00       	mov    $0x4e20,%edi
ffffffff8af22b8f:	e8 4c b6 f0 ff       	call   ffffffff8ae2e1e0 <handler_631_body-0xf3f00>
ffffffff8af22b94:	48 89 df             	mov    %rbx,%rdi
ffffffff8af22b97:	5b                   	pop    %rbx
ffffffff8af22b98:	41 5e                	pop    %r14
ffffffff8af22b9a:	5d                   	pop    %rbp
ffffffff8af22b9b:	e9 20 00 00 00       	jmp    ffffffff8af22bc0 <frame_candidate_562bc0>
ffffffff8af22ba0:	ef                   	out    %eax,(%dx)
ffffffff8af22ba1:	e9 c3 fc ff ff       	jmp    ffffffff8af22869 <frame_candidate_562800+0x69>
ffffffff8af22ba6:	ef                   	out    %eax,(%dx)
ffffffff8af22ba7:	e9 bd fe ff ff       	jmp    ffffffff8af22a69 <frame_candidate_562800+0x269>
ffffffff8af22bac:	ef                   	out    %eax,(%dx)
ffffffff8af22bad:	eb e5                	jmp    ffffffff8af22b94 <frame_candidate_562800+0x394>
ffffffff8af22baf:	ef                   	out    %eax,(%dx)
ffffffff8af22bb0:	e9 37 ff ff ff       	jmp    ffffffff8af22aec <frame_candidate_562800+0x2ec>
ffffffff8af22bb5:	ef                   	out    %eax,(%dx)
ffffffff8af22bb6:	eb 83                	jmp    ffffffff8af22b3b <frame_candidate_562800+0x33b>
ffffffff8af22bb8:	ef                   	out    %eax,(%dx)
ffffffff8af22bb9:	eb cf                	jmp    ffffffff8af22b8a <frame_candidate_562800+0x38a>
ffffffff8af22bbb:	90                   	nop
ffffffff8af22bbc:	90                   	nop
ffffffff8af22bbd:	90                   	nop
ffffffff8af22bbe:	90                   	nop
ffffffff8af22bbf:	90                   	nop

ffffffff8af22bc0 <frame_candidate_562bc0>:
ffffffff8af22bc0:	55                   	push   %rbp
ffffffff8af22bc1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8af22bc4:	8b 97 4c e3 18 00    	mov    0x18e34c(%rdi),%edx
ffffffff8af22bca:	b9 00 c1 00 00       	mov    $0xc100,%ecx
ffffffff8af22bcf:	01 ca                	add    %ecx,%edx
ffffffff8af22bd1:	48 03 97 28 e3 18 00 	add    0x18e328(%rdi),%rdx
ffffffff8af22bd8:	48 83 bf 20 e3 18 00 	cmpq   $0x0,0x18e320(%rdi)
ffffffff8af22bdf:	00 
ffffffff8af22be0:	74 0a                	je     ffffffff8af22bec <frame_candidate_562bc0+0x2c>
ffffffff8af22be2:	8b 02                	mov    (%rdx),%eax
ffffffff8af22be4:	83 e0 f0             	and    $0xfffffff0,%eax
ffffffff8af22be7:	83 c8 0e             	or     $0xe,%eax
ffffffff8af22bea:	eb 25                	jmp    ffffffff8af22c11 <frame_candidate_562bc0+0x51>
ffffffff8af22bec:	ed                   	in     (%dx),%eax
ffffffff8af22bed:	03 8f 4c e3 18 00    	add    0x18e34c(%rdi),%ecx
ffffffff8af22bf3:	83 e0 f0             	and    $0xfffffff0,%eax
ffffffff8af22bf6:	48 03 8f 28 e3 18 00 	add    0x18e328(%rdi),%rcx
ffffffff8af22bfd:	83 c8 0e             	or     $0xe,%eax
ffffffff8af22c00:	48 83 bf 20 e3 18 00 	cmpq   $0x0,0x18e320(%rdi)
ffffffff8af22c07:	00 
ffffffff8af22c08:	0f 84 af 00 00 00    	je     ffffffff8af22cbd <frame_candidate_562bc0+0xfd>
ffffffff8af22c0e:	48 89 ca             	mov    %rcx,%rdx
ffffffff8af22c11:	89 02                	mov    %eax,(%rdx)
ffffffff8af22c13:	ba 2c c1 00 00       	mov    $0xc12c,%edx
ffffffff8af22c18:	03 97 4c e3 18 00    	add    0x18e34c(%rdi),%edx
ffffffff8af22c1e:	48 03 97 28 e3 18 00 	add    0x18e328(%rdi),%rdx
ffffffff8af22c25:	48 83 bf 20 e3 18 00 	cmpq   $0x0,0x18e320(%rdi)
ffffffff8af22c2c:	00 
ffffffff8af22c2d:	74 08                	je     ffffffff8af22c37 <frame_candidate_562bc0+0x77>
ffffffff8af22c2f:	c7 02 10 c0 c0 7f    	movl   $0x7fc0c010,(%rdx)
ffffffff8af22c35:	eb 06                	jmp    ffffffff8af22c3d <frame_candidate_562bc0+0x7d>
ffffffff8af22c37:	b8 10 c0 c0 7f       	mov    $0x7fc0c010,%eax
ffffffff8af22c3c:	ef                   	out    %eax,(%dx)
ffffffff8af22c3d:	ba 00 c2 00 00       	mov    $0xc200,%edx
ffffffff8af22c42:	03 97 4c e3 18 00    	add    0x18e34c(%rdi),%edx
ffffffff8af22c48:	48 03 97 28 e3 18 00 	add    0x18e328(%rdi),%rdx
ffffffff8af22c4f:	48 83 bf 20 e3 18 00 	cmpq   $0x0,0x18e320(%rdi)
ffffffff8af22c56:	00 
ffffffff8af22c57:	74 08                	je     ffffffff8af22c61 <frame_candidate_562bc0+0xa1>
ffffffff8af22c59:	c7 02 48 15 00 00    	movl   $0x1548,(%rdx)
ffffffff8af22c5f:	eb 06                	jmp    ffffffff8af22c67 <frame_candidate_562bc0+0xa7>
ffffffff8af22c61:	b8 48 15 00 00       	mov    $0x1548,%eax
ffffffff8af22c66:	ef                   	out    %eax,(%dx)
ffffffff8af22c67:	ba 04 c2 00 00       	mov    $0xc204,%edx
ffffffff8af22c6c:	03 97 4c e3 18 00    	add    0x18e34c(%rdi),%edx
ffffffff8af22c72:	48 03 97 28 e3 18 00 	add    0x18e328(%rdi),%rdx
ffffffff8af22c79:	48 83 bf 20 e3 18 00 	cmpq   $0x0,0x18e320(%rdi)
ffffffff8af22c80:	00 
ffffffff8af22c81:	74 08                	je     ffffffff8af22c8b <frame_candidate_562bc0+0xcb>
ffffffff8af22c83:	c7 02 48 15 00 00    	movl   $0x1548,(%rdx)
ffffffff8af22c89:	eb 06                	jmp    ffffffff8af22c91 <frame_candidate_562bc0+0xd1>
ffffffff8af22c8b:	b8 48 15 00 00       	mov    $0x1548,%eax
ffffffff8af22c90:	ef                   	out    %eax,(%dx)
ffffffff8af22c91:	ba 08 c2 00 00       	mov    $0xc208,%edx
ffffffff8af22c96:	03 97 4c e3 18 00    	add    0x18e34c(%rdi),%edx
ffffffff8af22c9c:	48 03 97 28 e3 18 00 	add    0x18e328(%rdi),%rdx
ffffffff8af22ca3:	48 83 bf 20 e3 18 00 	cmpq   $0x0,0x18e320(%rdi)
ffffffff8af22caa:	00 
ffffffff8af22cab:	74 08                	je     ffffffff8af22cb5 <frame_candidate_562bc0+0xf5>
ffffffff8af22cad:	c7 02 48 15 00 00    	movl   $0x1548,(%rdx)
ffffffff8af22cb3:	5d                   	pop    %rbp
ffffffff8af22cb4:	c3                   	ret
ffffffff8af22cb5:	b8 48 15 00 00       	mov    $0x1548,%eax
ffffffff8af22cba:	ef                   	out    %eax,(%dx)
ffffffff8af22cbb:	5d                   	pop    %rbp
ffffffff8af22cbc:	c3                   	ret
ffffffff8af22cbd:	89 ca                	mov    %ecx,%edx
ffffffff8af22cbf:	ef                   	out    %eax,(%dx)
ffffffff8af22cc0:	e9 4e ff ff ff       	jmp    ffffffff8af22c13 <frame_candidate_562bc0+0x53>
ffffffff8af22cc5:	90                   	nop
ffffffff8af22cc6:	90                   	nop
ffffffff8af22cc7:	90                   	nop
ffffffff8af22cc8:	90                   	nop
ffffffff8af22cc9:	90                   	nop
ffffffff8af22cca:	90                   	nop
ffffffff8af22ccb:	90                   	nop
ffffffff8af22ccc:	90                   	nop
ffffffff8af22ccd:	90                   	nop
ffffffff8af22cce:	90                   	nop
ffffffff8af22ccf:	90                   	nop

ffffffff8af22cd0 <frame_candidate_562cd0>:
ffffffff8af22cd0:	55                   	push   %rbp
ffffffff8af22cd1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8af22cd4:	41 57                	push   %r15
ffffffff8af22cd6:	41 56                	push   %r14
ffffffff8af22cd8:	53                   	push   %rbx
ffffffff8af22cd9:	50                   	push   %rax
ffffffff8af22cda:	48 89 fb             	mov    %rdi,%rbx
ffffffff8af22cdd:	48 8b bf 38 dc 18 00 	mov    0x18dc38(%rdi),%rdi
ffffffff8af22ce4:	41 89 f6             	mov    %esi,%r14d
ffffffff8af22ce7:	e8 f4 0e d5 ff       	call   ffffffff8ac73be0 <handler_631_body-0x2ae500>
ffffffff8af22cec:	48 8b bb 38 dc 18 00 	mov    0x18dc38(%rbx),%rdi
ffffffff8af22cf3:	41 89 c7             	mov    %eax,%r15d
ffffffff8af22cf6:	e8 e5 0e d5 ff       	call   ffffffff8ac73be0 <handler_631_body-0x2ae500>
ffffffff8af22cfb:	45 85 ff             	test   %r15d,%r15d
ffffffff8af22cfe:	74 2d                	je     ffffffff8af22d2d <frame_candidate_562cd0+0x5d>
ffffffff8af22d00:	85 c0                	test   %eax,%eax
ffffffff8af22d02:	0f 85 d9 00 00 00    	jne    ffffffff8af22de1 <frame_candidate_562cd0+0x111>
ffffffff8af22d08:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af22d0e:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af22d15:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af22d1c:	00 
ffffffff8af22d1d:	0f 84 a1 00 00 00    	je     ffffffff8af22dc4 <frame_candidate_562cd0+0xf4>
ffffffff8af22d23:	8b 02                	mov    (%rdx),%eax
ffffffff8af22d25:	83 e0 fd             	and    $0xfffffffd,%eax
ffffffff8af22d28:	e9 b2 00 00 00       	jmp    ffffffff8af22ddf <frame_candidate_562cd0+0x10f>
ffffffff8af22d2d:	41 80 fe 02          	cmp    $0x2,%r14b
ffffffff8af22d31:	74 2f                	je     ffffffff8af22d62 <frame_candidate_562cd0+0x92>
ffffffff8af22d33:	41 0f b6 ce          	movzbl %r14b,%ecx
ffffffff8af22d37:	83 f9 01             	cmp    $0x1,%ecx
ffffffff8af22d3a:	75 4c                	jne    ffffffff8af22d88 <frame_candidate_562cd0+0xb8>
ffffffff8af22d3c:	85 c0                	test   %eax,%eax
ffffffff8af22d3e:	75 70                	jne    ffffffff8af22db0 <frame_candidate_562cd0+0xe0>
ffffffff8af22d40:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af22d46:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af22d4d:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af22d54:	00 
ffffffff8af22d55:	0f 84 ec 00 00 00    	je     ffffffff8af22e47 <frame_candidate_562cd0+0x177>
ffffffff8af22d5b:	8b 02                	mov    (%rdx),%eax
ffffffff8af22d5d:	83 e0 fd             	and    $0xfffffffd,%eax
ffffffff8af22d60:	eb 4c                	jmp    ffffffff8af22dae <frame_candidate_562cd0+0xde>
ffffffff8af22d62:	85 c0                	test   %eax,%eax
ffffffff8af22d64:	75 4a                	jne    ffffffff8af22db0 <frame_candidate_562cd0+0xe0>
ffffffff8af22d66:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af22d6c:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af22d73:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af22d7a:	00 
ffffffff8af22d7b:	0f 84 eb 00 00 00    	je     ffffffff8af22e6c <frame_candidate_562cd0+0x19c>
ffffffff8af22d81:	b8 ff ff fd ff       	mov    $0xfffdffff,%eax
ffffffff8af22d86:	eb 24                	jmp    ffffffff8af22dac <frame_candidate_562cd0+0xdc>
ffffffff8af22d88:	85 c0                	test   %eax,%eax
ffffffff8af22d8a:	75 24                	jne    ffffffff8af22db0 <frame_candidate_562cd0+0xe0>
ffffffff8af22d8c:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af22d92:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af22d99:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af22da0:	00 
ffffffff8af22da1:	0f 84 ec 00 00 00    	je     ffffffff8af22e93 <frame_candidate_562cd0+0x1c3>
ffffffff8af22da7:	b8 ff ff ff fd       	mov    $0xfdffffff,%eax
ffffffff8af22dac:	23 02                	and    (%rdx),%eax
ffffffff8af22dae:	89 02                	mov    %eax,(%rdx)
ffffffff8af22db0:	bf 20 4e 00 00       	mov    $0x4e20,%edi
ffffffff8af22db5:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8af22db9:	5b                   	pop    %rbx
ffffffff8af22dba:	41 5e                	pop    %r14
ffffffff8af22dbc:	41 5f                	pop    %r15
ffffffff8af22dbe:	5d                   	pop    %rbp
ffffffff8af22dbf:	e9 1c b4 f0 ff       	jmp    ffffffff8ae2e1e0 <handler_631_body-0xf3f00>
ffffffff8af22dc4:	ed                   	in     (%dx),%eax
ffffffff8af22dc5:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af22dcb:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af22dd2:	83 e0 fd             	and    $0xfffffffd,%eax
ffffffff8af22dd5:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af22ddc:	00 
ffffffff8af22ddd:	74 62                	je     ffffffff8af22e41 <frame_candidate_562cd0+0x171>
ffffffff8af22ddf:	89 02                	mov    %eax,(%rdx)
ffffffff8af22de1:	bf 10 27 00 00       	mov    $0x2710,%edi
ffffffff8af22de6:	e8 f5 b3 f0 ff       	call   ffffffff8ae2e1e0 <handler_631_body-0xf3f00>
ffffffff8af22deb:	48 8b bb 38 dc 18 00 	mov    0x18dc38(%rbx),%rdi
ffffffff8af22df2:	e8 e9 0d d5 ff       	call   ffffffff8ac73be0 <handler_631_body-0x2ae500>
ffffffff8af22df7:	85 c0                	test   %eax,%eax
ffffffff8af22df9:	75 3b                	jne    ffffffff8af22e36 <frame_candidate_562cd0+0x166>
ffffffff8af22dfb:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af22e01:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af22e08:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af22e0f:	00 
ffffffff8af22e10:	74 07                	je     ffffffff8af22e19 <frame_candidate_562cd0+0x149>
ffffffff8af22e12:	8b 02                	mov    (%rdx),%eax
ffffffff8af22e14:	83 c8 04             	or     $0x4,%eax
ffffffff8af22e17:	eb 1b                	jmp    ffffffff8af22e34 <frame_candidate_562cd0+0x164>
ffffffff8af22e19:	ed                   	in     (%dx),%eax
ffffffff8af22e1a:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af22e20:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af22e27:	83 c8 04             	or     $0x4,%eax
ffffffff8af22e2a:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af22e31:	00 
ffffffff8af22e32:	74 10                	je     ffffffff8af22e44 <frame_candidate_562cd0+0x174>
ffffffff8af22e34:	89 02                	mov    %eax,(%rdx)
ffffffff8af22e36:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8af22e3a:	5b                   	pop    %rbx
ffffffff8af22e3b:	41 5e                	pop    %r14
ffffffff8af22e3d:	41 5f                	pop    %r15
ffffffff8af22e3f:	5d                   	pop    %rbp
ffffffff8af22e40:	c3                   	ret
ffffffff8af22e41:	ef                   	out    %eax,(%dx)
ffffffff8af22e42:	eb 9d                	jmp    ffffffff8af22de1 <frame_candidate_562cd0+0x111>
ffffffff8af22e44:	ef                   	out    %eax,(%dx)
ffffffff8af22e45:	eb ef                	jmp    ffffffff8af22e36 <frame_candidate_562cd0+0x166>
ffffffff8af22e47:	ed                   	in     (%dx),%eax
ffffffff8af22e48:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af22e4e:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af22e55:	83 e0 fd             	and    $0xfffffffd,%eax
ffffffff8af22e58:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af22e5f:	00 
ffffffff8af22e60:	0f 85 48 ff ff ff    	jne    ffffffff8af22dae <frame_candidate_562cd0+0xde>
ffffffff8af22e66:	ef                   	out    %eax,(%dx)
ffffffff8af22e67:	e9 44 ff ff ff       	jmp    ffffffff8af22db0 <frame_candidate_562cd0+0xe0>
ffffffff8af22e6c:	ed                   	in     (%dx),%eax
ffffffff8af22e6d:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af22e73:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af22e7a:	25 ff ff fd ff       	and    $0xfffdffff,%eax
ffffffff8af22e7f:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af22e86:	00 
ffffffff8af22e87:	0f 85 21 ff ff ff    	jne    ffffffff8af22dae <frame_candidate_562cd0+0xde>
ffffffff8af22e8d:	ef                   	out    %eax,(%dx)
ffffffff8af22e8e:	e9 1d ff ff ff       	jmp    ffffffff8af22db0 <frame_candidate_562cd0+0xe0>
ffffffff8af22e93:	ed                   	in     (%dx),%eax
ffffffff8af22e94:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af22e9a:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af22ea1:	25 ff ff ff fd       	and    $0xfdffffff,%eax
ffffffff8af22ea6:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af22ead:	00 
ffffffff8af22eae:	0f 85 fa fe ff ff    	jne    ffffffff8af22dae <frame_candidate_562cd0+0xde>
ffffffff8af22eb4:	ef                   	out    %eax,(%dx)
ffffffff8af22eb5:	e9 f6 fe ff ff       	jmp    ffffffff8af22db0 <frame_candidate_562cd0+0xe0>
ffffffff8af22eba:	90                   	nop
ffffffff8af22ebb:	90                   	nop
ffffffff8af22ebc:	90                   	nop
ffffffff8af22ebd:	90                   	nop
ffffffff8af22ebe:	90                   	nop
ffffffff8af22ebf:	90                   	nop

ffffffff8af22ec0 <frame_candidate_562ec0>:
ffffffff8af22ec0:	55                   	push   %rbp
ffffffff8af22ec1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8af22ec4:	41 57                	push   %r15
ffffffff8af22ec6:	41 56                	push   %r14
ffffffff8af22ec8:	53                   	push   %rbx
ffffffff8af22ec9:	50                   	push   %rax
ffffffff8af22eca:	48 89 fb             	mov    %rdi,%rbx
ffffffff8af22ecd:	48 8b bf 38 dc 18 00 	mov    0x18dc38(%rdi),%rdi
ffffffff8af22ed4:	41 89 f6             	mov    %esi,%r14d
ffffffff8af22ed7:	e8 04 0d d5 ff       	call   ffffffff8ac73be0 <handler_631_body-0x2ae500>
ffffffff8af22edc:	48 8b bb 38 dc 18 00 	mov    0x18dc38(%rbx),%rdi
ffffffff8af22ee3:	41 89 c7             	mov    %eax,%r15d
ffffffff8af22ee6:	e8 f5 0c d5 ff       	call   ffffffff8ac73be0 <handler_631_body-0x2ae500>
ffffffff8af22eeb:	45 85 ff             	test   %r15d,%r15d
ffffffff8af22eee:	74 2d                	je     ffffffff8af22f1d <frame_candidate_562ec0+0x5d>
ffffffff8af22ef0:	85 c0                	test   %eax,%eax
ffffffff8af22ef2:	0f 85 dc 00 00 00    	jne    ffffffff8af22fd4 <frame_candidate_562ec0+0x114>
ffffffff8af22ef8:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af22efe:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af22f05:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af22f0c:	00 
ffffffff8af22f0d:	0f 84 a4 00 00 00    	je     ffffffff8af22fb7 <frame_candidate_562ec0+0xf7>
ffffffff8af22f13:	8b 02                	mov    (%rdx),%eax
ffffffff8af22f15:	83 c8 02             	or     $0x2,%eax
ffffffff8af22f18:	e9 b5 00 00 00       	jmp    ffffffff8af22fd2 <frame_candidate_562ec0+0x112>
ffffffff8af22f1d:	41 80 fe 02          	cmp    $0x2,%r14b
ffffffff8af22f21:	74 36                	je     ffffffff8af22f59 <frame_candidate_562ec0+0x99>
ffffffff8af22f23:	41 0f b6 ce          	movzbl %r14b,%ecx
ffffffff8af22f27:	83 f9 01             	cmp    $0x1,%ecx
ffffffff8af22f2a:	75 5c                	jne    ffffffff8af22f88 <frame_candidate_562ec0+0xc8>
ffffffff8af22f2c:	85 c0                	test   %eax,%eax
ffffffff8af22f2e:	0f 85 1e 01 00 00    	jne    ffffffff8af23052 <frame_candidate_562ec0+0x192>
ffffffff8af22f34:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af22f3a:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af22f41:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af22f48:	00 
ffffffff8af22f49:	0f 84 e2 00 00 00    	je     ffffffff8af23031 <frame_candidate_562ec0+0x171>
ffffffff8af22f4f:	8b 02                	mov    (%rdx),%eax
ffffffff8af22f51:	83 c8 02             	or     $0x2,%eax
ffffffff8af22f54:	e9 f7 00 00 00       	jmp    ffffffff8af23050 <frame_candidate_562ec0+0x190>
ffffffff8af22f59:	85 c0                	test   %eax,%eax
ffffffff8af22f5b:	0f 85 64 01 00 00    	jne    ffffffff8af230c5 <frame_candidate_562ec0+0x205>
ffffffff8af22f61:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af22f67:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af22f6e:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af22f75:	00 
ffffffff8af22f76:	0f 84 26 01 00 00    	je     ffffffff8af230a2 <frame_candidate_562ec0+0x1e2>
ffffffff8af22f7c:	b8 00 00 02 00       	mov    $0x20000,%eax
ffffffff8af22f81:	0b 02                	or     (%rdx),%eax
ffffffff8af22f83:	e9 3b 01 00 00       	jmp    ffffffff8af230c3 <frame_candidate_562ec0+0x203>
ffffffff8af22f88:	85 c0                	test   %eax,%eax
ffffffff8af22f8a:	0f 85 a6 01 00 00    	jne    ffffffff8af23136 <frame_candidate_562ec0+0x276>
ffffffff8af22f90:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af22f96:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af22f9d:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af22fa4:	00 
ffffffff8af22fa5:	0f 84 6c 01 00 00    	je     ffffffff8af23117 <frame_candidate_562ec0+0x257>
ffffffff8af22fab:	b8 00 00 00 02       	mov    $0x2000000,%eax
ffffffff8af22fb0:	0b 02                	or     (%rdx),%eax
ffffffff8af22fb2:	e9 7d 01 00 00       	jmp    ffffffff8af23134 <frame_candidate_562ec0+0x274>
ffffffff8af22fb7:	ed                   	in     (%dx),%eax
ffffffff8af22fb8:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af22fbe:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af22fc5:	83 c8 02             	or     $0x2,%eax
ffffffff8af22fc8:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af22fcf:	00 
ffffffff8af22fd0:	74 5c                	je     ffffffff8af2302e <frame_candidate_562ec0+0x16e>
ffffffff8af22fd2:	89 02                	mov    %eax,(%rdx)
ffffffff8af22fd4:	48 8b bb 38 dc 18 00 	mov    0x18dc38(%rbx),%rdi
ffffffff8af22fdb:	e8 00 0c d5 ff       	call   ffffffff8ac73be0 <handler_631_body-0x2ae500>
ffffffff8af22fe0:	85 c0                	test   %eax,%eax
ffffffff8af22fe2:	0f 85 7e 01 00 00    	jne    ffffffff8af23166 <frame_candidate_562ec0+0x2a6>
ffffffff8af22fe8:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af22fee:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af22ff5:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af22ffc:	00 
ffffffff8af22ffd:	74 0a                	je     ffffffff8af23009 <frame_candidate_562ec0+0x149>
ffffffff8af22fff:	8b 02                	mov    (%rdx),%eax
ffffffff8af23001:	83 e0 fb             	and    $0xfffffffb,%eax
ffffffff8af23004:	e9 5b 01 00 00       	jmp    ffffffff8af23164 <frame_candidate_562ec0+0x2a4>
ffffffff8af23009:	ed                   	in     (%dx),%eax
ffffffff8af2300a:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af23010:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af23017:	83 e0 fb             	and    $0xfffffffb,%eax
ffffffff8af2301a:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af23021:	00 
ffffffff8af23022:	0f 85 3c 01 00 00    	jne    ffffffff8af23164 <frame_candidate_562ec0+0x2a4>
ffffffff8af23028:	ef                   	out    %eax,(%dx)
ffffffff8af23029:	e9 38 01 00 00       	jmp    ffffffff8af23166 <frame_candidate_562ec0+0x2a6>
ffffffff8af2302e:	ef                   	out    %eax,(%dx)
ffffffff8af2302f:	eb a3                	jmp    ffffffff8af22fd4 <frame_candidate_562ec0+0x114>
ffffffff8af23031:	ed                   	in     (%dx),%eax
ffffffff8af23032:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af23038:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af2303f:	83 c8 02             	or     $0x2,%eax
ffffffff8af23042:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af23049:	00 
ffffffff8af2304a:	0f 84 41 01 00 00    	je     ffffffff8af23191 <frame_candidate_562ec0+0x2d1>
ffffffff8af23050:	89 02                	mov    %eax,(%rdx)
ffffffff8af23052:	48 8b bb 38 dc 18 00 	mov    0x18dc38(%rbx),%rdi
ffffffff8af23059:	e8 82 0b d5 ff       	call   ffffffff8ac73be0 <handler_631_body-0x2ae500>
ffffffff8af2305e:	85 c0                	test   %eax,%eax
ffffffff8af23060:	0f 85 00 01 00 00    	jne    ffffffff8af23166 <frame_candidate_562ec0+0x2a6>
ffffffff8af23066:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af2306c:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af23073:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af2307a:	00 
ffffffff8af2307b:	75 82                	jne    ffffffff8af22fff <frame_candidate_562ec0+0x13f>
ffffffff8af2307d:	ed                   	in     (%dx),%eax
ffffffff8af2307e:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af23084:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af2308b:	83 e0 fb             	and    $0xfffffffb,%eax
ffffffff8af2308e:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af23095:	00 
ffffffff8af23096:	0f 85 c8 00 00 00    	jne    ffffffff8af23164 <frame_candidate_562ec0+0x2a4>
ffffffff8af2309c:	ef                   	out    %eax,(%dx)
ffffffff8af2309d:	e9 c4 00 00 00       	jmp    ffffffff8af23166 <frame_candidate_562ec0+0x2a6>
ffffffff8af230a2:	ed                   	in     (%dx),%eax
ffffffff8af230a3:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af230a9:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af230b0:	0d 00 00 02 00       	or     $0x20000,%eax
ffffffff8af230b5:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af230bc:	00 
ffffffff8af230bd:	0f 84 d4 00 00 00    	je     ffffffff8af23197 <frame_candidate_562ec0+0x2d7>
ffffffff8af230c3:	89 02                	mov    %eax,(%rdx)
ffffffff8af230c5:	48 8b bb 38 dc 18 00 	mov    0x18dc38(%rbx),%rdi
ffffffff8af230cc:	e8 0f 0b d5 ff       	call   ffffffff8ac73be0 <handler_631_body-0x2ae500>
ffffffff8af230d1:	85 c0                	test   %eax,%eax
ffffffff8af230d3:	0f 85 8d 00 00 00    	jne    ffffffff8af23166 <frame_candidate_562ec0+0x2a6>
ffffffff8af230d9:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af230df:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af230e6:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af230ed:	00 
ffffffff8af230ee:	74 07                	je     ffffffff8af230f7 <frame_candidate_562ec0+0x237>
ffffffff8af230f0:	b8 ff ff fb ff       	mov    $0xfffbffff,%eax
ffffffff8af230f5:	eb 6b                	jmp    ffffffff8af23162 <frame_candidate_562ec0+0x2a2>
ffffffff8af230f7:	ed                   	in     (%dx),%eax
ffffffff8af230f8:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af230fe:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af23105:	25 ff ff fb ff       	and    $0xfffbffff,%eax
ffffffff8af2310a:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af23111:	00 
ffffffff8af23112:	75 50                	jne    ffffffff8af23164 <frame_candidate_562ec0+0x2a4>
ffffffff8af23114:	ef                   	out    %eax,(%dx)
ffffffff8af23115:	eb 4f                	jmp    ffffffff8af23166 <frame_candidate_562ec0+0x2a6>
ffffffff8af23117:	ed                   	in     (%dx),%eax
ffffffff8af23118:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af2311e:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af23125:	0d 00 00 00 02       	or     $0x2000000,%eax
ffffffff8af2312a:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af23131:	00 
ffffffff8af23132:	74 69                	je     ffffffff8af2319d <frame_candidate_562ec0+0x2dd>
ffffffff8af23134:	89 02                	mov    %eax,(%rdx)
ffffffff8af23136:	48 8b bb 38 dc 18 00 	mov    0x18dc38(%rbx),%rdi
ffffffff8af2313d:	e8 9e 0a d5 ff       	call   ffffffff8ac73be0 <handler_631_body-0x2ae500>
ffffffff8af23142:	85 c0                	test   %eax,%eax
ffffffff8af23144:	75 20                	jne    ffffffff8af23166 <frame_candidate_562ec0+0x2a6>
ffffffff8af23146:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af2314c:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af23153:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af2315a:	00 
ffffffff8af2315b:	74 14                	je     ffffffff8af23171 <frame_candidate_562ec0+0x2b1>
ffffffff8af2315d:	b8 ff ff ff fb       	mov    $0xfbffffff,%eax
ffffffff8af23162:	23 02                	and    (%rdx),%eax
ffffffff8af23164:	89 02                	mov    %eax,(%rdx)
ffffffff8af23166:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8af2316a:	5b                   	pop    %rbx
ffffffff8af2316b:	41 5e                	pop    %r14
ffffffff8af2316d:	41 5f                	pop    %r15
ffffffff8af2316f:	5d                   	pop    %rbp
ffffffff8af23170:	c3                   	ret
ffffffff8af23171:	ed                   	in     (%dx),%eax
ffffffff8af23172:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af23178:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af2317f:	25 ff ff ff fb       	and    $0xfbffffff,%eax
ffffffff8af23184:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af2318b:	00 
ffffffff8af2318c:	75 d6                	jne    ffffffff8af23164 <frame_candidate_562ec0+0x2a4>
ffffffff8af2318e:	ef                   	out    %eax,(%dx)
ffffffff8af2318f:	eb d5                	jmp    ffffffff8af23166 <frame_candidate_562ec0+0x2a6>
ffffffff8af23191:	ef                   	out    %eax,(%dx)
ffffffff8af23192:	e9 bb fe ff ff       	jmp    ffffffff8af23052 <frame_candidate_562ec0+0x192>
ffffffff8af23197:	ef                   	out    %eax,(%dx)
ffffffff8af23198:	e9 28 ff ff ff       	jmp    ffffffff8af230c5 <frame_candidate_562ec0+0x205>
ffffffff8af2319d:	ef                   	out    %eax,(%dx)
ffffffff8af2319e:	eb 96                	jmp    ffffffff8af23136 <frame_candidate_562ec0+0x276>

ffffffff8af231a0 <frame_candidate_5631a0>:
ffffffff8af231a0:	55                   	push   %rbp
ffffffff8af231a1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8af231a4:	53                   	push   %rbx
ffffffff8af231a5:	50                   	push   %rax
ffffffff8af231a6:	48 89 fb             	mov    %rdi,%rbx
ffffffff8af231a9:	48 8b bf 38 dc 18 00 	mov    0x18dc38(%rdi),%rdi
ffffffff8af231b0:	48 8d 35 3d 7d e3 00 	lea    0xe37d3d(%rip),%rsi        # ffffffff8bd5aef4 <frame_candidate_563fd0+0xe36f24>
ffffffff8af231b7:	31 c0                	xor    %eax,%eax
ffffffff8af231b9:	e8 b2 0a d5 ff       	call   ffffffff8ac73c70 <handler_631_body-0x2ae470>
ffffffff8af231be:	c7 83 60 e3 18 00 00 	movl   $0x100000,0x18e360(%rbx)
ffffffff8af231c5:	00 10 00 
ffffffff8af231c8:	48 8b bb 38 dc 18 00 	mov    0x18dc38(%rbx),%rdi
ffffffff8af231cf:	e8 0c 0a d5 ff       	call   ffffffff8ac73be0 <handler_631_body-0x2ae500>
ffffffff8af231d4:	85 c0                	test   %eax,%eax
ffffffff8af231d6:	75 19                	jne    ffffffff8af231f1 <frame_candidate_5631a0+0x51>
ffffffff8af231d8:	bf 24 00 00 00       	mov    $0x24,%edi
ffffffff8af231dd:	e8 9e 66 d5 ff       	call   ffffffff8ac79880 <handler_631_body-0x2a8860>
ffffffff8af231e2:	83 c8 02             	or     $0x2,%eax
ffffffff8af231e5:	bf 24 00 00 00       	mov    $0x24,%edi
ffffffff8af231ea:	89 c6                	mov    %eax,%esi
ffffffff8af231ec:	e8 bf 66 d5 ff       	call   ffffffff8ac798b0 <handler_631_body-0x2a8830>
ffffffff8af231f1:	48 8b bb 38 dc 18 00 	mov    0x18dc38(%rbx),%rdi
ffffffff8af231f8:	e8 e3 09 d5 ff       	call   ffffffff8ac73be0 <handler_631_body-0x2ae500>
ffffffff8af231fd:	85 c0                	test   %eax,%eax
ffffffff8af231ff:	75 19                	jne    ffffffff8af2321a <frame_candidate_5631a0+0x7a>
ffffffff8af23201:	bf 24 00 00 00       	mov    $0x24,%edi
ffffffff8af23206:	e8 75 66 d5 ff       	call   ffffffff8ac79880 <handler_631_body-0x2a8860>
ffffffff8af2320b:	83 c8 01             	or     $0x1,%eax
ffffffff8af2320e:	bf 24 00 00 00       	mov    $0x24,%edi
ffffffff8af23213:	89 c6                	mov    %eax,%esi
ffffffff8af23215:	e8 96 66 d5 ff       	call   ffffffff8ac798b0 <handler_631_body-0x2a8830>
ffffffff8af2321a:	48 8b bb 38 dc 18 00 	mov    0x18dc38(%rbx),%rdi
ffffffff8af23221:	e8 ba 09 d5 ff       	call   ffffffff8ac73be0 <handler_631_body-0x2ae500>
ffffffff8af23226:	85 c0                	test   %eax,%eax
ffffffff8af23228:	75 19                	jne    ffffffff8af23243 <frame_candidate_5631a0+0xa3>
ffffffff8af2322a:	bf 24 00 00 00       	mov    $0x24,%edi
ffffffff8af2322f:	e8 4c 66 d5 ff       	call   ffffffff8ac79880 <handler_631_body-0x2a8860>
ffffffff8af23234:	83 e0 fd             	and    $0xfffffffd,%eax
ffffffff8af23237:	bf 24 00 00 00       	mov    $0x24,%edi
ffffffff8af2323c:	89 c6                	mov    %eax,%esi
ffffffff8af2323e:	e8 6d 66 d5 ff       	call   ffffffff8ac798b0 <handler_631_body-0x2a8830>
ffffffff8af23243:	48 8b bb 38 dc 18 00 	mov    0x18dc38(%rbx),%rdi
ffffffff8af2324a:	e8 91 09 d5 ff       	call   ffffffff8ac73be0 <handler_631_body-0x2ae500>
ffffffff8af2324f:	85 c0                	test   %eax,%eax
ffffffff8af23251:	75 24                	jne    ffffffff8af23277 <frame_candidate_5631a0+0xd7>
ffffffff8af23253:	48 89 df             	mov    %rbx,%rdi
ffffffff8af23256:	31 f6                	xor    %esi,%esi
ffffffff8af23258:	e8 13 01 00 00       	call   ffffffff8af23370 <frame_candidate_563370>
ffffffff8af2325d:	48 89 df             	mov    %rbx,%rdi
ffffffff8af23260:	be 01 00 00 00       	mov    $0x1,%esi
ffffffff8af23265:	e8 06 01 00 00       	call   ffffffff8af23370 <frame_candidate_563370>
ffffffff8af2326a:	48 89 df             	mov    %rbx,%rdi
ffffffff8af2326d:	be 02 00 00 00       	mov    $0x2,%esi
ffffffff8af23272:	e8 f9 00 00 00       	call   ffffffff8af23370 <frame_candidate_563370>
ffffffff8af23277:	48 8b bb 38 dc 18 00 	mov    0x18dc38(%rbx),%rdi
ffffffff8af2327e:	e8 5d 09 d5 ff       	call   ffffffff8ac73be0 <handler_631_body-0x2ae500>
ffffffff8af23283:	85 c0                	test   %eax,%eax
ffffffff8af23285:	75 19                	jne    ffffffff8af232a0 <frame_candidate_5631a0+0x100>
ffffffff8af23287:	bf 24 00 00 00       	mov    $0x24,%edi
ffffffff8af2328c:	e8 ef 65 d5 ff       	call   ffffffff8ac79880 <handler_631_body-0x2a8860>
ffffffff8af23291:	83 e0 fe             	and    $0xfffffffe,%eax
ffffffff8af23294:	bf 24 00 00 00       	mov    $0x24,%edi
ffffffff8af23299:	89 c6                	mov    %eax,%esi
ffffffff8af2329b:	e8 10 66 d5 ff       	call   ffffffff8ac798b0 <handler_631_body-0x2a8830>
ffffffff8af232a0:	bf d0 07 00 00       	mov    $0x7d0,%edi
ffffffff8af232a5:	e8 36 af f0 ff       	call   ffffffff8ae2e1e0 <handler_631_body-0xf3f00>
ffffffff8af232aa:	48 8b bb 38 dc 18 00 	mov    0x18dc38(%rbx),%rdi
ffffffff8af232b1:	e8 2a 09 d5 ff       	call   ffffffff8ac73be0 <handler_631_body-0x2ae500>
ffffffff8af232b6:	85 c0                	test   %eax,%eax
ffffffff8af232b8:	75 24                	jne    ffffffff8af232de <frame_candidate_5631a0+0x13e>
ffffffff8af232ba:	48 89 df             	mov    %rbx,%rdi
ffffffff8af232bd:	31 f6                	xor    %esi,%esi
ffffffff8af232bf:	e8 1c 06 00 00       	call   ffffffff8af238e0 <frame_candidate_5638e0>
ffffffff8af232c4:	48 89 df             	mov    %rbx,%rdi
ffffffff8af232c7:	be 01 00 00 00       	mov    $0x1,%esi
ffffffff8af232cc:	e8 0f 06 00 00       	call   ffffffff8af238e0 <frame_candidate_5638e0>
ffffffff8af232d1:	48 89 df             	mov    %rbx,%rdi
ffffffff8af232d4:	be 02 00 00 00       	mov    $0x2,%esi
ffffffff8af232d9:	e8 02 06 00 00       	call   ffffffff8af238e0 <frame_candidate_5638e0>
ffffffff8af232de:	48 8b bb 38 dc 18 00 	mov    0x18dc38(%rbx),%rdi
ffffffff8af232e5:	e8 f6 08 d5 ff       	call   ffffffff8ac73be0 <handler_631_body-0x2ae500>
ffffffff8af232ea:	85 c0                	test   %eax,%eax
ffffffff8af232ec:	75 27                	jne    ffffffff8af23315 <frame_candidate_5631a0+0x175>
ffffffff8af232ee:	48 89 df             	mov    %rbx,%rdi
ffffffff8af232f1:	be 01 00 00 00       	mov    $0x1,%esi
ffffffff8af232f6:	e8 a5 09 00 00       	call   ffffffff8af23ca0 <frame_candidate_563ca0>
ffffffff8af232fb:	48 89 df             	mov    %rbx,%rdi
ffffffff8af232fe:	be 02 00 00 00       	mov    $0x2,%esi
ffffffff8af23303:	e8 98 09 00 00       	call   ffffffff8af23ca0 <frame_candidate_563ca0>
ffffffff8af23308:	48 89 df             	mov    %rbx,%rdi
ffffffff8af2330b:	be 03 00 00 00       	mov    $0x3,%esi
ffffffff8af23310:	e8 8b 09 00 00       	call   ffffffff8af23ca0 <frame_candidate_563ca0>
ffffffff8af23315:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af2331b:	83 c2 04             	add    $0x4,%edx
ffffffff8af2331e:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af23325:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af2332c:	00 
ffffffff8af2332d:	74 07                	je     ffffffff8af23336 <frame_candidate_5631a0+0x196>
ffffffff8af2332f:	8b 02                	mov    (%rdx),%eax
ffffffff8af23331:	83 e0 fe             	and    $0xfffffffe,%eax
ffffffff8af23334:	eb 1e                	jmp    ffffffff8af23354 <frame_candidate_5631a0+0x1b4>
ffffffff8af23336:	ed                   	in     (%dx),%eax
ffffffff8af23337:	8b 93 60 e3 18 00    	mov    0x18e360(%rbx),%edx
ffffffff8af2333d:	83 e0 fe             	and    $0xfffffffe,%eax
ffffffff8af23340:	83 c2 04             	add    $0x4,%edx
ffffffff8af23343:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af2334a:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af23351:	00 
ffffffff8af23352:	74 13                	je     ffffffff8af23367 <frame_candidate_5631a0+0x1c7>
ffffffff8af23354:	89 02                	mov    %eax,(%rdx)
ffffffff8af23356:	48 89 df             	mov    %rbx,%rdi
ffffffff8af23359:	e8 62 f8 ff ff       	call   ffffffff8af22bc0 <frame_candidate_562bc0>
ffffffff8af2335e:	31 c0                	xor    %eax,%eax
ffffffff8af23360:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8af23364:	5b                   	pop    %rbx
ffffffff8af23365:	5d                   	pop    %rbp
ffffffff8af23366:	c3                   	ret
ffffffff8af23367:	ef                   	out    %eax,(%dx)
ffffffff8af23368:	eb ec                	jmp    ffffffff8af23356 <frame_candidate_5631a0+0x1b6>
ffffffff8af2336a:	90                   	nop
ffffffff8af2336b:	90                   	nop
ffffffff8af2336c:	90                   	nop
ffffffff8af2336d:	90                   	nop
ffffffff8af2336e:	90                   	nop
ffffffff8af2336f:	90                   	nop

ffffffff8af23370 <frame_candidate_563370>:
ffffffff8af23370:	55                   	push   %rbp
ffffffff8af23371:	48 89 e5             	mov    %rsp,%rbp
ffffffff8af23374:	41 57                	push   %r15
ffffffff8af23376:	41 56                	push   %r14
ffffffff8af23378:	41 55                	push   %r13
ffffffff8af2337a:	41 54                	push   %r12
ffffffff8af2337c:	53                   	push   %rbx
ffffffff8af2337d:	48 83 ec 18          	sub    $0x18,%rsp
ffffffff8af23381:	4c 8d 2d 88 8f 3b 03 	lea    0x33b8f88(%rip),%r13        # ffffffff8e2dc310 <frame_candidate_563fd0+0x33b8340>
ffffffff8af23388:	48 89 fb             	mov    %rdi,%rbx
ffffffff8af2338b:	41 89 f6             	mov    %esi,%r14d
ffffffff8af2338e:	49 8b 45 00          	mov    0x0(%r13),%rax
ffffffff8af23392:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8af23396:	48 8b bf 38 dc 18 00 	mov    0x18dc38(%rdi),%rdi
ffffffff8af2339d:	e8 3e 08 d5 ff       	call   ffffffff8ac73be0 <handler_631_body-0x2ae500>
ffffffff8af233a2:	b9 00 00 12 00       	mov    $0x120000,%ecx
ffffffff8af233a7:	85 c0                	test   %eax,%eax
ffffffff8af233a9:	75 1b                	jne    ffffffff8af233c6 <frame_candidate_563370+0x56>
ffffffff8af233ab:	31 c0                	xor    %eax,%eax
ffffffff8af233ad:	41 83 fe 01          	cmp    $0x1,%r14d
ffffffff8af233b1:	b9 00 80 12 00       	mov    $0x128000,%ecx
ffffffff8af233b6:	0f 94 c0             	sete   %al
ffffffff8af233b9:	83 c8 48             	or     $0x48,%eax
ffffffff8af233bc:	c1 e0 0e             	shl    $0xe,%eax
ffffffff8af233bf:	41 83 fe 02          	cmp    $0x2,%r14d
ffffffff8af233c3:	0f 45 c8             	cmovne %eax,%ecx
ffffffff8af233c6:	bf 6c 00 00 00       	mov    $0x6c,%edi
ffffffff8af233cb:	89 8b 64 e3 18 00    	mov    %ecx,0x18e364(%rbx)
ffffffff8af233d1:	e8 0a 65 d5 ff       	call   ffffffff8ac798e0 <handler_631_body-0x2a8800>
ffffffff8af233d6:	41 89 c7             	mov    %eax,%r15d
ffffffff8af233d9:	bf 6c 00 00 00       	mov    $0x6c,%edi
ffffffff8af233de:	41 c1 ef 11          	shr    $0x11,%r15d
ffffffff8af233e2:	e8 f9 64 d5 ff       	call   ffffffff8ac798e0 <handler_631_body-0x2a8800>
ffffffff8af233e7:	41 89 c4             	mov    %eax,%r12d
ffffffff8af233ea:	41 c1 ec 19          	shr    $0x19,%r12d
ffffffff8af233ee:	45 21 fc             	and    %r15d,%r12d
ffffffff8af233f1:	4c 8b bb 38 dc 18 00 	mov    0x18dc38(%rbx),%r15
ffffffff8af233f8:	4c 89 ff             	mov    %r15,%rdi
ffffffff8af233fb:	e8 e0 07 d5 ff       	call   ffffffff8ac73be0 <handler_631_body-0x2ae500>
ffffffff8af23400:	41 f6 c4 01          	test   $0x1,%r12b
ffffffff8af23404:	74 32                	je     ffffffff8af23438 <frame_candidate_563370+0xc8>
ffffffff8af23406:	b9 98 00 00 00       	mov    $0x98,%ecx
ffffffff8af2340b:	85 c0                	test   %eax,%eax
ffffffff8af2340d:	75 41                	jne    ffffffff8af23450 <frame_candidate_563370+0xe0>
ffffffff8af2340f:	bf 44 00 00 00       	mov    $0x44,%edi
ffffffff8af23414:	e8 c7 64 d5 ff       	call   ffffffff8ac798e0 <handler_631_body-0x2a8800>
ffffffff8af23419:	41 83 fe 01          	cmp    $0x1,%r14d
ffffffff8af2341d:	0f 84 c8 03 00 00    	je     ffffffff8af237eb <frame_candidate_563370+0x47b>
ffffffff8af23423:	45 85 f6             	test   %r14d,%r14d
ffffffff8af23426:	0f 85 ce 03 00 00    	jne    ffffffff8af237fa <frame_candidate_563370+0x48a>
ffffffff8af2342c:	b9 10 05 00 00       	mov    $0x510,%ecx
ffffffff8af23431:	c4 e2 70 f7 c8       	bextr  %ecx,%eax,%ecx
ffffffff8af23436:	eb 18                	jmp    ffffffff8af23450 <frame_candidate_563370+0xe0>
ffffffff8af23438:	89 c2                	mov    %eax,%edx
ffffffff8af2343a:	48 8d 35 86 e1 e0 00 	lea    0xe0e186(%rip),%rsi        # ffffffff8bd315c7 <frame_candidate_563fd0+0xe0d5f7>
ffffffff8af23441:	4c 89 ff             	mov    %r15,%rdi
ffffffff8af23444:	31 c0                	xor    %eax,%eax
ffffffff8af23446:	e8 25 08 d5 ff       	call   ffffffff8ac73c70 <handler_631_body-0x2ae470>
ffffffff8af2344b:	b9 98 00 00 00       	mov    $0x98,%ecx
ffffffff8af23450:	8b 93 64 e3 18 00    	mov    0x18e364(%rbx),%edx
ffffffff8af23456:	be 00 08 00 00       	mov    $0x800,%esi
ffffffff8af2345b:	01 f2                	add    %esi,%edx
ffffffff8af2345d:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af23464:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af2346b:	00 
ffffffff8af2346c:	74 04                	je     ffffffff8af23472 <frame_candidate_563370+0x102>
ffffffff8af2346e:	8b 02                	mov    (%rdx),%eax
ffffffff8af23470:	eb 1f                	jmp    ffffffff8af23491 <frame_candidate_563370+0x121>
ffffffff8af23472:	ed                   	in     (%dx),%eax
ffffffff8af23473:	03 b3 64 e3 18 00    	add    0x18e364(%rbx),%esi
ffffffff8af23479:	48 03 b3 28 e3 18 00 	add    0x18e328(%rbx),%rsi
ffffffff8af23480:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af23487:	00 
ffffffff8af23488:	0f 84 e5 02 00 00    	je     ffffffff8af23773 <frame_candidate_563370+0x403>
ffffffff8af2348e:	48 89 f2             	mov    %rsi,%rdx
ffffffff8af23491:	c7 02 0a 48 00 00    	movl   $0x480a,(%rdx)
ffffffff8af23497:	8b 93 64 e3 18 00    	mov    0x18e364(%rbx),%edx
ffffffff8af2349d:	be 14 08 00 00       	mov    $0x814,%esi
ffffffff8af234a2:	01 f2                	add    %esi,%edx
ffffffff8af234a4:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af234ab:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af234b2:	00 
ffffffff8af234b3:	74 04                	je     ffffffff8af234b9 <frame_candidate_563370+0x149>
ffffffff8af234b5:	8b 02                	mov    (%rdx),%eax
ffffffff8af234b7:	eb 1f                	jmp    ffffffff8af234d8 <frame_candidate_563370+0x168>
ffffffff8af234b9:	ed                   	in     (%dx),%eax
ffffffff8af234ba:	03 b3 64 e3 18 00    	add    0x18e364(%rbx),%esi
ffffffff8af234c0:	48 03 b3 28 e3 18 00 	add    0x18e328(%rbx),%rsi
ffffffff8af234c7:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af234ce:	00 
ffffffff8af234cf:	0f 84 ab 02 00 00    	je     ffffffff8af23780 <frame_candidate_563370+0x410>
ffffffff8af234d5:	48 89 f2             	mov    %rsi,%rdx
ffffffff8af234d8:	c7 02 00 10 a0 10    	movl   $0x10a01000,(%rdx)
ffffffff8af234de:	8b 93 64 e3 18 00    	mov    0x18e364(%rbx),%edx
ffffffff8af234e4:	be 18 08 00 00       	mov    $0x818,%esi
ffffffff8af234e9:	01 f2                	add    %esi,%edx
ffffffff8af234eb:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af234f2:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af234f9:	00 
ffffffff8af234fa:	74 09                	je     ffffffff8af23505 <frame_candidate_563370+0x195>
ffffffff8af234fc:	b8 ff ff 7f ff       	mov    $0xff7fffff,%eax
ffffffff8af23501:	23 02                	and    (%rdx),%eax
ffffffff8af23503:	eb 24                	jmp    ffffffff8af23529 <frame_candidate_563370+0x1b9>
ffffffff8af23505:	ed                   	in     (%dx),%eax
ffffffff8af23506:	03 b3 64 e3 18 00    	add    0x18e364(%rbx),%esi
ffffffff8af2350c:	25 ff ff 7f ff       	and    $0xff7fffff,%eax
ffffffff8af23511:	48 03 b3 28 e3 18 00 	add    0x18e328(%rbx),%rsi
ffffffff8af23518:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af2351f:	00 
ffffffff8af23520:	0f 84 67 02 00 00    	je     ffffffff8af2378d <frame_candidate_563370+0x41d>
ffffffff8af23526:	48 89 f2             	mov    %rsi,%rdx
ffffffff8af23529:	89 02                	mov    %eax,(%rdx)
ffffffff8af2352b:	8b 93 64 e3 18 00    	mov    0x18e364(%rbx),%edx
ffffffff8af23531:	be 00 08 00 00       	mov    $0x800,%esi
ffffffff8af23536:	01 f2                	add    %esi,%edx
ffffffff8af23538:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af2353f:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af23546:	00 
ffffffff8af23547:	74 07                	je     ffffffff8af23550 <frame_candidate_563370+0x1e0>
ffffffff8af23549:	8b 02                	mov    (%rdx),%eax
ffffffff8af2354b:	83 c8 20             	or     $0x20,%eax
ffffffff8af2354e:	eb 22                	jmp    ffffffff8af23572 <frame_candidate_563370+0x202>
ffffffff8af23550:	ed                   	in     (%dx),%eax
ffffffff8af23551:	03 b3 64 e3 18 00    	add    0x18e364(%rbx),%esi
ffffffff8af23557:	83 c8 20             	or     $0x20,%eax
ffffffff8af2355a:	48 03 b3 28 e3 18 00 	add    0x18e328(%rbx),%rsi
ffffffff8af23561:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af23568:	00 
ffffffff8af23569:	0f 84 26 02 00 00    	je     ffffffff8af23795 <frame_candidate_563370+0x425>
ffffffff8af2356f:	48 89 f2             	mov    %rsi,%rdx
ffffffff8af23572:	89 02                	mov    %eax,(%rdx)
ffffffff8af23574:	8b 93 64 e3 18 00    	mov    0x18e364(%rbx),%edx
ffffffff8af2357a:	be 68 08 00 00       	mov    $0x868,%esi
ffffffff8af2357f:	01 f2                	add    %esi,%edx
ffffffff8af23581:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af23588:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af2358f:	00 
ffffffff8af23590:	74 09                	je     ffffffff8af2359b <frame_candidate_563370+0x22b>
ffffffff8af23592:	b8 ff ff fb ff       	mov    $0xfffbffff,%eax
ffffffff8af23597:	23 02                	and    (%rdx),%eax
ffffffff8af23599:	eb 24                	jmp    ffffffff8af235bf <frame_candidate_563370+0x24f>
ffffffff8af2359b:	ed                   	in     (%dx),%eax
ffffffff8af2359c:	03 b3 64 e3 18 00    	add    0x18e364(%rbx),%esi
ffffffff8af235a2:	25 ff ff fb ff       	and    $0xfffbffff,%eax
ffffffff8af235a7:	48 03 b3 28 e3 18 00 	add    0x18e328(%rbx),%rsi
ffffffff8af235ae:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af235b5:	00 
ffffffff8af235b6:	0f 84 e1 01 00 00    	je     ffffffff8af2379d <frame_candidate_563370+0x42d>
ffffffff8af235bc:	48 89 f2             	mov    %rsi,%rdx
ffffffff8af235bf:	89 02                	mov    %eax,(%rdx)
ffffffff8af235c1:	8b 93 64 e3 18 00    	mov    0x18e364(%rbx),%edx
ffffffff8af235c7:	be 04 08 00 00       	mov    $0x804,%esi
ffffffff8af235cc:	01 f2                	add    %esi,%edx
ffffffff8af235ce:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af235d5:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af235dc:	00 
ffffffff8af235dd:	74 0e                	je     ffffffff8af235ed <frame_candidate_563370+0x27d>
ffffffff8af235df:	b8 ff ff 07 ff       	mov    $0xff07ffff,%eax
ffffffff8af235e4:	23 02                	and    (%rdx),%eax
ffffffff8af235e6:	c1 e1 13             	shl    $0x13,%ecx
ffffffff8af235e9:	09 c1                	or     %eax,%ecx
ffffffff8af235eb:	eb 29                	jmp    ffffffff8af23616 <frame_candidate_563370+0x2a6>
ffffffff8af235ed:	ed                   	in     (%dx),%eax
ffffffff8af235ee:	03 b3 64 e3 18 00    	add    0x18e364(%rbx),%esi
ffffffff8af235f4:	25 ff ff 07 ff       	and    $0xff07ffff,%eax
ffffffff8af235f9:	c1 e1 13             	shl    $0x13,%ecx
ffffffff8af235fc:	48 03 b3 28 e3 18 00 	add    0x18e328(%rbx),%rsi
ffffffff8af23603:	09 c1                	or     %eax,%ecx
ffffffff8af23605:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af2360c:	00 
ffffffff8af2360d:	0f 84 92 01 00 00    	je     ffffffff8af237a5 <frame_candidate_563370+0x435>
ffffffff8af23613:	48 89 f2             	mov    %rsi,%rdx
ffffffff8af23616:	89 0a                	mov    %ecx,(%rdx)
ffffffff8af23618:	66 c7 45 ce 00 00    	movw   $0x0,-0x32(%rbp)
ffffffff8af2361e:	48 8b bb 38 dc 18 00 	mov    0x18dc38(%rbx),%rdi
ffffffff8af23625:	e8 b6 05 d5 ff       	call   ffffffff8ac73be0 <handler_631_body-0x2ae500>
ffffffff8af2362a:	31 f6                	xor    %esi,%esi
ffffffff8af2362c:	85 c0                	test   %eax,%eax
ffffffff8af2362e:	74 2f                	je     ffffffff8af2365f <frame_candidate_563370+0x2ef>
ffffffff8af23630:	83 e6 1f             	and    $0x1f,%esi
ffffffff8af23633:	8b 93 64 e3 18 00    	mov    0x18e364(%rbx),%edx
ffffffff8af23639:	b9 18 08 00 00       	mov    $0x818,%ecx
ffffffff8af2363e:	01 ca                	add    %ecx,%edx
ffffffff8af23640:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af23647:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af2364e:	00 
ffffffff8af2364f:	74 40                	je     ffffffff8af23691 <frame_candidate_563370+0x321>
ffffffff8af23651:	b8 0f ff ff ff       	mov    $0xffffff0f,%eax
ffffffff8af23656:	23 02                	and    (%rdx),%eax
ffffffff8af23658:	0d a0 00 00 00       	or     $0xa0,%eax
ffffffff8af2365d:	eb 5b                	jmp    ffffffff8af236ba <frame_candidate_563370+0x34a>
ffffffff8af2365f:	48 8d 55 ce          	lea    -0x32(%rbp),%rdx
ffffffff8af23663:	44 89 f6             	mov    %r14d,%esi
ffffffff8af23666:	31 ff                	xor    %edi,%edi
ffffffff8af23668:	e8 03 72 17 00       	call   ffffffff8b09a870 <frame_candidate_563fd0+0x1768a0>
ffffffff8af2366d:	0f b6 75 cf          	movzbl -0x31(%rbp),%esi
ffffffff8af23671:	81 fe ff 00 00 00    	cmp    $0xff,%esi
ffffffff8af23677:	0f 84 32 01 00 00    	je     ffffffff8af237af <frame_candidate_563370+0x43f>
ffffffff8af2367d:	40 80 fe 60          	cmp    $0x60,%sil
ffffffff8af23681:	72 ad                	jb     ffffffff8af23630 <frame_candidate_563370+0x2c0>
ffffffff8af23683:	89 f0                	mov    %esi,%eax
ffffffff8af23685:	83 e6 1f             	and    $0x1f,%esi
ffffffff8af23688:	c1 e8 05             	shr    $0x5,%eax
ffffffff8af2368b:	8d 74 30 fe          	lea    -0x2(%rax,%rsi,1),%esi
ffffffff8af2368f:	eb a2                	jmp    ffffffff8af23633 <frame_candidate_563370+0x2c3>
ffffffff8af23691:	ed                   	in     (%dx),%eax
ffffffff8af23692:	03 8b 64 e3 18 00    	add    0x18e364(%rbx),%ecx
ffffffff8af23698:	25 0f ff ff ff       	and    $0xffffff0f,%eax
ffffffff8af2369d:	48 03 8b 28 e3 18 00 	add    0x18e328(%rbx),%rcx
ffffffff8af236a4:	0d a0 00 00 00       	or     $0xa0,%eax
ffffffff8af236a9:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af236b0:	00 
ffffffff8af236b1:	0f 84 02 01 00 00    	je     ffffffff8af237b9 <frame_candidate_563370+0x449>
ffffffff8af236b7:	48 89 ca             	mov    %rcx,%rdx
ffffffff8af236ba:	89 02                	mov    %eax,(%rdx)
ffffffff8af236bc:	ba 18 08 00 00       	mov    $0x818,%edx
ffffffff8af236c1:	03 93 64 e3 18 00    	add    0x18e364(%rbx),%edx
ffffffff8af236c7:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af236ce:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af236d5:	00 
ffffffff8af236d6:	74 33                	je     ffffffff8af2370b <frame_candidate_563370+0x39b>
ffffffff8af236d8:	8b 02                	mov    (%rdx),%eax
ffffffff8af236da:	83 fe 02             	cmp    $0x2,%esi
ffffffff8af236dd:	77 32                	ja     ffffffff8af23711 <frame_candidate_563370+0x3a1>
ffffffff8af236df:	ba 18 08 00 00       	mov    $0x818,%edx
ffffffff8af236e4:	03 93 64 e3 18 00    	add    0x18e364(%rbx),%edx
ffffffff8af236ea:	83 e0 f0             	and    $0xfffffff0,%eax
ffffffff8af236ed:	83 c8 08             	or     $0x8,%eax
ffffffff8af236f0:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af236f7:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af236fe:	00 
ffffffff8af236ff:	0f 85 2b 01 00 00    	jne    ffffffff8af23830 <frame_candidate_563370+0x4c0>
ffffffff8af23705:	ef                   	out    %eax,(%dx)
ffffffff8af23706:	e9 27 01 00 00       	jmp    ffffffff8af23832 <frame_candidate_563370+0x4c2>
ffffffff8af2370b:	ed                   	in     (%dx),%eax
ffffffff8af2370c:	83 fe 02             	cmp    $0x2,%esi
ffffffff8af2370f:	76 ce                	jbe    ffffffff8af236df <frame_candidate_563370+0x36f>
ffffffff8af23711:	83 fe 05             	cmp    $0x5,%esi
ffffffff8af23714:	77 2c                	ja     ffffffff8af23742 <frame_candidate_563370+0x3d2>
ffffffff8af23716:	ba 18 08 00 00       	mov    $0x818,%edx
ffffffff8af2371b:	03 93 64 e3 18 00    	add    0x18e364(%rbx),%edx
ffffffff8af23721:	83 e0 f0             	and    $0xfffffff0,%eax
ffffffff8af23724:	83 c8 07             	or     $0x7,%eax
ffffffff8af23727:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af2372e:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af23735:	00 
ffffffff8af23736:	0f 85 f4 00 00 00    	jne    ffffffff8af23830 <frame_candidate_563370+0x4c0>
ffffffff8af2373c:	ef                   	out    %eax,(%dx)
ffffffff8af2373d:	e9 f0 00 00 00       	jmp    ffffffff8af23832 <frame_candidate_563370+0x4c2>
ffffffff8af23742:	83 fe 07             	cmp    $0x7,%esi
ffffffff8af23745:	77 7a                	ja     ffffffff8af237c1 <frame_candidate_563370+0x451>
ffffffff8af23747:	ba 18 08 00 00       	mov    $0x818,%edx
ffffffff8af2374c:	03 93 64 e3 18 00    	add    0x18e364(%rbx),%edx
ffffffff8af23752:	83 e0 f0             	and    $0xfffffff0,%eax
ffffffff8af23755:	83 c8 06             	or     $0x6,%eax
ffffffff8af23758:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af2375f:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af23766:	00 
ffffffff8af23767:	0f 85 c3 00 00 00    	jne    ffffffff8af23830 <frame_candidate_563370+0x4c0>
ffffffff8af2376d:	ef                   	out    %eax,(%dx)
ffffffff8af2376e:	e9 bf 00 00 00       	jmp    ffffffff8af23832 <frame_candidate_563370+0x4c2>
ffffffff8af23773:	b8 0a 48 00 00       	mov    $0x480a,%eax
ffffffff8af23778:	89 f2                	mov    %esi,%edx
ffffffff8af2377a:	ef                   	out    %eax,(%dx)
ffffffff8af2377b:	e9 17 fd ff ff       	jmp    ffffffff8af23497 <frame_candidate_563370+0x127>
ffffffff8af23780:	b8 00 10 a0 10       	mov    $0x10a01000,%eax
ffffffff8af23785:	89 f2                	mov    %esi,%edx
ffffffff8af23787:	ef                   	out    %eax,(%dx)
ffffffff8af23788:	e9 51 fd ff ff       	jmp    ffffffff8af234de <frame_candidate_563370+0x16e>
ffffffff8af2378d:	89 f2                	mov    %esi,%edx
ffffffff8af2378f:	ef                   	out    %eax,(%dx)
ffffffff8af23790:	e9 96 fd ff ff       	jmp    ffffffff8af2352b <frame_candidate_563370+0x1bb>
ffffffff8af23795:	89 f2                	mov    %esi,%edx
ffffffff8af23797:	ef                   	out    %eax,(%dx)
ffffffff8af23798:	e9 d7 fd ff ff       	jmp    ffffffff8af23574 <frame_candidate_563370+0x204>
ffffffff8af2379d:	89 f2                	mov    %esi,%edx
ffffffff8af2379f:	ef                   	out    %eax,(%dx)
ffffffff8af237a0:	e9 1c fe ff ff       	jmp    ffffffff8af235c1 <frame_candidate_563370+0x251>
ffffffff8af237a5:	89 c8                	mov    %ecx,%eax
ffffffff8af237a7:	89 f2                	mov    %esi,%edx
ffffffff8af237a9:	ef                   	out    %eax,(%dx)
ffffffff8af237aa:	e9 69 fe ff ff       	jmp    ffffffff8af23618 <frame_candidate_563370+0x2a8>
ffffffff8af237af:	be ff 00 00 00       	mov    $0xff,%esi
ffffffff8af237b4:	e9 7a fe ff ff       	jmp    ffffffff8af23633 <frame_candidate_563370+0x2c3>
ffffffff8af237b9:	89 ca                	mov    %ecx,%edx
ffffffff8af237bb:	ef                   	out    %eax,(%dx)
ffffffff8af237bc:	e9 fb fe ff ff       	jmp    ffffffff8af236bc <frame_candidate_563370+0x34c>
ffffffff8af237c1:	83 fe 09             	cmp    $0x9,%esi
ffffffff8af237c4:	77 43                	ja     ffffffff8af23809 <frame_candidate_563370+0x499>
ffffffff8af237c6:	ba 18 08 00 00       	mov    $0x818,%edx
ffffffff8af237cb:	03 93 64 e3 18 00    	add    0x18e364(%rbx),%edx
ffffffff8af237d1:	83 e0 f0             	and    $0xfffffff0,%eax
ffffffff8af237d4:	83 c8 05             	or     $0x5,%eax
ffffffff8af237d7:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af237de:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af237e5:	00 
ffffffff8af237e6:	75 48                	jne    ffffffff8af23830 <frame_candidate_563370+0x4c0>
ffffffff8af237e8:	ef                   	out    %eax,(%dx)
ffffffff8af237e9:	eb 47                	jmp    ffffffff8af23832 <frame_candidate_563370+0x4c2>
ffffffff8af237eb:	b9 15 05 00 00       	mov    $0x515,%ecx
ffffffff8af237f0:	c4 e2 70 f7 c8       	bextr  %ecx,%eax,%ecx
ffffffff8af237f5:	e9 56 fc ff ff       	jmp    ffffffff8af23450 <frame_candidate_563370+0xe0>
ffffffff8af237fa:	b9 1a 05 00 00       	mov    $0x51a,%ecx
ffffffff8af237ff:	c4 e2 70 f7 c8       	bextr  %ecx,%eax,%ecx
ffffffff8af23804:	e9 47 fc ff ff       	jmp    ffffffff8af23450 <frame_candidate_563370+0xe0>
ffffffff8af23809:	83 fe 0c             	cmp    $0xc,%esi
ffffffff8af2380c:	77 41                	ja     ffffffff8af2384f <frame_candidate_563370+0x4df>
ffffffff8af2380e:	ba 18 08 00 00       	mov    $0x818,%edx
ffffffff8af23813:	03 93 64 e3 18 00    	add    0x18e364(%rbx),%edx
ffffffff8af23819:	83 e0 f0             	and    $0xfffffff0,%eax
ffffffff8af2381c:	83 c8 04             	or     $0x4,%eax
ffffffff8af2381f:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af23826:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af2382d:	00 
ffffffff8af2382e:	74 7c                	je     ffffffff8af238ac <frame_candidate_563370+0x53c>
ffffffff8af23830:	89 02                	mov    %eax,(%rdx)
ffffffff8af23832:	49 8b 45 00          	mov    0x0(%r13),%rax
ffffffff8af23836:	48 3b 45 d0          	cmp    -0x30(%rbp),%rax
ffffffff8af2383a:	0f 85 93 00 00 00    	jne    ffffffff8af238d3 <frame_candidate_563370+0x563>
ffffffff8af23840:	48 83 c4 18          	add    $0x18,%rsp
ffffffff8af23844:	5b                   	pop    %rbx
ffffffff8af23845:	41 5c                	pop    %r12
ffffffff8af23847:	41 5d                	pop    %r13
ffffffff8af23849:	41 5e                	pop    %r14
ffffffff8af2384b:	41 5f                	pop    %r15
ffffffff8af2384d:	5d                   	pop    %rbp
ffffffff8af2384e:	c3                   	ret
ffffffff8af2384f:	48 8b bb 38 dc 18 00 	mov    0x18dc38(%rbx),%rdi
ffffffff8af23856:	48 8d 35 03 22 e4 00 	lea    0xe42203(%rip),%rsi        # ffffffff8bd65a60 <frame_candidate_563fd0+0xe41a90>
ffffffff8af2385d:	41 89 c7             	mov    %eax,%r15d
ffffffff8af23860:	31 c0                	xor    %eax,%eax
ffffffff8af23862:	e8 09 04 d5 ff       	call   ffffffff8ac73c70 <handler_631_body-0x2ae470>
ffffffff8af23867:	48 8b bb 38 dc 18 00 	mov    0x18dc38(%rbx),%rdi
ffffffff8af2386e:	e8 6d 03 d5 ff       	call   ffffffff8ac73be0 <handler_631_body-0x2ae500>
ffffffff8af23873:	85 c0                	test   %eax,%eax
ffffffff8af23875:	75 bb                	jne    ffffffff8af23832 <frame_candidate_563370+0x4c2>
ffffffff8af23877:	ba 18 08 00 00       	mov    $0x818,%edx
ffffffff8af2387c:	03 93 64 e3 18 00    	add    0x18e364(%rbx),%edx
ffffffff8af23882:	48 8b 8b 20 e3 18 00 	mov    0x18e320(%rbx),%rcx
ffffffff8af23889:	44 89 f8             	mov    %r15d,%eax
ffffffff8af2388c:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af23893:	83 e0 f0             	and    $0xfffffff0,%eax
ffffffff8af23896:	41 83 fe 01          	cmp    $0x1,%r14d
ffffffff8af2389a:	74 13                	je     ffffffff8af238af <frame_candidate_563370+0x53f>
ffffffff8af2389c:	45 85 f6             	test   %r14d,%r14d
ffffffff8af2389f:	75 20                	jne    ffffffff8af238c1 <frame_candidate_563370+0x551>
ffffffff8af238a1:	83 c8 04             	or     $0x4,%eax
ffffffff8af238a4:	48 85 c9             	test   %rcx,%rcx
ffffffff8af238a7:	75 87                	jne    ffffffff8af23830 <frame_candidate_563370+0x4c0>
ffffffff8af238a9:	ef                   	out    %eax,(%dx)
ffffffff8af238aa:	eb 86                	jmp    ffffffff8af23832 <frame_candidate_563370+0x4c2>
ffffffff8af238ac:	ef                   	out    %eax,(%dx)
ffffffff8af238ad:	eb 83                	jmp    ffffffff8af23832 <frame_candidate_563370+0x4c2>
ffffffff8af238af:	83 c8 06             	or     $0x6,%eax
ffffffff8af238b2:	48 85 c9             	test   %rcx,%rcx
ffffffff8af238b5:	0f 85 75 ff ff ff    	jne    ffffffff8af23830 <frame_candidate_563370+0x4c0>
ffffffff8af238bb:	ef                   	out    %eax,(%dx)
ffffffff8af238bc:	e9 71 ff ff ff       	jmp    ffffffff8af23832 <frame_candidate_563370+0x4c2>
ffffffff8af238c1:	83 c8 07             	or     $0x7,%eax
ffffffff8af238c4:	48 85 c9             	test   %rcx,%rcx
ffffffff8af238c7:	0f 85 63 ff ff ff    	jne    ffffffff8af23830 <frame_candidate_563370+0x4c0>
ffffffff8af238cd:	ef                   	out    %eax,(%dx)
ffffffff8af238ce:	e9 5f ff ff ff       	jmp    ffffffff8af23832 <frame_candidate_563370+0x4c2>
ffffffff8af238d3:	e8 d8 9d 19 00       	call   ffffffff8b0bd6b0 <frame_candidate_563fd0+0x1996e0>
ffffffff8af238d8:	0f 0b                	ud2
ffffffff8af238da:	90                   	nop
ffffffff8af238db:	90                   	nop
ffffffff8af238dc:	90                   	nop
ffffffff8af238dd:	90                   	nop
ffffffff8af238de:	90                   	nop
ffffffff8af238df:	90                   	nop

ffffffff8af238e0 <frame_candidate_5638e0>:
ffffffff8af238e0:	55                   	push   %rbp
ffffffff8af238e1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8af238e4:	41 57                	push   %r15
ffffffff8af238e6:	41 56                	push   %r14
ffffffff8af238e8:	41 55                	push   %r13
ffffffff8af238ea:	41 54                	push   %r12
ffffffff8af238ec:	53                   	push   %rbx
ffffffff8af238ed:	50                   	push   %rax
ffffffff8af238ee:	48 89 fb             	mov    %rdi,%rbx
ffffffff8af238f1:	48 8b bf 38 dc 18 00 	mov    0x18dc38(%rdi),%rdi
ffffffff8af238f8:	41 89 f6             	mov    %esi,%r14d
ffffffff8af238fb:	e8 e0 02 d5 ff       	call   ffffffff8ac73be0 <handler_631_body-0x2ae500>
ffffffff8af23900:	b9 00 00 12 00       	mov    $0x120000,%ecx
ffffffff8af23905:	85 c0                	test   %eax,%eax
ffffffff8af23907:	75 1b                	jne    ffffffff8af23924 <frame_candidate_5638e0+0x44>
ffffffff8af23909:	31 c0                	xor    %eax,%eax
ffffffff8af2390b:	41 83 fe 01          	cmp    $0x1,%r14d
ffffffff8af2390f:	b9 00 80 12 00       	mov    $0x128000,%ecx
ffffffff8af23914:	0f 94 c0             	sete   %al
ffffffff8af23917:	83 c8 48             	or     $0x48,%eax
ffffffff8af2391a:	c1 e0 0e             	shl    $0xe,%eax
ffffffff8af2391d:	41 83 fe 02          	cmp    $0x2,%r14d
ffffffff8af23921:	0f 45 c8             	cmovne %eax,%ecx
ffffffff8af23924:	89 8b 64 e3 18 00    	mov    %ecx,0x18e364(%rbx)
ffffffff8af2392a:	89 c9                	mov    %ecx,%ecx
ffffffff8af2392c:	48 8b 83 28 e3 18 00 	mov    0x18e328(%rbx),%rax
ffffffff8af23933:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af2393a:	00 
ffffffff8af2393b:	48 8d 94 01 14 08 00 	lea    0x814(%rcx,%rax,1),%rdx
ffffffff8af23942:	00 
ffffffff8af23943:	74 09                	je     ffffffff8af2394e <frame_candidate_5638e0+0x6e>
ffffffff8af23945:	b8 00 80 00 00       	mov    $0x8000,%eax
ffffffff8af2394a:	0b 02                	or     (%rdx),%eax
ffffffff8af2394c:	eb 26                	jmp    ffffffff8af23974 <frame_candidate_5638e0+0x94>
ffffffff8af2394e:	ed                   	in     (%dx),%eax
ffffffff8af2394f:	ba 14 08 00 00       	mov    $0x814,%edx
ffffffff8af23954:	03 93 64 e3 18 00    	add    0x18e364(%rbx),%edx
ffffffff8af2395a:	0d 00 80 00 00       	or     $0x8000,%eax
ffffffff8af2395f:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af23966:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af2396d:	00 
ffffffff8af2396e:	0f 84 b0 02 00 00    	je     ffffffff8af23c24 <frame_candidate_5638e0+0x344>
ffffffff8af23974:	89 02                	mov    %eax,(%rdx)
ffffffff8af23976:	bf 01 00 00 00       	mov    $0x1,%edi
ffffffff8af2397b:	e8 60 a8 f0 ff       	call   ffffffff8ae2e1e0 <handler_631_body-0xf3f00>
ffffffff8af23980:	8b 93 64 e3 18 00    	mov    0x18e364(%rbx),%edx
ffffffff8af23986:	b9 10 01 00 00       	mov    $0x110,%ecx
ffffffff8af2398b:	01 ca                	add    %ecx,%edx
ffffffff8af2398d:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af23994:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af2399b:	00 
ffffffff8af2399c:	74 09                	je     ffffffff8af239a7 <frame_candidate_5638e0+0xc7>
ffffffff8af2399e:	b8 00 01 00 00       	mov    $0x100,%eax
ffffffff8af239a3:	0b 02                	or     (%rdx),%eax
ffffffff8af239a5:	eb 24                	jmp    ffffffff8af239cb <frame_candidate_5638e0+0xeb>
ffffffff8af239a7:	ed                   	in     (%dx),%eax
ffffffff8af239a8:	03 8b 64 e3 18 00    	add    0x18e364(%rbx),%ecx
ffffffff8af239ae:	0d 00 01 00 00       	or     $0x100,%eax
ffffffff8af239b3:	48 03 8b 28 e3 18 00 	add    0x18e328(%rbx),%rcx
ffffffff8af239ba:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af239c1:	00 
ffffffff8af239c2:	0f 84 62 02 00 00    	je     ffffffff8af23c2a <frame_candidate_5638e0+0x34a>
ffffffff8af239c8:	48 89 ca             	mov    %rcx,%rdx
ffffffff8af239cb:	89 02                	mov    %eax,(%rdx)
ffffffff8af239cd:	8b 93 64 e3 18 00    	mov    0x18e364(%rbx),%edx
ffffffff8af239d3:	b9 00 01 00 00       	mov    $0x100,%ecx
ffffffff8af239d8:	01 ca                	add    %ecx,%edx
ffffffff8af239da:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af239e1:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af239e8:	00 
ffffffff8af239e9:	74 0e                	je     ffffffff8af239f9 <frame_candidate_5638e0+0x119>
ffffffff8af239eb:	b8 00 00 00 ff       	mov    $0xff000000,%eax
ffffffff8af239f0:	23 02                	and    (%rdx),%eax
ffffffff8af239f2:	0d 00 04 00 00       	or     $0x400,%eax
ffffffff8af239f7:	eb 29                	jmp    ffffffff8af23a22 <frame_candidate_5638e0+0x142>
ffffffff8af239f9:	ed                   	in     (%dx),%eax
ffffffff8af239fa:	03 8b 64 e3 18 00    	add    0x18e364(%rbx),%ecx
ffffffff8af23a00:	25 00 00 00 ff       	and    $0xff000000,%eax
ffffffff8af23a05:	48 03 8b 28 e3 18 00 	add    0x18e328(%rbx),%rcx
ffffffff8af23a0c:	0d 00 04 00 00       	or     $0x400,%eax
ffffffff8af23a11:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af23a18:	00 
ffffffff8af23a19:	0f 84 13 02 00 00    	je     ffffffff8af23c32 <frame_candidate_5638e0+0x352>
ffffffff8af23a1f:	48 89 ca             	mov    %rcx,%rdx
ffffffff8af23a22:	89 02                	mov    %eax,(%rdx)
ffffffff8af23a24:	8b 93 64 e3 18 00    	mov    0x18e364(%rbx),%edx
ffffffff8af23a2a:	b9 00 01 00 00       	mov    $0x100,%ecx
ffffffff8af23a2f:	01 ca                	add    %ecx,%edx
ffffffff8af23a31:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af23a38:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af23a3f:	00 
ffffffff8af23a40:	74 09                	je     ffffffff8af23a4b <frame_candidate_5638e0+0x16b>
ffffffff8af23a42:	b8 00 00 00 01       	mov    $0x1000000,%eax
ffffffff8af23a47:	0b 02                	or     (%rdx),%eax
ffffffff8af23a49:	eb 24                	jmp    ffffffff8af23a6f <frame_candidate_5638e0+0x18f>
ffffffff8af23a4b:	ed                   	in     (%dx),%eax
ffffffff8af23a4c:	03 8b 64 e3 18 00    	add    0x18e364(%rbx),%ecx
ffffffff8af23a52:	0d 00 00 00 01       	or     $0x1000000,%eax
ffffffff8af23a57:	48 03 8b 28 e3 18 00 	add    0x18e328(%rbx),%rcx
ffffffff8af23a5e:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af23a65:	00 
ffffffff8af23a66:	0f 84 ce 01 00 00    	je     ffffffff8af23c3a <frame_candidate_5638e0+0x35a>
ffffffff8af23a6c:	48 89 ca             	mov    %rcx,%rdx
ffffffff8af23a6f:	89 02                	mov    %eax,(%rdx)
ffffffff8af23a71:	41 bc e8 03 00 00    	mov    $0x3e8,%r12d
ffffffff8af23a77:	41 bd 0c 01 00 00    	mov    $0x10c,%r13d
ffffffff8af23a7d:	0f 1f 00             	nopl   (%rax)
ffffffff8af23a80:	8b 93 64 e3 18 00    	mov    0x18e364(%rbx),%edx
ffffffff8af23a86:	44 01 ea             	add    %r13d,%edx
ffffffff8af23a89:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af23a90:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af23a97:	00 
ffffffff8af23a98:	74 16                	je     ffffffff8af23ab0 <frame_candidate_5638e0+0x1d0>
ffffffff8af23a9a:	44 8b 3a             	mov    (%rdx),%r15d
ffffffff8af23a9d:	45 85 ff             	test   %r15d,%r15d
ffffffff8af23aa0:	74 17                	je     ffffffff8af23ab9 <frame_candidate_5638e0+0x1d9>
ffffffff8af23aa2:	eb 24                	jmp    ffffffff8af23ac8 <frame_candidate_5638e0+0x1e8>
ffffffff8af23aa4:	66 66 66 2e 0f 1f 84 	data16 data16 cs nopw 0x0(%rax,%rax,1)
ffffffff8af23aab:	00 00 00 00 00 
ffffffff8af23ab0:	ed                   	in     (%dx),%eax
ffffffff8af23ab1:	41 89 c7             	mov    %eax,%r15d
ffffffff8af23ab4:	45 85 ff             	test   %r15d,%r15d
ffffffff8af23ab7:	75 0f                	jne    ffffffff8af23ac8 <frame_candidate_5638e0+0x1e8>
ffffffff8af23ab9:	bf 01 00 00 00       	mov    $0x1,%edi
ffffffff8af23abe:	e8 1d a7 f0 ff       	call   ffffffff8ae2e1e0 <handler_631_body-0xf3f00>
ffffffff8af23ac3:	41 ff cc             	dec    %r12d
ffffffff8af23ac6:	75 b8                	jne    ffffffff8af23a80 <frame_candidate_5638e0+0x1a0>
ffffffff8af23ac8:	8b 93 64 e3 18 00    	mov    0x18e364(%rbx),%edx
ffffffff8af23ace:	b9 00 01 00 00       	mov    $0x100,%ecx
ffffffff8af23ad3:	01 ca                	add    %ecx,%edx
ffffffff8af23ad5:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af23adc:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af23ae3:	00 
ffffffff8af23ae4:	74 09                	je     ffffffff8af23aef <frame_candidate_5638e0+0x20f>
ffffffff8af23ae6:	b8 ff ff ff fe       	mov    $0xfeffffff,%eax
ffffffff8af23aeb:	23 02                	and    (%rdx),%eax
ffffffff8af23aed:	eb 24                	jmp    ffffffff8af23b13 <frame_candidate_5638e0+0x233>
ffffffff8af23aef:	ed                   	in     (%dx),%eax
ffffffff8af23af0:	03 8b 64 e3 18 00    	add    0x18e364(%rbx),%ecx
ffffffff8af23af6:	25 ff ff ff fe       	and    $0xfeffffff,%eax
ffffffff8af23afb:	48 03 8b 28 e3 18 00 	add    0x18e328(%rbx),%rcx
ffffffff8af23b02:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af23b09:	00 
ffffffff8af23b0a:	0f 84 32 01 00 00    	je     ffffffff8af23c42 <frame_candidate_5638e0+0x362>
ffffffff8af23b10:	48 89 ca             	mov    %rcx,%rdx
ffffffff8af23b13:	89 02                	mov    %eax,(%rdx)
ffffffff8af23b15:	8b 93 64 e3 18 00    	mov    0x18e364(%rbx),%edx
ffffffff8af23b1b:	b9 10 01 00 00       	mov    $0x110,%ecx
ffffffff8af23b20:	01 ca                	add    %ecx,%edx
ffffffff8af23b22:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af23b29:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af23b30:	00 
ffffffff8af23b31:	74 09                	je     ffffffff8af23b3c <frame_candidate_5638e0+0x25c>
ffffffff8af23b33:	b8 ff fe ff ff       	mov    $0xfffffeff,%eax
ffffffff8af23b38:	23 02                	and    (%rdx),%eax
ffffffff8af23b3a:	eb 24                	jmp    ffffffff8af23b60 <frame_candidate_5638e0+0x280>
ffffffff8af23b3c:	ed                   	in     (%dx),%eax
ffffffff8af23b3d:	03 8b 64 e3 18 00    	add    0x18e364(%rbx),%ecx
ffffffff8af23b43:	25 ff fe ff ff       	and    $0xfffffeff,%eax
ffffffff8af23b48:	48 03 8b 28 e3 18 00 	add    0x18e328(%rbx),%rcx
ffffffff8af23b4f:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af23b56:	00 
ffffffff8af23b57:	0f 84 ed 00 00 00    	je     ffffffff8af23c4a <frame_candidate_5638e0+0x36a>
ffffffff8af23b5d:	48 89 ca             	mov    %rcx,%rdx
ffffffff8af23b60:	89 02                	mov    %eax,(%rdx)
ffffffff8af23b62:	45 85 ff             	test   %r15d,%r15d
ffffffff8af23b65:	0f 84 eb 00 00 00    	je     ffffffff8af23c56 <frame_candidate_5638e0+0x376>
ffffffff8af23b6b:	b8 00 90 0b 00       	mov    $0xb9000,%eax
ffffffff8af23b70:	31 d2                	xor    %edx,%edx
ffffffff8af23b72:	be 14 08 00 00       	mov    $0x814,%esi
ffffffff8af23b77:	41 f7 f7             	div    %r15d
ffffffff8af23b7a:	8b 93 64 e3 18 00    	mov    0x18e364(%rbx),%edx
ffffffff8af23b80:	48 69 c8 38 89 41 00 	imul   $0x418938,%rax,%rcx
ffffffff8af23b87:	48 c1 e9 20          	shr    $0x20,%rcx
ffffffff8af23b8b:	01 f2                	add    %esi,%edx
ffffffff8af23b8d:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af23b94:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af23b9b:	00 
ffffffff8af23b9c:	74 0e                	je     ffffffff8af23bac <frame_candidate_5638e0+0x2cc>
ffffffff8af23b9e:	b8 ff 8f ff ff       	mov    $0xffff8fff,%eax
ffffffff8af23ba3:	23 02                	and    (%rdx),%eax
ffffffff8af23ba5:	c1 e1 0c             	shl    $0xc,%ecx
ffffffff8af23ba8:	09 c1                	or     %eax,%ecx
ffffffff8af23baa:	eb 29                	jmp    ffffffff8af23bd5 <frame_candidate_5638e0+0x2f5>
ffffffff8af23bac:	ed                   	in     (%dx),%eax
ffffffff8af23bad:	03 b3 64 e3 18 00    	add    0x18e364(%rbx),%esi
ffffffff8af23bb3:	25 ff 8f ff ff       	and    $0xffff8fff,%eax
ffffffff8af23bb8:	c1 e1 0c             	shl    $0xc,%ecx
ffffffff8af23bbb:	48 03 b3 28 e3 18 00 	add    0x18e328(%rbx),%rsi
ffffffff8af23bc2:	09 c1                	or     %eax,%ecx
ffffffff8af23bc4:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af23bcb:	00 
ffffffff8af23bcc:	0f 84 b0 00 00 00    	je     ffffffff8af23c82 <frame_candidate_5638e0+0x3a2>
ffffffff8af23bd2:	48 89 f2             	mov    %rsi,%rdx
ffffffff8af23bd5:	89 0a                	mov    %ecx,(%rdx)
ffffffff8af23bd7:	8b 93 64 e3 18 00    	mov    0x18e364(%rbx),%edx
ffffffff8af23bdd:	b9 14 08 00 00       	mov    $0x814,%ecx
ffffffff8af23be2:	01 ca                	add    %ecx,%edx
ffffffff8af23be4:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af23beb:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af23bf2:	00 
ffffffff8af23bf3:	74 0e                	je     ffffffff8af23c03 <frame_candidate_5638e0+0x323>
ffffffff8af23bf5:	b8 ff 7f ff ff       	mov    $0xffff7fff,%eax
ffffffff8af23bfa:	23 02                	and    (%rdx),%eax
ffffffff8af23bfc:	89 02                	mov    %eax,(%rdx)
ffffffff8af23bfe:	e9 8c 00 00 00       	jmp    ffffffff8af23c8f <frame_candidate_5638e0+0x3af>
ffffffff8af23c03:	ed                   	in     (%dx),%eax
ffffffff8af23c04:	03 8b 64 e3 18 00    	add    0x18e364(%rbx),%ecx
ffffffff8af23c0a:	25 ff 7f ff ff       	and    $0xffff7fff,%eax
ffffffff8af23c0f:	48 03 8b 28 e3 18 00 	add    0x18e328(%rbx),%rcx
ffffffff8af23c16:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af23c1d:	00 
ffffffff8af23c1e:	74 6c                	je     ffffffff8af23c8c <frame_candidate_5638e0+0x3ac>
ffffffff8af23c20:	89 01                	mov    %eax,(%rcx)
ffffffff8af23c22:	eb 6b                	jmp    ffffffff8af23c8f <frame_candidate_5638e0+0x3af>
ffffffff8af23c24:	ef                   	out    %eax,(%dx)
ffffffff8af23c25:	e9 4c fd ff ff       	jmp    ffffffff8af23976 <frame_candidate_5638e0+0x96>
ffffffff8af23c2a:	89 ca                	mov    %ecx,%edx
ffffffff8af23c2c:	ef                   	out    %eax,(%dx)
ffffffff8af23c2d:	e9 9b fd ff ff       	jmp    ffffffff8af239cd <frame_candidate_5638e0+0xed>
ffffffff8af23c32:	89 ca                	mov    %ecx,%edx
ffffffff8af23c34:	ef                   	out    %eax,(%dx)
ffffffff8af23c35:	e9 ea fd ff ff       	jmp    ffffffff8af23a24 <frame_candidate_5638e0+0x144>
ffffffff8af23c3a:	89 ca                	mov    %ecx,%edx
ffffffff8af23c3c:	ef                   	out    %eax,(%dx)
ffffffff8af23c3d:	e9 2f fe ff ff       	jmp    ffffffff8af23a71 <frame_candidate_5638e0+0x191>
ffffffff8af23c42:	89 ca                	mov    %ecx,%edx
ffffffff8af23c44:	ef                   	out    %eax,(%dx)
ffffffff8af23c45:	e9 cb fe ff ff       	jmp    ffffffff8af23b15 <frame_candidate_5638e0+0x235>
ffffffff8af23c4a:	89 ca                	mov    %ecx,%edx
ffffffff8af23c4c:	ef                   	out    %eax,(%dx)
ffffffff8af23c4d:	45 85 ff             	test   %r15d,%r15d
ffffffff8af23c50:	0f 85 15 ff ff ff    	jne    ffffffff8af23b6b <frame_candidate_5638e0+0x28b>
ffffffff8af23c56:	e8 f5 dc 28 00       	call   ffffffff8b1b1950 <frame_candidate_563fd0+0x28d980>
ffffffff8af23c5b:	44 89 f6             	mov    %r14d,%esi
ffffffff8af23c5e:	48 8d 3d f1 ff ff ff 	lea    -0xf(%rip),%rdi        # ffffffff8af23c56 <frame_candidate_5638e0+0x376>
ffffffff8af23c65:	e8 36 dc 28 00       	call   ffffffff8b1b18a0 <frame_candidate_563fd0+0x28d8d0>
ffffffff8af23c6a:	48 8d 35 77 d9 e0 00 	lea    0xe0d977(%rip),%rsi        # ffffffff8bd315e8 <frame_candidate_563fd0+0xe0d618>
ffffffff8af23c71:	bf 17 00 00 00       	mov    $0x17,%edi
ffffffff8af23c76:	44 89 f2             	mov    %r14d,%edx
ffffffff8af23c79:	31 c0                	xor    %eax,%eax
ffffffff8af23c7b:	e8 90 6d 73 00       	call   ffffffff8b65aa10 <frame_candidate_563fd0+0x736a40>
ffffffff8af23c80:	0f 0b                	ud2
ffffffff8af23c82:	89 c8                	mov    %ecx,%eax
ffffffff8af23c84:	89 f2                	mov    %esi,%edx
ffffffff8af23c86:	ef                   	out    %eax,(%dx)
ffffffff8af23c87:	e9 4b ff ff ff       	jmp    ffffffff8af23bd7 <frame_candidate_5638e0+0x2f7>
ffffffff8af23c8c:	89 ca                	mov    %ecx,%edx
ffffffff8af23c8e:	ef                   	out    %eax,(%dx)
ffffffff8af23c8f:	48 83 c4 08          	add    $0x8,%rsp
ffffffff8af23c93:	5b                   	pop    %rbx
ffffffff8af23c94:	41 5c                	pop    %r12
ffffffff8af23c96:	41 5d                	pop    %r13
ffffffff8af23c98:	41 5e                	pop    %r14
ffffffff8af23c9a:	41 5f                	pop    %r15
ffffffff8af23c9c:	5d                   	pop    %rbp
ffffffff8af23c9d:	c3                   	ret
ffffffff8af23c9e:	90                   	nop
ffffffff8af23c9f:	90                   	nop

ffffffff8af23ca0 <frame_candidate_563ca0>:
ffffffff8af23ca0:	55                   	push   %rbp
ffffffff8af23ca1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8af23ca4:	41 56                	push   %r14
ffffffff8af23ca6:	53                   	push   %rbx
ffffffff8af23ca7:	48 89 fb             	mov    %rdi,%rbx
ffffffff8af23caa:	48 8b bf 38 dc 18 00 	mov    0x18dc38(%rdi),%rdi
ffffffff8af23cb1:	41 89 f6             	mov    %esi,%r14d
ffffffff8af23cb4:	e8 27 ff d4 ff       	call   ffffffff8ac73be0 <handler_631_body-0x2ae500>
ffffffff8af23cb9:	85 c0                	test   %eax,%eax
ffffffff8af23cbb:	0f 85 10 01 00 00    	jne    ffffffff8af23dd1 <frame_candidate_563ca0+0x131>
ffffffff8af23cc1:	48 8b bb 38 dc 18 00 	mov    0x18dc38(%rbx),%rdi
ffffffff8af23cc8:	e8 13 ff d4 ff       	call   ffffffff8ac73be0 <handler_631_body-0x2ae500>
ffffffff8af23ccd:	b9 00 00 12 00       	mov    $0x120000,%ecx
ffffffff8af23cd2:	85 c0                	test   %eax,%eax
ffffffff8af23cd4:	75 1f                	jne    ffffffff8af23cf5 <frame_candidate_563ca0+0x55>
ffffffff8af23cd6:	41 0f b6 c6          	movzbl %r14b,%eax
ffffffff8af23cda:	31 d2                	xor    %edx,%edx
ffffffff8af23cdc:	b9 00 80 12 00       	mov    $0x128000,%ecx
ffffffff8af23ce1:	ff c8                	dec    %eax
ffffffff8af23ce3:	83 f8 01             	cmp    $0x1,%eax
ffffffff8af23ce6:	0f 94 c2             	sete   %dl
ffffffff8af23ce9:	83 ca 48             	or     $0x48,%edx
ffffffff8af23cec:	c1 e2 0e             	shl    $0xe,%edx
ffffffff8af23cef:	83 f8 02             	cmp    $0x2,%eax
ffffffff8af23cf2:	0f 45 ca             	cmovne %edx,%ecx
ffffffff8af23cf5:	89 8b 64 e3 18 00    	mov    %ecx,0x18e364(%rbx)
ffffffff8af23cfb:	89 c9                	mov    %ecx,%ecx
ffffffff8af23cfd:	48 8b 83 28 e3 18 00 	mov    0x18e328(%rbx),%rax
ffffffff8af23d04:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af23d0b:	00 
ffffffff8af23d0c:	48 8d 94 01 00 08 00 	lea    0x800(%rcx,%rax,1),%rdx
ffffffff8af23d13:	00 
ffffffff8af23d14:	74 07                	je     ffffffff8af23d1d <frame_candidate_563ca0+0x7d>
ffffffff8af23d16:	8b 02                	mov    (%rdx),%eax
ffffffff8af23d18:	83 c8 01             	or     $0x1,%eax
ffffffff8af23d1b:	eb 24                	jmp    ffffffff8af23d41 <frame_candidate_563ca0+0xa1>
ffffffff8af23d1d:	ed                   	in     (%dx),%eax
ffffffff8af23d1e:	ba 00 08 00 00       	mov    $0x800,%edx
ffffffff8af23d23:	03 93 64 e3 18 00    	add    0x18e364(%rbx),%edx
ffffffff8af23d29:	83 c8 01             	or     $0x1,%eax
ffffffff8af23d2c:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af23d33:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af23d3a:	00 
ffffffff8af23d3b:	0f 84 95 00 00 00    	je     ffffffff8af23dd6 <frame_candidate_563ca0+0x136>
ffffffff8af23d41:	89 02                	mov    %eax,(%rdx)
ffffffff8af23d43:	8b 93 64 e3 18 00    	mov    0x18e364(%rbx),%edx
ffffffff8af23d49:	b9 08 08 00 00       	mov    $0x808,%ecx
ffffffff8af23d4e:	01 ca                	add    %ecx,%edx
ffffffff8af23d50:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af23d57:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af23d5e:	00 
ffffffff8af23d5f:	74 09                	je     ffffffff8af23d6a <frame_candidate_563ca0+0xca>
ffffffff8af23d61:	b8 ff ff fd ff       	mov    $0xfffdffff,%eax
ffffffff8af23d66:	23 02                	and    (%rdx),%eax
ffffffff8af23d68:	eb 20                	jmp    ffffffff8af23d8a <frame_candidate_563ca0+0xea>
ffffffff8af23d6a:	ed                   	in     (%dx),%eax
ffffffff8af23d6b:	03 8b 64 e3 18 00    	add    0x18e364(%rbx),%ecx
ffffffff8af23d71:	25 ff ff fd ff       	and    $0xfffdffff,%eax
ffffffff8af23d76:	48 03 8b 28 e3 18 00 	add    0x18e328(%rbx),%rcx
ffffffff8af23d7d:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af23d84:	00 
ffffffff8af23d85:	74 55                	je     ffffffff8af23ddc <frame_candidate_563ca0+0x13c>
ffffffff8af23d87:	48 89 ca             	mov    %rcx,%rdx
ffffffff8af23d8a:	89 02                	mov    %eax,(%rdx)
ffffffff8af23d8c:	8b 93 64 e3 18 00    	mov    0x18e364(%rbx),%edx
ffffffff8af23d92:	b9 80 08 00 00       	mov    $0x880,%ecx
ffffffff8af23d97:	01 ca                	add    %ecx,%edx
ffffffff8af23d99:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af23da0:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af23da7:	00 
ffffffff8af23da8:	74 07                	je     ffffffff8af23db1 <frame_candidate_563ca0+0x111>
ffffffff8af23daa:	8b 02                	mov    (%rdx),%eax
ffffffff8af23dac:	83 c8 01             	or     $0x1,%eax
ffffffff8af23daf:	eb 1e                	jmp    ffffffff8af23dcf <frame_candidate_563ca0+0x12f>
ffffffff8af23db1:	ed                   	in     (%dx),%eax
ffffffff8af23db2:	03 8b 64 e3 18 00    	add    0x18e364(%rbx),%ecx
ffffffff8af23db8:	83 c8 01             	or     $0x1,%eax
ffffffff8af23dbb:	48 03 8b 28 e3 18 00 	add    0x18e328(%rbx),%rcx
ffffffff8af23dc2:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af23dc9:	00 
ffffffff8af23dca:	74 15                	je     ffffffff8af23de1 <frame_candidate_563ca0+0x141>
ffffffff8af23dcc:	48 89 ca             	mov    %rcx,%rdx
ffffffff8af23dcf:	89 02                	mov    %eax,(%rdx)
ffffffff8af23dd1:	5b                   	pop    %rbx
ffffffff8af23dd2:	41 5e                	pop    %r14
ffffffff8af23dd4:	5d                   	pop    %rbp
ffffffff8af23dd5:	c3                   	ret
ffffffff8af23dd6:	ef                   	out    %eax,(%dx)
ffffffff8af23dd7:	e9 67 ff ff ff       	jmp    ffffffff8af23d43 <frame_candidate_563ca0+0xa3>
ffffffff8af23ddc:	89 ca                	mov    %ecx,%edx
ffffffff8af23dde:	ef                   	out    %eax,(%dx)
ffffffff8af23ddf:	eb ab                	jmp    ffffffff8af23d8c <frame_candidate_563ca0+0xec>
ffffffff8af23de1:	89 ca                	mov    %ecx,%edx
ffffffff8af23de3:	ef                   	out    %eax,(%dx)
ffffffff8af23de4:	eb eb                	jmp    ffffffff8af23dd1 <frame_candidate_563ca0+0x131>
ffffffff8af23de6:	90                   	nop
ffffffff8af23de7:	90                   	nop
ffffffff8af23de8:	90                   	nop
ffffffff8af23de9:	90                   	nop
ffffffff8af23dea:	90                   	nop
ffffffff8af23deb:	90                   	nop
ffffffff8af23dec:	90                   	nop
ffffffff8af23ded:	90                   	nop
ffffffff8af23dee:	90                   	nop
ffffffff8af23def:	90                   	nop

ffffffff8af23df0 <frame_candidate_563df0>:
ffffffff8af23df0:	55                   	push   %rbp
ffffffff8af23df1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8af23df4:	5d                   	pop    %rbp
ffffffff8af23df5:	c3                   	ret
ffffffff8af23df6:	90                   	nop
ffffffff8af23df7:	90                   	nop
ffffffff8af23df8:	90                   	nop
ffffffff8af23df9:	90                   	nop
ffffffff8af23dfa:	90                   	nop
ffffffff8af23dfb:	90                   	nop
ffffffff8af23dfc:	90                   	nop
ffffffff8af23dfd:	90                   	nop
ffffffff8af23dfe:	90                   	nop
ffffffff8af23dff:	90                   	nop

ffffffff8af23e00 <frame_candidate_563e00>:
ffffffff8af23e00:	55                   	push   %rbp
ffffffff8af23e01:	48 89 e5             	mov    %rsp,%rbp
ffffffff8af23e04:	41 56                	push   %r14
ffffffff8af23e06:	53                   	push   %rbx
ffffffff8af23e07:	48 89 fb             	mov    %rdi,%rbx
ffffffff8af23e0a:	48 8b bf 38 dc 18 00 	mov    0x18dc38(%rdi),%rdi
ffffffff8af23e11:	41 89 f6             	mov    %esi,%r14d
ffffffff8af23e14:	e8 c7 fd d4 ff       	call   ffffffff8ac73be0 <handler_631_body-0x2ae500>
ffffffff8af23e19:	85 c0                	test   %eax,%eax
ffffffff8af23e1b:	75 7e                	jne    ffffffff8af23e9b <frame_candidate_563e00+0x9b>
ffffffff8af23e1d:	48 8b bb 38 dc 18 00 	mov    0x18dc38(%rbx),%rdi
ffffffff8af23e24:	e8 b7 fd d4 ff       	call   ffffffff8ac73be0 <handler_631_body-0x2ae500>
ffffffff8af23e29:	b9 00 00 12 00       	mov    $0x120000,%ecx
ffffffff8af23e2e:	85 c0                	test   %eax,%eax
ffffffff8af23e30:	75 1f                	jne    ffffffff8af23e51 <frame_candidate_563e00+0x51>
ffffffff8af23e32:	41 0f b6 c6          	movzbl %r14b,%eax
ffffffff8af23e36:	31 d2                	xor    %edx,%edx
ffffffff8af23e38:	b9 00 80 12 00       	mov    $0x128000,%ecx
ffffffff8af23e3d:	ff c8                	dec    %eax
ffffffff8af23e3f:	83 f8 01             	cmp    $0x1,%eax
ffffffff8af23e42:	0f 94 c2             	sete   %dl
ffffffff8af23e45:	83 ca 48             	or     $0x48,%edx
ffffffff8af23e48:	c1 e2 0e             	shl    $0xe,%edx
ffffffff8af23e4b:	83 f8 02             	cmp    $0x2,%eax
ffffffff8af23e4e:	0f 45 ca             	cmovne %edx,%ecx
ffffffff8af23e51:	89 8b 64 e3 18 00    	mov    %ecx,0x18e364(%rbx)
ffffffff8af23e57:	89 c9                	mov    %ecx,%ecx
ffffffff8af23e59:	48 8b 83 28 e3 18 00 	mov    0x18e328(%rbx),%rax
ffffffff8af23e60:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af23e67:	00 
ffffffff8af23e68:	48 8d 94 01 80 08 00 	lea    0x880(%rcx,%rax,1),%rdx
ffffffff8af23e6f:	00 
ffffffff8af23e70:	74 07                	je     ffffffff8af23e79 <frame_candidate_563e00+0x79>
ffffffff8af23e72:	8b 02                	mov    (%rdx),%eax
ffffffff8af23e74:	83 e0 fe             	and    $0xfffffffe,%eax
ffffffff8af23e77:	eb 20                	jmp    ffffffff8af23e99 <frame_candidate_563e00+0x99>
ffffffff8af23e79:	ed                   	in     (%dx),%eax
ffffffff8af23e7a:	ba 80 08 00 00       	mov    $0x880,%edx
ffffffff8af23e7f:	03 93 64 e3 18 00    	add    0x18e364(%rbx),%edx
ffffffff8af23e85:	83 e0 fe             	and    $0xfffffffe,%eax
ffffffff8af23e88:	48 03 93 28 e3 18 00 	add    0x18e328(%rbx),%rdx
ffffffff8af23e8f:	48 83 bb 20 e3 18 00 	cmpq   $0x0,0x18e320(%rbx)
ffffffff8af23e96:	00 
ffffffff8af23e97:	74 07                	je     ffffffff8af23ea0 <frame_candidate_563e00+0xa0>
ffffffff8af23e99:	89 02                	mov    %eax,(%rdx)
ffffffff8af23e9b:	5b                   	pop    %rbx
ffffffff8af23e9c:	41 5e                	pop    %r14
ffffffff8af23e9e:	5d                   	pop    %rbp
ffffffff8af23e9f:	c3                   	ret
ffffffff8af23ea0:	ef                   	out    %eax,(%dx)
ffffffff8af23ea1:	eb f8                	jmp    ffffffff8af23e9b <frame_candidate_563e00+0x9b>
ffffffff8af23ea3:	90                   	nop
ffffffff8af23ea4:	90                   	nop
ffffffff8af23ea5:	90                   	nop
ffffffff8af23ea6:	90                   	nop
ffffffff8af23ea7:	90                   	nop
ffffffff8af23ea8:	90                   	nop
ffffffff8af23ea9:	90                   	nop
ffffffff8af23eaa:	90                   	nop
ffffffff8af23eab:	90                   	nop
ffffffff8af23eac:	90                   	nop
ffffffff8af23ead:	90                   	nop
ffffffff8af23eae:	90                   	nop
ffffffff8af23eaf:	90                   	nop

ffffffff8af23eb0 <frame_candidate_563eb0>:
ffffffff8af23eb0:	55                   	push   %rbp
ffffffff8af23eb1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8af23eb4:	48 83 ec 10          	sub    $0x10,%rsp
ffffffff8af23eb8:	48 89 3c 24          	mov    %rdi,(%rsp)
ffffffff8af23ebc:	48 8d 3d 32 cc e4 00 	lea    0xe4cc32(%rip),%rdi        # ffffffff8bd70af5 <frame_candidate_563fd0+0xe4cb25>
ffffffff8af23ec3:	41 b9 01 00 00 00    	mov    $0x1,%r9d
ffffffff8af23ec9:	31 f6                	xor    %esi,%esi
ffffffff8af23ecb:	31 d2                	xor    %edx,%edx
ffffffff8af23ecd:	31 c9                	xor    %ecx,%ecx
ffffffff8af23ecf:	45 31 c0             	xor    %r8d,%r8d
ffffffff8af23ed2:	e8 29 03 04 00       	call   ffffffff8af64200 <frame_candidate_563fd0+0x40230>
ffffffff8af23ed7:	48 83 c4 10          	add    $0x10,%rsp
ffffffff8af23edb:	5d                   	pop    %rbp
ffffffff8af23edc:	c3                   	ret
ffffffff8af23edd:	90                   	nop
ffffffff8af23ede:	90                   	nop
ffffffff8af23edf:	90                   	nop

ffffffff8af23ee0 <frame_candidate_563ee0>:
ffffffff8af23ee0:	55                   	push   %rbp
ffffffff8af23ee1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8af23ee4:	41 57                	push   %r15
ffffffff8af23ee6:	41 56                	push   %r14
ffffffff8af23ee8:	53                   	push   %rbx
ffffffff8af23ee9:	48 81 ec 88 00 00 00 	sub    $0x88,%rsp
ffffffff8af23ef0:	4c 8d 3d 19 84 3b 03 	lea    0x33b8419(%rip),%r15        # ffffffff8e2dc310 <frame_candidate_563fd0+0x33b8340>
ffffffff8af23ef7:	48 8d 9d 60 ff ff ff 	lea    -0xa0(%rbp),%rbx
ffffffff8af23efe:	49 89 fe             	mov    %rdi,%r14
ffffffff8af23f01:	be 80 00 00 00       	mov    $0x80,%esi
ffffffff8af23f06:	48 89 df             	mov    %rbx,%rdi
ffffffff8af23f09:	49 8b 07             	mov    (%r15),%rax
ffffffff8af23f0c:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
ffffffff8af23f10:	e8 db 50 cf ff       	call   ffffffff8ac18ff0 <handler_631_body-0x3090f0>
ffffffff8af23f15:	4c 89 f7             	mov    %r14,%rdi
ffffffff8af23f18:	48 89 de             	mov    %rbx,%rsi
ffffffff8af23f1b:	48 89 da             	mov    %rbx,%rdx
ffffffff8af23f1e:	66 c7 85 60 ff ff ff 	movw   $0xffff,-0xa0(%rbp)
ffffffff8af23f25:	ff ff 
ffffffff8af23f27:	e8 e4 06 04 00       	call   ffffffff8af64610 <frame_candidate_563fd0+0x40640>
ffffffff8af23f2c:	85 c0                	test   %eax,%eax
ffffffff8af23f2e:	74 20                	je     ffffffff8af23f50 <frame_candidate_563ee0+0x70>
ffffffff8af23f30:	89 c3                	mov    %eax,%ebx
ffffffff8af23f32:	48 8d 3d 15 a5 e2 00 	lea    0xe2a515(%rip),%rdi        # ffffffff8bd4e44e <frame_candidate_563fd0+0xe2a47e>
ffffffff8af23f39:	48 8d 35 c8 d2 d3 00 	lea    0xd3d2c8(%rip),%rsi        # ffffffff8bc61208 <frame_candidate_563fd0+0xd3d238>
ffffffff8af23f40:	ba 38 00 00 00       	mov    $0x38,%edx
ffffffff8af23f45:	89 d9                	mov    %ebx,%ecx
ffffffff8af23f47:	31 c0                	xor    %eax,%eax
ffffffff8af23f49:	e8 c2 94 cf ff       	call   ffffffff8ac1d410 <handler_631_body-0x304cd0>
ffffffff8af23f4e:	eb 2a                	jmp    ffffffff8af23f7a <frame_candidate_563ee0+0x9a>
ffffffff8af23f50:	8b 8d 64 ff ff ff    	mov    -0x9c(%rbp),%ecx
ffffffff8af23f56:	85 c9                	test   %ecx,%ecx
ffffffff8af23f58:	74 39                	je     ffffffff8af23f93 <frame_candidate_563ee0+0xb3>
ffffffff8af23f5a:	48 8d 3d 9f bf de 00 	lea    0xdebf9f(%rip),%rdi        # ffffffff8bd0ff00 <frame_candidate_563fd0+0xdebf30>
ffffffff8af23f61:	48 8d 35 a0 d2 d3 00 	lea    0xd3d2a0(%rip),%rsi        # ffffffff8bc61208 <frame_candidate_563fd0+0xd3d238>
ffffffff8af23f68:	ba 3c 00 00 00       	mov    $0x3c,%edx
ffffffff8af23f6d:	31 c0                	xor    %eax,%eax
ffffffff8af23f6f:	e8 9c 94 cf ff       	call   ffffffff8ac1d410 <handler_631_body-0x304cd0>
ffffffff8af23f74:	8b 9d 64 ff ff ff    	mov    -0x9c(%rbp),%ebx
ffffffff8af23f7a:	49 8b 07             	mov    (%r15),%rax
ffffffff8af23f7d:	48 3b 45 e0          	cmp    -0x20(%rbp),%rax
ffffffff8af23f81:	75 37                	jne    ffffffff8af23fba <frame_candidate_563ee0+0xda>
ffffffff8af23f83:	89 d8                	mov    %ebx,%eax
ffffffff8af23f85:	48 81 c4 88 00 00 00 	add    $0x88,%rsp
ffffffff8af23f8c:	5b                   	pop    %rbx
ffffffff8af23f8d:	41 5e                	pop    %r14
ffffffff8af23f8f:	41 5f                	pop    %r15
ffffffff8af23f91:	5d                   	pop    %rbp
ffffffff8af23f92:	c3                   	ret
ffffffff8af23f93:	4c 89 f7             	mov    %r14,%rdi
ffffffff8af23f96:	e8 d5 05 04 00       	call   ffffffff8af64570 <frame_candidate_563fd0+0x405a0>
ffffffff8af23f9b:	85 c0                	test   %eax,%eax
ffffffff8af23f9d:	74 17                	je     ffffffff8af23fb6 <frame_candidate_563ee0+0xd6>
ffffffff8af23f9f:	89 c3                	mov    %eax,%ebx
ffffffff8af23fa1:	48 8d 3d 44 a2 d5 00 	lea    0xd5a244(%rip),%rdi        # ffffffff8bc7e1ec <frame_candidate_563fd0+0xd5a21c>
ffffffff8af23fa8:	48 8d 35 59 d2 d3 00 	lea    0xd3d259(%rip),%rsi        # ffffffff8bc61208 <frame_candidate_563fd0+0xd3d238>
ffffffff8af23faf:	ba 41 00 00 00       	mov    $0x41,%edx
ffffffff8af23fb4:	eb 8f                	jmp    ffffffff8af23f45 <frame_candidate_563ee0+0x65>
ffffffff8af23fb6:	31 db                	xor    %ebx,%ebx
ffffffff8af23fb8:	eb c0                	jmp    ffffffff8af23f7a <frame_candidate_563ee0+0x9a>
ffffffff8af23fba:	e8 f1 96 19 00       	call   ffffffff8b0bd6b0 <frame_candidate_563fd0+0x1996e0>
ffffffff8af23fbf:	0f 0b                	ud2
ffffffff8af23fc1:	90                   	nop
ffffffff8af23fc2:	90                   	nop
ffffffff8af23fc3:	90                   	nop
ffffffff8af23fc4:	90                   	nop
ffffffff8af23fc5:	90                   	nop
ffffffff8af23fc6:	90                   	nop
ffffffff8af23fc7:	90                   	nop
ffffffff8af23fc8:	90                   	nop
ffffffff8af23fc9:	90                   	nop
ffffffff8af23fca:	90                   	nop
ffffffff8af23fcb:	90                   	nop
ffffffff8af23fcc:	90                   	nop
ffffffff8af23fcd:	90                   	nop
ffffffff8af23fce:	90                   	nop
ffffffff8af23fcf:	90                   	nop

ffffffff8af23fd0 <frame_candidate_563fd0>:
ffffffff8af23fd0:	55                   	push   %rbp
ffffffff8af23fd1:	48 89 e5             	mov    %rsp,%rbp
ffffffff8af23fd4:	41 57                	push   %r15
ffffffff8af23fd6:	41 56                	push   %r14
ffffffff8af23fd8:	41 55                	push   %r13
ffffffff8af23fda:	41 54                	push   %r12
ffffffff8af23fdc:	53                   	push   %rbx
ffffffff8af23fdd:	48 81 ec 98 00 00 00 	sub    $0x98,%rsp
ffffffff8af23fe4:	48 8d 05 25 83 3b 03 	lea    0x33b8325(%rip),%rax        # ffffffff8e2dc310 <frame_candidate_563fd0+0x33b8340>
ffffffff8af23feb:	48 89 bd 40 ff ff ff 	mov    %rdi,-0xc0(%rbp)
ffffffff8af23ff2:	41 89 f6             	mov    %esi,%r14d
ffffffff8af23ff5:	48 8d bd 50 ff ff ff 	lea    -0xb0(%rbp),%rdi
ffffffff8af23ffc:	be 80 00 00 00       	mov    $0x80,%esi
ffffffff8af24001:	49 89 cc             	mov    %rcx,%r12
ffffffff8af24004:	41 89 d5             	mov    %edx,%r13d
ffffffff8af24007:	48 8b 00             	mov    (%rax),%rax
ffffffff8af2400a:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
ffffffff8af2400e:	e8 dd 4f cf ff       	call   ffffffff8ac18ff0 <handler_631_body-0x3090f0>
ffffffff8af24013:	48 8d 35 06 3a 57 01 	lea    0x1573a06(%rip),%rsi        # ffffffff8c497a20 <frame_candidate_563fd0+0x1573a50>
ffffffff8af2401a:	bf 00 40 00 00       	mov    $0x4000,%edi
ffffffff8af2401f:	ba 02 01 00 00       	mov    $0x102,%edx
ffffffff8af24024:	48 c7 85 50 ff ff ff 	movq   $0x2,-0xb0(%rbp)
ffffffff8af2402b:	02 00 00 00 
ffffffff8af2402f:	e8 1c 4b 6a 00       	call   ffffffff8b5c8b50 <frame_candidate_563fd0+0x6a4b80>
ffffffff8af24034:	48 89 c7             	mov    %rax,%rdi
ffffffff8af24037:	48 89 c3             	mov    %rax,%rbx
ffffffff8af2403a:	e8 f1 a2 37 00       	call   ffffffff8b29e330 <frame_candidate_563fd0+0x37a360>
ffffffff8af2403f:	ba 70 04 00 00       	mov    $0x470,%edx
ffffffff8af24044:	48 89 df             	mov    %rbx,%rdi
ffffffff8af24047:	4c 89 e6             	mov    %r12,%rsi
ffffffff8af2404a:	49 89 c7             	mov    %rax,%r15
ffffffff8af2404d:	4c 89 a5 48 ff ff ff 	mov    %r12,-0xb8(%rbp)
ffffffff8af24054:	e8 57 50 cf ff       	call   ffffffff8ac190b0 <handler_631_body-0x309030>
ffffffff8af24059:	48 8b bd 40 ff ff ff 	mov    -0xc0(%rbp),%rdi
ffffffff8af24060:	48 8d 95 50 ff ff ff 	lea    -0xb0(%rbp),%rdx
ffffffff8af24067:	44 89 b5 58 ff ff ff 	mov    %r14d,-0xa8(%rbp)
ffffffff8af2406e:	44 89 ad 5c ff ff ff 	mov    %r13d,-0xa4(%rbp)
ffffffff8af24075:	4c 89 bd 68 ff ff ff 	mov    %r15,-0x98(%rbp)
ffffffff8af2407c:	49 81 c7 70 04 00 00 	add    $0x470,%r15
ffffffff8af24083:	48 89 d6             	mov    %rdx,%rsi
ffffffff8af24086:	4c 89 bd 70 ff ff ff 	mov    %r15,-0x90(%rbp)
ffffffff8af2408d:	e8 7e 05 04 00       	call   ffffffff8af64610 <frame_candidate_563fd0+0x40640>
ffffffff8af24092:	85 c0                	test   %eax,%eax
ffffffff8af24094:	74 21                	je     ffffffff8af240b7 <frame_candidate_563fd0+0xe7>
ffffffff8af24096:	48 8d 3d 7a 86 d0 00 	lea    0xd0867a(%rip),%rdi        # ffffffff8bc2c717 <frame_candidate_563fd0+0xd08747>
ffffffff8af2409d:	48 8d 35 5a ca e4 00 	lea    0xe4ca5a(%rip),%rsi        # ffffffff8bd70afe <frame_candidate_563fd0+0xe4cb2e>
ffffffff8af240a4:	ba 68 00 00 00       	mov    $0x68,%edx
ffffffff8af240a9:	89 c1                	mov    %eax,%ecx
ffffffff8af240ab:	41 89 c7             	mov    %eax,%r15d
ffffffff8af240ae:	31 c0                	xor    %eax,%eax
ffffffff8af240b0:	e8 5b 93 cf ff       	call   ffffffff8ac1d410 <handler_631_body-0x304cd0>
ffffffff8af240b5:	eb 27                	jmp    ffffffff8af240de <frame_candidate_563fd0+0x10e>
ffffffff8af240b7:	48 8b bd 48 ff ff ff 	mov    -0xb8(%rbp),%rdi
ffffffff8af240be:	44 8b bd 54 ff ff ff 	mov    -0xac(%rbp),%r15d
ffffffff8af240c5:	45 85 ff             	test   %r15d,%r15d
ffffffff8af240c8:	75 14                	jne    ffffffff8af240de <frame_candidate_563fd0+0x10e>
ffffffff8af240ca:	48 8d b3 70 04 00 00 	lea    0x470(%rbx),%rsi
ffffffff8af240d1:	ba 70 04 00 00       	mov    $0x470,%edx
ffffffff8af240d6:	e8 d5 4f cf ff       	call   ffffffff8ac190b0 <handler_631_body-0x309030>
ffffffff8af240db:	45 31 ff             	xor    %r15d,%r15d
ffffffff8af240de:	48                   	rex.W
ffffffff8af240df:	85                   	.byte 0x85
