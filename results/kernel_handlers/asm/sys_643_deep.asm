
/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/deep_643.bin:     file format binary


Disassembly of section .data:

0000000000a37660 <.data>:
  a37660:	55                                              	push   rbp
  a37661:	48 89 e5                                        	mov    rbp,rsp
  a37664:	41 56                                           	push   r14
  a37666:	53                                              	push   rbx
  a37667:	48 89 f3                                        	mov    rbx,rsi
  a3766a:	8b 36                                           	mov    esi,DWORD PTR [rsi]
  a3766c:	49 89 fe                                        	mov    r14,rdi
  a3766f:	48 8d 3d 6c a2 92 00                            	lea    rdi,[rip+0x92a26c]        # 0x13618e2
  a37676:	31 c0                                           	xor    eax,eax
  a37678:	e8 93 5d 82 ff                                  	call   0x25d410
  a3767d:	8b 03                                           	mov    eax,DWORD PTR [rbx]
  a3767f:	49 8b 4e 08                                     	mov    rcx,QWORD PTR [r14+0x8]
  a37683:	09 81 34 0a 00 00                               	or     DWORD PTR [rcx+0xa34],eax
  a37689:	31 c0                                           	xor    eax,eax
  a3768b:	5b                                              	pop    rbx
  a3768c:	41 5e                                           	pop    r14
  a3768e:	5d                                              	pop    rbp
  a3768f:	c3                                              	ret
  a37690:	48 8b 47 20                                     	mov    rax,QWORD PTR [rdi+0x20]
  a37694:	48 8d 0d 75 c2 08 01                            	lea    rcx,[rip+0x108c275]        # 0x1ac3910
  a3769b:	0f b6 80 9d 00 00 00                            	movzx  eax,BYTE PTR [rax+0x9d]
  a376a2:	48 8b 04 c1                                     	mov    rax,QWORD PTR [rcx+rax*8]
  a376a6:	48 8b 48 40                                     	mov    rcx,QWORD PTR [rax+0x40]
  a376aa:	48 85 c9                                        	test   rcx,rcx
  a376ad:	74 18                                           	je     0xa376c7
  a376af:	48 8d 05 1a dc 82 ff                            	lea    rax,[rip+0xffffffffff82dc1a]        # 0x2652d0
  a376b6:	48 29 c8                                        	sub    rax,rcx
  a376b9:	48 c1 c8 03                                     	ror    rax,0x3
  a376bd:	48 3d bc 08 00 00                               	cmp    rax,0x8bc
  a376c3:	77 03                                           	ja     0xa376c8
  a376c5:	ff e1                                           	jmp    rcx
  a376c7:	c3                                              	ret
  a376c8:	55                                              	push   rbp
  a376c9:	48 89 e5                                        	mov    rbp,rsp
  a376cc:	41 56                                           	push   r14
  a376ce:	53                                              	push   rbx
  a376cf:	48 8d 05 da 0f b3 01                            	lea    rax,[rip+0x1b30fda]        # 0x25686b0
  a376d6:	48 89 fb                                        	mov    rbx,rdi
  a376d9:	48 89 ce                                        	mov    rsi,rcx
  a376dc:	49 89 ce                                        	mov    r14,rcx
  a376df:	48 89 c7                                        	mov    rdi,rax
  a376e2:	e8 d9 81 a1 ff                                  	call   0x44f8c0
  a376e7:	4c 89 f1                                        	mov    rcx,r14
  a376ea:	48 89 df                                        	mov    rdi,rbx
  a376ed:	5b                                              	pop    rbx
  a376ee:	41 5e                                           	pop    r14
  a376f0:	5d                                              	pop    rbp
  a376f1:	ff e1                                           	jmp    rcx
  a376f3:	90                                              	nop
  a376f4:	90                                              	nop
  a376f5:	90                                              	nop
  a376f6:	90                                              	nop
  a376f7:	90                                              	nop
  a376f8:	90                                              	nop
  a376f9:	90                                              	nop
  a376fa:	90                                              	nop
  a376fb:	90                                              	nop
  a376fc:	90                                              	nop
  a376fd:	90                                              	nop
  a376fe:	90                                              	nop
  a376ff:	90                                              	nop
  a37700:	55                                              	push   rbp
  a37701:	48 89 e5                                        	mov    rbp,rsp
  a37704:	41 57                                           	push   r15
  a37706:	41 56                                           	push   r14
  a37708:	41 55                                           	push   r13
  a3770a:	41 54                                           	push   r12
  a3770c:	53                                              	push   rbx
  a3770d:	48 81 ec 38 01 00 00                            	sub    rsp,0x138
  a37714:	4c 8d 2d f5 4b ee 02                            	lea    r13,[rip+0x2ee4bf5]        # 0x391c310
  a3771b:	48 89 fb                                        	mov    rbx,rdi
  a3771e:	48 8d 35 8b 14 b3 01                            	lea    rsi,[rip+0x1b3148b]        # 0x2568bb0
  a37725:	49 8b 45 00                                     	mov    rax,QWORD PTR [r13+0x0]
  a37729:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  a3772d:	65 4c 8b 34 25 00 00 00 00                      	mov    r14,QWORD PTR gs:0x0
  a37736:	48 8b bf a8 00 00 00                            	mov    rdi,QWORD PTR [rdi+0xa8]
  a3773d:	e8 5e 95 ba ff                                  	call   0x5e0ca0
  a37742:	41 bf 16 00 00 00                               	mov    r15d,0x16
  a37748:	85 c0                                           	test   eax,eax
  a3774a:	0f 85 52 03 00 00                               	jne    0xa37aa2
  a37750:	48 83 3d 38 7c 1b 03 00                         	cmp    QWORD PTR [rip+0x31b7c38],0x0        # 0x3bef390
  a37758:	74 15                                           	je     0xa3776f
  a3775a:	f6 83 9a 00 00 00 01                            	test   BYTE PTR [rbx+0x9a],0x1
  a37761:	0f 85 bd 00 00 00                               	jne    0xa37824
  a37767:	45 31 e4                                        	xor    r12d,r12d
  a3776a:	e9 82 02 00 00                                  	jmp    0xa379f1
  a3776f:	48 8d 3d 82 53 8f 00                            	lea    rdi,[rip+0x8f5382]        # 0x132caf8
  a37776:	be 10 01 00 00                                  	mov    esi,0x110
  a3777b:	31 d2                                           	xor    edx,edx
  a3777d:	31 c9                                           	xor    ecx,ecx
  a3777f:	45 31 c0                                        	xor    r8d,r8d
  a37782:	45 31 c9                                        	xor    r9d,r9d
  a37785:	6a 00                                           	push   0x0
  a37787:	6a 07                                           	push   0x7
  a37789:	e8 52 39 a0 ff                                  	call   0x43b0e0
  a3778e:	48 83 c4 10                                     	add    rsp,0x10
  a37792:	48 89 05 f7 7b 1b 03                            	mov    QWORD PTR [rip+0x31b7bf7],rax        # 0x3bef390
  a37799:	48 8d 3d f2 37 97 00                            	lea    rdi,[rip+0x9737f2]        # 0x13aaf92
  a377a0:	be a8 00 00 00                                  	mov    esi,0xa8
  a377a5:	31 d2                                           	xor    edx,edx
  a377a7:	31 c9                                           	xor    ecx,ecx
  a377a9:	45 31 c0                                        	xor    r8d,r8d
  a377ac:	45 31 c9                                        	xor    r9d,r9d
  a377af:	6a 00                                           	push   0x0
  a377b1:	6a 07                                           	push   0x7
  a377b3:	e8 28 39 a0 ff                                  	call   0x43b0e0
  a377b8:	48 83 c4 10                                     	add    rsp,0x10
  a377bc:	48 89 05 d5 7b 1b 03                            	mov    QWORD PTR [rip+0x31b7bd5],rax        # 0x3bef398
  a377c3:	48 8d 3d f5 86 87 00                            	lea    rdi,[rip+0x8786f5]        # 0x12afebf
  a377ca:	be c8 02 00 00                                  	mov    esi,0x2c8
  a377cf:	31 d2                                           	xor    edx,edx
  a377d1:	31 c9                                           	xor    ecx,ecx
  a377d3:	45 31 c0                                        	xor    r8d,r8d
  a377d6:	45 31 c9                                        	xor    r9d,r9d
  a377d9:	6a 00                                           	push   0x0
  a377db:	6a 07                                           	push   0x7
  a377dd:	e8 fe 38 a0 ff                                  	call   0x43b0e0
  a377e2:	48 83 c4 10                                     	add    rsp,0x10
  a377e6:	48 89 05 b3 7b 1b 03                            	mov    QWORD PTR [rip+0x31b7bb3],rax        # 0x3bef3a0
  a377ed:	48 8d 3d 2c db 95 00                            	lea    rdi,[rip+0x95db2c]        # 0x1395320
  a377f4:	be 10 03 00 00                                  	mov    esi,0x310
  a377f9:	31 d2                                           	xor    edx,edx
  a377fb:	31 c9                                           	xor    ecx,ecx
  a377fd:	45 31 c0                                        	xor    r8d,r8d
  a37800:	45 31 c9                                        	xor    r9d,r9d
  a37803:	6a 00                                           	push   0x0
  a37805:	6a 07                                           	push   0x7
  a37807:	e8 d4 38 a0 ff                                  	call   0x43b0e0
  a3780c:	48 83 c4 10                                     	add    rsp,0x10
  a37810:	48 89 05 91 7b 1b 03                            	mov    QWORD PTR [rip+0x31b7b91],rax        # 0x3bef3a8
  a37817:	f6 83 9a 00 00 00 01                            	test   BYTE PTR [rbx+0x9a],0x1
  a3781e:	0f 84 43 ff ff ff                               	je     0xa37767
  a37824:	4c 8b a3 98 02 00 00                            	mov    r12,QWORD PTR [rbx+0x298]
  a3782b:	4d 8b 7c 24 30                                  	mov    r15,QWORD PTR [r12+0x30]
  a37830:	41 0f b6 47 1a                                  	movzx  eax,BYTE PTR [r15+0x1a]
  a37835:	84 c0                                           	test   al,al
  a37837:	0f 84 00 01 00 00                               	je     0xa3793d
  a3783d:	3c 01                                           	cmp    al,0x1
  a3783f:	0f 85 ac 01 00 00                               	jne    0xa379f1
  a37845:	48 8b bb a8 00 00 00                            	mov    rdi,QWORD PTR [rbx+0xa8]
  a3784c:	48 8d 35 6e 9a 84 00                            	lea    rsi,[rip+0x849a6e]        # 0x12812c1
  a37853:	4c 89 bd a8 fe ff ff                            	mov    QWORD PTR [rbp-0x158],r15
  a3785a:	45 31 ff                                        	xor    r15d,r15d
  a3785d:	31 d2                                           	xor    edx,edx
  a3785f:	31 c9                                           	xor    ecx,ecx
  a37861:	e8 ea 99 ba ff                                  	call   0x5e1250
  a37866:	85 c0                                           	test   eax,eax
  a37868:	0f 85 83 01 00 00                               	jne    0xa379f1
  a3786e:	4c 89 a5 a0 fe ff ff                            	mov    QWORD PTR [rbp-0x160],r12
  a37875:	4d 8b 64 24 20                                  	mov    r12,QWORD PTR [r12+0x20]
  a3787a:	48 8d 15 5a 39 95 00                            	lea    rdx,[rip+0x95395a]        # 0x138b1db
  a37881:	be 00 04 08 00                                  	mov    esi,0x80400
  a37886:	b9 1b 02 00 00                                  	mov    ecx,0x21b
  a3788b:	4c 89 e7                                        	mov    rdi,r12
  a3788e:	e8 bd 82 c7 ff                                  	call   0x6afb50
  a37893:	49 8b 86 40 01 00 00                            	mov    rax,QWORD PTR [r14+0x140]
  a3789a:	48 8d 0d d7 31 0a 01                            	lea    rcx,[rip+0x10a31d7]        # 0x1adaa78
  a378a1:	48 8d b5 e8 fe ff ff                            	lea    rsi,[rbp-0x118]
  a378a8:	48 89 8d e8 fe ff ff                            	mov    QWORD PTR [rbp-0x118],rcx
  a378af:	4c 89 a5 f0 fe ff ff                            	mov    QWORD PTR [rbp-0x110],r12
  a378b6:	c7 85 f8 fe ff ff 80 01 00 00                   	mov    DWORD PTR [rbp-0x108],0x180
  a378c0:	48 89 85 00 ff ff ff                            	mov    QWORD PTR [rbp-0x100],rax
  a378c7:	4c 89 b5 08 ff ff ff                            	mov    QWORD PTR [rbp-0xf8],r14
  a378ce:	49 8b 7c 24 08                                  	mov    rdi,QWORD PTR [r12+0x8]
  a378d3:	e8 28 45 b5 ff                                  	call   0x58be00
  a378d8:	85 c0                                           	test   eax,eax
  a378da:	74 10                                           	je     0xa378ec
  a378dc:	4c 89 f7                                        	mov    rdi,r14
  a378df:	be 50 01 00 00                                  	mov    esi,0x150
  a378e4:	e8 47 81 0a 00                                  	call   0xadfa30
  a378e9:	41 89 c7                                        	mov    r15d,eax
  a378ec:	48 8d 05 d5 54 0a 01                            	lea    rax,[rip+0x10a54d5]        # 0x1adcdc8
  a378f3:	48 8d b5 e8 fe ff ff                            	lea    rsi,[rbp-0x118]
  a378fa:	48 89 85 e8 fe ff ff                            	mov    QWORD PTR [rbp-0x118],rax
  a37901:	4c 89 a5 f0 fe ff ff                            	mov    QWORD PTR [rbp-0x110],r12
  a37908:	c7 85 f8 fe ff ff 00 00 00 00                   	mov    DWORD PTR [rbp-0x108],0x0
  a37912:	49 8b 7c 24 08                                  	mov    rdi,QWORD PTR [r12+0x8]
  a37917:	e8 74 71 b5 ff                                  	call   0x58ea90
  a3791c:	45 85 ff                                        	test   r15d,r15d
  a3791f:	0f 84 1e 03 00 00                               	je     0xa37c43
  a37925:	48 8d 3d ea 28 85 00                            	lea    rdi,[rip+0x8528ea]        # 0x128a216
  a3792c:	48 8d 35 74 f7 91 00                            	lea    rsi,[rip+0x91f774]        # 0x13570a7
  a37933:	ba 26 02 00 00                                  	mov    edx,0x226
  a37938:	e9 58 01 00 00                                  	jmp    0xa37a95
  a3793d:	48 8b bb a8 00 00 00                            	mov    rdi,QWORD PTR [rbx+0xa8]
  a37944:	48 8d 35 76 99 84 00                            	lea    rsi,[rip+0x849976]        # 0x12812c1
  a3794b:	31 d2                                           	xor    edx,edx
  a3794d:	31 c9                                           	xor    ecx,ecx
  a3794f:	e8 fc 98 ba ff                                  	call   0x5e1250
  a37954:	85 c0                                           	test   eax,eax
  a37956:	0f 84 88 00 00 00                               	je     0xa379e4
  a3795c:	48 8b 43 40                                     	mov    rax,QWORD PTR [rbx+0x40]
  a37960:	4c 89 a5 a0 fe ff ff                            	mov    QWORD PTR [rbp-0x160],r12
  a37967:	41 bc ff ff ff ff                               	mov    r12d,0xffffffff
  a3796d:	4c 89 bd a8 fe ff ff                            	mov    QWORD PTR [rbp-0x158],r15
  a37974:	8b 78 28                                        	mov    edi,DWORD PTR [rax+0x28]
  a37977:	c1 ef 17                                        	shr    edi,0x17
  a3797a:	83 e7 02                                        	and    edi,0x2
  a3797d:	74 08                                           	je     0xa37987
  a3797f:	e8 6c a3 b2 ff                                  	call   0x561cf0
  a37984:	41 89 c4                                        	mov    r12d,eax
  a37987:	48 8b 43 38                                     	mov    rax,QWORD PTR [rbx+0x38]
  a3798b:	4c 8b 78 30                                     	mov    r15,QWORD PTR [rax+0x30]
  a3798f:	48 8d 05 4a 17 83 ff                            	lea    rax,[rip+0xffffffffff83174a]        # 0x2690e0
  a37996:	4c 29 f8                                        	sub    rax,r15
  a37999:	48 c1 c8 03                                     	ror    rax,0x3
  a3799d:	48 83 f8 72                                     	cmp    rax,0x72
  a379a1:	0f 87 91 04 00 00                               	ja     0xa37e38
  a379a7:	48 89 df                                        	mov    rdi,rbx
  a379aa:	be 01 00 00 00                                  	mov    esi,0x1
  a379af:	41 ff d7                                        	call   r15
  a379b2:	41 89 c7                                        	mov    r15d,eax
  a379b5:	41 83 fc ff                                     	cmp    r12d,0xffffffff
  a379b9:	74 08                                           	je     0xa379c3
  a379bb:	44 89 e7                                        	mov    edi,r12d
  a379be:	e8 1d a4 b2 ff                                  	call   0x561de0
  a379c3:	45 85 ff                                        	test   r15d,r15d
  a379c6:	0f 84 0f 02 00 00                               	je     0xa37bdb
  a379cc:	48 8d 3d 43 28 85 00                            	lea    rdi,[rip+0x852843]        # 0x128a216
  a379d3:	48 8d 35 cd f6 91 00                            	lea    rsi,[rip+0x91f6cd]        # 0x13570a7
  a379da:	ba ef 01 00 00                                  	mov    edx,0x1ef
  a379df:	e9 b1 00 00 00                                  	jmp    0xa37a95
  a379e4:	41 0f b6 47 1a                                  	movzx  eax,BYTE PTR [r15+0x1a]
  a379e9:	3c 01                                           	cmp    al,0x1
  a379eb:	0f 84 54 fe ff ff                               	je     0xa37845
  a379f1:	48 8b bb a8 00 00 00                            	mov    rdi,QWORD PTR [rbx+0xa8]
  a379f8:	48 8d 35 a2 b3 87 00                            	lea    rsi,[rip+0x87b3a2]        # 0x12b2da1
  a379ff:	48 8d 95 b0 fe ff ff                            	lea    rdx,[rbp-0x150]
  a37a06:	31 c9                                           	xor    ecx,ecx
  a37a08:	e8 c3 75 ba ff                                  	call   0x5defd0
  a37a0d:	85 c0                                           	test   eax,eax
  a37a0f:	74 26                                           	je     0xa37a37
  a37a11:	48 8d 3d fe 27 85 00                            	lea    rdi,[rip+0x8527fe]        # 0x128a216
  a37a18:	48 8d 35 88 f6 91 00                            	lea    rsi,[rip+0x91f688]        # 0x13570a7
  a37a1f:	41 bf 16 00 00 00                               	mov    r15d,0x16
  a37a25:	ba 4e 02 00 00                                  	mov    edx,0x24e
  a37a2a:	b9 16 00 00 00                                  	mov    ecx,0x16
  a37a2f:	41 b8 16 00 00 00                               	mov    r8d,0x16
  a37a35:	eb 64                                           	jmp    0xa37a9b
  a37a37:	4c 8b 85 b0 fe ff ff                            	mov    r8,QWORD PTR [rbp-0x150]
  a37a3e:	48 83 ec 08                                     	sub    rsp,0x8
  a37a42:	4c 8d bd e8 fe ff ff                            	lea    r15,[rbp-0x118]
  a37a49:	ba 44 00 00 00                                  	mov    edx,0x44
  a37a4e:	31 f6                                           	xor    esi,esi
  a37a50:	b9 01 00 00 00                                  	mov    ecx,0x1
  a37a55:	41 b9 9c ff ff ff                               	mov    r9d,0xffffff9c
  a37a5b:	4c 89 ff                                        	mov    rdi,r15
  a37a5e:	41 56                                           	push   r14
  a37a60:	6a 00                                           	push   0x0
  a37a62:	6a 00                                           	push   0x0
  a37a64:	e8 77 2c bc ff                                  	call   0x5fa6e0
  a37a69:	48 83 c4 20                                     	add    rsp,0x20
  a37a6d:	4c 89 ff                                        	mov    rdi,r15
  a37a70:	e8 ab 11 bc ff                                  	call   0x5f8c20
  a37a75:	89 85 bc fe ff ff                               	mov    DWORD PTR [rbp-0x144],eax
  a37a7b:	85 c0                                           	test   eax,eax
  a37a7d:	74 46                                           	je     0xa37ac5
  a37a7f:	41 89 c7                                        	mov    r15d,eax
  a37a82:	48 8d 3d 8d 27 85 00                            	lea    rdi,[rip+0x85278d]        # 0x128a216
  a37a89:	48 8d 35 17 f6 91 00                            	lea    rsi,[rip+0x91f617]        # 0x13570a7
  a37a90:	ba 57 02 00 00                                  	mov    edx,0x257
  a37a95:	44 89 f9                                        	mov    ecx,r15d
  a37a98:	45 89 f8                                        	mov    r8d,r15d
  a37a9b:	31 c0                                           	xor    eax,eax
  a37a9d:	e8 6e 59 82 ff                                  	call   0x25d410
  a37aa2:	49 8b 45 00                                     	mov    rax,QWORD PTR [r13+0x0]
  a37aa6:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  a37aaa:	0f 85 81 03 00 00                               	jne    0xa37e31
  a37ab0:	44 89 f8                                        	mov    eax,r15d
  a37ab3:	48 81 c4 38 01 00 00                            	add    rsp,0x138
  a37aba:	5b                                              	pop    rbx
  a37abb:	41 5c                                           	pop    r12
  a37abd:	41 5d                                           	pop    r13
  a37abf:	41 5e                                           	pop    r14
  a37ac1:	41 5f                                           	pop    r15
  a37ac3:	5d                                              	pop    rbp
  a37ac4:	c3                                              	ret
  a37ac5:	4c 8b bd 48 ff ff ff                            	mov    r15,QWORD PTR [rbp-0xb8]
  a37acc:	48 8d bd e8 fe ff ff                            	lea    rdi,[rbp-0x118]
  a37ad3:	be df ff ff ff                                  	mov    esi,0xffffffdf
  a37ad8:	e8 a3 2c bc ff                                  	call   0x5fa780
  a37add:	48 8d b5 bc fe ff ff                            	lea    rsi,[rbp-0x144]
  a37ae4:	4c 89 ff                                        	mov    rdi,r15
  a37ae7:	e8 14 4f b1 ff                                  	call   0x54ca00
  a37aec:	85 c0                                           	test   eax,eax
  a37aee:	0f 84 29 01 00 00                               	je     0xa37c1d
  a37af4:	48 8b 83 98 00 00 00                            	mov    rax,QWORD PTR [rbx+0x98]
  a37afb:	31 c9                                           	xor    ecx,ecx
  a37afd:	48 8d 15 74 2f 0a 01                            	lea    rdx,[rip+0x10a2f74]        # 0x1adaa78
  a37b04:	48 8d b5 c0 fe ff ff                            	lea    rsi,[rbp-0x140]
  a37b0b:	a8 01                                           	test   al,0x1
  a37b0d:	49 8b 86 40 01 00 00                            	mov    rax,QWORD PTR [r14+0x140]
  a37b14:	48 89 95 c0 fe ff ff                            	mov    QWORD PTR [rbp-0x140],rdx
  a37b1b:	4c 89 bd c8 fe ff ff                            	mov    QWORD PTR [rbp-0x138],r15
  a37b22:	0f 94 c1                                        	sete   cl
  a37b25:	83 c9 02                                        	or     ecx,0x2
  a37b28:	c1 e1 07                                        	shl    ecx,0x7
  a37b2b:	89 8d d0 fe ff ff                               	mov    DWORD PTR [rbp-0x130],ecx
  a37b31:	48 89 85 d8 fe ff ff                            	mov    QWORD PTR [rbp-0x128],rax
  a37b38:	4c 89 b5 e0 fe ff ff                            	mov    QWORD PTR [rbp-0x120],r14
  a37b3f:	49 8b 7f 08                                     	mov    rdi,QWORD PTR [r15+0x8]
  a37b43:	e8 b8 42 b5 ff                                  	call   0x58be00
  a37b48:	89 85 bc fe ff ff                               	mov    DWORD PTR [rbp-0x144],eax
  a37b4e:	85 c0                                           	test   eax,eax
  a37b50:	74 3d                                           	je     0xa37b8f
  a37b52:	4c 89 f7                                        	mov    rdi,r14
  a37b55:	be 50 01 00 00                                  	mov    esi,0x150
  a37b5a:	e8 d1 7e 0a 00                                  	call   0xadfa30
  a37b5f:	89 85 bc fe ff ff                               	mov    DWORD PTR [rbp-0x144],eax
  a37b65:	85 c0                                           	test   eax,eax
  a37b67:	74 26                                           	je     0xa37b8f
  a37b69:	4c 89 ff                                        	mov    rdi,r15
  a37b6c:	e8 cf 28 b1 ff                                  	call   0x54a440
  a37b71:	8b 8d bc fe ff ff                               	mov    ecx,DWORD PTR [rbp-0x144]
  a37b77:	48 8d 3d 98 26 85 00                            	lea    rdi,[rip+0x852698]        # 0x128a216
  a37b7e:	48 8d 35 22 f5 91 00                            	lea    rsi,[rip+0x91f522]        # 0x13570a7
  a37b85:	ba 73 02 00 00                                  	mov    edx,0x273
  a37b8a:	e9 8d 01 00 00                                  	jmp    0xa37d1c
  a37b8f:	f6 83 9a 00 00 00 01                            	test   BYTE PTR [rbx+0x9a],0x1
  a37b96:	0f 85 42 01 00 00                               	jne    0xa37cde
  a37b9c:	4c 89 ff                                        	mov    rdi,r15
  a37b9f:	48 89 de                                        	mov    rsi,rbx
  a37ba2:	e8 09 1c 00 00                                  	call   0xa397b0
  a37ba7:	89 85 bc fe ff ff                               	mov    DWORD PTR [rbp-0x144],eax
  a37bad:	85 c0                                           	test   eax,eax
  a37baf:	0f 84 7d 01 00 00                               	je     0xa37d32
  a37bb5:	4c 89 ff                                        	mov    rdi,r15
  a37bb8:	e8 63 25 b1 ff                                  	call   0x54a120
  a37bbd:	8b 8d bc fe ff ff                               	mov    ecx,DWORD PTR [rbp-0x144]
  a37bc3:	48 8d 3d 4c 26 85 00                            	lea    rdi,[rip+0x85264c]        # 0x128a216
  a37bca:	48 8d 35 d6 f4 91 00                            	lea    rsi,[rip+0x91f4d6]        # 0x13570a7
  a37bd1:	ba 88 02 00 00                                  	mov    edx,0x288
  a37bd6:	e9 41 01 00 00                                  	jmp    0xa37d1c
  a37bdb:	b8 13 01 00 00                                  	mov    eax,0x113
  a37be0:	48 89 df                                        	mov    rdi,rbx
  a37be3:	4c 89 f1                                        	mov    rcx,r14
  a37be6:	31 f6                                           	xor    esi,esi
  a37be8:	c4 e2 78 f7 83 98 00 00 00                      	bextr  eax,DWORD PTR [rbx+0x98],eax
  a37bf1:	8d 54 00 04                                     	lea    edx,[rax+rax*1+0x4]
  a37bf5:	e8 66 28 b1 ff                                  	call   0x54a460
  a37bfa:	85 c0                                           	test   eax,eax
  a37bfc:	0f 84 47 01 00 00                               	je     0xa37d49
  a37c02:	41 89 c7                                        	mov    r15d,eax
  a37c05:	48 8d 3d 0a 26 85 00                            	lea    rdi,[rip+0x85260a]        # 0x128a216
  a37c0c:	48 8d 35 94 f4 91 00                            	lea    rsi,[rip+0x91f494]        # 0x13570a7
  a37c13:	ba fb 01 00 00                                  	mov    edx,0x1fb
  a37c18:	e9 78 fe ff ff                                  	jmp    0xa37a95
  a37c1d:	4c 89 ff                                        	mov    rdi,r15
  a37c20:	e8 1b 28 b1 ff                                  	call   0x54a440
  a37c25:	8b 8d bc fe ff ff                               	mov    ecx,DWORD PTR [rbp-0x144]
  a37c2b:	48 8d 3d e4 25 85 00                            	lea    rdi,[rip+0x8525e4]        # 0x128a216
  a37c32:	48 8d 35 6e f4 91 00                            	lea    rsi,[rip+0x91f46e]        # 0x13570a7
  a37c39:	ba 60 02 00 00                                  	mov    edx,0x260
  a37c3e:	e9 d9 00 00 00                                  	jmp    0xa37d1c
  a37c43:	48 8b 85 a8 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x158]
  a37c4a:	80 78 19 01                                     	cmp    BYTE PTR [rax+0x19],0x1
  a37c4e:	75 28                                           	jne    0xa37c78
  a37c50:	f6 83 9a 00 00 00 08                            	test   BYTE PTR [rbx+0x9a],0x8
  a37c57:	41 bf 01 00 00 00                               	mov    r15d,0x1
  a37c5d:	0f 84 3f fe ff ff                               	je     0xa37aa2
  a37c63:	48 8d 3d fc 20 8a 00                            	lea    rdi,[rip+0x8a20fc]        # 0x12d9d66
  a37c6a:	48 8d 35 f8 f3 90 00                            	lea    rsi,[rip+0x90f3f8]        # 0x1347069
  a37c71:	31 c0                                           	xor    eax,eax
  a37c73:	e8 98 57 82 ff                                  	call   0x25d410
  a37c78:	48 8d 3d e9 36 ac 02                            	lea    rdi,[rip+0x2ac36e9]        # 0x34fb368
  a37c7f:	31 f6                                           	xor    esi,esi
  a37c81:	31 d2                                           	xor    edx,edx
  a37c83:	31 c9                                           	xor    ecx,ecx
  a37c85:	e8 96 3e 21 00                                  	call   0xc4bb20
  a37c8a:	4c 8b a5 a0 fe ff ff                            	mov    r12,QWORD PTR [rbp-0x160]
  a37c91:	ba 01 00 00 00                                  	mov    edx,0x1
  a37c96:	31 f6                                           	xor    esi,esi
  a37c98:	31 c9                                           	xor    ecx,ecx
  a37c9a:	49 8b 7c 24 10                                  	mov    rdi,QWORD PTR [r12+0x10]
  a37c9f:	e8 5c 5c dc ff                                  	call   0x7fd900
  a37ca4:	48 8d 3d bd 36 ac 02                            	lea    rdi,[rip+0x2ac36bd]        # 0x34fb368
  a37cab:	41 89 c7                                        	mov    r15d,eax
  a37cae:	89 85 bc fe ff ff                               	mov    DWORD PTR [rbp-0x144],eax
  a37cb4:	31 f6                                           	xor    esi,esi
  a37cb6:	31 d2                                           	xor    edx,edx
  a37cb8:	e8 f3 47 21 00                                  	call   0xc4c4b0
  a37cbd:	45 85 ff                                        	test   r15d,r15d
  a37cc0:	0f 84 dd 00 00 00                               	je     0xa37da3
  a37cc6:	48 8d 3d 49 25 85 00                            	lea    rdi,[rip+0x852549]        # 0x128a216
  a37ccd:	48 8d 35 d3 f3 91 00                            	lea    rsi,[rip+0x91f3d3]        # 0x13570a7
  a37cd4:	ba 3c 02 00 00                                  	mov    edx,0x23c
  a37cd9:	e9 b7 fd ff ff                                  	jmp    0xa37a95
  a37cde:	49 8b 4c 24 20                                  	mov    rcx,QWORD PTR [r12+0x20]
  a37ce3:	49 8b 47 30                                     	mov    rax,QWORD PTR [r15+0x30]
  a37ce7:	48 3b 41 30                                     	cmp    rax,QWORD PTR [rcx+0x30]
  a37ceb:	74 0a                                           	je     0xa37cf7
  a37ced:	c7 85 bc fe ff ff 16 00 00 00                   	mov    DWORD PTR [rbp-0x144],0x16
  a37cf7:	4c 89 ff                                        	mov    rdi,r15
  a37cfa:	e8 41 27 b1 ff                                  	call   0x54a440
  a37cff:	8b 8d bc fe ff ff                               	mov    ecx,DWORD PTR [rbp-0x144]
  a37d05:	85 c9                                           	test   ecx,ecx
  a37d07:	74 29                                           	je     0xa37d32
  a37d09:	48 8d 3d 06 25 85 00                            	lea    rdi,[rip+0x852506]        # 0x128a216
  a37d10:	48 8d 35 90 f3 91 00                            	lea    rsi,[rip+0x91f390]        # 0x13570a7
  a37d17:	ba 81 02 00 00                                  	mov    edx,0x281
  a37d1c:	41 89 c8                                        	mov    r8d,ecx
  a37d1f:	31 c0                                           	xor    eax,eax
  a37d21:	e8 ea 56 82 ff                                  	call   0x25d410
  a37d26:	44 8b bd bc fe ff ff                            	mov    r15d,DWORD PTR [rbp-0x144]
  a37d2d:	e9 70 fd ff ff                                  	jmp    0xa37aa2
  a37d32:	48 8b b5 b0 fe ff ff                            	mov    rsi,QWORD PTR [rbp-0x150]
  a37d39:	48 89 df                                        	mov    rdi,rbx
  a37d3c:	e8 df 96 ba ff                                  	call   0x5e1420
  a37d41:	45 31 ff                                        	xor    r15d,r15d
  a37d44:	e9 59 fd ff ff                                  	jmp    0xa37aa2
  a37d49:	4c 8d 25 18 36 ac 02                            	lea    r12,[rip+0x2ac3618]        # 0x34fb368
  a37d50:	31 f6                                           	xor    esi,esi
  a37d52:	31 d2                                           	xor    edx,edx
  a37d54:	31 c9                                           	xor    ecx,ecx
  a37d56:	4c 89 e7                                        	mov    rdi,r12
  a37d59:	e8 c2 3d 21 00                                  	call   0xc4bb20
  a37d5e:	48 8b 85 a0 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x160]
  a37d65:	ba ff ff ff ff                                  	mov    edx,0xffffffff
  a37d6a:	31 f6                                           	xor    esi,esi
  a37d6c:	31 c9                                           	xor    ecx,ecx
  a37d6e:	48 8b 78 10                                     	mov    rdi,QWORD PTR [rax+0x10]
  a37d72:	e8 89 5b dc ff                                  	call   0x7fd900
  a37d77:	4c 89 e7                                        	mov    rdi,r12
  a37d7a:	41 89 c7                                        	mov    r15d,eax
  a37d7d:	31 f6                                           	xor    esi,esi
  a37d7f:	31 d2                                           	xor    edx,edx
  a37d81:	e8 2a 47 21 00                                  	call   0xc4c4b0
  a37d86:	45 85 ff                                        	test   r15d,r15d
  a37d89:	74 5a                                           	je     0xa37de5
  a37d8b:	48 8d 3d 84 24 85 00                            	lea    rdi,[rip+0x852484]        # 0x128a216
  a37d92:	48 8d 35 0e f3 91 00                            	lea    rsi,[rip+0x91f30e]        # 0x13570a7
  a37d99:	ba 04 02 00 00                                  	mov    edx,0x204
  a37d9e:	e9 f2 fc ff ff                                  	jmp    0xa37a95
  a37da3:	48 8b 85 a8 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x158]
  a37daa:	4c 8d 7b 18                                     	lea    r15,[rbx+0x18]
  a37dae:	31 f6                                           	xor    esi,esi
  a37db0:	31 d2                                           	xor    edx,edx
  a37db2:	31 c9                                           	xor    ecx,ecx
  a37db4:	4c 89 ff                                        	mov    rdi,r15
  a37db7:	c6 40 1a 00                                     	mov    BYTE PTR [rax+0x1a],0x0
  a37dbb:	e8 40 ec a8 ff                                  	call   0x4c6a00
  a37dc0:	80 a3 98 00 00 00 fe                            	and    BYTE PTR [rbx+0x98],0xfe
  a37dc7:	4c 89 ff                                        	mov    rdi,r15
  a37dca:	31 f6                                           	xor    esi,esi
  a37dcc:	31 d2                                           	xor    edx,edx
  a37dce:	31 c9                                           	xor    ecx,ecx
  a37dd0:	e8 cb f1 a8 ff                                  	call   0x4c6fa0
  a37dd5:	48 8b 85 a8 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x158]
  a37ddc:	c6 40 19 00                                     	mov    BYTE PTR [rax+0x19],0x0
  a37de0:	e9 0c fc ff ff                                  	jmp    0xa379f1
  a37de5:	48 8b 85 a8 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x158]
  a37dec:	4c 8d 7b 18                                     	lea    r15,[rbx+0x18]
  a37df0:	31 f6                                           	xor    esi,esi
  a37df2:	31 d2                                           	xor    edx,edx
  a37df4:	31 c9                                           	xor    ecx,ecx
  a37df6:	4c 89 ff                                        	mov    rdi,r15
  a37df9:	c6 40 1a 01                                     	mov    BYTE PTR [rax+0x1a],0x1
  a37dfd:	e8 fe eb a8 ff                                  	call   0x4c6a00
  a37e02:	48 8d 3d 53 83 96 00                            	lea    rdi,[rip+0x968353]        # 0x13a015c
  a37e09:	31 c0                                           	xor    eax,eax
  a37e0b:	e8 00 56 82 ff                                  	call   0x25d410
  a37e10:	80 8b 98 00 00 00 01                            	or     BYTE PTR [rbx+0x98],0x1
  a37e17:	4c 89 ff                                        	mov    rdi,r15
  a37e1a:	31 f6                                           	xor    esi,esi
  a37e1c:	31 d2                                           	xor    edx,edx
  a37e1e:	31 c9                                           	xor    ecx,ecx
  a37e20:	e8 7b f1 a8 ff                                  	call   0x4c6fa0
  a37e25:	4c 8b a5 a0 fe ff ff                            	mov    r12,QWORD PTR [rbp-0x160]
  a37e2c:	e9 c0 fb ff ff                                  	jmp    0xa379f1
  a37e31:	e8 7a 58 cc ff                                  	call   0x6fd6b0
  a37e36:	0f 0b                                           	ud2
  a37e38:	48 8d 3d 41 0e b3 01                            	lea    rdi,[rip+0x1b30e41]        # 0x2568c80
  a37e3f:	4c 89 fe                                        	mov    rsi,r15
  a37e42:	e8 79 7a a1 ff                                  	call   0x44f8c0
  a37e47:	e9 5b fb ff ff                                  	jmp    0xa379a7
  a37e4c:	90                                              	nop
  a37e4d:	90                                              	nop
  a37e4e:	90                                              	nop
  a37e4f:	90                                              	nop
  a37e50:	55                                              	push   rbp
  a37e51:	48 89 e5                                        	mov    rbp,rsp
  a37e54:	41 57                                           	push   r15
  a37e56:	41 56                                           	push   r14
  a37e58:	41 54                                           	push   r12
  a37e5a:	53                                              	push   rbx
  a37e5b:	48 81 ec 40 01 00 00                            	sub    rsp,0x140
  a37e62:	4c 8d 25 a7 44 ee 02                            	lea    r12,[rip+0x2ee44a7]        # 0x391c310
  a37e69:	49 8b 04 24                                     	mov    rax,QWORD PTR [r12]
  a37e6d:	48 89 45 d8                                     	mov    QWORD PTR [rbp-0x28],rax
  a37e71:	48 85 f6                                        	test   rsi,rsi
  a37e74:	74 58                                           	je     0xa37ece
  a37e76:	49 89 fe                                        	mov    r14,rdi
  a37e79:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  a37e82:	49 89 f7                                        	mov    r15,rsi
  a37e85:	48 8d 35 b1 00 96 00                            	lea    rsi,[rip+0x9600b1]        # 0x1397f3d
  a37e8c:	48 89 d3                                        	mov    rbx,rdx
  a37e8f:	31 d2                                           	xor    edx,edx
  a37e91:	e8 4a 25 1e 00                                  	call   0xc1a3e0
  a37e96:	48 8d b5 48 ff ff ff                            	lea    rsi,[rbp-0xb8]
  a37e9d:	ba 90 00 00 00                                  	mov    edx,0x90
  a37ea2:	4c 89 ff                                        	mov    rdi,r15
  a37ea5:	e8 d6 13 82 ff                                  	call   0x259280
  a37eaa:	85 c0                                           	test   eax,eax
  a37eac:	75 25                                           	jne    0xa37ed3
  a37eae:	48 8d bd 50 ff ff ff                            	lea    rdi,[rbp-0xb0]
  a37eb5:	48 8d b5 a8 fe ff ff                            	lea    rsi,[rbp-0x158]
  a37ebc:	e8 5f 97 ba ff                                  	call   0x5e1620
  a37ec1:	4c 89 f7                                        	mov    rdi,r14
  a37ec4:	48 89 de                                        	mov    rsi,rbx
  a37ec7:	e8 84 96 ba ff                                  	call   0x5e1550
  a37ecc:	eb 05                                           	jmp    0xa37ed3
  a37ece:	b8 16 00 00 00                                  	mov    eax,0x16
  a37ed3:	49 8b 0c 24                                     	mov    rcx,QWORD PTR [r12]
  a37ed7:	48 3b 4d d8                                     	cmp    rcx,QWORD PTR [rbp-0x28]
  a37edb:	75 10                                           	jne    0xa37eed
  a37edd:	48 81 c4 40 01 00 00                            	add    rsp,0x140
  a37ee4:	5b                                              	pop    rbx
  a37ee5:	41 5c                                           	pop    r12
  a37ee7:	41 5e                                           	pop    r14
  a37ee9:	41 5f                                           	pop    r15
  a37eeb:	5d                                              	pop    rbp
  a37eec:	c3                                              	ret
  a37eed:	e8 be 57 cc ff                                  	call   0x6fd6b0
  a37ef2:	0f 0b                                           	ud2
  a37ef4:	90                                              	nop
  a37ef5:	90                                              	nop
  a37ef6:	90                                              	nop
  a37ef7:	90                                              	nop
  a37ef8:	90                                              	nop
  a37ef9:	90                                              	nop
  a37efa:	90                                              	nop
  a37efb:	90                                              	nop
  a37efc:	90                                              	nop
  a37efd:	90                                              	nop
  a37efe:	90                                              	nop
  a37eff:	90                                              	nop
  a37f00:	55                                              	push   rbp
  a37f01:	48 89 e5                                        	mov    rbp,rsp
  a37f04:	41 57                                           	push   r15
  a37f06:	41 56                                           	push   r14
  a37f08:	41 55                                           	push   r13
  a37f0a:	41 54                                           	push   r12
  a37f0c:	53                                              	push   rbx
  a37f0d:	48 83 ec 28                                     	sub    rsp,0x28
  a37f11:	4c 8d 25 f8 43 ee 02                            	lea    r12,[rip+0x2ee43f8]        # 0x391c310
  a37f18:	41 89 f5                                        	mov    r13d,esi
  a37f1b:	48 89 f9                                        	mov    rcx,rdi
  a37f1e:	49 8b 04 24                                     	mov    rax,QWORD PTR [r12]
  a37f22:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  a37f26:	48 8b 9f 98 02 00 00                            	mov    rbx,QWORD PTR [rdi+0x298]
  a37f2d:	48 8b 43 30                                     	mov    rax,QWORD PTR [rbx+0x30]
  a37f31:	83 bb 10 04 00 00 00                            	cmp    DWORD PTR [rbx+0x410],0x0
  a37f38:	8b 40 20                                        	mov    eax,DWORD PTR [rax+0x20]
  a37f3b:	48 89 45 c0                                     	mov    QWORD PTR [rbp-0x40],rax
  a37f3f:	0f 88 aa 00 00 00                               	js     0xa37fef
  a37f45:	48 8b 41 40                                     	mov    rax,QWORD PTR [rcx+0x40]
  a37f49:	49 89 df                                        	mov    r15,rbx
  a37f4c:	41 bc ff ff ff ff                               	mov    r12d,0xffffffff
  a37f52:	8b 78 28                                        	mov    edi,DWORD PTR [rax+0x28]
  a37f55:	c1 ef 17                                        	shr    edi,0x17
  a37f58:	83 e7 02                                        	and    edi,0x2
  a37f5b:	74 0e                                           	je     0xa37f6b
  a37f5d:	48 89 cb                                        	mov    rbx,rcx
  a37f60:	e8 8b 9d b2 ff                                  	call   0x561cf0
  a37f65:	48 89 d9                                        	mov    rcx,rbx
  a37f68:	41 89 c4                                        	mov    r12d,eax
  a37f6b:	48 8b 41 38                                     	mov    rax,QWORD PTR [rcx+0x38]
  a37f6f:	4c 8b 70 30                                     	mov    r14,QWORD PTR [rax+0x30]
  a37f73:	48 8d 05 66 11 83 ff                            	lea    rax,[rip+0xffffffffff831166]        # 0x2690e0
  a37f7a:	4c 29 f0                                        	sub    rax,r14
  a37f7d:	48 c1 c8 03                                     	ror    rax,0x3
  a37f81:	48 83 f8 72                                     	cmp    rax,0x72
  a37f85:	0f 87 f5 0a 00 00                               	ja     0xa38a80
  a37f8b:	48 89 cf                                        	mov    rdi,rcx
  a37f8e:	be 01 00 00 00                                  	mov    esi,0x1
  a37f93:	48 89 cb                                        	mov    rbx,rcx
  a37f96:	41 ff d6                                        	call   r14
  a37f99:	41 89 c6                                        	mov    r14d,eax
  a37f9c:	41 83 fc ff                                     	cmp    r12d,0xffffffff
  a37fa0:	74 08                                           	je     0xa37faa
  a37fa2:	44 89 e7                                        	mov    edi,r12d
  a37fa5:	e8 36 9e b2 ff                                  	call   0x561de0
  a37faa:	4c 8d 25 5f 43 ee 02                            	lea    r12,[rip+0x2ee435f]        # 0x391c310
  a37fb1:	48 89 d9                                        	mov    rcx,rbx
  a37fb4:	4c 89 fb                                        	mov    rbx,r15
  a37fb7:	45 85 f6                                        	test   r14d,r14d
  a37fba:	74 33                                           	je     0xa37fef
  a37fbc:	48 8d 3d 53 22 85 00                            	lea    rdi,[rip+0x852253]        # 0x128a216
  a37fc3:	48 8d 35 cb d3 95 00                            	lea    rsi,[rip+0x95d3cb]        # 0x1395395
  a37fca:	ba f1 0f 00 00                                  	mov    edx,0xff1
  a37fcf:	44 89 f1                                        	mov    ecx,r14d
  a37fd2:	45 89 f0                                        	mov    r8d,r14d
  a37fd5:	31 c0                                           	xor    eax,eax
  a37fd7:	e8 34 54 82 ff                                  	call   0x25d410
  a37fdc:	41 83 fe 06                                     	cmp    r14d,0x6
  a37fe0:	41 bd 13 00 00 00                               	mov    r13d,0x13
  a37fe6:	45 0f 45 ee                                     	cmovne r13d,r14d
  a37fea:	e9 61 0a 00 00                                  	jmp    0xa38a50
  a37fef:	ba 03 00 00 00                                  	mov    edx,0x3
  a37ff4:	41 f7 c5 00 00 08 00                            	test   r13d,0x80000
  a37ffb:	75 55                                           	jne    0xa38052
  a37ffd:	48 8b bb 10 02 00 00                            	mov    rdi,QWORD PTR [rbx+0x210]
  a38004:	ba 01 00 00 00                                  	mov    edx,0x1
  a38009:	48 85 ff                                        	test   rdi,rdi
  a3800c:	74 44                                           	je     0xa38052
  a3800e:	49 89 de                                        	mov    r14,rbx
  a38011:	48 89 cb                                        	mov    rbx,rcx
  a38014:	e8 f7 20 b1 ff                                  	call   0x54a110
  a38019:	48 89 d9                                        	mov    rcx,rbx
  a3801c:	4c 89 f3                                        	mov    rbx,r14
  a3801f:	ba 01 00 00 00                                  	mov    edx,0x1
  a38024:	83 f8 02                                        	cmp    eax,0x2
  a38027:	7c 29                                           	jl     0xa38052
  a38029:	48 8d 3d e6 21 85 00                            	lea    rdi,[rip+0x8521e6]        # 0x128a216
  a38030:	48 8d 35 5e d3 95 00                            	lea    rsi,[rip+0x95d35e]        # 0x1395395
  a38037:	41 bd 10 00 00 00                               	mov    r13d,0x10
  a3803d:	ba 01 10 00 00                                  	mov    edx,0x1001
  a38042:	b9 10 00 00 00                                  	mov    ecx,0x10
  a38047:	41 b8 10 00 00 00                               	mov    r8d,0x10
  a3804d:	e9 c7 01 00 00                                  	jmp    0xa38219
  a38052:	65 4c 8b 34 25 00 00 00 00                      	mov    r14,QWORD PTR gs:0x0
  a3805b:	48 89 cf                                        	mov    rdi,rcx
  a3805e:	49 89 cf                                        	mov    r15,rcx
  a38061:	4c 89 f1                                        	mov    rcx,r14
  a38064:	31 f6                                           	xor    esi,esi
  a38066:	e8 f5 23 b1 ff                                  	call   0x54a460
  a3806b:	85 c0                                           	test   eax,eax
  a3806d:	74 33                                           	je     0xa380a2
  a3806f:	48 8d 3d a0 21 85 00                            	lea    rdi,[rip+0x8521a0]        # 0x128a216
  a38076:	48 8d 35 18 d3 95 00                            	lea    rsi,[rip+0x95d318]        # 0x1395395
  a3807d:	ba 0e 10 00 00                                  	mov    edx,0x100e
  a38082:	89 c1                                           	mov    ecx,eax
  a38084:	41 89 c0                                        	mov    r8d,eax
  a38087:	89 c3                                           	mov    ebx,eax
  a38089:	31 c0                                           	xor    eax,eax
  a3808b:	e8 80 53 82 ff                                  	call   0x25d410
  a38090:	83 fb 06                                        	cmp    ebx,0x6
  a38093:	41 bd 13 00 00 00                               	mov    r13d,0x13
  a38099:	44 0f 45 eb                                     	cmovne r13d,ebx
  a3809d:	e9 ae 09 00 00                                  	jmp    0xa38a50
  a380a2:	83 bb 10 04 00 00 00                            	cmp    DWORD PTR [rbx+0x410],0x0
  a380a9:	4c 89 7d b8                                     	mov    QWORD PTR [rbp-0x48],r15
  a380ad:	0f 88 f8 02 00 00                               	js     0xa383ab
  a380b3:	48 83 bb 68 08 00 00 00                         	cmp    QWORD PTR [rbx+0x868],0x0
  a380bb:	0f 84 26 01 00 00                               	je     0xa381e7
  a380c1:	48 8b 83 d8 00 00 00                            	mov    rax,QWORD PTR [rbx+0xd8]
  a380c8:	4c 89 75 b0                                     	mov    QWORD PTR [rbp-0x50],r14
  a380cc:	4c 8b 60 10                                     	mov    r12,QWORD PTR [rax+0x10]
  a380d0:	49 8b 44 24 18                                  	mov    rax,QWORD PTR [r12+0x18]
  a380d5:	4c 8b b0 c8 08 00 00                            	mov    r14,QWORD PTR [rax+0x8c8]
  a380dc:	48 8d 05 a5 53 82 ff                            	lea    rax,[rip+0xffffffffff8253a5]        # 0x25d488
  a380e3:	4c 29 f0                                        	sub    rax,r14
  a380e6:	48 c1 c8 03                                     	ror    rax,0x3
  a380ea:	48 83 f8 05                                     	cmp    rax,0x5
  a380ee:	0f 87 a6 09 00 00                               	ja     0xa38a9a
  a380f4:	4c 8b 7d c0                                     	mov    r15,QWORD PTR [rbp-0x40]
  a380f8:	4c 8d 45 c8                                     	lea    r8,[rbp-0x38]
  a380fc:	4c 89 e7                                        	mov    rdi,r12
  a380ff:	31 f6                                           	xor    esi,esi
  a38101:	31 c9                                           	xor    ecx,ecx
  a38103:	44 89 fa                                        	mov    edx,r15d
  a38106:	41 ff d6                                        	call   r14
  a38109:	85 c0                                           	test   eax,eax
  a3810b:	74 6d                                           	je     0xa3817a
  a3810d:	48 8d 3d 02 21 85 00                            	lea    rdi,[rip+0x852102]        # 0x128a216
  a38114:	48 8d 35 7a d2 95 00                            	lea    rsi,[rip+0x95d27a]        # 0x1395395
  a3811b:	ba 22 10 00 00                                  	mov    edx,0x1022
  a38120:	89 c1                                           	mov    ecx,eax
  a38122:	41 89 c0                                        	mov    r8d,eax
  a38125:	41 89 c6                                        	mov    r14d,eax
  a38128:	31 c0                                           	xor    eax,eax
  a3812a:	e8 e1 52 82 ff                                  	call   0x25d410
  a3812f:	48 8b bb 68 08 00 00                            	mov    rdi,QWORD PTR [rbx+0x868]
  a38136:	41 83 fe 06                                     	cmp    r14d,0x6
  a3813a:	41 bd 13 00 00 00                               	mov    r13d,0x13
  a38140:	ba 00 01 00 00                                  	mov    edx,0x100
  a38145:	45 0f 45 ee                                     	cmovne r13d,r14d
  a38149:	31 f6                                           	xor    esi,esi
  a3814b:	e8 40 88 e3 ff                                  	call   0x870990
  a38150:	48 8b bb 68 08 00 00                            	mov    rdi,QWORD PTR [rbx+0x868]
  a38157:	48 8d 35 c2 06 b3 01                            	lea    rsi,[rip+0x1b306c2]        # 0x2568820
  a3815e:	e8 8d 0c 1d 00                                  	call   0xc08df0
  a38163:	4c 8d 25 a6 41 ee 02                            	lea    r12,[rip+0x2ee41a6]        # 0x391c310
  a3816a:	48 c7 83 68 08 00 00 00 00 00 00                	mov    QWORD PTR [rbx+0x868],0x0
  a38175:	e9 d6 08 00 00                                  	jmp    0xa38a50
  a3817a:	48 8b 45 c8                                     	mov    rax,QWORD PTR [rbp-0x38]
  a3817e:	48 8b b3 68 08 00 00                            	mov    rsi,QWORD PTR [rbx+0x868]
  a38185:	48 8b 40 18                                     	mov    rax,QWORD PTR [rax+0x18]
  a38189:	4a 8d bc 38 e0 eb ff ff                         	lea    rdi,[rax+r15*1-0x1420]
  a38191:	e8 9a 65 12 00                                  	call   0xb5e730
  a38196:	48 8b bb 68 08 00 00                            	mov    rdi,QWORD PTR [rbx+0x868]
  a3819d:	ba 00 01 00 00                                  	mov    edx,0x100
  a381a2:	31 f6                                           	xor    esi,esi
  a381a4:	41 89 c6                                        	mov    r14d,eax
  a381a7:	e8 e4 87 e3 ff                                  	call   0x870990
  a381ac:	48 8b bb 68 08 00 00                            	mov    rdi,QWORD PTR [rbx+0x868]
  a381b3:	48 8d 35 66 06 b3 01                            	lea    rsi,[rip+0x1b30666]        # 0x2568820
  a381ba:	e8 31 0c 1d 00                                  	call   0xc08df0
  a381bf:	48 c7 83 68 08 00 00 00 00 00 00                	mov    QWORD PTR [rbx+0x868],0x0
  a381ca:	45 85 f6                                        	test   r14d,r14d
  a381cd:	0f 84 e2 00 00 00                               	je     0xa382b5
  a381d3:	48 8b 7d c8                                     	mov    rdi,QWORD PTR [rbp-0x38]
  a381d7:	e8 b4 54 06 00                                  	call   0xa9d690
  a381dc:	4c 8d 25 2d 41 ee 02                            	lea    r12,[rip+0x2ee412d]        # 0x391c310
  a381e3:	4c 8b 75 b0                                     	mov    r14,QWORD PTR [rbp-0x50]
  a381e7:	48 89 df                                        	mov    rdi,rbx
  a381ea:	e8 d1 00 f1 ff                                  	call   0x9482c0
  a381ef:	85 c0                                           	test   eax,eax
  a381f1:	74 32                                           	je     0xa38225
  a381f3:	83 f8 06                                        	cmp    eax,0x6
  a381f6:	41 bd 13 00 00 00                               	mov    r13d,0x13
  a381fc:	48 8d 3d 13 20 85 00                            	lea    rdi,[rip+0x852013]        # 0x128a216
  a38203:	48 8d 35 8b d1 95 00                            	lea    rsi,[rip+0x95d18b]        # 0x1395395
  a3820a:	ba 54 10 00 00                                  	mov    edx,0x1054
  a3820f:	44 0f 45 e8                                     	cmovne r13d,eax
  a38213:	44 89 e9                                        	mov    ecx,r13d
  a38216:	45 89 e8                                        	mov    r8d,r13d
  a38219:	31 c0                                           	xor    eax,eax
  a3821b:	e8 f0 51 82 ff                                  	call   0x25d410
  a38220:	e9 2b 08 00 00                                  	jmp    0xa38a50
  a38225:	f6 83 13 04 00 00 10                            	test   BYTE PTR [rbx+0x413],0x10
  a3822c:	74 18                                           	je     0xa38246
  a3822e:	48 89 df                                        	mov    rdi,rbx
  a38231:	e8 2a d5 f0 ff                                  	call   0x945760
  a38236:	48 8b 83 48 03 00 00                            	mov    rax,QWORD PTR [rbx+0x348]
  a3823d:	48 8b 78 10                                     	mov    rdi,QWORD PTR [rax+0x10]
  a38241:	e8 9a c7 ef ff                                  	call   0x9349e0
  a38246:	48 8b 7b 20                                     	mov    rdi,QWORD PTR [rbx+0x20]
  a3824a:	48 83 ec 08                                     	sub    rsp,0x8
  a3824e:	4c 8b 7d c0                                     	mov    r15,QWORD PTR [rbp-0x40]
  a38252:	48 8d 45 c8                                     	lea    rax,[rbp-0x38]
  a38256:	31 f6                                           	xor    esi,esi
  a38258:	31 c9                                           	xor    ecx,ecx
  a3825a:	45 31 c0                                        	xor    r8d,r8d
  a3825d:	45 31 c9                                        	xor    r9d,r9d
  a38260:	44 89 fa                                        	mov    edx,r15d
  a38263:	50                                              	push   rax
  a38264:	6a 00                                           	push   0x0
  a38266:	6a 00                                           	push   0x0
  a38268:	e8 23 59 06 00                                  	call   0xa9db90
  a3826d:	48 83 c4 20                                     	add    rsp,0x20
  a38271:	85 c0                                           	test   eax,eax
  a38273:	0f 84 a1 00 00 00                               	je     0xa3831a
  a38279:	48 8d 3d 96 1f 85 00                            	lea    rdi,[rip+0x851f96]        # 0x128a216
  a38280:	48 8d 35 0e d1 95 00                            	lea    rsi,[rip+0x95d10e]        # 0x1395395
  a38287:	ba 60 10 00 00                                  	mov    edx,0x1060
  a3828c:	89 c1                                           	mov    ecx,eax
  a3828e:	41 89 c0                                        	mov    r8d,eax
  a38291:	89 c3                                           	mov    ebx,eax
  a38293:	31 c0                                           	xor    eax,eax
  a38295:	e8 76 51 82 ff                                  	call   0x25d410
  a3829a:	48 8b 7d c8                                     	mov    rdi,QWORD PTR [rbp-0x38]
  a3829e:	83 fb 06                                        	cmp    ebx,0x6
  a382a1:	41 bd 13 00 00 00                               	mov    r13d,0x13
  a382a7:	44 0f 45 eb                                     	cmovne r13d,ebx
  a382ab:	e8 e0 53 06 00                                  	call   0xa9d690
  a382b0:	e9 9b 07 00 00                                  	jmp    0xa38a50
  a382b5:	49 8b 44 24 18                                  	mov    rax,QWORD PTR [r12+0x18]
  a382ba:	4c 8b b0 d8 08 00 00                            	mov    r14,QWORD PTR [rax+0x8d8]
  a382c1:	48 8d 05 38 1c 83 ff                            	lea    rax,[rip+0xffffffffff831c38]        # 0x269f00
  a382c8:	4c 29 f0                                        	sub    rax,r14
  a382cb:	48 c1 c8 03                                     	ror    rax,0x3
  a382cf:	48 83 f8 16                                     	cmp    rax,0x16
  a382d3:	0f 87 39 08 00 00                               	ja     0xa38b12
  a382d9:	48 8b 75 c8                                     	mov    rsi,QWORD PTR [rbp-0x38]
  a382dd:	4c 89 e7                                        	mov    rdi,r12
  a382e0:	31 d2                                           	xor    edx,edx
  a382e2:	41 ff d6                                        	call   r14
  a382e5:	85 c0                                           	test   eax,eax
  a382e7:	0f 84 7f 07 00 00                               	je     0xa38a6c
  a382ed:	48 8d 3d 22 1f 85 00                            	lea    rdi,[rip+0x851f22]        # 0x128a216
  a382f4:	48 8d 35 9a d0 95 00                            	lea    rsi,[rip+0x95d09a]        # 0x1395395
  a382fb:	ba 3d 10 00 00                                  	mov    edx,0x103d
  a38300:	89 c1                                           	mov    ecx,eax
  a38302:	41 89 c0                                        	mov    r8d,eax
  a38305:	89 c3                                           	mov    ebx,eax
  a38307:	31 c0                                           	xor    eax,eax
  a38309:	e8 02 51 82 ff                                  	call   0x25d410
  a3830e:	4c 8d 25 fb 3f ee 02                            	lea    r12,[rip+0x2ee3ffb]        # 0x391c310
  a38315:	e9 76 fd ff ff                                  	jmp    0xa38090
  a3831a:	48 8b 43 30                                     	mov    rax,QWORD PTR [rbx+0x30]
  a3831e:	80 60 18 80                                     	and    BYTE PTR [rax+0x18],0x80
  a38322:	f6 83 10 04 00 00 01                            	test   BYTE PTR [rbx+0x410],0x1
  a38329:	74 08                                           	je     0xa38333
  a3832b:	48 89 df                                        	mov    rdi,rbx
  a3832e:	e8 7d ff ef ff                                  	call   0x9382b0
  a38333:	48 8b 45 c8                                     	mov    rax,QWORD PTR [rbp-0x38]
  a38337:	48 8b 7b 30                                     	mov    rdi,QWORD PTR [rbx+0x30]
  a3833b:	ba a0 05 00 00                                  	mov    edx,0x5a0
  a38340:	48 8b 70 18                                     	mov    rsi,QWORD PTR [rax+0x18]
  a38344:	e8 97 18 82 ff                                  	call   0x259be0
  a38349:	83 bb 50 04 00 00 03                            	cmp    DWORD PTR [rbx+0x450],0x3
  a38350:	75 50                                           	jne    0xa383a2
  a38352:	48 8b 45 c8                                     	mov    rax,QWORD PTR [rbp-0x38]
  a38356:	be 80 03 00 00                                  	mov    esi,0x380
  a3835b:	48 03 73 30                                     	add    rsi,QWORD PTR [rbx+0x30]
  a3835f:	48 8b 40 18                                     	mov    rax,QWORD PTR [rax+0x18]
  a38363:	4a 8d 7c 38 90                                  	lea    rdi,[rax+r15*1-0x70]
  a38368:	e8 73 66 12 00                                  	call   0xb5e9e0
  a3836d:	48 8b 45 c8                                     	mov    rax,QWORD PTR [rbp-0x38]
  a38371:	be a0 05 00 00                                  	mov    esi,0x5a0
  a38376:	48 8b 78 18                                     	mov    rdi,QWORD PTR [rax+0x18]
  a3837a:	e8 71 06 85 ff                                  	call   0x2889f0
  a3837f:	85 c0                                           	test   eax,eax
  a38381:	74 1f                                           	je     0xa383a2
  a38383:	48 8d 3d 8c 1e 85 00                            	lea    rdi,[rip+0x851e8c]        # 0x128a216
  a3838a:	48 8d 35 04 d0 95 00                            	lea    rsi,[rip+0x95d004]        # 0x1395395
  a38391:	ba 7f 10 00 00                                  	mov    edx,0x107f
  a38396:	89 c1                                           	mov    ecx,eax
  a38398:	41 89 c0                                        	mov    r8d,eax
  a3839b:	31 c0                                           	xor    eax,eax
  a3839d:	e8 6e 50 82 ff                                  	call   0x25d410
  a383a2:	48 8b 7d c8                                     	mov    rdi,QWORD PTR [rbp-0x38]
  a383a6:	e8 45 66 00 00                                  	call   0xa3e9f0
  a383ab:	83 bb 50 04 00 00 01                            	cmp    DWORD PTR [rbx+0x450],0x1
  a383b2:	75 5a                                           	jne    0xa3840e
  a383b4:	83 bb 84 07 00 00 ff                            	cmp    DWORD PTR [rbx+0x784],0xffffffff
  a383bb:	74 51                                           	je     0xa3840e
  a383bd:	4d 89 f7                                        	mov    r15,r14
  a383c0:	4c 8d 35 81 30 b7 02                            	lea    r14,[rip+0x2b73081]        # 0x35ab448
  a383c7:	31 f6                                           	xor    esi,esi
  a383c9:	31 d2                                           	xor    edx,edx
  a383cb:	31 c9                                           	xor    ecx,ecx
  a383cd:	4c 89 f7                                        	mov    rdi,r14
  a383d0:	e8 2b e6 a8 ff                                  	call   0x4c6a00
  a383d5:	48 63 83 84 07 00 00                            	movsxd rax,DWORD PTR [rbx+0x784]
  a383dc:	48 8d 3d 9d 30 b7 02                            	lea    rdi,[rip+0x2b7309d]        # 0x35ab480
  a383e3:	48 8d 04 40                                     	lea    rax,[rax+rax*2]
  a383e7:	48 c1 e0 06                                     	shl    rax,0x6
  a383eb:	48 01 c7                                        	add    rdi,rax
  a383ee:	e8 6d 6f fe ff                                  	call   0xa1f360
  a383f3:	4c 89 f7                                        	mov    rdi,r14
  a383f6:	4d 89 fe                                        	mov    r14,r15
  a383f9:	31 f6                                           	xor    esi,esi
  a383fb:	31 d2                                           	xor    edx,edx
  a383fd:	31 c9                                           	xor    ecx,ecx
  a383ff:	e8 9c eb a8 ff                                  	call   0x4c6fa0
  a38404:	c7 83 84 07 00 00 ff ff ff ff                   	mov    DWORD PTR [rbx+0x784],0xffffffff
  a3840e:	8b 83 10 04 00 00                               	mov    eax,DWORD PTR [rbx+0x410]
  a38414:	a8 01                                           	test   al,0x1
  a38416:	74 42                                           	je     0xa3845a
  a38418:	48 89 df                                        	mov    rdi,rbx
  a3841b:	4d 89 f7                                        	mov    r15,r14
  a3841e:	45 89 ee                                        	mov    r14d,r13d
  a38421:	e8 2a b4 15 00                                  	call   0xb93850
  a38426:	85 c0                                           	test   eax,eax
  a38428:	74 24                                           	je     0xa3844e
  a3842a:	48 8d 3d 50 0d 8b 00                            	lea    rdi,[rip+0x8b0d50]        # 0x12e9181
  a38431:	48 8d 35 5d cf 95 00                            	lea    rsi,[rip+0x95cf5d]        # 0x1395395
  a38438:	ba 9e 10 00 00                                  	mov    edx,0x109e
  a3843d:	89 c1                                           	mov    ecx,eax
  a3843f:	41 89 c5                                        	mov    r13d,eax
  a38442:	31 c0                                           	xor    eax,eax
  a38444:	e8 c7 4f 82 ff                                  	call   0x25d410
  a38449:	e9 02 06 00 00                                  	jmp    0xa38a50
  a3844e:	8b 83 10 04 00 00                               	mov    eax,DWORD PTR [rbx+0x410]
  a38454:	45 89 f5                                        	mov    r13d,r14d
  a38457:	4d 89 fe                                        	mov    r14,r15
  a3845a:	8b 8b 50 04 00 00                               	mov    ecx,DWORD PTR [rbx+0x450]
  a38460:	a8 01                                           	test   al,0x1
  a38462:	0f 85 31 01 00 00                               	jne    0xa38599
  a38468:	83 f9 01                                        	cmp    ecx,0x1
  a3846b:	0f 85 75 02 00 00                               	jne    0xa386e6
  a38471:	48 8d b3 f8 05 00 00                            	lea    rsi,[rbx+0x5f8]
  a38478:	48 89 df                                        	mov    rdi,rbx
  a3847b:	e8 50 25 f1 ff                                  	call   0x94a9d0
  a38480:	48 8b bb f8 06 00 00                            	mov    rdi,QWORD PTR [rbx+0x6f8]
  a38487:	48 85 ff                                        	test   rdi,rdi
  a3848a:	74 65                                           	je     0xa384f1
  a3848c:	48 81 c7 b0 00 00 00                            	add    rdi,0xb0
  a38493:	31 f6                                           	xor    esi,esi
  a38495:	31 d2                                           	xor    edx,edx
  a38497:	31 c9                                           	xor    ecx,ecx
  a38499:	e8 62 e5 a8 ff                                  	call   0x4c6a00
  a3849e:	48 8b bb f8 06 00 00                            	mov    rdi,QWORD PTR [rbx+0x6f8]
  a384a5:	f6 87 c4 01 00 00 80                            	test   BYTE PTR [rdi+0x1c4],0x80
  a384ac:	75 1a                                           	jne    0xa384c8
  a384ae:	48 8b 47 10                                     	mov    rax,QWORD PTR [rdi+0x10]
  a384b2:	48 8b 40 18                                     	mov    rax,QWORD PTR [rax+0x18]
  a384b6:	48 c7 80 10 07 00 00 00 00 00 00                	mov    QWORD PTR [rax+0x710],0x0
  a384c1:	48 8b bb f8 06 00 00                            	mov    rdi,QWORD PTR [rbx+0x6f8]
  a384c8:	48 81 c7 b0 00 00 00                            	add    rdi,0xb0
  a384cf:	31 f6                                           	xor    esi,esi
  a384d1:	31 d2                                           	xor    edx,edx
  a384d3:	31 c9                                           	xor    ecx,ecx
  a384d5:	e8 c6 ea a8 ff                                  	call   0x4c6fa0
  a384da:	48 8b bb f8 06 00 00                            	mov    rdi,QWORD PTR [rbx+0x6f8]
  a384e1:	48 c7 83 f8 06 00 00 00 00 00 00                	mov    QWORD PTR [rbx+0x6f8],0x0
  a384ec:	e8 2f 1c b1 ff                                  	call   0x54a120
  a384f1:	48 8b bb b0 06 00 00                            	mov    rdi,QWORD PTR [rbx+0x6b0]
  a384f8:	48 83 c7 48                                     	add    rdi,0x48
  a384fc:	e8 4f f9 a8 ff                                  	call   0x4c7e50
  a38501:	bf f0 00 00 00                                  	mov    edi,0xf0
  a38506:	48 03 bb b0 06 00 00                            	add    rdi,QWORD PTR [rbx+0x6b0]
  a3850d:	e8 3e f9 a8 ff                                  	call   0x4c7e50
  a38512:	bf 98 01 00 00                                  	mov    edi,0x198
  a38517:	48 03 bb b0 06 00 00                            	add    rdi,QWORD PTR [rbx+0x6b0]
  a3851e:	e8 2d f9 a8 ff                                  	call   0x4c7e50
  a38523:	bf 40 02 00 00                                  	mov    edi,0x240
  a38528:	48 03 bb b0 06 00 00                            	add    rdi,QWORD PTR [rbx+0x6b0]
  a3852f:	e8 1c f9 a8 ff                                  	call   0x4c7e50
  a38534:	48 8b bb b0 06 00 00                            	mov    rdi,QWORD PTR [rbx+0x6b0]
  a3853b:	4d 89 f7                                        	mov    r15,r14
  a3853e:	4c 8d 35 db 02 b3 01                            	lea    r14,[rip+0x1b302db]        # 0x2568820
  a38545:	4c 89 f6                                        	mov    rsi,r14
  a38548:	e8 a3 08 1d 00                                  	call   0xc08df0
  a3854d:	48 8d bb 18 06 00 00                            	lea    rdi,[rbx+0x618]
  a38554:	e8 f7 f8 a8 ff                                  	call   0x4c7e50
  a38559:	48 8d bb 60 06 00 00                            	lea    rdi,[rbx+0x660]
  a38560:	e8 eb f8 a8 ff                                  	call   0x4c7e50
  a38565:	48 8d bb d0 06 00 00                            	lea    rdi,[rbx+0x6d0]
  a3856c:	e8 df f8 a8 ff                                  	call   0x4c7e50
  a38571:	48 8d bb f0 06 00 00                            	lea    rdi,[rbx+0x6f0]
  a38578:	e8 d3 f8 a8 ff                                  	call   0x4c7e50
  a3857d:	48 8b bb 20 07 00 00                            	mov    rdi,QWORD PTR [rbx+0x720]
  a38584:	4c 89 f6                                        	mov    rsi,r14
  a38587:	4d 89 fe                                        	mov    r14,r15
  a3858a:	e8 61 08 1d 00                                  	call   0xc08df0
  a3858f:	bf 70 07 00 00                                  	mov    edi,0x770
  a38594:	e9 45 01 00 00                                  	jmp    0xa386de
  a38599:	83 f9 01                                        	cmp    ecx,0x1
  a3859c:	74 74                                           	je     0xa38612
  a3859e:	83 f9 03                                        	cmp    ecx,0x3
  a385a1:	0f 85 3f 01 00 00                               	jne    0xa386e6
  a385a7:	48 8d b3 a8 04 00 00                            	lea    rsi,[rbx+0x4a8]
  a385ae:	48 89 df                                        	mov    rdi,rbx
  a385b1:	e8 5a 23 f1 ff                                  	call   0x94a910
  a385b6:	48 8d b3 f0 04 00 00                            	lea    rsi,[rbx+0x4f0]
  a385bd:	48 89 df                                        	mov    rdi,rbx
  a385c0:	e8 4b 23 f1 ff                                  	call   0x94a910
  a385c5:	48 8b bb b0 05 00 00                            	mov    rdi,QWORD PTR [rbx+0x5b0]
  a385cc:	48 8d 35 4d 02 b3 01                            	lea    rsi,[rip+0x1b3024d]        # 0x2568820
  a385d3:	e8 18 08 1d 00                                  	call   0xc08df0
  a385d8:	48 8d bb c8 04 00 00                            	lea    rdi,[rbx+0x4c8]
  a385df:	e8 6c f8 a8 ff                                  	call   0x4c7e50
  a385e4:	48 8d bb 10 05 00 00                            	lea    rdi,[rbx+0x510]
  a385eb:	e8 60 f8 a8 ff                                  	call   0x4c7e50
  a385f0:	48 8d bb 58 05 00 00                            	lea    rdi,[rbx+0x558]
  a385f7:	e8 54 f8 a8 ff                                  	call   0x4c7e50
  a385fc:	48 8d bb f0 05 00 00                            	lea    rdi,[rbx+0x5f0]
  a38603:	e8 48 f8 a8 ff                                  	call   0x4c7e50
  a38608:	bf d0 05 00 00                                  	mov    edi,0x5d0
  a3860d:	e9 cc 00 00 00                                  	jmp    0xa386de
  a38612:	48 8d b3 f8 05 00 00                            	lea    rsi,[rbx+0x5f8]
  a38619:	48 89 df                                        	mov    rdi,rbx
  a3861c:	4d 89 f7                                        	mov    r15,r14
  a3861f:	e8 ac 23 f1 ff                                  	call   0x94a9d0
  a38624:	48 8b bb b0 05 00 00                            	mov    rdi,QWORD PTR [rbx+0x5b0]
  a3862b:	48 8d 35 ee 01 b3 01                            	lea    rsi,[rip+0x1b301ee]        # 0x2568820
  a38632:	e8 b9 07 1d 00                                  	call   0xc08df0
  a38637:	48 8b 45 b8                                     	mov    rax,QWORD PTR [rbp-0x48]
  a3863b:	41 be 14 00 00 00                               	mov    r14d,0x14
  a38641:	41 bc 48 00 00 00                               	mov    r12d,0x48
  a38647:	83 b8 30 03 00 00 01                            	cmp    DWORD PTR [rax+0x330],0x1
  a3864e:	b8 08 00 00 00                                  	mov    eax,0x8
  a38653:	4c 0f 44 f0                                     	cmove  r14,rax
  a38657:	66 0f 1f 84 00 00 00 00 00                      	nop    WORD PTR [rax+rax*1+0x0]
  a38660:	48 8b bb b0 06 00 00                            	mov    rdi,QWORD PTR [rbx+0x6b0]
  a38667:	4c 01 e7                                        	add    rdi,r12
  a3866a:	e8 e1 f7 a8 ff                                  	call   0x4c7e50
  a3866f:	49 81 c4 a8 00 00 00                            	add    r12,0xa8
  a38676:	49 ff ce                                        	dec    r14
  a38679:	75 e5                                           	jne    0xa38660
  a3867b:	48 8b bb b0 06 00 00                            	mov    rdi,QWORD PTR [rbx+0x6b0]
  a38682:	48 8d 35 97 01 b3 01                            	lea    rsi,[rip+0x1b30197]        # 0x2568820
  a38689:	e8 62 07 1d 00                                  	call   0xc08df0
  a3868e:	48 8d bb 58 05 00 00                            	lea    rdi,[rbx+0x558]
  a38695:	e8 b6 f7 a8 ff                                  	call   0x4c7e50
  a3869a:	48 8d bb f0 05 00 00                            	lea    rdi,[rbx+0x5f0]
  a386a1:	e8 aa f7 a8 ff                                  	call   0x4c7e50
  a386a6:	48 8d bb d0 05 00 00                            	lea    rdi,[rbx+0x5d0]
  a386ad:	e8 9e f7 a8 ff                                  	call   0x4c7e50
  a386b2:	48 8d bb 18 06 00 00                            	lea    rdi,[rbx+0x618]
  a386b9:	e8 92 f7 a8 ff                                  	call   0x4c7e50
  a386be:	48 8d bb 60 06 00 00                            	lea    rdi,[rbx+0x660]
  a386c5:	e8 86 f7 a8 ff                                  	call   0x4c7e50
  a386ca:	48 8d bb d0 06 00 00                            	lea    rdi,[rbx+0x6d0]
  a386d1:	e8 7a f7 a8 ff                                  	call   0x4c7e50
  a386d6:	bf f0 06 00 00                                  	mov    edi,0x6f0
  a386db:	4d 89 fe                                        	mov    r14,r15
  a386de:	48 01 df                                        	add    rdi,rbx
  a386e1:	e8 6a f7 a8 ff                                  	call   0x4c7e50
  a386e6:	48 83 bb a8 01 00 00 00                         	cmp    QWORD PTR [rbx+0x1a8],0x0
  a386ee:	74 47                                           	je     0xa38737
  a386f0:	48 8d bb e0 01 00 00                            	lea    rdi,[rbx+0x1e0]
  a386f7:	e8 64 90 1b 00                                  	call   0xbf1760
  a386fc:	48 8b bb c8 01 00 00                            	mov    rdi,QWORD PTR [rbx+0x1c8]
  a38703:	48 8d 35 c6 ff b2 01                            	lea    rsi,[rip+0x1b2ffc6]        # 0x25686d0
  a3870a:	e8 e1 06 1d 00                                  	call   0xc08df0
  a3870f:	48 8b 83 a8 01 00 00                            	mov    rax,QWORD PTR [rbx+0x1a8]
  a38716:	81 a0 c8 01 00 00 7f ff ff ff                   	and    DWORD PTR [rax+0x1c8],0xffffff7f
  a38720:	48 8b bb a8 01 00 00                            	mov    rdi,QWORD PTR [rbx+0x1a8]
  a38727:	e8 f4 19 b1 ff                                  	call   0x54a120
  a3872c:	48 c7 83 a8 01 00 00 00 00 00 00                	mov    QWORD PTR [rbx+0x1a8],0x0
  a38737:	48 83 bb 40 01 00 00 00                         	cmp    QWORD PTR [rbx+0x140],0x0
  a3873f:	74 47                                           	je     0xa38788
  a38741:	48 8d bb 78 01 00 00                            	lea    rdi,[rbx+0x178]
  a38748:	e8 13 90 1b 00                                  	call   0xbf1760
  a3874d:	48 8b bb 60 01 00 00                            	mov    rdi,QWORD PTR [rbx+0x160]
  a38754:	48 8d 35 75 ff b2 01                            	lea    rsi,[rip+0x1b2ff75]        # 0x25686d0
  a3875b:	e8 90 06 1d 00                                  	call   0xc08df0
  a38760:	48 8b 83 40 01 00 00                            	mov    rax,QWORD PTR [rbx+0x140]
  a38767:	81 a0 c8 01 00 00 7f ff ff ff                   	and    DWORD PTR [rax+0x1c8],0xffffff7f
  a38771:	48 8b bb 40 01 00 00                            	mov    rdi,QWORD PTR [rbx+0x140]
  a38778:	e8 a3 19 b1 ff                                  	call   0x54a120
  a3877d:	48 c7 83 40 01 00 00 00 00 00 00                	mov    QWORD PTR [rbx+0x140],0x0
  a38788:	48 83 bb 10 02 00 00 00                         	cmp    QWORD PTR [rbx+0x210],0x0
  a38790:	74 34                                           	je     0xa387c6
  a38792:	48 8d bb 48 02 00 00                            	lea    rdi,[rbx+0x248]
  a38799:	e8 c2 8f 1b 00                                  	call   0xbf1760
  a3879e:	48 8b 83 10 02 00 00                            	mov    rax,QWORD PTR [rbx+0x210]
  a387a5:	81 a0 c8 01 00 00 7f ff ff ff                   	and    DWORD PTR [rax+0x1c8],0xffffff7f
  a387af:	48 8b bb 10 02 00 00                            	mov    rdi,QWORD PTR [rbx+0x210]
  a387b6:	e8 65 19 b1 ff                                  	call   0x54a120
  a387bb:	48 c7 83 10 02 00 00 00 00 00 00                	mov    QWORD PTR [rbx+0x210],0x0
  a387c6:	48 83 bb 48 03 00 00 00                         	cmp    QWORD PTR [rbx+0x348],0x0
  a387ce:	74 47                                           	je     0xa38817
  a387d0:	48 8d bb 80 03 00 00                            	lea    rdi,[rbx+0x380]
  a387d7:	e8 84 8f 1b 00                                  	call   0xbf1760
  a387dc:	48 8b 83 48 03 00 00                            	mov    rax,QWORD PTR [rbx+0x348]
  a387e3:	48 8d 35 e6 fe b2 01                            	lea    rsi,[rip+0x1b2fee6]        # 0x25686d0
  a387ea:	81 a0 c8 01 00 00 7f ff ff ff                   	and    DWORD PTR [rax+0x1c8],0xffffff7f
  a387f4:	48 8b bb 68 03 00 00                            	mov    rdi,QWORD PTR [rbx+0x368]
  a387fb:	e8 f0 05 1d 00                                  	call   0xc08df0
  a38800:	48 8b bb 48 03 00 00                            	mov    rdi,QWORD PTR [rbx+0x348]
  a38807:	e8 14 19 b1 ff                                  	call   0x54a120
  a3880c:	48 c7 83 48 03 00 00 00 00 00 00                	mov    QWORD PTR [rbx+0x348],0x0
  a38817:	48 83 bb 78 02 00 00 00                         	cmp    QWORD PTR [rbx+0x278],0x0
  a3881f:	74 76                                           	je     0xa38897
  a38821:	48 8b 43 30                                     	mov    rax,QWORD PTR [rbx+0x30]
  a38825:	48 83 38 02                                     	cmp    QWORD PTR [rax],0x2
  a38829:	75 38                                           	jne    0xa38863
  a3882b:	4d 89 f7                                        	mov    r15,r14
  a3882e:	4c 8b b3 98 02 00 00                            	mov    r14,QWORD PTR [rbx+0x298]
  a38835:	31 c9                                           	xor    ecx,ecx
  a38837:	4c 89 f0                                        	mov    rax,r14
  a3883a:	f0 48 0f b1 8b 98 02 00 00                      	lock cmpxchg QWORD PTR [rbx+0x298],rcx
  a38843:	0f 85 a3 02 00 00                               	jne    0xa38aec
  a38849:	4c 89 f7                                        	mov    rdi,r14
  a3884c:	e8 ff 00 b3 ff                                  	call   0x568950
  a38851:	48 8d 35 38 00 b3 01                            	lea    rsi,[rip+0x1b30038]        # 0x2568890
  a38858:	4c 89 f7                                        	mov    rdi,r14
  a3885b:	e8 90 05 1d 00                                  	call   0xc08df0
  a38860:	4d 89 fe                                        	mov    r14,r15
  a38863:	48 8d bb b0 02 00 00                            	lea    rdi,[rbx+0x2b0]
  a3886a:	e8 f1 8e 1b 00                                  	call   0xbf1760
  a3886f:	48 8b 83 78 02 00 00                            	mov    rax,QWORD PTR [rbx+0x278]
  a38876:	81 a0 c8 01 00 00 7f ff ff ff                   	and    DWORD PTR [rax+0x1c8],0xffffff7f
  a38880:	48 8b bb 78 02 00 00                            	mov    rdi,QWORD PTR [rbx+0x278]
  a38887:	e8 94 18 b1 ff                                  	call   0x54a120
  a3888c:	48 c7 83 78 02 00 00 00 00 00 00                	mov    QWORD PTR [rbx+0x278],0x0
  a38897:	48 83 bb e0 02 00 00 00                         	cmp    QWORD PTR [rbx+0x2e0],0x0
  a3889f:	74 34                                           	je     0xa388d5
  a388a1:	48 8d bb 18 03 00 00                            	lea    rdi,[rbx+0x318]
  a388a8:	e8 b3 8e 1b 00                                  	call   0xbf1760
  a388ad:	48 8b 83 e0 02 00 00                            	mov    rax,QWORD PTR [rbx+0x2e0]
  a388b4:	81 a0 c8 01 00 00 7f ff ff ff                   	and    DWORD PTR [rax+0x1c8],0xffffff7f
  a388be:	48 8b bb e0 02 00 00                            	mov    rdi,QWORD PTR [rbx+0x2e0]
  a388c5:	e8 56 18 b1 ff                                  	call   0x54a120
  a388ca:	48 c7 83 e0 02 00 00 00 00 00 00                	mov    QWORD PTR [rbx+0x2e0],0x0
  a388d5:	48 8b 83 d0 00 00 00                            	mov    rax,QWORD PTR [rbx+0xd0]
  a388dc:	81 a0 c8 01 00 00 7f ff ff ff                   	and    DWORD PTR [rax+0x1c8],0xffffff7f
  a388e6:	48 8b bb d0 00 00 00                            	mov    rdi,QWORD PTR [rbx+0xd0]
  a388ed:	e8 2e 18 b1 ff                                  	call   0x54a120
  a388f2:	48 8b 83 d8 00 00 00                            	mov    rax,QWORD PTR [rbx+0xd8]
  a388f9:	81 a0 c8 01 00 00 7f ff ff ff                   	and    DWORD PTR [rax+0x1c8],0xffffff7f
  a38903:	48 8b bb d8 00 00 00                            	mov    rdi,QWORD PTR [rbx+0xd8]
  a3890a:	e8 11 18 b1 ff                                  	call   0x54a120
  a3890f:	48 8b 7d b8                                     	mov    rdi,QWORD PTR [rbp-0x48]
  a38913:	ba 02 00 00 00                                  	mov    edx,0x2
  a38918:	4c 89 f1                                        	mov    rcx,r14
  a3891b:	31 f6                                           	xor    esi,esi
  a3891d:	e8 3e 1b b1 ff                                  	call   0x54a460
  a38922:	85 c0                                           	test   eax,eax
  a38924:	74 1c                                           	je     0xa38942
  a38926:	89 c1                                           	mov    ecx,eax
  a38928:	48 8d 3d b4 d1 96 00                            	lea    rdi,[rip+0x96d1b4]        # 0x13a5ae3
  a3892f:	48 8d 35 5f ca 95 00                            	lea    rsi,[rip+0x95ca5f]        # 0x1395395
  a38936:	ba 51 11 00 00                                  	mov    edx,0x1151
  a3893b:	31 c0                                           	xor    eax,eax
  a3893d:	e8 ce 4a 82 ff                                  	call   0x25d410
  a38942:	48 89 df                                        	mov    rdi,rbx
  a38945:	44 89 6d c0                                     	mov    DWORD PTR [rbp-0x40],r13d
  a38949:	e8 22 2b 93 ff                                  	call   0x36b470
  a3894e:	48 8b 7b 20                                     	mov    rdi,QWORD PTR [rbx+0x20]
  a38952:	48 8d 15 82 28 95 00                            	lea    rdx,[rip+0x952882]        # 0x138b1db
  a38959:	be 00 04 08 00                                  	mov    esi,0x80400
  a3895e:	b9 56 11 00 00                                  	mov    ecx,0x1156
  a38963:	e8 e8 71 c7 ff                                  	call   0x6afb50
  a38968:	4c 8d 35 f9 29 ac 02                            	lea    r14,[rip+0x2ac29f9]        # 0x34fb368
  a3896f:	45 31 e4                                        	xor    r12d,r12d
  a38972:	31 f6                                           	xor    esi,esi
  a38974:	31 d2                                           	xor    edx,edx
  a38976:	31 c9                                           	xor    ecx,ecx
  a38978:	4c 89 f7                                        	mov    rdi,r14
  a3897b:	e8 a0 31 21 00                                  	call   0xc4bb20
  a38980:	48 8b 7b 10                                     	mov    rdi,QWORD PTR [rbx+0x10]
  a38984:	e8 f7 90 d0 ff                                  	call   0x741a80
  a38989:	4c 89 f7                                        	mov    rdi,r14
  a3898c:	31 f6                                           	xor    esi,esi
  a3898e:	31 d2                                           	xor    edx,edx
  a38990:	e8 1b 3b 21 00                                  	call   0xc4c4b0
  a38995:	48 8b 7b 20                                     	mov    rdi,QWORD PTR [rbx+0x20]
  a38999:	e8 a2 1a b1 ff                                  	call   0x54a440
  a3899e:	48 8b 7b 08                                     	mov    rdi,QWORD PTR [rbx+0x8]
  a389a2:	e8 c9 60 ca ff                                  	call   0x6dea70
  a389a7:	48 8b 7b 30                                     	mov    rdi,QWORD PTR [rbx+0x30]
  a389ab:	48 89 f8                                        	mov    rax,rdi
  a389ae:	f0 4c 0f b1 63 30                               	lock cmpxchg QWORD PTR [rbx+0x30],r12
  a389b4:	0f 85 f4 00 00 00                               	jne    0xa38aae
  a389ba:	48 8d 35 0f fd b2 01                            	lea    rsi,[rip+0x1b2fd0f]        # 0x25686d0
  a389c1:	e8 2a 04 1d 00                                  	call   0xc08df0
  a389c6:	48 8d 7b 68                                     	lea    rdi,[rbx+0x68]
  a389ca:	e8 91 8d 1b 00                                  	call   0xbf1760
  a389cf:	48 8d bb 30 04 00 00                            	lea    rdi,[rbx+0x430]
  a389d6:	e8 75 f4 a8 ff                                  	call   0x4c7e50
  a389db:	4c 8b 7d b8                                     	mov    r15,QWORD PTR [rbp-0x48]
  a389df:	4c 8d 25 2a 39 ee 02                            	lea    r12,[rip+0x2ee392a]        # 0x391c310
  a389e6:	45 31 ed                                        	xor    r13d,r13d
  a389e9:	48 89 d8                                        	mov    rax,rbx
  a389ec:	f0 4d 0f b1 af 98 02 00 00                      	lock cmpxchg QWORD PTR [r15+0x298],r13
  a389f5:	0f 85 d2 00 00 00                               	jne    0xa38acd
  a389fb:	48 8d 35 ce fc b2 01                            	lea    rsi,[rip+0x1b2fcce]        # 0x25686d0
  a38a02:	48 89 df                                        	mov    rdi,rbx
  a38a05:	e8 e6 03 1d 00                                  	call   0xc08df0
  a38a0a:	49 8d 5f 18                                     	lea    rbx,[r15+0x18]
  a38a0e:	31 f6                                           	xor    esi,esi
  a38a10:	31 d2                                           	xor    edx,edx
  a38a12:	31 c9                                           	xor    ecx,ecx
  a38a14:	48 89 df                                        	mov    rdi,rbx
  a38a17:	e8 e4 df a8 ff                                  	call   0x4c6a00
  a38a1c:	41 80 a7 99 00 00 00 ef                         	and    BYTE PTR [r15+0x99],0xef
  a38a24:	48 89 df                                        	mov    rdi,rbx
  a38a27:	31 f6                                           	xor    esi,esi
  a38a29:	31 d2                                           	xor    edx,edx
  a38a2b:	31 c9                                           	xor    ecx,ecx
  a38a2d:	e8 6e e5 a8 ff                                  	call   0x4c6fa0
  a38a32:	4c 89 ff                                        	mov    rdi,r15
  a38a35:	e8 76 be cd ff                                  	call   0x7148b0
  a38a3a:	8b 75 c0                                        	mov    esi,DWORD PTR [rbp-0x40]
  a38a3d:	48 89 c2                                        	mov    rdx,rax
  a38a40:	48 8d 3d 7b 25 97 00                            	lea    rdi,[rip+0x97257b]        # 0x13aafc2
  a38a47:	31 c9                                           	xor    ecx,ecx
  a38a49:	31 c0                                           	xor    eax,eax
  a38a4b:	e8 c0 49 82 ff                                  	call   0x25d410
  a38a50:	49 8b 04 24                                     	mov    rax,QWORD PTR [r12]
  a38a54:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  a38a58:	75 1f                                           	jne    0xa38a79
  a38a5a:	44 89 e8                                        	mov    eax,r13d
  a38a5d:	48 83 c4 28                                     	add    rsp,0x28
  a38a61:	5b                                              	pop    rbx
  a38a62:	41 5c                                           	pop    r12
  a38a64:	41 5d                                           	pop    r13
  a38a66:	41 5e                                           	pop    r14
  a38a68:	41 5f                                           	pop    r15
  a38a6a:	5d                                              	pop    rbp
  a38a6b:	c3                                              	ret
  a38a6c:	4c 89 e7                                        	mov    rdi,r12
  a38a6f:	e8 6c bf ef ff                                  	call   0x9349e0
  a38a74:	e9 63 f7 ff ff                                  	jmp    0xa381dc
  a38a79:	e8 32 4c cc ff                                  	call   0x6fd6b0
  a38a7e:	0f 0b                                           	ud2
  a38a80:	48 8d 3d 89 03 b3 01                            	lea    rdi,[rip+0x1b30389]        # 0x2568e10
  a38a87:	4c 89 f6                                        	mov    rsi,r14
  a38a8a:	48 89 cb                                        	mov    rbx,rcx
  a38a8d:	e8 2e 6e a1 ff                                  	call   0x44f8c0
  a38a92:	48 89 d9                                        	mov    rcx,rbx
  a38a95:	e9 f1 f4 ff ff                                  	jmp    0xa37f8b
  a38a9a:	48 8d 3d 8f 03 b3 01                            	lea    rdi,[rip+0x1b3038f]        # 0x2568e30
  a38aa1:	4c 89 f6                                        	mov    rsi,r14
  a38aa4:	e8 17 6e a1 ff                                  	call   0x44f8c0
  a38aa9:	e9 46 f6 ff ff                                  	jmp    0xa380f4
  a38aae:	e8 9d 8e db ff                                  	call   0x7f1950
  a38ab3:	48 8d 3d f4 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff4]        # 0xa38aae
  a38aba:	e8 51 8d db ff                                  	call   0x7f1810
  a38abf:	48 8d 35 4d 10 94 00                            	lea    rsi,[rip+0x94104d]        # 0x1379b13
  a38ac6:	bf 18 00 00 00                                  	mov    edi,0x18
  a38acb:	eb 3c                                           	jmp    0xa38b09
  a38acd:	e8 7e 8e db ff                                  	call   0x7f1950
  a38ad2:	48 8d 3d f4 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff4]        # 0xa38acd
  a38ad9:	e8 32 8d db ff                                  	call   0x7f1810
  a38ade:	48 8d 35 2e 10 94 00                            	lea    rsi,[rip+0x94102e]        # 0x1379b13
  a38ae5:	bf 1c 00 00 00                                  	mov    edi,0x1c
  a38aea:	eb 1d                                           	jmp    0xa38b09
  a38aec:	e8 5f 8e db ff                                  	call   0x7f1950
  a38af1:	48 8d 3d f4 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff4]        # 0xa38aec
  a38af8:	e8 13 8d db ff                                  	call   0x7f1810
  a38afd:	48 8d 35 0f 10 94 00                            	lea    rsi,[rip+0x94100f]        # 0x1379b13
  a38b04:	bf 14 00 00 00                                  	mov    edi,0x14
  a38b09:	31 c0                                           	xor    eax,eax
  a38b0b:	e8 00 1f 26 00                                  	call   0xc9aa10
  a38b10:	0f 0b                                           	ud2
  a38b12:	48 8d 3d 37 03 b3 01                            	lea    rdi,[rip+0x1b30337]        # 0x2568e50
  a38b19:	4c 89 f6                                        	mov    rsi,r14
  a38b1c:	e8 9f 6d a1 ff                                  	call   0x44f8c0
  a38b21:	e9 b3 f7 ff ff                                  	jmp    0xa382d9
  a38b26:	90                                              	nop
  a38b27:	90                                              	nop
  a38b28:	90                                              	nop
  a38b29:	90                                              	nop
  a38b2a:	90                                              	nop
  a38b2b:	90                                              	nop
  a38b2c:	90                                              	nop
  a38b2d:	90                                              	nop
  a38b2e:	90                                              	nop
  a38b2f:	90                                              	nop
  a38b30:	55                                              	push   rbp
  a38b31:	48 89 e5                                        	mov    rbp,rsp
  a38b34:	41 57                                           	push   r15
  a38b36:	41 56                                           	push   r14
  a38b38:	41 55                                           	push   r13
  a38b3a:	41 54                                           	push   r12
  a38b3c:	53                                              	push   rbx
  a38b3d:	48 83 ec 18                                     	sub    rsp,0x18
  a38b41:	48 8d 05 c8 37 ee 02                            	lea    rax,[rip+0x2ee37c8]        # 0x391c310
  a38b48:	48 89 d3                                        	mov    rbx,rdx
  a38b4b:	41 89 f7                                        	mov    r15d,esi
  a38b4e:	41 bc ff ff ff ff                               	mov    r12d,0xffffffff
  a38b54:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  a38b57:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  a38b5b:	48 8b 47 40                                     	mov    rax,QWORD PTR [rdi+0x40]
  a38b5f:	4c 8b b7 98 02 00 00                            	mov    r14,QWORD PTR [rdi+0x298]
  a38b66:	8b 40 28                                        	mov    eax,DWORD PTR [rax+0x28]
  a38b69:	c1 e8 17                                        	shr    eax,0x17
  a38b6c:	83 e0 02                                        	and    eax,0x2
  a38b6f:	74 10                                           	je     0xa38b81
  a38b71:	49 89 fc                                        	mov    r12,rdi
  a38b74:	89 c7                                           	mov    edi,eax
  a38b76:	e8 75 91 b2 ff                                  	call   0x561cf0
  a38b7b:	4c 89 e7                                        	mov    rdi,r12
  a38b7e:	41 89 c4                                        	mov    r12d,eax
  a38b81:	48 8b 47 38                                     	mov    rax,QWORD PTR [rdi+0x38]
  a38b85:	4c 8b 68 38                                     	mov    r13,QWORD PTR [rax+0x38]
  a38b89:	48 8d 05 48 2f 83 ff                            	lea    rax,[rip+0xffffffffff832f48]        # 0x26bad8
  a38b90:	4c 29 e8                                        	sub    rax,r13
  a38b93:	48 c1 c8 03                                     	ror    rax,0x3
  a38b97:	48 83 f8 0f                                     	cmp    rax,0xf
  a38b9b:	0f 87 c2 00 00 00                               	ja     0xa38c63
  a38ba1:	41 8b b6 18 02 00 00                            	mov    esi,DWORD PTR [r14+0x218]
  a38ba8:	48 8d 4d c8                                     	lea    rcx,[rbp-0x38]
  a38bac:	44 89 fa                                        	mov    edx,r15d
  a38baf:	41 ff d5                                        	call   r13
  a38bb2:	41 89 c7                                        	mov    r15d,eax
  a38bb5:	41 83 fc ff                                     	cmp    r12d,0xffffffff
  a38bb9:	74 08                                           	je     0xa38bc3
  a38bbb:	44 89 e7                                        	mov    edi,r12d
  a38bbe:	e8 1d 92 b2 ff                                  	call   0x561de0
  a38bc3:	45 85 ff                                        	test   r15d,r15d
  a38bc6:	74 22                                           	je     0xa38bea
  a38bc8:	48 8d 3d 47 16 85 00                            	lea    rdi,[rip+0x851647]        # 0x128a216
  a38bcf:	48 8d 35 ef 40 92 00                            	lea    rsi,[rip+0x9240ef]        # 0x135ccc5
  a38bd6:	ba 94 11 00 00                                  	mov    edx,0x1194
  a38bdb:	44 89 f9                                        	mov    ecx,r15d
  a38bde:	45 89 f8                                        	mov    r8d,r15d
  a38be1:	31 c0                                           	xor    eax,eax
  a38be3:	e8 28 48 82 ff                                  	call   0x25d410
  a38be8:	eb 57                                           	jmp    0xa38c41
  a38bea:	49 8b 86 48 04 00 00                            	mov    rax,QWORD PTR [r14+0x448]
  a38bf1:	48 3b 05 a8 67 1b 03                            	cmp    rax,QWORD PTR [rip+0x31b67a8]        # 0x3bef3a0
  a38bf8:	74 0c                                           	je     0xa38c06
  a38bfa:	48 8b 45 c8                                     	mov    rax,QWORD PTR [rbp-0x38]
  a38bfe:	45 31 ff                                        	xor    r15d,r15d
  a38c01:	48 89 03                                        	mov    QWORD PTR [rbx],rax
  a38c04:	eb 3b                                           	jmp    0xa38c41
  a38c06:	48 8b 75 c8                                     	mov    rsi,QWORD PTR [rbp-0x38]
  a38c0a:	4c 89 f7                                        	mov    rdi,r14
  a38c0d:	e8 2e 24 93 ff                                  	call   0x36b040
  a38c12:	85 c0                                           	test   eax,eax
  a38c14:	74 e4                                           	je     0xa38bfa
  a38c16:	48 8d 3d f9 15 85 00                            	lea    rdi,[rip+0x8515f9]        # 0x128a216
  a38c1d:	48 8d 35 a1 40 92 00                            	lea    rsi,[rip+0x9240a1]        # 0x135ccc5
  a38c24:	ba 9b 11 00 00                                  	mov    edx,0x119b
  a38c29:	89 c1                                           	mov    ecx,eax
  a38c2b:	41 89 c0                                        	mov    r8d,eax
  a38c2e:	41 89 c7                                        	mov    r15d,eax
  a38c31:	31 c0                                           	xor    eax,eax
  a38c33:	e8 d8 47 82 ff                                  	call   0x25d410
  a38c38:	48 8b 7d c8                                     	mov    rdi,QWORD PTR [rbp-0x38]
  a38c3c:	e8 ff 17 b1 ff                                  	call   0x54a440
  a38c41:	48 8d 05 c8 36 ee 02                            	lea    rax,[rip+0x2ee36c8]        # 0x391c310
  a38c48:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  a38c4b:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  a38c4f:	75 31                                           	jne    0xa38c82
  a38c51:	44 89 f8                                        	mov    eax,r15d
  a38c54:	48 83 c4 18                                     	add    rsp,0x18
  a38c58:	5b                                              	pop    rbx
  a38c59:	41 5c                                           	pop    r12
  a38c5b:	41 5d                                           	pop    r13
  a38c5d:	41 5e                                           	pop    r14
  a38c5f:	41 5f                                           	pop    r15
  a38c61:	5d                                              	pop    rbp
  a38c62:	c3                                              	ret
  a38c63:	48 8d 05 26 02 b3 01                            	lea    rax,[rip+0x1b30226]        # 0x2568e90
  a38c6a:	48 89 7d c0                                     	mov    QWORD PTR [rbp-0x40],rdi
  a38c6e:	4c 89 ee                                        	mov    rsi,r13
  a38c71:	48 89 c7                                        	mov    rdi,rax
  a38c74:	e8 47 6c a1 ff                                  	call   0x44f8c0
  a38c79:	48 8b 7d c0                                     	mov    rdi,QWORD PTR [rbp-0x40]
  a38c7d:	e9 1f ff ff ff                                  	jmp    0xa38ba1
  a38c82:	e8 29 4a cc ff                                  	call   0x6fd6b0
  a38c87:	0f 0b                                           	ud2
  a38c89:	90                                              	nop
  a38c8a:	90                                              	nop
  a38c8b:	90                                              	nop
  a38c8c:	90                                              	nop
  a38c8d:	90                                              	nop
  a38c8e:	90                                              	nop
  a38c8f:	90                                              	nop
  a38c90:	55                                              	push   rbp
  a38c91:	48 89 e5                                        	mov    rbp,rsp
  a38c94:	41 57                                           	push   r15
  a38c96:	41 56                                           	push   r14
  a38c98:	53                                              	push   rbx
  a38c99:	48 83 ec 18                                     	sub    rsp,0x18
  a38c9d:	4c 8d 3d 6c 36 ee 02                            	lea    r15,[rip+0x2ee366c]        # 0x391c310
  a38ca4:	48 89 f3                                        	mov    rbx,rsi
  a38ca7:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  a38caa:	48 89 45 e0                                     	mov    QWORD PTR [rbp-0x20],rax
  a38cae:	48 8b bf 98 02 00 00                            	mov    rdi,QWORD PTR [rdi+0x298]
  a38cb5:	48 8b 47 30                                     	mov    rax,QWORD PTR [rdi+0x30]
  a38cb9:	8b 08                                           	mov    ecx,DWORD PTR [rax]
  a38cbb:	89 0e                                           	mov    DWORD PTR [rsi],ecx
  a38cbd:	8b 48 20                                        	mov    ecx,DWORD PTR [rax+0x20]
  a38cc0:	48 89 4e 10                                     	mov    QWORD PTR [rsi+0x10],rcx
  a38cc4:	8b 48 20                                        	mov    ecx,DWORD PTR [rax+0x20]
  a38cc7:	48 89 4e 18                                     	mov    QWORD PTR [rsi+0x18],rcx
  a38ccb:	48 8b 40 38                                     	mov    rax,QWORD PTR [rax+0x38]
  a38ccf:	48 89 46 20                                     	mov    QWORD PTR [rsi+0x20],rax
  a38cd3:	48 8d 75 d8                                     	lea    rsi,[rbp-0x28]
  a38cd7:	e8 d4 15 ef ff                                  	call   0x92a2b0
  a38cdc:	41 89 c6                                        	mov    r14d,eax
  a38cdf:	85 c0                                           	test   eax,eax
  a38ce1:	74 22                                           	je     0xa38d05
  a38ce3:	48 8d 3d c8 7e 97 00                            	lea    rdi,[rip+0x977ec8]        # 0x13b0bb2
  a38cea:	48 8d 35 b8 e3 90 00                            	lea    rsi,[rip+0x90e3b8]        # 0x13470a9
  a38cf1:	ba bf 11 00 00                                  	mov    edx,0x11bf
  a38cf6:	44 89 f1                                        	mov    ecx,r14d
  a38cf9:	45 89 f0                                        	mov    r8d,r14d
  a38cfc:	31 c0                                           	xor    eax,eax
  a38cfe:	e8 0d 47 82 ff                                  	call   0x25d410
  a38d03:	eb 0c                                           	jmp    0xa38d11
  a38d05:	48 8b 45 d8                                     	mov    rax,QWORD PTR [rbp-0x28]
  a38d09:	48 89 43 28                                     	mov    QWORD PTR [rbx+0x28],rax
  a38d0d:	48 89 43 30                                     	mov    QWORD PTR [rbx+0x30],rax
  a38d11:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  a38d14:	48 3b 45 e0                                     	cmp    rax,QWORD PTR [rbp-0x20]
  a38d18:	75 0e                                           	jne    0xa38d28
  a38d1a:	44 89 f0                                        	mov    eax,r14d
  a38d1d:	48 83 c4 18                                     	add    rsp,0x18
  a38d21:	5b                                              	pop    rbx
  a38d22:	41 5e                                           	pop    r14
  a38d24:	41 5f                                           	pop    r15
  a38d26:	5d                                              	pop    rbp
  a38d27:	c3                                              	ret
  a38d28:	e8 83 49 cc ff                                  	call   0x6fd6b0
  a38d2d:	0f 0b                                           	ud2
  a38d2f:	90                                              	nop
  a38d30:	55                                              	push   rbp
  a38d31:	48 89 e5                                        	mov    rbp,rsp
  a38d34:	41 57                                           	push   r15
  a38d36:	41 56                                           	push   r14
  a38d38:	41 55                                           	push   r13
  a38d3a:	41 54                                           	push   r12
  a38d3c:	53                                              	push   rbx
  a38d3d:	48 83 ec 58                                     	sub    rsp,0x58
  a38d41:	4c 8d 2d c8 35 ee 02                            	lea    r13,[rip+0x2ee35c8]        # 0x391c310
  a38d48:	89 75 9c                                        	mov    DWORD PTR [rbp-0x64],esi
  a38d4b:	49 89 fe                                        	mov    r14,rdi
  a38d4e:	be 00 00 08 00                                  	mov    esi,0x80000
  a38d53:	31 d2                                           	xor    edx,edx
  a38d55:	31 c9                                           	xor    ecx,ecx
  a38d57:	45 31 c0                                        	xor    r8d,r8d
  a38d5a:	45 31 c9                                        	xor    r9d,r9d
  a38d5d:	49 8b 45 00                                     	mov    rax,QWORD PTR [r13+0x0]
  a38d61:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  a38d65:	48 8b 9f 98 02 00 00                            	mov    rbx,QWORD PTR [rdi+0x298]
  a38d6c:	48 8b 43 30                                     	mov    rax,QWORD PTR [rbx+0x30]
  a38d70:	4c 8d 7b 68                                     	lea    r15,[rbx+0x68]
  a38d74:	4c 89 ff                                        	mov    rdi,r15
  a38d77:	44 8b 60 20                                     	mov    r12d,DWORD PTR [rax+0x20]
  a38d7b:	65 48 8b 04 25 00 00 00 00                      	mov    rax,QWORD PTR gs:0x0
  a38d84:	48 89 45 90                                     	mov    QWORD PTR [rbp-0x70],rax
  a38d88:	6a 00                                           	push   0x0
  a38d8a:	6a 00                                           	push   0x0
  a38d8c:	e8 df 89 1b 00                                  	call   0xbf1770
  a38d91:	48 83 c4 10                                     	add    rsp,0x10
  a38d95:	83 bb 38 04 00 00 00                            	cmp    DWORD PTR [rbx+0x438],0x0
  a38d9c:	0f 84 88 00 00 00                               	je     0xa38e2a
  a38da2:	83 bb 10 04 00 00 00                            	cmp    DWORD PTR [rbx+0x410],0x0
  a38da9:	0f 88 a8 03 00 00                               	js     0xa39157
  a38daf:	48 8b 7b 20                                     	mov    rdi,QWORD PTR [rbx+0x20]
  a38db3:	48 83 ec 08                                     	sub    rsp,0x8
  a38db7:	48 8d 45 a0                                     	lea    rax,[rbp-0x60]
  a38dbb:	31 f6                                           	xor    esi,esi
  a38dbd:	44 89 e2                                        	mov    edx,r12d
  a38dc0:	31 c9                                           	xor    ecx,ecx
  a38dc2:	45 31 c0                                        	xor    r8d,r8d
  a38dc5:	45 31 c9                                        	xor    r9d,r9d
  a38dc8:	50                                              	push   rax
  a38dc9:	6a 00                                           	push   0x0
  a38dcb:	6a 00                                           	push   0x0
  a38dcd:	e8 be 4d 06 00                                  	call   0xa9db90
  a38dd2:	48 83 c4 20                                     	add    rsp,0x20
  a38dd6:	85 c0                                           	test   eax,eax
  a38dd8:	74 75                                           	je     0xa38e4f
  a38dda:	48 8b 7d a0                                     	mov    rdi,QWORD PTR [rbp-0x60]
  a38dde:	41 89 c4                                        	mov    r12d,eax
  a38de1:	e8 aa 48 06 00                                  	call   0xa9d690
  a38de6:	4c 89 ff                                        	mov    rdi,r15
  a38de9:	be 00 00 10 00                                  	mov    esi,0x100000
  a38dee:	31 d2                                           	xor    edx,edx
  a38df0:	31 c9                                           	xor    ecx,ecx
  a38df2:	45 31 c0                                        	xor    r8d,r8d
  a38df5:	45 31 c9                                        	xor    r9d,r9d
  a38df8:	6a 00                                           	push   0x0
  a38dfa:	6a 00                                           	push   0x0
  a38dfc:	e8 6f 89 1b 00                                  	call   0xbf1770
  a38e01:	48 83 c4 10                                     	add    rsp,0x10
  a38e05:	48 8d 3d 0a 14 85 00                            	lea    rdi,[rip+0x85140a]        # 0x128a216
  a38e0c:	48 8d 35 b9 9c 8d 00                            	lea    rsi,[rip+0x8d9cb9]        # 0x1312acc
  a38e13:	ba e0 11 00 00                                  	mov    edx,0x11e0
  a38e18:	44 89 e1                                        	mov    ecx,r12d
  a38e1b:	45 89 e0                                        	mov    r8d,r12d
  a38e1e:	31 c0                                           	xor    eax,eax
  a38e20:	e8 eb 45 82 ff                                  	call   0x25d410
  a38e25:	e9 0a 03 00 00                                  	jmp    0xa39134
  a38e2a:	48 89 5d 88                                     	mov    QWORD PTR [rbp-0x78],rbx
  a38e2e:	4c 89 ff                                        	mov    rdi,r15
  a38e31:	be 00 00 10 00                                  	mov    esi,0x100000
  a38e36:	31 d2                                           	xor    edx,edx
  a38e38:	31 c9                                           	xor    ecx,ecx
  a38e3a:	45 31 c0                                        	xor    r8d,r8d
  a38e3d:	45 31 c9                                        	xor    r9d,r9d
  a38e40:	6a 00                                           	push   0x0
  a38e42:	6a 00                                           	push   0x0
  a38e44:	e8 27 89 1b 00                                  	call   0xbf1770
  a38e49:	48 83 c4 10                                     	add    rsp,0x10
  a38e4d:	eb 6f                                           	jmp    0xa38ebe
  a38e4f:	48 8b 45 a0                                     	mov    rax,QWORD PTR [rbp-0x60]
  a38e53:	48 8b 7b 30                                     	mov    rdi,QWORD PTR [rbx+0x30]
  a38e57:	ba a0 05 00 00                                  	mov    edx,0x5a0
  a38e5c:	48 8b 70 18                                     	mov    rsi,QWORD PTR [rax+0x18]
  a38e60:	e8 7b 0d 82 ff                                  	call   0x259be0
  a38e65:	4c 89 ff                                        	mov    rdi,r15
  a38e68:	48 89 5d 88                                     	mov    QWORD PTR [rbp-0x78],rbx
  a38e6c:	c7 83 38 04 00 00 00 00 00 00                   	mov    DWORD PTR [rbx+0x438],0x0
  a38e76:	be 00 00 10 00                                  	mov    esi,0x100000
  a38e7b:	31 d2                                           	xor    edx,edx
  a38e7d:	31 c9                                           	xor    ecx,ecx
  a38e7f:	45 31 c0                                        	xor    r8d,r8d
  a38e82:	45 31 c9                                        	xor    r9d,r9d
  a38e85:	6a 00                                           	push   0x0
  a38e87:	6a 00                                           	push   0x0
  a38e89:	e8 e2 88 1b 00                                  	call   0xbf1770
  a38e8e:	48 83 c4 10                                     	add    rsp,0x10
  a38e92:	48 8b 7d a0                                     	mov    rdi,QWORD PTR [rbp-0x60]
  a38e96:	48 8b 07                                        	mov    rax,QWORD PTR [rdi]
  a38e99:	48 8b 40 20                                     	mov    rax,QWORD PTR [rax+0x20]
  a38e9d:	4c 8b 78 08                                     	mov    r15,QWORD PTR [rax+0x8]
  a38ea1:	48 8d 05 40 7e 82 ff                            	lea    rax,[rip+0xffffffffff827e40]        # 0x260ce8
  a38ea8:	4c 29 f8                                        	sub    rax,r15
  a38eab:	48 c1 c8 03                                     	ror    rax,0x3
  a38eaf:	48 3d ff 06 00 00                               	cmp    rax,0x6ff
  a38eb5:	0f 87 c2 02 00 00                               	ja     0xa3917d
  a38ebb:	41 ff d7                                        	call   r15
  a38ebe:	8b 4d 9c                                        	mov    ecx,DWORD PTR [rbp-0x64]
  a38ec1:	b8 01 00 00 00                                  	mov    eax,0x1
  a38ec6:	48 8d 7d a8                                     	lea    rdi,[rbp-0x58]
  a38eca:	4c 89 f6                                        	mov    rsi,r14
  a38ecd:	83 f9 04                                        	cmp    ecx,0x4
  a38ed0:	0f 45 c1                                        	cmovne eax,ecx
  a38ed3:	45 31 e4                                        	xor    r12d,r12d
  a38ed6:	83 f8 01                                        	cmp    eax,0x1
  a38ed9:	89 45 9c                                        	mov    DWORD PTR [rbp-0x64],eax
  a38edc:	41 0f 95 c7                                     	setne  r15b
  a38ee0:	e8 4b 1b b1 ff                                  	call   0x54aa30
  a38ee5:	48 85 c0                                        	test   rax,rax
  a38ee8:	0f 84 4c 01 00 00                               	je     0xa3903a
  a38eee:	45 88 fc                                        	mov    r12b,r15b
  a38ef1:	48 89 c3                                        	mov    rbx,rax
  a38ef4:	4d 8d 6e 18                                     	lea    r13,[r14+0x18]
  a38ef8:	4c 8d 7d a8                                     	lea    r15,[rbp-0x58]
  a38efc:	c7 45 98 00 00 00 00                            	mov    DWORD PTR [rbp-0x68],0x0
  a38f03:	41 c1 e4 09                                     	shl    r12d,0x9
  a38f07:	41 81 cc 00 09 08 00                            	or     r12d,0x80900
  a38f0e:	eb 4f                                           	jmp    0xa38f5f
  a38f10:	48 8d 3d ff 12 85 00                            	lea    rdi,[rip+0x8512ff]        # 0x128a216
  a38f17:	48 8d 35 ae 9b 8d 00                            	lea    rsi,[rip+0x8d9bae]        # 0x1312acc
  a38f1e:	ba 0f 12 00 00                                  	mov    edx,0x120f
  a38f23:	89 c1                                           	mov    ecx,eax
  a38f25:	41 89 c0                                        	mov    r8d,eax
  a38f28:	31 c0                                           	xor    eax,eax
  a38f2a:	e8 e1 44 82 ff                                  	call   0x25d410
  a38f2f:	4c 89 ef                                        	mov    rdi,r13
  a38f32:	31 f6                                           	xor    esi,esi
  a38f34:	31 d2                                           	xor    edx,edx
  a38f36:	31 c9                                           	xor    ecx,ecx
  a38f38:	e8 c3 da a8 ff                                  	call   0x4c6a00
  a38f3d:	4c 89 ff                                        	mov    rdi,r15
  a38f40:	4c 89 f6                                        	mov    rsi,r14
  a38f43:	e8 68 1c b1 ff                                  	call   0x54abb0
  a38f48:	4c 89 ff                                        	mov    rdi,r15
  a38f4b:	4c 89 f6                                        	mov    rsi,r14
  a38f4e:	e8 dd 1a b1 ff                                  	call   0x54aa30
  a38f53:	48 89 c3                                        	mov    rbx,rax
  a38f56:	48 85 c0                                        	test   rax,rax
  a38f59:	0f 84 e2 00 00 00                               	je     0xa39041
  a38f5f:	83 bb d4 01 00 00 00                            	cmp    DWORD PTR [rbx+0x1d4],0x0
  a38f66:	0f 84 a9 00 00 00                               	je     0xa39015
  a38f6c:	f6 83 c4 01 00 00 80                            	test   BYTE PTR [rbx+0x1c4],0x80
  a38f73:	0f 85 9c 00 00 00                               	jne    0xa39015
  a38f79:	48 8b 43 10                                     	mov    rax,QWORD PTR [rbx+0x10]
  a38f7d:	f6 40 20 0d                                     	test   BYTE PTR [rax+0x20],0xd
  a38f81:	75 13                                           	jne    0xa38f96
  a38f83:	83 7d 9c 03                                     	cmp    DWORD PTR [rbp-0x64],0x3
  a38f87:	0f 84 88 00 00 00                               	je     0xa39015
  a38f8d:	83 bb 58 01 00 00 00                            	cmp    DWORD PTR [rbx+0x158],0x0
  a38f94:	74 7f                                           	je     0xa39015
  a38f96:	48 8b 55 90                                     	mov    rdx,QWORD PTR [rbp-0x70]
  a38f9a:	48 89 df                                        	mov    rdi,rbx
  a38f9d:	44 89 e6                                        	mov    esi,r12d
  a38fa0:	e8 cb 0d b1 ff                                  	call   0x549d70
  a38fa5:	83 f8 02                                        	cmp    eax,0x2
  a38fa8:	0f 84 62 ff ff ff                               	je     0xa38f10
  a38fae:	83 f8 4d                                        	cmp    eax,0x4d
  a38fb1:	0f 84 59 ff ff ff                               	je     0xa38f10
  a38fb7:	85 c0                                           	test   eax,eax
  a38fb9:	75 6f                                           	jne    0xa3902a
  a38fbb:	48 8d 05 36 2b 0a 01                            	lea    rax,[rip+0x10a2b36]        # 0x1adbaf8
  a38fc2:	8b 4d 9c                                        	mov    ecx,DWORD PTR [rbp-0x64]
  a38fc5:	48 8d 75 b0                                     	lea    rsi,[rbp-0x50]
  a38fc9:	48 89 45 b0                                     	mov    QWORD PTR [rbp-0x50],rax
  a38fcd:	48 8b 45 90                                     	mov    rax,QWORD PTR [rbp-0x70]
  a38fd1:	48 89 5d b8                                     	mov    QWORD PTR [rbp-0x48],rbx
  a38fd5:	89 4d c0                                        	mov    DWORD PTR [rbp-0x40],ecx
  a38fd8:	48 89 45 c8                                     	mov    QWORD PTR [rbp-0x38],rax
  a38fdc:	48 8b 7b 08                                     	mov    rdi,QWORD PTR [rbx+0x8]
  a38fe0:	e8 bb 43 b5 ff                                  	call   0x58d3a0
  a38fe5:	85 c0                                           	test   eax,eax
  a38fe7:	74 22                                           	je     0xa3900b
  a38fe9:	48 8d 3d 26 12 85 00                            	lea    rdi,[rip+0x851226]        # 0x128a216
  a38ff0:	48 8d 35 d5 9a 8d 00                            	lea    rsi,[rip+0x8d9ad5]        # 0x1312acc
  a38ff7:	ba 18 12 00 00                                  	mov    edx,0x1218
  a38ffc:	89 c1                                           	mov    ecx,eax
  a38ffe:	41 89 c0                                        	mov    r8d,eax
  a39001:	89 45 98                                        	mov    DWORD PTR [rbp-0x68],eax
  a39004:	31 c0                                           	xor    eax,eax
  a39006:	e8 05 44 82 ff                                  	call   0x25d410
  a3900b:	48 89 df                                        	mov    rdi,rbx
  a3900e:	e8 2d 14 b1 ff                                  	call   0x54a440
  a39013:	eb 15                                           	jmp    0xa3902a
  a39015:	48 81 c3 b0 00 00 00                            	add    rbx,0xb0
  a3901c:	31 f6                                           	xor    esi,esi
  a3901e:	31 d2                                           	xor    edx,edx
  a39020:	31 c9                                           	xor    ecx,ecx
  a39022:	48 89 df                                        	mov    rdi,rbx
  a39025:	e8 76 df a8 ff                                  	call   0x4c6fa0
  a3902a:	4c 89 ff                                        	mov    rdi,r15
  a3902d:	4c 89 f6                                        	mov    rsi,r14
  a39030:	e8 ab 1f b1 ff                                  	call   0x54afe0
  a39035:	e9 19 ff ff ff                                  	jmp    0xa38f53
  a3903a:	c7 45 98 00 00 00 00                            	mov    DWORD PTR [rbp-0x68],0x0
  a39041:	48 8b 45 88                                     	mov    rax,QWORD PTR [rbp-0x78]
  a39045:	31 f6                                           	xor    esi,esi
  a39047:	31 d2                                           	xor    edx,edx
  a39049:	48 8b 58 20                                     	mov    rbx,QWORD PTR [rax+0x20]
  a3904d:	4c 8d b3 e8 00 00 00                            	lea    r14,[rbx+0xe8]
  a39054:	4c 89 f7                                        	mov    rdi,r14
  a39057:	e8 44 b6 d9 ff                                  	call   0x7d46a0
  a3905c:	83 7d 9c 03                                     	cmp    DWORD PTR [rbp-0x64],0x3
  a39060:	75 1c                                           	jne    0xa3907e
  a39062:	4c 89 f7                                        	mov    rdi,r14
  a39065:	31 f6                                           	xor    esi,esi
  a39067:	31 d2                                           	xor    edx,edx
  a39069:	e8 42 be d9 ff                                  	call   0x7d4eb0
  a3906e:	4c 8d 2d 9b 32 ee 02                            	lea    r13,[rip+0x2ee329b]        # 0x391c310
  a39075:	44 8b 65 98                                     	mov    r12d,DWORD PTR [rbp-0x68]
  a39079:	e9 b6 00 00 00                                  	jmp    0xa39134
  a3907e:	48 83 bb 60 01 00 00 00                         	cmp    QWORD PTR [rbx+0x160],0x0
  a39086:	7f 09                                           	jg     0xa39091
  a39088:	83 bb 58 01 00 00 00                            	cmp    DWORD PTR [rbx+0x158],0x0
  a3908f:	7e d1                                           	jle    0xa39062
  a39091:	4c 89 f7                                        	mov    rdi,r14
  a39094:	31 f6                                           	xor    esi,esi
  a39096:	31 d2                                           	xor    edx,edx
  a39098:	e8 13 be d9 ff                                  	call   0x7d4eb0
  a3909d:	48 8d 15 37 21 95 00                            	lea    rdx,[rip+0x952137]        # 0x138b1db
  a390a4:	48 89 df                                        	mov    rdi,rbx
  a390a7:	be 00 04 08 00                                  	mov    esi,0x80400
  a390ac:	b9 2b 12 00 00                                  	mov    ecx,0x122b
  a390b1:	e8 9a 6a c7 ff                                  	call   0x6afb50
  a390b6:	48 8d 05 3b 2a 0a 01                            	lea    rax,[rip+0x10a2a3b]        # 0x1adbaf8
  a390bd:	8b 4d 9c                                        	mov    ecx,DWORD PTR [rbp-0x64]
  a390c0:	48 8d 75 b0                                     	lea    rsi,[rbp-0x50]
  a390c4:	48 89 45 b0                                     	mov    QWORD PTR [rbp-0x50],rax
  a390c8:	48 8b 45 90                                     	mov    rax,QWORD PTR [rbp-0x70]
  a390cc:	48 89 5d b8                                     	mov    QWORD PTR [rbp-0x48],rbx
  a390d0:	89 4d c0                                        	mov    DWORD PTR [rbp-0x40],ecx
  a390d3:	48 89 45 c8                                     	mov    QWORD PTR [rbp-0x38],rax
  a390d7:	48 8b 7b 08                                     	mov    rdi,QWORD PTR [rbx+0x8]
  a390db:	e8 c0 42 b5 ff                                  	call   0x58d3a0
  a390e0:	4c 8d 2d 29 32 ee 02                            	lea    r13,[rip+0x2ee3229]        # 0x391c310
  a390e7:	44 8b 65 98                                     	mov    r12d,DWORD PTR [rbp-0x68]
  a390eb:	85 c0                                           	test   eax,eax
  a390ed:	74 22                                           	je     0xa39111
  a390ef:	48 8d 3d 20 11 85 00                            	lea    rdi,[rip+0x851120]        # 0x128a216
  a390f6:	48 8d 35 cf 99 8d 00                            	lea    rsi,[rip+0x8d99cf]        # 0x1312acc
  a390fd:	ba 2e 12 00 00                                  	mov    edx,0x122e
  a39102:	89 c1                                           	mov    ecx,eax
  a39104:	41 89 c0                                        	mov    r8d,eax
  a39107:	41 89 c4                                        	mov    r12d,eax
  a3910a:	31 c0                                           	xor    eax,eax
  a3910c:	e8 ff 42 82 ff                                  	call   0x25d410
  a39111:	48 8d 05 b0 3c 0a 01                            	lea    rax,[rip+0x10a3cb0]        # 0x1adcdc8
  a39118:	48 8d 75 b0                                     	lea    rsi,[rbp-0x50]
  a3911c:	48 89 45 b0                                     	mov    QWORD PTR [rbp-0x50],rax
  a39120:	48 89 5d b8                                     	mov    QWORD PTR [rbp-0x48],rbx
  a39124:	c7 45 c0 00 00 00 00                            	mov    DWORD PTR [rbp-0x40],0x0
  a3912b:	48 8b 7b 08                                     	mov    rdi,QWORD PTR [rbx+0x8]
  a3912f:	e8 5c 59 b5 ff                                  	call   0x58ea90
  a39134:	49 8b 45 00                                     	mov    rax,QWORD PTR [r13+0x0]
  a39138:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  a3913c:	75 12                                           	jne    0xa39150
  a3913e:	44 89 e0                                        	mov    eax,r12d
  a39141:	48 83 c4 58                                     	add    rsp,0x58
  a39145:	5b                                              	pop    rbx
  a39146:	41 5c                                           	pop    r12
  a39148:	41 5d                                           	pop    r13
  a3914a:	41 5e                                           	pop    r14
  a3914c:	41 5f                                           	pop    r15
  a3914e:	5d                                              	pop    rbp
  a3914f:	c3                                              	ret
  a39150:	e8 5b 45 cc ff                                  	call   0x6fd6b0
  a39155:	0f 0b                                           	ud2
  a39157:	e8 f4 87 db ff                                  	call   0x7f1950
  a3915c:	48 8d 3d f4 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff4]        # 0xa39157
  a39163:	e8 a8 86 db ff                                  	call   0x7f1810
  a39168:	48 8d 35 32 3b 92 00                            	lea    rsi,[rip+0x923b32]        # 0x135cca1
  a3916f:	bf 20 00 00 00                                  	mov    edi,0x20
  a39174:	31 c0                                           	xor    eax,eax
  a39176:	e8 95 18 26 00                                  	call   0xc9aa10
  a3917b:	0f 0b                                           	ud2
  a3917d:	48 8d 05 ec fc b2 01                            	lea    rax,[rip+0x1b2fcec]        # 0x2568e70
  a39184:	49 89 fc                                        	mov    r12,rdi
  a39187:	4c 89 fe                                        	mov    rsi,r15
  a3918a:	48 89 c7                                        	mov    rdi,rax
  a3918d:	e8 2e 67 a1 ff                                  	call   0x44f8c0
  a39192:	4c 89 e7                                        	mov    rdi,r12
  a39195:	e9 21 fd ff ff                                  	jmp    0xa38ebb
  a3919a:	90                                              	nop
  a3919b:	90                                              	nop
  a3919c:	90                                              	nop
  a3919d:	90                                              	nop
  a3919e:	90                                              	nop
  a3919f:	90                                              	nop
  a391a0:	55                                              	push   rbp
  a391a1:	48 89 e5                                        	mov    rbp,rsp
  a391a4:	41 57                                           	push   r15
  a391a6:	41 56                                           	push   r14
  a391a8:	41 55                                           	push   r13
  a391aa:	41 54                                           	push   r12
  a391ac:	53                                              	push   rbx
  a391ad:	48 83 ec 48                                     	sub    rsp,0x48
  a391b1:	48 8d 05 58 31 ee 02                            	lea    rax,[rip+0x2ee3158]        # 0x391c310
  a391b8:	49 89 cf                                        	mov    r15,rcx
  a391bb:	41 89 f5                                        	mov    r13d,esi
  a391be:	48 89 fb                                        	mov    rbx,rdi
  a391c1:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  a391c4:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  a391c8:	65 4c 8b 34 25 00 00 00 00                      	mov    r14,QWORD PTR gs:0x0
  a391d1:	48 83 ec 08                                     	sub    rsp,0x8
  a391d5:	89 55 b8                                        	mov    DWORD PTR [rbp-0x48],edx
  a391d8:	4c 89 f1                                        	mov    rcx,r14
  a391db:	4d 89 f8                                        	mov    r8,r15
  a391de:	45 31 c9                                        	xor    r9d,r9d
  a391e1:	6a 00                                           	push   0x0
  a391e3:	e8 88 68 0a 00                                  	call   0xadfa70
  a391e8:	48 83 c4 10                                     	add    rsp,0x10
  a391ec:	85 c0                                           	test   eax,eax
  a391ee:	74 2a                                           	je     0xa3921a
  a391f0:	48 8d 3d 1f 10 85 00                            	lea    rdi,[rip+0x85101f]        # 0x128a216
  a391f7:	48 8d 35 88 b6 88 00                            	lea    rsi,[rip+0x88b688]        # 0x12c4886
  a391fe:	ba 4f 12 00 00                                  	mov    edx,0x124f
  a39203:	89 c1                                           	mov    ecx,eax
  a39205:	41 89 c0                                        	mov    r8d,eax
  a39208:	41 89 c4                                        	mov    r12d,eax
  a3920b:	31 c0                                           	xor    eax,eax
  a3920d:	e8 fe 41 82 ff                                  	call   0x25d410
  a39212:	45 89 e5                                        	mov    r13d,r12d
  a39215:	e9 b1 01 00 00                                  	jmp    0xa393cb
  a3921a:	49 83 3f 00                                     	cmp    QWORD PTR [r15],0x0
  a3921e:	8b 4d b8                                        	mov    ecx,DWORD PTR [rbp-0x48]
  a39221:	44 89 6d c4                                     	mov    DWORD PTR [rbp-0x3c],r13d
  a39225:	41 bd 00 00 00 00                               	mov    r13d,0x0
  a3922b:	4c 89 75 98                                     	mov    QWORD PTR [rbp-0x68],r14
  a3922f:	0f 85 96 01 00 00                               	jne    0xa393cb
  a39235:	49 89 de                                        	mov    r14,rbx
  a39238:	48 8b 9b 98 02 00 00                            	mov    rbx,QWORD PTR [rbx+0x298]
  a3923f:	89 c8                                           	mov    eax,ecx
  a39241:	4c 89 7d b0                                     	mov    QWORD PTR [rbp-0x50],r15
  a39245:	41 89 cf                                        	mov    r15d,ecx
  a39248:	48 8b 3d 41 61 1b 03                            	mov    rdi,QWORD PTR [rip+0x31b6141]        # 0x3bef390
  a3924f:	ba 02 01 00 00                                  	mov    edx,0x102
  a39254:	41 81 e7 ff ff 00 ff                            	and    r15d,0xff00ffff
  a3925b:	25 00 00 ff 00                                  	and    eax,0xff0000
  a39260:	41 81 cf 00 00 08 00                            	or     r15d,0x80000
  a39267:	3d 00 00 20 00                                  	cmp    eax,0x200000
  a3926c:	44 0f 45 f9                                     	cmovne r15d,ecx
  a39270:	31 f6                                           	xor    esi,esi
  a39272:	48 8b 43 08                                     	mov    rax,QWORD PTR [rbx+0x8]
  a39276:	48 8b 4b 30                                     	mov    rcx,QWORD PTR [rbx+0x30]
  a3927a:	48 89 45 a0                                     	mov    QWORD PTR [rbp-0x60],rax
  a3927e:	48 89 4d b8                                     	mov    QWORD PTR [rbp-0x48],rcx
  a39282:	e8 f9 25 a0 ff                                  	call   0x43b880
  a39287:	48 8d 15 72 ae 08 01                            	lea    rdx,[rip+0x108ae72]        # 0x1ac4100
  a3928e:	48 8d 3d a4 7d 8d 00                            	lea    rdi,[rip+0x8d7da4]        # 0x1311039
  a39295:	48 8d 4d c8                                     	lea    rcx,[rbp-0x38]
  a39299:	4c 89 f6                                        	mov    rsi,r14
  a3929c:	49 89 c4                                        	mov    r12,rax
  a3929f:	e8 bc ec b0 ff                                  	call   0x547f60
  a392a4:	85 c0                                           	test   eax,eax
  a392a6:	74 37                                           	je     0xa392df
  a392a8:	48 8b 4d b0                                     	mov    rcx,QWORD PTR [rbp-0x50]
  a392ac:	4c 89 e6                                        	mov    rsi,r12
  a392af:	41 89 c5                                        	mov    r13d,eax
  a392b2:	31 d2                                           	xor    edx,edx
  a392b4:	48 c7 01 00 00 00 00                            	mov    QWORD PTR [rcx],0x0
  a392bb:	48 8b 3d ce 60 1b 03                            	mov    rdi,QWORD PTR [rip+0x31b60ce]        # 0x3bef390
  a392c2:	e8 f9 2d a0 ff                                  	call   0x43c0c0
  a392c7:	48 8d 3d 48 0f 85 00                            	lea    rdi,[rip+0x850f48]        # 0x128a216
  a392ce:	48 8d 35 b1 b5 88 00                            	lea    rsi,[rip+0x88b5b1]        # 0x12c4886
  a392d5:	ba 72 12 00 00                                  	mov    edx,0x1272
  a392da:	e9 df 00 00 00                                  	jmp    0xa393be
  a392df:	48 8b 45 c8                                     	mov    rax,QWORD PTR [rbp-0x38]
  a392e3:	44 89 7d ac                                     	mov    DWORD PTR [rbp-0x54],r15d
  a392e7:	be 00 00 08 00                                  	mov    esi,0x80000
  a392ec:	31 d2                                           	xor    edx,edx
  a392ee:	31 c9                                           	xor    ecx,ecx
  a392f0:	45 31 c0                                        	xor    r8d,r8d
  a392f3:	45 31 c9                                        	xor    r9d,r9d
  a392f6:	48 8b b8 b8 00 00 00                            	mov    rdi,QWORD PTR [rax+0xb8]
  a392fd:	6a 00                                           	push   0x0
  a392ff:	6a 00                                           	push   0x0
  a39301:	e8 6a 84 1b 00                                  	call   0xbf1770
  a39306:	48 83 c4 10                                     	add    rsp,0x10
  a3930a:	48 8b 45 c8                                     	mov    rax,QWORD PTR [rbp-0x38]
  a3930e:	48 8b b8 b8 00 00 00                            	mov    rdi,QWORD PTR [rax+0xb8]
  a39315:	e8 26 84 1b 00                                  	call   0xbf1740
  a3931a:	48 8b 45 c8                                     	mov    rax,QWORD PTR [rbp-0x38]
  a3931e:	48 8b 55 b8                                     	mov    rdx,QWORD PTR [rbp-0x48]
  a39322:	44 8b 7d c4                                     	mov    r15d,DWORD PTR [rbp-0x3c]
  a39326:	4c 89 f6                                        	mov    rsi,r14
  a39329:	4c 89 60 10                                     	mov    QWORD PTR [rax+0x10],r12
  a3932d:	8b 42 20                                        	mov    eax,DWORD PTR [rdx+0x20]
  a39330:	48 8b 4d c8                                     	mov    rcx,QWORD PTR [rbp-0x38]
  a39334:	89 81 6c 01 00 00                               	mov    DWORD PTR [rcx+0x16c],eax
  a3933a:	48 8b 4d a0                                     	mov    rcx,QWORD PTR [rbp-0x60]
  a3933e:	48 8b 45 c8                                     	mov    rax,QWORD PTR [rbp-0x38]
  a39342:	49 89 44 24 10                                  	mov    QWORD PTR [r12+0x10],rax
  a39347:	49 89 5c 24 18                                  	mov    QWORD PTR [r12+0x18],rbx
  a3934c:	49 89 54 24 40                                  	mov    QWORD PTR [r12+0x40],rdx
  a39351:	49 89 4c 24 28                                  	mov    QWORD PTR [r12+0x28],rcx
  a39356:	44 89 f9                                        	mov    ecx,r15d
  a39359:	48 8d 15 80 f9 b2 01                            	lea    rdx,[rip+0x1b2f980]        # 0x2568ce0
  a39360:	49 89 4c 24 30                                  	mov    QWORD PTR [r12+0x30],rcx
  a39365:	49 c7 84 24 a0 00 00 00 00 00 00 00             	mov    QWORD PTR [r12+0xa0],0x0
  a39371:	48 89 90 f0 00 00 00                            	mov    QWORD PTR [rax+0xf0],rdx
  a39378:	48 8b 7d c8                                     	mov    rdi,QWORD PTR [rbp-0x38]
  a3937c:	48 89 bf 10 01 00 00                            	mov    QWORD PTR [rdi+0x110],rdi
  a39383:	e8 28 f0 b0 ff                                  	call   0x5483b0
  a39388:	85 c0                                           	test   eax,eax
  a3938a:	74 65                                           	je     0xa393f1
  a3938c:	48 8b 3d fd 5f 1b 03                            	mov    rdi,QWORD PTR [rip+0x31b5ffd]        # 0x3bef390
  a39393:	4c 89 e6                                        	mov    rsi,r12
  a39396:	31 d2                                           	xor    edx,edx
  a39398:	41 89 c5                                        	mov    r13d,eax
  a3939b:	e8 20 2d a0 ff                                  	call   0x43c0c0
  a393a0:	48 8b 45 b0                                     	mov    rax,QWORD PTR [rbp-0x50]
  a393a4:	48 8d 3d 6b 0e 85 00                            	lea    rdi,[rip+0x850e6b]        # 0x128a216
  a393ab:	48 8d 35 d4 b4 88 00                            	lea    rsi,[rip+0x88b4d4]        # 0x12c4886
  a393b2:	ba 8f 12 00 00                                  	mov    edx,0x128f
  a393b7:	48 c7 00 00 00 00 00                            	mov    QWORD PTR [rax],0x0
  a393be:	44 89 e9                                        	mov    ecx,r13d
  a393c1:	45 89 e8                                        	mov    r8d,r13d
  a393c4:	31 c0                                           	xor    eax,eax
  a393c6:	e8 45 40 82 ff                                  	call   0x25d410
  a393cb:	48 8d 05 3e 2f ee 02                            	lea    rax,[rip+0x2ee2f3e]        # 0x391c310
  a393d2:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  a393d5:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  a393d9:	0f 85 4c 02 00 00                               	jne    0xa3962b
  a393df:	44 89 e8                                        	mov    eax,r13d
  a393e2:	48 83 c4 48                                     	add    rsp,0x48
  a393e6:	5b                                              	pop    rbx
  a393e7:	41 5c                                           	pop    r12
  a393e9:	41 5d                                           	pop    r13
  a393eb:	41 5e                                           	pop    r14
  a393ed:	41 5f                                           	pop    r15
  a393ef:	5d                                              	pop    rbp
  a393f0:	c3                                              	ret
  a393f1:	48 8b 45 c8                                     	mov    rax,QWORD PTR [rbp-0x38]
  a393f5:	81 a0 c8 01 00 00 ff ef ff ff                   	and    DWORD PTR [rax+0x1c8],0xffffefff
  a393ff:	48 8b 7d c8                                     	mov    rdi,QWORD PTR [rbp-0x38]
  a39403:	48 83 ec 08                                     	sub    rsp,0x8
  a39407:	44 89 fe                                        	mov    esi,r15d
  a3940a:	4c 8b 7d b0                                     	mov    r15,QWORD PTR [rbp-0x50]
  a3940e:	8b 55 ac                                        	mov    edx,DWORD PTR [rbp-0x54]
  a39411:	48 8b 4d 98                                     	mov    rcx,QWORD PTR [rbp-0x68]
  a39415:	45 31 ed                                        	xor    r13d,r13d
  a39418:	45 31 c9                                        	xor    r9d,r9d
  a3941b:	4d 89 f8                                        	mov    r8,r15
  a3941e:	6a 00                                           	push   0x0
  a39420:	e8 7b 68 0a 00                                  	call   0xadfca0
  a39425:	48 83 c4 10                                     	add    rsp,0x10
  a39429:	85 c0                                           	test   eax,eax
  a3942b:	74 29                                           	je     0xa39456
  a3942d:	48 8d 3d e2 0d 85 00                            	lea    rdi,[rip+0x850de2]        # 0x128a216
  a39434:	48 8d 35 4b b4 88 00                            	lea    rsi,[rip+0x88b44b]        # 0x12c4886
  a3943b:	ba 99 12 00 00                                  	mov    edx,0x1299
  a39440:	89 c1                                           	mov    ecx,eax
  a39442:	41 89 c0                                        	mov    r8d,eax
  a39445:	89 c3                                           	mov    ebx,eax
  a39447:	31 c0                                           	xor    eax,eax
  a39449:	e8 c2 3f 82 ff                                  	call   0x25d410
  a3944e:	41 89 dd                                        	mov    r13d,ebx
  a39451:	e9 75 ff ff ff                                  	jmp    0xa393cb
  a39456:	49 83 3f 00                                     	cmp    QWORD PTR [r15],0x0
  a3945a:	0f 85 6b ff ff ff                               	jne    0xa393cb
  a39460:	48 8b bb 48 04 00 00                            	mov    rdi,QWORD PTR [rbx+0x448]
  a39467:	ba 02 00 00 00                                  	mov    edx,0x2
  a3946c:	31 f6                                           	xor    esi,esi
  a3946e:	e8 0d 24 a0 ff                                  	call   0x43b880
  a39473:	4c 89 e7                                        	mov    rdi,r12
  a39476:	48 8d 15 5e bc 89 00                            	lea    rdx,[rip+0x89bc5e]        # 0x12d50db
  a3947d:	49 89 c6                                        	mov    r14,rax
  a39480:	49 89 84 24 88 00 00 00                         	mov    QWORD PTR [r12+0x88],rax
  a39488:	31 f6                                           	xor    esi,esi
  a3948a:	31 c9                                           	xor    ecx,ecx
  a3948c:	45 31 c0                                        	xor    r8d,r8d
  a3948f:	48 81 c7 c8 00 00 00                            	add    rdi,0xc8
  a39496:	e8 f5 81 1b 00                                  	call   0xbf1690
  a3949b:	8b 83 10 04 00 00                               	mov    eax,DWORD PTR [rbx+0x410]
  a394a1:	85 c0                                           	test   eax,eax
  a394a3:	78 26                                           	js     0xa394cb
  a394a5:	48 8d 7b 68                                     	lea    rdi,[rbx+0x68]
  a394a9:	be 00 00 08 00                                  	mov    esi,0x80000
  a394ae:	31 d2                                           	xor    edx,edx
  a394b0:	31 c9                                           	xor    ecx,ecx
  a394b2:	45 31 c0                                        	xor    r8d,r8d
  a394b5:	45 31 c9                                        	xor    r9d,r9d
  a394b8:	6a 00                                           	push   0x0
  a394ba:	6a 00                                           	push   0x0
  a394bc:	e8 af 82 1b 00                                  	call   0xbf1770
  a394c1:	48 83 c4 10                                     	add    rsp,0x10
  a394c5:	8b 83 10 04 00 00                               	mov    eax,DWORD PTR [rbx+0x410]
  a394cb:	a8 01                                           	test   al,0x1
  a394cd:	75 10                                           	jne    0xa394df
  a394cf:	8b 7d c4                                        	mov    edi,DWORD PTR [rbp-0x3c]
  a394d2:	48 89 de                                        	mov    rsi,rbx
  a394d5:	4c 89 f2                                        	mov    rdx,r14
  a394d8:	e8 23 c8 92 ff                                  	call   0x365d00
  a394dd:	eb 0e                                           	jmp    0xa394ed
  a394df:	8b 7d c4                                        	mov    edi,DWORD PTR [rbp-0x3c]
  a394e2:	48 89 de                                        	mov    rsi,rbx
  a394e5:	4c 89 f2                                        	mov    rdx,r14
  a394e8:	e8 03 d3 92 ff                                  	call   0x3667f0
  a394ed:	83 bb 10 04 00 00 00                            	cmp    DWORD PTR [rbx+0x410],0x0
  a394f4:	41 89 c5                                        	mov    r13d,eax
  a394f7:	78 20                                           	js     0xa39519
  a394f9:	48 8d 7b 68                                     	lea    rdi,[rbx+0x68]
  a394fd:	be 00 00 10 00                                  	mov    esi,0x100000
  a39502:	31 d2                                           	xor    edx,edx
  a39504:	31 c9                                           	xor    ecx,ecx
  a39506:	45 31 c0                                        	xor    r8d,r8d
  a39509:	45 31 c9                                        	xor    r9d,r9d
  a3950c:	6a 00                                           	push   0x0
  a3950e:	6a 00                                           	push   0x0
  a39510:	e8 5b 82 1b 00                                  	call   0xbf1770
  a39515:	48 83 c4 10                                     	add    rsp,0x10
  a39519:	45 85 ed                                        	test   r13d,r13d
  a3951c:	74 31                                           	je     0xa3954f
  a3951e:	48 8b 7d c8                                     	mov    rdi,QWORD PTR [rbp-0x38]
  a39522:	e8 99 1c b1 ff                                  	call   0x54b1c0
  a39527:	48 8b 7d c8                                     	mov    rdi,QWORD PTR [rbp-0x38]
  a3952b:	e8 10 0f b1 ff                                  	call   0x54a440
  a39530:	49 c7 07 00 00 00 00                            	mov    QWORD PTR [r15],0x0
  a39537:	48 8d 3d d8 0c 85 00                            	lea    rdi,[rip+0x850cd8]        # 0x128a216
  a3953e:	48 8d 35 41 b3 88 00                            	lea    rsi,[rip+0x88b341]        # 0x12c4886
  a39545:	ba b3 12 00 00                                  	mov    edx,0x12b3
  a3954a:	e9 6f fe ff ff                                  	jmp    0xa393be
  a3954f:	49 c7 44 24 58 00 00 00 00                      	mov    QWORD PTR [r12+0x58],0x0
  a39558:	48 8d 35 41 ab 09 01                            	lea    rsi,[rip+0x109ab41]        # 0x1ad40a0
  a3955f:	41 0f b7 06                                     	movzx  eax,WORD PTR [r14]
  a39563:	66 41 89 44 24 60                               	mov    WORD PTR [r12+0x60],ax
  a39569:	c1 e8 0c                                        	shr    eax,0xc
  a3956c:	41 8b 4e 04                                     	mov    ecx,DWORD PTR [r14+0x4]
  a39570:	41 89 8c 24 84 00 00 00                         	mov    DWORD PTR [r12+0x84],ecx
  a39578:	49 8b 4e 08                                     	mov    rcx,QWORD PTR [r14+0x8]
  a3957c:	49 89 4c 24 68                                  	mov    QWORD PTR [r12+0x68],rcx
  a39581:	41 8b 4e 48                                     	mov    ecx,DWORD PTR [r14+0x48]
  a39585:	41 89 4c 24 7c                                  	mov    DWORD PTR [r12+0x7c],ecx
  a3958a:	41 8b 4e 4c                                     	mov    ecx,DWORD PTR [r14+0x4c]
  a3958e:	41 89 8c 24 80 00 00 00                         	mov    DWORD PTR [r12+0x80],ecx
  a39596:	41 0f b7 4e 02                                  	movzx  ecx,WORD PTR [r14+0x2]
  a3959b:	66 41 89 4c 24 62                               	mov    WORD PTR [r12+0x62],cx
  a395a1:	49 8b 4e 10                                     	mov    rcx,QWORD PTR [r14+0x10]
  a395a5:	49 89 4c 24 70                                  	mov    QWORD PTR [r12+0x70],rcx
  a395aa:	8b 04 86                                        	mov    eax,DWORD PTR [rsi+rax*4]
  a395ad:	48 8b 55 c8                                     	mov    rdx,QWORD PTR [rbp-0x38]
  a395b1:	89 82 d4 01 00 00                               	mov    DWORD PTR [rdx+0x1d4],eax
  a395b7:	48 8b 45 c8                                     	mov    rax,QWORD PTR [rbp-0x38]
  a395bb:	48 8b b8 b8 00 00 00                            	mov    rdi,QWORD PTR [rax+0xb8]
  a395c2:	e8 69 81 1b 00                                  	call   0xbf1730
  a395c7:	8b 83 18 02 00 00                               	mov    eax,DWORD PTR [rbx+0x218]
  a395cd:	49 39 44 24 30                                  	cmp    QWORD PTR [r12+0x30],rax
  a395d2:	75 48                                           	jne    0xa3961c
  a395d4:	48 8b 45 c8                                     	mov    rax,QWORD PTR [rbp-0x38]
  a395d8:	48 8b 4d b8                                     	mov    rcx,QWORD PTR [rbp-0x48]
  a395dc:	83 88 c8 01 00 00 01                            	or     DWORD PTR [rax+0x1c8],0x1
  a395e3:	48 83 39 01                                     	cmp    QWORD PTR [rcx],0x1
  a395e7:	75 33                                           	jne    0xa3961c
  a395e9:	48 83 bb 78 02 00 00 00                         	cmp    QWORD PTR [rbx+0x278],0x0
  a395f1:	74 29                                           	je     0xa3961c
  a395f3:	48 8d 35 96 f2 b2 01                            	lea    rsi,[rip+0x1b2f296]        # 0x2568890
  a395fa:	bf 10 00 00 00                                  	mov    edi,0x10
  a395ff:	ba 02 01 00 00                                  	mov    edx,0x102
  a39604:	e8 47 f5 1c 00                                  	call   0xc08b50
  a39609:	48 c7 00 01 00 00 00                            	mov    QWORD PTR [rax],0x1
  a39610:	c6 40 08 2f                                     	mov    BYTE PTR [rax+0x8],0x2f
  a39614:	49 89 84 24 b8 00 00 00                         	mov    QWORD PTR [r12+0xb8],rax
  a3961c:	48 8b 45 c8                                     	mov    rax,QWORD PTR [rbp-0x38]
  a39620:	45 31 ed                                        	xor    r13d,r13d
  a39623:	49 89 07                                        	mov    QWORD PTR [r15],rax
  a39626:	e9 a0 fd ff ff                                  	jmp    0xa393cb
  a3962b:	e8 80 40 cc ff                                  	call   0x6fd6b0
  a39630:	0f 0b                                           	ud2
  a39632:	90                                              	nop
  a39633:	90                                              	nop
  a39634:	90                                              	nop
  a39635:	90                                              	nop
  a39636:	90                                              	nop
  a39637:	90                                              	nop
  a39638:	90                                              	nop
  a39639:	90                                              	nop
  a3963a:	90                                              	nop
  a3963b:	90                                              	nop
  a3963c:	90                                              	nop
  a3963d:	90                                              	nop
  a3963e:	90                                              	nop
  a3963f:	90                                              	nop
  a39640:	55                                              	push   rbp
  a39641:	48 89 e5                                        	mov    rbp,rsp
  a39644:	41 57                                           	push   r15
  a39646:	41 56                                           	push   r14
  a39648:	41 55                                           	push   r13
  a3964a:	41 54                                           	push   r12
  a3964c:	53                                              	push   rbx
  a3964d:	48 83 ec 28                                     	sub    rsp,0x28
  a39651:	4c 8d 2d b8 2c ee 02                            	lea    r13,[rip+0x2ee2cb8]        # 0x391c310
  a39658:	48 89 cb                                        	mov    rbx,rcx
  a3965b:	49 89 fe                                        	mov    r14,rdi
  a3965e:	41 bf ff ff ff ff                               	mov    r15d,0xffffffff
  a39664:	49 8b 45 00                                     	mov    rax,QWORD PTR [r13+0x0]
  a39668:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  a3966c:	48 85 ff                                        	test   rdi,rdi
  a3966f:	74 23                                           	je     0xa39694
  a39671:	49 8b 46 40                                     	mov    rax,QWORD PTR [r14+0x40]
  a39675:	8b 78 28                                        	mov    edi,DWORD PTR [rax+0x28]
  a39678:	c1 ef 17                                        	shr    edi,0x17
  a3967b:	83 e7 02                                        	and    edi,0x2
  a3967e:	74 14                                           	je     0xa39694
  a39680:	41 89 d7                                        	mov    r15d,edx
  a39683:	49 89 f4                                        	mov    r12,rsi
  a39686:	e8 65 86 b2 ff                                  	call   0x561cf0
  a3968b:	44 89 fa                                        	mov    edx,r15d
  a3968e:	4c 89 e6                                        	mov    rsi,r12
  a39691:	41 89 c7                                        	mov    r15d,eax
  a39694:	49 8b 46 38                                     	mov    rax,QWORD PTR [r14+0x38]
  a39698:	4c 8b 60 38                                     	mov    r12,QWORD PTR [rax+0x38]
  a3969c:	48 8d 05 35 24 83 ff                            	lea    rax,[rip+0xffffffffff832435]        # 0x26bad8
  a396a3:	4c 29 e0                                        	sub    rax,r12
  a396a6:	48 c1 c8 03                                     	ror    rax,0x3
  a396aa:	48 83 f8 0f                                     	cmp    rax,0xf
  a396ae:	0f 87 8e 00 00 00                               	ja     0xa39742
  a396b4:	8b 76 04                                        	mov    esi,DWORD PTR [rsi+0x4]
  a396b7:	48 8d 4d c8                                     	lea    rcx,[rbp-0x38]
  a396bb:	4c 89 f7                                        	mov    rdi,r14
  a396be:	41 ff d4                                        	call   r12
  a396c1:	41 83 ff ff                                     	cmp    r15d,0xffffffff
  a396c5:	74 0e                                           	je     0xa396d5
  a396c7:	44 89 ff                                        	mov    edi,r15d
  a396ca:	41 89 c7                                        	mov    r15d,eax
  a396cd:	e8 0e 87 b2 ff                                  	call   0x561de0
  a396d2:	44 89 f8                                        	mov    eax,r15d
  a396d5:	85 c0                                           	test   eax,eax
  a396d7:	74 09                                           	je     0xa396e2
  a396d9:	48 c7 03 00 00 00 00                            	mov    QWORD PTR [rbx],0x0
  a396e0:	eb 47                                           	jmp    0xa39729
  a396e2:	48 8b 7d c8                                     	mov    rdi,QWORD PTR [rbp-0x38]
  a396e6:	48 8b 47 10                                     	mov    rax,QWORD PTR [rdi+0x10]
  a396ea:	66 83 78 60 00                                  	cmp    WORD PTR [rax+0x60],0x0
  a396ef:	74 27                                           	je     0xa39718
  a396f1:	48 89 3b                                        	mov    QWORD PTR [rbx],rdi
  a396f4:	48 8b 70 68                                     	mov    rsi,QWORD PTR [rax+0x68]
  a396f8:	65 48 8b 14 25 00 00 00 00                      	mov    rdx,QWORD PTR gs:0x0
  a39701:	45 8b 86 30 03 00 00                            	mov    r8d,DWORD PTR [r14+0x330]
  a39708:	41 8b 8e 34 03 00 00                            	mov    ecx,DWORD PTR [r14+0x334]
  a3970f:	e8 cc eb c6 ff                                  	call   0x6a82e0
  a39714:	31 c0                                           	xor    eax,eax
  a39716:	eb 11                                           	jmp    0xa39729
  a39718:	e8 23 0d b1 ff                                  	call   0x54a440
  a3971d:	48 c7 03 00 00 00 00                            	mov    QWORD PTR [rbx],0x0
  a39724:	b8 46 00 00 00                                  	mov    eax,0x46
  a39729:	49 8b 4d 00                                     	mov    rcx,QWORD PTR [r13+0x0]
  a3972d:	48 3b 4d d0                                     	cmp    rcx,QWORD PTR [rbp-0x30]
  a39731:	75 31                                           	jne    0xa39764
  a39733:	48 83 c4 28                                     	add    rsp,0x28
  a39737:	5b                                              	pop    rbx
  a39738:	41 5c                                           	pop    r12
  a3973a:	41 5d                                           	pop    r13
  a3973c:	41 5e                                           	pop    r14
  a3973e:	41 5f                                           	pop    r15
  a39740:	5d                                              	pop    rbp
  a39741:	c3                                              	ret
  a39742:	48 89 75 b8                                     	mov    QWORD PTR [rbp-0x48],rsi
  a39746:	48 8d 3d 63 f7 b2 01                            	lea    rdi,[rip+0x1b2f763]        # 0x2568eb0
  a3974d:	4c 89 e6                                        	mov    rsi,r12
  a39750:	89 55 c4                                        	mov    DWORD PTR [rbp-0x3c],edx
  a39753:	e8 68 61 a1 ff                                  	call   0x44f8c0
  a39758:	48 8b 75 b8                                     	mov    rsi,QWORD PTR [rbp-0x48]
  a3975c:	8b 55 c4                                        	mov    edx,DWORD PTR [rbp-0x3c]
  a3975f:	e9 50 ff ff ff                                  	jmp    0xa396b4
  a39764:	e8 47 3f cc ff                                  	call   0x6fd6b0
  a39769:	0f 0b                                           	ud2
  a3976b:	90                                              	nop
  a3976c:	90                                              	nop
  a3976d:	90                                              	nop
  a3976e:	90                                              	nop
  a3976f:	90                                              	nop
  a39770:	55                                              	push   rbp
  a39771:	48 89 e5                                        	mov    rbp,rsp
  a39774:	e8 97 cd a2 ff                                  	call   0x466510
  a39779:	e8 42 bd 92 ff                                  	call   0x3654c0
  a3977e:	31 c0                                           	xor    eax,eax
  a39780:	5d                                              	pop    rbp
  a39781:	c3                                              	ret
  a39782:	90                                              	nop
  a39783:	90                                              	nop
  a39784:	90                                              	nop
  a39785:	90                                              	nop
  a39786:	90                                              	nop
  a39787:	90                                              	nop
  a39788:	90                                              	nop
  a39789:	90                                              	nop
  a3978a:	90                                              	nop
  a3978b:	90                                              	nop
  a3978c:	90                                              	nop
  a3978d:	90                                              	nop
  a3978e:	90                                              	nop
  a3978f:	90                                              	nop
  a39790:	55                                              	push   rbp
  a39791:	48 89 e5                                        	mov    rbp,rsp
  a39794:	e8 97 bd 92 ff                                  	call   0x365530
  a39799:	e8 d2 cf a2 ff                                  	call   0x466770
  a3979e:	31 c0                                           	xor    eax,eax
  a397a0:	5d                                              	pop    rbp
  a397a1:	c3                                              	ret
  a397a2:	90                                              	nop
  a397a3:	90                                              	nop
  a397a4:	90                                              	nop
  a397a5:	90                                              	nop
  a397a6:	90                                              	nop
  a397a7:	90                                              	nop
  a397a8:	90                                              	nop
  a397a9:	90                                              	nop
  a397aa:	90                                              	nop
  a397ab:	90                                              	nop
  a397ac:	90                                              	nop
  a397ad:	90                                              	nop
  a397ae:	90                                              	nop
  a397af:	90                                              	nop
  a397b0:	55                                              	push   rbp
  a397b1:	48 89 e5                                        	mov    rbp,rsp
  a397b4:	41 57                                           	push   r15
  a397b6:	41 56                                           	push   r14
  a397b8:	41 55                                           	push   r13
  a397ba:	41 54                                           	push   r12
  a397bc:	53                                              	push   rbx
  a397bd:	48 81 ec 78 01 00 00                            	sub    rsp,0x178
  a397c4:	48 8d 05 45 2b ee 02                            	lea    rax,[rip+0x2ee2b45]        # 0x391c310
  a397cb:	49 89 fc                                        	mov    r12,rdi
  a397ce:	48 89 f3                                        	mov    rbx,rsi
  a397d1:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  a397d4:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  a397d8:	48 c7 85 a8 fe ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x158],0x0
  a397e3:	48 c7 85 98 fe ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x168],0x0
  a397ee:	48 c7 85 a0 fe ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x160],0x0
  a397f9:	4c 8b ae 98 00 00 00                            	mov    r13,QWORD PTR [rsi+0x98]
  a39800:	48 8b 7f 30                                     	mov    rdi,QWORD PTR [rdi+0x30]
  a39804:	41 83 e5 01                                     	and    r13d,0x1
  a39808:	48 89 bd 70 fe ff ff                            	mov    QWORD PTR [rbp-0x190],rdi
  a3980f:	e8 0c 52 ca ff                                  	call   0x6dea20
  a39814:	4c 8d 35 4d 1b ac 02                            	lea    r14,[rip+0x2ac1b4d]        # 0x34fb368
  a3981b:	31 f6                                           	xor    esi,esi
  a3981d:	31 d2                                           	xor    edx,edx
  a3981f:	31 c9                                           	xor    ecx,ecx
  a39821:	4c 89 f7                                        	mov    rdi,r14
  a39824:	e8 f7 22 21 00                                  	call   0xc4bb20
  a39829:	44 8b 8b 30 03 00 00                            	mov    r9d,DWORD PTR [rbx+0x330]
  a39830:	44 8b 83 34 03 00 00                            	mov    r8d,DWORD PTR [rbx+0x334]
  a39837:	44 89 e9                                        	mov    ecx,r13d
  a3983a:	48 8d 15 ce 54 95 00                            	lea    rdx,[rip+0x9554ce]        # 0x138ed0f
  a39841:	48 8d b5 a0 fe ff ff                            	lea    rsi,[rbp-0x160]
  a39848:	4c 89 e7                                        	mov    rdi,r12
  a3984b:	83 f1 01                                        	xor    ecx,0x1
  a3984e:	e8 cd 80 d0 ff                                  	call   0x741920
  a39853:	4c 89 f7                                        	mov    rdi,r14
  a39856:	41 89 c7                                        	mov    r15d,eax
  a39859:	31 f6                                           	xor    esi,esi
  a3985b:	31 d2                                           	xor    edx,edx
  a3985d:	e8 4e 2c 21 00                                  	call   0xc4c4b0
  a39862:	48 8d 05 5f 35 0a 01                            	lea    rax,[rip+0x10a355f]        # 0x1adcdc8
  a39869:	48 8d b5 50 ff ff ff                            	lea    rsi,[rbp-0xb0]
  a39870:	48 89 85 50 ff ff ff                            	mov    QWORD PTR [rbp-0xb0],rax
  a39877:	4c 89 a5 58 ff ff ff                            	mov    QWORD PTR [rbp-0xa8],r12
  a3987e:	c7 85 60 ff ff ff 00 00 00 00                   	mov    DWORD PTR [rbp-0xa0],0x0
  a39888:	49 8b 7c 24 08                                  	mov    rdi,QWORD PTR [r12+0x8]
  a3988d:	e8 fe 51 b5 ff                                  	call   0x58ea90
  a39892:	45 85 ff                                        	test   r15d,r15d
  a39895:	0f 84 18 02 00 00                               	je     0xa39ab3
  a3989b:	48 8d 3d 74 09 85 00                            	lea    rdi,[rip+0x850974]        # 0x128a216
  a398a2:	48 8d 35 a5 be 97 00                            	lea    rsi,[rip+0x97bea5]        # 0x13b574e
  a398a9:	45 31 f6                                        	xor    r14d,r14d
  a398ac:	ba 6a 0d 00 00                                  	mov    edx,0xd6a
  a398b1:	44 89 f9                                        	mov    ecx,r15d
  a398b4:	45 89 f8                                        	mov    r8d,r15d
  a398b7:	31 c0                                           	xor    eax,eax
  a398b9:	e8 52 3b 82 ff                                  	call   0x25d410
  a398be:	48 8b bd a8 fe ff ff                            	mov    rdi,QWORD PTR [rbp-0x158]
  a398c5:	48 85 ff                                        	test   rdi,rdi
  a398c8:	74 05                                           	je     0xa398cf
  a398ca:	e8 c1 3d 06 00                                  	call   0xa9d690
  a398cf:	48 83 bd a0 fe ff ff 00                         	cmp    QWORD PTR [rbp-0x160],0x0
  a398d7:	74 76                                           	je     0xa3994f
  a398d9:	48 8d 15 fb 18 95 00                            	lea    rdx,[rip+0x9518fb]        # 0x138b1db
  a398e0:	4c 89 e7                                        	mov    rdi,r12
  a398e3:	be 00 04 08 00                                  	mov    esi,0x80400
  a398e8:	b9 e1 0e 00 00                                  	mov    ecx,0xee1
  a398ed:	e8 5e 62 c7 ff                                  	call   0x6afb50
  a398f2:	4c 8d 2d 6f 1a ac 02                            	lea    r13,[rip+0x2ac1a6f]        # 0x34fb368
  a398f9:	31 f6                                           	xor    esi,esi
  a398fb:	31 d2                                           	xor    edx,edx
  a398fd:	31 c9                                           	xor    ecx,ecx
  a398ff:	4c 89 ef                                        	mov    rdi,r13
  a39902:	e8 19 22 21 00                                  	call   0xc4bb20
  a39907:	48 8b bd a0 fe ff ff                            	mov    rdi,QWORD PTR [rbp-0x160]
  a3990e:	e8 6d 81 d0 ff                                  	call   0x741a80
  a39913:	4c 89 ef                                        	mov    rdi,r13
  a39916:	31 f6                                           	xor    esi,esi
  a39918:	31 d2                                           	xor    edx,edx
  a3991a:	e8 91 2b 21 00                                  	call   0xc4c4b0
  a3991f:	48 8d 05 a2 34 0a 01                            	lea    rax,[rip+0x10a34a2]        # 0x1adcdc8
  a39926:	48 8d b5 50 ff ff ff                            	lea    rsi,[rbp-0xb0]
  a3992d:	48 89 85 50 ff ff ff                            	mov    QWORD PTR [rbp-0xb0],rax
  a39934:	4c 89 a5 58 ff ff ff                            	mov    QWORD PTR [rbp-0xa8],r12
  a3993b:	c7 85 60 ff ff ff 00 00 00 00                   	mov    DWORD PTR [rbp-0xa0],0x0
  a39945:	49 8b 7c 24 08                                  	mov    rdi,QWORD PTR [r12+0x8]
  a3994a:	e8 41 51 b5 ff                                  	call   0x58ea90
  a3994f:	4d 85 f6                                        	test   r14,r14
  a39952:	0f 84 a4 07 00 00                               	je     0xa3a0fc
  a39958:	41 f6 86 10 04 00 00 01                         	test   BYTE PTR [r14+0x410],0x1
  a39960:	41 8b 86 50 04 00 00                            	mov    eax,DWORD PTR [r14+0x450]
  a39967:	0f 85 d8 02 00 00                               	jne    0xa39c45
  a3996d:	83 f8 01                                        	cmp    eax,0x1
  a39970:	0f 85 f1 04 00 00                               	jne    0xa39e67
  a39976:	49 83 be f8 05 00 00 00                         	cmp    QWORD PTR [r14+0x5f8],0x0
  a3997e:	74 0f                                           	je     0xa3998f
  a39980:	49 8d b6 f8 05 00 00                            	lea    rsi,[r14+0x5f8]
  a39987:	4c 89 f7                                        	mov    rdi,r14
  a3998a:	e8 41 10 f1 ff                                  	call   0x94a9d0
  a3998f:	49 8b be f8 06 00 00                            	mov    rdi,QWORD PTR [r14+0x6f8]
  a39996:	48 85 ff                                        	test   rdi,rdi
  a39999:	74 65                                           	je     0xa39a00
  a3999b:	48 81 c7 b0 00 00 00                            	add    rdi,0xb0
  a399a2:	31 f6                                           	xor    esi,esi
  a399a4:	31 d2                                           	xor    edx,edx
  a399a6:	31 c9                                           	xor    ecx,ecx
  a399a8:	e8 53 d0 a8 ff                                  	call   0x4c6a00
  a399ad:	49 8b be f8 06 00 00                            	mov    rdi,QWORD PTR [r14+0x6f8]
  a399b4:	f6 87 c4 01 00 00 80                            	test   BYTE PTR [rdi+0x1c4],0x80
  a399bb:	75 1a                                           	jne    0xa399d7
  a399bd:	48 8b 47 10                                     	mov    rax,QWORD PTR [rdi+0x10]
  a399c1:	48 8b 40 18                                     	mov    rax,QWORD PTR [rax+0x18]
  a399c5:	48 c7 80 10 07 00 00 00 00 00 00                	mov    QWORD PTR [rax+0x710],0x0
  a399d0:	49 8b be f8 06 00 00                            	mov    rdi,QWORD PTR [r14+0x6f8]
  a399d7:	48 81 c7 b0 00 00 00                            	add    rdi,0xb0
  a399de:	31 f6                                           	xor    esi,esi
  a399e0:	31 d2                                           	xor    edx,edx
  a399e2:	31 c9                                           	xor    ecx,ecx
  a399e4:	e8 b7 d5 a8 ff                                  	call   0x4c6fa0
  a399e9:	49 8b be f8 06 00 00                            	mov    rdi,QWORD PTR [r14+0x6f8]
  a399f0:	49 c7 86 f8 06 00 00 00 00 00 00                	mov    QWORD PTR [r14+0x6f8],0x0
  a399fb:	e8 20 07 b1 ff                                  	call   0x54a120
  a39a00:	49 8b be b0 06 00 00                            	mov    rdi,QWORD PTR [r14+0x6b0]
  a39a07:	48 85 ff                                        	test   rdi,rdi
  a39a0a:	74 7f                                           	je     0xa39a8b
  a39a0c:	48 83 c7 48                                     	add    rdi,0x48
  a39a10:	e8 3b e4 a8 ff                                  	call   0x4c7e50
  a39a15:	bf f0 00 00 00                                  	mov    edi,0xf0
  a39a1a:	49 03 be b0 06 00 00                            	add    rdi,QWORD PTR [r14+0x6b0]
  a39a21:	e8 2a e4 a8 ff                                  	call   0x4c7e50
  a39a26:	bf 98 01 00 00                                  	mov    edi,0x198
  a39a2b:	49 03 be b0 06 00 00                            	add    rdi,QWORD PTR [r14+0x6b0]
  a39a32:	e8 19 e4 a8 ff                                  	call   0x4c7e50
  a39a37:	bf 40 02 00 00                                  	mov    edi,0x240
  a39a3c:	49 03 be b0 06 00 00                            	add    rdi,QWORD PTR [r14+0x6b0]
  a39a43:	e8 08 e4 a8 ff                                  	call   0x4c7e50
  a39a48:	49 8b be b0 06 00 00                            	mov    rdi,QWORD PTR [r14+0x6b0]
  a39a4f:	48 8d 35 ca ed b2 01                            	lea    rsi,[rip+0x1b2edca]        # 0x2568820
  a39a56:	e8 95 f3 1c 00                                  	call   0xc08df0
  a39a5b:	49 8d be 18 06 00 00                            	lea    rdi,[r14+0x618]
  a39a62:	e8 e9 e3 a8 ff                                  	call   0x4c7e50
  a39a67:	49 8d be 60 06 00 00                            	lea    rdi,[r14+0x660]
  a39a6e:	e8 dd e3 a8 ff                                  	call   0x4c7e50
  a39a73:	49 8d be d0 06 00 00                            	lea    rdi,[r14+0x6d0]
  a39a7a:	e8 d1 e3 a8 ff                                  	call   0x4c7e50
  a39a7f:	49 8d be f0 06 00 00                            	lea    rdi,[r14+0x6f0]
  a39a86:	e8 c5 e3 a8 ff                                  	call   0x4c7e50
  a39a8b:	49 8b be 20 07 00 00                            	mov    rdi,QWORD PTR [r14+0x720]
  a39a92:	48 85 ff                                        	test   rdi,rdi
  a39a95:	0f 84 93 03 00 00                               	je     0xa39e2e
  a39a9b:	48 8d 35 7e ed b2 01                            	lea    rsi,[rip+0x1b2ed7e]        # 0x2568820
  a39aa2:	e8 49 f3 1c 00                                  	call   0xc08df0
  a39aa7:	49 8d be 70 07 00 00                            	lea    rdi,[r14+0x770]
  a39aae:	e9 76 03 00 00                                  	jmp    0xa39e29
  a39ab3:	48 8d 35 16 ec b2 01                            	lea    rsi,[rip+0x1b2ec16]        # 0x25686d0
  a39aba:	bf 98 09 00 00                                  	mov    edi,0x998
  a39abf:	ba 02 01 00 00                                  	mov    edx,0x102
  a39ac4:	e8 87 f0 1c 00                                  	call   0xc08b50
  a39ac9:	48 85 c0                                        	test   rax,rax
  a39acc:	0f 84 18 02 00 00                               	je     0xa39cea
  a39ad2:	48 8d 78 68                                     	lea    rdi,[rax+0x68]
  a39ad6:	48 8d 15 16 d3 85 00                            	lea    rdx,[rip+0x85d316]        # 0x1296df3
  a39add:	41 b8 01 00 00 00                               	mov    r8d,0x1
  a39ae3:	49 89 c7                                        	mov    r15,rax
  a39ae6:	49 89 c6                                        	mov    r14,rax
  a39ae9:	31 f6                                           	xor    esi,esi
  a39aeb:	31 c9                                           	xor    ecx,ecx
  a39aed:	e8 9e 7b 1b 00                                  	call   0xbf1690
  a39af2:	49 8d bf 30 04 00 00                            	lea    rdi,[r15+0x430]
  a39af9:	48 8d 35 51 5f 97 00                            	lea    rsi,[rip+0x975f51]        # 0x13afa51
  a39b00:	48 8d 15 bb 6b 95 00                            	lea    rdx,[rip+0x956bbb]        # 0x13906c2
  a39b07:	31 c9                                           	xor    ecx,ecx
  a39b09:	e8 c2 e2 a8 ff                                  	call   0x4c7dd0
  a39b0e:	48 b8 ff ff ff ff ff ff ff 7f                   	movabs rax,0x7fffffffffffffff
  a39b18:	41 c7 87 3c 04 00 00 09 00 00 00                	mov    DWORD PTR [r15+0x43c],0x9
  a39b23:	48 c7 85 50 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0xb0],0x0
  a39b2e:	48 8d 35 4e 5c 84 00                            	lea    rsi,[rip+0x845c4e]        # 0x127f783
  a39b35:	48 8d 15 b2 a5 90 00                            	lea    rdx,[rip+0x90a5b2]        # 0x13440ee
  a39b3c:	48 8d 8d b0 fe ff ff                            	lea    rcx,[rbp-0x150]
  a39b43:	49 89 87 40 04 00 00                            	mov    QWORD PTR [r15+0x440],rax
  a39b4a:	49 c7 87 b0 00 00 00 ff ff ff ff                	mov    QWORD PTR [r15+0xb0],0xffffffffffffffff
  a39b55:	49 c7 87 74 04 00 00 ff ff ff ff                	mov    QWORD PTR [r15+0x474],0xffffffffffffffff
  a39b60:	49 89 1f                                        	mov    QWORD PTR [r15],rbx
  a39b63:	31 c0                                           	xor    eax,eax
  a39b65:	48 8b bb a8 00 00 00                            	mov    rdi,QWORD PTR [rbx+0xa8]
  a39b6c:	e8 5f 77 ba ff                                  	call   0x5e12d0
  a39b71:	83 f8 01                                        	cmp    eax,0x1
  a39b74:	75 0d                                           	jne    0xa39b83
  a39b76:	8b 85 b0 fe ff ff                               	mov    eax,DWORD PTR [rbp-0x150]
  a39b7c:	41 89 86 c8 00 00 00                            	mov    DWORD PTR [r14+0xc8],eax
  a39b83:	48 8b bb a8 00 00 00                            	mov    rdi,QWORD PTR [rbx+0xa8]
  a39b8a:	48 8d 35 a7 bb 8e 00                            	lea    rsi,[rip+0x8ebba7]        # 0x1325738
  a39b91:	48 8d 15 56 a5 90 00                            	lea    rdx,[rip+0x90a556]        # 0x13440ee
  a39b98:	48 8d 8d b0 fe ff ff                            	lea    rcx,[rbp-0x150]
  a39b9f:	31 c0                                           	xor    eax,eax
  a39ba1:	e8 2a 77 ba ff                                  	call   0x5e12d0
  a39ba6:	83 f8 01                                        	cmp    eax,0x1
  a39ba9:	75 0d                                           	jne    0xa39bb8
  a39bab:	8b 85 b0 fe ff ff                               	mov    eax,DWORD PTR [rbp-0x150]
  a39bb1:	41 89 86 c4 00 00 00                            	mov    DWORD PTR [r14+0xc4],eax
  a39bb8:	48 8b bb a8 00 00 00                            	mov    rdi,QWORD PTR [rbx+0xa8]
  a39bbf:	48 8d 35 96 4f 83 00                            	lea    rsi,[rip+0x834f96]        # 0x126eb5c
  a39bc6:	48 8d 15 21 a5 90 00                            	lea    rdx,[rip+0x90a521]        # 0x13440ee
  a39bcd:	48 8d 8d b0 fe ff ff                            	lea    rcx,[rbp-0x150]
  a39bd4:	31 c0                                           	xor    eax,eax
  a39bd6:	e8 f5 76 ba ff                                  	call   0x5e12d0
  a39bdb:	83 f8 01                                        	cmp    eax,0x1
  a39bde:	75 17                                           	jne    0xa39bf7
  a39be0:	8b 85 b0 fe ff ff                               	mov    eax,DWORD PTR [rbp-0x150]
  a39be6:	85 c0                                           	test   eax,eax
  a39be8:	74 0d                                           	je     0xa39bf7
  a39bea:	83 f8 01                                        	cmp    eax,0x1
  a39bed:	75 4b                                           	jne    0xa39c3a
  a39bef:	41 80 8e 14 04 00 00 01                         	or     BYTE PTR [r14+0x414],0x1
  a39bf7:	48 8b bb a8 00 00 00                            	mov    rdi,QWORD PTR [rbx+0xa8]
  a39bfe:	48 8d 35 e2 3a 8e 00                            	lea    rsi,[rip+0x8e3ae2]        # 0x131d6e7
  a39c05:	48 8d 95 50 ff ff ff                            	lea    rdx,[rbp-0xb0]
  a39c0c:	31 c9                                           	xor    ecx,ecx
  a39c0e:	e8 bd 53 ba ff                                  	call   0x5defd0
  a39c13:	85 c0                                           	test   eax,eax
  a39c15:	0f 84 16 05 00 00                               	je     0xa3a131
  a39c1b:	48 8d 3d 01 f5 8a 00                            	lea    rdi,[rip+0x8af501]        # 0x12e9123
  a39c22:	48 8d 35 f4 67 94 00                            	lea    rsi,[rip+0x9467f4]        # 0x138041d
  a39c29:	ba d1 0b 00 00                                  	mov    edx,0xbd1
  a39c2e:	b9 16 00 00 00                                  	mov    ecx,0x16
  a39c33:	31 c0                                           	xor    eax,eax
  a39c35:	e8 d6 37 82 ff                                  	call   0x25d410
  a39c3a:	41 bf 16 00 00 00                               	mov    r15d,0x16
  a39c40:	e9 79 fc ff ff                                  	jmp    0xa398be
  a39c45:	83 f8 01                                        	cmp    eax,0x1
  a39c48:	0f 84 f5 00 00 00                               	je     0xa39d43
  a39c4e:	83 f8 02                                        	cmp    eax,0x2
  a39c51:	0f 84 bf 00 00 00                               	je     0xa39d16
  a39c57:	83 f8 03                                        	cmp    eax,0x3
  a39c5a:	0f 85 07 02 00 00                               	jne    0xa39e67
  a39c60:	49 83 be a8 04 00 00 00                         	cmp    QWORD PTR [r14+0x4a8],0x0
  a39c68:	74 0f                                           	je     0xa39c79
  a39c6a:	49 8d b6 a8 04 00 00                            	lea    rsi,[r14+0x4a8]
  a39c71:	4c 89 f7                                        	mov    rdi,r14
  a39c74:	e8 97 0c f1 ff                                  	call   0x94a910
  a39c79:	49 83 be f0 04 00 00 00                         	cmp    QWORD PTR [r14+0x4f0],0x0
  a39c81:	74 0f                                           	je     0xa39c92
  a39c83:	49 8d b6 f0 04 00 00                            	lea    rsi,[r14+0x4f0]
  a39c8a:	4c 89 f7                                        	mov    rdi,r14
  a39c8d:	e8 7e 0c f1 ff                                  	call   0x94a910
  a39c92:	49 8b be b0 05 00 00                            	mov    rdi,QWORD PTR [r14+0x5b0]
  a39c99:	48 85 ff                                        	test   rdi,rdi
  a39c9c:	0f 84 8c 01 00 00                               	je     0xa39e2e
  a39ca2:	48 8d 35 77 eb b2 01                            	lea    rsi,[rip+0x1b2eb77]        # 0x2568820
  a39ca9:	e8 42 f1 1c 00                                  	call   0xc08df0
  a39cae:	49 8d be c8 04 00 00                            	lea    rdi,[r14+0x4c8]
  a39cb5:	e8 96 e1 a8 ff                                  	call   0x4c7e50
  a39cba:	49 8d be 10 05 00 00                            	lea    rdi,[r14+0x510]
  a39cc1:	e8 8a e1 a8 ff                                  	call   0x4c7e50
  a39cc6:	49 8d be 58 05 00 00                            	lea    rdi,[r14+0x558]
  a39ccd:	e8 7e e1 a8 ff                                  	call   0x4c7e50
  a39cd2:	49 8d be f0 05 00 00                            	lea    rdi,[r14+0x5f0]
  a39cd9:	e8 72 e1 a8 ff                                  	call   0x4c7e50
  a39cde:	49 8d be d0 05 00 00                            	lea    rdi,[r14+0x5d0]
  a39ce5:	e9 3f 01 00 00                                  	jmp    0xa39e29
  a39cea:	48 8d 3d 25 05 85 00                            	lea    rdi,[rip+0x850525]        # 0x128a216
  a39cf1:	48 8d 35 56 ba 97 00                            	lea    rsi,[rip+0x97ba56]        # 0x13b574e
  a39cf8:	45 31 f6                                        	xor    r14d,r14d
  a39cfb:	41 bf 0c 00 00 00                               	mov    r15d,0xc
  a39d01:	ba 77 0d 00 00                                  	mov    edx,0xd77
  a39d06:	b9 0c 00 00 00                                  	mov    ecx,0xc
  a39d0b:	41 b8 0c 00 00 00                               	mov    r8d,0xc
  a39d11:	e9 a1 fb ff ff                                  	jmp    0xa398b7
  a39d16:	48 8d 3d f9 04 85 00                            	lea    rdi,[rip+0x8504f9]        # 0x128a216
  a39d1d:	48 8d 35 2a ba 97 00                            	lea    rsi,[rip+0x97ba2a]        # 0x13b574e
  a39d24:	ba 22 0f 00 00                                  	mov    edx,0xf22
  a39d29:	44 89 f9                                        	mov    ecx,r15d
  a39d2c:	45 89 f8                                        	mov    r8d,r15d
  a39d2f:	31 c0                                           	xor    eax,eax
  a39d31:	e8 da 36 82 ff                                  	call   0x25d410
  a39d36:	4c 89 f7                                        	mov    rdi,r14
  a39d39:	e8 32 17 93 ff                                  	call   0x36b470
  a39d3e:	e9 eb 00 00 00                                  	jmp    0xa39e2e
  a39d43:	4c 89 f7                                        	mov    rdi,r14
  a39d46:	e8 25 17 93 ff                                  	call   0x36b470
  a39d4b:	49 83 be f8 05 00 00 00                         	cmp    QWORD PTR [r14+0x5f8],0x0
  a39d53:	74 0f                                           	je     0xa39d64
  a39d55:	49 8d b6 f8 05 00 00                            	lea    rsi,[r14+0x5f8]
  a39d5c:	4c 89 f7                                        	mov    rdi,r14
  a39d5f:	e8 6c 0c f1 ff                                  	call   0x94a9d0
  a39d64:	49 8b be b0 05 00 00                            	mov    rdi,QWORD PTR [r14+0x5b0]
  a39d6b:	48 85 ff                                        	test   rdi,rdi
  a39d6e:	74 30                                           	je     0xa39da0
  a39d70:	48 8d 35 a9 ea b2 01                            	lea    rsi,[rip+0x1b2eaa9]        # 0x2568820
  a39d77:	e8 74 f0 1c 00                                  	call   0xc08df0
  a39d7c:	49 8d be 58 05 00 00                            	lea    rdi,[r14+0x558]
  a39d83:	e8 c8 e0 a8 ff                                  	call   0x4c7e50
  a39d88:	49 8d be f0 05 00 00                            	lea    rdi,[r14+0x5f0]
  a39d8f:	e8 bc e0 a8 ff                                  	call   0x4c7e50
  a39d94:	49 8d be d0 05 00 00                            	lea    rdi,[r14+0x5d0]
  a39d9b:	e8 b0 e0 a8 ff                                  	call   0x4c7e50
  a39da0:	49 83 be b0 06 00 00 00                         	cmp    QWORD PTR [r14+0x6b0],0x0
  a39da8:	0f 84 80 00 00 00                               	je     0xa39e2e
  a39dae:	83 bb 30 03 00 00 01                            	cmp    DWORD PTR [rbx+0x330],0x1
  a39db5:	b8 08 00 00 00                                  	mov    eax,0x8
  a39dba:	41 bc 14 00 00 00                               	mov    r12d,0x14
  a39dc0:	41 bd 48 00 00 00                               	mov    r13d,0x48
  a39dc6:	4c 0f 44 e0                                     	cmove  r12,rax
  a39dca:	66 0f 1f 44 00 00                               	nop    WORD PTR [rax+rax*1+0x0]
  a39dd0:	49 8b be b0 06 00 00                            	mov    rdi,QWORD PTR [r14+0x6b0]
  a39dd7:	4c 01 ef                                        	add    rdi,r13
  a39dda:	e8 71 e0 a8 ff                                  	call   0x4c7e50
  a39ddf:	49 81 c5 a8 00 00 00                            	add    r13,0xa8
  a39de6:	49 ff cc                                        	dec    r12
  a39de9:	75 e5                                           	jne    0xa39dd0
  a39deb:	49 8b be b0 06 00 00                            	mov    rdi,QWORD PTR [r14+0x6b0]
  a39df2:	48 8d 35 27 ea b2 01                            	lea    rsi,[rip+0x1b2ea27]        # 0x2568820
  a39df9:	e8 f2 ef 1c 00                                  	call   0xc08df0
  a39dfe:	49 8d be 18 06 00 00                            	lea    rdi,[r14+0x618]
  a39e05:	e8 46 e0 a8 ff                                  	call   0x4c7e50
  a39e0a:	49 8d be 60 06 00 00                            	lea    rdi,[r14+0x660]
  a39e11:	e8 3a e0 a8 ff                                  	call   0x4c7e50
  a39e16:	49 8d be d0 06 00 00                            	lea    rdi,[r14+0x6d0]
  a39e1d:	e8 2e e0 a8 ff                                  	call   0x4c7e50
  a39e22:	49 8d be f0 06 00 00                            	lea    rdi,[r14+0x6f0]
  a39e29:	e8 22 e0 a8 ff                                  	call   0x4c7e50
  a39e2e:	41 83 be 50 04 00 00 01                         	cmp    DWORD PTR [r14+0x450],0x1
  a39e36:	75 2f                                           	jne    0xa39e67
  a39e38:	49 63 86 84 07 00 00                            	movsxd rax,DWORD PTR [r14+0x784]
  a39e3f:	48 83 f8 ff                                     	cmp    rax,0xffffffffffffffff
  a39e43:	74 22                                           	je     0xa39e67
  a39e45:	48 8d 04 40                                     	lea    rax,[rax+rax*2]
  a39e49:	48 8d 0d 30 16 b7 02                            	lea    rcx,[rip+0x2b71630]        # 0x35ab480
  a39e50:	48 c1 e0 06                                     	shl    rax,0x6
  a39e54:	48 c7 04 08 00 00 00 00                         	mov    QWORD PTR [rax+rcx*1],0x0
  a39e5c:	41 c7 86 84 07 00 00 ff ff ff ff                	mov    DWORD PTR [r14+0x784],0xffffffff
  a39e67:	49 83 be a8 01 00 00 00                         	cmp    QWORD PTR [r14+0x1a8],0x0
  a39e6f:	74 3c                                           	je     0xa39ead
  a39e71:	49 8b be c8 01 00 00                            	mov    rdi,QWORD PTR [r14+0x1c8]
  a39e78:	48 8d 35 51 e8 b2 01                            	lea    rsi,[rip+0x1b2e851]        # 0x25686d0
  a39e7f:	e8 6c ef 1c 00                                  	call   0xc08df0
  a39e84:	49 8d be e0 01 00 00                            	lea    rdi,[r14+0x1e0]
  a39e8b:	e8 d0 78 1b 00                                  	call   0xbf1760
  a39e90:	49 8b 86 a8 01 00 00                            	mov    rax,QWORD PTR [r14+0x1a8]
  a39e97:	81 a0 c8 01 00 00 7f ff ff ff                   	and    DWORD PTR [rax+0x1c8],0xffffff7f
  a39ea1:	49 8b be a8 01 00 00                            	mov    rdi,QWORD PTR [r14+0x1a8]
  a39ea8:	e8 73 02 b1 ff                                  	call   0x54a120
  a39ead:	49 83 be 40 01 00 00 00                         	cmp    QWORD PTR [r14+0x140],0x0
  a39eb5:	74 3c                                           	je     0xa39ef3
  a39eb7:	49 8b be 60 01 00 00                            	mov    rdi,QWORD PTR [r14+0x160]
  a39ebe:	48 8d 35 0b e8 b2 01                            	lea    rsi,[rip+0x1b2e80b]        # 0x25686d0
  a39ec5:	e8 26 ef 1c 00                                  	call   0xc08df0
  a39eca:	49 8d be 78 01 00 00                            	lea    rdi,[r14+0x178]
  a39ed1:	e8 8a 78 1b 00                                  	call   0xbf1760
  a39ed6:	49 8b 86 40 01 00 00                            	mov    rax,QWORD PTR [r14+0x140]
  a39edd:	81 a0 c8 01 00 00 7f ff ff ff                   	and    DWORD PTR [rax+0x1c8],0xffffff7f
  a39ee7:	49 8b be 40 01 00 00                            	mov    rdi,QWORD PTR [r14+0x140]
  a39eee:	e8 2d 02 b1 ff                                  	call   0x54a120
  a39ef3:	49 83 be 10 02 00 00 00                         	cmp    QWORD PTR [r14+0x210],0x0
  a39efb:	74 29                                           	je     0xa39f26
  a39efd:	49 8d be 48 02 00 00                            	lea    rdi,[r14+0x248]
  a39f04:	e8 57 78 1b 00                                  	call   0xbf1760
  a39f09:	49 8b 86 10 02 00 00                            	mov    rax,QWORD PTR [r14+0x210]
  a39f10:	81 a0 c8 01 00 00 7f ff ff ff                   	and    DWORD PTR [rax+0x1c8],0xffffff7f
  a39f1a:	49 8b be 10 02 00 00                            	mov    rdi,QWORD PTR [r14+0x210]
  a39f21:	e8 fa 01 b1 ff                                  	call   0x54a120
  a39f26:	49 83 be 48 03 00 00 00                         	cmp    QWORD PTR [r14+0x348],0x0
  a39f2e:	74 29                                           	je     0xa39f59
  a39f30:	49 8d be 80 03 00 00                            	lea    rdi,[r14+0x380]
  a39f37:	e8 24 78 1b 00                                  	call   0xbf1760
  a39f3c:	49 8b 86 48 03 00 00                            	mov    rax,QWORD PTR [r14+0x348]
  a39f43:	81 a0 c8 01 00 00 7f ff ff ff                   	and    DWORD PTR [rax+0x1c8],0xffffff7f
  a39f4d:	49 8b be 48 03 00 00                            	mov    rdi,QWORD PTR [r14+0x348]
  a39f54:	e8 c7 01 b1 ff                                  	call   0x54a120
  a39f59:	49 83 be 78 02 00 00 00                         	cmp    QWORD PTR [r14+0x278],0x0
  a39f61:	74 64                                           	je     0xa39fc7
  a39f63:	49 8b 46 30                                     	mov    rax,QWORD PTR [r14+0x30]
  a39f67:	83 38 02                                        	cmp    DWORD PTR [rax],0x2
  a39f6a:	75 32                                           	jne    0xa39f9e
  a39f6c:	4d 8b a6 98 02 00 00                            	mov    r12,QWORD PTR [r14+0x298]
  a39f73:	31 c9                                           	xor    ecx,ecx
  a39f75:	4c 89 e0                                        	mov    rax,r12
  a39f78:	f0 49 0f b1 8e 98 02 00 00                      	lock cmpxchg QWORD PTR [r14+0x298],rcx
  a39f81:	0f 85 43 17 00 00                               	jne    0xa3b6ca
  a39f87:	4c 89 e7                                        	mov    rdi,r12
  a39f8a:	e8 c1 e9 b2 ff                                  	call   0x568950
  a39f8f:	48 8d 35 fa e8 b2 01                            	lea    rsi,[rip+0x1b2e8fa]        # 0x2568890
  a39f96:	4c 89 e7                                        	mov    rdi,r12
  a39f99:	e8 52 ee 1c 00                                  	call   0xc08df0
  a39f9e:	49 8d be b0 02 00 00                            	lea    rdi,[r14+0x2b0]
  a39fa5:	e8 b6 77 1b 00                                  	call   0xbf1760
  a39faa:	49 8b 86 78 02 00 00                            	mov    rax,QWORD PTR [r14+0x278]
  a39fb1:	81 a0 c8 01 00 00 7f ff ff ff                   	and    DWORD PTR [rax+0x1c8],0xffffff7f
  a39fbb:	49 8b be 78 02 00 00                            	mov    rdi,QWORD PTR [r14+0x278]
  a39fc2:	e8 59 01 b1 ff                                  	call   0x54a120
  a39fc7:	49 83 be e0 02 00 00 00                         	cmp    QWORD PTR [r14+0x2e0],0x0
  a39fcf:	74 29                                           	je     0xa39ffa
  a39fd1:	49 8d be 18 03 00 00                            	lea    rdi,[r14+0x318]
  a39fd8:	e8 83 77 1b 00                                  	call   0xbf1760
  a39fdd:	49 8b 86 e0 02 00 00                            	mov    rax,QWORD PTR [r14+0x2e0]
  a39fe4:	81 a0 c8 01 00 00 7f ff ff ff                   	and    DWORD PTR [rax+0x1c8],0xffffff7f
  a39fee:	49 8b be e0 02 00 00                            	mov    rdi,QWORD PTR [r14+0x2e0]
  a39ff5:	e8 26 01 b1 ff                                  	call   0x54a120
  a39ffa:	49 8b be 68 08 00 00                            	mov    rdi,QWORD PTR [r14+0x868]
  a3a001:	48 85 ff                                        	test   rdi,rdi
  a3a004:	74 2a                                           	je     0xa3a030
  a3a006:	ba 00 01 00 00                                  	mov    edx,0x100
  a3a00b:	31 f6                                           	xor    esi,esi
  a3a00d:	e8 7e 69 e3 ff                                  	call   0x870990
  a3a012:	49 8b be 68 08 00 00                            	mov    rdi,QWORD PTR [r14+0x868]
  a3a019:	48 8d 35 00 e8 b2 01                            	lea    rsi,[rip+0x1b2e800]        # 0x2568820
  a3a020:	e8 cb ed 1c 00                                  	call   0xc08df0
  a3a025:	49 c7 86 68 08 00 00 00 00 00 00                	mov    QWORD PTR [r14+0x868],0x0
  a3a030:	48 8b 85 98 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x168]
  a3a037:	48 85 c0                                        	test   rax,rax
  a3a03a:	74 13                                           	je     0xa3a04f
  a3a03c:	80 a0 c8 01 00 00 7f                            	and    BYTE PTR [rax+0x1c8],0x7f
  a3a043:	48 8b bd 98 fe ff ff                            	mov    rdi,QWORD PTR [rbp-0x168]
  a3a04a:	e8 d1 00 b1 ff                                  	call   0x54a120
  a3a04f:	49 8b 86 d0 00 00 00                            	mov    rax,QWORD PTR [r14+0xd0]
  a3a056:	48 85 c0                                        	test   rax,rax
  a3a059:	74 28                                           	je     0xa3a083
  a3a05b:	80 a0 c8 01 00 00 7f                            	and    BYTE PTR [rax+0x1c8],0x7f
  a3a062:	49 8b be d0 00 00 00                            	mov    rdi,QWORD PTR [r14+0xd0]
  a3a069:	e8 b2 00 b1 ff                                  	call   0x54a120
  a3a06e:	65 48 8b 0c 25 00 00 00 00                      	mov    rcx,QWORD PTR gs:0x0
  a3a077:	48 89 df                                        	mov    rdi,rbx
  a3a07a:	31 f6                                           	xor    esi,esi
  a3a07c:	31 d2                                           	xor    edx,edx
  a3a07e:	e8 dd 03 b1 ff                                  	call   0x54a460
  a3a083:	49 8b 7e 30                                     	mov    rdi,QWORD PTR [r14+0x30]
  a3a087:	48 85 ff                                        	test   rdi,rdi
  a3a08a:	74 1d                                           	je     0xa3a0a9
  a3a08c:	31 c9                                           	xor    ecx,ecx
  a3a08e:	48 89 f8                                        	mov    rax,rdi
  a3a091:	f0 49 0f b1 4e 30                               	lock cmpxchg QWORD PTR [r14+0x30],rcx
  a3a097:	0f 85 92 15 00 00                               	jne    0xa3b62f
  a3a09d:	48 8d 35 2c e6 b2 01                            	lea    rsi,[rip+0x1b2e62c]        # 0x25686d0
  a3a0a4:	e8 47 ed 1c 00                                  	call   0xc08df0
  a3a0a9:	41 f6 86 10 04 00 00 01                         	test   BYTE PTR [r14+0x410],0x1
  a3a0b1:	74 08                                           	je     0xa3a0bb
  a3a0b3:	4c 89 f7                                        	mov    rdi,r14
  a3a0b6:	e8 95 97 15 00                                  	call   0xb93850
  a3a0bb:	49 8d 7e 68                                     	lea    rdi,[r14+0x68]
  a3a0bf:	e8 9c 76 1b 00                                  	call   0xbf1760
  a3a0c4:	49 8d be 30 04 00 00                            	lea    rdi,[r14+0x430]
  a3a0cb:	e8 80 dd a8 ff                                  	call   0x4c7e50
  a3a0d0:	4c 39 b3 98 02 00 00                            	cmp    QWORD PTR [rbx+0x298],r14
  a3a0d7:	75 14                                           	jne    0xa3a0ed
  a3a0d9:	31 c9                                           	xor    ecx,ecx
  a3a0db:	4c 89 f0                                        	mov    rax,r14
  a3a0de:	f0 48 0f b1 8b 98 02 00 00                      	lock cmpxchg QWORD PTR [rbx+0x298],rcx
  a3a0e7:	0f 85 be 15 00 00                               	jne    0xa3b6ab
  a3a0ed:	48 8d 35 dc e5 b2 01                            	lea    rsi,[rip+0x1b2e5dc]        # 0x25686d0
  a3a0f4:	4c 89 f7                                        	mov    rdi,r14
  a3a0f7:	e8 f4 ec 1c 00                                  	call   0xc08df0
  a3a0fc:	48 8b bd 70 fe ff ff                            	mov    rdi,QWORD PTR [rbp-0x190]
  a3a103:	e8 68 49 ca ff                                  	call   0x6dea70
  a3a108:	48 8d 05 01 22 ee 02                            	lea    rax,[rip+0x2ee2201]        # 0x391c310
  a3a10f:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  a3a112:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  a3a116:	0f 85 8d 0f 00 00                               	jne    0xa3b0a9
  a3a11c:	44 89 f8                                        	mov    eax,r15d
  a3a11f:	48 81 c4 78 01 00 00                            	add    rsp,0x178
  a3a126:	5b                                              	pop    rbx
  a3a127:	41 5c                                           	pop    r12
  a3a129:	41 5d                                           	pop    r13
  a3a12b:	41 5e                                           	pop    r14
  a3a12d:	41 5f                                           	pop    r15
  a3a12f:	5d                                              	pop    rbp
  a3a130:	c3                                              	ret
  a3a131:	48 8b 8d 50 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xb0]
  a3a138:	48 8d 3d c1 62 94 00                            	lea    rdi,[rip+0x9462c1]        # 0x1380400
  a3a13f:	48 8d 35 d7 62 94 00                            	lea    rsi,[rip+0x9462d7]        # 0x138041d
  a3a146:	ba c2 0b 00 00                                  	mov    edx,0xbc2
  a3a14b:	31 c0                                           	xor    eax,eax
  a3a14d:	e8 be 32 82 ff                                  	call   0x25d410
  a3a152:	48 8b bd 50 ff ff ff                            	mov    rdi,QWORD PTR [rbp-0xb0]
  a3a159:	48 8d 35 22 8c 8b 00                            	lea    rsi,[rip+0x8b8c22]        # 0x12f2d82
  a3a160:	ba 03 00 00 00                                  	mov    edx,0x3
  a3a165:	e8 c6 78 e9 ff                                  	call   0x8d1a30
  a3a16a:	85 c0                                           	test   eax,eax
  a3a16c:	74 5e                                           	je     0xa3a1cc
  a3a16e:	48 8b bd 50 ff ff ff                            	mov    rdi,QWORD PTR [rbp-0xb0]
  a3a175:	48 8d 35 54 bf 94 00                            	lea    rsi,[rip+0x94bf54]        # 0x13860d0
  a3a17c:	ba 03 00 00 00                                  	mov    edx,0x3
  a3a181:	e8 aa 78 e9 ff                                  	call   0x8d1a30
  a3a186:	85 c0                                           	test   eax,eax
  a3a188:	74 50                                           	je     0xa3a1da
  a3a18a:	48 8b bd 50 ff ff ff                            	mov    rdi,QWORD PTR [rbp-0xb0]
  a3a191:	48 8d 35 48 b9 96 00                            	lea    rsi,[rip+0x96b948]        # 0x13a5ae0
  a3a198:	ba 03 00 00 00                                  	mov    edx,0x3
  a3a19d:	e8 8e 78 e9 ff                                  	call   0x8d1a30
  a3a1a2:	85 c0                                           	test   eax,eax
  a3a1a4:	74 42                                           	je     0xa3a1e8
  a3a1a6:	48 8b 8d 50 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xb0]
  a3a1ad:	48 8d 3d a4 69 97 00                            	lea    rdi,[rip+0x9769a4]        # 0x13b0b58
  a3a1b4:	48 8d 35 62 62 94 00                            	lea    rsi,[rip+0x946262]        # 0x138041d
  a3a1bb:	ba cb 0b 00 00                                  	mov    edx,0xbcb
  a3a1c0:	31 c0                                           	xor    eax,eax
  a3a1c2:	e8 49 32 82 ff                                  	call   0x25d410
  a3a1c7:	e9 6e fa ff ff                                  	jmp    0xa39c3a
  a3a1cc:	b8 03 00 00 00                                  	mov    eax,0x3
  a3a1d1:	4c 89 bd 80 fe ff ff                            	mov    QWORD PTR [rbp-0x180],r15
  a3a1d8:	eb 1a                                           	jmp    0xa3a1f4
  a3a1da:	4c 89 bd 80 fe ff ff                            	mov    QWORD PTR [rbp-0x180],r15
  a3a1e1:	b8 01 00 00 00                                  	mov    eax,0x1
  a3a1e6:	eb 0c                                           	jmp    0xa3a1f4
  a3a1e8:	4c 89 bd 80 fe ff ff                            	mov    QWORD PTR [rbp-0x180],r15
  a3a1ef:	b8 02 00 00 00                                  	mov    eax,0x2
  a3a1f4:	41 89 86 50 04 00 00                            	mov    DWORD PTR [r14+0x450],eax
  a3a1fb:	48 c7 85 b0 fe ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x150],0x0
  a3a206:	c7 85 20 ff ff ff 00 00 00 00                   	mov    DWORD PTR [rbp-0xe0],0x0
  a3a210:	48 8d 35 66 48 97 00                            	lea    rsi,[rip+0x974866]        # 0x13aea7d
  a3a217:	48 8d 95 b0 fe ff ff                            	lea    rdx,[rbp-0x150]
  a3a21e:	48 8d 8d 20 ff ff ff                            	lea    rcx,[rbp-0xe0]
  a3a225:	4d 8b 3e                                        	mov    r15,QWORD PTR [r14]
  a3a228:	49 8b bf a8 00 00 00                            	mov    rdi,QWORD PTR [r15+0xa8]
  a3a22f:	e8 9c 4d ba ff                                  	call   0x5defd0
  a3a234:	83 f8 02                                        	cmp    eax,0x2
  a3a237:	0f 84 97 00 00 00                               	je     0xa3a2d4
  a3a23d:	83 bd 20 ff ff ff 08                            	cmp    DWORD PTR [rbp-0xe0],0x8
  a3a244:	0f 85 8a 00 00 00                               	jne    0xa3a2d4
  a3a24a:	48 8b 85 b0 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x150]
  a3a251:	48 8d 3d 70 14 86 00                            	lea    rdi,[rip+0x861470]        # 0x129b6c8
  a3a258:	48 8d 35 d0 b0 95 00                            	lea    rsi,[rip+0x95b0d0]        # 0x139532f
  a3a25f:	ba 8a 0b 00 00                                  	mov    edx,0xb8a
  a3a264:	48 8b 08                                        	mov    rcx,QWORD PTR [rax]
  a3a267:	31 c0                                           	xor    eax,eax
  a3a269:	e8 a2 31 82 ff                                  	call   0x25d410
  a3a26e:	48 c7 85 50 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0xb0],0x0
  a3a279:	c7 85 28 ff ff ff 00 00 00 00                   	mov    DWORD PTR [rbp-0xd8],0x0
  a3a283:	48 8d 35 7b 76 92 00                            	lea    rsi,[rip+0x92767b]        # 0x1361905
  a3a28a:	48 8d 95 50 ff ff ff                            	lea    rdx,[rbp-0xb0]
  a3a291:	48 8d 8d 28 ff ff ff                            	lea    rcx,[rbp-0xd8]
  a3a298:	49 8b bf a8 00 00 00                            	mov    rdi,QWORD PTR [r15+0xa8]
  a3a29f:	e8 2c 4d ba ff                                  	call   0x5defd0
  a3a2a4:	83 f8 02                                        	cmp    eax,0x2
  a3a2a7:	74 54                                           	je     0xa3a2fd
  a3a2a9:	41 89 c7                                        	mov    r15d,eax
  a3a2ac:	85 c0                                           	test   eax,eax
  a3a2ae:	0f 85 85 00 00 00                               	jne    0xa3a339
  a3a2b4:	81 bd 28 ff ff ff 90 00 00 00                   	cmp    DWORD PTR [rbp-0xd8],0x90
  a3a2be:	4c 8b bd 80 fe ff ff                            	mov    r15,QWORD PTR [rbp-0x180]
  a3a2c5:	0f 85 0b 03 00 00                               	jne    0xa3a5d6
  a3a2cb:	b8 01 00 00 00                                  	mov    eax,0x1
  a3a2d0:	b2 01                                           	mov    dl,0x1
  a3a2d2:	eb 37                                           	jmp    0xa3a30b
  a3a2d4:	48 8d 3d 3b ff 84 00                            	lea    rdi,[rip+0x84ff3b]        # 0x128a216
  a3a2db:	48 8d 35 4d b0 95 00                            	lea    rsi,[rip+0x95b04d]        # 0x139532f
  a3a2e2:	41 bf 16 00 00 00                               	mov    r15d,0x16
  a3a2e8:	ba 85 0b 00 00                                  	mov    edx,0xb85
  a3a2ed:	b9 16 00 00 00                                  	mov    ecx,0x16
  a3a2f2:	41 b8 16 00 00 00                               	mov    r8d,0x16
  a3a2f8:	e9 ba f5 ff ff                                  	jmp    0xa398b7
  a3a2fd:	4c 8b bd 80 fe ff ff                            	mov    r15,QWORD PTR [rbp-0x180]
  a3a304:	b8 02 00 00 00                                  	mov    eax,0x2
  a3a309:	31 d2                                           	xor    edx,edx
  a3a30b:	49 89 86 78 08 00 00                            	mov    QWORD PTR [r14+0x878],rax
  a3a312:	41 83 be 50 04 00 00 03                         	cmp    DWORD PTR [r14+0x450],0x3
  a3a31a:	75 35                                           	jne    0xa3a351
  a3a31c:	48 8d 3d 30 74 90 00                            	lea    rdi,[rip+0x907430]        # 0x1341753
  a3a323:	48 8d 35 05 b0 95 00                            	lea    rsi,[rip+0x95b005]        # 0x139532f
  a3a32a:	ba 9b 0b 00 00                                  	mov    edx,0xb9b
  a3a32f:	b9 03 00 00 00                                  	mov    ecx,0x3
  a3a334:	e9 fa f8 ff ff                                  	jmp    0xa39c33
  a3a339:	48 8d 3d d6 fe 84 00                            	lea    rdi,[rip+0x84fed6]        # 0x128a216
  a3a340:	48 8d 35 e5 27 8f 00                            	lea    rsi,[rip+0x8f27e5]        # 0x132cb2c
  a3a347:	ba a7 05 00 00                                  	mov    edx,0x5a7
  a3a34c:	e9 60 f5 ff ff                                  	jmp    0xa398b1
  a3a351:	49 8d 8f 78 08 00 00                            	lea    rcx,[r15+0x878]
  a3a358:	48 8b b5 a0 fe ff ff                            	mov    rsi,QWORD PTR [rbp-0x160]
  a3a35f:	49 8d 84 24 d0 00 00 00                         	lea    rax,[r12+0xd0]
  a3a367:	48 89 8d 88 fe ff ff                            	mov    QWORD PTR [rbp-0x178],rcx
  a3a36e:	48 8b 8d 70 fe ff ff                            	mov    rcx,QWORD PTR [rbp-0x190]
  a3a375:	49 89 76 10                                     	mov    QWORD PTR [r14+0x10],rsi
  a3a379:	49 89 46 18                                     	mov    QWORD PTR [r14+0x18],rax
  a3a37d:	4d 89 66 20                                     	mov    QWORD PTR [r14+0x20],r12
  a3a381:	49 89 4e 08                                     	mov    QWORD PTR [r14+0x8],rcx
  a3a385:	49 8b 06                                        	mov    rax,QWORD PTR [r14]
  a3a388:	84 d2                                           	test   dl,dl
  a3a38a:	0f 84 64 02 00 00                               	je     0xa3a5f4
  a3a390:	49 c7 86 78 08 00 00 00 00 00 00                	mov    QWORD PTR [r14+0x878],0x0
  a3a39b:	49 c7 86 74 04 00 00 ff ff ff ff                	mov    QWORD PTR [r14+0x474],0xffffffffffffffff
  a3a3a6:	48 c7 85 10 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0xf0],0x0
  a3a3b1:	c7 85 0c ff ff ff 00 00 00 00                   	mov    DWORD PTR [rbp-0xf4],0x0
  a3a3bb:	48 8d 35 43 75 92 00                            	lea    rsi,[rip+0x927543]        # 0x1361905
  a3a3c2:	48 8d 95 10 ff ff ff                            	lea    rdx,[rbp-0xf0]
  a3a3c9:	48 8d 8d 0c ff ff ff                            	lea    rcx,[rbp-0xf4]
  a3a3d0:	48 8b b8 a8 00 00 00                            	mov    rdi,QWORD PTR [rax+0xa8]
  a3a3d7:	e8 f4 4b ba ff                                  	call   0x5defd0
  a3a3dc:	ba ba 05 00 00                                  	mov    edx,0x5ba
  a3a3e1:	83 f8 02                                        	cmp    eax,0x2
  a3a3e4:	0f 84 e2 02 00 00                               	je     0xa3a6cc
  a3a3ea:	81 bd 0c ff ff ff 90 00 00 00                   	cmp    DWORD PTR [rbp-0xf4],0x90
  a3a3f4:	ba bd 05 00 00                                  	mov    edx,0x5bd
  a3a3f9:	0f 85 cd 02 00 00                               	jne    0xa3a6cc
  a3a3ff:	48 8b 85 10 ff ff ff                            	mov    rax,QWORD PTR [rbp-0xf0]
  a3a406:	ba c4 05 00 00                                  	mov    edx,0x5c4
  a3a40b:	48 81 78 18 00 00 01 00                         	cmp    QWORD PTR [rax+0x18],0x10000
  a3a413:	0f 85 b3 02 00 00                               	jne    0xa3a6cc
  a3a419:	4c 89 bd 80 fe ff ff                            	mov    QWORD PTR [rbp-0x180],r15
  a3a420:	48 8b 48 28                                     	mov    rcx,QWORD PTR [rax+0x28]
  a3a424:	4c 8b 78 20                                     	mov    r15,QWORD PTR [rax+0x20]
  a3a428:	4c 8b 48 30                                     	mov    r9,QWORD PTR [rax+0x30]
  a3a42c:	48 8d 3d 9e 91 83 00                            	lea    rdi,[rip+0x83919e]        # 0x12735d1
  a3a433:	48 8d 35 48 d9 8d 00                            	lea    rsi,[rip+0x8dd948]        # 0x1317d82
  a3a43a:	ba c9 05 00 00                                  	mov    edx,0x5c9
  a3a43f:	48 89 85 90 fe ff ff                            	mov    QWORD PTR [rbp-0x170],rax
  a3a446:	31 c0                                           	xor    eax,eax
  a3a448:	48 89 8d 78 fe ff ff                            	mov    QWORD PTR [rbp-0x188],rcx
  a3a44f:	4e 8d 04 39                                     	lea    r8,[rcx+r15*1]
  a3a453:	4c 89 f9                                        	mov    rcx,r15
  a3a456:	e8 b5 2f 82 ff                                  	call   0x25d410
  a3a45b:	48 8b 85 78 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x188]
  a3a462:	48 8b 8d 90 fe ff ff                            	mov    rcx,QWORD PTR [rbp-0x170]
  a3a469:	48 c7 45 c8 00 00 00 00                         	mov    QWORD PTR [rbp-0x38],0x0
  a3a471:	48 c7 45 c0 00 00 00 00                         	mov    QWORD PTR [rbp-0x40],0x0
  a3a479:	48 c7 45 b8 00 00 00 00                         	mov    QWORD PTR [rbp-0x48],0x0
  a3a481:	48 c7 45 b0 00 00 00 00                         	mov    QWORD PTR [rbp-0x50],0x0
  a3a489:	48 c7 45 a8 00 00 00 00                         	mov    QWORD PTR [rbp-0x58],0x0
  a3a491:	48 c7 45 a0 00 00 00 00                         	mov    QWORD PTR [rbp-0x60],0x0
  a3a499:	48 c7 45 98 00 00 00 00                         	mov    QWORD PTR [rbp-0x68],0x0
  a3a4a1:	48 c7 45 90 00 00 00 00                         	mov    QWORD PTR [rbp-0x70],0x0
  a3a4a9:	48 c7 45 88 00 00 00 00                         	mov    QWORD PTR [rbp-0x78],0x0
  a3a4b1:	48 c7 45 80 00 00 00 00                         	mov    QWORD PTR [rbp-0x80],0x0
  a3a4b9:	48 c7 85 78 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x88],0x0
  a3a4c4:	48 c7 85 70 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x90],0x0
  a3a4cf:	48 c7 85 68 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x98],0x0
  a3a4da:	48 c7 85 60 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0xa0],0x0
  a3a4e5:	48 c7 85 58 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0xa8],0x0
  a3a4f0:	48 c7 85 50 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0xb0],0x0
  a3a4fb:	48 8d 95 50 ff ff ff                            	lea    rdx,[rbp-0xb0]
  a3a502:	4a 8d 84 38 00 00 ff ff                         	lea    rax,[rax+r15*1-0x10000]
  a3a50a:	8b 49 38                                        	mov    ecx,DWORD PTR [rcx+0x38]
  a3a50d:	48 c7 85 00 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x100],0x0
  a3a518:	48 c7 85 f8 fe ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x108],0x0
  a3a523:	48 c7 85 f0 fe ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x110],0x0
  a3a52e:	48 c7 85 e8 fe ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x118],0x0
  a3a539:	48 c7 85 e0 fe ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x120],0x0
  a3a544:	48 c7 85 d8 fe ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x128],0x0
  a3a54f:	48 c7 85 d0 fe ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x130],0x0
  a3a55a:	48 c7 85 c8 fe ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x138],0x0
  a3a565:	48 c7 85 c0 fe ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x140],0x0
  a3a570:	48 89 95 b0 fe ff ff                            	mov    QWORD PTR [rbp-0x150],rdx
  a3a577:	48 c1 e8 0d                                     	shr    rax,0xd
  a3a57b:	48 83 e0 f8                                     	and    rax,0xfffffffffffffff8
  a3a57f:	48 89 85 b8 fe ff ff                            	mov    QWORD PTR [rbp-0x148],rax
  a3a586:	49 8b 46 20                                     	mov    rax,QWORD PTR [r14+0x20]
  a3a58a:	89 4d c8                                        	mov    DWORD PTR [rbp-0x38],ecx
  a3a58d:	89 8d 00 ff ff ff                               	mov    DWORD PTR [rbp-0x100],ecx
  a3a593:	48 85 c0                                        	test   rax,rax
  a3a596:	0f 84 22 03 00 00                               	je     0xa3a8be
  a3a59c:	48 8b 38                                        	mov    rdi,QWORD PTR [rax]
  a3a59f:	48 8d 35 6e 2f 83 00                            	lea    rsi,[rip+0x832f6e]        # 0x126d514
  a3a5a6:	ba 06 00 00 00                                  	mov    edx,0x6
  a3a5ab:	e8 80 74 e9 ff                                  	call   0x8d1a30
  a3a5b0:	85 c0                                           	test   eax,eax
  a3a5b2:	0f 84 82 03 00 00                               	je     0xa3a93a
  a3a5b8:	48 8d 3d 57 fc 84 00                            	lea    rdi,[rip+0x84fc57]        # 0x128a216
  a3a5bf:	48 8d 35 78 19 8c 00                            	lea    rsi,[rip+0x8c1978]        # 0x12fbf3e
  a3a5c6:	41 bf 06 00 00 00                               	mov    r15d,0x6
  a3a5cc:	ba d7 03 00 00                                  	mov    edx,0x3d7
  a3a5d1:	e9 01 03 00 00                                  	jmp    0xa3a8d7
  a3a5d6:	48 8d 3d 39 fc 84 00                            	lea    rdi,[rip+0x84fc39]        # 0x128a216
  a3a5dd:	48 8d 35 48 25 8f 00                            	lea    rsi,[rip+0x8f2548]        # 0x132cb2c
  a3a5e4:	41 bf 16 00 00 00                               	mov    r15d,0x16
  a3a5ea:	ba 9e 05 00 00                                  	mov    edx,0x59e
  a3a5ef:	e9 f9 fc ff ff                                  	jmp    0xa3a2ed
  a3a5f4:	48 c7 85 b0 fe ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x150],0x0
  a3a5ff:	c7 85 28 ff ff ff 00 00 00 00                   	mov    DWORD PTR [rbp-0xd8],0x0
  a3a609:	48 8d 35 6d 44 97 00                            	lea    rsi,[rip+0x97446d]        # 0x13aea7d
  a3a610:	48 8d 95 b0 fe ff ff                            	lea    rdx,[rbp-0x150]
  a3a617:	48 8d 8d 28 ff ff ff                            	lea    rcx,[rbp-0xd8]
  a3a61e:	48 8b b8 a8 00 00 00                            	mov    rdi,QWORD PTR [rax+0xa8]
  a3a625:	e8 a6 49 ba ff                                  	call   0x5defd0
  a3a62a:	83 f8 02                                        	cmp    eax,0x2
  a3a62d:	0f 84 d7 00 00 00                               	je     0xa3a70a
  a3a633:	83 bd 28 ff ff ff 08                            	cmp    DWORD PTR [rbp-0xd8],0x8
  a3a63a:	0f 85 ca 00 00 00                               	jne    0xa3a70a
  a3a640:	48 8b 85 b0 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x150]
  a3a647:	4c 89 bd 80 fe ff ff                            	mov    QWORD PTR [rbp-0x180],r15
  a3a64e:	48 8d 35 7b e0 b2 01                            	lea    rsi,[rip+0x1b2e07b]        # 0x25686d0
  a3a655:	bf a0 05 00 00                                  	mov    edi,0x5a0
  a3a65a:	ba 02 01 00 00                                  	mov    edx,0x102
  a3a65f:	4c 8b 38                                        	mov    r15,QWORD PTR [rax]
  a3a662:	e8 e9 e4 1c 00                                  	call   0xc08b50
  a3a667:	48 8b 8d 88 fe ff ff                            	mov    rcx,QWORD PTR [rbp-0x178]
  a3a66e:	48 89 85 90 fe ff ff                            	mov    QWORD PTR [rbp-0x170],rax
  a3a675:	48 83 39 02                                     	cmp    QWORD PTR [rcx],0x2
  a3a679:	0f 84 bb 00 00 00                               	je     0xa3a73a
  a3a67f:	4c 8d 2d 90 fb 84 00                            	lea    r13,[rip+0x84fb90]        # 0x128a216
  a3a686:	48 8d 35 48 31 8d 00                            	lea    rsi,[rip+0x8d3148]        # 0x130d7d5
  a3a68d:	ba 04 0c 00 00                                  	mov    edx,0xc04
  a3a692:	b9 2d 00 00 00                                  	mov    ecx,0x2d
  a3a697:	41 b8 2d 00 00 00                               	mov    r8d,0x2d
  a3a69d:	41 bf 2d 00 00 00                               	mov    r15d,0x2d
  a3a6a3:	31 c0                                           	xor    eax,eax
  a3a6a5:	4c 89 ef                                        	mov    rdi,r13
  a3a6a8:	e8 63 2d 82 ff                                  	call   0x25d410
  a3a6ad:	48 8d 35 cb 70 90 00                            	lea    rsi,[rip+0x9070cb]        # 0x134177f
  a3a6b4:	4c 89 ef                                        	mov    rdi,r13
  a3a6b7:	ba 33 0c 00 00                                  	mov    edx,0xc33
  a3a6bc:	b9 2d 00 00 00                                  	mov    ecx,0x2d
  a3a6c1:	41 b8 2d 00 00 00                               	mov    r8d,0x2d
  a3a6c7:	e9 ec 00 00 00                                  	jmp    0xa3a7b8
  a3a6cc:	48 8d 3d 43 fb 84 00                            	lea    rdi,[rip+0x84fb43]        # 0x128a216
  a3a6d3:	48 8d 35 a8 d6 8d 00                            	lea    rsi,[rip+0x8dd6a8]        # 0x1317d82
  a3a6da:	41 bf 16 00 00 00                               	mov    r15d,0x16
  a3a6e0:	b9 16 00 00 00                                  	mov    ecx,0x16
  a3a6e5:	41 b8 16 00 00 00                               	mov    r8d,0x16
  a3a6eb:	31 c0                                           	xor    eax,eax
  a3a6ed:	e8 1e 2d 82 ff                                  	call   0x25d410
  a3a6f2:	48 8d 3d 1d fb 84 00                            	lea    rdi,[rip+0x84fb1d]        # 0x128a216
  a3a6f9:	48 8d 35 85 bd 93 00                            	lea    rsi,[rip+0x93bd85]        # 0x1376485
  a3a700:	ba c6 0c 00 00                                  	mov    edx,0xcc6
  a3a705:	e9 e3 00 00 00                                  	jmp    0xa3a7ed
  a3a70a:	48 8d 3d 05 fb 84 00                            	lea    rdi,[rip+0x84fb05]        # 0x128a216
  a3a711:	48 8d 35 67 70 90 00                            	lea    rsi,[rip+0x907067]        # 0x134177f
  a3a718:	ba 27 0c 00 00                                  	mov    edx,0xc27
  a3a71d:	b9 16 00 00 00                                  	mov    ecx,0x16
  a3a722:	41 b8 16 00 00 00                               	mov    r8d,0x16
  a3a728:	31 c0                                           	xor    eax,eax
  a3a72a:	41 bf 16 00 00 00                               	mov    r15d,0x16
  a3a730:	e8 db 2c 82 ff                                  	call   0x25d410
  a3a735:	e9 a0 00 00 00                                  	jmp    0xa3a7da
  a3a73a:	49 8b 7e 20                                     	mov    rdi,QWORD PTR [r14+0x20]
  a3a73e:	49 c1 ef 09                                     	shr    r15,0x9
  a3a742:	48 c7 85 50 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0xb0],0x0
  a3a74d:	48 83 ec 08                                     	sub    rsp,0x8
  a3a751:	48 8d 85 50 ff ff ff                            	lea    rax,[rbp-0xb0]
  a3a758:	4c 89 fe                                        	mov    rsi,r15
  a3a75b:	ba 00 00 01 00                                  	mov    edx,0x10000
  a3a760:	31 c9                                           	xor    ecx,ecx
  a3a762:	45 31 c0                                        	xor    r8d,r8d
  a3a765:	45 31 c9                                        	xor    r9d,r9d
  a3a768:	50                                              	push   rax
  a3a769:	6a 00                                           	push   0x0
  a3a76b:	6a 00                                           	push   0x0
  a3a76d:	e8 1e 34 06 00                                  	call   0xa9db90
  a3a772:	48 83 c4 20                                     	add    rsp,0x20
  a3a776:	85 c0                                           	test   eax,eax
  a3a778:	0f 84 94 00 00 00                               	je     0xa3a812
  a3a77e:	4c 8d 2d 91 fa 84 00                            	lea    r13,[rip+0x84fa91]        # 0x128a216
  a3a785:	48 8d 35 76 1c 91 00                            	lea    rsi,[rip+0x911c76]        # 0x134c402
  a3a78c:	ba df 0b 00 00                                  	mov    edx,0xbdf
  a3a791:	89 c1                                           	mov    ecx,eax
  a3a793:	41 89 c0                                        	mov    r8d,eax
  a3a796:	41 89 c7                                        	mov    r15d,eax
  a3a799:	31 c0                                           	xor    eax,eax
  a3a79b:	4c 89 ef                                        	mov    rdi,r13
  a3a79e:	e8 6d 2c 82 ff                                  	call   0x25d410
  a3a7a3:	48 8d 35 d5 6f 90 00                            	lea    rsi,[rip+0x906fd5]        # 0x134177f
  a3a7aa:	4c 89 ef                                        	mov    rdi,r13
  a3a7ad:	ba 3a 0c 00 00                                  	mov    edx,0xc3a
  a3a7b2:	44 89 f9                                        	mov    ecx,r15d
  a3a7b5:	45 89 f8                                        	mov    r8d,r15d
  a3a7b8:	31 c0                                           	xor    eax,eax
  a3a7ba:	e8 51 2c 82 ff                                  	call   0x25d410
  a3a7bf:	48 8b bd 90 fe ff ff                            	mov    rdi,QWORD PTR [rbp-0x170]
  a3a7c6:	48 8d 35 03 df b2 01                            	lea    rsi,[rip+0x1b2df03]        # 0x25686d0
  a3a7cd:	e8 1e e6 1c 00                                  	call   0xc08df0
  a3a7d2:	49 c7 46 30 00 00 00 00                         	mov    QWORD PTR [r14+0x30],0x0
  a3a7da:	48 8d 3d 35 fa 84 00                            	lea    rdi,[rip+0x84fa35]        # 0x128a216
  a3a7e1:	48 8d 35 9d bc 93 00                            	lea    rsi,[rip+0x93bc9d]        # 0x1376485
  a3a7e8:	ba cf 0c 00 00                                  	mov    edx,0xccf
  a3a7ed:	44 89 f9                                        	mov    ecx,r15d
  a3a7f0:	45 89 f8                                        	mov    r8d,r15d
  a3a7f3:	31 c0                                           	xor    eax,eax
  a3a7f5:	e8 16 2c 82 ff                                  	call   0x25d410
  a3a7fa:	48 8d 3d 15 fa 84 00                            	lea    rdi,[rip+0x84fa15]        # 0x128a216
  a3a801:	48 8d 35 46 af 97 00                            	lea    rsi,[rip+0x97af46]        # 0x13b574e
  a3a808:	ba 99 0d 00 00                                  	mov    edx,0xd99
  a3a80d:	e9 9f f0 ff ff                                  	jmp    0xa398b1
  a3a812:	48 8b 85 90 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x170]
  a3a819:	49 89 c7                                        	mov    r15,rax
  a3a81c:	48 85 c0                                        	test   rax,rax
  a3a81f:	75 19                                           	jne    0xa3a83a
  a3a821:	48 8d 35 a8 de b2 01                            	lea    rsi,[rip+0x1b2dea8]        # 0x25686d0
  a3a828:	bf a0 05 00 00                                  	mov    edi,0x5a0
  a3a82d:	ba 02 01 00 00                                  	mov    edx,0x102
  a3a832:	e8 19 e3 1c 00                                  	call   0xc08b50
  a3a837:	49 89 c7                                        	mov    r15,rax
  a3a83a:	48 8b 85 50 ff ff ff                            	mov    rax,QWORD PTR [rbp-0xb0]
  a3a841:	ba a0 05 00 00                                  	mov    edx,0x5a0
  a3a846:	4c 89 fe                                        	mov    rsi,r15
  a3a849:	48 8b 78 18                                     	mov    rdi,QWORD PTR [rax+0x18]
  a3a84d:	e8 8e f3 81 ff                                  	call   0x259be0
  a3a852:	48 8b 85 50 ff ff ff                            	mov    rax,QWORD PTR [rbp-0xb0]
  a3a859:	4d 89 7e 30                                     	mov    QWORD PTR [r14+0x30],r15
  a3a85d:	81 48 68 00 80 00 00                            	or     DWORD PTR [rax+0x68],0x8000
  a3a864:	48 8b bd 50 ff ff ff                            	mov    rdi,QWORD PTR [rbp-0xb0]
  a3a86b:	e8 20 2e 06 00                                  	call   0xa9d690
  a3a870:	48 8b 85 90 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x170]
  a3a877:	49 89 46 30                                     	mov    QWORD PTR [r14+0x30],rax
  a3a87b:	48 8b 48 08                                     	mov    rcx,QWORD PTR [rax+0x8]
  a3a87f:	48 81 f9 0a 2a 33 01                            	cmp    rcx,0x1332a0a
  a3a886:	77 7f                                           	ja     0xa3a907
  a3a888:	48 8d 3d 50 49 8a 00                            	lea    rdi,[rip+0x8a4950]        # 0x12df1df
  a3a88f:	48 8d 35 ef bb 93 00                            	lea    rsi,[rip+0x93bbef]        # 0x1376485
  a3a896:	ba d6 0c 00 00                                  	mov    edx,0xcd6
  a3a89b:	49 89 c8                                        	mov    r8,rcx
  a3a89e:	31 c0                                           	xor    eax,eax
  a3a8a0:	e8 6b 2b 82 ff                                  	call   0x25d410
  a3a8a5:	48 8d 3d 7c 48 89 00                            	lea    rdi,[rip+0x89487c]        # 0x12cf128
  a3a8ac:	31 c0                                           	xor    eax,eax
  a3a8ae:	e8 5d 2b 82 ff                                  	call   0x25d410
  a3a8b3:	41 bf 2d 00 00 00                               	mov    r15d,0x2d
  a3a8b9:	e9 3c ff ff ff                                  	jmp    0xa3a7fa
  a3a8be:	48 8d 3d 51 f9 84 00                            	lea    rdi,[rip+0x84f951]        # 0x128a216
  a3a8c5:	48 8d 35 72 16 8c 00                            	lea    rsi,[rip+0x8c1672]        # 0x12fbf3e
  a3a8cc:	41 bf 06 00 00 00                               	mov    r15d,0x6
  a3a8d2:	ba d2 03 00 00                                  	mov    edx,0x3d2
  a3a8d7:	b9 06 00 00 00                                  	mov    ecx,0x6
  a3a8dc:	41 b8 06 00 00 00                               	mov    r8d,0x6
  a3a8e2:	31 c0                                           	xor    eax,eax
  a3a8e4:	e8 27 2b 82 ff                                  	call   0x25d410
  a3a8e9:	48 8d 3d 26 f9 84 00                            	lea    rdi,[rip+0x84f926]        # 0x128a216
  a3a8f0:	48 8d 35 8b d4 8d 00                            	lea    rsi,[rip+0x8dd48b]        # 0x1317d82
  a3a8f7:	ba 25 06 00 00                                  	mov    edx,0x625
  a3a8fc:	44 89 f9                                        	mov    ecx,r15d
  a3a8ff:	45 89 f8                                        	mov    r8d,r15d
  a3a902:	e9 e4 fd ff ff                                  	jmp    0xa3a6eb
  a3a907:	80 78 1b 00                                     	cmp    BYTE PTR [rax+0x1b],0x0
  a3a90b:	0f 84 bd 00 00 00                               	je     0xa3a9ce
  a3a911:	48 8d 3d fe f8 84 00                            	lea    rdi,[rip+0x84f8fe]        # 0x128a216
  a3a918:	48 8d 35 66 bb 93 00                            	lea    rsi,[rip+0x93bb66]        # 0x1376485
  a3a91f:	41 bf 16 00 00 00                               	mov    r15d,0x16
  a3a925:	ba df 0c 00 00                                  	mov    edx,0xcdf
  a3a92a:	b9 16 00 00 00                                  	mov    ecx,0x16
  a3a92f:	41 b8 16 00 00 00                               	mov    r8d,0x16
  a3a935:	e9 b9 fe ff ff                                  	jmp    0xa3a7f3
  a3a93a:	49 8b 46 10                                     	mov    rax,QWORD PTR [r14+0x10]
  a3a93e:	48 85 c0                                        	test   rax,rax
  a3a941:	0f 84 ba 00 00 00                               	je     0xa3aa01
  a3a947:	4c 8b 78 18                                     	mov    r15,QWORD PTR [rax+0x18]
  a3a94b:	4d 85 ff                                        	test   r15,r15
  a3a94e:	0f 84 cb 00 00 00                               	je     0xa3aa1f
  a3a954:	48 c7 85 38 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0xc8],0x0
  a3a95f:	48 c7 85 48 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0xb8],0x0
  a3a96a:	48 c7 85 40 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0xc0],0x0
  a3a975:	48 c7 85 30 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0xd0],0x0
  a3a980:	48 c7 85 28 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0xd8],0x0
  a3a98b:	c7 85 38 ff ff ff ff ff ff ff                   	mov    DWORD PTR [rbp-0xc8],0xffffffff
  a3a995:	48 8d b5 28 ff ff ff                            	lea    rsi,[rbp-0xd8]
  a3a99c:	49 8b 47 18                                     	mov    rax,QWORD PTR [r15+0x18]
  a3a9a0:	48 8b b8 a0 00 00 00                            	mov    rdi,QWORD PTR [rax+0xa0]
  a3a9a7:	e8 74 07 8b ff                                  	call   0x2eb120
  a3a9ac:	85 c0                                           	test   eax,eax
  a3a9ae:	0f 84 38 01 00 00                               	je     0xa3aaec
  a3a9b4:	89 c1                                           	mov    ecx,eax
  a3a9b6:	48 8d 3d 59 f8 84 00                            	lea    rdi,[rip+0x84f859]        # 0x128a216
  a3a9bd:	48 8d 35 7a 15 8c 00                            	lea    rsi,[rip+0x8c157a]        # 0x12fbf3e
  a3a9c4:	ba ed 03 00 00                                  	mov    edx,0x3ed
  a3a9c9:	e9 63 01 00 00                                  	jmp    0xa3ab31
  a3a9ce:	48 8b 08                                        	mov    rcx,QWORD PTR [rax]
  a3a9d1:	48 89 85 90 fe ff ff                            	mov    QWORD PTR [rbp-0x170],rax
  a3a9d8:	48 83 f9 02                                     	cmp    rcx,0x2
  a3a9dc:	74 5f                                           	je     0xa3aa3d
  a3a9de:	48 83 f9 01                                     	cmp    rcx,0x1
  a3a9e2:	0f 85 cd 00 00 00                               	jne    0xa3aab5
  a3a9e8:	48 8b 85 88 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x178]
  a3a9ef:	48 83 38 00                                     	cmp    QWORD PTR [rax],0x0
  a3a9f3:	74 48                                           	je     0xa3aa3d
  a3a9f5:	48 8d 3d 4e a9 95 00                            	lea    rdi,[rip+0x95a94e]        # 0x139534a
  a3a9fc:	e9 ab fe ff ff                                  	jmp    0xa3a8ac
  a3aa01:	48 8d 3d 0e f8 84 00                            	lea    rdi,[rip+0x84f80e]        # 0x128a216
  a3aa08:	48 8d 35 2f 15 8c 00                            	lea    rsi,[rip+0x8c152f]        # 0x12fbf3e
  a3aa0f:	41 bf 06 00 00 00                               	mov    r15d,0x6
  a3aa15:	ba dd 03 00 00                                  	mov    edx,0x3dd
  a3aa1a:	e9 b8 fe ff ff                                  	jmp    0xa3a8d7
  a3aa1f:	48 8d 3d f0 f7 84 00                            	lea    rdi,[rip+0x84f7f0]        # 0x128a216
  a3aa26:	48 8d 35 11 15 8c 00                            	lea    rsi,[rip+0x8c1511]        # 0x12fbf3e
  a3aa2d:	41 bf 06 00 00 00                               	mov    r15d,0x6
  a3aa33:	ba e3 03 00 00                                  	mov    edx,0x3e3
  a3aa38:	e9 9a fe ff ff                                  	jmp    0xa3a8d7
  a3aa3d:	49 8b 06                                        	mov    rax,QWORD PTR [r14]
  a3aa40:	48 c7 85 50 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0xb0],0x0
  a3aa4b:	48 89 85 78 fe ff ff                            	mov    QWORD PTR [rbp-0x188],rax
  a3aa52:	41 8b 86 50 04 00 00                            	mov    eax,DWORD PTR [r14+0x450]
  a3aa59:	8d 48 ff                                        	lea    ecx,[rax-0x1]
  a3aa5c:	83 f9 02                                        	cmp    ecx,0x2
  a3aa5f:	0f 83 ec 00 00 00                               	jae    0xa3ab51
  a3aa65:	48 8b 85 78 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x188]
  a3aa6c:	48 8d 35 53 b0 96 00                            	lea    rsi,[rip+0x96b053]        # 0x13a5ac6
  a3aa73:	48 8d 95 50 ff ff ff                            	lea    rdx,[rbp-0xb0]
  a3aa7a:	31 c9                                           	xor    ecx,ecx
  a3aa7c:	48 8b b8 a8 00 00 00                            	mov    rdi,QWORD PTR [rax+0xa8]
  a3aa83:	e8 48 45 ba ff                                  	call   0x5defd0
  a3aa88:	85 c0                                           	test   eax,eax
  a3aa8a:	0f 85 ca 00 00 00                               	jne    0xa3ab5a
  a3aa90:	48 8b bd 50 ff ff ff                            	mov    rdi,QWORD PTR [rbp-0xb0]
  a3aa97:	48 8d 35 39 26 8e 00                            	lea    rsi,[rip+0x8e2639]        # 0x131d0d7
  a3aa9e:	ba 02 00 00 00                                  	mov    edx,0x2
  a3aaa3:	e8 88 6f e9 ff                                  	call   0x8d1a30
  a3aaa8:	85 c0                                           	test   eax,eax
  a3aaaa:	0f 85 35 01 00 00                               	jne    0xa3abe5
  a3aab0:	e9 a5 00 00 00                                  	jmp    0xa3ab5a
  a3aab5:	4c 8d 2d c9 b9 93 00                            	lea    r13,[rip+0x93b9c9]        # 0x1376485
  a3aabc:	48 8d 3d 1d 80 8d 00                            	lea    rdi,[rip+0x8d801d]        # 0x1312ae0
  a3aac3:	ba ee 0c 00 00                                  	mov    edx,0xcee
  a3aac8:	31 c0                                           	xor    eax,eax
  a3aaca:	4c 89 ee                                        	mov    rsi,r13
  a3aacd:	e8 3e 29 82 ff                                  	call   0x25d410
  a3aad2:	48 8d 3d 3d f7 84 00                            	lea    rdi,[rip+0x84f73d]        # 0x128a216
  a3aad9:	41 bf 16 00 00 00                               	mov    r15d,0x16
  a3aadf:	4c 89 ee                                        	mov    rsi,r13
  a3aae2:	ba f0 0c 00 00                                  	mov    edx,0xcf0
  a3aae7:	e9 3e fe ff ff                                  	jmp    0xa3a92a
  a3aaec:	48 c7 85 20 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0xe0],0x0
  a3aaf7:	8b b5 38 ff ff ff                               	mov    esi,DWORD PTR [rbp-0xc8]
  a3aafd:	48 8d 95 20 ff ff ff                            	lea    rdx,[rbp-0xe0]
  a3ab04:	49 8b 47 18                                     	mov    rax,QWORD PTR [r15+0x18]
  a3ab08:	48 8b b8 a0 00 00 00                            	mov    rdi,QWORD PTR [rax+0xa0]
  a3ab0f:	e8 8c 05 8b ff                                  	call   0x2eb0a0
  a3ab14:	85 c0                                           	test   eax,eax
  a3ab16:	0f 84 ab 01 00 00                               	je     0xa3acc7
  a3ab1c:	89 c1                                           	mov    ecx,eax
  a3ab1e:	48 8d 3d f1 f6 84 00                            	lea    rdi,[rip+0x84f6f1]        # 0x128a216
  a3ab25:	48 8d 35 12 14 8c 00                            	lea    rsi,[rip+0x8c1412]        # 0x12fbf3e
  a3ab2c:	ba f8 03 00 00                                  	mov    edx,0x3f8
  a3ab31:	41 89 c8                                        	mov    r8d,ecx
  a3ab34:	31 c0                                           	xor    eax,eax
  a3ab36:	41 89 cd                                        	mov    r13d,ecx
  a3ab39:	e8 d2 28 82 ff                                  	call   0x25d410
  a3ab3e:	41 83 fd ff                                     	cmp    r13d,0xffffffff
  a3ab42:	41 bf 06 00 00 00                               	mov    r15d,0x6
  a3ab48:	45 0f 45 fd                                     	cmovne r15d,r13d
  a3ab4c:	e9 98 fd ff ff                                  	jmp    0xa3a8e9
  a3ab51:	83 f8 03                                        	cmp    eax,0x3
  a3ab54:	0f 85 8b 00 00 00                               	jne    0xa3abe5
  a3ab5a:	48 8b 85 90 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x170]
  a3ab61:	0f b7 40 1c                                     	movzx  eax,WORD PTR [rax+0x1c]
  a3ab65:	a8 01                                           	test   al,0x1
  a3ab67:	75 33                                           	jne    0xa3ab9c
  a3ab69:	48 8d 3d b3 e5 8a 00                            	lea    rdi,[rip+0x8ae5b3]        # 0x12e9123
  a3ab70:	48 8d 35 6e 2c 8d 00                            	lea    rsi,[rip+0x8d2c6e]        # 0x130d7e5
  a3ab77:	ba 5b 0c 00 00                                  	mov    edx,0xc5b
  a3ab7c:	b9 60 00 00 00                                  	mov    ecx,0x60
  a3ab81:	31 c0                                           	xor    eax,eax
  a3ab83:	41 bf 60 00 00 00                               	mov    r15d,0x60
  a3ab89:	e8 82 28 82 ff                                  	call   0x25d410
  a3ab8e:	49 8b 16                                        	mov    rdx,QWORD PTR [r14]
  a3ab91:	65 48 8b 0c 25 00 00 00 00                      	mov    rcx,QWORD PTR gs:0x0
  a3ab9a:	eb 35                                           	jmp    0xa3abd1
  a3ab9c:	a8 04                                           	test   al,0x4
  a3ab9e:	75 45                                           	jne    0xa3abe5
  a3aba0:	48 8d 3d 7c e5 8a 00                            	lea    rdi,[rip+0x8ae57c]        # 0x12e9123
  a3aba7:	48 8d 35 37 2c 8d 00                            	lea    rsi,[rip+0x8d2c37]        # 0x130d7e5
  a3abae:	ba 63 0c 00 00                                  	mov    edx,0xc63
  a3abb3:	b9 60 00 00 00                                  	mov    ecx,0x60
  a3abb8:	31 c0                                           	xor    eax,eax
  a3abba:	41 bf 60 00 00 00                               	mov    r15d,0x60
  a3abc0:	e8 4b 28 82 ff                                  	call   0x25d410
  a3abc5:	49 8b 16                                        	mov    rdx,QWORD PTR [r14]
  a3abc8:	65 48 8b 0c 25 00 00 00 00                      	mov    rcx,QWORD PTR gs:0x0
  a3abd1:	bf 60 00 00 00                                  	mov    edi,0x60
  a3abd6:	31 f6                                           	xor    esi,esi
  a3abd8:	45 31 c0                                        	xor    r8d,r8d
  a3abdb:	e8 c0 fa b1 ff                                  	call   0x55a6a0
  a3abe0:	e9 15 fc ff ff                                  	jmp    0xa3a7fa
  a3abe5:	48 8b 85 90 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x170]
  a3abec:	0f b7 48 1c                                     	movzx  ecx,WORD PTR [rax+0x1c]
  a3abf0:	89 c8                                           	mov    eax,ecx
  a3abf2:	83 e0 13                                        	and    eax,0x13
  a3abf5:	83 f8 10                                        	cmp    eax,0x10
  a3abf8:	0f 87 c0 01 00 00                               	ja     0xa3adbe
  a3abfe:	48 8d 15 33 93 e9 00                            	lea    rdx,[rip+0xe99333]        # 0x18d3f38
  a3ac05:	48 63 04 82                                     	movsxd rax,DWORD PTR [rdx+rax*4]
  a3ac09:	48 01 d0                                        	add    rax,rdx
  a3ac0c:	ff e0                                           	jmp    rax
  a3ac0e:	48 8d 05 db e4 82 ff                            	lea    rax,[rip+0xffffffffff82e4db]        # 0x2690f0
  a3ac15:	48 8d 0d 74 e1 82 ff                            	lea    rcx,[rip+0xffffffffff82e174]        # 0x268d90
  a3ac1c:	49 c7 86 08 04 00 00 04 00 00 00                	mov    QWORD PTR [r14+0x408],0x4
  a3ac27:	49 c7 46 48 a8 00 00 00                         	mov    QWORD PTR [r14+0x48],0xa8
  a3ac2f:	48 8d 15 9a 57 83 ff                            	lea    rdx,[rip+0xffffffffff83579a]        # 0x2703d0
  a3ac36:	49 89 86 80 08 00 00                            	mov    QWORD PTR [r14+0x880],rax
  a3ac3d:	49 89 8e 88 08 00 00                            	mov    QWORD PTR [r14+0x888],rcx
  a3ac44:	48 8d 0d d5 43 83 ff                            	lea    rcx,[rip+0xffffffffff8343d5]        # 0x26f020
  a3ac4b:	49 89 96 90 08 00 00                            	mov    QWORD PTR [r14+0x890],rdx
  a3ac52:	48 8d 15 df 43 83 ff                            	lea    rdx,[rip+0xffffffffff8343df]        # 0x26f038
  a3ac59:	48 8b 05 38 47 1b 03                            	mov    rax,QWORD PTR [rip+0x31b4738]        # 0x3bef398
  a3ac60:	49 89 8e 98 08 00 00                            	mov    QWORD PTR [r14+0x898],rcx
  a3ac67:	48 8d 0d 2a f2 82 ff                            	lea    rcx,[rip+0xffffffffff82f22a]        # 0x269e98
  a3ac6e:	49 89 96 a0 08 00 00                            	mov    QWORD PTR [r14+0x8a0],rdx
  a3ac75:	48 8d 15 e4 f1 82 ff                            	lea    rdx,[rip+0xffffffffff82f1e4]        # 0x269e60
  a3ac7c:	49 89 8e a8 08 00 00                            	mov    QWORD PTR [r14+0x8a8],rcx
  a3ac83:	48 8d 0d 76 43 83 ff                            	lea    rcx,[rip+0xffffffffff834376]        # 0x26f000
  a3ac8a:	49 89 96 b0 08 00 00                            	mov    QWORD PTR [r14+0x8b0],rdx
  a3ac91:	48 8d 15 78 30 83 ff                            	lea    rdx,[rip+0xffffffffff833078]        # 0x26dd10
  a3ac98:	49 89 8e b8 08 00 00                            	mov    QWORD PTR [r14+0x8b8],rcx
  a3ac9f:	48 8d 0d ba 27 82 ff                            	lea    rcx,[rip+0xffffffffff8227ba]        # 0x25d460
  a3aca6:	49 89 96 c0 08 00 00                            	mov    QWORD PTR [r14+0x8c0],rdx
  a3acad:	48 8d 15 1c 75 83 ff                            	lea    rdx,[rip+0xffffffffff83751c]        # 0x2721d0
  a3acb4:	49 89 8e c8 08 00 00                            	mov    QWORD PTR [r14+0x8c8],rcx
  a3acbb:	48 8d 0d 8e f1 82 ff                            	lea    rcx,[rip+0xffffffffff82f18e]        # 0x269e50
  a3acc2:	e9 8a 04 00 00                                  	jmp    0xa3b151
  a3acc7:	48 8b bd 20 ff ff ff                            	mov    rdi,QWORD PTR [rbp-0xe0]
  a3acce:	48 8d b5 18 ff ff ff                            	lea    rsi,[rbp-0xe8]
  a3acd5:	48 c7 85 18 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0xe8],0x0
  a3ace0:	e8 ab 37 cf ff                                  	call   0x72e490
  a3ace5:	48 8b bd 20 ff ff ff                            	mov    rdi,QWORD PTR [rbp-0xe0]
  a3acec:	85 c0                                           	test   eax,eax
  a3acee:	74 26                                           	je     0xa3ad16
  a3acf0:	41 89 c7                                        	mov    r15d,eax
  a3acf3:	e8 28 f4 b0 ff                                  	call   0x54a120
  a3acf8:	48 8d 3d 17 f5 84 00                            	lea    rdi,[rip+0x84f517]        # 0x128a216
  a3acff:	48 8d 35 38 12 8c 00                            	lea    rsi,[rip+0x8c1238]        # 0x12fbf3e
  a3ad06:	ba 03 04 00 00                                  	mov    edx,0x403
  a3ad0b:	44 89 f9                                        	mov    ecx,r15d
  a3ad0e:	45 89 f8                                        	mov    r8d,r15d
  a3ad11:	e9 cc fb ff ff                                  	jmp    0xa3a8e2
  a3ad16:	48 8b 85 18 ff ff ff                            	mov    rax,QWORD PTR [rbp-0xe8]
  a3ad1d:	48 39 c7                                        	cmp    rdi,rax
  a3ad20:	74 22                                           	je     0xa3ad44
  a3ad22:	48 89 c7                                        	mov    rdi,rax
  a3ad25:	e8 36 f3 b0 ff                                  	call   0x54a060
  a3ad2a:	48 8b bd 20 ff ff ff                            	mov    rdi,QWORD PTR [rbp-0xe0]
  a3ad31:	e8 ea f3 b0 ff                                  	call   0x54a120
  a3ad36:	48 8b bd 18 ff ff ff                            	mov    rdi,QWORD PTR [rbp-0xe8]
  a3ad3d:	48 89 bd 20 ff ff ff                            	mov    QWORD PTR [rbp-0xe0],rdi
  a3ad44:	48 8b 3f                                        	mov    rdi,QWORD PTR [rdi]
  a3ad47:	48 8d 35 5e 27 8a 00                            	lea    rsi,[rip+0x8a275e]        # 0x12dd4ac
  a3ad4e:	ba 04 00 00 00                                  	mov    edx,0x4
  a3ad53:	e8 d8 6c e9 ff                                  	call   0x8d1a30
  a3ad58:	85 c0                                           	test   eax,eax
  a3ad5a:	0f 84 ee 02 00 00                               	je     0xa3b04e
  a3ad60:	48 8b 85 20 ff ff ff                            	mov    rax,QWORD PTR [rbp-0xe0]
  a3ad67:	48 8d 3d 89 2a 88 00                            	lea    rdi,[rip+0x882a89]        # 0x12bd7f7
  a3ad6e:	48 8d 35 c9 11 8c 00                            	lea    rsi,[rip+0x8c11c9]        # 0x12fbf3e
  a3ad75:	ba 0f 04 00 00                                  	mov    edx,0x40f
  a3ad7a:	48 8b 08                                        	mov    rcx,QWORD PTR [rax]
  a3ad7d:	31 c0                                           	xor    eax,eax
  a3ad7f:	e8 8c 26 82 ff                                  	call   0x25d410
  a3ad84:	48 8b 85 20 ff ff ff                            	mov    rax,QWORD PTR [rbp-0xe0]
  a3ad8b:	48 8d 35 34 d6 88 00                            	lea    rsi,[rip+0x88d634]        # 0x12c83c6
  a3ad92:	ba 04 00 00 00                                  	mov    edx,0x4
  a3ad97:	48 8b 38                                        	mov    rdi,QWORD PTR [rax]
  a3ad9a:	e8 91 6c e9 ff                                  	call   0x8d1a30
  a3ad9f:	85 c0                                           	test   eax,eax
  a3ada1:	0f 84 a7 02 00 00                               	je     0xa3b04e
  a3ada7:	48 8b bd 20 ff ff ff                            	mov    rdi,QWORD PTR [rbp-0xe0]
  a3adae:	e8 6d f3 b0 ff                                  	call   0x54a120
  a3adb3:	41 bf 2d 00 00 00                               	mov    r15d,0x2d
  a3adb9:	e9 2b fb ff ff                                  	jmp    0xa3a8e9
  a3adbe:	4c 8d 2d 20 2a 8d 00                            	lea    r13,[rip+0x8d2a20]        # 0x130d7e5
  a3adc5:	48 8d 3d c0 d6 8b 00                            	lea    rdi,[rip+0x8bd6c0]        # 0x12f848c
  a3adcc:	ba 96 0c 00 00                                  	mov    edx,0xc96
  a3add1:	31 c0                                           	xor    eax,eax
  a3add3:	4c 89 ee                                        	mov    rsi,r13
  a3add6:	e8 35 26 82 ff                                  	call   0x25d410
  a3addb:	48 8d 3d 34 f4 84 00                            	lea    rdi,[rip+0x84f434]        # 0x128a216
  a3ade2:	41 bf 16 00 00 00                               	mov    r15d,0x16
  a3ade8:	4c 89 ee                                        	mov    rsi,r13
  a3adeb:	ba 98 0c 00 00                                  	mov    edx,0xc98
  a3adf0:	e9 35 fb ff ff                                  	jmp    0xa3a92a
  a3adf5:	48 8d 05 f4 e2 82 ff                            	lea    rax,[rip+0xffffffffff82e2f4]        # 0x2690f0
  a3adfc:	48 8d 15 8d df 82 ff                            	lea    rdx,[rip+0xffffffffff82df8d]        # 0x268d90
  a3ae03:	48 8d 0d c6 55 83 ff                            	lea    rcx,[rip+0xffffffffff8355c6]        # 0x2703d0
  a3ae0a:	49 c7 86 08 04 00 00 08 00 00 00                	mov    QWORD PTR [r14+0x408],0x8
  a3ae15:	49 c7 46 48 f0 00 00 00                         	mov    QWORD PTR [r14+0x48],0xf0
  a3ae1d:	49 89 86 80 08 00 00                            	mov    QWORD PTR [r14+0x880],rax
  a3ae24:	49 89 96 88 08 00 00                            	mov    QWORD PTR [r14+0x888],rdx
  a3ae2b:	49 89 8e 90 08 00 00                            	mov    QWORD PTR [r14+0x890],rcx
  a3ae32:	48 8d 15 e7 41 83 ff                            	lea    rdx,[rip+0xffffffffff8341e7]        # 0x26f020
  a3ae39:	48 8d 0d f8 41 83 ff                            	lea    rcx,[rip+0xffffffffff8341f8]        # 0x26f038
  a3ae40:	48 8d 05 09 f0 82 ff                            	lea    rax,[rip+0xffffffffff82f009]        # 0x269e50
  a3ae47:	49 89 96 98 08 00 00                            	mov    QWORD PTR [r14+0x898],rdx
  a3ae4e:	49 89 8e a0 08 00 00                            	mov    QWORD PTR [r14+0x8a0],rcx
  a3ae55:	48 8d 15 3c f0 82 ff                            	lea    rdx,[rip+0xffffffffff82f03c]        # 0x269e98
  a3ae5c:	48 8d 0d fd ef 82 ff                            	lea    rcx,[rip+0xffffffffff82effd]        # 0x269e60
  a3ae63:	49 89 96 a8 08 00 00                            	mov    QWORD PTR [r14+0x8a8],rdx
  a3ae6a:	49 89 8e b0 08 00 00                            	mov    QWORD PTR [r14+0x8b0],rcx
  a3ae71:	48 8d 15 88 41 83 ff                            	lea    rdx,[rip+0xffffffffff834188]        # 0x26f000
  a3ae78:	48 8d 0d 91 2e 83 ff                            	lea    rcx,[rip+0xffffffffff832e91]        # 0x26dd10
  a3ae7f:	49 89 96 b8 08 00 00                            	mov    QWORD PTR [r14+0x8b8],rdx
  a3ae86:	49 89 8e c0 08 00 00                            	mov    QWORD PTR [r14+0x8c0],rcx
  a3ae8d:	48 8d 15 cc 25 82 ff                            	lea    rdx,[rip+0xffffffffff8225cc]        # 0x25d460
  a3ae94:	48 8d 0d 35 73 83 ff                            	lea    rcx,[rip+0xffffffffff837335]        # 0x2721d0
  a3ae9b:	e9 60 01 00 00                                  	jmp    0xa3b000
  a3aea0:	49 83 be 78 08 00 00 00                         	cmp    QWORD PTR [r14+0x878],0x0
  a3aea8:	49 c7 86 08 04 00 00 24 00 00 00                	mov    QWORD PTR [r14+0x408],0x24
  a3aeb3:	49 c7 46 48 c8 02 00 00                         	mov    QWORD PTR [r14+0x48],0x2c8
  a3aebb:	0f 84 ef 01 00 00                               	je     0xa3b0b0
  a3aec1:	48 8d 05 40 e2 82 ff                            	lea    rax,[rip+0xffffffffff82e240]        # 0x269108
  a3aec8:	48 8d 15 a9 25 82 ff                            	lea    rdx,[rip+0xffffffffff8225a9]        # 0x25d478
  a3aecf:	48 8d 0d 12 73 83 ff                            	lea    rcx,[rip+0xffffffffff837312]        # 0x2721e8
  a3aed6:	49 89 86 80 08 00 00                            	mov    QWORD PTR [r14+0x880],rax
  a3aedd:	48 8b 05 bc 44 1b 03                            	mov    rax,QWORD PTR [rip+0x31b44bc]        # 0x3bef3a0
  a3aee4:	49 c7 86 88 08 00 00 00 00 00 00                	mov    QWORD PTR [r14+0x888],0x0
  a3aeef:	49 c7 86 90 08 00 00 00 00 00 00                	mov    QWORD PTR [r14+0x890],0x0
  a3aefa:	49 c7 86 98 08 00 00 00 00 00 00                	mov    QWORD PTR [r14+0x898],0x0
  a3af05:	49 c7 86 a0 08 00 00 00 00 00 00                	mov    QWORD PTR [r14+0x8a0],0x0
  a3af10:	49 c7 86 a8 08 00 00 00 00 00 00                	mov    QWORD PTR [r14+0x8a8],0x0
  a3af1b:	49 c7 86 b0 08 00 00 00 00 00 00                	mov    QWORD PTR [r14+0x8b0],0x0
  a3af26:	49 c7 86 b8 08 00 00 00 00 00 00                	mov    QWORD PTR [r14+0x8b8],0x0
  a3af31:	49 c7 86 c0 08 00 00 00 00 00 00                	mov    QWORD PTR [r14+0x8c0],0x0
  a3af3c:	49 89 96 c8 08 00 00                            	mov    QWORD PTR [r14+0x8c8],rdx
  a3af43:	49 89 8e d0 08 00 00                            	mov    QWORD PTR [r14+0x8d0],rcx
  a3af4a:	49 c7 86 d8 08 00 00 00 00 00 00                	mov    QWORD PTR [r14+0x8d8],0x0
  a3af55:	e9 05 02 00 00                                  	jmp    0xa3b15f
  a3af5a:	48 8d 05 97 e1 82 ff                            	lea    rax,[rip+0xffffffffff82e197]        # 0x2690f8
  a3af61:	48 8d 15 30 de 82 ff                            	lea    rdx,[rip+0xffffffffff82de30]        # 0x268d98
  a3af68:	48 8d 0d 69 54 83 ff                            	lea    rcx,[rip+0xffffffffff835469]        # 0x2703d8
  a3af6f:	49 c7 86 08 04 00 00 28 00 00 00                	mov    QWORD PTR [r14+0x408],0x28
  a3af7a:	49 c7 46 48 10 03 00 00                         	mov    QWORD PTR [r14+0x48],0x310
  a3af82:	49 89 86 80 08 00 00                            	mov    QWORD PTR [r14+0x880],rax
  a3af89:	49 89 96 88 08 00 00                            	mov    QWORD PTR [r14+0x888],rdx
  a3af90:	49 89 8e 90 08 00 00                            	mov    QWORD PTR [r14+0x890],rcx
  a3af97:	48 8d 15 8a 40 83 ff                            	lea    rdx,[rip+0xffffffffff83408a]        # 0x26f028
  a3af9e:	48 8d 0d 8b 40 83 ff                            	lea    rcx,[rip+0xffffffffff83408b]        # 0x26f030
  a3afa5:	48 8d 05 ac ee 82 ff                            	lea    rax,[rip+0xffffffffff82eeac]        # 0x269e58
  a3afac:	49 89 96 98 08 00 00                            	mov    QWORD PTR [r14+0x898],rdx
  a3afb3:	49 89 8e a0 08 00 00                            	mov    QWORD PTR [r14+0x8a0],rcx
  a3afba:	48 8d 15 ef ee 82 ff                            	lea    rdx,[rip+0xffffffffff82eeef]        # 0x269eb0
  a3afc1:	48 8d 0d a0 ee 82 ff                            	lea    rcx,[rip+0xffffffffff82eea0]        # 0x269e68
  a3afc8:	49 89 96 a8 08 00 00                            	mov    QWORD PTR [r14+0x8a8],rdx
  a3afcf:	49 89 8e b0 08 00 00                            	mov    QWORD PTR [r14+0x8b0],rcx
  a3afd6:	48 8d 15 2b 40 83 ff                            	lea    rdx,[rip+0xffffffffff83402b]        # 0x26f008
  a3afdd:	48 8d 0d 34 2d 83 ff                            	lea    rcx,[rip+0xffffffffff832d34]        # 0x26dd18
  a3afe4:	49 89 96 b8 08 00 00                            	mov    QWORD PTR [r14+0x8b8],rdx
  a3afeb:	49 89 8e c0 08 00 00                            	mov    QWORD PTR [r14+0x8c0],rcx
  a3aff2:	48 8d 15 6f 24 82 ff                            	lea    rdx,[rip+0xffffffffff82246f]        # 0x25d468
  a3aff9:	48 8d 0d d8 71 83 ff                            	lea    rcx,[rip+0xffffffffff8371d8]        # 0x2721d8
  a3b000:	49 89 96 c8 08 00 00                            	mov    QWORD PTR [r14+0x8c8],rdx
  a3b007:	49 89 8e d0 08 00 00                            	mov    QWORD PTR [r14+0x8d0],rcx
  a3b00e:	49 89 86 d8 08 00 00                            	mov    QWORD PTR [r14+0x8d8],rax
  a3b015:	48 8b 05 8c 43 1b 03                            	mov    rax,QWORD PTR [rip+0x31b438c]        # 0x3bef3a8
  a3b01c:	e9 3e 01 00 00                                  	jmp    0xa3b15f
  a3b021:	48 8b 85 88 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x178]
  a3b028:	48 8b 30                                        	mov    rsi,QWORD PTR [rax]
  a3b02b:	48 83 fe 02                                     	cmp    rsi,0x2
  a3b02f:	0f 84 a1 04 00 00                               	je     0xa3b4d6
  a3b035:	48 8d 3d 43 41 89 00                            	lea    rdi,[rip+0x894143]        # 0x12cf17f
  a3b03c:	31 c0                                           	xor    eax,eax
  a3b03e:	e8 cd 23 82 ff                                  	call   0x25d410
  a3b043:	41 bf 16 00 00 00                               	mov    r15d,0x16
  a3b049:	e9 ac f7 ff ff                                  	jmp    0xa3a7fa
  a3b04e:	48 8b bd 20 ff ff ff                            	mov    rdi,QWORD PTR [rbp-0xe0]
  a3b055:	48 8d 15 7f 01 95 00                            	lea    rdx,[rip+0x95017f]        # 0x138b1db
  a3b05c:	be 00 00 20 00                                  	mov    esi,0x200000
  a3b061:	b9 16 04 00 00                                  	mov    ecx,0x416
  a3b066:	e8 e5 4a c7 ff                                  	call   0x6afb50
  a3b06b:	85 c0                                           	test   eax,eax
  a3b06d:	0f 84 af 04 00 00                               	je     0xa3b522
  a3b073:	48 8b bd 20 ff ff ff                            	mov    rdi,QWORD PTR [rbp-0xe0]
  a3b07a:	89 c1                                           	mov    ecx,eax
  a3b07c:	48 8d 35 9b 0b 8e 00                            	lea    rsi,[rip+0x8e0b9b]        # 0x131bc1e
  a3b083:	48 8d 15 b4 0e 8c 00                            	lea    rdx,[rip+0x8c0eb4]        # 0x12fbf3e
  a3b08a:	41 89 c5                                        	mov    r13d,eax
  a3b08d:	31 c0                                           	xor    eax,eax
  a3b08f:	e8 1c 06 b1 ff                                  	call   0x54b6b0
  a3b094:	48 8b bd 20 ff ff ff                            	mov    rdi,QWORD PTR [rbp-0xe0]
  a3b09b:	e8 80 f0 b0 ff                                  	call   0x54a120
  a3b0a0:	41 83 fd 02                                     	cmp    r13d,0x2
  a3b0a4:	e9 99 fa ff ff                                  	jmp    0xa3ab42
  a3b0a9:	e8 02 26 cc ff                                  	call   0x6fd6b0
  a3b0ae:	0f 0b                                           	ud2
  a3b0b0:	48 8d 05 41 e0 82 ff                            	lea    rax,[rip+0xffffffffff82e041]        # 0x2690f8
  a3b0b7:	48 8d 0d da dc 82 ff                            	lea    rcx,[rip+0xffffffffff82dcda]        # 0x268d98
  a3b0be:	48 8d 15 13 53 83 ff                            	lea    rdx,[rip+0xffffffffff835313]        # 0x2703d8
  a3b0c5:	49 89 86 80 08 00 00                            	mov    QWORD PTR [r14+0x880],rax
  a3b0cc:	49 89 8e 88 08 00 00                            	mov    QWORD PTR [r14+0x888],rcx
  a3b0d3:	48 8d 0d 4e 3f 83 ff                            	lea    rcx,[rip+0xffffffffff833f4e]        # 0x26f028
  a3b0da:	49 89 96 90 08 00 00                            	mov    QWORD PTR [r14+0x890],rdx
  a3b0e1:	48 8d 15 48 3f 83 ff                            	lea    rdx,[rip+0xffffffffff833f48]        # 0x26f030
  a3b0e8:	48 8b 05 b1 42 1b 03                            	mov    rax,QWORD PTR [rip+0x31b42b1]        # 0x3bef3a0
  a3b0ef:	49 89 8e 98 08 00 00                            	mov    QWORD PTR [r14+0x898],rcx
  a3b0f6:	48 8d 0d b3 ed 82 ff                            	lea    rcx,[rip+0xffffffffff82edb3]        # 0x269eb0
  a3b0fd:	49 89 96 a0 08 00 00                            	mov    QWORD PTR [r14+0x8a0],rdx
  a3b104:	48 8d 15 5d ed 82 ff                            	lea    rdx,[rip+0xffffffffff82ed5d]        # 0x269e68
  a3b10b:	49 89 8e a8 08 00 00                            	mov    QWORD PTR [r14+0x8a8],rcx
  a3b112:	48 8d 0d ef 3e 83 ff                            	lea    rcx,[rip+0xffffffffff833eef]        # 0x26f008
  a3b119:	49 89 96 b0 08 00 00                            	mov    QWORD PTR [r14+0x8b0],rdx
  a3b120:	48 8d 15 f1 2b 83 ff                            	lea    rdx,[rip+0xffffffffff832bf1]        # 0x26dd18
  a3b127:	49 89 8e b8 08 00 00                            	mov    QWORD PTR [r14+0x8b8],rcx
  a3b12e:	48 8d 0d 33 23 82 ff                            	lea    rcx,[rip+0xffffffffff822333]        # 0x25d468
  a3b135:	49 89 96 c0 08 00 00                            	mov    QWORD PTR [r14+0x8c0],rdx
  a3b13c:	48 8d 15 95 70 83 ff                            	lea    rdx,[rip+0xffffffffff837095]        # 0x2721d8
  a3b143:	49 89 8e c8 08 00 00                            	mov    QWORD PTR [r14+0x8c8],rcx
  a3b14a:	48 8d 0d 07 ed 82 ff                            	lea    rcx,[rip+0xffffffffff82ed07]        # 0x269e58
  a3b151:	49 89 96 d0 08 00 00                            	mov    QWORD PTR [r14+0x8d0],rdx
  a3b158:	49 89 8e d8 08 00 00                            	mov    QWORD PTR [r14+0x8d8],rcx
  a3b15f:	49 89 86 48 04 00 00                            	mov    QWORD PTR [r14+0x448],rax
  a3b166:	48 8b 85 90 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x170]
  a3b16d:	48 8d 35 c5 42 88 00                            	lea    rsi,[rip+0x8842c5]        # 0x12bf439
  a3b174:	48 8d 15 73 8f 90 00                            	lea    rdx,[rip+0x908f73]        # 0x13440ee
  a3b17b:	48 8d 8d b0 fe ff ff                            	lea    rcx,[rbp-0x150]
  a3b182:	0f b7 40 1c                                     	movzx  eax,WORD PTR [rax+0x1c]
  a3b186:	41 89 86 10 04 00 00                            	mov    DWORD PTR [r14+0x410],eax
  a3b18d:	48 8b 85 78 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x188]
  a3b194:	48 8b b8 a8 00 00 00                            	mov    rdi,QWORD PTR [rax+0xa8]
  a3b19b:	31 c0                                           	xor    eax,eax
  a3b19d:	e8 2e 61 ba ff                                  	call   0x5e12d0
  a3b1a2:	83 f8 01                                        	cmp    eax,0x1
  a3b1a5:	75 1a                                           	jne    0xa3b1c1
  a3b1a7:	8b 85 b0 fe ff ff                               	mov    eax,DWORD PTR [rbp-0x150]
  a3b1ad:	85 c0                                           	test   eax,eax
  a3b1af:	74 25                                           	je     0xa3b1d6
  a3b1b1:	41 bf 16 00 00 00                               	mov    r15d,0x16
  a3b1b7:	83 f8 01                                        	cmp    eax,0x1
  a3b1ba:	74 12                                           	je     0xa3b1ce
  a3b1bc:	e9 39 f6 ff ff                                  	jmp    0xa3a7fa
  a3b1c1:	48 8b 85 90 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x170]
  a3b1c8:	f6 40 1c 08                                     	test   BYTE PTR [rax+0x1c],0x8
  a3b1cc:	75 08                                           	jne    0xa3b1d6
  a3b1ce:	41 80 8e 14 04 00 00 02                         	or     BYTE PTR [r14+0x414],0x2
  a3b1d6:	48 8b 85 90 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x170]
  a3b1dd:	8b 48 20                                        	mov    ecx,DWORD PTR [rax+0x20]
  a3b1e0:	48 81 f9 00 10 00 00                            	cmp    rcx,0x1000
  a3b1e7:	73 37                                           	jae    0xa3b220
  a3b1e9:	4c 8d 2d 95 b2 93 00                            	lea    r13,[rip+0x93b295]        # 0x1376485
  a3b1f0:	48 8d 3d 15 d1 8c 00                            	lea    rdi,[rip+0x8cd115]        # 0x130830c
  a3b1f7:	ba 05 0d 00 00                                  	mov    edx,0xd05
  a3b1fc:	31 c0                                           	xor    eax,eax
  a3b1fe:	4c 89 ee                                        	mov    rsi,r13
  a3b201:	e8 0a 22 82 ff                                  	call   0x25d410
  a3b206:	48 8d 3d 09 f0 84 00                            	lea    rdi,[rip+0x84f009]        # 0x128a216
  a3b20d:	41 bf 16 00 00 00                               	mov    r15d,0x16
  a3b213:	4c 89 ee                                        	mov    rsi,r13
  a3b216:	ba 07 0d 00 00                                  	mov    edx,0xd07
  a3b21b:	e9 0a f7 ff ff                                  	jmp    0xa3a92a
  a3b220:	49 8b b6 08 04 00 00                            	mov    rsi,QWORD PTR [r14+0x408]
  a3b227:	49 8b 7e 48                                     	mov    rdi,QWORD PTR [r14+0x48]
  a3b22b:	ba 00 10 00 00                                  	mov    edx,0x1000
  a3b230:	48 89 d0                                        	mov    rax,rdx
  a3b233:	48 39 ca                                        	cmp    rdx,rcx
  a3b236:	74 0c                                           	je     0xa3b244
  a3b238:	48 8d 14 00                                     	lea    rdx,[rax+rax*1]
  a3b23c:	48 3d 01 00 00 02                               	cmp    rax,0x2000001
  a3b242:	72 ec                                           	jb     0xa3b230
  a3b244:	48 3d 01 00 00 02                               	cmp    rax,0x2000001
  a3b24a:	72 37                                           	jb     0xa3b283
  a3b24c:	4c 8d 2d 32 b2 93 00                            	lea    r13,[rip+0x93b232]        # 0x1376485
  a3b253:	48 8d 3d b2 d0 8c 00                            	lea    rdi,[rip+0x8cd0b2]        # 0x130830c
  a3b25a:	ba 10 0d 00 00                                  	mov    edx,0xd10
  a3b25f:	31 c0                                           	xor    eax,eax
  a3b261:	4c 89 ee                                        	mov    rsi,r13
  a3b264:	e8 a7 21 82 ff                                  	call   0x25d410
  a3b269:	48 8d 3d a6 ef 84 00                            	lea    rdi,[rip+0x84efa6]        # 0x128a216
  a3b270:	41 bf 16 00 00 00                               	mov    r15d,0x16
  a3b276:	4c 89 ee                                        	mov    rsi,r13
  a3b279:	ba 12 0d 00 00                                  	mov    edx,0xd12
  a3b27e:	e9 a7 f6 ff ff                                  	jmp    0xa3a92a
  a3b283:	f3 0f bc c1                                     	tzcnt  eax,ecx
  a3b287:	41 89 86 b0 03 00 00                            	mov    DWORD PTR [r14+0x3b0],eax
  a3b28e:	48 39 f1                                        	cmp    rcx,rsi
  a3b291:	72 0a                                           	jb     0xa3b29d
  a3b293:	89 c8                                           	mov    eax,ecx
  a3b295:	31 d2                                           	xor    edx,edx
  a3b297:	f7 f6                                           	div    esi
  a3b299:	89 c6                                           	mov    esi,eax
  a3b29b:	eb 02                                           	jmp    0xa3b29f
  a3b29d:	31 f6                                           	xor    esi,esi
  a3b29f:	41 89 76 40                                     	mov    DWORD PTR [r14+0x40],esi
  a3b2a3:	48 39 f9                                        	cmp    rcx,rdi
  a3b2a6:	72 08                                           	jb     0xa3b2b0
  a3b2a8:	89 c8                                           	mov    eax,ecx
  a3b2aa:	31 d2                                           	xor    edx,edx
  a3b2ac:	f7 f7                                           	div    edi
  a3b2ae:	eb 02                                           	jmp    0xa3b2b2
  a3b2b0:	31 c0                                           	xor    eax,eax
  a3b2b2:	49 89 f0                                        	mov    r8,rsi
  a3b2b5:	41 89 46 50                                     	mov    DWORD PTR [r14+0x50],eax
  a3b2b9:	49 89 b6 b8 03 00 00                            	mov    QWORD PTR [r14+0x3b8],rsi
  a3b2c0:	4c 0f af c6                                     	imul   r8,rsi
  a3b2c4:	4c 89 c1                                        	mov    rcx,r8
  a3b2c7:	4d 89 86 c0 03 00 00                            	mov    QWORD PTR [r14+0x3c0],r8
  a3b2ce:	49 01 f0                                        	add    r8,rsi
  a3b2d1:	48 0f af ce                                     	imul   rcx,rsi
  a3b2d5:	48 89 ca                                        	mov    rdx,rcx
  a3b2d8:	49 89 8e c8 03 00 00                            	mov    QWORD PTR [r14+0x3c8],rcx
  a3b2df:	48 0f af d6                                     	imul   rdx,rsi
  a3b2e3:	48 89 d7                                        	mov    rdi,rdx
  a3b2e6:	49 89 96 d0 03 00 00                            	mov    QWORD PTR [r14+0x3d0],rdx
  a3b2ed:	48 0f af fe                                     	imul   rdi,rsi
  a3b2f1:	49 89 be d8 03 00 00                            	mov    QWORD PTR [r14+0x3d8],rdi
  a3b2f8:	49 c7 86 e0 03 00 00 0c 00 00 00                	mov    QWORD PTR [r14+0x3e0],0xc
  a3b303:	49 01 b6 e8 03 00 00                            	add    QWORD PTR [r14+0x3e8],rsi
  a3b30a:	4d 01 86 f0 03 00 00                            	add    QWORD PTR [r14+0x3f0],r8
  a3b311:	49 01 c8                                        	add    r8,rcx
  a3b314:	4d 01 86 f8 03 00 00                            	add    QWORD PTR [r14+0x3f8],r8
  a3b31b:	49 01 d0                                        	add    r8,rdx
  a3b31e:	4d 01 86 00 04 00 00                            	add    QWORD PTR [r14+0x400],r8
  a3b325:	48 8b 83 98 00 00 00                            	mov    rax,QWORD PTR [rbx+0x98]
  a3b32c:	a8 02                                           	test   al,0x2
  a3b32e:	74 08                                           	je     0xa3b338
  a3b330:	41 80 8e 13 04 00 00 40                         	or     BYTE PTR [r14+0x413],0x40
  a3b338:	49 8b 4e 30                                     	mov    rcx,QWORD PTR [r14+0x30]
  a3b33c:	48 89 8d 88 fe ff ff                            	mov    QWORD PTR [rbp-0x178],rcx
  a3b343:	4d 85 ed                                        	test   r13,r13
  a3b346:	75 11                                           	jne    0xa3b359
  a3b348:	48 8b 8d 88 fe ff ff                            	mov    rcx,QWORD PTR [rbp-0x178]
  a3b34f:	80 79 1a 00                                     	cmp    BYTE PTR [rcx+0x1a],0x0
  a3b353:	0f 84 f8 02 00 00                               	je     0xa3b651
  a3b359:	41 80 8e 13 04 00 00 80                         	or     BYTE PTR [r14+0x413],0x80
  a3b361:	48 83 c8 01                                     	or     rax,0x1
  a3b365:	48 89 83 98 00 00 00                            	mov    QWORD PTR [rbx+0x98],rax
  a3b36c:	48 8b 8d 88 fe ff ff                            	mov    rcx,QWORD PTR [rbp-0x178]
  a3b373:	4c 89 b3 98 02 00 00                            	mov    QWORD PTR [rbx+0x298],r14
  a3b37a:	8b 41 20                                        	mov    eax,DWORD PTR [rcx+0x20]
  a3b37d:	48 89 83 d0 00 00 00                            	mov    QWORD PTR [rbx+0xd0],rax
  a3b384:	8b 41 10                                        	mov    eax,DWORD PTR [rcx+0x10]
  a3b387:	89 83 78 01 00 00                               	mov    DWORD PTR [rbx+0x178],eax
  a3b38d:	8b 41 14                                        	mov    eax,DWORD PTR [rcx+0x14]
  a3b390:	89 83 7c 01 00 00                               	mov    DWORD PTR [rbx+0x17c],eax
  a3b396:	83 79 10 00                                     	cmp    DWORD PTR [rcx+0x10],0x0
  a3b39a:	0f 94 c1                                        	sete   cl
  a3b39d:	85 c0                                           	test   eax,eax
  a3b39f:	0f 94 c0                                        	sete   al
  a3b3a2:	08 c8                                           	or     al,cl
  a3b3a4:	75 19                                           	jne    0xa3b3bf
  a3b3a6:	48 8d bb 78 01 00 00                            	lea    rdi,[rbx+0x178]
  a3b3ad:	e8 ee c4 b0 ff                                  	call   0x5478a0
  a3b3b2:	48 85 c0                                        	test   rax,rax
  a3b3b5:	74 10                                           	je     0xa3b3c7
  a3b3b7:	48 89 c7                                        	mov    rdi,rax
  a3b3ba:	e8 41 37 ba ff                                  	call   0x5deb00
  a3b3bf:	48 89 df                                        	mov    rdi,rbx
  a3b3c2:	e8 f9 c5 b0 ff                                  	call   0x5479c0
  a3b3c7:	4c 8d 7b 18                                     	lea    r15,[rbx+0x18]
  a3b3cb:	45 31 ed                                        	xor    r13d,r13d
  a3b3ce:	31 f6                                           	xor    esi,esi
  a3b3d0:	31 d2                                           	xor    edx,edx
  a3b3d2:	31 c9                                           	xor    ecx,ecx
  a3b3d4:	4c 89 ff                                        	mov    rdi,r15
  a3b3d7:	e8 24 b6 a8 ff                                  	call   0x4c6a00
  a3b3dc:	80 8b 99 00 00 00 10                            	or     BYTE PTR [rbx+0x99],0x10
  a3b3e3:	4c 89 ff                                        	mov    rdi,r15
  a3b3e6:	31 f6                                           	xor    esi,esi
  a3b3e8:	31 d2                                           	xor    edx,edx
  a3b3ea:	31 c9                                           	xor    ecx,ecx
  a3b3ec:	e8 af bb a8 ff                                  	call   0x4c6fa0
  a3b3f1:	41 c7 86 84 07 00 00 ff ff ff ff                	mov    DWORD PTR [r14+0x784],0xffffffff
  a3b3fc:	41 83 be 50 04 00 00 01                         	cmp    DWORD PTR [r14+0x450],0x1
  a3b404:	0f 85 ff 03 00 00                               	jne    0xa3b809
  a3b40a:	48 8d 3d 37 00 b7 02                            	lea    rdi,[rip+0x2b70037]        # 0x35ab448
  a3b411:	31 f6                                           	xor    esi,esi
  a3b413:	31 d2                                           	xor    edx,edx
  a3b415:	31 c9                                           	xor    ecx,ecx
  a3b417:	e8 e4 b5 a8 ff                                  	call   0x4c6a00
  a3b41c:	48 83 3d 5c 00 b7 02 00                         	cmp    QWORD PTR [rip+0x2b7005c],0x0        # 0x35ab480
  a3b424:	0f 84 57 02 00 00                               	je     0xa3b681
  a3b42a:	48 83 3d 0e 01 b7 02 00                         	cmp    QWORD PTR [rip+0x2b7010e],0x0        # 0x35ab540
  a3b432:	0f 84 b8 02 00 00                               	je     0xa3b6f0
  a3b438:	48 83 3d c0 01 b7 02 00                         	cmp    QWORD PTR [rip+0x2b701c0],0x0        # 0x35ab600
  a3b440:	0f 84 22 03 00 00                               	je     0xa3b768
  a3b446:	48 83 3d 72 02 b7 02 00                         	cmp    QWORD PTR [rip+0x2b70272],0x0        # 0x35ab6c0
  a3b44e:	0f 84 23 03 00 00                               	je     0xa3b777
  a3b454:	48 83 3d 24 03 b7 02 00                         	cmp    QWORD PTR [rip+0x2b70324],0x0        # 0x35ab780
  a3b45c:	0f 84 24 03 00 00                               	je     0xa3b786
  a3b462:	48 83 3d d6 03 b7 02 00                         	cmp    QWORD PTR [rip+0x2b703d6],0x0        # 0x35ab840
  a3b46a:	0f 84 25 03 00 00                               	je     0xa3b795
  a3b470:	48 83 3d 88 04 b7 02 00                         	cmp    QWORD PTR [rip+0x2b70488],0x0        # 0x35ab900
  a3b478:	0f 84 26 03 00 00                               	je     0xa3b7a4
  a3b47e:	48 83 3d 3a 05 b7 02 00                         	cmp    QWORD PTR [rip+0x2b7053a],0x0        # 0x35ab9c0
  a3b486:	0f 84 27 03 00 00                               	je     0xa3b7b3
  a3b48c:	48 83 3d ec 05 b7 02 00                         	cmp    QWORD PTR [rip+0x2b705ec],0x0        # 0x35aba80
  a3b494:	0f 84 28 03 00 00                               	je     0xa3b7c2
  a3b49a:	48 83 3d 9e 06 b7 02 00                         	cmp    QWORD PTR [rip+0x2b7069e],0x0        # 0x35abb40
  a3b4a2:	0f 84 29 03 00 00                               	je     0xa3b7d1
  a3b4a8:	48 83 3d 50 07 b7 02 00                         	cmp    QWORD PTR [rip+0x2b70750],0x0        # 0x35abc00
  a3b4b0:	0f 84 2a 03 00 00                               	je     0xa3b7e0
  a3b4b6:	48 83 3d 02 08 b7 02 00                         	cmp    QWORD PTR [rip+0x2b70802],0x0        # 0x35abcc0
  a3b4be:	0f 85 33 03 00 00                               	jne    0xa3b7f7
  a3b4c4:	48 8d 05 f5 07 b7 02                            	lea    rax,[rip+0x2b707f5]        # 0x35abcc0
  a3b4cb:	41 bd 0b 00 00 00                               	mov    r13d,0xb
  a3b4d1:	e9 17 03 00 00                                  	jmp    0xa3b7ed
  a3b4d6:	48 8b b5 88 fe ff ff                            	mov    rsi,QWORD PTR [rbp-0x178]
  a3b4dd:	4c 89 f7                                        	mov    rdi,r14
  a3b4e0:	e8 2b a1 92 ff                                  	call   0x365610
  a3b4e5:	85 c0                                           	test   eax,eax
  a3b4e7:	0f 84 a0 01 00 00                               	je     0xa3b68d
  a3b4ed:	48 8d 3d 22 ed 84 00                            	lea    rdi,[rip+0x84ed22]        # 0x128a216
  a3b4f4:	48 8d 35 ea 22 8d 00                            	lea    rsi,[rip+0x8d22ea]        # 0x130d7e5
  a3b4fb:	ba 89 0c 00 00                                  	mov    edx,0xc89
  a3b500:	89 c1                                           	mov    ecx,eax
  a3b502:	41 89 c0                                        	mov    r8d,eax
  a3b505:	41 89 c7                                        	mov    r15d,eax
  a3b508:	31 c0                                           	xor    eax,eax
  a3b50a:	e8 01 1f 82 ff                                  	call   0x25d410
  a3b50f:	48 8b 85 88 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x178]
  a3b516:	48 c7 00 00 00 00 00                            	mov    QWORD PTR [rax],0x0
  a3b51d:	e9 d8 f2 ff ff                                  	jmp    0xa3a7fa
  a3b522:	48 8b 85 48 ff ff ff                            	mov    rax,QWORD PTR [rbp-0xb8]
  a3b529:	48 03 85 40 ff ff ff                            	add    rax,QWORD PTR [rbp-0xc0]
  a3b530:	48 8b 8d 20 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xe0]
  a3b537:	48 8d 35 92 d1 b2 01                            	lea    rsi,[rip+0x1b2d192]        # 0x25686d0
  a3b53e:	bf 00 40 00 00                                  	mov    edi,0x4000
  a3b543:	ba 02 01 00 00                                  	mov    edx,0x102
  a3b548:	48 89 8d 60 fe ff ff                            	mov    QWORD PTR [rbp-0x1a0],rcx
  a3b54f:	48 89 85 e8 fe ff ff                            	mov    QWORD PTR [rbp-0x118],rax
  a3b556:	48 89 8d e0 fe ff ff                            	mov    QWORD PTR [rbp-0x120],rcx
  a3b55d:	e8 ee d5 1c 00                                  	call   0xc08b50
  a3b562:	48 8b 8d 90 fe ff ff                            	mov    rcx,QWORD PTR [rbp-0x170]
  a3b569:	48 89 85 c0 fe ff ff                            	mov    QWORD PTR [rbp-0x140],rax
  a3b570:	48 89 85 78 fe ff ff                            	mov    QWORD PTR [rbp-0x188],rax
  a3b577:	48 05 00 10 00 00                               	add    rax,0x1000
  a3b57d:	48 c7 85 c8 fe ff ff 00 10 00 00                	mov    QWORD PTR [rbp-0x138],0x1000
  a3b588:	41 bf 16 00 00 00                               	mov    r15d,0x16
  a3b58e:	48 89 85 d0 fe ff ff                            	mov    QWORD PTR [rbp-0x130],rax
  a3b595:	48 c7 85 d8 fe ff ff 00 30 00 00                	mov    QWORD PTR [rbp-0x128],0x3000
  a3b5a0:	48 89 85 68 fe ff ff                            	mov    QWORD PTR [rbp-0x198],rax
  a3b5a7:	b8 ff fe ff ff                                  	mov    eax,0xfffffeff
  a3b5ac:	03 41 38                                        	add    eax,DWORD PTR [rcx+0x38]
  a3b5af:	83 f8 0c                                        	cmp    eax,0xc
  a3b5b2:	77 1c                                           	ja     0xa3b5d0
  a3b5b4:	b9 2d 1b 00 00                                  	mov    ecx,0x1b2d
  a3b5b9:	0f a3 c1                                        	bt     ecx,eax
  a3b5bc:	73 12                                           	jae    0xa3b5d0
  a3b5be:	48 8d b5 b0 fe ff ff                            	lea    rsi,[rbp-0x150]
  a3b5c5:	4c 89 f7                                        	mov    rdi,r14
  a3b5c8:	e8 43 2a 00 00                                  	call   0xa3e010
  a3b5cd:	41 89 c7                                        	mov    r15d,eax
  a3b5d0:	48 8b bd 60 fe ff ff                            	mov    rdi,QWORD PTR [rbp-0x1a0]
  a3b5d7:	e8 64 ee b0 ff                                  	call   0x54a440
  a3b5dc:	48 83 7d 88 00                                  	cmp    QWORD PTR [rbp-0x78],0x0
  a3b5e1:	74 12                                           	je     0xa3b5f5
  a3b5e3:	48 8d b5 50 ff ff ff                            	lea    rsi,[rbp-0xb0]
  a3b5ea:	4c 89 f7                                        	mov    rdi,r14
  a3b5ed:	e8 5e fd 92 ff                                  	call   0x36b350
  a3b5f2:	41 89 c7                                        	mov    r15d,eax
  a3b5f5:	48 83 7d 90 00                                  	cmp    QWORD PTR [rbp-0x70],0x0
  a3b5fa:	0f 84 02 01 00 00                               	je     0xa3b702
  a3b600:	48 8d b5 50 ff ff ff                            	lea    rsi,[rbp-0xb0]
  a3b607:	4c 89 f7                                        	mov    rdi,r14
  a3b60a:	e8 41 fd 92 ff                                  	call   0x36b350
  a3b60f:	85 c0                                           	test   eax,eax
  a3b611:	0f 84 08 01 00 00                               	je     0xa3b71f
  a3b617:	48 8b 7d 90                                     	mov    rdi,QWORD PTR [rbp-0x70]
  a3b61b:	48 8d 35 ae d0 b2 01                            	lea    rsi,[rip+0x1b2d0ae]        # 0x25686d0
  a3b622:	41 89 c7                                        	mov    r15d,eax
  a3b625:	e8 c6 d7 1c 00                                  	call   0xc08df0
  a3b62a:	e9 d8 00 00 00                                  	jmp    0xa3b707
  a3b62f:	e8 1c 63 db ff                                  	call   0x7f1950
  a3b634:	48 8d 3d f4 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff4]        # 0xa3b62f
  a3b63b:	e8 d0 61 db ff                                  	call   0x7f1810
  a3b640:	48 8d 35 b9 3a 89 00                            	lea    rsi,[rip+0x893ab9]        # 0x12cf100
  a3b647:	bf 0c 00 00 00                                  	mov    edi,0xc
  a3b64c:	e9 96 00 00 00                                  	jmp    0xa3b6e7
  a3b651:	48 8d 3d ab 14 8f 00                            	lea    rdi,[rip+0x8f14ab]        # 0x132cb03
  a3b658:	48 8d 35 ef a0 97 00                            	lea    rsi,[rip+0x97a0ef]        # 0x13b574e
  a3b65f:	ba                                              	.byte 0xba
