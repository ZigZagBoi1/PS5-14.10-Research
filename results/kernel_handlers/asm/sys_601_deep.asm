
/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/deep_601.bin:     file format binary


Disassembly of section .data:

0000000000ca0630 <.data>:
  ca0630:	55                                              	push   rbp
  ca0631:	48 89 e5                                        	mov    rbp,rsp
  ca0634:	41 57                                           	push   r15
  ca0636:	41 56                                           	push   r14
  ca0638:	41 55                                           	push   r13
  ca063a:	41 54                                           	push   r12
  ca063c:	53                                              	push   rbx
  ca063d:	48 81 ec f8 00 00 00                            	sub    rsp,0xf8
  ca0644:	4c 8d 0d c5 bc c7 02                            	lea    r9,[rip+0x2c7bcc5]        # 0x391c310
  ca064b:	41 be 4e 00 00 00                               	mov    r14d,0x4e
  ca0651:	49 8b 01                                        	mov    rax,QWORD PTR [r9]
  ca0654:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  ca0658:	8b 06                                           	mov    eax,DWORD PTR [rsi]
  ca065a:	48 83 f8 27                                     	cmp    rax,0x27
  ca065e:	0f 87 b8 1b 00 00                               	ja     0xca221c
  ca0664:	48 8d 0d f5 0a db 00                            	lea    rcx,[rip+0xdb0af5]        # 0x1a51160
  ca066b:	4c 8b 7e 08                                     	mov    r15,QWORD PTR [rsi+0x8]
  ca066f:	4c 8b 66 10                                     	mov    r12,QWORD PTR [rsi+0x10]
  ca0673:	49 89 f8                                        	mov    r8,rdi
  ca0676:	48 63 14 81                                     	movsxd rdx,DWORD PTR [rcx+rax*4]
  ca067a:	48 01 ca                                        	add    rdx,rcx
  ca067d:	ff e2                                           	jmp    rdx
  ca067f:	45 31 ed                                        	xor    r13d,r13d
  ca0682:	83 f8 24                                        	cmp    eax,0x24
  ca0685:	48 8d 35 b1 78 6f 00                            	lea    rsi,[rip+0x6f78b1]        # 0x1397f3d
  ca068c:	4c 89 c3                                        	mov    rbx,r8
  ca068f:	0f 95 85 e8 fe ff ff                            	setne  BYTE PTR [rbp-0x118]
  ca0696:	31 d2                                           	xor    edx,edx
  ca0698:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  ca06a1:	e8 3a 9d f7 ff                                  	call   0xc1a3e0
  ca06a6:	48 8d b5 10 ff ff ff                            	lea    rsi,[rbp-0xf0]
  ca06ad:	ba 10 00 00 00                                  	mov    edx,0x10
  ca06b2:	4c 89 ff                                        	mov    rdi,r15
  ca06b5:	e8 c6 8b 5b ff                                  	call   0x259280
  ca06ba:	4c 8d 0d 4f bc c7 02                            	lea    r9,[rip+0x2c7bc4f]        # 0x391c310
  ca06c1:	41 89 c6                                        	mov    r14d,eax
  ca06c4:	85 c0                                           	test   eax,eax
  ca06c6:	0f 85 50 1b 00 00                               	jne    0xca221c
  ca06cc:	0f b6 85 e8 fe ff ff                            	movzx  eax,BYTE PTR [rbp-0x118]
  ca06d3:	41 88 c5                                        	mov    r13b,al
  ca06d6:	41 ff c5                                        	inc    r13d
  ca06d9:	e9 6a 02 00 00                                  	jmp    0xca0948
  ca06de:	41 be 16 00 00 00                               	mov    r14d,0x16
  ca06e4:	4d 85 e4                                        	test   r12,r12
  ca06e7:	0f 85 2f 1b 00 00                               	jne    0xca221c
  ca06ed:	41 f6 80 29 05 00 00 01                         	test   BYTE PTR [r8+0x529],0x1
  ca06f5:	41 be 01 00 00 00                               	mov    r14d,0x1
  ca06fb:	0f 84 1b 1b 00 00                               	je     0xca221c
  ca0701:	bf 48 01 00 00                                  	mov    edi,0x148
  ca0706:	49 03 78 08                                     	add    rdi,QWORD PTR [r8+0x8]
  ca070a:	4d 89 cd                                        	mov    r13,r9
  ca070d:	45 31 e4                                        	xor    r12d,r12d
  ca0710:	31 f6                                           	xor    esi,esi
  ca0712:	31 d2                                           	xor    edx,edx
  ca0714:	31 c9                                           	xor    ecx,ecx
  ca0716:	4c 89 c3                                        	mov    rbx,r8
  ca0719:	e8 e2 62 82 ff                                  	call   0x4c6a00
  ca071e:	48 8b 7b 08                                     	mov    rdi,QWORD PTR [rbx+0x8]
  ca0722:	41 be 00 00 00 00                               	mov    r14d,0x0
  ca0728:	f6 87 63 05 00 00 04                            	test   BYTE PTR [rdi+0x563],0x4
  ca072f:	0f 85 83 14 00 00                               	jne    0xca1bb8
  ca0735:	48 8b 87 68 05 00 00                            	mov    rax,QWORD PTR [rdi+0x568]
  ca073c:	48 85 c0                                        	test   rax,rax
  ca073f:	0f 84 6d 14 00 00                               	je     0xca1bb2
  ca0745:	8b 88 90 00 00 00                               	mov    ecx,DWORD PTR [rax+0x90]
  ca074b:	85 c9                                           	test   ecx,ecx
  ca074d:	75 06                                           	jne    0xca0755
  ca074f:	8b 8f 6c 03 00 00                               	mov    ecx,DWORD PTR [rdi+0x36c]
  ca0755:	44 8b b0 8c 00 00 00                            	mov    r14d,DWORD PTR [rax+0x8c]
  ca075c:	41 89 cc                                        	mov    r12d,ecx
  ca075f:	e9 54 14 00 00                                  	jmp    0xca1bb8
  ca0764:	49 8b 78 08                                     	mov    rdi,QWORD PTR [r8+0x8]
  ca0768:	bb 48 01 00 00                                  	mov    ebx,0x148
  ca076d:	45 31 f6                                        	xor    r14d,r14d
  ca0770:	31 f6                                           	xor    esi,esi
  ca0772:	31 d2                                           	xor    edx,edx
  ca0774:	31 c9                                           	xor    ecx,ecx
  ca0776:	4d 89 c5                                        	mov    r13,r8
  ca0779:	48 01 df                                        	add    rdi,rbx
  ca077c:	e8 7f 62 82 ff                                  	call   0x4c6a00
  ca0781:	49 8b 45 08                                     	mov    rax,QWORD PTR [r13+0x8]
  ca0785:	48 8b 78 40                                     	mov    rdi,QWORD PTR [rax+0x40]
  ca0789:	e8 12 c9 5c ff                                  	call   0x26d0a0
  ca078e:	49 03 5d 08                                     	add    rbx,QWORD PTR [r13+0x8]
  ca0792:	41 89 c4                                        	mov    r12d,eax
  ca0795:	31 f6                                           	xor    esi,esi
  ca0797:	31 d2                                           	xor    edx,edx
  ca0799:	31 c9                                           	xor    ecx,ecx
  ca079b:	48 89 df                                        	mov    rdi,rbx
  ca079e:	e8 fd 67 82 ff                                  	call   0x4c6fa0
  ca07a3:	45 85 e4                                        	test   r12d,r12d
  ca07a6:	0f 84 69 1a 00 00                               	je     0xca2215
  ca07ac:	4c 89 ff                                        	mov    rdi,r15
  ca07af:	e8 ec a1 ff ff                                  	call   0xc9a9a0
  ca07b4:	e9 5c 1a 00 00                                  	jmp    0xca2215
  ca07b9:	49 8b 78 08                                     	mov    rdi,QWORD PTR [r8+0x8]
  ca07bd:	4c 89 cb                                        	mov    rbx,r9
  ca07c0:	4d 89 c4                                        	mov    r12,r8
  ca07c3:	e8 f8 a7 ff ff                                  	call   0xc9afc0
  ca07c8:	bf 48 01 00 00                                  	mov    edi,0x148
  ca07cd:	49 03 7c 24 08                                  	add    rdi,QWORD PTR [r12+0x8]
  ca07d2:	45 31 f6                                        	xor    r14d,r14d
  ca07d5:	31 f6                                           	xor    esi,esi
  ca07d7:	31 d2                                           	xor    edx,edx
  ca07d9:	31 c9                                           	xor    ecx,ecx
  ca07db:	e8 20 62 82 ff                                  	call   0x4c6a00
  ca07e0:	49 8b 7c 24 08                                  	mov    rdi,QWORD PTR [r12+0x8]
  ca07e5:	48 8b 87 68 05 00 00                            	mov    rax,QWORD PTR [rdi+0x568]
  ca07ec:	48 85 c0                                        	test   rax,rax
  ca07ef:	74 0c                                           	je     0xca07fd
  ca07f1:	44 89 b8 ec 00 00 00                            	mov    DWORD PTR [rax+0xec],r15d
  ca07f8:	49 8b 7c 24 08                                  	mov    rdi,QWORD PTR [r12+0x8]
  ca07fd:	48 81 c7 48 01 00 00                            	add    rdi,0x148
  ca0804:	e9 c9 12 00 00                                  	jmp    0xca1ad2
  ca0809:	4d 89 c6                                        	mov    r14,r8
  ca080c:	4c 89 cb                                        	mov    rbx,r9
  ca080f:	e8 fc c5 e2 ff                                  	call   0xacce10
  ca0814:	85 c0                                           	test   eax,eax
  ca0816:	75 0d                                           	jne    0xca0825
  ca0818:	e8 33 c6 e2 ff                                  	call   0xacce50
  ca081d:	85 c0                                           	test   eax,eax
  ca081f:	0f 84 67 12 00 00                               	je     0xca1a8c
  ca0825:	41 f6 86 29 05 00 00 01                         	test   BYTE PTR [r14+0x529],0x1
  ca082d:	be 0a 03 02 a0                                  	mov    esi,0xa002030a
  ca0832:	4c 89 f7                                        	mov    rdi,r14
  ca0835:	0f 85 15 10 00 00                               	jne    0xca1850
  ca083b:	48 8b 03                                        	mov    rax,QWORD PTR [rbx]
  ca083e:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  ca0842:	0f 85 c2 1a 00 00                               	jne    0xca230a
  ca0848:	48 81 c6 18 80 00 00                            	add    rsi,0x8018
  ca084f:	e9 4d 12 00 00                                  	jmp    0xca1aa1
  ca0854:	4d 89 c7                                        	mov    r15,r8
  ca0857:	4d 89 cc                                        	mov    r12,r9
  ca085a:	48 89 f3                                        	mov    rbx,rsi
  ca085d:	e8 6e 70 e6 ff                                  	call   0xb078d0
  ca0862:	85 c0                                           	test   eax,eax
  ca0864:	0f 84 f8 0f 00 00                               	je     0xca1862
  ca086a:	48 81 7b 10 b8 00 00 00                         	cmp    QWORD PTR [rbx+0x10],0xb8
  ca0872:	41 be 16 00 00 00                               	mov    r14d,0x16
  ca0878:	75 59                                           	jne    0xca08d3
  ca087a:	49 8b 7f 08                                     	mov    rdi,QWORD PTR [r15+0x8]
  ca087e:	48 89 d8                                        	mov    rax,rbx
  ca0881:	bb 48 01 00 00                                  	mov    ebx,0x148
  ca0886:	4d 89 fd                                        	mov    r13,r15
  ca0889:	31 f6                                           	xor    esi,esi
  ca088b:	31 d2                                           	xor    edx,edx
  ca088d:	31 c9                                           	xor    ecx,ecx
  ca088f:	49 89 c7                                        	mov    r15,rax
  ca0892:	48 01 df                                        	add    rdi,rbx
  ca0895:	e8 66 61 82 ff                                  	call   0x4c6a00
  ca089a:	49 8b 7d 08                                     	mov    rdi,QWORD PTR [r13+0x8]
  ca089e:	4c 8d b5 10 ff ff ff                            	lea    r14,[rbp-0xf0]
  ca08a5:	4c 89 f6                                        	mov    rsi,r14
  ca08a8:	e8 63 41 d9 ff                                  	call   0xa34a10
  ca08ad:	49 03 5d 08                                     	add    rbx,QWORD PTR [r13+0x8]
  ca08b1:	31 f6                                           	xor    esi,esi
  ca08b3:	31 d2                                           	xor    edx,edx
  ca08b5:	31 c9                                           	xor    ecx,ecx
  ca08b7:	48 89 df                                        	mov    rdi,rbx
  ca08ba:	e8 e1 66 82 ff                                  	call   0x4c6fa0
  ca08bf:	49 8b 77 08                                     	mov    rsi,QWORD PTR [r15+0x8]
  ca08c3:	ba b8 00 00 00                                  	mov    edx,0xb8
  ca08c8:	4c 89 f7                                        	mov    rdi,r14
  ca08cb:	e8 30 a5 ff ff                                  	call   0xc9ae00
  ca08d0:	41 89 c6                                        	mov    r14d,eax
  ca08d3:	4d 89 e1                                        	mov    r9,r12
  ca08d6:	e9 41 19 00 00                                  	jmp    0xca221c
  ca08db:	49 8b 78 08                                     	mov    rdi,QWORD PTR [r8+0x8]
  ca08df:	bb 48 01 00 00                                  	mov    ebx,0x148
  ca08e4:	45 31 f6                                        	xor    r14d,r14d
  ca08e7:	31 f6                                           	xor    esi,esi
  ca08e9:	31 d2                                           	xor    edx,edx
  ca08eb:	31 c9                                           	xor    ecx,ecx
  ca08ed:	4d 89 c5                                        	mov    r13,r8
  ca08f0:	48 01 df                                        	add    rdi,rbx
  ca08f3:	e8 08 61 82 ff                                  	call   0x4c6a00
  ca08f8:	49 8b 45 08                                     	mov    rax,QWORD PTR [r13+0x8]
  ca08fc:	48 8b 78 40                                     	mov    rdi,QWORD PTR [rax+0x40]
  ca0900:	e8 0b 88 96 ff                                  	call   0x609110
  ca0905:	49 03 5d 08                                     	add    rbx,QWORD PTR [r13+0x8]
  ca0909:	41 89 c4                                        	mov    r12d,eax
  ca090c:	31 f6                                           	xor    esi,esi
  ca090e:	31 d2                                           	xor    edx,edx
  ca0910:	31 c9                                           	xor    ecx,ecx
  ca0912:	48 89 df                                        	mov    rdi,rbx
  ca0915:	e8 86 66 82 ff                                  	call   0x4c6fa0
  ca091a:	45 85 e4                                        	test   r12d,r12d
  ca091d:	0f 84 f2 18 00 00                               	je     0xca2215
  ca0923:	44 89 ff                                        	mov    edi,r15d
  ca0926:	e8 45 f9 ff ff                                  	call   0xca0270
  ca092b:	e9 e5 18 00 00                                  	jmp    0xca2215
  ca0930:	4c 89 bd 10 ff ff ff                            	mov    QWORD PTR [rbp-0xf0],r15
  ca0937:	4c 89 c3                                        	mov    rbx,r8
  ca093a:	48 c7 85 18 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0xe8],0x0
  ca0945:	45 31 ed                                        	xor    r13d,r13d
  ca0948:	e8 83 6f e6 ff                                  	call   0xb078d0
  ca094d:	85 c0                                           	test   eax,eax
  ca094f:	0f 84 ac 0e 00 00                               	je     0xca1801
  ca0955:	bf 48 01 00 00                                  	mov    edi,0x148
  ca095a:	48 03 7b 08                                     	add    rdi,QWORD PTR [rbx+0x8]
  ca095e:	31 f6                                           	xor    esi,esi
  ca0960:	31 d2                                           	xor    edx,edx
  ca0962:	31 c9                                           	xor    ecx,ecx
  ca0964:	e8 97 60 82 ff                                  	call   0x4c6a00
  ca0969:	48 8b 7b 08                                     	mov    rdi,QWORD PTR [rbx+0x8]
  ca096d:	48 8b 8d 10 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xf0]
  ca0974:	48 8b 95 18 ff ff ff                            	mov    rdx,QWORD PTR [rbp-0xe8]
  ca097b:	4d 89 e0                                        	mov    r8,r12
  ca097e:	b8 06 02 00 00                                  	mov    eax,0x206
  ca0983:	48 89 9d e8 fe ff ff                            	mov    QWORD PTR [rbp-0x118],rbx
  ca098a:	41 bf 16 00 00 00                               	mov    r15d,0x16
  ca0990:	49 c1 e8 08                                     	shr    r8,0x8
  ca0994:	c4 c2 78 f7 c4                                  	bextr  eax,r12d,eax
  ca0999:	41 f6 c4 20                                     	test   r12b,0x20
  ca099d:	0f 94 c3                                        	sete   bl
  ca09a0:	44 89 85 f0 fe ff ff                            	mov    DWORD PTR [rbp-0x110],r8d
  ca09a7:	83 f8 03                                        	cmp    eax,0x3
  ca09aa:	0f 84 66 10 00 00                               	je     0xca1a16
  ca09b0:	41 f6 c4 20                                     	test   r12b,0x20
  ca09b4:	0f 85 09 10 00 00                               	jne    0xca19c3
  ca09ba:	44 89 ee                                        	mov    esi,r13d
  ca09bd:	44 89 c2                                        	mov    edx,r8d
  ca09c0:	89 c1                                           	mov    ecx,eax
  ca09c2:	e8 29 c0 ff ff                                  	call   0xc9c9f0
  ca09c7:	48 8b 8d e8 fe ff ff                            	mov    rcx,QWORD PTR [rbp-0x118]
  ca09ce:	41 89 c7                                        	mov    r15d,eax
  ca09d1:	b3 01                                           	mov    bl,0x1
  ca09d3:	48 8b 79 08                                     	mov    rdi,QWORD PTR [rcx+0x8]
  ca09d7:	e9 3a 10 00 00                                  	jmp    0xca1a16
  ca09dc:	4d 89 cc                                        	mov    r12,r9
  ca09df:	49 89 f6                                        	mov    r14,rsi
  ca09e2:	e8 e9 6e e6 ff                                  	call   0xb078d0
  ca09e7:	85 c0                                           	test   eax,eax
  ca09e9:	0f 84 81 0e 00 00                               	je     0xca1870
  ca09ef:	48 8d 1d 52 cd 16 03                            	lea    rbx,[rip+0x316cd52]        # 0x3e0d748
  ca09f6:	31 f6                                           	xor    esi,esi
  ca09f8:	31 d2                                           	xor    edx,edx
  ca09fa:	31 c9                                           	xor    ecx,ecx
  ca09fc:	48 89 df                                        	mov    rdi,rbx
  ca09ff:	e8 fc 5f 82 ff                                  	call   0x4c6a00
  ca0a04:	44 0f b6 3d 1c cd 16 03                         	movzx  r15d,BYTE PTR [rip+0x316cd1c]        # 0x3e0d728
  ca0a0c:	48 89 df                                        	mov    rdi,rbx
  ca0a0f:	31 f6                                           	xor    esi,esi
  ca0a11:	31 d2                                           	xor    edx,edx
  ca0a13:	31 c9                                           	xor    ecx,ecx
  ca0a15:	e8 86 65 82 ff                                  	call   0x4c6fa0
  ca0a1a:	e9 54 0e 00 00                                  	jmp    0xca1873
  ca0a1f:	bf 48 01 00 00                                  	mov    edi,0x148
  ca0a24:	49 03 78 08                                     	add    rdi,QWORD PTR [r8+0x8]
  ca0a28:	48 89 f3                                        	mov    rbx,rsi
  ca0a2b:	4d 89 cf                                        	mov    r15,r9
  ca0a2e:	45 31 f6                                        	xor    r14d,r14d
  ca0a31:	31 f6                                           	xor    esi,esi
  ca0a33:	31 d2                                           	xor    edx,edx
  ca0a35:	31 c9                                           	xor    ecx,ecx
  ca0a37:	4d 89 c4                                        	mov    r12,r8
  ca0a3a:	e8 c1 5f 82 ff                                  	call   0x4c6a00
  ca0a3f:	49 8b 7c 24 08                                  	mov    rdi,QWORD PTR [r12+0x8]
  ca0a44:	48 8b 87 68 05 00 00                            	mov    rax,QWORD PTR [rdi+0x568]
  ca0a4b:	48 85 c0                                        	test   rax,rax
  ca0a4e:	74 07                                           	je     0xca0a57
  ca0a50:	44 8b b0 e8 00 00 00                            	mov    r14d,DWORD PTR [rax+0xe8]
  ca0a57:	48 81 c7 48 01 00 00                            	add    rdi,0x148
  ca0a5e:	44 89 b5 10 ff ff ff                            	mov    DWORD PTR [rbp-0xf0],r14d
  ca0a65:	31 f6                                           	xor    esi,esi
  ca0a67:	31 d2                                           	xor    edx,edx
  ca0a69:	31 c9                                           	xor    ecx,ecx
  ca0a6b:	e8 30 65 82 ff                                  	call   0x4c6fa0
  ca0a70:	48 8b 5b 08                                     	mov    rbx,QWORD PTR [rbx+0x8]
  ca0a74:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  ca0a7d:	48 8d 35 13 e8 6a 00                            	lea    rsi,[rip+0x6ae813]        # 0x134f297
  ca0a84:	31 d2                                           	xor    edx,edx
  ca0a86:	e8 55 99 f7 ff                                  	call   0xc1a3e0
  ca0a8b:	48 8d bd 10 ff ff ff                            	lea    rdi,[rbp-0xf0]
  ca0a92:	ba 04 00 00 00                                  	mov    edx,0x4
  ca0a97:	48 89 de                                        	mov    rsi,rbx
  ca0a9a:	e8 31 87 5b ff                                  	call   0x2591d0
  ca0a9f:	41 89 c6                                        	mov    r14d,eax
  ca0aa2:	4d 89 f9                                        	mov    r9,r15
  ca0aa5:	e9 72 17 00 00                                  	jmp    0xca221c
  ca0aaa:	49 8b 01                                        	mov    rax,QWORD PTR [r9]
  ca0aad:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  ca0ab1:	0f 85 53 18 00 00                               	jne    0xca230a
  ca0ab7:	4c 89 e7                                        	mov    rdi,r12
  ca0aba:	48 81 c4 f8 00 00 00                            	add    rsp,0xf8
  ca0ac1:	5b                                              	pop    rbx
  ca0ac2:	41 5c                                           	pop    r12
  ca0ac4:	41 5d                                           	pop    r13
  ca0ac6:	41 5e                                           	pop    r14
  ca0ac8:	41 5f                                           	pop    r15
  ca0aca:	5d                                              	pop    rbp
  ca0acb:	e9 20 09 b5 ff                                  	jmp    0x7f13f0
  ca0ad0:	41 be 16 00 00 00                               	mov    r14d,0x16
  ca0ad6:	4d 85 ff                                        	test   r15,r15
  ca0ad9:	0f 85 3d 17 00 00                               	jne    0xca221c
  ca0adf:	48 8d 85 0e ff ff ff                            	lea    rax,[rbp-0xf2]
  ca0ae6:	48 8d b5 10 ff ff ff                            	lea    rsi,[rbp-0xf0]
  ca0aed:	4c 89 cb                                        	mov    rbx,r9
  ca0af0:	48 89 85 f0 fe ff ff                            	mov    QWORD PTR [rbp-0x110],rax
  ca0af7:	48 8d 85 f0 fe ff ff                            	lea    rax,[rbp-0x110]
  ca0afe:	48 c7 85 f8 fe ff ff 02 00 00 00                	mov    QWORD PTR [rbp-0x108],0x2
  ca0b09:	48 89 85 10 ff ff ff                            	mov    QWORD PTR [rbp-0xf0],rax
  ca0b10:	c7 85 18 ff ff ff 01 00 00 00                   	mov    DWORD PTR [rbp-0xe8],0x1
  ca0b1a:	4c 89 a5 20 ff ff ff                            	mov    QWORD PTR [rbp-0xe0],r12
  ca0b21:	48 c7 85 28 ff ff ff 02 00 00 00                	mov    QWORD PTR [rbp-0xd8],0x2
  ca0b2c:	48 c7 85 30 ff ff ff 01 00 00 00                	mov    QWORD PTR [rbp-0xd0],0x1
  ca0b37:	4c 89 85 38 ff ff ff                            	mov    QWORD PTR [rbp-0xc8],r8
  ca0b3e:	49 8b 78 08                                     	mov    rdi,QWORD PTR [r8+0x8]
  ca0b42:	e8 39 63 d9 ff                                  	call   0xa36e80
  ca0b47:	49 89 d9                                        	mov    r9,rbx
  ca0b4a:	41 be 0e 00 00 00                               	mov    r14d,0xe
  ca0b50:	85 c0                                           	test   eax,eax
  ca0b52:	0f 85 c4 16 00 00                               	jne    0xca221c
  ca0b58:	0f b6 85 0e ff ff ff                            	movzx  eax,BYTE PTR [rbp-0xf2]
  ca0b5f:	0f b6 8d 0f ff ff ff                            	movzx  ecx,BYTE PTR [rbp-0xf1]
  ca0b66:	31 d2                                           	xor    edx,edx
  ca0b68:	41 be 23 00 00 00                               	mov    r14d,0x23
  ca0b6e:	34 cd                                           	xor    al,0xcd
  ca0b70:	80 f1 41                                        	xor    cl,0x41
  ca0b73:	08 c1                                           	or     cl,al
  ca0b75:	44 0f 45 f2                                     	cmovne r14d,edx
  ca0b79:	e9 9e 16 00 00                                  	jmp    0xca221c
  ca0b7e:	4d 8b 70 08                                     	mov    r14,QWORD PTR [r8+0x8]
  ca0b82:	31 f6                                           	xor    esi,esi
  ca0b84:	31 d2                                           	xor    edx,edx
  ca0b86:	31 c9                                           	xor    ecx,ecx
  ca0b88:	49 8d 9e 48 01 00 00                            	lea    rbx,[r14+0x148]
  ca0b8f:	48 89 df                                        	mov    rdi,rbx
  ca0b92:	e8 69 5e 82 ff                                  	call   0x4c6a00
  ca0b97:	4d 8b a6 68 05 00 00                            	mov    r12,QWORD PTR [r14+0x568]
  ca0b9e:	4c 89 b5 e8 fe ff ff                            	mov    QWORD PTR [rbp-0x118],r14
  ca0ba5:	4d 85 e4                                        	test   r12,r12
  ca0ba8:	0f 84 06 0d 00 00                               	je     0xca18b4
  ca0bae:	4d 8d 74 24 28                                  	lea    r14,[r12+0x28]
  ca0bb3:	31 f6                                           	xor    esi,esi
  ca0bb5:	31 d2                                           	xor    edx,edx
  ca0bb7:	31 c9                                           	xor    ecx,ecx
  ca0bb9:	4c 89 f7                                        	mov    rdi,r14
  ca0bbc:	e8 3f 5e 82 ff                                  	call   0x4c6a00
  ca0bc1:	41 80 4c 24 64 01                               	or     BYTE PTR [r12+0x64],0x1
  ca0bc7:	45 89 7c 24 60                                  	mov    DWORD PTR [r12+0x60],r15d
  ca0bcc:	41 c7 84 24 88 00 00 00 01 00 00 00             	mov    DWORD PTR [r12+0x88],0x1
  ca0bd8:	41 83 7c 24 34 02                               	cmp    DWORD PTR [r12+0x34],0x2
  ca0bde:	75 08                                           	jne    0xca0be8
  ca0be0:	4c 89 e7                                        	mov    rdi,r12
  ca0be3:	e8 18 e3 a9 ff                                  	call   0x73ef00
  ca0be8:	4c 89 f7                                        	mov    rdi,r14
  ca0beb:	45 31 ed                                        	xor    r13d,r13d
  ca0bee:	31 f6                                           	xor    esi,esi
  ca0bf0:	31 d2                                           	xor    edx,edx
  ca0bf2:	31 c9                                           	xor    ecx,ecx
  ca0bf4:	e8 a7 63 82 ff                                  	call   0x4c6fa0
  ca0bf9:	48 89 df                                        	mov    rdi,rbx
  ca0bfc:	31 f6                                           	xor    esi,esi
  ca0bfe:	31 d2                                           	xor    edx,edx
  ca0c00:	31 c9                                           	xor    ecx,ecx
  ca0c02:	e8 99 63 82 ff                                  	call   0x4c6fa0
  ca0c07:	65 4c 8b 34 25 00 00 00 00                      	mov    r14,QWORD PTR gs:0x0
  ca0c10:	48 89 df                                        	mov    rdi,rbx
  ca0c13:	48 c7 85 18 ff ff ff 40 42 0f 00                	mov    QWORD PTR [rbp-0xe8],0xf4240
  ca0c1e:	48 c7 85 10 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0xf0],0x0
  ca0c29:	31 f6                                           	xor    esi,esi
  ca0c2b:	31 d2                                           	xor    edx,edx
  ca0c2d:	31 c9                                           	xor    ecx,ecx
  ca0c2f:	e8 cc 5d 82 ff                                  	call   0x4c6a00
  ca0c34:	48 8b 85 e8 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x118]
  ca0c3b:	48 8b 40 10                                     	mov    rax,QWORD PTR [rax+0x10]
  ca0c3f:	48 85 c0                                        	test   rax,rax
  ca0c42:	0f 84 7c 00 00 00                               	je     0xca0cc4
  ca0c48:	4c 8d bd 10 ff ff ff                            	lea    r15,[rbp-0xf0]
  ca0c4f:	4c 8d a5 f0 fe ff ff                            	lea    r12,[rbp-0x110]
  ca0c56:	66 2e 0f 1f 84 00 00 00 00 00                   	cs nop WORD PTR [rax+rax*1+0x0]
  ca0c60:	0f ba a0 28 05 00 00 08                         	bt     DWORD PTR [rax+0x528],0x8
  ca0c68:	48 8b 40 10                                     	mov    rax,QWORD PTR [rax+0x10]
  ca0c6c:	41 83 d5 00                                     	adc    r13d,0x0
  ca0c70:	48 85 c0                                        	test   rax,rax
  ca0c73:	75 eb                                           	jne    0xca0c60
  ca0c75:	48 89 df                                        	mov    rdi,rbx
  ca0c78:	31 f6                                           	xor    esi,esi
  ca0c7a:	31 d2                                           	xor    edx,edx
  ca0c7c:	31 c9                                           	xor    ecx,ecx
  ca0c7e:	e8 1d 63 82 ff                                  	call   0x4c6fa0
  ca0c83:	45 85 ed                                        	test   r13d,r13d
  ca0c86:	74 4a                                           	je     0xca0cd2
  ca0c88:	0f 1f 84 00 00 00 00 00                         	nop    DWORD PTR [rax+rax*1+0x0]
  ca0c90:	4c 89 f7                                        	mov    rdi,r14
  ca0c93:	4c 89 fe                                        	mov    rsi,r15
  ca0c96:	4c 89 e2                                        	mov    rdx,r12
  ca0c99:	e8 72 b6 a1 ff                                  	call   0x6bc310
  ca0c9e:	83 f8 04                                        	cmp    eax,0x4
  ca0ca1:	74 ed                                           	je     0xca0c90
  ca0ca3:	48 89 df                                        	mov    rdi,rbx
  ca0ca6:	45 31 ed                                        	xor    r13d,r13d
  ca0ca9:	31 f6                                           	xor    esi,esi
  ca0cab:	31 d2                                           	xor    edx,edx
  ca0cad:	31 c9                                           	xor    ecx,ecx
  ca0caf:	e8 4c 5d 82 ff                                  	call   0x4c6a00
  ca0cb4:	48 8b 85 e8 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x118]
  ca0cbb:	48 8b 40 10                                     	mov    rax,QWORD PTR [rax+0x10]
  ca0cbf:	48 85 c0                                        	test   rax,rax
  ca0cc2:	75 9c                                           	jne    0xca0c60
  ca0cc4:	48 89 df                                        	mov    rdi,rbx
  ca0cc7:	31 f6                                           	xor    esi,esi
  ca0cc9:	31 d2                                           	xor    edx,edx
  ca0ccb:	31 c9                                           	xor    ecx,ecx
  ca0ccd:	e8 ce 62 82 ff                                  	call   0x4c6fa0
  ca0cd2:	45 31 f6                                        	xor    r14d,r14d
  ca0cd5:	e9 3b 15 00 00                                  	jmp    0xca2215
  ca0cda:	41 f6 80 29 05 00 00 01                         	test   BYTE PTR [r8+0x529],0x1
  ca0ce2:	0f 85 24 0b 00 00                               	jne    0xca180c
  ca0ce8:	49 8b b8 40 01 00 00                            	mov    rdi,QWORD PTR [r8+0x140]
  ca0cef:	4c 89 cb                                        	mov    rbx,r9
  ca0cf2:	4d 89 c6                                        	mov    r14,r8
  ca0cf5:	e8 96 82 96 ff                                  	call   0x608f90
  ca0cfa:	85 c0                                           	test   eax,eax
  ca0cfc:	0f 84 43 0d 00 00                               	je     0xca1a45
  ca0d02:	48 8b 03                                        	mov    rax,QWORD PTR [rbx]
  ca0d05:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  ca0d09:	0f 85 fb 15 00 00                               	jne    0xca230a
  ca0d0f:	4c 89 f7                                        	mov    rdi,r14
  ca0d12:	e9 05 0b 00 00                                  	jmp    0xca181c
  ca0d17:	49 8b 40 08                                     	mov    rax,QWORD PTR [r8+0x8]
  ca0d1b:	45 31 f6                                        	xor    r14d,r14d
  ca0d1e:	48 85 c0                                        	test   rax,rax
  ca0d21:	0f 84 f5 14 00 00                               	je     0xca221c
  ca0d27:	f6 80 64 04 00 00 01                            	test   BYTE PTR [rax+0x464],0x1
  ca0d2e:	0f 84 e8 14 00 00                               	je     0xca221c
  ca0d34:	4d 89 c4                                        	mov    r12,r8
  ca0d37:	4c 89 cb                                        	mov    rbx,r9
  ca0d3a:	e8 d1 c0 e2 ff                                  	call   0xacce10
  ca0d3f:	85 c0                                           	test   eax,eax
  ca0d41:	0f 85 01 0b 00 00                               	jne    0xca1848
  ca0d47:	e8 04 c1 e2 ff                                  	call   0xacce50
  ca0d4c:	49 89 d9                                        	mov    r9,rbx
  ca0d4f:	85 c0                                           	test   eax,eax
  ca0d51:	0f 85 c5 14 00 00                               	jne    0xca221c
  ca0d57:	49 8b 01                                        	mov    rax,QWORD PTR [r9]
  ca0d5a:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  ca0d5e:	0f 85 a6 15 00 00                               	jne    0xca230a
  ca0d64:	4c 89 e7                                        	mov    rdi,r12
  ca0d67:	e9 be 02 00 00                                  	jmp    0xca102a
  ca0d6c:	48 8d 35 0d b3 f5 01                            	lea    rsi,[rip+0x1f5b30d]        # 0x2bfc080
  ca0d73:	bf 00 10 00 00                                  	mov    edi,0x1000
  ca0d78:	ba 02 00 00 00                                  	mov    edx,0x2
  ca0d7d:	4d 89 cc                                        	mov    r12,r9
  ca0d80:	e8 cb 7d f6 ff                                  	call   0xc08b50
  ca0d85:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  ca0d8e:	48 8d 35 ef 92 6b 00                            	lea    rsi,[rip+0x6b92ef]        # 0x135a084
  ca0d95:	31 d2                                           	xor    edx,edx
  ca0d97:	48 89 c3                                        	mov    rbx,rax
  ca0d9a:	45 31 f6                                        	xor    r14d,r14d
  ca0d9d:	e8 3e 96 f7 ff                                  	call   0xc1a3e0
  ca0da2:	ba 00 10 00 00                                  	mov    edx,0x1000
  ca0da7:	4c 89 ff                                        	mov    rdi,r15
  ca0daa:	48 89 de                                        	mov    rsi,rbx
  ca0dad:	31 c9                                           	xor    ecx,ecx
  ca0daf:	e8 4c 8b 5b ff                                  	call   0x259900
  ca0db4:	85 c0                                           	test   eax,eax
  ca0db6:	75 17                                           	jne    0xca0dcf
  ca0db8:	be 00 10 00 00                                  	mov    esi,0x1000
  ca0dbd:	48 89 df                                        	mov    rdi,rbx
  ca0dc0:	e8 eb 40 7a ff                                  	call   0x444eb0
  ca0dc5:	48 89 df                                        	mov    rdi,rbx
  ca0dc8:	89 c6                                           	mov    esi,eax
  ca0dca:	e8 11 fd b0 ff                                  	call   0x7b0ae0
  ca0dcf:	48 8d 35 aa b2 f5 01                            	lea    rsi,[rip+0x1f5b2aa]        # 0x2bfc080
  ca0dd6:	48 89 df                                        	mov    rdi,rbx
  ca0dd9:	e8 12 80 f6 ff                                  	call   0xc08df0
  ca0dde:	4d 89 e1                                        	mov    r9,r12
  ca0de1:	e9 36 14 00 00                                  	jmp    0xca221c
  ca0de6:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  ca0def:	48 8d 35 47 71 6f 00                            	lea    rsi,[rip+0x6f7147]        # 0x1397f3d
  ca0df6:	31 d2                                           	xor    edx,edx
  ca0df8:	4d 89 c5                                        	mov    r13,r8
  ca0dfb:	4c 89 cb                                        	mov    rbx,r9
  ca0dfe:	e8 dd 95 f7 ff                                  	call   0xc1a3e0
  ca0e03:	48 8d b5 10 ff ff ff                            	lea    rsi,[rbp-0xf0]
  ca0e0a:	ba 20 00 00 00                                  	mov    edx,0x20
  ca0e0f:	4c 89 e7                                        	mov    rdi,r12
  ca0e12:	e8 69 84 5b ff                                  	call   0x259280
  ca0e17:	41 89 c6                                        	mov    r14d,eax
  ca0e1a:	85 c0                                           	test   eax,eax
  ca0e1c:	0f 85 26 0a 00 00                               	jne    0xca1848
  ca0e22:	49 8b 7d 08                                     	mov    rdi,QWORD PTR [r13+0x8]
  ca0e26:	41 be 48 01 00 00                               	mov    r14d,0x148
  ca0e2c:	31 f6                                           	xor    esi,esi
  ca0e2e:	31 d2                                           	xor    edx,edx
  ca0e30:	31 c9                                           	xor    ecx,ecx
  ca0e32:	4c 01 f7                                        	add    rdi,r14
  ca0e35:	e8 c6 5b 82 ff                                  	call   0x4c6a00
  ca0e3a:	49 8b 85 28 05 00 00                            	mov    rax,QWORD PTR [r13+0x528]
  ca0e41:	4d 89 e8                                        	mov    r8,r13
  ca0e44:	a9 00 04 00 00                                  	test   eax,0x400
  ca0e49:	0f 85 24 07 00 00                               	jne    0xca1573
  ca0e4f:	48 0d 00 00 00 01                               	or     rax,0x1000000
  ca0e55:	49 89 80 28 05 00 00                            	mov    QWORD PTR [r8+0x528],rax
  ca0e5c:	48 8b 85 10 ff ff ff                            	mov    rax,QWORD PTR [rbp-0xf0]
  ca0e63:	49 89 80 78 05 00 00                            	mov    QWORD PTR [r8+0x578],rax
  ca0e6a:	48 8b 85 18 ff ff ff                            	mov    rax,QWORD PTR [rbp-0xe8]
  ca0e71:	49 89 80 80 05 00 00                            	mov    QWORD PTR [r8+0x580],rax
  ca0e78:	e9 f6 06 00 00                                  	jmp    0xca1573
  ca0e7d:	4d 8b 78 08                                     	mov    r15,QWORD PTR [r8+0x8]
  ca0e81:	4d 89 cc                                        	mov    r12,r9
  ca0e84:	45 31 f6                                        	xor    r14d,r14d
  ca0e87:	31 f6                                           	xor    esi,esi
  ca0e89:	31 d2                                           	xor    edx,edx
  ca0e8b:	31 c9                                           	xor    ecx,ecx
  ca0e8d:	49 8d 9f 48 01 00 00                            	lea    rbx,[r15+0x148]
  ca0e94:	48 89 df                                        	mov    rdi,rbx
  ca0e97:	e8 64 5b 82 ff                                  	call   0x4c6a00
  ca0e9c:	4d 8b bf 68 05 00 00                            	mov    r15,QWORD PTR [r15+0x568]
  ca0ea3:	48 89 df                                        	mov    rdi,rbx
  ca0ea6:	31 f6                                           	xor    esi,esi
  ca0ea8:	31 d2                                           	xor    edx,edx
  ca0eaa:	31 c9                                           	xor    ecx,ecx
  ca0eac:	e8 ef 60 82 ff                                  	call   0x4c6fa0
  ca0eb1:	4d 85 ff                                        	test   r15,r15
  ca0eb4:	0f 84 13 0a 00 00                               	je     0xca18cd
  ca0eba:	49 8d 5f 28                                     	lea    rbx,[r15+0x28]
  ca0ebe:	31 f6                                           	xor    esi,esi
  ca0ec0:	31 d2                                           	xor    edx,edx
  ca0ec2:	31 c9                                           	xor    ecx,ecx
  ca0ec4:	48 89 df                                        	mov    rdi,rbx
  ca0ec7:	e8 34 5b 82 ff                                  	call   0x4c6a00
  ca0ecc:	41 8b 47 34                                     	mov    eax,DWORD PTR [r15+0x34]
  ca0ed0:	83 f8 01                                        	cmp    eax,0x1
  ca0ed3:	0f 84 7a 0b 00 00                               	je     0xca1a53
  ca0ed9:	83 f8 02                                        	cmp    eax,0x2
  ca0edc:	0f 84 94 0b 00 00                               	je     0xca1a76
  ca0ee2:	83 f8 03                                        	cmp    eax,0x3
  ca0ee5:	0f 85 85 0b 00 00                               	jne    0xca1a70
  ca0eeb:	41 be 03 00 00 00                               	mov    r14d,0x3
  ca0ef1:	e9 80 0b 00 00                                  	jmp    0xca1a76
  ca0ef6:	49 8b 40 08                                     	mov    rax,QWORD PTR [r8+0x8]
  ca0efa:	48 8d 35 96 e3 6a 00                            	lea    rsi,[rip+0x6ae396]        # 0x134f297
  ca0f01:	4c 89 cb                                        	mov    rbx,r9
  ca0f04:	31 d2                                           	xor    edx,edx
  ca0f06:	48 8b 80 60 05 00 00                            	mov    rax,QWORD PTR [rax+0x560]
  ca0f0d:	48 89 85 10 ff ff ff                            	mov    QWORD PTR [rbp-0xf0],rax
  ca0f14:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  ca0f1d:	e8 be 94 f7 ff                                  	call   0xc1a3e0
  ca0f22:	48 8d bd 10 ff ff ff                            	lea    rdi,[rbp-0xf0]
  ca0f29:	ba 08 00 00 00                                  	mov    edx,0x8
  ca0f2e:	4c 89 fe                                        	mov    rsi,r15
  ca0f31:	e8 9a 82 5b ff                                  	call   0x2591d0
  ca0f36:	49 89 d9                                        	mov    r9,rbx
  ca0f39:	41 89 c6                                        	mov    r14d,eax
  ca0f3c:	e9 db 12 00 00                                  	jmp    0xca221c
  ca0f41:	49 8b 78 08                                     	mov    rdi,QWORD PTR [r8+0x8]
  ca0f45:	4c 89 cb                                        	mov    rbx,r9
  ca0f48:	e8 73 a0 ff ff                                  	call   0xc9afc0
  ca0f4d:	49 89 d9                                        	mov    r9,rbx
  ca0f50:	45 31 f6                                        	xor    r14d,r14d
  ca0f53:	e9 c4 12 00 00                                  	jmp    0xca221c
  ca0f58:	41 be 16 00 00 00                               	mov    r14d,0x16
  ca0f5e:	4d 85 ff                                        	test   r15,r15
  ca0f61:	0f 85 b5 12 00 00                               	jne    0xca221c
  ca0f67:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  ca0f70:	48 8d 35 c6 6f 6f 00                            	lea    rsi,[rip+0x6f6fc6]        # 0x1397f3d
  ca0f77:	31 d2                                           	xor    edx,edx
  ca0f79:	4c 89 cb                                        	mov    rbx,r9
  ca0f7c:	4d 89 c5                                        	mov    r13,r8
  ca0f7f:	e8 5c 94 f7 ff                                  	call   0xc1a3e0
  ca0f84:	48 8d b5 10 ff ff ff                            	lea    rsi,[rbp-0xf0]
  ca0f8b:	ba 18 00 00 00                                  	mov    edx,0x18
  ca0f90:	4c 89 e7                                        	mov    rdi,r12
  ca0f93:	e8 e8 82 5b ff                                  	call   0x259280
  ca0f98:	49 89 d9                                        	mov    r9,rbx
  ca0f9b:	41 89 c6                                        	mov    r14d,eax
  ca0f9e:	85 c0                                           	test   eax,eax
  ca0fa0:	0f 85 76 12 00 00                               	jne    0xca221c
  ca0fa6:	48 83 bd 18 ff ff ff 00                         	cmp    QWORD PTR [rbp-0xe8],0x0
  ca0fae:	4c 89 ef                                        	mov    rdi,r13
  ca0fb1:	0f 84 04 0e 00 00                               	je     0xca1dbb
  ca0fb7:	48 8d 35 52 2e f6 01                            	lea    rsi,[rip+0x1f62e52]        # 0x2c03e10
  ca0fbe:	bf 80 04 00 00                                  	mov    edi,0x480
  ca0fc3:	ba 02 01 00 00                                  	mov    edx,0x102
  ca0fc8:	e8 83 7b f6 ff                                  	call   0xc08b50
  ca0fcd:	4c 8b bd 18 ff ff ff                            	mov    r15,QWORD PTR [rbp-0xe8]
  ca0fd4:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  ca0fdd:	48 8d 35 59 6f 6f 00                            	lea    rsi,[rip+0x6f6f59]        # 0x1397f3d
  ca0fe4:	31 d2                                           	xor    edx,edx
  ca0fe6:	49 89 c6                                        	mov    r14,rax
  ca0fe9:	e8 f2 93 f7 ff                                  	call   0xc1a3e0
  ca0fee:	ba 80 04 00 00                                  	mov    edx,0x480
  ca0ff3:	4c 89 ff                                        	mov    rdi,r15
  ca0ff6:	4c 89 f6                                        	mov    rsi,r14
  ca0ff9:	e8 82 82 5b ff                                  	call   0x259280
  ca0ffe:	85 c0                                           	test   eax,eax
  ca1000:	0f 84 30 0d 00 00                               	je     0xca1d36
  ca1006:	48 8d 35 03 2e f6 01                            	lea    rsi,[rip+0x1f62e03]        # 0x2c03e10
  ca100d:	4c 89 f7                                        	mov    rdi,r14
  ca1010:	e8 db 7d f6 ff                                  	call   0xc08df0
  ca1015:	e9 9e 0d 00 00                                  	jmp    0xca1db8
  ca101a:	49 8b 01                                        	mov    rax,QWORD PTR [r9]
  ca101d:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  ca1021:	0f 85 e3 12 00 00                               	jne    0xca230a
  ca1027:	4c 89 c7                                        	mov    rdi,r8
  ca102a:	4c 89 fe                                        	mov    rsi,r15
  ca102d:	e9 6f 0a 00 00                                  	jmp    0xca1aa1
  ca1032:	41 be 16 00 00 00                               	mov    r14d,0x16
  ca1038:	4d 85 ff                                        	test   r15,r15
  ca103b:	0f 85 db 11 00 00                               	jne    0xca221c
  ca1041:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  ca104a:	48 8d 35 ec 6e 6f 00                            	lea    rsi,[rip+0x6f6eec]        # 0x1397f3d
  ca1051:	31 d2                                           	xor    edx,edx
  ca1053:	4c 89 cb                                        	mov    rbx,r9
  ca1056:	4d 89 c7                                        	mov    r15,r8
  ca1059:	e8 82 93 f7 ff                                  	call   0xc1a3e0
  ca105e:	48 8d b5 10 ff ff ff                            	lea    rsi,[rbp-0xf0]
  ca1065:	ba 18 00 00 00                                  	mov    edx,0x18
  ca106a:	4c 89 e7                                        	mov    rdi,r12
  ca106d:	e8 0e 82 5b ff                                  	call   0x259280
  ca1072:	49 89 d9                                        	mov    r9,rbx
  ca1075:	41 89 c6                                        	mov    r14d,eax
  ca1078:	85 c0                                           	test   eax,eax
  ca107a:	0f 85 9c 11 00 00                               	jne    0xca221c
  ca1080:	48 83 bd 18 ff ff ff 00                         	cmp    QWORD PTR [rbp-0xe8],0x0
  ca1088:	0f 84 93 0a 00 00                               	je     0xca1b21
  ca108e:	49 8b 7f 08                                     	mov    rdi,QWORD PTR [r15+0x8]
  ca1092:	41 be 48 01 00 00                               	mov    r14d,0x148
  ca1098:	31 f6                                           	xor    esi,esi
  ca109a:	31 d2                                           	xor    edx,edx
  ca109c:	31 c9                                           	xor    ecx,ecx
  ca109e:	4c 01 f7                                        	add    rdi,r14
  ca10a1:	e8 5a 59 82 ff                                  	call   0x4c6a00
  ca10a6:	49 8b 87 28 05 00 00                            	mov    rax,QWORD PTR [r15+0x528]
  ca10ad:	4d 89 fd                                        	mov    r13,r15
  ca10b0:	a9 00 04 00 00                                  	test   eax,0x400
  ca10b5:	0f 85 71 0a 00 00                               	jne    0xca1b2c
  ca10bb:	4d 03 75 08                                     	add    r14,QWORD PTR [r13+0x8]
  ca10bf:	31 f6                                           	xor    esi,esi
  ca10c1:	31 d2                                           	xor    edx,edx
  ca10c3:	31 c9                                           	xor    ecx,ecx
  ca10c5:	4c 89 f7                                        	mov    rdi,r14
  ca10c8:	e8 d3 5e 82 ff                                  	call   0x4c6fa0
  ca10cd:	41 be 02 00 00 00                               	mov    r14d,0x2
  ca10d3:	49 89 d9                                        	mov    r9,rbx
  ca10d6:	e9 41 11 00 00                                  	jmp    0xca221c
  ca10db:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  ca10e4:	48 8d 35 52 6e 6f 00                            	lea    rsi,[rip+0x6f6e52]        # 0x1397f3d
  ca10eb:	31 d2                                           	xor    edx,edx
  ca10ed:	4d 89 c5                                        	mov    r13,r8
  ca10f0:	e8 eb 92 f7 ff                                  	call   0xc1a3e0
  ca10f5:	48 8d b5 10 ff ff ff                            	lea    rsi,[rbp-0xf0]
  ca10fc:	ba 48 00 00 00                                  	mov    edx,0x48
  ca1101:	4c 89 ff                                        	mov    rdi,r15
  ca1104:	e8 77 81 5b ff                                  	call   0x259280
  ca1109:	41 89 c6                                        	mov    r14d,eax
  ca110c:	85 c0                                           	test   eax,eax
  ca110e:	0f 85 01 11 00 00                               	jne    0xca2215
  ca1114:	c6 85 57 ff ff ff 00                            	mov    BYTE PTR [rbp-0xa9],0x0
  ca111b:	4d 8b 65 08                                     	mov    r12,QWORD PTR [r13+0x8]
  ca111f:	4c 89 e7                                        	mov    rdi,r12
  ca1122:	e8 99 9e ff ff                                  	call   0xc9afc0
  ca1127:	4d 8d bc 24 48 01 00 00                         	lea    r15,[r12+0x148]
  ca112f:	31 f6                                           	xor    esi,esi
  ca1131:	31 d2                                           	xor    edx,edx
  ca1133:	31 c9                                           	xor    ecx,ecx
  ca1135:	4c 89 ff                                        	mov    rdi,r15
  ca1138:	e8 c3 58 82 ff                                  	call   0x4c6a00
  ca113d:	49 8b 84 24 68 05 00 00                         	mov    rax,QWORD PTR [r12+0x568]
  ca1145:	4c 89 ff                                        	mov    rdi,r15
  ca1148:	31 f6                                           	xor    esi,esi
  ca114a:	31 d2                                           	xor    edx,edx
  ca114c:	31 c9                                           	xor    ecx,ecx
  ca114e:	48 8b 98 f0 00 00 00                            	mov    rbx,QWORD PTR [rax+0xf0]
  ca1155:	e8 46 5e 82 ff                                  	call   0x4c6fa0
  ca115a:	4c 8d b5 38 ff ff ff                            	lea    r14,[rbp-0xc8]
  ca1161:	48 85 db                                        	test   rbx,rbx
  ca1164:	0f 85 7d 0c 00 00                               	jne    0xca1de7
  ca116a:	48 8d 35 9f 2c f6 01                            	lea    rsi,[rip+0x1f62c9f]        # 0x2c03e10
  ca1171:	bf d8 00 00 00                                  	mov    edi,0xd8
  ca1176:	ba 02 01 00 00                                  	mov    edx,0x102
  ca117b:	e8 d0 79 f6 ff                                  	call   0xc08b50
  ca1180:	4c 89 ff                                        	mov    rdi,r15
  ca1183:	48 89 c3                                        	mov    rbx,rax
  ca1186:	31 f6                                           	xor    esi,esi
  ca1188:	31 d2                                           	xor    edx,edx
  ca118a:	31 c9                                           	xor    ecx,ecx
  ca118c:	e8 6f 58 82 ff                                  	call   0x4c6a00
  ca1191:	49 8b 84 24 68 05 00 00                         	mov    rax,QWORD PTR [r12+0x568]
  ca1199:	48 85 c0                                        	test   rax,rax
  ca119c:	74 0e                                           	je     0xca11ac
  ca119e:	48 83 b8 f0 00 00 00 00                         	cmp    QWORD PTR [rax+0xf0],0x0
  ca11a6:	0f 84 26 0c 00 00                               	je     0xca1dd2
  ca11ac:	4c 89 ff                                        	mov    rdi,r15
  ca11af:	31 f6                                           	xor    esi,esi
  ca11b1:	31 d2                                           	xor    edx,edx
  ca11b3:	31 c9                                           	xor    ecx,ecx
  ca11b5:	e8 e6 5d 82 ff                                  	call   0x4c6fa0
  ca11ba:	48 8d 35 4f 2c f6 01                            	lea    rsi,[rip+0x1f62c4f]        # 0x2c03e10
  ca11c1:	48 89 df                                        	mov    rdi,rbx
  ca11c4:	e8 27 7c f6 ff                                  	call   0xc08df0
  ca11c9:	e9 19 0c 00 00                                  	jmp    0xca1de7
  ca11ce:	4d 8b 68 08                                     	mov    r13,QWORD PTR [r8+0x8]
  ca11d2:	48 8d bd 10 ff ff ff                            	lea    rdi,[rbp-0xf0]
  ca11d9:	be 78 00 00 00                                  	mov    esi,0x78
  ca11de:	4c 89 85 e8 fe ff ff                            	mov    QWORD PTR [rbp-0x118],r8
  ca11e5:	e8 06 7e 5b ff                                  	call   0x258ff0
  ca11ea:	49 8d 44 24 f0                                  	lea    rax,[r12-0x10]
  ca11ef:	41 be 16 00 00 00                               	mov    r14d,0x16
  ca11f5:	48 83 f8 f2                                     	cmp    rax,0xfffffffffffffff2
  ca11f9:	0f 82 16 10 00 00                               	jb     0xca2215
  ca11ff:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  ca1208:	48 8d 35 2e 6d 6f 00                            	lea    rsi,[rip+0x6f6d2e]        # 0x1397f3d
  ca120f:	31 d2                                           	xor    edx,edx
  ca1211:	49 c1 e4 03                                     	shl    r12,0x3
  ca1215:	e8 c6 91 f7 ff                                  	call   0xc1a3e0
  ca121a:	48 8d b5 10 ff ff ff                            	lea    rsi,[rbp-0xf0]
  ca1221:	4c 89 ff                                        	mov    rdi,r15
  ca1224:	4c 89 e2                                        	mov    rdx,r12
  ca1227:	e8 54 80 5b ff                                  	call   0x259280
  ca122c:	41 89 c6                                        	mov    r14d,eax
  ca122f:	85 c0                                           	test   eax,eax
  ca1231:	0f 85 de 0f 00 00                               	jne    0xca2215
  ca1237:	48 8b 9d 10 ff ff ff                            	mov    rbx,QWORD PTR [rbp-0xf0]
  ca123e:	4c 8b bd 18 ff ff ff                            	mov    r15,QWORD PTR [rbp-0xe8]
  ca1245:	48 83 fb 01                                     	cmp    rbx,0x1
  ca1249:	49 8d 4f fd                                     	lea    rcx,[r15-0x3]
  ca124d:	0f 94 c0                                        	sete   al
  ca1250:	48 83 f9 02                                     	cmp    rcx,0x2
  ca1254:	0f 92 c1                                        	setb   cl
  ca1257:	20 c1                                           	and    cl,al
  ca1259:	80 f9 01                                        	cmp    cl,0x1
  ca125c:	0f 85 af 08 00 00                               	jne    0xca1b11
  ca1262:	48 8d 35 17 ae f5 01                            	lea    rsi,[rip+0x1f5ae17]        # 0x2bfc080
  ca1269:	4c 8b b5 20 ff ff ff                            	mov    r14,QWORD PTR [rbp-0xe0]
  ca1270:	bf 00 10 00 00                                  	mov    edi,0x1000
  ca1275:	ba 02 01 00 00                                  	mov    edx,0x102
  ca127a:	e8 d1 78 f6 ff                                  	call   0xc08b50
  ca127f:	48 c7 85 f0 fe ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x110],0x0
  ca128a:	48 8d 35 f3 8d 6b 00                            	lea    rsi,[rip+0x6b8df3]        # 0x135a084
  ca1291:	49 89 c4                                        	mov    r12,rax
  ca1294:	31 d2                                           	xor    edx,edx
  ca1296:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  ca129f:	e8 3c 91 f7 ff                                  	call   0xc1a3e0
  ca12a4:	48 8d 8d f0 fe ff ff                            	lea    rcx,[rbp-0x110]
  ca12ab:	ba 00 10 00 00                                  	mov    edx,0x1000
  ca12b0:	4c 89 f7                                        	mov    rdi,r14
  ca12b3:	4c 89 e6                                        	mov    rsi,r12
  ca12b6:	e8 45 86 5b ff                                  	call   0x259900
  ca12bb:	85 c0                                           	test   eax,eax
  ca12bd:	0f 84 9d 09 00 00                               	je     0xca1c60
  ca12c3:	48 8d 35 b6 ad f5 01                            	lea    rsi,[rip+0x1f5adb6]        # 0x2bfc080
  ca12ca:	41 89 c6                                        	mov    r14d,eax
  ca12cd:	4c 89 e7                                        	mov    rdi,r12
  ca12d0:	e9 ef 0c 00 00                                  	jmp    0xca1fc4
  ca12d5:	4d 8b 70 08                                     	mov    r14,QWORD PTR [r8+0x8]
  ca12d9:	4c 89 85 e8 fe ff ff                            	mov    QWORD PTR [rbp-0x118],r8
  ca12e0:	4c 89 f7                                        	mov    rdi,r14
  ca12e3:	e8 d8 9c ff ff                                  	call   0xc9afc0
  ca12e8:	49 8d 9e 48 01 00 00                            	lea    rbx,[r14+0x148]
  ca12ef:	48 c7 85 e0 fe ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x120],0x0
  ca12fa:	31 f6                                           	xor    esi,esi
  ca12fc:	31 d2                                           	xor    edx,edx
  ca12fe:	31 c9                                           	xor    ecx,ecx
  ca1300:	48 89 df                                        	mov    rdi,rbx
  ca1303:	e8 f8 56 82 ff                                  	call   0x4c6a00
  ca1308:	48 8b 85 e8 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x118]
  ca130f:	4d 8b ae 68 05 00 00                            	mov    r13,QWORD PTR [r14+0x568]
  ca1316:	48 89 df                                        	mov    rdi,rbx
  ca1319:	31 f6                                           	xor    esi,esi
  ca131b:	31 d2                                           	xor    edx,edx
  ca131d:	31 c9                                           	xor    ecx,ecx
  ca131f:	48 81 88 28 05 00 00 00 01 00 00                	or     QWORD PTR [rax+0x528],0x100
  ca132a:	e8 71 5c 82 ff                                  	call   0x4c6fa0
  ca132f:	49 8d 5d 28                                     	lea    rbx,[r13+0x28]
  ca1333:	31 f6                                           	xor    esi,esi
  ca1335:	31 d2                                           	xor    edx,edx
  ca1337:	31 c9                                           	xor    ecx,ecx
  ca1339:	48 89 df                                        	mov    rdi,rbx
  ca133c:	e8 bf 56 82 ff                                  	call   0x4c6a00
  ca1341:	48 8b 85 e8 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x118]
  ca1348:	8b 80 9c 00 00 00                               	mov    eax,DWORD PTR [rax+0x9c]
  ca134e:	41 89 85 94 00 00 00                            	mov    DWORD PTR [r13+0x94],eax
  ca1355:	41 83 bd 88 00 00 00 00                         	cmp    DWORD PTR [r13+0x88],0x0
  ca135d:	75 4c                                           	jne    0xca13ab
  ca135f:	4c 89 ef                                        	mov    rdi,r13
  ca1362:	41 c7 45 34 02 00 00 00                         	mov    DWORD PTR [r13+0x34],0x2
  ca136a:	e8 91 db a9 ff                                  	call   0x73ef00
  ca136f:	49 8d 75 10                                     	lea    rsi,[r13+0x10]
  ca1373:	4c 89 ef                                        	mov    rdi,r13
  ca1376:	31 d2                                           	xor    edx,edx
  ca1378:	48 c7 85 e0 fe ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x120],0x0
  ca1383:	e8 f8 d3 a9 ff                                  	call   0x73e780
  ca1388:	41 c7 45 34 01 00 00 00                         	mov    DWORD PTR [r13+0x34],0x1
  ca1390:	85 c0                                           	test   eax,eax
  ca1392:	74 17                                           	je     0xca13ab
  ca1394:	31 c0                                           	xor    eax,eax
  ca1396:	41 83 bd 88 00 00 00 00                         	cmp    DWORD PTR [r13+0x88],0x0
  ca139e:	0f 94 c0                                        	sete   al
  ca13a1:	c1 e0 02                                        	shl    eax,0x2
  ca13a4:	48 89 85 e0 fe ff ff                            	mov    QWORD PTR [rbp-0x120],rax
  ca13ab:	41 83 7d 38 00                                  	cmp    DWORD PTR [r13+0x38],0x0
  ca13b0:	41 be 16 00 00 00                               	mov    r14d,0x16
  ca13b6:	41 c7 85 88 00 00 00 00 00 00 00                	mov    DWORD PTR [r13+0x88],0x0
  ca13c1:	44 0f 44 b5 e0 fe ff ff                         	cmove  r14d,DWORD PTR [rbp-0x120]
  ca13c9:	45 85 f6                                        	test   r14d,r14d
  ca13cc:	0f 84 09 05 00 00                               	je     0xca18db
  ca13d2:	48 89 df                                        	mov    rdi,rbx
  ca13d5:	e9 30 0e 00 00                                  	jmp    0xca220a
  ca13da:	49 8b 78 08                                     	mov    rdi,QWORD PTR [r8+0x8]
  ca13de:	bb 48 01 00 00                                  	mov    ebx,0x148
  ca13e3:	4d 89 cf                                        	mov    r15,r9
  ca13e6:	45 31 f6                                        	xor    r14d,r14d
  ca13e9:	31 f6                                           	xor    esi,esi
  ca13eb:	31 d2                                           	xor    edx,edx
  ca13ed:	31 c9                                           	xor    ecx,ecx
  ca13ef:	4d 89 c4                                        	mov    r12,r8
  ca13f2:	48 01 df                                        	add    rdi,rbx
  ca13f5:	e8 06 56 82 ff                                  	call   0x4c6a00
  ca13fa:	41 80 8c 24 29 05 00 00 08                      	or     BYTE PTR [r12+0x529],0x8
  ca1403:	31 f6                                           	xor    esi,esi
  ca1405:	31 d2                                           	xor    edx,edx
  ca1407:	31 c9                                           	xor    ecx,ecx
  ca1409:	49 03 5c 24 08                                  	add    rbx,QWORD PTR [r12+0x8]
  ca140e:	48 89 df                                        	mov    rdi,rbx
  ca1411:	e8 8a 5b 82 ff                                  	call   0x4c6fa0
  ca1416:	4d 89 f9                                        	mov    r9,r15
  ca1419:	e9 fe 0d 00 00                                  	jmp    0xca221c
  ca141e:	bf 48 01 00 00                                  	mov    edi,0x148
  ca1423:	49 03 78 08                                     	add    rdi,QWORD PTR [r8+0x8]
  ca1427:	48 89 f3                                        	mov    rbx,rsi
  ca142a:	4d 89 cc                                        	mov    r12,r9
  ca142d:	31 f6                                           	xor    esi,esi
  ca142f:	31 d2                                           	xor    edx,edx
  ca1431:	31 c9                                           	xor    ecx,ecx
  ca1433:	4d 89 c5                                        	mov    r13,r8
  ca1436:	e8 c5 55 82 ff                                  	call   0x4c6a00
  ca143b:	48 8b 5b 08                                     	mov    rbx,QWORD PTR [rbx+0x8]
  ca143f:	49 8b 85 28 05 00 00                            	mov    rax,QWORD PTR [r13+0x528]
  ca1446:	49 8b 7d 08                                     	mov    rdi,QWORD PTR [r13+0x8]
  ca144a:	a9 00 01 00 00                                  	test   eax,0x100
  ca144f:	74 16                                           	je     0xca1467
  ca1451:	83 bf 6c 03 00 00 00                            	cmp    DWORD PTR [rdi+0x36c],0x0
  ca1458:	75 0d                                           	jne    0xca1467
  ca145a:	48 25 ff fd ff ff                               	and    rax,0xfffffffffffffdff
  ca1460:	49 89 85 28 05 00 00                            	mov    QWORD PTR [r13+0x528],rax
  ca1467:	4c 8b bf 68 05 00 00                            	mov    r15,QWORD PTR [rdi+0x568]
  ca146e:	4d 85 ff                                        	test   r15,r15
  ca1471:	74 36                                           	je     0xca14a9
  ca1473:	4d 8d 77 28                                     	lea    r14,[r15+0x28]
  ca1477:	31 f6                                           	xor    esi,esi
  ca1479:	31 d2                                           	xor    edx,edx
  ca147b:	31 c9                                           	xor    ecx,ecx
  ca147d:	4c 89 f7                                        	mov    rdi,r14
  ca1480:	e8 7b 55 82 ff                                  	call   0x4c6a00
  ca1485:	41 80 67 64 fe                                  	and    BYTE PTR [r15+0x64],0xfe
  ca148a:	48 85 db                                        	test   rbx,rbx
  ca148d:	74 08                                           	je     0xca1497
  ca148f:	41 c7 47 34 03 00 00 00                         	mov    DWORD PTR [r15+0x34],0x3
  ca1497:	4c 89 f7                                        	mov    rdi,r14
  ca149a:	31 f6                                           	xor    esi,esi
  ca149c:	31 d2                                           	xor    edx,edx
  ca149e:	31 c9                                           	xor    ecx,ecx
  ca14a0:	e8 fb 5a 82 ff                                  	call   0x4c6fa0
  ca14a5:	49 8b 7d 08                                     	mov    rdi,QWORD PTR [r13+0x8]
  ca14a9:	48 81 c7 48 01 00 00                            	add    rdi,0x148
  ca14b0:	45 31 f6                                        	xor    r14d,r14d
  ca14b3:	e9 c1 05 00 00                                  	jmp    0xca1a79
  ca14b8:	44 89 f8                                        	mov    eax,r15d
  ca14bb:	4c 89 cb                                        	mov    rbx,r9
  ca14be:	83 e0 fb                                        	and    eax,0xfffffffb
  ca14c1:	3d 02 01 02 a0                                  	cmp    eax,0xa0020102
  ca14c6:	0f 85 6c 03 00 00                               	jne    0xca1838
  ca14cc:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  ca14d5:	48 8d 35 61 6a 6f 00                            	lea    rsi,[rip+0x6f6a61]        # 0x1397f3d
  ca14dc:	31 d2                                           	xor    edx,edx
  ca14de:	4d 89 c5                                        	mov    r13,r8
  ca14e1:	e8 fa 8e f7 ff                                  	call   0xc1a3e0
  ca14e6:	48 8d b5 10 ff ff ff                            	lea    rsi,[rbp-0xf0]
  ca14ed:	ba 20 00 00 00                                  	mov    edx,0x20
  ca14f2:	4c 89 e7                                        	mov    rdi,r12
  ca14f5:	e8 86 7d 5b ff                                  	call   0x259280
  ca14fa:	41 89 c6                                        	mov    r14d,eax
  ca14fd:	85 c0                                           	test   eax,eax
  ca14ff:	0f 85 43 03 00 00                               	jne    0xca1848
  ca1505:	49 8b 7d 08                                     	mov    rdi,QWORD PTR [r13+0x8]
  ca1509:	41 be 48 01 00 00                               	mov    r14d,0x148
  ca150f:	31 f6                                           	xor    esi,esi
  ca1511:	31 d2                                           	xor    edx,edx
  ca1513:	31 c9                                           	xor    ecx,ecx
  ca1515:	4c 01 f7                                        	add    rdi,r14
  ca1518:	e8 e3 54 82 ff                                  	call   0x4c6a00
  ca151d:	49 8b 85 28 05 00 00                            	mov    rax,QWORD PTR [r13+0x528]
  ca1524:	4d 89 e8                                        	mov    r8,r13
  ca1527:	a9 00 04 00 00                                  	test   eax,0x400
  ca152c:	75 45                                           	jne    0xca1573
  ca152e:	48 0d 00 00 00 01                               	or     rax,0x1000000
  ca1534:	49 89 80 28 05 00 00                            	mov    QWORD PTR [r8+0x528],rax
  ca153b:	48 8b 85 10 ff ff ff                            	mov    rax,QWORD PTR [rbp-0xf0]
  ca1542:	49 89 80 78 05 00 00                            	mov    QWORD PTR [r8+0x578],rax
  ca1549:	48 8b 85 18 ff ff ff                            	mov    rax,QWORD PTR [rbp-0xe8]
  ca1550:	49 89 80 80 05 00 00                            	mov    QWORD PTR [r8+0x580],rax
  ca1557:	48 8b 85 20 ff ff ff                            	mov    rax,QWORD PTR [rbp-0xe0]
  ca155e:	49 89 80 88 05 00 00                            	mov    QWORD PTR [r8+0x588],rax
  ca1565:	48 8b 85 28 ff ff ff                            	mov    rax,QWORD PTR [rbp-0xd8]
  ca156c:	49 89 80 90 05 00 00                            	mov    QWORD PTR [r8+0x590],rax
  ca1573:	4d 03 70 08                                     	add    r14,QWORD PTR [r8+0x8]
  ca1577:	31 f6                                           	xor    esi,esi
  ca1579:	31 d2                                           	xor    edx,edx
  ca157b:	31 c9                                           	xor    ecx,ecx
  ca157d:	4c 89 f7                                        	mov    rdi,r14
  ca1580:	4d 89 c6                                        	mov    r14,r8
  ca1583:	e8 18 5a 82 ff                                  	call   0x4c6fa0
  ca1588:	4c 89 f7                                        	mov    rdi,r14
  ca158b:	4c 89 fe                                        	mov    rsi,r15
  ca158e:	e9 ad 02 00 00                                  	jmp    0xca1840
  ca1593:	49 8b 78 08                                     	mov    rdi,QWORD PTR [r8+0x8]
  ca1597:	41 bf 48 01 00 00                               	mov    r15d,0x148
  ca159d:	4c 89 cb                                        	mov    rbx,r9
  ca15a0:	45 31 f6                                        	xor    r14d,r14d
  ca15a3:	31 f6                                           	xor    esi,esi
  ca15a5:	31 d2                                           	xor    edx,edx
  ca15a7:	31 c9                                           	xor    ecx,ecx
  ca15a9:	4d 89 c4                                        	mov    r12,r8
  ca15ac:	4c 01 ff                                        	add    rdi,r15
  ca15af:	e8 4c 54 82 ff                                  	call   0x4c6a00
  ca15b4:	49 8b 84 24 28 05 00 00                         	mov    rax,QWORD PTR [r12+0x528]
  ca15bc:	4c 89 e1                                        	mov    rcx,r12
  ca15bf:	a9 00 01 00 00                                  	test   eax,0x100
  ca15c4:	74 0d                                           	je     0xca15d3
  ca15c6:	48 0d 00 02 00 00                               	or     rax,0x200
  ca15cc:	48 89 81 28 05 00 00                            	mov    QWORD PTR [rcx+0x528],rax
  ca15d3:	4c 03 79 08                                     	add    r15,QWORD PTR [rcx+0x8]
  ca15d7:	4c 89 ff                                        	mov    rdi,r15
  ca15da:	e9 f3 04 00 00                                  	jmp    0xca1ad2
  ca15df:	41 be 16 00 00 00                               	mov    r14d,0x16
  ca15e5:	4d 85 ff                                        	test   r15,r15
  ca15e8:	0f 85 2e 0c 00 00                               	jne    0xca221c
  ca15ee:	bf 48 01 00 00                                  	mov    edi,0x148
  ca15f3:	49 03 78 08                                     	add    rdi,QWORD PTR [r8+0x8]
  ca15f7:	4c 89 cb                                        	mov    rbx,r9
  ca15fa:	4d 89 c7                                        	mov    r15,r8
  ca15fd:	45 31 f6                                        	xor    r14d,r14d
  ca1600:	31 f6                                           	xor    esi,esi
  ca1602:	31 d2                                           	xor    edx,edx
  ca1604:	31 c9                                           	xor    ecx,ecx
  ca1606:	e8 f5 53 82 ff                                  	call   0x4c6a00
  ca160b:	49 83 fc 02                                     	cmp    r12,0x2
  ca160f:	0f 84 a2 04 00 00                               	je     0xca1ab7
  ca1615:	41 be 16 00 00 00                               	mov    r14d,0x16
  ca161b:	4c 89 f9                                        	mov    rcx,r15
  ca161e:	49 83 fc 01                                     	cmp    r12,0x1
  ca1622:	0f 85 a1 04 00 00                               	jne    0xca1ac9
  ca1628:	48 8b 79 08                                     	mov    rdi,QWORD PTR [rcx+0x8]
  ca162c:	e8 ef 17 00 00                                  	call   0xca2e20
  ca1631:	4c 89 f9                                        	mov    rcx,r15
  ca1634:	45 31 f6                                        	xor    r14d,r14d
  ca1637:	e9 8d 04 00 00                                  	jmp    0xca1ac9
  ca163c:	49 8b b8 40 01 00 00                            	mov    rdi,QWORD PTR [r8+0x140]
  ca1643:	4d 89 cf                                        	mov    r15,r9
  ca1646:	48 89 f3                                        	mov    rbx,rsi
  ca1649:	e8 42 79 96 ff                                  	call   0x608f90
  ca164e:	85 c0                                           	test   eax,eax
  ca1650:	0f 84 5f 03 00 00                               	je     0xca19b5
  ca1656:	48 8b 7b 08                                     	mov    rdi,QWORD PTR [rbx+0x8]
  ca165a:	48 8b 73 10                                     	mov    rsi,QWORD PTR [rbx+0x10]
  ca165e:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  ca1661:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  ca1665:	0f 85 9f 0c 00 00                               	jne    0xca230a
  ca166b:	48 81 c4 f8 00 00 00                            	add    rsp,0xf8
  ca1672:	5b                                              	pop    rbx
  ca1673:	41 5c                                           	pop    r12
  ca1675:	41 5d                                           	pop    r13
  ca1677:	41 5e                                           	pop    r14
  ca1679:	41 5f                                           	pop    r15
  ca167b:	5d                                              	pop    rbp
  ca167c:	e9 df 17 00 00                                  	jmp    0xca2e60
  ca1681:	49 8b 01                                        	mov    rax,QWORD PTR [r9]
  ca1684:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  ca1688:	0f 85 7c 0c 00 00                               	jne    0xca230a
  ca168e:	4c 89 c7                                        	mov    rdi,r8
  ca1691:	4c 89 fe                                        	mov    rsi,r15
  ca1694:	4c 89 e2                                        	mov    rdx,r12
  ca1697:	48 81 c4 f8 00 00 00                            	add    rsp,0xf8
  ca169e:	5b                                              	pop    rbx
  ca169f:	41 5c                                           	pop    r12
  ca16a1:	41 5d                                           	pop    r13
  ca16a3:	41 5e                                           	pop    r14
  ca16a5:	41 5f                                           	pop    r15
  ca16a7:	5d                                              	pop    rbp
  ca16a8:	e9 83 e5 cb ff                                  	jmp    0x95fc30
  ca16ad:	41 be 16 00 00 00                               	mov    r14d,0x16
  ca16b3:	49 83 fc 18                                     	cmp    r12,0x18
  ca16b7:	0f 85 5f 0b 00 00                               	jne    0xca221c
  ca16bd:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  ca16c6:	48 8d 35 70 68 6f 00                            	lea    rsi,[rip+0x6f6870]        # 0x1397f3d
  ca16cd:	31 d2                                           	xor    edx,edx
  ca16cf:	4d 89 c4                                        	mov    r12,r8
  ca16d2:	4d 89 cd                                        	mov    r13,r9
  ca16d5:	e8 06 8d f7 ff                                  	call   0xc1a3e0
  ca16da:	48 8d b5 f0 fe ff ff                            	lea    rsi,[rbp-0x110]
  ca16e1:	ba 18 00 00 00                                  	mov    edx,0x18
  ca16e6:	4c 89 ff                                        	mov    rdi,r15
  ca16e9:	e8 92 7b 5b ff                                  	call   0x259280
  ca16ee:	85 c0                                           	test   eax,eax
  ca16f0:	0f 85 5f 05 00 00                               	jne    0xca1c55
  ca16f6:	83 bd f4 fe ff ff 08                            	cmp    DWORD PTR [rbp-0x10c],0x8
  ca16fd:	4d 89 e9                                        	mov    r9,r13
  ca1700:	0f 85 16 0b 00 00                               	jne    0xca221c
  ca1706:	48 8b 9d 00 ff ff ff                            	mov    rbx,QWORD PTR [rbp-0x100]
  ca170d:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  ca1716:	48 8d 35 20 68 6f 00                            	lea    rsi,[rip+0x6f6820]        # 0x1397f3d
  ca171d:	31 d2                                           	xor    edx,edx
  ca171f:	e8 bc 8c f7 ff                                  	call   0xc1a3e0
  ca1724:	48 8d b5 10 ff ff ff                            	lea    rsi,[rbp-0xf0]
  ca172b:	ba 40 00 00 00                                  	mov    edx,0x40
  ca1730:	48 89 df                                        	mov    rdi,rbx
  ca1733:	e8 48 7b 5b ff                                  	call   0x259280
  ca1738:	85 c0                                           	test   eax,eax
  ca173a:	0f 85 15 05 00 00                               	jne    0xca1c55
  ca1740:	48 83 bd f8 fe ff ff 00                         	cmp    QWORD PTR [rbp-0x108],0x0
  ca1748:	0f 84 a8 0b 00 00                               	je     0xca22f6
  ca174e:	48 8d 1d bb 26 f6 01                            	lea    rbx,[rip+0x1f626bb]        # 0x2c03e10
  ca1755:	bf 80 04 00 00                                  	mov    edi,0x480
  ca175a:	ba 02 01 00 00                                  	mov    edx,0x102
  ca175f:	48 89 de                                        	mov    rsi,rbx
  ca1762:	e8 e9 73 f6 ff                                  	call   0xc08b50
  ca1767:	bf 40 00 00 00                                  	mov    edi,0x40
  ca176c:	48 89 de                                        	mov    rsi,rbx
  ca176f:	ba 02 01 00 00                                  	mov    edx,0x102
  ca1774:	49 89 c7                                        	mov    r15,rax
  ca1777:	e8 d4 73 f6 ff                                  	call   0xc08b50
  ca177c:	48 89 85 e8 fe ff ff                            	mov    QWORD PTR [rbp-0x118],rax
  ca1783:	48 8b 9d f8 fe ff ff                            	mov    rbx,QWORD PTR [rbp-0x108]
  ca178a:	48 8d 35 ac 67 6f 00                            	lea    rsi,[rip+0x6f67ac]        # 0x1397f3d
  ca1791:	31 d2                                           	xor    edx,edx
  ca1793:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  ca179c:	e8 3f 8c f7 ff                                  	call   0xc1a3e0
  ca17a1:	ba 80 04 00 00                                  	mov    edx,0x480
  ca17a6:	48 89 df                                        	mov    rdi,rbx
  ca17a9:	4c 89 fe                                        	mov    rsi,r15
  ca17ac:	e8 cf 7a 5b ff                                  	call   0x259280
  ca17b1:	85 c0                                           	test   eax,eax
  ca17b3:	75 20                                           	jne    0xca17d5
  ca17b5:	48 8b bd 00 ff ff ff                            	mov    rdi,QWORD PTR [rbp-0x100]
  ca17bc:	48 8b b5 e8 fe ff ff                            	mov    rsi,QWORD PTR [rbp-0x118]
  ca17c3:	ba 40 00 00 00                                  	mov    edx,0x40
  ca17c8:	e8 d3 b1 ff ff                                  	call   0xc9c9a0
  ca17cd:	85 c0                                           	test   eax,eax
  ca17cf:	0f 84 93 0a 00 00                               	je     0xca2268
  ca17d5:	48 8d 1d 34 26 f6 01                            	lea    rbx,[rip+0x1f62634]        # 0x2c03e10
  ca17dc:	4c 89 ff                                        	mov    rdi,r15
  ca17df:	41 89 c6                                        	mov    r14d,eax
  ca17e2:	48 89 de                                        	mov    rsi,rbx
  ca17e5:	e8 06 76 f6 ff                                  	call   0xc08df0
  ca17ea:	48 8b bd e8 fe ff ff                            	mov    rdi,QWORD PTR [rbp-0x118]
  ca17f1:	48 89 de                                        	mov    rsi,rbx
  ca17f4:	e8 f7 75 f6 ff                                  	call   0xc08df0
  ca17f9:	4d 89 e9                                        	mov    r9,r13
  ca17fc:	e9 1b 0a 00 00                                  	jmp    0xca221c
  ca1801:	41 be 01 00 00 00                               	mov    r14d,0x1
  ca1807:	e9 09 0a 00 00                                  	jmp    0xca2215
  ca180c:	49 8b 01                                        	mov    rax,QWORD PTR [r9]
  ca180f:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  ca1813:	0f 85 f1 0a 00 00                               	jne    0xca230a
  ca1819:	4c 89 c7                                        	mov    rdi,r8
  ca181c:	4c 89 fe                                        	mov    rsi,r15
  ca181f:	4c 89 e2                                        	mov    rdx,r12
  ca1822:	48 81 c4 f8 00 00 00                            	add    rsp,0xf8
  ca1829:	5b                                              	pop    rbx
  ca182a:	41 5c                                           	pop    r12
  ca182c:	41 5d                                           	pop    r13
  ca182e:	41 5e                                           	pop    r14
  ca1830:	41 5f                                           	pop    r15
  ca1832:	5d                                              	pop    rbp
  ca1833:	e9 e8 0a 00 00                                  	jmp    0xca2320
  ca1838:	be 0a 03 02 a0                                  	mov    esi,0xa002030a
  ca183d:	4c 89 c7                                        	mov    rdi,r8
  ca1840:	e8 db e1 ff ff                                  	call   0xc9fa20
  ca1845:	41 89 c6                                        	mov    r14d,eax
  ca1848:	49 89 d9                                        	mov    r9,rbx
  ca184b:	e9 cc 09 00 00                                  	jmp    0xca221c
  ca1850:	48 8b 03                                        	mov    rax,QWORD PTR [rbx]
  ca1853:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  ca1857:	0f 84 44 02 00 00                               	je     0xca1aa1
  ca185d:	e9 a8 0a 00 00                                  	jmp    0xca230a
  ca1862:	41 be 01 00 00 00                               	mov    r14d,0x1
  ca1868:	4d 89 e1                                        	mov    r9,r12
  ca186b:	e9 ac 09 00 00                                  	jmp    0xca221c
  ca1870:	45 31 ff                                        	xor    r15d,r15d
  ca1873:	4c 89 bd 10 ff ff ff                            	mov    QWORD PTR [rbp-0xf0],r15
  ca187a:	48 8d 35 16 da 6a 00                            	lea    rsi,[rip+0x6ada16]        # 0x134f297
  ca1881:	31 d2                                           	xor    edx,edx
  ca1883:	49 8b 5e 08                                     	mov    rbx,QWORD PTR [r14+0x8]
  ca1887:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  ca1890:	e8 4b 8b f7 ff                                  	call   0xc1a3e0
  ca1895:	48 8d bd 10 ff ff ff                            	lea    rdi,[rbp-0xf0]
  ca189c:	ba 08 00 00 00                                  	mov    edx,0x8
  ca18a1:	48 89 de                                        	mov    rsi,rbx
  ca18a4:	e8 27 79 5b ff                                  	call   0x2591d0
  ca18a9:	41 89 c6                                        	mov    r14d,eax
  ca18ac:	4d 89 e1                                        	mov    r9,r12
  ca18af:	e9 68 09 00 00                                  	jmp    0xca221c
  ca18b4:	48 89 df                                        	mov    rdi,rbx
  ca18b7:	31 f6                                           	xor    esi,esi
  ca18b9:	31 d2                                           	xor    edx,edx
  ca18bb:	31 c9                                           	xor    ecx,ecx
  ca18bd:	e8 de 56 82 ff                                  	call   0x4c6fa0
  ca18c2:	41 be 03 00 00 00                               	mov    r14d,0x3
  ca18c8:	e9 48 09 00 00                                  	jmp    0xca2215
  ca18cd:	41 be 16 00 00 00                               	mov    r14d,0x16
  ca18d3:	4d 89 e1                                        	mov    r9,r12
  ca18d6:	e9 41 09 00 00                                  	jmp    0xca221c
  ca18db:	48 8d bd 10 ff ff ff                            	lea    rdi,[rbp-0xf0]
  ca18e2:	be 28 00 00 00                                  	mov    esi,0x28
  ca18e7:	e8 04 77 5b ff                                  	call   0x258ff0
  ca18ec:	49 8b 85 80 00 00 00                            	mov    rax,QWORD PTR [r13+0x80]
  ca18f3:	48 89 df                                        	mov    rdi,rbx
  ca18f6:	31 f6                                           	xor    esi,esi
  ca18f8:	31 d2                                           	xor    edx,edx
  ca18fa:	48 89 85 30 ff ff ff                            	mov    QWORD PTR [rbp-0xd0],rax
  ca1901:	49 8b 45 78                                     	mov    rax,QWORD PTR [r13+0x78]
  ca1905:	48 89 85 28 ff ff ff                            	mov    QWORD PTR [rbp-0xd8],rax
  ca190c:	49 8b 45 70                                     	mov    rax,QWORD PTR [r13+0x70]
  ca1910:	48 89 85 20 ff ff ff                            	mov    QWORD PTR [rbp-0xe0],rax
  ca1917:	49 8b 45 60                                     	mov    rax,QWORD PTR [r13+0x60]
  ca191b:	49 8b 4d 68                                     	mov    rcx,QWORD PTR [r13+0x68]
  ca191f:	48 89 8d 18 ff ff ff                            	mov    QWORD PTR [rbp-0xe8],rcx
  ca1926:	31 c9                                           	xor    ecx,ecx
  ca1928:	48 89 85 10 ff ff ff                            	mov    QWORD PTR [rbp-0xf0],rax
  ca192f:	e8 6c 56 82 ff                                  	call   0x4c6fa0
  ca1934:	41 be 0e 00 00 00                               	mov    r14d,0xe
  ca193a:	45 85 e4                                        	test   r12d,r12d
  ca193d:	0f 88 d2 08 00 00                               	js     0xca2215
  ca1943:	41 81 e4 ff ff ff 7f                            	and    r12d,0x7fffffff
  ca194a:	bb 28 00 00 00                                  	mov    ebx,0x28
  ca194f:	48 8d 35 41 d9 6a 00                            	lea    rsi,[rip+0x6ad941]        # 0x134f297
  ca1956:	49 83 fc 28                                     	cmp    r12,0x28
  ca195a:	49 0f 42 dc                                     	cmovb  rbx,r12
  ca195e:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  ca1967:	31 d2                                           	xor    edx,edx
  ca1969:	e8 72 8a f7 ff                                  	call   0xc1a3e0
  ca196e:	48 8d bd 10 ff ff ff                            	lea    rdi,[rbp-0xf0]
  ca1975:	4c 89 fe                                        	mov    rsi,r15
  ca1978:	48 89 da                                        	mov    rdx,rbx
  ca197b:	e8 50 78 5b ff                                  	call   0x2591d0
  ca1980:	41 89 c6                                        	mov    r14d,eax
  ca1983:	85 c0                                           	test   eax,eax
  ca1985:	0f 85 8a 08 00 00                               	jne    0xca2215
  ca198b:	48 8b 95 e8 fe ff ff                            	mov    rdx,QWORD PTR [rbp-0x118]
  ca1992:	48 8d 3d 6e 7d 6b 00                            	lea    rdi,[rip+0x6b7d6e]        # 0x1359707
  ca1999:	31 c0                                           	xor    eax,eax
  ca199b:	8b b2 9c 00 00 00                               	mov    esi,DWORD PTR [rdx+0x9c]
  ca19a1:	48 81 c2 94 02 00 00                            	add    rdx,0x294
  ca19a8:	e8 63 ba 5b ff                                  	call   0x25d410
  ca19ad:	45 31 f6                                        	xor    r14d,r14d
  ca19b0:	e9 60 08 00 00                                  	jmp    0xca2215
  ca19b5:	41 be 01 00 00 00                               	mov    r14d,0x1
  ca19bb:	4d 89 f9                                        	mov    r9,r15
  ca19be:	e9 59 08 00 00                                  	jmp    0xca221c
  ca19c3:	be 01 02 00 00                                  	mov    esi,0x201
  ca19c8:	45 89 e0                                        	mov    r8d,r12d
  ca19cb:	c4 42 48 f7 cc                                  	bextr  r9d,r12d,esi
  ca19d0:	be 03 02 00 00                                  	mov    esi,0x203
  ca19d5:	41 83 e0 01                                     	and    r8d,0x1
  ca19d9:	c4 42 48 f7 d4                                  	bextr  r10d,r12d,esi
  ca19de:	48 83 ec 08                                     	sub    rsp,0x8
  ca19e2:	4c 8d 9d f0 fe ff ff                            	lea    r11,[rbp-0x110]
  ca19e9:	44 89 ee                                        	mov    esi,r13d
  ca19ec:	50                                              	push   rax
  ca19ed:	41 53                                           	push   r11
  ca19ef:	41 52                                           	push   r10
  ca19f1:	e8 3a b5 ff ff                                  	call   0xc9cf30
  ca19f6:	48 83 c4 20                                     	add    rsp,0x20
  ca19fa:	48 8b 8d e8 fe ff ff                            	mov    rcx,QWORD PTR [rbp-0x118]
  ca1a01:	41 89 c7                                        	mov    r15d,eax
  ca1a04:	45 31 f6                                        	xor    r14d,r14d
  ca1a07:	48 8b 79 08                                     	mov    rdi,QWORD PTR [rcx+0x8]
  ca1a0b:	45 85 ff                                        	test   r15d,r15d
  ca1a0e:	0f 84 d1 00 00 00                               	je     0xca1ae5
  ca1a14:	31 db                                           	xor    ebx,ebx
  ca1a16:	48 81 c7 48 01 00 00                            	add    rdi,0x148
  ca1a1d:	31 f6                                           	xor    esi,esi
  ca1a1f:	31 d2                                           	xor    edx,edx
  ca1a21:	31 c9                                           	xor    ecx,ecx
  ca1a23:	e8 78 55 82 ff                                  	call   0x4c6fa0
  ca1a28:	4c 8d 0d e1 a8 c7 02                            	lea    r9,[rip+0x2c7a8e1]        # 0x391c310
  ca1a2f:	45 31 f6                                        	xor    r14d,r14d
  ca1a32:	f6 c3 01                                        	test   bl,0x1
  ca1a35:	45 0f 44 f7                                     	cmove  r14d,r15d
  ca1a39:	45 85 ff                                        	test   r15d,r15d
  ca1a3c:	45 0f 45 f7                                     	cmovne r14d,r15d
  ca1a40:	e9 d7 07 00 00                                  	jmp    0xca221c
  ca1a45:	41 be 01 00 00 00                               	mov    r14d,0x1
  ca1a4b:	49 89 d9                                        	mov    r9,rbx
  ca1a4e:	e9 c9 07 00 00                                  	jmp    0xca221c
  ca1a53:	49 8d 77 10                                     	lea    rsi,[r15+0x10]
  ca1a57:	4c 89 ff                                        	mov    rdi,r15
  ca1a5a:	31 d2                                           	xor    edx,edx
  ca1a5c:	e8 1f cd a9 ff                                  	call   0x73e780
  ca1a61:	83 f8 ff                                        	cmp    eax,0xffffffff
  ca1a64:	41 be 04 00 00 00                               	mov    r14d,0x4
  ca1a6a:	44 0f 45 f0                                     	cmovne r14d,eax
  ca1a6e:	eb 06                                           	jmp    0xca1a76
  ca1a70:	41 be 23 00 00 00                               	mov    r14d,0x23
  ca1a76:	48 89 df                                        	mov    rdi,rbx
  ca1a79:	31 f6                                           	xor    esi,esi
  ca1a7b:	31 d2                                           	xor    edx,edx
  ca1a7d:	31 c9                                           	xor    ecx,ecx
  ca1a7f:	e8 1c 55 82 ff                                  	call   0x4c6fa0
  ca1a84:	4d 89 e1                                        	mov    r9,r12
  ca1a87:	e9 90 07 00 00                                  	jmp    0xca221c
  ca1a8c:	48 8b 03                                        	mov    rax,QWORD PTR [rbx]
  ca1a8f:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  ca1a93:	0f 85 71 08 00 00                               	jne    0xca230a
  ca1a99:	4c 89 f7                                        	mov    rdi,r14
  ca1a9c:	be 0a 03 02 a0                                  	mov    esi,0xa002030a
  ca1aa1:	48 81 c4 f8 00 00 00                            	add    rsp,0xf8
  ca1aa8:	5b                                              	pop    rbx
  ca1aa9:	41 5c                                           	pop    r12
  ca1aab:	41 5d                                           	pop    r13
  ca1aad:	41 5e                                           	pop    r14
  ca1aaf:	41 5f                                           	pop    r15
  ca1ab1:	5d                                              	pop    rbp
  ca1ab2:	e9 69 df ff ff                                  	jmp    0xc9fa20
  ca1ab7:	49 8b 47 08                                     	mov    rax,QWORD PTR [r15+0x8]
  ca1abb:	4c 89 f9                                        	mov    rcx,r15
  ca1abe:	48 81 88 60 05 00 00 00 00 00 10                	or     QWORD PTR [rax+0x560],0x10000000
  ca1ac9:	bf 48 01 00 00                                  	mov    edi,0x148
  ca1ace:	48 03 79 08                                     	add    rdi,QWORD PTR [rcx+0x8]
  ca1ad2:	31 f6                                           	xor    esi,esi
  ca1ad4:	31 d2                                           	xor    edx,edx
  ca1ad6:	31 c9                                           	xor    ecx,ecx
  ca1ad8:	e8 c3 54 82 ff                                  	call   0x4c6fa0
  ca1add:	49 89 d9                                        	mov    r9,rbx
  ca1ae0:	e9 37 07 00 00                                  	jmp    0xca221c
  ca1ae5:	44 8b bd f0 fe ff ff                            	mov    r15d,DWORD PTR [rbp-0x110]
  ca1aec:	48 81 c7 48 01 00 00                            	add    rdi,0x148
  ca1af3:	31 f6                                           	xor    esi,esi
  ca1af5:	31 d2                                           	xor    edx,edx
  ca1af7:	31 c9                                           	xor    ecx,ecx
  ca1af9:	e8 a2 54 82 ff                                  	call   0x4c6fa0
  ca1afe:	45 85 ff                                        	test   r15d,r15d
  ca1b01:	0f 89 0e 07 00 00                               	jns    0xca2215
  ca1b07:	41 f7 d7                                        	not    r15d
  ca1b0a:	31 db                                           	xor    ebx,ebx
  ca1b0c:	e9 17 ff ff ff                                  	jmp    0xca1a28
  ca1b11:	48 c7 85 e0 fe ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x120],0x0
  ca1b1c:	e9 7f 01 00 00                                  	jmp    0xca1ca0
  ca1b21:	41 be 0e 00 00 00                               	mov    r14d,0xe
  ca1b27:	e9 f0 06 00 00                                  	jmp    0xca221c
  ca1b2c:	48 25 ff fb ff ff                               	and    rax,0xfffffffffffffbff
  ca1b32:	4d 8b a5 78 05 00 00                            	mov    r12,QWORD PTR [r13+0x578]
  ca1b39:	4d 8b bd 80 05 00 00                            	mov    r15,QWORD PTR [r13+0x580]
  ca1b40:	31 f6                                           	xor    esi,esi
  ca1b42:	31 d2                                           	xor    edx,edx
  ca1b44:	31 c9                                           	xor    ecx,ecx
  ca1b46:	49 89 85 28 05 00 00                            	mov    QWORD PTR [r13+0x528],rax
  ca1b4d:	4d 03 75 08                                     	add    r14,QWORD PTR [r13+0x8]
  ca1b51:	4c 89 f7                                        	mov    rdi,r14
  ca1b54:	e8 47 54 82 ff                                  	call   0x4c6fa0
  ca1b59:	4d 85 e4                                        	test   r12,r12
  ca1b5c:	0f 84 ba 03 00 00                               	je     0xca1f1c
  ca1b62:	4c 8b b5 18 ff ff ff                            	mov    r14,QWORD PTR [rbp-0xe8]
  ca1b69:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  ca1b72:	48 8d 35 1e d7 6a 00                            	lea    rsi,[rip+0x6ad71e]        # 0x134f297
  ca1b79:	31 d2                                           	xor    edx,edx
  ca1b7b:	e8 60 88 f7 ff                                  	call   0xc1a3e0
  ca1b80:	ba 80 04 00 00                                  	mov    edx,0x480
  ca1b85:	4c 89 e7                                        	mov    rdi,r12
  ca1b88:	4c 89 f6                                        	mov    rsi,r14
  ca1b8b:	e8 40 76 5b ff                                  	call   0x2591d0
  ca1b90:	48 8d 35 79 22 f6 01                            	lea    rsi,[rip+0x1f62279]        # 0x2c03e10
  ca1b97:	4c 89 e7                                        	mov    rdi,r12
  ca1b9a:	41 89 c6                                        	mov    r14d,eax
  ca1b9d:	e8 4e 72 f6 ff                                  	call   0xc08df0
  ca1ba2:	49 c7 85 78 05 00 00 00 00 00 00                	mov    QWORD PTR [r13+0x578],0x0
  ca1bad:	e9 70 03 00 00                                  	jmp    0xca1f22
  ca1bb2:	45 31 e4                                        	xor    r12d,r12d
  ca1bb5:	45 31 f6                                        	xor    r14d,r14d
  ca1bb8:	48 81 c7 48 01 00 00                            	add    rdi,0x148
  ca1bbf:	31 db                                           	xor    ebx,ebx
  ca1bc1:	31 f6                                           	xor    esi,esi
  ca1bc3:	31 d2                                           	xor    edx,edx
  ca1bc5:	31 c9                                           	xor    ecx,ecx
  ca1bc7:	e8 d4 53 82 ff                                  	call   0x4c6fa0
  ca1bcc:	44 89 f7                                        	mov    edi,r14d
  ca1bcf:	be ff ff ff ff                                  	mov    esi,0xffffffff
  ca1bd4:	e8 47 08 ef ff                                  	call   0xb92420
  ca1bd9:	48 85 c0                                        	test   rax,rax
  ca1bdc:	74 2e                                           	je     0xca1c0c
  ca1bde:	48 8b 88 f8 03 00 00                            	mov    rcx,QWORD PTR [rax+0x3f8]
  ca1be5:	bf 48 01 00 00                                  	mov    edi,0x148
  ca1bea:	48 03 78 08                                     	add    rdi,QWORD PTR [rax+0x8]
  ca1bee:	31 f6                                           	xor    esi,esi
  ca1bf0:	31 d2                                           	xor    edx,edx
  ca1bf2:	48 8b 59 40                                     	mov    rbx,QWORD PTR [rcx+0x40]
  ca1bf6:	31 c9                                           	xor    ecx,ecx
  ca1bf8:	e8 a3 53 82 ff                                  	call   0x4c6fa0
  ca1bfd:	48 83 c3 10                                     	add    rbx,0x10
  ca1c01:	48 89 df                                        	mov    rdi,rbx
  ca1c04:	e8 77 0e ae ff                                  	call   0x782a80
  ca1c09:	48 89 c3                                        	mov    rbx,rax
  ca1c0c:	4c 8d b5 10 ff ff ff                            	lea    r14,[rbp-0xf0]
  ca1c13:	be 70 00 00 00                                  	mov    esi,0x70
  ca1c18:	4c 89 f7                                        	mov    rdi,r14
  ca1c1b:	e8 d0 73 5b ff                                  	call   0x258ff0
  ca1c20:	48 89 9d 10 ff ff ff                            	mov    QWORD PTR [rbp-0xf0],rbx
  ca1c27:	4c 89 a5 18 ff ff ff                            	mov    QWORD PTR [rbp-0xe8],r12
  ca1c2e:	48 8d 35 62 d6 6a 00                            	lea    rsi,[rip+0x6ad662]        # 0x134f297
  ca1c35:	31 d2                                           	xor    edx,edx
  ca1c37:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  ca1c40:	e8 9b 87 f7 ff                                  	call   0xc1a3e0
  ca1c45:	ba 70 00 00 00                                  	mov    edx,0x70
  ca1c4a:	4c 89 f7                                        	mov    rdi,r14
  ca1c4d:	4c 89 fe                                        	mov    rsi,r15
  ca1c50:	e8 7b 75 5b ff                                  	call   0x2591d0
  ca1c55:	41 89 c6                                        	mov    r14d,eax
  ca1c58:	4d 89 e9                                        	mov    r9,r13
  ca1c5b:	e9 bc 05 00 00                                  	jmp    0xca221c
  ca1c60:	48 8b bd f0 fe ff ff                            	mov    rdi,QWORD PTR [rbp-0x110]
  ca1c67:	48 8d 35 a2 21 f6 01                            	lea    rsi,[rip+0x1f621a2]        # 0x2c03e10
  ca1c6e:	ba 02 01 00 00                                  	mov    edx,0x102
  ca1c73:	e8 d8 6e f6 ff                                  	call   0xc08b50
  ca1c78:	48 8b 95 f0 fe ff ff                            	mov    rdx,QWORD PTR [rbp-0x110]
  ca1c7f:	48 89 c7                                        	mov    rdi,rax
  ca1c82:	4c 89 e6                                        	mov    rsi,r12
  ca1c85:	48 89 85 e0 fe ff ff                            	mov    QWORD PTR [rbp-0x120],rax
  ca1c8c:	e8 1f 74 5b ff                                  	call   0x2590b0
  ca1c91:	48 8d 35 e8 a3 f5 01                            	lea    rsi,[rip+0x1f5a3e8]        # 0x2bfc080
  ca1c98:	4c 89 e7                                        	mov    rdi,r12
  ca1c9b:	e8 50 71 f6 ff                                  	call   0xc08df0
  ca1ca0:	48 83 fb 01                                     	cmp    rbx,0x1
  ca1ca4:	4c 89 ef                                        	mov    rdi,r13
  ca1ca7:	0f 95 c3                                        	setne  bl
  ca1caa:	e8 11 93 ff ff                                  	call   0xc9afc0
  ca1caf:	4d 8d a5 48 01 00 00                            	lea    r12,[r13+0x148]
  ca1cb6:	31 f6                                           	xor    esi,esi
  ca1cb8:	31 d2                                           	xor    edx,edx
  ca1cba:	31 c9                                           	xor    ecx,ecx
  ca1cbc:	4c 89 e7                                        	mov    rdi,r12
  ca1cbf:	e8 3c 4d 82 ff                                  	call   0x4c6a00
  ca1cc4:	49 8b 85 68 05 00 00                            	mov    rax,QWORD PTR [r13+0x568]
  ca1ccb:	ba 16 00 00 00                                  	mov    edx,0x16
  ca1cd0:	41 be 0c 00 00 00                               	mov    r14d,0xc
  ca1cd6:	48 85 c0                                        	test   rax,rax
  ca1cd9:	0f 94 c1                                        	sete   cl
  ca1cdc:	44 0f 45 f2                                     	cmovne r14d,edx
  ca1ce0:	08 d9                                           	or     cl,bl
  ca1ce2:	0f 85 b7 02 00 00                               	jne    0xca1f9f
  ca1ce8:	49 ff cf                                        	dec    r15
  ca1ceb:	41 be 16 00 00 00                               	mov    r14d,0x16
  ca1cf1:	49 83 ff 03                                     	cmp    r15,0x3
  ca1cf5:	0f 87 a4 02 00 00                               	ja     0xca1f9f
  ca1cfb:	48 8d 0d fe f4 da 00                            	lea    rcx,[rip+0xdaf4fe]        # 0x1a51200
  ca1d02:	4a 63 14 b9                                     	movsxd rdx,DWORD PTR [rcx+r15*4]
  ca1d06:	48 01 ca                                        	add    rdx,rcx
  ca1d09:	ff e2                                           	jmp    rdx
  ca1d0b:	83 b8 70 01 00 00 00                            	cmp    DWORD PTR [rax+0x170],0x0
  ca1d12:	41 be 01 00 00 00                               	mov    r14d,0x1
  ca1d18:	0f 85 81 02 00 00                               	jne    0xca1f9f
  ca1d1e:	48 8b 8d e8 fe ff ff                            	mov    rcx,QWORD PTR [rbp-0x118]
  ca1d25:	8b 89 9c 00 00 00                               	mov    ecx,DWORD PTR [rcx+0x9c]
  ca1d2b:	89 88 70 01 00 00                               	mov    DWORD PTR [rax+0x170],ecx
  ca1d31:	e9 2a 05 00 00                                  	jmp    0xca2260
  ca1d36:	49 8b 7d 08                                     	mov    rdi,QWORD PTR [r13+0x8]
  ca1d3a:	41 bf 48 01 00 00                               	mov    r15d,0x148
  ca1d40:	31 f6                                           	xor    esi,esi
  ca1d42:	31 d2                                           	xor    edx,edx
  ca1d44:	31 c9                                           	xor    ecx,ecx
  ca1d46:	4c 01 ff                                        	add    rdi,r15
  ca1d49:	e8 b2 4c 82 ff                                  	call   0x4c6a00
  ca1d4e:	8b 85 10 ff ff ff                               	mov    eax,DWORD PTR [rbp-0xf0]
  ca1d54:	49 8b 4d 08                                     	mov    rcx,QWORD PTR [r13+0x8]
  ca1d58:	31 f6                                           	xor    esi,esi
  ca1d5a:	31 d2                                           	xor    edx,edx
  ca1d5c:	89 81 6c 03 00 00                               	mov    DWORD PTR [rcx+0x36c],eax
  ca1d62:	48 c1 e0 20                                     	shl    rax,0x20
  ca1d66:	49 8b 8d 28 05 00 00                            	mov    rcx,QWORD PTR [r13+0x528]
  ca1d6d:	81 e1 ff fb ff fe                               	and    ecx,0xfefffbff
  ca1d73:	48 8d 84 01 00 04 00 00                         	lea    rax,[rcx+rax*1+0x400]
  ca1d7b:	31 c9                                           	xor    ecx,ecx
  ca1d7d:	49 89 85 28 05 00 00                            	mov    QWORD PTR [r13+0x528],rax
  ca1d84:	4d 89 b5 78 05 00 00                            	mov    QWORD PTR [r13+0x578],r14
  ca1d8b:	49 c7 85 80 05 00 00 00 00 00 00                	mov    QWORD PTR [r13+0x580],0x0
  ca1d96:	49 c7 85 88 05 00 00 00 00 00 00                	mov    QWORD PTR [r13+0x588],0x0
  ca1da1:	49 c7 85 90 05 00 00 00 00 00 00                	mov    QWORD PTR [r13+0x590],0x0
  ca1dac:	4d 03 7d 08                                     	add    r15,QWORD PTR [r13+0x8]
  ca1db0:	4c 89 ff                                        	mov    rdi,r15
  ca1db3:	e8 e8 51 82 ff                                  	call   0x4c6fa0
  ca1db8:	4c 89 ef                                        	mov    rdi,r13
  ca1dbb:	48 63 b5 10 ff ff ff                            	movsxd rsi,DWORD PTR [rbp-0xf0]
  ca1dc2:	e8 59 dc ff ff                                  	call   0xc9fa20
  ca1dc7:	41 89 c6                                        	mov    r14d,eax
  ca1dca:	49 89 d9                                        	mov    r9,rbx
  ca1dcd:	e9 4a 04 00 00                                  	jmp    0xca221c
  ca1dd2:	4c 89 ff                                        	mov    rdi,r15
  ca1dd5:	48 89 98 f0 00 00 00                            	mov    QWORD PTR [rax+0xf0],rbx
  ca1ddc:	31 f6                                           	xor    esi,esi
  ca1dde:	31 d2                                           	xor    edx,edx
  ca1de0:	31 c9                                           	xor    ecx,ecx
  ca1de2:	e8 b9 51 82 ff                                  	call   0x4c6fa0
  ca1de7:	48 8d 3d 71 78 6b 00                            	lea    rdi,[rip+0x6b7871]        # 0x135965f
  ca1dee:	ba 10 00 00 00                                  	mov    edx,0x10
  ca1df3:	4c 89 f6                                        	mov    rsi,r14
  ca1df6:	e8 35 fc c2 ff                                  	call   0x8d1a30
  ca1dfb:	85 c0                                           	test   eax,eax
  ca1dfd:	0f 84 e7 00 00 00                               	je     0xca1eea
  ca1e03:	48 8d 3d 1c 0e 6e 00                            	lea    rdi,[rip+0x6e0e1c]        # 0x1382c26
  ca1e0a:	ba 10 00 00 00                                  	mov    edx,0x10
  ca1e0f:	4c 89 f6                                        	mov    rsi,r14
  ca1e12:	e8 19 fc c2 ff                                  	call   0x8d1a30
  ca1e17:	85 c0                                           	test   eax,eax
  ca1e19:	0f 84 d5 00 00 00                               	je     0xca1ef4
  ca1e1f:	48 8d 3d 83 33 68 00                            	lea    rdi,[rip+0x683383]        # 0x13251a9
  ca1e26:	ba 10 00 00 00                                  	mov    edx,0x10
  ca1e2b:	4c 89 f6                                        	mov    rsi,r14
  ca1e2e:	e8 fd fb c2 ff                                  	call   0x8d1a30
  ca1e33:	85 c0                                           	test   eax,eax
  ca1e35:	0f 84 c3 00 00 00                               	je     0xca1efe
  ca1e3b:	48 8d 3d 1f 33 66 00                            	lea    rdi,[rip+0x66331f]        # 0x1305161
  ca1e42:	ba 17 00 00 00                                  	mov    edx,0x17
  ca1e47:	4c 89 f6                                        	mov    rsi,r14
  ca1e4a:	e8 e1 fb c2 ff                                  	call   0x8d1a30
  ca1e4f:	85 c0                                           	test   eax,eax
  ca1e51:	0f 84 b1 00 00 00                               	je     0xca1f08
  ca1e57:	48 8d 3d 2d a2 63 00                            	lea    rdi,[rip+0x63a22d]        # 0x12dc08b
  ca1e5e:	ba 0e 00 00 00                                  	mov    edx,0xe
  ca1e63:	4c 89 f6                                        	mov    rsi,r14
  ca1e66:	e8 c5 fb c2 ff                                  	call   0x8d1a30
  ca1e6b:	85 c0                                           	test   eax,eax
  ca1e6d:	0f 84 9f 00 00 00                               	je     0xca1f12
  ca1e73:	48 8d 3d 35 23 6c 00                            	lea    rdi,[rip+0x6c2335]        # 0x13641af
  ca1e7a:	ba 0e 00 00 00                                  	mov    edx,0xe
  ca1e7f:	4c 89 f6                                        	mov    rsi,r14
  ca1e82:	e8 a9 fb c2 ff                                  	call   0x8d1a30
  ca1e87:	85 c0                                           	test   eax,eax
  ca1e89:	0f 84 c3 00 00 00                               	je     0xca1f52
  ca1e8f:	48 8d 3d 23 33 68 00                            	lea    rdi,[rip+0x683323]        # 0x13251b9
  ca1e96:	ba 0e 00 00 00                                  	mov    edx,0xe
  ca1e9b:	4c 89 f6                                        	mov    rsi,r14
  ca1e9e:	e8 8d fb c2 ff                                  	call   0x8d1a30
  ca1ea3:	85 c0                                           	test   eax,eax
  ca1ea5:	0f 84 44 01 00 00                               	je     0xca1fef
  ca1eab:	48 8d 3d e4 4f 62 00                            	lea    rdi,[rip+0x624fe4]        # 0x12c6e96
  ca1eb2:	ba 0e 00 00 00                                  	mov    edx,0xe
  ca1eb7:	4c 89 f6                                        	mov    rsi,r14
  ca1eba:	e8 71 fb c2 ff                                  	call   0x8d1a30
  ca1ebf:	85 c0                                           	test   eax,eax
  ca1ec1:	0f 84 2f 01 00 00                               	je     0xca1ff6
  ca1ec7:	48 8d 3d 78 67 6d 00                            	lea    rdi,[rip+0x6d6778]        # 0x1378646
  ca1ece:	ba 16 00 00 00                                  	mov    edx,0x16
  ca1ed3:	4c 89 f6                                        	mov    rsi,r14
  ca1ed6:	e8 55 fb c2 ff                                  	call   0x8d1a30
  ca1edb:	31 c9                                           	xor    ecx,ecx
  ca1edd:	85 c0                                           	test   eax,eax
  ca1edf:	0f 94 c1                                        	sete   cl
  ca1ee2:	8d 1c c9                                        	lea    ebx,[rcx+rcx*8]
  ca1ee5:	e9 11 01 00 00                                  	jmp    0xca1ffb
  ca1eea:	bb 01 00 00 00                                  	mov    ebx,0x1
  ca1eef:	e9 07 01 00 00                                  	jmp    0xca1ffb
  ca1ef4:	bb 02 00 00 00                                  	mov    ebx,0x2
  ca1ef9:	e9 fd 00 00 00                                  	jmp    0xca1ffb
  ca1efe:	bb 03 00 00 00                                  	mov    ebx,0x3
  ca1f03:	e9 f3 00 00 00                                  	jmp    0xca1ffb
  ca1f08:	bb 04 00 00 00                                  	mov    ebx,0x4
  ca1f0d:	e9 e9 00 00 00                                  	jmp    0xca1ffb
  ca1f12:	bb 05 00 00 00                                  	mov    ebx,0x5
  ca1f17:	e9 df 00 00 00                                  	jmp    0xca1ffb
  ca1f1c:	41 be 02 00 00 00                               	mov    r14d,0x2
  ca1f22:	4d 85 ff                                        	test   r15,r15
  ca1f25:	0f 84 1d f9 ff ff                               	je     0xca1848
  ca1f2b:	48 8d 35 de 1e f6 01                            	lea    rsi,[rip+0x1f61ede]        # 0x2c03e10
  ca1f32:	4c 89 ff                                        	mov    rdi,r15
  ca1f35:	e8 b6 6e f6 ff                                  	call   0xc08df0
  ca1f3a:	49 c7 85 80 05 00 00 00 00 00 00                	mov    QWORD PTR [r13+0x580],0x0
  ca1f45:	41 80 a5 2b 05 00 00 fd                         	and    BYTE PTR [r13+0x52b],0xfd
  ca1f4d:	e9 f6 f8 ff ff                                  	jmp    0xca1848
  ca1f52:	bb 06 00 00 00                                  	mov    ebx,0x6
  ca1f57:	e9 9f 00 00 00                                  	jmp    0xca1ffb
  ca1f5c:	48 83 b8 88 01 00 00 00                         	cmp    QWORD PTR [rax+0x188],0x0
  ca1f64:	41 be 01 00 00 00                               	mov    r14d,0x1
  ca1f6a:	75 33                                           	jne    0xca1f9f
  ca1f6c:	48 8b 8d e0 fe ff ff                            	mov    rcx,QWORD PTR [rbp-0x120]
  ca1f73:	48 89 88 88 01 00 00                            	mov    QWORD PTR [rax+0x188],rcx
  ca1f7a:	8b 8d f0 fe ff ff                               	mov    ecx,DWORD PTR [rbp-0x110]
  ca1f80:	89 88 68 01 00 00                               	mov    DWORD PTR [rax+0x168],ecx
  ca1f86:	e9 d5 02 00 00                                  	jmp    0xca2260
  ca1f8b:	48 83 b8 90 01 00 00 00                         	cmp    QWORD PTR [rax+0x190],0x0
  ca1f93:	41 be 01 00 00 00                               	mov    r14d,0x1
  ca1f99:	0f 84 a7 02 00 00                               	je     0xca2246
  ca1f9f:	4c 89 e7                                        	mov    rdi,r12
  ca1fa2:	31 f6                                           	xor    esi,esi
  ca1fa4:	31 d2                                           	xor    edx,edx
  ca1fa6:	31 c9                                           	xor    ecx,ecx
  ca1fa8:	e8 f3 4f 82 ff                                  	call   0x4c6fa0
  ca1fad:	48 8b bd e0 fe ff ff                            	mov    rdi,QWORD PTR [rbp-0x120]
  ca1fb4:	48 85 ff                                        	test   rdi,rdi
  ca1fb7:	0f 84 58 02 00 00                               	je     0xca2215
  ca1fbd:	48 8d 35 4c 1e f6 01                            	lea    rsi,[rip+0x1f61e4c]        # 0x2c03e10
  ca1fc4:	e8 27 6e f6 ff                                  	call   0xc08df0
  ca1fc9:	e9 47 02 00 00                                  	jmp    0xca2215
  ca1fce:	48 8b 8d 20 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xe0]
  ca1fd5:	48 8b 95 28 ff ff ff                            	mov    rdx,QWORD PTR [rbp-0xd8]
  ca1fdc:	48 89 88 80 01 00 00                            	mov    QWORD PTR [rax+0x180],rcx
  ca1fe3:	48 89 90 78 01 00 00                            	mov    QWORD PTR [rax+0x178],rdx
  ca1fea:	e9 71 02 00 00                                  	jmp    0xca2260
  ca1fef:	bb 07 00 00 00                                  	mov    ebx,0x7
  ca1ff4:	eb 05                                           	jmp    0xca1ffb
  ca1ff6:	bb 08 00 00 00                                  	mov    ebx,0x8
  ca1ffb:	49 8b 7d 08                                     	mov    rdi,QWORD PTR [r13+0x8]
  ca1fff:	41 bf 48 01 00 00                               	mov    r15d,0x148
  ca2005:	31 f6                                           	xor    esi,esi
  ca2007:	31 d2                                           	xor    edx,edx
  ca2009:	31 c9                                           	xor    ecx,ecx
  ca200b:	4c 01 ff                                        	add    rdi,r15
  ca200e:	e8 ed 49 82 ff                                  	call   0x4c6a00
  ca2013:	49 8b 45 08                                     	mov    rax,QWORD PTR [r13+0x8]
  ca2017:	41 be 03 00 00 00                               	mov    r14d,0x3
  ca201d:	48 8b 80 68 05 00 00                            	mov    rax,QWORD PTR [rax+0x568]
  ca2024:	48 85 c0                                        	test   rax,rax
  ca2027:	0f 84 d6 01 00 00                               	je     0xca2203
  ca202d:	48 8b 80 f0 00 00 00                            	mov    rax,QWORD PTR [rax+0xf0]
  ca2034:	48 85 c0                                        	test   rax,rax
  ca2037:	0f 84 c6 01 00 00                               	je     0xca2203
  ca203d:	ff cb                                           	dec    ebx
  ca203f:	83 fb 08                                        	cmp    ebx,0x8
  ca2042:	0f 87 f6 01 00 00                               	ja     0xca223e
  ca2048:	48 8d 0d c1 f1 da 00                            	lea    rcx,[rip+0xdaf1c1]        # 0x1a51210
  ca204f:	48 63 14 99                                     	movsxd rdx,DWORD PTR [rcx+rbx*4]
  ca2053:	48 01 ca                                        	add    rdx,rcx
  ca2056:	ff e2                                           	jmp    rdx
  ca2058:	80 88 d4 00 00 00 02                            	or     BYTE PTR [rax+0xd4],0x2
  ca205f:	48 8b 8d 18 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xe8]
  ca2066:	48 89 08                                        	mov    QWORD PTR [rax],rcx
  ca2069:	48 8b 8d 20 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xe0]
  ca2070:	48 89 48 08                                     	mov    QWORD PTR [rax+0x8],rcx
  ca2074:	48 8b 8d 28 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xd8]
  ca207b:	48 89 48 10                                     	mov    QWORD PTR [rax+0x10],rcx
  ca207f:	48 8b 8d 30 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xd0]
  ca2086:	48 89 48 18                                     	mov    QWORD PTR [rax+0x18],rcx
  ca208a:	e9 71 01 00 00                                  	jmp    0xca2200
  ca208f:	80 88 d4 00 00 00 20                            	or     BYTE PTR [rax+0xd4],0x20
  ca2096:	48 8b 8d 18 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xe8]
  ca209d:	48 89 48 60                                     	mov    QWORD PTR [rax+0x60],rcx
  ca20a1:	48 8b 8d 20 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xe0]
  ca20a8:	48 89 48 68                                     	mov    QWORD PTR [rax+0x68],rcx
  ca20ac:	e9 4f 01 00 00                                  	jmp    0xca2200
  ca20b1:	80 88 d4 00 00 00 08                            	or     BYTE PTR [rax+0xd4],0x8
  ca20b8:	48 8b 8d 18 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xe8]
  ca20bf:	48 89 48 30                                     	mov    QWORD PTR [rax+0x30],rcx
  ca20c3:	48 8b 8d 20 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xe0]
  ca20ca:	48 89 48 38                                     	mov    QWORD PTR [rax+0x38],rcx
  ca20ce:	48 8b 8d 28 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xd8]
  ca20d5:	48 89 48 40                                     	mov    QWORD PTR [rax+0x40],rcx
  ca20d9:	48 8b 8d 30 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xd0]
  ca20e0:	48 89 48 48                                     	mov    QWORD PTR [rax+0x48],rcx
  ca20e4:	e9 17 01 00 00                                  	jmp    0xca2200
  ca20e9:	80 88 d4 00 00 00 10                            	or     BYTE PTR [rax+0xd4],0x10
  ca20f0:	48 8b 8d 18 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xe8]
  ca20f7:	48 89 48 50                                     	mov    QWORD PTR [rax+0x50],rcx
  ca20fb:	48 8b 8d 20 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xe0]
  ca2102:	48 89 48 58                                     	mov    QWORD PTR [rax+0x58],rcx
  ca2106:	e9 f5 00 00 00                                  	jmp    0xca2200
  ca210b:	80 88 d5 00 00 00 01                            	or     BYTE PTR [rax+0xd5],0x1
  ca2112:	48 8b 8d 18 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xe8]
  ca2119:	48 89 88 b0 00 00 00                            	mov    QWORD PTR [rax+0xb0],rcx
  ca2120:	48 8b 8d 20 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xe0]
  ca2127:	48 89 88 b8 00 00 00                            	mov    QWORD PTR [rax+0xb8],rcx
  ca212e:	48 8b 8d 28 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xd8]
  ca2135:	48 89 88 c0 00 00 00                            	mov    QWORD PTR [rax+0xc0],rcx
  ca213c:	48 8b 8d 30 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xd0]
  ca2143:	48 89 88 c8 00 00 00                            	mov    QWORD PTR [rax+0xc8],rcx
  ca214a:	e9 b1 00 00 00                                  	jmp    0xca2200
  ca214f:	80 88 d4 00 00 00 04                            	or     BYTE PTR [rax+0xd4],0x4
  ca2156:	48 8b 8d 18 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xe8]
  ca215d:	48 89 48 20                                     	mov    QWORD PTR [rax+0x20],rcx
  ca2161:	48 8b 8d 20 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xe0]
  ca2168:	48 89 48 28                                     	mov    QWORD PTR [rax+0x28],rcx
  ca216c:	e9 8f 00 00 00                                  	jmp    0xca2200
  ca2171:	80 88 d4 00 00 00 40                            	or     BYTE PTR [rax+0xd4],0x40
  ca2178:	48 8b 8d 18 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xe8]
  ca217f:	48 89 48 70                                     	mov    QWORD PTR [rax+0x70],rcx
  ca2183:	48 8b 8d 20 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xe0]
  ca218a:	48 89 48 78                                     	mov    QWORD PTR [rax+0x78],rcx
  ca218e:	48 8b 8d 28 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xd8]
  ca2195:	48 89 88 80 00 00 00                            	mov    QWORD PTR [rax+0x80],rcx
  ca219c:	48 8b 8d 30 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xd0]
  ca21a3:	48 89 88 88 00 00 00                            	mov    QWORD PTR [rax+0x88],rcx
  ca21aa:	eb 54                                           	jmp    0xca2200
  ca21ac:	80 88 d4 00 00 00 80                            	or     BYTE PTR [rax+0xd4],0x80
  ca21b3:	48 8b 8d 18 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xe8]
  ca21ba:	48 89 88 90 00 00 00                            	mov    QWORD PTR [rax+0x90],rcx
  ca21c1:	48 8b 8d 20 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xe0]
  ca21c8:	48 89 88 98 00 00 00                            	mov    QWORD PTR [rax+0x98],rcx
  ca21cf:	48 8b 8d 28 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xd8]
  ca21d6:	48 89 88 a0 00 00 00                            	mov    QWORD PTR [rax+0xa0],rcx
  ca21dd:	48 8b 8d 30 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xd0]
  ca21e4:	48 89 88 a8 00 00 00                            	mov    QWORD PTR [rax+0xa8],rcx
  ca21eb:	eb 13                                           	jmp    0xca2200
  ca21ed:	80 88 d5 00 00 00 02                            	or     BYTE PTR [rax+0xd5],0x2
  ca21f4:	8b 8d 18 ff ff ff                               	mov    ecx,DWORD PTR [rbp-0xe8]
  ca21fa:	89 88 d0 00 00 00                               	mov    DWORD PTR [rax+0xd0],ecx
  ca2200:	45 31 f6                                        	xor    r14d,r14d
  ca2203:	4d 03 7d 08                                     	add    r15,QWORD PTR [r13+0x8]
  ca2207:	4c 89 ff                                        	mov    rdi,r15
  ca220a:	31 f6                                           	xor    esi,esi
  ca220c:	31 d2                                           	xor    edx,edx
  ca220e:	31 c9                                           	xor    ecx,ecx
  ca2210:	e8 8b 4d 82 ff                                  	call   0x4c6fa0
  ca2215:	4c 8d 0d f4 a0 c7 02                            	lea    r9,[rip+0x2c7a0f4]        # 0x391c310
  ca221c:	49 8b 01                                        	mov    rax,QWORD PTR [r9]
  ca221f:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  ca2223:	0f 85 e1 00 00 00                               	jne    0xca230a
  ca2229:	44 89 f0                                        	mov    eax,r14d
  ca222c:	48 81 c4 f8 00 00 00                            	add    rsp,0xf8
  ca2233:	5b                                              	pop    rbx
  ca2234:	41 5c                                           	pop    r12
  ca2236:	41 5d                                           	pop    r13
  ca2238:	41 5e                                           	pop    r14
  ca223a:	41 5f                                           	pop    r15
  ca223c:	5d                                              	pop    rbp
  ca223d:	c3                                              	ret
  ca223e:	41 be 16 00 00 00                               	mov    r14d,0x16
  ca2244:	eb bd                                           	jmp    0xca2203
  ca2246:	48 8b 8d e0 fe ff ff                            	mov    rcx,QWORD PTR [rbp-0x120]
  ca224d:	48 89 88 90 01 00 00                            	mov    QWORD PTR [rax+0x190],rcx
  ca2254:	8b 8d f0 fe ff ff                               	mov    ecx,DWORD PTR [rbp-0x110]
  ca225a:	89 88 6c 01 00 00                               	mov    DWORD PTR [rax+0x16c],ecx
  ca2260:	45 31 f6                                        	xor    r14d,r14d
  ca2263:	4c 89 e7                                        	mov    rdi,r12
  ca2266:	eb a2                                           	jmp    0xca220a
  ca2268:	49 8b 7c 24 08                                  	mov    rdi,QWORD PTR [r12+0x8]
  ca226d:	41 be 48 01 00 00                               	mov    r14d,0x148
  ca2273:	31 f6                                           	xor    esi,esi
  ca2275:	31 d2                                           	xor    edx,edx
  ca2277:	31 c9                                           	xor    ecx,ecx
  ca2279:	4c 01 f7                                        	add    rdi,r14
  ca227c:	e8 7f 47 82 ff                                  	call   0x4c6a00
  ca2281:	8b 85 f0 fe ff ff                               	mov    eax,DWORD PTR [rbp-0x110]
  ca2287:	49 8b 4c 24 08                                  	mov    rcx,QWORD PTR [r12+0x8]
  ca228c:	48 8b bd e8 fe ff ff                            	mov    rdi,QWORD PTR [rbp-0x118]
  ca2293:	31 f6                                           	xor    esi,esi
  ca2295:	31 d2                                           	xor    edx,edx
  ca2297:	89 81 6c 03 00 00                               	mov    DWORD PTR [rcx+0x36c],eax
  ca229d:	48 c1 e0 20                                     	shl    rax,0x20
  ca22a1:	49 8b 8c 24 28 05 00 00                         	mov    rcx,QWORD PTR [r12+0x528]
  ca22a9:	81 e1 ff fb ff fc                               	and    ecx,0xfcfffbff
  ca22af:	48 8d 84 01 00 04 00 02                         	lea    rax,[rcx+rax*1+0x2000400]
  ca22b7:	31 c9                                           	xor    ecx,ecx
  ca22b9:	49 89 84 24 28 05 00 00                         	mov    QWORD PTR [r12+0x528],rax
  ca22c1:	4d 89 bc 24 78 05 00 00                         	mov    QWORD PTR [r12+0x578],r15
  ca22c9:	49 89 bc 24 80 05 00 00                         	mov    QWORD PTR [r12+0x580],rdi
  ca22d1:	49 c7 84 24 88 05 00 00 00 00 00 00             	mov    QWORD PTR [r12+0x588],0x0
  ca22dd:	49 c7 84 24 90 05 00 00 00 00 00 00             	mov    QWORD PTR [r12+0x590],0x0
  ca22e9:	4d 03 74 24 08                                  	add    r14,QWORD PTR [r12+0x8]
  ca22ee:	4c 89 f7                                        	mov    rdi,r14
  ca22f1:	e8 aa 4c 82 ff                                  	call   0x4c6fa0
  ca22f6:	48 63 b5 f0 fe ff ff                            	movsxd rsi,DWORD PTR [rbp-0x110]
  ca22fd:	4c 89 e7                                        	mov    rdi,r12
  ca2300:	e8 1b d7 ff ff                                  	call   0xc9fa20
  ca2305:	e9 4b f9 ff ff                                  	jmp    0xca1c55
  ca230a:	e8 a1 b3 a5 ff                                  	call   0x6fd6b0
  ca230f:	0f 0b                                           	ud2
  ca2311:	90                                              	nop
  ca2312:	90                                              	nop
  ca2313:	90                                              	nop
  ca2314:	90                                              	nop
  ca2315:	90                                              	nop
  ca2316:	90                                              	nop
  ca2317:	90                                              	nop
  ca2318:	90                                              	nop
  ca2319:	90                                              	nop
  ca231a:	90                                              	nop
  ca231b:	90                                              	nop
  ca231c:	90                                              	nop
  ca231d:	90                                              	nop
  ca231e:	90                                              	nop
  ca231f:	90                                              	nop
  ca2320:	55                                              	push   rbp
  ca2321:	48 89 e5                                        	mov    rbp,rsp
  ca2324:	41 57                                           	push   r15
  ca2326:	41 56                                           	push   r14
  ca2328:	41 55                                           	push   r13
  ca232a:	41 54                                           	push   r12
  ca232c:	53                                              	push   rbx
  ca232d:	48 81 ec 88 00 00 00                            	sub    rsp,0x88
  ca2334:	4c 8d 25 d5 9f c7 02                            	lea    r12,[rip+0x2c79fd5]        # 0x391c310
  ca233b:	49 89 fe                                        	mov    r14,rdi
  ca233e:	49 89 f7                                        	mov    r15,rsi
  ca2341:	48 8d 35 f5 5b 6f 00                            	lea    rsi,[rip+0x6f5bf5]        # 0x1397f3d
  ca2348:	48 89 d3                                        	mov    rbx,rdx
  ca234b:	31 d2                                           	xor    edx,edx
  ca234d:	49 8b 04 24                                     	mov    rax,QWORD PTR [r12]
  ca2351:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  ca2355:	48 c7 45 c8 00 00 00 00                         	mov    QWORD PTR [rbp-0x38],0x0
  ca235d:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  ca2366:	e8 75 80 f7 ff                                  	call   0xc1a3e0
  ca236b:	48 8d 75 8c                                     	lea    rsi,[rbp-0x74]
  ca236f:	ba 3c 00 00 00                                  	mov    edx,0x3c
  ca2374:	4c 89 ff                                        	mov    rdi,r15
  ca2377:	e8 04 6f 5b ff                                  	call   0x259280
  ca237c:	41 89 c7                                        	mov    r15d,eax
  ca237f:	85 c0                                           	test   eax,eax
  ca2381:	74 23                                           	je     0xca23a6
  ca2383:	49 8b 04 24                                     	mov    rax,QWORD PTR [r12]
  ca2387:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  ca238b:	0f 85 87 0a 00 00                               	jne    0xca2e18
  ca2391:	44 89 f8                                        	mov    eax,r15d
  ca2394:	48 81 c4 88 00 00 00                            	add    rsp,0x88
  ca239b:	5b                                              	pop    rbx
  ca239c:	41 5c                                           	pop    r12
  ca239e:	41 5d                                           	pop    r13
  ca23a0:	41 5e                                           	pop    r14
  ca23a2:	41 5f                                           	pop    r15
  ca23a4:	5d                                              	pop    rbp
  ca23a5:	c3                                              	ret
  ca23a6:	49 8b 86 28 05 00 00                            	mov    rax,QWORD PTR [r14+0x528]
  ca23ad:	48 89 85 50 ff ff ff                            	mov    QWORD PTR [rbp-0xb0],rax
  ca23b4:	a9 00 01 00 00                                  	test   eax,0x100
  ca23b9:	0f 85 71 01 00 00                               	jne    0xca2530
  ca23bf:	8b 45 b0                                        	mov    eax,DWORD PTR [rbp-0x50]
  ca23c2:	41 bf 01 00 00 00                               	mov    r15d,0x1
  ca23c8:	83 f8 07                                        	cmp    eax,0x7
  ca23cb:	77 b6                                           	ja     0xca2383
  ca23cd:	b9 b8 00 00 00                                  	mov    ecx,0xb8
  ca23d2:	0f a3 c1                                        	bt     ecx,eax
  ca23d5:	73 ac                                           	jae    0xca2383
  ca23d7:	83 e0 fe                                        	and    eax,0xfffffffe
  ca23da:	83 f8 04                                        	cmp    eax,0x4
  ca23dd:	0f 85 4d 01 00 00                               	jne    0xca2530
  ca23e3:	83 7d a0 00                                     	cmp    DWORD PTR [rbp-0x60],0x0
  ca23e7:	0f 85 43 01 00 00                               	jne    0xca2530
  ca23ed:	bf 48 01 00 00                                  	mov    edi,0x148
  ca23f2:	49 03 7e 08                                     	add    rdi,QWORD PTR [r14+0x8]
  ca23f6:	31 f6                                           	xor    esi,esi
  ca23f8:	31 d2                                           	xor    edx,edx
  ca23fa:	31 c9                                           	xor    ecx,ecx
  ca23fc:	e8 ff 45 82 ff                                  	call   0x4c6a00
  ca2401:	49 8b 7e 08                                     	mov    rdi,QWORD PTR [r14+0x8]
  ca2405:	4c 8b a7 68 05 00 00                            	mov    r12,QWORD PTR [rdi+0x568]
  ca240c:	4d 85 e4                                        	test   r12,r12
  ca240f:	0f 84 a3 00 00 00                               	je     0xca24b8
  ca2415:	49 8d 7c 24 28                                  	lea    rdi,[r12+0x28]
  ca241a:	45 31 ff                                        	xor    r15d,r15d
  ca241d:	31 f6                                           	xor    esi,esi
  ca241f:	31 d2                                           	xor    edx,edx
  ca2421:	31 c9                                           	xor    ecx,ecx
  ca2423:	49 89 fd                                        	mov    r13,rdi
  ca2426:	e8 d5 45 82 ff                                  	call   0x4c6a00
  ca242b:	49 8b 44 24 40                                  	mov    rax,QWORD PTR [r12+0x40]
  ca2430:	48 85 c0                                        	test   rax,rax
  ca2433:	0f 84 9d 00 00 00                               	je     0xca24d6
  ca2439:	48 8b 55 98                                     	mov    rdx,QWORD PTR [rbp-0x68]
  ca243d:	8b 75 b0                                        	mov    esi,DWORD PTR [rbp-0x50]
  ca2440:	8b 7d 94                                        	mov    edi,DWORD PTR [rbp-0x6c]
  ca2443:	49 8d 4c 24 40                                  	lea    rcx,[r12+0x40]
  ca2448:	49 89 c0                                        	mov    r8,rax
  ca244b:	eb 08                                           	jmp    0xca2455
  ca244d:	0f 1f 00                                        	nop    DWORD PTR [rax]
  ca2450:	4d 85 c0                                        	test   r8,r8
  ca2453:	74 7e                                           	je     0xca24d3
  ca2455:	4d 89 c7                                        	mov    r15,r8
  ca2458:	4d 8b 00                                        	mov    r8,QWORD PTR [r8]
  ca245b:	49 39 57 14                                     	cmp    QWORD PTR [r15+0x14],rdx
  ca245f:	75 ef                                           	jne    0xca2450
  ca2461:	41 39 77 2c                                     	cmp    DWORD PTR [r15+0x2c],esi
  ca2465:	75 e9                                           	jne    0xca2450
  ca2467:	41 39 7f 10                                     	cmp    DWORD PTR [r15+0x10],edi
  ca246b:	75 e3                                           	jne    0xca2450
  ca246d:	4c 39 f8                                        	cmp    rax,r15
  ca2470:	0f 84 5e 04 00 00                               	je     0xca28d4
  ca2476:	48 89 c1                                        	mov    rcx,rax
  ca2479:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  ca247c:	4c 39 f8                                        	cmp    rax,r15
  ca247f:	75 f5                                           	jne    0xca2476
  ca2481:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  ca2484:	48 89 01                                        	mov    QWORD PTR [rcx],rax
  ca2487:	48 85 c0                                        	test   rax,rax
  ca248a:	75 05                                           	jne    0xca2491
  ca248c:	49 89 4c 24 48                                  	mov    QWORD PTR [r12+0x48],rcx
  ca2491:	41 8b 8c 24 f8 00 00 00                         	mov    ecx,DWORD PTR [r12+0xf8]
  ca2499:	49 8b 44 24 40                                  	mov    rax,QWORD PTR [r12+0x40]
  ca249e:	ff c9                                           	dec    ecx
  ca24a0:	41 89 8c 24 f8 00 00 00                         	mov    DWORD PTR [r12+0xf8],ecx
  ca24a8:	41 89 4c 24 30                                  	mov    DWORD PTR [r12+0x30],ecx
  ca24ad:	48 85 c0                                        	test   rax,rax
  ca24b0:	0f 85 40 04 00 00                               	jne    0xca28f6
  ca24b6:	eb 1e                                           	jmp    0xca24d6
  ca24b8:	48 81 c7 48 01 00 00                            	add    rdi,0x148
  ca24bf:	31 f6                                           	xor    esi,esi
  ca24c1:	31 d2                                           	xor    edx,edx
  ca24c3:	31 c9                                           	xor    ecx,ecx
  ca24c5:	e8 d6 4a 82 ff                                  	call   0x4c6fa0
  ca24ca:	4c 8d 25 3f 9e c7 02                            	lea    r12,[rip+0x2c79e3f]        # 0x391c310
  ca24d1:	eb 5d                                           	jmp    0xca2530
  ca24d3:	45 31 ff                                        	xor    r15d,r15d
  ca24d6:	4c 89 ef                                        	mov    rdi,r13
  ca24d9:	31 f6                                           	xor    esi,esi
  ca24db:	31 d2                                           	xor    edx,edx
  ca24dd:	31 c9                                           	xor    ecx,ecx
  ca24df:	e8 bc 4a 82 ff                                  	call   0x4c6fa0
  ca24e4:	bf 48 01 00 00                                  	mov    edi,0x148
  ca24e9:	49 03 7e 08                                     	add    rdi,QWORD PTR [r14+0x8]
  ca24ed:	31 f6                                           	xor    esi,esi
  ca24ef:	31 d2                                           	xor    edx,edx
  ca24f1:	31 c9                                           	xor    ecx,ecx
  ca24f3:	e8 a8 4a 82 ff                                  	call   0x4c6fa0
  ca24f8:	4c 8d 25 11 9e c7 02                            	lea    r12,[rip+0x2c79e11]        # 0x391c310
  ca24ff:	4d 85 ff                                        	test   r15,r15
  ca2502:	74 2c                                           	je     0xca2530
  ca2504:	49 8b 7f 48                                     	mov    rdi,QWORD PTR [r15+0x48]
  ca2508:	48 85 ff                                        	test   rdi,rdi
  ca250b:	74 0c                                           	je     0xca2519
  ca250d:	48 8d 35 6c 19 f6 01                            	lea    rsi,[rip+0x1f6196c]        # 0x2c03e80
  ca2514:	e8 d7 68 f6 ff                                  	call   0xc08df0
  ca2519:	48 8d 35 60 19 f6 01                            	lea    rsi,[rip+0x1f61960]        # 0x2c03e80
  ca2520:	4c 89 ff                                        	mov    rdi,r15
  ca2523:	e8 c8 68 f6 ff                                  	call   0xc08df0
  ca2528:	45 31 ff                                        	xor    r15d,r15d
  ca252b:	e9 53 fe ff ff                                  	jmp    0xca2383
  ca2530:	48 8d bd 78 ff ff ff                            	lea    rdi,[rbp-0x88]
  ca2537:	49 89 dd                                        	mov    r13,rbx
  ca253a:	e8 b1 d0 e2 ff                                  	call   0xacf5f0
  ca253f:	8b 45 80                                        	mov    eax,DWORD PTR [rbp-0x80]
  ca2542:	48 8b 8d 78 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0x88]
  ca2549:	89 45 b8                                        	mov    DWORD PTR [rbp-0x48],eax
  ca254c:	48 89 4d bc                                     	mov    QWORD PTR [rbp-0x44],rcx
  ca2550:	c7 45 c4 00 00 00 00                            	mov    DWORD PTR [rbp-0x3c],0x0
  ca2557:	49 8b 7e 08                                     	mov    rdi,QWORD PTR [r14+0x8]
  ca255b:	e8 60 8a ff ff                                  	call   0xc9afc0
  ca2560:	49 8b 7e 08                                     	mov    rdi,QWORD PTR [r14+0x8]
  ca2564:	41 bf 48 01 00 00                               	mov    r15d,0x148
  ca256a:	31 f6                                           	xor    esi,esi
  ca256c:	31 d2                                           	xor    edx,edx
  ca256e:	31 c9                                           	xor    ecx,ecx
  ca2570:	4c 01 ff                                        	add    rdi,r15
  ca2573:	e8 88 44 82 ff                                  	call   0x4c6a00
  ca2578:	49 8b 7e 08                                     	mov    rdi,QWORD PTR [r14+0x8]
  ca257c:	48 8b 9f 68 05 00 00                            	mov    rbx,QWORD PTR [rdi+0x568]
  ca2583:	48 85 db                                        	test   rbx,rbx
  ca2586:	74 7d                                           	je     0xca2605
  ca2588:	4c 8d 63 28                                     	lea    r12,[rbx+0x28]
  ca258c:	31 f6                                           	xor    esi,esi
  ca258e:	31 d2                                           	xor    edx,edx
  ca2590:	31 c9                                           	xor    ecx,ecx
  ca2592:	4c 89 e7                                        	mov    rdi,r12
  ca2595:	e8 66 44 82 ff                                  	call   0x4c6a00
  ca259a:	4c 89 e7                                        	mov    rdi,r12
  ca259d:	8b 5b 30                                        	mov    ebx,DWORD PTR [rbx+0x30]
  ca25a0:	4c 8d 25 69 9d c7 02                            	lea    r12,[rip+0x2c79d69]        # 0x391c310
  ca25a7:	31 f6                                           	xor    esi,esi
  ca25a9:	31 d2                                           	xor    edx,edx
  ca25ab:	31 c9                                           	xor    ecx,ecx
  ca25ad:	e8 ee 49 82 ff                                  	call   0x4c6fa0
  ca25b2:	4d 03 7e 08                                     	add    r15,QWORD PTR [r14+0x8]
  ca25b6:	31 f6                                           	xor    esi,esi
  ca25b8:	31 d2                                           	xor    edx,edx
  ca25ba:	31 c9                                           	xor    ecx,ecx
  ca25bc:	4c 89 ff                                        	mov    rdi,r15
  ca25bf:	e8 dc 49 82 ff                                  	call   0x4c6fa0
  ca25c4:	41 bf 1c 00 00 00                               	mov    r15d,0x1c
  ca25ca:	81 fb 00 01 00 00                               	cmp    ebx,0x100
  ca25d0:	0f 8f ad fd ff ff                               	jg     0xca2383
  ca25d6:	8b 45 b0                                        	mov    eax,DWORD PTR [rbp-0x50]
  ca25d9:	4c 89 eb                                        	mov    rbx,r13
  ca25dc:	83 f8 06                                        	cmp    eax,0x6
  ca25df:	7f 41                                           	jg     0xca2622
  ca25e1:	8d 48 fd                                        	lea    ecx,[rax-0x3]
  ca25e4:	83 f9 02                                        	cmp    ecx,0x2
  ca25e7:	0f 83 c3 00 00 00                               	jae    0xca26b0
  ca25ed:	81 7d ac 00 00 01 00                            	cmp    DWORD PTR [rbp-0x54],0x10000
  ca25f4:	41 bf 3f 00 00 00                               	mov    r15d,0x3f
  ca25fa:	0f 87 83 fd ff ff                               	ja     0xca2383
  ca2600:	e9 bd 03 00 00                                  	jmp    0xca29c2
  ca2605:	48 81 c7 48 01 00 00                            	add    rdi,0x148
  ca260c:	31 f6                                           	xor    esi,esi
  ca260e:	31 d2                                           	xor    edx,edx
  ca2610:	31 c9                                           	xor    ecx,ecx
  ca2612:	e8 89 49 82 ff                                  	call   0x4c6fa0
  ca2617:	41 bf 16 00 00 00                               	mov    r15d,0x16
  ca261d:	e9 61 fd ff ff                                  	jmp    0xca2383
  ca2622:	83 f8 07                                        	cmp    eax,0x7
  ca2625:	0f 84 b1 01 00 00                               	je     0xca27dc
  ca262b:	83 f8 64                                        	cmp    eax,0x64
  ca262e:	0f 85 91 03 00 00                               	jne    0xca29c5
  ca2634:	8b 45 a0                                        	mov    eax,DWORD PTR [rbp-0x60]
  ca2637:	48 8d 35 42 9a f5 01                            	lea    rsi,[rip+0x1f59a42]        # 0x2bfc080
  ca263e:	bb 00 10 00 00                                  	mov    ebx,0x1000
  ca2643:	ba 02 01 00 00                                  	mov    edx,0x102
  ca2648:	3d 00 10 00 00                                  	cmp    eax,0x1000
  ca264d:	0f 42 d8                                        	cmovb  ebx,eax
  ca2650:	8d 7b 01                                        	lea    edi,[rbx+0x1]
  ca2653:	e8 f8 64 f6 ff                                  	call   0xc08b50
  ca2658:	4c 8b 65 98                                     	mov    r12,QWORD PTR [rbp-0x68]
  ca265c:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  ca2665:	48 8d 35 d1 58 6f 00                            	lea    rsi,[rip+0x6f58d1]        # 0x1397f3d
  ca266c:	31 d2                                           	xor    edx,edx
  ca266e:	49 89 c6                                        	mov    r14,rax
  ca2671:	45 31 ff                                        	xor    r15d,r15d
  ca2674:	e8 67 7d f7 ff                                  	call   0xc1a3e0
  ca2679:	4c 89 e7                                        	mov    rdi,r12
  ca267c:	4c 89 f6                                        	mov    rsi,r14
  ca267f:	48 89 da                                        	mov    rdx,rbx
  ca2682:	e8 f9 6b 5b ff                                  	call   0x259280
  ca2687:	85 c0                                           	test   eax,eax
  ca2689:	0f 84 93 01 00 00                               	je     0xca2822
  ca268f:	48 8d 35 ea 99 f5 01                            	lea    rsi,[rip+0x1f599ea]        # 0x2bfc080
  ca2696:	4c 89 f7                                        	mov    rdi,r14
  ca2699:	41 89 c4                                        	mov    r12d,eax
  ca269c:	e8 4f 67 f6 ff                                  	call   0xc08df0
  ca26a1:	45 89 e7                                        	mov    r15d,r12d
  ca26a4:	4c 8d 25 65 9c c7 02                            	lea    r12,[rip+0x2c79c65]        # 0x391c310
  ca26ab:	e9 d3 fc ff ff                                  	jmp    0xca2383
  ca26b0:	83 f8 01                                        	cmp    eax,0x1
  ca26b3:	0f 85 0c 03 00 00                               	jne    0xca29c5
  ca26b9:	4d 8b 7e 08                                     	mov    r15,QWORD PTR [r14+0x8]
  ca26bd:	4c 89 ff                                        	mov    rdi,r15
  ca26c0:	e8 fb 88 ff ff                                  	call   0xc9afc0
  ca26c5:	4d 8d a7 48 01 00 00                            	lea    r12,[r15+0x148]
  ca26cc:	31 f6                                           	xor    esi,esi
  ca26ce:	31 d2                                           	xor    edx,edx
  ca26d0:	31 c9                                           	xor    ecx,ecx
  ca26d2:	4c 89 e7                                        	mov    rdi,r12
  ca26d5:	e8 26 43 82 ff                                  	call   0x4c6a00
  ca26da:	4d 8b bf 68 05 00 00                            	mov    r15,QWORD PTR [r15+0x568]
  ca26e1:	4c 89 e7                                        	mov    rdi,r12
  ca26e4:	31 f6                                           	xor    esi,esi
  ca26e6:	31 d2                                           	xor    edx,edx
  ca26e8:	31 c9                                           	xor    ecx,ecx
  ca26ea:	e8 b1 48 82 ff                                  	call   0x4c6fa0
  ca26ef:	49 83 7f 58 00                                  	cmp    QWORD PTR [r15+0x58],0x0
  ca26f4:	75 1a                                           	jne    0xca2710
  ca26f6:	48 8d 35 13 17 f6 01                            	lea    rsi,[rip+0x1f61713]        # 0x2c03e10
  ca26fd:	bf 00 00 08 00                                  	mov    edi,0x80000
  ca2702:	ba 02 01 00 00                                  	mov    edx,0x102
  ca2707:	e8 44 64 f6 ff                                  	call   0xc08b50
  ca270c:	49 89 47 58                                     	mov    QWORD PTR [r15+0x58],rax
  ca2710:	49 8b 7e 08                                     	mov    rdi,QWORD PTR [r14+0x8]
  ca2714:	41 bf 48 01 00 00                               	mov    r15d,0x148
  ca271a:	31 f6                                           	xor    esi,esi
  ca271c:	31 d2                                           	xor    edx,edx
  ca271e:	31 c9                                           	xor    ecx,ecx
  ca2720:	4c 01 ff                                        	add    rdi,r15
  ca2723:	e8 d8 42 82 ff                                  	call   0x4c6a00
  ca2728:	49 8b 7e 08                                     	mov    rdi,QWORD PTR [r14+0x8]
  ca272c:	4c 8b a7 68 05 00 00                            	mov    r12,QWORD PTR [rdi+0x568]
  ca2733:	4d 85 e4                                        	test   r12,r12
  ca2736:	0f 84 c2 00 00 00                               	je     0xca27fe
  ca273c:	49 8d 7c 24 28                                  	lea    rdi,[r12+0x28]
  ca2741:	31 f6                                           	xor    esi,esi
  ca2743:	31 d2                                           	xor    edx,edx
  ca2745:	31 c9                                           	xor    ecx,ecx
  ca2747:	48 89 bd 70 ff ff ff                            	mov    QWORD PTR [rbp-0x90],rdi
  ca274e:	e8 ad 42 82 ff                                  	call   0x4c6a00
  ca2753:	bb 00 00 08 00                                  	mov    ebx,0x80000
  ca2758:	41 2b 5c 24 50                                  	sub    ebx,DWORD PTR [r12+0x50]
  ca275d:	48 8b bd 70 ff ff ff                            	mov    rdi,QWORD PTR [rbp-0x90]
  ca2764:	31 f6                                           	xor    esi,esi
  ca2766:	31 d2                                           	xor    edx,edx
  ca2768:	31 c9                                           	xor    ecx,ecx
  ca276a:	e8 31 48 82 ff                                  	call   0x4c6fa0
  ca276f:	4d 03 7e 08                                     	add    r15,QWORD PTR [r14+0x8]
  ca2773:	31 f6                                           	xor    esi,esi
  ca2775:	31 d2                                           	xor    edx,edx
  ca2777:	31 c9                                           	xor    ecx,ecx
  ca2779:	4c 89 ff                                        	mov    rdi,r15
  ca277c:	e8 1f 48 82 ff                                  	call   0x4c6fa0
  ca2781:	44 8b 65 a0                                     	mov    r12d,DWORD PTR [rbp-0x60]
  ca2785:	44 39 e3                                        	cmp    ebx,r12d
  ca2788:	44 0f 42 e3                                     	cmovb  r12d,ebx
  ca278c:	85 db                                           	test   ebx,ebx
  ca278e:	0f 8e b3 00 00 00                               	jle    0xca2847
  ca2794:	48 8d 35 e5 98 f5 01                            	lea    rsi,[rip+0x1f598e5]        # 0x2bfc080
  ca279b:	44 89 e3                                        	mov    ebx,r12d
  ca279e:	ba 02 01 00 00                                  	mov    edx,0x102
  ca27a3:	48 89 df                                        	mov    rdi,rbx
  ca27a6:	e8 a5 63 f6 ff                                  	call   0xc08b50
  ca27ab:	48 8b 7d 98                                     	mov    rdi,QWORD PTR [rbp-0x68]
  ca27af:	48 89 c6                                        	mov    rsi,rax
  ca27b2:	48 89 da                                        	mov    rdx,rbx
  ca27b5:	48 89 85 70 ff ff ff                            	mov    QWORD PTR [rbp-0x90],rax
  ca27bc:	e8 df a1 ff ff                                  	call   0xc9c9a0
  ca27c1:	85 c0                                           	test   eax,eax
  ca27c3:	0f 84 95 00 00 00                               	je     0xca285e
  ca27c9:	48 8d 35 b0 98 f5 01                            	lea    rsi,[rip+0x1f598b0]        # 0x2bfc080
  ca27d0:	48 8b bd 70 ff ff ff                            	mov    rdi,QWORD PTR [rbp-0x90]
  ca27d7:	41 89 c7                                        	mov    r15d,eax
  ca27da:	eb 5a                                           	jmp    0xca2836
  ca27dc:	81 7d a0 00 01 00 00                            	cmp    DWORD PTR [rbp-0x60],0x100
  ca27e3:	41 bf 16 00 00 00                               	mov    r15d,0x16
  ca27e9:	0f 87 94 fb ff ff                               	ja     0xca2383
  ca27ef:	83 7d 94 0f                                     	cmp    DWORD PTR [rbp-0x6c],0xf
  ca27f3:	0f 86 c9 01 00 00                               	jbe    0xca29c2
  ca27f9:	e9 85 fb ff ff                                  	jmp    0xca2383
  ca27fe:	48 81 c7 48 01 00 00                            	add    rdi,0x148
  ca2805:	31 f6                                           	xor    esi,esi
  ca2807:	31 d2                                           	xor    edx,edx
  ca2809:	31 c9                                           	xor    ecx,ecx
  ca280b:	e8 90 47 82 ff                                  	call   0x4c6fa0
  ca2810:	4c 8d 25 f9 9a c7 02                            	lea    r12,[rip+0x2c79af9]        # 0x391c310
  ca2817:	41 bf 16 00 00 00                               	mov    r15d,0x16
  ca281d:	e9 61 fb ff ff                                  	jmp    0xca2383
  ca2822:	4c 89 f7                                        	mov    rdi,r14
  ca2825:	89 de                                           	mov    esi,ebx
  ca2827:	e8 b4 e2 b0 ff                                  	call   0x7b0ae0
  ca282c:	48 8d 35 4d 98 f5 01                            	lea    rsi,[rip+0x1f5984d]        # 0x2bfc080
  ca2833:	4c 89 f7                                        	mov    rdi,r14
  ca2836:	e8 b5 65 f6 ff                                  	call   0xc08df0
  ca283b:	4c 8d 25 ce 9a c7 02                            	lea    r12,[rip+0x2c79ace]        # 0x391c310
  ca2842:	e9 3c fb ff ff                                  	jmp    0xca2383
  ca2847:	4c 8d 25 c2 9a c7 02                            	lea    r12,[rip+0x2c79ac2]        # 0x391c310
  ca284e:	48 c7 45 c8 00 00 00 00                         	mov    QWORD PTR [rbp-0x38],0x0
  ca2856:	4c 89 eb                                        	mov    rbx,r13
  ca2859:	e9 64 01 00 00                                  	jmp    0xca29c2
  ca285e:	bf 48 01 00 00                                  	mov    edi,0x148
  ca2863:	49 03 7e 08                                     	add    rdi,QWORD PTR [r14+0x8]
  ca2867:	4c 89 ad 68 ff ff ff                            	mov    QWORD PTR [rbp-0x98],r13
  ca286e:	4c 8b ad 70 ff ff ff                            	mov    r13,QWORD PTR [rbp-0x90]
  ca2875:	49 89 df                                        	mov    r15,rbx
  ca2878:	31 f6                                           	xor    esi,esi
  ca287a:	31 d2                                           	xor    edx,edx
  ca287c:	31 c9                                           	xor    ecx,ecx
  ca287e:	e8 7d 41 82 ff                                  	call   0x4c6a00
  ca2883:	49 8b 7e 08                                     	mov    rdi,QWORD PTR [r14+0x8]
  ca2887:	48 8b 9f 68 05 00 00                            	mov    rbx,QWORD PTR [rdi+0x568]
  ca288e:	48 89 9d 58 ff ff ff                            	mov    QWORD PTR [rbp-0xa8],rbx
  ca2895:	48 85 db                                        	test   rbx,rbx
  ca2898:	0f 84 80 00 00 00                               	je     0xca291e
  ca289e:	48 8d 7b 28                                     	lea    rdi,[rbx+0x28]
  ca28a2:	31 f6                                           	xor    esi,esi
  ca28a4:	31 d2                                           	xor    edx,edx
  ca28a6:	31 c9                                           	xor    ecx,ecx
  ca28a8:	48 89 bd 60 ff ff ff                            	mov    QWORD PTR [rbp-0xa0],rdi
  ca28af:	e8 4c 41 82 ff                                  	call   0x4c6a00
  ca28b4:	48 63 7b 50                                     	movsxd rdi,DWORD PTR [rbx+0x50]
  ca28b8:	42 8d 04 27                                     	lea    eax,[rdi+r12*1]
  ca28bc:	3d 01 00 08 00                                  	cmp    eax,0x80001
  ca28c1:	0f 8c 8e 00 00 00                               	jl     0xca2955
  ca28c7:	48 c7 45 c8 00 00 00 00                         	mov    QWORD PTR [rbp-0x38],0x0
  ca28cf:	e9 98 00 00 00                                  	jmp    0xca296c
  ca28d4:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  ca28d7:	48 89 01                                        	mov    QWORD PTR [rcx],rax
  ca28da:	48 85 c0                                        	test   rax,rax
  ca28dd:	74 55                                           	je     0xca2934
  ca28df:	41 8b 8c 24 f8 00 00 00                         	mov    ecx,DWORD PTR [r12+0xf8]
  ca28e7:	ff c9                                           	dec    ecx
  ca28e9:	41 89 8c 24 f8 00 00 00                         	mov    DWORD PTR [r12+0xf8],ecx
  ca28f1:	41 89 4c 24 30                                  	mov    DWORD PTR [r12+0x30],ecx
  ca28f6:	31 c9                                           	xor    ecx,ecx
  ca28f8:	eb 0b                                           	jmp    0xca2905
  ca28fa:	ff c1                                           	inc    ecx
  ca28fc:	48 85 c0                                        	test   rax,rax
  ca28ff:	0f 84 d1 fb ff ff                               	je     0xca24d6
  ca2905:	48 89 c2                                        	mov    rdx,rax
  ca2908:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  ca290b:	89 4a 08                                        	mov    DWORD PTR [rdx+0x8],ecx
  ca290e:	83 7a 0c 01                                     	cmp    DWORD PTR [rdx+0xc],0x1
  ca2912:	75 e6                                           	jne    0xca28fa
  ca2914:	41 89 8c 24 9c 00 00 00                         	mov    DWORD PTR [r12+0x9c],ecx
  ca291c:	eb dc                                           	jmp    0xca28fa
  ca291e:	4c 8d 25 eb 99 c7 02                            	lea    r12,[rip+0x2c799eb]        # 0x391c310
  ca2925:	48 8b 9d 68 ff ff ff                            	mov    rbx,QWORD PTR [rbp-0x98]
  ca292c:	41 bf 16 00 00 00                               	mov    r15d,0x16
  ca2932:	eb 5f                                           	jmp    0xca2993
  ca2934:	49 89 4c 24 48                                  	mov    QWORD PTR [r12+0x48],rcx
  ca2939:	41 8b 84 24 f8 00 00 00                         	mov    eax,DWORD PTR [r12+0xf8]
  ca2941:	ff c8                                           	dec    eax
  ca2943:	41 89 84 24 f8 00 00 00                         	mov    DWORD PTR [r12+0xf8],eax
  ca294b:	41 89 44 24 30                                  	mov    DWORD PTR [r12+0x30],eax
  ca2950:	e9 81 fb ff ff                                  	jmp    0xca24d6
  ca2955:	48 03 7b 58                                     	add    rdi,QWORD PTR [rbx+0x58]
  ca2959:	4c 89 ee                                        	mov    rsi,r13
  ca295c:	4c 89 fa                                        	mov    rdx,r15
  ca295f:	e8 4c 67 5b ff                                  	call   0x2590b0
  ca2964:	4c 89 7d c8                                     	mov    QWORD PTR [rbp-0x38],r15
  ca2968:	44 01 63 50                                     	add    DWORD PTR [rbx+0x50],r12d
  ca296c:	48 8b bd 60 ff ff ff                            	mov    rdi,QWORD PTR [rbp-0xa0]
  ca2973:	4c 8d 25 96 99 c7 02                            	lea    r12,[rip+0x2c79996]        # 0x391c310
  ca297a:	48 8b 9d 68 ff ff ff                            	mov    rbx,QWORD PTR [rbp-0x98]
  ca2981:	45 31 ff                                        	xor    r15d,r15d
  ca2984:	31 f6                                           	xor    esi,esi
  ca2986:	31 d2                                           	xor    edx,edx
  ca2988:	31 c9                                           	xor    ecx,ecx
  ca298a:	e8 11 46 82 ff                                  	call   0x4c6fa0
  ca298f:	49 8b 7e 08                                     	mov    rdi,QWORD PTR [r14+0x8]
  ca2993:	48 81 c7 48 01 00 00                            	add    rdi,0x148
  ca299a:	31 f6                                           	xor    esi,esi
  ca299c:	31 d2                                           	xor    edx,edx
  ca299e:	31 c9                                           	xor    ecx,ecx
  ca29a0:	e8 fb 45 82 ff                                  	call   0x4c6fa0
  ca29a5:	48 8d 35 d4 96 f5 01                            	lea    rsi,[rip+0x1f596d4]        # 0x2bfc080
  ca29ac:	4c 89 ef                                        	mov    rdi,r13
  ca29af:	e8 3c 64 f6 ff                                  	call   0xc08df0
  ca29b4:	48 83 bd 58 ff ff ff 00                         	cmp    QWORD PTR [rbp-0xa8],0x0
  ca29bc:	0f 84 c1 f9 ff ff                               	je     0xca2383
  ca29c2:	8b 45 b0                                        	mov    eax,DWORD PTR [rbp-0x50]
  ca29c5:	ff c8                                           	dec    eax
  ca29c7:	83 f8 06                                        	cmp    eax,0x6
  ca29ca:	0f 87 86 00 00 00                               	ja     0xca2a56
  ca29d0:	48 8d 0d 5d e8 da 00                            	lea    rcx,[rip+0xdae85d]        # 0x1a51234
  ca29d7:	48 63 04 81                                     	movsxd rax,DWORD PTR [rcx+rax*4]
  ca29db:	48 01 c8                                        	add    rax,rcx
  ca29de:	ff e0                                           	jmp    rax
  ca29e0:	8b 7d ac                                        	mov    edi,DWORD PTR [rbp-0x54]
  ca29e3:	48 8d 35 96 14 f6 01                            	lea    rsi,[rip+0x1f61496]        # 0x2c03e80
  ca29ea:	ba 02 01 00 00                                  	mov    edx,0x102
  ca29ef:	ff c7                                           	inc    edi
  ca29f1:	e8 5a 61 f6 ff                                  	call   0xc08b50
  ca29f6:	44 8b 7d ac                                     	mov    r15d,DWORD PTR [rbp-0x54]
  ca29fa:	4c 8b 65 a4                                     	mov    r12,QWORD PTR [rbp-0x5c]
  ca29fe:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  ca2a07:	48 8d 35 2f 55 6f 00                            	lea    rsi,[rip+0x6f552f]        # 0x1397f3d
  ca2a0e:	31 d2                                           	xor    edx,edx
  ca2a10:	49 89 c5                                        	mov    r13,rax
  ca2a13:	e8 c8 79 f7 ff                                  	call   0xc1a3e0
  ca2a18:	4c 89 e7                                        	mov    rdi,r12
  ca2a1b:	4c 89 ee                                        	mov    rsi,r13
  ca2a1e:	4c 89 fa                                        	mov    rdx,r15
  ca2a21:	e8 5a 68 5b ff                                  	call   0x259280
  ca2a26:	48 98                                           	cdqe
  ca2a28:	48 89 45 c8                                     	mov    QWORD PTR [rbp-0x38],rax
  ca2a2c:	85 c0                                           	test   eax,eax
  ca2a2e:	0f 84 8c 01 00 00                               	je     0xca2bc0
  ca2a34:	48 8d 35 45 14 f6 01                            	lea    rsi,[rip+0x1f61445]        # 0x2c03e80
  ca2a3b:	4c 89 ef                                        	mov    rdi,r13
  ca2a3e:	e9 4b 03 00 00                                  	jmp    0xca2d8e
  ca2a43:	48 c7 45 c8 00 00 00 00                         	mov    QWORD PTR [rbp-0x38],0x0
  ca2a4b:	45 31 ff                                        	xor    r15d,r15d
  ca2a4e:	45 31 ed                                        	xor    r13d,r13d
  ca2a51:	e9 d8 01 00 00                                  	jmp    0xca2c2e
  ca2a56:	48 c7 45 c8 16 00 00 00                         	mov    QWORD PTR [rbp-0x38],0x16
  ca2a5e:	e9 37 03 00 00                                  	jmp    0xca2d9a
  ca2a63:	bf 48 01 00 00                                  	mov    edi,0x148
  ca2a68:	49 03 7e 08                                     	add    rdi,QWORD PTR [r14+0x8]
  ca2a6c:	45 31 ed                                        	xor    r13d,r13d
  ca2a6f:	31 f6                                           	xor    esi,esi
  ca2a71:	31 d2                                           	xor    edx,edx
  ca2a73:	31 c9                                           	xor    ecx,ecx
  ca2a75:	e8 86 3f 82 ff                                  	call   0x4c6a00
  ca2a7a:	49 8b 7e 08                                     	mov    rdi,QWORD PTR [r14+0x8]
  ca2a7e:	4c 8b a7 68 05 00 00                            	mov    r12,QWORD PTR [rdi+0x568]
  ca2a85:	4d 85 e4                                        	test   r12,r12
  ca2a88:	74 35                                           	je     0xca2abf
  ca2a8a:	4d 8d 7c 24 28                                  	lea    r15,[r12+0x28]
  ca2a8f:	31 f6                                           	xor    esi,esi
  ca2a91:	31 d2                                           	xor    edx,edx
  ca2a93:	31 c9                                           	xor    ecx,ecx
  ca2a95:	4c 89 ff                                        	mov    rdi,r15
  ca2a98:	e8 63 3f 82 ff                                  	call   0x4c6a00
  ca2a9d:	45 31 ed                                        	xor    r13d,r13d
  ca2aa0:	41 83 bc 24 9c 00 00 00 ff                      	cmp    DWORD PTR [r12+0x9c],0xffffffff
  ca2aa9:	4c 89 ff                                        	mov    rdi,r15
  ca2aac:	41 0f 95 c5                                     	setne  r13b
  ca2ab0:	31 f6                                           	xor    esi,esi
  ca2ab2:	31 d2                                           	xor    edx,edx
  ca2ab4:	31 c9                                           	xor    ecx,ecx
  ca2ab6:	e8 e5 44 82 ff                                  	call   0x4c6fa0
  ca2abb:	49 8b 7e 08                                     	mov    rdi,QWORD PTR [r14+0x8]
  ca2abf:	48 81 c7 48 01 00 00                            	add    rdi,0x148
  ca2ac6:	4c 89 ad 70 ff ff ff                            	mov    QWORD PTR [rbp-0x90],r13
  ca2acd:	45 31 ed                                        	xor    r13d,r13d
  ca2ad0:	31 f6                                           	xor    esi,esi
  ca2ad2:	31 d2                                           	xor    edx,edx
  ca2ad4:	31 c9                                           	xor    ecx,ecx
  ca2ad6:	e8 c5 44 82 ff                                  	call   0x4c6fa0
  ca2adb:	4c 8d 25 2e 98 c7 02                            	lea    r12,[rip+0x2c7982e]        # 0x391c310
  ca2ae2:	45 31 ff                                        	xor    r15d,r15d
  ca2ae5:	e9 37 01 00 00                                  	jmp    0xca2c21
  ca2aea:	44 8b 7d a0                                     	mov    r15d,DWORD PTR [rbp-0x60]
  ca2aee:	8b 45 94                                        	mov    eax,DWORD PTR [rbp-0x6c]
  ca2af1:	48 8d 35 88 13 f6 01                            	lea    rsi,[rip+0x1f61388]        # 0x2c03e80
  ca2af8:	ba 02 01 00 00                                  	mov    edx,0x102
  ca2afd:	4c 89 ff                                        	mov    rdi,r15
  ca2b00:	89 85 70 ff ff ff                               	mov    DWORD PTR [rbp-0x90],eax
  ca2b06:	e8 45 60 f6 ff                                  	call   0xc08b50
  ca2b0b:	48 8b 7d 98                                     	mov    rdi,QWORD PTR [rbp-0x68]
  ca2b0f:	48 89 c6                                        	mov    rsi,rax
  ca2b12:	4c 89 fa                                        	mov    rdx,r15
  ca2b15:	49 89 c5                                        	mov    r13,rax
  ca2b18:	e8 83 9e ff ff                                  	call   0xc9c9a0
  ca2b1d:	48 98                                           	cdqe
  ca2b1f:	48 89 45 c8                                     	mov    QWORD PTR [rbp-0x38],rax
  ca2b23:	85 c0                                           	test   eax,eax
  ca2b25:	0f 85 81 00 00 00                               	jne    0xca2bac
  ca2b2b:	bf 48 01 00 00                                  	mov    edi,0x148
  ca2b30:	49 03 7e 08                                     	add    rdi,QWORD PTR [r14+0x8]
  ca2b34:	31 f6                                           	xor    esi,esi
  ca2b36:	31 d2                                           	xor    edx,edx
  ca2b38:	31 c9                                           	xor    ecx,ecx
  ca2b3a:	e8 c1 3e 82 ff                                  	call   0x4c6a00
  ca2b3f:	49 8b 7e 08                                     	mov    rdi,QWORD PTR [r14+0x8]
  ca2b43:	4c 8b a7 68 05 00 00                            	mov    r12,QWORD PTR [rdi+0x568]
  ca2b4a:	4d 85 e4                                        	test   r12,r12
  ca2b4d:	74 44                                           	je     0xca2b93
  ca2b4f:	49 8d 7c 24 28                                  	lea    rdi,[r12+0x28]
  ca2b54:	31 f6                                           	xor    esi,esi
  ca2b56:	31 d2                                           	xor    edx,edx
  ca2b58:	31 c9                                           	xor    ecx,ecx
  ca2b5a:	48 89 bd 68 ff ff ff                            	mov    QWORD PTR [rbp-0x98],rdi
  ca2b61:	e8 9a 3e 82 ff                                  	call   0x4c6a00
  ca2b66:	41 8b 84 24 e8 01 00 00                         	mov    eax,DWORD PTR [r12+0x1e8]
  ca2b6e:	8b 8d 70 ff ff ff                               	mov    ecx,DWORD PTR [rbp-0x90]
  ca2b74:	0f a3 c8                                        	bt     eax,ecx
  ca2b77:	0f 83 5a 02 00 00                               	jae    0xca2dd7
  ca2b7d:	48 8b bd 68 ff ff ff                            	mov    rdi,QWORD PTR [rbp-0x98]
  ca2b84:	31 f6                                           	xor    esi,esi
  ca2b86:	31 d2                                           	xor    edx,edx
  ca2b88:	31 c9                                           	xor    ecx,ecx
  ca2b8a:	e8 11 44 82 ff                                  	call   0x4c6fa0
  ca2b8f:	49 8b 7e 08                                     	mov    rdi,QWORD PTR [r14+0x8]
  ca2b93:	48 81 c7 48 01 00 00                            	add    rdi,0x148
  ca2b9a:	31 f6                                           	xor    esi,esi
  ca2b9c:	31 d2                                           	xor    edx,edx
  ca2b9e:	31 c9                                           	xor    ecx,ecx
  ca2ba0:	e8 fb 43 82 ff                                  	call   0x4c6fa0
  ca2ba5:	4c 8d 25 64 97 c7 02                            	lea    r12,[rip+0x2c79764]        # 0x391c310
  ca2bac:	48 8d 35 cd 12 f6 01                            	lea    rsi,[rip+0x1f612cd]        # 0x2c03e80
  ca2bb3:	4c 89 ef                                        	mov    rdi,r13
  ca2bb6:	e8 35 62 f6 ff                                  	call   0xc08df0
  ca2bbb:	e9 da 01 00 00                                  	jmp    0xca2d9a
  ca2bc0:	41 ff c7                                        	inc    r15d
  ca2bc3:	83 7d b0 03                                     	cmp    DWORD PTR [rbp-0x50],0x3
  ca2bc7:	48 c7 85 70 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x90],0x0
  ca2bd2:	75 3c                                           	jne    0xca2c10
  ca2bd4:	8b 55 ac                                        	mov    edx,DWORD PTR [rbp-0x54]
  ca2bd7:	4c 89 f7                                        	mov    rdi,r14
  ca2bda:	4c 89 ee                                        	mov    rsi,r13
  ca2bdd:	e8 4e 12 00 00                                  	call   0xca3e30
  ca2be2:	4c 8d 25 27 97 c7 02                            	lea    r12,[rip+0x2c79727]        # 0x391c310
  ca2be9:	85 c0                                           	test   eax,eax
  ca2beb:	75 2a                                           	jne    0xca2c17
  ca2bed:	48 8d 35 8c 12 f6 01                            	lea    rsi,[rip+0x1f6128c]        # 0x2c03e80
  ca2bf4:	4c 89 ef                                        	mov    rdi,r13
  ca2bf7:	e8 f4 61 f6 ff                                  	call   0xc08df0
  ca2bfc:	b8 01 00 00 00                                  	mov    eax,0x1
  ca2c01:	45 31 ed                                        	xor    r13d,r13d
  ca2c04:	45 31 ff                                        	xor    r15d,r15d
  ca2c07:	48 89 85 70 ff ff ff                            	mov    QWORD PTR [rbp-0x90],rax
  ca2c0e:	eb 07                                           	jmp    0xca2c17
  ca2c10:	4c 8d 25 f9 96 c7 02                            	lea    r12,[rip+0x2c796f9]        # 0x391c310
  ca2c17:	44 89 f8                                        	mov    eax,r15d
  ca2c1a:	44 89 7d c4                                     	mov    DWORD PTR [rbp-0x3c],r15d
  ca2c1e:	49 89 c7                                        	mov    r15,rax
  ca2c21:	83 bd 70 ff ff ff 00                            	cmp    DWORD PTR [rbp-0x90],0x0
  ca2c28:	0f 85 6c 01 00 00                               	jne    0xca2d9a
  ca2c2e:	4d 8b 66 08                                     	mov    r12,QWORD PTR [r14+0x8]
  ca2c32:	48 8d 35 47 12 f6 01                            	lea    rsi,[rip+0x1f61247]        # 0x2c03e80
  ca2c39:	bf 58 00 00 00                                  	mov    edi,0x58
  ca2c3e:	ba 02 01 00 00                                  	mov    edx,0x102
  ca2c43:	e8 08 5f f6 ff                                  	call   0xc08b50
  ca2c48:	4c 8b 4d 8c                                     	mov    r9,QWORD PTR [rbp-0x74]
  ca2c4c:	4c 8b 45 9c                                     	mov    r8,QWORD PTR [rbp-0x64]
  ca2c50:	49 89 c6                                        	mov    r14,rax
  ca2c53:	48 8b 4d 94                                     	mov    rcx,QWORD PTR [rbp-0x6c]
  ca2c57:	8b 7d c4                                        	mov    edi,DWORD PTR [rbp-0x3c]
  ca2c5a:	31 f6                                           	xor    esi,esi
  ca2c5c:	31 d2                                           	xor    edx,edx
  ca2c5e:	4d 89 4e 08                                     	mov    QWORD PTR [r14+0x8],r9
  ca2c62:	4d 89 46 18                                     	mov    QWORD PTR [r14+0x18],r8
  ca2c66:	4c 8b 4d a4                                     	mov    r9,QWORD PTR [rbp-0x5c]
  ca2c6a:	4c 8b 45 ac                                     	mov    r8,QWORD PTR [rbp-0x54]
  ca2c6e:	49 89 4e 10                                     	mov    QWORD PTR [r14+0x10],rcx
  ca2c72:	41 89 7e 40                                     	mov    DWORD PTR [r14+0x40],edi
  ca2c76:	31 c9                                           	xor    ecx,ecx
  ca2c78:	4d 89 4e 20                                     	mov    QWORD PTR [r14+0x20],r9
  ca2c7c:	4d 89 46 28                                     	mov    QWORD PTR [r14+0x28],r8
  ca2c80:	4c 8b 4d b4                                     	mov    r9,QWORD PTR [rbp-0x4c]
  ca2c84:	4c 8b 45 bc                                     	mov    r8,QWORD PTR [rbp-0x44]
  ca2c88:	4d 89 4e 30                                     	mov    QWORD PTR [r14+0x30],r9
  ca2c8c:	4d 89 46 38                                     	mov    QWORD PTR [r14+0x38],r8
  ca2c90:	4d 89 6e 48                                     	mov    QWORD PTR [r14+0x48],r13
  ca2c94:	4d 89 7e 50                                     	mov    QWORD PTR [r14+0x50],r15
  ca2c98:	4d 8d bc 24 48 01 00 00                         	lea    r15,[r12+0x148]
  ca2ca0:	4c 89 ff                                        	mov    rdi,r15
  ca2ca3:	e8 58 3d 82 ff                                  	call   0x4c6a00
  ca2ca8:	4d 8b a4 24 68 05 00 00                         	mov    r12,QWORD PTR [r12+0x568]
  ca2cb0:	4d 85 e4                                        	test   r12,r12
  ca2cb3:	0f 84 a8 00 00 00                               	je     0xca2d61
  ca2cb9:	4d 8d 6c 24 28                                  	lea    r13,[r12+0x28]
  ca2cbe:	31 f6                                           	xor    esi,esi
  ca2cc0:	31 d2                                           	xor    edx,edx
  ca2cc2:	31 c9                                           	xor    ecx,ecx
  ca2cc4:	4c 89 ef                                        	mov    rdi,r13
  ca2cc7:	e8 34 3d 82 ff                                  	call   0x4c6a00
  ca2ccc:	41 83 7e 2c 01                                  	cmp    DWORD PTR [r14+0x2c],0x1
  ca2cd1:	41 8b 44 24 30                                  	mov    eax,DWORD PTR [r12+0x30]
  ca2cd6:	75 08                                           	jne    0xca2ce0
  ca2cd8:	41 89 84 24 9c 00 00 00                         	mov    DWORD PTR [r12+0x9c],eax
  ca2ce0:	41 89 46 08                                     	mov    DWORD PTR [r14+0x8],eax
  ca2ce4:	49 c7 06 00 00 00 00                            	mov    QWORD PTR [r14],0x0
  ca2ceb:	f7 85 50 ff ff ff 00 01 00 00                   	test   DWORD PTR [rbp-0xb0],0x100
  ca2cf5:	49 8b 44 24 48                                  	mov    rax,QWORD PTR [r12+0x48]
  ca2cfa:	4c 89 30                                        	mov    QWORD PTR [rax],r14
  ca2cfd:	41 8b 44 24 30                                  	mov    eax,DWORD PTR [r12+0x30]
  ca2d02:	4d 89 74 24 48                                  	mov    QWORD PTR [r12+0x48],r14
  ca2d07:	8d 48 01                                        	lea    ecx,[rax+0x1]
  ca2d0a:	41 89 4c 24 30                                  	mov    DWORD PTR [r12+0x30],ecx
  ca2d0f:	75 32                                           	jne    0xca2d43
  ca2d11:	41 8b 8c 24 f8 00 00 00                         	mov    ecx,DWORD PTR [r12+0xf8]
  ca2d19:	8d 51 01                                        	lea    edx,[rcx+0x1]
  ca2d1c:	41 89 94 24 f8 00 00 00                         	mov    DWORD PTR [r12+0xf8],edx
  ca2d24:	39 c1                                           	cmp    ecx,eax
  ca2d26:	74 1b                                           	je     0xca2d43
  ca2d28:	48 8d 3d f3 94 61 00                            	lea    rdi,[rip+0x6194f3]        # 0x12bc222
  ca2d2f:	31 c0                                           	xor    eax,eax
  ca2d31:	e8 da a6 5b ff                                  	call   0x25d410
  ca2d36:	41 8b 44 24 30                                  	mov    eax,DWORD PTR [r12+0x30]
  ca2d3b:	41 89 84 24 f8 00 00 00                         	mov    DWORD PTR [r12+0xf8],eax
  ca2d43:	4c 89 ef                                        	mov    rdi,r13
  ca2d46:	31 f6                                           	xor    esi,esi
  ca2d48:	31 d2                                           	xor    edx,edx
  ca2d4a:	31 c9                                           	xor    ecx,ecx
  ca2d4c:	e8 4f 42 82 ff                                  	call   0x4c6fa0
  ca2d51:	4c 89 ff                                        	mov    rdi,r15
  ca2d54:	31 f6                                           	xor    esi,esi
  ca2d56:	31 d2                                           	xor    edx,edx
  ca2d58:	31 c9                                           	xor    ecx,ecx
  ca2d5a:	e8 41 42 82 ff                                  	call   0x4c6fa0
  ca2d5f:	eb 32                                           	jmp    0xca2d93
  ca2d61:	4c 89 ff                                        	mov    rdi,r15
  ca2d64:	31 f6                                           	xor    esi,esi
  ca2d66:	31 d2                                           	xor    edx,edx
  ca2d68:	31 c9                                           	xor    ecx,ecx
  ca2d6a:	e8 31 42 82 ff                                  	call   0x4c6fa0
  ca2d6f:	49 8b 7e 48                                     	mov    rdi,QWORD PTR [r14+0x48]
  ca2d73:	48 85 ff                                        	test   rdi,rdi
  ca2d76:	74 0c                                           	je     0xca2d84
  ca2d78:	48 8d 35 01 11 f6 01                            	lea    rsi,[rip+0x1f61101]        # 0x2c03e80
  ca2d7f:	e8 6c 60 f6 ff                                  	call   0xc08df0
  ca2d84:	48 8d 35 f5 10 f6 01                            	lea    rsi,[rip+0x1f610f5]        # 0x2c03e80
  ca2d8b:	4c 89 f7                                        	mov    rdi,r14
  ca2d8e:	e8 5d 60 f6 ff                                  	call   0xc08df0
  ca2d93:	4c 8d 25 76 95 c7 02                            	lea    r12,[rip+0x2c79576]        # 0x391c310
  ca2d9a:	48 85 db                                        	test   rbx,rbx
  ca2d9d:	74 30                                           	je     0xca2dcf
  ca2d9f:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  ca2da8:	48 8d 35 e8 c4 6a 00                            	lea    rsi,[rip+0x6ac4e8]        # 0x134f297
  ca2daf:	31 d2                                           	xor    edx,edx
  ca2db1:	e8 2a 76 f7 ff                                  	call   0xc1a3e0
  ca2db6:	48 8d 7d c8                                     	lea    rdi,[rbp-0x38]
  ca2dba:	ba 08 00 00 00                                  	mov    edx,0x8
  ca2dbf:	48 89 de                                        	mov    rsi,rbx
  ca2dc2:	e8 09 64 5b ff                                  	call   0x2591d0
  ca2dc7:	41 89 c7                                        	mov    r15d,eax
  ca2dca:	e9 b4 f5 ff ff                                  	jmp    0xca2383
  ca2dcf:	45 31 ff                                        	xor    r15d,r15d
  ca2dd2:	e9 ac f5 ff ff                                  	jmp    0xca2383
  ca2dd7:	b8 01 00 00 00                                  	mov    eax,0x1
  ca2ddc:	44 89 7d c4                                     	mov    DWORD PTR [rbp-0x3c],r15d
  ca2de0:	48 8b bd 68 ff ff ff                            	mov    rdi,QWORD PTR [rbp-0x98]
  ca2de7:	31 f6                                           	xor    esi,esi
  ca2de9:	31 d2                                           	xor    edx,edx
  ca2deb:	c4 e2 71 f7 c0                                  	shlx   eax,eax,ecx
  ca2df0:	31 c9                                           	xor    ecx,ecx
  ca2df2:	41 09 84 24 e8 01 00 00                         	or     DWORD PTR [r12+0x1e8],eax
  ca2dfa:	e8 a1 41 82 ff                                  	call   0x4c6fa0
  ca2dff:	bf 48 01 00 00                                  	mov    edi,0x148
  ca2e04:	49 03 7e 08                                     	add    rdi,QWORD PTR [r14+0x8]
  ca2e08:	31 f6                                           	xor    esi,esi
  ca2e0a:	31 d2                                           	xor    edx,edx
  ca2e0c:	31 c9                                           	xor    ecx,ecx
  ca2e0e:	e8 8d 41 82 ff                                  	call   0x4c6fa0
  ca2e13:	e9 16 fe ff ff                                  	jmp    0xca2c2e
  ca2e18:	e8 93 a8 a5 ff                                  	call   0x6fd6b0
  ca2e1d:	0f 0b                                           	ud2
  ca2e1f:	90                                              	nop
  ca2e20:	55                                              	push   rbp
  ca2e21:	48 89 e5                                        	mov    rbp,rsp
  ca2e24:	53                                              	push   rbx
  ca2e25:	50                                              	push   rax
  ca2e26:	f6 87 68 04 00 00 02                            	test   BYTE PTR [rdi+0x468],0x2
  ca2e2d:	48 89 fb                                        	mov    rbx,rdi
  ca2e30:	75 0b                                           	jne    0xca2e3d
  ca2e32:	e8 49 00 94 ff                                  	call   0x5e2e80
  ca2e37:	85 c0                                           	test   eax,eax
  ca2e39:	75 1b                                           	jne    0xca2e56
  ca2e3b:	eb 12                                           	jmp    0xca2e4f
  ca2e3d:	48 8d 15 bc e5 da 00                            	lea    rdx,[rip+0xdae5bc]        # 0x1a51400
  ca2e44:	31 ff                                           	xor    edi,edi
  ca2e46:	31 f6                                           	xor    esi,esi
  ca2e48:	31 c0                                           	xor    eax,eax
  ca2e4a:	e8 81 16 e6 ff                                  	call   0xb044d0
  ca2e4f:	80 8b 62 05 00 00 10                            	or     BYTE PTR [rbx+0x562],0x10
  ca2e56:	48 83 c4 08                                     	add    rsp,0x8
  ca2e5a:	5b                                              	pop    rbx
  ca2e5b:	5d                                              	pop    rbp
  ca2e5c:	c3                                              	ret
  ca2e5d:	90                                              	nop
  ca2e5e:	90                                              	nop
  ca2e5f:	90                                              	nop
  ca2e60:	55                                              	push   rbp
  ca2e61:	48 89 e5                                        	mov    rbp,rsp
  ca2e64:	41 57                                           	push   r15
  ca2e66:	41 56                                           	push   r14
  ca2e68:	41 55                                           	push   r13
  ca2e6a:	41 54                                           	push   r12
  ca2e6c:	53                                              	push   rbx
  ca2e6d:	48 83 ec 28                                     	sub    rsp,0x28
  ca2e71:	48 8d 1d 98 94 c7 02                            	lea    rbx,[rip+0x2c79498]        # 0x391c310
  ca2e78:	49 89 fe                                        	mov    r14,rdi
  ca2e7b:	48 8d 3d de 6f 8e 02                            	lea    rdi,[rip+0x28e6fde]        # 0x3589e60
  ca2e82:	49 89 f7                                        	mov    r15,rsi
  ca2e85:	31 f6                                           	xor    esi,esi
  ca2e87:	31 d2                                           	xor    edx,edx
  ca2e89:	31 c9                                           	xor    ecx,ecx
  ca2e8b:	48 8b 03                                        	mov    rax,QWORD PTR [rbx]
  ca2e8e:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  ca2e92:	48 c7 45 c8 00 00 00 00                         	mov    QWORD PTR [rbp-0x38],0x0
  ca2e9a:	48 c7 45 c0 00 00 00 00                         	mov    QWORD PTR [rbp-0x40],0x0
  ca2ea2:	e8 a9 84 fa ff                                  	call   0xc4b350
  ca2ea7:	4c 8b 25 d2 6f 8e 02                            	mov    r12,QWORD PTR [rip+0x28e6fd2]        # 0x3589e80
  ca2eae:	4d 85 e4                                        	test   r12,r12
  ca2eb1:	0f 84 d3 00 00 00                               	je     0xca2f8a
  ca2eb7:	31 db                                           	xor    ebx,ebx
  ca2eb9:	4c 89 7d b8                                     	mov    QWORD PTR [rbp-0x48],r15
  ca2ebd:	eb 1e                                           	jmp    0xca2edd
  ca2ebf:	90                                              	nop
  ca2ec0:	49 89 dd                                        	mov    r13,rbx
  ca2ec3:	4c 89 ff                                        	mov    rdi,r15
  ca2ec6:	31 f6                                           	xor    esi,esi
  ca2ec8:	31 d2                                           	xor    edx,edx
  ca2eca:	31 c9                                           	xor    ecx,ecx
  ca2ecc:	e8 cf 40 82 ff                                  	call   0x4c6fa0
  ca2ed1:	4d 8b 24 24                                     	mov    r12,QWORD PTR [r12]
  ca2ed5:	4c 89 eb                                        	mov    rbx,r13
  ca2ed8:	4d 85 e4                                        	test   r12,r12
  ca2edb:	74 6c                                           	je     0xca2f49
  ca2edd:	4d 8d bc 24 48 01 00 00                         	lea    r15,[r12+0x148]
  ca2ee5:	31 f6                                           	xor    esi,esi
  ca2ee7:	31 d2                                           	xor    edx,edx
  ca2ee9:	31 c9                                           	xor    ecx,ecx
  ca2eeb:	4c 89 ff                                        	mov    rdi,r15
  ca2eee:	e8 0d 3b 82 ff                                  	call   0x4c6a00
  ca2ef3:	49 63 84 24 60 04 00 00                         	movsxd rax,DWORD PTR [r12+0x460]
  ca2efb:	49 39 c6                                        	cmp    r14,rax
  ca2efe:	75 c0                                           	jne    0xca2ec0
  ca2f00:	49 8b 84 24 60 05 00 00                         	mov    rax,QWORD PTR [r12+0x560]
  ca2f08:	b9 01 01 00 00                                  	mov    ecx,0x101
  ca2f0d:	ba 16 01 00 00                                  	mov    edx,0x116
  ca2f12:	be 1c 01 00 00                                  	mov    esi,0x11c
  ca2f17:	c4 e2 70 f7 c8                                  	bextr  ecx,eax,ecx
  ca2f1c:	c4 e2 68 f7 d0                                  	bextr  edx,eax,edx
  ca2f21:	c4 e2 48 f7 f0                                  	bextr  esi,eax,esi
  ca2f26:	8d 0c 51                                        	lea    ecx,[rcx+rdx*2]
  ca2f29:	44 8d 2c b1                                     	lea    r13d,[rcx+rsi*4]
  ca2f2d:	b9 01 00 00 00                                  	mov    ecx,0x1
  ca2f32:	48 89 4d c0                                     	mov    QWORD PTR [rbp-0x40],rcx
  ca2f36:	49 09 dd                                        	or     r13,rbx
  ca2f39:	a9 02 00 40 10                                  	test   eax,0x10400002
  ca2f3e:	74 83                                           	je     0xca2ec3
  ca2f40:	4c 89 6d c8                                     	mov    QWORD PTR [rbp-0x38],r13
  ca2f44:	e9 7a ff ff ff                                  	jmp    0xca2ec3
  ca2f49:	48 8d 3d 10 6f 8e 02                            	lea    rdi,[rip+0x28e6f10]        # 0x3589e60
  ca2f50:	31 f6                                           	xor    esi,esi
  ca2f52:	31 d2                                           	xor    edx,edx
  ca2f54:	e8 a7 93 fa ff                                  	call   0xc4c300
  ca2f59:	83 7d c0 00                                     	cmp    DWORD PTR [rbp-0x40],0x0
  ca2f5d:	74 42                                           	je     0xca2fa1
  ca2f5f:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  ca2f68:	48 8d 35 28 c3 6a 00                            	lea    rsi,[rip+0x6ac328]        # 0x134f297
  ca2f6f:	31 d2                                           	xor    edx,edx
  ca2f71:	e8 6a 74 f7 ff                                  	call   0xc1a3e0
  ca2f76:	48 8b 75 b8                                     	mov    rsi,QWORD PTR [rbp-0x48]
  ca2f7a:	48 8d 7d c8                                     	lea    rdi,[rbp-0x38]
  ca2f7e:	ba 08 00 00 00                                  	mov    edx,0x8
  ca2f83:	e8 48 62 5b ff                                  	call   0x2591d0
  ca2f88:	eb 1c                                           	jmp    0xca2fa6
  ca2f8a:	48 8d 3d cf 6e 8e 02                            	lea    rdi,[rip+0x28e6ecf]        # 0x3589e60
  ca2f91:	31 f6                                           	xor    esi,esi
  ca2f93:	31 d2                                           	xor    edx,edx
  ca2f95:	e8 66 93 fa ff                                  	call   0xc4c300
  ca2f9a:	b8 03 00 00 00                                  	mov    eax,0x3
  ca2f9f:	eb 0c                                           	jmp    0xca2fad
  ca2fa1:	b8 03 00 00 00                                  	mov    eax,0x3
  ca2fa6:	48 8d 1d 63 93 c7 02                            	lea    rbx,[rip+0x2c79363]        # 0x391c310
  ca2fad:	48 8b 0b                                        	mov    rcx,QWORD PTR [rbx]
  ca2fb0:	48 3b 4d d0                                     	cmp    rcx,QWORD PTR [rbp-0x30]
  ca2fb4:	75 0f                                           	jne    0xca2fc5
  ca2fb6:	48 83 c4 28                                     	add    rsp,0x28
  ca2fba:	5b                                              	pop    rbx
  ca2fbb:	41 5c                                           	pop    r12
  ca2fbd:	41 5d                                           	pop    r13
  ca2fbf:	41 5e                                           	pop    r14
  ca2fc1:	41 5f                                           	pop    r15
  ca2fc3:	5d                                              	pop    rbp
  ca2fc4:	c3                                              	ret
  ca2fc5:	e8 e6 a6 a5 ff                                  	call   0x6fd6b0
  ca2fca:	0f 0b                                           	ud2
  ca2fcc:	90                                              	nop
  ca2fcd:	90                                              	nop
  ca2fce:	90                                              	nop
  ca2fcf:	90                                              	nop
  ca2fd0:	55                                              	push   rbp
  ca2fd1:	48 89 e5                                        	mov    rbp,rsp
  ca2fd4:	41 57                                           	push   r15
  ca2fd6:	41 56                                           	push   r14
  ca2fd8:	41 55                                           	push   r13
  ca2fda:	41 54                                           	push   r12
  ca2fdc:	53                                              	push   rbx
  ca2fdd:	50                                              	push   rax
  ca2fde:	4c 8d 25 9b 90 f5 01                            	lea    r12,[rip+0x1f5909b]        # 0x2bfc080
  ca2fe5:	48 89 d3                                        	mov    rbx,rdx
  ca2fe8:	41 89 f6                                        	mov    r14d,esi
  ca2feb:	41 89 ff                                        	mov    r15d,edi
  ca2fee:	bf 28 00 00 00                                  	mov    edi,0x28
  ca2ff3:	ba 02 01 00 00                                  	mov    edx,0x102
  ca2ff8:	4c 89 e6                                        	mov    rsi,r12
  ca2ffb:	e8 50 5b f6 ff                                  	call   0xc08b50
  ca3000:	49 89 c5                                        	mov    r13,rax
  ca3003:	48 c7 00 03 00 00 00                            	mov    QWORD PTR [rax],0x3
  ca300a:	48 c7 40 08 08 00 00 00                         	mov    QWORD PTR [rax+0x8],0x8
  ca3012:	49 c1 e7 20                                     	shl    r15,0x20
  ca3016:	44 89 f0                                        	mov    eax,r14d
  ca3019:	be 28 00 00 00                                  	mov    esi,0x28
  ca301e:	4c 09 f8                                        	or     rax,r15
  ca3021:	4c 89 ef                                        	mov    rdi,r13
  ca3024:	49 89 45 10                                     	mov    QWORD PTR [r13+0x10],rax
  ca3028:	49 c7 45 18 08 00 00 00                         	mov    QWORD PTR [r13+0x18],0x8
  ca3030:	49 89 5d 20                                     	mov    QWORD PTR [r13+0x20],rbx
  ca3034:	e8 57 7a ff ff                                  	call   0xc9aa90
  ca3039:	4c 89 ef                                        	mov    rdi,r13
  ca303c:	4c 89 e6                                        	mov    rsi,r12
  ca303f:	48 83 c4 08                                     	add    rsp,0x8
  ca3043:	5b                                              	pop    rbx
  ca3044:	41 5c                                           	pop    r12
  ca3046:	41 5d                                           	pop    r13
  ca3048:	41 5e                                           	pop    r14
  ca304a:	41 5f                                           	pop    r15
  ca304c:	5d                                              	pop    rbp
  ca304d:	e9 9e 5d f6 ff                                  	jmp    0xc08df0
  ca3052:	90                                              	nop
  ca3053:	90                                              	nop
  ca3054:	90                                              	nop
  ca3055:	90                                              	nop
  ca3056:	90                                              	nop
  ca3057:	90                                              	nop
  ca3058:	90                                              	nop
  ca3059:	90                                              	nop
  ca305a:	90                                              	nop
  ca305b:	90                                              	nop
  ca305c:	90                                              	nop
  ca305d:	90                                              	nop
  ca305e:	90                                              	nop
  ca305f:	90                                              	nop
  ca3060:	55                                              	push   rbp
  ca3061:	48 89 e5                                        	mov    rbp,rsp
  ca3064:	53                                              	push   rbx
  ca3065:	48 83 ec 48                                     	sub    rsp,0x48
  ca3069:	48 8d 1d a0 92 c7 02                            	lea    rbx,[rip+0x2c792a0]        # 0x391c310
  ca3070:	48 c1 e7 20                                     	shl    rdi,0x20
  ca3074:	48 8b 03                                        	mov    rax,QWORD PTR [rbx]
  ca3077:	48 89 45 f0                                     	mov    QWORD PTR [rbp-0x10],rax
  ca307b:	89 f0                                           	mov    eax,esi
  ca307d:	be 38 00 00 00                                  	mov    esi,0x38
  ca3082:	48 c7 45 b8 03 00 00 00                         	mov    QWORD PTR [rbp-0x48],0x3
  ca308a:	48 c7 45 c0 09 00 00 00                         	mov    QWORD PTR [rbp-0x40],0x9
  ca3092:	48 09 f8                                        	or     rax,rdi
  ca3095:	48 8d 7d b8                                     	lea    rdi,[rbp-0x48]
  ca3099:	48 89 45 c8                                     	mov    QWORD PTR [rbp-0x38],rax
  ca309d:	48 c7 45 d0 18 00 00 00                         	mov    QWORD PTR [rbp-0x30],0x18
  ca30a5:	48 89 55 d8                                     	mov    QWORD PTR [rbp-0x28],rdx
  ca30a9:	48 89 4d e0                                     	mov    QWORD PTR [rbp-0x20],rcx
  ca30ad:	44 89 45 e8                                     	mov    DWORD PTR [rbp-0x18],r8d
  ca30b1:	44 89 4d ec                                     	mov    DWORD PTR [rbp-0x14],r9d
  ca30b5:	e8 d6 79 ff ff                                  	call   0xc9aa90
  ca30ba:	48 8b 03                                        	mov    rax,QWORD PTR [rbx]
  ca30bd:	48 3b 45 f0                                     	cmp    rax,QWORD PTR [rbp-0x10]
  ca30c1:	75 07                                           	jne    0xca30ca
  ca30c3:	48 83 c4 48                                     	add    rsp,0x48
  ca30c7:	5b                                              	pop    rbx
  ca30c8:	5d                                              	pop    rbp
  ca30c9:	c3                                              	ret
  ca30ca:	e8 e1 a5 a5 ff                                  	call   0x6fd6b0
  ca30cf:	0f 0b                                           	ud2
  ca30d1:	90                                              	nop
  ca30d2:	90                                              	nop
  ca30d3:	90                                              	nop
  ca30d4:	90                                              	nop
  ca30d5:	90                                              	nop
  ca30d6:	90                                              	nop
  ca30d7:	90                                              	nop
  ca30d8:	90                                              	nop
  ca30d9:	90                                              	nop
  ca30da:	90                                              	nop
  ca30db:	90                                              	nop
  ca30dc:	90                                              	nop
  ca30dd:	90                                              	nop
  ca30de:	90                                              	nop
  ca30df:	90                                              	nop
  ca30e0:	55                                              	push   rbp
  ca30e1:	48 89 e5                                        	mov    rbp,rsp
  ca30e4:	83 fe 02                                        	cmp    esi,0x2
  ca30e7:	0f 84 bf 01 00 00                               	je     0xca32ac
  ca30ed:	83 fe 01                                        	cmp    esi,0x1
  ca30f0:	0f 84 aa 01 00 00                               	je     0xca32a0
  ca30f6:	b8 2d 00 00 00                                  	mov    eax,0x2d
  ca30fb:	85 f6                                           	test   esi,esi
  ca30fd:	0f 85 ab 01 00 00                               	jne    0xca32ae
  ca3103:	48 8d 15 e3 ae 6c 00                            	lea    rdx,[rip+0x6caee3]        # 0x136dfed
  ca310a:	48 8d 3d 8f a7 16 03                            	lea    rdi,[rip+0x316a78f]        # 0x3e0d8a0
  ca3111:	c7 05 91 a7 16 03 00 00 00 00                   	mov    DWORD PTR [rip+0x316a791],0x0        # 0x3e0d8ac
  ca311b:	c7 05 83 a7 16 03 00 00 00 00                   	mov    DWORD PTR [rip+0x316a783],0x0        # 0x3e0d8a8
  ca3125:	31 c9                                           	xor    ecx,ecx
  ca3127:	48 89 d6                                        	mov    rsi,rdx
  ca312a:	e8 a1 4c 82 ff                                  	call   0x4c7dd0
  ca312f:	4c 8d 15 e7 0b 5f 00                            	lea    r10,[rip+0x5f0be7]        # 0x1293d1d
  ca3136:	48 8d 05 33 a7 16 03                            	lea    rax,[rip+0x316a733]        # 0x3e0d870
  ca313d:	48 c7 05 28 a7 16 03 00 00 00 00                	mov    QWORD PTR [rip+0x316a728],0x0        # 0x3e0d870
  ca3148:	48 8d 35 31 10 f6 01                            	lea    rsi,[rip+0x1f61031]        # 0x2c04180
  ca314f:	bf 10 00 00 00                                  	mov    edi,0x10
  ca3154:	31 d2                                           	xor    edx,edx
  ca3156:	31 c9                                           	xor    ecx,ecx
  ca3158:	45 31 c0                                        	xor    r8d,r8d
  ca315b:	45 31 c9                                        	xor    r9d,r9d
  ca315e:	48 89 05 13 a7 16 03                            	mov    QWORD PTR [rip+0x316a713],rax        # 0x3e0d878
  ca3165:	31 c0                                           	xor    eax,eax
  ca3167:	41 52                                           	push   r10
  ca3169:	68 80 01 00 00                                  	push   0x180
  ca316e:	e8 fd c3 a3 ff                                  	call   0x6df570
  ca3173:	48 83 c4 10                                     	add    rsp,0x10
  ca3177:	48 8d 35 20 45 64 00                            	lea    rsi,[rip+0x644520]        # 0x12e769e
  ca317e:	48 8d 15 93 4c 5c ff                            	lea    rdx,[rip+0xffffffffff5c4c93]        # 0x267e18
  ca3185:	48 8d 0d f4 1f 66 00                            	lea    rcx,[rip+0x661ff4]        # 0x1305180
  ca318c:	41 b9 20 4e 00 00                               	mov    r9d,0x4e20
  ca3192:	48 89 05 e7 a6 16 03                            	mov    QWORD PTR [rip+0x316a6e7],rax        # 0x3e0d880
  ca3199:	31 ff                                           	xor    edi,edi
  ca319b:	45 31 c0                                        	xor    r8d,r8d
  ca319e:	e8 9d ab a9 ff                                  	call   0x73dd40
  ca31a3:	48 8d 35 34 11 6e 00                            	lea    rsi,[rip+0x6e1134]        # 0x13842de
  ca31aa:	48 8d 15 8f 52 5c ff                            	lea    rdx,[rip+0xffffffffff5c528f]        # 0x268440
  ca31b1:	48 8d 0d e1 8e 63 00                            	lea    rcx,[rip+0x638ee1]        # 0x12dc099
  ca31b8:	41 b9 20 4e 00 00                               	mov    r9d,0x4e20
  ca31be:	48 89 05 9b a7 16 03                            	mov    QWORD PTR [rip+0x316a79b],rax        # 0x3e0d960
  ca31c5:	31 ff                                           	xor    edi,edi
  ca31c7:	45 31 c0                                        	xor    r8d,r8d
  ca31ca:	e8 71 ab a9 ff                                  	call   0x73dd40
  ca31cf:	48 8d 35 b5 79 69 00                            	lea    rsi,[rip+0x6979b5]        # 0x133ab8b
  ca31d6:	48 8d 15 43 4c 5c ff                            	lea    rdx,[rip+0xffffffffff5c4c43]        # 0x267e20
  ca31dd:	48 8d 0d 28 bd 5d 00                            	lea    rcx,[rip+0x5dbd28]        # 0x127ef0c
  ca31e4:	41 b9 20 4e 00 00                               	mov    r9d,0x4e20
  ca31ea:	48 89 05 77 a7 16 03                            	mov    QWORD PTR [rip+0x316a777],rax        # 0x3e0d968
  ca31f1:	31 ff                                           	xor    edi,edi
  ca31f3:	45 31 c0                                        	xor    r8d,r8d
  ca31f6:	e8 45 ab a9 ff                                  	call   0x73dd40
  ca31fb:	48 8d 35 c5 1f 68 00                            	lea    rsi,[rip+0x681fc5]        # 0x13251c7
  ca3202:	48 8d 15 8f ca 5c ff                            	lea    rdx,[rip+0xffffffffff5cca8f]        # 0x26fc98
  ca3209:	48 8d 0d 17 e9 62 00                            	lea    rcx,[rip+0x62e917]        # 0x12d1b27
  ca3210:	41 b9 20 4e 00 00                               	mov    r9d,0x4e20
  ca3216:	48 89 05 53 a7 16 03                            	mov    QWORD PTR [rip+0x316a753],rax        # 0x3e0d970
  ca321d:	31 ff                                           	xor    edi,edi
  ca321f:	45 31 c0                                        	xor    r8d,r8d
  ca3222:	e8 19 ab a9 ff                                  	call   0x73dd40
  ca3227:	48 8d 35 dd c8 68 00                            	lea    rsi,[rip+0x68c8dd]        # 0x132fb0b
  ca322e:	48 8d 15 f3 4b 5c ff                            	lea    rdx,[rip+0xffffffffff5c4bf3]        # 0x267e28
  ca3235:	48 8d 0d 18 a3 6e 00                            	lea    rcx,[rip+0x6ea318]        # 0x138d554
  ca323c:	41 b9 20 4e 00 00                               	mov    r9d,0x4e20
  ca3242:	48 89 05 2f a7 16 03                            	mov    QWORD PTR [rip+0x316a72f],rax        # 0x3e0d978
  ca3249:	31 ff                                           	xor    edi,edi
  ca324b:	45 31 c0                                        	xor    r8d,r8d
  ca324e:	e8 ed aa a9 ff                                  	call   0x73dd40
  ca3253:	48 8d 35 13 fd 6f 00                            	lea    rsi,[rip+0x6ffd13]        # 0x13a2f6d
  ca325a:	48 8d 15 cf 4b 5c ff                            	lea    rdx,[rip+0xffffffffff5c4bcf]        # 0x267e30
  ca3261:	48 8d 0d b9 bc 5d 00                            	lea    rcx,[rip+0x5dbcb9]        # 0x127ef21
  ca3268:	41 b9 20 4e 00 00                               	mov    r9d,0x4e20
  ca326e:	48 89 05 0b a7 16 03                            	mov    QWORD PTR [rip+0x316a70b],rax        # 0x3e0d980
  ca3275:	31 ff                                           	xor    edi,edi
  ca3277:	45 31 c0                                        	xor    r8d,r8d
  ca327a:	e8 c1 aa a9 ff                                  	call   0x73dd40
  ca327f:	48 8d 3d 2a a6 16 03                            	lea    rdi,[rip+0x316a62a]        # 0x3e0d8b0
  ca3286:	be 78 00 00 00                                  	mov    esi,0x78
  ca328b:	48 89 05 f6 a6 16 03                            	mov    QWORD PTR [rip+0x316a6f6],rax        # 0x3e0d988
  ca3292:	e8 59 5d 5b ff                                  	call   0x258ff0
  ca3297:	c6 05 82 a4 16 03 01                            	mov    BYTE PTR [rip+0x316a482],0x1        # 0x3e0d720
  ca329e:	eb 0c                                           	jmp    0xca32ac
  ca32a0:	48 8b 3d d9 a5 16 03                            	mov    rdi,QWORD PTR [rip+0x316a5d9]        # 0x3e0d880
  ca32a7:	e8 04 c9 a3 ff                                  	call   0x6dfbb0
  ca32ac:	31 c0                                           	xor    eax,eax
  ca32ae:	5d                                              	pop    rbp
  ca32af:	c3                                              	ret
  ca32b0:	55                                              	push   rbp
  ca32b1:	48 89 e5                                        	mov    rbp,rsp
  ca32b4:	41 57                                           	push   r15
  ca32b6:	41 56                                           	push   r14
  ca32b8:	41 55                                           	push   r13
  ca32ba:	41 54                                           	push   r12
  ca32bc:	53                                              	push   rbx
  ca32bd:	48 83 ec 18                                     	sub    rsp,0x18
  ca32c1:	48 8d 3d a0 a5 16 03                            	lea    rdi,[rip+0x316a5a0]        # 0x3e0d868
  ca32c8:	49 89 f6                                        	mov    r14,rsi
  ca32cb:	45 31 ed                                        	xor    r13d,r13d
  ca32ce:	31 f6                                           	xor    esi,esi
  ca32d0:	31 d2                                           	xor    edx,edx
  ca32d2:	31 c9                                           	xor    ecx,ecx
  ca32d4:	e8 27 37 82 ff                                  	call   0x4c6a00
  ca32d9:	48 83 3d 8f a5 16 03 00                         	cmp    QWORD PTR [rip+0x316a58f],0x0        # 0x3e0d870
  ca32e1:	75 2f                                           	jne    0xca3312
  ca32e3:	48 8b 3d 96 a5 16 03                            	mov    rdi,QWORD PTR [rip+0x316a596]        # 0x3e0d880
  ca32ea:	48 8d 35 5f a5 16 03                            	lea    rsi,[rip+0x316a55f]        # 0x3e0d850
  ca32f1:	48 8d 0d 80 1e 66 00                            	lea    rcx,[rip+0x661e80]        # 0x1305178
  ca32f8:	ba 00 10 00 00                                  	mov    edx,0x1000
  ca32fd:	c7 04 24 00 01 00 00                            	mov    DWORD PTR [rsp],0x100
  ca3304:	45 31 c0                                        	xor    r8d,r8d
  ca3307:	45 31 c9                                        	xor    r9d,r9d
  ca330a:	e8 51 2f f6 ff                                  	call   0xc06260
  ca330f:	41 89 c5                                        	mov    r13d,eax
  ca3312:	48 8d 3d 4f a5 16 03                            	lea    rdi,[rip+0x316a54f]        # 0x3e0d868
  ca3319:	31 f6                                           	xor    esi,esi
  ca331b:	31 d2                                           	xor    edx,edx
  ca331d:	31 c9                                           	xor    ecx,ecx
  ca331f:	e8 7c 3c 82 ff                                  	call   0x4c6fa0
  ca3324:	48 8d 35 55 8d f5 01                            	lea    rsi,[rip+0x1f58d55]        # 0x2bfc080
  ca332b:	bf 00 40 00 00                                  	mov    edi,0x4000
  ca3330:	ba 02 00 00 00                                  	mov    edx,0x2
  ca3335:	e8 16 58 f6 ff                                  	call   0xc08b50
  ca333a:	4d 8b 66 18                                     	mov    r12,QWORD PTR [r14+0x18]
  ca333e:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  ca3342:	4d 85 e4                                        	test   r12,r12
  ca3345:	0f 9f c0                                        	setg   al
  ca3348:	45 85 ed                                        	test   r13d,r13d
  ca334b:	0f 94 c1                                        	sete   cl
  ca334e:	20 c1                                           	and    cl,al
  ca3350:	80 f9 01                                        	cmp    cl,0x1
  ca3353:	0f 85 29 01 00 00                               	jne    0xca3482
  ca3359:	0f 1f 80 00 00 00 00                            	nop    DWORD PTR [rax+0x0]
  ca3360:	49 81 fc 00 40 00 00                            	cmp    r12,0x4000
  ca3367:	b8 00 40 00 00                                  	mov    eax,0x4000
  ca336c:	48 8d 3d f5 a4 16 03                            	lea    rdi,[rip+0x316a4f5]        # 0x3e0d868
  ca3373:	4c 0f 43 e0                                     	cmovae r12,rax
  ca3377:	31 f6                                           	xor    esi,esi
  ca3379:	31 d2                                           	xor    edx,edx
  ca337b:	31 c9                                           	xor    ecx,ecx
  ca337d:	e8 7e 36 82 ff                                  	call   0x4c6a00
  ca3382:	48 8b 1d e7 a4 16 03                            	mov    rbx,QWORD PTR [rip+0x316a4e7]        # 0x3e0d870
  ca3389:	48 85 db                                        	test   rbx,rbx
  ca338c:	0f 84 db 00 00 00                               	je     0xca346d
  ca3392:	48 63 43 10                                     	movsxd rax,DWORD PTR [rbx+0x10]
  ca3396:	44 8b 7b 14                                     	mov    r15d,DWORD PTR [rbx+0x14]
  ca339a:	48 89 c6                                        	mov    rsi,rax
  ca339d:	48 03 73 08                                     	add    rsi,QWORD PTR [rbx+0x8]
  ca33a1:	41 29 c7                                        	sub    r15d,eax
  ca33a4:	45 39 e7                                        	cmp    r15d,r12d
  ca33a7:	7d 77                                           	jge    0xca3420
  ca33a9:	48 8b 7d d0                                     	mov    rdi,QWORD PTR [rbp-0x30]
  ca33ad:	49 63 d7                                        	movsxd rdx,r15d
  ca33b0:	e8 fb 5c 5b ff                                  	call   0x2590b0
  ca33b5:	48 8b 05 b4 a4 16 03                            	mov    rax,QWORD PTR [rip+0x316a4b4]        # 0x3e0d870
  ca33bc:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  ca33bf:	48 89 05 aa a4 16 03                            	mov    QWORD PTR [rip+0x316a4aa],rax        # 0x3e0d870
  ca33c6:	48 85 c0                                        	test   rax,rax
  ca33c9:	75 0e                                           	jne    0xca33d9
  ca33cb:	48 8d 05 9e a4 16 03                            	lea    rax,[rip+0x316a49e]        # 0x3e0d870
  ca33d2:	48 89 05 9f a4 16 03                            	mov    QWORD PTR [rip+0x316a49f],rax        # 0x3e0d878
  ca33d9:	48 8d 3d 88 a4 16 03                            	lea    rdi,[rip+0x316a488]        # 0x3e0d868
  ca33e0:	45 31 ed                                        	xor    r13d,r13d
  ca33e3:	31 f6                                           	xor    esi,esi
  ca33e5:	31 d2                                           	xor    edx,edx
  ca33e7:	31 c9                                           	xor    ecx,ecx
  ca33e9:	e8 b2 3b 82 ff                                  	call   0x4c6fa0
  ca33ee:	48 8b 7b 08                                     	mov    rdi,QWORD PTR [rbx+0x8]
  ca33f2:	4c 8d 25 a7 09 f6 01                            	lea    r12,[rip+0x1f609a7]        # 0x2c03da0
  ca33f9:	4c 89 e6                                        	mov    rsi,r12
  ca33fc:	e8 ef 59 f6 ff                                  	call   0xc08df0
  ca3401:	48 89 df                                        	mov    rdi,rbx
  ca3404:	4c 89 e6                                        	mov    rsi,r12
  ca3407:	e8 e4 59 f6 ff                                  	call   0xc08df0
  ca340c:	45 85 ff                                        	test   r15d,r15d
  ca340f:	75 36                                           	jne    0xca3447
  ca3411:	eb 6f                                           	jmp    0xca3482
  ca3413:	66 66 66 66 2e 0f 1f 84 00 00 00 00 00          	data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  ca3420:	48 8b 7d d0                                     	mov    rdi,QWORD PTR [rbp-0x30]
  ca3424:	44 01 e0                                        	add    eax,r12d
  ca3427:	4c 89 e2                                        	mov    rdx,r12
  ca342a:	89 43 10                                        	mov    DWORD PTR [rbx+0x10],eax
  ca342d:	e8 7e 5c 5b ff                                  	call   0x2590b0
  ca3432:	48 8d 3d 2f a4 16 03                            	lea    rdi,[rip+0x316a42f]        # 0x3e0d868
  ca3439:	31 f6                                           	xor    esi,esi
  ca343b:	31 d2                                           	xor    edx,edx
  ca343d:	31 c9                                           	xor    ecx,ecx
  ca343f:	e8 5c 3b 82 ff                                  	call   0x4c6fa0
  ca3444:	45 89 e7                                        	mov    r15d,r12d
  ca3447:	48 8b 7d d0                                     	mov    rdi,QWORD PTR [rbp-0x30]
  ca344b:	44 89 fe                                        	mov    esi,r15d
  ca344e:	4c 89 f2                                        	mov    rdx,r14
  ca3451:	e8 ca f0 ad ff                                  	call   0x782520
  ca3456:	4d 8b 66 18                                     	mov    r12,QWORD PTR [r14+0x18]
  ca345a:	41 89 c5                                        	mov    r13d,eax
  ca345d:	4d 85 e4                                        	test   r12,r12
  ca3460:	7e 20                                           	jle    0xca3482
  ca3462:	45 85 ed                                        	test   r13d,r13d
  ca3465:	0f 84 f5 fe ff ff                               	je     0xca3360
  ca346b:	eb 15                                           	jmp    0xca3482
  ca346d:	48 8d 3d f4 a3 16 03                            	lea    rdi,[rip+0x316a3f4]        # 0x3e0d868
  ca3474:	45 31 ed                                        	xor    r13d,r13d
  ca3477:	31 f6                                           	xor    esi,esi
  ca3479:	31 d2                                           	xor    edx,edx
  ca347b:	31 c9                                           	xor    ecx,ecx
  ca347d:	e8 1e 3b 82 ff                                  	call   0x4c6fa0
  ca3482:	48 8d 35 f7 8b f5 01                            	lea    rsi,[rip+0x1f58bf7]        # 0x2bfc080
  ca3489:	48 8b 7d d0                                     	mov    rdi,QWORD PTR [rbp-0x30]
  ca348d:	e8 5e 59 f6 ff                                  	call   0xc08df0
  ca3492:	44 89 e8                                        	mov    eax,r13d
  ca3495:	48 83 c4 18                                     	add    rsp,0x18
  ca3499:	5b                                              	pop    rbx
  ca349a:	41 5c                                           	pop    r12
  ca349c:	41 5d                                           	pop    r13
  ca349e:	41 5e                                           	pop    r14
  ca34a0:	41 5f                                           	pop    r15
  ca34a2:	5d                                              	pop    rbp
  ca34a3:	c3                                              	ret
  ca34a4:	90                                              	nop
  ca34a5:	90                                              	nop
  ca34a6:	90                                              	nop
  ca34a7:	90                                              	nop
  ca34a8:	90                                              	nop
  ca34a9:	90                                              	nop
  ca34aa:	90                                              	nop
  ca34ab:	90                                              	nop
  ca34ac:	90                                              	nop
  ca34ad:	90                                              	nop
  ca34ae:	90                                              	nop
  ca34af:	90                                              	nop
  ca34b0:	55                                              	push   rbp
  ca34b1:	48 89 e5                                        	mov    rbp,rsp
  ca34b4:	41 57                                           	push   r15
  ca34b6:	41 56                                           	push   r14
  ca34b8:	41 55                                           	push   r13
  ca34ba:	41 54                                           	push   r12
  ca34bc:	53                                              	push   rbx
  ca34bd:	48 83 ec 48                                     	sub    rsp,0x48
  ca34c1:	48 8d 05 48 8e c7 02                            	lea    rax,[rip+0x2c78e48]        # 0x391c310
  ca34c8:	49 89 f7                                        	mov    r15,rsi
  ca34cb:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  ca34ce:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  ca34d2:	8b 86 2c 0a 00 00                               	mov    eax,DWORD PTR [rsi+0xa2c]
  ca34d8:	8b 8e 60 05 00 00                               	mov    ecx,DWORD PTR [rsi+0x560]
  ca34de:	c1 e0 08                                        	shl    eax,0x8
  ca34e1:	f7 d1                                           	not    ecx
  ca34e3:	0f b7 c0                                        	movzx  eax,ax
  ca34e6:	0b 86 30 0a 00 00                               	or     eax,DWORD PTR [rsi+0xa30]
  ca34ec:	89 c2                                           	mov    edx,eax
  ca34ee:	81 ca 80 00 00 00                               	or     edx,0x80
  ca34f4:	f6 c1 09                                        	test   cl,0x9
  ca34f7:	0f 45 d0                                        	cmovne edx,eax
  ca34fa:	48 8b 46 10                                     	mov    rax,QWORD PTR [rsi+0x10]
  ca34fe:	89 55 ac                                        	mov    DWORD PTR [rbp-0x54],edx
  ca3501:	48 85 c0                                        	test   rax,rax
  ca3504:	74 7c                                           	je     0xca3582
  ca3506:	48 8b 48 08                                     	mov    rcx,QWORD PTR [rax+0x8]
  ca350a:	48 85 c9                                        	test   rcx,rcx
  ca350d:	74 73                                           	je     0xca3582
  ca350f:	48 8d 15 e2 59 8e 02                            	lea    rdx,[rip+0x28e59e2]        # 0x3588ef8
  ca3516:	48 39 d1                                        	cmp    rcx,rdx
  ca3519:	74 67                                           	je     0xca3582
  ca351b:	48 8b 91 60 05 00 00                            	mov    rdx,QWORD PTR [rcx+0x560]
  ca3522:	83 e2 01                                        	and    edx,0x1
  ca3525:	74 5b                                           	je     0xca3582
  ca3527:	48 8b 91 e0 00 00 00                            	mov    rdx,QWORD PTR [rcx+0xe0]
  ca352e:	48 85 d2                                        	test   rdx,rdx
  ca3531:	74 09                                           	je     0xca353c
  ca3533:	83 ba bc 00 00 00 00                            	cmp    DWORD PTR [rdx+0xbc],0x0
  ca353a:	74 46                                           	je     0xca3582
  ca353c:	8b 89 bc 00 00 00                               	mov    ecx,DWORD PTR [rcx+0xbc]
  ca3542:	8b 80 9c 00 00 00                               	mov    eax,DWORD PTR [rax+0x9c]
  ca3548:	48 c7 45 b0 03 00 00 00                         	mov    QWORD PTR [rbp-0x50],0x3
  ca3550:	48 c7 45 b8 06 00 00 00                         	mov    QWORD PTR [rbp-0x48],0x6
  ca3558:	48 c1 e1 20                                     	shl    rcx,0x20
  ca355c:	48 09 c1                                        	or     rcx,rax
  ca355f:	80 3d ba a1 16 03 01                            	cmp    BYTE PTR [rip+0x316a1ba],0x1        # 0x3e0d720
  ca3566:	48 89 4d c0                                     	mov    QWORD PTR [rbp-0x40],rcx
  ca356a:	48 c7 45 c8 00 00 00 00                         	mov    QWORD PTR [rbp-0x38],0x0
  ca3572:	75 0e                                           	jne    0xca3582
  ca3574:	48 8d 7d b0                                     	lea    rdi,[rbp-0x50]
  ca3578:	be 20 00 00 00                                  	mov    esi,0x20
  ca357d:	e8 0e 75 ff ff                                  	call   0xc9aa90
  ca3582:	48 8d 3d b7 68 8e 02                            	lea    rdi,[rip+0x28e68b7]        # 0x3589e40
  ca3589:	31 db                                           	xor    ebx,ebx
  ca358b:	31 f6                                           	xor    esi,esi
  ca358d:	31 d2                                           	xor    edx,edx
  ca358f:	31 c9                                           	xor    ecx,ecx
  ca3591:	e8 ba 7d fa ff                                  	call   0xc4b350
  ca3596:	4d 8d af 48 01 00 00                            	lea    r13,[r15+0x148]
  ca359d:	31 f6                                           	xor    esi,esi
  ca359f:	31 d2                                           	xor    edx,edx
  ca35a1:	31 c9                                           	xor    ecx,ecx
  ca35a3:	4c 89 ef                                        	mov    rdi,r13
  ca35a6:	e8 55 34 82 ff                                  	call   0x4c6a00
  ca35ab:	49 8b 87 e0 00 00 00                            	mov    rax,QWORD PTR [r15+0xe0]
  ca35b2:	48 85 c0                                        	test   rax,rax
  ca35b5:	74 10                                           	je     0xca35c7
  ca35b7:	48 8b 78 40                                     	mov    rdi,QWORD PTR [rax+0x40]
  ca35bb:	e8 50 5b 96 ff                                  	call   0x609110
  ca35c0:	31 db                                           	xor    ebx,ebx
  ca35c2:	85 c0                                           	test   eax,eax
  ca35c4:	0f 95 c3                                        	setne  bl
  ca35c7:	49 8b 7f 40                                     	mov    rdi,QWORD PTR [r15+0x40]
  ca35cb:	e8 40 5b 96 ff                                  	call   0x609110
  ca35d0:	85 c0                                           	test   eax,eax
  ca35d2:	74 15                                           	je     0xca35e9
  ca35d4:	41 8b 87 bc 00 00 00                            	mov    eax,DWORD PTR [r15+0xbc]
  ca35db:	3b 05 af 7a 90 02                               	cmp    eax,DWORD PTR [rip+0x2907aaf]        # 0x35ab090
  ca35e1:	8d 4b 02                                        	lea    ecx,[rbx+0x2]
  ca35e4:	0f 44 cb                                        	cmove  ecx,ebx
  ca35e7:	89 cb                                           	mov    ebx,ecx
  ca35e9:	4d 8b b7 68 05 00 00                            	mov    r14,QWORD PTR [r15+0x568]
  ca35f0:	4c 89 ef                                        	mov    rdi,r13
  ca35f3:	49 c7 87 68 05 00 00 00 00 00 00                	mov    QWORD PTR [r15+0x568],0x0
  ca35fe:	31 f6                                           	xor    esi,esi
  ca3600:	31 d2                                           	xor    edx,edx
  ca3602:	31 c9                                           	xor    ecx,ecx
  ca3604:	e8 97 39 82 ff                                  	call   0x4c6fa0
  ca3609:	48 8d 3d 30 68 8e 02                            	lea    rdi,[rip+0x28e6830]        # 0x3589e40
  ca3610:	31 f6                                           	xor    esi,esi
  ca3612:	31 d2                                           	xor    edx,edx
  ca3614:	e8 e7 8c fa ff                                  	call   0xc4c300
  ca3619:	4c 89 ef                                        	mov    rdi,r13
  ca361c:	31 f6                                           	xor    esi,esi
  ca361e:	31 d2                                           	xor    edx,edx
  ca3620:	31 c9                                           	xor    ecx,ecx
  ca3622:	e8 d9 33 82 ff                                  	call   0x4c6a00
  ca3627:	4c 89 6d 98                                     	mov    QWORD PTR [rbp-0x68],r13
  ca362b:	4d 85 f6                                        	test   r14,r14
  ca362e:	74 7a                                           	je     0xca36aa
  ca3630:	49 8d bf 60 05 00 00                            	lea    rdi,[r15+0x560]
  ca3637:	48 8b 07                                        	mov    rax,QWORD PTR [rdi]
  ca363a:	48 a9 00 00 00 80                               	test   rax,0xffffffff80000000
  ca3640:	74 58                                           	je     0xca369a
  ca3642:	25 ff ff ff 7f                                  	and    eax,0x7fffffff
  ca3647:	48 89 07                                        	mov    QWORD PTR [rdi],rax
  ca364a:	41 c7 86 00 01 00 00 07 00 00 00                	mov    DWORD PTR [r14+0x100],0x7
  ca3655:	e8 b6 32 f6 ff                                  	call   0xc06910
  ca365a:	4c 89 ef                                        	mov    rdi,r13
  ca365d:	31 f6                                           	xor    esi,esi
  ca365f:	31 d2                                           	xor    edx,edx
  ca3661:	31 c9                                           	xor    ecx,ecx
  ca3663:	e8 38 39 82 ff                                  	call   0x4c6fa0
  ca3668:	4d 8d a6 30 01 00 00                            	lea    r12,[r14+0x130]
  ca366f:	90                                              	nop
  ca3670:	48 8b 3d 29 34 f5 02                            	mov    rdi,QWORD PTR [rip+0x2f53429]        # 0x3bf6aa0
  ca3677:	4c 89 e6                                        	mov    rsi,r12
  ca367a:	31 d2                                           	xor    edx,edx
  ca367c:	e8 df 7a 84 ff                                  	call   0x4eb160
  ca3681:	85 c0                                           	test   eax,eax
  ca3683:	0f 84 11 04 00 00                               	je     0xca3a9a
  ca3689:	48 8b 3d 10 34 f5 02                            	mov    rdi,QWORD PTR [rip+0x2f53410]        # 0x3bf6aa0
  ca3690:	4c 89 e6                                        	mov    rsi,r12
  ca3693:	e8 28 7d 84 ff                                  	call   0x4eb3c0
  ca3698:	eb d6                                           	jmp    0xca3670
  ca369a:	41 c7 86 00 01 00 00 07 00 00 00                	mov    DWORD PTR [r14+0x100],0x7
  ca36a5:	e8 66 32 f6 ff                                  	call   0xc06910
  ca36aa:	4c 89 ef                                        	mov    rdi,r13
  ca36ad:	31 f6                                           	xor    esi,esi
  ca36af:	31 d2                                           	xor    edx,edx
  ca36b1:	31 c9                                           	xor    ecx,ecx
  ca36b3:	e8 e8 38 82 ff                                  	call   0x4c6fa0
  ca36b8:	4c 8d 25 c1 89 f5 01                            	lea    r12,[rip+0x1f589c1]        # 0x2bfc080
  ca36bf:	4c 89 7d a0                                     	mov    QWORD PTR [rbp-0x60],r15
  ca36c3:	45 8b bf bc 00 00 00                            	mov    r15d,DWORD PTR [r15+0xbc]
  ca36ca:	bf 28 00 00 00                                  	mov    edi,0x28
  ca36cf:	ba 02 01 00 00                                  	mov    edx,0x102
  ca36d4:	4c 89 e6                                        	mov    rsi,r12
  ca36d7:	e8 74 54 f6 ff                                  	call   0xc08b50
  ca36dc:	48 63 4d ac                                     	movsxd rcx,DWORD PTR [rbp-0x54]
  ca36e0:	49 89 c5                                        	mov    r13,rax
  ca36e3:	49 c1 e7 20                                     	shl    r15,0x20
  ca36e7:	be 28 00 00 00                                  	mov    esi,0x28
  ca36ec:	48 c7 00 03 00 00 00                            	mov    QWORD PTR [rax],0x3
  ca36f3:	48 c7 40 08 02 00 00 00                         	mov    QWORD PTR [rax+0x8],0x2
  ca36fb:	4c 89 ef                                        	mov    rdi,r13
  ca36fe:	4c 09 f9                                        	or     rcx,r15
  ca3701:	49 89 4d 10                                     	mov    QWORD PTR [r13+0x10],rcx
  ca3705:	49 c7 45 18 08 00 00 00                         	mov    QWORD PTR [r13+0x18],0x8
  ca370d:	41 89 5d 20                                     	mov    DWORD PTR [r13+0x20],ebx
  ca3711:	e8 7a 73 ff ff                                  	call   0xc9aa90
  ca3716:	4c 89 ef                                        	mov    rdi,r13
  ca3719:	4c 89 e6                                        	mov    rsi,r12
  ca371c:	e8 cf 56 f6 ff                                  	call   0xc08df0
  ca3721:	4c 8b 6d 98                                     	mov    r13,QWORD PTR [rbp-0x68]
  ca3725:	31 f6                                           	xor    esi,esi
  ca3727:	31 d2                                           	xor    edx,edx
  ca3729:	31 c9                                           	xor    ecx,ecx
  ca372b:	4c 89 ef                                        	mov    rdi,r13
  ca372e:	e8 cd 32 82 ff                                  	call   0x4c6a00
  ca3733:	4d 85 f6                                        	test   r14,r14
  ca3736:	74 0b                                           	je     0xca3743
  ca3738:	41 c7 86 c8 00 00 00 ff ff ff ff                	mov    DWORD PTR [r14+0xc8],0xffffffff
  ca3743:	4c 8b 7d a0                                     	mov    r15,QWORD PTR [rbp-0x60]
  ca3747:	49 8b 5f 10                                     	mov    rbx,QWORD PTR [r15+0x10]
  ca374b:	48 85 db                                        	test   rbx,rbx
  ca374e:	74 74                                           	je     0xca37c4
  ca3750:	4c 8d 25 b9 06 f6 01                            	lea    r12,[rip+0x1f606b9]        # 0x2c03e10
  ca3757:	eb 10                                           	jmp    0xca3769
  ca3759:	0f 1f 80 00 00 00 00                            	nop    DWORD PTR [rax+0x0]
  ca3760:	48 8b 5b 10                                     	mov    rbx,QWORD PTR [rbx+0x10]
  ca3764:	48 85 db                                        	test   rbx,rbx
  ca3767:	74 5b                                           	je     0xca37c4
  ca3769:	48 8b 83 28 05 00 00                            	mov    rax,QWORD PTR [rbx+0x528]
  ca3770:	a9 00 04 00 00                                  	test   eax,0x400
  ca3775:	74 e9                                           	je     0xca3760
  ca3777:	48 25 ff fb ff ff                               	and    rax,0xfffffffffffffbff
  ca377d:	48 89 83 28 05 00 00                            	mov    QWORD PTR [rbx+0x528],rax
  ca3784:	48 8b bb 78 05 00 00                            	mov    rdi,QWORD PTR [rbx+0x578]
  ca378b:	48 85 ff                                        	test   rdi,rdi
  ca378e:	74 13                                           	je     0xca37a3
  ca3790:	4c 89 e6                                        	mov    rsi,r12
  ca3793:	e8 58 56 f6 ff                                  	call   0xc08df0
  ca3798:	48 c7 83 78 05 00 00 00 00 00 00                	mov    QWORD PTR [rbx+0x578],0x0
  ca37a3:	48 8b bb 80 05 00 00                            	mov    rdi,QWORD PTR [rbx+0x580]
  ca37aa:	48 85 ff                                        	test   rdi,rdi
  ca37ad:	74 b1                                           	je     0xca3760
  ca37af:	4c 89 e6                                        	mov    rsi,r12
  ca37b2:	e8 39 56 f6 ff                                  	call   0xc08df0
  ca37b7:	48 c7 83 80 05 00 00 00 00 00 00                	mov    QWORD PTR [rbx+0x580],0x0
  ca37c2:	eb 9c                                           	jmp    0xca3760
  ca37c4:	4c 89 ef                                        	mov    rdi,r13
  ca37c7:	31 f6                                           	xor    esi,esi
  ca37c9:	31 d2                                           	xor    edx,edx
  ca37cb:	31 c9                                           	xor    ecx,ecx
  ca37cd:	e8 ce 37 82 ff                                  	call   0x4c6fa0
  ca37d2:	4d 85 f6                                        	test   r14,r14
  ca37d5:	0f 84 51 02 00 00                               	je     0xca3a2c
  ca37db:	4d 8b be d0 00 00 00                            	mov    r15,QWORD PTR [r14+0xd0]
  ca37e2:	4d 85 ff                                        	test   r15,r15
  ca37e5:	74 6a                                           	je     0xca3851
  ca37e7:	49 8d 9e d0 00 00 00                            	lea    rbx,[r14+0xd0]
  ca37ee:	4c 8d 25 1b 06 f6 01                            	lea    r12,[rip+0x1f6061b]        # 0x2c03e10
  ca37f5:	eb 1c                                           	jmp    0xca3813
  ca37f7:	66 0f 1f 84 00 00 00 00 00                      	nop    WORD PTR [rax+rax*1+0x0]
  ca3800:	4c 89 ff                                        	mov    rdi,r15
  ca3803:	4c 89 e6                                        	mov    rsi,r12
  ca3806:	e8 e5 55 f6 ff                                  	call   0xc08df0
  ca380b:	4c 8b 3b                                        	mov    r15,QWORD PTR [rbx]
  ca380e:	4d 85 ff                                        	test   r15,r15
  ca3811:	74 3e                                           	je     0xca3851
  ca3813:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  ca3816:	48 89 03                                        	mov    QWORD PTR [rbx],rax
  ca3819:	48 85 c0                                        	test   rax,rax
  ca381c:	74 12                                           	je     0xca3830
  ca381e:	49 83 7f 20 00                                  	cmp    QWORD PTR [r15+0x20],0x0
  ca3823:	75 19                                           	jne    0xca383e
  ca3825:	eb d9                                           	jmp    0xca3800
  ca3827:	66 0f 1f 84 00 00 00 00 00                      	nop    WORD PTR [rax+rax*1+0x0]
  ca3830:	49 89 9e d8 00 00 00                            	mov    QWORD PTR [r14+0xd8],rbx
  ca3837:	49 83 7f 20 00                                  	cmp    QWORD PTR [r15+0x20],0x0
  ca383c:	74 c2                                           	je     0xca3800
  ca383e:	49 8b 7f 18                                     	mov    rdi,QWORD PTR [r15+0x18]
  ca3842:	48 85 ff                                        	test   rdi,rdi
  ca3845:	74 b9                                           	je     0xca3800
  ca3847:	4c 89 e6                                        	mov    rsi,r12
  ca384a:	e8 a1 55 f6 ff                                  	call   0xc08df0
  ca384f:	eb af                                           	jmp    0xca3800
  ca3851:	4d 8d 7e 28                                     	lea    r15,[r14+0x28]
  ca3855:	31 f6                                           	xor    esi,esi
  ca3857:	31 d2                                           	xor    edx,edx
  ca3859:	31 c9                                           	xor    ecx,ecx
  ca385b:	4c 89 ff                                        	mov    rdi,r15
  ca385e:	e8 9d 31 82 ff                                  	call   0x4c6a00
  ca3863:	41 c7 86 88 00 00 00 01 00 00 00                	mov    DWORD PTR [r14+0x88],0x1
  ca386e:	41 c7 46 38 01 00 00 00                         	mov    DWORD PTR [r14+0x38],0x1
  ca3876:	41 83 7e 34 02                                  	cmp    DWORD PTR [r14+0x34],0x2
  ca387b:	75 08                                           	jne    0xca3885
  ca387d:	4c 89 f7                                        	mov    rdi,r14
  ca3880:	e8 7b b6 a9 ff                                  	call   0x73ef00
  ca3885:	4c 89 ff                                        	mov    rdi,r15
  ca3888:	31 f6                                           	xor    esi,esi
  ca388a:	31 d2                                           	xor    edx,edx
  ca388c:	31 c9                                           	xor    ecx,ecx
  ca388e:	e8 0d 37 82 ff                                  	call   0x4c6fa0
  ca3893:	4c 89 f7                                        	mov    rdi,r14
  ca3896:	e8 95 ac a9 ff                                  	call   0x73e530
  ca389b:	4c 89 ff                                        	mov    rdi,r15
  ca389e:	49 8d 5e 40                                     	lea    rbx,[r14+0x40]
  ca38a2:	31 f6                                           	xor    esi,esi
  ca38a4:	31 d2                                           	xor    edx,edx
  ca38a6:	31 c9                                           	xor    ecx,ecx
  ca38a8:	e8 53 31 82 ff                                  	call   0x4c6a00
  ca38ad:	41 83 7e 30 00                                  	cmp    DWORD PTR [r14+0x30],0x0
  ca38b2:	0f 84 8e 00 00 00                               	je     0xca3946
  ca38b8:	4c 8d 25 c1 05 f6 01                            	lea    r12,[rip+0x1f605c1]        # 0x2c03e80
  ca38bf:	eb 2f                                           	jmp    0xca38f0
  ca38c1:	66 66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00    	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  ca38d0:	4c 89 ef                                        	mov    rdi,r13
  ca38d3:	4c 89 e6                                        	mov    rsi,r12
  ca38d6:	e8 15 55 f6 ff                                  	call   0xc08df0
  ca38db:	4c 89 ff                                        	mov    rdi,r15
  ca38de:	31 f6                                           	xor    esi,esi
  ca38e0:	31 d2                                           	xor    edx,edx
  ca38e2:	31 c9                                           	xor    ecx,ecx
  ca38e4:	e8 17 31 82 ff                                  	call   0x4c6a00
  ca38e9:	41 83 7e 30 00                                  	cmp    DWORD PTR [r14+0x30],0x0
  ca38ee:	74 56                                           	je     0xca3946
  ca38f0:	4c 89 ff                                        	mov    rdi,r15
  ca38f3:	31 f6                                           	xor    esi,esi
  ca38f5:	31 d2                                           	xor    edx,edx
  ca38f7:	31 c9                                           	xor    ecx,ecx
  ca38f9:	e8 a2 36 82 ff                                  	call   0x4c6fa0
  ca38fe:	4c 89 ff                                        	mov    rdi,r15
  ca3901:	31 f6                                           	xor    esi,esi
  ca3903:	31 d2                                           	xor    edx,edx
  ca3905:	31 c9                                           	xor    ecx,ecx
  ca3907:	e8 f4 30 82 ff                                  	call   0x4c6a00
  ca390c:	41 ff 4e 30                                     	dec    DWORD PTR [r14+0x30]
  ca3910:	4d 8b 6e 40                                     	mov    r13,QWORD PTR [r14+0x40]
  ca3914:	49 8b 45 00                                     	mov    rax,QWORD PTR [r13+0x0]
  ca3918:	49 89 46 40                                     	mov    QWORD PTR [r14+0x40],rax
  ca391c:	48 85 c0                                        	test   rax,rax
  ca391f:	75 04                                           	jne    0xca3925
  ca3921:	49 89 5e 48                                     	mov    QWORD PTR [r14+0x48],rbx
  ca3925:	4c 89 ff                                        	mov    rdi,r15
  ca3928:	31 f6                                           	xor    esi,esi
  ca392a:	31 d2                                           	xor    edx,edx
  ca392c:	31 c9                                           	xor    ecx,ecx
  ca392e:	e8 6d 36 82 ff                                  	call   0x4c6fa0
  ca3933:	49 8b 7d 48                                     	mov    rdi,QWORD PTR [r13+0x48]
  ca3937:	48 85 ff                                        	test   rdi,rdi
  ca393a:	74 94                                           	je     0xca38d0
  ca393c:	4c 89 e6                                        	mov    rsi,r12
  ca393f:	e8 ac 54 f6 ff                                  	call   0xc08df0
  ca3944:	eb 8a                                           	jmp    0xca38d0
  ca3946:	48 83 3b 00                                     	cmp    QWORD PTR [rbx],0x0
  ca394a:	74 0e                                           	je     0xca395a
  ca394c:	48 8d 3d 0b 59 5e 00                            	lea    rdi,[rip+0x5e590b]        # 0x128925e
  ca3953:	31 c0                                           	xor    eax,eax
  ca3955:	e8 b6 9a 5b ff                                  	call   0x25d410
  ca395a:	4c 89 ff                                        	mov    rdi,r15
  ca395d:	31 f6                                           	xor    esi,esi
  ca395f:	31 d2                                           	xor    edx,edx
  ca3961:	31 c9                                           	xor    ecx,ecx
  ca3963:	e8 38 36 82 ff                                  	call   0x4c6fa0
  ca3968:	4c 89 ff                                        	mov    rdi,r15
  ca396b:	e8 e0 44 82 ff                                  	call   0x4c7e50
  ca3970:	49 8b be c0 00 00 00                            	mov    rdi,QWORD PTR [r14+0xc0]
  ca3977:	48 85 ff                                        	test   rdi,rdi
  ca397a:	74 17                                           	je     0xca3993
  ca397c:	48 8d 35 8d 04 f6 01                            	lea    rsi,[rip+0x1f6048d]        # 0x2c03e10
  ca3983:	e8 68 54 f6 ff                                  	call   0xc08df0
  ca3988:	49 c7 86 c0 00 00 00 00 00 00 00                	mov    QWORD PTR [r14+0xc0],0x0
  ca3993:	49 8b 7e 58                                     	mov    rdi,QWORD PTR [r14+0x58]
  ca3997:	4c 8b 7d a0                                     	mov    r15,QWORD PTR [rbp-0x60]
  ca399b:	48 85 ff                                        	test   rdi,rdi
  ca399e:	74 14                                           	je     0xca39b4
  ca39a0:	48 8d 35 69 04 f6 01                            	lea    rsi,[rip+0x1f60469]        # 0x2c03e10
  ca39a7:	e8 44 54 f6 ff                                  	call   0xc08df0
  ca39ac:	49 c7 46 58 00 00 00 00                         	mov    QWORD PTR [r14+0x58],0x0
  ca39b4:	49 8b be f0 00 00 00                            	mov    rdi,QWORD PTR [r14+0xf0]
  ca39bb:	48 85 ff                                        	test   rdi,rdi
  ca39be:	74 17                                           	je     0xca39d7
  ca39c0:	48 8d 35 49 04 f6 01                            	lea    rsi,[rip+0x1f60449]        # 0x2c03e10
  ca39c7:	e8 24 54 f6 ff                                  	call   0xc08df0
  ca39cc:	49 c7 86 f0 00 00 00 00 00 00 00                	mov    QWORD PTR [r14+0xf0],0x0
  ca39d7:	49 8b be 88 01 00 00                            	mov    rdi,QWORD PTR [r14+0x188]
  ca39de:	48 85 ff                                        	test   rdi,rdi
  ca39e1:	74 17                                           	je     0xca39fa
  ca39e3:	48 8d 35 26 04 f6 01                            	lea    rsi,[rip+0x1f60426]        # 0x2c03e10
  ca39ea:	e8 01 54 f6 ff                                  	call   0xc08df0
  ca39ef:	49 c7 86 88 01 00 00 00 00 00 00                	mov    QWORD PTR [r14+0x188],0x0
  ca39fa:	49 8b be 90 01 00 00                            	mov    rdi,QWORD PTR [r14+0x190]
  ca3a01:	48 85 ff                                        	test   rdi,rdi
  ca3a04:	74 17                                           	je     0xca3a1d
  ca3a06:	48 8d 35 03 04 f6 01                            	lea    rsi,[rip+0x1f60403]        # 0x2c03e10
  ca3a0d:	e8 de 53 f6 ff                                  	call   0xc08df0
  ca3a12:	49 c7 86 90 01 00 00 00 00 00 00                	mov    QWORD PTR [r14+0x190],0x0
  ca3a1d:	48 8d 35 ec 03 f6 01                            	lea    rsi,[rip+0x1f603ec]        # 0x2c03e10
  ca3a24:	4c 89 f7                                        	mov    rdi,r14
  ca3a27:	e8 c4 53 f6 ff                                  	call   0xc08df0
  ca3a2c:	41 8b 9f bc 00 00 00                            	mov    ebx,DWORD PTR [r15+0xbc]
  ca3a33:	48 8d 3d 66 9e 16 03                            	lea    rdi,[rip+0x3169e66]        # 0x3e0d8a0
  ca3a3a:	31 f6                                           	xor    esi,esi
  ca3a3c:	31 d2                                           	xor    edx,edx
  ca3a3e:	31 c9                                           	xor    ecx,ecx
  ca3a40:	e8 bb 2f 82 ff                                  	call   0x4c6a00
  ca3a45:	39 1d 5d 9e 16 03                               	cmp    DWORD PTR [rip+0x3169e5d],ebx        # 0x3e0d8a8
  ca3a4b:	74 08                                           	je     0xca3a55
  ca3a4d:	39 1d 59 9e 16 03                               	cmp    DWORD PTR [rip+0x3169e59],ebx        # 0x3e0d8ac
  ca3a53:	75 14                                           	jne    0xca3a69
  ca3a55:	c7 05 4d 9e 16 03 00 00 00 00                   	mov    DWORD PTR [rip+0x3169e4d],0x0        # 0x3e0d8ac
  ca3a5f:	c7 05 3f 9e 16 03 00 00 00 00                   	mov    DWORD PTR [rip+0x3169e3f],0x0        # 0x3e0d8a8
  ca3a69:	48 8d 3d 30 9e 16 03                            	lea    rdi,[rip+0x3169e30]        # 0x3e0d8a0
  ca3a70:	31 f6                                           	xor    esi,esi
  ca3a72:	31 d2                                           	xor    edx,edx
  ca3a74:	31 c9                                           	xor    ecx,ecx
  ca3a76:	e8 25 35 82 ff                                  	call   0x4c6fa0
  ca3a7b:	48 8d 05 8e 88 c7 02                            	lea    rax,[rip+0x2c7888e]        # 0x391c310
  ca3a82:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  ca3a85:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  ca3a89:	75 4f                                           	jne    0xca3ada
  ca3a8b:	48 83 c4 48                                     	add    rsp,0x48
  ca3a8f:	5b                                              	pop    rbx
  ca3a90:	41 5c                                           	pop    r12
  ca3a92:	41 5d                                           	pop    r13
  ca3a94:	41 5e                                           	pop    r14
  ca3a96:	41 5f                                           	pop    r15
  ca3a98:	5d                                              	pop    rbp
  ca3a99:	c3                                              	ret
  ca3a9a:	4d 8d a6 10 01 00 00                            	lea    r12,[r14+0x110]
  ca3aa1:	66 66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00    	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  ca3ab0:	48 8b 3d e9 2f f5 02                            	mov    rdi,QWORD PTR [rip+0x2f52fe9]        # 0x3bf6aa0
  ca3ab7:	4c 89 e6                                        	mov    rsi,r12
  ca3aba:	31 d2                                           	xor    edx,edx
  ca3abc:	e8 9f 76 84 ff                                  	call   0x4eb160
  ca3ac1:	85 c0                                           	test   eax,eax
  ca3ac3:	0f 84 ef fb ff ff                               	je     0xca36b8
  ca3ac9:	48 8b 3d d0 2f f5 02                            	mov    rdi,QWORD PTR [rip+0x2f52fd0]        # 0x3bf6aa0
  ca3ad0:	4c 89 e6                                        	mov    rsi,r12
  ca3ad3:	e8 e8 78 84 ff                                  	call   0x4eb3c0
  ca3ad8:	eb d6                                           	jmp    0xca3ab0
  ca3ada:	e8 d1 9b a5 ff                                  	call   0x6fd6b0
  ca3adf:	0f 0b                                           	ud2
  ca3ae1:	90                                              	nop
  ca3ae2:	90                                              	nop
  ca3ae3:	90                                              	nop
  ca3ae4:	90                                              	nop
  ca3ae5:	90                                              	nop
  ca3ae6:	90                                              	nop
  ca3ae7:	90                                              	nop
  ca3ae8:	90                                              	nop
  ca3ae9:	90                                              	nop
  ca3aea:	90                                              	nop
  ca3aeb:	90                                              	nop
  ca3aec:	90                                              	nop
  ca3aed:	90                                              	nop
  ca3aee:	90                                              	nop
  ca3aef:	90                                              	nop
  ca3af0:	55                                              	push   rbp
  ca3af1:	48 89 e5                                        	mov    rbp,rsp
  ca3af4:	48 8b 86 60 05 00 00                            	mov    rax,QWORD PTR [rsi+0x560]
  ca3afb:	48 89 f7                                        	mov    rdi,rsi
  ca3afe:	48 89 c1                                        	mov    rcx,rax
  ca3b01:	48 81 c9 00 01 00 00                            	or     rcx,0x100
  ca3b08:	48 89 8e 60 05 00 00                            	mov    QWORD PTR [rsi+0x560],rcx
  ca3b0f:	f6 86 b1 00 00 00 08                            	test   BYTE PTR [rsi+0xb1],0x8
  ca3b16:	74 0d                                           	je     0xca3b25
  ca3b18:	48 0d 01 01 00 00                               	or     rax,0x101
  ca3b1e:	48 89 87 60 05 00 00                            	mov    QWORD PTR [rdi+0x560],rax
  ca3b25:	5d                                              	pop    rbp
  ca3b26:	e9 95 74 ff ff                                  	jmp    0xc9afc0
  ca3b2b:	90                                              	nop
  ca3b2c:	90                                              	nop
  ca3b2d:	90                                              	nop
  ca3b2e:	90                                              	nop
  ca3b2f:	90                                              	nop
  ca3b30:	55                                              	push   rbp
  ca3b31:	48 89 e5                                        	mov    rbp,rsp
  ca3b34:	41 57                                           	push   r15
  ca3b36:	41 56                                           	push   r14
  ca3b38:	41 54                                           	push   r12
  ca3b3a:	53                                              	push   rbx
  ca3b3b:	48 83 ec 30                                     	sub    rsp,0x30
  ca3b3f:	4c 8d 3d ca 87 c7 02                            	lea    r15,[rip+0x2c787ca]        # 0x391c310
  ca3b46:	4c 8d b6 48 01 00 00                            	lea    r14,[rsi+0x148]
  ca3b4d:	48 89 f3                                        	mov    rbx,rsi
  ca3b50:	31 f6                                           	xor    esi,esi
  ca3b52:	31 d2                                           	xor    edx,edx
  ca3b54:	31 c9                                           	xor    ecx,ecx
  ca3b56:	4c 89 f7                                        	mov    rdi,r14
  ca3b59:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  ca3b5c:	48 89 45 d8                                     	mov    QWORD PTR [rbp-0x28],rax
  ca3b60:	e8 9b 2e 82 ff                                  	call   0x4c6a00
  ca3b65:	e8 66 3d e6 ff                                  	call   0xb078d0
  ca3b6a:	85 c0                                           	test   eax,eax
  ca3b6c:	74 13                                           	je     0xca3b81
  ca3b6e:	48 8b 7b 40                                     	mov    rdi,QWORD PTR [rbx+0x40]
  ca3b72:	e8 19 5d 96 ff                                  	call   0x609890
  ca3b77:	41 bc 04 00 00 00                               	mov    r12d,0x4
  ca3b7d:	85 c0                                           	test   eax,eax
  ca3b7f:	75 03                                           	jne    0xca3b84
  ca3b81:	45 31 e4                                        	xor    r12d,r12d
  ca3b84:	4c 89 f7                                        	mov    rdi,r14
  ca3b87:	31 f6                                           	xor    esi,esi
  ca3b89:	31 d2                                           	xor    edx,edx
  ca3b8b:	31 c9                                           	xor    ecx,ecx
  ca3b8d:	e8 0e 34 82 ff                                  	call   0x4c6fa0
  ca3b92:	8b 83 bc 00 00 00                               	mov    eax,DWORD PTR [rbx+0xbc]
  ca3b98:	48 c7 45 b8 03 00 00 00                         	mov    QWORD PTR [rbp-0x48],0x3
  ca3ba0:	48 c7 45 c0 07 00 00 00                         	mov    QWORD PTR [rbp-0x40],0x7
  ca3ba8:	48 c1 e0 20                                     	shl    rax,0x20
  ca3bac:	4c 09 e0                                        	or     rax,r12
  ca3baf:	80 3d 6a 9b 16 03 01                            	cmp    BYTE PTR [rip+0x3169b6a],0x1        # 0x3e0d720
  ca3bb6:	48 89 45 c8                                     	mov    QWORD PTR [rbp-0x38],rax
  ca3bba:	48 c7 45 d0 00 00 00 00                         	mov    QWORD PTR [rbp-0x30],0x0
  ca3bc2:	75 0e                                           	jne    0xca3bd2
  ca3bc4:	48 8d 7d b8                                     	lea    rdi,[rbp-0x48]
  ca3bc8:	be 20 00 00 00                                  	mov    esi,0x20
  ca3bcd:	e8 be 6e ff ff                                  	call   0xc9aa90
  ca3bd2:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  ca3bd5:	48 3b 45 d8                                     	cmp    rax,QWORD PTR [rbp-0x28]
  ca3bd9:	75 0d                                           	jne    0xca3be8
  ca3bdb:	48 83 c4 30                                     	add    rsp,0x30
  ca3bdf:	5b                                              	pop    rbx
  ca3be0:	41 5c                                           	pop    r12
  ca3be2:	41 5e                                           	pop    r14
  ca3be4:	41 5f                                           	pop    r15
  ca3be6:	5d                                              	pop    rbp
  ca3be7:	c3                                              	ret
  ca3be8:	e8 c3 9a a5 ff                                  	call   0x6fd6b0
  ca3bed:	0f 0b                                           	ud2
  ca3bef:	90                                              	nop
  ca3bf0:	55                                              	push   rbp
  ca3bf1:	48 89 e5                                        	mov    rbp,rsp
  ca3bf4:	53                                              	push   rbx
  ca3bf5:	48 83 ec 28                                     	sub    rsp,0x28
  ca3bf9:	48 8d 1d 10 87 c7 02                            	lea    rbx,[rip+0x2c78710]        # 0x391c310
  ca3c00:	48 8b 03                                        	mov    rax,QWORD PTR [rbx]
  ca3c03:	48 89 45 f0                                     	mov    QWORD PTR [rbp-0x10],rax
  ca3c07:	8b 8e bc 00 00 00                               	mov    ecx,DWORD PTR [rsi+0xbc]
  ca3c0d:	8b 82 bc 00 00 00                               	mov    eax,DWORD PTR [rdx+0xbc]
  ca3c13:	48 c7 45 d0 03 00 00 00                         	mov    QWORD PTR [rbp-0x30],0x3
  ca3c1b:	48 c7 45 d8 04 00 00 00                         	mov    QWORD PTR [rbp-0x28],0x4
  ca3c23:	48 c1 e1 20                                     	shl    rcx,0x20
  ca3c27:	48 09 c1                                        	or     rcx,rax
  ca3c2a:	80 3d ef 9a 16 03 01                            	cmp    BYTE PTR [rip+0x3169aef],0x1        # 0x3e0d720
  ca3c31:	48 89 4d e0                                     	mov    QWORD PTR [rbp-0x20],rcx
  ca3c35:	48 c7 45 e8 00 00 00 00                         	mov    QWORD PTR [rbp-0x18],0x0
  ca3c3d:	75 0e                                           	jne    0xca3c4d
  ca3c3f:	48 8d 7d d0                                     	lea    rdi,[rbp-0x30]
  ca3c43:	be 20 00 00 00                                  	mov    esi,0x20
  ca3c48:	e8 43 6e ff ff                                  	call   0xc9aa90
  ca3c4d:	48 8b 03                                        	mov    rax,QWORD PTR [rbx]
  ca3c50:	48 3b 45 f0                                     	cmp    rax,QWORD PTR [rbp-0x10]
  ca3c54:	75 07                                           	jne    0xca3c5d
  ca3c56:	48 83 c4 28                                     	add    rsp,0x28
  ca3c5a:	5b                                              	pop    rbx
  ca3c5b:	5d                                              	pop    rbp
  ca3c5c:	c3                                              	ret
  ca3c5d:	e8 4e 9a a5 ff                                  	call   0x6fd6b0
  ca3c62:	0f 0b                                           	ud2
  ca3c64:	90                                              	nop
  ca3c65:	90                                              	nop
  ca3c66:	90                                              	nop
  ca3c67:	90                                              	nop
  ca3c68:	90                                              	nop
  ca3c69:	90                                              	nop
  ca3c6a:	90                                              	nop
  ca3c6b:	90                                              	nop
  ca3c6c:	90                                              	nop
  ca3c6d:	90                                              	nop
  ca3c6e:	90                                              	nop
  ca3c6f:	90                                              	nop
  ca3c70:	55                                              	push   rbp
  ca3c71:	48 89 e5                                        	mov    rbp,rsp
  ca3c74:	41 57                                           	push   r15
  ca3c76:	41 56                                           	push   r14
  ca3c78:	53                                              	push   rbx
  ca3c79:	50                                              	push   rax
  ca3c7a:	4c 8d b6 48 01 00 00                            	lea    r14,[rsi+0x148]
  ca3c81:	48 89 f3                                        	mov    rbx,rsi
  ca3c84:	31 f6                                           	xor    esi,esi
  ca3c86:	31 d2                                           	xor    edx,edx
  ca3c88:	31 c9                                           	xor    ecx,ecx
  ca3c8a:	4c 89 f7                                        	mov    rdi,r14
  ca3c8d:	e8 6e 2d 82 ff                                  	call   0x4c6a00
  ca3c92:	44 0f b7 bb 60 05 00 00                         	movzx  r15d,WORD PTR [rbx+0x560]
  ca3c9a:	4c 89 f7                                        	mov    rdi,r14
  ca3c9d:	31 f6                                           	xor    esi,esi
  ca3c9f:	31 d2                                           	xor    edx,edx
  ca3ca1:	31 c9                                           	xor    ecx,ecx
  ca3ca3:	e8 f8 32 82 ff                                  	call   0x4c6fa0
  ca3ca8:	66 45 85 ff                                     	test   r15w,r15w
  ca3cac:	79 30                                           	jns    0xca3cde
  ca3cae:	8b bb bc 00 00 00                               	mov    edi,DWORD PTR [rbx+0xbc]
  ca3cb4:	be 40 42 0f 00                                  	mov    esi,0xf4240
  ca3cb9:	31 d2                                           	xor    edx,edx
  ca3cbb:	e8 80 9c ff ff                                  	call   0xc9d940
  ca3cc0:	85 c0                                           	test   eax,eax
  ca3cc2:	74 1a                                           	je     0xca3cde
  ca3cc4:	89 c6                                           	mov    esi,eax
  ca3cc6:	48 8d 3d 07 15 68 00                            	lea    rdi,[rip+0x681507]        # 0x13251d4
  ca3ccd:	31 c0                                           	xor    eax,eax
  ca3ccf:	48 83 c4 08                                     	add    rsp,0x8
  ca3cd3:	5b                                              	pop    rbx
  ca3cd4:	41 5e                                           	pop    r14
  ca3cd6:	41 5f                                           	pop    r15
  ca3cd8:	5d                                              	pop    rbp
  ca3cd9:	e9 32 97 5b ff                                  	jmp    0x25d410
  ca3cde:	48 83 c4 08                                     	add    rsp,0x8
  ca3ce2:	5b                                              	pop    rbx
  ca3ce3:	41 5e                                           	pop    r14
  ca3ce5:	41 5f                                           	pop    r15
  ca3ce7:	5d                                              	pop    rbp
  ca3ce8:	c3                                              	ret
  ca3ce9:	90                                              	nop
  ca3cea:	90                                              	nop
  ca3ceb:	90                                              	nop
  ca3cec:	90                                              	nop
  ca3ced:	90                                              	nop
  ca3cee:	90                                              	nop
  ca3cef:	90                                              	nop
  ca3cf0:	55                                              	push   rbp
  ca3cf1:	48 89 e5                                        	mov    rbp,rsp
  ca3cf4:	41 56                                           	push   r14
  ca3cf6:	53                                              	push   rbx
  ca3cf7:	48 8d 9e 48 01 00 00                            	lea    rbx,[rsi+0x148]
  ca3cfe:	49 89 f6                                        	mov    r14,rsi
  ca3d01:	31 f6                                           	xor    esi,esi
  ca3d03:	31 d2                                           	xor    edx,edx
  ca3d05:	31 c9                                           	xor    ecx,ecx
  ca3d07:	48 89 df                                        	mov    rdi,rbx
  ca3d0a:	e8 f1 2c 82 ff                                  	call   0x4c6a00
  ca3d0f:	41 f6 86 62 05 00 00 40                         	test   BYTE PTR [r14+0x562],0x40
  ca3d17:	74 1f                                           	je     0xca3d38
  ca3d19:	48 8d 15 40 d5 da 00                            	lea    rdx,[rip+0xdad540]        # 0x1a51260
  ca3d20:	31 ff                                           	xor    edi,edi
  ca3d22:	31 f6                                           	xor    esi,esi
  ca3d24:	31 c0                                           	xor    eax,eax
  ca3d26:	e8 a5 07 e6 ff                                  	call   0xb044d0
  ca3d2b:	4c 89 f7                                        	mov    rdi,r14
  ca3d2e:	be 09 00 00 00                                  	mov    esi,0x9
  ca3d33:	e8 68 be 8b ff                                  	call   0x55fba0
  ca3d38:	48 89 df                                        	mov    rdi,rbx
  ca3d3b:	31 f6                                           	xor    esi,esi
  ca3d3d:	31 d2                                           	xor    edx,edx
  ca3d3f:	31 c9                                           	xor    ecx,ecx
  ca3d41:	5b                                              	pop    rbx
  ca3d42:	41 5e                                           	pop    r14
  ca3d44:	5d                                              	pop    rbp
  ca3d45:	e9 56 32 82 ff                                  	jmp    0x4c6fa0
  ca3d4a:	90                                              	nop
  ca3d4b:	90                                              	nop
  ca3d4c:	90                                              	nop
  ca3d4d:	90                                              	nop
  ca3d4e:	90                                              	nop
  ca3d4f:	90                                              	nop
  ca3d50:	55                                              	push   rbp
  ca3d51:	48 89 e5                                        	mov    rbp,rsp
  ca3d54:	41 57                                           	push   r15
  ca3d56:	41 56                                           	push   r14
  ca3d58:	41 54                                           	push   r12
  ca3d5a:	53                                              	push   rbx
  ca3d5b:	89 fb                                           	mov    ebx,edi
  ca3d5d:	48 8d 3d fc 60 8e 02                            	lea    rdi,[rip+0x28e60fc]        # 0x3589e60
  ca3d64:	31 f6                                           	xor    esi,esi
  ca3d66:	31 d2                                           	xor    edx,edx
  ca3d68:	31 c9                                           	xor    ecx,ecx
  ca3d6a:	e8 e1 75 fa ff                                  	call   0xc4b350
  ca3d6f:	4c 8d 25 0a 61 8e 02                            	lea    r12,[rip+0x28e610a]        # 0x3589e80
  ca3d76:	41 be ff ff ff ff                               	mov    r14d,0xffffffff
  ca3d7c:	eb 15                                           	jmp    0xca3d93
  ca3d7e:	66 90                                           	xchg   ax,ax
  ca3d80:	4c 89 ff                                        	mov    rdi,r15
  ca3d83:	31 f6                                           	xor    esi,esi
  ca3d85:	31 d2                                           	xor    edx,edx
  ca3d87:	31 c9                                           	xor    ecx,ecx
  ca3d89:	e8 12 32 82 ff                                  	call   0x4c6fa0
  ca3d8e:	45 85 f6                                        	test   r14d,r14d
  ca3d91:	7f 56                                           	jg     0xca3de9
  ca3d93:	4d 8b 24 24                                     	mov    r12,QWORD PTR [r12]
  ca3d97:	4d 85 e4                                        	test   r12,r12
  ca3d9a:	74 35                                           	je     0xca3dd1
  ca3d9c:	4d 8d bc 24 48 01 00 00                         	lea    r15,[r12+0x148]
  ca3da4:	31 f6                                           	xor    esi,esi
  ca3da6:	31 d2                                           	xor    edx,edx
  ca3da8:	31 c9                                           	xor    ecx,ecx
  ca3daa:	4c 89 ff                                        	mov    rdi,r15
  ca3dad:	e8 4e 2c 82 ff                                  	call   0x4c6a00
  ca3db2:	41 39 9c 24 d0 05 00 00                         	cmp    DWORD PTR [r12+0x5d0],ebx
  ca3dba:	75 c4                                           	jne    0xca3d80
  ca3dbc:	41 f6 84 24 64 04 00 00 01                      	test   BYTE PTR [r12+0x464],0x1
  ca3dc5:	74 b9                                           	je     0xca3d80
  ca3dc7:	45 8b b4 24 bc 00 00 00                         	mov    r14d,DWORD PTR [r12+0xbc]
  ca3dcf:	eb af                                           	jmp    0xca3d80
  ca3dd1:	48 8d 3d 88 60 8e 02                            	lea    rdi,[rip+0x28e6088]        # 0x3589e60
  ca3dd8:	31 f6                                           	xor    esi,esi
  ca3dda:	31 d2                                           	xor    edx,edx
  ca3ddc:	5b                                              	pop    rbx
  ca3ddd:	41 5c                                           	pop    r12
  ca3ddf:	41 5e                                           	pop    r14
  ca3de1:	41 5f                                           	pop    r15
  ca3de3:	5d                                              	pop    rbp
  ca3de4:	e9 17 85 fa ff                                  	jmp    0xc4c300
  ca3de9:	48 8d 3d 70 60 8e 02                            	lea    rdi,[rip+0x28e6070]        # 0x3589e60
  ca3df0:	31 f6                                           	xor    esi,esi
  ca3df2:	31 d2                                           	xor    edx,edx
  ca3df4:	e8 07 85 fa ff                                  	call   0xc4c300
  ca3df9:	44 89 f7                                        	mov    edi,r14d
  ca3dfc:	e8 6f 83 89 ff                                  	call   0x53c170
  ca3e01:	48 85 c0                                        	test   rax,rax
  ca3e04:	74 1a                                           	je     0xca3e20
  ca3e06:	be 04 43 02 a0                                  	mov    esi,0xa0024304
  ca3e0b:	48 89 c7                                        	mov    rdi,rax
  ca3e0e:	ba 01 00 00 00                                  	mov    edx,0x1
  ca3e13:	5b                                              	pop    rbx
  ca3e14:	41 5c                                           	pop    r12
  ca3e16:	41 5e                                           	pop    r14
  ca3e18:	41 5f                                           	pop    r15
  ca3e1a:	5d                                              	pop    rbp
  ca3e1b:	e9 c0 b5 ff ff                                  	jmp    0xc9f3e0
  ca3e20:	5b                                              	pop    rbx
  ca3e21:	41 5c                                           	pop    r12
  ca3e23:	41 5e                                           	pop    r14
  ca3e25:	41 5f                                           	pop    r15
  ca3e27:	5d                                              	pop    rbp
  ca3e28:	c3                                              	ret
  ca3e29:	90                                              	nop
  ca3e2a:	90                                              	nop
  ca3e2b:	90                                              	nop
  ca3e2c:	90                                              	nop
  ca3e2d:	90                                              	nop
  ca3e2e:	90                                              	nop
  ca3e2f:	90                                              	nop
  ca3e30:	55                                              	push   rbp
  ca3e31:	48 89 e5                                        	mov    rbp,rsp
  ca3e34:	41 57                                           	push   r15
  ca3e36:	41 56                                           	push   r14
  ca3e38:	41 55                                           	push   r13
  ca3e3a:	41 54                                           	push   r12
  ca3e3c:	53                                              	push   rbx
  ca3e3d:	48 81 ec 08 01 00 00                            	sub    rsp,0x108
  ca3e44:	48 8d 1d c5 84 c7 02                            	lea    rbx,[rip+0x2c784c5]        # 0x391c310
  ca3e4b:	48 85 f6                                        	test   rsi,rsi
  ca3e4e:	41 0f 94 c0                                     	sete   r8b
  ca3e52:	48 85 d2                                        	test   rdx,rdx
  ca3e55:	0f 94 c1                                        	sete   cl
  ca3e58:	45 31 ed                                        	xor    r13d,r13d
  ca3e5b:	44 08 c1                                        	or     cl,r8b
  ca3e5e:	48 8b 03                                        	mov    rax,QWORD PTR [rbx]
  ca3e61:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  ca3e65:	0f 85 a3 00 00 00                               	jne    0xca3f0e
  ca3e6b:	49 89 f6                                        	mov    r14,rsi
  ca3e6e:	48 8d 35 0b 82 f5 01                            	lea    rsi,[rip+0x1f5820b]        # 0x2bfc080
  ca3e75:	4c 8d 6a 01                                     	lea    r13,[rdx+0x1]
  ca3e79:	49 89 d4                                        	mov    r12,rdx
  ca3e7c:	48 89 bd d0 fe ff ff                            	mov    QWORD PTR [rbp-0x130],rdi
  ca3e83:	ba 02 01 00 00                                  	mov    edx,0x102
  ca3e88:	4c 89 ef                                        	mov    rdi,r13
  ca3e8b:	e8 c0 4c f6 ff                                  	call   0xc08b50
  ca3e90:	48 89 c7                                        	mov    rdi,rax
  ca3e93:	4c 89 f6                                        	mov    rsi,r14
  ca3e96:	4c 89 ea                                        	mov    rdx,r13
  ca3e99:	49 89 c7                                        	mov    r15,rax
  ca3e9c:	e8 cf 3c cb ff                                  	call   0x957b70
  ca3ea1:	45 31 ed                                        	xor    r13d,r13d
  ca3ea4:	43 80 7c 26 ff 2f                               	cmp    BYTE PTR [r14+r12*1-0x1],0x2f
  ca3eaa:	74 53                                           	je     0xca3eff
  ca3eac:	48 83 ec 08                                     	sub    rsp,0x8
  ca3eb0:	4d 89 f8                                        	mov    r8,r15
  ca3eb3:	4c 8d bd e8 fe ff ff                            	lea    r15,[rbp-0x118]
  ca3eba:	45 31 ed                                        	xor    r13d,r13d
  ca3ebd:	ba 10 00 00 04                                  	mov    edx,0x4000010
  ca3ec2:	31 f6                                           	xor    esi,esi
  ca3ec4:	b9 01 00 00 00                                  	mov    ecx,0x1
  ca3ec9:	41 b9 9c ff ff ff                               	mov    r9d,0xffffff9c
  ca3ecf:	4c 89 ff                                        	mov    rdi,r15
  ca3ed2:	4c 89 85 e0 fe ff ff                            	mov    QWORD PTR [rbp-0x120],r8
  ca3ed9:	ff b5 d0 fe ff ff                               	push   QWORD PTR [rbp-0x130]
  ca3edf:	6a 00                                           	push   0x0
  ca3ee1:	6a 00                                           	push   0x0
  ca3ee3:	e8 f8 67 95 ff                                  	call   0x5fa6e0
  ca3ee8:	48 83 c4 20                                     	add    rsp,0x20
  ca3eec:	4c 89 ff                                        	mov    rdi,r15
  ca3eef:	e8 2c 4d 95 ff                                  	call   0x5f8c20
  ca3ef4:	85 c0                                           	test   eax,eax
  ca3ef6:	74 38                                           	je     0xca3f30
  ca3ef8:	4c 8b bd e0 fe ff ff                            	mov    r15,QWORD PTR [rbp-0x120]
  ca3eff:	48 8d 35 7a 81 f5 01                            	lea    rsi,[rip+0x1f5817a]        # 0x2bfc080
  ca3f06:	4c 89 ff                                        	mov    rdi,r15
  ca3f09:	e8 e2 4e f6 ff                                  	call   0xc08df0
  ca3f0e:	48 8b 03                                        	mov    rax,QWORD PTR [rbx]
  ca3f11:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  ca3f15:	0f 85 66 01 00 00                               	jne    0xca4081
  ca3f1b:	44 89 e8                                        	mov    eax,r13d
  ca3f1e:	48 81 c4 08 01 00 00                            	add    rsp,0x108
  ca3f25:	5b                                              	pop    rbx
  ca3f26:	41 5c                                           	pop    r12
  ca3f28:	41 5d                                           	pop    r13
  ca3f2a:	41 5e                                           	pop    r14
  ca3f2c:	41 5f                                           	pop    r15
  ca3f2e:	5d                                              	pop    rbp
  ca3f2f:	c3                                              	ret
  ca3f30:	4c 8b bd 48 ff ff ff                            	mov    r15,QWORD PTR [rbp-0xb8]
  ca3f37:	4d 85 ff                                        	test   r15,r15
  ca3f3a:	0f 84 e7 00 00 00                               	je     0xca4027
  ca3f40:	48 8b 85 50 ff ff ff                            	mov    rax,QWORD PTR [rbp-0xb0]
  ca3f47:	41 8b 9f d4 01 00 00                            	mov    ebx,DWORD PTR [r15+0x1d4]
  ca3f4e:	48 8d bd e8 fe ff ff                            	lea    rdi,[rbp-0x118]
  ca3f55:	31 f6                                           	xor    esi,esi
  ca3f57:	45 31 ed                                        	xor    r13d,r13d
  ca3f5a:	48 89 85 d8 fe ff ff                            	mov    QWORD PTR [rbp-0x128],rax
  ca3f61:	e8 1a 68 95 ff                                  	call   0x5fa780
  ca3f66:	83 fb 01                                        	cmp    ebx,0x1
  ca3f69:	0f 85 fe 00 00 00                               	jne    0xca406d
  ca3f6f:	4c 3b bd d8 fe ff ff                            	cmp    r15,QWORD PTR [rbp-0x128]
  ca3f76:	48 8d 1d 93 83 c7 02                            	lea    rbx,[rip+0x2c78393]        # 0x391c310
  ca3f7d:	4c 8b bd e0 fe ff ff                            	mov    r15,QWORD PTR [rbp-0x120]
  ca3f84:	0f 84 75 ff ff ff                               	je     0xca3eff
  ca3f8a:	49 ff cc                                        	dec    r12
  ca3f8d:	0f 84 aa 00 00 00                               	je     0xca403d
  ca3f93:	43 80 3c 27 2f                                  	cmp    BYTE PTR [r15+r12*1],0x2f
  ca3f98:	75 f0                                           	jne    0xca3f8a
  ca3f9a:	43 c6 04 27 00                                  	mov    BYTE PTR [r15+r12*1],0x0
  ca3f9f:	48 83 ec 08                                     	sub    rsp,0x8
  ca3fa3:	4c 8d ad e8 fe ff ff                            	lea    r13,[rbp-0x118]
  ca3faa:	ba 10 00 00 04                                  	mov    edx,0x4000010
  ca3faf:	31 f6                                           	xor    esi,esi
  ca3fb1:	b9 01 00 00 00                                  	mov    ecx,0x1
  ca3fb6:	4d 89 f8                                        	mov    r8,r15
  ca3fb9:	41 b9 9c ff ff ff                               	mov    r9d,0xffffff9c
  ca3fbf:	4c 89 ef                                        	mov    rdi,r13
  ca3fc2:	ff b5 d0 fe ff ff                               	push   QWORD PTR [rbp-0x130]
  ca3fc8:	6a 00                                           	push   0x0
  ca3fca:	6a 00                                           	push   0x0
  ca3fcc:	e8 0f 67 95 ff                                  	call   0x5fa6e0
  ca3fd1:	48 83 c4 20                                     	add    rsp,0x20
  ca3fd5:	4c 89 ef                                        	mov    rdi,r13
  ca3fd8:	e8 43 4c 95 ff                                  	call   0x5f8c20
  ca3fdd:	85 c0                                           	test   eax,eax
  ca3fdf:	0f 85 94 00 00 00                               	jne    0xca4079
  ca3fe5:	4c 8b bd 48 ff ff ff                            	mov    r15,QWORD PTR [rbp-0xb8]
  ca3fec:	4d 85 ff                                        	test   r15,r15
  ca3fef:	74 36                                           	je     0xca4027
  ca3ff1:	41 8b 87 d4 01 00 00                            	mov    eax,DWORD PTR [r15+0x1d4]
  ca3ff8:	48 8b 9d 50 ff ff ff                            	mov    rbx,QWORD PTR [rbp-0xb0]
  ca3fff:	48 8d bd e8 fe ff ff                            	lea    rdi,[rbp-0x118]
  ca4006:	31 f6                                           	xor    esi,esi
  ca4008:	45 31 ed                                        	xor    r13d,r13d
  ca400b:	89 85 d8 fe ff ff                               	mov    DWORD PTR [rbp-0x128],eax
  ca4011:	e8 6a 67 95 ff                                  	call   0x5fa780
  ca4016:	83 bd d8 fe ff ff 02                            	cmp    DWORD PTR [rbp-0x128],0x2
  ca401d:	75 4e                                           	jne    0xca406d
  ca401f:	49 39 df                                        	cmp    r15,rbx
  ca4022:	e9 4f ff ff ff                                  	jmp    0xca3f76
  ca4027:	48 8d bd e8 fe ff ff                            	lea    rdi,[rbp-0x118]
  ca402e:	31 f6                                           	xor    esi,esi
  ca4030:	45 31 ed                                        	xor    r13d,r13d
  ca4033:	e8 48 67 95 ff                                  	call   0x5fa780
  ca4038:	e9 bb fe ff ff                                  	jmp    0xca3ef8
  ca403d:	48 8b bd d0 fe ff ff                            	mov    rdi,QWORD PTR [rbp-0x130]
  ca4044:	be 9c ff ff ff                                  	mov    esi,0xffffff9c
  ca4049:	4c 89 f2                                        	mov    rdx,r14
  ca404c:	b9 01 00 00 00                                  	mov    ecx,0x1
  ca4051:	41 b9 04 00 00 00                               	mov    r9d,0x4
  ca4057:	45 31 c0                                        	xor    r8d,r8d
  ca405a:	e8 c1 4b c5 ff                                  	call   0x8f8c20
  ca405f:	45 31 ed                                        	xor    r13d,r13d
  ca4062:	85 c0                                           	test   eax,eax
  ca4064:	41 0f 94 c5                                     	sete   r13b
  ca4068:	e9 92 fe ff ff                                  	jmp    0xca3eff
  ca406d:	48 8d 1d 9c 82 c7 02                            	lea    rbx,[rip+0x2c7829c]        # 0x391c310
  ca4074:	e9 7f fe ff ff                                  	jmp    0xca3ef8
  ca4079:	45 31 ed                                        	xor    r13d,r13d
  ca407c:	e9 7e fe ff ff                                  	jmp    0xca3eff
  ca4081:	e8 2a 96 a5 ff                                  	call   0x6fd6b0
  ca4086:	0f 0b                                           	ud2
  ca4088:	90                                              	nop
  ca4089:	90                                              	nop
  ca408a:	90                                              	nop
  ca408b:	90                                              	nop
  ca408c:	90                                              	nop
  ca408d:	90                                              	nop
  ca408e:	90                                              	nop
  ca408f:	90                                              	nop
  ca4090:	55                                              	push   rbp
  ca4091:	48 89 e5                                        	mov    rbp,rsp
  ca4094:	41 57                                           	push   r15
  ca4096:	41 56                                           	push   r14
  ca4098:	41 55                                           	push   r13
  ca409a:	41 54                                           	push   r12
  ca409c:	53                                              	push   rbx
  ca409d:	48 83 ec 38                                     	sub    rsp,0x38
  ca40a1:	4c 8d 25 68 82 c7 02                            	lea    r12,[rip+0x2c78268]        # 0x391c310
  ca40a8:	41 89 f6                                        	mov    r14d,esi
  ca40ab:	49 8b 04 24                                     	mov    rax,QWORD PTR [r12]
  ca40af:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  ca40b3:	4c 8b bf a8 00 00 00                            	mov    r15,QWORD PTR [rdi+0xa8]
  ca40ba:	41 f6 c6 01                                     	test   r14b,0x1
  ca40be:	74 10                                           	je     0xca40d0
  ca40c0:	41 f6 47 0c 01                                  	test   BYTE PTR [r15+0xc],0x1
  ca40c5:	b8 01 00 00 00                                  	mov    eax,0x1
  ca40ca:	0f 84 78 04 00 00                               	je     0xca4548
  ca40d0:	41 f6 c6 02                                     	test   r14b,0x2
  ca40d4:	74 10                                           	je     0xca40e6
  ca40d6:	41 f6 47 0c 02                                  	test   BYTE PTR [r15+0xc],0x2
  ca40db:	b8 01 00 00 00                                  	mov    eax,0x1
  ca40e0:	0f 84 62 04 00 00                               	je     0xca4548
  ca40e6:	48 8d 35 73 d8 f5 01                            	lea    rsi,[rip+0x1f5d873]        # 0x2c01960
  ca40ed:	bf 30 00 00 00                                  	mov    edi,0x30
  ca40f2:	ba 02 81 00 00                                  	mov    edx,0x8102
  ca40f7:	e8 54 4a f6 ff                                  	call   0xc08b50
  ca40fc:	48 89 c3                                        	mov    rbx,rax
  ca40ff:	41 8b 07                                        	mov    eax,DWORD PTR [r15]
  ca4102:	41 8b 4f 08                                     	mov    ecx,DWORD PTR [r15+0x8]
  ca4106:	48 8d 75 b8                                     	lea    rsi,[rbp-0x48]
  ca410a:	ba 01 00 00 00                                  	mov    edx,0x1
  ca410f:	48 89 df                                        	mov    rdi,rbx
  ca4112:	89 43 18                                        	mov    DWORD PTR [rbx+0x18],eax
  ca4115:	41 8b 47 04                                     	mov    eax,DWORD PTR [r15+0x4]
  ca4119:	89 43 1c                                        	mov    DWORD PTR [rbx+0x1c],eax
  ca411c:	89 4b 20                                        	mov    DWORD PTR [rbx+0x20],ecx
  ca411f:	41 0f b6 47 10                                  	movzx  eax,BYTE PTR [r15+0x10]
  ca4124:	88 43 28                                        	mov    BYTE PTR [rbx+0x28],al
  ca4127:	e8 84 23 00 00                                  	call   0xca64b0
  ca412c:	85 c0                                           	test   eax,eax
  ca412e:	74 19                                           	je     0xca4149
  ca4130:	48 8d 35 29 d8 f5 01                            	lea    rsi,[rip+0x1f5d829]        # 0x2c01960
  ca4137:	48 89 df                                        	mov    rdi,rbx
  ca413a:	e8 b1 4c f6 ff                                  	call   0xc08df0
  ca413f:	b8 06 00 00 00                                  	mov    eax,0x6
  ca4144:	e9 ff 03 00 00                                  	jmp    0xca4548
  ca4149:	44 89 73 24                                     	mov    DWORD PTR [rbx+0x24],r14d
  ca414d:	4c 8b 7b 08                                     	mov    r15,QWORD PTR [rbx+0x8]
  ca4151:	8b 7b 20                                        	mov    edi,DWORD PTR [rbx+0x20]
  ca4154:	85 ff                                           	test   edi,edi
  ca4156:	0f 88 b8 00 00 00                               	js     0xca4214
  ca415c:	b1 01                                           	mov    cl,0x1
  ca415e:	45 31 e4                                        	xor    r12d,r12d
  ca4161:	31 c0                                           	xor    eax,eax
  ca4163:	eb 1b                                           	jmp    0xca4180
  ca4165:	66 66 2e 0f 1f 84 00 00 00 00 00                	data16 cs nop WORD PTR [rax+rax*1+0x0]
  ca4170:	84 c9                                           	test   cl,cl
  ca4172:	0f 84 e9 00 00 00                               	je     0xca4261
  ca4178:	89 c2                                           	mov    edx,eax
  ca417a:	41 80 c4 02                                     	add    r12b,0x2
  ca417e:	89 d0                                           	mov    eax,edx
  ca4180:	44 89 e2                                        	mov    edx,r12d
  ca4183:	f6 da                                           	neg    dl
  ca4185:	71 0d                                           	jno    0xca4194
  ca4187:	84 c9                                           	test   cl,cl
  ca4189:	0f 84 85 03 00 00                               	je     0xca4514
  ca418f:	45 31 e4                                        	xor    r12d,r12d
  ca4192:	31 c9                                           	xor    ecx,ecx
  ca4194:	45 0f b6 ec                                     	movzx  r13d,r12b
  ca4198:	41 f6 c6 02                                     	test   r14b,0x2
  ca419c:	75 42                                           	jne    0xca41e0
  ca419e:	41 f6 c6 01                                     	test   r14b,0x1
  ca41a2:	0f 84 bb 00 00 00                               	je     0xca4263
  ca41a8:	4b 8b b4 ef c0 02 00 00                         	mov    rsi,QWORD PTR [r15+r13*8+0x2c0]
  ca41b0:	48 85 f6                                        	test   rsi,rsi
  ca41b3:	74 bb                                           	je     0xca4170
  ca41b5:	0f b7 96 1c 01 00 00                            	movzx  edx,WORD PTR [rsi+0x11c]
  ca41bc:	39 d7                                           	cmp    edi,edx
  ca41be:	75 b8                                           	jne    0xca4178
  ca41c0:	48 83 be f0 00 00 00 00                         	cmp    QWORD PTR [rsi+0xf0],0x0
  ca41c8:	b2 01                                           	mov    dl,0x1
  ca41ca:	75 ae                                           	jne    0xca417a
  ca41cc:	e9 92 00 00 00                                  	jmp    0xca4263
  ca41d1:	66 66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00    	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  ca41e0:	4b 8b b4 ef b8 02 00 00                         	mov    rsi,QWORD PTR [r15+r13*8+0x2b8]
  ca41e8:	48 85 f6                                        	test   rsi,rsi
  ca41eb:	74 1d                                           	je     0xca420a
  ca41ed:	0f b7 96 1c 01 00 00                            	movzx  edx,WORD PTR [rsi+0x11c]
  ca41f4:	39 d7                                           	cmp    edi,edx
  ca41f6:	75 80                                           	jne    0xca4178
  ca41f8:	48 83 be f0 00 00 00 00                         	cmp    QWORD PTR [rsi+0xf0],0x0
  ca4200:	b2 01                                           	mov    dl,0x1
  ca4202:	0f 85 72 ff ff ff                               	jne    0xca417a
  ca4208:	eb 94                                           	jmp    0xca419e
  ca420a:	84 c9                                           	test   cl,cl
  ca420c:	0f 85 66 ff ff ff                               	jne    0xca4178
  ca4212:	eb 8a                                           	jmp    0xca419e
  ca4214:	41 f6 c6 02                                     	test   r14b,0x2
  ca4218:	74 19                                           	je     0xca4233
  ca421a:	0f b6 43 28                                     	movzx  eax,BYTE PTR [rbx+0x28]
  ca421e:	49 8b 84 c7 b8 02 00 00                         	mov    rax,QWORD PTR [r15+rax*8+0x2b8]
  ca4226:	48 85 c0                                        	test   rax,rax
  ca4229:	0f 84 ec 02 00 00                               	je     0xca451b
  ca422f:	48 89 45 c0                                     	mov    QWORD PTR [rbp-0x40],rax
  ca4233:	41 f6 c6 01                                     	test   r14b,0x1
  ca4237:	74 19                                           	je     0xca4252
  ca4239:	0f b6 43 28                                     	movzx  eax,BYTE PTR [rbx+0x28]
  ca423d:	49 8b 84 c7 c0 02 00 00                         	mov    rax,QWORD PTR [r15+rax*8+0x2c0]
  ca4245:	48 85 c0                                        	test   rax,rax
  ca4248:	0f 84 cd 02 00 00                               	je     0xca451b
  ca424e:	48 89 45 b8                                     	mov    QWORD PTR [rbp-0x48],rax
  ca4252:	41 f6 c6 01                                     	test   r14b,0x1
  ca4256:	0f 85 a4 00 00 00                               	jne    0xca4300
  ca425c:	e9 d5 00 00 00                                  	jmp    0xca4336
  ca4261:	31 c9                                           	xor    ecx,ecx
  ca4263:	84 c9                                           	test   cl,cl
  ca4265:	0f 95 c1                                        	setne  cl
  ca4268:	83 ff 10                                        	cmp    edi,0x10
  ca426b:	0f 9c c2                                        	setl   dl
  ca426e:	08 ca                                           	or     dl,cl
  ca4270:	75 14                                           	jne    0xca4286
  ca4272:	84 c0                                           	test   al,al
  ca4274:	b9 16 00 00 00                                  	mov    ecx,0x16
  ca4279:	b8 10 00 00 00                                  	mov    eax,0x10
  ca427e:	0f 44 c1                                        	cmove  eax,ecx
  ca4281:	e9 9a 02 00 00                                  	jmp    0xca4520
  ca4286:	85 ff                                           	test   edi,edi
  ca4288:	0f 95 c1                                        	setne  cl
  ca428b:	84 c0                                           	test   al,al
  ca428d:	b8 10 00 00 00                                  	mov    eax,0x10
  ca4292:	0f 95 c2                                        	setne  dl
  ca4295:	84 d1                                           	test   cl,dl
  ca4297:	0f 85 83 02 00 00                               	jne    0xca4520
  ca429d:	41 f6 c6 02                                     	test   r14b,0x2
  ca42a1:	74 0f                                           	je     0xca42b2
  ca42a3:	4b 83 bc ef b8 02 00 00 00                      	cmp    QWORD PTR [r15+r13*8+0x2b8],0x0
  ca42ac:	0f 84 f7 00 00 00                               	je     0xca43a9
  ca42b2:	41 f6 c6 01                                     	test   r14b,0x1
  ca42b6:	74 13                                           	je     0xca42cb
  ca42b8:	41 8d 45 01                                     	lea    eax,[r13+0x1]
  ca42bc:	49 83 bc c7 b8 02 00 00 00                      	cmp    QWORD PTR [r15+rax*8+0x2b8],0x0
  ca42c5:	0f 84 95 01 00 00                               	je     0xca4460
  ca42cb:	41 f6 c6 02                                     	test   r14b,0x2
  ca42cf:	74 0c                                           	je     0xca42dd
  ca42d1:	4b 8b 84 ef b8 02 00 00                         	mov    rax,QWORD PTR [r15+r13*8+0x2b8]
  ca42d9:	48 89 45 c0                                     	mov    QWORD PTR [rbp-0x40],rax
  ca42dd:	41 f6 c6 01                                     	test   r14b,0x1
  ca42e1:	74 0c                                           	je     0xca42ef
  ca42e3:	4b 8b 84 ef c0 02 00 00                         	mov    rax,QWORD PTR [r15+r13*8+0x2c0]
  ca42eb:	48 89 45 b8                                     	mov    QWORD PTR [rbp-0x48],rax
  ca42ef:	44 88 63 28                                     	mov    BYTE PTR [rbx+0x28],r12b
  ca42f3:	4c 8d 25 16 80 c7 02                            	lea    r12,[rip+0x2c78016]        # 0x391c310
  ca42fa:	41 f6 c6 01                                     	test   r14b,0x1
  ca42fe:	74 36                                           	je     0xca4336
  ca4300:	48 8b 75 b8                                     	mov    rsi,QWORD PTR [rbp-0x48]
  ca4304:	48 89 df                                        	mov    rdi,rbx
  ca4307:	44 89 f2                                        	mov    edx,r14d
  ca430a:	e8 b1 24 00 00                                  	call   0xca67c0
  ca430f:	85 c0                                           	test   eax,eax
  ca4311:	74 23                                           	je     0xca4336
  ca4313:	48 8d 75 b8                                     	lea    rsi,[rbp-0x48]
  ca4317:	48 89 df                                        	mov    rdi,rbx
  ca431a:	41 89 c6                                        	mov    r14d,eax
  ca431d:	e8 de 23 00 00                                  	call   0xca6700
  ca4322:	48 8d 35 37 d6 f5 01                            	lea    rsi,[rip+0x1f5d637]        # 0x2c01960
  ca4329:	48 89 df                                        	mov    rdi,rbx
  ca432c:	e8 bf 4a f6 ff                                  	call   0xc08df0
  ca4331:	e9 0f 02 00 00                                  	jmp    0xca4545
  ca4336:	41 f6 c6 02                                     	test   r14b,0x2
  ca433a:	74 4b                                           	je     0xca4387
  ca433c:	48 8b 75 c0                                     	mov    rsi,QWORD PTR [rbp-0x40]
  ca4340:	48 89 df                                        	mov    rdi,rbx
  ca4343:	44 89 f2                                        	mov    edx,r14d
  ca4346:	e8 75 24 00 00                                  	call   0xca67c0
  ca434b:	85 c0                                           	test   eax,eax
  ca434d:	74 38                                           	je     0xca4387
  ca434f:	41 89 c7                                        	mov    r15d,eax
  ca4352:	41 f6 c6 01                                     	test   r14b,0x1
  ca4356:	74 0c                                           	je     0xca4364
  ca4358:	48 8b 7d b8                                     	mov    rdi,QWORD PTR [rbp-0x48]
  ca435c:	44 89 f6                                        	mov    esi,r14d
  ca435f:	e8 fc 12 00 00                                  	call   0xca5660
  ca4364:	48 8d 75 b8                                     	lea    rsi,[rbp-0x48]
  ca4368:	48 89 df                                        	mov    rdi,rbx
  ca436b:	e8 90 23 00 00                                  	call   0xca6700
  ca4370:	48 8d 35 e9 d5 f5 01                            	lea    rsi,[rip+0x1f5d5e9]        # 0x2c01960
  ca4377:	48 89 df                                        	mov    rdi,rbx
  ca437a:	e8 71 4a f6 ff                                  	call   0xc08df0
  ca437f:	44 89 f8                                        	mov    eax,r15d
  ca4382:	e9 c1 01 00 00                                  	jmp    0xca4548
  ca4387:	48 8d 75 b8                                     	lea    rsi,[rbp-0x48]
  ca438b:	48 89 df                                        	mov    rdi,rbx
  ca438e:	e8 6d 23 00 00                                  	call   0xca6700
  ca4393:	48 8d 35 8e 0e 5c ff                            	lea    rsi,[rip+0xffffffffff5c0e8e]        # 0x265228
  ca439a:	48 89 df                                        	mov    rdi,rbx
  ca439d:	e8 9e 77 7f ff                                  	call   0x49bb40
  ca43a2:	31 c0                                           	xor    eax,eax
  ca43a4:	e9 9f 01 00 00                                  	jmp    0xca4548
  ca43a9:	89 7d a8                                        	mov    DWORD PTR [rbp-0x58],edi
  ca43ac:	40 0f b6 f7                                     	movzx  esi,dil
  ca43b0:	4c 89 ff                                        	mov    rdi,r15
  ca43b3:	31 d2                                           	xor    edx,edx
  ca43b5:	e8 26 26 00 00                                  	call   0xca69e0
  ca43ba:	48 85 c0                                        	test   rax,rax
  ca43bd:	0f 84 58 01 00 00                               	je     0xca451b
  ca43c3:	49 8d bf 90 00 00 00                            	lea    rdi,[r15+0x90]
  ca43ca:	48 89 45 b0                                     	mov    QWORD PTR [rbp-0x50],rax
  ca43ce:	e8 2d 16 00 00                                  	call   0xca5a00
  ca43d3:	48 85 c0                                        	test   rax,rax
  ca43d6:	0f 84 38 01 00 00                               	je     0xca4514
  ca43dc:	8b 4d a8                                        	mov    ecx,DWORD PTR [rbp-0x58]
  ca43df:	44 88 a0 28 01 00 00                            	mov    BYTE PTR [rax+0x128],r12b
  ca43e6:	48 8b 55 b0                                     	mov    rdx,QWORD PTR [rbp-0x50]
  ca43ea:	48 8d 3d b7 96 16 03                            	lea    rdi,[rip+0x31696b7]        # 0x3e0daa8
  ca43f1:	31 f6                                           	xor    esi,esi
  ca43f3:	48 89 45 b0                                     	mov    QWORD PTR [rbp-0x50],rax
  ca43f7:	66 89 88 1c 01 00 00                            	mov    WORD PTR [rax+0x11c],cx
  ca43fe:	48 8d 0d db f3 f4 01                            	lea    rcx,[rip+0x1f4f3db]        # 0x2bf37e0
  ca4405:	48 89 90 f8 00 00 00                            	mov    QWORD PTR [rax+0xf8],rdx
  ca440c:	48 89 88 a0 00 00 00                            	mov    QWORD PTR [rax+0xa0],rcx
  ca4413:	0f b6 8a 5b 01 00 00                            	movzx  ecx,BYTE PTR [rdx+0x15b]
  ca441a:	31 d2                                           	xor    edx,edx
  ca441c:	88 88 27 01 00 00                               	mov    BYTE PTR [rax+0x127],cl
  ca4422:	31 c9                                           	xor    ecx,ecx
  ca4424:	4c 89 b8 c8 00 00 00                            	mov    QWORD PTR [rax+0xc8],r15
  ca442b:	e8 d0 25 82 ff                                  	call   0x4c6a00
  ca4430:	48 8b 45 b0                                     	mov    rax,QWORD PTR [rbp-0x50]
  ca4434:	48 8d 3d 6d 96 16 03                            	lea    rdi,[rip+0x316966d]        # 0x3e0daa8
  ca443b:	31 f6                                           	xor    esi,esi
  ca443d:	31 d2                                           	xor    edx,edx
  ca443f:	31 c9                                           	xor    ecx,ecx
  ca4441:	4b 89 84 ef b8 02 00 00                         	mov    QWORD PTR [r15+r13*8+0x2b8],rax
  ca4449:	e8 52 2b 82 ff                                  	call   0x4c6fa0
  ca444e:	8b 7d a8                                        	mov    edi,DWORD PTR [rbp-0x58]
  ca4451:	41 f6 c6 01                                     	test   r14b,0x1
  ca4455:	0f 85 5d fe ff ff                               	jne    0xca42b8
  ca445b:	e9 6b fe ff ff                                  	jmp    0xca42cb
  ca4460:	89 7d a8                                        	mov    DWORD PTR [rbp-0x58],edi
  ca4463:	40 0f b6 f7                                     	movzx  esi,dil
  ca4467:	4c 89 ff                                        	mov    rdi,r15
  ca446a:	ba 01 00 00 00                                  	mov    edx,0x1
  ca446f:	48 89 45 b0                                     	mov    QWORD PTR [rbp-0x50],rax
  ca4473:	e8 68 25 00 00                                  	call   0xca69e0
  ca4478:	48 85 c0                                        	test   rax,rax
  ca447b:	0f 84 9a 00 00 00                               	je     0xca451b
  ca4481:	49 8d bf 90 00 00 00                            	lea    rdi,[r15+0x90]
  ca4488:	48 89 45 a0                                     	mov    QWORD PTR [rbp-0x60],rax
  ca448c:	e8 6f 15 00 00                                  	call   0xca5a00
  ca4491:	48 85 c0                                        	test   rax,rax
  ca4494:	74 7e                                           	je     0xca4514
  ca4496:	48 8b 4d b0                                     	mov    rcx,QWORD PTR [rbp-0x50]
  ca449a:	48 8b 55 a0                                     	mov    rdx,QWORD PTR [rbp-0x60]
  ca449e:	48 8d 3d 03 96 16 03                            	lea    rdi,[rip+0x3169603]        # 0x3e0daa8
  ca44a5:	31 f6                                           	xor    esi,esi
  ca44a7:	88 88 28 01 00 00                               	mov    BYTE PTR [rax+0x128],cl
  ca44ad:	8b 4d a8                                        	mov    ecx,DWORD PTR [rbp-0x58]
  ca44b0:	48 89 45 a8                                     	mov    QWORD PTR [rbp-0x58],rax
  ca44b4:	66 89 88 1c 01 00 00                            	mov    WORD PTR [rax+0x11c],cx
  ca44bb:	48 8d 0d 1e f3 f4 01                            	lea    rcx,[rip+0x1f4f31e]        # 0x2bf37e0
  ca44c2:	48 89 90 f8 00 00 00                            	mov    QWORD PTR [rax+0xf8],rdx
  ca44c9:	48 89 88 a0 00 00 00                            	mov    QWORD PTR [rax+0xa0],rcx
  ca44d0:	0f b6 8a 5b 01 00 00                            	movzx  ecx,BYTE PTR [rdx+0x15b]
  ca44d7:	31 d2                                           	xor    edx,edx
  ca44d9:	88 88 27 01 00 00                               	mov    BYTE PTR [rax+0x127],cl
  ca44df:	31 c9                                           	xor    ecx,ecx
  ca44e1:	4c 89 b8 c8 00 00 00                            	mov    QWORD PTR [rax+0xc8],r15
  ca44e8:	e8 13 25 82 ff                                  	call   0x4c6a00
  ca44ed:	48 8b 45 b0                                     	mov    rax,QWORD PTR [rbp-0x50]
  ca44f1:	48 8b 4d a8                                     	mov    rcx,QWORD PTR [rbp-0x58]
  ca44f5:	48 8d 3d ac 95 16 03                            	lea    rdi,[rip+0x31695ac]        # 0x3e0daa8
  ca44fc:	31 f6                                           	xor    esi,esi
  ca44fe:	31 d2                                           	xor    edx,edx
  ca4500:	49 89 8c c7 b8 02 00 00                         	mov    QWORD PTR [r15+rax*8+0x2b8],rcx
  ca4508:	31 c9                                           	xor    ecx,ecx
  ca450a:	e8 91 2a 82 ff                                  	call   0x4c6fa0
  ca450f:	e9 b7 fd ff ff                                  	jmp    0xca42cb
  ca4514:	b8 0c 00 00 00                                  	mov    eax,0xc
  ca4519:	eb 05                                           	jmp    0xca4520
  ca451b:	b8 16 00 00 00                                  	mov    eax,0x16
  ca4520:	48 8d 75 b8                                     	lea    rsi,[rbp-0x48]
  ca4524:	48 89 df                                        	mov    rdi,rbx
  ca4527:	41 89 c6                                        	mov    r14d,eax
  ca452a:	e8 d1 21 00 00                                  	call   0xca6700
  ca452f:	48 8d 35 2a d4 f5 01                            	lea    rsi,[rip+0x1f5d42a]        # 0x2c01960
  ca4536:	48 89 df                                        	mov    rdi,rbx
  ca4539:	e8 b2 48 f6 ff                                  	call   0xc08df0
  ca453e:	4c 8d 25 cb 7d c7 02                            	lea    r12,[rip+0x2c77dcb]        # 0x391c310
  ca4545:	44 89 f0                                        	mov    eax,r14d
  ca4548:	49 8b 0c 24                                     	mov    rcx,QWORD PTR [r12]
  ca454c:	48 3b 4d d0                                     	cmp    rcx,QWORD PTR [rbp-0x30]
  ca4550:	75 0f                                           	jne    0xca4561
  ca4552:	48 83 c4 38                                     	add    rsp,0x38
  ca4556:	5b                                              	pop    rbx
  ca4557:	41 5c                                           	pop    r12
  ca4559:	41 5d                                           	pop    r13
  ca455b:	41 5e                                           	pop    r14
  ca455d:	41 5f                                           	pop    r15
  ca455f:	5d                                              	pop    rbp
  ca4560:	c3                                              	ret
  ca4561:	e8 4a 91 a5 ff                                  	call   0x6fd6b0
  ca4566:	0f 0b                                           	ud2
  ca4568:	90                                              	nop
  ca4569:	90                                              	nop
  ca456a:	90                                              	nop
  ca456b:	90                                              	nop
  ca456c:	90                                              	nop
  ca456d:	90                                              	nop
  ca456e:	90                                              	nop
  ca456f:	90                                              	nop
  ca4570:	55                                              	push   rbp
  ca4571:	48 89 e5                                        	mov    rbp,rsp
  ca4574:	41 57                                           	push   r15
  ca4576:	41 56                                           	push   r14
  ca4578:	41 55                                           	push   r13
  ca457a:	41 54                                           	push   r12
  ca457c:	53                                              	push   rbx
  ca457d:	48 83 ec 48                                     	sub    rsp,0x48
  ca4581:	48 8d 1d 88 7d c7 02                            	lea    rbx,[rip+0x2c77d88]        # 0x391c310
  ca4588:	48 8d 7d b0                                     	lea    rdi,[rbp-0x50]
  ca458c:	41 89 d4                                        	mov    r12d,edx
  ca458f:	49 89 f6                                        	mov    r14,rsi
  ca4592:	48 8b 03                                        	mov    rax,QWORD PTR [rbx]
  ca4595:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  ca4599:	e8 62 75 7f ff                                  	call   0x49bb00
  ca459e:	41 89 c5                                        	mov    r13d,eax
  ca45a1:	85 c0                                           	test   eax,eax
  ca45a3:	0f 85 81 00 00 00                               	jne    0xca462a
  ca45a9:	48 8b 7d b0                                     	mov    rdi,QWORD PTR [rbp-0x50]
  ca45ad:	48 8d 75 b8                                     	lea    rsi,[rbp-0x48]
  ca45b1:	31 d2                                           	xor    edx,edx
  ca45b3:	e8 f8 1e 00 00                                  	call   0xca64b0
  ca45b8:	41 bd 06 00 00 00                               	mov    r13d,0x6
  ca45be:	85 c0                                           	test   eax,eax
  ca45c0:	75 68                                           	jne    0xca462a
  ca45c2:	4c 8b 7d b8                                     	mov    r15,QWORD PTR [rbp-0x48]
  ca45c6:	4d 85 ff                                        	test   r15,r15
  ca45c9:	74 28                                           	je     0xca45f3
  ca45cb:	49 8b bf e8 00 00 00                            	mov    rdi,QWORD PTR [r15+0xe8]
  ca45d2:	31 f6                                           	xor    esi,esi
  ca45d4:	31 d2                                           	xor    edx,edx
  ca45d6:	31 c9                                           	xor    ecx,ecx
  ca45d8:	48 83 c7 18                                     	add    rdi,0x18
  ca45dc:	e8 1f 24 82 ff                                  	call   0x4c6a00
  ca45e1:	41 80 bf 20 01 00 00 00                         	cmp    BYTE PTR [r15+0x120],0x0
  ca45e9:	74 10                                           	je     0xca45fb
  ca45eb:	41 bd 05 00 00 00                               	mov    r13d,0x5
  ca45f1:	eb 14                                           	jmp    0xca4607
  ca45f3:	41 bd 01 00 00 00                               	mov    r13d,0x1
  ca45f9:	eb 22                                           	jmp    0xca461d
  ca45fb:	80 7d cb 00                                     	cmp    BYTE PTR [rbp-0x35],0x0
  ca45ff:	41 bd 16 00 00 00                               	mov    r13d,0x16
  ca4605:	74 42                                           	je     0xca4649
  ca4607:	49 8b bf e8 00 00 00                            	mov    rdi,QWORD PTR [r15+0xe8]
  ca460e:	31 f6                                           	xor    esi,esi
  ca4610:	31 d2                                           	xor    edx,edx
  ca4612:	31 c9                                           	xor    ecx,ecx
  ca4614:	48 83 c7 18                                     	add    rdi,0x18
  ca4618:	e8 83 29 82 ff                                  	call   0x4c6fa0
  ca461d:	48 8b 7d b0                                     	mov    rdi,QWORD PTR [rbp-0x50]
  ca4621:	48 8d 75 b8                                     	lea    rsi,[rbp-0x48]
  ca4625:	e8 d6 20 00 00                                  	call   0xca6700
  ca462a:	48 8b 03                                        	mov    rax,QWORD PTR [rbx]
  ca462d:	48                                              	rex.W
  ca462e:	3b                                              	.byte 0x3b
  ca462f:	45                                              	rex.RB
