
/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/deep_622.bin:     file format binary


Disassembly of section .data:

00000000007dcd40 <.data>:
  7dcd40:	55                                              	push   rbp
  7dcd41:	48 89 e5                                        	mov    rbp,rsp
  7dcd44:	41 57                                           	push   r15
  7dcd46:	41 56                                           	push   r14
  7dcd48:	41 55                                           	push   r13
  7dcd4a:	41 54                                           	push   r12
  7dcd4c:	53                                              	push   rbx
  7dcd4d:	48 83 ec 58                                     	sub    rsp,0x58
  7dcd51:	48 8d 05 b8 f5 13 03                            	lea    rax,[rip+0x313f5b8]        # 0x391c310
  7dcd58:	48 89 fb                                        	mov    rbx,rdi
  7dcd5b:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  7dcd5e:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  7dcd62:	48 8b 46 10                                     	mov    rax,QWORD PTR [rsi+0x10]
  7dcd66:	44 8b 36                                        	mov    r14d,DWORD PTR [rsi]
  7dcd69:	44 8b 7e 08                                     	mov    r15d,DWORD PTR [rsi+0x8]
  7dcd6d:	4c 8b 6e 18                                     	mov    r13,QWORD PTR [rsi+0x18]
  7dcd71:	4c 8b 66 20                                     	mov    r12,QWORD PTR [rsi+0x20]
  7dcd75:	c7 45 8c 00 00 00 00                            	mov    DWORD PTR [rbp-0x74],0x0
  7dcd7c:	48 89 45 80                                     	mov    QWORD PTR [rbp-0x80],rax
  7dcd80:	b8 01 00 0e 80                                  	mov    eax,0x800e0001
  7dcd85:	49 83 fc 40                                     	cmp    r12,0x40
  7dcd89:	76 6a                                           	jbe    0x7dcdf5
  7dcd8b:	89 45 8c                                        	mov    DWORD PTR [rbp-0x74],eax
  7dcd8e:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  7dcd97:	48 8d 35 f9 24 b7 00                            	lea    rsi,[rip+0xb724f9]        # 0x134f297
  7dcd9e:	31 d2                                           	xor    edx,edx
  7dcda0:	e8 3b d6 43 00                                  	call   0xc1a3e0
  7dcda5:	48 8b 75 80                                     	mov    rsi,QWORD PTR [rbp-0x80]
  7dcda9:	48 8d 7d 8c                                     	lea    rdi,[rbp-0x74]
  7dcdad:	ba 04 00 00 00                                  	mov    edx,0x4
  7dcdb2:	e8 19 c4 a7 ff                                  	call   0x2591d0
  7dcdb7:	b9 04 00 00 00                                  	mov    ecx,0x4
  7dcdbc:	83 f8 04                                        	cmp    eax,0x4
  7dcdbf:	74 0f                                           	je     0x7dcdd0
  7dcdc1:	83 bb 98 03 00 00 00                            	cmp    DWORD PTR [rbx+0x398],0x0
  7dcdc8:	0f 85 88 0d 00 00                               	jne    0x7ddb56
  7dcdce:	89 c1                                           	mov    ecx,eax
  7dcdd0:	48 8d 05 39 f5 13 03                            	lea    rax,[rip+0x313f539]        # 0x391c310
  7dcdd7:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  7dcdda:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  7dcdde:	0f 85 6b 0d 00 00                               	jne    0x7ddb4f
  7dcde4:	89 c8                                           	mov    eax,ecx
  7dcde6:	48 83 c4 58                                     	add    rsp,0x58
  7dcdea:	5b                                              	pop    rbx
  7dcdeb:	41 5c                                           	pop    r12
  7dcded:	41 5d                                           	pop    r13
  7dcdef:	41 5e                                           	pop    r14
  7dcdf1:	41 5f                                           	pop    r15
  7dcdf3:	5d                                              	pop    rbp
  7dcdf4:	c3                                              	ret
  7dcdf5:	41 81 fe 70 02 00 00                            	cmp    r14d,0x270
  7dcdfc:	0f 8f 14 01 00 00                               	jg     0x7dcf16
  7dce02:	41 8d 86 00 ff ff ff                            	lea    eax,[r14-0x100]
  7dce09:	83 f8 33                                        	cmp    eax,0x33
  7dce0c:	77 41                                           	ja     0x7dce4f
  7dce0e:	48 b9 d5 00 00 00 ff 8f 0f 00                   	movabs rcx,0xf8fff000000d5
  7dce18:	48 0f a3 c1                                     	bt     rcx,rax
  7dce1c:	0f 83 e9 01 00 00                               	jae    0x7dd00b
  7dce22:	48 8b bb 40 01 00 00                            	mov    rdi,QWORD PTR [rbx+0x140]
  7dce29:	e8 e2 c2 e2 ff                                  	call   0x609110
  7dce2e:	83 f8 01                                        	cmp    eax,0x1
  7dce31:	74 1c                                           	je     0x7dce4f
  7dce33:	48 8b bb 40 01 00 00                            	mov    rdi,QWORD PTR [rbx+0x140]
  7dce3a:	e8 01 c2 e2 ff                                  	call   0x609040
  7dce3f:	89 c1                                           	mov    ecx,eax
  7dce41:	b8 4e 00 02 80                                  	mov    eax,0x8002004e
  7dce46:	83 f9 01                                        	cmp    ecx,0x1
  7dce49:	0f 85 3c ff ff ff                               	jne    0x7dcd8b
  7dce4f:	48 8d 7d 90                                     	lea    rdi,[rbp-0x70]
  7dce53:	be 40 00 00 00                                  	mov    esi,0x40
  7dce58:	e8 93 c1 a7 ff                                  	call   0x258ff0
  7dce5d:	b8 ff ff ff ff                                  	mov    eax,0xffffffff
  7dce62:	41 81 fe 01 03 00 00                            	cmp    r14d,0x301
  7dce69:	7e 5f                                           	jle    0x7dceca
  7dce6b:	41 81 fe ff 03 00 00                            	cmp    r14d,0x3ff
  7dce72:	0f 8e 48 01 00 00                               	jle    0x7dcfc0
  7dce78:	41 8d 8e 00 fc ff ff                            	lea    ecx,[r14-0x400]
  7dce7f:	81 f9 93 00 00 00                               	cmp    ecx,0x93
  7dce85:	0f 87 f6 01 00 00                               	ja     0x7dd081
  7dce8b:	48 8d 15 fa 3d fa 00                            	lea    rdx,[rip+0xfa3dfa]        # 0x1780c8c
  7dce92:	48 63 0c 8a                                     	movsxd rcx,DWORD PTR [rdx+rcx*4]
  7dce96:	48 01 d1                                        	add    rcx,rdx
  7dce99:	ff e1                                           	jmp    rcx
  7dce9b:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dce9f:	4c 89 ef                                        	mov    rdi,r13
  7dcea2:	4c 89 e2                                        	mov    rdx,r12
  7dcea5:	e8 06 0d 00 00                                  	call   0x7ddbb0
  7dceaa:	85 c0                                           	test   eax,eax
  7dceac:	0f 85 05 ff ff ff                               	jne    0x7dcdb7
  7dceb2:	48 8d 55 90                                     	lea    rdx,[rbp-0x70]
  7dceb6:	48 8d 4d 8c                                     	lea    rcx,[rbp-0x74]
  7dceba:	48 89 df                                        	mov    rdi,rbx
  7dcebd:	44 89 fe                                        	mov    esi,r15d
  7dcec0:	e8 7b 83 bb ff                                  	call   0x395240
  7dcec5:	e9 78 0c 00 00                                  	jmp    0x7ddb42
  7dceca:	41 81 fe 33 01 00 00                            	cmp    r14d,0x133
  7dced1:	0f 87 99 00 00 00                               	ja     0x7dcf70
  7dced7:	44 89 f1                                        	mov    ecx,r14d
  7dceda:	48 8d 15 9b 36 fa 00                            	lea    rdx,[rip+0xfa369b]        # 0x178057c
  7dcee1:	48 63 0c 8a                                     	movsxd rcx,DWORD PTR [rdx+rcx*4]
  7dcee5:	48 01 d1                                        	add    rcx,rdx
  7dcee8:	ff e1                                           	jmp    rcx
  7dceea:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dceee:	4c 89 ef                                        	mov    rdi,r13
  7dcef1:	4c 89 e2                                        	mov    rdx,r12
  7dcef4:	e8 b7 0c 00 00                                  	call   0x7ddbb0
  7dcef9:	85 c0                                           	test   eax,eax
  7dcefb:	0f 85 b6 fe ff ff                               	jne    0x7dcdb7
  7dcf01:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dcf05:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dcf09:	48 89 df                                        	mov    rdi,rbx
  7dcf0c:	e8 5f 3c f1 ff                                  	call   0x6f0b70
  7dcf11:	e9 2c 0c 00 00                                  	jmp    0x7ddb42
  7dcf16:	41 81 fe 71 02 00 00                            	cmp    r14d,0x271
  7dcf1d:	74 16                                           	je     0x7dcf35
  7dcf1f:	41 81 fe 72 03 00 00                            	cmp    r14d,0x372
  7dcf26:	74 0d                                           	je     0x7dcf35
  7dcf28:	41 81 fe 73 04 00 00                            	cmp    r14d,0x473
  7dcf2f:	0f 85 1a ff ff ff                               	jne    0x7dce4f
  7dcf35:	48 8b bb 40 01 00 00                            	mov    rdi,QWORD PTR [rbx+0x140]
  7dcf3c:	e8 cf c1 e2 ff                                  	call   0x609110
  7dcf41:	83 f8 01                                        	cmp    eax,0x1
  7dcf44:	0f 84 05 ff ff ff                               	je     0x7dce4f
  7dcf4a:	48 8b bb 40 01 00 00                            	mov    rdi,QWORD PTR [rbx+0x140]
  7dcf51:	e8 7a c1 e2 ff                                  	call   0x6090d0
  7dcf56:	83 f8 01                                        	cmp    eax,0x1
  7dcf59:	0f 84 f0 fe ff ff                               	je     0x7dce4f
  7dcf5f:	48 8b bb 40 01 00 00                            	mov    rdi,QWORD PTR [rbx+0x140]
  7dcf66:	e8 35 01 a9 ff                                  	call   0x26d0a0
  7dcf6b:	e9 cf fe ff ff                                  	jmp    0x7dce3f
  7dcf70:	41 81 c6 ff fd ff ff                            	add    r14d,0xfffffdff
  7dcf77:	41 83 fe 70                                     	cmp    r14d,0x70
  7dcf7b:	0f 87 0a fe ff ff                               	ja     0x7dcd8b
  7dcf81:	48 8d 0d c4 3a fa 00                            	lea    rcx,[rip+0xfa3ac4]        # 0x1780a4c
  7dcf88:	4a 63 14 b1                                     	movsxd rdx,DWORD PTR [rcx+r14*4]
  7dcf8c:	48 01 ca                                        	add    rdx,rcx
  7dcf8f:	ff e2                                           	jmp    rdx
  7dcf91:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dcf95:	4c 89 ef                                        	mov    rdi,r13
  7dcf98:	4c 89 e2                                        	mov    rdx,r12
  7dcf9b:	e8 10 0c 00 00                                  	call   0x7ddbb0
  7dcfa0:	85 c0                                           	test   eax,eax
  7dcfa2:	0f 85 0f fe ff ff                               	jne    0x7dcdb7
  7dcfa8:	48 8d 55 90                                     	lea    rdx,[rbp-0x70]
  7dcfac:	48 8d 4d 8c                                     	lea    rcx,[rbp-0x74]
  7dcfb0:	48 89 df                                        	mov    rdi,rbx
  7dcfb3:	44 89 fe                                        	mov    esi,r15d
  7dcfb6:	e8 45 0c 00 00                                  	call   0x7ddc00
  7dcfbb:	e9 82 0b 00 00                                  	jmp    0x7ddb42
  7dcfc0:	41 8d 8e fe fc ff ff                            	lea    ecx,[r14-0x302]
  7dcfc7:	83 f9 1e                                        	cmp    ecx,0x1e
  7dcfca:	77 79                                           	ja     0x7dd045
  7dcfcc:	48 8d 15 3d 3c fa 00                            	lea    rdx,[rip+0xfa3c3d]        # 0x1780c10
  7dcfd3:	48 63 0c 8a                                     	movsxd rcx,DWORD PTR [rdx+rcx*4]
  7dcfd7:	48 01 d1                                        	add    rcx,rdx
  7dcfda:	ff e1                                           	jmp    rcx
  7dcfdc:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dcfe0:	4c 89 ef                                        	mov    rdi,r13
  7dcfe3:	4c 89 e2                                        	mov    rdx,r12
  7dcfe6:	e8 c5 0b 00 00                                  	call   0x7ddbb0
  7dcfeb:	85 c0                                           	test   eax,eax
  7dcfed:	0f 85 c4 fd ff ff                               	jne    0x7dcdb7
  7dcff3:	48 8d 55 90                                     	lea    rdx,[rbp-0x70]
  7dcff7:	48 8d 4d 8c                                     	lea    rcx,[rbp-0x74]
  7dcffb:	48 89 df                                        	mov    rdi,rbx
  7dcffe:	44 89 fe                                        	mov    esi,r15d
  7dd001:	e8 7a 21 00 00                                  	call   0x7df180
  7dd006:	e9 37 0b 00 00                                  	jmp    0x7ddb42
  7dd00b:	48 b9 00 00 00 00 00 60 00 00                   	movabs rcx,0x600000000000
  7dd015:	48 0f a3 c1                                     	bt     rcx,rax
  7dd019:	0f 83 30 fe ff ff                               	jae    0x7dce4f
  7dd01f:	48 8b bb 40 01 00 00                            	mov    rdi,QWORD PTR [rbx+0x140]
  7dd026:	e8 e5 c0 e2 ff                                  	call   0x609110
  7dd02b:	83 f8 01                                        	cmp    eax,0x1
  7dd02e:	0f 84 1b fe ff ff                               	je     0x7dce4f
  7dd034:	48 8b bb 40 01 00 00                            	mov    rdi,QWORD PTR [rbx+0x140]
  7dd03b:	e8 90 c0 e2 ff                                  	call   0x6090d0
  7dd040:	e9 fa fd ff ff                                  	jmp    0x7dce3f
  7dd045:	41 81 fe 72 03 00 00                            	cmp    r14d,0x372
  7dd04c:	0f 85 39 fd ff ff                               	jne    0x7dcd8b
  7dd052:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd056:	4c 89 ef                                        	mov    rdi,r13
  7dd059:	4c 89 e2                                        	mov    rdx,r12
  7dd05c:	e8 4f 0b 00 00                                  	call   0x7ddbb0
  7dd061:	85 c0                                           	test   eax,eax
  7dd063:	0f 85 4e fd ff ff                               	jne    0x7dcdb7
  7dd069:	48 8d 55 90                                     	lea    rdx,[rbp-0x70]
  7dd06d:	48 8d 4d 8c                                     	lea    rcx,[rbp-0x74]
  7dd071:	48 89 df                                        	mov    rdi,rbx
  7dd074:	44 89 fe                                        	mov    esi,r15d
  7dd077:	e8 d4 4f 42 00                                  	call   0xc02050
  7dd07c:	e9 c1 0a 00 00                                  	jmp    0x7ddb42
  7dd081:	41 81 fe 20 05 00 00                            	cmp    r14d,0x520
  7dd088:	0f 85 fd fc ff ff                               	jne    0x7dcd8b
  7dd08e:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd092:	48 89 df                                        	mov    rdi,rbx
  7dd095:	44 89 fe                                        	mov    esi,r15d
  7dd098:	e8 d3 d4 ab ff                                  	call   0x29a570
  7dd09d:	e9 a0 0a 00 00                                  	jmp    0x7ddb42
  7dd0a2:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd0a6:	48 89 df                                        	mov    rdi,rbx
  7dd0a9:	44 89 fe                                        	mov    esi,r15d
  7dd0ac:	e8 ef a1 bb ff                                  	call   0x3972a0
  7dd0b1:	e9 8c 0a 00 00                                  	jmp    0x7ddb42
  7dd0b6:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd0ba:	4c 89 ef                                        	mov    rdi,r13
  7dd0bd:	4c 89 e2                                        	mov    rdx,r12
  7dd0c0:	e8 eb 0a 00 00                                  	call   0x7ddbb0
  7dd0c5:	85 c0                                           	test   eax,eax
  7dd0c7:	0f 85 ea fc ff ff                               	jne    0x7dcdb7
  7dd0cd:	48 8d 55 90                                     	lea    rdx,[rbp-0x70]
  7dd0d1:	48 8d 4d 8c                                     	lea    rcx,[rbp-0x74]
  7dd0d5:	48 89 df                                        	mov    rdi,rbx
  7dd0d8:	44 89 fe                                        	mov    esi,r15d
  7dd0db:	e8 c0 a8 ab ff                                  	call   0x2979a0
  7dd0e0:	e9 5d 0a 00 00                                  	jmp    0x7ddb42
  7dd0e5:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd0e9:	4c 89 ef                                        	mov    rdi,r13
  7dd0ec:	4c 89 e2                                        	mov    rdx,r12
  7dd0ef:	e8 bc 0a 00 00                                  	call   0x7ddbb0
  7dd0f4:	85 c0                                           	test   eax,eax
  7dd0f6:	0f 85 bb fc ff ff                               	jne    0x7dcdb7
  7dd0fc:	48 8d 55 90                                     	lea    rdx,[rbp-0x70]
  7dd100:	48 8d 4d 8c                                     	lea    rcx,[rbp-0x74]
  7dd104:	48 89 df                                        	mov    rdi,rbx
  7dd107:	44 89 fe                                        	mov    esi,r15d
  7dd10a:	e8 a1 dd 2a 00                                  	call   0xa8aeb0
  7dd10f:	e9 2e 0a 00 00                                  	jmp    0x7ddb42
  7dd114:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd118:	4c 89 ef                                        	mov    rdi,r13
  7dd11b:	4c 89 e2                                        	mov    rdx,r12
  7dd11e:	e8 8d 0a 00 00                                  	call   0x7ddbb0
  7dd123:	85 c0                                           	test   eax,eax
  7dd125:	0f 85 8c fc ff ff                               	jne    0x7dcdb7
  7dd12b:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd12f:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd133:	44 89 ff                                        	mov    edi,r15d
  7dd136:	e8 95 3c 00 00                                  	call   0x7e0dd0
  7dd13b:	e9 02 0a 00 00                                  	jmp    0x7ddb42
  7dd140:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd144:	4c 89 ef                                        	mov    rdi,r13
  7dd147:	4c 89 e2                                        	mov    rdx,r12
  7dd14a:	e8 61 0a 00 00                                  	call   0x7ddbb0
  7dd14f:	85 c0                                           	test   eax,eax
  7dd151:	0f 85 60 fc ff ff                               	jne    0x7dcdb7
  7dd157:	48 8d 55 90                                     	lea    rdx,[rbp-0x70]
  7dd15b:	48 8d 4d 8c                                     	lea    rcx,[rbp-0x74]
  7dd15f:	48 89 df                                        	mov    rdi,rbx
  7dd162:	44 89 fe                                        	mov    esi,r15d
  7dd165:	e8 16 23 fe ff                                  	call   0x7bf480
  7dd16a:	e9 d3 09 00 00                                  	jmp    0x7ddb42
  7dd16f:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd173:	4c 89 ef                                        	mov    rdi,r13
  7dd176:	4c 89 e2                                        	mov    rdx,r12
  7dd179:	e8 32 0a 00 00                                  	call   0x7ddbb0
  7dd17e:	85 c0                                           	test   eax,eax
  7dd180:	0f 85 31 fc ff ff                               	jne    0x7dcdb7
  7dd186:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd18a:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd18e:	44 89 ff                                        	mov    edi,r15d
  7dd191:	e8 da 39 00 00                                  	call   0x7e0b70
  7dd196:	e9 a7 09 00 00                                  	jmp    0x7ddb42
  7dd19b:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd19f:	4c 89 ef                                        	mov    rdi,r13
  7dd1a2:	4c 89 e2                                        	mov    rdx,r12
  7dd1a5:	e8 06 0a 00 00                                  	call   0x7ddbb0
  7dd1aa:	85 c0                                           	test   eax,eax
  7dd1ac:	0f 85 05 fc ff ff                               	jne    0x7dcdb7
  7dd1b2:	48 8d 55 90                                     	lea    rdx,[rbp-0x70]
  7dd1b6:	48 8d 4d 8c                                     	lea    rcx,[rbp-0x74]
  7dd1ba:	48 89 df                                        	mov    rdi,rbx
  7dd1bd:	44 89 fe                                        	mov    esi,r15d
  7dd1c0:	e8 db 4f 42 00                                  	call   0xc021a0
  7dd1c5:	e9 78 09 00 00                                  	jmp    0x7ddb42
  7dd1ca:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd1ce:	4c 89 ef                                        	mov    rdi,r13
  7dd1d1:	4c 89 e2                                        	mov    rdx,r12
  7dd1d4:	e8 d7 09 00 00                                  	call   0x7ddbb0
  7dd1d9:	85 c0                                           	test   eax,eax
  7dd1db:	0f 85 d6 fb ff ff                               	jne    0x7dcdb7
  7dd1e1:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd1e5:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd1e9:	44 89 ff                                        	mov    edi,r15d
  7dd1ec:	e8 af 26 00 00                                  	call   0x7df8a0
  7dd1f1:	e9 4c 09 00 00                                  	jmp    0x7ddb42
  7dd1f6:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd1fa:	4c 89 ef                                        	mov    rdi,r13
  7dd1fd:	4c 89 e2                                        	mov    rdx,r12
  7dd200:	e8 ab 09 00 00                                  	call   0x7ddbb0
  7dd205:	85 c0                                           	test   eax,eax
  7dd207:	0f 85 aa fb ff ff                               	jne    0x7dcdb7
  7dd20d:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd211:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd215:	44 89 ff                                        	mov    edi,r15d
  7dd218:	e8 83 22 00 00                                  	call   0x7df4a0
  7dd21d:	e9 20 09 00 00                                  	jmp    0x7ddb42
  7dd222:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd226:	4c 89 ef                                        	mov    rdi,r13
  7dd229:	4c 89 e2                                        	mov    rdx,r12
  7dd22c:	e8 7f 09 00 00                                  	call   0x7ddbb0
  7dd231:	85 c0                                           	test   eax,eax
  7dd233:	0f 85 7e fb ff ff                               	jne    0x7dcdb7
  7dd239:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd23d:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd241:	44 89 ff                                        	mov    edi,r15d
  7dd244:	e8 f7 2d 00 00                                  	call   0x7e0040
  7dd249:	e9 f4 08 00 00                                  	jmp    0x7ddb42
  7dd24e:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd252:	4c 89 ef                                        	mov    rdi,r13
  7dd255:	4c 89 e2                                        	mov    rdx,r12
  7dd258:	e8 53 09 00 00                                  	call   0x7ddbb0
  7dd25d:	85 c0                                           	test   eax,eax
  7dd25f:	0f 85 52 fb ff ff                               	jne    0x7dcdb7
  7dd265:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd269:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd26d:	44 89 ff                                        	mov    edi,r15d
  7dd270:	e8 2b 33 00 00                                  	call   0x7e05a0
  7dd275:	e9 c8 08 00 00                                  	jmp    0x7ddb42
  7dd27a:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd27e:	4c 89 ef                                        	mov    rdi,r13
  7dd281:	4c 89 e2                                        	mov    rdx,r12
  7dd284:	e8 27 09 00 00                                  	call   0x7ddbb0
  7dd289:	85 c0                                           	test   eax,eax
  7dd28b:	0f 85 26 fb ff ff                               	jne    0x7dcdb7
  7dd291:	48 8d 55 90                                     	lea    rdx,[rbp-0x70]
  7dd295:	48 8d 4d 8c                                     	lea    rcx,[rbp-0x74]
  7dd299:	48 89 df                                        	mov    rdi,rbx
  7dd29c:	44 89 fe                                        	mov    esi,r15d
  7dd29f:	e8 7c 67 36 00                                  	call   0xb43a20
  7dd2a4:	e9 99 08 00 00                                  	jmp    0x7ddb42
  7dd2a9:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd2ad:	4c 89 ef                                        	mov    rdi,r13
  7dd2b0:	4c 89 e2                                        	mov    rdx,r12
  7dd2b3:	e8 f8 08 00 00                                  	call   0x7ddbb0
  7dd2b8:	85 c0                                           	test   eax,eax
  7dd2ba:	0f 85 f7 fa ff ff                               	jne    0x7dcdb7
  7dd2c0:	48 8d 55 90                                     	lea    rdx,[rbp-0x70]
  7dd2c4:	48 8d 4d 8c                                     	lea    rcx,[rbp-0x74]
  7dd2c8:	48 89 df                                        	mov    rdi,rbx
  7dd2cb:	44 89 fe                                        	mov    esi,r15d
  7dd2ce:	e8 1d 41 ae ff                                  	call   0x2c13f0
  7dd2d3:	e9 6a 08 00 00                                  	jmp    0x7ddb42
  7dd2d8:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd2dc:	4c 89 ef                                        	mov    rdi,r13
  7dd2df:	4c 89 e2                                        	mov    rdx,r12
  7dd2e2:	e8 c9 08 00 00                                  	call   0x7ddbb0
  7dd2e7:	85 c0                                           	test   eax,eax
  7dd2e9:	0f 85 c8 fa ff ff                               	jne    0x7dcdb7
  7dd2ef:	48 8d 55 90                                     	lea    rdx,[rbp-0x70]
  7dd2f3:	48 8d 4d 8c                                     	lea    rcx,[rbp-0x74]
  7dd2f7:	48 89 df                                        	mov    rdi,rbx
  7dd2fa:	44 89 fe                                        	mov    esi,r15d
  7dd2fd:	e8 1e 70 36 00                                  	call   0xb44320
  7dd302:	e9 3b 08 00 00                                  	jmp    0x7ddb42
  7dd307:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd30b:	4c 89 ef                                        	mov    rdi,r13
  7dd30e:	4c 89 e2                                        	mov    rdx,r12
  7dd311:	e8 9a 08 00 00                                  	call   0x7ddbb0
  7dd316:	85 c0                                           	test   eax,eax
  7dd318:	0f 85 99 fa ff ff                               	jne    0x7dcdb7
  7dd31e:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd322:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd326:	44 89 ff                                        	mov    edi,r15d
  7dd329:	e8 72 29 00 00                                  	call   0x7dfca0
  7dd32e:	e9 0f 08 00 00                                  	jmp    0x7ddb42
  7dd333:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd337:	4c 89 ef                                        	mov    rdi,r13
  7dd33a:	4c 89 e2                                        	mov    rdx,r12
  7dd33d:	e8 6e 08 00 00                                  	call   0x7ddbb0
  7dd342:	85 c0                                           	test   eax,eax
  7dd344:	0f 85 6d fa ff ff                               	jne    0x7dcdb7
  7dd34a:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd34e:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd352:	44 89 ff                                        	mov    edi,r15d
  7dd355:	e8 66 2f 00 00                                  	call   0x7e02c0
  7dd35a:	e9 e3 07 00 00                                  	jmp    0x7ddb42
  7dd35f:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd363:	4c 89 ef                                        	mov    rdi,r13
  7dd366:	4c 89 e2                                        	mov    rdx,r12
  7dd369:	e8 42 08 00 00                                  	call   0x7ddbb0
  7dd36e:	85 c0                                           	test   eax,eax
  7dd370:	0f 85 41 fa ff ff                               	jne    0x7dcdb7
  7dd376:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd37a:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd37e:	44 89 ff                                        	mov    edi,r15d
  7dd381:	e8 0a 35 00 00                                  	call   0x7e0890
  7dd386:	e9 b7 07 00 00                                  	jmp    0x7ddb42
  7dd38b:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd38f:	4c 89 ef                                        	mov    rdi,r13
  7dd392:	4c 89 e2                                        	mov    rdx,r12
  7dd395:	e8 16 08 00 00                                  	call   0x7ddbb0
  7dd39a:	85 c0                                           	test   eax,eax
  7dd39c:	0f 85 15 fa ff ff                               	jne    0x7dcdb7
  7dd3a2:	48 8d 55 90                                     	lea    rdx,[rbp-0x70]
  7dd3a6:	48 8d 4d 8c                                     	lea    rcx,[rbp-0x74]
  7dd3aa:	48 89 df                                        	mov    rdi,rbx
  7dd3ad:	44 89 fe                                        	mov    esi,r15d
  7dd3b0:	e8 8b 25 fe ff                                  	call   0x7bf940
  7dd3b5:	e9 88 07 00 00                                  	jmp    0x7ddb42
  7dd3ba:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd3be:	4c 89 ef                                        	mov    rdi,r13
  7dd3c1:	4c 89 e2                                        	mov    rdx,r12
  7dd3c4:	e8 e7 07 00 00                                  	call   0x7ddbb0
  7dd3c9:	85 c0                                           	test   eax,eax
  7dd3cb:	0f 85 e6 f9 ff ff                               	jne    0x7dcdb7
  7dd3d1:	48 8d 55 90                                     	lea    rdx,[rbp-0x70]
  7dd3d5:	48 8d 4d 8c                                     	lea    rcx,[rbp-0x74]
  7dd3d9:	48 89 df                                        	mov    rdi,rbx
  7dd3dc:	44 89 fe                                        	mov    esi,r15d
  7dd3df:	e8 1c 11 fe ff                                  	call   0x7be500
  7dd3e4:	e9 59 07 00 00                                  	jmp    0x7ddb42
  7dd3e9:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd3ed:	4c 89 ef                                        	mov    rdi,r13
  7dd3f0:	4c 89 e2                                        	mov    rdx,r12
  7dd3f3:	e8 b8 07 00 00                                  	call   0x7ddbb0
  7dd3f8:	85 c0                                           	test   eax,eax
  7dd3fa:	0f 85 b7 f9 ff ff                               	jne    0x7dcdb7
  7dd400:	48 8d 55 90                                     	lea    rdx,[rbp-0x70]
  7dd404:	48 8d 4d 8c                                     	lea    rcx,[rbp-0x74]
  7dd408:	48 89 df                                        	mov    rdi,rbx
  7dd40b:	44 89 fe                                        	mov    esi,r15d
  7dd40e:	e8 dd 2d fe ff                                  	call   0x7c01f0
  7dd413:	e9 2a 07 00 00                                  	jmp    0x7ddb42
  7dd418:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd41c:	4c 89 ef                                        	mov    rdi,r13
  7dd41f:	4c 89 e2                                        	mov    rdx,r12
  7dd422:	e8 89 07 00 00                                  	call   0x7ddbb0
  7dd427:	85 c0                                           	test   eax,eax
  7dd429:	0f 85 88 f9 ff ff                               	jne    0x7dcdb7
  7dd42f:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd433:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd437:	44 89 ff                                        	mov    edi,r15d
  7dd43a:	e8 11 ed f5 ff                                  	call   0x73c150
  7dd43f:	e9 fe 06 00 00                                  	jmp    0x7ddb42
  7dd444:	e8 a7 28 42 00                                  	call   0xbffcf0
  7dd449:	e9 3d f9 ff ff                                  	jmp    0x7dcd8b
  7dd44e:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd452:	4c 89 ef                                        	mov    rdi,r13
  7dd455:	4c 89 e2                                        	mov    rdx,r12
  7dd458:	e8 53 07 00 00                                  	call   0x7ddbb0
  7dd45d:	85 c0                                           	test   eax,eax
  7dd45f:	0f 85 52 f9 ff ff                               	jne    0x7dcdb7
  7dd465:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd469:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd46d:	44 89 ff                                        	mov    edi,r15d
  7dd470:	e8 eb fb f5 ff                                  	call   0x73d060
  7dd475:	e9 c8 06 00 00                                  	jmp    0x7ddb42
  7dd47a:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd47e:	4c 89 ef                                        	mov    rdi,r13
  7dd481:	4c 89 e2                                        	mov    rdx,r12
  7dd484:	e8 27 07 00 00                                  	call   0x7ddbb0
  7dd489:	85 c0                                           	test   eax,eax
  7dd48b:	0f 85 26 f9 ff ff                               	jne    0x7dcdb7
  7dd491:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd495:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd499:	44 89 ff                                        	mov    edi,r15d
  7dd49c:	e8 6f 59 42 00                                  	call   0xc02e10
  7dd4a1:	e9 9c 06 00 00                                  	jmp    0x7ddb42
  7dd4a6:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd4aa:	4c 89 ef                                        	mov    rdi,r13
  7dd4ad:	4c 89 e2                                        	mov    rdx,r12
  7dd4b0:	e8 fb 06 00 00                                  	call   0x7ddbb0
  7dd4b5:	85 c0                                           	test   eax,eax
  7dd4b7:	0f 85 fa f8 ff ff                               	jne    0x7dcdb7
  7dd4bd:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd4c1:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd4c5:	44 89 ff                                        	mov    edi,r15d
  7dd4c8:	e8 23 38 42 00                                  	call   0xc00cf0
  7dd4cd:	e9 70 06 00 00                                  	jmp    0x7ddb42
  7dd4d2:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd4d6:	4c 89 ef                                        	mov    rdi,r13
  7dd4d9:	4c 89 e2                                        	mov    rdx,r12
  7dd4dc:	e8 cf 06 00 00                                  	call   0x7ddbb0
  7dd4e1:	85 c0                                           	test   eax,eax
  7dd4e3:	0f 85 ce f8 ff ff                               	jne    0x7dcdb7
  7dd4e9:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd4ed:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd4f1:	44 89 ff                                        	mov    edi,r15d
  7dd4f4:	e8 07 55 42 00                                  	call   0xc02a00
  7dd4f9:	e9 44 06 00 00                                  	jmp    0x7ddb42
  7dd4fe:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd502:	4c 89 ef                                        	mov    rdi,r13
  7dd505:	4c 89 e2                                        	mov    rdx,r12
  7dd508:	e8 a3 06 00 00                                  	call   0x7ddbb0
  7dd50d:	85 c0                                           	test   eax,eax
  7dd50f:	0f 85 a2 f8 ff ff                               	jne    0x7dcdb7
  7dd515:	48 8d 7d 90                                     	lea    rdi,[rbp-0x70]
  7dd519:	48 8d 75 8c                                     	lea    rsi,[rbp-0x74]
  7dd51d:	e8 de ed f5 ff                                  	call   0x73c300
  7dd522:	e9 1b 06 00 00                                  	jmp    0x7ddb42
  7dd527:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd52b:	4c 89 ef                                        	mov    rdi,r13
  7dd52e:	4c 89 e2                                        	mov    rdx,r12
  7dd531:	e8 7a 06 00 00                                  	call   0x7ddbb0
  7dd536:	85 c0                                           	test   eax,eax
  7dd538:	0f 85 79 f8 ff ff                               	jne    0x7dcdb7
  7dd53e:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd542:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd546:	44 89 ff                                        	mov    edi,r15d
  7dd549:	e8 32 dc f5 ff                                  	call   0x73b180
  7dd54e:	e9 ef 05 00 00                                  	jmp    0x7ddb42
  7dd553:	4d 85 ed                                        	test   r13,r13
  7dd556:	b8 16 00 00 00                                  	mov    eax,0x16
  7dd55b:	0f 94 c1                                        	sete   cl
  7dd55e:	49 83 fc 40                                     	cmp    r12,0x40
  7dd562:	0f 95 c2                                        	setne  dl
  7dd565:	08 ca                                           	or     dl,cl
  7dd567:	0f 85 54 f8 ff ff                               	jne    0x7dcdc1
  7dd56d:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd571:	ba 40 00 00 00                                  	mov    edx,0x40
  7dd576:	4c 89 ef                                        	mov    rdi,r13
  7dd579:	e8 32 06 00 00                                  	call   0x7ddbb0
  7dd57e:	85 c0                                           	test   eax,eax
  7dd580:	0f 85 31 f8 ff ff                               	jne    0x7dcdb7
  7dd586:	48 8d 55 90                                     	lea    rdx,[rbp-0x70]
  7dd58a:	48 8d 4d 8c                                     	lea    rcx,[rbp-0x74]
  7dd58e:	48 89 df                                        	mov    rdi,rbx
  7dd591:	44 89 fe                                        	mov    esi,r15d
  7dd594:	e8 07 4d 42 00                                  	call   0xc022a0
  7dd599:	e9 a4 05 00 00                                  	jmp    0x7ddb42
  7dd59e:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd5a2:	4c 89 ef                                        	mov    rdi,r13
  7dd5a5:	4c 89 e2                                        	mov    rdx,r12
  7dd5a8:	e8 03 06 00 00                                  	call   0x7ddbb0
  7dd5ad:	85 c0                                           	test   eax,eax
  7dd5af:	0f 85 02 f8 ff ff                               	jne    0x7dcdb7
  7dd5b5:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd5b9:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd5bd:	44 89 ff                                        	mov    edi,r15d
  7dd5c0:	e8 7b e5 f5 ff                                  	call   0x73bb40
  7dd5c5:	e9 78 05 00 00                                  	jmp    0x7ddb42
  7dd5ca:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd5ce:	48 89 df                                        	mov    rdi,rbx
  7dd5d1:	44 89 fe                                        	mov    esi,r15d
  7dd5d4:	e8 87 c9 ab ff                                  	call   0x299f60
  7dd5d9:	e9 64 05 00 00                                  	jmp    0x7ddb42
  7dd5de:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd5e2:	4c 89 ef                                        	mov    rdi,r13
  7dd5e5:	4c 89 e2                                        	mov    rdx,r12
  7dd5e8:	e8 c3 05 00 00                                  	call   0x7ddbb0
  7dd5ed:	85 c0                                           	test   eax,eax
  7dd5ef:	0f 85 c2 f7 ff ff                               	jne    0x7dcdb7
  7dd5f5:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd5f9:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd5fd:	44 89 ff                                        	mov    edi,r15d
  7dd600:	e8 eb ca f5 ff                                  	call   0x73a0f0
  7dd605:	e9 38 05 00 00                                  	jmp    0x7ddb42
  7dd60a:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd60e:	4c 89 ef                                        	mov    rdi,r13
  7dd611:	4c 89 e2                                        	mov    rdx,r12
  7dd614:	e8 97 05 00 00                                  	call   0x7ddbb0
  7dd619:	85 c0                                           	test   eax,eax
  7dd61b:	0f 85 96 f7 ff ff                               	jne    0x7dcdb7
  7dd621:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd625:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd629:	44 89 ff                                        	mov    edi,r15d
  7dd62c:	e8 df dc f5 ff                                  	call   0x73b310
  7dd631:	e9 0c 05 00 00                                  	jmp    0x7ddb42
  7dd636:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd63a:	4c 89 ef                                        	mov    rdi,r13
  7dd63d:	4c 89 e2                                        	mov    rdx,r12
  7dd640:	e8 6b 05 00 00                                  	call   0x7ddbb0
  7dd645:	85 c0                                           	test   eax,eax
  7dd647:	0f 85 6a f7 ff ff                               	jne    0x7dcdb7
  7dd64d:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd651:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd655:	48 89 df                                        	mov    rdi,rbx
  7dd658:	e8 b3 9f bb ff                                  	call   0x397610
  7dd65d:	e9 e0 04 00 00                                  	jmp    0x7ddb42
  7dd662:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd666:	48 89 df                                        	mov    rdi,rbx
  7dd669:	44 89 fe                                        	mov    esi,r15d
  7dd66c:	e8 af f0 28 00                                  	call   0xa6c720
  7dd671:	e9 cc 04 00 00                                  	jmp    0x7ddb42
  7dd676:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd67a:	48 89 df                                        	mov    rdi,rbx
  7dd67d:	44 89 fe                                        	mov    esi,r15d
  7dd680:	e8 db f0 28 00                                  	call   0xa6c760
  7dd685:	e9 b8 04 00 00                                  	jmp    0x7ddb42
  7dd68a:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd68e:	4c 89 ef                                        	mov    rdi,r13
  7dd691:	4c 89 e2                                        	mov    rdx,r12
  7dd694:	e8 17 05 00 00                                  	call   0x7ddbb0
  7dd699:	85 c0                                           	test   eax,eax
  7dd69b:	0f 85 16 f7 ff ff                               	jne    0x7dcdb7
  7dd6a1:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd6a5:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd6a9:	44 89 ff                                        	mov    edi,r15d
  7dd6ac:	e8 8f c7 f5 ff                                  	call   0x739e40
  7dd6b1:	e9 8c 04 00 00                                  	jmp    0x7ddb42
  7dd6b6:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd6ba:	4c 89 ef                                        	mov    rdi,r13
  7dd6bd:	4c 89 e2                                        	mov    rdx,r12
  7dd6c0:	e8 eb 04 00 00                                  	call   0x7ddbb0
  7dd6c5:	85 c0                                           	test   eax,eax
  7dd6c7:	0f 85 ea f6 ff ff                               	jne    0x7dcdb7
  7dd6cd:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd6d1:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd6d5:	48 89 df                                        	mov    rdi,rbx
  7dd6d8:	e8 73 3f f1 ff                                  	call   0x6f1650
  7dd6dd:	e9 60 04 00 00                                  	jmp    0x7ddb42
  7dd6e2:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd6e6:	4c 89 ef                                        	mov    rdi,r13
  7dd6e9:	4c 89 e2                                        	mov    rdx,r12
  7dd6ec:	e8 bf 04 00 00                                  	call   0x7ddbb0
  7dd6f1:	85 c0                                           	test   eax,eax
  7dd6f3:	0f 85 be f6 ff ff                               	jne    0x7dcdb7
  7dd6f9:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd6fd:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd701:	44 89 ff                                        	mov    edi,r15d
  7dd704:	e8 07 ca f5 ff                                  	call   0x73a110
  7dd709:	e9 34 04 00 00                                  	jmp    0x7ddb42
  7dd70e:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd712:	4c 89 ef                                        	mov    rdi,r13
  7dd715:	4c 89 e2                                        	mov    rdx,r12
  7dd718:	e8 93 04 00 00                                  	call   0x7ddbb0
  7dd71d:	85 c0                                           	test   eax,eax
  7dd71f:	0f 85 92 f6 ff ff                               	jne    0x7dcdb7
  7dd725:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd729:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd72d:	44 89 ff                                        	mov    edi,r15d
  7dd730:	e8 8b cc f5 ff                                  	call   0x73a3c0
  7dd735:	e9 08 04 00 00                                  	jmp    0x7ddb42
  7dd73a:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd73e:	4c 89 ef                                        	mov    rdi,r13
  7dd741:	4c 89 e2                                        	mov    rdx,r12
  7dd744:	e8 67 04 00 00                                  	call   0x7ddbb0
  7dd749:	85 c0                                           	test   eax,eax
  7dd74b:	0f 85 66 f6 ff ff                               	jne    0x7dcdb7
  7dd751:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd755:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd759:	44 89 ff                                        	mov    edi,r15d
  7dd75c:	e8 6f c9 f5 ff                                  	call   0x73a0d0
  7dd761:	e9 dc 03 00 00                                  	jmp    0x7ddb42
  7dd766:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd76a:	4c 89 ef                                        	mov    rdi,r13
  7dd76d:	4c 89 e2                                        	mov    rdx,r12
  7dd770:	e8 3b 04 00 00                                  	call   0x7ddbb0
  7dd775:	85 c0                                           	test   eax,eax
  7dd777:	0f 85 3a f6 ff ff                               	jne    0x7dcdb7
  7dd77d:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd781:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd785:	44 89 ff                                        	mov    edi,r15d
  7dd788:	e8 03 38 42 00                                  	call   0xc00f90
  7dd78d:	e9 b0 03 00 00                                  	jmp    0x7ddb42
  7dd792:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd796:	4c 89 ef                                        	mov    rdi,r13
  7dd799:	4c 89 e2                                        	mov    rdx,r12
  7dd79c:	e8 0f 04 00 00                                  	call   0x7ddbb0
  7dd7a1:	85 c0                                           	test   eax,eax
  7dd7a3:	0f 85 0e f6 ff ff                               	jne    0x7dcdb7
  7dd7a9:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd7ad:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd7b1:	44 89 ff                                        	mov    edi,r15d
  7dd7b4:	e8 87 ce f5 ff                                  	call   0x73a640
  7dd7b9:	e9 84 03 00 00                                  	jmp    0x7ddb42
  7dd7be:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd7c2:	4c 89 ef                                        	mov    rdi,r13
  7dd7c5:	4c 89 e2                                        	mov    rdx,r12
  7dd7c8:	e8 e3 03 00 00                                  	call   0x7ddbb0
  7dd7cd:	85 c0                                           	test   eax,eax
  7dd7cf:	0f 85 e2 f5 ff ff                               	jne    0x7dcdb7
  7dd7d5:	8b 7d 90                                        	mov    edi,DWORD PTR [rbp-0x70]
  7dd7d8:	e8 f3 23 42 00                                  	call   0xbffbd0
  7dd7dd:	e9 a9 f5 ff ff                                  	jmp    0x7dcd8b
  7dd7e2:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd7e6:	4c 89 ef                                        	mov    rdi,r13
  7dd7e9:	4c 89 e2                                        	mov    rdx,r12
  7dd7ec:	e8 bf 03 00 00                                  	call   0x7ddbb0
  7dd7f1:	85 c0                                           	test   eax,eax
  7dd7f3:	0f 85 be f5 ff ff                               	jne    0x7dcdb7
  7dd7f9:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd7fd:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd801:	44 89 ff                                        	mov    edi,r15d
  7dd804:	e8 d7 cb f5 ff                                  	call   0x73a3e0
  7dd809:	e9 34 03 00 00                                  	jmp    0x7ddb42
  7dd80e:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd812:	4c 89 ef                                        	mov    rdi,r13
  7dd815:	4c 89 e2                                        	mov    rdx,r12
  7dd818:	e8 93 03 00 00                                  	call   0x7ddbb0
  7dd81d:	85 c0                                           	test   eax,eax
  7dd81f:	0f 85 92 f5 ff ff                               	jne    0x7dcdb7
  7dd825:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd829:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd82d:	44 89 ff                                        	mov    edi,r15d
  7dd830:	e8 6b cb f5 ff                                  	call   0x73a3a0
  7dd835:	e9 08 03 00 00                                  	jmp    0x7ddb42
  7dd83a:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd83e:	4c 89 ef                                        	mov    rdi,r13
  7dd841:	4c 89 e2                                        	mov    rdx,r12
  7dd844:	e8 67 03 00 00                                  	call   0x7ddbb0
  7dd849:	85 c0                                           	test   eax,eax
  7dd84b:	0f 85 66 f5 ff ff                               	jne    0x7dcdb7
  7dd851:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd855:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd859:	44 89 ff                                        	mov    edi,r15d
  7dd85c:	e8 3f dd f5 ff                                  	call   0x73b5a0
  7dd861:	e9 dc 02 00 00                                  	jmp    0x7ddb42
  7dd866:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd86a:	4c 89 ef                                        	mov    rdi,r13
  7dd86d:	4c 89 e2                                        	mov    rdx,r12
  7dd870:	e8 3b 03 00 00                                  	call   0x7ddbb0
  7dd875:	85 c0                                           	test   eax,eax
  7dd877:	0f 85 3a f5 ff ff                               	jne    0x7dcdb7
  7dd87d:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd881:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd885:	44 89 ff                                        	mov    edi,r15d
  7dd888:	e8 63 e0 f5 ff                                  	call   0x73b8f0
  7dd88d:	e9 b0 02 00 00                                  	jmp    0x7ddb42
  7dd892:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd896:	4c 89 ef                                        	mov    rdi,r13
  7dd899:	4c 89 e2                                        	mov    rdx,r12
  7dd89c:	e8 0f 03 00 00                                  	call   0x7ddbb0
  7dd8a1:	85 c0                                           	test   eax,eax
  7dd8a3:	0f 85 0e f5 ff ff                               	jne    0x7dcdb7
  7dd8a9:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd8ad:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd8b1:	44 89 ff                                        	mov    edi,r15d
  7dd8b4:	e8 17 d7 f5 ff                                  	call   0x73afd0
  7dd8b9:	e9 84 02 00 00                                  	jmp    0x7ddb42
  7dd8be:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd8c2:	4c 89 ef                                        	mov    rdi,r13
  7dd8c5:	4c 89 e2                                        	mov    rdx,r12
  7dd8c8:	e8 e3 02 00 00                                  	call   0x7ddbb0
  7dd8cd:	85 c0                                           	test   eax,eax
  7dd8cf:	0f 85 e2 f4 ff ff                               	jne    0x7dcdb7
  7dd8d5:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd8d9:	48 8d 55 8c                                     	lea    rdx,[rbp-0x74]
  7dd8dd:	44 89 ff                                        	mov    edi,r15d
  7dd8e0:	e8 6b ec f5 ff                                  	call   0x73c550
  7dd8e5:	e9 58 02 00 00                                  	jmp    0x7ddb42
  7dd8ea:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd8ee:	4c 89 ef                                        	mov    rdi,r13
  7dd8f1:	4c 89 e2                                        	mov    rdx,r12
  7dd8f4:	e8 b7 02 00 00                                  	call   0x7ddbb0
  7dd8f9:	85 c0                                           	test   eax,eax
  7dd8fb:	0f 85 b6 f4 ff ff                               	jne    0x7dcdb7
  7dd901:	48 8d 55 90                                     	lea    rdx,[rbp-0x70]
  7dd905:	48 8d 4d 8c                                     	lea    rcx,[rbp-0x74]
  7dd909:	48 89 df                                        	mov    rdi,rbx
  7dd90c:	44 89 fe                                        	mov    esi,r15d
  7dd90f:	e8 9c 3b 42 00                                  	call   0xc014b0
  7dd914:	e9 29 02 00 00                                  	jmp    0x7ddb42
  7dd919:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd91d:	4c 89 ef                                        	mov    rdi,r13
  7dd920:	4c 89 e2                                        	mov    rdx,r12
  7dd923:	e8 88 02 00 00                                  	call   0x7ddbb0
  7dd928:	85 c0                                           	test   eax,eax
  7dd92a:	0f 85 87 f4 ff ff                               	jne    0x7dcdb7
  7dd930:	48 8d 55 90                                     	lea    rdx,[rbp-0x70]
  7dd934:	48 8d 4d 8c                                     	lea    rcx,[rbp-0x74]
  7dd938:	48 89 df                                        	mov    rdi,rbx
  7dd93b:	44 89 fe                                        	mov    esi,r15d
  7dd93e:	e8 0d 2d ae ff                                  	call   0x2c0650
  7dd943:	e9 fa 01 00 00                                  	jmp    0x7ddb42
  7dd948:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd94c:	4c 89 ef                                        	mov    rdi,r13
  7dd94f:	4c 89 e2                                        	mov    rdx,r12
  7dd952:	e8 59 02 00 00                                  	call   0x7ddbb0
  7dd957:	85 c0                                           	test   eax,eax
  7dd959:	0f 85 58 f4 ff ff                               	jne    0x7dcdb7
  7dd95f:	48 8d 55 90                                     	lea    rdx,[rbp-0x70]
  7dd963:	48 8d 4d 8c                                     	lea    rcx,[rbp-0x74]
  7dd967:	48 89 df                                        	mov    rdi,rbx
  7dd96a:	44 89 fe                                        	mov    esi,r15d
  7dd96d:	e8 3e ae bb ff                                  	call   0x3987b0
  7dd972:	e9 cb 01 00 00                                  	jmp    0x7ddb42
  7dd977:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd97b:	4c 89 ef                                        	mov    rdi,r13
  7dd97e:	4c 89 e2                                        	mov    rdx,r12
  7dd981:	e8 2a 02 00 00                                  	call   0x7ddbb0
  7dd986:	85 c0                                           	test   eax,eax
  7dd988:	0f 85 29 f4 ff ff                               	jne    0x7dcdb7
  7dd98e:	48 8d 55 90                                     	lea    rdx,[rbp-0x70]
  7dd992:	48 8d 4d 8c                                     	lea    rcx,[rbp-0x74]
  7dd996:	48 89 df                                        	mov    rdi,rbx
  7dd999:	44 89 fe                                        	mov    esi,r15d
  7dd99c:	e8 bf a4 38 00                                  	call   0xb67e60
  7dd9a1:	e9 9c 01 00 00                                  	jmp    0x7ddb42
  7dd9a6:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd9aa:	4c 89 ef                                        	mov    rdi,r13
  7dd9ad:	4c 89 e2                                        	mov    rdx,r12
  7dd9b0:	e8 fb 01 00 00                                  	call   0x7ddbb0
  7dd9b5:	85 c0                                           	test   eax,eax
  7dd9b7:	0f 85 fa f3 ff ff                               	jne    0x7dcdb7
  7dd9bd:	48 8d 55 90                                     	lea    rdx,[rbp-0x70]
  7dd9c1:	48 8d 4d 8c                                     	lea    rcx,[rbp-0x74]
  7dd9c5:	48 89 df                                        	mov    rdi,rbx
  7dd9c8:	44 89 fe                                        	mov    esi,r15d
  7dd9cb:	e8 b0 4e 36 00                                  	call   0xb42880
  7dd9d0:	e9 6d 01 00 00                                  	jmp    0x7ddb42
  7dd9d5:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dd9d9:	4c 89 ef                                        	mov    rdi,r13
  7dd9dc:	4c 89 e2                                        	mov    rdx,r12
  7dd9df:	e8 cc 01 00 00                                  	call   0x7ddbb0
  7dd9e4:	85 c0                                           	test   eax,eax
  7dd9e6:	0f 85 cb f3 ff ff                               	jne    0x7dcdb7
  7dd9ec:	48 8d 55 90                                     	lea    rdx,[rbp-0x70]
  7dd9f0:	48 8d 4d 8c                                     	lea    rcx,[rbp-0x74]
  7dd9f4:	48 89 df                                        	mov    rdi,rbx
  7dd9f7:	44 89 fe                                        	mov    esi,r15d
  7dd9fa:	e8 11 f4 2a 00                                  	call   0xa8ce10
  7dd9ff:	e9 3e 01 00 00                                  	jmp    0x7ddb42
  7dda04:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dda08:	4c 89 ef                                        	mov    rdi,r13
  7dda0b:	4c 89 e2                                        	mov    rdx,r12
  7dda0e:	e8 9d 01 00 00                                  	call   0x7ddbb0
  7dda13:	85 c0                                           	test   eax,eax
  7dda15:	0f 85 9c f3 ff ff                               	jne    0x7dcdb7
  7dda1b:	48 8d 55 90                                     	lea    rdx,[rbp-0x70]
  7dda1f:	48 8d 4d 8c                                     	lea    rcx,[rbp-0x74]
  7dda23:	48 89 df                                        	mov    rdi,rbx
  7dda26:	44 89 fe                                        	mov    esi,r15d
  7dda29:	e8 62 3f ae ff                                  	call   0x2c1990
  7dda2e:	e9 0f 01 00 00                                  	jmp    0x7ddb42
  7dda33:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dda37:	4c 89 ef                                        	mov    rdi,r13
  7dda3a:	4c 89 e2                                        	mov    rdx,r12
  7dda3d:	e8 6e 01 00 00                                  	call   0x7ddbb0
  7dda42:	85 c0                                           	test   eax,eax
  7dda44:	0f 85 6d f3 ff ff                               	jne    0x7dcdb7
  7dda4a:	48 8d 55 90                                     	lea    rdx,[rbp-0x70]
  7dda4e:	48 8d 4d 8c                                     	lea    rcx,[rbp-0x74]
  7dda52:	48 89 df                                        	mov    rdi,rbx
  7dda55:	44 89 fe                                        	mov    esi,r15d
  7dda58:	e8 43 c5 ab ff                                  	call   0x299fa0
  7dda5d:	e9 e0 00 00 00                                  	jmp    0x7ddb42
  7dda62:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dda66:	4c 89 ef                                        	mov    rdi,r13
  7dda69:	4c 89 e2                                        	mov    rdx,r12
  7dda6c:	e8 3f 01 00 00                                  	call   0x7ddbb0
  7dda71:	85 c0                                           	test   eax,eax
  7dda73:	0f 85 3e f3 ff ff                               	jne    0x7dcdb7
  7dda79:	48 8d 55 90                                     	lea    rdx,[rbp-0x70]
  7dda7d:	48 8d 4d 8c                                     	lea    rcx,[rbp-0x74]
  7dda81:	48 89 df                                        	mov    rdi,rbx
  7dda84:	44 89 fe                                        	mov    esi,r15d
  7dda87:	e8 04 4b ae ff                                  	call   0x2c2590
  7dda8c:	e9 b1 00 00 00                                  	jmp    0x7ddb42
  7dda91:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7dda95:	4c 89 ef                                        	mov    rdi,r13
  7dda98:	4c 89 e2                                        	mov    rdx,r12
  7dda9b:	e8 10 01 00 00                                  	call   0x7ddbb0
  7ddaa0:	85 c0                                           	test   eax,eax
  7ddaa2:	0f 85 0f f3 ff ff                               	jne    0x7dcdb7
  7ddaa8:	48 8d 55 90                                     	lea    rdx,[rbp-0x70]
  7ddaac:	48 8d 4d 8c                                     	lea    rcx,[rbp-0x74]
  7ddab0:	48 89 df                                        	mov    rdi,rbx
  7ddab3:	44 89 fe                                        	mov    esi,r15d
  7ddab6:	e8 25 58 36 00                                  	call   0xb432e0
  7ddabb:	e9 82 00 00 00                                  	jmp    0x7ddb42
  7ddac0:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7ddac4:	4c 89 ef                                        	mov    rdi,r13
  7ddac7:	4c 89 e2                                        	mov    rdx,r12
  7ddaca:	e8 e1 00 00 00                                  	call   0x7ddbb0
  7ddacf:	85 c0                                           	test   eax,eax
  7ddad1:	0f 85 e0 f2 ff ff                               	jne    0x7dcdb7
  7ddad7:	48 8d 55 90                                     	lea    rdx,[rbp-0x70]
  7ddadb:	48 8d 4d 8c                                     	lea    rcx,[rbp-0x74]
  7ddadf:	48 89 df                                        	mov    rdi,rbx
  7ddae2:	44 89 fe                                        	mov    esi,r15d
  7ddae5:	e8 26 5f 36 00                                  	call   0xb43a10
  7ddaea:	eb 56                                           	jmp    0x7ddb42
  7ddaec:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7ddaf0:	4c 89 ef                                        	mov    rdi,r13
  7ddaf3:	4c 89 e2                                        	mov    rdx,r12
  7ddaf6:	e8 b5 00 00 00                                  	call   0x7ddbb0
  7ddafb:	85 c0                                           	test   eax,eax
  7ddafd:	0f 85 b4 f2 ff ff                               	jne    0x7dcdb7
  7ddb03:	48 8d 55 90                                     	lea    rdx,[rbp-0x70]
  7ddb07:	48 8d 4d 8c                                     	lea    rcx,[rbp-0x74]
  7ddb0b:	48 89 df                                        	mov    rdi,rbx
  7ddb0e:	44 89 fe                                        	mov    esi,r15d
  7ddb11:	e8 5a 57 36 00                                  	call   0xb43270
  7ddb16:	eb 2a                                           	jmp    0x7ddb42
  7ddb18:	48 8d 75 90                                     	lea    rsi,[rbp-0x70]
  7ddb1c:	4c 89 ef                                        	mov    rdi,r13
  7ddb1f:	4c 89 e2                                        	mov    rdx,r12
  7ddb22:	e8 89 00 00 00                                  	call   0x7ddbb0
  7ddb27:	85 c0                                           	test   eax,eax
  7ddb29:	0f 85 88 f2 ff ff                               	jne    0x7dcdb7
  7ddb2f:	48 8d 55 90                                     	lea    rdx,[rbp-0x70]
  7ddb33:	48 8d 4d 8c                                     	lea    rcx,[rbp-0x74]
  7ddb37:	48 89 df                                        	mov    rdi,rbx
  7ddb3a:	44 89 fe                                        	mov    esi,r15d
  7ddb3d:	e8 6e 5e 36 00                                  	call   0xb439b0
  7ddb42:	85 c0                                           	test   eax,eax
  7ddb44:	0f 85 6d f2 ff ff                               	jne    0x7dcdb7
  7ddb4a:	e9 3f f2 ff ff                                  	jmp    0x7dcd8e
  7ddb4f:	e8 5c fb f1 ff                                  	call   0x6fd6b0
  7ddb54:	0f 0b                                           	ud2
  7ddb56:	41 89 c6                                        	mov    r14d,eax
  7ddb59:	e8 f2 3d 01 00                                  	call   0x7f1950
  7ddb5e:	48 63 b3 9c 00 00 00                            	movsxd rsi,DWORD PTR [rbx+0x9c]
  7ddb65:	48 63 8b 98 03 00 00                            	movsxd rcx,DWORD PTR [rbx+0x398]
  7ddb6c:	4d 63 f6                                        	movsxd r14,r14d
  7ddb6f:	48 8d 3d e0 ff ff ff                            	lea    rdi,[rip+0xffffffffffffffe0]        # 0x7ddb56
  7ddb76:	4c 89 f2                                        	mov    rdx,r14
  7ddb79:	e8 42 45 01 00                                  	call   0x7f20c0
  7ddb7e:	8b 93 9c 00 00 00                               	mov    edx,DWORD PTR [rbx+0x9c]
  7ddb84:	44 8b 83 98 03 00 00                            	mov    r8d,DWORD PTR [rbx+0x398]
  7ddb8b:	48 8d 35 46 bd ab 00                            	lea    rsi,[rip+0xabbd46]        # 0x12998d8
  7ddb92:	bf 30 00 00 00                                  	mov    edi,0x30
  7ddb97:	44 89 f1                                        	mov    ecx,r14d
  7ddb9a:	31 c0                                           	xor    eax,eax
  7ddb9c:	e8 6f ce 4b 00                                  	call   0xc9aa10
  7ddba1:	0f 0b                                           	ud2
  7ddba3:	90                                              	nop
  7ddba4:	90                                              	nop
  7ddba5:	90                                              	nop
  7ddba6:	90                                              	nop
  7ddba7:	90                                              	nop
  7ddba8:	90                                              	nop
  7ddba9:	90                                              	nop
  7ddbaa:	90                                              	nop
  7ddbab:	90                                              	nop
  7ddbac:	90                                              	nop
  7ddbad:	90                                              	nop
  7ddbae:	90                                              	nop
  7ddbaf:	90                                              	nop
  7ddbb0:	55                                              	push   rbp
  7ddbb1:	48 89 e5                                        	mov    rbp,rsp
  7ddbb4:	41 57                                           	push   r15
  7ddbb6:	41 56                                           	push   r14
  7ddbb8:	53                                              	push   rbx
  7ddbb9:	50                                              	push   rax
  7ddbba:	49 89 ff                                        	mov    r15,rdi
  7ddbbd:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  7ddbc6:	49 89 f6                                        	mov    r14,rsi
  7ddbc9:	48 8d 35 6d a3 bb 00                            	lea    rsi,[rip+0xbba36d]        # 0x1397f3d
  7ddbd0:	48 89 d3                                        	mov    rbx,rdx
  7ddbd3:	31 d2                                           	xor    edx,edx
  7ddbd5:	e8 06 c8 43 00                                  	call   0xc1a3e0
  7ddbda:	4c 89 ff                                        	mov    rdi,r15
  7ddbdd:	4c 89 f6                                        	mov    rsi,r14
  7ddbe0:	48 89 da                                        	mov    rdx,rbx
  7ddbe3:	48 83 c4 08                                     	add    rsp,0x8
  7ddbe7:	5b                                              	pop    rbx
  7ddbe8:	41 5e                                           	pop    r14
  7ddbea:	41 5f                                           	pop    r15
  7ddbec:	5d                                              	pop    rbp
  7ddbed:	e9 8e b6 a7 ff                                  	jmp    0x259280
  7ddbf2:	90                                              	nop
  7ddbf3:	90                                              	nop
  7ddbf4:	90                                              	nop
  7ddbf5:	90                                              	nop
  7ddbf6:	90                                              	nop
  7ddbf7:	90                                              	nop
  7ddbf8:	90                                              	nop
  7ddbf9:	90                                              	nop
  7ddbfa:	90                                              	nop
  7ddbfb:	90                                              	nop
  7ddbfc:	90                                              	nop
  7ddbfd:	90                                              	nop
  7ddbfe:	90                                              	nop
  7ddbff:	90                                              	nop
  7ddc00:	55                                              	push   rbp
  7ddc01:	48 89 e5                                        	mov    rbp,rsp
  7ddc04:	41 57                                           	push   r15
  7ddc06:	41 56                                           	push   r14
  7ddc08:	41 55                                           	push   r13
  7ddc0a:	41 54                                           	push   r12
  7ddc0c:	53                                              	push   rbx
  7ddc0d:	48 81 ec c8 02 00 00                            	sub    rsp,0x2c8
  7ddc14:	48 8d 05 f5 e6 13 03                            	lea    rax,[rip+0x313e6f5]        # 0x391c310
  7ddc1b:	48 89 bd a0 fd ff ff                            	mov    QWORD PTR [rbp-0x260],rdi
  7ddc22:	41 89 f5                                        	mov    r13d,esi
  7ddc25:	49 89 cc                                        	mov    r12,rcx
  7ddc28:	48 8d bd c0 fd ff ff                            	lea    rdi,[rbp-0x240]
  7ddc2f:	49 89 d6                                        	mov    r14,rdx
  7ddc32:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  7ddc35:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  7ddc39:	48 c7 85 00 fe ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x200],0x0
  7ddc44:	48 c7 85 f8 fd ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x208],0x0
  7ddc4f:	48 c7 85 f0 fd ff ff 00 00 01 02                	mov    QWORD PTR [rbp-0x210],0x2010000
  7ddc5a:	48 8b 72 08                                     	mov    rsi,QWORD PTR [rdx+0x8]
  7ddc5e:	48 8b 02                                        	mov    rax,QWORD PTR [rdx]
  7ddc61:	48 8b 4a 10                                     	mov    rcx,QWORD PTR [rdx+0x10]
  7ddc65:	4c 8b 7a 18                                     	mov    r15,QWORD PTR [rdx+0x18]
  7ddc69:	c7 85 e4 fd ff ff 00 00 00 00                   	mov    DWORD PTR [rbp-0x21c],0x0
  7ddc73:	48 89 b5 58 fd ff ff                            	mov    QWORD PTR [rbp-0x2a8],rsi
  7ddc7a:	be 20 00 00 00                                  	mov    esi,0x20
  7ddc7f:	48 89 85 70 fd ff ff                            	mov    QWORD PTR [rbp-0x290],rax
  7ddc86:	48 89 8d 78 fd ff ff                            	mov    QWORD PTR [rbp-0x288],rcx
  7ddc8d:	e8 5e b3 a7 ff                                  	call   0x258ff0
  7ddc92:	48 8d b5 30 fe ff ff                            	lea    rsi,[rbp-0x1d0]
  7ddc99:	44 89 ef                                        	mov    edi,r13d
  7ddc9c:	c7 85 c0 fd ff ff ff 0f 00 00                   	mov    DWORD PTR [rbp-0x240],0xfff
  7ddca6:	44 89 ad c4 fd ff ff                            	mov    DWORD PTR [rbp-0x23c],r13d
  7ddcad:	48 c7 85 c8 fd ff ff ff ff ff ff                	mov    QWORD PTR [rbp-0x238],0xffffffffffffffff
  7ddcb8:	e8 63 45 42 00                                  	call   0xc02220
  7ddcbd:	85 c0                                           	test   eax,eax
  7ddcbf:	74 07                                           	je     0x7ddcc8
  7ddcc1:	c6 85 30 fe ff ff 00                            	mov    BYTE PTR [rbp-0x1d0],0x0
  7ddcc8:	45 8b 4e 08                                     	mov    r9d,DWORD PTR [r14+0x8]
  7ddccc:	48 83 ec 08                                     	sub    rsp,0x8
  7ddcd0:	48 8b bd a0 fd ff ff                            	mov    rdi,QWORD PTR [rbp-0x260]
  7ddcd7:	48 8d 85 30 fe ff ff                            	lea    rax,[rbp-0x1d0]
  7ddcde:	be 0a 97 00 00                                  	mov    esi,0x970a
  7ddce3:	44 89 ea                                        	mov    edx,r13d
  7ddce6:	b9 ff ff ff ff                                  	mov    ecx,0xffffffff
  7ddceb:	41 b8 ff ff ff ff                               	mov    r8d,0xffffffff
  7ddcf1:	50                                              	push   rax
  7ddcf2:	41 ff 36                                        	push   QWORD PTR [r14]
  7ddcf5:	6a 00                                           	push   0x0
  7ddcf7:	e8 74 1c 42 00                                  	call   0xbff970
  7ddcfc:	48 83 c4 20                                     	add    rsp,0x20
  7ddd00:	e8 cb 9b 32 00                                  	call   0xb078d0
  7ddd05:	85 c0                                           	test   eax,eax
  7ddd07:	74 79                                           	je     0x7ddd82
  7ddd09:	83 3d f0 22 4d 02 00                            	cmp    DWORD PTR [rip+0x24d22f0],0x0        # 0x2cb0000
  7ddd10:	74 70                                           	je     0x7ddd82
  7ddd12:	4c 89 fb                                        	mov    rbx,r15
  7ddd15:	4c 8b 3d 04 8c 41 03                            	mov    r15,QWORD PTR [rip+0x3418c04]        # 0x3bf6920
  7ddd1c:	48 8d 05 c5 b6 a8 ff                            	lea    rax,[rip+0xffffffffffa8b6c5]        # 0x2693e8
  7ddd23:	4c 29 f8                                        	sub    rax,r15
  7ddd26:	48 c1 c8 03                                     	ror    rax,0x3
  7ddd2a:	48 83 f8 01                                     	cmp    rax,0x1
  7ddd2e:	0f 87 7a 13 00 00                               	ja     0x7df0ae
  7ddd34:	44 89 e8                                        	mov    eax,r13d
  7ddd37:	49 ba 00 00 ff ff ff ff 00 00                   	movabs r10,0xffffffff0000
  7ddd41:	48 8b 8d 30 fe ff ff                            	mov    rcx,QWORD PTR [rbp-0x1d0]
  7ddd48:	4c 8b 85 38 fe ff ff                            	mov    r8,QWORD PTR [rbp-0x1c8]
  7ddd4f:	4c 8b 8d 40 fe ff ff                            	mov    r9,QWORD PTR [rbp-0x1c0]
  7ddd56:	ba 0a 97 00 00                                  	mov    edx,0x970a
  7ddd5b:	bf 08 00 00 00                                  	mov    edi,0x8
  7ddd60:	be 02 00 00 00                                  	mov    esi,0x2
  7ddd65:	49 09 c2                                        	or     r10,rax
  7ddd68:	41 8b 46 08                                     	mov    eax,DWORD PTR [r14+0x8]
  7ddd6c:	41 ff 36                                        	push   QWORD PTR [r14]
  7ddd6f:	50                                              	push   rax
  7ddd70:	41 52                                           	push   r10
  7ddd72:	ff b5 48 fe ff ff                               	push   QWORD PTR [rbp-0x1b8]
  7ddd78:	41 ff d7                                        	call   r15
  7ddd7b:	48 83 c4 20                                     	add    rsp,0x20
  7ddd7f:	49 89 df                                        	mov    r15,rbx
  7ddd82:	48 83 bd 70 fd ff ff 00                         	cmp    QWORD PTR [rbp-0x290],0x0
  7ddd8a:	48 8b bd a0 fd ff ff                            	mov    rdi,QWORD PTR [rbp-0x260]
  7ddd91:	0f 94 c0                                        	sete   al
  7ddd94:	48 83 bd 78 fd ff ff 00                         	cmp    QWORD PTR [rbp-0x288],0x0
  7ddd9c:	0f 94 c1                                        	sete   cl
  7ddd9f:	08 c1                                           	or     cl,al
  7ddda1:	80 f9 01                                        	cmp    cl,0x1
  7ddda4:	75 29                                           	jne    0x7dddcf
  7ddda6:	b8 20 03 02 a0                                  	mov    eax,0xa0020320
  7dddab:	bb 00 00 01 02                                  	mov    ebx,0x2010000
  7dddb0:	45 31 ff                                        	xor    r15d,r15d
  7dddb3:	48 89 85 00 fe ff ff                            	mov    QWORD PTR [rbp-0x200],rax
  7dddba:	48 c7 85 f8 fd ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x208],0x0
  7dddc5:	b8 16 00 00 00                                  	mov    eax,0x16
  7dddca:	e9 1d 10 00 00                                  	jmp    0x7dedec
  7dddcf:	48 83 bd 58 fd ff ff 00                         	cmp    QWORD PTR [rbp-0x2a8],0x0
  7dddd7:	74 66                                           	je     0x7dde3f
  7dddd9:	4d 85 ff                                        	test   r15,r15
  7ddddc:	0f 84 90 00 00 00                               	je     0x7dde72
  7ddde2:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  7dddeb:	48 8d 35 4b a1 bb 00                            	lea    rsi,[rip+0xbba14b]        # 0x1397f3d
  7dddf2:	31 d2                                           	xor    edx,edx
  7dddf4:	e8 e7 c5 43 00                                  	call   0xc1a3e0
  7dddf9:	48 8d 9d e4 fd ff ff                            	lea    rbx,[rbp-0x21c]
  7dde00:	ba 04 00 00 00                                  	mov    edx,0x4
  7dde05:	4c 89 ff                                        	mov    rdi,r15
  7dde08:	48 89 de                                        	mov    rsi,rbx
  7dde0b:	e8 70 b4 a7 ff                                  	call   0x259280
  7dde10:	85 c0                                           	test   eax,eax
  7dde12:	0f 84 d8 00 00 00                               	je     0x7ddef0
  7dde18:	b9 20 03 02 a0                                  	mov    ecx,0xa0020320
  7dde1d:	bb 03 00 01 02                                  	mov    ebx,0x2010003
  7dde22:	48 89 8d 00 fe ff ff                            	mov    QWORD PTR [rbp-0x200],rcx
  7dde29:	c7 85 f0 fd ff ff 03 00 01 02                   	mov    DWORD PTR [rbp-0x210],0x2010003
  7dde33:	4c 89 bd f8 fd ff ff                            	mov    QWORD PTR [rbp-0x208],r15
  7dde3a:	e9 a6 0f 00 00                                  	jmp    0x7dede5
  7dde3f:	b8 20 03 02 a0                                  	mov    eax,0xa0020320
  7dde44:	bb 01 00 01 02                                  	mov    ebx,0x2010001
  7dde49:	45 31 ff                                        	xor    r15d,r15d
  7dde4c:	48 89 85 00 fe ff ff                            	mov    QWORD PTR [rbp-0x200],rax
  7dde53:	c7 85 f0 fd ff ff 01 00 01 02                   	mov    DWORD PTR [rbp-0x210],0x2010001
  7dde5d:	48 c7 85 f8 fd ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x208],0x0
  7dde68:	b8 0c 00 00 00                                  	mov    eax,0xc
  7dde6d:	e9 7a 0f 00 00                                  	jmp    0x7dedec
  7dde72:	48 c7 85 48 fd ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x2b8],0x0
  7dde7d:	48 8d bd c0 fd ff ff                            	lea    rdi,[rbp-0x240]
  7dde84:	be 20 00 00 00                                  	mov    esi,0x20
  7dde89:	e8 62 b1 a7 ff                                  	call   0x258ff0
  7dde8e:	48 8d 95 b8 fd ff ff                            	lea    rdx,[rbp-0x248]
  7dde95:	44 89 ef                                        	mov    edi,r13d
  7dde98:	be 01 80 00 00                                  	mov    esi,0x8001
  7dde9d:	b9 ff ff ff 03                                  	mov    ecx,0x3ffffff
  7ddea2:	c7 85 c0 fd ff ff ff 0f 00 00                   	mov    DWORD PTR [rbp-0x240],0xfff
  7ddeac:	44 89 ad c4 fd ff ff                            	mov    DWORD PTR [rbp-0x23c],r13d
  7ddeb3:	48 c7 85 c8 fd ff ff ff ff ff ff                	mov    QWORD PTR [rbp-0x238],0xffffffffffffffff
  7ddebe:	e8 4d 0d e3 ff                                  	call   0x60ec10
  7ddec3:	85 c0                                           	test   eax,eax
  7ddec5:	74 66                                           	je     0x7ddf2d
  7ddec7:	89 c2                                           	mov    edx,eax
  7ddec9:	b8 05 00 01 02                                  	mov    eax,0x2010005
  7ddece:	b9 20 03 02 a0                                  	mov    ecx,0xa0020320
  7dded3:	48 89 8d 00 fe ff ff                            	mov    QWORD PTR [rbp-0x200],rcx
  7ddeda:	89 85 f0 fd ff ff                               	mov    DWORD PTR [rbp-0x210],eax
  7ddee0:	48 c7 85 f8 fd ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x208],0x0
  7ddeeb:	e9 7f 0e 00 00                                  	jmp    0x7ded6f
  7ddef0:	8b 85 e4 fd ff ff                               	mov    eax,DWORD PTR [rbp-0x21c]
  7ddef6:	48 89 9d 48 fd ff ff                            	mov    QWORD PTR [rbp-0x2b8],rbx
  7ddefd:	48 85 c0                                        	test   rax,rax
  7ddf00:	0f 84 77 ff ff ff                               	je     0x7dde7d
  7ddf06:	b9 20 03 02 a0                                  	mov    ecx,0xa0020320
  7ddf0b:	ba 16 00 00 00                                  	mov    edx,0x16
  7ddf10:	48 89 8d 00 fe ff ff                            	mov    QWORD PTR [rbp-0x200],rcx
  7ddf17:	c7 85 f0 fd ff ff 04 00 01 02                   	mov    DWORD PTR [rbp-0x210],0x2010004
  7ddf21:	48 89 85 f8 fd ff ff                            	mov    QWORD PTR [rbp-0x208],rax
  7ddf28:	e9 47 0e 00 00                                  	jmp    0x7ded74
  7ddf2d:	48 8b 8d a0 fd ff ff                            	mov    rcx,QWORD PTR [rbp-0x260]
  7ddf34:	48 8b b5 70 fd ff ff                            	mov    rsi,QWORD PTR [rbp-0x290]
  7ddf3b:	44 89 e8                                        	mov    eax,r13d
  7ddf3e:	41 0f b7 d5                                     	movzx  edx,r13w
  7ddf42:	44 89 ad b4 fd ff ff                            	mov    DWORD PTR [rbp-0x24c],r13d
  7ddf49:	4c 89 bd a8 fd ff ff                            	mov    QWORD PTR [rbp-0x258],r15
  7ddf50:	4c 89 a5 60 fd ff ff                            	mov    QWORD PTR [rbp-0x2a0],r12
  7ddf57:	0d 00 00 ff ff                                  	or     eax,0xffff0000
  7ddf5c:	48 89 85 40 fd ff ff                            	mov    QWORD PTR [rbp-0x2c0],rax
  7ddf63:	48 8d 81 94 02 00 00                            	lea    rax,[rcx+0x294]
  7ddf6a:	48 b9 00 00 00 00 ff ff 00 00                   	movabs rcx,0xffff00000000
  7ddf74:	48 89 85 20 fd ff ff                            	mov    QWORD PTR [rbp-0x2e0],rax
  7ddf7b:	48 8d 86 50 01 00 00                            	lea    rax,[rsi+0x150]
  7ddf82:	48 09 ca                                        	or     rdx,rcx
  7ddf85:	48 89 85 38 fd ff ff                            	mov    QWORD PTR [rbp-0x2c8],rax
  7ddf8c:	48 89 95 28 fd ff ff                            	mov    QWORD PTR [rbp-0x2d8],rdx
  7ddf93:	66 66 66 66 2e 0f 1f 84 00 00 00 00 00          	data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  7ddfa0:	4c 8b b5 b8 fd ff ff                            	mov    r14,QWORD PTR [rbp-0x248]
  7ddfa7:	31 f6                                           	xor    esi,esi
  7ddfa9:	31 d2                                           	xor    edx,edx
  7ddfab:	31 c9                                           	xor    ecx,ecx
  7ddfad:	49 8d 5e 28                                     	lea    rbx,[r14+0x28]
  7ddfb1:	48 89 df                                        	mov    rdi,rbx
  7ddfb4:	e8 67 db 46 00                                  	call   0xc4bb20
  7ddfb9:	49 8b 56 60                                     	mov    rdx,QWORD PTR [r14+0x60]
  7ddfbd:	4c 89 f0                                        	mov    rax,r14
  7ddfc0:	48 85 d2                                        	test   rdx,rdx
  7ddfc3:	0f 84 14 06 00 00                               	je     0x7de5dd
  7ddfc9:	8b 8d f0 fd ff ff                               	mov    ecx,DWORD PTR [rbp-0x210]
  7ddfcf:	4c 8b b5 00 fe ff ff                            	mov    r14,QWORD PTR [rbp-0x200]
  7ddfd6:	4c 8b ad f8 fd ff ff                            	mov    r13,QWORD PTR [rbp-0x208]
  7ddfdd:	4c 8d bd 80 fe ff ff                            	lea    r15,[rbp-0x180]
  7ddfe4:	49 89 d4                                        	mov    r12,rdx
  7ddfe7:	48 89 85 30 fd ff ff                            	mov    QWORD PTR [rbp-0x2d0],rax
  7ddfee:	48 c7 85 98 fd ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x268],0x0
  7ddff9:	48 89 9d 18 fd ff ff                            	mov    QWORD PTR [rbp-0x2e8],rbx
  7de000:	89 8d 84 fd ff ff                               	mov    DWORD PTR [rbp-0x27c],ecx
  7de006:	e9 d6 00 00 00                                  	jmp    0x7de0e1
  7de00b:	8b 43 08                                        	mov    eax,DWORD PTR [rbx+0x8]
  7de00e:	48 8b 8d 30 fe ff ff                            	mov    rcx,QWORD PTR [rbp-0x1d0]
  7de015:	4c 8b 85 38 fe ff ff                            	mov    r8,QWORD PTR [rbp-0x1c8]
  7de01c:	4c 8b 8d 40 fe ff ff                            	mov    r9,QWORD PTR [rbp-0x1c0]
  7de023:	45 8b 54 24 48                                  	mov    r10d,DWORD PTR [r12+0x48]
  7de028:	bf 08 00 00 00                                  	mov    edi,0x8
  7de02d:	be 02 00 00 00                                  	mov    esi,0x2
  7de032:	4c 89 ea                                        	mov    rdx,r13
  7de035:	c1 e0 10                                        	shl    eax,0x10
  7de038:	48 0b 85 28 fd ff ff                            	or     rax,QWORD PTR [rbp-0x2d8]
  7de03f:	41 56                                           	push   r14
  7de041:	41 52                                           	push   r10
  7de043:	50                                              	push   rax
  7de044:	ff b5 48 fe ff ff                               	push   QWORD PTR [rbp-0x1b8]
  7de04a:	41 ff d3                                        	call   r11
  7de04d:	48 83 c4 20                                     	add    rsp,0x20
  7de051:	4c 8b b5 a0 fd ff ff                            	mov    r14,QWORD PTR [rbp-0x260]
  7de058:	83 8d 84 fd ff ff 08                            	or     DWORD PTR [rbp-0x27c],0x8
  7de05f:	41 8b 44 24 4c                                  	mov    eax,DWORD PTR [r12+0x4c]
  7de064:	48 8d 3d cd b9 aa 00                            	lea    rdi,[rip+0xaab9cd]        # 0x1289a38
  7de06b:	be 0a 03 00 00                                  	mov    esi,0x30a
  7de070:	45 8b ae 9c 00 00 00                            	mov    r13d,DWORD PTR [r14+0x9c]
  7de077:	48 c1 e0 20                                     	shl    rax,0x20
  7de07b:	49 09 c5                                        	or     r13,rax
  7de07e:	31 c0                                           	xor    eax,eax
  7de080:	e8 8b f3 a7 ff                                  	call   0x25d410
  7de085:	41 8b b6 9c 00 00 00                            	mov    esi,DWORD PTR [r14+0x9c]
  7de08c:	8b 4b 08                                        	mov    ecx,DWORD PTR [rbx+0x8]
  7de08f:	4c 8b 43 18                                     	mov    r8,QWORD PTR [rbx+0x18]
  7de093:	45 8b 4c 24 48                                  	mov    r9d,DWORD PTR [r12+0x48]
  7de098:	48 8b 95 20 fd ff ff                            	mov    rdx,QWORD PTR [rbp-0x2e0]
  7de09f:	48 8d 3d 80 dd b0 00                            	lea    rdi,[rip+0xb0dd80]        # 0x12ebe26
  7de0a6:	31 c0                                           	xor    eax,eax
  7de0a8:	e8 63 f3 a7 ff                                  	call   0x25d410
  7de0ad:	b8 10 00 00 00                                  	mov    eax,0x10
  7de0b2:	41 be 20 03 02 a0                               	mov    r14d,0xa0020320
  7de0b8:	48 89 85 98 fd ff ff                            	mov    QWORD PTR [rbp-0x268],rax
  7de0bf:	90                                              	nop
  7de0c0:	4c 89 e7                                        	mov    rdi,r12
  7de0c3:	31 f6                                           	xor    esi,esi
  7de0c5:	31 d2                                           	xor    edx,edx
  7de0c7:	e8 e4 e3 46 00                                  	call   0xc4c4b0
  7de0cc:	4d 8b 64 24 28                                  	mov    r12,QWORD PTR [r12+0x28]
  7de0d1:	48 8b bd 18 fd ff ff                            	mov    rdi,QWORD PTR [rbp-0x2e8]
  7de0d8:	4d 85 e4                                        	test   r12,r12
  7de0db:	0f 84 af 04 00 00                               	je     0x7de590
  7de0e1:	4c 89 ff                                        	mov    rdi,r15
  7de0e4:	e8 c7 11 2f 00                                  	call   0xacf2b0
  7de0e9:	48 b8 cf f7 53 e3 a5 9b c4 20                   	movabs rax,0x20c49ba5e353f7cf
  7de0f3:	48 69 8d 80 fe ff ff 40 42 0f 00                	imul   rcx,QWORD PTR [rbp-0x180],0xf4240
  7de0fe:	4c 89 e7                                        	mov    rdi,r12
  7de101:	31 f6                                           	xor    esi,esi
  7de103:	48 f7 ad 88 fe ff ff                            	imul   QWORD PTR [rbp-0x178]
  7de10a:	48 89 d0                                        	mov    rax,rdx
  7de10d:	48 c1 fa 07                                     	sar    rdx,0x7
  7de111:	48 c1 e8 3f                                     	shr    rax,0x3f
  7de115:	48 01 c2                                        	add    rdx,rax
  7de118:	48 01 ca                                        	add    rdx,rcx
  7de11b:	31 c9                                           	xor    ecx,ecx
  7de11d:	48 89 95 90 fd ff ff                            	mov    QWORD PTR [rbp-0x270],rdx
  7de124:	31 d2                                           	xor    edx,edx
  7de126:	e8 f5 d9 46 00                                  	call   0xc4bb20
  7de12b:	4d 8b 84 24 60 04 00 00                         	mov    r8,QWORD PTR [r12+0x460]
  7de133:	4d 85 c0                                        	test   r8,r8
  7de136:	0f 84 b4 01 00 00                               	je     0x7de2f0
  7de13c:	41 83 78 04 00                                  	cmp    DWORD PTR [r8+0x4],0x0
  7de141:	48 8b bd a0 fd ff ff                            	mov    rdi,QWORD PTR [rbp-0x260]
  7de148:	0f 85 5c 03 00 00                               	jne    0x7de4aa
  7de14e:	41 8b 54 24 58                                  	mov    edx,DWORD PTR [r12+0x58]
  7de153:	4c 89 a5 68 fd ff ff                            	mov    QWORD PTR [rbp-0x298],r12
  7de15a:	4c 89 85 88 fd ff ff                            	mov    QWORD PTR [rbp-0x278],r8
  7de161:	85 d2                                           	test   edx,edx
  7de163:	0f 84 93 01 00 00                               	je     0x7de2fc
  7de169:	8b 8f 9c 00 00 00                               	mov    ecx,DWORD PTR [rdi+0x9c]
  7de16f:	4d 8d 8c 24 78 04 00 00                         	lea    r9,[r12+0x478]
  7de177:	31 c0                                           	xor    eax,eax
  7de179:	45 31 ff                                        	xor    r15d,r15d
  7de17c:	4c 89 8d 50 fd ff ff                            	mov    QWORD PTR [rbp-0x2b0],r9
  7de183:	e9 bd 00 00 00                                  	jmp    0x7de245
  7de188:	0f 1f 84 00 00 00 00 00                         	nop    DWORD PTR [rax+rax*1+0x0]
  7de190:	48 8b 85 88 fd ff ff                            	mov    rax,QWORD PTR [rbp-0x278]
  7de197:	48 ba 00 00 00 00 ff ff 00 00                   	movabs rdx,0xffff00000000
  7de1a1:	45 8b 54 24 10                                  	mov    r10d,DWORD PTR [r12+0x10]
  7de1a6:	48 8b 8d 30 fe ff ff                            	mov    rcx,QWORD PTR [rbp-0x1d0]
  7de1ad:	4c 8b 85 38 fe ff ff                            	mov    r8,QWORD PTR [rbp-0x1c8]
  7de1b4:	4c 8b 8d 40 fe ff ff                            	mov    r9,QWORD PTR [rbp-0x1c0]
  7de1bb:	48 c1 e3 20                                     	shl    rbx,0x20
  7de1bf:	bf 08 00 00 00                                  	mov    edi,0x8
  7de1c4:	be 02 00 00 00                                  	mov    esi,0x2
  7de1c9:	8b 40 08                                        	mov    eax,DWORD PTR [rax+0x8]
  7de1cc:	49 09 da                                        	or     r10,rbx
  7de1cf:	48 c1 e0 20                                     	shl    rax,0x20
  7de1d3:	48 21 d0                                        	and    rax,rdx
  7de1d6:	48 03 85 40 fd ff ff                            	add    rax,QWORD PTR [rbp-0x2c0]
  7de1dd:	ba 15 17 00 00                                  	mov    edx,0x1715
  7de1e2:	41 56                                           	push   r14
  7de1e4:	41 52                                           	push   r10
  7de1e6:	50                                              	push   rax
  7de1e7:	ff b5 48 fe ff ff                               	push   QWORD PTR [rbp-0x1b8]
  7de1ed:	41 ff d5                                        	call   r13
  7de1f0:	48 83 c4 20                                     	add    rsp,0x20
  7de1f4:	48 8b bd a0 fd ff ff                            	mov    rdi,QWORD PTR [rbp-0x260]
  7de1fb:	45 8b 6c 24 04                                  	mov    r13d,DWORD PTR [r12+0x4]
  7de200:	4c 8b a5 68 fd ff ff                            	mov    r12,QWORD PTR [rbp-0x298]
  7de207:	83 8d 84 fd ff ff 06                            	or     DWORD PTR [rbp-0x27c],0x6
  7de20e:	4c 8b 85 88 fd ff ff                            	mov    r8,QWORD PTR [rbp-0x278]
  7de215:	4c 8b 8d 50 fd ff ff                            	mov    r9,QWORD PTR [rbp-0x2b0]
  7de21c:	b8 10 00 00 00                                  	mov    eax,0x10
  7de221:	41 be 20 03 02 a0                               	mov    r14d,0xa0020320
  7de227:	8b 8f 9c 00 00 00                               	mov    ecx,DWORD PTR [rdi+0x9c]
  7de22d:	41 8b 54 24 58                                  	mov    edx,DWORD PTR [r12+0x58]
  7de232:	49 c1 e5 20                                     	shl    r13,0x20
  7de236:	49 09 cd                                        	or     r13,rcx
  7de239:	41 ff c7                                        	inc    r15d
  7de23c:	41 39 d7                                        	cmp    r15d,edx
  7de23f:	0f 83 b9 00 00 00                               	jae    0x7de2fe
  7de245:	49 63 df                                        	movsxd rbx,r15d
  7de248:	48 8d 34 5b                                     	lea    rsi,[rbx+rbx*2]
  7de24c:	41 39 4c f1 04                                  	cmp    DWORD PTR [r9+rsi*8+0x4],ecx
  7de251:	75 e6                                           	jne    0x7de239
  7de253:	4d 8d 24 f1                                     	lea    r12,[r9+rsi*8]
  7de257:	4c 8b b5 90 fd ff ff                            	mov    r14,QWORD PTR [rbp-0x270]
  7de25e:	45 8b 40 08                                     	mov    r8d,DWORD PTR [r8+0x8]
  7de262:	4d 2b 74 24 08                                  	sub    r14,QWORD PTR [r12+0x8]
  7de267:	45 8b 4c 24 10                                  	mov    r9d,DWORD PTR [r12+0x10]
  7de26c:	48 83 ec 08                                     	sub    rsp,0x8
  7de270:	8b 95 b4 fd ff ff                               	mov    edx,DWORD PTR [rbp-0x24c]
  7de276:	48 8d 85 30 fe ff ff                            	lea    rax,[rbp-0x1d0]
  7de27d:	be 15 17 00 00                                  	mov    esi,0x1715
  7de282:	b9 ff ff ff ff                                  	mov    ecx,0xffffffff
  7de287:	50                                              	push   rax
  7de288:	41 56                                           	push   r14
  7de28a:	41 57                                           	push   r15
  7de28c:	e8 df 16 42 00                                  	call   0xbff970
  7de291:	48 83 c4 20                                     	add    rsp,0x20
  7de295:	e8 36 96 32 00                                  	call   0xb078d0
  7de29a:	85 c0                                           	test   eax,eax
  7de29c:	0f 84 52 ff ff ff                               	je     0x7de1f4
  7de2a2:	83 3d 57 1d 4d 02 00                            	cmp    DWORD PTR [rip+0x24d1d57],0x0        # 0x2cb0000
  7de2a9:	0f 84 45 ff ff ff                               	je     0x7de1f4
  7de2af:	4c 8b 2d 6a 86 41 03                            	mov    r13,QWORD PTR [rip+0x341866a]        # 0x3bf6920
  7de2b6:	48 8d 05 2b b1 a8 ff                            	lea    rax,[rip+0xffffffffffa8b12b]        # 0x2693e8
  7de2bd:	4c 29 e8                                        	sub    rax,r13
  7de2c0:	48 c1 c8 03                                     	ror    rax,0x3
  7de2c4:	48 83 f8 01                                     	cmp    rax,0x1
  7de2c8:	0f 86 c2 fe ff ff                               	jbe    0x7de190
  7de2ce:	48 8d 3d db f8 d5 01                            	lea    rdi,[rip+0x1d5f8db]        # 0x253dbb0
  7de2d5:	4c 89 ee                                        	mov    rsi,r13
  7de2d8:	e8 e3 15 c7 ff                                  	call   0x44f8c0
  7de2dd:	e9 ae fe ff ff                                  	jmp    0x7de190
  7de2e2:	66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00       	data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  7de2f0:	48 8b bd a0 fd ff ff                            	mov    rdi,QWORD PTR [rbp-0x260]
  7de2f7:	e9 ae 01 00 00                                  	jmp    0x7de4aa
  7de2fc:	31 c0                                           	xor    eax,eax
  7de2fe:	41 8b 54 24 70                                  	mov    edx,DWORD PTR [r12+0x70]
  7de303:	85 d2                                           	test   edx,edx
  7de305:	0f 84 85 01 00 00                               	je     0x7de490
  7de30b:	8b 8f 9c 00 00 00                               	mov    ecx,DWORD PTR [rdi+0x9c]
  7de311:	4d 8d 8c 24 f8 05 00 00                         	lea    r9,[r12+0x5f8]
  7de319:	45 31 ff                                        	xor    r15d,r15d
  7de31c:	4c 89 8d 50 fd ff ff                            	mov    QWORD PTR [rbp-0x2b0],r9
  7de323:	e9 bd 00 00 00                                  	jmp    0x7de3e5
  7de328:	0f 1f 84 00 00 00 00 00                         	nop    DWORD PTR [rax+rax*1+0x0]
  7de330:	48 8b 85 88 fd ff ff                            	mov    rax,QWORD PTR [rbp-0x278]
  7de337:	48 ba 00 00 00 00 ff ff 00 00                   	movabs rdx,0xffff00000000
  7de341:	45 8b 54 24 10                                  	mov    r10d,DWORD PTR [r12+0x10]
  7de346:	48 8b 8d 30 fe ff ff                            	mov    rcx,QWORD PTR [rbp-0x1d0]
  7de34d:	4c 8b 85 38 fe ff ff                            	mov    r8,QWORD PTR [rbp-0x1c8]
  7de354:	4c 8b 8d 40 fe ff ff                            	mov    r9,QWORD PTR [rbp-0x1c0]
  7de35b:	48 c1 e3 20                                     	shl    rbx,0x20
  7de35f:	bf 08 00 00 00                                  	mov    edi,0x8
  7de364:	be 02 00 00 00                                  	mov    esi,0x2
  7de369:	8b 40 08                                        	mov    eax,DWORD PTR [rax+0x8]
  7de36c:	49 09 da                                        	or     r10,rbx
  7de36f:	48 c1 e0 20                                     	shl    rax,0x20
  7de373:	48 21 d0                                        	and    rax,rdx
  7de376:	48 03 85 40 fd ff ff                            	add    rax,QWORD PTR [rbp-0x2c0]
  7de37d:	ba 16 17 00 00                                  	mov    edx,0x1716
  7de382:	41 56                                           	push   r14
  7de384:	41 52                                           	push   r10
  7de386:	50                                              	push   rax
  7de387:	ff b5 48 fe ff ff                               	push   QWORD PTR [rbp-0x1b8]
  7de38d:	41 ff d5                                        	call   r13
  7de390:	48 83 c4 20                                     	add    rsp,0x20
  7de394:	48 8b bd a0 fd ff ff                            	mov    rdi,QWORD PTR [rbp-0x260]
  7de39b:	45 8b 6c 24 20                                  	mov    r13d,DWORD PTR [r12+0x20]
  7de3a0:	4c 8b a5 68 fd ff ff                            	mov    r12,QWORD PTR [rbp-0x298]
  7de3a7:	83 8d 84 fd ff ff 07                            	or     DWORD PTR [rbp-0x27c],0x7
  7de3ae:	4c 8b 85 88 fd ff ff                            	mov    r8,QWORD PTR [rbp-0x278]
  7de3b5:	4c 8b 8d 50 fd ff ff                            	mov    r9,QWORD PTR [rbp-0x2b0]
  7de3bc:	b8 10 00 00 00                                  	mov    eax,0x10
  7de3c1:	41 be 20 03 02 a0                               	mov    r14d,0xa0020320
  7de3c7:	8b 8f 9c 00 00 00                               	mov    ecx,DWORD PTR [rdi+0x9c]
  7de3cd:	41 8b 54 24 70                                  	mov    edx,DWORD PTR [r12+0x70]
  7de3d2:	49 c1 e5 20                                     	shl    r13,0x20
  7de3d6:	49 09 cd                                        	or     r13,rcx
  7de3d9:	41 ff c7                                        	inc    r15d
  7de3dc:	41 39 d7                                        	cmp    r15d,edx
  7de3df:	0f 83 ab 00 00 00                               	jae    0x7de490
  7de3e5:	49 63 df                                        	movsxd rbx,r15d
  7de3e8:	48 8d 34 9b                                     	lea    rsi,[rbx+rbx*4]
  7de3ec:	41 39 4c f1 20                                  	cmp    DWORD PTR [r9+rsi*8+0x20],ecx
  7de3f1:	75 e6                                           	jne    0x7de3d9
  7de3f3:	48 8d 04 5b                                     	lea    rax,[rbx+rbx*2]
  7de3f7:	4c 89 e1                                        	mov    rcx,r12
  7de3fa:	4d 8d 24 f1                                     	lea    r12,[r9+rsi*8]
  7de3fe:	4c 8b b5 90 fd ff ff                            	mov    r14,QWORD PTR [rbp-0x270]
  7de405:	45 8b 40 08                                     	mov    r8d,DWORD PTR [r8+0x8]
  7de409:	4c 2b b4 c1 80 04 00 00                         	sub    r14,QWORD PTR [rcx+rax*8+0x480]
  7de411:	45 8b 4c 24 10                                  	mov    r9d,DWORD PTR [r12+0x10]
  7de416:	48 83 ec 08                                     	sub    rsp,0x8
  7de41a:	8b 95 b4 fd ff ff                               	mov    edx,DWORD PTR [rbp-0x24c]
  7de420:	48 8d 85 30 fe ff ff                            	lea    rax,[rbp-0x1d0]
  7de427:	be 16 17 00 00                                  	mov    esi,0x1716
  7de42c:	b9 ff ff ff ff                                  	mov    ecx,0xffffffff
  7de431:	50                                              	push   rax
  7de432:	41 56                                           	push   r14
  7de434:	53                                              	push   rbx
  7de435:	e8 36 15 42 00                                  	call   0xbff970
  7de43a:	48 83 c4 20                                     	add    rsp,0x20
  7de43e:	e8 8d 94 32 00                                  	call   0xb078d0
  7de443:	85 c0                                           	test   eax,eax
  7de445:	0f 84 49 ff ff ff                               	je     0x7de394
  7de44b:	83 3d ae 1b 4d 02 00                            	cmp    DWORD PTR [rip+0x24d1bae],0x0        # 0x2cb0000
  7de452:	0f 84 3c ff ff ff                               	je     0x7de394
  7de458:	4c 8b 2d c1 84 41 03                            	mov    r13,QWORD PTR [rip+0x34184c1]        # 0x3bf6920
  7de45f:	48 8d 05 82 af a8 ff                            	lea    rax,[rip+0xffffffffffa8af82]        # 0x2693e8
  7de466:	4c 29 e8                                        	sub    rax,r13
  7de469:	48 c1 c8 03                                     	ror    rax,0x3
  7de46d:	48 83 f8 01                                     	cmp    rax,0x1
  7de471:	0f 86 b9 fe ff ff                               	jbe    0x7de330
  7de477:	48 8d 3d 52 f7 d5 01                            	lea    rdi,[rip+0x1d5f752]        # 0x253dbd0
  7de47e:	4c 89 ee                                        	mov    rsi,r13
  7de481:	e8 3a 14 c7 ff                                  	call   0x44f8c0
  7de486:	e9 a5 fe ff ff                                  	jmp    0x7de330
  7de48b:	0f 1f 44 00 00                                  	nop    DWORD PTR [rax+rax*1+0x0]
  7de490:	48 8b 8d 98 fd ff ff                            	mov    rcx,QWORD PTR [rbp-0x268]
  7de497:	85 c0                                           	test   eax,eax
  7de499:	4c 8d bd 80 fe ff ff                            	lea    r15,[rbp-0x180]
  7de4a0:	0f 45 c8                                        	cmovne ecx,eax
  7de4a3:	48 89 8d 98 fd ff ff                            	mov    QWORD PTR [rbp-0x268],rcx
  7de4aa:	49 8b 9c 24 98 01 00 00                         	mov    rbx,QWORD PTR [r12+0x198]
  7de4b2:	48 85 db                                        	test   rbx,rbx
  7de4b5:	0f 84 05 fc ff ff                               	je     0x7de0c0
  7de4bb:	83 7b 04 00                                     	cmp    DWORD PTR [rbx+0x4],0x0
  7de4bf:	0f 85 fb fb ff ff                               	jne    0x7de0c0
  7de4c5:	41 8b 44 24 4c                                  	mov    eax,DWORD PTR [r12+0x4c]
  7de4ca:	3b 87 9c 00 00 00                               	cmp    eax,DWORD PTR [rdi+0x9c]
  7de4d0:	0f 85 ea fb ff ff                               	jne    0x7de0c0
  7de4d6:	45 8b 4c 24 48                                  	mov    r9d,DWORD PTR [r12+0x48]
  7de4db:	4c 8b 95 90 fd ff ff                            	mov    r10,QWORD PTR [rbp-0x270]
  7de4e2:	4d 2b 54 24 50                                  	sub    r10,QWORD PTR [r12+0x50]
  7de4e7:	45 31 ed                                        	xor    r13d,r13d
  7de4ea:	8b 4b 08                                        	mov    ecx,DWORD PTR [rbx+0x8]
  7de4ed:	41 83 f9 01                                     	cmp    r9d,0x1
  7de4f1:	41 0f 95 c5                                     	setne  r13b
  7de4f5:	49 81 c5 13 17 00 00                            	add    r13,0x1713
  7de4fc:	48 83 ec 08                                     	sub    rsp,0x8
  7de500:	8b 95 b4 fd ff ff                               	mov    edx,DWORD PTR [rbp-0x24c]
  7de506:	48 8d 85 30 fe ff ff                            	lea    rax,[rbp-0x1d0]
  7de50d:	44 89 ee                                        	mov    esi,r13d
  7de510:	41 b8 ff ff ff ff                               	mov    r8d,0xffffffff
  7de516:	50                                              	push   rax
  7de517:	4d 89 d6                                        	mov    r14,r10
  7de51a:	41 52                                           	push   r10
  7de51c:	6a 00                                           	push   0x0
  7de51e:	e8 4d 14 42 00                                  	call   0xbff970
  7de523:	48 83 c4 20                                     	add    rsp,0x20
  7de527:	e8 a4 93 32 00                                  	call   0xb078d0
  7de52c:	85 c0                                           	test   eax,eax
  7de52e:	0f 84 1d fb ff ff                               	je     0x7de051
  7de534:	83 3d c5 1a 4d 02 00                            	cmp    DWORD PTR [rip+0x24d1ac5],0x0        # 0x2cb0000
  7de53b:	0f 84 10 fb ff ff                               	je     0x7de051
  7de541:	4c 8b 1d d8 83 41 03                            	mov    r11,QWORD PTR [rip+0x34183d8]        # 0x3bf6920
  7de548:	48 8d 05 99 ae a8 ff                            	lea    rax,[rip+0xffffffffffa8ae99]        # 0x2693e8
  7de54f:	4c 29 d8                                        	sub    rax,r11
  7de552:	48 c1 c8 03                                     	ror    rax,0x3
  7de556:	48 83 f8 01                                     	cmp    rax,0x1
  7de55a:	0f 86 ab fa ff ff                               	jbe    0x7de00b
  7de560:	48 8d 3d 89 f6 d5 01                            	lea    rdi,[rip+0x1d5f689]        # 0x253dbf0
  7de567:	4c 89 de                                        	mov    rsi,r11
  7de56a:	4c 89 9d 88 fd ff ff                            	mov    QWORD PTR [rbp-0x278],r11
  7de571:	e8 4a 13 c7 ff                                  	call   0x44f8c0
  7de576:	4c 8b 9d 88 fd ff ff                            	mov    r11,QWORD PTR [rbp-0x278]
  7de57d:	e9 89 fa ff ff                                  	jmp    0x7de00b
  7de582:	66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00       	data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  7de590:	8b 85 84 fd ff ff                               	mov    eax,DWORD PTR [rbp-0x27c]
  7de596:	48 8b 8d 30 fd ff ff                            	mov    rcx,QWORD PTR [rbp-0x2d0]
  7de59d:	4c 89 b5 00 fe ff ff                            	mov    QWORD PTR [rbp-0x200],r14
  7de5a4:	31 f6                                           	xor    esi,esi
  7de5a6:	31 d2                                           	xor    edx,edx
  7de5a8:	89 85 f0 fd ff ff                               	mov    DWORD PTR [rbp-0x210],eax
  7de5ae:	4c 89 ad f8 fd ff ff                            	mov    QWORD PTR [rbp-0x208],r13
  7de5b5:	4c 8b b9 98 00 00 00                            	mov    r15,QWORD PTR [rcx+0x98]
  7de5bc:	e8 ef de 46 00                                  	call   0xc4c4b0
  7de5c1:	83 bd 98 fd ff ff 00                            	cmp    DWORD PTR [rbp-0x268],0x0
  7de5c8:	44 8b ad b4 fd ff ff                            	mov    r13d,DWORD PTR [rbp-0x24c]
  7de5cf:	4c 8b a5 60 fd ff ff                            	mov    r12,QWORD PTR [rbp-0x2a0]
  7de5d6:	74 18                                           	je     0x7de5f0
  7de5d8:	e9 75 07 00 00                                  	jmp    0x7ded52
  7de5dd:	4c 8b b8 98 00 00 00                            	mov    r15,QWORD PTR [rax+0x98]
  7de5e4:	48 89 df                                        	mov    rdi,rbx
  7de5e7:	31 f6                                           	xor    esi,esi
  7de5e9:	31 d2                                           	xor    edx,edx
  7de5eb:	e8 c0 de 46 00                                  	call   0xc4c4b0
  7de5f0:	48 8b bd b8 fd ff ff                            	mov    rdi,QWORD PTR [rbp-0x248]
  7de5f7:	48 8b 8d 58 fd ff ff                            	mov    rcx,QWORD PTR [rbp-0x2a8]
  7de5fe:	ba 00 01 00 00                                  	mov    edx,0x100
  7de603:	48 8b 87 88 00 00 00                            	mov    rax,QWORD PTR [rdi+0x88]
  7de60a:	48 01 d0                                        	add    rax,rdx
  7de60d:	48 39 c1                                        	cmp    rcx,rax
  7de610:	0f 82 dd 06 00 00                               	jb     0x7decf3
  7de616:	48 8b 87 80 00 00 00                            	mov    rax,QWORD PTR [rdi+0x80]
  7de61d:	48 01 d0                                        	add    rax,rdx
  7de620:	48 39 c1                                        	cmp    rcx,rax
  7de623:	0f 82 ca 06 00 00                               	jb     0x7decf3
  7de629:	48 8b b5 48 fd ff ff                            	mov    rsi,QWORD PTR [rbp-0x2b8]
  7de630:	48 85 f6                                        	test   rsi,rsi
  7de633:	74 17                                           	je     0x7de64c
  7de635:	83 bd e4 fd ff ff 00                            	cmp    DWORD PTR [rbp-0x21c],0x0
  7de63c:	75 0e                                           	jne    0x7de64c
  7de63e:	48 8d b5 e8 fd ff ff                            	lea    rsi,[rbp-0x218]
  7de645:	e8 f6 93 38 00                                  	call   0xb67a40
  7de64a:	eb 0c                                           	jmp    0x7de658
  7de64c:	48 8d 95 e8 fd ff ff                            	lea    rdx,[rbp-0x218]
  7de653:	e8 98 8a 38 00                                  	call   0xb670f0
  7de658:	89 c2                                           	mov    edx,eax
  7de65a:	85 c0                                           	test   eax,eax
  7de65c:	0f 85 c1 06 00 00                               	jne    0x7ded23
  7de662:	44 89 ef                                        	mov    edi,r13d
  7de665:	be 01 80 00 00                                  	mov    esi,0x8001
  7de66a:	31 d2                                           	xor    edx,edx
  7de66c:	e8 5f 06 e3 ff                                  	call   0x60ecd0
  7de671:	83 f8 02                                        	cmp    eax,0x2
  7de674:	0f 83 5c 0a 00 00                               	jae    0x7df0d6
  7de67a:	4c 8b b5 e8 fd ff ff                            	mov    r14,QWORD PTR [rbp-0x218]
  7de681:	48 8b bd a0 fd ff ff                            	mov    rdi,QWORD PTR [rbp-0x260]
  7de688:	4c 8d 95 c0 fd ff ff                            	lea    r10,[rbp-0x240]
  7de68f:	41 8b 46 10                                     	mov    eax,DWORD PTR [r14+0x10]
  7de693:	83 f8 2f                                        	cmp    eax,0x2f
  7de696:	7e 50                                           	jle    0x7de6e8
  7de698:	83 f8 4f                                        	cmp    eax,0x4f
  7de69b:	7f 67                                           	jg     0x7de704
  7de69d:	83 f8 30                                        	cmp    eax,0x30
  7de6a0:	74 70                                           	je     0x7de712
  7de6a2:	83 f8 40                                        	cmp    eax,0x40
  7de6a5:	0f 85 58 0a 00 00                               	jne    0x7df103
  7de6ab:	41 8b 5e 18                                     	mov    ebx,DWORD PTR [r14+0x18]
  7de6af:	41 8b 46 1c                                     	mov    eax,DWORD PTR [r14+0x1c]
  7de6b3:	be 04 80 00 00                                  	mov    esi,0x8004
  7de6b8:	48 8d 95 18 fe ff ff                            	lea    rdx,[rbp-0x1e8]
  7de6bf:	b9 ff ff ff 07                                  	mov    ecx,0x7ffffff
  7de6c4:	89 df                                           	mov    edi,ebx
  7de6c6:	89 85 88 fd ff ff                               	mov    DWORD PTR [rbp-0x278],eax
  7de6cc:	e8 3f 05 e3 ff                                  	call   0x60ec10
  7de6d1:	85 c0                                           	test   eax,eax
  7de6d3:	0f 84 92 01 00 00                               	je     0x7de86b
  7de6d9:	4c 89 f7                                        	mov    rdi,r14
  7de6dc:	e8 bf 89 38 00                                  	call   0xb670a0
  7de6e1:	ba ff ff ff ff                                  	mov    edx,0xffffffff
  7de6e6:	eb 5a                                           	jmp    0x7de742
  7de6e8:	83 f8 01                                        	cmp    eax,0x1
  7de6eb:	0f 84 f0 00 00 00                               	je     0x7de7e1
  7de6f1:	83 f8 10                                        	cmp    eax,0x10
  7de6f4:	0f 84 aa 00 00 00                               	je     0x7de7a4
  7de6fa:	83 f8 20                                        	cmp    eax,0x20
  7de6fd:	74 13                                           	je     0x7de712
  7de6ff:	e9 ff 09 00 00                                  	jmp    0x7df103
  7de704:	83 f8 50                                        	cmp    eax,0x50
  7de707:	74 09                                           	je     0x7de712
  7de709:	83 f8 60                                        	cmp    eax,0x60
  7de70c:	0f 85 f1 09 00 00                               	jne    0x7df103
  7de712:	48 8b 95 70 fd ff ff                            	mov    rdx,QWORD PTR [rbp-0x290]
  7de719:	48 8b 8d 78 fd ff ff                            	mov    rcx,QWORD PTR [rbp-0x288]
  7de720:	48 8d 85 f0 fd ff ff                            	lea    rax,[rbp-0x210]
  7de727:	4c 89 f6                                        	mov    rsi,r14
  7de72a:	4d 89 f8                                        	mov    r8,r15
  7de72d:	4c 8d 8d 50 fe ff ff                            	lea    r9,[rbp-0x1b0]
  7de734:	50                                              	push   rax
  7de735:	41 52                                           	push   r10
  7de737:	e8 64 2d 00 00                                  	call   0x7e14a0
  7de73c:	48 83 c4 10                                     	add    rsp,0x10
  7de740:	89 c2                                           	mov    edx,eax
  7de742:	4c 8b bd a8 fd ff ff                            	mov    r15,QWORD PTR [rbp-0x258]
  7de749:	85 d2                                           	test   edx,edx
  7de74b:	0f 89 1e 06 00 00                               	jns    0x7ded6f
  7de751:	be 20 00 00 00                                  	mov    esi,0x20
  7de756:	48 8d bd c0 fd ff ff                            	lea    rdi,[rbp-0x240]
  7de75d:	e8 8e a8 a7 ff                                  	call   0x258ff0
  7de762:	44 89 ef                                        	mov    edi,r13d
  7de765:	be 01 80 00 00                                  	mov    esi,0x8001
  7de76a:	48 8d 95 b8 fd ff ff                            	lea    rdx,[rbp-0x248]
  7de771:	b9 ff ff ff 03                                  	mov    ecx,0x3ffffff
  7de776:	c7 85 c0 fd ff ff ff 0f 00 00                   	mov    DWORD PTR [rbp-0x240],0xfff
  7de780:	44 89 ad c4 fd ff ff                            	mov    DWORD PTR [rbp-0x23c],r13d
  7de787:	48 c7 85 c8 fd ff ff ff ff ff ff                	mov    QWORD PTR [rbp-0x238],0xffffffffffffffff
  7de792:	e8 79 04 e3 ff                                  	call   0x60ec10
  7de797:	85 c0                                           	test   eax,eax
  7de799:	0f 84 01 f8 ff ff                               	je     0x7ddfa0
  7de79f:	e9 9e 05 00 00                                  	jmp    0x7ded42
  7de7a4:	48 8b 95 70 fd ff ff                            	mov    rdx,QWORD PTR [rbp-0x290]
  7de7ab:	48 8b 8d 58 fd ff ff                            	mov    rcx,QWORD PTR [rbp-0x2a8]
  7de7b2:	4c 8b 85 78 fd ff ff                            	mov    r8,QWORD PTR [rbp-0x288]
  7de7b9:	48 8d 85 f0 fd ff ff                            	lea    rax,[rbp-0x210]
  7de7c0:	4c 89 f6                                        	mov    rsi,r14
  7de7c3:	45 89 e9                                        	mov    r9d,r13d
  7de7c6:	50                                              	push   rax
  7de7c7:	41 52                                           	push   r10
  7de7c9:	48 8d 85 50 fe ff ff                            	lea    rax,[rbp-0x1b0]
  7de7d0:	50                                              	push   rax
  7de7d1:	41 57                                           	push   r15
  7de7d3:	e8 a8 28 00 00                                  	call   0x7e1080
  7de7d8:	48 83 c4 20                                     	add    rsp,0x20
  7de7dc:	e9 5f ff ff ff                                  	jmp    0x7de740
  7de7e1:	48 b8 b0 00 00 00 ff ff ff ff                   	movabs rax,0xffffffff000000b0
  7de7eb:	48 8d 35 a5 0a b7 00                            	lea    rsi,[rip+0xb70aa5]        # 0x134f297
  7de7f2:	31 d2                                           	xor    edx,edx
  7de7f4:	48 89 85 58 fe ff ff                            	mov    QWORD PTR [rbp-0x1a8],rax
  7de7fb:	48 c7 85 50 fe ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x1b0],0x0
  7de806:	4c 89 bd 60 fe ff ff                            	mov    QWORD PTR [rbp-0x1a0],r15
  7de80d:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  7de816:	e8 c5 bb 43 00                                  	call   0xc1a3e0
  7de81b:	48 8b 9d 78 fd ff ff                            	mov    rbx,QWORD PTR [rbp-0x288]
  7de822:	ba 18 00 00 00                                  	mov    edx,0x18
  7de827:	48 8d bd 50 fe ff ff                            	lea    rdi,[rbp-0x1b0]
  7de82e:	48 89 de                                        	mov    rsi,rbx
  7de831:	e8 9a a9 a7 ff                                  	call   0x2591d0
  7de836:	85 c0                                           	test   eax,eax
  7de838:	0f 84 2f 08 00 00                               	je     0x7df06d
  7de83e:	4c 89 f7                                        	mov    rdi,r14
  7de841:	49 89 c7                                        	mov    r15,rax
  7de844:	e8 57 88 38 00                                  	call   0xb670a0
  7de849:	b8 20 03 02 a0                                  	mov    eax,0xa0020320
  7de84e:	4c 89 fa                                        	mov    rdx,r15
  7de851:	48 89 85 00 fe ff ff                            	mov    QWORD PTR [rbp-0x200],rax
  7de858:	80 8d f0 fd ff ff 12                            	or     BYTE PTR [rbp-0x210],0x12
  7de85f:	48 89 9d f8 fd ff ff                            	mov    QWORD PTR [rbp-0x208],rbx
  7de866:	e9 d7 fe ff ff                                  	jmp    0x7de742
  7de86b:	be 50 01 00 00                                  	mov    esi,0x150
  7de870:	48 8d bd 80 fe ff ff                            	lea    rdi,[rbp-0x180]
  7de877:	48 c7 85 08 fe ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x1f8],0x0
  7de882:	89 9d 90 fd ff ff                               	mov    DWORD PTR [rbp-0x270],ebx
  7de888:	e8 63 a7 a7 ff                                  	call   0x258ff0
  7de88d:	48 8b 3d 14 f2 d5 01                            	mov    rdi,QWORD PTR [rip+0x1d5f214]        # 0x253daa8
  7de894:	31 f6                                           	xor    esi,esi
  7de896:	31 d2                                           	xor    edx,edx
  7de898:	31 c9                                           	xor    ecx,ecx
  7de89a:	e8 81 d2 46 00                                  	call   0xc4bb20
  7de89f:	8b 95 90 fd ff ff                               	mov    edx,DWORD PTR [rbp-0x270]
  7de8a5:	48 8b bd a0 fd ff ff                            	mov    rdi,QWORD PTR [rbp-0x260]
  7de8ac:	8b 8d 88 fd ff ff                               	mov    ecx,DWORD PTR [rbp-0x278]
  7de8b2:	4c 8b 85 70 fd ff ff                            	mov    r8,QWORD PTR [rbp-0x290]
  7de8b9:	48 8d 85 80 fe ff ff                            	lea    rax,[rbp-0x180]
  7de8c0:	44 89 ee                                        	mov    esi,r13d
  7de8c3:	4c 8d 8d 10 fe ff ff                            	lea    r9,[rbp-0x1f0]
  7de8ca:	89 d3                                           	mov    ebx,edx
  7de8cc:	50                                              	push   rax
  7de8cd:	48 8d 85 08 fe ff ff                            	lea    rax,[rbp-0x1f8]
  7de8d4:	50                                              	push   rax
  7de8d5:	e8 f6 33 00 00                                  	call   0x7e1cd0
  7de8da:	48 83 c4 10                                     	add    rsp,0x10
  7de8de:	85 c0                                           	test   eax,eax
  7de8e0:	0f 84 b0 00 00 00                               	je     0x7de996
  7de8e6:	48 8b 9d 08 fe ff ff                            	mov    rbx,QWORD PTR [rbp-0x1f8]
  7de8ed:	48 89 df                                        	mov    rdi,rbx
  7de8f0:	e8 0b 08 bc ff                                  	call   0x39f100
  7de8f5:	49 89 c5                                        	mov    r13,rax
  7de8f8:	49 83 c5 e8                                     	add    r13,0xffffffffffffffe8
  7de8fc:	4c 39 ad 58 fd ff ff                            	cmp    QWORD PTR [rbp-0x2a8],r13
  7de903:	0f 83 b0 00 00 00                               	jae    0x7de9b9
  7de909:	48 8b 85 10 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x1f0]
  7de910:	31 f6                                           	xor    esi,esi
  7de912:	31 d2                                           	xor    edx,edx
  7de914:	48 89 58 70                                     	mov    QWORD PTR [rax+0x70],rbx
  7de918:	48 c7 40 58 00 00 00 00                         	mov    QWORD PTR [rax+0x58],0x0
  7de920:	c7 40 4c ff ff ff ff                            	mov    DWORD PTR [rax+0x4c],0xffffffff
  7de927:	48 8b 3d 7a f1 d5 01                            	mov    rdi,QWORD PTR [rip+0x1d5f17a]        # 0x253daa8
  7de92e:	e8 7d db 46 00                                  	call   0xc4c4b0
  7de933:	8b bd 5c fe ff ff                               	mov    edi,DWORD PTR [rbp-0x1a4]
  7de939:	be 04 80 00 00                                  	mov    esi,0x8004
  7de93e:	31 d2                                           	xor    edx,edx
  7de940:	e8 8b 03 e3 ff                                  	call   0x60ecd0
  7de945:	8b bd b4 fd ff ff                               	mov    edi,DWORD PTR [rbp-0x24c]
  7de94b:	4c 89 f6                                        	mov    rsi,r14
  7de94e:	ba ff ff ff 03                                  	mov    edx,0x3ffffff
  7de953:	e8 58 92 38 00                                  	call   0xb67bb0
  7de958:	4c 8b bd a8 fd ff ff                            	mov    r15,QWORD PTR [rbp-0x258]
  7de95f:	85 c0                                           	test   eax,eax
  7de961:	74 08                                           	je     0x7de96b
  7de963:	4c 89 f7                                        	mov    rdi,r14
  7de966:	e8 35 87 38 00                                  	call   0xb670a0
  7de96b:	b8 20 03 02 a0                                  	mov    eax,0xa0020320
  7de970:	ba 0c 00 00 00                                  	mov    edx,0xc
  7de975:	48 89 85 00 fe ff ff                            	mov    QWORD PTR [rbp-0x200],rax
  7de97c:	80 8d f0 fd ff ff 13                            	or     BYTE PTR [rbp-0x210],0x13
  7de983:	4c 89 ad f8 fd ff ff                            	mov    QWORD PTR [rbp-0x208],r13
  7de98a:	44 8b ad b4 fd ff ff                            	mov    r13d,DWORD PTR [rbp-0x24c]
  7de991:	e9 b3 fd ff ff                                  	jmp    0x7de749
  7de996:	48 8b 3d 0b f1 d5 01                            	mov    rdi,QWORD PTR [rip+0x1d5f10b]        # 0x253daa8
  7de99d:	31 f6                                           	xor    esi,esi
  7de99f:	31 d2                                           	xor    edx,edx
  7de9a1:	e8 0a db 46 00                                  	call   0xc4c4b0
  7de9a6:	89 df                                           	mov    edi,ebx
  7de9a8:	be 04 80 00 00                                  	mov    esi,0x8004
  7de9ad:	31 d2                                           	xor    edx,edx
  7de9af:	e8 1c 03 e3 ff                                  	call   0x60ecd0
  7de9b4:	e9 20 fd ff ff                                  	jmp    0x7de6d9
  7de9b9:	48 8b 3d e8 f0 d5 01                            	mov    rdi,QWORD PTR [rip+0x1d5f0e8]        # 0x253daa8
  7de9c0:	31 f6                                           	xor    esi,esi
  7de9c2:	31 d2                                           	xor    edx,edx
  7de9c4:	e8 e7 da 46 00                                  	call   0xc4c4b0
  7de9c9:	48 89 df                                        	mov    rdi,rbx
  7de9cc:	48 89 9d 68 fd ff ff                            	mov    QWORD PTR [rbp-0x298],rbx
  7de9d3:	e8 18 07 bc ff                                  	call   0x39f0f0
  7de9d8:	4c 8d a5 50 fe ff ff                            	lea    r12,[rbp-0x1b0]
  7de9df:	b9 30 00 00 00                                  	mov    ecx,0x30
  7de9e4:	48 89 c6                                        	mov    rsi,rax
  7de9e7:	31 d2                                           	xor    edx,edx
  7de9e9:	4c 89 e7                                        	mov    rdi,r12
  7de9ec:	e8 1f 09 bc ff                                  	call   0x39f310
  7de9f1:	4c 89 bd 60 fe ff ff                            	mov    QWORD PTR [rbp-0x1a0],r15
  7de9f8:	4c 8d 3d 98 08 b7 00                            	lea    r15,[rip+0xb70898]        # 0x134f297
  7de9ff:	31 d2                                           	xor    edx,edx
  7dea01:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  7dea0a:	4c 89 fe                                        	mov    rsi,r15
  7dea0d:	e8 ce b9 43 00                                  	call   0xc1a3e0
  7dea12:	48 8b b5 78 fd ff ff                            	mov    rsi,QWORD PTR [rbp-0x288]
  7dea19:	ba 18 00 00 00                                  	mov    edx,0x18
  7dea1e:	4c 89 e7                                        	mov    rdi,r12
  7dea21:	e8 aa a7 a7 ff                                  	call   0x2591d0
  7dea26:	85 c0                                           	test   eax,eax
  7dea28:	74 10                                           	je     0x7dea3a
  7dea2a:	44 8b ad b4 fd ff ff                            	mov    r13d,DWORD PTR [rbp-0x24c]
  7dea31:	4c 8b bd a8 fd ff ff                            	mov    r15,QWORD PTR [rbp-0x258]
  7dea38:	eb 41                                           	jmp    0x7dea7b
  7dea3a:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  7dea43:	4c 89 fe                                        	mov    rsi,r15
  7dea46:	31 d2                                           	xor    edx,edx
  7dea48:	e8 93 b9 43 00                                  	call   0xc1a3e0
  7dea4d:	48 8b b5 70 fd ff ff                            	mov    rsi,QWORD PTR [rbp-0x290]
  7dea54:	ba 50 01 00 00                                  	mov    edx,0x150
  7dea59:	48 8d bd 80 fe ff ff                            	lea    rdi,[rbp-0x180]
  7dea60:	e8 6b a7 a7 ff                                  	call   0x2591d0
  7dea65:	44 8b ad b4 fd ff ff                            	mov    r13d,DWORD PTR [rbp-0x24c]
  7dea6c:	4c 8b bd a8 fd ff ff                            	mov    r15,QWORD PTR [rbp-0x258]
  7dea73:	85 c0                                           	test   eax,eax
  7dea75:	0f 84 09 01 00 00                               	je     0x7deb84
  7dea7b:	4c 8b a5 60 fd ff ff                            	mov    r12,QWORD PTR [rbp-0x2a0]
  7dea82:	48 89 85 98 fd ff ff                            	mov    QWORD PTR [rbp-0x268],rax
  7dea89:	48 8b 3d 18 f0 d5 01                            	mov    rdi,QWORD PTR [rip+0x1d5f018]        # 0x253daa8
  7dea90:	8b 9d 90 fd ff ff                               	mov    ebx,DWORD PTR [rbp-0x270]
  7dea96:	31 f6                                           	xor    esi,esi
  7dea98:	31 d2                                           	xor    edx,edx
  7dea9a:	31 c9                                           	xor    ecx,ecx
  7dea9c:	e8 7f d0 46 00                                  	call   0xc4bb20
  7deaa1:	48 8b 3d 00 f0 d5 01                            	mov    rdi,QWORD PTR [rip+0x1d5f000]        # 0x253daa8
  7deaa8:	48 8b 95 a0 fd ff ff                            	mov    rdx,QWORD PTR [rbp-0x260]
  7deaaf:	48 8b b5 68 fd ff ff                            	mov    rsi,QWORD PTR [rbp-0x298]
  7deab6:	44 8b 85 88 fd ff ff                            	mov    r8d,DWORD PTR [rbp-0x278]
  7deabd:	48 8b 47 38                                     	mov    rax,QWORD PTR [rdi+0x38]
  7deac1:	48 85 c0                                        	test   rax,rax
  7deac4:	75 54                                           	jne    0x7deb1a
  7deac6:	31 f6                                           	xor    esi,esi
  7deac8:	31 d2                                           	xor    edx,edx
  7deaca:	e8 e1 d9 46 00                                  	call   0xc4c4b0
  7deacf:	89 df                                           	mov    edi,ebx
  7dead1:	be 04 80 00 00                                  	mov    esi,0x8004
  7dead6:	31 d2                                           	xor    edx,edx
  7dead8:	e8 f3 01 e3 ff                                  	call   0x60ecd0
  7deadd:	4c 89 f7                                        	mov    rdi,r14
  7deae0:	e8 bb 85 38 00                                  	call   0xb670a0
  7deae5:	b8 20 03 02 a0                                  	mov    eax,0xa0020320
  7deaea:	48 8b 95 98 fd ff ff                            	mov    rdx,QWORD PTR [rbp-0x268]
  7deaf1:	48 89 85 00 fe ff ff                            	mov    QWORD PTR [rbp-0x200],rax
  7deaf8:	80 8d f0 fd ff ff 14                            	or     BYTE PTR [rbp-0x210],0x14
  7deaff:	48 8b 85 78 fd ff ff                            	mov    rax,QWORD PTR [rbp-0x288]
  7deb06:	48 89 85 f8 fd ff ff                            	mov    QWORD PTR [rbp-0x208],rax
  7deb0d:	e9 37 fc ff ff                                  	jmp    0x7de749
  7deb12:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  7deb15:	48 85 c0                                        	test   rax,rax
  7deb18:	74 ac                                           	je     0x7deac6
  7deb1a:	39 58 18                                        	cmp    DWORD PTR [rax+0x18],ebx
  7deb1d:	75 f3                                           	jne    0x7deb12
  7deb1f:	44 39 40 1c                                     	cmp    DWORD PTR [rax+0x1c],r8d
  7deb23:	75 ed                                           	jne    0x7deb12
  7deb25:	44 39 68 48                                     	cmp    DWORD PTR [rax+0x48],r13d
  7deb29:	75 e7                                           	jne    0x7deb12
  7deb2b:	8b 48 4c                                        	mov    ecx,DWORD PTR [rax+0x4c]
  7deb2e:	3b 8a 9c 00 00 00                               	cmp    ecx,DWORD PTR [rdx+0x9c]
  7deb34:	75 dc                                           	jne    0x7deb12
  7deb36:	48 89 70 70                                     	mov    QWORD PTR [rax+0x70],rsi
  7deb3a:	48 c7 40 58 00 00 00 00                         	mov    QWORD PTR [rax+0x58],0x0
  7deb42:	c7 40 4c ff ff ff ff                            	mov    DWORD PTR [rax+0x4c],0xffffffff
  7deb49:	31 f6                                           	xor    esi,esi
  7deb4b:	31 d2                                           	xor    edx,edx
  7deb4d:	48 8b 3d 54 ef d5 01                            	mov    rdi,QWORD PTR [rip+0x1d5ef54]        # 0x253daa8
  7deb54:	e8 57 d9 46 00                                  	call   0xc4c4b0
  7deb59:	89 df                                           	mov    edi,ebx
  7deb5b:	be 04 80 00 00                                  	mov    esi,0x8004
  7deb60:	31 d2                                           	xor    edx,edx
  7deb62:	e8 69 01 e3 ff                                  	call   0x60ecd0
  7deb67:	44 89 ef                                        	mov    edi,r13d
  7deb6a:	4c 89 f6                                        	mov    rsi,r14
  7deb6d:	ba ff ff ff 03                                  	mov    edx,0x3ffffff
  7deb72:	e8 39 90 38 00                                  	call   0xb67bb0
  7deb77:	85 c0                                           	test   eax,eax
  7deb79:	0f 85 5e ff ff ff                               	jne    0x7deadd
  7deb7f:	e9 61 ff ff ff                                  	jmp    0x7deae5
  7deb84:	48 8b bd 68 fd ff ff                            	mov    rdi,QWORD PTR [rbp-0x298]
  7deb8b:	4c 8b bd 50 fe ff ff                            	mov    r15,QWORD PTR [rbp-0x1b0]
  7deb92:	48 c7 c0 b0 fe ff ff                            	mov    rax,0xfffffffffffffeb0
  7deb99:	49 01 c7                                        	add    r15,rax
  7deb9c:	e8 4f 05 bc ff                                  	call   0x39f0f0
  7deba1:	48 8b bd 38 fd ff ff                            	mov    rdi,QWORD PTR [rbp-0x2c8]
  7deba8:	48 89 c6                                        	mov    rsi,rax
  7debab:	ba 30 00 00 00                                  	mov    edx,0x30
  7debb0:	4c 89 f9                                        	mov    rcx,r15
  7debb3:	e8 28 09 bc ff                                  	call   0x39f4e0
  7debb8:	4c 8b a5 60 fd ff ff                            	mov    r12,QWORD PTR [rbp-0x2a0]
  7debbf:	85 c0                                           	test   eax,eax
  7debc1:	74 0c                                           	je     0x7debcf
  7debc3:	4c 8b bd a8 fd ff ff                            	mov    r15,QWORD PTR [rbp-0x258]
  7debca:	e9 b3 fe ff ff                                  	jmp    0x7dea82
  7debcf:	48 8b 85 18 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x1e8]
  7debd6:	31 f6                                           	xor    esi,esi
  7debd8:	31 d2                                           	xor    edx,edx
  7debda:	31 c9                                           	xor    ecx,ecx
  7debdc:	48 8b 78 28                                     	mov    rdi,QWORD PTR [rax+0x28]
  7debe0:	e8 3b cf 46 00                                  	call   0xc4bb20
  7debe5:	48 8d bd 20 fe ff ff                            	lea    rdi,[rbp-0x1e0]
  7debec:	e8 bf 06 2f 00                                  	call   0xacf2b0
  7debf1:	48 b8 cf f7 53 e3 a5 9b c4 20                   	movabs rax,0x20c49ba5e353f7cf
  7debfb:	48 8b b5 18 fe ff ff                            	mov    rsi,QWORD PTR [rbp-0x1e8]
  7dec02:	48 f7 ad 28 fe ff ff                            	imul   QWORD PTR [rbp-0x1d8]
  7dec09:	48 69 85 20 fe ff ff 40 42 0f 00                	imul   rax,QWORD PTR [rbp-0x1e0],0xf4240
  7dec14:	48 89 d1                                        	mov    rcx,rdx
  7dec17:	48 c1 fa 07                                     	sar    rdx,0x7
  7dec1b:	48 c1 e9 3f                                     	shr    rcx,0x3f
  7dec1f:	48 01 ca                                        	add    rdx,rcx
  7dec22:	8b 8d 58 fe ff ff                               	mov    ecx,DWORD PTR [rbp-0x1a8]
  7dec28:	48 01 c2                                        	add    rdx,rax
  7dec2b:	48 8b 46 28                                     	mov    rax,QWORD PTR [rsi+0x28]
  7dec2f:	48 8b b5 a0 fd ff ff                            	mov    rsi,QWORD PTR [rbp-0x260]
  7dec36:	8b b6 9c 00 00 00                               	mov    esi,DWORD PTR [rsi+0x9c]
  7dec3c:	89 48 48                                        	mov    DWORD PTR [rax+0x48],ecx
  7dec3f:	89 70 4c                                        	mov    DWORD PTR [rax+0x4c],esi
  7dec42:	48 89 50 50                                     	mov    QWORD PTR [rax+0x50],rdx
  7dec46:	31 f6                                           	xor    esi,esi
  7dec48:	31 d2                                           	xor    edx,edx
  7dec4a:	48 8b 85 18 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x1e8]
  7dec51:	48 8b 78 28                                     	mov    rdi,QWORD PTR [rax+0x28]
  7dec55:	e8 56 d8 46 00                                  	call   0xc4c4b0
  7dec5a:	8b bd 5c fe ff ff                               	mov    edi,DWORD PTR [rbp-0x1a4]
  7dec60:	be 04 80 00 00                                  	mov    esi,0x8004
  7dec65:	31 d2                                           	xor    edx,edx
  7dec67:	e8 64 00 e3 ff                                  	call   0x60ecd0
  7dec6c:	48 8b 9d 68 fd ff ff                            	mov    rbx,QWORD PTR [rbp-0x298]
  7dec73:	48 89 df                                        	mov    rdi,rbx
  7dec76:	e8 75 04 bc ff                                  	call   0x39f0f0
  7dec7b:	48 89 df                                        	mov    rdi,rbx
  7dec7e:	48 89 c6                                        	mov    rsi,rax
  7dec81:	e8 3a 03 bc ff                                  	call   0x39efc0
  7dec86:	48 89 df                                        	mov    rdi,rbx
  7dec89:	e8 c2 00 bc ff                                  	call   0x39ed50
  7dec8e:	48 8b 3d 2b ee d5 01                            	mov    rdi,QWORD PTR [rip+0x1d5ee2b]        # 0x253dac0
  7dec95:	48 89 de                                        	mov    rsi,rbx
  7dec98:	31 d2                                           	xor    edx,edx
  7dec9a:	e8 21 d4 c5 ff                                  	call   0x43c0c0
  7dec9f:	4c 89 f7                                        	mov    rdi,r14
  7deca2:	e8 f9 83 38 00                                  	call   0xb670a0
  7deca7:	48 8b 85 18 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x1e8]
  7decae:	8b 8d 90 fd ff ff                               	mov    ecx,DWORD PTR [rbp-0x270]
  7decb4:	31 d2                                           	xor    edx,edx
  7decb6:	8b 40 10                                        	mov    eax,DWORD PTR [rax+0x10]
  7decb9:	c7 85 c0 fd ff ff 0b 17 00 00                   	mov    DWORD PTR [rbp-0x240],0x170b
  7decc3:	c7 85 c8 fd ff ff ff ff ff ff                   	mov    DWORD PTR [rbp-0x238],0xffffffff
  7deccd:	89 8d cc fd ff ff                               	mov    DWORD PTR [rbp-0x234],ecx
  7decd3:	89 85 d0 fd ff ff                               	mov    DWORD PTR [rbp-0x230],eax
  7decd9:	c7 85 d4 fd ff ff 00 00 00 00                   	mov    DWORD PTR [rbp-0x22c],0x0
  7dece3:	48 c7 85 d8 fd ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x228],0x0
  7decee:	e9 4f fa ff ff                                  	jmp    0x7de742
  7decf3:	b8 20 03 02 a0                                  	mov    eax,0xa0020320
  7decf8:	44 89 ef                                        	mov    edi,r13d
  7decfb:	be 01 80 00 00                                  	mov    esi,0x8001
  7ded00:	31 d2                                           	xor    edx,edx
  7ded02:	48 89 85 00 fe ff ff                            	mov    QWORD PTR [rbp-0x200],rax
  7ded09:	80 8d f0 fd ff ff 09                            	or     BYTE PTR [rbp-0x210],0x9
  7ded10:	48 89 8d f8 fd ff ff                            	mov    QWORD PTR [rbp-0x208],rcx
  7ded17:	e8 b4 ff e2 ff                                  	call   0x60ecd0
  7ded1c:	ba 0c 00 00 00                                  	mov    edx,0xc
  7ded21:	eb 45                                           	jmp    0x7ded68
  7ded23:	48 c7 85 00 fe ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x200],0x0
  7ded2e:	80 8d f0 fd ff ff 0a                            	or     BYTE PTR [rbp-0x210],0xa
  7ded35:	48 c7 85 f8 fd ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x208],0x0
  7ded40:	eb 26                                           	jmp    0x7ded68
  7ded42:	89 c2                                           	mov    edx,eax
  7ded44:	8b 85 f0 fd ff ff                               	mov    eax,DWORD PTR [rbp-0x210]
  7ded4a:	83 c8 05                                        	or     eax,0x5
  7ded4d:	e9 7c f1 ff ff                                  	jmp    0x7ddece
  7ded52:	44 89 ef                                        	mov    edi,r13d
  7ded55:	be 01 80 00 00                                  	mov    esi,0x8001
  7ded5a:	31 d2                                           	xor    edx,edx
  7ded5c:	e8 6f ff e2 ff                                  	call   0x60ecd0
  7ded61:	48 8b 95 98 fd ff ff                            	mov    rdx,QWORD PTR [rbp-0x268]
  7ded68:	4c 8b bd a8 fd ff ff                            	mov    r15,QWORD PTR [rbp-0x258]
  7ded6f:	4d 85 ff                                        	test   r15,r15
  7ded72:	74 59                                           	je     0x7dedcd
  7ded74:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  7ded7d:	48 8d 35 13 05 b7 00                            	lea    rsi,[rip+0xb70513]        # 0x134f297
  7ded84:	48 89 d3                                        	mov    rbx,rdx
  7ded87:	31 d2                                           	xor    edx,edx
  7ded89:	e8 52 b6 43 00                                  	call   0xc1a3e0
  7ded8e:	48 8d bd e4 fd ff ff                            	lea    rdi,[rbp-0x21c]
  7ded95:	ba 04 00 00 00                                  	mov    edx,0x4
  7ded9a:	4c 89 fe                                        	mov    rsi,r15
  7ded9d:	e8 2e a4 a7 ff                                  	call   0x2591d0
  7deda2:	48 89 da                                        	mov    rdx,rbx
  7deda5:	85 c0                                           	test   eax,eax
  7deda7:	74 24                                           	je     0x7dedcd
  7deda9:	b9 20 03 02 a0                                  	mov    ecx,0xa0020320
  7dedae:	48 89 8d 00 fe ff ff                            	mov    QWORD PTR [rbp-0x200],rcx
  7dedb5:	8b 9d f0 fd ff ff                               	mov    ebx,DWORD PTR [rbp-0x210]
  7dedbb:	83 cb 15                                        	or     ebx,0x15
  7dedbe:	89 9d f0 fd ff ff                               	mov    DWORD PTR [rbp-0x210],ebx
  7dedc4:	4c 89 bd f8 fd ff ff                            	mov    QWORD PTR [rbp-0x208],r15
  7dedcb:	eb 18                                           	jmp    0x7dede5
  7dedcd:	85 d2                                           	test   edx,edx
  7dedcf:	0f 84 91 01 00 00                               	je     0x7def66
  7dedd5:	8b 9d f0 fd ff ff                               	mov    ebx,DWORD PTR [rbp-0x210]
  7deddb:	4c 8b bd f8 fd ff ff                            	mov    r15,QWORD PTR [rbp-0x208]
  7dede2:	48 89 d0                                        	mov    rax,rdx
  7dede5:	48 8b bd a0 fd ff ff                            	mov    rdi,QWORD PTR [rbp-0x260]
  7dedec:	44 8b 85 c8 fd ff ff                            	mov    r8d,DWORD PTR [rbp-0x238]
  7dedf3:	8b 8d cc fd ff ff                               	mov    ecx,DWORD PTR [rbp-0x234]
  7dedf9:	49 89 c4                                        	mov    r12,rax
  7dedfc:	44 8d b0 00 00 02 80                            	lea    r14d,[rax-0x7ffe0000]
  7dee03:	48 83 ec 08                                     	sub    rsp,0x8
  7dee07:	48 8d 85 30 fe ff ff                            	lea    rax,[rbp-0x1d0]
  7dee0e:	be 12 17 00 00                                  	mov    esi,0x1712
  7dee13:	44 89 ea                                        	mov    edx,r13d
  7dee16:	45 89 f1                                        	mov    r9d,r14d
  7dee19:	50                                              	push   rax
  7dee1a:	41 57                                           	push   r15
  7dee1c:	53                                              	push   rbx
  7dee1d:	e8 4e 0b 42 00                                  	call   0xbff970
  7dee22:	48 83 c4 20                                     	add    rsp,0x20
  7dee26:	e8 a5 8a 32 00                                  	call   0xb078d0
  7dee2b:	85 c0                                           	test   eax,eax
  7dee2d:	0f 84 97 00 00 00                               	je     0x7deeca
  7dee33:	83 3d c6 11 4d 02 00                            	cmp    DWORD PTR [rip+0x24d11c6],0x0        # 0x2cb0000
  7dee3a:	0f 84 8a 00 00 00                               	je     0x7deeca
  7dee40:	4c 89 bd a8 fd ff ff                            	mov    QWORD PTR [rbp-0x258],r15
  7dee47:	4c 8b 3d d2 7a 41 03                            	mov    r15,QWORD PTR [rip+0x3417ad2]        # 0x3bf6920
  7dee4e:	48 8d 05 93 a5 a8 ff                            	lea    rax,[rip+0xffffffffffa8a593]        # 0x2693e8
  7dee55:	4c 29 f8                                        	sub    rax,r15
  7dee58:	48 c1 c8 03                                     	ror    rax,0x3
  7dee5c:	48 83 f8 01                                     	cmp    rax,0x1
  7dee60:	0f 87 5c 02 00 00                               	ja     0x7df0c2
  7dee66:	8b 85 c8 fd ff ff                               	mov    eax,DWORD PTR [rbp-0x238]
  7dee6c:	8b 95 cc fd ff ff                               	mov    edx,DWORD PTR [rbp-0x234]
  7dee72:	48 8b 8d 30 fe ff ff                            	mov    rcx,QWORD PTR [rbp-0x1d0]
  7dee79:	4c 8b 85 38 fe ff ff                            	mov    r8,QWORD PTR [rbp-0x1c8]
  7dee80:	4c 8b 8d 40 fe ff ff                            	mov    r9,QWORD PTR [rbp-0x1c0]
  7dee87:	45 0f b7 d5                                     	movzx  r10d,r13w
  7dee8b:	48 c1 e3 20                                     	shl    rbx,0x20
  7dee8f:	bf 08 00 00 00                                  	mov    edi,0x8
  7dee94:	be 02 00 00 00                                  	mov    esi,0x2
  7dee99:	0f b7 c0                                        	movzx  eax,ax
  7dee9c:	c1 e2 10                                        	shl    edx,0x10
  7dee9f:	48 c1 e0 20                                     	shl    rax,0x20
  7deea3:	49 09 c2                                        	or     r10,rax
  7deea6:	44 89 f0                                        	mov    eax,r14d
  7deea9:	49 09 d2                                        	or     r10,rdx
  7deeac:	48 09 d8                                        	or     rax,rbx
  7deeaf:	ba 12 17 00 00                                  	mov    edx,0x1712
  7deeb4:	ff b5 a8 fd ff ff                               	push   QWORD PTR [rbp-0x258]
  7deeba:	50                                              	push   rax
  7deebb:	41 52                                           	push   r10
  7deebd:	ff b5 48 fe ff ff                               	push   QWORD PTR [rbp-0x1b8]
  7deec3:	41 ff d7                                        	call   r15
  7deec6:	48 83 c4 20                                     	add    rsp,0x20
  7deeca:	4c 8d 3d 3f d4 13 03                            	lea    r15,[rip+0x313d43f]        # 0x391c310
  7deed1:	48 8b 9d 00 fe ff ff                            	mov    rbx,QWORD PTR [rbp-0x200]
  7deed8:	48 85 db                                        	test   rbx,rbx
  7deedb:	74 67                                           	je     0x7def44
  7deedd:	65 4c 8b 34 25 00 00 00 00                      	mov    r14,QWORD PTR gs:0x0
  7deee6:	49 8b 4e 08                                     	mov    rcx,QWORD PTR [r14+0x8]
  7deeea:	81 b9 d4 05 00 00 00 00 50 03                   	cmp    DWORD PTR [rcx+0x5d4],0x3500000
  7deef4:	72 4e                                           	jb     0x7def44
  7deef6:	48 8d 3d 3b ab aa 00                            	lea    rdi,[rip+0xaaab3b]        # 0x1289a38
  7deefd:	be c2 00 00 00                                  	mov    esi,0xc2
  7def02:	31 c0                                           	xor    eax,eax
  7def04:	e8 07 e5 a7 ff                                  	call   0x25d410
  7def09:	41 8b b6 9c 00 00 00                            	mov    esi,DWORD PTR [r14+0x9c]
  7def10:	44 8b 85 f0 fd ff ff                            	mov    r8d,DWORD PTR [rbp-0x210]
  7def17:	4c 8b 8d f8 fd ff ff                            	mov    r9,QWORD PTR [rbp-0x208]
  7def1e:	4c 89 f2                                        	mov    rdx,r14
  7def21:	48 8d 3d 7f d7 a8 00                            	lea    rdi,[rip+0xa8d77f]        # 0x126c6a7
  7def28:	48 89 d9                                        	mov    rcx,rbx
  7def2b:	31 c0                                           	xor    eax,eax
  7def2d:	48 81 c2 94 02 00 00                            	add    rdx,0x294
  7def34:	e8 d7 e4 a7 ff                                  	call   0x25d410
  7def39:	4c 89 f7                                        	mov    rdi,r14
  7def3c:	48 89 de                                        	mov    rsi,rbx
  7def3f:	e8 dc 0a 4c 00                                  	call   0xc9fa20
  7def44:	49 8b 0f                                        	mov    rcx,QWORD PTR [r15]
  7def47:	48 3b 4d d0                                     	cmp    rcx,QWORD PTR [rbp-0x30]
  7def4b:	0f 85 56 01 00 00                               	jne    0x7df0a7
  7def51:	44 89 e0                                        	mov    eax,r12d
  7def54:	48 81 c4 c8 02 00 00                            	add    rsp,0x2c8
  7def5b:	5b                                              	pop    rbx
  7def5c:	41 5c                                           	pop    r12
  7def5e:	41 5d                                           	pop    r13
  7def60:	41 5e                                           	pop    r14
  7def62:	41 5f                                           	pop    r15
  7def64:	5d                                              	pop    rbp
  7def65:	c3                                              	ret
  7def66:	8b 85 c0 fd ff ff                               	mov    eax,DWORD PTR [rbp-0x240]
  7def6c:	3d ff 0f 00 00                                  	cmp    eax,0xfff
  7def71:	0f 84 c0 01 00 00                               	je     0x7df137
  7def77:	44 8b 85 c8 fd ff ff                            	mov    r8d,DWORD PTR [rbp-0x238]
  7def7e:	8b 8d cc fd ff ff                               	mov    ecx,DWORD PTR [rbp-0x234]
  7def84:	44 8b 8d d0 fd ff ff                            	mov    r9d,DWORD PTR [rbp-0x230]
  7def8b:	44 8b 95 d4 fd ff ff                            	mov    r10d,DWORD PTR [rbp-0x22c]
  7def92:	48 83 ec 08                                     	sub    rsp,0x8
  7def96:	48 8b bd a0 fd ff ff                            	mov    rdi,QWORD PTR [rbp-0x260]
  7def9d:	0f b7 f0                                        	movzx  esi,ax
  7defa0:	48 8d 85 30 fe ff ff                            	lea    rax,[rbp-0x1d0]
  7defa7:	44 89 ea                                        	mov    edx,r13d
  7defaa:	50                                              	push   rax
  7defab:	ff b5 d8 fd ff ff                               	push   QWORD PTR [rbp-0x228]
  7defb1:	41 52                                           	push   r10
  7defb3:	e8 b8 09 42 00                                  	call   0xbff970
  7defb8:	48 83 c4 20                                     	add    rsp,0x20
  7defbc:	e8 0f 89 32 00                                  	call   0xb078d0
  7defc1:	4c 8d 3d 48 d3 13 03                            	lea    r15,[rip+0x313d348]        # 0x391c310
  7defc8:	85 c0                                           	test   eax,eax
  7defca:	0f 84 8d 00 00 00                               	je     0x7df05d
  7defd0:	83 3d 29 10 4d 02 00                            	cmp    DWORD PTR [rip+0x24d1029],0x0        # 0x2cb0000
  7defd7:	0f 84 80 00 00 00                               	je     0x7df05d
  7defdd:	4c 8b 35 3c 79 41 03                            	mov    r14,QWORD PTR [rip+0x341793c]        # 0x3bf6920
  7defe4:	48 8d 05 fd a3 a8 ff                            	lea    rax,[rip+0xffffffffffa8a3fd]        # 0x2693e8
  7defeb:	4c 29 f0                                        	sub    rax,r14
  7defee:	48 c1 c8 03                                     	ror    rax,0x3
  7deff2:	48 83 f8 01                                     	cmp    rax,0x1
  7deff6:	0f 87 67 01 00 00                               	ja     0x7df163
  7deffc:	8b 85 c8 fd ff ff                               	mov    eax,DWORD PTR [rbp-0x238]
  7df002:	8b b5 cc fd ff ff                               	mov    esi,DWORD PTR [rbp-0x234]
  7df008:	0f b7 95 c0 fd ff ff                            	movzx  edx,WORD PTR [rbp-0x240]
  7df00f:	48 8b 8d 30 fe ff ff                            	mov    rcx,QWORD PTR [rbp-0x1d0]
  7df016:	4c 8b 85 38 fe ff ff                            	mov    r8,QWORD PTR [rbp-0x1c8]
  7df01d:	4c 8b 8d 40 fe ff ff                            	mov    r9,QWORD PTR [rbp-0x1c0]
  7df024:	45 0f b7 d5                                     	movzx  r10d,r13w
  7df028:	bf 08 00 00 00                                  	mov    edi,0x8
  7df02d:	0f b7 c0                                        	movzx  eax,ax
  7df030:	c1 e6 10                                        	shl    esi,0x10
  7df033:	48 c1 e0 20                                     	shl    rax,0x20
  7df037:	49 09 c2                                        	or     r10,rax
  7df03a:	49 09 f2                                        	or     r10,rsi
  7df03d:	be 02 00 00 00                                  	mov    esi,0x2
  7df042:	ff b5 d8 fd ff ff                               	push   QWORD PTR [rbp-0x228]
  7df048:	ff b5 d0 fd ff ff                               	push   QWORD PTR [rbp-0x230]
  7df04e:	41 52                                           	push   r10
  7df050:	ff b5 48 fe ff ff                               	push   QWORD PTR [rbp-0x1b8]
  7df056:	41 ff d6                                        	call   r14
  7df059:	48 83 c4 20                                     	add    rsp,0x20
  7df05d:	41 c7 04 24 00 00 00 00                         	mov    DWORD PTR [r12],0x0
  7df065:	45 31 e4                                        	xor    r12d,r12d
  7df068:	e9 64 fe ff ff                                  	jmp    0x7deed1
  7df06d:	4c 89 f7                                        	mov    rdi,r14
  7df070:	c7 85 c0 fd ff ff 10 17 00 00                   	mov    DWORD PTR [rbp-0x240],0x1710
  7df07a:	48 c7 85 c8 fd ff ff ff ff ff ff                	mov    QWORD PTR [rbp-0x238],0xffffffffffffffff
  7df085:	48 c7 85 d0 fd ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x230],0x0
  7df090:	48 c7 85 d8 fd ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x228],0x0
  7df09b:	e8 00 80 38 00                                  	call   0xb670a0
  7df0a0:	31 d2                                           	xor    edx,edx
  7df0a2:	e9 c1 fc ff ff                                  	jmp    0x7ded68
  7df0a7:	e8 04 e6 f1 ff                                  	call   0x6fd6b0
  7df0ac:	0f 0b                                           	ud2
  7df0ae:	48 8d 3d 9b ea d5 01                            	lea    rdi,[rip+0x1d5ea9b]        # 0x253db50
  7df0b5:	4c 89 fe                                        	mov    rsi,r15
  7df0b8:	e8 03 08 c7 ff                                  	call   0x44f8c0
  7df0bd:	e9 72 ec ff ff                                  	jmp    0x7ddd34
  7df0c2:	48 8d 3d c7 ea d5 01                            	lea    rdi,[rip+0x1d5eac7]        # 0x253db90
  7df0c9:	4c 89 fe                                        	mov    rsi,r15
  7df0cc:	e8 ef 07 c7 ff                                  	call   0x44f8c0
  7df0d1:	e9 90 fd ff ff                                  	jmp    0x7dee66
  7df0d6:	89 c3                                           	mov    ebx,eax
  7df0d8:	e8 73 28 01 00                                  	call   0x7f1950
  7df0dd:	48 63 f3                                        	movsxd rsi,ebx
  7df0e0:	48 8d 3d ef ff ff ff                            	lea    rdi,[rip+0xffffffffffffffef]        # 0x7df0d6
  7df0e7:	e8 b4 27 01 00                                  	call   0x7f18a0
  7df0ec:	48 8d 35 b4 b8 b4 00                            	lea    rsi,[rip+0xb4b8b4]        # 0x132a9a7
  7df0f3:	bf 04 00 00 00                                  	mov    edi,0x4
  7df0f8:	89 da                                           	mov    edx,ebx
  7df0fa:	31 c0                                           	xor    eax,eax
  7df0fc:	e8 0f b9 4b 00                                  	call   0xc9aa10
  7df101:	0f 0b                                           	ud2
  7df103:	e8 48 28 01 00                                  	call   0x7f1950
  7df108:	48 8b 85 e8 fd ff ff                            	mov    rax,QWORD PTR [rbp-0x218]
  7df10f:	48 8d 3d ed ff ff ff                            	lea    rdi,[rip+0xffffffffffffffed]        # 0x7df103
  7df116:	48 63 70 10                                     	movsxd rsi,DWORD PTR [rax+0x10]
  7df11a:	e8 81 27 01 00                                  	call   0x7f18a0
  7df11f:	48 8b 85 e8 fd ff ff                            	mov    rax,QWORD PTR [rbp-0x218]
  7df126:	48 8d 35 eb ac b6 00                            	lea    rsi,[rip+0xb6aceb]        # 0x1349e18
  7df12d:	bf 08 00 00 00                                  	mov    edi,0x8
  7df132:	8b 50 10                                        	mov    edx,DWORD PTR [rax+0x10]
  7df135:	eb c3                                           	jmp    0x7df0fa
  7df137:	e8 14 28 01 00                                  	call   0x7f1950
  7df13c:	48 63 b5 58 fe ff ff                            	movsxd rsi,DWORD PTR [rbp-0x1a8]
  7df143:	48 8d 3d ed ff ff ff                            	lea    rdi,[rip+0xffffffffffffffed]        # 0x7df137
  7df14a:	e8 51 27 01 00                                  	call   0x7f18a0
  7df14f:	8b 95 58 fe ff ff                               	mov    edx,DWORD PTR [rbp-0x1a8]
  7df155:	48 8d 35 1e d8 ae 00                            	lea    rsi,[rip+0xaed81e]        # 0x12cc97a
  7df15c:	bf 0c 00 00 00                                  	mov    edi,0xc
  7df161:	eb 97                                           	jmp    0x7df0fa
  7df163:	48 8d 3d 06 ea d5 01                            	lea    rdi,[rip+0x1d5ea06]        # 0x253db70
  7df16a:	4c 89 f6                                        	mov    rsi,r14
  7df16d:	e8 4e 07 c7 ff                                  	call   0x44f8c0
  7df172:	e9 85 fe ff ff                                  	jmp    0x7deffc
  7df177:	90                                              	nop
  7df178:	90                                              	nop
  7df179:	90                                              	nop
  7df17a:	90                                              	nop
  7df17b:	90                                              	nop
  7df17c:	90                                              	nop
  7df17d:	90                                              	nop
  7df17e:	90                                              	nop
  7df17f:	90                                              	nop
  7df180:	55                                              	push   rbp
  7df181:	48 89 e5                                        	mov    rbp,rsp
  7df184:	41 57                                           	push   r15
  7df186:	41 56                                           	push   r14
  7df188:	41 55                                           	push   r13
  7df18a:	41 54                                           	push   r12
  7df18c:	53                                              	push   rbx
  7df18d:	48 83 ec 58                                     	sub    rsp,0x58
  7df191:	48 8d 05 78 d1 13 03                            	lea    rax,[rip+0x313d178]        # 0x391c310
  7df198:	49 89 cc                                        	mov    r12,rcx
  7df19b:	49 89 d5                                        	mov    r13,rdx
  7df19e:	48 89 fb                                        	mov    rbx,rdi
  7df1a1:	41 89 f6                                        	mov    r14d,esi
  7df1a4:	89 f7                                           	mov    edi,esi
  7df1a6:	48 8d 55 a8                                     	lea    rdx,[rbp-0x58]
  7df1aa:	be 02 80 00 00                                  	mov    esi,0x8002
  7df1af:	b9 ff ff ff 03                                  	mov    ecx,0x3ffffff
  7df1b4:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  7df1b7:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  7df1bb:	48 c7 45 a8 00 00 00 00                         	mov    QWORD PTR [rbp-0x58],0x0
  7df1c3:	c6 45 b0 00                                     	mov    BYTE PTR [rbp-0x50],0x0
  7df1c7:	c7 45 a4 ff ff ff ff                            	mov    DWORD PTR [rbp-0x5c],0xffffffff
  7df1ce:	e8 3d fa e2 ff                                  	call   0x60ec10
  7df1d3:	85 c0                                           	test   eax,eax
  7df1d5:	74 57                                           	je     0x7df22e
  7df1d7:	48 8d 3d 99 07 b5 00                            	lea    rdi,[rip+0xb50799]        # 0x132f977
  7df1de:	be 24 07 00 00                                  	mov    esi,0x724
  7df1e3:	41 89 c7                                        	mov    r15d,eax
  7df1e6:	31 c0                                           	xor    eax,eax
  7df1e8:	48 c7 45 90 00 00 00 00                         	mov    QWORD PTR [rbp-0x70],0x0
  7df1f0:	e8 1b e2 a7 ff                                  	call   0x25d410
  7df1f5:	8b b3 9c 00 00 00                               	mov    esi,DWORD PTR [rbx+0x9c]
  7df1fb:	48 8d 3d 94 bc b2 00                            	lea    rdi,[rip+0xb2bc94]        # 0x130ae96
  7df202:	44 89 f2                                        	mov    edx,r14d
  7df205:	44 89 f1                                        	mov    ecx,r14d
  7df208:	45 89 f8                                        	mov    r8d,r15d
  7df20b:	31 c0                                           	xor    eax,eax
  7df20d:	e8 fe e1 a7 ff                                  	call   0x25d410
  7df212:	b8 20 03 02 a0                                  	mov    eax,0xa0020320
  7df217:	41 bf 00 00 02 03                               	mov    r15d,0x3020000
  7df21d:	bb 02 00 00 00                                  	mov    ebx,0x2
  7df222:	45 31 e4                                        	xor    r12d,r12d
  7df225:	48 89 45 88                                     	mov    QWORD PTR [rbp-0x78],rax
  7df229:	e9 f2 00 00 00                                  	jmp    0x7df320
  7df22e:	48 8b 45 a8                                     	mov    rax,QWORD PTR [rbp-0x58]
  7df232:	48 8d 7d b0                                     	lea    rdi,[rbp-0x50]
  7df236:	ba 20 00 00 00                                  	mov    edx,0x20
  7df23b:	4c 89 65 90                                     	mov    QWORD PTR [rbp-0x70],r12
  7df23f:	48 8b 70 18                                     	mov    rsi,QWORD PTR [rax+0x18]
  7df243:	e8 28 89 17 00                                  	call   0x957b70
  7df248:	48 8b 45 a8                                     	mov    rax,QWORD PTR [rbp-0x58]
  7df24c:	31 db                                           	xor    ebx,ebx
  7df24e:	31 f6                                           	xor    esi,esi
  7df250:	31 d2                                           	xor    edx,edx
  7df252:	31 c9                                           	xor    ecx,ecx
  7df254:	48 8b 78 28                                     	mov    rdi,QWORD PTR [rax+0x28]
  7df258:	e8 c3 c8 46 00                                  	call   0xc4bb20
  7df25d:	48 8b 45 a8                                     	mov    rax,QWORD PTR [rbp-0x58]
  7df261:	48 8b 78 28                                     	mov    rdi,QWORD PTR [rax+0x28]
  7df265:	44 8b 7f 20                                     	mov    r15d,DWORD PTR [rdi+0x20]
  7df269:	41 f7 c7 00 00 02 00                            	test   r15d,0x20000
  7df270:	75 0f                                           	jne    0x7df281
  7df272:	b8 01 00 02 03                                  	mov    eax,0x3020001
  7df277:	bb 03 00 00 00                                  	mov    ebx,0x3
  7df27c:	4d 89 fc                                        	mov    r12,r15
  7df27f:	eb 11                                           	jmp    0x7df292
  7df281:	8b 87 94 01 00 00                               	mov    eax,DWORD PTR [rdi+0x194]
  7df287:	45 31 e4                                        	xor    r12d,r12d
  7df28a:	89 45 a4                                        	mov    DWORD PTR [rbp-0x5c],eax
  7df28d:	b8 00 00 02 03                                  	mov    eax,0x3020000
  7df292:	48 89 45 98                                     	mov    QWORD PTR [rbp-0x68],rax
  7df296:	48 c7 45 88 00 00 00 00                         	mov    QWORD PTR [rbp-0x78],0x0
  7df29e:	31 f6                                           	xor    esi,esi
  7df2a0:	31 d2                                           	xor    edx,edx
  7df2a2:	e8 09 d2 46 00                                  	call   0xc4c4b0
  7df2a7:	44 89 f7                                        	mov    edi,r14d
  7df2aa:	be 02 80 00 00                                  	mov    esi,0x8002
  7df2af:	31 d2                                           	xor    edx,edx
  7df2b1:	e8 1a fa e2 ff                                  	call   0x60ecd0
  7df2b6:	41 f7 c7 00 00 02 00                            	test   r15d,0x20000
  7df2bd:	75 0c                                           	jne    0x7df2cb
  7df2bf:	4c 8b 7d 98                                     	mov    r15,QWORD PTR [rbp-0x68]
  7df2c3:	b0 01                                           	mov    al,0x1
  7df2c5:	48 89 45 90                                     	mov    QWORD PTR [rbp-0x70],rax
  7df2c9:	eb 55                                           	jmp    0x7df320
  7df2cb:	4d 8b 7d 00                                     	mov    r15,QWORD PTR [r13+0x0]
  7df2cf:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  7df2d8:	48 8d 35 b8 ff b6 00                            	lea    rsi,[rip+0xb6ffb8]        # 0x134f297
  7df2df:	31 d2                                           	xor    edx,edx
  7df2e1:	31 db                                           	xor    ebx,ebx
  7df2e3:	e8 f8 b0 43 00                                  	call   0xc1a3e0
  7df2e8:	48 8d 7d a4                                     	lea    rdi,[rbp-0x5c]
  7df2ec:	ba 04 00 00 00                                  	mov    edx,0x4
  7df2f1:	4c 89 fe                                        	mov    rsi,r15
  7df2f4:	e8 d7 9e a7 ff                                  	call   0x2591d0
  7df2f9:	85 c0                                           	test   eax,eax
  7df2fb:	0f 84 58 01 00 00                               	je     0x7df459
  7df301:	4c 8b 7d 98                                     	mov    r15,QWORD PTR [rbp-0x68]
  7df305:	4d 8b 65 00                                     	mov    r12,QWORD PTR [r13+0x0]
  7df309:	89 c3                                           	mov    ebx,eax
  7df30b:	b8 20 03 02 a0                                  	mov    eax,0xa0020320
  7df310:	48 c7 45 90 00 00 00 00                         	mov    QWORD PTR [rbp-0x70],0x0
  7df318:	48 89 45 88                                     	mov    QWORD PTR [rbp-0x78],rax
  7df31c:	41 83 cf 02                                     	or     r15d,0x2
  7df320:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  7df329:	44 8d ab 00 00 02 80                            	lea    r13d,[rbx-0x7ffe0000]
  7df330:	48 83 ec 08                                     	sub    rsp,0x8
  7df334:	48 8d 45 b0                                     	lea    rax,[rbp-0x50]
  7df338:	be 14 47 00 00                                  	mov    esi,0x4714
  7df33d:	ba ff ff ff ff                                  	mov    edx,0xffffffff
  7df342:	b9 ff ff ff ff                                  	mov    ecx,0xffffffff
  7df347:	45 89 f0                                        	mov    r8d,r14d
  7df34a:	45 89 e9                                        	mov    r9d,r13d
  7df34d:	50                                              	push   rax
  7df34e:	41 54                                           	push   r12
  7df350:	41 57                                           	push   r15
  7df352:	e8 19 06 42 00                                  	call   0xbff970
  7df357:	48 83 c4 20                                     	add    rsp,0x20
  7df35b:	e8 70 85 32 00                                  	call   0xb078d0
  7df360:	85 c0                                           	test   eax,eax
  7df362:	0f 84 86 00 00 00                               	je     0x7df3ee
  7df368:	83 3d 91 0c 4d 02 00                            	cmp    DWORD PTR [rip+0x24d0c91],0x0        # 0x2cb0000
  7df36f:	74 7d                                           	je     0x7df3ee
  7df371:	48 89 5d 98                                     	mov    QWORD PTR [rbp-0x68],rbx
  7df375:	4c 89 fb                                        	mov    rbx,r15
  7df378:	4c 8b 3d a1 75 41 03                            	mov    r15,QWORD PTR [rip+0x34175a1]        # 0x3bf6920
  7df37f:	48 8d 05 62 a0 a8 ff                            	lea    rax,[rip+0xffffffffffa8a062]        # 0x2693e8
  7df386:	4c 29 f8                                        	sub    rax,r15
  7df389:	48 c1 c8 03                                     	ror    rax,0x3
  7df38d:	48 83 f8 01                                     	cmp    rax,0x1
  7df391:	0f 87 f4 00 00 00                               	ja     0x7df48b
  7df397:	41 0f b7 c6                                     	movzx  eax,r14w
  7df39b:	41 bb 20 03 02 a0                               	mov    r11d,0xa0020320
  7df3a1:	48 8b 4d b0                                     	mov    rcx,QWORD PTR [rbp-0x50]
  7df3a5:	4c 8b 45 b8                                     	mov    r8,QWORD PTR [rbp-0x48]
  7df3a9:	4c 8b 4d c0                                     	mov    r9,QWORD PTR [rbp-0x40]
  7df3ad:	45 89 ea                                        	mov    r10d,r13d
  7df3b0:	ba 14 47 00 00                                  	mov    edx,0x4714
  7df3b5:	bf 08 00 00 00                                  	mov    edi,0x8
  7df3ba:	be 02 00 00 00                                  	mov    esi,0x2
  7df3bf:	48 c1 e0 20                                     	shl    rax,0x20
  7df3c3:	49 81 c3 df fc fd 5f                            	add    r11,0x5ffdfcdf
  7df3ca:	49 09 c3                                        	or     r11,rax
  7df3cd:	48 89 d8                                        	mov    rax,rbx
  7df3d0:	48 c1 e0 20                                     	shl    rax,0x20
  7df3d4:	49 09 c2                                        	or     r10,rax
  7df3d7:	41 54                                           	push   r12
  7df3d9:	41 52                                           	push   r10
  7df3db:	41 53                                           	push   r11
  7df3dd:	ff 75 c8                                        	push   QWORD PTR [rbp-0x38]
  7df3e0:	41 ff d7                                        	call   r15
  7df3e3:	49 89 df                                        	mov    r15,rbx
  7df3e6:	48 83 c4 20                                     	add    rsp,0x20
  7df3ea:	48 8b 5d 98                                     	mov    rbx,QWORD PTR [rbp-0x68]
  7df3ee:	80 7d 90 00                                     	cmp    BYTE PTR [rbp-0x70],0x0
  7df3f2:	75 6f                                           	jne    0x7df463
  7df3f4:	65 4c 8b 34 25 00 00 00 00                      	mov    r14,QWORD PTR gs:0x0
  7df3fd:	49 8b 46 08                                     	mov    rax,QWORD PTR [r14+0x8]
  7df401:	81 b8 d4 05 00 00 00 00 50 03                   	cmp    DWORD PTR [rax+0x5d4],0x3500000
  7df40b:	72 56                                           	jb     0x7df463
  7df40d:	48 8d 3d 24 a6 aa 00                            	lea    rdi,[rip+0xaaa624]        # 0x1289a38
  7df414:	be c2 00 00 00                                  	mov    esi,0xc2
  7df419:	31 c0                                           	xor    eax,eax
  7df41b:	e8 f0 df a7 ff                                  	call   0x25d410
  7df420:	4c 8b 6d 88                                     	mov    r13,QWORD PTR [rbp-0x78]
  7df424:	41 8b b6 9c 00 00 00                            	mov    esi,DWORD PTR [r14+0x9c]
  7df42b:	4c 89 f2                                        	mov    rdx,r14
  7df42e:	48 8d 3d 72 d2 a8 00                            	lea    rdi,[rip+0xa8d272]        # 0x126c6a7
  7df435:	45 89 f8                                        	mov    r8d,r15d
  7df438:	4d 89 e1                                        	mov    r9,r12
  7df43b:	31 c0                                           	xor    eax,eax
  7df43d:	48 81 c2 94 02 00 00                            	add    rdx,0x294
  7df444:	4c 89 e9                                        	mov    rcx,r13
  7df447:	e8 c4 df a7 ff                                  	call   0x25d410
  7df44c:	4c 89 f7                                        	mov    rdi,r14
  7df44f:	4c 89 ee                                        	mov    rsi,r13
  7df452:	e8 c9 05 4c 00                                  	call   0xc9fa20
  7df457:	eb 0a                                           	jmp    0x7df463
  7df459:	48 8b 45 90                                     	mov    rax,QWORD PTR [rbp-0x70]
  7df45d:	c7 00 00 00 00 00                               	mov    DWORD PTR [rax],0x0
  7df463:	48 8d 05 a6 ce 13 03                            	lea    rax,[rip+0x313cea6]        # 0x391c310
  7df46a:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  7df46d:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  7df471:	75 11                                           	jne    0x7df484
  7df473:	89 d8                                           	mov    eax,ebx
  7df475:	48 83 c4 58                                     	add    rsp,0x58
  7df479:	5b                                              	pop    rbx
  7df47a:	41 5c                                           	pop    r12
  7df47c:	41 5d                                           	pop    r13
  7df47e:	41 5e                                           	pop    r14
  7df480:	41 5f                                           	pop    r15
  7df482:	5d                                              	pop    rbp
  7df483:	c3                                              	ret
  7df484:	e8 27 e2 f1 ff                                  	call   0x6fd6b0
  7df489:	0f 0b                                           	ud2
  7df48b:	48 8d 3d 7e e7 d5 01                            	lea    rdi,[rip+0x1d5e77e]        # 0x253dc10
  7df492:	4c 89 fe                                        	mov    rsi,r15
  7df495:	e8 26 04 c7 ff                                  	call   0x44f8c0
  7df49a:	e9 f8 fe ff ff                                  	jmp    0x7df397
  7df49f:	90                                              	nop
  7df4a0:	55                                              	push   rbp
  7df4a1:	48 89 e5                                        	mov    rbp,rsp
  7df4a4:	41 57                                           	push   r15
  7df4a6:	41 56                                           	push   r14
  7df4a8:	41 55                                           	push   r13
  7df4aa:	41 54                                           	push   r12
  7df4ac:	53                                              	push   rbx
  7df4ad:	48 83 ec 68                                     	sub    rsp,0x68
  7df4b1:	4c 8d 35 58 ce 13 03                            	lea    r14,[rip+0x313ce58]        # 0x391c310
  7df4b8:	49 89 d5                                        	mov    r13,rdx
  7df4bb:	49 89 f4                                        	mov    r12,rsi
  7df4be:	48 8d 55 a8                                     	lea    rdx,[rbp-0x58]
  7df4c2:	be 02 80 00 00                                  	mov    esi,0x8002
  7df4c7:	b9 ff ff ff 03                                  	mov    ecx,0x3ffffff
  7df4cc:	89 fb                                           	mov    ebx,edi
  7df4ce:	49 8b 06                                        	mov    rax,QWORD PTR [r14]
  7df4d1:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  7df4d5:	48 c7 45 a8 00 00 00 00                         	mov    QWORD PTR [rbp-0x58],0x0
  7df4dd:	c6 45 b0 00                                     	mov    BYTE PTR [rbp-0x50],0x0
  7df4e1:	e8 2a f7 e2 ff                                  	call   0x60ec10
  7df4e6:	85 c0                                           	test   eax,eax
  7df4e8:	74 22                                           	je     0x7df50c
  7df4ea:	41 89 c7                                        	mov    r15d,eax
  7df4ed:	b8 20 03 02 a0                                  	mov    eax,0xa0020320
  7df4f2:	41 ba 00 00 63 04                               	mov    r10d,0x4630000
  7df4f8:	48 c7 45 88 00 00 00 00                         	mov    QWORD PTR [rbp-0x78],0x0
  7df500:	45 31 ed                                        	xor    r13d,r13d
  7df503:	48 89 45 90                                     	mov    QWORD PTR [rbp-0x70],rax
  7df507:	e9 0e 02 00 00                                  	jmp    0x7df71a
  7df50c:	48 8b 45 a8                                     	mov    rax,QWORD PTR [rbp-0x58]
  7df510:	48 8d 7d b0                                     	lea    rdi,[rbp-0x50]
  7df514:	ba 20 00 00 00                                  	mov    edx,0x20
  7df519:	4c 89 6d 80                                     	mov    QWORD PTR [rbp-0x80],r13
  7df51d:	48 8b 70 18                                     	mov    rsi,QWORD PTR [rax+0x18]
  7df521:	e8 4a 86 17 00                                  	call   0x957b70
  7df526:	48 8b 45 a8                                     	mov    rax,QWORD PTR [rbp-0x58]
  7df52a:	45 31 ff                                        	xor    r15d,r15d
  7df52d:	31 f6                                           	xor    esi,esi
  7df52f:	31 d2                                           	xor    edx,edx
  7df531:	31 c9                                           	xor    ecx,ecx
  7df533:	48 8b 78 28                                     	mov    rdi,QWORD PTR [rax+0x28]
  7df537:	e8 e4 c5 46 00                                  	call   0xc4bb20
  7df53c:	48 8b 45 a8                                     	mov    rax,QWORD PTR [rbp-0x58]
  7df540:	4c 89 a5 78 ff ff ff                            	mov    QWORD PTR [rbp-0x88],r12
  7df547:	48 8b 78 28                                     	mov    rdi,QWORD PTR [rax+0x28]
  7df54b:	44 8b 6f 20                                     	mov    r13d,DWORD PTR [rdi+0x20]
  7df54f:	41 f7 c5 00 00 02 00                            	test   r13d,0x20000
  7df556:	75 10                                           	jne    0x7df568
  7df558:	b8 02 00 63 04                                  	mov    eax,0x4630002
  7df55d:	41 bf 03 00 00 00                               	mov    r15d,0x3
  7df563:	45 31 e4                                        	xor    r12d,r12d
  7df566:	eb 31                                           	jmp    0x7df599
  7df568:	44 8b b7 94 01 00 00                            	mov    r14d,DWORD PTR [rdi+0x194]
  7df56f:	41 83 fe ff                                     	cmp    r14d,0xffffffff
  7df573:	74 0d                                           	je     0x7df582
  7df575:	b8 00 00 63 04                                  	mov    eax,0x4630000
  7df57a:	41 b4 01                                        	mov    r12b,0x1
  7df57d:	45 31 ed                                        	xor    r13d,r13d
  7df580:	eb 17                                           	jmp    0x7df599
  7df582:	b8 01 00 63 04                                  	mov    eax,0x4630001
  7df587:	41 be ff ff ff ff                               	mov    r14d,0xffffffff
  7df58d:	41 bf 03 00 00 00                               	mov    r15d,0x3
  7df593:	45 31 ed                                        	xor    r13d,r13d
  7df596:	45 31 e4                                        	xor    r12d,r12d
  7df599:	48 89 45 98                                     	mov    QWORD PTR [rbp-0x68],rax
  7df59d:	48 c7 45 90 00 00 00 00                         	mov    QWORD PTR [rbp-0x70],0x0
  7df5a5:	31 f6                                           	xor    esi,esi
  7df5a7:	31 d2                                           	xor    edx,edx
  7df5a9:	e8 02 cf 46 00                                  	call   0xc4c4b0
  7df5ae:	89 df                                           	mov    edi,ebx
  7df5b0:	be 02 80 00 00                                  	mov    esi,0x8002
  7df5b5:	31 d2                                           	xor    edx,edx
  7df5b7:	e8 14 f7 e2 ff                                  	call   0x60ecd0
  7df5bc:	b0 01                                           	mov    al,0x1
  7df5be:	48 89 45 88                                     	mov    QWORD PTR [rbp-0x78],rax
  7df5c2:	45 84 e4                                        	test   r12b,r12b
  7df5c5:	74 63                                           	je     0x7df62a
  7df5c7:	48 8d 3d 92 a8 da 02                            	lea    rdi,[rip+0x2daa892]        # 0x3589e60
  7df5ce:	c7 45 a4 00 00 00 00                            	mov    DWORD PTR [rbp-0x5c],0x0
  7df5d5:	31 f6                                           	xor    esi,esi
  7df5d7:	31 d2                                           	xor    edx,edx
  7df5d9:	31 c9                                           	xor    ecx,ecx
  7df5db:	e8 70 bd 46 00                                  	call   0xc4b350
  7df5e0:	49 63 ce                                        	movsxd rcx,r14d
  7df5e3:	48 23 0d 26 a8 da 02                            	and    rcx,QWORD PTR [rip+0x2daa826]        # 0x3589e10
  7df5ea:	48 8b 05 27 a8 da 02                            	mov    rax,QWORD PTR [rip+0x2daa827]        # 0x3589e18
  7df5f1:	4c 8b a5 78 ff ff ff                            	mov    r12,QWORD PTR [rbp-0x88]
  7df5f8:	4c 8b 6d 80                                     	mov    r13,QWORD PTR [rbp-0x80]
  7df5fc:	4c 8b 3c c8                                     	mov    r15,QWORD PTR [rax+rcx*8]
  7df600:	4d 85 ff                                        	test   r15,r15
  7df603:	0f 84 e3 00 00 00                               	je     0x7df6ec
  7df609:	0f 1f 80 00 00 00 00                            	nop    DWORD PTR [rax+0x0]
  7df610:	45 39 b7 bc 00 00 00                            	cmp    DWORD PTR [r15+0xbc],r14d
  7df617:	74 21                                           	je     0x7df63a
  7df619:	4d 8b bf c0 00 00 00                            	mov    r15,QWORD PTR [r15+0xc0]
  7df620:	4d 85 ff                                        	test   r15,r15
  7df623:	75 eb                                           	jne    0x7df610
  7df625:	e9 c2 00 00 00                                  	jmp    0x7df6ec
  7df62a:	4c 8d 35 df cc 13 03                            	lea    r14,[rip+0x313ccdf]        # 0x391c310
  7df631:	4c 8b 55 98                                     	mov    r10,QWORD PTR [rbp-0x68]
  7df635:	e9 e0 00 00 00                                  	jmp    0x7df71a
  7df63a:	4d 8d b7 48 01 00 00                            	lea    r14,[r15+0x148]
  7df641:	31 f6                                           	xor    esi,esi
  7df643:	31 d2                                           	xor    edx,edx
  7df645:	31 c9                                           	xor    ecx,ecx
  7df647:	4c 89 f7                                        	mov    rdi,r14
  7df64a:	e8 b1 73 ce ff                                  	call   0x4c6a00
  7df64f:	41 83 bf b8 00 00 00 00                         	cmp    DWORD PTR [r15+0xb8],0x0
  7df657:	0f 84 81 00 00 00                               	je     0x7df6de
  7df65d:	41 8b 87 60 04 00 00                            	mov    eax,DWORD PTR [r15+0x460]
  7df664:	4c 89 f7                                        	mov    rdi,r14
  7df667:	45 31 ff                                        	xor    r15d,r15d
  7df66a:	31 f6                                           	xor    esi,esi
  7df66c:	31 d2                                           	xor    edx,edx
  7df66e:	31 c9                                           	xor    ecx,ecx
  7df670:	89 45 a4                                        	mov    DWORD PTR [rbp-0x5c],eax
  7df673:	e8 28 79 ce ff                                  	call   0x4c6fa0
  7df678:	48 8d 3d e1 a7 da 02                            	lea    rdi,[rip+0x2daa7e1]        # 0x3589e60
  7df67f:	31 f6                                           	xor    esi,esi
  7df681:	31 d2                                           	xor    edx,edx
  7df683:	e8 78 cc 46 00                                  	call   0xc4c300
  7df688:	4d 8b 34 24                                     	mov    r14,QWORD PTR [r12]
  7df68c:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  7df695:	48 8d 35 fb fb b6 00                            	lea    rsi,[rip+0xb6fbfb]        # 0x134f297
  7df69c:	31 d2                                           	xor    edx,edx
  7df69e:	e8 3d ad 43 00                                  	call   0xc1a3e0
  7df6a3:	48 8d 7d a4                                     	lea    rdi,[rbp-0x5c]
  7df6a7:	ba 04 00 00 00                                  	mov    edx,0x4
  7df6ac:	4c 89 f6                                        	mov    rsi,r14
  7df6af:	e8 1c 9b a7 ff                                  	call   0x2591d0
  7df6b4:	85 c0                                           	test   eax,eax
  7df6b6:	0f 84 a9 01 00 00                               	je     0x7df865
  7df6bc:	4c 8b 55 98                                     	mov    r10,QWORD PTR [rbp-0x68]
  7df6c0:	4d 8b 2c 24                                     	mov    r13,QWORD PTR [r12]
  7df6c4:	41 89 c7                                        	mov    r15d,eax
  7df6c7:	b8 20 03 02 a0                                  	mov    eax,0xa0020320
  7df6cc:	48 c7 45 88 00 00 00 00                         	mov    QWORD PTR [rbp-0x78],0x0
  7df6d4:	48 89 45 90                                     	mov    QWORD PTR [rbp-0x70],rax
  7df6d8:	41 83 ca 04                                     	or     r10d,0x4
  7df6dc:	eb 35                                           	jmp    0x7df713
  7df6de:	4c 89 f7                                        	mov    rdi,r14
  7df6e1:	31 f6                                           	xor    esi,esi
  7df6e3:	31 d2                                           	xor    edx,edx
  7df6e5:	31 c9                                           	xor    ecx,ecx
  7df6e7:	e8 b4 78 ce ff                                  	call   0x4c6fa0
  7df6ec:	48 8d 3d 6d a7 da 02                            	lea    rdi,[rip+0x2daa76d]        # 0x3589e60
  7df6f3:	48 c7 45 90 00 00 00 00                         	mov    QWORD PTR [rbp-0x70],0x0
  7df6fb:	31 f6                                           	xor    esi,esi
  7df6fd:	31 d2                                           	xor    edx,edx
  7df6ff:	e8 fc cb 46 00                                  	call   0xc4c300
  7df704:	41 ba 03 00 63 04                               	mov    r10d,0x4630003
  7df70a:	41 bf 03 00 00 00                               	mov    r15d,0x3
  7df710:	45 31 ed                                        	xor    r13d,r13d
  7df713:	4c 8d 35 f6 cb 13 03                            	lea    r14,[rip+0x313cbf6]        # 0x391c310
  7df71a:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  7df723:	45 8d a7 00 00 02 80                            	lea    r12d,[r15-0x7ffe0000]
  7df72a:	48 83 ec 08                                     	sub    rsp,0x8
  7df72e:	48 8d 45 b0                                     	lea    rax,[rbp-0x50]
  7df732:	be 15 47 00 00                                  	mov    esi,0x4715
  7df737:	ba ff ff ff ff                                  	mov    edx,0xffffffff
  7df73c:	b9 ff ff ff ff                                  	mov    ecx,0xffffffff
  7df741:	41 89 d8                                        	mov    r8d,ebx
  7df744:	45 89 e1                                        	mov    r9d,r12d
  7df747:	50                                              	push   rax
  7df748:	41 55                                           	push   r13
  7df74a:	4c 89 55 98                                     	mov    QWORD PTR [rbp-0x68],r10
  7df74e:	41 52                                           	push   r10
  7df750:	e8 1b 02 42 00                                  	call   0xbff970
  7df755:	48 83 c4 20                                     	add    rsp,0x20
  7df759:	e8 72 81 32 00                                  	call   0xb078d0
  7df75e:	85 c0                                           	test   eax,eax
  7df760:	74 7f                                           	je     0x7df7e1
  7df762:	83 3d 97 08 4d 02 00                            	cmp    DWORD PTR [rip+0x24d0897],0x0        # 0x2cb0000
  7df769:	74 76                                           	je     0x7df7e1
  7df76b:	4c 8b 35 ae 71 41 03                            	mov    r14,QWORD PTR [rip+0x34171ae]        # 0x3bf6920
  7df772:	48 8d 05 6f 9c a8 ff                            	lea    rax,[rip+0xffffffffffa89c6f]        # 0x2693e8
  7df779:	4c 29 f0                                        	sub    rax,r14
  7df77c:	48 c1 c8 03                                     	ror    rax,0x3
  7df780:	48 83 f8 01                                     	cmp    rax,0x1
  7df784:	0f 87 f3 00 00 00                               	ja     0x7df87d
  7df78a:	0f b7 c3                                        	movzx  eax,bx
  7df78d:	41 bb 20 03 02 a0                               	mov    r11d,0xa0020320
  7df793:	48 8b 4d b0                                     	mov    rcx,QWORD PTR [rbp-0x50]
  7df797:	4c 8b 45 b8                                     	mov    r8,QWORD PTR [rbp-0x48]
  7df79b:	4c 8b 4d c0                                     	mov    r9,QWORD PTR [rbp-0x40]
  7df79f:	45 89 e2                                        	mov    r10d,r12d
  7df7a2:	ba 15 47 00 00                                  	mov    edx,0x4715
  7df7a7:	bf 08 00 00 00                                  	mov    edi,0x8
  7df7ac:	be 02 00 00 00                                  	mov    esi,0x2
  7df7b1:	48 c1 e0 20                                     	shl    rax,0x20
  7df7b5:	49 81 c3 df fc fd 5f                            	add    r11,0x5ffdfcdf
  7df7bc:	49 09 c3                                        	or     r11,rax
  7df7bf:	48 8b 45 98                                     	mov    rax,QWORD PTR [rbp-0x68]
  7df7c3:	48 c1 e0 20                                     	shl    rax,0x20
  7df7c7:	49 09 c2                                        	or     r10,rax
  7df7ca:	41 55                                           	push   r13
  7df7cc:	41 52                                           	push   r10
  7df7ce:	41 53                                           	push   r11
  7df7d0:	ff 75 c8                                        	push   QWORD PTR [rbp-0x38]
  7df7d3:	41 ff d6                                        	call   r14
  7df7d6:	48 83 c4 20                                     	add    rsp,0x20
  7df7da:	4c 8d 35 2f cb 13 03                            	lea    r14,[rip+0x313cb2f]        # 0x391c310
  7df7e1:	80 7d 88 00                                     	cmp    BYTE PTR [rbp-0x78],0x0
  7df7e5:	75 63                                           	jne    0x7df84a
  7df7e7:	65 48 8b 1c 25 00 00 00 00                      	mov    rbx,QWORD PTR gs:0x0
  7df7f0:	48 8b 43 08                                     	mov    rax,QWORD PTR [rbx+0x8]
  7df7f4:	81 b8 d4 05 00 00 00 00 50 03                   	cmp    DWORD PTR [rax+0x5d4],0x3500000
  7df7fe:	72 4a                                           	jb     0x7df84a
  7df800:	48 8d 3d 31 a2 aa 00                            	lea    rdi,[rip+0xaaa231]        # 0x1289a38
  7df807:	be c2 00 00 00                                  	mov    esi,0xc2
  7df80c:	31 c0                                           	xor    eax,eax
  7df80e:	e8 fd db a7 ff                                  	call   0x25d410
  7df813:	4c 8b 65 90                                     	mov    r12,QWORD PTR [rbp-0x70]
  7df817:	8b b3 9c 00 00 00                               	mov    esi,DWORD PTR [rbx+0x9c]
  7df81d:	48 89 da                                        	mov    rdx,rbx
  7df820:	48 8d 3d 80 ce a8 00                            	lea    rdi,[rip+0xa8ce80]        # 0x126c6a7
  7df827:	4d 89 e9                                        	mov    r9,r13
  7df82a:	4c 8b 45 98                                     	mov    r8,QWORD PTR [rbp-0x68]
  7df82e:	31 c0                                           	xor    eax,eax
  7df830:	48 81 c2 94 02 00 00                            	add    rdx,0x294
  7df837:	4c 89 e1                                        	mov    rcx,r12
  7df83a:	e8 d1 db a7 ff                                  	call   0x25d410
  7df83f:	48 89 df                                        	mov    rdi,rbx
  7df842:	4c 89 e6                                        	mov    rsi,r12
  7df845:	e8 d6 01 4c 00                                  	call   0xc9fa20
  7df84a:	49 8b 06                                        	mov    rax,QWORD PTR [r14]
  7df84d:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  7df851:	75 23                                           	jne    0x7df876
  7df853:	44 89 f8                                        	mov    eax,r15d
  7df856:	48 83 c4 68                                     	add    rsp,0x68
  7df85a:	5b                                              	pop    rbx
  7df85b:	41 5c                                           	pop    r12
  7df85d:	41 5d                                           	pop    r13
  7df85f:	41 5e                                           	pop    r14
  7df861:	41 5f                                           	pop    r15
  7df863:	5d                                              	pop    rbp
  7df864:	c3                                              	ret
  7df865:	4c 8d 35 a4 ca 13 03                            	lea    r14,[rip+0x313caa4]        # 0x391c310
  7df86c:	41 c7 45 00 00 00 00 00                         	mov    DWORD PTR [r13+0x0],0x0
  7df874:	eb d4                                           	jmp    0x7df84a
  7df876:	e8 35 de f1 ff                                  	call   0x6fd6b0
  7df87b:	0f 0b                                           	ud2
  7df87d:	48 8d 3d ac e3 d5 01                            	lea    rdi,[rip+0x1d5e3ac]        # 0x253dc30
  7df884:	4c 89 f6                                        	mov    rsi,r14
  7df887:	e8 34 00 c7 ff                                  	call   0x44f8c0
  7df88c:	e9 f9 fe ff ff                                  	jmp    0x7df78a
  7df891:	90                                              	nop
  7df892:	90                                              	nop
  7df893:	90                                              	nop
  7df894:	90                                              	nop
  7df895:	90                                              	nop
  7df896:	90                                              	nop
  7df897:	90                                              	nop
  7df898:	90                                              	nop
  7df899:	90                                              	nop
  7df89a:	90                                              	nop
  7df89b:	90                                              	nop
  7df89c:	90                                              	nop
  7df89d:	90                                              	nop
  7df89e:	90                                              	nop
  7df89f:	90                                              	nop
  7df8a0:	55                                              	push   rbp
  7df8a1:	48 89 e5                                        	mov    rbp,rsp
  7df8a4:	41 57                                           	push   r15
  7df8a6:	41 56                                           	push   r14
  7df8a8:	41 55                                           	push   r13
  7df8aa:	41 54                                           	push   r12
  7df8ac:	53                                              	push   rbx
  7df8ad:	48 83 ec 68                                     	sub    rsp,0x68
  7df8b1:	4c 8d 35 58 ca 13 03                            	lea    r14,[rip+0x313ca58]        # 0x391c310
  7df8b8:	49 89 d5                                        	mov    r13,rdx
  7df8bb:	49 89 f4                                        	mov    r12,rsi
  7df8be:	48 8d 55 a8                                     	lea    rdx,[rbp-0x58]
  7df8c2:	be 02 80 00 00                                  	mov    esi,0x8002
  7df8c7:	b9 ff ff ff 03                                  	mov    ecx,0x3ffffff
  7df8cc:	89 fb                                           	mov    ebx,edi
  7df8ce:	49 8b 06                                        	mov    rax,QWORD PTR [r14]
  7df8d1:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  7df8d5:	48 c7 45 a8 00 00 00 00                         	mov    QWORD PTR [rbp-0x58],0x0
  7df8dd:	c6 45 b0 00                                     	mov    BYTE PTR [rbp-0x50],0x0
  7df8e1:	e8 2a f3 e2 ff                                  	call   0x60ec10
  7df8e6:	85 c0                                           	test   eax,eax
  7df8e8:	74 22                                           	je     0x7df90c
  7df8ea:	41 89 c7                                        	mov    r15d,eax
  7df8ed:	b8 20 03 02 a0                                  	mov    eax,0xa0020320
  7df8f2:	41 ba 00 00 64 04                               	mov    r10d,0x4640000
  7df8f8:	48 c7 45 88 00 00 00 00                         	mov    QWORD PTR [rbp-0x78],0x0
  7df900:	45 31 ed                                        	xor    r13d,r13d
  7df903:	48 89 45 90                                     	mov    QWORD PTR [rbp-0x70],rax
  7df907:	e9 10 02 00 00                                  	jmp    0x7dfb1c
  7df90c:	48 8b 45 a8                                     	mov    rax,QWORD PTR [rbp-0x58]
  7df910:	48 8d 7d b0                                     	lea    rdi,[rbp-0x50]
  7df914:	ba 20 00 00 00                                  	mov    edx,0x20
  7df919:	4c 89 6d 80                                     	mov    QWORD PTR [rbp-0x80],r13
  7df91d:	48 8b 70 18                                     	mov    rsi,QWORD PTR [rax+0x18]
  7df921:	e8 4a 82 17 00                                  	call   0x957b70
  7df926:	48 8b 45 a8                                     	mov    rax,QWORD PTR [rbp-0x58]
  7df92a:	45 31 ff                                        	xor    r15d,r15d
  7df92d:	31 f6                                           	xor    esi,esi
  7df92f:	31 d2                                           	xor    edx,edx
  7df931:	31 c9                                           	xor    ecx,ecx
  7df933:	48 8b 78 28                                     	mov    rdi,QWORD PTR [rax+0x28]
  7df937:	e8 e4 c1 46 00                                  	call   0xc4bb20
  7df93c:	48 8b 45 a8                                     	mov    rax,QWORD PTR [rbp-0x58]
  7df940:	4c 89 a5 78 ff ff ff                            	mov    QWORD PTR [rbp-0x88],r12
  7df947:	48 8b 78 28                                     	mov    rdi,QWORD PTR [rax+0x28]
  7df94b:	44 8b 6f 20                                     	mov    r13d,DWORD PTR [rdi+0x20]
  7df94f:	41 f7 c5 00 00 02 00                            	test   r13d,0x20000
  7df956:	75 10                                           	jne    0x7df968
  7df958:	b8 02 00 64 04                                  	mov    eax,0x4640002
  7df95d:	41 bf 03 00 00 00                               	mov    r15d,0x3
  7df963:	45 31 e4                                        	xor    r12d,r12d
  7df966:	eb 31                                           	jmp    0x7df999
  7df968:	44 8b b7 94 01 00 00                            	mov    r14d,DWORD PTR [rdi+0x194]
  7df96f:	41 83 fe ff                                     	cmp    r14d,0xffffffff
  7df973:	74 0d                                           	je     0x7df982
  7df975:	b8 00 00 64 04                                  	mov    eax,0x4640000
  7df97a:	41 b4 01                                        	mov    r12b,0x1
  7df97d:	45 31 ed                                        	xor    r13d,r13d
  7df980:	eb 17                                           	jmp    0x7df999
  7df982:	b8 01 00 64 04                                  	mov    eax,0x4640001
  7df987:	41 be ff ff ff ff                               	mov    r14d,0xffffffff
  7df98d:	41 bf 03 00 00 00                               	mov    r15d,0x3
  7df993:	45 31 ed                                        	xor    r13d,r13d
  7df996:	45 31 e4                                        	xor    r12d,r12d
  7df999:	48 89 45 98                                     	mov    QWORD PTR [rbp-0x68],rax
  7df99d:	48 c7 45 90 00 00 00 00                         	mov    QWORD PTR [rbp-0x70],0x0
  7df9a5:	31 f6                                           	xor    esi,esi
  7df9a7:	31 d2                                           	xor    edx,edx
  7df9a9:	e8 02 cb 46 00                                  	call   0xc4c4b0
  7df9ae:	89 df                                           	mov    edi,ebx
  7df9b0:	be 02 80 00 00                                  	mov    esi,0x8002
  7df9b5:	31 d2                                           	xor    edx,edx
  7df9b7:	e8 14 f3 e2 ff                                  	call   0x60ecd0
  7df9bc:	b0 01                                           	mov    al,0x1
  7df9be:	48 89 45 88                                     	mov    QWORD PTR [rbp-0x78],rax
  7df9c2:	45 84 e4                                        	test   r12b,r12b
  7df9c5:	74 63                                           	je     0x7dfa2a
  7df9c7:	48 8d 3d 92 a4 da 02                            	lea    rdi,[rip+0x2daa492]        # 0x3589e60
  7df9ce:	c7 45 a4 00 00 00 00                            	mov    DWORD PTR [rbp-0x5c],0x0
  7df9d5:	31 f6                                           	xor    esi,esi
  7df9d7:	31 d2                                           	xor    edx,edx
  7df9d9:	31 c9                                           	xor    ecx,ecx
  7df9db:	e8 70 b9 46 00                                  	call   0xc4b350
  7df9e0:	49 63 ce                                        	movsxd rcx,r14d
  7df9e3:	48 23 0d 26 a4 da 02                            	and    rcx,QWORD PTR [rip+0x2daa426]        # 0x3589e10
  7df9ea:	48 8b 05 27 a4 da 02                            	mov    rax,QWORD PTR [rip+0x2daa427]        # 0x3589e18
  7df9f1:	4c 8b a5 78 ff ff ff                            	mov    r12,QWORD PTR [rbp-0x88]
  7df9f8:	4c 8b 6d 80                                     	mov    r13,QWORD PTR [rbp-0x80]
  7df9fc:	4c 8b 3c c8                                     	mov    r15,QWORD PTR [rax+rcx*8]
  7dfa00:	4d 85 ff                                        	test   r15,r15
  7dfa03:	0f 84 e5 00 00 00                               	je     0x7dfaee
  7dfa09:	0f 1f 80 00 00 00 00                            	nop    DWORD PTR [rax+0x0]
  7dfa10:	45 39 b7 bc 00 00 00                            	cmp    DWORD PTR [r15+0xbc],r14d
  7dfa17:	74 21                                           	je     0x7dfa3a
  7dfa19:	4d 8b bf c0 00 00 00                            	mov    r15,QWORD PTR [r15+0xc0]
  7dfa20:	4d 85 ff                                        	test   r15,r15
  7dfa23:	75 eb                                           	jne    0x7dfa10
  7dfa25:	e9 c4 00 00 00                                  	jmp    0x7dfaee
  7dfa2a:	4c 8d 35 df c8 13 03                            	lea    r14,[rip+0x313c8df]        # 0x391c310
  7dfa31:	4c 8b 55 98                                     	mov    r10,QWORD PTR [rbp-0x68]
  7dfa35:	e9 e2 00 00 00                                  	jmp    0x7dfb1c
  7dfa3a:	4d 8d b7 48 01 00 00                            	lea    r14,[r15+0x148]
  7dfa41:	31 f6                                           	xor    esi,esi
  7dfa43:	31 d2                                           	xor    edx,edx
  7dfa45:	31 c9                                           	xor    ecx,ecx
  7dfa47:	4c 89 f7                                        	mov    rdi,r14
  7dfa4a:	e8 b1 6f ce ff                                  	call   0x4c6a00
  7dfa4f:	41 83 bf b8 00 00 00 00                         	cmp    DWORD PTR [r15+0xb8],0x0
  7dfa57:	0f 84 83 00 00 00                               	je     0x7dfae0
  7dfa5d:	49 8b 7f 40                                     	mov    rdi,QWORD PTR [r15+0x40]
  7dfa61:	e8 2a 95 e2 ff                                  	call   0x608f90
  7dfa66:	4c 89 f7                                        	mov    rdi,r14
  7dfa69:	89 45 a4                                        	mov    DWORD PTR [rbp-0x5c],eax
  7dfa6c:	45 31 ff                                        	xor    r15d,r15d
  7dfa6f:	31 f6                                           	xor    esi,esi
  7dfa71:	31 d2                                           	xor    edx,edx
  7dfa73:	31 c9                                           	xor    ecx,ecx
  7dfa75:	e8 26 75 ce ff                                  	call   0x4c6fa0
  7dfa7a:	48 8d 3d df a3 da 02                            	lea    rdi,[rip+0x2daa3df]        # 0x3589e60
  7dfa81:	31 f6                                           	xor    esi,esi
  7dfa83:	31 d2                                           	xor    edx,edx
  7dfa85:	e8 76 c8 46 00                                  	call   0xc4c300
  7dfa8a:	4d 8b 34 24                                     	mov    r14,QWORD PTR [r12]
  7dfa8e:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  7dfa97:	48 8d 35 f9 f7 b6 00                            	lea    rsi,[rip+0xb6f7f9]        # 0x134f297
  7dfa9e:	31 d2                                           	xor    edx,edx
  7dfaa0:	e8 3b a9 43 00                                  	call   0xc1a3e0
  7dfaa5:	48 8d 7d a4                                     	lea    rdi,[rbp-0x5c]
  7dfaa9:	ba 04 00 00 00                                  	mov    edx,0x4
  7dfaae:	4c 89 f6                                        	mov    rsi,r14
  7dfab1:	e8 1a 97 a7 ff                                  	call   0x2591d0
  7dfab6:	85 c0                                           	test   eax,eax
  7dfab8:	0f 84 a9 01 00 00                               	je     0x7dfc67
  7dfabe:	4c 8b 55 98                                     	mov    r10,QWORD PTR [rbp-0x68]
  7dfac2:	4d 8b 2c 24                                     	mov    r13,QWORD PTR [r12]
  7dfac6:	41 89 c7                                        	mov    r15d,eax
  7dfac9:	b8 20 03 02 a0                                  	mov    eax,0xa0020320
  7dface:	48 c7 45 88 00 00 00 00                         	mov    QWORD PTR [rbp-0x78],0x0
  7dfad6:	48 89 45 90                                     	mov    QWORD PTR [rbp-0x70],rax
  7dfada:	41 83 ca 04                                     	or     r10d,0x4
  7dfade:	eb 35                                           	jmp    0x7dfb15
  7dfae0:	4c 89 f7                                        	mov    rdi,r14
  7dfae3:	31 f6                                           	xor    esi,esi
  7dfae5:	31 d2                                           	xor    edx,edx
  7dfae7:	31 c9                                           	xor    ecx,ecx
  7dfae9:	e8 b2 74 ce ff                                  	call   0x4c6fa0
  7dfaee:	48 8d 3d 6b a3 da 02                            	lea    rdi,[rip+0x2daa36b]        # 0x3589e60
  7dfaf5:	48 c7 45 90 00 00 00 00                         	mov    QWORD PTR [rbp-0x70],0x0
  7dfafd:	31 f6                                           	xor    esi,esi
  7dfaff:	31 d2                                           	xor    edx,edx
  7dfb01:	e8 fa c7 46 00                                  	call   0xc4c300
  7dfb06:	41 ba 03 00 64 04                               	mov    r10d,0x4640003
  7dfb0c:	41 bf 03 00 00 00                               	mov    r15d,0x3
  7dfb12:	45 31 ed                                        	xor    r13d,r13d
  7dfb15:	4c 8d 35 f4 c7 13 03                            	lea    r14,[rip+0x313c7f4]        # 0x391c310
  7dfb1c:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  7dfb25:	45 8d a7 00 00 02 80                            	lea    r12d,[r15-0x7ffe0000]
  7dfb2c:	48 83 ec 08                                     	sub    rsp,0x8
  7dfb30:	48 8d 45 b0                                     	lea    rax,[rbp-0x50]
  7dfb34:	be 16 47 00 00                                  	mov    esi,0x4716
  7dfb39:	ba ff ff ff ff                                  	mov    edx,0xffffffff
  7dfb3e:	b9 ff ff ff ff                                  	mov    ecx,0xffffffff
  7dfb43:	41 89 d8                                        	mov    r8d,ebx
  7dfb46:	45 89 e1                                        	mov    r9d,r12d
  7dfb49:	50                                              	push   rax
  7dfb4a:	41 55                                           	push   r13
  7dfb4c:	4c 89 55 98                                     	mov    QWORD PTR [rbp-0x68],r10
  7dfb50:	41 52                                           	push   r10
  7dfb52:	e8 19 fe 41 00                                  	call   0xbff970
  7dfb57:	48 83 c4 20                                     	add    rsp,0x20
  7dfb5b:	e8 70 7d 32 00                                  	call   0xb078d0
  7dfb60:	85 c0                                           	test   eax,eax
  7dfb62:	74 7f                                           	je     0x7dfbe3
  7dfb64:	83 3d 95 04 4d 02 00                            	cmp    DWORD PTR [rip+0x24d0495],0x0        # 0x2cb0000
  7dfb6b:	74 76                                           	je     0x7dfbe3
  7dfb6d:	4c 8b 35 ac 6d 41 03                            	mov    r14,QWORD PTR [rip+0x3416dac]        # 0x3bf6920
  7dfb74:	48 8d 05 6d 98 a8 ff                            	lea    rax,[rip+0xffffffffffa8986d]        # 0x2693e8
  7dfb7b:	4c 29 f0                                        	sub    rax,r14
  7dfb7e:	48 c1 c8 03                                     	ror    rax,0x3
  7dfb82:	48 83 f8 01                                     	cmp    rax,0x1
  7dfb86:	0f 87 f3 00 00 00                               	ja     0x7dfc7f
  7dfb8c:	0f b7 c3                                        	movzx  eax,bx
  7dfb8f:	41 bb 20 03 02 a0                               	mov    r11d,0xa0020320
  7dfb95:	48 8b 4d b0                                     	mov    rcx,QWORD PTR [rbp-0x50]
  7dfb99:	4c 8b 45 b8                                     	mov    r8,QWORD PTR [rbp-0x48]
  7dfb9d:	4c 8b 4d c0                                     	mov    r9,QWORD PTR [rbp-0x40]
  7dfba1:	45 89 e2                                        	mov    r10d,r12d
  7dfba4:	ba 16 47 00 00                                  	mov    edx,0x4716
  7dfba9:	bf 08 00 00 00                                  	mov    edi,0x8
  7dfbae:	be 02 00 00 00                                  	mov    esi,0x2
  7dfbb3:	48 c1 e0 20                                     	shl    rax,0x20
  7dfbb7:	49 81 c3 df fc fd 5f                            	add    r11,0x5ffdfcdf
  7dfbbe:	49 09 c3                                        	or     r11,rax
  7dfbc1:	48 8b 45 98                                     	mov    rax,QWORD PTR [rbp-0x68]
  7dfbc5:	48 c1 e0 20                                     	shl    rax,0x20
  7dfbc9:	49 09 c2                                        	or     r10,rax
  7dfbcc:	41 55                                           	push   r13
  7dfbce:	41 52                                           	push   r10
  7dfbd0:	41 53                                           	push   r11
  7dfbd2:	ff 75 c8                                        	push   QWORD PTR [rbp-0x38]
  7dfbd5:	41 ff d6                                        	call   r14
  7dfbd8:	48 83 c4 20                                     	add    rsp,0x20
  7dfbdc:	4c 8d 35 2d c7 13 03                            	lea    r14,[rip+0x313c72d]        # 0x391c310
  7dfbe3:	80 7d 88 00                                     	cmp    BYTE PTR [rbp-0x78],0x0
  7dfbe7:	75 63                                           	jne    0x7dfc4c
  7dfbe9:	65 48 8b 1c 25 00 00 00 00                      	mov    rbx,QWORD PTR gs:0x0
  7dfbf2:	48 8b 43 08                                     	mov    rax,QWORD PTR [rbx+0x8]
  7dfbf6:	81 b8 d4 05 00 00 00 00 50 03                   	cmp    DWORD PTR [rax+0x5d4],0x3500000
  7dfc00:	72 4a                                           	jb     0x7dfc4c
  7dfc02:	48 8d 3d 2f 9e aa 00                            	lea    rdi,[rip+0xaa9e2f]        # 0x1289a38
  7dfc09:	be c2 00 00 00                                  	mov    esi,0xc2
  7dfc0e:	31 c0                                           	xor    eax,eax
  7dfc10:	e8 fb d7 a7 ff                                  	call   0x25d410
  7dfc15:	4c 8b 65 90                                     	mov    r12,QWORD PTR [rbp-0x70]
  7dfc19:	8b b3 9c 00 00 00                               	mov    esi,DWORD PTR [rbx+0x9c]
  7dfc1f:	48 89 da                                        	mov    rdx,rbx
  7dfc22:	48 8d 3d 7e ca a8 00                            	lea    rdi,[rip+0xa8ca7e]        # 0x126c6a7
  7dfc29:	4d 89 e9                                        	mov    r9,r13
  7dfc2c:	4c 8b 45 98                                     	mov    r8,QWORD PTR [rbp-0x68]
  7dfc30:	31 c0                                           	xor    eax,eax
  7dfc32:	48 81 c2 94 02 00 00                            	add    rdx,0x294
  7dfc39:	4c 89 e1                                        	mov    rcx,r12
  7dfc3c:	e8 cf d7 a7 ff                                  	call   0x25d410
  7dfc41:	48 89 df                                        	mov    rdi,rbx
  7dfc44:	4c 89 e6                                        	mov    rsi,r12
  7dfc47:	e8 d4 fd 4b 00                                  	call   0xc9fa20
  7dfc4c:	49 8b 06                                        	mov    rax,QWORD PTR [r14]
  7dfc4f:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  7dfc53:	75 23                                           	jne    0x7dfc78
  7dfc55:	44 89 f8                                        	mov    eax,r15d
  7dfc58:	48 83 c4 68                                     	add    rsp,0x68
  7dfc5c:	5b                                              	pop    rbx
  7dfc5d:	41 5c                                           	pop    r12
  7dfc5f:	41 5d                                           	pop    r13
  7dfc61:	41 5e                                           	pop    r14
  7dfc63:	41 5f                                           	pop    r15
  7dfc65:	5d                                              	pop    rbp
  7dfc66:	c3                                              	ret
  7dfc67:	4c 8d 35 a2 c6 13 03                            	lea    r14,[rip+0x313c6a2]        # 0x391c310
  7dfc6e:	41 c7 45 00 00 00 00 00                         	mov    DWORD PTR [r13+0x0],0x0
  7dfc76:	eb d4                                           	jmp    0x7dfc4c
  7dfc78:	e8 33 da f1 ff                                  	call   0x6fd6b0
  7dfc7d:	0f 0b                                           	ud2
  7dfc7f:	48 8d 3d ca df d5 01                            	lea    rdi,[rip+0x1d5dfca]        # 0x253dc50
  7dfc86:	4c 89 f6                                        	mov    rsi,r14
  7dfc89:	e8 32 fc c6 ff                                  	call   0x44f8c0
  7dfc8e:	e9 f9 fe ff ff                                  	jmp    0x7dfb8c
  7dfc93:	90                                              	nop
  7dfc94:	90                                              	nop
  7dfc95:	90                                              	nop
  7dfc96:	90                                              	nop
  7dfc97:	90                                              	nop
  7dfc98:	90                                              	nop
  7dfc99:	90                                              	nop
  7dfc9a:	90                                              	nop
  7dfc9b:	90                                              	nop
  7dfc9c:	90                                              	nop
  7dfc9d:	90                                              	nop
  7dfc9e:	90                                              	nop
  7dfc9f:	90                                              	nop
  7dfca0:	55                                              	push   rbp
  7dfca1:	48 89 e5                                        	mov    rbp,rsp
  7dfca4:	41 57                                           	push   r15
  7dfca6:	41 56                                           	push   r14
  7dfca8:	41 55                                           	push   r13
  7dfcaa:	41 54                                           	push   r12
  7dfcac:	53                                              	push   rbx
  7dfcad:	48 83 ec 68                                     	sub    rsp,0x68
  7dfcb1:	4c 8d 3d 58 c6 13 03                            	lea    r15,[rip+0x313c658]        # 0x391c310
  7dfcb8:	49 89 d4                                        	mov    r12,rdx
  7dfcbb:	49 89 f6                                        	mov    r14,rsi
  7dfcbe:	48 8d 55 a8                                     	lea    rdx,[rbp-0x58]
  7dfcc2:	be 02 80 00 00                                  	mov    esi,0x8002
  7dfcc7:	b9 ff ff ff 03                                  	mov    ecx,0x3ffffff
  7dfccc:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  7dfccf:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  7dfcd3:	48 89 bd 78 ff ff ff                            	mov    QWORD PTR [rbp-0x88],rdi
  7dfcda:	48 c7 45 a8 00 00 00 00                         	mov    QWORD PTR [rbp-0x58],0x0
  7dfce2:	48 c7 45 a0 00 00 00 00                         	mov    QWORD PTR [rbp-0x60],0x0
  7dfcea:	48 c7 45 98 00 00 00 00                         	mov    QWORD PTR [rbp-0x68],0x0
  7dfcf2:	c6 45 b0 00                                     	mov    BYTE PTR [rbp-0x50],0x0
  7dfcf6:	e8 15 ef e2 ff                                  	call   0x60ec10
  7dfcfb:	85 c0                                           	test   eax,eax
  7dfcfd:	74 26                                           	je     0x7dfd25
  7dfcff:	89 c3                                           	mov    ebx,eax
  7dfd01:	b8 20 03 02 a0                                  	mov    eax,0xa0020320
  7dfd06:	41 ba 00 00 65 04                               	mov    r10d,0x4650000
  7dfd0c:	ba ff ff ff ff                                  	mov    edx,0xffffffff
  7dfd11:	48 c7 45 80 00 00 00 00                         	mov    QWORD PTR [rbp-0x80],0x0
  7dfd19:	45 31 ed                                        	xor    r13d,r13d
  7dfd1c:	48 89 45 88                                     	mov    QWORD PTR [rbp-0x78],rax
  7dfd20:	e9 ec 00 00 00                                  	jmp    0x7dfe11
  7dfd25:	48 8b 45 a8                                     	mov    rax,QWORD PTR [rbp-0x58]
  7dfd29:	48 8d 7d b0                                     	lea    rdi,[rbp-0x50]
  7dfd2d:	ba 20 00 00 00                                  	mov    edx,0x20
  7dfd32:	4c 89 65 88                                     	mov    QWORD PTR [rbp-0x78],r12
  7dfd36:	48 8b 70 18                                     	mov    rsi,QWORD PTR [rax+0x18]
  7dfd3a:	e8 31 7e 17 00                                  	call   0x957b70
  7dfd3f:	48 8b 45 a8                                     	mov    rax,QWORD PTR [rbp-0x58]
  7dfd43:	31 db                                           	xor    ebx,ebx
  7dfd45:	31 f6                                           	xor    esi,esi
  7dfd47:	31 d2                                           	xor    edx,edx
  7dfd49:	31 c9                                           	xor    ecx,ecx
  7dfd4b:	48 8b 78 28                                     	mov    rdi,QWORD PTR [rax+0x28]
  7dfd4f:	e8 cc bd 46 00                                  	call   0xc4bb20
  7dfd54:	48 8b 45 a8                                     	mov    rax,QWORD PTR [rbp-0x58]
  7dfd58:	48 8b 78 28                                     	mov    rdi,QWORD PTR [rax+0x28]
  7dfd5c:	44 8b 7f 20                                     	mov    r15d,DWORD PTR [rdi+0x20]
  7dfd60:	41 f7 c7 00 00 02 00                            	test   r15d,0x20000
  7dfd67:	75 17                                           	jne    0x7dfd80
  7dfd69:	bb 03 00 00 00                                  	mov    ebx,0x3
  7dfd6e:	41 bc 01 00 65 04                               	mov    r12d,0x4650001
  7dfd74:	4d 89 fd                                        	mov    r13,r15
  7dfd77:	c7 45 90 ff ff ff ff                            	mov    DWORD PTR [rbp-0x70],0xffffffff
  7dfd7e:	eb 0f                                           	jmp    0x7dfd8f
  7dfd80:	8b 47 38                                        	mov    eax,DWORD PTR [rdi+0x38]
  7dfd83:	41 bc 00 00 65 04                               	mov    r12d,0x4650000
  7dfd89:	45 31 ed                                        	xor    r13d,r13d
  7dfd8c:	89 45 90                                        	mov    DWORD PTR [rbp-0x70],eax
  7dfd8f:	31 f6                                           	xor    esi,esi
  7dfd91:	31 d2                                           	xor    edx,edx
  7dfd93:	e8 18 c7 46 00                                  	call   0xc4c4b0
  7dfd98:	be 02 80 00 00                                  	mov    esi,0x8002
  7dfd9d:	48 8b bd 78 ff ff ff                            	mov    rdi,QWORD PTR [rbp-0x88]
  7dfda4:	31 d2                                           	xor    edx,edx
  7dfda6:	e8 25 ef e2 ff                                  	call   0x60ecd0
  7dfdab:	b0 01                                           	mov    al,0x1
  7dfdad:	48 89 45 80                                     	mov    QWORD PTR [rbp-0x80],rax
  7dfdb1:	41 f7 c7 00 00 02 00                            	test   r15d,0x20000
  7dfdb8:	75 17                                           	jne    0x7dfdd1
  7dfdba:	4c 8d 3d 4f c5 13 03                            	lea    r15,[rip+0x313c54f]        # 0x391c310
  7dfdc1:	48 c7 45 88 00 00 00 00                         	mov    QWORD PTR [rbp-0x78],0x0
  7dfdc9:	4d 89 e2                                        	mov    r10,r12
  7dfdcc:	8b 55 90                                        	mov    edx,DWORD PTR [rbp-0x70]
  7dfdcf:	eb 40                                           	jmp    0x7dfe11
  7dfdd1:	44 8b 6d 90                                     	mov    r13d,DWORD PTR [rbp-0x70]
  7dfdd5:	48 8d 55 a0                                     	lea    rdx,[rbp-0x60]
  7dfdd9:	be 01 80 00 00                                  	mov    esi,0x8001
  7dfdde:	b9 ff ff ff 03                                  	mov    ecx,0x3ffffff
  7dfde3:	44 89 ef                                        	mov    edi,r13d
  7dfde6:	e8 25 ee e2 ff                                  	call   0x60ec10
  7dfdeb:	4c 8d 3d 1e c5 13 03                            	lea    r15,[rip+0x313c51e]        # 0x391c310
  7dfdf2:	85 c0                                           	test   eax,eax
  7dfdf4:	0f 84 7a 01 00 00                               	je     0x7dff74
  7dfdfa:	4d 89 e2                                        	mov    r10,r12
  7dfdfd:	44 89 ea                                        	mov    edx,r13d
  7dfe00:	89 c3                                           	mov    ebx,eax
  7dfe02:	48 c7 45 88 00 00 00 00                         	mov    QWORD PTR [rbp-0x78],0x0
  7dfe0a:	45 31 ed                                        	xor    r13d,r13d
  7dfe0d:	41 83 ca 02                                     	or     r10d,0x2
  7dfe11:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  7dfe1a:	44 8d a3 00 00 02 80                            	lea    r12d,[rbx-0x7ffe0000]
  7dfe21:	48 83 ec 08                                     	sub    rsp,0x8
  7dfe25:	48 8d 45 b0                                     	lea    rax,[rbp-0x50]
  7dfe29:	41 89 d6                                        	mov    r14d,edx
  7dfe2c:	4c 8b 85 78 ff ff ff                            	mov    r8,QWORD PTR [rbp-0x88]
  7dfe33:	be 17 47 00 00                                  	mov    esi,0x4717
  7dfe38:	b9 ff ff ff ff                                  	mov    ecx,0xffffffff
  7dfe3d:	45 89 e1                                        	mov    r9d,r12d
  7dfe40:	50                                              	push   rax
  7dfe41:	41 55                                           	push   r13
  7dfe43:	4c 89 55 90                                     	mov    QWORD PTR [rbp-0x70],r10
  7dfe47:	41 52                                           	push   r10
  7dfe49:	e8 22 fb 41 00                                  	call   0xbff970
  7dfe4e:	48 83 c4 20                                     	add    rsp,0x20
  7dfe52:	e8 79 7a 32 00                                  	call   0xb078d0
  7dfe57:	85 c0                                           	test   eax,eax
  7dfe59:	0f 84 8d 00 00 00                               	je     0x7dfeec
  7dfe5f:	83 3d 9a 01 4d 02 00                            	cmp    DWORD PTR [rip+0x24d019a],0x0        # 0x2cb0000
  7dfe66:	0f 84 80 00 00 00                               	je     0x7dfeec
  7dfe6c:	4c 8b 3d ad 6a 41 03                            	mov    r15,QWORD PTR [rip+0x3416aad]        # 0x3bf6920
  7dfe73:	48 8d 05 6e 95 a8 ff                            	lea    rax,[rip+0xffffffffffa8956e]        # 0x2693e8
  7dfe7a:	4c 29 f8                                        	sub    rax,r15
  7dfe7d:	48 c1 c8 03                                     	ror    rax,0x3
  7dfe81:	48 83 f8 01                                     	cmp    rax,0x1
  7dfe85:	0f 87 9a 01 00 00                               	ja     0x7e0025
  7dfe8b:	0f b7 85 78 ff ff ff                            	movzx  eax,WORD PTR [rbp-0x88]
  7dfe92:	44 89 f2                                        	mov    edx,r14d
  7dfe95:	48 8b 4d b0                                     	mov    rcx,QWORD PTR [rbp-0x50]
  7dfe99:	4c 8b 45 b8                                     	mov    r8,QWORD PTR [rbp-0x48]
  7dfe9d:	4c 8b 4d c0                                     	mov    r9,QWORD PTR [rbp-0x40]
  7dfea1:	41 bb 20 03 02 a0                               	mov    r11d,0xa0020320
  7dfea7:	45 89 e2                                        	mov    r10d,r12d
  7dfeaa:	bf 08 00 00 00                                  	mov    edi,0x8
  7dfeaf:	be 02 00 00 00                                  	mov    esi,0x2
  7dfeb4:	49 81 c3 e0 fc fc 5f                            	add    r11,0x5ffcfce0
  7dfebb:	48 c1 e0 20                                     	shl    rax,0x20
  7dfebf:	48 09 c2                                        	or     rdx,rax
  7dfec2:	48 8b 45 90                                     	mov    rax,QWORD PTR [rbp-0x70]
  7dfec6:	49 09 d3                                        	or     r11,rdx
  7dfec9:	ba 17 47 00 00                                  	mov    edx,0x4717
  7dfece:	48 c1 e0 20                                     	shl    rax,0x20
  7dfed2:	49 09 c2                                        	or     r10,rax
  7dfed5:	41 55                                           	push   r13
  7dfed7:	41 52                                           	push   r10
  7dfed9:	41 53                                           	push   r11
  7dfedb:	ff 75 c8                                        	push   QWORD PTR [rbp-0x38]
  7dfede:	41 ff d7                                        	call   r15
  7dfee1:	48 83 c4 20                                     	add    rsp,0x20
  7dfee5:	4c 8d 3d 24 c4 13 03                            	lea    r15,[rip+0x313c424]        # 0x391c310
  7dfeec:	80 7d 80 00                                     	cmp    BYTE PTR [rbp-0x80],0x0
  7dfef0:	75 64                                           	jne    0x7dff56
  7dfef2:	65 4c 8b 34 25 00 00 00 00                      	mov    r14,QWORD PTR gs:0x0
  7dfefb:	49 8b 46 08                                     	mov    rax,QWORD PTR [r14+0x8]
  7dfeff:	81 b8 d4 05 00 00 00 00 50 03                   	cmp    DWORD PTR [rax+0x5d4],0x3500000
  7dff09:	72 4b                                           	jb     0x7dff56
  7dff0b:	48 8d 3d 26 9b aa 00                            	lea    rdi,[rip+0xaa9b26]        # 0x1289a38
  7dff12:	be c2 00 00 00                                  	mov    esi,0xc2
  7dff17:	31 c0                                           	xor    eax,eax
  7dff19:	e8 f2 d4 a7 ff                                  	call   0x25d410
  7dff1e:	4c 8b 65 88                                     	mov    r12,QWORD PTR [rbp-0x78]
  7dff22:	41 8b b6 9c 00 00 00                            	mov    esi,DWORD PTR [r14+0x9c]
  7dff29:	4c 89 f2                                        	mov    rdx,r14
  7dff2c:	48 8d 3d 74 c7 a8 00                            	lea    rdi,[rip+0xa8c774]        # 0x126c6a7
  7dff33:	4d 89 e9                                        	mov    r9,r13
  7dff36:	4c 8b 45 90                                     	mov    r8,QWORD PTR [rbp-0x70]
  7dff3a:	31 c0                                           	xor    eax,eax
  7dff3c:	48 81 c2 94 02 00 00                            	add    rdx,0x294
  7dff43:	4c 89 e1                                        	mov    rcx,r12
  7dff46:	e8 c5 d4 a7 ff                                  	call   0x25d410
  7dff4b:	4c 89 f7                                        	mov    rdi,r14
  7dff4e:	4c 89 e6                                        	mov    rsi,r12
  7dff51:	e8 ca fa 4b 00                                  	call   0xc9fa20
  7dff56:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  7dff59:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  7dff5d:	0f 85 bb 00 00 00                               	jne    0x7e001e
  7dff63:	89 d8                                           	mov    eax,ebx
  7dff65:	48 83 c4 68                                     	add    rsp,0x68
  7dff69:	5b                                              	pop    rbx
  7dff6a:	41 5c                                           	pop    r12
  7dff6c:	41 5d                                           	pop    r13
  7dff6e:	41 5e                                           	pop    r14
  7dff70:	41 5f                                           	pop    r15
  7dff72:	5d                                              	pop    rbp
  7dff73:	c3                                              	ret
  7dff74:	48 8b 7d a0                                     	mov    rdi,QWORD PTR [rbp-0x60]
  7dff78:	31 db                                           	xor    ebx,ebx
  7dff7a:	31 f6                                           	xor    esi,esi
  7dff7c:	31 d2                                           	xor    edx,edx
  7dff7e:	31 c9                                           	xor    ecx,ecx
  7dff80:	48 83 c7 28                                     	add    rdi,0x28
  7dff84:	e8 97 bb 46 00                                  	call   0xc4bb20
  7dff89:	48 8b 7d a0                                     	mov    rdi,QWORD PTR [rbp-0x60]
  7dff8d:	31 f6                                           	xor    esi,esi
  7dff8f:	31 d2                                           	xor    edx,edx
  7dff91:	48 8b 47 48                                     	mov    rax,QWORD PTR [rdi+0x48]
  7dff95:	48 83 c7 28                                     	add    rdi,0x28
  7dff99:	48 89 45 98                                     	mov    QWORD PTR [rbp-0x68],rax
  7dff9d:	e8 0e c5 46 00                                  	call   0xc4c4b0
  7dffa2:	44 89 ef                                        	mov    edi,r13d
  7dffa5:	be 01 80 00 00                                  	mov    esi,0x8001
  7dffaa:	31 d2                                           	xor    edx,edx
  7dffac:	e8 1f ed e2 ff                                  	call   0x60ecd0
  7dffb1:	4d 8b 3e                                        	mov    r15,QWORD PTR [r14]
  7dffb4:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  7dffbd:	48 8d 35 d3 f2 b6 00                            	lea    rsi,[rip+0xb6f2d3]        # 0x134f297
  7dffc4:	31 d2                                           	xor    edx,edx
  7dffc6:	e8 15 a4 43 00                                  	call   0xc1a3e0
  7dffcb:	48 8d 7d 98                                     	lea    rdi,[rbp-0x68]
  7dffcf:	ba 08 00 00 00                                  	mov    edx,0x8
  7dffd4:	4c 89 fe                                        	mov    rsi,r15
  7dffd7:	e8 f4 91 a7 ff                                  	call   0x2591d0
  7dffdc:	85 c0                                           	test   eax,eax
  7dffde:	74 28                                           	je     0x7e0008
  7dffe0:	4d 8b 2e                                        	mov    r13,QWORD PTR [r14]
  7dffe3:	4c 8d 3d 26 c3 13 03                            	lea    r15,[rip+0x313c326]        # 0x391c310
  7dffea:	89 c3                                           	mov    ebx,eax
  7dffec:	41 ba 03 00 65 04                               	mov    r10d,0x4650003
  7dfff2:	b8 20 03 02 a0                                  	mov    eax,0xa0020320
  7dfff7:	48 c7 45 80 00 00 00 00                         	mov    QWORD PTR [rbp-0x80],0x0
  7dffff:	48 89 45 88                                     	mov    QWORD PTR [rbp-0x78],rax
  7e0003:	e9 c4 fd ff ff                                  	jmp    0x7dfdcc
  7e0008:	48 8b 45 88                                     	mov    rax,QWORD PTR [rbp-0x78]
  7e000c:	4c 8d 3d fd c2 13 03                            	lea    r15,[rip+0x313c2fd]        # 0x391c310
  7e0013:	c7 00 00 00 00 00                               	mov    DWORD PTR [rax],0x0
  7e0019:	e9 38 ff ff ff                                  	jmp    0x7dff56
  7e001e:	e8 8d d6 f1 ff                                  	call   0x6fd6b0
  7e0023:	0f 0b                                           	ud2
  7e0025:	48 8d 3d 44 dc d5 01                            	lea    rdi,[rip+0x1d5dc44]        # 0x253dc70
  7e002c:	4c 89 fe                                        	mov    rsi,r15
  7e002f:	e8 8c f8 c6 ff                                  	call   0x44f8c0
  7e0034:	e9 52 fe ff ff                                  	jmp    0x7dfe8b
  7e0039:	90                                              	nop
  7e003a:	90                                              	nop
  7e003b:	90                                              	nop
  7e003c:	90                                              	nop
  7e003d:	90                                              	nop
  7e003e:	90                                              	nop
  7e003f:	90                                              	nop
  7e0040:	55                                              	push   rbp
  7e0041:	48 89 e5                                        	mov    rbp,rsp
  7e0044:	41 57                                           	push   r15
  7e0046:	41 56                                           	push   r14
  7e0048:	41 55                                           	push   r13
  7e004a:	41 54                                           	push   r12
  7e004c:	53                                              	push   rbx
  7e004d:	48 83 ec 58                                     	sub    rsp,0x58
  7e0051:	48 8d 05 b8 c2 13 03                            	lea    rax,[rip+0x313c2b8]        # 0x391c310
  7e0058:	49 89 d5                                        	mov    r13,rdx
  7e005b:	49 89 f4                                        	mov    r12,rsi
  7e005e:	48 8d 55 a8                                     	lea    rdx,[rbp-0x58]
  7e0062:	be 01 80 00 00                                  	mov    esi,0x8001
  7e0067:	b9 ff ff ff 03                                  	mov    ecx,0x3ffffff
  7e006c:	41 89 ff                                        	mov    r15d,edi
  7e006f:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  7e0072:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  7e0076:	48 c7 45 a8 00 00 00 00                         	mov    QWORD PTR [rbp-0x58],0x0
  7e007e:	c6 45 b0 00                                     	mov    BYTE PTR [rbp-0x50],0x0
  7e0082:	e8 89 eb e2 ff                                  	call   0x60ec10
  7e0087:	41 89 c6                                        	mov    r14d,eax
  7e008a:	85 c0                                           	test   eax,eax
  7e008c:	74 19                                           	je     0x7e00a7
  7e008e:	41 bc 00 00 66 04                               	mov    r12d,0x4660000
  7e0094:	45 31 d2                                        	xor    r10d,r10d
  7e0097:	48 c7 45 98 00 00 00 00                         	mov    QWORD PTR [rbp-0x68],0x0
  7e009f:	45 89 f5                                        	mov    r13d,r14d
  7e00a2:	e9 9e 00 00 00                                  	jmp    0x7e0145
  7e00a7:	48 8b 45 a8                                     	mov    rax,QWORD PTR [rbp-0x58]
  7e00ab:	48 8d 7d b0                                     	lea    rdi,[rbp-0x50]
  7e00af:	ba 20 00 00 00                                  	mov    edx,0x20
  7e00b4:	48 8b 70 18                                     	mov    rsi,QWORD PTR [rax+0x18]
  7e00b8:	e8 b3 7a 17 00                                  	call   0x957b70
  7e00bd:	48 8b 7d a8                                     	mov    rdi,QWORD PTR [rbp-0x58]
  7e00c1:	31 f6                                           	xor    esi,esi
  7e00c3:	31 d2                                           	xor    edx,edx
  7e00c5:	31 c9                                           	xor    ecx,ecx
  7e00c7:	48 83 c7 28                                     	add    rdi,0x28
  7e00cb:	e8 50 ba 46 00                                  	call   0xc4bb20
  7e00d0:	48 8b 7d a8                                     	mov    rdi,QWORD PTR [rbp-0x58]
  7e00d4:	31 f6                                           	xor    esi,esi
  7e00d6:	31 d2                                           	xor    edx,edx
  7e00d8:	48 8b 87 90 00 00 00                            	mov    rax,QWORD PTR [rdi+0x90]
  7e00df:	48 83 c7 28                                     	add    rdi,0x28
  7e00e3:	48 89 45 a0                                     	mov    QWORD PTR [rbp-0x60],rax
  7e00e7:	e8 c4 c3 46 00                                  	call   0xc4c4b0
  7e00ec:	44 89 ff                                        	mov    edi,r15d
  7e00ef:	be 01 80 00 00                                  	mov    esi,0x8001
  7e00f4:	31 d2                                           	xor    edx,edx
  7e00f6:	e8 d5 eb e2 ff                                  	call   0x60ecd0
  7e00fb:	49 8b 1c 24                                     	mov    rbx,QWORD PTR [r12]
  7e00ff:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  7e0108:	48 8d 35 88 f1 b6 00                            	lea    rsi,[rip+0xb6f188]        # 0x134f297
  7e010f:	31 d2                                           	xor    edx,edx
  7e0111:	e8 ca a2 43 00                                  	call   0xc1a3e0
  7e0116:	48 8d 7d a0                                     	lea    rdi,[rbp-0x60]
  7e011a:	ba 08 00 00 00                                  	mov    edx,0x8
  7e011f:	48 89 de                                        	mov    rsi,rbx
  7e0122:	e8 a9 90 a7 ff                                  	call   0x2591d0
  7e0127:	85 c0                                           	test   eax,eax
  7e0129:	0f 84 42 01 00 00                               	je     0x7e0271
  7e012f:	4d 8b 14 24                                     	mov    r10,QWORD PTR [r12]
  7e0133:	b9 20 03 02 a0                                  	mov    ecx,0xa0020320
  7e0138:	41 bc 01 00 66 04                               	mov    r12d,0x4660001
  7e013e:	41 89 c5                                        	mov    r13d,eax
  7e0141:	48 89 4d 98                                     	mov    QWORD PTR [rbp-0x68],rcx
  7e0145:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  7e014e:	41 8d 9d 00 00 02 80                            	lea    ebx,[r13-0x7ffe0000]
  7e0155:	48 83 ec 08                                     	sub    rsp,0x8
  7e0159:	48 8d 45 b0                                     	lea    rax,[rbp-0x50]
  7e015d:	be 18 17 00 00                                  	mov    esi,0x1718
  7e0162:	44 89 fa                                        	mov    edx,r15d
  7e0165:	b9 ff ff ff ff                                  	mov    ecx,0xffffffff
  7e016a:	41 b8 ff ff ff ff                               	mov    r8d,0xffffffff
  7e0170:	41 89 d9                                        	mov    r9d,ebx
  7e0173:	50                                              	push   rax
  7e0174:	4c 89 55 90                                     	mov    QWORD PTR [rbp-0x70],r10
  7e0178:	41 52                                           	push   r10
  7e017a:	41 54                                           	push   r12
  7e017c:	e8 ef f7 41 00                                  	call   0xbff970
  7e0181:	48 83 c4 20                                     	add    rsp,0x20
  7e0185:	e8 46 77 32 00                                  	call   0xb078d0
  7e018a:	85 c0                                           	test   eax,eax
  7e018c:	74 79                                           	je     0x7e0207
  7e018e:	83 3d 6b fe 4c 02 00                            	cmp    DWORD PTR [rip+0x24cfe6b],0x0        # 0x2cb0000
  7e0195:	74 70                                           	je     0x7e0207
  7e0197:	4c 89 6d 88                                     	mov    QWORD PTR [rbp-0x78],r13
  7e019b:	4c 8b 2d 7e 67 41 03                            	mov    r13,QWORD PTR [rip+0x341677e]        # 0x3bf6920
  7e01a2:	48 8d 05 3f 92 a8 ff                            	lea    rax,[rip+0xffffffffffa8923f]        # 0x2693e8
  7e01a9:	4c 29 e8                                        	sub    rax,r13
  7e01ac:	48 c1 c8 03                                     	ror    rax,0x3
  7e01b0:	48 83 f8 01                                     	cmp    rax,0x1
  7e01b4:	0f 87 eb 00 00 00                               	ja     0x7e02a5
  7e01ba:	48 8b 4d b0                                     	mov    rcx,QWORD PTR [rbp-0x50]
  7e01be:	4c 8b 45 b8                                     	mov    r8,QWORD PTR [rbp-0x48]
  7e01c2:	4c 8b 4d c0                                     	mov    r9,QWORD PTR [rbp-0x40]
  7e01c6:	44 89 f8                                        	mov    eax,r15d
  7e01c9:	49 ba 00 00 ff ff ff ff 00 00                   	movabs r10,0xffffffff0000
  7e01d3:	41 89 db                                        	mov    r11d,ebx
  7e01d6:	ba 18 17 00 00                                  	mov    edx,0x1718
  7e01db:	bf 08 00 00 00                                  	mov    edi,0x8
  7e01e0:	be 02 00 00 00                                  	mov    esi,0x2
  7e01e5:	49 09 c2                                        	or     r10,rax
  7e01e8:	4c 89 e0                                        	mov    rax,r12
  7e01eb:	48 c1 e0 20                                     	shl    rax,0x20
  7e01ef:	49 09 c3                                        	or     r11,rax
  7e01f2:	ff 75 90                                        	push   QWORD PTR [rbp-0x70]
  7e01f5:	41 53                                           	push   r11
  7e01f7:	41 52                                           	push   r10
  7e01f9:	ff 75 c8                                        	push   QWORD PTR [rbp-0x38]
  7e01fc:	41 ff d5                                        	call   r13
  7e01ff:	48 83 c4 20                                     	add    rsp,0x20
  7e0203:	4c 8b 6d 88                                     	mov    r13,QWORD PTR [rbp-0x78]
  7e0207:	45 85 f6                                        	test   r14d,r14d
  7e020a:	75 70                                           	jne    0x7e027c
  7e020c:	65 48 8b 1c 25 00 00 00 00                      	mov    rbx,QWORD PTR gs:0x0
  7e0215:	48 8b 43 08                                     	mov    rax,QWORD PTR [rbx+0x8]
  7e0219:	81 b8 d4 05 00 00 00 00 50 03                   	cmp    DWORD PTR [rax+0x5d4],0x3500000
  7e0223:	72 57                                           	jb     0x7e027c
  7e0225:	48 8d 3d 0c 98 aa 00                            	lea    rdi,[rip+0xaa980c]        # 0x1289a38
  7e022c:	be c2 00 00 00                                  	mov    esi,0xc2
  7e0231:	31 c0                                           	xor    eax,eax
  7e0233:	e8 d8 d1 a7 ff                                  	call   0x25d410
  7e0238:	4c 8b 75 98                                     	mov    r14,QWORD PTR [rbp-0x68]
  7e023c:	8b b3 9c 00 00 00                               	mov    esi,DWORD PTR [rbx+0x9c]
  7e0242:	4c 8b 4d 90                                     	mov    r9,QWORD PTR [rbp-0x70]
  7e0246:	48 89 da                                        	mov    rdx,rbx
  7e0249:	48 8d 3d 57 c4 a8 00                            	lea    rdi,[rip+0xa8c457]        # 0x126c6a7
  7e0250:	45 89 e0                                        	mov    r8d,r12d
  7e0253:	31 c0                                           	xor    eax,eax
  7e0255:	48 81 c2 94 02 00 00                            	add    rdx,0x294
  7e025c:	4c 89 f1                                        	mov    rcx,r14
  7e025f:	e8 ac d1 a7 ff                                  	call   0x25d410
  7e0264:	48 89 df                                        	mov    rdi,rbx
  7e0267:	4c 89 f6                                        	mov    rsi,r14
  7e026a:	e8 b1 f7 4b 00                                  	call   0xc9fa20
  7e026f:	eb 0b                                           	jmp    0x7e027c
  7e0271:	41 c7 45 00 00 00 00 00                         	mov    DWORD PTR [r13+0x0],0x0
  7e0279:	45 31 ed                                        	xor    r13d,r13d
  7e027c:	48 8d 05 8d c0 13 03                            	lea    rax,[rip+0x313c08d]        # 0x391c310
  7e0283:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  7e0286:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  7e028a:	75 12                                           	jne    0x7e029e
  7e028c:	44 89 e8                                        	mov    eax,r13d
  7e028f:	48 83 c4 58                                     	add    rsp,0x58
  7e0293:	5b                                              	pop    rbx
  7e0294:	41 5c                                           	pop    r12
  7e0296:	41 5d                                           	pop    r13
  7e0298:	41 5e                                           	pop    r14
  7e029a:	41 5f                                           	pop    r15
  7e029c:	5d                                              	pop    rbp
  7e029d:	c3                                              	ret
  7e029e:	e8 0d d4 f1 ff                                  	call   0x6fd6b0
  7e02a3:	0f 0b                                           	ud2
  7e02a5:	48 8d 3d e4 d9 d5 01                            	lea    rdi,[rip+0x1d5d9e4]        # 0x253dc90
  7e02ac:	4c 89 ee                                        	mov    rsi,r13
  7e02af:	e8 0c f6 c6 ff                                  	call   0x44f8c0
  7e02b4:	e9 01 ff ff ff                                  	jmp    0x7e01ba
  7e02b9:	90                                              	nop
  7e02ba:	90                                              	nop
  7e02bb:	90                                              	nop
  7e02bc:	90                                              	nop
  7e02bd:	90                                              	nop
  7e02be:	90                                              	nop
  7e02bf:	90                                              	nop
  7e02c0:	55                                              	push   rbp
  7e02c1:	48 89 e5                                        	mov    rbp,rsp
  7e02c4:	41 57                                           	push   r15
  7e02c6:	41 56                                           	push   r14
  7e02c8:	41 55                                           	push   r13
  7e02ca:	41 54                                           	push   r12
  7e02cc:	53                                              	push   rbx
  7e02cd:	48 83 ec 58                                     	sub    rsp,0x58
  7e02d1:	4c 8d 3d 38 c0 13 03                            	lea    r15,[rip+0x313c038]        # 0x391c310
  7e02d8:	49 89 d4                                        	mov    r12,rdx
  7e02db:	49 89 f5                                        	mov    r13,rsi
  7e02de:	48 8d 55 a8                                     	lea    rdx,[rbp-0x58]
  7e02e2:	be 04 80 00 00                                  	mov    esi,0x8004
  7e02e7:	b9 ff ff ff 03                                  	mov    ecx,0x3ffffff
  7e02ec:	41 89 fe                                        	mov    r14d,edi
  7e02ef:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  7e02f2:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  7e02f6:	48 c7 45 a8 00 00 00 00                         	mov    QWORD PTR [rbp-0x58],0x0
  7e02fe:	48 c7 45 a0 00 00 00 00                         	mov    QWORD PTR [rbp-0x60],0x0
  7e0306:	c6 45 b0 00                                     	mov    BYTE PTR [rbp-0x50],0x0
  7e030a:	e8 01 e9 e2 ff                                  	call   0x60ec10
  7e030f:	89 c3                                           	mov    ebx,eax
  7e0311:	b0 01                                           	mov    al,0x1
  7e0313:	89 45 94                                        	mov    DWORD PTR [rbp-0x6c],eax
  7e0316:	85 db                                           	test   ebx,ebx
  7e0318:	74 16                                           	je     0x7e0330
  7e031a:	41 ba 00 00 67 04                               	mov    r10d,0x4670000
  7e0320:	48 c7 45 88 00 00 00 00                         	mov    QWORD PTR [rbp-0x78],0x0
  7e0328:	45 31 e4                                        	xor    r12d,r12d
  7e032b:	e9 fb 00 00 00                                  	jmp    0x7e042b
  7e0330:	48 8b 45 a8                                     	mov    rax,QWORD PTR [rbp-0x58]
  7e0334:	48 8d 7d b0                                     	lea    rdi,[rbp-0x50]
  7e0338:	ba 20 00 00 00                                  	mov    edx,0x20
  7e033d:	4c 89 65 80                                     	mov    QWORD PTR [rbp-0x80],r12
  7e0341:	48 8b 70 18                                     	mov    rsi,QWORD PTR [rax+0x18]
  7e0345:	e8 26 78 17 00                                  	call   0x957b70
  7e034a:	48 8b 45 a8                                     	mov    rax,QWORD PTR [rbp-0x58]
  7e034e:	31 db                                           	xor    ebx,ebx
  7e0350:	31 f6                                           	xor    esi,esi
  7e0352:	31 d2                                           	xor    edx,edx
  7e0354:	31 c9                                           	xor    ecx,ecx
  7e0356:	48 8b 78 28                                     	mov    rdi,QWORD PTR [rax+0x28]
  7e035a:	e8 c1 b7 46 00                                  	call   0xc4bb20
  7e035f:	48 8b 45 a8                                     	mov    rax,QWORD PTR [rbp-0x58]
  7e0363:	48 8b 78 28                                     	mov    rdi,QWORD PTR [rax+0x28]
  7e0367:	44 8b 7f 20                                     	mov    r15d,DWORD PTR [rdi+0x20]
  7e036b:	41 f7 c7 00 00 00 20                            	test   r15d,0x20000000
  7e0372:	75 15                                           	jne    0x7e0389
  7e0374:	48 8b 87 b0 01 00 00                            	mov    rax,QWORD PTR [rdi+0x1b0]
  7e037b:	45 31 e4                                        	xor    r12d,r12d
  7e037e:	48 89 45 a0                                     	mov    QWORD PTR [rbp-0x60],rax
  7e0382:	b8 00 00 67 04                                  	mov    eax,0x4670000
  7e0387:	eb 0d                                           	jmp    0x7e0396
  7e0389:	b8 01 00 67 04                                  	mov    eax,0x4670001
  7e038e:	bb 02 00 00 00                                  	mov    ebx,0x2
  7e0393:	4d 89 fc                                        	mov    r12,r15
  7e0396:	48 89 45 98                                     	mov    QWORD PTR [rbp-0x68],rax
  7e039a:	48 c7 45 88 00 00 00 00                         	mov    QWORD PTR [rbp-0x78],0x0
  7e03a2:	31 f6                                           	xor    esi,esi
  7e03a4:	31 d2                                           	xor    edx,edx
  7e03a6:	e8 05 c1 46 00                                  	call   0xc4c4b0
  7e03ab:	44 89 f7                                        	mov    edi,r14d
  7e03ae:	be 04 80 00 00                                  	mov    esi,0x8004
  7e03b3:	31 d2                                           	xor    edx,edx
  7e03b5:	e8 16 e9 e2 ff                                  	call   0x60ecd0
  7e03ba:	41 f7 c7 00 00 00 20                            	test   r15d,0x20000000
  7e03c1:	75 5d                                           	jne    0x7e0420
  7e03c3:	4d 8b 7d 00                                     	mov    r15,QWORD PTR [r13+0x0]
  7e03c7:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  7e03d0:	48 8d 35 c0 ee b6 00                            	lea    rsi,[rip+0xb6eec0]        # 0x134f297
  7e03d7:	31 d2                                           	xor    edx,edx
  7e03d9:	31 db                                           	xor    ebx,ebx
  7e03db:	e8 00 a0 43 00                                  	call   0xc1a3e0
  7e03e0:	48 8d 7d a0                                     	lea    rdi,[rbp-0x60]
  7e03e4:	ba 08 00 00 00                                  	mov    edx,0x8
  7e03e9:	4c 89 fe                                        	mov    rsi,r15
  7e03ec:	e8 df 8d a7 ff                                  	call   0x2591d0
  7e03f1:	85 c0                                           	test   eax,eax
  7e03f3:	0f 84 5f 01 00 00                               	je     0x7e0558
  7e03f9:	4c 8b 55 98                                     	mov    r10,QWORD PTR [rbp-0x68]
  7e03fd:	4d 8b 65 00                                     	mov    r12,QWORD PTR [r13+0x0]
  7e0401:	4c 8d 3d 08 bf 13 03                            	lea    r15,[rip+0x313bf08]        # 0x391c310
  7e0408:	b9 20 03 02 a0                                  	mov    ecx,0xa0020320
  7e040d:	89 c3                                           	mov    ebx,eax
  7e040f:	c7 45 94 00 00 00 00                            	mov    DWORD PTR [rbp-0x6c],0x0
  7e0416:	48 89 4d 88                                     	mov    QWORD PTR [rbp-0x78],rcx
  7e041a:	41 83 ca 02                                     	or     r10d,0x2
  7e041e:	eb 0b                                           	jmp    0x7e042b
  7e0420:	4c 8d 3d e9 be 13 03                            	lea    r15,[rip+0x313bee9]        # 0x391c310
  7e0427:	4c 8b 55 98                                     	mov    r10,QWORD PTR [rbp-0x68]
  7e042b:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  7e0434:	44 8d ab 00 00 02 80                            	lea    r13d,[rbx-0x7ffe0000]
  7e043b:	48 83 ec 08                                     	sub    rsp,0x8
  7e043f:	48 8d 45 b0                                     	lea    rax,[rbp-0x50]
  7e0443:	be 1b 27 00 00                                  	mov    esi,0x271b
  7e0448:	ba ff ff ff ff                                  	mov    edx,0xffffffff
  7e044d:	44 89 f1                                        	mov    ecx,r14d
  7e0450:	41 b8 ff ff ff ff                               	mov    r8d,0xffffffff
  7e0456:	45 89 e9                                        	mov    r9d,r13d
  7e0459:	50                                              	push   rax
  7e045a:	41 54                                           	push   r12
  7e045c:	4c 89 55 98                                     	mov    QWORD PTR [rbp-0x68],r10
  7e0460:	41 52                                           	push   r10
  7e0462:	e8 09 f5 41 00                                  	call   0xbff970
  7e0467:	48 83 c4 20                                     	add    rsp,0x20
  7e046b:	e8 60 74 32 00                                  	call   0xb078d0
  7e0470:	85 c0                                           	test   eax,eax
  7e0472:	74 78                                           	je     0x7e04ec
  7e0474:	83 3d 85 fb 4c 02 00                            	cmp    DWORD PTR [rip+0x24cfb85],0x0        # 0x2cb0000
  7e047b:	74 6f                                           	je     0x7e04ec
  7e047d:	4c 8b 3d 9c 64 41 03                            	mov    r15,QWORD PTR [rip+0x341649c]        # 0x3bf6920
  7e0484:	48 8d 05 5d 8f a8 ff                            	lea    rax,[rip+0xffffffffffa88f5d]        # 0x2693e8
  7e048b:	4c 29 f8                                        	sub    rax,r15
  7e048e:	48 c1 c8 03                                     	ror    rax,0x3
  7e0492:	48 83 f8 01                                     	cmp    rax,0x1
  7e0496:	0f 87 ee 00 00 00                               	ja     0x7e058a
  7e049c:	48 8b 55 98                                     	mov    rdx,QWORD PTR [rbp-0x68]
  7e04a0:	48 8b 4d b0                                     	mov    rcx,QWORD PTR [rbp-0x50]
  7e04a4:	4c 8b 45 b8                                     	mov    r8,QWORD PTR [rbp-0x48]
  7e04a8:	4c 8b 4d c0                                     	mov    r9,QWORD PTR [rbp-0x40]
  7e04ac:	41 c1 e6 10                                     	shl    r14d,0x10
  7e04b0:	48 b8 ff ff 00 00 ff ff 00 00                   	movabs rax,0xffff0000ffff
  7e04ba:	45 89 ea                                        	mov    r10d,r13d
  7e04bd:	bf 08 00 00 00                                  	mov    edi,0x8
  7e04c2:	be 02 00 00 00                                  	mov    esi,0x2
  7e04c7:	4c 09 f0                                        	or     rax,r14
  7e04ca:	48 c1 e2 20                                     	shl    rdx,0x20
  7e04ce:	49 09 d2                                        	or     r10,rdx
  7e04d1:	ba 1b 27 00 00                                  	mov    edx,0x271b
  7e04d6:	41 54                                           	push   r12
  7e04d8:	41 52                                           	push   r10
  7e04da:	50                                              	push   rax
  7e04db:	ff 75 c8                                        	push   QWORD PTR [rbp-0x38]
  7e04de:	41 ff d7                                        	call   r15
  7e04e1:	48 83 c4 20                                     	add    rsp,0x20
  7e04e5:	4c 8d 3d 24 be 13 03                            	lea    r15,[rip+0x313be24]        # 0x391c310
  7e04ec:	80 7d 94 00                                     	cmp    BYTE PTR [rbp-0x6c],0x0
  7e04f0:	75 77                                           	jne    0x7e0569
  7e04f2:	65 4c 8b 34 25 00 00 00 00                      	mov    r14,QWORD PTR gs:0x0
  7e04fb:	49 8b 46 08                                     	mov    rax,QWORD PTR [r14+0x8]
  7e04ff:	81 b8 d4 05 00 00 00 00 50 03                   	cmp    DWORD PTR [rax+0x5d4],0x3500000
  7e0509:	72 5e                                           	jb     0x7e0569
  7e050b:	48 8d 3d 26 95 aa 00                            	lea    rdi,[rip+0xaa9526]        # 0x1289a38
  7e0512:	be c2 00 00 00                                  	mov    esi,0xc2
  7e0517:	31 c0                                           	xor    eax,eax
  7e0519:	e8 f2 ce a7 ff                                  	call   0x25d410
  7e051e:	4c 8b 6d 88                                     	mov    r13,QWORD PTR [rbp-0x78]
  7e0522:	41 8b b6 9c 00 00 00                            	mov    esi,DWORD PTR [r14+0x9c]
  7e0529:	4c 89 f2                                        	mov    rdx,r14
  7e052c:	48 8d 3d 74 c1 a8 00                            	lea    rdi,[rip+0xa8c174]        # 0x126c6a7
  7e0533:	4d 89 e1                                        	mov    r9,r12
  7e0536:	4c 8b 45 98                                     	mov    r8,QWORD PTR [rbp-0x68]
  7e053a:	31 c0                                           	xor    eax,eax
  7e053c:	48 81 c2 94 02 00 00                            	add    rdx,0x294
  7e0543:	4c 89 e9                                        	mov    rcx,r13
  7e0546:	e8 c5 ce a7 ff                                  	call   0x25d410
  7e054b:	4c 89 f7                                        	mov    rdi,r14
  7e054e:	4c 89 ee                                        	mov    rsi,r13
  7e0551:	e8 ca f4 4b 00                                  	call   0xc9fa20
  7e0556:	eb 11                                           	jmp    0x7e0569
  7e0558:	48 8b 45 80                                     	mov    rax,QWORD PTR [rbp-0x80]
  7e055c:	4c 8d 3d ad bd 13 03                            	lea    r15,[rip+0x313bdad]        # 0x391c310
  7e0563:	c7 00 00 00 00 00                               	mov    DWORD PTR [rax],0x0
  7e0569:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  7e056c:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  7e0570:	75 11                                           	jne    0x7e0583
  7e0572:	89 d8                                           	mov    eax,ebx
  7e0574:	48 83 c4 58                                     	add    rsp,0x58
  7e0578:	5b                                              	pop    rbx
  7e0579:	41 5c                                           	pop    r12
  7e057b:	41 5d                                           	pop    r13
  7e057d:	41 5e                                           	pop    r14
  7e057f:	41 5f                                           	pop    r15
  7e0581:	5d                                              	pop    rbp
  7e0582:	c3                                              	ret
  7e0583:	e8 28 d1 f1 ff                                  	call   0x6fd6b0
  7e0588:	0f 0b                                           	ud2
  7e058a:	48 8d 3d 1f d7 d5 01                            	lea    rdi,[rip+0x1d5d71f]        # 0x253dcb0
  7e0591:	4c 89 fe                                        	mov    rsi,r15
  7e0594:	e8 27 f3 c6 ff                                  	call   0x44f8c0
  7e0599:	e9 fe fe ff ff                                  	jmp    0x7e049c
  7e059e:	90                                              	nop
  7e059f:	90                                              	nop
  7e05a0:	55                                              	push   rbp
  7e05a1:	48 89 e5                                        	mov    rbp,rsp
  7e05a4:	41 57                                           	push   r15
  7e05a6:	41 56                                           	push   r14
  7e05a8:	41 55                                           	push   r13
  7e05aa:	41 54                                           	push   r12
  7e05ac:	53                                              	push   rbx
  7e05ad:	48 83 ec 58                                     	sub    rsp,0x58
  7e05b1:	4c 8d 3d 58 bd 13 03                            	lea    r15,[rip+0x313bd58]        # 0x391c310
  7e05b8:	49 89 d5                                        	mov    r13,rdx
  7e05bb:	49 89 f4                                        	mov    r12,rsi
  7e05be:	48 8d 55 a8                                     	lea    rdx,[rbp-0x58]
  7e05c2:	be 02 80 00 00                                  	mov    esi,0x8002
  7e05c7:	b9 ff ff ff 03                                  	mov    ecx,0x3ffffff
  7e05cc:	41 89 fe                                        	mov    r14d,edi
  7e05cf:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  7e05d2:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  7e05d6:	48 c7 45 a8 00 00 00 00                         	mov    QWORD PTR [rbp-0x58],0x0
  7e05de:	48 c7 45 a0 00 00 00 00                         	mov    QWORD PTR [rbp-0x60],0x0
  7e05e6:	c6 45 b0 00                                     	mov    BYTE PTR [rbp-0x50],0x0
  7e05ea:	e8 21 e6 e2 ff                                  	call   0x60ec10
  7e05ef:	89 c3                                           	mov    ebx,eax
  7e05f1:	b0 01                                           	mov    al,0x1
  7e05f3:	89 45 94                                        	mov    DWORD PTR [rbp-0x6c],eax
  7e05f6:	85 db                                           	test   ebx,ebx
  7e05f8:	74 16                                           	je     0x7e0610
  7e05fa:	41 ba 00 00 68 04                               	mov    r10d,0x4680000
  7e0600:	48 c7 45 88 00 00 00 00                         	mov    QWORD PTR [rbp-0x78],0x0
  7e0608:	45 31 ed                                        	xor    r13d,r13d
  7e060b:	e9 fb 00 00 00                                  	jmp    0x7e070b
  7e0610:	48 8b 45 a8                                     	mov    rax,QWORD PTR [rbp-0x58]
  7e0614:	48 8d 7d b0                                     	lea    rdi,[rbp-0x50]
  7e0618:	ba 20 00 00 00                                  	mov    edx,0x20
  7e061d:	4c 89 6d 80                                     	mov    QWORD PTR [rbp-0x80],r13
  7e0621:	48 8b 70 18                                     	mov    rsi,QWORD PTR [rax+0x18]
  7e0625:	e8 46 75 17 00                                  	call   0x957b70
  7e062a:	48 8b 45 a8                                     	mov    rax,QWORD PTR [rbp-0x58]
  7e062e:	31 db                                           	xor    ebx,ebx
  7e0630:	31 f6                                           	xor    esi,esi
  7e0632:	31 d2                                           	xor    edx,edx
  7e0634:	31 c9                                           	xor    ecx,ecx
  7e0636:	48 8b 78 28                                     	mov    rdi,QWORD PTR [rax+0x28]
  7e063a:	e8 e1 b4 46 00                                  	call   0xc4bb20
  7e063f:	48 8b 45 a8                                     	mov    rax,QWORD PTR [rbp-0x58]
  7e0643:	48 8b 78 28                                     	mov    rdi,QWORD PTR [rax+0x28]
  7e0647:	44 8b 7f 20                                     	mov    r15d,DWORD PTR [rdi+0x20]
  7e064b:	41 f7 c7 00 00 01 00                            	test   r15d,0x10000
  7e0652:	75 15                                           	jne    0x7e0669
  7e0654:	48 8b 87 f8 08 00 00                            	mov    rax,QWORD PTR [rdi+0x8f8]
  7e065b:	45 31 ed                                        	xor    r13d,r13d
  7e065e:	48 89 45 a0                                     	mov    QWORD PTR [rbp-0x60],rax
  7e0662:	b8 00 00 68 04                                  	mov    eax,0x4680000
  7e0667:	eb 0d                                           	jmp    0x7e0676
  7e0669:	b8 01 00 68 04                                  	mov    eax,0x4680001
  7e066e:	bb 02 00 00 00                                  	mov    ebx,0x2
  7e0673:	4d 89 fd                                        	mov    r13,r15
  7e0676:	48 89 45 98                                     	mov    QWORD PTR [rbp-0x68],rax
  7e067a:	48 c7 45 88 00 00 00 00                         	mov    QWORD PTR [rbp-0x78],0x0
  7e0682:	31 f6                                           	xor    esi,esi
  7e0684:	31 d2                                           	xor    edx,edx
  7e0686:	e8 25 be 46 00                                  	call   0xc4c4b0
  7e068b:	44 89 f7                                        	mov    edi,r14d
  7e068e:	be 02 80 00 00                                  	mov    esi,0x8002
  7e0693:	31 d2                                           	xor    edx,edx
  7e0695:	e8 36 e6 e2 ff                                  	call   0x60ecd0
  7e069a:	41 f7 c7 00 00 01 00                            	test   r15d,0x10000
  7e06a1:	75 5d                                           	jne    0x7e0700
  7e06a3:	4d 8b 3c 24                                     	mov    r15,QWORD PTR [r12]
  7e06a7:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  7e06b0:	48 8d 35 e0 eb b6 00                            	lea    rsi,[rip+0xb6ebe0]        # 0x134f297
  7e06b7:	31 d2                                           	xor    edx,edx
  7e06b9:	31 db                                           	xor    ebx,ebx
  7e06bb:	e8 20 9d 43 00                                  	call   0xc1a3e0
  7e06c0:	48 8d 7d a0                                     	lea    rdi,[rbp-0x60]
  7e06c4:	ba 08 00 00 00                                  	mov    edx,0x8
  7e06c9:	4c 89 fe                                        	mov    rsi,r15
  7e06cc:	e8 ff 8a a7 ff                                  	call   0x2591d0
  7e06d1:	85 c0                                           	test   eax,eax
  7e06d3:	0f 84 62 01 00 00                               	je     0x7e083b
  7e06d9:	4c 8b 55 98                                     	mov    r10,QWORD PTR [rbp-0x68]
  7e06dd:	4d 8b 2c 24                                     	mov    r13,QWORD PTR [r12]
  7e06e1:	4c 8d 3d 28 bc 13 03                            	lea    r15,[rip+0x313bc28]        # 0x391c310
  7e06e8:	b9 20 03 02 a0                                  	mov    ecx,0xa0020320
  7e06ed:	89 c3                                           	mov    ebx,eax
  7e06ef:	c7 45 94 00 00 00 00                            	mov    DWORD PTR [rbp-0x6c],0x0
  7e06f6:	48 89 4d 88                                     	mov    QWORD PTR [rbp-0x78],rcx
  7e06fa:	41 83 ca 02                                     	or     r10d,0x2
  7e06fe:	eb 0b                                           	jmp    0x7e070b
  7e0700:	4c 8d 3d 09 bc 13 03                            	lea    r15,[rip+0x313bc09]        # 0x391c310
  7e0707:	4c 8b 55 98                                     	mov    r10,QWORD PTR [rbp-0x68]
  7e070b:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  7e0714:	44 8d a3 00 00 02 80                            	lea    r12d,[rbx-0x7ffe0000]
  7e071b:	48 83 ec 08                                     	sub    rsp,0x8
  7e071f:	48 8d 45 b0                                     	lea    rax,[rbp-0x50]
  7e0723:	be 18 47 00 00                                  	mov    esi,0x4718
  7e0728:	ba ff ff ff ff                                  	mov    edx,0xffffffff
  7e072d:	b9 ff ff ff ff                                  	mov    ecx,0xffffffff
  7e0732:	45 89 f0                                        	mov    r8d,r14d
  7e0735:	45 89 e1                                        	mov    r9d,r12d
  7e0738:	50                                              	push   rax
  7e0739:	41 55                                           	push   r13
  7e073b:	4c 89 55 98                                     	mov    QWORD PTR [rbp-0x68],r10
  7e073f:	41 52                                           	push   r10
  7e0741:	e8 2a f2 41 00                                  	call   0xbff970
  7e0746:	48 83 c4 20                                     	add    rsp,0x20
  7e074a:	e8 81 71 32 00                                  	call   0xb078d0
  7e074f:	85 c0                                           	test   eax,eax
  7e0751:	74 7c                                           	je     0x7e07cf
  7e0753:	83 3d a6 f8 4c 02 00                            	cmp    DWORD PTR [rip+0x24cf8a6],0x0        # 0x2cb0000
  7e075a:	74 73                                           	je     0x7e07cf
  7e075c:	4c 8b 3d bd 61 41 03                            	mov    r15,QWORD PTR [rip+0x34161bd]        # 0x3bf6920
  7e0763:	48 8d 05 7e 8c a8 ff                            	lea    rax,[rip+0xffffffffffa88c7e]        # 0x2693e8
  7e076a:	4c 29 f8                                        	sub    rax,r15
  7e076d:	48 c1 c8 03                                     	ror    rax,0x3
  7e0771:	48 83 f8 01                                     	cmp    rax,0x1
  7e0775:	0f 87 f2 00 00 00                               	ja     0x7e086d
  7e077b:	4c 8b 5d 98                                     	mov    r11,QWORD PTR [rbp-0x68]
  7e077f:	48 8b 4d b0                                     	mov    rcx,QWORD PTR [rbp-0x50]
  7e0783:	4c 8b 45 b8                                     	mov    r8,QWORD PTR [rbp-0x48]
  7e0787:	4c 8b 4d c0                                     	mov    r9,QWORD PTR [rbp-0x40]
  7e078b:	41 0f b7 c6                                     	movzx  eax,r14w
  7e078f:	ba 20 03 02 a0                                  	mov    edx,0xa0020320
  7e0794:	45 89 e2                                        	mov    r10d,r12d
  7e0797:	bf 08 00 00 00                                  	mov    edi,0x8
  7e079c:	be 02 00 00 00                                  	mov    esi,0x2
  7e07a1:	48 c1 e0 20                                     	shl    rax,0x20
  7e07a5:	48 8d 84 10 df fc fd 5f                         	lea    rax,[rax+rdx*1+0x5ffdfcdf]
  7e07ad:	ba 18 47 00 00                                  	mov    edx,0x4718
  7e07b2:	49 c1 e3 20                                     	shl    r11,0x20
  7e07b6:	4d 09 da                                        	or     r10,r11
  7e07b9:	41 55                                           	push   r13
  7e07bb:	41 52                                           	push   r10
  7e07bd:	50                                              	push   rax
  7e07be:	ff 75 c8                                        	push   QWORD PTR [rbp-0x38]
  7e07c1:	41 ff d7                                        	call   r15
  7e07c4:	48 83 c4 20                                     	add    rsp,0x20
  7e07c8:	4c 8d 3d 41 bb 13 03                            	lea    r15,[rip+0x313bb41]        # 0x391c310
  7e07cf:	80 7d 94 00                                     	cmp    BYTE PTR [rbp-0x6c],0x0
  7e07d3:	75 77                                           	jne    0x7e084c
  7e07d5:	65 4c 8b 34 25 00 00 00 00                      	mov    r14,QWORD PTR gs:0x0
  7e07de:	49 8b 46 08                                     	mov    rax,QWORD PTR [r14+0x8]
  7e07e2:	81 b8 d4 05 00 00 00 00 50 03                   	cmp    DWORD PTR [rax+0x5d4],0x3500000
  7e07ec:	72 5e                                           	jb     0x7e084c
  7e07ee:	48 8d 3d 43 92 aa 00                            	lea    rdi,[rip+0xaa9243]        # 0x1289a38
  7e07f5:	be c2 00 00 00                                  	mov    esi,0xc2
  7e07fa:	31 c0                                           	xor    eax,eax
  7e07fc:	e8 0f cc a7 ff                                  	call   0x25d410
  7e0801:	4c 8b 65 88                                     	mov    r12,QWORD PTR [rbp-0x78]
  7e0805:	41 8b b6 9c 00 00 00                            	mov    esi,DWORD PTR [r14+0x9c]
  7e080c:	4c 89 f2                                        	mov    rdx,r14
  7e080f:	48 8d 3d 91 be a8 00                            	lea    rdi,[rip+0xa8be91]        # 0x126c6a7
  7e0816:	4d 89 e9                                        	mov    r9,r13
  7e0819:	4c 8b 45 98                                     	mov    r8,QWORD PTR [rbp-0x68]
  7e081d:	31 c0                                           	xor    eax,eax
  7e081f:	48 81 c2 94 02 00 00                            	add    rdx,0x294
  7e0826:	4c 89 e1                                        	mov    rcx,r12
  7e0829:	e8 e2 cb a7 ff                                  	call   0x25d410
  7e082e:	4c 89 f7                                        	mov    rdi,r14
  7e0831:	4c 89 e6                                        	mov    rsi,r12
  7e0834:	e8 e7 f1 4b 00                                  	call   0xc9fa20
  7e0839:	eb 11                                           	jmp    0x7e084c
  7e083b:	48 8b 45 80                                     	mov    rax,QWORD PTR [rbp-0x80]
  7e083f:	4c 8d 3d ca ba 13 03                            	lea    r15,[rip+0x313baca]        # 0x391c310
  7e0846:	c7 00 00 00 00 00                               	mov    DWORD PTR [rax],0x0
  7e084c:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  7e084f:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  7e0853:	75 11                                           	jne    0x7e0866
  7e0855:	89 d8                                           	mov    eax,ebx
  7e0857:	48 83 c4 58                                     	add    rsp,0x58
  7e085b:	5b                                              	pop    rbx
  7e085c:	41 5c                                           	pop    r12
  7e085e:	41 5d                                           	pop    r13
  7e0860:	41 5e                                           	pop    r14
  7e0862:	41 5f                                           	pop    r15
  7e0864:	5d                                              	pop    rbp
  7e0865:	c3                                              	ret
  7e0866:	e8 45 ce f1 ff                                  	call   0x6fd6b0
  7e086b:	0f 0b                                           	ud2
  7e086d:	48 8d 3d 5c d4 d5 01                            	lea    rdi,[rip+0x1d5d45c]        # 0x253dcd0
  7e0874:	4c 89 fe                                        	mov    rsi,r15
  7e0877:	e8 44 f0 c6 ff                                  	call   0x44f8c0
  7e087c:	e9 fa fe ff ff                                  	jmp    0x7e077b
  7e0881:	90                                              	nop
  7e0882:	90                                              	nop
  7e0883:	90                                              	nop
  7e0884:	90                                              	nop
  7e0885:	90                                              	nop
  7e0886:	90                                              	nop
  7e0887:	90                                              	nop
  7e0888:	90                                              	nop
  7e0889:	90                                              	nop
  7e088a:	90                                              	nop
  7e088b:	90                                              	nop
  7e088c:	90                                              	nop
  7e088d:	90                                              	nop
  7e088e:	90                                              	nop
  7e088f:	90                                              	nop
  7e0890:	55                                              	push   rbp
  7e0891:	48 89 e5                                        	mov    rbp,rsp
  7e0894:	41 57                                           	push   r15
  7e0896:	41 56                                           	push   r14
  7e0898:	41 55                                           	push   r13
  7e089a:	41 54                                           	push   r12
  7e089c:	53                                              	push   rbx
  7e089d:	48 83 ec 58                                     	sub    rsp,0x58
  7e08a1:	4c 8d 3d 68 ba 13 03                            	lea    r15,[rip+0x313ba68]        # 0x391c310
  7e08a8:	49 89 d4                                        	mov    r12,rdx
  7e08ab:	49 89 f5                                        	mov    r13,rsi
  7e08ae:	48 8d 55 a8                                     	lea    rdx,[rbp-0x58]
  7e08b2:	be 04 80 00 00                                  	mov    esi,0x8004
  7e08b7:	b9 ff ff ff 03                                  	mov    ecx,0x3ffffff
  7e08bc:	41 89 fe                                        	mov    r14d,edi
  7e08bf:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  7e08c2:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  7e08c6:	48 c7 45 a8 00 00 00 00                         	mov    QWORD PTR [rbp-0x58],0x0
  7e08ce:	c7 45 a4 ff ff ff ff                            	mov    DWORD PTR [rbp-0x5c],0xffffffff
  7e08d5:	c6 45 b0 00                                     	mov    BYTE PTR [rbp-0x50],0x0
  7e08d9:	e8 32 e3 e2 ff                                  	call   0x60ec10
  7e08de:	89 c3                                           	mov    ebx,eax
  7e08e0:	b0 01                                           	mov    al,0x1
  7e08e2:	89 45 94                                        	mov    DWORD PTR [rbp-0x6c],eax
  7e08e5:	85 db                                           	test   ebx,ebx
  7e08e7:	74 16                                           	je     0x7e08ff
  7e08e9:	41 ba 00 00 69 04                               	mov    r10d,0x4690000
  7e08ef:	48 c7 45 88 00 00 00 00                         	mov    QWORD PTR [rbp-0x78],0x0
  7e08f7:	45 31 e4                                        	xor    r12d,r12d
  7e08fa:	e9 f6 00 00 00                                  	jmp    0x7e09f5
  7e08ff:	48 8b 45 a8                                     	mov    rax,QWORD PTR [rbp-0x58]
  7e0903:	48 8d 7d b0                                     	lea    rdi,[rbp-0x50]
  7e0907:	ba 20 00 00 00                                  	mov    edx,0x20
  7e090c:	4c 89 65 80                                     	mov    QWORD PTR [rbp-0x80],r12
  7e0910:	48 8b 70 18                                     	mov    rsi,QWORD PTR [rax+0x18]
  7e0914:	e8 57 72 17 00                                  	call   0x957b70
  7e0919:	48 8b 45 a8                                     	mov    rax,QWORD PTR [rbp-0x58]
  7e091d:	31 db                                           	xor    ebx,ebx
  7e091f:	31 f6                                           	xor    esi,esi
  7e0921:	31 d2                                           	xor    edx,edx
  7e0923:	31 c9                                           	xor    ecx,ecx
  7e0925:	48 8b 78 28                                     	mov    rdi,QWORD PTR [rax+0x28]
  7e0929:	e8 f2 b1 46 00                                  	call   0xc4bb20
  7e092e:	48 8b 45 a8                                     	mov    rax,QWORD PTR [rbp-0x58]
  7e0932:	48 8b 78 28                                     	mov    rdi,QWORD PTR [rax+0x28]
  7e0936:	44 8b 7f 20                                     	mov    r15d,DWORD PTR [rdi+0x20]
  7e093a:	41 f7 c7 00 00 00 04                            	test   r15d,0x4000000
  7e0941:	75 0f                                           	jne    0x7e0952
  7e0943:	b8 01 00 69 04                                  	mov    eax,0x4690001
  7e0948:	bb 03 00 00 00                                  	mov    ebx,0x3
  7e094d:	4d 89 fc                                        	mov    r12,r15
  7e0950:	eb 0e                                           	jmp    0x7e0960
  7e0952:	8b 47 3c                                        	mov    eax,DWORD PTR [rdi+0x3c]
  7e0955:	45 31 e4                                        	xor    r12d,r12d
  7e0958:	89 45 a4                                        	mov    DWORD PTR [rbp-0x5c],eax
  7e095b:	b8 00 00 69 04                                  	mov    eax,0x4690000
  7e0960:	48 89 45 98                                     	mov    QWORD PTR [rbp-0x68],rax
  7e0964:	48 c7 45 88 00 00 00 00                         	mov    QWORD PTR [rbp-0x78],0x0
  7e096c:	31 f6                                           	xor    esi,esi
  7e096e:	31 d2                                           	xor    edx,edx
  7e0970:	e8 3b bb 46 00                                  	call   0xc4c4b0
  7e0975:	44 89 f7                                        	mov    edi,r14d
  7e0978:	be 04 80 00 00                                  	mov    esi,0x8004
  7e097d:	31 d2                                           	xor    edx,edx
  7e097f:	e8 4c e3 e2 ff                                  	call   0x60ecd0
  7e0984:	41 f7 c7 00 00 00 04                            	test   r15d,0x4000000
  7e098b:	75 0d                                           	jne    0x7e099a
  7e098d:	4c 8d 3d 7c b9 13 03                            	lea    r15,[rip+0x313b97c]        # 0x391c310
  7e0994:	4c 8b 55 98                                     	mov    r10,QWORD PTR [rbp-0x68]
  7e0998:	eb 5b                                           	jmp    0x7e09f5
  7e099a:	4d 8b 7d 00                                     	mov    r15,QWORD PTR [r13+0x0]
  7e099e:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  7e09a7:	48 8d 35 e9 e8 b6 00                            	lea    rsi,[rip+0xb6e8e9]        # 0x134f297
  7e09ae:	31 d2                                           	xor    edx,edx
  7e09b0:	31 db                                           	xor    ebx,ebx
  7e09b2:	e8 29 9a 43 00                                  	call   0xc1a3e0
  7e09b7:	48 8d 7d a4                                     	lea    rdi,[rbp-0x5c]
  7e09bb:	ba 04 00 00 00                                  	mov    edx,0x4
  7e09c0:	4c 89 fe                                        	mov    rsi,r15
  7e09c3:	e8 08 88 a7 ff                                  	call   0x2591d0
  7e09c8:	85 c0                                           	test   eax,eax
  7e09ca:	0f 84 52 01 00 00                               	je     0x7e0b22
  7e09d0:	4c 8b 55 98                                     	mov    r10,QWORD PTR [rbp-0x68]
  7e09d4:	4d 8b 65 00                                     	mov    r12,QWORD PTR [r13+0x0]
  7e09d8:	4c 8d 3d 31 b9 13 03                            	lea    r15,[rip+0x313b931]        # 0x391c310
  7e09df:	b9 20 03 02 a0                                  	mov    ecx,0xa0020320
  7e09e4:	89 c3                                           	mov    ebx,eax
  7e09e6:	c7 45 94 00 00 00 00                            	mov    DWORD PTR [rbp-0x6c],0x0
  7e09ed:	48 89 4d 88                                     	mov    QWORD PTR [rbp-0x78],rcx
  7e09f1:	41 83 ca 02                                     	or     r10d,0x2
  7e09f5:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  7e09fe:	44 8d ab 00 00 02 80                            	lea    r13d,[rbx-0x7ffe0000]
  7e0a05:	48 83 ec 08                                     	sub    rsp,0x8
  7e0a09:	48 8d 45 b0                                     	lea    rax,[rbp-0x50]
  7e0a0d:	be 1a 27 00 00                                  	mov    esi,0x271a
  7e0a12:	ba ff ff ff ff                                  	mov    edx,0xffffffff
  7e0a17:	44 89 f1                                        	mov    ecx,r14d
  7e0a1a:	41 b8 ff ff ff ff                               	mov    r8d,0xffffffff
  7e0a20:	45 89 e9                                        	mov    r9d,r13d
  7e0a23:	50                                              	push   rax
  7e0a24:	41 54                                           	push   r12
  7e0a26:	4c 89 55 98                                     	mov    QWORD PTR [rbp-0x68],r10
  7e0a2a:	41 52                                           	push   r10
  7e0a2c:	e8 3f ef 41 00                                  	call   0xbff970
  7e0a31:	48 83 c4 20                                     	add    rsp,0x20
  7e0a35:	e8 96 6e 32 00                                  	call   0xb078d0
  7e0a3a:	85 c0                                           	test   eax,eax
  7e0a3c:	74 78                                           	je     0x7e0ab6
  7e0a3e:	83 3d bb f5 4c 02 00                            	cmp    DWORD PTR [rip+0x24cf5bb],0x0        # 0x2cb0000
  7e0a45:	74 6f                                           	je     0x7e0ab6
  7e0a47:	4c 8b 3d d2 5e 41 03                            	mov    r15,QWORD PTR [rip+0x3415ed2]        # 0x3bf6920
  7e0a4e:	48 8d 05 93 89 a8 ff                            	lea    rax,[rip+0xffffffffffa88993]        # 0x2693e8
  7e0a55:	4c 29 f8                                        	sub    rax,r15
  7e0a58:	48 c1 c8 03                                     	ror    rax,0x3
  7e0a5c:	48 83 f8 01                                     	cmp    rax,0x1
  7e0a60:	0f 87 ee 00 00 00                               	ja     0x7e0b54
  7e0a66:	48 8b 55 98                                     	mov    rdx,QWORD PTR [rbp-0x68]
  7e0a6a:	48 8b 4d b0                                     	mov    rcx,QWORD PTR [rbp-0x50]
  7e0a6e:	4c 8b 45 b8                                     	mov    r8,QWORD PTR [rbp-0x48]
  7e0a72:	4c 8b 4d c0                                     	mov    r9,QWORD PTR [rbp-0x40]
  7e0a76:	41 c1 e6 10                                     	shl    r14d,0x10
  7e0a7a:	48 b8 ff ff 00 00 ff ff 00 00                   	movabs rax,0xffff0000ffff
  7e0a84:	45 89 ea                                        	mov    r10d,r13d
  7e0a87:	bf 08 00 00 00                                  	mov    edi,0x8
  7e0a8c:	be 02 00 00 00                                  	mov    esi,0x2
  7e0a91:	4c 09 f0                                        	or     rax,r14
  7e0a94:	48 c1 e2 20                                     	shl    rdx,0x20
  7e0a98:	49 09 d2                                        	or     r10,rdx
  7e0a9b:	ba 1a 27 00 00                                  	mov    edx,0x271a
  7e0aa0:	41 54                                           	push   r12
  7e0aa2:	41 52                                           	push   r10
  7e0aa4:	50                                              	push   rax
  7e0aa5:	ff 75 c8                                        	push   QWORD PTR [rbp-0x38]
  7e0aa8:	41 ff d7                                        	call   r15
  7e0aab:	48 83 c4 20                                     	add    rsp,0x20
  7e0aaf:	4c 8d 3d 5a b8 13 03                            	lea    r15,[rip+0x313b85a]        # 0x391c310
  7e0ab6:	80 7d 94 00                                     	cmp    BYTE PTR [rbp-0x6c],0x0
  7e0aba:	75 77                                           	jne    0x7e0b33
  7e0abc:	65 4c 8b 34 25 00 00 00 00                      	mov    r14,QWORD PTR gs:0x0
  7e0ac5:	49 8b 46 08                                     	mov    rax,QWORD PTR [r14+0x8]
  7e0ac9:	81 b8 d4 05 00 00 00 00 50 03                   	cmp    DWORD PTR [rax+0x5d4],0x3500000
  7e0ad3:	72 5e                                           	jb     0x7e0b33
  7e0ad5:	48 8d 3d 5c 8f aa 00                            	lea    rdi,[rip+0xaa8f5c]        # 0x1289a38
  7e0adc:	be c2 00 00 00                                  	mov    esi,0xc2
  7e0ae1:	31 c0                                           	xor    eax,eax
  7e0ae3:	e8 28 c9 a7 ff                                  	call   0x25d410
  7e0ae8:	4c 8b 6d 88                                     	mov    r13,QWORD PTR [rbp-0x78]
  7e0aec:	41 8b b6 9c 00 00 00                            	mov    esi,DWORD PTR [r14+0x9c]
  7e0af3:	4c 89 f2                                        	mov    rdx,r14
  7e0af6:	48 8d 3d aa bb a8 00                            	lea    rdi,[rip+0xa8bbaa]        # 0x126c6a7
  7e0afd:	4d 89 e1                                        	mov    r9,r12
  7e0b00:	4c 8b 45 98                                     	mov    r8,QWORD PTR [rbp-0x68]
  7e0b04:	31 c0                                           	xor    eax,eax
  7e0b06:	48 81 c2 94 02 00 00                            	add    rdx,0x294
  7e0b0d:	4c 89 e9                                        	mov    rcx,r13
  7e0b10:	e8 fb c8 a7 ff                                  	call   0x25d410
  7e0b15:	4c 89 f7                                        	mov    rdi,r14
  7e0b18:	4c 89 ee                                        	mov    rsi,r13
  7e0b1b:	e8 00 ef 4b 00                                  	call   0xc9fa20
  7e0b20:	eb 11                                           	jmp    0x7e0b33
  7e0b22:	48 8b 45 80                                     	mov    rax,QWORD PTR [rbp-0x80]
  7e0b26:	4c 8d 3d e3 b7 13 03                            	lea    r15,[rip+0x313b7e3]        # 0x391c310
  7e0b2d:	c7 00 00 00 00 00                               	mov    DWORD PTR [rax],0x0
  7e0b33:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  7e0b36:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  7e0b3a:	75 11                                           	jne    0x7e0b4d
  7e0b3c:	89 d8                                           	mov    eax,ebx
  7e0b3e:	48 83 c4 58                                     	add    rsp,0x58
  7e0b42:	5b                                              	pop    rbx
  7e0b43:	41 5c                                           	pop    r12
  7e0b45:	41 5d                                           	pop    r13
  7e0b47:	41 5e                                           	pop    r14
  7e0b49:	41 5f                                           	pop    r15
  7e0b4b:	5d                                              	pop    rbp
  7e0b4c:	c3                                              	ret
  7e0b4d:	e8 5e cb f1 ff                                  	call   0x6fd6b0
  7e0b52:	0f 0b                                           	ud2
  7e0b54:	48 8d 3d 95 d1 d5 01                            	lea    rdi,[rip+0x1d5d195]        # 0x253dcf0
  7e0b5b:	4c 89 fe                                        	mov    rsi,r15
  7e0b5e:	e8 5d ed c6 ff                                  	call   0x44f8c0
  7e0b63:	e9 fe fe ff ff                                  	jmp    0x7e0a66
  7e0b68:	90                                              	nop
  7e0b69:	90                                              	nop
  7e0b6a:	90                                              	nop
  7e0b6b:	90                                              	nop
  7e0b6c:	90                                              	nop
  7e0b6d:	90                                              	nop
  7e0b6e:	90                                              	nop
  7e0b6f:	90                                              	nop
  7e0b70:	55                                              	push   rbp
  7e0b71:	48 89 e5                                        	mov    rbp,rsp
  7e0b74:	41 57                                           	push   r15
  7e0b76:	41 56                                           	push   r14
  7e0b78:	41 55                                           	push   r13
  7e0b7a:	41 54                                           	push   r12
  7e0b7c:	53                                              	push   rbx
  7e0b7d:	48 83 ec 48                                     	sub    rsp,0x48
  7e0b81:	4c 8d 2d 88 b7 13 03                            	lea    r13,[rip+0x313b788]        # 0x391c310
  7e0b88:	49 89 d4                                        	mov    r12,rdx
  7e0b8b:	48 89 f3                                        	mov    rbx,rsi
  7e0b8e:	48 8d 55 a8                                     	lea    rdx,[rbp-0x58]
  7e0b92:	be 01 80 00 00                                  	mov    esi,0x8001
  7e0b97:	b9 ff ff ff 03                                  	mov    ecx,0x3ffffff
  7e0b9c:	41 89 ff                                        	mov    r15d,edi
  7e0b9f:	49 8b 45 00                                     	mov    rax,QWORD PTR [r13+0x0]
  7e0ba3:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  7e0ba7:	48 c7 45 a8 00 00 00 00                         	mov    QWORD PTR [rbp-0x58],0x0
  7e0baf:	c6 45 b0 00                                     	mov    BYTE PTR [rbp-0x50],0x0
  7e0bb3:	e8 58 e0 e2 ff                                  	call   0x60ec10
  7e0bb8:	41 89 c6                                        	mov    r14d,eax
  7e0bbb:	85 c0                                           	test   eax,eax
  7e0bbd:	74 16                                           	je     0x7e0bd5
  7e0bbf:	41 ba 00 00 6a 04                               	mov    r10d,0x46a0000
  7e0bc5:	48 c7 45 98 00 00 00 00                         	mov    QWORD PTR [rbp-0x68],0x0
  7e0bcd:	44 89 f3                                        	mov    ebx,r14d
  7e0bd0:	e9 82 00 00 00                                  	jmp    0x7e0c57
  7e0bd5:	48 8b 45 a8                                     	mov    rax,QWORD PTR [rbp-0x58]
  7e0bd9:	48 8d 7d b0                                     	lea    rdi,[rbp-0x50]
  7e0bdd:	ba 20 00 00 00                                  	mov    edx,0x20
  7e0be2:	4c 89 65 a0                                     	mov    QWORD PTR [rbp-0x60],r12
  7e0be6:	48 8b 70 18                                     	mov    rsi,QWORD PTR [rax+0x18]
  7e0bea:	e8 81 6f 17 00                                  	call   0x957b70
  7e0bef:	48 8b 45 a8                                     	mov    rax,QWORD PTR [rbp-0x58]
  7e0bf3:	4c 8b 23                                        	mov    r12,QWORD PTR [rbx]
  7e0bf6:	48 8d 35 9a e6 b6 00                            	lea    rsi,[rip+0xb6e69a]        # 0x134f297
  7e0bfd:	31 db                                           	xor    ebx,ebx
  7e0bff:	31 d2                                           	xor    edx,edx
  7e0c01:	4c 8b 68 18                                     	mov    r13,QWORD PTR [rax+0x18]
  7e0c05:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  7e0c0e:	e8 cd 97 43 00                                  	call   0xc1a3e0
  7e0c13:	ba 19 00 00 00                                  	mov    edx,0x19
  7e0c18:	4c 89 ef                                        	mov    rdi,r13
  7e0c1b:	4c 89 e6                                        	mov    rsi,r12
  7e0c1e:	e8 ad 85 a7 ff                                  	call   0x2591d0
  7e0c23:	44 89 ff                                        	mov    edi,r15d
  7e0c26:	be 01 80 00 00                                  	mov    esi,0x8001
  7e0c2b:	31 d2                                           	xor    edx,edx
  7e0c2d:	41 89 c5                                        	mov    r13d,eax
  7e0c30:	e8 9b e0 e2 ff                                  	call   0x60ecd0
  7e0c35:	45 85 ed                                        	test   r13d,r13d
  7e0c38:	0f 84 45 01 00 00                               	je     0x7e0d83
  7e0c3e:	44 89 eb                                        	mov    ebx,r13d
  7e0c41:	4c 8d 2d c8 b6 13 03                            	lea    r13,[rip+0x313b6c8]        # 0x391c310
  7e0c48:	41 ba 01 00 6a 04                               	mov    r10d,0x46a0001
  7e0c4e:	b8 20 03 02 a0                                  	mov    eax,0xa0020320
  7e0c53:	48 89 45 98                                     	mov    QWORD PTR [rbp-0x68],rax
  7e0c57:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  7e0c60:	44 8d a3 00 00 02 80                            	lea    r12d,[rbx-0x7ffe0000]
  7e0c67:	48 83 ec 08                                     	sub    rsp,0x8
  7e0c6b:	48 8d 45 b0                                     	lea    rax,[rbp-0x50]
  7e0c6f:	be 19 17 00 00                                  	mov    esi,0x1719
  7e0c74:	44 89 fa                                        	mov    edx,r15d
  7e0c77:	b9 ff ff ff ff                                  	mov    ecx,0xffffffff
  7e0c7c:	41 b8 ff ff ff ff                               	mov    r8d,0xffffffff
  7e0c82:	45 89 e1                                        	mov    r9d,r12d
  7e0c85:	50                                              	push   rax
  7e0c86:	6a 00                                           	push   0x0
  7e0c88:	4c 89 55 a0                                     	mov    QWORD PTR [rbp-0x60],r10
  7e0c8c:	41 52                                           	push   r10
  7e0c8e:	e8 dd ec 41 00                                  	call   0xbff970
  7e0c93:	48 83 c4 20                                     	add    rsp,0x20
  7e0c97:	e8 34 6c 32 00                                  	call   0xb078d0
  7e0c9c:	85 c0                                           	test   eax,eax
  7e0c9e:	74 78                                           	je     0x7e0d18
  7e0ca0:	83 3d 59 f3 4c 02 00                            	cmp    DWORD PTR [rip+0x24cf359],0x0        # 0x2cb0000
  7e0ca7:	74 6f                                           	je     0x7e0d18
  7e0ca9:	4c 8b 2d 70 5c 41 03                            	mov    r13,QWORD PTR [rip+0x3415c70]        # 0x3bf6920
  7e0cb0:	48 8d 05 31 87 a8 ff                            	lea    rax,[rip+0xffffffffffa88731]        # 0x2693e8
  7e0cb7:	4c 29 e8                                        	sub    rax,r13
  7e0cba:	48 c1 c8 03                                     	ror    rax,0x3
  7e0cbe:	48 83 f8 01                                     	cmp    rax,0x1
  7e0cc2:	0f 87 ee 00 00 00                               	ja     0x7e0db6
  7e0cc8:	44 89 f8                                        	mov    eax,r15d
  7e0ccb:	49 ba 00 00 ff ff ff ff 00 00                   	movabs r10,0xffffffff0000
  7e0cd5:	48 8b 4d b0                                     	mov    rcx,QWORD PTR [rbp-0x50]
  7e0cd9:	4c 8b 45 b8                                     	mov    r8,QWORD PTR [rbp-0x48]
  7e0cdd:	4c 8b 4d c0                                     	mov    r9,QWORD PTR [rbp-0x40]
  7e0ce1:	45 89 e3                                        	mov    r11d,r12d
  7e0ce4:	ba 19 17 00 00                                  	mov    edx,0x1719
  7e0ce9:	bf 08 00 00 00                                  	mov    edi,0x8
  7e0cee:	be 02 00 00 00                                  	mov    esi,0x2
  7e0cf3:	49 09 c2                                        	or     r10,rax
  7e0cf6:	48 8b 45 a0                                     	mov    rax,QWORD PTR [rbp-0x60]
  7e0cfa:	48 c1 e0 20                                     	shl    rax,0x20
  7e0cfe:	49 09 c3                                        	or     r11,rax
  7e0d01:	6a 00                                           	push   0x0
  7e0d03:	41 53                                           	push   r11
  7e0d05:	41 52                                           	push   r10
  7e0d07:	ff 75 c8                                        	push   QWORD PTR [rbp-0x38]
  7e0d0a:	41 ff d5                                        	call   r13
  7e0d0d:	48 83 c4 20                                     	add    rsp,0x20
  7e0d11:	4c 8d 2d f8 b5 13 03                            	lea    r13,[rip+0x313b5f8]        # 0x391c310
  7e0d18:	45 85 f6                                        	test   r14d,r14d
  7e0d1b:	75 77                                           	jne    0x7e0d94
  7e0d1d:	65 4c 8b 34 25 00 00 00 00                      	mov    r14,QWORD PTR gs:0x0
  7e0d26:	49 8b 46 08                                     	mov    rax,QWORD PTR [r14+0x8]
  7e0d2a:	81 b8 d4 05 00 00 00 00 50 03                   	cmp    DWORD PTR [rax+0x5d4],0x3500000
  7e0d34:	72 5e                                           	jb     0x7e0d94
  7e0d36:	48 8d 3d fb 8c aa 00                            	lea    rdi,[rip+0xaa8cfb]        # 0x1289a38
  7e0d3d:	be c2 00 00 00                                  	mov    esi,0xc2
  7e0d42:	31 c0                                           	xor    eax,eax
  7e0d44:	e8 c7 c6 a7 ff                                  	call   0x25d410
  7e0d49:	4c 8b 7d 98                                     	mov    r15,QWORD PTR [rbp-0x68]
  7e0d4d:	41 8b b6 9c 00 00 00                            	mov    esi,DWORD PTR [r14+0x9c]
  7e0d54:	4c 89 f2                                        	mov    rdx,r14
  7e0d57:	48 8d 3d 49 b9 a8 00                            	lea    rdi,[rip+0xa8b949]        # 0x126c6a7
  7e0d5e:	4c 8b 45 a0                                     	mov    r8,QWORD PTR [rbp-0x60]
  7e0d62:	45 31 c9                                        	xor    r9d,r9d
  7e0d65:	31 c0                                           	xor    eax,eax
  7e0d67:	48 81 c2 94 02 00 00                            	add    rdx,0x294
  7e0d6e:	4c 89 f9                                        	mov    rcx,r15
  7e0d71:	e8 9a c6 a7 ff                                  	call   0x25d410
  7e0d76:	4c 89 f7                                        	mov    rdi,r14
  7e0d79:	4c 89 fe                                        	mov    rsi,r15
  7e0d7c:	e8 9f ec 4b 00                                  	call   0xc9fa20
  7e0d81:	eb 11                                           	jmp    0x7e0d94
  7e0d83:	48 8b 45 a0                                     	mov    rax,QWORD PTR [rbp-0x60]
  7e0d87:	4c 8d 2d 82 b5 13 03                            	lea    r13,[rip+0x313b582]        # 0x391c310
  7e0d8e:	c7 00 00 00 00 00                               	mov    DWORD PTR [rax],0x0
  7e0d94:	49 8b 45 00                                     	mov    rax,QWORD PTR [r13+0x0]
  7e0d98:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  7e0d9c:	75 11                                           	jne    0x7e0daf
  7e0d9e:	89 d8                                           	mov    eax,ebx
  7e0da0:	48 83 c4 48                                     	add    rsp,0x48
  7e0da4:	5b                                              	pop    rbx
  7e0da5:	41 5c                                           	pop    r12
  7e0da7:	41 5d                                           	pop    r13
  7e0da9:	41 5e                                           	pop    r14
  7e0dab:	41 5f                                           	pop    r15
  7e0dad:	5d                                              	pop    rbp
  7e0dae:	c3                                              	ret
  7e0daf:	e8 fc c8 f1 ff                                  	call   0x6fd6b0
  7e0db4:	0f 0b                                           	ud2
  7e0db6:	48 8d 3d 53 cf d5 01                            	lea    rdi,[rip+0x1d5cf53]        # 0x253dd10
  7e0dbd:	4c 89 ee                                        	mov    rsi,r13
  7e0dc0:	e8 fb ea c6 ff                                  	call   0x44f8c0
  7e0dc5:	e9 fe fe ff ff                                  	jmp    0x7e0cc8
  7e0dca:	90                                              	nop
  7e0dcb:	90                                              	nop
  7e0dcc:	90                                              	nop
  7e0dcd:	90                                              	nop
  7e0dce:	90                                              	nop
  7e0dcf:	90                                              	nop
  7e0dd0:	55                                              	push   rbp
  7e0dd1:	48 89 e5                                        	mov    rbp,rsp
  7e0dd4:	41 57                                           	push   r15
  7e0dd6:	41 56                                           	push   r14
  7e0dd8:	41 55                                           	push   r13
  7e0dda:	41 54                                           	push   r12
  7e0ddc:	53                                              	push   rbx
  7e0ddd:	48 83 ec 48                                     	sub    rsp,0x48
  7e0de1:	48 8d 05 28 b5 13 03                            	lea    rax,[rip+0x313b528]        # 0x391c310
  7e0de8:	49 89 d7                                        	mov    r15,rdx
  7e0deb:	49 89 f4                                        	mov    r12,rsi
  7e0dee:	48 8d 55 a8                                     	lea    rdx,[rbp-0x58]
  7e0df2:	be 04 80 00 00                                  	mov    esi,0x8004
  7e0df7:	b9 ff ff ff 03                                  	mov    ecx,0x3ffffff
  7e0dfc:	41 89 fe                                        	mov    r14d,edi
  7e0dff:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  7e0e02:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  7e0e06:	48 c7 45 a8 00 00 00 00                         	mov    QWORD PTR [rbp-0x58],0x0
  7e0e0e:	48 c7 45 c8 00 00 00 00                         	mov    QWORD PTR [rbp-0x38],0x0
  7e0e16:	48 c7 45 c0 00 00 00 00                         	mov    QWORD PTR [rbp-0x40],0x0
  7e0e1e:	48 c7 45 b8 00 00 00 00                         	mov    QWORD PTR [rbp-0x48],0x0
  7e0e26:	48 c7 45 b0 00 00 00 00                         	mov    QWORD PTR [rbp-0x50],0x0
  7e0e2e:	e8 dd dd e2 ff                                  	call   0x60ec10
  7e0e33:	85 c0                                           	test   eax,eax
  7e0e35:	74 16                                           	je     0x7e0e4d
  7e0e37:	89 c3                                           	mov    ebx,eax
  7e0e39:	b0 01                                           	mov    al,0x1
  7e0e3b:	41 bc 00 00 6b 04                               	mov    r12d,0x46b0000
  7e0e41:	45 31 ff                                        	xor    r15d,r15d
  7e0e44:	48 89 45 a0                                     	mov    QWORD PTR [rbp-0x60],rax
  7e0e48:	e9 c4 00 00 00                                  	jmp    0x7e0f11
  7e0e4d:	48 8b 45 a8                                     	mov    rax,QWORD PTR [rbp-0x58]
  7e0e51:	31 f6                                           	xor    esi,esi
  7e0e53:	31 d2                                           	xor    edx,edx
  7e0e55:	31 c9                                           	xor    ecx,ecx
  7e0e57:	48 8b 78 28                                     	mov    rdi,QWORD PTR [rax+0x28]
  7e0e5b:	e8 c0 ac 46 00                                  	call   0xc4bb20
  7e0e60:	48 8b 45 a8                                     	mov    rax,QWORD PTR [rbp-0x58]
  7e0e64:	48 8b 78 28                                     	mov    rdi,QWORD PTR [rax+0x28]
  7e0e68:	f6 47 23 20                                     	test   BYTE PTR [rdi+0x23],0x20
  7e0e6c:	0f 85 82 00 00 00                               	jne    0x7e0ef4
  7e0e72:	48 8b 70 18                                     	mov    rsi,QWORD PTR [rax+0x18]
  7e0e76:	4c 8d 6d b0                                     	lea    r13,[rbp-0x50]
  7e0e7a:	ba 20 00 00 00                                  	mov    edx,0x20
  7e0e7f:	4c 89 ef                                        	mov    rdi,r13
  7e0e82:	e8 e9 6c 17 00                                  	call   0x957b70
  7e0e87:	48 8b 45 a8                                     	mov    rax,QWORD PTR [rbp-0x58]
  7e0e8b:	31 db                                           	xor    ebx,ebx
  7e0e8d:	31 f6                                           	xor    esi,esi
  7e0e8f:	31 d2                                           	xor    edx,edx
  7e0e91:	48 8b 78 28                                     	mov    rdi,QWORD PTR [rax+0x28]
  7e0e95:	e8 16 b6 46 00                                  	call   0xc4c4b0
  7e0e9a:	44 89 f7                                        	mov    edi,r14d
  7e0e9d:	be 04 80 00 00                                  	mov    esi,0x8004
  7e0ea2:	31 d2                                           	xor    edx,edx
  7e0ea4:	e8 27 de e2 ff                                  	call   0x60ecd0
  7e0ea9:	4d 8b 24 24                                     	mov    r12,QWORD PTR [r12]
  7e0ead:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  7e0eb6:	48 8d 35 da e3 b6 00                            	lea    rsi,[rip+0xb6e3da]        # 0x134f297
  7e0ebd:	31 d2                                           	xor    edx,edx
  7e0ebf:	e8 1c 95 43 00                                  	call   0xc1a3e0
  7e0ec4:	ba 19 00 00 00                                  	mov    edx,0x19
  7e0ec9:	4c 89 ef                                        	mov    rdi,r13
  7e0ecc:	4c 89 e6                                        	mov    rsi,r12
  7e0ecf:	e8 fc 82 a7 ff                                  	call   0x2591d0
  7e0ed4:	85 c0                                           	test   eax,eax
  7e0ed6:	0f 84 59 01 00 00                               	je     0x7e1035
  7e0edc:	41 bc 01 00 6b 04                               	mov    r12d,0x46b0001
  7e0ee2:	41 bf 20 03 02 a0                               	mov    r15d,0xa0020320
  7e0ee8:	89 c3                                           	mov    ebx,eax
  7e0eea:	48 c7 45 a0 00 00 00 00                         	mov    QWORD PTR [rbp-0x60],0x0
  7e0ef2:	eb 1d                                           	jmp    0x7e0f11
  7e0ef4:	b0 01                                           	mov    al,0x1
  7e0ef6:	45 31 ff                                        	xor    r15d,r15d
  7e0ef9:	31 f6                                           	xor    esi,esi
  7e0efb:	31 d2                                           	xor    edx,edx
  7e0efd:	48 89 45 a0                                     	mov    QWORD PTR [rbp-0x60],rax
  7e0f01:	e8 aa b5 46 00                                  	call   0xc4c4b0
  7e0f06:	bb 02 00 00 00                                  	mov    ebx,0x2
  7e0f0b:	41 bc 01 00 6b 04                               	mov    r12d,0x46b0001
  7e0f11:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  7e0f1a:	44 8d ab 00 00 02 80                            	lea    r13d,[rbx-0x7ffe0000]
  7e0f21:	48 83 ec 08                                     	sub    rsp,0x8
  7e0f25:	48 8d 45 b0                                     	lea    rax,[rbp-0x50]
  7e0f29:	be 1c 27 00 00                                  	mov    esi,0x271c
  7e0f2e:	ba ff ff ff ff                                  	mov    edx,0xffffffff
  7e0f33:	44 89 f1                                        	mov    ecx,r14d
  7e0f36:	41 b8 ff ff ff ff                               	mov    r8d,0xffffffff
  7e0f3c:	45 89 e9                                        	mov    r9d,r13d
  7e0f3f:	50                                              	push   rax
  7e0f40:	6a 00                                           	push   0x0
  7e0f42:	41 54                                           	push   r12
  7e0f44:	e8 27 ea 41 00                                  	call   0xbff970
  7e0f49:	48 83 c4 20                                     	add    rsp,0x20
  7e0f4d:	e8 7e 69 32 00                                  	call   0xb078d0
  7e0f52:	85 c0                                           	test   eax,eax
  7e0f54:	74 78                                           	je     0x7e0fce
  7e0f56:	83 3d a3 f0 4c 02 00                            	cmp    DWORD PTR [rip+0x24cf0a3],0x0        # 0x2cb0000
  7e0f5d:	74 6f                                           	je     0x7e0fce
  7e0f5f:	4c 89 7d 98                                     	mov    QWORD PTR [rbp-0x68],r15
  7e0f63:	4c 8b 3d b6 59 41 03                            	mov    r15,QWORD PTR [rip+0x34159b6]        # 0x3bf6920
  7e0f6a:	48 8d 05 77 84 a8 ff                            	lea    rax,[rip+0xffffffffffa88477]        # 0x2693e8
  7e0f71:	4c 29 f8                                        	sub    rax,r15
  7e0f74:	48 c1 c8 03                                     	ror    rax,0x3
  7e0f78:	48 83 f8 01                                     	cmp    rax,0x1
  7e0f7c:	0f 87 e2 00 00 00                               	ja     0x7e1064
  7e0f82:	48 8b 4d b0                                     	mov    rcx,QWORD PTR [rbp-0x50]
  7e0f86:	4c 8b 45 b8                                     	mov    r8,QWORD PTR [rbp-0x48]
  7e0f8a:	4c 8b 4d c0                                     	mov    r9,QWORD PTR [rbp-0x40]
  7e0f8e:	4c 89 e2                                        	mov    rdx,r12
  7e0f91:	41 c1 e6 10                                     	shl    r14d,0x10
  7e0f95:	48 b8 ff ff 00 00 ff ff 00 00                   	movabs rax,0xffff0000ffff
  7e0f9f:	45 89 ea                                        	mov    r10d,r13d
  7e0fa2:	bf 08 00 00 00                                  	mov    edi,0x8
  7e0fa7:	be 02 00 00 00                                  	mov    esi,0x2
  7e0fac:	48 c1 e2 20                                     	shl    rdx,0x20
  7e0fb0:	4c 09 f0                                        	or     rax,r14
  7e0fb3:	49 09 d2                                        	or     r10,rdx
  7e0fb6:	ba 1c 27 00 00                                  	mov    edx,0x271c
  7e0fbb:	6a 00                                           	push   0x0
  7e0fbd:	41 52                                           	push   r10
  7e0fbf:	50                                              	push   rax
  7e0fc0:	ff 75 c8                                        	push   QWORD PTR [rbp-0x38]
  7e0fc3:	41 ff d7                                        	call   r15
  7e0fc6:	48 83 c4 20                                     	add    rsp,0x20
  7e0fca:	4c 8b 7d 98                                     	mov    r15,QWORD PTR [rbp-0x68]
  7e0fce:	80 7d a0 00                                     	cmp    BYTE PTR [rbp-0x60],0x0
  7e0fd2:	75 68                                           	jne    0x7e103c
  7e0fd4:	65 4c 8b 34 25 00 00 00 00                      	mov    r14,QWORD PTR gs:0x0
  7e0fdd:	49 8b 46 08                                     	mov    rax,QWORD PTR [r14+0x8]
  7e0fe1:	81 b8 d4 05 00 00 00 00 50 03                   	cmp    DWORD PTR [rax+0x5d4],0x3500000
  7e0feb:	72 4f                                           	jb     0x7e103c
  7e0fed:	48 8d 3d 44 8a aa 00                            	lea    rdi,[rip+0xaa8a44]        # 0x1289a38
  7e0ff4:	be c2 00 00 00                                  	mov    esi,0xc2
  7e0ff9:	31 c0                                           	xor    eax,eax
  7e0ffb:	e8 10 c4 a7 ff                                  	call   0x25d410
  7e1000:	41 8b b6 9c 00 00 00                            	mov    esi,DWORD PTR [r14+0x9c]
  7e1007:	4c 89 f2                                        	mov    rdx,r14
  7e100a:	48 8d 3d 96 b6 a8 00                            	lea    rdi,[rip+0xa8b696]        # 0x126c6a7
  7e1011:	4c 89 f9                                        	mov    rcx,r15
  7e1014:	45 89 e0                                        	mov    r8d,r12d
  7e1017:	45 31 c9                                        	xor    r9d,r9d
  7e101a:	31 c0                                           	xor    eax,eax
  7e101c:	48 81 c2 94 02 00 00                            	add    rdx,0x294
  7e1023:	e8 e8 c3 a7 ff                                  	call   0x25d410
  7e1028:	4c 89 f7                                        	mov    rdi,r14
  7e102b:	4c 89 fe                                        	mov    rsi,r15
  7e102e:	e8 ed e9 4b 00                                  	call   0xc9fa20
  7e1033:	eb 07                                           	jmp    0x7e103c
  7e1035:	41 c7 07 00 00 00 00                            	mov    DWORD PTR [r15],0x0
  7e103c:	48 8d 05 cd b2 13 03                            	lea    rax,[rip+0x313b2cd]        # 0x391c310
  7e1043:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  7e1046:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  7e104a:	75 11                                           	jne    0x7e105d
  7e104c:	89 d8                                           	mov    eax,ebx
  7e104e:	48 83 c4 48                                     	add    rsp,0x48
  7e1052:	5b                                              	pop    rbx
  7e1053:	41 5c                                           	pop    r12
  7e1055:	41 5d                                           	pop    r13
  7e1057:	41 5e                                           	pop    r14
  7e1059:	41 5f                                           	pop    r15
  7e105b:	5d                                              	pop    rbp
  7e105c:	c3                                              	ret
  7e105d:	e8 4e c6 f1 ff                                  	call   0x6fd6b0
  7e1062:	0f 0b                                           	ud2
  7e1064:	48 8d 3d c5 cc d5 01                            	lea    rdi,[rip+0x1d5ccc5]        # 0x253dd30
  7e106b:	4c 89 fe                                        	mov    rsi,r15
  7e106e:	e8 4d e8 c6 ff                                  	call   0x44f8c0
  7e1073:	e9 0a ff ff ff                                  	jmp    0x7e0f82
  7e1078:	90                                              	nop
  7e1079:	90                                              	nop
  7e107a:	90                                              	nop
  7e107b:	90                                              	nop
  7e107c:	90                                              	nop
  7e107d:	90                                              	nop
  7e107e:	90                                              	nop
  7e107f:	90                                              	nop
  7e1080:	55                                              	push   rbp
  7e1081:	48 89 e5                                        	mov    rbp,rsp
  7e1084:	41 57                                           	push   r15
  7e1086:	41 56                                           	push   r14
  7e1088:	41 55                                           	push   r13
  7e108a:	41 54                                           	push   r12
  7e108c:	53                                              	push   rbx
  7e108d:	48 83 ec 48                                     	sub    rsp,0x48
  7e1091:	48 8d 05 78 b2 13 03                            	lea    rax,[rip+0x313b278]        # 0x391c310
  7e1098:	4c 89 45 a0                                     	mov    QWORD PTR [rbp-0x60],r8
  7e109c:	48 89 7d 98                                     	mov    QWORD PTR [rbp-0x68],rdi
  7e10a0:	48 89 cb                                        	mov    rbx,rcx
  7e10a3:	49 89 d4                                        	mov    r12,rdx
  7e10a6:	49 89 f6                                        	mov    r14,rsi
  7e10a9:	48 8d 55 b0                                     	lea    rdx,[rbp-0x50]
  7e10ad:	48 8d 4d a8                                     	lea    rcx,[rbp-0x58]
  7e10b1:	45 89 cd                                        	mov    r13d,r9d
  7e10b4:	45 89 c8                                        	mov    r8d,r9d
  7e10b7:	41 b9 ff ff ff 03                               	mov    r9d,0x3ffffff
  7e10bd:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  7e10c0:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  7e10c4:	8b 7e 18                                        	mov    edi,DWORD PTR [rsi+0x18]
  7e10c7:	48 89 de                                        	mov    rsi,rbx
  7e10ca:	e8 41 00 bc ff                                  	call   0x3a1110
  7e10cf:	41 89 c7                                        	mov    r15d,eax
  7e10d2:	83 f8 23                                        	cmp    eax,0x23
  7e10d5:	77 26                                           	ja     0x7e10fd
  7e10d7:	44 89 f8                                        	mov    eax,r15d
  7e10da:	48 8d 0d fb fd f9 00                            	lea    rcx,[rip+0xf9fdfb]        # 0x1780edc
  7e10e1:	48 63 04 81                                     	movsxd rax,DWORD PTR [rcx+rax*4]
  7e10e5:	48 01 c8                                        	add    rax,rcx
  7e10e8:	ff e0                                           	jmp    rax
  7e10ea:	4c 89 f7                                        	mov    rdi,r14
  7e10ed:	e8 ae 5f 38 00                                  	call   0xb670a0
  7e10f2:	41 bc ff ff ff ff                               	mov    r12d,0xffffffff
  7e10f8:	e9 b2 02 00 00                                  	jmp    0x7e13af
  7e10fd:	41 83 ff 59                                     	cmp    r15d,0x59
  7e1101:	0f 85 d1 02 00 00                               	jne    0x7e13d8
  7e1107:	44 89 ef                                        	mov    edi,r13d
  7e110a:	4c 89 f6                                        	mov    rsi,r14
  7e110d:	ba ff ff ff 03                                  	mov    edx,0x3ffffff
  7e1112:	e8 99 6a 38 00                                  	call   0xb67bb0
  7e1117:	85 c0                                           	test   eax,eax
  7e1119:	74 08                                           	je     0x7e1123
  7e111b:	4c 89 f7                                        	mov    rdi,r14
  7e111e:	e8 7d 5f 38 00                                  	call   0xb670a0
  7e1123:	48 8b 4d 28                                     	mov    rcx,QWORD PTR [rbp+0x28]
  7e1127:	b8 20 03 02 a0                                  	mov    eax,0xa0020320
  7e112c:	41 bc 0c 00 00 00                               	mov    r12d,0xc
  7e1132:	48 89 41 10                                     	mov    QWORD PTR [rcx+0x10],rax
  7e1136:	80 09 0c                                        	or     BYTE PTR [rcx],0xc
  7e1139:	48 c7 41 08 00 00 00 00                         	mov    QWORD PTR [rcx+0x8],0x0
  7e1141:	e9 69 02 00 00                                  	jmp    0x7e13af
  7e1146:	48 8b 45 28                                     	mov    rax,QWORD PTR [rbp+0x28]
  7e114a:	44 89 ef                                        	mov    edi,r13d
  7e114d:	4c 89 f6                                        	mov    rsi,r14
  7e1150:	ba ff ff ff 03                                  	mov    edx,0x3ffffff
  7e1155:	48 c7 40 10 00 00 00 00                         	mov    QWORD PTR [rax+0x10],0x0
  7e115d:	80 08 0b                                        	or     BYTE PTR [rax],0xb
  7e1160:	48 c7 40 08 00 00 00 00                         	mov    QWORD PTR [rax+0x8],0x0
  7e1168:	e8 43 6a 38 00                                  	call   0xb67bb0
  7e116d:	41 bc 04 00 00 00                               	mov    r12d,0x4
  7e1173:	85 c0                                           	test   eax,eax
  7e1175:	0f 85 2c 02 00 00                               	jne    0x7e13a7
  7e117b:	e9 2f 02 00 00                                  	jmp    0x7e13af
  7e1180:	48 8b 45 b0                                     	mov    rax,QWORD PTR [rbp-0x50]
  7e1184:	4c 8b 4d a8                                     	mov    r9,QWORD PTR [rbp-0x58]
  7e1188:	4c 8b 78 10                                     	mov    r15,QWORD PTR [rax+0x10]
  7e118c:	49 83 c7 e8                                     	add    r15,0xffffffffffffffe8
  7e1190:	4c 39 fb                                        	cmp    rbx,r15
  7e1193:	73 4b                                           	jae    0x7e11e0
  7e1195:	4c 89 cf                                        	mov    rdi,r9
  7e1198:	e8 d3 fa bb ff                                  	call   0x3a0c70
  7e119d:	85 c0                                           	test   eax,eax
  7e119f:	0f 85 6d 02 00 00                               	jne    0x7e1412
  7e11a5:	44 89 ef                                        	mov    edi,r13d
  7e11a8:	4c 89 f6                                        	mov    rsi,r14
  7e11ab:	ba ff ff ff 03                                  	mov    edx,0x3ffffff
  7e11b0:	e8 fb 69 38 00                                  	call   0xb67bb0
  7e11b5:	85 c0                                           	test   eax,eax
  7e11b7:	74 08                                           	je     0x7e11c1
  7e11b9:	4c 89 f7                                        	mov    rdi,r14
  7e11bc:	e8 df 5e 38 00                                  	call   0xb670a0
  7e11c1:	48 8b 4d 28                                     	mov    rcx,QWORD PTR [rbp+0x28]
  7e11c5:	b8 20 03 02 a0                                  	mov    eax,0xa0020320
  7e11ca:	41 bc 0c 00 00 00                               	mov    r12d,0xc
  7e11d0:	48 89 41 10                                     	mov    QWORD PTR [rcx+0x10],rax
  7e11d4:	80 09 0d                                        	or     BYTE PTR [rcx],0xd
  7e11d7:	4c 89 79 08                                     	mov    QWORD PTR [rcx+0x8],r15
  7e11db:	e9 cf 01 00 00                                  	jmp    0x7e13af
  7e11e0:	48 8b 5d 18                                     	mov    rbx,QWORD PTR [rbp+0x18]
  7e11e4:	48 8b 55 10                                     	mov    rdx,QWORD PTR [rbp+0x10]
  7e11e8:	48 83 ec 08                                     	sub    rsp,0x8
  7e11ec:	4c 8b 45 a0                                     	mov    r8,QWORD PTR [rbp-0x60]
  7e11f0:	4c 89 e7                                        	mov    rdi,r12
  7e11f3:	4c 89 f6                                        	mov    rsi,r14
  7e11f6:	44 89 e9                                        	mov    ecx,r13d
  7e11f9:	ff 75 28                                        	push   QWORD PTR [rbp+0x28]
  7e11fc:	53                                              	push   rbx
  7e11fd:	50                                              	push   rax
  7e11fe:	e8 9d 05 00 00                                  	call   0x7e17a0
  7e1203:	48 83 c4 20                                     	add    rsp,0x20
  7e1207:	41 89 c4                                        	mov    r12d,eax
  7e120a:	85 c0                                           	test   eax,eax
  7e120c:	0f 85 9d 01 00 00                               	jne    0x7e13af
  7e1212:	48 8b 55 20                                     	mov    rdx,QWORD PTR [rbp+0x20]
  7e1216:	8b 43 08                                        	mov    eax,DWORD PTR [rbx+0x8]
  7e1219:	83 f8 03                                        	cmp    eax,0x3
  7e121c:	0f 85 9c 00 00 00                               	jne    0x7e12be
  7e1222:	8b 5b 0c                                        	mov    ebx,DWORD PTR [rbx+0xc]
  7e1225:	48 8d 55 b8                                     	lea    rdx,[rbp-0x48]
  7e1229:	be 04 80 00 00                                  	mov    esi,0x8004
  7e122e:	b9 ff ff ff 07                                  	mov    ecx,0x7ffffff
  7e1233:	89 df                                           	mov    edi,ebx
  7e1235:	e8 d6 d9 e2 ff                                  	call   0x60ec10
  7e123a:	b9 ff ff ff ff                                  	mov    ecx,0xffffffff
  7e123f:	41 bf ff ff ff ff                               	mov    r15d,0xffffffff
  7e1245:	41 bc ff ff ff ff                               	mov    r12d,0xffffffff
  7e124b:	85 c0                                           	test   eax,eax
  7e124d:	0f 85 1c 01 00 00                               	jne    0x7e136f
  7e1253:	48 8b 45 b8                                     	mov    rax,QWORD PTR [rbp-0x48]
  7e1257:	48 8b 78 28                                     	mov    rdi,QWORD PTR [rax+0x28]
  7e125b:	48 8b 87 60 04 00 00                            	mov    rax,QWORD PTR [rdi+0x460]
  7e1262:	48 85 c0                                        	test   rax,rax
  7e1265:	74 04                                           	je     0x7e126b
  7e1267:	44 8b 78 08                                     	mov    r15d,DWORD PTR [rax+0x8]
  7e126b:	48 8b 87 98 01 00 00                            	mov    rax,QWORD PTR [rdi+0x198]
  7e1272:	48 85 c0                                        	test   rax,rax
  7e1275:	74 03                                           	je     0x7e127a
  7e1277:	8b 48 10                                        	mov    ecx,DWORD PTR [rax+0x10]
  7e127a:	89 4d a0                                        	mov    DWORD PTR [rbp-0x60],ecx
  7e127d:	31 f6                                           	xor    esi,esi
  7e127f:	31 d2                                           	xor    edx,edx
  7e1281:	31 c9                                           	xor    ecx,ecx
  7e1283:	e8 98 a8 46 00                                  	call   0xc4bb20
  7e1288:	48 8b 45 b8                                     	mov    rax,QWORD PTR [rbp-0x48]
  7e128c:	48 8b 40 28                                     	mov    rax,QWORD PTR [rax+0x28]
  7e1290:	8b 48 20                                        	mov    ecx,DWORD PTR [rax+0x20]
  7e1293:	89 ca                                           	mov    edx,ecx
  7e1295:	81 e2 20 03 00 08                               	and    edx,0x8000320
  7e129b:	81 fa 00 00 00 08                               	cmp    edx,0x8000000
  7e12a1:	0f 85 a6 00 00 00                               	jne    0x7e134d
  7e12a7:	83 b8 00 09 00 00 00                            	cmp    DWORD PTR [rax+0x900],0x0
  7e12ae:	74 3b                                           	je     0x7e12eb
  7e12b0:	81 c9 00 01 00 00                               	or     ecx,0x100
  7e12b6:	89 48 20                                        	mov    DWORD PTR [rax+0x20],ecx
  7e12b9:	e9 8f 00 00 00                                  	jmp    0x7e134d
  7e12be:	83 c8 10                                        	or     eax,0x10
  7e12c1:	89 c1                                           	mov    ecx,eax
  7e12c3:	81 e1 ff 7f ff ff                               	and    ecx,0xffff7fff
  7e12c9:	83 f9 51                                        	cmp    ecx,0x51
  7e12cc:	74 09                                           	je     0x7e12d7
  7e12ce:	83 f8 53                                        	cmp    eax,0x53
  7e12d1:	0f 85 95 01 00 00                               	jne    0x7e146c
  7e12d7:	48 8b 7d 98                                     	mov    rdi,QWORD PTR [rbp-0x68]
  7e12db:	48 89 de                                        	mov    rsi,rbx
  7e12de:	e8 3d 06 00 00                                  	call   0x7e1920
  7e12e3:	41 89 c4                                        	mov    r12d,eax
  7e12e6:	e9 a7 00 00 00                                  	jmp    0x7e1392
  7e12eb:	48 8d 7d c0                                     	lea    rdi,[rbp-0x40]
  7e12ef:	e8 bc df 2e 00                                  	call   0xacf2b0
  7e12f4:	48 b8 cf f7 53 e3 a5 9b c4 20                   	movabs rax,0x20c49ba5e353f7cf
  7e12fe:	48 69 4d c0 40 42 0f 00                         	imul   rcx,QWORD PTR [rbp-0x40],0xf4240
  7e1306:	48 8b 75 98                                     	mov    rsi,QWORD PTR [rbp-0x68]
  7e130a:	45 31 e4                                        	xor    r12d,r12d
  7e130d:	48 f7 6d c8                                     	imul   QWORD PTR [rbp-0x38]
  7e1311:	48 89 d0                                        	mov    rax,rdx
  7e1314:	48 c1 fa 07                                     	sar    rdx,0x7
  7e1318:	48 c1 e8 3f                                     	shr    rax,0x3f
  7e131c:	48 01 c2                                        	add    rdx,rax
  7e131f:	48 01 ca                                        	add    rdx,rcx
  7e1322:	48 8b 4d b8                                     	mov    rcx,QWORD PTR [rbp-0x48]
  7e1326:	48 8b 41 28                                     	mov    rax,QWORD PTR [rcx+0x28]
  7e132a:	48 8b 4d 18                                     	mov    rcx,QWORD PTR [rbp+0x18]
  7e132e:	83 48 20 20                                     	or     DWORD PTR [rax+0x20],0x20
  7e1332:	48 8b 45 b8                                     	mov    rax,QWORD PTR [rbp-0x48]
  7e1336:	8b 49 08                                        	mov    ecx,DWORD PTR [rcx+0x8]
  7e1339:	8b b6 9c 00 00 00                               	mov    esi,DWORD PTR [rsi+0x9c]
  7e133f:	48 8b 40 28                                     	mov    rax,QWORD PTR [rax+0x28]
  7e1343:	89 48 48                                        	mov    DWORD PTR [rax+0x48],ecx
  7e1346:	89 70 4c                                        	mov    DWORD PTR [rax+0x4c],esi
  7e1349:	48 89 50 50                                     	mov    QWORD PTR [rax+0x50],rdx
  7e134d:	48 8b 45 b8                                     	mov    rax,QWORD PTR [rbp-0x48]
  7e1351:	31 f6                                           	xor    esi,esi
  7e1353:	31 d2                                           	xor    edx,edx
  7e1355:	48 8b 78 28                                     	mov    rdi,QWORD PTR [rax+0x28]
  7e1359:	e8 52 b1 46 00                                  	call   0xc4c4b0
  7e135e:	89 df                                           	mov    edi,ebx
  7e1360:	be 04 80 00 00                                  	mov    esi,0x8004
  7e1365:	31 d2                                           	xor    edx,edx
  7e1367:	e8 64 d9 e2 ff                                  	call   0x60ecd0
  7e136c:	8b 4d a0                                        	mov    ecx,DWORD PTR [rbp-0x60]
  7e136f:	48 8b 45 20                                     	mov    rax,QWORD PTR [rbp+0x20]
  7e1373:	c7 00 0c 17 00 00                               	mov    DWORD PTR [rax],0x170c
  7e1379:	44 89 78 08                                     	mov    DWORD PTR [rax+0x8],r15d
  7e137d:	89 58 0c                                        	mov    DWORD PTR [rax+0xc],ebx
  7e1380:	89 48 10                                        	mov    DWORD PTR [rax+0x10],ecx
  7e1383:	c7 40 14 03 00 00 00                            	mov    DWORD PTR [rax+0x14],0x3
  7e138a:	48 c7 40 18 00 00 00 00                         	mov    QWORD PTR [rax+0x18],0x0
  7e1392:	48 8b 7d a8                                     	mov    rdi,QWORD PTR [rbp-0x58]
  7e1396:	48 8b 75 b0                                     	mov    rsi,QWORD PTR [rbp-0x50]
  7e139a:	e8 d1 f9 bb ff                                  	call   0x3a0d70
  7e139f:	85 c0                                           	test   eax,eax
  7e13a1:	0f 85 92 00 00 00                               	jne    0x7e1439
  7e13a7:	4c 89 f7                                        	mov    rdi,r14
  7e13aa:	e8 f1 5c 38 00                                  	call   0xb670a0
  7e13af:	48 8d 05 5a af 13 03                            	lea    rax,[rip+0x313af5a]        # 0x391c310
  7e13b6:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  7e13b9:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  7e13bd:	75 12                                           	jne    0x7e13d1
  7e13bf:	44 89 e0                                        	mov    eax,r12d
  7e13c2:	48 83 c4 48                                     	add    rsp,0x48
  7e13c6:	5b                                              	pop    rbx
  7e13c7:	41 5c                                           	pop    r12
  7e13c9:	41 5d                                           	pop    r13
  7e13cb:	41 5e                                           	pop    r14
  7e13cd:	41 5f                                           	pop    r15
  7e13cf:	5d                                              	pop    rbp
  7e13d0:	c3                                              	ret
  7e13d1:	e8 da c2 f1 ff                                  	call   0x6fd6b0
  7e13d6:	0f 0b                                           	ud2
  7e13d8:	e8 73 05 01 00                                  	call   0x7f1950
  7e13dd:	49 63 56 18                                     	movsxd rdx,DWORD PTR [r14+0x18]
  7e13e1:	49 63 f5                                        	movsxd rsi,r13d
  7e13e4:	49 63 cf                                        	movsxd rcx,r15d
  7e13e7:	48 8d 3d ea ff ff ff                            	lea    rdi,[rip+0xffffffffffffffea]        # 0x7e13d8
  7e13ee:	e8 cd 0c 01 00                                  	call   0x7f20c0
  7e13f3:	41 8b 4e 18                                     	mov    ecx,DWORD PTR [r14+0x18]
  7e13f7:	48 8d 35 33 8a b6 00                            	lea    rsi,[rip+0xb68a33]        # 0x1349e31
  7e13fe:	bf 1c 00 00 00                                  	mov    edi,0x1c
  7e1403:	44 89 ea                                        	mov    edx,r13d
  7e1406:	45 89 f8                                        	mov    r8d,r15d
  7e1409:	31 c0                                           	xor    eax,eax
  7e140b:	e8 00 96 4b 00                                  	call   0xc9aa10
  7e1410:	0f 0b                                           	ud2
  7e1412:	89 c3                                           	mov    ebx,eax
  7e1414:	e8 37 05 01 00                                  	call   0x7f1950
  7e1419:	49 63 f5                                        	movsxd rsi,r13d
  7e141c:	48 63 d3                                        	movsxd rdx,ebx
  7e141f:	48 8d 3d ec ff ff ff                            	lea    rdi,[rip+0xffffffffffffffec]        # 0x7e1412
  7e1426:	e8 e5 0b 01 00                                  	call   0x7f2010
  7e142b:	48 8d 35 ff 76 ba 00                            	lea    rsi,[rip+0xba76ff]        # 0x1388b31
  7e1432:	bf 10 00 00 00                                  	mov    edi,0x10
  7e1437:	eb 25                                           	jmp    0x7e145e
  7e1439:	89 c3                                           	mov    ebx,eax
  7e143b:	e8 10 05 01 00                                  	call   0x7f1950
  7e1440:	49 63 f5                                        	movsxd rsi,r13d
  7e1443:	48 63 d3                                        	movsxd rdx,ebx
  7e1446:	48 8d 3d ec ff ff ff                            	lea    rdi,[rip+0xffffffffffffffec]        # 0x7e1439
  7e144d:	e8 be 0b 01 00                                  	call   0x7f2010
  7e1452:	48 8d 35 25 39 b7 00                            	lea    rsi,[rip+0xb73925]        # 0x1354d7e
  7e1459:	bf 18 00 00 00                                  	mov    edi,0x18
  7e145e:	44 89 ea                                        	mov    edx,r13d
  7e1461:	89 d9                                           	mov    ecx,ebx
  7e1463:	31 c0                                           	xor    eax,eax
  7e1465:	e8 a6 95 4b 00                                  	call   0xc9aa10
  7e146a:	0f 0b                                           	ud2
  7e146c:	e8 df 04 01 00                                  	call   0x7f1950
  7e1471:	48 63 53 08                                     	movsxd rdx,DWORD PTR [rbx+0x8]
  7e1475:	49 63 f5                                        	movsxd rsi,r13d
  7e1478:	48 8d 3d ed ff ff ff                            	lea    rdi,[rip+0xffffffffffffffed]        # 0x7e146c
  7e147f:	e8 8c 0b 01 00                                  	call   0x7f2010
  7e1484:	8b 4b 08                                        	mov    ecx,DWORD PTR [rbx+0x8]
  7e1487:	48 8d 35 5c 0a ae 00                            	lea    rsi,[rip+0xae0a5c]        # 0x12c1eea
  7e148e:	bf 14 00 00 00                                  	mov    edi,0x14
  7e1493:	44 89 ea                                        	mov    edx,r13d
  7e1496:	eb cb                                           	jmp    0x7e1463
  7e1498:	90                                              	nop
  7e1499:	90                                              	nop
  7e149a:	90                                              	nop
  7e149b:	90                                              	nop
  7e149c:	90                                              	nop
  7e149d:	90                                              	nop
  7e149e:	90                                              	nop
  7e149f:	90                                              	nop
  7e14a0:	55                                              	push   rbp
  7e14a1:	48 89 e5                                        	mov    rbp,rsp
  7e14a4:	41 57                                           	push   r15
  7e14a6:	41 56                                           	push   r14
  7e14a8:	41 55                                           	push   r13
  7e14aa:	41 54                                           	push   r12
  7e14ac:	53                                              	push   rbx
  7e14ad:	48 83 ec 58                                     	sub    rsp,0x58
  7e14b1:	48 8d 05 58 ae 13 03                            	lea    rax,[rip+0x313ae58]        # 0x391c310
  7e14b8:	4c 89 4d 88                                     	mov    QWORD PTR [rbp-0x78],r9
  7e14bc:	4c 89 45 80                                     	mov    QWORD PTR [rbp-0x80],r8
  7e14c0:	49 89 cd                                        	mov    r13,rcx
  7e14c3:	49 89 d4                                        	mov    r12,rdx
  7e14c6:	49 89 f7                                        	mov    r15,rsi
  7e14c9:	48 89 fb                                        	mov    rbx,rdi
  7e14cc:	48 8d 55 b8                                     	lea    rdx,[rbp-0x48]
  7e14d0:	b9 ff ff ff 03                                  	mov    ecx,0x3ffffff
  7e14d5:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  7e14d8:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  7e14dc:	44 8b 76 18                                     	mov    r14d,DWORD PTR [rsi+0x18]
  7e14e0:	be 02 80 00 00                                  	mov    esi,0x8002
  7e14e5:	44 89 f7                                        	mov    edi,r14d
  7e14e8:	e8 23 d7 e2 ff                                  	call   0x60ec10
  7e14ed:	85 c0                                           	test   eax,eax
  7e14ef:	74 0d                                           	je     0x7e14fe
  7e14f1:	4c 89 ff                                        	mov    rdi,r15
  7e14f4:	e8 a7 5b 38 00                                  	call   0xb670a0
  7e14f9:	e9 95 00 00 00                                  	jmp    0x7e1593
  7e14fe:	48 8b 45 b8                                     	mov    rax,QWORD PTR [rbp-0x48]
  7e1502:	4c 89 7d a0                                     	mov    QWORD PTR [rbp-0x60],r15
  7e1506:	44 89 75 ac                                     	mov    DWORD PTR [rbp-0x54],r14d
  7e150a:	31 f6                                           	xor    esi,esi
  7e150c:	31 d2                                           	xor    edx,edx
  7e150e:	31 c9                                           	xor    ecx,ecx
  7e1510:	48 8b 78 28                                     	mov    rdi,QWORD PTR [rax+0x28]
  7e1514:	48 8b 87 68 04 00 00                            	mov    rax,QWORD PTR [rdi+0x468]
  7e151b:	48 89 45 b0                                     	mov    QWORD PTR [rbp-0x50],rax
  7e151f:	e8 fc a5 46 00                                  	call   0xc4bb20
  7e1524:	48 8b 45 b8                                     	mov    rax,QWORD PTR [rbp-0x48]
  7e1528:	48 8b 78 28                                     	mov    rdi,QWORD PTR [rax+0x28]
  7e152c:	48 8b 87 98 01 00 00                            	mov    rax,QWORD PTR [rdi+0x198]
  7e1533:	48 85 c0                                        	test   rax,rax
  7e1536:	74 09                                           	je     0x7e1541
  7e1538:	44 8b 78 08                                     	mov    r15d,DWORD PTR [rax+0x8]
  7e153c:	8b 50 10                                        	mov    edx,DWORD PTR [rax+0x10]
  7e153f:	eb 0b                                           	jmp    0x7e154c
  7e1541:	41 bf ff ff ff ff                               	mov    r15d,0xffffffff
  7e1547:	ba ff ff ff ff                                  	mov    edx,0xffffffff
  7e154c:	8b 47 20                                        	mov    eax,DWORD PTR [rdi+0x20]
  7e154f:	49 89 de                                        	mov    r14,rbx
  7e1552:	89 c1                                           	mov    ecx,eax
  7e1554:	81 e1 20 00 02 00                               	and    ecx,0x20020
  7e155a:	81 f9 00 00 02 00                               	cmp    ecx,0x20000
  7e1560:	75 19                                           	jne    0x7e157b
  7e1562:	83 bf 00 09 00 00 00                            	cmp    DWORD PTR [rdi+0x900],0x0
  7e1569:	74 50                                           	je     0x7e15bb
  7e156b:	0d 00 02 00 00                                  	or     eax,0x200
  7e1570:	89 47 20                                        	mov    DWORD PTR [rdi+0x20],eax
  7e1573:	48 8b 45 b8                                     	mov    rax,QWORD PTR [rbp-0x48]
  7e1577:	48 8b 78 28                                     	mov    rdi,QWORD PTR [rax+0x28]
  7e157b:	31 f6                                           	xor    esi,esi
  7e157d:	31 d2                                           	xor    edx,edx
  7e157f:	e8 2c af 46 00                                  	call   0xc4c4b0
  7e1584:	8b 7d ac                                        	mov    edi,DWORD PTR [rbp-0x54]
  7e1587:	be 02 80 00 00                                  	mov    esi,0x8002
  7e158c:	31 d2                                           	xor    edx,edx
  7e158e:	e8 3d d7 e2 ff                                  	call   0x60ecd0
  7e1593:	b8 ff ff ff ff                                  	mov    eax,0xffffffff
  7e1598:	48 8d 0d 71 ad 13 03                            	lea    rcx,[rip+0x313ad71]        # 0x391c310
  7e159f:	48 8b 09                                        	mov    rcx,QWORD PTR [rcx]
  7e15a2:	48 3b 4d d0                                     	cmp    rcx,QWORD PTR [rbp-0x30]
  7e15a6:	0f 85 c1 01 00 00                               	jne    0x7e176d
  7e15ac:	48 83 c4 58                                     	add    rsp,0x58
  7e15b0:	5b                                              	pop    rbx
  7e15b1:	41 5c                                           	pop    r12
  7e15b3:	41 5d                                           	pop    r13
  7e15b5:	41 5e                                           	pop    r14
  7e15b7:	41 5f                                           	pop    r15
  7e15b9:	5d                                              	pop    rbp
  7e15ba:	c3                                              	ret
  7e15bb:	48 8b 4d a0                                     	mov    rcx,QWORD PTR [rbp-0x60]
  7e15bf:	83 c8 20                                        	or     eax,0x20
  7e15c2:	bb a0 00 00 00                                  	mov    ebx,0xa0
  7e15c7:	89 55 94                                        	mov    DWORD PTR [rbp-0x6c],edx
  7e15ca:	8b 49 10                                        	mov    ecx,DWORD PTR [rcx+0x10]
  7e15cd:	89 47 20                                        	mov    DWORD PTR [rdi+0x20],eax
  7e15d0:	8b 45 ac                                        	mov    eax,DWORD PTR [rbp-0x54]
  7e15d3:	89 4d 9c                                        	mov    DWORD PTR [rbp-0x64],ecx
  7e15d6:	83 f9 50                                        	cmp    ecx,0x50
  7e15d9:	75 55                                           	jne    0x7e1630
  7e15db:	48 8d 7d c0                                     	lea    rdi,[rbp-0x40]
  7e15df:	e8 cc dc 2e 00                                  	call   0xacf2b0
  7e15e4:	48 b8 cf f7 53 e3 a5 9b c4 20                   	movabs rax,0x20c49ba5e353f7cf
  7e15ee:	48 69 4d c0 40 42 0f 00                         	imul   rcx,QWORD PTR [rbp-0x40],0xf4240
  7e15f6:	48 8b 75 b8                                     	mov    rsi,QWORD PTR [rbp-0x48]
  7e15fa:	bb 03 00 00 00                                  	mov    ebx,0x3
  7e15ff:	48 f7 6d c8                                     	imul   QWORD PTR [rbp-0x38]
  7e1603:	48 89 d0                                        	mov    rax,rdx
  7e1606:	48 c1 fa 07                                     	sar    rdx,0x7
  7e160a:	48 c1 e8 3f                                     	shr    rax,0x3f
  7e160e:	48 01 c2                                        	add    rdx,rax
  7e1611:	48 8b 46 28                                     	mov    rax,QWORD PTR [rsi+0x28]
  7e1615:	48 01 ca                                        	add    rdx,rcx
  7e1618:	41 8b 8e 9c 00 00 00                            	mov    ecx,DWORD PTR [r14+0x9c]
  7e161f:	c7 40 48 03 00 00 00                            	mov    DWORD PTR [rax+0x48],0x3
  7e1626:	89 48 4c                                        	mov    DWORD PTR [rax+0x4c],ecx
  7e1629:	48 89 50 50                                     	mov    QWORD PTR [rax+0x50],rdx
  7e162d:	44 89 f8                                        	mov    eax,r15d
  7e1630:	48 8b 4d b8                                     	mov    rcx,QWORD PTR [rbp-0x48]
  7e1634:	44 89 7d 98                                     	mov    DWORD PTR [rbp-0x68],r15d
  7e1638:	41 89 c6                                        	mov    r14d,eax
  7e163b:	31 f6                                           	xor    esi,esi
  7e163d:	31 d2                                           	xor    edx,edx
  7e163f:	48 8b 79 28                                     	mov    rdi,QWORD PTR [rcx+0x28]
  7e1643:	e8 68 ae 46 00                                  	call   0xc4c4b0
  7e1648:	8b 7d ac                                        	mov    edi,DWORD PTR [rbp-0x54]
  7e164b:	be 02 80 00 00                                  	mov    esi,0x8002
  7e1650:	31 d2                                           	xor    edx,edx
  7e1652:	e8 79 d6 e2 ff                                  	call   0x60ecd0
  7e1657:	4c 8b 7d 88                                     	mov    r15,QWORD PTR [rbp-0x78]
  7e165b:	48 8b 45 80                                     	mov    rax,QWORD PTR [rbp-0x80]
  7e165f:	48 8d 35 31 dc b6 00                            	lea    rsi,[rip+0xb6dc31]        # 0x134f297
  7e1666:	31 d2                                           	xor    edx,edx
  7e1668:	41 89 5f 08                                     	mov    DWORD PTR [r15+0x8],ebx
  7e166c:	45 89 77 0c                                     	mov    DWORD PTR [r15+0xc],r14d
  7e1670:	49 c7 07 08 00 00 00                            	mov    QWORD PTR [r15],0x8
  7e1677:	49 89 47 10                                     	mov    QWORD PTR [r15+0x10],rax
  7e167b:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  7e1684:	e8 57 8d 43 00                                  	call   0xc1a3e0
  7e1689:	ba 18 00 00 00                                  	mov    edx,0x18
  7e168e:	4c 89 ff                                        	mov    rdi,r15
  7e1691:	4c 89 ee                                        	mov    rsi,r13
  7e1694:	e8 37 7b a7 ff                                  	call   0x2591d0
  7e1699:	85 c0                                           	test   eax,eax
  7e169b:	74 26                                           	je     0x7e16c3
  7e169d:	48 8b 7d a0                                     	mov    rdi,QWORD PTR [rbp-0x60]
  7e16a1:	89 c3                                           	mov    ebx,eax
  7e16a3:	e8 f8 59 38 00                                  	call   0xb670a0
  7e16a8:	48 8b 55 18                                     	mov    rdx,QWORD PTR [rbp+0x18]
  7e16ac:	b9 20 03 02 a0                                  	mov    ecx,0xa0020320
  7e16b1:	89 d8                                           	mov    eax,ebx
  7e16b3:	48 89 4a 10                                     	mov    QWORD PTR [rdx+0x10],rcx
  7e16b7:	80 0a 10                                        	or     BYTE PTR [rdx],0x10
  7e16ba:	4c 89 6a 08                                     	mov    QWORD PTR [rdx+0x8],r13
  7e16be:	e9 d5 fe ff ff                                  	jmp    0x7e1598
  7e16c3:	4c 8b 75 18                                     	mov    r14,QWORD PTR [rbp+0x18]
  7e16c7:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  7e16d0:	48 8d 35 c0 db b6 00                            	lea    rsi,[rip+0xb6dbc0]        # 0x134f297
  7e16d7:	31 d2                                           	xor    edx,edx
  7e16d9:	e8 02 8d 43 00                                  	call   0xc1a3e0
  7e16de:	48 8d 7d b0                                     	lea    rdi,[rbp-0x50]
  7e16e2:	ba 08 00 00 00                                  	mov    edx,0x8
  7e16e7:	4c 89 e6                                        	mov    rsi,r12
  7e16ea:	e8 e1 7a a7 ff                                  	call   0x2591d0
  7e16ef:	85 c0                                           	test   eax,eax
  7e16f1:	74 23                                           	je     0x7e1716
  7e16f3:	48 8b 7d a0                                     	mov    rdi,QWORD PTR [rbp-0x60]
  7e16f7:	89 c3                                           	mov    ebx,eax
  7e16f9:	e8 a2 59 38 00                                  	call   0xb670a0
  7e16fe:	b9 20 03 02 a0                                  	mov    ecx,0xa0020320
  7e1703:	89 d8                                           	mov    eax,ebx
  7e1705:	49 89 4e 10                                     	mov    QWORD PTR [r14+0x10],rcx
  7e1709:	41 80 0e 11                                     	or     BYTE PTR [r14],0x11
  7e170d:	4d 89 66 08                                     	mov    QWORD PTR [r14+0x8],r12
  7e1711:	e9 82 fe ff ff                                  	jmp    0x7e1598
  7e1716:	48 8b 45 88                                     	mov    rax,QWORD PTR [rbp-0x78]
  7e171a:	8b 55 94                                        	mov    edx,DWORD PTR [rbp-0x6c]
  7e171d:	8b 75 ac                                        	mov    esi,DWORD PTR [rbp-0x54]
  7e1720:	48 8b 7d a0                                     	mov    rdi,QWORD PTR [rbp-0x60]
  7e1724:	4c 63 78 08                                     	movsxd r15,DWORD PTR [rax+0x8]
  7e1728:	b8 0c 17 00 00                                  	mov    eax,0x170c
  7e172d:	49 83 ff 03                                     	cmp    r15,0x3
  7e1731:	74 0e                                           	je     0x7e1741
  7e1733:	41 81 ff a0 00 00 00                            	cmp    r15d,0xa0
  7e173a:	75 38                                           	jne    0x7e1774
  7e173c:	b8 0f 17 00 00                                  	mov    eax,0x170f
  7e1741:	48 8b 4d 10                                     	mov    rcx,QWORD PTR [rbp+0x10]
  7e1745:	89 01                                           	mov    DWORD PTR [rcx],eax
  7e1747:	89 71 08                                        	mov    DWORD PTR [rcx+0x8],esi
  7e174a:	8b 75 98                                        	mov    esi,DWORD PTR [rbp-0x68]
  7e174d:	89 71 0c                                        	mov    DWORD PTR [rcx+0xc],esi
  7e1750:	89 51 10                                        	mov    DWORD PTR [rcx+0x10],edx
  7e1753:	8b 55 9c                                        	mov    edx,DWORD PTR [rbp-0x64]
  7e1756:	89 51 14                                        	mov    DWORD PTR [rcx+0x14],edx
  7e1759:	48 c7 41 18 00 00 00 00                         	mov    QWORD PTR [rcx+0x18],0x0
  7e1761:	e8 3a 59 38 00                                  	call   0xb670a0
  7e1766:	31 c0                                           	xor    eax,eax
  7e1768:	e9 2b fe ff ff                                  	jmp    0x7e1598
  7e176d:	e8 3e bf f1 ff                                  	call   0x6fd6b0
  7e1772:	0f 0b                                           	ud2
  7e1774:	e8 d7 01 01 00                                  	call   0x7f1950
  7e1779:	48 8d 3d f4 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff4]        # 0x7e1774
  7e1780:	4c 89 fe                                        	mov    rsi,r15
  7e1783:	e8 18 01 01 00                                  	call   0x7f18a0
  7e1788:	48 8d 35 87 22 ac 00                            	lea    rsi,[rip+0xac2287]        # 0x12a3a16
  7e178f:	bf 20 00 00 00                                  	mov    edi,0x20
  7e1794:	44 89 fa                                        	mov    edx,r15d
  7e1797:	31 c0                                           	xor    eax,eax
  7e1799:	e8 72 92 4b 00                                  	call   0xc9aa10
  7e179e:	0f 0b                                           	ud2
  7e17a0:	55                                              	push   rbp
  7e17a1:	48 89 e5                                        	mov    rbp,rsp
  7e17a4:	41 57                                           	push   r15
  7e17a6:	41 56                                           	push   r14
  7e17a8:	41 55                                           	push   r13
  7e17aa:	41 54                                           	push   r12
  7e17ac:	53                                              	push   rbx
  7e17ad:	48 83 ec 18                                     	sub    rsp,0x18
  7e17b1:	48 8b 5d 18                                     	mov    rbx,QWORD PTR [rbp+0x18]
  7e17b5:	48 89 75 c8                                     	mov    QWORD PTR [rbp-0x38],rsi
  7e17b9:	48 8b 75 10                                     	mov    rsi,QWORD PTR [rbp+0x10]
  7e17bd:	89 4d d4                                        	mov    DWORD PTR [rbp-0x2c],ecx
  7e17c0:	48 89 7d c0                                     	mov    QWORD PTR [rbp-0x40],rdi
  7e17c4:	b9 30 00 00 00                                  	mov    ecx,0x30
  7e17c9:	49 89 d4                                        	mov    r12,rdx
  7e17cc:	4d 89 cd                                        	mov    r13,r9
  7e17cf:	4d 89 c7                                        	mov    r15,r8
  7e17d2:	45 31 f6                                        	xor    r14d,r14d
  7e17d5:	31 d2                                           	xor    edx,edx
  7e17d7:	48 89 df                                        	mov    rdi,rbx
  7e17da:	e8 31 db bb ff                                  	call   0x39f310
  7e17df:	4c 89 63 10                                     	mov    QWORD PTR [rbx+0x10],r12
  7e17e3:	48 8d 35 ad da b6 00                            	lea    rsi,[rip+0xb6daad]        # 0x134f297
  7e17ea:	31 d2                                           	xor    edx,edx
  7e17ec:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  7e17f5:	e8 e6 8b 43 00                                  	call   0xc1a3e0
  7e17fa:	ba 18 00 00 00                                  	mov    edx,0x18
  7e17ff:	48 89 df                                        	mov    rdi,rbx
  7e1802:	4c 89 fe                                        	mov    rsi,r15
  7e1805:	e8 c6 79 a7 ff                                  	call   0x2591d0
  7e180a:	85 c0                                           	test   eax,eax
  7e180c:	74 2e                                           	je     0x7e183c
  7e180e:	4c 89 ef                                        	mov    rdi,r13
  7e1811:	41 89 c4                                        	mov    r12d,eax
  7e1814:	e8 57 f4 bb ff                                  	call   0x3a0c70
  7e1819:	85 c0                                           	test   eax,eax
  7e181b:	0f 85 96 00 00 00                               	jne    0x7e18b7
  7e1821:	4c 8b 6d c8                                     	mov    r13,QWORD PTR [rbp-0x38]
  7e1825:	8b 7d d4                                        	mov    edi,DWORD PTR [rbp-0x2c]
  7e1828:	ba ff ff ff 03                                  	mov    edx,0x3ffffff
  7e182d:	4c 89 ee                                        	mov    rsi,r13
  7e1830:	e8 7b 63 38 00                                  	call   0xb67bb0
  7e1835:	bb 0e 00 00 00                                  	mov    ebx,0xe
  7e183a:	eb 44                                           	jmp    0x7e1880
  7e183c:	4c 8b 7d c0                                     	mov    r15,QWORD PTR [rbp-0x40]
  7e1840:	48 8b 0b                                        	mov    rcx,QWORD PTR [rbx]
  7e1843:	48 8b 75 10                                     	mov    rsi,QWORD PTR [rbp+0x10]
  7e1847:	ba 30 00 00 00                                  	mov    edx,0x30
  7e184c:	4c 89 ff                                        	mov    rdi,r15
  7e184f:	e8 8c dc bb ff                                  	call   0x39f4e0
  7e1854:	85 c0                                           	test   eax,eax
  7e1856:	74 4d                                           	je     0x7e18a5
  7e1858:	4c 89 ef                                        	mov    rdi,r13
  7e185b:	41 89 c4                                        	mov    r12d,eax
  7e185e:	e8 0d f4 bb ff                                  	call   0x3a0c70
  7e1863:	85 c0                                           	test   eax,eax
  7e1865:	75 7e                                           	jne    0x7e18e5
  7e1867:	4c 8b 6d c8                                     	mov    r13,QWORD PTR [rbp-0x38]
  7e186b:	8b 7d d4                                        	mov    edi,DWORD PTR [rbp-0x2c]
  7e186e:	ba ff ff ff 03                                  	mov    edx,0x3ffffff
  7e1873:	4c 89 ee                                        	mov    rsi,r13
  7e1876:	e8 35 63 38 00                                  	call   0xb67bb0
  7e187b:	bb 0f 00 00 00                                  	mov    ebx,0xf
  7e1880:	45 89 e6                                        	mov    r14d,r12d
  7e1883:	85 c0                                           	test   eax,eax
  7e1885:	74 0b                                           	je     0x7e1892
  7e1887:	4c 89 ef                                        	mov    rdi,r13
  7e188a:	e8 11 58 38 00                                  	call   0xb670a0
  7e188f:	45 89 e6                                        	mov    r14d,r12d
  7e1892:	48 8b 45 20                                     	mov    rax,QWORD PTR [rbp+0x20]
  7e1896:	b9 20 03 02 a0                                  	mov    ecx,0xa0020320
  7e189b:	48 89 48 10                                     	mov    QWORD PTR [rax+0x10],rcx
  7e189f:	09 18                                           	or     DWORD PTR [rax],ebx
  7e18a1:	4c 89 78 08                                     	mov    QWORD PTR [rax+0x8],r15
  7e18a5:	44 89 f0                                        	mov    eax,r14d
  7e18a8:	48 83 c4 18                                     	add    rsp,0x18
  7e18ac:	5b                                              	pop    rbx
  7e18ad:	41 5c                                           	pop    r12
  7e18af:	41 5d                                           	pop    r13
  7e18b1:	41 5e                                           	pop    r14
  7e18b3:	41 5f                                           	pop    r15
  7e18b5:	5d                                              	pop    rbp
  7e18b6:	c3                                              	ret
  7e18b7:	89 c3                                           	mov    ebx,eax
  7e18b9:	e8 92 00 01 00                                  	call   0x7f1950
  7e18be:	4c 63 75 d4                                     	movsxd r14,DWORD PTR [rbp-0x2c]
  7e18c2:	48 63 d3                                        	movsxd rdx,ebx
  7e18c5:	48 8d 3d eb ff ff ff                            	lea    rdi,[rip+0xffffffffffffffeb]        # 0x7e18b7
  7e18cc:	4c 89 f6                                        	mov    rsi,r14
  7e18cf:	e8 3c 07 01 00                                  	call   0x7f2010
  7e18d4:	48 8d 35 56 72 ba 00                            	lea    rsi,[rip+0xba7256]        # 0x1388b31
  7e18db:	bf 24 00 00 00                                  	mov    edi,0x24
  7e18e0:	44 89 f2                                        	mov    edx,r14d
  7e18e3:	eb 2c                                           	jmp    0x7e1911
  7e18e5:	89 c3                                           	mov    ebx,eax
  7e18e7:	e8 64 00 01 00                                  	call   0x7f1950
  7e18ec:	44 8b 75 d4                                     	mov    r14d,DWORD PTR [rbp-0x2c]
  7e18f0:	48 63 d3                                        	movsxd rdx,ebx
  7e18f3:	48 8d 3d eb ff ff ff                            	lea    rdi,[rip+0xffffffffffffffeb]        # 0x7e18e5
  7e18fa:	49 63 f6                                        	movsxd rsi,r14d
  7e18fd:	e8 0e 07 01 00                                  	call   0x7f2010
  7e1902:	48 8d 35 28 72 ba 00                            	lea    rsi,[rip+0xba7228]        # 0x1388b31
  7e1909:	bf 28 00 00 00                                  	mov    edi,0x28
  7e190e:	44 89 f2                                        	mov    edx,r14d
  7e1911:	89 d9                                           	mov    ecx,ebx
  7e1913:	31 c0                                           	xor    eax,eax
  7e1915:	e8 f6 90 4b 00                                  	call   0xc9aa10
  7e191a:	0f 0b                                           	ud2
  7e191c:	90                                              	nop
  7e191d:	90                                              	nop
  7e191e:	90                                              	nop
  7e191f:	90                                              	nop
  7e1920:	55                                              	push   rbp
  7e1921:	48 89 e5                                        	mov    rbp,rsp
  7e1924:	41 57                                           	push   r15
  7e1926:	41 56                                           	push   r14
  7e1928:	41 55                                           	push   r13
  7e192a:	41 54                                           	push   r12
  7e192c:	53                                              	push   rbx
  7e192d:	48 83 ec 48                                     	sub    rsp,0x48
  7e1931:	4c 8d 25 d8 a9 13 03                            	lea    r12,[rip+0x313a9d8]        # 0x391c310
  7e1938:	48 89 55 a0                                     	mov    QWORD PTR [rbp-0x60],rdx
  7e193c:	48 89 f3                                        	mov    rbx,rsi
  7e193f:	49 89 fe                                        	mov    r14,rdi
  7e1942:	48 8d 55 b8                                     	lea    rdx,[rbp-0x48]
  7e1946:	b9 ff ff ff 03                                  	mov    ecx,0x3ffffff
  7e194b:	49 8b 04 24                                     	mov    rax,QWORD PTR [r12]
  7e194f:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  7e1953:	44 8b 7e 0c                                     	mov    r15d,DWORD PTR [rsi+0xc]
  7e1957:	be 02 80 00 00                                  	mov    esi,0x8002
  7e195c:	44 89 ff                                        	mov    edi,r15d
  7e195f:	e8 ac d2 e2 ff                                  	call   0x60ec10
  7e1964:	41 bd ff ff ff ff                               	mov    r13d,0xffffffff
  7e196a:	85 c0                                           	test   eax,eax
  7e196c:	0f 85 3b 03 00 00                               	jne    0x7e1cad
  7e1972:	48 8b 45 b8                                     	mov    rax,QWORD PTR [rbp-0x48]
  7e1976:	48 89 5d a8                                     	mov    QWORD PTR [rbp-0x58],rbx
  7e197a:	31 f6                                           	xor    esi,esi
  7e197c:	31 d2                                           	xor    edx,edx
  7e197e:	31 c9                                           	xor    ecx,ecx
  7e1980:	48 8b 78 28                                     	mov    rdi,QWORD PTR [rax+0x28]
  7e1984:	e8 97 a1 46 00                                  	call   0xc4bb20
  7e1989:	4c 8b 65 b8                                     	mov    r12,QWORD PTR [rbp-0x48]
  7e198d:	b8 20 03 00 04                                  	mov    eax,0x4000320
  7e1992:	49 8b 7c 24 28                                  	mov    rdi,QWORD PTR [r12+0x28]
  7e1997:	23 47 20                                        	and    eax,DWORD PTR [rdi+0x20]
  7e199a:	3d 00 00 00 04                                  	cmp    eax,0x4000000
  7e199f:	0f 85 8f 01 00 00                               	jne    0x7e1b34
  7e19a5:	48 8b 4d a8                                     	mov    rcx,QWORD PTR [rbp-0x58]
  7e19a9:	8b 41 08                                        	mov    eax,DWORD PTR [rcx+0x8]
  7e19ac:	83 c8 10                                        	or     eax,0x10
  7e19af:	83 f8 53                                        	cmp    eax,0x53
  7e19b2:	0f 85 88 01 00 00                               	jne    0x7e1b40
  7e19b8:	48 8d 41 18                                     	lea    rax,[rcx+0x18]
  7e19bc:	48 89 45 b0                                     	mov    QWORD PTR [rbp-0x50],rax
  7e19c0:	48 63 41 18                                     	movsxd rax,DWORD PTR [rcx+0x18]
  7e19c4:	4c 8d 2c 80                                     	lea    r13,[rax+rax*4]
  7e19c8:	48 89 c3                                        	mov    rbx,rax
  7e19cb:	42 83 bc ef 08 06 00 00 ff                      	cmp    DWORD PTR [rdi+r13*8+0x608],0xffffffff
  7e19d4:	75 14                                           	jne    0x7e19ea
  7e19d6:	4a 8d 84 ef f8 05 00 00                         	lea    rax,[rdi+r13*8+0x5f8]
  7e19de:	83 78 04 ff                                     	cmp    DWORD PTR [rax+0x4],0xffffffff
  7e19e2:	75 06                                           	jne    0x7e19ea
  7e19e4:	83 78 20 ff                                     	cmp    DWORD PTR [rax+0x20],0xffffffff
  7e19e8:	74 53                                           	je     0x7e1a3d
  7e19ea:	48 8d 3d 47 80 aa 00                            	lea    rdi,[rip+0xaa8047]        # 0x1289a38
  7e19f1:	be 62 06 00 00                                  	mov    esi,0x662
  7e19f6:	31 c0                                           	xor    eax,eax
  7e19f8:	e8 13 ba a7 ff                                  	call   0x25d410
  7e19fd:	48 8b 45 b0                                     	mov    rax,QWORD PTR [rbp-0x50]
  7e1a01:	41 8b b6 9c 00 00 00                            	mov    esi,DWORD PTR [r14+0x9c]
  7e1a08:	49 8b 54 24 18                                  	mov    rdx,QWORD PTR [r12+0x18]
  7e1a0d:	48 8d 3d cd 6e bc 00                            	lea    rdi,[rip+0xbc6ecd]        # 0x13a88e1
  7e1a14:	8b 08                                           	mov    ecx,DWORD PTR [rax]
  7e1a16:	49 8b 44 24 28                                  	mov    rax,QWORD PTR [r12+0x28]
  7e1a1b:	46 8b 8c e8 fc 05 00 00                         	mov    r9d,DWORD PTR [rax+r13*8+0x5fc]
  7e1a23:	46 8b 84 e8 08 06 00 00                         	mov    r8d,DWORD PTR [rax+r13*8+0x608]
  7e1a2b:	42 8b 84 e8 18 06 00 00                         	mov    eax,DWORD PTR [rax+r13*8+0x618]
  7e1a33:	89 04 24                                        	mov    DWORD PTR [rsp],eax
  7e1a36:	31 c0                                           	xor    eax,eax
  7e1a38:	e8 d3 b9 a7 ff                                  	call   0x25d410
  7e1a3d:	48 8d 7d c0                                     	lea    rdi,[rbp-0x40]
  7e1a41:	e8 6a d8 2e 00                                  	call   0xacf2b0
  7e1a46:	48 b8 cf f7 53 e3 a5 9b c4 20                   	movabs rax,0x20c49ba5e353f7cf
  7e1a50:	4c 8b 45 a8                                     	mov    r8,QWORD PTR [rbp-0x58]
  7e1a54:	48 69 4d c0 40 42 0f 00                         	imul   rcx,QWORD PTR [rbp-0x40],0xf4240
  7e1a5c:	49 8b 7c 24 28                                  	mov    rdi,QWORD PTR [r12+0x28]
  7e1a61:	48 c1 e3 03                                     	shl    rbx,0x3
  7e1a65:	48 f7 6d c8                                     	imul   QWORD PTR [rbp-0x38]
  7e1a69:	48 8d 34 9b                                     	lea    rsi,[rbx+rbx*4]
  7e1a6d:	48 89 d0                                        	mov    rax,rdx
  7e1a70:	48 c1 fa 07                                     	sar    rdx,0x7
  7e1a74:	48 c1 e8 3f                                     	shr    rax,0x3f
  7e1a78:	48 01 c2                                        	add    rdx,rax
  7e1a7b:	41 8b 40 1c                                     	mov    eax,DWORD PTR [r8+0x1c]
  7e1a7f:	48 01 ca                                        	add    rdx,rcx
  7e1a82:	89 84 37 08 06 00 00                            	mov    DWORD PTR [rdi+rsi*1+0x608],eax
  7e1a89:	41 8b 40 20                                     	mov    eax,DWORD PTR [r8+0x20]
  7e1a8d:	49 8b 4c 24 28                                  	mov    rcx,QWORD PTR [r12+0x28]
  7e1a92:	89 84 31 fc 05 00 00                            	mov    DWORD PTR [rcx+rsi*1+0x5fc],eax
  7e1a99:	49 8b 44 24 28                                  	mov    rax,QWORD PTR [r12+0x28]
  7e1a9e:	48 89 94 30 00 06 00 00                         	mov    QWORD PTR [rax+rsi*1+0x600],rdx
  7e1aa6:	41 8b 40 24                                     	mov    eax,DWORD PTR [r8+0x24]
  7e1aaa:	49 8b 4c 24 28                                  	mov    rcx,QWORD PTR [r12+0x28]
  7e1aaf:	89 84 31 0c 06 00 00                            	mov    DWORD PTR [rcx+rsi*1+0x60c],eax
  7e1ab6:	49 8b 40 28                                     	mov    rax,QWORD PTR [r8+0x28]
  7e1aba:	49 8b 4c 24 28                                  	mov    rcx,QWORD PTR [r12+0x28]
  7e1abf:	48 89 84 31 10 06 00 00                         	mov    QWORD PTR [rcx+rsi*1+0x610],rax
  7e1ac7:	41 8b 86 9c 00 00 00                            	mov    eax,DWORD PTR [r14+0x9c]
  7e1ace:	49 8b 4c 24 28                                  	mov    rcx,QWORD PTR [r12+0x28]
  7e1ad3:	89 84 31 18 06 00 00                            	mov    DWORD PTR [rcx+rsi*1+0x618],eax
  7e1ada:	b9 ff ff ff ff                                  	mov    ecx,0xffffffff
  7e1adf:	49 8b 44 24 28                                  	mov    rax,QWORD PTR [r12+0x28]
  7e1ae4:	c7 84 30 1c 06 00 00 00 00 00 00                	mov    DWORD PTR [rax+rsi*1+0x61c],0x0
  7e1aef:	b8 ff ff ff ff                                  	mov    eax,0xffffffff
  7e1af4:	49 8b 54 24 28                                  	mov    rdx,QWORD PTR [r12+0x28]
  7e1af9:	48 8b b2 60 04 00 00                            	mov    rsi,QWORD PTR [rdx+0x460]
  7e1b00:	48 85 f6                                        	test   rsi,rsi
  7e1b03:	74 03                                           	je     0x7e1b08
  7e1b05:	8b 4e 08                                        	mov    ecx,DWORD PTR [rsi+0x8]
  7e1b08:	48 8b 92 98 01 00 00                            	mov    rdx,QWORD PTR [rdx+0x198]
  7e1b0f:	4c 8d 25 fa a7 13 03                            	lea    r12,[rip+0x313a7fa]        # 0x391c310
  7e1b16:	48 8b 5d a0                                     	mov    rbx,QWORD PTR [rbp-0x60]
  7e1b1a:	48 85 d2                                        	test   rdx,rdx
  7e1b1d:	74 03                                           	je     0x7e1b22
  7e1b1f:	8b 42 08                                        	mov    eax,DWORD PTR [rdx+0x8]
  7e1b22:	49 8b 50 20                                     	mov    rdx,QWORD PTR [r8+0x20]
  7e1b26:	49 83 c0 1c                                     	add    r8,0x1c
  7e1b2a:	be 0e 97 00 00                                  	mov    esi,0x970e
  7e1b2f:	e9 2c 01 00 00                                  	jmp    0x7e1c60
  7e1b34:	4c 8d 25 d5 a7 13 03                            	lea    r12,[rip+0x313a7d5]        # 0x391c310
  7e1b3b:	e9 55 01 00 00                                  	jmp    0x7e1c95
  7e1b40:	48 63 59 18                                     	movsxd rbx,DWORD PTR [rcx+0x18]
  7e1b44:	48 8d 41 18                                     	lea    rax,[rcx+0x18]
  7e1b48:	48 89 45 b0                                     	mov    QWORD PTR [rbp-0x50],rax
  7e1b4c:	4c 8d 2c 5b                                     	lea    r13,[rbx+rbx*2]
  7e1b50:	42 83 bc ef 88 04 00 00 ff                      	cmp    DWORD PTR [rdi+r13*8+0x488],0xffffffff
  7e1b59:	75 0e                                           	jne    0x7e1b69
  7e1b5b:	4a 8d 84 ef 78 04 00 00                         	lea    rax,[rdi+r13*8+0x478]
  7e1b63:	83 78 04 ff                                     	cmp    DWORD PTR [rax+0x4],0xffffffff
  7e1b67:	74 48                                           	je     0x7e1bb1
  7e1b69:	48 8d 3d c8 7e aa 00                            	lea    rdi,[rip+0xaa7ec8]        # 0x1289a38
  7e1b70:	be 20 06 00 00                                  	mov    esi,0x620
  7e1b75:	31 c0                                           	xor    eax,eax
  7e1b77:	e8 94 b8 a7 ff                                  	call   0x25d410
  7e1b7c:	48 8b 45 b0                                     	mov    rax,QWORD PTR [rbp-0x50]
  7e1b80:	41 8b b6 9c 00 00 00                            	mov    esi,DWORD PTR [r14+0x9c]
  7e1b87:	49 8b 54 24 18                                  	mov    rdx,QWORD PTR [r12+0x18]
  7e1b8c:	48 8d 3d c9 a2 b0 00                            	lea    rdi,[rip+0xb0a2c9]        # 0x12ebe5c
  7e1b93:	8b 08                                           	mov    ecx,DWORD PTR [rax]
  7e1b95:	49 8b 44 24 28                                  	mov    rax,QWORD PTR [r12+0x28]
  7e1b9a:	46 8b 8c e8 7c 04 00 00                         	mov    r9d,DWORD PTR [rax+r13*8+0x47c]
  7e1ba2:	46 8b 84 e8 88 04 00 00                         	mov    r8d,DWORD PTR [rax+r13*8+0x488]
  7e1baa:	31 c0                                           	xor    eax,eax
  7e1bac:	e8 5f b8 a7 ff                                  	call   0x25d410
  7e1bb1:	48 8d 7d c0                                     	lea    rdi,[rbp-0x40]
  7e1bb5:	e8 f6 d6 2e 00                                  	call   0xacf2b0
  7e1bba:	48 b8 cf f7 53 e3 a5 9b c4 20                   	movabs rax,0x20c49ba5e353f7cf
  7e1bc4:	4c 8b 45 a8                                     	mov    r8,QWORD PTR [rbp-0x58]
  7e1bc8:	48 69 4d c0 40 42 0f 00                         	imul   rcx,QWORD PTR [rbp-0x40],0xf4240
  7e1bd0:	49 8b 7c 24 28                                  	mov    rdi,QWORD PTR [r12+0x28]
  7e1bd5:	48 c1 e3 03                                     	shl    rbx,0x3
  7e1bd9:	48 f7 6d c8                                     	imul   QWORD PTR [rbp-0x38]
  7e1bdd:	48 8d 34 5b                                     	lea    rsi,[rbx+rbx*2]
  7e1be1:	48 89 d0                                        	mov    rax,rdx
  7e1be4:	48 c1 fa 07                                     	sar    rdx,0x7
  7e1be8:	48 c1 e8 3f                                     	shr    rax,0x3f
  7e1bec:	48 01 c2                                        	add    rdx,rax
  7e1bef:	41 8b 40 1c                                     	mov    eax,DWORD PTR [r8+0x1c]
  7e1bf3:	48 01 ca                                        	add    rdx,rcx
  7e1bf6:	89 84 37 88 04 00 00                            	mov    DWORD PTR [rdi+rsi*1+0x488],eax
  7e1bfd:	41 8b 86 9c 00 00 00                            	mov    eax,DWORD PTR [r14+0x9c]
  7e1c04:	49 8b 4c 24 28                                  	mov    rcx,QWORD PTR [r12+0x28]
  7e1c09:	89 84 31 7c 04 00 00                            	mov    DWORD PTR [rcx+rsi*1+0x47c],eax
  7e1c10:	b9 ff ff ff ff                                  	mov    ecx,0xffffffff
  7e1c15:	49 8b 44 24 28                                  	mov    rax,QWORD PTR [r12+0x28]
  7e1c1a:	48 89 94 30 80 04 00 00                         	mov    QWORD PTR [rax+rsi*1+0x480],rdx
  7e1c22:	b8 ff ff ff ff                                  	mov    eax,0xffffffff
  7e1c27:	49 8b 54 24 28                                  	mov    rdx,QWORD PTR [r12+0x28]
  7e1c2c:	48 8b b2 60 04 00 00                            	mov    rsi,QWORD PTR [rdx+0x460]
  7e1c33:	48 85 f6                                        	test   rsi,rsi
  7e1c36:	74 03                                           	je     0x7e1c3b
  7e1c38:	8b 4e 08                                        	mov    ecx,DWORD PTR [rsi+0x8]
  7e1c3b:	48 8b 92 98 01 00 00                            	mov    rdx,QWORD PTR [rdx+0x198]
  7e1c42:	4c 8d 25 c7 a6 13 03                            	lea    r12,[rip+0x313a6c7]        # 0x391c310
  7e1c49:	48 8b 5d a0                                     	mov    rbx,QWORD PTR [rbp-0x60]
  7e1c4d:	49 83 c0 1c                                     	add    r8,0x1c
  7e1c51:	be 0d 97 00 00                                  	mov    esi,0x970d
  7e1c56:	48 85 d2                                        	test   rdx,rdx
  7e1c59:	74 03                                           	je     0x7e1c5e
  7e1c5b:	8b 42 08                                        	mov    eax,DWORD PTR [rdx+0x8]
  7e1c5e:	31 d2                                           	xor    edx,edx
  7e1c60:	48 8b 7d b0                                     	mov    rdi,QWORD PTR [rbp-0x50]
  7e1c64:	45 8b 00                                        	mov    r8d,DWORD PTR [r8]
  7e1c67:	45 31 ed                                        	xor    r13d,r13d
  7e1c6a:	8b 3f                                           	mov    edi,DWORD PTR [rdi]
  7e1c6c:	89 33                                           	mov    DWORD PTR [rbx],esi
  7e1c6e:	89 4b 08                                        	mov    DWORD PTR [rbx+0x8],ecx
  7e1c71:	89 43 0c                                        	mov    DWORD PTR [rbx+0xc],eax
  7e1c74:	44 89 43 10                                     	mov    DWORD PTR [rbx+0x10],r8d
  7e1c78:	89 7b 14                                        	mov    DWORD PTR [rbx+0x14],edi
  7e1c7b:	48 89 53 18                                     	mov    QWORD PTR [rbx+0x18],rdx
  7e1c7f:	48 8b 45 b8                                     	mov    rax,QWORD PTR [rbp-0x48]
  7e1c83:	48 8b 40 28                                     	mov    rax,QWORD PTR [rax+0x28]
  7e1c87:	ff 80 00 09 00 00                               	inc    DWORD PTR [rax+0x900]
  7e1c8d:	48 8b 45 b8                                     	mov    rax,QWORD PTR [rbp-0x48]
  7e1c91:	48 8b 78 28                                     	mov    rdi,QWORD PTR [rax+0x28]
  7e1c95:	31 f6                                           	xor    esi,esi
  7e1c97:	31 d2                                           	xor    edx,edx
  7e1c99:	e8 12 a8 46 00                                  	call   0xc4c4b0
  7e1c9e:	44 89 ff                                        	mov    edi,r15d
  7e1ca1:	be 02 80 00 00                                  	mov    esi,0x8002
  7e1ca6:	31 d2                                           	xor    edx,edx
  7e1ca8:	e8 23 d0 e2 ff                                  	call   0x60ecd0
  7e1cad:	49 8b 04 24                                     	mov    rax,QWORD PTR [r12]
  7e1cb1:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  7e1cb5:	75 12                                           	jne    0x7e1cc9
  7e1cb7:	44 89 e8                                        	mov    eax,r13d
  7e1cba:	48 83 c4 48                                     	add    rsp,0x48
  7e1cbe:	5b                                              	pop    rbx
  7e1cbf:	41 5c                                           	pop    r12
  7e1cc1:	41 5d                                           	pop    r13
  7e1cc3:	41 5e                                           	pop    r14
  7e1cc5:	41 5f                                           	pop    r15
  7e1cc7:	5d                                              	pop    rbp
  7e1cc8:	c3                                              	ret
  7e1cc9:	e8 e2 b9 f1 ff                                  	call   0x6fd6b0
  7e1cce:	0f 0b                                           	ud2
  7e1cd0:	55                                              	push   rbp
  7e1cd1:	48 89 e5                                        	mov    rbp,rsp
  7e1cd4:	41 56                                           	push   r14
  7e1cd6:	53                                              	push   rbx
  7e1cd7:	48 8b 05 ca bd d5 01                            	mov    rax,QWORD PTR [rip+0x1d5bdca]        # 0x253daa8
  7e1cde:	48 8b 58 38                                     	mov    rbx,QWORD PTR [rax+0x38]
  7e1ce2:	31 c0                                           	xor    eax,eax
  7e1ce4:	48 85 db                                        	test   rbx,rbx
  7e1ce7:	74 7d                                           	je     0x7e1d66
  7e1ce9:	49 89 fb                                        	mov    r11,rdi
  7e1cec:	48 8b 7d 18                                     	mov    rdi,QWORD PTR [rbp+0x18]
  7e1cf0:	4c 8b 55 10                                     	mov    r10,QWORD PTR [rbp+0x10]
  7e1cf4:	eb 12                                           	jmp    0x7e1d08
  7e1cf6:	66 2e 0f 1f 84 00 00 00 00 00                   	cs nop WORD PTR [rax+rax*1+0x0]
  7e1d00:	48 8b 1b                                        	mov    rbx,QWORD PTR [rbx]
  7e1d03:	48 85 db                                        	test   rbx,rbx
  7e1d06:	74 5e                                           	je     0x7e1d66
  7e1d08:	44 8b 73 14                                     	mov    r14d,DWORD PTR [rbx+0x14]
  7e1d0c:	41 f6 c6 01                                     	test   r14b,0x1
  7e1d10:	74 59                                           	je     0x7e1d6b
  7e1d12:	41 f7 c6 00 05 00 00                            	test   r14d,0x500
  7e1d19:	75 e5                                           	jne    0x7e1d00
  7e1d1b:	39 53 18                                        	cmp    DWORD PTR [rbx+0x18],edx
  7e1d1e:	75 e0                                           	jne    0x7e1d00
  7e1d20:	39 4b 1c                                        	cmp    DWORD PTR [rbx+0x1c],ecx
  7e1d23:	75 db                                           	jne    0x7e1d00
  7e1d25:	39 73 48                                        	cmp    DWORD PTR [rbx+0x48],esi
  7e1d28:	75 d6                                           	jne    0x7e1d00
  7e1d2a:	83 7b 4c ff                                     	cmp    DWORD PTR [rbx+0x4c],0xffffffff
  7e1d2e:	75 d0                                           	jne    0x7e1d00
  7e1d30:	41 8b 83 9c 00 00 00                            	mov    eax,DWORD PTR [r11+0x9c]
  7e1d37:	48 8d 73 78                                     	lea    rsi,[rbx+0x78]
  7e1d3b:	ba 50 01 00 00                                  	mov    edx,0x150
  7e1d40:	4d 89 ce                                        	mov    r14,r9
  7e1d43:	89 43 4c                                        	mov    DWORD PTR [rbx+0x4c],eax
  7e1d46:	4c 89 43 58                                     	mov    QWORD PTR [rbx+0x58],r8
  7e1d4a:	48 8b 43 70                                     	mov    rax,QWORD PTR [rbx+0x70]
  7e1d4e:	49 89 02                                        	mov    QWORD PTR [r10],rax
  7e1d51:	48 c7 43 70 00 00 00 00                         	mov    QWORD PTR [rbx+0x70],0x0
  7e1d59:	e8 52 73 a7 ff                                  	call   0x2590b0
  7e1d5e:	49 89 1e                                        	mov    QWORD PTR [r14],rbx
  7e1d61:	b8 01 00 00 00                                  	mov    eax,0x1
  7e1d66:	5b                                              	pop    rbx
  7e1d67:	41 5e                                           	pop    r14
  7e1d69:	5d                                              	pop    rbp
  7e1d6a:	c3                                              	ret
  7e1d6b:	e8 e0 fb 00 00                                  	call   0x7f1950
  7e1d70:	48 8d 3d f4 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff4]        # 0x7e1d6b
  7e1d77:	e8 94 fa 00 00                                  	call   0x7f1810
  7e1d7c:	48 8d 35 8f 7b ab 00                            	lea    rsi,[rip+0xab7b8f]        # 0x1299912
  7e1d83:	bf 2c 00 00 00                                  	mov    edi,0x2c
  7e1d88:	31 c0                                           	xor    eax,eax
  7e1d8a:	e8 81 8c 4b 00                                  	call   0xc9aa10
  7e1d8f:	0f 0b                                           	ud2
  7e1d91:	90                                              	nop
  7e1d92:	90                                              	nop
  7e1d93:	90                                              	nop
  7e1d94:	90                                              	nop
  7e1d95:	90                                              	nop
  7e1d96:	90                                              	nop
  7e1d97:	90                                              	nop
  7e1d98:	90                                              	nop
  7e1d99:	90                                              	nop
  7e1d9a:	90                                              	nop
  7e1d9b:	90                                              	nop
  7e1d9c:	90                                              	nop
  7e1d9d:	90                                              	nop
  7e1d9e:	90                                              	nop
  7e1d9f:	90                                              	nop
  7e1da0:	55                                              	push   rbp
  7e1da1:	48 89 e5                                        	mov    rbp,rsp
  7e1da4:	85 f6                                           	test   esi,esi
  7e1da6:	75 59                                           	jne    0x7e1e01
  7e1da8:	48 8d 35 6f 3a b8 00                            	lea    rsi,[rip+0xb83a6f]        # 0x136581e
  7e1daf:	48 8d 15 ea 5a a8 ff                            	lea    rdx,[rip+0xffffffffffa85aea]        # 0x2678a0
  7e1db6:	48 8d 0d 09 bb ac 00                            	lea    rcx,[rip+0xacbb09]        # 0x12ad8c6
  7e1dbd:	41 b9 10 27 00 00                               	mov    r9d,0x2710
  7e1dc3:	31 ff                                           	xor    edi,edi
  7e1dc5:	45 31 c0                                        	xor    r8d,r8d
  7e1dc8:	e8 73 bf f5 ff                                  	call   0x73dd40
  7e1dcd:	48 85 c0                                        	test   rax,rax
  7e1dd0:	74 33                                           	je     0x7e1e05
  7e1dd2:	48 8d 35 c5 58 b0 00                            	lea    rsi,[rip+0xb058c5]        # 0x12e769e
  7e1dd9:	48 8d 15 c8 5a a8 ff                            	lea    rdx,[rip+0xffffffffffa85ac8]        # 0x2678a8
  7e1de0:	48 8d 0d 6f fc af 00                            	lea    rcx,[rip+0xaffc6f]        # 0x12e1a56
  7e1de7:	41 b9 10 27 00 00                               	mov    r9d,0x2710
  7e1ded:	31 ff                                           	xor    edi,edi
  7e1def:	45 31 c0                                        	xor    r8d,r8d
  7e1df2:	e8 49 bf f5 ff                                  	call   0x73dd40
  7e1df7:	48 85 c0                                        	test   rax,rax
  7e1dfa:	74 2f                                           	je     0x7e1e2b
  7e1dfc:	e8 6f 02 00 00                                  	call   0x7e2070
  7e1e01:	31 c0                                           	xor    eax,eax
  7e1e03:	5d                                              	pop    rbp
  7e1e04:	c3                                              	ret
  7e1e05:	e8 46 fb 00 00                                  	call   0x7f1950
  7e1e0a:	48 8d 3d f4 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff4]        # 0x7e1e05
  7e1e11:	48 c7 c6 40 00 0e 80                            	mov    rsi,0xffffffff800e0040
  7e1e18:	e8 83 fa 00 00                                  	call   0x7f18a0
  7e1e1d:	48 8d 35 34 1d b9 00                            	lea    rsi,[rip+0xb91d34]        # 0x1373b58
  7e1e24:	bf 48 00 00 00                                  	mov    edi,0x48
  7e1e29:	eb 24                                           	jmp    0x7e1e4f
  7e1e2b:	e8 20 fb 00 00                                  	call   0x7f1950
  7e1e30:	48 8d 3d f4 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff4]        # 0x7e1e2b
  7e1e37:	48 c7 c6 40 00 0e 80                            	mov    rsi,0xffffffff800e0040
  7e1e3e:	e8 5d fa 00 00                                  	call   0x7f18a0
  7e1e43:	48 8d 35 15 6b bc 00                            	lea    rsi,[rip+0xbc6b15]        # 0x13a895f
  7e1e4a:	bf 4c 00 00 00                                  	mov    edi,0x4c
  7e1e4f:	ba 40 00 0e 80                                  	mov    edx,0x800e0040
  7e1e54:	31 c0                                           	xor    eax,eax
  7e1e56:	e8 b5 8b 4b 00                                  	call   0xc9aa10
  7e1e5b:	0f 0b                                           	ud2
  7e1e5d:	90                                              	nop
  7e1e5e:	90                                              	nop
  7e1e5f:	90                                              	nop
  7e1e60:	55                                              	push   rbp
  7e1e61:	48 89 e5                                        	mov    rbp,rsp
  7e1e64:	48 c7 86 40 05 00 00 00 00 00 00                	mov    QWORD PTR [rsi+0x540],0x0
  7e1e6f:	c7 86 48 05 00 00 00 00 00 00                   	mov    DWORD PTR [rsi+0x548],0x0
  7e1e79:	5d                                              	pop    rbp
  7e1e7a:	c3                                              	ret
  7e1e7b:	90                                              	nop
  7e1e7c:	90                                              	nop
  7e1e7d:	90                                              	nop
  7e1e7e:	90                                              	nop
  7e1e7f:	90                                              	nop
  7e1e80:	55                                              	push   rbp
  7e1e81:	48 89 e5                                        	mov    rbp,rsp
  7e1e84:	41 57                                           	push   r15
  7e1e86:	41 56                                           	push   r14
  7e1e88:	41 54                                           	push   r12
  7e1e8a:	53                                              	push   rbx
  7e1e8b:	48 83 ec 10                                     	sub    rsp,0x10
  7e1e8f:	4c 8d 3d 7a a4 13 03                            	lea    r15,[rip+0x313a47a]        # 0x391c310
  7e1e96:	48 89 f3                                        	mov    rbx,rsi
  7e1e99:	48 8d 35 90 bb d5 01                            	lea    rsi,[rip+0x1d5bb90]        # 0x253da30
  7e1ea0:	bf 00 40 00 00                                  	mov    edi,0x4000
  7e1ea5:	ba 02 01 00 00                                  	mov    edx,0x102
  7e1eaa:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  7e1ead:	48 89 45 d8                                     	mov    QWORD PTR [rbp-0x28],rax
  7e1eb1:	e8 9a 6c 42 00                                  	call   0xc08b50
  7e1eb6:	48 85 c0                                        	test   rax,rax
  7e1eb9:	0f 84 61 01 00 00                               	je     0x7e2020
  7e1ebf:	48 8b 3d da bb d5 01                            	mov    rdi,QWORD PTR [rip+0x1d5bbda]        # 0x253daa0
  7e1ec6:	4c 8d 45 d4                                     	lea    r8,[rbp-0x2c]
  7e1eca:	be 02 80 00 00                                  	mov    esi,0x8002
  7e1ecf:	48 89 c2                                        	mov    rdx,rax
  7e1ed2:	b9 00 40 00 00                                  	mov    ecx,0x4000
  7e1ed7:	49 89 c6                                        	mov    r14,rax
  7e1eda:	c7 45 d4 00 00 00 00                            	mov    DWORD PTR [rbp-0x2c],0x0
  7e1ee1:	e8 0a 79 bb ff                                  	call   0x3997f0
  7e1ee6:	83 7d d4 00                                     	cmp    DWORD PTR [rbp-0x2c],0x0
  7e1eea:	74 1e                                           	je     0x7e1f0a
  7e1eec:	45 31 e4                                        	xor    r12d,r12d
  7e1eef:	90                                              	nop
  7e1ef0:	4d 63 e4                                        	movsxd r12,r12d
  7e1ef3:	48 89 de                                        	mov    rsi,rbx
  7e1ef6:	31 d2                                           	xor    edx,edx
  7e1ef8:	43 8b 3c a6                                     	mov    edi,DWORD PTR [r14+r12*4]
  7e1efc:	e8 3f 6a ab ff                                  	call   0x298940
  7e1f01:	41 ff c4                                        	inc    r12d
  7e1f04:	44 3b 65 d4                                     	cmp    r12d,DWORD PTR [rbp-0x2c]
  7e1f08:	72 e6                                           	jb     0x7e1ef0
  7e1f0a:	48 8b 3d 8f bb d5 01                            	mov    rdi,QWORD PTR [rip+0x1d5bb8f]        # 0x253daa0
  7e1f11:	4c 8d 45 d4                                     	lea    r8,[rbp-0x2c]
  7e1f15:	be 04 80 00 00                                  	mov    esi,0x8004
  7e1f1a:	4c 89 f2                                        	mov    rdx,r14
  7e1f1d:	b9 00 40 00 00                                  	mov    ecx,0x4000
  7e1f22:	c7 45 d4 00 00 00 00                            	mov    DWORD PTR [rbp-0x2c],0x0
  7e1f29:	e8 c2 78 bb ff                                  	call   0x3997f0
  7e1f2e:	83 7d d4 00                                     	cmp    DWORD PTR [rbp-0x2c],0x0
  7e1f32:	74 26                                           	je     0x7e1f5a
  7e1f34:	45 31 e4                                        	xor    r12d,r12d
  7e1f37:	66 0f 1f 84 00 00 00 00 00                      	nop    WORD PTR [rax+rax*1+0x0]
  7e1f40:	4d 63 e4                                        	movsxd r12,r12d
  7e1f43:	48 89 de                                        	mov    rsi,rbx
  7e1f46:	31 d2                                           	xor    edx,edx
  7e1f48:	43 8b 3c a6                                     	mov    edi,DWORD PTR [r14+r12*4]
  7e1f4c:	e8 4f 99 28 00                                  	call   0xa6b8a0
  7e1f51:	41 ff c4                                        	inc    r12d
  7e1f54:	44 3b 65 d4                                     	cmp    r12d,DWORD PTR [rbp-0x2c]
  7e1f58:	72 e6                                           	jb     0x7e1f40
  7e1f5a:	48 8b 3d 3f bb d5 01                            	mov    rdi,QWORD PTR [rip+0x1d5bb3f]        # 0x253daa0
  7e1f61:	4c 8d 45 d4                                     	lea    r8,[rbp-0x2c]
  7e1f65:	be 01 80 00 00                                  	mov    esi,0x8001
  7e1f6a:	4c 89 f2                                        	mov    rdx,r14
  7e1f6d:	b9 00 40 00 00                                  	mov    ecx,0x4000
  7e1f72:	c7 45 d4 00 00 00 00                            	mov    DWORD PTR [rbp-0x2c],0x0
  7e1f79:	e8 72 78 bb ff                                  	call   0x3997f0
  7e1f7e:	83 7d d4 00                                     	cmp    DWORD PTR [rbp-0x2c],0x0
  7e1f82:	74 26                                           	je     0x7e1faa
  7e1f84:	45 31 e4                                        	xor    r12d,r12d
  7e1f87:	66 0f 1f 84 00 00 00 00 00                      	nop    WORD PTR [rax+rax*1+0x0]
  7e1f90:	4d 63 e4                                        	movsxd r12,r12d
  7e1f93:	48 89 de                                        	mov    rsi,rbx
  7e1f96:	31 d2                                           	xor    edx,edx
  7e1f98:	43 8b 3c a6                                     	mov    edi,DWORD PTR [r14+r12*4]
  7e1f9c:	e8 ff 8c 28 00                                  	call   0xa6aca0
  7e1fa1:	41 ff c4                                        	inc    r12d
  7e1fa4:	44 3b 65 d4                                     	cmp    r12d,DWORD PTR [rbp-0x2c]
  7e1fa8:	72 e6                                           	jb     0x7e1f90
  7e1faa:	48 8b 3d ef ba d5 01                            	mov    rdi,QWORD PTR [rip+0x1d5baef]        # 0x253daa0
  7e1fb1:	4c 8d 45 d4                                     	lea    r8,[rbp-0x2c]
  7e1fb5:	be 08 80 00 00                                  	mov    esi,0x8008
  7e1fba:	4c 89 f2                                        	mov    rdx,r14
  7e1fbd:	b9 00 40 00 00                                  	mov    ecx,0x4000
  7e1fc2:	c7 45 d4 00 00 00 00                            	mov    DWORD PTR [rbp-0x2c],0x0
  7e1fc9:	e8 22 78 bb ff                                  	call   0x3997f0
  7e1fce:	83 7d d4 00                                     	cmp    DWORD PTR [rbp-0x2c],0x0
  7e1fd2:	74 27                                           	je     0x7e1ffb
  7e1fd4:	45 31 e4                                        	xor    r12d,r12d
  7e1fd7:	66 0f 1f 84 00 00 00 00 00                      	nop    WORD PTR [rax+rax*1+0x0]
  7e1fe0:	4d 63 e4                                        	movsxd r12,r12d
  7e1fe3:	8b b3 bc 00 00 00                               	mov    esi,DWORD PTR [rbx+0xbc]
  7e1fe9:	43 8b 3c a6                                     	mov    edi,DWORD PTR [r14+r12*4]
  7e1fed:	e8 7e d9 bb ff                                  	call   0x39f970
  7e1ff2:	41 ff c4                                        	inc    r12d
  7e1ff5:	44 3b 65 d4                                     	cmp    r12d,DWORD PTR [rbp-0x2c]
  7e1ff9:	72 e5                                           	jb     0x7e1fe0
  7e1ffb:	48 8d 35 2e ba d5 01                            	lea    rsi,[rip+0x1d5ba2e]        # 0x253da30
  7e2002:	4c 89 f7                                        	mov    rdi,r14
  7e2005:	e8 e6 6d 42 00                                  	call   0xc08df0
  7e200a:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  7e200d:	48 3b 45 d8                                     	cmp    rax,QWORD PTR [rbp-0x28]
  7e2011:	75 49                                           	jne    0x7e205c
  7e2013:	48 83 c4 10                                     	add    rsp,0x10
  7e2017:	5b                                              	pop    rbx
  7e2018:	41 5c                                           	pop    r12
  7e201a:	41 5e                                           	pop    r14
  7e201c:	41 5f                                           	pop    r15
  7e201e:	5d                                              	pop    rbp
  7e201f:	c3                                              	ret
  7e2020:	48 8d 3d 50 d9 b4 00                            	lea    rdi,[rip+0xb4d950]        # 0x132f977
  7e2027:	be c1 0e 00 00                                  	mov    esi,0xec1
  7e202c:	31 c0                                           	xor    eax,eax
  7e202e:	e8 dd b3 a7 ff                                  	call   0x25d410
  7e2033:	8b b3 bc 00 00 00                               	mov    esi,DWORD PTR [rbx+0xbc]
  7e2039:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  7e203c:	48 3b 45 d8                                     	cmp    rax,QWORD PTR [rbp-0x28]
  7e2040:	75 1a                                           	jne    0x7e205c
  7e2042:	48 8d 3d fa 3d b1 00                            	lea    rdi,[rip+0xb13dfa]        # 0x12f5e43
  7e2049:	31 c0                                           	xor    eax,eax
  7e204b:	48 83 c4 10                                     	add    rsp,0x10
  7e204f:	5b                                              	pop    rbx
  7e2050:	41 5c                                           	pop    r12
  7e2052:	41 5e                                           	pop    r14
  7e2054:	41 5f                                           	pop    r15
  7e2056:	5d                                              	pop    rbp
  7e2057:	e9 b4 b3 a7 ff                                  	jmp    0x25d410
  7e205c:	e8 4f b6 f1 ff                                  	call   0x6fd6b0
  7e2061:	0f 0b                                           	ud2
  7e2063:	90                                              	nop
  7e2064:	90                                              	nop
  7e2065:	90                                              	nop
  7e2066:	90                                              	nop
  7e2067:	90                                              	nop
  7e2068:	90                                              	nop
  7e2069:	90                                              	nop
  7e206a:	90                                              	nop
  7e206b:	90                                              	nop
  7e206c:	90                                              	nop
  7e206d:	90                                              	nop
  7e206e:	90                                              	nop
  7e206f:	90                                              	nop
  7e2070:	55                                              	push   rbp
  7e2071:	48 89 e5                                        	mov    rbp,rsp
  7e2074:	48 8d 3d 1a e1 b3 00                            	lea    rdi,[rip+0xb3e11a]        # 0x1320195
  7e207b:	e8 60 77 bb ff                                  	call   0x3997e0
  7e2080:	48 89 05 19 ba d5 01                            	mov    QWORD PTR [rip+0x1d5ba19],rax        # 0x253daa0
  7e2087:	48 85 c0                                        	test   rax,rax
  7e208a:	0f 84 1a 01 00 00                               	je     0x7e21aa
  7e2090:	48 8d 35 99 b9 d5 01                            	lea    rsi,[rip+0x1d5b999]        # 0x253da30
  7e2097:	bf 48 00 00 00                                  	mov    edi,0x48
  7e209c:	ba 02 01 00 00                                  	mov    edx,0x102
  7e20a1:	e8 aa 6a 42 00                                  	call   0xc08b50
  7e20a6:	48 89 05 fb b9 d5 01                            	mov    QWORD PTR [rip+0x1d5b9fb],rax        # 0x253daa8
  7e20ad:	48 85 c0                                        	test   rax,rax
  7e20b0:	0f 84 13 01 00 00                               	je     0x7e21c9
  7e20b6:	48 89 c6                                        	mov    rsi,rax
  7e20b9:	48 8d 48 20                                     	lea    rcx,[rax+0x20]
  7e20bd:	48 c7 40 30 00 00 00 00                         	mov    QWORD PTR [rax+0x30],0x0
  7e20c5:	48 c7 40 20 00 00 00 00                         	mov    QWORD PTR [rax+0x20],0x0
  7e20cd:	48 89 c7                                        	mov    rdi,rax
  7e20d0:	31 d2                                           	xor    edx,edx
  7e20d2:	48 83 c6 38                                     	add    rsi,0x38
  7e20d6:	48 89 48 28                                     	mov    QWORD PTR [rax+0x28],rcx
  7e20da:	48 c7 40 38 00 00 00 00                         	mov    QWORD PTR [rax+0x38],0x0
  7e20e2:	48 89 70 40                                     	mov    QWORD PTR [rax+0x40],rsi
  7e20e6:	48 8d 35 eb b7 ac 00                            	lea    rsi,[rip+0xacb7eb]        # 0x12ad8d8
  7e20ed:	e8 9e 91 46 00                                  	call   0xc4b290
  7e20f2:	48 8d 3d 76 6a ba 00                            	lea    rdi,[rip+0xba6a76]        # 0x1388b6f
  7e20f9:	be 08 09 00 00                                  	mov    esi,0x908
  7e20fe:	31 d2                                           	xor    edx,edx
  7e2100:	31 c9                                           	xor    ecx,ecx
  7e2102:	45 31 c0                                        	xor    r8d,r8d
  7e2105:	45 31 c9                                        	xor    r9d,r9d
  7e2108:	6a 00                                           	push   0x0
  7e210a:	6a 07                                           	push   0x7
  7e210c:	e8 cf 8f c5 ff                                  	call   0x43b0e0
  7e2111:	48 83 c4 10                                     	add    rsp,0x10
  7e2115:	48 89 05 94 b9 d5 01                            	mov    QWORD PTR [rip+0x1d5b994],rax        # 0x253dab0
  7e211c:	48 85 c0                                        	test   rax,rax
  7e211f:	0f 84 ca 00 00 00                               	je     0x7e21ef
  7e2125:	48 8d 3d d5 8e a9 00                            	lea    rdi,[rip+0xa98ed5]        # 0x127b001
  7e212c:	be c8 01 00 00                                  	mov    esi,0x1c8
  7e2131:	31 d2                                           	xor    edx,edx
  7e2133:	31 c9                                           	xor    ecx,ecx
  7e2135:	45 31 c0                                        	xor    r8d,r8d
  7e2138:	45 31 c9                                        	xor    r9d,r9d
  7e213b:	6a 00                                           	push   0x0
  7e213d:	6a 07                                           	push   0x7
  7e213f:	e8 9c 8f c5 ff                                  	call   0x43b0e0
  7e2144:	48 83 c4 10                                     	add    rsp,0x10
  7e2148:	48 89 05 69 b9 d5 01                            	mov    QWORD PTR [rip+0x1d5b969],rax        # 0x253dab8
  7e214f:	48 85 c0                                        	test   rax,rax
  7e2152:	0f 84 c0 00 00 00                               	je     0x7e2218
  7e2158:	48 8d 3d ab e6 b1 00                            	lea    rdi,[rip+0xb1e6ab]        # 0x130080a
  7e215f:	be 20 00 00 00                                  	mov    esi,0x20
  7e2164:	31 d2                                           	xor    edx,edx
  7e2166:	31 c9                                           	xor    ecx,ecx
  7e2168:	45 31 c0                                        	xor    r8d,r8d
  7e216b:	45 31 c9                                        	xor    r9d,r9d
  7e216e:	6a 00                                           	push   0x0
  7e2170:	6a 07                                           	push   0x7
  7e2172:	e8 69 8f c5 ff                                  	call   0x43b0e0
  7e2177:	48 83 c4 10                                     	add    rsp,0x10
  7e217b:	48 89 05 3e b9 d5 01                            	mov    QWORD PTR [rip+0x1d5b93e],rax        # 0x253dac0
  7e2182:	48 85 c0                                        	test   rax,rax
  7e2185:	0f 84 b6 00 00 00                               	je     0x7e2241
  7e218b:	e8 00 cd e2 ff                                  	call   0x60ee90
  7e2190:	e8 9b f8 bb ff                                  	call   0x3a1a30
  7e2195:	e8 f6 5e 38 00                                  	call   0xb68090
  7e219a:	e8 81 d5 41 00                                  	call   0xbff720
  7e219f:	e8 4c e9 41 00                                  	call   0xc00af0
  7e21a4:	5d                                              	pop    rbp
  7e21a5:	e9 a6 09 42 00                                  	jmp    0xc02b50
  7e21aa:	e8 a1 f7 00 00                                  	call   0x7f1950
  7e21af:	48 8d 3d f4 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff4]        # 0x7e21aa
  7e21b6:	e8 55 f6 00 00                                  	call   0x7f1810
  7e21bb:	48 8d 35 83 be b9 00                            	lea    rsi,[rip+0xb9be83]        # 0x137e045
  7e21c2:	bf 34 00 00 00                                  	mov    edi,0x34
  7e21c7:	eb 1d                                           	jmp    0x7e21e6
  7e21c9:	e8 82 f7 00 00                                  	call   0x7f1950
  7e21ce:	48 8d 3d f4 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff4]        # 0x7e21c9
  7e21d5:	e8 36 f6 00 00                                  	call   0x7f1810
  7e21da:	48 8d 35 f0 87 b4 00                            	lea    rsi,[rip+0xb487f0]        # 0x132a9d1
  7e21e1:	bf 38 00 00 00                                  	mov    edi,0x38
  7e21e6:	31 c0                                           	xor    eax,eax
  7e21e8:	e8 23 88 4b 00                                  	call   0xc9aa10
  7e21ed:	0f 0b                                           	ud2
  7e21ef:	e8 5c f7 00 00                                  	call   0x7f1950
  7e21f4:	48 8d 3d f4 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff4]        # 0x7e21ef
  7e21fb:	be 08 09 00 00                                  	mov    esi,0x908
  7e2200:	e8 9b f6 00 00                                  	call   0x7f18a0
  7e2205:	48 8d 35 27 18 ac 00                            	lea    rsi,[rip+0xac1827]        # 0x12a3a33
  7e220c:	ba 08 09 00 00                                  	mov    edx,0x908
  7e2211:	bf 3c 00 00 00                                  	mov    edi,0x3c
  7e2216:	eb 50                                           	jmp    0x7e2268
  7e2218:	e8 33 f7 00 00                                  	call   0x7f1950
  7e221d:	48 8d 3d f4 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff4]        # 0x7e2218
  7e2224:	be c8 01 00 00                                  	mov    esi,0x1c8
  7e2229:	e8 72 f6 00 00                                  	call   0x7f18a0
  7e222e:	48 8d 35 3e 7c b6 00                            	lea    rsi,[rip+0xb67c3e]        # 0x1349e73
  7e2235:	ba c8 01 00 00                                  	mov    edx,0x1c8
  7e223a:	bf 40 00 00 00                                  	mov    edi,0x40
  7e223f:	eb 27                                           	jmp    0x7e2268
  7e2241:	e8 0a f7 00 00                                  	call   0x7f1950
  7e2246:	48 8d 3d f4 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff4]        # 0x7e2241
  7e224d:	be 20 00 00 00                                  	mov    esi,0x20
  7e2252:	e8 49 f6 00 00                                  	call   0x7f18a0
  7e2257:	48 8d 35 08 18 ac 00                            	lea    rsi,[rip+0xac1808]        # 0x12a3a66
  7e225e:	ba 20 00 00 00                                  	mov    edx,0x20
  7e2263:	bf 44 00 00 00                                  	mov    edi,0x44
  7e2268:	31 c0                                           	xor    eax,eax
  7e226a:	e8 a1 87 4b 00                                  	call   0xc9aa10
  7e226f:	0f 0b                                           	ud2
  7e2271:	90                                              	nop
  7e2272:	90                                              	nop
  7e2273:	90                                              	nop
  7e2274:	90                                              	nop
  7e2275:	90                                              	nop
  7e2276:	90                                              	nop
  7e2277:	90                                              	nop
  7e2278:	90                                              	nop
  7e2279:	90                                              	nop
  7e227a:	90                                              	nop
  7e227b:	90                                              	nop
  7e227c:	90                                              	nop
  7e227d:	90                                              	nop
  7e227e:	90                                              	nop
  7e227f:	90                                              	nop
  7e2280:	55                                              	push   rbp
  7e2281:	48 89 e5                                        	mov    rbp,rsp
  7e2284:	8b 07                                           	mov    eax,DWORD PTR [rdi]
  7e2286:	83 c0 03                                        	add    eax,0x3
  7e2289:	83 e0 fc                                        	and    eax,0xfffffffc
  7e228c:	8b 44 07 0c                                     	mov    eax,DWORD PTR [rdi+rax*1+0xc]
  7e2290:	89 06                                           	mov    DWORD PTR [rsi],eax
  7e2292:	b8 01 00 00 00                                  	mov    eax,0x1
  7e2297:	5d                                              	pop    rbp
  7e2298:	c3                                              	ret
  7e2299:	90                                              	nop
  7e229a:	90                                              	nop
  7e229b:	90                                              	nop
  7e229c:	90                                              	nop
  7e229d:	90                                              	nop
  7e229e:	90                                              	nop
  7e229f:	90                                              	nop
  7e22a0:	55                                              	push   rbp
  7e22a1:	48 89 e5                                        	mov    rbp,rsp
  7e22a4:	8b 0f                                           	mov    ecx,DWORD PTR [rdi]
  7e22a6:	31 c0                                           	xor    eax,eax
  7e22a8:	83 c1 03                                        	add    ecx,0x3
  7e22ab:	83 e1 fc                                        	and    ecx,0xfffffffc
  7e22ae:	83 7c 0f 0c 03                                  	cmp    DWORD PTR [rdi+rcx*1+0xc],0x3
  7e22b3:	75 1d                                           	jne    0x7e22d2
  7e22b5:	69 44 0f 10 a0 86 01 00                         	imul   eax,DWORD PTR [rdi+rcx*1+0x10],0x186a0
  7e22bd:	69 54 0f 14 e8 03 00 00                         	imul   edx,DWORD PTR [rdi+rcx*1+0x14],0x3e8
  7e22c5:	01 c2                                           	add    edx,eax
  7e22c7:	03 54 0f 18                                     	add    edx,DWORD PTR [rdi+rcx*1+0x18]
  7e22cb:	b8 01 00 00 00                                  	mov    eax,0x1
  7e22d0:	89 16                                           	mov    DWORD PTR [rsi],edx
  7e22d2:	5d                                              	pop    rbp
  7e22d3:	c3                                              	ret
  7e22d4:	90                                              	nop
  7e22d5:	90                                              	nop
  7e22d6:	90                                              	nop
  7e22d7:	90                                              	nop
  7e22d8:	90                                              	nop
  7e22d9:	90                                              	nop
  7e22da:	90                                              	nop
  7e22db:	90                                              	nop
  7e22dc:	90                                              	nop
  7e22dd:	90                                              	nop
  7e22de:	90                                              	nop
  7e22df:	90                                              	nop
  7e22e0:	48 83 3d 08 2d 25 03 00                         	cmp    QWORD PTR [rip+0x3252d08],0x0        # 0x3a34ff0
  7e22e8:	48 89 fa                                        	mov    rdx,rdi
  7e22eb:	74 66                                           	je     0x7e2353
  7e22ed:	48 83 3d 03 2d 25 03 00                         	cmp    QWORD PTR [rip+0x3252d03],0x0        # 0x3a34ff8
  7e22f5:	74 65                                           	je     0x7e235c
  7e22f7:	48 83 3d 01 2d 25 03 00                         	cmp    QWORD PTR [rip+0x3252d01],0x0        # 0x3a35000
  7e22ff:	74 64                                           	je     0x7e2365
  7e2301:	48 83 3d ff 2c 25 03 00                         	cmp    QWORD PTR [rip+0x3252cff],0x0        # 0x3a35008
  7e2309:	74 63                                           	je     0x7e236e
  7e230b:	48 83 3d fd 2c 25 03 00                         	cmp    QWORD PTR [rip+0x3252cfd],0x0        # 0x3a35010
  7e2313:	74 62                                           	je     0x7e2377
  7e2315:	48 83 3d fb 2c 25 03 00                         	cmp    QWORD PTR [rip+0x3252cfb],0x0        # 0x3a35018
  7e231d:	74 61                                           	je     0x7e2380
  7e231f:	48 83 3d f9 2c 25 03 00                         	cmp    QWORD PTR [rip+0x3252cf9],0x0        # 0x3a35020
  7e2327:	74 60                                           	je     0x7e2389
  7e2329:	48 83 3d f7 2c 25 03 00                         	cmp    QWORD PTR [rip+0x3252cf7],0x0        # 0x3a35028
  7e2331:	74 5f                                           	je     0x7e2392
  7e2333:	55                                              	push   rbp
  7e2334:	48 89 e5                                        	mov    rbp,rsp
  7e2337:	48 8d 3d 55 18 b9 00                            	lea    rdi,[rip+0xb91855]        # 0x1373b93
  7e233e:	48 8d 35 70 2a b7 00                            	lea    rsi,[rip+0xb72a70]        # 0x1354db5
  7e2345:	31 c0                                           	xor    eax,eax
  7e2347:	e8 c4 b0 a7 ff                                  	call   0x25d410
  7e234c:	b8 ff ff ff ff                                  	mov    eax,0xffffffff
  7e2351:	5d                                              	pop    rbp
  7e2352:	c3                                              	ret
  7e2353:	48 8d 05 96 2c 25 03                            	lea    rax,[rip+0x3252c96]        # 0x3a34ff0
  7e235a:	eb 3d                                           	jmp    0x7e2399
  7e235c:	48 8d 05 95 2c 25 03                            	lea    rax,[rip+0x3252c95]        # 0x3a34ff8
  7e2363:	eb 34                                           	jmp    0x7e2399
  7e2365:	48 8d 05 94 2c 25 03                            	lea    rax,[rip+0x3252c94]        # 0x3a35000
  7e236c:	eb 2b                                           	jmp    0x7e2399
  7e236e:	48 8d 05 93 2c 25 03                            	lea    rax,[rip+0x3252c93]        # 0x3a35008
  7e2375:	eb 22                                           	jmp    0x7e2399
  7e2377:	48 8d 05 92 2c 25 03                            	lea    rax,[rip+0x3252c92]        # 0x3a35010
  7e237e:	eb 19                                           	jmp    0x7e2399
  7e2380:	48 8d 05 91 2c 25 03                            	lea    rax,[rip+0x3252c91]        # 0x3a35018
  7e2387:	eb 10                                           	jmp    0x7e2399
  7e2389:	48 8d 05 90 2c 25 03                            	lea    rax,[rip+0x3252c90]        # 0x3a35020
  7e2390:	eb 07                                           	jmp    0x7e2399
  7e2392:	48 8d 05 8f 2c 25 03                            	lea    rax,[rip+0x3252c8f]        # 0x3a35028
  7e2399:	48 89 10                                        	mov    QWORD PTR [rax],rdx
  7e239c:	31 c0                                           	xor    eax,eax
  7e239e:	c3                                              	ret
  7e239f:	90                                              	nop
  7e23a0:	55                                              	push   rbp
  7e23a1:	48 89 e5                                        	mov    rbp,rsp
  7e23a4:	41 57                                           	push   r15
  7e23a6:	41 56                                           	push   r14
  7e23a8:	41 55                                           	push   r13
  7e23aa:	41 54                                           	push   r12
  7e23ac:	53                                              	push   rbx
  7e23ad:	48 83 ec 18                                     	sub    rsp,0x18
  7e23b1:	48 8b 46 68                                     	mov    rax,QWORD PTR [rsi+0x68]
  7e23b5:	4c 8b 7e 48                                     	mov    r15,QWORD PTR [rsi+0x48]
  7e23b9:	48 8b 17                                        	mov    rdx,QWORD PTR [rdi]
  7e23bc:	48 89 75 d0                                     	mov    QWORD PTR [rbp-0x30],rsi
  7e23c0:	48 89 7d c0                                     	mov    QWORD PTR [rbp-0x40],rdi
  7e23c4:	8b 48 34                                        	mov    ecx,DWORD PTR [rax+0x34]
  7e23c7:	8b 40 38                                        	mov    eax,DWORD PTR [rax+0x38]
  7e23ca:	49 83 3f ff                                     	cmp    QWORD PTR [r15],0xffffffffffffffff
  7e23ce:	48 89 55 c8                                     	mov    QWORD PTR [rbp-0x38],rdx
  7e23d2:	8d 44 01 02                                     	lea    eax,[rcx+rax*1+0x2]
  7e23d6:	48 98                                           	cdqe
  7e23d8:	4c 8d 24 c2                                     	lea    r12,[rdx+rax*8]
  7e23dc:	74 21                                           	je     0x7e23ff
  7e23de:	be 02 00 00 00                                  	mov    esi,0x2
  7e23e3:	4c 89 e7                                        	mov    rdi,r12
  7e23e6:	4d 8d 6c 24 08                                  	lea    r13,[r12+0x8]
  7e23eb:	e8 30 73 a7 ff                                  	call   0x259720
  7e23f0:	49 8b 37                                        	mov    rsi,QWORD PTR [r15]
  7e23f3:	4c 89 ef                                        	mov    rdi,r13
  7e23f6:	49 83 c4 10                                     	add    r12,0x10
  7e23fa:	e8 21 73 a7 ff                                  	call   0x259720
  7e23ff:	be 03 00 00 00                                  	mov    esi,0x3
  7e2404:	4c 89 e7                                        	mov    rdi,r12
  7e2407:	4d 8d 6c 24 08                                  	lea    r13,[r12+0x8]
  7e240c:	e8 0f 73 a7 ff                                  	call   0x259720
  7e2411:	49 8b 77 08                                     	mov    rsi,QWORD PTR [r15+0x8]
  7e2415:	4c 89 ef                                        	mov    rdi,r13
  7e2418:	49 8d 5c 24 10                                  	lea    rbx,[r12+0x10]
  7e241d:	e8 fe 72 a7 ff                                  	call   0x259720
  7e2422:	be 04 00 00 00                                  	mov    esi,0x4
  7e2427:	48 89 df                                        	mov    rdi,rbx
  7e242a:	4d 8d 6c 24 18                                  	lea    r13,[r12+0x18]
  7e242f:	e8 ec 72 a7 ff                                  	call   0x259720
  7e2434:	49 8b 77 10                                     	mov    rsi,QWORD PTR [r15+0x10]
  7e2438:	4c 89 ef                                        	mov    rdi,r13
  7e243b:	49 8d 5c 24 20                                  	lea    rbx,[r12+0x20]
  7e2440:	e8 db 72 a7 ff                                  	call   0x259720
  7e2445:	be 05 00 00 00                                  	mov    esi,0x5
  7e244a:	48 89 df                                        	mov    rdi,rbx
  7e244d:	4d 8d 6c 24 28                                  	lea    r13,[r12+0x28]
  7e2452:	e8 c9 72 a7 ff                                  	call   0x259720
  7e2457:	49 8b 77 18                                     	mov    rsi,QWORD PTR [r15+0x18]
  7e245b:	4c 89 ef                                        	mov    rdi,r13
  7e245e:	49 8d 5c 24 30                                  	lea    rbx,[r12+0x30]
  7e2463:	e8 b8 72 a7 ff                                  	call   0x259720
  7e2468:	be 06 00 00 00                                  	mov    esi,0x6
  7e246d:	48 89 df                                        	mov    rdi,rbx
  7e2470:	4d 8d 6c 24 38                                  	lea    r13,[r12+0x38]
  7e2475:	e8 a6 72 a7 ff                                  	call   0x259720
  7e247a:	49 8b 77 20                                     	mov    rsi,QWORD PTR [r15+0x20]
  7e247e:	4c 89 ef                                        	mov    rdi,r13
  7e2481:	49 8d 5c 24 40                                  	lea    rbx,[r12+0x40]
  7e2486:	e8 95 72 a7 ff                                  	call   0x259720
  7e248b:	be 08 00 00 00                                  	mov    esi,0x8
  7e2490:	48 89 df                                        	mov    rdi,rbx
  7e2493:	4d 8d 6c 24 48                                  	lea    r13,[r12+0x48]
  7e2498:	e8 83 72 a7 ff                                  	call   0x259720
  7e249d:	49 8b 77 30                                     	mov    rsi,QWORD PTR [r15+0x30]
  7e24a1:	4c 89 ef                                        	mov    rdi,r13
  7e24a4:	49 8d 5c 24 50                                  	lea    rbx,[r12+0x50]
  7e24a9:	e8 72 72 a7 ff                                  	call   0x259720
  7e24ae:	be 09 00 00 00                                  	mov    esi,0x9
  7e24b3:	48 89 df                                        	mov    rdi,rbx
  7e24b6:	4d 8d 6c 24 58                                  	lea    r13,[r12+0x58]
  7e24bb:	e8 60 72 a7 ff                                  	call   0x259720
  7e24c0:	49 8b 77 38                                     	mov    rsi,QWORD PTR [r15+0x38]
  7e24c4:	4c 89 ef                                        	mov    rdi,r13
  7e24c7:	49 8d 5c 24 60                                  	lea    rbx,[r12+0x60]
  7e24cc:	e8 4f 72 a7 ff                                  	call   0x259720
  7e24d1:	be 07 00 00 00                                  	mov    esi,0x7
  7e24d6:	48 89 df                                        	mov    rdi,rbx
  7e24d9:	4d 8d 74 24 68                                  	lea    r14,[r12+0x68]
  7e24de:	e8 3d 72 a7 ff                                  	call   0x259720
  7e24e3:	49 8b 77 28                                     	mov    rsi,QWORD PTR [r15+0x28]
  7e24e7:	4c 89 f7                                        	mov    rdi,r14
  7e24ea:	4d 8d 6c 24 70                                  	lea    r13,[r12+0x70]
  7e24ef:	e8 2c 72 a7 ff                                  	call   0x259720
  7e24f4:	4c 8b 7d d0                                     	mov    r15,QWORD PTR [rbp-0x30]
  7e24f8:	49 83 bf 80 00 00 00 00                         	cmp    QWORD PTR [r15+0x80],0x0
  7e2500:	74 28                                           	je     0x7e252a
  7e2502:	be 0f 00 00 00                                  	mov    esi,0xf
  7e2507:	4c 89 ef                                        	mov    rdi,r13
  7e250a:	49 8d 5c 24 78                                  	lea    rbx,[r12+0x78]
  7e250f:	e8 0c 72 a7 ff                                  	call   0x259720
  7e2514:	49 8b b7 80 00 00 00                            	mov    rsi,QWORD PTR [r15+0x80]
  7e251b:	48 89 df                                        	mov    rdi,rbx
  7e251e:	49 83 ec 80                                     	sub    r12,0xffffffffffffff80
  7e2522:	e8 f9 71 a7 ff                                  	call   0x259720
  7e2527:	4d 89 e5                                        	mov    r13,r12
  7e252a:	be 12 00 00 00                                  	mov    esi,0x12
  7e252f:	4c 89 ef                                        	mov    rdi,r13
  7e2532:	49 8d 5d 08                                     	lea    rbx,[r13+0x8]
  7e2536:	e8 e5 71 a7 ff                                  	call   0x259720
  7e253b:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  7e253e:	48 89 df                                        	mov    rdi,rbx
  7e2541:	4d 8d 65 10                                     	lea    r12,[r13+0x10]
  7e2545:	48 8b 40 40                                     	mov    rax,QWORD PTR [rax+0x40]
  7e2549:	48 8b 40 30                                     	mov    rax,QWORD PTR [rax+0x30]
  7e254d:	48 63 b0 14 01 00 00                            	movsxd rsi,DWORD PTR [rax+0x114]
  7e2554:	e8 c7 71 a7 ff                                  	call   0x259720
  7e2559:	49 83 bf 90 00 00 00 00                         	cmp    QWORD PTR [r15+0x90],0x0
  7e2561:	74 4b                                           	je     0x7e25ae
  7e2563:	be 10 00 00 00                                  	mov    esi,0x10
  7e2568:	4c 89 e7                                        	mov    rdi,r12
  7e256b:	49 8d 5d 18                                     	lea    rbx,[r13+0x18]
  7e256f:	e8 ac 71 a7 ff                                  	call   0x259720
  7e2574:	49 8b b7 90 00 00 00                            	mov    rsi,QWORD PTR [r15+0x90]
  7e257b:	48 89 df                                        	mov    rdi,rbx
  7e257e:	4d 8d 75 20                                     	lea    r14,[r13+0x20]
  7e2582:	e8 99 71 a7 ff                                  	call   0x259720
  7e2587:	be 11 00 00 00                                  	mov    esi,0x11
  7e258c:	4c 89 f7                                        	mov    rdi,r14
  7e258f:	49 8d 5d 28                                     	lea    rbx,[r13+0x28]
  7e2593:	e8 88 71 a7 ff                                  	call   0x259720
  7e2598:	49 63 b7 98 00 00 00                            	movsxd rsi,DWORD PTR [r15+0x98]
  7e259f:	48 89 df                                        	mov    rdi,rbx
  7e25a2:	49 83 c5 30                                     	add    r13,0x30
  7e25a6:	e8 75 71 a7 ff                                  	call   0x259720
  7e25ab:	4d 89 ec                                        	mov    r12,r13
  7e25ae:	be 13 00 00 00                                  	mov    esi,0x13
  7e25b3:	4c 89 e7                                        	mov    rdi,r12
  7e25b6:	49 8d 5c 24 08                                  	lea    rbx,[r12+0x8]
  7e25bb:	e8 60 71 a7 ff                                  	call   0x259720
  7e25c0:	48 63 35 f5 c2 52 03                            	movsxd rsi,DWORD PTR [rip+0x352c2f5]        # 0x3d0e8bc
  7e25c7:	48 89 df                                        	mov    rdi,rbx
  7e25ca:	4d 8d 6c 24 10                                  	lea    r13,[r12+0x10]
  7e25cf:	e8 4c 71 a7 ff                                  	call   0x259720
  7e25d4:	49 83 bf a0 00 00 00 00                         	cmp    QWORD PTR [r15+0xa0],0x0
  7e25dc:	74 4e                                           	je     0x7e262c
  7e25de:	be 14 00 00 00                                  	mov    esi,0x14
  7e25e3:	4c 89 ef                                        	mov    rdi,r13
  7e25e6:	49 8d 5c 24 18                                  	lea    rbx,[r12+0x18]
  7e25eb:	e8 30 71 a7 ff                                  	call   0x259720
  7e25f0:	49 8b b7 a0 00 00 00                            	mov    rsi,QWORD PTR [r15+0xa0]
  7e25f7:	48 89 df                                        	mov    rdi,rbx
  7e25fa:	4d 8d 74 24 20                                  	lea    r14,[r12+0x20]
  7e25ff:	e8 1c 71 a7 ff                                  	call   0x259720
  7e2604:	be 15 00 00 00                                  	mov    esi,0x15
  7e2609:	4c 89 f7                                        	mov    rdi,r14
  7e260c:	49 8d 5c 24 28                                  	lea    rbx,[r12+0x28]
  7e2611:	e8 0a 71 a7 ff                                  	call   0x259720
  7e2616:	49 63 b7 a8 00 00 00                            	movsxd rsi,DWORD PTR [r15+0xa8]
  7e261d:	48 89 df                                        	mov    rdi,rbx
  7e2620:	49 83 c4 30                                     	add    r12,0x30
  7e2624:	e8 f7 70 a7 ff                                  	call   0x259720
  7e2629:	4d 89 e5                                        	mov    r13,r12
  7e262c:	49 8b 47 70                                     	mov    rax,QWORD PTR [r15+0x70]
  7e2630:	48 8b 88 c8 00 00 00                            	mov    rcx,QWORD PTR [rax+0xc8]
  7e2637:	48 3b 88 c0 00 00 00                            	cmp    rcx,QWORD PTR [rax+0xc0]
  7e263e:	72 39                                           	jb     0x7e2679
  7e2640:	be 16 00 00 00                                  	mov    esi,0x16
  7e2645:	4c 89 ef                                        	mov    rdi,r13
  7e2648:	49 8d 5d 08                                     	lea    rbx,[r13+0x8]
  7e264c:	e8 cf 70 a7 ff                                  	call   0x259720
  7e2651:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  7e2654:	49 8b 4f 70                                     	mov    rcx,QWORD PTR [r15+0x70]
  7e2658:	48 89 df                                        	mov    rdi,rbx
  7e265b:	49 83 c5 10                                     	add    r13,0x10
  7e265f:	48 8b 80 00 02 00 00                            	mov    rax,QWORD PTR [rax+0x200]
  7e2666:	48 8b b0 18 02 00 00                            	mov    rsi,QWORD PTR [rax+0x218]
  7e266d:	48 03 b1 c8 00 00 00                            	add    rsi,QWORD PTR [rcx+0xc8]
  7e2674:	e8 a7 70 a7 ff                                  	call   0x259720
  7e2679:	be 17 00 00 00                                  	mov    esi,0x17
  7e267e:	4c 89 ef                                        	mov    rdi,r13
  7e2681:	e8 9a 70 a7 ff                                  	call   0x259720
  7e2686:	49 8b 47 70                                     	mov    rax,QWORD PTR [r15+0x70]
  7e268a:	48 83 b8 d8 00 00 00 00                         	cmp    QWORD PTR [rax+0xd8],0x0
  7e2692:	74 0c                                           	je     0x7e26a0
  7e2694:	41 0f b7 8f ac 00 00 00                         	movzx  ecx,WORD PTR [r15+0xac]
  7e269c:	85 c9                                           	test   ecx,ecx
  7e269e:	75 03                                           	jne    0x7e26a3
  7e26a0:	8b 48 78                                        	mov    ecx,DWORD PTR [rax+0x78]
  7e26a3:	49 8d 7d 08                                     	lea    rdi,[r13+0x8]
  7e26a7:	48 63 f1                                        	movsxd rsi,ecx
  7e26aa:	49 8d 5d 10                                     	lea    rbx,[r13+0x10]
  7e26ae:	e8 6d 70 a7 ff                                  	call   0x259720
  7e26b3:	48 89 df                                        	mov    rdi,rbx
  7e26b6:	31 f6                                           	xor    esi,esi
  7e26b8:	49 83 c5 18                                     	add    r13,0x18
  7e26bc:	e8 5f 70 a7 ff                                  	call   0x259720
  7e26c1:	4c 89 ef                                        	mov    rdi,r13
  7e26c4:	31 f6                                           	xor    esi,esi
  7e26c6:	e8 55 70 a7 ff                                  	call   0x259720
  7e26cb:	49 8b 7f 48                                     	mov    rdi,QWORD PTR [r15+0x48]
  7e26cf:	48 8d 35 aa 99 41 02                            	lea    rsi,[rip+0x24199aa]        # 0x2bfc080
  7e26d6:	e8 15 67 42 00                                  	call   0xc08df0
  7e26db:	49 c7 47 48 00 00 00 00                         	mov    QWORD PTR [r15+0x48],0x0
  7e26e3:	48 8b 5d c8                                     	mov    rbx,QWORD PTR [rbp-0x38]
  7e26e7:	49 8b 47 68                                     	mov    rax,QWORD PTR [r15+0x68]
  7e26eb:	48 83 c3 f8                                     	add    rbx,0xfffffffffffffff8
  7e26ef:	48 63 70 34                                     	movsxd rsi,DWORD PTR [rax+0x34]
  7e26f3:	48 89 df                                        	mov    rdi,rbx
  7e26f6:	e8 25 70 a7 ff                                  	call   0x259720
  7e26fb:	48 8b 45 c0                                     	mov    rax,QWORD PTR [rbp-0x40]
  7e26ff:	48 89 18                                        	mov    QWORD PTR [rax],rbx
  7e2702:	31 c0                                           	xor    eax,eax
  7e2704:	48 83 c4 18                                     	add    rsp,0x18
  7e2708:	5b                                              	pop    rbx
  7e2709:	41 5c                                           	pop    r12
  7e270b:	41 5d                                           	pop    r13
  7e270d:	41 5e                                           	pop    r14
  7e270f:	41 5f                                           	pop    r15
  7e2711:	5d                                              	pop    rbp
  7e2712:	c3                                              	ret
  7e2713:	90                                              	nop
  7e2714:	90                                              	nop
  7e2715:	90                                              	nop
  7e2716:	90                                              	nop
  7e2717:	90                                              	nop
  7e2718:	90                                              	nop
  7e2719:	90                                              	nop
  7e271a:	90                                              	nop
  7e271b:	90                                              	nop
  7e271c:	90                                              	nop
  7e271d:	90                                              	nop
  7e271e:	90                                              	nop
  7e271f:	90                                              	nop
  7e2720:	55                                              	push   rbp
  7e2721:	48 89 e5                                        	mov    rbp,rsp
  7e2724:	41 57                                           	push   r15
  7e2726:	41 56                                           	push   r14
  7e2728:	41 55                                           	push   r13
  7e272a:	41 54                                           	push   r12
  7e272c:	53                                              	push   rbx
  7e272d:	48 81 ec b8 00 00 00                            	sub    rsp,0xb8
  7e2734:	48 8d 05 d5 9b 13 03                            	lea    rax,[rip+0x3139bd5]        # 0x391c310
  7e273b:	48 89 95 20 ff ff ff                            	mov    QWORD PTR [rbp-0xe0],rdx
  7e2742:	48 89 b5 28 ff ff ff                            	mov    QWORD PTR [rbp-0xd8],rsi
  7e2749:	48 8d 4d 98                                     	lea    rcx,[rbp-0x68]
  7e274d:	31 f6                                           	xor    esi,esi
  7e274f:	31 d2                                           	xor    edx,edx
  7e2751:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  7e2754:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  7e2758:	48 89 bd 58 ff ff ff                            	mov    QWORD PTR [rbp-0xa8],rdi
  7e275f:	48 8b 87 40 01 00 00                            	mov    rax,QWORD PTR [rdi+0x140]
  7e2766:	48 c7 45 98 00 00 00 00                         	mov    QWORD PTR [rbp-0x68],0x0
  7e276e:	c7 45 a8 00 00 00 00                            	mov    DWORD PTR [rbp-0x58],0x0
  7e2775:	48 89 4d a0                                     	mov    QWORD PTR [rbp-0x60],rcx
  7e2779:	48 c7 45 b0 00 00 00 00                         	mov    QWORD PTR [rbp-0x50],0x0
  7e2781:	48 89 85 30 ff ff ff                            	mov    QWORD PTR [rbp-0xd0],rax
  7e2788:	48 8b 47 08                                     	mov    rax,QWORD PTR [rdi+0x8]
  7e278c:	48 8b 98 00 02 00 00                            	mov    rbx,QWORD PTR [rax+0x200]
  7e2793:	48 89 df                                        	mov    rdi,rbx
  7e2796:	e8 85 40 ae ff                                  	call   0x2c6820
  7e279b:	4c 8b 73 08                                     	mov    r14,QWORD PTR [rbx+0x8]
  7e279f:	49 39 de                                        	cmp    r14,rbx
  7e27a2:	0f 84 f6 00 00 00                               	je     0x7e289e
  7e27a8:	4c 8d 65 a8                                     	lea    r12,[rbp-0x58]
  7e27ac:	eb 1f                                           	jmp    0x7e27cd
  7e27ae:	49 83 c7 18                                     	add    r15,0x18
  7e27b2:	31 f6                                           	xor    esi,esi
  7e27b4:	31 d2                                           	xor    edx,edx
  7e27b6:	4c 89 ff                                        	mov    rdi,r15
  7e27b9:	e8 22 2f ff ff                                  	call   0x7d56e0
  7e27be:	66 90                                           	xchg   ax,ax
  7e27c0:	4d 8b 76 08                                     	mov    r14,QWORD PTR [r14+0x8]
  7e27c4:	49 39 de                                        	cmp    r14,rbx
  7e27c7:	0f 84 d1 00 00 00                               	je     0x7e289e
  7e27cd:	83 3d 5c 28 25 03 00                            	cmp    DWORD PTR [rip+0x325285c],0x0        # 0x3a35030
  7e27d4:	41 0f b7 46 64                                  	movzx  eax,WORD PTR [r14+0x64]
  7e27d9:	74 15                                           	je     0x7e27f0
  7e27db:	f7 d0                                           	not    eax
  7e27dd:	a8 03                                           	test   al,0x3
  7e27df:	75 df                                           	jne    0x7e27c0
  7e27e1:	eb 11                                           	jmp    0x7e27f4
  7e27e3:	66 66 66 66 2e 0f 1f 84 00 00 00 00 00          	data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  7e27f0:	a8 07                                           	test   al,0x7
  7e27f2:	74 cc                                           	je     0x7e27c0
  7e27f4:	41 0f b7 46 60                                  	movzx  eax,WORD PTR [r14+0x60]
  7e27f9:	a9 02 04 00 00                                  	test   eax,0x402
  7e27fe:	75 c0                                           	jne    0x7e27c0
  7e2800:	4d 8b 6e 50                                     	mov    r13,QWORD PTR [r14+0x50]
  7e2804:	4d 85 ed                                        	test   r13,r13
  7e2807:	74 b7                                           	je     0x7e27c0
  7e2809:	49 8d 7d 18                                     	lea    rdi,[r13+0x18]
  7e280d:	31 f6                                           	xor    esi,esi
  7e280f:	31 d2                                           	xor    edx,edx
  7e2811:	e8 aa 28 ff ff                                  	call   0x7d50c0
  7e2816:	49 8b 85 b0 00 00 00                            	mov    rax,QWORD PTR [r13+0xb0]
  7e281d:	48 85 c0                                        	test   rax,rax
  7e2820:	74 3f                                           	je     0x7e2861
  7e2822:	66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00       	data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  7e2830:	48 8d 78 18                                     	lea    rdi,[rax+0x18]
  7e2834:	49 89 c7                                        	mov    r15,rax
  7e2837:	31 f6                                           	xor    esi,esi
  7e2839:	31 d2                                           	xor    edx,edx
  7e283b:	e8 80 28 ff ff                                  	call   0x7d50c0
  7e2840:	49 83 c5 18                                     	add    r13,0x18
  7e2844:	31 f6                                           	xor    esi,esi
  7e2846:	31 d2                                           	xor    edx,edx
  7e2848:	4c 89 ef                                        	mov    rdi,r13
  7e284b:	e8 90 2e ff ff                                  	call   0x7d56e0
  7e2850:	49 8b 87 b0 00 00 00                            	mov    rax,QWORD PTR [r15+0xb0]
  7e2857:	4d 89 fd                                        	mov    r13,r15
  7e285a:	48 85 c0                                        	test   rax,rax
  7e285d:	75 d1                                           	jne    0x7e2830
  7e285f:	eb 03                                           	jmp    0x7e2864
  7e2861:	4d 89 ef                                        	mov    r15,r13
  7e2864:	41 0f b6 87 9d 00 00 00                         	movzx  eax,BYTE PTR [r15+0x9d]
  7e286c:	83 f8 04                                        	cmp    eax,0x4
  7e286f:	0f 87 39 ff ff ff                               	ja     0x7e27ae
  7e2875:	83 f8 03                                        	cmp    eax,0x3
  7e2878:	0f 84 30 ff ff ff                               	je     0x7e27ae
  7e287e:	49 83 c7 18                                     	add    r15,0x18
  7e2882:	31 f6                                           	xor    esi,esi
  7e2884:	31 d2                                           	xor    edx,edx
  7e2886:	4c 89 ff                                        	mov    rdi,r15
  7e2889:	e8 52 2e ff ff                                  	call   0x7d56e0
  7e288e:	4c 89 f7                                        	mov    rdi,r14
  7e2891:	4c 89 e6                                        	mov    rsi,r12
  7e2894:	e8 17 50 a8 ff                                  	call   0x2678b0
  7e2899:	e9 22 ff ff ff                                  	jmp    0x7e27c0
  7e289e:	48 89 df                                        	mov    rdi,rbx
  7e28a1:	31 f6                                           	xor    esi,esi
  7e28a3:	31 d2                                           	xor    edx,edx
  7e28a5:	e8 c6 3f ae ff                                  	call   0x2c6870
  7e28aa:	4c 8b ad 58 ff ff ff                            	mov    r13,QWORD PTR [rbp-0xa8]
  7e28b1:	48 8d 1d c8 97 41 02                            	lea    rbx,[rip+0x24197c8]        # 0x2bfc080
  7e28b8:	8b 45 a8                                        	mov    eax,DWORD PTR [rbp-0x58]
  7e28bb:	bf 30 00 00 00                                  	mov    edi,0x30
  7e28c0:	ba 02 01 00 00                                  	mov    edx,0x102
  7e28c5:	4d 8b 75 08                                     	mov    r14,QWORD PTR [r13+0x8]
  7e28c9:	48 89 de                                        	mov    rsi,rbx
  7e28cc:	89 85 60 ff ff ff                               	mov    DWORD PTR [rbp-0xa0],eax
  7e28d2:	e8 79 62 42 00                                  	call   0xc08b50
  7e28d7:	48 8b 55 a0                                     	mov    rdx,QWORD PTR [rbp-0x60]
  7e28db:	48 8d 0d 36 5a a8 ff                            	lea    rcx,[rip+0xffffffffffa85a36]        # 0x268318
  7e28e2:	c7 00 03 00 00 00                               	mov    DWORD PTR [rax],0x3
  7e28e8:	4d 89 f7                                        	mov    r15,r14
  7e28eb:	48 89 48 08                                     	mov    QWORD PTR [rax+0x8],rcx
  7e28ef:	4c 89 70 10                                     	mov    QWORD PTR [rax+0x10],r14
  7e28f3:	41 be 8c 00 00 00                               	mov    r14d,0x8c
  7e28f9:	48 8d 48 20                                     	lea    rcx,[rax+0x20]
  7e28fd:	48 c7 40 18 78 00 00 00                         	mov    QWORD PTR [rax+0x18],0x78
  7e2905:	48 c7 40 20 00 00 00 00                         	mov    QWORD PTR [rax+0x20],0x0
  7e290d:	48 89 50 28                                     	mov    QWORD PTR [rax+0x28],rdx
  7e2911:	48 89 02                                        	mov    QWORD PTR [rdx],rax
  7e2914:	48 89 4d a0                                     	mov    QWORD PTR [rbp-0x60],rcx
  7e2918:	eb 17                                           	jmp    0x7e2931
  7e291a:	66 0f 1f 44 00 00                               	nop    WORD PTR [rax+rax*1+0x0]
  7e2920:	4f 8d b4 26 34 03 00 00                         	lea    r14,[r14+r12*1+0x334]
  7e2928:	4d 85 ed                                        	test   r13,r13
  7e292b:	0f 84 75 01 00 00                               	je     0x7e2aa6
  7e2931:	bf 30 00 00 00                                  	mov    edi,0x30
  7e2936:	48 89 de                                        	mov    rsi,rbx
  7e2939:	ba 02 01 00 00                                  	mov    edx,0x102
  7e293e:	e8 0d 62 42 00                                  	call   0xc08b50
  7e2943:	48 8b 55 a0                                     	mov    rdx,QWORD PTR [rbp-0x60]
  7e2947:	48 8d 0d d2 59 a8 ff                            	lea    rcx,[rip+0xffffffffffa859d2]        # 0x268320
  7e294e:	c7 00 01 00 00 00                               	mov    DWORD PTR [rax],0x1
  7e2954:	bf 30 00 00 00                                  	mov    edi,0x30
  7e2959:	48 89 de                                        	mov    rsi,rbx
  7e295c:	48 89 48 08                                     	mov    QWORD PTR [rax+0x8],rcx
  7e2960:	4c 89 68 10                                     	mov    QWORD PTR [rax+0x10],r13
  7e2964:	48 c7 40 18 e0 00 00 00                         	mov    QWORD PTR [rax+0x18],0xe0
  7e296c:	48 c7 40 20 00 00 00 00                         	mov    QWORD PTR [rax+0x20],0x0
  7e2974:	48 8d 48 20                                     	lea    rcx,[rax+0x20]
  7e2978:	48 89 50 28                                     	mov    QWORD PTR [rax+0x28],rdx
  7e297c:	48 89 02                                        	mov    QWORD PTR [rdx],rax
  7e297f:	ba 02 01 00 00                                  	mov    edx,0x102
  7e2984:	48 89 4d a0                                     	mov    QWORD PTR [rbp-0x60],rcx
  7e2988:	e8 c3 61 42 00                                  	call   0xc08b50
  7e298d:	48 8b 55 a0                                     	mov    rdx,QWORD PTR [rbp-0x60]
  7e2991:	48 8d 0d 90 59 a8 ff                            	lea    rcx,[rip+0xffffffffffa85990]        # 0x268328
  7e2998:	c7 00 02 00 00 00                               	mov    DWORD PTR [rax],0x2
  7e299e:	bf 30 00 00 00                                  	mov    edi,0x30
  7e29a3:	48 89 de                                        	mov    rsi,rbx
  7e29a6:	48 89 48 08                                     	mov    QWORD PTR [rax+0x8],rcx
  7e29aa:	4c 89 68 10                                     	mov    QWORD PTR [rax+0x10],r13
  7e29ae:	48 c7 40 18 00 02 00 00                         	mov    QWORD PTR [rax+0x18],0x200
  7e29b6:	48 c7 40 20 00 00 00 00                         	mov    QWORD PTR [rax+0x20],0x0
  7e29be:	48 8d 48 20                                     	lea    rcx,[rax+0x20]
  7e29c2:	48 89 50 28                                     	mov    QWORD PTR [rax+0x28],rdx
  7e29c6:	48 89 02                                        	mov    QWORD PTR [rdx],rax
  7e29c9:	ba 02 01 00 00                                  	mov    edx,0x102
  7e29ce:	48 89 4d a0                                     	mov    QWORD PTR [rbp-0x60],rcx
  7e29d2:	e8 79 61 42 00                                  	call   0xc08b50
  7e29d7:	48 8b 55 a0                                     	mov    rdx,QWORD PTR [rbp-0x60]
  7e29db:	48 8d 0d 4e 59 a8 ff                            	lea    rcx,[rip+0xffffffffffa8594e]        # 0x268330
  7e29e2:	c7 00 07 00 00 00                               	mov    DWORD PTR [rax],0x7
  7e29e8:	4c 89 ef                                        	mov    rdi,r13
  7e29eb:	31 f6                                           	xor    esi,esi
  7e29ed:	48 89 48 08                                     	mov    QWORD PTR [rax+0x8],rcx
  7e29f1:	4c 89 68 10                                     	mov    QWORD PTR [rax+0x10],r13
  7e29f5:	48 c7 40 18 18 00 00 00                         	mov    QWORD PTR [rax+0x18],0x18
  7e29fd:	48 c7 40 20 00 00 00 00                         	mov    QWORD PTR [rax+0x20],0x0
  7e2a05:	48 8d 48 20                                     	lea    rcx,[rax+0x20]
  7e2a09:	48 89 50 28                                     	mov    QWORD PTR [rax+0x28],rdx
  7e2a0d:	48 89 02                                        	mov    QWORD PTR [rdx],rax
  7e2a10:	48 8d 95 68 ff ff ff                            	lea    rdx,[rbp-0x98]
  7e2a17:	48 89 4d a0                                     	mov    QWORD PTR [rbp-0x60],rcx
  7e2a1b:	48 c7 85 68 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x98],0x0
  7e2a26:	e8 d5 c4 37 00                                  	call   0xb5ef00
  7e2a2b:	48 89 de                                        	mov    rsi,rbx
  7e2a2e:	31 ff                                           	xor    edi,edi
  7e2a30:	e8 bb 63 42 00                                  	call   0xc08df0
  7e2a35:	4c 8b a5 68 ff ff ff                            	mov    r12,QWORD PTR [rbp-0x98]
  7e2a3c:	bf 30 00 00 00                                  	mov    edi,0x30
  7e2a41:	48 89 de                                        	mov    rsi,rbx
  7e2a44:	ba 02 01 00 00                                  	mov    edx,0x102
  7e2a49:	e8 02 61 42 00                                  	call   0xc08b50
  7e2a4e:	48 8b 55 a0                                     	mov    rdx,QWORD PTR [rbp-0x60]
  7e2a52:	48 8d 0d df 58 a8 ff                            	lea    rcx,[rip+0xffffffffffa858df]        # 0x268338
  7e2a59:	c7 00 ff ff ff ff                               	mov    DWORD PTR [rax],0xffffffff
  7e2a5f:	48 89 48 08                                     	mov    QWORD PTR [rax+0x8],rcx
  7e2a63:	48 8d 48 20                                     	lea    rcx,[rax+0x20]
  7e2a67:	4c 89 68 10                                     	mov    QWORD PTR [rax+0x10],r13
  7e2a6b:	4c 89 60 18                                     	mov    QWORD PTR [rax+0x18],r12
  7e2a6f:	48 c7 40 20 00 00 00 00                         	mov    QWORD PTR [rax+0x20],0x0
  7e2a77:	48 89 50 28                                     	mov    QWORD PTR [rax+0x28],rdx
  7e2a7b:	48 89 02                                        	mov    QWORD PTR [rdx],rax
  7e2a7e:	48 89 4d a0                                     	mov    QWORD PTR [rbp-0x60],rcx
  7e2a82:	48 8b 8d 58 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xa8]
  7e2a89:	49 39 cd                                        	cmp    r13,rcx
  7e2a8c:	4d 0f 44 ef                                     	cmove  r13,r15
  7e2a90:	4d 8b 6d 10                                     	mov    r13,QWORD PTR [r13+0x10]
  7e2a94:	49 39 cd                                        	cmp    r13,rcx
  7e2a97:	0f 85 83 fe ff ff                               	jne    0x7e2920
  7e2a9d:	4d 8b 6d 10                                     	mov    r13,QWORD PTR [r13+0x10]
  7e2aa1:	e9 7a fe ff ff                                  	jmp    0x7e2920
  7e2aa6:	8b 85 60 ff ff ff                               	mov    eax,DWORD PTR [rbp-0xa0]
  7e2aac:	49 63 8f 48 0b 00 00                            	movsxd rcx,DWORD PTR [r15+0xb48]
  7e2ab3:	48 8d 35 c6 95 41 02                            	lea    rsi,[rip+0x24195c6]        # 0x2bfc080
  7e2aba:	bf 30 00 00 00                                  	mov    edi,0x30
  7e2abf:	ba 02 01 00 00                                  	mov    edx,0x102
  7e2ac4:	4d 89 fd                                        	mov    r13,r15
  7e2ac7:	ff c0                                           	inc    eax
  7e2ac9:	48 98                                           	cdqe
  7e2acb:	48 6b c0 38                                     	imul   rax,rax,0x38
  7e2acf:	48 89 85 60 ff ff ff                            	mov    QWORD PTR [rbp-0xa0],rax
  7e2ad6:	48 69 c1 48 04 00 00                            	imul   rax,rcx,0x448
  7e2add:	48 89 85 38 ff ff ff                            	mov    QWORD PTR [rbp-0xc8],rax
  7e2ae4:	48 8d 58 04                                     	lea    rbx,[rax+0x4]
  7e2ae8:	e8 63 60 42 00                                  	call   0xc08b50
  7e2aed:	48 8b 55 a0                                     	mov    rdx,QWORD PTR [rbp-0x60]
  7e2af1:	48 8d 0d 48 58 a8 ff                            	lea    rcx,[rip+0xffffffffffa85848]        # 0x268340
  7e2af8:	c7 00 08 00 00 00                               	mov    DWORD PTR [rax],0x8
  7e2afe:	48 c7 85 50 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0xb0],0x0
  7e2b09:	48 89 48 08                                     	mov    QWORD PTR [rax+0x8],rcx
  7e2b0d:	4c 89 78 10                                     	mov    QWORD PTR [rax+0x10],r15
  7e2b11:	48 89 58 18                                     	mov    QWORD PTR [rax+0x18],rbx
  7e2b15:	48 c7 40 20 00 00 00 00                         	mov    QWORD PTR [rax+0x20],0x0
  7e2b1d:	31 db                                           	xor    ebx,ebx
  7e2b1f:	48 8d 48 20                                     	lea    rcx,[rax+0x20]
  7e2b23:	48 89 50 28                                     	mov    QWORD PTR [rax+0x28],rdx
  7e2b27:	48 89 02                                        	mov    QWORD PTR [rdx],rax
  7e2b2a:	ba 80 00 00 00                                  	mov    edx,0x80
  7e2b2f:	48 89 4d a0                                     	mov    QWORD PTR [rbp-0x60],rcx
  7e2b33:	c7 45 b8 70 05 00 00                            	mov    DWORD PTR [rbp-0x48],0x570
  7e2b3a:	48 c7 85 68 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x98],0x0
  7e2b45:	83 3d f4 78 a1 01 00                            	cmp    DWORD PTR [rip+0x1a178f4],0x0        # 0x21fa440
  7e2b4c:	0f 95 c3                                        	setne  bl
  7e2b4f:	31 ff                                           	xor    edi,edi
  7e2b51:	31 f6                                           	xor    esi,esi
  7e2b53:	31 c9                                           	xor    ecx,ecx
  7e2b55:	e8 c6 b8 0d 00                                  	call   0x8be420
  7e2b5a:	48 8d 35 6f 95 a8 ff                            	lea    rsi,[rip+0xffffffffffa8956f]        # 0x26c0d0
  7e2b61:	48 8d 95 68 ff ff ff                            	lea    rdx,[rbp-0x98]
  7e2b68:	48 89 c7                                        	mov    rdi,rax
  7e2b6b:	49 89 c7                                        	mov    r15,rax
  7e2b6e:	e8 ed ba 0d 00                                  	call   0x8be660
  7e2b73:	48 8d 75 b8                                     	lea    rsi,[rbp-0x48]
  7e2b77:	ba 04 00 00 00                                  	mov    edx,0x4
  7e2b7c:	4c 89 ff                                        	mov    rdi,r15
  7e2b7f:	e8 ec ba 0d 00                                  	call   0x8be670
  7e2b84:	4d 8d a5 48 01 00 00                            	lea    r12,[r13+0x148]
  7e2b8b:	31 f6                                           	xor    esi,esi
  7e2b8d:	31 d2                                           	xor    edx,edx
  7e2b8f:	31 c9                                           	xor    ecx,ecx
  7e2b91:	4c 89 e7                                        	mov    rdi,r12
  7e2b94:	e8 67 3e ce ff                                  	call   0x4c6a00
  7e2b99:	4c 89 ef                                        	mov    rdi,r13
  7e2b9c:	4c 89 fe                                        	mov    rsi,r15
  7e2b9f:	48 c7 c2 ff ff ff ff                            	mov    rdx,0xffffffffffffffff
  7e2ba6:	89 d9                                           	mov    ecx,ebx
  7e2ba8:	e8 53 c7 f4 ff                                  	call   0x72f300
  7e2bad:	4c 89 ff                                        	mov    rdi,r15
  7e2bb0:	e8 2b bf 0d 00                                  	call   0x8beae0
  7e2bb5:	4c 89 ff                                        	mov    rdi,r15
  7e2bb8:	e8 f3 b9 0d 00                                  	call   0x8be5b0
  7e2bbd:	48 8b 9d 68 ff ff ff                            	mov    rbx,QWORD PTR [rbp-0x98]
  7e2bc4:	48 8d 35 b5 94 41 02                            	lea    rsi,[rip+0x24194b5]        # 0x2bfc080
  7e2bcb:	bf 30 00 00 00                                  	mov    edi,0x30
  7e2bd0:	ba 02 01 00 00                                  	mov    edx,0x102
  7e2bd5:	48 89 9d 40 ff ff ff                            	mov    QWORD PTR [rbp-0xc0],rbx
  7e2bdc:	e8 6f 5f 42 00                                  	call   0xc08b50
  7e2be1:	48 8b 55 a0                                     	mov    rdx,QWORD PTR [rbp-0x60]
  7e2be5:	48 8d 0d 5c 57 a8 ff                            	lea    rcx,[rip+0xffffffffffa8575c]        # 0x268348
  7e2bec:	c7 00 09 00 00 00                               	mov    DWORD PTR [rax],0x9
  7e2bf2:	48 89 48 08                                     	mov    QWORD PTR [rax+0x8],rcx
  7e2bf6:	4c 89 68 10                                     	mov    QWORD PTR [rax+0x10],r13
  7e2bfa:	48 89 58 18                                     	mov    QWORD PTR [rax+0x18],rbx
  7e2bfe:	48 c7 40 20 00 00 00 00                         	mov    QWORD PTR [rax+0x20],0x0
  7e2c06:	31 db                                           	xor    ebx,ebx
  7e2c08:	48 8d 48 20                                     	lea    rcx,[rax+0x20]
  7e2c0c:	48 89 50 28                                     	mov    QWORD PTR [rax+0x28],rdx
  7e2c10:	48 89 02                                        	mov    QWORD PTR [rdx],rax
  7e2c13:	ba 80 00 00 00                                  	mov    edx,0x80
  7e2c18:	48 89 4d a0                                     	mov    QWORD PTR [rbp-0x60],rcx
  7e2c1c:	c7 45 b8 88 04 00 00                            	mov    DWORD PTR [rbp-0x48],0x488
  7e2c23:	48 c7 85 68 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x98],0x0
  7e2c2e:	83 3d 73 78 a1 01 00                            	cmp    DWORD PTR [rip+0x1a17873],0x0        # 0x21fa4a8
  7e2c35:	0f 95 c3                                        	setne  bl
  7e2c38:	31 ff                                           	xor    edi,edi
  7e2c3a:	31 f6                                           	xor    esi,esi
  7e2c3c:	31 c9                                           	xor    ecx,ecx
  7e2c3e:	e8 dd b7 0d 00                                  	call   0x8be420
  7e2c43:	48 8d 95 68 ff ff ff                            	lea    rdx,[rbp-0x98]
  7e2c4a:	48 89 c7                                        	mov    rdi,rax
  7e2c4d:	48 8d 35 7c 94 a8 ff                            	lea    rsi,[rip+0xffffffffffa8947c]        # 0x26c0d0
  7e2c54:	49 89 c7                                        	mov    r15,rax
  7e2c57:	e8 04 ba 0d 00                                  	call   0x8be660
  7e2c5c:	48 8d 75 b8                                     	lea    rsi,[rbp-0x48]
  7e2c60:	ba 04 00 00 00                                  	mov    edx,0x4
  7e2c65:	4c 89 ff                                        	mov    rdi,r15
  7e2c68:	e8 03 ba 0d 00                                  	call   0x8be670
  7e2c6d:	4c 89 e7                                        	mov    rdi,r12
  7e2c70:	31 f6                                           	xor    esi,esi
  7e2c72:	31 d2                                           	xor    edx,edx
  7e2c74:	31 c9                                           	xor    ecx,ecx
  7e2c76:	e8 85 3d ce ff                                  	call   0x4c6a00
  7e2c7b:	4c 89 ef                                        	mov    rdi,r13
  7e2c7e:	4c 89 fe                                        	mov    rsi,r15
  7e2c81:	48 c7 c2 ff ff ff ff                            	mov    rdx,0xffffffffffffffff
  7e2c88:	89 d9                                           	mov    ecx,ebx
  7e2c8a:	e8 21 b5 d5 ff                                  	call   0x53e1b0
  7e2c8f:	4c 89 ff                                        	mov    rdi,r15
  7e2c92:	e8 49 be 0d 00                                  	call   0x8beae0
  7e2c97:	4c 89 ff                                        	mov    rdi,r15
  7e2c9a:	e8 11 b9 0d 00                                  	call   0x8be5b0
  7e2c9f:	4c 8d 3d da 93 41 02                            	lea    r15,[rip+0x24193da]        # 0x2bfc080
  7e2ca6:	48 8b 9d 68 ff ff ff                            	mov    rbx,QWORD PTR [rbp-0x98]
  7e2cad:	bf 30 00 00 00                                  	mov    edi,0x30
  7e2cb2:	ba 02 01 00 00                                  	mov    edx,0x102
  7e2cb7:	4c 89 fe                                        	mov    rsi,r15
  7e2cba:	e8 91 5e 42 00                                  	call   0xc08b50
  7e2cbf:	48 8b 55 a0                                     	mov    rdx,QWORD PTR [rbp-0x60]
  7e2cc3:	48 8d 0d 86 56 a8 ff                            	lea    rcx,[rip+0xffffffffffa85686]        # 0x268350
  7e2cca:	c7 00 0a 00 00 00                               	mov    DWORD PTR [rax],0xa
  7e2cd0:	bf 30 00 00 00                                  	mov    edi,0x30
  7e2cd5:	4c 89 fe                                        	mov    rsi,r15
  7e2cd8:	48 89 48 08                                     	mov    QWORD PTR [rax+0x8],rcx
  7e2cdc:	48 8d 48 20                                     	lea    rcx,[rax+0x20]
  7e2ce0:	4c 89 68 10                                     	mov    QWORD PTR [rax+0x10],r13
  7e2ce4:	48 89 58 18                                     	mov    QWORD PTR [rax+0x18],rbx
  7e2ce8:	48 c7 40 20 00 00 00 00                         	mov    QWORD PTR [rax+0x20],0x0
  7e2cf0:	48 89 50 28                                     	mov    QWORD PTR [rax+0x28],rdx
  7e2cf4:	48 89 02                                        	mov    QWORD PTR [rdx],rax
  7e2cf7:	48 89 4d a0                                     	mov    QWORD PTR [rbp-0x60],rcx
  7e2cfb:	ba 02 01 00 00                                  	mov    edx,0x102
  7e2d00:	49 8b 45 40                                     	mov    rax,QWORD PTR [r13+0x40]
  7e2d04:	48 63 40 10                                     	movsxd rax,DWORD PTR [rax+0x10]
  7e2d08:	48 89 85 48 ff ff ff                            	mov    QWORD PTR [rbp-0xb8],rax
  7e2d0f:	4c 8d 24 85 04 00 00 00                         	lea    r12,[rax*4+0x4]
  7e2d17:	e8 34 5e 42 00                                  	call   0xc08b50
  7e2d1c:	48 8b 55 a0                                     	mov    rdx,QWORD PTR [rbp-0x60]
  7e2d20:	48 8d 0d 31 56 a8 ff                            	lea    rcx,[rip+0xffffffffffa85631]        # 0x268358
  7e2d27:	c7 00 0b 00 00 00                               	mov    DWORD PTR [rax],0xb
  7e2d2d:	bf 30 00 00 00                                  	mov    edi,0x30
  7e2d32:	4c 89 fe                                        	mov    rsi,r15
  7e2d35:	48 89 48 08                                     	mov    QWORD PTR [rax+0x8],rcx
  7e2d39:	4c 89 68 10                                     	mov    QWORD PTR [rax+0x10],r13
  7e2d3d:	4c                                              	rex.WR
  7e2d3e:	89                                              	.byte 0x89
  7e2d3f:	60                                              	(bad)
