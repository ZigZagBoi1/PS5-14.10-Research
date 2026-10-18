
/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/deep_653.bin:     file format binary


Disassembly of section .data:

00000000009a7d10 <.data>:
  9a7d10:	55                                              	push   rbp
  9a7d11:	48 89 e5                                        	mov    rbp,rsp
  9a7d14:	41 57                                           	push   r15
  9a7d16:	41 56                                           	push   r14
  9a7d18:	41 55                                           	push   r13
  9a7d1a:	41 54                                           	push   r12
  9a7d1c:	53                                              	push   rbx
  9a7d1d:	48 83 ec 18                                     	sub    rsp,0x18
  9a7d21:	48 8d 0d e8 45 f7 02                            	lea    rcx,[rip+0x2f745e8]        # 0x391c310
  9a7d28:	48 8b 01                                        	mov    rax,QWORD PTR [rcx]
  9a7d2b:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  9a7d2f:	b8 16 00 00 00                                  	mov    eax,0x16
  9a7d34:	44 8b 3e                                        	mov    r15d,DWORD PTR [rsi]
  9a7d37:	41 f7 c7 ff ff af ff                            	test   r15d,0xffafffff
  9a7d3e:	0f 85 c5 01 00 00                               	jne    0x9a7f09
  9a7d44:	65 4c 8b 24 25 00 00 00 00                      	mov    r12,QWORD PTR gs:0x0
  9a7d4d:	49 8b 44 24 08                                  	mov    rax,QWORD PTR [r12+0x8]
  9a7d52:	48 89 fb                                        	mov    rbx,rdi
  9a7d55:	48 8d 35 74 80 bb 01                            	lea    rsi,[rip+0x1bb8074]        # 0x255fdd0
  9a7d5c:	bf b0 10 04 00                                  	mov    edi,0x410b0
  9a7d61:	ba 02 81 00 00                                  	mov    edx,0x8102
  9a7d66:	44 8b a8 d0 05 00 00                            	mov    r13d,DWORD PTR [rax+0x5d0]
  9a7d6d:	e8 de 0d 26 00                                  	call   0xc08b50
  9a7d72:	48 8d 78 28                                     	lea    rdi,[rax+0x28]
  9a7d76:	48 8d 35 da d2 a0 00                            	lea    rsi,[rip+0xa0d2da]        # 0x13b5057
  9a7d7d:	49 89 c6                                        	mov    r14,rax
  9a7d80:	31 d2                                           	xor    edx,edx
  9a7d82:	31 c9                                           	xor    ecx,ecx
  9a7d84:	e8 47 00 b2 ff                                  	call   0x4c7dd0
  9a7d89:	49 8b 44 24 08                                  	mov    rax,QWORD PTR [r12+0x8]
  9a7d8e:	31 f6                                           	xor    esi,esi
  9a7d90:	8b b8 c4 05 00 00                               	mov    edi,DWORD PTR [rax+0x5c4]
  9a7d96:	41 89 7e 60                                     	mov    DWORD PTR [r14+0x60],edi
  9a7d9a:	45 89 6e 64                                     	mov    DWORD PTR [r14+0x64],r13d
  9a7d9e:	e8 7d bb a1 ff                                  	call   0x3c3920
  9a7da3:	31 f6                                           	xor    esi,esi
  9a7da5:	41 83 7e 60 00                                  	cmp    DWORD PTR [r14+0x60],0x0
  9a7daa:	48 8d 4d c8                                     	lea    rcx,[rbp-0x38]
  9a7dae:	48 89 c7                                        	mov    rdi,rax
  9a7db1:	49 89 c4                                        	mov    r12,rax
  9a7db4:	40 0f 94 c6                                     	sete   sil
  9a7db8:	31 d2                                           	xor    edx,edx
  9a7dba:	48 c1 e6 26                                     	shl    rsi,0x26
  9a7dbe:	49 89 76 38                                     	mov    QWORD PTR [r14+0x38],rsi
  9a7dc2:	e8 79 b8 a1 ff                                  	call   0x3c3640
  9a7dc7:	49 8b 76 38                                     	mov    rsi,QWORD PTR [r14+0x38]
  9a7dcb:	85 c0                                           	test   eax,eax
  9a7dcd:	74 08                                           	je     0x9a7dd7
  9a7dcf:	31 c0                                           	xor    eax,eax
  9a7dd1:	49 89 76 40                                     	mov    QWORD PTR [r14+0x40],rsi
  9a7dd5:	eb 13                                           	jmp    0x9a7dea
  9a7dd7:	48 8b 45 c8                                     	mov    rax,QWORD PTR [rbp-0x38]
  9a7ddb:	4c 89 e7                                        	mov    rdi,r12
  9a7dde:	48 01 f0                                        	add    rax,rsi
  9a7de1:	49 89 46 40                                     	mov    QWORD PTR [r14+0x40],rax
  9a7de5:	e8 c6 b8 a1 ff                                  	call   0x3c36b0
  9a7dea:	48 8d 3d 87 e0 1f 03                            	lea    rdi,[rip+0x31fe087]        # 0x3ba5e78
  9a7df1:	49 89 46 30                                     	mov    QWORD PTR [r14+0x30],rax
  9a7df5:	31 f6                                           	xor    esi,esi
  9a7df7:	31 d2                                           	xor    edx,edx
  9a7df9:	31 c9                                           	xor    ecx,ecx
  9a7dfb:	e8 00 ec b1 ff                                  	call   0x4c6a00
  9a7e00:	45 85 ed                                        	test   r13d,r13d
  9a7e03:	78 1e                                           	js     0x9a7e23
  9a7e05:	48 8d 05 84 e0 1f 03                            	lea    rax,[rip+0x31fe084]        # 0x3ba5e90
  9a7e0c:	48 8d 15 ad e0 1f 03                            	lea    rdx,[rip+0x31fe0ad]        # 0x3ba5ec0
  9a7e13:	42 8b 0c a8                                     	mov    ecx,DWORD PTR [rax+r13*4]
  9a7e17:	42 39 0c aa                                     	cmp    DWORD PTR [rdx+r13*4],ecx
  9a7e1b:	76 76                                           	jbe    0x9a7e93
  9a7e1d:	ff c1                                           	inc    ecx
  9a7e1f:	42 89 0c a8                                     	mov    DWORD PTR [rax+r13*4],ecx
  9a7e23:	48 8b 05 5e e0 1f 03                            	mov    rax,QWORD PTR [rip+0x31fe05e]        # 0x3ba5e88
  9a7e2a:	48 8d 3d 47 e0 1f 03                            	lea    rdi,[rip+0x31fe047]        # 0x3ba5e78
  9a7e31:	49 c7 06 00 00 00 00                            	mov    QWORD PTR [r14],0x0
  9a7e38:	41 83 cf 02                                     	or     r15d,0x2
  9a7e3c:	31 f6                                           	xor    esi,esi
  9a7e3e:	31 d2                                           	xor    edx,edx
  9a7e40:	31 c9                                           	xor    ecx,ecx
  9a7e42:	49 89 46 08                                     	mov    QWORD PTR [r14+0x8],rax
  9a7e46:	4c 89 30                                        	mov    QWORD PTR [rax],r14
  9a7e49:	4c 89 35 38 e0 1f 03                            	mov    QWORD PTR [rip+0x31fe038],r14        # 0x3ba5e88
  9a7e50:	e8 4b f1 b1 ff                                  	call   0x4c6fa0
  9a7e55:	f0 41 83 46 58 01                               	lock add DWORD PTR [r14+0x58],0x1
  9a7e5b:	48 8d 75 c8                                     	lea    rsi,[rbp-0x38]
  9a7e5f:	48 8d 55 c4                                     	lea    rdx,[rbp-0x3c]
  9a7e63:	48 89 df                                        	mov    rdi,rbx
  9a7e66:	44 89 f9                                        	mov    ecx,r15d
  9a7e69:	45 31 c0                                        	xor    r8d,r8d
  9a7e6c:	e8 2f 49 d8 ff                                  	call   0x72c7a0
  9a7e71:	85 c0                                           	test   eax,eax
  9a7e73:	74 46                                           	je     0x9a7ebb
  9a7e75:	b9 ff ff ff ff                                  	mov    ecx,0xffffffff
  9a7e7a:	f0 41 0f c1 4e 58                               	lock xadd DWORD PTR [r14+0x58],ecx
  9a7e80:	83 f9 01                                        	cmp    ecx,0x1
  9a7e83:	75 7d                                           	jne    0x9a7f02
  9a7e85:	4c 89 f7                                        	mov    rdi,r14
  9a7e88:	89 c3                                           	mov    ebx,eax
  9a7e8a:	e8 71 fd ff ff                                  	call   0x9a7c00
  9a7e8f:	89 d8                                           	mov    eax,ebx
  9a7e91:	eb 6f                                           	jmp    0x9a7f02
  9a7e93:	48 8d 3d de df 1f 03                            	lea    rdi,[rip+0x31fdfde]        # 0x3ba5e78
  9a7e9a:	31 f6                                           	xor    esi,esi
  9a7e9c:	31 d2                                           	xor    edx,edx
  9a7e9e:	31 c9                                           	xor    ecx,ecx
  9a7ea0:	e8 fb f0 b1 ff                                  	call   0x4c6fa0
  9a7ea5:	48 8d 35 24 7f bb 01                            	lea    rsi,[rip+0x1bb7f24]        # 0x255fdd0
  9a7eac:	4c 89 f7                                        	mov    rdi,r14
  9a7eaf:	e8 3c 0f 26 00                                  	call   0xc08df0
  9a7eb4:	b8 18 00 00 00                                  	mov    eax,0x18
  9a7eb9:	eb 47                                           	jmp    0x9a7f02
  9a7ebb:	48 8b 7d c8                                     	mov    rdi,QWORD PTR [rbp-0x38]
  9a7ebf:	4c 8d 05 02 80 bb 01                            	lea    r8,[rip+0x1bb8002]        # 0x255fec8
  9a7ec6:	44 89 fe                                        	mov    esi,r15d
  9a7ec9:	ba 11 00 00 00                                  	mov    edx,0x11
  9a7ece:	4c 89 f1                                        	mov    rcx,r14
  9a7ed1:	e8 2a 61 d8 ff                                  	call   0x72e000
  9a7ed6:	48 8b 45 c8                                     	mov    rax,QWORD PTR [rbp-0x38]
  9a7eda:	b9 ff ff ff ff                                  	mov    ecx,0xffffffff
  9a7edf:	f0 0f c1 48 28                                  	lock xadd DWORD PTR [rax+0x28],ecx
  9a7ee4:	83 f9 01                                        	cmp    ecx,0x1
  9a7ee7:	75 0c                                           	jne    0x9a7ef5
  9a7ee9:	48 8b 7d c8                                     	mov    rdi,QWORD PTR [rbp-0x38]
  9a7eed:	48 89 de                                        	mov    rsi,rbx
  9a7ef0:	e8 8b 34 d8 ff                                  	call   0x72b380
  9a7ef5:	48 63 45 c4                                     	movsxd rax,DWORD PTR [rbp-0x3c]
  9a7ef9:	48 89 83 08 04 00 00                            	mov    QWORD PTR [rbx+0x408],rax
  9a7f00:	31 c0                                           	xor    eax,eax
  9a7f02:	48 8d 0d 07 44 f7 02                            	lea    rcx,[rip+0x2f74407]        # 0x391c310
  9a7f09:	48 8b 09                                        	mov    rcx,QWORD PTR [rcx]
  9a7f0c:	48 3b 4d d0                                     	cmp    rcx,QWORD PTR [rbp-0x30]
  9a7f10:	75 0f                                           	jne    0x9a7f21
  9a7f12:	48 83 c4 18                                     	add    rsp,0x18
  9a7f16:	5b                                              	pop    rbx
  9a7f17:	41 5c                                           	pop    r12
  9a7f19:	41 5d                                           	pop    r13
  9a7f1b:	41 5e                                           	pop    r14
  9a7f1d:	41 5f                                           	pop    r15
  9a7f1f:	5d                                              	pop    rbp
  9a7f20:	c3                                              	ret
  9a7f21:	e8 8a 57 d5 ff                                  	call   0x6fd6b0
  9a7f26:	0f 0b                                           	ud2
  9a7f28:	90                                              	nop
  9a7f29:	90                                              	nop
  9a7f2a:	90                                              	nop
  9a7f2b:	90                                              	nop
  9a7f2c:	90                                              	nop
  9a7f2d:	90                                              	nop
  9a7f2e:	90                                              	nop
  9a7f2f:	90                                              	nop
  9a7f30:	55                                              	push   rbp
  9a7f31:	48 89 e5                                        	mov    rbp,rsp
  9a7f34:	41 57                                           	push   r15
  9a7f36:	41 56                                           	push   r14
  9a7f38:	41 55                                           	push   r13
  9a7f3a:	41 54                                           	push   r12
  9a7f3c:	53                                              	push   rbx
  9a7f3d:	48 83 ec 18                                     	sub    rsp,0x18
  9a7f41:	48 8b 87 d8 01 00 00                            	mov    rax,QWORD PTR [rdi+0x1d8]
  9a7f48:	48 8b 99 e8 00 00 00                            	mov    rbx,QWORD PTR [rcx+0xe8]
  9a7f4f:	48 29 f2                                        	sub    rdx,rsi
  9a7f52:	49 89 ff                                        	mov    r15,rdi
  9a7f55:	48 89 cf                                        	mov    rdi,rcx
  9a7f58:	49 89 f6                                        	mov    r14,rsi
  9a7f5b:	31 f6                                           	xor    esi,esi
  9a7f5d:	49 89 d4                                        	mov    r12,rdx
  9a7f60:	48 c1 ea 10                                     	shr    rdx,0x10
  9a7f64:	49 c1 ec 15                                     	shr    r12,0x15
  9a7f68:	48 89 45 c0                                     	mov    QWORD PTR [rbp-0x40],rax
  9a7f6c:	48 89 4d c8                                     	mov    QWORD PTR [rbp-0x38],rcx
  9a7f70:	e8 0b 01 00 00                                  	call   0x9a8080
  9a7f75:	89 45 d4                                        	mov    DWORD PTR [rbp-0x2c],eax
  9a7f78:	45 85 e4                                        	test   r12d,r12d
  9a7f7b:	7e 4e                                           	jle    0x9a7fcb
  9a7f7d:	48 8b 45 c8                                     	mov    rax,QWORD PTR [rbp-0x38]
  9a7f81:	4c 8b 6b 30                                     	mov    r13,QWORD PTR [rbx+0x30]
  9a7f85:	48 8b 98 60 01 00 00                            	mov    rbx,QWORD PTR [rax+0x160]
  9a7f8c:	0f 1f 40 00                                     	nop    DWORD PTR [rax+0x0]
  9a7f90:	48 8b 7d c0                                     	mov    rdi,QWORD PTR [rbp-0x40]
  9a7f94:	4c 89 f6                                        	mov    rsi,r14
  9a7f97:	4c 89 ea                                        	mov    rdx,r13
  9a7f9a:	48 89 d9                                        	mov    rcx,rbx
  9a7f9d:	e8 ee c9 f3 ff                                  	call   0x8e4990
  9a7fa2:	4c 89 ff                                        	mov    rdi,r15
  9a7fa5:	4c 89 f6                                        	mov    rsi,r14
  9a7fa8:	4c 89 ea                                        	mov    rdx,r13
  9a7fab:	48 89 d9                                        	mov    rcx,rbx
  9a7fae:	e8 9d 5c 04 00                                  	call   0x9edc50
  9a7fb3:	85 c0                                           	test   eax,eax
  9a7fb5:	0f 85 9b 00 00 00                               	jne    0x9a8056
  9a7fbb:	49 81 c6 00 00 20 00                            	add    r14,0x200000
  9a7fc2:	48 83 eb 80                                     	sub    rbx,0xffffffffffffff80
  9a7fc6:	41 ff cc                                        	dec    r12d
  9a7fc9:	75 c5                                           	jne    0x9a7f90
  9a7fcb:	4c 8b 7d c8                                     	mov    r15,QWORD PTR [rbp-0x38]
  9a7fcf:	8b 45 d4                                        	mov    eax,DWORD PTR [rbp-0x2c]
  9a7fd2:	31 f6                                           	xor    esi,esi
  9a7fd4:	31 d2                                           	xor    edx,edx
  9a7fd6:	49 8d 5f 18                                     	lea    rbx,[r15+0x18]
  9a7fda:	4c 8d 34 40                                     	lea    r14,[rax+rax*2]
  9a7fde:	48 89 df                                        	mov    rdi,rbx
  9a7fe1:	e8 ba c6 e2 ff                                  	call   0x7d46a0
  9a7fe6:	43 c7 84 b7 68 01 00 00 ff ff ff ff             	mov    DWORD PTR [r15+r14*4+0x168],0xffffffff
  9a7ff2:	43 83 bc b7 70 01 00 00 00                      	cmp    DWORD PTR [r15+r14*4+0x170],0x0
  9a7ffb:	75 24                                           	jne    0x9a8021
  9a7ffd:	41 83 bf 98 01 00 00 00                         	cmp    DWORD PTR [r15+0x198],0x0
  9a8005:	75 37                                           	jne    0x9a803e
  9a8007:	48 89 df                                        	mov    rdi,rbx
  9a800a:	31 f6                                           	xor    esi,esi
  9a800c:	31 d2                                           	xor    edx,edx
  9a800e:	48 83 c4 18                                     	add    rsp,0x18
  9a8012:	5b                                              	pop    rbx
  9a8013:	41 5c                                           	pop    r12
  9a8015:	41 5d                                           	pop    r13
  9a8017:	41 5e                                           	pop    r14
  9a8019:	41 5f                                           	pop    r15
  9a801b:	5d                                              	pop    rbp
  9a801c:	e9 8f ce e2 ff                                  	jmp    0x7d4eb0
  9a8021:	4b 8d bc b7 70 01 00 00                         	lea    rdi,[r15+r14*4+0x170]
  9a8029:	c7 07 00 00 00 00                               	mov    DWORD PTR [rdi],0x0
  9a802f:	e8 dc e8 25 00                                  	call   0xc06910
  9a8034:	41 83 bf 98 01 00 00 00                         	cmp    DWORD PTR [r15+0x198],0x0
  9a803c:	74 c9                                           	je     0x9a8007
  9a803e:	49 81 c7 98 01 00 00                            	add    r15,0x198
  9a8045:	4c 89 ff                                        	mov    rdi,r15
  9a8048:	41 c7 07 00 00 00 00                            	mov    DWORD PTR [r15],0x0
  9a804f:	e8 bc e8 25 00                                  	call   0xc06910
  9a8054:	eb b1                                           	jmp    0x9a8007
  9a8056:	e8 f5 98 e4 ff                                  	call   0x7f1950
  9a805b:	48 8d 3d f4 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff4]        # 0x9a8056
  9a8062:	e8 a9 97 e4 ff                                  	call   0x7f1810
  9a8067:	48 8d 35 87 45 8d 00                            	lea    rsi,[rip+0x8d4587]        # 0x127c5f5
  9a806e:	bf 2f 00 00 00                                  	mov    edi,0x2f
  9a8073:	31 c0                                           	xor    eax,eax
  9a8075:	e8 96 29 2f 00                                  	call   0xc9aa10
  9a807a:	0f 0b                                           	ud2
  9a807c:	90                                              	nop
  9a807d:	90                                              	nop
  9a807e:	90                                              	nop
  9a807f:	90                                              	nop
  9a8080:	55                                              	push   rbp
  9a8081:	48 89 e5                                        	mov    rbp,rsp
  9a8084:	41 57                                           	push   r15
  9a8086:	41 56                                           	push   r14
  9a8088:	41 55                                           	push   r13
  9a808a:	41 54                                           	push   r12
  9a808c:	53                                              	push   rbx
  9a808d:	48 83 ec 28                                     	sub    rsp,0x28
  9a8091:	89 d3                                           	mov    ebx,edx
  9a8093:	41 89 f6                                        	mov    r14d,esi
  9a8096:	49 89 fc                                        	mov    r12,rdi
  9a8099:	48 83 c7 18                                     	add    rdi,0x18
  9a809d:	31 f6                                           	xor    esi,esi
  9a809f:	31 d2                                           	xor    edx,edx
  9a80a1:	83 c3 1f                                        	add    ebx,0x1f
  9a80a4:	41 83 e6 e0                                     	and    r14d,0xffffffe0
  9a80a8:	48 89 7d b8                                     	mov    QWORD PTR [rbp-0x48],rdi
  9a80ac:	83 e3 e0                                        	and    ebx,0xffffffe0
  9a80af:	e8 ec c5 e2 ff                                  	call   0x7d46a0
  9a80b4:	4d 8d bc 24 68 01 00 00                         	lea    r15,[r12+0x168]
  9a80bc:	49 8d b4 24 98 01 00 00                         	lea    rsi,[r12+0x198]
  9a80c4:	4d 8d 84 24 80 01 00 00                         	lea    r8,[r12+0x180]
  9a80cc:	4d 8d 8c 24 74 01 00 00                         	lea    r9,[r12+0x174]
  9a80d4:	4c 8d 15 f6 ca 9e 00                            	lea    r10,[rip+0x9ecaf6]        # 0x1394bd1
  9a80db:	48 8d 0d b9 dd 9c 00                            	lea    rcx,[rip+0x9cddb9]        # 0x1375e9b
  9a80e2:	41 8b 17                                        	mov    edx,DWORD PTR [r15]
  9a80e5:	b8 00 00 00 00                                  	mov    eax,0x0
  9a80ea:	85 d2                                           	test   edx,edx
  9a80ec:	0f 89 9e 00 00 00                               	jns    0x9a8190
  9a80f2:	41 8b 11                                        	mov    edx,DWORD PTR [r9]
  9a80f5:	41 bb 01 00 00 00                               	mov    r11d,0x1
  9a80fb:	85 d2                                           	test   edx,edx
  9a80fd:	0f 89 ad 00 00 00                               	jns    0x9a81b0
  9a8103:	41 8b 00                                        	mov    eax,DWORD PTR [r8]
  9a8106:	41 bd 02 00 00 00                               	mov    r13d,0x2
  9a810c:	85 c0                                           	test   eax,eax
  9a810e:	0f 88 0b 01 00 00                               	js     0x9a821f
  9a8114:	39 c3                                           	cmp    ebx,eax
  9a8116:	7e 11                                           	jle    0x9a8129
  9a8118:	4c 89 c7                                        	mov    rdi,r8
  9a811b:	45 39 b4 24 84 01 00 00                         	cmp    DWORD PTR [r12+0x184],r14d
  9a8123:	0f 8f 9f 00 00 00                               	jg     0x9a81c8
  9a8129:	45 89 dd                                        	mov    r13d,r11d
  9a812c:	45 85 db                                        	test   r11d,r11d
  9a812f:	0f 89 ea 00 00 00                               	jns    0x9a821f
  9a8135:	c7 06 01 00 00 00                               	mov    DWORD PTR [rsi],0x1
  9a813b:	48 89 75 c0                                     	mov    QWORD PTR [rbp-0x40],rsi
  9a813f:	4c 89 45 c8                                     	mov    QWORD PTR [rbp-0x38],r8
  9a8143:	4c 89 4d d0                                     	mov    QWORD PTR [rbp-0x30],r9
  9a8147:	48 89 f7                                        	mov    rdi,rsi
  9a814a:	4c 89 e6                                        	mov    rsi,r12
  9a814d:	ba 44 00 00 00                                  	mov    edx,0x44
  9a8152:	4c 89 d1                                        	mov    rcx,r10
  9a8155:	c7 04 24 00 01 00 00                            	mov    DWORD PTR [rsp],0x100
  9a815c:	45 31 c0                                        	xor    r8d,r8d
  9a815f:	45 31 c9                                        	xor    r9d,r9d
  9a8162:	4d 89 d5                                        	mov    r13,r10
  9a8165:	e8 f6 e0 25 00                                  	call   0xc06260
  9a816a:	41 83 bc 24 98 01 00 00 00                      	cmp    DWORD PTR [r12+0x198],0x0
  9a8173:	4c 8b 4d d0                                     	mov    r9,QWORD PTR [rbp-0x30]
  9a8177:	4c 8b 45 c8                                     	mov    r8,QWORD PTR [rbp-0x38]
  9a817b:	48 8b 75 c0                                     	mov    rsi,QWORD PTR [rbp-0x40]
  9a817f:	48 8d 0d 15 dd 9c 00                            	lea    rcx,[rip+0x9cdd15]        # 0x1375e9b
  9a8186:	4d 89 ea                                        	mov    r10,r13
  9a8189:	75 bc                                           	jne    0x9a8147
  9a818b:	e9 52 ff ff ff                                  	jmp    0x9a80e2
  9a8190:	b8 ff ff ff ff                                  	mov    eax,0xffffffff
  9a8195:	39 d3                                           	cmp    ebx,edx
  9a8197:	0f 8e 55 ff ff ff                               	jle    0x9a80f2
  9a819d:	4c 89 ff                                        	mov    rdi,r15
  9a81a0:	45 39 b4 24 6c 01 00 00                         	cmp    DWORD PTR [r12+0x16c],r14d
  9a81a8:	0f 8e 44 ff ff ff                               	jle    0x9a80f2
  9a81ae:	eb 18                                           	jmp    0x9a81c8
  9a81b0:	39 d3                                           	cmp    ebx,edx
  9a81b2:	7e 63                                           	jle    0x9a8217
  9a81b4:	4c 89 cf                                        	mov    rdi,r9
  9a81b7:	41 89 c3                                        	mov    r11d,eax
  9a81ba:	45 39 b4 24 78 01 00 00                         	cmp    DWORD PTR [r12+0x178],r14d
  9a81c2:	0f 8e 3b ff ff ff                               	jle    0x9a8103
  9a81c8:	c7 47 08 01 00 00 00                            	mov    DWORD PTR [rdi+0x8],0x1
  9a81cf:	48 89 75 c0                                     	mov    QWORD PTR [rbp-0x40],rsi
  9a81d3:	48 83 c7 08                                     	add    rdi,0x8
  9a81d7:	4c 89 e6                                        	mov    rsi,r12
  9a81da:	ba 44 00 00 00                                  	mov    edx,0x44
  9a81df:	4c 89 45 c8                                     	mov    QWORD PTR [rbp-0x38],r8
  9a81e3:	4c 89 4d d0                                     	mov    QWORD PTR [rbp-0x30],r9
  9a81e7:	c7 04 24 00 01 00 00                            	mov    DWORD PTR [rsp],0x100
  9a81ee:	45 31 c0                                        	xor    r8d,r8d
  9a81f1:	45 31 c9                                        	xor    r9d,r9d
  9a81f4:	4d 89 d5                                        	mov    r13,r10
  9a81f7:	e8 64 e0 25 00                                  	call   0xc06260
  9a81fc:	4c 8b 4d d0                                     	mov    r9,QWORD PTR [rbp-0x30]
  9a8200:	4c 8b 45 c8                                     	mov    r8,QWORD PTR [rbp-0x38]
  9a8204:	48 8b 75 c0                                     	mov    rsi,QWORD PTR [rbp-0x40]
  9a8208:	48 8d 0d 8c dc 9c 00                            	lea    rcx,[rip+0x9cdc8c]        # 0x1375e9b
  9a820f:	4d 89 ea                                        	mov    r10,r13
  9a8212:	e9 cb fe ff ff                                  	jmp    0x9a80e2
  9a8217:	41 89 c3                                        	mov    r11d,eax
  9a821a:	e9 e4 fe ff ff                                  	jmp    0x9a8103
  9a821f:	48 8b 7d b8                                     	mov    rdi,QWORD PTR [rbp-0x48]
  9a8223:	44 89 e8                                        	mov    eax,r13d
  9a8226:	31 f6                                           	xor    esi,esi
  9a8228:	31 d2                                           	xor    edx,edx
  9a822a:	48 8d 04 40                                     	lea    rax,[rax+rax*2]
  9a822e:	45 89 34 87                                     	mov    DWORD PTR [r15+rax*4],r14d
  9a8232:	41 89 5c 87 04                                  	mov    DWORD PTR [r15+rax*4+0x4],ebx
  9a8237:	41 c7 44 87 08 00 00 00 00                      	mov    DWORD PTR [r15+rax*4+0x8],0x0
  9a8240:	e8 6b cc e2 ff                                  	call   0x7d4eb0
  9a8245:	44 89 e8                                        	mov    eax,r13d
  9a8248:	48 83 c4 28                                     	add    rsp,0x28
  9a824c:	5b                                              	pop    rbx
  9a824d:	41 5c                                           	pop    r12
  9a824f:	41 5d                                           	pop    r13
  9a8251:	41 5e                                           	pop    r14
  9a8253:	41 5f                                           	pop    r15
  9a8255:	5d                                              	pop    rbp
  9a8256:	c3                                              	ret
  9a8257:	90                                              	nop
  9a8258:	90                                              	nop
  9a8259:	90                                              	nop
  9a825a:	90                                              	nop
  9a825b:	90                                              	nop
  9a825c:	90                                              	nop
  9a825d:	90                                              	nop
  9a825e:	90                                              	nop
  9a825f:	90                                              	nop
  9a8260:	55                                              	push   rbp
  9a8261:	48 89 e5                                        	mov    rbp,rsp
  9a8264:	41 57                                           	push   r15
  9a8266:	41 56                                           	push   r14
  9a8268:	41 55                                           	push   r13
  9a826a:	41 54                                           	push   r12
  9a826c:	53                                              	push   rbx
  9a826d:	48 83 ec 78                                     	sub    rsp,0x78
  9a8271:	41 89 cc                                        	mov    r12d,ecx
  9a8274:	48 8d 0d 95 40 f7 02                            	lea    rcx,[rip+0x2f74095]        # 0x391c310
  9a827b:	48 89 95 70 ff ff ff                            	mov    QWORD PTR [rbp-0x90],rdx
  9a8282:	48 89 75 b8                                     	mov    QWORD PTR [rbp-0x48],rsi
  9a8286:	48 8b 01                                        	mov    rax,QWORD PTR [rcx]
  9a8289:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  9a828d:	48 89 7d 88                                     	mov    QWORD PTR [rbp-0x78],rdi
  9a8291:	f6 87 44 02 00 00 01                            	test   BYTE PTR [rdi+0x244],0x1
  9a8298:	0f 84 ae 02 00 00                               	je     0x9a854c
  9a829e:	48 8d 3d d3 db 1f 03                            	lea    rdi,[rip+0x31fdbd3]        # 0x3ba5e78
  9a82a5:	65 48 8b 04 25 00 00 00 00                      	mov    rax,QWORD PTR gs:0x0
  9a82ae:	45 89 c5                                        	mov    r13d,r8d
  9a82b1:	48 89 45 90                                     	mov    QWORD PTR [rbp-0x70],rax
  9a82b5:	31 f6                                           	xor    esi,esi
  9a82b7:	31 d2                                           	xor    edx,edx
  9a82b9:	31 c9                                           	xor    ecx,ecx
  9a82bb:	e8 40 e7 b1 ff                                  	call   0x4c6a00
  9a82c0:	48 8b 05 11 dc 1f 03                            	mov    rax,QWORD PTR [rip+0x31fdc11]        # 0x3ba5ed8
  9a82c7:	48 85 c0                                        	test   rax,rax
  9a82ca:	75 50                                           	jne    0x9a831c
  9a82cc:	48 8d 1d 05 dc 1f 03                            	lea    rbx,[rip+0x31fdc05]        # 0x3ba5ed8
  9a82d3:	4c 8d 35 86 db 1f 03                            	lea    r14,[rip+0x31fdb86]        # 0x3ba5e60
  9a82da:	4c 8d 3d df aa 8c 00                            	lea    r15,[rip+0x8caadf]        # 0x1272dc0
  9a82e1:	66 66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00    	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  9a82f0:	48 89 df                                        	mov    rdi,rbx
  9a82f3:	4c 89 f6                                        	mov    rsi,r14
  9a82f6:	ba 44 00 00 00                                  	mov    edx,0x44
  9a82fb:	4c 89 f9                                        	mov    rcx,r15
  9a82fe:	c7 04 24 00 01 00 00                            	mov    DWORD PTR [rsp],0x100
  9a8305:	45 31 c0                                        	xor    r8d,r8d
  9a8308:	45 31 c9                                        	xor    r9d,r9d
  9a830b:	e8 50 df 25 00                                  	call   0xc06260
  9a8310:	48 8b 05 c1 db 1f 03                            	mov    rax,QWORD PTR [rip+0x31fdbc1]        # 0x3ba5ed8
  9a8317:	48 85 c0                                        	test   rax,rax
  9a831a:	74 d4                                           	je     0x9a82f0
  9a831c:	f3 4c 0f bc f8                                  	tzcnt  r15,rax
  9a8321:	c4 e2 f8 f3 c8                                  	blsr   rax,rax
  9a8326:	48 8d 3d 4b db 1f 03                            	lea    rdi,[rip+0x31fdb4b]        # 0x3ba5e78
  9a832d:	31 f6                                           	xor    esi,esi
  9a832f:	31 d2                                           	xor    edx,edx
  9a8331:	31 c9                                           	xor    ecx,ecx
  9a8333:	48 89 05 9e db 1f 03                            	mov    QWORD PTR [rip+0x31fdb9e],rax        # 0x3ba5ed8
  9a833a:	e8 61 ec b1 ff                                  	call   0x4c6fa0
  9a833f:	41 c1 e7 0d                                     	shl    r15d,0xd
  9a8343:	4c 03 3d 96 db 1f 03                            	add    r15,QWORD PTR [rip+0x31fdb96]        # 0x3ba5ee0
  9a834a:	45 39 ec                                        	cmp    r12d,r13d
  9a834d:	0f 8d 9d 01 00 00                               	jge    0x9a84f0
  9a8353:	48 8b 55 b8                                     	mov    rdx,QWORD PTR [rbp-0x48]
  9a8357:	44 89 e6                                        	mov    esi,r12d
  9a835a:	49 63 c5                                        	movsxd rax,r13d
  9a835d:	44 89 6d b4                                     	mov    DWORD PTR [rbp-0x4c],r13d
  9a8361:	4c 89 bd 78 ff ff ff                            	mov    QWORD PTR [rbp-0x88],r15
  9a8368:	48 89 45 80                                     	mov    QWORD PTR [rbp-0x80],rax
  9a836c:	89 f3                                           	mov    ebx,esi
  9a836e:	89 75 b0                                        	mov    DWORD PTR [rbp-0x50],esi
  9a8371:	48 8d 8a 68 01 00 00                            	lea    rcx,[rdx+0x168]
  9a8378:	4c 8d 62 18                                     	lea    r12,[rdx+0x18]
  9a837c:	48 8d 82 98 01 00 00                            	lea    rax,[rdx+0x198]
  9a8383:	48 89 4d 98                                     	mov    QWORD PTR [rbp-0x68],rcx
  9a8387:	48 89 45 a0                                     	mov    QWORD PTR [rbp-0x60],rax
  9a838b:	0f 1f 44 00 00                                  	nop    DWORD PTR [rax+rax*1+0x0]
  9a8390:	4c 89 7d c8                                     	mov    QWORD PTR [rbp-0x38],r15
  9a8394:	4c 8b 7d b8                                     	mov    r15,QWORD PTR [rbp-0x48]
  9a8398:	48 8b 45 80                                     	mov    rax,QWORD PTR [rbp-0x80]
  9a839c:	4c 63 f3                                        	movsxd r14,ebx
  9a839f:	44 89 ea                                        	mov    edx,r13d
  9a83a2:	48 c7 45 c0 00 00 00 00                         	mov    QWORD PTR [rbp-0x40],0x0
  9a83aa:	49 8d 9e 00 08 00 00                            	lea    rbx,[r14+0x800]
  9a83b1:	48 39 c3                                        	cmp    rbx,rax
  9a83b4:	4c 89 ff                                        	mov    rdi,r15
  9a83b7:	48 0f 43 d8                                     	cmovae rbx,rax
  9a83bb:	e8 c0 fc ff ff                                  	call   0x9a8080
  9a83c0:	4d 89 e5                                        	mov    r13,r12
  9a83c3:	4c 8b 65 88                                     	mov    r12,QWORD PTR [rbp-0x78]
  9a83c7:	48 8b 95 70 ff ff ff                            	mov    rdx,QWORD PTR [rbp-0x90]
  9a83ce:	89 45 ac                                        	mov    DWORD PTR [rbp-0x54],eax
  9a83d1:	48 8d 45 c8                                     	lea    rax,[rbp-0x38]
  9a83d5:	4c 89 fe                                        	mov    rsi,r15
  9a83d8:	44 89 f1                                        	mov    ecx,r14d
  9a83db:	41 89 d8                                        	mov    r8d,ebx
  9a83de:	4c 8d 4d c0                                     	lea    r9,[rbp-0x40]
  9a83e2:	48 89 04 24                                     	mov    QWORD PTR [rsp],rax
  9a83e6:	4c 89 e7                                        	mov    rdi,r12
  9a83e9:	e8 82 01 00 00                                  	call   0x9a8570
  9a83ee:	49 8b bc 24 d8 01 00 00                         	mov    rdi,QWORD PTR [r12+0x1d8]
  9a83f6:	48 8b 75 c0                                     	mov    rsi,QWORD PTR [rbp-0x40]
  9a83fa:	4d 89 ec                                        	mov    r12,r13
  9a83fd:	e8 3e 6f f4 ff                                  	call   0x8ef340
  9a8402:	48 8b 45 90                                     	mov    rax,QWORD PTR [rbp-0x70]
  9a8406:	80 b8 17 01 00 00 00                            	cmp    BYTE PTR [rax+0x117],0x0
  9a840d:	74 3a                                           	je     0x9a8449
  9a840f:	48 8b 45 90                                     	mov    rax,QWORD PTR [rbp-0x70]
  9a8413:	48 8d 0d ce de 0e 01                            	lea    rcx,[rip+0x10edece]        # 0x1a962e8
  9a841a:	c6 80 17 01 00 00 00                            	mov    BYTE PTR [rax+0x117],0x0
  9a8421:	48 8b 01                                        	mov    rax,QWORD PTR [rcx]
  9a8424:	4c 8b 70 40                                     	mov    r14,QWORD PTR [rax+0x40]
  9a8428:	48 8d 05 b9 88 8b ff                            	lea    rax,[rip+0xffffffffff8b88b9]        # 0x260ce8
  9a842f:	4c 29 f0                                        	sub    rax,r14
  9a8432:	48 c1 c8 03                                     	ror    rax,0x3
  9a8436:	48 3d ff 06 00 00                               	cmp    rax,0x6ff
  9a843c:	0f 87 9a 00 00 00                               	ja     0x9a84dc
  9a8442:	48 8b 7d 88                                     	mov    rdi,QWORD PTR [rbp-0x78]
  9a8446:	41 ff d6                                        	call   r14
  9a8449:	4c 8b bd 78 ff ff ff                            	mov    r15,QWORD PTR [rbp-0x88]
  9a8450:	48 8b 55 c8                                     	mov    rdx,QWORD PTR [rbp-0x38]
  9a8454:	48 8b 7d b8                                     	mov    rdi,QWORD PTR [rbp-0x48]
  9a8458:	4c 29 fa                                        	sub    rdx,r15
  9a845b:	4c 89 fe                                        	mov    rsi,r15
  9a845e:	48 c1 ea 02                                     	shr    rdx,0x2
  9a8462:	e8 59 02 00 00                                  	call   0x9a86c0
  9a8467:	8b 45 ac                                        	mov    eax,DWORD PTR [rbp-0x54]
  9a846a:	4c 89 e7                                        	mov    rdi,r12
  9a846d:	31 f6                                           	xor    esi,esi
  9a846f:	31 d2                                           	xor    edx,edx
  9a8471:	4c 8d 34 40                                     	lea    r14,[rax+rax*2]
  9a8475:	e8 26 c2 e2 ff                                  	call   0x7d46a0
  9a847a:	48 8b 45 98                                     	mov    rax,QWORD PTR [rbp-0x68]
  9a847e:	42 c7 04 b0 ff ff ff ff                         	mov    DWORD PTR [rax+r14*4],0xffffffff
  9a8486:	42 83 7c b0 08 00                               	cmp    DWORD PTR [rax+r14*4+0x8],0x0
  9a848c:	75 27                                           	jne    0x9a84b5
  9a848e:	48 8b 45 a0                                     	mov    rax,QWORD PTR [rbp-0x60]
  9a8492:	44 8b 6d b4                                     	mov    r13d,DWORD PTR [rbp-0x4c]
  9a8496:	83 38 00                                        	cmp    DWORD PTR [rax],0x0
  9a8499:	75 30                                           	jne    0x9a84cb
  9a849b:	4c 89 e7                                        	mov    rdi,r12
  9a849e:	31 f6                                           	xor    esi,esi
  9a84a0:	31 d2                                           	xor    edx,edx
  9a84a2:	e8 09 ca e2 ff                                  	call   0x7d4eb0
  9a84a7:	8b 75 b0                                        	mov    esi,DWORD PTR [rbp-0x50]
  9a84aa:	41 39 dd                                        	cmp    r13d,ebx
  9a84ad:	0f 8f dd fe ff ff                               	jg     0x9a8390
  9a84b3:	eb 3b                                           	jmp    0x9a84f0
  9a84b5:	48 8b 45 98                                     	mov    rax,QWORD PTR [rbp-0x68]
  9a84b9:	4a 8d 7c b0 08                                  	lea    rdi,[rax+r14*4+0x8]
  9a84be:	c7 07 00 00 00 00                               	mov    DWORD PTR [rdi],0x0
  9a84c4:	e8 47 e4 25 00                                  	call   0xc06910
  9a84c9:	eb c3                                           	jmp    0x9a848e
  9a84cb:	48 8b 7d a0                                     	mov    rdi,QWORD PTR [rbp-0x60]
  9a84cf:	c7 07 00 00 00 00                               	mov    DWORD PTR [rdi],0x0
  9a84d5:	e8 36 e4 25 00                                  	call   0xc06910
  9a84da:	eb bf                                           	jmp    0x9a849b
  9a84dc:	48 8d 3d 5d 79 bb 01                            	lea    rdi,[rip+0x1bb795d]        # 0x255fe40
  9a84e3:	4c 89 f6                                        	mov    rsi,r14
  9a84e6:	e8 d5 73 aa ff                                  	call   0x44f8c0
  9a84eb:	e9 52 ff ff ff                                  	jmp    0x9a8442
  9a84f0:	48 8d 3d 81 d9 1f 03                            	lea    rdi,[rip+0x31fd981]        # 0x3ba5e78
  9a84f7:	31 f6                                           	xor    esi,esi
  9a84f9:	31 d2                                           	xor    edx,edx
  9a84fb:	31 c9                                           	xor    ecx,ecx
  9a84fd:	e8 fe e4 b1 ff                                  	call   0x4c6a00
  9a8502:	44 2b 3d d7 d9 1f 03                            	sub    r15d,DWORD PTR [rip+0x31fd9d7]        # 0x3ba5ee0
  9a8509:	48 8b 05 c8 d9 1f 03                            	mov    rax,QWORD PTR [rip+0x31fd9c8]        # 0x3ba5ed8
  9a8510:	48 89 c1                                        	mov    rcx,rax
  9a8513:	41 c1 ef 0d                                     	shr    r15d,0xd
  9a8517:	4c 0f ab f9                                     	bts    rcx,r15
  9a851b:	48 89 0d b6 d9 1f 03                            	mov    QWORD PTR [rip+0x31fd9b6],rcx        # 0x3ba5ed8
  9a8522:	48 85 c0                                        	test   rax,rax
  9a8525:	75 0c                                           	jne    0x9a8533
  9a8527:	48 8d 3d aa d9 1f 03                            	lea    rdi,[rip+0x31fd9aa]        # 0x3ba5ed8
  9a852e:	e8 dd e3 25 00                                  	call   0xc06910
  9a8533:	48 8d 3d 3e d9 1f 03                            	lea    rdi,[rip+0x31fd93e]        # 0x3ba5e78
  9a853a:	31 f6                                           	xor    esi,esi
  9a853c:	31 d2                                           	xor    edx,edx
  9a853e:	31 c9                                           	xor    ecx,ecx
  9a8540:	e8 5b ea b1 ff                                  	call   0x4c6fa0
  9a8545:	48 8d 0d c4 3d f7 02                            	lea    rcx,[rip+0x2f73dc4]        # 0x391c310
  9a854c:	48 8b 01                                        	mov    rax,QWORD PTR [rcx]
  9a854f:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  9a8553:	75 0f                                           	jne    0x9a8564
  9a8555:	48 83 c4 78                                     	add    rsp,0x78
  9a8559:	5b                                              	pop    rbx
  9a855a:	41 5c                                           	pop    r12
  9a855c:	41 5d                                           	pop    r13
  9a855e:	41 5e                                           	pop    r14
  9a8560:	41 5f                                           	pop    r15
  9a8562:	5d                                              	pop    rbp
  9a8563:	c3                                              	ret
  9a8564:	e8 47 51 d5 ff                                  	call   0x6fd6b0
  9a8569:	0f 0b                                           	ud2
  9a856b:	90                                              	nop
  9a856c:	90                                              	nop
  9a856d:	90                                              	nop
  9a856e:	90                                              	nop
  9a856f:	90                                              	nop
  9a8570:	55                                              	push   rbp
  9a8571:	48 89 e5                                        	mov    rbp,rsp
  9a8574:	41 57                                           	push   r15
  9a8576:	41 56                                           	push   r14
  9a8578:	41 55                                           	push   r13
  9a857a:	41 54                                           	push   r12
  9a857c:	53                                              	push   rbx
  9a857d:	48 83 ec 38                                     	sub    rsp,0x38
  9a8581:	48 8b 45 10                                     	mov    rax,QWORD PTR [rbp+0x10]
  9a8585:	4c 89 4d b8                                     	mov    QWORD PTR [rbp-0x48],r9
  9a8589:	4c 8b 8e 90 01 00 00                            	mov    r9,QWORD PTR [rsi+0x190]
  9a8590:	48 89 75 a8                                     	mov    QWORD PTR [rbp-0x58],rsi
  9a8594:	41 89 cc                                        	mov    r12d,ecx
  9a8597:	44 89 45 b4                                     	mov    DWORD PTR [rbp-0x4c],r8d
  9a859b:	45 31 f6                                        	xor    r14d,r14d
  9a859e:	4d 63 ec                                        	movsxd r13,r12d
  9a85a1:	4c 8b 38                                        	mov    r15,QWORD PTR [rax]
  9a85a4:	48 8b 86 60 01 00 00                            	mov    rax,QWORD PTR [rsi+0x160]
  9a85ab:	48 8b b7 d8 01 00 00                            	mov    rsi,QWORD PTR [rdi+0x1d8]
  9a85b2:	4c 89 4d a0                                     	mov    QWORD PTR [rbp-0x60],r9
  9a85b6:	48 89 75 c8                                     	mov    QWORD PTR [rbp-0x38],rsi
  9a85ba:	4c 89 ee                                        	mov    rsi,r13
  9a85bd:	4a 8d 1c a8                                     	lea    rbx,[rax+r13*4]
  9a85c1:	48 c1 e6 10                                     	shl    rsi,0x10
  9a85c5:	65 48 8b 0c 25 00 00 00 00                      	mov    rcx,QWORD PTR gs:0x0
  9a85ce:	48 89 55 c0                                     	mov    QWORD PTR [rbp-0x40],rdx
  9a85d2:	c6 81 17 01 00 00 01                            	mov    BYTE PTR [rcx+0x117],0x1
  9a85d9:	48 01 d6                                        	add    rsi,rdx
  9a85dc:	44 89 c2                                        	mov    edx,r8d
  9a85df:	48 89 d9                                        	mov    rcx,rbx
  9a85e2:	45 31 c0                                        	xor    r8d,r8d
  9a85e5:	44 29 ea                                        	sub    edx,r13d
  9a85e8:	48 89 75 d0                                     	mov    QWORD PTR [rbp-0x30],rsi
  9a85ec:	e8 1f 3e 04 00                                  	call   0x9ec410
  9a85f1:	8b 55 b4                                        	mov    edx,DWORD PTR [rbp-0x4c]
  9a85f4:	44 39 ea                                        	cmp    edx,r13d
  9a85f7:	7e 64                                           	jle    0x9a865d
  9a85f9:	48 8b 75 a0                                     	mov    rsi,QWORD PTR [rbp-0x60]
  9a85fd:	eb 0d                                           	jmp    0x9a860c
  9a85ff:	90                                              	nop
  9a8600:	41 ff c4                                        	inc    r12d
  9a8603:	48 83 c3 04                                     	add    rbx,0x4
  9a8607:	44 39 e2                                        	cmp    edx,r12d
  9a860a:	74 35                                           	je     0x9a8641
  9a860c:	44 8b 2b                                        	mov    r13d,DWORD PTR [rbx]
  9a860f:	44 89 e8                                        	mov    eax,r13d
  9a8612:	c1 e8 1c                                        	shr    eax,0x1c
  9a8615:	83 e0 03                                        	and    eax,0x3
  9a8618:	74 e6                                           	je     0x9a8600
  9a861a:	83 f8 01                                        	cmp    eax,0x1
  9a861d:	75 73                                           	jne    0x9a8692
  9a861f:	44 89 e0                                        	mov    eax,r12d
  9a8622:	c7 03 00 00 00 00                               	mov    DWORD PTR [rbx],0x0
  9a8628:	45 89 2f                                        	mov    DWORD PTR [r15],r13d
  9a862b:	49 83 c7 04                                     	add    r15,0x4
  9a862f:	31 c9                                           	xor    ecx,ecx
  9a8631:	c1 f8 05                                        	sar    eax,0x5
  9a8634:	48 98                                           	cdqe
  9a8636:	fe 0c 06                                        	dec    BYTE PTR [rsi+rax*1]
  9a8639:	0f 94 c1                                        	sete   cl
  9a863c:	41 01 ce                                        	add    r14d,ecx
  9a863f:	eb bf                                           	jmp    0x9a8600
  9a8641:	45 85 f6                                        	test   r14d,r14d
  9a8644:	7e 17                                           	jle    0x9a865d
  9a8646:	48 8b 45 a8                                     	mov    rax,QWORD PTR [rbp-0x58]
  9a864a:	44 89 f6                                        	mov    esi,r14d
  9a864d:	89 d3                                           	mov    ebx,edx
  9a864f:	0f b6 b8 9c 01 00 00                            	movzx  edi,BYTE PTR [rax+0x19c]
  9a8656:	e8 75 4f f4 ff                                  	call   0x8ed5d0
  9a865b:	89 da                                           	mov    edx,ebx
  9a865d:	48 8b 45 c0                                     	mov    rax,QWORD PTR [rbp-0x40]
  9a8661:	48 8b 4d b8                                     	mov    rcx,QWORD PTR [rbp-0x48]
  9a8665:	48 8b 7d c8                                     	mov    rdi,QWORD PTR [rbp-0x38]
  9a8669:	48 8b 75 d0                                     	mov    rsi,QWORD PTR [rbp-0x30]
  9a866d:	48 63 d2                                        	movsxd rdx,edx
  9a8670:	48 8b 5d 10                                     	mov    rbx,QWORD PTR [rbp+0x10]
  9a8674:	48 c1 e2 10                                     	shl    rdx,0x10
  9a8678:	48 01 c2                                        	add    rdx,rax
  9a867b:	e8 00 61 f4 ff                                  	call   0x8ee780
  9a8680:	4c 89 3b                                        	mov    QWORD PTR [rbx],r15
  9a8683:	48 83 c4 38                                     	add    rsp,0x38
  9a8687:	5b                                              	pop    rbx
  9a8688:	41 5c                                           	pop    r12
  9a868a:	41 5d                                           	pop    r13
  9a868c:	41 5e                                           	pop    r14
  9a868e:	41 5f                                           	pop    r15
  9a8690:	5d                                              	pop    rbp
  9a8691:	c3                                              	ret
  9a8692:	e8 b9 92 e4 ff                                  	call   0x7f1950
  9a8697:	48 8d 3d f4 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff4]        # 0x9a8692
  9a869e:	4c 89 ee                                        	mov    rsi,r13
  9a86a1:	e8 fa 91 e4 ff                                  	call   0x7f18a0
  9a86a6:	48 8d 35 d1 b8 91 00                            	lea    rsi,[rip+0x91b8d1]        # 0x12c3f7e
  9a86ad:	bf 2b 00 00 00                                  	mov    edi,0x2b
  9a86b2:	44 89 ea                                        	mov    edx,r13d
  9a86b5:	31 c0                                           	xor    eax,eax
  9a86b7:	e8 54 23 2f 00                                  	call   0xc9aa10
  9a86bc:	0f 0b                                           	ud2
  9a86be:	90                                              	nop
  9a86bf:	90                                              	nop
  9a86c0:	85 d2                                           	test   edx,edx
  9a86c2:	0f 84 04 01 00 00                               	je     0x9a87cc
  9a86c8:	55                                              	push   rbp
  9a86c9:	48 89 e5                                        	mov    rbp,rsp
  9a86cc:	41 57                                           	push   r15
  9a86ce:	41 56                                           	push   r14
  9a86d0:	41 55                                           	push   r13
  9a86d2:	41 54                                           	push   r12
  9a86d4:	53                                              	push   rbx
  9a86d5:	50                                              	push   rax
  9a86d6:	4c 8b a7 e8 00 00 00                            	mov    r12,QWORD PTR [rdi+0xe8]
  9a86dd:	41 89 d7                                        	mov    r15d,edx
  9a86e0:	48 89 f3                                        	mov    rbx,rsi
  9a86e3:	45 31 ed                                        	xor    r13d,r13d
  9a86e6:	31 f6                                           	xor    esi,esi
  9a86e8:	31 d2                                           	xor    edx,edx
  9a86ea:	31 c9                                           	xor    ecx,ecx
  9a86ec:	4d 8d 74 24 28                                  	lea    r14,[r12+0x28]
  9a86f1:	4c 89 f7                                        	mov    rdi,r14
  9a86f4:	e8 07 e3 b1 ff                                  	call   0x4c6a00
  9a86f9:	44 89 f8                                        	mov    eax,r15d
  9a86fc:	b9 01 00 00 00                                  	mov    ecx,0x1
  9a8701:	eb 19                                           	jmp    0x9a871c
  9a8703:	66 66 66 66 2e 0f 1f 84 00 00 00 00 00          	data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  9a8710:	49 ff c5                                        	inc    r13
  9a8713:	44 39 e8                                        	cmp    eax,r13d
  9a8716:	0f 84 94 00 00 00                               	je     0x9a87b0
  9a871c:	42 8b 34 ab                                     	mov    esi,DWORD PTR [rbx+r13*4]
  9a8720:	f7 c6 00 00 80 00                               	test   esi,0x800000
  9a8726:	75 18                                           	jne    0x9a8740
  9a8728:	41 ff 4c 24 54                                  	dec    DWORD PTR [r12+0x54]
  9a872d:	41 ff 44 24 4c                                  	inc    DWORD PTR [r12+0x4c]
  9a8732:	ba 90 08 02 00                                  	mov    edx,0x20890
  9a8737:	eb 16                                           	jmp    0x9a874f
  9a8739:	0f 1f 80 00 00 00 00                            	nop    DWORD PTR [rax+0x0]
  9a8740:	41 ff 4c 24 50                                  	dec    DWORD PTR [r12+0x50]
  9a8745:	41 ff 44 24 48                                  	inc    DWORD PTR [r12+0x48]
  9a874a:	ba 70 00 00 00                                  	mov    edx,0x70
  9a874f:	41 89 f0                                        	mov    r8d,esi
  9a8752:	4c 01 e2                                        	add    rdx,r12
  9a8755:	41 c1 e8 06                                     	shr    r8d,0x6
  9a8759:	44 89 c7                                        	mov    edi,r8d
  9a875c:	81 e7 ff 3f 00 00                               	and    edi,0x3fff
  9a8762:	4c 8b 0c fa                                     	mov    r9,QWORD PTR [rdx+rdi*8]
  9a8766:	4d 89 ca                                        	mov    r10,r9
  9a8769:	49 0f ab f2                                     	bts    r10,rsi
  9a876d:	4c 89 14 fa                                     	mov    QWORD PTR [rdx+rdi*8],r10
  9a8771:	4d 85 c9                                        	test   r9,r9
  9a8774:	75 9a                                           	jne    0x9a8710
  9a8776:	89 fe                                           	mov    esi,edi
  9a8778:	c1 ee 06                                        	shr    esi,0x6
  9a877b:	4c 8b 8c f2 00 00 02 00                         	mov    r9,QWORD PTR [rdx+rsi*8+0x20000]
  9a8783:	4d 89 ca                                        	mov    r10,r9
  9a8786:	4d 0f ab c2                                     	bts    r10,r8
  9a878a:	4c 89 94 f2 00 00 02 00                         	mov    QWORD PTR [rdx+rsi*8+0x20000],r10
  9a8792:	4d 85 c9                                        	test   r9,r9
  9a8795:	0f 85 75 ff ff ff                               	jne    0x9a8710
  9a879b:	c4 e2 c9 f7 f1                                  	shlx   rsi,rcx,rsi
  9a87a0:	c1 ef 0c                                        	shr    edi,0xc
  9a87a3:	48 09 b4 fa 00 08 02 00                         	or     QWORD PTR [rdx+rdi*8+0x20800],rsi
  9a87ab:	e9 60 ff ff ff                                  	jmp    0x9a8710
  9a87b0:	4c 89 f7                                        	mov    rdi,r14
  9a87b3:	31 f6                                           	xor    esi,esi
  9a87b5:	31 d2                                           	xor    edx,edx
  9a87b7:	31 c9                                           	xor    ecx,ecx
  9a87b9:	48 83 c4 08                                     	add    rsp,0x8
  9a87bd:	5b                                              	pop    rbx
  9a87be:	41 5c                                           	pop    r12
  9a87c0:	41 5d                                           	pop    r13
  9a87c2:	41 5e                                           	pop    r14
  9a87c4:	41 5f                                           	pop    r15
  9a87c6:	5d                                              	pop    rbp
  9a87c7:	e9 d4 e7 b1 ff                                  	jmp    0x4c6fa0
  9a87cc:	c3                                              	ret
  9a87cd:	90                                              	nop
  9a87ce:	90                                              	nop
  9a87cf:	90                                              	nop
  9a87d0:	55                                              	push   rbp
  9a87d1:	48 89 e5                                        	mov    rbp,rsp
  9a87d4:	41 57                                           	push   r15
  9a87d6:	41 56                                           	push   r14
  9a87d8:	41 55                                           	push   r13
  9a87da:	41 54                                           	push   r12
  9a87dc:	53                                              	push   rbx
  9a87dd:	48 83 ec 68                                     	sub    rsp,0x68
  9a87e1:	4c 8d 2d 28 3b f7 02                            	lea    r13,[rip+0x2f73b28]        # 0x391c310
  9a87e8:	48 89 55 88                                     	mov    QWORD PTR [rbp-0x78],rdx
  9a87ec:	48 89 7d b8                                     	mov    QWORD PTR [rbp-0x48],rdi
  9a87f0:	48 89 f3                                        	mov    rbx,rsi
  9a87f3:	48 89 f7                                        	mov    rdi,rsi
  9a87f6:	89 ce                                           	mov    esi,ecx
  9a87f8:	44 89 c2                                        	mov    edx,r8d
  9a87fb:	45 89 cc                                        	mov    r12d,r9d
  9a87fe:	41 89 cf                                        	mov    r15d,ecx
  9a8801:	49 8b 45 00                                     	mov    rax,QWORD PTR [r13+0x0]
  9a8805:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  9a8809:	44 89 45 c4                                     	mov    DWORD PTR [rbp-0x3c],r8d
  9a880d:	e8 6e f8 ff ff                                  	call   0x9a8080
  9a8812:	4c 8b b3 60 01 00 00                            	mov    r14,QWORD PTR [rbx+0x160]
  9a8819:	48 89 5d b0                                     	mov    QWORD PTR [rbp-0x50],rbx
  9a881d:	41 f7 c4 a2 02 00 00                            	test   r12d,0x2a2
  9a8824:	74 43                                           	je     0x9a8869
  9a8826:	8b 4d c4                                        	mov    ecx,DWORD PTR [rbp-0x3c]
  9a8829:	41 89 c8                                        	mov    r8d,ecx
  9a882c:	45 29 f8                                        	sub    r8d,r15d
  9a882f:	7e 38                                           	jle    0x9a8869
  9a8831:	48 8b 4d b8                                     	mov    rcx,QWORD PTR [rbp-0x48]
  9a8835:	0f b6 89 44 02 00 00                            	movzx  ecx,BYTE PTR [rcx+0x244]
  9a883c:	80 e1 02                                        	and    cl,0x2
  9a883f:	74 28                                           	je     0x9a8869
  9a8841:	49 63 cf                                        	movsxd rcx,r15d
  9a8844:	31 d2                                           	xor    edx,edx
  9a8846:	be 00 00 f0 00                                  	mov    esi,0xf00000
  9a884b:	49 8d 0c 8e                                     	lea    rcx,[r14+rcx*4]
  9a884f:	90                                              	nop
  9a8850:	8b 3c 91                                        	mov    edi,DWORD PTR [rcx+rdx*4]
  9a8853:	21 f7                                           	and    edi,esi
  9a8855:	81 ff 00 00 80 00                               	cmp    edi,0x800000
  9a885b:	0f 84 e1 01 00 00                               	je     0x9a8a42
  9a8861:	48 ff c2                                        	inc    rdx
  9a8864:	41 39 d0                                        	cmp    r8d,edx
  9a8867:	75 e7                                           	jne    0x9a8850
  9a8869:	48 8b 4d b8                                     	mov    rcx,QWORD PTR [rbp-0x48]
  9a886d:	89 45 ac                                        	mov    DWORD PTR [rbp-0x54],eax
  9a8870:	48 8b 45 b0                                     	mov    rax,QWORD PTR [rbp-0x50]
  9a8874:	48 8b 89 d8 01 00 00                            	mov    rcx,QWORD PTR [rcx+0x1d8]
  9a887b:	48 8b 80 e8 00 00 00                            	mov    rax,QWORD PTR [rax+0xe8]
  9a8882:	48 c7 45 c8 00 00 00 00                         	mov    QWORD PTR [rbp-0x38],0x0
  9a888a:	48 89 4d a0                                     	mov    QWORD PTR [rbp-0x60],rcx
  9a888e:	44 39 7d c4                                     	cmp    DWORD PTR [rbp-0x3c],r15d
  9a8892:	0f 8e ed 00 00 00                               	jle    0x9a8985
  9a8898:	b9 01 01 00 00                                  	mov    ecx,0x101
  9a889d:	48 8b 50 30                                     	mov    rdx,QWORD PTR [rax+0x30]
  9a88a1:	44 89 f8                                        	mov    eax,r15d
  9a88a4:	48 63 75 c4                                     	movsxd rsi,DWORD PTR [rbp-0x3c]
  9a88a8:	c4 c2 70 f7 cc                                  	bextr  ecx,r12d,ecx
  9a88ad:	83 e0 e0                                        	and    eax,0xffffffe0
  9a88b0:	44 09 e1                                        	or     ecx,r12d
  9a88b3:	41 83 e4 30                                     	and    r12d,0x30
  9a88b7:	48 98                                           	cdqe
  9a88b9:	83 e1 03                                        	and    ecx,0x3
  9a88bc:	41 c1 e4 16                                     	shl    r12d,0x16
  9a88c0:	48 83 c0 20                                     	add    rax,0x20
  9a88c4:	c1 e1 18                                        	shl    ecx,0x18
  9a88c7:	48 89 75 98                                     	mov    QWORD PTR [rbp-0x68],rsi
  9a88cb:	48 89 55 90                                     	mov    QWORD PTR [rbp-0x70],rdx
  9a88cf:	41 09 cc                                        	or     r12d,ecx
  9a88d2:	48 39 f0                                        	cmp    rax,rsi
  9a88d5:	44 89 f9                                        	mov    ecx,r15d
  9a88d8:	48 0f 43 c6                                     	cmovae rax,rsi
  9a88dc:	eb 3f                                           	jmp    0x9a891d
  9a88de:	66 90                                           	xchg   ax,ax
  9a88e0:	48 89 de                                        	mov    rsi,rbx
  9a88e3:	48 8b 5d 90                                     	mov    rbx,QWORD PTR [rbp-0x70]
  9a88e7:	48 8b 7d a0                                     	mov    rdi,QWORD PTR [rbp-0x60]
  9a88eb:	4c 8b 45 80                                     	mov    r8,QWORD PTR [rbp-0x80]
  9a88ef:	48 8d 45 c8                                     	lea    rax,[rbp-0x38]
  9a88f3:	45 89 e1                                        	mov    r9d,r12d
  9a88f6:	48 89 04 24                                     	mov    QWORD PTR [rsp],rax
  9a88fa:	48 89 da                                        	mov    rdx,rbx
  9a88fd:	e8 0e 5a f4 ff                                  	call   0x8ee310
  9a8902:	48 8b 4d 98                                     	mov    rcx,QWORD PTR [rbp-0x68]
  9a8906:	49 8d 47 20                                     	lea    rax,[r15+0x20]
  9a890a:	48 89 da                                        	mov    rdx,rbx
  9a890d:	48 39 c8                                        	cmp    rax,rcx
  9a8910:	48 0f 43 c1                                     	cmovae rax,rcx
  9a8914:	8b 4d a8                                        	mov    ecx,DWORD PTR [rbp-0x58]
  9a8917:	44 39 7d c4                                     	cmp    DWORD PTR [rbp-0x3c],r15d
  9a891b:	7e 68                                           	jle    0x9a8985
  9a891d:	4c 63 e9                                        	movsxd r13,ecx
  9a8920:	48 8b 7d b8                                     	mov    rdi,QWORD PTR [rbp-0x48]
  9a8924:	89 c1                                           	mov    ecx,eax
  9a8926:	45 89 e1                                        	mov    r9d,r12d
  9a8929:	41 89 c7                                        	mov    r15d,eax
  9a892c:	4c 89 eb                                        	mov    rbx,r13
  9a892f:	4f 8d 04 ae                                     	lea    r8,[r14+r13*4]
  9a8933:	44 29 e9                                        	sub    ecx,r13d
  9a8936:	48 c1 e3 10                                     	shl    rbx,0x10
  9a893a:	48 03 5d 88                                     	add    rbx,QWORD PTR [rbp-0x78]
  9a893e:	4c 89 45 80                                     	mov    QWORD PTR [rbp-0x80],r8
  9a8942:	48 89 de                                        	mov    rsi,rbx
  9a8945:	e8 b6 46 04 00                                  	call   0x9ed000
  9a894a:	44 89 f9                                        	mov    ecx,r15d
  9a894d:	44 89 7d a8                                     	mov    DWORD PTR [rbp-0x58],r15d
  9a8951:	4d 63 ff                                        	movsxd r15,r15d
  9a8954:	44 29 e9                                        	sub    ecx,r13d
  9a8957:	7f 13                                           	jg     0x9a896c
  9a8959:	eb 85                                           	jmp    0x9a88e0
  9a895b:	0f 1f 44 00 00                                  	nop    DWORD PTR [rax+rax*1+0x0]
  9a8960:	49 ff c5                                        	inc    r13
  9a8963:	4d 39 ef                                        	cmp    r15,r13
  9a8966:	0f 84 74 ff ff ff                               	je     0x9a88e0
  9a896c:	43 8b 04 ae                                     	mov    eax,DWORD PTR [r14+r13*4]
  9a8970:	a9 00 00 00 30                                  	test   eax,0x30000000
  9a8975:	74 e9                                           	je     0x9a8960
  9a8977:	25 ff ff ff f0                                  	and    eax,0xf0ffffff
  9a897c:	44 09 e0                                        	or     eax,r12d
  9a897f:	43 89 04 ae                                     	mov    DWORD PTR [r14+r13*4],eax
  9a8983:	eb db                                           	jmp    0x9a8960
  9a8985:	65 48 8b 04 25 00 00 00 00                      	mov    rax,QWORD PTR gs:0x0
  9a898e:	80 b8 16 01 00 00 00                            	cmp    BYTE PTR [rax+0x116],0x0
  9a8995:	4c 8b 65 b0                                     	mov    r12,QWORD PTR [rbp-0x50]
  9a8999:	75 2e                                           	jne    0x9a89c9
  9a899b:	48 8d 05 46 d9 0e 01                            	lea    rax,[rip+0x10ed946]        # 0x1a962e8
  9a89a2:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  9a89a5:	48 8b 58 40                                     	mov    rbx,QWORD PTR [rax+0x40]
  9a89a9:	48 8d 05 38 83 8b ff                            	lea    rax,[rip+0xffffffffff8b8338]        # 0x260ce8
  9a89b0:	48 29 d8                                        	sub    rax,rbx
  9a89b3:	48 c1 c8 03                                     	ror    rax,0x3
  9a89b7:	48 3d ff 06 00 00                               	cmp    rax,0x6ff
  9a89bd:	0f 87 c8 00 00 00                               	ja     0x9a8a8b
  9a89c3:	48 8b 7d b8                                     	mov    rdi,QWORD PTR [rbp-0x48]
  9a89c7:	ff d3                                           	call   rbx
  9a89c9:	48 8b 75 c8                                     	mov    rsi,QWORD PTR [rbp-0x38]
  9a89cd:	48 8b 7d a0                                     	mov    rdi,QWORD PTR [rbp-0x60]
  9a89d1:	e8 6a 69 f4 ff                                  	call   0x8ef340
  9a89d6:	4c 8d 2d 33 39 f7 02                            	lea    r13,[rip+0x2f73933]        # 0x391c310
  9a89dd:	8b 45 ac                                        	mov    eax,DWORD PTR [rbp-0x54]
  9a89e0:	31 db                                           	xor    ebx,ebx
  9a89e2:	4d 8d 74 24 18                                  	lea    r14,[r12+0x18]
  9a89e7:	89 c0                                           	mov    eax,eax
  9a89e9:	31 f6                                           	xor    esi,esi
  9a89eb:	31 d2                                           	xor    edx,edx
  9a89ed:	4c 89 f7                                        	mov    rdi,r14
  9a89f0:	4c 8d 3c 40                                     	lea    r15,[rax+rax*2]
  9a89f4:	e8 a7 bc e2 ff                                  	call   0x7d46a0
  9a89f9:	43 c7 84 bc 68 01 00 00 ff ff ff ff             	mov    DWORD PTR [r12+r15*4+0x168],0xffffffff
  9a8a05:	43 83 bc bc 70 01 00 00 00                      	cmp    DWORD PTR [r12+r15*4+0x170],0x0
  9a8a0e:	75 3d                                           	jne    0x9a8a4d
  9a8a10:	41 83 bc 24 98 01 00 00 00                      	cmp    DWORD PTR [r12+0x198],0x0
  9a8a19:	75 50                                           	jne    0x9a8a6b
  9a8a1b:	4c 89 f7                                        	mov    rdi,r14
  9a8a1e:	31 f6                                           	xor    esi,esi
  9a8a20:	31 d2                                           	xor    edx,edx
  9a8a22:	e8 89 c4 e2 ff                                  	call   0x7d4eb0
  9a8a27:	49 8b 45 00                                     	mov    rax,QWORD PTR [r13+0x0]
  9a8a2b:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  9a8a2f:	75 53                                           	jne    0x9a8a84
  9a8a31:	89 d8                                           	mov    eax,ebx
  9a8a33:	48 83 c4 68                                     	add    rsp,0x68
  9a8a37:	5b                                              	pop    rbx
  9a8a38:	41 5c                                           	pop    r12
  9a8a3a:	41 5d                                           	pop    r13
  9a8a3c:	41 5e                                           	pop    r14
  9a8a3e:	41 5f                                           	pop    r15
  9a8a40:	5d                                              	pop    rbp
  9a8a41:	c3                                              	ret
  9a8a42:	4c 8b 65 b0                                     	mov    r12,QWORD PTR [rbp-0x50]
  9a8a46:	bb 0d 00 00 00                                  	mov    ebx,0xd
  9a8a4b:	eb 95                                           	jmp    0x9a89e2
  9a8a4d:	4b 8d bc bc 70 01 00 00                         	lea    rdi,[r12+r15*4+0x170]
  9a8a55:	c7 07 00 00 00 00                               	mov    DWORD PTR [rdi],0x0
  9a8a5b:	e8 b0 de 25 00                                  	call   0xc06910
  9a8a60:	41 83 bc 24 98 01 00 00 00                      	cmp    DWORD PTR [r12+0x198],0x0
  9a8a69:	74 b0                                           	je     0x9a8a1b
  9a8a6b:	49 81 c4 98 01 00 00                            	add    r12,0x198
  9a8a72:	4c 89 e7                                        	mov    rdi,r12
  9a8a75:	41 c7 04 24 00 00 00 00                         	mov    DWORD PTR [r12],0x0
  9a8a7d:	e8 8e de 25 00                                  	call   0xc06910
  9a8a82:	eb 97                                           	jmp    0x9a8a1b
  9a8a84:	e8 27 4c d5 ff                                  	call   0x6fd6b0
  9a8a89:	0f 0b                                           	ud2
  9a8a8b:	48 8d 3d be 74 bb 01                            	lea    rdi,[rip+0x1bb74be]        # 0x255ff50
  9a8a92:	48 89 de                                        	mov    rsi,rbx
  9a8a95:	e8 26 6e aa ff                                  	call   0x44f8c0
  9a8a9a:	e9 24 ff ff ff                                  	jmp    0x9a89c3
  9a8a9f:	90                                              	nop
  9a8aa0:	55                                              	push   rbp
  9a8aa1:	48 89 e5                                        	mov    rbp,rsp
  9a8aa4:	41 57                                           	push   r15
  9a8aa6:	41 56                                           	push   r14
  9a8aa8:	41 55                                           	push   r13
  9a8aaa:	41 54                                           	push   r12
  9a8aac:	53                                              	push   rbx
  9a8aad:	48 83 ec 68                                     	sub    rsp,0x68
  9a8ab1:	4c 8d 2d 58 38 f7 02                            	lea    r13,[rip+0x2f73858]        # 0x391c310
  9a8ab8:	48 89 95 78 ff ff ff                            	mov    QWORD PTR [rbp-0x88],rdx
  9a8abf:	48 89 fb                                        	mov    rbx,rdi
  9a8ac2:	48 89 f7                                        	mov    rdi,rsi
  9a8ac5:	44 89 c2                                        	mov    edx,r8d
  9a8ac8:	45 89 cc                                        	mov    r12d,r9d
  9a8acb:	41 89 cf                                        	mov    r15d,ecx
  9a8ace:	49 8b 45 00                                     	mov    rax,QWORD PTR [r13+0x0]
  9a8ad2:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  9a8ad6:	48 89 75 80                                     	mov    QWORD PTR [rbp-0x80],rsi
  9a8ada:	89 ce                                           	mov    esi,ecx
  9a8adc:	44 89 45 bc                                     	mov    DWORD PTR [rbp-0x44],r8d
  9a8ae0:	e8 9b f5 ff ff                                  	call   0x9a8080
  9a8ae5:	41 89 c6                                        	mov    r14d,eax
  9a8ae8:	0f b6 83 44 02 00 00                            	movzx  eax,BYTE PTR [rbx+0x244]
  9a8aef:	48 89 5d b0                                     	mov    QWORD PTR [rbp-0x50],rbx
  9a8af3:	41 83 fc 0a                                     	cmp    r12d,0xa
  9a8af7:	77 33                                           	ja     0x9a8b2c
  9a8af9:	b9 09 04 00 00                                  	mov    ecx,0x409
  9a8afe:	44 0f a3 e1                                     	bt     ecx,r12d
  9a8b02:	73 28                                           	jae    0x9a8b2c
  9a8b04:	a8 02                                           	test   al,0x2
  9a8b06:	75 42                                           	jne    0x9a8b4a
  9a8b08:	44 89 e7                                        	mov    edi,r12d
  9a8b0b:	e8 00 41 00 00                                  	call   0x9acc10
  9a8b10:	31 c9                                           	xor    ecx,ecx
  9a8b12:	85 c0                                           	test   eax,eax
  9a8b14:	48 8b 45 b0                                     	mov    rax,QWORD PTR [rbp-0x50]
  9a8b18:	0f 94 c1                                        	sete   cl
  9a8b1b:	44 8d 24 8d 0f 00 00 00                         	lea    r12d,[rcx*4+0xf]
  9a8b23:	0f b6 80 44 02 00 00                            	movzx  eax,BYTE PTR [rax+0x244]
  9a8b2a:	eb 1e                                           	jmp    0x9a8b4a
  9a8b2c:	41 8d 4c 24 eb                                  	lea    ecx,[r12-0x15]
  9a8b31:	bb 16 00 00 00                                  	mov    ebx,0x16
  9a8b36:	83 f9 f6                                        	cmp    ecx,0xfffffff6
  9a8b39:	0f 82 7f 03 00 00                               	jb     0x9a8ebe
  9a8b3f:	89 c1                                           	mov    ecx,eax
  9a8b41:	80 e1 02                                        	and    cl,0x2
  9a8b44:	0f 85 74 03 00 00                               	jne    0x9a8ebe
  9a8b4a:	44 89 75 8c                                     	mov    DWORD PTR [rbp-0x74],r14d
  9a8b4e:	a8 02                                           	test   al,0x2
  9a8b50:	75 23                                           	jne    0x9a8b75
  9a8b52:	41 83 c4 f5                                     	add    r12d,0xfffffff5
  9a8b56:	c7 45 c4 00 00 00 00                            	mov    DWORD PTR [rbp-0x3c],0x0
  9a8b5d:	41 83 fc 09                                     	cmp    r12d,0x9
  9a8b61:	77 2c                                           	ja     0x9a8b8f
  9a8b63:	44 89 e0                                        	mov    eax,r12d
  9a8b66:	48 8d 0d 1f 50 f2 00                            	lea    rcx,[rip+0xf2501f]        # 0x18cdb8c
  9a8b6d:	8b 04 81                                        	mov    eax,DWORD PTR [rcx+rax*4]
  9a8b70:	89 45 c4                                        	mov    DWORD PTR [rbp-0x3c],eax
  9a8b73:	eb 1a                                           	jmp    0x9a8b8f
  9a8b75:	31 c0                                           	xor    eax,eax
  9a8b77:	41 83 fc 0a                                     	cmp    r12d,0xa
  9a8b7b:	b9 00 00 c0 00                                  	mov    ecx,0xc00000
  9a8b80:	0f 94 c0                                        	sete   al
  9a8b83:	c1 e0 17                                        	shl    eax,0x17
  9a8b86:	45 85 e4                                        	test   r12d,r12d
  9a8b89:	0f 45 c8                                        	cmovne ecx,eax
  9a8b8c:	89 4d c4                                        	mov    DWORD PTR [rbp-0x3c],ecx
  9a8b8f:	48 8b 45 80                                     	mov    rax,QWORD PTR [rbp-0x80]
  9a8b93:	4d 63 e7                                        	movsxd r12,r15d
  9a8b96:	44 89 7d c0                                     	mov    DWORD PTR [rbp-0x40],r15d
  9a8b9a:	44 8b 7d bc                                     	mov    r15d,DWORD PTR [rbp-0x44]
  9a8b9e:	48 8b bd 78 ff ff ff                            	mov    rdi,QWORD PTR [rbp-0x88]
  9a8ba5:	4c 89 e6                                        	mov    rsi,r12
  9a8ba8:	48 c1 e6 10                                     	shl    rsi,0x10
  9a8bac:	48 8b 88 e8 00 00 00                            	mov    rcx,QWORD PTR [rax+0xe8]
  9a8bb3:	4c 8b b0 60 01 00 00                            	mov    r14,QWORD PTR [rax+0x160]
  9a8bba:	48 c7 45 c8 00 00 00 00                         	mov    QWORD PTR [rbp-0x38],0x0
  9a8bc2:	49 63 d7                                        	movsxd rdx,r15d
  9a8bc5:	48 01 fe                                        	add    rsi,rdi
  9a8bc8:	48 89 55 90                                     	mov    QWORD PTR [rbp-0x70],rdx
  9a8bcc:	48 c1 e2 10                                     	shl    rdx,0x10
  9a8bd0:	48 01 fa                                        	add    rdx,rdi
  9a8bd3:	48 89 4d 98                                     	mov    QWORD PTR [rbp-0x68],rcx
  9a8bd7:	48 8b 4d b0                                     	mov    rcx,QWORD PTR [rbp-0x50]
  9a8bdb:	48 8b 99 d8 01 00 00                            	mov    rbx,QWORD PTR [rcx+0x1d8]
  9a8be2:	48 8d 4d c8                                     	lea    rcx,[rbp-0x38]
  9a8be6:	48 89 df                                        	mov    rdi,rbx
  9a8be9:	e8 92 5b f4 ff                                  	call   0x8ee780
  9a8bee:	48 8b 75 c8                                     	mov    rsi,QWORD PTR [rbp-0x38]
  9a8bf2:	48 89 df                                        	mov    rdi,rbx
  9a8bf5:	e8 46 67 f4 ff                                  	call   0x8ef340
  9a8bfa:	44 3b 7d c0                                     	cmp    r15d,DWORD PTR [rbp-0x40]
  9a8bfe:	7e 73                                           	jle    0x9a8c73
  9a8c00:	8b 45 c4                                        	mov    eax,DWORD PTR [rbp-0x3c]
  9a8c03:	4c 89 e1                                        	mov    rcx,r12
  9a8c06:	45 31 ed                                        	xor    r13d,r13d
  9a8c09:	45 31 ff                                        	xor    r15d,r15d
  9a8c0c:	25 00 00 80 00                                  	and    eax,0x800000
  9a8c11:	eb 16                                           	jmp    0x9a8c29
  9a8c13:	49 81 c7 00 00 01 00                            	add    r15,0x10000
  9a8c1a:	66 0f 1f 44 00 00                               	nop    WORD PTR [rax+rax*1+0x0]
  9a8c20:	48 ff c1                                        	inc    rcx
  9a8c23:	48 39 4d 90                                     	cmp    QWORD PTR [rbp-0x70],rcx
  9a8c27:	74 50                                           	je     0x9a8c79
  9a8c29:	41 8b 14 8e                                     	mov    edx,DWORD PTR [r14+rcx*4]
  9a8c2d:	89 d6                                           	mov    esi,edx
  9a8c2f:	81 e6 00 00 f0 00                               	and    esi,0xf00000
  9a8c35:	39 75 c4                                        	cmp    DWORD PTR [rbp-0x3c],esi
  9a8c38:	74 e6                                           	je     0x9a8c20
  9a8c3a:	81 e2 00 00 80 00                               	and    edx,0x800000
  9a8c40:	39 c2                                           	cmp    edx,eax
  9a8c42:	74 10                                           	je     0x9a8c54
  9a8c44:	85 c0                                           	test   eax,eax
  9a8c46:	75 09                                           	jne    0x9a8c51
  9a8c48:	41 ff cd                                        	dec    r13d
  9a8c4b:	85 d2                                           	test   edx,edx
  9a8c4d:	75 c4                                           	jne    0x9a8c13
  9a8c4f:	eb cf                                           	jmp    0x9a8c20
  9a8c51:	41 ff c5                                        	inc    r13d
  9a8c54:	85 d2                                           	test   edx,edx
  9a8c56:	74 c8                                           	je     0x9a8c20
  9a8c58:	81 7d c4 00 00 80 00                            	cmp    DWORD PTR [rbp-0x3c],0x800000
  9a8c5f:	75 bf                                           	jne    0x9a8c20
  9a8c61:	48 8b 55 b0                                     	mov    rdx,QWORD PTR [rbp-0x50]
  9a8c65:	0f b6 92 44 02 00 00                            	movzx  edx,BYTE PTR [rdx+0x244]
  9a8c6c:	80 e2 02                                        	and    dl,0x2
  9a8c6f:	74 a2                                           	je     0x9a8c13
  9a8c71:	eb ad                                           	jmp    0x9a8c20
  9a8c73:	45 31 ff                                        	xor    r15d,r15d
  9a8c76:	45 31 ed                                        	xor    r13d,r13d
  9a8c79:	4c 89 65 a8                                     	mov    QWORD PTR [rbp-0x58],r12
  9a8c7d:	4c 8b 65 98                                     	mov    r12,QWORD PTR [rbp-0x68]
  9a8c81:	31 f6                                           	xor    esi,esi
  9a8c83:	31 d2                                           	xor    edx,edx
  9a8c85:	31 c9                                           	xor    ecx,ecx
  9a8c87:	49 8d 5c 24 28                                  	lea    rbx,[r12+0x28]
  9a8c8c:	48 89 df                                        	mov    rdi,rbx
  9a8c8f:	e8 6c dd b1 ff                                  	call   0x4c6a00
  9a8c94:	45 01 6c 24 50                                  	add    DWORD PTR [r12+0x50],r13d
  9a8c99:	45 29 6c 24 54                                  	sub    DWORD PTR [r12+0x54],r13d
  9a8c9e:	49 81 ff 00 00 20 00                            	cmp    r15,0x200000
  9a8ca5:	72 18                                           	jb     0x9a8cbf
  9a8ca7:	4c 89 e7                                        	mov    rdi,r12
  9a8caa:	e8 a1 37 00 00                                  	call   0x9ac450
  9a8caf:	48 89 df                                        	mov    rdi,rbx
  9a8cb2:	31 f6                                           	xor    esi,esi
  9a8cb4:	31 d2                                           	xor    edx,edx
  9a8cb6:	31 c9                                           	xor    ecx,ecx
  9a8cb8:	e8 e3 e2 b1 ff                                  	call   0x4c6fa0
  9a8cbd:	eb 77                                           	jmp    0x9a8d36
  9a8cbf:	8b 45 bc                                        	mov    eax,DWORD PTR [rbp-0x44]
  9a8cc2:	48 89 df                                        	mov    rdi,rbx
  9a8cc5:	41 89 c5                                        	mov    r13d,eax
  9a8cc8:	44 2b 6d c0                                     	sub    r13d,DWORD PTR [rbp-0x40]
  9a8ccc:	0f 9e 45 a0                                     	setle  BYTE PTR [rbp-0x60]
  9a8cd0:	31 f6                                           	xor    esi,esi
  9a8cd2:	31 d2                                           	xor    edx,edx
  9a8cd4:	31 c9                                           	xor    ecx,ecx
  9a8cd6:	e8 c5 e2 b1 ff                                  	call   0x4c6fa0
  9a8cdb:	4d 85 ff                                        	test   r15,r15
  9a8cde:	0f 94 c0                                        	sete   al
  9a8ce1:	0a 45 a0                                        	or     al,BYTE PTR [rbp-0x60]
  9a8ce4:	75 50                                           	jne    0x9a8d36
  9a8ce6:	48 8b 45 a8                                     	mov    rax,QWORD PTR [rbp-0x58]
  9a8cea:	45 31 ff                                        	xor    r15d,r15d
  9a8ced:	49 8d 1c 86                                     	lea    rbx,[r14+rax*4]
  9a8cf1:	eb 15                                           	jmp    0x9a8d08
  9a8cf3:	66 66 66 66 2e 0f 1f 84 00 00 00 00 00          	data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  9a8d00:	49 ff c7                                        	inc    r15
  9a8d03:	45 39 fd                                        	cmp    r13d,r15d
  9a8d06:	74 2e                                           	je     0x9a8d36
  9a8d08:	42 8b 34 bb                                     	mov    esi,DWORD PTR [rbx+r15*4]
  9a8d0c:	89 f0                                           	mov    eax,esi
  9a8d0e:	25 00 00 80 30                                  	and    eax,0x30800000
  9a8d13:	3d 00 00 80 10                                  	cmp    eax,0x10800000
  9a8d18:	75 e6                                           	jne    0x9a8d00
  9a8d1a:	89 f0                                           	mov    eax,esi
  9a8d1c:	25 00 00 f0 00                                  	and    eax,0xf00000
  9a8d21:	3b 45 c4                                        	cmp    eax,DWORD PTR [rbp-0x3c]
  9a8d24:	74 da                                           	je     0x9a8d00
  9a8d26:	81 e6 ff ff 0f 00                               	and    esi,0xfffff
  9a8d2c:	4c 89 e7                                        	mov    rdi,r12
  9a8d2f:	e8 cc 37 00 00                                  	call   0x9ac500
  9a8d34:	eb ca                                           	jmp    0x9a8d00
  9a8d36:	48 8b 45 b0                                     	mov    rax,QWORD PTR [rbp-0x50]
  9a8d3a:	8b 4d c0                                        	mov    ecx,DWORD PTR [rbp-0x40]
  9a8d3d:	48 8b 80 d8 01 00 00                            	mov    rax,QWORD PTR [rax+0x1d8]
  9a8d44:	48 c7 45 c8 00 00 00 00                         	mov    QWORD PTR [rbp-0x38],0x0
  9a8d4c:	48 89 45 a8                                     	mov    QWORD PTR [rbp-0x58],rax
  9a8d50:	39 4d bc                                        	cmp    DWORD PTR [rbp-0x44],ecx
  9a8d53:	0f 8e 0b 01 00 00                               	jle    0x9a8e64
  9a8d59:	8b 75 10                                        	mov    esi,DWORD PTR [rbp+0x10]
  9a8d5c:	b8 01 01 00 00                                  	mov    eax,0x101
  9a8d61:	48 8b 7d 90                                     	mov    rdi,QWORD PTR [rbp-0x70]
  9a8d65:	8b 5d c4                                        	mov    ebx,DWORD PTR [rbp-0x3c]
  9a8d68:	49 8b 54 24 30                                  	mov    rdx,QWORD PTR [r12+0x30]
  9a8d6d:	c4 e2 78 f7 c6                                  	bextr  eax,esi,eax
  9a8d72:	48 89 95 70 ff ff ff                            	mov    QWORD PTR [rbp-0x90],rdx
  9a8d79:	09 f0                                           	or     eax,esi
  9a8d7b:	83 e6 30                                        	and    esi,0x30
  9a8d7e:	83 e0 03                                        	and    eax,0x3
  9a8d81:	c1 e6 16                                        	shl    esi,0x16
  9a8d84:	c1 e0 18                                        	shl    eax,0x18
  9a8d87:	09 c6                                           	or     esi,eax
  9a8d89:	89 c8                                           	mov    eax,ecx
  9a8d8b:	83 e0 e0                                        	and    eax,0xffffffe0
  9a8d8e:	48 89 75 a0                                     	mov    QWORD PTR [rbp-0x60],rsi
  9a8d92:	48 98                                           	cdqe
  9a8d94:	48 83 c0 20                                     	add    rax,0x20
  9a8d98:	48 39 f8                                        	cmp    rax,rdi
  9a8d9b:	48 0f 43 c7                                     	cmovae rax,rdi
  9a8d9f:	09 f3                                           	or     ebx,esi
  9a8da1:	eb 52                                           	jmp    0x9a8df5
  9a8da3:	66 66 66 66 2e 0f 1f 84 00 00 00 00 00          	data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  9a8db0:	4c 89 e6                                        	mov    rsi,r12
  9a8db3:	4c 8b a5 70 ff ff ff                            	mov    r12,QWORD PTR [rbp-0x90]
  9a8dba:	48 8b 7d a8                                     	mov    rdi,QWORD PTR [rbp-0x58]
  9a8dbe:	4c 8b 45 98                                     	mov    r8,QWORD PTR [rbp-0x68]
  9a8dc2:	44 8b 4d c4                                     	mov    r9d,DWORD PTR [rbp-0x3c]
  9a8dc6:	48 8d 45 c8                                     	lea    rax,[rbp-0x38]
  9a8dca:	4c 89 e2                                        	mov    rdx,r12
  9a8dcd:	50                                              	push   rax
  9a8dce:	ff 75 a0                                        	push   QWORD PTR [rbp-0x60]
  9a8dd1:	e8 ca 5c f4 ff                                  	call   0x8eeaa0
  9a8dd6:	4c 89 e2                                        	mov    rdx,r12
  9a8dd9:	48 83 c4 10                                     	add    rsp,0x10
  9a8ddd:	48 8b 4d 90                                     	mov    rcx,QWORD PTR [rbp-0x70]
  9a8de1:	49 8d 47 20                                     	lea    rax,[r15+0x20]
  9a8de5:	48 39 c8                                        	cmp    rax,rcx
  9a8de8:	48 0f 43 c1                                     	cmovae rax,rcx
  9a8dec:	8b 4d c0                                        	mov    ecx,DWORD PTR [rbp-0x40]
  9a8def:	44 39 7d bc                                     	cmp    DWORD PTR [rbp-0x44],r15d
  9a8df3:	7e 6f                                           	jle    0x9a8e64
  9a8df5:	4c 63 e9                                        	movsxd r13,ecx
  9a8df8:	48 8b 7d b0                                     	mov    rdi,QWORD PTR [rbp-0x50]
  9a8dfc:	89 c1                                           	mov    ecx,eax
  9a8dfe:	41 89 d9                                        	mov    r9d,ebx
  9a8e01:	41 89 c7                                        	mov    r15d,eax
  9a8e04:	4d 89 ec                                        	mov    r12,r13
  9a8e07:	4f 8d 04 ae                                     	lea    r8,[r14+r13*4]
  9a8e0b:	44 29 e9                                        	sub    ecx,r13d
  9a8e0e:	49 c1 e4 10                                     	shl    r12,0x10
  9a8e12:	4c 03 a5 78 ff ff ff                            	add    r12,QWORD PTR [rbp-0x88]
  9a8e19:	4c 89 45 98                                     	mov    QWORD PTR [rbp-0x68],r8
  9a8e1d:	4c 89 e6                                        	mov    rsi,r12
  9a8e20:	e8 0b 48 04 00                                  	call   0x9ed630
  9a8e25:	44 89 f9                                        	mov    ecx,r15d
  9a8e28:	44 89 7d c0                                     	mov    DWORD PTR [rbp-0x40],r15d
  9a8e2c:	4d 63 ff                                        	movsxd r15,r15d
  9a8e2f:	44 29 e9                                        	sub    ecx,r13d
  9a8e32:	7f 18                                           	jg     0x9a8e4c
  9a8e34:	e9 77 ff ff ff                                  	jmp    0x9a8db0
  9a8e39:	0f 1f 80 00 00 00 00                            	nop    DWORD PTR [rax+0x0]
  9a8e40:	49 ff c5                                        	inc    r13
  9a8e43:	4d 39 ef                                        	cmp    r15,r13
  9a8e46:	0f 84 64 ff ff ff                               	je     0x9a8db0
  9a8e4c:	43 8b 04 ae                                     	mov    eax,DWORD PTR [r14+r13*4]
  9a8e50:	a9 00 00 00 30                                  	test   eax,0x30000000
  9a8e55:	74 e9                                           	je     0x9a8e40
  9a8e57:	25 ff ff 0f f0                                  	and    eax,0xf00fffff
  9a8e5c:	09 d8                                           	or     eax,ebx
  9a8e5e:	43 89 04 ae                                     	mov    DWORD PTR [r14+r13*4],eax
  9a8e62:	eb dc                                           	jmp    0x9a8e40
  9a8e64:	65 48 8b 04 25 00 00 00 00                      	mov    rax,QWORD PTR gs:0x0
  9a8e6d:	80 b8 16 01 00 00 00                            	cmp    BYTE PTR [rax+0x116],0x0
  9a8e74:	4c 8d 2d 95 34 f7 02                            	lea    r13,[rip+0x2f73495]        # 0x391c310
  9a8e7b:	44 8b 75 8c                                     	mov    r14d,DWORD PTR [rbp-0x74]
  9a8e7f:	75 2e                                           	jne    0x9a8eaf
  9a8e81:	48 8d 05 60 d4 0e 01                            	lea    rax,[rip+0x10ed460]        # 0x1a962e8
  9a8e88:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  9a8e8b:	48 8b 58 40                                     	mov    rbx,QWORD PTR [rax+0x40]
  9a8e8f:	48 8d 05 52 7e 8b ff                            	lea    rax,[rip+0xffffffffff8b7e52]        # 0x260ce8
  9a8e96:	48 29 d8                                        	sub    rax,rbx
  9a8e99:	48 c1 c8 03                                     	ror    rax,0x3
  9a8e9d:	48 3d ff 06 00 00                               	cmp    rax,0x6ff
  9a8ea3:	0f 87 b8 00 00 00                               	ja     0x9a8f61
  9a8ea9:	48 8b 7d b0                                     	mov    rdi,QWORD PTR [rbp-0x50]
  9a8ead:	ff d3                                           	call   rbx
  9a8eaf:	48 8b 75 c8                                     	mov    rsi,QWORD PTR [rbp-0x38]
  9a8eb3:	48 8b 7d a8                                     	mov    rdi,QWORD PTR [rbp-0x58]
  9a8eb7:	e8 84 64 f4 ff                                  	call   0x8ef340
  9a8ebc:	31 db                                           	xor    ebx,ebx
  9a8ebe:	4c 8b 65 80                                     	mov    r12,QWORD PTR [rbp-0x80]
  9a8ec2:	44 89 f0                                        	mov    eax,r14d
  9a8ec5:	31 f6                                           	xor    esi,esi
  9a8ec7:	31 d2                                           	xor    edx,edx
  9a8ec9:	4c 8d 3c 40                                     	lea    r15,[rax+rax*2]
  9a8ecd:	4d 8d 74 24 18                                  	lea    r14,[r12+0x18]
  9a8ed2:	4c 89 f7                                        	mov    rdi,r14
  9a8ed5:	e8 c6 b7 e2 ff                                  	call   0x7d46a0
  9a8eda:	43 c7 84 bc 68 01 00 00 ff ff ff ff             	mov    DWORD PTR [r12+r15*4+0x168],0xffffffff
  9a8ee6:	43 83 bc bc 70 01 00 00 00                      	cmp    DWORD PTR [r12+r15*4+0x170],0x0
  9a8eef:	75 32                                           	jne    0x9a8f23
  9a8ef1:	41 83 bc 24 98 01 00 00 00                      	cmp    DWORD PTR [r12+0x198],0x0
  9a8efa:	75 45                                           	jne    0x9a8f41
  9a8efc:	4c 89 f7                                        	mov    rdi,r14
  9a8eff:	31 f6                                           	xor    esi,esi
  9a8f01:	31 d2                                           	xor    edx,edx
  9a8f03:	e8 a8 bf e2 ff                                  	call   0x7d4eb0
  9a8f08:	49 8b 45 00                                     	mov    rax,QWORD PTR [r13+0x0]
  9a8f0c:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  9a8f10:	75 48                                           	jne    0x9a8f5a
  9a8f12:	89 d8                                           	mov    eax,ebx
  9a8f14:	48 83 c4 68                                     	add    rsp,0x68
  9a8f18:	5b                                              	pop    rbx
  9a8f19:	41 5c                                           	pop    r12
  9a8f1b:	41 5d                                           	pop    r13
  9a8f1d:	41 5e                                           	pop    r14
  9a8f1f:	41 5f                                           	pop    r15
  9a8f21:	5d                                              	pop    rbp
  9a8f22:	c3                                              	ret
  9a8f23:	4b 8d bc bc 70 01 00 00                         	lea    rdi,[r12+r15*4+0x170]
  9a8f2b:	c7 07 00 00 00 00                               	mov    DWORD PTR [rdi],0x0
  9a8f31:	e8 da d9 25 00                                  	call   0xc06910
  9a8f36:	41 83 bc 24 98 01 00 00 00                      	cmp    DWORD PTR [r12+0x198],0x0
  9a8f3f:	74 bb                                           	je     0x9a8efc
  9a8f41:	49 81 c4 98 01 00 00                            	add    r12,0x198
  9a8f48:	4c 89 e7                                        	mov    rdi,r12
  9a8f4b:	41 c7 04 24 00 00 00 00                         	mov    DWORD PTR [r12],0x0
  9a8f53:	e8 b8 d9 25 00                                  	call   0xc06910
  9a8f58:	eb a2                                           	jmp    0x9a8efc
  9a8f5a:	e8 51 47 d5 ff                                  	call   0x6fd6b0
  9a8f5f:	0f 0b                                           	ud2
  9a8f61:	48 8d 3d 08 70 bb 01                            	lea    rdi,[rip+0x1bb7008]        # 0x255ff70
  9a8f68:	48 89 de                                        	mov    rsi,rbx
  9a8f6b:	e8 50 69 aa ff                                  	call   0x44f8c0
  9a8f70:	e9 34 ff ff ff                                  	jmp    0x9a8ea9
  9a8f75:	90                                              	nop
  9a8f76:	90                                              	nop
  9a8f77:	90                                              	nop
  9a8f78:	90                                              	nop
  9a8f79:	90                                              	nop
  9a8f7a:	90                                              	nop
  9a8f7b:	90                                              	nop
  9a8f7c:	90                                              	nop
  9a8f7d:	90                                              	nop
  9a8f7e:	90                                              	nop
  9a8f7f:	90                                              	nop
  9a8f80:	55                                              	push   rbp
  9a8f81:	48 89 e5                                        	mov    rbp,rsp
  9a8f84:	41 57                                           	push   r15
  9a8f86:	41 56                                           	push   r14
  9a8f88:	41 55                                           	push   r13
  9a8f8a:	41 54                                           	push   r12
  9a8f8c:	53                                              	push   rbx
  9a8f8d:	48 83 ec 28                                     	sub    rsp,0x28
  9a8f91:	4d 85 c0                                        	test   r8,r8
  9a8f94:	0f 84 a1 00 00 00                               	je     0x9a903b
  9a8f9a:	48 89 d3                                        	mov    rbx,rdx
  9a8f9d:	4c 8b be e8 00 00 00                            	mov    r15,QWORD PTR [rsi+0xe8]
  9a8fa4:	4c 8b ae 60 01 00 00                            	mov    r13,QWORD PTR [rsi+0x160]
  9a8fab:	49 89 d4                                        	mov    r12,rdx
  9a8fae:	49 89 f6                                        	mov    r14,rsi
  9a8fb1:	48 89 f7                                        	mov    rdi,rsi
  9a8fb4:	4c 89 45 b0                                     	mov    QWORD PTR [rbp-0x50],r8
  9a8fb8:	48 c1 eb 10                                     	shr    rbx,0x10
  9a8fbc:	8d 53 01                                        	lea    edx,[rbx+0x1]
  9a8fbf:	89 de                                           	mov    esi,ebx
  9a8fc1:	e8 ba f0 ff ff                                  	call   0x9a8080
  9a8fc6:	48 63 cb                                        	movsxd rcx,ebx
  9a8fc9:	41 8b 54 8d 00                                  	mov    edx,DWORD PTR [r13+rcx*4+0x0]
  9a8fce:	89 d1                                           	mov    ecx,edx
  9a8fd0:	81 e1 00 00 00 30                               	and    ecx,0x30000000
  9a8fd6:	89 4d c4                                        	mov    DWORD PTR [rbp-0x3c],ecx
  9a8fd9:	81 f9 00 00 00 10                               	cmp    ecx,0x10000000
  9a8fdf:	75 65                                           	jne    0x9a9046
  9a8fe1:	89 d1                                           	mov    ecx,edx
  9a8fe3:	41 0f b7 dc                                     	movzx  ebx,r12w
  9a8fe7:	49 8d 7e 18                                     	lea    rdi,[r14+0x18]
  9a8feb:	89 45 d0                                        	mov    DWORD PTR [rbp-0x30],eax
  9a8fee:	81 e1 ff ff 0f 00                               	and    ecx,0xfffff
  9a8ff4:	48 89 7d c8                                     	mov    QWORD PTR [rbp-0x38],rdi
  9a8ff8:	48 c1 e1 10                                     	shl    rcx,0x10
  9a8ffc:	48 09 cb                                        	or     rbx,rcx
  9a8fff:	49 03 5f 30                                     	add    rbx,QWORD PTR [r15+0x30]
  9a9003:	f7 c2 00 00 80 00                               	test   edx,0x800000
  9a9009:	0f 95 45 d4                                     	setne  BYTE PTR [rbp-0x2c]
  9a900d:	49 c1 fc 0e                                     	sar    r12,0xe
  9a9011:	31 f6                                           	xor    esi,esi
  9a9013:	31 d2                                           	xor    edx,edx
  9a9015:	e8 86 b6 e2 ff                                  	call   0x7d46a0
  9a901a:	4c 89 f7                                        	mov    rdi,r14
  9a901d:	4c 89 e6                                        	mov    rsi,r12
  9a9020:	e8 bb 07 1e 00                                  	call   0xb897e0
  9a9025:	4c 8d 3d 14 34 3d 03                            	lea    r15,[rip+0x33d3414]        # 0x3d7c440
  9a902c:	48 85 c0                                        	test   rax,rax
  9a902f:	74 20                                           	je     0x9a9051
  9a9031:	49 89 c5                                        	mov    r13,rax
  9a9034:	31 db                                           	xor    ebx,ebx
  9a9036:	e9 23 01 00 00                                  	jmp    0x9a915e
  9a903b:	41 bc 05 00 00 00                               	mov    r12d,0x5
  9a9041:	e9 d1 01 00 00                                  	jmp    0x9a9217
  9a9046:	41 bc 02 00 00 00                               	mov    r12d,0x2
  9a904c:	e9 73 01 00 00                                  	jmp    0x9a91c4
  9a9051:	0f b6 4d d4                                     	movzx  ecx,BYTE PTR [rbp-0x2c]
  9a9055:	31 c0                                           	xor    eax,eax
  9a9057:	48 89 5d b8                                     	mov    QWORD PTR [rbp-0x48],rbx
  9a905b:	31 db                                           	xor    ebx,ebx
  9a905d:	88 c8                                           	mov    al,cl
  9a905f:	8d 44 80 01                                     	lea    eax,[rax+rax*4+0x1]
  9a9063:	0f b6 c0                                        	movzx  eax,al
  9a9066:	89 45 d4                                        	mov    DWORD PTR [rbp-0x2c],eax
  9a9069:	4d 8b 6e 68                                     	mov    r13,QWORD PTR [r14+0x68]
  9a906d:	4d 85 ed                                        	test   r13,r13
  9a9070:	74 57                                           	je     0x9a90c9
  9a9072:	66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00       	data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  9a9080:	41 8b 45 30                                     	mov    eax,DWORD PTR [r13+0x30]
  9a9084:	31 f6                                           	xor    esi,esi
  9a9086:	31 d2                                           	xor    edx,edx
  9a9088:	31 c9                                           	xor    ecx,ecx
  9a908a:	c1 e8 0f                                        	shr    eax,0xf
  9a908d:	25 c0 3f 00 00                                  	and    eax,0x3fc0
  9a9092:	4a 8d 7c 38 18                                  	lea    rdi,[rax+r15*1+0x18]
  9a9097:	e8 64 d9 b1 ff                                  	call   0x4c6a00
  9a909c:	66 41 83 7d 60 00                               	cmp    WORD PTR [r13+0x60],0x0
  9a90a2:	74 79                                           	je     0x9a911d
  9a90a4:	41 8b 45 30                                     	mov    eax,DWORD PTR [r13+0x30]
  9a90a8:	31 f6                                           	xor    esi,esi
  9a90aa:	31 d2                                           	xor    edx,edx
  9a90ac:	31 c9                                           	xor    ecx,ecx
  9a90ae:	c1 e8 0f                                        	shr    eax,0xf
  9a90b1:	25 c0 3f 00 00                                  	and    eax,0x3fc0
  9a90b6:	4a 8d 7c 38 18                                  	lea    rdi,[rax+r15*1+0x18]
  9a90bb:	e8 e0 de b1 ff                                  	call   0x4c6fa0
  9a90c0:	4d 8b 6d 10                                     	mov    r13,QWORD PTR [r13+0x10]
  9a90c4:	4d 85 ed                                        	test   r13,r13
  9a90c7:	75 b7                                           	jne    0x9a9080
  9a90c9:	48 85 db                                        	test   rbx,rbx
  9a90cc:	0f 85 57 01 00 00                               	jne    0x9a9229
  9a90d2:	4c 8b 6d c8                                     	mov    r13,QWORD PTR [rbp-0x38]
  9a90d6:	31 f6                                           	xor    esi,esi
  9a90d8:	31 d2                                           	xor    edx,edx
  9a90da:	4c 89 ef                                        	mov    rdi,r13
  9a90dd:	e8 ce bd e2 ff                                  	call   0x7d4eb0
  9a90e2:	48 8b 7d b8                                     	mov    rdi,QWORD PTR [rbp-0x48]
  9a90e6:	8b 75 d4                                        	mov    esi,DWORD PTR [rbp-0x2c]
  9a90e9:	e8 d2 01 1e 00                                  	call   0xb892c0
  9a90ee:	4c 89 ef                                        	mov    rdi,r13
  9a90f1:	48 89 c3                                        	mov    rbx,rax
  9a90f4:	c7 40 5c 01 00 00 00                            	mov    DWORD PTR [rax+0x5c],0x1
  9a90fb:	31 f6                                           	xor    esi,esi
  9a90fd:	31 d2                                           	xor    edx,edx
  9a90ff:	e8 9c b5 e2 ff                                  	call   0x7d46a0
  9a9104:	4c 89 f7                                        	mov    rdi,r14
  9a9107:	4c 89 e6                                        	mov    rsi,r12
  9a910a:	e8 d1 06 1e 00                                  	call   0xb897e0
  9a910f:	48 85 c0                                        	test   rax,rax
  9a9112:	0f 84 51 ff ff ff                               	je     0x9a9069
  9a9118:	49 89 c5                                        	mov    r13,rax
  9a911b:	eb 41                                           	jmp    0x9a915e
  9a911d:	4c 89 ef                                        	mov    rdi,r13
  9a9120:	e8 db 04 1e 00                                  	call   0xb89600
  9a9125:	41 8b 45 30                                     	mov    eax,DWORD PTR [r13+0x30]
  9a9129:	31 f6                                           	xor    esi,esi
  9a912b:	31 d2                                           	xor    edx,edx
  9a912d:	31 c9                                           	xor    ecx,ecx
  9a912f:	c1 e8 0f                                        	shr    eax,0xf
  9a9132:	25 c0 3f 00 00                                  	and    eax,0x3fc0
  9a9137:	4a 8d 7c 38 18                                  	lea    rdi,[rax+r15*1+0x18]
  9a913c:	e8 5f de b1 ff                                  	call   0x4c6fa0
  9a9141:	48 8b 75 b8                                     	mov    rsi,QWORD PTR [rbp-0x48]
  9a9145:	8b 55 d4                                        	mov    edx,DWORD PTR [rbp-0x2c]
  9a9148:	4c 89 ef                                        	mov    rdi,r13
  9a914b:	e8 00 02 1e 00                                  	call   0xb89350
  9a9150:	4c 89 ef                                        	mov    rdi,r13
  9a9153:	4c 89 f6                                        	mov    rsi,r14
  9a9156:	4c 89 e2                                        	mov    rdx,r12
  9a9159:	e8 22 04 1e 00                                  	call   0xb89580
  9a915e:	41 8b 45 30                                     	mov    eax,DWORD PTR [r13+0x30]
  9a9162:	4c 8b 65 c8                                     	mov    r12,QWORD PTR [rbp-0x38]
  9a9166:	31 f6                                           	xor    esi,esi
  9a9168:	31 d2                                           	xor    edx,edx
  9a916a:	31 c9                                           	xor    ecx,ecx
  9a916c:	c1 e8 0f                                        	shr    eax,0xf
  9a916f:	25 c0 3f 00 00                                  	and    eax,0x3fc0
  9a9174:	4a 8d 7c 38 18                                  	lea    rdi,[rax+r15*1+0x18]
  9a9179:	e8 82 d8 b1 ff                                  	call   0x4c6a00
  9a917e:	4c 89 ef                                        	mov    rdi,r13
  9a9181:	e8 aa fd 1d 00                                  	call   0xb88f30
  9a9186:	41 8b 45 30                                     	mov    eax,DWORD PTR [r13+0x30]
  9a918a:	31 f6                                           	xor    esi,esi
  9a918c:	31 d2                                           	xor    edx,edx
  9a918e:	31 c9                                           	xor    ecx,ecx
  9a9190:	c1 e8 0f                                        	shr    eax,0xf
  9a9193:	25 c0 3f 00 00                                  	and    eax,0x3fc0
  9a9198:	4a 8d 7c 38 18                                  	lea    rdi,[rax+r15*1+0x18]
  9a919d:	e8 fe dd b1 ff                                  	call   0x4c6fa0
  9a91a2:	4c 89 e7                                        	mov    rdi,r12
  9a91a5:	31 f6                                           	xor    esi,esi
  9a91a7:	31 d2                                           	xor    edx,edx
  9a91a9:	e8 02 bd e2 ff                                  	call   0x7d4eb0
  9a91ae:	41 bc 00 00 00 00                               	mov    r12d,0x0
  9a91b4:	48 85 db                                        	test   rbx,rbx
  9a91b7:	74 08                                           	je     0x9a91c1
  9a91b9:	48 89 df                                        	mov    rdi,rbx
  9a91bc:	e8 6f 01 1e 00                                  	call   0xb89330
  9a91c1:	8b 45 d0                                        	mov    eax,DWORD PTR [rbp-0x30]
  9a91c4:	49 8d 5e 18                                     	lea    rbx,[r14+0x18]
  9a91c8:	89 c0                                           	mov    eax,eax
  9a91ca:	31 f6                                           	xor    esi,esi
  9a91cc:	31 d2                                           	xor    edx,edx
  9a91ce:	48 89 df                                        	mov    rdi,rbx
  9a91d1:	4c 8d 3c 40                                     	lea    r15,[rax+rax*2]
  9a91d5:	e8 c6 b4 e2 ff                                  	call   0x7d46a0
  9a91da:	43 c7 84 be 68 01 00 00 ff ff ff ff             	mov    DWORD PTR [r14+r15*4+0x168],0xffffffff
  9a91e6:	43 83 bc be 70 01 00 00 00                      	cmp    DWORD PTR [r14+r15*4+0x170],0x0
  9a91ef:	75 42                                           	jne    0x9a9233
  9a91f1:	41 83 be 98 01 00 00 00                         	cmp    DWORD PTR [r14+0x198],0x0
  9a91f9:	75 55                                           	jne    0x9a9250
  9a91fb:	48 89 df                                        	mov    rdi,rbx
  9a91fe:	31 f6                                           	xor    esi,esi
  9a9200:	31 d2                                           	xor    edx,edx
  9a9202:	e8 a9 bc e2 ff                                  	call   0x7d4eb0
  9a9207:	81 7d c4 00 00 00 10                            	cmp    DWORD PTR [rbp-0x3c],0x10000000
  9a920e:	75 07                                           	jne    0x9a9217
  9a9210:	48 8b 45 b0                                     	mov    rax,QWORD PTR [rbp-0x50]
  9a9214:	4c 89 28                                        	mov    QWORD PTR [rax],r13
  9a9217:	44 89 e0                                        	mov    eax,r12d
  9a921a:	48 83 c4 28                                     	add    rsp,0x28
  9a921e:	5b                                              	pop    rbx
  9a921f:	41 5c                                           	pop    r12
  9a9221:	41 5d                                           	pop    r13
  9a9223:	41 5e                                           	pop    r14
  9a9225:	41 5f                                           	pop    r15
  9a9227:	5d                                              	pop    rbp
  9a9228:	c3                                              	ret
  9a9229:	49 89 dd                                        	mov    r13,rbx
  9a922c:	31 db                                           	xor    ebx,ebx
  9a922e:	e9 1d ff ff ff                                  	jmp    0x9a9150
  9a9233:	4b 8d bc be 70 01 00 00                         	lea    rdi,[r14+r15*4+0x170]
  9a923b:	c7 07 00 00 00 00                               	mov    DWORD PTR [rdi],0x0
  9a9241:	e8 ca d6 25 00                                  	call   0xc06910
  9a9246:	41 83 be 98 01 00 00 00                         	cmp    DWORD PTR [r14+0x198],0x0
  9a924e:	74 ab                                           	je     0x9a91fb
  9a9250:	49 81 c6 98 01 00 00                            	add    r14,0x198
  9a9257:	4c 89 f7                                        	mov    rdi,r14
  9a925a:	41 c7 06 00 00 00 00                            	mov    DWORD PTR [r14],0x0
  9a9261:	e8 aa d6 25 00                                  	call   0xc06910
  9a9266:	eb 93                                           	jmp    0x9a91fb
  9a9268:	90                                              	nop
  9a9269:	90                                              	nop
  9a926a:	90                                              	nop
  9a926b:	90                                              	nop
  9a926c:	90                                              	nop
  9a926d:	90                                              	nop
  9a926e:	90                                              	nop
  9a926f:	90                                              	nop
  9a9270:	55                                              	push   rbp
  9a9271:	48 89 e5                                        	mov    rbp,rsp
  9a9274:	41 57                                           	push   r15
  9a9276:	41 56                                           	push   r14
  9a9278:	41 55                                           	push   r13
  9a927a:	41 54                                           	push   r12
  9a927c:	53                                              	push   rbx
  9a927d:	48 83 ec 48                                     	sub    rsp,0x48
  9a9281:	48 8d 05 88 30 f7 02                            	lea    rax,[rip+0x2f73088]        # 0x391c310
  9a9288:	4c 89 4d 90                                     	mov    QWORD PTR [rbp-0x70],r9
  9a928c:	4c 89 45 98                                     	mov    QWORD PTR [rbp-0x68],r8
  9a9290:	48 89 55 a0                                     	mov    QWORD PTR [rbp-0x60],rdx
  9a9294:	48 89 d3                                        	mov    rbx,rdx
  9a9297:	49 89 ff                                        	mov    r15,rdi
  9a929a:	48 89 f7                                        	mov    rdi,rsi
  9a929d:	49 89 cc                                        	mov    r12,rcx
  9a92a0:	49 89 f5                                        	mov    r13,rsi
  9a92a3:	45 31 f6                                        	xor    r14d,r14d
  9a92a6:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  9a92a9:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  9a92ad:	48 8b 96 88 00 00 00                            	mov    rdx,QWORD PTR [rsi+0x88]
  9a92b4:	31 f6                                           	xor    esi,esi
  9a92b6:	48 c1 ea 02                                     	shr    rdx,0x2
  9a92ba:	e8 c1 ed ff ff                                  	call   0x9a8080
  9a92bf:	4c 8b 45 20                                     	mov    r8,QWORD PTR [rbp+0x20]
  9a92c3:	4c 89 e6                                        	mov    rsi,r12
  9a92c6:	49 29 dc                                        	sub    r12,rbx
  9a92c9:	49 8b 9d 88 00 00 00                            	mov    rbx,QWORD PTR [r13+0x88]
  9a92d0:	4c 89 6d b0                                     	mov    QWORD PTR [rbp-0x50],r13
  9a92d4:	4d 8b ad 60 01 00 00                            	mov    r13,QWORD PTR [r13+0x160]
  9a92db:	48 8d 55 c8                                     	lea    rdx,[rbp-0x38]
  9a92df:	48 8d 4d c0                                     	lea    rcx,[rbp-0x40]
  9a92e3:	4c 89 ff                                        	mov    rdi,r15
  9a92e6:	89 45 bc                                        	mov    DWORD PTR [rbp-0x44],eax
  9a92e9:	4c 89 7d a8                                     	mov    QWORD PTR [rbp-0x58],r15
  9a92ed:	49 c1 ec 10                                     	shr    r12,0x10
  9a92f1:	e8 aa dd 91 ff                                  	call   0x2c70a0
  9a92f6:	4c 8b 45 a0                                     	mov    r8,QWORD PTR [rbp-0x60]
  9a92fa:	48 8b 45 c8                                     	mov    rax,QWORD PTR [rbp-0x38]
  9a92fe:	49 63 d4                                        	movsxd rdx,r12d
  9a9301:	45 8b 7c 95 00                                  	mov    r15d,DWORD PTR [r13+rdx*4+0x0]
  9a9306:	4c 29 c0                                        	sub    rax,r8
  9a9309:	4c 0f 43 f0                                     	cmovae r14,rax
  9a930d:	48 8b 45 c0                                     	mov    rax,QWORD PTR [rbp-0x40]
  9a9311:	48 c1 eb 02                                     	shr    rbx,0x2
  9a9315:	48 63 cb                                        	movsxd rcx,ebx
  9a9318:	49 c1 ee 10                                     	shr    r14,0x10
  9a931c:	49 63 f6                                        	movsxd rsi,r14d
  9a931f:	4c 29 c0                                        	sub    rax,r8
  9a9322:	48 c1 e8 10                                     	shr    rax,0x10
  9a9326:	48 39 c1                                        	cmp    rcx,rax
  9a9329:	48 0f 42 c1                                     	cmovb  rax,rcx
  9a932d:	44 39 f2                                        	cmp    edx,r14d
  9a9330:	41 8d 4c 24 01                                  	lea    ecx,[r12+0x1]
  9a9335:	45 0f 4c f4                                     	cmovl  r14d,r12d
  9a9339:	41 f7 c7 00 00 00 30                            	test   r15d,0x30000000
  9a9340:	74 2a                                           	je     0x9a936c
  9a9342:	48 8b 5d b0                                     	mov    rbx,QWORD PTR [rbp-0x50]
  9a9346:	66 2e 0f 1f 84 00 00 00 00 00                   	cs nop WORD PTR [rax+rax*1+0x0]
  9a9350:	48 39 f2                                        	cmp    rdx,rsi
  9a9353:	7e 30                                           	jle    0x9a9385
  9a9355:	41 8b 7c 95 fc                                  	mov    edi,DWORD PTR [r13+rdx*4-0x4]
  9a935a:	48 ff ca                                        	dec    rdx
  9a935d:	ff c9                                           	dec    ecx
  9a935f:	44 31 ff                                        	xor    edi,r15d
  9a9362:	f7 c7 00 00 f0 3f                               	test   edi,0x3ff00000
  9a9368:	74 e6                                           	je     0x9a9350
  9a936a:	eb 1c                                           	jmp    0x9a9388
  9a936c:	48 8b 5d b0                                     	mov    rbx,QWORD PTR [rbp-0x50]
  9a9370:	48 39 f2                                        	cmp    rdx,rsi
  9a9373:	7e 48                                           	jle    0x9a93bd
  9a9375:	ff c9                                           	dec    ecx
  9a9377:	41 f6 44 95 ff 30                               	test   BYTE PTR [r13+rdx*4-0x1],0x30
  9a937d:	48 8d 52 ff                                     	lea    rdx,[rdx-0x1]
  9a9381:	74 ed                                           	je     0x9a9370
  9a9383:	eb 3b                                           	jmp    0x9a93c0
  9a9385:	44 89 f1                                        	mov    ecx,r14d
  9a9388:	41 8d 54 24 01                                  	lea    edx,[r12+0x1]
  9a938d:	39 c2                                           	cmp    edx,eax
  9a938f:	0f 4e d0                                        	cmovle edx,eax
  9a9392:	66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00       	data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  9a93a0:	41 ff c4                                        	inc    r12d
  9a93a3:	41 39 c4                                        	cmp    r12d,eax
  9a93a6:	7d 3e                                           	jge    0x9a93e6
  9a93a8:	49 63 f4                                        	movsxd rsi,r12d
  9a93ab:	41 8b 74 b5 00                                  	mov    esi,DWORD PTR [r13+rsi*4+0x0]
  9a93b0:	44 31 fe                                        	xor    esi,r15d
  9a93b3:	f7 c6 00 00 f0 3f                               	test   esi,0x3ff00000
  9a93b9:	74 e5                                           	je     0x9a93a0
  9a93bb:	eb 26                                           	jmp    0x9a93e3
  9a93bd:	44 89 f1                                        	mov    ecx,r14d
  9a93c0:	41 8d 54 24 01                                  	lea    edx,[r12+0x1]
  9a93c5:	39 c2                                           	cmp    edx,eax
  9a93c7:	0f 4e d0                                        	cmovle edx,eax
  9a93ca:	66 0f 1f 44 00 00                               	nop    WORD PTR [rax+rax*1+0x0]
  9a93d0:	41 ff c4                                        	inc    r12d
  9a93d3:	41 39 c4                                        	cmp    r12d,eax
  9a93d6:	7d 0e                                           	jge    0x9a93e6
  9a93d8:	49 63 f4                                        	movsxd rsi,r12d
  9a93db:	41 f6 44 b5 03 30                               	test   BYTE PTR [r13+rsi*4+0x3],0x30
  9a93e1:	74 ed                                           	je     0x9a93d0
  9a93e3:	44 89 e2                                        	mov    edx,r12d
  9a93e6:	83 7d 28 00                                     	cmp    DWORD PTR [rbp+0x28],0x0
  9a93ea:	48 8b 45 10                                     	mov    rax,QWORD PTR [rbp+0x10]
  9a93ee:	74 10                                           	je     0x9a9400
  9a93f0:	48 63 c9                                        	movsxd rcx,ecx
  9a93f3:	48 63 d2                                        	movsxd rdx,edx
  9a93f6:	48 c1 e1 10                                     	shl    rcx,0x10
  9a93fa:	48 c1 e2 10                                     	shl    rdx,0x10
  9a93fe:	eb 0c                                           	jmp    0x9a940c
  9a9400:	c1 e1 10                                        	shl    ecx,0x10
  9a9403:	c1 e2 10                                        	shl    edx,0x10
  9a9406:	48 63 c9                                        	movsxd rcx,ecx
  9a9409:	48 63 d2                                        	movsxd rdx,edx
  9a940c:	4c 01 c1                                        	add    rcx,r8
  9a940f:	be 18 01 00 00                                  	mov    esi,0x118
  9a9414:	4c 01 c2                                        	add    rdx,r8
  9a9417:	bf 03 00 00 00                                  	mov    edi,0x3
  9a941c:	45 89 f9                                        	mov    r9d,r15d
  9a941f:	4c 8b 45 98                                     	mov    r8,QWORD PTR [rbp-0x68]
  9a9423:	c4 c2 48 f7 f7                                  	bextr  esi,r15d,esi
  9a9428:	41 f7 c7 00 00 00 02                            	test   r15d,0x2000000
  9a942f:	0f 44 fe                                        	cmove  edi,esi
  9a9432:	41 c1 e9 16                                     	shr    r9d,0x16
  9a9436:	41 83 e1 30                                     	and    r9d,0x30
  9a943a:	41 09 f9                                        	or     r9d,edi
  9a943d:	48 8b 7d 90                                     	mov    rdi,QWORD PTR [rbp-0x70]
  9a9441:	49 89 08                                        	mov    QWORD PTR [r8],rcx
  9a9444:	48 89 17                                        	mov    QWORD PTR [rdi],rdx
  9a9447:	44 89 08                                        	mov    DWORD PTR [rax],r9d
  9a944a:	41 f7 c7 00 00 00 30                            	test   r15d,0x30000000
  9a9451:	74 53                                           	je     0x9a94a6
  9a9453:	48 8b 4d a8                                     	mov    rcx,QWORD PTR [rbp-0x58]
  9a9457:	48 8b 45 18                                     	mov    rax,QWORD PTR [rbp+0x18]
  9a945b:	f6 81 44 02 00 00 02                            	test   BYTE PTR [rcx+0x244],0x2
  9a9462:	75 1d                                           	jne    0x9a9481
  9a9464:	b9 14 04 00 00                                  	mov    ecx,0x414
  9a9469:	c4 c2 70 f7 d7                                  	bextr  edx,r15d,ecx
  9a946e:	31 c9                                           	xor    ecx,ecx
  9a9470:	83 fa 0f                                        	cmp    edx,0xf
  9a9473:	74 2f                                           	je     0x9a94a4
  9a9475:	48 8d 0d d4 46 f2 00                            	lea    rcx,[rip+0xf246d4]        # 0x18cdb50
  9a947c:	8b 0c 91                                        	mov    ecx,DWORD PTR [rcx+rdx*4]
  9a947f:	eb 23                                           	jmp    0x9a94a4
  9a9481:	44 89 f9                                        	mov    ecx,r15d
  9a9484:	31 d2                                           	xor    edx,edx
  9a9486:	be 0a 00 00 00                                  	mov    esi,0xa
  9a948b:	81 e1 00 00 f0 00                               	and    ecx,0xf00000
  9a9491:	81 f9 00 00 80 00                               	cmp    ecx,0x800000
  9a9497:	0f 45 f2                                        	cmovne esi,edx
  9a949a:	85 c9                                           	test   ecx,ecx
  9a949c:	b9 03 00 00 00                                  	mov    ecx,0x3
  9a94a1:	0f 45 ce                                        	cmovne ecx,esi
  9a94a4:	89 08                                           	mov    DWORD PTR [rax],ecx
  9a94a6:	8b 45 bc                                        	mov    eax,DWORD PTR [rbp-0x44]
  9a94a9:	4c 8d 73 18                                     	lea    r14,[rbx+0x18]
  9a94ad:	31 f6                                           	xor    esi,esi
  9a94af:	31 d2                                           	xor    edx,edx
  9a94b1:	4c 89 f7                                        	mov    rdi,r14
  9a94b4:	4c 8d 24 40                                     	lea    r12,[rax+rax*2]
  9a94b8:	e8 e3 b1 e2 ff                                  	call   0x7d46a0
  9a94bd:	42 c7 84 a3 68 01 00 00 ff ff ff ff             	mov    DWORD PTR [rbx+r12*4+0x168],0xffffffff
  9a94c9:	42 83 bc a3 70 01 00 00 00                      	cmp    DWORD PTR [rbx+r12*4+0x170],0x0
  9a94d2:	75 46                                           	jne    0x9a951a
  9a94d4:	83 bb 98 01 00 00 00                            	cmp    DWORD PTR [rbx+0x198],0x0
  9a94db:	75 59                                           	jne    0x9a9536
  9a94dd:	31 db                                           	xor    ebx,ebx
  9a94df:	41 f7 c7 00 00 00 30                            	test   r15d,0x30000000
  9a94e6:	4c 89 f7                                        	mov    rdi,r14
  9a94e9:	41 0f 95 c7                                     	setne  r15b
  9a94ed:	31 f6                                           	xor    esi,esi
  9a94ef:	31 d2                                           	xor    edx,edx
  9a94f1:	e8 ba b9 e2 ff                                  	call   0x7d4eb0
  9a94f6:	48 8d 05 13 2e f7 02                            	lea    rax,[rip+0x2f72e13]        # 0x391c310
  9a94fd:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  9a9500:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  9a9504:	75 47                                           	jne    0x9a954d
  9a9506:	44 88 fb                                        	mov    bl,r15b
  9a9509:	89 d8                                           	mov    eax,ebx
  9a950b:	48 83 c4 48                                     	add    rsp,0x48
  9a950f:	5b                                              	pop    rbx
  9a9510:	41 5c                                           	pop    r12
  9a9512:	41 5d                                           	pop    r13
  9a9514:	41 5e                                           	pop    r14
  9a9516:	41 5f                                           	pop    r15
  9a9518:	5d                                              	pop    rbp
  9a9519:	c3                                              	ret
  9a951a:	4a 8d bc a3 70 01 00 00                         	lea    rdi,[rbx+r12*4+0x170]
  9a9522:	c7 07 00 00 00 00                               	mov    DWORD PTR [rdi],0x0
  9a9528:	e8 e3 d3 25 00                                  	call   0xc06910
  9a952d:	83 bb 98 01 00 00 00                            	cmp    DWORD PTR [rbx+0x198],0x0
  9a9534:	74 a7                                           	je     0x9a94dd
  9a9536:	48 81 c3 98 01 00 00                            	add    rbx,0x198
  9a953d:	48 89 df                                        	mov    rdi,rbx
  9a9540:	c7 03 00 00 00 00                               	mov    DWORD PTR [rbx],0x0
  9a9546:	e8 c5 d3 25 00                                  	call   0xc06910
  9a954b:	eb 90                                           	jmp    0x9a94dd
  9a954d:	e8 5e 41 d5 ff                                  	call   0x6fd6b0
  9a9552:	0f 0b                                           	ud2
  9a9554:	90                                              	nop
  9a9555:	90                                              	nop
  9a9556:	90                                              	nop
  9a9557:	90                                              	nop
  9a9558:	90                                              	nop
  9a9559:	90                                              	nop
  9a955a:	90                                              	nop
  9a955b:	90                                              	nop
  9a955c:	90                                              	nop
  9a955d:	90                                              	nop
  9a955e:	90                                              	nop
  9a955f:	90                                              	nop
  9a9560:	55                                              	push   rbp
  9a9561:	48 89 e5                                        	mov    rbp,rsp
  9a9564:	41 57                                           	push   r15
  9a9566:	41 56                                           	push   r14
  9a9568:	41 55                                           	push   r13
  9a956a:	41 54                                           	push   r12
  9a956c:	53                                              	push   rbx
  9a956d:	48 83 ec 28                                     	sub    rsp,0x28
  9a9571:	4c 8d 3d 98 2d f7 02                            	lea    r15,[rip+0x2f72d98]        # 0x391c310
  9a9578:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  9a957b:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  9a957f:	48 8b 47 08                                     	mov    rax,QWORD PTR [rdi+0x8]
  9a9583:	4c 8b 36                                        	mov    r14,QWORD PTR [rsi]
  9a9586:	48 8b 98 00 02 00 00                            	mov    rbx,QWORD PTR [rax+0x200]
  9a958d:	b8 16 00 00 00                                  	mov    eax,0x16
  9a9592:	4c 39 73 20                                     	cmp    QWORD PTR [rbx+0x20],r14
  9a9596:	76 1c                                           	jbe    0x9a95b4
  9a9598:	49 8b 0f                                        	mov    rcx,QWORD PTR [r15]
  9a959b:	48 3b 4d d0                                     	cmp    rcx,QWORD PTR [rbp-0x30]
  9a959f:	0f 85 df 01 00 00                               	jne    0x9a9784
  9a95a5:	48 83 c4 28                                     	add    rsp,0x28
  9a95a9:	5b                                              	pop    rbx
  9a95aa:	41 5c                                           	pop    r12
  9a95ac:	41 5d                                           	pop    r13
  9a95ae:	41 5e                                           	pop    r14
  9a95b0:	41 5f                                           	pop    r15
  9a95b2:	5d                                              	pop    rbp
  9a95b3:	c3                                              	ret
  9a95b4:	66 45 85 f6                                     	test   r14w,r14w
  9a95b8:	75 de                                           	jne    0x9a9598
  9a95ba:	48 8b 4b 28                                     	mov    rcx,QWORD PTR [rbx+0x28]
  9a95be:	4c 39 f1                                        	cmp    rcx,r14
  9a95c1:	76 d5                                           	jbe    0x9a9598
  9a95c3:	4c 8b 46 08                                     	mov    r8,QWORD PTR [rsi+0x8]
  9a95c7:	41 0f b7 d0                                     	movzx  edx,r8w
  9a95cb:	48 85 d2                                        	test   rdx,rdx
  9a95ce:	75 c8                                           	jne    0x9a9598
  9a95d0:	4c 29 f1                                        	sub    rcx,r14
  9a95d3:	4c 39 c1                                        	cmp    rcx,r8
  9a95d6:	72 c0                                           	jb     0x9a9598
  9a95d8:	44 8b 6e 10                                     	mov    r13d,DWORD PTR [rsi+0x10]
  9a95dc:	44 8b 4e 18                                     	mov    r9d,DWORD PTR [rsi+0x18]
  9a95e0:	44 8b 66 20                                     	mov    r12d,DWORD PTR [rsi+0x20]
  9a95e4:	0f b6 8b 44 02 00 00                            	movzx  ecx,BYTE PTR [rbx+0x244]
  9a95eb:	41 83 fd 0a                                     	cmp    r13d,0xa
  9a95ef:	77 4b                                           	ja     0x9a963c
  9a95f1:	ba 09 04 00 00                                  	mov    edx,0x409
  9a95f6:	44 0f a3 ea                                     	bt     edx,r13d
  9a95fa:	73 40                                           	jae    0x9a963c
  9a95fc:	f6 c1 02                                        	test   cl,0x2
  9a95ff:	75 51                                           	jne    0x9a9652
  9a9601:	48 89 7d c0                                     	mov    QWORD PTR [rbp-0x40],rdi
  9a9605:	44 89 ef                                        	mov    edi,r13d
  9a9608:	4d 89 c5                                        	mov    r13,r8
  9a960b:	45 89 cf                                        	mov    r15d,r9d
  9a960e:	e8 fd 35 00 00                                  	call   0x9acc10
  9a9613:	45 89 f9                                        	mov    r9d,r15d
  9a9616:	89 c1                                           	mov    ecx,eax
  9a9618:	48 8b 7d c0                                     	mov    rdi,QWORD PTR [rbp-0x40]
  9a961c:	4c 8d 3d ed 2c f7 02                            	lea    r15,[rip+0x2f72ced]        # 0x391c310
  9a9623:	31 d2                                           	xor    edx,edx
  9a9625:	4d 89 e8                                        	mov    r8,r13
  9a9628:	b8 16 00 00 00                                  	mov    eax,0x16
  9a962d:	85 c9                                           	test   ecx,ecx
  9a962f:	0f 94 c2                                        	sete   dl
  9a9632:	44 8d 2c 95 0f 00 00 00                         	lea    r13d,[rdx*4+0xf]
  9a963a:	eb 16                                           	jmp    0x9a9652
  9a963c:	41 8d 55 eb                                     	lea    edx,[r13-0x15]
  9a9640:	83 fa f6                                        	cmp    edx,0xfffffff6
  9a9643:	0f 82 4f ff ff ff                               	jb     0x9a9598
  9a9649:	80 e1 02                                        	and    cl,0x2
  9a964c:	0f 85 46 ff ff ff                               	jne    0x9a9598
  9a9652:	44 89 c9                                        	mov    ecx,r9d
  9a9655:	83 e1 cc                                        	and    ecx,0xffffffcc
  9a9658:	44 09 e1                                        	or     ecx,r12d
  9a965b:	0f 85 37 ff ff ff                               	jne    0x9a9598
  9a9661:	41 83 fd 0a                                     	cmp    r13d,0xa
  9a9665:	0f 95 c0                                        	setne  al
  9a9668:	41 f6 c1 22                                     	test   r9b,0x22
  9a966c:	0f 94 c1                                        	sete   cl
  9a966f:	08 c1                                           	or     cl,al
  9a9671:	b8 0d 00 00 00                                  	mov    eax,0xd
  9a9676:	80 f9 01                                        	cmp    cl,0x1
  9a9679:	0f 85 19 ff ff ff                               	jne    0x9a9598
  9a967f:	48 89 7d c0                                     	mov    QWORD PTR [rbp-0x40],rdi
  9a9683:	48 89 df                                        	mov    rdi,rbx
  9a9686:	44 89 4d bc                                     	mov    DWORD PTR [rbp-0x44],r9d
  9a968a:	4d 89 c4                                        	mov    r12,r8
  9a968d:	31 f6                                           	xor    esi,esi
  9a968f:	31 d2                                           	xor    edx,edx
  9a9691:	e8 8a d1 91 ff                                  	call   0x2c6820
  9a9696:	48 8d 55 c8                                     	lea    rdx,[rbp-0x38]
  9a969a:	48 89 df                                        	mov    rdi,rbx
  9a969d:	4c 89 f6                                        	mov    rsi,r14
  9a96a0:	e8 9b d5 91 ff                                  	call   0x2c6c40
  9a96a5:	89 c1                                           	mov    ecx,eax
  9a96a7:	b8 16 00 00 00                                  	mov    eax,0x16
  9a96ac:	85 c9                                           	test   ecx,ecx
  9a96ae:	0f 84 bb 00 00 00                               	je     0x9a976f
  9a96b4:	48 8b 4d c8                                     	mov    rcx,QWORD PTR [rbp-0x38]
  9a96b8:	f6 41 60 02                                     	test   BYTE PTR [rcx+0x60],0x2
  9a96bc:	0f 85 ad 00 00 00                               	jne    0x9a976f
  9a96c2:	48 8b 71 50                                     	mov    rsi,QWORD PTR [rcx+0x50]
  9a96c6:	48 85 f6                                        	test   rsi,rsi
  9a96c9:	0f 84 a0 00 00 00                               	je     0x9a976f
  9a96cf:	80 be 9d 00 00 00 0b                            	cmp    BYTE PTR [rsi+0x9d],0xb
  9a96d6:	0f 85 93 00 00 00                               	jne    0x9a976f
  9a96dc:	48 8b 51 28                                     	mov    rdx,QWORD PTR [rcx+0x28]
  9a96e0:	4c 29 f2                                        	sub    rdx,r14
  9a96e3:	4c 39 e2                                        	cmp    rdx,r12
  9a96e6:	0f 82 83 00 00 00                               	jb     0x9a976f
  9a96ec:	4d 89 e0                                        	mov    r8,r12
  9a96ef:	4d 85 e4                                        	test   r12,r12
  9a96f2:	74 79                                           	je     0x9a976d
  9a96f4:	48 8b 51 20                                     	mov    rdx,QWORD PTR [rcx+0x20]
  9a96f8:	f0 83 83 c4 01 00 00 01                         	lock add DWORD PTR [rbx+0x1c4],0x1
  9a9700:	49 c1 e8 10                                     	shr    r8,0x10
  9a9704:	48 89 df                                        	mov    rdi,rbx
  9a9707:	44 89 2c 24                                     	mov    DWORD PTR [rsp],r13d
  9a970b:	44 8b 4d bc                                     	mov    r9d,DWORD PTR [rbp-0x44]
  9a970f:	49 29 d6                                        	sub    r14,rdx
  9a9712:	49 c1 ee 10                                     	shr    r14,0x10
  9a9716:	44 89 f1                                        	mov    ecx,r14d
  9a9719:	45 01 f0                                        	add    r8d,r14d
  9a971c:	e8 7f 00 00 00                                  	call   0x9a97a0
  9a9721:	48 8b 4d c0                                     	mov    rcx,QWORD PTR [rbp-0x40]
  9a9725:	80 b9 17 01 00 00 00                            	cmp    BYTE PTR [rcx+0x117],0x0
  9a972c:	74 41                                           	je     0x9a976f
  9a972e:	c6 81 17 01 00 00 00                            	mov    BYTE PTR [rcx+0x117],0x0
  9a9735:	48 8d 0d ac cb 0e 01                            	lea    rcx,[rip+0x10ecbac]        # 0x1a962e8
  9a973c:	4d 89 fc                                        	mov    r12,r15
  9a973f:	41 89 c7                                        	mov    r15d,eax
  9a9742:	48 8b 01                                        	mov    rax,QWORD PTR [rcx]
  9a9745:	4c 8b 70 40                                     	mov    r14,QWORD PTR [rax+0x40]
  9a9749:	48 8d 05 98 75 8b ff                            	lea    rax,[rip+0xffffffffff8b7598]        # 0x260ce8
  9a9750:	4c 29 f0                                        	sub    rax,r14
  9a9753:	48 c1 c8 03                                     	ror    rax,0x3
  9a9757:	48 3d ff 06 00 00                               	cmp    rax,0x6ff
  9a975d:	77 2c                                           	ja     0x9a978b
  9a975f:	48 89 df                                        	mov    rdi,rbx
  9a9762:	41 ff d6                                        	call   r14
  9a9765:	44 89 f8                                        	mov    eax,r15d
  9a9768:	4d 89 e7                                        	mov    r15,r12
  9a976b:	eb 02                                           	jmp    0x9a976f
  9a976d:	31 c0                                           	xor    eax,eax
  9a976f:	48 89 df                                        	mov    rdi,rbx
  9a9772:	31 f6                                           	xor    esi,esi
  9a9774:	31 d2                                           	xor    edx,edx
  9a9776:	89 c3                                           	mov    ebx,eax
  9a9778:	e8 f3 d0 91 ff                                  	call   0x2c6870
  9a977d:	89 d8                                           	mov    eax,ebx
  9a977f:	e9 14 fe ff ff                                  	jmp    0x9a9598
  9a9784:	e8 27 3f d5 ff                                  	call   0x6fd6b0
  9a9789:	0f 0b                                           	ud2
  9a978b:	48 8d 3d ce 66 bb 01                            	lea    rdi,[rip+0x1bb66ce]        # 0x255fe60
  9a9792:	4c 89 f6                                        	mov    rsi,r14
  9a9795:	e8 26 61 aa ff                                  	call   0x44f8c0
  9a979a:	eb c3                                           	jmp    0x9a975f
  9a979c:	90                                              	nop
  9a979d:	90                                              	nop
  9a979e:	90                                              	nop
  9a979f:	90                                              	nop
  9a97a0:	55                                              	push   rbp
  9a97a1:	48 89 e5                                        	mov    rbp,rsp
  9a97a4:	41 57                                           	push   r15
  9a97a6:	41 56                                           	push   r14
  9a97a8:	41 55                                           	push   r13
  9a97aa:	41 54                                           	push   r12
  9a97ac:	53                                              	push   rbx
  9a97ad:	48 81 ec 38 01 00 00                            	sub    rsp,0x138
  9a97b4:	4c 8d 3d 55 2b f7 02                            	lea    r15,[rip+0x2f72b55]        # 0x391c310
  9a97bb:	48 89 95 e8 fe ff ff                            	mov    QWORD PTR [rbp-0x118],rdx
  9a97c2:	89 cb                                           	mov    ebx,ecx
  9a97c4:	8b 4d 10                                        	mov    ecx,DWORD PTR [rbp+0x10]
  9a97c7:	49 89 f4                                        	mov    r12,rsi
  9a97ca:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  9a97cd:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  9a97d1:	48 89 bd 20 ff ff ff                            	mov    QWORD PTR [rbp-0xe0],rdi
  9a97d8:	0f b6 87 44 02 00 00                            	movzx  eax,BYTE PTR [rdi+0x244]
  9a97df:	a8 02                                           	test   al,0x2
  9a97e1:	75 18                                           	jne    0x9a97fb
  9a97e3:	83 c1 f5                                        	add    ecx,0xfffffff5
  9a97e6:	31 f6                                           	xor    esi,esi
  9a97e8:	83 f9 09                                        	cmp    ecx,0x9
  9a97eb:	77 23                                           	ja     0x9a9810
  9a97ed:	89 c9                                           	mov    ecx,ecx
  9a97ef:	48 8d 15 96 43 f2 00                            	lea    rdx,[rip+0xf24396]        # 0x18cdb8c
  9a97f6:	8b 34 8a                                        	mov    esi,DWORD PTR [rdx+rcx*4]
  9a97f9:	eb 15                                           	jmp    0x9a9810
  9a97fb:	31 d2                                           	xor    edx,edx
  9a97fd:	83 f9 0a                                        	cmp    ecx,0xa
  9a9800:	be 00 00 c0 00                                  	mov    esi,0xc00000
  9a9805:	0f 94 c2                                        	sete   dl
  9a9808:	c1 e2 17                                        	shl    edx,0x17
  9a980b:	85 c9                                           	test   ecx,ecx
  9a980d:	0f 45 f2                                        	cmovne esi,edx
  9a9810:	44 89 c9                                        	mov    ecx,r9d
  9a9813:	44 89 8d 38 ff ff ff                            	mov    DWORD PTR [rbp-0xc8],r9d
  9a981a:	83 e1 30                                        	and    ecx,0x30
  9a981d:	89 8d 44 ff ff ff                               	mov    DWORD PTR [rbp-0xbc],ecx
  9a9823:	89 f1                                           	mov    ecx,esi
  9a9825:	81 e1 00 00 80 00                               	and    ecx,0x800000
  9a982b:	89 ca                                           	mov    edx,ecx
  9a982d:	c1 ea 17                                        	shr    edx,0x17
  9a9830:	89 95 28 ff ff ff                               	mov    DWORD PTR [rbp-0xd8],edx
  9a9836:	89 95 2c ff ff ff                               	mov    DWORD PTR [rbp-0xd4],edx
  9a983c:	a8 02                                           	test   al,0x2
  9a983e:	74 21                                           	je     0x9a9861
  9a9840:	85 c9                                           	test   ecx,ecx
  9a9842:	89 f1                                           	mov    ecx,esi
  9a9844:	0f 95 c0                                        	setne  al
  9a9847:	81 e1 00 00 f0 00                               	and    ecx,0xf00000
  9a984d:	81 f9 00 00 80 00                               	cmp    ecx,0x800000
  9a9853:	0f 95 c1                                        	setne  cl
  9a9856:	20 c1                                           	and    cl,al
  9a9858:	0f b6 c1                                        	movzx  eax,cl
  9a985b:	89 85 2c ff ff ff                               	mov    DWORD PTR [rbp-0xd4],eax
  9a9861:	49 8b 84 24 e8 00 00 00                         	mov    rax,QWORD PTR [r12+0xe8]
  9a9869:	c1 a5 44 ff ff ff 16                            	shl    DWORD PTR [rbp-0xbc],0x16
  9a9870:	4d 8b b4 24 60 01 00 00                         	mov    r14,QWORD PTR [r12+0x160]
  9a9878:	41 89 f5                                        	mov    r13d,esi
  9a987b:	4c 89 e7                                        	mov    rdi,r12
  9a987e:	89 de                                           	mov    esi,ebx
  9a9880:	44 89 c2                                        	mov    edx,r8d
  9a9883:	44 89 85 40 ff ff ff                            	mov    DWORD PTR [rbp-0xc0],r8d
  9a988a:	48 89 85 c8 fe ff ff                            	mov    QWORD PTR [rbp-0x138],rax
  9a9891:	49 8b 84 24 90 01 00 00                         	mov    rax,QWORD PTR [r12+0x190]
  9a9899:	48 89 85 10 ff ff ff                            	mov    QWORD PTR [rbp-0xf0],rax
  9a98a0:	e8 db e7 ff ff                                  	call   0x9a8080
  9a98a5:	44 8b 95 40 ff ff ff                            	mov    r10d,DWORD PTR [rbp-0xc0]
  9a98ac:	41 89 c3                                        	mov    r11d,eax
  9a98af:	44 89 d0                                        	mov    eax,r10d
  9a98b2:	29 d8                                           	sub    eax,ebx
  9a98b4:	7e 1b                                           	jle    0x9a98d1
  9a98b6:	48 63 cb                                        	movsxd rcx,ebx
  9a98b9:	31 d2                                           	xor    edx,edx
  9a98bb:	49 8d 0c 8e                                     	lea    rcx,[r14+rcx*4]
  9a98bf:	90                                              	nop
  9a98c0:	83 3c 91 00                                     	cmp    DWORD PTR [rcx+rdx*4],0x0
  9a98c4:	0f 85 0d 03 00 00                               	jne    0x9a9bd7
  9a98ca:	48 ff c2                                        	inc    rdx
  9a98cd:	39 d0                                           	cmp    eax,edx
  9a98cf:	75 ef                                           	jne    0x9a98c0
  9a98d1:	4c 8b 85 10 ff ff ff                            	mov    r8,QWORD PTR [rbp-0xf0]
  9a98d8:	89 d8                                           	mov    eax,ebx
  9a98da:	44 89 d6                                        	mov    esi,r10d
  9a98dd:	4c 89 b5 d8 fe ff ff                            	mov    QWORD PTR [rbp-0x128],r14
  9a98e4:	c1 f8 05                                        	sar    eax,0x5
  9a98e7:	c1 fe 05                                        	sar    esi,0x5
  9a98ea:	4c 63 c8                                        	movsxd r9,eax
  9a98ed:	31 c0                                           	xor    eax,eax
  9a98ef:	41 8d 49 01                                     	lea    ecx,[r9+0x1]
  9a98f3:	43 0f b6 14 08                                  	movzx  edx,BYTE PTR [r8+r9*1]
  9a98f8:	84 d2                                           	test   dl,dl
  9a98fa:	0f 94 c0                                        	sete   al
  9a98fd:	41 f6 c2 1f                                     	test   r10b,0x1f
  9a9901:	40 0f 94 c7                                     	sete   dil
  9a9905:	41 39 f1                                        	cmp    r9d,esi
  9a9908:	41 0f 9d c1                                     	setge  r9b
  9a990c:	41 08 f9                                        	or     r9b,dil
  9a990f:	75 13                                           	jne    0x9a9924
  9a9911:	31 ff                                           	xor    edi,edi
  9a9913:	80 fa 01                                        	cmp    dl,0x1
  9a9916:	4c 63 ce                                        	movsxd r9,esi
  9a9919:	83 d7 01                                        	adc    edi,0x1
  9a991c:	43 80 3c 08 00                                  	cmp    BYTE PTR [r8+r9*1],0x0
  9a9921:	0f 44 c7                                        	cmove  eax,edi
  9a9924:	31 d2                                           	xor    edx,edx
  9a9926:	29 ce                                           	sub    esi,ecx
  9a9928:	0f 4e f2                                        	cmovle esi,edx
  9a992b:	01 c6                                           	add    esi,eax
  9a992d:	7e 30                                           	jle    0x9a995f
  9a992f:	41 0f b6 bc 24 9c 01 00 00                      	movzx  edi,BYTE PTR [r12+0x19c]
  9a9938:	41 89 f6                                        	mov    r14d,esi
  9a993b:	45 89 df                                        	mov    r15d,r11d
  9a993e:	e8 0d 3c f4 ff                                  	call   0x8ed550
  9a9943:	45 89 fb                                        	mov    r11d,r15d
  9a9946:	4c 8d 3d c3 29 f7 02                            	lea    r15,[rip+0x2f729c3]        # 0x391c310
  9a994d:	44 8b 95 40 ff ff ff                            	mov    r10d,DWORD PTR [rbp-0xc0]
  9a9954:	44 89 f6                                        	mov    esi,r14d
  9a9957:	85 c0                                           	test   eax,eax
  9a9959:	0f 85 e5 03 00 00                               	jne    0x9a9d44
  9a995f:	48 8b 85 20 ff ff ff                            	mov    rax,QWORD PTR [rbp-0xe0]
  9a9966:	31 d2                                           	xor    edx,edx
  9a9968:	41 b9 00 07 00 00                               	mov    r9d,0x700
  9a996e:	bf 02 00 00 00                                  	mov    edi,0x2
  9a9973:	b9 00 0a 00 00                                  	mov    ecx,0xa00
  9a9978:	f6 80 44 02 00 00 02                            	test   BYTE PTR [rax+0x244],0x2
  9a997f:	b8 00 00 00 00                                  	mov    eax,0x0
  9a9984:	44 0f 45 cf                                     	cmovne r9d,edi
  9a9988:	0f 44 cf                                        	cmove  ecx,edi
  9a998b:	41 0f 95 c0                                     	setne  r8b
  9a998f:	41 39 da                                        	cmp    r10d,ebx
  9a9992:	0f 8e ac 03 00 00                               	jle    0x9a9d44
  9a9998:	8b 85 38 ff ff ff                               	mov    eax,DWORD PTR [rbp-0xc8]
  9a999e:	44 88 c2                                        	mov    dl,r8b
  9a99a1:	bf 01 01 00 00                                  	mov    edi,0x101
  9a99a6:	89 b5 0c ff ff ff                               	mov    DWORD PTR [rbp-0xf4],esi
  9a99ac:	4c 8b 85 c8 fe ff ff                            	mov    r8,QWORD PTR [rbp-0x138]
  9a99b3:	4c 63 fb                                        	movsxd r15,ebx
  9a99b6:	89 9d 08 ff ff ff                               	mov    DWORD PTR [rbp-0xf8],ebx
  9a99bc:	44 89 9d 34 ff ff ff                            	mov    DWORD PTR [rbp-0xcc],r11d
  9a99c3:	4c 89 a5 18 ff ff ff                            	mov    QWORD PTR [rbp-0xe8],r12
  9a99ca:	8d 54 d2 0c                                     	lea    edx,[rdx+rdx*8+0xc]
  9a99ce:	4c 89 bd c0 fe ff ff                            	mov    QWORD PTR [rbp-0x140],r15
  9a99d5:	49 c1 e7 10                                     	shl    r15,0x10
  9a99d9:	4c 03 bd e8 fe ff ff                            	add    r15,QWORD PTR [rbp-0x118]
  9a99e0:	c4 e2 40 f7 f8                                  	bextr  edi,eax,edi
  9a99e5:	09 c7                                           	or     edi,eax
  9a99e7:	c4 c2 6b f7 c5                                  	shrx   eax,r13d,edx
  9a99ec:	44 21 c8                                        	and    eax,r9d
  9a99ef:	4c 8b 8d 20 ff ff ff                            	mov    r9,QWORD PTR [rbp-0xe0]
  9a99f6:	89 fe                                           	mov    esi,edi
  9a99f8:	0f b7 d7                                        	movzx  edx,di
  9a99fb:	89 bd fc fe ff ff                               	mov    DWORD PTR [rbp-0x104],edi
  9a9a01:	4c 89 bd f0 fe ff ff                            	mov    QWORD PTR [rbp-0x110],r15
  9a9a08:	09 c8                                           	or     eax,ecx
  9a9a0a:	83 e6 03                                        	and    esi,0x3
  9a9a0d:	89 95 04 ff ff ff                               	mov    DWORD PTR [rbp-0xfc],edx
  9a9a13:	89 85 00 ff ff ff                               	mov    DWORD PTR [rbp-0x100],eax
  9a9a19:	89 d8                                           	mov    eax,ebx
  9a9a1b:	c1 e6 18                                        	shl    esi,0x18
  9a9a1e:	83 e0 e0                                        	and    eax,0xffffffe0
  9a9a21:	41 09 f5                                        	or     r13d,esi
  9a9a24:	44 0b ad 44 ff ff ff                            	or     r13d,DWORD PTR [rbp-0xbc]
  9a9a2b:	89 b5 30 ff ff ff                               	mov    DWORD PTR [rbp-0xd0],esi
  9a9a31:	49 63 f2                                        	movsxd rsi,r10d
  9a9a34:	8d 48 20                                        	lea    ecx,[rax+0x20]
  9a9a37:	48 89 85 b0 fe ff ff                            	mov    QWORD PTR [rbp-0x150],rax
  9a9a3e:	49 8b 81 d8 01 00 00                            	mov    rax,QWORD PTR [r9+0x1d8]
  9a9a45:	48 89 b5 a8 fe ff ff                            	mov    QWORD PTR [rbp-0x158],rsi
  9a9a4c:	48 89 8d b8 fe ff ff                            	mov    QWORD PTR [rbp-0x148],rcx
  9a9a53:	48 89 85 e0 fe ff ff                            	mov    QWORD PTR [rbp-0x120],rax
  9a9a5a:	49 8b 40 30                                     	mov    rax,QWORD PTR [r8+0x30]
  9a9a5e:	41 81 cd 00 00 00 10                            	or     r13d,0x10000000
  9a9a65:	44 89 ad f8 fe ff ff                            	mov    DWORD PTR [rbp-0x108],r13d
  9a9a6c:	41 89 dd                                        	mov    r13d,ebx
  9a9a6f:	89 cb                                           	mov    ebx,ecx
  9a9a71:	48 89 85 d0 fe ff ff                            	mov    QWORD PTR [rbp-0x130],rax
  9a9a78:	eb 28                                           	jmp    0x9a9aa2
  9a9a7a:	66 0f 1f 44 00 00                               	nop    WORD PTR [rax+rax*1+0x0]
  9a9a80:	44 8b 95 40 ff ff ff                            	mov    r10d,DWORD PTR [rbp-0xc0]
  9a9a87:	41 c1 e4 10                                     	shl    r12d,0x10
  9a9a8b:	41 89 dd                                        	mov    r13d,ebx
  9a9a8e:	49 63 c4                                        	movsxd rax,r12d
  9a9a91:	49 01 c7                                        	add    r15,rax
  9a9a94:	8d 43 20                                        	lea    eax,[rbx+0x20]
  9a9a97:	44 39 d3                                        	cmp    ebx,r10d
  9a9a9a:	89 c3                                           	mov    ebx,eax
  9a9a9c:	0f 8d e8 01 00 00                               	jge    0x9a9c8a
  9a9aa2:	48 8b 8d a8 fe ff ff                            	mov    rcx,QWORD PTR [rbp-0x158]
  9a9aa9:	48 63 c3                                        	movsxd rax,ebx
  9a9aac:	4c 89 bd 38 ff ff ff                            	mov    QWORD PTR [rbp-0xc8],r15
  9a9ab3:	41 89 de                                        	mov    r14d,ebx
  9a9ab6:	48 8b bd c8 fe ff ff                            	mov    rdi,QWORD PTR [rbp-0x138]
  9a9abd:	8b 95 2c ff ff ff                               	mov    edx,DWORD PTR [rbp-0xd4]
  9a9ac3:	4c 8d 85 50 ff ff ff                            	lea    r8,[rbp-0xb0]
  9a9aca:	49 89 c7                                        	mov    r15,rax
  9a9acd:	48 39 c1                                        	cmp    rcx,rax
  9a9ad0:	4c 0f 4c f9                                     	cmovl  r15,rcx
  9a9ad4:	41 39 c2                                        	cmp    r10d,eax
  9a9ad7:	8b 8d 28 ff ff ff                               	mov    ecx,DWORD PTR [rbp-0xd8]
  9a9add:	45 0f 4c f2                                     	cmovl  r14d,r10d
  9a9ae1:	45 89 f4                                        	mov    r12d,r14d
  9a9ae4:	45 29 ec                                        	sub    r12d,r13d
  9a9ae7:	44 89 e6                                        	mov    esi,r12d
  9a9aea:	e8 b1 21 00 00                                  	call   0x9abca0
  9a9aef:	85 c0                                           	test   eax,eax
  9a9af1:	0f 85 ea 00 00 00                               	jne    0x9a9be1
  9a9af7:	48 8b 8d 10 ff ff ff                            	mov    rcx,QWORD PTR [rbp-0xf0]
  9a9afe:	44 89 e8                                        	mov    eax,r13d
  9a9b01:	8b b5 f8 fe ff ff                               	mov    esi,DWORD PTR [rbp-0x108]
  9a9b07:	c1 f8 05                                        	sar    eax,0x5
  9a9b0a:	48 98                                           	cdqe
  9a9b0c:	44 00 24 01                                     	add    BYTE PTR [rcx+rax*1],r12b
  9a9b10:	45 39 ee                                        	cmp    r14d,r13d
  9a9b13:	7e 32                                           	jle    0x9a9b47
  9a9b15:	48 8b 8d d8 fe ff ff                            	mov    rcx,QWORD PTR [rbp-0x128]
  9a9b1c:	49 63 c5                                        	movsxd rax,r13d
  9a9b1f:	49 29 c7                                        	sub    r15,rax
  9a9b22:	48 8d 04 81                                     	lea    rax,[rcx+rax*4]
  9a9b26:	31 c9                                           	xor    ecx,ecx
  9a9b28:	0f 1f 84 00 00 00 00 00                         	nop    DWORD PTR [rax+rax*1+0x0]
  9a9b30:	48 63 d1                                        	movsxd rdx,ecx
  9a9b33:	8b 94 95 50 ff ff ff                            	mov    edx,DWORD PTR [rbp+rdx*4-0xb0]
  9a9b3a:	09 f2                                           	or     edx,esi
  9a9b3c:	89 14 88                                        	mov    DWORD PTR [rax+rcx*4],edx
  9a9b3f:	48 ff c1                                        	inc    rcx
  9a9b42:	49 39 cf                                        	cmp    r15,rcx
  9a9b45:	75 e9                                           	jne    0x9a9b30
  9a9b47:	83 bd 30 ff ff ff 00                            	cmp    DWORD PTR [rbp-0xd0],0x0
  9a9b4e:	4c 8b bd 38 ff ff ff                            	mov    r15,QWORD PTR [rbp-0xc8]
  9a9b55:	74 30                                           	je     0x9a9b87
  9a9b57:	8b 85 28 ff ff ff                               	mov    eax,DWORD PTR [rbp-0xd8]
  9a9b5d:	48 8b bd e0 fe ff ff                            	mov    rdi,QWORD PTR [rbp-0x120]
  9a9b64:	48 8b 95 d0 fe ff ff                            	mov    rdx,QWORD PTR [rbp-0x130]
  9a9b6b:	44 8b 8d 04 ff ff ff                            	mov    r9d,DWORD PTR [rbp-0xfc]
  9a9b72:	4c 89 fe                                        	mov    rsi,r15
  9a9b75:	44 89 e1                                        	mov    ecx,r12d
  9a9b78:	4c 8d 85 50 ff ff ff                            	lea    r8,[rbp-0xb0]
  9a9b7f:	89 04 24                                        	mov    DWORD PTR [rsp],eax
  9a9b82:	e8 89 43 f4 ff                                  	call   0x8edf10
  9a9b87:	83 bd 44 ff ff ff 00                            	cmp    DWORD PTR [rbp-0xbc],0x0
  9a9b8e:	0f 84 ec fe ff ff                               	je     0x9a9a80
  9a9b94:	8b 85 00 ff ff ff                               	mov    eax,DWORD PTR [rbp-0x100]
  9a9b9a:	48 8b bd 20 ff ff ff                            	mov    rdi,QWORD PTR [rbp-0xe0]
  9a9ba1:	48 8b 95 d0 fe ff ff                            	mov    rdx,QWORD PTR [rbp-0x130]
  9a9ba8:	44 8b 8d fc fe ff ff                            	mov    r9d,DWORD PTR [rbp-0x104]
  9a9baf:	4c 89 fe                                        	mov    rsi,r15
  9a9bb2:	44 89 e1                                        	mov    ecx,r12d
  9a9bb5:	4c 8d 85 50 ff ff ff                            	lea    r8,[rbp-0xb0]
  9a9bbc:	89 04 24                                        	mov    DWORD PTR [rsp],eax
  9a9bbf:	e8 5c 26 04 00                                  	call   0x9ec220
  9a9bc4:	85 c0                                           	test   eax,eax
  9a9bc6:	0f 84 b4 fe ff ff                               	je     0x9a9a80
  9a9bcc:	89 85 38 ff ff ff                               	mov    DWORD PTR [rbp-0xc8],eax
  9a9bd2:	45 89 f5                                        	mov    r13d,r14d
  9a9bd5:	eb 10                                           	jmp    0x9a9be7
  9a9bd7:	b8 10 00 00 00                                  	mov    eax,0x10
  9a9bdc:	e9 63 01 00 00                                  	jmp    0x9a9d44
  9a9be1:	89 85 38 ff ff ff                               	mov    DWORD PTR [rbp-0xc8],eax
  9a9be7:	83 bd 30 ff ff ff 00                            	cmp    DWORD PTR [rbp-0xd0],0x0
  9a9bee:	8b 9d 08 ff ff ff                               	mov    ebx,DWORD PTR [rbp-0xf8]
  9a9bf4:	4c 8b b5 d8 fe ff ff                            	mov    r14,QWORD PTR [rbp-0x128]
  9a9bfb:	4c 8b a5 c0 fe ff ff                            	mov    r12,QWORD PTR [rbp-0x140]
  9a9c02:	74 45                                           	je     0x9a9c49
  9a9c04:	49 63 d5                                        	movsxd rdx,r13d
  9a9c07:	4c 8b bd e0 fe ff ff                            	mov    r15,QWORD PTR [rbp-0x120]
  9a9c0e:	48 8b b5 f0 fe ff ff                            	mov    rsi,QWORD PTR [rbp-0x110]
  9a9c15:	48 8d 8d 48 ff ff ff                            	lea    rcx,[rbp-0xb8]
  9a9c1c:	48 c7 85 48 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0xb8],0x0
  9a9c27:	48 c1 e2 10                                     	shl    rdx,0x10
  9a9c2b:	48 03 95 e8 fe ff ff                            	add    rdx,QWORD PTR [rbp-0x118]
  9a9c32:	4c 89 ff                                        	mov    rdi,r15
  9a9c35:	e8 46 4b f4 ff                                  	call   0x8ee780
  9a9c3a:	48 8b b5 48 ff ff ff                            	mov    rsi,QWORD PTR [rbp-0xb8]
  9a9c41:	4c 89 ff                                        	mov    rdi,r15
  9a9c44:	e8 f7 56 f4 ff                                  	call   0x8ef340
  9a9c49:	83 bd 44 ff ff ff 00                            	cmp    DWORD PTR [rbp-0xbc],0x0
  9a9c50:	74 4d                                           	je     0x9a9c9f
  9a9c52:	65 48 8b 04 25 00 00 00 00                      	mov    rax,QWORD PTR gs:0x0
  9a9c5b:	48 8b bd 20 ff ff ff                            	mov    rdi,QWORD PTR [rbp-0xe0]
  9a9c62:	48 8b b5 f0 fe ff ff                            	mov    rsi,QWORD PTR [rbp-0x110]
  9a9c69:	45 89 ef                                        	mov    r15d,r13d
  9a9c6c:	4b 8d 0c a6                                     	lea    rcx,[r14+r12*4]
  9a9c70:	41 b8 01 00 00 00                               	mov    r8d,0x1
  9a9c76:	c6 80 17 01 00 00 00                            	mov    BYTE PTR [rax+0x117],0x0
  9a9c7d:	41 29 df                                        	sub    r15d,ebx
  9a9c80:	44 89 fa                                        	mov    edx,r15d
  9a9c83:	e8 88 27 04 00                                  	call   0x9ec410
  9a9c88:	eb 1b                                           	jmp    0x9a9ca5
  9a9c8a:	4c 8d 3d 7f 26 f7 02                            	lea    r15,[rip+0x2f7267f]        # 0x391c310
  9a9c91:	4c 8b a5 18 ff ff ff                            	mov    r12,QWORD PTR [rbp-0xe8]
  9a9c98:	31 c0                                           	xor    eax,eax
  9a9c9a:	e9 9e 00 00 00                                  	jmp    0x9a9d3d
  9a9c9f:	45 89 ef                                        	mov    r15d,r13d
  9a9ca2:	41 29 df                                        	sub    r15d,ebx
  9a9ca5:	48 8b bd 18 ff ff ff                            	mov    rdi,QWORD PTR [rbp-0xe8]
  9a9cac:	4f 8d 24 a6                                     	lea    r12,[r14+r12*4]
  9a9cb0:	44 89 fa                                        	mov    edx,r15d
  9a9cb3:	4c 89 e6                                        	mov    rsi,r12
  9a9cb6:	e8 05 ea ff ff                                  	call   0x9a86c0
  9a9cbb:	49 63 f7                                        	movsxd rsi,r15d
  9a9cbe:	4c 89 e7                                        	mov    rdi,r12
  9a9cc1:	48 c1 e6 02                                     	shl    rsi,0x2
  9a9cc5:	e8 26 f3 8a ff                                  	call   0x258ff0
  9a9cca:	48 8b 95 10 ff ff ff                            	mov    rdx,QWORD PTR [rbp-0xf0]
  9a9cd1:	48 8b b5 b0 fe ff ff                            	mov    rsi,QWORD PTR [rbp-0x150]
  9a9cd8:	48 8b bd b8 fe ff ff                            	mov    rdi,QWORD PTR [rbp-0x148]
  9a9cdf:	41 39 dd                                        	cmp    r13d,ebx
  9a9ce2:	7e 31                                           	jle    0x9a9d15
  9a9ce4:	66 66 66 2e 0f 1f 84 00 00 00 00 00             	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  9a9cf0:	83 c6 20                                        	add    esi,0x20
  9a9cf3:	89 d9                                           	mov    ecx,ebx
  9a9cf5:	41 39 f5                                        	cmp    r13d,esi
  9a9cf8:	89 f0                                           	mov    eax,esi
  9a9cfa:	41 0f 4c c5                                     	cmovl  eax,r13d
  9a9cfe:	c1 fb 05                                        	sar    ebx,0x5
  9a9d01:	29 c1                                           	sub    ecx,eax
  9a9d03:	48 63 c3                                        	movsxd rax,ebx
  9a9d06:	89 fb                                           	mov    ebx,edi
  9a9d08:	00 0c 02                                        	add    BYTE PTR [rdx+rax*1],cl
  9a9d0b:	8d 47 20                                        	lea    eax,[rdi+0x20]
  9a9d0e:	89 c7                                           	mov    edi,eax
