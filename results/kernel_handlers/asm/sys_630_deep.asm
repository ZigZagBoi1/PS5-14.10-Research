
/tmp/claude-1000/-home-violence-ps5-research-repo/5b61b6f2-f8c2-4b4b-901d-a3076db70d12/scratchpad/dumps_13.60/deep_handlers/deep_630.bin:     file format binary


Disassembly of section .data:

000000000091cc70 <.data>:
  91cc70:	55                                              	push   rbp
  91cc71:	48 89 e5                                        	mov    rbp,rsp
  91cc74:	41 57                                           	push   r15
  91cc76:	41 56                                           	push   r14
  91cc78:	53                                              	push   rbx
  91cc79:	50                                              	push   rax
  91cc7a:	49 89 f7                                        	mov    r15,rsi
  91cc7d:	49 89 fe                                        	mov    r14,rdi
  91cc80:	48 8d 35 89 51 c3 01                            	lea    rsi,[rip+0x1c35189]        # 0x2551e10
  91cc87:	bf 00 04 00 00                                  	mov    edi,0x400
  91cc8c:	ba 02 00 00 00                                  	mov    edx,0x2
  91cc91:	e8 ba be 2e 00                                  	call   0xc08b50
  91cc96:	4d 8b 3f                                        	mov    r15,QWORD PTR [r15]
  91cc99:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  91cca2:	48 8d 35 db d3 a3 00                            	lea    rsi,[rip+0xa3d3db]        # 0x135a084
  91cca9:	31 d2                                           	xor    edx,edx
  91ccab:	48 89 c3                                        	mov    rbx,rax
  91ccae:	e8 2d d7 2f 00                                  	call   0xc1a3e0
  91ccb3:	ba 00 04 00 00                                  	mov    edx,0x400
  91ccb8:	4c 89 ff                                        	mov    rdi,r15
  91ccbb:	48 89 de                                        	mov    rsi,rbx
  91ccbe:	31 c9                                           	xor    ecx,ecx
  91ccc0:	e8 3b cc 93 ff                                  	call   0x259900
  91ccc5:	41 89 c7                                        	mov    r15d,eax
  91ccc8:	85 c0                                           	test   eax,eax
  91ccca:	75 57                                           	jne    0x91cd23
  91cccc:	49 8b be 40 01 00 00                            	mov    rdi,QWORD PTR [r14+0x140]
  91ccd3:	e8 f8 c5 ce ff                                  	call   0x6092d0
  91ccd8:	85 c0                                           	test   eax,eax
  91ccda:	74 39                                           	je     0x91cd15
  91ccdc:	48 8d 35 be 07 f0 00                            	lea    rsi,[rip+0xf007be]        # 0x181d4a1
  91cce3:	ba 0c 00 00 00                                  	mov    edx,0xc
  91cce8:	48 89 df                                        	mov    rdi,rbx
  91cceb:	e8 40 4d fb ff                                  	call   0x8d1a30
  91ccf0:	85 c0                                           	test   eax,eax
  91ccf2:	74 21                                           	je     0x91cd15
  91ccf4:	48 8d 3d 62 d1 a6 00                            	lea    rdi,[rip+0xa6d162]        # 0x1389e5d
  91ccfb:	48 8d 0d 9f 07 f0 00                            	lea    rcx,[rip+0xf0079f]        # 0x181d4a1
  91cd02:	4c 89 f6                                        	mov    rsi,r14
  91cd05:	48 89 da                                        	mov    rdx,rbx
  91cd08:	e8 93 08 ef ff                                  	call   0x80d5a0
  91cd0d:	41 bf 02 00 00 00                               	mov    r15d,0x2
  91cd13:	eb 0e                                           	jmp    0x91cd23
  91cd15:	4c 89 f7                                        	mov    rdi,r14
  91cd18:	48 89 de                                        	mov    rsi,rbx
  91cd1b:	e8 20 fa ff ff                                  	call   0x91c740
  91cd20:	41 89 c7                                        	mov    r15d,eax
  91cd23:	48 8d 35 e6 50 c3 01                            	lea    rsi,[rip+0x1c350e6]        # 0x2551e10
  91cd2a:	48 89 df                                        	mov    rdi,rbx
  91cd2d:	e8 be c0 2e 00                                  	call   0xc08df0
  91cd32:	44 89 f8                                        	mov    eax,r15d
  91cd35:	48 83 c4 08                                     	add    rsp,0x8
  91cd39:	5b                                              	pop    rbx
  91cd3a:	41 5e                                           	pop    r14
  91cd3c:	41 5f                                           	pop    r15
  91cd3e:	5d                                              	pop    rbp
  91cd3f:	c3                                              	ret
  91cd40:	55                                              	push   rbp
  91cd41:	48 89 e5                                        	mov    rbp,rsp
  91cd44:	41 57                                           	push   r15
  91cd46:	41 56                                           	push   r14
  91cd48:	41 55                                           	push   r13
  91cd4a:	41 54                                           	push   r12
  91cd4c:	53                                              	push   rbx
  91cd4d:	50                                              	push   rax
  91cd4e:	48 85 d2                                        	test   rdx,rdx
  91cd51:	0f 84 e6 00 00 00                               	je     0x91ce3d
  91cd57:	48 85 ff                                        	test   rdi,rdi
  91cd5a:	48 89 d3                                        	mov    rbx,rdx
  91cd5d:	49 89 f6                                        	mov    r14,rsi
  91cd60:	49 89 ff                                        	mov    r15,rdi
  91cd63:	0f 94 c0                                        	sete   al
  91cd66:	48 85 f6                                        	test   rsi,rsi
  91cd69:	0f 94 c1                                        	sete   cl
  91cd6c:	45 31 e4                                        	xor    r12d,r12d
  91cd6f:	08 c1                                           	or     cl,al
  91cd71:	75 03                                           	jne    0x91cd76
  91cd73:	45 8b 26                                        	mov    r12d,DWORD PTR [r14]
  91cd76:	48 8d 3d d3 9b 25 03                            	lea    rdi,[rip+0x3259bd3]        # 0x3b76950
  91cd7d:	45 31 ed                                        	xor    r13d,r13d
  91cd80:	31 f6                                           	xor    esi,esi
  91cd82:	31 d2                                           	xor    edx,edx
  91cd84:	31 c9                                           	xor    ecx,ecx
  91cd86:	e8 75 9c ba ff                                  	call   0x4c6a00
  91cd8b:	48 8d 0d ce 9b 25 03                            	lea    rcx,[rip+0x3259bce]        # 0x3b76960
  91cd92:	66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00       	data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  91cda0:	48 8b 09                                        	mov    rcx,QWORD PTR [rcx]
  91cda3:	4c 89 e8                                        	mov    rax,r13
  91cda6:	49 89 cd                                        	mov    r13,rcx
  91cda9:	48 85 c9                                        	test   rcx,rcx
  91cdac:	75 f2                                           	jne    0x91cda0
  91cdae:	45 31 ed                                        	xor    r13d,r13d
  91cdb1:	48 85 c0                                        	test   rax,rax
  91cdb4:	74 5e                                           	je     0x91ce14
  91cdb6:	66 2e 0f 1f 84 00 00 00 00 00                   	cs nop WORD PTR [rax+rax*1+0x0]
  91cdc0:	48 89 c1                                        	mov    rcx,rax
  91cdc3:	45 39 e5                                        	cmp    r13d,r12d
  91cdc6:	7d 0b                                           	jge    0x91cdd3
  91cdc8:	48 8b 41 28                                     	mov    rax,QWORD PTR [rcx+0x28]
  91cdcc:	49 63 d5                                        	movsxd rdx,r13d
  91cdcf:	49 89 04 d7                                     	mov    QWORD PTR [r15+rdx*8],rax
  91cdd3:	48 8b 51 08                                     	mov    rdx,QWORD PTR [rcx+0x8]
  91cdd7:	41 ff c5                                        	inc    r13d
  91cdda:	48 85 d2                                        	test   rdx,rdx
  91cddd:	74 11                                           	je     0x91cdf0
  91cddf:	90                                              	nop
  91cde0:	48 89 d0                                        	mov    rax,rdx
  91cde3:	48 8b 12                                        	mov    rdx,QWORD PTR [rdx]
  91cde6:	48 85 d2                                        	test   rdx,rdx
  91cde9:	75 f5                                           	jne    0x91cde0
  91cdeb:	eb d3                                           	jmp    0x91cdc0
  91cded:	0f 1f 00                                        	nop    DWORD PTR [rax]
  91cdf0:	48 8b 41 10                                     	mov    rax,QWORD PTR [rcx+0x10]
  91cdf4:	48 85 c0                                        	test   rax,rax
  91cdf7:	74 07                                           	je     0x91ce00
  91cdf9:	48 3b 08                                        	cmp    rcx,QWORD PTR [rax]
  91cdfc:	74 c2                                           	je     0x91cdc0
  91cdfe:	66 90                                           	xchg   ax,ax
  91ce00:	48 8b 41 10                                     	mov    rax,QWORD PTR [rcx+0x10]
  91ce04:	48 85 c0                                        	test   rax,rax
  91ce07:	74 0b                                           	je     0x91ce14
  91ce09:	48 3b 48 08                                     	cmp    rcx,QWORD PTR [rax+0x8]
  91ce0d:	48 89 c1                                        	mov    rcx,rax
  91ce10:	74 ee                                           	je     0x91ce00
  91ce12:	eb ac                                           	jmp    0x91cdc0
  91ce14:	48 8d 3d 35 9b 25 03                            	lea    rdi,[rip+0x3259b35]        # 0x3b76950
  91ce1b:	45 31 ff                                        	xor    r15d,r15d
  91ce1e:	31 f6                                           	xor    esi,esi
  91ce20:	31 d2                                           	xor    edx,edx
  91ce22:	31 c9                                           	xor    ecx,ecx
  91ce24:	e8 77 a1 ba ff                                  	call   0x4c6fa0
  91ce29:	4d 85 f6                                        	test   r14,r14
  91ce2c:	74 0a                                           	je     0x91ce38
  91ce2e:	45 39 ec                                        	cmp    r12d,r13d
  91ce31:	45 0f 4d e5                                     	cmovge r12d,r13d
  91ce35:	45 89 26                                        	mov    DWORD PTR [r14],r12d
  91ce38:	44 89 2b                                        	mov    DWORD PTR [rbx],r13d
  91ce3b:	eb 06                                           	jmp    0x91ce43
  91ce3d:	41 bf 16 00 00 00                               	mov    r15d,0x16
  91ce43:	44 89 f8                                        	mov    eax,r15d
  91ce46:	48 83 c4 08                                     	add    rsp,0x8
  91ce4a:	5b                                              	pop    rbx
  91ce4b:	41 5c                                           	pop    r12
  91ce4d:	41 5d                                           	pop    r13
  91ce4f:	41 5e                                           	pop    r14
  91ce51:	41 5f                                           	pop    r15
  91ce53:	5d                                              	pop    rbp
  91ce54:	c3                                              	ret
  91ce55:	90                                              	nop
  91ce56:	90                                              	nop
  91ce57:	90                                              	nop
  91ce58:	90                                              	nop
  91ce59:	90                                              	nop
  91ce5a:	90                                              	nop
  91ce5b:	90                                              	nop
  91ce5c:	90                                              	nop
  91ce5d:	90                                              	nop
  91ce5e:	90                                              	nop
  91ce5f:	90                                              	nop
  91ce60:	55                                              	push   rbp
  91ce61:	48 89 e5                                        	mov    rbp,rsp
  91ce64:	41 57                                           	push   r15
  91ce66:	41 56                                           	push   r14
  91ce68:	41 55                                           	push   r13
  91ce6a:	41 54                                           	push   r12
  91ce6c:	53                                              	push   rbx
  91ce6d:	50                                              	push   rax
  91ce6e:	49 89 ff                                        	mov    r15,rdi
  91ce71:	48 8d 3d d8 9a 25 03                            	lea    rdi,[rip+0x3259ad8]        # 0x3b76950
  91ce78:	48 89 d3                                        	mov    rbx,rdx
  91ce7b:	49 89 f6                                        	mov    r14,rsi
  91ce7e:	45 31 e4                                        	xor    r12d,r12d
  91ce81:	31 f6                                           	xor    esi,esi
  91ce83:	31 d2                                           	xor    edx,edx
  91ce85:	31 c9                                           	xor    ecx,ecx
  91ce87:	e8 74 9b ba ff                                  	call   0x4c6a00
  91ce8c:	48 8d 0d cd 9a 25 03                            	lea    rcx,[rip+0x3259acd]        # 0x3b76960
  91ce93:	66 66 66 66 2e 0f 1f 84 00 00 00 00 00          	data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  91cea0:	48 8b 09                                        	mov    rcx,QWORD PTR [rcx]
  91cea3:	4c 89 e0                                        	mov    rax,r12
  91cea6:	49 89 cc                                        	mov    r12,rcx
  91cea9:	48 85 c9                                        	test   rcx,rcx
  91ceac:	75 f2                                           	jne    0x91cea0
  91ceae:	41 bc 09 00 00 00                               	mov    r12d,0x9
  91ceb4:	48 85 c0                                        	test   rax,rax
  91ceb7:	74 37                                           	je     0x91cef0
  91ceb9:	4c 39 78 28                                     	cmp    QWORD PTR [rax+0x28],r15
  91cebd:	75 6a                                           	jne    0x91cf29
  91cebf:	49 89 c5                                        	mov    r13,rax
  91cec2:	4d 85 f6                                        	test   r14,r14
  91cec5:	74 10                                           	je     0x91ced7
  91cec7:	ba 20 00 00 00                                  	mov    edx,0x20
  91cecc:	4c 89 ff                                        	mov    rdi,r15
  91cecf:	4c 89 f6                                        	mov    rsi,r14
  91ced2:	e8 09 cd 93 ff                                  	call   0x259be0
  91ced7:	45 31 e4                                        	xor    r12d,r12d
  91ceda:	48 85 db                                        	test   rbx,rbx
  91cedd:	74 11                                           	je     0x91cef0
  91cedf:	49 8b 75 20                                     	mov    rsi,QWORD PTR [r13+0x20]
  91cee3:	ba 00 04 00 00                                  	mov    edx,0x400
  91cee8:	48 89 df                                        	mov    rdi,rbx
  91ceeb:	e8 80 ac 03 00                                  	call   0x957b70
  91cef0:	48 8d 3d 59 9a 25 03                            	lea    rdi,[rip+0x3259a59]        # 0x3b76950
  91cef7:	31 f6                                           	xor    esi,esi
  91cef9:	31 d2                                           	xor    edx,edx
  91cefb:	31 c9                                           	xor    ecx,ecx
  91cefd:	e8 9e a0 ba ff                                  	call   0x4c6fa0
  91cf02:	44 89 e0                                        	mov    eax,r12d
  91cf05:	48 83 c4 08                                     	add    rsp,0x8
  91cf09:	5b                                              	pop    rbx
  91cf0a:	41 5c                                           	pop    r12
  91cf0c:	41 5d                                           	pop    r13
  91cf0e:	41 5e                                           	pop    r14
  91cf10:	41 5f                                           	pop    r15
  91cf12:	5d                                              	pop    rbp
  91cf13:	c3                                              	ret
  91cf14:	66 66 66 2e 0f 1f 84 00 00 00 00 00             	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  91cf20:	4c 89 e8                                        	mov    rax,r13
  91cf23:	4d 39 7d 28                                     	cmp    QWORD PTR [r13+0x28],r15
  91cf27:	74 99                                           	je     0x91cec2
  91cf29:	48 8b 48 08                                     	mov    rcx,QWORD PTR [rax+0x8]
  91cf2d:	48 85 c9                                        	test   rcx,rcx
  91cf30:	74 1e                                           	je     0x91cf50
  91cf32:	66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00       	data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  91cf40:	49 89 cd                                        	mov    r13,rcx
  91cf43:	48 8b 09                                        	mov    rcx,QWORD PTR [rcx]
  91cf46:	48 85 c9                                        	test   rcx,rcx
  91cf49:	75 f5                                           	jne    0x91cf40
  91cf4b:	eb d3                                           	jmp    0x91cf20
  91cf4d:	0f 1f 00                                        	nop    DWORD PTR [rax]
  91cf50:	4c 8b 68 10                                     	mov    r13,QWORD PTR [rax+0x10]
  91cf54:	4d 85 ed                                        	test   r13,r13
  91cf57:	74 07                                           	je     0x91cf60
  91cf59:	49 3b 45 00                                     	cmp    rax,QWORD PTR [r13+0x0]
  91cf5d:	74 c1                                           	je     0x91cf20
  91cf5f:	90                                              	nop
  91cf60:	4c 8b 68 10                                     	mov    r13,QWORD PTR [rax+0x10]
  91cf64:	4d 85 ed                                        	test   r13,r13
  91cf67:	74 87                                           	je     0x91cef0
  91cf69:	49 3b 45 08                                     	cmp    rax,QWORD PTR [r13+0x8]
  91cf6d:	4c 89 e8                                        	mov    rax,r13
  91cf70:	74 ee                                           	je     0x91cf60
  91cf72:	eb ac                                           	jmp    0x91cf20
  91cf74:	90                                              	nop
  91cf75:	90                                              	nop
  91cf76:	90                                              	nop
  91cf77:	90                                              	nop
  91cf78:	90                                              	nop
  91cf79:	90                                              	nop
  91cf7a:	90                                              	nop
  91cf7b:	90                                              	nop
  91cf7c:	90                                              	nop
  91cf7d:	90                                              	nop
  91cf7e:	90                                              	nop
  91cf7f:	90                                              	nop
  91cf80:	55                                              	push   rbp
  91cf81:	48 89 e5                                        	mov    rbp,rsp
  91cf84:	41 57                                           	push   r15
  91cf86:	41 56                                           	push   r14
  91cf88:	41 55                                           	push   r13
  91cf8a:	41 54                                           	push   r12
  91cf8c:	53                                              	push   rbx
  91cf8d:	48 83 ec 18                                     	sub    rsp,0x18
  91cf91:	48 85 d2                                        	test   rdx,rdx
  91cf94:	0f 84 01 01 00 00                               	je     0x91d09b
  91cf9a:	48 85 ff                                        	test   rdi,rdi
  91cf9d:	bb 00 00 00 00                                  	mov    ebx,0x0
  91cfa2:	48 89 55 c8                                     	mov    QWORD PTR [rbp-0x38],rdx
  91cfa6:	48 89 7d c0                                     	mov    QWORD PTR [rbp-0x40],rdi
  91cfaa:	0f 94 c0                                        	sete   al
  91cfad:	48 85 f6                                        	test   rsi,rsi
  91cfb0:	0f 94 c1                                        	sete   cl
  91cfb3:	45 31 ed                                        	xor    r13d,r13d
  91cfb6:	08 c1                                           	or     cl,al
  91cfb8:	75 02                                           	jne    0x91cfbc
  91cfba:	8b 1e                                           	mov    ebx,DWORD PTR [rsi]
  91cfbc:	48 8d 3d 9d ce c6 02                            	lea    rdi,[rip+0x2c6ce9d]        # 0x3589e60
  91cfc3:	48 89 75 d0                                     	mov    QWORD PTR [rbp-0x30],rsi
  91cfc7:	31 f6                                           	xor    esi,esi
  91cfc9:	31 d2                                           	xor    edx,edx
  91cfcb:	31 c9                                           	xor    ecx,ecx
  91cfcd:	e8 7e e3 32 00                                  	call   0xc4b350
  91cfd2:	4c 8b 35 a7 ce c6 02                            	mov    r14,QWORD PTR [rip+0x2c6cea7]        # 0x3589e80
  91cfd9:	4d 85 f6                                        	test   r14,r14
  91cfdc:	0f 84 8b 00 00 00                               	je     0x91d06d
  91cfe2:	45 31 ed                                        	xor    r13d,r13d
  91cfe5:	eb 1d                                           	jmp    0x91d004
  91cfe7:	66 0f 1f 84 00 00 00 00 00                      	nop    WORD PTR [rax+rax*1+0x0]
  91cff0:	4c 89 e7                                        	mov    rdi,r12
  91cff3:	31 f6                                           	xor    esi,esi
  91cff5:	31 d2                                           	xor    edx,edx
  91cff7:	e8 04 f3 32 00                                  	call   0xc4c300
  91cffc:	4d 8b 36                                        	mov    r14,QWORD PTR [r14]
  91cfff:	4d 85 f6                                        	test   r14,r14
  91d002:	74 69                                           	je     0x91d06d
  91d004:	4d 8b 7e 48                                     	mov    r15,QWORD PTR [r14+0x48]
  91d008:	31 f6                                           	xor    esi,esi
  91d00a:	31 d2                                           	xor    edx,edx
  91d00c:	31 c9                                           	xor    ecx,ecx
  91d00e:	4d 8d 67 40                                     	lea    r12,[r15+0x40]
  91d012:	4c 89 e7                                        	mov    rdi,r12
  91d015:	e8 36 e3 32 00                                  	call   0xc4b350
  91d01a:	41 8b 4f 28                                     	mov    ecx,DWORD PTR [r15+0x28]
  91d01e:	85 c9                                           	test   ecx,ecx
  91d020:	78 ce                                           	js     0x91cff0
  91d022:	48 8b 7d c0                                     	mov    rdi,QWORD PTR [rbp-0x40]
  91d026:	31 c0                                           	xor    eax,eax
  91d028:	eb 0f                                           	jmp    0x91d039
  91d02a:	66 0f 1f 44 00 00                               	nop    WORD PTR [rax+rax*1+0x0]
  91d030:	41 ff c5                                        	inc    r13d
  91d033:	ff c0                                           	inc    eax
  91d035:	39 c8                                           	cmp    eax,ecx
  91d037:	7f b7                                           	jg     0x91cff0
  91d039:	48 63 f0                                        	movsxd rsi,eax
  91d03c:	49 8b 17                                        	mov    rdx,QWORD PTR [r15]
  91d03f:	48 8d 34 76                                     	lea    rsi,[rsi+rsi*2]
  91d043:	48 c1 e6 04                                     	shl    rsi,0x4
  91d047:	48 8b 54 32 08                                  	mov    rdx,QWORD PTR [rdx+rsi*1+0x8]
  91d04c:	48 85 d2                                        	test   rdx,rdx
  91d04f:	74 e2                                           	je     0x91d033
  91d051:	66 83 7a 20 10                                  	cmp    WORD PTR [rdx+0x20],0x10
  91d056:	75 db                                           	jne    0x91d033
  91d058:	41 39 dd                                        	cmp    r13d,ebx
  91d05b:	7d d3                                           	jge    0x91d030
  91d05d:	48 8b 0a                                        	mov    rcx,QWORD PTR [rdx]
  91d060:	49 63 d5                                        	movsxd rdx,r13d
  91d063:	48 89 0c d7                                     	mov    QWORD PTR [rdi+rdx*8],rcx
  91d067:	41 8b 4f 28                                     	mov    ecx,DWORD PTR [r15+0x28]
  91d06b:	eb c3                                           	jmp    0x91d030
  91d06d:	48 8d 3d ec cd c6 02                            	lea    rdi,[rip+0x2c6cdec]        # 0x3589e60
  91d074:	45 31 ff                                        	xor    r15d,r15d
  91d077:	31 f6                                           	xor    esi,esi
  91d079:	31 d2                                           	xor    edx,edx
  91d07b:	e8 80 f2 32 00                                  	call   0xc4c300
  91d080:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  91d084:	48 85 c0                                        	test   rax,rax
  91d087:	74 09                                           	je     0x91d092
  91d089:	44 39 eb                                        	cmp    ebx,r13d
  91d08c:	41 0f 4d dd                                     	cmovge ebx,r13d
  91d090:	89 18                                           	mov    DWORD PTR [rax],ebx
  91d092:	48 8b 45 c8                                     	mov    rax,QWORD PTR [rbp-0x38]
  91d096:	44 89 28                                        	mov    DWORD PTR [rax],r13d
  91d099:	eb 06                                           	jmp    0x91d0a1
  91d09b:	41 bf 16 00 00 00                               	mov    r15d,0x16
  91d0a1:	44 89 f8                                        	mov    eax,r15d
  91d0a4:	48 83 c4 18                                     	add    rsp,0x18
  91d0a8:	5b                                              	pop    rbx
  91d0a9:	41 5c                                           	pop    r12
  91d0ab:	41 5d                                           	pop    r13
  91d0ad:	41 5e                                           	pop    r14
  91d0af:	41 5f                                           	pop    r15
  91d0b1:	5d                                              	pop    rbp
  91d0b2:	c3                                              	ret
  91d0b3:	90                                              	nop
  91d0b4:	90                                              	nop
  91d0b5:	90                                              	nop
  91d0b6:	90                                              	nop
  91d0b7:	90                                              	nop
  91d0b8:	90                                              	nop
  91d0b9:	90                                              	nop
  91d0ba:	90                                              	nop
  91d0bb:	90                                              	nop
  91d0bc:	90                                              	nop
  91d0bd:	90                                              	nop
  91d0be:	90                                              	nop
  91d0bf:	90                                              	nop
  91d0c0:	55                                              	push   rbp
  91d0c1:	48 89 e5                                        	mov    rbp,rsp
  91d0c4:	41 57                                           	push   r15
  91d0c6:	41 56                                           	push   r14
  91d0c8:	41 55                                           	push   r13
  91d0ca:	41 54                                           	push   r12
  91d0cc:	53                                              	push   rbx
  91d0cd:	48 83 ec 18                                     	sub    rsp,0x18
  91d0d1:	8b 1a                                           	mov    ebx,DWORD PTR [rdx]
  91d0d3:	49 89 fc                                        	mov    r12,rdi
  91d0d6:	48 8d 3d 83 cd c6 02                            	lea    rdi,[rip+0x2c6cd83]        # 0x3589e60
  91d0dd:	48 89 4d c8                                     	mov    QWORD PTR [rbp-0x38],rcx
  91d0e1:	49 89 d6                                        	mov    r14,rdx
  91d0e4:	48 89 75 c0                                     	mov    QWORD PTR [rbp-0x40],rsi
  91d0e8:	45 31 ff                                        	xor    r15d,r15d
  91d0eb:	31 f6                                           	xor    esi,esi
  91d0ed:	31 d2                                           	xor    edx,edx
  91d0ef:	31 c9                                           	xor    ecx,ecx
  91d0f1:	e8 5a e2 32 00                                  	call   0xc4b350
  91d0f6:	85 db                                           	test   ebx,ebx
  91d0f8:	74 43                                           	je     0x91d13d
  91d0fa:	89 df                                           	mov    edi,ebx
  91d0fc:	e8 6f f0 c1 ff                                  	call   0x53c170
  91d101:	48 85 c0                                        	test   rax,rax
  91d104:	0f 84 f9 00 00 00                               	je     0x91d203
  91d10a:	48 89 c7                                        	mov    rdi,rax
  91d10d:	49 89 c5                                        	mov    r13,rax
  91d110:	4c 89 75 d0                                     	mov    QWORD PTR [rbp-0x30],r14
  91d114:	31 f6                                           	xor    esi,esi
  91d116:	31 d2                                           	xor    edx,edx
  91d118:	31 c9                                           	xor    ecx,ecx
  91d11a:	48 81 c7 48 01 00 00                            	add    rdi,0x148
  91d121:	e8 7a 9e ba ff                                  	call   0x4c6fa0
  91d126:	48 8b 45 c8                                     	mov    rax,QWORD PTR [rbp-0x38]
  91d12a:	41 bf ff ff ff ff                               	mov    r15d,0xffffffff
  91d130:	8b 00                                           	mov    eax,DWORD PTR [rax]
  91d132:	85 c0                                           	test   eax,eax
  91d134:	44 0f 49 f8                                     	cmovns r15d,eax
  91d138:	41 ff c7                                        	inc    r15d
  91d13b:	eb 2f                                           	jmp    0x91d16c
  91d13d:	4c 8b 2d 3c cd c6 02                            	mov    r13,QWORD PTR [rip+0x2c6cd3c]        # 0x3589e80
  91d144:	4c 89 75 d0                                     	mov    QWORD PTR [rbp-0x30],r14
  91d148:	eb 22                                           	jmp    0x91d16c
  91d14a:	66 0f 1f 44 00 00                               	nop    WORD PTR [rax+rax*1+0x0]
  91d150:	48 89 df                                        	mov    rdi,rbx
  91d153:	45 31 ff                                        	xor    r15d,r15d
  91d156:	31 f6                                           	xor    esi,esi
  91d158:	31 d2                                           	xor    edx,edx
  91d15a:	e8 a1 f1 32 00                                  	call   0xc4c300
  91d15f:	4d 8b 6d 00                                     	mov    r13,QWORD PTR [r13+0x0]
  91d163:	4d 85 ed                                        	test   r13,r13
  91d166:	0f 84 9f 00 00 00                               	je     0x91d20b
  91d16c:	4d 8b 75 48                                     	mov    r14,QWORD PTR [r13+0x48]
  91d170:	31 f6                                           	xor    esi,esi
  91d172:	31 d2                                           	xor    edx,edx
  91d174:	31 c9                                           	xor    ecx,ecx
  91d176:	49 8d 5e 40                                     	lea    rbx,[r14+0x40]
  91d17a:	48 89 df                                        	mov    rdi,rbx
  91d17d:	e8 ce e1 32 00                                  	call   0xc4b350
  91d182:	41 8b 46 28                                     	mov    eax,DWORD PTR [r14+0x28]
  91d186:	41 39 c7                                        	cmp    r15d,eax
  91d189:	7f c5                                           	jg     0x91d150
  91d18b:	49 8b 0e                                        	mov    rcx,QWORD PTR [r14]
  91d18e:	48 83 c1 08                                     	add    rcx,0x8
  91d192:	eb 14                                           	jmp    0x91d1a8
  91d194:	66 66 66 2e 0f 1f 84 00 00 00 00 00             	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  91d1a0:	41 ff c7                                        	inc    r15d
  91d1a3:	41 39 c7                                        	cmp    r15d,eax
  91d1a6:	7f a8                                           	jg     0x91d150
  91d1a8:	49 63 d7                                        	movsxd rdx,r15d
  91d1ab:	48 8d 14 52                                     	lea    rdx,[rdx+rdx*2]
  91d1af:	48 c1 e2 04                                     	shl    rdx,0x4
  91d1b3:	48 8b 14 11                                     	mov    rdx,QWORD PTR [rcx+rdx*1]
  91d1b7:	48 85 d2                                        	test   rdx,rdx
  91d1ba:	74 e4                                           	je     0x91d1a0
  91d1bc:	66 83 7a 20 10                                  	cmp    WORD PTR [rdx+0x20],0x10
  91d1c1:	75 dd                                           	jne    0x91d1a0
  91d1c3:	4c 39 22                                        	cmp    QWORD PTR [rdx],r12
  91d1c6:	75 d8                                           	jne    0x91d1a0
  91d1c8:	48 8b 75 c0                                     	mov    rsi,QWORD PTR [rbp-0x40]
  91d1cc:	48 85 f6                                        	test   rsi,rsi
  91d1cf:	74 0d                                           	je     0x91d1de
  91d1d1:	ba 20 00 00 00                                  	mov    edx,0x20
  91d1d6:	4c 89 e7                                        	mov    rdi,r12
  91d1d9:	e8 02 ca 93 ff                                  	call   0x259be0
  91d1de:	41 8b 85 bc 00 00 00                            	mov    eax,DWORD PTR [r13+0xbc]
  91d1e5:	48 8b 4d d0                                     	mov    rcx,QWORD PTR [rbp-0x30]
  91d1e9:	48 89 df                                        	mov    rdi,rbx
  91d1ec:	45 31 f6                                        	xor    r14d,r14d
  91d1ef:	31 f6                                           	xor    esi,esi
  91d1f1:	31 d2                                           	xor    edx,edx
  91d1f3:	89 01                                           	mov    DWORD PTR [rcx],eax
  91d1f5:	48 8b 4d c8                                     	mov    rcx,QWORD PTR [rbp-0x38]
  91d1f9:	44 89 39                                        	mov    DWORD PTR [rcx],r15d
  91d1fc:	e8 ff f0 32 00                                  	call   0xc4c300
  91d201:	eb 0e                                           	jmp    0x91d211
  91d203:	41 be 03 00 00 00                               	mov    r14d,0x3
  91d209:	eb 06                                           	jmp    0x91d211
  91d20b:	41 be 09 00 00 00                               	mov    r14d,0x9
  91d211:	48 8d 3d 48 cc c6 02                            	lea    rdi,[rip+0x2c6cc48]        # 0x3589e60
  91d218:	31 f6                                           	xor    esi,esi
  91d21a:	31 d2                                           	xor    edx,edx
  91d21c:	e8 df f0 32 00                                  	call   0xc4c300
  91d221:	44 89 f0                                        	mov    eax,r14d
  91d224:	48 83 c4 18                                     	add    rsp,0x18
  91d228:	5b                                              	pop    rbx
  91d229:	41 5c                                           	pop    r12
  91d22b:	41 5d                                           	pop    r13
  91d22d:	41 5e                                           	pop    r14
  91d22f:	41 5f                                           	pop    r15
  91d231:	5d                                              	pop    rbp
  91d232:	c3                                              	ret
  91d233:	90                                              	nop
  91d234:	90                                              	nop
  91d235:	90                                              	nop
  91d236:	90                                              	nop
  91d237:	90                                              	nop
  91d238:	90                                              	nop
  91d239:	90                                              	nop
  91d23a:	90                                              	nop
  91d23b:	90                                              	nop
  91d23c:	90                                              	nop
  91d23d:	90                                              	nop
  91d23e:	90                                              	nop
  91d23f:	90                                              	nop
  91d240:	55                                              	push   rbp
  91d241:	48 89 e5                                        	mov    rbp,rsp
  91d244:	48 8d 3d fc 31 97 00                            	lea    rdi,[rip+0x9731fc]        # 0x1290447
  91d24b:	be 20 00 00 00                                  	mov    esi,0x20
  91d250:	31 d2                                           	xor    edx,edx
  91d252:	31 c9                                           	xor    ecx,ecx
  91d254:	45 31 c0                                        	xor    r8d,r8d
  91d257:	45 31 c9                                        	xor    r9d,r9d
  91d25a:	6a 00                                           	push   0x0
  91d25c:	6a 07                                           	push   0x7
  91d25e:	e8 7d de b1 ff                                  	call   0x43b0e0
  91d263:	48 83 c4 10                                     	add    rsp,0x10
  91d267:	48 89 05 fa 96 25 03                            	mov    QWORD PTR [rip+0x32596fa],rax        # 0x3b76968
  91d26e:	5d                                              	pop    rbp
  91d26f:	c3                                              	ret
  91d270:	55                                              	push   rbp
  91d271:	48 89 e5                                        	mov    rbp,rsp
  91d274:	48 8d 3d d5 96 25 03                            	lea    rdi,[rip+0x32596d5]        # 0x3b76950
  91d27b:	48 8d 35 ee 34 a2 00                            	lea    rsi,[rip+0xa234ee]        # 0x1340770
  91d282:	31 d2                                           	xor    edx,edx
  91d284:	31 c9                                           	xor    ecx,ecx
  91d286:	e8 45 ab ba ff                                  	call   0x4c7dd0
  91d28b:	48 c7 05 ca 96 25 03 00 00 00 00                	mov    QWORD PTR [rip+0x32596ca],0x0        # 0x3b76960
  91d296:	48 8d 3d d6 83 a5 00                            	lea    rdi,[rip+0xa583d6]        # 0x1375673
  91d29d:	be 30 00 00 00                                  	mov    esi,0x30
  91d2a2:	31 d2                                           	xor    edx,edx
  91d2a4:	31 c9                                           	xor    ecx,ecx
  91d2a6:	45 31 c0                                        	xor    r8d,r8d
  91d2a9:	45 31 c9                                        	xor    r9d,r9d
  91d2ac:	6a 00                                           	push   0x0
  91d2ae:	6a 07                                           	push   0x7
  91d2b0:	e8 2b de b1 ff                                  	call   0x43b0e0
  91d2b5:	48 83 c4 10                                     	add    rsp,0x10
  91d2b9:	48 89 05 98 96 25 03                            	mov    QWORD PTR [rip+0x3259698],rax        # 0x3b76958
  91d2c0:	5d                                              	pop    rbp
  91d2c1:	c3                                              	ret
  91d2c2:	90                                              	nop
  91d2c3:	90                                              	nop
  91d2c4:	90                                              	nop
  91d2c5:	90                                              	nop
  91d2c6:	90                                              	nop
  91d2c7:	90                                              	nop
  91d2c8:	90                                              	nop
  91d2c9:	90                                              	nop
  91d2ca:	90                                              	nop
  91d2cb:	90                                              	nop
  91d2cc:	90                                              	nop
  91d2cd:	90                                              	nop
  91d2ce:	90                                              	nop
  91d2cf:	90                                              	nop
  91d2d0:	83 ff 14                                        	cmp    edi,0x14
  91d2d3:	77 1b                                           	ja     0x91d2f0
  91d2d5:	b8 ff fb 1f 00                                  	mov    eax,0x1ffbff
  91d2da:	c4 e2 43 f7 c0                                  	shrx   eax,eax,edi
  91d2df:	a8 01                                           	test   al,0x1
  91d2e1:	74 0d                                           	je     0x91d2f0
  91d2e3:	89 f8                                           	mov    eax,edi
  91d2e5:	48 8d 0d c4 01 f0 00                            	lea    rcx,[rip+0xf001c4]        # 0x181d4b0
  91d2ec:	8b 04 81                                        	mov    eax,DWORD PTR [rcx+rax*4]
  91d2ef:	c3                                              	ret
  91d2f0:	55                                              	push   rbp
  91d2f1:	48 89 e5                                        	mov    rbp,rsp
  91d2f4:	53                                              	push   rbx
  91d2f5:	50                                              	push   rax
  91d2f6:	89 fb                                           	mov    ebx,edi
  91d2f8:	e8 53 46 ed ff                                  	call   0x7f1950
  91d2fd:	48 63 f3                                        	movsxd rsi,ebx
  91d300:	48 8d 3d e9 ff ff ff                            	lea    rdi,[rip+0xffffffffffffffe9]        # 0x91d2f0
  91d307:	e8 94 45 ed ff                                  	call   0x7f18a0
  91d30c:	48 8d 35 8f 74 97 00                            	lea    rsi,[rip+0x97748f]        # 0x12947a2
  91d313:	bf 03 00 00 00                                  	mov    edi,0x3
  91d318:	89 da                                           	mov    edx,ebx
  91d31a:	31 c0                                           	xor    eax,eax
  91d31c:	e8 ef d6 37 00                                  	call   0xc9aa10
  91d321:	0f 0b                                           	ud2
  91d323:	90                                              	nop
  91d324:	90                                              	nop
  91d325:	90                                              	nop
  91d326:	90                                              	nop
  91d327:	90                                              	nop
  91d328:	90                                              	nop
  91d329:	90                                              	nop
  91d32a:	90                                              	nop
  91d32b:	90                                              	nop
  91d32c:	90                                              	nop
  91d32d:	90                                              	nop
  91d32e:	90                                              	nop
  91d32f:	90                                              	nop
  91d330:	55                                              	push   rbp
  91d331:	48 89 e5                                        	mov    rbp,rsp
  91d334:	b8 2d 00 00 00                                  	mov    eax,0x2d
  91d339:	5d                                              	pop    rbp
  91d33a:	c3                                              	ret
  91d33b:	90                                              	nop
  91d33c:	90                                              	nop
  91d33d:	90                                              	nop
  91d33e:	90                                              	nop
  91d33f:	90                                              	nop
  91d340:	55                                              	push   rbp
  91d341:	48 89 e5                                        	mov    rbp,rsp
  91d344:	b8 2d 00 00 00                                  	mov    eax,0x2d
  91d349:	5d                                              	pop    rbp
  91d34a:	c3                                              	ret
  91d34b:	90                                              	nop
  91d34c:	90                                              	nop
  91d34d:	90                                              	nop
  91d34e:	90                                              	nop
  91d34f:	90                                              	nop
  91d350:	55                                              	push   rbp
  91d351:	48 89 e5                                        	mov    rbp,rsp
  91d354:	41 57                                           	push   r15
  91d356:	41 56                                           	push   r14
  91d358:	53                                              	push   rbx
  91d359:	50                                              	push   rax
  91d35a:	48 8b 07                                        	mov    rax,QWORD PTR [rdi]
  91d35d:	49 89 f7                                        	mov    r15,rsi
  91d360:	31 f6                                           	xor    esi,esi
  91d362:	31 d2                                           	xor    edx,edx
  91d364:	49 81 c7 ff 3f 00 00                            	add    r15,0x3fff
  91d36b:	49 c1 ff 0e                                     	sar    r15,0xe
  91d36f:	4c 8b 30                                        	mov    r14,QWORD PTR [rax]
  91d372:	49 8d 5e 18                                     	lea    rbx,[r14+0x18]
  91d376:	48 89 df                                        	mov    rdi,rbx
  91d379:	e8 22 73 eb ff                                  	call   0x7d46a0
  91d37e:	4c 89 fe                                        	mov    rsi,r15
  91d381:	41 bf 2d 00 00 00                               	mov    r15d,0x2d
  91d387:	49 3b b6 88 00 00 00                            	cmp    rsi,QWORD PTR [r14+0x88]
  91d38e:	72 0b                                           	jb     0x91d39b
  91d390:	4c 89 f7                                        	mov    rdi,r14
  91d393:	e8 68 e6 ff ff                                  	call   0x91ba00
  91d398:	41 89 c7                                        	mov    r15d,eax
  91d39b:	48 89 df                                        	mov    rdi,rbx
  91d39e:	31 f6                                           	xor    esi,esi
  91d3a0:	31 d2                                           	xor    edx,edx
  91d3a2:	e8 09 7b eb ff                                  	call   0x7d4eb0
  91d3a7:	44 89 f8                                        	mov    eax,r15d
  91d3aa:	48 83 c4 08                                     	add    rsp,0x8
  91d3ae:	5b                                              	pop    rbx
  91d3af:	41 5e                                           	pop    r14
  91d3b1:	41 5f                                           	pop    r15
  91d3b3:	5d                                              	pop    rbp
  91d3b4:	c3                                              	ret
  91d3b5:	90                                              	nop
  91d3b6:	90                                              	nop
  91d3b7:	90                                              	nop
  91d3b8:	90                                              	nop
  91d3b9:	90                                              	nop
  91d3ba:	90                                              	nop
  91d3bb:	90                                              	nop
  91d3bc:	90                                              	nop
  91d3bd:	90                                              	nop
  91d3be:	90                                              	nop
  91d3bf:	90                                              	nop
  91d3c0:	b8 19 00 00 00                                  	mov    eax,0x19
  91d3c5:	48 81 fe 00 a2 04 40                            	cmp    rsi,0x4004a200
  91d3cc:	75 15                                           	jne    0x91d3e3
  91d3ce:	55                                              	push   rbp
  91d3cf:	48 89 e5                                        	mov    rbp,rsp
  91d3d2:	48 8b 07                                        	mov    rax,QWORD PTR [rdi]
  91d3d5:	31 c9                                           	xor    ecx,ecx
  91d3d7:	83 78 18 00                                     	cmp    DWORD PTR [rax+0x18],0x0
  91d3db:	0f 95 c1                                        	setne  cl
  91d3de:	31 c0                                           	xor    eax,eax
  91d3e0:	89 0a                                           	mov    DWORD PTR [rdx],ecx
  91d3e2:	5d                                              	pop    rbp
  91d3e3:	c3                                              	ret
  91d3e4:	90                                              	nop
  91d3e5:	90                                              	nop
  91d3e6:	90                                              	nop
  91d3e7:	90                                              	nop
  91d3e8:	90                                              	nop
  91d3e9:	90                                              	nop
  91d3ea:	90                                              	nop
  91d3eb:	90                                              	nop
  91d3ec:	90                                              	nop
  91d3ed:	90                                              	nop
  91d3ee:	90                                              	nop
  91d3ef:	90                                              	nop
  91d3f0:	55                                              	push   rbp
  91d3f1:	48 89 e5                                        	mov    rbp,rsp
  91d3f4:	b8 2d 00 00 00                                  	mov    eax,0x2d
  91d3f9:	5d                                              	pop    rbp
  91d3fa:	c3                                              	ret
  91d3fb:	90                                              	nop
  91d3fc:	90                                              	nop
  91d3fd:	90                                              	nop
  91d3fe:	90                                              	nop
  91d3ff:	90                                              	nop
  91d400:	55                                              	push   rbp
  91d401:	48 89 e5                                        	mov    rbp,rsp
  91d404:	b8 2d 00 00 00                                  	mov    eax,0x2d
  91d409:	5d                                              	pop    rbp
  91d40a:	c3                                              	ret
  91d40b:	90                                              	nop
  91d40c:	90                                              	nop
  91d40d:	90                                              	nop
  91d40e:	90                                              	nop
  91d40f:	90                                              	nop
  91d410:	55                                              	push   rbp
  91d411:	48 89 e5                                        	mov    rbp,rsp
  91d414:	41 57                                           	push   r15
  91d416:	41 56                                           	push   r14
  91d418:	41 54                                           	push   r12
  91d41a:	53                                              	push   rbx
  91d41b:	4c 8b 3f                                        	mov    r15,QWORD PTR [rdi]
  91d41e:	48 89 f3                                        	mov    rbx,rsi
  91d421:	31 f6                                           	xor    esi,esi
  91d423:	31 d2                                           	xor    edx,edx
  91d425:	4d 8b 27                                        	mov    r12,QWORD PTR [r15]
  91d428:	4d 8d 74 24 18                                  	lea    r14,[r12+0x18]
  91d42d:	4c 89 f7                                        	mov    rdi,r14
  91d430:	e8 6b 72 eb ff                                  	call   0x7d46a0
  91d435:	4d 8b a4 24 88 00 00 00                         	mov    r12,QWORD PTR [r12+0x88]
  91d43d:	4c 89 f7                                        	mov    rdi,r14
  91d440:	31 f6                                           	xor    esi,esi
  91d442:	31 d2                                           	xor    edx,edx
  91d444:	e8 67 7a eb ff                                  	call   0x7d4eb0
  91d449:	be 78 00 00 00                                  	mov    esi,0x78
  91d44e:	48 89 df                                        	mov    rdi,rbx
  91d451:	e8 9a bb 93 ff                                  	call   0x258ff0
  91d456:	4c 89 e0                                        	mov    rax,r12
  91d459:	c7 43 58 00 40 00 00                            	mov    DWORD PTR [rbx+0x58],0x4000
  91d460:	48 c1 e0 0e                                     	shl    rax,0xe
  91d464:	48 89 43 48                                     	mov    QWORD PTR [rbx+0x48],rax
  91d468:	4c 89 63 50                                     	mov    QWORD PTR [rbx+0x50],r12
  91d46c:	b8 00 90 00 00                                  	mov    eax,0x9000
  91d471:	41 0b 47 10                                     	or     eax,DWORD PTR [r15+0x10]
  91d475:	66 89 43 08                                     	mov    WORD PTR [rbx+0x8],ax
  91d479:	41 8b 47 08                                     	mov    eax,DWORD PTR [r15+0x8]
  91d47d:	89 43 0c                                        	mov    DWORD PTR [rbx+0xc],eax
  91d480:	41 8b 47 0c                                     	mov    eax,DWORD PTR [r15+0xc]
  91d484:	89 43 10                                        	mov    DWORD PTR [rbx+0x10],eax
  91d487:	31 c0                                           	xor    eax,eax
  91d489:	5b                                              	pop    rbx
  91d48a:	41 5c                                           	pop    r12
  91d48c:	41 5e                                           	pop    r14
  91d48e:	41 5f                                           	pop    r15
  91d490:	5d                                              	pop    rbp
  91d491:	c3                                              	ret
  91d492:	90                                              	nop
  91d493:	90                                              	nop
  91d494:	90                                              	nop
  91d495:	90                                              	nop
  91d496:	90                                              	nop
  91d497:	90                                              	nop
  91d498:	90                                              	nop
  91d499:	90                                              	nop
  91d49a:	90                                              	nop
  91d49b:	90                                              	nop
  91d49c:	90                                              	nop
  91d49d:	90                                              	nop
  91d49e:	90                                              	nop
  91d49f:	90                                              	nop
  91d4a0:	55                                              	push   rbp
  91d4a1:	48 89 e5                                        	mov    rbp,rsp
  91d4a4:	53                                              	push   rbx
  91d4a5:	50                                              	push   rax
  91d4a6:	48 8b 1f                                        	mov    rbx,QWORD PTR [rdi]
  91d4a9:	48 c7 07 00 00 00 00                            	mov    QWORD PTR [rdi],0x0
  91d4b0:	b8 ff ff ff ff                                  	mov    eax,0xffffffff
  91d4b5:	f0 0f c1 43 14                                  	lock xadd DWORD PTR [rbx+0x14],eax
  91d4ba:	83 f8 01                                        	cmp    eax,0x1
  91d4bd:	75 19                                           	jne    0x91d4d8
  91d4bf:	48 8b 3b                                        	mov    rdi,QWORD PTR [rbx]
  91d4c2:	e8 d9 46 b4 ff                                  	call   0x461ba0
  91d4c7:	48 8b 3d 9a 94 25 03                            	mov    rdi,QWORD PTR [rip+0x325949a]        # 0x3b76968
  91d4ce:	48 89 de                                        	mov    rsi,rbx
  91d4d1:	31 d2                                           	xor    edx,edx
  91d4d3:	e8 e8 eb b1 ff                                  	call   0x43c0c0
  91d4d8:	31 c0                                           	xor    eax,eax
  91d4da:	48 83 c4 08                                     	add    rsp,0x8
  91d4de:	5b                                              	pop    rbx
  91d4df:	5d                                              	pop    rbp
  91d4e0:	c3                                              	ret
  91d4e1:	90                                              	nop
  91d4e2:	90                                              	nop
  91d4e3:	90                                              	nop
  91d4e4:	90                                              	nop
  91d4e5:	90                                              	nop
  91d4e6:	90                                              	nop
  91d4e7:	90                                              	nop
  91d4e8:	90                                              	nop
  91d4e9:	90                                              	nop
  91d4ea:	90                                              	nop
  91d4eb:	90                                              	nop
  91d4ec:	90                                              	nop
  91d4ed:	90                                              	nop
  91d4ee:	90                                              	nop
  91d4ef:	90                                              	nop
  91d4f0:	55                                              	push   rbp
  91d4f1:	48 89 e5                                        	mov    rbp,rsp
  91d4f4:	b8 2d 00 00 00                                  	mov    eax,0x2d
  91d4f9:	5d                                              	pop    rbp
  91d4fa:	c3                                              	ret
  91d4fb:	90                                              	nop
  91d4fc:	90                                              	nop
  91d4fd:	90                                              	nop
  91d4fe:	90                                              	nop
  91d4ff:	90                                              	nop
  91d500:	55                                              	push   rbp
  91d501:	48 89 e5                                        	mov    rbp,rsp
  91d504:	b8 2d 00 00 00                                  	mov    eax,0x2d
  91d509:	5d                                              	pop    rbp
  91d50a:	c3                                              	ret
  91d50b:	90                                              	nop
  91d50c:	90                                              	nop
  91d50d:	90                                              	nop
  91d50e:	90                                              	nop
  91d50f:	90                                              	nop
  91d510:	55                                              	push   rbp
  91d511:	48 89 e5                                        	mov    rbp,rsp
  91d514:	c7 46 04 ff 00 00 00                            	mov    DWORD PTR [rsi+0x4],0xff
  91d51b:	31 c0                                           	xor    eax,eax
  91d51d:	5d                                              	pop    rbp
  91d51e:	c3                                              	ret
  91d51f:	90                                              	nop
  91d520:	55                                              	push   rbp
  91d521:	48 89 e5                                        	mov    rbp,rsp
  91d524:	41 57                                           	push   r15
  91d526:	41 56                                           	push   r14
  91d528:	41 55                                           	push   r13
  91d52a:	41 54                                           	push   r12
  91d52c:	53                                              	push   rbx
  91d52d:	50                                              	push   rax
  91d52e:	8b 45 10                                        	mov    eax,DWORD PTR [rbp+0x10]
  91d531:	41 be 16 00 00 00                               	mov    r14d,0x16
  91d537:	a8 02                                           	test   al,0x2
  91d539:	75 6e                                           	jne    0x91d5a9
  91d53b:	8b 47 24                                        	mov    eax,DWORD PTR [rdi+0x24]
  91d53e:	48 89 4d d0                                     	mov    QWORD PTR [rbp-0x30],rcx
  91d542:	b9 11 00 00 00                                  	mov    ecx,0x11
  91d547:	49 89 d7                                        	mov    r15,rdx
  91d54a:	45 89 c4                                        	mov    r12d,r8d
  91d54d:	49 89 f5                                        	mov    r13,rsi
  91d550:	83 e0 01                                        	and    eax,0x1
  91d553:	0f 44 c8                                        	cmove  ecx,eax
  91d556:	8b 47 24                                        	mov    eax,DWORD PTR [rdi+0x24]
  91d559:	48 8b 1f                                        	mov    rbx,QWORD PTR [rdi]
  91d55c:	8d 51 22                                        	lea    edx,[rcx+0x22]
  91d55f:	48 8b 3b                                        	mov    rdi,QWORD PTR [rbx]
  91d562:	a8 02                                           	test   al,0x2
  91d564:	0f 44 d1                                        	cmove  edx,ecx
  91d567:	41 21 d1                                        	and    r9d,edx
  91d56a:	45 89 ce                                        	mov    r14d,r9d
  91d56d:	e8 ae 45 b4 ff                                  	call   0x461b20
  91d572:	48 8b 55 d0                                     	mov    rdx,QWORD PTR [rbp-0x30]
  91d576:	44 8b 4d 10                                     	mov    r9d,DWORD PTR [rbp+0x10]
  91d57a:	41 0f b7 cc                                     	movzx  ecx,r12w
  91d57e:	4c 89 ef                                        	mov    rdi,r13
  91d581:	4c 89 fe                                        	mov    rsi,r15
  91d584:	45 89 f0                                        	mov    r8d,r14d
  91d587:	ff 75 20                                        	push   QWORD PTR [rbp+0x20]
  91d58a:	6a 00                                           	push   0x0
  91d58c:	ff 75 18                                        	push   QWORD PTR [rbp+0x18]
  91d58f:	ff 33                                           	push   QWORD PTR [rbx]
  91d591:	e8 9a c9 19 00                                  	call   0xab9f30
  91d596:	48 83 c4 20                                     	add    rsp,0x20
  91d59a:	45 31 f6                                        	xor    r14d,r14d
  91d59d:	85 c0                                           	test   eax,eax
  91d59f:	74 08                                           	je     0x91d5a9
  91d5a1:	48 8b 3b                                        	mov    rdi,QWORD PTR [rbx]
  91d5a4:	e8 f7 45 b4 ff                                  	call   0x461ba0
  91d5a9:	44 89 f0                                        	mov    eax,r14d
  91d5ac:	48 83 c4 08                                     	add    rsp,0x8
  91d5b0:	5b                                              	pop    rbx
  91d5b1:	41 5c                                           	pop    r12
  91d5b3:	41 5d                                           	pop    r13
  91d5b5:	41 5e                                           	pop    r14
  91d5b7:	41 5f                                           	pop    r15
  91d5b9:	5d                                              	pop    rbp
  91d5ba:	c3                                              	ret
  91d5bb:	90                                              	nop
  91d5bc:	90                                              	nop
  91d5bd:	90                                              	nop
  91d5be:	90                                              	nop
  91d5bf:	90                                              	nop
  91d5c0:	55                                              	push   rbp
  91d5c1:	48 89 e5                                        	mov    rbp,rsp
  91d5c4:	41 57                                           	push   r15
  91d5c6:	41 56                                           	push   r14
  91d5c8:	41 55                                           	push   r13
  91d5ca:	41 54                                           	push   r12
  91d5cc:	53                                              	push   rbx
  91d5cd:	48 83 ec 28                                     	sub    rsp,0x28
  91d5d1:	48 8d 1d 38 ed ff 02                            	lea    rbx,[rip+0x2ffed38]        # 0x391c310
  91d5d8:	bf 01 00 00 00                                  	mov    edi,0x1
  91d5dd:	48 8b 03                                        	mov    rax,QWORD PTR [rbx]
  91d5e0:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  91d5e4:	48 c7 45 c0 00 00 00 00                         	mov    QWORD PTR [rbp-0x40],0x0
  91d5ec:	e8 af a8 19 00                                  	call   0xab7ea0
  91d5f1:	41 89 c7                                        	mov    r15d,eax
  91d5f4:	85 c0                                           	test   eax,eax
  91d5f6:	75 2e                                           	jne    0x91d626
  91d5f8:	48 83 3d 98 c0 0a 03 00                         	cmp    QWORD PTR [rip+0x30ac098],0x0        # 0x39c9698
  91d600:	74 43                                           	je     0x91d645
  91d602:	bf 01 00 00 00                                  	mov    edi,0x1
  91d607:	e8 14 a9 19 00                                  	call   0xab7f20
  91d60c:	48 8d 35 4b 8a a1 00                            	lea    rsi,[rip+0xa18a4b]        # 0x133605e
  91d613:	48 8d 0d 86 c0 0a 03                            	lea    rcx,[rip+0x30ac086]        # 0x39c96a0
  91d61a:	31 ff                                           	xor    edi,edi
  91d61c:	31 d2                                           	xor    edx,edx
  91d61e:	e8 dd 98 1a 00                                  	call   0xac6f00
  91d623:	41 89 c7                                        	mov    r15d,eax
  91d626:	48 8b 03                                        	mov    rax,QWORD PTR [rbx]
  91d629:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  91d62d:	0f 85 65 02 00 00                               	jne    0x91d898
  91d633:	44 89 f8                                        	mov    eax,r15d
  91d636:	48 83 c4 28                                     	add    rsp,0x28
  91d63a:	5b                                              	pop    rbx
  91d63b:	41 5c                                           	pop    r12
  91d63d:	41 5d                                           	pop    r13
  91d63f:	41 5e                                           	pop    r14
  91d641:	41 5f                                           	pop    r15
  91d643:	5d                                              	pop    rbp
  91d644:	c3                                              	ret
  91d645:	48 8d 05 24 c0 0a 03                            	lea    rax,[rip+0x30ac024]        # 0x39c9670
  91d64c:	48 8d 1d 2d 67 56 00                            	lea    rbx,[rip+0x56672d]        # 0xe83d80
  91d653:	4c 8d 2d 71 90 9b 00                            	lea    r13,[rip+0x9b9071]        # 0x12d66cb
  91d65a:	4c 8d 35 76 25 a0 00                            	lea    r14,[rip+0xa02576]        # 0x131fbd7
  91d661:	48 89 05 30 c0 0a 03                            	mov    QWORD PTR [rip+0x30ac030],rax        # 0x39c9698
  91d668:	eb 39                                           	jmp    0x91d6a3
  91d66a:	66 0f 1f 44 00 00                               	nop    WORD PTR [rax+rax*1+0x0]
  91d670:	48 8d 3d b1 fe ef 00                            	lea    rdi,[rip+0xeffeb1]        # 0x181d528
  91d677:	be 7c 00 00 00                                  	mov    esi,0x7c
  91d67c:	89 c2                                           	mov    edx,eax
  91d67e:	48 8d 0d cb 2d 97 00                            	lea    rcx,[rip+0x972dcb]        # 0x1290450
  91d685:	4d 89 e8                                        	mov    r8,r13
  91d688:	41 89 c7                                        	mov    r15d,eax
  91d68b:	31 c0                                           	xor    eax,eax
  91d68d:	e8 fe a3 dd ff                                  	call   0x6f7a90
  91d692:	4c 8b 6b 18                                     	mov    r13,QWORD PTR [rbx+0x18]
  91d696:	48 83 c3 18                                     	add    rbx,0x18
  91d69a:	4d 85 ed                                        	test   r13,r13
  91d69d:	0f 84 ad 01 00 00                               	je     0x91d850
  91d6a3:	4c 89 ef                                        	mov    rdi,r13
  91d6a6:	4c 89 f6                                        	mov    rsi,r14
  91d6a9:	e8 02 e3 94 ff                                  	call   0x26b9b0
  91d6ae:	44 0f b6 63 08                                  	movzx  r12d,BYTE PTR [rbx+0x8]
  91d6b3:	48 8d 45 c8                                     	lea    rax,[rbp-0x38]
  91d6b7:	4c 89 ee                                        	mov    rsi,r13
  91d6ba:	b9 02 00 00 00                                  	mov    ecx,0x2
  91d6bf:	31 ff                                           	xor    edi,edi
  91d6c1:	45 31 c0                                        	xor    r8d,r8d
  91d6c4:	45 31 c9                                        	xor    r9d,r9d
  91d6c7:	48 89 04 24                                     	mov    QWORD PTR [rsp],rax
  91d6cb:	44 89 e2                                        	mov    edx,r12d
  91d6ce:	e8 cd 01 00 00                                  	call   0x91d8a0
  91d6d3:	85 c0                                           	test   eax,eax
  91d6d5:	75 99                                           	jne    0x91d670
  91d6d7:	4c 8b 73 10                                     	mov    r14,QWORD PTR [rbx+0x10]
  91d6db:	4d 85 f6                                        	test   r14,r14
  91d6de:	0f 84 8b 00 00 00                               	je     0x91d76f
  91d6e4:	48 89 df                                        	mov    rdi,rbx
  91d6e7:	48 8d 75 c0                                     	lea    rsi,[rbp-0x40]
  91d6eb:	e8 c0 16 05 00                                  	call   0x96edb0
  91d6f0:	41 89 c7                                        	mov    r15d,eax
  91d6f3:	85 c0                                           	test   eax,eax
  91d6f5:	74 1d                                           	je     0x91d714
  91d6f7:	48 8d 3d 2a fe ef 00                            	lea    rdi,[rip+0xeffe2a]        # 0x181d528
  91d6fe:	be 8b 00 00 00                                  	mov    esi,0x8b
  91d703:	48 8d 15 0b 89 a3 00                            	lea    rdx,[rip+0xa3890b]        # 0x1356015
  91d70a:	4c 89 e9                                        	mov    rcx,r13
  91d70d:	31 c0                                           	xor    eax,eax
  91d70f:	e8 dc a2 dd ff                                  	call   0x6f79f0
  91d714:	48 83 7d c0 00                                  	cmp    QWORD PTR [rbp-0x40],0x0
  91d719:	75 04                                           	jne    0x91d71f
  91d71b:	4c 89 75 c0                                     	mov    QWORD PTR [rbp-0x40],r14
  91d71f:	48 8d 3d 02 fe ef 00                            	lea    rdi,[rip+0xeffe02]        # 0x181d528
  91d726:	be 99 00 00 00                                  	mov    esi,0x99
  91d72b:	ba 10 00 00 00                                  	mov    edx,0x10
  91d730:	44 89 e1                                        	mov    ecx,r12d
  91d733:	e8 e8 ed 38 00                                  	call   0xcac520
  91d738:	48 85 c0                                        	test   rax,rax
  91d73b:	0f 84 2e 01 00 00                               	je     0x91d86f
  91d741:	49 89 c6                                        	mov    r14,rax
  91d744:	41 8d 44 24 ff                                  	lea    eax,[r12-0x1]
  91d749:	83 f8 08                                        	cmp    eax,0x8
  91d74c:	0f 87 cd 00 00 00                               	ja     0x91d81f
  91d752:	48 8d 0d ab fd ef 00                            	lea    rcx,[rip+0xeffdab]        # 0x181d504
  91d759:	48 63 04 81                                     	movsxd rax,DWORD PTR [rcx+rax*4]
  91d75d:	48 01 c8                                        	add    rax,rcx
  91d760:	ff e0                                           	jmp    rax
  91d762:	48 8b 45 c0                                     	mov    rax,QWORD PTR [rbp-0x40]
  91d766:	49 89 46 10                                     	mov    QWORD PTR [r14+0x10],rax
  91d76a:	e9 9a 00 00 00                                  	jmp    0x91d809
  91d76f:	45 31 ff                                        	xor    r15d,r15d
  91d772:	e9 cd 00 00 00                                  	jmp    0x91d844
  91d777:	0f b6 45 c0                                     	movzx  eax,BYTE PTR [rbp-0x40]
  91d77b:	41 88 46 0e                                     	mov    BYTE PTR [r14+0xe],al
  91d77f:	41 80 4e 0c 04                                  	or     BYTE PTR [r14+0xc],0x4
  91d784:	48 8d 05 9d c5 94 ff                            	lea    rax,[rip+0xffffffffff94c59d]        # 0x269d28
  91d78b:	41 c6 46 0d 02                                  	mov    BYTE PTR [r14+0xd],0x2
  91d790:	49 89 46 28                                     	mov    QWORD PTR [r14+0x28],rax
  91d794:	eb 73                                           	jmp    0x91d809
  91d796:	48 8b 7d c0                                     	mov    rdi,QWORD PTR [rbp-0x40]
  91d79a:	e8 01 50 f1 ff                                  	call   0x8327a0
  91d79f:	41 89 46 18                                     	mov    DWORD PTR [r14+0x18],eax
  91d7a3:	48 8b 45 c0                                     	mov    rax,QWORD PTR [rbp-0x40]
  91d7a7:	49 89 46 10                                     	mov    QWORD PTR [r14+0x10],rax
  91d7ab:	41 80 4e 0c 02                                  	or     BYTE PTR [r14+0xc],0x2
  91d7b0:	eb 57                                           	jmp    0x91d809
  91d7b2:	48 8b 45 c8                                     	mov    rax,QWORD PTR [rbp-0x38]
  91d7b6:	4c 89 f7                                        	mov    rdi,r14
  91d7b9:	48 83 c7 10                                     	add    rdi,0x10
  91d7bd:	49 89 46 38                                     	mov    QWORD PTR [r14+0x38],rax
  91d7c1:	0f b6 45 c0                                     	movzx  eax,BYTE PTR [rbp-0x40]
  91d7c5:	fe c8                                           	dec    al
  91d7c7:	41 88 46 0d                                     	mov    BYTE PTR [r14+0xd],al
  91d7cb:	e8 00 c8 a5 ff                                  	call   0x379fd0
  91d7d0:	85 c0                                           	test   eax,eax
  91d7d2:	0f 85 9f 00 00 00                               	jne    0x91d877
  91d7d8:	4c 89 ef                                        	mov    rdi,r13
  91d7db:	48 8d 35 d0 fa 98 00                            	lea    rsi,[rip+0x98fad0]        # 0x12ad2b2
  91d7e2:	e8 c9 e1 94 ff                                  	call   0x26b9b0
  91d7e7:	85 c0                                           	test   eax,eax
  91d7e9:	75 1e                                           	jne    0x91d809
  91d7eb:	bf 01 00 00 00                                  	mov    edi,0x1
  91d7f0:	48 8d 15 71 bd 0a 03                            	lea    rdx,[rip+0x30abd71]        # 0x39c9568
  91d7f7:	31 f6                                           	xor    esi,esi
  91d7f9:	4c 89 35 60 bd 0a 03                            	mov    QWORD PTR [rip+0x30abd60],r14        # 0x39c9560
  91d800:	e8 1b c3 a5 ff                                  	call   0x379b20
  91d805:	85 c0                                           	test   eax,eax
  91d807:	75 6e                                           	jne    0x91d877
  91d809:	48 8b 7d c8                                     	mov    rdi,QWORD PTR [rbp-0x38]
  91d80d:	41 0f b6 56 09                                  	movzx  edx,BYTE PTR [r14+0x9]
  91d812:	4c 89 f6                                        	mov    rsi,r14
  91d815:	e8 86 b7 cb ff                                  	call   0x5d8fa0
  91d81a:	41 89 c7                                        	mov    r15d,eax
  91d81d:	eb 1d                                           	jmp    0x91d83c
  91d81f:	48 8d 3d 02 fd ef 00                            	lea    rdi,[rip+0xeffd02]        # 0x181d528
  91d826:	be e9 00 00 00                                  	mov    esi,0xe9
  91d82b:	48 8d 15 72 60 9a 00                            	lea    rdx,[rip+0x9a6072]        # 0x12c38a4
  91d832:	44 89 e1                                        	mov    ecx,r12d
  91d835:	31 c0                                           	xor    eax,eax
  91d837:	e8 b4 a1 dd ff                                  	call   0x6f79f0
  91d83c:	4c 89 f7                                        	mov    rdi,r14
  91d83f:	e8 7c cc 22 00                                  	call   0xb4a4c0
  91d844:	4c 8d 35 8c 23 a0 00                            	lea    r14,[rip+0xa0238c]        # 0x131fbd7
  91d84b:	e9 42 fe ff ff                                  	jmp    0x91d692
  91d850:	bf 01 00 00 00                                  	mov    edi,0x1
  91d855:	e8 c6 a6 19 00                                  	call   0xab7f20
  91d85a:	48 8d 1d af ea ff 02                            	lea    rbx,[rip+0x2ffeaaf]        # 0x391c310
  91d861:	45 85 ff                                        	test   r15d,r15d
  91d864:	0f 85 bc fd ff ff                               	jne    0x91d626
  91d86a:	e9 9d fd ff ff                                  	jmp    0x91d60c
  91d86f:	41 bf 04 00 00 00                               	mov    r15d,0x4
  91d875:	eb 0b                                           	jmp    0x91d882
  91d877:	4c 89 f7                                        	mov    rdi,r14
  91d87a:	41 89 c7                                        	mov    r15d,eax
  91d87d:	e8 3e cc 22 00                                  	call   0xb4a4c0
  91d882:	48 8d 1d 87 ea ff 02                            	lea    rbx,[rip+0x2ffea87]        # 0x391c310
  91d889:	bf 01 00 00 00                                  	mov    edi,0x1
  91d88e:	e8 8d a6 19 00                                  	call   0xab7f20
  91d893:	e9 8e fd ff ff                                  	jmp    0x91d626
  91d898:	e8 13 fe dd ff                                  	call   0x6fd6b0
  91d89d:	0f 0b                                           	ud2
  91d89f:	90                                              	nop
  91d8a0:	55                                              	push   rbp
  91d8a1:	48 89 e5                                        	mov    rbp,rsp
  91d8a4:	41 57                                           	push   r15
  91d8a6:	41 56                                           	push   r14
  91d8a8:	41 55                                           	push   r13
  91d8aa:	41 54                                           	push   r12
  91d8ac:	53                                              	push   rbx
  91d8ad:	48 83 ec 38                                     	sub    rsp,0x38
  91d8b1:	4c 8d 3d 58 ea ff 02                            	lea    r15,[rip+0x2ffea58]        # 0x391c310
  91d8b8:	89 4d b0                                        	mov    DWORD PTR [rbp-0x50],ecx
  91d8bb:	4c 8b 65 10                                     	mov    r12,QWORD PTR [rbp+0x10]
  91d8bf:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  91d8c2:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  91d8c6:	4d 85 e4                                        	test   r12,r12
  91d8c9:	74 5d                                           	je     0x91d928
  91d8cb:	49 c7 04 24 00 00 00 00                         	mov    QWORD PTR [r12],0x0
  91d8d3:	ff 05 7b bd 0a 03                               	inc    DWORD PTR [rip+0x30abd7b]        # 0x39c9654
  91d8d9:	41 89 d6                                        	mov    r14d,edx
  91d8dc:	48 8b 15 b5 bd 0a 03                            	mov    rdx,QWORD PTR [rip+0x30abdb5]        # 0x39c9698
  91d8e3:	48 85 d2                                        	test   rdx,rdx
  91d8e6:	74 4a                                           	je     0x91d932
  91d8e8:	44 89 45 b4                                     	mov    DWORD PTR [rbp-0x4c],r8d
  91d8ec:	4c 89 4d b8                                     	mov    QWORD PTR [rbp-0x48],r9
  91d8f0:	48 85 ff                                        	test   rdi,rdi
  91d8f3:	74 7c                                           	je     0x91d971
  91d8f5:	4c 8b 6f 10                                     	mov    r13,QWORD PTR [rdi+0x10]
  91d8f9:	4d 85 ed                                        	test   r13,r13
  91d8fc:	74 73                                           	je     0x91d971
  91d8fe:	41 80 7d 08 0f                                  	cmp    BYTE PTR [r13+0x8],0xf
  91d903:	75 37                                           	jne    0x91d93c
  91d905:	f6 45 b4 10                                     	test   BYTE PTR [rbp-0x4c],0x10
  91d909:	75 63                                           	jne    0x91d96e
  91d90b:	41 0f b6 7d 09                                  	movzx  edi,BYTE PTR [r13+0x9]
  91d910:	48 89 f3                                        	mov    rbx,rsi
  91d913:	e8 98 95 1a 00                                  	call   0xac6eb0
  91d918:	4c 89 ea                                        	mov    rdx,r13
  91d91b:	85 c0                                           	test   eax,eax
  91d91d:	0f 84 ab 02 00 00                               	je     0x91dbce
  91d923:	48 89 de                                        	mov    rsi,rbx
  91d926:	eb 49                                           	jmp    0x91d971
  91d928:	b8 01 10 00 00                                  	mov    eax,0x1001
  91d92d:	e9 80 02 00 00                                  	jmp    0x91dbb2
  91d932:	b8 03 00 00 00                                  	mov    eax,0x3
  91d937:	e9 76 02 00 00                                  	jmp    0x91dbb2
  91d93c:	4c 89 ef                                        	mov    rdi,r13
  91d93f:	e8 8c c3 ba ff                                  	call   0x4c9cd0
  91d944:	49 89 c0                                        	mov    r8,rax
  91d947:	48 8d 3d da fb ef 00                            	lea    rdi,[rip+0xeffbda]        # 0x181d528
  91d94e:	48 8d 15 4a b7 9b 00                            	lea    rdx,[rip+0x9bb74a]        # 0x12d909f
  91d955:	be 5d 01 00 00                                  	mov    esi,0x15d
  91d95a:	4c 89 e9                                        	mov    rcx,r13
  91d95d:	31 c0                                           	xor    eax,eax
  91d95f:	e8 8c a0 dd ff                                  	call   0x6f79f0
  91d964:	b8 0f 30 00 00                                  	mov    eax,0x300f
  91d969:	e9 44 02 00 00                                  	jmp    0x91dbb2
  91d96e:	4c 89 ea                                        	mov    rdx,r13
  91d971:	48 85 f6                                        	test   rsi,rsi
  91d974:	74 22                                           	je     0x91d998
  91d976:	0f b6 06                                        	movzx  eax,BYTE PTR [rsi]
  91d979:	44 89 75 c0                                     	mov    DWORD PTR [rbp-0x40],r14d
  91d97d:	3c 5c                                           	cmp    al,0x5c
  91d97f:	75 2b                                           	jne    0x91d9ac
  91d981:	48 8b 15 10 bd 0a 03                            	mov    rdx,QWORD PTR [rip+0x30abd10]        # 0x39c9698
  91d988:	45 31 f6                                        	xor    r14d,r14d
  91d98b:	48 89 55 c8                                     	mov    QWORD PTR [rbp-0x38],rdx
  91d98f:	0f b6 46 01                                     	movzx  eax,BYTE PTR [rsi+0x1]
  91d993:	48 ff c6                                        	inc    rsi
  91d996:	eb 49                                           	jmp    0x91d9e1
  91d998:	48 8b 15 f9 bc 0a 03                            	mov    rdx,QWORD PTR [rip+0x30abcf9]        # 0x39c9698
  91d99f:	48 8b 5d b8                                     	mov    rbx,QWORD PTR [rbp-0x48]
  91d9a3:	48 89 55 c8                                     	mov    QWORD PTR [rbp-0x38],rdx
  91d9a7:	e9 c8 01 00 00                                  	jmp    0x91db74
  91d9ac:	41 be 01 00 00 00                               	mov    r14d,0x1
  91d9b2:	48 89 55 c8                                     	mov    QWORD PTR [rbp-0x38],rdx
  91d9b6:	3c 5e                                           	cmp    al,0x5e
  91d9b8:	75 27                                           	jne    0x91d9e1
  91d9ba:	48 89 f3                                        	mov    rbx,rsi
  91d9bd:	0f 1f 00                                        	nop    DWORD PTR [rax]
  91d9c0:	48 8b 52 10                                     	mov    rdx,QWORD PTR [rdx+0x10]
  91d9c4:	48 89 55 c8                                     	mov    QWORD PTR [rbp-0x38],rdx
  91d9c8:	48 85 d2                                        	test   rdx,rdx
  91d9cb:	0f 84 14 01 00 00                               	je     0x91dae5
  91d9d1:	0f b6 43 01                                     	movzx  eax,BYTE PTR [rbx+0x1]
  91d9d5:	48 ff c3                                        	inc    rbx
  91d9d8:	3c 5e                                           	cmp    al,0x5e
  91d9da:	74 e4                                           	je     0x91d9c0
  91d9dc:	45 31 f6                                        	xor    r14d,r14d
  91d9df:	eb 03                                           	jmp    0x91d9e4
  91d9e1:	48 89 f3                                        	mov    rbx,rsi
  91d9e4:	3c 2f                                           	cmp    al,0x2f
  91d9e6:	74 33                                           	je     0x91da1b
  91d9e8:	0f b6 c8                                        	movzx  ecx,al
  91d9eb:	83 f9 2e                                        	cmp    ecx,0x2e
  91d9ee:	74 17                                           	je     0x91da07
  91d9f0:	b8 01 00 00 00                                  	mov    eax,0x1
  91d9f5:	85 c9                                           	test   ecx,ecx
  91d9f7:	75 19                                           	jne    0x91da12
  91d9f9:	44 0f b6 72 09                                  	movzx  r14d,BYTE PTR [rdx+0x9]
  91d9fe:	48 8b 5d b8                                     	mov    rbx,QWORD PTR [rbp-0x48]
  91da02:	e9 6d 01 00 00                                  	jmp    0x91db74
  91da07:	48 ff c3                                        	inc    rbx
  91da0a:	45 31 f6                                        	xor    r14d,r14d
  91da0d:	b8 02 00 00 00                                  	mov    eax,0x2
  91da12:	85 c0                                           	test   eax,eax
  91da14:	75 18                                           	jne    0x91da2e
  91da16:	e9 51 01 00 00                                  	jmp    0x91db6c
  91da1b:	0f b6 43 01                                     	movzx  eax,BYTE PTR [rbx+0x1]
  91da1f:	48 83 c3 02                                     	add    rbx,0x2
  91da23:	45 31 f6                                        	xor    r14d,r14d
  91da26:	85 c0                                           	test   eax,eax
  91da28:	0f 84 3e 01 00 00                               	je     0x91db6c
  91da2e:	48 85 d2                                        	test   rdx,rdx
  91da31:	0f 84 35 01 00 00                               	je     0x91db6c
  91da37:	8b 4d b4                                        	mov    ecx,DWORD PTR [rbp-0x4c]
  91da3a:	41 81 ce 88 00 00 00                            	or     r14d,0x88
  91da41:	41 89 c4                                        	mov    r12d,eax
  91da44:	45 31 ff                                        	xor    r15d,r15d
  91da47:	49 8d 44 24 ff                                  	lea    rax,[r12-0x1]
  91da4c:	48 89 45 a8                                     	mov    QWORD PTR [rbp-0x58],rax
  91da50:	41 89 cd                                        	mov    r13d,ecx
  91da53:	41 21 ce                                        	and    r14d,ecx
  91da56:	41 81 e5 76 ff ff ff                            	and    r13d,0xffffff76
  91da5d:	eb 0a                                           	jmp    0x91da69
  91da5f:	90                                              	nop
  91da60:	48 85 d2                                        	test   rdx,rdx
  91da63:	0f 84 f6 00 00 00                               	je     0x91db5f
  91da69:	44 39 7d a8                                     	cmp    DWORD PTR [rbp-0x58],r15d
  91da6d:	41 b8 00 00 00 00                               	mov    r8d,0x0
  91da73:	42 8b 3c bb                                     	mov    edi,DWORD PTR [rbx+r15*4]
  91da77:	44 89 e8                                        	mov    eax,r13d
  91da7a:	41 bd 00 00 00 00                               	mov    r13d,0x0
  91da80:	48 8b 75 b8                                     	mov    rsi,QWORD PTR [rbp-0x48]
  91da84:	8b 4d b0                                        	mov    ecx,DWORD PTR [rbp-0x50]
  91da87:	89 7d c4                                        	mov    DWORD PTR [rbp-0x3c],edi
  91da8a:	44 0f 44 45 c0                                  	cmove  r8d,DWORD PTR [rbp-0x40]
  91da8f:	45 0f 44 ee                                     	cmove  r13d,r14d
  91da93:	41 09 c5                                        	or     r13d,eax
  91da96:	48 8d 45 c8                                     	lea    rax,[rbp-0x38]
  91da9a:	45 89 e9                                        	mov    r9d,r13d
  91da9d:	48 89 04 24                                     	mov    QWORD PTR [rsp],rax
  91daa1:	e8 8a a7 09 00                                  	call   0x9b8230
  91daa6:	85 c0                                           	test   eax,eax
  91daa8:	75 62                                           	jne    0x91db0c
  91daaa:	49 ff c7                                        	inc    r15
  91daad:	45 39 fc                                        	cmp    r12d,r15d
  91dab0:	74 71                                           	je     0x91db23
  91dab2:	48 8b 55 c8                                     	mov    rdx,QWORD PTR [rbp-0x38]
  91dab6:	80 7a 09 15                                     	cmp    BYTE PTR [rdx+0x9],0x15
  91daba:	75 a4                                           	jne    0x91da60
  91dabc:	48 8b 02                                        	mov    rax,QWORD PTR [rdx]
  91dabf:	48 85 c0                                        	test   rax,rax
  91dac2:	0f 84 47 01 00 00                               	je     0x91dc0f
  91dac8:	0f b6 78 09                                     	movzx  edi,BYTE PTR [rax+0x9]
  91dacc:	e8 df 93 1a 00                                  	call   0xac6eb0
  91dad1:	48 8b 55 c8                                     	mov    rdx,QWORD PTR [rbp-0x38]
  91dad5:	85 c0                                           	test   eax,eax
  91dad7:	74 87                                           	je     0x91da60
  91dad9:	48 8b 12                                        	mov    rdx,QWORD PTR [rdx]
  91dadc:	48 89 55 c8                                     	mov    QWORD PTR [rbp-0x38],rdx
  91dae0:	e9 7b ff ff ff                                  	jmp    0x91da60
  91dae5:	48 89 f1                                        	mov    rcx,rsi
  91dae8:	48 8d 3d 39 fa ef 00                            	lea    rdi,[rip+0xeffa39]        # 0x181d528
  91daef:	48 8d 15 a0 9a 9d 00                            	lea    rdx,[rip+0x9d9aa0]        # 0x12f7596
  91daf6:	be c2 01 00 00                                  	mov    esi,0x1c2
  91dafb:	31 c0                                           	xor    eax,eax
  91dafd:	e8 ee 9e dd ff                                  	call   0x6f79f0
  91db02:	b8 05 00 00 00                                  	mov    eax,0x5
  91db07:	e9 a6 00 00 00                                  	jmp    0x91dbb2
  91db0c:	48 8b 4d c8                                     	mov    rcx,QWORD PTR [rbp-0x38]
  91db10:	48 8b 55 10                                     	mov    rdx,QWORD PTR [rbp+0x10]
  91db14:	4c 8d 3d f5 e7 ff 02                            	lea    r15,[rip+0x2ffe7f5]        # 0x391c310
  91db1b:	48 89 0a                                        	mov    QWORD PTR [rdx],rcx
  91db1e:	e9 8f 00 00 00                                  	jmp    0x91dbb2
  91db23:	44 8b 75 c0                                     	mov    r14d,DWORD PTR [rbp-0x40]
  91db27:	41 83 fe 1b                                     	cmp    r14d,0x1b
  91db2b:	0f 87 ec 00 00 00                               	ja     0x91dc1d
  91db31:	b8 01 00 60 08                                  	mov    eax,0x8600001
  91db36:	44 0f a3 f0                                     	bt     eax,r14d
  91db3a:	0f 83 dd 00 00 00                               	jae    0x91dc1d
  91db40:	48 8b 55 c8                                     	mov    rdx,QWORD PTR [rbp-0x38]
  91db44:	4c 8d 3d c5 e7 ff 02                            	lea    r15,[rip+0x2ffe7c5]        # 0x391c310
  91db4b:	48 8b 5d b8                                     	mov    rbx,QWORD PTR [rbp-0x48]
  91db4f:	45 85 f6                                        	test   r14d,r14d
  91db52:	75 05                                           	jne    0x91db59
  91db54:	44 0f b6 72 09                                  	movzx  r14d,BYTE PTR [rdx+0x9]
  91db59:	4c 8b 65 10                                     	mov    r12,QWORD PTR [rbp+0x10]
  91db5d:	eb 15                                           	jmp    0x91db74
  91db5f:	4c 8d 3d aa e7 ff 02                            	lea    r15,[rip+0x2ffe7aa]        # 0x391c310
  91db66:	4c 8b 65 10                                     	mov    r12,QWORD PTR [rbp+0x10]
  91db6a:	31 d2                                           	xor    edx,edx
  91db6c:	48 8b 5d b8                                     	mov    rbx,QWORD PTR [rbp-0x48]
  91db70:	44 8b 75 c0                                     	mov    r14d,DWORD PTR [rbp-0x40]
  91db74:	8b 4d b4                                        	mov    ecx,DWORD PTR [rbp-0x4c]
  91db77:	83 e1 02                                        	and    ecx,0x2
  91db7a:	d1 e9                                           	shr    ecx,1
  91db7c:	48 85 db                                        	test   rbx,rbx
  91db7f:	0f 94 c0                                        	sete   al
  91db82:	08 c8                                           	or     al,cl
  91db84:	75 26                                           	jne    0x91dbac
  91db86:	44 89 f7                                        	mov    edi,r14d
  91db89:	e8 22 93 1a 00                                  	call   0xac6eb0
  91db8e:	48 8b 55 c8                                     	mov    rdx,QWORD PTR [rbp-0x38]
  91db92:	85 c0                                           	test   eax,eax
  91db94:	74 16                                           	je     0x91dbac
  91db96:	48 89 d7                                        	mov    rdi,rdx
  91db99:	44 89 f6                                        	mov    esi,r14d
  91db9c:	48 89 da                                        	mov    rdx,rbx
  91db9f:	e8 ac 20 ee ff                                  	call   0x7ffc50
  91dba4:	85 c0                                           	test   eax,eax
  91dba6:	75 0a                                           	jne    0x91dbb2
  91dba8:	48 8b 55 c8                                     	mov    rdx,QWORD PTR [rbp-0x38]
  91dbac:	31 c0                                           	xor    eax,eax
  91dbae:	49 89 14 24                                     	mov    QWORD PTR [r12],rdx
  91dbb2:	49 8b 0f                                        	mov    rcx,QWORD PTR [r15]
  91dbb5:	48 3b 4d d0                                     	cmp    rcx,QWORD PTR [rbp-0x30]
  91dbb9:	0f 85 b2 00 00 00                               	jne    0x91dc71
  91dbbf:	48 83 c4 38                                     	add    rsp,0x38
  91dbc3:	5b                                              	pop    rbx
  91dbc4:	41 5c                                           	pop    r12
  91dbc6:	41 5d                                           	pop    r13
  91dbc8:	41 5e                                           	pop    r14
  91dbca:	41 5f                                           	pop    r15
  91dbcc:	5d                                              	pop    rbp
  91dbcd:	c3                                              	ret
  91dbce:	48 89 de                                        	mov    rsi,rbx
  91dbd1:	66 66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00    	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  91dbe0:	80 7a 09 00                                     	cmp    BYTE PTR [rdx+0x9],0x0
  91dbe4:	0f 84 87 fd ff ff                               	je     0x91d971
  91dbea:	48 8b 52 10                                     	mov    rdx,QWORD PTR [rdx+0x10]
  91dbee:	45 89 f5                                        	mov    r13d,r14d
  91dbf1:	0f b6 7a 09                                     	movzx  edi,BYTE PTR [rdx+0x9]
  91dbf5:	49 89 d6                                        	mov    r14,rdx
  91dbf8:	e8 b3 92 1a 00                                  	call   0xac6eb0
  91dbfd:	4c 89 f2                                        	mov    rdx,r14
  91dc00:	48 89 de                                        	mov    rsi,rbx
  91dc03:	45 89 ee                                        	mov    r14d,r13d
  91dc06:	85 c0                                           	test   eax,eax
  91dc08:	74 d6                                           	je     0x91dbe0
  91dc0a:	e9 62 fd ff ff                                  	jmp    0x91d971
  91dc0f:	4c 8d 3d fa e6 ff 02                            	lea    r15,[rip+0x2ffe6fa]        # 0x391c310
  91dc16:	b8 06 00 00 00                                  	mov    eax,0x6
  91dc1b:	eb 95                                           	jmp    0x91dbb2
  91dc1d:	48 8b 45 c8                                     	mov    rax,QWORD PTR [rbp-0x38]
  91dc21:	0f b6 78 09                                     	movzx  edi,BYTE PTR [rax+0x9]
  91dc25:	85 ff                                           	test   edi,edi
  91dc27:	0f 94 c0                                        	sete   al
  91dc2a:	41 39 fe                                        	cmp    r14d,edi
  91dc2d:	0f 94 c1                                        	sete   cl
  91dc30:	08 c1                                           	or     cl,al
  91dc32:	0f 85 08 ff ff ff                               	jne    0x91db40
  91dc38:	e8 c3 bf ba ff                                  	call   0x4c9c00
  91dc3d:	44 89 f7                                        	mov    edi,r14d
  91dc40:	49 89 c4                                        	mov    r12,rax
  91dc43:	e8 b8 bf ba ff                                  	call   0x4c9c00
  91dc48:	49 89 c1                                        	mov    r9,rax
  91dc4b:	48 8d 3d d6 f8 ef 00                            	lea    rdi,[rip+0xeff8d6]        # 0x181d528
  91dc52:	48 8d 15 76 b6 99 00                            	lea    rdx,[rip+0x99b676]        # 0x12b92cf
  91dc59:	48 8d 4d c4                                     	lea    rcx,[rbp-0x3c]
  91dc5d:	be 94 02 00 00                                  	mov    esi,0x294
  91dc62:	4d 89 e0                                        	mov    r8,r12
  91dc65:	31 c0                                           	xor    eax,eax
  91dc67:	e8 e4 9e dd ff                                  	call   0x6f7b50
  91dc6c:	e9 cf fe ff ff                                  	jmp    0x91db40
  91dc71:	e8 3a fa dd ff                                  	call   0x6fd6b0
  91dc76:	0f 0b                                           	ud2
  91dc78:	90                                              	nop
  91dc79:	90                                              	nop
  91dc7a:	90                                              	nop
  91dc7b:	90                                              	nop
  91dc7c:	90                                              	nop
  91dc7d:	90                                              	nop
  91dc7e:	90                                              	nop
  91dc7f:	90                                              	nop
  91dc80:	55                                              	push   rbp
  91dc81:	48 89 e5                                        	mov    rbp,rsp
  91dc84:	41 57                                           	push   r15
  91dc86:	41 56                                           	push   r14
  91dc88:	41 55                                           	push   r13
  91dc8a:	41 54                                           	push   r12
  91dc8c:	53                                              	push   rbx
  91dc8d:	48 83 ec 28                                     	sub    rsp,0x28
  91dc91:	31 c0                                           	xor    eax,eax
  91dc93:	48 89 7d b0                                     	mov    QWORD PTR [rbp-0x50],rdi
  91dc97:	e8 14 30 17 00                                  	call   0xa90cb0
  91dc9c:	89 45 b8                                        	mov    DWORD PTR [rbp-0x48],eax
  91dc9f:	31 c0                                           	xor    eax,eax
  91dca1:	e8 8a 2e 17 00                                  	call   0xa90b30
  91dca6:	41 89 c7                                        	mov    r15d,eax
  91dca9:	31 c0                                           	xor    eax,eax
  91dcab:	e8 00 2f 17 00                                  	call   0xa90bb0
  91dcb0:	bf d7 00 00 00                                  	mov    edi,0xd7
  91dcb5:	89 45 bc                                        	mov    DWORD PTR [rbp-0x44],eax
  91dcb8:	e8 33 2f 17 00                                  	call   0xa90bf0
  91dcbd:	bf 10 01 00 00                                  	mov    edi,0x110
  91dcc2:	41 89 c4                                        	mov    r12d,eax
  91dcc5:	e8 26 2f 17 00                                  	call   0xa90bf0
  91dcca:	bf 04 00 00 00                                  	mov    edi,0x4
  91dccf:	89 45 c0                                        	mov    DWORD PTR [rbp-0x40],eax
  91dcd2:	e8 19 2f 17 00                                  	call   0xa90bf0
  91dcd7:	bf 9e 00 00 00                                  	mov    edi,0x9e
  91dcdc:	41 89 c5                                        	mov    r13d,eax
  91dcdf:	e8 0c 2f 17 00                                  	call   0xa90bf0
  91dce4:	bf 02 00 00 00                                  	mov    edi,0x2
  91dce9:	89 45 c4                                        	mov    DWORD PTR [rbp-0x3c],eax
  91dcec:	e8 ff 2e 17 00                                  	call   0xa90bf0
  91dcf1:	bf 01 00 00 00                                  	mov    edi,0x1
  91dcf6:	89 45 c8                                        	mov    DWORD PTR [rbp-0x38],eax
  91dcf9:	e8 f2 2e 17 00                                  	call   0xa90bf0
  91dcfe:	bf 42 00 00 00                                  	mov    edi,0x42
  91dd03:	41 89 c6                                        	mov    r14d,eax
  91dd06:	e8 e5 2e 17 00                                  	call   0xa90bf0
  91dd0b:	bf cb 00 00 00                                  	mov    edi,0xcb
  91dd10:	89 45 cc                                        	mov    DWORD PTR [rbp-0x34],eax
  91dd13:	e8 d8 2e 17 00                                  	call   0xa90bf0
  91dd18:	89 45 d0                                        	mov    DWORD PTR [rbp-0x30],eax
  91dd1b:	31 c0                                           	xor    eax,eax
  91dd1d:	e8 fe 2e 17 00                                  	call   0xa90c20
  91dd22:	89 45 d4                                        	mov    DWORD PTR [rbp-0x2c],eax
  91dd25:	31 c0                                           	xor    eax,eax
  91dd27:	e8 04 2e 17 00                                  	call   0xa90b30
  91dd2c:	89 c3                                           	mov    ebx,eax
  91dd2e:	31 c0                                           	xor    eax,eax
  91dd30:	e8 6b 2f 17 00                                  	call   0xa90ca0
  91dd35:	44 03 6d c0                                     	add    r13d,DWORD PTR [rbp-0x40]
  91dd39:	44 03 75 c8                                     	add    r14d,DWORD PTR [rbp-0x38]
  91dd3d:	8b 75 b8                                        	mov    esi,DWORD PTR [rbp-0x48]
  91dd40:	44 03 65 bc                                     	add    r12d,DWORD PTR [rbp-0x44]
  91dd44:	03 5d d4                                        	add    ebx,DWORD PTR [rbp-0x2c]
  91dd47:	31 d2                                           	xor    edx,edx
  91dd49:	44 03 75 cc                                     	add    r14d,DWORD PTR [rbp-0x34]
  91dd4d:	44 03 6d c4                                     	add    r13d,DWORD PTR [rbp-0x3c]
  91dd51:	44 03 75 d0                                     	add    r14d,DWORD PTR [rbp-0x30]
  91dd55:	41 01 f7                                        	add    r15d,esi
  91dd58:	45 01 fc                                        	add    r12d,r15d
  91dd5b:	45 01 e5                                        	add    r13d,r12d
  91dd5e:	45 01 ee                                        	add    r14d,r13d
  91dd61:	44 01 f3                                        	add    ebx,r14d
  91dd64:	8d 4c 18 ff                                     	lea    ecx,[rax+rbx*1-0x1]
  91dd68:	89 c8                                           	mov    eax,ecx
  91dd6a:	f7 f6                                           	div    esi
  91dd6c:	48 8b 45 b0                                     	mov    rax,QWORD PTR [rbp-0x50]
  91dd70:	29 d1                                           	sub    ecx,edx
  91dd72:	c1 e1 02                                        	shl    ecx,0x2
  91dd75:	89 08                                           	mov    DWORD PTR [rax],ecx
  91dd77:	31 c0                                           	xor    eax,eax
  91dd79:	48 83 c4 28                                     	add    rsp,0x28
  91dd7d:	5b                                              	pop    rbx
  91dd7e:	41 5c                                           	pop    r12
  91dd80:	41 5d                                           	pop    r13
  91dd82:	41 5e                                           	pop    r14
  91dd84:	41 5f                                           	pop    r15
  91dd86:	5d                                              	pop    rbp
  91dd87:	c3                                              	ret
  91dd88:	90                                              	nop
  91dd89:	90                                              	nop
  91dd8a:	90                                              	nop
  91dd8b:	90                                              	nop
  91dd8c:	90                                              	nop
  91dd8d:	90                                              	nop
  91dd8e:	90                                              	nop
  91dd8f:	90                                              	nop
  91dd90:	55                                              	push   rbp
  91dd91:	48 89 e5                                        	mov    rbp,rsp
  91dd94:	41 57                                           	push   r15
  91dd96:	41 56                                           	push   r14
  91dd98:	41 55                                           	push   r13
  91dd9a:	41 54                                           	push   r12
  91dd9c:	53                                              	push   rbx
  91dd9d:	50                                              	push   rax
  91dd9e:	31 c0                                           	xor    eax,eax
  91dda0:	48 89 f3                                        	mov    rbx,rsi
  91dda3:	41 89 ff                                        	mov    r15d,edi
  91dda6:	e8 05 2f 17 00                                  	call   0xa90cb0
  91ddab:	bf 02 00 00 00                                  	mov    edi,0x2
  91ddb0:	48 89 de                                        	mov    rsi,rbx
  91ddb3:	41 89 c6                                        	mov    r14d,eax
  91ddb6:	e8 f5 2c 17 00                                  	call   0xa90ab0
  91ddbb:	31 c0                                           	xor    eax,eax
  91ddbd:	e8 6e 2d 17 00                                  	call   0xa90b30
  91ddc2:	41 89 c4                                        	mov    r12d,eax
  91ddc5:	89 c0                                           	mov    eax,eax
  91ddc7:	48 8d 3c 83                                     	lea    rdi,[rbx+rax*4]
  91ddcb:	e8 70 2d 17 00                                  	call   0xa90b40
  91ddd0:	31 c0                                           	xor    eax,eax
  91ddd2:	e8 d9 2d 17 00                                  	call   0xa90bb0
  91ddd7:	41 89 c5                                        	mov    r13d,eax
  91ddda:	48 8d 35 5f f7 ef 00                            	lea    rsi,[rip+0xeff75f]        # 0x181d540
  91dde1:	bf 00 a0 00 00                                  	mov    edi,0xa000
  91dde6:	ba d7 00 00 00                                  	mov    edx,0xd7
  91ddeb:	45 01 e5                                        	add    r13d,r12d
  91ddee:	4a 8d 0c ab                                     	lea    rcx,[rbx+r13*4]
  91ddf2:	e8 c9 2d 17 00                                  	call   0xa90bc0
  91ddf7:	bf d7 00 00 00                                  	mov    edi,0xd7
  91ddfc:	e8 ef 2d 17 00                                  	call   0xa90bf0
  91de01:	41 89 c4                                        	mov    r12d,eax
  91de04:	48 8d 35 35 fd ef 00                            	lea    rsi,[rip+0xeffd35]        # 0x181db40
  91de0b:	bf d8 a0 00 00                                  	mov    edi,0xa0d8
  91de10:	ba 10 01 00 00                                  	mov    edx,0x110
  91de15:	45 01 ec                                        	add    r12d,r13d
  91de18:	4a 8d 0c a3                                     	lea    rcx,[rbx+r12*4]
  91de1c:	e8 9f 2d 17 00                                  	call   0xa90bc0
  91de21:	bf 10 01 00 00                                  	mov    edi,0x110
  91de26:	e8 c5 2d 17 00                                  	call   0xa90bf0
  91de2b:	41 89 c5                                        	mov    r13d,eax
  91de2e:	48 8d 35 6b fa ef 00                            	lea    rsi,[rip+0xeffa6b]        # 0x181d8a0
  91de35:	bf f5 a1 00 00                                  	mov    edi,0xa1f5
  91de3a:	ba 04 00 00 00                                  	mov    edx,0x4
  91de3f:	45 01 e5                                        	add    r13d,r12d
  91de42:	4a 8d 0c ab                                     	lea    rcx,[rbx+r13*4]
  91de46:	e8 75 2d 17 00                                  	call   0xa90bc0
  91de4b:	bf 04 00 00 00                                  	mov    edi,0x4
  91de50:	e8 9b 2d 17 00                                  	call   0xa90bf0
  91de55:	41 89 c4                                        	mov    r12d,eax
  91de58:	48 8d 35 51 fa ef 00                            	lea    rsi,[rip+0xeffa51]        # 0x181d8b0
  91de5f:	bf ff a1 00 00                                  	mov    edi,0xa1ff
  91de64:	ba 9e 00 00 00                                  	mov    edx,0x9e
  91de69:	45 01 ec                                        	add    r12d,r13d
  91de6c:	4a 8d 0c a3                                     	lea    rcx,[rbx+r12*4]
  91de70:	e8 4b 2d 17 00                                  	call   0xa90bc0
  91de75:	bf 9e 00 00 00                                  	mov    edi,0x9e
  91de7a:	e8 71 2d 17 00                                  	call   0xa90bf0
  91de7f:	41 89 c5                                        	mov    r13d,eax
  91de82:	48 8d 35 9f fc ef 00                            	lea    rsi,[rip+0xeffc9f]        # 0x181db28
  91de89:	bf a0 a2 00 00                                  	mov    edi,0xa2a0
  91de8e:	ba 02 00 00 00                                  	mov    edx,0x2
  91de93:	45 01 e5                                        	add    r13d,r12d
  91de96:	4a 8d 0c ab                                     	lea    rcx,[rbx+r13*4]
  91de9a:	e8 21 2d 17 00                                  	call   0xa90bc0
  91de9f:	bf 02 00 00 00                                  	mov    edi,0x2
  91dea4:	e8 47 2d 17 00                                  	call   0xa90bf0
  91dea9:	41 89 c4                                        	mov    r12d,eax
  91deac:	48 8d 35 7d fc ef 00                            	lea    rsi,[rip+0xeffc7d]        # 0x181db30
  91deb3:	bf a3 a2 00 00                                  	mov    edi,0xa2a3
  91deb8:	ba 01 00 00 00                                  	mov    edx,0x1
  91debd:	45 01 ec                                        	add    r12d,r13d
  91dec0:	4a 8d 0c a3                                     	lea    rcx,[rbx+r12*4]
  91dec4:	e8 f7 2c 17 00                                  	call   0xa90bc0
  91dec9:	bf 01 00 00 00                                  	mov    edi,0x1
  91dece:	e8 1d 2d 17 00                                  	call   0xa90bf0
  91ded3:	41 89 c5                                        	mov    r13d,eax
  91ded6:	48 8d 35 a3 00 f0 00                            	lea    rsi,[rip+0xf000a3]        # 0x181df80
  91dedd:	bf a5 a2 00 00                                  	mov    edi,0xa2a5
  91dee2:	ba 42 00 00 00                                  	mov    edx,0x42
  91dee7:	45 01 e5                                        	add    r13d,r12d
  91deea:	4a 8d 0c ab                                     	lea    rcx,[rbx+r13*4]
  91deee:	e8 cd 2c 17 00                                  	call   0xa90bc0
  91def3:	bf 42 00 00 00                                  	mov    edi,0x42
  91def8:	e8 f3 2c 17 00                                  	call   0xa90bf0
  91defd:	41 89 c4                                        	mov    r12d,eax
  91df00:	48 8d 35 89 01 f0 00                            	lea    rsi,[rip+0xf00189]        # 0x181e090
  91df07:	bf f5 a2 00 00                                  	mov    edi,0xa2f5
  91df0c:	ba cb 00 00 00                                  	mov    edx,0xcb
  91df11:	45 01 ec                                        	add    r12d,r13d
  91df14:	4a 8d 0c a3                                     	lea    rcx,[rbx+r12*4]
  91df18:	e8 a3 2c 17 00                                  	call   0xa90bc0
  91df1d:	bf cb 00 00 00                                  	mov    edi,0xcb
  91df22:	e8 c9 2c 17 00                                  	call   0xa90bf0
  91df27:	41 89 c5                                        	mov    r13d,eax
  91df2a:	bf d7 a0 00 00                                  	mov    edi,0xa0d7
  91df2f:	44 89 fe                                        	mov    esi,r15d
  91df32:	45 01 e5                                        	add    r13d,r12d
  91df35:	4a 8d 14 ab                                     	lea    rdx,[rbx+r13*4]
  91df39:	e8 c2 2c 17 00                                  	call   0xa90c00
  91df3e:	31 c0                                           	xor    eax,eax
  91df40:	e8 db 2c 17 00                                  	call   0xa90c20
  91df45:	41 89 c7                                        	mov    r15d,eax
  91df48:	bf 03 00 00 00                                  	mov    edi,0x3
  91df4d:	45 01 ef                                        	add    r15d,r13d
  91df50:	4a 8d 34 bb                                     	lea    rsi,[rbx+r15*4]
  91df54:	e8 57 2b 17 00                                  	call   0xa90ab0
  91df59:	31 c0                                           	xor    eax,eax
  91df5b:	e8 d0 2b 17 00                                  	call   0xa90b30
  91df60:	41 89 c4                                        	mov    r12d,eax
  91df63:	45 01 fc                                        	add    r12d,r15d
  91df66:	4a 8d 3c a3                                     	lea    rdi,[rbx+r12*4]
  91df6a:	e8 c1 2c 17 00                                  	call   0xa90c30
  91df6f:	31 c0                                           	xor    eax,eax
  91df71:	e8 2a 2d 17 00                                  	call   0xa90ca0
  91df76:	89 c1                                           	mov    ecx,eax
  91df78:	31 d2                                           	xor    edx,edx
  91df7a:	44 01 e1                                        	add    ecx,r12d
  91df7d:	89 c8                                           	mov    eax,ecx
  91df7f:	41 f7 f6                                        	div    r14d
  91df82:	85 d2                                           	test   edx,edx
  91df84:	74 1b                                           	je     0x91dfa1
  91df86:	41 29 d6                                        	sub    r14d,edx
  91df89:	89 c8                                           	mov    eax,ecx
  91df8b:	be 01 40 00 00                                  	mov    esi,0x4001
  91df90:	41 83 fe 01                                     	cmp    r14d,0x1
  91df94:	48 8d 3c 83                                     	lea    rdi,[rbx+rax*4]
  91df98:	41 0f 45 f6                                     	cmovne esi,r14d
  91df9c:	e8 1f 2d 17 00                                  	call   0xa90cc0
  91dfa1:	31 c0                                           	xor    eax,eax
  91dfa3:	48 83 c4 08                                     	add    rsp,0x8
  91dfa7:	5b                                              	pop    rbx
  91dfa8:	41 5c                                           	pop    r12
  91dfaa:	41 5d                                           	pop    r13
  91dfac:	41 5e                                           	pop    r14
  91dfae:	41 5f                                           	pop    r15
  91dfb0:	5d                                              	pop    rbp
  91dfb1:	c3                                              	ret
  91dfb2:	90                                              	nop
  91dfb3:	90                                              	nop
  91dfb4:	90                                              	nop
  91dfb5:	90                                              	nop
  91dfb6:	90                                              	nop
  91dfb7:	90                                              	nop
  91dfb8:	90                                              	nop
  91dfb9:	90                                              	nop
  91dfba:	90                                              	nop
  91dfbb:	90                                              	nop
  91dfbc:	90                                              	nop
  91dfbd:	90                                              	nop
  91dfbe:	90                                              	nop
  91dfbf:	90                                              	nop
  91dfc0:	48 85 d2                                        	test   rdx,rdx
  91dfc3:	74 6e                                           	je     0x91e033
  91dfc5:	55                                              	push   rbp
  91dfc6:	48 89 e5                                        	mov    rbp,rsp
  91dfc9:	40 0f b6 c6                                     	movzx  eax,sil
  91dfcd:	49 89 f9                                        	mov    r9,rdi
  91dfd0:	48 01 fa                                        	add    rdx,rdi
  91dfd3:	69 c0 01 01 01 01                               	imul   eax,eax,0x1010101
  91dfd9:	49 83 e1 f8                                     	and    r9,0xfffffffffffffff8
  91dfdd:	49 8d 49 08                                     	lea    rcx,[r9+0x8]
  91dfe1:	49 89 c0                                        	mov    r8,rax
  91dfe4:	49 c1 e0 20                                     	shl    r8,0x20
  91dfe8:	49 09 c0                                        	or     r8,rax
  91dfeb:	48 39 cf                                        	cmp    rdi,rcx
  91dfee:	73 21                                           	jae    0x91e011
  91dff0:	4d 39 01                                        	cmp    QWORD PTR [r9],r8
  91dff3:	74 1c                                           	je     0x91e011
  91dff5:	48 89 f8                                        	mov    rax,rdi
  91dff8:	4c 29 c8                                        	sub    rax,r9
  91dffb:	48 83 c0 f8                                     	add    rax,0xfffffffffffffff8
  91dfff:	90                                              	nop
  91e000:	40 38 37                                        	cmp    BYTE PTR [rdi],sil
  91e003:	0f 85 99 00 00 00                               	jne    0x91e0a2
  91e009:	48 ff c7                                        	inc    rdi
  91e00c:	48 ff c0                                        	inc    rax
  91e00f:	75 ef                                           	jne    0x91e000
  91e011:	31 c0                                           	xor    eax,eax
  91e013:	48 39 d1                                        	cmp    rcx,rdx
  91e016:	73 19                                           	jae    0x91e031
  91e018:	0f 1f 84 00 00 00 00 00                         	nop    DWORD PTR [rax+rax*1+0x0]
  91e020:	48 8b 39                                        	mov    rdi,QWORD PTR [rcx]
  91e023:	4c 39 c7                                        	cmp    rdi,r8
  91e026:	75 0e                                           	jne    0x91e036
  91e028:	48 83 c1 08                                     	add    rcx,0x8
  91e02c:	48 39 d1                                        	cmp    rcx,rdx
  91e02f:	72 ef                                           	jb     0x91e020
  91e031:	5d                                              	pop    rbp
  91e032:	c3                                              	ret
  91e033:	31 c0                                           	xor    eax,eax
  91e035:	c3                                              	ret
  91e036:	40 38 f7                                        	cmp    dil,sil
  91e039:	75 64                                           	jne    0x91e09f
  91e03b:	89 f8                                           	mov    eax,edi
  91e03d:	c1 e8 08                                        	shr    eax,0x8
  91e040:	40 38 f0                                        	cmp    al,sil
  91e043:	75 3f                                           	jne    0x91e084
  91e045:	89 f8                                           	mov    eax,edi
  91e047:	c1 e8 10                                        	shr    eax,0x10
  91e04a:	40 38 f0                                        	cmp    al,sil
  91e04d:	75 3a                                           	jne    0x91e089
  91e04f:	89 f8                                           	mov    eax,edi
  91e051:	c1 e8 18                                        	shr    eax,0x18
  91e054:	40 38 f0                                        	cmp    al,sil
  91e057:	75 36                                           	jne    0x91e08f
  91e059:	48 89 f8                                        	mov    rax,rdi
  91e05c:	48 c1 e8 20                                     	shr    rax,0x20
  91e060:	40 38 f0                                        	cmp    al,sil
  91e063:	75 30                                           	jne    0x91e095
  91e065:	48 89 f8                                        	mov    rax,rdi
  91e068:	48 c1 e8 28                                     	shr    rax,0x28
  91e06c:	40 38 f0                                        	cmp    al,sil
  91e06f:	75 2a                                           	jne    0x91e09b
  91e071:	48 c1 ef 30                                     	shr    rdi,0x30
  91e075:	31 c0                                           	xor    eax,eax
  91e077:	40 38 f7                                        	cmp    dil,sil
  91e07a:	0f 94 c0                                        	sete   al
  91e07d:	48 8d 7c 01 06                                  	lea    rdi,[rcx+rax*1+0x6]
  91e082:	eb 1e                                           	jmp    0x91e0a2
  91e084:	48 ff c1                                        	inc    rcx
  91e087:	eb 16                                           	jmp    0x91e09f
  91e089:	48 83 c1 02                                     	add    rcx,0x2
  91e08d:	eb 10                                           	jmp    0x91e09f
  91e08f:	48 83 c1 03                                     	add    rcx,0x3
  91e093:	eb 0a                                           	jmp    0x91e09f
  91e095:	48 83 c1 04                                     	add    rcx,0x4
  91e099:	eb 04                                           	jmp    0x91e09f
  91e09b:	48 83 c1 05                                     	add    rcx,0x5
  91e09f:	48 89 cf                                        	mov    rdi,rcx
  91e0a2:	31 c0                                           	xor    eax,eax
  91e0a4:	48 39 d7                                        	cmp    rdi,rdx
  91e0a7:	48 0f 42 c7                                     	cmovb  rax,rdi
  91e0ab:	5d                                              	pop    rbp
  91e0ac:	c3                                              	ret
  91e0ad:	90                                              	nop
  91e0ae:	90                                              	nop
  91e0af:	90                                              	nop
  91e0b0:	55                                              	push   rbp
  91e0b1:	48 89 e5                                        	mov    rbp,rsp
  91e0b4:	41 56                                           	push   r14
  91e0b6:	53                                              	push   rbx
  91e0b7:	48 89 fb                                        	mov    rbx,rdi
  91e0ba:	48 8d 3d df 88 25 03                            	lea    rdi,[rip+0x32588df]        # 0x3b769a0
  91e0c1:	45 31 f6                                        	xor    r14d,r14d
  91e0c4:	31 f6                                           	xor    esi,esi
  91e0c6:	31 d2                                           	xor    edx,edx
  91e0c8:	31 c9                                           	xor    ecx,ecx
  91e0ca:	e8 51 da 32 00                                  	call   0xc4bb20
  91e0cf:	48 8d 05 2a 9f 25 03                            	lea    rax,[rip+0x3259f2a]        # 0x3b78000
  91e0d6:	66 2e 0f 1f 84 00 00 00 00 00                   	cs nop WORD PTR [rax+rax*1+0x0]
  91e0e0:	4a 39 5c f0 28                                  	cmp    QWORD PTR [rax+r14*8+0x28],rbx
  91e0e5:	74 20                                           	je     0x91e107
  91e0e7:	49 ff c6                                        	inc    r14
  91e0ea:	49 81 fe 80 00 00 00                            	cmp    r14,0x80
  91e0f1:	75 ed                                           	jne    0x91e0e0
  91e0f3:	48 8d 3d a6 88 25 03                            	lea    rdi,[rip+0x32588a6]        # 0x3b769a0
  91e0fa:	31 db                                           	xor    ebx,ebx
  91e0fc:	31 f6                                           	xor    esi,esi
  91e0fe:	31 d2                                           	xor    edx,edx
  91e100:	e8 ab e3 32 00                                  	call   0xc4c4b0
  91e105:	eb 16                                           	jmp    0x91e11d
  91e107:	48 8d 3d 92 88 25 03                            	lea    rdi,[rip+0x3258892]        # 0x3b769a0
  91e10e:	31 f6                                           	xor    esi,esi
  91e110:	31 d2                                           	xor    edx,edx
  91e112:	e8 99 e3 32 00                                  	call   0xc4c4b0
  91e117:	8b 1d e7 9e 25 03                               	mov    ebx,DWORD PTR [rip+0x3259ee7]        # 0x3b78004
  91e11d:	89 d8                                           	mov    eax,ebx
  91e11f:	5b                                              	pop    rbx
  91e120:	41 5e                                           	pop    r14
  91e122:	5d                                              	pop    rbp
  91e123:	c3                                              	ret
  91e124:	90                                              	nop
  91e125:	90                                              	nop
  91e126:	90                                              	nop
  91e127:	90                                              	nop
  91e128:	90                                              	nop
  91e129:	90                                              	nop
  91e12a:	90                                              	nop
  91e12b:	90                                              	nop
  91e12c:	90                                              	nop
  91e12d:	90                                              	nop
  91e12e:	90                                              	nop
  91e12f:	90                                              	nop
  91e130:	55                                              	push   rbp
  91e131:	48 89 e5                                        	mov    rbp,rsp
  91e134:	53                                              	push   rbx
  91e135:	50                                              	push   rax
  91e136:	83 fe 01                                        	cmp    esi,0x1
  91e139:	0f 84 89 00 00 00                               	je     0x91e1c8
  91e13f:	bb 2d 00 00 00                                  	mov    ebx,0x2d
  91e144:	85 f6                                           	test   esi,esi
  91e146:	0f 85 ad 00 00 00                               	jne    0x91e1f9
  91e14c:	48 8d 3d 65 3e c3 01                            	lea    rdi,[rip+0x1c33e65]        # 0x2551fb8
  91e153:	4c 8d 0d 45 6c 98 00                            	lea    r9,[rip+0x986c45]        # 0x12a4d9f
  91e15a:	41 b8 80 01 00 00                               	mov    r8d,0x180
  91e160:	31 db                                           	xor    ebx,ebx
  91e162:	31 f6                                           	xor    esi,esi
  91e164:	31 d2                                           	xor    edx,edx
  91e166:	31 c9                                           	xor    ecx,ecx
  91e168:	31 c0                                           	xor    eax,eax
  91e16a:	e8 11 13 dc ff                                  	call   0x6df480
  91e16f:	48 89 05 ba a2 25 03                            	mov    QWORD PTR [rip+0x325a2ba],rax        # 0x3b78430
  91e176:	48 85 c0                                        	test   rax,rax
  91e179:	74 79                                           	je     0x91e1f4
  91e17b:	48 8d 3d 1e 88 25 03                            	lea    rdi,[rip+0x325881e]        # 0x3b769a0
  91e182:	48 8d 35 a4 4e 9c 00                            	lea    rsi,[rip+0x9c4ea4]        # 0x12e302d
  91e189:	31 d2                                           	xor    edx,edx
  91e18b:	e8 00 d1 32 00                                  	call   0xc4b290
  91e190:	48 8d 3d a1 a2 25 03                            	lea    rdi,[rip+0x325a2a1]        # 0x3b78438
  91e197:	be 08 08 00 00                                  	mov    esi,0x808
  91e19c:	e8 4f ae 93 ff                                  	call   0x258ff0
  91e1a1:	48 8d 35 30 a1 98 00                            	lea    rsi,[rip+0x98a130]        # 0x12a82d8
  91e1a8:	48 8d 15 69 5d 94 ff                            	lea    rdx,[rip+0xffffffffff945d69]        # 0x263f18
  91e1af:	48 8d 0d dc 82 96 00                            	lea    rcx,[rip+0x9682dc]        # 0x1286492
  91e1b6:	41 b9 20 4e 00 00                               	mov    r9d,0x4e20
  91e1bc:	31 ff                                           	xor    edi,edi
  91e1be:	45 31 c0                                        	xor    r8d,r8d
  91e1c1:	e8 7a fb e1 ff                                  	call   0x73dd40
  91e1c6:	eb 31                                           	jmp    0x91e1f9
  91e1c8:	48 8d 3d d1 87 25 03                            	lea    rdi,[rip+0x32587d1]        # 0x3b769a0
  91e1cf:	e8 bc 2e 94 ff                                  	call   0x261090
  91e1d4:	48 8b 3d 55 a2 25 03                            	mov    rdi,QWORD PTR [rip+0x325a255]        # 0x3b78430
  91e1db:	31 db                                           	xor    ebx,ebx
  91e1dd:	48 85 ff                                        	test   rdi,rdi
  91e1e0:	74 17                                           	je     0x91e1f9
  91e1e2:	e8 c9 19 dc ff                                  	call   0x6dfbb0
  91e1e7:	48 c7 05 3e a2 25 03 00 00 00 00                	mov    QWORD PTR [rip+0x325a23e],0x0        # 0x3b78430
  91e1f2:	eb 05                                           	jmp    0x91e1f9
  91e1f4:	bb 0c 00 00 00                                  	mov    ebx,0xc
  91e1f9:	89 d8                                           	mov    eax,ebx
  91e1fb:	48 83 c4 08                                     	add    rsp,0x8
  91e1ff:	5b                                              	pop    rbx
  91e200:	5d                                              	pop    rbp
  91e201:	c3                                              	ret
  91e202:	90                                              	nop
  91e203:	90                                              	nop
  91e204:	90                                              	nop
  91e205:	90                                              	nop
  91e206:	90                                              	nop
  91e207:	90                                              	nop
  91e208:	90                                              	nop
  91e209:	90                                              	nop
  91e20a:	90                                              	nop
  91e20b:	90                                              	nop
  91e20c:	90                                              	nop
  91e20d:	90                                              	nop
  91e20e:	90                                              	nop
  91e20f:	90                                              	nop
  91e210:	83 3d 21 a2 25 03 00                            	cmp    DWORD PTR [rip+0x325a221],0x0        # 0x3b78438
  91e217:	74 47                                           	je     0x91e260
  91e219:	55                                              	push   rbp
  91e21a:	48 89 e5                                        	mov    rbp,rsp
  91e21d:	44 8b 05 18 a2 25 03                            	mov    r8d,DWORD PTR [rip+0x325a218]        # 0x3b7843c
  91e224:	48 8d 15 15 a2 25 03                            	lea    rdx,[rip+0x325a215]        # 0x3b78440
  91e22b:	b9 00 08 00 00                                  	mov    ecx,0x800
  91e230:	41 b9 01 00 00 00                               	mov    r9d,0x1
  91e236:	31 ff                                           	xor    edi,edi
  91e238:	31 f6                                           	xor    esi,esi
  91e23a:	e8 11 02 00 00                                  	call   0x91e450
  91e23f:	85 c0                                           	test   eax,eax
  91e241:	5d                                              	pop    rbp
  91e242:	74 1c                                           	je     0x91e260
  91e244:	89 c1                                           	mov    ecx,eax
  91e246:	48 8d 3d 20 7e a1 00                            	lea    rdi,[rip+0xa17e20]        # 0x133606d
  91e24d:	48 8d 35 3e 82 96 00                            	lea    rsi,[rip+0x96823e]        # 0x1286492
  91e254:	ba 59 01 00 00                                  	mov    edx,0x159
  91e259:	31 c0                                           	xor    eax,eax
  91e25b:	e9 b0 f1 93 ff                                  	jmp    0x25d410
  91e260:	c3                                              	ret
  91e261:	90                                              	nop
  91e262:	90                                              	nop
  91e263:	90                                              	nop
  91e264:	90                                              	nop
  91e265:	90                                              	nop
  91e266:	90                                              	nop
  91e267:	90                                              	nop
  91e268:	90                                              	nop
  91e269:	90                                              	nop
  91e26a:	90                                              	nop
  91e26b:	90                                              	nop
  91e26c:	90                                              	nop
  91e26d:	90                                              	nop
  91e26e:	90                                              	nop
  91e26f:	90                                              	nop
  91e270:	55                                              	push   rbp
  91e271:	48 89 e5                                        	mov    rbp,rsp
  91e274:	48 8b b9 40 01 00 00                            	mov    rdi,QWORD PTR [rcx+0x140]
  91e27b:	e8 20 ee 94 ff                                  	call   0x26d0a0
  91e280:	31 c9                                           	xor    ecx,ecx
  91e282:	85 c0                                           	test   eax,eax
  91e284:	0f 94 c1                                        	sete   cl
  91e287:	89 c8                                           	mov    eax,ecx
  91e289:	5d                                              	pop    rbp
  91e28a:	c3                                              	ret
  91e28b:	90                                              	nop
  91e28c:	90                                              	nop
  91e28d:	90                                              	nop
  91e28e:	90                                              	nop
  91e28f:	90                                              	nop
  91e290:	55                                              	push   rbp
  91e291:	48 89 e5                                        	mov    rbp,rsp
  91e294:	31 c0                                           	xor    eax,eax
  91e296:	5d                                              	pop    rbp
  91e297:	c3                                              	ret
  91e298:	90                                              	nop
  91e299:	90                                              	nop
  91e29a:	90                                              	nop
  91e29b:	90                                              	nop
  91e29c:	90                                              	nop
  91e29d:	90                                              	nop
  91e29e:	90                                              	nop
  91e29f:	90                                              	nop
  91e2a0:	55                                              	push   rbp
  91e2a1:	48 89 e5                                        	mov    rbp,rsp
  91e2a4:	41 57                                           	push   r15
  91e2a6:	41 56                                           	push   r14
  91e2a8:	41 55                                           	push   r13
  91e2aa:	41 54                                           	push   r12
  91e2ac:	53                                              	push   rbx
  91e2ad:	48 83 ec 18                                     	sub    rsp,0x18
  91e2b1:	4c 8d 3d 58 e0 ff 02                            	lea    r15,[rip+0x2ffe058]        # 0x391c310
  91e2b8:	48 89 d3                                        	mov    rbx,rdx
  91e2bb:	49 8b 07                                        	mov    rax,QWORD PTR [r15]
  91e2be:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  91e2c2:	b8 03 52 30 c0                                  	mov    eax,0xc0305203
  91e2c7:	48 39 c6                                        	cmp    rsi,rax
  91e2ca:	0f 84 e6 00 00 00                               	je     0x91e3b6
  91e2d0:	b8 02 52 30 c0                                  	mov    eax,0xc0305202
  91e2d5:	48 39 c6                                        	cmp    rsi,rax
  91e2d8:	74 22                                           	je     0x91e2fc
  91e2da:	b8 fd ff ff ff                                  	mov    eax,0xfffffffd
  91e2df:	b9 01 52 30 c0                                  	mov    ecx,0xc0305201
  91e2e4:	48 39 ce                                        	cmp    rsi,rcx
  91e2e7:	0f 85 05 01 00 00                               	jne    0x91e3f2
  91e2ed:	41 bc 00 88 00 00                               	mov    r12d,0x8800
  91e2f3:	c7 45 c4 00 00 00 00                            	mov    DWORD PTR [rbp-0x3c],0x0
  91e2fa:	eb 0d                                           	jmp    0x91e309
  91e2fc:	c7 45 c4 01 00 00 00                            	mov    DWORD PTR [rbp-0x3c],0x1
  91e303:	41 bc 00 08 10 00                               	mov    r12d,0x100800
  91e309:	48 8d 35 a0 3b c3 01                            	lea    rsi,[rip+0x1c33ba0]        # 0x2551eb0
  91e310:	bf 00 08 10 00                                  	mov    edi,0x100800
  91e315:	ba 02 01 00 00                                  	mov    edx,0x102
  91e31a:	e8 31 a8 2e 00                                  	call   0xc08b50
  91e31f:	4c 8b 6b 20                                     	mov    r13,QWORD PTR [rbx+0x20]
  91e323:	49 89 c6                                        	mov    r14,rax
  91e326:	48 c7 45 c8 00 00 00 00                         	mov    QWORD PTR [rbp-0x38],0x0
  91e32e:	49 81 fd 01 08 00 00                            	cmp    r13,0x801
  91e335:	0f 92 c0                                        	setb   al
  91e338:	4d 39 e5                                        	cmp    r13,r12
  91e33b:	0f 97 c1                                        	seta   cl
  91e33e:	08 c1                                           	or     cl,al
  91e340:	74 10                                           	je     0x91e352
  91e342:	41 bc ea ff ff ff                               	mov    r12d,0xffffffea
  91e348:	4d 85 f6                                        	test   r14,r14
  91e34b:	75 58                                           	jne    0x91e3a5
  91e34d:	e9 9a 00 00 00                                  	jmp    0x91e3ec
  91e352:	4c 8b 63 18                                     	mov    r12,QWORD PTR [rbx+0x18]
  91e356:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  91e35f:	48 8d 35 d7 9b a7 00                            	lea    rsi,[rip+0xa79bd7]        # 0x1397f3d
  91e366:	31 d2                                           	xor    edx,edx
  91e368:	e8 73 c0 2f 00                                  	call   0xc1a3e0
  91e36d:	4c 89 e7                                        	mov    rdi,r12
  91e370:	4c 89 f6                                        	mov    rsi,r14
  91e373:	4c 89 ea                                        	mov    rdx,r13
  91e376:	e8 05 af 93 ff                                  	call   0x259280
  91e37b:	41 bc f2 ff ff ff                               	mov    r12d,0xfffffff2
  91e381:	85 c0                                           	test   eax,eax
  91e383:	75 20                                           	jne    0x91e3a5
  91e385:	44 8b 45 c4                                     	mov    r8d,DWORD PTR [rbp-0x3c]
  91e389:	48 8d 75 c8                                     	lea    rsi,[rbp-0x38]
  91e38d:	4c 89 f7                                        	mov    rdi,r14
  91e390:	4c 89 f2                                        	mov    rdx,r14
  91e393:	4c 89 e9                                        	mov    rcx,r13
  91e396:	45 31 c9                                        	xor    r9d,r9d
  91e399:	e8 b2 00 00 00                                  	call   0x91e450
  91e39e:	41 89 c4                                        	mov    r12d,eax
  91e3a1:	85 c0                                           	test   eax,eax
  91e3a3:	74 65                                           	je     0x91e40a
  91e3a5:	48 8d 35 04 3b c3 01                            	lea    rsi,[rip+0x1c33b04]        # 0x2551eb0
  91e3ac:	4c 89 f7                                        	mov    rdi,r14
  91e3af:	e8 3c aa 2e 00                                  	call   0xc08df0
  91e3b4:	eb 36                                           	jmp    0x91e3ec
  91e3b6:	83 3d 7b a0 25 03 00                            	cmp    DWORD PTR [rip+0x325a07b],0x0        # 0x3b78438
  91e3bd:	74 27                                           	je     0x91e3e6
  91e3bf:	44 8b 05 76 a0 25 03                            	mov    r8d,DWORD PTR [rip+0x325a076]        # 0x3b7843c
  91e3c6:	48 8d 15 73 a0 25 03                            	lea    rdx,[rip+0x325a073]        # 0x3b78440
  91e3cd:	b9 00 08 00 00                                  	mov    ecx,0x800
  91e3d2:	41 b9 01 00 00 00                               	mov    r9d,0x1
  91e3d8:	31 ff                                           	xor    edi,edi
  91e3da:	31 f6                                           	xor    esi,esi
  91e3dc:	e8 6f 00 00 00                                  	call   0x91e450
  91e3e1:	41 89 c4                                        	mov    r12d,eax
  91e3e4:	eb 06                                           	jmp    0x91e3ec
  91e3e6:	41 bc d8 ff ff ff                               	mov    r12d,0xffffffd8
  91e3ec:	31 c0                                           	xor    eax,eax
  91e3ee:	44 89 63 28                                     	mov    DWORD PTR [rbx+0x28],r12d
  91e3f2:	49 8b 0f                                        	mov    rcx,QWORD PTR [r15]
  91e3f5:	48 3b 4d d0                                     	cmp    rcx,QWORD PTR [rbp-0x30]
  91e3f9:	75 47                                           	jne    0x91e442
  91e3fb:	48 83 c4 18                                     	add    rsp,0x18
  91e3ff:	5b                                              	pop    rbx
  91e400:	41 5c                                           	pop    r12
  91e402:	41 5d                                           	pop    r13
  91e404:	41 5e                                           	pop    r14
  91e406:	41 5f                                           	pop    r15
  91e408:	5d                                              	pop    rbp
  91e409:	c3                                              	ret
  91e40a:	48 8b 43 08                                     	mov    rax,QWORD PTR [rbx+0x8]
  91e40e:	41 bc ea ff ff ff                               	mov    r12d,0xffffffea
  91e414:	48 85 c0                                        	test   rax,rax
  91e417:	74 8c                                           	je     0x91e3a5
  91e419:	48 8b 55 c8                                     	mov    rdx,QWORD PTR [rbp-0x38]
  91e41d:	48 39 d0                                        	cmp    rax,rdx
  91e420:	72 83                                           	jb     0x91e3a5
  91e422:	48 89 53 10                                     	mov    QWORD PTR [rbx+0x10],rdx
  91e426:	4c 89 f7                                        	mov    rdi,r14
  91e429:	48 8b 33                                        	mov    rsi,QWORD PTR [rbx]
  91e42c:	e8 df 03 00 00                                  	call   0x91e810
  91e431:	85 c0                                           	test   eax,eax
  91e433:	41 bc f2 ff ff ff                               	mov    r12d,0xfffffff2
  91e439:	44 0f 44 e0                                     	cmove  r12d,eax
  91e43d:	e9 63 ff ff ff                                  	jmp    0x91e3a5
  91e442:	e8 69 f2 dd ff                                  	call   0x6fd6b0
  91e447:	0f 0b                                           	ud2
  91e449:	90                                              	nop
  91e44a:	90                                              	nop
  91e44b:	90                                              	nop
  91e44c:	90                                              	nop
  91e44d:	90                                              	nop
  91e44e:	90                                              	nop
  91e44f:	90                                              	nop
  91e450:	55                                              	push   rbp
  91e451:	48 89 e5                                        	mov    rbp,rsp
  91e454:	41 57                                           	push   r15
  91e456:	41 56                                           	push   r14
  91e458:	41 55                                           	push   r13
  91e45a:	41 54                                           	push   r12
  91e45c:	53                                              	push   rbx
  91e45d:	48 81 ec 48 01 00 00                            	sub    rsp,0x148
  91e464:	48 8d 05 a5 de ff 02                            	lea    rax,[rip+0x2ffdea5]        # 0x391c310
  91e46b:	48 89 bd a8 fe ff ff                            	mov    QWORD PTR [rbp-0x158],rdi
  91e472:	48 89 b5 a0 fe ff ff                            	mov    QWORD PTR [rbp-0x160],rsi
  91e479:	45 85 c0                                        	test   r8d,r8d
  91e47c:	41 be 00 08 10 00                               	mov    r14d,0x100800
  91e482:	48 8d 3d 17 85 25 03                            	lea    rdi,[rip+0x3258517]        # 0x3b769a0
  91e489:	45 89 cc                                        	mov    r12d,r9d
  91e48c:	45 89 c7                                        	mov    r15d,r8d
  91e48f:	48 89 cb                                        	mov    rbx,rcx
  91e492:	49 89 d5                                        	mov    r13,rdx
  91e495:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  91e498:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  91e49c:	b8 00 88 00 00                                  	mov    eax,0x8800
  91e4a1:	48 c7 85 c8 fe ff ff ff ff ff ff                	mov    QWORD PTR [rbp-0x138],0xffffffffffffffff
  91e4ac:	48 c7 85 48 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0xb8],0x0
  91e4b7:	48 c7 85 40 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0xc0],0x0
  91e4c2:	48 c7 85 38 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0xc8],0x0
  91e4cd:	48 c7 85 30 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0xd0],0x0
  91e4d8:	48 c7 85 28 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0xd8],0x0
  91e4e3:	48 c7 85 20 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0xe0],0x0
  91e4ee:	48 c7 85 18 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0xe8],0x0
  91e4f9:	48 c7 85 10 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0xf0],0x0
  91e504:	48 c7 85 08 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0xf8],0x0
  91e50f:	48 c7 85 00 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x100],0x0
  91e51a:	48 c7 85 f8 fe ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x108],0x0
  91e525:	48 c7 85 f0 fe ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x110],0x0
  91e530:	48 c7 85 e8 fe ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x118],0x0
  91e53b:	48 c7 85 e0 fe ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x120],0x0
  91e546:	48 c7 85 d8 fe ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x128],0x0
  91e551:	48 c7 85 d0 fe ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x130],0x0
  91e55c:	48 c7 85 c0 fe ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x140],0x0
  91e567:	48 c7 85 b8 fe ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x148],0x0
  91e572:	4c 0f 44 f0                                     	cmove  r14,rax
  91e576:	31 f6                                           	xor    esi,esi
  91e578:	31 d2                                           	xor    edx,edx
  91e57a:	31 c9                                           	xor    ecx,ecx
  91e57c:	e8 9f d5 32 00                                  	call   0xc4bb20
  91e581:	45 85 e4                                        	test   r12d,r12d
  91e584:	75 25                                           	jne    0x91e5ab
  91e586:	48 8d 3d b3 9e 25 03                            	lea    rdi,[rip+0x3259eb3]        # 0x3b78440
  91e58d:	ba 00 08 00 00                                  	mov    edx,0x800
  91e592:	4c 89 ee                                        	mov    rsi,r13
  91e595:	c7 05 99 9e 25 03 01 00 00 00                   	mov    DWORD PTR [rip+0x3259e99],0x1        # 0x3b78438
  91e59f:	44 89 3d 96 9e 25 03                            	mov    DWORD PTR [rip+0x3259e96],r15d        # 0x3b7843c
  91e5a6:	e8 05 ab 93 ff                                  	call   0x2590b0
  91e5ab:	4c 8d 05 4e da 25 03                            	lea    r8,[rip+0x325da4e]        # 0x3b7c000
  91e5b2:	48 8d bd c0 fe ff ff                            	lea    rdi,[rbp-0x140]
  91e5b9:	48 8d b5 b8 fe ff ff                            	lea    rsi,[rbp-0x148]
  91e5c0:	41 b9 00 40 00 00                               	mov    r9d,0x4000
  91e5c6:	4c 89 ea                                        	mov    rdx,r13
  91e5c9:	48 89 d9                                        	mov    rcx,rbx
  91e5cc:	e8 9f 94 d1 ff                                  	call   0x637a70
  91e5d1:	85 c0                                           	test   eax,eax
  91e5d3:	75 35                                           	jne    0x91e60a
  91e5d5:	48 8d 85 c8 fe ff ff                            	lea    rax,[rbp-0x138]
  91e5dc:	48 8d 3d 81 7a a1 00                            	lea    rdi,[rip+0xa17a81]        # 0x1336064
  91e5e3:	41 b9 01 00 00 00                               	mov    r9d,0x1
  91e5e9:	4c 89 ad b0 fe ff ff                            	mov    QWORD PTR [rbp-0x150],r13
  91e5f0:	31 f6                                           	xor    esi,esi
  91e5f2:	31 d2                                           	xor    edx,edx
  91e5f4:	31 c9                                           	xor    ecx,ecx
  91e5f6:	45 31 c0                                        	xor    r8d,r8d
  91e5f9:	48 89 04 24                                     	mov    QWORD PTR [rsp],rax
  91e5fd:	e8 fe 5b c8 ff                                  	call   0x5a4200
  91e602:	85 c0                                           	test   eax,eax
  91e604:	0f 84 17 01 00 00                               	je     0x91e721
  91e60a:	41 89 c5                                        	mov    r13d,eax
  91e60d:	48 8b 9d c8 fe ff ff                            	mov    rbx,QWORD PTR [rbp-0x138]
  91e614:	48 83 fb ff                                     	cmp    rbx,0xffffffffffffffff
  91e618:	0f 84 b9 00 00 00                               	je     0x91e6d7
  91e61e:	48 8d 95 50 ff ff ff                            	lea    rdx,[rbp-0xb0]
  91e625:	48 89 df                                        	mov    rdi,rbx
  91e628:	48 c7 85 50 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0xb0],0x0
  91e633:	48 c7 45 c8 00 00 00 00                         	mov    QWORD PTR [rbp-0x38],0x0
  91e63b:	48 c7 45 c0 00 00 00 00                         	mov    QWORD PTR [rbp-0x40],0x0
  91e643:	48 c7 45 b8 00 00 00 00                         	mov    QWORD PTR [rbp-0x48],0x0
  91e64b:	48 c7 45 b0 00 00 00 00                         	mov    QWORD PTR [rbp-0x50],0x0
  91e653:	48 c7 45 a8 00 00 00 00                         	mov    QWORD PTR [rbp-0x58],0x0
  91e65b:	48 c7 45 a0 00 00 00 00                         	mov    QWORD PTR [rbp-0x60],0x0
  91e663:	48 c7 45 98 00 00 00 00                         	mov    QWORD PTR [rbp-0x68],0x0
  91e66b:	48 c7 45 90 00 00 00 00                         	mov    QWORD PTR [rbp-0x70],0x0
  91e673:	48 c7 45 88 00 00 00 00                         	mov    QWORD PTR [rbp-0x78],0x0
  91e67b:	48 c7 45 80 00 00 00 00                         	mov    QWORD PTR [rbp-0x80],0x0
  91e683:	48 c7 85 78 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x88],0x0
  91e68e:	48 c7 85 70 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x90],0x0
  91e699:	48 c7 85 68 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0x98],0x0
  91e6a4:	48 c7 85 60 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0xa0],0x0
  91e6af:	48 c7 85 58 ff ff ff 00 00 00 00                	mov    QWORD PTR [rbp-0xa8],0x0
  91e6ba:	66 c7 85 50 ff ff ff ff ff                      	mov    WORD PTR [rbp-0xb0],0xffff
  91e6c3:	48 89 d6                                        	mov    rsi,rdx
  91e6c6:	e8 45 5f c8 ff                                  	call   0x5a4610
  91e6cb:	85 c0                                           	test   eax,eax
  91e6cd:	75 08                                           	jne    0x91e6d7
  91e6cf:	48 89 df                                        	mov    rdi,rbx
  91e6d2:	e8 99 5e c8 ff                                  	call   0x5a4570
  91e6d7:	48 8b bd b8 fe ff ff                            	mov    rdi,QWORD PTR [rbp-0x148]
  91e6de:	48 85 ff                                        	test   rdi,rdi
  91e6e1:	74 05                                           	je     0x91e6e8
  91e6e3:	e8 a8 93 d1 ff                                  	call   0x637a90
  91e6e8:	48 8d 3d b1 82 25 03                            	lea    rdi,[rip+0x32582b1]        # 0x3b769a0
  91e6ef:	31 f6                                           	xor    esi,esi
  91e6f1:	31 d2                                           	xor    edx,edx
  91e6f3:	e8 b8 dd 32 00                                  	call   0xc4c4b0
  91e6f8:	48 8d 05 11 dc ff 02                            	lea    rax,[rip+0x2ffdc11]        # 0x391c310
  91e6ff:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  91e702:	48 3b 45 d0                                     	cmp    rax,QWORD PTR [rbp-0x30]
  91e706:	0f 85 f9 00 00 00                               	jne    0x91e805
  91e70c:	44 89 e8                                        	mov    eax,r13d
  91e70f:	48 81 c4 48 01 00 00                            	add    rsp,0x148
  91e716:	5b                                              	pop    rbx
  91e717:	41 5c                                           	pop    r12
  91e719:	41 5d                                           	pop    r13
  91e71b:	41 5e                                           	pop    r14
  91e71d:	41 5f                                           	pop    r15
  91e71f:	5d                                              	pop    rbp
  91e720:	c3                                              	ret
  91e721:	48 8b 8d c0 fe ff ff                            	mov    rcx,QWORD PTR [rbp-0x140]
  91e728:	41 83 ff 01                                     	cmp    r15d,0x1
  91e72c:	66 b8 02 00                                     	mov    ax,0x2
  91e730:	48 8d 3d c9 98 25 03                            	lea    rdi,[rip+0x32598c9]        # 0x3b78000
  91e737:	66 83 d8 00                                     	sbb    ax,0x0
  91e73b:	66 89 85 d0 fe ff ff                            	mov    WORD PTR [rbp-0x130],ax
  91e742:	66 c7 85 d2 fe ff ff 00 00                      	mov    WORD PTR [rbp-0x12e],0x0
  91e74b:	c7 85 d4 fe ff ff 00 00 00 00                   	mov    DWORD PTR [rbp-0x12c],0x0
  91e755:	48 89 8d d8 fe ff ff                            	mov    QWORD PTR [rbp-0x128],rcx
  91e75c:	48 89 9d e0 fe ff ff                            	mov    QWORD PTR [rbp-0x120],rbx
  91e763:	e8 c8 fb fb ff                                  	call   0x8de330
  91e768:	48 8b bd c8 fe ff ff                            	mov    rdi,QWORD PTR [rbp-0x138]
  91e76f:	48 8d 95 d0 fe ff ff                            	lea    rdx,[rbp-0x130]
  91e776:	48 89 85 e8 fe ff ff                            	mov    QWORD PTR [rbp-0x118],rax
  91e77d:	44 89 a5 f0 fe ff ff                            	mov    DWORD PTR [rbp-0x110],r12d
  91e784:	48 89 d6                                        	mov    rsi,rdx
  91e787:	e8 84 5e c8 ff                                  	call   0x5a4610
  91e78c:	44 8b ad d4 fe ff ff                            	mov    r13d,DWORD PTR [rbp-0x12c]
  91e793:	89 c1                                           	mov    ecx,eax
  91e795:	44 09 e9                                        	or     ecx,r13d
  91e798:	75 60                                           	jne    0x91e7fa
  91e79a:	45 31 ed                                        	xor    r13d,r13d
  91e79d:	45 85 e4                                        	test   r12d,r12d
  91e7a0:	0f 85 67 fe ff ff                               	jne    0x91e60d
  91e7a6:	48 8b 85 d8 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x128]
  91e7ad:	41 bd da ff ff ff                               	mov    r13d,0xffffffda
  91e7b3:	48 3d 00 08 00 00                               	cmp    rax,0x800
  91e7b9:	0f 87 4e fe ff ff                               	ja     0x91e60d
  91e7bf:	48 8b 9d e0 fe ff ff                            	mov    rbx,QWORD PTR [rbp-0x120]
  91e7c6:	4c 39 f3                                        	cmp    rbx,r14
  91e7c9:	0f 87 3e fe ff ff                               	ja     0x91e60d
  91e7cf:	48 8b b5 b0 fe ff ff                            	mov    rsi,QWORD PTR [rbp-0x150]
  91e7d6:	48 8b bd a8 fe ff ff                            	mov    rdi,QWORD PTR [rbp-0x158]
  91e7dd:	48 89 da                                        	mov    rdx,rbx
  91e7e0:	48 01 c6                                        	add    rsi,rax
  91e7e3:	e8 c8 a8 93 ff                                  	call   0x2590b0
  91e7e8:	48 8b 85 a0 fe ff ff                            	mov    rax,QWORD PTR [rbp-0x160]
  91e7ef:	45 31 ed                                        	xor    r13d,r13d
  91e7f2:	48 89 18                                        	mov    QWORD PTR [rax],rbx
  91e7f5:	e9 13 fe ff ff                                  	jmp    0x91e60d
  91e7fa:	85 c0                                           	test   eax,eax
  91e7fc:	44 0f 45 e8                                     	cmovne r13d,eax
  91e800:	e9 08 fe ff ff                                  	jmp    0x91e60d
  91e805:	e8 a6 ee dd ff                                  	call   0x6fd6b0
  91e80a:	0f 0b                                           	ud2
  91e80c:	90                                              	nop
  91e80d:	90                                              	nop
  91e80e:	90                                              	nop
  91e80f:	90                                              	nop
  91e810:	55                                              	push   rbp
  91e811:	48 89 e5                                        	mov    rbp,rsp
  91e814:	41 57                                           	push   r15
  91e816:	41 56                                           	push   r14
  91e818:	53                                              	push   rbx
  91e819:	50                                              	push   rax
  91e81a:	49 89 ff                                        	mov    r15,rdi
  91e81d:	65 48 8b 3c 25 00 00 00 00                      	mov    rdi,QWORD PTR gs:0x0
  91e826:	49 89 f6                                        	mov    r14,rsi
  91e829:	48 8d 35 67 0a a3 00                            	lea    rsi,[rip+0xa30a67]        # 0x134f297
  91e830:	48 89 d3                                        	mov    rbx,rdx
  91e833:	31 d2                                           	xor    edx,edx
  91e835:	e8 a6 bb 2f 00                                  	call   0xc1a3e0
  91e83a:	4c 89 ff                                        	mov    rdi,r15
  91e83d:	4c 89 f6                                        	mov    rsi,r14
  91e840:	48 89 da                                        	mov    rdx,rbx
  91e843:	48 83 c4 08                                     	add    rsp,0x8
  91e847:	5b                                              	pop    rbx
  91e848:	41 5e                                           	pop    r14
  91e84a:	41 5f                                           	pop    r15
  91e84c:	5d                                              	pop    rbp
  91e84d:	e9 7e a9 93 ff                                  	jmp    0x2591d0
  91e852:	90                                              	nop
  91e853:	90                                              	nop
  91e854:	90                                              	nop
  91e855:	90                                              	nop
  91e856:	90                                              	nop
  91e857:	90                                              	nop
  91e858:	90                                              	nop
  91e859:	90                                              	nop
  91e85a:	90                                              	nop
  91e85b:	90                                              	nop
  91e85c:	90                                              	nop
  91e85d:	90                                              	nop
  91e85e:	90                                              	nop
  91e85f:	90                                              	nop
  91e860:	55                                              	push   rbp
  91e861:	48 89 e5                                        	mov    rbp,rsp
  91e864:	4c 8b 87 b8 00 00 00                            	mov    r8,QWORD PTR [rdi+0xb8]
  91e86b:	48 89 f1                                        	mov    rcx,rsi
  91e86e:	85 d2                                           	test   edx,edx
  91e870:	7e 3a                                           	jle    0x91e8ac
  91e872:	31 c0                                           	xor    eax,eax
  91e874:	49 39 f0                                        	cmp    r8,rsi
  91e877:	48 89 f1                                        	mov    rcx,rsi
  91e87a:	0f 95 c0                                        	setne  al
  91e87d:	c1 e0 15                                        	shl    eax,0x15
  91e880:	0d ff ff cf ff                                  	or     eax,0xffcfffff
  91e885:	eb 10                                           	jmp    0x91e897
  91e887:	66 0f 1f 84 00 00 00 00 00                      	nop    WORD PTR [rax+rax*1+0x0]
  91e890:	48 8b 09                                        	mov    rcx,QWORD PTR [rcx]
  91e893:	ff ca                                           	dec    edx
  91e895:	74 15                                           	je     0x91e8ac
  91e897:	21 41 1c                                        	and    DWORD PTR [rcx+0x1c],eax
  91e89a:	49 39 f0                                        	cmp    r8,rsi
  91e89d:	75 f1                                           	jne    0x91e890
  91e89f:	44 8b 49 18                                     	mov    r9d,DWORD PTR [rcx+0x18]
  91e8a3:	44 01 8f c4 00 00 00                            	add    DWORD PTR [rdi+0xc4],r9d
  91e8aa:	eb e4                                           	jmp    0x91e890
  91e8ac:	b8 24 00 00 00                                  	mov    eax,0x24
  91e8b1:	49 39 f0                                        	cmp    r8,rsi
  91e8b4:	74 02                                           	je     0x91e8b8
  91e8b6:	5d                                              	pop    rbp
  91e8b7:	c3                                              	ret
  91e8b8:	31 c0                                           	xor    eax,eax
  91e8ba:	48 85 c9                                        	test   rcx,rcx
  91e8bd:	74 26                                           	je     0x91e8e5
  91e8bf:	90                                              	nop
  91e8c0:	8b 51 1c                                        	mov    edx,DWORD PTR [rcx+0x1c]
  91e8c3:	f7 c2 00 00 10 00                               	test   edx,0x100000
  91e8c9:	75 1c                                           	jne    0x91e8e7
  91e8cb:	81 e2 ff ff cf ff                               	and    edx,0xffcfffff
  91e8d1:	89 51 1c                                        	mov    DWORD PTR [rcx+0x1c],edx
  91e8d4:	8b 51 18                                        	mov    edx,DWORD PTR [rcx+0x18]
  91e8d7:	01 97 c4 00 00 00                               	add    DWORD PTR [rdi+0xc4],edx
  91e8dd:	48 8b 09                                        	mov    rcx,QWORD PTR [rcx]
  91e8e0:	48 85 c9                                        	test   rcx,rcx
  91e8e3:	75 db                                           	jne    0x91e8c0
  91e8e5:	31 c9                                           	xor    ecx,ecx
  91e8e7:	48 89 8f b8 00 00 00                            	mov    QWORD PTR [rdi+0xb8],rcx
  91e8ee:	5d                                              	pop    rbp
  91e8ef:	c3                                              	ret
  91e8f0:	55                                              	push   rbp
  91e8f1:	48 89 e5                                        	mov    rbp,rsp
  91e8f4:	41 56                                           	push   r14
  91e8f6:	53                                              	push   rbx
  91e8f7:	8b 46 18                                        	mov    eax,DWORD PTR [rsi+0x18]
  91e8fa:	49 89 f6                                        	mov    r14,rsi
  91e8fd:	48 89 fb                                        	mov    rbx,rdi
  91e900:	01 87 c8 00 00 00                               	add    DWORD PTR [rdi+0xc8],eax
  91e906:	8b 76 18                                        	mov    esi,DWORD PTR [rsi+0x18]
  91e909:	e8 82 8c d7 ff                                  	call   0x697590
  91e90e:	8b 83 c8 00 00 00                               	mov    eax,DWORD PTR [rbx+0xc8]
  91e914:	3b 83 94 00 00 00                               	cmp    eax,DWORD PTR [rbx+0x94]
  91e91a:	76 06                                           	jbe    0x91e922
  91e91c:	89 83 94 00 00 00                               	mov    DWORD PTR [rbx+0x94],eax
  91e922:	48 83 bb b8 00 00 00 00                         	cmp    QWORD PTR [rbx+0xb8],0x0
  91e92a:	41 8b 46 1c                                     	mov    eax,DWORD PTR [r14+0x1c]
  91e92e:	74 0b                                           	je     0x91e93b
  91e930:	0d 00 00 20 00                                  	or     eax,0x200000
  91e935:	41 89 46 1c                                     	mov    DWORD PTR [r14+0x1c],eax
  91e939:	eb 1a                                           	jmp    0x91e955
  91e93b:	a9 00 00 10 00                                  	test   eax,0x100000
  91e940:	75 0c                                           	jne    0x91e94e
  91e942:	41 8b 46 18                                     	mov    eax,DWORD PTR [r14+0x18]
  91e946:	01 83 c4 00 00 00                               	add    DWORD PTR [rbx+0xc4],eax
  91e94c:	eb 07                                           	jmp    0x91e955
  91e94e:	4c 89 b3 b8 00 00 00                            	mov    QWORD PTR [rbx+0xb8],r14
  91e955:	41 0f b6 46 1c                                  	movzx  eax,BYTE PTR [r14+0x1c]
  91e95a:	83 f8 01                                        	cmp    eax,0x1
  91e95d:	74 0f                                           	je     0x91e96e
  91e95f:	83 f8 10                                        	cmp    eax,0x10
  91e962:	74 0a                                           	je     0x91e96e
  91e964:	41 8b 46 18                                     	mov    eax,DWORD PTR [r14+0x18]
  91e968:	01 83 e0 00 00 00                               	add    DWORD PTR [rbx+0xe0],eax
  91e96e:	b8 00 01 00 00                                  	mov    eax,0x100
  91e973:	03 83 d0 00 00 00                               	add    eax,DWORD PTR [rbx+0xd0]
  91e979:	89 83 d0 00 00 00                               	mov    DWORD PTR [rbx+0xd0],eax
  91e97f:	ff 83 d4 00 00 00                               	inc    DWORD PTR [rbx+0xd4]
  91e985:	41 f6 46 1d 01                                  	test   BYTE PTR [r14+0x1d],0x1
  91e98a:	74 13                                           	je     0x91e99f
  91e98c:	41 03 86 88 00 00 00                            	add    eax,DWORD PTR [r14+0x88]
  91e993:	89 83 d0 00 00 00                               	mov    DWORD PTR [rbx+0xd0],eax
  91e999:	ff 83 d8 00 00 00                               	inc    DWORD PTR [rbx+0xd8]
  91e99f:	5b                                              	pop    rbx
  91e9a0:	41 5e                                           	pop    r14
  91e9a2:	5d                                              	pop    rbp
  91e9a3:	c3                                              	ret
  91e9a4:	90                                              	nop
  91e9a5:	90                                              	nop
  91e9a6:	90                                              	nop
  91e9a7:	90                                              	nop
  91e9a8:	90                                              	nop
  91e9a9:	90                                              	nop
  91e9aa:	90                                              	nop
  91e9ab:	90                                              	nop
  91e9ac:	90                                              	nop
  91e9ad:	90                                              	nop
  91e9ae:	90                                              	nop
  91e9af:	90                                              	nop
  91e9b0:	55                                              	push   rbp
  91e9b1:	48 89 e5                                        	mov    rbp,rsp
  91e9b4:	41 56                                           	push   r14
  91e9b6:	53                                              	push   rbx
  91e9b7:	8b 46 18                                        	mov    eax,DWORD PTR [rsi+0x18]
  91e9ba:	49 89 f6                                        	mov    r14,rsi
  91e9bd:	48 89 fb                                        	mov    rbx,rdi
  91e9c0:	29 87 c8 00 00 00                               	sub    DWORD PTR [rdi+0xc8],eax
  91e9c6:	8b 76 18                                        	mov    esi,DWORD PTR [rsi+0x18]
  91e9c9:	e8 82 8c d7 ff                                  	call   0x697650
  91e9ce:	41 f6 46 1e 30                                  	test   BYTE PTR [r14+0x1e],0x30
  91e9d3:	74 0b                                           	je     0x91e9e0
  91e9d5:	4c 3b b3 b8 00 00 00                            	cmp    r14,QWORD PTR [rbx+0xb8]
  91e9dc:	75 50                                           	jne    0x91ea2e
  91e9de:	eb 13                                           	jmp    0x91e9f3
  91e9e0:	41 8b 46 18                                     	mov    eax,DWORD PTR [r14+0x18]
  91e9e4:	29 83 c4 00 00 00                               	sub    DWORD PTR [rbx+0xc4],eax
  91e9ea:	4c 3b b3 b8 00 00 00                            	cmp    r14,QWORD PTR [rbx+0xb8]
  91e9f1:	75 3b                                           	jne    0x91ea2e
  91e9f3:	49 8b 06                                        	mov    rax,QWORD PTR [r14]
  91e9f6:	48 85 c0                                        	test   rax,rax
  91e9f9:	74 2a                                           	je     0x91ea25
  91e9fb:	0f 1f 44 00 00                                  	nop    DWORD PTR [rax+rax*1+0x0]
  91ea00:	8b 48 1c                                        	mov    ecx,DWORD PTR [rax+0x1c]
  91ea03:	f7 c1 00 00 10 00                               	test   ecx,0x100000
  91ea09:	75 1c                                           	jne    0x91ea27
  91ea0b:	81 e1 ff ff cf ff                               	and    ecx,0xffcfffff
  91ea11:	89 48 1c                                        	mov    DWORD PTR [rax+0x1c],ecx
  91ea14:	8b 48 18                                        	mov    ecx,DWORD PTR [rax+0x18]
  91ea17:	01 8b c4 00 00 00                               	add    DWORD PTR [rbx+0xc4],ecx
  91ea1d:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  91ea20:	48 85 c0                                        	test   rax,rax
  91ea23:	75 db                                           	jne    0x91ea00
  91ea25:	31 c0                                           	xor    eax,eax
  91ea27:	48 89 83 b8 00 00 00                            	mov    QWORD PTR [rbx+0xb8],rax
  91ea2e:	41 0f b6 46 1c                                  	movzx  eax,BYTE PTR [r14+0x1c]
  91ea33:	83 f8 01                                        	cmp    eax,0x1
  91ea36:	74 0f                                           	je     0x91ea47
  91ea38:	83 f8 10                                        	cmp    eax,0x10
  91ea3b:	74 0a                                           	je     0x91ea47
  91ea3d:	41 8b 46 18                                     	mov    eax,DWORD PTR [r14+0x18]
  91ea41:	29 83 e0 00 00 00                               	sub    DWORD PTR [rbx+0xe0],eax
  91ea47:	b8 00 ff ff ff                                  	mov    eax,0xffffff00
  91ea4c:	03 83 d0 00 00 00                               	add    eax,DWORD PTR [rbx+0xd0]
  91ea52:	89 83 d0 00 00 00                               	mov    DWORD PTR [rbx+0xd0],eax
  91ea58:	ff 8b d4 00 00 00                               	dec    DWORD PTR [rbx+0xd4]
  91ea5e:	41 f6 46 1d 01                                  	test   BYTE PTR [r14+0x1d],0x1
  91ea63:	74 13                                           	je     0x91ea78
  91ea65:	41 2b 86 88 00 00 00                            	sub    eax,DWORD PTR [r14+0x88]
  91ea6c:	89 83 d0 00 00 00                               	mov    DWORD PTR [rbx+0xd0],eax
  91ea72:	ff 8b d8 00 00 00                               	dec    DWORD PTR [rbx+0xd8]
  91ea78:	4c 39 b3 b0 00 00 00                            	cmp    QWORD PTR [rbx+0xb0],r14
  91ea7f:	74 16                                           	je     0x91ea97
  91ea81:	8b 83 c0 00 00 00                               	mov    eax,DWORD PTR [rbx+0xc0]
  91ea87:	85 c0                                           	test   eax,eax
  91ea89:	74 21                                           	je     0x91eaac
  91ea8b:	41 2b 46 18                                     	sub    eax,DWORD PTR [r14+0x18]
  91ea8f:	89 83 c0 00 00 00                               	mov    DWORD PTR [rbx+0xc0],eax
  91ea95:	eb 15                                           	jmp    0x91eaac
  91ea97:	48 c7 83 b0 00 00 00 00 00 00 00                	mov    QWORD PTR [rbx+0xb0],0x0
  91eaa2:	c7 83 c0 00 00 00 00 00 00 00                   	mov    DWORD PTR [rbx+0xc0],0x0
  91eaac:	5b                                              	pop    rbx
  91eaad:	41 5e                                           	pop    r14
  91eaaf:	5d                                              	pop    rbp
  91eab0:	c3                                              	ret
  91eab1:	90                                              	nop
  91eab2:	90                                              	nop
  91eab3:	90                                              	nop
  91eab4:	90                                              	nop
  91eab5:	90                                              	nop
  91eab6:	90                                              	nop
  91eab7:	90                                              	nop
  91eab8:	90                                              	nop
  91eab9:	90                                              	nop
  91eaba:	90                                              	nop
  91eabb:	90                                              	nop
  91eabc:	90                                              	nop
  91eabd:	90                                              	nop
  91eabe:	90                                              	nop
  91eabf:	90                                              	nop
  91eac0:	55                                              	push   rbp
  91eac1:	48 89 e5                                        	mov    rbp,rsp
  91eac4:	41 56                                           	push   r14
  91eac6:	53                                              	push   rbx
  91eac7:	80 8f 60 02 00 00 10                            	or     BYTE PTR [rdi+0x260],0x10
  91eace:	49 89 fe                                        	mov    r14,rdi
  91ead1:	48 8b 9f 48 04 00 00                            	mov    rbx,QWORD PTR [rdi+0x448]
  91ead8:	0f b7 87 c0 02 00 00                            	movzx  eax,WORD PTR [rdi+0x2c0]
  91eadf:	a9 bc 01 00 00                                  	test   eax,0x1bc
  91eae4:	74 16                                           	je     0x91eafc
  91eae6:	49 8d b6 d0 01 00 00                            	lea    rsi,[r14+0x1d0]
  91eaed:	4c 89 f7                                        	mov    rdi,r14
  91eaf0:	e8 7b 00 00 00                                  	call   0x91eb70
  91eaf5:	48 85 db                                        	test   rbx,rbx
  91eaf8:	75 19                                           	jne    0x91eb13
  91eafa:	eb 5a                                           	jmp    0x91eb56
  91eafc:	49 8d be 38 02 00 00                            	lea    rdi,[r14+0x238]
  91eb03:	31 f6                                           	xor    esi,esi
  91eb05:	31 d2                                           	xor    edx,edx
  91eb07:	31 c9                                           	xor    ecx,ecx
  91eb09:	e8 92 84 ba ff                                  	call   0x4c6fa0
  91eb0e:	48 85 db                                        	test   rbx,rbx
  91eb11:	74 43                                           	je     0x91eb56
  91eb13:	41 f6 46 10 01                                  	test   BYTE PTR [r14+0x10],0x1
  91eb18:	75 3c                                           	jne    0x91eb56
  91eb1a:	4c 8d b3 38 02 00 00                            	lea    r14,[rbx+0x238]
  91eb21:	31 f6                                           	xor    esi,esi
  91eb23:	31 d2                                           	xor    edx,edx
  91eb25:	31 c9                                           	xor    ecx,ecx
  91eb27:	4c 89 f7                                        	mov    rdi,r14
  91eb2a:	e8 d1 7e ba ff                                  	call   0x4c6a00
  91eb2f:	66 c7 43 76 a5 00                               	mov    WORD PTR [rbx+0x76],0xa5
  91eb35:	0f b7 83 c0 02 00 00                            	movzx  eax,WORD PTR [rbx+0x2c0]
  91eb3c:	a9 bc 01 00 00                                  	test   eax,0x1bc
  91eb41:	74 18                                           	je     0x91eb5b
  91eb43:	48 8d b3 d0 01 00 00                            	lea    rsi,[rbx+0x1d0]
  91eb4a:	48 89 df                                        	mov    rdi,rbx
  91eb4d:	5b                                              	pop    rbx
  91eb4e:	41 5e                                           	pop    r14
  91eb50:	5d                                              	pop    rbp
  91eb51:	e9 1a 00 00 00                                  	jmp    0x91eb70
  91eb56:	5b                                              	pop    rbx
  91eb57:	41 5e                                           	pop    r14
  91eb59:	5d                                              	pop    rbp
  91eb5a:	c3                                              	ret
  91eb5b:	4c 89 f7                                        	mov    rdi,r14
  91eb5e:	31 f6                                           	xor    esi,esi
  91eb60:	31 d2                                           	xor    edx,edx
  91eb62:	31 c9                                           	xor    ecx,ecx
  91eb64:	5b                                              	pop    rbx
  91eb65:	41 5e                                           	pop    r14
  91eb67:	5d                                              	pop    rbp
  91eb68:	e9 33 84 ba ff                                  	jmp    0x4c6fa0
  91eb6d:	90                                              	nop
  91eb6e:	90                                              	nop
  91eb6f:	90                                              	nop
  91eb70:	55                                              	push   rbp
  91eb71:	48 89 e5                                        	mov    rbp,rsp
  91eb74:	41 57                                           	push   r15
  91eb76:	41 56                                           	push   r14
  91eb78:	53                                              	push   rbx
  91eb79:	50                                              	push   rax
  91eb7a:	48 89 fb                                        	mov    rbx,rdi
  91eb7d:	49 89 f6                                        	mov    r14,rsi
  91eb80:	48 89 f7                                        	mov    rdi,rsi
  91eb83:	be 58 00 00 00                                  	mov    esi,0x58
  91eb88:	e8 83 06 bd ff                                  	call   0x4ef210
  91eb8d:	49 83 3e 00                                     	cmp    QWORD PTR [r14],0x0
  91eb91:	41 0f b7 86 f0 00 00 00                         	movzx  eax,WORD PTR [r14+0xf0]
  91eb99:	0f 84 e0 00 00 00                               	je     0x91ec7f
  91eb9f:	a8 04                                           	test   al,0x4
  91eba1:	74 19                                           	je     0x91ebbc
  91eba3:	25 fb ff 00 00                                  	and    eax,0xfffb
  91eba8:	49 8d be c4 00 00 00                            	lea    rdi,[r14+0xc4]
  91ebaf:	66 41 89 86 f0 00 00 00                         	mov    WORD PTR [r14+0xf0],ax
  91ebb7:	e8 54 7d 2e 00                                  	call   0xc06910
  91ebbc:	49 8d 7e 10                                     	lea    rdi,[r14+0x10]
  91ebc0:	ba 01 00 00 00                                  	mov    edx,0x1
  91ebc5:	31 f6                                           	xor    esi,esi
  91ebc7:	e8 84 51 9f ff                                  	call   0x313d50
  91ebcc:	4d 8b be 08 01 00 00                            	mov    r15,QWORD PTR [r14+0x108]
  91ebd3:	4d 85 ff                                        	test   r15,r15
  91ebd6:	74 60                                           	je     0x91ec38
  91ebd8:	48 8d 05 71 c9 94 ff                            	lea    rax,[rip+0xffffffffff94c971]        # 0x26b550
  91ebdf:	4c 29 f8                                        	sub    rax,r15
  91ebe2:	48 c1 c8 03                                     	ror    rax,0x3
  91ebe6:	48 3d a4 00 00 00                               	cmp    rax,0xa4
  91ebec:	0f 87 a7 00 00 00                               	ja     0x91ec99
  91ebf2:	49 8b b6 10 01 00 00                            	mov    rsi,QWORD PTR [r14+0x110]
  91ebf9:	48 89 df                                        	mov    rdi,rbx
  91ebfc:	ba 01 00 00 00                                  	mov    edx,0x1
  91ec01:	41 ff d7                                        	call   r15
  91ec04:	83 f8 01                                        	cmp    eax,0x1
  91ec07:	75 2f                                           	jne    0x91ec38
  91ec09:	48 89 df                                        	mov    rdi,rbx
  91ec0c:	be 01 00 00 00                                  	mov    esi,0x1
  91ec11:	e8 da e8 be ff                                  	call   0x50d4f0
  91ec16:	49 83 c6 68                                     	add    r14,0x68
  91ec1a:	31 f6                                           	xor    esi,esi
  91ec1c:	31 d2                                           	xor    edx,edx
  91ec1e:	31 c9                                           	xor    ecx,ecx
  91ec20:	4c 89 f7                                        	mov    rdi,r14
  91ec23:	e8 78 83 ba ff                                  	call   0x4c6fa0
  91ec28:	48 89 df                                        	mov    rdi,rbx
  91ec2b:	e8 00 e4 be ff                                  	call   0x50d030
  91ec30:	f6 43 11 02                                     	test   BYTE PTR [rbx+0x11],0x2
  91ec34:	75 1a                                           	jne    0x91ec50
  91ec36:	eb 3c                                           	jmp    0x91ec74
  91ec38:	49 83 c6 68                                     	add    r14,0x68
  91ec3c:	31 f6                                           	xor    esi,esi
  91ec3e:	31 d2                                           	xor    edx,edx
  91ec40:	31 c9                                           	xor    ecx,ecx
  91ec42:	4c 89 f7                                        	mov    rdi,r14
  91ec45:	e8 56 83 ba ff                                  	call   0x4c6fa0
  91ec4a:	f6 43 11 02                                     	test   BYTE PTR [rbx+0x11],0x2
  91ec4e:	74 24                                           	je     0x91ec74
  91ec50:	48 83 7b 78 00                                  	cmp    QWORD PTR [rbx+0x78],0x0
  91ec55:	74 1d                                           	je     0x91ec74
  91ec57:	48 83 c3 78                                     	add    rbx,0x78
  91ec5b:	be 17 00 00 00                                  	mov    esi,0x17
  91ec60:	31 d2                                           	xor    edx,edx
  91ec62:	48 89 df                                        	mov    rdi,rbx
  91ec65:	48 83 c4 08                                     	add    rsp,0x8
  91ec69:	5b                                              	pop    rbx
  91ec6a:	41 5e                                           	pop    r14
  91ec6c:	41 5f                                           	pop    r15
  91ec6e:	5d                                              	pop    rbp
  91ec6f:	e9 1c 35 c4 ff                                  	jmp    0x562190
  91ec74:	48 83 c4 08                                     	add    rsp,0x8
  91ec78:	5b                                              	pop    rbx
  91ec79:	41 5e                                           	pop    r14
  91ec7b:	41 5f                                           	pop    r15
  91ec7d:	5d                                              	pop    rbp
  91ec7e:	c3                                              	ret
  91ec7f:	25 f7 ff 00 00                                  	and    eax,0xfff7
  91ec84:	66 41 89 86 f0 00 00 00                         	mov    WORD PTR [r14+0xf0],ax
  91ec8c:	a8 04                                           	test   al,0x4
  91ec8e:	0f 85 0f ff ff ff                               	jne    0x91eba3
  91ec94:	e9 23 ff ff ff                                  	jmp    0x91ebbc
  91ec99:	48 8d 3d f0 33 c3 01                            	lea    rdi,[rip+0x1c333f0]        # 0x2552090
  91eca0:	4c 89 fe                                        	mov    rsi,r15
  91eca3:	e8 18 0c b3 ff                                  	call   0x44f8c0
  91eca8:	e9 45 ff ff ff                                  	jmp    0x91ebf2
  91ecad:	90                                              	nop
  91ecae:	90                                              	nop
  91ecaf:	90                                              	nop
  91ecb0:	55                                              	push   rbp
  91ecb1:	48 89 e5                                        	mov    rbp,rsp
  91ecb4:	53                                              	push   rbx
  91ecb5:	50                                              	push   rax
  91ecb6:	48 89 fb                                        	mov    rbx,rdi
  91ecb9:	48 81 c7 38 02 00 00                            	add    rdi,0x238
  91ecc0:	31 f6                                           	xor    esi,esi
  91ecc2:	31 d2                                           	xor    edx,edx
  91ecc4:	31 c9                                           	xor    ecx,ecx
  91ecc6:	e8 35 7d ba ff                                  	call   0x4c6a00
  91eccb:	48 89 df                                        	mov    rdi,rbx
  91ecce:	48 83 c4 08                                     	add    rsp,0x8
  91ecd2:	5b                                              	pop    rbx
  91ecd3:	5d                                              	pop    rbp
  91ecd4:	e9 e7 fd ff ff                                  	jmp    0x91eac0
  91ecd9:	90                                              	nop
  91ecda:	90                                              	nop
  91ecdb:	90                                              	nop
  91ecdc:	90                                              	nop
  91ecdd:	90                                              	nop
  91ecde:	90                                              	nop
  91ecdf:	90                                              	nop
  91ece0:	55                                              	push   rbp
  91ece1:	48 89 e5                                        	mov    rbp,rsp
  91ece4:	41 56                                           	push   r14
  91ece6:	53                                              	push   rbx
  91ece7:	80 8f 18 01 00 00 20                            	or     BYTE PTR [rdi+0x118],0x20
  91ecee:	49 89 fe                                        	mov    r14,rdi
  91ecf1:	48 8b 9f 48 04 00 00                            	mov    rbx,QWORD PTR [rdi+0x448]
  91ecf8:	0f b7 87 78 01 00 00                            	movzx  eax,WORD PTR [rdi+0x178]
  91ecff:	a9 bc 01 00 00                                  	test   eax,0x1bc
  91ed04:	74 16                                           	je     0x91ed1c
  91ed06:	49 8d b6 88 00 00 00                            	lea    rsi,[r14+0x88]
  91ed0d:	4c 89 f7                                        	mov    rdi,r14
  91ed10:	e8 5b fe ff ff                                  	call   0x91eb70
  91ed15:	48 85 db                                        	test   rbx,rbx
  91ed18:	75 19                                           	jne    0x91ed33
  91ed1a:	eb 5a                                           	jmp    0x91ed76
  91ed1c:	49 8d be f0 00 00 00                            	lea    rdi,[r14+0xf0]
  91ed23:	31 f6                                           	xor    esi,esi
  91ed25:	31 d2                                           	xor    edx,edx
  91ed27:	31 c9                                           	xor    ecx,ecx
  91ed29:	e8 72 82 ba ff                                  	call   0x4c6fa0
  91ed2e:	48 85 db                                        	test   rbx,rbx
  91ed31:	74 43                                           	je     0x91ed76
  91ed33:	41 f6 46 10 01                                  	test   BYTE PTR [r14+0x10],0x1
  91ed38:	75 3c                                           	jne    0x91ed76
  91ed3a:	4c 8d b3 f0 00 00 00                            	lea    r14,[rbx+0xf0]
  91ed41:	31 f6                                           	xor    esi,esi
  91ed43:	31 d2                                           	xor    edx,edx
  91ed45:	31 c9                                           	xor    ecx,ecx
  91ed47:	4c 89 f7                                        	mov    rdi,r14
  91ed4a:	e8 b1 7c ba ff                                  	call   0x4c6a00
  91ed4f:	66 c7 43 76 a5 00                               	mov    WORD PTR [rbx+0x76],0xa5
  91ed55:	0f b7 83 78 01 00 00                            	movzx  eax,WORD PTR [rbx+0x178]
  91ed5c:	a9 bc 01 00 00                                  	test   eax,0x1bc
  91ed61:	74 18                                           	je     0x91ed7b
  91ed63:	48 8d b3 88 00 00 00                            	lea    rsi,[rbx+0x88]
  91ed6a:	48 89 df                                        	mov    rdi,rbx
  91ed6d:	5b                                              	pop    rbx
  91ed6e:	41 5e                                           	pop    r14
  91ed70:	5d                                              	pop    rbp
  91ed71:	e9 fa fd ff ff                                  	jmp    0x91eb70
  91ed76:	5b                                              	pop    rbx
  91ed77:	41 5e                                           	pop    r14
  91ed79:	5d                                              	pop    rbp
  91ed7a:	c3                                              	ret
  91ed7b:	4c 89 f7                                        	mov    rdi,r14
  91ed7e:	31 f6                                           	xor    esi,esi
  91ed80:	31 d2                                           	xor    edx,edx
  91ed82:	31 c9                                           	xor    ecx,ecx
  91ed84:	5b                                              	pop    rbx
  91ed85:	41 5e                                           	pop    r14
  91ed87:	5d                                              	pop    rbp
  91ed88:	e9 13 82 ba ff                                  	jmp    0x4c6fa0
  91ed8d:	90                                              	nop
  91ed8e:	90                                              	nop
  91ed8f:	90                                              	nop
  91ed90:	55                                              	push   rbp
  91ed91:	48 89 e5                                        	mov    rbp,rsp
  91ed94:	53                                              	push   rbx
  91ed95:	50                                              	push   rax
  91ed96:	48 89 fb                                        	mov    rbx,rdi
  91ed99:	48 81 c7 f0 00 00 00                            	add    rdi,0xf0
  91eda0:	31 f6                                           	xor    esi,esi
  91eda2:	31 d2                                           	xor    edx,edx
  91eda4:	31 c9                                           	xor    ecx,ecx
  91eda6:	e8 55 7c ba ff                                  	call   0x4c6a00
  91edab:	48 89 df                                        	mov    rdi,rbx
  91edae:	48 83 c4 08                                     	add    rsp,0x8
  91edb2:	5b                                              	pop    rbx
  91edb3:	5d                                              	pop    rbp
  91edb4:	e9 27 ff ff ff                                  	jmp    0x91ece0
  91edb9:	90                                              	nop
  91edba:	90                                              	nop
  91edbb:	90                                              	nop
  91edbc:	90                                              	nop
  91edbd:	90                                              	nop
  91edbe:	90                                              	nop
  91edbf:	90                                              	nop
  91edc0:	55                                              	push   rbp
  91edc1:	48 89 e5                                        	mov    rbp,rsp
  91edc4:	41 57                                           	push   r15
  91edc6:	41 56                                           	push   r14
  91edc8:	53                                              	push   rbx
  91edc9:	48 83 ec 28                                     	sub    rsp,0x28
  91edcd:	4c 8d 35 3c d5 ff 02                            	lea    r14,[rip+0x2ffd53c]        # 0x391c310
  91edd4:	48 89 fb                                        	mov    rbx,rdi
  91edd7:	49 8b 06                                        	mov    rax,QWORD PTR [r14]
  91edda:	48 89 45 e0                                     	mov    QWORD PTR [rbp-0x20],rax
  91edde:	80 8f f0 00 00 00 04                            	or     BYTE PTR [rdi+0xf0],0x4
  91ede5:	48 8d 7d d0                                     	lea    rdi,[rbp-0x30]
  91ede9:	e8 d2 09 1b 00                                  	call   0xacf7c0
  91edee:	0f b7 8b f0 00 00 00                            	movzx  ecx,WORD PTR [rbx+0xf0]
  91edf5:	f7 c1 00 40 00 00                               	test   ecx,0x4000
  91edfb:	75 37                                           	jne    0x91ee34
  91edfd:	49 bf ed b5 a0 f7 c6 10 00 00                   	movabs r15,0x10c6f7a0b5ed
  91ee07:	4c 0f af 7d d8                                  	imul   r15,QWORD PTR [rbp-0x28]
  91ee0c:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  91ee10:	31 d2                                           	xor    edx,edx
  91ee12:	4c 8b 83 e8 00 00 00                            	mov    r8,QWORD PTR [rbx+0xe8]
  91ee19:	48 8d bb c4 00 00 00                            	lea    rdi,[rbx+0xc4]
  91ee20:	48 8d 73 50                                     	lea    rsi,[rbx+0x50]
  91ee24:	48 c1 e0 20                                     	shl    rax,0x20
  91ee28:	49 c1 ef 20                                     	shr    r15,0x20
  91ee2c:	49 09 c7                                        	or     r15,rax
  91ee2f:	f6 c1 40                                        	test   cl,0x40
  91ee32:	eb 4e                                           	jmp    0x91ee82
  91ee34:	4c 8b 83 e8 00 00 00                            	mov    r8,QWORD PTR [rbx+0xe8]
  91ee3b:	4c 8b bb 00 01 00 00                            	mov    r15,QWORD PTR [rbx+0x100]
  91ee42:	4d 85 c0                                        	test   r8,r8
  91ee45:	7e 2b                                           	jle    0x91ee72
  91ee47:	48 ba ed b5 a0 f7 c6 10 00 00                   	movabs rdx,0x10c6f7a0b5ed
  91ee51:	48 0f af 55 d8                                  	imul   rdx,QWORD PTR [rbp-0x28]
  91ee56:	48 8b 45 d0                                     	mov    rax,QWORD PTR [rbp-0x30]
  91ee5a:	48 c1 e0 20                                     	shl    rax,0x20
  91ee5e:	48 c1 ea 20                                     	shr    rdx,0x20
  91ee62:	48 09 c2                                        	or     rdx,rax
  91ee65:	b8 23 00 00 00                                  	mov    eax,0x23
  91ee6a:	4c 29 fa                                        	sub    rdx,r15
  91ee6d:	49 29 d0                                        	sub    r8,rdx
  91ee70:	7e 3b                                           	jle    0x91eead
  91ee72:	31 d2                                           	xor    edx,edx
  91ee74:	f6 c1 40                                        	test   cl,0x40
  91ee77:	48 8d bb c4 00 00 00                            	lea    rdi,[rbx+0xc4]
  91ee7e:	48 8d 73 50                                     	lea    rsi,[rbx+0x50]
  91ee82:	0f 94 c2                                        	sete   dl
  91ee85:	c1 e2 0c                                        	shl    edx,0xc
  91ee88:	83 ca 58                                        	or     edx,0x58
  91ee8b:	48 8d 0d 14 56 a7 00                            	lea    rcx,[rip+0xa75614]        # 0x13944a6
  91ee92:	45 31 c9                                        	xor    r9d,r9d
  91ee95:	c7 04 24 00 00 00 00                            	mov    DWORD PTR [rsp],0x0
  91ee9c:	e8 bf 73 2e 00                                  	call   0xc06260
  91eea1:	0f b7 8b f0 00 00 00                            	movzx  ecx,WORD PTR [rbx+0xf0]
  91eea8:	83 f8 ff                                        	cmp    eax,0xffffffff
  91eeab:	74 13                                           	je     0x91eec0
  91eead:	81 e1 ff bf 00 00                               	and    ecx,0xbfff
  91eeb3:	48 c7 83 00 01 00 00 00 00 00 00                	mov    QWORD PTR [rbx+0x100],0x0
  91eebe:	eb 12                                           	jmp    0x91eed2
  91eec0:	4c 89 bb 00 01 00 00                            	mov    QWORD PTR [rbx+0x100],r15
  91eec7:	81 c9 00 40 00 00                               	or     ecx,0x4000
  91eecd:	b8 ff ff ff ff                                  	mov    eax,0xffffffff
  91eed2:	66 89 8b f0 00 00 00                            	mov    WORD PTR [rbx+0xf0],cx
  91eed9:	49 8b 0e                                        	mov    rcx,QWORD PTR [r14]
  91eedc:	48 3b 4d e0                                     	cmp    rcx,QWORD PTR [rbp-0x20]
  91eee0:	75 0b                                           	jne    0x91eeed
  91eee2:	48 83 c4 28                                     	add    rsp,0x28
  91eee6:	5b                                              	pop    rbx
  91eee7:	41 5e                                           	pop    r14
  91eee9:	41 5f                                           	pop    r15
  91eeeb:	5d                                              	pop    rbp
  91eeec:	c3                                              	ret
  91eeed:	e8 be e7 dd ff                                  	call   0x6fd6b0
  91eef2:	0f 0b                                           	ud2
  91eef4:	90                                              	nop
  91eef5:	90                                              	nop
  91eef6:	90                                              	nop
  91eef7:	90                                              	nop
  91eef8:	90                                              	nop
  91eef9:	90                                              	nop
  91eefa:	90                                              	nop
  91eefb:	90                                              	nop
  91eefc:	90                                              	nop
  91eefd:	90                                              	nop
  91eefe:	90                                              	nop
  91eeff:	90                                              	nop
  91ef00:	55                                              	push   rbp
  91ef01:	48 89 e5                                        	mov    rbp,rsp
  91ef04:	41 56                                           	push   r14
  91ef06:	53                                              	push   rbx
  91ef07:	40 f6 c6 01                                     	test   sil,0x1
  91ef0b:	75 1d                                           	jne    0x91ef2a
  91ef0d:	48 83 c7 70                                     	add    rdi,0x70
  91ef11:	45 31 f6                                        	xor    r14d,r14d
  91ef14:	31 f6                                           	xor    esi,esi
  91ef16:	31 d2                                           	xor    edx,edx
  91ef18:	e8 f3 d2 32 00                                  	call   0xc4c210
  91ef1d:	85 c0                                           	test   eax,eax
  91ef1f:	bb 23 00 00 00                                  	mov    ebx,0x23
  91ef24:	41 0f 45 de                                     	cmovne ebx,r14d
  91ef28:	eb 3b                                           	jmp    0x91ef65
  91ef2a:	48 8d 47 70                                     	lea    rax,[rdi+0x70]
  91ef2e:	40 f6 c6 02                                     	test   sil,0x2
  91ef32:	75 21                                           	jne    0x91ef55
  91ef34:	0f b7 8f f0 00 00 00                            	movzx  ecx,WORD PTR [rdi+0xf0]
  91ef3b:	83 e1 40                                        	and    ecx,0x40
  91ef3e:	75 15                                           	jne    0x91ef55
  91ef40:	48 89 c7                                        	mov    rdi,rax
  91ef43:	be 40 00 00 00                                  	mov    esi,0x40
  91ef48:	31 d2                                           	xor    edx,edx
  91ef4a:	31 c9                                           	xor    ecx,ecx
  91ef4c:	5b                                              	pop    rbx
  91ef4d:	41 5e                                           	pop    r14
  91ef4f:	5d                                              	pop    rbp
  91ef50:	e9 cb cb 32 00                                  	jmp    0xc4bb20
  91ef55:	48 89 c7                                        	mov    rdi,rax
  91ef58:	31 db                                           	xor    ebx,ebx
  91ef5a:	31 f6                                           	xor    esi,esi
  91ef5c:	31 d2                                           	xor    edx,edx
  91ef5e:	31 c9                                           	xor    ecx,ecx
  91ef60:	e8 bb cb 32 00                                  	call   0xc4bb20
  91ef65:	89 d8                                           	mov    eax,ebx
  91ef67:	5b                                              	pop    rbx
  91ef68:	41 5e                                           	pop    r14
  91ef6a:	5d                                              	pop    rbp
  91ef6b:	c3                                              	ret
  91ef6c:	90                                              	nop
  91ef6d:	90                                              	nop
  91ef6e:	90                                              	nop
  91ef6f:	90                                              	nop
  91ef70:	55                                              	push   rbp
  91ef71:	48 89 e5                                        	mov    rbp,rsp
  91ef74:	48 83 c7 70                                     	add    rdi,0x70
  91ef78:	31 f6                                           	xor    esi,esi
  91ef7a:	31 d2                                           	xor    edx,edx
  91ef7c:	5d                                              	pop    rbp
  91ef7d:	e9 2e d5 32 00                                  	jmp    0xc4c4b0
  91ef82:	90                                              	nop
  91ef83:	90                                              	nop
  91ef84:	90                                              	nop
  91ef85:	90                                              	nop
  91ef86:	90                                              	nop
  91ef87:	90                                              	nop
  91ef88:	90                                              	nop
  91ef89:	90                                              	nop
  91ef8a:	90                                              	nop
  91ef8b:	90                                              	nop
  91ef8c:	90                                              	nop
  91ef8d:	90                                              	nop
  91ef8e:	90                                              	nop
  91ef8f:	90                                              	nop
  91ef90:	55                                              	push   rbp
  91ef91:	48 89 e5                                        	mov    rbp,rsp
  91ef94:	41 57                                           	push   r15
  91ef96:	41 56                                           	push   r14
  91ef98:	41 55                                           	push   r13
  91ef9a:	41 54                                           	push   r12
  91ef9c:	53                                              	push   rbx
  91ef9d:	48 83 ec 18                                     	sub    rsp,0x18
  91efa1:	65 4c 8b 24 25 00 00 00 00                      	mov    r12,QWORD PTR gs:0x0
  91efaa:	49 89 ff                                        	mov    r15,rdi
  91efad:	48 81 c7 38 02 00 00                            	add    rdi,0x238
  91efb4:	49 89 d5                                        	mov    r13,rdx
  91efb7:	48 89 f3                                        	mov    rbx,rsi
  91efba:	31 f6                                           	xor    esi,esi
  91efbc:	31 d2                                           	xor    edx,edx
  91efbe:	31 c9                                           	xor    ecx,ecx
  91efc0:	48 89 7d d0                                     	mov    QWORD PTR [rbp-0x30],rdi
  91efc4:	e8 37 7a ba ff                                  	call   0x4c6a00
  91efc9:	4d 8d b7 f0 00 00 00                            	lea    r14,[r15+0xf0]
  91efd0:	31 f6                                           	xor    esi,esi
  91efd2:	31 d2                                           	xor    edx,edx
  91efd4:	31 c9                                           	xor    ecx,ecx
  91efd6:	4c 89 f7                                        	mov    rdi,r14
  91efd9:	e8 22 7a ba ff                                  	call   0x4c6a00
  91efde:	48 3b 1d 9b 30 c3 01                            	cmp    rbx,QWORD PTR [rip+0x1c3309b]        # 0x2552080
  91efe5:	0f 87 c7 01 00 00                               	ja     0x91f1b2
  91efeb:	48 b9 ff ff ff ff ff ff ff 7f                   	movabs rcx,0x7fffffffffffffff
  91eff5:	4d 85 e4                                        	test   r12,r12
  91eff8:	74 10                                           	je     0x91f00a
  91effa:	4c 89 e7                                        	mov    rdi,r12
  91effd:	be 09 00 00 00                                  	mov    esi,0x9
  91f002:	e8 a9 31 b8 ff                                  	call   0x4a21b0
  91f007:	48 89 c1                                        	mov    rcx,rax
  91f00a:	49 8b 87 18 03 00 00                            	mov    rax,QWORD PTR [r15+0x318]
  91f011:	49 8d b7 9c 02 00 00                            	lea    rsi,[r15+0x29c]
  91f018:	89 da                                           	mov    edx,ebx
  91f01a:	48 89 75 c8                                     	mov    QWORD PTR [rbp-0x38],rsi
  91f01e:	48 8b 78 20                                     	mov    rdi,QWORD PTR [rax+0x20]
  91f022:	e8 a9 36 b8 ff                                  	call   0x4a26d0
  91f027:	85 c0                                           	test   eax,eax
  91f029:	0f 84 83 01 00 00                               	je     0x91f1b2
  91f02f:	0f af 1d 7a 30 c3 01                            	imul   ebx,DWORD PTR [rip+0x1c3307a]        # 0x25520b0
  91f036:	8b 05 3c 30 c3 01                               	mov    eax,DWORD PTR [rip+0x1c3303c]        # 0x2552078
  91f03c:	39 c3                                           	cmp    ebx,eax
  91f03e:	0f 43 d8                                        	cmovae ebx,eax
  91f041:	41 89 9f ac 02 00 00                            	mov    DWORD PTR [r15+0x2ac],ebx
  91f048:	41 8b 87 9c 02 00 00                            	mov    eax,DWORD PTR [r15+0x29c]
  91f04f:	41 39 87 b4 02 00 00                            	cmp    DWORD PTR [r15+0x2b4],eax
  91f056:	76 07                                           	jbe    0x91f05f
  91f058:	41 89 87 b4 02 00 00                            	mov    DWORD PTR [r15+0x2b4],eax
  91f05f:	4c 3b 2d 1a 30 c3 01                            	cmp    r13,QWORD PTR [rip+0x1c3301a]        # 0x2552080
  91f066:	0f 87 c5 00 00 00                               	ja     0x91f131
  91f06c:	48 b9 ff ff ff ff ff ff ff 7f                   	movabs rcx,0x7fffffffffffffff
  91f076:	4d 85 e4                                        	test   r12,r12
  91f079:	74 10                                           	je     0x91f08b
  91f07b:	4c 89 e7                                        	mov    rdi,r12
  91f07e:	be 09 00 00 00                                  	mov    esi,0x9
  91f083:	e8 28 31 b8 ff                                  	call   0x4a21b0
  91f088:	48 89 c1                                        	mov    rcx,rax
  91f08b:	49 8b 87 18 03 00 00                            	mov    rax,QWORD PTR [r15+0x318]
  91f092:	49 8d b7 54 01 00 00                            	lea    rsi,[r15+0x154]
  91f099:	44 89 ea                                        	mov    edx,r13d
  91f09c:	48 8b 78 20                                     	mov    rdi,QWORD PTR [rax+0x20]
  91f0a0:	e8 2b 36 b8 ff                                  	call   0x4a26d0
  91f0a5:	85 c0                                           	test   eax,eax
  91f0a7:	0f 84 84 00 00 00                               	je     0x91f131
  91f0ad:	44 0f af 2d fb 2f c3 01                         	imul   r13d,DWORD PTR [rip+0x1c32ffb]        # 0x25520b0
  91f0b5:	8b 05 bd 2f c3 01                               	mov    eax,DWORD PTR [rip+0x1c32fbd]        # 0x2552078
  91f0bb:	41 39 c5                                        	cmp    r13d,eax
  91f0be:	44 0f 43 e8                                     	cmovae r13d,eax
  91f0c2:	45 89 af 64 01 00 00                            	mov    DWORD PTR [r15+0x164],r13d
  91f0c9:	41 8b 87 54 01 00 00                            	mov    eax,DWORD PTR [r15+0x154]
  91f0d0:	41 8b 8f 6c 01 00 00                            	mov    ecx,DWORD PTR [r15+0x16c]
  91f0d7:	39 c1                                           	cmp    ecx,eax
  91f0d9:	0f 42 c1                                        	cmovb  eax,ecx
  91f0dc:	0f 96 c2                                        	setbe  dl
  91f0df:	85 c0                                           	test   eax,eax
  91f0e1:	0f 95 c1                                        	setne  cl
  91f0e4:	84 ca                                           	test   dl,cl
  91f0e6:	75 0d                                           	jne    0x91f0f5
  91f0e8:	83 f8 01                                        	cmp    eax,0x1
  91f0eb:	83 d0 00                                        	adc    eax,0x0
  91f0ee:	41 89 87 6c 01 00 00                            	mov    DWORD PTR [r15+0x16c],eax
  91f0f5:	41 8b 87 b4 02 00 00                            	mov    eax,DWORD PTR [r15+0x2b4]
  91f0fc:	48 8b 5d d0                                     	mov    rbx,QWORD PTR [rbp-0x30]
  91f100:	85 c0                                           	test   eax,eax
  91f102:	75 10                                           	jne    0x91f114
  91f104:	b8 00 08 00 00                                  	mov    eax,0x800
  91f109:	41 c7 87 b4 02 00 00 00 08 00 00                	mov    DWORD PTR [r15+0x2b4],0x800
  91f114:	48 8b 4d c8                                     	mov    rcx,QWORD PTR [rbp-0x38]
  91f118:	45 31 e4                                        	xor    r12d,r12d
  91f11b:	8b 09                                           	mov    ecx,DWORD PTR [rcx]
  91f11d:	39 c8                                           	cmp    eax,ecx
  91f11f:	0f 86 97 00 00 00                               	jbe    0x91f1bc
  91f125:	41 89 8f b4 02 00 00                            	mov    DWORD PTR [r15+0x2b4],ecx
  91f12c:	e9 8b 00 00 00                                  	jmp    0x91f1bc
  91f131:	41 83 bf a0 02 00 00 00                         	cmp    DWORD PTR [r15+0x2a0],0x0
  91f139:	74 4c                                           	je     0x91f187
  91f13b:	49 8d 9f d0 01 00 00                            	lea    rbx,[r15+0x1d0]
  91f142:	eb 26                                           	jmp    0x91f16a
  91f144:	66 66 66 2e 0f 1f 84 00 00 00 00 00             	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  91f150:	48 89 df                                        	mov    rdi,rbx
  91f153:	e8 c8 0d 00 00                                  	call   0x91ff20
  91f158:	48 89 c7                                        	mov    rdi,rax
  91f15b:	e8 f0 b6 b0 ff                                  	call   0x42a850
  91f160:	41 83 bf a0 02 00 00 00                         	cmp    DWORD PTR [r15+0x2a0],0x0
  91f168:	74 1d                                           	je     0x91f187
  91f16a:	41 8b b7 98 02 00 00                            	mov    esi,DWORD PTR [r15+0x298]
  91f171:	85 f6                                           	test   esi,esi
  91f173:	75 db                                           	jne    0x91f150
  91f175:	49 8b 87 68 02 00 00                            	mov    rax,QWORD PTR [r15+0x268]
  91f17c:	48 85 c0                                        	test   rax,rax
  91f17f:	74 06                                           	je     0x91f187
  91f181:	83 78 18 00                                     	cmp    DWORD PTR [rax+0x18],0x0
  91f185:	74 c9                                           	je     0x91f150
  91f187:	49 8b 87 18 03 00 00                            	mov    rax,QWORD PTR [r15+0x318]
  91f18e:	48 8b 75 c8                                     	mov    rsi,QWORD PTR [rbp-0x38]
  91f192:	48 b9 ff ff ff ff ff ff ff 7f                   	movabs rcx,0x7fffffffffffffff
  91f19c:	31 d2                                           	xor    edx,edx
  91f19e:	48 8b 78 20                                     	mov    rdi,QWORD PTR [rax+0x20]
  91f1a2:	e8 29 35 b8 ff                                  	call   0x4a26d0
  91f1a7:	41 c7 87 ac 02 00 00 00 00 00 00                	mov    DWORD PTR [r15+0x2ac],0x0
  91f1b2:	48 8b 5d d0                                     	mov    rbx,QWORD PTR [rbp-0x30]
  91f1b6:	41 bc 37 00 00 00                               	mov    r12d,0x37
  91f1bc:	4c 89 f7                                        	mov    rdi,r14
  91f1bf:	31 f6                                           	xor    esi,esi
  91f1c1:	31 d2                                           	xor    edx,edx
  91f1c3:	31 c9                                           	xor    ecx,ecx
  91f1c5:	e8 d6 7d ba ff                                  	call   0x4c6fa0
  91f1ca:	48 89 df                                        	mov    rdi,rbx
  91f1cd:	31 f6                                           	xor    esi,esi
  91f1cf:	31 d2                                           	xor    edx,edx
  91f1d1:	31 c9                                           	xor    ecx,ecx
  91f1d3:	e8 c8 7d ba ff                                  	call   0x4c6fa0
  91f1d8:	44 89 e0                                        	mov    eax,r12d
  91f1db:	48 83 c4 18                                     	add    rsp,0x18
  91f1df:	5b                                              	pop    rbx
  91f1e0:	41 5c                                           	pop    r12
  91f1e2:	41 5d                                           	pop    r13
  91f1e4:	41 5e                                           	pop    r14
  91f1e6:	41 5f                                           	pop    r15
  91f1e8:	5d                                              	pop    rbp
  91f1e9:	c3                                              	ret
  91f1ea:	90                                              	nop
  91f1eb:	90                                              	nop
  91f1ec:	90                                              	nop
  91f1ed:	90                                              	nop
  91f1ee:	90                                              	nop
  91f1ef:	90                                              	nop
  91f1f0:	55                                              	push   rbp
  91f1f1:	48 89 e5                                        	mov    rbp,rsp
  91f1f4:	41 57                                           	push   r15
  91f1f6:	41 56                                           	push   r14
  91f1f8:	41 54                                           	push   r12
  91f1fa:	53                                              	push   rbx
  91f1fb:	45 31 f6                                        	xor    r14d,r14d
  91f1fe:	48 3b 35 7b 2e c3 01                            	cmp    rsi,QWORD PTR [rip+0x1c32e7b]        # 0x2552080
  91f205:	0f 87 81 00 00 00                               	ja     0x91f28c
  91f20b:	49 89 f7                                        	mov    r15,rsi
  91f20e:	48 89 fb                                        	mov    rbx,rdi
  91f211:	48 85 c9                                        	test   rcx,rcx
  91f214:	74 18                                           	je     0x91f22e
  91f216:	48 89 cf                                        	mov    rdi,rcx
  91f219:	be 09 00 00 00                                  	mov    esi,0x9
  91f21e:	49 89 d4                                        	mov    r12,rdx
  91f221:	e8 8a 2f b8 ff                                  	call   0x4a21b0
  91f226:	4c 89 e2                                        	mov    rdx,r12
  91f229:	48 89 c1                                        	mov    rcx,rax
  91f22c:	eb 0a                                           	jmp    0x91f238
  91f22e:	48 b9 ff ff ff ff ff ff ff 7f                   	movabs rcx,0x7fffffffffffffff
  91f238:	48 8b 82 18 03 00 00                            	mov    rax,QWORD PTR [rdx+0x318]
  91f23f:	48 8d b3 cc 00 00 00                            	lea    rsi,[rbx+0xcc]
  91f246:	44 89 fa                                        	mov    edx,r15d
  91f249:	48 8b 78 20                                     	mov    rdi,QWORD PTR [rax+0x20]
  91f24d:	e8 7e 34 b8 ff                                  	call   0x4a26d0
  91f252:	85 c0                                           	test   eax,eax
  91f254:	74 36                                           	je     0x91f28c
  91f256:	44 0f af 3d 52 2e c3 01                         	imul   r15d,DWORD PTR [rip+0x1c32e52]        # 0x25520b0
  91f25e:	8b 05 14 2e c3 01                               	mov    eax,DWORD PTR [rip+0x1c32e14]        # 0x2552078
  91f264:	41 be 01 00 00 00                               	mov    r14d,0x1
  91f26a:	41 39 c7                                        	cmp    r15d,eax
  91f26d:	44 0f 43 f8                                     	cmovae r15d,eax
  91f271:	44 89 bb dc 00 00 00                            	mov    DWORD PTR [rbx+0xdc],r15d
  91f278:	8b 83 cc 00 00 00                               	mov    eax,DWORD PTR [rbx+0xcc]
  91f27e:	39 83 e4 00 00 00                               	cmp    DWORD PTR [rbx+0xe4],eax
  91f284:	76 06                                           	jbe    0x91f28c
  91f286:	89 83 e4 00 00 00                               	mov    DWORD PTR [rbx+0xe4],eax
  91f28c:	44 89 f0                                        	mov    eax,r14d
  91f28f:	5b                                              	pop    rbx
  91f290:	41 5c                                           	pop    r12
  91f292:	41 5e                                           	pop    r14
  91f294:	41 5f                                           	pop    r15
  91f296:	5d                                              	pop    rbp
  91f297:	c3                                              	ret
  91f298:	90                                              	nop
  91f299:	90                                              	nop
  91f29a:	90                                              	nop
  91f29b:	90                                              	nop
  91f29c:	90                                              	nop
  91f29d:	90                                              	nop
  91f29e:	90                                              	nop
  91f29f:	90                                              	nop
  91f2a0:	55                                              	push   rbp
  91f2a1:	48 89 e5                                        	mov    rbp,rsp
  91f2a4:	41 57                                           	push   r15
  91f2a6:	41 56                                           	push   r14
  91f2a8:	41 55                                           	push   r13
  91f2aa:	41 54                                           	push   r12
  91f2ac:	53                                              	push   rbx
  91f2ad:	50                                              	push   rax
  91f2ae:	48 8d 5f 68                                     	lea    rbx,[rdi+0x68]
  91f2b2:	49 89 ff                                        	mov    r15,rdi
  91f2b5:	49 89 ce                                        	mov    r14,rcx
  91f2b8:	49 89 d5                                        	mov    r13,rdx
  91f2bb:	49 89 f4                                        	mov    r12,rsi
  91f2be:	31 f6                                           	xor    esi,esi
  91f2c0:	31 d2                                           	xor    edx,edx
  91f2c2:	31 c9                                           	xor    ecx,ecx
  91f2c4:	48 89 df                                        	mov    rdi,rbx
  91f2c7:	e8 34 77 ba ff                                  	call   0x4c6a00
  91f2cc:	4c 3b 25 ad 2d c3 01                            	cmp    r12,QWORD PTR [rip+0x1c32dad]        # 0x2552080
  91f2d3:	76 05                                           	jbe    0x91f2da
  91f2d5:	45 31 f6                                        	xor    r14d,r14d
  91f2d8:	eb 7b                                           	jmp    0x91f355
  91f2da:	4d 85 f6                                        	test   r14,r14
  91f2dd:	74 12                                           	je     0x91f2f1
  91f2df:	4c 89 f7                                        	mov    rdi,r14
  91f2e2:	be 09 00 00 00                                  	mov    esi,0x9
  91f2e7:	e8 c4 2e b8 ff                                  	call   0x4a21b0
  91f2ec:	48 89 c1                                        	mov    rcx,rax
  91f2ef:	eb 0a                                           	jmp    0x91f2fb
  91f2f1:	48 b9 ff ff ff ff ff ff ff 7f                   	movabs rcx,0x7fffffffffffffff
  91f2fb:	49 8b 85 18 03 00 00                            	mov    rax,QWORD PTR [r13+0x318]
  91f302:	49 8d b7 cc 00 00 00                            	lea    rsi,[r15+0xcc]
  91f309:	44 89 e2                                        	mov    edx,r12d
  91f30c:	45 31 f6                                        	xor    r14d,r14d
  91f30f:	48 8b 78 20                                     	mov    rdi,QWORD PTR [rax+0x20]
  91f313:	e8 b8 33 b8 ff                                  	call   0x4a26d0
  91f318:	85 c0                                           	test   eax,eax
  91f31a:	74 39                                           	je     0x91f355
  91f31c:	44 0f af 25 8c 2d c3 01                         	imul   r12d,DWORD PTR [rip+0x1c32d8c]        # 0x25520b0
  91f324:	8b 05 4e 2d c3 01                               	mov    eax,DWORD PTR [rip+0x1c32d4e]        # 0x2552078
  91f32a:	41 be 01 00 00 00                               	mov    r14d,0x1
  91f330:	41 39 c4                                        	cmp    r12d,eax
  91f333:	44 0f 43 e0                                     	cmovae r12d,eax
  91f337:	45 89 a7 dc 00 00 00                            	mov    DWORD PTR [r15+0xdc],r12d
  91f33e:	41 8b 87 cc 00 00 00                            	mov    eax,DWORD PTR [r15+0xcc]
  91f345:	41 39 87 e4 00 00 00                            	cmp    DWORD PTR [r15+0xe4],eax
  91f34c:	76 07                                           	jbe    0x91f355
  91f34e:	41 89 87 e4 00 00 00                            	mov    DWORD PTR [r15+0xe4],eax
  91f355:	48 89 df                                        	mov    rdi,rbx
  91f358:	31 f6                                           	xor    esi,esi
  91f35a:	31 d2                                           	xor    edx,edx
  91f35c:	31 c9                                           	xor    ecx,ecx
  91f35e:	e8 3d 7c ba ff                                  	call   0x4c6fa0
  91f363:	44 89 f0                                        	mov    eax,r14d
  91f366:	48 83 c4 08                                     	add    rsp,0x8
  91f36a:	5b                                              	pop    rbx
  91f36b:	41 5c                                           	pop    r12
  91f36d:	41 5d                                           	pop    r13
  91f36f:	41 5e                                           	pop    r14
  91f371:	41 5f                                           	pop    r15
  91f373:	5d                                              	pop    rbp
  91f374:	c3                                              	ret
  91f375:	90                                              	nop
  91f376:	90                                              	nop
  91f377:	90                                              	nop
  91f378:	90                                              	nop
  91f379:	90                                              	nop
  91f37a:	90                                              	nop
  91f37b:	90                                              	nop
  91f37c:	90                                              	nop
  91f37d:	90                                              	nop
  91f37e:	90                                              	nop
  91f37f:	90                                              	nop
  91f380:	55                                              	push   rbp
  91f381:	48 89 e5                                        	mov    rbp,rsp
  91f384:	41 56                                           	push   r14
  91f386:	53                                              	push   rbx
  91f387:	83 bf d0 00 00 00 00                            	cmp    DWORD PTR [rdi+0xd0],0x0
  91f38e:	49 89 f6                                        	mov    r14,rsi
  91f391:	48 89 fb                                        	mov    rbx,rdi
  91f394:	75 23                                           	jne    0x91f3b9
  91f396:	eb 3d                                           	jmp    0x91f3d5
  91f398:	0f 1f 84 00 00 00 00 00                         	nop    DWORD PTR [rax+rax*1+0x0]
  91f3a0:	48 89 df                                        	mov    rdi,rbx
  91f3a3:	e8 78 0b 00 00                                  	call   0x91ff20
  91f3a8:	48 89 c7                                        	mov    rdi,rax
  91f3ab:	e8 a0 b4 b0 ff                                  	call   0x42a850
  91f3b0:	83 bb d0 00 00 00 00                            	cmp    DWORD PTR [rbx+0xd0],0x0
  91f3b7:	74 1c                                           	je     0x91f3d5
  91f3b9:	8b b3 c8 00 00 00                               	mov    esi,DWORD PTR [rbx+0xc8]
  91f3bf:	85 f6                                           	test   esi,esi
  91f3c1:	75 dd                                           	jne    0x91f3a0
  91f3c3:	48 8b 83 98 00 00 00                            	mov    rax,QWORD PTR [rbx+0x98]
  91f3ca:	48 85 c0                                        	test   rax,rax
  91f3cd:	74 06                                           	je     0x91f3d5
  91f3cf:	83 78 18 00                                     	cmp    DWORD PTR [rax+0x18],0x0
  91f3d3:	74 cb                                           	je     0x91f3a0
  91f3d5:	49 8b 86 18 03 00 00                            	mov    rax,QWORD PTR [r14+0x318]
  91f3dc:	48 8d b3 cc 00 00 00                            	lea    rsi,[rbx+0xcc]
  91f3e3:	48 b9 ff ff ff ff ff ff ff 7f                   	movabs rcx,0x7fffffffffffffff
  91f3ed:	31 d2                                           	xor    edx,edx
  91f3ef:	48 8b 78 20                                     	mov    rdi,QWORD PTR [rax+0x20]
  91f3f3:	e8 d8 32 b8 ff                                  	call   0x4a26d0
  91f3f8:	c7 83 dc 00 00 00 00 00 00 00                   	mov    DWORD PTR [rbx+0xdc],0x0
  91f402:	5b                                              	pop    rbx
  91f403:	41 5e                                           	pop    r14
  91f405:	5d                                              	pop    rbp
  91f406:	c3                                              	ret
  91f407:	90                                              	nop
  91f408:	90                                              	nop
  91f409:	90                                              	nop
  91f40a:	90                                              	nop
  91f40b:	90                                              	nop
  91f40c:	90                                              	nop
  91f40d:	90                                              	nop
  91f40e:	90                                              	nop
  91f40f:	90                                              	nop
  91f410:	55                                              	push   rbp
  91f411:	48 89 e5                                        	mov    rbp,rsp
  91f414:	41 56                                           	push   r14
  91f416:	53                                              	push   rbx
  91f417:	83 bf d0 00 00 00 00                            	cmp    DWORD PTR [rdi+0xd0],0x0
  91f41e:	49 89 f6                                        	mov    r14,rsi
  91f421:	48 89 fb                                        	mov    rbx,rdi
  91f424:	75 23                                           	jne    0x91f449
  91f426:	eb 3d                                           	jmp    0x91f465
  91f428:	0f 1f 84 00 00 00 00 00                         	nop    DWORD PTR [rax+rax*1+0x0]
  91f430:	48 89 df                                        	mov    rdi,rbx
  91f433:	e8 e8 0a 00 00                                  	call   0x91ff20
  91f438:	48 89 c7                                        	mov    rdi,rax
  91f43b:	e8 10 b4 b0 ff                                  	call   0x42a850
  91f440:	83 bb d0 00 00 00 00                            	cmp    DWORD PTR [rbx+0xd0],0x0
  91f447:	74 1c                                           	je     0x91f465
  91f449:	8b b3 c8 00 00 00                               	mov    esi,DWORD PTR [rbx+0xc8]
  91f44f:	85 f6                                           	test   esi,esi
  91f451:	75 dd                                           	jne    0x91f430
  91f453:	48 8b 83 98 00 00 00                            	mov    rax,QWORD PTR [rbx+0x98]
  91f45a:	48 85 c0                                        	test   rax,rax
  91f45d:	74 06                                           	je     0x91f465
  91f45f:	83 78 18 00                                     	cmp    DWORD PTR [rax+0x18],0x0
  91f463:	74 cb                                           	je     0x91f430
  91f465:	49 8b 86 18 03 00 00                            	mov    rax,QWORD PTR [r14+0x318]
  91f46c:	48 8d b3 cc 00 00 00                            	lea    rsi,[rbx+0xcc]
  91f473:	48 b9 ff ff ff ff ff ff ff 7f                   	movabs rcx,0x7fffffffffffffff
  91f47d:	31 d2                                           	xor    edx,edx
  91f47f:	48 8b 78 20                                     	mov    rdi,QWORD PTR [rax+0x20]
  91f483:	e8 48 32 b8 ff                                  	call   0x4a26d0
  91f488:	c7 83 dc 00 00 00 00 00 00 00                   	mov    DWORD PTR [rbx+0xdc],0x0
  91f492:	5b                                              	pop    rbx
  91f493:	41 5e                                           	pop    r14
  91f495:	5d                                              	pop    rbp
  91f496:	c3                                              	ret
  91f497:	90                                              	nop
  91f498:	90                                              	nop
  91f499:	90                                              	nop
  91f49a:	90                                              	nop
  91f49b:	90                                              	nop
  91f49c:	90                                              	nop
  91f49d:	90                                              	nop
  91f49e:	90                                              	nop
  91f49f:	90                                              	nop
  91f4a0:	55                                              	push   rbp
  91f4a1:	48 89 e5                                        	mov    rbp,rsp
  91f4a4:	41 56                                           	push   r14
  91f4a6:	53                                              	push   rbx
  91f4a7:	48 85 f6                                        	test   rsi,rsi
  91f4aa:	74 75                                           	je     0x91f521
  91f4ac:	83 e2 08                                        	and    edx,0x8
  91f4af:	48 89 f3                                        	mov    rbx,rsi
  91f4b2:	48 89 f0                                        	mov    rax,rsi
  91f4b5:	c1 e2 11                                        	shl    edx,0x11
  91f4b8:	81 ca ff ff 0f e0                               	or     edx,0xe00fffff
  91f4be:	66 90                                           	xchg   ax,ax
  91f4c0:	21 50 1c                                        	and    DWORD PTR [rax+0x1c],edx
  91f4c3:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  91f4c6:	48 85 c0                                        	test   rax,rax
  91f4c9:	75 f5                                           	jne    0x91f4c0
  91f4cb:	48 8b 8f 98 00 00 00                            	mov    rcx,QWORD PTR [rdi+0x98]
  91f4d2:	48 85 c9                                        	test   rcx,rcx
  91f4d5:	74 4f                                           	je     0x91f526
  91f4d7:	66 0f 1f 84 00 00 00 00 00                      	nop    WORD PTR [rax+rax*1+0x0]
  91f4e0:	48 89 c8                                        	mov    rax,rcx
  91f4e3:	48 8b 49 08                                     	mov    rcx,QWORD PTR [rcx+0x8]
  91f4e7:	48 85 c9                                        	test   rcx,rcx
  91f4ea:	75 f4                                           	jne    0x91f4e0
  91f4ec:	eb 0d                                           	jmp    0x91f4fb
  91f4ee:	66 90                                           	xchg   ax,ax
  91f4f0:	48 89 c2                                        	mov    rdx,rax
  91f4f3:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  91f4f6:	48 85 c0                                        	test   rax,rax
  91f4f9:	74 61                                           	je     0x91f55c
  91f4fb:	f6 40 1d 04                                     	test   BYTE PTR [rax+0x1d],0x4
  91f4ff:	74 ef                                           	je     0x91f4f0
  91f501:	48 89 d8                                        	mov    rax,rbx
  91f504:	66 66 66 2e 0f 1f 84 00 00 00 00 00             	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  91f510:	81 60 1c ff ff 0f e0                            	and    DWORD PTR [rax+0x1c],0xe00fffff
  91f517:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  91f51a:	48 85 c0                                        	test   rax,rax
  91f51d:	75 f1                                           	jne    0x91f510
  91f51f:	eb 5e                                           	jmp    0x91f57f
  91f521:	5b                                              	pop    rbx
  91f522:	41 5e                                           	pop    r14
  91f524:	5d                                              	pop    rbp
  91f525:	c3                                              	ret
  91f526:	48 8b 87 a8 00 00 00                            	mov    rax,QWORD PTR [rdi+0xa8]
  91f52d:	48 85 c0                                        	test   rax,rax
  91f530:	74 21                                           	je     0x91f553
  91f532:	66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00       	data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  91f540:	f6 40 1d 04                                     	test   BYTE PTR [rax+0x1d],0x4
  91f544:	75 1b                                           	jne    0x91f561
  91f546:	48 89 c2                                        	mov    rdx,rax
  91f549:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  91f54c:	48 85 c0                                        	test   rax,rax
  91f54f:	75 ef                                           	jne    0x91f540
  91f551:	eb 09                                           	jmp    0x91f55c
  91f553:	31 d2                                           	xor    edx,edx
  91f555:	48 89 9f a8 00 00 00                            	mov    QWORD PTR [rdi+0xa8],rbx
  91f55c:	48 89 de                                        	mov    rsi,rbx
  91f55f:	eb 7b                                           	jmp    0x91f5dc
  91f561:	48 89 d8                                        	mov    rax,rbx
  91f564:	66 66 66 2e 0f 1f 84 00 00 00 00 00             	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  91f570:	81 60 1c ff ff 0f e0                            	and    DWORD PTR [rax+0x1c],0xe00fffff
  91f577:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  91f57a:	48 85 c0                                        	test   rax,rax
  91f57d:	75 f1                                           	jne    0x91f570
  91f57f:	48 89 de                                        	mov    rsi,rbx
  91f582:	49 89 fe                                        	mov    r14,rdi
  91f585:	e8 66 f3 ff ff                                  	call   0x91e8f0
  91f58a:	49 8b 86 a8 00 00 00                            	mov    rax,QWORD PTR [r14+0xa8]
  91f591:	48 85 c0                                        	test   rax,rax
  91f594:	74 06                                           	je     0x91f59c
  91f596:	48 89 58 08                                     	mov    QWORD PTR [rax+0x8],rbx
  91f59a:	eb 07                                           	jmp    0x91f5a3
  91f59c:	49 89 9e 98 00 00 00                            	mov    QWORD PTR [r14+0x98],rbx
  91f5a3:	49 89 9e a8 00 00 00                            	mov    QWORD PTR [r14+0xa8],rbx
  91f5aa:	49 89 9e a0 00 00 00                            	mov    QWORD PTR [r14+0xa0],rbx
  91f5b1:	48 8b 33                                        	mov    rsi,QWORD PTR [rbx]
  91f5b4:	48 c7 03 00 00 00 00                            	mov    QWORD PTR [rbx],0x0
  91f5bb:	48 85 f6                                        	test   rsi,rsi
  91f5be:	74 16                                           	je     0x91f5d6
  91f5c0:	8b 43 1c                                        	mov    eax,DWORD PTR [rbx+0x1c]
  91f5c3:	a9 00 04 00 00                                  	test   eax,0x400
  91f5c8:	74 0c                                           	je     0x91f5d6
  91f5ca:	25 ff fb ff ff                                  	and    eax,0xfffffbff
  91f5cf:	89 43 1c                                        	mov    DWORD PTR [rbx+0x1c],eax
  91f5d2:	80 4e 1d 04                                     	or     BYTE PTR [rsi+0x1d],0x4
  91f5d6:	4c 89 f7                                        	mov    rdi,r14
  91f5d9:	48 89 da                                        	mov    rdx,rbx
  91f5dc:	5b                                              	pop    rbx
  91f5dd:	41 5e                                           	pop    r14
  91f5df:	5d                                              	pop    rbp
  91f5e0:	e9 0b 00 00 00                                  	jmp    0x91f5f0
  91f5e5:	90                                              	nop
  91f5e6:	90                                              	nop
  91f5e7:	90                                              	nop
  91f5e8:	90                                              	nop
  91f5e9:	90                                              	nop
  91f5ea:	90                                              	nop
  91f5eb:	90                                              	nop
  91f5ec:	90                                              	nop
  91f5ed:	90                                              	nop
  91f5ee:	90                                              	nop
  91f5ef:	90                                              	nop
  91f5f0:	48 85 f6                                        	test   rsi,rsi
  91f5f3:	0f 84 78 03 00 00                               	je     0x91f971
  91f5f9:	55                                              	push   rbp
  91f5fa:	48 89 e5                                        	mov    rbp,rsp
  91f5fd:	41 57                                           	push   r15
  91f5ff:	41 56                                           	push   r14
  91f601:	41 55                                           	push   r13
  91f603:	41 54                                           	push   r12
  91f605:	53                                              	push   rbx
  91f606:	48 83 ec 28                                     	sub    rsp,0x28
  91f60a:	49 89 d7                                        	mov    r15,rdx
  91f60d:	48 89 fb                                        	mov    rbx,rdi
  91f610:	45 31 ed                                        	xor    r13d,r13d
  91f613:	66 66 66 66 2e 0f 1f 84 00 00 00 00 00          	data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  91f620:	49 8d 47 78                                     	lea    rax,[r15+0x78]
  91f624:	49 8d 57 78                                     	lea    rdx,[r15+0x78]
  91f628:	49 8d 4f 20                                     	lea    rcx,[r15+0x20]
  91f62c:	4d 89 fe                                        	mov    r14,r15
  91f62f:	49 89 f7                                        	mov    r15,rsi
  91f632:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  91f636:	48 89 55 b8                                     	mov    QWORD PTR [rbp-0x48],rdx
  91f63a:	48 89 4d c0                                     	mov    QWORD PTR [rbp-0x40],rcx
  91f63e:	eb 14                                           	jmp    0x91f654
  91f640:	4c 89 ff                                        	mov    rdi,r15
  91f643:	e8 68 a9 b0 ff                                  	call   0x429fb0
  91f648:	4d 89 e7                                        	mov    r15,r12
  91f64b:	4d 85 e4                                        	test   r12,r12
  91f64e:	0f 84 1e 03 00 00                               	je     0x91f972
  91f654:	41 8b 4f 1c                                     	mov    ecx,DWORD PTR [r15+0x1c]
  91f658:	44 89 e8                                        	mov    eax,r13d
  91f65b:	41 89 cd                                        	mov    r13d,ecx
  91f65e:	41 c1 ed 08                                     	shr    r13d,0x8
  91f662:	41 83 e5 04                                     	and    r13d,0x4
  91f666:	41 09 c5                                        	or     r13d,eax
  91f669:	49 63 47 18                                     	movsxd rax,DWORD PTR [r15+0x18]
  91f66d:	48 85 c0                                        	test   rax,rax
  91f670:	0f 84 aa 00 00 00                               	je     0x91f720
  91f676:	4d 85 f6                                        	test   r14,r14
  91f679:	0f 84 a6 02 00 00                               	je     0x91f925
  91f67f:	41 8b 56 1c                                     	mov    edx,DWORD PTR [r14+0x1c]
  91f683:	f7 c2 00 0c 00 00                               	test   edx,0xc00
  91f689:	0f 85 91 02 00 00                               	jne    0x91f920
  91f68f:	f7 c2 00 01 00 00                               	test   edx,0x100
  91f695:	74 20                                           	je     0x91f6b7
  91f697:	41 f6 86 8d 00 00 00 01                         	test   BYTE PTR [r14+0x8d],0x1
  91f69f:	48 8b 75 d0                                     	mov    rsi,QWORD PTR [rbp-0x30]
  91f6a3:	75 07                                           	jne    0x91f6ac
  91f6a5:	48 8b 75 d0                                     	mov    rsi,QWORD PTR [rbp-0x30]
  91f6a9:	48 8b 36                                        	mov    rsi,QWORD PTR [rsi]
  91f6ac:	8b 36                                           	mov    esi,DWORD PTR [rsi]
  91f6ae:	83 fe 01                                        	cmp    esi,0x1
  91f6b1:	0f 85 69 02 00 00                               	jne    0x91f920
  91f6b7:	3d 00 02 00 00                                  	cmp    eax,0x200
  91f6bc:	0f 8f 5e 02 00 00                               	jg     0x91f920
  91f6c2:	0f b7 b3 f0 00 00 00                            	movzx  esi,WORD PTR [rbx+0xf0]
  91f6c9:	81 e6 00 02 00 00                               	and    esi,0x200
  91f6cf:	0f 85 4b 02 00 00                               	jne    0x91f920
  91f6d5:	89 d6                                           	mov    esi,edx
  91f6d7:	09 ce                                           	or     esi,ecx
  91f6d9:	81 e6 00 00 10 00                               	and    esi,0x100000
  91f6df:	0f 85 3b 02 00 00                               	jne    0x91f920
  91f6e5:	f7 c2 00 01 00 00                               	test   edx,0x100
  91f6eb:	0f 85 bf 00 00 00                               	jne    0x91f7b0
  91f6f1:	48 8b 75 b8                                     	mov    rsi,QWORD PTR [rbp-0x48]
  91f6f5:	f7 c2 00 02 00 00                               	test   edx,0x200
  91f6fb:	bf 88 00 00 00                                  	mov    edi,0x88
  91f700:	41 b8 e0 00 00 00                               	mov    r8d,0xe0
  91f706:	41 0f 44 f8                                     	cmove  edi,r8d
  91f70a:	48 0f 44 75 c0                                  	cmove  rsi,QWORD PTR [rbp-0x40]
  91f70f:	e9 c6 00 00 00                                  	jmp    0x91f7da
  91f714:	66 66 66 2e 0f 1f 84 00 00 00 00 00             	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
  91f720:	4d 8b 27                                        	mov    r12,QWORD PTR [r15]
  91f723:	45 85 ed                                        	test   r13d,r13d
  91f726:	74 22                                           	je     0x91f74a
  91f728:	4c 89 f2                                        	mov    rdx,r14
  91f72b:	4c 09 e2                                        	or     rdx,r12
  91f72e:	0f 84 f1 01 00 00                               	je     0x91f925
  91f734:	4d 85 e4                                        	test   r12,r12
  91f737:	4c 89 f2                                        	mov    rdx,r14
  91f73a:	49 0f 45 d4                                     	cmovne rdx,r12
  91f73e:	0f b6 52 1c                                     	movzx  edx,BYTE PTR [rdx+0x1c]
  91f742:	30 ca                                           	xor    dl,cl
  91f744:	0f 85 2c ff ff ff                               	jne    0x91f676
  91f74a:	4c 39 bb a8 00 00 00                            	cmp    QWORD PTR [rbx+0xa8],r15
  91f751:	75 07                                           	jne    0x91f75a
  91f753:	4c 89 a3 a8 00 00 00                            	mov    QWORD PTR [rbx+0xa8],r12
  91f75a:	48 8d 05 6f 75 c4 01                            	lea    rax,[rip+0x1c4756f]        # 0x2566cd0
  91f761:	48 8b 78 48                                     	mov    rdi,QWORD PTR [rax+0x48]
  91f765:	48 85 ff                                        	test   rdi,rdi
  91f768:	0f 84 0a 01 00 00                               	je     0x91f878
  91f76e:	48 8d 05 b3 c7 17 01                            	lea    rax,[rip+0x117c7b3]        # 0x1a9bf28
  91f775:	4c 8b 10                                        	mov    r10,QWORD PTR [rax]
  91f778:	48 8d 05 69 8a 94 ff                            	lea    rax,[rip+0xffffffffff948a69]        # 0x2681e8
  91f77f:	4c 29 d0                                        	sub    rax,r10
  91f782:	48 c1 c8 03                                     	ror    rax,0x3
  91f786:	48 83 f8 01                                     	cmp    rax,0x1
  91f78a:	0f 86 50 01 00 00                               	jbe    0x91f8e0
  91f790:	48 8d 3d 49 2a c3 01                            	lea    rdi,[rip+0x1c32a49]        # 0x25521e0
  91f797:	4c 89 d6                                        	mov    rsi,r10
  91f79a:	4c 89 55 c8                                     	mov    QWORD PTR [rbp-0x38],r10
  91f79e:	e8 1d 01 b3 ff                                  	call   0x44f8c0
  91f7a3:	e9 5d 01 00 00                                  	jmp    0x91f905
  91f7a8:	0f 1f 84 00 00 00 00 00                         	nop    DWORD PTR [rax+rax*1+0x0]
  91f7b0:	41 f6 86 8d 00 00 00 01                         	test   BYTE PTR [r14+0x8d],0x1
  91f7b8:	48 8b 75 d0                                     	mov    rsi,QWORD PTR [rbp-0x30]
  91f7bc:	75 07                                           	jne    0x91f7c5
  91f7be:	48 8b 75 d0                                     	mov    rsi,QWORD PTR [rbp-0x30]
  91f7c2:	48 8b 36                                        	mov    rsi,QWORD PTR [rsi]
  91f7c5:	8b 36                                           	mov    esi,DWORD PTR [rsi]
  91f7c7:	83 fe 01                                        	cmp    esi,0x1
  91f7ca:	75 28                                           	jne    0x91f7f4
  91f7cc:	49 8b b6 80 00 00 00                            	mov    rsi,QWORD PTR [r14+0x80]
  91f7d3:	41 8b be 88 00 00 00                            	mov    edi,DWORD PTR [r14+0x88]
  91f7da:	4d 63 46 18                                     	movsxd r8,DWORD PTR [r14+0x18]
  91f7de:	4d 03 46 10                                     	add    r8,QWORD PTR [r14+0x10]
  91f7e2:	89 ff                                           	mov    edi,edi
  91f7e4:	48 01 f7                                        	add    rdi,rsi
  91f7e7:	4c 29 c7                                        	sub    rdi,r8
  91f7ea:	48 39 c7                                        	cmp    rdi,rax
  91f7ed:	7d 10                                           	jge    0x91f7ff
  91f7ef:	e9 2c 01 00 00                                  	jmp    0x91f920
  91f7f4:	31 ff                                           	xor    edi,edi
  91f7f6:	48 39 c7                                        	cmp    rdi,rax
  91f7f9:	0f 8c 21 01 00 00                               	jl     0x91f920
  91f7ff:	30 ca                                           	xor    dl,cl
  91f801:	0f 85 19 01 00 00                               	jne    0x91f920
  91f807:	49 63 76 18                                     	movsxd rsi,DWORD PTR [r14+0x18]
  91f80b:	49 03 76 10                                     	add    rsi,QWORD PTR [r14+0x10]
  91f80f:	49 8b 7f 10                                     	mov    rdi,QWORD PTR [r15+0x10]
  91f813:	89 c2                                           	mov    edx,eax
  91f815:	e8 c6 a3 93 ff                                  	call   0x259be0
  91f81a:	41 8b 47 18                                     	mov    eax,DWORD PTR [r15+0x18]
  91f81e:	48 89 df                                        	mov    rdi,rbx
  91f821:	41 01 46 18                                     	add    DWORD PTR [r14+0x18],eax
  91f825:	41 8b 47 18                                     	mov    eax,DWORD PTR [r15+0x18]
  91f829:	01 83 c8 00 00 00                               	add    DWORD PTR [rbx+0xc8],eax
  91f82f:	41 8b 77 18                                     	mov    esi,DWORD PTR [r15+0x18]
  91f833:	e8 58 7d d7 ff                                  	call   0x697590
  91f838:	48 83 bb b8 00 00 00 00                         	cmp    QWORD PTR [rbx+0xb8],0x0
  91f840:	75 0a                                           	jne    0x91f84c
  91f842:	41 8b 47 18                                     	mov    eax,DWORD PTR [r15+0x18]
  91f846:	01 83 c4 00 00 00                               	add    DWORD PTR [rbx+0xc4],eax
  91f84c:	41 0f b6 47 1c                                  	movzx  eax,BYTE PTR [r15+0x1c]
  91f851:	83 f8 01                                        	cmp    eax,0x1
  91f854:	74 0f                                           	je     0x91f865
  91f856:	83 f8 10                                        	cmp    eax,0x10
  91f859:	74 0a                                           	je     0x91f865
  91f85b:	41 8b 47 18                                     	mov    eax,DWORD PTR [r15+0x18]
  91f85f:	01 83 e0 00 00 00                               	add    DWORD PTR [rbx+0xe0],eax
  91f865:	48 8d 05 64 74 c4 01                            	lea    rax,[rip+0x1c47464]        # 0x2566cd0
  91f86c:	4d 8b 27                                        	mov    r12,QWORD PTR [r15]
  91f86f:	48 8b 78 48                                     	mov    rdi,QWORD PTR [rax+0x48]
  91f873:	48 85 ff                                        	test   rdi,rdi
  91f876:	75 4a                                           	jne    0x91f8c2
  91f878:	41 8b 47 1c                                     	mov    eax,DWORD PTR [r15+0x1c]
  91f87c:	89 c1                                           	mov    ecx,eax
  91f87e:	f7 d1                                           	not    ecx
  91f880:	f7 c1 00 02 02 00                               	test   ecx,0x20200
  91f886:	75 0e                                           	jne    0x91f896
  91f888:	4c 89 ff                                        	mov    rdi,r15
  91f88b:	31 f6                                           	xor    esi,esi
  91f88d:	e8 fe 57 9a ff                                  	call   0x2c5090
  91f892:	41 8b 47 1c                                     	mov    eax,DWORD PTR [r15+0x1c]
  91f896:	a9 00 01 00 00                                  	test   eax,0x100
  91f89b:	0f 85 9f fd ff ff                               	jne    0x91f640
  91f8a1:	a9 00 00 02 00                                  	test   eax,0x20000
  91f8a6:	0f 85 9c fd ff ff                               	jne    0x91f648
  91f8ac:	48 8b 3d 6d 57 bd 02                            	mov    rdi,QWORD PTR [rip+0x2bd576d]        # 0x34f5020
  91f8b3:	4c 89 fe                                        	mov    rsi,r15
  91f8b6:	31 d2                                           	xor    edx,edx
  91f8b8:	e8 03 c8 b1 ff                                  	call   0x43c0c0
  91f8bd:	e9 86 fd ff ff                                  	jmp    0x91f648
  91f8c2:	48 8d 05 5f c6 17 01                            	lea    rax,[rip+0x117c65f]        # 0x1a9bf28
  91f8c9:	4c 8b 10                                        	mov    r10,QWORD PTR [rax]
  91f8cc:	48 8d 05 15 89 94 ff                            	lea    rax,[rip+0xffffffffff948915]        # 0x2681e8
  91f8d3:	4c 29 d0                                        	sub    rax,r10
  91f8d6:	48 c1 c8 03                                     	ror    rax,0x3
  91f8da:	48 83 f8 01                                     	cmp    rax,0x1
  91f8de:	77 12                                           	ja     0x91f8f2
  91f8e0:	4c 89 fe                                        	mov    rsi,r15
  91f8e3:	31 d2                                           	xor    edx,edx
  91f8e5:	31 c9                                           	xor    ecx,ecx
  91f8e7:	45 31 c0                                        	xor    r8d,r8d
  91f8ea:	45 31 c9                                        	xor    r9d,r9d
  91f8ed:	41 ff d2                                        	call   r10
  91f8f0:	eb 86                                           	jmp    0x91f878
  91f8f2:	48 8d 3d e7 28 c3 01                            	lea    rdi,[rip+0x1c328e7]        # 0x25521e0
  91f8f9:	4c 89 d6                                        	mov    rsi,r10
  91f8fc:	4c 89 55 c8                                     	mov    QWORD PTR [rbp-0x38],r10
  91f900:	e8 bb ff b2 ff                                  	call   0x44f8c0
  91f905:	48 8d 05 c4 73 c4 01                            	lea    rax,[rip+0x1c473c4]        # 0x2566cd0
  91f90c:	4c 8b 55 c8                                     	mov    r10,QWORD PTR [rbp-0x38]
  91f910:	48 8b 78 48                                     	mov    rdi,QWORD PTR [rax+0x48]
  91f914:	eb ca                                           	jmp    0x91f8e0
  91f916:	66 2e 0f 1f 84 00 00 00 00 00                   	cs nop WORD PTR [rax+rax*1+0x0]
  91f920:	4d 89 3e                                        	mov    QWORD PTR [r14],r15
  91f923:	eb 07                                           	jmp    0x91f92c
  91f925:	4c 89 bb 98 00 00 00                            	mov    QWORD PTR [rbx+0x98],r15
  91f92c:	48 89 df                                        	mov    rdi,rbx
  91f92f:	4c 89 fe                                        	mov    rsi,r15
  91f932:	4c 89 bb a0 00 00 00                            	mov    QWORD PTR [rbx+0xa0],r15
  91f939:	e8 b2 ef ff ff                                  	call   0x91e8f0
  91f93e:	41 80 67 1d fb                                  	and    BYTE PTR [r15+0x1d],0xfb
  91f943:	49 8b 37                                        	mov    rsi,QWORD PTR [r15]
  91f946:	49 c7 07 00 00 00 00                            	mov    QWORD PTR [r15],0x0
  91f94d:	48 85 f6                                        	test   rsi,rsi
  91f950:	0f 85 ca fc ff ff                               	jne    0x91f620
  91f956:	45 85 ed                                        	test   r13d,r13d
  91f959:	74 08                                           	je     0x91f963
  91f95b:	41 c1 e5 08                                     	shl    r13d,0x8
  91f95f:	45 09 6f 1c                                     	or     DWORD PTR [r15+0x1c],r13d
  91f963:	48 83 c4 28                                     	add    rsp,0x28
  91f967:	5b                                              	pop    rbx
  91f968:	41 5c                                           	pop    r12
  91f96a:	41 5d                                           	pop    r13
  91f96c:	41 5e                                           	pop    r14
  91f96e:	41 5f                                           	pop    r15
  91f970:	5d                                              	pop    rbp
  91f971:	c3                                              	ret
  91f972:	4d 89 f7                                        	mov    r15,r14
  91f975:	45 85 ed                                        	test   r13d,r13d
  91f978:	75 e1                                           	jne    0x91f95b
  91f97a:	eb e7                                           	jmp    0x91f963
  91f97c:	90                                              	nop
  91f97d:	90                                              	nop
  91f97e:	90                                              	nop
  91f97f:	90                                              	nop
  91f980:	55                                              	push   rbp
  91f981:	48 89 e5                                        	mov    rbp,rsp
  91f984:	41 56                                           	push   r14
  91f986:	53                                              	push   rbx
  91f987:	83 e2 08                                        	and    edx,0x8
  91f98a:	49 89 fe                                        	mov    r14,rdi
  91f98d:	48 89 f3                                        	mov    rbx,rsi
  91f990:	48 89 f7                                        	mov    rdi,rsi
  91f993:	be 01 00 00 00                                  	mov    esi,0x1
  91f998:	c1 e2 09                                        	shl    edx,0x9
  91f99b:	e8 b0 84 0f 00                                  	call   0xa17e50
  91f9a0:	49 8b 96 a0 00 00 00                            	mov    rdx,QWORD PTR [r14+0xa0]
  91f9a7:	4c 89 f7                                        	mov    rdi,r14
  91f9aa:	48 89 de                                        	mov    rsi,rbx
  91f9ad:	e8 3e fc ff ff                                  	call   0x91f5f0
  91f9b2:	49 8b 86 98 00 00 00                            	mov    rax,QWORD PTR [r14+0x98]
  91f9b9:	49 89 86 a8 00 00 00                            	mov    QWORD PTR [r14+0xa8],rax
  91f9c0:	5b                                              	pop    rbx
  91f9c1:	41 5e                                           	pop    r14
  91f9c3:	5d                                              	pop    rbp
  91f9c4:	c3                                              	ret
  91f9c5:	90                                              	nop
  91f9c6:	90                                              	nop
  91f9c7:	90                                              	nop
  91f9c8:	90                                              	nop
  91f9c9:	90                                              	nop
  91f9ca:	90                                              	nop
  91f9cb:	90                                              	nop
  91f9cc:	90                                              	nop
  91f9cd:	90                                              	nop
  91f9ce:	90                                              	nop
  91f9cf:	90                                              	nop
  91f9d0:	55                                              	push   rbp
  91f9d1:	48 89 e5                                        	mov    rbp,rsp
  91f9d4:	41 57                                           	push   r15
  91f9d6:	41 56                                           	push   r14
  91f9d8:	41 54                                           	push   r12
  91f9da:	53                                              	push   rbx
  91f9db:	4c 8d 77 68                                     	lea    r14,[rdi+0x68]
  91f9df:	48 89 fb                                        	mov    rbx,rdi
  91f9e2:	41 89 d7                                        	mov    r15d,edx
  91f9e5:	49 89 f4                                        	mov    r12,rsi
  91f9e8:	31 f6                                           	xor    esi,esi
  91f9ea:	31 d2                                           	xor    edx,edx
  91f9ec:	31 c9                                           	xor    ecx,ecx
  91f9ee:	4c 89 f7                                        	mov    rdi,r14
  91f9f1:	e8 0a 70 ba ff                                  	call   0x4c6a00
  91f9f6:	41 83 e7 08                                     	and    r15d,0x8
  91f9fa:	4c 89 e7                                        	mov    rdi,r12
  91f9fd:	be 01 00 00 00                                  	mov    esi,0x1
  91fa02:	41 c1 e7 09                                     	shl    r15d,0x9
  91fa06:	44 89 fa                                        	mov    edx,r15d
  91fa09:	e8 42 84 0f 00                                  	call   0xa17e50
  91fa0e:	48 8b 93 a0 00 00 00                            	mov    rdx,QWORD PTR [rbx+0xa0]
  91fa15:	48 89 df                                        	mov    rdi,rbx
  91fa18:	4c 89 e6                                        	mov    rsi,r12
  91fa1b:	e8 d0 fb ff ff                                  	call   0x91f5f0
  91fa20:	48 8b 83 98 00 00 00                            	mov    rax,QWORD PTR [rbx+0x98]
  91fa27:	4c 89 f7                                        	mov    rdi,r14
  91fa2a:	31 f6                                           	xor    esi,esi
  91fa2c:	31 d2                                           	xor    edx,edx
  91fa2e:	31 c9                                           	xor    ecx,ecx
  91fa30:	48 89 83 a8 00 00 00                            	mov    QWORD PTR [rbx+0xa8],rax
  91fa37:	5b                                              	pop    rbx
  91fa38:	41 5c                                           	pop    r12
  91fa3a:	41 5e                                           	pop    r14
  91fa3c:	41 5f                                           	pop    r15
  91fa3e:	5d                                              	pop    rbp
  91fa3f:	e9 5c 75 ba ff                                  	jmp    0x4c6fa0
  91fa44:	90                                              	nop
  91fa45:	90                                              	nop
  91fa46:	90                                              	nop
  91fa47:	90                                              	nop
  91fa48:	90                                              	nop
  91fa49:	90                                              	nop
  91fa4a:	90                                              	nop
  91fa4b:	90                                              	nop
  91fa4c:	90                                              	nop
  91fa4d:	90                                              	nop
  91fa4e:	90                                              	nop
  91fa4f:	90                                              	nop
  91fa50:	55                                              	push   rbp
  91fa51:	48 89 e5                                        	mov    rbp,rsp
  91fa54:	41 57                                           	push   r15
  91fa56:	41 56                                           	push   r14
  91fa58:	41 55                                           	push   r13
  91fa5a:	41 54                                           	push   r12
  91fa5c:	53                                              	push   rbx
  91fa5d:	48 83 ec 18                                     	sub    rsp,0x18
  91fa61:	48 8d 05 a8 c8 ff 02                            	lea    rax,[rip+0x2ffc8a8]        # 0x391c310
  91fa68:	48 89 cb                                        	mov    rbx,rcx
  91fa6b:	49 89 d6                                        	mov    r14,rdx
  91fa6e:	49 89 f7                                        	mov    r15,rsi
  91fa71:	49 89 fc                                        	mov    r12,rdi
  91fa74:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  91fa77:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  91fa7b:	44 0f b6 2e                                     	movzx  r13d,BYTE PTR [rsi]
  91fa7f:	48 85 d2                                        	test   rdx,rdx
  91fa82:	74 0f                                           	je     0x91fa93
  91fa84:	41 f6 46 1d 02                                  	test   BYTE PTR [r14+0x1d],0x2
  91fa89:	0f 84 94 00 00 00                               	je     0x91fb23
  91fa8f:	45 03 6e 30                                     	add    r13d,DWORD PTR [r14+0x30]
  91fa93:	48 8d 75 c8                                     	lea    rsi,[rbp-0x38]
  91fa97:	48 89 df                                        	mov    rdi,rbx
  91fa9a:	e8 71 a5 0f 00                                  	call   0xa1a010
  91fa9f:	44 01 e8                                        	add    eax,r13d
  91faa2:	48 63 c8                                        	movsxd rcx,eax
  91faa5:	31 c0                                           	xor    eax,eax
  91faa7:	41 f6 84 24 f1 00 00 00 10                      	test   BYTE PTR [r12+0xf1],0x10
  91fab0:	75 2f                                           	jne    0x91fae1
  91fab2:	41 8b 94 24 cc 00 00 00                         	mov    edx,DWORD PTR [r12+0xcc]
  91faba:	41 8b b4 24 dc 00 00 00                         	mov    esi,DWORD PTR [r12+0xdc]
  91fac2:	41 2b 94 24 c8 00 00 00                         	sub    edx,DWORD PTR [r12+0xc8]
  91faca:	41 2b b4 24 d0 00 00 00                         	sub    esi,DWORD PTR [r12+0xd0]
  91fad2:	39 f2                                           	cmp    edx,esi
  91fad4:	0f 4c f2                                        	cmovl  esi,edx
  91fad7:	48 63 d6                                        	movsxd rdx,esi
  91fada:	48 39 ca                                        	cmp    rdx,rcx
  91fadd:	7d 09                                           	jge    0x91fae8
  91fadf:	eb 1c                                           	jmp    0x91fafd
  91fae1:	31 d2                                           	xor    edx,edx
  91fae3:	48 39 ca                                        	cmp    rdx,rcx
  91fae6:	7c 15                                           	jl     0x91fafd
  91fae8:	4c 8b 45 c8                                     	mov    r8,QWORD PTR [rbp-0x38]
  91faec:	4c 89 e7                                        	mov    rdi,r12
  91faef:	4c 89 fe                                        	mov    rsi,r15
  91faf2:	4c 89 f2                                        	mov    rdx,r14
  91faf5:	48 89 d9                                        	mov    rcx,rbx
  91faf8:	e8 53 00 00 00                                  	call   0x91fb50
  91fafd:	48 8d 0d 0c c8 ff 02                            	lea    rcx,[rip+0x2ffc80c]        # 0x391c310
  91fb04:	48 8b 09                                        	mov    rcx,QWORD PTR [rcx]
  91fb07:	48 3b 4d d0                                     	cmp    rcx,QWORD PTR [rbp-0x30]
  91fb0b:	75 0f                                           	jne    0x91fb1c
  91fb0d:	48 83 c4 18                                     	add    rsp,0x18
  91fb11:	5b                                              	pop    rbx
  91fb12:	41 5c                                           	pop    r12
  91fb14:	41 5d                                           	pop    r13
  91fb16:	41 5e                                           	pop    r14
  91fb18:	41 5f                                           	pop    r15
  91fb1a:	5d                                              	pop    rbp
  91fb1b:	c3                                              	ret
  91fb1c:	e8 8f db dd ff                                  	call   0x6fd6b0
  91fb21:	0f 0b                                           	ud2
  91fb23:	e8 28 1e ed ff                                  	call   0x7f1950
  91fb28:	48 8d 3d f4 ff ff ff                            	lea    rdi,[rip+0xfffffffffffffff4]        # 0x91fb23
  91fb2f:	e8 dc 1c ed ff                                  	call   0x7f1810
  91fb34:	48 8d 35 5f 71 9f 00                            	lea    rsi,[rip+0x9f715f]        # 0x1316c9a
  91fb3b:	bf 0f 00 00 00                                  	mov    edi,0xf
  91fb40:	31 c0                                           	xor    eax,eax
  91fb42:	e8 c9 ae 37 00                                  	call   0xc9aa10
  91fb47:	0f 0b                                           	ud2
  91fb49:	90                                              	nop
  91fb4a:	90                                              	nop
  91fb4b:	90                                              	nop
  91fb4c:	90                                              	nop
  91fb4d:	90                                              	nop
  91fb4e:	90                                              	nop
  91fb4f:	90                                              	nop
  91fb50:	55                                              	push   rbp
  91fb51:	48 89 e5                                        	mov    rbp,rsp
  91fb54:	41 57                                           	push   r15
  91fb56:	41 56                                           	push   r14
  91fb58:	41 55                                           	push   r13
  91fb5a:	41 54                                           	push   r12
  91fb5c:	53                                              	push   rbx
  91fb5d:	48 83 ec 28                                     	sub    rsp,0x28
  91fb61:	49 89 d4                                        	mov    r12,rdx
  91fb64:	48 8d 15 a5 c7 ff 02                            	lea    rdx,[rip+0x2ffc7a5]        # 0x391c310
  91fb6b:	45 31 ff                                        	xor    r15d,r15d
  91fb6e:	48 8b 02                                        	mov    rax,QWORD PTR [rdx]
  91fb71:	48 89 45 d0                                     	mov    QWORD PTR [rbp-0x30],rax
  91fb75:	80 3e e0                                        	cmp    BYTE PTR [rsi],0xe0
  91fb78:	0f 87 35 01 00 00                               	ja     0x91fcb3
  91fb7e:	48 89 fb                                        	mov    rbx,rdi
  91fb81:	48 8b 3d 98 54 bd 02                            	mov    rdi,QWORD PTR [rip+0x2bd5498]        # 0x34f5020
  91fb88:	49 89 f5                                        	mov    r13,rsi
  91fb8b:	48 8d 75 c8                                     	lea    rsi,[rbp-0x38]
  91fb8f:	ba 01 00 00 00                                  	mov    edx,0x1
  91fb94:	c7 45 c8 00 00 00 00                            	mov    DWORD PTR [rbp-0x38],0x0
  91fb9b:	4c 89 45 b0                                     	mov    QWORD PTR [rbp-0x50],r8
  91fb9f:	48 89 4d b8                                     	mov    QWORD PTR [rbp-0x48],rcx
  91fba3:	66 c7 45 cc 08 00                               	mov    WORD PTR [rbp-0x34],0x8
  91fba9:	e8 d2 bc b1 ff                                  	call   0x43b880
  91fbae:	48 8d 0d bb 70 c4 01                            	lea    rcx,[rip+0x1c470bb]        # 0x2566c70
  91fbb5:	49 89 c6                                        	mov    r14,rax
  91fbb8:	48 8b 79 48                                     	mov    rdi,QWORD PTR [rcx+0x48]
  91fbbc:	48 85 ff                                        	test   rdi,rdi
  91fbbf:	0f 85 09 01 00 00                               	jne    0x91fcce
  91fbc5:	48 8d 15 44 c7 ff 02                            	lea    rdx,[rip+0x2ffc744]        # 0x391c310
  91fbcc:	4d 85 f6                                        	test   r14,r14
  91fbcf:	0f 84 de 00 00 00                               	je     0x91fcb3
  91fbd5:	41 0f b6 45 00                                  	movzx  eax,BYTE PTR [r13+0x0]
  91fbda:	4c 89 ef                                        	mov    rdi,r13
  91fbdd:	41 89 46 18                                     	mov    DWORD PTR [r14+0x18],eax
  91fbe1:	49 8b 76 10                                     	mov    rsi,QWORD PTR [r14+0x10]
  91fbe5:	41 0f b6 55 00                                  	movzx  edx,BYTE PTR [r13+0x0]
  91fbea:	e8 f1 9f 93 ff                                  	call   0x259be0
  91fbef:	4d 85 e4                                        	test   r12,r12
  91fbf2:	74 4e                                           	je     0x91fc42
  91fbf4:	4c 89 e0                                        	mov    rax,r12
  91fbf7:	66 0f 1f 84 00 00 00 00 00                      	nop    WORD PTR [rax+rax*1+0x0]
  91fc00:	81 60 1c ff ff 0f e0                            	and    DWORD PTR [rax+0x1c],0xe00fffff
  91fc07:	48 8b 00                                        	mov    rax,QWORD PTR [rax]
  91fc0a:	48 85 c0                                        	test   rax,rax
  91fc0d:	75 f1                                           	jne    0x91fc00
  91fc0f:	4c 89 e7                                        	mov    rdi,r12
  91fc12:	31 f6                                           	xor    esi,esi
  91fc14:	e8 77 54 9a ff                                  	call   0x2c5090
  91fc19:	49 c7 44 24 20 00 00 00 00                      	mov    QWORD PTR [r12+0x20],0x0
  91fc22:	41 c7 44 24 34 00 00 00 00                      	mov    DWORD PTR [r12+0x34],0x0
  91fc2b:	49 c7 44 24 38 00 00 00 00                      	mov    QWORD PTR [r12+0x38],0x0
  91fc34:	66 41 c7 44 24 40 00 00                         	mov    WORD PTR [r12+0x40],0x0
  91fc3c:	41 c6 44 24 43 00                               	mov    BYTE PTR [r12+0x43],0x0
  91fc42:	48 8b 45 b0                                     	mov    rax,QWORD PTR [rbp-0x50]
  91fc46:	48 85 c0                                        	test   rax,rax
  91fc49:	74 07                                           	je     0x91fc52
  91fc4b:	4c 89 20                                        	mov    QWORD PTR [rax],r12
  91fc4e:	4c 8b 65 b8                                     	mov    r12,QWORD PTR [rbp-0x48]
  91fc52:	4d 89 f7                                        	mov    r15,r14
  91fc55:	4d 89 26                                        	mov    QWORD PTR [r14],r12
  91fc58:	4d 85 e4                                        	test   r12,r12
  91fc5b:	74 17                                           	je     0x91fc74
  91fc5d:	4d 89 f7                                        	mov    r15,r14
  91fc60:	48 89 df                                        	mov    rdi,rbx
  91fc63:	4c 89 fe                                        	mov    rsi,r15
  91fc66:	e8 85 ec ff ff                                  	call   0x91e8f0
  91fc6b:	4d 8b 3f                                        	mov    r15,QWORD PTR [r15]
  91fc6e:	49                                              	rex.WB
  91fc6f:	83                                              	.byte 0x83
